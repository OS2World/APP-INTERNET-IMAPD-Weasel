/*
   POP3 protocol implementation.

*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define INCL_DOSSEMAPHORES
#define INCL_DOSPROCESS
#define INCL_DOSMISC
#define INCL_DOSERRORS
#include <os2.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include "linkseq.h"
#include "utils.h"
#include "context.h"
#include "storage.h"
#include "message.h"
#include "wcfg.h"
#include "log.h"
#include "netserv.h"
#include "imapfs.h"
#include "pop3.h"
#include "linkseq.h"
#include "debug.h"               // Should be last.

// Delay before "authorization failure" response (msec).
#define _AUTH_FAIL_RESP_DELAY    10000

#define _STATE_AUTHORIZATION     0
#define _STATE_TRANSACTION       1
#define _STATE_UPDATE            2

#define _CMD_FL_AUTHORIZATION_STATE        0x01
#define _CMD_FL_TRANSACTION_STATE          0x02
#define _CMD_FL_ANY_STATE                  (_CMD_FL_AUTHORIZATION_STATE | \
                                            _CMD_FL_TRANSACTION_STATE)

#define _AUTH_PLAIN              1
#define _AUTH_CRAMMD5            2

// Flags for MSFILE.ulUser
#define _FILE_FL_DELETED         0x01
#define _FILE_FL_HASH            0x02
#define _FILE_FL_HASHEA          0x04

#define _HASH_EA_NAME            "IMAPD.HASH"

#define _MAX_BAD_COMMANDS        4

#define _WEASEL_LOCK_FILE        "LOCK.!!!"

typedef struct _PROTODATA {
  SEQOBJ     stSeqObj;
  ULONG      ulState;                      // _STATE_xxxxx
  union {
    struct {
      PSZ        pszTimestamp;             // High memory pointer.
      ULONG      ulAuthMechanism;          // _AUTH_xxxxx
      PSZ        pszUser;                  // High memory pointer.
    } _auth_data;

    struct {
      PSZ        pszShortPath;
      MSLIST     stFList;
    } _trans_data;
  } _state_depended;
#define _sd_pszTimestamp         _state_depended._auth_data.pszTimestamp
#define _sd_pszUser              _state_depended._auth_data.pszUser
#define _sd_ulAuthMechanism      _state_depended._auth_data.ulAuthMechanism
#define _sd_pszShortPath         _state_depended._trans_data.pszShortPath
#define _sd_stFList              _state_depended._trans_data.stFList

  USHORT     usBadLogins;
  USHORT     usBadCommands;

} PROTODATA, *PPROTODATA;

// This data will stored for each file in PROTODATA._sd_stFList list:
// _sd_stFList.papFiles[...]->ulUser.
typedef struct _POP3FILEINFO {
  ULONG      ulFlags;                                // _FILE_FL_xxxxx
  CHAR       acHash[UTIL_FILE_HASH_LENGTH];
} POP3FILEINFO, *PPOP3FILEINFO;

#define _setFInfo(__ulIdx, __fi) \
 pProtoData->_sd_stFList.papFiles[__ulIdx]->ulUser = (ULONG)__fi

// Macros to get POP3FILEINFO object for the message.
#define _getFInfo(__ulIdx) \
 ((PPOP3FILEINFO)(pProtoData->_sd_stFList.papFiles[__ulIdx]->ulUser))

#define _isMsgDeleted(__ulIdx) \
 ( (_getFInfo(__ulIdx)->ulFlags & _FILE_FL_DELETED) != 0 )

typedef struct _HOMELOCK {
  BOOL       fFile;
  CHAR       acPath[1];
} HOMELOCK, *PHOMELOCK;

typedef struct _CMD {
  PSZ        pszName;
  ULONG      ulFlags;
  BOOL (*fnCmd)(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
} CMD, *PCMD;


static BOOL cfnQUIT(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnCAPA(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnUSER(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnPASS(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnAPOP(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnAUTH(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnSTLS(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnSTAT(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnLIST(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnNOOP(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnRETR(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnDELE(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnRSET(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnTOP(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnUIDL(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);

static CMD   aCmdList[] =
{
  { "QUIT", _CMD_FL_ANY_STATE,           cfnQUIT },
  { "CAPA", _CMD_FL_ANY_STATE,           cfnCAPA },
  { "USER", _CMD_FL_AUTHORIZATION_STATE, cfnUSER },
  { "PASS", _CMD_FL_AUTHORIZATION_STATE, cfnPASS },
  { "APOP", _CMD_FL_AUTHORIZATION_STATE, cfnAPOP },
  { "AUTH", _CMD_FL_AUTHORIZATION_STATE, cfnAUTH },
  { "STLS", _CMD_FL_AUTHORIZATION_STATE, cfnSTLS },
  { "STAT", _CMD_FL_TRANSACTION_STATE,   cfnSTAT },
  { "LIST", _CMD_FL_TRANSACTION_STATE,   cfnLIST },
  { "NOOP", _CMD_FL_TRANSACTION_STATE,   cfnNOOP },
  { "RETR", _CMD_FL_TRANSACTION_STATE,   cfnRETR },
  { "DELE", _CMD_FL_TRANSACTION_STATE,   cfnDELE },
  { "RSET", _CMD_FL_TRANSACTION_STATE,   cfnRSET },
  { "TOP",  _CMD_FL_TRANSACTION_STATE,   cfnTOP  },
  { "UIDL", _CMD_FL_TRANSACTION_STATE,   cfnUIDL },
  { NULL, NULL }                           // End of list.
};

static PSZ   apszResp[] =
{
  // Successful responses.
  "logged in",                             // 0
  "send password",                         // 1
  "capability list follows",               // 2
  "Begin TLS negotiation now",             // 3
  "message deleted",                       // 4

  // Errors.
  "[SYS/PERM] internal error",             // 5
  "syntax error",                          // 6
  "command received in invalid state",     // 7
  "[AUTH] authorization failure",          // 8
  "command not permitted when TLS active", // 9
  "unknown command",                       // A
  "unknown authentication mechanism",      // B
  "mailbox already locked",                // C
  "no such message",                       // D
  "[AUTH] encrypted password is required"  // E
     // or "This server requires an encrypted connection." ?
     // "Plain text passwords is not allowed." ?
};

// Flag for "-ERR" messages.
#define POP3R_FL_ERR                       0x00010000

// Messages with this flag increase PROTODATA.usBadCommands counter.
#define POP3R_FL_BAD_COMMANDS_CNT          0x00020000

// Messages with this flag increase PROTODATA.usBadLogins counter.
#define POP3R_FL_LOGIN_ATTEMPTS_CNT        0x00040000

// List of messages IDs. Low word of message ID is index for apszResp[].
#define POP3R_OK_LOGGED_IN                 0x00
#define POP3R_OK_SEND_PASS                 0x01
#define POP3R_OK_CAPA_LIST                 0x02
#define POP3R_OK_BEGIN_TLS                 0x03
#define POP3R_OK_MESSAGE_DELETED           0x04
#define POP3R_ERR_INTERNAL_ERROR           (POP3R_FL_ERR | 0x05)
#define POP3R_ERR_SYNTAX_ERROR             \
             (POP3R_FL_ERR | POP3R_FL_BAD_COMMANDS_CNT | 0x06)
#define POP3R_ERR_INVALID_STATE            \
             (POP3R_FL_ERR | POP3R_FL_BAD_COMMANDS_CNT | 0x07)
#define POP3R_ERR_AUTH_FAIL                \
             (POP3R_FL_ERR | POP3R_FL_LOGIN_ATTEMPTS_CNT | 0x08)
#define POP3R_ERR_NOT_ALLOWED_WHEN_TLS     (POP3R_FL_ERR | 0x09)
#define POP3R_ERR_UNKNOWN_COMMAND          \
             (POP3R_FL_ERR | POP3R_FL_BAD_COMMANDS_CNT | 0x0A)
#define POP3R_ERR_UNKNOWN_AUTH             (POP3R_FL_ERR | 0x0B)
#define POP3R_ERR_ALREADY_LOCKED           \
             (POP3R_FL_ERR | POP3R_FL_LOGIN_ATTEMPTS_CNT | 0x0C)
#define POP3R_ERR_NO_SUCH_MESSAGE          (POP3R_FL_ERR | 0x0D)
#define POP3R_ERR_ENCRYPTION_REQUIRED      \
             (POP3R_FL_ERR | POP3R_FL_LOGIN_ATTEMPTS_CNT | 0x0E)

static ULONG           cLockList      = 0;
static ULONG           ulLockListMax  = 0;
static PHOMELOCK       *ppLockList    = NULL;
static HMTX            hmtxLockList   = NULLHANDLE;


static VOID _destroyStateData(PPROTODATA pProtoData);

static BOOL pop3New(PCLNTDATA pClntData)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PCTX       pCtx = netsrvClntGetContext( pClntData );
  CHAR       acBuf[256];

  if ( pCtx == NULL )
    return FALSE;

  if ( imfGenerateMsgId( sizeof(acBuf), acBuf, NULL ) == -1 )
    acBuf[0] = '\0';

  if ( !ctxWriteFmtLn( pCtx, "+OK POP3 server ready %s", acBuf ) )
    return FALSE;

  if ( acBuf[0] != '\0' )
    pProtoData->_sd_pszTimestamp = strdup( acBuf );

  return TRUE;
}

static VOID pop3Destroy(PCLNTDATA pClntData)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         ulIdx;
  LONG          cbPathName;
  CHAR          acFullName[CCHMAXPATH];
  PPOP3FILEINFO pFileInfo;

  cbPathName = wcfgQueryMailRootDir( sizeof(acFullName) - 1, acFullName,
                                     pProtoData->_sd_pszShortPath );
  acFullName[cbPathName] = '\\';
  cbPathName++;

  for( ulIdx = 0; ulIdx < pProtoData->_sd_stFList.ulCount; ulIdx++ )
  {
    pFileInfo = _getFInfo( ulIdx );

    if ( pFileInfo != NULL )
    {
      if ( (pFileInfo->ulFlags & (_FILE_FL_HASH | _FILE_FL_HASHEA)) ==
           _FILE_FL_HASH )
      {
        // We have hash for the message and it wasn't loaded from EA.
        // Store hash to EA (to avoid further calculations).

        strlcpy( &acFullName[cbPathName],
                 pProtoData->_sd_stFList.papFiles[ulIdx]->acName,
                 sizeof(acFullName) - cbPathName );

        utilStoreFileHash( acFullName, _HASH_EA_NAME, UTIL_FILE_HASH_LENGTH,
                           pFileInfo->acHash );
      }

      free( pFileInfo );
      _setFInfo( ulIdx, NULL );
    }
  }

  _destroyStateData( pProtoData );
}


/* ****************************************************************** */
/*                                                                    */
/*                     fnRequest implementation                       */
/*                                                                    */
/* ****************************************************************** */
/*
 *  Main function:
 *    static BOOL pop3Request(PCLNTDATA pClntData, PSZ pszLine)
 */

static VOID _destroyStateData(PPROTODATA pProtoData)
{
  ULONG                ulIdx;
  PPOP3FILEINFO        pFileInfo;

  switch( pProtoData->ulState )
  {
    case _STATE_AUTHORIZATION: 
      if ( pProtoData->_sd_pszTimestamp != NULL )
      {
        free( pProtoData->_sd_pszTimestamp );
        pProtoData->_sd_pszTimestamp = NULL;
      }

      if ( pProtoData->_sd_pszUser != NULL )
      {
        free( pProtoData->_sd_pszUser );
        pProtoData->_sd_pszUser = NULL;
      }

      pProtoData->_sd_ulAuthMechanism = 0;
      break;

    case _STATE_TRANSACTION:
      for( ulIdx = 0; ulIdx < pProtoData->_sd_stFList.ulCount; ulIdx++ )
      {
        pFileInfo = _getFInfo( ulIdx );
        if ( pFileInfo != NULL )
          free( pFileInfo );
      }
      msListDestroy( &pProtoData->_sd_stFList );

      if ( pProtoData->_sd_pszShortPath != NULL )
      {
        pop3Lock( pProtoData->_sd_pszShortPath, FALSE );
        free( pProtoData->_sd_pszShortPath );
      }

      break;
  }
}

// Returns TRUE if plain-text logins allowed or it's an encrypted connection or
// client is a localhost.
static BOOL _clntPlaintextLoginAllowed(PCLNTDATA pClntData)
{
  ULONG                ulUser = (ULONG)netsrvClntGetUserPtr( pClntData );
  struct in_addr       stAddr;

  return ( (ulUser & POP3_LOGINDISABLED) == 0 ) ||
         netsrvClntIsTLSMode( pClntData ) ||
         ( netsrvClntGetRemoteAddr( pClntData, &stAddr, NULL ) &&
           ( stAddr.s_addr == 0x0100007F /* 127.0.0.1 */ ) );
}

static BOOL _clntResp(PCLNTDATA pClntData, ULONG ulCode)
{
  PSZ        pszStatus;
  PCTX       pCtx;
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  if ( (ulCode & POP3R_FL_ERR) != 0 )
    pszStatus = "-ERR";
  else
  {
    pszStatus = "+OK";
    pProtoData->usBadCommands = 0;
  }

  if ( (ulCode & POP3R_FL_BAD_COMMANDS_CNT) != 0 )
  {
    pProtoData->usBadCommands++;
    if ( pProtoData->usBadCommands >= _MAX_BAD_COMMANDS )
    {
      netsrvClntLog( pClntData, 3, "Too many \"ERR\" replies" );
      return FALSE;
    }
  }

  if ( (ulCode & POP3R_FL_LOGIN_ATTEMPTS_CNT) != 0 )
  {
    ULONG      ulLimit = wcfgQueryBadPasswordLimit();

    if ( ulLimit != 0 )
    {
      pProtoData->usBadLogins++;
      if ( pProtoData->usBadLogins >= ulLimit )
      {
        netsrvClntLog( pClntData, 3, "Too many login attempts (%u)",
                       pProtoData->usBadLogins );
        return FALSE;
      }
    }
  }

  if ( ulCode == POP3R_ERR_AUTH_FAIL )
    netsrvSetOutputDelay( pClntData, _AUTH_FAIL_RESP_DELAY );

  ulCode &= 0xFFFF;

  pCtx = netsrvClntGetContext( pClntData );
  if ( pCtx == NULL )
    return FALSE;

  if ( ulCode >= ARRAYSIZE( apszResp ) )
    return ctxWriteStrLn( pCtx, pszStatus );

  return ctxWriteFmtLn( pCtx, "%s %s", pszStatus, apszResp[ulCode] );
}

static ULONG _clntAuthenticated(PCLNTDATA pClntData, PSZ pszShortPath,
                                PSZ pszLogMethod)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  LONG          lIdx;
  PPOP3FILEINFO pFileInfo;

  if ( pProtoData->ulState != _STATE_AUTHORIZATION )
    return POP3R_ERR_INVALID_STATE;

  if ( !pop3Lock( pszShortPath, TRUE ) )
  {
    netsrvClntLog( pClntData, 5, "Home directory %s already locked",
                   pszShortPath );
    return POP3R_ERR_ALREADY_LOCKED;
  }

  _destroyStateData( pProtoData );

  netsrvClntLog( pClntData, 3, "User is logged in (%s): %s",
                 pszLogMethod, pszShortPath );

  if ( !msReadMsgList( pszShortPath, TRUE, &pProtoData->_sd_stFList ) )
  {
    pop3Lock( pszShortPath, FALSE );
    netsrvClntLog( pClntData, 0, "The file list could not be read: %s",
                   pszShortPath );
    return POP3R_ERR_INTERNAL_ERROR;
  }

  pProtoData->_sd_pszShortPath = strdup( pszShortPath );
  if ( pProtoData->_sd_pszShortPath == NULL )
  {
    pop3Lock( pszShortPath, FALSE );
    return POP3R_ERR_INTERNAL_ERROR;
  }
  pProtoData->ulState = _STATE_TRANSACTION;

  // Set information data for the each file record.
  for( lIdx = pProtoData->_sd_stFList.ulCount - 1; lIdx >= 0; lIdx-- )
  {
    pFileInfo = malloc( sizeof(POP3FILEINFO) );
    if ( pFileInfo == NULL )
    {
      msListRemoveIdx( &pProtoData->_sd_stFList, lIdx );
      continue;
    }

    pFileInfo->ulFlags = 0;
    _setFInfo( lIdx, pFileInfo );
  }

  return POP3R_OK_LOGGED_IN;
}

static BOOL _clntAuthResp(PCLNTDATA pClntData, ULONG cbInput, PCHAR pcInput)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         cbB64Dec;
  PCHAR         pcB64Dec;
  PSZ           pszUser = NULL;
  LONG          cbBuf;
  CHAR          acBuf[CCHMAXPATH];
  ULONG         ulResp = POP3R_ERR_AUTH_FAIL;
  ULONG         ulAuthMechanism = pProtoData->_sd_ulAuthMechanism;
  PSZ           pszLogMethod = NULL;

  pProtoData->_sd_ulAuthMechanism = 0;
  if ( !utilB64Dec( cbInput, pcInput, &cbB64Dec, &pcB64Dec ) )
    ulResp = POP3R_ERR_SYNTAX_ERROR;
  else
  {
    pcInput = pcB64Dec;
    cbInput = cbB64Dec;

    switch( ulAuthMechanism )
    {
      case _AUTH_PLAIN:
        pszLogMethod = "AUTH PLAIN";
        {
          PSZ          pszPassword;

          // Client response:
          //   [authorize-id] NUL authenticate-id NUL password

          pszUser = memchr( pcInput, '\0', cbInput - 1 );
          if ( pszUser != NULL )
          {
            pszUser++;

            pszPassword = memchr( pszUser, '\0',
                                  &pcInput[cbInput] - (PCHAR)pszUser );
            if ( pszPassword != NULL )
            {
              pszPassword++;

              cbBuf = wcfgQueryUser( pszUser, pszPassword, WC_USRFL_ACTIVE,
                                     sizeof(acBuf), acBuf );

              if ( cbBuf == -1 )                // acBuf too small?
                ulResp = POP3R_ERR_INTERNAL_ERROR;
              else if ( cbBuf != 0 )
                ulResp = _clntAuthenticated( pClntData, acBuf, pszLogMethod );
            } // if ( pszPassword != NULL )
          }  // if ( pszUser != NULL )
        }
        break;

      case _AUTH_CRAMMD5:
        pszLogMethod = "AUTH CRAM-MD5";
        if ( pProtoData->_sd_pszTimestamp == NULL )
          ulResp = POP3R_ERR_INTERNAL_ERROR;
        else
        {
          PWCFINDUSR   pFind;
          PCHAR        pcRef, pcDst;
          CHAR         acRef[EVP_MAX_MD_SIZE];
          CHAR         acHexRef[(2 * EVP_MAX_MD_SIZE) + 1];
          int          cbRef;

          if ( !utilStrCutWord( (PSZ *)&pcInput, &pszUser ) )
            break;

          pFind = wcfgFindUserBegin( pszUser, WC_USRFL_ACTIVE );
          if ( pFind == NULL )
            ulResp = POP3R_ERR_INTERNAL_ERROR;
          else
          {
            while( wcfgFindUser( pFind ) )
            {
              // Create a reference hash for found user.
              pcRef = HMAC( EVP_md5(),
                            pFind->pszPassword, strlen( pFind->pszPassword ),
                            pProtoData->_sd_pszTimestamp,
                            strlen( pProtoData->_sd_pszTimestamp ),
                            acRef, &cbRef );
              if ( pcRef == NULL )
              {
                debugCP( "WTF?" );
                continue;
              }

              // Convert out reference hash to hex string.
              for( pcDst = acHexRef; cbRef != 0; pcRef++, pcDst += 2, cbRef-- )
                sprintf( pcDst, "%02x", *pcRef & 0xFF );
              *pcDst = '\0';

              // Compare reference with user's digest.
              if ( strcmp( pcInput, acHexRef ) == 0 )
              {
                ulResp = _clntAuthenticated( pClntData, pFind->acHomeDir,
                                             pszLogMethod );
                break;
              }
            }  // while( wcfgFindUser( pFind ) )
            wcfgFindUserEnd( pFind );
          }  // if ( pFind == NULL )
        }
        break;
    }  // switch( ulAuthMechanism )

    if ( ( ulResp == POP3R_ERR_AUTH_FAIL ) && ( pszUser != NULL ) )
      netsrvClntLog( pClntData, 3, "Authentication failed (%s), user \"%s\"",
                     pszLogMethod, pszUser );

    free( pcB64Dec );
  }

  return _clntResp( pClntData, ulResp );
}

static BOOL _clntSendMsg(PCLNTDATA pClntData, ULONG ulMsg, ULONG ulNumLines,
                         PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         ulLine = 0;
  FILE          *pfMsg;
  LONG          cbBuf;
  CHAR          acBuf[1032];
  BOOL          fInHeader = TRUE;

  cbBuf = wcfgQueryMailRootDir( sizeof(acBuf) - 1, acBuf,
                                pProtoData->_sd_pszShortPath );
  if ( cbBuf == -1 )
    return _clntResp( pClntData, POP3R_ERR_INTERNAL_ERROR );
  acBuf[cbBuf] = '\\';
  cbBuf++;

  ulMsg--;
  if ( ( ulMsg >= pProtoData->_sd_stFList.ulCount ) ||
       _isMsgDeleted( ulMsg ) )
    return _clntResp( pClntData, POP3R_ERR_NO_SUCH_MESSAGE );

  strlcpy( &acBuf[cbBuf], pProtoData->_sd_stFList.papFiles[ulMsg]->acName,
           sizeof(acBuf) - cbBuf );

  pfMsg = fopen( acBuf, "rt" );
  if ( pfMsg == NULL )
  {
    netsrvClntLog( pClntData, 3, "Error opening %s", acBuf );
    return _clntResp( pClntData, POP3R_ERR_INTERNAL_ERROR );
  }

  ctxWrite( pCtx, -1, "+OK message follows\r\n" );

  while( TRUE )
  {
    if ( fgets( acBuf, sizeof(acBuf) - 2, pfMsg ) == NULL )
      break;

    cbBuf = strlen( acBuf );
    if ( cbBuf == 0 )
    {
      debugCP( "WTF?" );
      continue;
    }

    if ( acBuf[cbBuf - 1] == '\n' )
      cbBuf--;

    if ( !fInHeader )
    {
      if ( ulLine == ulNumLines )
        break;
      ulLine++;
    }
    else if ( cbBuf == 0 )
      fInHeader = FALSE;

    acBuf[cbBuf++] = '\r';
    acBuf[cbBuf++] = '\n';
    if ( acBuf[0] == '.' )
      ctxWrite( pCtx, 1, "." );

    ctxWrite( pCtx, cbBuf, acBuf );
  }

  fclose( pfMsg );

  return ctxWrite( pCtx, 3, ".\r\n" );
}

static BOOL cfnQUIT(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  if ( ( pProtoData->ulState == _STATE_TRANSACTION ) &&
       ( pProtoData->_sd_stFList.ulCount != 0 ) )
  {
    /*
       [RFC 1939] 6. The UPDATE State
       When the client issues the QUIT command from the TRANSACTION state, the
       POP3 session enters the UPDATE state.
     */
    LONG               lIdx;
    PPOP3FILEINFO      pFileInfo;
    MSLIST             stDelList;

    // We will collect records of deleted messages to stDelList list.
    stDelList.ulCount = 0;
    stDelList.papFiles = malloc( pProtoData->_sd_stFList.ulCount *
                                  sizeof(PMSFILE) );
    if ( stDelList.papFiles != NULL )
    {
      // Move all deleted files records to the new list stDelList.
      // Destroy PPOP3FILEINFO objects for files which will be removed from disk.
      for( lIdx = pProtoData->_sd_stFList.ulCount - 1; lIdx >= 0; lIdx-- )
      {
        pFileInfo = _getFInfo( lIdx );
        if ( (pFileInfo->ulFlags & _FILE_FL_DELETED) == 0 )
          continue;

        // Destroy PPOP3FILEINFO object.
        free( pFileInfo );
        _setFInfo( lIdx, NULL );

        // Move record to the temporary list.

        stDelList.papFiles[stDelList.ulCount] =
          pProtoData->_sd_stFList.papFiles[lIdx];
        stDelList.ulCount++;

        pProtoData->_sd_stFList.ulCount--;
        pProtoData->_sd_stFList.papFiles[lIdx] =
          pProtoData->_sd_stFList.papFiles[pProtoData->_sd_stFList.ulCount];
      }

      // Delete files from disk.
      fsDeleteFiles( pProtoData->_sd_pszShortPath, &stDelList );
      msListDestroy( &stDelList );
    }  // if ( stDelList.papFiles != NULL )

    ctxWriteFmtLn( pCtx, "+OK Bye (%lu messages left)",
                   pProtoData->_sd_stFList.ulCount );
  }
  else
    ctxWrite( pCtx, 9, "+OK Bye\r\n" );

  return FALSE;  // End session and close connectin.
}

static BOOL cfnCAPA(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  /*
    [RFC 2449] 5.  The CAPA Command
    Capabilities available in the AUTHORIZATION state MUST be announced in
    both states.
   */

  _clntResp( pClntData, POP3R_OK_CAPA_LIST );
  ctxWrite( pCtx, -1,
      "TOP\r\n"
      "UIDL\r\n"
      "PIPELINING\r\n"
      "RESP-CODES\r\n"
      /* The RESP-CODES capability indicates that any response text issued
         by this server which begins with an open square bracket ("[") is
         an extended response code (see section 8). */
      "AUTH-RESP-CODE\r\n"
      /* The AUTH-RESP-CODE capability indicates that the server includes
         the AUTH response code with any authentication error caused by a
         problem with the user's credentials. */
  );

  if ( netsrvClntIsTLSAvailable( pClntData ) )
    ctxWrite( pCtx, -1, "STLS\r\n" );

  if ( _clntPlaintextLoginAllowed( pClntData ) )
  {
    ctxWrite( pCtx, -1, 
      "USER\r\n"
      "SASL CRAM-MD5 PLAIN\r\n" );
  }
  else
    ctxWrite( pCtx, -1, "SASL CRAM-MD5\r\n" );

  return ctxWrite( pCtx, -1, ".\r\n" );
}

static BOOL cfnUSER(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszUser;
  ULONG         ulResp;

  if ( !_clntPlaintextLoginAllowed( pClntData ) )
    ulResp = POP3R_ERR_ENCRYPTION_REQUIRED;
  else if ( !utilStrCutComp( &pszArgLine, &pszUser ) )
    ulResp = POP3R_ERR_SYNTAX_ERROR;
  else
  {
    if ( pProtoData->_sd_pszUser != NULL )
      free( pProtoData->_sd_pszUser );

    pProtoData->_sd_pszUser = strdup( pszUser );
    if ( pProtoData->_sd_pszUser == NULL )
      return FALSE;

    ulResp = POP3R_OK_SEND_PASS;
  }

  return _clntResp( pClntData, ulResp );
}

static BOOL cfnPASS(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszPass;
  CHAR          acBuf[CCHMAXPATH];
  LONG          cbBuf;
  ULONG         ulResp;

  if ( pProtoData->_sd_pszUser == NULL )
    ulResp = POP3R_ERR_INVALID_STATE;
  else if ( !utilStrCutComp( &pszArgLine, &pszPass ) )
    ulResp = POP3R_ERR_AUTH_FAIL;
  else
  {
    cbBuf = wcfgQueryUser( pProtoData->_sd_pszUser, pszPass, WC_USRFL_ACTIVE,
                           sizeof(acBuf), acBuf );

    if ( cbBuf == -1 )                 // acBuf too small?
      ulResp = POP3R_ERR_INTERNAL_ERROR;
    else if ( cbBuf == 0 )
    {
      netsrvClntLog( pClntData, 3, "User name \"%s\" or password rejected",
                     pProtoData->_sd_pszUser );
      ulResp = POP3R_ERR_AUTH_FAIL;
    }
    else
      ulResp = _clntAuthenticated( pClntData, acBuf, "USER/PASS" );
  }

  return _clntResp( pClntData, ulResp );
}

static BOOL cfnAPOP(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszUser;
  PSZ           pszDigest;
  PWCFINDUSR    pFind;
  ULONG         ulResp = POP3R_ERR_AUTH_FAIL;
  MD5_CTX       md5ctx;
  UCHAR         acMD5[MD5_DIGEST_LENGTH];
  CHAR          acHexRef[(2 * MD5_DIGEST_LENGTH) + 1];    // Text from acMD5[].
  PCHAR         pcDst;
  ULONG         ulIdx;

  if ( pProtoData->_sd_pszTimestamp == NULL )
    return _clntResp( pClntData, POP3R_ERR_INVALID_STATE );

  if ( !utilStrCutComp( &pszArgLine, &pszUser ) ||
       !utilStrCutComp( &pszArgLine, &pszDigest ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  pFind = wcfgFindUserBegin( pszUser, WC_USRFL_ACTIVE );
  while( wcfgFindUser( pFind ) )
  {
    // Make MD5 hash from timestamp + password.
    MD5_Init( &md5ctx );
    MD5_Update( &md5ctx, pProtoData->_sd_pszTimestamp,
                strlen( pProtoData->_sd_pszTimestamp ) );
    MD5_Update( &md5ctx, pFind->pszPassword, strlen( pFind->pszPassword ) );
    MD5_Final( acMD5, &md5ctx );

    // Convert out reference hash to hex string.
    for( pcDst = acHexRef, ulIdx = 0; ulIdx < MD5_DIGEST_LENGTH;
         ulIdx++, pcDst += 2 )
      sprintf( pcDst, "%02x", acMD5[ulIdx] & 0xFF );
    *pcDst = '\0';

    // Compare reference with user's digest.
    if ( strcmp( pszDigest, acHexRef ) == 0 )
    {
      ulResp = _clntAuthenticated( pClntData, pFind->acHomeDir, "APOP" );
      break;
    }
  }
  wcfgFindUserEnd( pFind );

  if ( ulResp == POP3R_ERR_AUTH_FAIL )
    netsrvClntLog( pClntData, 3, "Authentication failed (APOP), user \"%s\"",
                   pszUser );

  return _clntResp( pClntData, ulResp );
}

static BOOL cfnAUTH(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszMechanism;
  PSZ           pszInitResp = NULL;

  if ( !utilStrCutWord( &pszArgLine, &pszMechanism ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  if ( !utilStrCutWord( &pszArgLine, &pszInitResp ) )
    pszInitResp = NULL;
    // pszInitResp: NULL or '=' or Base64 string.

  switch( utilStrWordIndex( "PLAIN CRAM-MD5", -1, pszMechanism ) )
  {
    case 0:  // PLAIN
      if ( !_clntPlaintextLoginAllowed( pClntData ) )
        return _clntResp( pClntData, POP3R_ERR_ENCRYPTION_REQUIRED );

      pProtoData->_sd_ulAuthMechanism = _AUTH_PLAIN;

      if ( pszInitResp == NULL )
        return ctxWrite( pCtx, 4, "+ \r\n" );      // Client should send data

      return _clntAuthResp( pClntData, strlen( pszInitResp ), pszInitResp );

    case 1:  // CRAM-MD5
      {
        CHAR           acBuf[512];
        LONG           cbTimestamp, cbBuf;
        PSZ            pszTimestamp;
        PCHAR          pcBuf;
        BOOL           fRes;

        pProtoData->_sd_ulAuthMechanism = _AUTH_CRAMMD5;

        cbTimestamp = imfGenerateMsgId( sizeof(acBuf), acBuf, NULL );
        if ( ( cbTimestamp == -1 ) ||
             ( (pszTimestamp = strdup( acBuf )) == NULL ) )
          return _clntResp( pClntData, POP3R_ERR_INTERNAL_ERROR );

        if ( pProtoData->_sd_pszTimestamp != NULL )
          free( pProtoData->_sd_pszTimestamp );
        pProtoData->_sd_pszTimestamp = pszTimestamp;
        
        if ( !utilB64Enc( cbTimestamp, pszTimestamp, &cbBuf, &pcBuf ) )
        {
          debug( "utilB64Enc() failed" );
          return FALSE;
        }

        fRes = ctxWriteFmtLn( pCtx, "+ %s", pcBuf );
        free( pcBuf );

        return fRes;
      }

    case -1: // Unknown method.
      return _clntResp( pClntData, POP3R_ERR_UNKNOWN_AUTH );
  }

  return FALSE;
}

static BOOL cfnSTLS(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         ulResp;

  if ( !netsrvClntIsTLSAvailable( pClntData ) )
    ulResp = POP3R_ERR_UNKNOWN_COMMAND;
  else if ( pProtoData->ulState != _STATE_AUTHORIZATION )
    ulResp = POP3R_ERR_INVALID_STATE;
  else if ( netsrvClntIsTLSMode( pClntData ) )
    ulResp = POP3R_ERR_NOT_ALLOWED_WHEN_TLS;
  else if ( netsrvClntStartTLS( pClntData ) )
  {
    ulResp = POP3R_OK_BEGIN_TLS;
    netsrvClntLog( pClntData, 5, "STLS" );
  }
  else
    ulResp = POP3R_ERR_INTERNAL_ERROR;

  return _clntResp( pClntData, ulResp );
}

static BOOL cfnSTAT(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         ulIdx, ulCount = 0;
  ULLONG        ullSize = 0;

  for( ulIdx = 0; ulIdx < pProtoData->_sd_stFList.ulCount; ulIdx++ )
  {
    if ( !_isMsgDeleted( ulIdx ) )
    {
      ulCount++;
      ullSize += pProtoData->_sd_stFList.papFiles[ulIdx]->ullSize;
    }
  }

  return ctxWriteFmtLn( pCtx, "+OK %lu %llu", ulCount, ullSize );
}

static BOOL cfnLIST(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszMsg;
  ULONG         ulMsg, ulIdx;
  PCHAR         pcEnd;

  if ( utilStrCutWord( (PSZ *)&pszArgLine, &pszMsg ) )
  {
    ulMsg = strtoul( (PCHAR)pszMsg, &pcEnd, 10 );
    if ( ( pcEnd == (PCHAR)pszMsg ) || ( ulMsg == 0 ) )
      return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

    if ( ( ulMsg > pProtoData->_sd_stFList.ulCount ) ||
         _isMsgDeleted( ulMsg - 1 ) )
      return _clntResp( pClntData, POP3R_ERR_NO_SUCH_MESSAGE );

    return ctxWriteFmtLn( pCtx, "+OK %lu %llu", ulMsg,
                          pProtoData->_sd_stFList.papFiles[ulMsg - 1]->ullSize );
  }

  ctxWriteFmtLn( pCtx, "+OK %lu total messages",
                 pProtoData->_sd_stFList.ulCount );

  for( ulIdx = 0; ulIdx < pProtoData->_sd_stFList.ulCount; ulIdx++ )
  {
    if ( !_isMsgDeleted( ulIdx ) )
      ctxWriteFmtLn( pCtx, "%lu %llu", ulIdx + 1,
                     pProtoData->_sd_stFList.papFiles[ulIdx]->ullSize );
  }

  return ctxWrite( pCtx, 3, ".\r\n" );
}

static BOOL cfnNOOP(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  return ctxWrite( pCtx, 6, "+OK \r\n" );
}

static BOOL cfnRETR(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PSZ           pszVal;
  ULONG         ulMsg;
  PCHAR         pcEnd;

  if ( !utilStrCutWord( (PSZ *)&pszArgLine, &pszVal ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  ulMsg = strtoul( (PCHAR)pszVal, &pcEnd, 10 );
  if ( ( pcEnd == (PCHAR)pszVal ) || ( ulMsg == 0 ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  return _clntSendMsg( pClntData, ulMsg, ULONG_MAX, pCtx );
}

static BOOL cfnDELE(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszMsg;
  ULONG         ulMsg;
  PCHAR         pcEnd;

  if ( !utilStrCutWord( (PSZ *)&pszArgLine, &pszMsg ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  ulMsg = strtoul( (PCHAR)pszMsg, &pcEnd, 10 );
  if ( ( pcEnd == (PCHAR)pszMsg ) || ( ulMsg == 0 ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  if ( ( ulMsg > pProtoData->_sd_stFList.ulCount ) &&
       _isMsgDeleted( ulMsg - 1 ) )
    return _clntResp( pClntData, POP3R_ERR_NO_SUCH_MESSAGE );

  _getFInfo( ulMsg - 1 )->ulFlags |= _FILE_FL_DELETED;

  return _clntResp( pClntData, POP3R_OK_MESSAGE_DELETED );
}

static BOOL cfnRSET(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         ulIdx;
  ULLONG        ullSize = 0;

  for( ulIdx = 0; ulIdx < pProtoData->_sd_stFList.ulCount; ulIdx++ )
  {
    _getFInfo( ulIdx )->ulFlags &= ~_FILE_FL_DELETED;
    ullSize += pProtoData->_sd_stFList.papFiles[ulIdx]->ullSize;
  }

  return ctxWriteFmtLn( pCtx, "+OK maildrop has %lu messages (%llu octets)",
                        pProtoData->_sd_stFList.ulCount, ullSize );
}

static BOOL cfnTOP(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PSZ           pszVal;
  ULONG         ulMsg, ulNumLines;
  PCHAR         pcEnd;

  if ( !utilStrCutWord( (PSZ *)&pszArgLine, &pszVal ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  ulMsg = strtoul( (PCHAR)pszVal, &pcEnd, 10 );
  if ( ( pcEnd == (PCHAR)pszVal ) || ( ulMsg == 0 ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  if ( !utilStrCutWord( (PSZ *)&pszArgLine, &pszVal ) )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  ulNumLines = strtoul( (PCHAR)pszVal, &pcEnd, 10 );
  if ( pcEnd == (PCHAR)pszVal )
    return _clntResp( pClntData, POP3R_ERR_SYNTAX_ERROR );

  return _clntSendMsg( pClntData, ulMsg, ulNumLines, pCtx );
}


// BOOL cfnUIDL(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)

typedef struct _GETHASHDATA {
  PPROTODATA           pProtoData;
  LONG                 cbPathName;
  CHAR                 acFullName[CCHMAXPATH];
  CHAR                 acHash[UTIL_FILE_HASH_STR_SIZE];        // output
} GETHASHDATA, *PGETHASHDATA;

static BOOL _getHash(PGETHASHDATA pData, ULONG ulIdx)
{
  PPROTODATA           pProtoData = pData->pProtoData;
  PPOP3FILEINFO        pFileInfo;
  BOOL                 fFromEA;

  pFileInfo = _getFInfo( ulIdx );
  if ( (pFileInfo->ulFlags & _FILE_FL_HASH) == 0 )
  {
    if ( pData->cbPathName <= 0 )
    {
      pData->cbPathName = wcfgQueryMailRootDir( sizeof(pData->acFullName) - 1,
                             pData->acFullName, pProtoData->_sd_pszShortPath );
      if ( pData->cbPathName == -1 )
        return FALSE;

      pData->acFullName[pData->cbPathName] = '\\';
      pData->cbPathName++;
    }

    strlcpy( &pData->acFullName[pData->cbPathName],
             pProtoData->_sd_stFList.papFiles[ulIdx]->acName,
             sizeof(pData->acFullName) - pData->cbPathName );

    if ( utilGetFileHash( pData->acFullName, _HASH_EA_NAME,
                sizeof(pFileInfo->acHash), pFileInfo->acHash, &fFromEA ) <= 0 )
      return FALSE;

    pFileInfo->ulFlags = fFromEA ? (_FILE_FL_HASH | _FILE_FL_HASHEA)
                                 : _FILE_FL_HASH;
  }

  utilFileHashToStr( sizeof(pFileInfo->acHash), pFileInfo->acHash,
                     sizeof(pData->acHash), pData->acHash );

  return TRUE;
}


static BOOL cfnUIDL(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PSZ           pszVal;
  PCHAR         pcEnd;
  ULONG         ulMsg;
  ULONG         ulIdx;
  GETHASHDATA   stData;

  stData.pProtoData = pProtoData;
  stData.cbPathName = 0;

  if ( utilStrCutWord( (PSZ *)&pszArgLine, &pszVal ) )
  {
    ulMsg = strtoul( (PCHAR)pszVal, &pcEnd, 10 );

    if ( ( pcEnd == (PCHAR)pszVal ) || ( ulMsg == 0 ) )
      ulMsg = POP3R_ERR_SYNTAX_ERROR;
    else if ( ( ulMsg > pProtoData->_sd_stFList.ulCount ) ||
              _isMsgDeleted( ulMsg - 1 ) )
      ulMsg = POP3R_ERR_NO_SUCH_MESSAGE;
    else if ( !_getHash( &stData, ulMsg - 1 ) )
      ulMsg = POP3R_ERR_INTERNAL_ERROR;
    else
      return ctxWriteFmtLn( pCtx, "+OK %lu %s", ulMsg, stData.acHash );

    return _clntResp( pClntData, ulMsg );
  }

  ctxWrite( pCtx, 14, "+OK messages\r\n" );

  for( ulIdx = 0; ulIdx < pProtoData->_sd_stFList.ulCount; ulIdx++ )
  {
    if ( _getHash( &stData, ulIdx ) )
      ctxWriteFmtLn( pCtx, "%lu %s", ulIdx + 1, stData.acHash );
  }

  return ctxWrite( pCtx, 3, ".\r\n" );
}


static BOOL pop3Request(PCLNTDATA pClntData, LONG cbInput, PCHAR pcInput)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PCTX          pCtx = netsrvClntGetContext( pClntData );
  PSZ           pszCmd;
  PCMD          pCmd;

  // Authentication protocol.
  if ( ( pProtoData->ulState == _STATE_AUTHORIZATION ) &&
       ( pProtoData->_sd_ulAuthMechanism != 0 ) )
  {
    if ( cbInput > 1 )
    {
      if ( pcInput[0] == '*' )
      {
        pProtoData->_sd_ulAuthMechanism = 0;
        return ctxWrite( pCtx, -1, "+ERR canceled\r\n" );
      }
      return _clntAuthResp( pClntData, cbInput, pcInput );
    }
    return FALSE;
  }

  // Read command from the input data.

  if ( ( cbInput == 0 ) || !utilStrCutWord( (PSZ *)&pcInput, &pszCmd ) )
    // Empty line.
    return TRUE;

  for( pCmd = aCmdList; pCmd->pszName != NULL; pCmd++ )
  {
    if ( stricmp( pCmd->pszName, pszCmd ) == 0 )
      break;
  }

  if ( pCmd->pszName == NULL )
    return _clntResp( pClntData, POP3R_ERR_UNKNOWN_COMMAND );

  if ( ( ( pProtoData->ulState == _STATE_AUTHORIZATION ) &&
         ( (pCmd->ulFlags & _CMD_FL_AUTHORIZATION_STATE) == 0 ) ) ||
       ( ( pProtoData->ulState == _STATE_TRANSACTION ) &&
         ( (pCmd->ulFlags & _CMD_FL_TRANSACTION_STATE) == 0 ) ) )
    return _clntResp( pClntData, POP3R_ERR_INVALID_STATE );

  // Call command routine.

  return pCmd->fnCmd( pClntData, (PSZ)pcInput, pCtx );
}


// Public routines.

BOOL pop3Init()
{
  ULONG      ulRC;

  ulRC = DosCreateMutexSem( NULL, &hmtxLockList, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  return TRUE;
}

VOID pop3Done()
{
  ULONG      ulRC, ulIdx;

  ulRC = DosCloseMutexSem( hmtxLockList );
  if ( ulRC != NO_ERROR )
    debug( "DosCloseMutexSem(), rc = %u", ulRC );

  if ( ppLockList != NULL )
  {
    for( ulIdx = 0; ulIdx < cLockList; ulIdx++ )
      if ( ppLockList[ulIdx] != NULL )
        free( ppLockList[ulIdx] );

    free( ppLockList );
  }
}

BOOL pop3Lock(PSZ pszHomePath, BOOL fLock)
{
  ULONG      ulIdx, ulRC;
  BOOL       fRes = FALSE;
  CHAR       acLockFile[CCHMAXPATH];
  PHOMELOCK  pHomeLock;
  HFILE      hLockFile;
  BOOL       fLockFile;
  LONG       cbPathname;

  ulRC = DosRequestMutexSem( hmtxLockList, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  for( ulIdx = 0; ulIdx < cLockList; ulIdx++ )
  {
    if ( stricmp( ppLockList[ulIdx]->acPath, pszHomePath ) == 0 )
    {
      fRes = TRUE;
      break;
    }
  }

  fRes = ( fRes != fLock );
  if ( fRes )
  do
  {
    // Name for the Weasel lock file.
    cbPathname = wcfgQueryMailRootDir(
                            sizeof(acLockFile) - strlen(_WEASEL_LOCK_FILE) - 1,
                            acLockFile, pszHomePath );
    if ( cbPathname != - 1 )
    {
      acLockFile[cbPathname] = '\\';
      cbPathname++;
      strcpy( &acLockFile[cbPathname], _WEASEL_LOCK_FILE );
    }

    if ( fLock )
    {
      // Check/create Weasel lock file.
      fLockFile = FALSE;
      if ( fGlWCfgPOP3Enabled )  // We use lock files only for Weasel.
      {
        ulRC = DosOpenL( acLockFile, &hLockFile, &ulIdx, 0, FILE_NORMAL,
                 OPEN_ACTION_CREATE_IF_NEW | OPEN_ACTION_FAIL_IF_EXISTS,
                 OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                 OPEN_SHARE_DENYREADWRITE | OPEN_ACCESS_WRITEONLY, NULL );
        if ( ulRC == ERROR_OPEN_FAILED )
        {
          // File already exists, locked by Weasel.
          DosReleaseMutexSem( hmtxLockList );
          return FALSE;
        }

        if ( ulRC == NO_ERROR )
        {
          fLockFile = TRUE;
          DosClose( hLockFile );
        }
      }

      pHomeLock = malloc( sizeof(HOMELOCK) + strlen( pszHomePath ) );
      if ( pHomeLock == NULL )
        break;
      strcpy( pHomeLock->acPath, pszHomePath );
      pHomeLock->fFile = fLockFile;

      if ( cLockList == ulLockListMax )
      {
        PHOMELOCK      *ppNew = realloc( ppLockList,
                                          (cLockList+8) * sizeof(PHOMELOCK) );

        if ( ppNew == NULL )
        {
          if ( fLockFile )
            DosDelete( acLockFile );

          free( pHomeLock );
          fRes = FALSE;
          break;
        }
        ppLockList = ppNew;
        ulLockListMax += 8;
      }

      ppLockList[cLockList] = pHomeLock;
      cLockList++;
    }  // if ( fLock )
    else
    {
      // Delete lock file only if _we_ created this.
      if ( ppLockList[ulIdx]->fFile )
        // File was created by IMAPD, delete it.
        DosDelete( acLockFile );

      cLockList--;
      free( ppLockList[ulIdx] );
      ppLockList[ulIdx] = ppLockList[cLockList];
    }
  }
  while( FALSE );

  DosReleaseMutexSem( hmtxLockList );

  return fRes;
}



// Protocol handler.

NSPROTO stProtoPOP3 = {
  sizeof(PROTODATA),   // cbProtoData
  "POP3",              // acLogId
  1000 * 60 * 10,      // ulTimeout
  0,                   // ulMaxClients
  pop3New,             // fnNew
  pop3Destroy,         // fnDestroy
  pop3Request,         // fnRequest
  NULL,                // fnReadyToSend
  NULL                 // fnIdle
};
