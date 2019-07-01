/*
   IMAP4 protocol implementation.

   [Future]: CONDSTORE extension - RFC 4551
             QRESYNC extension - RFC 5162
             SEARCHRES extension - RFC 5182
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <openssl/hmac.h>
#define INCL_DOSPROCESS
#include <os2.h>
#include "linkseq.h"
#include "utils.h"
#include "context.h"
#include "storage.h"
#include "imapfs.h"
#include "message.h"
#include "wcfg.h"
#include "log.h"
#include "imap.h"
#include "debug.h"               // Should be last.

extern ULONG cmdSearch(PUHSESS pUHSess, PCTX pCtx, BOOL fUID, PSZ pszLine);

// Delay before "authorization failure" response (msec).
#define _AUTH_FAIL_RESP_DELAY    7000

// Delay before "BAD" response (msec).
#define _BAD_RESP_DELAY          2000

// _MAX_BAD_COMMANDS
// Client will be disconnected after _MAX_BAD_COMMANDS consecutive "BAD"
// responses.
#define _MAX_BAD_COMMANDS        4

// _MAXBODYCACHE
// Number of cached messages context in session for command FETCH
// (BODY[...]<n1,n2>)
// I do not think we need more than one.
// The cache is useful for cases when a client sends a series of partial fetch
// requests for same message, to avoid read message file from the beginning on
// each request.
#define _MAXBODYCACHE            1

#define _STATE_NOTAUTHENTICATED  0
#define _STATE_AUTHENTICATED     1
#define _STATE_SELECTED          2
#define _STATE_IDLE              3

// _CMDMAXARG - maximum number of the command arguments.
#define _CMDMAXARG               4

#define _AUTH_PLAIN              0
#define _AUTH_CRAMMD5            1

typedef struct _AUTH {
  ULONG      ulType;             // _AUTH_xxxxx
  CHAR       acCmdId[32];
} AUTH, *PAUTH;

typedef struct _BODYCACHE {
  SEQOBJ     stSeqObj;
  PCTX       pCtx;
  ULONG      ulUID;              // Message index.
  ULONG      ulFlags;            // IMFFL_xxxxx
  PSZ        pszFields;
  ULONG      cPart;
  ULONG      aPart[1];
} BODYCACHE, *PBODYCACHE;

typedef struct _CMDDATA {
  ULONG      ulCmd;              // Index of aCmdList[].
  BOOL       fUID;               // UID command.
  ULONG      cArg;               // Number of obtained arguments (in apszArg[]).
  PVOID      apArg[_CMDMAXARG];  // Pointers to the low memory.
  BOOL       fLiteral;           // Reads a literal.
  ULLONG     ullLitOctets;       // Left octets of literal to read.
  PCTX       pLitCtx;            // Literal data.
  CHAR       acId[1];            // Client's identifier for the command.
} CMDDATA, *PCMDDATA;

#pragma pack(2)
typedef struct _PROTODATA {
  ULONG      ulState;            // _STATE_xxxxx
  PCMDDATA   pCmdData;           // High memory pointer.
  union {
    PAUTH      pAuth;            // Authenticate data.
    PSZ        pszIdleCmdId;     // DILE command id for responce on DONE.
  } _state_depended;             //   ^^ High memory pointers.
#define _sd_pAuth                _state_depended.pAuth
#define _sd_pszIdleCmdId         _state_depended.pszIdleCmdId
  USHORT     usBadLogins;
  USHORT     usBadCommands;
  UHSESS     stUHSess;
  LINKSEQ    lsBodyCache;        // Body cache (for FETCH command)
} PROTODATA, *PPROTODATA;
#pragma pack()

typedef struct _AUTHPLAIN {
  AUTH       stAuth;
} AUTHPLAIN, *PAUTHPLAIN;

typedef struct _AUTHCRAMMD5 {
  AUTH       stAuth;

  ULONG      cbChallenge;
  CHAR       acChallenge[256];
} AUTHCRAMMD5, *PAUTHCRAMMD5;

BOOL         fGlIMAPEnabled;

// List of IMAP commands.

// _ARGFL_xxx - command argument types.

// Optioal argument flag. Cannot be followed by argument w/o this flag.
#define _ARGFL_OPTIONAL          0x0100

#define _ARGFL_TYPEMASK          0x00FF
// _ARGFL_STR - quoted string or word.
#define _ARGFL_STR               0x0001
// _ARGFL_PLST - parenthesized list.
#define _ARGFL_PLST              0x0002
// _ARGFL_LIT - data in the literal. Should be last argument.
#define _ARGFL_LIT               0x0003
// _ARGFL_SEQ - number sequence, like n1,n2:n3,n4:*
#define _ARGFL_SEQ               0x0004
// _ARGFL_RAW - rest of the line. Should be last argument or before _ARGFL_LIT.
#define _ARGFL_RAW               0x0005
// _ARGFL_WRD - single word (sequence of any characters up to space or end of
//              line).
#define _ARGFL_WRD               0x0006

typedef struct _CMD {
  PSZ        pszName;
  BOOL       fUID;                   // Prefix UID allowed for the command.
  ULONG      aulArg[_CMDMAXARG + 1]; // List of argument types (_ARGFL_xxxxx).
  ULONG (*fnCmd)(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
} CMD, *PCMD;

static ULONG cfnCapability(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnNoop(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnLogout(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnStartTLS(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnLogin(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnAuthenticate(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnSelect(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnExamine(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnCreate(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnDelete(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnRename(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnSubscribe(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnUnsubscribe(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnList(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnLSub(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnStatus(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnAppend(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnIdle(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnSetQuota(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnGetQuota(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnGetQuotaRoot(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnCheck(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnClose(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnExpunge(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnSearch(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnFetch(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnStore(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnCopy(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);
static ULONG cfnMove(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx);

static CMD   aCmdList[] =
{
  /* 0 - 2   # Any state commands.                         */
  /*  0 */ { "CAPABILITY",   FALSE, { 0, 0, 0, 0, 0 },
           cfnCapability },
  /*  1 */ { "NOOP",         FALSE, { 0, 0, 0, 0, 0 },
           cfnNoop },
  /*  2 */ { "LOGOUT",       FALSE, { 0, 0, 0, 0, 0 },
           cfnLogout },
  /* 3 - 5   # Not Authenticated State commands.           */
  /*  3 */ { "STARTTLS",     FALSE, { 0, 0, 0, 0 },
           cfnStartTLS },
  /*  4 */ { "LOGIN",        FALSE, { _ARGFL_STR, _ARGFL_STR, 0, 0, 0 },
           cfnLogin },
  /*  5 */ { "AUTHENTICATE", FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnAuthenticate },
  /* 6 - 20  # Authenticated State commands.               */
  /*  6 */ { "SELECT",       FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnSelect },
  /*  7 */ { "EXAMINE",      FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnExamine },
  /*  8 */ { "CREATE",       FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnCreate },
  /*  9 */ { "DELETE",       FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnDelete },
  /* 10 */ { "RENAME",       FALSE, { _ARGFL_STR, _ARGFL_STR, 0, 0, 0 },
           cfnRename },
  /* 11 */ { "SUBSCRIBE",    FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnSubscribe },
  /* 12 */ { "UNSUBSCRIBE",  FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnUnsubscribe },
  /* 13 */ { "LIST",         FALSE, { _ARGFL_STR, _ARGFL_STR, 0, 0, 0 },
           cfnList },
  /* 14 */ { "LSUB",         FALSE, { _ARGFL_STR, _ARGFL_STR, 0, 0, 0 },
           cfnLSub },
  /* 15 */ { "STATUS",       FALSE, { _ARGFL_STR, _ARGFL_PLST, 0, 0, 0 },
           cfnStatus },
  /* 16 */ { "APPEND",       FALSE, { _ARGFL_RAW, _ARGFL_LIT, 0, 0, 0 },
           cfnAppend },
           /* APPEND mailbox optional_flags optional_time message_literal
              We will store first 3 arguments (one required and two optional)
              in index 0 (argument flag _ARGFL_RAW) and message body in index 1.
           */
  /* 17 */ { "IDLE",         FALSE, { 0, 0, 0, 0, 0 },
           cfnIdle },
           /* 2017-10-05 IDLE moved to Authenticated State from Selected State
              as required by RFC 2177:
              command_auth ::= append / create / delete / examine / list / lsub /
                    / rename / select / status / subscribe / unsubscribe / idle
              It is not clear what can be sent in idle mode before Selected
              State.
           */
  /* 18 */ { "SETQUOTA",     FALSE, { _ARGFL_STR, _ARGFL_PLST, 0, 0, 0 },
           cfnSetQuota },
  /* 19 */ { "GETQUOTA",     FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnGetQuota },
  /* 20 */ { "GETQUOTAROOT", FALSE, { _ARGFL_STR, 0, 0, 0, 0 },
           cfnGetQuotaRoot },
  /* 21 - 28 # Selected State commands.                    */
  /* 21 */ { "CHECK",        FALSE, { 0, 0, 0, 0, 0 },
           cfnCheck },
  /* 22 */ { "CLOSE",        FALSE, { 0, 0, 0, 0, 0 },
           cfnClose },
  /* 23 */ { "EXPUNGE",      TRUE,  { _ARGFL_OPTIONAL | _ARGFL_SEQ, 0, 0, 0, 0 },
           cfnExpunge },
  /* 24 */ { "SEARCH",       TRUE,  { _ARGFL_RAW, 0, 0, 0, 0 },
           cfnSearch },
  /* 25 */ { "FETCH",        TRUE,  { _ARGFL_SEQ, _ARGFL_PLST, 0, 0, 0 },
           cfnFetch },
  /* 26 */ { "STORE",        TRUE,  { _ARGFL_SEQ, _ARGFL_WRD, _ARGFL_PLST, 0, 0 },
           cfnStore },
  /* 27 */ { "COPY",         TRUE,  { _ARGFL_SEQ, _ARGFL_STR, 0, 0, 0 },
           cfnCopy },
  /* 28 */ { "MOVE",         TRUE,  { _ARGFL_SEQ, _ARGFL_STR, 0, 0, 0 },
           cfnMove }
};

// Commands allowed on the each state.
// Index is state (_STATE_xxxxx), value is last allowed command number.
static ULONG           aStateAllowCmd[4] = { 5, 20, 28, 0 };


// Protocol replies.

static PSZ apszTagResp[] =
{
  // OK
  "completed",                                                 //  0
  "[READ-WRITE] SELECT completed",                             //  1
  "[READ-ONLY] EXAMINE completed",                             //  2
  "begin TLS negotiation now",                                 //  3
  "terminated",                                                //  4

  // NO
  "not implemented",                                           //  5
  "failure",                                                   //  6
  "[SERVERBUG] internal server error",                         //  7
  "[TRYCREATE] mailbox does not exist",                        //  8
  "[BADCHARSET] SEARCH unsupported charset",                   //  9
  "unknown flag",                                              // 10
  "invalid date/time",                                         // 11
  "not enough space on the disk",                              // 12
  "[OVERQUOTA] disk quota exceeded",                           // 13
  "can't set that data",                                       // 14
  "no such quota root",                                        // 15
  "[AUTHENTICATIONFAILED] Authentication failed",              // 16
  "[NONEXISTENT] no such mailbox",                             // 17
  "[ALREADYEXISTS] destination mailbox already exists",        // 18
  ": Inbox locked by POP3 user",                               // 19

  // BAD
  "syntax error",                                              // 20
  "command error",                                             // 21
  "command received in invalid state",                         // 22
  "canceled"                                                   // 23
};


static VOID _authDestroy(PPROTODATA pProtoData);
static VOID _bcClear(PPROTODATA pProtoData);
static VOID _cmdDataFree(PPROTODATA pProtoData);


static BOOL imapNew(PCLNTDATA pClntData)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PCTX       pCtx = netsrvClntGetContext( pClntData );

  if ( !fGlIMAPEnabled || ( pCtx == NULL ) )
    return FALSE;

  lnkseqInit( &pProtoData->lsBodyCache );

  // Currently fsSessInit() does not allocated any resources and returns only
  // TRUE. In future it may be is necessary to call fsSessDone() if ctxWrite()
  // fails.
  fsSessInit( &pProtoData->stUHSess );

  return ctxWrite( pCtx, -1, "* OK IMAP4rev1 Service Ready\r\n" );
}

static VOID imapDestroy(PCLNTDATA pClntData)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  // Destroy command parser data.
  _cmdDataFree( pProtoData );

  // Clear message body cache.
  _bcClear( pProtoData );

  // Store mailbox state, remove mailbox selection for session.
  fsQueryMailbox( &pProtoData->stUHSess, NULL, FSGMB_SELECT, NULL );

  if ( pProtoData->ulState != _STATE_IDLE )
  {
    // Destroy authenticate data.
    _authDestroy( pProtoData );
  }
  else if ( pProtoData->_sd_pszIdleCmdId != NULL )
    free( pProtoData->_sd_pszIdleCmdId );

  // Destroy user-home session.
  fsSessDone( &pProtoData->stUHSess );
}


/* ****************************************************************** */
/*                                                                    */
/*                     fnRequest implementation                       */
/*                                                                    */
/* ****************************************************************** */
/*
 *  Main function:
 *    static BOOL imapRequest(PCLNTDATA pClntData, PSZ pszLine)
 */

#define _IMFFL_BCEXCLFL  (IMFFL_CONTENT | IMFFL_PSTART | IMFFL_PLENGTH)

static VOID __bcFree(PBODYCACHE pBodyCache)
{
  if ( pBodyCache->pszFields != NULL )
    free( pBodyCache->pszFields );

  ctxFree( pBodyCache->pCtx );
  free( pBodyCache );
}

static PCTX _bcGet(PPROTODATA pProtoData, ULONG ulUID, PIMFBODYPARAM pBody)
{
  PLINKSEQ             plsBodyCache = &pProtoData->lsBodyCache;
  PBODYCACHE           pBodyCache;

  for( pBodyCache = (PBODYCACHE)lnkseqGetFirst( plsBodyCache );
       pBodyCache != NULL;
       pBodyCache = (PBODYCACHE)lnkseqGetNext( pBodyCache ) )
    if ( ( pBodyCache->ulUID == ulUID ) &&
         ( pBodyCache->ulFlags == (pBody->ulFlags & ~_IMFFL_BCEXCLFL) ) &&
         ( pBodyCache->cPart == pBody->cPart ) &&
         ( memcmp( &pBodyCache->aPart, pBody->paPart,
                   pBody->cPart * sizeof(ULONG) ) == 0 ) &&
         ( ( (pBodyCache->ulFlags & IMFFL_HEADER) == 0 ) ||
           utilStrIsListEqual( pBodyCache->pszFields, pBody->pszFields ) ) )
    {
      PCTX             pCtx = pBodyCache->pCtx;
      ULLONG           cbCtx = ctxQuerySize( pCtx );

      // Set "start" and "length" output values in pBody.

      if ( (pBody->ulFlags & IMFFL_PSTART) == 0 )
        pBody->ullStart = 0;
      else if ( pBody->ullStart > cbCtx )
        pBody->ullStart = cbCtx;

      cbCtx -= pBody->ullStart;
      if ( ( (pBody->ulFlags & IMFFL_PLENGTH) == 0 ) ||
           ( pBody->ullLength >= cbCtx ) )
        pBody->ullLength = cbCtx;

      ctxSetReadPos( pCtx, CTX_RPO_BEGIN, pBody->ullStart );

      return pCtx;
    } // if

  return NULL;
}

static BOOL _bcPut(PPROTODATA pProtoData, ULONG ulUID, PIMFBODYPARAM pBody,
                   PCTX pCtx)
{
  PLINKSEQ             plsBodyCache = &pProtoData->lsBodyCache;
  PBODYCACHE           pBodyCache;

  if ( (pBody->ulFlags & (IMFFL_PSTART | IMFFL_PLENGTH)) == 0 )
    // We will store partial requests only.
    return FALSE;

  while( lnkseqGetCount( plsBodyCache ) >= _MAXBODYCACHE )
  {
    pBodyCache = (PBODYCACHE)lnkseqGetFirst( plsBodyCache );
    lnkseqRemove( plsBodyCache, pBodyCache );
    __bcFree( pBodyCache );
  }

  pBodyCache = malloc( sizeof(BODYCACHE) - sizeof(ULONG) +
                        ( pBody->cPart * sizeof(ULONG) ) );
  if ( pBodyCache == NULL )
    return FALSE;

  pBodyCache->pCtx    = pCtx;
  pBodyCache->ulUID   = ulUID;
  pBodyCache->ulFlags = pBody->ulFlags & ~_IMFFL_BCEXCLFL;

  if ( ( (pBody->ulFlags & IMFFL_HEADER) != NULL ) &&
       ( pBody->pszFields != NULL ) )
    pBodyCache->pszFields = strdup( pBody->pszFields );
  else
    pBodyCache->pszFields = NULL;

  pBodyCache->cPart = pBody->cPart;
  memcpy( &pBodyCache->aPart, pBody->paPart, pBody->cPart * sizeof(ULONG) );

  lnkseqAdd( plsBodyCache, pBodyCache );

  return TRUE;
}

static VOID _bcClear(PPROTODATA pProtoData)
{
  PLINKSEQ             plsBodyCache = &pProtoData->lsBodyCache;

  lnkseqFree( plsBodyCache, PBODYCACHE, __bcFree );
}

static BOOL _ctxWritePath(PCTX pCtx, PSZ pszPath, BOOL fCRLF)
{
  ULONG      cbSafe;

  if ( pszPath[ strcspn( pszPath, " \"\\" ) ] == '\0' )
    ctxWrite( pCtx, -1, pszPath );
//    ctxWriteFmt( pCtx, "\"%s\"", pszPath );
  else
  {
    ctxWrite( pCtx, 1, "\"" );
    while( *pszPath != '\0' )
    {
      cbSafe = strcspn( pszPath, "\"\\" );
      ctxWrite( pCtx, cbSafe, pszPath );
      pszPath += cbSafe;
      if ( *pszPath == '\0' )
        break;
      ctxWrite( pCtx, 1, "\\" );
      ctxWrite( pCtx, 1, pszPath );
      pszPath++;
    }

    ctxWrite( pCtx, 1, "\"" );
  }

  return !fCRLF || ctxWrite( pCtx, 2, "\r\n" );
}

static BOOL _ctxWriteMsgFlags(PCTX pCtx, ULONG ulFlags)
{
  CHAR   acBuf[64];
  PCHAR  pcEnd;

  acBuf[0] = '\0';
  pcEnd = acBuf;
  if ( ( ulFlags & FSMSGFL_SEEN ) != 0 )
    pcEnd += sprintf( pcEnd, "\\Seen " );
  if ( ( ulFlags & FSMSGFL_ANSWERED ) != 0 )
    pcEnd += sprintf( pcEnd, "\\Answered " );
  if ( ( ulFlags & FSMSGFL_FLAGGED ) != 0 )
    pcEnd += sprintf( pcEnd, "\\Flagged " );
  if ( ( ulFlags & FSMSGFL_DELETED ) != 0 )
    pcEnd += sprintf( pcEnd, "\\Deleted " );
  if ( ( ulFlags & FSMSGFL_DRAFT ) != 0 )
    pcEnd += sprintf( pcEnd, "\\Draft " );
  if ( ( ulFlags & FSMSGFL_RECENT ) != 0 )
    pcEnd += sprintf( pcEnd, "\\Recent " );

  if ( (pcEnd > acBuf) && (*(pcEnd - 1) == ' ') )
    pcEnd--;
  *pcEnd = '\0';

  return ctxWriteFmt( pCtx, "FLAGS (%s)", acBuf );
}

static BOOL _clntWriteResp(PCLNTDATA pClntData, PSZ pszCmdId, PSZ pszCmd,
                           ULONG ulCode)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PCTX       pCtx;
  PSZ        pszStatus;
  PSZ        pszText;

  switch( ulCode & 0xFFFF0000 )
  {
    case IMAPR_OK:     pszStatus = "OK"; pProtoData->usBadCommands = 0; break;
    case IMAPR_NO:
      pszStatus = "NO";
      pProtoData->usBadCommands = 0;

      if ( ulCode == IMAPR_NO_AUTHENTICATION_FAILED )
        netsrvSetOutputDelay( pClntData, _AUTH_FAIL_RESP_DELAY );

      break;

    case IMAPR_BAD:
      pProtoData->usBadCommands++;
      if ( pProtoData->usBadCommands >= _MAX_BAD_COMMANDS )
      {
        netsrvClntLog( pClntData, 3, "Too many \"BAD\" replies" );
        return FALSE;
      }
      pszStatus = "BAD";
      netsrvSetOutputDelay( pClntData, _BAD_RESP_DELAY );
      break;

    case IMAPR_VOID:
      return TRUE;

    default:           // IMAPR_DISCONNECT
      return FALSE;
  }

  pCtx = netsrvClntGetContext( pClntData );
  if ( pCtx == NULL )
    return FALSE;

  ctxWriteFmt( pCtx, "%s %s ",
               ( pszCmdId == NULL ) || ( *pszCmdId == '\0' )
                 ? (PSZ)"*" : pszCmdId,
               pszStatus );

  ulCode &= 0xFFFF;
  pszText = ulCode >= ARRAYSIZE(apszTagResp) ? (PSZ)"" : apszTagResp[ulCode];
  if ( ( *pszText != '[' ) && ( pszCmd != NULL ) && ( *pszCmd != '\0' ) )
    ctxWriteFmt( pCtx, "%s ", pszCmd );

  return ctxWriteStrLn( pCtx, pszText );
}

// Returns TRUE if plain-text logins allowed or it's an encrypted connection or
// client is a localhost.
static BOOL _clntPlaintextLoginAllowed(PCLNTDATA pClntData)
{
  ULONG                ulUser = (ULONG)netsrvClntGetUserPtr( pClntData );
  struct in_addr       stAddr;

  return ( (ulUser & IMAPF_LOGINDISABLED) == 0 ) ||
         netsrvClntIsTLSMode( pClntData ) ||
         ( netsrvClntGetRemoteAddr( pClntData, &stAddr, NULL ) &&
           ( stAddr.s_addr == 0x0100007F /* 127.0.0.1 */ ) );
}

static VOID _clntSendChanges(PCLNTDATA pClntData, ULONG ulTimeout)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  FSCHANGES  stChanges;
  ULONG      ulIdx;

  // fsGetChanges() fills stChanges and reset information about changes for the
  // session.
  if ( fsGetChanges( &pProtoData->stUHSess, &stChanges, ulTimeout ) )
  {
    PCTX     pCtx = netsrvClntGetContext( pClntData );
             // The function netsrvClntGetContext() creates context. Therefore,
             // we call it only now, when we have data to send.

    if ( pCtx != NULL )
    {
      for( ulIdx = 0; ulIdx < stChanges.cChgMsg; ulIdx++ )
      {
        ctxWriteFmt( pCtx, "* %u ", stChanges.pChgMsg[ulIdx].ulSeqNum );

        if ( stChanges.pChgMsg[ulIdx].ulFlags == (~0) )
        {
          ctxWriteStrLn( pCtx, "EXPUNGE" );
          netsrvClntLog( pClntData, 6, "Notify client: expunge %u",
                         stChanges.pChgMsg[ulIdx].ulSeqNum );
        }
        else
        {
          ctxWrite( pCtx, -1, "FETCH (" );
          _ctxWriteMsgFlags( pCtx, stChanges.pChgMsg[ulIdx].ulFlags );
          ctxWriteStrLn( pCtx, ")" );
          netsrvClntLog( pClntData, 6, "Notify client: flags for %u",
                         stChanges.pChgMsg[ulIdx].ulSeqNum );
        }
      }

      if ( (stChanges.ulFlags & FSSESSFL_EXISTSCH) != 0 )
      {
        ctxWriteFmtLn( pCtx, "* %u EXISTS", stChanges.ulExists );
        netsrvClntLog( pClntData, 6, "Notify client: %u EXISTS",
                       stChanges.ulExists );
      }

      if ( (stChanges.ulFlags & FSSESSFL_RECENTCH) != 0 )
      {
        ctxWriteFmtLn( pCtx, "* %u RECENT", stChanges.ulRecent );
        netsrvClntLog( pClntData, 6, "Notify client: %u RECENT",
                       stChanges.ulRecent );
      }
    }  // if ( pCtx != NULL )

    fsReleaseChanges( &stChanges );
  }
}

static BOOL _ctxAuthWrite(PCTX pCtx, LONG cbData, PCHAR pcData)
{
  ULONG      cbBuf;
  PCHAR      pcBuf;
  BOOL       fSuccess;

  if ( cbData == -1 )
    cbData = STR_LEN( pcData );

  if ( cbData == 0 )
    fSuccess = ctxWriteStrLn( pCtx, "+" );
  else if ( utilB64Enc( cbData, pcData, &cbBuf, &pcBuf ) )
  {
//    logf( 6, "Authentication ready response: %s", pcBuf );
    fSuccess = ctxWriteFmtLn( pCtx, "+ %s", pcBuf );
    free( pcBuf );
  }
  else
    fSuccess = FALSE;

  return fSuccess;
}

static VOID _authDestroy(PPROTODATA pProtoData)
{
  if ( pProtoData->_sd_pAuth == NULL )
    return;

  // <-- Destroy pProtoData->_sd_pAuth object's data. -->

  free( pProtoData->_sd_pAuth );
  pProtoData->_sd_pAuth = NULL;
}

static BOOL _authResp(PCLNTDATA pClntData, ULONG ulCode)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  BOOL       fSuccess;

  if ( pProtoData->_sd_pAuth == NULL )
  {
    debug( "Warning! pProtoData->_sd_pAuth is NULL" );
    fSuccess = TRUE;
  }
  else
  {
    fSuccess = _clntWriteResp( pClntData, pProtoData->_sd_pAuth->acCmdId,
                              "AUTHENTICATE", ulCode );
    _authDestroy( pProtoData );
  }

  return fSuccess;
}

// Returns TRUE until the number of unsuccessful login attempts is less than
// configured limit.
static BOOL _authIncBadLoginCnt(PCLNTDATA pClntData)
{
  ULONG      ulLimit = wcfgQueryBadPasswordLimit();

  if ( ulLimit != 0 )
  {
    PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

    pProtoData->usBadLogins++;
    if ( pProtoData->usBadLogins >= ulLimit )
    {
      netsrvClntLog( pClntData, 3, "Too many login attempts (%u)",
                     pProtoData->usBadLogins );
      return FALSE;
    }
  }

  return TRUE;
}

// Returns FALSE to disconnect.
static BOOL _authClientResponse(PCLNTDATA pClntData, ULONG cbData, PCHAR pcData)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG      ulResp = IMAPR_NO_AUTHENTICATION_FAILED;
  CHAR       acBuf[CCHMAXPATH];
  LONG       cbBuf;
  PSZ        pszUser;
  PSZ        pszMechanism;

  // The pProtoData->_sd_pAuth->ulType value was detected in cfnAuthenticate().
  switch( pProtoData->_sd_pAuth->ulType )
  {
    case _AUTH_PLAIN:            // PLAIN
      pszMechanism = "PLAIN";
      if ( cbData >= 4 )
      {
        PSZ        pszPassword;

        // Client response:
        //   [authorize-id] NUL authenticate-id NUL password

        pszUser = memchr( pcData, '\0', cbData - 1 );
        if ( pszUser != NULL )
        {
          pszUser++;

          pszPassword = memchr( pszUser, '\0',
                                &pcData[cbData] - (PCHAR)pszUser );
          if ( pszPassword != NULL )
          {
            pszPassword++;
            debug( "user: %s, password: %s\n", pszUser, pszPassword );

            cbBuf = wcfgQueryUser( pszUser, pszPassword,
                                   WC_USRFL_ACTIVE | WC_USRFL_USE_IMAP,
                                   sizeof(acBuf), acBuf );

            if ( cbBuf == -1 )                // acBuf too small?
              ulResp = IMAPR_NO_INTERNAL_ERROR;
            else if ( ( cbBuf != 0 ) &&
                      fsSessOpen( &pProtoData->stUHSess, acBuf ) )
            {
              ulResp = IMAPR_OK_COMPLETED;
              pProtoData->ulState = _STATE_AUTHENTICATED;
              pProtoData->usBadLogins = 0;
            }
          } // if ( pszPassword != NULL )
        }  // if ( pszUser != NULL )
      }
      break;

    case _AUTH_CRAMMD5:          // CRAM-MD5
      pszMechanism = "CRAM-MD5";
      {
        PAUTHCRAMMD5   pAuth = (PAUTHCRAMMD5)pProtoData->_sd_pAuth;
        PCHAR          pcRef, pcDst;
        CHAR           acRef[EVP_MAX_MD_SIZE];
        CHAR           acHexRef[(2 * EVP_MAX_MD_SIZE) + 1];
        int            cbRef;
        PWCFINDUSR     pFind;
        PSZ            pszHomeDir = NULL;

        if ( !utilStrCutWord( (PSZ *)&pcData, &pszUser ) )
          break;
        // pcData now is a responce: hash for our challenge with key=password.

        // Look for users with username as pszUser.

//        netsrvClntLog( pClntData, 6, "CRAM-MD5 for user %s, digest: %s", pszUser, pcData );
        pFind = wcfgFindUserBegin( pszUser,
                                   WC_USRFL_ACTIVE | WC_USRFL_USE_IMAP );
        if ( pFind == NULL )
        {
          ulResp = IMAPR_NO_INTERNAL_ERROR;
          break;
        }

        while( wcfgFindUser( pFind ) )
        {
//          netsrvClntLog( pClntData, 6, "User found" );

          // Create a reference hash for found user.
          pcRef = HMAC( EVP_md5(),
                        pFind->pszPassword, strlen( pFind->pszPassword ),
                        pAuth->acChallenge, pAuth->cbChallenge,
                        acRef, &cbRef );
          if ( pcRef == NULL )
          {
            debugCP( "WTF?" );
            netsrvClntLog( pClntData, 0, "Could not create a CRAM-MD5 reference hash for user" );
            continue;
          }

          // Convert out reference hash to hex string.
          for( pcDst = acHexRef; cbRef != 0; pcRef++, pcDst += 2, cbRef-- )
            sprintf( pcDst, "%02x", *pcRef & 0xFF );
          *pcDst = '\0';

          // Compare reference with user's digest.
          if ( strcmp( pcData, acHexRef ) == 0 )
          {
            // Ok, user is found and authenticated.
            // We will open session AFTER wcfgFindUserEnd() to avoid deadlock:
            // mutex in wcfg module (hmtxWCfg) and mutex in imapfs (hmtxHome).
            pszHomeDir = strdup( pFind->acHomeDir );
            break;            
          }
/*          else
            netsrvClntLog( pClntData, 6,
                           "Failed to compare reference with user's digest. "
                           "User: %s, domain: %s",
                           pszUser, pFind->pszDomainName );*/
        }

//        netsrvClntLog( pClntData, 6, "CRAM-MD5 - end" );
        wcfgFindUserEnd( pFind );

        if ( pszHomeDir != NULL )
        {
          if ( fsSessOpen( &pProtoData->stUHSess, pszHomeDir ) )
          {
            pProtoData->ulState = _STATE_AUTHENTICATED;
            pProtoData->usBadLogins = 0;
            ulResp = IMAPR_OK_COMPLETED;
//            netsrvClntLog( pClntData, 6, "Authenticated, session is open" );
          }
          else
            netsrvClntLog( pClntData, 0, "Could not open user session" );

          free( pszHomeDir );
        }
/*        else
          netsrvClntLog( pClntData, 6, "User not found" );*/
      }
      break;

    default:
      debugCP( "WTF?!" );
      netsrvClntLog( pClntData, 0,
                     "Internal error - unknown authentication mechanism" );
      return FALSE;
  }

  netsrvClntLog( pClntData, 3,
                 "Authentication %s (%s), username: %s",
                 ulResp == IMAPR_OK_COMPLETED ? "successful" : "failed",
                 pszMechanism, pszUser );

  return ( ( ulResp == IMAPR_OK_COMPLETED ) ||
             _authIncBadLoginCnt( pClntData ) ) &&
           _authResp( pClntData, ulResp );
}

static VOID _cmdDataFree(PPROTODATA pProtoData)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  ULONG      ulIdx;
  PCMD       pCmd;

  if ( pCmdData == NULL )
    return;

  pCmd = &aCmdList[pCmdData->ulCmd];
  for( ulIdx = 0; ulIdx < pCmdData->cArg; ulIdx++ )
    if ( pCmdData->apArg[ulIdx] != NULL )
    {
      if ( pCmd->aulArg[ulIdx] == _ARGFL_LIT )
        ctxFree( (PCTX)pCmdData->apArg[ulIdx] );
      else
        free( pCmdData->apArg[ulIdx] );
    }

  if ( pCmdData->pLitCtx != NULL )
    ctxFree( pCmdData->pLitCtx );

  free( pCmdData );
  pProtoData->pCmdData = NULL;
}


/*
   Command routines
   ----------------
*/

static ULONG cfnCapability(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  CHAR       acBuf[256];
  BOOL       fTLSMode = netsrvClntIsTLSMode( pClntData );

  strcpy( acBuf, "* CAPABILITY IMAP4 IMAP4rev1 LITERAL+ IDLE UIDPLUS "
                 "QUOTA MOVE AUTH=CRAM-MD5" );
  strcat( acBuf, _clntPlaintextLoginAllowed( pClntData )
                   ? " AUTH=PLAIN" : " LOGINDISABLED" );

  if ( !fTLSMode && netsrvClntIsTLSAvailable( pClntData ) )
    // Report STARTTLS only for unencrypted channel and when TLS is available.
    strcat( acBuf, " STARTTLS" );

  netsrvClntLog( pClntData, 6, acBuf );

  strcat( acBuf, "\r\n" );       // CRLF

  ctxWrite( pCtx, -1, acBuf );

  return IMAPR_OK_COMPLETED;
}

static ULONG cfnNoop(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  return IMAPR_OK_COMPLETED;
}

static ULONG cfnLogout(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  netsrvClntLog( pClntData, 5, "LOGOUT" );
  ctxWriteStrLn( pCtx, "* BYE" );
  return IMAPR_DISCONNECT;
}

static ULONG cfnStartTLS(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  if ( !netsrvClntStartTLS( pClntData ) )
  {
    debugCP( "netsrvClntStartTLS() failed" );
    return IMAPR_NO_FAILURE;
  }

  netsrvClntLog( pClntData, 5, "STARTTLS" );
  return IMAPR_OK_STARTTLS;
}

static ULONG cfnLogin(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  CHAR       acBuf[CCHMAXPATH];
  LONG       cbBuf;

  if ( !_clntPlaintextLoginAllowed( pClntData ) )
    // Plain logins on unencrypted connection are forbidden.
    return IMAPR_BAD_INVALID_STATE;

  cbBuf = wcfgQueryUser( pCmdData->apArg[0], pCmdData->apArg[1],
                         WC_USRFL_ACTIVE | WC_USRFL_USE_IMAP,
                         sizeof(acBuf), acBuf );

  if ( cbBuf == -1 )                 // acBuf too small?
    return IMAPR_NO_INTERNAL_ERROR;

  if ( ( cbBuf == 0 ) ||             // User name or password rejected.
       !fsSessOpen( &pProtoData->stUHSess, acBuf ) )
  {
    netsrvClntLog( pClntData, 3, "User name \"%s\" or password rejected",
                   pCmdData->apArg[0] );
    return _authIncBadLoginCnt( pClntData )
              ? IMAPR_NO_AUTHENTICATION_FAILED : IMAPR_DISCONNECT;
  }

  netsrvClntLog( pClntData, 3, "User is logged in, name: %s",
                 pCmdData->apArg[0] );

  pProtoData->ulState = _STATE_AUTHENTICATED;
  pProtoData->usBadLogins = 0;

  return IMAPR_OK_COMPLETED;
}

static ULONG cfnAuthenticate(PCLNTDATA pClntData, PPROTODATA pProtoData,
                             PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  LONG       lMethod = utilStrWordIndex( "PLAIN CRAM-MD5", -1,
                                         pCmdData->apArg[0] );

  switch( lMethod )
  {
    case -1: // Unknown method.
      netsrvClntLog( pClntData, 6, "Unknown authentication mechanism" );
      return IMAPR_NO_FAILURE;

    case 0:  // _AUTH_PLAIN
      {
        if ( !_clntPlaintextLoginAllowed( pClntData ) )
          // Plain logins on unencrypted connection are forbidden.
          return IMAPR_BAD_INVALID_STATE;

        pProtoData->_sd_pAuth = (PAUTH)malloc( sizeof(AUTHPLAIN) );
        if ( pProtoData->_sd_pAuth == NULL )
          break;
        _ctxAuthWrite( pCtx, 0, NULL );      // Send empty <+>-response.
      }
      break;

    case 1:  // _AUTH_CRAMMD5
      {
        PAUTHCRAMMD5   pAuth = malloc( sizeof(AUTHCRAMMD5) );
        LONG           cb;

        if ( pAuth == NULL )
          break;

        /*
           [RFC 2195] 2. Challenge-Response Authentication Mechanism (CRAM)
           ... The data encoded in the first ready response contains an
           presumptively arbitrary string of random digits, a timestamp, and
           the fully-qualified primary host name of the server.
        */
        cb = imfGenerateMsgId( sizeof(pAuth->acChallenge), pAuth->acChallenge,
                               NULL );
        if ( cb == -1 )
        {
          free( pAuth );
          netsrvClntLog( pClntData, 0, "Could not generate challenge" );
        }
        else
        {
//          netsrvClntLog( pClntData, 6, "Challenge: %s", pAuth->acChallenge );
          pAuth->cbChallenge = cb;
          _ctxAuthWrite( pCtx, pAuth->cbChallenge, pAuth->acChallenge );
          pProtoData->_sd_pAuth = (PAUTH)pAuth;
        }
      }
      break;
  }

  if ( pProtoData->_sd_pAuth == NULL )
  {
    netsrvClntLog( pClntData, 0, "Internal error during authorization" );
    return IMAPR_NO_INTERNAL_ERROR;
  }

  pProtoData->_sd_pAuth->ulType = lMethod;
  strlcpy( pProtoData->_sd_pAuth->acCmdId, pCmdData->acId,
           sizeof(pProtoData->_sd_pAuth->acCmdId) );

  // pProtoData->_sd_pAuth in not a NULL - authentication protocol is started.

  return IMAPR_VOID;   // No tagged response, response "+ ..." has been sent.
}

static ULONG _cfnSelect(PPROTODATA pProtoData, PCTX pCtx, BOOL fExamine)
{
  PCMDDATA             pCmdData = pProtoData->pCmdData;
  MAILBOXINFO          stInfo;

  if ( !fsQueryMailbox( &pProtoData->stUHSess, pCmdData->apArg[0],
                        fExamine ? FSGMB_EXAMINE : FSGMB_SELECT,
                        &stInfo ) )
  {
    pProtoData->ulState = _STATE_AUTHENTICATED;
    return IMAPR_NO_FAILURE;
  }

  pProtoData->ulState = _STATE_SELECTED;
  ctxWriteFmtLn( pCtx,
    "* %u EXISTS\r\n"
    "* %u RECENT\r\n"
    "* OK [UNSEEN %u] First unseen\r\n"
    "* OK [UIDVALIDITY %u] UIDs valid\r\n"
    "* OK [UIDNEXT %u] Predicted next UID\r\n"
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
    stInfo.ulExists, stInfo.ulRecent, stInfo.ulUnseen,
    stInfo.ulUIDValidity, stInfo.ulUIDNext );

  ctxWriteStrLn( pCtx,
                 fExamine 
                   ? "* OK [PERMANENTFLAGS ()] No permanent flags permitted"
                   : "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted "
                     "\\Seen \\Draft)] Limited" );

  return fExamine ? IMAPR_OK_EXAMINE_COMPLETED : IMAPR_OK_SELECT_COMPLETED;
}

static ULONG cfnSelect(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  return _cfnSelect( pProtoData, pCtx, FALSE );
}

static ULONG cfnExamine(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  return _cfnSelect( pProtoData, pCtx, TRUE );
}

static ULONG cfnCreate(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;

  return fsCreateMailbox( &pProtoData->stUHSess, pCmdData->apArg[0] )
           ? IMAPR_OK_COMPLETED : IMAPR_NO_FAILURE;
}

static ULONG cfnDelete(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;

  return fsDeleteMailbox( &pProtoData->stUHSess, pCmdData->apArg[0] ) ?
           IMAPR_OK_COMPLETED : IMAPR_NO_FAILURE;
}

static ULONG cfnRename(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;

  switch( fsRename( &pProtoData->stUHSess,
                    pCmdData->apArg[0], pCmdData->apArg[1] ) )
  {
    case FSR_OK:             return IMAPR_OK_COMPLETED;
    case FSR_NON_EXISTENT:   return IMAPR_NO_NONEXISTENT;
    case FSR_ALREADY_EXISTS: return IMAPR_NO_ALREADYEXISTS;
    case FSR_POP3_LOCKED:    return IMAPR_NO_POP3_LOCKED;
  }

  return IMAPR_NO_FAILURE;
}

static ULONG cfnSubscribe(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;

  return fsSubscribe( &pProtoData->stUHSess, pCmdData->apArg[0] )
           ? IMAPR_OK_COMPLETED : IMAPR_NO_FAILURE;
}

static ULONG cfnUnsubscribe(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;

  return fsUnsubscribe( &pProtoData->stUHSess, pCmdData->apArg[0] )
           ? IMAPR_OK_COMPLETED : IMAPR_NO_FAILURE;
}

static ULONG cfnList(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
/* [TODO] Add flags in responce:

   \Noinferiors It is not possible for any child levels of hierarchy to exist
                under this name; no child levels exist now and none can be
                created in the future.
   \Noselect    It is not possible to use this name as a selectable mailbox.
   \Marked      The mailbox has been marked "interesting" by the server; the
                mailbox probably contains messages that have been added since
                the last time the mailbox was selected.
   \Unmarked    The mailbox does not contain any additional messages since the
                last time the mailbox was selected.
*/
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  PSZ        pszMailbox = pCmdData->apArg[1];
  FSFIND     stFind;
  BOOL       fRC;

  if ( *pszMailbox == '\0' )
  {
    ctxWriteStrLn( pCtx, "* LIST (\\Noselect) \"/\" \"\"" );
    return IMAPR_OK_COMPLETED;
  }

  if ( *(PSZ)pCmdData->apArg[0] != '\0' )
  {
    // Reference (1st argument) is specified.

    ULONG    cbMBox = strlen( pCmdData->apArg[0] ) + strlen( pszMailbox );
    PSZ      pszNew = malloc( cbMBox );

    if ( pszNew == NULL )
      return IMAPR_NO_INTERNAL_ERROR;

    strcpy( pszNew, pCmdData->apArg[0] );
    strcat( pszNew, pszMailbox );
    pszMailbox = pszNew;
  }

  fsFindBegin( &pProtoData->stUHSess, &stFind, pszMailbox );
  while( fsFind( &pProtoData->stUHSess, &stFind ) )
  {
    fRC = ctxWriteFmt( pCtx, "* LIST (%s) \"/\" ", stFind.acFlags ) &&
          _ctxWritePath( pCtx, stFind.pszName, TRUE );

    if ( !fRC )
      break;
  }
  fsFindEnd( &pProtoData->stUHSess, &stFind );

  if ( *(PSZ)pCmdData->apArg[0] != '\0' )
    free( pszMailbox );

  return IMAPR_OK_COMPLETED;
}

static ULONG cfnLSub(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  PSZ        pszMailbox = pCmdData->apArg[1];
  FSFIND     stFind;
  BOOL       fRC;

  if ( *pszMailbox == '\0' )
  {
    ctxWriteStrLn( pCtx, "* LIST (\\Noselect) \"/\" \"\"" );
    return IMAPR_OK_COMPLETED;
  }

  if ( *(PSZ)pCmdData->apArg[0] != '\0' )
  {
    // Reference (1st argument) is specified.

    ULONG    cbMBox = strlen( pCmdData->apArg[0] ) + strlen( pszMailbox );
    PSZ      pszNew = malloc( cbMBox );

    if ( pszNew == NULL )
      return IMAPR_NO_INTERNAL_ERROR;

    strcpy( pszNew, pCmdData->apArg[0] );
    strcat( pszNew, pszMailbox );
    pszMailbox = pszNew;
  }

  fsFindBegin( &pProtoData->stUHSess, &stFind, pszMailbox );
  while( fsFindSubscribe( &pProtoData->stUHSess, &stFind ) )
  {
    fRC = ctxWriteFmt( pCtx, "* LSUB (%s) \"/\" ", stFind.acFlags ) &&
          _ctxWritePath( pCtx, stFind.pszName, TRUE );

    if ( !fRC )
      break;
  }
  fsFindEnd( &pProtoData->stUHSess, &stFind );

  if ( *(PSZ)pCmdData->apArg[0] != '\0' )
    free( pszMailbox );

  return IMAPR_OK_COMPLETED;
}

static ULONG cfnStatus(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA       pCmdData = pProtoData->pCmdData;
  MAILBOXINFO    stInfo;
  PCHAR          pcEnd;
  CHAR           acBuf[128];

  if ( !fsQueryMailbox( &pProtoData->stUHSess, pCmdData->apArg[0],
                        FSGMB_STATUS, &stInfo ) )
    return IMAPR_NO_FAILURE;

  pcEnd = acBuf;

  if ( utilStrWordIndex( pCmdData->apArg[1], -1, "MESSAGES" ) != -1 )
    pcEnd += sprintf( pcEnd, "MESSAGES %lu ", stInfo.ulExists );
  if ( utilStrWordIndex( pCmdData->apArg[1], -1, "RECENT" ) != -1 )
    pcEnd += sprintf( pcEnd, "RECENT %lu ", stInfo.ulRecent );
  if ( utilStrWordIndex( pCmdData->apArg[1], -1, "UNSEEN" ) != -1 )
    pcEnd += sprintf( pcEnd, "UNSEEN %lu ", stInfo.ulUnseen );
  if ( utilStrWordIndex( pCmdData->apArg[1], -1, "UIDNEXT" ) != -1 )
    pcEnd += sprintf( pcEnd, "UIDNEXT %lu ", stInfo.ulUIDNext );
  if ( utilStrWordIndex( pCmdData->apArg[1], -1, "UIDVALIDITY" ) != -1 )
    pcEnd += sprintf( pcEnd, "UIDVALIDITY %lu ", stInfo.ulUIDValidity );

  if ( ( pcEnd > acBuf ) && ( *(pcEnd - 1) == ' ' ) )
    pcEnd--;
  *pcEnd = '\0';

  ctxWrite( pCtx, -1, "* STATUS " );
  _ctxWritePath( pCtx, pCmdData->apArg[0], FALSE );
  ctxWriteFmtLn( pCtx, " (%s)", acBuf );
  netsrvClntLog( pClntData, 6, "* STATUS %s (%s)", pCmdData->apArg[0], acBuf );

  return IMAPR_OK_COMPLETED;
}

// ULONG cfnAppend(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
// -------------------------------------------------

// ULONG _cfnAppendParse3Arg(PSZ psz3Arg, PAPPEND3ARG p3Arg)
// Parse first 3 arguments of the APPEND command:
//   mailbox name
//   OPTIONAL flag parenthesized list
//   OPTIONAL date/time string

static ULONG _cfnAppendParse3Arg(PSZ psz3Arg, PFSAPPENDINFO pInfo)
{
  PSZ        pszArg;

  memset( pInfo, 0, sizeof(FSAPPENDINFO) );

  if ( !utilStrCutComp( &psz3Arg, &pInfo->pszMailbox ) )
    return IMAPR_BAD_SYNTAX_ERROR;

  STR_SKIP_SPACES( psz3Arg );
  if ( ( *psz3Arg == '(' ) && utilStrCutList( &psz3Arg, &pszArg ) )
  {
    PSZ      pszFlag;
    LONG     lFlag;

    while( utilStrCutWord( &pszArg, &pszFlag ) )
    {
      lFlag = utilStrWordIndex( "\\SEEN \\ANSWERED \\FLAGGED \\DELETED "
                                "\\DRAFT \\RECENT", -1, pszFlag );
      if ( lFlag == -1 )
      {
        debug( "Unknown flag: %s", pszFlag );
        return IMAPR_NO_UNKNOWN_FLAG;
      }
      pInfo->ulFlags |= (1 << lFlag);
    }
  }

  if ( utilStrCutComp( &psz3Arg, &pszArg ) &&
       !utilStrToIMAPTime( pszArg, &pInfo->timeMsg ) )
    return IMAPR_NO_INVALID_TIME;

  return IMAPR_VOID;
}

static ULONG cfnAppend(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA       pCmdData = pProtoData->pCmdData;
  FSAPPENDINFO   stInfo;
  ULONG          ulRC;
  ULONG          ulUIDValidity, ulUID;

  ulRC = _cfnAppendParse3Arg( pCmdData->apArg[0], &stInfo );
  if ( ulRC != IMAPR_VOID )
    return ulRC;

  if ( pCmdData->cArg == 1 )
  {
    // Preliminary function call before reading the literal.
    // Check the existence of the mailbox.

    //debugCP( "Preliminary function call before reading the literal." );

    return fsQueryMailbox( &pProtoData->stUHSess, stInfo.pszMailbox,
                           FSGMB_STATUS, NULL ) ?
             IMAPR_VOID : IMAPR_NO_TRYCREATE;
  }

  ulRC = fsAppend( &pProtoData->stUHSess, &stInfo, (PCTX)pCmdData->apArg[1],
                   &ulUIDValidity, &ulUID );
  switch( ulRC )
  {
    case FSR_NOMAILBOX:      return IMAPR_NO_TRYCREATE;
    case FSR_DISK_FULL:      return IMAPR_NO_DISK_FULL;
    case FSR_LIMIT_REACHED:  return IMAPR_NO_LIMIT_REACHED;
    case FSR_FAIL:           return IMAPR_NO_FAILURE;
    case FSR_POP3_LOCKED:    return IMAPR_NO_POP3_LOCKED;
  }

  // Make responce like [RFC 4315]:
  // A003 OK [APPENDUID 38505 3955] APPEND completed

  return ctxWriteFmt( pCtx, "%s OK [APPENDUID %u %u] APPEND completed\r\n",
                      pCmdData->acId, ulUIDValidity, ulUID )
           ? IMAPR_VOID : IMAPR_DISCONNECT;
}

static ULONG cfnIdle(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;

  pProtoData->ulState = _STATE_IDLE;
  pProtoData->_sd_pszIdleCmdId = strdup( pCmdData->acId );

  /*
     [RFC 2177] 3. Specification
     ... The server requests a response to the IDLE command using the
     continuation ("+") response.
  */
  return ctxWrite( pCtx, 10, "+ idling\r\n" ) ? IMAPR_VOID : IMAPR_DISCONNECT;
}

static ULONG cfnSetQuota(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  return IMAPR_NO_CANT_SET_THAT_DATA;
}

static ULONG cfnGetQuota(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  // Argument is quota root.
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  MSSIZE     stSizeInfo;
  PCHAR      pcSlash;
  CHAR       acUser[CCHMAXPATHCOMP];
  CHAR       acDomain[CCHMAXPATHCOMP];
  ULONG      ulRC = fsQuerySize( &pProtoData->stUHSess, NULL,
                                 &stSizeInfo, sizeof(acDomain), acDomain );

  if ( ulRC != FSR_OK )
    return IMAPR_NO_INTERNAL_ERROR;

  pcSlash = strchr( acDomain, '\\' );
  if ( pcSlash != NULL )
  {
    *pcSlash = '\0';
    sprintf( acUser, "%s@%s", &pcSlash[1], acDomain );
  }
  else
  {
    strcpy( acUser, acDomain );
    acDomain[0] = '\0';
  }

  if ( stricmp( pCmdData->apArg[0], "~MailRoot" ) == 0 )
  {
    if ( stSizeInfo.llMailRootLimit != LLONG_MAX )
    {
      ctxWriteFmtLn( pCtx, "* QUOTA \"~MailRoot\" (STORAGE %lld %lld)",
                     stSizeInfo.llMailRoot / 1024,
                     stSizeInfo.llMailRootLimit / 1024 );
      return IMAPR_OK_COMPLETED;
    }
  }
  else if ( stricmp( pCmdData->apArg[0], acDomain ) == 0 )
  {
    if ( stSizeInfo.llDomainLimit != LLONG_MAX )
    {
      ctxWriteFmtLn( pCtx, "* QUOTA \"%s\" (STORAGE %lld %lld)",
                     acDomain, stSizeInfo.llDomain / 1024,
                     stSizeInfo.llDomainLimit / 1024 );
      return IMAPR_OK_COMPLETED;
    }
  }
  else if ( stricmp( pCmdData->apArg[0], acUser ) == 0 )
  {
    if ( stSizeInfo.llUserLimit != LLONG_MAX )     // User quota.
    {
      ctxWriteFmtLn( pCtx, "* QUOTA \"%s\" (STORAGE %lld %lld)",
                     acUser, (stSizeInfo.llInbox + stSizeInfo.llImap) / 1024,
                     stSizeInfo.llUserLimit / 1024 );
      return IMAPR_OK_COMPLETED;
    }
  }

  return IMAPR_NO_NOSUCHQUOTA;
}

static ULONG cfnGetQuotaRoot(PCLNTDATA pClntData, PPROTODATA pProtoData,
                             PCTX pCtx)
{
  // Argument: mailbox name
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  MSSIZE     stSizeInfo;
  PCHAR      pcSlash;
  CHAR       acDomain[CCHMAXPATHCOMP];
  CHAR       acUser[CCHMAXPATHCOMP];
  ULONG      ulRC = fsQuerySize( &pProtoData->stUHSess, pCmdData->apArg[0],
                                 &stSizeInfo, sizeof(acDomain), acDomain );

  if ( ulRC == FSR_NOMAILBOX )
    return IMAPR_NO_NONEXISTENT;

  if ( ulRC != FSR_OK )
    return IMAPR_NO_INTERNAL_ERROR;

  pcSlash = strchr( acDomain, '\\' );
  if ( pcSlash != NULL )
  {
    *pcSlash = '\0';
    sprintf( acUser, "%s@%s", &pcSlash[1], acDomain );
  }
  else
  {
    strcpy( acUser, acDomain );
    acDomain[0] = '\0';
  }

  /*
   [RFC 2087] 4.3. GETQUOTAROOT Command
   The GETQUOTAROOT command takes the name of a mailbox and returns the
   list of quota roots for the mailbox in an untagged QUOTAROOT
   response.  For each listed quota root, it also returns the quota
   root's resource usage and limits in an untagged QUOTA response.

   But! Thunderbird and AfterLogic WebMail Lite show only one quota root and
   it's not clear what quota root will be selected for display. Well, we will
   give only one: user home quota if it available, than domain quota if it
   available and finaly MailRoot quota.
  */

  // QUOTAROOT responce.

  ctxWriteFmt( pCtx, "* QUOTAROOT %s", pCmdData->apArg[0] );

  if ( stSizeInfo.llUserLimit != LLONG_MAX )
    ctxWriteFmt( pCtx, " \"%s\"", acUser );             // User quota name.
  else if ( stSizeInfo.llDomainLimit != LLONG_MAX )
    ctxWriteFmt( pCtx, " \"%s\"", acDomain );           // Domain quota name.
  else if ( stSizeInfo.llMailRootLimit != LLONG_MAX )
    ctxWrite( pCtx, 12, " \"~MailRoot\"" );             // MailRoot quota name.

  ctxWrite( pCtx, 2, "\r\n" );                   // End of QUOTAROOT responce.

  // QUOTA responces.

  if ( stSizeInfo.llUserLimit != LLONG_MAX )            // User quota.
    ctxWriteFmtLn( pCtx, "* QUOTA \"%s\" (STORAGE %lld %lld)",
                   acUser, (stSizeInfo.llInbox + stSizeInfo.llImap) / 1024,
                   stSizeInfo.llUserLimit / 1024 );
  else if ( stSizeInfo.llDomainLimit != LLONG_MAX )     // Domain quota.
    ctxWriteFmtLn( pCtx, "* QUOTA \"%s\" (STORAGE %lld %lld)",
                   acDomain, stSizeInfo.llDomain / 1024,
                   stSizeInfo.llDomainLimit / 1024 );
  else if ( stSizeInfo.llMailRootLimit != LLONG_MAX )   // MailRoot quota.
    ctxWriteFmtLn( pCtx, "* QUOTA \"~MailRoot\" (STORAGE %lld %lld)",
                   stSizeInfo.llMailRoot / 1024,
                   stSizeInfo.llMailRootLimit / 1024 );

  return IMAPR_OK_COMPLETED;
}

static ULONG cfnCheck(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  fsSave( &pProtoData->stUHSess );
  return IMAPR_OK_COMPLETED;
//  return IMAPR_NO_NOT_IMPLEMENTED;
}

static ULONG cfnClose(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  fsQueryMailbox( &pProtoData->stUHSess, NULL, FSGMB_SELECT, NULL );
  pProtoData->ulState = _STATE_AUTHENTICATED;
  return IMAPR_OK_COMPLETED;
}

static ULONG cfnExpunge(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  ULONG      ulSeqNum = 0;
  PUTILRANGE pUIDSet = pCmdData->fUID ? pCmdData->apArg[0] : NULL;

  while( fsExpunge( &pProtoData->stUHSess, &ulSeqNum, pUIDSet ) )
    ctxWriteFmtLn( pCtx, "* %u EXPUNGE", ulSeqNum );

  return IMAPR_OK_COMPLETED;
}

static ULONG cfnSearch(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA       pCmdData = pProtoData->pCmdData;

  return cmdSearch( &pProtoData->stUHSess, pCtx, pCmdData->fUID,
                    pCmdData->apArg[0] );
}

// ULONG cfnFetch(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
// ------------------------------------------------

#define _doneFetchBody(__pBody) do { \
  if ( (__pBody)->paPart != NULL ) free( (__pBody)->paPart ); \
} while( FALSE )

static PSZ pszMIMEFields = "Content-Type Content-Transfer-Encoding "
                           "Content-Disposition";

static BOOL _parseFetchBody(PSZ *ppszText, PIMFBODYPARAM pBody/*, BOOL fPeek*/)
{
  PSZ        pszText = *ppszText;
  PCHAR      pcEnd;
  ULONG      ulN;
  PULONG     paPart;

  memset( pBody, 0, sizeof(IMFBODYPARAM) );

  if ( *pszText != '[' )
    return FALSE;

  pcEnd = strchr( pszText, ']' );
  if ( pcEnd == NULL )
    return FALSE;
  *pcEnd = '\0';

  // Read part numbers separated by '.'.
  do
  {
    pszText++;
    ulN = strtoul( pszText, &pcEnd, 10 );
    if ( ( ulN == 0 ) || ( pszText == (PSZ)pcEnd ) )
      break;

    paPart = realloc( pBody->paPart, ( pBody->cPart + 1 ) * sizeof(ULONG) );
    if ( paPart == NULL )
      break;

    paPart[pBody->cPart] = ulN;
    pBody->paPart = paPart;
    pBody->cPart++;
    pszText = pcEnd;
  }
  while( *pszText == '.' );

  do
  {
    if ( *pszText == '\0' )
    {
      // BODY[] or BODY[n1.n2.n3]
      pBody->ulFlags = pBody->cPart == 0 ? IMFFL_FULL : IMFFL_CONTENT;
    }
    else if ( utilStrCutWord( &pszText, (PSZ *)&pcEnd ) )
    {
      LONG     lIdx;

      lIdx = utilStrWordIndex( "HEADER HEADER.FIELDS HEADER.FIELDS.NOT TEXT MIME",
                               -1, pcEnd );
      if ( ( lIdx == -1 ) || ( lIdx == 4 && pBody->cPart == 0 ) )
        break;         // Syntax error.

      if ( ( ( lIdx == 1 ) || ( lIdx == 2 ) ) &&
           utilStrCutList( &pszText, (PSZ *)&pcEnd ) )
        pBody->pszFields = pcEnd;

      switch( lIdx )
      {
        case 0: // HEADER Not listed fileds, field list is empty - full header.
        case 2: // HEADER.FIELDS.NOT Not listed fileds, field list is not empty.
          pBody->ulFlags = IMFFL_HEADER | IMFFL_NOTFIELDS;
          break;

        case 4: // MIME MIME fields.
          pBody->pszFields = pszMIMEFields;

        case 1: // HEADER.FIELDS Listed fields only, field list is not empty.
          pBody->ulFlags = IMFFL_HEADER;
          break;

        case 3: // TEXT Message entry without header.
          pBody->ulFlags = IMFFL_TEXT;
          break;
      }
    }

    pszText = strchr( pszText, '\0' ) + 1;   // After ']'
    STR_SKIP_SPACES( pszText );

    if ( *pszText != '<' )
    {
      *ppszText = pszText;
      return TRUE;
    }

    pszText++;
    if ( *pszText == '>' )
    {
      *ppszText = pszText + 1;
      return TRUE;
    }

    pBody->ullStart = strtoull( pszText, &pcEnd, 10 );
    if ( pszText == (PSZ)pcEnd )
      break;           // Syntax error.
    pBody->ulFlags |= IMFFL_PSTART;

    if ( *pcEnd == '.' )
    {
      pszText = pcEnd + 1;
      pBody->ullLength = strtoull( pszText, &pcEnd, 10 );
      if ( pszText == (PSZ)pcEnd )
        break;         // Syntax error.
      pBody->ulFlags |= IMFFL_PLENGTH;
    }

    if ( *pcEnd != '>' )
      break;           // Syntax error.

    *ppszText = pcEnd + 1;

    return TRUE;
  }
  while( FALSE );

  if ( pBody->paPart != NULL )
    free( pBody->paPart );

  return FALSE;
}

static BOOL _writeFetchBodyReply(PCTX pCtx, PIMFBODYPARAM pBody)
{
  ULONG      ulIdx;
  ULONG      ulFlags = pBody->ulFlags & IMFFL_FULL;

  if ( !ctxWrite( pCtx, 5, "BODY[" ) )
    return FALSE;

  for( ulIdx = 0; ulIdx < pBody->cPart; ulIdx++ )
    ctxWriteFmt( pCtx, ulIdx > 0 ? ".%u" : "%u", pBody->paPart[ulIdx] );

  if ( ( ulFlags != IMFFL_FULL ) &&
       // Flag IMFFL_FULL is used for the request BODY[].
       ( ulFlags != IMFFL_CONTENT ) )
       // Flag IMFFL_CONTENT gives same result as IMFFL_TEXT but it was set for
       // request like BODY[n1.n2.n3] (flag IMFFL_TEXT is used for requests
       // like BODY[n.TEXT]).
  {
    PSZ      pszPart = NULL;
    BOOL     fFields = FALSE;;

    if ( ulIdx > 0 )
      ctxWrite( pCtx, 1, "." );

    switch( ulFlags )
    {
      case (IMFFL_HEADER | IMFFL_NOTFIELDS):
        fFields = pBody->pszFields != NULL;
        pszPart = fFields ? "HEADER.FIELDS.NOT" : "HEADER";
        break;

      case IMFFL_HEADER:
        fFields = pBody->pszFields != pszMIMEFields;
        pszPart = fFields ? "HEADER.FIELDS" : "MIME";
        break;

      case IMFFL_TEXT:
        fFields = FALSE;
        pszPart = "TEXT";
        break;

      default:
        debugCP( "WTF?" );
    }

    ctxWrite( pCtx, -1, pszPart );
    if ( fFields )
      ctxWriteFmt( pCtx, " (%s)", pBody->pszFields );
  }

  if ( (pBody->ulFlags & IMFFL_PSTART) != 0 )
    ctxWriteFmt( pCtx, "]<%lu>", pBody->ullStart );
  else
    ctxWrite( pCtx, 1, "]" );

  return ctxWriteFmtLn( pCtx, " {%lu}", pBody->ullLength );
}

static ULONG cfnFetch(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
#define _FETCH_ITEMS   "BODY BODY.PEEK BODYSTRUCTURE ENVELOPE FLAGS " \
                       "INTERNALDATE RFC822 RFC822.HEADER RFC822.SIZE " \
                       "RFC822.TEXT UID ALL FAST FULL"
#define _FETCH_BODY               0
#define _FETCH_BODYPEEK           1
#define _FETCH_BODYSTRUCTURE      2
#define _FETCH_ENVELOPE           3
#define _FETCH_FLAGS              4
#define _FETCH_INTERNALDATE       5
#define _FETCH_RFC822             6
#define _FETCH_RFC822HEADER       7
#define _FETCH_RFC822SIZE         8
#define _FETCH_RFC822TEXT         9
#define _FETCH_UID               10
#define _FETCH_ALL               11
#define _FETCH_FAST              12
#define _FETCH_FULL              13

#define _FETCH_BODY_MASK         1
#define _FETCH_BODYPEEK_MASK     (1 << _FETCH_BODYPEEK)
#define _FETCH_BODYSTRUCT_MASK   (1 << _FETCH_BODYSTRUCTURE)
#define _FETCH_ENVELOPE_MASK     (1 << _FETCH_ENVELOPE)
#define _FETCH_FLAGS_MASK        (1 << _FETCH_FLAGS)
#define _FETCH_INTERNALDATE_MASK (1 << _FETCH_INTERNALDATE)
#define _FETCH_RFC822_MASK       (1 << _FETCH_RFC822)
#define _FETCH_RFC822HDR_MASK    (1 << _FETCH_RFC822HEADER)
#define _FETCH_RFC822SIZE_MASK   (1 << _FETCH_RFC822SIZE)
#define _FETCH_RFC822TEXT_MASK   (1 << _FETCH_RFC822TEXT)
#define _FETCH_UID_MASK          (1 << _FETCH_UID)

  PCMDDATA       pCmdData = pProtoData->pCmdData;
  PSZ            pszItems = pCmdData->apArg[1];
  FSENUMMSG      stEnum;
  PUTILRANGE     pSeqSet = NULL;
  PUTILRANGE     pUIDSet = NULL;
  PCHAR          pcEnd;
  LONG           lItem = -1;
  ULONG          ulItems = 0;
  PIMFBODYPARAM  pBodySect = NULL;
  ULONG          cBodySect = 0;
  BOOL           fFirst, fFlSeenChanged;
  ULONG          ulIdx;
  PCTX           pCtxItem;
  IMFBODYPARAM   stBodySect;
  UTILFTIMESTAMP stFTimestamp;
  ULLONG         ullFSize;
  BOOL           fHaveNoPeekBody = FALSE;
  BOOL           fCached;

  if ( pCmdData->fUID )
    pUIDSet = pCmdData->apArg[0];
  else
    pSeqSet = pCmdData->apArg[0];

  do
  {
    STR_SKIP_SPACES( pszItems );
    if ( *pszItems == '\0' )
      break;
    pcEnd = pszItems;

    while( isalnum( *pcEnd ) || ( *pcEnd == '.' ) )
      pcEnd++;

    lItem = utilStrWordIndex( _FETCH_ITEMS, pcEnd - (PCHAR)pszItems, pszItems );
    pszItems = pcEnd;
    if ( lItem == -1 )
      break;

    if ( ( ( lItem == _FETCH_BODY ) || ( lItem == _FETCH_BODYPEEK ) ) &&
         ( *pcEnd == '[' ) )
    {
      // BODY[...] or BODY.PEEK[...]
      PIMFBODYPARAM  pNew = realloc( pBodySect,
                                     (cBodySect + 1) * sizeof(IMFBODYPARAM) );
      if ( pNew != NULL )
      {
        pBodySect = pNew;
        if ( !_parseFetchBody( &pszItems, &pNew[cBodySect]/*,
                               lItem == _FETCH_BODYPEEK*/ ) )
          lItem = -1;
        else        
          cBodySect++;
      }

      if ( lItem == _FETCH_BODY )
        fHaveNoPeekBody = TRUE;
    }
    else
    {
      // Collect ulItems flags _FETCH_xxxxx.

      switch( lItem )
      {
        case _FETCH_ALL:
          ulItems |= _FETCH_FLAGS_MASK | _FETCH_INTERNALDATE_MASK |
                     _FETCH_RFC822SIZE_MASK | _FETCH_ENVELOPE_MASK;
          break;

        case _FETCH_FAST:
          ulItems |= _FETCH_FLAGS_MASK | _FETCH_INTERNALDATE_MASK |
                     _FETCH_RFC822SIZE_MASK;
          break;

        case _FETCH_FULL:
          ulItems |= _FETCH_FLAGS_MASK | _FETCH_INTERNALDATE_MASK |
                     _FETCH_RFC822SIZE_MASK | _FETCH_ENVELOPE_MASK |
                     _FETCH_BODY_MASK;
          break;

        default:
          ulItems |= (1 << lItem);         // _FETCH_xxxxx_MASK
      }
    }
  }
  while( lItem != -1 );

  if ( lItem == -1 )
  {
    for( ulIdx = 0; ulIdx < cBodySect; ulIdx++ )
      _doneFetchBody( &pBodySect[ulIdx] );
    if ( pBodySect != NULL )
      free( pBodySect );

    return IMAPR_BAD_SYNTAX_ERROR;
  }

  if ( pCmdData->fUID )
    ulItems |= _FETCH_UID_MASK;

  if ( (ulItems & _FETCH_INTERNALDATE_MASK) != 0 )
    tzset();

  // FETCH Responses.

  fsEnumMsgBegin( &pProtoData->stUHSess, &stEnum, pSeqSet, pUIDSet );
  while( fsEnumMsg( &pProtoData->stUHSess, &stEnum ) )
  {
    if ( (ulItems & (_FETCH_RFC822SIZE_MASK | _FETCH_INTERNALDATE_MASK)) != 0 )
    {
      debug( "utilQueryFileInfo(\"%s\",,)...", stEnum.acFile );
      if ( !utilQueryFileInfo( stEnum.acFile, &stFTimestamp, &ullFSize ) )
      {
        debug( "utilQueryFileInfo(\"%s\",) failed", stEnum.acFile );
        continue;
      }
    }

    ctxWriteFmt( pCtx, "* %u FETCH (", stEnum.ulIndex );
    fFlSeenChanged = FALSE;
    fFirst = TRUE;

    if ( !pProtoData->stUHSess.fSelMailboxRO )
    {
      // Selected mailbox is not in read-only mode.

      stEnum.ulFlags &= ~FSMSGFL_RECENT;

      if ( fHaveNoPeekBody && ( (stEnum.ulFlags & FSMSGFL_SEEN) == 0 ) )
      {
        // Flag changes will be applied by fsEnumMsg().
        stEnum.ulFlags |= FSMSGFL_SEEN;
        // BODY[] fetch request changes \seen flag - send changed flags.
        fFlSeenChanged = TRUE;
      }
    }

    /* ulItems - flags for all request parts except particular body section
       for BODY[...] and BODY.PEEK[...]  */

    if ( (ulItems & _FETCH_BODY_MASK) != 0 )
    {
      pCtxItem = imfGetBodyStruct( stEnum.acFile, FALSE );
      if ( pCtxItem != NULL )
      {
        if ( !fFirst )
          ctxWrite( pCtx, 1, " " );
        else
          fFirst = FALSE;

        ctxWrite( pCtx, 5, "BODY " );
        ctxWriteCtx( pCtx, pCtxItem, CTX_ALL );
        ctxFree( pCtxItem );
      }
    }

    if ( (ulItems & _FETCH_BODYSTRUCT_MASK) != 0 )
    {
      pCtxItem = imfGetBodyStruct( stEnum.acFile, TRUE );
      if ( pCtxItem != NULL )
      {
        if ( !fFirst )
          ctxWrite( pCtx, 1, " " );
        else
          fFirst = FALSE;

        ctxWrite( pCtx, -1, "BODYSTRUCTURE " );
        ctxWriteCtx( pCtx, pCtxItem, CTX_ALL );
        ctxFree( pCtxItem );
      }
    }

    if ( (ulItems & _FETCH_ENVELOPE_MASK) != 0 )
    {
      pCtxItem = imfGetEnvelope( stEnum.acFile );
      if ( pCtxItem != NULL )
      {
        if ( !fFirst )
          ctxWrite( pCtx, 1, " " );
        else
          fFirst = FALSE;

//        ctxWriteFmtLn( pCtx, "ENVELOPE {%lu}", ctxQuerySize( pCtxItem ) );
        ctxWrite( pCtx, -1, "ENVELOPE " );
        ctxWriteCtx( pCtx, pCtxItem, CTX_ALL );
        ctxFree( pCtxItem );
      }
    }

    if ( ( (ulItems & _FETCH_FLAGS_MASK) != 0 ) || fFlSeenChanged )
    {
      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      _ctxWriteMsgFlags( pCtx, stEnum.ulFlags );
    }

    if ( (ulItems & _FETCH_INTERNALDATE_MASK) != 0 )
    {
      // INTERNALDATE "17-Jul-1996 02:44:25 -0700"
      static PSZ       aMonth[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
      LONG             lTZM = -timezone / 60;

      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      ctxWriteFmt( pCtx, "INTERNALDATE \"%u-%s-%u %.2u:%.2u:%.2u %+.2d%.2d\"",
                   stFTimestamp.fdateLastWrite.day,
                   aMonth[stFTimestamp.fdateLastWrite.month - 1],
                   stFTimestamp.fdateLastWrite.year + 1980,
                   stFTimestamp.ftimeLastWrite.hours,
                   stFTimestamp.ftimeLastWrite.minutes,
                   stFTimestamp.ftimeLastWrite.twosecs * 2,
                   lTZM / 60, lTZM % 60 );
    }

    if ( (ulItems & _FETCH_RFC822SIZE_MASK) != 0 )
    {
      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      ctxWriteFmt( pCtx, "RFC822.SIZE %llu", ullFSize );
    }

    if ( (ulItems & _FETCH_UID_MASK) != 0 )
    {
      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      ctxWriteFmt( pCtx, "UID %u", stEnum.ulUID );
    }

    if ( (ulItems & _FETCH_RFC822HDR_MASK) != 0 )
    {
      // Equivalent to BODY[HEADER].

      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      stBodySect.cPart = 0;
      stBodySect.paPart = NULL;
      stBodySect.ulFlags = IMFFL_HEADER | IMFFL_NOTFIELDS;
      stBodySect.pszFields = NULL;

      pCtxItem = imfGetBody( stEnum.acFile, &stBodySect );

      if ( pCtxItem != NULL )
      {
        ctxWriteFmtLn( pCtx, "RFC822.HEADER {%lu}", stBodySect.ullLength );
        ctxWriteCtx( pCtx, pCtxItem, stBodySect.ullLength );
        ctxFree( pCtxItem );
      }
    }

    if ( (ulItems & _FETCH_RFC822_MASK) != 0 )
    {
      // Equivalent to BODY[]. Untagged FETCH data is RFC822.

      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      stBodySect.cPart = 0;
      stBodySect.paPart = NULL;
      stBodySect.ulFlags = IMFFL_FULL;
      stBodySect.pszFields = NULL;

      pCtxItem = imfGetBody( stEnum.acFile, &stBodySect );

      if ( pCtxItem != NULL )
      {
        ctxWriteFmtLn( pCtx, "RFC822 {%lu}", stBodySect.ullLength );
        ctxWriteCtx( pCtx, pCtxItem, stBodySect.ullLength );
        ctxFree( pCtxItem );
      }
    }

    if ( (ulItems & _FETCH_RFC822TEXT_MASK) != 0 )
    {
      // Equivalent to BODY[TEXT].

      if ( !fFirst )
        ctxWrite( pCtx, 1, " " );
      else
        fFirst = FALSE;

      stBodySect.cPart = 0;
      stBodySect.paPart = NULL;
      stBodySect.ulFlags = IMFFL_TEXT;
      stBodySect.pszFields = NULL;

      pCtxItem = imfGetBody( stEnum.acFile, &stBodySect );

      if ( pCtxItem != NULL )
      {
        ctxWriteFmtLn( pCtx, "RFC822.TEXT {%lu}", stBodySect.ullLength );
        ctxWriteCtx( pCtx, pCtxItem, stBodySect.ullLength );
        ctxFree( pCtxItem );
      }
    }

    /* The text of a particular body section - BODY[...]<n> ...
       We cache the response context to avoid opening the file frequently and
       examine its structure.  */

    for( ulIdx = 0; ulIdx < cBodySect; ulIdx++ )
    {
      // Look for cached context object.
      pCtxItem = _bcGet( pProtoData, stEnum.ulUID, &pBodySect[ulIdx] );
      fCached = pCtxItem != NULL;
      if ( !fCached )
      {
        debugCP( "Body was not cached" );
        pCtxItem = imfGetBody( stEnum.acFile, &pBodySect[ulIdx] );
      }
      else
        debugCP( "Body has been cached" );

      if ( pCtxItem != NULL )
      {
        if ( !fCached )
          fCached = _bcPut( pProtoData, stEnum.ulUID, &pBodySect[ulIdx],
                            pCtxItem );

        if ( !fFirst )
          ctxWrite( pCtx, 1, " " );
        else
          fFirst = FALSE;

        if ( _writeFetchBodyReply( pCtx, &pBodySect[ulIdx] ) )
          ctxWriteCtx( pCtx, pCtxItem, pBodySect[ulIdx].ullLength );

        if ( !fCached )
          ctxFree( pCtxItem );
      }
    }

    ctxWriteStrLn( pCtx, ")" );
  } // while( fsEnumMsg( &pProtoData->stUHSess, &stEnum ) )
  fsEnumMsgEnd( &pProtoData->stUHSess, &stEnum );

  for( ulIdx = 0; ulIdx < cBodySect; ulIdx++ )
    _doneFetchBody( &pBodySect[ulIdx] );
  if ( pBodySect != NULL )
    free( pBodySect );

  return IMAPR_OK_COMPLETED;
}

// ULONG cfnStore(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
// ---------------------------------------------------------------------

static ULONG _strToFlags(PSZ pszFlags)
{
  ULONG      cbFlags = STR_LEN( pszFlags );
  ULONG      cbFlag;
  PCHAR      pcFlag;
  ULONG      ulFlags = 0;
  LONG       lIdx;

  while( utilBufCutWord( &cbFlags, (PCHAR *)&pszFlags, &cbFlag, &pcFlag ) )
  {
    // \Recent flag can not be altered by the client.
    lIdx = utilStrWordIndex( "\\SEEN \\ANSWERED \\FLAGGED \\DELETED \\DRAFT"
                             /* " \\RECENT" */, cbFlag, pcFlag );
    if ( lIdx == -1 )
    {
      debug( "Unknown flag: %s", debugBufPSZ( pcFlag, cbFlag ) );
      continue;
    }

    ulFlags |= 1 << lIdx;
  }

  return ulFlags;
}

static ULONG cfnStore(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  PCMDDATA       pCmdData = pProtoData->pCmdData;
  PSZ            pszItem = pCmdData->apArg[1];
  PUTILRANGE     pSeqSet = NULL;
  PUTILRANGE     pUIDSet = NULL;
  ULONG          ulOp;
  BOOL           fSilent = FALSE;
  ULONG          ulFlags, ulMsgFlags;
  FSENUMMSG      stEnum;
  ULONG          ulResult = IMAPR_OK_COMPLETED;

  if ( pCmdData->fUID )
    pUIDSet = pCmdData->apArg[0];
  else
    pSeqSet = pCmdData->apArg[0];

  switch( pszItem[0] )
  {
    case '+': ulOp = 1; break;   // Add listed flags.
    case '-': ulOp = 2; break;   // Remove listed flags.
    default:  ulOp = 0;          // Replace flags with listed.
  }
  if ( ulOp != 0 )
    pszItem++;

  do
  {
    if ( memicmp( pszItem, "FLAGS", 5 ) != 0 )
    {
      ulResult = IMAPR_BAD_SYNTAX_ERROR;
      break;
    }

    pszItem += 5;

    if ( *pszItem != '\0' )
    {
      if ( stricmp( pszItem, ".SILENT" ) != 0 )
      {
        ulResult = IMAPR_BAD_SYNTAX_ERROR;
        break;
      }
      fSilent = TRUE;
    }

    fsEnumMsgBegin( &pProtoData->stUHSess, &stEnum, pSeqSet, pUIDSet );

    if ( pProtoData->stUHSess.fSelMailboxRO )
      debugCP( "Attempt set flags for message in read-only selected mailbox" );
    else
    {
      ulFlags = _strToFlags( pCmdData->apArg[2] );
      debug( "flags: 0x%X", ulFlags );

      while( fsEnumMsg( &pProtoData->stUHSess, &stEnum ) )
      {
        ulMsgFlags = stEnum.ulFlags;

        switch( ulOp )
        {
          case 1:          // Add listed flags.
            stEnum.ulFlags |= ulFlags;
           break;

          case 2:          // Remove listed flags.
            stEnum.ulFlags &= ~ulFlags;
           break;

          default:         // 0 - Replace flags with listed (other than \Recent).
            stEnum.ulFlags = (stEnum.ulFlags & FSMSGFL_RECENT) | ulFlags;
           break;
        }

        if ( !fSilent && ( ulMsgFlags != stEnum.ulFlags ) )
        {
          ctxWriteFmt( pCtx, "* %u FETCH (", stEnum.ulIndex );
          _ctxWriteMsgFlags( pCtx, stEnum.ulFlags );

          if ( pCmdData->fUID )
            ctxWriteFmt( pCtx, " UID %u", stEnum.ulUID );

          ctxWriteStrLn( pCtx, ")" );
        }
      }  // while( fsEnumMsg( &pProtoData->stUHSess, &stEnum ) )
    }  // if ( !pProtoData->stUHSess.fSelMailboxRO )

    fsEnumMsgEnd( &pProtoData->stUHSess, &stEnum );
  }
  while( FALSE );

  return ulResult;
}

// cfnCopy() and cfnMove()
// -----------------------

static ULONG _cfnCopyMove(PCLNTDATA pClntData, PPROTODATA pProtoData,
                          PCTX pCtx, BOOL fMove)
{
  PCMDDATA       pCmdData = pProtoData->pCmdData;
  PUTILRANGE     pSeqSet = NULL;
  PUTILRANGE     pUIDSet = NULL;
  ULONG          ulRC;
  COPYUID        stCopyUID;
  PSZ            pszUIDs = NULL;
  LONG           cbUIDs, cbDstUIDs;

  if ( pCmdData->fUID )
    pUIDSet = pCmdData->apArg[0];
  else
    pSeqSet = pCmdData->apArg[0];

  if ( fMove )
    ulRC = fsMove( &pProtoData->stUHSess, pSeqSet, pUIDSet, pCmdData->apArg[1],
                   &stCopyUID );
  else
    ulRC = fsCopy( &pProtoData->stUHSess, pSeqSet, pUIDSet, pCmdData->apArg[1],
                   &stCopyUID );

  switch( ulRC )
  {
    case FSR_NOMAILBOX:      return IMAPR_NO_TRYCREATE;
    case FSR_DISK_FULL:      return IMAPR_NO_DISK_FULL;
    case FSR_LIMIT_REACHED:  return IMAPR_NO_LIMIT_REACHED;
    case FSR_FAIL:           return IMAPR_NO_FAILURE;
    case FSR_POP3_LOCKED:    return IMAPR_NO_POP3_LOCKED;
  }

  if ( ulRC != FSR_OK )
    debugCP( "WTF?!" );

  ulRC = IMAPR_OK_COMPLETED;

  if ( ( stCopyUID.pSrcUIDs != NULL ) && ( stCopyUID.pDstUIDs != NULL ) )
  do
  {
    // Make responce like [RFC 4315]:
    // A004 OK [COPYUID 38505 304,319:320 3956:3958] Done

    cbUIDs = utilNumSetToStr( stCopyUID.pSrcUIDs, 0, NULL );
    cbDstUIDs = utilNumSetToStr( stCopyUID.pDstUIDs, 0, NULL );
    if ( ( cbUIDs <= 0 ) || ( cbDstUIDs <= 0 ) )
      break;

    cbDstUIDs++;  // trailing ZERO
    cbUIDs += cbDstUIDs + 1;  // +1 - SPACE
    pszUIDs = malloc( cbUIDs );
    if ( pszUIDs == NULL )
      break;

    cbUIDs = utilNumSetToStr( stCopyUID.pSrcUIDs, cbUIDs, (PCHAR)pszUIDs );
    if ( cbUIDs == -1 )
      break;
    pszUIDs[cbUIDs] = ' ';
    cbUIDs++;
    cbUIDs = utilNumSetToStr( stCopyUID.pDstUIDs, cbDstUIDs,
                              (PCHAR)&pszUIDs[cbUIDs] );
    if ( cbUIDs == -1 )
      break;

    if ( fMove )
    {
      /*
         [RFC 6851] 4.3.  RFC 4315, UIDPLUS
         ... Servers implementing UIDPLUS are also advised to send the COPYUID
         response code in an untagged OK before sending EXPUNGE or moved
         responses.  (Sending COPYUID in the tagged OK, as described in the
         UIDPLUS specification, means that clients first receive an EXPUNGE
         for a message and afterwards COPYUID for the same message.  It can be
         unnecessarily difficult to process that sequence usefully.)
      */
      ctxWriteFmt( pCtx, "* OK [COPYUID %u ", stCopyUID.ulUIDValidity );
      ctxWrite( pCtx, -1, pszUIDs );
      ctxWrite( pCtx, 3, "]\r\n" );

      _clntSendChanges( pClntData, SEM_INDEFINITE_WAIT );
    }

    ulRC = ctxWriteFmt( pCtx, "%s OK [COPYUID %u ",
                        pCmdData->acId, stCopyUID.ulUIDValidity ) &&
           ctxWrite( pCtx, -1, pszUIDs ) &&
           ctxWrite( pCtx, 8, "] Done\r\n" )
             ? IMAPR_VOID : IMAPR_DISCONNECT;
  }
  while( FALSE );

  if ( pszUIDs != NULL )
    free( pszUIDs );

  // Destroy memory blocks allocated by fsCopy().
  fsFreeCopyUID( &stCopyUID );

  return ulRC;
}

static ULONG cfnCopy(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  return _cfnCopyMove( pClntData, pProtoData, pCtx, FALSE );
}

static ULONG cfnMove(PCLNTDATA pClntData, PPROTODATA pProtoData, PCTX pCtx)
{
  return _cfnCopyMove( pClntData, pProtoData, pCtx, TRUE );
}

static BOOL imapRequest(PCLNTDATA pClntData, LONG cbInput, PCHAR pcInput)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PCMDDATA   pCmdData = pProtoData->pCmdData;
  PCMD       pCmd;
  ULONG      ulResp;
  PSZ        pszArg;

  if ( pProtoData->ulState == _STATE_IDLE )
  {
    if ( stricmp( pcInput, "DONE" ) == 0 )
    {
      pProtoData->ulState = _STATE_SELECTED;
      ulResp = _clntWriteResp( pClntData, pProtoData->_sd_pszIdleCmdId, "IDLE",
                               IMAPR_OK_IDLE_TERMINATED );
      free( pProtoData->_sd_pszIdleCmdId );
      pProtoData->_sd_pszIdleCmdId = NULL;
    }
    else
      ulResp = TRUE;

    return ulResp;
  }

  /*
     Authentication protocol.
  */

  if ( pProtoData->_sd_pAuth != NULL )
  {
    ULONG    cbBuf = 0;
    PCHAR    pcBuf = NULL;
    BOOL     fSuccess;

    if ( *pcInput == '*' )
      return _authResp( pClntData, IMAPR_BAD_CANCELED );

    if ( !utilB64Dec( cbInput, pcInput, &cbBuf, &pcBuf ) )
      return _authResp( pClntData, IMAPR_NO_INTERNAL_ERROR );

    fSuccess = _authClientResponse( pClntData, cbBuf, pcBuf );
    free( pcBuf );

    return fSuccess;
  }

  /*
     Read command from the input data. Prepare pProtoData->pCmdData object.
  */

  if ( netsrvClntGetRawInput( pClntData ) )
  {
    // Read the literal data.

    ULONG    cbChunk = MIN( cbInput, pCmdData->ullLitOctets );

    pCmd = &aCmdList[pCmdData->ulCmd];

    if ( pCmdData->pLitCtx == NULL )
    {
      // First block of the literal data.
      pCmdData->pLitCtx = ctxNew();
      if ( pCmdData == NULL )
      {
        _clntWriteResp( pClntData, pCmdData->acId, pCmd->pszName,
                       IMAPR_NO_INTERNAL_ERROR );
        return FALSE;
      }
    }

    // Store the input data chunk to the literal context.
    if ( !ctxWrite( pCmdData->pLitCtx, cbChunk, pcInput ) )
    {
      _clntWriteResp( pClntData, pCmdData->acId, pCmd->pszName,
                     IMAPR_NO_INTERNAL_ERROR );
      return FALSE;
    }

    pCmdData->ullLitOctets -= cbChunk;
    netsrvClntSetRawInput( pClntData, pCmdData->ullLitOctets );

    if ( pCmdData->ullLitOctets == 0 )
    {
      // The literal is fully read.

      ULONG  ulArgFl = pCmd->aulArg[pCmdData->cArg];

      if ( ulArgFl == _ARGFL_LIT )
        pCmdData->apArg[pCmdData->cArg] = pCmdData->pLitCtx;
      else
      {
        ULLONG           cbLitData = ctxQuerySize( pCmdData->pLitCtx );
        PCHAR            pcLitData = malloc( cbLitData + 1 );

        if ( pcLitData == NULL )
        {
          _clntWriteResp( pClntData, pCmdData->acId, pCmd->pszName,
                          IMAPR_NO_INTERNAL_ERROR );
          return FALSE;
        }

        cbLitData = ctxRead( pCmdData->pLitCtx, cbLitData, pcLitData, FALSE );
        pcLitData[cbLitData] = '\0';
        ctxFree( pCmdData->pLitCtx );

        switch( ulArgFl )
        {
          case _ARGFL_STR:
          case _ARGFL_RAW:
            pCmdData->apArg[pCmdData->cArg] = pcLitData;
            break;

          case _ARGFL_PLST:
            if ( utilStrCutList( (PSZ *)&pcLitData, &pszArg ) )
              pCmdData->apArg[pCmdData->cArg] = strdup( pszArg );
            free( pcLitData );
            break;

          case _ARGFL_SEQ:
            utilStrToNewNumSet( pcLitData,
                              (PUTILRANGE *)&pCmdData->apArg[pCmdData->cArg] );
            free( pcLitData );
            break;

          default:
            debugCP( "WTF?" );
            free( pcLitData );
        }  // switch
      }

      pCmdData->pLitCtx = NULL;
      pCmdData->cArg++;
    } // if ( pCmdData->ullLitOctets == 0 )

    if ( pCmd->aulArg[pCmdData->cArg] != 0 )
      // Not all arguments are read.
      return TRUE;

    pcInput += cbChunk;
    cbInput -= cbChunk;
  }
  else if ( pCmdData == NULL )
  {
    // Begin the parsing of the command.

    LONG     lCmd = -1;
    PSZ      pszCmdId, pszCmd;
    BOOL     fUID;

    // Read command identifier, prefix "UID" and command. Find command index.

    if ( cbInput == 0 )
    {
      // Empty line.
      pProtoData->usBadCommands++;
      return ( pProtoData->usBadCommands < _MAX_BAD_COMMANDS );
    }

         // Read command identifier (tag).
    if ( utilStrCutWord( (PSZ *)&pcInput, &pszCmdId ) &&
         // Read command name.
         utilStrCutWord( (PSZ *)&pcInput, &pszCmd ) )
    {
      fUID = stricmp( pszCmd, "UID" ) == 0;
             // UID prefix specified, command name is a next word.

      // Search command in our commands list ( aCmdList[] ).
      if ( !fUID || utilStrCutWord( (PSZ *)&pcInput, &pszCmd ) )
      {
        for( lCmd = ARRAYSIZE(aCmdList) - 1;
             lCmd >= 0 && ( stricmp( pszCmd, aCmdList[lCmd].pszName ) != 0 );
             lCmd-- );

        if ( ( lCmd != -1 ) && fUID && !aCmdList[lCmd].fUID )
          // Command has been found but don't support UID prefix.
          lCmd = -1;
      }
    }

    if ( lCmd < 0 )
      return _clntWriteResp( pClntData, pszCmdId, NULL,
                             IMAPR_BAD_COMMAND_ERROR );

    if ( lCmd > aStateAllowCmd[pProtoData->ulState] )
      return _clntWriteResp( pClntData, pszCmdId, pszCmd,
                             IMAPR_BAD_INVALID_STATE );

    // Create the PCMDDATA object.

    pCmdData = calloc( 1, sizeof(CMDDATA) + strlen( pszCmdId ) );
    if ( pCmdData == NULL )
      return _clntWriteResp( pClntData, pszCmdId, pszCmd,
                             IMAPR_NO_INTERNAL_ERROR );

    pCmdData->ulCmd = lCmd;
    pCmdData->fUID  = fUID;
    strcpy( pCmdData->acId, pszCmdId );
    pProtoData->pCmdData = pCmdData;
  }

  // Parsing arguments.

  pCmd = &aCmdList[pCmdData->ulCmd];

  {
    ULONG    ulArgFl;
    BOOL     fArg;
    PCHAR    pcEnd = strchr( pcInput, '\0' );
    BOOL     fLiteral = FALSE, fLiteralPlus = FALSE;

    // Detecting a literal in a command.
    // Set variables fLiteral, fLiteralPlus and pCmdData->ulLitOctets.

    if ( *(pcEnd-1) == '}' )
    {
      PCHAR    pcRCurlyBracket = pcEnd - 1;
      PCHAR    pcLCurlyBracket = pcRCurlyBracket;

      while( pcLCurlyBracket > pcInput )
      {
        pcLCurlyBracket--;
        if ( *pcLCurlyBracket == '{' )
        {
          fLiteral = TRUE;
          break;
        }
      }

      if ( fLiteral )
      {
        PCHAR   pcOctets = pcLCurlyBracket + 1;
        PCHAR   pcEndOctets;

        pCmdData->ullLitOctets = strtol( pcOctets, &pcEndOctets, 10 ); 
        if ( pcOctets == pcEndOctets )
          fLiteral = FALSE;
        else if ( *pcEndOctets == '+' )
          fLiteralPlus = TRUE;
        else if ( pcEndOctets != pcRCurlyBracket )
          fLiteral = FALSE;

        if ( fLiteral )
          *pcLCurlyBracket = '\0';
      }
    }

    // Read arguments from the line.

    while( TRUE )
    {
      ulArgFl = pCmd->aulArg[pCmdData->cArg];
      if ( ulArgFl == 0 )
        // All arguments are read.
        break;

      STR_SKIP_SPACES( pcInput );
      if ( *pcInput == '\0' )
      {
        if ( fLiteral && ( pCmdData->ullLitOctets != 0 ) )
        {
          PCTX         pCtx = netsrvClntGetContext( pClntData );

          if ( pCtx == NULL )
            return FALSE;

          if ( ( (ulArgFl & _ARGFL_TYPEMASK) == _ARGFL_LIT ) && !fLiteralPlus )
          {
          /*
            A special case for the literal argument (used in APPDEND command).
            Preliminary command function call to test arguments. Function
            should check arguments counter to detect preliminary or final call.

            Thunderbird sends literal-plus with APPEND and does not want any
            responces before end of command (we must first get the entire
            message body).

            [RFC 3502] 6.3.11.  APPEND Command
            ... The server MAY return an error before processing all the
            message arguments.
          */

            ulResp = pCmd->fnCmd( pClntData, pProtoData, pCtx );

            if ( ulResp != IMAPR_VOID )
            {
              ulResp = _clntWriteResp( pClntData, pCmdData->acId,
                                       aCmdList[pCmdData->ulCmd].pszName,
                                       ulResp );
              _cmdDataFree( pProtoData );

              return ulResp;
            }
            // Response IMAPR_VOID - start reading the literal.
          }

          netsrvClntSetRawInput( pClntData, pCmdData->ullLitOctets );

          return fLiteralPlus ||
                 ctxWriteStrLn( pCtx, "+ Ready for additional command text" );
        }

        if ( (ulArgFl & _ARGFL_OPTIONAL) != 0 )
        {
          pCmdData->cArg++;
          continue;
        }

        fArg = FALSE;  // syntax error.
      }
      else
      {
        switch( ulArgFl & _ARGFL_TYPEMASK )
        {
          case _ARGFL_WRD:
            fArg = utilStrCutWord( (PSZ *)&pcInput, &pszArg );
            if ( fArg )
              pCmdData->apArg[pCmdData->cArg] = strdup( pszArg );
            break;

          case _ARGFL_STR:
            fArg = utilStrCutComp( (PSZ *)&pcInput, &pszArg );
            if ( fArg )
              pCmdData->apArg[pCmdData->cArg] = strdup( pszArg );
            break;

          case _ARGFL_PLST:
            fArg = utilStrCutList( (PSZ *)&pcInput, &pszArg );
            if ( fArg )
              pCmdData->apArg[pCmdData->cArg] = strdup( pszArg );
            break;

          case _ARGFL_SEQ:
            fArg = utilStrCutWord( (PSZ *)&pcInput, &pszArg );
            if ( fArg )
              fArg = utilStrToNewNumSet( pszArg,
                              (PUTILRANGE *)&pCmdData->apArg[pCmdData->cArg] );
            break;

          case _ARGFL_RAW:
            pCmdData->apArg[pCmdData->cArg] = strdup( pcInput );
            fArg = TRUE;
            pcInput = strchr( pcInput, '\0' );
            break;

          case _ARGFL_LIT:
            fArg = FALSE;        // Syntax error.
            break;

          default:
            debug( "Unknown flag 0x%X for argument #%u in command #%u",
                   ulArgFl, pCmdData->cArg, pCmdData->ulCmd );
            fArg = TRUE;
        }  // switch
      }  // if ( *pszLine == '\0' ) else

      if ( !fArg || ( pCmdData->apArg[pCmdData->cArg] == NULL ) )
      {
        ulResp = _clntWriteResp( pClntData, pCmdData->acId,
                       aCmdList[pCmdData->ulCmd].pszName,
                       fArg ? IMAPR_NO_INTERNAL_ERROR : IMAPR_BAD_SYNTAX_ERROR );

        _cmdDataFree( pProtoData );

        return ulResp;
      }

      pCmdData->cArg++;
    }  // while( TRUE )
  }

#if 0
  // Debug parser via telnet.
  {
    PCTX               pCtx = netsrvClntGetContext( pClntData );

    ctxWriteFmtLn( pCtx,
             "Id: %s, Cmd: [%u] %s, Arguments: %u",
             pCmdData->acId,
             pCmdData->ulCmd, aCmdList[pCmdData->ulCmd].pszName,
             pCmdData->cArg );
    {
      ULONG    ulIdx;

      for( ulIdx = 0; ulIdx < pCmdData->cArg; ulIdx++ )
        if ( pCmd->aulArg[ulIdx] == _ARGFL_SEQ )
        {
          CHAR          acBuf[128];

          utilNumSetToStr( (PUTILRANGE)pCmdData->apArg[ulIdx],
                           sizeof(acBuf), acBuf );
          ctxWriteFmtLn( pCtx, "Arg #%u: sequence:<%s>", ulIdx, acBuf );
        }
        else if ( pCmd->aulArg[ulIdx] == _ARGFL_LIT )
        {
          CHAR   acBuf[2048];
          ULONG  cbBuf = ctxRead( (PCTX)pCmdData->apArg[ulIdx],
                                  sizeof(acBuf) - 1, acBuf, TRUE );

          acBuf[cbBuf] = '\0';

          ctxWriteFmtLn( pCtx, "Arg #%u: literal:<%s>", ulIdx, acBuf );
        }
        else
          ctxWriteFmtLn( pCtx, "Arg #%u: %s", ulIdx, pCmdData->apArg[ulIdx] );
    }
  }

  _cmdDataFree( pProtoData );

  return TRUE;
#endif

  /*
     We have a new command at pProtoData->pCmdData object.

     Send untagged responses: EXPUNGE and FETCH(FLAGS ...) for changed messages
     in selected mailbox and EXISTS and RECENT on changes (made by other
     clients) in selected mailbox.
     SELECT (6) and EXAMINE (7) will generate EXISTS and RECENT responces -
     no need to send it here.
  */
  if ( ( pProtoData->ulState >= _STATE_SELECTED ) &&
       ( ( pCmdData->ulCmd != 6 ) && ( pCmdData->ulCmd != 7 ) ) )
    _clntSendChanges( pClntData, SEM_INDEFINITE_WAIT );

  /*
     Call the command function.
  */

  {
    PCTX               pCtx = netsrvClntGetContext( pClntData );

    if ( pCtx == NULL )
      ulResp = (ULONG)FALSE;
    else
      ulResp = _clntWriteResp( pClntData, pCmdData->acId,
                              aCmdList[pCmdData->ulCmd].pszName,
                              pCmd->fnCmd == NULL
                                ? IMAPR_NO_NOT_IMPLEMENTED
                                : pCmd->fnCmd( pClntData, pProtoData, pCtx ) );
  }

  _cmdDataFree( pProtoData );

  return (BOOL)ulResp;
}

static VOID imapReadyToSend(PCLNTDATA pClntData)
{
  /*
     Here we can send data that the client did not request.
     [RFC 3501] 5.2. Mailbox Size and Message Status Updates
     At any time, a server can send data that the client did not request.
     Sometimes, such behavior is REQUIRED.

     ver. 0.0.7 Now we do it only in IDLE state (RFC 2177).
  */

  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  if ( pProtoData->ulState == _STATE_IDLE )
  {
    // We are not waiting for the data to become available - this function
    // should be executed as soon as possible (we always can get changes
    // on subsequent function calls).
    _clntSendChanges( pClntData, SEM_IMMEDIATE_RETURN );
  }
}

VOID imapIdle(ULONG ulTime)
{
  CHAR       acBuf[CCHMAXPATH];
  ULONG      ulRC = fsNotifyCheck( ulTime, sizeof(acBuf), acBuf );

  if ( ulRC != FSNRC_DELAYED )
  {
    if ( ulRC >= ARRAYSIZE(apszFSNotifyResults) )
      logf( 4, "Notify \"%s\": #%lu", acBuf, ulRC );
    else
      logf( 4, "Notify \"%s\": %s", acBuf, &apszFSNotifyResults[ulRC][1] );
  }
  else
    fsSaveCheck( ulTime );
}


BOOL imapInit()
{
  fGlIMAPEnabled = TRUE;
  return fsInit();
}

VOID imapDone()
{
  fsDone();
}


// Protocol handler.

NSPROTO stProtoIMAP = {
  sizeof(PROTODATA),   // cbProtoData
  "IMAP",              // acLogId
  1000 * 60 * 30,      // ulTimeout
  0,                   // ulMaxClients
  imapNew,             // fnNew
  imapDestroy,         // fnDestroy
  imapRequest,         // fnRequest
  imapReadyToSend,     // fnReadyToSend
  imapIdle             // fnIdle
};
