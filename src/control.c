/*
    Control commands.

    The implementation of the control protocol. This module does not interact
    with the client. Modules ctlpipe and ctlproto provide user interaction
    through appropriate interfaces.
*/

#include <string.h>
#include <ctype.h>
#define INCL_DOSMISC
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <os2.h>
#include "linkseq.h"
#include "log.h"
#include "context.h"
#include "wcfg.h"
#include "piper.h"
#include "storage.h"
#include "imapfs.h"
#include "control.h"
#include "debug.h"               // Should be last.


typedef struct _EXQUOTARCPT {
  ULONG                cObjects;
  PSZ                  *ppszObjects;     // List of objects where quota excess.
  PSZ                  pszAttachFile;
  PSZ                  pszTempFile;
  CHAR                 acRcpt[1];        // Address for sending notification.
} EXQUOTARCPT;


extern PPIPER          pWLogPiper;         // main.c

static BOOL cfnNotify(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnNWPNotify(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnQueryStorage(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnQuerySize(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnQueryFS(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnChkAvailSpace(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnChkAvailSize(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
#ifdef DEBUG_CODE
static BOOL cfnDebug(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
#endif

typedef struct _CMD {
  PSZ        pszName;
  BOOL (*fnCmd)(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx);
} CMD, *PCMD;


/* aCmdList[]

   A list of commands and related functions that implement this.
   Commands are processed by function ctlRequest().

   Commands are specified as strings:
     COMMAND argument1 argument2 ... CRLF

   Answers contain a string consisting of code (+OK or -ERR), SPACE, details
   and CRLF.
   Examples:
     +OK no error
     -ERR not found

   Some commands add a body to a successful response. The body ends with a
   string containing only a dot (POP3 protocol style).
*/

static CMD   aCmdList[] =
{
  { "NOTIFY",     cfnNotify },             // delay pathname.
  /* Informs about changes in the user home directory (INBOX), appearance or
     deletion of a .MSG file.
     delay    - delay in seconds to process the notificaton (0..9),
     pathname - user home directory or new/deleted .MSG file full name. */

  { "NWPNOTIFY",  cfnNWPNotify },          // Same as for NOTIFY.
  /* Same as NOTIFY but it will be rejected if the Weasel log pipe currently is
     connected.  */

  { "QUERYSTORAGE", cfnQueryStorage },
  /* Returns responce with body: information about all
     storage sizes. */

  { "QUERYSIZE", cfnQuerySize },           // user_home_dir
  /* Responce: +OK [MainRootSize DomainSize InboxSize FoldersSize] */

  { "QUERYFS", cfnQueryFS },
  /* Returns responce with body: information about open user home objects and
     sessions. */

  { "CHKAVAILSPACE", cfnChkAvailSpace },   // object size [notify_to]
  /* Disk quota check.
     object    - local user email OR full pathname to user home directory OR
                 path relative MailRoot,
     size      - number of bytes/Kb/Mb to add in user home directory,
     notify_to - e-mail, who should be notified by message.
     Responce is one of apszMSResponces[] messages. It will not returns
     "-ERR excess\r\n" if user non-blocked when the limit is exceeded.
   */

  { "CHKAVAILSIZE", cfnChkAvailSize },     // object new_msg [notify_to]
  /* Disk quota check.
     object    - local user email OR full pathname to user home directory OR
                 path relative MailRoot,
     new_msg   - received message file,
     notify_to - e-mail, who should be notified by message (sender of new_msg).
     Responce is one of apszMSResponces[] messages. It will not returns
     "-ERR excess\r\n" if user non-blocked when the limit is exceeded.
   */

#ifdef DEBUG_CODE 
  { "DEBUG", cfnDebug },
#endif

  { NULL, NULL }                           // End of list.
};

// Messages for msQuerySize() and msCheckAvailableSize() result codes.
// Index of apszMSResponces[] is the function result code.

static PSZ   apszMSResponces[] =
{
  "+OK no error\r\n",           // MSR_OK                   0
  "-ERR internal error\r\n",    // MSR_INTERNAL_ERROR       1
  "-ERR not found\r\n",         // MSR_NOT_FOUND            2
  "-ERR excess\r\n"             // MSR_EXCESS               3
};


/* Creates a copy of file pszSrcFile with a unique name. Name of the new file
   is stored in the buffer cbDstFile/pcDstFile.  */
static BOOL _makeTempFileCopy(PSZ pszSrcFile, ULONG cbDstFile, PCHAR pcDstFile)
{
#define _COPY_FILE_BUF_SIZE      (80 * 1024)
  HFILE    hSrcFile, hDstFile;
  ULONG    ulRC, ulActual;
  PCHAR    pcBuf;
  PCHAR    pcSlash = strrchr( pszSrcFile, '\\' );

  if ( pcSlash == NULL )
    pcSlash = pszSrcFile;

  ulRC = DosOpenL( pszSrcFile, &hSrcFile, &ulActual, 0, 0,
                   OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                   OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                   OPEN_SHARE_DENYWRITE | OPEN_ACCESS_READONLY, NULL );
  if ( ulRC != NO_ERROR )
  {
    debug( "Can't open source file: %s , rc = %u", pszSrcFile, ulRC );
    return FALSE;
  }

  ulRC = DosAllocMem( (PVOID *)&pcBuf, _COPY_FILE_BUF_SIZE,
                      PAG_COMMIT | PAG_READ | PAG_WRITE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosAllocMem(), rc = %u", ulRC );
    DosClose( hSrcFile );
    return FALSE;
  }

  ulRC = utilOpenTempFile( pcSlash - (PCHAR)pszSrcFile, pszSrcFile, 0,
                           cbDstFile, pcDstFile, &hDstFile );
  if ( ulRC != NO_ERROR )
  {
    debug( "utilOpenTempFile(), rc = %u", ulRC );
    DosFreeMem( pcBuf );
    DosClose( hSrcFile );
    return FALSE;
  }

  do
  {
    ulRC = DosRead( hSrcFile, pcBuf, _COPY_FILE_BUF_SIZE, &ulActual );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosRead(), rc = %u", ulRC );
      break;
    }

    ulRC = DosWrite( hDstFile, pcBuf, ulActual, &ulActual );
    if ( ulRC != NO_ERROR )
      debug( "DosWrite(), rc = %u", ulRC );
  }
  while( ( ulRC == NO_ERROR ) && ( ulActual == _COPY_FILE_BUF_SIZE ) );

  DosFreeMem( pcBuf );
  DosClose( hSrcFile );
  DosClose( hDstFile );

  if ( ulRC != NO_ERROR )
  {
    DosDelete( pcDstFile );
    return FALSE;
  }

  return TRUE;
}

/* Add recipient pszRcpt and object (e-mail or path to user home directory) to
   session object list. This data will be used to send notification e-mail
   about exceeded disk quota.  */
static VOID _addExcessQuotaEMail(PCTLSESS pCtlSess, PSZ pszRcpt,
                                 PSZ pszObject, PSZ pszAttachFile)
{
  PEXQUOTARCPT  pRcpt = NULL;
  ULONG         ulIdx;
  PEXQUOTARCPT  pExQuotaRcpt;

  for( ulIdx = 0; ulIdx < pCtlSess->cExQuotaRcpt; ulIdx++ )
  {
    pExQuotaRcpt = pCtlSess->ppExQuotaRcpt[ulIdx];
    if ( ( stricmp( pExQuotaRcpt->acRcpt, pszRcpt ) == 0 ) &&
         ( STR_ICMP( pExQuotaRcpt->pszAttachFile, pszAttachFile ) == 0 ) )
    {
      pRcpt = pCtlSess->ppExQuotaRcpt[ulIdx];
      break;
    }
  }

  if ( pRcpt == NULL )
  {
    // Make temporary copy of the original file.

    CHAR     acTempFile[CCHMAXPATH];

    if ( ( pszAttachFile != NULL ) &&
         !_makeTempFileCopy( pszAttachFile, sizeof(acTempFile), acTempFile ) )
      pszAttachFile = NULL;

    if ( (pCtlSess->cExQuotaRcpt & 0x7) == 0 )
    {
      PEXQUOTARCPT  *ppNew = realloc( pCtlSess->ppExQuotaRcpt,
                                       (pCtlSess->cExQuotaRcpt + 8) *
                                          sizeof(PEXQUOTARCPT) );
      if ( ppNew == NULL )
      {
        if ( pszAttachFile != NULL )
          DosDelete( acTempFile );
        return;
      }

      pCtlSess->ppExQuotaRcpt = ppNew;
    }

    pRcpt = malloc( sizeof(EXQUOTARCPT) + strlen( pszRcpt ) );
    if ( pRcpt == NULL )
    {
      if ( pszAttachFile != NULL )
        DosDelete( acTempFile );
      return;
    }

    strcpy( pRcpt->acRcpt, pszRcpt );

    if ( pszAttachFile == NULL )
    {
      pRcpt->pszAttachFile  = NULL;
      pRcpt->pszTempFile    = NULL;
    }
    else
    {
      pRcpt->pszAttachFile  = strdup( pszAttachFile );
      pRcpt->pszTempFile    = strdup( acTempFile );
    }

    pRcpt->cObjects = 0;
    pRcpt->ppszObjects = NULL;
    pCtlSess->ppExQuotaRcpt[pCtlSess->cExQuotaRcpt] = pRcpt;
    pCtlSess->cExQuotaRcpt++;
  }

  if ( (pRcpt->cObjects & 0x7) == 0 )
  {
    PSZ *ppszNew = realloc( pRcpt->ppszObjects,
                             (pRcpt->cObjects + 8) * sizeof(PSZ *)  );

    if ( ppszNew == NULL )
      return;

    pRcpt->ppszObjects = ppszNew;
  }

  pRcpt->ppszObjects[pRcpt->cObjects] = strdup( pszObject );
  pRcpt->cObjects++;
}


/* *************************************************************** */
/*                       Command functions                         */
/* *************************************************************** */

/*
   BOOL cfnXXXXX(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)

   pszArgLine - pointer to an argument string.
   pCtx - context object to store the answer.
*/


static BOOL cfnNotify(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  PSZ        pszDelay, pszPathname;
  ULONG      ulRC;

  if ( !utilStrCutWord( &pszArgLine, &pszDelay ) ||
       ( pszDelay[1] != '\0' ) || !isdigit( *pszDelay ) ||
       !utilStrCutComp( &pszArgLine, &pszPathname ) )
    return ctxWrite( pCtx, -1, "-ERR syntax error\r\n" );

  ulRC = fsNotifyChange( (*pszDelay - '0') * 1000, pszPathname );

  // Text for the result code.
  pszDelay = ulRC >= ARRAYSIZE(apszFSNotifyResults)
               ? (PSZ)"-ERR unknown error" : apszFSNotifyResults[ulRC];
  logf( 4, "Notify \"%s\": %s", pszPathname, &pszDelay[1] );

  return ctxWriteStrLn( pCtx, pszDelay );
}

static BOOL cfnNWPNotify(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  if ( prIsConnected( pWLogPiper ) )
    return ctxWrite( pCtx, -1, "+OK rejected\r\n" );

  return cfnNotify( pCtlSess, pszArgLine, pCtx );
}

static BOOL cfnQueryStorage(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  CHAR       acBuf[CCHMAXPATH];
  LONG       cbBuf = wcfgQueryMailRootDir( sizeof(acBuf), acBuf, NULL );

  if ( cbBuf > 0 )
    acBuf[cbBuf - 1] = '\0';               // Remove trailing slash.

  return ctxWriteFmtLn( pCtx, "+OK storage: %s", acBuf ) &&
         msQueryInfoCtx( pCtx );
}

static BOOL cfnQuerySize(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  PSZ        pszObject;
  MSSIZE     stSizeInfo;
  CHAR       acBuf1[64];
  CHAR       acBuf2[64];
  CHAR       acBuf3[64];
  ULONG      ulRC;

  if ( !utilStrCutComp( &pszArgLine, &pszObject ) )
    return ctxWrite( pCtx, -1, "-ERR syntax error\r\n" );

  ulRC = msQuerySize( pszObject, &stSizeInfo );
  if ( ulRC != MSR_OK )
    return ctxWrite( pCtx, -1, apszMSResponces[ulRC] );

  return ctxWriteFmtLn( pCtx, "+OK [%lld/%s %lld/%s %lld,%lld/%s]",
     stSizeInfo.llMailRoot, LIMIT_TO_STR( stSizeInfo.llMailRootLimit, acBuf1 ),
     stSizeInfo.llDomain, LIMIT_TO_STR( stSizeInfo.llDomainLimit, acBuf2 ),
     stSizeInfo.llInbox, stSizeInfo.llImap,
     LIMIT_TO_STR( stSizeInfo.llUserLimit, acBuf3 ) );
}

static BOOL cfnChkAvailSpace(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  // Arguments: object size [notify_to]
  PSZ        pszObject, pszSize, pszRcpt;
  ULLONG     ullSize;
  ULONG      ulRC;
  PSZ        pszResponce = "-ERR syntax error\r\n";

  if ( utilStrCutComp( &pszArgLine, &pszObject ) &&
       utilStrCutWord( &pszArgLine, &pszSize ) )
  {
    if ( utilStrToBytes( pszSize, &ullSize, UTIL_BYTES ) )
    {
      ulRC = msCheckAvailableSize( pszObject, ullSize );

      if ( ( ulRC == MSR_EXCESS ) && utilStrCutWord( &pszArgLine, &pszRcpt ) )
        _addExcessQuotaEMail( pCtlSess, pszRcpt, pszObject, NULL );

      pszResponce = apszMSResponces[ulRC];
    }
  }
  
  return ctxWrite( pCtx, -1, pszResponce );
}

static BOOL cfnChkAvailSize(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  // Arguments: object new_msg [notify_to]
  PSZ        pszObject, pszNewMsgFile, pszRcpt;
  ULLONG     ullSize;
  ULONG      ulRC;
  PSZ        pszResponce;

  if ( !utilStrCutComp( &pszArgLine, &pszObject ) ||
       !utilStrCutWord( &pszArgLine, &pszNewMsgFile ) )
    pszResponce = "-ERR syntax error\r\n";
  else
  {
    if ( !utilQueryFileInfo( pszNewMsgFile, NULL, &ullSize ) )
      pszResponce = "-ERR file does not exist\r\n";
    else
    {
      ulRC = msCheckAvailableSize( pszObject, ullSize );

      if ( ( ulRC == MSR_EXCESS ) && utilStrCutWord( &pszArgLine, &pszRcpt ) )
        _addExcessQuotaEMail( pCtlSess, pszRcpt, pszObject, pszNewMsgFile );

      pszResponce = apszMSResponces[ulRC];
    }
  }
  
  return ctxWrite( pCtx, -1, pszResponce );
}

static BOOL cfnQueryFS(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  return ctxWrite( pCtx, -1, "+OK IMAP file system\r\n" ) &&
         fsQueryInfoCtx( pCtx );
}

#ifdef DEBUG_CODE
static BOOL cfnDebug(PCTLSESS pCtlSess, PSZ pszArgLine, PCTX pCtx)
{
  debugStat();
  return FALSE;
}
#endif


/* *************************************************************** */
/*                        Public routines                          */
/* *************************************************************** */

/* Initializes a new session.
   pCtlSess is the structure-handler of the session in the caller memory space
   that will be prepared.
*/
VOID ctlInit(PCTLSESS pCtlSess)
{
  memset( pCtlSess, 0, sizeof(CTLSESS) );
}

/* Session finalization.
   Will send all notifications generated by commands CHKAVAILSPACE and
   CHKAVAILSIZE. Then all session data will be destroyed and the memory freed.
*/
VOID ctlDone(PCTLSESS pCtlSess)
{
  ULONG         ulIdx, ulObjIdx;
  PEXQUOTARCPT  pRcpt;

  if ( pCtlSess->ppExQuotaRcpt != NULL )
  {
    for( ulIdx = 0; ulIdx < pCtlSess->cExQuotaRcpt; ulIdx++ )
    {
      pRcpt = pCtlSess->ppExQuotaRcpt[ulIdx];
      if ( pRcpt == NULL )
        continue;

      msSendExceededQuotaEMail( pRcpt->acRcpt, pRcpt->cObjects,
                                pRcpt->ppszObjects, pRcpt->pszTempFile );

      for( ulObjIdx = 0; ulObjIdx < pRcpt->cObjects; ulObjIdx++ )
      {
        if ( pRcpt->ppszObjects[ulObjIdx] != NULL )
          free( pRcpt->ppszObjects[ulObjIdx] );
      }

      free( pRcpt->ppszObjects );

      if ( pRcpt->pszAttachFile != NULL )
        free( pRcpt->pszAttachFile );

      if ( pRcpt->pszTempFile != NULL )
      {
        DosDelete( pRcpt->pszTempFile );
        free( pRcpt->pszTempFile );
      }

      free( pRcpt );
    }

    free( pCtlSess->ppExQuotaRcpt );
    pCtlSess->ppExQuotaRcpt = NULL;
  }
  pCtlSess->cExQuotaRcpt = 0;
}

/* Executes the command pointed to by cbInput/pcInput. The result (response)
   is written to the context object pCtx.
   Returns FALSE if a write error has occurred.
*/
BOOL ctlRequest(PCTLSESS pCtlSess, PCTX pCtx, LONG cbInput, PCHAR pcInput)
{
  PSZ        pszCmd;
  PCMD       pCmd;

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
    return ctxWriteFmtLn( pCtx, "-ERR Unknown command %s", pszCmd );

  // Call command routine.

  return pCmd->fnCmd( pCtlSess, (PSZ)pcInput, pCtx );
}
