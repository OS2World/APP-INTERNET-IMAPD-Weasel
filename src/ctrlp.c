/*
  Control protocol implementation.
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
#include "netserv.h"
#include "wcfg.h"
#include "wlog.h"
#include "storage.h"
#include "imapfs.h"
#include "hmem.h"
#include "debug.h"               // Should be last.


typedef struct _EXQUOTARCPT {
  ULONG                cObjects;
  PSZ                  *ppszObjects;     // List of objects where quota excess.
  PSZ                  pszAttachFile;
  PSZ                  pszTempFile;
  CHAR                 acRcpt[1];        // Address for sending notification.
} EXQUOTARCPT, *PEXQUOTARCPT;

typedef struct _PROTODATA {
  CHAR                 chData;
  ULONG                cExQuotaRcpt;
  PEXQUOTARCPT         *ppExQuotaRcpt;
} PROTODATA, *PPROTODATA;


static BOOL cfnNotify(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnNWPNotify(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnQueryStorage(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnQuerySize(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnQueryFS(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnChkAvailSpace(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
static BOOL cfnChkAvailSize(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
#ifdef DEBUG_CODE
static BOOL cfnDebug(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
#endif

typedef struct _CMD {
  PSZ        pszName;
  BOOL (*fnCmd)(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx);
} CMD, *PCMD;


static CMD   aCmdList[] =
{
  { "NOTIFY",     cfnNotify },             // delay[sec.] pathname.
  /* Informs about changes in the user home directory (INBOX), appearance or
     deletion of a .MSG file.
     delay    - delay in seconds to process the notificaton (0..9),
     pathname - user home directory or new/deleted .MSG file full name. */

  { "NWPNOTIFY",  cfnNWPNotify },          // Same as for NOTIFY.
  /* Same as NOTIFY but it will be rejected if the Weasel log pipe currently is
     connected.  */

  { "QUERYSTORAGE", cfnQueryStorage },
  /* Returns responce with body (POP3 protocol style) - information about all
     storage sizes. */

  { "QUERYSIZE", cfnQuerySize },           // user_home_dir
  /* Responce: +OK [MainRootSize DomainSize InboxSize FoldersSize] */

  { "QUERYFS", cfnQueryFS },
  /* Information about open user home objects and sessions. */

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
  if ( ulRC != FSR_OK )
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

// Add recipient pszRcpt and object (e-mail or path to user home directory) to
// session object list. This data will be used to send notification e-mail
// about exceeded disk quota.
static VOID _addExcessQuotaEMail(PCLNTDATA pClntData, PSZ pszRcpt,
                                 PSZ pszObject, PSZ pszAttachFile)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  PEXQUOTARCPT  pRcpt = NULL;
  ULONG         ulIdx;
  PEXQUOTARCPT  pExQuotaRcpt;

  for( ulIdx = 0; ulIdx < pProtoData->cExQuotaRcpt; ulIdx++ )
  {
    pExQuotaRcpt = pProtoData->ppExQuotaRcpt[ulIdx];
    if ( ( stricmp( pExQuotaRcpt->acRcpt, pszRcpt ) == 0 ) &&
         ( STR_ICMP( pExQuotaRcpt->pszAttachFile, pszAttachFile ) == 0 ) )
    {
      pRcpt = pProtoData->ppExQuotaRcpt[ulIdx];
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

    if ( (pProtoData->cExQuotaRcpt & 0x7) == 0 )
    {
      PEXQUOTARCPT  *ppNew = hrealloc( pProtoData->ppExQuotaRcpt,
                                       (pProtoData->cExQuotaRcpt + 8) *
                                          sizeof(PEXQUOTARCPT) );
      if ( ppNew == NULL )
      {
        if ( pszAttachFile != NULL )
          DosDelete( acTempFile );
        return;
      }

      pProtoData->ppExQuotaRcpt = ppNew;
    }

    pRcpt = hmalloc( sizeof(EXQUOTARCPT) + strlen( pszRcpt ) );
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
      pRcpt->pszAttachFile  = hstrdup( pszAttachFile );
      pRcpt->pszTempFile    = strdup( acTempFile );      // Low memory pointer.
    }

    pRcpt->cObjects = 0;
    pRcpt->ppszObjects = NULL;
    pProtoData->ppExQuotaRcpt[pProtoData->cExQuotaRcpt] = pRcpt;
    pProtoData->cExQuotaRcpt++;
  }

  if ( (pRcpt->cObjects & 0x7) == 0 )
  {
    PSZ *ppszNew = hrealloc( pRcpt->ppszObjects,
                             (pRcpt->cObjects + 8) * sizeof(PSZ *)  );

    if ( ppszNew == NULL )
      return;

    pRcpt->ppszObjects = ppszNew;
  }

  pRcpt->ppszObjects[pRcpt->cObjects] = hstrdup( pszObject );
  pRcpt->cObjects++;
}


static BOOL cfnNotify(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
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

static BOOL cfnNWPNotify(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  if ( wlogIsConnected() )
    return ctxWrite( pCtx, -1, "+OK rejected\r\n" );

  return cfnNotify( pClntData, pszArgLine, pCtx );
}

static BOOL cfnQueryStorage(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  CHAR       acBuf[CCHMAXPATH];
  LONG       cbBuf = wcfgQueryMailRootDir( sizeof(acBuf), acBuf, NULL );

  if ( cbBuf > 0 )
    acBuf[cbBuf - 1] = '\0';               // Remove trailing slash.

  return ctxWriteFmtLn( pCtx, "+OK storage: %s", acBuf ) &&
         msQueryInfoCtx( pCtx );
}

static BOOL cfnQuerySize(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
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

static BOOL cfnChkAvailSpace(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
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
        _addExcessQuotaEMail( pClntData, pszRcpt, pszObject, NULL );

      pszResponce = apszMSResponces[ulRC];
    }
  }
  
  return ctxWrite( pCtx, -1, pszResponce );
}

static BOOL cfnChkAvailSize(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
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
        _addExcessQuotaEMail( pClntData, pszRcpt, pszObject, pszNewMsgFile );

      pszResponce = apszMSResponces[ulRC];
    }
  }
  
  return ctxWrite( pCtx, -1, pszResponce );
}

static BOOL cfnQueryFS(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  return ctxWrite( pCtx, -1, "+OK IMAP file system\r\n" ) &&
         fsQueryInfoCtx( pCtx );
}

#ifdef DEBUG_CODE
static BOOL cfnDebug(PCLNTDATA pClntData, PSZ pszArgLine, PCTX pCtx)
{
  debugStat();
  return FALSE;
}
#endif

static BOOL ctrlNew(PCLNTDATA pClntData)
{
  return TRUE;
}

static VOID ctrlDestroy(PCLNTDATA pClntData)
{
  PPROTODATA    pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );
  ULONG         ulIdx, ulObjIdx;
  PEXQUOTARCPT  pRcpt;

  if ( pProtoData->ppExQuotaRcpt != NULL )
  {
    for( ulIdx = 0; ulIdx < pProtoData->cExQuotaRcpt; ulIdx++ )
    {
      pRcpt = pProtoData->ppExQuotaRcpt[ulIdx];
      if ( pRcpt == NULL )
        continue;

      msSendExceededQuotaEMail( pRcpt->acRcpt, pRcpt->cObjects,
                                pRcpt->ppszObjects, pRcpt->pszTempFile );

      for( ulObjIdx = 0; ulObjIdx < pRcpt->cObjects; ulObjIdx++ )
      {
        if ( pRcpt->ppszObjects[ulObjIdx] != NULL )
          hfree( pRcpt->ppszObjects[ulObjIdx] );
      }

      hfree( pRcpt->ppszObjects );

      if ( pRcpt->pszAttachFile != NULL )
        hfree( pRcpt->pszAttachFile );

      if ( pRcpt->pszTempFile != NULL )
      {
        DosDelete( pRcpt->pszTempFile );
        free( pRcpt->pszTempFile );                  // Low memory pointer.
      }

      hfree( pRcpt );
    }

    hfree( pProtoData->ppExQuotaRcpt );
  }
}

static BOOL ctrlRequest(PCLNTDATA pClntData, LONG cbInput, PCHAR pcInput)
{
  PCTX       pCtx = netsrvClntGetContext( pClntData );
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

  return pCmd->fnCmd( pClntData, (PSZ)pcInput, pCtx );
}


// Protocol handler.

NSPROTO stProtoCtrl = {
  sizeof(PROTODATA),   // cbProtoData
  "CTRL",              // acLogId
  1000 * 30,           // ulTimeout
  0,                   // ulMaxClients
  ctrlNew,             // fnNew
  ctrlDestroy,         // fnDestroy
  ctrlRequest,         // fnRequest
  NULL,                // fnReadyToSend
  NULL                 // fnIdle
};
