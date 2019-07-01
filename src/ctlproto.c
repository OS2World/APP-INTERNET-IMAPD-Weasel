/*
    Network (local socket) interface for the control protocol.
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
#include "piper.h"
#include "storage.h"
#include "imapfs.h"
#include "control.h"
#include "debug.h"               // Should be last.


typedef struct _PROTODATA {
  CTLSESS    stCtlSess;
} PROTODATA, *PPROTODATA;


static BOOL cprNew(PCLNTDATA pClntData)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  ctlInit( &pProtoData->stCtlSess );

  return TRUE;
}

static VOID cprDestroy(PCLNTDATA pClntData)
{
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  ctlDone( &pProtoData->stCtlSess );
}

static BOOL cprRequest(PCLNTDATA pClntData, LONG cbInput, PCHAR pcInput)
{
  PCTX       pCtx = netsrvClntGetContext( pClntData );
  PPROTODATA pProtoData = (PPROTODATA)netsrvClntGetProtoData( pClntData );

  return ctlRequest( &pProtoData->stCtlSess, pCtx, cbInput, pcInput );
}


// Protocol handler.

NSPROTO stProtoCtrl = {
  sizeof(PROTODATA),   // cbProtoData
  "CTRL",              // acLogId
  1000 * 30,           // ulTimeout
  0,                   // ulMaxClients
  cprNew,              // fnNew
  cprDestroy,          // fnDestroy
  cprRequest,          // fnRequest
  NULL,                // fnReadyToSend
  NULL                 // fnIdle
};
