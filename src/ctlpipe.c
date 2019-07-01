/*
    System named pipe interface for the control protocol.
*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#define INCL_DOSSEMAPHORES   /* Semaphore values */
#define INCL_DOSERRORS       /* DOS error values */
#define INCL_DOSNMPIPES
#define INCL_DOSPROCESS
#include <os2.h>
#include "log.h"
#include "piper.h"     // prExpandPipeName()
#include "context.h"
#include "control.h"
#include "ctlpipe.h"
#include "debug.h"     // Must be the last.

#define THREAD_STACK_SIZE        65535
#define WRITE_BUF_SIZE           1024
#define READ_BUF_SIZE            1024

typedef struct _PIPEDATA {
  HPIPE      hPipe;              // Named pipe handler.
  PCTX       pCtx;               // Context object for the answer text.
  CTLSESS    stCtlSess;          // Control protocol session object.
} PIPEDATA, *PPIPEDATA;

static PPIPEDATA       paPipes = NULL;
static ULONG           cPipes = 0;
static HEV             hevPipes = NULLHANDLE;
static PSZ             pszPipe = NULL;
volatile static TID    tid = ((TID)(-1));

static VOID _destroyPipe(PPIPEDATA pPipeData)
{
  if ( pPipeData->hPipe != NULLHANDLE )
  {
    DosClose( pPipeData->hPipe );
    pPipeData->hPipe = NULLHANDLE;
  }

  if ( pPipeData->pCtx != NULL )
  {
    ctxFree( pPipeData->pCtx );
    pPipeData->pCtx = NULL;
  }

  ctlDone( &pPipeData->stCtlSess );
}

static BOOL _createPipe(PPIPEDATA pPipeData, ULONG cPipes, PSZ pszName,
                        ULONG ulKey)
{
  ULONG                ulRC;

  ulRC = DosCreateNPipe( pszName, &pPipeData->hPipe,
                         NP_NOINHERIT | NP_ACCESS_DUPLEX,
                         NP_NOWAIT | NP_TYPE_BYTE | NP_READMODE_BYTE |
                         cPipes, WRITE_BUF_SIZE, READ_BUF_SIZE, 0 );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateNPipe(), rc = %lu", ulRC );
    logf( 1, "Cannot create named pipe %s, rc = %lu", pszName, ulRC );
    if ( ulRC == ERROR_PIPE_BUSY )
      printf( "Named pipe %s is busy.\n", pszName );
    return FALSE;
  }

  // Set pipe semaphore. On this semaphore we will receive pipe events.
  ulRC = DosSetNPipeSem( pPipeData->hPipe, (HSEM)hevPipes, ulKey );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosSetNPipeSem(), rc = %lu", ulRC );
    DosClose( pPipeData->hPipe );
    pPipeData->hPipe = NULLHANDLE;
    return FALSE;
  }

  // Set listening mode for pipe.
  ulRC = DosConnectNPipe( pPipeData->hPipe );
  if ( ulRC != NO_ERROR && ulRC != ERROR_PIPE_NOT_CONNECTED )
  {
    debug( "DosConnectNPipe(), rc = %s", ulRC );
    logf( 1, "Cannot connect named pipe %s, rc = %lu", pszName, ulRC );
    DosClose( pPipeData->hPipe );
    return FALSE;
  }

  // Initialize a new session of the control protocol.
  ctlInit( &pPipeData->stCtlSess );

  pPipeData->pCtx = NULL;
  debug( "Pipe %s created (key: %lu)", pszName, ulKey );

  return TRUE;
}

/* Sends data from the context object (if any). Destroys the context object
   when all data has been sent.
*/
static VOID _sendCtx(PPIPEDATA pPipeData)
{
  ULONG      ulRC;

  if ( pPipeData->pCtx == NULL )
    return;

  ulRC = ctxFileWrite( pPipeData->pCtx, pPipeData->hPipe );

  if ( ulRC != NO_ERROR )
    debug( "ctxFileWrite(), rc = %lu", ulRC );
  else if ( ctxQueryAvailForRead( pPipeData->pCtx ) != 0 )
    return;

  ctxFree( pPipeData->pCtx );
  pPipeData->pCtx = NULL;
}

/* Cuts input data into lines and executes each line as a command.
   Sends an answer, if the answer is not sent completely - creates a context
   object pPipeData->pCtx.
*/
static VOID _parseNewData(PPIPEDATA pPipeData, ULONG cbBuf, PCHAR pcBuf)
{
  PCHAR      pcLine = pcBuf;
  PCHAR      pcEnd = &pcBuf[cbBuf];
  PCHAR      pcEOL, pcNext;

  if ( pPipeData->pCtx == NULL )
  {
    pPipeData->pCtx = ctxNew();
    if ( pPipeData->pCtx == NULL )
      return;
  }

  while( pcLine < pcEnd )
  {
    pcEOL = memchr( pcLine, '\n', pcEnd - pcLine );
    if ( pcEOL == NULL )
      pcEOL = pcEnd;
    pcNext = &pcEOL[1];
    while( ( pcEOL > pcLine ) && isspace( *(pcEOL-1) ) )
      pcEOL--;


    debug( "Input line: %s", debugBufPSZ( pcLine, pcEOL - pcLine ) );
    if ( !ctlRequest( &pPipeData->stCtlSess, pPipeData->pCtx, pcEOL - pcLine,
                      pcLine ) )
    {
      debugCP( "ctlRequest() failed" );
      break;
    }

    pcLine = pcNext;
  }

  _sendCtx( pPipeData );
}

static void threadPipes(void *pData)
{
  ULONG                ulRC;
  ULONG                cbPipeState = (cPipes + 2) * sizeof(PIPESEMSTATE);
  PPIPESEMSTATE        paPipeState, pPipeState;
  PCHAR                pcBuf;
  ULONG                cbBuf;

  pcBuf = malloc( READ_BUF_SIZE + 1 ); // +1 - for terminator (\0)
  if ( pcBuf == NULL )
  {
    debugCP( "Not enough memory" );
    _endthread();
    return;
  }

  paPipeState = alloca( cbPipeState );
  if ( paPipeState == NULL )
  {
    debugCP( "Not enough memory" );
    free( pcBuf );
    _endthread();
    return;
  }

  while( TRUE )
  {
    // Wait event from pipes or ifpipeDone().
    ulRC = DosWaitEventSem( hevPipes, SEM_INDEFINITE_WAIT );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosWaitEventSem(), rc = %lu", ulRC );
      break;
    }

    // Shutdown signal from ifpipeDone().
    if ( tid == ((TID)(-1)) )
      break;

    // Query information about pipes that are attached to the semaphore. 
    ulRC = DosQueryNPipeSemState( (HSEM)hevPipes, paPipeState, cbPipeState );
    if ( ulRC != NO_ERROR )
    {
      logf( 1, "Pipe interface error. DosQueryNPipeSemState(), rc = %lu", ulRC );
      continue;
    }

    // Check pipe states.
    for( pPipeState = paPipeState; pPipeState->fStatus != NPSS_EOI;
         pPipeState++ )
    {
      if ( pPipeState->usKey >= cPipes )
      {
        debug( "Unknow pPipeState->usKey: %lu, status: %lu, total pipes: %lu",
               pPipeState->usKey, pPipeState->fStatus, cPipes );
        continue;
      }

      switch( pPipeState->fStatus )
      {
        case NPSS_WSPACE:
          // The pipe has space in the output buffer.
//          debug( "NPSS_WSPACE %lu", pPipeState->usKey );
          _sendCtx( &paPipes[pPipeState->usKey] );
          break;

        case NPSS_RDATA:
          // The pipe received data.
//          debug( "NPSS_RDATA %lu", pPipeState->usKey );
          ulRC = DosRead( paPipes[pPipeState->usKey].hPipe, pcBuf,
                          pPipeState->usAvail, &cbBuf );
          if ( ulRC == NO_ERROR )
          {
            _parseNewData( &paPipes[pPipeState->usKey], cbBuf, pcBuf );
            break;
          }

          debug( "DosRead(), rc = %lu", ulRC );

        case NPSS_CLOSE:
//          debug( "NPSS_CLOSE %lu", pPipeState->usKey );
          {
            ulRC = DosDisConnectNPipe( paPipes[pPipeState->usKey].hPipe );
            if ( ulRC != NO_ERROR )
            {
              debug( "DosDisConnectNPipe(), rc = %lu (key: %lu)",
                     ulRC, pPipeState->usKey );
              logf( 1, "Cannot disconnect named pipe %s, rc = %lu",
                   pszPipe, ulRC );
            }
            else
            {
              ulRC = DosConnectNPipe( paPipes[pPipeState->usKey].hPipe );
              if ( (ulRC != NO_ERROR) && (ulRC != ERROR_PIPE_NOT_CONNECTED) )
              {
                debug( "DosConnectNPipe(), rc = %lu (key: %lu)",
                       ulRC, pPipeState->usKey );
                logf( 1, "Cannot connect named pipe %s, rc = %lu",
                     pszPipe, ulRC );
              }
            }

            if ( ulRC != NO_ERROR && ulRC != ERROR_PIPE_NOT_CONNECTED )
            {
              _destroyPipe( &paPipes[pPipeState->usKey] );
              _createPipe( &paPipes[pPipeState->usKey], cPipes, pszPipe,
                           pPipeState->usKey );
            }
          }
          break;
      }
    }  // for( pPipeState ...
  }

  free( pcBuf );
  _endthread();
}


/* Creates a pipes whose number is given by ulPipes and the name by
   pszPipeName.
*/
BOOL ctlpipeInit(PSZ pszPipeName, ULONG ulPipes)
{
  CHAR                 szBuf[CCHMAXPATH];
  ULONG                ulRC;
  ULONG                ulIdx;

  if ( paPipes != NULL )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  // Make a pipe name. Add the prefix \PIPE\ if it is missing.
  if ( prExpandPipeName( sizeof(szBuf), szBuf, pszPipeName ) == 0 )
  {
    debug( "Too long pipe name: %s", pszPipeName );
    return FALSE;
  }

  paPipes = malloc( ulPipes * sizeof(PIPEDATA) );
  if ( paPipes == NULL )
  {
    debugCP( "Not enough memory" );
    return FALSE;
  }

  ulRC = DosCreateEventSem( NULL, &hevPipes, DC_SEM_SHARED | DCE_AUTORESET,
                            FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateEventSem(), rc = %lu", ulRC );
    free( paPipes );
    return FALSE;
  }

  pszPipe = strdup( szBuf );
  if ( pszPipe == NULL )
    debugCP( "Not enough memory" );
  else
  {
    // Create pipes and attach event semaphore.
    debug( "Create %lu named pipes %s...", ulPipes, &szBuf );
    for( ulIdx = 0; ( ulIdx < ulPipes ) &&
         _createPipe( &paPipes[ulIdx], ulPipes, szBuf, ulIdx ); ulIdx++ );

    if ( ulIdx < ulPipes )
      debug( "_createPipe() failed" );
    else
    {
      cPipes = ulPipes;
      pszPipe = strdup( szBuf );

      tid = _beginthread( threadPipes, NULL, THREAD_STACK_SIZE, NULL );
      if ( tid != ((TID)(-1)) )
        return TRUE;

      debug( "_beginthread() failed" );
    }
  }

  ctlpipeDone();
  return FALSE;
}

/* Destroys the created pipes and frees the memory.
*/
VOID ctlpipeDone()
{
  ULONG                ulRC, ulIdx;
  volatile TID         tidWait = tid;

  if ( paPipes == NULL )
  {
    debug( "Was not initialized" );
    return;
  }

  if ( tid != ((TID)(-1)) )
  {
    // Signal to shutdown for the thread.
    tid = ((TID)(-1));
    DosPostEventSem( hevPipes );
    // Wait until thread ended.
    ulRC = DosWaitThread( (PTID)&tidWait, DCWW_WAIT );
    if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_INVALID_THREADID ) )
      debug( "DosWaitThread(), rc = %lu", ulRC );
  }

  for( ulIdx = 0; ulIdx < cPipes; ulIdx++ )
    _destroyPipe( &paPipes[ulIdx] );

  free( paPipes );
  paPipes = NULL;

  DosCloseEventSem( hevPipes );
  hevPipes = NULLHANDLE;

  if ( pszPipe != NULL )
  {
    free( pszPipe );
    pszPipe = NULL;
  }
}
