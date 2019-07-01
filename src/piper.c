/*
   Pipe redirector.

   This module will try to connect to one of listed named pipes and, optionaly,
   redirect to it's one (server) named pipes.

   Server named pipes will be created when the input pipe connects and
   destroyed when the input pipe is disconnected.
*/

#include <signal.h>
#include <stdio.h>
#include <process.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef __WATCOMC__
#include <malloc.h>
#endif
#define INCL_DOSNMPIPES
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#define INCL_DOSMISC
#define INCL_DOSPROCESS
#include <os2.h>
#include "piper.h"
#include "debug.h"

#define _INPUT_PIPE_KEY          0xFFFF

/*#ifdef DEBUG_FILE
#include <stdio.h>
#define debugCP(s) printf( __FILE__"#%u %s() [control point] "s"\n", __LINE__, __func__ )
#define debug(s,...) printf(__FILE__"/%s(): "s"\n", __func__, ##__VA_ARGS__)
#else
#define debugCP(s)
#define debug(s,...)
#endif*/

struct _PIPER {
  HPIPE                hInputPipe;
  PSZ                  pcPipes;
  ULONG                ulLostPipeTime;
  ULONG                ulReconnectPeriod;
  PSZ                  pszServerPipes;
  HEV                  hevPipes;
  ULONG                cServerPipes;
  PPRFNUSER            fnUser;
  ULONG                ulWriteBufSize;
  ULONG                ulReadBufSize;

  PHPIPE               phServerPipes;
  PCHAR                pcReadBuf;
  ULONG                ulReadBufPos;
  PSZ                  pszCurPipe;
                       // Currently connected pipe name from the list pcPipes.

  HEV                  hevInputPipe;
  ULONG                ulInputPipeKey;
};

typedef struct _PIPER PIPER;


static VOID _destroyServerPipes(PPIPER pPiper)
{
  ULONG      ulIdx;

  if ( pPiper->phServerPipes == NULL )
    return;

  debug( "Close %lu server pipes", pPiper->cServerPipes );
  for( ulIdx = 0; ulIdx < pPiper->cServerPipes; ulIdx++ )
  {
    if ( pPiper->phServerPipes[ulIdx] != NULLHANDLE )
    {
      DosClose( pPiper->phServerPipes[ulIdx] );
      pPiper->phServerPipes[ulIdx] = NULLHANDLE;
    }
  }

  free( pPiper->phServerPipes );
  pPiper->phServerPipes = NULL;
}

static BOOL _createServerPipes(PPIPER pPiper)
{
  ULONG      ulRC = NO_ERROR;
  ULONG      ulIdx;

  if ( pPiper->cServerPipes == 0 )
    return TRUE;

  if ( pPiper->phServerPipes != NULL )
  {
    debugCP( "Already created" );
    return TRUE;
  }

  pPiper->phServerPipes = calloc( pPiper->cServerPipes, sizeof(HPIPE) );
  if ( pPiper->phServerPipes == NULL )
  {
    debugCP( "Not enough memory" );
    return FALSE;
  }

  for( ulIdx = 0; ulIdx < pPiper->cServerPipes; ulIdx++ )
  {
    ulRC = DosCreateNPipe( pPiper->pszServerPipes, &pPiper->phServerPipes[ulIdx],
                           NP_NOINHERIT | NP_ACCESS_OUTBOUND,
                           NP_NOWAIT | NP_TYPE_BYTE | pPiper->cServerPipes,
                           pPiper->ulWriteBufSize, 0, 0 );
    if ( ulRC != NO_ERROR )  
    {
      debug( "DosCreateNPipe(\"%s\",...), rc = %lu", pPiper->pszServerPipes, ulRC );
      break;
    }

    ulRC = DosSetNPipeSem( pPiper->phServerPipes[ulIdx],
                           (HSEM)pPiper->hevPipes, ulIdx );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosSetNPipeSem(), rc = %lu", ulRC );
      break;
    }

    ulRC = DosConnectNPipe( pPiper->phServerPipes[ulIdx] );
    if ( ulRC == ERROR_PIPE_NOT_CONNECTED )
      ulRC = NO_ERROR;
    else if ( ulRC != NO_ERROR )
    {
      debug( "DosConnectNPipe(), rc = %lu", ulRC );
      break;
    }
  }

  if ( ulRC != NO_ERROR )
  {
    _destroyServerPipes( pPiper );

    if ( pPiper->fnUser != NULL )
      pPiper->fnUser( pPiper, PREVENT_PIPECREATEERROR, pPiper->pszServerPipes );

    return FALSE;
  }

  debug( "%lu server pipe(s) %s created",
         pPiper->cServerPipes, pPiper->pszServerPipes );
  return TRUE;
}


static BOOL _openInputPipe(PPIPER pPiper)
{
  PSZ        pszCurPipe = (PSZ)pPiper->pcPipes;
  HPIPE      hNewPipe;
  ULONG      ulRC, ulIdx;

  if ( pPiper->hInputPipe != NULLHANDLE )
    return TRUE;

  while( *pszCurPipe != '\0' )
  {
    // Try to open input pipe...
    ulRC = DosOpen( pszCurPipe, &hNewPipe, &ulIdx, 0, FILE_NORMAL,
                    OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                    OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                    OPEN_FLAGS_NOINHERIT | OPEN_SHARE_DENYNONE |
                    OPEN_ACCESS_READONLY, NULL );
    if ( ulRC == NO_ERROR )
    {
      debug( "Connected to %s", pszCurPipe );
      pPiper->pszCurPipe = pszCurPipe;
      pPiper->hInputPipe = hNewPipe;
      pPiper->ulReadBufPos = 0;

      if ( pPiper->fnUser != NULL )
        pPiper->fnUser( pPiper, PREVENT_CONNECTED, pszCurPipe );

      ulRC = DosSetNPHState( hNewPipe, NP_NOWAIT );
      if ( ulRC != NO_ERROR )
        debug( "DosSetNPHState(), rc = %lu", ulRC );

      ulRC = DosSetNPipeSem( hNewPipe, (HSEM)pPiper->hevInputPipe,
                             pPiper->ulInputPipeKey );
      if ( ulRC != NO_ERROR )
        debug( "DosSetNPipeSem(), rc = %lu", ulRC );

      _createServerPipes( pPiper );

      break;
    }
    debug( "Could not connect to %s", pszCurPipe );

    // Jump to the next name
    pszCurPipe = strchr( pszCurPipe, '\0' ) + 1;
  }

  return pPiper->hInputPipe != NULLHANDLE;
}

static VOID _closeInputPipe(PPIPER pPiper)
{
  if ( pPiper->hInputPipe != NULLHANDLE )
  {
    debugCP( "Close input pipe" );
    DosClose( pPiper->hInputPipe );
  }

  pPiper->hInputPipe = NULLHANDLE;
  pPiper->pszCurPipe = NULL;
  _destroyServerPipes( pPiper );
}

/* Reads data from the input pipe. Writes data to the output pipes and calls a
   user function for each line received. */
static BOOL _readInputPipe(PPIPER pPiper)
{
  ULONG      ulRC;
  ULONG      cbBuf;
  ULONG      ulIdx;
  PCHAR      pcReadBuf;
  PCHAR      pcEOL;
  ULONG      ulReadBufPos;

  while( TRUE )
  {
    // Read data from the input (client) pipe

    pcReadBuf = pPiper->pcReadBuf;
    ulRC = DosRead( pPiper->hInputPipe, &pcReadBuf[pPiper->ulReadBufPos],
                    pPiper->ulReadBufSize - pPiper->ulReadBufPos, &cbBuf );
    if ( ulRC == ERROR_NO_DATA )
      break;

    if ( ( ulRC != NO_ERROR ) || ( cbBuf == 0 ) )
    {
      if ( ulRC != NO_ERROR )
        debug( "DosRead(), rc = %lu", ulRC );

      debugCP( "Input pipe is disconnected" );
      return FALSE;
    }


    // Write data to the output (server) pipes

    if ( pPiper->phServerPipes != NULL )
    {
      for( ulIdx = 0; ulIdx < pPiper->cServerPipes; ulIdx++ )
        DosWrite( pPiper->phServerPipes[ulIdx], &pcReadBuf[pPiper->ulReadBufPos],
                  cbBuf, &ulReadBufPos );
    }


    // Split input data on lines and call user function

    if ( pPiper->fnUser != NULL )
    {
      ulReadBufPos = pPiper->ulReadBufPos + cbBuf;
      while( TRUE )
      {
        pcEOL = memchr( pcReadBuf, '\n', ulReadBufPos );
        if ( pcEOL != NULL )
        {
          if ( ( pcEOL > pcReadBuf ) && ( *(pcEOL - 1) == '\r' ) )
            *(pcEOL - 1) = '\0';
          else
            *pcEOL = '\0';

          pPiper->fnUser( pPiper, PREVENT_INPUTLINE, pcReadBuf );

          pcEOL++;
          ulReadBufPos -= ( pcEOL - pcReadBuf );
          pcReadBuf = pcEOL;
        }
        else
        {
          if ( pcReadBuf != pPiper->pcReadBuf )
            // Move the tail without a line break at the beginning of the buffer.
            memcpy( pPiper->pcReadBuf, pcReadBuf, ulReadBufPos );
          else if ( ulReadBufPos == pPiper->ulReadBufSize )
            // Received line is too long.
            ulReadBufPos = 0;

          break;
        }
      }

      pPiper->ulReadBufPos = ulReadBufPos;
    }  // if ( pPiper->fnUser != NULL )
    else
      pPiper->ulReadBufPos = 0;
  }

  return TRUE;
}

/* Check events on input and server pipes. */
static VOID _checkPipeEvents(PPIPER pPiper, BOOL fInputPipeOnly)
{
  PPIPESEMSTATE       paPipeState, pPipeState;
  ULONG               cbPipeState, ulRC;
  HSEM                hSem = fInputPipeOnly ? (HSEM)pPiper->hevInputPipe
                                            : (HSEM)pPiper->hevPipes;

  if ( hSem == NULL )
    return;

  cbPipeState = (pPiper->cServerPipes + 2) * sizeof(PIPESEMSTATE);
  paPipeState = alloca( cbPipeState );
  if ( paPipeState == NULL )
  {
    debugCP( "Not enough stack space" );
    return;
  }

  // Query information about pipes that are attached to the semaphore.

  ulRC = DosQueryNPipeSemState( hSem, paPipeState, cbPipeState );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosQueryNPipeSemState(), rc = %lu" , ulRC );
    return;
  }

  for( pPipeState = paPipeState; pPipeState->fStatus != NPSS_EOI;
       pPipeState++ )
  {
    switch( pPipeState->fStatus )
    {
      case NPSS_RDATA:
        if ( ( pPipeState->usKey != pPiper->ulInputPipeKey ) ||
             _readInputPipe( pPiper ) )
          break;
        /* Error in _readInputPipe(), failing to the next case to call
           _closeInputPipe(). */

      case NPSS_CLOSE:
        if ( pPipeState->usKey == pPiper->ulInputPipeKey )
        {
          debugCP( "Input pipe is closed by the server" );
          if ( pPiper->fnUser != NULL )
            pPiper->fnUser( pPiper, PREVENT_DISCONNECTED,
                            pPiper->pszCurPipe );

          _closeInputPipe( pPiper );
          DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT,
                           &pPiper->ulLostPipeTime, sizeof(ULONG) );
        }
        else if ( !fInputPipeOnly && ( pPiper->phServerPipes != NULL ) )
        {
          debug( "The server pipe #%d is closed by the client",
                 pPipeState->usKey );
          DosDisConnectNPipe( pPiper->phServerPipes[pPipeState->usKey] );
          DosConnectNPipe( pPiper->phServerPipes[pPipeState->usKey] );
        }
        break;
    }
  }
}


ULONG prExpandPipeName(ULONG cbBuf, PCHAR pcBuf, PSZ pszName)
{
  int        cBytes;

  while( isspace( *pszName ) )
    pszName++;

  if ( memicmp( pszName, "\\PIPE\\", 6 ) == 0 )
    pszName += 6;

  cBytes = _snprintf( pcBuf, cbBuf, "\\PIPE\\%s", pszName );
  if ( cBytes < 0 )
    return 0;

  return cBytes;
}


ULONG prInit(PPIPER *ppPiper, PPRINIT pInit)
{
  CHAR       acName[_MAX_PATH];
  ULONG      ulRC;
  ULONG      cBytes;
  ULONG      ulRes = PRRC_OK;
  PSZ        pszScan, pszNew;
  ULONG      cbPipes = 0;
  PPIPER     pPiper;
  
  if ( ( pInit->pcPipes == NULL ) || ( *pInit->pcPipes == '\0' ) )
    return PRRC_INVALIDSRVPIPENAME;

  pPiper = calloc( 1, sizeof(PIPER) );
  if ( pPiper == NULL )
    return PRRC_NOTENOUGHMENORY;

  pPiper->pcReadBuf = malloc( pInit->ulReadBufSize );

  if ( pPiper->pcReadBuf == NULL )
    ulRes = PRRC_NOTENOUGHMENORY;
  else
  do
  {
    if ( pInit->hevInputPipe != NULLHANDLE )
    {
      /* The user specified an event semaphore for the input pipe, check it. */
      ULONG  ulPostCount;

      ulRC = DosOpenEventSem( NULL, &pInit->hevInputPipe );
      if ( ulRC != NO_ERROR )
      {
        debug( "DosOpenEventSem(), rc = %lu", ulRC );
        ulRes = PRRC_INVALIDSEMAPHORE;
        break;
      }

      pPiper->hevInputPipe = pInit->hevInputPipe;
      pPiper->ulInputPipeKey = pInit->ulInputPipeKey;

      ulRC = DosResetEventSem( pInit->hevInputPipe, &ulPostCount );
      if ( ulRC != NO_ERROR && ulRC != ERROR_ALREADY_RESET )
      {
        debug( "DosResetEventSem(), rc = %lu", ulRC );
        ulRes = PRRC_INVALIDSEMAPHORE;
        break;
      }
    }

    // Store server pipes name.

    if ( ( pInit->pszServerPipe == NULL ) || ( *pInit->pszServerPipe == '\0' )
         || ( pInit->cServerPipes == 0 ) )
      pPiper->cServerPipes = 0;
    else
    {
      cBytes = prExpandPipeName( sizeof(acName), acName, pInit->pszServerPipe );
      if ( cBytes == 0 )
      {
        ulRes = PRRC_INVALIDSRVPIPENAME;
        break;
      }

      pPiper->pszServerPipes = strdup( acName );
      if ( pPiper->pszServerPipes == NULL )
      {
        ulRes = PRRC_NOTENOUGHMENORY;
        break;
      }

      pPiper->cServerPipes = pInit->cServerPipes;
      debug( "Server pipes (%lu) name: %s",
             pPiper->cServerPipes, pPiper->pszServerPipes );

    }  // if ( ( pszServerPipe != NULL ) && ( cServerPipes != 0 ) )


    // Store the list of pipes to which we will connect

    for( pszScan = pInit->pcPipes; *pszScan != '\0';
         pszScan = strchr( pszScan, '\0' ) + 1 )
    {
      // Expand pipe name to \PIPE\xxxxx
      cBytes = prExpandPipeName( sizeof(acName), acName, pszScan );
      if ( cBytes == 0 )
      {
        ulRes = PRRC_INVALIDPIPENAME;
        break;
      }

      if ( ( pPiper->pszServerPipes != NULL ) &&
           ( stricmp( acName, pPiper->pszServerPipes ) == 0 ) )
      {
        ulRes = PRRC_NAMECOLLISION;
        break;
      }

      // Add name to the list
      cBytes++;      // '\0' terminator for name.
      pszNew = realloc( pPiper->pcPipes,
                        cbPipes + cBytes + 1 ); // +1 : second '\0' for list.
      if ( pszNew == NULL )
      {
        debugCP( "Not enough memory" );
        ulRes = PRRC_NOTENOUGHMENORY;
        break;
      }
      pPiper->pcPipes = pszNew;

      debug( "Store Weasel log pipe name (%lu): %s", cBytes, acName );
      memcpy( &pszNew[cbPipes], acName, cBytes );
      cbPipes += cBytes;
      pszNew[cbPipes] = '\0';
    }  // for( pszScan ...


    // Create event semaphore for pipes

    ulRC = DosCreateEventSem( NULL, &pPiper->hevPipes,
                              DC_SEM_SHARED | DCE_AUTORESET, FALSE );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosCreateEventSem(), rc = %lu", ulRC );
      ulRes = PRRC_SRVPIPECREATEERR;
    }
    debug( "pPiper->hevPipes = %lu", pPiper->hevPipes );
  }
  while( FALSE );

  if ( ulRes != PRRC_OK )
  {
    prDone( pPiper );
    *ppPiper = NULL;
  }
  else
  {
    if ( pInit->hevInputPipe == NULLHANDLE )
    {
      // The user did not specify an input pipe semaphore; we will use our own.
      pPiper->hevInputPipe = pPiper->hevPipes;
      pPiper->ulInputPipeKey = _INPUT_PIPE_KEY;
    }

    pPiper->ulReconnectPeriod = pInit->ulReconnectPeriod;
    pPiper->fnUser = pInit->fnUser;
    pPiper->ulReadBufSize = pInit->ulReadBufSize;
    pPiper->ulWriteBufSize = pInit->ulWriteBufSize;

    /* We set the timerstamp so that the attempt to connect to the input pipe
       occurs when function prProcess() is called for the first time. */
    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &pPiper->ulLostPipeTime,
                     sizeof(ULONG) );
    pPiper->ulLostPipeTime -= pPiper->ulReconnectPeriod;

    // Pipe redirector object is ready.
    *ppPiper = pPiper;
  }

  return ulRes;
}

VOID prDone(PPIPER pPiper)
{
  if ( pPiper == NULL )
    return;

  _closeInputPipe( pPiper );

  if ( pPiper->hevInputPipe != NULLHANDLE &&
       pPiper->hevInputPipe != pPiper->hevPipes )
    DosCloseEventSem( pPiper->hevInputPipe );

  if ( pPiper->hevPipes != NULLHANDLE )
    DosCloseEventSem( pPiper->hevPipes );

  if ( pPiper->pszServerPipes != NULL )
    free( pPiper->pszServerPipes );

  if ( pPiper->pcPipes != NULL )
    free( pPiper->pcPipes );

  if ( pPiper->pcReadBuf != NULL )
    free( pPiper->pcReadBuf );

  free( pPiper );
}

VOID prProcess(PPIPER pPiper, BOOL fInputOnly)
{
  ULONG      ulRC;

  if ( pPiper == NULL )
    return;

  if ( fInputOnly )
  {
    if ( pPiper->hevInputPipe == pPiper->hevPipes )
      debugCP( "Parameter fInputOnly is TRUE but input pipe event sem. was not specified" );
    else
      /* The input pipe is attached to the user event semaphore. Check events
         on the input pipe only. */
      _checkPipeEvents( pPiper, TRUE );

    return;
  }

  if ( ( pPiper->hInputPipe == NULLHANDLE ) && ( pPiper->pcPipes != NULL ) )
  {
    // Input pipe not connected.

    ULONG    ulTime;

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
    if ( ( ulTime - pPiper->ulLostPipeTime ) < pPiper->ulReconnectPeriod )
      // It is not time to reconnect.
      return;

    // Try to connect to one of input pipes.
    if ( !_openInputPipe( pPiper ) )
    {
      /* Could not connect to the input pipe. Inform the user and postpone the
         attempt.  */

      pPiper->ulLostPipeTime = ulTime;
      if ( pPiper->fnUser != NULL )
        pPiper->fnUser( pPiper, PREVENT_CONNECTERROR, NULL );
      return;
    }

    // Ok, input pipe is connected now.
  }


  // Check events on pipes.

  // Check the semaphore to which the pipes are attached.
  ulRC = DosWaitEventSem( pPiper->hevPipes, SEM_IMMEDIATE_RETURN );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
      debug( "DosWaitEventSem(), rc = %lu", ulRC );
  }
  else
    /* Check events on input (if user event semaphore does not used) and server
       pipes. */
    _checkPipeEvents( pPiper, FALSE );
}

// Returns TRUE if the input pipe is connected.
BOOL prIsConnected(PPIPER pPiper)
{
  return ( pPiper != NULL ) && ( pPiper->hInputPipe != NULLHANDLE );
}
