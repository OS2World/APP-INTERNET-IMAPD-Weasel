#define INCL_DOSNMPIPES
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#define INCL_DOSMISC
#define INCL_DOSPROCESS
#include <os2.h>
#include <process.h>
#include <string.h>
#include <ctype.h>
#include "context.h"
#include "storage.h"
#include "imapfs.h"
#include "log.h"
#include "wcfg.h"
#include "debug.h"               // Should be last.

#define _LOG_PIPE                "\\PIPE\\WeaselTransLog"
#define _PIPE_OPEN_DELAY         7000 //19000     // msec.
#define _LOG_BUF_SIZE            32768

static PCHAR           pcLogBuf = NULL;
static ULONG           ulBufPos = 0;
static HFILE           hPipe = NULLHANDLE;
static ULONG           ulOpenTime;
static BOOL            fScreen = FALSE;


static VOID _logLine(ULONG cbLine, PCHAR pcLine)
{
  /*
     Catch SMTP records:
       2017-09-19 21:42:23 S  1016  D:\MAIL\os2.snc.ru\sms-gate\KV64WB.MSG
  */

  ULONG      ulRC;

  if ( fScreen )
    printf( "[Weasel] %s\n", pcLine );

  if ( // SMTP log record?
       ( cbLine > 32 ) && ( pcLine[10] == ' ' ) &&
       ( *((PULONG)&pcLine[19]) == 0x20205320 /* ' S  ' */ ) &&

       // File pathname (begins with 'D:\')?
       isalpha( pcLine[29] ) && ( pcLine[30] == ':' ) &&
       ( pcLine[31] == '\\' ) &&

       // Ends with '.MSG'?
       ( *((PULONG)&pcLine[cbLine - 4]) == 0x47534D2E ) )
  {
    PSZ      pszFile = &pcLine[29];

    logf( 5, "Weasel SMTP log record caught for %s", pszFile );
    ulRC = fsNotifyChange( 0, pszFile );
    if ( ulRC < ARRAYSIZE(apszFSNotifyResults) )
      logf( 4, "Notify \"%s\": %s", pszFile, &apszFSNotifyResults[ulRC][1] );
  }
}


BOOL wlogInit(BOOL fScreenOutput)
{
  if ( pcLogBuf != NULL )
  {
    debug( "Already initialized" );
    return TRUE;
  }

  pcLogBuf = malloc( _LOG_BUF_SIZE );
  if ( pcLogBuf == NULL )
  {
    debug( "Not enough memory" );
    return FALSE;
  }
  ulBufPos = 0;
  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulOpenTime, sizeof(ULONG) );
  fScreen = fScreenOutput;
  return TRUE;
}

VOID wlogDone()
{
  if ( pcLogBuf == NULL )
    // The module was not initialized.
    return;

  if ( hPipe != NULLHANDLE )
  {
    DosClose( hPipe );
    hPipe = NULLHANDLE;
  }

  free( pcLogBuf );
  pcLogBuf = NULL;
}

VOID wlogRead()
{
  ULONG      ulRC;
  static ULONG ulLastRC = NO_ERROR;
  ULONG      ulTime;
  ULONG      ulActual;
  AVAILDATA  stAvail;
  ULONG      ulState;
  PCHAR      pcLine, pcNextLine;

  if ( pcLogBuf == NULL )
    // The module was not initialized.
    return;

  if ( hPipe == NULLHANDLE )
  {
    // The pipe was not open.

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
    if ( ( (ulOpenTime - ulTime) & 0x80000000 ) == 0 )
      // Not time to reopen the pipe.
      return;

    // Try to open pipe...
    ulRC = DosOpen( _LOG_PIPE, &hPipe, &ulActual, 0, FILE_NORMAL,
                    OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                    OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                    OPEN_FLAGS_NOINHERIT | OPEN_SHARE_DENYNONE |
                    OPEN_ACCESS_READONLY, NULL );
    if ( ulRC != NO_ERROR )
    {
      hPipe = NULLHANDLE;
      ulOpenTime = ulTime + _PIPE_OPEN_DELAY;        // Next open try time.

      if ( ulLastRC != ulRC )                        // Do not repeat message.
      {
        if ( ulRC == ERROR_PIPE_BUSY )
          logs( 4, "Weasel log pipe is busy. Open attempt postponed." );
        else if ( ulRC == ERROR_PATH_NOT_FOUND )
          logf( 4, "Weasel log pipe does not exist. Open attempt postponed." );
        else
          logf( 4, "Weasel log pipe open error %u.", ulRC );

        ulLastRC = ulRC;
      }
      return;
    }

    logs( 4, "Weasel log pipe is open." );
    ulLastRC = NO_ERROR;
    ulBufPos = 0;
  }  // if ( hPipe == NULLHANDLE )

  while( TRUE )
  {
    // Check input data to be available.

    ulRC = DosPeekNPipe( hPipe, &pcNextLine, sizeof(pcNextLine), &ulActual,
                         &stAvail, &ulState );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosPeekNPipe(), rc = %u", ulRC );
      break;
    }

    if ( ulActual == 0 )
    {
      // No new data in pipe.

      if ( ulState == NP_STATE_CLOSING )
        // Close pipe, set reconnection timeout.
        ulRC = ~(0);

      break;
    }

    // Read data from the pipe.

    ulRC = DosRead( hPipe, &pcLogBuf[ulBufPos], _LOG_BUF_SIZE - ulBufPos,
                    &ulActual );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosRead(), rc = %u", ulRC );
      break;
    }
    ulBufPos += ulActual; // ulBufPos - next buffer write position;

    // Scan all received lines.

    pcLine = pcLogBuf;
    do
    {
      pcNextLine = memchr( pcLine, '\n', ulBufPos - ( pcLine - pcLogBuf ) );

      if ( pcNextLine != NULL )
      {
        PCHAR          pcEnd = pcNextLine;

        while( ( pcEnd > pcLine ) && isspace( *(pcEnd - 1) ) )
          pcEnd--;
        *pcEnd = '\0';

        // Parse received line.
        _logLine( pcEnd - pcLine, pcLine );

        pcLine = pcNextLine + 1;
      }
      else if ( pcLine != pcLogBuf )
      {
        // End of line not found and data is not at the beginning of buffer.
        // Move received data to the beginning of buffer and read more data.
        ulBufPos -= ( pcLine - pcLogBuf );
        memcpy( pcLogBuf, pcLine, ulBufPos );
        break;
      }
      else
      {
        // Received line is too long. Well, drop received data.
        ulBufPos = 0;
        break;
      }
    }
    while( ulBufPos != 0 );
  }  // while( TRUE )

  if ( ulRC != NO_ERROR )
  {
    // On error - close the pipe and set timeout for next pipe open trying.
    if ( hPipe != NULLHANDLE )
    {
      DosClose( hPipe );
      hPipe = NULLHANDLE;
    }

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
    // Set time for next attempt to open pipe.
    ulOpenTime = ulTime + _PIPE_OPEN_DELAY;
  }
}

BOOL wlogIsConnected()
{
  return hPipe != NULLHANDLE;
}
