/*
  Logfiles.
*/

#include <string.h>
#include <time.h>
#define INCL_DOSFILEMGR
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <os2.h>
#include "utils.h"
#include "log.h"
#include "debug.h"               // Should be last.

#define STDOUT         1

ULONG                  ulGlLogLevel = 4;
ULONG                  ulGlLogHistoryFiles = 0;
ULLONG                 ullGlLogMaxSize = 0;

static HMTX            hmtxLog     = NULLHANDLE;
static ULONG           ulLogFlags  = LOGFL_SCREEN;
static PSZ             pszLogFile  = NULL;
static HFILE           hLogFile    = NULLHANDLE;
// iLastRecordDay - day of the month in last record or 0.
static struct tm       stTMLastRecord;
static time_t          timeLastRecord = 0;


static HFILE _openLogFile(PSZ pszFile)
{
  ULONG      ulRC, ulAction;
  HFILE      hFile;

  debug( "File: %s", pszFile );

  ulRC = DosOpen( pszFile, &hFile, &ulAction, 0, FILE_NORMAL,
                  OPEN_ACTION_CREATE_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                  OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                  OPEN_SHARE_DENYWRITE | OPEN_ACCESS_WRITEONLY, NULL );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosOpen(), rc = %u", ulRC );
    printf( "A new logfile \"%s\" could not be opened.\n", pszFile );
    return NULLHANDLE;
  }

  if ( ulAction == FILE_EXISTED )
  {
    ulRC = DosSetFilePtr( hFile, 0, FILE_END, &ulAction );
    if ( ulRC != NO_ERROR )
      debug( "DosSetFilePtr(), rc = %u", ulRC );
  }

  return hFile;
}


// VOID _logRotation(ULONG ulMethod, time_t timeNow)

// ulMethod:
// Note: the following examples for logfile name IMAP4.LOG.

// _LRM_NUMBERS - Rename old files IMAP4-000.LOG to IMAP4-001.LOG,
// IMAP4-001.LOG to IMAP4-002.LOG, e.t.c. Rename current logfile to logfile
// with index 000. Remove file with greatest index (ulGlLogHistoryFiles - 1).
#define _LRM_NUMBERS             0

// _LRM_PREV_DATE - rename current logfile to logfile with date of last record
// like IMAP4-20170922.LOG and remove oldest date file(s)
// (ulGlLogHistoryFiles days old: IMAP4-20170810.LOG, IMAP4-20170810-??????.LOG)
#define _LRM_PREV_DATE           1

// _LRM_LAST_REC_TIMESTAMP - only rename current logfile to name with last
// record timestamp like IMAP4-20170922-233501.LOG
#define _LRM_LAST_REC_TIMESTAMP  2

// timeNow - current time stamp, uses only with _LRM_PREV_DATE

static VOID _logRotation(ULONG ulMethod, time_t timeNow)
{
  ULONG      ulRC, ulAddLen;
  CHAR       acBasename[CCHMAXPATH];
  ULONG      cbBasename;
  PCHAR      pcLastSlash, pcExt;
  CHAR       acNewName[CCHMAXPATH];

  if ( pszLogFile == NULL ) 
  {
    debugCP( "Logfile name was not set" );
    return;
  }

/*
  if ( ulGlLogHistoryFiles == 0 )
  {
    // Do not store history files - restart logfile (simply remove the file).

    ulRC = DosDelete( pszLogFile );
    if ( ulRC != NO_ERROR )
      debug( "#1 DosDelete(\"%s\"), rc = %u", pszLogFile, ulRC );

    return;
  }
*/

  // Get logfile extension.
  pcLastSlash = strrchr( pszLogFile, '\\' );
  if ( pcLastSlash == NULL )
    pcLastSlash = pszLogFile;
  pcExt = strrchr( pcLastSlash, '.' );
  if ( pcExt == NULL )
    pcExt = strchr( pcExt, '\0' );

  switch( ulMethod )
  {
    case _LRM_NUMBERS:             ulAddLen = 3;  break;  // "NNN"
    case _LRM_PREV_DATE:           ulAddLen = 8;  break;  // "YYYYMMDD"
//    case _LRM_LAST_REC_TIMESTAMP:
    default:                       ulAddLen = 15; break;  // "YYYYMMDD-HHMMSS"
  }

  cbBasename = pcExt - (PCHAR)pszLogFile;
  if ( ( cbBasename + ulAddLen + strlen( pcExt ) ) >=
       ( sizeof(acBasename) - 1 /* '-' */ ) )
  {
    debug( "Logfile full name is too long (%u bytes + mark %u bytes + "
           "extension %u bytes): \"%s\"",
           cbBasename, ulAddLen + 1, strlen( pcExt ),
           debugBufPSZ( pszLogFile, cbBasename ) );
    return;
  }

  // Store logfile pathname without extension, add '-' character.
  memcpy( acBasename, pszLogFile, cbBasename );
  acBasename[cbBasename] = '-';
  cbBasename++;

  switch( ulMethod )
  {
    case _LRM_NUMBERS:
      {
        // Size-based rotation. Hostory files will be named as "logfile-000.ext",
        // "logfile-001.ext", e.t.c,

        ULONG    ulIdx;

        // Remove oldest history file.
        _snprintf( &acBasename[cbBasename], sizeof(acBasename) - cbBasename,
                   "%.3u%s", ulGlLogHistoryFiles - 1, pcExt );
        ulRC = DosDelete( acBasename );
        if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_FILE_NOT_FOUND ) )
          debug( "#2 DosDelete(\"%s\"), rc = %u", acBasename, ulRC );

        // Rename history files.
        for( ulIdx = ulGlLogHistoryFiles - 1; ; ulIdx-- )
        {
          strcpy( acNewName, acBasename );
          if ( ulIdx == 0 )
            break;

          _snprintf( &acBasename[cbBasename], sizeof(acBasename) - cbBasename,
                     "%.3u%s", ulIdx - 1, pcExt );

          ulRC = DosMove( acBasename, acNewName );
          if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_FILE_NOT_FOUND ) )
            debug( "#1 DosMove(\"%s\",\"%s\"), rc = %u",
                   acBasename, acNewName, ulRC );
        }

        // Rename logfile to history file with index 0.
        ulRC = DosMove( pszLogFile, acNewName );
        if ( ulRC != NO_ERROR )
          debug( "#2 DosMove(\"%s\",\"%s\"), rc = %u",
                 pszLogFile, acNewName, ulRC );
      }
      break;

    case _LRM_PREV_DATE:
      {
        // Date-based rotation. Hostory files will be named like
        // logfile-YYYYMMDD.ext.

        struct tm          stTM;

        // Remove oldest date history file (for ex. IMAP4-20170922).

        timeNow -= ( (ulGlLogHistoryFiles + 1) * (24*60*60) );
        memcpy( &stTM, localtime( &timeNow ), sizeof(stTM) );
        strftime( &acBasename[cbBasename], sizeof(acBasename) - cbBasename,
                  "%Y%m%d", &stTM );
        strcpy( &acBasename[cbBasename + 8], pcExt );

        ulRC = DosDelete( acBasename );
        if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_FILE_NOT_FOUND ) )
          debug( "#3 DosDelete(\"%s\"), rc = %u", acBasename, ulRC );

        // Remove files with time for oldest date (ex.: IMAP4-20170922-??????).
        // These files could be created by calls with _LRM_LAST_REC_TIMESTAMP.
        {
          HDIR               hDir = HDIR_CREATE;
          FILEFINDBUF3       stFind;
          ULONG              cFind = 1;
          CHAR               acNewName[CCHMAXPATH];
          ULONG              cbPath = pcLastSlash - (PCHAR)pszLogFile;

          memcpy( acNewName, acBasename, cbPath );

          sprintf( &acBasename[cbBasename + 8], "-??????%s", pcExt );
          ulRC = DosFindFirst( acBasename, &hDir, FILE_ARCHIVED, &stFind,
                               sizeof(stFind), &cFind, FIL_STANDARD );
          while( ulRC == NO_ERROR )
          {
            sprintf( (PSZ)&acNewName[cbPath], "\\%s", stFind.achName );
            ulRC = DosDelete( acNewName );
            if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_FILE_NOT_FOUND ) )
              debug( "#4 DosDelete(\"%s\"), rc = %u", acNewName, ulRC );

            cFind = 1;
            ulRC = DosFindNext( hDir, &stFind, sizeof(FILEFINDBUF3), &cFind );
          }
          DosFindClose( hDir );
        }

        // Make name for the new history file.
        strftime( &acBasename[cbBasename], sizeof(acBasename) - cbBasename,
                  "%Y%m%d", &stTMLastRecord );
        strcpy( &acBasename[cbBasename + 8], pcExt );

        // Rename logfile to history file with current date in name.

        ulRC = DosDelete( acBasename );
        if ( ( ulRC != NO_ERROR ) && ( ulRC != ERROR_FILE_NOT_FOUND ) )
          debug( "#4 DosDelete(\"%s\"), rc = %u", acBasename, ulRC );

        ulRC = DosMove( pszLogFile, acBasename );
        if ( ulRC != NO_ERROR )
          debug( "#3 DosMove(\"%s\",\"%s\"), rc = %u",
                 pszLogFile, acBasename, ulRC );
      }
      break;

    default: // _LRM_LAST_REC_TIMESTAMP:
      // Make name for the new history file.
      strftime( &acBasename[cbBasename], sizeof(acBasename) - cbBasename,
                "%Y%m%d-%H%M%S", &stTMLastRecord );
      strcpy( &acBasename[cbBasename + 15], pcExt );

      ulRC = DosMove( pszLogFile, acBasename );
      if ( ulRC != NO_ERROR )
        debug( "#4 DosMove(\"%s\",\"%s\"), rc = %u",
               pszLogFile, acBasename, ulRC );

      break;
  }  // switch( ulMethod )
}



BOOL logInit()
{
  ULONG      ulRC;

  if ( hmtxLog != NULLHANDLE )
  {
    debugCP( "Already initialized" );
    return TRUE;
  }

  timeLastRecord = 0;

  ulRC = DosCreateMutexSem( NULL, &hmtxLog, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  return TRUE;
}

VOID logDone()
{
  ULONG      ulRC;

  if ( pszLogFile != NULL )
  {
    free( pszLogFile );
    pszLogFile = NULL;
  }

  if ( hmtxLog != NULLHANDLE )
  {
    ulRC = DosCloseMutexSem( hmtxLog );
    if ( ulRC != NO_ERROR )
      debug( "DosCloseMutexSem(), rc = %u", ulRC );

    hmtxLog = NULLHANDLE;
  }

  if ( hLogFile != NULLHANDLE )
  {
    ulRC = DosClose( hLogFile );
    if ( ulRC != NO_ERROR )
      debug( "DosClose(), rc = %u", ulRC );

    hLogFile = NULLHANDLE;
  }
}

VOID logSetup(ULONG ulFlags, PSZ pszFile)
{
  ULONG      ulRC;
  BOOL       fChangeFileName = STR_ICMP( pszLogFile, pszFile ) != 0;
  HFILE      hNewFile = NULLHANDLE;
  BOOL       fEmptyNewFileName = ( pszFile == NULL ) || ( *pszFile == '\0' );

  if ( hmtxLog == NULLHANDLE )
  {
    debugCP( "Not initialized" );
    return;
  }

//  debug( "Flags: 0x%X, file: %s", ulFlags, pszFile );

  if ( ( (ulFlags & LOGFL_DISK) != 0 ) &&
       ( fChangeFileName || ( hLogFile == NULLHANDLE ) ) )
  {
    if ( !fEmptyNewFileName )
    {
      hNewFile = _openLogFile( pszFile );

      if ( hNewFile == NULLHANDLE )
        fChangeFileName = FALSE;
    }
  }

  DosRequestMutexSem( hmtxLog, SEM_INDEFINITE_WAIT );

  if ( ( hLogFile != NULLHANDLE ) &&
       ( ( hNewFile != NULLHANDLE ) || ( (ulFlags & LOGFL_DISK) == 0 ) ) )
  {
    ulRC = DosClose( hLogFile );
    if ( ulRC != NO_ERROR )
      debug( "DosClose(), rc = %u", ulRC );

    hLogFile = NULLHANDLE;
  }

  if ( fChangeFileName )
  {
    if ( pszLogFile != NULL )
      free( pszLogFile );

    pszLogFile = fEmptyNewFileName ? NULL : strdup( pszFile );
  }

  if ( hNewFile != NULLHANDLE )
    hLogFile = hNewFile;

  ulLogFlags = ulFlags;

  DosReleaseMutexSem( hmtxLog );
}

VOID logRotation()
{
  DosRequestMutexSem( hmtxLog, SEM_INDEFINITE_WAIT );

  DosClose( hLogFile );
  _logRotation( ullGlLogMaxSize != 0 ? _LRM_NUMBERS : _LRM_LAST_REC_TIMESTAMP,
                0 );
  hLogFile = _openLogFile( pszLogFile );

  DosReleaseMutexSem( hmtxLog );
}

VOID logWrite(ULONG ulLevel, LONG cbLine, PCHAR pcLine)
{
  time_t     timeLog;
  struct tm  stTM;
  CHAR       acBuf[512];
  ULONG      ulActual;
  ULONG      ulRC;

  // Write timestamp to the buffer.
  time( &timeLog );
  memcpy( &stTM, localtime( &timeLog ), sizeof(stTM) );
  strftime( acBuf, sizeof(acBuf), "%Y%m%d %H%M%S ", &stTM );
 
#ifdef DEBUG_CODE
  // Add loglevel after the timestamp for debug build.
  sprintf( &acBuf[16], "[%.2lu] ", ulLevel );
#define _LOGBUFTEXTOFFS          21
#else
#define _LOGBUFTEXTOFFS          16
#endif

  if ( cbLine < 0 )
    cbLine = strlen( pcLine );

  // Write a message to the buffer.
  if ( cbLine > ( sizeof(acBuf) - _LOGBUFTEXTOFFS - 2 ) )
    cbLine = sizeof(acBuf) - _LOGBUFTEXTOFFS - 2;
  memcpy( &acBuf[_LOGBUFTEXTOFFS], pcLine, cbLine );
  cbLine += _LOGBUFTEXTOFFS;

  // Append CR LF.
  acBuf[cbLine++] = '\r';
  acBuf[cbLine++] = '\n';

  // Output a new log record.

  DosRequestMutexSem( hmtxLog, SEM_INDEFINITE_WAIT );

  if ( hLogFile != NULLHANDLE )
  {
    if ( ulGlLogHistoryFiles != 0 )
    {
      // Rotation is allowed.

      BOOL             fSizeBasedRotation = ( ullGlLogMaxSize != 0 );
      FILESTATUS3L     sInfo;
      BOOL             fRotate;

      if ( fSizeBasedRotation )
      {
        // Query logfile size for size-based rotation.
        ulRC = DosQueryFileInfo( hLogFile, FIL_STANDARDL, &sInfo,
                                 sizeof(FILESTATUS3L) );
        if ( ulRC != NO_ERROR )
          debug( "DosQueryFileInfo(), rc = %u" );

        fRotate = ( ulRC == NO_ERROR ) && ( sInfo.cbFile >= ullGlLogMaxSize );
      }
      else
        fRotate = ( timeLastRecord != 0 ) && ( timeLastRecord < timeLog ) &&
                  ( stTMLastRecord.tm_mday != stTM.tm_mday );

      if ( fRotate )
      {
        DosClose( hLogFile );
        _logRotation( fSizeBasedRotation ? _LRM_NUMBERS : _LRM_PREV_DATE,
                      timeLog );
        hLogFile = _openLogFile( pszLogFile );
      }
    }

    // Write a new log record to the file.
    DosWrite( hLogFile, acBuf, cbLine, &ulActual );
  }

  if ( (ulLogFlags & LOGFL_SCREEN) != 0 )
    // Output to the console.
    DosWrite( STDOUT, acBuf, cbLine, &ulActual );

  stTMLastRecord = stTM;
  timeLastRecord = timeLog;

  DosReleaseMutexSem( hmtxLog );
}

VOID logWriteVA(ULONG ulLevel, PSZ pszFormat, va_list arglist)
{
  LONG       cbBuf;
  CHAR       acBuf[512];

  // Write a formatted message to the buffer.
  cbBuf = vsnprintf( acBuf, sizeof(acBuf), pszFormat, arglist );

  logWrite( ulLevel, cbBuf < 0 ? sizeof(acBuf) : cbBuf, acBuf );
}

VOID logWriteFmt(ULONG ulLevel, PSZ pszFormat, ...)
{
  va_list    arglist;

  va_start( arglist, pszFormat );
  logWriteVA( ulLevel, pszFormat, arglist );
  va_end( arglist );
}
