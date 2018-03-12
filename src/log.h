#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <utils.h>     // ULLONG type

// LOGFL_xxxxx for logSetup(ulFlags,)
#define LOGFL_DISK     0x0001
#define LOGFL_SCREEN   0x0002

extern ULONG           ulGlLogLevel;
extern ULONG           ulGlLogHistoryFiles; // 0 - do not rotate.
extern ULLONG          ullGlLogMaxSize;     // [bytes], 0 - date-based rotation.

#define IF_LOGLEVEL(_level) if ( ulGlLogLevel >= _level ) do {
#define END_IF_LOGLEVEL } while( FALSE );
#define BREAK_LOGLEVEL break;

#define logf(_level,_fmt,...) do { \
  if ( ulGlLogLevel >= _level ) logWriteFmt( _level, (_fmt), ##__VA_ARGS__ ); \
} while( FALSE )

#define logs(_level,_str) do { \
  if ( ulGlLogLevel >= _level ) logWrite( _level, -1, _str); \
} while( FALSE )

#define logv(_level,_fmt,_arglist) do { \
  if ( ulGlLogLevel >= _level ) logWriteVA( _level, (_fmt), _arglist); \
} while( FALSE )


BOOL logInit();
VOID logDone();

// ulFlags: LOGFL_xxxxx
VOID logSetup(ULONG ulFlags, PSZ pszFile);

VOID logRotation();

VOID logWrite(ULONG ulLevel, LONG cbLine, PCHAR pcLine);
VOID logWriteVA(ULONG ulLevel, PSZ pszFormat, va_list arglist);
VOID logWriteFmt(ULONG ulLevel, PSZ pszFormat, ...);

#endif // LOG_H
