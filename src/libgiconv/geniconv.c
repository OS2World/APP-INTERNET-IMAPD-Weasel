/*
  Universal iconv implementation for OS/2.

  Andrey Vasilkin, 2016.
*/

#define INCL_DOSMODULEMGR     /* Module Manager values */
#define INCL_DOSERRORS        /* Error values */
#define INCL_DOSNLS
#include <os2.h>
#include <iconv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef DEBUG_FILE

#include <os2/debug.h>

#else

#ifdef DEBUG
# define debug(s,...) printf("%s(): "s"\n", __func__, ##__VA_ARGS__)
#else
# define debug(s,...)
#endif

#endif

// Exports from os2iconv.c.
extern iconv_t _System os2_iconv_open(const char* tocode, const char* fromcode);
extern size_t _System os2_iconv(iconv_t cd, const char* * inbuf,
                                size_t *inbytesleft, char* * outbuf,
                                size_t *outbytesleft);
extern int _System os2_iconv_close(iconv_t cd);

// Functions pointers types.
typedef iconv_t _System (*FNICONV_OPEN)(const char* tocode, const char* fromcode);
typedef size_t _System (*FNICONV)(iconv_t cd, const char* * inbuf,
                                  size_t *inbytesleft, char* * outbuf,
                                  size_t *outbytesleft);
typedef int _System (*FNICONV_CLOSE)(iconv_t cd);

// Used DLL module handle.
static HMODULE         hmIconv = NULLHANDLE;
// Functions pointers.
static FNICONV_OPEN    fn_iconv_open = NULL;
static FNICONV         fn_iconv = NULL;
static FNICONV_CLOSE   fn_iconv_close = NULL;
static CHAR            acLocalCharset[16] = { 0 };


static BOOL _loadDLL(PSZ pszName, PSZ pszIconvOpen, PSZ pszIconv,
                     PSZ pszIconvClose)
{
  ULONG      ulRC;
  CHAR       acError[256];

  ulRC = DosLoadModule( acError, sizeof(acError), pszName, &hmIconv );
  if ( ulRC != NO_ERROR )
  {
    debug( "DLL not loaded: %s", acError );
    return FALSE;
  }

  do
  {
    ulRC = DosQueryProcAddr( hmIconv, 0, pszIconvOpen, (PFN *)&fn_iconv_open );
    if ( ulRC != NO_ERROR )
    {
      debug( "Error: cannot find entry %s in %s", pszIconvOpen, pszName );
      break;
    }

    ulRC = DosQueryProcAddr( hmIconv, 0, pszIconv, (PFN *)&fn_iconv );
    if ( ulRC != NO_ERROR )
    {
      debug( "Error: cannot find entry %s in %s", pszIconv, pszName );
      break;
    }

    ulRC = DosQueryProcAddr( hmIconv, 0, pszIconvClose, (PFN *)&fn_iconv_close );
    if ( ulRC != NO_ERROR )
    {
      debug( "Error: cannot find entry %s in %s", pszIconvClose, pszName );
      break;
    }

    debug( "DLL %s used", pszName );
    return TRUE;
  }
  while( FALSE );

  DosFreeModule( hmIconv );
  hmIconv = NULLHANDLE;
  return FALSE;
}

static void _init()
{
  PSZ        pszEnvSet;

  if ( fn_iconv_open != NULL )
    // Already was initialized.
    return;

  pszEnvSet = getenv( "GENICONV" );

  // Try to load iconv2.dll, kiconv.dll or iconv.dll.
  if (
       (
         ( pszEnvSet != NULL ) && ( stricmp( pszEnvSet, "UCONV" ) == 0 )
       )
     ||
       (
         !_loadDLL( "ICONV2", "_libiconv_open", "_libiconv", "_libiconv_close" ) &&
         !_loadDLL( "KICONV", "_libiconv_open", "_libiconv", "_libiconv_close" ) &&
         !_loadDLL( "ICONV", "_iconv_open", "_iconv", "_iconv_close" )
       )
     )
  {
    // No one DLL was loaded - use OS/2 conversion objects API.

    debug( "Uni*() API used" );
    fn_iconv_open  = os2_iconv_open;
    fn_iconv       = os2_iconv;
    fn_iconv_close = os2_iconv_close;
  }
  else
  {
    ULONG    aulCP[3];
    ULONG    cbCP, ulRC;

    ulRC = DosQueryCp( sizeof(aulCP), aulCP, &cbCP );

    if ( ulRC != NO_ERROR ) 
      debug( "DosQueryCp(), rc = %u", ulRC );
    else
    {
      if ( aulCP[0] == 437 )
      {
        /* We need to use name ISO-8859-1 as system-default cp because iconv
           DLL does not understand codepage 437. */
        debug( "Local codepage 437 detected" );
        strcpy( acLocalCharset, "ISO-8859-1" );
      }
      else
      {
        debug( "Local codepage: %u", aulCP[0] );
        sprintf( acLocalCharset, "CP%lu", aulCP[0] );
      }
    }
  }
}

// Makes libiconv-style codepage name from OS/2-style IBM-xxxx name.
// Convert IBM-437 to ISO-8859-1, IBM-xxxx to CPxxxx
// ppszName - in/out.
// pcBuf/cbBuf - buffer for the new name.
// Returns FALSE if buffer pcBuf/cbBuf too small.

static BOOL _correctName(PSZ *ppszName, PCHAR pcBuf, ULONG cbBuf)
{
  if ( *ppszName == NULL )
    return FALSE;

  if ( ( stricmp( *ppszName, "IBM-437" ) == 0 ) ||
       ( stricmp( *ppszName, "CP437"   ) == 0 ) ||
       ( stricmp( *ppszName, "CP-437"  ) == 0 ) )
  {
    if ( cbBuf < 11 )
      return FALSE;

    strcpy( pcBuf, "ISO-8859-1" );
  }
  else
  {
    if ( ( memicmp( *ppszName, "IBM-", 4 ) != 0 ) ||
         ( _snprintf( pcBuf, cbBuf, "CP%s", &((*ppszName)[4]) ) == -1 ) )
      return FALSE;

    pcBuf[cbBuf - 1] = '\0';
  }

  debug( "CP name %s used instead %s", pcBuf, *ppszName );
  *ppszName = pcBuf;

  return TRUE;
}

static iconv_t _iconv_open(const char* tocode, const char* fromcode)
{
  iconv_t    ic;
  const char *pcToCode = ( tocode == NULL || *tocode == '\0' ) ?
                           (const char *)acLocalCharset : tocode;
  const char *pcFromCode = ( fromcode == NULL || *fromcode == '\0' ) ?
                             (const char *)acLocalCharset : fromcode;

  ic = fn_iconv_open( pcToCode, pcFromCode );

  if ( ic == (iconv_t)-1 )
  {
    CHAR  acToCode[128];
    CHAR  acFromCode[128];
    BOOL  fToCode = _correctName( (PSZ *)&pcToCode, acToCode, sizeof(acToCode) );
    BOOL  fFromCode = _correctName( (PSZ *)&pcToCode, acFromCode,
                                    sizeof(acFromCode) );

    if ( fToCode || fFromCode )
      ic = fn_iconv_open( tocode, fromcode );
  }

  return ic;
}


//           Public routines.
//           ----------------

// Non-standard function for iconv to unload the used dynamic library.
void iconv_clean()
{
  if ( hmIconv != NULLHANDLE )
  {
    DosFreeModule( hmIconv );
    hmIconv = NULLHANDLE;

    fn_iconv_open  = NULL;
    fn_iconv       = NULL;
    fn_iconv_close = NULL;
  }
}

iconv_t iconv_open(const char* tocode, const char* fromcode)
{
  _init();

  return _iconv_open( tocode, fromcode );
}

size_t iconv(iconv_t cd, const char* * inbuf, size_t *inbytesleft,
                char* * outbuf, size_t *outbytesleft)
{
  return fn_iconv( cd, (const char **)inbuf, inbytesleft, outbuf, outbytesleft );
}

int iconv_close(iconv_t cd)
{
  return fn_iconv_close( cd );
}
