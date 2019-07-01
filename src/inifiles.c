/*
  OS/2 native INI and TNI text files formats support.
*/

#include <string.h>
#include <ctype.h>
#define INCL_DOSERRORS
#define INCL_WINSHELLDATA
#include <os2.h>
#include "inifiles.h"
#include "utils.h"
#include "debug.h"               // Should be last.

#ifdef DEBUG_CODE
//#define DEBUG_TNI
#endif

//#define _NO_HIGHMEM


static LHANDLE APIENTRY tniOpen(LHANDLE, PSZ pszFileName);
static BOOL APIENTRY tniClose(LHANDLE hObj);
static BOOL APIENTRY tniQuerySize(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                  PULONG pulReqLen);
static BOOL APIENTRY tniQueryData(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                  PVOID pBuf, PULONG pulBufLen);
static ULONG APIENTRY tniQueryString(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                     PSZ pszDefault, PVOID pBuffer,
                                     ULONG ulBufferMax);
/*static LONG APIENTRY tniQueryInt(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                 LONG lDefault);*/

static INICLASS        aClass[] =
{
  { // Class type INITYPE_INI (0) - native OS/2 INI files.
    // Type switching to avoid compiler warnings about PSZ/PCSZ types.
    (IFNOPEN)PrfOpenProfile,               // fnOpen
    PrfCloseProfile,                       // fnClose
    (IFNQUERYSIZE)PrfQueryProfileSize,     // fnQuerySize
    (IFNQUERYDATA)PrfQueryProfileData,     // fnQueryData
    (IFNQUERYSTRING)PrfQueryProfileString/*, // fnQueryString
    (IFNQUERYINT)PrfQueryProfileInt        // fnQueryInt
*/
  },
  { // Class type INITYPE_TNI (1) - text TNI files.
    tniOpen,
    tniClose,
    tniQuerySize,
    tniQueryData,
    tniQueryString/*,
    tniQueryInt*/
  }
  /* Any other types impementations. May be XML? :) */
};


/*
    Text TNI files impementation
    ----------------------------
*/

typedef struct TNIKEY {
  ULONG      cbName;             // Including ZERO.
  ULONG      cbVal;
  CHAR       acData[1];
} TNIKEY, *PTNIKEY;

typedef struct TNIAPP {
  ULONG      cKey;
  PTNIKEY    *papKey;
  CHAR       acName[1];
} TNIAPP, *PTNIAPP;

typedef struct TNI {
  ULONG      cApp;
  PTNIAPP    *papApp;
} TNI, *PTNI;


typedef struct TNIREAD {
  FILE       *fd;
  ULONG      ulLine;
  ULONG      ulMaxBuf;
  ULONG      cbBuf;
  PCHAR      pcBuf;
} TNIREAD, *PTNIREAD;

static BOOL _fReadStr(PTNIREAD pReadData, ULONG cbBuf, PCHAR pcBuf, PSZ *ppszLine)
{
  if ( fgets( pcBuf, cbBuf, pReadData->fd ) == NULL )
    return FALSE;

  STR_SKIP_SPACES( pcBuf );
  STR_RTRIM( pcBuf );
  *ppszLine = pcBuf;

  pReadData->ulLine++;

  return TRUE;
}

static BOOL _tniInsData(PTNIREAD pReadData, ULONG cbData, PVOID pData)
{
  ULONG      ulNewSize = pReadData->cbBuf + cbData;

  if ( ulNewSize > pReadData->ulMaxBuf )
  {
    PCHAR    pcNew;

    ulNewSize = (ulNewSize & ~0x00FF) + 0x0100;
    pcNew = realloc( pReadData->pcBuf, ulNewSize );
    if ( pcNew == NULL )
      return FALSE;
    pReadData->pcBuf = pcNew;
    pReadData->ulMaxBuf = ulNewSize;
  }

  memcpy( &pReadData->pcBuf[pReadData->cbBuf], pData, cbData );
  pReadData->cbBuf += cbData;

  return FALSE;
}

static BOOL _insertItem(PVOID **ppapArray, PULONG pcItems, PVOID pItem)
{
  PVOID      *papArray = *ppapArray;
  ULONG      cItems = *pcItems;

  if ( (cItems & 0x3F) == 0 )
  {
    PVOID    *papNew = realloc( papArray, (cItems + 0x40) * sizeof(PVOID) );

    if ( papNew == NULL )
    {
      debugCP( "Not enough memory" );
      return FALSE;
    }

    papArray = papNew;
    *ppapArray = papArray;
  }

  papArray[cItems] = pItem;
  *pcItems = cItems + 1;

  return TRUE;
}

#ifdef DEBUG_TNI
static VOID _tniDebugPrint(PTNI pTNI)
{
  ULONG      ulAppIdx, ulKeyIdx;
  PTNIAPP    pApp;
  PTNIKEY    pKey;

  for( ulAppIdx = 0; ulAppIdx < pTNI->cApp; ulAppIdx++ )
  {
    pApp = pTNI->papApp[ulAppIdx];
    printf( "[%s]\n", pApp->acName );

    for( ulKeyIdx = 0; ulKeyIdx < pApp->cKey; ulKeyIdx++ )
    {
      pKey = pApp->papKey[ulKeyIdx];

      printf( "  %s, %u bytes\n", pKey->acData, pKey->cbVal );
    }
  }
}
#else
#define _tniDebugPrint(_ptni)
#endif

static int __compTNIKey(const void *p1, const void *p2)
{
  PTNIKEY    pKey1 = *((PTNIKEY *)p1);
  PTNIKEY    pKey2 = *((PTNIKEY *)p2);

  return strcmp( pKey1->acData, pKey2->acData );
}

static int __compSearchTNIKey(const void *p1, const void *p2)
{
  PSZ        pszKey = (PSZ)p1;
  PTNIKEY    pKey   = *((PTNIKEY *)p2);

  return strcmp( pszKey, pKey->acData );
}

static int __compTNIApp(const void *p1, const void *p2)
{
  PTNIAPP    pApp1 = *((PTNIAPP *)p1);
  PTNIAPP    pApp2 = *((PTNIAPP *)p2);

  return strcmp( pApp1->acName, pApp2->acName );
}

static int __compSearchTNIApp(const void *p1, const void *p2)
{
  PSZ        pszApp = (PSZ)p1;
  PTNIAPP    pApp   = *((PTNIAPP *)p2);

  return strcmp( pszApp, pApp->acName );
}

static PTNIKEY _tniNewKey(PTNIREAD pReadData, ULONG cbLine, PSZ pszLine)
{
  PTNIKEY    pKey;
  PCHAR      pcName;
  PCHAR      pcVal = strchr( pszLine, '=' );
  ULONG      cbName;
  PCHAR      pcEnd;
  CHAR       acBuf[1024];
  BOOL       fLineList = pcVal == NULL;
  ULONG      ulNumSize, ulNumBase;

  // Get key name.

  if ( fLineList )
  {
    if ( ( *pszLine != '[' ) || ( pszLine[cbLine-1] != ']' ) )
      return NULL;

    // The name in square brackets: key is a list of strings.
    cbName = cbLine - 2;
    pcName = &pszLine[1];
  }
  else
  {
    // Calculate the length of name w/o trailing spaces.
    pcName = pszLine;
    pcEnd = pcVal;
    while( ( pcEnd > (PCHAR)pszLine ) && isspace( *(pcEnd-1) ) )
      pcEnd--;
    cbName = pcEnd - (PCHAR)pszLine;

    // Move pcVal to the beginning of value.
    pcVal++;
    STR_SKIP_SPACES( pcVal );
  }

  // Reset the buffer for collection data of the key.
  pReadData->cbBuf = 0;

  // Collect key's value data.
  do
  {
    if ( fLineList )
    {
      ULONG  cbVal;

      if ( !_fReadStr( pReadData, sizeof(acBuf), acBuf, (PSZ *)&pcVal ) )
        break;

      cbVal = strlen( pcVal );
      if ( ( *((PUSHORT)pcVal) == 0x2F5B /* [/ */ ) &&
           ( pcVal[cbVal - 1] == ']' ) &&
           ( (cbVal - 3) == cbName ) &&
           ( memicmp( &pcVal[2], pcName, cbName ) == 0 ) )
        // End of strings list.
        break;
    }

    if ( ( *pcVal == '(' ) && ( pcVal[2] == ')' ) &&
         ( pcVal[1] == '1' || pcVal[1] == '2' || pcVal[1] == '3' ||
           pcVal[1] == '4' || pcVal[1] == 'X' ) )
    {
      if ( pcVal[1] == 'X' )
      {
        // Prfix is (X) - value is a list of hex 1-byte values
        ulNumBase = 16;
        ulNumSize = 1;
      }
      else
      {
        // Prfix is (N) - value is a list of dec. N-byte values
        ulNumBase = 10;
        ulNumSize = pcVal[1] - '0';
      }

      pcVal += 3;
      STR_SKIP_SPACES( pcVal );
    }
    else if ( isdigit( *pcVal ) )
    {
      // Value is numerical 4-byte value.
      ulNumBase = 10;
      ulNumSize = 4;
    }
    else
      // Value is a string.
      ulNumSize = 0;

    if ( ulNumSize != 0 )
    {
      ULONG    ulNumVal;

      while( *pcVal != '\0' )
      {
        ulNumVal = strtoul( pcVal, &pcEnd, ulNumBase );
        if ( pcVal == pcEnd )
          break;

        _tniInsData( pReadData, ulNumSize, &ulNumVal );

        STR_SKIP_SPACES( pcEnd );
        if ( *pcEnd == '+' )
        {
          if ( !_fReadStr( pReadData, sizeof(acBuf), acBuf, (PSZ *)&pcVal ) )
            break;
        }
        else
          pcVal = pcEnd;
      }
    }
    else
    {
      // Read strings.

      CHAR     chQuote;
      PCHAR    pcEnd;

      while( TRUE )
      {
        pcEnd = NULL;
        chQuote = *pcVal;
        if ( chQuote == '"' || chQuote == '\'' )
        {
          pcVal++;
          pcEnd = strchr( pcVal, chQuote );
        }

        if ( pcEnd == NULL )
        {
          chQuote = '\0';
          pcEnd = strchr( pcVal, '\0' );
        }

        _tniInsData( pReadData, pcEnd - pcVal, pcVal );
        if ( *pcEnd == '\0' )
          break;

        pcVal = pcEnd + 1;
        STR_SKIP_SPACES( pcVal );

        if ( *pcVal == '+' )
        {
          pcVal++;
          STR_SKIP_SPACES( pcVal );

          if ( ( *pcVal == '\0' ) &&
               !_fReadStr( pReadData, sizeof(acBuf), acBuf, (PSZ *)&pcVal ) )
            break;
        }
      }
    }

    if ( fLineList )
    {
      pcVal = NULL;
      _tniInsData( pReadData, 1, &pcVal );
    }
  }
  while( fLineList && ( feof( pReadData->fd ) == 0 ) );

  if ( fLineList )
  {
    // Trailing zero for strings list.
    pcVal = NULL;
    _tniInsData( pReadData, 1, &pcVal );
  }

  // Create TNIKEY object.

  pKey = malloc( sizeof(TNIKEY) + cbName + 1 + pReadData->cbBuf );
  if ( pKey == NULL )
  {
    debugCP( "Not enough memory" );
    return NULL;
  }

  pKey->cbVal = pReadData->cbBuf;

  memcpy( pKey->acData, pcName, cbName );
  pKey->acData[cbName] = '\0';
  cbName++;
  pKey->cbName = cbName;
  memcpy( &pKey->acData[cbName], pReadData->pcBuf, pReadData->cbBuf );

  return pKey;
}


static VOID _tniFreeApp(PTNIAPP pApp)
{
  ULONG      ulIdx;

  if ( pApp->papKey != NULL )
  {
    for( ulIdx = 0; ulIdx < pApp->cKey; ulIdx++ )
      free( pApp->papKey[ulIdx] );

    free( pApp->papKey );
  }

  free( pApp );
}

static PTNIAPP _tniReadApp(PTNIREAD pReadData, ULONG cbName, PCHAR pcName)
{
  PTNIAPP    pApp;
  ULONG      cbLine;
  PSZ        pszLine;
  CHAR       acBuf[1024];
  PTNIKEY    pKey;
  BOOL       fError = FALSE;

  pApp = malloc( sizeof(TNIAPP) + cbName );
  if ( pApp == NULL )
  {
    debugCP( "Not enough memory" );
    return NULL;
  }

  pApp->cKey    = 0;
  pApp->papKey  = NULL;
  memcpy( pApp->acName, pcName, cbName );
  pApp->acName[cbName] = '\0';

  while( _fReadStr( pReadData, sizeof(acBuf), acBuf, &pszLine ) )
  {
    if ( pszLine[0] == '\0' )
      // Empty line.
      continue;

    cbLine = strlen( pszLine );
    if ( ( *((PUSHORT)pszLine) == 0x2F5B /* [/ */ ) &&
         ( pszLine[cbLine - 1] == ']' ) &&
         ( (cbLine - 3) == cbName ) &&
         ( memicmp( &pszLine[2], pcName, cbName ) == 0 ) )
     // End of application block.
     break;

    pKey = _tniNewKey( pReadData, cbLine, pszLine );
    if ( ( pKey != NULL ) &&
         !_insertItem( (PVOID **)&pApp->papKey, &pApp->cKey, pKey ) )
    {
      debugCP( "_insertItem() failed" );
      free( pKey );
      fError = TRUE;
      break;
    }
  }

  if ( fError )
  {
    _tniFreeApp( pApp );
    return NULL;
  }

  qsort( pApp->papKey, pApp->cKey, sizeof(PTNIKEY), __compTNIKey ); 

  return pApp;
}

static LHANDLE APIENTRY tniOpen(LHANDLE hab, PSZ pszFileName)
{
  TNIREAD    stReadData;
  PTNI       pTNI = calloc( 1, sizeof(TNI) );
  CHAR       acBuf[1024];
  ULONG      cbLine;
  PSZ        pszLine;
  PTNIAPP    pApp;
  BOOL       fError = FALSE;

  if ( pTNI == NULL )
  {
    debugCP( "Not enough memory" );
    return NULLHANDLE;
  }

  memset( &stReadData, 0, sizeof(TNIREAD) );

  stReadData.fd = fopen( pszFileName, "r" );
  if ( stReadData.fd == NULL )
  {
    debug( "Cannot open a file: %s", pszFileName );
    free( pTNI );
    return NULLHANDLE;
  }

  while( _fReadStr( &stReadData, sizeof(acBuf), acBuf, &pszLine ) )
  {
    if ( pszLine[0] == '\0' )
      // Empty line.
      continue;

    cbLine = strlen( pszLine ) - 1;

    if ( ( pszLine[0] != '[' ) || ( pszLine[cbLine] != ']' ) )
    {
      debug( "Invalid application open line: %s", acBuf );
      continue;
    }

    pApp = _tniReadApp( &stReadData, cbLine - 1, &pszLine[1] );
    if ( pApp == NULL )
    {
      debugCP( "_tniReadApp() failed" );
      fError = TRUE;
      break;
    }

    if ( !_insertItem( (PVOID **)&pTNI->papApp, &pTNI->cApp, pApp ) )
    {
      debugCP( "_insertItem() failed" );
      _tniFreeApp( pApp );
      fError = TRUE;
      break;
    }
  }

  fclose( stReadData.fd );
  if ( stReadData.pcBuf != NULL )
    free( stReadData.pcBuf );

  if ( fError )
  {
    tniClose( (LHANDLE)pTNI );
    return NULLHANDLE;
  }

  qsort( pTNI->papApp, pTNI->cApp, sizeof(PTNIAPP), __compTNIApp ); 

  _tniDebugPrint( pTNI );

  return (LHANDLE)pTNI;
}

static BOOL APIENTRY tniClose(LHANDLE hObj)
{
  PTNI       pTNI = (PTNI)hObj;
  ULONG      ulIdx;

  if ( pTNI->papApp != NULL )
  {
    for( ulIdx = 0; ulIdx < pTNI->cApp; ulIdx++ )
      _tniFreeApp( pTNI->papApp[ulIdx] );

    free( pTNI->papApp );
  }

  free( pTNI );

  return FALSE;
}

static BOOL APIENTRY tniQuerySize(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                  PULONG pulReqLen)
{
  PTNI       pTNI = (PTNI)hObj;
  ULONG      ulIdx;
  PTNIAPP    *ppApp;
  PTNIKEY    *ppKey;
  ULONG      ulReqLen = 0;

  if ( pszApp == NULL )
  {
    ppApp = pTNI->papApp;
    for( ulIdx = 0; ulIdx < pTNI->cApp; ulIdx++, ppApp++ )
      ulReqLen += strlen( (*ppApp)->acName ) + 1;
    ulReqLen++;
  }
  else
  {
    ppApp = (PTNIAPP *)bsearch( pszApp, pTNI->papApp, pTNI->cApp,
                                sizeof(PTNIAPP), __compSearchTNIApp ); 
    if ( ppApp == NULL )
    {
      *pulReqLen = 0;
      return FALSE;
    }

    if ( pszKey == NULL )
    {
      ppKey = (*ppApp)->papKey;
      for( ulIdx = 0; ulIdx < (*ppApp)->cKey; ulIdx++, ppKey++ )
        ulReqLen += (*ppKey)->cbName;
      ulReqLen++;
    }
    else
    {
      ppKey = (PTNIKEY *)bsearch( pszKey, (*ppApp)->papKey, (*ppApp)->cKey,
                                  sizeof(PTNIKEY), __compSearchTNIKey ); 
      if ( ppKey == NULL )
      {
        *pulReqLen = 0;
        return FALSE;
      }
      ulReqLen = (*ppKey)->cbVal;
    }
  }
  *pulReqLen = ulReqLen;

  return TRUE;
}

static BOOL APIENTRY tniQueryData(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                  PVOID pBuf, PULONG pulBufLen)
{
  PTNI       pTNI = (PTNI)hObj;
  ULONG      ulIdx, cbName;
  ULONG      cbBuf = *pulBufLen;
  PCHAR      pcBuf = (PCHAR)pBuf;
  PTNIAPP    *ppApp, pApp;
  PTNIKEY    *ppKey, pKey;
  BOOL       fSuccess;

  if ( pszApp == NULL )
  {
    ppApp = pTNI->papApp;
    for( ulIdx = 0; ulIdx < pTNI->cApp; ulIdx++, ppApp++ )
    {
      pApp = *ppApp;

      cbName = strlen( pApp->acName ) + 1;
      if ( cbBuf <= cbName )
      {
        memcpy( pcBuf, pApp->acName, cbBuf );
        pcBuf += cbBuf;
        *pulBufLen = pcBuf - (PCHAR)pBuf;
        return FALSE;
      }

      memcpy( pcBuf, pApp->acName, cbName );
      pcBuf += cbName;
      cbBuf -= cbName;
    }

    *pcBuf = '\0';
    *pulBufLen = pcBuf - (PCHAR)pBuf;
    return TRUE;
  }

  ppApp = (PTNIAPP *)bsearch( pszApp, pTNI->papApp, pTNI->cApp,
                              sizeof(PTNIAPP), __compSearchTNIApp ); 
  if ( ppApp == NULL )
  {
    *pulBufLen = 0;
    return FALSE;
  }
  pApp = *ppApp;

  if ( pszKey == NULL )
  {
    ppKey = pApp->papKey;
    for( ulIdx = 0; ulIdx < pApp->cKey; ulIdx++, ppKey++ )
    {
      pKey = *ppKey;

      if ( cbBuf <= pKey->cbName )
      {
        memcpy( pcBuf, pKey->acData, cbBuf );
        pcBuf += cbBuf;
        *pulBufLen = pcBuf - (PCHAR)pBuf;
        return FALSE;
      }

      memcpy( pcBuf, pKey->acData, pKey->cbName );
      pcBuf += pKey->cbName;
      cbBuf -= pKey->cbName;
    }

    *pcBuf = '\0';
    *pulBufLen = pcBuf - (PCHAR)pBuf;
    return TRUE;
  }

  ppKey = (PTNIKEY *)bsearch( pszKey, pApp->papKey, pApp->cKey,
                              sizeof(PTNIKEY), __compSearchTNIKey ); 
  if ( ppKey == NULL )
  {
    *pulBufLen = 0;
    return FALSE;
  }
  pKey = *ppKey;

  fSuccess = pKey->cbVal <= cbBuf;
  if ( fSuccess )
  {
    cbBuf = pKey->cbVal;
    *pulBufLen = cbBuf;
  }

  memcpy( pcBuf, &pKey->acData[pKey->cbName], cbBuf );

  return TRUE;
}

static ULONG APIENTRY tniQueryString(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                     PSZ pszDefault, PVOID pBuffer,
                                     ULONG ulBufferMax)
{
  // It's not clear code but we reproduce the logic of PrfQueryProfileString().

  BOOL       fList = ( pszApp == NULL ) || ( pszKey == NULL );
  ULONG      cbBuffer = ulBufferMax;

  if ( !tniQueryData( hObj, pszApp, pszKey, pBuffer, &cbBuffer ) )
  {
    if ( fList || ( pszDefault == NULL ) )
      return 0;

    strncpy( (PCHAR)pBuffer, pszDefault, ulBufferMax );
    cbBuffer = strlen( pszDefault ) + 1;
    if ( cbBuffer > ulBufferMax )
      cbBuffer = ulBufferMax;
  }

  if ( cbBuffer == ulBufferMax )
    ((PCHAR)pBuffer)[cbBuffer - 1] = '\0';

  return cbBuffer;
}
/*
static LONG APIENTRY tniQueryInt(LHANDLE hObj, PSZ pszApp, PSZ pszKey,
                                 LONG lDefault)
{

}
*/


/*
    Public routines
    ---------------
*/

BOOL iniOpen(PINI pINI, ULONG ulType, PSZ pszFile)
{
  if ( ulType >= ARRAYSIZE(aClass) )
  {
    debug( "Invalid type %u", ulType );
    return FALSE;
  }

  pINI->pClass = &aClass[ulType];
  pINI->hObj   = pINI->pClass->fnOpen( 0, pszFile );

  if ( pINI->hObj == NULLHANDLE )
    debug( "File open failed (type %u): %s", ulType, pszFile );

  return pINI->hObj != NULLHANDLE;
}
