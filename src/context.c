/*
    Context is an object to store sequential data (like disk file). It have
    read position and can occupy the high memory and external temporary files.
    First it attempts to use the high memory.
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include <os2.h>
#include "context.h"
#include "debug.h"               // Should be last.

// Size of memory block.
//#define _CTX_BUF_SIZE            262080
#define _CTX_BUF_SIZE            102400

// Maximum number of blocks for the single context.
//#define _CTX_BUF_MAX_NUM         20
#define _CTX_BUF_MAX_NUM         50

// Context data over (_CTX_BUF_SIZE * _CTX_BUF_MAX_NUM) bytes will be stored on
// the disk (in temporary file).


#define _FILE_IO_BUF_SIZE        (80 * 1024)

#define _FL_ERROR                0x01
#define _FL_FILE                 0x02

typedef struct _CTX {
  PCTXWRITEFILTER      pfnWriteFilter;
  PVOID                pWriteFilterData;

  ULONG                ulFlags;
  ULLONG               ullReadPos;
  ULLONG               ullWritePos;
  ULONG                cCtxBuf;
  PCHAR                *papCtxBuf;

  ULONG                hFile;
  PSZ                  pszFile;
} CTX;


PCTX ctxNew()
{
  PCTX       pCtx = calloc( 1, sizeof(CTX) );

  return pCtx;
}

VOID ctxFree(PCTX pCtx)
{
  if ( pCtx == NULL )
    return;

  while( pCtx->cCtxBuf > 0 )
  {
    pCtx->cCtxBuf--;
    free( pCtx->papCtxBuf[pCtx->cCtxBuf] );
  }
  if ( pCtx->papCtxBuf != NULL )
    free( pCtx->papCtxBuf );

  if ( pCtx->hFile != NULLHANDLE )
  {
    debugDec( "$ctx_files" );
    DosClose( pCtx->hFile );
  }

  if ( pCtx->pszFile != NULL )
  {
    DosDelete( pCtx->pszFile );
    free( pCtx->pszFile );
  }

  free( pCtx );
}

VOID ctxSetWriteFilter(PCTX pCtx, PCTXWRITEFILTER pfnFilter, PVOID pFilterData)
{
  pCtx->pfnWriteFilter    = pfnFilter;
  pCtx->pWriteFilterData  = pFilterData;
}

BOOL ctxWrite(PCTX pCtx, LONG cbData, PVOID pData)
{
  ULONG      cbWrite, ulBufPos, ulRC;
  PCHAR      pcCtxBuf;

  if ( ( pCtx == NULL ) || ( (pCtx->ulFlags & _FL_ERROR) != 0 ) )
    return FALSE;

  if ( pData == NULL )
    return TRUE;

  if ( cbData == -1 )
    cbData = strlen( pData );

  if ( cbData == 0 )
    return TRUE;

  if ( pCtx->pfnWriteFilter != NULL )
  {
    LONG   lRC = pCtx->pfnWriteFilter( cbData, pData, pCtx->pWriteFilterData );

    if ( lRC < 0 )
    {
      pCtx->ulFlags |= _FL_ERROR;
      return FALSE;
    }

    cbData -= lRC;
    pData = &((PCHAR)pData)[lRC];
  }

  if ( cbData == 0 )
    return TRUE;

  // Store data to the memory blocks.

  if ( (pCtx->ulFlags & _FL_FILE) == 0 )
  do
  {
    ulBufPos = pCtx->ullWritePos % _CTX_BUF_SIZE;
    if ( ulBufPos != 0 )
    {
      // We have free space in last allocated block.
      pcCtxBuf = pCtx->papCtxBuf[pCtx->ullWritePos / _CTX_BUF_SIZE];
    }
    else if ( pCtx->cCtxBuf < _CTX_BUF_MAX_NUM )
    {
      // Add a new block.
      pcCtxBuf = malloc( _CTX_BUF_SIZE );

      if ( pcCtxBuf != NULL )
      {
        PCHAR  *papNewList = realloc( pCtx->papCtxBuf,
                                     ( pCtx->cCtxBuf + 1 ) * sizeof(PCHAR *) );

        if ( papNewList == NULL )
        {
          free( pcCtxBuf );
          pcCtxBuf = NULL;
        }
        else
        {
          papNewList[pCtx->cCtxBuf] = pcCtxBuf;
          pCtx->cCtxBuf++;
          pCtx->papCtxBuf = papNewList;
        }
      }  // if ( pcCtxBuf != NULL )

      if ( pcCtxBuf == NULL )
      {                                    // Not enough memory.
        pCtx->ulFlags |= _FL_FILE;
        break;
      }
    }  // else if ( pCtx->cCtxBuf < _CTX_BUF_MAX_NUM )
    else
    {                                      // Number of blocks limit is reached
      pCtx->ulFlags |= _FL_FILE;
      break;
    }

    cbWrite = _CTX_BUF_SIZE - ulBufPos;
    if ( cbWrite > cbData )
      cbWrite = cbData;

    memcpy( &pcCtxBuf[ulBufPos], pData, cbWrite );
    pData = &((PCHAR)pData)[cbWrite];
    cbData -= cbWrite;
    pCtx->ullWritePos += cbWrite;
  }
  while( cbData != 0 );

  // Store data to the file.

  if ( (pCtx->ulFlags & _FL_FILE) != 0 )
  {
    if ( pCtx->hFile == NULLHANDLE )
    {
      // Create an unique file name and open temporary file.

      CHAR             acFName[CCHMAXPATH];
      PSZ              pszTemp = getenv( "TEMP" );
      ULONG            cbFName, ulIdx;

      if ( pCtx->pszFile != NULL )
      {
        DosDelete( pCtx->pszFile );
        free( pCtx->pszFile );
        pCtx->pszFile = NULL;
      }

      if ( pszTemp == NULL )
        pszTemp = ".";
      cbFName = sprintf( acFName, "%s\\", pszTemp );

      // Create a new temporary file.
      while( TRUE )
      {
        for( ulIdx = cbFName; ulIdx < (cbFName + 8); ulIdx++ )
          acFName[ulIdx] = 'A' + (rand() % 26);
        acFName[ulIdx] = '\0';

        ulRC = DosOpenL( acFName, &pCtx->hFile, &ulIdx, 0, FILE_NORMAL,
                         OPEN_ACTION_CREATE_IF_NEW | OPEN_ACTION_FAIL_IF_EXISTS,
                         OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                         OPEN_SHARE_DENYREADWRITE | OPEN_ACCESS_READWRITE, NULL );
        if ( ulRC == NO_ERROR )
        {
          pCtx->pszFile = strdup( acFName );
          debugInc( "$ctx_files" );
          break;
        }

        if ( ulRC != ERROR_OPEN_FAILED )
        {
          debug( "Can't create temporary file: %s , rc = %u", acFName, ulRC );
          pCtx->ulFlags |= _FL_ERROR;
          return FALSE;
        }
      }
    } // if ( pCtx->hFile == NULLHANDLE )
    else
    {
      LONGLONG         llActual;

      ulRC = DosSetFilePtrL( pCtx->hFile, 0, FILE_END, &llActual );
      if ( ulRC != NO_ERROR )
        debug( "DosSetFilePtr(), rc = %u", ulRC );
    }

    ulRC = DosWrite( pCtx->hFile, pData, cbData, &cbWrite );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosWrite(), rc = %u", ulRC );
      pCtx->ulFlags |= _FL_ERROR;
      return FALSE;
    }
    pCtx->ullWritePos += cbWrite;
  }  // if ( (pCtx->ulFlags & _FL_FILE) != 0 )

  return TRUE;
}

ULONG ctxRead(PCTX pCtx, ULONG cbData, PVOID pData, BOOL fPeek)
{
  ULONG      ulBufNum;
  ULONG      ulBufPos, ulRC;
  PCHAR      pcCtxBuf;
  ULONG      cbRead, cbTotalCtxBuf;
  ULLONG     ullReadPos = pCtx->ullReadPos;
  ULLONG     ullLeft = pCtx->ullWritePos - ullReadPos;

  if ( ( ullLeft == 0 ) || ( cbData == 0 ) )
    // Nothing to read.
    return 0;

  if ( ullLeft < cbData )
    cbData = ullLeft;

  if ( fPeek && ( pData == NULL ) )
    return cbData;

  // Read from context memory buffers.

  cbTotalCtxBuf = pCtx->cCtxBuf * _CTX_BUF_SIZE;
  if ( cbTotalCtxBuf > pCtx->ullWritePos )
    cbTotalCtxBuf = pCtx->ullWritePos;

  while( ( cbData != 0 ) && ( ullReadPos < cbTotalCtxBuf ) )
  {
    ulBufNum = ullReadPos / _CTX_BUF_SIZE;
    ulBufPos = ullReadPos % _CTX_BUF_SIZE;

    pcCtxBuf = pCtx->papCtxBuf[ulBufNum];
    cbRead = _CTX_BUF_SIZE - ulBufPos;
    if ( cbRead > cbData )
      cbRead = cbData;

    if ( pData != NULL )
    {
      memcpy( pData, &pcCtxBuf[ulBufPos], cbRead );
      pData = &((PCHAR)pData)[cbRead];
    }
    cbData -= cbRead;
    ullReadPos += cbRead;
  }

  // Read from the temporary file.

  if ( ( cbData != 0 ) && ( ullReadPos >= cbTotalCtxBuf ) &&
       ( (pCtx->ulFlags & _FL_FILE) != 0 ) )
  {
    LONGLONG           llActual;
    ULLONG             ullPos = ullReadPos - cbTotalCtxBuf;

    ulRC = DosSetFilePtrL( pCtx->hFile, *((PLONGLONG)&ullPos), FILE_BEGIN,
                           &llActual );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosSetFilePtr(), rc = %u", ulRC );
      return 0;
    }

    if ( pData != NULL )
    {
      ulRC = DosRead( pCtx->hFile, pData, cbData, &ulBufPos );
      if ( ulRC != NO_ERROR )
      {
        debug( "DosRead(), rc = %u", ulRC );
        return 0;
      }
    }

    ullReadPos += cbData;
  }

  cbRead = ullReadPos - pCtx->ullReadPos;
  if ( !fPeek )
    pCtx->ullReadPos = ullReadPos;

  return cbRead;
}

ULLONG ctxQuerySize(PCTX pCtx)
{
  if ( pCtx == NULL )
  {
    debugCP( "Argument is NULL" );
    return 0;
  }

  return pCtx->ullWritePos;
}

ULLONG ctxQueryAvailForRead(PCTX pCtx)
{
  if ( pCtx == NULL )
  {
    debugCP( "Argument is NULL" );
    return 0;
  }

  return pCtx->ullWritePos - pCtx->ullReadPos;
}

BOOL ctxSetReadPos(PCTX pCtx, ULONG ulOrigin, LLONG llPos)
{
  if ( ulOrigin == CTX_RPO_CURRENT )
    llPos += pCtx->ullReadPos;
  else if ( ulOrigin == CTX_RPO_END )
    llPos += pCtx->ullWritePos;
  // else is ulOrigin == CTX_RPO_BEGIN

  if ( llPos > pCtx->ullWritePos )
    pCtx->ullReadPos = pCtx->ullWritePos;
  else
    pCtx->ullReadPos = (ULLONG)llPos;

  return TRUE;
}

#if 0
// deprecated
BOOL ctxTruncate(PCTX pCtx, LLONG llNewSize)
{
  ULONG      cCtxBuf, cbTotalCtxBuf;
  PCHAR      *papNewList;
  ULONG      ulRC;

  if ( llNewSize < 0 )
    llNewSize = pCtx->ullWritePos - llNewSize;

  if ( ( llNewSize < 0 ) || ( llNewSize >= pCtx->ullWritePos ) )
    return FALSE;

  // Remove or truncate the temporary file.

  cbTotalCtxBuf = pCtx->cCtxBuf * _CTX_BUF_SIZE;
  if ( cbTotalCtxBuf > pCtx->ullWritePos )
    cbTotalCtxBuf = pCtx->ullWritePos;
  if ( pCtx->ullWritePos < cbTotalCtxBuf )
  {
    // Remove file.

    if ( pCtx->hFile != NULLHANDLE )
    {
      debugDec( "$ctx_files" );
      DosClose( pCtx->hFile );
      pCtx->hFile = NULLHANDLE;
    }

    if ( pCtx->pszFile != NULL )
    {
      DosDelete( pCtx->pszFile );
      free( pCtx->pszFile );
      pCtx->pszFile = NULL;
    }
  }
  else if ( (pCtx->ulFlags & _FL_FILE) != 0 )
  {
    // Truncate file.

    ULLONG   ullFSize = pCtx->ullWritePos - cbTotalCtxBuf;

    ulRC = DosSetFileSizeL( pCtx->hFile, *((PLONGLONG)&ullFSize) );
    if ( ulRC != NO_ERROR )
      debug( "DosSetFileSizeL(), rc = %u", ulRC );
  }

  // Free buffers.

  cCtxBuf = ( llNewSize + (_CTX_BUF_SIZE - 1) ) / _CTX_BUF_SIZE;
  while( pCtx->cCtxBuf > cCtxBuf )
  {
    pCtx->cCtxBuf--;
    free( pCtx->papCtxBuf[pCtx->cCtxBuf] );
  }

  // Collapse list of buffers.
  papNewList = realloc( pCtx->papCtxBuf, pCtx->cCtxBuf * sizeof(PCHAR *) );
  if ( papNewList != NULL )
    pCtx->papCtxBuf = papNewList;

  // Set a new write position.
  pCtx->ullWritePos = llNewSize;
  if ( pCtx->ullReadPos > llNewSize )
    pCtx->ullReadPos = llNewSize;

  return TRUE;
}
#endif

BOOL ctxWriteFmtV(PCTX pCtx, BOOL fCRLF, PSZ pszFmt, va_list arglist)
{
  int        iRC;
  CHAR       acBuf[2048];

  iRC = _vsnprintf( acBuf, sizeof(acBuf) - 2, pszFmt, arglist ); 
  if ( iRC < 0 )
    return FALSE;

  if ( fCRLF )
  {
    acBuf[iRC++] = 0x0D;
    acBuf[iRC++] = 0x0A;
/*    *((PUSHORT)&acBuf[iRC]) = (USHORT)0x0A0D;
    iRC += 2;*/
  }

  return ctxWrite( pCtx, iRC, acBuf );
}

BOOL ctxWriteFmt(PCTX pCtx, PSZ pszFmt, ...)
{
  va_list    arglist;
  BOOL       fRC;

  va_start( arglist, pszFmt ); 
  fRC = ctxWriteFmtV( pCtx, FALSE, pszFmt, arglist );
  va_end( arglist );

  return fRC;
}

BOOL ctxWriteFmtLn(PCTX pCtx, PSZ pszFmt, ...)
{
  va_list    arglist;
  BOOL       fRC;

  va_start( arglist, pszFmt ); 
  fRC = ctxWriteFmtV( pCtx, TRUE, pszFmt, arglist );
  va_end( arglist );

  return fRC;
}

BOOL ctxWriteStrLn(PCTX pCtx, PSZ pszStr)
{
  return ctxWrite( pCtx, -1, pszStr ) && ctxWrite( pCtx, 2, "\r\n" );
}

BOOL ctxWriteCtx(PCTX pCtx, PCTX pCtxSrc, ULLONG ullMaxBytes)
{
#define _CTX_SEND_BUF           (1024*65)
  PVOID      pBuf = malloc( _CTX_SEND_BUF );
  ULONG      ulActual;

  if ( pBuf == NULL )
    return FALSE;

  do
  {
    ulActual = ctxRead( pCtxSrc, MIN(_CTX_SEND_BUF, ullMaxBytes), pBuf,
                        FALSE );

    if ( !ctxWrite( pCtx, ulActual, pBuf ) )
    {
      free( pBuf );
      return FALSE;
    }

    ullMaxBytes -= ulActual;
  }
  while( ulActual == _CTX_SEND_BUF );

  free( pBuf );
  return TRUE;
}

PCTX ctxNewFromTemplate(LONG cbText, PCHAR pcText,
                        BOOL (*fnSubset)(PCTX pCtx, ULONG cbKey, PSZ pszKey,
                                         PVOID pData),
                        PVOID pData)
{
  PCTX       pCtx;
  PCHAR      pcEnd = &pcText[cbText];
  PCHAR      pcChunkEnd, pcKey;
  PCHAR      pcScan;
  ULONG      cbKey;
  CHAR       acKey[256];
  BOOL       fEscape;
  CHAR       chKey;

  if ( pcText == NULL )
    return NULL;

  pCtx = ctxNew();
  if ( pCtx == NULL )
    return NULL;

  if ( cbText == -1 )
    cbText = strlen( pcText );
  pcEnd = &pcText[cbText];

  while( pcText < pcEnd )
  {
    // Serarch "$(a". Where 'a' is alphabetic character.
    pcScan = pcText;
    while( TRUE )
    {
      pcKey = memchr( pcScan, '$', pcEnd - pcScan );
      if ( ( pcKey == NULL ) ||
           ( ((pcKey+3) < pcEnd) && (pcKey[1] == '(') && isalnum(pcKey[2]) ) )
        break;
      pcScan++;
    }

    cbKey = 0;
    if ( pcKey == NULL )
    {
      pcChunkEnd = pcEnd;
      pcKey = pcEnd;
    }
    else
    {
      // pcKey points to '$'. Copy (unescape) content from $(...) to the buffer
      // acKey.

      pcChunkEnd = pcKey;
      pcKey += 2;
      fEscape = FALSE;
      while( TRUE )
      {
        if ( ( pcKey == pcEnd ) || ( cbKey == ( sizeof(acKey) - 2 ) ) )
        {
          pcChunkEnd = pcKey;
          cbKey = 0;
          break;
        }

        chKey = *pcKey;
        if ( !fEscape )
        {
          if ( chKey == ')' )
          {
            pcKey++;
            acKey[cbKey]      = '\0';
            acKey[cbKey + 1]  = '\0';
            break;
          }

          if ( chKey == '\\' )
          {
            fEscape = TRUE;
            pcKey++;
            continue;
          }

          if ( chKey == ',' )
            chKey = '\0';
        }
        else
        {
          switch( chKey )
          {
            case 't': chKey = '\t'; break;
            case 'r': chKey = '\r'; break;
            case 'n': chKey = '\n'; break;
          }

          fEscape = FALSE;
        }

        acKey[cbKey] = chKey;
        cbKey++;
        pcKey++;
      }
    } // if ( pcKey != NULL )

    // pcText ... pcChunkEnd  - text before '$(',
    // pcKey ... pcEnd        - remaining text after ')',
    // acKey[]                - unescaped content from $(...), length - cbKey.

         // Copy text before '$(' to the output context.
    if ( !ctxWrite( pCtx, pcChunkEnd - pcText, pcText ) ||
         // Get key value from user.
         ( ( cbKey != 0 ) && !fnSubset( pCtx, cbKey, acKey, pData ) ) )
    {
      ctxFree( pCtx );
      return NULL;
    }

    // Next chunk...
    pcText = pcKey;
  }

  return pCtx;
}

ULONG ctxFileWrite(PCTX pCtx, HFILE hFile)
{
  PCHAR      pcBuf;
  ULONG      cbBuf, ulActual;
  ULONG      ulRC;

  ulRC = DosAllocMem( (PVOID *)&pcBuf, _FILE_IO_BUF_SIZE,
                      PAG_COMMIT | PAG_READ | PAG_WRITE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosAllocMem(), rc = %u", ulRC );
    return ulRC;
  }

  do
  {
    cbBuf = ctxRead( pCtx, _FILE_IO_BUF_SIZE, pcBuf, TRUE );
    if ( cbBuf == 0 )
      break;

    ulRC = DosWrite( hFile, pcBuf, cbBuf, &ulActual );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosWrite(), rc = %lu", ulRC );
      break;
    }

    if ( !ctxSetReadPos( pCtx, CTX_RPO_CURRENT, ulActual ) )
      debugCP( "ctxSetReadPos() failed" );
  }
  while( ulActual == cbBuf );

  DosFreeMem( pcBuf );

  return ulRC;
}

ULONG ctxFileRead(PCTX pCtx, HFILE hFile)
{
  PCHAR      pcBuf;
  ULONG      ulActual;
  ULONG      ulRC;

  ulRC = DosAllocMem( (PVOID *)&pcBuf, _FILE_IO_BUF_SIZE,
                      PAG_COMMIT | PAG_READ | PAG_WRITE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosAllocMem(), rc = %u", ulRC );
    return ulRC;
  }

  do
  {
    ulRC = DosRead( hFile, pcBuf, _FILE_IO_BUF_SIZE, &ulActual );
    if ( ulRC != NO_ERROR )
      break;

    ulRC = ctxWrite( pCtx, ulActual, pcBuf ) ? NO_ERROR : (~0);
  }
  while( ( ulRC == NO_ERROR ) && ( ulActual == _FILE_IO_BUF_SIZE ) );

  DosFreeMem( pcBuf );

  if ( ulRC != NO_ERROR )
    debug( "DosWrite(), rc = %lu", ulRC );

  return ulRC;
}
