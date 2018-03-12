/*
  Different helpers.
*/

#include <string.h>
#include <ctype.h>
#include <errno.h>
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#include <os2.h>
#include <uconv.h>
#ifdef __WATCOMC__
#include <types.h>
#endif
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#include "utils.h"
#include <stdio.h>
#include "debug.h"               // Should be last.

// utilBufCutWord(PULONG pcbText, PCHAR *ppcText,
//                PULONG pcbWord, PCHAR *ppcWord)
//
// Locates first word from the string *ppcText (length *pcbText) and places
// pointer to the finded word to ppcWord and length of this word in pcbWord.
// On return *pcbText contains pointer to the first character after founded
// word and *ppcText left length of the text.
// *pcbWord == 0 when no more words in the input text.

BOOL utilBufCutWord(PULONG pcbText, PCHAR *ppcText,
                    PULONG pcbWord, PCHAR *ppcWord)
{
  ULONG            cbText = *pcbText;
  PCHAR            pcText = *ppcText;
  PCHAR            pcWord;

  BUF_SKIP_SPACES( cbText, pcText );
  pcWord = pcText;
  BUF_MOVE_TO_SPACE( cbText, pcText );

  *pcbText = cbText;
  *ppcText = pcText;
  *pcbWord = pcText - pcWord;
  *ppcWord = pcWord;

  return pcText != pcWord;
}

// LONG utilStrWordIndex(PSZ pszList, LONG cbWord, PCHAR pcWord)
//
// Returns index of word pointed by pcWord (and length equals cbWord) in the
// list pszList. The list must contain the words separated by a space.
// When cbWord < 0 the paramether pcWord is treated as zero-terminated string.
// The function returns -1 if the word is not found.

LONG utilStrWordIndex(PSZ pszList, LONG cbWord, PCHAR pcWord)
{
  ULONG      ulIdx;
  ULONG      cbList;
  ULONG      cbScanWord;
  PCHAR      pcScanWord;

  if ( pszList == NULL || pcWord == NULL || cbWord == 0 )
    return -1;

  if ( cbWord < 0 )
    cbWord = strlen( pcWord );

  BUF_SKIP_SPACES( cbWord, pcWord );
  BUF_RTRIM( cbWord, pcWord );
  if ( cbWord == 0 )
    return -1;

  cbList = strlen( pszList );
  for( ulIdx = 0; ; ulIdx++ )
  {
    utilBufCutWord( &cbList, (PCHAR *)&pszList, &cbScanWord, &pcScanWord );
    if ( cbScanWord == 0 )
      // All words in the list was checked.
      break;

    if ( ( cbScanWord == cbWord ) &&
         ( memicmp( pcScanWord, pcWord, cbScanWord ) == 0 ) )
      // Word found - return list index of word.
      return ulIdx;
  }

  return -1;
}

// Returns TRUE if word list pszList contains all words from list pszWords.
BOOL utilStrIsWordListContains(PSZ pszList, PSZ pszWords)
{
  ULONG      cbWords = STR_LEN( pszWords );
  ULONG      cbWord;
  PCHAR      pcWord;

  while( utilBufCutWord( &cbWords, (PCHAR *)&pszWords, &cbWord, &pcWord) )
  {
    if ( utilStrWordIndex( pszList, (LONG)cbWord, pcWord ) == -1 )
      return FALSE;
  }

  return TRUE;
}

BOOL utilStrIsListEqual(PSZ pszList1, PSZ pszList2)
{
  return utilStrIsWordListContains( pszList1, pszList2 ) &&
         utilStrIsWordListContains( pszList2, pszList1 );
}

BOOL utilStrCutWord(PSZ *ppszText, PSZ *ppszWord)
{
  PSZ        pszText = *ppszText;

  STR_SKIP_SPACES( pszText );

  *ppszWord = pszText;
  if ( *pszText == '\0' )
  {
    *ppszText = pszText;
    return FALSE;
  }

  STR_MOVE_TO_SPACE( pszText );
/*  while( (*pszText != '\0') && !isspace( *pszText ) && (*pszText != '(') &&
         (*pszText != ')') )
    pszText++;*/

  if ( *pszText != '\0' )
  {
    *pszText = '\0';
    pszText++;
  }

  *ppszText = pszText;
  return TRUE;
}

BOOL utilStrCutComp(PSZ *ppszText, PSZ *ppszWord)
{
  PSZ        pszText = *ppszText;

  STR_SKIP_SPACES( pszText );

  if ( *pszText == '"' )
  {
    PCHAR    pcDst;

    pszText++;
    *ppszWord = pszText;
    pcDst = pszText;
    while( ( *pszText != '"' ) && ( *pszText != '\0' ) )
    {
      if ( ( *pszText == '\\' ) && ( *(pszText + 1) != '\0' ) )
        pszText++;

      if ( pcDst != (PCHAR)pszText )
        *pcDst = *pszText;

      pszText++;
      pcDst++;
    }

    if ( *pszText != '\0' )
      pszText++;
    *pcDst = '\0';

    *ppszText = pszText;

    return TRUE;
  }

  return utilStrCutWord( ppszText, ppszWord );
}

BOOL utilStrCutList(PSZ *ppszText, PSZ *ppszWord)
{
  PSZ        pszText = *ppszText;

  STR_SKIP_SPACES( pszText );

  if ( *pszText == '(' )
  {
    ULONG    cLBracket = 0;

    pszText++;
    *ppszWord = pszText;
    while( *pszText != '\0' )
    {
      if ( *pszText == ')' )
      {
        if ( cLBracket == 0 )
        {
          *pszText = '\0';
          pszText++;
          break;
        }
        cLBracket--;
      }
      else if ( *pszText == '(' )
        cLBracket++;

      pszText++;
    }

    *ppszText = pszText;

    return TRUE;
  }

  return utilStrCutWord( ppszText, ppszWord );
}

BOOL utilStrCutVDir(PSZ *ppszText, PSZ *ppszVDir)
{
  PSZ        pszText = *ppszText;
  PSZ        pszVDir;

  while( *pszText == '/' )
    pszText++;
  pszVDir = pszText;

  while( *pszText != '\0' )
  {
    pszText++;

    if ( *pszText == '/' )
    {
      *pszText = '\0';
      *ppszText = pszText + 1;
      *ppszVDir = pszVDir;
      return TRUE;
    }
  }

  *ppszText = pszText;
  *ppszVDir = pszVDir;
  return *pszVDir != '\0';
}

PSZ utilStrGetCompNew(PSZ *ppszText)
{
  PSZ        pszText  = *ppszText;
  PCHAR      pcDst    = NULL;
  ULONG      cbDst    = 0;

  STR_SKIP_SPACES( pszText );

  if ( *pszText == '"' )
  {
    pszText++;
    while( ( *pszText != '"' ) && ( *pszText != '\0' ) )
    {
      if ( ( *pszText == '\\' ) && ( *(pszText + 1) != '\0' ) )
        pszText++;

      if ( (cbDst & 0x0F) == 0 )
      {
        PCHAR  pcNew = realloc( pcDst, cbDst + 0x10 + 1 /* ZERO */ );

        if ( pcNew == NULL )
        {
          free( pcDst );
          return NULL;
        }
        pcDst = pcNew;
      }

      pcDst[cbDst] = *pszText;
      cbDst++;

      pszText++;
    }

    if ( *pszText != '\0' )      // Skip last '"'.
      pszText++;

    if ( pcDst != NULL )
    {
      // Collapse memory block.
      if ( (cbDst & 0x10) != 0 )
      {
        PCHAR  pcNew = realloc( pcDst, cbDst + 1 );

        if ( pcNew != NULL )
          pcDst = pcNew;
      }

      pcDst[cbDst] = '\0';
    }
  }
  else
  {
    PCHAR    pcWordStart = pszText;

    STR_MOVE_TO_SPACE( pszText );
    cbDst = (PCHAR)pszText - pcWordStart;

    if ( cbDst != 0 )
    {
      pcDst = malloc( cbDst + 1 );
      if ( pcDst == NULL )
        return NULL;

      memcpy( pcDst, pcWordStart, cbDst );
      pcDst[cbDst] = '\0';
    }
  }

  *ppszText = pszText;

  return pcDst;
}

BOOL utilStrSkipComp(PSZ *ppszText)
{
  PSZ        pszText  = *ppszText;
  BOOL       fMoved;

  STR_SKIP_SPACES( pszText );

  if ( *pszText == '\0' )
    return FALSE;

  if ( *pszText == '"' )
  {
    pszText++;
    while( ( *pszText != '"' ) && ( *pszText != '\0' ) )
    {
      if ( ( *pszText == '\\' ) && ( *(pszText + 1) != '\0' ) )
        pszText++;

      pszText++;
    }

    if ( *pszText != '\0' )      // Skip last <">.
      pszText++;
  }
  else
    STR_MOVE_TO_SPACE( pszText );

  fMoved = *ppszText != pszText;
  if ( fMoved )
    *ppszText = pszText;

  return fMoved;
}

BOOL utilStrSkipAtom(PSZ *ppszText)
{
  PSZ        pszText = *ppszText;
  BOOL       fMoved;

  if ( *pszText == '\0' )
    return FALSE;

  while( ( *pszText > 31 ) && ( *pszText != 127 ) &&
         ( strchr( " ()<>@,;:\\\".[]", *pszText ) == NULL ) )
    pszText++;

  fMoved = *ppszText != pszText;
  if ( fMoved )
    *ppszText = pszText;

  return fMoved;
}

BOOL utilStrSkipWordAtom(PSZ *ppszText)
{
  PSZ        pszText = *ppszText;

  return *pszText == '"' ? utilStrSkipComp( ppszText )
                         : utilStrSkipAtom( ppszText );
}

BOOL utilStrToBytes(PSZ pszVal, PULLONG pullBytes, ULONG ulDefaultUnits)
{
  ULLONG     ullBytes;
  PCHAR      pcEnd;

  STR_SKIP_SPACES( pszVal );
  if ( *pszVal == '-' )
    return FALSE;
  ullBytes = strtoull( pszVal, &pcEnd, 10 );
  if ( (PCHAR)pszVal == pcEnd )
    return FALSE;

  STR_SKIP_SPACES( pcEnd );

  switch( *pcEnd != '\0'
            ? utilStrWordIndex( "BYTE BYTES B KB K MB M GB G TB T", -1, pcEnd )
            : ulDefaultUnits )
  {
    case 0:
    case 1:
    case 2:  break;
    case 3:
    case 4:  ullBytes *= 1024;                        break;
    case 5:
    case 6:  ullBytes *= (1024 * 1024);               break;
    case 7:
    case 8:  ullBytes *= (1024 * 1024 * 1024);        break;
    case 9:
    case 10: ullBytes *= (1024ULL * 1024ULL *
                          1024ULL * 1024ULL);         break;
    default: return FALSE;
  }

  *pullBytes = ullBytes;
  return TRUE;
}

BOOL utilStrToIMAPTime(PSZ pszTime, time_t *pT)
{
  // Input string like: 17-Jul-1996 02:44:25 -0700
  struct tm          stTM;
  LONG               lOffsSine = 60;
  ULONG              ulOffs = 0;

  stTM.tm_mday = strtoul( pszTime, (PCHAR *)&pszTime, 10 ); 
  if ( ( *pszTime != '-' ) || ( (ULONG)stTM.tm_mday > 31 ) )
    return FALSE;
  pszTime++;

  stTM.tm_mon = utilStrWordIndex( "Jan Feb Mar Apr May Jun Jul Aug Sep Oct "
                                  "Nov Dec", 3, pszTime );
  if ( ( stTM.tm_mon == -1 ) || ( pszTime[3] != '-' ) )
    return FALSE;

  pszTime += 4;
  stTM.tm_year = strtoul( pszTime, (PCHAR *)&pszTime, 10 ) - 1900;
  if ( *pszTime != ' ' )
    return FALSE;

  stTM.tm_hour = strtoul( pszTime, (PCHAR *)&pszTime, 10 ); 
  if ( ( *pszTime != ':' ) || ( (ULONG)stTM.tm_hour > 24 ) )
    return FALSE;
  pszTime++;

  stTM.tm_min = strtoul( pszTime, (PCHAR *)&pszTime, 10 ); 
  if ( ( *pszTime != ':' ) || ( (ULONG)stTM.tm_min > 60 ) )
    return FALSE;
  pszTime++;

  stTM.tm_sec = strtoul( pszTime, (PCHAR *)&pszTime, 10 ); 
  if ( (ULONG)stTM.tm_sec > 60 )
    return FALSE;

  STR_SKIP_SPACES( pszTime );
  if ( *pszTime != '\0' )
  {
    if ( *pszTime == '-' )
      lOffsSine = -60;
    else if ( *pszTime != '+' )
      return FALSE;

    pszTime++;
    ulOffs = strtoul( pszTime, (PCHAR *)&pszTime, 10 ); 
    ulOffs = ((ulOffs / 100) * 60) + (ulOffs % 100);
  }

  tzset();
  *pT = mktime( &stTM ) - ( ulOffs * lOffsSine ) - timezone;

  return TRUE;
}

BOOL utilIMAPIsMatch(PSZ pszStr, PSZ pszPtrn, PSZ *ppszRem)
{
  ULONG         cbStr = strlen( pszStr );
  ULONG         cbPtrn = strlen( pszPtrn );
  PCHAR		pcStarStr = NULL;
  ULONG		cbStarStr = 0;
  PCHAR		pcStartPtrn = NULL;
  ULONG		cbStartPtrn = 0;
  CHAR		chStr, chPtrn;
  BOOL          fProc;

  if ( cbStr == 0 && cbPtrn == 0 )
    return TRUE;

  while( cbStr != 0 )
  {
    chStr = toupper( *pszStr );

    if ( cbPtrn != 0 )
    {
      chPtrn = toupper( *pszPtrn );

      if ( chPtrn == chStr )
      {
        pszPtrn++;
        cbPtrn--;
        pszStr++;
        cbStr--;
        continue;
      }

      if ( ( chPtrn == '*' ) || ( chPtrn == '%' ) )
      {
        // Skip all continuous '*' / '%'.
        do
        {
          cbPtrn--;
          fProc = chPtrn == '%';
          if ( !fProc && cbPtrn == 0 )     // If end with '*' / '%', its match.
            return TRUE;
          pszPtrn++;
        }
        while( ( *pszPtrn == '*' ) || ( *pszPtrn == '%' ) );

        pcStartPtrn = pszPtrn;   // Store '*' pos. for string and pattern.
        cbStartPtrn = cbPtrn;
        pcStarStr = pszStr;
        cbStarStr = cbStr;
        continue;
      }
    }

    if ( ( cbPtrn == 0 || chPtrn != chStr ) && ( pcStartPtrn != NULL ) &&
         ( !fProc || chStr != '/' ) )
    {
      pcStarStr++;		// Skip non-match char of string, regard it
      cbStarStr--;		// matched in '*'.
      pszStr = pcStarStr;
      cbStr = cbStarStr;

      pszPtrn = pcStartPtrn;	// Pattern backtrace to later char of '*'/'%'.
      cbPtrn = cbStartPtrn;
    }
    else
    {
      if ( ppszRem != NULL )
        *ppszRem = ( pcStartPtrn != NULL ) && fProc && ( cbPtrn == 0 )
                     ? pszStr : NULL;

      return FALSE;
    }
  }

  // Check if later part of ptrn are all '*'

  while( cbPtrn != 0 )
  {
    if ( ( *pszPtrn != '*' ) && ( *pszPtrn != '%' ) )
      return FALSE;

    pszPtrn++;
    cbPtrn--;
  }

  return TRUE;
}

// BOOL utilStrToInAddrPort(PSZ pszStr, PULONG pulAddr, PUSHORT pusPort,
//                          BOOL fAnyIP, USHORT usDefaultPort)
//
// Parses the string pointed by pszStr and writes ip-address to pulAddr and
// port to pusPort. The input string format is: [n.n.n.n|*|any|all][:port] .
// Values "0.0.0.0", "*", "any", "all" for ip-address allowed only when fAnyIP
// is TRUE, result ip will be 0. If port is not specified in string
// usDefaultPort will be used.
//
BOOL utilStrToInAddrPort(PSZ pszStr, PULONG pulAddr, PUSHORT pusPort,
                         BOOL fAnyIP, USHORT usDefaultPort)
{
  PCHAR      pcIPEnd;
  CHAR       szIP[16];
  LONG       cbStr;

  STR_SKIP_SPACES( pszStr );
  pcIPEnd = strchr( pszStr, ':' );

  if ( pcIPEnd != NULL )
  {
    PCHAR    pcEnd;
    PCHAR    pcBegin = &pcIPEnd[1];
    LONG     lPort = strtol( pcBegin, &pcEnd, 10 );

    cbStr = pcIPEnd - (PCHAR)pszStr;
    if ( ( cbStr >= sizeof(szIP) ) || ( pcEnd == pcBegin ) || ( lPort <= 0 ) ||
         ( lPort > 0xFFFF ) )
      return FALSE;

    *pusPort = lPort;
    memcpy( szIP, pszStr, cbStr );
    szIP[cbStr] = '\0';
    pszStr = szIP;
  }
  else
  {
    *pusPort = usDefaultPort;
    cbStr = -1;
  }

  if ( utilStrWordIndex( "* ANY ALL", cbStr, (PCHAR)pszStr ) != -1 )
  {
    *pulAddr = 0;
    return fAnyIP;
  }

  *pulAddr = inet_addr( pszStr );

  return ( *pulAddr != ((ULONG)(-1)) );
}

#if 0
// No need any more.
PCHAR utilStrKeysSubsetNew(LONG cbText, PCHAR pcText,
                           ULONG (*fnSubset)(ULONG cbKey, PSZ pszKey,
                                             ULONG cbVal, PCHAR pcVal,
                                             PVOID pData),
                           PVOID pData, PULONG pcbResult)
{
  PCHAR      pcEnd = &pcText[cbText];
  PCHAR      pcChunkEnd, pcKey;
  PCHAR      pcScan;
  ULONG      cbKey;
  CHAR       acKey[256];
  BOOL       fEscape;
  ULONG      cbOutput = 0;
  PCHAR      pcOutput = NULL;
  ULONG      ulOutputPos = 0;
  ULONG      cbValue;
  PCHAR      pcNew;
  CHAR       chKey;

  if ( pcText == NULL )
  {
    if ( pcbResult != NULL )
      *pcbResult = 0;

    return NULL;
  }

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

    // Expand output buffer if need.
    cbText = pcChunkEnd - pcText;
    if ( ( cbText + ulOutputPos + 512 ) >= cbOutput )
    {
      pcNew = realloc( pcOutput, cbOutput + cbText + 4096 + 1 );

      if ( pcNew == NULL )
      {
        if ( pcOutput != NULL )
          free( pcOutput );
        return NULL;
      }
      pcOutput = pcNew;
      cbOutput += 4096;
    }

    // Copy text before '$(' to the output buffer.
    memcpy( &pcOutput[ulOutputPos], pcText, cbText );
    ulOutputPos += cbText;

    // Get key value from user.
    if ( cbKey != 0 )
    {
      cbValue = fnSubset( cbKey, acKey,
                          cbOutput - ulOutputPos, &pcOutput[ulOutputPos],
                          pData );
      ulOutputPos += cbValue;
      pcOutput[ulOutputPos] = '\0';
    }

    // Next chunk...
    pcText = pcKey;
  }

  // Collapse buffer.
  pcNew = realloc( pcOutput, ulOutputPos + 1 );
  if ( pcNew != NULL )
    pcOutput = pcNew;

  if ( pcbResult != NULL )
    *pcbResult = ulOutputPos;

  return pcOutput;
}
#endif

VOID utilRndAlnum(ULONG cbBuf, PCHAR pcBuf)
{
  static const CHAR    aNameChr[36] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  while( cbBuf > 0 )
  {
    *pcBuf = aNameChr[rand() % sizeof(aNameChr)];
    pcBuf++;
    cbBuf--;
  }
}

BOOL utilIConvChunk(iconv_t ic, PULONG pcbDst, PCHAR *ppcDst,
                    PULONG pcbSrc, PCHAR *ppcSrc)
{
  BOOL       fError = FALSE;
  size_t     rc;

  if ( ic == ((iconv_t)(-1)) )
    return FALSE;

  while( *pcbSrc > 0 )
  {
    rc = iconv( ic, (const char **)ppcSrc, (size_t *)pcbSrc,
                ppcDst, (size_t *)pcbDst );
    if ( rc == (size_t)-1 )
    {
      rc = errno;
      if ( rc == EILSEQ )
      {
        // Try to skip invalid character.
        (*ppcSrc)++;
        (*pcbSrc)--;
        continue;
      }
//      debugCP( "iconv() failed" );
      fError = TRUE;
      break;
    }
  }

  if ( !fError )
    iconv( ic, NULL, 0, ppcDst, (size_t *)pcbDst );

  return !fError;
}

PSZ utilIConv(iconv_t ic, LONG cbStrIn, PCHAR pcStrIn, PULONG pcbStrOut)
{
  ULONG      cbStrOut;
  PCHAR      pcStrOut, pcDst;
  size_t     rc;
  BOOL       fError = FALSE;

  if ( ic == ((iconv_t)(-1)) )
    return NULL;

  if ( cbStrIn == -1 )
    cbStrIn = strlen( pcStrIn );

  cbStrOut = ( ( cbStrIn > 4 ? cbStrIn : 4 ) + 2 ) * 2;
  pcStrOut = malloc( cbStrOut );
  if ( pcStrOut == NULL )
  {
    debugCP( "Not enough memory" );
    return NULL;
  }

  pcDst = pcStrOut;
  while( cbStrIn > 0 )
  {
    rc = iconv( ic, (const char **)&pcStrIn, (size_t *)&cbStrIn,
                &pcDst, (size_t *)&cbStrOut );
    if ( rc == (size_t)-1 )
    {
      if ( errno == EILSEQ )
      {
        // Try to skip invalid character.
        pcStrIn++;
        cbStrIn--;
        continue;
      }

//      debugCP( "iconv() failed" );
      fError = TRUE;
      break;
    }
  }

  if ( !fError )
    iconv( ic, NULL, 0, &pcDst, (size_t *)&cbStrOut );

  if ( fError )
  {
    free( pcStrOut );
    return NULL;
  }

  rc = pcDst - pcStrOut;

  // Write trailing ZERO (2 bytes).
  if ( cbStrOut >= 2 )
  {
    *((PUSHORT)pcDst) = 0;
    pcDst += 2;
  }
  else
  {
//    fError = TRUE;               // The destination buffer overflow.
    if ( cbStrOut == 1 )
    {
      *pcDst = 0;
      pcDst++;
    }
  }

  pcDst = realloc( pcStrOut, (pcDst - pcStrOut) );
  if ( pcDst != NULL )
    pcStrOut = pcDst;

  if ( pcbStrOut != NULL )
    *pcbStrOut = rc;

  return pcStrOut;
}

// Converts given string pszStr in charset pszCharset to uppercase and UTF-16
// charset. Resuls should be destroyed with free().
PSZ utilStrToUTF16Upper(PSZ pszStr, PSZ pszCharset)
{
  iconv_t    ic;

  ic = iconv_open( "UTF-16LE", pszCharset );
  if ( ic == ((iconv_t)(-1)) )
  {
    debug( "iconv_open(\"%s\",\"%s\") failed", "UTF-16LE", pszCharset );
    return NULL;
  }

  pszStr = utilIConv( ic, -1, pszStr, NULL );
  iconv_close( ic );

  if ( pszStr == NULL )
    debug( "utilIConv() failed" );
  else
    UniStrupr( (UniChar *)pszStr );

  return pszStr;
}

ULONG utilQueryStackSpace()
{
  PTIB       tib;
  PPIB       pib;
  ULONG      ulRC;

  ulRC = DosGetInfoBlocks( &tib, &pib );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosGetInfoBlocks(), rc = %u", ulRC );
    return 0;
  }

  return (PCHAR)&pib - (PCHAR)tib->tib_pstack;
}


// BOOL utilStrToNewNumSet(PSZ pszText, PUTILRANGE *ppRange)
// ---------------------------------------------------------

static BOOL _strToRange(PSZ *ppszText, PUTILRANGE pRange, PBOOL pfToAsterisk)
{
  PSZ        pszText = *ppszText;
  PCHAR      pcEnd;

//  if ( *((PUSHORT)pszText) == 0x002A /* "*\0" */ ||
//       *((PUSHORT)pszText) == 0x2C2A /* "*,"  */ )
  if ( *pszText == '*' )
  {
    pRange->ulFrom  = 1;
    pRange->ulTo    = ULONG_MAX;
    pcEnd = &pszText[1];
  }
  else
  {
    if ( !isdigit( *pszText ) )
      return FALSE;
    pRange->ulFrom = strtoul( pszText, &pcEnd, 10 );
    if ( ( pszText == (PSZ)pcEnd ) || ( pRange->ulFrom == 0 ) )
      return FALSE;

    if ( *pcEnd == ':' )
    {
      pszText = pcEnd + 1;
      if ( *pszText == '*' )
      {
        pRange->ulTo = ULONG_MAX;
        pcEnd = &pszText[1];
        *pfToAsterisk = TRUE;
      }
      else
      {
        if ( !isdigit( *pszText ) )
          return FALSE;

        pRange->ulTo = strtoul( pszText, &pcEnd, 10 );
        if ( ( pszText == (PSZ)pcEnd ) || ( pRange->ulTo < pRange->ulFrom ) )
          return FALSE;
      }
    }
    else
      pRange->ulTo = pRange->ulFrom;
  }

  if ( *pcEnd == ',' )
    *ppszText = pcEnd + 1;
  else
    *ppszText = pcEnd;
/*  if ( *pcEnd == '\0' )
    *ppszText = pcEnd;
  else if ( *pcEnd == ',' )
    *ppszText = pcEnd + 1;
  else
    return FALSE;*/

  return TRUE;
}

BOOL utilStrToNewNumSet(PSZ pszText, PUTILRANGE *ppRange)
{
  PUTILRANGE           pScan, pNew, pList = NULL;
  UTILRANGE            stRange;
  ULONG                ulCount = 0;
  ULONG                ulMax = 0;
  BOOL                 fUnion;
  ULONG                ulIdx;
  BOOL                 fToAsterisk = FALSE;

  while( *pszText != '\0' && strchr( "01234567890:,*", *pszText ) != NULL )
  {
    if ( !_strToRange( &pszText, &stRange, &fToAsterisk ) )
    {
      free( pList );
      return FALSE;
    }

    fUnion = FALSE;
    for( ulIdx = 0, pScan = pList; ulIdx < ulCount; ulIdx++, pScan++ )
    {
      if ( ( (stRange.ulFrom - 1) <= pScan->ulTo ) &&
           ( stRange.ulTo >= (pScan->ulFrom - 1) ) )
      {
        if ( stRange.ulTo > pScan->ulTo )
          pScan->ulTo = stRange.ulTo;
        if ( stRange.ulFrom < pScan->ulFrom )
          pScan->ulFrom = stRange.ulFrom;
        fUnion = TRUE;
        break;
      }

      if ( stRange.ulFrom <= pScan->ulFrom )
        break;
    }

    if ( fUnion )
    {
      while( (ulIdx + 1) < ulCount )
      {
        if ( pScan->ulTo < (pScan[1].ulFrom - 1) )
          break;
   
        if ( pScan[1].ulTo > pScan->ulTo )
          pScan->ulTo = pScan[1].ulTo;

        ulCount--;
        if ( ulCount > (ulIdx + 1) )
          memcpy( &pScan[1], &pScan[2],
                  ( ulCount - ulIdx - 1 ) * sizeof(stRange) );
      }
    }
    else
    {
      if ( ulCount == ulMax )
      {
        pNew = realloc( pList, (ulMax + 32) * sizeof(UTILRANGE) );
        if ( pNew == NULL )
        {
          free( pList );
          return FALSE;
        }
        pList = pNew;
        ulMax += 32;
        pScan = &pList[ulIdx];
      }

      memmove( &pScan[1], pScan, (ulCount - ulIdx) * sizeof(UTILRANGE) );
      *pScan = stRange;
      ulCount++;
    }
  }

  // Expand/collapse range list memory to hold the last element (terminator).
  pNew = realloc( pList, (ulCount + 1) * sizeof(UTILRANGE) );
  if ( pNew == NULL )
  {
    free( pList );
    return FALSE;
  }
  pList = pNew;

  // Terminator: ulFrom is zero.
  pScan = &pList[ulCount];
  pScan->ulFrom = 0;
  pScan->ulTo = fToAsterisk ? 1 : 0;

  *ppRange = pList;
  return TRUE;
}

BOOL utilIsInNumSet(PUTILRANGE pRange, ULONG ulNum)
{
  PUTILRANGE pScan;

  if ( pRange == NULL )
    return FALSE;

  for( pScan = pRange; pScan->ulFrom != 0; pScan++ )
  {
    if ( ( ulNum >= pScan->ulFrom ) && ( ulNum <= pScan->ulTo ) )
      return TRUE;
  }

  return FALSE;
}

LONG utilNumSetToStr(PUTILRANGE pRange, ULONG cbBuf, PCHAR pcBuf)
{
  PUTILRANGE pScan;
  CHAR       acRange[32];
  ULONG      cbRange;
  ULONG      ulLength = pcBuf != NULL ? 0 : 1;

  if ( cbBuf != 0 )
    *pcBuf = '\0';

  if ( pRange == NULL )
    return 0;

  for( pScan = pRange; pScan->ulFrom != 0; pScan++ )
  {
    if ( pScan != pRange )
    {
      acRange[0] = ',';
      cbRange = 1;
    }
    else
      cbRange = 0;

    if ( pScan->ulFrom == pScan->ulTo )
      cbRange += sprintf( &acRange[cbRange], "%lu", pScan->ulFrom );
    else
    {
      cbRange += sprintf( &acRange[cbRange], "%lu:", pScan->ulFrom );

      if ( pScan->ulTo == ULONG_MAX )
      {
//        *((PUSHORT)&acRange[cbRange]) = 0x002A; // '*\0'
        acRange[cbRange++] = '*';
        acRange[cbRange]   = '\0';
        cbRange++;
      }
      else
        cbRange += sprintf( &acRange[cbRange], "%lu", pScan->ulTo );
    }

    ulLength += cbRange;

    if ( pcBuf != NULL )
    {
      if ( cbBuf <= cbRange )
        return -1;

      strcpy( pcBuf, acRange );
      pcBuf += cbRange;
      cbBuf -= cbRange;
    }
  }

  return ulLength;
}

BOOL utilNumSetInsert(PUTILRANGE *ppRange, ULONG ulNum)
{
  PUTILRANGE pRange = *ppRange;
  PUTILRANGE pNew;
  ULONG      ulIdx, ulCount;

  if ( ulNum == 0 )
    return FALSE;

  if ( pRange == NULL )
  {
    pRange = malloc( 2 * sizeof(UTILRANGE) );
    if ( pRange == NULL )
      return FALSE;

    pRange[0].ulFrom  = ulNum;
    pRange[0].ulTo    = ulNum;
    pRange[1].ulFrom  = 0;
    pRange[1].ulTo    = 0;

    *ppRange = pRange;
    return TRUE;
  }

  // Count the number of ranges in the list (incl. terminator).
  for( ulCount = 0; pRange[ulCount].ulFrom != 0; ulCount++ );
  ulCount++;

  for( ulIdx = 0; ulIdx < (ulCount - 1); ulIdx++ )
  {
    if ( ( ulNum >= pRange[ulIdx].ulFrom ) &&
         ( ulNum <= pRange[ulIdx].ulTo ) )
      // Already in range.
      return TRUE;

    if ( ulNum == (pRange[ulIdx].ulTo + 1) )
    {
      // Expand current range on top.
      if ( ( ( ulIdx + 1 ) == ( ulCount - 1 ) ) ||
           ( ulNum < (pRange[ulIdx + 1].ulFrom - 1) ) )
      {
        // No need to unite with next range.
        pRange[ulIdx].ulTo = ulNum;
      }
      else
      {
        // Combine with a subsequent range.
        pRange[ulIdx].ulTo = pRange[ulIdx + 1].ulTo;
        // Remove next range.
        memcpy( &pRange[ulIdx + 1], &pRange[ulIdx + 2],
                (PCHAR)&pRange[ulCount] - (PCHAR)&pRange[ulIdx + 2] );
        ulCount--;
        // Collapse allocated memory.
        pNew = realloc( pRange, ulCount * sizeof(UTILRANGE) );
        if ( pNew != NULL )
          *ppRange = pNew;
      }
      return TRUE;
    }

    if ( ulNum == (pRange[ulIdx].ulFrom - 1) )
    {
      // Expand range on bottom.
      pRange[ulIdx].ulFrom = ulNum;
      return TRUE;
    }

    if ( ulNum < (pRange[ulIdx].ulFrom - 1) )
    {
      // Insert a new range ulNum:ulNum on the current range position.

      pNew = realloc( pRange, ( ulCount + 1 ) * sizeof(UTILRANGE) );
      if ( pNew == NULL )
        return FALSE;
      pRange = pNew;

      memmove( &pRange[ulIdx + 1], &pRange[ulIdx],
               (PCHAR)&pRange[ulCount] - (PCHAR)&pRange[ulIdx] );
      ulCount++;
      pRange[ulIdx].ulFrom  = ulNum;
      pRange[ulIdx].ulTo    = ulNum;

      *ppRange = pRange;
      return TRUE;
    }
  }  // for()

  // Number was not inserted.

  pNew = realloc( pRange, ( ulCount + 1 ) * sizeof(UTILRANGE) );
  if ( pNew == NULL )
    return FALSE;
  pRange = pNew;

  pRange[ulCount - 1].ulFrom    = ulNum;
  pRange[ulCount - 1].ulTo      = ulNum;
  pRange[ulCount].ulFrom  = 0;
  pRange[ulCount].ulTo    = 0;
  *ppRange = pRange;

  return TRUE;
}


// [RFC 2045] 6.7.  Quoted-Printable Content-Transfer-Encoding
VOID utilQPDecChunk(PQPDEC pQPDec, PULONG pcbDst, PCHAR *ppcDst,
                    PULONG pcbSrc, PCHAR *ppcSrc)
{
  static CHAR          acHex[16] = "0123456789ABCDEF";
  PCHAR                pcHex;
  CHAR                 chChar;

  if ( pcbSrc == NULL )
    // User whant to pull out bytes form the buffer. It can be used at end of
    // the (potentially broken) input text.
    pQPDec->ulFlags |= 0x0002;

  while( *pcbDst != 0 )
  {
    if ( (pQPDec->ulFlags & 0x0002) != 0 )
    {
      if ( pQPDec->cbBuf != 0 )
      {
        *(*ppcDst) = pQPDec->acBuf[0];
        (*ppcDst)++;
        (*pcbDst)--;
        // *((PULONG)pQPDec->acBuf) >>= 8;
        // Make gcc -Wall happy...
        {
          PVOID        pBuf = (PVOID)pQPDec->acBuf;
          *((PULONG)pBuf) >>= 8;
        }
        pQPDec->cbBuf--;
        continue;
      }

      pQPDec->ulFlags = 0;
    }

    if ( ( pcbSrc == NULL ) || ( *pcbSrc == 0 ) )
      break;

    chChar = *(*ppcSrc);
    if ( chChar == '_' )
      chChar = ' ';
    (*ppcSrc)++;
    (*pcbSrc)--;

    if ( (pQPDec->ulFlags & 0x0001) == 0 )
    {
      if ( chChar != '=' )
      {
        *(*ppcDst) = chChar;
        (*ppcDst)++;
        (*pcbDst)--;
        continue;
      }

      pQPDec->ulFlags |= 0x0001;   // "have '='" flag,
      pQPDec->cbBuf = 0;
    }
    else
    {
      if ( ( chChar == 0x20 ) || ( chChar == 0x09 ) || ( chChar == 0x0D ) )
        continue;

      if ( chChar == 0x0A )
      {
        pQPDec->ulFlags = 0;
        continue;
      }

      pcHex = strchr( acHex, toupper( chChar ) );
      if ( pcHex == NULL )
        pQPDec->ulFlags |= 0x0002;   // output acBuf flag,
      else if ( pQPDec->cbBuf == 2 ) // 2: '=?' (? - hex. character).
      {
        *(*ppcDst) =
          ( (strchr( acHex, toupper( pQPDec->acBuf[1] ) ) - acHex) << 4 ) +
          ( pcHex - acHex );
        (*ppcDst)++;
        (*pcbDst)--;
        pQPDec->cbBuf = 0;
        pQPDec->ulFlags = 0;
        continue;
      }
    }

    if ( pQPDec->cbBuf > 2 )
      debugCP( "WTF?!" );

    pQPDec->acBuf[pQPDec->cbBuf] = chChar;
    pQPDec->cbBuf++;
  }
}

BOOL utilQPDec(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf)
{
  PCHAR      pcDst;
  ULONG      cbDst;
  QPDEC      stQPDec;

  if ( cbData == -1 )
    cbData = strlen( pcData );

  pcDst = malloc( cbData + 1 );
  if ( pcDst == NULL )
    return FALSE;

  cbDst = cbData;
  *pcbBuf = cbDst;
  *ppcBuf = pcDst;

  utilQPDecBegin( &stQPDec );
  utilQPDecChunk( &stQPDec, &cbDst, &pcDst, &cbData, &pcData );
  utilQPDecChunk( &stQPDec, &cbDst, &pcDst, NULL, NULL );
  *pcbBuf -= cbDst;

  pcData = realloc( *ppcBuf, *pcbBuf + 1 );
  if ( pcData != NULL )
    *ppcBuf = pcData;
  (*ppcBuf)[*pcbBuf] = '\0';

  return TRUE;
}


BOOL utilB64Enc(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf)
{
  BIO        *bioBufNew, *bioBuf, *bioB64f;
  BUF_MEM    *pMem;

  bioB64f = BIO_new( BIO_f_base64() );
  if ( bioB64f == NULL )
    return FALSE;
  bioBufNew = BIO_new( BIO_s_mem() );
  if ( bioBufNew == NULL )
  {
    BIO_free( bioB64f );
    return FALSE;
  }
  bioBuf = BIO_push( bioB64f, bioBufNew );
  if ( bioBuf == NULL )
  {
    BIO_free( bioB64f );
    BIO_free( bioBufNew );
    return FALSE;
  }

  BIO_set_flags( bioBuf, BIO_FLAGS_BASE64_NO_NL );
  BIO_set_close( bioBuf, BIO_CLOSE );
  BIO_write( bioBuf, pcData, cbData < 0 ? strlen( pcData ) : cbData );
  BIO_flush( bioBuf );

  BIO_get_mem_ptr( bioBuf, &pMem );
  *pcbBuf = pMem->length;
  *ppcBuf = malloc( *pcbBuf + 1 );
  if ( *ppcBuf != NULL )
  {
    memcpy( *ppcBuf, pMem->data, *pcbBuf );
    (*ppcBuf)[ *pcbBuf ] = '\0';
  }

  BIO_free_all( bioBuf );

  return *ppcBuf != NULL;
}

BOOL utilB64Dec(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf)
{
  BIO        *bioBufNew, *bioBuf, *bioB64f;

  if ( cbData < 0 )
    cbData = strlen( pcData );

  bioB64f = BIO_new( BIO_f_base64() );
  if ( bioB64f == NULL )
    return FALSE;
  bioBufNew = BIO_new_mem_buf( (void *)pcData, cbData );
  if ( bioBufNew == NULL )
  {
    BIO_free( bioB64f );
    return FALSE;
  }
  bioBuf = BIO_push( bioB64f, bioBufNew );
  if ( bioBuf == NULL )
  {
    BIO_free( bioB64f );
    BIO_free( bioBufNew );
    return FALSE;
  }

  *ppcBuf = malloc( cbData );
  if ( *ppcBuf != NULL )
  {
    int      iRC;

    BIO_set_flags( bioBuf, BIO_FLAGS_BASE64_NO_NL );
    BIO_set_close( bioBuf, BIO_CLOSE );
    iRC = BIO_read( bioBuf, *ppcBuf, cbData );
    if ( iRC <= 0 )
    {
      free( *ppcBuf );
      *ppcBuf = NULL;
    }
    else
    {
      *pcbBuf = iRC;
      *ppcBuf = realloc( *ppcBuf, (*pcbBuf) + 1 );
      (*ppcBuf)[ *pcbBuf ] = '\0';
    }
  }

  BIO_free_all( bioBuf );

  return *ppcBuf != NULL;
}

static const CHAR acBase64Table[65] =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0";

VOID utilB64DecChunk(PB64DEC pB64Dec, PULONG pcbDst, PCHAR *ppcDst,
                     PULONG pcbSrc, PCHAR *ppcSrc)
{
  BOOL		fEnd = ( ppcSrc == NULL ) || ( pcbSrc == NULL ) || ( *pcbSrc == 0 );
  ULONG		cbBuf;
  PCHAR		pcDst = *ppcDst;
  ULONG		cbDst = *pcbDst;
  PCHAR		pcSrc = NULL;
  ULONG		cbSrc = 0;
  PCHAR		pcPtr;

  if ( !fEnd )
  {
    pcSrc = *ppcSrc;
    cbSrc = *pcbSrc;
  }

  while( TRUE )
  {
    if ( pB64Dec->cbOutBuf != 0 )
    {
      cbBuf = MIN( pB64Dec->cbOutBuf, cbDst );
      memcpy( pcDst, &pB64Dec->acOutBuf, cbBuf );
      pB64Dec->cbOutBuf -= cbBuf;
      memcpy( &pB64Dec->acOutBuf, &pB64Dec->acOutBuf[cbBuf], pB64Dec->cbOutBuf );
      pcDst += cbBuf;
      cbDst -= cbBuf;

      if ( ( pB64Dec->cbOutBuf != 0 ) || fEnd )
        break;
    }

    if ( !fEnd )
    {
      while( ( cbSrc > 0 ) && ( pB64Dec->cbInBuf < 4 ) )
      {
        if ( *pcSrc == '=' )
        {
          fEnd = TRUE;
          *ppcSrc = ( pcSrc + cbSrc );
          *pcbSrc = 0;
          bzero( &pB64Dec->acInBuf[pB64Dec->cbInBuf],
                 sizeof(pB64Dec->acInBuf) - pB64Dec->cbInBuf );
          break;
        }

        pcPtr = strchr( acBase64Table, *pcSrc );
        if ( pcPtr != NULL )
          pB64Dec->acInBuf[pB64Dec->cbInBuf++] = pcPtr - acBase64Table;

        pcSrc++;
        cbSrc--;
      }

      if ( !fEnd && ( pB64Dec->cbInBuf < 4 ) )
        break;
    }
    else if ( pB64Dec->cbInBuf == 0 )
      break;

#if 0
    pB64Dec->acOutBuf[0] = ( pB64Dec->acInBuf[0] << 2 ) |
                          ( pB64Dec->acInBuf[1] >> 4 );
    pB64Dec->acOutBuf[1] = ( pB64Dec->acInBuf[1] << 4 ) |
                          ( pB64Dec->acInBuf[2] >> 2 );
    pB64Dec->acOutBuf[2] = ( (pB64Dec->acInBuf[2] & 0x03 ) << 6 ) |
                          ( pB64Dec->acInBuf[3] & 0x3f );
    pB64Dec->cbOutBuf = pB64Dec->cbInBuf - 1;
    pB64Dec->cbInBuf = 0;
    if ( pB64Dec->cbOutBuf != 3 )
      break;
#else
    pB64Dec->acOutBuf[0] = pB64Dec->acInBuf[0] << 2;
    if ( pB64Dec->cbInBuf > 1 )
    {
      pB64Dec->acOutBuf[0] |= pB64Dec->acInBuf[1] >> 4;
      pB64Dec->acOutBuf[1] = pB64Dec->acInBuf[1] << 4;
      if ( pB64Dec->cbInBuf > 2 )
      {
        pB64Dec->acOutBuf[1] |= pB64Dec->acInBuf[2] >> 2;
        pB64Dec->acOutBuf[2] = (pB64Dec->acInBuf[2] & 0x03 ) << 6;
        if ( pB64Dec->cbInBuf > 3 )
        {
          pB64Dec->acOutBuf[2] |= pB64Dec->acInBuf[3] & 0x3f;
          pB64Dec->cbOutBuf = 3;
          pB64Dec->cbInBuf = 0;
          continue;
        }
        else
          pB64Dec->cbOutBuf = 2;
      }
      else
        pB64Dec->cbOutBuf = 1;

      if ( fEnd );
        continue;
    }
    else
      pB64Dec->cbOutBuf = 0;

    pB64Dec->cbInBuf = 0;
    break;
#endif
  }

  *ppcDst = pcDst;
  *pcbDst = cbDst;
  if ( !fEnd )
  {
    *ppcSrc = pcSrc;
    *pcbSrc = cbSrc;
  }
}


BOOL utilQueryFileInfo(PSZ pszFile, PUTILFTIMESTAMP pFTimestamp,
                       PULLONG pullSize)
{
  FILESTATUS3L stFileStat;
  ULONG        ulRC;

  ulRC = DosQueryPathInfo( pszFile, FIL_STANDARDL, &stFileStat,
                           sizeof(stFileStat) );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosQueryPathInfo(\"%s\",,,), rc = %u", pszFile, ulRC );

    if ( pFTimestamp != NULL )
      bzero( pFTimestamp, sizeof(UTILFTIMESTAMP) );

    if ( pullSize != NULL )
      *pullSize = 0;

    return FALSE;
  }

  if ( (stFileStat.attrFile & FILE_DIRECTORY) != 0 )
    return FALSE;

  if ( pFTimestamp != NULL )
  {
    pFTimestamp->fdateLastWrite = stFileStat.fdateLastWrite;
    pFTimestamp->ftimeLastWrite = stFileStat.ftimeLastWrite;
  }

  if ( pullSize != NULL )
    *pullSize = stFileStat.cbFile;

  return TRUE;
}


#define _RND_FNAME_LEN           6
#define _RND_FNAME_ITERATIONS    1000

static LONG _utilMakeRndFName(ULONG cbPath, PCHAR pcPath,
                              ULONG cbFullName, PCHAR pcFullName)
{
  if ( ( cbPath > 1 ) && ( pcPath[cbPath - 1] == '\\' ) )
    cbPath--;

  if ( (cbPath + 1 + _RND_FNAME_LEN) >= cbFullName )
    return -1;

  if ( cbPath != 0 )
  {
    memcpy( pcFullName, pcPath, cbPath );
    pcFullName[cbPath] = '\\';
    cbPath++;
  }
  utilRndAlnum( _RND_FNAME_LEN, &pcFullName[cbPath] );

  return cbPath + _RND_FNAME_LEN;;
}

ULONG utilOpenTempFile(ULONG cbPath, PCHAR pcPath, ULLONG ullSize,
                       ULONG cbFullName, PCHAR pcFullName, PHFILE phFile)
{
  ULONG      ulIdx;
  LONG       lRC, ulAction = 0;

  for( ulIdx = 0; ulIdx < _RND_FNAME_ITERATIONS; ulIdx++ )
  {
    lRC = _utilMakeRndFName( cbPath, pcPath, cbFullName - 2, pcFullName );
    if ( lRC == -1 )
      return ERROR_BUFFER_OVERFLOW;

    strcpy( &pcFullName[lRC], ".#" );

    *phFile = NULLHANDLE;
    lRC = DosOpenL( pcFullName, phFile, &ulAction, ullSize, FILE_NORMAL,
                    OPEN_ACTION_CREATE_IF_NEW | OPEN_ACTION_FAIL_IF_EXISTS,
                    OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                    OPEN_SHARE_DENYREADWRITE | OPEN_ACCESS_WRITEONLY, NULL );
    if ( lRC == NO_ERROR )
      break;

    if ( lRC != ERROR_OPEN_FAILED )
    {
      debug( "Can't create destination file: %s , rc = %u", pcFullName, lRC );
      break;
    }
  }

  return lRC;
}

ULONG utilRenameFileToRndName(PSZ pszOldFullName, PSZ pszNewExt,
                              ULONG cbNewFullName, PCHAR pcNewFullName)
{
  ULONG      cbNewExt = strlen( pszNewExt );
  ULONG      ulIdx, ulRC;
  PCHAR      pcFName = strrchr( pszOldFullName, '\\' );
  ULONG      cbPath, cb;

  if ( pcFName == NULL )
    pcFName = pszOldFullName;
  cbPath = pcFName - (PCHAR)pszOldFullName;

  if ( cbNewFullName <= (cbPath + 1 + _RND_FNAME_LEN + 1 + cbNewExt) )
    return ERROR_BUFFER_OVERFLOW;

  memcpy( pcNewFullName, pszOldFullName, cbPath );

  for( ulIdx = 0; ulIdx < _RND_FNAME_ITERATIONS; ulIdx++ )
  {
    cb = _utilMakeRndFName( cbPath, pcNewFullName,
                            cbNewFullName - cbNewExt - 1, pcNewFullName );
    if ( cb == -1 )
    {
      debugCP( "WTF?!" );
      return ERROR_BUFFER_OVERFLOW;
    }

    if ( cbNewExt != 0 )
    {
      pcNewFullName[cb] = '.';
      strcpy( &pcNewFullName[cb + 1], pszNewExt );
    }

    //debug( "DosMove(\"%s\",\"%s\")", pszOldFullName, pcNewPathname );
    ulRC = DosMove( pszOldFullName, pcNewFullName );
    if ( ulRC != ERROR_ACCESS_DENIED )     // ERROR_ACCESS_DENIED - file exist.
      break;
  }

  return ulRC;
}


// Returns: -1 - not enough buffer space,
//           0 - file open/read error or not enough memory.
//          other value - result lenght.
//
LONG utilGetFileHash(PSZ pszFile, PSZ pszEAName, ULONG cbHash, PCHAR pcHash,
                     PBOOL pfLoadedFromEA)
{
#define _MD5READ_FILE_BUF_SIZE   65536
  ULONG      ulRC, ulActual;
  HFILE      hFile;
  MD5_CTX    md5ctx;
  PCHAR      pcBuf;

  if ( cbHash < MD5_DIGEST_LENGTH )
    return -1;

  ulRC = DosOpenL( pszFile, &hFile, &ulActual, 0, 0,
                   OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                   OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                   OPEN_SHARE_DENYWRITE | OPEN_ACCESS_READONLY, NULL );
  if ( ulRC != NO_ERROR )
  {
    debug( "Can't open file: %s , rc = %u", pszFile, ulRC );
    return 0;
  }

  if ( pszEAName != NULL )
  {
    // Try to read hash from EA.

    ULONG              cbEAName = strlen( pszEAName );
    ULONG              cbGEAList = sizeof(GEA2LIST) + cbEAName;
    PGEA2LIST          pGEAList;
    PGEA2              pGEA;
    ULONG              cbFEAList = sizeof(FEA2LIST) + cbEAName +
                                   MD5_DIGEST_LENGTH;
    PFEA2LIST          pFEAList;
    PFEA2              pFEA;
    EAOP2              stEAOp;

    // Allocate spaces for lists aligned on a doubleword boundary.
    pGEAList = (PGEA2LIST)( ( (ULONG)alloca( cbGEAList + 3 ) + 3 ) & ~3 );
    pFEAList = (PFEA2LIST)( ( (ULONG)alloca( cbFEAList + 3 ) + 3 ) & ~3 );

    if ( ( pGEAList != NULL ) && ( pFEAList != NULL ) )
    {
      pGEA = &pGEAList->list[0];
      pFEA = &pFEAList->list[0];

      pGEAList->cbList = cbGEAList;
      pGEA->oNextEntryOffset = 0;
      pGEA->cbName = cbEAName;
      strcpy( pGEA->szName, pszEAName );
      pFEAList->cbList = cbFEAList;

      stEAOp.fpGEA2List = pGEAList;
      stEAOp.fpFEA2List = pFEAList;
      stEAOp.oError = 0;

      ulRC = DosQueryFileInfo( hFile, FIL_QUERYEASFROMLIST, &stEAOp,
                               sizeof(EAOP2) );
      if ( ulRC == NO_ERROR )
      {
        ULONG  cbVal = pFEAList->cbList - sizeof(FEA2LIST) - cbEAName - 1;

        if ( cbVal == MD5_DIGEST_LENGTH )
        {
          debug( "Hash has been loaded from EA for %s", pszFile );
          memcpy( pcHash, &pFEA->szName[cbEAName + 1], MD5_DIGEST_LENGTH );
          if ( pfLoadedFromEA != NULL )
            *pfLoadedFromEA = TRUE;
          goto l00;
        }
      }
      else
        debug( "DosQueryFileInfo(), rc = %u", ulRC );
    }
  }

  ulRC = DosAllocMem( (PVOID *)&pcBuf, _MD5READ_FILE_BUF_SIZE,
                      PAG_COMMIT | PAG_READ | PAG_WRITE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosAllocMem(), rc = %u", ulRC );
    DosClose( hFile );
    return 0;
  }

  if ( pfLoadedFromEA != NULL )
    *pfLoadedFromEA = FALSE;

  MD5_Init( &md5ctx );

  do
  {
    ulRC = DosRead( hFile, pcBuf, _MD5READ_FILE_BUF_SIZE, &ulActual );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosRead(), rc = %u", ulRC );
      break;
    }

    MD5_Update( &md5ctx, pcBuf, ulActual );
  }
  while( ( ulRC == NO_ERROR ) && ( ulActual == _MD5READ_FILE_BUF_SIZE ) );

  MD5_Final( pcHash, &md5ctx );
  DosFreeMem( pcBuf );
l00:
  DosClose( hFile );

  return ulRC != NO_ERROR ? 0 : MD5_DIGEST_LENGTH;
}

BOOL utilStoreFileHash(PSZ pszFile, PSZ pszEAName, ULONG cbHash, PCHAR pcHash)
{
  ULONG      ulRC;
  ULONG      cbEAName = strlen( pszEAName );
  ULONG      cbFEAList = sizeof(FEA2LIST) + cbEAName + MD5_DIGEST_LENGTH;
  PFEA2LIST  pFEAList;
  PFEA2      pFEA;
  EAOP2      stEAOp;

  if ( cbHash != MD5_DIGEST_LENGTH )
    return FALSE;

  // Allocate spaces for FEA2LIST aligned on a doubleword boundary.
  pFEAList = (PFEA2LIST)( ( (ULONG)alloca( cbFEAList + 113 ) + 3 ) & ~3 );
  if ( pFEAList == NULL )
    return FALSE;

  pFEAList->cbList = cbFEAList;
  pFEA = &pFEAList->list[0];
  pFEA->oNextEntryOffset = 0;
  pFEA->fEA = 0;
  pFEA->cbName = cbEAName;
  pFEA->cbValue = MD5_DIGEST_LENGTH;
  strcpy( pFEA->szName, pszEAName );
  memcpy( &pFEA->szName[cbEAName + 1], pcHash, MD5_DIGEST_LENGTH );

  stEAOp.fpGEA2List = NULL;
  stEAOp.fpFEA2List = pFEAList;
  stEAOp.oError = 0;

  ulRC = DosSetPathInfo( pszFile, FIL_QUERYEASIZE, &stEAOp, sizeof(EAOP2),
                         DSPI_WRTTHRU );
  if ( ulRC != NO_ERROR )
    debug( "DosSetPathInfo(), rc = %lu", ulRC );

  return ulRC == NO_ERROR;
}

// Convert file hash to hex string.
PSZ utilFileHashToStr(ULONG cbHash, PCHAR pcHash, ULONG cbBuf, PCHAR pcBuf)
{
  ULONG      ulIdx;
  PCHAR      pcPos;

  if ( ( cbHash != MD5_DIGEST_LENGTH ) ||
       ( cbBuf <= (2 * MD5_DIGEST_LENGTH) ) )
    return NULL;

  for( ulIdx = 0, pcPos = pcBuf; ulIdx < MD5_DIGEST_LENGTH;
       ulIdx++, pcPos += 2 )
    sprintf( pcPos, "%02x", pcHash[ulIdx] & 0xFF );
  *pcPos = '\0';

  return (PSZ)pcBuf;
}


/* BOOL utilBSearch(PVOID pKey, PVOID pBase, ULONG ulNum, ULONG cbWidth,
                 int (*fnComp)( const void *pkey, const void *pbase),
                 PULONG pulIndex)

   Alternative to LIBC bsearch() function.
   Returns a pointer to the array element in base that matches key and index of
   the element at pulIndex if a element found.
   Returns NULL and index where element pKey must be placed at pulIndex if a
   matching element could not be found. 
*/

PVOID utilBSearch(const void *pKey, PVOID pBase, ULONG ulNum, ULONG cbWidth,
                  int (*fnComp)(const void *pkey, const void *pbase),
                  PULONG pulIndex)
{
  PCHAR		pcList = (PCHAR)pBase;
  LONG		lHi, lLo, lMed = 0;
  LONG		lComp;
  PCHAR         pElement = NULL;

  if ( ulNum != 0 )
  do
  {
    pElement = &pcList[( ulNum - 1 ) * cbWidth];
    lComp = fnComp( pKey, pElement );

    if ( lComp > 0 )
    {
      lMed = ulNum;
      pElement = NULL;
      break;
    }

    if ( lComp == 0 )
    {
      lMed = ulNum - 1;
      break;
    }

    lComp = fnComp( pKey, pcList );

    if ( lComp < 0 )
    {
      pElement = NULL;
      break;
    }

    if ( lComp == 0 )
    {
      pElement = pcList;
      break;
    }

    lHi = ulNum - 1;
    lLo = 0;

    while( ( lHi - lLo ) > 1 )
    {
      lMed = ( lLo + lHi ) / 2;
      pElement = &pcList[lMed * cbWidth];
      lComp = fnComp( pKey, pElement );

      if ( lComp > 0 )
      {
        lLo = lMed;
      }
      else if ( lComp < 0 )
      {
        lHi = lMed;
      }
      else
        break;
    }

    if ( lComp != 0 )
    {
      lMed = lHi;
      pElement = NULL;
    }
  }
  while( FALSE );

  if ( pulIndex != NULL )
    *pulIndex = lMed;

  return pElement;
}
