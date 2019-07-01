#ifndef UTILS_H
#define UTILS_H

#include <iconv.h>
#include <time.h>

#define BUF_SKIP_SPACES(cb, pc) \
  while( (cb > 0) && isspace( *pc ) ) { cb--; pc++; }
#define BUF_MOVE_TO_SPACE(cb, pc) \
  while( (cb > 0) && !isspace( *pc ) ) { cb--; pc++; }
#define BUF_RTRIM(cb, pc) \
  while( (cb > 0) && ( isspace( pc[cb - 1] ) ) ) cb--

#define STR_SAFE(p) ( ((PCHAR)p) == NULL ? "" : ((PCHAR)p) )
#define STR_LEN(p) ( (p) == NULL ? 0 : strlen( p ) )
#define STR_ICMP(s1,s2) stricmp( STR_SAFE(s1), STR_SAFE(s2) )
#define STR_COPY(d,s) strcpy( d, STR_SAFE(s) )

#define STR_SKIP_SPACES(p) do { while( isspace( *(p) ) ) (p)++; } while( 0 )
#define STR_RTRIM(p) do { PCHAR __p = strchr( p, '\0' ); \
  while( (__p > p) && isspace( *(__p - 1) ) ) __p--; \
  *__p = '\0'; \
} while( 0 )
#define STR_MOVE_TO_SPACE(p) \
  do { while( (*(p) != '\0') && !isspace( *(p) ) ) (p)++; } while( 0 )

#define ARRAYSIZE(a) ( sizeof(a) / sizeof(a[0]) )

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef LONG_MAX
#define	LONG_MAX       0x7fffffffL         /* max value for a long */
#endif
#ifndef LONG_MIN
#define	LONG_MIN       (-0x7fffffffL - 1)  /* min value for a long */
#endif
#ifndef ULONG_MAX
#define	ULONG_MAX      (~0)                /* max value for a unsigned long */
#endif
#ifndef ULONG_MIN
#define	ULONG_MIN      0                   /* min value for a unsigned long */
#endif
#ifndef LLONG_MAX
#define LLONG_MAX      0x7FFFFFFFFFFFFFFF
#endif

typedef unsigned long long       ULLONG, *PULLONG;
typedef long long                LLONG, *PLLONG;


BOOL utilBufCutWord(PULONG pcbText, PCHAR *ppcText,
                    PULONG pcbWord, PCHAR *ppcWord);
LONG utilStrWordIndex(PSZ pszList, LONG cbWord, PCHAR pcWord);
// Returns TRUE if word list pszList contains all words from list pszWords.
BOOL utilStrIsWordListContains(PSZ pszList, PSZ pszWords);
BOOL utilStrIsListEqual(PSZ pszList1, PSZ pszList2);

// The following functions utilStrCut*() cuts out the first element of the
// string and moves the pointer pointed with ppszText after this element.
// Returns FALSE if there are no more elements.
// These functions are destructive for the source (moves bytes, writes ZERO)!

// Skips SPACEs and cuts off sequence of characters up to SPACE.
BOOL utilStrCutWord(PSZ *ppszText, PSZ *ppszWord);
// Skips SPACEs and cuts off '\'-escaped phrase in quotes, or unquoted word.
BOOL utilStrCutComp(PSZ *ppszText, PSZ *ppszWord);
// Skips SPACEs and cuts off list in brackets or one word if first ch. is not (.
BOOL utilStrCutList(PSZ *ppszText, PSZ *ppszWord);
// Cuts off v-directory name from the path dir1/dir2/dir3
BOOL utilStrCutVDir(PSZ *ppszText, PSZ *ppszVDir);

// PSZ utilStrGetCompNew(PSZ *ppszText);
//
// Non-destructive for the source.
// Skips SPACEs and returns a new string: unescaped phrase in quotes, or
// unquoted word. Result should be destroyed by free().
//
PSZ utilStrGetCompNew(PSZ *ppszText);

BOOL utilStrSkipComp(PSZ *ppszText);

// BOOL utilStrSkipAtom(PSZ *ppszText);
//
// Skips 'atom' in notation specified in [RFC822] - moves the pointer pointed
// with ppszText after this 'atom'.
// Retrns FALSE in *ppszText is end of string (ZERO).
//
BOOL utilStrSkipAtom(PSZ *ppszText);

// BOOL utilStrSkipWordAtom(PSZ *ppszText);
//
// Skips 'word' (atom / quoted-string) in notation specified in [RFC822] -
// moves the pointer pointed with ppszText after this 'word'.
// Retrns FALSE in *ppszText is end of string (ZERO).
//
BOOL utilStrSkipWordAtom(PSZ *ppszText);

#define UTIL_BYTES     0
#define UTIL_KB        3
#define UTIL_MB        5
#define UTIL_GB        7
#define UTIL_TB        9
BOOL utilStrToBytes(PSZ pszVal, PULLONG pullBytes, ULONG ulDefaultUnits);

// Converts string like "17-Jul-1996 02:44:25 -0700" to the unix timestamp.
BOOL utilStrToIMAPTime(PSZ pszTime, time_t *pT);

BOOL utilIMAPIsMatch(PSZ pszStr, PSZ pszPtrn, PSZ *ppszRem);

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
                         BOOL fAnyIP, USHORT usDefaultPort);

#if 0
// No need any more.

// For each key in form $(key) from the input text pcText calls user function
// fnSubset which should write value for key pszKey to the given buffer pcVal
// and return number of writed bytes.
// Returns allocated memory to the new text and length of this text in
// *pcbResult.
// Result shoul be destroyed by free().
//
// User function fnSubset() gets unescaped key "name" - value between '$(' and
// ')'. All ',' replaced with ZERO, key ends with double ZERO.
// For example for $(KEY,'(','\)') it will be "KEY\0'('\0')'\0\0" (without
// double quotas). User function is free to corrupt data in given key buffer.
//
PCHAR utilStrKeysSubsetNew(LONG cbText, PCHAR pcText,
                           ULONG (*fnSubset)(ULONG cbKey, PSZ pszKey,
                                             ULONG cbVal, PCHAR pcVal,
                                             PVOID pData),
                           PVOID pData, PULONG pcbResult);
#endif

VOID utilRndAlnum(ULONG cbBuf, PCHAR pcBuf);

BOOL utilIConvChunk(iconv_t ic, PULONG pcbDst, PCHAR *ppcDst,
                    PULONG pcbSrc, PCHAR *ppcSrc);
PSZ utilIConv(iconv_t ic, LONG cbStrIn, PCHAR pcStrIn, PULONG pcbStrOut);

// PSZ utilStrToUTF16Upper(PSZ pszStr, PSZ pszCharset);
//
// Converts given string pszStr in charset pszCharset to uppercase and UTF-16
// charset. Resuls should be destroyed with free().
//
PSZ utilStrToUTF16Upper(PSZ pszStr, PSZ pszCharset);

ULONG utilQueryStackSpace();


// Number sets
// -----------

// Result data for utilStrToNewNumSet()
// See: utilIsInNumSet(PUTILRANGE,) and utilNumSetToStr(PUTILRANGE,,).
typedef struct _UTILRANGE {
  ULONG      ulFrom;   // 0 for last (terminator) record.
  ULONG      ulTo;     // 1 in terminator means that string has record as n:*.
} UTILRANGE, *PUTILRANGE;

// BOOL utilStrToNewNumSet(PSZ pszText, PUTILRANGE &ppRange);
//
// Parses the string of values and ranges, like: 1,3,2:5,10,15:*,20:25
// The minimum value is 1. The end of the range '*' means the maximum ULONG
// value. The resulting list pRange ends with a record where the ulFrom field
// is zero. The filed ulTo of this record Is not zero if '*' was used in one of
// ranges. The resulting list *ppRange should be destroyed by free().
// Returns FALSE with a syntax or memory error.
//
BOOL utilStrToNewNumSet(PSZ pszText, PUTILRANGE *ppRange);

BOOL utilIsInNumSet(PUTILRANGE pRange, ULONG ulNum);

// LONG utilNumSetToStr(PUTILRANGE pRange, ULONG cbBuf, PCHAR pcBuf);
//
// Converts number set to string. Returns length of result string without ZERO
// or -1 on not enough buffer space. If pcBuf is NULL functions returns [size-1]
// of the buffer needed to build string.
LONG utilNumSetToStr(PUTILRANGE pRange, ULONG cbBuf, PCHAR pcBuf);

// BOOL utilNumSetInsert(PUTILRANGE *ppRange, ULONG ulNum);
//
// Inserts ulNum to the number set *ppRange and stores pointer to the new list
// to *ppRange. If *ppRange is NULL it will be created.
// The resulting list *ppRange should be destroyed by free().
BOOL utilNumSetInsert(PUTILRANGE *ppRange, ULONG ulNum);


// Quoted-Printable Content-Transfer-Encoding
// ------------------------------------------

typedef struct _QPDEC {
  ULONG      ulFlags;
  CHAR       acBuf[4];
  ULONG      cbBuf; 
} QPDEC, *PQPDEC;

#define utilQPDecBegin(_pqpdec) memset( (_pqpdec), 0, sizeof(QPDEC) )

VOID utilQPDecChunk(PQPDEC pQPDec, PULONG pcbDst, PCHAR *ppcDst,
                    PULONG pcbSrc, PCHAR *ppcSrc);

BOOL utilQPDec(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf);


// Base64
// ------

typedef struct _B64DEC {
  CHAR       acInBuf[4];
  ULONG      cbInBuf;
  CHAR       acOutBuf[3];
  ULONG      cbOutBuf;
} B64DEC, *PB64DEC;

// BOOL utilB64Enc(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf);
// BOOL utilB64Dec(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf);
//
// Encode/decode base64 data. Functions return FALSE if there is insufficient
// memory available.
//
BOOL utilB64Enc(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf);
BOOL utilB64Dec(LONG cbData, PCHAR pcData, PULONG pcbBuf, PCHAR *ppcBuf);

#define utilB64DecBegin(_b64dec) memset( (_b64dec), 0, sizeof(B64DEC) )

VOID utilB64DecChunk(PB64DEC pB64Dec, PULONG pcbDst, PCHAR *ppcDst,
                     PULONG pcbSrc, PCHAR *ppcSrc);


#pragma pack(1)
typedef struct _FTIMESTAMP {
  FDATE      fdateLastWrite;
  FTIME      ftimeLastWrite;
} UTILFTIMESTAMP, *PUTILFTIMESTAMP;
#pragma pack()

#define utilIsSameFileDateTime(__pfts1, __pfts2) \
  ( memcmp( __pfts1, __pfts2, sizeof(UTILFTIMESTAMP) ) == 0 )

BOOL utilQueryFileInfo(PSZ pszFile, PUTILFTIMESTAMP pFTimestamp,
                       PULLONG pullSize);
ULONG utilOpenTempFile(ULONG cbPath, PCHAR pcPath, ULLONG ullSize,
                       ULONG cbFullName, PCHAR pcFullName, PHFILE phFile);
ULONG utilRenameFileToRndName(PSZ pszOldFullName, PSZ pszNewExt,
                              ULONG cbNewFullName, PCHAR pcNewFullName);

// Returns: -1 - not enough buffer space (should be minimum
//               (2 * MD5_DIGEST_LENGTH) + 1),
//           0 - file open/read error or not enough memory.
//          other value - result string lenght (without trailing ZERO).
//
#define UTIL_FILE_HASH_LENGTH    16
#define UTIL_FILE_HASH_STR_SIZE  ((2 * UTIL_FILE_HASH_LENGTH) + 1)

LONG utilGetFileHash(PSZ pszFile, PSZ pszEAName, ULONG cbHash, PCHAR pcHash,
                     PBOOL pfLoadedFromEA);
BOOL utilStoreFileHash(PSZ pszFile, PSZ pszEAName, ULONG cbHash, PCHAR pcHash);
PSZ utilFileHashToStr(ULONG cbHash, PCHAR pcHash, ULONG cbBuf, PCHAR pcBuf);

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
                 PULONG pulIndex);

#endif // UTILS_H
