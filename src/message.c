/*
  MIME firmat e-mail files parser.
*/

#define INCL_DOSMISC
#include <os2.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <uconv.h>
#include "message.h"
#include "wcfg.h"
#include "debug.h"               // Should be last.


/* *************************************************************** */
/*                                                                 */
/*                     Message header fields                       */
/*                                                                 */
/* *************************************************************** */

static PFIELD _fldFind(PFIELD pFields, PSZ pszName)
{
  PFIELD     pField;
  ULONG      cbName = strlen( pszName );

  for( pField = pFields; pField != NULL; pField = pField->pNext )
  {
    if ( ( cbName == pField->cbName ) &&
         ( memicmp( pszName, pField->acField, cbName ) == 0 ) )
      break;
  }

  return pField;
}

VOID fldFree(PFIELD pFields)
{
  PFIELD     pNext;

  while( pFields != NULL )
  {
    pNext = pFields->pNext;

    free( pFields );
    pFields = pNext;
  }
}

PFIELD fldRead(FILE *pfMsg, PSZ pszBoundary)
{
  CHAR       acBuf[1032];
  ULONG      cbBoundary = STR_LEN( pszBoundary );
  PVOID      pEnd = &acBuf[cbBoundary + 2];
  PFIELD     pFields = NULL;
  PFIELD     pField = NULL;
  PFIELD     *ppField = NULL, *ppNext = &pFields;
  ULONG      cbBuf;
  PCHAR      pcColon;

  while( TRUE )
  {
    if ( fgets( acBuf, sizeof(acBuf) - 3, pfMsg ) == NULL )
      return pFields;

    cbBuf = strlen( acBuf );
    if ( cbBuf == 0 )
    {
      debugCP( "WTF?" );
      continue;
    }

    if ( acBuf[cbBuf - 1] != '\n' )
    {
      if ( cbBuf == (sizeof(acBuf) - 4) )
        { debugCP( "Too long line?" ); }
      else
        { debugCP( "Unexpected end of file?" ); }
      break;
    }

    if ( cbBuf == 1 )
    {
      // End of header.
      // Insert special field (cbName equals 0) for the empty line.
      pField = calloc( 1, sizeof(FIELD) );
      if ( pField == NULL )
        break;
      *ppNext = pField;

      return pFields;
    }

    if ( ( pszBoundary != NULL ) &&
// [Not good for -Wall]         ( *((PUSHORT)acBuf) == 0x2D2D /* "--" */ ) &&
         ( acBuf[0] == '-' && acBuf[1] == '-' ) &&
         ( memcmp( &acBuf[2], pszBoundary, cbBoundary ) == 0 ) &&
         ( ( *((PCHAR)pEnd) == '\n' ) ||
           ( *((PULONG)pEnd) == 0x000A2D2D ) ) )   // '--\n\0'
      return pFields;

// [Not good for -Wall]    *((PULONG)&acBuf[cbBuf - 1]) = 0x00000A0D;
    acBuf[cbBuf - 1] = '\r';
    acBuf[cbBuf]     = '\n';
    acBuf[cbBuf + 1] = '\0';
    acBuf[cbBuf + 2] = '\0';

    if ( acBuf[0] == ' ' || acBuf[0] == '\t' )
    {
      // Continue of the field's context on the next line.
      ULONG    cbField;

      if ( pField == NULL )
        debugCP( "Line begins from space" );
      else
      {
        PFIELD         pNew;

        cbField = strlen( pField->acField );
        pNew = realloc( pField, sizeof(FIELD) + cbField + cbBuf );
        if ( pNew == NULL )
          break;

        pField = pNew;
        strcpy( &pField->acField[cbField], acBuf );
        *ppField = pField;
        ppNext = &pField->pNext;
      }
      continue;
    }

    if ( cbBuf >= 4 )
    {
      pcColon = strchr( acBuf, ':' );
      if ( ( pcColon > acBuf ) && ( pcColon[1] != '\n' ) )
      {
        pField = malloc( sizeof(FIELD) + cbBuf );
        if ( pField == NULL )
          break;

        pField->pNext = NULL;
        pField->cbName = pcColon - acBuf;
        strcpy( pField->acField, acBuf );
        *ppNext = pField;
        ppField = ppNext;
        ppNext = &pField->pNext;
      }
      continue;
    }

    break;
  }

  fldFree( pFields );
  return NULL;
}

PFIELD fldReadHeader(PSZ pszFile)
{
  FILE       *pfMsg;
  PFIELD     pFields;

  pfMsg = fopen( pszFile, "rt" );
  if ( pfMsg == NULL )
  {
    debug( "Can't open %s", pszFile );
    return NULL;
  }

  // Read header fields of the message or of the part.
  pFields = fldRead( pfMsg, NULL );
  fclose( pfMsg );

  return pFields;
}

PSZ fldFind(PFIELD pFields, PSZ pszName)
{
  PFIELD     pField = _fldFind( pFields, pszName );

  if ( pField != NULL )
  {
    PSZ      pszVal = &pField->acField[pField->cbName + 1];

    STR_SKIP_SPACES( pszVal );

    return pszVal;
  }

  return NULL;
}

// PCHAR fldVGetParam(PSZ pszValue, PSZ pszName, PULONG pcbVal)
//
// Reads 'param' from string like 'value; a="Aaa"; b=0.1; param="text"'
// Returns pointer to the value ('text') and length of value at pcbVal.

PCHAR fldVGetParam(PSZ pszValue, PSZ pszName, PULONG pcbVal)
{
  ULONG      cbName = strlen( pszName );
  ULONG      cBytes;
  PCHAR      pcEnd;

  if ( pszValue == NULL )
    return NULL;

  while( TRUE )
  {
    STR_SKIP_SPACES( pszValue );

    cBytes = strcspn( pszValue, " ;=" );
    if ( ( pszValue[cBytes] == '=' ) && ( cBytes == cbName ) &&
         ( memicmp( pszValue, pszName, cbName ) == 0 ) )
    {
      // Paramether name is found.
      pszValue = &pszValue[cBytes + 1];
      STR_SKIP_SPACES( pszValue );
      break;
    }

    pszValue = &pszValue[cBytes];
    if ( *pszValue == '\0' )
      break;

    if ( *pszValue == '=' )
    {
      pszValue++;
      if ( *pszValue == '"' )
      {
        pszValue = strchr( &pszValue[1], '"' );
        if ( pszValue == NULL )
          break;

        pszValue++;
        if ( *pszValue == ';' )
          pszValue++;
      }
    }
    else if ( *pszValue == ';' )
      pszValue++;
  }

  if ( ( pszValue == NULL ) || ( *pszValue == '\0' ) )
    return NULL;

  if ( *pszValue == '"' )
  {
    pszValue++;
    pcEnd = strchr( pszValue, '"' );
    if ( pcEnd == NULL )
      return NULL;
  }
  else
  {
    pcEnd = pszValue;
    while( ( *pcEnd != '\0' ) && ( *pcEnd != ';' ) && !isspace( *pcEnd ) )
      pcEnd++;
  }

  *pcbVal = pcEnd - (PCHAR)pszValue;

  return pszValue;
}

// PSZ fldVGetParamNew(PSZ pszValue, PSZ pszName)
//
// Reads 'param' from string like 'value; a="Aaa"; b=0.1; param="text"'
// Returns pointer to the allocated memory contains ASCIIZ value ('text').
// Pointer should be destroyed with free().

PSZ fldVGetParamNew(PSZ pszValue, PSZ pszName)
{
  ULONG      cbVal;
  PCHAR      pcVal = fldVGetParam( pszValue, pszName, &cbVal );
  PSZ        pszVal;

  if ( pcVal == NULL )
    return NULL;

  pszVal = malloc( cbVal + 1 );
  if ( pszVal == NULL )
    return NULL;

  memcpy( pszVal, pcVal, cbVal );
  pszVal[cbVal] = '\0';

  return pszVal;
}

// PCHAR fldVGetContentSubtype(PSZ pszValue, PULONG pcbVal)
//
// Reads subtype from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the subtype name and length of subtype name at pcbVal.

PCHAR fldVGetContentSubtype(PSZ pszValue, PULONG pcbVal)
{
  PCHAR      pcSubtype;

  if ( pszValue == NULL )
    return NULL;

  STR_SKIP_SPACES( pszValue );

  // Skip type.
  while( isalnum( *pszValue ) || ( *pszValue == '-' ) )
    pszValue++;

  if ( *pszValue != '/' )
    return NULL;

  pszValue++;
  pcSubtype = pszValue;

  // Look for end of subtype.
  while( isalnum( *pszValue ) || ( *pszValue == '-' ) )
    pszValue++;

  if ( pcSubtype == (PCHAR)pszValue )
    return NULL;

  *pcbVal = (PCHAR)pszValue - pcSubtype;   // Return length of subtype name.
  return pcSubtype;                        // Return pointer to subtype name.
}

// ULONG fldVGetContentSubtypeBuf(PSZ pszValue, ULONG cbBuf, PCHAR pcBuf)
//
// Reads subtype from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Subtype stores at pcBuf as ASCIIZ and returns length of name.

#if 0
ULONG fldVGetContentSubtypeBuf(PSZ pszValue, ULONG cbBuf, PCHAR pcBuf)
{
  ULONG      cbVal;
  PCHAR      pcVal = fldVGetContentSubtype( pszValue, &cbVal );

  if ( ( pcVal == NULL ) || ( cbVal >= cbBuf ) )
  {
    if ( cbBuf != 0 )
      pcBuf[0] = '\0';
    return 0;
  }

  memcpy( pcBuf, pcVal, cbVal );
  pcBuf[cbVal] = '\0';
  return cbVal;
}
#endif

// PSZ fldVGetContentSubtypeNew(PSZ pszValue, BOOL fUppercase)
//
// Reads subtype from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the allocated memory contains ASCIIZ subtype name.
// Pointer should be destroyed with free().

PSZ fldVGetContentSubtypeNew(PSZ pszValue, BOOL fUppercase)
{
  ULONG      cbVal;
  PCHAR      pcVal = fldVGetContentSubtype( pszValue, &cbVal );
  PSZ        pszVal;

  if ( pcVal == NULL )
    return NULL;

  pszVal = malloc( cbVal + 1 );
  if ( pszVal == NULL )
    return NULL;

  memcpy( pszVal, pcVal, cbVal );
  pszVal[cbVal] = '\0';
  if ( fUppercase )
    strupr( pszVal );

  return pszVal;
}

// PCHAR fldVGetContentType(PSZ pszValue, PULONG pcbVal)
//
// Reads content type from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the type name and length of type name at pcbVal.

PCHAR fldVGetContentType(PSZ pszValue, PULONG pcbVal)
{
  PCHAR      pcType;

  if ( pszValue == NULL )
    return NULL;

  STR_SKIP_SPACES( pszValue );
  pcType = pszValue;

  // Scan type.
  while( isalnum( *pszValue ) || ( *pszValue == '-' ) )
    pszValue++;

  if ( ( *pszValue != '/' ) || ( pszValue == (PSZ)pcType ) )
    return NULL;

  *pcbVal = (PCHAR)pszValue - pcType;      // Return length of the type name.
  return pcType;                           // Return pointer to the type name.
}

// PSZ fldVGetContentTypeNew(PSZ pszValue, BOOL fUppercase)
//
// Reads content type from value of Content-Type field:
//   type/subtype; param1=val1, param2=val2
// Returns pointer to the allocated memory contains ASCIIZ type name.
// Pointer should be destroyed with free().

PSZ fldVGetContentTypeNew(PSZ pszValue, BOOL fUppercase)
{
  ULONG      cbVal;
  PCHAR      pcVal = fldVGetContentType( pszValue, &cbVal );
  PSZ        pszVal;

  if ( pcVal == NULL )
    return NULL;

  pszVal = malloc( cbVal + 1 );
  if ( pszVal == NULL )
    return NULL;

  memcpy( pszVal, pcVal, cbVal );
  pszVal[cbVal] = '\0';
  if ( fUppercase )
    strupr( pszVal );

  return pszVal;
}

// PCHAR fldVGetValue(PSZ pszValue, PULONG pcbVal)
//
// Reads value of sructured field: "value; param1=val1, param2=val2".
// Returns pointer to the 'value' and length of 'value' at pcbVal.

PCHAR fldVGetValue(PSZ pszValue, PULONG pcbVal)
{
  PCHAR      pcVal;

  if ( pszValue == NULL )
    return NULL;

  STR_SKIP_SPACES( pszValue );
  pcVal = pszValue;

  // Scan value.
  while( !isspace( *pszValue ) && ( *pszValue != ';' ) && ( *pszValue != '\0' ) )
    pszValue++;

  if ( pszValue == (PSZ)pcVal )
    return NULL;

  *pcbVal = (PCHAR)pszValue - pcVal;       // Return length of value.
  return pcVal;                            // Return pointer to value.
}


/* *************************************************************** */
/*                                                                 */
/*                      Address list parser                        */
/*                                                                 */
/* *************************************************************** */
/*
  Main functions:
    VOID flgVAddrLstBegin(PIMFADDRPARSER pParser, ULONG ulFlags, PSZ pszInput,
                          PSZ pszCharset);
    VOID flgVAddrLstEnd(PIMFADDRPARSER pParser);
    BOOL flgVAddrLstNext(PIMFADDRPARSER pParser);

  RFC 822 syntax.

     destination =  "To"          ":" 1#address  ; Primary
                 /  "Resent-To"   ":" 1#address
                 /  "cc"          ":" 1#address  ; Secondary
                 /  "Resent-cc"   ":" 1#address
                 /  "bcc"         ":"  #address  ; Blind carbon
                 /  "Resent-bcc"  ":"  #address

     authentic   =   "From"       ":"   mailbox  ; Single author
                 / ( "Sender"     ":"   mailbox  ; Actual submittor
                     "From"       ":" 1#mailbox) ; Multiple authors

     resent-authentic =
                 =   "Resent-From"      ":"   mailbox
                 / ( "Resent-Sender"    ":"   mailbox
                     "Resent-From"      ":" 1#mailbox  )

     address     =  mailbox                      ; one addressee
                 /  group                        ; named list
     group       =  phrase ":" [#mailbox] ";"
     mailbox     =  addr-spec                    ; simple address
                 /  phrase route-addr            ; name & addr-spec
     route-addr  =  "<" [route] addr-spec ">"
     route       =  1#("@" domain) ":"           ; path-relative
     addr-spec   =  local-part "@" domain        ; global address
     local-part  =  word *("." word)             ; uninterpreted
     domain      =  sub-domain *("." sub-domain)
     sub-domain  =  domain-ref / domain-literal
     domain-literal =  "[" *(dtext / quoted-pair) "]"
     domain-ref  =  atom                         ; symbolic reference
     dtext       =  <any CHAR excluding "[",     ; => may be folded
                     "]", "\" & CR, & including
                     linear-white-space>
     quoted-pair =  "\" CHAR                     ; may quote any char
     phrase      =  1*word                       ; Sequence of words
     word        =  atom / quoted-string
     atom        =  1*<any CHAR except specials, SPACE and CTLs>
     CTL         =  <any ASCII control           ; (  0- 37,  0.- 31.)
                     character and DEL>          ; (    177,     127.)
     specials    =  "(" / ")" / "<" / ">" / "@"  ; Must be in quoted-
                 /  "," / ";" / ":" / "\" / <">  ;  string, to use
                 /  "." / "[" / "]"              ;  within a word.

(1) An 'encoded-word' may replace a 'text' token (as defined by RFC 822)
    in any Subject or Comments header field, any extension message
    header field, or any MIME body part field for which the field body
    is defined as '*text'.  An 'encoded-word' may also appear in any

    user-defined ("X-") message or body part header field.
                 /  "Subject"           ":"  *text
                 /  "Comments"          ":"  *text
    extension-field =
                  <Any field which is defined in a document
                   published as a formal extension to this
                   specification; none will have names beginning
                   with the string "X-">
*/

static BOOL _strSkipSubdomain(PSZ *ppszText)
{
  PSZ        pszText = *ppszText;
  BOOL       fMoved;

  if ( *pszText == '\0' )
    return FALSE;

  if ( *pszText != '[' )
    return utilStrSkipAtom( ppszText );

  while( TRUE )
  {
    pszText++;
    if ( *pszText == '\\' )
    {
      pszText++;
      if ( *pszText != '\0' )
        continue;
    }
    if ( strchr( "[]\\\r", *pszText ) != NULL )
      break;
  }

  if ( *pszText == ']' )
    pszText++;

  fMoved = *ppszText != pszText;
  if ( fMoved )
    *ppszText = pszText;

  return fMoved;
}

static BOOL _strSkipDomain(PSZ *ppszText)
{
  BOOL       fMoved = FALSE;

  while( _strSkipSubdomain( ppszText ) )
  {
    if ( *(*ppszText) != '.' )
      break;
    (*ppszText)++;
    fMoved = TRUE;
  }

  return fMoved;
}

// PSZ _strUnquoteFieldValue(LONG cbText, PCHAR pcText, PULONG pulLength)
//
// Unquotes text like 'w1 w2 "w3 \"w 4\" w5"' to 'w1 w2 w3 "w 4" w5'.
// Returns pointer to a unquoted text (should be destroyed by free()).
//
static PSZ _strUnquoteFieldValue(LONG cbText, PCHAR pcText, PULONG pulLength)
{
  PSZ        pszOutput  = NULL;
  ULONG      cbOutput   = 0;
  BOOL       fInQuotas  = FALSE;

  if ( cbText == -1 )
    cbText = STR_LEN( pcText );

  while( cbText != 0 )
  {
    if ( *pcText == '\"' )
    {
      fInQuotas = !fInQuotas;
      pcText++;
      cbText--;
      continue;
    }

    if ( fInQuotas && ( *pcText == '\\' ) )
    {
      pcText++;
      cbText--;
      if ( cbText == 0 )
        break;
    }


    if ( (cbOutput & 0x0F) == 0 )
    {
      PSZ    pszNew = realloc( pszOutput, cbOutput + 0x10 + 1 );

      if ( pszNew == NULL )
      {
        free( pszOutput );
        pszOutput  = 0;
        cbOutput   = 0;
        break;
      }
      pszOutput = pszNew;
    }

    pszOutput[cbOutput] = *pcText;
    cbOutput++;
    pcText++;
    cbText--;
  }

  if ( ( cbOutput == 0 ) || (cbOutput & 0x0F) != 0 )
  {
    PSZ    pszNext = realloc( pszOutput, cbOutput + 1 );

    if ( pszNext != NULL )
      pszOutput = pszNext;
  }

  pszOutput[cbOutput] = '\0';

  if ( pulLength != NULL )
    *pulLength = cbOutput;

  return pszOutput;
}

// PSZ _strDecWord(ULONG cbWord, PCHAR pcWord, PSZ pszToCode,
//                 PULONG pcbDecWord)
//
// Converts an encoed-word (like =?xxx?x?xxx?=) to the specified charset.
// Returns pointer to converted text (should be detroyed with free()) or NULL
// if word is not encoded-word.
//
static PSZ _strDecWord(ULONG cbWord, PCHAR pcWord, PSZ pszToCode,
                       PULONG pcbDecWord)
{
  PSZ        pszDecWord;
  PCHAR      pcEnd, pcCharset;
  ULONG      cbCharset;
  CHAR       chEncoding;
  iconv_t    ic;
  CHAR       acCharset[64];

  *pcbDecWord = 0;

  if ( ( cbWord < 11 ) ||
       ( *((PUSHORT)pcWord) != 0x3F3D /* '=?' */ ) ||
       ( *((PUSHORT)&pcWord[cbWord - 2]) != 0x3D3F /* '?=' */ ) )
    return NULL;

  // Get parts: charset "?" encoding "?" encoded-text
  //   charset -> acCharset, encoding -> chEncoding (Q/B),
  //   encoded-text -> pcWord/cbWord.

  pcEnd = &pcWord[cbWord - 2];
  pcWord += 2;
  pcCharset = pcWord;
  pcWord = memchr( pcCharset, '?', pcEnd - pcCharset );
  if ( ( pcWord == NULL ) || ( pcWord == pcCharset ) || ( pcWord[2] != '?' ) )
    return NULL;
  cbCharset = pcWord - pcCharset;

  if ( cbCharset >= sizeof(acCharset) )
    return FALSE;
  memcpy( acCharset, pcCharset, cbCharset );
  acCharset[cbCharset] = '\0';

  pcWord++;
  chEncoding = toupper( *pcWord );
  if ( ( chEncoding != 'Q' ) && ( chEncoding != 'B' ) )
    return NULL;
  pcWord += 2;

  if ( pcWord >= pcEnd )
    return NULL;
  cbWord = pcEnd - pcWord;

  // Quoted-printable or base64 decoding.

  if ( chEncoding == 'B' )
  {
    if ( !utilB64Dec( cbWord, pcWord, &cbWord, &pcWord ) )
      return NULL;
  }
  else if ( !utilQPDec( cbWord, pcWord, &cbWord, &pcWord ) )
    return NULL;

  // Convert.

  ic = iconv_open( pszToCode, acCharset );
  if ( ic == ((iconv_t)(-1)) )
  {
    debug( "iconv_open(\"%s\",\"%s\") failed", pszToCode, acCharset );
    free( pcWord );
    return NULL;
  }

  pszDecWord = utilIConv( ic, cbWord, pcWord, pcbDecWord );
  iconv_close( ic );
  free( pcWord );

  return pszDecWord;
}

// PCHAR _strDecodeFieldValue(LONG cbText, PCHAR pcText, PSZ pszToCode,
//                            PULONG pulLength)
//
// Converts filed values with plaint text and encoded-words to the text in
// specified charset.
//
static PCHAR _strDecodeFieldValue(LONG cbText, PCHAR pcText, PSZ pszToCode,
                                  PULONG pulLength)
{
  PCHAR      pcUnquoted;
  ULONG      cbUnquoted;
  PCHAR      pcSpaces, pcWord, pcWordEnd;
  PCHAR      pcDecWord, pcDecPlain;
  ULONG      cbDecWord, cbDecPlain;
  BOOL       fLastDecWord = TRUE;
  iconv_t    ic;
  PCHAR      pcNew, pcDecText = NULL;
  ULONG      cbChunk, cbDecText = 0;

  if ( pulLength != NULL )
    *pulLength = 0;

  // Get string with unquoted parts. For example:
  //   In: word1 "word <2> \"Word 3\"" =?ISO-8859-1?Q?word4?=
  //   Out: word1 word <2> "Word 3" =?ISO-8859-1?Q?word4?=
  pcUnquoted = _strUnquoteFieldValue( cbText, pcText, &cbUnquoted );
  if ( pcUnquoted == NULL )
    return NULL;

  ic = iconv_open( pszToCode, "US-ASCII" );
  if ( ic == ((iconv_t)(-1)) )
  {
    debug( "iconv_open(\"%s\",\"US-ASCII\") failed", pszToCode );
    return NULL;
  }

  pcSpaces = (PCHAR)pcUnquoted;
  while( *pcSpaces != '\0' )
  {
    // Take a pair: spaces, word.
    pcWord = pcSpaces;
    STR_SKIP_SPACES( pcWord );
    pcWordEnd = strstr( pcWord, "?=" );
    if ( pcWordEnd != NULL )
    {
      pcWordEnd += 2;
      // Try to decode word as "encoded-word" [RFC 2047] first.
      pcDecWord = _strDecWord( pcWordEnd - pcWord, pcWord, pszToCode, &cbDecWord );
    }
    else
    {
      pcWordEnd = pcWord;
      STR_MOVE_TO_SPACE( pcWordEnd );
      cbDecWord = 0;
      pcDecWord = NULL;
    }

    // Decode spaces if word is "encoded-word" or spaces and word otherwise.
    pcDecPlain = utilIConv( ic,
                            (pcDecWord == NULL ? pcWordEnd : pcWord) - pcSpaces,
                            pcSpaces, &cbDecPlain );

    if ( pcDecWord == NULL )
      fLastDecWord = FALSE;
    else
    {
      // We have decoded encoded-word ==> cbDecPlain is only spaces before
      // this word. We should not place any spaces between two encoded-words.
      if ( fLastDecWord )
        cbDecPlain = 0;
      fLastDecWord = TRUE;
    }

    // Expand memory for the output string.
    cbChunk = cbDecPlain + cbDecWord;
    pcNew = realloc( pcDecText, cbDecText + cbChunk + 2 ); /* 2 - for ZERO */
    pcDecText = pcNew;

    if ( cbDecPlain != 0 )
    {
      // Strore spaces or spaces and not-encoded-word.
      memcpy( &pcDecText[cbDecText], pcDecPlain, cbDecPlain );
      cbDecText += cbDecPlain;
    }

    if ( cbDecWord != 0 )
    {
      // Strore decoded encoded-word.
      memcpy( &pcDecText[cbDecText], pcDecWord, cbDecWord );
      cbDecText += cbDecWord;
    }

    if ( pcDecWord != NULL )
      free( pcDecWord );
    if ( pcDecPlain != NULL )
      free( pcDecPlain );

    pcSpaces = pcWordEnd;
  }

  iconv_close( ic );
  free( pcUnquoted );

  if ( pcDecText != 0 )
    *((PUSHORT)&pcDecText[cbDecText]) = 0;

  return pcDecText;
}

// Skips the local part of e-mail address.
static VOID _strSkipLocalPart(PSZ *ppszText)
{
  while( utilStrSkipWordAtom( ppszText ) )
  {
    if ( ( *(*ppszText) == '@' ) || ( *(*ppszText) != '.' ) )
      break;
    (*ppszText)++;
  }
}

// Skips the encoded word.
static BOOL _strSkipEncWord(PSZ *ppszText)
{
  PCHAR      pcWordEnd;

  if ( *((PUSHORT)(*ppszText)) != 0x3F3D /* '=?' */ )
    return FALSE;

  pcWordEnd = strstr( *ppszText, "?=" );
  if ( pcWordEnd == NULL )
    return FALSE;

  *ppszText = pcWordEnd + 2;

  return TRUE;
}


VOID flgVAddrLstBegin(PIMFADDRPARSER pParser, ULONG ulFlags, PSZ pszInput,
                      PSZ pszCharset)
{
  STR_SKIP_SPACES( pszInput );

  memset( pParser, 0, sizeof(IMFADDRPARSER) );
  pParser->pszInput    = pszInput;
  pParser->pszCharset  = pszCharset;
  pParser->ulFlags     = ulFlags & ~IMFAP_PUTPUT_MASK;
}

VOID flgVAddrLstEnd(PIMFADDRPARSER pParser)
{
  if ( pParser->pcName != NULL )
    free( pParser->pcName );

  if ( pParser->pcAddr != NULL )
    free( pParser->pcAddr );
}

BOOL flgVAddrLstNext(PIMFADDRPARSER pParser)
{
  PSZ        pszInput = pParser->pszInput;
  PCHAR      pcName = NULL;
  ULONG      cbName = 0;
  PCHAR      pcAddr = NULL;
  ULONG      cbAddr = 0;

  if ( (pParser->ulFlags & IMFAP_GROUPEND) != 0 )
    pParser->ulFlags &= ~(IMFAP_GROUP | IMFAP_GROUPBEGIN | IMFAP_GROUPEND);
  else
    pParser->ulFlags &= ~IMFAP_GROUPBEGIN;

  if ( *pszInput == '\0' )
    return FALSE;

  _strSkipLocalPart( &pszInput );

  if ( *pszInput == '@' )
  {
    // Next part is user@domain.dom

    pcAddr = (PCHAR)pParser->pszInput;
    pszInput++;
    _strSkipDomain( &pszInput );
    cbAddr = (PCHAR)pszInput - pcAddr;
  }
  else
  {
    pszInput = pParser->pszInput;
    while( _strSkipEncWord( &pszInput ) || utilStrSkipWordAtom( &pszInput ) )
    {
      if ( *pszInput == ':' )
        break;

      STR_SKIP_SPACES( pszInput );
      if ( *pszInput == '<' )
        break;
    }

    if ( *pszInput == '<' )
    {
      // Next part is: Name <user@domain.dom>

      pcName = pParser->pszInput;
      cbName = (PCHAR)pszInput - pcName;
      BUF_RTRIM( cbName, pcName );

      pszInput++;
      STR_SKIP_SPACES( pszInput );
      pcAddr = (PCHAR)pszInput;
      _strSkipLocalPart( &pszInput );
      if ( *pszInput == '@' )
      {
        pszInput++;
        _strSkipDomain( &pszInput );
      }
      cbAddr = (PCHAR)pszInput - pcAddr;
 
      while( *pszInput != '\0' )
      {
        if ( *pszInput == '>' )
        {
          pszInput++;
          break;
        }
        pszInput++;
      }
    }
    else if ( *pszInput == ':' )
    {
      // Next part is: Group name:

      pParser->ulFlags |= (IMFAP_GROUP | IMFAP_GROUPBEGIN);
      pcName = (PCHAR)pParser->pszInput;
      cbName = (PCHAR)pszInput - pcName;
      BUF_RTRIM( cbName, pcName );
      pszInput++;
      STR_SKIP_SPACES( pszInput );

      if ( *pszInput == ';' )
      {
        pParser->ulFlags |= IMFAP_GROUPEND;
        do
        {
          pszInput++;
          STR_SKIP_SPACES( pszInput );
        }
        while( *pszInput == ',' || *pszInput == ';' || *pszInput == '.' );
      }
    }
    else
    {
      pParser->ulFlags |= IMFAP_ERROR;
      return FALSE;
    }
  }

  if ( pcAddr != NULL )
    while( *pszInput != '\0' )
    {
      if ( ( (pParser->ulFlags | IMFAP_GROUP) != 0 ) && ( *pszInput == ';' ) )
      {
        pParser->ulFlags |= IMFAP_GROUPEND;
        do
        {
          pszInput++;
          STR_SKIP_SPACES( pszInput );
        }
        while( *pszInput == ',' || *pszInput == ';' );
        break;
      }

      if ( *pszInput == ',' )
      {
        do
        {
          pszInput++;
          STR_SKIP_SPACES( pszInput );
        }
        while( *pszInput == ',' );
        break;
      }

      pszInput++;
    }
/*
  printf( "Flags: 0x%X\n", pParser->ulFlags );
  printf( "Name:  (%s)\n", debugBufPSZ( pcName, cbName ) );
  printf( "Addr:  (%s)\n", debugBufPSZ( pcAddr, cbAddr ) );
  printf( "Left: (%s)\n", pszInput );
*/

  if ( (pParser->ulFlags & IMFAP_NONAMES) == 0 )
  {
    if ( pParser->pcName != NULL )
      free( pParser->pcName );
    pParser->pcName = _strDecodeFieldValue( cbName, pcName, pParser->pszCharset,
                                            &pParser->cbName );
  }

  if ( pParser->pcAddr != NULL )
  {
    free( pParser->pcAddr );
    pParser->cbAddr = 0;
    pParser->pcAddr = NULL;
  }

  if ( pcAddr != NULL )
  {
    iconv_t  ic = iconv_open( pParser->pszCharset, "US-ASCII" );

    if ( ic == ((iconv_t)(-1)) )
    {
      debug( "iconv_open(\"%s\",\"US-ASCII\") failed", pParser->pszCharset );
      pParser->pcAddr = malloc( cbAddr + 1 );
      if ( pParser->pcAddr != NULL )
      {
        memcpy( pParser->pcAddr, pcAddr, cbAddr );
        pParser->pcAddr[cbAddr] = '\0';
        pParser->cbAddr = cbAddr;
      }
    }
    else
    {
      pParser->pcAddr = utilIConv( ic, cbAddr, pcAddr, &pParser->cbAddr );
      iconv_close( ic );
    }
  }

  pParser->pszInput = pszInput;

  return TRUE;
}


/* *************************************************************** */
/*                                                                 */
/*                     Search text in fields                       */
/*                                                                 */
/* *************************************************************** */
/*
  Main functions:
    BOOL fldIsContainsSubstr(PFIELD pFields, PSZ pszField, BOOL fAddrOnly,
                             PSZ pszText, PSZ pszCharset);
    BOOL fldHdrIsContainsSubstr(PFIELD pFields, PSZ pszText, PSZ pszCharset);
*/

// Finds substring pszICUpStr (internal charset, uppercase) into the field's
// value according to the type of the field (address list, structured or plain
// text). Returns TRUE if substring has been found in the field's value.
static BOOL _fldIsContainsSubstr(PFIELD pField, BOOL fAddrOnly, PSZ pszICUpStr)
{
  LONG       lIdx;
  PSZ        pszVal = &pField->acField[pField->cbName + 1];
  BOOL       fFound = FALSE;

  STR_SKIP_SPACES( pszVal );

  lIdx = utilStrWordIndex( "To Resent-To cc Resent-cc bcc Resent-bcc From "
                           "Sender From Resent-From Resent-Sender Resent-From",
                           pField->cbName, pField->acField );
  if ( lIdx != -1 )
  {
    // Search in address list.

    IMFADDRPARSER        stParser;

    flgVAddrLstBegin( &stParser, fAddrOnly ? IMFAP_NONAMES : 0, pszVal,
                      "UTF-16LE" );
    while( flgVAddrLstNext( &stParser ) )
    {
      if ( ( ( stParser.pcName != NULL ) &&
             ( UniStrstr( UniStrupr( (UniChar *)stParser.pcName ),
                          (UniChar *)pszICUpStr ) != NULL ) )
           ||
           ( ( stParser.pcAddr != NULL ) &&
             ( UniStrstr( UniStrupr( (UniChar *)stParser.pcAddr ),
                          (UniChar *)pszICUpStr ) != NULL ) ) )
      {
        fFound = TRUE;
        break;
      }
    }
    flgVAddrLstEnd( &stParser );
  }
  else
  {
    ULONG    cbVal;
    PCHAR    pcVal;

    pcVal = _strDecodeFieldValue( -1, pszVal, "UTF-16LE", &cbVal );
    if ( pcVal != NULL )
    {
      fFound = UniStrstr( UniStrupr( (UniChar *)pcVal ),
                          (UniChar *)pszICUpStr ) != NULL;
      free( pcVal );
    }
  }

  return fFound;
}

BOOL fldIsContainsSubstr(PFIELD pFields, PSZ pszField, BOOL fAddrOnly,
                         PSZ pszText, PSZ pszCharset)
{
  PFIELD     pField;
  BOOL       fFound;

  pField = _fldFind( pFields, pszField );
  if ( pField == NULL )
    return FALSE;

  if ( pszText == NULL )
  /* [RFC 3501] 6.4.4. SEARCH Command; HEADER <field-name> <string>.
     If the string to search is zero-length, this matches all messages that
     have a header line with the specified field-name regardless of
     the contents.
  */
    return TRUE;

  if ( pszCharset != NULL )
  {
    // Convert given substring to uppercase and internal charset.
    pszText = utilStrToUTF16Upper( pszText, pszCharset );
    if ( pszText == NULL )
      return FALSE;
  }

  if ( *((PUSHORT)pszText) == 0 )
    // Empty string. See comment with [RFC 3501] above.
    fFound = TRUE;
  else
    // Find substring in the value of field.
    fFound = _fldIsContainsSubstr( pField, fAddrOnly, pszText );

  if ( pszCharset != NULL )
    free( pszText );

  return fFound;
}

BOOL fldHdrIsContainsSubstr(PFIELD pFields, PSZ pszText, PSZ pszCharset)
{
  PFIELD     pField;
  BOOL       fFound = FALSE;

  if ( pszCharset != NULL )
  {
    // Convert given substring to uppercase and internal charset.
    pszText = utilStrToUTF16Upper( pszText, pszCharset );
    if ( pszText == NULL )
      return FALSE;
  }

  // Scan all fields and find substring.
  for( pField = pFields; pField != NULL; pField = pField->pNext )
  {
    if ( _fldIsContainsSubstr( pField, FALSE, pszText ) )
    {
      fFound = TRUE;
      break;
    }
  }

  if ( pszCharset != NULL )
    free( pszText );

  return fFound;
}

/* *************************************************************** */
/*                                                                 */
/*                         Message format                          */
/*                                                                 */
/* *************************************************************** */

typedef struct _PARTSTAT {
  ULONG      ulLines;
  ULLONG     ullBytes;
} PARTSTAT, *PPARTSTAT;

// Returns FALSE if end of file or close boundary was encountered and TRUE id
// part-separate boundary was encountered. If pCtx is not NULL it will be
// filled with section context. Pointer pStat may be NULL.
static BOOL _fileReadSectText(FILE *pfMsg, PSZ pszBoundary,
                              PCTX pCtx, PPARTSTAT pStat)
{
  ULONG      cbBoundary = STR_LEN( pszBoundary );
  CHAR       acBuf[1032];
  PVOID      pEnd = &acBuf[cbBoundary + 2];
  ULONG      cbBuf;
  BOOL       fPartSeparator = FALSE;

  if ( pStat != NULL )
    memset( pStat, 0, sizeof(PARTSTAT) );

  while( fgets( acBuf, sizeof(acBuf) - 3, pfMsg ) != NULL )
  {
    if ( ( pszBoundary != NULL ) &&
         ( acBuf[0] == '-' && acBuf[1] == '-' ) &&
         ( memcmp( &acBuf[2], pszBoundary, cbBoundary ) == 0 ) )
    {
      if ( *((PCHAR)pEnd) == '\n' )
      {
        fPartSeparator = TRUE;
        break;
      }

      if ( *((PULONG)(PVOID)pEnd) == 0x000A2D2D ) // '--\n\0'
        break;
    }

    cbBuf = strlen( acBuf );

    if ( pCtx != NULL )
    {
      // Store context.

      if ( ( cbBuf != 0 ) && ( acBuf[cbBuf - 1] == '\n' ) )
      {
        // Trailing \n -> \r\n
// [Not good for -Wall]    *((PULONG)&acBuf[cbBuf - 1]) = 0x00000A0D;
        acBuf[cbBuf - 1] = '\r';
        acBuf[cbBuf]     = '\n';
        acBuf[cbBuf + 1] = '\0';
        acBuf[cbBuf + 2] = '\0';
      }
      ctxWrite( pCtx, -1, acBuf );
    }

    if ( pStat != NULL )
    {
      // Store statistics.

      pStat->ulLines++;
      pStat->ullBytes += cbBuf + 1;
    }
  }

  return fPartSeparator;
}


static PCTX _fileReadSect(FILE *pfMsg, PSZ pszBoundary, PFIELD pFields,
                          ULONG ulFlags, PSZ pszFields)
{
  PCTX       pCtx = ctxNew();

  if ( pCtx == NULL )
    return NULL;

  if ( (ulFlags & IMFFL_HEADER) != 0 )
  {
    while( ( pFields != NULL ) && ( pFields->cbName != 0 )  )
    {
      if ( ( utilStrWordIndex( pszFields, pFields->cbName, pFields->acField )
             != -1 ) == ( (ulFlags & IMFFL_NOTFIELDS) == 0 ) )
        ctxWrite( pCtx, -1, pFields->acField );

      pFields = pFields->pNext;
    }

    if ( pFields != NULL )
      // An empty line is present in the header.
      ctxWrite( pCtx, 2, "\r\n" );
  }

  if ( (ulFlags & IMFFL_TEXT) != 0 )
    _fileReadSectText( pfMsg, pszBoundary, pCtx, NULL );

  return pCtx;
}

#define _ctxWriteQuotedStr(__pCtx, __pszBuf) \
  _ctxWriteQuotedBuf(__pCtx, -1, __pszBuf)

BOOL _ctxWriteQuotedBuf(PCTX pCtx, LONG cbBuf, PCHAR pcBuf)
{
  if ( !ctxWrite( pCtx, 1, "\"" ) )
    return FALSE;

  if ( cbBuf == -1 )
    cbBuf = STR_LEN( pcBuf );

  for( ; cbBuf != 0; cbBuf--, pcBuf++ )
  {
    if ( ( ( *pcBuf == '\\' ) || ( *pcBuf == '\"' ) ) &&
         !ctxWrite( pCtx, 1, "\\" ) )
      return FALSE;

    if ( ( ( *pcBuf != '\r' ) && ( *pcBuf != '\n' ) ) &&
         !ctxWrite( pCtx, 1, pcBuf ) )
      return FALSE;
  }

  return ctxWrite( pCtx, 1, "\"" );
}

// BOOL _ctxWriteAddrStruct(PCTX pCtx, PSZ *ppszNameAddr)
//
// Writes to the pCtx object email address like:
//   "Kolobok" <ball@road.forest.dom>
// in next form: ("Kolobok" NIL "ball" "road.forest.dom") .

static BOOL _ctxWriteAddrStruct(PCTX pCtx, PSZ *ppszNameAddr)
{
  PSZ        pszNameAddr = *ppszNameAddr;
  PSZ        pszDispName = NULL;
  PSZ        pszLocal, pszDomain;
  PCHAR      pcEnd;

l00:
  STR_SKIP_SPACES( pszNameAddr );

  if ( *pszNameAddr == '"' )
  {
    utilStrCutComp( &pszNameAddr, &pszDispName );
    if ( *pszNameAddr == ':' )
    {
      pszNameAddr++;
      goto l00;
    }

    STR_SKIP_SPACES( pszNameAddr );
    pszLocal = pszNameAddr;
  }
  else if ( *pszNameAddr != '<' )
  {
    pszLocal = strchr( pszNameAddr, '<' );
    if ( pszLocal == NULL )
      pszLocal = pszNameAddr;
    else
    {
      pszDispName = pszNameAddr;
      pcEnd = pszLocal;

      while( (pcEnd > (PCHAR)pszDispName) && isspace( *(pcEnd - 1) ) )
        pcEnd--;
      *pcEnd = '\0';
    }
  }
  else
    pszLocal = pszNameAddr;

  if ( *pszLocal == '<' )
    pszLocal++;

  for( pszDomain = pszLocal;
       *pszDomain != '@' && *pszDomain != '\0' && !isspace( *pszDomain );
       pszDomain++ );

  if ( *pszDomain != '@' )
  {
    *ppszNameAddr = pszDomain;
    return FALSE;
  }

  *pszDomain = '\0';
  pszDomain++;

  for( pcEnd = pszDomain; isalnum( *pcEnd ) || *pcEnd == '.' || *pcEnd == '-';
       pcEnd++ );
  if ( *pcEnd != '\0' )
  {
    *pcEnd = '\0';
    pcEnd++;
  }
  *ppszNameAddr = pcEnd;

  ctxWrite( pCtx, 1, "(" );
  if ( ( pszDispName == NULL ) || ( *pszDispName == '\0' ) )
    ctxWrite( pCtx, 3, "NIL" );
  else
    _ctxWriteQuotedStr( pCtx, pszDispName );
  ctxWrite( pCtx, 5, " NIL " );
  _ctxWriteQuotedStr( pCtx, pszLocal );
  ctxWrite( pCtx, 1, " " );
  _ctxWriteQuotedStr( pCtx, pszDomain );
  ctxWrite( pCtx, 1, ")" );

  return TRUE;
}

// BOOL _ctxWriteAddrStructList(PCTX pCtx, PSZ pszEMails)
//
// Writes list of addresses like
//   "First user" <abc@dom.com>, Second User <Aaa@dom1.com>
// to the pCtx object in form:
//   (("First user" NIL "abc" "dom.com")("Second User" NIL "Aaa" "dom1.com")).
// It writes 'NIL' if pszEMails is NULL or points to the empty string.

static VOID _ctxWriteAddrStructList(PCTX pCtx, PSZ pszEMails)
{
  if ( ( pszEMails == NULL ) || ( *pszEMails == '\0' ) )
  {
    ctxWrite( pCtx, 3, "NIL" );
    return;
  }

  ctxWrite( pCtx, 1, "(" );
  do
  {
    if ( !_ctxWriteAddrStruct( pCtx, &pszEMails ) )
      return;

    STR_SKIP_SPACES( pszEMails );
    if ( *pszEMails == ',' )
      pszEMails++;
  }
  while( *pszEMails != '\0' );
  ctxWrite( pCtx, 1, ")" );
}


PCTX imfGetBody(PSZ pszFile, PIMFBODYPARAM pBody)
{
  FILE       *pfMsg;
  PFIELD     pFields = NULL;
  PSZ        pszVal, pszBoundary = NULL;
  ULONG      ulDeep = 0;
  ULONG      ulIdx;
  PCTX       pCtx = NULL;
  ULONG      ulPartType;

  pfMsg = fopen( pszFile, "rt" );
  if ( pfMsg == NULL )
  {
    debug( "Can't open %s", pszFile );
    return NULL;
  }

  while( TRUE )
  {
    if ( pFields != NULL )
      fldFree( pFields );

    // Read header fields of the message or of the part.
    pFields = fldRead( pfMsg, pszBoundary );

    // Is all nested part numbers passed?
    if ( ulDeep == pBody->cPart )
    {
      // Part is found: read section according to the set flags pBody->ulFlags.
      pCtx = _fileReadSect( pfMsg, pszBoundary, pFields, pBody->ulFlags,
                            pBody->pszFields );
      break;
    }

    // Check header.

    pszVal = fldFind( pFields, "Content-Type" );
    if ( pszVal == NULL )
      ulPartType = 0;
    else if ( memicmp( pszVal, "message/rfc822", 14 ) == 0 )
      ulPartType = 1;
    else if ( memicmp( pszVal, "multipart/", 10 ) == 0 )
      ulPartType = 2;
    else
      ulPartType = 0;

    if ( ulPartType == 0 )
    {
      if ( ( pBody->cPart == 1 ) && ( pBody->paPart[0] == 1 ) )
      {
        /* Requested BODY[1].

           [RFC 3501, 6.4.5.  FETCH Command]:
           Every message has at least one part number.  Non-[MIME-IMB]
           messages, and non-multipart [MIME-IMB] messages with no
           encapsulated message, only have a part 1.
        */
        pCtx = _fileReadSect( pfMsg, pszBoundary, pFields, IMFFL_TEXT, NULL );
      }
      else
        debug( "No content type on level %u", ulDeep );

      break;
    }

    if ( ulPartType == 1 )       // message/rfc822
    {
      // Content of "message/rfc822" can have only one sub-part. We have read
      // header on the part and now on the beginig of encapsulated message.

      if ( pBody->paPart[ulDeep] != 1 )
      {
        debug( "Part %u on level %u. This is message/rfc822, part should be 1",
               pBody->paPart[ulDeep], ulDeep );
        break;
      }
    }
    else
    {
      // Read message (move read position) to the next specified part.

      if ( pszBoundary != NULL )
      {
        free( pszBoundary );
        pszBoundary = NULL;
      }

      if ( ulPartType == 2 )     // multipart/
        pszBoundary = fldVGetParamNew( pszVal, "boundary" );

      if ( pszBoundary == NULL )
      {
        // No more nested parts.
        debug( "No more nested parts" );
        break;
      }
//    debug( "Boundary: %s", pszBoundary );

      // Skip parts up to pBody->paPart[ulDeep]

//    debug( "Skip %u parts on level %u", pBody->paPart[ulDeep], ulDeep );
      for( ulIdx = pBody->paPart[ulDeep]; ulIdx > 0; ulIdx-- )
      {
        if ( !_fileReadSectText( pfMsg, pszBoundary, NULL, NULL ) )
          break;
      }
      if ( ulIdx != 0 )
      {
        debug( "Part %u on level %u is not found", pBody->paPart[ulDeep], ulDeep );
        break;
      }
    }

    ulDeep++;
  }

  if ( pFields != NULL )
    fldFree( pFields );

  if ( pszBoundary != NULL )
    free( pszBoundary );

  fclose( pfMsg );

  if ( pCtx != NULL )
  {
    ULLONG   cbCtx = ctxQuerySize( pCtx );

    // Set "start" and "length" output values.

    if ( (pBody->ulFlags & IMFFL_PSTART) == 0 )
      pBody->ullStart = 0;
    else if ( pBody->ullStart > cbCtx )
      pBody->ullStart = cbCtx;

    cbCtx -= pBody->ullStart;
    if ( ( (pBody->ulFlags & IMFFL_PLENGTH) == 0 ) ||
         ( pBody->ullLength >= cbCtx ) )
      pBody->ullLength = cbCtx;

    ctxSetReadPos( pCtx, CTX_RPO_BEGIN, pBody->ullStart );
  }

  return pCtx;
}

/*
   PCTX imfGetEnvelope(PSZ pszFile)

   [RFC 3501, 7.4.2.  FETCH Response]
        A parenthesized list that describes the envelope structure of a
        message.
        The fields of the envelope structure are in the following
        order: date, subject, from, sender, reply-to, to, cc, bcc,
        in-reply-to, and message-id.  The date, subject, in-reply-to,
        and message-id fields are strings.  The from, sender, reply-to,
        to, cc, and bcc fields are parenthesized lists of address
        structures.

   Address: (("Name on Email Account" NIL "mbox" "domain.com"))
*/

static VOID _ctxWriteEnvelope(PCTX pCtx, PFIELD pFields)
{
  static struct _ENVFIELD {
    PSZ      pszName;
    BOOL     fAddr;
  }          aEnvFields[] =
    { { "date", FALSE }, { "subject", FALSE }, { "from", TRUE },
      { "sender", TRUE }, { "reply-to", TRUE }, { "to", TRUE }, { "cc", TRUE },
      { "bcc", TRUE }, { "in-reply-to", FALSE }, { "message-id", FALSE } };

  PSZ        pszVal;
  ULONG      ulIdx;

  ctxWrite( pCtx, 1, "(" );

  for( ulIdx = 0; ulIdx < ARRAYSIZE(aEnvFields); ulIdx++ )
  {
    if ( ulIdx != 0 )
      ctxWrite( pCtx, 1, " " );

    pszVal = fldFind( pFields, aEnvFields[ulIdx].pszName );
    if ( pszVal == NULL )
      ctxWrite( pCtx, 3, "NIL" );
    else if ( aEnvFields[ulIdx].fAddr )
      _ctxWriteAddrStructList( pCtx, pszVal );
    else
      _ctxWriteQuotedStr( pCtx, pszVal );
  }

  ctxWrite( pCtx, 1, ")" );
}

PCTX imfGetEnvelope(PSZ pszFile)
{
  FILE       *pfMsg;
  PFIELD     pFields;
  PCTX       pCtx = ctxNew();

  if ( pCtx == NULL )
    return NULL;

  pfMsg = fopen( pszFile, "rt" );
  if ( pfMsg == NULL )
  {
    debug( "Can't open %s", pszFile );
    ctxFree( pCtx );
    return NULL;
  }

  // Read header fields of the message or of the part.
  pFields = fldRead( pfMsg, NULL );

  fclose( pfMsg );

  _ctxWriteEnvelope( pCtx, pFields );

  fldFree( pFields );

  return pCtx;
}


/*
    PCTX imfGetBodyStruct(PSZ pszFile, BOOL fExtData)

  multipart body
  --------------

  (
    (
      "TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 1152 23
    )
    (
      "TEXT" "PLAIN" ("CHARSET" "US-ASCII" "NAME" "cc.diff")
      "<960723163407.20117h@cac.washington.edu>" "Compiler diff"
      "BASE64" 4554 73
    )
    "MIXED"
    [ExtData:
      body parameter list: ("foo" "bar" "baz" "rag" ...)
      body disposition:    ("inline" ("filename" "letter.html"))            [DISPOSITION], Content-Disposition
      body language:       ("..." "..." ...)                [LANGUAGE-TAGS] - <Accept-Language: ru-RU, en-US> <Content-Language: ru-RU> ???
      body location:       "location"                       [LOCATION]
    ]
  )


  1 related image, and 2 attachments:
  (
    (
      ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7bit" 36 2)
      (
        ("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "8bit" 344 12)
        ("IMAGE" "JPEG" ("NAME" "starfish.jpg") "<part1.06050003.00040008@chilkatsoft.com>" NIL "base64" 8538 NIL ("inline" ("FILENAME" "starfish.jpg"))) 
        "RELATED"
        ("BOUNDARY" "------------090406030500000101040309") NIL NIL
      )
      "ALTERNATIVE"
      ("BOUNDARY" "------------060809010805020700040701") NIL NIL
    )
    ("TEXT" "XML" ("NAME" "resp.xml") NIL NIL "7bit" 328 9 NIL ("attachment" ("FILENAME" "resp.xml")))
    ("IMAGE" "JPEG" ("NAME" "red.jpg") NIL NIL "base64" 278322 NIL ("attachment" ("FILENAME" "red.jpg"))) 
    "MIXED"
    ("BOUNDARY" "------------040506060907070101020201") NIL NIL
  )


  (
    (
      ( "TEXT" "PLAIN" ("charset" "UTF-8") NIL NIL "7bit" 4 1 )
      ( "TEXT" "HTML" ("charset" "UTF-8") NIL NIL "7bit" 4 1 )
      "ALTERNATIVE"
      ("boundary" "----=_Part_18_28612235.1384442157276")
    )
    ("IMAGE" "PNG" ("name" "Screen Shot 2013-11-14 at 4.15.41 PM.png") NIL NIL "base64" 13858 NIL ("attachment" ("filename" "Screen Shot 2013-11-14 at 4.15.41 PM.png" "size" "10127")))
    "MIXED"
    ("boundary" "----=_Part_17_22578400.1384442157276")
  )


  non-multipart body
  ------------------

  (
    "TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 1152 23
  or
    <Basic fields:
      body type:           "A string giving the content media type name"
      body subtype:        "..."
      body parameter list: ("attr" "val" "baz" "rag" ...)
      body id:             "..."
      body description:    "content description"
      body encoding:       "content transfer encoding"
      body size:           size of the body
    >
    [Fields for MESSAGE/RFC822:
      the envelope structure,
      body structure,
      size in text lines
    ]
    [Filelds for type TEXT/:
      the size of the body in text lines
    ]
    [ExtData:
      body MD5:            "md5"                    [MD5]
      body disposition:    (disposition ??? ...)
      body language:       ("..." "..." ...)
      body location:       "location"
    ]
  )
*/

static BOOL _scanBodyStruct(PCTX pCtx, FILE *pfMsg, PSZ pszBoundary,
                            BOOL fExtData)
{
  PFIELD     pFields;
  BOOL       fEnd;
  PSZ        pszVal, pszType, pszSubtype;

  if ( utilQueryStackSpace() < 2048 )
    // Not enough stack space.
    return FALSE;

  pFields = fldRead( pfMsg, pszBoundary );
  if ( pFields == NULL )
    return FALSE;

  ctxWrite( pCtx, 1, "(" );

  pszVal = fldFind( pFields, "Content-Type" );
  pszType = fldVGetContentTypeNew( pszVal, TRUE );
  pszSubtype = fldVGetContentSubtypeNew( pszVal, TRUE );

  if ( ( pszType != NULL ) && ( strcmp( pszType, "MULTIPART" ) == 0 ) )
  {
    PSZ      pszBoundary2 = fldVGetParamNew( pszVal, "boundary" );

    // Go to first sub-part.
    _fileReadSectText( pfMsg, pszBoundary2, NULL, NULL );

    // Read all sub-parts and store results at the context.
    while( _scanBodyStruct( pCtx, pfMsg, pszBoundary2, fExtData ) );

    // Write result for this multipart.
    ctxWrite( pCtx, 2, " \"" );
    if ( pszSubtype != NULL )
      ctxWrite( pCtx, -1, strupr( pszSubtype ) );
    ctxWrite( pCtx, 1, "\"" );
    if ( fExtData )
    {
      ctxWrite( pCtx, -1, " (\"BOUNDARY\" \"" );
      ctxWrite( pCtx, -1, pszBoundary2 );
      ctxWrite( pCtx, 2, "\")" );
    }
    if ( pszBoundary2 != NULL )
      free( pszBoundary2 );

    // Skip boundary of this multipart.
    fEnd = _fileReadSectText( pfMsg, pszBoundary, NULL, NULL );
  }
  else
  {
    PARTSTAT stStat;
    PSZ      pszCharset = fldVGetParamNew( pszVal, "charset" );
    PSZ      pszName = fldVGetParamNew( pszVal, "name" );
    LONG     lSaveFPos;

    _ctxWriteQuotedStr( pCtx, pszType == NULL ? (PSZ)"TEXT" : pszType );
    ctxWrite( pCtx, 1, " " );
    _ctxWriteQuotedStr( pCtx, pszSubtype );

    if ( ( pszCharset != NULL ) || ( pszName != NULL ) )
    {
      ctxWrite( pCtx, 2, " (" );
      if ( pszCharset != NULL )
      {
        ctxWrite( pCtx, -1, "\"CHARSET\" " );
        _ctxWriteQuotedStr( pCtx, pszCharset );
        free( pszCharset );
      }

      if ( pszName != NULL )
      {
        if ( pszCharset != NULL )
          ctxWrite( pCtx, 1, " " );
        ctxWrite( pCtx, -1, "\"NAME\" " );
        _ctxWriteQuotedStr( pCtx, pszName );
        free( pszName );
      }
      ctxWrite( pCtx, 1, ")" );
    }
    else
      ctxWrite( pCtx, 4, " NIL" );

    ctxWrite( pCtx, 9, " NIL NIL " );

    pszVal = fldFind( pFields, "Content-Transfer-Encoding" );

    if ( pszVal != NULL )
      _ctxWriteQuotedStr( pCtx, pszVal );
    else
      ctxWrite( pCtx, 3, "NIL" );

    lSaveFPos = ftell( pfMsg ); 
    fEnd = _fileReadSectText( pfMsg, pszBoundary, NULL, &stStat );

    ctxWriteFmt( pCtx, " %llu", stStat.ullBytes );

    if ( ( pszType == NULL ) || ( strcmp( pszType, "TEXT" ) == 0 ) )
    {
      ctxWriteFmt( pCtx, " %u", stStat.ulLines );
    }
    else if ( ( strcmp( pszType, "MESSAGE" ) == 0 ) &&
              ( pszSubtype != NULL ) &&
              ( strcmp( pszSubtype, "RFC822" ) == 0 ) )
    {
      // Fields for MESSAGE/RFC822: envelope structure, body structure, lines
      PFIELD     pFields;

      fseek( pfMsg, lSaveFPos, SEEK_SET ); 
      pFields = fldRead( pfMsg, pszBoundary );
      if ( pFields != NULL )
      {
        ctxWrite( pCtx, 1, " " );
        _ctxWriteEnvelope( pCtx, pFields );
        fldFree( pFields );
      }

      fseek( pfMsg, lSaveFPos, SEEK_SET ); 
      ctxWrite( pCtx, 1, " " );
      lSaveFPos = ftell( pfMsg ); 
      _scanBodyStruct( pCtx, pfMsg, pszBoundary, fExtData );

      fseek( pfMsg, lSaveFPos, SEEK_SET ); 
      fEnd = _fileReadSectText( pfMsg, pszBoundary, NULL, &stStat );
      ctxWriteFmt( pCtx, " %u", stStat.ulLines );
    }

    if ( fExtData )
    {
      pszVal = fldFind( pFields, "Content-Disposition" );
      if ( pszVal != NULL )
      {
        static PSZ aDispParam[] = { "filename", "creation-date",
                                    "modification-date", "read-date", "size" };
        ULONG  ulIdx, cbVal;
        PCHAR  pcVal = fldVGetValue( pszVal, &cbVal );
        BOOL   fDispParam = FALSE;

        ctxWrite( pCtx, 6, " NIL (" );
        _ctxWriteQuotedBuf( pCtx, cbVal, pcVal );

        for( ulIdx = 0; ulIdx < ARRAYSIZE(aDispParam); ulIdx++ )
        {
          pcVal = fldVGetParam( pszVal, aDispParam[ulIdx], &cbVal );
          if ( pcVal != NULL )
          {
            ctxWriteFmt( pCtx, "%s\"%s\" ",
                         !fDispParam ? " (" : " ", aDispParam[ulIdx] );
            fDispParam = TRUE;
            _ctxWriteQuotedBuf( pCtx, cbVal, pcVal );
          }
        }

        if ( fDispParam )
          ctxWrite( pCtx, 1, ")" );
        ctxWrite( pCtx, 1, ")" );
      }
    } // if ( fExtData )
  }

  if ( pszType != NULL )
    free( pszType );

  if ( pszSubtype != NULL )
    free( pszSubtype );

  ctxWrite( pCtx, 1, ")" );
  fldFree( pFields );

  return fEnd;
}

PCTX imfGetBodyStruct(PSZ pszFile, BOOL fExtData)
{
  FILE       *pfMsg;
  PCTX       pCtx = ctxNew();

  if ( pCtx == NULL )
    return NULL;

  pfMsg = fopen( pszFile, "rt" );
  if ( pfMsg == NULL )
  {
    debug( "Can't open %s", pszFile );
    ctxFree( pCtx );
    return NULL;
  }

  _scanBodyStruct( pCtx, pfMsg, NULL, fExtData );

  fclose( pfMsg );

  return pCtx;
}


/* *************************************************************** */

// _SINP_NOTFOUND  Sub-part scanned, text was not found.
#define _SINP_NOTFOUND           0
// _SINP_ENDOFPART Not found, eof or close separator (boundary) was encountered.
#define _SINP_ENDOFPART          1
// _SINP_FOUND     Text has been found.
#define _SINP_FOUND              2

static ULONG _searchInTextPart(FILE *pfMsg, PFIELD pFields, PSZ pszICUpStr,
                               PSZ pszBoundary)
{
/*
  Used fields:
    Content-Type (for ex.: text/plain; charset="us-ascii"),
    Content-Transfer-Encoding (for ex.: quoted-printable).

  [TODO]: What about HTML, CRLFs, space sequences? Or we don't need to handle
          such difficult situations?
*/
  ULONG      cbBuf;
  CHAR       acBuf[1036];
  ULONG      cbReadBuf;
  PCHAR      pcReadBuf;

  CHAR       acTXDecBuf[1036];
  ULONG      cbTXDecBuf;
  PCHAR      pcTXDecBuf;
  ULONG      cbTXDecBufF = sizeof(acTXDecBuf);
  PCHAR      pcTXDecBufF = acTXDecBuf;

  CHAR       acICUpBuf[1036 * 2 + 2];
  ULONG      cbICUpBuf;
  PCHAR      pcICUpBuf;

  ULONG      cbBoundary = STR_LEN( pszBoundary );
  PSZ        pszVal = fldFind( pFields, "Content-Type" );
//  ULONG      cbSubtype;
//  PCHAR      pcSubtype = fldVGetContentSubtype( pszVal, &cbSubtype );
//  BOOL       fHTML;
  PSZ        pszCharset;
  LONG       lTXEnc;   // -1 - plain (7bit?), 0 - quoted-printable, 1 - base64.
  ULONG      ulRC = _SINP_ENDOFPART;
  QPDEC      stQPDec;
  B64DEC     stB64Dec;
  iconv_t    ic;
  ULONG      cbICUpStr = UniStrlen( (UniChar *)pszICUpStr ) * 2;

  // The converted text in uppercase will accumulate in this buffer.
  // Substring search is performed when the buffer is full (or part is readed).
  ULONG      cbICUpBlock = MAX( 1024 * 130, cbICUpStr * 2 );
  PCHAR      pcICUpBlock = malloc( cbICUpBlock + 2 ); // 2 - for trailing ZERO.
  ULONG      ulICUpBlockPos = 0;

  if ( pcICUpBlock == NULL )
  {
    debugCP( "Not enough memory" );
    return _SINP_ENDOFPART;
  }

//  fHTML = ( cbSubtype == 4 ) && ( memicmp( pcSubtype, "html", 4 ) == 0 );
  pszCharset = fldVGetParamNew( pszVal, "charset" );
  lTXEnc = utilStrWordIndex( "quoted-printable base64", -1,
                             fldFind( pFields, "Content-Transfer-Encoding" ) );

  ic = iconv_open( "UTF-16LE",
                   pszCharset == NULL ? (PSZ)"US-ASCII" : pszCharset );
  if ( ic == ((iconv_t)(-1)) )
  {
    debug( "iconv_open(\"%s\",\"%s\") failed", "UTF-16LE",
           pszCharset == NULL ? (PSZ)"US-ASCII" : pszCharset );
    free( pcICUpBlock );
    return _SINP_ENDOFPART;
  }

  switch( lTXEnc )
  {
    case 0: utilQPDecBegin( &stQPDec );   break;
    case 1: utilB64DecBegin( &stB64Dec ); break;
  }

  while( ( ulRC == _SINP_ENDOFPART ) &&
         ( fgets( acBuf, sizeof(acBuf) - 4, pfMsg ) != NULL ) )
  {
    // Compare read string with part separator.
    if ( ( cbBoundary != 0 ) && ( acBuf[0] == '-' && acBuf[1] == '-' ) &&
         ( memcmp( &acBuf[2], pszBoundary, cbBoundary ) == 0 ) )
    {
      PVOID  pEnd = &acBuf[cbBoundary + 2];

      if ( *((PCHAR)pEnd) == '\n' )
      {
        ulRC = _SINP_NOTFOUND;
        break;
      }

      if ( *((PULONG)(PVOID)pEnd) == 0x000A2D2D ) // '--\n\0'
        break;
    }

    cbBuf = strlen( acBuf );
    if ( cbBuf == 0 )
    {
      debugCP( "WTF?" );
      continue;
    }

    // Replace trailing \n by CRLF.
    if ( acBuf[cbBuf - 1] != '\n' )
      debugCP( "File line too long" );
    else
    {
// [Not good for -Wall]      *((PULONG)&acBuf[cbBuf - 1]) = 0x00000A0D;
      acBuf[cbBuf - 1] = '\r';
      acBuf[cbBuf]     = '\n';
      acBuf[cbBuf + 1] = '\0';
      acBuf[cbBuf + 2] = '\0';
      cbBuf++;
    }

    // Decode readed string (quoted-printable / base64).

    if ( lTXEnc == -1 )
    {
      cbTXDecBuf = cbBuf;
      pcTXDecBuf = acBuf;
    }
    else
    {
      pcReadBuf  = acBuf;
      cbReadBuf  = cbBuf;
      pcTXDecBuf = pcTXDecBufF;
      cbTXDecBuf = cbTXDecBufF;

      switch( lTXEnc )
      {
        case 0:
          utilQPDecChunk( &stQPDec, &cbTXDecBuf, &pcTXDecBuf,
                          &cbReadBuf, &pcReadBuf );
          if ( cbReadBuf != 0 )
            debugCP( "utilQPDecChunk() - not enough output buffer space?" );
          break;

        case 1:
          utilB64DecChunk( &stB64Dec, &cbTXDecBuf, &pcTXDecBuf,
                           &cbReadBuf, &pcReadBuf );
          break;
      }

      cbTXDecBuf = pcTXDecBuf - acTXDecBuf;
      pcTXDecBuf = acTXDecBuf;
    }

    // Convert the decoded string to the internal charset (+uppercase).

    pcICUpBuf  = acICUpBuf;
    cbICUpBuf  = sizeof(acICUpBuf);
    utilIConvChunk( ic, &cbICUpBuf, &pcICUpBuf, &cbTXDecBuf, &pcTXDecBuf );
    // Move uncoded bytes (not enough data for character?) to the begin of buf.
    memcpy( acTXDecBuf, pcTXDecBuf, cbTXDecBuf );
    // pcTXDecBufF - buffer pointer to add bytes for uncoded character if
    // cbTXDecBuf is not a zero.
    pcTXDecBufF = &acTXDecBuf[cbTXDecBuf];
    cbTXDecBufF = sizeof(acTXDecBuf) - cbTXDecBuf;

    if ( cbICUpBuf == sizeof(acICUpBuf) )
      // Not enough bytes read to convert even one character - continue reading.
      continue;

    *((PUSHORT)pcICUpBuf) = 0;
    UniStrupr( (UniChar *)acICUpBuf );
    cbICUpBuf = sizeof(acICUpBuf) - cbICUpBuf;
    pcICUpBuf = acICUpBuf;
    // Now we have zero-terminated uppercase UTF-16LE chunk of the message at
    // pcICUpBuf, length in bytes is cbICUpBuf.

    // Fill the text buffer pcICUpBlock with conversion result and search the
    // substring.

    do
    {
      // Append text buffer pcICUpBlock with conversion result from pcICUpBuf.

      cbReadBuf = cbICUpBlock - ulICUpBlockPos;
      if ( cbReadBuf > cbICUpBuf )
        cbReadBuf = cbICUpBuf;

      memcpy( &pcICUpBlock[ulICUpBlockPos], pcICUpBuf, cbReadBuf );
      pcICUpBuf += cbReadBuf;
      cbICUpBuf -= cbReadBuf;
      ulICUpBlockPos += cbReadBuf;

      if ( ulICUpBlockPos == cbICUpBlock )
      {
        // The text buffer pcICUpBlock is full - search given substring.

        *((PUSHORT)&pcICUpBlock[ulICUpBlockPos]) = 0;
        if ( UniStrstr( (UniChar *)pcICUpBlock, (UniChar *)pszICUpStr ) != NULL )
        {
          ulRC = _SINP_FOUND;
          break;
        }

        // Substring is not found. Move last bytes, which could not participate
        // in the comparison (substring length - 1) to the beginning of buffer.
        ulICUpBlockPos = cbICUpStr - 2;
        memcpy( pcICUpBlock, &pcICUpBlock[cbICUpBlock - ulICUpBlockPos],
                ulICUpBlockPos );
      }
    }
    while( cbICUpBuf != 0 );
  }

  if ( ( ulRC != _SINP_FOUND ) && ( ulICUpBlockPos >= cbICUpStr ) )
  {
    // There are enough bytes left in the buffer pcICUpBlock to compare.
    *((PUSHORT)&pcICUpBlock[ulICUpBlockPos]) = 0;
    if ( UniStrstr( (UniChar *)pcICUpBlock, (UniChar *)pszICUpStr ) != NULL )
      ulRC = _SINP_FOUND;
  }

  iconv_close( ic );
  if ( pszCharset != NULL )
    free( pszCharset );
  free( pcICUpBlock );

  return ulRC;
}

static ULONG _searchInParts(FILE *pfMsg, PSZ pszText, PSZ pszBoundary)
{
  PFIELD     pFields;
  PSZ        pszVal;
  ULONG      cbVal;
  PCHAR      pcVal;
  ULONG      ulRC;

  if ( utilQueryStackSpace() < 8192 )
  {
    debug( "Not enough stack space" );
    return _SINP_ENDOFPART;
  }

  pFields = fldRead( pfMsg, pszBoundary );
  if ( pFields == NULL )
  {
    debug( "Part header reading failed" );
    return _SINP_ENDOFPART;
  }

  pszVal = fldFind( pFields, "Content-Type" );
  pcVal = fldVGetContentType( pszVal, &cbVal );

  switch( pcVal == NULL ?
            -1 : utilStrWordIndex( "multipart message text", cbVal, pcVal ) )
  {
    case 0:  // multipart
      pszVal = fldVGetParamNew( pszVal, "boundary" );
      fldFree( pFields );
      pFields = NULL;
      if ( pszVal != NULL )
      {
        do
          ulRC = _searchInParts( pfMsg, pszText, pszVal );
        while( ulRC == _SINP_NOTFOUND );

        free( pszVal );
        break;
      }
      debug( "Not found \"boundary\" in Content-Type (multipart)" );

    default: // case -1:
      ulRC = _fileReadSectText( pfMsg, pszBoundary, NULL, NULL )
               ? _SINP_NOTFOUND : _SINP_ENDOFPART;
      break;

    case 1:  // message
      ulRC = _searchInParts( pfMsg, pszText, pszBoundary );
      break;

    case 2:  // text
      ulRC = _searchInTextPart( pfMsg, pFields, pszText, pszBoundary );
      break;
  }

  if ( pFields != NULL )
    fldFree( pFields );

  return ulRC;
}

BOOL imfSearchText(PSZ pszFile, PSZ pszText, PSZ pszCharset)
{
  FILE       *pfMsg;
  BOOL       fRes;

  pfMsg = fopen( pszFile, "rt" );
  if ( pfMsg == NULL )
  {
    debug( "Can't open %s", pszFile );
    return FALSE;
  }

  if ( pszCharset != NULL )
  {
    // Convert given substring to uppercase and internal charset.
    pszText = utilStrToUTF16Upper( pszText, pszCharset );
    if ( pszText == NULL )
    {
      fclose( pfMsg );
      return FALSE;
    }
  }

  fRes = _searchInParts( pfMsg, pszText, NULL ) == _SINP_FOUND;

  if ( pszCharset != NULL )
    free( pszText );
  fclose( pfMsg );

  return fRes;
}


LONG imfGenerateMsgId(ULONG cbBuf, PCHAR pcBuf, PSZ pszDomain)
{
  UCHAR      aucRand[16];
  PCHAR      pcBufEnd = &pcBuf[cbBuf];
  PCHAR      pcPos = pcBuf;
  LONG       lIdx, cb;
  ULONG      ulTime;

  if ( cbBuf < ( sizeof(aucRand) + 15 ) )
  {
    debugCP();
    return -1;
  }

  *(pcPos++) = '<';

  if ( RAND_bytes( aucRand, sizeof(aucRand) ) )
  {
    for( lIdx = 0; lIdx < sizeof(aucRand); lIdx++ )
      *(pcPos++) = '0' + ( aucRand[lIdx] % 10 );
  }

  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
  pcPos += sprintf( pcPos, ".%lu@", ulTime );

  lIdx = pcBufEnd - pcPos - 1;  // -1 - trailing '>'
  if ( pszDomain != NULL )
  {
    cb = strlen( pszDomain );
    if ( cb >= lIdx )
    {
      debugCP();
      return -1;
    }

    strcpy( pcPos, pszDomain );
  }
  else
  {
    cb = wcfgQueryOurHostName( lIdx, pcPos );
    if ( cb < 0 )
    {
      debugCP();
      return -1;
    }

    strlwr( pcPos );
  }

  pcPos += cb;
  *(pcPos++) = '>';
  *(pcPos) = '\0';

  return pcPos - pcBuf;
}
