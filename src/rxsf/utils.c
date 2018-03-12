/*
  Different helpers.
*/

#include <string.h>
#include <ctype.h>
#include <errno.h>
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#include <os2.h>
#ifdef __WATCOMC__
#include <types.h>
#endif
#include "utils.h"
#include <stdio.h>
#include "debug.h"

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
