/*
    SEARCH command implementation for IMAP4 protocol.

    This module exports only one function:

      ULONG cmdSearch(PUHSESS pUHSess, PCTX pCtx, BOOL fUID, PSZ pszLine)

    which is called from the function imap.c/imapRequest()->cfnSearch().
*/

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include <os2.h>
#include "imap.h"
#include "context.h"
#include "storage.h"
#include "imapfs.h"
#include "message.h"
#include "utils.h"
#include "debug.h"               // Should be last.

//#define DEBUG_CRIT

#define _CRIT_NOT_FLAG           0x00010000

#define _CRIT_EL_LBRACKET        0xFF04
#define _CRIT_EL_RBRACKET        0xFF05
#define _CRIT_EL_END             0xFF01

#define _CRIT_ALL                0x0000
#define _CRIT_OR                 0x0001
#define _CRIT_EL_NOT             0x0002

// CRITSEQ
#define _CRIT_SEQ                0x02FF
#define _CRIT_UID                0x0203

// CRITFLAG
#define _CRIT_FLAG               0x03FF
#define _CRIT_FLAG_EL_KEYWORD    0x0304
#define _CRIT_FLAG_EL_UNKEYWORD  0x0305
#define _CRIT_FLAG_EL_ANSWERED   0x0306
#define _CRIT_FLAG_EL_DELETED    0x0307
#define _CRIT_FLAG_EL_DRAFT      0x0308
#define _CRIT_FLAG_EL_FLAGGED    0x0309
#define _CRIT_FLAG_EL_NEW        0x030A
#define _CRIT_FLAG_EL_OLD        0x030B
#define _CRIT_FLAG_EL_RECENT     0x030C
#define _CRIT_FLAG_EL_SEEN       0x030D
#define _CRIT_FLAG_EL_UNANSWERED 0x030E
#define _CRIT_FLAG_EL_UNDELETED  0x030F
#define _CRIT_FLAG_EL_UNDRAFT    0x0310
#define _CRIT_FLAG_EL_UNFLAGGED  0x0311
#define _CRIT_FLAG_EL_UNSEEN     0x0312

// CRITSTR
#define _CRIT_HEADER             0x0413
#define _CRIT_HEADER_EL_BCC      0x0414
#define _CRIT_HEADER_EL_CC       0x0415
#define _CRIT_HEADER_EL_FROM     0x0416
#define _CRIT_HEADER_EL_SUBJECT  0x0417
#define _CRIT_HEADER_EL_TO       0x0418
#define _CRIT_BODY               0x0419
#define _CRIT_TEXT               0x041A
#define _CRIT_HEADERADDR         0x04FF

// CRITDATE
#define _CRIT_BEFORE             0x051B
#define _CRIT_ON                 0x051C
#define _CRIT_SENTBEFORE         0x051D
#define _CRIT_SENTON             0x051E
#define _CRIT_SENTSINCE          0x051F
#define _CRIT_SINCE              0x0520

// CRITSIZE
#define _CRIT_LARGER             0x0621
#define _CRIT_SMALLER            0x0622

#pragma pack(1)
typedef struct _CRDATE {
  UCHAR      ucDay;
  UCHAR      ucMonth;
  USHORT     usYear;
} CRDATE, *PCRDATE;
#pragma pack()

typedef struct _CRITERIA {
  ULONG                ulType;
  struct _CRITERIA     *pNext;
} CRITERIA, *PCRITERIA;


typedef struct _CRITLIST {
  CRITERIA   stCriteria;         // _CRIT_ALL _CRIT_OR
  struct _CRITERIA     *pCritList;
} CRITLIST, *PCRITLIST;

typedef struct _CRITSEQ {
  CRITERIA   stCriteria;         // _CRIT_SEQ _CRIT_UID
  PUTILRANGE pRange;
} CRITSEQ, *PCRITSEQ;

typedef struct _CRITFLAG {
  CRITERIA   stCriteria;         // _CRIT_FLAG
  ULONG      ulFlag;
  ULONG      ulNotFlag;
} CRITFLAG, *PCRITFLAG;

typedef struct _CRITSTR {
  CRITERIA   stCriteria;         // _CRIT_BODY _CRIT_HEADER _CRIT_HEADERADDR
                                 // _CRIT_TEXT.
  PSZ        pszField;           // NULL for _CRIT_BODY and _CRIT_TEXT.
  PSZ        pszSubstr;
} CRITSTR, *PCRITSTR;

typedef struct _CRITDATE {
  CRITERIA   stCriteria;         // _CRIT_BEFORE _CRIT_ON _CRIT_SENTBEFORE
                                 // _CRIT_SENTON _CRIT_SENTSINCE _CRIT_SINCE
  CRDATE     stDate;
} CRITDATE, *PCRITDATE;

typedef struct _CRITSIZE {
  CRITERIA   stCriteria;         // _CRIT_LARGER _CRIT_SMALLER
  ULLONG     ullSize;
} CRITSIZE, *PCRITSIZE;

#define STR_SKIP_ELEMENT(p) \
  while( *(p) != '\0' && !isspace(*(p)) && *(p) != '(' && *(p) != ')' ) p++



/* *************************************************************** */
/*                                                                 */
/*                    Request string parser                        */ 
/*                                                                 */
/* *************************************************************** */
/*
   Main parser functions:
     static PCRITERIA _critNew(PSZ pszRequest)
     static VOID _critFree(PCRITERIA pCrit)
*/

static PSZ _cutString(PSZ *ppszLine, PSZ pszCharset)
{
  PCHAR      pcStart = *ppszLine;
  PCHAR      pcEnd;
  ULONG      cbString;
  
  STR_SKIP_SPACES( pcStart );

  if ( *pcStart == '\"' )
    pcEnd = utilStrGetCompNew( ppszLine );
  else
  {
    pcEnd = pcStart;
    STR_SKIP_ELEMENT( pcEnd );
    *ppszLine = pcEnd;
    cbString = pcEnd - pcStart;

    pcEnd = malloc( cbString + 1 );
    if ( pcEnd == NULL )
      return NULL;

    memcpy( pcEnd, pcStart, cbString );
    pcEnd[cbString] = '\0';
  }

  pcStart = utilStrToUTF16Upper( pcEnd, pszCharset );
  free( pcEnd );

  return pcStart;
}

static ULONG _cutFlag(PSZ *ppszLine)
{
  PCHAR      pcStart = *ppszLine;
  PCHAR      pcEnd;
  LONG       lFlag;

  STR_SKIP_SPACES( pcStart );
  pcEnd = pcStart;
  STR_SKIP_ELEMENT( pcEnd );

  lFlag = utilStrWordIndex( "\\SEEN \\ANSWERED \\FLAGGED \\DELETED \\DRAFT "
                            "\\RECENT", pcEnd - pcStart, pcStart );
  lFlag = lFlag == -1 ? 0 : (1 << lFlag);

  *ppszLine = pcEnd;
  return lFlag;
}

static PUTILRANGE _cutNumSet(PSZ *ppszLine)
{
  PSZ        pszSeq = *ppszLine;
  PUTILRANGE pRange;

  STR_SKIP_SPACES( pszSeq );

  if ( !utilStrToNewNumSet( pszSeq, &pRange ) )
    pRange = NULL;
  STR_SKIP_ELEMENT( pszSeq );
  *ppszLine = pszSeq;

  return pRange;
}

static VOID _cutDate(PCRDATE pDate, PSZ *ppszLine)
{
  PCHAR      pcDate = *ppszLine;
  PCHAR      pcEnd;
  LONG       lMonth;

  pDate->ucDay = strtoul( pcDate, &pcEnd, 10 ); 
  if ( pcDate != pcEnd && ( *pcEnd == '-' || *pcEnd == ' ' ) )
  {
    pcDate = pcEnd + 1;
    lMonth = utilStrWordIndex( "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",
                               3, pcDate );
    if ( lMonth != -1 )
    {
      pDate->ucMonth = lMonth;
      pcDate += 3;
      if ( *pcDate == '-' || *pcDate == ' ' )
      {
        pcDate++;
        pDate->usYear = strtoul( pcDate, &pcEnd, 10 ); 
      }
    }
  }

  STR_SKIP_ELEMENT( pcDate );
  *ppszLine = pcDate;
}

static ULLONG _cutULLong(PSZ *ppszLine)
{
  PCHAR      pcVal = *ppszLine;
  ULLONG     ullVal = (ULLONG)strtoull( pcVal, (PCHAR *)ppszLine, 10 );

  return ullVal;
}

// Cuts next word of criteria from string *ppszLine, set pointer *ppszLine to
// the next word. Returns value _CRIT_xxxxx (including _CRIT_EL_xxxxx).
static LONG _cutElement(PSZ *ppszLine)
{
  PCHAR      pcWordEnd, pcWord = *ppszLine;;
  ULONG      cbWord;
  LONG       lElement;

  STR_SKIP_SPACES( pcWord );

  if ( *pcWord == '\0' )
    return _CRIT_EL_END;

  if ( *pcWord == '(' )
  {
    *ppszLine = pcWord + 1;
    return _CRIT_EL_LBRACKET;
  }

  if ( *pcWord == ')' )
  {
    *ppszLine = pcWord + 1;
    return _CRIT_EL_RBRACKET;
  }

  pcWordEnd = pcWord;
  while( isalpha( *pcWordEnd ) )
    pcWordEnd++;

  *ppszLine = pcWordEnd;
  cbWord = pcWordEnd - pcWord;
  if ( cbWord == 0 )
  {
    pcWordEnd = pcWord;
    while( strchr( "01234567890:,*", *pcWordEnd ) != NULL )
      pcWordEnd++;

    if ( pcWordEnd != pcWord )
      return _CRIT_SEQ;
  }

  lElement = utilStrWordIndex(
               "ALL OR NOT UID KEYWORD UNKEYWORD ANSWERED DELETED DRAFT "
               "FLAGGED NEW OLD RECENT SEEN UNANSWERED UNDELETED UNDRAFT "
               "UNFLAGGED UNSEEN HEADER BCC CC FROM SUBJECT TO BODY TEXT "
               "BEFORE ON SENTBEFORE SENTON SENTSINCE SINCE LARGER SMALLER",
               cbWord, pcWord );
  if ( lElement == -1 )
    return -1;

  switch( lElement )
  {
    case -1:
      return -1;

    case 0:            // ALL
    case 1:            // OR
    case 2:            // NOT
      return lElement;

    case 3:            // UID
      return _CRIT_UID;

    case 0x04:         // KEYWORD
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
    case 0x0D:
    case 0x0E:
    case 0x0F:
    case 0x10:
    case 0x11:
    case 0x12:         // UNSEEN
      return lElement | 0x0300;

    case 0x13:         // HEADER
    case 0x14:         // BCC
    case 0x15:         // CC
    case 0x16:         // FROM
    case 0x17:         // SUBJECT
    case 0x18:         // TO
    case 0x19:         // BODY
    case 0x1A:         // TEXT
      return lElement | 0x0400;

    case 0x1B:         // BEFORE
    case 0x1C:
    case 0x1D:
    case 0x1E:
    case 0x1F:
    case 0x20:         // SINCE
      return lElement | 0x0500;

    case 0x21:         // LARGER
    case 0x22:         // SMALLER
      return lElement | 0x0600;

    default:
      debugCP( "WTF?!" );
  }

  return -1;
}

static PCRITERIA _critBuildList(PSZ *ppszLine, PSZ pszCharset, ULONG ulElements,
                                BOOL fEatRBracket);

static PCRITERIA _critBuild(PSZ *ppszLine, PSZ pszCharset, BOOL fEatRBracket)
{
  LONG       lType;
  PCRITERIA  pCrit = NULL;

  if ( utilQueryStackSpace() < 4096 )
    // Not enough stack space.
    return NULL;

  // Get next element of criteria (word) as value _CRIT_xxxxx / _CRIT_EL_xxxxx.
  lType = _cutElement( ppszLine );
  if ( lType == -1 )
    // Unknown element.
    return NULL;

  switch( lType & 0xFF00 )
  {
    case 0x0000:
      switch( lType )
      {
        case _CRIT_OR:
          pCrit = _critBuildList( ppszLine, pszCharset, 2, FALSE );
          pCrit->ulType = lType;
          break;

        case _CRIT_ALL:
          pCrit = _critBuildList( ppszLine, pszCharset, 0, FALSE );
          break;

        case _CRIT_EL_NOT:
          pCrit = _critBuild( ppszLine, pszCharset, TRUE );
          pCrit->ulType |= _CRIT_NOT_FLAG;
          break;
      }
      break;

    case 0xFF00:
      switch( lType )
      {
        case _CRIT_EL_LBRACKET:
          pCrit = _critBuildList( ppszLine, pszCharset, 0, TRUE );
          break;

        case _CRIT_EL_RBRACKET:
          if ( !fEatRBracket )
            ppszLine--;

        case _CRIT_EL_END:
          pCrit = NULL;
          break;
      }
      break;

    case 0x0200:     // CRITSEQ
      pCrit = malloc( sizeof(CRITSEQ) );
      pCrit->ulType = lType;
      ((PCRITSEQ)pCrit)->pRange = _cutNumSet( ppszLine );
      break;

    case 0x0300:     // CRITFLAG
      pCrit = malloc( sizeof(CRITFLAG) );
      pCrit->ulType = _CRIT_FLAG;

      switch( lType )
      {
        case _CRIT_FLAG_EL_KEYWORD:
          ((PCRITFLAG)pCrit)->ulFlag = _cutFlag( ppszLine );
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_UNKEYWORD:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = _cutFlag( ppszLine );
          break;

        case _CRIT_FLAG_EL_ANSWERED:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_ANSWERED;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_DELETED:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_DELETED;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_DRAFT:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_DRAFT;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_FLAGGED:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_FLAGGED;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_NEW:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_RECENT;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_SEEN;
          break;

        case _CRIT_FLAG_EL_OLD:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_RECENT;
          break;

        case _CRIT_FLAG_EL_RECENT:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_RECENT;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_SEEN:
          ((PCRITFLAG)pCrit)->ulFlag = FSMSGFL_SEEN;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
          break;

        case _CRIT_FLAG_EL_UNANSWERED:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_ANSWERED;
          break;

        case _CRIT_FLAG_EL_UNDELETED:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_DELETED;
          break;

        case _CRIT_FLAG_EL_UNDRAFT:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_DRAFT;
          break;

        case _CRIT_FLAG_EL_UNFLAGGED:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_FLAGGED;
          break;

        case _CRIT_FLAG_EL_UNSEEN:
          ((PCRITFLAG)pCrit)->ulFlag = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = FSMSGFL_SEEN;
          break;

        default:
          debugCP( "WTF?!" );
          ((PCRITFLAG)pCrit)->ulFlag    = 0;
          ((PCRITFLAG)pCrit)->ulNotFlag = 0;
      }
      break;

    case 0x0400:     // CRITSTR

      // pCrit->ulType:
      // _CRIT_HEADERADDR for _CRIT_HEADER_EL_BCC, _CRIT_HEADER_EL_CC,
      //                      _CRIT_HEADER_EL_FROM, and _CRIT_HEADER_EL_TO;
      // _CRIT_HEADER for _CRIT_HEADER and _CRIT_HEADER_EL_SUBJECT;
      // _CRIT_BODY for _CRIT_BODY; _CRIT_TEXT for _CRIT_TEXT.

      pCrit = malloc( sizeof(CRITSTR) );
      pCrit->ulType = _CRIT_HEADERADDR;
      ((PCRITSTR)pCrit)->pszField = NULL;

      // Get field name.
      switch( lType )
      {
        case _CRIT_HEADER:
          // First argument for HEADER - field name of the message header.
//          ((PCRITSTR)pCrit)->pszField = _cutString( ppszLine, pszCharset );
          ((PCRITSTR)pCrit)->pszField = utilStrGetCompNew( ppszLine );

        case _CRIT_BODY:
        case _CRIT_TEXT:
          pCrit->ulType = lType;
          break;

        case _CRIT_HEADER_EL_BCC:
          ((PCRITSTR)pCrit)->pszField = strdup( "BCC" );
          break;

        case _CRIT_HEADER_EL_CC:
          ((PCRITSTR)pCrit)->pszField = strdup( "CC" );
          break;

        case _CRIT_HEADER_EL_FROM:
          ((PCRITSTR)pCrit)->pszField = strdup( "FROM" );
          break;

        case _CRIT_HEADER_EL_SUBJECT:
          ((PCRITSTR)pCrit)->pszField = strdup( "SUBJECT" );
          pCrit->ulType = _CRIT_HEADER;
          break;

        case _CRIT_HEADER_EL_TO:
          ((PCRITSTR)pCrit)->pszField = strdup( "TO" );
          break;
      }

      // Get string argument of the element.
      ((PCRITSTR)pCrit)->pszSubstr = _cutString( ppszLine, pszCharset );
      break;

    case 0x0500:     // CRITDATE
      pCrit = malloc( sizeof(CRITDATE) );
      pCrit->ulType = lType;
      _cutDate( &((PCRITDATE)pCrit)->stDate, ppszLine );
      break;

    case 0x0600:     // CRITSIZE
      pCrit = malloc( sizeof(CRITSIZE) );
      pCrit->ulType = lType;
      ((PCRITSIZE)pCrit)->ullSize = _cutULLong( ppszLine );
      break;
  } // switch( lType & 0xFF00 )

  if ( pCrit != NULL )
    pCrit->pNext = NULL;

  return pCrit;
}

// PCRITERIA _critBuildList(PSZ *ppszLine, PSZ pszCharset, ULONG ulElements,
//                          BOOL fEatRBracket)
//
// Parses input string *ppszLine up to ulElements elements. Element is one key
// with arguments splited by SPACE. Pointer *ppszLine will be set to the end of
// parsed data. fEatRBracket is FALSE for the list began with 'ALL' and FALSE
// in other case (list began with the left bracket) It is used for the inner
// workings of the parser.
//
static PCRITERIA _critBuildList(PSZ *ppszLine, PSZ pszCharset, ULONG ulElements,
                                BOOL fEatRBracket)
{
  PCRITERIA  pCrit, pCritNew;
  PCRITERIA  *ppCritLast;

  if ( memicmp( *ppszLine, "ALL ", 4 ) == 0 )
    *ppszLine += 4;

  pCrit = malloc( sizeof(CRITLIST) );
  pCrit->ulType = _CRIT_ALL;
  pCrit->pNext = NULL;
  ((PCRITLIST)pCrit)->pCritList = NULL;
  ppCritLast = &((PCRITLIST)pCrit)->pCritList;

  do
  {
    pCritNew = _critBuild( ppszLine, pszCharset, fEatRBracket );
    if ( pCritNew == NULL )
      break;
    *ppCritLast = pCritNew;
    ppCritLast = &pCritNew->pNext;

    ulElements--;
  }
  while( ulElements != 0 );

  return pCrit;
}

static PCRITERIA _critNew(PSZ pszRequest, PSZ pszCharset)
{
  return _critBuildList( &pszRequest, pszCharset, 0, TRUE );
}

static VOID _critFree(PCRITERIA pCrit)
{
  PCRITERIA  pCritNext;

  while( pCrit != NULL )
  {
    pCritNext = pCrit->pNext;

    switch( pCrit->ulType & 0xFF00 )
    {
      case 0x0000:
        _critFree( ((PCRITLIST)pCrit)->pCritList );
        break;

      case 0x0200:
        if ( ((PCRITSEQ)pCrit)->pRange != NULL )
          free( ((PCRITSEQ)pCrit)->pRange );
        break;

      case 0x0400:
        {
          PCRITSTR    pCritStr = (PCRITSTR)pCrit;

          if ( pCritStr->pszField != NULL )
            free( pCritStr->pszField );

          if ( pCritStr->pszSubstr != NULL )
            free( pCritStr->pszSubstr );
        }
        break;
    }

    free( pCrit );
    pCrit = pCritNext;
  }
}

#ifdef DEBUG_CRIT
static VOID _debugPrintCrit(PCRITERIA pCrit)
{
  PSZ        pszElement;

  puts( "" );
  if ( pCrit == NULL )
  {
    printf( "<NULL>" );
    return;
  }

  while( pCrit != NULL )
  {
    if ( (pCrit->ulType & _CRIT_NOT_FLAG) != 0 )
      printf( "NOT " );

    switch( pCrit->ulType & 0xFFFF )
    {
      case _CRIT_ALL: pszElement = "ALL"; break;
      case _CRIT_OR: pszElement = "OR"; break;
      case _CRIT_SEQ: pszElement = "SEQ"; break;
      case _CRIT_UID: pszElement = "UID"; break;
      case _CRIT_FLAG: pszElement = "FLAG"; break;
      case _CRIT_BODY: pszElement = "BODY"; break;
      case _CRIT_HEADER: pszElement = "HEADER"; break;
      case _CRIT_HEADERADDR: pszElement = "HEADERADDR"; break;
      case _CRIT_TEXT: pszElement = "TEXT"; break;
      case _CRIT_BEFORE: pszElement = "BEFORE"; break;
      case _CRIT_ON: pszElement = "ON"; break;
      case _CRIT_SENTBEFORE: pszElement = "SENTBEFORE"; break;
      case _CRIT_SENTON: pszElement = "SENTON"; break;
      case _CRIT_SENTSINCE: pszElement = "SENTSINCE"; break;
      case _CRIT_SINCE: pszElement = "SINCE"; break;
      case _CRIT_LARGER: pszElement = "LARGER"; break;
      case _CRIT_SMALLER: pszElement = "SMALLER"; break;
      default: pszElement = "???";
    }

    printf( "%s ", pszElement );

    switch( pCrit->ulType & 0xFF00 )
    {
      case 0x0000:
        printf( "(" );
        _debugPrintCrit( ((PCRITLIST)pCrit)->pCritList );
        printf( ") " );
        break;

      case 0x0200:
        {
          PCRITSEQ     pCritSeq = (PCRITSEQ)pCrit;
          CHAR         acBuf[512];

          utilNumSetToStr( pCritSeq->pRange, sizeof(acBuf), acBuf );
          printf( "%s ", acBuf );
        }
        break;

      case 0x0300:
        {
          PCRITFLAG    pCritFlag = (PCRITFLAG)pCrit;

          printf( "<0x%X and not 0x%X> ",
                  pCritFlag->ulFlag, pCritFlag->ulNotFlag );
        }
        break;

      case 0x0400:
        {
          PCRITSTR    pCritStr = (PCRITSTR)pCrit;

          if ( pCritStr->pszField != NULL )
            printf( "%s:", pCritStr->pszField );
          printf( "%s ", pCritStr->pszSubstr );
        }
        break;

      case 0x0500:
        {
          PCRITDATE    pCritDate = (PCRITDATE)pCrit;

          printf( "%u.%.2u.%u ", pCritDate->stDate.ucDay,
                  pCritDate->stDate.ucMonth + 1, pCritDate->stDate.usYear );
        }
        break;

      case 0x0600:
        printf( "%lu ", ((PCRITSIZE)pCrit)->ullSize );
        break;

      default:
        printf( "???" );
    } // switch( pCrit->ulType & 0xFF00 )

    pCrit = pCrit->pNext;
  } // while( pCrit != NULL )

  puts( "" );
}
#else
#define _debugPrintCrit(__pCrit)
#endif // DEBUG_CODE


/* *************************************************************** */
/*                                                                 */
/*          Verify that the message matches the request            */ 
/*                                                                 */
/* *************************************************************** */
/*
   Main function:
     static BOOL _checkMsg(PCRITERIA pCrit, PSCANMSG pScanMsg)
 */

#define _SCANMSG_FL_STAT         0x01
#define _SCANMSG_FL_HEADER       0x02
#define _SCANMSG_FL_MSG_DATE     0x04

typedef struct _SCANMSG {
  FSENUMMSG            stEnum;
  PSZ                  pszCharset;
  ULONG                ulFlags;     // _SCANMSG_FL_xxxxx
  FILESTATUS3L         stFileStat;  // Valid with _SCANMSG_FL_STAT
  PFIELD               pHeader;     // Valid with _SCANMSG_FL_HEADER
} SCANMSG, *PSCANMSG;


static BOOL __qmiFileStat(PSCANMSG pScanMsg)
{
  ULONG      ulRC;

  if ( (pScanMsg->ulFlags & _SCANMSG_FL_STAT) != 0 )
    return TRUE;

  ulRC = DosQueryPathInfo( pScanMsg->stEnum.acFile, FIL_STANDARDL,
                           &pScanMsg->stFileStat, sizeof(FILESTATUS3L) );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosQueryPathInfoL(\"%s\",,,), rc = %u",
           pScanMsg->stEnum.acFile, ulRC );
    return FALSE;
  }

  pScanMsg->ulFlags |= _SCANMSG_FL_STAT;
  return TRUE;
}

static BOOL __qmiFileHeader(PSCANMSG pScanMsg)
{
  if ( (pScanMsg->ulFlags & _SCANMSG_FL_HEADER) == 0 )
  {
    pScanMsg->pHeader = fldReadHeader( pScanMsg->stEnum.acFile );
    pScanMsg->ulFlags |= _SCANMSG_FL_HEADER;
  }

  return pScanMsg->pHeader != NULL;
}

static VOID _qmiClean(PSCANMSG pScanMsg)
{
  if ( pScanMsg->pHeader != NULL )
  {
    fldFree( pScanMsg->pHeader );
    pScanMsg->pHeader = NULL;
  }
  pScanMsg->ulFlags = 0;
}

static ULONG _qmiIntDate(PSCANMSG pScanMsg)
{
  CRDATE     stDate;

  if ( !__qmiFileStat( pScanMsg ) )
    return 0;

  stDate.ucDay    = pScanMsg->stFileStat.fdateLastWrite.day;
  stDate.ucMonth  = pScanMsg->stFileStat.fdateLastWrite.month - 1;
  stDate.usYear   = pScanMsg->stFileStat.fdateLastWrite.year + 1980;

  return *((PULONG)&stDate);
}

static ULLONG _qmiSize(PSCANMSG pScanMsg)
{
  return __qmiFileStat( pScanMsg ) ? pScanMsg->stFileStat.cbFile : 0;
}

static ULONG _qmiHdrDate(PSCANMSG pScanMsg)
{
  PSZ        pszDate;
  CRDATE     stDate;

  if ( !__qmiFileHeader( pScanMsg ) )
    return 0;

  *((PULONG)&stDate) = 0;
  pszDate = fldFind( pScanMsg->pHeader, "DATE" );
  // Header date format: Wed, 28 Jun 2017 12:32:55 +1100

  STR_MOVE_TO_SPACE( pszDate );
  if ( *pszDate != '\0' )
  {
    STR_SKIP_SPACES( pszDate );
    _cutDate( &stDate, &pszDate );
  }

  return *((PULONG)&stDate);
}

static BOOL _qmiHdrFindStr(PSCANMSG pScanMsg, PSZ pszField, BOOL fAddrOnly,
                           PSZ pszText)
{
  if ( !__qmiFileHeader( pScanMsg ) )
  {
    debugCP( "__qmiFileHeader() failed" );
    return FALSE;
  }

  if ( pszField != NULL )
    return fldIsContainsSubstr( pScanMsg->pHeader, pszField, fAddrOnly,
                                pszText, NULL );

  return fldHdrIsContainsSubstr( pScanMsg->pHeader, pszText, NULL );
}

static BOOL _checkMsg(PCRITERIA pCrit, PSCANMSG pScanMsg)
{
  ULONG      ulType = pCrit->ulType & 0xFFFF;
  BOOL       fRes = FALSE;

  switch( ulType & 0xFF00 )
  {
    case 0x0000:
      {
        PCRITLIST      pCritList = ((PCRITLIST)pCrit);
        PCRITERIA      pCritScan = pCritList->pCritList;

        for( pCritScan = pCritList->pCritList; pCritScan != NULL;
             pCritScan = pCritScan->pNext )
        {
          if ( ulType == _CRIT_ALL )                 // Logical AND.
          {
            if ( !_checkMsg( pCritScan, pScanMsg ) )
            {
              fRes = FALSE;
              break;
            }
          }
          else                                       // Logical OR.
          {
            if ( _checkMsg( pCritScan, pScanMsg ) )
            {
              fRes = TRUE;
              break;
            }
          }
        }

        if ( pCritScan == NULL )
          fRes = ulType == _CRIT_ALL;
      }
      break;

    case 0x0200:
      fRes = utilIsInNumSet( ((PCRITSEQ)pCrit)->pRange,
                             ulType == _CRIT_SEQ ? pScanMsg->stEnum.ulIndex
                                                 : pScanMsg->stEnum.ulUID );
      break;

    case 0x0300:
      {
        PCRITFLAG      pCritFlag = (PCRITFLAG)pCrit;

        fRes = ( ( pCritFlag->ulFlag == 0 ) ||
                 ( (pScanMsg->stEnum.ulFlags & pCritFlag->ulFlag) != 0 ) )
               &&
               ( (pScanMsg->stEnum.ulFlags & pCritFlag->ulNotFlag) == 0 );
      }
      break;


    case 0x0400:
      {
        PCRITSTR    pCritStr = (PCRITSTR)pCrit;

        if ( ulType == _CRIT_HEADERADDR )
          fRes = _qmiHdrFindStr( pScanMsg, pCritStr->pszField, TRUE,
                                 pCritStr->pszSubstr );
        else if ( ( ulType == _CRIT_BODY ) || ( ulType == _CRIT_HEADER ) )
          fRes = _qmiHdrFindStr( pScanMsg, pCritStr->pszField, FALSE,
                                 pCritStr->pszSubstr );

        if ( ( ulType == _CRIT_BODY && !fRes ) || ( ulType == _CRIT_TEXT ) )
          fRes = imfSearchText( pScanMsg->stEnum.acFile, pCritStr->pszSubstr,
                                pScanMsg->pszCharset );
      }
      break;

    case 0x0500:
      {
        PCRITDATE      pCritDate = (PCRITDATE)pCrit;
        ULONG          ulReqDate = *((PULONG)&pCritDate->stDate);

        switch( ulType )
        {
          case _CRIT_BEFORE:
            fRes = _qmiIntDate( pScanMsg ) < ulReqDate;
            break;

          case _CRIT_ON:
            fRes = _qmiIntDate( pScanMsg ) == ulReqDate;
            break;

          case _CRIT_SENTBEFORE:
            fRes = _qmiHdrDate( pScanMsg ) < ulReqDate;
            break;

          case _CRIT_SENTON:
            fRes = _qmiHdrDate( pScanMsg ) == ulReqDate;
            break;

          case _CRIT_SENTSINCE:
            fRes = _qmiHdrDate( pScanMsg ) >= ulReqDate;
            break;

          case _CRIT_SINCE:
            fRes = _qmiIntDate( pScanMsg ) >= ulReqDate;
            break;

          default:
            debugCP( "WTF?!" );
            return FALSE;
        }

        break;
      }

    case 0x0600:
      {
        ULLONG         ullSize = _qmiSize( pScanMsg );

        fRes = ulType == _CRIT_LARGER ? ullSize > ((PCRITSIZE)pCrit)->ullSize
                                      : ullSize < ((PCRITSIZE)pCrit)->ullSize;
      }

    default:
      debugCP( "WTF?!" );
      return FALSE;
  }

  return (pCrit->ulType & _CRIT_NOT_FLAG) != 0 ? !fRes : fRes;
}


ULONG cmdSearch(PUHSESS pUHSess, PCTX pCtx, BOOL fUID, PSZ pszLine)
{
  PCRITERIA  pCrit;
  SCANMSG    stScanMsg;
  PSZ        pszCharset;

  ctxWrite( pCtx, 8, "* SEARCH" );

  if ( memicmp( pszLine, "CHARSET ", 8 ) == 0 )
  {
    // Charset specified by request. This charset will be used for string
    // arguments in the request.

    iconv_t    ic;

    pszLine += 8;
    pszCharset = utilStrGetCompNew( &pszLine );
    if ( pszCharset == NULL )
      return IMAPR_NO_SEARCH_BADCHARSET;

    // Check the charset.
    ic = iconv_open( "UTF-16LE", pszCharset );
    if ( ic == ((iconv_t)(-1)) )
    {
      free( pszCharset );
      return IMAPR_NO_SEARCH_BADCHARSET;
    }
    iconv_close( ic );

    STR_SKIP_SPACES( pszLine );
  }
  else
    pszCharset = strdup( "US-ASCII" );

  pCrit = _critNew( pszLine, pszCharset );

  if ( pCrit != NULL )
  {
    _debugPrintCrit( pCrit );

    memset( &stScanMsg, 0, sizeof(SCANMSG) );
    stScanMsg.pszCharset = pszCharset;
    fsEnumMsgBegin( pUHSess, &stScanMsg.stEnum, NULL, NULL );

    while( fsEnumMsg( pUHSess, &stScanMsg.stEnum ) )
    {
      if ( _checkMsg( pCrit, &stScanMsg ) )
      {
        if ( !ctxWriteFmt( pCtx, " %u", fUID ? stScanMsg.stEnum.ulUID
                                             : stScanMsg.stEnum.ulIndex ) )
          break;
      }

      _qmiClean( &stScanMsg );
    }

    _qmiClean( &stScanMsg );
    fsEnumMsgEnd( pUHSess, &stScanMsg.stEnum );

    _critFree( pCrit );
  }

  ctxWriteStrLn( pCtx, "" );
  free( pszCharset );

  return IMAPR_OK_COMPLETED;
}
