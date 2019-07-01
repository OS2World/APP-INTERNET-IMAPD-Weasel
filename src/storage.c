#include <string.h>
#include <ctype.h>
#include <search.h>
#define INCL_DOSMISC
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <os2.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "linkseq.h"
#include "utils.h"
#include "log.h"
#include "wcfg.h"
#include "context.h"
#include "message.h"
#include "xmlutils.h"
#include "storage.h"
#include "debug.h"               // Should be last.

// Save state to <MailRoot>\imap.xml after changes delay.
#define _SAVE_DELAY              (60 * 1000)

#define _XML_FILE                "imapd-quotas.xml"

// Refresh INBOXes sizes on requests period. It should be more than
// imapfs.c/_INBOX_CHECK_PERIOD_MAX
#define _INBOX_REFRESH_PERIOD    (30 * 60 * 1000)

#define _QUOTAS_FILE_CHK_PERIOD  (4 * 1000)

#define _FL_SYNC                 0x0001
#define _FL_LIST_CHANGED         0x0002
#define _FL_LOADED               0x0004
#define _FL_QUOTAS_SYNC          0x0008
#define _FL_NO_BLOCK_ON_LIMIT    0x0010    // For USER object only.

typedef struct _USER {
  ULONG      ulFlags;                      // _FL_xxxxx
  LLONG      llInboxSize;
  LLONG      llImapSize;
  LLONG      llLimit;
  ULONG      ulInboxRefreshTimestamp;
  CHAR       acName[1];
} USER, *PUSER;

typedef struct _DOMAIN {
  ULONG      ulFlags;                      // _FL_xxxxx
  LLONG      llSize;
  LLONG      llLimit;
  ULONG      cUsers;                       // Number of items in papUsers.
  PUSER      *papUsers;                    // Sorted list of PUSER objects.
  CHAR       acName[1];
} DOMAIN, *PDOMAIN;


extern PSZ             pszWeaselPath;      // Imported from wcfg.c

static LLONG           llMailRootSize = 0;
static LLONG           llMailRootLimit = LLONG_MAX;
static ULONG           cDomains;           // Number of items in papDomains.
static PDOMAIN         *papDomains;        // Sorted list of DOMAIN objects.
static HMTX            hmtxStorage = NULLHANDLE;
static ULONG           ulFlags = 0;        // _FL_xxxxx
static ULONG           ulSaveTime;         // Next time for dalayed save sate.
static UTILFTIMESTAMP  stQFTimestamp;
static PSZ             pszLetterBody = NULL;
static PSZ             pszLetterFrom = NULL;


static BOOL _getQuotasFName(ULONG cbBuf, PCHAR pcBuf)
{
  return _snprintf( pcBuf, cbBuf, "%s\\"_XML_FILE,
                    pszWeaselPath == NULL ? "." : (PCHAR)pszWeaselPath ) > 0;
}

static VOID _userFree(PUSER pUser)
{
  free( pUser );
}

static VOID _domainFree(PDOMAIN pDomain)
{
  ULONG      ulIdx;

  for( ulIdx = 0; ulIdx < pDomain->cUsers; ulIdx++ )
    _userFree( pDomain->papUsers[ulIdx] );

  if ( pDomain->papUsers != NULL )
    free( pDomain->papUsers );

  free( pDomain );
}

static int _compSearchDomain(const void *p1, const void *p2)
{
  return STR_ICMP( (PSZ)p1, (*((PDOMAIN *)p2))->acName );
}

static int _compSearchUser(const void *p1, const void *p2)
{
  return stricmp( (PSZ)p1, (*((PUSER *)p2))->acName );
}


// Inserts a new DOMAIN object in the list papDomains.
static BOOL _insertDomain(PSZ pszDomain, PDOMAIN *ppDomain)
{
  PDOMAIN    pDomain, *ppFind;
  ULONG      ulIndex;

  ppFind = utilBSearch( pszDomain, papDomains, cDomains,
                        sizeof(PDOMAIN), _compSearchDomain, &ulIndex );

  if ( ppFind != NULL )
  {
    *ppDomain = *ppFind;
    return FALSE;
  }

  pDomain = calloc( 1, sizeof(DOMAIN) + STR_LEN( pszDomain ) );
  *ppDomain = pDomain;

  if ( pDomain == NULL )
    return FALSE;

  if ( pszDomain == NULL )
    pDomain->acName[0] = '\0';
  else
    strcpy( pDomain->acName, pszDomain );

  if ( (cDomains & 0x07) == 0 )
  {
    PDOMAIN          *papNew = realloc( papDomains,
                                         (cDomains + 8) * sizeof(PDOMAIN) );
    if ( papNew == NULL )
    {
      free( pDomain );
      *ppDomain = NULL;
      return FALSE;
    }
    papDomains = papNew;
  }

  memmove( &papDomains[ulIndex + 1], &papDomains[ulIndex],
           (cDomains - ulIndex) * sizeof(PDOMAIN) );
  papDomains[ulIndex] = pDomain;
  cDomains++;

  return TRUE;
}

// Inserts a new USER object to the DOMAIN's list of users.
static BOOL _insertUser(PDOMAIN pDomain, PSZ pszUser, PUSER *ppUser)
{
  PUSER      pUser, *ppFind;
  ULONG      ulIndex;

  ppFind = utilBSearch( pszUser, pDomain->papUsers, pDomain->cUsers,
                        sizeof(PUSER), _compSearchUser, &ulIndex );

  if ( ppFind != NULL )
  {
    *ppUser = *ppFind;
    return FALSE;
  }

  pUser = calloc( 1, sizeof(USER) + strlen( pszUser ) );
  *ppUser = pUser;

  if ( pUser == NULL )
    return FALSE;

  strcpy( pUser->acName, pszUser );

  if ( (pDomain->cUsers & 0xFF) == 0 )
  {
    PUSER        *papNew = realloc( pDomain->papUsers,
                               (pDomain->cUsers + 0x0100) * sizeof(PUSER) );
    if ( papNew == NULL )
    {
      free( pUser );
      *ppUser = NULL;
      return FALSE;
    }
    pDomain->papUsers = papNew;
  }

  memmove( &pDomain->papUsers[ulIndex + 1], &pDomain->papUsers[ulIndex],
           (pDomain->cUsers - ulIndex) * sizeof(PUSER) );
  pDomain->papUsers[ulIndex] = pUser;
  pDomain->cUsers++;

  return TRUE;
}


/*  BOOL _readFileList(PSZ pszFileSpec, PMSLIST pList, PLLONG pllSize)
 *
 *  Reads files list to pList if it is not a NULL and returns total size of
 *  files in *pllSize.
 */

struct _RUHDATA {
  PMSLIST              pList;
  LLONG                llSize;
  FILEFINDBUF3L        aFind[32];
  ULONG                cFind;
};

static BOOL __ruhAdd(struct _RUHDATA *pData)
{
  ULONG                ulIdx;
  PFILEFINDBUF3L       pFind = pData->aFind;
  PMSFILE              pFile;

  for( ulIdx = 0; ulIdx < pData->cFind; ulIdx++ )
  {
    if ( (pFind->attrFile & FILE_DIRECTORY) == 0 )
    {
      pData->llSize = pData->llSize + pFind->cbFile;

      if ( pData->pList != NULL )
      {
        if ( (pData->pList->ulCount & 0xFF) == 0 )
        {
          PMSFILE *pNew = realloc( pData->pList->papFiles,
                          (pData->pList->ulCount + 0x0100) * sizeof(PMSFILE) );
          if ( pNew == NULL )
          {
            debugCP( "Not enough memory" );
            return FALSE;
          }
          pData->pList->papFiles = pNew;
        }

        pFile = malloc( sizeof(MSFILE) + strlen( pFind->achName ) );
        if ( pFile == NULL )
        {
          debugCP( "Not enough memory" );
          return FALSE;
        }

        pData->pList->papFiles[pData->pList->ulCount] = pFile;
        pData->pList->ulCount++;

        strcpy( pFile->acName, pFind->achName );
        pFile->ullSize = pFind->cbFile;
        pFile->stFTimestamp.fdateLastWrite = pFind->fdateLastWrite;
        pFile->stFTimestamp.ftimeLastWrite = pFind->ftimeLastWrite;
        pFile->ulUser = 0;
      }
    }  // if ( (pFind->attrFile & FILE_DIRECTORY) == 0 )

    if ( pFind->oNextEntryOffset == 0 )
      break;

    // Go to next find record.
    pFind = (PFILEFINDBUF3L)&((PCHAR)pFind)[pFind->oNextEntryOffset];
  }

  return TRUE;
}

static BOOL _readFileList(PSZ pszFileSpec, PMSLIST pList, PLLONG pllSize)
{
  ULONG                ulRC;
  HDIR                 hDir = HDIR_CREATE;
  struct _RUHDATA      stData;

  stData.cFind = ARRAYSIZE( stData.aFind );
  ulRC = DosFindFirst( pszFileSpec, &hDir, FILE_NORMAL, &stData.aFind,
                       sizeof(stData.aFind), &stData.cFind, FIL_STANDARDL );

  stData.llSize = 0;
  stData.pList = pList;

  while( ( ulRC == NO_ERROR ) && __ruhAdd( &stData ) )
  {
    stData.cFind = ARRAYSIZE( stData.aFind );
    ulRC = DosFindNext( hDir, &stData.aFind, sizeof(stData.aFind),
                        &stData.cFind );
  }

  DosFindClose( hDir );

  if ( pllSize != NULL )
    *pllSize = stData.llSize;

  return ulRC == ERROR_NO_MORE_FILES;
}


// Set new size for USER. Returns TRUE if size is changed.
static BOOL _setSize(PUSER pUser, PDOMAIN pDomain, BOOL fInbox, LLONG llSize)
{
  LLONG                llSizeDiff;

  if ( llSize < 0 )
    return FALSE;

  if ( fInbox )
  {
    llSizeDiff = llSize - pUser->llInboxSize;
    pUser->llInboxSize = llSize;

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT,
                     &pUser->ulInboxRefreshTimestamp, sizeof(ULONG) );
  }
  else
  {
    llSizeDiff = llSize - pUser->llImapSize;
    pUser->llImapSize = llSize;
  }

  pDomain->llSize += llSizeDiff;
  llMailRootSize += llSizeDiff;

  return llSizeDiff != 0;
}


/*  VOID _msSync()
 *
 *  Synchronization of the list of objects with the Weasel configuration.
 *  I.e. adds objects not listed in <MailRoot>\imap.xml but listed in the
 *  Weasel configuration and removes objects not listed in Weasel conf.
 */

static BOOL __readUserHomeSize(PUSER pUser, PDOMAIN pDomain, BOOL fInbox)
{
  CHAR                 acBuf[CCHMAXPATH];
  LONG                 cbBase;
  ULONG                cbDomainName = strlen( pDomain->acName );
  LLONG                llSize;

  cbBase = wcfgQueryMailRootDir( sizeof(acBuf) - 12 + ( cbDomainName +
                                 strlen( pUser->acName ) ), acBuf, NULL );
  if ( cbBase == -1 )
    return FALSE;

  if ( cbDomainName != 0 )
  {
    memcpy( &acBuf[cbBase], pDomain->acName, cbDomainName );
    cbBase += cbDomainName;
    acBuf[cbBase++] = '\\';
  }

  sprintf( &acBuf[cbBase], "%s\\%s",
           pUser->acName, fInbox ? "*.MSG" : "imap\\*.MSG" );

  if ( !_readFileList( acBuf, NULL, &llSize ) )
    return FALSE;

  _setSize( pUser, pDomain, fInbox, llSize );

  return TRUE;
}

static BOOL __syncUser(PSZ pszUser, ULONG ulUserFlags, PVOID pDomainPtr)
{
  PUSER      pUser;
  PDOMAIN    pDomain = (PDOMAIN)pDomainPtr;

  if ( _insertUser( pDomain, pszUser, &pUser ) )
  {
    ulFlags |= _FL_LIST_CHANGED;

    __readUserHomeSize( pUser, pDomain, TRUE );
    __readUserHomeSize( pUser, pDomain, FALSE );
  }

  if ( pUser != NULL )
    pUser->ulFlags = (pUser->ulFlags & ~(_FL_SYNC | _FL_QUOTAS_SYNC)) |
                     (ulFlags & (_FL_SYNC | _FL_QUOTAS_SYNC));

  return TRUE;
}

static BOOL __syncDomain(PSZ pszDomain, PVOID pUser)
{
  PDOMAIN    pDomain;
  BOOL       fDomAddeded = _insertDomain( pszDomain, &pDomain );

  if ( fDomAddeded )
    ulFlags |= _FL_LIST_CHANGED;

  if ( pDomain != NULL )
  {
    LONG     lIdx;
    LLONG    llSize;

    pDomain->ulFlags = (pDomain->ulFlags & ~(_FL_SYNC | _FL_QUOTAS_SYNC)) |
                       (ulFlags & (_FL_SYNC | _FL_QUOTAS_SYNC));
    wcfgForEachUser( pszDomain, __syncUser, pDomain );

    for( lIdx = pDomain->cUsers - 1; lIdx >= 0; lIdx-- )
    {
      if ( (pDomain->papUsers[lIdx]->ulFlags & _FL_SYNC) !=
           (ulFlags & _FL_SYNC) )
      {
        debug( "Remove user \"%s\"", pDomain->papUsers[lIdx]->acName );

        llSize = ( pDomain->papUsers[lIdx]->llInboxSize + 
                   pDomain->papUsers[lIdx]->llImapSize );

        pDomain->llSize -= llSize;
        llMailRootSize -= llSize;

        _userFree( pDomain->papUsers[lIdx] );
        pDomain->cUsers--;
        memcpy( &pDomain->papUsers[lIdx], &pDomain->papUsers[lIdx + 1],
                ( pDomain->cUsers - lIdx ) * sizeof(PUSER) );
        ulFlags |= _FL_LIST_CHANGED;
      }
    }

    if ( fDomAddeded )
      logf( 4, "Domain addeded: %s (%lld Kb)",
            pszDomain, pDomain->llSize / 1024 );
  }

  return TRUE;
}

static VOID _msSync()
{
  LONG       lIdx;

  // Invert global SYNC flag.
  ulFlags = (ulFlags & ~_FL_SYNC) | (~ulFlags & _FL_SYNC);

  wcfgForEachDomain( __syncDomain, NULL );

  for( lIdx = cDomains - 1; lIdx >= 0; lIdx-- )
  {
    if ( (papDomains[lIdx]->ulFlags & _FL_SYNC) !=
         (ulFlags & _FL_SYNC) )
    {
      logf( 4, "Domain removed: %s (%lld Kb)",
            papDomains[lIdx]->acName, papDomains[lIdx]->llSize / 1024 );

      debug( "Remove domain: %s", papDomains[lIdx]->acName );
      llMailRootSize -= papDomains[lIdx]->llSize;

      _domainFree( papDomains[lIdx] );
      cDomains--;
      memcpy( &papDomains[lIdx], &papDomains[lIdx + 1],
              ( cDomains - lIdx ) * sizeof(PDOMAIN) );
      ulFlags |= _FL_LIST_CHANGED;
    }
  }
}


// BOOL _findObjects(PSZ pszUHPath, PUSER *ppUser, PDOMAIN *ppDomain)
//
// Search DOMAIN and USER objects for given full/short path to user home
// directory or e-mail.

static BOOL _findObjectsSplitPath(PMSSPLITHOMEPATH pHomePath,
                                  PUSER *ppUser, PDOMAIN *ppDomain)
{
  PUSER                *ppFindUser;
  PDOMAIN              *ppFindDomain;

  // Search DOMAIN object.
  ppFindDomain = utilBSearch( pHomePath->acDomain, papDomains, cDomains,
                              sizeof(PDOMAIN), _compSearchDomain, NULL );
  if ( ppFindDomain == NULL )
  {
    debug( "Invalid domain directory name \"%s\"", pHomePath->acDomain );
    return FALSE;
  }

  // Search USER object in DOMAIN.
  ppFindUser = utilBSearch( pHomePath->pszUser, (*ppFindDomain)->papUsers,
                            (*ppFindDomain)->cUsers, sizeof(PUSER),
                            _compSearchUser, NULL );
  if ( ppFindUser == NULL )
  {
    debug( "Invalid user directory name \"%s\" in domain \"%s\"",
           pHomePath->pszUser, pHomePath->acDomain );
    return FALSE;
  }

  if ( ppDomain != NULL )
    *ppDomain  = *ppFindDomain;

  if ( ppUser != NULL )
    *ppUser    = *ppFindUser;

  return TRUE;
}

static BOOL _findObjects(PSZ pszUHPath, PUSER *ppUser, PDOMAIN *ppDomain)
{
  MSSPLITHOMEPATH      stHomePath;

  if ( !msSplitHomePath( pszUHPath, &stHomePath ) )
    return FALSE;

  return _findObjectsSplitPath( &stHomePath, ppUser, ppDomain );
}

// Writes storage state to <MailRoot>\imap.xml
static VOID _msSave()
{
  xmlDocPtr            pxmlDoc;
  xmlNodePtr           pxmlRoot, pxmlDomain, pxmlUsers, pxmlUser;
  ULONG                ulIdxDom, ulIdxUsr;
  PDOMAIN              pDomain;
  PUSER                pUser;
  CHAR                 acBuf[CCHMAXPATH];
  LONG                 cbBase, lRC;

  pxmlDoc = xmlNewDoc( "1.0" );
  if ( pxmlDoc == NULL )
  {
    debug( "xmlNewDoc() failed" );
    return;
  }

  pxmlRoot = xmlNewNode( NULL, "storage" );
  if ( pxmlRoot == NULL )
  {
    debug( "xmlNewNode() failed" );
    xmlFreeDoc( pxmlDoc );
    return;
  }
  xmlDocSetRootElement( pxmlDoc, pxmlRoot );
  xmlAddPrevSibling( pxmlRoot, xmlNewDocComment( pxmlDoc,
    " This is an automatically generated file. It will be read and "
    "overwritten.\n     Do Not Edit! " ) );

  for( ulIdxDom = 0; ulIdxDom < cDomains; ulIdxDom++ )
  {
    pDomain = papDomains[ulIdxDom];

    pxmlDomain = xmlNewChild( pxmlRoot, NULL, "domain", NULL );
    if ( ( pxmlDomain == NULL ) ||
         ( ( pDomain->acName != NULL ) &&
           ( xmlNewChild( pxmlDomain, NULL, "name", pDomain->acName ) ==
               NULL ) ) )
      break;

    pxmlUsers = xmlNewChild( pxmlDomain, NULL, "users", NULL );
    if ( pxmlUsers == NULL )
      break;

    for( ulIdxUsr = 0; ulIdxUsr < pDomain->cUsers; ulIdxUsr++ )
    {
      pUser = pDomain->papUsers[ulIdxUsr];

      pxmlUser = xmlNewChild( pxmlUsers, NULL, "user", NULL );
      if ( ( pxmlUsers == NULL ) ||
           ( xmlNewChild( pxmlUser, NULL, "name", pUser->acName ) == NULL ) ||
           ( xmlNewChild( pxmlUser, NULL, "inbox-size",
                        ulltoa( pUser->llInboxSize, acBuf, 10 ) ) == NULL ) ||
           ( xmlNewChild( pxmlUser, NULL, "imap-size",
                        ulltoa( pUser->llImapSize, acBuf, 10 ) ) == NULL ) )
        break;
    }

    if ( ulIdxUsr < pDomain->cUsers )
      break;
  }

  if ( ulIdxDom < cDomains )
  {
    debugCP( "Can't build XML tree" );
    xmlFreeDoc( pxmlDoc );
    return; 
  }

  // Save XML-tree to the file.

  cbBase = wcfgQueryMailRootDir( sizeof(acBuf) - 10, acBuf, "imap." );
  if ( cbBase == -1 )
  {
    debugCP( "Path too long" );
    xmlFreeDoc( pxmlDoc );
    return;
  }

  strcpy( &acBuf[cbBase], "#" );
  lRC = xmlSaveFormatFileEnc( acBuf, pxmlDoc, "UTF-8", 1 );
  xmlFreeDoc( pxmlDoc );

  if ( lRC == -1 )
    debug( "xmlSaveFormatFileEnc() failed" );
  else
  {
    CHAR     acFNameXML[CCHMAXPATH];
                                                // Data saved to imap.#.
    strcpy( &acBuf[cbBase], "bak" );
    memcpy( acFNameXML, acBuf, cbBase );
    strcpy( &acFNameXML[cbBase], "xml" );
    DosDelete( acBuf );                         // Delete imap.bak.
    lRC = DosMove( acFNameXML, acBuf );         // Rename imap.xml to imap.bak.
    if ( lRC != NO_ERROR )
      DosDelete( acFNameXML );                  // Failed - delete imap.xml.

    strcpy( &acBuf[cbBase], "#" );
    lRC = DosMove( acBuf, acFNameXML );         // Rename imap.# to imap.xml.
    if ( lRC != NO_ERROR )
      debug( "DosMove(), rc = %lu", lRC );
    else
      ulFlags &= ~_FL_LIST_CHANGED;
  }
}

// Sets a new time to save state changes.
static VOID _msDelayedSaving()
{
  ulFlags |= _FL_LIST_CHANGED;
  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulSaveTime, sizeof(ULONG) );
  ulSaveTime += _SAVE_DELAY;
}


/*  VOID _qSync()
 *
 *  Set limits for DOMAIN and USER dobject from the user file imapd-quotas.xml.
 */

// Reads pxmlNode/<limit> value (if present) converted to bytes, reads
// pxmlNode/<quota> (if present), resolves it to bytes. Returns minimum value
// or LLONG_MAX if neither of values is specified.
static LLONG __qXMLGetLimit(xmlNodePtr pxmlNode)
{
  LONG       cbBuf;
  CHAR       acBuf[64];
  xmlNodePtr pxmlSubNode = xmluGetChildNode( pxmlNode, "limit" );
  PSZ        pszVal;
  LLONG      llLimit = LLONG_MAX;
  LLONG      llQuota = LLONG_MAX;

  pszVal = xmluGetNodeText( pxmlSubNode );
  if ( ( pszVal != NULL ) && !utilStrToBytes( pszVal, &llLimit, UTIL_KB ) )
  {
    logf( 0, "Invalid limit value \"%s\" at line %d, "_XML_FILE,
          pszVal, xmlGetLineNo( pxmlSubNode ) );
  }

  pxmlSubNode = xmluGetChildNode( pxmlNode, "quota" );
  pszVal = xmluGetNodeText( pxmlSubNode );
  if ( pszVal != NULL )
  {
    cbBuf = xmluGetPathValue( pxmlNode->doc, sizeof(acBuf), acBuf,
                      "/quotas/presets/quota[@name='%s']/limit", pszVal );
    if ( cbBuf < 0 )
      logf( 0, "Quota \"%s\" is not specified at line %d, "_XML_FILE,
            pszVal, xmlGetLineNo( pxmlSubNode ) );
    else if ( !utilStrToBytes( acBuf, &llQuota, UTIL_KB ) )
      logf( 0, "Invalid quota \"%s\" value \"%s\", "_XML_FILE, pszVal, acBuf );
  }

  return MIN( llLimit, llQuota );
}

static VOID _qSync()
{
  CHAR                 acBuf[CCHMAXPATH];
  xmlDocPtr            pxmlDoc = NULL;
  xmlNodePtr           pxmlRoot, pxmlDomain, pxmlNode, pxmlMailRoot = NULL;
  PSZ                  pszVal;
  PCHAR                pcEnd;
  PDOMAIN              *ppDomain, pDomain;
  PUSER                *ppUser, pUser;
  LLONG                llLimit, llDomainDefLimit = LLONG_MAX;
  LLONG                llUserDefLimit;
  ULONG                ulIdx, ulUsrIdx;
  ULONG                ulSyncFl, ulNoBlockFl, ulDefNoBlockFl;
  BOOL                 fMultiDomain = wcfgQueryMultiDomain();

  // Invert global QUOTAS SYNC flag.
  ulFlags = (ulFlags & ~_FL_QUOTAS_SYNC) | (~ulFlags & _FL_QUOTAS_SYNC);
  // New QUOTAS SYNC flag.
  ulSyncFl = (ulFlags & _FL_QUOTAS_SYNC);

  if ( _getQuotasFName( sizeof(acBuf), acBuf ) )
  do
  {
    utilQueryFileInfo( acBuf, &stQFTimestamp, NULL );

    pxmlDoc = xmluReadFile( acBuf, "quotas", &pxmlRoot );
    if ( pxmlDoc == NULL )
    {
      logf( 6, "Could not load quotas configuration %s", acBuf );
      break;
    }

    if ( pszLetterFrom != NULL )
    {
      free( pszLetterFrom );
      pszLetterFrom = NULL;
    }

    if ( pszLetterBody != NULL )
    {
      free( pszLetterBody );
      pszLetterBody = NULL;
    }

    // Check quotas/enabled node.

    pszVal = xmluGetChildNodeText( pxmlRoot, "enable" );
    if ( pszVal != NULL )
    {
      pcEnd = strchr( pszVal, '\0' );
      while( ( pcEnd > (PCHAR)pszVal ) && isspace( *(pcEnd-1) ) )
        pcEnd--;
      if ( utilStrWordIndex( "1 YES Y ENABLE", pcEnd - (PCHAR)pszVal, pszVal )
           == -1 )
        pszVal = NULL;
    }

    logf( 3, "Load quotas configuration %s (%s)",
          acBuf, pszVal == NULL ? "disabled" : "enabled" );
    if ( pszVal == NULL )
      break;

    // Get notifiacation letter text and "from" attribute.
    pxmlNode = xmluGetChildNode( pxmlRoot, "notification-letter" );
    if ( pxmlNode != NULL )
    {
      pxmlNode = xmluGetChildNode( pxmlNode, "body" );
      if ( pxmlNode != NULL )
      {
        pszVal = xmluGetNodeText( pxmlNode );
        if ( ( pszVal != NULL ) && ( *pszVal != '\0' ) )
        {
          // Get "from" attribute of the "body" node.

          pszLetterBody = strdup( pszVal );
          pszVal = xmlGetNoNsProp( pxmlNode, "from" );
          if ( ( pszVal != NULL ) && ( *pszVal != '\0' ) )
          {
            if ( *pszVal == '@' )
              // Value should not begins with '@'.
              logf( 2, "Invalid \"from\" value for node \"body\" "
                    "at line %d, "_XML_FILE, xmlGetLineNo( pxmlNode ) );
            else
            {
              // Make copy of "from" value without trailing '@'.
              ULONG    cbVal = strlen( pszVal );

              if ( pszVal[cbVal - 1] == '@' )
                cbVal--;

              pszLetterFrom = malloc( cbVal + 1 );
              if ( pszLetterFrom != NULL )
              {
                memcpy( pszLetterFrom, pszVal, cbVal );
                pszLetterFrom[cbVal] = '\0';
              }
            }
          }  // if ( ( pszVal != NULL ) && ( *pszVal != '\0' ) )
        }  // if ( ( pszVal != NULL ) && ( *pszVal != '\0' ) )
      }  // if ( pxmlNode != NULL )
    }  // if ( pxmlNode != NULL )

    // Get quotas/mail-root node
    pxmlMailRoot = xmluGetChildNode( pxmlRoot, "mail-root" );
    if ( pxmlMailRoot == NULL )
      break;

    // Global storage limit.
    llMailRootLimit = __qXMLGetLimit( pxmlMailRoot );

    // Scan quotas/mail-root/domain nodes.
    for( pxmlDomain = xmluGetChildNode( pxmlMailRoot, "domain" );
         pxmlDomain != NULL;
         pxmlDomain = xmluGetNextNode( pxmlDomain, "domain" ) )
    {
      pszVal = xmlGetNoNsProp( pxmlDomain, "name" );
      llLimit = __qXMLGetLimit( pxmlDomain );
      pxmlNode = xmluGetChildNode( pxmlDomain, "user" );

      if ( fMultiDomain &&
           ( ( pszVal == NULL ) || ( *pszVal == '\0' ) ) )
      {
        // <domain> without name - default domain limit for not listed domains.
        llDomainDefLimit = llLimit;

        // Warning about non-empty user list in default <domain> node.
        if ( pxmlNode != NULL )
          logf( 2, "\"user\" nodes are ignored for the default domain "
                "at line %d, "_XML_FILE, xmlGetLineNo( pxmlNode ) );
        continue;
      }

      // Search DOMAIN object.
      ppDomain = utilBSearch( pszVal, papDomains, cDomains, sizeof(PDOMAIN),
                              _compSearchDomain, NULL );
      if ( ppDomain == NULL )
        continue;

      pDomain = *ppDomain;
      pDomain->llLimit = llLimit;
      // Mark DOMAIN object as "processed".
      pDomain->ulFlags = (pDomain->ulFlags & ~_FL_QUOTAS_SYNC) | ulSyncFl;

      // Scan domain/users nodes.
      llUserDefLimit = LLONG_MAX;
      ulDefNoBlockFl = 0;
      for( ; pxmlNode != NULL; pxmlNode = xmluGetNextNode( pxmlNode, "user" ) )
      {
        pszVal = xmlGetNoNsProp( pxmlNode, "name" );
        llLimit = __qXMLGetLimit( pxmlNode );
        ulNoBlockFl = utilStrWordIndex( "1 YES Y ENABLE", -1,
                        xmlGetNoNsProp( pxmlNode, "non-blocked" ) ) != -1
                        ? _FL_NO_BLOCK_ON_LIMIT : 0;

        if ( ( pszVal == NULL ) || ( *pszVal == '\0' ) )
        {
          // <user> without name - default user limit for not listed users.
          llUserDefLimit = llLimit;
          ulDefNoBlockFl = ulNoBlockFl;
          continue;
        }

        // Search USER object.
        ppUser = utilBSearch( pszVal, pDomain->papUsers, pDomain->cUsers,
                              sizeof(PUSER), _compSearchUser, NULL );
        if ( ppUser == NULL )
          continue;

        pUser = *ppUser;
        pUser->llLimit = llLimit;
        // Mark USER object as "processed".
        pUser->ulFlags = ( pUser->ulFlags &
                                ~(_FL_QUOTAS_SYNC | _FL_NO_BLOCK_ON_LIMIT) ) |
                         ulSyncFl | ulNoBlockFl;
      }

      // Set default limit for all unprocessed USER objects in DOMAIN.
      for( ulIdx = 0; ulIdx < pDomain->cUsers; ulIdx++ )
      {
        pUser = pDomain->papUsers[ulIdx];
        if ( (pUser->ulFlags & _FL_QUOTAS_SYNC) == (ulFlags & _FL_QUOTAS_SYNC) )
          continue;

        pUser->llLimit = llUserDefLimit;
        pUser->ulFlags =  ( pUser->ulFlags &
                                 ~(_FL_QUOTAS_SYNC | _FL_NO_BLOCK_ON_LIMIT) ) |
                          ulSyncFl | ulDefNoBlockFl;
      }
    }

    // Set default limit for all unprocessed DOMAIN objects.
    for( ulIdx = 0; ulIdx < cDomains; ulIdx++ )
    {
      pDomain = papDomains[ulIdx];
      if ( (pDomain->ulFlags & _FL_QUOTAS_SYNC) == (ulFlags & _FL_QUOTAS_SYNC) )
        continue;

      pDomain->llLimit = llDomainDefLimit;
      pDomain->ulFlags = (pDomain->ulFlags & ~_FL_QUOTAS_SYNC) | ulSyncFl;

      // Do not use by-user limits for the default domain limit.
      for( ulUsrIdx = 0; ulUsrIdx < pDomain->cUsers; ulUsrIdx++ )
      {
        pUser = pDomain->papUsers[ulUsrIdx];
        pUser->llLimit = LLONG_MAX;
        pUser->ulFlags = (pUser->ulFlags & ~_FL_QUOTAS_SYNC) | ulSyncFl;
      }
    }
  }
  while( FALSE );

  if ( pxmlDoc != NULL )
    xmlFreeDoc( pxmlDoc );

  if ( pxmlMailRoot == NULL )
  {
    // Quotas was not readed. Set maximum values for limits.

    llMailRootLimit = LLONG_MAX;

    for( ulIdx = 0; ulIdx < cDomains; ulIdx++ )
    {
      pDomain = papDomains[ulIdx];
      pDomain->llLimit = LLONG_MAX;
      pDomain->ulFlags = (pDomain->ulFlags & ~_FL_QUOTAS_SYNC) | ulSyncFl;

      for( ulUsrIdx = 0; ulUsrIdx < pDomain->cUsers; ulUsrIdx++ )
      {
        pUser = pDomain->papUsers[ulUsrIdx];
        pUser->llLimit = LLONG_MAX;
        pUser->ulFlags = (pUser->ulFlags & ~_FL_QUOTAS_SYNC) | ulSyncFl;
      }
    }
  }
}


/* ******************************************************************* */
/*                                                                     */
/*                          Public routines                            */
/*                                                                     */
/* ******************************************************************* */

BOOL msInit()
{
  ULONG                ulRC;

  ulRC = DosCreateMutexSem( NULL, &hmtxStorage, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  bzero( &stQFTimestamp, sizeof(stQFTimestamp) );

  return TRUE;
}

VOID msDone()
{
  ULONG      ulIdx;

  if ( (ulFlags & _FL_LIST_CHANGED) != 0 )
    _msSave();

  if ( hmtxStorage != NULLHANDLE )
    DosCloseMutexSem( hmtxStorage );

  for( ulIdx = 0; ulIdx < cDomains; ulIdx++ )
    _domainFree( papDomains[ulIdx] );

  if ( papDomains != NULL )
    free( papDomains );

  if ( pszLetterFrom != NULL )
    free( pszLetterFrom );

  if ( pszLetterBody != NULL )
    free( pszLetterBody );
}

VOID msSync()
{
  ULONG      ulRC;

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return;
  }

  if ( (ulFlags & _FL_LOADED) == 0 )
  do
  {
    // State was not loaded yet. Read state now from <MailRoot>\imap.xml

    LONG                 cbBase;
    CHAR                 acFName[CCHMAXPATH];
    xmlDocPtr            pxmlDoc;
    xmlNodePtr           pxmlRoot, pxmlDomain, pxmlUsers, pxmlUser;
    PDOMAIN              pDomain;
    PUSER                pUser;
    PSZ                  pszVal;
    ULONG                ulTime;

    cbBase = wcfgQueryMailRootDir( sizeof(acFName)-10, acFName, "imap." );
    if ( cbBase == -1 )
    {
      debugCP( "MailRoot is too long?" );
      break;
    }

    // Try to load imap.xml than imap.bak.
    strcpy( &acFName[cbBase], "xml" );
    debug( "Load %s", acFName );
    pxmlDoc = xmluReadFile( acFName, "storage", &pxmlRoot );
    if ( pxmlDoc == NULL )
    {
      debug( "XML load failed: %s, try to load *.bak", acFName );
      strcpy( &acFName[cbBase], "bak" );
      pxmlDoc = xmluReadFile( acFName, "storage", &pxmlRoot );
      if ( pxmlDoc == NULL )
      {
        debug( "XML load failed: %s", acFName );
        strcpy( &acFName[cbBase], "xml" );
        logf( 1, "Storage state data %s could not be loaded. "
                 "Please wait while storage is scanning...", acFName );
        break;
      }

      logf( 2, "Storage state data %s is loaded", acFName );
    }

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
    llMailRootSize = 0;

    // Scan /storage/domain nodes.
    for( pxmlDomain = xmluGetChildNode( pxmlRoot, "domain" ); pxmlDomain != NULL;
         pxmlDomain = xmluGetNextNode( pxmlDomain, "domain" ) )
    {
      // Create DOMAIN object from <domain> node.

      pszVal = xmluGetChildNodeText( pxmlDomain, "name" );

      _insertDomain( pszVal, &pDomain );
      if ( pDomain == NULL )
        continue;

      pxmlUsers = xmluGetChildNode( pxmlDomain, "users" );
      if ( pxmlUsers != NULL )
      {
        // Create USER objects from domain/users/user nodes.

        for( pxmlUser = xmluGetChildNode( pxmlUsers, "user" ); pxmlUser != NULL;
             pxmlUser = xmluGetNextNode( pxmlUser, "user" ) )
        {
          pszVal = xmluGetChildNodeText( pxmlUser, "name" );
          if ( ( pszVal == NULL ) || ( *pszVal == '\0' ) )
            continue;

          // Create a new USER object in DOMAIN object.
          _insertUser( pDomain, pszVal, &pUser );
          if ( pUser == NULL )
            break;

          pUser->ulInboxRefreshTimestamp = ulTime;   // Fake refresh timestamp.
          pUser->llInboxSize = xmluGetChildNodeLLong( pxmlUser,
                                                      "inbox-size", 0 );
          pUser->llImapSize = xmluGetChildNodeLLong( pxmlUser,
                                                     "imap-size", 0 );

          // Increase size for DOMAIN by USER's size.
          pDomain->llSize += ( pUser->llInboxSize + pUser->llImapSize );
        }
      }

      llMailRootSize += pDomain->llSize;
    }

    xmlFreeDoc( pxmlDoc );

    // We have loaded data from <MailRoot>\imap.xml. Do not do this anymore.
    ulFlags |= _FL_LOADED;
  }
  while( FALSE );

  // Synchronization DOMAIN (and USER) objects list with Weasel list.
  _msSync();

  // Set limits for DOMAINs and USERs from the user file imapd-quotas.xml.
  _qSync();

  if ( (ulFlags & _FL_LIST_CHANGED) != 0 )
  {
    // DOMAIN/USERS list was changed after synchronization with Weasel list.
    debugCP( "call _msSave()..." );
    _msSave();
  }

  DosReleaseMutexSem( hmtxStorage );
  debugCP( "Done" );
}

BOOL msReadMsgList(PSZ pszUHPath, BOOL fInbox, PMSLIST pList)
{
  ULONG                ulRC;
  PUSER                pUser = NULL;
  PDOMAIN              pDomain = NULL;
  BOOL                 fRes = FALSE;
  CHAR                 acBuf[CCHMAXPATH];
  LONG                 cbBase;
  LLONG                llSize;

  // Read files list to pList.

  if ( pList != NULL )
    bzero( pList, sizeof(MSLIST) );

  if ( isalpha( pszUHPath[0] ) && ( pszUHPath[1] == ':' ) &&
       ( pszUHPath[2] == '\\' ) )
  {
    // Full path is given.

    cbBase = strlen( pszUHPath );
    if ( ( cbBase < 3 ) || ( cbBase > (sizeof(acBuf) - ( fInbox ? 6 : 11 )) ) )
      return FALSE;

    memcpy( acBuf, pszUHPath, cbBase );
  }
  else
  {
    // Short path (domain\user) is given.

    cbBase = wcfgQueryMailRootDir( sizeof(acBuf) - ( fInbox ? 6 : 11 ), acBuf,
                                   pszUHPath );
    if ( cbBase == -1 )
      return FALSE;
  }

  if ( ( cbBase > 1 ) && ( acBuf[cbBase - 1] == '\\' ) )
    cbBase--;

  strcpy( &acBuf[cbBase], fInbox ? "\\*.MSG" : "\\imap\\*.MSG" );

  // Read list of files before locking (hmtxStorage).
  if ( !_readFileList( (PSZ)&acBuf, pList, &llSize ) )
    return FALSE;

  // Correct sizes.

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
    debug( "DosRequestMutexSem(), rc = %u" );
  else
  {
    if ( !_findObjects( pszUHPath, &pUser, &pDomain ) )
      debug( "Can't find records for %s", pszUHPath );
    else
    {
      if ( _setSize( pUser, pDomain, fInbox, llSize ) )
        // Size of object is changed.
        _msDelayedSaving();

      fRes = TRUE;
    }

    DosReleaseMutexSem( hmtxStorage );
  }

  if ( !fRes && ( pList != NULL ) )
    // Error - remove all records from the output list.
    msListDestroy( pList );

  return fRes;
}

VOID msListDestroy(PMSLIST pList)
{
  ULONG      ulIdx;

  for( ulIdx = 0; ulIdx < pList->ulCount; ulIdx++ )
  {
    if ( pList->papFiles[ulIdx] != NULL )
      free( pList->papFiles[ulIdx] );
  }

  if ( pList->papFiles != NULL )
    free( pList->papFiles );

  pList->papFiles = NULL;
  pList->ulCount = 0;
}

BOOL msListRemove(PMSLIST pList, PSZ pszFName)
{
  ULONG      ulIdx;

  for( ulIdx = 0; ulIdx < pList->ulCount; ulIdx++ )
  {
    if ( STR_ICMP( pList->papFiles[ulIdx]->acName, pszFName ) == 0 )
    {
      free( pList->papFiles[ulIdx] );
      pList->ulCount--;
      pList->papFiles[ulIdx] = pList->papFiles[pList->ulCount];
      return TRUE;
    }
  }

  return FALSE;
}

BOOL msListRemoveIdx(PMSLIST pList, ULONG ulIdx)
{
  if ( ulIdx >= pList->ulCount )
    return FALSE;

  free( pList->papFiles[ulIdx] );
  pList->ulCount--;
  pList->papFiles[ulIdx] = pList->papFiles[pList->ulCount];
  return TRUE;
}

BOOL msChange(PSZ pszUHPath, BOOL fInbox, LLONG llSizeDiff)
{
  PUSER      pUser = NULL;
  PDOMAIN    pDomain = NULL;
  BOOL       fRes = FALSE;
  ULONG      ulRC;

  if ( llSizeDiff == 0 )
    return TRUE;

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return FALSE;
  }

  if ( _findObjects( pszUHPath, &pUser, &pDomain ) )
  {
    if ( fInbox )
      pUser->llInboxSize += llSizeDiff;
    else
      pUser->llImapSize += llSizeDiff;

    pDomain->llSize += llSizeDiff;
    llMailRootSize += llSizeDiff;
    _msDelayedSaving();
    fRes = TRUE;
  }

  DosReleaseMutexSem( hmtxStorage );

  return fRes;
}

ULONG msCheckAvailableSize(PSZ pszUHPath, LLONG llSizeIncr)
{
  PUSER      pUser = NULL;
  PDOMAIN    pDomain = NULL;
  ULONG      ulRC;

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return MSR_INTERNAL_ERROR;
  }

  if ( !_findObjects( pszUHPath, &pUser, &pDomain ) )
    ulRC = MSR_NOT_FOUND;
  else
    ulRC = ( (pUser->ulFlags & _FL_NO_BLOCK_ON_LIMIT) != 0 ) ||
           ( ( (pUser->llInboxSize + pUser->llImapSize + llSizeIncr) <=
               pUser->llLimit ) &&
             ( (pDomain->llSize + llSizeIncr) <= pDomain->llLimit ) &&
             ( (llMailRootSize + llSizeIncr) <= llMailRootLimit ) )
             ? MSR_OK : MSR_EXCESS;

  DosReleaseMutexSem( hmtxStorage );

  return ulRC;
}

BOOL msMove(PSZ pszUHPath, BOOL fToInbox, LLONG llSize)
{
  ULONG      ulRC;
  PUSER      pUser = NULL;
  PDOMAIN    pDomain = NULL;
  BOOL       fRes = FALSE;

  if ( llSize == 0 )
    return TRUE;

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return FALSE;
  }

  if ( _findObjects( pszUHPath, &pUser, &pDomain ) )
  {
    if ( !fToInbox )
      llSize *= -1;

    pUser->llInboxSize += llSize;
    pUser->llImapSize -= llSize;
    _msDelayedSaving();
    fRes = TRUE;
  }

  DosReleaseMutexSem( hmtxStorage );

  return fRes;
}

BOOL msQueryInfoCtx(PCTX pCtx)
{
  ULONG      ulDomIdx, ulUsrIdx;
  PDOMAIN    pDomain;
  PUSER      pUser;
  ULONG      ulRC;
  CHAR       acBuf[64];

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return FALSE;
  }

  if ( ctxWriteFmtLn( pCtx, "MailRoot: %lld/%s",
                    llMailRootSize, LIMIT_TO_STR( llMailRootLimit, acBuf ) ) )
  {
    for( ulDomIdx = 0; ulDomIdx < cDomains; ulDomIdx++ )
    {
      pDomain = papDomains[ulDomIdx];
      if ( !ctxWriteFmtLn( pCtx, "Domain %s: %lld/%s",
                           pDomain->acName, pDomain->llSize,
                           LIMIT_TO_STR( pDomain->llLimit, acBuf ) ) )
        break;

      for( ulUsrIdx = 0; ulUsrIdx < pDomain->cUsers; ulUsrIdx++ )
      {
        pUser = pDomain->papUsers[ulUsrIdx];
        if ( !ctxWriteFmtLn( pCtx, "User %s: %lld,%lld/%s%s",
                             pUser->acName, pUser->llInboxSize,
                             pUser->llImapSize,
                             LIMIT_TO_STR( pUser->llLimit, acBuf ),
                             (pUser->ulFlags & _FL_NO_BLOCK_ON_LIMIT) != 0 ?
                               " (non-blocked)" : "" ) )
          break;
      }
    }
  }

  DosReleaseMutexSem( hmtxStorage );

  return ctxWrite( pCtx, 3, ".\r\n" );
}

ULONG msQuerySize(PSZ pszUHPath, PMSSIZE pSizeInfo)
{
  ULONG      ulRC;
  PDOMAIN    pDomain = NULL;
  PUSER      pUser = NULL;

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return MSR_INTERNAL_ERROR;
  }

  if ( !_findObjects( pszUHPath, &pUser, &pDomain ) )
    ulRC = MSR_NOT_FOUND;
  else
  {
    ULONG    ulTime;

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );

    if ( (ulTime - pUser->ulInboxRefreshTimestamp) >= _INBOX_REFRESH_PERIOD )
    {
      // INBOX has not been updated for a long time. Do it.

      // Release semaphore to allow read directory at msReadMsgList() without
      // locking.
      DosReleaseMutexSem( hmtxStorage );

      if ( msReadMsgList( pszUHPath, TRUE, NULL ) ) // Refresh INBOX size.
        return msQuerySize( pszUHPath, pSizeInfo );
    }

    pSizeInfo->llMailRoot      = llMailRootSize;
    pSizeInfo->llDomain        = pDomain->llSize;
    pSizeInfo->llInbox         = pUser->llInboxSize;
    pSizeInfo->llImap          = pUser->llImapSize;
    pSizeInfo->llMailRootLimit = llMailRootLimit;
    pSizeInfo->llDomainLimit   = pDomain->llLimit;;
    pSizeInfo->llUserLimit     = pUser->llLimit;
    ulRC = MSR_OK;
  }

  DosReleaseMutexSem( hmtxStorage );

  return ulRC;
}

BOOL msSaveCheck(ULONG ulTime)
{
  ULONG      ulRC;
  BOOL       fRes;

  ulRC = DosRequestMutexSem( hmtxStorage, SEM_IMMEDIATE_RETURN );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
      debug( "DosRequestMutexSem(), rc = %u" );
    return FALSE;
  }

  fRes = ( (ulFlags & _FL_LIST_CHANGED) != 0 ) &&
         ( ((ulSaveTime - ulTime) & 0x80000000) != 0 );
  if ( fRes )
    _msSave();

  DosReleaseMutexSem( hmtxStorage );

  return fRes;
}

VOID msUpdateQuotas()
{
  CHAR       acBuf[CCHMAXPATH];

  if ( _getQuotasFName( sizeof(acBuf), acBuf ) )
  {
    UTILFTIMESTAMP     stFTimestampNow;
    ULONG              ulRC;

    utilQueryFileInfo( acBuf, &stFTimestampNow, NULL );

    ulRC = DosRequestMutexSem( hmtxStorage, SEM_INDEFINITE_WAIT );
    if ( ulRC != NO_ERROR )
      debug( "DosRequestMutexSem(), rc = %u", ulRC );
    else
    {
      if ( !utilIsSameFileDateTime( &stFTimestampNow, &stQFTimestamp ) )
        _qSync();

      DosReleaseMutexSem( hmtxStorage );
    }
  }
}

/* pszPathname may be in different forms:
     D:\MailRoot\domain\user\file.MSG
     D:\MailRoot\user\file.MSG
     D:\MailRoot\domain\user
     D:\MailRoot\user
     domain\user\file.MSG
     user\file.MSG
     domain\user
     user
     user@domain
*/

BOOL msSplitHomePath(PSZ pszPathname, PMSSPLITHOMEPATH pHomePath)
{
  ULONG      cbPathname = STR_LEN( pszPathname );
  CHAR       acMailRoot[CCHMAXPATH];
  LONG       cbMailRoot;
  PCHAR      pcShortPath;
  ULONG      cbShortPath;
  BOOL       fFullName;
  BOOL       fMultiDomain;

  if ( cbPathname == 0 )
    return FALSE;

  fFullName = isalpha( *pszPathname ) && ( pszPathname[1] == ':' )
              && ( pszPathname[2] == '\\' );
  fMultiDomain = wcfgQueryMultiDomain();

  cbMailRoot = wcfgQueryMailRootDir( sizeof(acMailRoot), acMailRoot, NULL );
  if ( cbMailRoot == -1 )
    return FALSE;

  // Make full pathname in pHomePath->acPathname.

  if ( fFullName )
  {
    // Full path name is given.
    if ( ( cbPathname <= cbMailRoot ) ||
         ( memicmp( pszPathname, acMailRoot, cbMailRoot ) != 0 ) )
      return FALSE;

    strcpy( pHomePath->acPathname, pszPathname );
  }
  else
  {
    PCHAR    pcAt;

    if ( (cbMailRoot + cbPathname) >= CCHMAXPATH )
      return FALSE;

    memcpy( pHomePath->acPathname, acMailRoot, cbMailRoot );
    pcAt = strchr( pszPathname, '@' );

    if ( pcAt == NULL )
    {
      // Short pathname is given.
      strcpy( &pHomePath->acPathname[cbMailRoot], pszPathname );
    }
    else
    {
      // E-mail address is given.

      ULONG  cbUser = pcAt - (PCHAR)pszPathname;
      ULONG  cb;
      CHAR   acDomain[512];

      if ( cbUser == 0 )
        return FALSE;

      // Get domain name from given address which may be an alias.
      if ( !wcfgGetDomainName( &pcAt[1], sizeof(acDomain), acDomain ) )
      {
        debug( "No domain found for \"%s\"", &pcAt[1] );
        return FALSE;
      }

      if ( fMultiDomain )
      {
        strcpy( &pHomePath->acPathname[cbMailRoot], acDomain );
        cb = strlen( pHomePath->acPathname );
        pHomePath->acPathname[cb] = '\\';
        cb++;
      }
      else
        cb = cbMailRoot;
      memcpy( &pHomePath->acPathname[cb], pszPathname, cbUser );
      pHomePath->acPathname[cb + cbUser] = '\0';
    }
  }

  // Set pointer on the filename in pHomePath->pszFile.

  pcShortPath = (PSZ)&pHomePath->acPathname[cbMailRoot];

  pHomePath->pszFile = strchr( pcShortPath, '\\' );
  if ( pHomePath->pszFile != NULL )
    pHomePath->pszFile++;

  if ( fMultiDomain )
  {
    if ( pHomePath->pszFile == NULL )
      return FALSE;

    pHomePath->pszFile = strchr( pHomePath->pszFile, '\\' );
    if ( pHomePath->pszFile != NULL )
      pHomePath->pszFile++;
  }

  if ( ( pHomePath->pszFile != NULL ) && ( *pHomePath->pszFile == '\0' ) )
  {
    // Given path ends with slash.
    *(pHomePath->pszFile - 1) = '\0';
    pHomePath->pszFile = NULL;
  }

  // Make short path in pHomePath->acShortPath.

  if ( pHomePath->pszFile != NULL )
  {
    if ( strchr( pHomePath->pszFile, '\\' ) != NULL )
      return FALSE;

    cbShortPath = (PCHAR)pHomePath->pszFile - pcShortPath - 1;

    if ( *pHomePath->pszFile == '\0' )
      pHomePath->pszFile = NULL;
  }
  else
    cbShortPath = strlen( pcShortPath );

  if ( cbShortPath >= CCHMAXPATH )
    return FALSE;

  memcpy( pHomePath->acShortPath, pcShortPath, cbShortPath );
  pHomePath->acShortPath[cbShortPath] = '\0';

  // Set pointer on the username in pHomePath->pszUser.
  // Copy domain name to pHomePath->acDomain.

  if ( !fMultiDomain )
  {
    pHomePath->pszUser = pHomePath->acShortPath;
    pHomePath->acDomain[0] = '\0';
  }
  else
  {
    pHomePath->pszUser = strchr( pHomePath->acShortPath, '\\' );
    if ( pHomePath->pszUser == NULL )
      return FALSE;

    cbShortPath = (PCHAR)pHomePath->pszUser - pHomePath->acShortPath;
    pHomePath->pszUser++;
    memcpy( pHomePath->acDomain, pHomePath->acShortPath, cbShortPath );
    pHomePath->acDomain[cbShortPath] = '\0';
  }

  return TRUE;
}

typedef struct _LTRSUBSETDATA {
  PSZ        pszRcpt;
  CHAR       acFrom[512];
  CHAR       acBoundary[36];
  ULONG      cObjects;
  PSZ        *ppszObjects;
  PSZ        pszAttachMsg;
} LTRSUBSETDATA, *PLTRSUBSETDATA;

static ULONG _subsetLetter(PCTX pCtx, ULONG cbKey, PSZ pszKey, PVOID pData)
{
  PLTRSUBSETDATA       pSubsetData = (PLTRSUBSETDATA)pData;

  switch( utilStrWordIndex( "RCPT FROM FROM_DOMAIN MSG-ID DATE BOUNDARY "
                            "OBJECTS MESSAGE",
                            -1, pszKey ) )
  {
    case 0:            // RCPT
      return ctxWrite( pCtx, -1, pSubsetData->pszRcpt );

    case 1:            // FROM
      return ctxWrite( pCtx, -1, pSubsetData->acFrom );

    case 2:            // FROM_DOMAIN
      {
        PCHAR          pcAt = strchr( pSubsetData->acFrom, '@' );

        return ( pcAt == NULL ) || ctxWrite( pCtx, -1, &pcAt[1] );
      }

    case 3:            // MSG-ID
      {
        PCHAR          pcAt = strchr( pSubsetData->acFrom, '@' );
        CHAR           acBuf[256];
        LONG           cbBuf = imfGenerateMsgId( sizeof(acBuf), acBuf,
                                              pcAt == NULL ? NULL : &pcAt[1] );

        return ( cbBuf > 0 ) && ctxWrite( pCtx, cbBuf, acBuf );
      }

    case 4:            // DATE
      {
        // "Tue, 10 Oct 2017 03:55:13 +0500"
        static PSZ     aDOW[7] =
                         { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        static PSZ     aMonth[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        time_t         timeLtr = time( NULL );
        struct tm      *pTm = localtime( &timeLtr );
        LONG           lTZM = timezone / 60;
        LONG           cbBuf;
        CHAR           acBuf[64];

        cbBuf = _snprintf( acBuf, sizeof(acBuf),
                   "%s, %u %s %u %.2u:%.2u:%.2u %+.2d%.2d",
                   aDOW[pTm->tm_wday], pTm->tm_mday, aMonth[pTm->tm_mon],
                   1900 + pTm->tm_year, pTm->tm_hour, pTm->tm_min, pTm->tm_sec,
                   lTZM / 60, lTZM % 60 );

        return ( cbBuf > 0 ) && ctxWrite( pCtx, cbBuf, acBuf );
      }

    case 5:            // BOUNDARY
      return ctxWrite( pCtx, -1, pSubsetData->acBoundary );

    case 6:            // OBJECTS
      {
        ULONG          ulIdx;
        PCHAR          pcSeparator = strchr( pszKey, '\0' ) + 1;

        if ( *pcSeparator == '\0' )
          pcSeparator = " ";

        for( ulIdx = 0; ulIdx < pSubsetData->cObjects; ulIdx++ )
        {
          if ( ulIdx != 0 )
            ctxWrite( pCtx, -1, pcSeparator );

          ctxWrite( pCtx, -1, pSubsetData->ppszObjects[ulIdx] );
        }
      }
      return TRUE;

    case 7:
      if ( pSubsetData->pszAttachMsg != NULL )
      {
        HFILE          hFile = NULLHANDLE;
        ULONG          ulRC, ulActual;

        ulRC = DosOpenL( pSubsetData->pszAttachMsg, &hFile, &ulActual, 0, 0,
                         OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                         OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                         OPEN_SHARE_DENYWRITE | OPEN_ACCESS_READONLY, NULL );
        if ( ulRC != NO_ERROR )
        {
          debug( "Can't open message file: %s , rc = %u",
                 pSubsetData->pszAttachMsg, ulRC );
          return TRUE;
        }

        ctxFileRead( pCtx, hFile );
        DosClose( hFile );
      }
      return TRUE;
  }

  return TRUE;
}

static BOOL _getLetterFrom(PSZ pszLetterFrom, ULONG cObjects, PSZ *ppszObjects,
                           ULONG cbBuf, PCHAR pcBuf)
{
  PCHAR                pcAt;
  MSSPLITHOMEPATH      stHomePath;
  PWCFINDUSR           pFind;
  LONG                 lRC = -1;
  PSZ                  pszDomain;

  if ( pszLetterFrom == NULL )
  {
    pszLetterFrom = "postmaster";
    pcAt = NULL;
  }
  else
    pcAt = strchr( pszLetterFrom, '@' );

  if ( pcAt != NULL )
  {
    if ( strlen( pszLetterFrom ) >= cbBuf )
    {
      debug( "Address \"%s\" is too long", pszLetterFrom );
      return FALSE;
    }

    strcpy( pcBuf, pszLetterFrom );
    return TRUE;
  }

  msSplitHomePath( ppszObjects[0], &stHomePath );

  pFind = wcfgFindUserBegin( pszLetterFrom, WC_USRFL_ACTIVE );
  while( wcfgFindUser( pFind ) )
  {
    if ( pFind->pszDomainName != NULL )
      pszDomain = pFind->pszDomainName;
    else if ( ( pFind->pcDomainAliases != NULL ) &&
              ( *pFind->pcDomainAliases != '\0' ) )
      pszDomain = pFind->pcDomainAliases;
    else
      continue;

    lRC = _snprintf( pcBuf, cbBuf, "%s@%s", pszLetterFrom, pszDomain );
  
    if ( ( lRC != -1 ) &&
         ( stricmp( stHomePath.acDomain, 
                    pFind->pszDomainName == NULL
                      ? (PSZ)"" : pFind->pszDomainName ) == 0 ) )
      break;
  }
  wcfgFindUserEnd( pFind );

  if ( lRC == -1 )
  {
    CHAR     acBuf[256];

    if ( wcfgQueryOurHostName( sizeof(acBuf), acBuf ) != -1 )
      lRC = _snprintf( pcBuf, cbBuf, "%s@%s", pszLetterFrom, acBuf );
  }

  return lRC != -1;
}

VOID msSendExceededQuotaEMail(PSZ pszRcpt, ULONG cObjects, PSZ *ppszObjects,
                              PSZ pszAttachMsg)
{
  LONG       cbTemp;
  CHAR       acTemp[CCHMAXPATH];
  CHAR       acFwdFName[CCHMAXPATH];
  ULONG      ulRC, cbActual;
  HFILE      hFile;
  ULONG      cbHeader;
  PCHAR      pcHeader;
  HEV        hevForwardMail = NULLHANDLE;
  LTRSUBSETDATA        stSubsetData;
  PCTX       pCtx;

  if ( ( pszRcpt == NULL ) || ( *pszRcpt == '\0' ) || ( cObjects == 0 ) )
  {
    debugCP( "Invalid argument" );
    return;
  }

  if ( ( pszLetterBody == NULL ) ||
       !_getLetterFrom( pszLetterFrom, cObjects, ppszObjects,
                        sizeof(stSubsetData.acFrom), stSubsetData.acFrom ) )
    return;

  stSubsetData.pszRcpt        = pszRcpt;
  stSubsetData.cObjects       = cObjects;
  stSubsetData.ppszObjects    = ppszObjects;
  stSubsetData.pszAttachMsg   = pszAttachMsg;
  stSubsetData.acBoundary[0]  = '=';
  stSubsetData.acBoundary[1]  = '_';
  utilRndAlnum( sizeof(stSubsetData.acBoundary) - 3,
                &stSubsetData.acBoundary[2] );
  stSubsetData.acBoundary[sizeof(stSubsetData.acBoundary) - 1] = '\0';

  pCtx = ctxNewFromTemplate( -1, (PCHAR)pszLetterBody,
                             _subsetLetter, &stSubsetData );
  if ( pCtx == NULL )
  {
    debug( "utilStrKeysSubsetNew() failed" );
    return;
  }

  // Get path to the "forward" Weasel directory.
  cbTemp = wcfgQueryMailRootDir( sizeof(acTemp), acTemp, "forward" );
  if ( cbTemp == -1 )
  {
    ctxFree( pCtx );
    return;
  }

  // Open temporary file to write.
  ulRC = utilOpenTempFile( cbTemp, acTemp, 0, sizeof(acTemp), acTemp, &hFile );
  if ( ulRC != NO_ERROR )
  {
    debug( "utilOpenTempFile(,\"%s\",,,,), rc = %lu", acTemp, ulRC );
    ctxFree( pCtx );
    return;
  }

  // Create and write header for "forward" message.
  cbHeader = 10 + strlen( stSubsetData.acFrom ) + 1 + strlen( pszRcpt ) + 1;
  pcHeader = malloc( cbHeader + 1 );    // +1 for trailing ZERO from sprintf().
  if ( pcHeader == NULL )
  {
    DosClose( hFile );
    DosDelete( acTemp );
    ctxFree( pCtx );
    return;
  }
  memcpy( pcHeader, "V000\0\0\0\0\0\0", 10 );
  sprintf( &pcHeader[10], "%s(%s)", stSubsetData.acFrom, pszRcpt );
  DosWrite( hFile, pcHeader, cbHeader, &cbActual );
  free( pcHeader );

  ctxSetReadPos( pCtx, CTX_RPO_BEGIN, 0 );
  ctxFileWrite( pCtx, hFile );
  ctxFree( pCtx );
  DosClose( hFile );

  // Letter is created. Rename temporary file to *.FWD.
  ulRC = utilRenameFileToRndName( (PSZ)acTemp, "FWD",
                                  sizeof(acFwdFName), acFwdFName );
  if ( ulRC != NO_ERROR )
  {
    debug( "utilRenameFileToRndName(), rc = %u", ulRC );
    DosDelete( acTemp );
    return;
  }

  // Post semaphore to force Weasel to do a fresh check of the "forward"
  // directory.

  ulRC = DosOpenEventSem( "\\SEM32\\WEASEL\\FORWARDMAIL", &hevForwardMail );
  if ( ulRC != NO_ERROR )
    debug( "DosOpenEventSem(), rc = %lu", ulRC );
  else
  {
    ulRC = DosPostEventSem( hevForwardMail );
    if ( ulRC != NO_ERROR )
      debug( "DosPostEventSem(), rc = %lu", ulRC );
    DosCloseEventSem( hevForwardMail );
  }
}
