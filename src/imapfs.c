/*
  IMAP virtual file system.
*/

#include <string.h>
#include <ctype.h>
#define INCL_DOSFILEMGR
#define INCL_DOSMISC
#define INCL_DOSERRORS
#define INCL_DOSSEMAPHORES
#include <os2.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "wcfg.h"
#include "log.h"
#include "utils.h"
#include "xmlutils.h"
#include "hmem.h"
#include "context.h"
#include "storage.h"
#include "pop3.h"
#include "imapfs.h"
#include "debug.h"               // Should be last.

// The minimum period for checking the mailbox when processing next request.
#define _INBOX_CHECK_PERIOD_MIN      (60 * 1000)               // [msec]
// The maximum period for checking the mailbox when processing next request.
#define _INBOX_CHECK_PERIOD_MAX      (10 * 60 * 1000)          // [msec]
// The value on which the period will increase or decrease.
#define _INBOX_CHECK_PERIOD_STEP     (10 * 1000)               // [msec]
// Delay to save state of home directories with "dirty" flag set after fsSave().
#define _HOME_CHECK_SAVE_DELAY       (15 * 1000)               // [msec]
// Minimum loaded "home directory" objects even if they do not have sessions.
#define _KEEP_LOADED_USERHOME        20

#define _MSG_NAME_LENGTH         6
#define _COPY_FILE_BUF_SIZE      (80 * 1024)
#define _IMAP_SUBDIR             "\\imap"
#define _IMAP_SUBDIR_LEN         5
#define _LOSTMSG_MBOX            "Lost messages"
#define _RENAME_ITERATIONS       1000


typedef struct _NOTIFICATION {
  SEQOBJ               stSeqObj;
  ULONG                ulTime;
  CHAR                 acPathname[1];
} NOTIFICATION, *PNOTIFICATION;


PSZ   apszFSNotifyResults[6] =
{
  "+OK fixed",                             // FSNRC_FIXED              0
  "+OK delayed",                           // FSNRC_DELAYED            1
  "-ERR shutdown",                         // FSNRC_SHUTDOWN           2
  "-ERR internal error",                   // FSNRC_INTERNAL_ERROR     3
  "-ERR invalid pathname",                 // FSNRC_INVALID_PATHNAME   4
  "-ERR can not read the message list"     // FSNRC_CANNOT_READ_OBJ    5
};


// List of all created objects USERHOME.
static LINKSEQ         lsHome;             // List of USERHOME objects.
static HMTX            hmtxHome = NULLHANDLE;
static HEV             hevShutdown = NULLHANDLE;
static ULONG           ulInboxCheckPeriod = _INBOX_CHECK_PERIOD_MIN;
static HMTX            hmtxNotifications = NULLHANDLE;
static LINKSEQ         lsNotifications;


// _isShutdown() will return a successful return code if shutdown occurs. 
// This is used to avoid long-term operations after the shutdown event posted
// by fsShutdown().
#define _isShutdown() \
  ( DosWaitEventSem( hevShutdown, SEM_IMMEDIATE_RETURN ) != ERROR_TIMEOUT )

// Renames file pszOldPathname to unique name with ".MSG" extension.
// Stores a new name (without path) to pcNewName.
static ULONG __renameTempToMsgFile(PSZ pszOldFullName,
                                   ULONG cbNewName, PCHAR pcNewName)
{
  ULONG      ulRC;
  CHAR       acBuf[CCHMAXPATH];
  PCHAR      pcFName;

  ulRC = utilRenameFileToRndName( pszOldFullName, "MSG", sizeof(acBuf), acBuf );
  if ( ulRC != NO_ERROR )
  {
    logf( 0, "File rename %s to *.MSG error code: %lu", pszOldFullName, ulRC );
    return FSR_FAIL;
  }

  pcFName = strrchr( acBuf, '\\' );
  if ( pcFName == NULL )
    pcFName = acBuf;
  else
    pcFName++;

  if ( cbNewName <= strlen( pcFName ) )
    return FSR_FAIL;

  strcpy( pcNewName, pcFName );
  return FSR_OK;
}

static int __compSubscribe(const void *pS1, const void *pS2)
{
  PSZ        pszS1 = *((PSZ *)pS1), pszS2 = *((PSZ *)pS2);

  return stricmp( pszS1, pszS2 );
}

// Converts data from struct tm to the system file date/time structures.
static VOID __mkFTime(struct tm *pTM, PFDATE pFDate, PFTIME pFTime)
{
  pFDate->year    = pTM->tm_year - 80;
  pFDate->month   = pTM->tm_mon + 1;
  pFDate->day     = pTM->tm_mday;
  pFTime->hours   = pTM->tm_hour;
  pFTime->minutes = pTM->tm_min;
  pFTime->twosecs = pTM->tm_sec / 2;
}


/* *************************************************************** */
/*                                                                 */
/*                      Virtual directories                        */
/*                                                                 */
/* *************************************************************** */

static VOID _msgFree(PMESSAGE pMsg)
{
  hfree( pMsg );
}


static PMAILBOX _mboxNew(PVDIR pVDir, ULONG ulUIDValidity)
{
  PMAILBOX   pMailbox;

  if ( ( pVDir == NULL ) || ( pVDir->pMailbox != NULL ) )
    return NULL;

  pMailbox = hcalloc( 1, sizeof(MAILBOX) );
  if ( pMailbox == NULL )
    return NULL;

  pMailbox->pVDir = pVDir;
  pMailbox->ulUIDValidity = ulUIDValidity;
  pMailbox->ulUIDNext = 1;
  pVDir->pMailbox = pMailbox;

  return pMailbox;
}

static VOID _mboxFree(PMAILBOX pMailbox)
{
  ULONG      ulIdx;

  if ( pMailbox->papMessages != NULL )
  {
    for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
      _msgFree( pMailbox->papMessages[ulIdx] );
    hfree( pMailbox->papMessages );
  }

  if ( pMailbox->pVDir != NULL )
    pMailbox->pVDir->pMailbox = NULL;

  hfree( pMailbox );
}

// Returns UID of the new message or 0 on error.
static ULONG _mboxAddMessage(PMAILBOX pMailbox, PSZ pszFName, ULONG ulFlags)
{
  PMESSAGE   pMsg;

  if ( ( pszFName == NULL ) || ( *pszFName == '\0' ) )
    return 0;

  pMsg = hmalloc( sizeof(MESSAGE) + strlen( pszFName ) );
  if ( pMsg == NULL )
    return 0;

  if ( pMailbox->cMessages == pMailbox->ulMaxMessages )
  {
    PMESSAGE *pNew = hrealloc( pMailbox->papMessages,
                           (pMailbox->ulMaxMessages + 32) * sizeof(PMESSAGE) );

    if ( pNew == NULL )
    {
      free( pMsg );
      return 0;
    }

    pMailbox->papMessages = pNew;
    pMailbox->ulMaxMessages += 32;
  }

  pMsg->ulUID    = pMailbox->ulUIDNext;
  pMsg->ulFlags  = ulFlags;
  strcpy( pMsg->acFName, pszFName );

  pMailbox->papMessages[pMailbox->cMessages] = pMsg;
  pMailbox->cMessages++;

  pMailbox->ulUIDNext++;

  return pMsg->ulUID;
}

/*
2018-05-11 - Replaced with _mboxGetCnt()
static BOOL _mboxGetRecentCnt(PMAILBOX pMailbox)
{
  ULONG      ulIdx;
  ULONG      ulCount = 0;

  for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
    if ( (pMailbox->papMessages[ulIdx]->ulFlags & FSMSGFL_RECENT) != 0 )
      ulCount++;

  return ulCount;
}

2018-05-11 - No need any more.
// Returns sequence number (1..N).
static ULONG _mboxGetFirstUnseen(PMAILBOX pMailbox)
{
  ULONG      ulIdx;

  for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
    if ( (pMailbox->papMessages[ulIdx]->ulFlags & FSMSGFL_SEEN) == 0 )
      return (ulIdx + 1);

  return 0;
}
*/

static VOID _mboxGetCnt(PMAILBOX pMailbox, PULONG pulRecent, PULONG pulUnseen)
{
  ULONG      ulIdx;
  ULONG      ulRecent = 0;
  ULONG      ulUnseen = 0;

  for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
  {
    if ( (pMailbox->papMessages[ulIdx]->ulFlags & FSMSGFL_RECENT) != 0 )
      ulRecent++;
    if ( (pMailbox->papMessages[ulIdx]->ulFlags & FSMSGFL_SEEN) == 0 )
      ulUnseen++;
  }

  if ( pulRecent != NULL )
    *pulRecent = ulRecent;
  if ( pulUnseen != NULL )
    *pulUnseen = ulUnseen;
}


static PVDIR _vdirNew(PSZ pszName)
{
  PVDIR      pVDir = hmalloc( sizeof(VDIR) );

  pVDir->pszName = hstrdup( pszName );
  if ( pVDir->pszName == NULL )
  {
    hfree( pVDir );
    return NULL;
  }

  pVDir->pVDirParent = NULL;
  pVDir->pMailbox = NULL;
  lnkseqInit( &pVDir->lsVDir );

  return pVDir;
}

static VOID _vdirFree(PVDIR pVDir)
{
  lnkseqFree( &pVDir->lsVDir, PVDIR, _vdirFree );

  if ( pVDir->pMailbox != NULL )
    _mboxFree( pVDir->pMailbox );

  if ( pVDir->pszName != NULL )
    hfree( pVDir->pszName );

  hfree( pVDir );
}

static VOID _vdirInsert(PVDIR pVDir, PVDIR pVDirSub)
{
  if ( pVDirSub != NULL )
  {
    pVDirSub->pVDirParent = pVDir;
    lnkseqAdd( &pVDir->lsVDir, pVDirSub );
  }
}


static BOOL _homeSubscribe(PUSERHOME pHome, PSZ pszMailbox, BOOL fSubscribe);
static BOOL _homeCheckInbox(PUSERHOME pHome);

// Inserts (creates) a new VDir to the parent pVDirParent or to the root list
// of pHome if pVDirParent is NULL.
// Returns new VDir or an existing VDir named pszName.
static PVDIR __homeInsertVDir(PUSERHOME pHome, PVDIR pVDirParent, PSZ pszName)
{
  PVDIR      pVDir;
  PLINKSEQ   plsVDir = pVDirParent != NULL
                         ? &pVDirParent->lsVDir : &pHome->lsVDir;

  if ( ( pszName == NULL ) || ( *pszName == '\0' ) )
    pszName = "unknown";

  for( pVDir = (PVDIR)lnkseqGetFirst( plsVDir ); pVDir != NULL;
       pVDir = (PVDIR)lnkseqGetNext( pVDir ) )
  {
    if ( stricmp( pVDir->pszName, pszName ) == 0 )
      return pVDir;
  }

  pVDir = _vdirNew( pszName );
  if ( pVDir != NULL )
  {
    pVDir->pVDirParent = pVDirParent;
    lnkseqAdd( plsVDir, pVDir );
  }

  return pVDir;
}

static VOID __homeLoad(PUSERHOME pHome)
{
  xmlDocPtr            pxmlDoc;
  xmlNodePtr           pxmlRoot, pxmlVDir, pxmlVDirNext, pxmlMBox, pxmlMsg;
  xmlNodePtr           pxmlSubscribe;
  PVDIR                pVDir = NULL;
  PVDIR                pVDirParent;
  PSZ                  pszName, pszAttr;
  PMAILBOX             pMailbox;
  CHAR                 acFName[CCHMAXPATH];
  LONG                 cbFNameDir;
  ULONG                ulUID, ulFlags;
  MSLIST               stList;
  BOOL                 fInbox;

  cbFNameDir = wcfgQueryMailRootDir( sizeof(acFName) - _IMAP_SUBDIR_LEN - 10,
                                     acFName, pHome->pszPath );
  if ( cbFNameDir == -1 )
  {
    debugCP( "Path too long" );
    return;
  }

  // Read message files in imap subdirectory at home directory - all not inbox
  // messages.
  msReadMsgList( acFName, FALSE, &stList );

  strcpy( &acFName[cbFNameDir], _IMAP_SUBDIR );
  cbFNameDir += _IMAP_SUBDIR_LEN;

  // Try to load imap.xml than imap.bak.
  strcpy( &acFName[cbFNameDir], "\\imap.xml" );

  pxmlDoc = xmluReadFile( acFName, "home", &pxmlRoot );
  if ( pxmlDoc == NULL )
  {
    debug( "XML load failed: %s , try to load *.bak", acFName );
    strcpy( &acFName[cbFNameDir], "\\imap.bak" );
    pxmlDoc = xmluReadFile( acFName, "home", &pxmlRoot );
    if ( pxmlDoc == NULL )
    {
      // Mailbox configuration has not been loaded - collect all messages to
      // _LOSTMSG_MBOX mailbox.
      debug( "XML load failed: %s", acFName );
      strcpy( &acFName[cbFNameDir], "\\imap.xml" );
      logf( 6, "User home configuration %s could not be loaded", acFName );
      goto l00;
    }

    logf( 1, "User home backup configuration %s is loaded", acFName );
  }

  pxmlSubscribe = xmluGetChildNode( pxmlRoot, "subscribe" );
  pHome->ulMaxSubscribe = xmluChildElementCount( pxmlSubscribe, "item" );
  if ( pHome->ulMaxSubscribe != 0 )
  {
    pHome->cSubscribe = 0;
    pHome->ppszSubscribe = hmalloc( pHome->ulMaxSubscribe * sizeof(PSZ) );

    if ( pHome->ppszSubscribe == NULL )
      pHome->ulMaxSubscribe = 0;
    else
    {
      for( pxmlMBox = xmluGetChildNode( pxmlSubscribe, "item" );
           ( pxmlMBox != NULL ) && ( pHome->cSubscribe < pHome->ulMaxSubscribe );
           pxmlMBox = xmluGetNextNode( pxmlMBox, "item" ) )
      {
        pszName = xmluGetNodeText( pxmlMBox );
        if ( ( pszName == NULL ) || ( *pszName == '\0' ) )
          continue;

        pHome->ppszSubscribe[pHome->cSubscribe] =
          hstrdup( xmluGetNodeText( pxmlMBox ) );
        if ( pHome->ppszSubscribe[pHome->cSubscribe] != NULL )
          pHome->cSubscribe++;
      }

      qsort( pHome->ppszSubscribe, pHome->cSubscribe, sizeof(PSZ),
             __compSubscribe );
    }
  }

  pxmlVDir = xmluGetChildNode( pxmlRoot, "vdir" );
  pVDirParent = NULL;
  while( pxmlVDir != NULL )
  {
    // Read "vdir" node: create VDir object, mailbox in this VDir and messages
    // in mailbox.

    pszName = xmluGetChildNodeText( pxmlVDir, "name" );
    if ( ( pszName != NULL ) && ( *pszName != '\0' ) )
    {
      fInbox = ( pVDirParent == NULL ) && ( stricmp( pszName, "INBOX" ) == 0 );

      pVDir = __homeInsertVDir( pHome, pVDirParent, pszName );
      if ( pVDir == NULL )
        debug( "__homeInsertVDir() failed" );
      else
      {
        pxmlMBox = xmluGetChildNode( pxmlVDir, "mbox" );
        if ( pxmlMBox != NULL )
        {
          pszAttr = xmlGetNoNsProp( pxmlMBox, "uid-validity" );
          ulUID = pszAttr != NULL ? atol( pszAttr ) : pHome->ulUIDValidityNext;

          pMailbox = pVDir->pMailbox == NULL
                       ? _mboxNew( pVDir, ulUID ) : pVDir->pMailbox;

          if ( pMailbox != NULL )
          {
            if ( pHome->ulUIDValidityNext <= ulUID )
              pHome->ulUIDValidityNext = ulUID + 1;

            for( pxmlMsg = xmluGetChildNode( pxmlMBox, "msg" ); pxmlMsg != NULL;
                 pxmlMsg = xmluGetNextNode( pxmlMsg, "msg" ) )
            {
              pszName = xmluGetNodeText( pxmlMsg );
              if ( !fInbox && !msListRemove( &stList, pszName ) )
              {
                // The file does not exist.
                pHome->ulFlags |= FSUHF_DIRTY;
                continue;
              }

              pszAttr = xmlGetNoNsProp( pxmlMsg, "flags" );
              ulFlags = pszAttr != NULL
                          ? ( strtoul( pszAttr, NULL, 0 ) & FSMSGFL_ALLMASK )
                          : 0;

              pszAttr = xmlGetNoNsProp( pxmlMsg, "uid" );
              ulUID = pszAttr != NULL ? atol( pszAttr ) : 0;
              if ( ulUID != 0 )
                pMailbox->ulUIDNext = ulUID;

              _mboxAddMessage( pMailbox, pszName, ulFlags );
            }

            pszAttr = xmlGetNoNsProp( pxmlMBox, "uid-next" );
            ulUID = pszAttr != NULL ? atol( pszAttr ) : 0;
            if ( ulUID != 0 )
              pMailbox->ulUIDNext = ulUID;
          } // if ( pMailbox != NULL )
        } // if ( pxmlMBox != NULL )
      } // if ( pVDir != NULL )
    } // if ( ( pszName != NULL ) && ( *pszName != '\0' ) )

    // Get next "vdir" node.

    pxmlVDirNext = xmluGetChildNode( pxmlVDir, "vdir" );
    if ( pxmlVDirNext != NULL )
      pVDirParent = pVDir;
    else
    {
      do
      {
        pxmlVDirNext = xmluGetNextNode( pxmlVDir, "vdir" );
        if ( pxmlVDirNext != NULL )
          break;

        pxmlVDir = pxmlVDir->parent;

        if ( pVDir == NULL )
          // VDir has not been created (some error).
          pVDirParent = NULL;
        else
        {
          pVDir = pVDir->pVDirParent;
          if ( pVDir != NULL )
            pVDirParent = pVDir->pVDirParent;
        }
      }
      while( pxmlVDir != pxmlRoot );
    }

    pxmlVDir = pxmlVDirNext;
  }

  xmlFreeDoc( pxmlDoc );

l00:
  if ( stList.ulCount != 0 )
  {
    // We have a not listed (lost) non-inbox message files. Place all lost
    // messages in a special mailbox whose name is specified by _LOSTMSG_MBOX.

    pVDir = __homeInsertVDir( pHome, NULL, _LOSTMSG_MBOX );
    if ( pVDir == NULL )
      debug( "__homeInsertVDir(,,\"%s\") failed", _LOSTMSG_MBOX );
    else
    {
      pMailbox = pVDir->pMailbox;
      if ( pMailbox == NULL )
      {
        pMailbox = _mboxNew( pVDir, pHome->ulUIDValidityNext );
        pHome->ulUIDValidityNext++;
      }

      if ( pMailbox != NULL )
      {
        for( ulUID = 0; ulUID < stList.ulCount; ulUID++ )
          _mboxAddMessage( pMailbox, stList.papFiles[ulUID]->acName,
                           FSMSGFL_RECENT );

        _homeSubscribe( pHome, _LOSTMSG_MBOX, TRUE );
        pHome->ulFlags |= FSUHF_DIRTY;
      }
    }
  }

  msListDestroy( &stList );
}

static VOID __homeSave(PUSERHOME pHome)
{
  xmlDocPtr            pxmlDoc;
  xmlNodePtr           pxmlRoot, pxmlVDir, pxmlMBox, pxmlMsg;
  PVDIR                pVDir, pVDirNext;
  PMAILBOX             pMailbox;
  PMESSAGE             pMsg;
  CHAR                 acBuf[CCHMAXPATH];
  LONG                 lIdx;
  LONG                 cbPath;

  if ( ( pHome->pszPath == NULL ) || ( (pHome->ulFlags & FSUHF_DIRTY) == 0 ) )
    return;

  pxmlDoc = xmlNewDoc( "1.0" );
  if ( pxmlDoc == NULL )
  {
    debug( "xmlNewDoc() failed" );
    return;
  }

  pxmlRoot = xmlNewNode( NULL, "home" );
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

  if ( pHome->cSubscribe != 0 )
  {
    xmlNodePtr         pxmlSubscribe = xmlNewChild( pxmlRoot, NULL,
                                                    "subscribe", NULL );

    if ( pxmlSubscribe != NULL )
    {
      for( lIdx = 0; lIdx < pHome->cSubscribe; lIdx++ )
        xmlAddChild( 
          xmlNewChild( pxmlSubscribe, NULL, "item", NULL ),
          xmlNewCDataBlock( pxmlDoc, BAD_CAST pHome->ppszSubscribe[lIdx],
                                        strlen( pHome->ppszSubscribe[lIdx] ) ) );
    }
  }

  pVDir = (PVDIR)lnkseqGetFirst( &pHome->lsVDir );
  while( pVDir != NULL )
  {
    // Build "vdir" XML-tree.

    pxmlVDir = xmlNewChild( pxmlRoot, NULL, "vdir", NULL );
    if ( pxmlVDir == NULL )
      break;
    xmlAddChild( xmlNewChild( pxmlVDir, NULL, "name", NULL ),
                 xmlNewCDataBlock( pxmlDoc, BAD_CAST pVDir->pszName,
                                   strlen( pVDir->pszName ) ) );

    if ( pVDir->pMailbox != NULL )
    {
      pMailbox = pVDir->pMailbox;

      pxmlMBox = xmlNewChild( pxmlVDir, NULL, "mbox", NULL );
      if ( pxmlMBox == NULL )
        break;

      xmlNewProp( pxmlMBox, "uid-validity",
                  ltoa( pMailbox->ulUIDValidity, acBuf, 10 ) );
      xmlNewProp( pxmlMBox, "uid-next",
                  ltoa( pMailbox->ulUIDNext, acBuf, 10 ) );
      for( lIdx = 0; lIdx < pMailbox->cMessages; lIdx++ )
      {
        pMsg = pMailbox->papMessages[lIdx];

        pxmlMsg = xmlNewChild( pxmlMBox, NULL, "msg", pMsg->acFName );
        if ( pxmlMsg == NULL )
          break;

        xmlNewProp( pxmlMsg, "uid", ltoa( pMsg->ulUID, acBuf, 10 ) );
        sprintf( acBuf, "0x%lX", pMsg->ulFlags );
        xmlNewProp( pxmlMsg, "flags", acBuf );
      }
    }

    // Get next VDir object.

    pVDirNext = (PVDIR)lnkseqGetFirst( &pVDir->lsVDir );
    if ( pVDirNext != NULL )
      pxmlRoot = pxmlVDir;
    else
    {
      do
      {
        pVDirNext = (PVDIR)lnkseqGetNext( pVDir );
        if ( pVDirNext != NULL )
          break;
        pVDir = pVDir->pVDirParent;

        pxmlVDir = pxmlVDir->parent;
        if ( pxmlVDir == NULL )
          debugCP( "WTF?!" );
        pxmlRoot = pxmlVDir->parent;
      }
      while( pVDir != NULL );
    }

    pVDir = pVDirNext;
  }

  // Save XML-tree to the file.

  cbPath = wcfgQueryMailRootDir( sizeof(acBuf) - _IMAP_SUBDIR_LEN - 10, acBuf,
                                pHome->pszPath );
  if ( cbPath == -1 )
  {
    debugCP( "Path too long" );
    xmlFreeDoc( pxmlDoc );
    return;
  }
  strcpy( &acBuf[cbPath], _IMAP_SUBDIR );
  cbPath += _IMAP_SUBDIR_LEN;

  DosCreateDir( acBuf, NULL );
  strcpy( &acBuf[cbPath], "\\imap.#" );
  lIdx = xmlSaveFormatFileEnc( acBuf, pxmlDoc, "UTF-8", 1 );
  xmlFreeDoc( pxmlDoc );

  if ( lIdx == -1 )
    debug( "xmlSaveFormatFileEnc() failed" );
  else
  {
    CHAR     acFNameXML[CCHMAXPATH];
    ULONG    ulRC;
                                                // USERHOME saved to imap.#.
    strcpy( &acBuf[cbPath], "\\imap.bak" );
    memcpy( acFNameXML, acBuf, cbPath );
    strcpy( &acFNameXML[cbPath], "\\imap.xml" );
    DosDelete( acBuf );                         // Delete imap.bak.
    ulRC = DosMove( acFNameXML, acBuf );        // Rename imap.xml to imap.bak.
    if ( ulRC != NO_ERROR )
      DosDelete( acFNameXML );                  // Failed - delete imap.xml.

    strcpy( &acBuf[cbPath], "\\imap.#" );
    ulRC = DosMove( acBuf, acFNameXML );        // Rename imap.# to imap.xml.
    if ( ulRC != NO_ERROR )
      debug( "DosMove(), rc = %u", ulRC );
    else
      pHome->ulFlags &= ~FSUHF_DIRTY;
  }
}

static PUSERHOME _homeNew(PSZ pszPath)
{
  PUSERHOME            pHome;
  CHAR                 acBuf[CCHMAXPATH - _IMAP_SUBDIR_LEN];
  FILESTATUS3          sInfo;
  ULONG                ulRC;
  PVDIR                pVDir;
  PMAILBOX             pInbox;

  if ( wcfgQueryMailRootDir( sizeof(acBuf), acBuf, pszPath ) == -1 )
  {
    debugCP( "Pathname too long" );
    return NULL;
  }

  ulRC = DosQueryPathInfo( acBuf, FIL_STANDARD, &sInfo, sizeof(FILESTATUS3) );
  if ( ulRC != NO_ERROR )
  {
    debug( "The path \"%s\" does not exist", acBuf );
    return NULL;
  }

  if ( (sInfo.attrFile & FILE_DIRECTORY) == 0 )
  {
    debug( "The path \"%s\" is not a directory", pszPath );
    return NULL;
  }

  pHome = hcalloc( 1, sizeof(USERHOME) );
  if ( pHome == NULL )
    return NULL;

  pHome->pszPath = hstrdup( pszPath );
  if ( pHome->pszPath != NULL )
  do
  {
    ulRC = DosCreateMutexSem( NULL, &pHome->hmtxLock, 0, FALSE );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosCreateMutexSem(), rc = %u", ulRC );
      break;
    }

    lnkseqInit( &pHome->lsVDir );
    lnkseqInit( &pHome->lsSess );

    // Create imap directory in user's home directory.
    strcat( acBuf, _IMAP_SUBDIR );
    DosCreateDir( acBuf, NULL );

    // Create default mailbox INBOX.
    pVDir = _vdirNew( "INBOX" );
    if ( pVDir == NULL )
      break;
    lnkseqAdd( &pHome->lsVDir, pVDir );
    pInbox = _mboxNew( pVDir, 1 );
    if ( pInbox == NULL )
    {
      _vdirFree( pVDir );
      break;
    }
    pHome->ulUIDValidityNext = 2;

    __homeLoad( pHome );         // Load VDir objects and mailboxes structure.

/*  2017-09-25 Call _homeCheckInbox() moved to fsQueryMailbox(). Now INBOX will
               be synchronized only when it selected for the first time.
    debugCP( "call _homeCheckInbox()..." );
    _homeCheckInbox( pHome );    // Synchronize INBOX. */

    return pHome;
  }
  while( FALSE );

  if ( pHome->hmtxLock != NULLHANDLE )
    DosCloseMutexSem( pHome->hmtxLock );

  if ( pHome->pszPath != NULL )
    hfree( pHome->pszPath );

  hfree( pHome );

  return NULL;
}

static VOID _homeFree(PUSERHOME pHome)
{
  ULONG      ulIdx;

  __homeSave( pHome );

  if ( lnkseqGetCount( &pHome->lsSess ) != 0 )
  {
    debugCP( "Failed: USERHOME linked with UHSESS objects" );
    return;
  }

  lnkseqFree( &pHome->lsVDir, PVDIR, _vdirFree );

  if ( pHome->pszPath != NULL )
    hfree( pHome->pszPath );

  DosCloseMutexSem( pHome->hmtxLock );

  if ( pHome->ppszSubscribe != NULL )
  {
    for( ulIdx = 0; ulIdx < pHome->cSubscribe; ulIdx++ )
      hfree( pHome->ppszSubscribe[ulIdx] );

    hfree( pHome->ppszSubscribe );
  }

  hfree( pHome );
}

static ULONG _homeRemoveSess(PUSERHOME pHome, PUHSESS pUHSess)
{
  lnkseqRemove( &pHome->lsSess, pUHSess );
  return lnkseqGetCount( &pHome->lsSess );
}

static VOID _homeAddSess(PUSERHOME pHome, PUHSESS pUHSess)
{
  lnkseqAdd( &pHome->lsSess, pUHSess );
}

static PVDIR _homeGetVDir(PUSERHOME pHome, PSZ pszMailbox, BOOL fCreate)
{
  PLINKSEQ   plsVDir;
  PVDIR      pVDir = NULL;
  PVDIR      pVDirPrev = NULL;
  PSZ        pszLeft, pszVDir;

  if ( ( pszMailbox == NULL ) || ( *pszMailbox == '\0' ) )
    return NULL;

  pszMailbox = strdup( pszMailbox );       // Low memory pointer.
  if ( pszMailbox == NULL )
    return NULL;
  pszLeft = pszMailbox;

  plsVDir = &pHome->lsVDir;

  while( utilStrCutVDir( &pszLeft, &pszVDir ) )
  {
    if ( plsVDir == NULL )
      pVDir = NULL;
    else
    {
      for( pVDir = (PVDIR)lnkseqGetFirst( plsVDir ); pVDir != NULL;
           pVDir = (PVDIR)lnkseqGetNext( pVDir ) )
      {
        if ( stricmp( pszVDir, pVDir->pszName ) == 0 )
          break;
      }
    }

    if ( pVDir == NULL )
    {
      if ( !fCreate )
        break;

      pVDir = _vdirNew( pszVDir );
      if ( pVDir == NULL )
        break;

      if ( pVDirPrev == NULL )
        lnkseqAdd( &pHome->lsVDir, pVDir );
      else
        _vdirInsert( pVDirPrev, pVDir );
      plsVDir = NULL;
    }
    else
      plsVDir = &pVDir->lsVDir;

    pVDirPrev = pVDir;
  }

  free( pszMailbox );                      // Low memory pointer.

  return pVDir;
}

// Inserts (fSubscribe is TRUE) or removes (fSubscribe is FALSE) given mailbox
// pathname (pszMailbox) to the subscribe list.
static BOOL _homeSubscribe(PUSERHOME pHome, PSZ pszMailbox, BOOL fSubscribe)
{
  ULONG      ulIndex;
  PVDIR      pVDir;
  PSZ        *ppszFound = utilBSearch( (const void *)&pszMailbox,
                                      pHome->ppszSubscribe,  pHome->cSubscribe, 
                                      sizeof(PSZ), __compSubscribe, &ulIndex );

  if ( fSubscribe )
  {
    if ( ppszFound != NULL )
    {
      debug( "\"%s\" already subscribed", pszMailbox );
      return TRUE;
    }

    pVDir = _homeGetVDir( pHome, pszMailbox, FALSE );
    if ( ( pVDir == NULL ) /*|| ( pVDir->pMailbox == NULL )*/ )
      return FALSE;

    pszMailbox = hstrdup( pszMailbox );
    if ( pszMailbox == NULL )
      return FALSE;

    if ( pHome->cSubscribe == pHome->ulMaxSubscribe )
    {
      PSZ      *ppszNew = hrealloc( pHome->ppszSubscribe,
                                   (pHome->ulMaxSubscribe + 8) * sizeof(PSZ) );

      if ( ppszNew == NULL )
      {
        hfree( pszMailbox );
        return FALSE;
      }

      pHome->ulMaxSubscribe += 8;
      pHome->ppszSubscribe = ppszNew;
    }

    memmove( &pHome->ppszSubscribe[ulIndex + 1],
             &pHome->ppszSubscribe[ulIndex],
             (pHome->cSubscribe - ulIndex) * sizeof(PSZ) );
    pHome->ppszSubscribe[ulIndex] = pszMailbox;
    pHome->cSubscribe++;
  }
  else
  {
    if ( ppszFound == NULL )
    {
      debug( "\"%s\" is not subscribed", pszMailbox );
      return FALSE;
    }

    hfree( *ppszFound );
    pHome->cSubscribe--;
    memcpy( ppszFound, &ppszFound[1],
            (pHome->cSubscribe - ulIndex) * sizeof(PSZ) );
  }

  return TRUE;
}

// Sets "mailbox changed" flags ulFlags (FSSESSFL_xxxxxCH) for sessions with
// home object pHome which have selected mailbox pMailbox.
static VOID _homeBroadcastMailboxCh(PUSERHOME pHome, PMAILBOX pMailbox,
                                    ULONG ulFlags)
{
  PUHSESS    pScan;

  if ( ulFlags == 0 )
    return;

  for( pScan = (PUHSESS)lnkseqGetFirst( &pHome->lsSess );
       pScan != NULL; pScan = (PUHSESS)lnkseqGetNext( pScan ) )
  {
    if ( pScan->pSelMailbox != pMailbox )
      continue;

    pScan->ulFlags |= ulFlags;
  }
}

// Register message flags changes and messages deleting (ulFlags = ~0) for
// sessions with home object pHome which have selected mailbox pMailbox.
static VOID _homeBroadcastMessageCh(PUSERHOME pHome, PMAILBOX pMailbox,
                                    ULONG ulSeqNum, ULONG ulFlags)
{
  PUHSESS    pScan;

  for( pScan = (PUHSESS)lnkseqGetFirst( &pHome->lsSess );
       pScan != NULL; pScan = (PUHSESS)lnkseqGetNext( pScan ) )
  {
    if ( pScan->pSelMailbox != pMailbox )
      continue;

    if ( (pScan->cChgMsg & 0x0F) == 0 )
    {
      PCHGMSG  pNew = hrealloc( pScan->pChgMsg,
                                (pScan->cChgMsg + 0x10) * sizeof(CHGMSG) );
      if ( pNew == NULL )
        return;
      pScan->pChgMsg = pNew;
    }

    pScan->pChgMsg[pScan->cChgMsg].ulSeqNum = ulSeqNum;
    pScan->pChgMsg[pScan->cChgMsg].ulFlags  = ulFlags;
    pScan->cChgMsg++;
  }
}

// Synchronizes the contents of the INBOX mailbox in USERHOME object with the
// list of files in the home directory. Sessions where this INBOX selected will
// be notified of changes.
// Returns TRUE if any changes are detected.
static BOOL _homeCheckInbox(PUSERHOME pHome)
{
  MSLIST     stList;
  PVDIR      pVDir = _homeGetVDir( pHome, "INBOX", FALSE );
  LONG       lIdx;
  PMAILBOX   pMailbox;
  PMESSAGE   pMsg;
  ULONG      cMessages;
  ULONG      ulMBoxChFl = 0;
  LONG       lRecentCh = 0;
  BOOL       fFileListChanged = FALSE;

  if ( ( pVDir == NULL ) || ( pVDir->pMailbox == NULL ) )
  {
    debugCP( "WTF?! INBOX does not exist" );
    return FALSE;
  }

  // Read message files list for INBOX.
  if ( !msReadMsgList( pHome->pszPath, TRUE, &stList ) )
    return FALSE;

  pMailbox = pVDir->pMailbox;
  cMessages = pMailbox->cMessages;

  // Delete non-existent messages from mailbox object.
  for( lIdx = pMailbox->cMessages - 1; lIdx >= 0; lIdx-- )
  {
    pMsg = pMailbox->papMessages[lIdx];
    if ( !msListRemove( &stList, pMsg->acFName ) )
    {
      // The message file is missing.

      if ( (pMsg->ulFlags & FSMSGFL_RECENT) != 0 )
        lRecentCh--;

      // Delete message object from mailbox object.
      //debug( "Delete message from mailbox %s", pVDir->pszName );
      _msgFree( pMsg );
      pMailbox->cMessages--;
      memcpy( &pMailbox->papMessages[lIdx], &pMailbox->papMessages[lIdx + 1],
              (pMailbox->cMessages - lIdx) * sizeof(PMESSAGE) );

      // Inform all sessions with selected mailbox pMailbox about deleted
      // message.
      _homeBroadcastMessageCh( pHome, pMailbox, lIdx + 1, ~0 );

      fFileListChanged = TRUE;
    }
  }

  // Add new messages to mailbox object.
  for( lIdx = 0; lIdx < stList.ulCount; lIdx++ )
  {
    if ( _mboxAddMessage( pMailbox, stList.papFiles[lIdx]->acName,
                          FSMSGFL_RECENT ) )
    {
      lRecentCh++;
      fFileListChanged = TRUE;
      //debug( "A new message was added to mailbox %s", pVDir->pszName );
    }
  }

  msListDestroy( &stList );              // Destroy message files list.

  // Inform all sessions with selected mailbox pMailbox about changes in
  // mailbox.

  /*
    Was:
    if ( cMessages != pMailbox->cMessages )

    [RFC 3501] 5.2. Mailbox Size and Message Status Updates
    ... it is NOT permitted to send an EXISTS response that would reduce the
    number of messages in the mailbox; only the EXPUNGE response can do this.
  */
  if ( cMessages < pMailbox->cMessages )
    // Nubmber of messages in the mailbox has (was:changed) increased.
    ulMBoxChFl = FSSESSFL_EXISTSCH;

  if ( lRecentCh != 0 )
    // Number of messages with \Recent flag has changed.
    ulMBoxChFl |= FSSESSFL_RECENTCH;

  _homeBroadcastMailboxCh( pHome, pMailbox, ulMBoxChFl );

  pHome->ulFlags |= FSUHF_INBOX_CHECKED;
  if ( fFileListChanged )
    pHome->ulFlags |= FSUHF_DIRTY;

  // Store mailbox checking timestamp.
  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &pHome->ulInboxChkTimestamp,
                   sizeof(ULONG) );

  return fFileListChanged;
}

static LONG _homeQueryMBoxPath(PUSERHOME pHome, PMAILBOX pMailbox,
                               ULONG cbPath, PCHAR pcPath)
{
  PCHAR    pcBuf = pcPath;
  LONG     lRC;

  lRC = wcfgQueryMailRootDir( cbPath, pcBuf, pHome->pszPath );
  if ( lRC == -1 )
  {
    debug( "MailRoot + home (%s) path name too long", pHome->pszPath );
    return -1;
  }

  pcBuf += lRC;

  if ( stricmp( pMailbox->pVDir->pszName, "INBOX" ) != 0 )
  {
    if ( (cbPath - lRC) <= _IMAP_SUBDIR_LEN )
    {
      debugCP( "Pathname too long" );
      return -1;
    }
    strcpy( pcBuf, _IMAP_SUBDIR );
    pcBuf += _IMAP_SUBDIR_LEN;
  }

  return ( pcBuf - pcPath );
}

// pszMailbox should not be INBOX
static BOOL _homeDeleteMailbox(PUSERHOME pHome, PSZ pszMailbox)
{
  PVDIR      pVDir, pVDirScan, pVDirLast = NULL;
  PMAILBOX   pMailbox;

  pVDir = _homeGetVDir( pHome, pszMailbox, TRUE );
  if ( pVDir == NULL )
  {
    debug( "VDir \"%s\" not found", pszMailbox );
    return FALSE;
  }

  pMailbox = pVDir->pMailbox;
  if ( pMailbox != NULL )
  {
    PUHSESS            pScan;
    ULONG              ulIdx, ulRC;
    CHAR               acBuf[CCHMAXPATH];
    LONG               cbBuf;
    PMESSAGE           pMsg;
    FILESTATUS3L       sInfo;
    LLONG              llSize = 0;

    // Unset selected mailbox for sessions which has selected our mailbox.
    for( pScan = (PUHSESS)lnkseqGetFirst( &pHome->lsSess );
         pScan != NULL; pScan = (PUHSESS)lnkseqGetNext( pScan ) )
    {
      if ( pScan->pSelMailbox == pMailbox )
      {
        pScan->pSelMailbox = NULL;
        pScan->cChgMsg = 0;
        if ( pScan->pChgMsg != NULL )
        {
          hfree( pScan->pChgMsg );
          pScan->pChgMsg = NULL;
        }
      }
    }

    // Delete message files.
    cbBuf = _homeQueryMBoxPath( pHome, pMailbox, sizeof(acBuf), acBuf );
    if ( cbBuf != -1 )
    {
      acBuf[cbBuf] = '\\';
      cbBuf++;
      for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
      {
        pMsg = pMailbox->papMessages[ulIdx];

        if ( ( cbBuf + strlen( pMsg->acFName ) ) >= sizeof(acBuf) )
          debugCP( "File name is too long" );
        else
        {
          strcpy( &acBuf[cbBuf], pMsg->acFName );

          ulRC = DosQueryPathInfo( acBuf, FIL_STANDARDL,
                                   &sInfo, sizeof(FILESTATUS3L) );
          if ( ulRC != NO_ERROR )
            debug( "DosQueryPathInfo(), rc = %u" );
          else
            llSize += sInfo.cbFile;

          ulRC = DosDelete( acBuf );
          if ( ulRC != NO_ERROR )
            debug( "DosDelete(\"%s\"), rc = %u", acBuf, ulRC );
        }
      }

      msChange( pHome->pszPath, FALSE, -llSize );
    }

    _mboxFree( pMailbox );
    pVDir->pMailbox = NULL;
  }

  pHome->ulFlags |= FSUHF_DIRTY;

  // Search inferior hierarchical mailbox.
  while( TRUE )
  {
    if ( pVDirLast == NULL )
      pVDirScan = (PVDIR)lnkseqGetFirst( &pVDir->lsVDir );
    else
    {
      pVDirScan = (PVDIR)lnkseqGetFirst( &pVDirLast->lsVDir );

      if ( pVDirScan == NULL )
      {
        do
        {
          pVDirScan = (PVDIR)lnkseqGetNext( pVDirLast );
          if ( pVDirScan != NULL )
            break;
          pVDirLast = pVDirLast->pVDirParent;
        }
        while( pVDirLast != pVDir );
      }
    }

    if ( pVDirScan == NULL )
      break;

    if ( pVDirScan->pMailbox != NULL )
      // We have inferior hierarchical mailbox and must not remove inferior
      // hierarchical VDir objects. Our resuil is TRUE if mailbox was removed.
      return TRUE;

    pVDirLast = pVDirScan;
  }

  // Remove given virtual directory with subdirectories.
  lnkseqRemove( pVDir->pVDirParent == NULL ? &pHome->lsVDir
                                           : &pVDir->pVDirParent->lsVDir,
                pVDir );
  _vdirFree( pVDir );

  return TRUE;
}

static VOID _homeSave(PUSERHOME pHome)
{
  ULONG      ulTime;

  if ( (pHome->ulFlags & FSUHF_DIRTY) == 0 )
    return;

  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
  ulTime += _HOME_CHECK_SAVE_DELAY;
  pHome->ulSaveTime = ulTime;
  pHome->ulFlags |= FSUHF_SAVE_DELAY;
}

// Creates and open a new temporary file in given mailbox path.
// Returns full name in pcFName and file's handle in phFile.
static ULONG _sessOpenTempMsgFile(PUHSESS pUHSess, PMAILBOX pMailbox,
                                  ULLONG ullSize,
                                  ULONG cbFName, PCHAR pcFName, PHFILE phFile)
{
  ULONG      ulRC;
  LONG       cbBuf;
  CHAR       acBuf[CCHMAXPATH];

  cbBuf = _homeQueryMBoxPath( pUHSess->pHome, pMailbox, sizeof(acBuf), acBuf );
  if ( cbBuf == -1 )
    return FSR_FAIL;

  ulRC = utilOpenTempFile( cbBuf, acBuf, ullSize, cbFName, pcFName, phFile );
  switch( ulRC )
  {
    case NO_ERROR:         ulRC = FSR_OK; break;
    case ERROR_DISK_FULL:  ulRC = FSR_DISK_FULL; break;
    default:
      logf( 0, "Error creating %s, error code: %lu", acBuf, ulRC );
      ulRC = FSR_FAIL;
  }

  return ulRC;
}

static ULONG _sessCopyMsg(PUHSESS pUHSess, PFSENUMMSG pEnum,
                          PMAILBOX pDstMailbox,
                          PULONG pulNewUID, PULLONG pullSize)
{
  FILESTATUS3L         sInfo;
  ULONG                ulRC;
  CHAR                 acDstPathname[CCHMAXPATH];
  CHAR                 acMsgFile[_MSG_NAME_LENGTH + 5];
  HFILE                hSrcFile, hDstFile;
  PCHAR                pcBuf;
  ULONG                ulActual;

  // Open source file.

  ulRC = DosOpenL( pEnum->acFile, &hSrcFile, &ulActual, 0, 0,
                   OPEN_ACTION_FAIL_IF_NEW | OPEN_ACTION_OPEN_IF_EXISTS,
                   OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_SEQUENTIAL |
                   OPEN_SHARE_DENYWRITE | OPEN_ACCESS_READONLY, NULL );
  if ( ulRC != NO_ERROR )
  {
    debug( "Can't open source file: %s , rc = %u", pEnum->acFile, ulRC );
    return FSR_FAIL;
  }

  ulRC = DosQueryFileInfo( hSrcFile, FIL_STANDARDL, &sInfo,
                           sizeof(FILESTATUS3L) );
  if ( ulRC != NO_ERROR )
  {
    debug( "#1 DosQueryFileInfo(), rc = %u", ulRC );
    DosClose( hSrcFile );
    return FSR_FAIL;
  }

  // Create an unique file name and open destination file.

  ulRC = _sessOpenTempMsgFile( pUHSess, pDstMailbox, sInfo.cbFile,
                               sizeof(acDstPathname), acDstPathname, &hDstFile );
  if ( ulRC != FSR_OK )
  {
    DosClose( hSrcFile );
    return ulRC;
  }

  // Copy file.

  ulRC = DosAllocMem( (PVOID *)&pcBuf, _COPY_FILE_BUF_SIZE,
                      PAG_COMMIT | PAG_READ | PAG_WRITE );
  if ( ulRC != NO_ERROR )
    debug( "DosAllocMem(), rc = %u", ulRC );
  else
  {
    do
    {
      ulRC = DosRead( hSrcFile, pcBuf, _COPY_FILE_BUF_SIZE, &ulActual );
      if ( ulRC != NO_ERROR )
      {
        debug( "DosRead(), rc = %u", ulRC );
        break;
      }

      ulRC = DosWrite( hDstFile, pcBuf, ulActual, &ulActual );
      if ( ulRC != NO_ERROR )
        debug( "DosWrite(), rc = %u", ulRC );
    }
    while( ( ulRC == NO_ERROR ) && ( ulActual == _COPY_FILE_BUF_SIZE ) );

    DosFreeMem( pcBuf );

    if ( ulRC == NO_ERROR )
    {
      // Copy time for destionation file from the source file.

      FILESTATUS3L     sDstInfo;

      ulRC = DosQueryFileInfo( hDstFile, FIL_STANDARDL, &sDstInfo,
                               sizeof(FILESTATUS3L) );
      if ( ulRC != NO_ERROR )
        debug( "#2 DosQueryFileInfo(), rc = %u", ulRC );
      else
      {
        sDstInfo.fdateCreation    = sInfo.fdateCreation;
        sDstInfo.ftimeCreation    = sInfo.ftimeCreation;
        sDstInfo.fdateLastAccess  = sInfo.fdateLastAccess;
        sDstInfo.ftimeLastAccess  = sInfo.ftimeLastAccess;
        sDstInfo.fdateLastWrite   = sInfo.fdateLastWrite;
        sDstInfo.ftimeLastWrite   = sInfo.ftimeLastWrite;

        ulRC = DosSetFileInfo( hDstFile, FIL_STANDARDL, &sDstInfo,
                               sizeof(FILESTATUS3L) );
        if ( ulRC != NO_ERROR )
          debug( "DosSetFileInfo(), rc = %u", ulRC );
      }
    }  // if ( ulRC == NO_ERROR )
  }  // if ( ulRC != NO_ERROR ) else

  DosClose( hSrcFile );
  DosClose( hDstFile );

  if ( ulRC == NO_ERROR )
    // Rename destination file to .MSG
    ulRC = __renameTempToMsgFile( acDstPathname, sizeof(acMsgFile), acMsgFile );

  if ( ulRC != NO_ERROR /* NO_ERROR equal FSR_OK */ )
  {
    ulRC = DosDelete( acDstPathname );
    if ( ulRC != NO_ERROR )
      debug( "#1 DosDelete(\"%s\"), rc = %u", acDstPathname, ulRC );
    return FSR_FAIL;
  }

  // Create a new record in the destination mailbox.
  ulActual = _mboxAddMessage( pDstMailbox, acMsgFile,
                              pEnum->ulFlags | FSMSGFL_RECENT );
  if ( ulActual == 0 )
  {
    ulRC = DosDelete( acMsgFile );
    if ( ulRC != NO_ERROR )
      debug( "#2 DosDelete(\"%s\"), rc = %u", acMsgFile, ulRC );
    return FSR_FAIL;
  }

  if ( pulNewUID != NULL )
    *pulNewUID = ulActual;

  if ( pullSize != NULL )
    *pullSize = sInfo.cbFile;

  pUHSess->pHome->ulFlags |= FSUHF_DIRTY;

  return FSR_OK;
}

// Sets "mailbox changed" flags ulFlags (FSSESSFL_xxxxxCH) for sessions other
// than pUHSess which have selected mailbox pMailbox.
static VOID _sessBroadcastMailboxCh(PUHSESS pUHSess, PMAILBOX pMailbox,
                                    ULONG ulFlags)
{
  PMAILBOX   pSelMailbox;

  pSelMailbox = pUHSess->pSelMailbox;
  pUHSess->pSelMailbox = NULL;         // Avoid register changes for pUHSess.
  _homeBroadcastMailboxCh( pUHSess->pHome, pMailbox, ulFlags );
  pUHSess->pSelMailbox = pSelMailbox;
}

// Register message flags changes and messages deleting (ulFlags = ~0) for
// sessions other than pUHSess which have selected mailbox pMailbox.
static VOID _sessBroadcastMessageCh(PUHSESS pUHSess, PMAILBOX pMailbox,
                                    ULONG ulSeqNum, ULONG ulFlags)
{
  PMAILBOX   pSelMailbox;

  pSelMailbox = pUHSess->pSelMailbox;
  pUHSess->pSelMailbox = NULL;         // Avoid register changes for pUHSess.
  _homeBroadcastMessageCh( pUHSess->pHome, pMailbox, ulSeqNum, ulFlags );
  pUHSess->pSelMailbox = pSelMailbox;
}

static ULONG _sessMove(PUHSESS pUHSess, PMAILBOX pDstMailbox,
                       PUTILRANGE pSeqSet, PUTILRANGE pUIDSet,
                       PCOPYUID pMoveUID)
{
  FSENUMMSG      stEnum;
  ULLONG         ullMoveBytes = 0;
  FILESTATUS3L   sInfo;
  ULONG          ulRC;
  CHAR           acFile[CCHMAXPATH];
  PSZ            pszFName;
  PMAILBOX       pSrcMailbox = pUHSess->pSelMailbox;
  LONG           lIdx, cbPath;
  PMESSAGE       pMsg;
  BOOL           fDstIsInbox =
                   stricmp( pDstMailbox->pVDir->pszName, "INBOX" ) == 0;
  BOOL           fSrcIsInbox =
                   stricmp( pSrcMailbox->pVDir->pszName, "INBOX" ) == 0;
  BOOL           fPOP3Lock;

  if ( pMoveUID != NULL )
  {
    pMoveUID->pSrcUIDs = NULL;
    pMoveUID->pDstUIDs = NULL;
    pMoveUID->ulUIDValidity = pDstMailbox->ulUIDValidity;
  }

  if ( fDstIsInbox || fSrcIsInbox )
  {
    fPOP3Lock = pop3Lock( pUHSess->pHome->pszPath, TRUE );
    if ( !fPOP3Lock )
      return FSR_POP3_LOCKED;
  }

  // Move messages.

  fsEnumMsgBegin( pUHSess, &stEnum, pSeqSet, pUIDSet );

  while( fsEnumMsg( pUHSess, &stEnum ) )
  {
    ulRC = DosQueryPathInfo( stEnum.acFile, FIL_STANDARDL, &sInfo,
                             sizeof(FILESTATUS3L) );
    if ( ulRC != NO_ERROR )
    {
      debug( "DosQueryFileInfo(), rc = %u", ulRC );
      continue;
    }

    if ( fSrcIsInbox != fDstIsInbox )
    {
      // Moving files between <home> and <home\imap> directories.

      cbPath = _homeQueryMBoxPath( pUHSess->pHome, pDstMailbox,
                                   sizeof(acFile) - 11, acFile );
      if ( cbPath == -1 )
      {
        debug( "_homeQueryMBoxPath() failed" );
        continue;
      }
      acFile[cbPath] = '\\';
      cbPath++;

      for( lIdx = 0; lIdx < 200; lIdx++ )
      {
        utilRndAlnum( 6, &acFile[cbPath] );
        strcpy( &acFile[cbPath + 6], ".MSG" );
        ulRC = DosMove( stEnum.acFile, acFile );
        if ( ulRC != ERROR_ACCESS_DENIED ) // ERROR_ACCESS_DENIED - file exist.
          break;
      }

      if ( ulRC != NO_ERROR )
      {
        debug( "DosMove(), rc = %lu", ulRC );
        continue;
      }

      pszFName = (PSZ)&acFile[cbPath];
    }
    else
      pszFName = pSrcMailbox->papMessages[stEnum.ulIndex - 1]->acFName;

    // Create a new record in the destination mailbox.
    ulRC = _mboxAddMessage( pDstMailbox, pszFName,
                            stEnum.ulFlags | FSMSGFL_RECENT );
    if ( ulRC == 0 )
      break;
    stEnum.ulFlags |= FSMSGFL_INTERNAL_MOVED;

    if ( pMoveUID != NULL )
    {
      utilNumSetInsert( &pMoveUID->pSrcUIDs, stEnum.ulUID );
      utilNumSetInsert( &pMoveUID->pDstUIDs, ulRC );
    }

    ullMoveBytes += sInfo.cbFile;
  }

  fsEnumMsgEnd( pUHSess, &stEnum );

  if ( ullMoveBytes != 0 )
  {
    // Remove messages from the source mailbox.
    for( lIdx = pSrcMailbox->cMessages - 1; lIdx >= 0; lIdx-- )
    {
      pMsg = pSrcMailbox->papMessages[lIdx];
      if ( (pMsg->ulFlags & FSMSGFL_INTERNAL_MOVED) == 0 )
        continue;

      // Notify sessions which have select source mailbox about removed message.
      // _sessBroadcastMessageCh( pUHSess, pUHSess->pSelMailbox, lIdx, ~0 );
      // Including pUHSess session.
      _homeBroadcastMessageCh( pUHSess->pHome, pSrcMailbox, lIdx + 1, ~0 );

      _msgFree( pMsg );
      pSrcMailbox->cMessages--;
      memcpy( &pSrcMailbox->papMessages[lIdx],
              &pSrcMailbox->papMessages[lIdx + 1],
              (pSrcMailbox->cMessages - lIdx) * sizeof(PMESSAGE) );
    }

    // Correct storage size counters.
    if ( fSrcIsInbox != fDstIsInbox )
      msMove( pUHSess->pHome->pszPath, fDstIsInbox, ullMoveBytes );

    _sessBroadcastMailboxCh( pUHSess, pDstMailbox,
                             FSSESSFL_EXISTSCH | FSSESSFL_RECENTCH );
    pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
  }

  if ( fPOP3Lock )
    pop3Lock( pUHSess->pHome->pszPath, FALSE );

  return FSR_OK;
}

#define _sessLockHome(__pUHSess) \
  DosRequestMutexSem( (__pUHSess)->pHome->hmtxLock, SEM_INDEFINITE_WAIT )

#define _sessUnlockHome(__pUHSess) \
  DosReleaseMutexSem( (__pUHSess)->pHome->hmtxLock )


/* *************************************************************** */
/*                                                                 */
/*                        Public routines                          */
/*                                                                 */
/* *************************************************************** */

BOOL fsInit()
{
  ULONG      ulSeed;
  ULONG      ulRC;

  lnkseqInit( &lsHome );
  lnkseqInit( &lsNotifications );

  ulRC = DosCreateMutexSem( NULL, &hmtxHome, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(,&hmtxHome,,), rc = %u", ulRC );
    return FALSE;
  }

  ulRC = DosCreateMutexSem( NULL, &hmtxNotifications, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(,&hmtxNotifications,,), rc = %u", ulRC );
    DosCloseMutexSem( hmtxHome );
    return FALSE;
  }

  ulRC = DosCreateEventSem( NULL, &hevShutdown, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateEventSem(), rc = %u", ulRC );
    DosCloseMutexSem( hmtxHome );
    DosCloseMutexSem( hmtxNotifications );
    return FALSE;
  }

  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulSeed, sizeof(ULONG) );
  srand( ulSeed );

  return TRUE;
}

VOID fsDone()
{
  ULONG      ulRC;

  if ( hmtxHome != NULLHANDLE )
  {
    ulRC = DosCloseMutexSem( hmtxHome );
    if ( ulRC != NO_ERROR )
      debug( "DosCloseMutexSem(hmtxHome), rc = %u", ulRC );
  }

  if ( hmtxNotifications != NULLHANDLE )
  {
    ulRC = DosCloseMutexSem( hmtxNotifications );
    if ( ulRC != NO_ERROR )
      debug( "DosCloseMutexSem(hmtxNotifications), rc = %u", ulRC );
  }

  if ( hevShutdown != NULLHANDLE )
  {
    ulRC = DosCloseEventSem( hevShutdown );
    if ( ulRC != NO_ERROR )
      debug( "DosCloseEventSem(), rc = %u", ulRC );
  }

  lnkseqFree( &lsNotifications, PNOTIFICATION, hfree );
  lnkseqFree( &lsHome, PUSERHOME, _homeFree );
}

VOID fsShutdown()
{
  DosPostEventSem( hevShutdown );
}


BOOL fsSessInit(PUHSESS pUHSess)
{
  memset( pUHSess, 0, sizeof(UHSESS) );
  return TRUE;
}

VOID fsSessDone(PUHSESS pUHSess)
{
  if ( pUHSess->pHome != NULL )
  {
    fsSave( pUHSess );
    _sessLockHome( pUHSess );
    _homeRemoveSess( pUHSess->pHome, pUHSess );
    _sessUnlockHome( pUHSess );
  }

  if ( pUHSess->pChgMsg != NULL )
    hfree( pUHSess->pChgMsg );
}

BOOL fsSessOpen(PUHSESS pUHSess, PSZ pszHomeDir)
{
  PUSERHOME  pHome, pNext;
  ULONG      ulRC;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FALSE;
  }

  if ( pUHSess->pHome != NULL )
  {
    debug( "Session for %s is already open", pszHomeDir );
    return FALSE;
  }

  ulRC = DosRequestMutexSem( hmtxHome, SEM_INDEFINITE_WAIT );
//  ulRC = DosRequestMutexSem( hmtxHome, 2000 );
  if ( ulRC != NO_ERROR )
  {
//logf( 1, "[EXT] fsSessOpen(): DosRequestMutexSem(hmtxHome,), rc = %u", ulRC );
    debug( "DosRequestMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  for( pHome = (PUSERHOME)lnkseqGetFirst( &lsHome ); pHome != NULL;
       pHome = (PUSERHOME)lnkseqGetNext( pHome ) )
  {
    if ( stricmp( pszHomeDir, pHome->pszPath ) == 0 )
    {
      pUHSess->pHome = pHome;
      _sessLockHome( pUHSess );
      _homeAddSess( pHome, pUHSess );
      _sessUnlockHome( pUHSess );

      // USERHOME will be inserted to the end of list. Remove it now.
      lnkseqRemove( &lsHome, pHome );
      break;
    }
  }

  if ( pHome == NULL )
  {
    // USERHOME object for given home directory was not found. Create a new.
    pHome = _homeNew( pszHomeDir );
    if ( pHome == NULL )
    {
      debug( "_homeNew() failed" );
      DosReleaseMutexSem( hmtxHome );
      return FALSE;
    }

    pUHSess->pHome = pHome;
    _homeAddSess( pHome, pUHSess );
  }

  // Add USERHOME object to global list.
  lnkseqAdd( &lsHome, pHome );

  // Remove loaded extra USERHOME objects without sessions.
  if ( lnkseqGetCount( &lsHome ) > _KEEP_LOADED_USERHOME )
  {
    pHome = (PUSERHOME)lnkseqGetFirst( &lsHome );
    while( pHome != NULL )
    {
      pNext = (PUSERHOME)lnkseqGetNext( pHome );

      ulRC = DosRequestMutexSem( pHome->hmtxLock, SEM_IMMEDIATE_RETURN );
      if ( ulRC == NO_ERROR )
      {
        if ( lnkseqGetCount( &pHome->lsSess ) == 0 )
        {
          lnkseqRemove( &lsHome, pHome );
          DosReleaseMutexSem( pHome->hmtxLock );
          _homeFree( pHome );

          if ( lnkseqGetCount( &lsHome ) <= _KEEP_LOADED_USERHOME );
            break;
        }
        else
          DosReleaseMutexSem( pHome->hmtxLock );
      }

      pHome = pNext;
    }
  }

  DosReleaseMutexSem( hmtxHome );

  return TRUE;
}

VOID fsFindBegin(PUHSESS pUHSess, PFSFIND pFind, PSZ pszPtrn)
{
  debugInc( "fsFind" );
  memset( pFind, 0, sizeof(FSFIND) );
  pFind->pszPtrn = pszPtrn;
  _sessLockHome( pUHSess );
}

VOID fsFindEnd(PUHSESS pUHSess, PFSFIND pFind)
{
  _sessUnlockHome( pUHSess );
  if ( pFind->pszName != NULL )
    free( pFind->pszName );                // Low memory pointer.
  debugDec( "fsFind" );
}

BOOL fsFind(PUHSESS pUHSess, PFSFIND pFind)
{
  PVDIR      pVDirLastFind = (PVDIR)pFind->pLast;
  PVDIR      pVDir;
  ULONG      cbFindName, cbVDirName;
  PSZ        pszFindName;
  PCHAR      pcPtr;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FALSE;
  }

  if ( ( pFind->pszPtrn == NULL ) || ( *pFind->pszPtrn == '\0' ) )
    return FALSE;

  while( TRUE )
  {
    if ( pVDirLastFind == NULL )
      pVDir = (PVDIR)lnkseqGetFirst( &pUHSess->pHome->lsVDir );
    else
    {
      pVDir = (PVDIR)lnkseqGetFirst( &pVDirLastFind->lsVDir );

      if ( pVDir == NULL )
      {
        do
        {
          pVDir = (PVDIR)lnkseqGetNext( pVDirLastFind );
          if ( pVDir != NULL )
            break;
          pVDirLastFind = pVDirLastFind->pVDirParent;
        }
        while( pVDirLastFind != NULL );
      }
    }

    if ( pVDir == NULL )
    {
      // End of list.
      return FALSE;
    }

    // Detect full path name length.

    for( pVDirLastFind = pVDir, cbFindName = 0; pVDirLastFind != NULL;
         pVDirLastFind = pVDirLastFind->pVDirParent )
    {
      cbFindName += strlen( pVDirLastFind->pszName ) + 1;
    }

    // Get buffer for the full name.

    if ( pFind->ulNameMax < cbFindName )
    {
      if ( pFind->pszName != NULL )
        free( pFind->pszName );            // Low memory pointer.

      pszFindName = malloc( cbFindName );  // Low memory pointer.
      pFind->pszName = pszFindName;

      if ( pFind->pszName == NULL )
      {
        pFind->ulNameMax = 0;
        return FALSE;
      }
      pFind->ulNameMax = cbFindName;
    }
    else
      pszFindName = pFind->pszName;

    // Build full name.

    pcPtr = &pszFindName[cbFindName];
    for( pVDirLastFind = pVDir; pVDirLastFind != NULL;
         pVDirLastFind = pVDirLastFind->pVDirParent )
    {
      cbVDirName = strlen( pVDirLastFind->pszName );
      pcPtr -= (cbVDirName + 1);
      memcpy( pcPtr, pVDirLastFind->pszName, cbVDirName );
      pcPtr[cbVDirName] = '/';
    }
    pszFindName[cbFindName - 1] = '\0';

    // Check full name by given mask.
    if ( utilIMAPIsMatch( pszFindName, pFind->pszPtrn, NULL ) )
      break;

    pVDirLastFind = pVDir;
  }

  pFind->pLast = pVDir;
  pFind->acFlags[0] = '\0';
  if ( pVDir->pMailbox == NULL )
    strcpy( pFind->acFlags, "\\Noselect" );

  return TRUE;
}

BOOL fsCreateMailbox(PUHSESS pUHSess, PSZ pszMailbox)
{
  PVDIR      pVDir;
  PMAILBOX   pMailbox;
  BOOL       fRes = FALSE;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FALSE;
  }

  _sessLockHome( pUHSess );

  pVDir = _homeGetVDir( pUHSess->pHome, pszMailbox, TRUE );
  if ( ( pVDir != NULL ) && ( pVDir->pMailbox == NULL ) )
  {
    pMailbox = _mboxNew( pVDir, pUHSess->pHome->ulUIDValidityNext );
    if ( pMailbox != NULL )
    {
      pUHSess->pHome->ulUIDValidityNext++;
      pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
      fRes = TRUE;
    }
  }

  _sessUnlockHome( pUHSess );

  return fRes;
}

BOOL fsDeleteMailbox(PUHSESS pUHSess, PSZ pszMailbox)
{
  BOOL       fRes;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FALSE;
  }

  if ( stricmp( pszMailbox, "INBOX" ) == 0 )
  {
    debugCP( "Deleting INBOX is not allowed" );
    return FALSE;
  }

  _sessLockHome( pUHSess );
  fRes = _homeDeleteMailbox( pUHSess->pHome, pszMailbox );
  _sessUnlockHome( pUHSess );

  return fRes;
}

BOOL fsQueryMailbox(PUHSESS pUHSess, PSZ pszMailbox, ULONG ulOp,
                    PMAILBOXINFO pInfo)
{
  PVDIR      pVDir;
  PMAILBOX   pMailbox;

  // Do not check shutdown event here. This function can be called on final
  // steps.

  if ( pUHSess->pHome == NULL )
    return FALSE;

  _sessLockHome( pUHSess );

  if ( pszMailbox == NULL )
    pMailbox = NULL;
  else
  {
    pVDir = _homeGetVDir( pUHSess->pHome, pszMailbox, FALSE );
    pMailbox = pVDir == NULL ? NULL : pVDir->pMailbox;
  }

  if ( ulOp != FSGMB_STATUS )
  {
    // Select mailbox for the session.
    ULONG    ulSeqNum = 0;

    while( fsExpunge( pUHSess, &ulSeqNum, NULL ) );

    if ( pUHSess->pSelMailbox != pMailbox )
    {
      // Reset messages/selected mailbox change events.
      pUHSess->ulFlags &= ~(FSSESSFL_EXISTSCH | FSSESSFL_RECENTCH);
      pUHSess->cChgMsg = 0;
      if ( pUHSess->pChgMsg != NULL )
      {
        hfree( pUHSess->pChgMsg );
        pUHSess->pChgMsg = NULL;
      }
    }

    pUHSess->pSelMailbox   = pMailbox;
    pUHSess->fSelMailboxRO = ( pMailbox != NULL ) && ( ulOp == FSGMB_EXAMINE );
  }

  // 2017-09-25 Call _homeCheckInbox() moved here from _homeNew().
  // 2018-05-11 Moved out from "if ( ulOp != FSGMB_STATUS )" block.
  if ( ( pMailbox != NULL ) &&
       ( (pUHSess->pHome->ulFlags & FSUHF_INBOX_CHECKED) == 0 ) &&
       ( stricmp( pszMailbox, "INBOX" ) == 0 ) )
//       ( stricmp( pVDir->pszName, "INBOX" ) == 0 ) )
  {
    //debugCP( "call _homeCheckInbox()..." );
    _homeCheckInbox( pUHSess->pHome );    // Synchronize INBOX.
  }

  if ( ( pMailbox != NULL ) && ( pInfo != NULL ) )
  {
    pInfo->ulExists       = pMailbox->cMessages;
    pInfo->ulUIDValidity  = pMailbox->ulUIDValidity;
    pInfo->ulUIDNext      = pMailbox->ulUIDNext;
    _mboxGetCnt( pMailbox, &pInfo->ulRecent, &pInfo->ulUnseen );
  }

  _sessUnlockHome( pUHSess );

  return pMailbox != NULL;
}

ULONG fsRename(PUHSESS pUHSess, PSZ pszOldName, PSZ pszNewName)
{
  PUSERHOME  pHome = pUHSess->pHome;
  PVDIR      pVDirOld, pVDirNew, pVDir;
  PLINKSEQ   plsVDir;
  ULONG      ulRC = FSR_FAIL;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FSR_FAIL;
  }

  debug( "Rename <%s> to <%s>", pszOldName, pszNewName );

  _sessLockHome( pUHSess );

  pVDirOld = _homeGetVDir( pHome, pszOldName, FALSE );
  if ( pVDirOld == NULL )
  {
    debug( "\"%s\" does not exist", pszOldName );
    ulRC = FSR_NON_EXISTENT;
  }    
  if ( pVDirOld->pMailbox == NULL )
  {
    debug( "Mailbox for \"%s\" does not exist", pszOldName );
    ulRC = FSR_NON_EXISTENT;
  }
  else if ( _homeGetVDir( pHome, pszNewName, FALSE ) != NULL )
  {
    debug( "\"%s\" already exist", pszNewName );
    ulRC = FSR_ALREADY_EXISTS;
  }
  else
  {
    // The old path does exist and the new path does not exist.

    // Create a new VDIR object.
    pVDirNew = _homeGetVDir( pHome, pszNewName, TRUE );
    if ( pVDirNew == NULL )
      debug( "_homeGetVDir(,\"%s\", TRUE) failed", pszNewName );
    else
    {
      pUHSess->pHome->ulFlags |= FSUHF_DIRTY;

      if ( stricmp( pszOldName, "INBOX" ) == 0 )
      {
        /*
          [RFC 3501] 6.3.5. RENAME Command
          Renaming INBOX is permitted, and has special behavior. It moves all
          messages in INBOX to a new mailbox with the given name, leaving INBOX
          empty. If the server implementation supports inferior hierarchical
          names of INBOX, these are unaffected by a rename of INBOX.
        */

        // Create a new mailbox in the new VDIR object.
        PMAILBOX       pMailbox = _mboxNew( pVDirNew,
                                            pUHSess->pHome->ulUIDValidityNext );

        if ( pMailbox != NULL )
        {
          PMAILBOX     pSelMailbox;
          BOOL         fSelMailboxRO;
          ULONG        cChgMsg;
          PCHGMSG      pChgMsg;
          ULONG        ulFlags;
          BOOL         fInboxSelected =
                         pVDirOld->pMailbox == pUHSess->pSelMailbox;

          if ( !fInboxSelected )
          {
            pSelMailbox    = pUHSess->pSelMailbox;
            fSelMailboxRO  = pUHSess->fSelMailboxRO;
            cChgMsg        = pUHSess->cChgMsg;
            pChgMsg        = pUHSess->pChgMsg;
            ulFlags        = pUHSess->ulFlags;
            pUHSess->pSelMailbox    = pVDirOld->pMailbox;
            pUHSess->fSelMailboxRO  = FALSE;
            pUHSess->cChgMsg        = 0;
            pUHSess->pChgMsg        = NULL;
          }

          ulRC = _sessMove( pUHSess, pMailbox, NULL, NULL, NULL );

          if ( !fInboxSelected )
          {
            if ( pUHSess->pChgMsg != NULL )
              hfree( pUHSess->pChgMsg );

            pUHSess->pSelMailbox    = pSelMailbox;
            pUHSess->fSelMailboxRO  = fSelMailboxRO;
            pUHSess->cChgMsg        = cChgMsg;
            pUHSess->pChgMsg        = pChgMsg;
            pUHSess->ulFlags        = ulFlags;
          }
        }
      }  // if ( stricmp( pszOldName, "INBOX" ) == 0 )
      else
      {
        // A new VDir object (or "new path") created.

        // Move all sub-VDir objects from old path to the new.
        lnkseqMove( &pVDirNew->lsVDir, &pVDirOld->lsVDir );
        for( pVDir = (PVDIR)lnkseqGetFirst( &pVDirNew->lsVDir ); pVDir != NULL;
             pVDir = (PVDIR)lnkseqGetNext( pVDir ) )
          pVDir->pVDirParent = pVDirNew;

        // Move mailbox to new place.
        if ( pVDirOld->pMailbox != NULL )
        {
          pVDirNew->pMailbox = pVDirOld->pMailbox;
          pVDirNew->pMailbox->pVDir = pVDirNew;
          pVDirOld->pMailbox = NULL;
        }

        // Remove old VDir object.
        plsVDir = pVDirOld->pVDirParent != NULL ? &pVDirOld->pVDirParent->lsVDir
                                                : &pHome->lsVDir;
        lnkseqRemove( plsVDir, pVDirOld );
        _vdirFree( pVDirOld );

        ulRC = FSR_OK;
      }  // if ( stricmp( pszOldName, "INBOX" ) == 0 ) else
    }  // if ( pVDirNew == NULL ) else
  }

  _sessUnlockHome( pUHSess );

  return ulRC;
}


BOOL fsSubscribe(PUHSESS pUHSess, PSZ pszMailbox)
{
  BOOL       fRes;

  _sessLockHome( pUHSess );
  fRes = _homeSubscribe( pUHSess->pHome, pszMailbox, TRUE );
  if ( fRes )
    pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
  _sessUnlockHome( pUHSess );

  return fRes;
}

BOOL fsUnsubscribe(PUHSESS pUHSess, PSZ pszMailbox)
{
  BOOL       fRes;

  _sessLockHome( pUHSess );
  fRes = _homeSubscribe( pUHSess->pHome, pszMailbox, FALSE );
  if ( fRes )
    pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
  _sessUnlockHome( pUHSess );

  return fRes;
}

BOOL fsFindSubscribe(PUHSESS pUHSess, PFSFIND pFind)
{
  PUSERHOME  pHome = pUHSess->pHome;
  ULONG      ulIdx;
  PVDIR      pVDir;
  ULONG      cbSubItem = 0;
  PSZ        pszSubItem;
  PSZ        pszRemPath;

  for( ulIdx = (ULONG)pFind->pLast; ulIdx < pHome->cSubscribe; ulIdx++ )
  {
    pszSubItem = pHome->ppszSubscribe[ulIdx];

    if ( utilIMAPIsMatch( pszSubItem, pFind->pszPtrn, &pszRemPath ) )
    {
      // The subscribe item fully matches the pattern.

      cbSubItem = strlen( pszSubItem );

      pVDir = _homeGetVDir( pHome, pszSubItem, FALSE );
      pFind->acFlags[0] = '\0';
      if ( ( pVDir == NULL ) || ( pVDir->pMailbox == NULL ) )
        strcpy( pFind->acFlags, "\\Noselect" );

      break;
    }

    if ( pszRemPath != NULL )
    {
      /*
         We have trailing '%' in pattern and remainder after suitable part of
         the subscribe item.

         [RFC 3501] 6.3.9. LSUB Command
         A special situation occurs when using LSUB with the % wildcard.
         Consider what happens if "foo/bar" (with a hierarchy delimiter of "/")
         is subscribed but "foo" is not. A "%" wildcard to LSUB must return
         foo, not foo/bar, in the LSUB response, and it MUST be flagged with
         the \Noselect attribute.
      */

      cbSubItem = pszRemPath - pszSubItem;
      if ( ( ulIdx == 0 ) ||
           // ppszSubscribe is sorted => we compare only with one previous item.
           ( memicmp( pHome->ppszSubscribe[ulIdx],
                      pHome->ppszSubscribe[ulIdx - 1], cbSubItem ) != 0 ) )
      {
        // Suitable path has not yet returned.
        strcpy( pFind->acFlags, "\\Noselect" );
        break;
      }
      cbSubItem = 0;
    }
  }  // for()

  if ( cbSubItem == 0 )
    return FALSE;

  pFind->pLast = (PVOID)(ulIdx + 1);

  if ( pFind->ulNameMax < cbSubItem )
  {
    if ( pFind->pszName != NULL )
      free( pFind->pszName );                        // Low memory pointer.

    pFind->pszName = malloc( cbSubItem + 1 );        // Low memory pointer.
    if ( pFind->pszName == NULL )
    {
      pFind->ulNameMax = 0;
      return FALSE;
    }
    pFind->ulNameMax = cbSubItem;
  }

  memcpy( pFind->pszName, pszSubItem, cbSubItem );
  pFind->pszName[cbSubItem] = '\0';

  return TRUE;
}

VOID fsEnumMsgBegin(PUHSESS pUHSess, PFSENUMMSG pEnum,
                    PUTILRANGE pSeqSet, PUTILRANGE pUIDSet)
{
  PUTILRANGE           pScan;
  ULONG                cScan;
  PMAILBOX             pMailbox;

  pEnum->pSeqSet   = pSeqSet;
  pEnum->pUIDSet   = pUIDSet;
  pEnum->fAsterisk = FALSE;
  pEnum->ulIndex   = 0;

  _sessLockHome( pUHSess );
  pMailbox = pUHSess->pSelMailbox;

  /* [RFC 3501]: ...a UID range of 559:* always includes the UID of the last
     message in the mailbox, even if 559 is higher than any assigned UID value.
  */
  if ( ( pUIDSet != NULL ) && ( pMailbox != NULL ) &&
       ( pMailbox->cMessages != 0 ) )
  {
    for( pScan = pUIDSet, cScan = 0; pScan->ulFrom != 0; pScan++, cScan++ )
    {
      if ( ( pScan->ulTo == ULONG_MAX ) && ( pScan->ulFrom != 1 ) )
        pEnum->fAsterisk = TRUE;
    }

    if ( pEnum->fAsterisk )
    {
      // We have range n:* in numset - add range maxUID:maxUID.

      PUTILRANGE       pNewUIDSet = hmalloc( (cScan + 1) * sizeof(UTILRANGE) );

      if ( pNewUIDSet == NULL )
        pEnum->fAsterisk = FALSE;
      else
      {
        ULONG          ulIdx, ulUID = 1;

        for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
          if ( ulUID < pMailbox->papMessages[ulIdx]->ulUID )
            ulUID = pMailbox->papMessages[ulIdx]->ulUID;

        pNewUIDSet[0].ulFrom  = ulUID;
        pNewUIDSet[0].ulTo    = ulUID;
        memcpy( &pNewUIDSet[1], pUIDSet, cScan * sizeof(UTILRANGE) );
        pEnum->pUIDSet = pNewUIDSet;
      }
    }
  }
  debugInc( "fsEnumMsg" );
}

VOID fsEnumMsgEnd(PUHSESS pUHSess, PFSENUMMSG pEnum)
{
  _sessUnlockHome( pUHSess );

  if ( ( pEnum != NULL ) && pEnum->fAsterisk && ( pEnum->pUIDSet != NULL ) )
    hfree( pEnum->pUIDSet );

  debugDec( "fsEnumMsg" );
}

BOOL fsEnumMsg(PUHSESS pUHSess, PFSENUMMSG pEnum)
{
  ULONG      ulIdx;
  BOOL       fFound = FALSE;
  PMESSAGE   pMsg;
  LONG       cbPath;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FALSE;
  }

  if ( pUHSess->pSelMailbox == NULL )
    return FALSE;

  if ( ( pEnum->ulIndex != 0 ) && ( pEnum->ulFlags != (~0) ) &&
       !pUHSess->fSelMailboxRO )
  {
    // User may change flags at pEnum...
    ULONG    ulMsgFl;
    ULONG    ulNewFl = pEnum->ulFlags & FSMSGFL_ALLMASK;

    pMsg = pUHSess->pSelMailbox->papMessages[pEnum->ulIndex - 1];
    ulMsgFl = pMsg->ulFlags & FSMSGFL_ALLMASK;

    // Broadcast changes to other sessions.

    if ( (ulMsgFl & FSMSGFL_RECENT) != (ulNewFl & FSMSGFL_RECENT) )
      _sessBroadcastMailboxCh( pUHSess, pUHSess->pSelMailbox,
                               FSSESSFL_RECENTCH );

    if ( (ulMsgFl & ~FSMSGFL_RECENT) != (ulNewFl & ~FSMSGFL_RECENT) )
      _sessBroadcastMessageCh( pUHSess, pUHSess->pSelMailbox, pEnum->ulIndex,
                               ulNewFl );

    // Return altered flags to the message object.
    if ( ulMsgFl != ulNewFl )
    {
      debug( "Message N %u, UID: %u, old flags: 0x%X, new flags: 0x%X",
             pEnum->ulIndex, pMsg->ulUID, ulMsgFl, pEnum->ulFlags );
      pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
    }
    pMsg->ulFlags = pEnum->ulFlags;    // All, including not FSMSGFL_ALLMASK.
  }

  ulIdx = pEnum->ulIndex;
  if ( ( pEnum->pSeqSet == NULL ) && ( pEnum->pUIDSet == NULL ) )
  {
    fFound = ulIdx < pUHSess->pSelMailbox->cMessages;
    if ( fFound )
      pMsg = pUHSess->pSelMailbox->papMessages[ulIdx];
  }
  else
  {
    for( ; ulIdx < pUHSess->pSelMailbox->cMessages; ulIdx++ )
    {
      pMsg = pUHSess->pSelMailbox->papMessages[ulIdx];
      if ( utilIsInNumSet( pEnum->pSeqSet, ulIdx + 1 ) ||
           utilIsInNumSet( pEnum->pUIDSet, pMsg->ulUID ) )
      {
        fFound = TRUE;
        break;
      }
    }
  }

  pEnum->ulIndex = ulIdx + 1;
  if ( !fFound )
    return FALSE;

  pEnum->ulUID   = pMsg->ulUID;
  pEnum->ulFlags = pMsg->ulFlags;          // FSMSGFL_xxxxx

  cbPath = _homeQueryMBoxPath( pUHSess->pHome, pUHSess->pSelMailbox,
                               sizeof(pEnum->acFile), pEnum->acFile );
  pEnum->acFile[cbPath] = '\\';
  cbPath++;
  strcpy( &pEnum->acFile[cbPath], pMsg->acFName );

  return TRUE;
}

ULONG fsCopy(PUHSESS pUHSess, PUTILRANGE pSeqSet, PUTILRANGE pUIDSet,
             PSZ pszMailbox, PCOPYUID pCopyUID)
{
  FSENUMMSG      stEnum;
  PVDIR          pVDir;
  PMAILBOX       pMailbox;
  ULONG          ulMBoxMessages, ulNewUID;
  ULONG          ulRC = FSR_OK;
  PMESSAGE       pMsg;
  ULLONG         ullBytes, ullCopyBytes = 0;
  BOOL           fDstIsInbox = stricmp( pszMailbox, "INBOX" ) == 0;
  BOOL           fPOP3Lock;

  if ( pCopyUID != NULL )
  {
    pCopyUID->pSrcUIDs = NULL;
    pCopyUID->pDstUIDs = NULL;
  }

  _sessLockHome( pUHSess );

  if ( pUHSess->pSelMailbox == NULL )
  {
    // No mailbox selected.
    _sessUnlockHome( pUHSess );
    return FSR_OK;
  }

  // Get destination mailbox.
  pVDir = _homeGetVDir( pUHSess->pHome, pszMailbox, FALSE );
  pMailbox = pVDir != NULL ? pVDir->pMailbox : NULL;
  if ( pMailbox == NULL )
  {
    _sessUnlockHome( pUHSess );
    debug( "Mailbox %s not found", pszMailbox );
    return FSR_NOMAILBOX;
  }

  if ( pCopyUID != NULL )
    pCopyUID->ulUIDValidity = pMailbox->ulUIDValidity;

  ulMBoxMessages = pMailbox->cMessages;

  // Calculate the total size of files.
  fsEnumMsgBegin( pUHSess, &stEnum, pSeqSet, pUIDSet );
  while( fsEnumMsg( pUHSess, &stEnum ) )
  {
    utilQueryFileInfo( stEnum.acFile, NULL, &ullBytes );
    ullCopyBytes += ullBytes;
  }
  fsEnumMsgEnd( pUHSess, &stEnum );

  if ( msCheckAvailableSize( pUHSess->pHome->pszPath, ullCopyBytes ) ==
         MSR_EXCESS )
  {
    // Not enough space (size limit).
    _sessUnlockHome( pUHSess );
    return FSR_LIMIT_REACHED;
  }

  if ( fDstIsInbox ||
       ( stricmp( pUHSess->pSelMailbox->pVDir->pszName, "INBOX" ) == 0 ) )
  {
    // pop3Lock() should be always called when USERHOME is locked
    // (_sessLockHome()) to avoid locks (reject) IMAP service by other IMAP
    // function.

    fPOP3Lock = pop3Lock( pUHSess->pHome->pszPath, TRUE );
    if ( !fPOP3Lock )
    {
      _sessUnlockHome( pUHSess );
      return FSR_POP3_LOCKED;
    }
  }

  // Copy messages.

  ullCopyBytes = 0;
  fsEnumMsgBegin( pUHSess, &stEnum, pSeqSet, pUIDSet );

  while( fsEnumMsg( pUHSess, &stEnum ) )
  {
    ulRC = _sessCopyMsg( pUHSess, &stEnum, pMailbox, &ulNewUID, &ullBytes );
    if ( ulRC != FSR_OK )
      break;

    ullCopyBytes += ullBytes;

    if ( pCopyUID != NULL )
    {
      utilNumSetInsert( &pCopyUID->pSrcUIDs, stEnum.ulUID );
      utilNumSetInsert( &pCopyUID->pDstUIDs, ulNewUID );
    }
  }

  fsEnumMsgEnd( pUHSess, &stEnum );

  // fsEnumMsg() can finish on the shutdown event, in this case we have ulRC
  // equal FSR_OK. Therefore, we are checking the shutdown state now.
  // Hm... FSR_OK will be returned on shutdown.
  if ( ( ulRC != FSR_OK ) || _isShutdown() )
  {
    // Error occurred. Rollback changes: remove copied messages form the
    // destination mailbox.

    LONG     cbFName;
    CHAR     acFName[CCHMAXPATH];

    cbFName = _homeQueryMBoxPath( pUHSess->pHome, pMailbox, sizeof(acFName),
                                  acFName );
    if ( cbFName != -1 )
    {
      ULONG  ulRC;

      acFName[cbFName] = '\\';
      cbFName++;

      while( pMailbox->cMessages > ulMBoxMessages )
      {
        pMailbox->cMessages--;
        pMsg = pMailbox->papMessages[pMailbox->cMessages];

        strlcpy( &acFName[cbFName], pMsg->acFName, CCHMAXPATH - cbFName );
        ulRC = DosDelete( acFName );
        if ( ulRC != NO_ERROR )
          debug( "DosDelete(\"%s\"), rc = %u", acFName, ulRC );

        _msgFree( pMsg );
      }
    }

    if ( fPOP3Lock )
      pop3Lock( pUHSess->pHome->pszPath, FALSE );

    _sessUnlockHome( pUHSess );

    if ( pCopyUID != NULL)
    {
      fsFreeCopyUID( pCopyUID );
      pCopyUID->pSrcUIDs = NULL;
      pCopyUID->pDstUIDs = NULL;
    }

  }
  else
  {
    msChange( pUHSess->pHome->pszPath, fDstIsInbox, ullCopyBytes );

    pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
    _sessBroadcastMailboxCh( pUHSess, pMailbox,
                             FSSESSFL_EXISTSCH | FSSESSFL_RECENTCH );

    if ( fPOP3Lock )
      pop3Lock( pUHSess->pHome->pszPath, FALSE );

    _sessUnlockHome( pUHSess );
    ulRC = FSR_OK;
  }

  return ulRC;
}

ULONG fsMove(PUHSESS pUHSess, PUTILRANGE pSeqSet, PUTILRANGE pUIDSet,
             PSZ pszMailbox, PCOPYUID pMoveUID)
{
  PVDIR          pVDir;
  PMAILBOX       pMailbox;
  ULONG          ulRC;

  _sessLockHome( pUHSess );

  if ( pUHSess->fSelMailboxRO )
  {
    debugCP( "Selected mailbox in read-only mode" );
    ulRC = FSR_FAIL;
  }
  else
  {
    // Get destination mailbox.
    pVDir = _homeGetVDir( pUHSess->pHome, pszMailbox, FALSE );
    pMailbox = pVDir != NULL ? pVDir->pMailbox : NULL;
    if ( pMailbox == NULL )
    {
      debug( "Mailbox %s not found", pszMailbox );
      ulRC = FSR_NOMAILBOX;
    }
    else
      ulRC = _sessMove( pUHSess, pMailbox, pSeqSet, pUIDSet, pMoveUID );
  }

  _sessUnlockHome( pUHSess );

  return ulRC;
}

ULONG fsAppend(PUHSESS pUHSess, PFSAPPENDINFO pInfo, PCTX pMsgCtx,
               PULONG pulUIDValidity, PULONG pulUID)
{
  PMAILBOX   pDstMailbox;
  ULONG      ulRC;
  CHAR       acDstPathname[CCHMAXPATH];
  CHAR       acMsgFile[_MSG_NAME_LENGTH + 5];
  HFILE      hDstFile;
  PCHAR      pcBuf;
  ULONG      ulActual;
  PVDIR      pVDir;
  ULLONG     ullMsgSize = ctxQuerySize( pMsgCtx );
  BOOL       fInbox, fPOP3Lock;

  _sessLockHome( pUHSess );

  pVDir = _homeGetVDir( pUHSess->pHome, pInfo->pszMailbox, FALSE );
  pDstMailbox = pVDir != NULL ? pVDir->pMailbox : NULL;
  if ( pDstMailbox == NULL )
  {
    _sessUnlockHome( pUHSess );
    debug( "Mailbox %s not found", pInfo->pszMailbox );
    return FSR_NOMAILBOX;
  }

  if ( msCheckAvailableSize( pUHSess->pHome->pszPath, ullMsgSize ) ==
         MSR_EXCESS )
  {
    // Not enough space (size limit).
    _sessUnlockHome( pUHSess );
    return FSR_LIMIT_REACHED;
  }

  if ( pulUIDValidity != NULL )
    *pulUIDValidity = pDstMailbox->ulUIDValidity;

  fInbox = stricmp( pInfo->pszMailbox, "INBOX" ) == 0;
  if ( fInbox )
  {
    fPOP3Lock = pop3Lock( pUHSess->pHome->pszPath, TRUE );
    if ( !fPOP3Lock )
    {
      _sessUnlockHome( pUHSess );
      return FSR_POP3_LOCKED;
    }
  }

  ulRC = _sessOpenTempMsgFile( pUHSess, pDstMailbox, ullMsgSize,
                             sizeof(acDstPathname), acDstPathname, &hDstFile );
  if ( ulRC != FSR_OK )
  {
    if ( fPOP3Lock )
      pop3Lock( pUHSess->pHome->pszPath, FALSE );

    _sessUnlockHome( pUHSess );
    return ulRC;
  }

  // Store message from the context object to the file.

  ulRC = DosAllocMem( (PVOID *)&pcBuf, _COPY_FILE_BUF_SIZE,
                      PAG_COMMIT | PAG_READ | PAG_WRITE );
  if ( ulRC != NO_ERROR )
    logf( 0, "Memory allocation error code: %lu", ulRC );
  else
  {
    ctxSetReadPos( pMsgCtx, 0 );

    do
    {
      ulActual = ctxRead( pMsgCtx, _COPY_FILE_BUF_SIZE, pcBuf, FALSE );

      ulRC = DosWrite( hDstFile, pcBuf, ulActual, &ulActual );

      if ( _isShutdown() )
      {
        ulRC = ERROR_DISCARDED;
        debug( "Shutdown state. Set fake error code ERROR_DISCARDED (%u) to "
               "cancel operation", ulRC );
      }
    }
    while( ( ulRC == NO_ERROR ) && ( ulActual == _COPY_FILE_BUF_SIZE ) );

    DosFreeMem( pcBuf );

    if ( ( ulRC == NO_ERROR ) && ( pInfo->timeMsg != 0 ) )
    {
      // Set date/time for the new file.

      FILESTATUS3L     sDstInfo;
      struct tm        stTM;
      time_t           timeFile = pInfo->timeMsg;

      ulRC = DosQueryFileInfo( hDstFile, FIL_STANDARDL, &sDstInfo,
                               sizeof(FILESTATUS3L) );
      if ( ulRC != NO_ERROR )
        debug( "#2 DosQueryFileInfo(), rc = %u", ulRC );
      else
      {
        // Get local time from the unix time stamp.
        memcpy( &stTM, localtime( &timeFile ), sizeof(struct tm) );
        if ( stTM.tm_isdst == 1 && 0 )
        {
          // We got time with Daylight Savings Time flag. 
          stTM.tm_isdst = 0;
          timeFile -= ( mktime( &stTM ) - timeFile );
          memcpy( &stTM, localtime( &timeFile ), sizeof(struct tm) );
        }

        __mkFTime( &stTM, &sDstInfo.fdateCreation, &sDstInfo.ftimeCreation );
        __mkFTime( &stTM, &sDstInfo.fdateLastAccess, &sDstInfo.ftimeLastAccess );
        __mkFTime( &stTM, &sDstInfo.fdateLastWrite, &sDstInfo.ftimeLastWrite );

        ulRC = DosSetFileInfo( hDstFile, FIL_STANDARDL, &sDstInfo,
                               sizeof(FILESTATUS3L) );
        if ( ulRC != NO_ERROR )
          debug( "DosSetFileInfo(), rc = %u", ulRC );
      }
    } // if ( ulRC == NO_ERROR )
  } // if ( ulRC == NO_ERROR )

  DosClose( hDstFile );

  if ( ulRC == NO_ERROR )
    // Rename destination file to .MSG
    ulRC = __renameTempToMsgFile( acDstPathname, sizeof(acMsgFile), acMsgFile );

  if ( ulRC != NO_ERROR /* NO_ERROR equal FSR_OK */ )
  {
    ulRC = DosDelete( acDstPathname );
    if ( ulRC != NO_ERROR )
      debug( "#1 DosDelete(\"%s\"), rc = %u", acDstPathname, ulRC );

    ulRC = FSR_FAIL;
  }
  else
  {
    /* Create a new record in the destination mailbox.

       [RFC 3501] 6.3.11. APPEND Command
       If a flag parenthesized list is specified, the flags SHOULD be set in
       the resulting message; otherwise, the flag list of the resulting message
       is set to empty by default. In either case, the Recent flag is also set.
    */
    ulActual = _mboxAddMessage( pDstMailbox, acMsgFile,
                                pInfo->ulFlags | FSMSGFL_RECENT );
    if ( pulUID != NULL )
      *pulUID = ulActual;

    if ( ulActual == 0 )
    {
      PCHAR  pcLastSlash = strrchr( acDstPathname, '\\' );

      if ( pcLastSlash == NULL )
        debugCP( "WTF?!" );
      else
      {
        strcpy( &pcLastSlash[1], acMsgFile );

        ulRC = DosDelete( acDstPathname );
        if ( ulRC != NO_ERROR )
          debug( "#2 DosDelete(\"%s\"), rc = %u", acDstPathname, ulRC );
      }

      ulRC = FSR_FAIL;
    }
    else
    {
      msChange( pUHSess->pHome->pszPath, fInbox, ullMsgSize );

      pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
      _homeBroadcastMailboxCh( pUHSess->pHome, pDstMailbox,
                               FSSESSFL_RECENTCH | FSSESSFL_EXISTSCH );
    }

    // No need to assign ulRC = FSR_OK i.e. FSR_OK same as NO_ERROR
    // equals FSR_OK
  }

  if ( fPOP3Lock )
    pop3Lock( pUHSess->pHome->pszPath, FALSE );

  _sessUnlockHome( pUHSess );

  return ulRC;
}

BOOL fsExpunge(PUHSESS pUHSess, PULONG pulSeqNum, PUTILRANGE pUIDSet)
{
  ULONG                ulIdx = *pulSeqNum;
  ULONG                ulRC;
  PMAILBOX             pMailbox;
  PMESSAGE             pMsg;
  LONG                 cbFName;
  CHAR                 acFName[CCHMAXPATH];
  FILESTATUS3L         sInfo;
  BOOL                 fInbox, fPOP3Lock;

  // Do not check shutdown event here. This function can be called on final
  // steps directly or over fsQueryMailbox().

//  debug( "Backward scan from message index %u", ulIdx );
  _sessLockHome( pUHSess );

  pMailbox = pUHSess->pSelMailbox;
  if ( ( pMailbox == NULL ) || pUHSess->fSelMailboxRO )
  {
    // No mailbox selected or mailbox is in read-only mode.

    //debugCP( "No mailbox selected or mailbox is in read-only mode" );
    if ( pMailbox == NULL )
      {}//debug( "No mailbox selected" );
    else
      debug( "Mailbox is in read-only mode" );

    _sessUnlockHome( pUHSess );
    *pulSeqNum = 0;
    return FALSE;
  }

  fInbox = stricmp( pMailbox->pVDir->pszName, "INBOX" ) == 0;
  if ( fInbox )
  {
    fPOP3Lock = pop3Lock( pUHSess->pHome->pszPath, TRUE );
    if ( !fPOP3Lock )
    {
      _sessUnlockHome( pUHSess );
      return FALSE;
    }
  }

  if ( ( ulIdx == 0 ) || ( ulIdx > pMailbox->cMessages ) )
    ulIdx = pMailbox->cMessages;
  else
    ulIdx--;

  while( ulIdx != 0 )
  {
    ulIdx--;
    pMsg = pMailbox->papMessages[ulIdx];

    if ( ( (pMsg->ulFlags & FSMSGFL_DELETED) != 0 ) &&
         ( ( pUIDSet == NULL ) || utilIsInNumSet( pUIDSet, pMsg->ulUID ) ) )
    {
      // Make full name for the message file.
      cbFName = _homeQueryMBoxPath( pUHSess->pHome, pMailbox, sizeof(acFName),
                                    acFName );
      if ( cbFName == -1 )
        break;
      acFName[cbFName] = '\\';
      cbFName++;
      strlcpy( &acFName[cbFName], pMsg->acFName, CCHMAXPATH - cbFName );

      // Correct size information in USERHOME object.
      ulRC = DosQueryPathInfo( acFName, FIL_STANDARDL, &sInfo,
                               sizeof(FILESTATUS3L) );
      if ( ulRC != NO_ERROR )
        debug( "DosQueryPathInfo(\"%s\",,,), rc = %u", acFName, ulRC );
      else
        msChange( pUHSess->pHome->pszPath, fInbox, -sInfo.cbFile );

      // Delete the message file.
      ulRC = DosDelete( acFName );
      if ( ulRC != NO_ERROR )
        debug( "DosDelete(\"%s\")", acFName );

      // Destroy and remove message object.
      _msgFree( pMsg );
      pMailbox->cMessages--;
      memcpy( &pMailbox->papMessages[ulIdx], &pMailbox->papMessages[ulIdx + 1],
              (pMailbox->cMessages - ulIdx) * sizeof(PMESSAGE) );

      ulIdx++;         // Index to sequence number.
      *pulSeqNum = ulIdx;

      pUHSess->pHome->ulFlags |= FSUHF_DIRTY;
      _sessBroadcastMessageCh( pUHSess, pMailbox, ulIdx, ~0 );

      if ( fPOP3Lock )
        pop3Lock( pUHSess->pHome->pszPath, FALSE );

      _sessUnlockHome( pUHSess );

      return TRUE;
    }
  }

  if ( fPOP3Lock )
    pop3Lock( pUHSess->pHome->pszPath, FALSE );

  _sessUnlockHome( pUHSess );

  *pulSeqNum = 0;

  return FALSE;
}

BOOL fsGetChanges(PUHSESS pUHSess, PFSCHANGES pChanges, ULONG ulWaitHomeTime)
{
  ULONG      ulRC;

  // There is no point in checking the shutdown event here. This function
  // calls often and does not take much time.

  ulRC = DosRequestMutexSem( pUHSess->pHome->hmtxLock, ulWaitHomeTime );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
      debug( "DosRequestMutexSem(), rc = %u", ulRC );

    return FALSE;
  }

  if ( pUHSess->pSelMailbox == NULL )
  {
    // No mailbox selected - no changes.
    _sessUnlockHome( pUHSess );
    pChanges->ulFlags = 0;
    pChanges->cChgMsg = pUHSess->cChgMsg;
    pChanges->pChgMsg = pUHSess->pChgMsg;
    return FALSE;
  }

  if ( stricmp( pUHSess->pSelMailbox->pVDir->pszName, "INBOX" ) == 0 )
  {
    // Look for the new/deleted message files at INBOX (if INBOX is selected).
    // Inform all sessions with selected INBOX about changes.

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulRC, sizeof(ULONG) );

    if ( (ulRC - pUHSess->pHome->ulInboxChkTimestamp) >= ulInboxCheckPeriod )
    {
      //debugCP( "call _homeCheckInbox()..." );

      if ( _homeCheckInbox( pUHSess->pHome ) )
      {
        // Changes were found in the user home directory. It seems. we do not
        // have notifications about changes. Reset the period to the minimum.
        if ( ulInboxCheckPeriod != _INBOX_CHECK_PERIOD_MIN )
          debugCP( "Reset INBOX checking period to the minimum." );
        else
          debugCP( "No changes" );
        ulInboxCheckPeriod = _INBOX_CHECK_PERIOD_MIN;
      }
    }
  }

  pChanges->ulFlags = pUHSess->ulFlags & (FSSESSFL_EXISTSCH | FSSESSFL_RECENTCH);

  if ( (pUHSess->ulFlags & FSSESSFL_EXISTSCH) != 0 )
    pChanges->ulExists = pUHSess->pSelMailbox->cMessages;

  if ( (pUHSess->ulFlags & FSSESSFL_RECENTCH) != 0 )
    _mboxGetCnt( pUHSess->pSelMailbox, &pChanges->ulRecent, NULL );

  pChanges->cChgMsg = pUHSess->cChgMsg;
  pChanges->pChgMsg = pUHSess->pChgMsg;

  pUHSess->ulFlags &= ~(FSSESSFL_EXISTSCH | FSSESSFL_RECENTCH);
  pUHSess->cChgMsg = 0;
  pUHSess->pChgMsg = NULL;

  _sessUnlockHome( pUHSess );

  return ( pChanges->ulFlags != 0 ) || ( pChanges->cChgMsg != 0 );
}

ULONG fsQuerySize(PUHSESS pUHSess, PSZ pszMailbox, PMSSIZE pSizeInfo,
                  ULONG cbUHPath, PCHAR pcUHPath)
{
  ULONG      ulRC;

  _sessLockHome( pUHSess );

  if ( pszMailbox != NULL )
  {
    PVDIR    pVDir = _homeGetVDir( pUHSess->pHome, pszMailbox, TRUE );

    if ( ( pVDir == NULL ) || ( pVDir->pMailbox == NULL ) )
    {
      _sessUnlockHome( pUHSess );
      return FSR_NOMAILBOX;
    }
  }

  if ( pcUHPath != NULL )
    strlcpy( pcUHPath, pUHSess->pHome->pszPath, cbUHPath );

  ulRC = msQuerySize( pUHSess->pHome->pszPath, pSizeInfo );
  if ( ulRC != MSR_OK )
    debug( "msQuerySize(\"%s\",), rc = %lu", pUHSess->pHome->pszPath, ulRC );

  switch( ulRC )
  {
    case MSR_OK:             ulRC = FSR_OK;        break;
    case MSR_NOT_FOUND:      ulRC = FSR_NOMAILBOX; break;
    default:
      debugCP( "WTF?!" );
    case MSR_INTERNAL_ERROR: ulRC = FSR_FAIL;      break;
  }

  _sessUnlockHome( pUHSess );

  return ulRC;
}

VOID fsSave(PUHSESS pUHSess)
{
  _sessLockHome( pUHSess );
  _homeSave( pUHSess->pHome );
  _sessUnlockHome( pUHSess );
}

BOOL fsQueryInfoCtx(PCTX pCtx)
{
  ULONG      ulRC;
  PUSERHOME  pHome;

  ulRC = DosRequestMutexSem( hmtxHome, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  ulRC = ctxWriteFmtLn( pCtx, "INBOX check period: %lu sec.",
                        ulInboxCheckPeriod / 1000 );

  for( pHome = (PUSERHOME)lnkseqGetFirst( &lsHome );
       ( pHome != NULL ) && ulRC; pHome = (PUSERHOME)lnkseqGetNext( pHome ) )
  {
    DosRequestMutexSem( pHome->hmtxLock, 500 );

    ulRC = ctxWriteFmt( pCtx, "Home %s: %lu",
                        pHome->pszPath, lnkseqGetCount( &pHome->lsSess ) )
           && ( ( (pHome->ulFlags & FSUHF_DIRTY) == 0 ) ||
                ctxWrite( pCtx, 7, ", dirty" ) )
           && ctxWrite( pCtx, 2, "\r\n" );

    DosReleaseMutexSem( pHome->hmtxLock );
  }

  DosReleaseMutexSem( hmtxHome );

  return ulRC && ctxWrite( pCtx, 3, ".\r\n" );
}

VOID fsSaveCheck(ULONG ulTime)
{
  ULONG      ulRC;
  PUSERHOME  pHome = NULL;

  ulRC = DosRequestMutexSem( hmtxHome, SEM_IMMEDIATE_RETURN );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
      debug( "DosRequestMutexSem(hmtxHome,), rc = %u", ulRC );
  }
  else
  {
    for( pHome = (PUSERHOME)lnkseqGetFirst( &lsHome ); pHome != NULL;
         pHome = (PUSERHOME)lnkseqGetNext( pHome ) )
    {
      if ( ( (pHome->ulFlags & FSUHF_SAVE_DELAY) != 0 ) &&
           ( ((pHome->ulSaveTime - ulTime) & 0x80000000) != 0 ) )
      {
        ulRC = DosRequestMutexSem( pHome->hmtxLock, SEM_IMMEDIATE_RETURN );

        if ( ulRC != NO_ERROR )
        {
          if ( ulRC != ERROR_TIMEOUT )
            debug( "DosRequestMutexSem(pHome->hmtxLock,), rc = %u", ulRC );
        }
        else
        {
          pHome->ulFlags &= ~FSUHF_SAVE_DELAY;
          __homeSave( pHome );
          DosReleaseMutexSem( pHome->hmtxLock );
          break;
        }
      }
    }

    DosReleaseMutexSem( hmtxHome );
  }

  if ( pHome == NULL )
    msSaveCheck( ulTime );
}


static ULONG _fsNotifySplitPath(PMSSPLITHOMEPATH pHomePath, ULONG ulMtxTimeout)
{
  PUSERHOME            pHome;
  ULONG                ulRC;
  BOOL                 fFileExists;
  ULLONG               ullFileSize;
  BOOL                 fFixed = FALSE;

  fFileExists = ( pHomePath->pszFile != NULL ) &&
                utilQueryFileInfo( pHomePath->acPathname, NULL, &ullFileSize );

  ulRC = DosRequestMutexSem( hmtxHome, ulMtxTimeout );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
    {
      debug( "DosRequestMutexSem(hmtxHome,), rc = %u", ulRC );
      return FSNRC_INTERNAL_ERROR;
    }
    return FSNRC_DELAYED;
  }

  // Look for USERHOME object for the given path.
  for( pHome = (PUSERHOME)lnkseqGetFirst( &lsHome ); pHome != NULL;
       pHome = (PUSERHOME)lnkseqGetNext( pHome ) )
  {
    if ( stricmp( pHomePath->acShortPath, pHome->pszPath ) == 0 )
      break;
  }

  if ( pHome != NULL )
  {
    // We have open USERHOME object for given path.

    // Lock USERHOME object.
    ulRC = DosRequestMutexSem( pHome->hmtxLock, ulMtxTimeout );
    if ( ulRC != NO_ERROR )
    {
      DosReleaseMutexSem( hmtxHome );
      if ( ulRC != ERROR_TIMEOUT )
      {
        debug( "DosRequestMutexSem(pHome->hmtxLock,), rc = %u", ulRC );
        return FSNRC_INTERNAL_ERROR;
      }
      return FSNRC_DELAYED;
    }

    if ( (pHome->ulFlags & FSUHF_INBOX_CHECKED) == 0 )
      // INBOX was not loaded.
      debug( "Inbox for %s has not been loaded yet", pHomePath->acShortPath );
    else
    {
      if ( !fFileExists )
      {
        // File name not given (user home path given), or given name of deleted
        // file - we don't kown size of deleted file. Read user home directory
        // over _homeCheckInbox(), i.e. update USERHOME data for INBOX.

        debug( "Check inbox for %s ...", pHomePath->acShortPath );
        _homeCheckInbox( pHome );
        fFixed = TRUE;
      }
      else
      {
        // Check file.

        PVDIR              pVDir = _homeGetVDir( pHome, "INBOX", FALSE );
        PMAILBOX           pMailbox;
        ULONG              ulIdx;
        PMESSAGE           pMsg;
        BOOL               fMsgExists = FALSE;

        if ( ( pVDir == NULL ) || ( pVDir->pMailbox == NULL ) )
          debugCP( "WTF?! INBOX does not exist" );
        else
        {
          pMailbox = pVDir->pMailbox;

          // Check the existence of the message in mailbox corresponding to
          // the file.
          for( ulIdx = 0; ulIdx < pMailbox->cMessages; ulIdx++ )
          {
            pMsg = pMailbox->papMessages[ulIdx];
            if ( stricmp( pMsg->acFName, pHomePath->pszFile ) == 0 )
            {
              fMsgExists = TRUE;
              debug( "Message already exists for %s, no changes",
                     pHomePath->acShortPath );
              break;
            }
          }

          if ( !fMsgExists )
          {
            // Message does not exist and file exists - create a new record in
            // the mailbox.

            debug( "Create a new record in the mailbox: %s",
                   pHomePath->acShortPath );

            if ( _mboxAddMessage( pMailbox, pHomePath->pszFile,
                                  FSMSGFL_RECENT ) != 0 )
            {
              pHome->ulFlags |= FSUHF_DIRTY;
              _homeBroadcastMailboxCh( pHome, pMailbox,
                                       FSSESSFL_RECENTCH | FSSESSFL_EXISTSCH );
            }

            // Correct direcotory size on size of the new file.
            msChange( pHome->pszPath, TRUE, ullFileSize );
          }

          fFixed = TRUE;
        }  // if ( ( pVDir == NULL ) || ( pVDir->pMailbox == NULL ) ) else
      }  // if ( !fFileExists ) else

      // Defferred saving if USERHOME object have flag "dirty".
      _homeSave( pHome );

    }  // if ( (pHome->ulFlags & FSUHF_INBOX_CHECKED) == 0 ) else

    DosReleaseMutexSem( pHome->hmtxLock );
  }  // if ( pHome != NULL )

  DosReleaseMutexSem( hmtxHome );

  if ( !fFixed )
  {
    // USERHOME object not open or INBOX for opened USERHOME was not loaded.
    // Update sizes directly over storage module.

    debug( "No open objects to check, call msReadMsgList(\"%s\",,)...",
           pHomePath->acPathname );

    if ( fFileExists )
      // This is place for potential errors. User can give file (for not
      // opened USERHOME object) whose size is already counted.
      // But here we avoid reading the entire directory.
      msChange( pHomePath->acPathname, TRUE, ullFileSize );
    else
    {
      // File name not given (user home path given) or given name of deleted
      // file. Read user home directory.

      if ( pHomePath->pszFile != NULL )
      {
        ULONG  cbFile = strlen( pHomePath->pszFile );
        ULONG  cbPathname = strlen( pHomePath->acPathname );

        pHomePath->acPathname[cbPathname - cbFile] = '\0';
      }

      if ( !msReadMsgList( pHomePath->acPathname, TRUE, NULL ) )
        return FSNRC_CANNOT_READ_OBJ;
    }

    fFixed = TRUE;
  }

  if ( fFixed )
  {
    // It seems, we we can trust notifications - increase the period of
    // checking mailbox (INBOXes).

    if ( ulInboxCheckPeriod < _INBOX_CHECK_PERIOD_MAX )
    {
      ulInboxCheckPeriod += _INBOX_CHECK_PERIOD_STEP;
      debug( "Increase INBOX checking period, now is %u", ulInboxCheckPeriod );
    }
  }

  return FSNRC_FIXED;
}

static ULONG _fsNotify(PSZ pszPathname, ULONG ulMtxTimeout)
{
  MSSPLITHOMEPATH      stHomePath;

  if ( !msSplitHomePath( pszPathname, &stHomePath ) )
  {
    debug( "msSplitHomePath() failed for \"%s\"", pszPathname );
    return FSNRC_INVALID_PATHNAME;
  }

  return _fsNotifySplitPath( &stHomePath, SEM_INDEFINITE_WAIT );
}


// Notifies virtual file system about changes in file lists. It will force
// informing current client sessions about new or removed messages.
ULONG fsNotifyChange(ULONG ulDelay, PSZ pszPathname)
{
  // pszPathname may be in different forms:
  //   D:\MailRoot\domain\user\file.MSG
  //   D:\MailRoot\user\file.MSG
  //   D:\MailRoot\domain\user
  //   D:\MailRoot\user
  //   domain\user\file.MSG
  //   user\file.MSG
  //   domain\user
  //   user
  //   user@domain
  // where file.MSG - appeared or deleted file.

  PNOTIFICATION        pNotification;
  ULONG                ulRC, cbPath;
  MSSPLITHOMEPATH      stHomePath;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FSNRC_SHUTDOWN;
  }

  if ( !msSplitHomePath( pszPathname, &stHomePath ) )
  {
    debug( "msSplitHomePath() failed for \"%s\"", pszPathname );
    return FSNRC_INVALID_PATHNAME;
  }
  cbPath = strlen( stHomePath.acPathname );
  if ( stHomePath.pszFile != NULL )
    cbPath -= ( strlen( stHomePath.pszFile ) + 1 );

  // Lock the notifications list.
  ulRC = DosRequestMutexSem( hmtxNotifications, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u", ulRC );
    return FSNRC_INTERNAL_ERROR;
  }

  // Looking for similar pending notifications.

  for( pNotification = (PNOTIFICATION)lnkseqGetFirst( &lsNotifications );
       pNotification != NULL;
       pNotification = (PNOTIFICATION)lnkseqGetNext( pNotification ) )
  {
    if ( memicmp( stHomePath.acPathname, pNotification->acPathname, cbPath )
         != 0 )
      continue;

    if ( pNotification->acPathname[cbPath] == '\0' )
    {
      // Already have notification for same path. Ingore a new.
      ulRC = FSNRC_DELAYED;
      break;
    }

    if ( pNotification->acPathname[cbPath] == '\\' )
    {
      if ( stHomePath.pszFile == NULL )
      {
        // Have notif. for file in given path - change old notif. file->path.
        pNotification->acPathname[cbPath] = '\0';
        ulRC = FSNRC_DELAYED;
        break;
      }

      if ( stricmp( stHomePath.pszFile,
                    &pNotification->acPathname[cbPath + 1] ) == 0 )
      {
        // Have notification for that file. Ignore a new.
        ulRC = FSNRC_DELAYED;
        break;
      }
    }
  }

  if ( pNotification == NULL )
  {
    if ( ulDelay == 0 )
      // No delay - perform the operation immediately.
      ulRC = _fsNotifySplitPath( &stHomePath, SEM_INDEFINITE_WAIT );
    else
    {
      // Create a new notification.

      pNotification = hmalloc( sizeof(NOTIFICATION) +
                               strlen( stHomePath.acPathname ) );
      if ( pNotification == NULL )
        ulRC = FSNRC_INTERNAL_ERROR;
      else
      {
        strcpy( (PSZ)&pNotification->acPathname, stHomePath.acPathname );
        // Calculation of a timestamp for a new notification.
        DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &pNotification->ulTime,
                         sizeof(ULONG) );
        pNotification->ulTime += ulDelay;

        // Insert a new notification to the pending list.

        lnkseqAdd( &lsNotifications, pNotification );
        ulRC = FSNRC_DELAYED;
      }
    }  // if ( ulDelay == 0 ) else
  }  // if ( pNotification == NULL )

  DosReleaseMutexSem( hmtxNotifications );

  return ulRC;
}

ULONG fsNotifyCheck(ULONG ulTime, ULONG cbBuf, PCHAR pcBuf)
{
  ULONG                ulRC;
  PNOTIFICATION        pScan;

  if ( _isShutdown() )
  {
    debugCP( "Shutdown state" );
    return FSNRC_SHUTDOWN;
  }

  if ( ( cbBuf != 0 ) && ( pcBuf != NULL ) )
    *pcBuf ='\0';

  ulRC = DosRequestMutexSem( hmtxNotifications, SEM_IMMEDIATE_RETURN );
  if ( ulRC != NO_ERROR )
  {
    if ( ulRC != ERROR_TIMEOUT )
    {
      debug( "DosRequestMutexSem(hmtxNotifications,), rc = %u", ulRC );
      return FSNRC_INTERNAL_ERROR;
    }
    return FSNRC_DELAYED;
  }

  ulRC = FSNRC_DELAYED;
  for( pScan = (PNOTIFICATION)lnkseqGetFirst( &lsNotifications );
       pScan != NULL; pScan = (PNOTIFICATION)lnkseqGetNext( pScan ) )
  {
    if ( ((pScan->ulTime - ulTime) & 0x80000000) != 0 )
    {
      ulRC = _fsNotify( pScan->acPathname, SEM_IMMEDIATE_RETURN );
      if ( ulRC != FSNRC_DELAYED )
      {
        if ( pcBuf != NULL )
          strlcpy( pcBuf, pScan->acPathname, cbBuf );

        lnkseqRemove( &lsNotifications, pScan );
        hfree( pScan );
      }
      break;
    }
  }

  DosReleaseMutexSem( hmtxNotifications );

  return ulRC;
}

VOID fsDeleteFiles(PSZ pszHomeDir, PMSLIST pList)
{
  LONG       cbPathName;
  CHAR       acFullName[CCHMAXPATH];
  PSZ        pszFile;
  ULONG      ulIdx, ulMsgIdx, ulRC;
  ULLONG     ullSize = 0;
  PUSERHOME  pHome;
  PMAILBOX   pMailbox = NULL;
  PMESSAGE   pMsg;

  if ( pList->ulCount == 0 )
    return;

  cbPathName = wcfgQueryMailRootDir( sizeof(acFullName) - 1, acFullName,
                                     pszHomeDir );
  acFullName[cbPathName] = '\\';
  cbPathName++;

  ulRC = DosRequestMutexSem( hmtxHome, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(hmtxHome,), rc = %u", ulRC );
    return;
  }

  // Look for USERHOME object for the given path.
  for( pHome = (PUSERHOME)lnkseqGetFirst( &lsHome ); pHome != NULL;
       pHome = (PUSERHOME)lnkseqGetNext( pHome ) )
  {
    if ( stricmp( pszHomeDir, pHome->pszPath ) == 0 )
    {
      PVDIR  pVDir = _homeGetVDir( pHome, "INBOX", FALSE );

      if ( ( pVDir == NULL ) || ( pVDir->pMailbox == NULL ) )
        debugCP( "WTF?! INBOX does not exist" );
      else if ( (pHome->ulFlags & FSUHF_INBOX_CHECKED) == 0 )
        debug( "Inbox for %s has not been loaded yet", pszHomeDir );
      else
      {
        pMailbox = pVDir->pMailbox;
        DosRequestMutexSem( pHome->hmtxLock, SEM_INDEFINITE_WAIT );
      }

      break;
    }
  }

  // If pMailbox is NULL:
  // USERHOME object is not open. There is no sessions to inform about the
  // changes in the mailbox (INBOX).

  for( ulIdx = 0; ulIdx < pList->ulCount; ulIdx++ )
  {
    pszFile = pList->papFiles[ulIdx]->acName;
    strlcpy( &acFullName[cbPathName], pszFile,
             sizeof(acFullName) - cbPathName );

    ulRC = DosDelete( acFullName );
    if ( ulRC != NO_ERROR )
      debug( "DosDelete(\"%s\"), rc = %lu", acFullName, ulRC );
    else
    {
      ullSize += pList->papFiles[ulIdx]->ullSize;

      if ( pMailbox != NULL )
      {
        // Remove message corresponding to the file from the mailbox.
        for( ulMsgIdx = 0; ulMsgIdx < pMailbox->cMessages; ulMsgIdx++ )
        {
          pMsg = pMailbox->papMessages[ulMsgIdx];

          if ( stricmp( pMsg->acFName, pszFile ) == 0 )
          {
            // Destroy and remove message object.
            _msgFree( pMsg );
            pMailbox->cMessages--;
            memcpy( &pMailbox->papMessages[ulMsgIdx],
                    &pMailbox->papMessages[ulMsgIdx + 1],
                    (pMailbox->cMessages - ulMsgIdx) * sizeof(PMESSAGE) );

            // Inform all sessions with selected INBOX about deleteting the
            // message.
            _homeBroadcastMessageCh( pHome, pMailbox, ulMsgIdx + 1, ~0 );
            break;
          }
        }  // for( ulMsgIdx ...
      }  // if ( pMailbox != NULL )
    }  // if ( ulRC != NO_ERROR ) else
  }  // for( ulIdx

  if ( pMailbox != NULL )
    DosReleaseMutexSem( pHome->hmtxLock );

  DosReleaseMutexSem( hmtxHome );

  // Correct storage size.
  msChange( pszHomeDir, TRUE, -ullSize );
}
