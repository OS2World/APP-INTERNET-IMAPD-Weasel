#ifndef IMAPFS_H
#define IMAPFS_H

#include "linkseq.h"
#include "utils.h"
#include "context.h"

/*
   PROTODATA/UHSESS <-+              +-> VDIR <-+-> VDIR <-> MAILBOX
                      |              |          +-> VDIR <-> MAILBOX
   PROTODATA/UHSESS <-+-> USERHOME <-+-> VDIR
                      |              |
   PROTODATA/UHSESS <-+              +-> VDIR <-> MAILBOX -+-> MESSAGE
                |                                    ^     +-> MESSAGE
                +----------[ pSelMailbox ]-----------+     +-> MESSAGE
*/

// MESSAGE.ulFlags
#define FSMSGFL_SEEN             0x01
#define FSMSGFL_ANSWERED         0x02
#define FSMSGFL_FLAGGED          0x04
#define FSMSGFL_DELETED          0x08
#define FSMSGFL_DRAFT            0x10
#define FSMSGFL_RECENT           0x20
#define FSMSGFL_ALLMASK          0x3F
#define FSMSGFL_INTERNAL_MOVED   0x0100

// fsCopy() and fsAppend() result codes.
#define FSR_OK                   0
#define FSR_NOMAILBOX            1
#define FSR_FAIL                 2
#define FSR_DISK_FULL            3
#define FSR_LIMIT_REACHED        4
#define FSR_ALREADY_EXISTS       5
#define FSR_NON_EXISTENT         6
#define FSR_POP3_LOCKED          7

// UHSESS.ulFlags and FSCHANGES.ulFlags
#define FSSESSFL_EXISTSCH        0x01
#define FSSESSFL_RECENTCH        0x02

// fsQueryMailbox(,,ulOp,)

// FSGMB_SELECT  - Select mailbox for the session.
#define FSGMB_SELECT             0
// FSGMB_EXAMINE - Select mailbox for the session in read-only mode
#define FSGMB_EXAMINE            1
// FSGMB_STATUS  - Obtain status of mailbox, do not select.
#define FSGMB_STATUS             2

// fsNotify*() result codes.
#define FSNRC_FIXED              0
#define FSNRC_DELAYED            1
#define FSNRC_SHUTDOWN           2
#define FSNRC_INTERNAL_ERROR     3
#define FSNRC_INVALID_PATHNAME   4
#define FSNRC_CANNOT_READ_OBJ    5

// USERHOME.ulFlags
#define FSUHF_INBOX_CHECKED      0x0001
#define FSUHF_SAVE_DELAY         0x0002
#define FSUHF_DIRTY              0x0004

typedef struct _MESSAGE {
  ULONG      ulUID;
  ULONG      ulFlags;            // FSMSGFL_xxxxx
  CHAR       acFName[1];
} MESSAGE, *PMESSAGE;

typedef struct _VDIR *PVDIR;

typedef struct _MAILBOX {
  PVDIR      pVDir;
  ULONG      ulUIDValidity;      // Unique identifier of the mailbox.
  ULONG      ulUIDNext;          // Unique identifier for the next message.

  ULONG      cMessages;
  ULONG      ulMaxMessages;
  PMESSAGE   *papMessages;
} MAILBOX, *PMAILBOX;

typedef struct _VDIR {
  SEQOBJ     stSeqObj;
  PVDIR      pVDirParent;
  PSZ        pszName;
  PMAILBOX   pMailbox;
  LINKSEQ    lsVDir;
} VDIR;

typedef struct _USERHOME *PUSERHOME;

typedef struct _CHGMSG {
  ULONG      ulSeqNum;
  ULONG      ulFlags;            // FSMSGFL_xxxxx or ~0 for expunged messages.
} CHGMSG, *PCHGMSG;

typedef struct _UHSESS {
  SEQOBJ     stSeqObj;
  ULONG      ulFlags;            // FSSESSFL_xxxxx

  PUSERHOME  pHome;
  PMAILBOX   pSelMailbox;
  BOOL       fSelMailboxRO;

  ULONG      cChgMsg;
  PCHGMSG    pChgMsg;
} UHSESS, *PUHSESS;

typedef struct _USERHOME {
  SEQOBJ     stSeqObj;
  HMTX       hmtxLock;

  PSZ        pszPath;
  ULONG      ulUIDValidityNext;
  LINKSEQ    lsVDir;
  LINKSEQ    lsSess;
  ULONG      ulInboxChkTimestamp;
  ULONG      ulSaveTime;
  ULONG      ulFlags;            // FSUHF_xxxxx

  ULONG      cSubscribe;
  ULONG      ulMaxSubscribe;
  PSZ        *ppszSubscribe;
} USERHOME;


// Mailbox information returned by fsQueryMailbox(,,,PMAILBOXINFO).

typedef struct _MAILBOXINFO {
  ULONG      ulExists;
  ULONG      ulRecent;
  ULONG      ulUnseen;
  ULONG      ulUIDValidity;
  ULONG      ulUIDNext;
} MAILBOXINFO, *PMAILBOXINFO;


// Find object for fsFind() and fsFindSubscribe().

typedef struct _FSFIND {
  PSZ        pszPtrn;
  PVOID      pLast;
  ULONG      ulNameMax;
  PSZ        pszName;            // Memory where placed result full name.
  CHAR       acFlags[56];        // \Noinferiors \Noselect \Marked \Unmarked
} FSFIND, *PFSFIND;


// Messages enumeration object for fsEnum*()

typedef struct _FSENUMMSG {
  PUTILRANGE           pSeqSet;
  PUTILRANGE           pUIDSet;
  BOOL                 fAsterisk;
  ULONG                ulIndex;

  // Result from fsEnumMsg().
  ULONG                ulUID;
  ULONG                ulFlags;            // FSMSGFL_xxxxx
  CHAR                 acFile[CCHMAXPATH];
} FSENUMMSG, *PFSENUMMSG;


// Output data for fsGetChanges(,PFSCHANGES)

typedef struct _FSCHANGES {
  ULONG      ulFlags;            // FSSESSFL_xxxxx
  ULONG      ulExists;
  ULONG      ulRecent;
  ULONG      cChgMsg;
  PCHGMSG    pChgMsg;
} FSCHANGES, *PFSCHANGES;

#define fsReleaseChanges(__pChanges) do { \
  if ( (__pChanges)->pChgMsg != NULL ) hfree( (__pChanges)->pChgMsg ); \
} while( 0 )

// Input data for fsAppend()

typedef struct _FSAPPENDINFO {
  PSZ        pszMailbox;
  ULONG      ulFlags;
  time_t     timeMsg;
} FSAPPENDINFO, *PFSAPPENDINFO;


// Output date for fsCopy(,,,,PCOPYUID)

typedef struct _COPYUID {
  ULONG      ulUIDValidity;      // Destination mailbox ID (UIDValidity).
  PUTILRANGE pSrcUIDs;           // UIDs of the messages in the source mailbox.
  PUTILRANGE pDstUIDs;           // UIDs assigned to the copied messages.
} COPYUID, *PCOPYUID;

#define fsFreeCopyUID(__p) do { \
  if ( (__p)->pSrcUIDs != NULL ) free( (__p)->pSrcUIDs ); \
  if ( (__p)->pDstUIDs != NULL ) free( (__p)->pDstUIDs ); \
} while( FALSE )


// fsNotify*() result codes to text conversation array. Index is FSNRC_xxxxx.
extern PSZ   apszFSNotifyResults[6];


// It must be called before calling any other function.
BOOL fsInit();

// This function must be the last one called.
// Calling to any other function after this call is prohibited.
VOID fsDone();

// Cancels the current operations. Preparation for the end of work.
VOID fsShutdown();


BOOL fsSessInit(PUHSESS pUHSess);
VOID fsSessDone(PUHSESS pUHSess);

// pszHomeDir - path from mail-root directory to home directory.
// For ex. for multi-domain mode: "my.domain.com\\user" or "user" for
// single-domain mode.
BOOL fsSessOpen(PUHSESS pUHSess, PSZ pszHomeDir);

VOID fsFindBegin(PUHSESS pUHSess, PFSFIND pFind, PSZ pszPtrn);
VOID fsFindEnd(PUHSESS pUHSess, PFSFIND pFind);
BOOL fsFind(PUHSESS pUHSess, PFSFIND pFind);

BOOL fsCreateMailbox(PUHSESS pUHSess, PSZ pszMailbox);
BOOL fsDeleteMailbox(PUHSESS pUHSess, PSZ pszMailbox);
BOOL fsQueryMailbox(PUHSESS pUHSess, PSZ pszMailbox, ULONG ulOp,
                    PMAILBOXINFO pInfo);
// Result: FSR_xxxxx
ULONG fsRename(PUHSESS pUHSess, PSZ pszOldName, PSZ pszNewName);

BOOL fsSubscribe(PUHSESS pUHSess, PSZ pszMailbox);
BOOL fsUnsubscribe(PUHSESS pUHSess, PSZ pszMailbox);
BOOL fsFindSubscribe(PUHSESS pUHSess, PFSFIND pFind);

/*
   fsEnum*(): Enumerates messages in the selected mailbox. Number sets pSeqSet
   and pUIDSet is lists of ranges, last range shoud have ulFrom = 0.
   If botch number sets are NULL, then all messages will be enumerated.

   FSENUMMSG  stEnum;
   fsEnumMsgBegin(...);
   while( fsEnumMsg( pUHSess, &stEnum ) ) { ... }
   fsEnumMsgEnd( &stEnum );
*/
VOID fsEnumMsgBegin(PUHSESS pUHSess, PFSENUMMSG pEnum,
                    PUTILRANGE pSeqSet, PUTILRANGE pUIDSet);
VOID fsEnumMsgEnd(PUHSESS pUHSess, PFSENUMMSG pEnum);
BOOL fsEnumMsg(PUHSESS pUHSess, PFSENUMMSG pEnum);

// pCopyUID is an output data, may be NULL. It should be destroyed by
// fsFreeCopyUID() if result code is FSR_OK.
// Result: FSR_xxxxx
ULONG fsCopy(PUHSESS pUHSess, PUTILRANGE pSeqSet, PUTILRANGE pUIDSet,
             PSZ pszMailbox, PCOPYUID pCopyUID);

ULONG fsMove(PUHSESS pUHSess, PUTILRANGE pSeqSet, PUTILRANGE pUIDSet,
             PSZ pszMailbox, PCOPYUID pMoveUID);

// Creates a new message in mailbox.
// pulUIDValidity - (output, may be NULL) mailbox UIDVALIDITY value,
// pulUID - (output, may be NULL) UID assigned to a new message.
// Result: FSR_xxxxx
ULONG fsAppend(PUHSESS pUHSess, PFSAPPENDINFO pInfo, PCTX pMsgCtx,
               PULONG pulUIDValidity, PULONG pulUID);

// Permanently removes all messages that both have the \Deleted flag set and
// have a UID that is included in pUIDSet sequence set (if it's not NULL) from
// the currently selected mailbox. If pUIDSet is NULL than function removes all
// messages that have \Deleted flag.
// pulSeqNum in: number of last removed message, 0 for start scanning;
//           out: number of removed messge.
BOOL fsExpunge(PUHSESS pUHSess, PULONG pulSeqNum, PUTILRANGE pUIDSet);

// pChanges - structure in caller memory space, should be released with
// fsReleaseChanges().
// ulWaitHomeTime - maximum amount of time unlock USERHOME object attached to
//                  the session.
//    SEM_IMMEDIATE_RETURN (0) -  if the USERHOME object is locked function
//                                returns immediately with result code FALSE.
//    SEM_INDEFINITE_WAIT (-1L) - function blocks the calling thread until
//                                USERHOME object unlocked.
// This function resets current changes for the session.
BOOL fsGetChanges(PUHSESS pUHSess, PFSCHANGES pChanges, ULONG ulWaitHomeTime);

// Result: FSR_xxxxx
ULONG fsQuerySize(PUHSESS pUHSess, PSZ pszMailbox, PMSSIZE pSizeInfo,
                  ULONG cbUHPath, PCHAR pcUHPath);

// Delayed session saving (to imap.xml).
VOID fsSave(PUHSESS pUHSess);

// Writes to the given context object the current summary information about
// storage.
BOOL fsQueryInfoCtx(PCTX pCtx);

// Should be called periodically.
VOID fsSaveCheck(ULONG ulTime);

// Notifies virtual file system about changes in the user home directory file
// list (INBOX). It will force informing current client sessions about new or
// removed messages.
// pszPathname may be in different forms:
//   D:\MailRoot\domain\user\file.MSG
//   D:\MailRoot\user\file.MSG
//   D:\MailRoot\domain\user
//   D:\MailRoot\user
//   domain\user\file.MSG
//   user\file.MSG
//   domain\user
//   user
// where file.MSG - appeared or deleted file.
// ulDelay - delay time in msec.
// Result - FSNRC_xxxxx.
ULONG fsNotifyChange(ULONG ulDelay, PSZ pszPathname);

// Should be called periodically.
// ulTime - system timer value:
//    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
// pcBuf - (output) notify path specified with fsNotifyChange(). May be NULL.
//
// Result: FSNRC_xxxxx. FSNRC_DELAYED - have no notifies on this moment.
ULONG fsNotifyCheck(ULONG ulTime, ULONG cbBuf, PCHAR pcBuf);

// Delete files from the user home directory (INBOX) and inform all sessions
// in which the INBOX mailbox is selected for the given user (home directory).
// Also this corrects the storage size.
// pszHomeDir - _short_ path to the user home directory.
VOID fsDeleteFiles(PSZ pszHomeDir, PMSLIST pList);

#endif // IMAPFS_H
