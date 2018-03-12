#ifndef STORAGE_H
#define STORAGE_H

#define MSR_OK                   0
#define MSR_INTERNAL_ERROR       1
#define MSR_NOT_FOUND            2
#define MSR_EXCESS               3

typedef struct _MSFILE {
  ULLONG               ullSize;
  UTILFTIMESTAMP       stFTimestamp;
  ULONG                ulUser;
  CHAR                 acName[1];
} MSFILE, *PMSFILE;

typedef struct _MSLIST {
  ULONG      ulCount;
  PMSFILE    *papFiles;
} MSLIST, *PMSLIST;

typedef struct _MSSIZE {
  LLONG      llMailRoot;
  LLONG      llDomain;
  LLONG      llInbox;
  LLONG      llImap;
  LLONG      llMailRootLimit;
  LLONG      llDomainLimit;
  LLONG      llUserLimit;
} MSSIZE, *PMSSIZE;

typedef struct _MSSPLITHOMEPATH {
  PSZ        pszUser;                      // Points in acShortPath.
  PSZ        pszFile;                      // Points in pcShortPath.
  CHAR       acPathname[CCHMAXPATH];
  CHAR       acShortPath[CCHMAXPATH];
  CHAR       acDomain[CCHMAXPATHCOMP];
} MSSPLITHOMEPATH, *PMSSPLITHOMEPATH;


#define LIMIT_TO_STR(__val,__buf) \
( __val == LLONG_MAX ? "unlimited" : ulltoa( __val, __buf, 10 ) )

BOOL msInit();
VOID msDone();

// Synchronization of the list of objects with Weasel configuration.
VOID msSync();

// Reads message files to the list pList (in caller memory space). List should
// be destroyed by msListDestroy(). Function updates information about sizes
// in internal data. pList may be a null (to update information only).
BOOL msReadMsgList(PSZ pszUHPath, BOOL fInbox, PMSLIST pList);

VOID msListDestroy(PMSLIST pList);

// Removes given file name from the list created with msReadMsgList().
// Returns TRUE if name was found and removed.
BOOL msListRemove(PMSLIST pList, PSZ pszFName);

BOOL msListRemoveIdx(PMSLIST pList, ULONG ulIdx);

// Informs about size changes in the storage.
BOOL msChange(PSZ pszUHPath, BOOL fInbox, LLONG llDiff);

// Returns MSR_xxxxx code.
ULONG msCheckAvailableSize(PSZ pszUHPath, LLONG llSizeIncr);

// Informs about size changes in the user home directory on file move.
// fToInbox - TRUE: message file moved from any folder to INBOX.
//            FALSE: message file moved from INBOX to any folder.
BOOL msMove(PSZ pszUHPath, BOOL fToInbox, LLONG llSize);

// Writes to the given context object the current summary information about
// storage.
BOOL msQueryInfoCtx(PCTX pCtx);

// Fills pSizeInfo for given user home directory.
// Returns MSR_xxxxx code.
ULONG msQuerySize(PSZ pszUHPath, PMSSIZE pSizeInfo);

// Should be called periodically to save state to <MailRoot>\imap.xml.
// ulTime - system timer value:
//    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );
// Returns TRUE if <MailRool>\imap.xml was saved.
BOOL msSaveCheck(ULONG ulTime);

// Refresh data from imap-quotas.xml if it was changed.
VOID msUpdateQuotas();

BOOL msSplitHomePath(PSZ pszPathname, PMSSPLITHOMEPATH pHomePath);

VOID msSendExceededQuotaEMail(PSZ pszRcpt, ULONG cObjects, PSZ *ppszObjects,
                              PSZ pszAttachFile);

#endif // STORAGE_H
