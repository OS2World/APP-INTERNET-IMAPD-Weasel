#ifndef IMAP_H
#define IMAP_H

#include "netserv.h"

#define IMAPR_OK                 0x00010000
#define IMAPR_NO                 0x00020000
#define IMAPR_BAD                0x00030000
#define IMAPR_DISCONNECT         0xFFFF0000
#define IMAPR_VOID               0x00000000

#define IMAPR_OK_COMPLETED                 (IMAPR_OK | 0)
#define IMAPR_OK_SELECT_COMPLETED          (IMAPR_OK | 1)
#define IMAPR_OK_EXAMINE_COMPLETED         (IMAPR_OK | 2)
#define IMAPR_OK_STARTTLS                  (IMAPR_OK | 3)
#define IMAPR_OK_IDLE_TERMINATED           (IMAPR_OK | 4)
#define IMAPR_NO_NOT_IMPLEMENTED           (IMAPR_NO | 5)
#define IMAPR_NO_FAILURE                   (IMAPR_NO | 6)
#define IMAPR_NO_INTERNAL_ERROR            (IMAPR_NO | 7)
#define IMAPR_NO_TRYCREATE                 (IMAPR_NO | 8)
#define IMAPR_NO_SEARCH_BADCHARSET         (IMAPR_NO | 9)
#define IMAPR_NO_UNKNOWN_FLAG              (IMAPR_NO | 10)
#define IMAPR_NO_INVALID_TIME              (IMAPR_NO | 11)
#define IMAPR_NO_DISK_FULL                 (IMAPR_NO | 12)
#define IMAPR_NO_LIMIT_REACHED             (IMAPR_NO | 13)
#define IMAPR_NO_CANT_SET_THAT_DATA        (IMAPR_NO | 14)
#define IMAPR_NO_NOSUCHQUOTA               (IMAPR_NO | 15)
#define IMAPR_NO_AUTHENTICATION_FAILED     (IMAPR_NO | 16)
#define IMAPR_NO_NONEXISTENT               (IMAPR_NO | 17)
#define IMAPR_NO_ALREADYEXISTS             (IMAPR_NO | 18)
#define IMAPR_NO_POP3_LOCKED               (IMAPR_NO | 19)
#define IMAPR_BAD_SYNTAX_ERROR             (IMAPR_BAD | 20)
#define IMAPR_BAD_COMMAND_ERROR            (IMAPR_BAD | 21)
#define IMAPR_BAD_INVALID_STATE            (IMAPR_BAD | 22)
#define IMAPR_BAD_CANCELED                 (IMAPR_BAD | 23)

#define IMAPF_LOGINDISABLED      0x0001

extern BOOL            fGlIMAPEnabled;

BOOL imapInit();
VOID imapDone();

#endif // IMAP_H
