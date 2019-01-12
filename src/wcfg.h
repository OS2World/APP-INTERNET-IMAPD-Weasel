#ifndef WCFG_H
#define WCFG_H

#include "inifiles.h"

#define WC_AS_CONFIGURED   (~0)
#define WC_STRICTLY_INI    INITYPE_INI
#define WC_STRICTLY_TNI    INITYPE_TNI

#define WC_USRFL_ACTIVE    0x01
#define WC_USRFL_USE_IMAP  0x02


extern ULONG           ulGlWCfgPOP3BindPort;
extern ULONG           ulGlWCfgIMAPBindPort;
extern BOOL            fGlWCfgPOP3Enabled;

// Users enumeration object for wcfgFindUser*().

typedef struct _WCFINDUSR {
  PSZ        pszPassword;                  // out
  CHAR       acHomeDir[CCHMAXPATH];        // out
  PSZ        pszDomainName;                // out
  PSZ        pcDomainAliases;              // out
  ULONG      ulReqFlags;
  ULONG      ulNextDomain;
  ULONG      cbUser;
  PSZ        pszInDomain;
  CHAR       acUser[1];
} WCFINDUSR, *PWCFINDUSR;

// pszPath - Weasel home directory.
// ulSelectCfg - WC_xxxxx
BOOL wcfgInit(PSZ pszPath, ULONG ulSelectCfg);
VOID wcfgDone();
BOOL wcfgUpdate(BOOL fIgnoreFTimeCheck);

// Fills pcBuf (up to cbBuf bytes incl. ZERO) with MailRoot path WITH trailing
// slash. If pszSubPath is not NULL the result path will be appended with given
// string.
LONG wcfgQueryMailRootDir(ULONG cbBuf, PCHAR pcBuf, PSZ pszSubPath);

BOOL wcfgQueryMultiDomain();
LONG wcfgQueryOurHostName(ULONG cbBuf, PCHAR pcBuf);
ULONG wcfgQueryBadPasswordLimit();

// Users enumeration for given username (with or w/o domain part).
// Only records with flags WC_USRFL_* specified by ulReqFlags will be
// processed.
// Warning: The configuration will be locked before the function
// wcfgFindUserEnd() is called. Calling other wcfg*() functions before calling
// function wcfgFindUserEnd() after wcfgFindUserBegin() will block the thread.
PWCFINDUSR wcfgFindUserBegin(PSZ pszUser, ULONG ulReqFlags);
VOID wcfgFindUserEnd(PWCFINDUSR pFind);
BOOL wcfgFindUser(PWCFINDUSR pFind);

// LONG wcfgQueryUser(PSZ pszUser, PSZ pszPassword, ULONG ulReqFlags,
//                    ULONG cbHomeDir, PCHAR pcHomeDir)
//
// Fills pcHomeDir (up to cbHomeDir bytes incl. ZERO) with (sub)path relative
// to MailRoot directory without leading and trailing slashes.
// Only records with flags WC_USRFL_* specified by ulReqFlags will be
// processed.
// Returns length of result string in pcBuf without ZERO or: 0 - user/password
// has not been not found, -1 - not enough space at pcHomeDir (cbHomeDir too
// small).
//
LONG wcfgQueryUser(PSZ pszUser, PSZ pszPassword, ULONG ulReqFlags,
                   ULONG cbHomeDir, PCHAR pcHomeDir);

// Calls user function for the each configured domain while it returns TRUE. In
// single domain mode fnOnDomain() will be called once with NULL argument.
// Returns TRUE if all records has been processed (user function returns TRUE
// for all domains).
BOOL wcfgForEachDomain(BOOL (*fnOnDomain)(PSZ pszDomain, PVOID pUser),
                       PVOID pUser);

BOOL wcfgForEachUser(PSZ pszDomain,
                     BOOL (*fnOnUser)(PSZ pszUser, ULONG ulFlags, PVOID pUser),
                     PVOID pUser);

// Searches pszDomain in domain names than in aliases.
// Copies found domain name to pcBuf.
// Returns TRUE if domain with given name or alias was found and buffer space
// is sufficient. If cbBuf is 0 and name/alias is found function will not copy
// domain name to buffer and will return TRUE.
BOOL wcfgGetDomainName(PSZ pszDomain, ULONG cbBuf, PCHAR pcBuf);

LONG wcfgGenerateMsgId(ULONG cbBuf, PCHAR pcBuf);

#endif // WCFG_H
