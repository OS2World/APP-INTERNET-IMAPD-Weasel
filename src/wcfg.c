/*
  Weasel configuration reader.
*/

#include <string.h>
#include <stdlib.h>
#define INCL_DOSERRORS
#define INCL_DOSSEMAPHORES
#define INCL_DOSPROCESS
#include <os2.h>
#include "utils.h"
#include "log.h"
#include "imap.h"
#include "inifiles.h"
#include "hmem.h"
#include "storage.h"
#include "wcfg.h"
#include "debug.h"               // Should be last.

//#define DEBUG_USERS

extern NSPROTO         stProtoPOP3;        // pop3.c
extern NSPROTO         stProtoIMAP;        // imap.c

ULONG                  ulGlWCfgPOP3BindPort;
ULONG                  ulGlWCfgIMAPBindPort;
BOOL                   fGlWCfgPOP3Enabled;

typedef struct _LOGIN {
  ULONG      ulFlags;                      // WC_USRFL_xxxxx
  CHAR       acLogin[1];                   // username<ZERO>password<ZERO>
} LOGIN, *PLOGIN;

typedef struct _DOMAIN {
  PSZ        pszName;
  PCHAR      pcAliases;
  BOOL       fStrictChecking;
  ULONG      cLogins;
  PLOGIN     apLogins[1];
} DOMAIN, *PDOMAIN;

typedef struct _WCFG {
  PSZ        pszMailRoot;
  BOOL       fMultiDomain;
  ULONG      ulBadPasswordLimit;
  PSZ        pszOurHostName;
  BOOL       fSingleMatch;
  ULONG      cDomains;
  PDOMAIN    apDomains[1];
} WCFG, *PWCFG;


PSZ                    pszWeaselPath = NULL;

static UTILFTIMESTAMP  stLastTimestamp;
static ULONG           ulLastINIType;
static ULONG           ulSelectWeaselCfg;

static PWCFG           pWCfg     = NULL;
static HMTX            hmtxWCfg  = NULLHANDLE;

#ifdef DEBUG_USERS
static VOID _debugPrintWCfg(PWCFG pWCfg)
{
  ULONG      ulIdx, ulLogin;
  PDOMAIN    pDomain;
  PLOGIN     pLogin;

  printf( "Domains: %u\n", pWCfg->cDomains );
  for( ulIdx = 0; ulIdx < pWCfg->cDomains; ulIdx++ )
  {
    pDomain = pWCfg->apDomains[ulIdx];
    printf( "Domain: %s\n", pDomain->pszName );

    for( ulLogin = 0; ulLogin < pDomain->cLogins; ulLogin++ )
    {
      pLogin = pDomain->apLogins[ulLogin];
      printf( "  %s", pLogin->acLogin );
      printf( "\t%s\n", strchr( pLogin->acLogin, '\0' ) + 1 );
    }
  }
}
#else
#define _debugPrintWCfg(__pWCfg)
#endif

static PSZ _iniQueryNewString(PINI pINI, PSZ pszApp, PSZ pszKey)
{
  ULONG      cbStr;
  PSZ        pszStr;

  if ( !iniQuerySize( pINI, pszApp, pszKey, &cbStr ) )
  {
    debug( "iniQuerySize(,\"%s\",\"%s\",) failed", pszApp, pszKey );
    return NULL;
  }

  cbStr++;
  pszStr = hmalloc( cbStr );
  if ( pszStr == NULL )
    return FALSE;

  if ( !iniQueryData( pINI, pszApp, pszKey, pszStr, &cbStr ) )
  {
    debug( "iniQueryData(,\"%s\",\"%s\",,) failed", pszApp, pszKey );
    hfree( pszStr );
    return NULL;
  }
  pszStr[cbStr] = '\0';

  return pszStr;
}

static LONG _iniQueryLong(PINI pINI, PSZ pszApp, PSZ pszKey, LONG lDefault)
{
  LONG       lVal = 0;
  ULONG      cbVal = sizeof(LONG);

  if ( !iniQueryData( pINI, pszApp, pszKey, &lVal, &cbVal ) )
    return lDefault;

  return lVal;
}

static int _compLogins(const void *p1, const void *p2)
{
  return stricmp( (*(PLOGIN *)p1)->acLogin, (*(PLOGIN *)p2)->acLogin );
}

static int _compSearchLogin(const void *p1, const void *p2)
{
  return stricmp( (PSZ)p1, (*(PLOGIN *)p2)->acLogin );
}

static VOID _domainFree(PDOMAIN pDomain)
{
  ULONG      ulIdx;

  if ( pDomain == NULL )
    return;

  for( ulIdx = 0; ulIdx < pDomain->cLogins; ulIdx++ )
    if ( pDomain->apLogins[ulIdx] != NULL )
      hfree( pDomain->apLogins[ulIdx] );

  if ( pDomain->pszName != NULL )
    hfree( pDomain->pszName );

  if ( pDomain->pcAliases != NULL )
    hfree( pDomain->pcAliases );

  hfree( pDomain );
}

static PDOMAIN _domainINIHdlNew(PINI pINI, PSZ pszDomain)
{
  BOOL       fSuccess = FALSE;
  ULONG      cbPassword, cbLogins;
  PSZ        pszScan;
  PDOMAIN    pDomain = NULL;
  PSZ        pszLogins = NULL;
  PLOGIN     pLogin;

  do
  {
    // Read all "Application names" from ini.

    if ( !iniQuerySize( pINI, NULL, NULL, &cbLogins ) )
    {
      debug( "iniQuerySize(,NULL,NULL,) failed" );
      break;
    }

    cbLogins++;
    pszLogins = hmalloc( cbLogins );
    if ( pszLogins == NULL )
      break;

    if ( !iniQueryData( pINI, NULL, NULL, pszLogins, &cbLogins ) )
    {
      debug( "iniQueryData() failed" );
      break;
    }

    // Scan "Application names".
    for( pszScan = pszLogins; *pszScan != '\0';
         pszScan = strchr( pszScan, '\0' ) + 1 )
    {
      if ( ( *pszScan == '$' ) ||
           !iniQuerySize( pINI, pszScan, "Password", &cbPassword ) )
        continue;

      // Make login record: username<ZERO>password<ZERO>
      cbLogins = strlen( pszScan );
      cbPassword++;
      pLogin = hmalloc( sizeof(LOGIN) + cbLogins + 1 + cbPassword );
      if ( pLogin == NULL )
        break;

      pLogin->ulFlags = _iniQueryLong( pINI, pszScan, "Active", 0 ) != 0
                          ? WC_USRFL_ACTIVE : 0;
      if ( _iniQueryLong( pINI, pszScan, "UseIMAP", 0 ) != 0 )
        pLogin->ulFlags |= WC_USRFL_USE_IMAP;

      strcpy( pLogin->acLogin, pszScan );
      cbLogins++;
      cbLogins += iniQueryString( pINI, pszScan, "Password", NULL,
                                  &pLogin->acLogin[cbLogins], cbPassword );
      pLogin->acLogin[cbLogins] = '\0';

      cbLogins = pDomain == NULL ? 0 : pDomain->cLogins;
      if ( (cbLogins & 0x00FF) == 0 )
      {
        // Expand DOMAIN object.
        PDOMAIN  pNew = hrealloc( pDomain,
                                 ( sizeof(DOMAIN) - sizeof(PLOGIN) ) +
                                 ( (cbLogins + 0x0100) * sizeof(PLOGIN) ) );
        if ( pNew == NULL )
        {
          hfree( pLogin );
          break;
        }
        pDomain = pNew;
      }

      // Store login in DOMAIN object.
      pDomain->apLogins[cbLogins] = pLogin;
      pDomain->cLogins = cbLogins + 1;
    }

    if ( pDomain == NULL )
    {
      // No IMAP4 users were found. Create an empty list (DOMAIN object).

      pDomain = hmalloc( sizeof(DOMAIN) - sizeof(PLOGIN) );
      if ( pDomain == NULL )
        break;
      pDomain->cLogins = 0;
    }

    if ( pszDomain != NULL )
    {
      // Store domain name in DOMAIN object.
      pDomain->pszName = hstrdup( pszDomain );
      fSuccess = pDomain->pszName != NULL;
    }
    else
    {
      pDomain->pszName = NULL;
      fSuccess = TRUE;
    }

    // Get domain aliases.

    pDomain->pcAliases = _iniQueryNewString( pINI, "$SYS", "Local" );
    pDomain->fStrictChecking =
      _iniQueryLong( pINI, "$SYS", "StrictChecking", 0 ) != 0;
  }
  while( FALSE );

  if ( pszLogins != NULL )
    hfree( pszLogins );

  if ( fSuccess )
  {
    // Collapse DOMAIN object.
    PDOMAIN  pNew = hrealloc( pDomain, ( sizeof(DOMAIN) - sizeof(PLOGIN) ) +
                                       ( pDomain->cLogins * sizeof(PLOGIN) ) );
    if ( pNew != NULL )
      pDomain = pNew;

    qsort( pDomain->apLogins, pDomain->cLogins, sizeof(PLOGIN), _compLogins );
  }
  else if ( pDomain != NULL )
  {
    _domainFree( pDomain );
    pDomain = NULL;
  }

  return pDomain;
}

static PDOMAIN _domainINIFileNew(PSZ pszMailRoot, ULONG ulINIType,
                                 PSZ pszDomain)
{
  INI                  stINI;
  CHAR                 acFile[CCHMAXPATH];
  PDOMAIN              pDomain;

  if ( _snprintf( acFile, sizeof(acFile), "%s%s\\DOMAIN.%s",
                  pszMailRoot, pszDomain,
                  ulINIType == INITYPE_INI ? "INI" : "TNI" ) == -1 )
    return NULL;

  if ( !iniOpen( &stINI, ulINIType, acFile ) )
  {
    debug( "iniOpen(,\"%s\") failed", acFile );
    pDomain = NULL;
  }
  else
  {
    debug( "Read %s", acFile );
    pDomain = _domainINIHdlNew( &stINI, pszDomain );
    iniClose( &stINI );
  }

  return pDomain;
}

static VOID _wcfgFree(PWCFG pWCfg)
{
  ULONG      ulIdx;

  for( ulIdx = 0; ulIdx < pWCfg->cDomains; ulIdx++ )
  {
    if ( pWCfg->apDomains[ulIdx] != NULL )
      _domainFree( pWCfg->apDomains[ulIdx] );
  }

  if ( pWCfg->pszMailRoot != NULL )
    hfree( pWCfg->pszMailRoot );

  if ( pWCfg->pszOurHostName != NULL )
    hfree( pWCfg->pszOurHostName );

  hfree( pWCfg );
}

#define _LOAD_OK                 0
#define _LOAD_FAIL               1
#define _LOAD_NO_MAILROOT        2
#define _LOAD_WANT_OTHER_TYPE    3
#define _LOAD_OPEN_FAIL          4

ULONG _wcfgLoad(PSZ pszFile, ULONG ulINIType, PUTILFTIMESTAMP pFTimestamp,
                BOOL fIgnoreFTimeCheck, BOOL fFailOnInvalidType)
{
  INI                  stINI;
  PSZ                  pszScan;
  PWCFG                pOldWCfg, pNewWCfg = NULL;
  ULONG                cDomains;
  LONG                 ulIdx;
  CHAR                 acMailRool[CCHMAXPATH];
  BOOL                 fIMAPEnabled, fPOP3Enabled, fMultiDomain;
  CHAR                 acLogFile[CCHMAXPATH];
  ULONG                ulLogFlags;
  ULONG                ulPOP3BindPort   = 0,  ulIMAPBindPort    = 0;
  ULONG                ulPOP3Timeout    = 0,  ulIMAPTimeout     = 0;
  ULONG                ulPOP3MaxClients = 0,  ulIMAPMaxClients  = 0;
  ULONG                aulData[4];
  ULONG                cbData;
  ULONG                ulRC = NO_ERROR;
  BOOL                 fSuccess = FALSE;

  if ( !fIgnoreFTimeCheck && ( pWCfg != NULL ) &&
       ( ulLastINIType == ulINIType ) &&
       utilIsSameFileDateTime( pFTimestamp, &stLastTimestamp ) )
  {
//    debugCP( "Weasel configuration file has not been changed" );
    return _LOAD_OK;
  }

  if ( !iniOpen( &stINI, ulINIType, pszFile ) )
  {
    debug( "iniOpen(,\"%s\") failed", pszFile );
    return _LOAD_OPEN_FAIL;
  }

  if ( fFailOnInvalidType )
  {
    ULONG    ulUseTNI = 0;
    ULONG    cbUseTNI = sizeof(ULONG);

    if ( iniQueryData( &stINI, "$SYS", "UseTNI", &ulUseTNI, &cbUseTNI ) )
    {
      if ( ( ulINIType == INITYPE_TNI ) != ( ulUseTNI != 0 ) )
      {
        iniClose( &stINI );
        return _LOAD_WANT_OTHER_TYPE;
      }
    }
  }

  logf( 2, "Getting configuration data from %s", pszFile );

  ulRC = iniQueryString( &stINI, "$SYS", "MailRoot", NULL,
                         acMailRool, sizeof(acMailRool) - 2 );
  if ( ulRC == 0 )
  {
    logs( 0, "MailRoot path is not specified by the Weasel configuration" );
    iniClose( &stINI );
    return _LOAD_NO_MAILROOT;
  }

/* [Not good for -Wall]
  *((PUSHORT)&acMailRool[ulRC]) = 
    acMailRool[ulRC - 1] != '\\' ? (USHORT)0x005C : 0;*/
  if ( acMailRool[ulRC - 1] != '\\' )
    acMailRool[ulRC++] = '\\';
  acMailRool[ulRC] = '\0';

  debug( "MailRoot: %s", acMailRool );

  // Key "Enable": bits: 0x01 - SMTP, 0x02 - POP3, 0x04 - IMAP4.
  ulRC = _iniQueryLong( &stINI, "$SYS", "Enable", 0x04 );
  fIMAPEnabled = (ulRC & 0x04) != 0;
  fPOP3Enabled = (ulRC & 0x02) != 0;

  ulRC = iniQueryString( &stINI, "$SYS", "IMAPLogFileName", NULL,
                         acLogFile, sizeof(acLogFile) - 1 );
  acLogFile[ulRC] = '\0';

  // Key "IMAPTransLevel": logfile output, bits: 0x01 - disk, 0x02 - screen.
  ulLogFlags = _iniQueryLong( &stINI, "$SYS", "IMAPTransLevel",
                              LOGFL_DISK | LOGFL_SCREEN );

  // Key "MaxUsers": four ULONG values: 0 - SMTP, 1 - POP3, 2 - IMAP4,
  //                                    3 - SMTP, message submission.
  cbData = sizeof(aulData);
  if ( iniQueryData( &stINI, "$SYS", "MaxUsers", &aulData, &cbData ) )
  {
    ulPOP3MaxClients = aulData[1];
    ulIMAPMaxClients = aulData[2];
  }

  // Key "ServerPort": four ULONG values: 0 - SMTP, 1 - POP3, 2 - IMAP4,
  //                                      3 - SMTP, message submission.
  cbData = sizeof(aulData);
  if ( iniQueryData( &stINI, "$SYS", "ServerPort", &aulData, &cbData ) )
  {
    ulPOP3BindPort = aulData[1];
    ulIMAPBindPort = aulData[2];
  }

  // Key "TimeOut": four ULONG values: 0 - SMTP, 1 - POP3, 2 - IMAP4,
  //                                   3 - SMTP, message submission.
  cbData = sizeof(aulData);
  if ( iniQueryData( &stINI, "$SYS", "TimeOut", &aulData, &cbData ) )
  {
    ulPOP3Timeout = aulData[1];
    ulIMAPTimeout = aulData[2];
  }

  fMultiDomain = _iniQueryLong( &stINI, "$SYS", "MultiDomainEnabled", 0 ) != 0;
  if ( !fMultiDomain )
  {
    // Single domain mode - read logins from WEASEL.INI or WEASEL.TNI.

    pNewWCfg = hmalloc( sizeof(WCFG) );

    if ( pNewWCfg != NULL )
    {
      pNewWCfg->pszMailRoot = NULL;
      pNewWCfg->cDomains = 1;
      pNewWCfg->apDomains[0] = _domainINIHdlNew( &stINI, NULL );
      fSuccess = pNewWCfg->apDomains[0] != NULL;
    }
  }
  else
  {
    // Multi-domain mode - read logins from <MailRoot>\<domain>\DOMAIN.INI.

    PSZ      pszDomains = _iniQueryNewString( &stINI, "$SYS", "Domains" );

    if ( pszDomains != NULL )
    {
      for( pszScan = pszDomains, cDomains = 0; *pszScan != '\0';
           pszScan = strchr( pszScan, '\0' ) + 1, cDomains++ );

      pNewWCfg = hmalloc( ( sizeof(WCFG) - sizeof(PDOMAIN) ) +
                          ( cDomains * sizeof(PDOMAIN) ) );
      if ( pNewWCfg != NULL )
      {
        pNewWCfg->pszMailRoot = NULL;
        pNewWCfg->cDomains = 0;
        for( pszScan = pszDomains, ulIdx = 0;
             *pszScan != '\0' && ulIdx < cDomains;
             pszScan = strchr( pszScan, '\0' ) + 1, ulIdx++ )
        {
          pNewWCfg->apDomains[ulIdx] = _domainINIFileNew( acMailRool,
                                                           ulINIType, pszScan );
          if ( pNewWCfg->apDomains[ulIdx] == NULL )
            break;
          pNewWCfg->cDomains++;
        }

        fSuccess = *pszScan == '\0';
      }

      hfree( pszDomains );
    } // if ( pszDomains != NULL )
  } // Multidomain mode

  if ( fSuccess )
  {
    CHAR     acOurHostName[128];

    // "Always report our hostname as" setup option.
    ulRC = _iniQueryLong( &stINI, "$SYS", "UseFixedLocalName", 0 ) != 0
             ? iniQueryString( &stINI, "$SYS", "OurHostName", NULL,
                               acOurHostName, sizeof(acOurHostName) - 1 )
             : 0;
    acOurHostName[ulRC] = '\0';

    pNewWCfg->pszOurHostName = ulRC == 0 ? NULL : hstrdup( acOurHostName );

    // "Bad password limit" setup option.
    pNewWCfg->ulBadPasswordLimit =
      _iniQueryLong( &stINI, "$SYS", "BadPasswordLimit", 0 );

    // "Accept only the first username/domain match" setup option.
    pNewWCfg->fSingleMatch =
      _iniQueryLong( &stINI, "$SYS", "SingleMatch", 0 ) != 0;

    pNewWCfg->pszMailRoot = hstrdup( acMailRool );
    fSuccess = pNewWCfg->pszMailRoot != NULL;
  }

  iniClose( &stINI );

  if ( !fSuccess )
  {
    if ( pNewWCfg != NULL )
      _wcfgFree( pNewWCfg );
    return _LOAD_FAIL;
  }

  pNewWCfg->fMultiDomain     = fMultiDomain;

  DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );
  pOldWCfg         = pWCfg;
  pWCfg            = pNewWCfg;
  stLastTimestamp  = *pFTimestamp;
  ulLastINIType    = ulINIType;
  _debugPrintWCfg( pWCfg );
  DosReleaseMutexSem( hmtxWCfg );

  if ( pOldWCfg != NULL )
    _wcfgFree( pOldWCfg );

  logSetup( ulLogFlags, acLogFile );

  logf( 5, "%s domain mode", fMultiDomain ? "Multiple" : "Single" );

  if ( fGlIMAPEnabled != fIMAPEnabled )
  {
    logf( 0, "IMAP4 service is %s now", fIMAPEnabled ? "enabled" : "disabled" );
    fGlIMAPEnabled = fIMAPEnabled;
  }

  fGlWCfgPOP3Enabled        = fPOP3Enabled;
  ulGlWCfgPOP3BindPort      = ulPOP3BindPort;
  ulGlWCfgIMAPBindPort      = ulIMAPBindPort;

  // stProtoIMAP defined in imap.c - global protocol settings.
  stProtoIMAP.ulMaxClients  = ulIMAPMaxClients;
  stProtoIMAP.ulTimeout     = ulIMAPTimeout * 1000;

  // stProtoPOP3 defined in pop3.c - global protocol settings.
  stProtoPOP3.ulMaxClients  = ulPOP3MaxClients;
  stProtoPOP3.ulTimeout     = ulPOP3Timeout * 1000;

  debugCP( "msSync()..." );
  msSync();

  debugCP( "Done, _LOAD_OK" );
  return _LOAD_OK;
}


BOOL wcfgInit(PSZ pszPath, ULONG ulSelectCfg)
{
  ULONG      ulRC;

  if ( ( pszPath == NULL ) || ( *pszPath == '\0' ) )
    pszWeaselPath = NULL;
  else
  {
    ULONG    cbWeaselPath = strlen( pszPath );

    if ( pszPath[cbWeaselPath - 1] == '\\' )
      cbWeaselPath--;

    pszWeaselPath = hmalloc( cbWeaselPath + 1);
    if ( pszWeaselPath == NULL )
      return FALSE;

    memcpy( pszWeaselPath, pszPath, cbWeaselPath );
    pszWeaselPath[cbWeaselPath] = '\0';
  }
  ulSelectWeaselCfg = ulSelectCfg;

  ulRC = DosCreateMutexSem( NULL, &hmtxWCfg, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(), rc = %u", ulRC );
    return FALSE;
  }

  bzero( &stLastTimestamp, sizeof(stLastTimestamp) );
  ulLastINIType = INITYPE_INI;

  if ( !wcfgUpdate( TRUE ) )
  {
    debugCP( "call wcfgDone()..." );
    wcfgDone();
    return FALSE;
  }

  return TRUE;
}

VOID wcfgDone()
{
  if ( pszWeaselPath != NULL )
  {
    hfree( pszWeaselPath );
    pszWeaselPath = NULL;
  }

  if ( hmtxWCfg != NULLHANDLE )
  {
    DosCloseMutexSem( hmtxWCfg );
    hmtxWCfg = NULLHANDLE;
  }

  if ( pWCfg != NULL )
  {
    _wcfgFree( pWCfg );
    pWCfg = NULL;
  }
}

BOOL wcfgUpdate(BOOL fIgnoreFTimeCheck)
{
  CHAR                 acINIFile[CCHMAXPATH];
  UTILFTIMESTAMP       stINITime;
  BOOL                 fINIExist;
  CHAR                 acTNIFile[CCHMAXPATH];
  UTILFTIMESTAMP       stTNITime;
  BOOL                 fTNIExist;
  ULONG                ulRC;

  if ( ( _snprintf( acINIFile, sizeof(acINIFile), "%s\\WEASEL.INI",
           pszWeaselPath == NULL ? "." : (PCHAR)pszWeaselPath ) < 0 ) ||
       ( _snprintf( acTNIFile, sizeof(acTNIFile), "%s\\WEASEL.TNI",
           pszWeaselPath == NULL ? "." : (PCHAR)pszWeaselPath ) < 0 ) )
    return FALSE;

  fINIExist = utilQueryFileInfo( acINIFile, &stINITime, NULL );
  fTNIExist = utilQueryFileInfo( acTNIFile, &stTNITime, NULL );

  if ( ulSelectWeaselCfg == WC_STRICTLY_INI )
  {
//    debugCP( "User want strictly WEASEL.INI" );
    ulRC = _wcfgLoad( acINIFile, INITYPE_INI, &stINITime, fIgnoreFTimeCheck,
                      FALSE );
  }
  else if ( ulSelectWeaselCfg == WC_STRICTLY_TNI )
  {
//    debugCP( "User want strictly WEASEL.TNI" );
    ulRC = _wcfgLoad( acTNIFile, INITYPE_TNI, &stTNITime, fIgnoreFTimeCheck,
                      FALSE );
  }
  else if ( fINIExist && fTNIExist )
  {
/*    debug( "Both files (WEASEL.INI and WEASEL.TNI) exist - try first %s",
           ulLastINIType == INITYPE_INI ? "INI" : "TNI" );*/

    if ( ulLastINIType == INITYPE_INI )
      ulRC = _wcfgLoad( acINIFile, INITYPE_INI, &stINITime, fIgnoreFTimeCheck,
                        TRUE );
    else
      ulRC = _wcfgLoad( acTNIFile, INITYPE_TNI, &stTNITime, fIgnoreFTimeCheck,
                        TRUE );

    if ( ulRC == _LOAD_WANT_OTHER_TYPE )
    {
      ulLastINIType = ulLastINIType == INITYPE_INI ? INITYPE_TNI : INITYPE_INI;
/*      debug( "Switch to %s...",
             ulLastINIType == INITYPE_INI ? "INI" : "TNI" );*/

      if ( ulLastINIType == INITYPE_INI )
        ulRC = _wcfgLoad( acINIFile, INITYPE_INI, &stINITime,
                          fIgnoreFTimeCheck, TRUE );
      else
        ulRC = _wcfgLoad( acTNIFile, INITYPE_TNI, &stTNITime,
                          fIgnoreFTimeCheck, TRUE );

      if ( ulRC == _LOAD_WANT_OTHER_TYPE )
      {
        logs( 0, "Inconsistency between Weasel.INI and Weasel.TNI. "
                 "Run ChooseTNI to fix the problem, then try again." );
      }
    }
  }
  else if ( fINIExist )
  {
//    debugCP( "Only file WEASEL.INI exist" );
    ulRC = _wcfgLoad( acINIFile, INITYPE_INI, &stINITime, fIgnoreFTimeCheck,
                      FALSE );
  }
  else if ( fTNIExist )
  {
//    debugCP( "Only file WEASEL.TNI exist" );
    ulRC = _wcfgLoad( acTNIFile, INITYPE_TNI, &stTNITime, fIgnoreFTimeCheck,
                      FALSE );
  }
  else
  {
    debugCP( "WEASEL.INI and WEASEL.TNI do not exist" );
    return FALSE;
  }

  if ( ulRC != _LOAD_OK )
    debug( "#2 _wcfgLoad(), rc = %u", ulRC );

  return ulRC == _LOAD_OK;
}

LONG wcfgQueryMailRootDir(ULONG cbBuf, PCHAR pcBuf, PSZ pszSubPath)
{
  LONG      cbMailRoot;
  ULONG     cbSubPath;

  DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );

  if ( ( pWCfg == NULL ) || ( pWCfg->pszMailRoot == NULL ) )
  {
    cbMailRoot = -1;
    debugCP( "Is wcfg module initialized?" );
  }
  else
  {
    cbMailRoot = strlen( pWCfg->pszMailRoot );
    if ( cbMailRoot >= cbBuf )
      cbMailRoot = -1;
    else
      strcpy( pcBuf, pWCfg->pszMailRoot );
  }

  DosReleaseMutexSem( hmtxWCfg );

  if ( ( cbMailRoot != -1 ) && ( pszSubPath != NULL ) )
  {
    while( *pszSubPath == '\\' )
      pszSubPath++;

    cbSubPath = strlen( pszSubPath );

    if ( ( cbMailRoot + cbSubPath ) >= cbBuf )
      cbMailRoot = -1;
    else
    {
      strcpy( &pcBuf[cbMailRoot], pszSubPath );
      cbMailRoot += cbSubPath;
    }
  }

  return cbMailRoot;
}

BOOL wcfgQueryMultiDomain()
{
  BOOL      fMultiDomain;

  DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );
  fMultiDomain = ( pWCfg != NULL ) && pWCfg->fMultiDomain;
  DosReleaseMutexSem( hmtxWCfg );

  return fMultiDomain;
}

LONG wcfgQueryOurHostName(ULONG cbBuf, PCHAR pcBuf)
{
  LONG      cbOurHostName;

  if ( cbBuf == 0 )
    return -1;

  DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );

  if ( ( pWCfg == NULL ) || ( pWCfg->pszOurHostName == NULL ) )
    cbOurHostName = 0;
  else
  {
    cbOurHostName = strlen( pWCfg->pszOurHostName );
    if ( cbOurHostName >= cbBuf )
      cbOurHostName = -1;
    else
      strcpy( pcBuf, pWCfg->pszOurHostName );
  }

  DosReleaseMutexSem( hmtxWCfg );

  if ( cbOurHostName <= 0 )
  {
    PSZ      pszEnvHostName = getenv( "HOSTNAME" );

    if ( pszEnvHostName == NULL )
    {
      *pcBuf = '\0';
      cbOurHostName = 0;
    }
    else
    {
      cbOurHostName = strlen( pszEnvHostName );
      if ( cbOurHostName >= cbBuf )
        cbOurHostName = -1;
      else
        strcpy( pcBuf, pszEnvHostName );
    }
  }

  return cbOurHostName;
}

ULONG wcfgQueryBadPasswordLimit()
{
  ULONG      ulBadPasswordLimit;

  DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );
  ulBadPasswordLimit = pWCfg == NULL ? 0 : pWCfg->ulBadPasswordLimit;
  DosReleaseMutexSem( hmtxWCfg );

  return ulBadPasswordLimit;
}

PWCFINDUSR wcfgFindUserBegin(PSZ pszUser, ULONG ulReqFlags)
{
  PWCFINDUSR pFind;
  PSZ        pszDomain;
  ULONG      ulRC;

  pFind = hmalloc( sizeof(WCFINDUSR) + strlen(pszUser) );
  if ( pFind == NULL )
    return NULL;

  strcpy( pFind->acUser, pszUser );
  pszDomain = strpbrk( pFind->acUser, "@%" );
  if ( pszDomain == NULL )
  {
    // Domain is not specified in the username.
    pFind->cbUser = strlen( pszUser );
    pFind->pszInDomain = NULL;
  }
  else
  {
    // Domain is specified in the username.
    pFind->cbUser = pszDomain - pszUser;
    *pszDomain = '\0';
    pszDomain++;
    pFind->pszInDomain = *pszDomain == '\0' ? NULL : pszDomain;
  }
  pFind->ulNextDomain = 0;
  pFind->ulReqFlags = ulReqFlags;

  ulRC = DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u", ulRC );
    hfree( pFind );
    return NULL;
  }

  if ( pWCfg == NULL )
  {
    DosReleaseMutexSem( hmtxWCfg );
    hfree( pFind );
    return NULL;
  }

  return pFind;
}

VOID wcfgFindUserEnd(PWCFINDUSR pFind)
{
  ULONG      ulRC;

  if ( pFind == NULL )
    return;

  ulRC = DosReleaseMutexSem( hmtxWCfg );
  if ( ulRC != NO_ERROR )
    debug( "DosReleaseMutexSem(), rc = %u", ulRC );

  hfree( pFind );
}

BOOL wcfgFindUser(PWCFINDUSR pFind)
{
  ULONG      ulDomain;
  PDOMAIN    pDomain;
  LONG       lRes = -1;
  PLOGIN     *ppLogin;
  PSZ        pszUser = pFind->acUser; 

  if ( ( pFind == NULL ) || ( pFind->ulNextDomain >= pWCfg->cDomains ) ||
       ( ( pFind->ulNextDomain != 0 ) && pWCfg->fSingleMatch ) )
    return FALSE;

  for( ulDomain = pFind->ulNextDomain; ulDomain < pWCfg->cDomains; ulDomain++ )
  {
    pDomain = pWCfg->apDomains[ulDomain];
    if ( pFind->pszInDomain != NULL )
    {
      BOOL   fFound = FALSE;
      PCHAR  pcAliases = pDomain->pcAliases;

      if ( ( pDomain->pszName != NULL ) &&
           ( stricmp( pFind->pszInDomain, pDomain->pszName ) == 0 ) )
        fFound = TRUE;
      else if ( pcAliases != NULL )
      {
        for( ; *pcAliases != '\0'; pcAliases = strchr( pcAliases, '\0' ) + 1 )
        {
          if ( stricmp( pFind->pszInDomain, pcAliases ) == 0 )
          {
            fFound = TRUE;
            break;
          }
        }
      }

      if ( !fFound )
        continue;
    }

    ppLogin = bsearch( pszUser, pDomain->apLogins, pDomain->cLogins,
                       sizeof(PLOGIN), _compSearchLogin );
    if ( ( ppLogin != NULL ) &&
         ( ((*ppLogin)->ulFlags & pFind->ulReqFlags) == pFind->ulReqFlags ) )
    {
      pFind->pszPassword = (PSZ)( strchr( (*ppLogin)->acLogin, '\0' ) + 1 );
      pFind->pszDomainName = pDomain->pszName;
      pFind->pcDomainAliases = pDomain->pcAliases;

      if ( pWCfg->fMultiDomain )
        lRes = _snprintf( pFind->acHomeDir, sizeof(pFind->acHomeDir),
                          "%s\\%s", pDomain->pszName, (*ppLogin)->acLogin );
      else
        lRes = _snprintf( pFind->acHomeDir, sizeof(pFind->acHomeDir), "%s",
                          (*ppLogin)->acLogin );
      
      ulDomain++;
      break;
    }
  }

  pFind->ulNextDomain = ulDomain;
  return lRes != -1;
}

// LONG wcfgQueryUser(PSZ pszUser, PSZ pszPassword,
//                    ULONG cbHomeDir, PCHAR pcHomeDir)
//
// Fills pcHomeDir (up to cbHomeDir bytes incl. ZERO) with (sub)path relative
// to MailRoot directory without initial and trailing slashes.
// Returns length of result string in pcBuf without ZERO or: 0 - user/password
// has not been not found, -1 - not enough space at pcHomeDir (cbHomeDir too
// small).
//
LONG wcfgQueryUser(PSZ pszUser, PSZ pszPassword, ULONG ulReqFlags,
                   ULONG cbHomeDir, PCHAR pcHomeDir)
{
  PWCFINDUSR pFind;
  LONG       cbDir = 0;

  if ( pszUser == NULL || *pszUser == '\0' ||
       pszPassword == NULL || *pszPassword == '\0' )
    return 0;

  pFind = wcfgFindUserBegin( pszUser, ulReqFlags );

  while( wcfgFindUser( pFind ) )
  {
    if ( strcmp( pszPassword, pFind->pszPassword ) == 0 )
    {
      cbDir = strlen( pFind->acHomeDir );
      if ( cbDir >= cbHomeDir )
        cbDir = -1;
      else
        strcpy( pcHomeDir, pFind->acHomeDir );

      break;
    }
  }

  wcfgFindUserEnd( pFind );

  return cbDir;
}

BOOL wcfgForEachDomain(BOOL (*fnOnDomain)(PSZ pszDomain, PVOID pUser),
                       PVOID pUser)
{
  ULONG      ulRC;
  ULONG      ulIdx;
  BOOL       fUserRes = FALSE;

  ulRC = DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
    debug( "DosRequestMutexSem(), rc = %u" );
  else
  {
    for( ulIdx = 0; ulIdx < pWCfg->cDomains; ulIdx++ )
    {
      fUserRes = fnOnDomain( pWCfg->apDomains[ulIdx]->pszName, pUser );
      if ( !fUserRes )
        break;
    }

    DosReleaseMutexSem( hmtxWCfg );
  }

  return fUserRes;
}

BOOL wcfgForEachUser(PSZ pszDomain,
                     BOOL (*fnOnUser)(PSZ pszUser, ULONG ulFlags, PVOID pUser),
                     PVOID pUser)
{
  ULONG      ulRC, ulIdx;
  PDOMAIN    pDomain = NULL;
  BOOL       fUserRes = FALSE;

  ulRC = DosRequestMutexSem( hmtxWCfg, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosRequestMutexSem(), rc = %u" );
    return FALSE;
  }

  for( ulIdx = 0; ulIdx < pWCfg->cDomains; ulIdx++ )
  {
    if ( STR_ICMP( pWCfg->apDomains[ulIdx]->pszName, pszDomain ) == 0 )
    {
      pDomain = pWCfg->apDomains[ulIdx];
      break;
    }
  }

  if ( pDomain != NULL )
  {
    for( ulIdx = 0; ulIdx < pDomain->cLogins; ulIdx++ )
    {
      fUserRes = fnOnUser( pDomain->apLogins[ulIdx]->acLogin,
                           pDomain->apLogins[ulIdx]->ulFlags, pUser );
      if ( !fUserRes )
        break;
    }
  }

  DosReleaseMutexSem( hmtxWCfg );

  return fUserRes;
}

BOOL wcfgGetDomainName(PSZ pszDomain, ULONG cbBuf, PCHAR pcBuf)
{
  PDOMAIN    pDomain = NULL;
  ULONG      ulIdx;

  // First, search in domain names.
  for( ulIdx = 0; ulIdx < pWCfg->cDomains; ulIdx++ )
  {
    if ( STR_ICMP( pWCfg->apDomains[ulIdx]->pszName, pszDomain ) == 0 )
    {
      pDomain = pWCfg->apDomains[ulIdx];
      break;
    }
  }

  if ( ( pDomain == NULL ) && ( pszDomain != NULL ) )
  {
    // Name was not found First - search in domains aliases.
    PCHAR    pcAliases;

    for( ulIdx = 0; ulIdx < pWCfg->cDomains; ulIdx++ )
    {
      pcAliases = pWCfg->apDomains[ulIdx]->pcAliases;
      if ( pcAliases == NULL )
        continue;

      for( ; *pcAliases != '\0'; pcAliases = strchr( pcAliases, '\0' ) + 1 )
      {
        if ( stricmp( pszDomain, pcAliases ) == 0 )
        {
          pDomain = pWCfg->apDomains[ulIdx];
          break;
        }
      }
    }
  }

  if ( ( pDomain == NULL ) ||
       ( ( cbBuf != 0 ) && ( cbBuf <= strlen( pDomain->pszName ) ) ) )
    return FALSE;

  if ( ( pcBuf != NULL ) && ( cbBuf != 0 ) )
    strcpy( pcBuf, pDomain->pszName );

  return TRUE;
}
