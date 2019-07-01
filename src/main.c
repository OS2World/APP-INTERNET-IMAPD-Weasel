#include <stdio.h> 
#include <signal.h>
#include <memory.h>
#include <ctype.h>
#define INCL_BASE
#define INCL_DOSSEMAPHORES
#define INCL_DOSDATETIME
#define INCL_DOSERRORS
#define INCL_DOSPROCESS
#include <os2.h>
#ifdef EXCEPTQ
#define INCL_LOADEXCEPTQ
#include "exceptq.h"
#endif
#include "utils.h"
#include "context.h"
#include "storage.h"
#include "imapfs.h"
#include "imap.h"
#include "pop3.h"
#include "storage.h"
#include "wcfg.h"
#include "piper.h"
#include "log.h"
#include "ctlpipe.h"
#include "debug.h"               // Should be last.

#ifndef VERSION
# define VERSION_STRING           ""
#else
# ifdef DEBUG_CODE
#  define VERSION_STRING           ", ver. "VERSION" (debug)"
# else
#  define VERSION_STRING           ", ver. "VERSION
# endif
#endif


#define _IMAP_DEFAULT_PORT       143
#define _IMAP_DEFAULT_SSLPORT    993
#define _POP3_DEFAULT_PORT       110
#define _POP3_DEFAULT_SSLPORT    995
#define _EVSEM_LIST              "SHUTDOWN UPDATED ROTATE QUOTASUPDATED"
#define _EVSEM_ID_SHUTDOWN       0
#define _EVSEM_ID_UPDATED        1
#define _EVSEM_ID_ROTATE         2
#define _EVSEM_ID_QUOTASUPDATED  3
#define _EVSEM_ID_NULL           (~0)
#define _CHECK_UPDATE_TIME       (15 * 1000)
#define _CHECK_QUPDATE_TIME      (16 * 1000)

#define _IMAPSRV_DEF_THREADS     4
#define _IMAPSRV_DEF_MAXTHREADS  16
#define _TLS_DEF_CERTIFICATE     "imapd.crt"
#define _TLS_DEF_PRIVATEKEY      "imapd.key"

#define _LOG_DEF_LEVEL           5
#define _LOG_DEF_HISTORYFILES    0
#define _LOG_DEF_MAXSIZE         0

// Protocol implementation handlers.
extern NSPROTO         stProtoCtrl;        // ctlproto.c
extern NSPROTO         stProtoPOP3;        // pop3.c
extern NSPROTO         stProtoIMAP;        // imap.c

PPIPER                 pWLogPiper     = NULL;

static int             iWLog          = (int)'Q';
static HMUX            hmuxSem        = NULLHANDLE;
static HTIMER          htmrRefresh    = NULLHANDLE;
static HTIMER          htmrQRefresh   = NULLHANDLE;
static HEV             hevShutdown;
static BOOL            fConnErrReported = FALSE;

static VOID _cbPREvent(PPIPER pPiper, ULONG ulCode, PSZ pszData)
{
  ULONG      cbData;

  switch( ulCode )
  {
    case PREVENT_CONNECTED:
      logf( 5, "Weasel log pipe %s is open", pszData );
      fConnErrReported = TRUE;
      return;

    case PREVENT_DISCONNECTED:
      logf( 5, "Weasel log pipe %s closed", pszData );
      return;

    case PREVENT_CONNECTERROR:
      if ( !fConnErrReported )
      {
        logf( 1, "Error connecting to the Weasel log pipe. "
                "Operation postponed." );
        fConnErrReported = TRUE;
      }
      return;

    case PREVENT_PIPECREATEERROR:
      logf( 0, "Error creating named pipe(s) %s", pszData );
      return;

    case PREVENT_INPUTLINE:
      break;

    default:
      debugCP( "WTF?!" );
      return;
  }

  if ( iWLog == (int)'S' )
    printf( "[Weasel] %s\n", pszData );

  cbData = strlen( pszData );

  if ( // SMTP log record?
       ( cbData > 32 ) && ( pszData[10] == ' ' ) &&
       ( *((PULONG)&pszData[19]) == 0x20205320 /* ' S  ' */ ) &&

       // File pathname (begins with 'D:\')?
       isalpha( pszData[29] ) && ( pszData[30] == ':' ) &&
       ( pszData[31] == '\\' ) &&

       // Ends with '.MSG'?
       ( *((PULONG)&pszData[cbData - 4]) == 0x47534D2E ) )
  {
    PSZ      pszFile = &pszData[29];
    ULONG    ulRC = fsNotifyChange( 0, pszFile );

    logf( 5, "Weasel SMTP log record caught for %s", pszFile );
    if ( ulRC < ARRAYSIZE(apszFSNotifyResults) )
      logf( 4, "Notify \"%s\": %s", pszFile, &apszFSNotifyResults[ulRC][1] );
  }
}

static void _signalStop(int iSignal) 
{
  ULONG      ulRC = DosPostEventSem( hevShutdown );

  logs( 2, "Break signal" );
  if ( ulRC != NO_ERROR )
    debug( "DosPostEventSem(), rc = %u", ulRC );
}

static HEV _createEvSem(PSZ pszName)
{
  HEV        hEv = NULLHANDLE;
  ULONG      ulRC;

  ulRC = DosCreateEventSem( pszName, &hEv, DC_SEM_SHARED, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateEventSem(%s,&hevShutdown,,), rc = %u",
           pszName == NULL ? (PSZ)"" : pszName, ulRC );
    if ( pszName != NULL )
      hEv = _createEvSem( NULL );
  }

  return hEv;
}

static ULONG _waitMuxWaitSem(HMUX hmuxSem, ULONG ulTimeout)
{
  ULONG      ulSemId;
  SEMRECORD  aSemRec[16];
  ULONG      cSemRec = ARRAYSIZE( aSemRec );
  ULONG      ulAttr;
  ULONG      ulRC = DosWaitMuxWaitSem( hmuxSem, ulTimeout, (PULONG)&ulSemId );

  if ( ulRC != NO_ERROR )
    return _EVSEM_ID_NULL;

  ulRC = DosQueryMuxWaitSem( hmuxSem, &cSemRec, aSemRec, &ulAttr );
  if ( ulRC != NO_ERROR )
    debug( "DosQueryMuxWaitSem(), rc = %u", ulRC );
  else if ( ulSemId != _EVSEM_ID_SHUTDOWN )
  {
    ulRC = DosResetEventSem( (HEV)aSemRec[ulSemId].hsemCur, &cSemRec );
    if ( ulRC != NO_ERROR )
      debug( "DosResetEventSem(), rc = %u", ulRC );
  }

  return ulSemId;
}

static VOID _appDone()
{
  debug( "prDone()..." );
  prDone( pWLogPiper );

  // Cancel current operations on IMAP file system to release threads.
  debug( "fsShutdown()..." );
  fsShutdown();

  debug( "netsrvDone()..." );
  netsrvDone();
  debug( "pop3Done()..." );
  pop3Done();
  debug( "imapDone()..." );
  imapDone();
  debug( "ctlpipeDone()..." );
  ctlpipeDone();
  debug( "msDone()..." );
  msDone();
  debug( "wcfgDone()..." );
  wcfgDone();

  debug( "Stop timers..." );

  if ( htmrRefresh != NULLHANDLE )
    DosStopTimer( htmrRefresh );

  if ( htmrQRefresh != NULLHANDLE )
    DosStopTimer( htmrQRefresh );

  if ( hmuxSem != NULLHANDLE )
  {
    SEMRECORD          aSemRec[16];
    ULONG              cSemRec = ARRAYSIZE( aSemRec );
    ULONG              ulRC, ulIdx;

    debug( "Destroy shared semaphores..." );

    ulRC = DosQueryMuxWaitSem( hmuxSem, &cSemRec, aSemRec, &ulIdx );
    if ( ulRC != NO_ERROR )
      debug( "DosQueryMuxWaitSem(), rc = %u", ulRC );
    else
    {
      for( ulIdx = 0; ulIdx < cSemRec; ulIdx++ )
      {
        ulRC = DosCloseEventSem( (HEV)aSemRec[ulIdx].hsemCur );
        if ( ulRC != NO_ERROR )
          debug( "#%u DosCloseEventSem(), rc = %u", ulIdx, ulRC );
      }
    }

    DosCloseMutexSem( hmuxSem );
  }

  debug( "logDone()..." );
  logDone();
#ifdef ICONV_CLEAN
  debug( "iconv_clean()..." );
  iconv_clean();
#endif
  debug( "debugDone()..." );
  debugDone();
}


// BOOL _appInit(int argc, char** argv)
// ------------------------------------

// Data to create servers with __createServ().
struct _SRVPARAM {
  ULONG              cBind;
  struct _SRVBIND {
    ULONG    ulAddr;
    USHORT   usPort;
    BOOL     fSSL;
  }                  aBind[16];
  CHAR               acTLSCert[CCHMAXPATH];
  CHAR               acTLSKey[CCHMAXPATH];
  NSCREATEDATA       stCreateData;         // Data for netsrvCreate().
};

static BOOL __createServ(PNSPROTO pProtocol, struct _SRVPARAM *pParam)
{
  ULONG      ulIdx;
  PSERVDATA  pServData;

  pParam->stCreateData.pszTLSCert = pParam->acTLSCert;
  pParam->stCreateData.pszTLSKey  = pParam->acTLSKey;

  pServData = netsrvCreate( pProtocol, &pParam->stCreateData );

  if ( (pParam->stCreateData.ulFlags & NSCRFL_TLS_CERTFAIL) != 0 )
    logf( 2, "%s Certificate loading failed", pProtocol->acLogId );
  if ( (pParam->stCreateData.ulFlags & NSCRFL_TLS_KEYFAIL) != 0 )
    logf( 2, "%s Private key loading failed", pProtocol->acLogId );
  if ( (pParam->stCreateData.ulFlags & (NSCRFL_TLS_INITFAIL |
                                        NSCRFL_TLS_CERTFAIL |
                                        NSCRFL_TLS_KEYFAIL)) ==
          NSCRFL_TLS_INITFAIL )
    logf( 1, "%s TLS initialization failed", pProtocol->acLogId );

  if ( pServData == NULL )
  {
    logf( 0, "%s Server initialization failed", pProtocol->acLogId );
    return FALSE;
  }

  for( ulIdx = 0; ulIdx < pParam->cBind; ulIdx++ )
  {
    logf( 3, "%s Bind to %s:%u%s",
          pProtocol->acLogId,
          inet_ntoa( *((struct in_addr *)&pParam->aBind[ulIdx].ulAddr) ),
          pParam->aBind[ulIdx].usPort,
          pParam->aBind[ulIdx].fSSL ? " (SSL)" : "" );

    if ( !netservBind( pServData, pParam->aBind[ulIdx].ulAddr,
                       pParam->aBind[ulIdx].usPort,
                       pParam->aBind[ulIdx].fSSL ) )
    {
      logf( 0, "%s Could not bind service to %s:%u%s",
            pProtocol->acLogId,
            inet_ntoa( *((struct in_addr *)&pParam->aBind[ulIdx].ulAddr) ),
            pParam->aBind[ulIdx].usPort,
            pParam->aBind[ulIdx].fSSL ? " (SSL)" : "" );
      break;
    }
  }

  if ( ulIdx != pParam->cBind )
  {
    // Could not bind to some address/port. Exit.
    netsrvDestroy( pServData );
    return FALSE;
  }

  return TRUE;
}

static PCHAR __addPipeName(PCHAR pcWeaselLogPipes, LONG cbName, PCHAR pcName)
{
  ULONG      cbWeaselLogPipes;
  PSZ        pszNew;

  if ( ( cbName != 0 ) && ( pcName != NULL ) )
  {
    cbWeaselLogPipes = pcWeaselLogPipes == NULL
                         ? 0 : ( strlen( pcWeaselLogPipes ) + 1 );

    if ( cbName < 0 )
      cbName = strlen( pcName );

    pszNew = realloc( pcWeaselLogPipes, cbWeaselLogPipes + cbName + 2 );

    if ( pszNew != NULL )
    {
      memcpy( &pszNew[cbWeaselLogPipes], pcName, cbName );
      cbWeaselLogPipes += cbName;
      pszNew[cbWeaselLogPipes++] = '\0';  // End of pipe name.
      pszNew[cbWeaselLogPipes]   = '\0';  // Double zero - end of list.

      pcWeaselLogPipes = pszNew;
    }
  }

  return pcWeaselLogPipes;
}

static BOOL _appInit(int argc, char** argv)
{
  static PSZ apszErrorMsg[] =
  { "Invalid switch",
    "Switch must have value",
    "Unknown switch",
    "Invalid bind address or port",
    "Invalid threads parameter",
    "Invalid logfile properties",
    "Invalid signal name",
    "Cannot find event semaphore. Is imapd runned?",
    "Event semaphore open/post error",
    "Invalid Weasel log pipe read mode" };

// Indexes for apszErrorMsg[].
#define _SWEM_INVALID            0
#define _SWEM_NO_VALUE           1
#define _SWEM_UNKNOWN            2
#define _SWEM_INVALID_BIND       3
#define _SWEM_INVALID_THREADS    4
#define _SWEM_INVALID_LOGPROP    5
#define _SWEM_INVALID_SEMNAME    6
#define _SWEM_SEM_NOT_FOUND      7
#define _SWEM_SEM_FAIL           8
#define _SWEM_INVALID_WLOG       9

                       // Data for __createServ()
  struct _SRVPARAM     stIMAPParam, stPOP3Param, *pParam;

  ULONG                ulIdx, ulRC;
  CHAR                 acWeaselPath[CCHMAXPATH] = ".";
  ULONG                ulSelectCfg = WC_AS_CONFIGURED;
  CHAR                 chSw;
  PSZ                  pszVal;
  LONG                 lErrorMsgId = -1;
  BOOL                 fPOP3 = FALSE;
  SEMRECORD            aSemRec[8];      // Should be enough for all semaphores.
  ULONG                cWLogServerPipes = 0;
  CHAR                 acWLogServerPipes[CCHMAXPATH];
  PCHAR                pcWLogPipes = NULL;

  debugInit();

  // Default logfile properties.
  ulGlLogLevel         = _LOG_DEF_LEVEL;
  ulGlLogHistoryFiles  = _LOG_DEF_HISTORYFILES;
  ullGlLogMaxSize      = _LOG_DEF_MAXSIZE;

  // Default IMAP server creation paramethers.
  stIMAPParam.stCreateData.ulFlags       = NSCRFL_TLS_INIT | NSCRFL_LOGGING;
  stIMAPParam.stCreateData.ulThreads     = _IMAPSRV_DEF_THREADS;
  stIMAPParam.stCreateData.ulMaxThreads  = _IMAPSRV_DEF_MAXTHREADS;
  stIMAPParam.stCreateData.pUser         = (PVOID)IMAPF_LOGINDISABLED;
  stIMAPParam.cBind = 0;
  strcpy( stIMAPParam.acTLSCert, _TLS_DEF_CERTIFICATE );
  strcpy( stIMAPParam.acTLSKey, _TLS_DEF_PRIVATEKEY );

  // Default POP3 server creation paramethers.
  stPOP3Param.stCreateData.ulFlags       = NSCRFL_TLS_INIT | NSCRFL_LOGGING;
  stPOP3Param.stCreateData.ulThreads     = _IMAPSRV_DEF_THREADS;
  stPOP3Param.stCreateData.ulMaxThreads  = _IMAPSRV_DEF_MAXTHREADS;
  stPOP3Param.stCreateData.pUser         = (PVOID)POP3_LOGINDISABLED;
  stPOP3Param.cBind = 0;
  strcpy( stPOP3Param.acTLSCert, _TLS_DEF_CERTIFICATE );
  strcpy( stPOP3Param.acTLSKey, _TLS_DEF_PRIVATEKEY );

  pParam = &stIMAPParam;

  pcWLogPipes = __addPipeName( NULL, -1, "WeaselTransLog" );

  // Read command line switches.

  do
  {
    argc--;
    if ( argc == 0 )
      // End of switch list.
      break;

    argv++;
    if ( ( (*argv)[0] != '-' ) || ( (*argv)[1] == '\0' ) )
    {
      // Switch does not begin with character '-' or has no character after '-'.
      lErrorMsgId = _SWEM_INVALID;
      chSw = ' ';
      break;
    }

    chSw = (*argv)[1]; // The switch character after '-'.

    if ( strchr( "bplswCKT", chSw ) != NULL )
    {
      // The switch must have value (like: "-a123" or "-a 123" ).

      pszVal = &(*argv)[2];
      if ( *pszVal == '\0' )
      {
        // Value in next argument (like: -a<SPACE>123).
        argc--;
        argv++;
        if ( argc == 0 )
        {
          lErrorMsgId = _SWEM_NO_VALUE;
          break;
        }

        pszVal = *argv;
        STR_SKIP_SPACES( pszVal );
        if ( *pszVal == '\0' )
        {
          lErrorMsgId = _SWEM_NO_VALUE;
          break;
        }
      }
    }
    else
      pszVal = NULL;

    // Now, we have: chSw - switch character, pszVal/cbVal - switch value.

    switch( chSw )
    {
      case '?':
      case 'h':
        printf( "IMAP4 server for the Weasel mail server"VERSION_STRING"\n\n"
          "Usage: IMAPD.EXE [-b [ssl,]<address[:port]>] [-p <path>] [-t|-i]\n"
          "                 [-l level,[N[,size]]] [-w Off|Quiet|Screen] [-e] [-C <file>]\n"
          "                 [-K <file>] [-T n[,max]] [-P]\n"
          "Where:\n"
          "  -b  Bind specified address and port to an IMAP4 server. For example:\n"
          "        192.168.1.1   - listen on the specified address and default port %u\n"
          "        *:1143        - listen on all addresses and port 1143.\n"
          "        ssl           - SSL connections on all addresses and default port %u.\n"
          "        ssl,any:1993  - SSL connections on all addresses and port 1993.\n"
          "      You can specify the switch -b multiple times.\n"
          "      By default, the configured value will be used.\n"
          "  -p  Path to the Weasel directory.\n"
          "      Default is current directory.\n"
          "  -t  Read configuration data from WEASEL.TNI (ignore the default rules).\n"
          "  -i  Read configuration data from WEASEL.INI (ignore the default rules).\n"
          "  -l  Logfile properties: \"level[,N[,size]]\", where:\n"
          "        level          - Minimal lightweight logging (0..6).\n"
          "        N              - Number of logfile rotations to make, 0 means no\n"
          "                         rotations. When size is 0 or omitted it means how many\n"
          "                         days to keep history logfiles.\n"
          "        size[Kb/Mb/Gb] - Maximum size of the logfile. If 0 is specified and\n"
          "                         N is not 0 then files will be renamed every day.\n"
          "      Default is \"%u,%u,%u\".\n"
          "  -s  Send signal to the runned IMAPD and exit.\n"
          "      Signals: "_EVSEM_LIST"\n"
          "  -w  <O|Q|S>[[,N,ServerPipe]:AlternativePipe1 ... :AlternativePipeN]\n"
          "      Read Weasel detailed log from pipe to fast-tracking incoming messages.\n"
          "        (O)ff    - Do not connect to the pipe (do not receive log).\n"
          "        (Q)uiet  - Connect to the pipe.\n"
          "        (S)creen - Connect to the pipe and print all output to the screen.\n"
          "        N,serverPipe - Number and name of new pipes for redirecting Weasel log.\n"
          "        AlternativePipe - Names of alternative pipes for reading Weasel log.\n"
          "      Note: prefix \\PIPE\\ adopted in OS/2 in pipe names may be omitted.\n"
          "      Default is Q (quiet).\n"
          "  -e  Allow plain-text authentication on unencrypted connections.\n"
          "  -C  Certificate file.\n"
          "      Default is "_TLS_DEF_CERTIFICATE".\n"
          "  -K  Private key file.\n"
          "      Default is "_TLS_DEF_PRIVATEKEY".\n"
          "  -T  Normal and maximum number of threads to process requests.\n"
          "      Default is \"%u,%u\".\n"
          "  -P  Start POP3 server. The following parameters b,e,C,K,T will applied to\n"
          "      POP3 server.\n",
          _IMAP_DEFAULT_PORT, _IMAP_DEFAULT_SSLPORT,
          _LOG_DEF_LEVEL, _LOG_DEF_HISTORYFILES, _LOG_DEF_MAXSIZE,
          _IMAPSRV_DEF_THREADS, _IMAPSRV_DEF_MAXTHREADS
        );
        return FALSE;

      case 'b':        // "-b [ssl,][<ip-address|any|all|*>:]port"
        if ( pParam->cBind == ARRAYSIZE(pParam->aBind) )
          break;

        if ( memicmp( pszVal, "ssl", 3 ) == 0 )
        {
          pszVal += 3;
          STR_SKIP_SPACES( pszVal );

          pParam->aBind[pParam->cBind].fSSL = TRUE;
          pParam->aBind[pParam->cBind].usPort =
                         fPOP3 ? _POP3_DEFAULT_SSLPORT : _IMAP_DEFAULT_SSLPORT;
          if ( *pszVal == '\0' )
          {
            pParam->aBind[pParam->cBind].ulAddr = 0;
            pParam->cBind++;
            break;
          }

          if ( *pszVal != ',' )
          {
            lErrorMsgId = _SWEM_INVALID_BIND;
            break;
          }
          pszVal++;
          STR_SKIP_SPACES( pszVal );
        }
        else
        {
          pParam->aBind[pParam->cBind].fSSL = FALSE;
          pParam->aBind[pParam->cBind].usPort =
                               fPOP3 ? _POP3_DEFAULT_PORT : _IMAP_DEFAULT_PORT;
        }

        if ( !utilStrToInAddrPort( pszVal,
                                   &pParam->aBind[pParam->cBind].ulAddr,
                                   &pParam->aBind[pParam->cBind].usPort, TRUE,
                                   pParam->aBind[pParam->cBind].usPort ) )
          lErrorMsgId = _SWEM_INVALID_BIND;
        else
          pParam->cBind++;
        break;

      case 'p':
        strlcpy( acWeaselPath, pszVal, sizeof(acWeaselPath) );
        break;

      case 't':
        ulSelectCfg = WC_STRICTLY_TNI;
        break;

      case 'i':
        ulSelectCfg = WC_STRICTLY_INI;
        break;

      case 'l':
        // level[,files[,size]]

        ulGlLogLevel = strtoul( pszVal, (PCHAR *)&pszVal, 10 );
        STR_SKIP_SPACES( pszVal );
        if ( *pszVal == ',' )
        {
          ulGlLogHistoryFiles = strtoul( pszVal + 1, (PCHAR *)&pszVal, 10 );
          if ( ulGlLogHistoryFiles > 999 )
          {
            lErrorMsgId = _SWEM_INVALID_LOGPROP;
            break;
          }

          STR_SKIP_SPACES( pszVal );
          if ( ( *pszVal == ',' ) &&
               !utilStrToBytes( pszVal + 1, &ullGlLogMaxSize, UTIL_KB ) )
          {
            lErrorMsgId = _SWEM_INVALID_LOGPROP;
            break;
          }
        }

        break;

      case 's':
        if ( utilStrWordIndex( _EVSEM_LIST, -1, pszVal ) == -1 )
          lErrorMsgId = _SWEM_INVALID_SEMNAME;
        else
        {
          HEV          hevSignal = NULLHANDLE;

          sprintf( acWeaselPath, "\\SEM32\\IMAPD\\%s", pszVal );

          ulRC = DosOpenEventSem( acWeaselPath, &hevSignal );
#ifdef DEBUG_CODE
          if ( ulRC != NO_ERROR )
            printf( "DosOpenEventSem(), rc = %lu\n", ulRC );
#endif

          switch( ulRC )
          {
            case ERROR_SEM_NOT_FOUND:
              lErrorMsgId = _SWEM_SEM_NOT_FOUND;
              break;

            case NO_ERROR:
              ulRC = DosPostEventSem( hevSignal );
#ifdef DEBUG_CODE
              if ( ulRC != NO_ERROR )
                printf( "DosPostEventSem(), rc = %lu\n", ulRC );
#endif
              if ( ulRC == NO_ERROR || ulRC == ERROR_ALREADY_POSTED )
              {
                puts( "The signal has been sent." );
                DosCloseEventSem( hevSignal );
                return FALSE;
              }

            default:
              lErrorMsgId = _SWEM_SEM_FAIL;
              break;
          }

          DosCloseEventSem( hevSignal );
        }

        break;

      case 'w':
      {
        // SCREEN[,2,IMAPDlogPipe[:weaselLog_sf:...]]
        PCHAR          pcSep = strchr( (PCHAR)pszVal, ',' );
        PCHAR          pcName;
        ULONG          cbName;

        if ( utilStrWordIndex( "OFF O QUIET Q SCREEN S",
                               pcSep == NULL ? -1 : ( pcSep - (PCHAR)pszVal ),
                               (PCHAR)pszVal ) == -1 )
        {
          lErrorMsgId = _SWEM_INVALID_WLOG;
          break;
        }
        iWLog = toupper( pszVal[0] );

        if ( pcSep == NULL )
          break;

        cWLogServerPipes = strtoul( pcSep + 1, (PCHAR *)&pcSep, 10 );
        if ( *pcSep != ',' )
        {
          lErrorMsgId = _SWEM_INVALID_WLOG;
          break;
        }

        pszVal = pcSep + 1;
        pcSep = strchr( (PCHAR)pszVal, ':' );
        cbName = pcSep != NULL ? (pcSep - (PCHAR)pszVal)
                               : strlen( (PCHAR)pszVal );
        if ( cbName >= sizeof(acWLogServerPipes) )
        {
          lErrorMsgId = _SWEM_INVALID_WLOG;
          break;
        }
        memcpy( acWLogServerPipes, pszVal, cbName );
        acWLogServerPipes[cbName] = '\0';

        while( pcSep != NULL )
        {
          pcName = &pcSep[1];
          pcSep = strchr( pcName, ':' );
          pcWLogPipes = __addPipeName( pcWLogPipes,
                                       pcSep == NULL ? -1 : ( pcSep - pcName ),
                                       pcName );
        }

        break;
      }

      case 'e':
        pParam->stCreateData.pUser =
           (PVOID)( (ULONG)pParam->stCreateData.pUser & ~IMAPF_LOGINDISABLED );
//        stIMAPSrvCreateData.ulFlags |= NSCRFL_TLS_REQUIRED;
        break;

      case 'C':
        strlcpy( pParam->acTLSCert, pszVal, sizeof(pParam->acTLSCert) );
        break;

      case 'K':
        strlcpy( pParam->acTLSKey, pszVal, sizeof(pParam->acTLSKey) );
        break;

      case 'T':
        // n[,max]

        pParam->stCreateData.ulThreads = strtoul( pszVal, (PCHAR *)&pszVal, 10 );
        STR_SKIP_SPACES( pszVal );
        if ( *pszVal == '\0' )
          pParam->stCreateData.ulMaxThreads = pParam->stCreateData.ulThreads;
        else if ( *pszVal == ',' )
        {
          pszVal++;
          pParam->stCreateData.ulMaxThreads =
            strtoul( pszVal, (PCHAR *)&pszVal, 10 );
          STR_SKIP_SPACES( pszVal );
        }

        if ( ( *pszVal != '\0' ) || ( pParam->stCreateData.ulThreads == 0 ) ||
             ( pParam->stCreateData.ulThreads >
                 pParam->stCreateData.ulMaxThreads ) )
          lErrorMsgId = _SWEM_INVALID_THREADS;
        break;

      case 'P':
        fPOP3 = TRUE;
        pParam = &stPOP3Param;
        break;

      default:
        lErrorMsgId = _SWEM_UNKNOWN;

    } // switch( chSw )
  }
  while( lErrorMsgId == -1 );

  if ( lErrorMsgId != -1 )
  {
    printf( "%s (-%c).", apszErrorMsg[lErrorMsgId], chSw );
    free( pcWLogPipes );
    return FALSE;
  }

  // Create event semaphores and multiple wait (muxwait) semaphore.

  {
    ULONG    cbSem, cbList = strlen( _EVSEM_LIST );
    PCHAR    pcSem, pcList = _EVSEM_LIST;
    CHAR     acName[CCHMAXPATH];
    ULONG    ulNamePos =  sprintf( acName, "\\SEM32\\IMAPD\\" );
    
    for( ulIdx = 0;
         ( ulIdx < ARRAYSIZE(aSemRec) ) &&
         utilBufCutWord( &cbList, &pcList, &cbSem, &pcSem );
         ulIdx++ )
    {
      memcpy( &acName[ulNamePos], pcSem, cbSem );
      acName[ulNamePos + cbSem] = '\0';

      aSemRec[ulIdx].hsemCur  = (HSEM)_createEvSem( acName );
      if ( aSemRec[ulIdx].hsemCur == NULLHANDLE )
      {
        logf( 0, "Could not create an event semaphore: %s", acName );
        break;
      }
      aSemRec[ulIdx].ulUser = ulIdx;
    }

    if ( cbList == 0 )
    {
      ulRC = DosCreateMuxWaitSem( NULL, &hmuxSem, ulIdx, aSemRec,
                                  DCMW_WAIT_ANY );
      if ( ulRC != NO_ERROR )
      {
        debug( "DosCreateMuxWaitSem(), rc = %u", ulRC );
        hmuxSem = NULLHANDLE;
      }
      hevShutdown = (HEV)aSemRec[_EVSEM_ID_SHUTDOWN].hsemCur;
    }
  }

  // Initialize modules, start servers.
  if ( ( hmuxSem == NULLHANDLE ) || !netsrvInit() || !imapInit() ||
       !pop3Init() || !logInit() || !msInit() )
    logs( 0, "Initialization failed. Exit." );
  else if ( !wcfgInit( acWeaselPath, ulSelectCfg ) )
    logs( 0, "Could not load Weasel configuration file. Exit." );
  else
  {
    debugCP( "Create servers..." );

    if ( stIMAPParam.cBind == 0 )
    {
      // No bindings for IMAP are specified.
      // Bind imap4 server to the configured port at any address.
      stIMAPParam.aBind[0].ulAddr = 0;
      stIMAPParam.aBind[0].usPort = ulGlWCfgIMAPBindPort == 0
                                  ? _IMAP_DEFAULT_PORT : ulGlWCfgIMAPBindPort;
      stIMAPParam.aBind[0].fSSL   = FALSE;
      stIMAPParam.cBind = 1;
    }

    if ( fPOP3 )
    {
      if ( fGlWCfgPOP3Enabled )
        logs( 3, "Please disable POP3 in the Weasel setup" );

      if ( stPOP3Param.cBind == 0 )
      {
        // No bindings for POP3 are specified.
        // Bind pop3 server to the configured port at any address.
        stPOP3Param.aBind[0].ulAddr = 0;
        stPOP3Param.aBind[0].usPort = ulGlWCfgPOP3BindPort == 0
                                  ? _POP3_DEFAULT_PORT : ulGlWCfgPOP3BindPort;
        stPOP3Param.aBind[0].fSSL   = FALSE;
        stPOP3Param.cBind = 1;
      }
    }

    if ( __createServ( &stProtoIMAP, &stIMAPParam ) &&
         ( !fPOP3 || __createServ( &stProtoPOP3, &stPOP3Param ) ) )
    {
      // Now we create a server for management through a local named socket.
      NSCREATEDATA       stSrvCreateData;
      PSERVDATA          pServData;

#ifdef DEBUG_CODE
      stSrvCreateData.ulFlags      = NSCRFL_LOGGING;
#else
      stSrvCreateData.ulFlags      = 0;
#endif
      stSrvCreateData.ulThreads    = 2;
      stSrvCreateData.ulMaxThreads = 4;
      stSrvCreateData.pszTLSCert   = NULL;
      stSrvCreateData.pszTLSKey    = NULL;
      stSrvCreateData.pUser        = (PVOID)0;
      pServData = netsrvCreate( &stProtoCtrl, &stSrvCreateData );

      if ( ( pServData != NULL ) && !netservBindName( pServData, "imapd" ) )
      {
        logs( 0, "Could not bind local management service. "
              "Is IMAPD already runned?" );
        netsrvDestroy( pServData );
      }

      if ( !ctlpipeInit( "imapd", 3 ) )
      {
        logs( 0, "Failed to create a pipe for the local management service." );
      }

      // Start weasel log pipe reader.

      if ( iWLog != 'O' )        // Weasel log is not OFF.
      {
        PRINIT     stInit;
        PSZ        pszErr;

        stInit.pcPipes = pcWLogPipes;
        stInit.ulReconnectPeriod = 10000;
        stInit.pszServerPipe = (PSZ)acWLogServerPipes;
        stInit.cServerPipes = cWLogServerPipes;
        stInit.fnUser = _cbPREvent;
        stInit.ulWriteBufSize = 1024;
        stInit.ulReadBufSize = 1024;
        stInit.hevInputPipe = NULLHANDLE;
        stInit.ulInputPipeKey = 0;

        ulRC = prInit( &pWLogPiper, &stInit );
        if ( ulRC != PRRC_OK )
        {
          debug( "prInit() failed, rc = %lu", ulRC );

          switch( ulRC )
          {
            case PRRC_INVALIDPIPENAME:
              pszErr = "invalid alternative pipe name";
              break;

            case PRRC_NOTENOUGHMENORY:
              pszErr = "not enough memory";
              break;

            case PRRC_SRVPIPECREATEERR:
              pszErr = "failed to create Weasel log server pipe";
              break;

            case PRRC_INVALIDSRVPIPENAME:
              pszErr = "invalid Weasel log server pipe name";
              break;

            case PRRC_NAMECOLLISION:
              pszErr = "same names for Weasel log pipe listening and server pipe";
              break;

            default:
              pszErr = "";
          }

          logf( 0, "Error creating Weasel log pipe: %s", pszErr );
        }
      }  // if ( iWLog != 'O' )

      // Run timer to check Weasel configuration changes.

      ulRC = DosStartTimer( _CHECK_UPDATE_TIME,
                            aSemRec[_EVSEM_ID_UPDATED].hsemCur, &htmrRefresh );
      if ( ulRC != NO_ERROR )
        debug( "DosStartTimer(), rc = %u", ulRC );

      // Run timer to check quotas configuration changes.

      ulRC = DosStartTimer( _CHECK_QUPDATE_TIME,
                            aSemRec[_EVSEM_ID_QUOTASUPDATED].hsemCur,
                            &htmrQRefresh );
      if ( ulRC != NO_ERROR )
        debug( "DosStartTimer(), rc = %u", ulRC );

      // Ok. We are ready.
      free( pcWLogPipes );
      return TRUE;
    }
  }

  free( pcWLogPipes );
  _appDone();

  return FALSE;
}

static VOID APIENTRY _appOnExit(ULONG ulCode)
{
  static BOOL          fPanic = FALSE;

  if ( !fPanic )
  {
    fPanic = TRUE;
    debugCP( "Panic! Shutdown IMAP virtual file system." );
    fsDone();
    msDone();
  }

  DosExitList( EXLST_EXIT, (PFNEXITLIST)NULL );
}


int main(int argc, char** argv)
{
  ULONG              ulSemId;
#ifdef EXCEPTQ
  EXCEPTIONREGISTRATIONRECORD  exRegRec;

  LoadExceptq( &exRegRec, "I", "imapd" );
#endif

  if ( !_appInit( argc, argv ) )
  {
#ifdef EXCEPTQ
    UninstallExceptq( &exRegRec );
#endif
    return 1;
  }

  signal( SIGINT, _signalStop );
  signal( SIGBREAK, _signalStop );

  if ( DosExitList( EXLST_ADD, (PFNEXITLIST)_appOnExit ) != NO_ERROR )
    debugCP( "DosExitList(EXLST_ADD,) failed" );

  logs( 1, "Start" );
  debug( "----- Start -----" );

  while( (ulSemId = _waitMuxWaitSem( hmuxSem, SEM_IMMEDIATE_RETURN )) !=
         _EVSEM_ID_SHUTDOWN )
  {
    switch( ulSemId )
    {
      case _EVSEM_ID_UPDATED:
        // Timer event to reload Weasel configuration if it was changed.
        wcfgUpdate( FALSE );
        break;

      case _EVSEM_ID_ROTATE:
        // Logfiles rotation signal.
        logRotation();
        break;

      case _EVSEM_ID_QUOTASUPDATED:
        // Timer event to reload quotas configuration if it was changed.
        msUpdateQuotas();
        break;
    }

    if ( !netsrvProcess( 1 ) )
      break;

    prProcess( pWLogPiper, FALSE );        // Read Weasel log pipe.
  }

  logs( 4, "Shutdown" );
  _appDone();
  logs( 0, "Exit" );

  if ( DosExitList( EXLST_REMOVE, (PFNEXITLIST)_appOnExit ) != NO_ERROR )
    debugCP( "DosExitList(EXLST_REMOVE,) failed" );

#ifdef EXCEPTQ
  UninstallExceptq( &exRegRec );
#endif
  return 0;
}
