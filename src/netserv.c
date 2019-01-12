/*
  TCP/IP network generic server.
*/

#include <conio.h> 
#include <stdlib.h>
#include <memory.h>
#include <types.h>
#include <ctype.h>
#include <arpa\inet.h>
#include <netdb.h>
#include <sys\socket.h>
#include <sys\time.h>
#include <sys\ioctl.h>
#include <sys\un.h>
#include <net\route.h>
#include <net\if.h>
#include <net\if_arp.h>
#include <nerrno.h>
#include <unistd.h>
#define INCL_BASE
#define INCL_DOSPROCESS
#define INCL_DOSFILEMGR
#define INCL_DOSMISC
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <os2.h>
#ifdef EXCEPTQ
#include "exceptq.h"
#endif
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "linkseq.h"
#include "log.h"
#include "hmem.h"
#include "netserv.h"
#include "debug.h"               // Should be last.

// Defined in main.c with '#include "exceptq.h"'.
BOOL LoadExceptq(EXCEPTIONREGISTRATIONRECORD* pExRegRec, const char* pOpts,
                 const char* pInfo);

#ifdef DEBUG_CODE
#define DEBUG_NETRX
#define DEBUG_NETTX
#endif


// Line-input mode values.

// Minimum buffer free space.
#define _INBUFMINSPACE             16
// Input buffer will be expanded by _INBUFDELTA bytes every time the free space
// is reduced to _INBUFMINSPACE or less.
// _INBUFDELTA must be greater than _INBUFMINSPACE.
#define _INBUFDELTA                64
// Connection will be closed when input buffer expanded to _INBUFMAXLINELENGTH
// and no end-of-line character is received.
#define _INBUFMAXLINELENGTH      8192

// _SRVFL_STOP - stop signal for all threads (shutdown).
#define _SRVFL_STOP              0x00010000
// _SRVFL_LOGGING - logging on server allowed.
#define _SRVFL_LOGGING           0x00020000
// _SRVFL_NEXTCLNTLOGIDMASK - Id mask for logging next client.
#define _SRVFL_NEXTCLNTLOGIDMASK 0x0000FFFF

#define _CLNTFL_WRITEFILTEROFF   0x00010000
#define _CLNTFL_TLSMODE          0x00020000
#define _CLNTFL_DELAYSEND        0x00040000
#define _CLNTFL_SSLACCEPTWRITE   0x01000000
#define _CLNTFL_SSLACCEPTREAD    0x02000000
#define _CLNTFL_SSLACCEPTINIT    0x04000000
#define _CLNTFL_PROTOINITIALIZED 0x08000000
#define _CLNTFL_LOGIDMASK        0x0000FFFF
#define _CLNTFL_SSLFLAGS         (_CLNTFL_SSLACCEPTINIT | _CLNTFL_SSLACCEPTWRITE | \
                                  _CLNTFL_SSLACCEPTREAD)

typedef struct _TXDATA {
  ULONG      cbBuf;
  CHAR       acBuf[1];
} TXDATA, *PTXDATA;

typedef struct _CLNTDATA {
  SEQOBJ     stSeqObj;

  PSERVDATA  pServData;
  int        iSock;
  ULONG      ulFlags;            // _CLNTFL_xxxxx

  PCHAR      pcRXData;           // Buffer for line input mode.
  ULONG      cbRXData;           // Bytes stored in pcRXData.
  ULONG      ulRXDataMax;        // Allocated space for pcRXData.
  ULONG      ulMaxRawBlock;      // Not 0 for raw input mode.
  union {                        // ulSend used when _CLNTFL_DELAYSEND is set:
    ULONG      ulLastAct;        //   Timestamp of last client's activity.
    ULONG      ulSend;           //   Delay send (future) timestamp.
  } _cltime;

  PCTX       pCtx;               // Output data.
  PTXDATA    pTXData;            // Buffer to copy data from pCtx to socket.

  SSL        *pSSL;

  CHAR       acProtoData[1];     // Protocol relaited data.
} CLNTDATA;

typedef struct _SERVDATA {
  SEQOBJ     stSeqObj;

  ULONG      cSock;
  int        *paiSock;           // Listen sockets (high memory pointer).
  ULONG      ulFirstNonSSLSock;  // Index in paiSock of the first socket for
                                 // non-SSL connections.

  LINKSEQ    lsClients;          // List of CLNTDATA objects.
  LINKSEQ    lsPendClients;
  HMTX       hmtxClients;        // Locking lists lsClients and lsPendClients.
  HEV        hevPendClients;

  ULONG      ulFlags;            // _SRVFL_xxxxx
  ULONG      ulKeepThreads;
  ULONG      ulMaxThreads;
  ULONG      cThreads;
  ULONG      cThreadsBusy;

  SSL_CTX    *pSSLCtx;

  PVOID      pUser;              // User data (NSCREATEDATA.pUser).
  PNSPROTO   pProtocol;

  ULONG      cSelWriteSock;      // | Used in netsrvProcess().
  ULONG      cSelReadSock;       // |
} SERVDATA;


static LINKSEQ         lsServers;          // List of all created servers.

static ULONG           ulSelSockMax = 0;
static int             *paiSelSock = NULL;

#define _srvClientSetActTime(_pclntdata) \
  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, \
                   &(_pclntdata)->_cltime.ulLastAct, sizeof(ULONG) )

#define _srvClientLog(_pclntdata,_level,_fmt,...) do {\
  if ( ((_pclntdata)->pServData->ulFlags & _SRVFL_LOGGING) != 0 ) \
    logf( _level, "%s %.4X "_fmt, _pclntdata->pServData->pProtocol->acLogId, \
    _pclntdata->ulFlags & _CLNTFL_LOGIDMASK, ##__VA_ARGS__ ); } while( FALSE )

static BOOL _srvBind(PSERVDATA pServData,
                     ULONG cbSockAddr, struct sockaddr *pSockAddr,
                     int iSock, int iQueueLen, BOOL fSSL)
{
  int                  *paiSock;

  if ( ( fSSL && !netsrvIsTLSAvailable( pServData ) ) ||
       ( bind( iSock, pSockAddr, cbSockAddr ) == -1 ) )
    return FALSE;

  if ( listen( iSock, iQueueLen ) < 0 )
  {
    debugCP( "listen() failed" );
    return FALSE;
  }

  // Add a new socket to the list of server sockets.

  paiSock = hrealloc( pServData->paiSock,
                      ( pServData->cSock + 1 ) * sizeof(int) );
  if ( paiSock == NULL )
    return FALSE;
  pServData->paiSock = paiSock;

  if ( !fSSL )
  {
    paiSock[pServData->cSock] = iSock;
    pServData->paiSock = paiSock;
  }
  else
  {
    memmove( &paiSock[1], paiSock, pServData->cSock * sizeof(int) );
    paiSock[0] = iSock;
    pServData->ulFirstNonSSLSock++;
  }

  pServData->cSock++;

  return TRUE;
}

static PCLNTDATA _srvClientNew(PSERVDATA pServData, int iClntSock, BOOL fSSL)
{
  PCLNTDATA  pClntData = hcalloc( 1, sizeof(CLNTDATA) - 1 +
                                     pServData->pProtocol->cbProtoData );
             // Get the client log-records id from the server's object flags.
  ULONG      ulSrvFlags = pServData->ulFlags;
  ULONG      ulLogId = ulSrvFlags & _SRVFL_NEXTCLNTLOGIDMASK;

  if ( pClntData == NULL )
    return NULL;

  pClntData->pServData = pServData;
  pClntData->iSock = iClntSock;
  // Set log-id for the client to client's flags.
  pClntData->ulFlags = ulLogId & _CLNTFL_LOGIDMASK;

  // Set log-id for the next client to server's flags.
  ulLogId++;
  pServData->ulFlags = (ulLogId & _SRVFL_NEXTCLNTLOGIDMASK) |
                       (ulSrvFlags & ~_SRVFL_NEXTCLNTLOGIDMASK);

  if ( fSSL )
    // We will call pProtocol->fnNew() for connections on server SSL-port when
    // SSL established.
    pClntData->ulFlags |= _CLNTFL_SSLACCEPTINIT;
  else
  {
    // Call protocol routine.
    if ( ( pServData->pProtocol->fnNew != NULL ) &&
         !pServData->pProtocol->fnNew( pClntData ) )
    {
      if ( pClntData->pCtx != NULL )
        ctxFree( pClntData->pCtx );
      hfree( pClntData );
      return NULL;
    }
    pClntData->ulFlags |= _CLNTFL_PROTOINITIALIZED;
  }

  _srvClientSetActTime( pClntData );

  IF_LOGLEVEL( 3 )
    if ( (pServData->ulFlags & _SRVFL_LOGGING) != 0 )
    {
      struct sockaddr_in   stAddr;
      int                  cbAddr = sizeof(struct sockaddr_in);
      CHAR                 acClient[16];
      CHAR                 acServer[32];

      bzero( &stAddr, sizeof(stAddr) );
      strcpy( acClient,
              getpeername( iClntSock, (struct sockaddr *)&stAddr,
                           &cbAddr ) == -1
                ? "?" : stAddr.sin_family == AF_UNIX ?
                          "local" : inet_ntoa( stAddr.sin_addr ) );

      if ( stAddr.sin_family == AF_UNIX )
        acServer[0] = '\0';
      else
      {
        cbAddr = sizeof(struct sockaddr_in);
        bzero( &stAddr, sizeof(stAddr) );
        if ( getsockname( iClntSock, (struct sockaddr *)&stAddr,
                          &cbAddr ) == -1 )
          acServer[0] = '\0';
        else
          sprintf( acServer, " on %s:%u", inet_ntoa( stAddr.sin_addr ),
                   ntohs( stAddr.sin_port ) );
      }

      logWriteFmt( 3, "%s %.4X New client [%s]%s%s",
                   pClntData->pServData->pProtocol->acLogId,
                   pClntData->ulFlags & _CLNTFL_LOGIDMASK, acClient, acServer,
                   fSSL ? " (SSL)" : "" );
    }
  END_IF_LOGLEVEL

  return pClntData;
}

static VOID _srvClientOutputClean(PCLNTDATA pClntData)
{
  if ( pClntData->pCtx != NULL )
  {
    ctxFree( pClntData->pCtx );
    pClntData->pCtx = NULL;
  }

  if ( pClntData->pTXData != NULL )
  {
    free( pClntData->pTXData );
    pClntData->pTXData = NULL;
  }
}

// VOID _srvClientDestroy(PCLNTDATA pClntData)
//
// Closes client socket and destroys client data. May be called from any thread.

static VOID _srvClientDestroy(PCLNTDATA pClntData)
{
  _srvClientLog( pClntData, 3, "End of session" );

  if ( ( (pClntData->ulFlags & _CLNTFL_PROTOINITIALIZED) != 0 ) &&
       ( pClntData->pServData->pProtocol->fnDestroy != NULL ) )
    pClntData->pServData->pProtocol->fnDestroy( pClntData );

  if ( pClntData->pSSL != NULL )
  {
//  SSL_shutdown() fails after _srvClientSockRecv(): SSL_read(), Error code: 6
//    SSL_shutdown( pClntData->pSSL );
    SSL_free( pClntData->pSSL );
  }
//  else
    shutdown( pClntData->iSock, 1 );

  soclose( pClntData->iSock );

  _srvClientOutputClean( pClntData );

  if ( pClntData->pcRXData != NULL )
    free( pClntData->pcRXData );

  hfree( pClntData );
}

static BOOL _srvClientSSLAccept(PCLNTDATA pClntData)
{
  int        iRC;

  if ( pClntData->pCtx != NULL )
  {
    // Start SSL accept only when all data will be sent.
    pClntData->ulFlags |= _CLNTFL_SSLACCEPTINIT;
    return TRUE;
  }

  pClntData->ulFlags &= ~_CLNTFL_SSLFLAGS;

  if ( pClntData->pSSL == NULL )
  {
    if ( pClntData->pServData->pSSLCtx == NULL )
    {
      debugCP( "Have no SSL context" );
      return FALSE;
    }

    pClntData->pSSL = SSL_new( pClntData->pServData->pSSLCtx );
    if ( pClntData->pSSL == NULL )
    {
      debugCP( "SSL_new() failed" );
      return FALSE;
    }

    SSL_set_fd( pClntData->pSSL, pClntData->iSock );
  }

  iRC = SSL_accept( pClntData->pSSL );

  if ( iRC > 0 )
  {
    // SSL connection established.

    _srvClientOutputClean( pClntData );
    pClntData->ulFlags |= _CLNTFL_TLSMODE;
    SSL_set_mode( pClntData->pSSL, SSL_MODE_ENABLE_PARTIAL_WRITE );
    _srvClientLog( pClntData, 4, "Secure connection is established" );

    if ( (pClntData->ulFlags & _CLNTFL_PROTOINITIALIZED) == 0 )
    {
      // Call protocol routine.
      if ( ( pClntData->pServData->pProtocol->fnNew != NULL ) &&
           !pClntData->pServData->pProtocol->fnNew( pClntData ) )
        return FALSE;
      pClntData->ulFlags |= _CLNTFL_PROTOINITIALIZED;
    }
  }
  else
  {
    int iErr = SSL_get_error( pClntData->pSSL, iRC );

    switch( iErr )
    {
      case SSL_ERROR_WANT_READ:
        pClntData->ulFlags |= _CLNTFL_SSLACCEPTREAD;
        iRC = 1;
        break;

      case SSL_ERROR_WANT_WRITE:
        pClntData->ulFlags |= _CLNTFL_SSLACCEPTWRITE;
        iRC = 1;
        break;

      default:
        {
//          CHAR       acBuf[128];

          debug( "SSL_accept(), Error code: %d", iRC );
/*          while( ( iErr = ERR_get_error() ) != 0 )
          {
            ERR_error_string_n( iErr, acBuf, sizeof(acBuf) );
            debug( "SSL_accept() failed, error: %s", &acBuf );
            debug( "Error is %s", ERR_reason_error_string( iErr ) );
          }*/
        }
        _srvClientLog( pClntData, 3, "TLS negotiation failed" );
        SSL_free( pClntData->pSSL );
        pClntData->pSSL = NULL;
    }

    ERR_clear_error();
  }

  return iRC > 0;
}

static LONG _srvClientSockSend(PCLNTDATA pClntData, ULONG cbBuf, PVOID pBuf)
{
  int iRC;

  if ( (pClntData->ulFlags & (_CLNTFL_SSLACCEPTREAD | _CLNTFL_SSLACCEPTWRITE))
         != 0 )
  {
    debug( "TLS negotiation in progress (flags: 0x%X)...",
           pClntData->ulFlags & ~_CLNTFL_LOGIDMASK );
    return 0;
  }

  if ( (pClntData->ulFlags & _CLNTFL_TLSMODE) == 0 )
  {
    iRC = send( pClntData->iSock, (PCHAR)pBuf, (int)cbBuf, 0 );
    if ( iRC == -1 )
    {
      int    iErr = sock_errno();

      if ( iErr != SOCEWOULDBLOCK )
        debug( "send() failed, error: %d", iErr );
      else
        iRC = 0;
    }
  }
  else
  {
    iRC = SSL_write( pClntData->pSSL, (PCHAR)pBuf, (int)cbBuf );
    if ( iRC < 0 )
    {
      int    iErr = SSL_get_error( pClntData->pSSL, iRC );

      switch( iErr )
      {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          iRC = 0;
          break;

        default:
          {
//            CHAR       acBuf[128];

            debug( "SSL_write(), Error code: %d", iErr );
/*            while( ( iErr = ERR_get_error() ) != 0 )
            {
              ERR_error_string_n( iErr, acBuf, sizeof(acBuf) );
              debug( "SSL_write() failed, error: %s", &acBuf );
              debug( "Error is %s", ERR_reason_error_string( iErr ) );
            }*/
          }
          iRC = -1;
      }

      ERR_clear_error();
    }
  }

#ifdef DEBUG_NETTX
  if ( iRC > 0 )
  {
    ULONG    ulIdx;
    CHAR     acOutput[1024];
    ULONG    cbOutput = 0;

    for( ulIdx = 0; ulIdx < iRC; ulIdx++ )
    {
      if ( ((PCHAR)pBuf)[ulIdx] != '\r' )
      {
        acOutput[cbOutput] = ((PCHAR)pBuf)[ulIdx];
        cbOutput++;
        if ( cbOutput == sizeof(acOutput) )
        {
          debugTextBuf( acOutput, cbOutput, FALSE );
          cbOutput = 0;
        }
      }
    }

    if ( cbOutput != 0 )
      debugTextBuf( acOutput, cbOutput, FALSE );
  }
#endif

  return iRC;
}

static LONG _srvClientSockRecv(PCLNTDATA pClntData, ULONG cbBuf, PVOID pBuf)
{
  int iRC;

  if ( (pClntData->ulFlags & (_CLNTFL_SSLACCEPTREAD | _CLNTFL_SSLACCEPTWRITE))
         != 0 )
  {
    debug( "TLS negotiation in progress (flags: 0x%X)...",
           pClntData->ulFlags & ~_CLNTFL_LOGIDMASK );
    return 0;
  }

  if ( (pClntData->ulFlags & _CLNTFL_TLSMODE) == 0 )
  {
    iRC = recv( pClntData->iSock, pBuf, cbBuf, 0 );

    if ( iRC <= 0 )
    {
      if ( iRC == 0 )
      {
        debug( "Connection %d closed by the client",
               pClntData->iSock );
        iRC = -1;
      }
      else
      {
        int  iErr = sock_errno();

        if ( iErr != SOCEWOULDBLOCK )
          debug( "recv() failed, error: %d", iErr );
        else
          iRC = 0;
      }
    }
  }
  else
  {
    iRC = SSL_read( pClntData->pSSL, (PCHAR)pBuf, (int)cbBuf );

    if ( iRC <= 0 )
    {
      int    iErr = SSL_get_error( pClntData->pSSL, iRC );

      switch( iErr )
      {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          iRC = 0;
          break;

        default:
          {
//            CHAR       acBuf[128];

            debug( "SSL_read(), Error code: %d", iErr );
/*            while( ( iErr = ERR_get_error() ) != 0 )
            {
              ERR_error_string_n( iErr, acBuf, sizeof(acBuf) );
              debug( "SSL_read() failed, error: %s", &acBuf );
              debug( "Error is %s", ERR_reason_error_string( iErr ) );
            }*/
          }
          iRC = -1;
      }

      ERR_clear_error();
    }
  }

  return iRC;
}

// BOOL _srvClientRead(PCLNTDATA pClntData)
//
// Reads data from the socket to the object's buffer.
// In line-input mode function splits the data into lines (LF-terminated
// strings), removes trailing SPACEs/TABs/CRs, adds zero and calls
// NSPROTO.fnRequest for each line. In raw-input mode NSPROTO.fnRequest will be
// called for each (up to CLNTDATA.ulMaxRawBlock bytes) chunk of data (see
// netsrvClntSetRawInput()).
// Returns _CLNTREAD_xxxxx code.

#define _CLNTREAD_OK             0
#define _CLNTREAD_CLOSE          1
#define _CLNTREAD_NODATA         2

static BOOL _srvClientRead(PCLNTDATA pClntData)
{
  LONG       lRC;
  PCHAR      pcRead;
  ULONG      cbRead;
  PCHAR      pcEndOfLine;
  ULONG      ulSpace, cbChunk, ulResize;

  // Send data from the input buffer to the protocol layer
  // -----------------------------------------------------

  while( TRUE )
  {
    // Call the protocol function for each line or chunk in the buffer.

    pcRead = pClntData->pcRXData;
    cbRead = pClntData->cbRXData;
    while( cbRead > 0 )
    {
      if ( pClntData->ulMaxRawBlock != 0 )
      {
        // RAW-input mode.

        cbChunk = MIN( pClntData->ulMaxRawBlock, cbRead );

#ifdef DEBUG_NETRX
        debug( "C %d RAW: %s", pClntData->iSock,
                               (PSZ)debugBufPSZ( pcRead, cbChunk ) );
        printf( "RAW -> %s\n", (PSZ)debugBufPSZ( pcRead, cbChunk ) );
#endif

        // Call protocol routine.
        if ( !pClntData->pServData->pProtocol->fnRequest( pClntData,
                                                          cbChunk, pcRead ) )
        {
          // Protocol function wants to close the connection.
          return FALSE;
        }

        if ( ( pClntData->pCtx != NULL ) &&
             ( ctxQuerySize( pClntData->pCtx ) == 0 ) )
        {
          ctxFree( pClntData->pCtx );
          pClntData->pCtx = NULL;
        }

        pcRead += cbChunk;
        cbRead -= cbChunk;
        if ( (pClntData->ulFlags & _CLNTFL_DELAYSEND) == 0 )
          _srvClientSetActTime( pClntData );

        if ( pClntData->ulMaxRawBlock == 0 )
        {
          // Input mode is switched to RAW-input. Move remaining data to the
          // beginning of the buffer.
          memcpy( pClntData->pcRXData, pcRead, cbRead );
          pcRead = pClntData->pcRXData;
        }
      }
      else
      {
        // Line-input mode.

        pcEndOfLine = memchr( pcRead, '\n', cbRead );
        if ( pcEndOfLine != NULL )
        {
          cbChunk = ( pcEndOfLine - pcRead ) + 1;

          // Remove trailing SPACEs, TABs, CRs.
          while( ( pcEndOfLine > pcRead ) && isspace( *(pcEndOfLine - 1) ) )
            pcEndOfLine--;
          *pcEndOfLine = '\0';

#ifdef DEBUG_NETRX
          debug( "C %d: %s", pClntData->iSock,
                             (PSZ)debugBufPSZ( pcRead, pcEndOfLine - pcRead ) );
#endif
          _srvClientLog( pClntData, 6, "< %s", pcRead );

          // Call protocol routine.
          if ( !pClntData->pServData->pProtocol->fnRequest( pClntData,
                                                 pcEndOfLine - pcRead, pcRead ) )
            // Protocol function wants to close the connection.
            return FALSE;

          pcRead += cbChunk;
          cbRead -= cbChunk;
          if ( (pClntData->ulFlags & _CLNTFL_DELAYSEND) == 0 )
            _srvClientSetActTime( pClntData );
        }
        else
        {
          // Move remaining data (part of next string) to the beginning of buffer.
          memcpy( pClntData->pcRXData, pcRead, cbRead );
          break;
        }
      }  // if ( pClntData->ulMaxRawBlock != 0 ) else
    }  // while( cbRead > 0 )

    pClntData->cbRXData = cbRead;


    // Read more data from the socket
    // ------------------------------

    // Left free scpace in buffer.
    ulSpace = pClntData->ulRXDataMax - cbRead;

    // Resize input buffer.

    if ( pClntData->ulMaxRawBlock != 0 )
    {
      // Minimum buffer size in RAW-input mode is pClntData->ulMaxRawBlock.
      ulResize = pClntData->ulRXDataMax < pClntData->ulMaxRawBlock ?
                   pClntData->ulMaxRawBlock : 0;
    }
    else if ( ulSpace <= _INBUFMINSPACE )
    {
      if ( pClntData->ulRXDataMax >= _INBUFMAXLINELENGTH )
      {
        _srvClientLog( pClntData, 3, "Client tries to send too long string" );
        debugCP( "Input line too long" );
        return FALSE;
      }

      ulResize = pClntData->ulRXDataMax + _INBUFDELTA;
    }
    else
      ulResize = 0;

    if ( ulResize != 0 )
    {
      PCHAR    pcNew = realloc( pClntData->pcRXData, ulResize );

      if ( pcNew == NULL )
      {
        debugCP( "Not enough memory" );
        return FALSE;
      }

      pClntData->pcRXData     = pcNew;
      pClntData->ulRXDataMax  = ulResize;
      ulSpace = ( ulResize - cbRead );
      //debug( "New input buffer size: %u bytes", ulResize );
    }

    lRC = _srvClientSockRecv( pClntData, ulSpace, &pClntData->pcRXData[cbRead] );

    if ( lRC < 0 )
    {
      // Socket read error.
      _srvClientLog( pClntData, 6, "Connection lost" );
      return FALSE;
    }

    if ( lRC == 0 )
      // No more data in the socket.
      break;

    pClntData->cbRXData += lRC;
  }  // while( TRUE )

  return TRUE;
}

// BOOL _srvClientSend(PSERVDATA pServData, PCLNTDATA pClntData)
//
// Sends the output data that has been saved in the context.
// We allocate buffer to transmit data from the CTX object to the socket each
// function call as long as _srvClientSockSend() does not return 0. If this
// occurs, it can mean that the SSL_write() has set the error code to
// SSL_ERROR_WANT_WRITE and should be called next time with same pointer to the
// buffer. To fulfill this requirement, we store the pointer in the pClntData
// object.
//
// [OpenSSL documentation]
//   When an SSL_write() operation has to be repeated because of
//   SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be repeated with the
//   same arguments.
//
// Returns FALSE on error.

static BOOL _srvClientSend(PSERVDATA pServData, PCLNTDATA pClntData)
{
  LONG       lRC;
  ULONG      ulActual;
  PTXDATA    pTXData;
  BOOL       fEOF;

  if ( ( pClntData->pCtx == NULL ) ||
       ( (pClntData->ulFlags & _CLNTFL_DELAYSEND) != 0 ) )
    return TRUE;

  // Get buffer to read the context.

  if ( pClntData->pTXData == NULL )
  {
    // Detect buffer size.
    ULONG    cbBuf;

    lRC = sizeof(cbBuf);
    if ( getsockopt( pClntData->iSock, SOL_SOCKET, SO_SNDBUF,
                     (char *)&cbBuf, (int *)&lRC ) == -1 )
    {
      debugCP( "getsockopt() failed" );
      cbBuf = (8 * 1024);
    }

    // Allocate output buffer.
    pTXData = malloc( sizeof(TXDATA) - 1 + cbBuf );
    if ( pTXData == NULL )
    {
      debugCP( "Not enough memory" );
      return FALSE;
    }

    pTXData->cbBuf = cbBuf;
  }
  else
  {
    // We have output buffer in the client's object, ok - use it.
    // The buffer was stored because previous _srvClientSockSend() returns 0.
    pTXData = pClntData->pTXData;
  }

  // Read data to the output buffer. Do not change context read pointer.
  ulActual = ctxRead( pClntData->pCtx, pTXData->cbBuf, pTXData->acBuf, TRUE );
  fEOF = ulActual < pTXData->cbBuf;

  if ( ulActual != 0 )
  {
    // Send buffered data over socket.
    lRC = _srvClientSockSend( pClntData, ulActual, pTXData->acBuf );
    if ( lRC == -1 )
      return FALSE;

    if ( lRC == 0 )
    {
      // The data can't be sent over socket right now. It may be case when
      // SSL_write() set the error code SSL_ERROR_WANT_WRITE and we should
      // call it next time with same pointer to the buffer.
      // Store pointer to the buffer in the client's object - it will be used
      // on next function call.
      pClntData->pTXData = pTXData;
    }
    else
    {
      // Move context read pointer forward on number of bytes sent.
      ctxRead( pClntData->pCtx, lRC, NULL, FALSE );
      pClntData->pTXData = NULL;
    }

    if ( lRC != ulActual )
      // Not all readed data was sent. Reset end-of-file flag.
      fEOF = FALSE;
  }

  if ( pClntData->pTXData == NULL )
    // Pointer to the output buffer was not stored in the client's object -
    // destroy it.
    free( pTXData );

  if ( fEOF )
    // All current output data has been sent. Destroy context object and
    // output buffer.
    _srvClientOutputClean( pClntData );

  return TRUE;
}

#if 0
// No good for speed.

// Called from ctxWrite() before storing data into context. The filter tries to
// send data immediately before writing to the context. So we use context only
// when the socket buffer is full.
static LONG cbCtxWriteFilter(ULONG cbBuf, PVOID pBuf, PVOID pData)
{
  PCLNTDATA  pClntData = (PCLNTDATA)pData;
  LONG       lRC;

  if ( (pClntData->ulFlags & (_CLNTFL_WRITEFILTEROFF | _CLNTFL_SSLFLAGS |
                              _CLNTFL_TLSMODE)) != 0 )
  /* Filter is OFF or TLS used.
     I think it's not safety to use context write filter with TLS: filter
     calls _srvClientSockSend() with different pointers to the output buffers
     and _srvClientSockSend() calls SSL_write() which should be called with
     same pointer repeatedly in the special case (OpenSSL documentation):
     "When an SSL_write() operation has to be repeated because of
     SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be repeated with the
     same arguments." */
    return 0;

  lRC = _srvClientSockSend( pClntData, cbBuf, pBuf );
  if ( lRC < cbBuf )
    pClntData->ulFlags |= _CLNTFL_WRITEFILTEROFF;

  return lRC;
}
#endif

static BOOL _srvClientHaveOutputData(PCLNTDATA pClntData)
{
  PNSPROTO   pProtocol;

  if ( (pClntData->ulFlags & _CLNTFL_DELAYSEND) != 0 )
    return FALSE;

  pProtocol = pClntData->pServData->pProtocol;

  if ( pProtocol->fnReadyToSend != NULL )
    pProtocol->fnReadyToSend( pClntData );

  return pClntData->pCtx != NULL;
}


/* *************************************************************** */

static VOID threadClient(void *pData)
{
  PSERVDATA  pServData = (PSERVDATA)pData;
  PCLNTDATA  pClntData;
  ULONG      ulRC, ulWaitEvRC;
#ifdef EXCEPTQ
  EXCEPTIONREGISTRATIONRECORD    exRegRec;

  LoadExceptq( &exRegRec, NULL, NULL );
#endif

  ulRC = DosRequestMutexSem( pServData->hmtxClients, SEM_INDEFINITE_WAIT );
  if ( ulRC != NO_ERROR )
  {
    debug( "#%u DosRequestMutexSem(), rc = %u", __LINE__, ulRC );
#ifdef EXCEPTQ
    UninstallExceptq( &exRegRec );
#endif
    _endthread();
    return;
  }
  pServData->cThreads++;

  while( TRUE )
  {
    // Get next pending client (wait for).

    pClntData = NULL;

    while( (pServData->ulFlags & _SRVFL_STOP) == 0 )
    {
      // Extract an object from the "pending" list.

      pClntData = (PCLNTDATA)lnkseqGetFirst( &pServData->lsPendClients );
      if ( pClntData != NULL )
      {
        lnkseqRemove( &pServData->lsPendClients, pClntData );
        // Increase the counter of busy threads.
        pServData->cThreadsBusy++;
        // The object was extracted.
        break;
      }

      // The object was not extracted. Waiting for the next signal.

      DosReleaseMutexSem( pServData->hmtxClients );

      ulWaitEvRC = DosWaitEventSem( pServData->hevPendClients, 2000 );

      ulRC = DosRequestMutexSem( pServData->hmtxClients, SEM_INDEFINITE_WAIT );
      if ( ulRC != NO_ERROR )
      {
        debug( "#%u DosRequestMutexSem(), rc = %u", __LINE__, ulRC );
        break;
      }

      if ( ulWaitEvRC == ERROR_TIMEOUT )
      {
        // Timeout. Check the number of threads.

        if ( pServData->cThreads > pServData->ulKeepThreads )
        {
          debug( "Too many threads (%u) - exit", pServData->cThreads );
          if ( (pServData->ulFlags & _SRVFL_LOGGING) != 0 )
            logs( 4, "Finish the additional thread" );

          break;
        }
      }
      else if ( ulWaitEvRC != NO_ERROR )
      {
        debug( "DosWaitEventSem(), rc = %u", ulRC );
        break;
      }
    }  // while( (pServData->ulFlags & _SRVFL_STOP) == 0 )

    if ( pClntData == NULL )
      // Client is not obtained - error or stop signal. Leave the thread.
      break;

    DosReleaseMutexSem( pServData->hmtxClients );

    // Read input data and call the protocol implementation function.
    if ( !_srvClientRead( pClntData ) ||
         !_srvClientSend( pServData, pClntData ) )
    {
      // Connection lost, session finished or some error occurred.
      // Destroy client object.
      _srvClientDestroy( pClntData );
      pClntData = NULL;
    }

    // Return alive client object to main server client list to wait next event
    // on socket. Decrease the counter of busy threads.

    ulRC = DosRequestMutexSem( pServData->hmtxClients, SEM_INDEFINITE_WAIT );
    if ( ulRC != NO_ERROR )
    {
      debug( "#%u DosRequestMutexSem(), rc = %u", __LINE__, ulRC );
      if ( pClntData != NULL )
        _srvClientDestroy( pClntData );
      break;
    }

    pServData->cThreadsBusy--;

    if ( pClntData != NULL )
      // Return client object to the main client list.
      lnkseqAdd( &pServData->lsClients, pClntData );

  }  // while( TRUE )

  pServData->cThreads--;
  DosReleaseMutexSem( pServData->hmtxClients );

#ifdef EXCEPTQ
  UninstallExceptq( &exRegRec );
#endif
  _endthread();
} 


/* *************************************************************** */
/*                                                                 */
/*                        Protocol helpers                         */
/*                                                                 */
/* *************************************************************** */

BOOL netsrvClntGetStopFlag(PCLNTDATA pClntData)
{
  return (pClntData->pServData->ulFlags & _SRVFL_STOP) != 0;
}

PVOID netsrvClntGetUserPtr(PCLNTDATA pClntData)
{
  return netsrvGetUserPtr( pClntData->pServData );
}

PVOID netsrvClntGetProtoData(PCLNTDATA pClntData)
{
  return pClntData->acProtoData;
}

PCTX netsrvClntGetContext(PCLNTDATA pClntData)
{
  if ( pClntData->pCtx == NULL )
  {
    pClntData->pCtx = ctxNew();
//    ctxSetWriteFilter( pClntData->pCtx, cbCtxWriteFilter, pClntData );
    pClntData->ulFlags &= ~_CLNTFL_WRITEFILTEROFF;
  }

  return pClntData->pCtx;
}

BOOL netsrvClntGetRemoteAddr(PCLNTDATA pClntData, struct in_addr *pAddr,
                             PULONG pulPort)
{
  struct sockaddr_in   stClntAddr;
  int                  cbClntAddr = sizeof(struct sockaddr_in);

  if ( getpeername( pClntData->iSock, (struct sockaddr *)&stClntAddr,
                    &cbClntAddr ) == -1 )
    return FALSE;

  if ( pAddr != NULL )
    *pAddr = stClntAddr.sin_addr;

  if ( pulPort != NULL )
    *pulPort = stClntAddr.sin_port;

  return TRUE;
}

VOID netsrvSetOutputDelay(PCLNTDATA pClntData, ULONG ulDelay)
{
  DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &pClntData->_cltime.ulSend,
                   sizeof(ULONG) );
  pClntData->_cltime.ulSend += ulDelay;
  pClntData->ulFlags |= _CLNTFL_DELAYSEND;
}

VOID netsrvClntSetRawInput(PCLNTDATA pClntData, ULLONG ullMaxRawBlock)
{
//  pClntData->ulMaxRawBlock = MIN( ullMaxRawBlock, _RAWINPUTMAXBLOCKSIZE );
  ULONG    ulVal;
  int      cbVal = sizeof(ulVal);

  if ( getsockopt( pClntData->iSock, SOL_SOCKET, SO_RCVBUF, (char *)&ulVal,
                   &cbVal ) == -1 )
    ulVal = 65535;

  pClntData->ulMaxRawBlock = MIN( ullMaxRawBlock, ulVal );
}

BOOL netsrvClntGetRawInput(PCLNTDATA pClntData)
{
  return pClntData->ulMaxRawBlock != 0;
}

BOOL netsrvClntStartTLS(PCLNTDATA pClntData)
{
  if ( !netsrvClntIsTLSAvailable( pClntData ) )
  {
    debugCP( "TLS is not available" );
    return FALSE;
  }

  pClntData->ulFlags |= _CLNTFL_SSLACCEPTINIT;

  return TRUE;
}

BOOL netsrvClntIsTLSMode(PCLNTDATA pClntData)
{
//  return pClntData->pSSL != NULL;

  return (pClntData->ulFlags & _CLNTFL_TLSMODE) != 0;
}

BOOL netsrvClntIsTLSAvailable(PCLNTDATA pClntData)
{
  return netsrvIsTLSAvailable( pClntData->pServData );
}

VOID netsrvClntLog(PCLNTDATA pClntData, ULONG ulLevel, PSZ pszFormat, ...)
{
  va_list    arglist;
  LONG       cbBuf, cbPref;
  CHAR       acBuf[512];

  IF_LOGLEVEL( ulLevel )

  cbPref = sprintf( acBuf, "%s %.4lX ",
                     pClntData->pServData->pProtocol->acLogId,
                     pClntData->ulFlags & _CLNTFL_LOGIDMASK );

  va_start( arglist, pszFormat ); 
  cbBuf = _vsnprintf( &acBuf[cbPref], sizeof(acBuf) - cbPref, pszFormat,
                      arglist );
  va_end( arglist );

  logWrite( ulLevel, cbBuf < 0 ? sizeof(acBuf) : (cbPref + cbBuf), acBuf );

  END_IF_LOGLEVEL
}



/* *************************************************************** */
/*                                                                 */
/*                        Public routines                          */
/*                                                                 */
/* *************************************************************** */

BOOL netsrvInit()
{
  sock_init();

#ifdef DEBUG_CODE
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
#endif
  SSL_library_init();
  OpenSSL_add_ssl_algorithms(); // or OpenSSL_add_all_algorithms();

  lnkseqInit( &lsServers );

  return TRUE;
}

VOID netsrvDone()
{
  while( lnkseqGetCount( &lsServers ) != 0 )
    netsrvDestroy( (PSERVDATA)lnkseqGetFirst( &lsServers ) );

  if ( paiSelSock != NULL )
    free( paiSelSock );

  ERR_remove_state( 0 );
  ENGINE_cleanup();
  CONF_modules_unload( 1 );
  ERR_free_strings();

  EVP_cleanup();

  sk_SSL_COMP_free( SSL_COMP_get_compression_methods() );
  CRYPTO_cleanup_all_ex_data();
}

PSERVDATA netsrvCreate(PNSPROTO pProtocol, PNSCREATEDATA pCreateData)
{
  PSERVDATA  pServData;
  ULONG      ulRC;

  if ( pCreateData->ulThreads == 0 )
  {
    debugCP( "pCreateData->ulThreads should be > 0" );
    return NULL;
  }

  pServData = hcalloc( 1, sizeof(SERVDATA) );
  if ( pServData == NULL )
    return NULL;

  lnkseqInit( &pServData->lsClients );
  lnkseqInit( &pServData->lsPendClients );
  pServData->pProtocol = pProtocol;
  pServData->pUser = pCreateData->pUser;
  pServData->ulKeepThreads = pCreateData->ulThreads;
  pServData->ulMaxThreads = pCreateData->ulMaxThreads;

  if ( (pCreateData->ulFlags & NSCRFL_LOGGING) != 0 )
    pServData->ulFlags = _SRVFL_LOGGING;

  if ( (pCreateData->ulFlags & (NSCRFL_TLS_INIT | NSCRFL_TLS_REQUIRED)) != 0 )
  {
    // Create context for TLS.

    // Clear TLS output flags.
    pCreateData->ulFlags &= ~(NSCRFL_TLS_INITFAIL | NSCRFL_TLS_CERTFAIL |
                              NSCRFL_TLS_KEYFAIL);

    pServData->pSSLCtx = SSL_CTX_new( SSLv23_server_method() );

    if ( pServData->pSSLCtx == NULL )
    {
      debugCP( "Unable to create SSL context" );
      ERR_print_errors_fp( stderr );
      pCreateData->ulFlags |= NSCRFL_TLS_INITFAIL;
    }
    else
    {
      SSL_CTX_set_ecdh_auto( pServData->pSSLCtx, 1 );

      // Set the certificate and private key.

      if ( ( pCreateData->pszTLSCert == NULL ) ||
           ( SSL_CTX_use_certificate_file( pServData->pSSLCtx,
                                           pCreateData->pszTLSCert,
                                           SSL_FILETYPE_PEM ) <= 0 ) )
      {
        debugCP( "Certificate load fail" );
        pCreateData->ulFlags |= (NSCRFL_TLS_INITFAIL | NSCRFL_TLS_CERTFAIL);
      }

      if ( ( pCreateData->pszTLSKey == NULL ) ||
           ( SSL_CTX_use_PrivateKey_file( pServData->pSSLCtx,
                                          pCreateData->pszTLSKey,
                                          SSL_FILETYPE_PEM ) <= 0 ) )
      {
        debugCP( "Private key load fail" );
        pCreateData->ulFlags |= (NSCRFL_TLS_INITFAIL | NSCRFL_TLS_KEYFAIL);
      }
    }  // if ( pServData->pSSLCtx == NULL ) else

    if ( (pCreateData->ulFlags & NSCRFL_TLS_INITFAIL) != 0 )
    {
      // TLS initialization failed.
#ifdef DEBUG_CODE
      if ( ( (pCreateData->ulFlags &
               (NSCRFL_TLS_CERTFAIL | NSCRFL_TLS_KEYFAIL)) != 0 ) &&
           ( pCreateData->pszTLSCert != NULL ) &&
           ( pCreateData->pszTLSKey != NULL ) )
      {
        ERR_print_errors_fp( stderr );
        puts( "" );
      }
#endif
      if ( pServData->pSSLCtx != NULL )
        SSL_CTX_free( pServData->pSSLCtx );

      if ( (pCreateData->ulFlags & NSCRFL_TLS_REQUIRED) != 0 )
      {
        // TLS is required but cannot be initialized.
        hfree( pServData );
        return NULL;
      }

      pServData->pSSLCtx = NULL;
    }
  }  // NSCRFL_TLS_INIT or NSCRFL_TLS_REQUIRED flag is set by caller.

  ulRC = DosCreateMutexSem( NULL, &pServData->hmtxClients, 0, FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateMutexSem(), rc = %u", ulRC );
    hfree( pServData );
    return NULL;
  }

  ulRC = DosCreateEventSem( NULL, &pServData->hevPendClients, DCE_AUTORESET,
                            FALSE );
  if ( ulRC != NO_ERROR )
  {
    debug( "DosCreateEventSem(), rc = %u", ulRC );
    DosCloseMutexSem( pServData->hmtxClients );
    hfree( pServData );
    return NULL;
  }

  logf( 6, "%s Start %u thread(s) (%u max.)...",
        pServData->pProtocol->acLogId, pCreateData->ulThreads,
        pCreateData->ulMaxThreads );
  for( ulRC = 0; ulRC < pCreateData->ulThreads; ulRC++ )
  {
    if ( _beginthread( threadClient, NULL, 65535, pServData ) == -1 )
    {
      logWriteFmt( 0, "%s Could not start thread #%u",
                   pServData->pProtocol->acLogId, ulRC );
      break;
    }
  }

  // Insert a new server to the global servers list.
  lnkseqAdd( &lsServers, pServData );

  return pServData;
}

VOID netsrvDestroy(PSERVDATA pServData)
{
  ULONG      ulIdx;
  ULONG      ulRC;

  // Remove the server from the global servers list.
  lnkseqRemove( &lsServers, pServData );

  // Shutdown all threads.
  pServData->ulFlags |= _SRVFL_STOP;
  do
  {
    DosPostEventSem( pServData->hevPendClients );
    DosSleep( 1 );

    DosRequestMutexSem( pServData->hmtxClients, 50 );
    ulRC = pServData->cThreads;
    DosReleaseMutexSem( pServData->hmtxClients );
  }
  while( ulRC != 0 );

  // Destroy all clients.
  lnkseqFree( &pServData->lsClients, PCLNTDATA, _srvClientDestroy );
  lnkseqFree( &pServData->lsPendClients, PCLNTDATA, _srvClientDestroy );

  // Close all listening sockets.
  if ( pServData->paiSock != NULL )
  {
    for( ulIdx = 0; ulIdx < pServData->cSock; ulIdx++ )
    {
      shutdown( pServData->paiSock[ulIdx], 1 );
      soclose( pServData->paiSock[ulIdx] );
    }
    hfree( pServData->paiSock );
  }

  ulRC = DosCloseMutexSem( pServData->hmtxClients );
  if ( ulRC != NO_ERROR )
    debug( "DosCloseMutexSem(), rc = %u", ulRC );

  ulRC = DosCloseEventSem( pServData->hevPendClients );
  if ( ulRC != NO_ERROR )
    debug( "DosCloseEventSem(), rc = %u", ulRC );

  if ( pServData->pSSLCtx != NULL )
    SSL_CTX_free( pServData->pSSLCtx );

  hfree( pServData );
}

BOOL netservBind(PSERVDATA pServData, ULONG ulAddr, USHORT usPort, BOOL fSSL)
{
  int                  iSock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
  struct sockaddr_in   stSockAddrIn;
  ULONG                ulVal = 1;

  if ( iSock == -1 )
  {
    debug( "Cannot create socket, error: %d", sock_errno() );
    return FALSE;
  }

  setsockopt( iSock, SOL_SOCKET, SO_REUSEADDR, (const void *)&ulVal,
              sizeof(ULONG) );

  memset( &stSockAddrIn, 0, sizeof(stSockAddrIn) );
  stSockAddrIn.sin_len          = sizeof(stSockAddrIn);
  stSockAddrIn.sin_addr.s_addr  = ulAddr;
  stSockAddrIn.sin_family       = AF_INET;
  stSockAddrIn.sin_port         = htons( usPort );

  if ( !_srvBind( pServData, sizeof(struct sockaddr_in),
                  (struct sockaddr *)&stSockAddrIn, iSock, 32, fSSL ) )
  {
    soclose( iSock );
    return FALSE;
  }

  return TRUE;
}

BOOL netservBindName(PSERVDATA pServData, PSZ pszSocket)
{
  struct sockaddr_un   stUn;
  int                  iSock;

  stUn.sun_len = sizeof(stUn);
  stUn.sun_family = AF_UNIX;
  if ( _snprintf( stUn.sun_path, sizeof(stUn.sun_path), "\\socket\\%s",
                  pszSocket ) == -1 )
  {
    debugCP( "Socket name is too long" );
    return FALSE;
  }

  iSock = socket( PF_UNIX, SOCK_STREAM, 0 );
  if ( iSock == -1 )
  {
    debug( "Cannot create socket, error: %d", sock_errno() );
    return FALSE;
  }

  if ( !_srvBind( pServData, sizeof(stUn), (struct sockaddr *)&stUn,
                  iSock, 8, FALSE ) )
  {
    soclose( iSock );
    return FALSE;
  }

  return TRUE;
}

BOOL netsrvIsTLSAvailable(PSERVDATA pServData)
{
  return pServData->pSSLCtx != NULL;
}

PVOID netsrvGetUserPtr(PSERVDATA pServData)
{
  return pServData->pUser;
}


// BOOL netsrvProcess(ULONG ulTimeout)
// -----------------------------------

#define _srvLockClients(__pServData) do { \
  ULONG      ulRC = DosRequestMutexSem( __pServData->hmtxClients, \
                                        SEM_INDEFINITE_WAIT ); \
  if ( ulRC != NO_ERROR ) \
    debug( "#%u DosRequestMutexSem(), rc = %lu", __LINE__, ulRC ); \
} while( FALSE )

#define _srvUnlockClients(__pServData) \
  DosReleaseMutexSem( pServData->hmtxClients )

#define _SELSOCK_LIST_DELTA      16

static VOID __addSock(PULONG pulSSPos, int iSock)
{
  if ( *pulSSPos == ulSelSockMax )
  {
    int *paiNew = realloc( paiSelSock,
                         (ulSelSockMax + _SELSOCK_LIST_DELTA) * sizeof(int) );
    if ( paiNew == NULL )
      return;
    paiSelSock = paiNew;
    ulSelSockMax += _SELSOCK_LIST_DELTA;
  }

  paiSelSock[*pulSSPos] = iSock;
  (*pulSSPos)++;
}

static VOID __addSockList(PULONG pulSSPos, ULONG cList, int *pList)
{
  ULONG      ulNewPos = *pulSSPos + cList;

  if ( ulNewPos > ulSelSockMax )
  {
    int *paiNew = realloc( paiSelSock, ulNewPos * sizeof(int) );

    if ( paiNew == NULL )
      return;
    paiSelSock = paiNew;
    ulSelSockMax = ulNewPos;
  }

  memcpy( &paiSelSock[*pulSSPos], pList, cList * sizeof(int) );
  *pulSSPos += cList;
}

BOOL netsrvProcess(ULONG ulTimeout)
{
  PSERVDATA            pServData;
  PCLNTDATA            pClntData;
  ULONG                ulSSPos = 0;
  ULONG                cSelRead = 0;
  int                  cSelSock;
  ULONG                ulIdx, ulRC, ulCount;
  int                  iSock, iClntSock;
  struct sockaddr_in   stSockAddrIn;
  int                  cbSockAddrIn;

  // Get sockets to read from all servers.

  for( pServData = (PSERVDATA)lnkseqGetFirst( &lsServers );
       pServData != NULL; pServData = (PSERVDATA)lnkseqGetNext( pServData ) )
  {
    _srvLockClients( pServData );

    // The first group of server's sockets is listening (read) server sockets.
    __addSockList( &ulSSPos, pServData->cSock, pServData->paiSock );

    // The second group of server's sockets is client read sockets.
    for( pClntData = (PCLNTDATA)lnkseqGetFirst( &pServData->lsClients );
         pClntData != NULL; pClntData = (PCLNTDATA)lnkseqGetNext( pClntData ) )
    {
      __addSock( &ulSSPos, pClntData->iSock );
    }
    pServData->cSelReadSock = lnkseqGetCount( &pServData->lsClients );

    _srvUnlockClients( pServData );
  }
  cSelRead = ulSSPos;

  // Get sockets to write from all servers.

  for( pServData = (PSERVDATA)lnkseqGetFirst( &lsServers );
       pServData != NULL; pServData = (PSERVDATA)lnkseqGetNext( pServData ) )
  {
    _srvLockClients( pServData );

    pServData->cSelWriteSock = 0;
    for( pClntData = (PCLNTDATA)lnkseqGetFirst( &pServData->lsClients );
         pClntData != NULL; pClntData = (PCLNTDATA)lnkseqGetNext( pClntData ) )
    {
      if ( ( pClntData->pCtx == NULL ) &&
           ( (pClntData->ulFlags & _CLNTFL_SSLACCEPTINIT) != 0 ) )
        // Protocol layer initialized encryption with netsrvClntStartTLS() and
        // all pending output data from the context object has been sent.
        // Now we can call _srvClientSSLAccept() first time for the session.
        _srvClientSSLAccept( pClntData );

      if ( ( ( pClntData->pSSL != NULL ) &&
             ( (pClntData->ulFlags & _CLNTFL_SSLACCEPTWRITE) != 0 ) ) ||
           _srvClientHaveOutputData( pClntData ) )
      {
        __addSock( &ulSSPos, pClntData->iSock );
        pServData->cSelWriteSock++;
      }
    }

    _srvUnlockClients( pServData );
  }


  // Waiting for socket activity.

  cSelSock = os2_select( paiSelSock, cSelRead, ulSSPos - cSelRead, 0,
                         ulTimeout );
  if ( cSelSock < 0 )
  {
    int      iErr = sock_errno();

    if ( iErr != EINTR )
    {
      debug( "os2_select(), error: %d", iErr );
      return FALSE;
    }

    return TRUE;
  }

  if ( cSelSock == 0 )
  {
    // os2_select() timed out.

    ULONG  ulProtoTimeout;
    ULONG  ulTime;

    DosQuerySysInfo( QSV_MS_COUNT, QSV_MS_COUNT, &ulTime, sizeof(ULONG) );

    for( pServData = (PSERVDATA)lnkseqGetFirst( &lsServers );
         pServData != NULL; pServData = (PSERVDATA)lnkseqGetNext( pServData ) )
    {
      /*  For each server:
            - Determine whether to run an additional thread.
            - Check timeouts for clients. Remove only one by server.
            - Run the thread if necessary.
            - Call protocol idle function if it specified.  */

      _srvLockClients( pServData );

#ifdef DEBUG_CODE
      if ( pServData->cThreadsBusy == pServData->cThreads )
        debug( "All %u threads are busy, we have %u clients, %u threatds max.",
               pServData->cThreadsBusy,
               lnkseqGetCount( &pServData->lsPendClients ),
               pServData->ulMaxThreads );
#endif

      ulCount = !lnkseqIsEmpty( &pServData->lsPendClients ) &&
                ( pServData->cThreadsBusy == pServData->cThreads ) &&
                ( pServData->cThreads < pServData->ulMaxThreads )
                  ? pServData->cThreads : 0;
      // If ulCount is not a zero than we need the additional thread.

      if ( ulCount == 0 )
      {
        // No need to run additional thread. Check client timeouts.

        ulProtoTimeout = pServData->pProtocol->ulTimeout;
        for( pClntData = (PCLNTDATA)lnkseqGetFirst( &pServData->lsClients );
             pClntData != NULL; pClntData = (PCLNTDATA)lnkseqGetNext( pClntData ) )
        {
          if ( (pClntData->ulFlags & _CLNTFL_DELAYSEND) != 0 )
          {
            if ( (LONG)( pClntData->_cltime.ulSend - ulTime ) < 0 )
            {
              pClntData->ulFlags &= ~_CLNTFL_DELAYSEND;
              pClntData->_cltime.ulLastAct = ulTime;
            }
          }
          else if ( (LONG)( (pClntData->_cltime.ulLastAct + ulProtoTimeout) -
                            ulTime ) < 0 )
          {
            lnkseqRemove( &pServData->lsClients, pClntData );
            _srvClientLog( pClntData, 4, "Session is timed out" );
            _srvClientDestroy( pClntData );
            break;
          }
        }
      }

      _srvUnlockClients( pServData );

      if ( ulCount != 0 )
      {
        // All threads are busy and we can start more...

        if ( (pServData->ulFlags & _SRVFL_LOGGING) != 0 )
          logf( 2, "%s All of %u threads are busy - start a new one",
                pServData->pProtocol->acLogId, ulCount );

        _beginthread( threadClient, NULL, 65535, pServData );
      }
      else if ( (pClntData == NULL) && (pServData->pProtocol->fnIdle != NULL) )
        // No timedout sessions and no additional threads was runned.
        // Call protocol idle function.
        pServData->pProtocol->fnIdle( ulTime );

    }  // go to the next server...

    // All work for timedout os2_select() is done...
    return TRUE;

  }  // if ( cSelSock == 0 )


  // Check read events on sockets for all servers.

  ulSSPos = 0;
  for( pServData = (PSERVDATA)lnkseqGetFirst( &lsServers );
       pServData != NULL; pServData = (PSERVDATA)lnkseqGetNext( pServData ) )
  {
    _srvLockClients( pServData );

    // Check listening sockets on server.

    for( ulIdx = 0; ulIdx < pServData->cSock; ulIdx++ )
    {
      iSock = paiSelSock[ulSSPos];
      ulSSPos++;

      if ( iSock == -1 )
        continue;

      cbSockAddrIn = sizeof(stSockAddrIn);
      iClntSock = accept( iSock, (struct sockaddr *)&stSockAddrIn,
                          &cbSockAddrIn );
      if ( iClntSock < 0 )
      {
        debug( "accept(), error: %u", sock_errno() );
        continue;
      }

      ulRC = 1;
      pClntData = NULL;

      // Is connection limit reached?
      if ( ( pServData->pProtocol->ulMaxClients != 0 ) &&
           ( lnkseqGetCount( &pServData->lsClients ) >=
               pServData->pProtocol->ulMaxClients ) )
      {
        if ( (pServData->ulFlags & _SRVFL_LOGGING) != 0 )
          logf( 3, "%s Maximum connection limit reached (%lu)",
                pServData->pProtocol->acLogId,
                pServData->pProtocol->ulMaxClients );
      }
      else if ( ioctl( iClntSock, FIONBIO, (PCHAR)&ulRC ) == -1 )
      {
        debugCP( "ioctl() failed" );
      }
      else
      {
        pClntData = _srvClientNew( pServData, iClntSock,
                                   ulIdx < pServData->ulFirstNonSSLSock );

        if ( pClntData != NULL )
          lnkseqAdd( &pServData->lsClients, pClntData );
      }

      if ( pClntData == NULL )
        soclose( iClntSock );
    }  // for( ulIdx = 0; ulIdx < pServData->cSock; ulIdx++ )

    // Check sockets to read on server.

    for( ulIdx = 0; ulIdx < pServData->cSelReadSock; ulIdx++ )
    {
      iSock = paiSelSock[ulSSPos];
      ulSSPos++;

      if ( iSock == -1 )
        continue;

      for( pClntData = (PCLNTDATA)lnkseqGetFirst( &pServData->lsClients );
           pClntData != NULL; pClntData = (PCLNTDATA)lnkseqGetNext( pClntData ) )
      {
        if ( iSock != pClntData->iSock )
          continue;

        if ( (pClntData->ulFlags & _CLNTFL_SSLACCEPTREAD) != 0 )
        {
          if ( ( pClntData->pCtx == NULL ) && !_srvClientSSLAccept( pClntData ) )
          {
            lnkseqRemove( &pServData->lsClients, pClntData );
            _srvClientDestroy( pClntData );
          }
        }
        else if ( (pClntData->ulFlags & _CLNTFL_SSLACCEPTWRITE) == 0 )
        {
          // Read input data in other thread.

          lnkseqRemove( &pServData->lsClients, pClntData );
          lnkseqAdd( &pServData->lsPendClients, pClntData );

          // Send a signal to the thread(s) about the new pending client.
          ulRC = DosPostEventSem( pServData->hevPendClients );
          if ( ( ulRC != NO_ERROR ) || ( ulRC == ERROR_ALREADY_POSTED ) )
            debug( "DosPostEventSem(), rc = %u", ulRC );
        }

        break;
      }  // for( pClntData ...
    }  // for( ulIdx = 0; ulIdx < pServData->cSelReadSock; ulIdx++ )

    _srvUnlockClients( pServData );

  }  // for( pServData ...


  // Check write events on sockets for all servers.

  for( pServData = (PSERVDATA)lnkseqGetFirst( &lsServers );
       pServData != NULL; pServData = (PSERVDATA)lnkseqGetNext( pServData ) )
  {
    _srvLockClients( pServData );

    for( ulIdx = 0; ulIdx < pServData->cSelWriteSock; ulIdx++ )
    {
      iSock = paiSelSock[ulSSPos];
      ulSSPos++;

      if ( iSock == -1 )
        continue;

      for( pClntData = (PCLNTDATA)lnkseqGetFirst( &pServData->lsClients );
           pClntData != NULL;
           pClntData = (PCLNTDATA)lnkseqGetNext( pClntData ) )
      {
        if ( iSock == pClntData->iSock )
        {
          BOOL fSuccess;

          if ( (pClntData->ulFlags & _CLNTFL_SSLACCEPTWRITE) != 0 )
            fSuccess = _srvClientSSLAccept( pClntData );
          else if ( pClntData->pCtx != NULL )
            fSuccess = _srvClientSend( pServData, pClntData );
          else
            break;

          if ( !fSuccess )
          {
            lnkseqRemove( &pServData->lsClients, pClntData );
            _srvClientDestroy( pClntData );
          }

          break;
        }
      }  // for( pClntData ...
    }  // for( ulIdx = 0; ulIdx < pServData->cSelWriteSock; ulIdx++ )

    _srvUnlockClients( pServData );

  }  // for( pServData ...


  return TRUE;  
}
