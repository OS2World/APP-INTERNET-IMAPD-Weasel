#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#define INCL_RXMACRO              /* include macrospace info         */
#define INCL_RXFUNC               /* include external function  info */
#define INCL_REXXSAA
#include <os2.h>
#ifdef __WATCOMC__
#include <rexxsaa.h>
#endif
#include <ctype.h>
#include <nerrno.h>
#include <stdio.h>
#include <string.h>
#include <types.h>
#include <sys\socket.h>
#include <unistd.h>
#include <sys\un.h>
#include <utils.h>
#include <debug.h>

#define INVALID_ROUTINE		40           /* Raise Rexx error           */
#define VALID_ROUTINE		0            /* Successful completion      */

#define BUILDRXSTRING(t, s) { \
  strcpy((PCHAR)(t)->strptr,(PCHAR)(s));\
  (t)->strlength = strlen((PCHAR)(s)); \
}

ULONG APIENTRY rxsfLoadFuncs(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                    PSZ pszQueue, RXSTRING *prxstrRet);
ULONG APIENTRY rxsfDropFuncs(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                    PSZ pszQueue, RXSTRING *prxstrRet);
ULONG APIENTRY rxsfOpen(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
               PSZ pszQueue, RXSTRING *prxstrRet);
ULONG APIENTRY rxsfClose(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                              PSZ pszQueue, RXSTRING *prxstrRet);
ULONG APIENTRY rxsfSend(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                             PSZ pszQueue, RXSTRING *prxstrRet);
ULONG APIENTRY rxsfRecv(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                             PSZ pszQueue, RXSTRING *prxstrRet);
ULONG APIENTRY rxsfRequest(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                                PSZ pszQueue, RXSTRING *prxstrRet);

static PSZ RxFncTable[] =
{
  (PSZ)"rxsfLoadFuncs",
  (PSZ)"rxsfDropFuncs",
  (PSZ)"rxsfOpen",
  (PSZ)"rxsfClose",
  (PSZ)"rxsfSend",
  (PSZ)"rxsfRecv",
  (PSZ)"rxsfRequest"
};


static BOOL _rxstrtoi(RXSTRING rxsValue, int *piValue)
{
  PSZ      pszValue = RXSTRPTR( rxsValue );
  PCHAR    pcEnd;

  if ( !RXVALIDSTRING( rxsValue ) )
    return FALSE;

  *piValue = (int)strtol( (PCHAR)pszValue, &pcEnd, 10 );

  return ( (PSZ)pcEnd != pszValue ) && ( errno == 0 );
}

static BOOL _setRxValue(PSZ pszName, ULONG cbValue, PCHAR pcValue)
{
  SHVBLOCK	sBlock;

  strupr( (PCHAR)pszName );

  sBlock.shvnext = NULL;
  MAKERXSTRING( sBlock.shvname, pszName, strlen( pszName ) );
  sBlock.shvvalue.strptr = pcValue;
  sBlock.shvvalue.strlength = cbValue;
  sBlock.shvnamelen = sBlock.shvname.strlength;
  sBlock.shvvaluelen = sBlock.shvvalue.strlength;
  sBlock.shvcode = RXSHV_SET;
  sBlock.shvret = 0;

  return RexxVariablePool( &sBlock ) != RXSHV_BADN;
}

static int _connOpen(PSZ pszSocket)
{
  struct sockaddr_un   stUn;
  int                  iSocket;

  stUn.sun_path[sizeof(stUn.sun_path) - 1] = '\0';
  _snprintf( stUn.sun_path, sizeof(stUn.sun_path) - 1, "\\socket\\%s",
             ( pszSocket == NULL || *pszSocket == '\0' )
                ? (PSZ)"SPAMFILTER" : pszSocket );
  stUn.sun_len = sizeof(stUn);
  stUn.sun_family = AF_UNIX;

  iSocket = socket( PF_UNIX, SOCK_STREAM, 0 );

  if ( ( iSocket != -1 ) &&
       ( connect( iSocket, (struct sockaddr *)&stUn, SUN_LEN( &stUn ) ) == -1 ) )
  {
    debug( "connect() failed, error: %d", sock_errno() );
    soclose( iSocket );
    iSocket = -1;
  }

  return iSocket;
}

static BOOL _connClose(int iSocket)
{
  shutdown( iSocket, 1 );
  return soclose( iSocket ) == 0;
}


ULONG rxsfLoadFuncs(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                    PSZ pszQueue, RXSTRING *prxstrRet)
{
  ULONG			ulIdx;
 
  prxstrRet->strlength = 0;
  if ( cArgs > 0 )
    return INVALID_ROUTINE;
 
  for( ulIdx = 0; ulIdx < ARRAYSIZE(RxFncTable); ulIdx++ )
    RexxRegisterFunctionDll( RxFncTable[ulIdx], "RXSF", RxFncTable[ulIdx] );

  debugInit();
  return VALID_ROUTINE;
}

ULONG rxsfDropFuncs(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                    PSZ pszQueue, RXSTRING *prxstrRet)
{
  ULONG			ulIdx;
 
  prxstrRet->strlength = 0;
  if ( cArgs > 0 )
    return INVALID_ROUTINE;
 
  for( ulIdx = 0; ulIdx < ARRAYSIZE(RxFncTable); ulIdx++ )
    RexxDeregisterFunction( RxFncTable[ulIdx] );

  debug( "Done. Allocated memory: %d", debugMemUsed() );
  debugDone();
  return VALID_ROUTINE;
}

// socket = rxsfOpen( [name] )
//
// Opens connection to the program (local IPC socket).
// Name: local socket name witout leading part "\socket\". By default name is
// "SPAMFILTER". Returns socket handle or -1 on error.

ULONG rxsfOpen(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
               PSZ pszQueue, RXSTRING *prxstrRet)
{
  CHAR                 acBuf[16];

  ltoa( _connOpen( cArgs == 0 ? NULL : RXSTRPTR( aArgs[0] ) ),
        (PSZ)&acBuf, 10 );
  BUILDRXSTRING( prxstrRet, &acBuf );

  return VALID_ROUTINE;
}

// ret = rxsfClose( socket )
//
// Closes connection created by rxsfOpen().
// Return: The value OK indicates success; the value ERROR indicates an error.

ULONG rxsfClose(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
               PSZ pszQueue, RXSTRING *prxstrRet)
{
  int        iSocket;

  if ( cArgs != 1 || !_rxstrtoi( aArgs[0], &iSocket ) )
    return INVALID_ROUTINE;

  BUILDRXSTRING( prxstrRet, _connClose( iSocket ) ? "OK:" : "ERROR:" );
  return VALID_ROUTINE;
}

// rxsfSend( socket, data[, flags] )
//
// Flags: one or more separated by spaces: MSG_DONTROUTE, MSG_DONTWAIT, MSG_OOB.
// Return: Number of bytes that is added to the send buffer;
//         the value -1 indicates an error.

ULONG rxsfSend(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
               PSZ pszQueue, RXSTRING *prxstrRet)
{
  int        iSocket;
  int        iFlags = 0;

  if ( ( cArgs < 2 ) || ( cArgs > 3 ) || !_rxstrtoi( aArgs[0], &iSocket ) ||
       !RXVALIDSTRING( aArgs[1] ) )
    return INVALID_ROUTINE;

  if ( ( cArgs == 3 ) && RXVALIDSTRING( aArgs[2] ) )
  {
    ULONG    cbFlags = aArgs[2].strlength;
    PCHAR    pcFlags = aArgs[2].strptr;
    ULONG    cbFlag;
    PCHAR    pcFlag;

    while( utilBufCutWord( &cbFlags, &pcFlags, &cbFlag, &pcFlag ) )
    {
      switch( utilStrWordIndex( "MSG_DONTROUTE MSG_DONTWAIT MSG_OOB", cbFlag,
                                pcFlag ) )
      {
        case -1:
          return INVALID_ROUTINE;

        case 0:
          iFlags |= MSG_DONTROUTE;
          break;

        case 1:
          iFlags |= MSG_DONTWAIT;
          break;

        case 2:
          iFlags |= MSG_OOB;
          break;
      }
    }
  }

  itoa( send( iSocket, aArgs[1].strptr, aArgs[1].strlength, iFlags ),
        prxstrRet->strptr, 10 );
  prxstrRet->strlength = strlen( prxstrRet->strptr );

  return VALID_ROUTINE;
}

// rxsfRecv( socket, varName[, flags] )
//
// Flags: one or more separated by spaces: MSG_DONTWAIT, MSG_OOB, MSG_PEEK,
//        MSG_WAITALL.
// Return: The value OK indicates success; the value ERROR indicates an error.

ULONG rxsfRecv(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
               PSZ pszQueue, RXSTRING *prxstrRet)
{
  int        iSocket;
  int        iFlags = 0;
  PCHAR      pcBuf;
  int        iRC;
  BOOL       fSuccess;

  if ( ( cArgs < 2 ) || ( cArgs > 3 ) || !_rxstrtoi( aArgs[0], &iSocket ) ||
       !RXVALIDSTRING( aArgs[1] ) )
    return INVALID_ROUTINE;

  if ( ( cArgs == 3 ) && RXVALIDSTRING( aArgs[2] ) )
  {
    ULONG    cbFlags = aArgs[2].strlength;
    PCHAR    pcFlags = aArgs[2].strptr;
    ULONG    cbFlag;
    PCHAR    pcFlag;

    while( utilBufCutWord( &cbFlags, &pcFlags, &cbFlag, &pcFlag ) )
    {
      switch( utilStrWordIndex( "MSG_DONTWAIT MSG_OOB MSG_PEEK MSG_WAITALL",
                                cbFlag, pcFlag ) )
      {
        case -1:
          return INVALID_ROUTINE;

        case 0:
          iFlags |= MSG_DONTWAIT;
          break;

        case 1:
          iFlags |= MSG_OOB;
          break;

        case 2:
          iFlags |= MSG_PEEK;
          break;

        case 3:
          iFlags |= MSG_WAITALL;
          break;
      }
    }
  }

  pcBuf = debugMAlloc( 65535 );

  if ( pcBuf == NULL )
  {
    BUILDRXSTRING( prxstrRet, "ERROR: Not enough memory" );
  }
  else
  {
    iRC = recv( iSocket, pcBuf, 65535, iFlags );
    fSuccess = ( iRC == -1 ) ||
               _setRxValue( RXSTRPTR( aArgs[1] ), iRC, pcBuf );
    debugFree( pcBuf );

    if ( !fSuccess )
    {
      BUILDRXSTRING( prxstrRet, "ERROR: Cannot set variable" );
    }
    else
    {
      itoa( iRC, prxstrRet->strptr, 10 );
      prxstrRet->strlength = strlen( prxstrRet->strptr );
    }
  }

  return VALID_ROUTINE;
}

// answer = rxsfRequest( [socket], request[, stem] )
//
// Sends request to the program and returns an answer. Socket may be a handle
// open by rxsfOpen() or local IPC socket name witout leading "\socket\".
// By default socket is "SPAMFILTER".
// If stem name is specified function will try to read POP3-like responce:
//   +OK text
//   data line 1
//   data line 2
//   .
// "+OK text" - will be returned as func. result, "data line 1" -> stem.1,
// "data line 2" -> stem.2 and stem.0 is number of lines - 2.

ULONG rxsfRequest(PUCHAR puchName, ULONG cArgs, RXSTRING aArgs[],
                  PSZ pszQueue, RXSTRING *prxstrRet)
{
  int        iSocket;
  PCHAR      pcBuf = NULL;
  int        iRC;
  ULONG      cbRequest;
  PCHAR      pcRequest;
  BOOL       fNewConn = FALSE;
  CHAR       acName[256];
  ULONG      ulStemN = 0;

  if ( ( ( cArgs < 2 ) || ( cArgs > 3 ) || !RXVALIDSTRING( aArgs[1] ) ) ||
       ( ( cArgs == 3 ) && !RXVALIDSTRING( aArgs[2] ) ) )
    return INVALID_ROUTINE;

  pcRequest = aArgs[1].strptr;
  cbRequest = aArgs[1].strlength;

  // Add CRLF if this is not present in a given string.

  if ( ( cbRequest < 2 ) ||
       ( *((PUSHORT)&pcRequest[ cbRequest - 2 ]) != 0x0A0D ) )
  {
    pcBuf = malloc( cbRequest + 4 );
    if ( pcBuf == NULL )
    {
      BUILDRXSTRING( prxstrRet, "ERROR: Not enough memory" );
      if ( pcBuf != NULL )
        free( pcBuf );
      return VALID_ROUTINE;
    }
    memcpy( pcBuf, pcRequest, cbRequest );
    *((PULONG)&pcBuf[cbRequest]) = 0x000A0D;

    pcRequest = pcBuf;
    cbRequest += 2;
  }

  do
  {
    // If 1st argument (socket) is numerical - try send use this socket handle.
    if ( _rxstrtoi( aArgs[0], &iSocket ) )
    {
      iRC = send( iSocket, pcRequest, cbRequest, 0 );
      if ( ( iRC != -1 ) || ( sock_errno() != SOCENOTSOCK ) )
        break;
    }

    // First argument is not a socket or string - try open socket using first
    // argument as the name.
    iSocket = _connOpen( RXSTRPTR( aArgs[0] ) );
    if ( iSocket == -1 )
    {
      BUILDRXSTRING( prxstrRet, "ERROR: Cannot connect to the program" );
      if ( pcBuf != NULL )
        free( pcBuf );
      return VALID_ROUTINE;
    }
    fNewConn = TRUE;

    // Connection was open - send data.
    iRC = send( iSocket, pcRequest, cbRequest, 0 );
  }
  while( FALSE );

  // Destroy temporary buffer (used for trailing CRLF).
  if ( pcBuf != NULL )
    free( pcBuf );

  if ( iRC == -1 )
  {
    BUILDRXSTRING( prxstrRet, "ERROR: Cannot send a request to the program" );
  }
  else
  {
    // Read server responce.

    PCHAR    pcLine, pcEOL, pcNextLine;
    ULONG    cbLine, cbBuf = 0;
    CHAR     acName[256];
    BOOL     fBody = FALSE;

    // Allocate receive buffer.
    pcBuf = malloc( 65535 );
    if ( pcBuf == NULL )
    {
      BUILDRXSTRING( prxstrRet, "ERROR: Not enough memory" );
      if ( fNewConn )
        _connClose( iSocket );
      return VALID_ROUTINE;
    }

    prxstrRet->strlength = 0;
    while( TRUE )
    {
      // Receive a new chunk of responce.
      iRC = recv( iSocket, &pcBuf[cbBuf], 65535 - cbBuf, 0 );
      if ( iRC <= 0 )
        break;

      // Split received chunk on lines.

      cbBuf += iRC;
      pcLine = pcBuf;
      while( ( pcEOL = memchr( pcLine, '\n', cbBuf ) ) != NULL )
      {
        pcNextLine = pcEOL + 1;

        while( ( pcEOL > pcLine ) && isspace( *(pcEOL - 1) ) )
          pcEOL--;

        cbLine = pcEOL - pcLine;
        if ( !fBody )
        {
          // First line of the responce is "result" - it will be returned
          // as function result.

          prxstrRet->strlength = cbLine;
          memcpy( prxstrRet->strptr, pcLine, cbLine );
          if ( ( cArgs < 3 ) || ( memcmp( pcLine, "+OK ", 4 ) != 0 ) )
          {
            // User don't whant responce "body" or result is not "+OK ..."
            iRC = 0;
            break;
          }
          fBody = TRUE;
        }
        else
        {
          // Next lines after result "+OK ..." is a responce "body".

          PCHAR        pcRespLine;

          if ( ( cbLine >= 1 ) && ( *pcLine == '.' ) )
          {
            if ( cbLine == 1 )
            {
              // A dot is an end of body.
              iRC = 0;
              break;
            }
            // First character is dot - remove it.
            pcRespLine = &pcLine[1];
            cbLine--;
          }
          else
            pcRespLine = pcLine;

          ulStemN++;
          sprintf( acName,
                   aArgs[2].strptr[aArgs[2].strlength-1] == '.'
                     ? "%s%lu" : "%s.%lu",
                   RXSTRPTR( aArgs[2] ), ulStemN );
          _setRxValue( (PSZ)acName, cbLine, pcRespLine );
        }

        cbBuf -= ( pcNextLine - pcLine );
        pcLine = pcNextLine;
      }

      if ( iRC <= 0 )
        // Rend of responce.
        break;

      // Move left bytes to the beginning of the buffer.
      if ( pcLine != pcBuf )
        memcpy( pcBuf, pcLine, cbBuf );
      else if ( cbBuf == 65535 )
      {
        debugCP( "Received line is too long" );
        break;
      }
    }

    free( pcBuf );
  }

  if ( fNewConn )
    _connClose( iSocket );

  if ( cArgs >= 3 )
  {
    // stem.0 - number of body lines (stem is 3th argument).
    CHAR     acVal[32];

    sprintf( acName,
             aArgs[2].strptr[aArgs[2].strlength-1] == '.'
               ? "%s0" : "%s.0",
             RXSTRPTR( aArgs[2] ) );
    _setRxValue( (PSZ)acName, sprintf( acVal, "%lu", ulStemN ), acVal );
  }

  return VALID_ROUTINE;
}
