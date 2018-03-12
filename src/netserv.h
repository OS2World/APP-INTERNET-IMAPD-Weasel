#ifndef NETSERV_H
#define NETSERV_H

#include <stdarg.h>
#include <arpa\inet.h>
#include "context.h"
#include "utils.h"

typedef struct _SERVDATA         *PSERVDATA;
typedef struct _CLNTDATA         *PCLNTDATA;


// Protocol implementation handler.

typedef struct _NSPROTO {
  // Size of protocol-related data for the each client.
  // Pointer on this data may be obtained by netsrvClntGetProtoData().
  // All bytes of this memory block is initialized to 0 before calling fnNew().
  ULONG      cbProtoData;

  CHAR       acLogId[8];

  // Inactivity client timeout [msec.]
  ULONG      ulTimeout;

  // Maximum number of clients (0 - no limit).
  ULONG      ulMaxClients;

  // BOOL fnNew(PCLNTDATA pClntData)
  //
  // Will be called (if specified - is not NULL) for the each new client.
  // Client will be disconnected immediately if result code is FALSE.
  BOOL (*fnNew)(PCLNTDATA pClntData);

  // VOID fnDestroy(PCLNTDATA pClntData)
  //
  // If specified, will be called before disconnection of the client.
  VOID (*fnDestroy)(PCLNTDATA pClntData);

  // BOOL fnRequest(PCLNTDATA pClntData, LONG cbInput, PCHAR pcInput)
  //
  // Called from server threads when a new line (cbInput is -1) or raw data
  // (cbInput > 0) obtained from the client to to perform protocol operations.
  // Returns FALSE if client should be destroyed (error or end of session).
  BOOL (*fnRequest)(PCLNTDATA pClntData, LONG cbInput, PCHAR pcInput);

  // VOID (*fnReadyToSend)(PCLNTDATA pClntData);
  //
  // If client have some data (generated outside the request) to send they can
  // write it to the output context. The server serializes this function with
  // fnRequest, so it is thread-safe. This function should be executed as soon
  // as possible.
  // May be NULL.
  VOID (*fnReadyToSend)(PCLNTDATA pClntData);

  // May be NULL.
  VOID (*fnIdle)(ULONG ulTime);

} NSPROTO, *PNSPROTO;


// Server create data structure ( netsrvCreate(,PNSCREATEDATA) )

// NSCRFL_TLS_INIT - Initialize TLS context ( to use netsrvClntStartTLS() ).
#define NSCRFL_TLS_INIT          0x0001
// NSCRFL_TLSREQUIRED - Fail if TLS cannot be initialized.
#define NSCRFL_TLS_REQUIRED      0x0002
// NSCRFL_LOGGING - Logging for server is On.
#define NSCRFL_LOGGING           0x0004
// NSCRFL_TLS_INITFAIL (Output) - TLS initialization failed.
#define NSCRFL_TLS_INITFAIL      0x0100
// NSCRFL_TLSCERTFAIL (Output) - The certificate was not loaded
//                               (NSCRFL_TLS_INITFAIL is set).
#define NSCRFL_TLS_CERTFAIL      0x0200
// NSCRFL_TLSKEYFAIL (Output) - The private key was not loaded.
//                               (NSCRFL_TLS_INITFAIL is set).
#define NSCRFL_TLS_KEYFAIL       0x0400

typedef struct _NSCREATEDATA {
  ULONG      ulFlags;                      // NSCRFL_xxxxx
  ULONG      ulThreads;                    // Normal number of threads.
  ULONG      ulMaxThreads;                 // Max. number of threads.
  PSZ        pszTLSCert;                   // Certificate file.
  PSZ        pszTLSKey;                    // Private key file.
  PVOID      pUser;
} NSCREATEDATA, *PNSCREATEDATA;


BOOL netsrvInit();
VOID netsrvDone();


// Protocol helpers. This functions may be used in protocol's routines.

BOOL netsrvClntGetStopFlag(PCLNTDATA pClntData);

// PVOID netsrvClntGetUserPtr(PCLNTDATA pClntData)
// Returns user pointer for the protocol object ( NSCREATEDATA.pUser ).
PVOID netsrvClntGetUserPtr(PCLNTDATA pClntData);

// PVOID netsrvClntGetProtoData(PCLNTDATA pClntData)
// Returns pointer to the protocol memory space (available size is
// NSPROTO.cbProtoData).
PVOID netsrvClntGetProtoData(PCLNTDATA pClntData);

// PCTX netsrvClntGetContext(PCLNTDATA pClntData)
// Returns client output context. The protocol writes data to this object to
// send it to the client.
PCTX netsrvClntGetContext(PCLNTDATA pClntData);

// BOOL netsrvClntGetRemoteAddr(PCLNTDATA pClntData, struct in_addr *pAddr,
//                              PULONG pulPort)
// Returns client host ip-address in pAddr and port in pulPort.
// Pointers pAddr and/or pulPort can be NULL.
BOOL netsrvClntGetRemoteAddr(PCLNTDATA pClntData, struct in_addr *pAddr,
                             PULONG pulPort);

VOID netsrvSetOutputDelay(PCLNTDATA pClntData, ULONG ulDelay);

// netsrvClntSetRawInput(PCLNTDATA pClntData, ULLONG ullMaxRawBlock)
//
// ulMaxRawBlock > 0 - set pClntData to the raw-input mode, ullMaxRawBlock is
//                     maximum input data chunk size.
// ulMaxRawBlock = 0 - set pClntData to the line-input mode.
VOID netsrvClntSetRawInput(PCLNTDATA pClntData, ULLONG ulMaxRawBlock);

BOOL netsrvClntGetRawInput(PCLNTDATA pClntData);

BOOL netsrvClntStartTLS(PCLNTDATA pClntData);
BOOL netsrvClntIsTLSMode(PCLNTDATA pClntData);
BOOL netsrvClntIsTLSAvailable(PCLNTDATA pClntData);

VOID netsrvClntLog(PCLNTDATA pClntData, ULONG ulLevel, PSZ pszFormat, ...);


// Server control functions.

// pProtocol    - protocol implementation handle.
// pCreateData  - server object paramethers.
// Once created, the server must be bound to the address(es) by netservBind()
// and/or netservBindName().
// Server can be destroyed by netsrvDestroy(), otherwise it will be destroyed
// by netsrvDone().
PSERVDATA netsrvCreate(PNSPROTO pProtocol, PNSCREATEDATA pCreateData);

VOID netsrvDestroy(PSERVDATA pServData);
BOOL netservBind(PSERVDATA pServData, ULONG ulAddr, USHORT usPort, BOOL fSSL);

// Bind to the local socket.
// pszSocket - local socket name without "\socket\" prefix.
BOOL netservBindName(PSERVDATA pServData, PSZ pszSocket);

BOOL netsrvIsTLSAvailable(PSERVDATA pServData);

// PVOID netsrvGetUserPtr(PSERVDATA pServData)
// Returns user pointer for the protocol object ( NSCREATEDATA.pUser ).
PVOID netsrvGetUserPtr(PSERVDATA pServData);

// Process sockets on all servers.
BOOL netsrvProcess(ULONG ulTimeout);

#endif // NETSERV_H
