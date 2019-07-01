#ifndef PIPER_H
#define PIPER_H

// prInit() return codes.
#define PRRC_OK                  0
#define PRRC_INVALIDPIPENAME     1
#define PRRC_NOTENOUGHMENORY     2
#define PRRC_SRVPIPECREATEERR    3
#define PRRC_INVALIDSRVPIPENAME  4
#define PRRC_INVALIDSEMAPHORE    5
// Same names of client and server named pipes.
#define PRRC_NAMECOLLISION       6

// Codes for function PPRFNUSER.
#define PREVENT_CONNECTED        0
#define PREVENT_DISCONNECTED     1
#define PREVENT_INPUTLINE        2
#define PREVENT_PIPECREATEERROR  3
#define PREVENT_CONNECTERROR     4

typedef struct _PIPER *PPIPER;

typedef VOID (*PPRFNUSER)(PPIPER pPiper, ULONG ulCode, PSZ pszData);

typedef struct _PRINIT {
  PCHAR      pcPipes;
  /* List of named pipes to connect. Each name must be terminated with zero.
     Last name in list must be terminated with two zeros. */

  ULONG      ulReconnectPeriod;
  /* Period in msec. to reconnect to pipes listed in pcPipes. */

  PSZ        pszServerPipe;
  /* Name of server named pipe to send data received from client named pipe.
     May be NULL (do not create server named pipes).

     These pipes will be created when the input pipe connects and destroyed
     when the input pipe is disconnected.
   */

  ULONG      cServerPipes;
  /* Number of server named pipes pszServerPipe. I.e. maximum number of
     clients. May be zero (do not create server named pipes). */

  ULONG      ulWriteBufSize;
  ULONG      ulReadBufSize;

  PPRFNUSER  fnUser;
  /* User callback function. It will be triggered by events: the connection to
     the one of the named pipes (pcPipes) is established, the connection is
     broken, the line is received. May be NULL. */

  HEV        hevInputPipe;
  /* Handle of user's shared event semaphore. This semaphore will be attached
     to the input pipe and will posts when data is available for reading.
     User code should check this semaphore and call prProcess(,TRUE) when it is
     posted. Thus, the input data will be processed immediately.

     Function prProcess(,FALSE) should still be called besides the events on
     the semaphore.

     Set it to NULLHANDLE to check the input pipe only during periodic calls
     function prProcess().
   */

  ULONG      ulInputPipeKey;
  /* Unique key for using event semaphore hevInputPipe with other pipes. */

} PRINIT, *PPRINIT;


/* If necessary, adds string "\PIPE\" to the beginning of name pszName.
   The result will be stored in buffer pcBuf.
   Returns the length of the resulting string, or 0 if there is not enough
   space in the buffer.
*/
ULONG prExpandPipeName(ULONG cbBuf, PCHAR pcBuf, PSZ pszName);

// Create PIPER object. Returns PRRC_xxxxx.
ULONG prInit(PPIPER *ppPiper, PPRINIT pInit);

// Destroy PIPER object.
VOID prDone(PPIPER pPiper);

/* This function must be called periodically. It does all the work: connecting
   to the input pipe, reading and transferring data to the server pipes and
   calling user function PRINIT.fnUser.

   fInputOnly is TRUE - an event on the semaphore PRINIT.hevInputPipe (if it
   was specified for prInit()) has occurred.
   In any case, this function must be called periodically with the argument
   fInputOnly equal to FALSE for processing data and connections.

   Returns TRUE if the input pipe is connected. */
VOID prProcess(PPIPER pPiper, BOOL fInputOnly);

// Returns TRUE if the input pipe is connected.
BOOL prIsConnected(PPIPER pPiper);

#endif // PIPER_H

