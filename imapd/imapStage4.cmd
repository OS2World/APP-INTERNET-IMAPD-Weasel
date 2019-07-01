/*
  Weasel stage 4 filter for the IMAP4 server.
  Sends notification to IMAPD of the received file.
*/


/* ************************************************************* */
/*                        User settings                          */
/* ************************************************************* */

/* Your stage 4 filter (will be runned first). */
userFilter = ""

/* Debug information will be displayed if debugMode is equal to 1. */
debugMode = 1


/* ************************************************************* */

/* Set trap conditions. */
signal on Error
signal on Failure name Error
signal on Halt
signal on Syntax name Error

pipeName      = "imapd"
socketName    = "imapd"
usePipe       = 0
socketHandle  = -1
global        = "pipeName socketName usePipe socketHandle debugMode"

parse arg nameFile" "msgFile
if msgFile = "" then
  call die "This code should be called from Weasel as stage 4 filter."

if RxFuncQuery('SysLoadFuncs') = 1 then
do
  call RxFuncAdd 'SysLoadFuncs', 'RexxUtil', 'SysLoadFuncs'
  call SysLoadFuncs
end


/* ************************************************************* */

/*
   Run user filter
*/

if symbol( "userFilter" ) = "VAR" & userFilter \= "" then
do
  cmd = userFilter || " " || nameFile || " " || msgFile
  call debug "Run: " || cmd

  "@cmd /c " || cmd
  res = rc
  call debug "User filter result code: " || res
end
else
  res = 0

/*
   If message was not filtered by the user filter then send request to imapd.
*/

if res < 2 | res = 16 then
do

  /* Load Weasel nameFile. */

  /* Read client network address, EHLO, FROM */
  do _cnt = 1 by 1
    nameSender._cnt = linein( nameFile )
    if nameSender._cnt = "" then
      leave
  end
  nameSender.0 = _cnt - 1

  /* Read recepients list */
  _cnt = 0
  do while lines( nameFile ) \= 0
    line = linein( nameFile )
    if line = "" then iterate

    _cnt = _cnt + 1
    nameRcpt._cnt = line
  end
  nameRcpt.0 = _cnt

  drop _cnt
  call stream nameFile, "C", "close"
  /*
    nameFile loaded.
      nameSender.0 = 3
      nameSender.1 - [client_ip] client_hostname
      nameSender.2 - HELO/EHLO
      nameSender.3 - MAIL FROM address
      Stem nameRcpt - List of recipients
   */


  /* Check quotas and notify IMAPD about changes in mailboxes. */


  if imapdOpen() then          /* Connect to IMAPD. */
  do

    /* Get MAIL FROM address. */
    mailFrom = nameSender.3
    if left( mailFrom, 1 ) = "<" then
      parse var mailFrom "<" mailFrom ">" _cntOk

    rcptOk.0 = 0
    do _idx = 1 to nameRcpt.0              /* For the each recepient listed
                                              in nameFile. */
      /*
        Check the quota.

        Request to runned IMAPD: CHKAVAILSIZE - disk quota check.
        Arguments: object new_msg [notify_to]

        object    - local user email OR full pathname to user home directory OR
                    path relative to MailRoot,
        new_msg   - received message file for user,
        notify_to - e-mail, who should be notified by automatic message (sender
                    of new_msg).

        Responces:
          +OK no error         - ok, the message can be delivered.
          -ERR internal error  - internal server error (BUG!).
          -ERR not found       - local user not found.
          -ERR excess          - mailbox quota exceeded (no space for the new
                                 message). If we receive this report, then
                                 senders will be notified by automatic message.

        Responce "+OK no error" returns instead "-ERR excess" when the limit is
        exceeded and it is non-blocked user.
      */
      imapRes = imapdRequest( "CHKAVAILSIZE " || nameRcpt._idx || " " ,
                              || msgFile || " " || mailFrom )
      if imapRes = "-ERR excess" then
      do
        call log "Disk quota excess for " || nameRcpt._idx
        fExcess = 1
        iterate
      end

      if imapRes \= "-ERR not found" then
      do
        /* Local recepient - notify imapd about changes in the mailbox:
           if Weasel log pipe is not available the user home directory
           (INBOX) will be checked for changes in 3 sec.

           Successful responses:
             +OK fixed     - Operation completed
             +OK delayed   - Operation will be performed after the time expires.
             +OK rejected  - IMAPD is connected to Weasel pipe, this request is
                             redundant.
        */

        imapRes = imapdRequest( "NWPNOTIFY 3 " || nameRcpt._idx )
      end
      
      /* Add a recipient to a new list of recipients. */
      rcptOk.0 = rcptOk.0 + 1
      call value "rcptOk." || rcptOk.0, nameRcpt._idx

    end  /* do _idx = 1 to nameRcpt.0 */

    call imapdClose                 /* Close connection to imapd. */


    if nameRcpt.0 \= rcptOk.0 then
    do
      /* The number of recipients has changed - disk quota excess for somebody
         of recepients. Create a new nameFile (exclude recepients). */

      call debug "Rebuild namefile " || nameFile
      call SysFileDelete nameFile

      do _idx = 1 to nameSender.0
        call lineout nameFile, nameSender._idx
      end

      call lineout nameFile, ""

      /* List all recepients who can accept new letter. */
      do _idx = 1 to rcptOk.0
        call lineout nameFile, rcptOk._idx
      end
      call stream nameFile, "C", "close"

      res = 1  /* Reconstruct the list of recipients from the namefile. */

    end  /* if rcptExcess.0 \= 0 then */

  end  /* if imapdOpen() then */

end  /* if res < 2 | res = 16 then */


call log "Result code for Weasel: " || res

return res



/* ************************************************************* */
/*          IMAPD control interface universal routines           */
/* ************************************************************* */

/* imapdOpen()

   Open pipe (global variable usePipe is not 0) or socket (usePipe is 0).
   Returns 0 if an error occurred or 1 if successful.
*/
imapdOpen: procedure expose (global)
  if symbol( "pipeName" ) = "VAR" then
  do
    /* Use pipe interface if variable pipeName is set. */

    /* Expand the pipe name according to the system requirements. */
    if translate( left( pipeName, 6 ) ) \= "\PIPE\" then
      pipeName = "\PIPE\" || pipeName

    rc = stream( pipeName, "c", "open" )
    if left( rc, 6 ) = "READY:" then
    do
      call debug "Pipe " || pipeName || " is open"
      usePipe = 1
      return 1
    end

    if left( rc, 9 ) = "NOTREADY:" then
    do
      rc = substr( rc, 10 )
      select
        when rc = 231 then       /* ERROR_PIPE_BUSY */
          rc = rc || ", pipe is busy"
   
        when rc = 3 then         /* ERROR_PATH_NOT_FOUND  */
          rc = rc || ", pipe does not exist"
      end
    end
    call debug "Pipe " || pipeName || " open error: " || rc

    if symbol( "socketName" ) \= "VAR" then
      return 0

    call debug "Try to open a socket..."

  end
  else if symbol( "socketName" ) \= "VAR" then
    call die "You need to set at least one interface name (pipe or socket)"

  /* Load SpamFilter local socket REXX API */
  if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
  do
    call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"

    if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
      call die "Error loading library RXSF.DLL"
  end

  socketHandle = rxsfOpen( socketName )
  if socketHandle = -1 then
  do
    call debug "Socket " || socketName || " open error"
    return 0
  end

  call debug "Socket " || socketName || " is open"
  usePipe = 0
  return 1


/* imapdClose()

   Closes the socket or pipe opened by function imapdOpen().
*/
imapdClose: procedure expose (global)
  if usePipe then
  do
    call debug "close pipe"
    call stream pipeName, "c", "close"
  end
  else if socketHandle \= -1 then
  do
    call debug "close socket"
    call rxsfClose socketHandle
    socketHandle = -1
  end
  return


/* imapdRequest( request )

   Sends a request and receives a response.
   Returns the spam filter response like: [OK|SPAM|DELAYED|ERROR]:details
*/
imapdRequest: procedure expose (global)
  request = arg( 1 )

  if usePipe then
  do

    /* Send a request through the pipe. */
    call debug "Request: " || request
    rc = lineout( pipeName, request )
    if rc \= 0 then
    do
      call log "Error writing to the pipe " || pipeName
      return "ERROR:Error writing to the pipe"
    end

    /* Get a response from SpamFilter. */
    sfRes = linein( pipeName )

  end   /* if usePipe */
  else
    sfRes = rxsfRequest( socketHandle, request )

  call debug "Answer: " || sfRes
  return sfRes

/* ************************************************************* */

Error:
  parse source . . cmdFile
  say "---"
  say "Signal " || condition( "C" ) || " in " || cmdFile
  say "  Source line " || SIGL || ": " || sourceline( SIGL )

  haveRC = symbol("RC") = "VAR"

  if condition( "D" ) \= '' then
    say "  Description: " || condition( "D" )
  if ( condition( "C" ) = 'SYNTAX' ) & haveRC then
    say "  Error (" || RC || "): " || errortext( RC )
  else if haveRC then
    say "  Error " || RC

  exit 0


/* log( message )
   Prints messages on the screen. */
log: procedure
  say "[imapStage4] " || arg( 1 )
  return

/* debug( message ) */
debug:
  if debugMode = 1 then
    call log "DEBUG " || arg( 1 )
  return

/* die( message ) */
die: procedure
  call log "ERROR " || arg( 1 )
  exit 0
