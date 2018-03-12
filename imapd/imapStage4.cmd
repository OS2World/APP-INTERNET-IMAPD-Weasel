/*
  Weasel stage 4 filter for the IMAP4 server.
  Sends notification to IMAPD of the received file.
*/

/* Your stage 4 filter (will be runned first). */
userFilter = ""

/* Debug is 1 - print debug messages to the screen. */
debug = 1


parse arg nameFile" "msgFile
if msgFile = "" then
do
  say "This code should be called from Weasel as stage 4 filter."
  return 0
end

socketName = "imapd"


/*
   Run user filter
*/

if symbol( "userFilter" ) = "VAR" & userFilter \= "" then
do
  cmd = userFilter || " " || nameFile || " " || msgFile
  if debug = 1 then
    say "[imapStage4] Run: " || cmd

  "@cmd /c " || cmd
  res = rc
  if debug = 1 then
    say "[imapStage4] User filter " || userFilter || " result code: " || res
end
else
  res = 0

/*
   If message was not filtered by the user filter then send request to imapd.
*/

if res < 2 | res == 16 then
do

  /* Load Weasel nameFile. */

  /* Read client network address, EHLO, FROM */
  do _cnt = 1 by 1
    nameSender._cnt = linein( nameFile )
    if nameSender._cnt == "" then
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
  call stream nameFile, "C", "close"


  /* Load local named sockets REXX API */
  if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
  do
    call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"
    call rxsfLoadFuncs
  end

  if RxFuncQuery('SysLoadFuncs') = 1 then
  do
    call RxFuncAdd 'SysLoadFuncs', 'RexxUtil', 'SysLoadFuncs'
    call SysLoadFuncs
  end

  /* Check quotas and notify IMAPD about changes in mailboxes. */

  socket = rxsfOpen( socketName )          /* Connect to IMAPD. */
  if socket \= -1 then
  do

    /* Get MAIL FROM address. */
    mailFrom = nameSender.3
    if left( mailFrom, 1 ) = "<" then
      parse var mailFrom "<" mailFrom ">" _cntOk

    _cntExcess = 0; _cntOk = 0
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
                                 message).

        Responce "+OK no error" returns instead "-ERR excess" when the limit is
        exceeded and it is non-blocked user.
      */
      imapRes = rxsfRequest( socket, "CHKAVAILSIZE " || nameRcpt._idx || ,
                             " " || msgFile || " " || mailFrom )
      if imapRes = "-ERR excess" then
      do
        if debug = 1 then
          say "[imapStage4] Disk quota excess for " || nameRcpt._idx
        _cntExcess = _cntExcess + 1
        rcptExcess._cntExcess = nameRcpt._idx
      end
      else
      do
        if imapRes \= "-ERR not found" then
        do
          /* Local recepient - notify imapd about changes in the mailbox:
             if Weasel log pipe is not available the user home directory
             (INBOX) will be checked for changes in 3 sec. */

          imapRes = rxsfRequest( socket, "NWPNOTIFY 3 " || nameRcpt._idx )
          if debug = 1 then
            say "[imapStage4] imapd notification result for " || ,
                nameRcpt._idx || ": " || imapRes
        end
      
        _cntOk = _cntOk + 1
        rcptOk._cntOk = nameRcpt._idx
      end

    end  /* do _idx = 1 to nameRcpt.0 */

    rcptExcess.0 = _cntExcess
    rcptOk.0 = _cntOk
    drop _cntExcess _cntOk

    call rxsfClose socket                  /* Close connection to imapd. */

/*
    It seems empty recepient list in namefile it's ok...

    if rcptOk.0 == 0 then                  / * No resepients left.        * /
      res = 2  / * Don't deliver the message and return the reply 250 OK. * /
    else
*/
    if rcptExcess.0 \= 0 then
    do
      /* Disk quota excess for somebody of recepients.
         Create a new nameFile (exclude users). */

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

  end  /* if socket \= -1 then */

end  /* if res < 2 | res == 16 then */

return res
