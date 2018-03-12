/*
  Example QUERYSIZE.

  Returns imapd responce: information about "user home" directory size.
  Also, it returns information about mail storage and domain directory sizes.

  "size" - the total size of ".MSG" files in bytes, slash, limit in bytes.
 */


/* Users whose information we want to receive.
   Can be specified in different forms: e-mail address, path to the home
   directory relative MailRoot or full home directory pathname.

   Here we request information about the same user three times.
 */
users.0 = 3
users.1 = "digi@example.domain"
users.2 = "example.domain\digi"
users.3 = "D:\mail\example.domain\digi"


/* Load rxsf.dll */
if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
do
  call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"
  call rxsfLoadFuncs
end


/* Open single connection to imapd for all our requests. */
sockHandle = rxsfOpen( "imapd" )
if sockHandle = -1 then
do
  say "Could not connect to IMAPD. Is it runned?"
  exit
end

do i = 1 to users.0

  /* Send request to the runned imapd for the next user. */
  request = "QUERYSIZE " || users.i
  result = rxsfRequest( sockHandle, request )

  say
  say "Request: " || request

  /* Responce: +OK [MainRootSize DomainSize InboxSize FoldersSize] */
  say "Result: " || result
end

/* Close connection to imapd. */
call rxsfClose sockHandle
