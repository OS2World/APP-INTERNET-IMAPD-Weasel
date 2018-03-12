/*
  Inform IMAPD about changes in the user home directory (INBOX).

  NOTIFY request example.
 */

parse arg userObj

if userObj = "" then
do
  say "Usage:"
  say "  UserDirChanged.cmd D:\MailRoot\User\newFile.MSG"
  say "  UserDirChanged.cmd D:\MailRoot\User"
  say "  UserDirChanged.cmd local_email"
  exit
end

/* Load rxsf.dll */
if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
do
  call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"
  call rxsfLoadFuncs
end


result = rxsfRequest( "imapd", "NOTIFY 0 " || userObj )

say result

EXIT
