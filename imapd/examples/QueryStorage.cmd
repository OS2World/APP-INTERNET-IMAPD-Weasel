/*
  Example QUERYSTORAGE.

  Returns imapd responce: information about all storage sizes (total size of
  ".MSG" files in bytes) and limits configured by imapd-quotas.xml.

 */


/* Load rxsf.dll */
if RxFuncQuery( "rxsfLoadFuncs" ) = 1 then
do
  call RxFuncAdd "rxsfLoadFuncs", "rxsf", "rxsfLoadFuncs"
  call rxsfLoadFuncs
end


/* Send request to the runned imapd.

   Arguments:
     - Local socket name ("imapd") or socket handle.
     - Request.
     - The name of the stem variable to place the result body.
   Return: responce result.
*/

result = rxsfRequest( "imapd", "QUERYSTORAGE", "data" )


/* Display result string with MailRoot path. */

say result

if word( result, 1 ) == "+OK" then         /* First word is "+OK" - success. */
do
  /* Display responce body lines:
       - Object type ("MailRoot" OR "Domain" OR "User").
       - Object name, ':'.
       - Size(s) in bytes, '/'
         For "User" object we have two sizes: INBOX,folders
         Where folders is all other imap mailboxes.
       - Limits (bytes OR "unlimited") and optional "(non-blocked)" flag.
   */

  do i = 1 to data.0
    say data.i
  end
end

EXIT
