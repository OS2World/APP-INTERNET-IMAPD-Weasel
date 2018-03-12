/*
  Example QUERYFS.

  Returns imapd responce: information about open "user home" objects and
  number of connections (sessions) for each.

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

result = rxsfRequest( "imapd", "QUERYFS", "data" )


if word( result, 1 ) \= "+OK" then      /* First word is not "+OK" - error. */
do
  /* Display result string with error text. */

  say result

end
else
do

  /* Display responce body lines. */

  do i = 1 to data.0
    say data.i
  end

end

EXIT
