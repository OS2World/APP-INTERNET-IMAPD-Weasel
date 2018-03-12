/******************************************************************************
 *
 *  exceptq.h - exceptq public header - v7.1
 *
 *  Parts of this file are
 *    Copyright (c) 2000-2010 Steven Levine and Associates, Inc.
 *    Copyright (c) 2010-2011 Richard L Walsh
 *
 *
 *****************************************************************************/

#ifndef EXCEPTQ_H_INCLUDED
  #define EXCEPTQ_H_INCLUDED

#if !defined(__OS2_H__) && !defined(OS2_INCLUDED) && !defined(_OS2_H) && !defined(_OS2EMX_H)
#error os2.h must be #included before exceptq.h
#endif

#ifdef __cplusplus
  extern "C" {
#endif

/******************************************************************************

Function Arguments
------------------

These are the arguments used by InstallExceptq(), UninstallExceptq(), and
SetExceptqOptions().  See below for info on the helper function LoadExceptq().

* pExRegRec:  a pointer to an EXCEPTIONREGISTRATIONRECORD structure.  This
    structure *must* be on the stack and *must* persist for the life of the
    thread.  You do not have initialize it - Exceptq will do that for you.

* pszOptions:  a string containing zero or more 1- or 2-character options.
    If you don't want to change the default options (or provide a report
    info string), you can pass a null pointer or a null string.

* pszReportInfo:  a string of up to 80 characters (including the null) that
    will be displayed at the top of Exceptq's report.  It can be used to
    display the app's version number or build ID.  If you supply a string
    to InstallExceptq(), you must also include the 'I' option in pszOptions;
    it is not needed when calling SetExceptqOptions().  If you don't want
    to provide a string, you can pass a null pointer or a null string.

  Important:  InstallExceptq() uses the arguments in pszOptions and
    pszReportInfo the first time you call it and *ignores* them on
    subsequent calls. Consequently, you should supply them in main()
    and set them to null in your threadproc(s).  If this isn't possible,
    you can use SetExceptqOptions() to set or reset them at any time.

  Note:  when calling SetExceptqOptions(), pass a null pointer or null
    string in either pszOptions or pszReportInfo to leave that setting
    unchanged.  To reset options to their default or erase the current
    report info string, pass a string containing only whitespace (" ").
    You do not need to use the 'I' option to (re)set pszReportInfo.

Options
-------
All options (except 'I') can also be set in the environment using
'SET EXCEPTQ=' and override conflicting options set by the application.
For best results, do not change Exceptq's default options;  instead,
ask your users to change them via the environment variable _if needed_.

Report Verbosity:
* VV  very verbose
* V   verbose
* C   concise (default)
* T   terse
* TT  terribly terse

User Options:
* B   beep (default)  - alert the user when creating a report
* Q   quiet           - don't beep when creating a report

* Y   yes (default)   - create a report
* N   no              - don't create a report

* D   debug           - report debug and fatal exceptions
* F   fatal (default) - report fatal exceptions only

App-only Option:
* I   info           - pszReportInfo contains a valid string to display


Exceptq Debug Exception
-----------------------

You can force Exceptq to generate a report at any point in your program by
raising the non-fatal EXCEPTQ_DEBUG_EXCEPTION. If exceptq.dll is present, it
will capture a snapshot of the app at the time you call DosRaiseException();
if not, the exception will be ignored.  In either case, the app will continue
executing.  To have the program terminate instead, set the EH_NONCONTINUABLE
flag in EXCEPTIONREPORTRECORD.fHandlerFlags.

Because this feature can generate a lot unnecessary reports it is disabled
by default.  Instead of enabling it when you call InstallExceptq(), have your
users enable it with 'SET EXCEPTQ=D' when needed.  To avoid creating too much
output when it is enabled, consider using a static flag or counter to limit
the number of times each exception is raised.

To increase the reports' usefulness, you can pass debug info to the handler
using the EXCEPTIONREPORTRECORD.ExceptionInfo[] array.  The data will be
displayed toward the top of the report in either of two formats:

* preformatted:  set ExceptionInfo[0] to zero, then place up to 3 arguments in
  the remaining ExceptionInfo elements starting at index number 1.  Be sure to
  set EXCEPTIONREPORTRECORD.cParameters correctly:  if you want to display two
  values (in [1] & [2]), set cParameters to 3.  The report will look like this:
    Cause:    Program requested an Exceptq debug report
    Debug:    [1]= 00000005  [2]= 00040001  [3]= 26030a32

* your format:  put a pointer to a printf format string in ExceptionInfo[0],
  then put your arguments in the remaining array elements starting at index
  number 1.  If you need more than 3 arguments, just extend the array beyond
  the end of the structure.  Regardless of the number of arguments, set
  EXCEPTIONREPORTRECORD.cParameters to 2.  The address of ExceptionInfo[1]
  will be passed to vprintf() as a pointer to the array of arguments.  The
  report will look something like this:
    Cause:    Program requested an Exceptq debug report
    Debug:    initialize - rv= 5  flags= 40001  file= places.sqlite


******************************************************************************/

/**
 * Non-fatal exception code ("XQxq") to force an Exceptq report
 */
#define EXCEPTQ_DEBUG_EXCEPTION   0x71785158


/**
 * Install/Uninstall MyHandler() - 32-bit entrypoint
 */
APIRET   APIENTRY   InstallExceptq(EXCEPTIONREGISTRATIONRECORD* pExRegRec,
                                   const char* pszOptions,
                                   const char* pszReportInfo);

typedef APIRET APIENTRY _INSTEXQ(EXCEPTIONREGISTRATIONRECORD*,
                                 const char*, const char*);
typedef _INSTEXQ* PINSTEXQ;

#define UninstallExceptq(pExRegRec) DosUnsetExceptionHandler((pExRegRec))


/**
 * Set/reset options & report info after InstallExceptq() has been called
 */
void     APIENTRY   SetExceptqOptions(const char* pszOptions,
                                      const char* pszReportInfo);

/**
 * The exception handler
 */
ULONG    APIENTRY   MYHANDLER(EXCEPTIONREPORTRECORD* pExRepRec,
                              EXCEPTIONREGISTRATIONRECORD* pExRegRec,
                              CONTEXTRECORD* pCtxRec,
                              void* p);


/**
 * Install/Uninstall MyHandler() - 16-bit entrypoints
 * Use #define INCL_EXCEPTQ16 to include these prototypes for the
 * 16-bit entrypoints;  the entrypoints themselves are always present
 * in the dll regardless of the #define.
 */
#ifdef INCL_EXCEPTQ16
APIRET16 APIENTRY16 SETEXCEPT(EXCEPTIONREGISTRATIONRECORD* _Seg16 pExRegRec);
APIRET16 APIENTRY16 UNSETEXCEPT(EXCEPTIONREGISTRATIONRECORD* _Seg16 pExRegRec);
#endif


/**
 * Force the app to exit via a forced trap
 */
void     APIENTRY   FORCEEXIT(void);

/*****************************************************************************/
#ifdef INCL_LOADEXCEPTQ

BOOL    LoadExceptq(EXCEPTIONREGISTRATIONRECORD* pExRegRec,
                    const char* pOpts, const char* pInfo);

/**
 * The following sample function loads and installs Exceptq dynamically
 * so your application can use it without being dependent on its presence.
 * By design, it will fail if it finds a version of Exceptq earlier than v7.0.
 * You can either copy it into your source or you can #define INCL_LOADEXCEPTQ
 * in *one* of your files to have it included.  It assumes that you have
 * #defined INCL_DOS and #included <os2.h> and <string.h> *before* exceptq.h.
 *
 * Important:  for each thread your app creates, you must call this function
 * on entry and UninstallExceptq() on exit.  Typically, LoadExceptq() should
 * be the first line of code in main() and each threadproc. UninstallExceptq()
 * should be called immediately before exiting main() and each threadproc.
 */

BOOL    LoadExceptq(EXCEPTIONREGISTRATIONRECORD* pExRegRec,
                    const char* pOpts, const char* pInfo)
{
  static BOOL      fLoadTried = FALSE;
  static PINSTEXQ  pfnInstall = 0;

  HMODULE   hmod = 0;
  char      szFailName[16];

  /* Make only one attempt to load the dll & resolve the proc address. */
  if (!fLoadTried) {
    fLoadTried = TRUE;

    /* If the dll can't be found on the LIBPATH, look for it in the
     * exe's directory (which may not be the current directory).
     */
    if (DosLoadModule(szFailName, sizeof(szFailName), "EXCEPTQ", &hmod)) {
      PPIB      ppib;
      PTIB      ptib;
      char *    ptr;
      char      szPath[CCHMAXPATH];

      DosGetInfoBlocks(&ptib, &ppib);
      if (DosQueryModuleName(ppib->pib_hmte, CCHMAXPATH, szPath) ||
          (ptr = strrchr(szPath, '\\')) == 0)
        return FALSE;

      strcpy(&ptr[1], "EXCEPTQ.DLL");
      if (DosLoadModule(szFailName, sizeof(szFailName), szPath, &hmod))
        return FALSE;
    }

    /* If the proc address isn't found (possibly because an older
     * version of exceptq.dll was loaded), unload the dll & exit.
     */
    if (DosQueryProcAddr(hmod, 0, "InstallExceptq", (PFN*)&pfnInstall)) {
      DosFreeModule(hmod);
      return FALSE;
    }
  }

  /* Ensure we have the proc address. */
  if (!pfnInstall)
    return FALSE;

  /* Call InstallExceptq().  It really shouldn't fail, so if
   * it does, zero-out the address to avoid further problems.
   */
  if (pfnInstall(pExRegRec, pOpts, pInfo)) {
    pfnInstall = 0;
    return FALSE;
  }

  return TRUE;
}

#endif
/*****************************************************************************/

#ifdef __cplusplus
  }
#endif

#endif /* EXCEPTQ_H_INCLUDED */

