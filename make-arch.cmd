@echo off
rem
rem  make-arch.cmd :
rem
rem  1. cleaning,
rem  2. archive sources,
rem  3. compiling,
rem  4. archive binaries,
rem  5. cleaning.

rem Query current date (variable %archdate%).
@%unixroot%\usr\libexec\bin\date +"set archdate=%%Y%%m%%d" >archdate.cmd
call archdate.cmd
del archdate.cmd

set fnSrc=imapd-src-%archdate%.zip
set fnBin=imapd-bin-%archdate%.zip

echo Cleaning.
cd src
make clean >nul
cd ..
@rm %fnSrc% 2>nul

rem Make archives of sources and binaries.

echo Packing sources to %fnSrc%
@rm -f %fnSrc%
7za.exe a -tzip -mx7 -r0 -x!*.zip %fnSrc% .\src .\imapd make-arch.cmd >nul

rem only sources: exit

echo Compiling the project.
cd src
set PUBLICBUILD=YES
make
cd ..

echo Packing binaries to %fnBin%
@rm -f %fnBin%
7za.exe a -tzip -mx7 -r0 -x!imapd\imapd.map %fnBin% .\imapd >nul

echo Cleaning.
cd src
make clean >nul
cd ..
