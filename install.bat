@echo off
setlocal enableextensions

if "%1"=="" goto Default
if "%1"=="all" goto All
if "%1"=="All" goto All
goto Help

:Help
echo Installer script for WinAppDbg
echo.
echo To install on your default Python version, run:
echo     %0
echo.
echo To Install on every available Python version, run:
echo     %0 all
echo.
echo Python interpreters detected in this machine:
for /f "delims=#" %%P in (install.cfg) do cmd /c if exist "%%P" echo     %%P
goto Exit

:Default
python setup.py install
python -c "import winappdbg; from winappdbg import *; from winappdbg import sql; print 'Installation successful.'"
goto Exit

:All
echo Installing...
echo.
for /f "delims=#" %%P in (install.cfg) do (
    cmd /c if exist "%%P" "%%P" setup.py install
    cmd /c if exist "%%P" echo.
)
echo -------------------------------------------------------------------------------
echo.
echo Testing installation success...
echo.
for /f "delims=#" %%P in (install.cfg) do (
    cmd /c if exist "%%P" "%%P" -c "print 'Interpreter: %%P'; import winappdbg; from winappdbg import *; from winappdbg import sql; print 'OK'"
    cmd /c if exist "%%P" echo.
)
echo Done.
goto Exit

:Exit
