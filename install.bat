@echo off
setlocal EnableExtensions
setlocal EnableDelayedExpansion

if not "%~2" == "" goto Help
if "%~1" == "" goto Default
if "%~1" == "all" goto All
if "%~1" == "All" goto All
if "%~1" == "ALL" goto All
if "%~1" == "/?" goto Help
if "%~1" == "/h" goto Help
if "%~1" == "/H" goto Help
if "%~1" == "-h" goto Help
if "%~1" == "--help" goto Help
if "%~1" == "/help" goto Help
if "%~1" == "/HELP" goto Help
if not exist "%~1" goto NotExistHelp
if exist "%~1\*" goto NotExistHelp
goto Specific

:NotExistHelp
echo Error: Python interpreter not found: %1
echo.
echo Run %0 /? for more help.
goto Exit

:Help
echo Installer script for WinAppDbg
echo.
echo To install on your default Python installation, run:
echo     %0
echo.
echo To install on a specific Python installation, run:
echo     %0 ^<Full path to Python interpreter^>
echo.
echo To Install on every detected Python installation, run:
echo     %0 all
echo.
echo Python installations detected in this machine:
for /f "delims=#" %%P in (install.cfg) do cmd /c if exist %%P echo     %%P
goto Exit

:Default
echo Installing on the default Python installation...
echo.
python setup.py install
python test.py
goto Exit

:Specific
echo Installing on: %~1
echo.
%1 setup.py install
%1 test.py
goto Exit

:All
echo Installing...
echo.
for /f "delims=#" %%P in (install.cfg) do (
    cmd /c if exist %%P echo Interpreter: %%P
    cmd /c if exist %%P %%P setup.py install
    cmd /c if exist %%P echo.
)
echo -------------------------------------------------------------------------------
echo.
echo Testing installation success...
echo.
for /f "delims=#" %%P in (install.cfg) do (
    cmd /c if exist %%P echo Interpreter: %%P
    cmd /c if exist %%P %%P test.py
    cmd /c if exist %%P echo.
)
echo Done.
goto Exit

:Exit
