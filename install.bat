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
for /f "delims=" %%P in (install.cfg) do cmd /c if exist "%%P" echo     %%P
goto Exit

:Default
python setup.py install
goto Exit

:All
for /f "delims=" %%P in (install.cfg) do cmd /c if exist "%%P" "%%P" setup.py install
goto Exit

:Exit
