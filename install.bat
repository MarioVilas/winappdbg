@echo off

if "%1"=="" goto Default
if "%1"=="all" goto All
if "%1"=="All" goto All
if "%1"=="/?" goto Help

:Unknown
echo Unsupported version of Python: %1
goto Exit

:Help
echo Installer script for WinAppDbg
echo
echo To install on your default Python version, run:
echo     %0
echo
echo To Install on every available Python version, run:
echo     %0 all
echo
echo Python is assumed to be installed in:
echo     %SystemDrive%\Python2*\       (for 32 bits)
echo     %SystemDrive%\Python2*-x64\   (for 64 bits)
goto Exit

:Default
python setup.py install
goto Exit

:All
if exist %SystemDrive%\Python24\python.exe %SystemDrive%\Python24\python.exe setup.py install
if exist %SystemDrive%\Python25\python.exe %SystemDrive%\Python25\python.exe setup.py install
if exist %SystemDrive%\Python26\python.exe %SystemDrive%\Python26\python.exe setup.py install
if exist %SystemDrive%\Python27\python.exe %SystemDrive%\Python27\python.exe setup.py install
if exist %SystemDrive%\Python25-x64\python.exe %SystemDrive%\Python25-x64\python.exe setup.py install
if exist %SystemDrive%\Python26-x64\python.exe %SystemDrive%\Python26-x64\python.exe setup.py install
if exist %SystemDrive%\Python27-x64\python.exe %SystemDrive%\Python27-x64\python.exe setup.py install
goto Exit

:Exit
