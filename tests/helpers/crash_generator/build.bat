@echo off
echo Building crash_generator.exe...

:: Check if CMake is installed
where cmake >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo CMake is not installed or not in the PATH.
    echo Please install CMake and try again.
    exit /b 1
)

:: Check if Visual Studio is installed
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo Visual Studio not found.
    echo Please install Visual Studio with C++ development tools.
    exit /b 1
)

:: Find latest Visual Studio installation
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set VS_PATH=%%i
)

if not defined VS_PATH (
    echo Visual Studio with C++ tools not found.
    exit /b 1
)

:: Create build directory
if not exist build mkdir build
cd build

:: Generate Visual Studio solution
cmake .. -A x64

:: Build the solution
cmake --build . --config Release

:: Check if build was successful
if %ERRORLEVEL% neq 0 (
    echo Build failed.
    cd ..
    exit /b 1
)

:: Copy the executable to the parent directory
copy /Y Release\crash_generator.exe ..

echo Build completed successfully.
cd ..
exit /b 0