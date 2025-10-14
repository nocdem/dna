@echo off
setlocal

echo ============================================================================
echo DNA Messenger - Windows Installation
echo ============================================================================
echo.

set DNA_DIR=C:\dna-messenger
set BUILD_TYPE=Release

where git >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git not found in PATH
    pause
    exit /b 1
)

where cmake >nul 2>&1
if errorlevel 1 (
    echo ERROR: CMake not found in PATH
    pause
    exit /b 1
)

echo Step 1: Update repository
echo.
cd /d %DNA_DIR%
git pull origin main
echo.

echo Step 2: Clean build
echo.
if exist build rmdir /S /Q build
mkdir build
cd build
echo.

echo Step 3: Configure with CMake
echo.
if exist C:\vcpkg\scripts\buildsystems\vcpkg.cmake (
    echo Using vcpkg toolchain...
    cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -A x64
) else (
    echo Using standard CMake...
    cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
)
if errorlevel 1 goto ERROR
echo.

echo Step 4: Build
echo.
cmake --build . --config %BUILD_TYPE% -j
if errorlevel 1 goto ERROR

echo.
echo ============================================================================
echo SUCCESS!
echo ============================================================================
echo.
echo Executable: %DNA_DIR%\build\%BUILD_TYPE%\dna_messenger.exe
echo.
pause
exit /b 0

:ERROR
echo.
echo ============================================================================
echo BUILD FAILED
echo ============================================================================
echo.
echo Install vcpkg dependencies:
echo   cd C:\vcpkg
echo   .\vcpkg install openssl:x64-windows libpq:x64-windows
echo.
pause
exit /b 1
