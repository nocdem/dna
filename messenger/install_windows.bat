@echo off
REM ============================================================================
REM DNA Messenger - Windows Installation Script
REM ============================================================================
REM This script installs DNA Messenger on Windows
REM
REM Prerequisites:
REM   - Git for Windows
REM   - CMake
REM   - Visual Studio Build Tools (or full Visual Studio)
REM   - PostgreSQL client library (libpq)
REM
REM Usage:
REM   install_windows.bat
REM ============================================================================

echo ============================================================================
echo DNA Messenger - Windows Installation
echo ============================================================================
echo.

REM Configuration
set "DNA_DIR=C:\dna-messenger"
set "BUILD_TYPE=Release"
set "GIT_REPO=https://github.com/nocdem/dna-messenger.git"
set "GIT_BRANCH=main"

REM Check if Git is installed
where git >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git is not installed or not in PATH
    echo.
    echo Please install Git for Windows:
    echo   https://git-scm.com/download/win
    echo.
    pause
    exit /b 1
)

REM Check if CMake is installed
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake is not installed or not in PATH
    echo.
    echo Please install CMake:
    echo   https://cmake.org/download/
    echo   Select "Add CMake to system PATH" during installation
    echo.
    echo Or using winget:
    echo   winget install Kitware.CMake
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================================================
echo Step 1: Clone or Update Repository
echo ============================================================================
echo.

if exist "%DNA_DIR%\.git" (
    echo Repository exists, updating...
    cd /d "%DNA_DIR%"

    REM Check for local changes
    git diff --quiet
    if %ERRORLEVEL% NEQ 0 (
        echo [WARNING] Local changes detected, stashing...
        git stash save "Auto-stash by installer"
    )

    git fetch origin
    git checkout %GIT_BRANCH%
    git pull origin %GIT_BRANCH%
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to update repository
        exit /b 1
    )
    echo [OK] Repository updated
) else (
    echo Cloning DNA Messenger...
    if exist "%DNA_DIR%" (
        rmdir /S /Q "%DNA_DIR%"
    )
    git clone %GIT_REPO% "%DNA_DIR%"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to clone repository
        exit /b 1
    )
    cd /d "%DNA_DIR%"
    git checkout %GIT_BRANCH%
    echo [OK] Repository cloned
)

echo.
echo ============================================================================
echo Step 2: Install Dependencies
echo ============================================================================
echo.

echo Checking for PostgreSQL client library...
echo.
echo DNA Messenger requires PostgreSQL libpq (client library only).
echo.
echo Installation options:
echo   1. PostgreSQL installer (includes libpq):
echo      https://www.postgresql.org/download/windows/
echo.
echo   2. vcpkg (recommended for developers):
echo      vcpkg install libpq:x64-windows
echo      vcpkg integrate install
echo.
echo   3. Pre-built binaries:
echo      Download from https://www.postgresql.org/ftp/odbc/versions/msi/
echo.
set /p CONTINUE="Have you installed libpq? (Y/N): "
if /i not "%CONTINUE%"=="Y" (
    echo.
    echo Please install libpq first, then run this script again.
    pause
    exit /b 1
)

echo.
echo ============================================================================
echo Step 3: Clean Build Directory
echo ============================================================================
echo.

if exist "%DNA_DIR%\build" (
    echo Removing old build...
    rmdir /S /Q "%DNA_DIR%\build"
)

echo Creating fresh build directory...
mkdir "%DNA_DIR%\build"
cd /d "%DNA_DIR%\build"
echo [OK] Build directory ready

echo.
echo ============================================================================
echo Step 4: Configure with CMake
echo ============================================================================
echo.
REM Check if vcpkg toolchain file exists
if exist "C:\vcpkg\scripts\buildsystems\vcpkg.cmake" (
    echo Found vcpkg toolchain at C:\vcpkg\scripts\buildsystems\vcpkg.cmake
    echo Running cmake with vcpkg toolchain...
    echo.
    cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -A x64
) else (
    echo vcpkg toolchain not found at C:\vcpkg\scripts\buildsystems\vcpkg.cmake
    echo Trying standard CMake - may fail if OpenSSL not found
    echo.
    cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] CMake configuration failed
    echo.
    echo Possible issues:
    echo   - Visual Studio not installed
    echo   - PostgreSQL libpq not found
    echo   - OpenSSL not found
    echo.
    echo To fix, install dependencies with vcpkg:
    echo   1. Install vcpkg if not already installed:
    echo      cd C:\
    echo      git clone https://github.com/Microsoft/vcpkg.git
    echo      cd vcpkg
    echo      .\bootstrap-vcpkg.bat
    echo      .\vcpkg integrate install
    echo.
    echo   2. Install dependencies:
    echo      cd C:\vcpkg
    echo      .\vcpkg install openssl:x64-windows libpq:x64-windows
    echo.
    echo   3. Run this script again
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] CMake configuration successful

echo.
echo ============================================================================
echo Step 5: Build DNA Messenger
echo ============================================================================
echo.

echo Building...
cmake --build . --config %BUILD_TYPE% -j

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed
    pause
    exit /b 1
)

echo [OK] Build successful

echo.
echo ============================================================================
echo Installation Complete!
echo ============================================================================
echo.
echo DNA Messenger has been built successfully!
echo.
echo Executable location:
echo   %DNA_DIR%\build\%BUILD_TYPE%\dna_messenger.exe
echo.
echo To run DNA Messenger:
echo   cd %DNA_DIR%\build\%BUILD_TYPE%
echo   dna_messenger.exe
echo.
echo On first run, configure server (option 3):
echo   - DNA Server: ai.cpunk.io
echo   - Port: 5432 (default)
echo   - Database: dna_messenger (default)
echo.
echo For local testing, use "localhost" as server
echo.
echo ============================================================================

echo.
pause
