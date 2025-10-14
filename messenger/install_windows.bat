@echo off
REM ============================================================================
REM DNA Messenger - Windows Installation Script
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo DNA Messenger - Windows Installation
echo ============================================================================
echo.

REM Configuration
set DNA_DIR=C:\dna-messenger
set BUILD_TYPE=Release
set GIT_REPO=https://github.com/nocdem/dna-messenger.git
set GIT_BRANCH=main

REM Check if Git is installed
where git >nul 2>&1
if errorlevel 1 (
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
if errorlevel 1 (
    echo [ERROR] CMake is not installed or not in PATH
    echo.
    echo Please install CMake:
    echo   https://cmake.org/download/
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

    REM Stash any local changes
    git diff --quiet >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] Local changes detected, stashing...
        git stash save "Auto-stash by installer" >nul 2>&1
    )

    git fetch origin
    git checkout %GIT_BRANCH%
    git pull origin %GIT_BRANCH%
    if errorlevel 1 (
        echo [ERROR] Failed to update repository
        pause
        exit /b 1
    )
    echo [OK] Repository updated
) else (
    echo Cloning DNA Messenger...
    if exist "%DNA_DIR%" (
        rmdir /S /Q "%DNA_DIR%"
    )
    git clone %GIT_REPO% "%DNA_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to clone repository
        pause
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

echo DNA Messenger requires:
echo   - PostgreSQL libpq (client library)
echo   - OpenSSL
echo.
echo Installation with vcpkg (recommended):
echo   1. Install vcpkg:
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
set /p CONTINUE="Have you installed dependencies? (Y/N): "
if /i not "%CONTINUE%"=="Y" (
    echo.
    echo Please install dependencies first, then run this script again.
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

REM Check if vcpkg toolchain exists
set VCPKG_CMAKE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

if exist "%VCPKG_CMAKE%" (
    echo Found vcpkg toolchain
    echo Configuring with vcpkg...
    echo.
    cmake .. -DCMAKE_TOOLCHAIN_FILE=%VCPKG_CMAKE% -A x64
) else (
    echo vcpkg not found, using standard CMake
    echo.
    cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
)

if errorlevel 1 (
    echo.
    echo [ERROR] CMake configuration failed
    echo.
    echo Please ensure:
    echo   - Visual Studio Build Tools are installed
    echo   - vcpkg dependencies are installed
    echo   - vcpkg integrate install has been run
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

if errorlevel 1 (
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
