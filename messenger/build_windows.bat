@echo off
REM ============================================================================
REM QGP (Quantum Good Privacy) - Windows Build Script
REM ============================================================================
REM This script clones/updates QGP from GitHub and builds it on Windows
REM
REM Prerequisites:
REM   - Git for Windows installed
REM   - CMake installed
REM   - Visual Studio Build Tools (or full Visual Studio)
REM   - vcpkg installed at C:\vcpkg (or adjust path below)
REM
REM Usage:
REM   build_windows.bat
REM ============================================================================

echo ============================================================================
echo QGP Windows Build Script
echo ============================================================================
echo.

REM Configuration
set "QGP_DIR=C:\qgp"
set "VCPKG_ROOT=C:\vcpkg"
set "BUILD_TYPE=Release"
set "GIT_REPO=https://github.com/nocdem/qgp.git"
set "GIT_BRANCH=main"

REM Check if Git is installed
where git >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git is not installed or not in PATH
    echo.
    echo Please install Git for Windows:
    echo   https://git-scm.com/download/win
    echo.
    echo After installation, open a NEW Command Prompt and run this script again.
    echo.
    pause
    exit /b 1
)

REM Check if CMake is installed
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake is not installed or not in PATH
    echo.
    echo Please install CMake using one of these methods:
    echo.
    echo   1. Download installer (recommended):
    echo      https://cmake.org/download/
    echo      ^(Download "Windows x64 Installer" - cmake-X.XX.X-windows-x86_64.msi^)
    echo      IMPORTANT: During installation, select "Add CMake to system PATH"
    echo.
    echo   2. Using winget (Windows 10/11):
    echo      winget install Kitware.CMake
    echo.
    echo   3. Using Chocolatey:
    echo      choco install cmake
    echo.
    echo After installation, open a NEW Command Prompt and run this script again.
    echo.
    pause
    exit /b 1
)

REM Check if vcpkg exists
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
    echo [WARNING] vcpkg not found at %VCPKG_ROOT%
    echo vcpkg is optional but recommended for dependency management
    echo.
    set "VCPKG_TOOLCHAIN="
) else (
    echo [OK] Found vcpkg at %VCPKG_ROOT%
    set "VCPKG_TOOLCHAIN=-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake"
)

echo.
echo ============================================================================
echo Step 1: Clone or Update Repository
echo ============================================================================
echo.

if exist "%QGP_DIR%\.git" (
    echo Repository exists, updating...
    cd /d "%QGP_DIR%"

    echo Fetching latest changes from remote...
    git fetch origin

    echo Checking out %GIT_BRANCH% branch...
    git checkout %GIT_BRANCH%

    echo Pulling latest changes...
    git pull origin %GIT_BRANCH%

    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to update repository
        exit /b 1
    )
    echo [OK] Repository updated successfully
) else (
    echo Repository does not exist, cloning...

    if exist "%QGP_DIR%" (
        echo [WARNING] Directory %QGP_DIR% exists but is not a git repository
        echo Removing directory...
        rmdir /S /Q "%QGP_DIR%"
    )

    echo Cloning from %GIT_REPO%...
    git clone %GIT_REPO% "%QGP_DIR%"

    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to clone repository
        exit /b 1
    )

    cd /d "%QGP_DIR%"
    echo Checking out %GIT_BRANCH% branch...
    git checkout %GIT_BRANCH%

    echo [OK] Repository cloned successfully
)

echo.
echo ============================================================================
echo Step 2: Clean Build Directory
echo ============================================================================
echo.

if exist "%QGP_DIR%\build" (
    echo Removing old build directory...
    rmdir /S /Q "%QGP_DIR%\build"
    if %ERRORLEVEL% NEQ 0 (
        echo [WARNING] Could not remove old build directory
        echo This may cause issues, but continuing...
    )
)

echo Creating fresh build directory...
mkdir "%QGP_DIR%\build"
cd /d "%QGP_DIR%\build"

echo [OK] Build directory ready

echo.
echo ============================================================================
echo Step 3: Configure with CMake
echo ============================================================================
echo.

echo Running CMake configuration...
echo Build Type: %BUILD_TYPE%
if defined VCPKG_TOOLCHAIN (
    echo vcpkg: Enabled
    cmake .. %VCPKG_TOOLCHAIN% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
) else (
    echo vcpkg: Not available
    cmake .. -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
)

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake configuration failed
    echo.
    echo Possible issues:
    echo   - Visual Studio not installed
    echo   - CMake version too old
    echo   - Missing dependencies
    echo.
    echo Please check the error messages above
    exit /b 1
)

echo [OK] CMake configuration successful

echo.
echo ============================================================================
echo Step 4: Build with CMake
echo ============================================================================
echo.

echo Building QGP (%BUILD_TYPE%)...
cmake --build . --config %BUILD_TYPE%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed
    echo Please check the error messages above
    exit /b 1
)

echo [OK] Build successful

echo.
echo ============================================================================
echo Build Complete!
echo ============================================================================
echo.
echo QGP has been built successfully!
echo.
echo Executable location:
echo   %QGP_DIR%\build\%BUILD_TYPE%\qgp.exe
echo.
echo To test the build:
echo   cd %QGP_DIR%\build\%BUILD_TYPE%
echo   qgp.exe --version
echo.
echo To add to PATH (run as Administrator):
echo   setx /M PATH "%%PATH%%;%QGP_DIR%\build\%BUILD_TYPE%"
echo.
echo ============================================================================

REM Optional: Run a quick test
echo.
set /p RUNTEST="Run version check test? (Y/N): "
if /i "%RUNTEST%"=="Y" (
    echo.
    echo Running: qgp.exe --version
    echo ----------------------------------------
    "%QGP_DIR%\build\%BUILD_TYPE%\qgp.exe" --version
    if %ERRORLEVEL% EQU 0 (
        echo ----------------------------------------
        echo [OK] QGP is working!
    ) else (
        echo ----------------------------------------
        echo [WARNING] QGP test failed
    )
)

echo.
echo Press any key to exit...
pause >nul
