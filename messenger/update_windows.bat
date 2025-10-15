@echo off
REM DNA Messenger Windows Updater
REM This script runs AFTER the GUI has closed

echo =========================================
echo  DNA Messenger Updater
echo =========================================
echo.
echo DEBUG: Script location: %~dp0
echo DEBUG: Current directory: %CD%
echo.
echo Waiting for application to close...
timeout /t 3 /nobreak >nul

REM Kill any remaining processes
echo DEBUG: Killing any remaining processes...
taskkill /F /IM dna_messenger_gui.exe >nul 2>&1
taskkill /F /IM dna_messenger.exe >nul 2>&1
timeout /t 2 /nobreak >nul

REM Change to the directory where this script is located
echo DEBUG: Changing to script directory...
cd /d "%~dp0"
if %errorlevel% neq 0 (
    echo ERROR: Could not change to script directory: %~dp0
    echo.
    pause
    exit /b 1
)

echo DEBUG: Now in directory: %CD%
echo.

echo DEBUG: Checking for .git directory...
if not exist .git (
    echo ERROR: Not a git repository (no .git directory found)
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)
echo DEBUG: .git directory found

echo.
echo Updating repository from GitHub...
git pull origin main
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Git pull failed (exit code: %errorlevel%)
    echo.
    pause
    exit /b 1
)
echo DEBUG: Git pull successful

echo.
echo DEBUG: Checking build directory...
if not exist build (
    echo ERROR: build directory not found
    echo.
    pause
    exit /b 1
)
echo DEBUG: build directory exists

echo.
echo Cleaning old binaries...
if exist build\gui\Release\dna_messenger_gui.exe (
    echo DEBUG: Deleting build\gui\Release\dna_messenger_gui.exe
    del /F /Q build\gui\Release\dna_messenger_gui.exe 2>nul
)
if exist build\Release\dna_messenger.exe (
    echo DEBUG: Deleting build\Release\dna_messenger.exe
    del /F /Q build\Release\dna_messenger.exe 2>nul
)

timeout /t 1 /nobreak >nul

echo DEBUG: Changing to build directory...
cd build
echo DEBUG: Now in: %CD%

echo.
echo Rebuilding project (this may take a few minutes)...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Build failed (exit code: %errorlevel%)
    echo Check the output above for errors
    echo.
    pause
    exit /b 1
)
echo DEBUG: Build successful

echo.
echo =========================================
echo  Update Complete!
echo =========================================
echo.
echo You can now restart DNA Messenger GUI
echo.
pause

REM Optional: Auto-restart GUI
REM start "" "C:\dna-messenger\build\gui\Release\dna_messenger_gui.exe"
