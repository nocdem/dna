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
timeout /t 2 /nobreak >nul

REM Kill any remaining processes and wait for them to terminate
echo DEBUG: Killing any remaining processes...
taskkill /F /IM dna_messenger_gui.exe >nul 2>&1
taskkill /F /IM dna_messenger.exe >nul 2>&1

REM Wait up to 15 seconds for processes to terminate
echo DEBUG: Waiting for processes to terminate...
set COUNTER=0
:WAIT_LOOP
tasklist /FI "IMAGENAME eq dna_messenger_gui.exe" 2>nul | find /I "dna_messenger_gui.exe" >nul
if %errorlevel% equ 0 (
    set /a COUNTER+=1
    if %COUNTER% gtr 15 (
        echo WARNING: Process still running after 15 seconds, forcing shutdown...
        taskkill /F /IM dna_messenger_gui.exe >nul 2>&1
        timeout /t 2 /nobreak >nul
        goto WAIT_DONE
    )
    timeout /t 1 /nobreak >nul
    goto WAIT_LOOP
)
:WAIT_DONE
echo DEBUG: All processes terminated

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
    echo WARNING: Not a git repository (no .git directory found)
    echo Current directory: %CD%
    echo.
    echo Falling back to install_windows.bat...
    echo.

    REM Check if install_windows.bat exists
    if exist install_windows.bat (
        echo Running install_windows.bat...
        call install_windows.bat
        exit /b %errorlevel%
    ) else (
        echo ERROR: install_windows.bat not found
        echo Cannot update without git repository or install script
        echo.
        pause
        exit /b 1
    )
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
