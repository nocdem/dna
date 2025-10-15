@echo off
REM DNA Messenger Windows Updater
REM This script runs AFTER the GUI has closed

echo DNA Messenger Updater
echo.
echo Waiting for application to close...
timeout /t 3 /nobreak >nul

REM Kill any remaining processes
taskkill /F /IM dna_messenger_gui.exe >nul 2>&1
taskkill /F /IM dna_messenger.exe >nul 2>&1
timeout /t 2 /nobreak >nul

cd /d C:\dna-messenger
if %errorlevel% neq 0 (
    echo ERROR: C:\dna-messenger not found
    echo.
    echo Please ensure DNA Messenger is installed in C:\dna-messenger
    pause
    exit /b 1
)

echo Updating repository...
git pull origin main
if %errorlevel% neq 0 (
    echo ERROR: Git pull failed
    echo.
    pause
    exit /b 1
)

echo.
echo Cleaning build directory...
if exist build\gui\Release\dna_messenger_gui.exe (
    del /F /Q build\gui\Release\dna_messenger_gui.exe 2>nul
)
if exist build\Release\dna_messenger.exe (
    del /F /Q build\Release\dna_messenger.exe 2>nul
)

timeout /t 1 /nobreak >nul

cd build

echo.
echo Rebuilding...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Build failed
    echo Check the output above for errors
    pause
    exit /b 1
)

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
