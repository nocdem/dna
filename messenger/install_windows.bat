@echo off
echo Installing DNA Messenger for Windows
echo.

where git >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Git not found
    pause
    exit /b 1
)

where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: CMake not found
    pause
    exit /b 1
)

where vcpkg >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: vcpkg not found
    echo Please install vcpkg from: https://github.com/microsoft/vcpkg
    pause
    exit /b 1
)

echo Installing dependencies via vcpkg...
vcpkg install openssl:x64-windows libpq:x64-windows qt5-base:x64-windows qt5-multimedia:x64-windows

cd /d C:\dna-messenger
if %errorlevel% neq 0 (
    echo ERROR: Directory not found
    pause
    exit /b 1
)

echo Stashing local changes...
git stash

echo Updating repository...
git pull

echo Cleaning build directory...
if exist build rmdir /S /Q build
mkdir build
cd build

echo Running CMake...
if exist C:\vcpkg\scripts\buildsystems\vcpkg.cmake (
    cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -A x64
) else (
    cmake ..
)
if %errorlevel% neq 0 (
    echo ERROR: CMake failed
    pause
    exit /b 1
)

echo Building...
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo.
echo =========================================
echo  Installation Complete
echo =========================================
echo.
echo Binaries:
echo   CLI: C:\dna-messenger\build\Release\dna_messenger.exe
echo   GUI: C:\dna-messenger\build\gui\Release\dna_messenger_gui.exe
echo.
echo To run:
echo   cd C:\dna-messenger\build\Release
echo   dna_messenger.exe           (CLI version)
echo.
echo   cd C:\dna-messenger\build\gui\Release
echo   dna_messenger_gui.exe       (GUI version)
echo.
echo On first run, configure server (option 4):
echo   - Server: ai.cpunk.io
echo.
echo Features:
echo   + Post-quantum encryption (Dilithium3 + Kyber512)
echo   + BIP39 seed phrase key generation
echo   + End-to-end encrypted messaging
echo   + Message search and filtering
echo   + Conversation history
echo   + Cross-platform (Linux and Windows)
echo.
pause
