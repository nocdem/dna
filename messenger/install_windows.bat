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

cd /d C:\dna-messenger
if %errorlevel% neq 0 (
    echo ERROR: Directory not found
    pause
    exit /b 1
)

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
echo SUCCESS! Executable: C:\dna-messenger\build\Release\dna_messenger.exe
echo.
pause
