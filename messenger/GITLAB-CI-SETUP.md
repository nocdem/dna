# GitLab CI/CD Setup for DNA Messenger

## Overview

This document describes the GitLab CI/CD pipeline configuration for building DNA Messenger across all major platforms with proper static linking on Windows.

## Changes Made

### 1. GitLab CI Configuration (`.gitlab-ci.yml`)

Created comprehensive CI pipeline with 3 stages:
- **build**: Compile for all platforms
- **test**: Run smoke tests
- **package**: Create distribution archives

#### Build Jobs

**Linux x86_64 (native):**
- Ubuntu 22.04 base image
- Builds both CLI and GUI (Qt5)
- Dynamic linking (standard Linux approach)

**Linux ARM64 (cross-compile):**
- Cross-compilation using `aarch64-linux-gnu-gcc`
- CLI only (no Qt5 GUI)
- Uses toolchain file for cross-compilation

**Windows x64 (MSVC with vcpkg):**
- Uses Windows runner with vcpkg
- **Static linking** with `x64-windows-static` triplet
- Includes: OpenSSL, libpq, json-c, Qt5 (all static)
- Forces `/MT` runtime (MultiThreaded static)
- Builds both CLI and GUI

**Windows x64 MinGW (alternative):**
- Cross-compile from Linux using MinGW
- Builds json-c statically from source
- Forces `-static -static-libgcc -static-libstdc++`
- CLI only
- Marked as `allow_failure: true` (fallback method)

**macOS x64/ARM64:**
- Requires osxcross toolchain
- CLI only
- Marked as `allow_failure: true` (optional)

### 2. CMakeLists.txt Improvements

#### Static Linking Configuration for Windows

```cmake
# Force static runtime library on Windows
if(WIN32)
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
    elseif(MINGW)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
endif()
```

#### json-c Static Library Detection

- Detects vcpkg static triplet automatically
- Improved library finding with multiple name variants
- Proper include directory handling
- Fatal error if not found (was warning before)

#### Library Linking Updates

- Added `${JSONC_LIBRARIES}` to `dna_lib` target
- Added `ws2_32` and `crypt32` for Windows (required by OpenSSL)
- Include directories for json-c added to all targets

#### PostgreSQL Library Detection

- Improved to search multiple paths
- Better Windows support with PATH_SUFFIXES
- Searches for both `pq` and `libpq` names

### 3. GUI CMakeLists.txt

- Added json-c include directories to GUI target
- Ensures GUI can compile with static libraries

## Windows Static Linking Solution

### The Problem

Previously, Windows builds were missing `json-c.dll` at runtime because:
1. Dynamic linking was used by default
2. DLL dependencies were not included in artifacts
3. vcpkg default triplet (`x64-windows`) builds shared libraries

### The Solution

**Method 1: MSVC with vcpkg static triplet (recommended)**

```bash
# Install static libraries
vcpkg install openssl:x64-windows-static libpq:x64-windows-static json-c:x64-windows-static

# Configure CMake
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-windows-static \
  -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreaded"
```

This statically links:
- OpenSSL (libcrypto)
- PostgreSQL client (libpq)
- json-c
- Qt5 (if building GUI)
- C/C++ runtime libraries

**Method 2: MinGW cross-compile (alternative)**

- Builds json-c from source with static flags
- Uses `-static` linker flags
- Works on Linux CI runners without Windows runner

## CI/CD Pipeline Usage

### Automatic Builds

Pipeline runs automatically on:
- Push to any branch
- Merge requests
- Git tags

### Artifacts

Each build job produces artifacts:
- **Linux x86_64**: `dna_messenger`, `dna_messenger_gui`
- **Linux ARM64**: `dna_messenger`
- **Windows x64**: `dna_messenger.exe`, `dna_messenger_gui.exe`
- **macOS**: `dna_messenger` (if osxcross available)

Artifacts expire after 1 week (or 4 weeks for packaged releases).

### Package Stage

Creates distribution archives:
- `dna-messenger-{version}-linux-x64.tar.gz`
- `dna-messenger-{version}-linux-arm64.tar.gz`
- `dna-messenger-{version}-windows-x64.zip`

## GitLab Runner Requirements

### Linux Runner (required)

```yaml
tags:
  - linux
```

Capabilities:
- Ubuntu 22.04 container support
- Docker executor recommended
- Used for: Linux x64, Linux ARM64, Windows MinGW, macOS (via osxcross)

### Windows Runner (required for main Windows build)

```yaml
tags:
  - windows
```

Requirements:
- Windows 10/11 or Windows Server
- PowerShell
- vcpkg installed at `$env:VCPKG_ROOT`
- Visual Studio 2019+ with C++ tools
- CMake

Setup vcpkg:
```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat
[System.Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\vcpkg', 'Machine')
```

### macOS Runner (optional)

```yaml
tags:
  - osxcross
```

Requires osxcross toolchain installed at `/opt/osxcross`.

## Testing the Build Locally

### Linux

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=ON
make -j$(nproc)
```

### Windows (with vcpkg)

```powershell
mkdir build
cd build
cmake .. `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreaded" `
  -A x64
cmake --build . --config Release
```

### Verify Static Linking (Windows)

```powershell
# Check dependencies (should show minimal system DLLs only)
dumpbin /dependents build\Release\dna_messenger.exe

# Expected: kernel32.dll, user32.dll, advapi32.dll (system only)
# NOT expected: json-c.dll, libpq.dll, libssl-*.dll
```

### Verify Static Linking (Linux)

```bash
# Check dependencies
ldd build/dna_messenger

# Should show: libc, libm, libpthread, libdl (system only)
# json-c should NOT appear (it's statically linked)
```

## Troubleshooting

### json-c not found on Windows

**Error**: `json-c not found. Install: vcpkg install json-c:x64-windows-static`

**Solution**:
```powershell
vcpkg install json-c:x64-windows-static
```

### Missing DLLs at runtime (Windows)

**Error**: "The code execution cannot proceed because json-c.dll was not found"

**Cause**: Used dynamic triplet instead of static

**Solution**:
1. Clean build directory: `rmdir /S /Q build`
2. Reinstall with static triplet: `vcpkg install json-c:x64-windows-static`
3. Rebuild with `-DVCPKG_TARGET_TRIPLET=x64-windows-static`

### PostgreSQL not found

**Linux**: `sudo apt-get install libpq-dev`
**Windows**: `vcpkg install libpq:x64-windows-static`

### Qt5 not found (GUI build)

**Linux**: `sudo apt-get install qtbase5-dev qtmultimedia5-dev`
**Windows**: `vcpkg install qt5-base:x64-windows-static qt5-multimedia:x64-windows-static`

## Notes

1. **Static linking increases binary size** (Windows exe will be ~10-20 MB larger)
2. **Easier deployment** - no DLL dependency hell
3. **vcpkg integration** - toolchain file auto-finds static libraries
4. **Cross-platform** - Linux uses dynamic linking (standard practice)
5. **CI artifacts** are self-contained executables

## Next Steps

1. Configure GitLab runners (Linux + Windows)
2. Set up vcpkg on Windows runner
3. Test pipeline on first push
4. Monitor build logs for any missing dependencies
5. Adjust runner tags if needed

## References

- [vcpkg Documentation](https://vcpkg.io/)
- [CMake Static Linking](https://cmake.org/cmake/help/latest/variable/CMAKE_MSVC_RUNTIME_LIBRARY.html)
- [GitLab CI/CD](https://docs.gitlab.com/ee/ci/)
