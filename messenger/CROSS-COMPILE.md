# DNA Messenger - Cross-Compilation Guide

This guide explains how to build DNA Messenger binaries for all major platforms.

## Quick Start

**Build everything (automatic):**
```bash
./build-cross-compile.sh all
```

**Build specific platform:**
```bash
./build-cross-compile.sh linux-x64     # Linux x86_64
./build-cross-compile.sh linux-arm64   # Linux ARM64
./build-cross-compile.sh windows-x64   # Windows x86_64
./build-cross-compile.sh macos-x64     # macOS Intel
./build-cross-compile.sh macos-arm64   # macOS Apple Silicon
```

## Supported Platforms

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| **Linux** | x86_64 | ✅ Native | Full GUI support |
| **Linux** | ARM64 | ✅ Cross-compile | CLI only |
| **Windows** | x86_64 | ✅ Cross-compile (MinGW) | CLI only |
| **macOS** | x86_64 | ✅ Cross-compile (osxcross) | CLI only |
| **macOS** | ARM64 | ✅ Cross-compile (osxcross) | CLI only (Apple Silicon) |

## Prerequisites

### Common Tools
```bash
# Debian/Ubuntu
sudo apt-get install cmake git build-essential

# Arch Linux
sudo pacman -S cmake git base-devel
```

### Linux x86_64 (Native Build)
```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev libpq-dev libjson-c-dev qtbase5-dev qtmultimedia5-dev

# Arch Linux
sudo pacman -S openssl postgresql-libs json-c qt5-base qt5-multimedia
```

### Linux ARM64 (Cross-Compile)
```bash
# Install ARM64 cross-compiler
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# Install ARM64 libraries
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install libssl-dev:arm64 libpq-dev:arm64 libjson-c-dev:arm64
```

### Windows x86_64 (MinGW Cross-Compile)
```bash
# Install MinGW toolchain
sudo apt-get install mingw-w64

# Optional: Wine for testing
sudo apt-get install wine wine64
```

### macOS (osxcross)

**Set up osxcross:**
```bash
# Clone osxcross
git clone https://github.com/tpoechtrager/osxcross
cd osxcross

# Download macOS SDK (requires Apple Developer account)
# Place MacOSX*.sdk.tar.xz in osxcross/tarballs/

# Build osxcross
./build.sh

# Install to /opt/osxcross
sudo mv target /opt/osxcross
export OSXCROSS_TARGET_DIR=/opt/osxcross
export PATH=$OSXCROSS_TARGET_DIR/bin:$PATH
```

## Manual Build Instructions

### Linux x86_64
```bash
mkdir -p build-release/linux-x64
cd build-release/linux-x64

cmake ../.. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI=ON

make -j$(nproc)
```

### Linux ARM64
```bash
mkdir -p build-release/linux-arm64
cd build-release/linux-arm64

# Create toolchain file
cat > toolchain-arm64.cmake << 'EOF'
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

cmake ../.. \
    -DCMAKE_TOOLCHAIN_FILE=toolchain-arm64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI=OFF

make -j$(nproc)
```

### Windows x86_64 (MinGW)
```bash
mkdir -p build-release/windows-x64
cd build-release/windows-x64

# Create toolchain file
cat > toolchain-mingw64.cmake << 'EOF'
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(WIN32 TRUE)
set(MINGW TRUE)
EOF

cmake ../.. \
    -DCMAKE_TOOLCHAIN_FILE=toolchain-mingw64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI=OFF

make -j$(nproc)
```

### macOS x86_64 (osxcross)
```bash
export OSXCROSS_TARGET_DIR=/opt/osxcross
export PATH=$OSXCROSS_TARGET_DIR/bin:$PATH

mkdir -p build-release/macos-x64
cd build-release/macos-x64

# Create toolchain file
cat > toolchain-macos.cmake << EOF
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER ${OSXCROSS_TARGET_DIR}/bin/x86_64-apple-darwin21.4-clang)
set(CMAKE_CXX_COMPILER ${OSXCROSS_TARGET_DIR}/bin/x86_64-apple-darwin21.4-clang++)
set(CMAKE_FIND_ROOT_PATH ${OSXCROSS_TARGET_DIR})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_OSX_ARCHITECTURES x86_64)
EOF

cmake ../.. \
    -DCMAKE_TOOLCHAIN_FILE=toolchain-macos.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI=OFF

make -j$(nproc)
```

### macOS ARM64 (osxcross)
```bash
export OSXCROSS_TARGET_DIR=/opt/osxcross
export PATH=$OSXCROSS_TARGET_DIR/bin:$PATH

mkdir -p build-release/macos-arm64
cd build-release/macos-arm64

# Create toolchain file
cat > toolchain-macos-arm64.cmake << EOF
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER ${OSXCROSS_TARGET_DIR}/bin/aarch64-apple-darwin21.4-clang)
set(CMAKE_CXX_COMPILER ${OSXCROSS_TARGET_DIR}/bin/aarch64-apple-darwin21.4-clang++)
set(CMAKE_FIND_ROOT_PATH ${OSXCROSS_TARGET_DIR})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_OSX_ARCHITECTURES arm64)
EOF

cmake ../.. \
    -DCMAKE_TOOLCHAIN_FILE=toolchain-macos-arm64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI=OFF

make -j$(nproc)
```

## GitHub Actions CI/CD

Automated builds are configured in `.github/workflows/build-cross-platform.yml`.

**Triggers:**
- Push to `main` or `develop` branches
- New tags (`v*`)
- Pull requests to `main`
- Manual workflow dispatch

**Artifacts:**
- Linux x86_64 (with GUI)
- Linux ARM64 (CLI only)
- Windows x86_64 (CLI only)
- macOS x86_64 (CLI only)
- macOS ARM64 (CLI only)

**Release Process:**
```bash
# Tag a release
git tag v0.1.110
git push origin v0.1.110

# GitHub Actions will automatically:
# 1. Build all platforms
# 2. Create GitHub release
# 3. Upload all binaries
```

## Testing

### Linux x86_64
```bash
./build-release/linux-x64/dna_messenger --version
./build-release/linux-x64/gui/dna_messenger_gui
```

### Linux ARM64 (QEMU)
```bash
sudo apt-get install qemu-user-static
qemu-aarch64-static ./build-release/linux-arm64/dna_messenger --version
```

### Windows x86_64 (Wine)
```bash
wine ./build-release/windows-x64/dna_messenger.exe --version
```

### macOS (on macOS system)
```bash
./build-release/macos-x64/dna_messenger --version
./build-release/macos-arm64/dna_messenger --version
```

## Output Structure

```
dist/
├── dna-messenger-0.1.110-<hash>-linux-x64.tar.gz
├── dna-messenger-0.1.110-<hash>-linux-arm64.tar.gz
├── dna-messenger-0.1.110-<hash>-windows-x64.zip
├── dna-messenger-0.1.110-<hash>-macos-x64.tar.gz
└── dna-messenger-0.1.110-<hash>-macos-arm64.tar.gz
```

Each archive contains:
- `dna_messenger` or `dna_messenger.exe` (CLI)
- `dna_messenger_gui` (if built with Qt support)
- Required DLLs/shared libraries (if applicable)

## Troubleshooting

### Missing dependencies
```bash
# Check what libraries the binary needs
ldd ./dna_messenger
objdump -p ./dna_messenger | grep NEEDED

# For Windows
x86_64-w64-mingw32-objdump -p dna_messenger.exe | grep DLL
```

### Cross-compile not working
```bash
# Verify cross-compiler installation
aarch64-linux-gnu-gcc --version
x86_64-w64-mingw32-gcc --version

# Check osxcross
echo $OSXCROSS_TARGET_DIR
ls -la $OSXCROSS_TARGET_DIR/bin/
```

### Qt GUI not building
```bash
# Install Qt5 development packages
sudo apt-get install qtbase5-dev qtmultimedia5-dev

# Or disable GUI build
cmake .. -DBUILD_GUI=OFF
```

## Static Linking (Advanced)

For fully portable binaries with no dependencies:

```bash
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_STATIC=ON \
    -DCMAKE_EXE_LINKER_FLAGS="-static"
```

**Note:** Static linking may not work on all platforms due to glibc limitations.

## Code Signing

### Windows
```bash
# Sign with signtool (requires Windows SDK)
signtool sign /f certificate.pfx /p password dna_messenger.exe
```

### macOS
```bash
# Sign with codesign (requires Apple Developer account)
codesign --sign "Developer ID Application: Your Name" dna_messenger
```

## Distribution

**Recommended platforms for pre-built binaries:**
1. **Linux x86_64** - Primary platform, full GUI support
2. **Windows x86_64** - Wide user base
3. **macOS ARM64** - Modern Macs (M1/M2/M3)
4. **macOS x86_64** - Intel Macs
5. **Linux ARM64** - Raspberry Pi, ARM servers

**Consider providing:**
- Portable archives (`.tar.gz`, `.zip`)
- Linux packages (`.deb`, `.rpm`, `.AppImage`)
- Windows installer (`.exe` via NSIS/Inno Setup)
- macOS DMG or PKG installer

## Future Platforms

**Planned support:**
- Android (via Termux or native app)
- iOS (native app)
- FreeBSD
- OpenBSD
- Web (WebAssembly)

---

**For questions or issues, see:**
- [README.md](./README.md)
- [ROADMAP.md](./ROADMAP.md)
- GitHub Issues: https://github.com/nocdem/dna-messenger/issues
