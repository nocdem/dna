#!/bin/bash
#
# DNA Messenger - Cross-Compilation Build Script
# Builds binaries for all major platforms
#
# Supported targets:
#   - Linux x86_64 (native)
#   - Linux ARM64 (aarch64)
#   - Windows x86_64 (via MinGW)
#   - macOS x86_64 (via osxcross)
#   - macOS ARM64 (Apple Silicon via osxcross)
#
# Usage:
#   ./build-cross-compile.sh all          # Build all platforms
#   ./build-cross-compile.sh linux-x64    # Build Linux x86_64
#   ./build-cross-compile.sh linux-arm64  # Build Linux ARM64
#   ./build-cross-compile.sh windows-x64  # Build Windows x86_64
#   ./build-cross-compile.sh macos-x64    # Build macOS x86_64
#   ./build-cross-compile.sh macos-arm64  # Build macOS ARM64 (Apple Silicon)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project info
PROJECT_NAME="dna-messenger"
BUILD_DIR="build-release"
DIST_DIR="dist"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Version
VERSION=$(git rev-list --count HEAD 2>/dev/null || echo "0")
GIT_HASH=$(git log -1 --format=%h 2>/dev/null || echo "unknown")
BUILD_DATE=$(date +%Y-%m-%d)
FULL_VERSION="0.1.${VERSION}-${GIT_HASH}"

# Dependency versions
GLFW_VERSION="3.4"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} DNA Messenger - Cross-Compilation${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "Version: ${GREEN}${FULL_VERSION}${NC}"
echo -e "Build Date: ${GREEN}${BUILD_DATE}${NC}"
echo ""

# Check dependencies
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 not found${NC}"
        echo -e "Install: $2"
        return 1
    fi
    echo -e "${GREEN}✓${NC} $1 found"
}

# Clean old builds
clean_builds() {
    echo -e "${YELLOW}Cleaning old builds...${NC}"
    cd "${PROJECT_ROOT}"
    rm -rf "$BUILD_DIR" "$DIST_DIR"
    mkdir -p "$DIST_DIR"
    echo -e "${GREEN}✓${NC} Clean complete"
    echo ""
}

# Build Linux x86_64 (native)
build_linux_x64() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: Linux x86_64${NC}"
    echo -e "${BLUE}=========================================${NC}"

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/linux-x64"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

    # Build with optional CMAKE_PREFIX_PATH for custom dependencies
    CMAKE_ARGS=(
        "${PROJECT_ROOT}"
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_C_FLAGS="-O3 -march=x86-64 -mtune=generic"
        -DCMAKE_CXX_FLAGS="-O3 -march=x86-64 -mtune=generic"
        -DBUILD_GUI=ON
    )

    if [ -n "${CMAKE_PREFIX_PATH}" ]; then
        CMAKE_ARGS+=(-DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}")
    fi

    cmake "${CMAKE_ARGS[@]}"

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/linux-x64"
    # Package ImGui GUI executable
    if [ -f imgui_gui/dna-messenger ]; then
        cp imgui_gui/dna-messenger "${PROJECT_ROOT}/${DIST_DIR}/linux-x64/"
    else
        echo -e "${RED}Error: GUI executable not found${NC}"
        return 1
    fi

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Linux x86_64 build complete${NC}"
    echo ""
}

# Build Linux x86_64 Debug (with ASAN)
build_linux_x64_debug() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: Linux x86_64 Debug + ASAN${NC}"
    echo -e "${BLUE}=========================================${NC}"

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/linux-x64-debug"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

    # Build with Debug mode (ASAN automatically enabled in CMakeLists.txt)
    CMAKE_ARGS=(
        "${PROJECT_ROOT}"
        -DCMAKE_BUILD_TYPE=Debug
        -DBUILD_GUI=ON
    )

    if [ -n "${CMAKE_PREFIX_PATH}" ]; then
        CMAKE_ARGS+=(-DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}")
    fi

    cmake "${CMAKE_ARGS[@]}"

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/linux-x64-debug"
    # Package ImGui GUI executable
    if [ -f imgui_gui/dna-messenger ]; then
        cp imgui_gui/dna-messenger "${PROJECT_ROOT}/${DIST_DIR}/linux-x64-debug/"
    else
        echo -e "${RED}Error: GUI executable not found${NC}"
        return 1
    fi

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Linux x86_64 Debug build complete${NC}"
    echo ""
}

# Build Linux ARM64 (cross-compile)
build_linux_arm64() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: Linux ARM64${NC}"
    echo -e "${BLUE}=========================================${NC}"

    # Check for cross-compiler
    if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
        echo -e "${RED}Error: aarch64-linux-gnu-gcc not found${NC}"
        echo -e "Install: ${YELLOW}sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu${NC}"
        return 1
    fi

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/linux-arm64"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

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

    # Build with optional CMAKE_PREFIX_PATH for custom dependencies
    CMAKE_ARGS=(
        "${PROJECT_ROOT}"
        -DCMAKE_TOOLCHAIN_FILE=toolchain-arm64.cmake
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_GUI=ON
    )

    if [ -n "${CMAKE_PREFIX_PATH}" ]; then
        CMAKE_ARGS+=(-DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}")
    fi

    cmake "${CMAKE_ARGS[@]}"

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/linux-arm64"
    # Package GUI executable
    if [ -f imgui_gui/dna-messenger ]; then
        cp imgui_gui/dna-messenger "${PROJECT_ROOT}/${DIST_DIR}/linux-arm64/"
        echo -e "${GREEN}✓${NC} Packaged GUI executable"
    else
        echo -e "${RED}Error: GUI executable not found${NC}"
        return 1
    fi

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Linux ARM64 build complete${NC}"
    echo ""
}

# Build Windows x86_64 (llvm-mingw cross-compile)
build_windows_x64() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: Windows x86_64${NC}"
    echo -e "${BLUE}=========================================${NC}"

    # llvm-mingw directory - configurable via environment variable
    # Download and setup llvm-mingw
    LLVM_MINGW_VERSION="20251118"
    LLVM_MINGW_DIR="${HOME}/.cache/llvm-mingw"
    LLVM_MINGW_RELEASE="llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-x86_64"
    LLVM_MINGW_URL="https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_VERSION}/${LLVM_MINGW_RELEASE}.tar.xz"
    MINGW_PREFIX="${LLVM_MINGW_DIR}/${LLVM_MINGW_RELEASE}"

    if [ ! -d "${MINGW_PREFIX}" ]; then
        echo -e "${BLUE}Downloading llvm-mingw ${LLVM_MINGW_VERSION} (~200MB)...${NC}"
        mkdir -p "${LLVM_MINGW_DIR}"
        cd "${LLVM_MINGW_DIR}"

        if [ ! -f "${LLVM_MINGW_RELEASE}.tar.xz" ]; then
            wget "${LLVM_MINGW_URL}"
        fi

        echo -e "${BLUE}Extracting llvm-mingw...${NC}"
        tar -xJf "${LLVM_MINGW_RELEASE}.tar.xz"
        echo -e "${GREEN}✓${NC} llvm-mingw installed to ${MINGW_PREFIX}"
    else
        echo -e "${GREEN}✓${NC} llvm-mingw already installed"
    fi

    # Set up environment for llvm-mingw
    export PATH="${MINGW_PREFIX}/bin:$PATH"
    export MINGW_TARGET="x86_64-w64-mingw32"
    export MINGW_TARGET_PREFIX="${MINGW_PREFIX}/${MINGW_TARGET}"
    export LLVM_MINGW_DIR

    echo -e "${BLUE}Using llvm-mingw toolchain:${NC}"
    echo -e "  Toolchain: ${MINGW_PREFIX}/bin"
    echo -e "  Target: ${MINGW_TARGET}"
    echo -e "  Prefix: ${MINGW_TARGET_PREFIX}"

    # Build OpenDHT and msgpack for Windows
    echo -e "${BLUE}Building P2P dependencies (OpenDHT, msgpack)...${NC}"
    "${PROJECT_ROOT}/setup-windows-build.sh"

    # Download and install GLFW prebuilt binaries for Windows
    GLFW_DIR="${HOME}/.cache/glfw-${GLFW_VERSION}"
    GLFW_INSTALLED="${MINGW_TARGET_PREFIX}/include/GLFW/glfw3.h"

    if [ ! -f "${GLFW_INSTALLED}" ]; then
        echo -e "${BLUE}Downloading GLFW ${GLFW_VERSION} prebuilt binaries...${NC}"
        mkdir -p "${GLFW_DIR}"
        cd "${GLFW_DIR}"

        if [ ! -f "glfw-${GLFW_VERSION}.bin.WIN64.zip" ]; then
            wget "https://github.com/glfw/glfw/releases/download/${GLFW_VERSION}/glfw-${GLFW_VERSION}.bin.WIN64.zip"
        fi

        echo -e "${BLUE}Extracting GLFW ${GLFW_VERSION}...${NC}"
        unzip -o "glfw-${GLFW_VERSION}.bin.WIN64.zip"

        echo -e "${BLUE}Installing GLFW ${GLFW_VERSION} to ${MINGW_TARGET_PREFIX}...${NC}"
        # Copy headers
        mkdir -p "${MINGW_TARGET_PREFIX}/include"
        cp -r "glfw-${GLFW_VERSION}.bin.WIN64/include/GLFW" "${MINGW_TARGET_PREFIX}/include/"

        # Copy static library (lib-mingw-w64 is for 64-bit MinGW)
        mkdir -p "${MINGW_TARGET_PREFIX}/lib"
        cp "glfw-${GLFW_VERSION}.bin.WIN64/lib-mingw-w64/libglfw3.a" "${MINGW_TARGET_PREFIX}/lib/"

        echo -e "${GREEN}✓${NC} GLFW ${GLFW_VERSION} installed"
    else
        echo -e "${GREEN}✓${NC} GLFW ${GLFW_VERSION} already installed"
    fi

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/windows-x64"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

    # Create toolchain file for llvm-mingw
    cat > toolchain-mingw64.cmake << EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Use llvm-mingw compilers (Clang-based cross-compiler)
set(CMAKE_C_COMPILER ${MINGW_PREFIX}/bin/${MINGW_TARGET}-clang)
set(CMAKE_CXX_COMPILER ${MINGW_PREFIX}/bin/${MINGW_TARGET}-clang++)
set(CMAKE_RC_COMPILER ${MINGW_PREFIX}/bin/${MINGW_TARGET}-windres)
set(CMAKE_AR ${MINGW_PREFIX}/bin/${MINGW_TARGET}-ar)
set(CMAKE_RANLIB ${MINGW_PREFIX}/bin/${MINGW_TARGET}-ranlib)

set(CMAKE_FIND_ROOT_PATH ${MINGW_TARGET_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(WIN32 TRUE)
set(MINGW TRUE)

# Force static linking
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
EOF

    echo -e "${BLUE}Configuring CMake...${NC}"
    cmake "${PROJECT_ROOT}" \
        -DCMAKE_TOOLCHAIN_FILE=toolchain-mingw64.cmake \
        -DCMAKE_PREFIX_PATH="${MINGW_TARGET_PREFIX};${MINGW_TARGET_PREFIX}/lib64" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=ON

    echo -e "${BLUE}Building...${NC}"
    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/windows-x64"
    # ImGui GUI executable
    if [ -f imgui_gui/dna-messenger.exe ]; then
        cp imgui_gui/dna-messenger.exe "${PROJECT_ROOT}/${DIST_DIR}/windows-x64/"
    else
        echo -e "${RED}Error: GUI executable not found${NC}"
        return 1
    fi

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Windows x86_64 build complete${NC}"
    echo ""
}

# Build Windows x86_64 Debug
build_windows_x64_debug() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: Windows x86_64 Debug${NC}"
    echo -e "${BLUE}=========================================${NC}"

    # llvm-mingw directory - configurable via environment variable
    # Download and setup llvm-mingw
    LLVM_MINGW_VERSION="20251118"
    LLVM_MINGW_DIR="${HOME}/.cache/llvm-mingw"
    LLVM_MINGW_RELEASE="llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-x86_64"
    LLVM_MINGW_URL="https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_VERSION}/${LLVM_MINGW_RELEASE}.tar.xz"
    MINGW_PREFIX="${LLVM_MINGW_DIR}/${LLVM_MINGW_RELEASE}"

    if [ ! -d "${MINGW_PREFIX}" ]; then
        echo -e "${BLUE}Downloading llvm-mingw ${LLVM_MINGW_VERSION} (~200MB)...${NC}"
        mkdir -p "${LLVM_MINGW_DIR}"
        cd "${LLVM_MINGW_DIR}"

        if [ ! -f "${LLVM_MINGW_RELEASE}.tar.xz" ]; then
            wget "${LLVM_MINGW_URL}"
        fi

        echo -e "${BLUE}Extracting llvm-mingw...${NC}"
        tar -xJf "${LLVM_MINGW_RELEASE}.tar.xz"
        echo -e "${GREEN}✓${NC} llvm-mingw installed to ${MINGW_PREFIX}"
    else
        echo -e "${GREEN}✓${NC} llvm-mingw already installed"
    fi

    # Set up environment for llvm-mingw
    export PATH="${MINGW_PREFIX}/bin:$PATH"
    export MINGW_TARGET="x86_64-w64-mingw32"
    export MINGW_TARGET_PREFIX="${MINGW_PREFIX}/${MINGW_TARGET}"
    export LLVM_MINGW_DIR

    echo -e "${BLUE}Using llvm-mingw toolchain:${NC}"
    echo -e "  Toolchain: ${MINGW_PREFIX}/bin"
    echo -e "  Target: ${MINGW_TARGET}"
    echo -e "  Prefix: ${MINGW_TARGET_PREFIX}"

    # Build OpenDHT and msgpack for Windows
    echo -e "${BLUE}Building P2P dependencies (OpenDHT, msgpack)...${NC}"
    "${PROJECT_ROOT}/setup-windows-build.sh"

    # Download and install GLFW prebuilt binaries for Windows
    GLFW_DIR="${HOME}/.cache/glfw-${GLFW_VERSION}"
    GLFW_INSTALLED="${MINGW_TARGET_PREFIX}/include/GLFW/glfw3.h"

    if [ ! -f "${GLFW_INSTALLED}" ]; then
        echo -e "${BLUE}Downloading GLFW ${GLFW_VERSION} prebuilt binaries...${NC}"
        mkdir -p "${GLFW_DIR}"
        cd "${GLFW_DIR}"

        if [ ! -f "glfw-${GLFW_VERSION}.bin.WIN64.zip" ]; then
            wget "https://github.com/glfw/glfw/releases/download/${GLFW_VERSION}/glfw-${GLFW_VERSION}.bin.WIN64.zip"
        fi

        echo -e "${BLUE}Extracting GLFW ${GLFW_VERSION}...${NC}"
        unzip -o "glfw-${GLFW_VERSION}.bin.WIN64.zip"

        echo -e "${BLUE}Installing GLFW ${GLFW_VERSION} to ${MINGW_TARGET_PREFIX}...${NC}"
        # Copy headers
        mkdir -p "${MINGW_TARGET_PREFIX}/include"
        cp -r "glfw-${GLFW_VERSION}.bin.WIN64/include/GLFW" "${MINGW_TARGET_PREFIX}/include/"

        # Copy static library (lib-mingw-w64 is for 64-bit MinGW)
        mkdir -p "${MINGW_TARGET_PREFIX}/lib"
        cp "glfw-${GLFW_VERSION}.bin.WIN64/lib-mingw-w64/libglfw3.a" "${MINGW_TARGET_PREFIX}/lib/"

        echo -e "${GREEN}✓${NC} GLFW ${GLFW_VERSION} installed"
    else
        echo -e "${GREEN}✓${NC} GLFW ${GLFW_VERSION} already installed"
    fi

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/windows-x64-debug"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

    # Create toolchain file for llvm-mingw
    cat > toolchain-mingw64.cmake << EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Use llvm-mingw compilers (Clang-based cross-compiler)
set(CMAKE_C_COMPILER ${MINGW_PREFIX}/bin/${MINGW_TARGET}-clang)
set(CMAKE_CXX_COMPILER ${MINGW_PREFIX}/bin/${MINGW_TARGET}-clang++)
set(CMAKE_RC_COMPILER ${MINGW_PREFIX}/bin/${MINGW_TARGET}-windres)
set(CMAKE_AR ${MINGW_PREFIX}/bin/${MINGW_TARGET}-ar)
set(CMAKE_RANLIB ${MINGW_PREFIX}/bin/${MINGW_TARGET}-ranlib)

set(CMAKE_FIND_ROOT_PATH ${MINGW_TARGET_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(WIN32 TRUE)
set(MINGW TRUE)

# Force static linking
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
EOF

    echo -e "${BLUE}Configuring CMake for Debug build...${NC}"
    cmake "${PROJECT_ROOT}" \
        -DCMAKE_TOOLCHAIN_FILE=toolchain-mingw64.cmake \
        -DCMAKE_PREFIX_PATH="${MINGW_TARGET_PREFIX};${MINGW_TARGET_PREFIX}/lib64" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_GUI=ON

    echo -e "${BLUE}Building...${NC}"
    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/windows-x64-debug"
    # ImGui GUI executable
    if [ -f imgui_gui/dna-messenger.exe ]; then
        cp imgui_gui/dna-messenger.exe "${PROJECT_ROOT}/${DIST_DIR}/windows-x64-debug/"
    else
        echo -e "${RED}Error: GUI executable not found${NC}"
        return 1
    fi

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Windows x86_64 Debug build complete${NC}"
    echo ""
}

# Build macOS x86_64 (osxcross)
build_macos_x64() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: macOS x86_64${NC}"
    echo -e "${BLUE}=========================================${NC}"

    # Check for osxcross
    if [ -z "$OSXCROSS_TARGET_DIR" ]; then
        echo -e "${YELLOW}Warning: OSXCROSS_TARGET_DIR not set${NC}"
        echo -e "${YELLOW}Attempting to use /opt/osxcross${NC}"
        export OSXCROSS_TARGET_DIR="/opt/osxcross"
    fi

    if [ ! -d "$OSXCROSS_TARGET_DIR" ]; then
        echo -e "${RED}Error: osxcross not found${NC}"
        echo -e "Install osxcross: https://github.com/tpoechtrager/osxcross"
        return 1
    fi

    export PATH="$OSXCROSS_TARGET_DIR/bin:$PATH"

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/macos-x64"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

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

    cmake "${PROJECT_ROOT}" \
        -DCMAKE_TOOLCHAIN_FILE=toolchain-macos.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=OFF

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/macos-x64"
    cp dna_messenger "${PROJECT_ROOT}/${DIST_DIR}/macos-x64/"

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ macOS x86_64 build complete${NC}"
    echo ""
}

# Build macOS ARM64 (Apple Silicon via osxcross)
build_macos_arm64() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: macOS ARM64 (Apple Silicon)${NC}"
    echo -e "${BLUE}=========================================${NC}"

    # Check for osxcross
    if [ -z "$OSXCROSS_TARGET_DIR" ]; then
        echo -e "${YELLOW}Warning: OSXCROSS_TARGET_DIR not set${NC}"
        echo -e "${YELLOW}Attempting to use /opt/osxcross${NC}"
        export OSXCROSS_TARGET_DIR="/opt/osxcross"
    fi

    if [ ! -d "$OSXCROSS_TARGET_DIR" ]; then
        echo -e "${RED}Error: osxcross not found${NC}"
        echo -e "Install osxcross: https://github.com/tpoechtrager/osxcross"
        return 1
    fi

    export PATH="$OSXCROSS_TARGET_DIR/bin:$PATH"

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/macos-arm64"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

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

    cmake "${PROJECT_ROOT}" \
        -DCMAKE_TOOLCHAIN_FILE=toolchain-macos-arm64.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=OFF

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/macos-arm64"
    cp dna_messenger "${PROJECT_ROOT}/${DIST_DIR}/macos-arm64/"

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ macOS ARM64 build complete${NC}"
    echo ""
}

# Build all platforms
build_all() {
    clean_builds

    echo -e "${BLUE}Building all platforms...${NC}"
    echo ""

    # Always build native Linux
    build_linux_x64

    # Try to build others (skip if dependencies missing)
    build_linux_arm64 || echo -e "${YELLOW}Skipped: Linux ARM64${NC}"
    build_windows_x64 || echo -e "${YELLOW}Skipped: Windows x64${NC}"
    build_macos_x64 || echo -e "${YELLOW}Skipped: macOS x64${NC}"
    build_macos_arm64 || echo -e "${YELLOW}Skipped: macOS ARM64${NC}"

    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN} Build Summary${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Build artifacts staged in: ${DIST_DIR}/"
    ls -lh "${DIST_DIR}/" 2>/dev/null || echo "No builds completed"
    echo ""
}

# Show usage
show_usage() {
    echo "Usage: $0 [target]"
    echo ""
    echo "Targets:"
    echo "  all                - Build all platforms (default)"
    echo "  linux-x64          - Linux x86_64 (Release)"
    echo "  linux-x64-debug    - Linux x86_64 (Debug + ASAN)"
    echo "  linux-arm64        - Linux ARM64"
    echo "  windows-x64        - Windows x86_64 (Release)"
    echo "  windows-x64-debug  - Windows x86_64 (Debug)"
    echo "  macos-x64          - macOS x86_64"
    echo "  macos-arm64        - macOS ARM64 (Apple Silicon)"
    echo "  clean              - Clean build directories"
    echo ""
    echo "Environment Variables:"
    echo "  LLVM_MINGW_DIR         - Custom llvm-mingw installation directory"
    echo "                           (default: ~/.cache/llvm-mingw)"
    echo ""
    echo "Examples:"
    echo "  $0 all                                    # Build everything"
    echo "  $0 linux-x64                              # Build Linux only"
    echo "  $0 windows-x64                            # Build Windows only"
    echo "  LLVM_MINGW_DIR=/opt/llvm-mingw $0 windows-x64  # Use custom llvm-mingw location"
    echo ""
}

# Main
case "${1:-all}" in
    all)
        build_all
        ;;
    linux-x64)
        clean_builds
        build_linux_x64
        ;;
    linux-x64-debug)
        clean_builds
        build_linux_x64_debug
        ;;
    linux-arm64)
        clean_builds
        build_linux_arm64
        ;;
    windows-x64)
        clean_builds
        build_windows_x64
        ;;
    windows-x64-debug)
        clean_builds
        build_windows_x64_debug
        ;;
    macos-x64)
        clean_builds
        build_macos_x64
        ;;
    macos-arm64)
        clean_builds
        build_macos_arm64
        ;;
    clean)
        clean_builds
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo -e "${RED}Error: Unknown target '$1'${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN} Done!${NC}"
echo -e "${GREEN}=========================================${NC}"
