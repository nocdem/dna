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

    cmake "${PROJECT_ROOT}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-O3 -march=x86-64 -mtune=generic" \
        -DCMAKE_CXX_FLAGS="-O3 -march=x86-64 -mtune=generic" \
        -DBUILD_GUI=ON

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/linux-x64"
    cp dna_messenger "${PROJECT_ROOT}/${DIST_DIR}/linux-x64/"
    if [ -f gui/dna_messenger_gui ]; then
        cp gui/dna_messenger_gui "${PROJECT_ROOT}/${DIST_DIR}/linux-x64/"
    fi

    # Create tarball
    cd "${PROJECT_ROOT}/${DIST_DIR}"
    tar -czf "${PROJECT_NAME}-${FULL_VERSION}-linux-x64.tar.gz" linux-x64/

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Linux x86_64 build complete${NC}"
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

    cmake "${PROJECT_ROOT}" \
        -DCMAKE_TOOLCHAIN_FILE=toolchain-arm64.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=OFF

    make -j$(nproc)

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/linux-arm64"
    cp dna_messenger "${PROJECT_ROOT}/${DIST_DIR}/linux-arm64/"

    # Create tarball
    cd "${PROJECT_ROOT}/${DIST_DIR}"
    tar -czf "${PROJECT_NAME}-${FULL_VERSION}-linux-arm64.tar.gz" linux-arm64/

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Linux ARM64 build complete${NC}"
    echo ""
}

# Build Windows x86_64 (MXE static cross-compile)
build_windows_x64() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE} Building: Windows x86_64${NC}"
    echo -e "${BLUE}=========================================${NC}"

    # MXE directory - configurable via environment variable
    # Priority: MXE_DIR env var > ~/.cache/mxe > project/mxe
    if [ -n "$MXE_DIR" ]; then
        echo -e "${BLUE}Using MXE_DIR from environment: ${MXE_DIR}${NC}"
    elif [ -d "$HOME/.cache/mxe" ] || [ -z "${MXE_USE_PROJECT_DIR}" ]; then
        MXE_DIR="$HOME/.cache/mxe"
        echo -e "${BLUE}Using cached MXE directory: ${MXE_DIR}${NC}"
    else
        MXE_DIR="${PROJECT_ROOT}/mxe"
        echo -e "${BLUE}Using project MXE directory: ${MXE_DIR}${NC}"
    fi

    MXE_PREFIX="${MXE_DIR}/usr/x86_64-w64-mingw32.static"

    # Check if MXE is already built
    if [ ! -d "$MXE_DIR" ]; then
        echo -e "${YELLOW}MXE not found, cloning to ${MXE_DIR}...${NC}"
        mkdir -p "$(dirname "$MXE_DIR")"
        cd "$(dirname "$MXE_DIR")"
        git clone https://github.com/mxe/mxe.git "$(basename "$MXE_DIR")"
    else
        echo -e "${GREEN}✓${NC} MXE directory found at ${MXE_DIR}"
    fi

    # Check if MXE is already built (check for qmake as indicator)
    if [ ! -f "${MXE_PREFIX}/bin/qmake" ]; then
        echo -e "${YELLOW}MXE build incomplete or missing, building dependencies...${NC}"
        echo -e "${YELLOW}This will take a while on first run (1-2 hours)${NC}"

        # Check for required build dependencies
        echo -e "${BLUE}Checking build dependencies...${NC}"
        MISSING_DEPS=""
        for dep in git make gcc g++ cmake autoconf automake libtool pkg-config bison flex gperf ruby unzip; do
            if ! command -v "$dep" &> /dev/null; then
                MISSING_DEPS="$MISSING_DEPS $dep"
            fi
        done

        # Check for 7z (command from p7zip package)
        if ! command -v 7z &> /dev/null && ! command -v 7za &> /dev/null; then
            MISSING_DEPS="$MISSING_DEPS p7zip"
        fi

        if [ -n "$MISSING_DEPS" ]; then
            echo -e "${RED}Error: Missing dependencies:${MISSING_DEPS}${NC}"
            echo -e "Arch Linux: ${YELLOW}sudo pacman -S base-devel git cmake autoconf automake libtool pkg-config perl python bison flex gperf ruby unzip p7zip lzip intltool xz gettext${NC}"
            echo -e "Ubuntu/Debian: ${YELLOW}sudo apt install git make gcc g++ cmake autoconf automake libtool libtool-bin pkg-config perl libxml-parser-perl python3 python3-mako bison flex gperf ruby unzip p7zip-full lzip intltool xz-utils libgdk-pixbuf2.0-dev gettext autopoint libssl-dev zlib1g-dev bzip2${NC}"
            return 1
        fi

        # Create python symlink if needed (MXE expects 'python' not 'python3')
        if [ ! -e /usr/bin/python ] && [ -e /usr/bin/python3 ]; then
            echo -e "${YELLOW}Creating python symlink...${NC}"
            sudo ln -sf /usr/bin/python3 /usr/bin/python || true
        fi

        cd "$MXE_DIR"
        echo -e "${BLUE}Building MXE dependencies: qtbase qtmultimedia postgresql openssl json-c curl${NC}"
        make MXE_TARGETS=x86_64-w64-mingw32.static qtbase qtmultimedia postgresql openssl json-c curl -j$(nproc)
        echo -e "${GREEN}✓${NC} MXE build complete"
    else
        echo -e "${GREEN}✓${NC} MXE build already complete, skipping build step"
    fi

    # Set up environment
    # Add both the general bin dir and the target-specific bin dir to PATH
    # The target bin dir contains the actual binutils (as, ld, etc.)
    export PATH="${MXE_DIR}/usr/bin:${MXE_PREFIX}/bin:$PATH"
    export MXE_PREFIX

    BUILD_PATH="${PROJECT_ROOT}/${BUILD_DIR}/windows-x64"
    mkdir -p "$BUILD_PATH"
    cd "$BUILD_PATH"

    # Create a wrapper bin directory with unprefixed symlinks for binutils
    # This allows GCC to find tools like 'as', 'ld', etc. without the target prefix
    WRAPPER_BIN="${BUILD_PATH}/mxe-wrapper-bin"
    mkdir -p "$WRAPPER_BIN"

    # Create symlinks for common binutils
    for tool in as ld ar nm objcopy objdump ranlib strip; do
        ln -sf "${MXE_DIR}/usr/bin/x86_64-w64-mingw32.static-${tool}" "${WRAPPER_BIN}/${tool}"
    done

    # Create toolchain file
    cat > toolchain-mingw64.cmake << EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Use full paths to compilers to ensure proper toolchain discovery
set(CMAKE_C_COMPILER ${MXE_DIR}/usr/bin/x86_64-w64-mingw32.static-gcc)
set(CMAKE_CXX_COMPILER ${MXE_DIR}/usr/bin/x86_64-w64-mingw32.static-g++)
set(CMAKE_RC_COMPILER ${MXE_DIR}/usr/bin/x86_64-w64-mingw32.static-windres)

# Tell GCC where to find binutils (assembler, linker, etc.) using -B flag
# This points to a wrapper directory with unprefixed symlinks to the MXE tools
set(CMAKE_C_FLAGS_INIT "-B${BUILD_PATH}/mxe-wrapper-bin")
set(CMAKE_CXX_FLAGS_INIT "-B${BUILD_PATH}/mxe-wrapper-bin")

set(CMAKE_FIND_ROOT_PATH ${MXE_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(WIN32 TRUE)
set(MINGW TRUE)
# Force static linking
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(PKG_CONFIG_EXECUTABLE ${MXE_DIR}/usr/bin/x86_64-w64-mingw32.static-pkg-config)
set(Qt5_DIR "${MXE_PREFIX}/qt5/lib/cmake/Qt5")
set(Qt5Core_DIR "${MXE_PREFIX}/qt5/lib/cmake/Qt5Core")
set(Qt5Widgets_DIR "${MXE_PREFIX}/qt5/lib/cmake/Qt5Widgets")
set(Qt5Multimedia_DIR "${MXE_PREFIX}/qt5/lib/cmake/Qt5Multimedia")
EOF

    echo -e "${BLUE}Configuring CMake...${NC}"
    cmake "${PROJECT_ROOT}" \
        -DCMAKE_TOOLCHAIN_FILE=toolchain-mingw64.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=ON

    echo -e "${BLUE}Building...${NC}"
    make -j$(nproc) VERBOSE=1

    # Package
    mkdir -p "${PROJECT_ROOT}/${DIST_DIR}/windows-x64"
    cp dna_messenger.exe "${PROJECT_ROOT}/${DIST_DIR}/windows-x64/"
    if [ -f gui/dna_messenger_gui.exe ]; then
        cp gui/dna_messenger_gui.exe "${PROJECT_ROOT}/${DIST_DIR}/windows-x64/"
    fi

    # Create zip
    cd "${PROJECT_ROOT}/${DIST_DIR}"
    zip -r "${PROJECT_NAME}-${FULL_VERSION}-windows-x64.zip" windows-x64/

    cd "${PROJECT_ROOT}"
    echo -e "${GREEN}✓ Windows x86_64 build complete${NC}"
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

    # Create tarball
    cd "${PROJECT_ROOT}/${DIST_DIR}"
    tar -czf "${PROJECT_NAME}-${FULL_VERSION}-macos-x64.tar.gz" macos-x64/

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

    # Create tarball
    cd "${PROJECT_ROOT}/${DIST_DIR}"
    tar -czf "${PROJECT_NAME}-${FULL_VERSION}-macos-arm64.tar.gz" macos-arm64/

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
    echo "Release artifacts in: ${DIST_DIR}/"
    ls -lh "${DIST_DIR}/"*.{tar.gz,zip} 2>/dev/null || echo "No archives created"
    echo ""
}

# Show usage
show_usage() {
    echo "Usage: $0 [target]"
    echo ""
    echo "Targets:"
    echo "  all           - Build all platforms (default)"
    echo "  linux-x64     - Linux x86_64"
    echo "  linux-arm64   - Linux ARM64"
    echo "  windows-x64   - Windows x86_64"
    echo "  macos-x64     - macOS x86_64"
    echo "  macos-arm64   - macOS ARM64 (Apple Silicon)"
    echo "  clean         - Clean build directories"
    echo ""
    echo "Environment Variables:"
    echo "  MXE_DIR                - Custom MXE installation directory"
    echo "                           (default: ~/.cache/mxe)"
    echo "  MXE_USE_PROJECT_DIR=1  - Force MXE to be in project/mxe directory"
    echo ""
    echo "Examples:"
    echo "  $0 all                                    # Build everything"
    echo "  $0 linux-x64                              # Build Linux only"
    echo "  $0 windows-x64                            # Build Windows only"
    echo "  MXE_DIR=/opt/mxe $0 windows-x64           # Use custom MXE location"
    echo "  MXE_USE_PROJECT_DIR=1 $0 windows-x64      # Use project/mxe directory"
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
    linux-arm64)
        clean_builds
        build_linux_arm64
        ;;
    windows-x64)
        clean_builds
        build_windows_x64
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
