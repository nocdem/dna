#!/bin/bash
# DNA Messenger Flutter GUI - Full build script
# Pulls latest code, builds native library, and runs the Flutter app

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLUTTER_DIR="$PROJECT_ROOT/dna_messenger_flutter"
BUILD_DIR="$PROJECT_ROOT/build"
FLUTTER_LIBS_DIR="$FLUTTER_DIR/linux/libs"
FLUTTER_BUNDLE_LIB="$FLUTTER_DIR/build/linux/x64/debug/bundle/lib"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== DNA Messenger Flutter GUI - Full Build ===${NC}"

# Check for required tools
check_dependencies() {
    local missing=()

    command -v cmake >/dev/null 2>&1 || missing+=("cmake")
    command -v make >/dev/null 2>&1 || missing+=("make")
    command -v flutter >/dev/null 2>&1 || missing+=("flutter")
    command -v git >/dev/null 2>&1 || missing+=("git")

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
}

# Pull latest code
pull_latest() {
    echo -e "${YELLOW}Pulling latest code...${NC}"
    cd "$PROJECT_ROOT"

    # Use gitlab remote if available, otherwise origin
    if git remote | grep -q "^gitlab$"; then
        git pull --no-rebase gitlab main
    else
        git pull --no-rebase origin main
    fi

    echo -e "${GREEN}Code updated${NC}"
}

# Build native library
build_native_lib() {
    echo -e "${YELLOW}Building native library...${NC}"

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure with shared library option
    cmake "$PROJECT_ROOT" -DBUILD_SHARED_LIB=ON -DCMAKE_BUILD_TYPE=Release

    # Build just the dna_lib target
    make -j$(nproc) dna_lib

    if [ ! -f "$BUILD_DIR/libdna_lib.so" ]; then
        echo -e "${RED}Error: Failed to build libdna_lib.so${NC}"
        exit 1
    fi

    echo -e "${GREEN}Native library built successfully${NC}"
}

# Copy library to Flutter project
copy_library() {
    echo -e "${YELLOW}Copying library to Flutter project...${NC}"

    mkdir -p "$FLUTTER_LIBS_DIR"
    cp "$BUILD_DIR/libdna_lib.so" "$FLUTTER_LIBS_DIR/"

    # Also copy to bundle for flutter run
    mkdir -p "$FLUTTER_BUNDLE_LIB"
    cp "$BUILD_DIR/libdna_lib.so" "$FLUTTER_BUNDLE_LIB/"

    echo -e "${GREEN}Library copied to $FLUTTER_LIBS_DIR and bundle${NC}"
}

# Run Flutter app
run_flutter() {
    echo -e "${YELLOW}Starting Flutter app...${NC}"

    cd "$FLUTTER_DIR"

    # Get Flutter dependencies if needed
    flutter pub get

    # Run the app
    flutter run -d linux "$@"
}

# Main
main() {
    check_dependencies
    pull_latest
    build_native_lib
    copy_library
    run_flutter "$@"
}

# Show help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS] [FLUTTER_ARGS...]"
    echo ""
    echo "This script pulls latest code, builds the native library, and runs the Flutter app."
    echo "Use dna_messenger_flutter/run_linux.sh for faster iterations without git pull."
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Pull, build, and run"
    echo "  $0 --release          # Pull, build, and run in release mode"
    exit 0
fi

main "$@"
