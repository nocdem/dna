#!/bin/bash
# DNA Messenger Flutter - Linux build and run script
# Compiles native library, copies to correct location, and runs the app

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
FLUTTER_LIBS_DIR="$SCRIPT_DIR/linux/libs"
FLUTTER_BUNDLE_LIB="$SCRIPT_DIR/build/linux/x64/debug/bundle/lib"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== DNA Messenger Flutter - Linux ===${NC}"

# Check for required tools
check_dependencies() {
    local missing=()

    command -v cmake >/dev/null 2>&1 || missing+=("cmake")
    command -v make >/dev/null 2>&1 || missing+=("make")
    command -v flutter >/dev/null 2>&1 || missing+=("flutter")

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
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

    cd "$SCRIPT_DIR"

    # Get Flutter dependencies if needed
    flutter pub get

    # Run the app
    flutter run -d linux "$@"
}

# Pull latest code
pull_latest() {
    echo -e "${YELLOW}Pulling latest...${NC}"
    cd "$PROJECT_ROOT"
    # Use gitlab remote if available, otherwise origin
    if git remote | grep -q "^gitlab$"; then
        git pull --no-rebase gitlab main
    else
        git pull --no-rebase origin main
    fi
}

# Main
main() {
    check_dependencies
    pull_latest

    # Handle --no-build flag to skip native library build
    if [ "$1" = "--no-build" ] || [ "$1" = "-n" ]; then
        shift
    else
        # Always rebuild native library to catch any changes
        build_native_lib
        copy_library
    fi

    run_flutter "$@"
}

# Show help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS] [FLUTTER_ARGS...]"
    echo ""
    echo "Options:"
    echo "  -n, --no-build   Skip native library build (faster restart)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build native lib and run"
    echo "  $0 --no-build         # Skip build and run (faster)"
    echo "  $0 --release          # Build and run in release mode"
    exit 0
fi

main "$@"
