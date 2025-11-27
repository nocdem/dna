#!/bin/bash
#
# build-android.sh - Build DNA Messenger for Android
#
# Prerequisites:
#   1. Android NDK installed (r21+ recommended)
#   2. Set ANDROID_NDK environment variable:
#      export ANDROID_NDK=/path/to/android-ndk-r25c
#
# Usage:
#   ./build-android.sh [ABI]
#
# ABIs:
#   arm64-v8a   - 64-bit ARM (default, recommended)
#   armeabi-v7a - 32-bit ARM
#   x86_64      - 64-bit x86 (emulator)
#   x86         - 32-bit x86 (emulator)
#

set -e

# Default ABI
ABI=${1:-arm64-v8a}

# Minimum API level (24 = Android 7.0, required for getrandom())
API_LEVEL=24

# Check for ANDROID_NDK
if [ -z "$ANDROID_NDK" ]; then
    # Try common paths
    if [ -d "$HOME/Android/Sdk/ndk" ]; then
        ANDROID_NDK=$(ls -d "$HOME/Android/Sdk/ndk"/* 2>/dev/null | sort -V | tail -1)
    elif [ -d "/opt/android-ndk" ]; then
        ANDROID_NDK="/opt/android-ndk"
    fi
fi

if [ -z "$ANDROID_NDK" ] || [ ! -d "$ANDROID_NDK" ]; then
    echo "ERROR: ANDROID_NDK not set or not found"
    echo ""
    echo "Please set ANDROID_NDK environment variable:"
    echo "  export ANDROID_NDK=/path/to/android-ndk-r25c"
    echo ""
    echo "Or install Android NDK:"
    echo "  1. Via Android Studio: Tools > SDK Manager > SDK Tools > NDK"
    echo "  2. Or download from: https://developer.android.com/ndk/downloads"
    exit 1
fi

echo "=== DNA Messenger Android Build ==="
echo "NDK: $ANDROID_NDK"
echo "ABI: $ABI"
echo "API: $API_LEVEL"
echo ""

# Create build directory
BUILD_DIR="build-android-$ABI"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with CMake
echo "Configuring CMake..."
cmake \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$API_LEVEL" \
    -DANDROID_STL=c++_static \
    -DBUILD_GUI=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    ..

# Build
echo ""
echo "Building..."
make -j$(nproc) dna_lib dht_lib p2p_transport kem dsa

# Show results
echo ""
echo "=== Build Complete ==="
echo "Libraries built:"
ls -lh *.a 2>/dev/null || echo "(libraries in subdirectories)"
find . -name "*.a" -exec ls -lh {} \; 2>/dev/null | head -10

echo ""
echo "Output directory: $BUILD_DIR"
echo ""
echo "Next steps:"
echo "  1. Create Android Studio project with native support"
echo "  2. Add libraries to app/src/main/jniLibs/$ABI/"
echo "  3. Create JNI bindings to call dna_engine_* functions"
echo "  4. Call qgp_platform_set_app_dirs() during app init"
