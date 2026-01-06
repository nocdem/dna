#!/bin/bash
# Build Android APK using Docker (matches CI environment)
# Builds native library + Flutter APK
#
# First build: ~2-3 hours (builds all dependencies)
# Subsequent builds: ~5 minutes (dependencies cached)
#
# Usage: ./scripts/build-android-docker.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CACHE_DIR="$HOME/.cache/dna-android-build"

# Docker images
BUILD_IMAGE="ubuntu:24.04"
FLUTTER_IMAGE="instrumentisto/flutter:3.38"

# Android config (match CI)
ANDROID_NDK_VERSION="26b"
ANDROID_API_LEVEL="24"
ANDROID_ABI="arm64-v8a"

cd "$PROJECT_DIR"

echo "==> DNA Messenger Android Build"
echo "==> Cache dir: $CACHE_DIR"
echo ""

# Create cache directory
mkdir -p "$CACHE_DIR"

# Step 1: Build native library
echo "==> Step 1/2: Building native library (libdna_lib.so)..."

docker run --rm \
    -v "$PROJECT_DIR:/src:ro" \
    -v "$CACHE_DIR:/cache" \
    -v "$PROJECT_DIR/dna_messenger_flutter/android/app/src/main/jniLibs:/output" \
    -e ANDROID_NDK_VERSION="$ANDROID_NDK_VERSION" \
    -e ANDROID_API_LEVEL="$ANDROID_API_LEVEL" \
    -e ANDROID_ABI="$ANDROID_ABI" \
    "$BUILD_IMAGE" \
    bash -c '
set -e

export DEBIAN_FRONTEND=noninteractive
export HOME=/cache

echo "Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential cmake git pkg-config xxd wget unzip autoconf automake libtool python3 ninja-build m4 texinfo >/dev/null 2>&1

# Setup Android NDK
if [ ! -d "/cache/android-ndk/android-ndk-r${ANDROID_NDK_VERSION}" ]; then
    echo "Downloading Android NDK r${ANDROID_NDK_VERSION}..."
    mkdir -p /cache/android-ndk && cd /cache/android-ndk
    wget -q https://dl.google.com/android/repository/android-ndk-r${ANDROID_NDK_VERSION}-linux.zip
    unzip -q android-ndk-r${ANDROID_NDK_VERSION}-linux.zip
    rm -f android-ndk-r${ANDROID_NDK_VERSION}-linux.zip
fi

export ANDROID_NDK_HOME="/cache/android-ndk/android-ndk-r${ANDROID_NDK_VERSION}"
export TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
export TARGET="aarch64-linux-android"
export API="${ANDROID_API_LEVEL}"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
export CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"
export LD="${TOOLCHAIN}/bin/ld"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"
export PATH="${TOOLCHAIN}/bin:$PATH"
export DEPS_DIR="/cache/android-deps"
mkdir -p "${DEPS_DIR}"

# Build GMP
if [ ! -f "${DEPS_DIR}/gmp-arm64/lib/libgmp.a" ]; then
    echo "Building GMP..."
    cd /tmp && rm -rf gmp-*
    wget -q https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
    tar xf gmp-6.3.0.tar.xz && cd gmp-6.3.0
    ./configure --host=aarch64-linux-android --prefix="${DEPS_DIR}/gmp-arm64" \
        --enable-static --disable-shared --with-pic \
        CC="${CC}" AR="${AR}" RANLIB="${RANLIB}" CFLAGS="-fPIC" >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build Nettle
if [ ! -f "${DEPS_DIR}/nettle-arm64/lib/libnettle.a" ]; then
    echo "Building Nettle..."
    cd /tmp && rm -rf nettle-*
    wget -q https://ftp.gnu.org/gnu/nettle/nettle-3.10.tar.gz
    tar xzf nettle-3.10.tar.gz && cd nettle-3.10
    ./configure --host=aarch64-linux-android --prefix="${DEPS_DIR}/nettle-arm64" \
        --enable-static --disable-shared --disable-documentation \
        --with-lib-path="${DEPS_DIR}/gmp-arm64/lib" \
        --with-include-path="${DEPS_DIR}/gmp-arm64/include" \
        CC="${CC}" AR="${AR}" RANLIB="${RANLIB}" \
        CFLAGS="-fPIC -I${DEPS_DIR}/gmp-arm64/include" \
        LDFLAGS="-L${DEPS_DIR}/gmp-arm64/lib" >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build libtasn1
if [ ! -f "${DEPS_DIR}/libtasn1-arm64/lib/libtasn1.a" ]; then
    echo "Building libtasn1..."
    cd /tmp && rm -rf libtasn1-*
    wget -q https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.19.0.tar.gz
    tar xzf libtasn1-4.19.0.tar.gz && cd libtasn1-4.19.0
    ./configure --host=aarch64-linux-android --prefix="${DEPS_DIR}/libtasn1-arm64" \
        --enable-static --disable-shared \
        CC="${CC}" AR="${AR}" RANLIB="${RANLIB}" CFLAGS="-fPIC" >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build GnuTLS
if [ ! -f "${DEPS_DIR}/gnutls-arm64/lib/libgnutls.a" ]; then
    echo "Building GnuTLS..."
    cd /tmp && rm -rf gnutls-*
    wget -q https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.7.tar.xz
    tar xf gnutls-3.8.7.tar.xz && cd gnutls-3.8.7
    ./configure --host=aarch64-linux-android --prefix="${DEPS_DIR}/gnutls-arm64" \
        --enable-static --disable-shared \
        --disable-tools --disable-tests --disable-doc --disable-cxx --disable-nls \
        --without-p11-kit --without-tpm --without-tpm2 \
        --with-included-libtasn1=no --with-included-unistring \
        GMP_CFLAGS="-I${DEPS_DIR}/gmp-arm64/include" \
        GMP_LIBS="-L${DEPS_DIR}/gmp-arm64/lib -lgmp" \
        NETTLE_CFLAGS="-I${DEPS_DIR}/nettle-arm64/include" \
        NETTLE_LIBS="-L${DEPS_DIR}/nettle-arm64/lib -lnettle" \
        HOGWEED_CFLAGS="-I${DEPS_DIR}/nettle-arm64/include" \
        HOGWEED_LIBS="-L${DEPS_DIR}/nettle-arm64/lib -lhogweed -L${DEPS_DIR}/gmp-arm64/lib -lgmp" \
        LIBTASN1_CFLAGS="-I${DEPS_DIR}/libtasn1-arm64/include" \
        LIBTASN1_LIBS="-L${DEPS_DIR}/libtasn1-arm64/lib -ltasn1" \
        CC="${CC}" AR="${AR}" RANLIB="${RANLIB}" \
        CFLAGS="-fPIC -I${DEPS_DIR}/gmp-arm64/include -I${DEPS_DIR}/nettle-arm64/include -I${DEPS_DIR}/libtasn1-arm64/include" \
        LDFLAGS="-L${DEPS_DIR}/gmp-arm64/lib -L${DEPS_DIR}/nettle-arm64/lib -L${DEPS_DIR}/libtasn1-arm64/lib" >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build argon2
if [ ! -f "${DEPS_DIR}/argon2-arm64/lib/libargon2.a" ]; then
    echo "Building argon2..."
    cd /tmp && rm -rf phc-winner-argon2-*
    wget -q https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz -O argon2.tar.gz
    tar xzf argon2.tar.gz && cd phc-winner-argon2-20190702
    make CC="${CC}" AR="${AR}" CFLAGS="-fPIC -Iinclude" LIBRARY_REL=lib PREFIX="${DEPS_DIR}/argon2-arm64" OPTTARGET=none libargon2.a >/dev/null
    mkdir -p "${DEPS_DIR}/argon2-arm64/lib" "${DEPS_DIR}/argon2-arm64/include"
    cp libargon2.a "${DEPS_DIR}/argon2-arm64/lib/"
    cp include/argon2.h "${DEPS_DIR}/argon2-arm64/include/"
fi

# Build fmt
if [ ! -f "${DEPS_DIR}/fmt-arm64/lib/libfmt.a" ]; then
    echo "Building fmt..."
    cd /tmp && rm -rf fmt-*
    wget -q https://github.com/fmtlib/fmt/archive/refs/tags/10.2.1.tar.gz -O fmt.tar.gz
    tar xzf fmt.tar.gz && cd fmt-10.2.1 && mkdir build && cd build
    cmake .. -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=android-${API} -DANDROID_STL=c++_static \
        -DCMAKE_INSTALL_PREFIX="${DEPS_DIR}/fmt-arm64" -DBUILD_SHARED_LIBS=OFF -DFMT_TEST=OFF >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Download ASIO (header-only)
if [ ! -d "${DEPS_DIR}/asio-1.30.2" ]; then
    echo "Downloading ASIO..."
    cd /tmp && rm -rf asio-*
    wget -q https://sourceforge.net/projects/asio/files/asio/1.30.2%20%28Stable%29/asio-1.30.2.tar.gz/download -O asio.tar.gz
    tar xzf asio.tar.gz
    mkdir -p "${DEPS_DIR}/asio-1.30.2/include"
    cp -r asio-1.30.2/include/* "${DEPS_DIR}/asio-1.30.2/include/"
fi

# Download msgpack (header-only)
if [ ! -d "${DEPS_DIR}/msgpack-arm64" ]; then
    echo "Downloading msgpack..."
    cd /tmp && rm -rf msgpack-*
    wget -q https://github.com/msgpack/msgpack-c/releases/download/cpp-6.1.1/msgpack-cxx-6.1.1.tar.gz
    tar xzf msgpack-cxx-6.1.1.tar.gz
    mkdir -p "${DEPS_DIR}/msgpack-arm64/include"
    cp -r msgpack-cxx-6.1.1/include/* "${DEPS_DIR}/msgpack-arm64/include/"
fi

# Build OpenSSL
if [ ! -f "${DEPS_DIR}/openssl-arm64/lib/libcrypto.a" ]; then
    echo "Building OpenSSL..."
    cd /tmp && rm -rf openssl-*
    wget -q https://www.openssl.org/source/openssl-3.3.2.tar.gz
    tar xzf openssl-3.3.2.tar.gz && cd openssl-3.3.2
    export ANDROID_NDK_ROOT="${ANDROID_NDK_HOME}"
    ./Configure android-arm64 no-shared no-tests --prefix="${DEPS_DIR}/openssl-arm64" -D__ANDROID_API__=${API} >/dev/null
    make -j$(nproc) >/dev/null 2>&1
    make install_sw >/dev/null
fi

# Build SQLite
if [ ! -f "${DEPS_DIR}/sqlite-arm64/lib/libsqlite3.a" ]; then
    echo "Building SQLite..."
    cd /tmp && rm -rf sqlite-*
    wget -q https://www.sqlite.org/2024/sqlite-autoconf-3460000.tar.gz
    tar xzf sqlite-autoconf-3460000.tar.gz && cd sqlite-autoconf-3460000
    ./configure --host=aarch64-linux-android --prefix="${DEPS_DIR}/sqlite-arm64" \
        --enable-static --disable-shared \
        CC="${CC}" AR="${AR}" RANLIB="${RANLIB}" CFLAGS="-fPIC" >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build json-c
if [ ! -f "${DEPS_DIR}/jsonc-arm64/lib/libjson-c.a" ]; then
    echo "Building json-c..."
    cd /tmp && rm -rf json-c-*
    wget -q https://github.com/json-c/json-c/archive/refs/tags/json-c-0.17-20230812.tar.gz
    tar xzf json-c-0.17-20230812.tar.gz && cd json-c-json-c-0.17-20230812
    mkdir build && cd build
    cmake .. -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=android-${API} -DANDROID_STL=c++_static \
        -DCMAKE_INSTALL_PREFIX="${DEPS_DIR}/jsonc-arm64" -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build libcurl
if [ ! -f "${DEPS_DIR}/curl-arm64/lib/libcurl.a" ]; then
    echo "Building curl..."
    cd /tmp && rm -rf curl-*
    wget -q https://curl.se/download/curl-8.10.1.tar.gz
    tar xzf curl-8.10.1.tar.gz && cd curl-8.10.1
    ./configure --host=aarch64-linux-android --prefix="${DEPS_DIR}/curl-arm64" \
        --with-openssl="${DEPS_DIR}/openssl-arm64" \
        --enable-static --disable-shared \
        --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet \
        --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp \
        --disable-gopher --disable-mqtt --disable-manual --disable-docs \
        --without-libidn2 --without-librtmp --without-libpsl \
        CC="${CC}" AR="${AR}" RANLIB="${RANLIB}" \
        CFLAGS="-fPIC -I${DEPS_DIR}/openssl-arm64/include" \
        LDFLAGS="-L${DEPS_DIR}/openssl-arm64/lib" >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

# Build zstd
if [ ! -f "${DEPS_DIR}/zstd-arm64/lib/libzstd.a" ]; then
    echo "Building zstd..."
    cd /tmp && rm -rf zstd-*
    wget -q https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz
    tar xzf zstd-1.5.6.tar.gz && cd zstd-1.5.6/build/cmake
    cmake . -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=android-${API} -DANDROID_STL=c++_static \
        -DCMAKE_INSTALL_PREFIX="${DEPS_DIR}/zstd-arm64" \
        -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON >/dev/null
    make -j$(nproc) >/dev/null && make install >/dev/null
fi

echo "Building libdna_lib.so..."
cp -r /src /tmp/dna-messenger
cd /tmp/dna-messenger
mkdir -p build-android && cd build-android
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=${ANDROID_ABI} \
    -DANDROID_PLATFORM=android-${ANDROID_API_LEVEL} \
    -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIB=ON >/dev/null
make -j$(nproc) dna_lib

# Copy to output
mkdir -p /output/arm64-v8a
cp libdna_lib.so /output/arm64-v8a/
echo "Native library built: /output/arm64-v8a/libdna_lib.so"
'

# Verify native lib
NATIVE_LIB="dna_messenger_flutter/android/app/src/main/jniLibs/arm64-v8a/libdna_lib.so"
if [ ! -f "$NATIVE_LIB" ]; then
    echo "ERROR: Native library build failed!"
    exit 1
fi
echo "==> Native library: $NATIVE_LIB ($(du -h "$NATIVE_LIB" | cut -f1))"

# Step 2: Build Flutter APK
echo ""
echo "==> Step 2/2: Building Flutter APK..."

docker run --rm \
    -v "$PROJECT_DIR:/app" \
    -w /app/dna_messenger_flutter \
    "$FLUTTER_IMAGE" \
    bash -c "flutter pub get && flutter build apk --release"

APK_PATH="dna_messenger_flutter/build/app/outputs/flutter-apk/app-release.apk"

if [ -f "$APK_PATH" ]; then
    cp "$APK_PATH" "dna-messenger-android.apk"
    echo ""
    echo "=========================================="
    echo "BUILD SUCCESSFUL!"
    echo "=========================================="
    echo "APK: dna-messenger-android.apk ($(du -h dna-messenger-android.apk | cut -f1))"
    echo ""
    echo "Install: adb install -r dna-messenger-android.apk"
else
    echo "ERROR: Flutter build failed!"
    exit 1
fi
