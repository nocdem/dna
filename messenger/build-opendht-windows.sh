#!/bin/bash
#
# Build OpenDHT and ALL dependencies for Windows (llvm-mingw cross-compilation)
# This builds a complete P2P stack for Windows
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# llvm-mingw setup (replaces MXE)
LLVM_MINGW_VERSION="20251118"
LLVM_MINGW_DIR="${MXE_DIR:-$HOME/.cache/llvm-mingw}"
LLVM_MINGW_RELEASE="llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-x86_64"
MINGW_PREFIX="${LLVM_MINGW_DIR}/${LLVM_MINGW_RELEASE}"

MXE_TARGET="x86_64-w64-mingw32"
MXE_PREFIX="${MINGW_PREFIX}/${MXE_TARGET}"
BUILD_DIR="/tmp/dna-win-deps"

export PATH="${MINGW_PREFIX}/bin:$PATH"
export PKG_CONFIG_PATH="${MXE_PREFIX}/lib/pkgconfig"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} Building Full P2P Stack for Windows${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "llvm-mingw: ${MINGW_PREFIX}"
echo -e "Target: ${MXE_TARGET}"
echo -e "Prefix: ${MXE_PREFIX}"
echo ""

# Check if already built
if [ -f "${MXE_PREFIX}/lib/libopendht.a" ] && [ -f "${MXE_PREFIX}/include/opendht/dhtrunner.h" ]; then
    echo -e "${GREEN}✓${NC} OpenDHT already built for Windows"
    exit 0
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Create CMake toolchain file for llvm-mingw
TOOLCHAIN_FILE="$BUILD_DIR/toolchain-mingw64.cmake"
cat > "$TOOLCHAIN_FILE" << EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Use llvm-mingw compilers (Clang-based cross-compiler)
set(CMAKE_C_COMPILER ${MINGW_PREFIX}/bin/${MXE_TARGET}-clang)
set(CMAKE_CXX_COMPILER ${MINGW_PREFIX}/bin/${MXE_TARGET}-clang++)
set(CMAKE_RC_COMPILER ${MINGW_PREFIX}/bin/${MXE_TARGET}-windres)
set(CMAKE_AR ${MINGW_PREFIX}/bin/${MXE_TARGET}-ar)
set(CMAKE_RANLIB ${MINGW_PREFIX}/bin/${MXE_TARGET}-ranlib)

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
EOF

echo -e "${GREEN}✓${NC} Created CMake toolchain file: $TOOLCHAIN_FILE"

# 1. Build fmt (formatting library)
echo -e "${BLUE}[1/6] Building fmt...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libfmt.a" ]; then
    if [ ! -d "fmt" ]; then
        git clone --depth 1 --branch 10.2.1 https://github.com/fmtlib/fmt.git
    fi
    cd fmt
    rm -rf build-win
    mkdir -p build-win && cd build-win
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MXE_PREFIX}" \
        -DFMT_TEST=OFF \
        -DFMT_DOC=OFF
    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} fmt installed"
else
    echo -e "${GREEN}✓${NC} fmt already installed"
fi

# 2. Build jsoncpp (JSON library)
echo -e "${BLUE}[2/6] Building jsoncpp...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libjsoncpp.a" ]; then
    if [ ! -d "jsoncpp" ]; then
        git clone --depth 1 --branch 1.9.5 https://github.com/open-source-parsers/jsoncpp.git
    fi
    cd jsoncpp
    rm -rf build-win
    mkdir -p build-win && cd build-win
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MXE_PREFIX}" \
        -DJSONCPP_WITH_TESTS=OFF \
        -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF \
        -DBUILD_SHARED_LIBS=OFF
    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} jsoncpp installed"
else
    echo -e "${GREEN}✓${NC} jsoncpp already installed"
fi

# 3. Build libargon2 (password hashing)
echo -e "${BLUE}[3/6] Building libargon2...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libargon2.a" ]; then
    if [ ! -d "phc-winner-argon2" ]; then
        git clone --depth 1 --branch 20190702 https://github.com/P-H-C/phc-winner-argon2.git
    fi
    cd phc-winner-argon2

    # Cross-compile argon2 (it uses Makefile, not CMake)
    # Only build static library to avoid lld linker issues with -soname
    make clean || true
    make libargon2.a CC="${MXE_TARGET}-gcc" \
         AR="${MXE_TARGET}-ar" \
         RANLIB="${MXE_TARGET}-ranlib" \
         LIBRARY_REL=lib \
         -j$(nproc)

    # Manual install
    mkdir -p "${MXE_PREFIX}/lib" "${MXE_PREFIX}/include"
    cp libargon2.a "${MXE_PREFIX}/lib/"
    cp include/argon2.h "${MXE_PREFIX}/include/"

    # Create pkg-config file
    mkdir -p "${MXE_PREFIX}/lib/pkgconfig"
    cat > "${MXE_PREFIX}/lib/pkgconfig/libargon2.pc" <<EOF
prefix=${MXE_PREFIX}
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libargon2
Description: Argon2 password hashing library
Version: 20190702
Libs: -L\${libdir} -largon2
Cflags: -I\${includedir}
EOF

    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} libargon2 installed"
else
    echo -e "${GREEN}✓${NC} libargon2 already installed"
fi

# 4. Build msgpack-cxx (serialization library)
echo -e "${BLUE}[4/6] Installing msgpack-cxx...${NC}"
if [ ! -f "${MXE_PREFIX}/include/msgpack.hpp" ]; then
    if [ ! -d "msgpack-c" ]; then
        git clone --depth 1 --branch cpp-6.1.0 https://github.com/msgpack/msgpack-c.git
    fi
    cd msgpack-c
    rm -rf build-win
    mkdir -p build-win && cd build-win
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MXE_PREFIX}" \
        -DMSGPACK_BUILD_EXAMPLES=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_USE_BOOST=OFF \
        -DMSGPACK_CXX17=ON
    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} msgpack-cxx installed"
else
    echo -e "${GREEN}✓${NC} msgpack-cxx already installed"
fi

# 5. Build zlib (compression library)
echo -e "${BLUE}[5/10] Building zlib...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libz.a" ]; then
    if [ ! -d "zlib-1.3.1" ]; then
        wget https://zlib.net/zlib-1.3.1.tar.gz
        tar -xzf zlib-1.3.1.tar.gz
    fi
    cd zlib-1.3.1

    # zlib has custom configure script
    CC="${MXE_TARGET}-gcc" \
    AR="${MXE_TARGET}-ar" \
    RANLIB="${MXE_TARGET}-ranlib" \
    ./configure \
        --prefix="${MXE_PREFIX}" \
        --static

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} zlib installed"
else
    echo -e "${GREEN}✓${NC} zlib already installed"
fi

# 6. Build Freetype (font rendering)
echo -e "${BLUE}[6/10] Building Freetype...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libfreetype.a" ]; then
    if [ ! -d "freetype-2.13.3" ]; then
        wget https://download.savannah.gnu.org/releases/freetype/freetype-2.13.3.tar.gz
        tar -xzf freetype-2.13.3.tar.gz
    fi
    cd freetype-2.13.3

    ./configure \
        --host=${MXE_TARGET} \
        --prefix="${MXE_PREFIX}" \
        --disable-shared \
        --enable-static \
        --without-harfbuzz \
        --without-png \
        --without-bzip2 \
        --without-brotli

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} Freetype installed"
else
    echo -e "${GREEN}✓${NC} Freetype already installed"
fi

# 7. Build SQLite3 (database library)
echo -e "${BLUE}[7/10] Building SQLite3...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libsqlite3.a" ]; then
    if [ ! -d "sqlite-autoconf-3470200" ]; then
        wget https://www.sqlite.org/2024/sqlite-autoconf-3470200.tar.gz
        tar -xzf sqlite-autoconf-3470200.tar.gz
    fi
    cd sqlite-autoconf-3470200

    ./configure \
        --host=${MXE_TARGET} \
        --prefix="${MXE_PREFIX}" \
        --disable-shared \
        --enable-static

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} SQLite3 installed"
else
    echo -e "${GREEN}✓${NC} SQLite3 already installed"
fi

# 8. Build OpenSSL (TLS library)
echo -e "${BLUE}[8/10] Building OpenSSL...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libssl.a" ]; then
    if [ ! -d "openssl-3.0.15" ]; then
        wget https://www.openssl.org/source/openssl-3.0.15.tar.gz
        tar -xzf openssl-3.0.15.tar.gz
    fi
    cd openssl-3.0.15

    # OpenSSL uses its own configure system (not autoconf)
    ./Configure mingw64 \
        --prefix="${MXE_PREFIX}" \
        --cross-compile-prefix=${MXE_TARGET}- \
        no-shared \
        no-dso \
        no-engine \
        no-tests \
        -static

    make -j$(nproc)
    make install_sw install_ssldirs
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} OpenSSL installed"
else
    echo -e "${GREEN}✓${NC} OpenSSL already installed"
fi

# 9. Build json-c (JSON library)
echo -e "${BLUE}[9/11] Building json-c...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libjson-c.a" ]; then
    if [ ! -d "json-c-0.17" ]; then
        wget https://github.com/json-c/json-c/archive/refs/tags/json-c-0.17-20230812.tar.gz
        tar -xzf json-c-0.17-20230812.tar.gz
        mv json-c-json-c-0.17-20230812 json-c-0.17
    fi
    cd json-c-0.17
    rm -rf build-win
    mkdir -p build-win && cd build-win

    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MXE_PREFIX}" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON \
        -DBUILD_APPS=OFF \
        -DBUILD_TESTING=OFF

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} json-c installed"
else
    echo -e "${GREEN}✓${NC} json-c already installed"
fi

# 10. Build CURL (HTTP library)
echo -e "${BLUE}[10/11] Building CURL...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libcurl.a" ]; then
    if [ ! -d "curl-8.11.0" ]; then
        wget https://curl.se/download/curl-8.11.0.tar.gz
        tar -xzf curl-8.11.0.tar.gz
    fi
    cd curl-8.11.0

    # Configure CURL with OpenSSL (static build)
    ./configure \
        --host=${MXE_TARGET} \
        --prefix="${MXE_PREFIX}" \
        --with-openssl="${MXE_PREFIX}" \
        --disable-shared \
        --enable-static \
        --disable-ldap \
        --disable-ldaps \
        --without-librtmp \
        --without-libidn2 \
        --without-libpsl \
        --without-brotli \
        --without-zstd \
        CPPFLAGS="-I${MXE_PREFIX}/include" \
        LDFLAGS="-L${MXE_PREFIX}/lib64 -L${MXE_PREFIX}/lib"

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} CURL installed"
else
    echo -e "${GREEN}✓${NC} CURL already installed"
fi

# 11. Build OpenDHT (finally!)
echo -e "${BLUE}[11/11] Building OpenDHT...${NC}"
if [ ! -d "opendht" ]; then
    git clone --depth 1 --branch v3.2.0 https://github.com/savoirfairelinux/opendht.git
fi
cd opendht
rm -rf build-win
mkdir -p build-win && cd build-win

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DCMAKE_INSTALL_PREFIX="${MXE_PREFIX}" \
    -DCMAKE_PREFIX_PATH="${MXE_PREFIX}" \
    -DOPENDHT_PYTHON=OFF \
    -DOPENDHT_TOOLS=OFF \
    -DBUILD_TESTING=OFF \
    -DOPENDHT_PROXY_SERVER=OFF \
    -DOPENDHT_PUSH_NOTIFICATIONS=OFF \
    -DOPENDHT_HTTP=OFF \
    -DOPENDHT_PEER_DISCOVERY=OFF \
    -DOPENDHT_STATIC=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_CXX_FLAGS="-DGNUTLS_STATIC"

make -j$(nproc)
make install

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN} ✓ Full P2P Stack Built for Windows!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo -e "Dependencies installed:"
echo -e "  - fmt (formatting)"
echo -e "  - jsoncpp (JSON)"
echo -e "  - libargon2 (password hashing)"
echo -e "  - msgpack-cxx (serialization)"
echo -e "  - zlib (compression)"
echo -e "  - Freetype (font rendering)"
echo -e "  - SQLite3 (database)"
echo -e "  - OpenSSL (TLS library)"
echo -e "  - json-c (JSON library)"
echo -e "  - CURL (HTTP library)"
echo -e "  - OpenDHT (P2P DHT library)"
echo ""
echo -e "Windows builds now have full P2P support!"
