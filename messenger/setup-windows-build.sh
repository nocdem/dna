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

# llvm-mingw setup
LLVM_MINGW_VERSION="20251118"
LLVM_MINGW_DIR="${LLVM_MINGW_DIR:-$HOME/.cache/llvm-mingw}"
LLVM_MINGW_RELEASE="llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-x86_64"
MINGW_PREFIX="${LLVM_MINGW_DIR}/${LLVM_MINGW_RELEASE}"

MINGW_TARGET="x86_64-w64-mingw32"
MINGW_TARGET_PREFIX="${MINGW_PREFIX}/${MINGW_TARGET}"
BUILD_DIR="/tmp/dna-win-deps"

export PATH="${MINGW_PREFIX}/bin:$PATH"
export PKG_CONFIG_PATH="${MINGW_TARGET_PREFIX}/lib/pkgconfig"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} Building Full P2P Stack for Windows${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "llvm-mingw: ${MINGW_PREFIX}"
echo -e "Target: ${MINGW_TARGET}"
echo -e "Prefix: ${MINGW_TARGET_PREFIX}"
echo ""

# Check if already built
if [ -f "${MINGW_TARGET_PREFIX}/lib/libopendht.a" ] && [ -f "${MINGW_TARGET_PREFIX}/include/opendht/dhtrunner.h" ]; then
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

# Prevent system header inclusion - use sysroot
set(CMAKE_SYSROOT ${MINGW_TARGET_PREFIX})
set(CMAKE_C_FLAGS "--sysroot=${MINGW_TARGET_PREFIX}")
set(CMAKE_CXX_FLAGS "--sysroot=${MINGW_TARGET_PREFIX}")

# Force static linking
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
EOF

echo -e "${GREEN}✓${NC} Created CMake toolchain file: $TOOLCHAIN_FILE"

# 1. Build fmt (formatting library)
echo -e "${BLUE}[1/6] Building fmt...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libfmt.a" ]; then
    if [ ! -d "fmt" ]; then
        git clone --depth 1 --branch 10.2.1 https://github.com/fmtlib/fmt.git
    fi
    cd fmt
    rm -rf build-win
    mkdir -p build-win && cd build-win
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MINGW_TARGET_PREFIX}" \
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
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libjsoncpp.a" ]; then
    if [ ! -d "jsoncpp" ]; then
        git clone --depth 1 --branch 1.9.5 https://github.com/open-source-parsers/jsoncpp.git
    fi
    cd jsoncpp
    rm -rf build-win
    mkdir -p build-win && cd build-win
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MINGW_TARGET_PREFIX}" \
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
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libargon2.a" ]; then
    if [ ! -d "phc-winner-argon2" ]; then
        git clone --depth 1 --branch 20190702 https://github.com/P-H-C/phc-winner-argon2.git
    fi
    cd phc-winner-argon2

    # Cross-compile argon2 (it uses Makefile, not CMake)
    # Only build static library to avoid lld linker issues with -soname
    make clean || true
    make libargon2.a CC="${MINGW_TARGET}-gcc" \
         AR="${MINGW_TARGET}-ar" \
         RANLIB="${MINGW_TARGET}-ranlib" \
         LIBRARY_REL=lib \
         -j$(nproc)

    # Manual install
    mkdir -p "${MINGW_TARGET_PREFIX}/lib" "${MINGW_TARGET_PREFIX}/include"
    cp libargon2.a "${MINGW_TARGET_PREFIX}/lib/"
    cp include/argon2.h "${MINGW_TARGET_PREFIX}/include/"

    # Create pkg-config file
    mkdir -p "${MINGW_TARGET_PREFIX}/lib/pkgconfig"
    cat > "${MINGW_TARGET_PREFIX}/lib/pkgconfig/libargon2.pc" <<EOF
prefix=${MINGW_TARGET_PREFIX}
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
if [ ! -f "${MINGW_TARGET_PREFIX}/include/msgpack.hpp" ]; then
    if [ ! -d "msgpack-c" ]; then
        git clone --depth 1 --branch cpp-6.1.0 https://github.com/msgpack/msgpack-c.git
    fi
    cd msgpack-c
    rm -rf build-win
    mkdir -p build-win && cd build-win
    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MINGW_TARGET_PREFIX}" \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
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

# 5. Build GMP (GNU Multiple Precision library - required by Nettle)
echo -e "${BLUE}[5/14] Building GMP...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libgmp.a" ]; then
    if [ ! -d "gmp-6.3.0" ]; then
        wget https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
        tar -xf gmp-6.3.0.tar.xz
    fi
    cd gmp-6.3.0

    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --enable-static \
        --disable-shared

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} GMP installed"
else
    echo -e "${GREEN}✓${NC} GMP already installed"
fi

# 6. Build Nettle (low-level crypto library - required by GnuTLS)
echo -e "${BLUE}[6/14] Building Nettle...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libnettle.a" ]; then
    if [ ! -d "nettle-3.9.1" ]; then
        wget https://ftp.gnu.org/gnu/nettle/nettle-3.9.1.tar.gz
        tar -xzf nettle-3.9.1.tar.gz
    fi
    cd nettle-3.9.1

    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --enable-static \
        --disable-shared \
        --disable-documentation

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} Nettle installed"
else
    echo -e "${GREEN}✓${NC} Nettle already installed"
fi

# 7. Build Brotli (compression library - required by GnuTLS)
echo -e "${BLUE}[7/15] Building Brotli...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libbrotlicommon.a" ]; then
    if [ ! -d "brotli" ]; then
        git clone --depth 1 --branch v1.1.0 https://github.com/google/brotli.git
    fi
    cd brotli
    rm -rf build-win
    mkdir -p build-win && cd build-win

    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
        -DCMAKE_INSTALL_PREFIX="${MINGW_TARGET_PREFIX}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} Brotli installed"
else
    echo -e "${GREEN}✓${NC} Brotli already installed"
fi

# 8. Build zstd (compression library - required by GnuTLS)
echo -e "${BLUE}[8/16] Building zstd...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libzstd.a" ]; then
    if [ ! -d "zstd-1.5.6" ]; then
        wget https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz
        tar -xzf zstd-1.5.6.tar.gz
    fi
    cd zstd-1.5.6

    # zstd uses make with custom variables
    # Build only static library to avoid lld soname issues
    cd lib
    make -j$(nproc) \
        CC="${MINGW_TARGET}-gcc" \
        CXX="${MINGW_TARGET}-g++" \
        AR="${MINGW_TARGET}-ar" \
        RANLIB="${MINGW_TARGET}-ranlib" \
        PREFIX="${MINGW_TARGET_PREFIX}" \
        MOREFLAGS="-DZSTD_MULTITHREAD" \
        libzstd.a

    # Install manually
    mkdir -p "${MINGW_TARGET_PREFIX}/lib"
    mkdir -p "${MINGW_TARGET_PREFIX}/include"
    cp libzstd.a "${MINGW_TARGET_PREFIX}/lib/"
    cp zstd.h zdict.h zstd_errors.h "${MINGW_TARGET_PREFIX}/include/"
    cd ..

    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} zstd installed"
else
    echo -e "${GREEN}✓${NC} zstd already installed"
fi

# 9. Build libidn2 (Internationalized Domain Names - required by GnuTLS)
echo -e "${BLUE}[9/18] Building libidn2...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libidn2.a" ]; then
    if [ ! -d "libidn2-2.3.7" ]; then
        wget https://ftp.gnu.org/gnu/libidn/libidn2-2.3.7.tar.gz
        tar -xzf libidn2-2.3.7.tar.gz
    fi
    cd libidn2-2.3.7

    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --enable-static \
        --disable-shared \
        --disable-doc

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} libidn2 installed"
else
    echo -e "${GREEN}✓${NC} libidn2 already installed"
fi

# 10. Build GnuTLS (TLS library - required by OpenDHT)
echo -e "${BLUE}[10/17] Building GnuTLS...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libgnutls.a" ]; then
    if [ ! -d "gnutls-3.8.3" ]; then
        wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.3.tar.xz
        tar -xf gnutls-3.8.3.tar.xz
    fi
    cd gnutls-3.8.3

    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --enable-static \
        --disable-shared \
        --disable-doc \
        --disable-tests \
        --disable-tools \
        --disable-cxx \
        --disable-guile \
        --with-included-libtasn1 \
        --with-included-unistring \
        --without-p11-kit \
        --without-tpm \
        --with-tpm2=no

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} GnuTLS installed"
else
    echo -e "${GREEN}✓${NC} GnuTLS already installed"
fi

# 11. Build zlib (compression library)
echo -e "${BLUE}[11/17] Building zlib...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libz.a" ]; then
    if [ ! -d "zlib-1.3.1" ]; then
        wget https://zlib.net/zlib-1.3.1.tar.gz
        tar -xzf zlib-1.3.1.tar.gz
    fi
    cd zlib-1.3.1

    # zlib has custom configure script
    CC="${MINGW_TARGET}-gcc" \
    AR="${MINGW_TARGET}-ar" \
    RANLIB="${MINGW_TARGET}-ranlib" \
    ./configure \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --static

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} zlib installed"
else
    echo -e "${GREEN}✓${NC} zlib already installed"
fi

# 12. Build Freetype (font rendering)
echo -e "${BLUE}[12/17] Building Freetype...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libfreetype.a" ]; then
    if [ ! -d "freetype-2.13.3" ]; then
        wget https://download.savannah.gnu.org/releases/freetype/freetype-2.13.3.tar.gz
        tar -xzf freetype-2.13.3.tar.gz
    fi
    cd freetype-2.13.3

    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
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

# 13. Build SQLite3 (database library)
echo -e "${BLUE}[13/17] Building SQLite3...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libsqlite3.a" ]; then
    if [ ! -d "sqlite-autoconf-3470200" ]; then
        wget https://www.sqlite.org/2024/sqlite-autoconf-3470200.tar.gz
        tar -xzf sqlite-autoconf-3470200.tar.gz
    fi
    cd sqlite-autoconf-3470200

    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --disable-shared \
        --enable-static

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} SQLite3 installed"
else
    echo -e "${GREEN}✓${NC} SQLite3 already installed"
fi

# 14. Build OpenSSL (TLS library)
echo -e "${BLUE}[14/17] Building OpenSSL...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libssl.a" ]; then
    if [ ! -d "openssl-3.0.15" ]; then
        wget https://www.openssl.org/source/openssl-3.0.15.tar.gz
        tar -xzf openssl-3.0.15.tar.gz
    fi
    cd openssl-3.0.15

    # OpenSSL uses its own configure system (not autoconf)
    ./Configure mingw64 \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --cross-compile-prefix=${MINGW_TARGET}- \
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

# 15. Build json-c (JSON library)
echo -e "${BLUE}[15/17] Building json-c...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libjson-c.a" ]; then
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
        -DCMAKE_INSTALL_PREFIX="${MINGW_TARGET_PREFIX}" \
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

# 16. Build CURL (HTTP library)
echo -e "${BLUE}[16/17] Building CURL...${NC}"
if [ ! -f "${MINGW_TARGET_PREFIX}/lib/libcurl.a" ]; then
    if [ ! -d "curl-8.11.0" ]; then
        wget https://curl.se/download/curl-8.11.0.tar.gz
        tar -xzf curl-8.11.0.tar.gz
    fi
    cd curl-8.11.0

    # Configure CURL with OpenSSL (static build)
    ./configure \
        --host=${MINGW_TARGET} \
        --prefix="${MINGW_TARGET_PREFIX}" \
        --with-openssl="${MINGW_TARGET_PREFIX}" \
        --disable-shared \
        --enable-static \
        --disable-ldap \
        --disable-ldaps \
        --without-librtmp \
        --without-libidn2 \
        --without-libpsl \
        --without-brotli \
        --without-zstd \
        CPPFLAGS="-I${MINGW_TARGET_PREFIX}/include" \
        LDFLAGS="-L${MINGW_TARGET_PREFIX}/lib64 -L${MINGW_TARGET_PREFIX}/lib"

    make -j$(nproc)
    make install
    cd "$BUILD_DIR"
    echo -e "${GREEN}✓${NC} CURL installed"
else
    echo -e "${GREEN}✓${NC} CURL already installed"
fi

# 17. Build OpenDHT (finally!)
echo -e "${BLUE}[17/17] Building OpenDHT...${NC}"
if [ ! -d "opendht" ]; then
    git clone --depth 1 --branch v3.2.0 https://github.com/savoirfairelinux/opendht.git
fi
cd opendht
rm -rf build-win
mkdir -p build-win && cd build-win

# Prevent pkg-config from finding system packages
export PKG_CONFIG_PATH="${MINGW_TARGET_PREFIX}/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="${MINGW_TARGET_PREFIX}/lib/pkgconfig"

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
    -DCMAKE_INSTALL_PREFIX="${MINGW_TARGET_PREFIX}" \
    -DCMAKE_PREFIX_PATH="${MINGW_TARGET_PREFIX}" \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DOPENDHT_PYTHON=OFF \
    -DOPENDHT_TOOLS=OFF \
    -DOPENDHT_DOCUMENTATION=OFF \
    -DBUILD_TESTING=OFF \
    -DOPENDHT_PROXY_SERVER=OFF \
    -DOPENDHT_PUSH_NOTIFICATIONS=OFF \
    -DOPENDHT_HTTP=OFF \
    -DOPENDHT_PEER_DISCOVERY=OFF \
    -DOPENDHT_STATIC=ON \
    -DBUILD_SHARED_LIBS=OFF

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
