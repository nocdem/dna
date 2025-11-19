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
LLVM_MINGW_RELEASE="llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-x86_64-linux"
MINGW_PREFIX="${LLVM_MINGW_DIR}/${LLVM_MINGW_RELEASE}"

MXE_TARGET="x86_64-w64-mingw32"
MXE_PREFIX="${MINGW_PREFIX}/${MXE_TARGET}"
BUILD_DIR="/tmp/dna-win-deps"

export PATH="${MINGW_PREFIX}/bin:$PATH"
export PKG_CONFIG_PATH="${MXE_PREFIX}/lib/pkgconfig"
export CMAKE_PREFIX_PATH="${MXE_PREFIX}"

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

# 1. Build fmt (formatting library)
echo -e "${BLUE}[1/5] Building fmt...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libfmt.a" ]; then
    if [ ! -d "fmt" ]; then
        git clone --depth 1 --branch 10.2.1 https://github.com/fmtlib/fmt.git
    fi
    cd fmt
    mkdir -p build-win && cd build-win
    ${MXE_TARGET}-cmake .. \
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
echo -e "${BLUE}[2/5] Building jsoncpp...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libjsoncpp.a" ]; then
    if [ ! -d "jsoncpp" ]; then
        git clone --depth 1 --branch 1.9.5 https://github.com/open-source-parsers/jsoncpp.git
    fi
    cd jsoncpp
    mkdir -p build-win && cd build-win
    ${MXE_TARGET}-cmake .. \
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
echo -e "${BLUE}[3/5] Building libargon2...${NC}"
if [ ! -f "${MXE_PREFIX}/lib/libargon2.a" ]; then
    if [ ! -d "phc-winner-argon2" ]; then
        git clone --depth 1 --branch 20190702 https://github.com/P-H-C/phc-winner-argon2.git
    fi
    cd phc-winner-argon2

    # Cross-compile argon2 (it uses Makefile, not CMake)
    make clean || true
    make CC="${MXE_TARGET}-gcc" \
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
echo -e "${BLUE}[4/5] Installing msgpack-cxx...${NC}"
if [ ! -f "${MXE_PREFIX}/include/msgpack.hpp" ]; then
    if [ ! -d "msgpack-c" ]; then
        git clone --depth 1 --branch cpp-6.1.0 https://github.com/msgpack/msgpack-c.git
    fi
    cd msgpack-c
    mkdir -p build-win && cd build-win
    ${MXE_TARGET}-cmake .. \
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

# 5. Build OpenDHT (finally!)
echo -e "${BLUE}[5/5] Building OpenDHT...${NC}"
if [ ! -d "opendht" ]; then
    git clone --depth 1 --branch v3.2.0 https://github.com/savoirfairelinux/opendht.git
fi
cd opendht
rm -rf build-win
mkdir -p build-win && cd build-win

${MXE_TARGET}-cmake .. \
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
echo -e "  - OpenDHT (P2P DHT library)"
echo ""
echo -e "Windows builds now have full P2P support!"
