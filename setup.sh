#!/bin/bash
# DNA Monorepo — Full setup script for fresh Linux machines
# Usage: curl -fsSL https://raw.githubusercontent.com/nocdem/dna/main/setup.sh | bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

INSTALL_DIR="${DNA_DIR:-/opt/dna}"
REPO_URL="https://github.com/nocdem/dna.git"

# ── Pre-flight checks ──────────────────────────────────────────────
command -v git >/dev/null 2>&1 || error "git not found. Install it first: sudo apt install git"

if [ -d "$INSTALL_DIR/.git" ]; then
    warn "$INSTALL_DIR already exists, pulling latest..."
    cd "$INSTALL_DIR" && git pull
else
    info "Cloning DNA monorepo to $INSTALL_DIR..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami)" "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ── Install dependencies ───────────────────────────────────────────
info "Installing build dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        build-essential cmake pkg-config xxd \
        libssl-dev libcurl4-openssl-dev libjson-c-dev \
        libsqlite3-dev libzstd-dev \
        libgnutls28-dev libargon2-dev
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y \
        gcc gcc-c++ make cmake pkgconf vim-common \
        openssl-devel libcurl-devel json-c-devel \
        sqlite-devel libzstd-devel \
        gnutls-devel libargon2-devel
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm --needed \
        base-devel cmake pkgconf xxd \
        openssl curl json-c sqlite zstd \
        gnutls argon2
else
    warn "Unknown package manager — install these manually:"
    warn "  cmake, openssl, curl, json-c, sqlite3, zstd, gnutls, argon2"
fi

# ── Build messenger (must be first — dnac links against it) ───────
info "Building messenger..."
cd "$INSTALL_DIR/messenger"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIB=ON -DBUILD_GUI=OFF
make -j"$(nproc)"
info "Messenger built OK"

# ── Build nodus ────────────────────────────────────────────────────
info "Building nodus..."
cd "$INSTALL_DIR/nodus"
mkdir -p build && cd build
cmake ..
make -j"$(nproc)"
info "Nodus built OK"

# ── Build dnac ─────────────────────────────────────────────────────
info "Building dnac..."
cd "$INSTALL_DIR/dnac"
mkdir -p build && cd build
cmake ..
make -j"$(nproc)"
info "DNAC built OK"

# ── Run tests ──────────────────────────────────────────────────────
info "Running tests..."

FAIL=0

cd "$INSTALL_DIR/messenger/build"
if ctest --output-on-failure 2>&1; then
    info "Messenger tests: PASS"
else
    warn "Messenger tests: SOME FAILURES"
    FAIL=1
fi

cd "$INSTALL_DIR/nodus/build"
if ctest --output-on-failure 2>&1; then
    info "Nodus tests: PASS"
else
    warn "Nodus tests: SOME FAILURES"
    FAIL=1
fi

# ── Done ───────────────────────────────────────────────────────────
echo ""
info "=============================="
info "  DNA Monorepo setup complete"
info "=============================="
echo ""
echo "  Messenger CLI:  $INSTALL_DIR/messenger/build/cli/dna-messenger-cli"
echo "  Nodus server:   $INSTALL_DIR/nodus/build/nodus-server"
echo "  DNAC CLI:       $INSTALL_DIR/dnac/build/dnac"
echo ""

if [ $FAIL -ne 0 ]; then
    warn "Some tests failed — check output above"
    exit 1
fi
