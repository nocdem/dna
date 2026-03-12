#!/bin/bash
# DNA Connect — Full setup script for fresh Linux machines
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
        libgnutls28-dev libargon2-dev \
        libgtk-3-dev libblkid-dev liblzma-dev libsecret-1-dev
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y \
        gcc gcc-c++ make cmake pkgconf vim-common \
        openssl-devel libcurl-devel json-c-devel \
        sqlite-devel libzstd-devel \
        gnutls-devel libargon2-devel \
        gtk3-devel libblkid-devel xz-devel libsecret-devel
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm --needed \
        base-devel cmake pkgconf xxd \
        openssl curl json-c sqlite zstd \
        gnutls argon2 \
        gtk3 util-linux-libs xz libsecret
else
    warn "Unknown package manager — install these manually:"
    warn "  cmake, openssl, curl, json-c, sqlite3, zstd, gnutls, argon2"
    warn "  gtk3, libblkid, lzma, libsecret (for Flutter desktop)"
fi

# ── Install Flutter ───────────────────────────────────────────────
FLUTTER_DIR="$HOME/.flutter-sdk"
if command -v flutter >/dev/null 2>&1; then
    info "Flutter already installed: $(flutter --version 2>/dev/null | head -1)"
elif [ -x "$FLUTTER_DIR/bin/flutter" ]; then
    info "Flutter found at $FLUTTER_DIR"
    export PATH="$FLUTTER_DIR/bin:$PATH"
else
    info "Installing Flutter SDK..."
    git clone https://github.com/flutter/flutter.git -b stable "$FLUTTER_DIR"
    export PATH="$FLUTTER_DIR/bin:$PATH"
    flutter precache --linux
    info "Flutter installed: $(flutter --version 2>/dev/null | head -1)"

    if ! grep -q 'flutter-sdk/bin' "$HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH="$HOME/.flutter-sdk/bin:$PATH"' >> "$HOME/.bashrc"
        info "Added Flutter to ~/.bashrc"
    fi
fi

# ── Build C library ───────────────────────────────────────────────
info "Building messenger C library..."
cd "$INSTALL_DIR/messenger"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIB=ON -DBUILD_GUI=OFF
make -j"$(nproc)"
info "C library built OK"

# ── Build Flutter app ─────────────────────────────────────────────
info "Building Flutter app (Linux desktop)..."
cd "$INSTALL_DIR/messenger/dna_messenger_flutter"
flutter pub get
flutter build linux
info "Flutter app built OK"

# ── Run tests ─────────────────────────────────────────────────────
info "Running C library tests..."
cd "$INSTALL_DIR/messenger/build"
if ctest --output-on-failure 2>&1; then
    info "Tests: PASS"
else
    warn "Tests: SOME FAILURES"
fi

# ── Done ──────────────────────────────────────────────────────────
echo ""
info "=============================="
info "  DNA Connect setup complete"
info "=============================="
echo ""
echo "  CLI tool:     $INSTALL_DIR/messenger/build/cli/dna-messenger-cli"
echo "  Flutter app:  $INSTALL_DIR/messenger/dna_messenger_flutter/build/linux/x64/release/bundle/dna_messenger"
echo ""
echo "  Run the app:  cd $INSTALL_DIR/messenger/dna_messenger_flutter && flutter run -d linux"
echo ""
