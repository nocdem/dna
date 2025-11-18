#!/bin/bash
#
# OpenDHT 3.5.5 Installation Script
# DNA Messenger - Post-Quantum Encrypted Messenger
#
# This script installs OpenDHT 3.5.5 from source when the system repository
# provides an outdated version (< 3.0).
#
# Tested on:
#   - Debian 11 (Bullseye) - repo has 2.4.x
#   - Debian 12 (Bookworm) - repo has 2.4.12
#   - Ubuntu 20.04 (Focal) - repo has 2.4.x
#   - Ubuntu 22.04 (Jammy) - repo has 3.1.x (this script still upgrades to 3.5.5)
#
# Usage:
#   ./scripts/install-opendht.sh
#
# Author: DNA Messenger Team
# Date: 2025-11-18
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
OPENDHT_VERSION="3.5.5"
OPENDHT_TAG="v${OPENDHT_VERSION}"
BUILD_DIR="/tmp/opendht-build-$$"
INSTALL_PREFIX="/usr/local"

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

print_header() {
    echo ""
    print_msg "$BLUE" "=========================================="
    print_msg "$BLUE" "$@"
    print_msg "$BLUE" "=========================================="
    echo ""
}

print_success() {
    print_msg "$GREEN" "✓ $@"
}

print_error() {
    print_msg "$RED" "✗ $@"
}

print_warning() {
    print_msg "$YELLOW" "⚠ $@"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Do not run this script as root!"
    print_msg "$NC" "Run as normal user. The script will use sudo when needed."
    exit 1
fi

# Check OS
print_header "OpenDHT ${OPENDHT_VERSION} Installation Script"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    print_msg "$NC" "Operating System: $NAME $VERSION"
else
    print_error "Cannot detect OS version"
    exit 1
fi

# Check current OpenDHT version
print_msg "$NC" ""
print_msg "$NC" "Checking current OpenDHT version..."
if command -v pkg-config &> /dev/null; then
    CURRENT_VERSION=$(pkg-config --modversion opendht 2>/dev/null || echo "not installed")
    if [ "$CURRENT_VERSION" = "not installed" ]; then
        print_warning "OpenDHT not installed"
    elif [ "$CURRENT_VERSION" = "$OPENDHT_VERSION" ]; then
        print_success "OpenDHT ${OPENDHT_VERSION} already installed!"
        print_msg "$NC" "Nothing to do. Exiting."
        exit 0
    else
        print_warning "Current version: $CURRENT_VERSION (requires ${OPENDHT_VERSION})"
    fi
else
    print_error "pkg-config not found. Installing dependencies..."
fi

# Confirm installation
print_msg "$NC" ""
print_msg "$NC" "This script will:"
print_msg "$NC" "  1. Remove old OpenDHT package (if installed)"
print_msg "$NC" "  2. Install build dependencies"
print_msg "$NC" "  3. Build OpenDHT ${OPENDHT_VERSION} from source"
print_msg "$NC" "  4. Install to ${INSTALL_PREFIX}"
print_msg "$NC" ""
read -p "Continue? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    print_msg "$NC" "Installation cancelled."
    exit 0
fi

# Step 1: Remove old package
print_header "Step 1/4: Removing old OpenDHT package"

if dpkg -l | grep -q libopendht-dev; then
    print_msg "$NC" "Removing libopendht-dev package..."
    sudo apt remove -y libopendht-dev
    print_success "Old package removed"
else
    print_msg "$NC" "No package installation found (skip)"
fi

# Step 2: Install dependencies
print_header "Step 2/4: Installing build dependencies"

print_msg "$NC" "Updating package lists..."
sudo apt update

print_msg "$NC" "Installing dependencies..."
sudo apt install -y \
    git \
    cmake \
    build-essential \
    pkg-config \
    libncurses5-dev \
    libreadline-dev \
    nettle-dev \
    libgnutls28-dev \
    libjsoncpp-dev \
    libargon2-dev \
    libssl-dev \
    libfmt-dev \
    libmsgpack-dev \
    libasio-dev \
    libcppunit-dev

print_success "Dependencies installed"

# Step 3: Build OpenDHT
print_header "Step 3/4: Building OpenDHT ${OPENDHT_VERSION}"

print_msg "$NC" "Creating build directory: ${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

print_msg "$NC" "Cloning OpenDHT repository..."
git clone https://github.com/savoirfairelinux/opendht.git
cd opendht

print_msg "$NC" "Checking out version ${OPENDHT_TAG}..."
git checkout "${OPENDHT_TAG}"

print_msg "$NC" "Configuring build..."
mkdir build && cd build
cmake .. \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DOPENDHT_PYTHON=OFF \
    -DOPENDHT_TOOLS=ON \
    -DOPENDHT_STATIC=OFF \
    -DCMAKE_BUILD_TYPE=Release

print_msg "$NC" "Compiling (using all CPU cores)..."
CPU_CORES=$(nproc)
print_msg "$NC" "Building with ${CPU_CORES} parallel jobs..."
make -j${CPU_CORES}

print_success "Build completed"

# Step 4: Install
print_header "Step 4/4: Installing OpenDHT"

print_msg "$NC" "Installing to ${INSTALL_PREFIX}..."
sudo make install

print_msg "$NC" "Updating library cache..."
sudo ldconfig

print_success "Installation completed"

# Cleanup
print_msg "$NC" ""
print_msg "$NC" "Cleaning up build directory..."
cd /
rm -rf "${BUILD_DIR}"
print_success "Cleanup done"

# Verify installation
print_header "Verification"

INSTALLED_VERSION=$(pkg-config --modversion opendht 2>/dev/null || echo "ERROR")

if [ "$INSTALLED_VERSION" = "$OPENDHT_VERSION" ]; then
    print_success "OpenDHT ${OPENDHT_VERSION} installed successfully!"
    print_msg "$NC" ""
    print_msg "$NC" "Library path: $(pkg-config --variable=libdir opendht)"
    print_msg "$NC" "Include path: $(pkg-config --variable=includedir opendht)"
    print_msg "$NC" ""
    print_success "You can now build DNA Messenger!"
    print_msg "$NC" ""
    print_msg "$NC" "Next steps:"
    print_msg "$NC" "  cd /path/to/dna-messenger"
    print_msg "$NC" "  rm -rf build && mkdir build && cd build"
    print_msg "$NC" "  cmake .."
    print_msg "$NC" "  make -j${CPU_CORES}"
    print_msg "$NC" ""
else
    print_error "Installation verification failed!"
    print_msg "$NC" "Expected version: ${OPENDHT_VERSION}"
    print_msg "$NC" "Installed version: ${INSTALLED_VERSION}"
    exit 1
fi

print_header "Installation Complete"
