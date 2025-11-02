#!/bin/bash
#
# DNA Messenger - Quick Build Script
# Downloads latest version from GitHub and builds
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

REPO_URL="https://github.com/nocdem/dna-messenger.git"
INSTALL_DIR="${DNA_INSTALL_DIR:-$HOME/dna-messenger}"
BUILD_TYPE="${BUILD_TYPE:-Release}"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} DNA Messenger - Build Script${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "Repository: ${REPO_URL}"
echo -e "Install Directory: ${INSTALL_DIR}"
echo -e "Build Type: ${BUILD_TYPE}"
echo ""

# Check for required dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"
MISSING_DEPS=""

for cmd in git cmake make gcc g++ pkg-config; do
    if ! command -v $cmd &> /dev/null; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done

if [ ! -z "$MISSING_DEPS" ]; then
    echo -e "${RED}✗ Missing dependencies:${MISSING_DEPS}${NC}"
    echo -e "${YELLOW}Install with:${NC}"
    echo -e "  sudo apt-get update"
    echo -e "  sudo apt-get install -y git cmake build-essential pkg-config libssl-dev libpq-dev libopendht-dev qtbase5-dev qtmultimedia5-dev libcurl4-openssl-dev libjson-c-dev"
    exit 1
fi

echo -e "${GREEN}✓${NC} All required tools found"

# Download or update repository
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Directory exists, pulling latest changes...${NC}"
    cd "$INSTALL_DIR"

    # Stash any local changes
    if ! git diff-index --quiet HEAD --; then
        echo -e "${YELLOW}Stashing local changes...${NC}"
        git stash
    fi

    # Pull latest
    git pull origin main
    echo -e "${GREEN}✓${NC} Updated to latest version"
else
    echo -e "${YELLOW}Cloning repository...${NC}"
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    echo -e "${GREEN}✓${NC} Repository cloned"
fi

# Show version info
GIT_SHA=$(git rev-parse --short HEAD)
BUILD_DATE=$(date +%Y-%m-%d)
echo -e "${BLUE}Version:${NC} $GIT_SHA ($BUILD_DATE)"
echo ""

# Build
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} Building DNA Messenger${NC}"
echo -e "${BLUE}=========================================${NC}"

# Clean old build
if [ -d "build" ]; then
    echo -e "${YELLOW}Cleaning old build...${NC}"
    rm -rf build
fi

mkdir -p build
cd build

# Configure
echo -e "${YELLOW}Configuring with CMake...${NC}"
if [ "$BUILD_TYPE" = "Debug" ]; then
    cmake .. -DCMAKE_BUILD_TYPE=Debug
else
    cmake .. -DCMAKE_BUILD_TYPE=Release
fi

# Build
echo -e "${YELLOW}Building (this may take a few minutes)...${NC}"
CORES=$(nproc)
echo -e "Using ${CORES} cores"

if make -j${CORES}; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN} ✓ Build Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""

    # Show what was built
    echo -e "${BLUE}Built executables:${NC}"

    if [ -f "dna_messenger" ]; then
        SIZE=$(du -h dna_messenger | cut -f1)
        echo -e "  ${GREEN}✓${NC} CLI:  $INSTALL_DIR/build/dna_messenger (${SIZE})"
    fi

    if [ -f "gui/dna_messenger_gui" ]; then
        SIZE=$(du -h gui/dna_messenger_gui | cut -f1)
        echo -e "  ${GREEN}✓${NC} GUI:  $INSTALL_DIR/build/gui/dna_messenger_gui (${SIZE})"
    fi

    echo ""
    echo -e "${BLUE}Quick start:${NC}"
    echo -e "  CLI:  cd $INSTALL_DIR/build && ./dna_messenger --help"
    echo -e "  GUI:  cd $INSTALL_DIR/build/gui && ./dna_messenger_gui"
    echo ""

    # Optional: Create symlinks in ~/bin if it exists
    if [ -d "$HOME/bin" ]; then
        echo -e "${YELLOW}Creating symlinks in ~/bin...${NC}"
        ln -sf "$INSTALL_DIR/build/dna_messenger" "$HOME/bin/dna-messenger" 2>/dev/null && \
            echo -e "  ${GREEN}✓${NC} CLI: dna-messenger"

        if [ -f "gui/dna_messenger_gui" ]; then
            ln -sf "$INSTALL_DIR/build/gui/dna_messenger_gui" "$HOME/bin/dna-messenger-gui" 2>/dev/null && \
                echo -e "  ${GREEN}✓${NC} GUI: dna-messenger-gui"
        fi
        echo ""
    fi

    exit 0
else
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED} ✗ Build Failed${NC}"
    echo -e "${RED}=========================================${NC}"
    echo ""
    echo -e "${YELLOW}Check the error messages above.${NC}"
    echo -e "${YELLOW}Common issues:${NC}"
    echo -e "  - Missing dependencies (install with apt-get)"
    echo -e "  - OpenDHT not installed (required for P2P support)"
    echo -e "  - Qt5 not installed (required for GUI)"
    echo ""
    exit 1
fi
