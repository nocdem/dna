#!/bin/bash
#
# DNA Messenger - Quick Installer
#
# One-line install:
#   curl -sSL https://raw.githubusercontent.com/nocdem/dna-messenger/main/install.sh | bash
#
# Or download and run:
#   wget https://raw.githubusercontent.com/nocdem/dna-messenger/main/install.sh
#   chmod +x install.sh
#   ./install.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
REPO_URL="https://github.com/nocdem/dna-messenger.git"
INSTALL_DIR="${DNA_INSTALL_DIR:-$HOME/dna-messenger}"
BUILD_TYPE="${BUILD_TYPE:-Release}"

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} DNA Messenger - Quick Installer${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "Repository: ${REPO_URL}"
echo -e "Install Directory: ${INSTALL_DIR}"
echo -e "Build Type: ${BUILD_TYPE}"
echo ""

# Detect OS
OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

echo -e "${BLUE}Detected OS:${NC} $OS"
echo ""

# Check for required tools
echo -e "${YELLOW}Checking required tools...${NC}"
MISSING_TOOLS=""

for cmd in git cmake make gcc g++ pkg-config; do
    if ! command -v $cmd &> /dev/null; then
        MISSING_TOOLS="$MISSING_TOOLS $cmd"
    fi
done

if [ ! -z "$MISSING_TOOLS" ]; then
    echo -e "${RED}✗ Missing tools:${MISSING_TOOLS}${NC}"
    echo ""
    echo -e "${YELLOW}Install with:${NC}"

    case $OS in
        ubuntu|debian)
            echo "  sudo apt-get update"
            echo "  sudo apt-get install -y git cmake build-essential pkg-config"
            ;;
        fedora|rhel|centos)
            echo "  sudo dnf install -y git cmake gcc gcc-c++ pkg-config"
            ;;
        arch|manjaro)
            echo "  sudo pacman -S git cmake base-devel pkg-config"
            ;;
        *)
            echo "  Install: git cmake gcc g++ make pkg-config"
            ;;
    esac

    exit 1
fi

echo -e "${GREEN}✓${NC} All required tools found"

# Check for dependencies
echo -e "${YELLOW}Checking build dependencies...${NC}"
MISSING_DEPS=""

# Core dependencies
for pkg in libssl-dev libcurl4-openssl-dev libjson-c-dev libsqlite3-dev; do
    if ! dpkg -l 2>/dev/null | grep -q "^ii  $pkg" && ! rpm -q ${pkg//-dev/} &>/dev/null; then
        MISSING_DEPS="$MISSING_DEPS $pkg"
    fi
done

# GUI dependencies (optional but recommended)
for pkg in libglfw3-dev libglew-dev libfreetype6-dev libgl1-mesa-dev; do
    if ! dpkg -l 2>/dev/null | grep -q "^ii  $pkg" && ! rpm -q ${pkg//-dev/} &>/dev/null; then
        MISSING_DEPS="$MISSING_DEPS $pkg"
    fi
done

if [ ! -z "$MISSING_DEPS" ]; then
    echo -e "${RED}✗ Missing dependencies:${MISSING_DEPS}${NC}"
    echo ""
    echo -e "${YELLOW}Install with:${NC}"

    case $OS in
        ubuntu|debian)
            echo "  sudo apt-get update"
            echo "  sudo apt-get install -y libssl-dev libcurl4-openssl-dev libjson-c-dev libsqlite3-dev \\"
            echo "    libglfw3-dev libglew-dev libfreetype6-dev libgl1-mesa-dev zenity"
            ;;
        fedora|rhel|centos)
            echo "  sudo dnf install -y openssl-devel libcurl-devel json-c-devel sqlite-devel \\"
            echo "    glfw-devel glew-devel freetype-devel mesa-libGL-devel zenity"
            ;;
        arch|manjaro)
            echo "  sudo pacman -S openssl curl json-c sqlite glfw-x11 glew freetype2 mesa zenity"
            ;;
        *)
            echo "  Install SSL, curl, json-c, sqlite, GLFW, GLEW, freetype, OpenGL development packages"
            ;;
    esac

    echo ""
    echo -e "${YELLOW}Note: GUI dependencies are optional. You can still build the CLI tools.${NC}"
    echo -e "${YELLOW}Continue anyway? [y/N]${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${GREEN}✓${NC} Dependencies check complete"
echo ""

# Clone or update repository
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Directory exists. Updating to latest version...${NC}"
    cd "$INSTALL_DIR"

    # Stash any local changes
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        echo -e "${YELLOW}Stashing local changes...${NC}"
        git stash save "Auto-stash by install.sh $(date +%Y-%m-%d_%H:%M:%S)"
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
GIT_DATE=$(git log -1 --format=%cd --date=short)
GIT_COUNT=$(git rev-list --count HEAD)
FULL_VERSION="0.1.${GIT_COUNT}-${GIT_SHA}"

echo ""
echo -e "${BLUE}Version:${NC} ${GREEN}${FULL_VERSION}${NC}"
echo -e "${BLUE}Commit:${NC} ${GIT_SHA} (${GIT_DATE})"
echo ""

# Build
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE} Building DNA Messenger${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Check if build-cross-compile.sh exists
if [ ! -f "build-cross-compile.sh" ]; then
    echo -e "${RED}✗ build-cross-compile.sh not found${NC}"
    echo -e "${YELLOW}Falling back to manual CMake build...${NC}"

    # Fallback to manual build
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
    make -j$(nproc)

    BINARY_PATH="$INSTALL_DIR/build/cli/dna-messenger-cli"
else
    # Use new build system
    chmod +x build-cross-compile.sh

    echo -e "${YELLOW}Building for Linux x86_64...${NC}"
    ./build-cross-compile.sh linux-x64

    BINARY_PATH="$INSTALL_DIR/dist/linux-x64/dna-messenger"
fi

# Check if build succeeded
if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED} ✗ Build Failed${NC}"
    echo -e "${RED}=========================================${NC}"
    echo ""
    echo -e "${YELLOW}Binary not found at: ${BINARY_PATH}${NC}"
    echo -e "${YELLOW}Check the error messages above.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN} ✓ Build Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""

# Show binary info
BINARY_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
echo -e "${BLUE}Binary:${NC} ${BINARY_PATH}"
echo -e "${BLUE}Size:${NC} ${BINARY_SIZE}"
echo -e "${BLUE}Version:${NC} ${FULL_VERSION}"
echo ""

# Create symlinks in ~/bin (if it exists)
if [ -d "$HOME/bin" ]; then
    echo -e "${YELLOW}Creating shortcuts in ~/bin...${NC}"

    ln -sf "$BINARY_PATH" "$HOME/bin/dna-messenger" 2>/dev/null && \
        echo -e "  ${GREEN}✓${NC} Created: ~/bin/dna-messenger"

    # Add ~/bin to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
        echo ""
        echo -e "${YELLOW}Note: Add ~/bin to your PATH for easier access:${NC}"
        echo -e "  echo 'export PATH=\"\$HOME/bin:\$PATH\"' >> ~/.bashrc"
        echo -e "  source ~/.bashrc"
    fi
    echo ""
fi

# Create desktop entry (optional)
if [ -d "$HOME/.local/share/applications" ]; then
    echo -e "${YELLOW}Create desktop shortcut? [y/N]${NC}"
    read -r create_desktop

    if [[ "$create_desktop" =~ ^[Yy]$ ]]; then
        DESKTOP_FILE="$HOME/.local/share/applications/dna-messenger.desktop"

        cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=DNA Messenger
Comment=Post-Quantum E2E Encrypted Messenger
Exec=$BINARY_PATH
Icon=utilities-terminal
Terminal=false
Categories=Network;InstantMessaging;
EOF

        chmod +x "$DESKTOP_FILE"
        echo -e "${GREEN}✓${NC} Desktop entry created"
        echo ""
    fi
fi

# Final instructions
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN} Installation Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo ""

if [ -d "$HOME/bin" ] && [[ ":$PATH:" == *":$HOME/bin:"* ]]; then
    echo -e "  ${GREEN}dna-messenger${NC}                # Run from anywhere"
else
    echo -e "  ${GREEN}$BINARY_PATH${NC}"
fi

echo ""
echo -e "${BLUE}Update Later:${NC}"
echo -e "  cd $INSTALL_DIR"
echo -e "  git pull origin main"
echo -e "  ./build-cross-compile.sh linux-x64"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo -e "  https://github.com/nocdem/dna-messenger"
echo ""
echo -e "${BLUE}Support:${NC}"
echo -e "  https://cpunk.io"
echo -e "  https://t.me/chippunk_official"
echo ""
