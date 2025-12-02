#!/bin/bash
# DNA Nodus Build Script
# Builds dna-nodus and handles first-time installation

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
SERVICE_FILE="$PROJECT_ROOT/vendor/opendht-pq/tools/systemd/dna-nodus.service"
CONFIG_EXAMPLE="$PROJECT_ROOT/vendor/opendht-pq/tools/dna-nodus.conf.example"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== DNA Nodus Build Script ===${NC}"
echo ""

# Check for required tools
check_dependencies() {
    local missing=()

    command -v cmake >/dev/null 2>&1 || missing+=("cmake")
    command -v make >/dev/null 2>&1 || missing+=("make")
    command -v git >/dev/null 2>&1 || missing+=("git")

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
}

# Pull latest code
pull_latest() {
    echo -e "${YELLOW}Pulling latest code...${NC}"
    cd "$PROJECT_ROOT"

    if git remote | grep -q "^gitlab$"; then
        git pull --no-rebase gitlab main
    else
        git pull --no-rebase origin main
    fi

    COMMIT=$(git log --oneline -1)
    echo -e "${GREEN}Current commit: $COMMIT${NC}"
    echo ""
}

# Build dna-nodus
build_nodus() {
    echo -e "${YELLOW}Building dna-nodus...${NC}"

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure headless build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF "$PROJECT_ROOT"

    # Build dependencies and dna-nodus
    make -j$(nproc) dht_lib
    make -j$(nproc) dna-nodus

    if [ ! -f "$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus" ]; then
        echo -e "${RED}Error: Failed to build dna-nodus${NC}"
        exit 1
    fi

    echo -e "${GREEN}Build successful${NC}"
    echo ""
}

# Install binary
install_binary() {
    echo -e "${YELLOW}Installing dna-nodus to /usr/local/bin/...${NC}"

    sudo cp "$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus" /usr/local/bin/dna-nodus
    sudo chmod +x /usr/local/bin/dna-nodus

    SIZE=$(ls -lh /usr/local/bin/dna-nodus | awk '{print $5}')
    echo -e "${GREEN}Installed /usr/local/bin/dna-nodus ($SIZE)${NC}"
    echo ""
}

# First-time installation
first_time_install() {
    echo -e "${YELLOW}First-time installation detected...${NC}"

    # Create persistence directory
    if [ ! -d /var/lib/dna-dht ]; then
        echo "Creating /var/lib/dna-dht..."
        sudo mkdir -p /var/lib/dna-dht
    fi

    # Copy config file
    if [ ! -f /etc/dna-nodus.conf ]; then
        echo "Copying example config to /etc/dna-nodus.conf..."
        sudo cp "$CONFIG_EXAMPLE" /etc/dna-nodus.conf
        echo -e "${YELLOW}NOTE: Edit /etc/dna-nodus.conf to set public_ip for this server${NC}"
    fi

    # Copy systemd service
    echo "Installing systemd service..."
    sudo cp "$SERVICE_FILE" /etc/systemd/system/dna-nodus.service
    sudo systemctl daemon-reload

    # Enable service
    echo "Enabling dna-nodus service..."
    sudo systemctl enable dna-nodus

    # Start service
    echo "Starting dna-nodus service..."
    sudo systemctl start dna-nodus

    echo -e "${GREEN}First-time installation complete${NC}"
    echo ""
}

# Update existing installation
update_install() {
    echo -e "${YELLOW}Updating existing installation...${NC}"

    # Update systemd service file if changed
    sudo cp "$SERVICE_FILE" /etc/systemd/system/dna-nodus.service
    sudo systemctl daemon-reload

    # Restart service
    echo "Restarting dna-nodus service..."
    sudo systemctl restart dna-nodus
    sleep 2

    echo -e "${GREEN}Service restarted${NC}"
    echo ""
}

# Show status
show_status() {
    echo -e "${YELLOW}Service status:${NC}"
    sudo systemctl status dna-nodus --no-pager -l | head -15
}

# Main
main() {
    check_dependencies
    pull_latest
    build_nodus
    install_binary

    # Check if first-time install or update
    if [ ! -f /etc/systemd/system/dna-nodus.service ]; then
        first_time_install
    else
        update_install
    fi

    show_status
}

# Show help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Builds and installs dna-nodus. Handles first-time setup automatically."
    echo ""
    echo "First-time install:"
    echo "  - Creates /var/lib/dna-dht"
    echo "  - Copies config to /etc/dna-nodus.conf"
    echo "  - Installs systemd service"
    echo "  - Enables and starts service"
    echo ""
    echo "Update:"
    echo "  - Pulls latest code"
    echo "  - Rebuilds binary"
    echo "  - Restarts service"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    exit 0
fi

main "$@"
