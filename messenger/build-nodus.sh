#!/bin/bash
# DNA Nodus Build Script
# Builds dna-nodus and handles first-time installation

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$PROJECT_ROOT/vendor/opendht-pq/tools/systemd/dna-nodus.service"
CONFIG_EXAMPLE="$PROJECT_ROOT/vendor/opendht-pq/tools/dna-nodus.conf.example"

# Parse arguments
DEBUG_BUILD=0
BUILD_TYPE="Release"
BUILD_DIR="$PROJECT_ROOT/build"

for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_BUILD=1
            BUILD_TYPE="Debug"
            BUILD_DIR="$PROJECT_ROOT/build-debug"
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ $DEBUG_BUILD -eq 1 ]; then
    echo -e "${GREEN}=== DNA Nodus Build Script (Debug+ASAN) ===${NC}"
else
    echo -e "${GREEN}=== DNA Nodus Build Script ===${NC}"
fi
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
    echo -e "${YELLOW}Building dna-nodus (${BUILD_TYPE})...${NC}"

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure headless build
    if [ $DEBUG_BUILD -eq 1 ]; then
        echo -e "${YELLOW}Debug build with AddressSanitizer${NC}"
        cmake -DCMAKE_BUILD_TYPE=Debug \
              -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
              -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
              -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
              -DBUILD_GUI=OFF "$PROJECT_ROOT"
    else
        cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF "$PROJECT_ROOT"
    fi

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

# Verify binary exists
verify_binary() {
    if [ ! -f "$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus" ]; then
        echo -e "${RED}Error: Binary not found at $BUILD_DIR/vendor/opendht-pq/tools/dna-nodus${NC}"
        exit 1
    fi

    SIZE=$(ls -lh "$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus" | awk '{print $5}')
    echo -e "${GREEN}Binary ready: $BUILD_DIR/vendor/opendht-pq/tools/dna-nodus ($SIZE)${NC}"
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

    # Install systemd service
    echo "Installing systemd service (${SERVICE_NAME})..."
    if [ $DEBUG_BUILD -eq 1 ]; then
        # Create debug service with ASAN environment
        sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=DNA Nodus Bootstrap Server (Debug+ASAN)
After=network.target

[Service]
Type=simple
ExecStart=$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus
Restart=on-failure
RestartSec=5
Environment="ASAN_OPTIONS=detect_leaks=1:log_path=/var/log/dna-nodus-asan"

[Install]
WantedBy=multi-user.target
EOF
    else
        sudo cp "$SERVICE_FILE" /etc/systemd/system/${SERVICE_NAME}.service
    fi
    sudo systemctl daemon-reload

    # Enable service
    echo "Enabling ${SERVICE_NAME} service..."
    sudo systemctl enable ${SERVICE_NAME}

    # Start service
    echo "Starting ${SERVICE_NAME} service..."
    sudo systemctl start ${SERVICE_NAME}

    echo -e "${GREEN}First-time installation complete${NC}"
    echo ""
}

# Update existing installation
update_install() {
    echo -e "${YELLOW}Updating existing installation...${NC}"

    # Update systemd service file if changed
    if [ $DEBUG_BUILD -eq 1 ]; then
        # Recreate debug service with updated paths
        sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=DNA Nodus Bootstrap Server (Debug+ASAN)
After=network.target

[Service]
Type=simple
ExecStart=$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus
Restart=on-failure
RestartSec=5
Environment="ASAN_OPTIONS=detect_leaks=1:log_path=/var/log/dna-nodus-asan"

[Install]
WantedBy=multi-user.target
EOF
    else
        sudo cp "$SERVICE_FILE" /etc/systemd/system/${SERVICE_NAME}.service
    fi
    sudo systemctl daemon-reload

    # Restart service
    echo "Restarting ${SERVICE_NAME} service..."
    sudo systemctl restart ${SERVICE_NAME}
    sleep 2

    echo -e "${GREEN}Service restarted${NC}"
    echo ""
}

# Show status
show_status() {
    echo -e "${YELLOW}Service status:${NC}"
    sudo systemctl status ${SERVICE_NAME} --no-pager -l | head -15
}

# Main
main() {
    check_dependencies
    pull_latest
    build_nodus
    verify_binary

    # Check if first-time install or update
    if [ $DEBUG_BUILD -eq 1 ]; then
        SERVICE_NAME="dna-nodus-debug"
    else
        SERVICE_NAME="dna-nodus"
    fi

    if [ ! -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
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
    echo "Builds dna-nodus and manages systemd service."
    echo "Binary runs directly from build directory (no copy needed)."
    echo ""
    echo "First-time install:"
    echo "  - Creates /var/lib/dna-dht"
    echo "  - Copies config to /etc/dna-nodus.conf"
    echo "  - Installs systemd service"
    echo "  - Enables and starts service"
    echo ""
    echo "Update:"
    echo "  - Pulls latest code"
    echo "  - Rebuilds binary in place"
    echo "  - Restarts service"
    echo ""
    echo "Options:"
    echo "  --debug       Build with AddressSanitizer (debug build in build-debug/)"
    echo "                Creates separate dna-nodus-debug systemd service"
    echo "  -h, --help    Show this help message"
    exit 0
fi

main "$@"
