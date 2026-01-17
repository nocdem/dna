#!/bin/bash
# DNA Nodus Build Script
# Builds dna-nodus and installs to /opt/dna-nodus/

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_EXAMPLE="$PROJECT_ROOT/vendor/opendht-pq/tools/dna-nodus.conf.example"
INSTALL_DIR="/opt/dna-nodus"

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

# Set binary name and service name based on build type
if [ $DEBUG_BUILD -eq 1 ]; then
    BINARY_NAME="dna-nodus-debug"
    SERVICE_NAME="dna-nodus-debug"
else
    BINARY_NAME="dna-nodus"
    SERVICE_NAME="dna-nodus"
fi

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

# Install binary to /opt/dna-nodus/
install_binary() {
    echo -e "${YELLOW}Installing to ${INSTALL_DIR}/${NC}"

    # Create install directory
    sudo mkdir -p "${INSTALL_DIR}/bin"

    # Copy binary
    sudo cp "$BUILD_DIR/vendor/opendht-pq/tools/dna-nodus" "${INSTALL_DIR}/bin/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/bin/${BINARY_NAME}"

    SIZE=$(ls -lh "${INSTALL_DIR}/bin/${BINARY_NAME}" | awk '{print $5}')
    echo -e "${GREEN}Installed: ${INSTALL_DIR}/bin/${BINARY_NAME} ($SIZE)${NC}"
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
ExecStart=${INSTALL_DIR}/bin/${BINARY_NAME}
Restart=on-failure
RestartSec=5
Environment="ASAN_OPTIONS=detect_leaks=1:log_path=/var/log/dna-nodus-asan"

[Install]
WantedBy=multi-user.target
EOF
    else
        # Create release service
        sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=DNA Nodus - Post-Quantum DHT Bootstrap Server
Documentation=https://gitlab.cpunk.io/cpunk/dna-messenger
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/bin/${BINARY_NAME}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/dna-dht
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dna-nodus
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
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

    # Restart service (binary already updated by install_binary)
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
    install_binary

    # Check if first-time install or update
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
    echo "Builds dna-nodus and installs to ${INSTALL_DIR}/"
    echo ""
    echo "First-time install:"
    echo "  - Creates /var/lib/dna-dht"
    echo "  - Copies config to /etc/dna-nodus.conf"
    echo "  - Installs binary to ${INSTALL_DIR}/bin/"
    echo "  - Installs systemd service"
    echo "  - Enables and starts service"
    echo ""
    echo "Update:"
    echo "  - Pulls latest code"
    echo "  - Rebuilds and reinstalls binary"
    echo "  - Restarts service"
    echo ""
    echo "Options:"
    echo "  --debug       Build with AddressSanitizer (installs as dna-nodus-debug)"
    echo "                Creates separate dna-nodus-debug systemd service"
    echo "  -h, --help    Show this help message"
    exit 0
fi

main "$@"
