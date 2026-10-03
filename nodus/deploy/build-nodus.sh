#!/bin/bash
# Nodus Build & Deploy Script
#
# Builds the Nodus binaries and installs them.
#
# Split S6 (decision docs/plans/decisions/2026-10-01-nodus-component-split.md
# item 8: the combined nodus-server stays): a Release build installs
# nodus-server, nodus-core, nodus-storage, nodus-witness and nodus-cli, and
# copies the three split units (nodus-core / nodus-storage / nodus-witness
# .service) beside nodus.service WITHOUT enabling them. A first install
# starts the combined nodus.service, as before. Switching a host to the
# three-process layout is an operator step (docs/DEPLOY_RUNBOOK.md
# "Three-process node"). An update restarts whichever layout is running.
# A --debug build still builds and installs only nodus-server-debug.
#
# Usage:
#   ./build-nodus.sh           # Build + install + restart service
#   ./build-nodus.sh --debug   # Build with AddressSanitizer
#   ./build-nodus.sh --help    # Show help

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MONOREPO_ROOT="$(cd "$NODUS_DIR/.." && pwd)"

INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/nodus"
CONFIG_FILE="/etc/nodus.conf"
SERVICE_NAME="nodus"
# Release binaries (split S6). The combined nodus-server is the default
# service; the three split binaries back the split units.
RELEASE_BINARIES="nodus-server nodus-core nodus-storage nodus-witness nodus-cli"
SPLIT_UNITS="nodus-core nodus-storage nodus-witness"

# Parse arguments
DEBUG_BUILD=0
BUILD_TYPE="Release"

for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_BUILD=1
            BUILD_TYPE="Debug"
            SERVICE_NAME="nodus-debug"
            ;;
        --help|-h)
            echo "Nodus Build & Deploy Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug     Build with AddressSanitizer (separate service)"
            echo "  --help      Show this help"
            echo ""
            echo "First-time install:"
            echo "  - Creates ${DATA_DIR}/{data,identity}"
            echo "  - Copies config to ${CONFIG_FILE}"
            echo "  - Installs ${RELEASE_BINARIES} to ${INSTALL_DIR}/"
            echo "  - Installs and starts the combined nodus.service"
            echo "  - Copies the split units (${SPLIT_UNITS}) — NOT enabled"
            echo ""
            echo "Update:"
            echo "  - Pulls latest code"
            echo "  - Rebuilds and reinstalls the binaries"
            echo "  - Restarts the running layout (combined, or the three split units)"
            exit 0
            ;;
    esac
done

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Nodus Build Script (${BUILD_TYPE}) ===${NC}"
echo ""

# Check dependencies
check_deps() {
    local missing=()
    command -v cmake >/dev/null 2>&1 || missing+=("cmake")
    command -v make  >/dev/null 2>&1 || missing+=("make")
    command -v git   >/dev/null 2>&1 || missing+=("git")

    # Check dev libraries
    [ -f /usr/include/openssl/evp.h ] || missing+=("libssl-dev")
    [ -f /usr/include/sqlite3.h ]     || missing+=("libsqlite3-dev")

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
        echo "Install with: sudo apt install build-essential cmake git libssl-dev libsqlite3-dev libjson-c-dev"
        exit 1
    fi
}

# Pull latest code
pull_latest() {
    echo -e "${YELLOW}Pulling latest code...${NC}"
    cd "$MONOREPO_ROOT"
    git pull --no-rebase origin main 2>/dev/null || true
    COMMIT=$(git log --oneline -1)
    echo -e "${GREEN}Commit: $COMMIT${NC}"
    echo ""
}

# Build the binaries
build_nodus() {
    echo -e "${YELLOW}Building nodus (${BUILD_TYPE})...${NC}"

    BUILD_DIR="$NODUS_DIR/build"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    if [ $DEBUG_BUILD -eq 1 ]; then
        cmake -DCMAKE_BUILD_TYPE=Debug \
              -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
              -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
              "$NODUS_DIR"
    else
        cmake -DCMAKE_BUILD_TYPE=Release "$NODUS_DIR"
    fi

    if [ $DEBUG_BUILD -eq 1 ]; then
        TARGETS="nodus-server"
    else
        TARGETS="$RELEASE_BINARIES"
    fi
    # shellcheck disable=SC2086
    make -j$(nproc) $TARGETS

    for t in $TARGETS; do
        if [ ! -f "$BUILD_DIR/$t" ]; then
            echo -e "${RED}Build failed: $t not found${NC}"
            exit 1
        fi
    done

    echo -e "${GREEN}Build successful${NC}"
    echo ""
}

# Install the binaries
install_binary() {
    if [ $DEBUG_BUILD -eq 1 ]; then
        echo -e "${YELLOW}Installing nodus-server-debug to ${INSTALL_DIR}/${NC}"
        sudo cp "$NODUS_DIR/build/nodus-server" "${INSTALL_DIR}/nodus-server-debug"
        sudo chmod +x "${INSTALL_DIR}/nodus-server-debug"
        SIZE=$(ls -lh "${INSTALL_DIR}/nodus-server-debug" | awk '{print $5}')
        echo -e "${GREEN}Installed: ${INSTALL_DIR}/nodus-server-debug ($SIZE)${NC}"
        echo ""
        return
    fi
    for b in $RELEASE_BINARIES; do
        echo -e "${YELLOW}Installing ${b} to ${INSTALL_DIR}/${NC}"
        sudo cp "$NODUS_DIR/build/$b" "${INSTALL_DIR}/$b"
        sudo chmod +x "${INSTALL_DIR}/$b"
        SIZE=$(ls -lh "${INSTALL_DIR}/$b" | awk '{print $5}')
        echo -e "${GREEN}Installed: ${INSTALL_DIR}/$b ($SIZE)${NC}"
    done
    echo ""
}

# Split S6: copy the three split units beside nodus.service. Not enabled,
# not started — the combined nodus.service stays the default (decision
# item 8); switching a host is an operator step. Re-copied on every run so
# an update carries unit changes too.
install_split_units() {
    [ $DEBUG_BUILD -eq 1 ] && return
    for u in $SPLIT_UNITS; do
        sudo cp "$SCRIPT_DIR/$u.service" "/etc/systemd/system/$u.service"
    done
    sudo systemctl daemon-reload
    echo -e "${GREEN}Split units installed (not enabled): ${SPLIT_UNITS}${NC}"
    echo ""
}

# First-time setup
first_time_install() {
    echo -e "${YELLOW}First-time installation...${NC}"

    # Create data directories
    sudo mkdir -p "${DATA_DIR}/data"
    sudo mkdir -p "${DATA_DIR}/identity"

    # Generate server identity if none exists
    if [ ! -f "${DATA_DIR}/identity/identity.dsa" ]; then
        echo -e "${YELLOW}Generating server identity...${NC}"
        # Identity will be auto-generated by nodus-server on first start
        echo "(Identity will be generated on first server start)"
    fi

    # Install config
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Installing config to ${CONFIG_FILE}..."
        sudo cp "$SCRIPT_DIR/nodus.conf.example" "$CONFIG_FILE"
        echo -e "${YELLOW}NOTE: Edit ${CONFIG_FILE} to set seed_nodes for this server${NC}"
    fi

    # Install systemd service
    echo "Installing systemd service (${SERVICE_NAME})..."
    if [ $DEBUG_BUILD -eq 1 ]; then
        sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=Nodus - Post-Quantum DHT Server (Debug+ASAN)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/nodus-server-debug -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5
Environment="ASAN_OPTIONS=detect_leaks=1:log_path=/var/log/nodus-asan"
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
    else
        sudo cp "$SCRIPT_DIR/nodus.service" /etc/systemd/system/${SERVICE_NAME}.service
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}
    sudo systemctl start ${SERVICE_NAME}

    echo -e "${GREEN}Installation complete${NC}"
    echo ""
}

# Is this host running the three-process layout? (split S6: nodus-core
# active; the units conflict with nodus.service, so at most one layout is.)
split_layout_active() {
    [ $DEBUG_BUILD -eq 0 ] && systemctl is-active --quiet nodus-core 2>/dev/null
}

# Update existing
update_install() {
    if split_layout_active; then
        # The three units together. systemd orders their STARTS by After=
        # (core first); this script claims no restart order on a live
        # validator beyond that — that order is an OPEN operator item
        # (docs/DEPLOY_RUNBOOK.md "Three-process node").
        echo -e "${YELLOW}Restarting ${SPLIT_UNITS}...${NC}"
        # shellcheck disable=SC2086
        sudo systemctl restart $SPLIT_UNITS
    else
        echo -e "${YELLOW}Restarting ${SERVICE_NAME}...${NC}"
        sudo systemctl restart ${SERVICE_NAME}
    fi
    sleep 2
    echo -e "${GREEN}Service restarted${NC}"
    echo ""
}

# Show status
show_status() {
    echo -e "${YELLOW}Service status:${NC}"
    if split_layout_active; then
        for u in $SPLIT_UNITS; do
            sudo systemctl status "$u" --no-pager -l 2>/dev/null | head -15 || true
        done
    else
        sudo systemctl status ${SERVICE_NAME} --no-pager -l 2>/dev/null | head -15 || true
    fi
}

# Main
check_deps
pull_latest
build_nodus
install_binary
install_split_units

if [ ! -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
    first_time_install
else
    update_install
fi

show_status
