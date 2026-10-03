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
# "Three-process node").
#
# An update keeps the layout the host is ENABLED for (systemctl
# is-enabled, never is-active — a layout that is down at the moment is
# still the host's layout): nodus.service enabled → the combined server;
# nodus-core enabled → the split units that are enabled (core is in every
# layout, decision item 12: core+storage, core+witness, all three). Both
# enabled, neither enabled, or a split unit enabled without nodus-core →
# the script refuses and changes nothing; it never guesses, and never
# starts nodus.service on a host whose split units are enabled. The
# layout's units are stopped, every binary is installed atomically
# (install to <dest>.new, then mv over <dest> — a running binary is never
# written in place), the unit files are re-copied, then the units start.
# A --debug build still builds and installs only nodus-server-debug, and
# refuses on a host where any split unit is enabled or active.
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
            echo "  - Rebuilds the binaries"
            echo "  - Finds the ENABLED layout (nodus.service, or nodus-core + the"
            echo "    enabled split units); refuses if both, neither, or a split"
            echo "    unit without nodus-core is enabled"
            echo "  - Stops that layout, installs the binaries atomically, re-copies"
            echo "    the split units, starts that layout again"
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

# install_one SRC DEST — install SRC as DEST atomically: a full copy to
# DEST.new, then a rename over DEST. A process still running the old DEST
# keeps its own (unlinked) inode; nothing ever writes into a running
# binary, and DEST is at every moment either the old file or the new one.
install_one() {
    sudo install -m 0755 "$1" "$2.new"
    sudo mv -f "$2.new" "$2"
}

# Install the binaries
install_binary() {
    if [ $DEBUG_BUILD -eq 1 ]; then
        echo -e "${YELLOW}Installing nodus-server-debug to ${INSTALL_DIR}/${NC}"
        install_one "$NODUS_DIR/build/nodus-server" "${INSTALL_DIR}/nodus-server-debug"
        SIZE=$(ls -lh "${INSTALL_DIR}/nodus-server-debug" | awk '{print $5}')
        echo -e "${GREEN}Installed: ${INSTALL_DIR}/nodus-server-debug ($SIZE)${NC}"
        echo ""
        return
    fi
    for b in $RELEASE_BINARIES; do
        echo -e "${YELLOW}Installing ${b} to ${INSTALL_DIR}/${NC}"
        install_one "$NODUS_DIR/build/$b" "${INSTALL_DIR}/$b"
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

    # Install config. deploy/nodus.conf.example is gitignored, so a fresh
    # clone has none: say so and go on, rather than abort under set -e.
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$SCRIPT_DIR/nodus.conf.example" ]; then
            echo "Installing config to ${CONFIG_FILE}..."
            sudo cp "$SCRIPT_DIR/nodus.conf.example" "$CONFIG_FILE"
            echo -e "${YELLOW}NOTE: Edit ${CONFIG_FILE} to set seed_nodes for this server${NC}"
        else
            echo -e "${RED}No ${CONFIG_FILE}, and no ${SCRIPT_DIR}/nodus.conf.example to copy"
            echo -e "(that file is gitignored — a fresh clone does not have it)."
            echo -e "Config NOT installed: ${SERVICE_NAME} cannot start until you write"
            echo -e "${CONFIG_FILE}; then: sudo systemctl restart ${SERVICE_NAME}${NC}"
        fi
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

# unit_enabled UNIT — 0 when `systemctl is-enabled UNIT` prints exactly
# "enabled". The exit code alone is not used: it is also 0 for static,
# indirect, alias and generated units.
unit_enabled() {
    [ "$(systemctl is-enabled "$1" 2>/dev/null || true)" = "enabled" ]
}

# split_units_in_use — print the split units that are enabled or active
# (empty when none is).
split_units_in_use() {
    local u out=""
    for u in $SPLIT_UNITS; do
        if unit_enabled "$u" || systemctl is-active --quiet "$u" 2>/dev/null; then
            out="$out $u"
        fi
    done
    echo "${out# }"
}

# refuse_on_split_host WHAT — exit 1 (nothing installed or started) when a
# split unit is enabled or active: WHAT (a --debug build's nodus-debug, or
# a first install's nodus.service) would run a second server on the same
# /var/lib/nodus beside it.
refuse_on_split_host() {
    local used
    used=$(split_units_in_use)
    [ -z "$used" ] && return 0
    echo -e "${RED}Refusing: split unit(s) enabled or active on this host: ${used}.${NC}"
    echo -e "${RED}$1 would run a second server on ${DATA_DIR} beside them. Nothing was installed.${NC}"
    echo "Switch the host back first (docs/DEPLOY_RUNBOOK.md \"Three-process node\", Rollback)."
    exit 1
}

# detect_layout — the layout this host is ENABLED for (split S6). Sets
# LAYOUT_UNITS to the units to stop / start: "nodus" when nodus.service is
# enabled; the enabled split units when nodus-core is enabled (decision
# item 12: core in every layout; storage and witness each optional).
# Refuses (exit 1, nothing changed) when the answer is not unique: both
# layouts enabled, neither enabled, or storage / witness enabled without
# nodus-core. is-enabled, never is-active: a layout that is down at this
# moment is still the host's layout, and an is-active check would restart
# nodus.service on a split host whose units happened to be stopped.
detect_layout() {
    local u en=""
    for u in $SPLIT_UNITS; do
        unit_enabled "$u" && en="$en $u"
    done
    en="${en# }"
    if unit_enabled nodus; then
        if [ -n "$en" ]; then
            echo -e "${RED}Refusing: nodus.service AND split unit(s) (${en}) are enabled — two layouts on one data directory.${NC}"
            echo "Disable one layout (docs/DEPLOY_RUNBOOK.md \"Three-process node\"), then run this again. Nothing was installed."
            exit 1
        fi
        LAYOUT_UNITS="nodus"
    elif [ -n "$en" ]; then
        if ! unit_enabled nodus-core; then
            echo -e "${RED}Refusing: split unit(s) ${en} enabled without nodus-core — core runs in every layout (decision item 12).${NC}"
            echo "Enable nodus-core or disable ${en}, then run this again. Nothing was installed."
            exit 1
        fi
        LAYOUT_UNITS="$en"
    else
        echo -e "${RED}Refusing: neither nodus.service nor nodus-core.service is enabled — no layout to update.${NC}"
        echo "Enable the layout this host should run, then run this again. Nothing was installed."
        exit 1
    fi
}

# Update existing: stop the layout's units (LAYOUT_UNITS, decided before
# the pull), install, start them again.
update_install() {
    # systemd orders the split units' STARTS by After= (core first); this
    # script claims no restart order on a live validator beyond that — that
    # order is an OPEN operator item (docs/DEPLOY_RUNBOOK.md
    # "Three-process node").
    echo -e "${YELLOW}Stopping ${LAYOUT_UNITS}...${NC}"
    # shellcheck disable=SC2086
    sudo systemctl stop $LAYOUT_UNITS
    install_binary
    install_split_units
    echo -e "${YELLOW}Starting ${LAYOUT_UNITS}...${NC}"
    # shellcheck disable=SC2086
    sudo systemctl start $LAYOUT_UNITS
    sleep 2
    echo -e "${GREEN}Service restarted${NC}"
    echo ""
}

# Show status
show_status() {
    echo -e "${YELLOW}Service status:${NC}"
    for u in ${LAYOUT_UNITS:-$SERVICE_NAME}; do
        sudo systemctl status "$u" --no-pager -l 2>/dev/null | head -15 || true
    done
}

# Main. Every refusal comes before the pull, so a refused host has
# nothing changed, not even its checkout.
check_deps
FIRST_INSTALL=0
[ -f /etc/systemd/system/${SERVICE_NAME}.service ] || FIRST_INSTALL=1
if [ $DEBUG_BUILD -eq 1 ]; then
    # --debug (F4): refused beside any split unit rather than given
    # Conflicts= — the nodus-debug unit is written only on its first
    # install, so a Conflicts= line would never reach an existing one.
    refuse_on_split_host "nodus-debug (--debug)"
    LAYOUT_UNITS="$SERVICE_NAME"
elif [ $FIRST_INSTALL -eq 1 ]; then
    refuse_on_split_host "a first install's nodus.service"
else
    detect_layout
fi
pull_latest
build_nodus

if [ $FIRST_INSTALL -eq 1 ]; then
    install_binary
    install_split_units
    first_time_install
else
    update_install
fi

show_status
