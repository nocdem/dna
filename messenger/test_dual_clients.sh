#!/bin/bash
#
# DNA Messenger - Dual Client Testing Script
# 
# This script launches two separate DNA Messenger instances with isolated
# home directories in /tmp for testing P2P messaging between clients.
#
# Usage:
#   ./test_dual_clients.sh           # Launch both clients
#   ./test_dual_clients.sh alice     # Launch only Alice
#   ./test_dual_clients.sh bob       # Launch only Bob
#   ./test_dual_clients.sh clean     # Clean up /tmp directories
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/imgui_gui"
BINARY="$BUILD_DIR/dna_messenger_imgui"

# Temporary home directories
ALICE_HOME="/tmp/dna_alice_home"
BOB_HOME="/tmp/dna_bob_home"

# DHT ports (different for each client - DHT listens on this)
ALICE_DHT_PORT=4000
BOB_DHT_PORT=5000

# P2P ports (different for each client - TCP messaging)
ALICE_P2P_PORT=4001
BOB_P2P_PORT=4002

# DHT bootstrap nodes (same for both - they'll find each other)
DHT_BOOTSTRAP="bootstrap1.cpunk.io:4000,bootstrap2.cpunk.io:4000,bootstrap3.cpunk.io:4000"

function print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  DNA Messenger - Dual Client Test${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

function check_build() {
    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}Error: Binary not found at $BINARY${NC}"
        echo -e "${YELLOW}Please build first: cd build && make dna_messenger_imgui${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Found binary: $BINARY${NC}"
}

function setup_home() {
    local name=$1
    local home_dir=$2
    
    echo -e "${YELLOW}Setting up home directory for $name...${NC}"
    
    # Create temporary home directory
    mkdir -p "$home_dir"
    
    # Create .dna directory
    mkdir -p "$home_dir/.dna"
    
    # Create config directory
    mkdir -p "$home_dir/.config/dna_messenger"
    
    echo -e "${GREEN}✓ Home directory ready: $home_dir${NC}"
}

function launch_client() {
    local name=$1
    local home_dir=$2
    local dht_port=$3
    local p2p_port=$4
    local color=$5
    
    echo -e "${color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${color}  Launching $name's Client${NC}"
    echo -e "${color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Home: $home_dir${NC}"
    echo -e "${YELLOW}DHT Port: $dht_port${NC}"
    echo -e "${YELLOW}P2P Port: $p2p_port${NC}"
    echo -e "${YELLOW}Data: $home_dir/.dna/${NC}"
    echo ""
    
    # Setup home directory
    setup_home "$name" "$home_dir"
    
    # Set environment variables
    export HOME="$home_dir"
    export DNA_DHT_PORT="$dht_port"
    export DNA_P2P_PORT="$p2p_port"
    
    # Launch client
    echo -e "${GREEN}Starting DNA Messenger for $name...${NC}"
    "$BINARY" &
    
    local pid=$!
    echo -e "${GREEN}✓ $name's client started (PID: $pid)${NC}"
    echo -e "${YELLOW}Window title should show as '$name'${NC}"
    echo ""
    
    # Give it a moment to start
    sleep 1
}

function clean_homes() {
    echo -e "${YELLOW}Cleaning up temporary directories...${NC}"
    
    if [ -d "$ALICE_HOME" ]; then
        rm -rf "$ALICE_HOME"
        echo -e "${GREEN}✓ Removed $ALICE_HOME${NC}"
    fi
    
    if [ -d "$BOB_HOME" ]; then
        rm -rf "$BOB_HOME"
        echo -e "${GREEN}✓ Removed $BOB_HOME${NC}"
    fi
    
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

function show_help() {
    print_header
    echo ""
    echo "Usage: $0 [alice|bob|clean]"
    echo ""
    echo "Options:"
    echo "  (none)    Launch both Alice and Bob clients"
    echo "  alice     Launch only Alice's client"
    echo "  bob       Launch only Bob's client"
    echo "  clean     Clean up /tmp directories"
    echo ""
    echo "Testing workflow:"
    echo "  1. Run: ./test_dual_clients.sh"
    echo "  2. In Alice's window: Create identity 'alice'"
    echo "  3. In Bob's window: Create identity 'bob'"
    echo "  4. Add each other as contacts using usernames"
    echo "  5. Send messages between them"
    echo ""
    echo "Notes:"
    echo "  - Each client has isolated ~/.dna directory"
    echo "  - DHT ports: Alice=4000, Bob=5000"
    echo "  - P2P ports: Alice=4001, Bob=4002"
    echo "  - Both connect to same DHT bootstrap nodes"
    echo "  - Messages are encrypted end-to-end"
    echo ""
}

# Main script
print_header
echo ""

case "${1:-both}" in
    alice)
        check_build
        launch_client "Alice" "$ALICE_HOME" "$ALICE_DHT_PORT" "$ALICE_P2P_PORT" "$GREEN"
        echo -e "${GREEN}Alice's client is running. Close the window to stop.${NC}"
        wait
        ;;
    
    bob)
        check_build
        launch_client "Bob" "$BOB_HOME" "$BOB_DHT_PORT" "$BOB_P2P_PORT" "$BLUE"
        echo -e "${BLUE}Bob's client is running. Close the window to stop.${NC}"
        wait
        ;;
    
    clean)
        clean_homes
        ;;
    
    both)
        check_build
        
        # Launch Alice
        launch_client "Alice" "$ALICE_HOME" "$ALICE_DHT_PORT" "$ALICE_P2P_PORT" "$GREEN"
        
        # Launch Bob
        launch_client "Bob" "$BOB_HOME" "$BOB_DHT_PORT" "$BOB_P2P_PORT" "$BLUE"
        
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  Both clients are running!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}Next steps:${NC}"
        echo "  1. Create identity 'alice' in first window"
        echo "  2. Create identity 'bob' in second window"
        echo "  3. Add each other as contacts"
        echo "  4. Send encrypted messages!"
        echo ""
        echo -e "${YELLOW}Press Ctrl+C to stop both clients${NC}"
        echo -e "${YELLOW}Or close windows individually${NC}"
        echo ""
        
        # Wait for all background processes
        wait
        ;;
    
    help|--help|-h)
        show_help
        ;;
    
    *)
        echo -e "${RED}Error: Unknown option '$1'${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
