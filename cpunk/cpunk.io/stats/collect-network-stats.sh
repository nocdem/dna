#!/bin/bash

# CPUNK Network Statistics Collection Script
# Collects active masternodes and block height data from Cellframe network
# Updates net-stats.json only when network is fully synced

# Configuration
NETWORK="Alvin"
JSON_FILE="/var/www/html/stats/net-stats.json"
CLI_PATH="/opt/cellframe-node/bin/cellframe-node-cli"
TEMP_DIR="/tmp/cpunk-stats"
LOG_FILE="/tmp/cpunk-stats.log"
TREASURY_ADDRESS="Rj7J7MiX2bWy8sNyZcoLqkZuNznvU4KbK6RHgqrGj9iqwKPhoVKE1xNrEMmgtVsnyTZtFhftMPAJbaswuSLp7UeBS7jiRmE5uvuUJaKA"
RPC_URL="http://rpc.cellframe.net/connect"

# Create temp directory
mkdir -p "$TEMP_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S UTC')] $1" | tee -a "$LOG_FILE" >&2
}

# Function to check if network is fully synced
check_network_sync() {
    log "Checking network sync status..."
    
    # Get network status
    local status_output
    status_output=$("$CLI_PATH" net get status -net "$NETWORK" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to get network status"
        return 1
    fi
    
    # Parse sync percentages for both chains
    local zerochain_percent
    local main_percent
    
    # Extract zerochain sync percentage
    zerochain_percent=$(echo "$status_output" | awk '
        /zerochain:/ { in_zerochain = 1 }
        in_zerochain && /percent:/ { 
            gsub(/percent:/, ""); 
            gsub(/%/, ""); 
            gsub(/^[ \t]+/, ""); 
            print $1; 
            in_zerochain = 0 
        }
    ')
    
    # Extract main chain sync percentage
    main_percent=$(echo "$status_output" | awk '
        /main:/ { in_main = 1 }
        in_main && /percent:/ { 
            gsub(/percent:/, ""); 
            gsub(/%/, ""); 
            gsub(/^[ \t]+/, ""); 
            print $1; 
            in_main = 0 
        }
    ')
    
    log "Network sync status - Zerochain: ${zerochain_percent}%, Main: ${main_percent}%"
    
    # Check if both chains are 100% synced
    if [[ "$zerochain_percent" == "100.000" ]] && [[ "$main_percent" == "100.000" ]]; then
        log "Network is fully synced (100%)"
        return 0
    else
        log "WARNING: Network not fully synced. Skipping stats update."
        return 1
    fi
}

# Function to get active masternodes count
get_active_masternodes() {
    log "Getting active masternodes count..."
    
    # Get stake list
    local stake_output
    stake_output=$("$CLI_PATH" srv_stake list keys -net "$NETWORK" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to get stake list"
        return 1
    fi
    
    # Extract total and inactive keys
    local total_keys
    local inactive_keys
    
    total_keys=$(echo "$stake_output" | grep "total_keys:" | awk '{print $2}')
    inactive_keys=$(echo "$stake_output" | grep "inactive_keys:" | awk '{print $2}')
    
    if [[ -z "$total_keys" || -z "$inactive_keys" ]]; then
        log "ERROR: Could not parse stake list output"
        return 1
    fi
    
    # Calculate active masternodes
    local active_masternodes=$((total_keys - inactive_keys))
    
    log "Masternodes - Total: $total_keys, Inactive: $inactive_keys, Active: $active_masternodes"
    
    echo "$active_masternodes"
    return 0
}

# Function to get block heights
get_block_heights() {
    log "Getting block heights..."
    
    # Get network status
    local status_output
    status_output=$("$CLI_PATH" net get status -net "$NETWORK" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to get network status for block heights"
        return 1
    fi
    
    # Extract block heights
    local zerochain_height
    local main_height
    
    # Extract zerochain current block
    zerochain_height=$(echo "$status_output" | grep -A3 "zerochain:" | grep "current:" | awk '{print $2}')
    
    # Extract main chain current block
    main_height=$(echo "$status_output" | grep -A3 "main:" | grep "current:" | awk '{print $2}')
    
    if [[ -z "$zerochain_height" || -z "$main_height" ]]; then
        log "ERROR: Could not parse block heights"
        return 1
    fi
    
    log "Block heights - Zerochain: '$zerochain_height', Main: '$main_height'"
    log "DEBUG: Active masternodes value: '$active_masternodes'"
    
    # Return as colon-separated values for easier parsing
    echo "$zerochain_height:$main_height"
    return 0
}

# Function to get treasury balances using Cellframe public RPC
get_treasury_balances() {
    log "Getting treasury wallet balances..."
    
    # Make RPC call to get treasury wallet info
    local rpc_response
    rpc_response=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{
            "method": "wallet",
            "subcommand": "info", 
            "arguments": {
                "net": "Backbone",
                "addr": "'"$TREASURY_ADDRESS"'"
            },
            "id": "treasury-check"
        }' 2>/dev/null)
    
    if [ $? -ne 0 ] || [ -z "$rpc_response" ]; then
        log "ERROR: Failed to get treasury wallet info from RPC"
        return 1
    fi
    
    # Parse CELL and CPUNK balances from response
    local cell_balance
    local cpunk_balance
    
    # Extract CELL balance
    cell_balance=$(echo "$rpc_response" | jq -r '.result[0][0].tokens[] | select(.token.ticker == "CELL") | .coins' 2>/dev/null)
    
    # Extract CPUNK balance  
    cpunk_balance=$(echo "$rpc_response" | jq -r '.result[0][0].tokens[] | select(.token.ticker == "CPUNK") | .coins' 2>/dev/null)
    
    if [[ -z "$cell_balance" || -z "$cpunk_balance" || "$cell_balance" == "null" || "$cpunk_balance" == "null" ]]; then
        log "ERROR: Could not parse treasury balances from RPC response"
        log "DEBUG: RPC response: $rpc_response"
        return 1
    fi
    
    log "Treasury balances - CELL: $cell_balance, CPUNK: $cpunk_balance"
    
    # Return as colon-separated values for easier parsing
    echo "$cell_balance:$cpunk_balance"
    return 0
}

# Function to update JSON file
update_json_file() {
    local active_masternodes="$1"
    local block_heights="$2"
    local treasury_balances="$3"
    local timestamp
    
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    
    log "Updating JSON file: $JSON_FILE"
    log "DEBUG: Input active_masternodes='$active_masternodes'"
    log "DEBUG: Input block_heights='$block_heights'"
    log "DEBUG: Input treasury_balances='$treasury_balances'"
    
    # Parse block heights
    local zerochain_height=$(echo "$block_heights" | cut -d: -f1)
    local main_height=$(echo "$block_heights" | cut -d: -f2)
    
    # Parse treasury balances
    local cell_balance=$(echo "$treasury_balances" | cut -d: -f1)
    local cpunk_balance=$(echo "$treasury_balances" | cut -d: -f2)
    
    log "DEBUG: Parsed zerochain_height='$zerochain_height'"
    log "DEBUG: Parsed main_height='$main_height'"
    log "DEBUG: Parsed cell_balance='$cell_balance'"
    log "DEBUG: Parsed cpunk_balance='$cpunk_balance'"
    
    # Create new JSON data
    local json_data
    json_data=$(jq -n \
        --arg timestamp "$timestamp" \
        --argjson network_synced true \
        --argjson active_masternodes "$active_masternodes" \
        --argjson zerochain_height "$zerochain_height" \
        --argjson main_height "$main_height" \
        --arg cell_balance "$cell_balance" \
        --arg cpunk_balance "$cpunk_balance" \
        '{
            timestamp: $timestamp,
            network_synced: $network_synced,
            active_masternodes: $active_masternodes,
            block_height: {
                zerochain: $zerochain_height,
                main: $main_height
            },
            treasury: {
                cell_balance: $cell_balance,
                cpunk_balance: $cpunk_balance
            }
        }')
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to create JSON data"
        return 1
    fi
    
    # Write to file atomically
    echo "$json_data" > "${JSON_FILE}.tmp" && mv "${JSON_FILE}.tmp" "$JSON_FILE"
    
    if [ $? -eq 0 ]; then
        log "Successfully updated $JSON_FILE"
        log "JSON content: $json_data"
        return 0
    else
        log "ERROR: Failed to write JSON file"
        return 1
    fi
}

# Main execution
main() {
    log "Starting network statistics collection..."
    
    # Check if CLI exists
    if [ ! -x "$CLI_PATH" ]; then
        log "ERROR: Cellframe CLI not found at $CLI_PATH"
        exit 1
    fi
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        log "ERROR: jq is not installed"
        exit 1
    fi
    
    # Check network sync status first
    if ! check_network_sync; then
        log "Network not synced. Exiting without updating stats."
        exit 0
    fi
    
    # Get active masternodes
    local active_masternodes
    active_masternodes=$(get_active_masternodes)
    if [ $? -ne 0 ]; then
        log "Failed to get active masternodes count"
        exit 1
    fi
    
    # Get block heights  
    local block_heights
    block_heights=$(get_block_heights "$active_masternodes")
    if [ $? -ne 0 ]; then
        log "Failed to get block heights"
        exit 1
    fi
    
    # Get treasury balances
    local treasury_balances
    treasury_balances=$(get_treasury_balances)
    if [ $? -ne 0 ]; then
        log "Failed to get treasury balances"
        exit 1
    fi
    
    # Update JSON file
    if update_json_file "$active_masternodes" "$block_heights" "$treasury_balances"; then
        log "Network statistics collection completed successfully"
    else
        log "Failed to update JSON file"
        exit 1
    fi
}

# Run main function
main "$@"