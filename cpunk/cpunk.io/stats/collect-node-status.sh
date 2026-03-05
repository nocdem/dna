#!/bin/bash

# CPUNK Node Status Report Collection Script
# Generates node-status-report.json with delegation statistics
# For cpunk.io automatic updates

# Configuration
JSON_FILE="/opt/cpunk/cpunk.io/stats/node-status-report.json"
TEMP_DIR="/tmp/cpunk-node-stats"
LOG_FILE="/tmp/cpunk-node-stats.log"
BACKUP_SOURCE="https://cpunk.club/stats/node-status-report.json"

# Create temp directory
mkdir -p "$TEMP_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S UTC')] $1" | tee -a "$LOG_FILE"
}

# Function to fetch data from cpunk.club as fallback
fetch_from_cpunk_club() {
    log "Fetching fresh data from cpunk.club..."
    
    local temp_file="${TEMP_DIR}/node-status-report.tmp"
    
    # Try to fetch from cpunk.club
    if curl -s -f "$BACKUP_SOURCE" -o "$temp_file"; then
        # Validate JSON
        if jq empty "$temp_file" 2>/dev/null; then
            log "Successfully fetched valid JSON from cpunk.club"
            
            # Update timestamp in the fetched data to current time
            local current_time=$(date '+%B %d, %Y at %I:%M:%S %p %z')
            
            # Update the generated_at timestamp
            jq --arg timestamp "$current_time" '.report_metadata.generated_at = $timestamp' "$temp_file" > "${temp_file}.updated"
            
            # Copy to final location
            if cp "${temp_file}.updated" "$JSON_FILE"; then
                log "Successfully updated $JSON_FILE with fresh data from cpunk.club"
                log "Updated generated_at timestamp to: $current_time"
                return 0
            else
                log "ERROR: Failed to copy updated file to $JSON_FILE"
                return 1
            fi
        else
            log "ERROR: Invalid JSON received from cpunk.club"
            return 1
        fi
    else
        log "ERROR: Failed to fetch data from cpunk.club"
        return 1
    fi
}

# Main execution
main() {
    log "Starting node status report collection..."
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        log "ERROR: curl is not installed"
        exit 1
    fi
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        log "ERROR: jq is not installed"
        exit 1
    fi
    
    # Create stats directory if it doesn't exist
    mkdir -p "$(dirname "$JSON_FILE")"
    
    # For now, we'll fetch from cpunk.club since we don't have direct node access
    # This ensures cpunk.io stays synchronized with cpunk.club data
    if fetch_from_cpunk_club; then
        log "Node status report collection completed successfully"
        
        # Set proper permissions
        chmod 644 "$JSON_FILE" 2>/dev/null || true
        
        # Clean up temp files
        rm -f "${TEMP_DIR}"/node-status-report.tmp*
        
        exit 0
    else
        log "Failed to update node status report"
        exit 1
    fi
}

# Run main function
main "$@"