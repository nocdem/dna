#!/bin/bash
# Sync delegation stats data from cpunk.club to cpunk.io
# This ensures both sites show identical data

STATS_DIR="/opt/cpunk/cpunk.io/stats"
SOURCE_URL="https://cpunk.club/stats/node-status-report.json"
DEST_FILE="$STATS_DIR/node-status-report.json"

# Create stats directory if it doesn't exist
mkdir -p "$STATS_DIR"

# Download latest data with timestamp
echo "$(date): Syncing stats data from cpunk.club..."

if wget -q -O "$DEST_FILE.tmp" "$SOURCE_URL"; then
    # Verify the downloaded file is valid JSON
    if jq empty "$DEST_FILE.tmp" 2>/dev/null; then
        mv "$DEST_FILE.tmp" "$DEST_FILE"
        echo "$(date): Stats data synced successfully"
        # Set proper permissions
        chown bios:cpunk-team "$DEST_FILE"
        chmod 644 "$DEST_FILE"
    else
        echo "$(date): ERROR - Downloaded file is not valid JSON"
        rm -f "$DEST_FILE.tmp"
        exit 1
    fi
else
    echo "$(date): ERROR - Failed to download stats data"
    rm -f "$DEST_FILE.tmp"
    exit 1
fi