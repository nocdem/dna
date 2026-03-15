#!/bin/bash
# nodus-update — Self-update nodus from git, rebuild, restart
#
# Usage:
#   nodus-cli update       — check + ask before updating
#   nodus-cli update -s    — silent, update without asking
#
# Reports: "Updated from vX.Y.Z to vA.B.C" or "Already up to date"

set -e

NODUS_DIR="/opt/dna/nodus"
BUILD_DIR="$NODUS_DIR/build"
BINARY="/usr/local/bin/nodus-server"
SERVICE="nodus"
BRANCH="feature/group-channel"  # TODO: change to main after merge
SILENT=0

# Parse args
for arg in "$@"; do
    case "$arg" in
        -s|--silent) SILENT=1 ;;
        -h|--help)
            echo "Usage: nodus-update [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -s, --silent    Update without asking"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
    esac
done

# Get current version (from running binary)
CURRENT=$($BINARY -h 2>&1 | grep -oP 'v[0-9.]+' | head -1 || echo "unknown")
CURRENT_COMMIT=$(cd "$NODUS_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Current: $CURRENT (commit $CURRENT_COMMIT)"

# Fetch latest from remote
cd /opt/dna
git fetch origin "$BRANCH" --quiet 2>/dev/null

# Check if update available
LOCAL=$(git rev-parse HEAD 2>/dev/null)
REMOTE=$(git rev-parse "origin/$BRANCH" 2>/dev/null)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "✅ Already up to date ($CURRENT, commit $CURRENT_COMMIT)"
    exit 0
fi

# Count new commits
NEW_COMMITS=$(git log --oneline "$LOCAL..$REMOTE" 2>/dev/null | wc -l)
REMOTE_SHORT=$(echo "$REMOTE" | cut -c1-8)

echo "📦 Update available: $NEW_COMMITS new commit(s) (latest: $REMOTE_SHORT)"

# Show changelog
echo ""
echo "Changes:"
git log --oneline "$LOCAL..$REMOTE" 2>/dev/null | head -10
if [ "$NEW_COMMITS" -gt 10 ]; then
    echo "  ... and $((NEW_COMMITS - 10)) more"
fi
echo ""

# Ask unless silent
if [ "$SILENT" -eq 0 ]; then
    read -p "Update now? [y/N] " REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        echo "Cancelled."
        exit 0
    fi
fi

echo "🔄 Updating..."

# Pull
git checkout "$BRANCH" --quiet 2>/dev/null
git pull origin "$BRANCH" --quiet 2>/dev/null

# Rebuild
echo "🔨 Building..."
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

# Stop, install, start
echo "🔄 Restarting nodus..."
systemctl stop "$SERVICE" 2>/dev/null || true
cp "$BUILD_DIR/nodus-server" "$BINARY"
systemctl start "$SERVICE"

# Wait for startup
sleep 2

# Verify
if systemctl is-active --quiet "$SERVICE"; then
    NEW_COMMIT=$(cd "$NODUS_DIR" && git rev-parse --short HEAD)
    echo ""
    echo "✅ Updated successfully!"
    echo "   $CURRENT ($CURRENT_COMMIT) → $CURRENT ($NEW_COMMIT)"
    echo "   $NEW_COMMITS commit(s) applied"
    echo "   Service: active"
else
    echo "❌ Service failed to start after update!"
    echo "   Check: journalctl -u $SERVICE -n 20"
    exit 1
fi
