#!/bin/bash
# nodus-update — Self-update nodus from git, rebuild, restart
#
# Usage:
#   nodus-cli update       — check + ask before updating
#   nodus-cli update -s    — silent, update without asking
#
# Reports: "Updated from vX.Y.Z to vA.B.C" or "Already up to date"
#
# Split S6 (decision docs/plans/decisions/2026-10-01-nodus-component-split.md
# item 8): every binary is installed — nodus-server, nodus-core,
# nodus-storage, nodus-witness. The host keeps the layout it runs: when the
# three split units are installed AND nodus-core is active, the three are
# restarted together (systemd orders their starts by After=, core first);
# otherwise the combined nodus.service, as before. No restart ORDER beyond
# After= is claimed here — the per-host order on a live validator is an
# OPEN operator item (docs/DEPLOY_RUNBOOK.md "Three-process node").

set -e

NODUS_DIR="/opt/dna/nodus"
BUILD_DIR="$NODUS_DIR/build"
INSTALL_DIR="/usr/local/bin"
BINARY="$INSTALL_DIR/nodus-server"
BINARIES="nodus-server nodus-core nodus-storage nodus-witness"
SERVICE="nodus"
SPLIT_UNITS="nodus-core nodus-storage nodus-witness"
BRANCH="main"
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

# Which layout this host runs (split S6): the three split units, when they
# are installed and nodus-core is active; the combined service otherwise.
# The units conflict with nodus.service, so at most one layout is active.
SPLIT=0
if [ -f /etc/systemd/system/nodus-core.service ] && \
   systemctl is-active --quiet nodus-core 2>/dev/null; then
    SPLIT=1
fi
if [ "$SPLIT" -eq 1 ]; then
    UNITS="$SPLIT_UNITS"
else
    UNITS="$SERVICE"
fi

for b in $BINARIES; do
    if [ ! -f "$BUILD_DIR/$b" ]; then
        echo "❌ Build produced no $b!"
        exit 1
    fi
done

# Stop, install, start
echo "🔄 Restarting $UNITS..."
# shellcheck disable=SC2086
systemctl stop $UNITS 2>/dev/null || true
for b in $BINARIES; do
    cp "$BUILD_DIR/$b" "$INSTALL_DIR/$b"
done
# shellcheck disable=SC2086
systemctl start $UNITS

# Wait for startup
sleep 2

# Verify — every unit of the layout
FAILED=""
for u in $UNITS; do
    systemctl is-active --quiet "$u" || FAILED="$FAILED $u"
done
if [ -z "$FAILED" ]; then
    NEW_COMMIT=$(cd "$NODUS_DIR" && git rev-parse --short HEAD)
    echo ""
    echo "✅ Updated successfully!"
    echo "   $CURRENT ($CURRENT_COMMIT) → $CURRENT ($NEW_COMMIT)"
    echo "   $NEW_COMMITS commit(s) applied"
    echo "   Service(s): $UNITS active"
else
    echo "❌ Service(s) failed to start after update:$FAILED"
    for u in $FAILED; do
        echo "   Check: journalctl -u $u -n 20"
    done
    exit 1
fi
