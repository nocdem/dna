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
# items 8, 12): every binary is installed — nodus-server, nodus-core,
# nodus-storage, nodus-witness, nodus-cli (the set deploy/build-nodus.sh
# installs). The host keeps the layout it is ENABLED for (systemctl
# is-enabled, never is-active — a layout that is down at the moment is
# still the host's layout): nodus.service enabled → the combined server;
# nodus-core enabled → the split units that are enabled (core is in every
# layout, item 12). Both enabled, neither enabled, or a split unit enabled
# without nodus-core → refuse, nothing changed; never guess, never start
# nodus.service on a host whose split units are enabled.
#
# Order: decide the layout (before the pull); pull and build; copy the
# three split unit files from
# nodus/deploy/ and `systemctl daemon-reload` (so unit fixes reach hosts
# kept up to date with this script); stop the layout's units; install every
# binary atomically (install to <dest>.new, mv over <dest> — never a write
# into a running binary); start the units. systemd orders the split units'
# starts by After= (core first); no restart ORDER beyond that is claimed
# here — the per-host order on a live validator is an OPEN operator item
# (docs/DEPLOY_RUNBOOK.md "Three-process node").
#
# Host lock: /run/lock/nodus-admin.lock (flock -n; never waits), taken after
# the confirmation and before the enabled set is read, released when the
# script exits. Another Nodus install, update or package change holding it →
# refuse, nothing changed. The lock file is root:root 0600; one that is not a
# regular, non-symlink, root-owned 0600 file is refused ("remove it and
# retry"), never adopted. The script needs root for the lock (and for the
# install that follows).

set -e

NODUS_DIR="/opt/dna/nodus"
BUILD_DIR="$NODUS_DIR/build"
INSTALL_DIR="/usr/local/bin"
BINARY="$INSTALL_DIR/nodus-server"
BINARIES="nodus-server nodus-core nodus-storage nodus-witness nodus-cli"
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

# Host lock: one Nodus install, update or package change at a time on this
# host (also taken by install.sh, install-node.sh, build-nodus.sh and
# nodus-cli package — same file, exclusive flock). Taken without waiting,
# BEFORE the enabled set is read and held until this process exits, after
# the last unit start (the descriptor closes then). Held elsewhere → exit 1,
# nothing changed.
ADMIN_LOCK="/run/lock/nodus-admin.lock"
if ! command -v flock >/dev/null 2>&1; then
    echo "❌ Refusing: flock not found (util-linux) — it provides the host lock that keeps two Nodus installs, updates or package changes apart. Nothing was changed."
    exit 1
fi
# /run/lock is world-writable: the file is root:root 0600 (created so when
# missing, with noclobber = O_EXCL, never written through a planted symlink)
# and is accepted only as a regular, non-symlink file owned by uid 0 with
# mode exactly 600. A non-root run must not create it (a file owned by
# someone else would then block every later root run).
if [ "$(id -u)" != "0" ]; then
    echo "❌ Refusing: must run as root (the host lock $ADMIN_LOCK is root-owned). Nothing was changed."
    exit 1
fi
if [ ! -e "$ADMIN_LOCK" ] && [ ! -L "$ADMIN_LOCK" ]; then
    ( umask 077; set -C; : > "$ADMIN_LOCK" ) 2>/dev/null || :
fi
if [ -L "$ADMIN_LOCK" ] || [ ! -f "$ADMIN_LOCK" ] ||
   [ "$(stat -c '%u' "$ADMIN_LOCK" 2>/dev/null || :)" != "0" ] ||
   [ "$(stat -c '%a' "$ADMIN_LOCK" 2>/dev/null || :)" != "600" ]; then
    echo "❌ Refusing: $ADMIN_LOCK is not a root-owned 0600 regular file; remove it and retry. Nothing was changed."
    exit 1
fi
if [ ! -r "$ADMIN_LOCK" ]; then
    echo "❌ Refusing: cannot read $ADMIN_LOCK. Nothing was changed."
    exit 1
fi
exec 9< "$ADMIN_LOCK"
if ! flock -n 9; then
    echo "❌ Refusing: another Nodus install, update or package change is running on this host — nothing was changed."
    exit 1
fi

# unit_enabled UNIT — 0 when `systemctl is-enabled UNIT` prints exactly
# "enabled". The exit code alone is not used: it is also 0 for static,
# indirect, alias and generated units.
unit_enabled() {
    [ "$(systemctl is-enabled "$1" 2>/dev/null || true)" = "enabled" ]
}

# Which layout this host is enabled for (split S6, header): UNITS = the
# units to stop and start, or refuse — before the pull, so a refused host
# has nothing changed, not even its checkout.
EN=""
for u in $SPLIT_UNITS; do
    if unit_enabled "$u"; then EN="$EN $u"; fi
done
EN="${EN# }"
if unit_enabled "$SERVICE"; then
    if [ -n "$EN" ]; then
        echo "❌ Refusing: $SERVICE.service AND split unit(s) ($EN) are enabled — two layouts on one data directory."
        echo "   Disable one layout (docs/DEPLOY_RUNBOOK.md \"Three-process node\"), then run this again. Nothing was changed."
        exit 1
    fi
    UNITS="$SERVICE"
elif [ -n "$EN" ]; then
    if ! unit_enabled nodus-core; then
        echo "❌ Refusing: split unit(s) $EN enabled without nodus-core — core runs in every layout (decision item 12)."
        echo "   Enable nodus-core or disable $EN, then run this again. Nothing was changed."
        exit 1
    fi
    UNITS="$EN"
else
    echo "❌ Refusing: neither $SERVICE.service nor nodus-core.service is enabled — no layout to update."
    echo "   Enable the layout this host should run, then run this again. Nothing was changed."
    exit 1
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

for b in $BINARIES; do
    if [ ! -f "$BUILD_DIR/$b" ]; then
        echo "❌ Build produced no $b!"
        exit 1
    fi
done
for u in $SPLIT_UNITS; do
    if [ ! -f "$NODUS_DIR/deploy/$u.service" ]; then
        echo "❌ No $NODUS_DIR/deploy/$u.service in the tree!"
        exit 1
    fi
done

# The split unit files — copied whether or not they are enabled, as
# deploy/build-nodus.sh does, so a unit fix reaches every host — then a
# daemon-reload, before anything is stopped or started.
for u in $SPLIT_UNITS; do
    cp "$NODUS_DIR/deploy/$u.service" "/etc/systemd/system/$u.service"
done
systemctl daemon-reload

# Stop, install (atomically: <dest>.new, then rename over <dest>), start
echo "🔄 Restarting $UNITS..."
# shellcheck disable=SC2086
systemctl stop $UNITS
for b in $BINARIES; do
    install -m 0755 "$BUILD_DIR/$b" "$INSTALL_DIR/$b.new"
    mv -f "$INSTALL_DIR/$b.new" "$INSTALL_DIR/$b"
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
