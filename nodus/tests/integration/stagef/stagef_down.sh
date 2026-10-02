#!/usr/bin/env bash
#
# Stage F harness — teardown. Kills every process recorded in
# $BASE_DIR/pids.txt and removes the BASE_DIR. In a split mode
# (STAGEF_MODE=splitw / mixedw) a split node has TWO lines there — its
# nodus-server and its nodus-witness (stagef_up_v2.sh) — and both are
# killed by the same loop; nothing here is mode-specific.
#
# Safe to run without an active harness (no-op).

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[ok] no active Stage F run"
    rm -f "$STAGEF_POINTER"
    exit 0
fi

if [ -f "$BASE_DIR/pids.txt" ]; then
    while read -r pid; do
        [ -z "$pid" ] && continue
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done < "$BASE_DIR/pids.txt"
    # Give them 2s to shut down gracefully, then force.
    sleep 2
    while read -r pid; do
        [ -z "$pid" ] && continue
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done < "$BASE_DIR/pids.txt"
fi

# Safety: refuse to rm -rf anything outside /tmp/stagef-*.
case "$BASE_DIR" in
    /tmp/stagef-*) rm -rf "$BASE_DIR" ;;
    *) echo "[WARN] BASE_DIR $BASE_DIR outside /tmp/stagef-*, not removing" >&2 ;;
esac

rm -f "$STAGEF_POINTER"
echo "[ok] Stage F harness torn down"
