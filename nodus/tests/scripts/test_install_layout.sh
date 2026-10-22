#!/bin/bash
# test_install_layout.sh — nodus/deploy/install.sh --dry-run: which units a
# split host keeps, and when the combined layout is refused.
#
# Usage: test_install_layout.sh <path to nodus/deploy/install.sh>
#
# What it proves (each would be false if the case failed):
#   - a FIRST install (no nodus unit enabled) with --layout split plans all
#     three units: core, storage, witness;
#   - on an EXISTING split host (nodus-core enabled), --layout split without
#     --no-* plans exactly the split units that are enabled — a package that
#     was turned off (storage or witness) stays off, one or both;
#   - --layout combined on a split host where storage or witness is not
#     enabled is refused, naming the removed package(s) and the command that
#     adds them back; with all three enabled it is planned as before;
#   - the refusals that existed before stay: core alone (both --no-* flags),
#     a split unit enabled but not asked for, both layouts enabled; and an
#     explicit --no-witness on a host whose witness is already off is honoured.
#
# What it requires: bash, a default build is NOT needed (no nodus binary is
# built or run; the "binaries" are tiny shell scripts that print a banner).
# No compile flags, no STAGEF_* / NODUS_FAULT_* environment. It needs the
# host to have: coreutils (timeout, readlink -m, sha256sum), no
# /etc/nodus.conf, and no systemd drop-in for a nodus unit (install.sh --dry-run
# reads both of the real host).
#
# What it leaves behind: nothing — one mktemp -d directory, removed on exit.
# It never calls the real systemctl (a fake one is first on PATH) and never
# takes the host lock (--dry-run takes none).
#
# How it can lie: exit 77 means SKIPPED (the host has /etc/nodus.conf or a
# nodus drop-in), not passed — ctest reports it as skipped. It checks the
# printed PLAN of the dry run only; it does not start units, and does not
# prove the lock (that is exercised by the real run, not here).

set -u

INSTALL_SH=${1:-}
[ -n "$INSTALL_SH" ] && [ -f "$INSTALL_SH" ] || {
    echo "usage: $0 <path to install.sh>" >&2
    exit 2
}
INSTALL_SH=$(readlink -f "$INSTALL_SH")

if [ -e /etc/nodus.conf ]; then
    echo "SKIP: /etc/nodus.conf exists on this host; install.sh --dry-run would read it"
    exit 77
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/pkg"
FAKEBIN="$WORK/bin"
mkdir -p "$PKG" "$FAKEBIN"

# --- the fake package: what install.sh checks before the plan ---------------
BINARIES="nodus-server nodus-core nodus-storage nodus-witness nodus-cli"
for b in $BINARIES; do
    printf '#!/bin/sh\necho "Nodus Fake v1.2.3"\nexit 0\n' > "$PKG/$b"
    chmod 0755 "$PKG/$b"
done
for u in nodus nodus-core nodus-storage nodus-witness; do
    printf '[Service]\nExecStart=/usr/local/bin/%s -c /etc/nodus.conf\nReadWritePaths=/var/lib/nodus\n' \
        "$u" > "$PKG/$u.service"
done
cp "$INSTALL_SH" "$PKG/install.sh"
chmod 0755 "$PKG/install.sh"
echo "fake package" > "$PKG/README"
printf 'nodus 1.2.3\ncommit fake\narch %s\n' "$(uname -m)" > "$PKG/VERSION"
(
    cd "$PKG" &&
    sha256sum $BINARIES nodus.service nodus-core.service nodus-storage.service \
        nodus-witness.service install.sh README VERSION > SHA256SUMS
) || { echo "FAIL: cannot write SHA256SUMS" >&2; exit 1; }
printf '{"identity_path": "/var/lib/nodus", "data_path": "/var/lib/nodus"}\n' > "$WORK/nodus.conf"

# --- the fake systemctl: reports FAKE_ENABLED / FAKE_ACTIVE, nothing else ----
cat > "$FAKEBIN/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
    is-enabled)
        for u in ${FAKE_ENABLED:-}; do
            if [ "$u" = "$2" ]; then echo enabled; exit 0; fi
        done
        echo disabled; exit 1 ;;
    is-active)
        for u in ${FAKE_ACTIVE:-}; do
            if [ "$u" = "$2" ]; then echo active; exit 0; fi
        done
        echo inactive; exit 3 ;;
    *)
        echo "fake systemctl: unexpected call: $*" >&2
        exit 99 ;;
esac
EOF
chmod 0755 "$FAKEBIN/systemctl"

FAILS=0
OUT=""
RC=0

# plan ENABLED_UNITS ARGS... — run the dry run; sets OUT and RC.
plan() {
    local enabled=$1
    shift
    OUT=$(env PATH="$FAKEBIN:$PATH" FAKE_ENABLED="$enabled" FAKE_ACTIVE="$enabled" \
          NODUS_ADMIN_LOCK_HELD= \
          sh "$PKG/install.sh" "$@" --config "$WORK/nodus.conf" --allow-downgrade --dry-run 2>&1)
    RC=$?
}

fail() {
    echo "FAIL: $1" >&2
    echo "---- output (rc=$RC) ----" >&2
    printf '%s\n' "$OUT" >&2
    echo "-------------------------" >&2
    FAILS=$((FAILS + 1))
}
want_rc() {    # want_rc CASE RC
    [ "$RC" -eq "$2" ] || fail "$1: expected exit $2"
}
want_text() {  # want_text CASE FIXED-STRING
    printf '%s\n' "$OUT" | grep -qF -- "$2" || fail "$1: output lacks: $2"
}
want_line() {  # want_line CASE EXTENDED-REGEX (a whole output line)
    printf '%s\n' "$OUT" | grep -qE -- "$2" || fail "$1: no line matching: $2"
}
no_text() {    # no_text CASE FIXED-STRING
    if printf '%s\n' "$OUT" | grep -qF -- "$2"; then fail "$1: output must not contain: $2"; fi
}

# Host sanity: a nodus drop-in on the real host is read by the dry run.
plan "" --layout split
if printf '%s\n' "$OUT" | grep -q 'drop-in .* exists'; then
    echo "SKIP: this host has a systemd drop-in for a nodus unit; the dry run refuses on it"
    exit 77
fi

C="first install"
plan "" --layout split
want_rc "$C" 0
want_text "$C" "wanted: split (nodus-core nodus-storage nodus-witness)"
want_line "$C" '^nodus-install: +enable \+ start, in order: nodus-core nodus-storage nodus-witness$'
no_text "$C" "keeping the enabled split units"

C="split host, storage off"
plan "nodus-core nodus-witness" --layout split
want_rc "$C" 0
want_text "$C" "wanted: split (nodus-core nodus-witness)"
want_line "$C" '^nodus-install: +enable \+ start, in order: nodus-core nodus-witness$'
want_text "$C" "keeping the enabled split units"

C="split host, witness off"
plan "nodus-core nodus-storage" --layout split
want_rc "$C" 0
want_line "$C" '^nodus-install: +enable \+ start, in order: nodus-core nodus-storage$'

C="split host, all three"
plan "nodus-core nodus-storage nodus-witness" --layout split
want_rc "$C" 0
want_line "$C" '^nodus-install: +enable \+ start, in order: nodus-core nodus-storage nodus-witness$'

C="split host, only core enabled (nothing to keep)"
plan "nodus-core" --layout split
want_rc "$C" 1
want_text "$C" "core alone is not an install of decision item 12"

C="explicit --no-witness, witness already off"
plan "nodus-core nodus-storage" --layout split --no-witness
want_rc "$C" 0
want_line "$C" '^nodus-install: +enable \+ start, in order: nodus-core nodus-storage$'
no_text "$C" "keeping the enabled split units"

C="combined, storage off"
plan "nodus-core nodus-witness" --layout combined
want_rc "$C" 1
want_text "$C" "packages removed: storage;"
want_text "$C" "sudo nodus-cli package add storage"
want_text "$C" "the combined server always runs both"

C="combined, witness off"
plan "nodus-core nodus-storage" --layout combined
want_rc "$C" 1
want_text "$C" "packages removed: witness;"
want_text "$C" "sudo nodus-cli package add witness"

C="combined, both off"
plan "nodus-core" --layout combined
want_rc "$C" 1
want_text "$C" "packages removed: storage witness;"
want_text "$C" "sudo nodus-cli package add storage; sudo nodus-cli package add witness"

C="combined, all three on"
plan "nodus-core nodus-storage nodus-witness" --layout combined
want_rc "$C" 0
want_text "$C" "wanted: combined (nodus)"

C="combined, host already combined"
plan "nodus" --layout combined
want_rc "$C" 0
want_text "$C" "wanted: combined (nodus)"

C="core alone (both --no-* flags)"
plan "" --layout split --no-storage --no-witness
want_rc "$C" 1
want_text "$C" "leave core alone"

C="split unit enabled but not asked for"
plan "nodus-core nodus-storage nodus-witness" --layout split --no-storage
want_rc "$C" 1
want_text "$C" "nodus-storage is enabled on this host but not asked for"

C="both layouts enabled"
plan "nodus nodus-core" --layout split
want_rc "$C" 1
want_text "$C" "two layouts on one data directory"

if [ "$FAILS" -ne 0 ]; then
    echo "test_install_layout: $FAILS check(s) FAILED" >&2
    exit 1
fi
echo "test_install_layout: all checks passed"
exit 0
