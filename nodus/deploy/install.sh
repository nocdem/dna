#!/bin/sh
# install.sh — the `nodus` installer (component split S7). Shipped inside
# the tarball nodus/deploy/make-dist.sh builds; run from the extracted
# directory.
#
# Decision docs/plans/decisions/2026-10-01-nodus-component-split.md:
#   item 26  installer artefact = tar.gz (binaries + this script)
#   item 8   the combined nodus-server stays (rollback path) — every
#            install carries all five binaries, whichever layout runs
#   item 12  core is in every split install; storage and witness are each
#            optional: core+storage / core+witness / core+storage+witness
#   item 10  only core writes identity files — this script starts core
#            first and waits for them before storage / witness start
#   item 18  one config file, /etc/nodus.conf, for every service
#   item 21  moving nodus.addr_seq out of the identity directory is the
#            installer's step (here, below)
#   item 11  each service has its own unit; restart policy is in the units
#
# Usage:
#   ./install.sh --layout combined|split [--no-storage] [--no-witness]
#                [--prefix DIR] [--config FILE] [--allow-downgrade]
#                [--dry-run]
#
#   --layout combined   nodus.service (the combined nodus-server)
#   --layout split      nodus-core + nodus-storage + nodus-witness
#   --no-storage        split without nodus-storage (core + witness)
#   --no-witness        split without nodus-witness (core + storage)
#   --prefix DIR        where the binaries go (default /usr/local/bin); the
#                       units' ExecStart= paths are rewritten to match. Not
#                       under /home, /root, /tmp, /var/tmp or /run/user (the
#                       units run with ProtectHome=true and PrivateTmp=true).
#                       deploy/build-nodus.sh and tools/nodus-update.sh
#                       install to /usr/local/bin only: a host installed
#                       with another --prefix keeps using this installer.
#   --config FILE       installed as /etc/nodus.conf when that file does not
#                       exist yet; never overwrites an existing one
#   --allow-downgrade   install even when the installed nodus is newer than
#                       this package, or its version cannot be read. An
#                       older release does not follow a chain that has voted
#                       a hard fork it lacks (docs/DEPLOY_RUNBOOK.md §2.2).
#   --dry-run           print every action, change nothing (root not
#                       required, but the config must be readable — an
#                       /etc/nodus.conf this installer wrote is 0600)
#
# Order (nothing on the system is changed until every check has passed):
#   1. SHA256SUMS of the payload verified. VERSION's arch must equal
#      `uname -m`, and each packaged binary must run here: `<binary> -h`
#      exits 0 and prints this package's version (a missing shared library
#      or a too-old glibc fails here, before any unit is touched).
#   2. Checks: root, config, layout. The current layout is what systemd has
#      ENABLED (`systemctl is-enabled` printing exactly "enabled" — the
#      same rule as deploy/build-nodus.sh and tools/nodus-update.sh): both
#      layouts enabled, or nodus-storage / nodus-witness enabled without
#      nodus-core → refuse. A split host is never shrunk silently: a split
#      unit that is enabled but not asked for → refuse. Also refused:
#      nodus-debug.service (a deploy/build-nodus.sh --debug build) enabled
#      or running; a drop-in (*.conf in /etc or /run systemd/system/
#      <unit>.service.d/) for any nodus unit — the checks read the packaged
#      unit, not what a drop-in turns it into; an installed nodus (in
#      --prefix, or named by an installed unit's ExecStart=) newer than
#      this package, or of a version that cannot be read, without
#      --allow-downgrade.
#   3. The five binaries and four units are staged as <dest>.new while the
#      node still runs (a failed copy stops nothing, and the .new files are
#      removed).
#   4. The running nodus units are stopped; units of the old layout that
#      the new one does not use are disabled.
#   5. All staged files are renamed over their destinations (mv -f), then
#      daemon-reload — no mix of old and new binaries after a failed copy.
#   6. nodus.addr_seq migration (item 21) when the split witness is about
#      to run on this host for the first time.
#   7. The wanted units are enabled and started: nodus-core first, then —
#      once core's identity files exist (bounded wait) — nodus-storage,
#      then nodus-witness. The final `systemctl is-active` of each wanted
#      unit is printed; any unit not active → exit 1 with the rollback
#      commands. Ctrl-C, SIGTERM and SIGHUP (an SSH drop) also print them
#      — run this inside tmux / screen on a remote host.
#
# Never wiped, never touched: chain data, nodus.db, every identity file
# other than nodus.addr_seq, an existing /etc/nodus.conf.

set -eu

PROG="nodus-install"
BINARIES="nodus-server nodus-core nodus-storage nodus-witness nodus-cli"
UNITS="nodus nodus-core nodus-storage nodus-witness"
SPLIT_UNITS="nodus-core nodus-storage nodus-witness"
DEBUG_UNIT="nodus-debug"        # deploy/build-nodus.sh --debug
UNIT_DIR="/etc/systemd/system"
ETC_CONF="/etc/nodus.conf"
UNIT_PREFIX="/usr/local/bin"   # the ExecStart= prefix in the shipped units
# Core's identity files (nodus_identity.c, nodus_identity_load_readonly):
# storage and witness refuse to start until all six exist.
IDENTITY_FILES="nodus.pk nodus.sk nodus.kyber_pk nodus.kyber_sk nodus.mlkem_pk nodus.mlkem_sk"
ADDR_SEQ="nodus.addr_seq"
IDENTITY_WAIT_TRIES=60          # x 1 s
SETTLE_SECONDS=5
VERSION_TIMEOUT=10              # s, for each `<binary> -h`

LAYOUT=""
WANT_STORAGE=1
WANT_WITNESS=1
PREFIX="/usr/local/bin"
CONFIG_ARG=""
ALLOW_DOWNGRADE=0
DRY=0
CHANGED=0       # set once the first system change is made (rollback hint)
SWAPPED=0       # set once the staged binaries are renamed into place
STAGED=""       # <dest>.new files written so far (removed on failure)
UNIT_TMP=""     # scratch dir for --prefix-rewritten units (removed on exit)
OLD_SEQ=""
NEW_SEQ=""
MIGRATE=0
PKG_VER=""
INSTALLED_DESC="none"

say() { echo "$PROG: $*"; }
die() {
    echo "$PROG: $*" >&2
    exit 1
}

usage() {
    sed -n '/^# Usage:/,/^# Order/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

# run CMD... — do it, or in --dry-run print it. Every change goes through
# here (or through a function that checks DRY itself).
run() {
    if [ "$DRY" -eq 1 ]; then
        echo "  [dry-run] $*"
    else
        echo "  + $*"
        CHANGED=1
        "$@"
    fi
}

# --- arguments -----------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --layout)
            [ $# -ge 2 ] || die "--layout needs combined or split"
            LAYOUT=$2; shift ;;
        --layout=*) LAYOUT=${1#--layout=} ;;
        --no-storage) WANT_STORAGE=0 ;;
        --no-witness) WANT_WITNESS=0 ;;
        --prefix)
            [ $# -ge 2 ] || die "--prefix needs a directory"
            PREFIX=$2; shift ;;
        --prefix=*) PREFIX=${1#--prefix=} ;;
        --config)
            [ $# -ge 2 ] || die "--config needs a file"
            CONFIG_ARG=$2; shift ;;
        --config=*) CONFIG_ARG=${1#--config=} ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
        --dry-run) DRY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (--help for usage)" ;;
    esac
    shift
done

case "$LAYOUT" in
    combined)
        [ "$WANT_STORAGE" -eq 1 ] && [ "$WANT_WITNESS" -eq 1 ] ||
            die "--no-storage / --no-witness apply to --layout split only"
        WANTED="nodus" ;;
    split)
        [ "$WANT_STORAGE" -eq 1 ] || [ "$WANT_WITNESS" -eq 1 ] ||
            die "--no-storage and --no-witness together leave core alone — not an install of decision item 12 (core+storage / core+witness / all three)"
        WANTED="nodus-core"
        [ "$WANT_STORAGE" -eq 1 ] && WANTED="$WANTED nodus-storage"
        [ "$WANT_WITNESS" -eq 1 ] && WANTED="$WANTED nodus-witness"
        ;;
    "") die "--layout combined|split is required (--help for usage)" ;;
    *) die "--layout must be combined or split, not '$LAYOUT'" ;;
esac

# A path that goes into a unit file or a command: absolute, and only
# characters that need no quoting anywhere.
check_path() {
    case "$2" in
        /*) ;;
        *) die "$1 must be an absolute path, got '$2'" ;;
    esac
    case "$2" in
        *[!A-Za-z0-9/._-]*) die "$1 may hold only A-Z a-z 0-9 / . _ - , got '$2'" ;;
    esac
    case "$2" in
        */..|*/../*|*/.|*/./*|*//*) die "$1 must be a plain path (no . / .. components, no //), got '$2'" ;;
    esac
}
# A path a service uses: not where the units' ProtectHome=true (/home,
# /root, /run/user) or PrivateTmp=true (/tmp, /var/tmp) hide it — the
# service would see an empty or private directory. Checked as written
# and, symlinks resolved, as it really is.
check_service_path() {
    for p in "$2" "$(readlink -m "$2" 2>/dev/null || true)"; do
        r=""
        [ "$p" = "$2" ] || r=" (resolves to $p)"
        case "$p" in
            /home|/home/*|/root|/root/*|/run/user|/run/user/*)
                die "$1 $2$r is under /home, /root or /run/user — the units run with ProtectHome=true and could not see it" ;;
            /tmp|/tmp/*|/var/tmp|/var/tmp/*)
                die "$1 $2$r is under /tmp or /var/tmp — the units run with PrivateTmp=true and would see an empty private directory there" ;;
        esac
    done
}
check_path "--prefix" "$PREFIX"
PREFIX=${PREFIX%/}
[ -n "$PREFIX" ] || die "--prefix / is not a binary directory"
check_service_path "--prefix" "$PREFIX"

in_list() {   # in_list WORD LIST...
    w=$1; shift
    for x in "$@"; do [ "$x" = "$w" ] && return 0; done
    return 1
}

# banner_version TEXT — X.Y.Z from the first line "<Title> vX.Y.Z" that
# every nodus binary's -h prints (tools/nodus_node_config.c usage(),
# tools/nodus-cli.c usage()); "" when there is none.
banner_version() {
    printf '%s\n' "$1" | head -n 1 |
        sed -n 's/^.* v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p'
}

# ver_gt A B — 0 when X.Y.Z A is newer than B (numeric per field).
ver_gt() {
    old_ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086
    set -- $1 $2
    IFS=$old_ifs
    [ "$1" -gt "$4" ] && return 0
    [ "$1" -lt "$4" ] && return 1
    [ "$2" -gt "$5" ] && return 0
    [ "$2" -lt "$5" ] && return 1
    [ "$3" -gt "$6" ]
}

# probe BINARY — runs `BINARY -h` (it prints its banner and exits before
# any init), bounded; sets PROBE_RC and PROBE_OUT.
probe() {
    if PROBE_OUT=$(timeout "$VERSION_TIMEOUT" "$1" -h 2>&1); then
        PROBE_RC=0
    else
        PROBE_RC=$?
    fi
}

if [ "$DRY" -eq 1 ]; then
    say "DRY RUN — nothing on this system is changed"
fi

# A relative --config is relative to where the installer was started, not
# to the package directory it changes into below.
if [ -n "$CONFIG_ARG" ]; then
    case "$CONFIG_ARG" in
        /*) ;;
        *) CONFIG_ARG="$PWD/$CONFIG_ARG" ;;
    esac
    [ -f "$CONFIG_ARG" ] || die "--config $CONFIG_ARG is not a file"
fi

# --- 1. payload integrity, and does it run here ------------------------------
PKG_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$PKG_DIR"
[ -f SHA256SUMS ] || die "$PKG_DIR/SHA256SUMS not found — not an extracted nodus tarball"
EXPECTED="$BINARIES nodus.service nodus-core.service nodus-storage.service nodus-witness.service install.sh README VERSION"
# Every listed name must be one we expect, each expected file listed once.
LISTED=$(awk '{ n = $2; sub(/^\*/, "", n); print n }' SHA256SUMS)
for f in $LISTED; do
    # shellcheck disable=SC2086
    in_list "$f" $EXPECTED || die "SHA256SUMS lists an unexpected file '$f' — refusing"
done
for f in $EXPECTED; do
    [ "$(printf '%s\n' "$LISTED" | grep -c -x -F "$f")" = 1 ] ||
        die "SHA256SUMS does not list $f exactly once — refusing"
done
sha256sum -c --strict --quiet SHA256SUMS ||
    die "SHA256SUMS verification FAILED — the payload is not what make-dist.sh wrote; nothing was changed"
say "payload verified (SHA256SUMS, $(printf '%s\n' "$LISTED" | wc -l | tr -d ' ') files)"
PKG_VER=$(sed -n 's/^nodus //p' VERSION)
[ "$(printf '%s\n' "$PKG_VER" | grep -c '^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$')" = 1 ] ||
    die "VERSION has no 'nodus X.Y.Z' line (got '$PKG_VER') — refusing"
say "package: nodus $PKG_VER ($(sed -n 's/^commit //p' VERSION))"

PKG_ARCH=$(sed -n 's/^arch //p' VERSION)
HOST_ARCH=$(uname -m)
[ "$PKG_ARCH" = "$HOST_ARCH" ] ||
    die "this package is for '$PKG_ARCH', this host is '$HOST_ARCH' — nothing was changed"
command -v timeout >/dev/null 2>&1 || die "timeout not found (coreutils) — needed to run the binaries' -h check"
for b in $BINARIES; do
    probe "$PKG_DIR/$b"
    [ "$PROBE_RC" -eq 0 ] ||
        die "$b does not run on this host (-h exit $PROBE_RC): $(printf '%s\n' "$PROBE_OUT" | head -n 3 | tr '\n' ' ') — missing shared library or too old a glibc? Nothing was changed."
    bver=$(banner_version "$PROBE_OUT")
    [ "$bver" = "$PKG_VER" ] ||
        die "$b -h reports '${bver:-no version}', VERSION says $PKG_VER — refusing. Nothing was changed."
done
say "the five binaries run on this host ($HOST_ARCH, each -h reports v$PKG_VER)"

# --- 2. checks -------------------------------------------------------------
if [ "$DRY" -eq 0 ] && [ "$(id -u)" != 0 ]; then
    die "must run as root (or use --dry-run)"
fi
command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this installer drives systemd units"

# Config: /etc/nodus.conf is the one config of every service (item 18).
INSTALL_CONF=0
if [ -e "$ETC_CONF" ]; then
    if [ -n "$CONFIG_ARG" ]; then
        if ! cmp -s "$CONFIG_ARG" "$ETC_CONF"; then
            die "$ETC_CONF exists and differs from --config $CONFIG_ARG — an existing config is never overwritten; edit $ETC_CONF yourself or drop --config"
        fi
    fi
    CONF_SRC="$ETC_CONF"
else
    [ -n "$CONFIG_ARG" ] ||
        die "$ETC_CONF does not exist — write it first, or pass --config <file> to install one (this package carries no config)"
    CONF_SRC="$CONFIG_ARG"
    INSTALL_CONF=1
fi
[ -r "$CONF_SRC" ] || die "cannot read $CONF_SRC"

# The config on one line: a line break between a key and its value is
# legal JSON and must not hide the key from the checks below.
conf_flat() {
    tr '\r\n' '  ' < "$CONF_SRC"
}

# conf_string KEY — the string value of a top-level "KEY": "value" in the
# config, "" when the key is absent. More than one occurrence, or a value
# that is not a plain string → refuse.
conf_string() {
    n=$(grep -o "\"$1\"[[:space:]]*:" "$CONF_SRC" | wc -l | tr -d ' ')
    [ "$n" -le 1 ] || die "$CONF_SRC has \"$1\" $n times — refusing to guess which one the services use"
    [ "$n" -eq 1 ] || return 0
    v=$(conf_flat |
        sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p")
    [ -n "$v" ] || die "$CONF_SRC: \"$1\" is not a non-empty string"
    printf '%s\n' "$v"
}
IDENTITY_PATH=$(conf_string identity_path)
DATA_PATH=$(conf_string data_path)
# The binaries' own default when the config has no data_path
# (nodus_node_config.c: "/var/lib/nodus"); identity_path has no default.
[ -n "$DATA_PATH" ] || DATA_PATH="/var/lib/nodus"
check_path "data_path" "$DATA_PATH"
DATA_PATH=${DATA_PATH%/}
check_service_path "data_path" "$DATA_PATH"
if [ -n "$IDENTITY_PATH" ]; then
    check_path "identity_path" "$IDENTITY_PATH"
    IDENTITY_PATH=${IDENTITY_PATH%/}
    check_service_path "identity_path" "$IDENTITY_PATH"
fi

# The *_external flags belong on the split units' command lines, never in
# the config: with one in the file, the same file no longer starts the
# combined nodus.service as the combined server (rollback).
for k in witness_external storage_external; do
    if conf_flat | grep -q "\"$k\"[[:space:]]*:[[:space:]]*true"; then
        die "$CONF_SRC sets \"$k\": true — keep it false or absent (the split units pass --$(echo "$k" | tr _ -) themselves; docs/DEPLOY_RUNBOOK.md \"Three-process node\")"
    fi
done
# The units run with ProtectSystem=strict and one ReadWritePaths= — the
# only directory tree a service may write. A data_path or identity_path
# outside it would be read-only to the service: refuse now, not as a
# restart loop later.
RW_PATH=""
for u in $UNITS; do
    [ "$(grep -c '^ReadWritePaths=' "$PKG_DIR/$u.service")" = 1 ] ||
        die "$u.service has no single ReadWritePaths= line — refusing"
    p=$(sed -n 's/^ReadWritePaths=//p' "$PKG_DIR/$u.service")
    [ -z "$RW_PATH" ] || [ "$p" = "$RW_PATH" ] ||
        die "the units disagree on ReadWritePaths= ($RW_PATH vs $p) — refusing"
    RW_PATH=$p
done
under_rw() {
    case "$1" in
        "$RW_PATH"|"$RW_PATH"/*) return 0 ;;
    esac
    return 1
}
under_rw "$DATA_PATH" ||
    die "data_path $DATA_PATH is outside the units' ReadWritePaths=$RW_PATH — the services could not write it"
if [ -n "$IDENTITY_PATH" ]; then
    under_rw "$IDENTITY_PATH" ||
        die "identity_path $IDENTITY_PATH is outside the units' ReadWritePaths=$RW_PATH — core could not write it"
fi
if [ "$LAYOUT" = split ] && [ -z "$IDENTITY_PATH" ]; then
    die "$CONF_SRC has no \"identity_path\" — nodus-storage and nodus-witness refuse to start without one (they read the identity core writes)"
fi

# Current layout — what systemd has ENABLED.
unit_enabled() {
    [ "$(systemctl is-enabled "$1" 2>/dev/null || true)" = "enabled" ]
}
unit_state() {
    systemctl is-active "$1" 2>/dev/null || true
}

# deploy/build-nodus.sh --debug writes nodus-debug.service: same
# /etc/nodus.conf, same data directory, no Conflicts= with these units,
# and not in this installer's stop list. Refuse while it is enabled or
# running.
s=$(systemctl is-enabled "$DEBUG_UNIT" 2>/dev/null || true)
case "$s" in
    enabled*|linked*|alias|indirect)
        die "$DEBUG_UNIT.service is '$s' (a build-nodus.sh --debug build on the same config and data directory) — systemctl disable --now $DEBUG_UNIT first. Nothing was changed." ;;
esac
s=$(unit_state "$DEBUG_UNIT")
case "$s" in
    active|activating|reloading|deactivating|refreshing)
        die "$DEBUG_UNIT.service is $s (a build-nodus.sh --debug build on the same config and data directory) — systemctl disable --now $DEBUG_UNIT first. Nothing was changed." ;;
esac

# Drop-ins: every check here reads the PACKAGED unit (ReadWritePaths=,
# ExecStart=); a drop-in can change what actually runs.
for u in $UNITS; do
    for d in "$UNIT_DIR/$u.service.d" "/run/systemd/system/$u.service.d"; do
        for f in "$d"/*.conf; do
            [ ! -e "$f" ] ||
                die "drop-in $f exists — this installer checks the packaged $u.service, not what a drop-in turns it into. Fold it into the config or remove it, then run again. Nothing was changed."
        done
    done
done

# Installed version — refuse to go back without --allow-downgrade. Read
# from every nodus binary in --prefix and every binary an installed nodus
# unit's ExecStart= names (the running layout may live elsewhere).
CANDIDATES=""
for b in $BINARIES; do
    CANDIDATES="$CANDIDATES $PREFIX/$b"
done
for u in $UNITS; do
    [ -f "$UNIT_DIR/$u.service" ] || continue
    e=$(sed -n 's/^ExecStart=[-@:+!]*\([^ ]*\).*/\1/p' "$UNIT_DIR/$u.service" | head -n 1)
    [ -z "$e" ] || CANDIDATES="$CANDIDATES $e"
done
INST_MAX=""
INST_FOUND=""
INST_UNREADABLE=""
for c in $CANDIDATES; do
    [ -f "$c" ] || continue
    in_list "$c" $INST_FOUND && continue
    INST_FOUND="$INST_FOUND $c"
    probe "$c"
    v=""
    [ "$PROBE_RC" -ne 0 ] || v=$(banner_version "$PROBE_OUT")
    if [ -z "$v" ]; then
        INST_UNREADABLE="$INST_UNREADABLE $c"
    elif [ -z "$INST_MAX" ] || ver_gt "$v" "$INST_MAX"; then
        INST_MAX=$v
    fi
done
if [ -n "$INST_FOUND" ]; then
    INSTALLED_DESC="${INST_MAX:+v$INST_MAX}${INST_UNREADABLE:+ (version unreadable:$INST_UNREADABLE)}"
fi
say "installed: $INSTALLED_DESC; package: v$PKG_VER"
DOWNGRADE_WHY=""
if [ -n "$INST_MAX" ] && ver_gt "$INST_MAX" "$PKG_VER"; then
    DOWNGRADE_WHY="the installed nodus is v$INST_MAX, this package is v$PKG_VER"
elif [ -n "$INST_UNREADABLE" ]; then
    DOWNGRADE_WHY="the version of$INST_UNREADABLE cannot be read (its -h fails or prints no version), so this may be a downgrade"
fi
if [ -n "$DOWNGRADE_WHY" ]; then
    if [ "$ALLOW_DOWNGRADE" -eq 0 ]; then
        die "$DOWNGRADE_WHY — refusing without --allow-downgrade. An older release does not follow a chain that has voted a hard fork it lacks: hard forks are height-activated and a binary older than the one that introduced a voted fork stops participating (docs/DEPLOY_RUNBOOK.md §2.2, \"Live hard forks\"). Nothing was changed."
    fi
    say "WARNING: $DOWNGRADE_WHY — going on because of --allow-downgrade. A release older than the binary that introduced a hard fork this chain has voted (docs/DEPLOY_RUNBOOK.md §2.2) stops participating."
fi

EN_SPLIT=""
for u in $SPLIT_UNITS; do
    if unit_enabled "$u"; then EN_SPLIT="$EN_SPLIT $u"; fi
done
EN_SPLIT=${EN_SPLIT# }
if unit_enabled nodus; then
    [ -z "$EN_SPLIT" ] ||
        die "nodus.service AND split unit(s) ($EN_SPLIT) are enabled — two layouts on one data directory. Disable one layout first (docs/DEPLOY_RUNBOOK.md \"Three-process node\"). Nothing was changed."
    CURRENT="combined"
    CURRENT_UNITS="nodus"
elif [ -n "$EN_SPLIT" ]; then
    unit_enabled nodus-core ||
        die "split unit(s) $EN_SPLIT enabled without nodus-core — core runs in every layout (decision item 12). Nothing was changed."
    CURRENT="split"
    CURRENT_UNITS="$EN_SPLIT"
else
    CURRENT="none"
    CURRENT_UNITS=""
fi
say "current layout: $CURRENT${CURRENT_UNITS:+ ($CURRENT_UNITS)}; wanted: $LAYOUT ($WANTED)"

# A split host is never shrunk silently (e.g. a validator's witness
# disabled because --no-witness was typed by mistake).
if [ "$CURRENT" = split ] && [ "$LAYOUT" = split ]; then
    for u in $CURRENT_UNITS; do
        # shellcheck disable=SC2086
        in_list "$u" $WANTED ||
            die "$u is enabled on this host but not asked for — this installer does not remove a split service. Disable it yourself (systemctl disable --now $u) and run again, or drop the --no-* flag. Nothing was changed."
    done
fi

# Units to disable: the old layout's units the new one does not use.
TO_DISABLE=""
for u in $CURRENT_UNITS; do
    # shellcheck disable=SC2086
    in_list "$u" $WANTED || TO_DISABLE="$TO_DISABLE $u"
done
TO_DISABLE=${TO_DISABLE# }

# Units to stop before the binaries are replaced: every nodus unit that is
# running or (re)starting, plus the current layout's units. Order:
# witness, storage, core, combined.
TO_STOP=""
for u in nodus-witness nodus-storage nodus-core nodus; do
    s=$(unit_state "$u")
    if in_list "$u" $CURRENT_UNITS || [ "$s" = active ] || [ "$s" = activating ] ||
       [ "$s" = reloading ] || [ "$s" = deactivating ]; then
        TO_STOP="$TO_STOP $u"
    fi
done
TO_STOP=${TO_STOP# }

# Item 21: nodus.addr_seq moves from the identity directory (where the
# combined binary keeps it, seq_dir = identity_path) to data_path (where
# nodus-witness keeps it). Done when the split witness is about to run on
# this host for the first time — i.e. the witness is wanted and
# nodus-witness is not enabled now. Both files present → refuse: which
# sequence is current cannot be decided here.
if [ "$LAYOUT" = split ] && [ "$WANT_WITNESS" -eq 1 ] && ! unit_enabled nodus-witness &&
   [ "$IDENTITY_PATH" != "$DATA_PATH" ]; then
    OLD_SEQ="$IDENTITY_PATH/$ADDR_SEQ"
    NEW_SEQ="$DATA_PATH/$ADDR_SEQ"
    if [ -e "$OLD_SEQ" ] && [ -e "$NEW_SEQ" ]; then
        die "both $OLD_SEQ and $NEW_SEQ exist — cannot tell which address-record sequence is current. Keep the right one, remove the other, run again. Nothing was changed."
    elif [ -e "$OLD_SEQ" ]; then
        MIGRATE=1
    fi
fi
# The way back (split → combined) is not a migration of item 21: the file
# is not moved back. Say so — the combined server keeps its sequence in
# the identity directory.
SEQ_NOTE=""
if [ "$LAYOUT" = combined ] && [ "$CURRENT" = split ] && [ -n "$IDENTITY_PATH" ] &&
   [ "$IDENTITY_PATH" != "$DATA_PATH" ] &&
   [ -e "$DATA_PATH/$ADDR_SEQ" ] && [ ! -e "$IDENTITY_PATH/$ADDR_SEQ" ]; then
    SEQ_NOTE="note: $DATA_PATH/$ADDR_SEQ stays where it is; the combined server keeps its address-record sequence in $IDENTITY_PATH/$ADDR_SEQ (absent). To carry the sequence back, mv $DATA_PATH/$ADDR_SEQ $IDENTITY_PATH/$ADDR_SEQ yourself while nodus.service is stopped."
fi

# --- the plan ---------------------------------------------------------------
say "plan:"
[ "$INSTALL_CONF" -eq 1 ] && say "  install $CONFIG_ARG as $ETC_CONF (0600)"
say "  create (if missing) $DATA_PATH${IDENTITY_PATH:+ and $IDENTITY_PATH} and $PREFIX"
say "  stage (node still running): $BINARIES -> $PREFIX/<name>.new; $UNITS -> $UNIT_DIR/<unit>.service.new (ExecStart prefix $PREFIX)"
say "  stop: ${TO_STOP:-<nothing running>}"
say "  disable: ${TO_DISABLE:-<none>}"
say "  rename every staged .new over its destination; daemon-reload"
if [ "$MIGRATE" -eq 1 ]; then
    say "  move $OLD_SEQ -> $NEW_SEQ (decision item 21)"
fi
say "  enable + start, in order: $WANTED"
[ -z "$SEQ_NOTE" ] || say "  $SEQ_NOTE"

# On failure after the first change: how to get back to nodus.service.
on_exit() {
    rc=$?
    [ -z "$UNIT_TMP" ] || rm -rf "$UNIT_TMP"
    if [ "$rc" -ne 0 ] && [ "$DRY" -eq 0 ] && [ -n "$STAGED" ]; then
        # shellcheck disable=SC2086
        rm -f $STAGED
    fi
    if [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
        echo "" >&2
        echo "$PROG: FAILED after changing this system (exit $rc)." >&2
        echo "$PROG: to return to the combined server (same config, same data directory):" >&2
        echo "    systemctl disable --now nodus-core nodus-storage nodus-witness" >&2
        echo "    systemctl enable --now nodus" >&2
        if [ "$SWAPPED" -eq 1 ]; then
            echo "$PROG: the binaries in $PREFIX are now $PKG_VER (were: $INSTALLED_DESC); for the previous" >&2
            echo "$PROG: version run the previous release's install.sh --layout combined --allow-downgrade." >&2
            echo "$PROG: WARNING: going back to an older release after this chain has voted a hard fork" >&2
            echo "$PROG: that release lacks makes this node stop following the chain — hard forks are" >&2
            echo "$PROG: height-activated (docs/DEPLOY_RUNBOOK.md §2.2, \"Live hard forks\")." >&2
        else
            echo "$PROG: the binaries in $PREFIX were NOT replaced (still: $INSTALLED_DESC)." >&2
        fi
        echo "$PROG: Logs: journalctl -u <unit> -n 50" >&2
        if [ "$MIGRATE" -eq 1 ] && [ -e "$NEW_SEQ" ] && [ ! -e "$OLD_SEQ" ]; then
            echo "$PROG: $ADDR_SEQ was moved to $NEW_SEQ; the combined server reads $OLD_SEQ —" >&2
            echo "$PROG: move it back (mv $NEW_SEQ $OLD_SEQ) before starting nodus.service." >&2
        fi
    fi
}
trap on_exit EXIT
# A signal (Ctrl-C, kill, an SSH drop) exits through on_exit too.
trap 'exit 130' INT TERM HUP

# --- 3-7. do it -------------------------------------------------------------
if [ "$INSTALL_CONF" -eq 1 ]; then
    run install -m 0600 "$CONFIG_ARG" "$ETC_CONF.new"
    run mv -f "$ETC_CONF.new" "$ETC_CONF"
fi
run mkdir -p "$DATA_PATH"
[ -n "$IDENTITY_PATH" ] && run mkdir -p "$IDENTITY_PATH"
run mkdir -p "$PREFIX"

# 3. Stage every file next to its destination while the node runs.
# stage SRC DEST MODE — install SRC as DEST.new (recorded for cleanup).
stage() {
    if [ "$DRY" -eq 1 ]; then
        echo "  [dry-run] install -m $3 $1 $2.new"
    else
        STAGED="$STAGED $2.new"
        echo "  + install -m $3 $1 $2.new"
        install -m "$3" "$1" "$2.new"
    fi
}
for b in $BINARIES; do
    stage "$PKG_DIR/$b" "$PREFIX/$b" 0755
done
# Unit files: ExecStart= rewritten when --prefix is not the shipped one.
# The shipped unit must have exactly one ExecStart= line under
# $UNIT_PREFIX, or the rewrite is refused.
if [ "$DRY" -eq 0 ]; then
    UNIT_TMP=$(mktemp -d)
fi
for u in $UNITS; do
    src="$PKG_DIR/$u.service"
    [ "$(grep -c "^ExecStart=$UNIT_PREFIX/" "$src")" = 1 ] ||
        die "$src has no single ExecStart=$UNIT_PREFIX/ line — refusing to install it"
    if [ "$PREFIX" != "$UNIT_PREFIX" ]; then
        if [ "$DRY" -eq 1 ]; then
            echo "  [dry-run] rewrite ExecStart=$UNIT_PREFIX/ -> ExecStart=$PREFIX/ in $u.service"
        else
            sed "s|^ExecStart=$UNIT_PREFIX/|ExecStart=$PREFIX/|" "$src" > "$UNIT_TMP/$u.service"
            src="$UNIT_TMP/$u.service"
        fi
    fi
    stage "$src" "$UNIT_DIR/$u.service" 0644
done

# 4. Stop, disable.
if [ -n "$TO_STOP" ]; then
    # shellcheck disable=SC2086
    run systemctl stop $TO_STOP
fi
if [ -n "$TO_DISABLE" ]; then
    # shellcheck disable=SC2086
    run systemctl disable $TO_DISABLE
fi

# 5. Every staged file renamed into place: binaries, then units.
for b in $BINARIES; do
    run mv -f "$PREFIX/$b.new" "$PREFIX/$b"
    SWAPPED=1
done
for u in $UNITS; do
    run mv -f "$UNIT_DIR/$u.service.new" "$UNIT_DIR/$u.service"
done
STAGED=""
run systemctl daemon-reload

if [ "$MIGRATE" -eq 1 ]; then
    # Re-checked now that every unit is stopped (the combined server
    # writes the old file while it runs).
    [ ! -e "$NEW_SEQ" ] || die "$NEW_SEQ appeared while units were stopping — refusing to move $OLD_SEQ over it"
    run mv "$OLD_SEQ" "$NEW_SEQ"
fi

# identity_ready — 0 when all six of core's identity files exist.
identity_ready() {
    for f in $IDENTITY_FILES; do
        [ -f "$IDENTITY_PATH/$f" ] || return 1
    done
    return 0
}

for u in $WANTED; do
    run systemctl enable "$u"
    run systemctl start "$u"
    if [ "$u" = nodus-core ]; then
        # Only core writes the identity (item 10); storage and witness
        # exit until it exists. Bounded wait; stop early if core died.
        if [ "$DRY" -eq 1 ]; then
            echo "  [dry-run] wait until $IDENTITY_PATH holds $IDENTITY_FILES (at most $IDENTITY_WAIT_TRIES x 1 s)"
        else
            i=0
            until identity_ready; do
                i=$((i + 1))
                s=$(unit_state nodus-core)
                if [ "$s" = failed ] || [ "$s" = inactive ]; then
                    die "nodus-core is $s before its identity files exist in $IDENTITY_PATH — see journalctl -u nodus-core -n 50"
                fi
                [ "$i" -lt "$IDENTITY_WAIT_TRIES" ] ||
                    die "identity files not in $IDENTITY_PATH after $IDENTITY_WAIT_TRIES s — see journalctl -u nodus-core -n 50"
                sleep 1
            done
            say "identity present in $IDENTITY_PATH"
        fi
    fi
done

if [ "$DRY" -eq 1 ]; then
    echo "  [dry-run] after ${SETTLE_SECONDS} s, print systemctl is-active of: $WANTED (exit 1 if any is not active)"
    say "dry run complete — nothing was changed"
    exit 0
fi

# Type=simple units are "active" as soon as they are forked; a short
# fixed settle lets one that exits at once show it. A snapshot, not a
# health check — run docs/DEPLOY_RUNBOOK.md §3 afterwards.
sleep "$SETTLE_SECONDS"
FAILED=""
for u in $WANTED; do
    s=$(unit_state "$u")
    say "$u: $s"
    [ "$s" = active ] || FAILED="$FAILED $u"
done
[ -z "$FAILED" ] || die "not active:$FAILED"
say "installed nodus $PKG_VER, layout $LAYOUT ($WANTED) — now verify the node (docs/DEPLOY_RUNBOOK.md §3)"
