#!/usr/bin/env bash
# install-node.sh — install or update a Nodus node (testnet).
#
# Published at https://nodusnetwork.io/install-node.sh. Run it on a Debian or
# Ubuntu x86-64 server:
#
#   curl -fsSL https://nodusnetwork.io/install-node.sh | sudo bash
#
# or download it, check its SHA-256, then:
#
#   sudo bash install-node.sh
#
# What it does: checks the machine, installs the build tools, downloads the
# Nodus source, builds it, packages it with nodus/deploy/make-dist.sh and
# installs it with that package's install.sh (three services: nodus-core,
# nodus-storage, nodus-witness). On a machine that already runs a node
# installed this way (/etc/nodus.conf + nodus-core.service enabled) the same
# script UPDATES the node in place: it keeps the node's key, its settings and
# its chain data.
#
# A real run (not --build-only) holds the host lock /run/lock/nodus-admin.lock
# (flock -n, never waits) from before it reads which services are enabled
# until it exits; a second install, update or package change on the same
# machine stops with "nothing was changed". The lock file is root:root 0600
# (created so when missing); one that is not a regular, non-symlink,
# root-owned 0600 file is refused ("remove it and retry"), never adopted.
# install.sh receives the open lock in NODUS_ADMIN_LOCK_HELD=9.
#
# Afterwards the owner goes to Nodus Connect -> More -> Nodus -> "Become a
# storage node" / "Become a witness" and runs the one command shown there
# (sudo nodus-cli consent <code>).
#
# Spec: docs/plans/decisions/2026-10-14-node-install-script.md (local) and the
# manual steps it automates, nodus/docs/STORAGE_NODE.md.
#
# The whole script is one function called on the last line, so a download
# cut short runs nothing at all.

set -euo pipefail

# ---------------------------------------------------------------------------
# Source. The script builds whatever `main` is at run time — there is no
# pinned commit (operator decision 2026-10-14: "hep son main"). The commit
# that was built is printed and recorded in /var/lib/nodus/install-commit.
# ---------------------------------------------------------------------------
NODUS_REPO="https://github.com/nocdem/dna.git"
NODUS_BRANCH="main"

# Testnet chain id and the seven witnesses to connect to — copied verbatim
# from nodus/docs/STORAGE_NODE.md step 3 (the list was read from the chain
# on 2026-10-14).
GENESIS_PIN="a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114"
PERSISTENT_PEERS=(
    "fd429639366cbc41d98db7603d51166ed5542d2d161cf69ff1ab6dbe80176197@161.97.85.25:4004"
    "16af3eaa620ab5d239ca63abd01943c7b1a8580a3c0204ec8a093bf7992c79df@156.67.24.125:4004"
    "04cdf00b3c37782b7df02fc0f71ba3b74893a60cbb800369d9ee6e97c46dd3ed@156.67.25.251:4004"
    "681c12a60cae6956d1c7a1b8c75b08594961888e0d8319882fee4c94ce77b55f@164.68.105.227:4004"
    "a7b23e52f02af2d2f526d58c741bb405825af8e31d753dc670b9c94cc01d2401@164.68.116.180:4004"
    "6573f74c177c9d97ba784e9607b487125f973f71026931e522051d9ba6fe713a@75.119.141.51:4004"
    "03499d1fae35f9e9aaf60a1c3f18d8c7d1ffa49f2c65bd4b6a531bdf8ef92c21@154.38.182.161:4004"
)

PROG="install-node"
ETC_CONF="/etc/nodus.conf"
# One lock for every Nodus install / update / package change on this host
# (also install.sh, tools/nodus-update.sh, deploy/build-nodus.sh, nodus-cli
# package). Same path, exclusive flock.
ADMIN_LOCK="/run/lock/nodus-admin.lock"
NETWORK_FILE="/etc/nodus-network.json"
VAR_DIR="/var/lib/nodus"                 # the units' ReadWritePaths=
IDENTITY_DIR="$VAR_DIR/identity"
DATA_DIR="$VAR_DIR/data"
COMMIT_FILE="$VAR_DIR/install-commit"
MIN_FREE_GIB=50
APT_PACKAGES=(git cmake build-essential pkg-config libssl-dev libsqlite3-dev
              libjson-c-dev m4 xz-utils xxd ca-certificates curl)
# Commands the build needs (from the packages above).
NEEDED_COMMANDS=(git cmake make gcc g++ pkg-config m4 xz xxd curl tar sha256sum)
UNITS_ALL=(nodus nodus-core nodus-storage nodus-witness)
SPLIT_UNITS=(nodus-core nodus-storage nodus-witness)

say()  { printf '%s: %s\n' "$PROG" "$*"; }
warn() { printf '%s: WARNING: %s\n' "$PROG" "$*" >&2; }
die()  { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Install or update a Nodus node (testnet) on a Debian/Ubuntu x86-64 server.

Usage:
  curl -fsSL https://nodusnetwork.io/install-node.sh | sudo bash
  curl -fsSL https://nodusnetwork.io/install-node.sh | sudo bash -s -- [options]
  sudo bash install-node.sh [options]

Options:
  --ip <IPv4>       this server's public IPv4 address (otherwise you are asked)
  --yes             do not ask questions; use the suggested answers
                    (the firewall is left unchanged unless --open-firewall)
  --open-firewall   if ufw is active, allow TCP 4004 (the witness port)
  --build-only      download, build and package only; install nothing and
                    write nothing under /etc (may run as a normal user,
                    together with --src-dir)
  --src-dir <dir>   where the source is downloaded and built
                    (default /opt/nodus-src)
  --force           update even when the node already runs the latest main
  -h, --help        show this help

On a machine that already runs a Nodus node installed with this script
(/etc/nodus.conf and nodus-core.service enabled) it updates that node and
keeps its key, its settings and its chain data.
EOF
}

# have_tty — 0 when /dev/tty can be opened (questions are read from it:
# under `curl | bash` the standard input is the script itself).
have_tty() {
    { : </dev/tty; } 2>/dev/null
}

# ask PROMPT — prints the answer read from /dev/tty.
ask() {
    local reply
    printf '%s' "$1" >/dev/tty
    IFS= read -r reply </dev/tty || reply=""
    printf '%s\n' "$reply"
}

# ask_yes_no PROMPT — 0 for y/yes, 1 for anything else (default: no).
ask_yes_no() {
    local reply
    reply=$(ask "$1 [y/N] ")
    case "$reply" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

# take_admin_lock — hold the host lock for the rest of this process: an
# exclusive flock on ADMIN_LOCK, taken without waiting. Another Nodus
# install, update or package change holding it → stop at once, nothing
# changed. Taken before the enabled units are read (the update below keeps
# exactly what is enabled) and released when this script exits, which is
# after install.sh has started the last unit. The open, locked descriptor
# (9) is handed on to install.sh: NODUS_ADMIN_LOCK_HELD=9, which install.sh
# accepts only when fd 9 refers to the lock file.
take_admin_lock() {
    command -v flock >/dev/null 2>&1 ||
        die "flock not found (util-linux) — it provides the host lock that keeps two Nodus installs, updates or package changes apart. Nothing was changed."
    # /run/lock is world-writable: create the file root-owned 0600 with
    # noclobber (O_EXCL, never written through a planted symlink) and accept
    # only a regular, non-symlink file owned by uid 0 with mode exactly 600.
    if [ ! -e "$ADMIN_LOCK" ] && [ ! -L "$ADMIN_LOCK" ]; then
        ( umask 077; set -C; : >"$ADMIN_LOCK" ) 2>/dev/null || :
    fi
    if [ -L "$ADMIN_LOCK" ] || [ ! -f "$ADMIN_LOCK" ] ||
       [ "$(stat -c '%u' "$ADMIN_LOCK" 2>/dev/null || :)" != "0" ] ||
       [ "$(stat -c '%a' "$ADMIN_LOCK" 2>/dev/null || :)" != "600" ]; then
        die "$ADMIN_LOCK is not a root-owned 0600 regular file; remove it and retry. Nothing was changed."
    fi
    [ -r "$ADMIN_LOCK" ] || die "cannot read $ADMIN_LOCK. Nothing was changed."
    exec 9<"$ADMIN_LOCK"
    flock -n 9 ||
        die "another Nodus install, update or package change is running on this host — nothing was changed."
    export NODUS_ADMIN_LOCK_HELD=9
}

unit_enabled() {
    [ "$(systemctl is-enabled "$1" 2>/dev/null || true)" = "enabled" ]
}
unit_state() {
    systemctl is-active "$1" 2>/dev/null || true
}
unit_busy() {
    case "$(unit_state "$1")" in
        active|activating|reloading|deactivating|refreshing) return 0 ;;
    esac
    return 1
}

# valid_ipv4 ADDR — dotted quad, each part 0-255, no leading zeros.
valid_ipv4() {
    local ip=$1 part
    local -a parts
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a parts <<<"$ip"
    for part in "${parts[@]}"; do
        [[ $part =~ ^(0|[1-9][0-9]*)$ ]] || return 1
        [ "$part" -le 255 ] || return 1
    done
    return 0
}

# private_ipv4 ADDR — 0 for 10/8, 172.16/12, 192.168/16, 127/8, 100.64/10.
private_ipv4() {
    local a b
    IFS=. read -r a b _ _ <<<"$1"
    [ "$a" -eq 10 ] && return 0
    [ "$a" -eq 127 ] && return 0
    [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 0
    [ "$a" -eq 192 ] && [ "$b" -eq 168 ] && return 0
    [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 0
    return 1
}

# conf_identity_path — the "identity_path" string in /etc/nodus.conf
# (empty when absent).
conf_identity_path() {
    tr '\r\n' '  ' <"$ETC_CONF" |
        sed -n 's/.*"identity_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

main() {
    local opt_ip="" opt_yes=0 opt_open_fw=0 opt_build_only=0 opt_force=0
    local src_dir="/opt/nodus-src"

    while [ $# -gt 0 ]; do
        case "$1" in
            --ip)
                [ $# -ge 2 ] || { usage >&2; exit 2; }
                opt_ip=$2; shift ;;
            --ip=*) opt_ip=${1#--ip=} ;;
            --yes) opt_yes=1 ;;
            --open-firewall) opt_open_fw=1 ;;
            --build-only) opt_build_only=1 ;;
            --src-dir)
                [ $# -ge 2 ] || { usage >&2; exit 2; }
                src_dir=$2; shift ;;
            --src-dir=*) src_dir=${1#--src-dir=} ;;
            --force) opt_force=1 ;;
            -h|--help) usage; exit 0 ;;
            *)
                printf '%s: unknown option %s\n\n' "$PROG" "$1" >&2
                usage >&2
                exit 2 ;;
        esac
        shift
    done
    case "$src_dir" in
        /*) ;;
        *) src_dir="$PWD/$src_dir" ;;
    esac
    src_dir=${src_dir%/}
    [ -n "$src_dir" ] || die "--src-dir / is not allowed"

    say "Nodus node installer (testnet)."
    if [ "$opt_build_only" -eq 0 ]; then
        say "Note: if you are connected over SSH, running this inside tmux or screen is safer —"
        say "a dropped connection would otherwise stop the installer half-way."
    fi

    # --- 1. checks -----------------------------------------------------------
    say "Checking this machine..."
    if [ "$opt_build_only" -eq 0 ] && [ "$EUID" -ne 0 ]; then
        die "please run as root: curl -fsSL https://nodusnetwork.io/install-node.sh | sudo bash"
    fi
    [ -r /etc/os-release ] || die "cannot read /etc/os-release — this installer supports Debian and Ubuntu only."
    local os_id os_like
    os_id=$( (. /etc/os-release && printf '%s' "${ID:-}") )
    os_like=$( (. /etc/os-release && printf '%s' "${ID_LIKE:-}") )
    case " $os_id $os_like " in
        *" debian "*|*" ubuntu "*) ;;
        *) die "this system is '$os_id' — this installer supports Debian and Ubuntu only." ;;
    esac
    local arch
    arch=$(uname -m)
    [ "$arch" = "x86_64" ] || die "this machine is '$arch' — a Nodus node needs an x86-64 (amd64) machine."
    local flags flag
    flags=$(grep -m 1 '^flags' /proc/cpuinfo || true)
    for flag in avx bmi2 adx; do
        grep -qw "$flag" <<<"$flags" ||
            die "the CPU does not have '$flag'. The node runs a self-test of its EVM at start and refuses to start without AVX, BMI2 and ADX."
    done
    say "System: $os_id, $arch, CPU has AVX, BMI2 and ADX."

    # Existing node? UPDATE when it is a three-process node this script
    # (or install.sh --layout split) installed; stop on anything else.
    local mode="install" u
    local -a seen=()
    if [ "$opt_build_only" -eq 0 ]; then
        command -v systemctl >/dev/null 2>&1 || die "systemctl not found — the node runs as systemd services."
        take_admin_lock
        [ ! -e "$ETC_CONF" ] || seen+=("$ETC_CONF exists")
        for u in "${UNITS_ALL[@]}"; do
            if unit_enabled "$u"; then seen+=("$u.service is enabled"); fi
            if unit_busy "$u"; then seen+=("$u.service is $(unit_state "$u")"); fi
        done
        if [ "${#seen[@]}" -gt 0 ]; then
            if unit_enabled nodus; then
                die "this machine runs the older single-service Nodus layout (nodus.service is enabled). This installer only updates the three-service layout (nodus-core, nodus-storage, nodus-witness); see nodus/docs/DEPLOY_RUNBOOK.md \"Three-process node\". Nothing was changed."
            fi
            if unit_busy nodus; then
                die "nodus.service (the older single-service layout) is $(unit_state nodus) on this machine — a mixed state this installer does not touch. Nothing was changed."
            fi
            if [ -f "$ETC_CONF" ] && unit_enabled nodus-core; then
                mode="update"
            else
                die "this machine already has parts of a Nodus node, and not in a state this installer can update ($(IFS=';'; printf '%s' "${seen[*]}")). An update needs /etc/nodus.conf and nodus-core.service enabled. Nothing was changed."
            fi
        fi
    fi
    local want_storage=1 want_witness=1
    if [ "$mode" = "update" ]; then
        unit_enabled nodus-storage || want_storage=0
        unit_enabled nodus-witness || want_witness=0
        if [ "$want_storage" -eq 0 ] && [ "$want_witness" -eq 0 ]; then
            die "nodus-core.service is enabled but neither nodus-storage nor nodus-witness is — not a layout this installer can update. Nothing was changed."
        fi
        say "Found a Nodus node on this machine: it will be UPDATED in place (key, settings and chain data are kept)."
    fi

    local avail_kib avail_gib
    if avail_kib=$(df -Pk /var/lib 2>/dev/null | awk 'NR == 2 { print $4 }') && [ -n "$avail_kib" ]; then
        avail_gib=$((avail_kib / 1024 / 1024))
        if [ "$avail_gib" -lt "$MIN_FREE_GIB" ]; then
            warn "only $avail_gib GiB free under /var/lib. A node needs at least $MIN_FREE_GIB GiB; a storage node needs at least 150 GiB (200 GiB recommended)."
        else
            say "Free disk under /var/lib: $avail_gib GiB."
        fi
    else
        warn "could not read the free disk space under /var/lib."
    fi

    # Questions come from /dev/tty. Find out now, before the long build,
    # whether they can be asked at all.
    if [ "$mode" = "install" ] && [ "$opt_build_only" -eq 0 ] && [ "$opt_yes" -eq 0 ] && ! have_tty; then
        die "no terminal to ask questions on. Run it again with the answers as options: --ip <public IPv4> and --yes (add --open-firewall to open TCP 4004 in ufw)."
    fi
    if [ -n "$opt_ip" ] && ! valid_ipv4 "$opt_ip"; then
        die "--ip '$opt_ip' is not an IPv4 address like 203.0.113.10."
    fi

    # --- 2. packages ---------------------------------------------------------
    local c
    local -a missing=()
    if [ "$EUID" -eq 0 ] && [ "$opt_build_only" -eq 0 ]; then
        say "Installing the build tools (apt-get)..."
        DEBIAN_FRONTEND=noninteractive apt-get update </dev/null ||
            die "apt-get update failed — check the network and the apt sources."
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            "${APT_PACKAGES[@]}" </dev/null ||
            die "apt-get install failed."
    else
        say "Skipping apt-get (--build-only changes nothing on the system); checking that the build tools are present..."
    fi
    for c in "${NEEDED_COMMANDS[@]}"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        die "missing commands: ${missing[*]}. Install them with: sudo apt-get install ${APT_PACKAGES[*]}"
    fi
    say "Build tools present."

    # --- 3. source -----------------------------------------------------------
    say "Getting the Nodus source ($NODUS_BRANCH of $NODUS_REPO) into $src_dir..."
    local reuse=0 url top
    if [ -e "$src_dir" ] && [ ! -d "$src_dir" ]; then
        die "$src_dir exists and is not a directory. Choose another place with --src-dir."
    fi
    if [ -d "$src_dir/.git" ]; then
        # A git checkout must be one this script made: same remote, owned
        # by the user running now, no edits to tracked files.
        [ "$(stat -c %u "$src_dir")" = "$EUID" ] && [ "$(stat -c %u "$src_dir/.git")" = "$EUID" ] ||
            die "$src_dir belongs to another user. Use another --src-dir (or run as the user who created it). Nothing was deleted."
        top=$(git -C "$src_dir" rev-parse --show-toplevel 2>/dev/null) || top=""
        url=$(git -C "$src_dir" remote get-url origin 2>/dev/null) || url=""
        [ "$top" = "$src_dir" ] && [ "$url" = "$NODUS_REPO" ] ||
            die "$src_dir holds something this installer did not make (another git checkout). Choose another place with --src-dir. Nothing was deleted."
        [ -z "$(git -C "$src_dir" status --porcelain --untracked-files=no)" ] ||
            die "files in $src_dir were edited by hand. This installer does not discard edits: choose another --src-dir, or undo them. Nothing was deleted."
        reuse=1
    elif [ -d "$src_dir" ]; then
        [ -z "$(ls -A "$src_dir")" ] ||
            die "$src_dir exists and is not empty. Choose another place with --src-dir. Nothing was deleted."
    else
        mkdir -p "$src_dir" ||
            die "cannot create $src_dir. Choose a place you can write to with --src-dir."
    fi
    if [ "$reuse" -eq 0 ]; then
        git -C "$src_dir" init -q </dev/null
        git -C "$src_dir" remote add origin "$NODUS_REPO" </dev/null
    fi
    git -C "$src_dir" fetch -q --depth 1 origin "$NODUS_BRANCH" </dev/null ||
        die "downloading the source from $NODUS_REPO failed — check the network."
    local new_commit old_commit=""
    new_commit=$(git -C "$src_dir" rev-parse FETCH_HEAD)
    [[ $new_commit =~ ^[0-9a-f]{40}$ ]] || die "could not read the downloaded commit ('$new_commit')."

    if [ "$mode" = "update" ] && [ -f "$COMMIT_FILE" ]; then
        old_commit=$(head -n 1 "$COMMIT_FILE")
        [[ $old_commit =~ ^[0-9a-f]{40}$ ]] || old_commit=""
        if [ "$old_commit" = "$new_commit" ] && [ "$opt_force" -eq 0 ]; then
            say "Already up to date ($new_commit). Nothing to do (use --force to rebuild anyway)."
            exit 0
        fi
    fi

    git -C "$src_dir" checkout -q --detach FETCH_HEAD </dev/null
    # The one clean allowed: inside this script's own source directory.
    git -C "$src_dir" clean -q -fdx </dev/null
    local head
    head=$(git -C "$src_dir" rev-parse HEAD)
    [ "$head" = "$new_commit" ] ||
        die "the checkout is at $head, not the downloaded $new_commit — stopping."
    say "Building commit $new_commit"

    # --- 4. build ------------------------------------------------------------
    local log="$src_dir/nodus-build.log"
    say "Building Nodus (this takes several minutes). Full log: $log"
    if ! { cmake -S "$src_dir/nodus" -B "$src_dir/nodus/build" -DCMAKE_BUILD_TYPE=Release &&
           cmake --build "$src_dir/nodus/build" -j "$(nproc)" \
               --target nodus-server nodus-core nodus-storage nodus-witness nodus-cli; \
         } >"$log" 2>&1 </dev/null; then
        printf '%s: the build FAILED. Last 40 lines of %s:\n' "$PROG" "$log" >&2
        tail -n 40 "$log" >&2
        exit 1
    fi
    say "Build finished."

    # --- 5. package ----------------------------------------------------------
    say "Packaging the build (nodus/deploy/make-dist.sh)..."
    local dist_dir="$src_dir/dist" dist_out tarball
    mkdir -p "$dist_dir"
    if ! dist_out=$(sh "$src_dir/nodus/deploy/make-dist.sh" "$src_dir/nodus/build" "$dist_dir" 2>&1 </dev/null); then
        printf '%s\n' "$dist_out" >>"$log"
        printf '%s\n' "$dist_out" >&2
        die "packaging failed (the message above is from make-dist.sh)."
    fi
    printf '%s\n' "$dist_out" >>"$log"
    tarball=$(sed -n 's/^make-dist: wrote //p' <<<"$dist_out")
    [ -n "$tarball" ] && [ -f "$tarball" ] || die "make-dist.sh did not report the package it wrote (see $log)."
    say "Package: $tarball"
    local dist_ver
    dist_ver=$(sed -n 's/^make-dist: \(version .*\)$/\1/p' <<<"$dist_out")
    [ -z "$dist_ver" ] || say "Package $dist_ver"

    if [ "$opt_build_only" -eq 1 ]; then
        say "--build-only: nothing was installed. The package is $tarball"
        exit 0
    fi

    local pkg_name extract_dir pkg_dir
    pkg_name=$(basename "$tarball" .tar.gz)
    extract_dir="$dist_dir/extract"
    mkdir -p "$extract_dir"
    tar -xzf "$tarball" -C "$extract_dir" </dev/null
    pkg_dir="$extract_dir/$pkg_name"
    [ -x "$pkg_dir/install.sh" ] || die "$pkg_dir/install.sh not found in the package."

    local identity_dir="$IDENTITY_DIR" new_conf=""
    if [ "$mode" = "install" ]; then
        # --- 6. public IP ----------------------------------------------------
        local suggested="" ip=""
        if command -v ip >/dev/null 2>&1; then
            suggested=$(ip -4 route get 1.1.1.1 2>/dev/null |
                        sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1 || true)
            valid_ipv4 "$suggested" || suggested=""
        fi
        if [ -n "$opt_ip" ]; then
            ip=$opt_ip
        elif [ "$opt_yes" -eq 1 ]; then
            [ -n "$suggested" ] ||
                die "could not find this server's address. Run again with --ip <public IPv4>."
            if private_ipv4 "$suggested"; then
                die "this server's own address is $suggested, a private address; its public address is probably different. Run again with --ip <public IPv4>."
            fi
            ip=$suggested
        else
            while :; do
                ip=$(ask "This server's public IPv4 address${suggested:+ [$suggested]}: ")
                [ -n "$ip" ] || ip=$suggested
                valid_ipv4 "$ip" && break
                printf '%s: "%s" is not an IPv4 address like 203.0.113.10 — try again.\n' "$PROG" "$ip" >/dev/tty
            done
        fi
        if private_ipv4 "$ip"; then
            warn "$ip is a private or local address. The witnesses must reach this node on TCP 4004 from the internet; with a private address they cannot, unless your router forwards it."
            if [ "$opt_yes" -eq 0 ]; then
                ask_yes_no "Continue with $ip anyway?" || die "stopped. Nothing was installed."
            fi
        fi
        say "Public address: $ip"

        # --- 7. configuration ------------------------------------------------
        if [ -e "$NETWORK_FILE" ]; then
            say "$NETWORK_FILE already exists — keeping it as it is."
        else
            say "Writing $NETWORK_FILE (the testnet chain id and the seven witnesses)..."
            local tmp i
            tmp=$(mktemp "$NETWORK_FILE.XXXXXX")
            {
                printf '{\n'
                printf '  "v2_genesis_pin": "%s",\n' "$GENESIS_PIN"
                printf '  "persistent_peers": [\n'
                for i in "${!PERSISTENT_PEERS[@]}"; do
                    if [ "$i" -lt $((${#PERSISTENT_PEERS[@]} - 1)) ]; then
                        printf '    "%s",\n' "${PERSISTENT_PEERS[$i]}"
                    else
                        printf '    "%s"\n' "${PERSISTENT_PEERS[$i]}"
                    fi
                done
                printf '  ]\n'
                printf '}\n'
            } >"$tmp"
            chmod 0644 "$tmp"
            mv "$tmp" "$NETWORK_FILE"
        fi
        # /etc/nodus.conf was checked absent above (else: update mode or
        # stop). The file is written next to the package and handed to
        # install.sh with --config: install.sh installs it as /etc/nodus.conf
        # (mode 0600) only after all of its own checks have passed, so a
        # refusal there leaves no /etc/nodus.conf behind to block a rerun.
        say "Preparing the node settings (installed as $ETC_CONF, only readable by root)..."
        new_conf="$dist_dir/nodus.conf"
        ( umask 077 && : >"$new_conf" )
        chmod 0600 "$new_conf"
        cat >"$new_conf" <<EOF
{
  "bind_ip": "0.0.0.0",
  "external_ip": "$ip",
  "udp_port": 4000,
  "tcp_port": 4001,
  "peer_port": 4002,
  "witness_port": 4004,
  "identity_path": "$IDENTITY_DIR",
  "data_path": "$DATA_DIR",
  "network_file": "$NETWORK_FILE"
}
EOF
        if [ ! -d "$VAR_DIR" ]; then
            install -d -m 0700 -o root -g root "$VAR_DIR"
        fi
    else
        identity_dir=$(conf_identity_path)
        [ -n "$identity_dir" ] || identity_dir="$IDENTITY_DIR"
    fi

    # --- 8. clock ------------------------------------------------------------
    local ntp=""
    if command -v timedatectl >/dev/null 2>&1; then
        ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    fi
    if [ "$ntp" = "yes" ]; then
        say "Clock: synchronized (NTP)."
    else
        warn "the clock is not shown as synchronized (NTP). A witness's question to this node carries a deadline 10 seconds ahead; a clock that is a few seconds off makes the node miss answers. Turn NTP on, for example: sudo timedatectl set-ntp true — then check that 'timedatectl' shows 'System clock synchronized: yes'."
    fi

    # --- 9. firewall (new installs only) ---------------------------------------
    if [ "$mode" = "install" ]; then
        local ufw_active=0
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
            ufw_active=1
        fi
        if [ "$ufw_active" -eq 1 ]; then
            if [ "$opt_open_fw" -eq 1 ]; then
                say "Firewall: allowing TCP 4004 in ufw..."
                ufw allow 4004/tcp </dev/null
            elif [ "$opt_yes" -eq 0 ] && ask_yes_no "The ufw firewall is on. Allow TCP 4004 (the port the witnesses use to reach this node)?"; then
                ufw allow 4004/tcp </dev/null
            else
                say "Firewall: left unchanged. TCP 4004 must be reachable from the internet: sudo ufw allow 4004/tcp"
            fi
        else
            say "Firewall: TCP 4004 must be reachable from the internet. If your provider has a firewall (a cloud security group, for example), open TCP 4004 there."
        fi
    fi

    # --- 10. install / update ------------------------------------------------
    local -a install_args=(--layout split)
    [ -z "$new_conf" ] || install_args+=(--config "$new_conf")
    [ "$want_storage" -eq 1 ] || install_args+=(--no-storage)
    [ "$want_witness" -eq 1 ] || install_args+=(--no-witness)
    say "Installing the node: $pkg_dir/install.sh ${install_args[*]}"
    if ! "$pkg_dir/install.sh" "${install_args[@]}" </dev/null; then
        die "install.sh stopped (its message is above). Nothing more was done."
    fi

    local tmpm
    tmpm=$(mktemp "$COMMIT_FILE.XXXXXX")
    printf '%s\n' "$new_commit" >"$tmpm"
    chmod 0644 "$tmpm"
    mv "$tmpm" "$COMMIT_FILE"

    # --- 11. the node's identity and state ----------------------------------
    # install.sh already waited for core to write the identity files; this
    # bounded wait only covers a slow file system (progress: the file).
    local n=0
    while [ ! -f "$identity_dir/nodus.pk" ] && [ "$n" -lt 30 ]; do
        sleep 2
        n=$((n + 1))
    done
    if [ -f "$identity_dir/nodus.pk" ]; then
        say "This node's identity:"
        nodus-cli -i "$identity_dir" whoami </dev/null || warn "nodus-cli whoami failed."
    else
        warn "$identity_dir/nodus.pk did not appear — see: journalctl -u nodus-core -n 50"
    fi
    say "Services:"
    for u in "${SPLIT_UNITS[@]}"; do
        if unit_enabled "$u"; then
            say "  $u: $(unit_state "$u")"
        fi
    done

    # --- 12. what next -------------------------------------------------------
    echo
    if [ "$mode" = "update" ]; then
        say "Update done: ${old_commit:-<not recorded>} -> $new_commit"
        say "The node keeps its key, its settings and its chain data."
        say "Its state on one screen: sudo nodus-cli status"
        say "Logs: journalctl -u nodus-witness -f"
        exit 0
    fi
    cat <<EOF
The Nodus node is installed (commit $new_commit).

It now downloads the whole chain. This takes a while. To watch it:
  sudo nodus-cli status
It shows the whole node on one screen; under "Chain", "behind by" is how
many blocks it still lacks against the network (OK at 2 or less).
Or compare the first line of
  nodus-cli -s 127.0.0.1 ruleset-info     (tip=<height>)
with the latest block on https://scan.nodusnetwork.io

When the two are close, register the node:
  1. Open https://connect.nodusnetwork.io with the wallet that will own it.
  2. Go to More -> Nodus -> "Become a storage node" (bond 1,000,000 NODUS)
     or "Become a witness" (bond 2,000,000 NODUS or more).
  3. Run the one command it shows on THIS machine, and paste the answer
     back into the page.

Do not turn on pruning yet:
  https://wiki.nodusnetwork.io/network.html#storage-node

Back up $identity_dir — it is this node's identity; a lost key
cannot be replaced.

Logs: journalctl -u nodus-witness -f
EOF
}

main "$@"
