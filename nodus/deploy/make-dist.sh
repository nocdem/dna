#!/bin/sh
# make-dist.sh — build the `nodus` installer tarball from an EXISTING build
# directory (component split S7).
#
# Decision docs/plans/decisions/2026-10-01-nodus-component-split.md item 26:
# the installer artefact is a tar.gz (binaries + install script); a .deb is
# later work. Item 8: the combined nodus-server ships beside the three
# split binaries (rollback path). Where the tarball is published and how
# it is signed is OPEN in that decision ("Açık kalanlar") — this script
# only produces the file and its SHA-256.
#
# Usage:
#   nodus/deploy/make-dist.sh <build-dir> [<out-dir>]
#
# Produces <out-dir>/nodus-<NODUS_VERSION_STRING>-linux-<uname -m>.tar.gz
# (out-dir defaults to the current directory) holding one top-level
# directory of the same name with:
#   nodus-server nodus-core nodus-storage nodus-witness nodus-cli
#   nodus.service nodus-core.service nodus-storage.service
#   nodus-witness.service install.sh README VERSION SHA256SUMS
#
# Refuses (nothing written) when: a binary is missing or not executable;
# the version in nodus/include/nodus/nodus_types.h is malformed or its
# MAJOR/MINOR/PATCH disagree with NODUS_VERSION_STRING; any binary's `-h`
# banner carries a version other than that one (a stale build directory);
# the build was made with a sanitizer; the build directory's
# CMAKE_BUILD_TYPE is not exactly Release (empty = unoptimized); the git
# tree has uncommitted or untracked changes under nodus/ or shared/ (both
# are compiled into the binaries); git cannot be asked at all (git missing,
# not a checkout — the source's provenance cannot be verified); the output
# file already exists.
#
# Staged files get explicit modes — 0755 for the directory, the binaries
# and install.sh, 0644 for everything else — whatever the umask.
#
# Every payload file is named explicitly — nothing is globbed from
# nodus/deploy/, so a local (gitignored) nodus.conf.example, an identity or
# any other file there can never enter the tarball.
#
# The only binaries this script executes are the five payload binaries,
# each with `-h` (they print their banner and exit before any init).

set -eu

PROG="make-dist"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
NODUS_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
TYPES_H="$NODUS_DIR/include/nodus/nodus_types.h"

BINARIES="nodus-server nodus-core nodus-storage nodus-witness nodus-cli"
UNITS="nodus.service nodus-core.service nodus-storage.service nodus-witness.service"

die() {
    echo "$PROG: $*" >&2
    exit 1
}

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <build-dir> [<out-dir>]" >&2
    exit 1
fi
[ -d "$1" ] || die "build directory $1 does not exist"
BUILD_DIR=$(cd "$1" && pwd)
OUT_DIR=${2:-.}
[ -d "$OUT_DIR" ] || die "output directory $OUT_DIR does not exist"
OUT_DIR=$(cd "$OUT_DIR" && pwd)

# --- version: read from the header, never typed by hand -----------------
[ -f "$TYPES_H" ] || die "$TYPES_H not found"
hdr_define() {
    sed -n "s/^#define $1[[:space:]][[:space:]]*\\(.*[^[:space:]]\\)[[:space:]]*\$/\\1/p" "$TYPES_H"
}
VER=$(hdr_define NODUS_VERSION_STRING | tr -d '"')
V_MAJ=$(hdr_define NODUS_VERSION_MAJOR)
V_MIN=$(hdr_define NODUS_VERSION_MINOR)
V_PAT=$(hdr_define NODUS_VERSION_PATCH)
[ "$(printf '%s\n' "$VER" | grep -c '^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$')" = 1 ] ||
    die "NODUS_VERSION_STRING in $TYPES_H is not of the form X.Y.Z: '$VER'"
[ "$V_MAJ.$V_MIN.$V_PAT" = "$VER" ] ||
    die "$TYPES_H disagrees with itself: MAJOR.MINOR.PATCH = $V_MAJ.$V_MIN.$V_PAT, NODUS_VERSION_STRING = $VER"

ARCH=$(uname -m)
NAME="nodus-$VER-linux-$ARCH"
TARBALL="$OUT_DIR/$NAME.tar.gz"
[ ! -e "$TARBALL" ] || die "$TARBALL already exists — remove it first (a published artefact is never replaced in place)"

# --- the build: no sanitizer builds in an installer ---------------------
CACHE="$BUILD_DIR/CMakeCache.txt"
[ -f "$CACHE" ] || die "$CACHE not found — $BUILD_DIR is not a configured CMake build directory"
if grep -q -- '-fsanitize' "$CACHE"; then
    die "$CACHE carries -fsanitize — a sanitizer (debug) build is not packaged"
fi
BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:[A-Z]*=//p' "$CACHE")
[ "$BUILD_TYPE" = Release ] ||
    die "$CACHE has CMAKE_BUILD_TYPE='$BUILD_TYPE' — only a Release build is packaged (configure with -DCMAKE_BUILD_TYPE=Release)"

# --- the binaries: all five from this one build dir, one version --------
for b in $BINARIES; do
    [ -f "$BUILD_DIR/$b" ] && [ -x "$BUILD_DIR/$b" ] ||
        die "$BUILD_DIR/$b is missing or not executable — build all of: $BINARIES"
done
for b in $BINARIES; do
    # usage() prints "<Title> v<version>" to stderr as its first line and
    # the option list after it; -h returns 0, but the exit code is not
    # relied on — only the banner's version token is compared.
    banner=$("$BUILD_DIR/$b" -h 2>&1 | head -n 1 || true)
    bver=$(printf '%s\n' "$banner" | sed -n 's/^.* v\([0-9][0-9.]*\)$/\1/p')
    [ -n "$bver" ] || die "$BUILD_DIR/$b -h printed no version banner (got: '$banner')"
    [ "$bver" = "$VER" ] ||
        die "$BUILD_DIR/$b reports v$bver, the source tree is $VER — rebuild $BUILD_DIR before packaging"
    echo "$PROG: $b: $banner"
done

for u in $UNITS install.sh README-dist.md; do
    [ -f "$SCRIPT_DIR/$u" ] || die "$SCRIPT_DIR/$u not found"
done

# --- provenance for VERSION ---------------------------------------------
# nodus/ and shared/ are both compiled into the binaries: a change in
# either, committed or not, must be in the commit VERSION names.
# When git cannot be asked, neither the commit nor a clean tree can be
# verified: refuse rather than ship a tarball of unknown source.
NOPROV="— refusing: without the commit and the clean-tree check the tarball's provenance (which source the binaries were built from) cannot be verified"
REPO=$(git -C "$NODUS_DIR" rev-parse --show-toplevel 2>/dev/null) ||
    die "git cannot be asked about $NODUS_DIR (git missing, or not a git checkout) $NOPROV"
COMMIT=$(git -C "$REPO" rev-parse HEAD 2>/dev/null) ||
    die "git rev-parse HEAD failed in $REPO $NOPROV"
STATUS=$(git -C "$REPO" status --porcelain -- nodus shared 2>/dev/null) ||
    die "git status failed in $REPO $NOPROV"
[ -z "$STATUS" ] ||
    die "uncommitted or untracked changes under nodus/ or shared/ in $REPO — commit or remove them first; VERSION must name the source the binaries were built from:
$STATUS"
TREE="clean"
MTIME=$(git -C "$REPO" log -1 --format=%ct 2>/dev/null) ||
    die "git log failed in $REPO (the archive's mtime is the last commit's) $NOPROV"

# --- stage ---------------------------------------------------------------
STAGE_ROOT=$(mktemp -d)
TMP_TAR=""
trap 'rm -rf "$STAGE_ROOT"; [ -z "$TMP_TAR" ] || rm -f "$TMP_TAR"' EXIT
STAGE="$STAGE_ROOT/$NAME"
mkdir "$STAGE"
chmod 0755 "$STAGE"

for b in $BINARIES; do
    install -m 0755 "$BUILD_DIR/$b" "$STAGE/$b"
done
for u in $UNITS; do
    install -m 0644 "$SCRIPT_DIR/$u" "$STAGE/$u"
done
install -m 0755 "$SCRIPT_DIR/install.sh" "$STAGE/install.sh"
install -m 0644 "$SCRIPT_DIR/README-dist.md" "$STAGE/README"
{
    echo "nodus $VER"
    echo "arch $ARCH"
    echo "commit $COMMIT"
    echo "tree $TREE"
    echo "build_type ${BUILD_TYPE:-<unset>}"
} > "$STAGE/VERSION"
chmod 0644 "$STAGE/VERSION"

PAYLOAD="$BINARIES $UNITS install.sh README VERSION"
# shellcheck disable=SC2086
(cd "$STAGE" && sha256sum $PAYLOAD > SHA256SUMS)
chmod 0644 "$STAGE/SHA256SUMS"

# Deterministic archive: sorted names, numeric root owner, one mtime (the
# last commit's), gzip without a timestamp.
# The temporary file is made by mktemp in the output directory (same
# filesystem, so the final mv is a rename); mktemp creates it 0600.
TMP_TAR=$(mktemp "$OUT_DIR/.$NAME.tar.gz.XXXXXX")
tar -C "$STAGE_ROOT" --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@$MTIME" -cf - "$NAME" | gzip -n -9 > "$TMP_TAR"
chmod 0644 "$TMP_TAR"
mv -f "$TMP_TAR" "$TARBALL"
TMP_TAR=""

echo "$PROG: wrote $TARBALL"
echo "$PROG: version $VER, commit $COMMIT, tree $TREE"
(cd "$OUT_DIR" && sha256sum "$NAME.tar.gz")
