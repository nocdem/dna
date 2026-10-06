#!/usr/bin/env bash
# package.sh — package a built Nodus solc (32-byte addresses) for download.
#
# Governing record: docs/plans/decisions/2026-10-06-evm-dev-tooling.md item 1 — the
# Nodus solc is distributed as a ready binary from our own site (Linux x86-64), with its
# sha256 and a build-it-yourself recipe (build.sh in this directory).
#
# Usage:  ./package.sh <solc-binary> <solidity-source-root> <out-dir>
#   solc-binary           the built compiler (build.sh: $WORK_DIR/solidity/build/solc/solc)
#   solidity-source-root  the solidity checkout it was built from ($WORK_DIR/solidity): it
#                         must be upstream commit SOLC_COMMIT with exactly
#                         0001-nodus-address-256.patch applied, and hold LICENSE.txt
#   out-dir               where the archive and its .sha256 go (created if missing)
#
# Output (in out-dir):
#   nodus-solc-0.8.30-nodus.addr256-linux-x86_64.tar.gz, with one top-level directory of
#   the same name holding
#     solc-nodus         the binary (the name nodus-cli looks for: /usr/local/bin/solc-nodus)
#     README.md          what it is, install, verify, the measured glibc / libstdc++ floor
#     NOTICE             GPL-3.0 notice + the source offer (upstream commit, our patch, build.sh)
#     LICENSE.txt        upstream's GPL-3.0 text (copied from the source root)
#     LICENSES-solc.txt  `solc --license` (GPL-3.0 + the bundled dependencies' notices)
#   nodus-solc-0.8.30-nodus.addr256-linux-x86_64.tar.gz.sha256   (`sha256sum -c` format)
#
# Refuses (exit 2) when: `solc --version` lacks "nodus.addr256" or the commit 73712a01; the
# binary is not ELF x86-64; the source root is not the pinned commit, or its working-tree
# diff is not exactly the committed patch (git patch-id); LICENSE.txt is missing.
#
# Reproducible: file order, owner, modes and mtime (the upstream commit time) are fixed and
# gzip stores no name/time, so the same binary packages to the same sha256.
# What it leaves behind: the two files in out-dir (overwritten); nothing else.
set -euo pipefail

SOLC_COMMIT="73712a01b2de56d9ad91e3b6936f85c90cb7de36"
SOLC_SHORT="${SOLC_COMMIT:0:8}"
NAME="nodus-solc-0.8.30-nodus.addr256-linux-x86_64"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$HERE/0001-nodus-address-256.patch"

if [ $# -ne 3 ]; then
	echo "usage: $0 <solc-binary> <solidity-source-root> <out-dir>" >&2
	exit 2
fi
SOLC="$1"
SRC="$2"
OUT="$3"

refuse() { echo "refusing: $*" >&2; exit 2; }

[ -x "$SOLC" ] || refuse "$SOLC is not an executable"
[ -f "$PATCH" ] || refuse "missing $PATCH"

VERSION_LINE="$("$SOLC" --version | tail -n 1)"
case "$VERSION_LINE" in
	*nodus.addr256*) ;;
	*) refuse "'$VERSION_LINE' is not the Nodus 32-byte-address solc (no nodus.addr256)" ;;
esac
case "$VERSION_LINE" in
	*"commit.$SOLC_SHORT"*) ;;
	*) refuse "'$VERSION_LINE' does not name the pinned upstream commit $SOLC_SHORT" ;;
esac

case "$(objdump -f "$SOLC")" in
	*"file format elf64-x86-64"*) ;;
	*) refuse "$SOLC is not ELF x86-64" ;;
esac

# The source offer must be true: the root is the pinned commit plus exactly our patch.
[ -f "$SRC/LICENSE.txt" ] || refuse "no LICENSE.txt in $SRC"
head="$(git -C "$SRC" rev-parse HEAD)" || refuse "$SRC is not a git checkout"
[ "$head" = "$SOLC_COMMIT" ] || refuse "$SRC is at $head, not $SOLC_COMMIT"
tree_id="$(git -C "$SRC" diff | git patch-id --stable | cut -d' ' -f1)"
patch_id="$(git patch-id --stable < "$PATCH" | cut -d' ' -f1)"
[ -n "$patch_id" ] && [ "$tree_id" = "$patch_id" ] ||
	refuse "the working tree of $SRC is not exactly $PATCH applied (patch-id $tree_id vs $patch_id)"

# Measured run-time floor (the highest versioned symbol the binary imports).
max_ver() { objdump -T "$SOLC" | grep -o "$1[0-9.]*" | sort -uV | tail -n 1; }
GLIBC_MAX="$(max_ver 'GLIBC_')"
GLIBCXX_MAX="$(max_ver 'GLIBCXX_')"
CXXABI_MAX="$(max_ver 'CXXABI_')"
NEEDED="$(objdump -p "$SOLC" | awk '/NEEDED/ { print $2 }' | sort | paste -sd' ' -)"
[ -n "$GLIBC_MAX" ] || refuse "could not read the GLIBC symbol versions of $SOLC"
BIN_SHA="$(sha256sum "$SOLC" | cut -d' ' -f1)"
MTIME="$(git -C "$SRC" log -1 --format=%ct "$SOLC_COMMIT")"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/$NAME"
mkdir -p "$PKG"
cp "$SOLC" "$PKG/solc-nodus"
cp "$SRC/LICENSE.txt" "$PKG/LICENSE.txt"
"$SOLC" --license > "$PKG/LICENSES-solc.txt"

cat > "$PKG/NOTICE" <<EOF
solc-nodus — the Solidity compiler with 32-byte addresses, for the Nodus EVM.

This program is a modified version of the Solidity compiler (solc), Copyright the
Solidity contributors, licensed under the GNU General Public License version 3
(LICENSE.txt). It is distributed WITHOUT ANY WARRANTY; see LICENSE.txt. The licences
of the parts and dependencies built into it are printed by \`solc-nodus --license\`
(copied in LICENSES-solc.txt).

Modification: the Solidity "address" type is 256 bits wide (no 160-bit masking;
conversions that would truncate an address are compile errors). Version string:
$VERSION_LINE

Corresponding source:
  - upstream: https://github.com/ethereum/solidity, tag v0.8.30,
    commit $SOLC_COMMIT
  - our change: nodus/tools/evm/solc/0001-nodus-address-256.patch
  - the build recipe: nodus/tools/evm/solc/build.sh (clones the commit above,
    verifies it, applies the patch, builds the solc target)
  both in the Nodus source repository, https://github.com/nocdem/dna
EOF

cat > "$PKG/README.md" <<EOF
# Nodus solc — Solidity 0.8.30 with 32-byte addresses

\`solc-nodus\` compiles Solidity for the **Nodus EVM**, whose addresses are 32 bytes.
A stock solc truncates every address to 20 bytes, which on Nodus silently turns one
account into another — use this compiler for Nodus contracts.

    $VERSION_LINE

Linux x86-64 only. sha256 of \`solc-nodus\`: \`$BIN_SHA\`

## Requirements (measured from the binary)

- glibc **${GLIBC_MAX#GLIBC_}** or newer (highest symbol version imported: \`$GLIBC_MAX\`)
- a libstdc++ that provides \`$GLIBCXX_MAX\` and \`$CXXABI_MAX\`
- shared libraries it loads: $NEEDED (Boost is linked in statically)

A system whose glibc is older fails at start with "version \`$GLIBC_MAX' not found";
build the compiler yourself there (below).

## Install

    install -m 0755 solc-nodus /usr/local/bin/solc-nodus
    solc-nodus --version            # must print "nodus.addr256"

\`nodus-cli evm deploy --solc <file.sol>:<Contract>\` runs \`/usr/local/bin/solc-nodus\` by
default; elsewhere set \`NODUS_SOLC=/path/to/solc-nodus\` or pass \`--solc-bin <path>\`.

## What is different from stock solc

- \`address\` is 256 bits everywhere: ABI words, storage (a whole slot, never packed),
  \`abi.encodePacked(address)\` is 32 bytes.
- Conversions between \`address\` and \`uint160\` / \`bytes20\` are compile errors; use
  \`uint256\` / \`bytes32\`.
- Address literals are 64 hex digits with a 64-digit EIP-55-style checksum.
- External function types cannot be stored or ABI-encoded; linked (external/public)
  library calls are refused.
- \`ecrecover\` returns a 20-byte Ethereum address padded to 32 bytes: never use it to
  authorize Nodus accounts.

Full rules: \`nodus/tools/evm/solc/README.md\` in the source repository.

## Build it yourself

    git clone https://github.com/nocdem/dna && cd dna/nodus/tools/evm/solc
    JOBS=4 ./build.sh /path/to/work
    # result: /path/to/work/solidity/build/solc/solc

## Licence

GPL-3.0 (LICENSE.txt); source offer in NOTICE.
EOF

chmod 0755 "$PKG/solc-nodus"
chmod 0644 "$PKG/README.md" "$PKG/NOTICE" "$PKG/LICENSE.txt" "$PKG/LICENSES-solc.txt"
chmod 0755 "$PKG"

mkdir -p "$OUT"
ARCHIVE="$OUT/$NAME.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$MTIME" \
	--format=gnu -C "$STAGE" -cf - "$NAME" | gzip -n -9 > "$ARCHIVE"
(cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")

echo "package: $ARCHIVE"
echo "sha256:  $(cut -d' ' -f1 "$ARCHIVE.sha256")"
echo "binary:  $BIN_SHA"
echo "floor:   $GLIBC_MAX, $GLIBCXX_MAX, $CXXABI_MAX; needs $NEEDED"
