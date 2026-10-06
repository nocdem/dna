#!/usr/bin/env bash
# build.sh — compile the execution-evidence contracts in four configurations.
#
# What it does: compiles every *.sol in this directory with the patched solc (../../build.sh) in
#   legacy           --evm-version prague
#   legacy-opt       --evm-version prague --optimize            (optimizer runs = 200, the default)
#   viair            --evm-version prague --via-ir
#   viair-opt        --evm-version prague --via-ir --optimize   (runs = 200)
#   and writes, per contract, out/<config>/<Contract>.creation.hex (the --bin output) and
#   out/<config>/<Contract>.runtime.hex (the --bin-runtime output), plus out/VERSION.txt (the
#   compiler version line and the exact flags). The outputs are COMMITTED: the C test
#   shared/evm/tests/test_solc_exec.c executes them and needs no solc.
# What it requires: SOLC=<path to the patched solc> (or the first argument). Its --version must
#   carry the nodus.addr256 tag, or the script refuses.
# What it leaves behind: out/ rewritten (the whole tree is regenerated); nothing else.
# Reproducibility: sources are passed as basenames from this directory, so the CBOR metadata
#   (which hashes the source and its path) does not depend on where the tree is checked out.
#   Measured: two runs on one host give a byte-identical out/ tree (diff -r); identity across
#   machines is expected for the same compiler binary but has not been measured.
#   Any compiler diagnostic (warning or error) fails the build.
set -euo pipefail

SOLC="${1:-${SOLC:-}}"
if [ -z "$SOLC" ] || [ ! -x "$SOLC" ]; then
	echo "usage: SOLC=/path/to/solc $0   (or: $0 /path/to/solc)" >&2
	exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VERSION_LINE="$("$SOLC" --version | tail -n 1)"
case "$VERSION_LINE" in
	*nodus.addr256*) ;;
	*) echo "refusing: '$VERSION_LINE' is not the Nodus 32-byte-address solc" >&2; exit 2 ;;
esac

CONFIGS=(legacy legacy-opt viair viair-opt)
flags_of() {
	case "$1" in
		legacy)     echo "--evm-version prague" ;;
		legacy-opt) echo "--evm-version prague --optimize" ;;
		viair)      echo "--evm-version prague --via-ir" ;;
		viair-opt)  echo "--evm-version prague --via-ir --optimize" ;;
	esac
}

SOURCES=()
for f in *.sol; do SOURCES+=("$f"); done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rm -rf out
mkdir -p out
{
	echo "$VERSION_LINE"
	echo "sources: ${SOURCES[*]}"
	for c in "${CONFIGS[@]}"; do
		echo "$c: $(flags_of "$c") --bin --bin-runtime"
	done
} > out/VERSION.txt

for c in "${CONFIGS[@]}"; do
	mkdir -p "out/$c" "$TMP/$c"
	# shellcheck disable=SC2046
	"$SOLC" $(flags_of "$c") --bin --bin-runtime -o "$TMP/$c" "${SOURCES[@]}" \
		2> "$TMP/$c.err"
	if [ -s "$TMP/$c.err" ]; then
		echo "solc printed diagnostics for config $c:" >&2
		cat "$TMP/$c.err" >&2
		exit 1
	fi
	for bin in "$TMP/$c"/*.bin; do
		name="$(basename "$bin" .bin)"
		if [ ! -s "$bin" ]; then
			continue    # interfaces / abstract contracts have no code
		fi
		cp "$bin" "out/$c/$name.creation.hex"
		cp "$TMP/$c/$name.bin-runtime" "out/$c/$name.runtime.hex"
	done
	echo "$c: $(ls "out/$c" | wc -l) files"
done
echo "compiler: $VERSION_LINE"
