#!/usr/bin/env bash
# build.sh — compile the Nodus EVM example contracts with the Nodus solc.
#
# What it does: compiles every *.sol in this directory in two configurations
#   default    no flags at all — exactly what `nodus-cli evm deploy --solc <file>:<C>`
#              runs (`solc --bin <file>`, nodus/tools/nodus-cli.c evm_solc): legacy
#              pipeline, optimizer off, the compiler's default EVM version (prague,
#              nodus/tools/evm/solc/README.md "Version string")
#   optimize   --optimize (optimizer runs = 200, the default)
#   and writes, per contract with code, out/<config>/<Contract>.creation.hex (--bin),
#   out/<config>/<Contract>.runtime.hex (--bin-runtime), out/<Contract>.abi.json (--abi;
#   the ABI does not depend on the configuration — the script refuses if the two differ),
#   plus out/VERSION.txt (the compiler version line and the exact flags). The outputs
#   are COMMITTED: shared/evm/tests/test_example_token.c executes them and needs no solc.
# What it requires: SOLC=<path to the Nodus solc> (or the first argument). Its --version
#   must carry the nodus.addr256 tag, or the script refuses.
# What it leaves behind: out/ rewritten (the whole tree is regenerated); nothing else.
# Reproducibility: sources are passed as basenames from this directory, so the CBOR
#   metadata (which hashes the source and its unit name) does not depend on where the
#   tree is checked out. A deployment through `nodus-cli evm deploy --solc` passes the
#   path the user typed, so its metadata tail can differ from out/default; the code
#   before the metadata is the same. Any compiler diagnostic (warning or error) fails
#   the build.
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

CONFIGS=(default optimize)
flags_of() {
	case "$1" in
		default)  echo "" ;;
		optimize) echo "--optimize" ;;
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
		f="$(flags_of "$c")"
		echo "$c: ${f:+$f }--bin --bin-runtime --abi"
	done
} > out/VERSION.txt

for c in "${CONFIGS[@]}"; do
	mkdir -p "out/$c" "$TMP/$c"
	# shellcheck disable=SC2046
	"$SOLC" $(flags_of "$c") --bin --bin-runtime --abi -o "$TMP/$c" "${SOURCES[@]}" \
		> "$TMP/$c.out" 2> "$TMP/$c.err"
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
		if [ "$c" = "default" ]; then
			cp "$TMP/$c/$name.abi" "out/$name.abi.json"
		elif ! cmp -s "$TMP/$c/$name.abi" "out/$name.abi.json"; then
			echo "the ABI of $name differs between configurations" >&2
			exit 1
		fi
	done
	echo "$c: $(ls "out/$c" | wc -l) files"
done
echo "compiler: $VERSION_LINE"
