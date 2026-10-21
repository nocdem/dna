#!/usr/bin/env bash
# build.sh — compile the Nodus security contract library (src/) and its test mocks
# (test/mocks/) with the pinned Nodus solc.
#
# What it does: compiles every *.sol under src/ and test/mocks/ together in two
#   configurations, both with --evm-version prague passed explicitly:
#   default    no optimizer — what `nodus-cli evm deploy --solc` runs (`solc --bin <file>`,
#              nodus/tools/nodus-cli.c evm_solc), plus the explicit EVM version
#   optimize   --optimize (optimizer runs = 200, the default)
#   and writes, per contract with code, <out>/<config>/<Contract>.creation.hex (--bin),
#   <out>/<config>/<Contract>.runtime.hex (--bin-runtime), <out>/<Contract>.abi.json (--abi;
#   the ABI does not depend on the configuration — the script refuses if the two differ),
#   plus <out>/VERSION.txt (the compiler version line, the source list and the exact flags).
#   Abstract contracts (Ownable, AccessControl, ReentrancyGuard, Pausable) have no code of
#   their own; they are exercised through the mocks. <out> is out/ (COMMITTED:
#   shared/evm/tests/test_contract_lib.c executes it and needs no solc), or OUT_DIR when set
#   (verify.sh uses that to rebuild into a temporary directory with the same flags).
# What it requires: SOLC=<path to the Nodus solc> (or the first argument). Its --version
#   must end with EXACTLY the pinned line
#       Version: 0.8.30+nodus.addr256.commit.73712a01.Linux.g++
#   or the script refuses (exit 2).
# What it leaves behind: <out> rewritten (the whole tree is regenerated); nothing else.
# Reproducibility: the script runs from this directory and passes every source by its path
#   relative to it (src/…, test/mocks/…), so the CBOR metadata (which hashes each source and
#   its unit name) does not depend on where the tree is checked out; relative imports resolve
#   against those unit names. Any compiler diagnostic (warning or error) fails the build.
set -euo pipefail

PINNED_VERSION="Version: 0.8.30+nodus.addr256.commit.73712a01.Linux.g++"

SOLC="${1:-${SOLC:-}}"
if [ -z "$SOLC" ] || [ ! -x "$SOLC" ]; then
	echo "usage: SOLC=/path/to/solc $0   (or: $0 /path/to/solc)" >&2
	exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
OUT="${OUT_DIR:-$HERE/out}"

VERSION_LINE="$("$SOLC" --version | tail -n 1)"
if [ "$VERSION_LINE" != "$PINNED_VERSION" ]; then
	echo "refusing: '$VERSION_LINE' is not the pinned compiler '$PINNED_VERSION'" >&2
	exit 2
fi

CONFIGS=(default optimize)
flags_of() {
	case "$1" in
		default)  echo "--evm-version prague" ;;
		optimize) echo "--evm-version prague --optimize" ;;
	esac
}

SOURCES=()
while IFS= read -r f; do SOURCES+=("$f"); done < <(find src test/mocks -name '*.sol' | LC_ALL=C sort)
if [ "${#SOURCES[@]}" -eq 0 ]; then
	echo "no sources found under src/ and test/mocks/" >&2
	exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rm -rf "$OUT"
mkdir -p "$OUT"
{
	echo "$VERSION_LINE"
	echo "sources: ${SOURCES[*]}"
	for c in "${CONFIGS[@]}"; do
		echo "$c: $(flags_of "$c") --bin --bin-runtime --abi"
	done
} > "$OUT/VERSION.txt"

for c in "${CONFIGS[@]}"; do
	mkdir -p "$OUT/$c" "$TMP/$c"
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
			continue    # abstract contracts have no code
		fi
		cp "$bin" "$OUT/$c/$name.creation.hex"
		cp "$TMP/$c/$name.bin-runtime" "$OUT/$c/$name.runtime.hex"
		if [ "$c" = "default" ]; then
			cp "$TMP/$c/$name.abi" "$OUT/$name.abi.json"
		elif ! cmp -s "$TMP/$c/$name.abi" "$OUT/$name.abi.json"; then
			echo "the ABI of $name differs between configurations" >&2
			exit 1
		fi
	done
	echo "$c: $(ls "$OUT/$c" | wc -l) files"
done
echo "compiler: $VERSION_LINE"
