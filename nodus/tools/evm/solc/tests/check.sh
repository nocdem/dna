#!/usr/bin/env bash
# check.sh — output checks for the Nodus EVM solc variant (32-byte addresses).
#
# What it proves: the patched compiler's OUTPUT (bytecode, IR, storage layout, ABI, diagnostics)
#   follows the rules in ../README.md. Nothing is executed on an EVM.
# What it requires: a solc built by ../build.sh, passed as SOLC=<path> or as the first argument;
#   python3 (JSON parsing). No network, no compile flags.
# What it leaves behind: nothing (scratch output goes to a mktemp dir that is removed on exit).
# How it can lie:
#   - the bytecode mask check greps hex for the three known encodings of the 160-bit mask
#     (PUSH20 0xff..ff, the optimizer's "PUSH1 1 PUSH1 1 PUSH1 0xa0 SHL SUB", and a 96-bit
#     SHL/SHR pair). Another encoding of the same mask would not be caught; the IR check
#     (no cleanup_t_uint160 / no 40-f literal in the Yul) covers the --via-ir path independently.
#   - a hex match inside an unrelated PUSH immediate would be a false FAILURE, never a false pass.
#   - error checks only assert that compilation fails AND the expected text appears.
set -u

SOLC="${1:-${SOLC:-}}"
if [ -z "$SOLC" ] || [ ! -x "$SOLC" ]; then
	echo "usage: SOLC=/path/to/solc $0   (or: $0 /path/to/solc)" >&2
	exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok()   { echo "PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $*"; fail=$((fail + 1)); }

echo "solc: $("$SOLC" --version | tail -n 1)"
case "$("$SOLC" --version)" in
	*nodus.addr256*) ok "version string carries the nodus.addr256 tag" ;;
	*) bad "version string lacks the nodus.addr256 tag" ;;
esac

OK_SOL="$HERE/ok_address.sol"

# 1. ok_address.sol compiles in every pipeline, and no 160-bit address mask survives.
check_no_mask() {
	local label="$1"; shift
	local out="$TMP/bin_$label.txt"
	if ! "$SOLC" --no-cbor-metadata --bin-runtime "$@" "$OK_SOL" > "$out" 2> "$TMP/err_$label.txt"; then
		bad "$label: ok_address.sol failed to compile"
		cat "$TMP/err_$label.txt"
		return
	fi
	# Runtime code of AddressOps only (the hex line after its header).
	local hex
	hex="$(awk '/^======= .*:AddressOps =======/{f=1;next} f&&/^[0-9a-f]+$/{print;exit}' "$out")"
	if [ -z "$hex" ]; then
		bad "$label: no runtime bytecode for AddressOps"
		return
	fi
	local found=""
	case "$hex" in *73ffffffffffffffffffffffffffffffffffffffff*) found="PUSH20 0xff..ff" ;; esac
	case "$hex" in *6001600160a01b03*) found="$found PUSH1 1 PUSH1 1 PUSH1 0xa0 SHL SUB" ;; esac
	case "$hex" in *60601b60601c*|*60601c60601b*) found="$found SHL/SHR 96 pair" ;; esac
	if [ -z "$found" ]; then
		ok "$label: no 160-bit address mask in AddressOps runtime bytecode"
	else
		bad "$label: 160-bit address mask found: $found"
	fi
}
check_no_mask legacy
check_no_mask legacy-opt --optimize
check_no_mask viair --via-ir
check_no_mask viair-opt --via-ir --optimize

# 2. The Yul IR has no 160-bit cleanup at all.
if "$SOLC" --ir "$OK_SOL" > "$TMP/ir.txt" 2> "$TMP/ir_err.txt"; then
	if grep -q "cleanup_t_uint160" "$TMP/ir.txt" || grep -Eq "0x[fF]{40}([^0-9a-fA-F]|$)" "$TMP/ir.txt"; then
		bad "IR contains a 160-bit cleanup (cleanup_t_uint160 or a 40-digit 0xff..ff literal)"
	else
		ok "IR contains no 160-bit cleanup"
	fi
else
	bad "--ir failed"; cat "$TMP/ir_err.txt"
fi

# 3. Library deploy-time self address is PUSH32 00..00 at offset 0 (legacy codegen).
"$SOLC" --no-cbor-metadata --bin-runtime "$OK_SOL" > "$TMP/lib.txt" 2>/dev/null
libhex="$(awk '/^======= .*:SelfAddressLib =======/{f=1;next} f&&/^[0-9a-f]+$/{print;exit}' "$TMP/lib.txt")"
case "$libhex" in
	7f0000000000000000000000000000000000000000000000000000000000000000*) ok "library runtime starts with PUSH32 00..00 (deploy-time address slot)" ;;
	*) bad "library runtime does not start with PUSH32 00..00: ${libhex:0:80}" ;;
esac

# 4. Storage layout: addresses take whole slots.
if "$SOLC" --storage-layout "$OK_SOL" > "$TMP/layout.txt" 2> "$TMP/layout_err.txt"; then
	python3 - "$TMP/layout.txt" <<'PY' && ok "storage layout: owner/peer are 32-byte slots, never packed" || bad "storage layout check"
import json, sys
text = open(sys.argv[1]).read()
blocks = text.split("=======")
layout = None
for i, b in enumerate(blocks):
    if b.strip().endswith(":AddressOps"):
        body = blocks[i + 1]
        layout = json.loads(body[body.index("{"):])
        break
assert layout is not None, "no layout for AddressOps"
want = {"small": ("0", 0), "owner": ("1", 0), "small2": ("2", 0), "peer": ("3", 0)}
for s in layout["storage"]:
    if s["label"] in want:
        slot, off = want[s["label"]]
        assert s["slot"] == slot and s["offset"] == off, (s["label"], s["slot"], s["offset"])
for name, t in layout["types"].items():
    if name.startswith("t_address") or name.startswith("t_contract"):
        assert t["numberOfBytes"] == "32", (name, t["numberOfBytes"])
print("  layout:", [(s["label"], s["slot"], s["offset"]) for s in layout["storage"]])
PY
else
	bad "--storage-layout failed"; cat "$TMP/layout_err.txt"
fi

# 5. ABI JSON still says "address".
if "$SOLC" --abi "$OK_SOL" > "$TMP/abi.txt" 2> "$TMP/abi_err.txt"; then
	python3 - "$TMP/abi.txt" <<'PY' && ok "ABI JSON types addresses as \"address\"" || bad "ABI JSON check"
import json, sys
text = open(sys.argv[1]).read()
blocks = text.split("=======")
abi = None
for i, b in enumerate(blocks):
    if b.strip().endswith(":AddressOps"):
        body = blocks[i + 1]
        abi = json.loads(body[body.index("["):])
        break
assert abi is not None
store = [e for e in abi if e.get("name") == "store"][0]
assert store["inputs"][0]["type"] == "address", store
fixed = [e for e in abi if e.get("name") == "fixedAddr"][0]
assert fixed["outputs"][0]["type"] == "address", fixed
PY
else
	bad "--abi failed"; cat "$TMP/abi_err.txt"
fi

# 6. Every err_*.sol must fail with its EXPECT text (legacy and --via-ir).
for f in "$HERE"/err_*.sol; do
	expect="$(sed -n 's#^// EXPECT: ##p' "$f" | head -n 1)"
	for mode in legacy viair; do
		args=(--bin)
		[ "$mode" = viair ] && args+=(--via-ir)
		if "$SOLC" "${args[@]}" "$f" > "$TMP/o.txt" 2> "$TMP/e.txt"; then
			bad "$(basename "$f") [$mode]: compiled, expected an error containing: $expect"
		elif grep -qF "$expect" "$TMP/e.txt"; then
			ok "$(basename "$f") [$mode]: error: $expect"
		else
			bad "$(basename "$f") [$mode]: failed, but without: $expect"
			cat "$TMP/e.txt"
		fi
	done
done

echo "----"
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
