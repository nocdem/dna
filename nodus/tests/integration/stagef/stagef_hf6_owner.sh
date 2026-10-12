#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# stagef_hf6_owner.sh — HF-6 6f-2: the PRE-BUILD step of the rotation
# phase of tests/test_hf6_edge.sh. Generates (or re-reads) ONE single-key
# nodus identity that a TEST build compiles in as the HF-6 Foundation
# owner, and prints the exact cmake flag and environment that go with it.
# ════════════════════════════════════════════════════════════════════
#
# WHY A PRE-BUILD STEP. After the HF-6 generation-4 edge every genesis
# validator's owner is the COMPILED DNAC_HF6_FOUNDATION_OWNER
# (dnac/include/dnac/dnac.h; the migration gives it to every row with
# active_since_block <= 1 — decision docs/plans/decisions/2026-10-09-
# kurultay-16-hf6-storage-summary.md D2 (a)). The default is the K8 address
# (decision 2026-10-08-kurultay-14-hf6-summary.md K8), a 2-of-3 whose keys
# the harness does not hold, and nodus-cli's `v2-envelope rotate` builds
# kind-1 (single-key) owners only (nodus-cli.c cmd_v2_stake header, 6f-1).
# So an owner operation of a genesis validator is signable in the harness
# only on a build whose owner is SHA3-512 of a key the harness holds — and
# that key must exist BEFORE the build (the build bakes it in), so it
# cannot be born at bring-up like every other harness identity.
#
# USAGE
#   bash stagef_hf6_owner.sh <DIR> [NODUS_SERVER_BIN]
#     DIR               where the identity goes: DIR/identity (nodus.pk,
#                       nodus.sk, nodus.fp, …) and DIR/data (scratch for the
#                       generating spawn). Created if absent. If
#                       DIR/identity/nodus.pk already exists NOTHING is
#                       generated — the existing identity is checked and
#                       its values printed again (re-runnable).
#     NODUS_SERVER_BIN  the nodus-server that generates the identity
#                       (default: $STAGEF_NODUS_BIN, i.e. nodus/build/
#                       nodus-server). ANY build will do — the identity
#                       files do not depend on the compiled owner; the
#                       override build is made AFTER this, with the
#                       printed flag.
#
# HOW THE IDENTITY IS MADE — the harness's own way, not a new one:
# stagef_up_v2.sh section 1b generates every non-node identity (v2user,
# v2pump, v2probe, cand<i>) by a SHORT-LIVED `nodus-server -i DIR -d DIR`
# spawn on a port block of its own and kills it once nodus.pk / nodus.fp
# exist: the server creates an identity only when neither key file exists
# (nodus_server.c nodus_server_identity_load_or_create: generate + save).
# nodus-cli has no saving keygen (without -i it uses a random, unsaved
# key — nodus-cli.c main). Same here, on port block STAGEF index 90
# (UDP 14890, TCP 14891-14894), which no harness script uses (the bring-up
# uses 1..C+3+candidates+pump identities, the grow joiner the next one);
# every one of the five ports is checked free with `ss` first.
#
# CHECKED, NOT ASSUMED: nodus.fp == SHA3-512(nodus.pk) (openssl over the
# raw 2592 bytes — stagef_env.sh stagef_sha3_512_hex), and nodus.sk exists
# (the owner SIGNS the ROTATE envelope). That 128-hex value is the owner_fp
# a kind-1 owner has (design docs/plans/2026-10-03-hf5-validator-owner-
# stake-design.md rev 6 §1.3: SHA3-512(signer pk) == owner_fp).
#
# THE FLAG — VERIFIED, NOT GUESSED (6f-2 author, 2026-10-12): the form is
# dnac.h's own comment form, `-DDNAC_HF6_FOUNDATION_OWNER="{0x..,…}"`
# inside CMAKE_C_FLAGS, no spaces in the list. A scratch configure of this
# tree with a dummy list 0x01..0x40 (CMake "Unix Makefiles" generator,
# /bin/sh = dash) wrote it verbatim into flags.make, and the one consumer
# (nodus_witness_v2_apply.c, `static const uint8_t foundation[] =
# DNAC_HF6_FOUNDATION_OWNER;` + its 64-byte _Static_assert) compiled with
# the 64 bytes present in the object. Another generator or shell was not
# checked.
#
# WHAT IT LEAVES BEHIND: DIR/identity and DIR/data (the spawn's scratch),
# DIR/identity_gen.log. Nothing else; no process (the spawn is killed and
# reaped; a port check failure exits before anything starts).
#
# HOW IT CAN LIE: it proves the identity's files agree with each other; it
# cannot prove the BUILD you make next carries the printed bytes — that is
# test_hf6_edge.sh's job (step 7 FAILs unless every migrated row's owner_fp
# equals STAGEF_HF6_OWNER_FP_HEX; the rotation phase's gate FAILs unless
# SHA3-512 of STAGEF_HF6_OWNER_KEYS's nodus.pk equals it).
#
# Exit: 0 printed; 1 refused (reason on stderr). Not a scenario — no
# sentinel, never in the sweep.
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stagef_env.sh"

die() { echo "[FAIL] $*" >&2; exit 1; }

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 <DIR> [NODUS_SERVER_BIN]"
DIR="$1"
SRV="${2:-$STAGEF_NODUS_BIN}"
command -v openssl >/dev/null 2>&1 || die "openssl is not installed (the SHA3-512 check needs it)"
command -v ss >/dev/null 2>&1 || die "ss is not installed (the port check needs it)"
mkdir -p "$DIR/identity" "$DIR/data"
DIR="$(cd "$DIR" && pwd)"
ID="$DIR/identity"

if [ -s "$ID/nodus.pk" ]; then
    echo "[ok] $ID already holds an identity — nothing generated, re-checking it"
else
    [ -x "$SRV" ] || die "no executable nodus-server at '$SRV' (pass one as the 2nd argument)"
    PIDX=90
    for port in "$(stagef_udp_port "$PIDX")" "$(stagef_tcp_port "$PIDX")" \
                "$(stagef_peer_port "$PIDX")" "$(stagef_chan_port "$PIDX")" \
                "$(stagef_witness_port "$PIDX")"; do
        # read the whole listing, then match (no early-exit pipe reader)
        lst=$(ss -ltunH 2>/dev/null || true)
        if grep -Eq "[:.]${port}\\b" <<< "$lst"; then
            die "port $port (block $PIDX) is in use — stop whatever holds it, nothing was started"
        fi
    done
    # stagef_up_v2.sh section 1b's spawn line, verbatim but for the dirs
    "$SRV" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$PIDX")" -t "$(stagef_tcp_port "$PIDX")" \
        -p "$(stagef_peer_port "$PIDX")" -C "$(stagef_chan_port "$PIDX")" \
        -W "$(stagef_witness_port "$PIDX")" \
        -i "$ID" -d "$DIR/data" \
        > "$DIR/identity_gen.log" 2>&1 &
    gp=$!
    # the bring-up's own bound: 40 x 0.25 s
    for _ in $(seq 1 40); do
        [ -s "$ID/nodus.pk" ] && [ -s "$ID/nodus.sk" ] && [ -s "$ID/nodus.fp" ] && break
        sleep 0.25
    done
    kill "$gp" 2>/dev/null || true; wait "$gp" 2>/dev/null || true
    [ -s "$ID/nodus.pk" ] || { cat "$DIR/identity_gen.log" >&2; die "the spawn wrote no $ID/nodus.pk"; }
    echo "[ok] identity generated in $ID (by $SRV)"
fi

[ -s "$ID/nodus.sk" ] || die "$ID has no nodus.sk — the owner must SIGN the ROTATE envelope"
[ -s "$ID/nodus.fp" ] || die "$ID has no nodus.fp"
PK_LEN=$(stat -c %s "$ID/nodus.pk")
[ "$PK_LEN" = 2592 ] || die "$ID/nodus.pk is $PK_LEN bytes, not 2592 (ML-DSA-87)"
FP=$(stagef_sha3_512_hex "$ID/nodus.pk")
[[ "$FP" =~ ^[0-9a-f]{128}$ ]] || die "SHA3-512 of $ID/nodus.pk could not be computed ('$FP')"
FILE_FP=$(tr 'A-F' 'a-f' < "$ID/nodus.fp" | tr -d '[:space:]')
[ "$FILE_FP" = "$FP" ] || die "$ID/nodus.fp ('${FILE_FP:0:16}…') is not SHA3-512 of nodus.pk ('${FP:0:16}…')"

# the brace initializer dnac.h expects: 64 bytes, "0x..", no spaces
LIST=""
for (( i = 0; i < 128; i += 2 )); do LIST="$LIST,0x${FP:$i:2}"; done
LIST="{${LIST#,}}"

cat <<EOF

[ok] owner_fp = SHA3-512(nodus.pk) = $FP

── 1. build (ONE tree, nodus-server + nodus-cli from the SAME build dir;
      the short-epoch + short-grace set test_hf6_edge.sh needs, plus the owner)
F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
O='-DDNAC_HF6_FOUNDATION_OWNER="$LIST"'
cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf6rot -DCMAKE_C_FLAGS="\$F \$O"
make -C <TREE>/nodus/build-hf6rot -j"\$(nproc)" nodus-server nodus-cli

── 2. environment (export BEFORE stagef_up_v2.sh)
export STAGEF_NODUS_BIN=<TREE>/nodus/build-hf6rot/nodus-server
export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-hf6rot/nodus-cli
export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
export STAGEF_V2_CANDIDATES=1
export STAGEF_HF6_OWNER_FP_HEX=$FP
export STAGEF_HF6_OWNER_KEYS=$ID

── 3. run (the scenario's own header has the rest)
bash <TREE>/nodus/tests/integration/stagef/stagef_up_v2.sh
bash <TREE>/nodus/tests/integration/stagef/tests/test_hf6_edge.sh; echo "rc=\$?"
bash <TREE>/nodus/tests/integration/stagef/stagef_down.sh

A build with this owner is a TEST build only: production never defines
DNAC_HF6_FOUNDATION_OWNER (dnac/include/dnac/dnac.h).
EOF
