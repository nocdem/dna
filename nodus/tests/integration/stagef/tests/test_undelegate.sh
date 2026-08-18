#!/usr/bin/env bash
#
# Stage F test — DELEGATE + UNDELEGATE consensus check.
#
# The 2026-04-19 chain halt (d8d4d9c2 block 25) was an UNDELEGATE TX
# that produced 4 different state_roots across 7 nodes. This test
# would have caught that bug in seconds. It repeats the exact TX
# pattern on the harness and asserts 3/3 identical state_root.
#
# Requires an active Stage F harness (stagef_up.sh).

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

USER_FP=$(cat "$BASE_DIR/user_fp.txt")

# Read validator_0 pubkey hex from the chain_def.conf we built at
# bring-up — that's the node 1 validator pubkey.
V0_PUBKEY=$(awk -F= '/^validator_0_pubkey=/ {print $2}' "$BASE_DIR/chain_def.conf")
if [ -z "$V0_PUBKEY" ]; then
    echo "[FAIL] could not extract validator_0 pubkey from chain_def.conf" >&2
    exit 1
fi

# O15B §7 — this scenario spends from stagef_user directly rather than
# through stagef_mk_funded_user, which is exactly why it broke: by the time
# it runs, test_delegate_to_retiring has UNSTAKED, minting a cooldown-locked
# release coin into that same wallet. Coin selection had no notion of a
# lock, chose it, and every validator rejected the transaction — surfacing
# here as "delegate submit failed".
stagef_sentinel SETUP_OK

# Baseline state_root (post-genesis).
bash "$(dirname "$0")/../stagef_diff.sh" "baseline"

# ── DELEGATE 5M DNAC → validator 0 ──────────────────────────────────
echo ""
echo "== DELEGATE 5M → validator 0 =="
stagef_dna -q dna delegate "$V0_PUBKEY" 500000000000000 "test-delegate" \
    > "$BASE_DIR/test_delegate.log" 2>&1 || {
    echo "[FAIL] delegate submit failed" >&2
    tail -10 "$BASE_DIR/test_delegate.log" >&2
    exit 2
}
# Wait a few block intervals.
sleep 8
bash "$(dirname "$0")/../stagef_diff.sh" "post-DELEGATE"

# ── UNDELEGATE 2M partial ───────────────────────────────────────────
echo ""
echo "== UNDELEGATE 2M (partial) =="
stagef_dna -q dna undelegate "$V0_PUBKEY" 200000000000000 \
    > "$BASE_DIR/test_undelegate.log" 2>&1 || {
    echo "[FAIL] undelegate submit failed" >&2
    tail -10 "$BASE_DIR/test_undelegate.log" >&2
    exit 3
}
stagef_sentinel TARGET_REACHED
sleep 8
# ASSERT_RUN must be recorded BEFORE the assertion, not after.
#
# stagef_diff.sh IS this scenario's terminal assertion, and it aborts the
# script under `set -euo pipefail`. Marking afterwards meant a genuine
# state_root divergence exited with marks `SETUP_OK TARGET_REACHED` — which
# reads as "the fixture broke", the exact misdiagnosis the sentinels exist
# to prevent. The mark states that the assertion is ABOUT TO RUN; whether it
# passes is carried by the exit code. (Review R3.)
stagef_sentinel ASSERT_RUN
bash "$(dirname "$0")/../stagef_diff.sh" "post-UNDELEGATE"

stagef_sentinel PASS
echo ""
echo "[PASS] DELEGATE + UNDELEGATE consensus intact across 3 nodes"
