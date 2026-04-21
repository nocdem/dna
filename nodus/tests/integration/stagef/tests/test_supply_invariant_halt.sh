#!/usr/bin/env bash
#
# Stage F.3 test — supply-invariant hard-gate rejection.
#
# Goal: prove that an on-chain attempt to inflate supply past
#   expected = genesis_supply + total_minted − total_burned
# is rejected by check_supply_invariant_v016 in finalize_block —
# the block does NOT commit, chain stalls at the prior height, and
# every node logs "SUPPLY INVARIANT VIOLATION" with matching
# expected/observed/delta bytes.
#
# Injection path options (ranked cheapest → most expensive):
#   A) Debug-build hook: a compile-time flag that lets a test-only
#      RPC force supply_tracking.total_minted += N without a matching
#      utxo/stake/pool delta. Simplest. Requires a Debug build + a
#      witness-side FORCE_TEST env guard.
#   B) Raw TX injection: submit a hand-crafted TX whose update_utxo_set
#      output sum > input sum (mint-from-thin-air). The verifier
#      should reject at TX admission; if it somehow passes (regression),
#      finalize_block's hard gate catches it.
#   C) DB poke: SIGSTOP the witness, sqlite3 UPDATE on supply_tracking,
#      SIGCONT, submit a block-trigger TX. Most reliable but requires
#      root on the harness nodes.
#
# This stub documents the test and FAILS (exit 99 = TODO) until the
# chosen injection path is wired up. For now it at least verifies
# that stagef_diff is intact post-bring-up — baseline consensus
# health check.
#
# Requires an active Stage F harness (stagef_up.sh).

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

echo "== Baseline consensus check =="
bash "$(dirname "$0")/../stagef_diff.sh" "pre-injection" || exit 2

echo ""
echo "[TODO] supply-invariant injection path not yet wired."
echo "       The check_supply_invariant_v016 hard gate (Stage F.1)"
echo "       is ACTIVE on live finalize_block — any real-world supply"
echo "       drift will halt the chain immediately. This test script"
echo "       exists to assert the gate fires WHEN the injection path"
echo "       is added; see top-of-file comments for design options."
exit 99
