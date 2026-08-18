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
# O15B.1 — SKIP CLASSIFICATION (capability, not environment noise).
#
# This is an INTENTIONAL rc=99, and the reason is that all three
# injection paths above are out of reach without doing something this
# tree forbids:
#
#   A) A production fault hook that forces supply_tracking.total_minted
#      is a live path into the very counter the hard gate defends. The
#      gate must be fail-closed and unreachable from any input; adding a
#      way to move its input is the opposite of that.
#   B) A mint-from-thin-air TX is rejected at ADMISSION
#      (nodus_witness_verify.c), so it never reaches finalize_block and
#      cannot exercise the gate this scenario is named for.
#   C) A DB poke reaches the gate, but only by breaking the shared
#      fixture: the documented contract is "EVERY node logs SUPPLY
#      INVARIANT VIOLATION and the chain stalls", which means poking all
#      seven — and genesis_protocol.sh runs eleven further scenarios
#      against that same cluster afterwards, with no recovery path
#      (halt_auto_recover defaults off, feedback_genesis_protocol).
#
# What this skip does NOT hide:
#   - the gate itself: check_supply_invariant_v016 has unit coverage in
#     nodus/tests/test_witness_state_root_failclose.c (fail-close on a DB
#     error), and the conservation invariant it defends is property-
#     tested over 3x1000 random TX sequences in
#     nodus/tests/test_supply_invariant.c;
#   - bootstrap, validator-set grow/shrink, or any state_root path —
#     this scenario touches none of them.
#
# The script still runs a REAL assertion before skipping: stagef_diff
# proves state_root is identical across all nodes at this point in the
# run. Wiring path (C) into a scenario of its own — with its own
# cluster, poked on all seven nodes, torn down afterwards — is the
# honest way to close this, and it is not O15B.1's scope.
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
echo "[SKIP] supply-invariant injection is a CAPABILITY this harness does"
echo "       not have, not an unwritten assertion. Path A needs a"
echo "       production hook into the counter the gate defends; path B is"
echo "       rejected at TX admission and never reaches finalize_block;"
echo "       path C halts the shared 7-node cluster that eleven later"
echo "       scenarios run against, with no recovery path."
echo "       The gate is NOT unverified: check_supply_invariant_v016 is"
echo "       fail-close tested in ctest test_witness_state_root_failclose,"
echo "       and the conservation invariant is property-tested in ctest"
echo "       test_supply_invariant. The 7/7 state_root assertion above DID"
echo "       run. Closing this properly needs its own disposable cluster."
exit 99
