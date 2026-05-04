#!/usr/bin/env bash
#
# Stage F test — PR 3 / F3: cold-DR --cold-bootstrap operator escape.
#
# CI default: SKIP (rc=99). End-to-end exercise of this scenario
# requires DESTROYING the active 7-node cluster (wiping all 7 chain
# DBs) and rebuilding from a fresh genesis with one node carrying
# the --cold-bootstrap CLI flag. Subsequent tests in
# genesis_protocol.sh would observe a different chain (different
# chain_id, different state_root, no stagef_user funding) and fail
# spuriously.
#
# To exercise manually:
#
#   1. Run the harness up to its current state.
#   2. bash stagef_down.sh
#   3. Spawn 7 nodes from scratch (mirror stagef_up.sh) with
#      exactly ONE carrying --cold-bootstrap as a CLI flag (E1
#      shipped the parser hook).
#   4. Verify all 7 reach DONE, exactly one logs the
#      "answered via --cold-bootstrap operator escape (C4); cabal
#      protection bypassed" line, the other 6 reach DONE via the
#      regular DISCOVER -> w_chain_q quorum path.
#   5. Verify state_root identical 7/7 once the test workload runs.
#
# Coverage rationale for default-SKIP:
#   * The CLI flag wire-up is exercised by --cold-bootstrap appearing
#     in `nodus-server -h` output (E1 commit verified this) and by
#     the C4 unit code path in nodus_witness_bootstrap.c.
#   * The handle_chain_q "answered via --cold-bootstrap" branch is a
#     simple boolean check — no consensus surface beyond the C-2
#     bypass, which has its own log line for operator triage.
#   * The cabal-protection invariant ("MUST not run more than one")
#     is operator-enforced, not protocol-enforced (nodus_server.h:96
#     comment); a harness can verify the single-node path but cannot
#     simulate operator misuse meaningfully.
#
# Set STAGEF_RUN_DESTRUCTIVE=1 to run this test (will tear down the
# active harness; CI MUST NOT set this).

if [ -z "${STAGEF_RUN_DESTRUCTIVE:-}" ]; then
    echo "[skip] PR 3 / F3 cold-DR test requires STAGEF_RUN_DESTRUCTIVE=1"
    echo "       (destroys the active 7-node cluster; see file header)"
    exit 99
fi

# Real implementation deferred — see file header for the manual
# procedure that exercises the --cold-bootstrap path end-to-end on
# an isolated cluster bring-up.
echo "[FAIL] STAGEF_RUN_DESTRUCTIVE=1 set but no automated cold-DR" \
     "implementation in this script — invoke the manual procedure" \
     "documented in the file header instead."
exit 1
