#!/usr/bin/env bash
#
# Stage F test — PR 3 / F4: H-9 mixed-version cluster fail-fast.
#
# CI default: SKIP (rc=99). End-to-end coverage of this scenario
# requires running an OLDER nodus-server binary on at least one node
# alongside the new one. The worktree only ships a single binary, so
# there is no in-process way to mock an older peer reporting a
# pre-PR-3 nodus_version on its w_ident exchange.
#
# Coverage rationale for default-SKIP:
#   * The detection helper
#     nodus_witness_bootstrap_any_peer_older(w, local_nv)
#     is fully exercised by tests/test_witness_bootstrap_mixed_version.c
#     (8 cases including: empty peer set, all-same, all-newer, legacy
#     remote_nodus_version=0, one-older, minor-older, mixed). That
#     unit test is the authoritative correctness gate.
#   * The wire-up of any_peer_older into bootstrap_tick + the
#     exit(3) call site is a single forward edge — visually
#     reviewed in the E4 GREEN commit. No code path is reachable
#     from the helper that this test could surface beyond the unit
#     test's coverage.
#   * Production rolling deploy IS the real test of this path: any
#     mid-deploy fresh node would hit exit(3) if the operator started
#     bootstrap on a node before the rolling upgrade completes. The
#     operator-facing log line + distinct exit code (3 vs 2) are the
#     test artifacts.
#
# To exercise manually (requires building a second nodus-server with
# NODUS_VERSION_PATCH bumped down):
#
#   1. Save current binary as nodus-server.new
#   2. Edit nodus/include/nodus/nodus_types.h, decrement
#      NODUS_VERSION_PATCH, rebuild as nodus-server.old.
#   3. Bring up 6 nodes with .new + 1 node with .old. Wipe the
#      .new node's data. Restart it.
#   4. Verify the .new fresh node exits with code 3 within seconds
#      and emits "MIXED VERSION CLUSTER DETECTED" to stderr.
#
# Set STAGEF_RUN_DESTRUCTIVE=1 to attempt the test (currently
# unimplemented — exits FAIL with a pointer to the manual procedure).

if [ -z "${STAGEF_RUN_DESTRUCTIVE:-}" ]; then
    echo "[skip] PR 3 / F4 mixed-version test requires STAGEF_RUN_DESTRUCTIVE=1"
    echo "       AND a separately built older nodus-server binary"
    echo "       (see file header for full procedure)"
    exit 99
fi

echo "[FAIL] STAGEF_RUN_DESTRUCTIVE=1 set but no automated mixed-version" \
     "implementation — invoke the manual procedure documented in the" \
     "file header instead."
exit 1
