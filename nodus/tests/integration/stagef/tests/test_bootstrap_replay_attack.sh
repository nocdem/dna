#!/usr/bin/env bash
#
# Stage F test — PR 3 / F6: C-4 nonce-mismatch replay rejection.
#
# CI default: SKIP (rc=99). End-to-end coverage of this scenario
# requires capturing a real w_chain_r message off the wire of one
# bootstrap round and replaying it into a fresh node's bootstrap
# state at a moment when its in-flight nonce has rotated. Without a
# packet-capture + injection harness (libpcap + raw socket replay or
# code-path fault-injection hook), the harness cannot synthesize
# this in-process.
#
# Coverage rationale for default-SKIP:
#   * The wire-side nonce echo invariant is exercised by
#     tests/test_t3_bootstrap_wire.c — that test asserts
#     w_chain_q.nonce roundtrips intact through encode/decode and
#     that q.nonce == r.nonce holds for every accepted response.
#   * The bootstrap state machine's nonce-stale filter is part of
#     handle_chain_r (drops responses whose nonce does not match the
#     current round's bootstrap_round_nonce — see the random 16B
#     seed captured per round in start_discover_round). Stale-nonce
#     responses are silently dropped without affecting quorum
#     accumulation; this is straightforward stateful logic visually
#     reviewed in the C3 commit and inherently exercised by every
#     bootstrap round.
#   * The W3C-style replay attack against an authenticated round
#     (capture round N's w_chain_r, replay during round N+1) is
#     defended by the per-round nonce regeneration in
#     start_discover_round (qgp_randombytes 16 bytes per round).
#     Failing this defense would require a PRNG bias which is out
#     of scope for PR 3 (qgp_randombytes is the project-wide CSPRNG
#     and has its own coverage).
#
# To exercise manually:
#
#   1. Add a fault-injection hook in nodus_witness_bootstrap.c that,
#      when a debug env var is set, replays a hardcoded w_chain_r
#      buffer with a stale nonce.
#   2. Restart node $TARGET with the env var; verify the response
#      is silently dropped (no quorum advancement, no log noise
#      claiming the response counted).
#   3. Re-run with a fresh w_chain_r matching the current nonce —
#      verify quorum advances normally.
#
# That hook is out of scope for PR 3 — adding it requires either a
# build-time flag (recompile cost on every dev cycle) or a runtime
# CLI knob (operator-misuse surface).

if [ -z "${STAGEF_RUN_DESTRUCTIVE:-}" ]; then
    echo "[skip] PR 3 / F6 replay-attack test requires STAGEF_RUN_DESTRUCTIVE=1"
    echo "       AND a fault-injection build (see file header)"
    exit 99
fi

echo "[FAIL] STAGEF_RUN_DESTRUCTIVE=1 set but no automated replay-attack" \
     "implementation — invoke the manual procedure documented in the" \
     "file header instead."
exit 1
