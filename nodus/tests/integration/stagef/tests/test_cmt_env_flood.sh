#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_env_flood.sh — a block beyond 10 envelopes, 7/7 agreement
# (R3 W4-C delta 2)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES (INTENDED — NOT YET RUNNABLE; see "WHY IT SKIPS")
#   That a single block can carry MORE than the retired chain-config
#   envelope cap (10) of ENVELOPE-classified items (not claims — those
#   are test_cmt_claim_flood.sh's subject), that every one of them
#   applies, and that all 7 nodes agree — the operator's decision
#   (atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1) names this
#   scenario explicitly as part of what delta 2 delivers, alongside a
#   measurement of wall-clock cost per envelope.
#
# WHY IT SKIPS — A CLI CAPABILITY GAP, GROUNDED BY GREP, NOT ASSUMED
#   The PUMP identity's 40 UTXOs (created by test_cmt_claim_flood.sh's
#   claims, if that scenario ran first) can only be SPENT by submitting
#   an ENVELOPE with a CORE leg that consumes them — the shape the
#   dispatch calls "one dnac_spend each". `nodus-cli` (the only client
#   this harness drives, `STAGEF_NODUSCLI_BIN`) has NO such command:
#     - `grep -n '"spend"\|"transfer"' nodus/tools/nodus-cli.c` — EMPTY.
#     - The DNAC-lane top-level commands it dispatches are exactly
#       `chain-config`, `stake`, `v2-envelope` (whose only implemented
#       non-stake subcommand is `chain-config` — cmd_v2_envelope,
#       nodus-cli.c:1551, refuses any `sub` other than "chain-config"),
#       and `v2-claim`. None of these is a generic CORE-domain value
#       transfer.
#     - `v2-envelope stake` builds a two-leg SYSTEM+CORE STAKE envelope,
#       but it is a ONE-TIME bond per identity (self-stake), not a
#       repeatable spend, and it requires a NON-VALIDATOR identity —
#       shaping 40 repeated submissions from ONE identity through it
#       would not be 40 spends, it would be one stake attempt followed
#       by 39 refusals from an already-staked identity, proving nothing
#       about envelope-count capacity.
#     - `v2-envelope chain-config` is a governance proposal (committee
#       vote, grace period, one parameter change at a time) — not a
#       value transfer, and not repeatable 40 times in one block either.
#   This is a TOOLING gap, not a nullifier/intent RULE the way the
#   dispatch's own escape hatch anticipated ("if a single identity
#   cannot spend 40 UTXOs in one block for a reason you read, say which
#   rule") — the reason here is that no CLI path reaches the operation
#   at all, for ANY identity. Adding one is a `nodus-cli.c` CHANGE
#   outside this delta's whitelist (which grants ONLY "the name table +
#   usage lines" in that file) and is not a harness-script decision to
#   make unilaterally.
#
# WHAT IT REQUIRES (once the CLI gap above is closed)
#   Compile flags: none beyond a default build.
#   Environment: a cluster from stagef_up_v2.sh; PUMP UTXOs to spend
#   (test_cmt_claim_flood.sh run first in the sweep).
#
# WHAT IT LEAVES BEHIND
#   Nothing — this run is a SKIP (exit 99), it submits nothing.
#
# HOW IT CAN LIE
#   - **A SKIP is not a pass.** This scenario existing on disk, green in
#     a sweep, proves NOTHING about envelope-count capacity beyond 10 —
#     that coverage has not happened. Do not fold this exit into a green
#     count.
#   - **rc=99 here means a missing CLIENT CAPABILITY, not a missing
#     CLUSTER.** Every other `exit 99` in this suite means "not a Comet
#     cluster" or "no short-epoch binary"; this one fires on an
#     otherwise perfectly healthy Comet cluster. Read this script's own
#     stderr line, not just the exit code, before assuming which.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"

echo "[SKIP] test_cmt_env_flood.sh: nodus-cli has no generic CORE-domain" >&2
echo "       spend/transfer envelope command — grep -n '\"spend\"' " >&2
echo "       nodus/tools/nodus-cli.c is empty, and v2-envelope's only" >&2
echo "       implemented non-stake subcommand is chain-config" >&2
echo "       (cmd_v2_envelope, nodus-cli.c:1551). This is a CLI TOOLING" >&2
echo "       gap outside this package's whitelist (nodus-cli.c is only" >&2
echo "       approved for its name-table + usage-line edits), not a" >&2
echo "       consensus/nullifier rule. Reported to the ORCHESTRATOR;" >&2
echo "       this scenario needs a v2-envelope spend/transfer builder" >&2
echo "       before it can run for real." >&2
exit 99
