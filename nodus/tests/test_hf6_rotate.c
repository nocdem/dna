/**
 * @file nodus/tests/test_hf6_rotate.c
 * @brief HF-6 slice 6 — ROTATE_CONSENSUS_KEY (runtime_op 10): owned and
 *        priced by generation 4 only (sub-slice 6a), its exec (6b), the
 *        by-validator_id readers and the swap writer (6c), the freeze's
 *        budget pass, the boundary swap and the sweep (6d), their fault
 *        stages and the graduate's previous key (6e).
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §2 (ROTATE = runtime_op 10, call validator_id[64] ‖ new_pk[2592] ‖
 * consent_sig[4627] ‖ consent_expiry u64 = 7291 B; the generation-4
 * SYSTEM descriptor {1..10}; the consent re-construction contract), §3
 * (rotation; khan decisions of 2026-10-12: A1 exec writes the first
 * boundary >= the commit height, A4 the funding leg is fee-only, A5 only
 * ACTIVE / ELIGIBLE rows, A6 versions stay SYSTEM 9 / CORE 7), §4 (key
 * uniqueness), §6.1 (consent bytes, ctx "nodus.valbind.v1", expiry rule),
 * §6.3 (row); decision 2026-10-08-kurultay-14-hf6-summary.md K7; plan
 * tasks/hf6-slice6-plan.md §1.1, §1.2, §1.4, §1.8, §2 "6a" .. "6d" (khan
 * A2: the previous key released at U+E; A3: skip-and-continue, 0 for a
 * candidate absent from S(F); A8 (2026-10-13): the previous key of a
 * validator S(F) does not seat released in the swap at U).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. TABLE (no database):
 *   A1 DNA_SYSRULE_ROTATE_CONSENSUS_KEY == 10; the generation-4 SYSTEM
 *      descriptor (still v9) owns op 10 and no earlier generation's
 *      SYSTEM or CORE descriptor does — the list rt_owns_runtime_op
 *      (nodus_witness_v2_apply.c, static) walks, restated here as the
 *      same ascending scan.
 *   A2 the generation-4 SYSTEM policy prices op 10 at weight 1; no
 *      earlier one does; the compiled table passes its selfcheck (every
 *      pin re-derives — the oracle literals of shared/dnac/tests/
 *      storage_oracle.py) and the param-18 vote value D4
 *      (DNAC_CFG_RULESET_GEN_ROLES_D, hf6_vote_oracle.py) re-derives
 *      from the generation-4 hashes through nodus_runtime_gen4_vote_digest.
 *   A3 the SYSTEM read plan and exec of generations 1..3 and of a NULL
 *      runtime refuse op 10 (-1, never -2).
 *  H. HOOKS — the generation-4 SYSTEM / CORE runtimes over fabricated
 *     engine facts (a decoded 2-leg envelope, a verdict, mediated-read
 *     results) and REAL ML-DSA-87 consent signatures:
 *   H1 the plan is [op 13 validator_id] [op 17 SHA3-512(new_pk)], in
 *      that order; length 7290 / 7292 refused by plan and exec; the
 *      generation-3 runtime refuses the 7291-B call.
 *   H2 kind-1 owner (ACTIVE and ELIGIBLE rows) and kind-3 owner (2-of-3
 *      address) positives: exactly two effects — CREATE op 17 behind
 *      ABSENT (key SHA3-512(new_pk), value validator_id ‖ role 2), then
 *      SET op 13 behind EXISTS_VHASH bound to the observed row's hash,
 *      whose value is the observed row with ONLY pending_consensus_pubkey
 *      := new_pk and consensus_key_effective_epoch := F changed; F = the
 *      first epoch boundary >= h (h itself at a boundary, else the next).
 *   H3 refusals (-1): unknown validator_id; a kind-1 signer that is not
 *      the row's owner; a kind-3 descriptor of another address; kind 2;
 *      status RETIRING / UNSTAKED / AUTO_RETIRED; a pending key already
 *      set; new_pk equal to the row's current key; new_pk reserved by
 *      another validator as role 1 and as role 2 (a malformed reservation
 *      answer -2); expiry h - 1 and h + 721 (h and h + 720 accepted);
 *      consents with op 1 (STAKE), an all-zero subject, another
 *      validator's id, another owner, another chain, signed by the OLD
 *      key, signed under ctx "nodus.valbind.v2"; a malformed SYSFUND
 *      sibling and a non-SYSFUND sibling; a read count that is not 2
 *      (-2).
 *   H4 the CORE SYSFUND leg pairs with a ROTATE sibling under generation
 *      4 (plan = inputs + pool) and NOT under generation 3; the
 *      read-only describer describes both legs (SYSTEM: no record kind).
 *  B. ENGINE (twin seeded chains, EVM-enabled build — the test_hf6_stake
 *     fixture: V0..V6 ACTIVE 10M since 1; param 9 at 2, param 14 at 3,
 *     param 18 (RULESET_GEN_ROLES = D4, the generation-4 vote) at 4, so
 *     the edge runs in
 *     block 3):
 *   B1 block 3 (generation 3): a 2-leg {SYSTEM op 10, CORE SYSFUND}
 *      envelope is refused at ADMISSION (the live gate is
 *      rt_owns_runtime_op in env_admit_legs; rt_admit_common judges
 *      (tx_type, pool) only and is reached solely through
 *      nodus_witness_domreg_admit_v2, which has no production caller — so
 *      no SYS_TYPES change is involved); its funding coin stays unspent.
 *   B2 block 4: a generation-4 STAKE (owner KO, key KC1) opens V_A.
 *   B3 block 5: a kind-1 ROTATE of V_A to KN APPLIES: the roles row
 *      carries pending = KN and epoch F = E (the first boundary >= 5), the
 *      consensus key stays KC1, KN is reserved to V_A as role 2 and KC1
 *      stays role 1; the funding coin is consumed; Σutxo + Σself_stake +
 *      Σtotal_delegated + reward_pool is conserved (fee -> pool).
 *   B4 block 6: a second ROTATE of V_A (to KN2) is REFUSED with the ledger
 *      tables byte-identical (a rotation is pending).
 *   B5 block 7: a STAKE opens V_B (key KC2); block 8: a ROTATE of V_B to
 *      KN (pending for V_A, role 2) and block 9: to V1's key (role 1,
 *      reserved by the migration) are REFUSED, ledger byte-identical; the
 *      twins' databases agree at the end.
 *  C. SLICES 6c + 6d (plan §2 "6c", "6d") — the same twin fixture, run to
 *     4E, rotators NOT seated in S(F). Every committed state change goes
 *     through the engine (real STAKE / ROTATE / UNSTAKE envelopes); the
 *     direct writes are probes on twin A, each undone before the next
 *     committed block and followed by an A == B digest check. The
 *     rotators are generation-4 STAKEd rows (owner KO): a genesis seat's
 *     owner is the compiled Foundation address, which no test can sign for.
 *   C1 blocks 4..6: STAKEs open V_A / V_B / V_C (keys KC1 / KC2 / KC3);
 *      blocks 7..9: ROTATEs to KN / KN2 / KN1 apply (pending + F = E,
 *      role-2 reservations).
 *   C1c (e) the ruleset-1 bridge (A only, ROLLED BACK): V1 (genesis) given
 *      a pending key; the preview of S(2E) accepts it (S(E) = [10M x 7]
 *      raw, 60M > 46666666 in both sets); with V1's S(E) entry raised to
 *      100M (160M − 100M = 60M ≤ 106666666) it WAITS — so the bridge found
 *      it in the v1 S(E) and counted its power.
 *   C2 nodus_validator_v2_rotate_apply on V_A's real pending state (A
 *      only, ROLLED BACK): autocommit refused with nothing written; a
 *      wrong old key refused with nothing written; new == old refused; no
 *      pending key (V0) / another pending key refused at step 2, a missing
 *      role-2 reservation at step 3 (caller rollback); the swap: consensus
 *      key := pending, pending 2592 x 0x00, epoch 0, KN role 2 -> 1, KC1
 *      still role 1 (rotate_apply never touches the old key's row — its
 *      caller, the swap, releases it at U (A8) or leaves it to the sweep
 *      (A2)); a replay refused; A then byte-identical to B.
 *   C3 boundary E: (c) the three are not seated in S(2E) — they WAIT,
 *      rows untouched, F = E kept (the swap at E reads the ruleset-1 S(E)
 *      and returns).
 *   C4 boundary 2E: all three accepted (successor [10M x 7, 2M x 3],
 *      P = 76M, party 6M; absent from S(F) ⇒ 0 there); S(3E) carries the
 *      pending keys with their voter_ids; the rows are not written; the
 *      preview_next(2E) bytes equal the stored S(3E) (§12g at generation 4
 *      with pending rotations). C4b probes on S(F) = S(2E) (A only, ROLLED
 *      BACK): (d) every S(2E) seat at 1 coin (P_F = 7) — still accepted;
 *      (f) S(2E) deleted — the freeze FAULTS with candidates, builds
 *      without them, and then equals the stored S(3E) under the CURRENT
 *      keys (no pending row ⇒ the pre-6d bytes); (h) one S(2E) seat below
 *      one coin — FAULT with candidates, builds without (the helper is not
 *      called).
 *   C5 block 2E+1: V_B UNSTAKEs (RETIRING, pending kept).
 *   C6a an attendance row for KC1's voter_id PLANTED on both twins at
 *      2E+1 (the old voter of a validator seated in an earlier set; this
 *      fixture cannot seat a STAKEd row before S(3E)).
 *   C6 boundary 3E: F62 on A first — a FAULT rolled back whole (no swap,
 *      the previous keys still role 1, KC1's row present); then THE SWAP
 *      on both twins — all three rows (V_B RETIRING too) switch to the
 *      key S(3E) seats, pending 0, epoch 0, the new key role 1; none of
 *      the three has a seat in S(2E), so (khan A8) each previous key's
 *      role-1 row is deleted in the swap — ONE role-1 row each — and the
 *      sweep at 3E deletes KC1's planted attendance row (after the
 *      digest); the flips activate V_A / V_C, the graduation defers V_B,
 *      all by validator_id; A == B.
 *   C6s block 3E+1: a REAL STAKE of a new validator under KC3 (V_C's
 *      released previous key, its own consent) APPLIES — KC3 reserved to
 *      the new validator_id.
 *   C7 from block 3E+3 KN1 (V_C's key) signs; KN never does. C7b: on A
 *      alone, before BOUNDARY 4E, S(3E)'s V4 entry given a third key makes
 *      boundary 4E FAULT; restored, A equals B. C7c: ONE extra role-1
 *      row naming V_A is one difference for the boundary-start check's
 *      core (derivation of 3E) and makes the sweep at 4E FAULT (S(2E)
 *      does not seat V_A: no previous key is due — never released
 *      silently); TWO extra rows (three in all) FAULT too; removed, A
 *      equals B each time.
 *   C8 boundary 4E: applies on both twins; V_B graduates (key_release
 *      takes KN2; KC2 already went in the swap at 3E); the sweep has no
 *      candidate; KC1 free, KC3 the C6s validator's; Rule N on duty
 *      S(3E): V_A counter 1 (KN never signed), V_C 0; the twins agree.
 *  D. SLICE 6d — the budget and one full rotation (F / U / U+E) of
 *     validators seated in S(F): three 12M STAKEs, ROTATEs in (2E, 3E]
 *     (F = 3E); S(3E) = S(4E) = [12M x 3, 10M x 7] counted, P = 106M,
 *     floor(2P/3) = 70666666.
 *   D3 boundary 3E: (b) the first two in validator_id ASC accepted (94M,
 *      82M > 70666666), the third waits (70M); preview_next(3E) == stored
 *      S(4E).
 *   D4 boundary 4E: the distribution pays the owner KO (its accrual +
 *      UTXO value rises, no -2); (a) the swap of the two (row, pending,
 *      KEYRES 1/1); the third untouched with F = 3E kept; Rule N on duty
 *      S(3E) by id on the OLD keys — o0 (signed) counter 0, o1 (absent)
 *      counter 1; S(5E) carries the two new keys (U's freeze copies them)
 *      and the third's OLD key — khan A7 (the BUGS Z-27 case): S(4E)
 *      already carries o0 / o1's rotations (24M against S(3E)), so the
 *      third's 12M would make 36M, 70M ≤ 70666666: it waits again;
 *      preview_next(4E) == stored S(5E).
 *   D4s block 4E+1: a REAL STAKE of a new validator under o0's previous
 *      key (its own consent) is REFUSED at exec — the key is still
 *      reserved to o0 (khan A2: o0 was seated in S(F)) — ledger tables
 *      byte-identical, the coin unspent. D5s block 5E+1: the same call
 *      APPLIES (the sweep at 5E released the key).
 *   D5x (A only) a stray role-1 row naming V0 (never rotated) before
 *      boundary 6E: one difference for the boundary-start check's core
 *      (derivation of 5E); the sweep at 6E FAULTS (S(4E) seats V0 under
 *      its current key — no previous key is due); removed, A == B.
 *   D5 boundary 5E: KO paid again; (a) the sweep deletes the two old
 *      voters' attendance rows (credited at 4E+1, 4E+2) and their role-1
 *      rows; Rule N 0 on the new keys; the third not swapped (F = 3E
 *      kept) and accepted into S(6E) (S(5E) vs S(4E): no key change,
 *      carry 0, 94M). D6 boundary 6E: the third swapped, its old key kept,
 *      Rule N 0 on its old key. D7 boundary 7E: the third's old key and
 *      attendance row released. (i) the twins agree.
 *   D-F (slice 6e, plan §5 B2) the two rotation fault stages, on twin A
 *      alone: boundary 4E with F61 (V2AP_FAIL_AFTER_ROTATE_SWAP) and
 *      boundary 5E with F62 (V2AP_FAIL_AFTER_ROTATE_SWEEP) are node FAULTS
 *      (phase 6e) with the whole database byte-identical; the rows the
 *      step would have written are named and found unchanged (o0 / o1
 *      still pending with role-2 reservations; the old voters' attendance
 *      and role-1 rows present, o2 not swapped); the clean boundary then
 *      applies on both twins and A == B, byte for byte, right after it.
 *      Placed here, not in test_v2_epoch / test_v2_apply (where F39-F60
 *      live): their fixtures have no generation 4 and no ROTATE path, and
 *      the stages act only at a generation-4 boundary with a rotation in
 *      flight.
 *  E. SLICE 6e — a validator swapped at U that graduates at U+E (design
 *     rev 6 §3: the previous voter's attendance row is deleted at U+E,
 *     after that epoch's digest; khan A2). One 12M STAKE (KC1) at 4,
 *     ROTATE to KN at 2E+1 (F = 3E, accepted: S(4E) seats KN), KC1 signs
 *     from 3E+3, UNSTAKE at 3E+3 (RETIRING before U's freeze); boundary
 *     4E swaps it (RETIRING), defers its graduation, S(5E) does not seat
 *     it; KC1 signs 4E / 4E+1, KN from 4E+3; before 5E KC1's attendance
 *     row exists. Boundary 5E with F62 on A rolls the graduation and the
 *     sweep back together; the clean 5E: UNSTAKED under KN, KC1's
 *     attendance row gone, no reservation naming the validator (KN by the
 *     graduation, KC1 by the sweep's graduated arm), A == B.
 *  F. KHAN A7 (2026-10-13, BUGS Z-27) — the cumulative predecessor budget
 *     over the seven genesis seats ([10M × 7], P = 70M), rolled-back
 *     preview probes (the C1c device; full list above t_cumulative):
 *     f = 3E — no carry: both candidates accepted (the pre-A7 answer);
 *     S(3E) carrying V0, V1 re-keyed against S(2E) (2/7): both WAIT;
 *     carrying V0 alone: one accepted, one waits; V0 without a seat in
 *     S(2E): not counted; S(2E) absent: carry 0; S(2E) unreadable: FAULT
 *     with candidates, builds without; a carry of 3/7: FAULT with
 *     candidates, builds without. f = 2E — S(E) ruleset 1: matched through
 *     the migrated-id bridge, carry 2/7 both wait, 1/7 one waits.
 *  K. THE KEY-RESERVATION SELF-CHECK (nodus_witness_v2_keyres_diff, the
 *     core of the log-only boundary step 7):
 *   K1 every generation-4 boundary of C, D, E and F that apply_both
 *      commits: the check compares on both twins and finds 0 differences
 *      (rc 0, n 0) — through the normal rotation (D: swap at U, previous
 *      keys DERIVED from S(F), released at U+E), the A3 rotation (C:
 *      previous keys released in the swap, khan A8 — no tolerance), the
 *      re-use of released keys (C6s, D5s), the graduation of a swapped
 *      validator (C at 4E, E) and the ruleset-1 bridge boundary (2E);
 *      counted per case (2 per boundary).
 *   K2 (D4k, at 4E, A only, ROLLED BACK) each single-row corruption is
 *      exactly one difference: a derived previous key deleted, a current
 *      key and a pending key in the other role, a previous key naming
 *      another validator, a spare role-1 row for a validator with a seat
 *      in S(F); rolled back: 0, A == B.
 *   K3 (C6k, at 3E) no tolerance (khan A8): the A3 rotator's own released
 *      previous key put back at role 1, a spare row on an A3 rotator, a
 *      spare row on a validator both snapshots seat — each one difference
 *      (the former blind spot is now seen).
 *   K5 (C7c, D5x) the BOUNDARY-START check (step 0, the derivation of
 *      H − E, before the swap and the sweep) sees a stray role-1 row
 *      written between boundaries as 1 difference — the core is called
 *      directly at the pre-boundary state; that step 0 calls it is read
 *      from the source.
 *   K4 (F2k, at 2E) the ruleset-1 bridge: S(2E)'s V0 entry re-keyed (A
 *      only, ROLLED BACK) makes the bridge match V0 in S(E) under another
 *      key, deriving V0's own key a second time: one difference.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). B assumes
 * DNAC_EPOCH_LENGTH >= 12 (checked; true for the production 720 and the
 * harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_hf6_rotate_* directories per engine case (B, C, D, E, F),
 * removed at the end of the case (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - A1 restates rt_owns_runtime_op's scan (the engine's is static); B1
 *    is what drives the real gate.
 *  - The pinned hashes are oracle literals: selfcheck proves this build's
 *    encoder agrees with them, not that the oracle's inputs are the
 *    design's (the oracle names its sources in its docstring).
 *  - Section H fabricates the verdicts and the read results: it proves
 *    the hook's rule decisions, not the engine's reads (B does those).
 *    Its consent signatures are real. Kind 3 is exercised only there (the
 *    engine's kind-3 SYSTEM authorization is test_hf6_stake's B3).
 *  - B stops before the first boundary; C and D carry the rotation through
 *    the freeze, the swap and the sweep.
 *  - C's and D's freeze probes call nodus_witness_vset_preview_next, the
 *    same core commit_next runs, on a state edited inside a rolled-back
 *    transaction — they prove the pass on that state, not that the
 *    boundary would reach it. (f)'s and (h)'s "builds without candidates"
 *    prove the pass reads nothing then; that a gen-4 freeze with no
 *    pending row is byte-identical to the pre-6d builder is pinned by
 *    (f)'s expected bytes, built from the stored S(3E) with the three
 *    entries put back under their current keys.
 *  - The B4 arm of the distribution (entry key == the row's PENDING key)
 *    is no longer reached on any path here: with the 6d swap placed after
 *    the distribution, strict equality holds at U and at U+E.
 *  - F61 / F62 (D-F, E, C6): that the stage fires AFTER the step's writes is
 *    read from the source (nodus_witness_v2_epoch.c, steps 1d / 3d), not
 *    observed — the test proves that the injected block faults (so the
 *    stage fired: the clean block with the same inputs commits) and that
 *    nothing it wrote survives. The faulted apply runs on A's witness
 *    handle; in-memory state it may leave there is not compared (the C7b
 *    caveat). They go around v2x_cmt_injected (v2_genesis_fixture.h),
 *    whose class table does not list 61 / 62.
 *  - E covers the graduation at U+E of a validator that UNSTAKEd; one
 *    AUTO_RETIRED by Rule N at U (the other way to miss S(U+E)) takes the
 *    same graduation and sweep path but is not driven here.
 *  - The Comet side of a rotation is test_cmt_app's
 *    t_val_updates_rotation (a hand-written S(E)), not driven from here:
 *    this fixture has no host pipeline.
 *  - C runs ~4E blocks per twin, D ~7E, E ~5E, F ~3E (2880 / 5040 / 3600
 *    / 2160 at the production E = 720).
 *  - C7b applies a FAULTING boundary on twin A and then continues on A:
 *    the digest check after it covers the database only. In-memory
 *    state the aborted apply may have left in A's witness handle is not
 *    compared — if A and B later diverge at 4E, suspect this probe first
 *    (a production node does the same: the faulted block is rolled back
 *    and the decided block re-applied).
 *  - B's genesis UTXOs are SEEDED (V2X_SEED_NOT_REAL_UTXOS); the reward
 *    pool is non-zero by hand (the test_v2_econ device).
 *  - K calls the self-check's core directly after each committed block;
 *    that the boundary's log-only wrapper calls the same core, and that
 *    it logs rather than returns, is read from the source
 *    (nodus_witness_v2_epoch.c step 7), not observed — no log is
 *    captured. K2-K4 corrupt the table / a snapshot inside a rolled-back
 *    transaction and call the core there; they prove the comparison, not
 *    that any writer could produce that state.
 *  - Khan A8 (C6): every A8 release here reads a RULESET-2 S(F) (S(2E));
 *    the swap's ruleset-1 bridge arm (U = 2E, S(F) = the genesis S(E))
 *    is not driven end to end — no fixture rotation reaches U = 2E (a
 *    genesis seat is Foundation-owned and cannot ROTATE here). The swap
 *    calls the same v2ep_member_in_snapshot the sweep and Rule N use.
 *  - The sweep's new "previous key = the key S(U − E) seats" check is
 *    driven only through its FAULT arms (C7c, D5x); its pass arm is every
 *    clean A2 release in D and E.
 *  - C6a's attendance row is PLANTED (on both twins), not earned: the
 *    fixture cannot seat a rotator in a set before S(F). It proves the
 *    swap → sweep hand-off deletes it at 3E; that the delete runs AFTER
 *    the digest of 3E (so that digest still folds it) is read from the
 *    source (steps 3b / 3d), not observed.
 *  - D4s's refusal is asserted as NODUS_V2_TX_ERR_EXEC with the ledger
 *    untouched; D5s (the same call, applied after the sweep) is what pins
 *    the refusal to the reservation and not to the call.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_native.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/cmt_pb.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/msig_wire.h"
#include "dnac/res_meter.h"
#include "dnac/valbind_wire.h"
#include "dnac/vset_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define FEE       ((uint64_t)DNAC_MIN_FEE_RAW)
#define TEN_M     ((uint64_t)DNAC_SELF_STAKE_AMOUNT)
#define SMIN      ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define RPOOL     10000000000000000ULL               /* 10^16 raw         */
#define PK_LEN    ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN   ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define SGN_LEN   ((size_t)NODUS_RT_AUTH_SIGNER_LEN)
#define AUTH1     (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define ROT_LEN   7291u           /* design §2 (K7): 64+2592+4627+8      */
#define STK_LEN   7301u           /* design §2 (K7): 64+2592+4627+8+2+8  */

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_VAL2       13u
#define OP_KEYRES     17u
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_CPK_OFF    128u
#define V2_PPK_OFF    (128u + 2592u)
#define V2_KEFF_OFF   (128u + 2u * 2592u)             /* 5312 */
#define V2_SELF_OFF   (V2_KEFF_OFF + 8u)
#define V2_COMM_OFF   (V2_SELF_OFF + 24u)
#define V2_STAT_OFF   (V2_COMM_OFF + 12u)
#define V2_SINCE_OFF  (V2_STAT_OFF + 1u)

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
/* the first epoch boundary >= h, written independently (khan A1) */
static uint64_t first_boundary(uint64_t h) {
    return ((h + E_LEN - 1) / E_LEN) * E_LEN;
}

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* V0..V6 the genesis committee; KO a single-key owner / funder, KX a
 * foreign key, K1..K3 the multisig keys; KC1 / KC2 consensus keys of
 * STAKEd validators, KN / KN2 rotation targets (case C adds KN1, a third
 * target, and KC3, a third STAKEd key — appended so every earlier key
 * keeps its seed) */
enum { V0, V1, V2, V3, V4, V5, V6, KO, KX, K1, K2, K3, KC1, KC2, KN, KN2,
       KN1, KC3, N_KEYS };
#define N_VAL 7
static sk_key_t g_k[N_KEYS];
/* the commit votes every block carries: V0..V6, plus — cases C and D only
 * — up to three extra voters in the slots after them (g_nvote up to
 * N_VAL + N_XVOTE) */
#define N_XVOTE 3
static uint8_t  g_vaddr[N_VAL + N_XVOTE][32];
static int32_t  g_vflag[N_VAL + N_XVOTE];
static size_t   g_nvote = N_VAL;

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x31 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    for (int i = 0; i < N_VAL; i++) {
        if (nodus_chain_config_derive_witness_id(g_k[i].pk, g_vaddr[i]) != 0)
            return -1;
        g_vflag[i] = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    return 0;
}

/* ══ the multisig descriptor M = 2-of-3 {K1, K2, K3} ══════════════════ */

static uint8_t g_dm[DNA_MSIG_MAX_DESC_LEN];
static size_t  g_dm_len;
static uint8_t g_am[64];                       /* address of M            */
static uint8_t g_an[64];                       /* a second (foreign) one  */

static void sort_keys(const int *ks, int n, int *ord) {
    for (int i = 0; i < n; i++) ord[i] = ks[i];
    for (int a = 1; a < n; a++)
        for (int b = a; b > 0 &&
             memcmp(g_k[ord[b - 1]].pk, g_k[ord[b]].pk, PK_LEN) > 0; b--) {
            int t = ord[b];
            ord[b] = ord[b - 1];
            ord[b - 1] = t;
        }
}

static int desc_make(void) {
    static uint8_t keys[3 * 2592];
    const int km[3] = { K1, K2, K3 };
    int ord[3];
    sort_keys(km, 3, ord);
    for (int i = 0; i < 3; i++)
        memcpy(keys + (size_t)i * PK_LEN, g_k[ord[i]].pk, PK_LEN);
    if (dna_msig_desc_encode(2, 3, keys, g_dm, DNA_MSIG_MAX_DESC_LEN,
                             &g_dm_len) != 0)
        return -1;
    if (dna_msig_address(g_dm, g_dm_len, g_am) != 0) return -1;
    memset(g_an, 0xA7, sizeof(g_an));
    return 0;
}

/* ══ the ROTATE call and its consent ══════════════════════════════════ */

/* How the consent is formed (H3 variants). */
enum {
    CS_OK = 0,        /* the §6.1 ROTATE message, ctx "nodus.valbind.v1" */
    CS_OP_STAKE,      /* op 1 (STAKE) with the zero subject              */
    CS_SUBJ_ZERO,     /* op 2 with an all-zero subject (hand-built: the
                       * codec refuses to build it)                      */
    CS_SUBJ_OTHER,    /* op 2 naming another validator_id                */
    CS_OWNER_OTHER,   /* another owner_fp in the signed message          */
    CS_CHAIN_OTHER,   /* another chain id                                */
    CS_KEY_OLD,       /* signed by the row's CURRENT key's sk            */
    CS_CTX_OTHER      /* ctx "nodus.valbind.v2"                          */
};

/* validator_id ‖ new_pk ‖ consent_sig ‖ expiry. `owner` is the owner the
 * consent names (the committed row's, for a valid one); `old_key` the
 * row's current key (CS_KEY_OLD). @return ROT_LEN / 0 on setup failure. */
static uint32_t rot_call(uint8_t *dst, const uint8_t chain32[32],
                         const uint8_t vid[64], const uint8_t owner[64],
                         int new_key, int old_key, uint64_t expiry,
                         int variant) {
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    uint8_t chain[32], own[64], subj[64];
    uint8_t op = DNA_VALBIND_OP_ROTATE;
    memcpy(chain, chain32, 32);
    memcpy(own, owner, 64);
    memcpy(subj, vid, 64);
    if (variant == CS_CHAIN_OTHER) chain[0] ^= 0x01;
    if (variant == CS_OWNER_OTHER) own[0] ^= 0x01;
    if (variant == CS_SUBJ_OTHER) subj[0] ^= 0x01;
    if (variant == CS_OP_STAKE) {
        op = DNA_VALBIND_OP_STAKE;
        memset(subj, 0, sizeof(subj));
    }
    if (dna_valbind_consent_msg(msg, chain, op, subj, own, g_k[new_key].pk,
                                expiry) != 0)
        return 0;
    uint8_t *sig = dst + 64 + PK_LEN;
    size_t sl = 0;
    int rc;
    static const uint8_t ctx1[] = "nodus.valbind.v1";
    static const uint8_t ctx2[] = "nodus.valbind.v2";
    if (variant == CS_SUBJ_ZERO) {
        /* the codec refuses op 2 with a zero subject on build AND sign, so
         * the 2765 bytes are zeroed by hand and signed with the right ctx */
        memset(msg + DNA_VALBIND_OFF_SUBJECT, 0, DNA_VALBIND_SUBJECT_LEN);
        rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg), ctx1, 16,
                                g_k[new_key].sk);
    } else if (variant == CS_CTX_OTHER) {
        rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg), ctx2, 16,
                                g_k[new_key].sk);
    } else {
        rc = dna_valbind_consent_sign(sig, &sl, msg,
                                      g_k[variant == CS_KEY_OLD ? old_key
                                                                : new_key].sk);
    }
    if (rc != 0 || sl != SIG_LEN) return 0;
    memcpy(dst, vid, 64);
    memcpy(dst + 64, g_k[new_key].pk, PK_LEN);
    put64(dst + 64 + PK_LEN + SIG_LEN, expiry);
    return ROT_LEN;
}

/* SYSFUND call: in_count ‖ nullifier ‖ out_count 0 */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64]) {
    dst[0] = 1;
    memcpy(dst + 1, nul, 64);
    dst[65] = 0;
    return 66u;
}

/* ══ A. the table ════════════════════════════════════════════════════ */

/* the rt_owns_runtime_op scan (nodus_witness_v2_apply.c — static there) */
static int owns(const nodus_domain_runtime_t *rt, uint32_t op) {
    const dna_ruleset_desc_t *d = &rt->descriptor;
    for (size_t i = 0; i < d->rule_count; i++) {
        if (d->rule_ids[i] == op) return 1;
        if (d->rule_ids[i] > op) break;
    }
    return 0;
}

/* ══ H. hook level ═══════════════════════════════════════════════════ */

/* sibling shapes for hk_build */
enum { SIB_OK = 0, SIB_BAD_CALL, SIB_SPEND };

typedef struct {
    uint8_t  fund[66];
    uint8_t  auth[2][AUTH1];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

static int hk_build(hk_env_t *e, const uint8_t *call, uint32_t call_len,
                    uint8_t sys_kind, int sib) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul);
    if (sib == SIB_BAD_CALL) fl = 65u;          /* truncated: no out_count */
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = DNA_SYSRULE_ROTATE_CONSENSUS_KEY;
    legs[0].hdr.ruleset_version = 9;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = sys_kind;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH1;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = e->auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = sib == SIB_SPEND ? DNA_CORERULE_SPEND
                                              : DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = 7;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH1;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = e->fund;
    legs[1].auth_data = e->auth[1];
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0)
        return -1;
    return dna_env_decode(e->bytes, e->len, &e->view);
}

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];

static void ctx_reset(uint64_t height) {
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_chain, 0x4C, sizeof(g_chain));
    memset(g_intent, 0x5D, sizeof(g_intent));
    memset(g_dig, 0x3C, sizeof(g_dig));
    g_ctx.chain_id = g_chain;
    g_ctx.global_height = height;
    g_ctx.epoch = height / E_LEN;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
}

static void av_k1(int key) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], g_k[key].fp, 64);
}

static void av_k3(const uint8_t addr[64]) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 2;
    memcpy(g_av.signer_fp[0], g_k[K1].fp, 64);
    memcpy(g_av.signer_fp[1], g_k[K2].fp, 64);
    g_av.n_msig = 1;
    memcpy(g_av.msig_addr[0], addr, 64);
    g_av.msig_satisfied[0] = 1;
    g_av.msig_signers_in_desc = 1u;
}

static nodus_rt_read_res_t g_reads[4];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* the observed §6.3 record (op 13 value) of validator `vid`: owner, the
 * current key `cpk`, `status`, pending key `ppk` (-1 = none) with epoch
 * `keff`; self 2M, commission 500, active since 1 */
static void row_make(uint8_t rec[V2_REC_LEN], const uint8_t vid[64],
                     const uint8_t owner[64], int cpk, uint8_t status,
                     int ppk, uint64_t keff) {
    memset(rec, 0, V2_REC_LEN);
    memcpy(rec, vid, 64);
    memcpy(rec + V2_OWNER_OFF, owner, 64);
    memcpy(rec + V2_CPK_OFF, g_k[cpk].pk, PK_LEN);
    if (ppk >= 0) {
        memcpy(rec + V2_PPK_OFF, g_k[ppk].pk, PK_LEN);
        put64(rec + V2_KEFF_OFF, keff);
    }
    put64(rec + V2_SELF_OFF, SMIN);
    rec[V2_COMM_OFF] = 0x01;
    rec[V2_COMM_OFF + 1] = 0xF4;                       /* 500 bps         */
    rec[V2_STAT_OFF] = status;
    put64(rec + V2_SINCE_OFF, 1);
}

/* the two reads of a ROTATE that may apply: the row present, the key
 * absent */
static void rd_row(const uint8_t rec[V2_REC_LEN]) {
    memset(g_reads, 0, sizeof(g_reads));
    g_reads[0].present = 1;
    g_reads[0].value_len = V2_REC_LEN;
    memcpy(g_reads[0].value, rec, V2_REC_LEN);
}

static int sys_exec(const nodus_domain_runtime_t *rt, const hk_env_t *e,
                    uint16_t n_reads, dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, &e->view, 0, &g_ctx, g_reads, n_reads,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int sys_plan(const nodus_domain_runtime_t *rt, const hk_env_t *e,
                    nodus_rt_read_req_t *rq, uint16_t *n) {
    return nodus_rt_system_read_plan(rt, &e->view, 0, &g_ctx, rq,
                                     NODUS_RT_MAX_READS, n);
}

/* hook fixture: validator VA (owner KO, current key V0); VB another id */
static uint8_t g_va[64], g_vb[64];

/* build + exec one variant against row `rec` with the "may apply" reads;
 * @return exec rc */
static int try_rot(const nodus_domain_runtime_t *s4, hk_env_t *e,
                   uint8_t *call, const uint8_t rec[V2_REC_LEN],
                   const uint8_t owner[64], int new_key, uint64_t expiry,
                   int variant, uint8_t kind) {
    if (rot_call(call, g_chain, g_va, owner, new_key, V0, expiry, variant)
        != ROT_LEN)
        return -100;
    if (hk_build(e, call, ROT_LEN, kind, SIB_OK) != 0) return -101;
    rd_row(rec);
    return sys_exec(s4, e, 2, NULL);
}

static int t_table(void) {
    const uint32_t OP = DNA_SYSRULE_ROTATE_CONSENSUS_KEY;
    CHECK(OP == 10u, "ROTATE_CONSENSUS_KEY is runtime_op 10 (design §2)");
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "the compiled table passes its selfcheck (the oracle pins and "
          "the generation-4 vote literal re-derive)");

    for (uint32_t g = 1; g <= NODUS_RT_GEN_STORAGE; g++) {
        const nodus_domain_runtime_t *s =
            nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c =
            nodus_runtime_for_generation(g, DNA_DOMAIN_CORE);
        CHECK(s && c, "generations 1..4 compiled");
        CHECK(owns(c, OP) == 0, "no CORE descriptor owns op 10");
        CHECK(owns(s, OP) == (g == NODUS_RT_GEN_STORAGE),
              "only the generation-4 SYSTEM descriptor owns op 10");
        uint64_t w = 0;
        int priced = s->meter_policy &&
                     dna_meter_op_weight(s->meter_policy, OP, &w) == 0;
        CHECK(priced == (g == NODUS_RT_GEN_STORAGE),
              "only the generation-4 SYSTEM policy prices op 10");
        if (priced) CHECK(w == 1u, "at weight 1");
    }
    {
        const nodus_domain_runtime_t *s4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_CORE);
        CHECK(s4->ruleset_version == 9 && c4->ruleset_version == 7,
              "the generation-4 versions stay SYSTEM 9 / CORE 7 (A6)");
        CHECK(s4->descriptor.rule_count == 10 &&
              s4->descriptor.rule_ids[9] == OP,
              "SYSTEM v9 rules {1..10}");
        uint64_t d = 0;
        CHECK(nodus_runtime_gen4_vote_digest(&d) == 0 &&
              d == (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D,
              "the generation-4 vote D4 re-derives from the re-pinned "
              "hashes (HF-6 slice 8c: the param-18 vote)");
    }

    /* A3: below generation 4 every SYSTEM hook refuses op 10 */
    {
        static hk_env_t e;
        static uint8_t call[ROT_LEN];
        static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
        memset(call, 0x5A, sizeof(call));
        CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                       SIB_OK) == 0, "an op-10 envelope");
        ctx_reset(10);
        av_k1(KO);
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        for (uint32_t g = 0; g < NODUS_RT_GEN_STORAGE; g++) {
            const nodus_domain_runtime_t *s =
                g ? nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM)
                  : NULL;
            uint16_t n = 0;
            size_t rl = 0;
            CHECK(nodus_rt_system_read_plan(s, &e.view, 0, &g_ctx, rq,
                                            NODUS_RT_MAX_READS, &n) == -1,
                  "op 10's read plan refuses (-1) below generation 4");
            CHECK(nodus_rt_system_exec(s, &e.view, 0, &g_ctx, NULL, 0, res,
                                       sizeof(res), &rl) == -1,
                  "op 10's exec refuses (-1) below generation 4");
        }
    }
    return 0;
}

static int t_hooks(void) {
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_CORE);
    CHECK(s4 && s3 && c4 && c3, "generations 3 and 4 compiled");

    static hk_env_t e;
    static uint8_t call[ROT_LEN + 8];
    static uint8_t row[V2_REC_LEN], row2[V2_REC_LEN];
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    uint16_t n = 0;
    dna_effect_view_t ev;
    const uint64_t H = 9;
    const uint64_t EXP = H + 100;
    ctx_reset(H);
    memset(g_va, 0x2A, sizeof(g_va));
    memset(g_vb, 0x2B, sizeof(g_vb));

    uint8_t khn[64];
    CHECK(qgp_sha3_512(g_k[KN].pk, PK_LEN, khn) == 0, "key hash");
    row_make(row, g_va, g_k[KO].fp, V0, (uint8_t)DNAC_VALIDATOR_ACTIVE, -1,
             0);

    /* ── H1. the plan and the length ───────────────────────────────── */
    CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
          == ROT_LEN, "a 7291-byte call");
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_OK) == 0, "env");
    CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 2, "ROTATE: 2 reads");
    CHECK(rq[0].op_id == OP_VAL2 && rq[0].key_len == 64 &&
          memcmp(rq[0].key, g_va, 64) == 0,
          "read 0: op 13 keyed by the call's validator_id");
    CHECK(rq[1].op_id == OP_KEYRES && rq[1].key_len == 64 &&
          memcmp(rq[1].key, khn, 64) == 0,
          "read 1: op 17 keyed by SHA3-512(new_pk)");
    for (int d = -1; d <= 1; d += 2) {
        CHECK(hk_build(&e, call, (uint32_t)((int)ROT_LEN + d),
                       NODUS_RT_AUTHKIND_DSA87_MULTI_V1, SIB_OK) == 0,
              "env ± 1");
        av_k1(KO);
        rd_row(row);
        CHECK(sys_plan(s4, &e, rq, &n) == -1, "7291 ± 1 refused (plan)");
        CHECK(sys_exec(s4, &e, 2, NULL) == -1, "7291 ± 1 refused (exec)");
    }
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_OK) == 0, "env");
    CHECK(sys_plan(s3, &e, rq, &n) == -1,
          "the generation-3 runtime refuses the ROTATE");

    /* ── H2. positives ─────────────────────────────────────────────── */
    av_k1(KO);
    rd_row(row);
    CHECK(sys_exec(s4, &e, 2, &ev) == 0 && ev.effect_count == 2,
          "kind-1 owner, ACTIVE row: applies, exactly two effects");
    {
        const uint8_t *v0 = ev.buf + ev.val_off[0];
        const uint8_t *v1 = ev.buf + ev.val_off[1];
        uint8_t vh[DNA_EFFECT_HASH_LEN];
        CHECK(ev.eff[0].op_id == OP_KEYRES &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].key_len == 64 &&
              memcmp(ev.buf + ev.key_off[0], khn, 64) == 0 &&
              ev.eff[0].value_len == 65 && memcmp(v0, g_va, 64) == 0 &&
              v0[64] == (uint8_t)NODUS_V2_KEY_ROLE_PENDING && v0[64] == 2u,
              "effect 0: CREATE op 17 — SHA3-512(new_pk) -> validator_id, "
              "role 2 (pending)");
        CHECK(dna_effect_value_hash(row, V2_REC_LEN, vh) == 0 &&
              ev.eff[1].op_id == OP_VAL2 &&
              ev.eff[1].effect_kind == DNA_EFFECT_SET &&
              ev.eff[1].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
              memcmp(ev.eff[1].expected_vhash, vh, sizeof(vh)) == 0 &&
              ev.eff[1].key_len == 64 &&
              memcmp(ev.buf + ev.key_off[1], g_va, 64) == 0 &&
              ev.eff[1].value_len == V2_REC_LEN,
              "effect 1: SET op 13 under validator_id, bound to the "
              "observed row's hash");
        CHECK(memcmp(v1 + V2_PPK_OFF, g_k[KN].pk, PK_LEN) == 0 &&
              get64(v1 + V2_KEFF_OFF) == first_boundary(H) &&
              first_boundary(H) == E_LEN,
              "the row carries pending = new_pk and epoch F = the first "
              "boundary >= h (A1)");
        CHECK(memcmp(v1, row, V2_PPK_OFF) == 0 &&
              memcmp(v1 + V2_KEFF_OFF + 8, row + V2_KEFF_OFF + 8,
                     V2_REC_LEN - (V2_KEFF_OFF + 8)) == 0,
              "nothing else in the row moves (consensus key, owner, stake, "
              "status, Rule K stamp unchanged)");
    }
    {
        /* F at and just past a boundary */
        const uint64_t hs[2] = { E_LEN, E_LEN + 1 };
        const uint64_t fs[2] = { E_LEN, 2 * E_LEN };
        for (int i = 0; i < 2; i++) {
            ctx_reset(hs[i]);
            av_k1(KO);
            CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0,
                           hs[i] + 1, CS_OK) == ROT_LEN &&
                  hk_build(&e, call, ROT_LEN,
                           NODUS_RT_AUTHKIND_DSA87_MULTI_V1, SIB_OK) == 0,
                  "env");
            rd_row(row);
            CHECK(sys_exec(s4, &e, 2, &ev) == 0 &&
                  get64(ev.buf + ev.val_off[1] + V2_KEFF_OFF) == fs[i],
                  "F = h at a boundary (a ROTATE committed AT F is "
                  "included), the next boundary one block later");
        }
        ctx_reset(H);
    }
    av_k1(KO);
    row_make(row2, g_va, g_k[KO].fp, V0, (uint8_t)DNAC_VALIDATOR_ELIGIBLE,
             -1, 0);
    CHECK(try_rot(s4, &e, call, row2, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "kind-1 owner, ELIGIBLE row: applies");
    row_make(row2, g_va, g_am, V0, (uint8_t)DNAC_VALIDATOR_ACTIVE, -1, 0);
    av_k3(g_am);
    CHECK(try_rot(s4, &e, call, row2, g_am, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0,
          "kind-3 owner (2-of-3 address): applies");

    /* ── H3. refusals ──────────────────────────────────────────────── */
    av_k1(KO);
    CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
          == ROT_LEN && hk_build(&e, call, ROT_LEN,
                                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, SIB_OK)
          == 0, "env");
    memset(g_reads, 0, sizeof(g_reads));
    CHECK(sys_exec(s4, &e, 2, NULL) == -1, "unknown validator_id: -1");
    rd_row(row);
    CHECK(sys_exec(s4, &e, 1, NULL) == -2, "one read: a node fault");

    av_k1(KX);
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "kind 1 by a non-owner refused");
    av_k3(g_an);
    CHECK(try_rot(s4, &e, call, row2, g_am, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == -1,
          "kind 3 with another address refused");
    av_k1(KO);
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_CC_V1) == -1, "kind 2 refused");
    {
        static const uint8_t bad_st[3] = {
            (uint8_t)DNAC_VALIDATOR_RETIRING,
            (uint8_t)DNAC_VALIDATOR_UNSTAKED,
            (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED
        };
        for (int i = 0; i < 3; i++) {
            row_make(row2, g_va, g_k[KO].fp, V0, bad_st[i], -1, 0);
            CHECK(try_rot(s4, &e, call, row2, g_k[KO].fp, KN, EXP, CS_OK,
                          NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
                  "RETIRING / UNSTAKED / AUTO_RETIRED refused (A5)");
        }
    }
    row_make(row2, g_va, g_k[KO].fp, V0, (uint8_t)DNAC_VALIDATOR_ACTIVE, KN2,
             E_LEN);
    CHECK(try_rot(s4, &e, call, row2, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "a pending key already set: the second ROTATE refused (§3)");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, V0, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "new_pk == the row's current key refused (with the reservation "
          "read fabricated absent: the explicit check decides)");
    for (uint8_t role = 1; role <= 2; role++) {
        CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
              == ROT_LEN && hk_build(&e, call, ROT_LEN,
                                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                                     SIB_OK) == 0, "env");
        rd_row(row);
        g_reads[1].present = 1;
        g_reads[1].value_len = 65;
        memcpy(g_reads[1].value, g_vb, 64);
        g_reads[1].value[64] = role;
        CHECK(sys_exec(s4, &e, 2, NULL) == -1,
              "new_pk reserved by another validator (role 1, then role 2) "
              "refused (§4)");
    }
    g_reads[1].value_len = 64;
    CHECK(sys_exec(s4, &e, 2, NULL) == -2,
          "a reservation answer outside the adapter contract: -2");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H - 1, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "expiry h - 1 refused");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H + 721, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "expiry h + 721 refused");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "expiry h accepted");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H + 720, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "expiry h + 720 accepted");
    {
        static const struct { int v; const char *what; } bad[] = {
            { CS_OP_STAKE,    "a STAKE (op 1) consent" },
            { CS_SUBJ_ZERO,   "an all-zero subject" },
            { CS_SUBJ_OTHER,  "another validator's id as subject" },
            { CS_OWNER_OTHER, "a consent for another owner" },
            { CS_CHAIN_OTHER, "a consent for another chain" },
            { CS_KEY_OLD,     "the OLD key's signature" },
            { CS_CTX_OTHER,   "ctx nodus.valbind.v2" },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            int rc = try_rot(s4, &e, call, row, g_k[KO].fp, KN, EXP,
                             bad[i].v, NODUS_RT_AUTHKIND_DSA87_MULTI_V1);
            if (rc != -1)
                fprintf(stderr, "consent variant: %s -> %d\n", bad[i].what,
                        rc);
            CHECK(rc == -1, "a bad consent is a verdict (-1)");
        }
    }
    CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
          == ROT_LEN, "call");
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_BAD_CALL) == 0, "env with a truncated SYSFUND call");
    rd_row(row);
    CHECK(sys_exec(s4, &e, 2, NULL) == -1, "a malformed SYSFUND sibling: -1");
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_SPEND) == 0, "env with a SPEND sibling");
    rd_row(row);
    CHECK(sys_exec(s4, &e, 2, NULL) == -1, "a non-SYSFUND sibling: -1");
    CHECK(sys_plan(s4, &e, rq, &n) == -1, "and its plan: -1");

    /* ── H4. CORE pairing and the describer ────────────────────────── */
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_OK) == 0, "env");
    {
        nodus_rt_read_req_t cr[NODUS_RT_MAX_READS];
        uint16_t cn = 0;
        CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2, "gen-4 CORE: the ROTATE sibling plans inputs + pool");
        CHECK(nodus_rt_core_read_plan(c3, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == -1,
              "gen-3 CORE: SYSFUND does not pair with op 10");
        nodus_rt_leg_desc_t d;
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == 0
              && d.rec == NODUS_RT_DESC_REC_NONE &&
              d.runtime_op == DNA_SYSRULE_ROTATE_CONSENSUS_KEY,
              "describer: an applied ROTATE is described, no record kind");
        CHECK(nodus_rt_native_describe_leg(&e.view, 1, H, g_intent, &d) == 0
              && d.n_consumed == 1 && d.n_created == 0,
              "describer: the SYSFUND sibling consumes its input, creates "
              "nothing (fee-only, A4)");
    }
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

/* every coin is KO's: S* fund a STAKE (bond STAKE_MIN + FEE), R* a
 * ROTATE, an UNSTAKE or an admission probe (exactly FEE — neither locks
 * anything). S3 (case C's third STAKE) is appended last so every earlier
 * coin keeps its nullifier; case B leaves it an unused FEE coin. */
enum { S1, S2, R1, R2, R3, R4, R5, R6, S3, N_COINS };
static uint8_t  g_nul[N_COINS][64];
static uint64_t g_amt[N_COINS];

#define H9   2u
#define HE   3u
#define H14  4u       /* param 18: the gen-4 edge runs in block H14 − 1 */

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[KO].hex, 128);
    memset(pre + 128, 0x61 + c, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coin(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_bind_text(st, 2, g_k[KO].hex, 128, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_bind_int64(st, 3, (sqlite3_int64)g_amt[c]) == SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_bind_int64(st, 1, (sqlite3_int64)param) == SQLITE_OK &&
        sqlite3_bind_int64(st, 2, (sqlite3_int64)value) == SQLITE_OK &&
        sqlite3_bind_int64(st, 3, (sqlite3_int64)effective) == SQLITE_OK &&
        sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce) == SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int seed_val(nodus_witness_t *w, int k) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PK_LEN);
    v.self_stake = TEN_M;
    v.commission_bps = 500;
    v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
    v.active_since_block = 1;
    memcpy(v.unstake_destination_fp, g_k[k].hex, 129);
    return nodus_validator_insert(w, &v);
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));          /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_rotate_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x6E, sizeof(fx->chain16));
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
               H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, H14, 13) != 0)
        return -1;
    uint64_t total = 0;
    for (int i = 0; i < N_VAL; i++) {
        if (seed_val(w, i) != 0) return -1;
        total += TEN_M;
    }
    for (int c = 0; c < N_COINS; c++) {
        if (seed_coin(w, c) != 0) return -1;
        total += g_amt[c];
    }
    {
        /* not a real genesis: a non-zero reward pool (the test_v2_econ
         * device) and spendable coins; supply = bonds + coins + pool */
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, %llu)",
                 (unsigned long long)(total + RPOOL),
                 (unsigned long long)(total + RPOOL),
                 (unsigned long long)RPOOL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    return v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, NULL);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
    if (h > 1) {
        b->cmt.votes_address = (const uint8_t (*)[32])g_vaddr;
        b->cmt.votes_block_id_flag = g_vflag;
        b->cmt.votes_len = g_nvote;
    }
}

/* HF-6 key-reservation self-check (nodus_witness_v2_keyres_diff): the
 * count of differences at boundary `h`, or -1 when it did not compare
 * (rc != 0: generation < 4, an unreadable input, a bad argument). */
static long kr_diff(nodus_witness_t *w, uint64_t h) {
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    size_t n = 0;
    if (nodus_witness_v2_chain_id(w, chain32) != 0 ||
        nodus_witness_v2_keyres_diff(w, h, chain32, &n) != 0)
        return -1;
    return (long)n;
}

/* every generation-4 boundary apply_both commits: the self-check
 * compares (rc 0) and finds no difference. Below generation 4 it must
 * answer "not applicable" (rc 1). 0 / -1. */
static int g_kr_runs = 0;      /* boundaries the self-check compared at */
static int kr_boundary(nodus_witness_t *w, uint64_t h) {
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    size_t n = 0;
    if (nodus_witness_v2_chain_id(w, chain32) != 0) return -1;
    int rc = nodus_witness_v2_keyres_diff(w, h, chain32, &n);
    if (rc == 1) return 0;
    if (rc != 0 || n != 0) {
        fprintf(stderr, "boundary %llu: key-reservation self-check rc %d, "
                "%zu difference(s)\n", (unsigned long long)h, rc, n);
        return -1;
    }
    g_kr_runs++;
    return 0;
}

/* one block on both twins (0 or 1 envelope); the item codes agree and the
 * committed global roots agree; at an epoch boundary the key-reservation
 * self-check finds no difference on either twin (kr_boundary). *code =
 * the item's code. 0 / -1. */
static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const uint8_t *env, size_t len, uint32_t *code) {
    nodus_v2_envelope_t v[1] = { { env, len } };
    nodus_v2_tx_result_t ra[1], rb[1];
    nodus_v2_block_t ba, bb;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, env ? v : NULL, env ? 1 : 0);
    mk_block(&bb, h, env ? v : NULL, env ? 1 : 0);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 1;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 1;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0) {
        fprintf(stderr, "block %llu: %s | %s\n", (unsigned long long)h,
                ba.out_reason, bb.out_reason);
        return -1;
    }
    if (env && ra[0].code != rb[0].code) return -1;
    if (code) *code = env ? ra[0].code : 0;
    uint8_t ca[64], cb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        memcmp(ca, cb, 64) != 0) {
        fprintf(stderr, "block %llu: twin global roots differ\n",
                (unsigned long long)h);
        return -1;
    }
    if ((h % E_LEN) == 0 &&
        (kr_boundary(a->w, h) != 0 || kr_boundary(b->w, h) != 0))
        return -1;
    return 0;
}

static int run_to(fixture_t *a, fixture_t *b, uint64_t *h, uint64_t last) {
    while (*h < last) {
        if (apply_both(a, b, *h + 1, NULL, 0, NULL) != 0) return -1;
        (*h)++;
    }
    return 0;
}

/* A 2-leg {SYSTEM `op`, CORE SYSFUND} envelope against the registry's
 * CURRENT manifests, REALLY signed (two passes): the SYSTEM leg kind 1 by
 * KO, the CORE SYSFUND leg kind 1 by KO spending coin `c` entirely.
 * *intent_out (may be NULL) = the engine-derived intent_id.
 * @return 0 / -1. */
static int rec_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                   const uint8_t *call, uint32_t call_len, int c,
                   uint8_t **out, size_t *out_len, uint8_t *intent_out) {
    static uint8_t fund[66];
    static uint8_t sys_auth[AUTH1];
    static uint8_t core_auth[AUTH1];
    dna_domain_manifest_t sys, core;
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0
        || nodus_witness_v2_chain_id(w, chain32) != 0)
        return -1;
    uint32_t fl = fund_call(fund, g_nul[c]);
    memset(sys_auth, 0, sizeof(sys_auth));
    memset(core_auth, 0, sizeof(core_auth));

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH1;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = sys_auth;
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH1;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = core_auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys.ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core.ruleset_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        size_t sl = 0;
        sys_auth[0] = 1;
        memcpy(sys_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(sys_auth + 1 + PK_LEN, &sl, pf->auth_digest[0],
                           64, g_k[KO].sk) != 0)
            break;
        core_auth[0] = 1;
        memcpy(core_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(core_auth + 1 + PK_LEN, &sl, pf->auth_digest[1],
                           64, g_k[KO].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (intent_out) memcpy(intent_out, pf->intent_id, 64);
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* the generation-4 STAKE call (owner KO, key `ckey`, bond `bond` raw —
 * STAKE_MIN for cases B and C — commission 300) with its op-1 consent —
 * test_hf6_stake's layout. @return STK_LEN / 0. */
static uint32_t stake2_call(uint8_t *dst, const uint8_t chain32[32],
                            int ckey, uint64_t expiry, uint64_t bond) {
    static const uint8_t zero_subj[64] = { 0 };
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    if (dna_valbind_consent_msg(msg, chain32, DNA_VALBIND_OP_STAKE,
                                zero_subj, g_k[KO].fp, g_k[ckey].pk,
                                expiry) != 0)
        return 0;
    size_t sl = 0;
    if (dna_valbind_consent_sign(dst + 64 + PK_LEN, &sl, msg,
                                 g_k[ckey].sk) != 0 || sl != SIG_LEN)
        return 0;
    memcpy(dst, g_k[KO].fp, 64);
    memcpy(dst + 64, g_k[ckey].pk, PK_LEN);
    size_t off = 64 + PK_LEN + SIG_LEN;
    put64(dst + off, expiry);         off += 8;
    dst[off++] = 0x01;
    dst[off++] = 0x2C;                                 /* 300 bps         */
    put64(dst + off, bond);           off += 8;
    return off == STK_LEN ? STK_LEN : 0;
}

/* the independent §6.2 recomputation: SHA3-512("NDS.VALID.v1" + 4 × 0x00
 * ‖ chain32 ‖ intent_id) */
static int vid_expect(const uint8_t chain32[32], const uint8_t intent[64],
                      uint8_t out[64]) {
    uint8_t pre[16 + 32 + 64];
    memset(pre, 0, 16);
    memcpy(pre, "NDS.VALID.v1", 12);
    memcpy(pre + 16, chain32, 32);
    memcpy(pre + 48, intent, 64);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* SHA3-512 over the ledger tables' rows in key order — the state a
 * refused leg must leave untouched */
static int ledger_digest(nodus_witness_t *w, uint8_t out[64]) {
    static const char *const q[] = {
        "SELECT * FROM validators ORDER BY pubkey_hash",
        "SELECT * FROM v2_validator_roles ORDER BY validator_id",
        "SELECT * FROM v2_consensus_keys ORDER BY consensus_pk_hash",
        "SELECT * FROM delegations ORDER BY delegator_hash, validator_hash",
        "SELECT * FROM utxo_set ORDER BY nullifier",
        "SELECT * FROM supply_tracking ORDER BY id",
        "SELECT * FROM validator_stats ORDER BY key",
    };
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    int ok = 0;
    for (size_t i = 0; i < sizeof(q) / sizeof(q[0]) && ok == 0; i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, q[i], -1, &st, NULL) != SQLITE_OK) {
            ok = -1;
            break;
        }
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && ok == 0) {
            int nc = sqlite3_column_count(st);
            for (int c = 0; c < nc && ok == 0; c++) {
                int t = sqlite3_column_type(st, c);
                const void *p = NULL;
                int n = 0;
                sqlite3_int64 iv = 0;
                if (t == SQLITE_INTEGER) {
                    iv = sqlite3_column_int64(st, c);
                    p = &iv;
                    n = (int)sizeof(iv);
                } else if (t != SQLITE_NULL) {
                    p = sqlite3_column_blob(st, c);
                    n = sqlite3_column_bytes(st, c);
                }
                size_t need = len + 1 + 4 + (size_t)n;
                if (need > cap) {
                    size_t nc2 = cap;
                    while (nc2 < need) nc2 *= 2;
                    uint8_t *g = realloc(buf, nc2);
                    if (!g) { ok = -1; break; }
                    buf = g;
                    cap = nc2;
                }
                buf[len++] = (uint8_t)t;
                buf[len++] = (uint8_t)(n >> 24);
                buf[len++] = (uint8_t)(n >> 16);
                buf[len++] = (uint8_t)(n >> 8);
                buf[len++] = (uint8_t)n;
                if (n > 0 && p) memcpy(buf + len, p, (size_t)n);
                len += (size_t)n;
            }
        }
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) ok = -1;
        sqlite3_finalize(st);
    }
    if (ok == 0 && qgp_sha3_512(buf, len, out) != 0) ok = -1;
    free(buf);
    return ok;
}

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* Σutxo + Σself_stake + Σtotal_delegated + reward_pool — the value a
 * ROTATE only MOVES (its fee -> pool) */
static int value_sum(nodus_witness_t *w, uint64_t *out) {
    uint64_t u = 0, s = 0, p = 0;
    if (q_u64(w, "SELECT COALESCE(SUM(amount), 0) FROM utxo_set", &u) != 0 ||
        q_u64(w, "SELECT COALESCE(SUM(self_stake), 0) + "
              "COALESCE(SUM(total_delegated), 0) FROM validators", &s) != 0 ||
        q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
              &p) != 0)
        return -1;
    *out = u + s + p;
    return 0;
}

/* rows of utxo_set holding coin `c`: 1 unspent / 0 spent / -1 error */
static int coin_count(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    int out = -1;
    if (sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

/* the reservation of `pk`: 0 found (vid, role) / 1 absent / -1 */
static int key_of(nodus_witness_t *w, const uint8_t *pk, uint8_t vid[64],
                  uint8_t *role) {
    uint8_t kh[64];
    if (qgp_sha3_512(pk, PK_LEN, kh) != 0) return -1;
    return nodus_validator_v2_key_get(w, kh, vid, role);
}

/* one SYSTEM-`op` block expected REFUSED at exec with the ledger tables
 * untouched and the funding coin unspent */
static int env_refused(fixture_t *A, fixture_t *B, uint64_t h, uint32_t op,
                       const uint8_t *call, uint32_t len, int coin) {
    uint8_t *e = NULL, d0[64], d1[64];
    size_t l = 0;
    uint32_t code = 0;
    if (rec_env(A->w, h, op, call, len, coin, &e, &l, NULL) != 0)
        return -1;
    int ok = ledger_digest(A->w, d0) == 0 &&
             apply_both(A, B, h, e, l, &code) == 0 &&
             code == NODUS_V2_TX_ERR_EXEC &&
             ledger_digest(A->w, d1) == 0 && memcmp(d0, d1, 64) == 0 &&
             coin_count(A->w, coin) == 1;
    free(e);
    return ok ? 0 : -1;
}

/* one ROTATE block expected REFUSED with the ledger tables untouched */
static int rot_refused(fixture_t *A, fixture_t *B, uint64_t h,
                       const uint8_t *call, int coin) {
    return env_refused(A, B, h, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call,
                       ROT_LEN, coin);
}

static int t_engine(void) {
    fixture_t A, B;
    static uint8_t call[STK_LEN];
    uint8_t *e = NULL, intent[64], chain32[DNA_CHAIN_ID_LEN];
    uint8_t vid_a[64], vid_b[64], got[64], role = 0;
    size_t l = 0;
    uint64_t h = 0, sum0 = 0, sum1 = 0;
    uint32_t code = 0;

    CHECK(E_LEN >= 12, "no epoch boundary among heights 1..11");
    g_amt[S1] = SMIN + FEE;
    g_amt[S2] = SMIN + FEE;
    for (int c = R1; c < N_COINS; c++) g_amt[c] = FEE;
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    /* ── B1. block 3 (generation 3): refused at ADMISSION ──────────── */
    {
        uint8_t vid0[64];
        CHECK(dna_validator_id_migrated(vid0, chain32, g_k[V0].pk) == 0,
              "V0's migrated validator_id");
        CHECK(rot_call(call, chain32, vid0, g_k[V0].fp, KN, V0, HE + 100,
                       CS_OK) == ROT_LEN, "a 7291-byte call");
    }
    CHECK(run_to(&A, &B, &h, HE - 1) == 0, "blocks 1..2");
    CHECK(rec_env(A.w, HE, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                  R1, &e, &l, NULL) == 0, "an op-10 envelope at block 3");
    CHECK(apply_both(&A, &B, HE, e, l, &code) == 0 &&
          code == NODUS_V2_TX_ERR_ADMISSION,
          "generation 3: op 10 is refused at admission (unowned)");
    free(e); e = NULL;
    h = HE;
    /* block 3 also runs the generation-4 edge (the migration rewrites
     * the validator tables), so no whole-ledger comparison here: the
     * refused envelope's funding coin is what must survive */
    CHECK(coin_count(A.w, R1) == 1,
          "the refused envelope's funding coin is unspent");

    /* ── B2. block 4: STAKE opens V_A (owner KO, key KC1) ──────────── */
    CHECK(stake2_call(call, chain32, KC1, H14 + 100, SMIN) == STK_LEN,
          "call");
    CHECK(rec_env(A.w, H14, DNA_SYSRULE_STAKE, call, STK_LEN, S1, &e, &l,
                  intent) == 0, "envelope");
    CHECK(apply_both(&A, &B, H14, e, l, &code) == 0 &&
          code == NODUS_V2_TX_OK, "block 4: the STAKE applies");
    free(e); e = NULL;
    h = H14;
    CHECK(vid_expect(chain32, intent, vid_a) == 0, "V_A's validator_id");

    /* ── B3. block 5: ROTATE V_A -> KN applies ─────────────────────── */
    CHECK(value_sum(A.w, &sum0) == 0, "value before");
    CHECK(rot_call(call, chain32, vid_a, g_k[KO].fp, KN, KC1, 5 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rec_env(A.w, 5, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                  R2, &e, &l, NULL) == 0, "envelope");
    CHECK(apply_both(&A, &B, 5, e, l, &code) == 0 && code == NODUS_V2_TX_OK,
          "block 5: the kind-1 ROTATE applies");
    free(e); e = NULL;
    h = 5;
    {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        CHECK(r != NULL, "alloc");
        int ok = nodus_validator_v2_get(A.w, vid_a, r) == 0 &&
                 memcmp(r->pending_consensus_pubkey, g_k[KN].pk, PK_LEN)
                     == 0 &&
                 r->consensus_key_effective_epoch == first_boundary(5) &&
                 r->consensus_key_effective_epoch == E_LEN &&
                 memcmp(r->rec.pubkey, g_k[KC1].pk, PK_LEN) == 0 &&
                 memcmp(r->owner_fp, g_k[KO].fp, 64) == 0 &&
                 r->rec.status == DNAC_VALIDATOR_ACTIVE &&
                 r->rec.self_stake == SMIN &&
                 r->rec.last_validator_update_block == 0;
        free(r);
        CHECK(ok, "the §6.3 row: pending = KN, epoch F = E (A1), the "
              "consensus key still KC1, nothing else moved");
    }
    CHECK(key_of(A.w, g_k[KN].pk, got, &role) == 0 &&
          memcmp(got, vid_a, 64) == 0 && role == NODUS_V2_KEY_ROLE_PENDING,
          "KN reserved to V_A, role 2 (pending)");
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 0 &&
          memcmp(got, vid_a, 64) == 0 && role == NODUS_V2_KEY_ROLE_ACTIVE,
          "KC1 still reserved to V_A, role 1");
    CHECK(coin_count(A.w, R2) == 0, "the funding coin is consumed");
    CHECK(value_sum(A.w, &sum1) == 0 && sum1 == sum0,
          "Σutxo + Σstake + pool conserved (the fee -> pool; no lock, A4)");

    /* ── B4. block 6: a second ROTATE of V_A is refused ────────────── */
    CHECK(rot_call(call, chain32, vid_a, g_k[KO].fp, KN2, KC1, 6 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rot_refused(&A, &B, 6, call, R3) == 0,
          "block 6: a second ROTATE while one is pending is refused, the "
          "ledger tables byte-identical");
    h = 6;

    /* ── B5. V_B: the pending and the migrated keys are reserved ───── */
    CHECK(stake2_call(call, chain32, KC2, 7 + 100, SMIN) == STK_LEN,
          "call");
    CHECK(rec_env(A.w, 7, DNA_SYSRULE_STAKE, call, STK_LEN, S2, &e, &l,
                  intent) == 0, "envelope");
    CHECK(apply_both(&A, &B, 7, e, l, &code) == 0 && code == NODUS_V2_TX_OK,
          "block 7: the STAKE of V_B applies");
    free(e); e = NULL;
    h = 7;
    CHECK(vid_expect(chain32, intent, vid_b) == 0, "V_B's validator_id");
    CHECK(rot_call(call, chain32, vid_b, g_k[KO].fp, KN, KC2, 8 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rot_refused(&A, &B, 8, call, R4) == 0,
          "block 8: V_B -> KN (pending for V_A, role 2) refused");
    CHECK(rot_call(call, chain32, vid_b, g_k[KO].fp, V1, KC2, 9 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rot_refused(&A, &B, 9, call, R5) == 0,
          "block 9: V_B -> V1's key (role 1, the migration's) refused");
    h = 9;
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
    }
    fx_close(&A);
    fx_close(&B);
    return 0;
}

/* ══ C. slices 6c + 6d — rotate_apply, the freeze, the swap, the sweep
 *        for validators S(F) does not seat ═════════════════════════════
 *
 * Every state change reaches the chain through the engine — real STAKE,
 * ROTATE and UNSTAKE envelopes (case B's helpers). Since slice 6d the
 * freeze pass produces S(U) with the pending keys and the boundary swap
 * switches the rows; the 6c plant that stood in for both is gone. The
 * only direct writes are PROBES on twin A, each undone before the next
 * committed block (rolled-back transactions, or a faulting boundary the
 * host rolls back followed by a restore immediately before that same
 * boundary block — a boundary declares SYSTEM touched,
 * nodus_witness_v2_apply.c phase 6e `dsys->touched = 1`, so phase 8's
 * untouched-domain guard accepts a moved SYSTEM root only there), and A
 * is compared with B after each.
 *
 * Why the rotators are STAKEd rows, not genesis seats: a genesis seat's
 * owner is the compiled Foundation address (migration D2 (a), dnac.h
 * DNAC_HF6_FOUNDATION_OWNER) whose keys no test holds, so no test can
 * sign its ROTATE; a STAKEd row's owner is KO. A STAKEd row is first
 * seated in S(3E) (tenure: active_since + 2E <= e_start). ROTATEs in
 * blocks 7..9 have F = E: the freeze at E WAITS them (not seated in
 * S(2E)), the freeze at 2E accepts them with 0 in S(F) = S(2E) (khan A3),
 * U = 3E, U + E = 4E. Their previous keys are in NO committed snapshot,
 * so (khan A8, 2026-10-13) the swap at U releases them — the sweep at
 * U + E has nothing of theirs left. */

/* cases C and D: three STAKEd validators — consensus key, rotation
 * target, the STAKE coin; validator_ids filled from the STAKE intents */
enum { RA, RB, RC, N_ROT };
static const int g_ck[N_ROT] = { KC1, KC2, KC3 };
static const int g_tk[N_ROT] = { KN, KN2, KN1 };
static const int g_sc[N_ROT] = { S1, S2, S3 };
static uint8_t   g_rid[N_ROT][64];

/* one envelope block on both twins, expected APPLIED: 0 / -1 */
static int env_ok(fixture_t *A, fixture_t *B, uint64_t h, uint32_t op,
                  const uint8_t *call, uint32_t len, int coin,
                  uint8_t *intent) {
    uint8_t *e = NULL;
    size_t l = 0;
    uint32_t code = 0;
    if (rec_env(A->w, h, op, call, len, coin, &e, &l, intent) != 0)
        return -1;
    int ok = apply_both(A, B, h, e, l, &code) == 0 &&
             code == NODUS_V2_TX_OK;
    free(e);
    return ok ? 0 : -1;
}

/* rows of v2_consensus_keys naming `vid` with `role`: count / -1 */
static int keys_naming(nodus_witness_t *w, const uint8_t vid[64],
                       unsigned role) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM v2_consensus_keys "
            "WHERE validator_id = ?1 AND role = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    int out = -1;
    if (sqlite3_bind_blob(st, 1, vid, 64, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int(st, 2, (int)role) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

/* One ROLLED-BACK edit on `w` (`sql` binds ?1 / ?2 to the 64-byte blobs
 * b1 / b2 when non-NULL; EXACTLY one row must change), then the
 * key-reservation self-check's count at boundary `h` inside the same
 * transaction. The count / -1 (the edit did not apply as written, the
 * check did not compare, or the rollback failed). */
static long kr_probe(nodus_witness_t *w, uint64_t h, const char *sql,
                     const uint8_t *b1, const uint8_t *b2) {
    if (v2x_sql(w->db, "BEGIN IMMEDIATE") != 0) return -1;
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) == SQLITE_OK &&
             (!b1 || sqlite3_bind_blob(st, 1, b1, 64, SQLITE_TRANSIENT)
                         == SQLITE_OK) &&
             (!b2 || sqlite3_bind_blob(st, 2, b2, 64, SQLITE_TRANSIENT)
                         == SQLITE_OK) &&
             sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) == 1;
    if (st) sqlite3_finalize(st);
    long n = ok ? kr_diff(w, h) : -1;
    if (v2x_sql(w->db, "ROLLBACK") != 0) n = -1;
    w->cached_committee_epoch_start = UINT64_MAX;
    return n;
}

#define KR_SQL_ADD  "INSERT INTO v2_consensus_keys (consensus_pk_hash, " \
                    "validator_id, role) VALUES (?1, ?2, 1)"
#define KR_SQL_DEL  "DELETE FROM v2_consensus_keys WHERE consensus_pk_hash = ?1"
#define KR_SQL_ROLE "UPDATE v2_consensus_keys SET role = 3 - role " \
                    "WHERE consensus_pk_hash = ?1"
#define KR_SQL_VID  "UPDATE v2_consensus_keys SET validator_id = ?2 " \
                    "WHERE consensus_pk_hash = ?1"

/* SHA3-512(g_k[key].pk) — the reservation's key column */
static int kh_of(int key, uint8_t out[64]) {
    return qgp_sha3_512(g_k[key].pk, PK_LEN, out);
}

/* the v2 row of `vid`: (status, consensus key == key `ck`, pending ==
 * key `pk` or all-zero when pk < 0, effective epoch, missed counter) */
typedef struct {
    uint8_t  status;
    int      cur_is;      /* rec.pubkey == g_k[ck].pk                     */
    int      pend_is;     /* pending == g_k[pk].pk / all-zero if pk < 0   */
    uint64_t epoch;
    uint64_t missed;
} rowv_t;

static int row_view(nodus_witness_t *w, const uint8_t vid[64], int ck,
                    int pk, rowv_t *o) {
    static const uint8_t zero[QGP_DSA87_PUBLICKEYBYTES] = { 0 };
    nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
    int ok = -1;
    if (r && nodus_validator_v2_get(w, vid, r) == 0) {
        o->status = r->rec.status;
        o->cur_is = memcmp(r->rec.pubkey, g_k[ck].pk, PK_LEN) == 0;
        o->pend_is = memcmp(r->pending_consensus_pubkey,
                            pk < 0 ? zero : g_k[pk].pk, PK_LEN) == 0;
        o->epoch = r->consensus_key_effective_epoch;
        o->missed = r->rec.consecutive_missed_epochs;
        ok = 0;
    }
    free(r);
    return ok;
}

/* The canonical bytes of `s` (its own ruleset's layout) into *out (heap,
 * free()), *len. 0 / -1. */
static int snap_bytes(const dna_vset_snapshot_t *s, uint8_t **out,
                      size_t *len) {
    *out = NULL;
    size_t need = dna_vset_encoded_len_ex(s, DNA_VSET_RULESET_TOPN_V2);
    size_t used = 0;
    uint8_t *b = need ? malloc(need) : NULL;
    if (!b || dna_vset_encode_ex(s, DNA_VSET_RULESET_TOPN_V2, b, need,
                                 &used) != 0 || used != need) {
        free(b);
        return -1;
    }
    *out = b;
    *len = need;
    return 0;
}

/* Overwrite the STORED snapshot row of s->epoch with `s` (any ruleset;
 * the hash re-derived under the tag its header names) and drop the
 * committee cache so no reader serves the old set. In a transaction.
 * 0 / -1. Rewriting a stored, hash-committed row is safe in this fixture:
 * the host builds every block record from the genesis state
 * (v2_genesis_fixture.h v2x_cmt_store_block) — no block links to this
 * snapshot's hash — and every rewrite that reaches a committed block is
 * applied to both twins (the probes roll theirs back). */
static int snap_store(nodus_witness_t *w, const dna_vset_snapshot_t *s) {
    uint8_t *buf = NULL, hash[DNA_VSET_HASH_LEN];
    size_t len = 0;
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (snap_bytes(s, &buf, &len) == 0 &&
        dna_vset_hash_bytes_ex(buf, len, DNA_VSET_RULESET_TOPN_V2,
                               hash) == 0 &&
        sqlite3_prepare_v2(w->db,
            "UPDATE validator_set_snapshots SET snapshot_blob = ?1, "
            "snapshot_hash = ?2, active_count = ?3 WHERE epoch_start = ?4",
            -1, &st, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(st, 1, buf, (int)len, SQLITE_TRANSIENT)
            == SQLITE_OK &&
        sqlite3_bind_blob(st, 2, hash, DNA_VSET_HASH_LEN, SQLITE_TRANSIENT)
            == SQLITE_OK &&
        sqlite3_bind_int(st, 3, (int)s->active_count) == SQLITE_OK &&
        sqlite3_bind_int64(st, 4, (sqlite3_int64)s->epoch) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) == 1)
        ok = 0;
    if (st) sqlite3_finalize(st);
    free(buf);
    w->cached_committee_epoch_start = UINT64_MAX;
    return ok;
}

/* Replace, in the STORED ruleset-2 snapshot of `epoch`, the key of the
 * one entry naming `vid` by g_k[key].pk (voter_id recomputed). Order,
 * powers, ids, owners unchanged. In a transaction. 0 / -1. */
static int snap_rekey(nodus_witness_t *w, uint64_t epoch,
                      const uint8_t vid[64], int key) {
    dna_vset_snapshot_t *s = NULL;
    if (nodus_witness_vset_get(w, epoch, &s, NULL) != 0 || !s) return -1;
    int ok = -1, hit = 0;
    if (s->selection_ruleset == DNA_VSET_RULESET_TOPN_V2) {
        for (uint16_t j = 0; j < s->active_count; j++) {
            if (memcmp(s->entries[j].validator_id, vid, 64) != 0) continue;
            memcpy(s->entries[j].pubkey, g_k[key].pk, PK_LEN);
            if (nodus_chain_config_derive_witness_id(
                    g_k[key].pk, s->entries[j].voter_id) != 0)
                hit = -1;
            else
                hit++;
        }
        if (hit == 1) ok = snap_store(w, s);
    }
    dna_vset_free(&s);
    return ok;
}

/* index of the entry of `s` naming `vid`, -1 when none */
static int snap_idx(const dna_vset_snapshot_t *s, const uint8_t vid[64]) {
    for (uint16_t j = 0; j < s->active_count; j++)
        if (memcmp(s->entries[j].validator_id, vid, 64) == 0) return (int)j;
    return -1;
}

/* does the stored S(epoch) seat `vid` under g_k[key] with the voter_id
 * the key derives? 1 yes / 0 no (absent, another key) / -1 unreadable */
static int seats_under(nodus_witness_t *w, uint64_t epoch,
                       const uint8_t vid[64], int key) {
    dna_vset_snapshot_t *s = NULL;
    if (nodus_witness_vset_get(w, epoch, &s, NULL) != 0 || !s) return -1;
    uint8_t vo[32];
    int j = snap_idx(s, vid), out = 0;
    if (j >= 0 &&
        nodus_chain_config_derive_witness_id(g_k[key].pk, vo) == 0 &&
        memcmp(s->entries[j].pubkey, g_k[key].pk, PK_LEN) == 0 &&
        memcmp(s->entries[j].voter_id, vo, 32) == 0)
        out = 1;
    dna_vset_free(&s);
    return out;
}

/* the v2_attendance rows of g_k[key]'s voter_id: count / -1 */
static int att_rows(nodus_witness_t *w, int key) {
    uint8_t vo[32];
    if (nodus_chain_config_derive_witness_id(g_k[key].pk, vo) != 0)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM v2_attendance WHERE voter_id = ?1", -1,
            &st, NULL) != SQLITE_OK)
        return -1;
    int out = -1;
    if (sqlite3_bind_blob(st, 1, vo, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

/* preview_next(F) at generation 4, encoded: 0 built (*b, *l heap) /
 * 1 empty / -1 fault */
static int preview_bytes(nodus_witness_t *w, uint64_t f, uint8_t **b,
                         size_t *l) {
    dna_vset_snapshot_t *s = NULL;
    *b = NULL;
    int rc = nodus_witness_vset_preview_next(w, f, NODUS_RT_GEN_STORAGE, &s);
    if (rc != 0) return rc;
    rc = snap_bytes(s, b, l);
    dna_vset_free(&s);
    return rc;
}

/* the stored blob of S(epoch): 0 (*b, *l heap) / -1 */
static int stored_bytes(nodus_witness_t *w, uint64_t epoch, uint8_t **b,
                        size_t *l) {
    dna_vset_snapshot_t *s = NULL;
    *b = NULL;
    if (nodus_witness_vset_get(w, epoch, &s, NULL) != 0 || !s) return -1;
    int rc = snap_bytes(s, b, l);
    dna_vset_free(&s);
    return rc;
}

/* point vote slot N_VAL + `slot` at g_k[key] with `flag` */
static int vote_slot(int slot, int key, int32_t flag) {
    if (slot < 0 || slot >= N_XVOTE) return -1;
    if (nodus_chain_config_derive_witness_id(g_k[key].pk,
                                             g_vaddr[N_VAL + slot]) != 0)
        return -1;
    g_vflag[N_VAL + slot] = flag;
    return 0;
}

static void votes_reset(void) {
    g_nvote = N_VAL;
    memset(g_vaddr[N_VAL], 0, sizeof(g_vaddr[0]) * N_XVOTE);
    for (int i = 0; i < N_XVOTE; i++) g_vflag[N_VAL + i] = 0;
}

/* defined with case D below (C6 uses them since khan A8) */
static int inject_boundary(fixture_t *A, uint64_t h, nodus_v2_apply_fail_t pt);
static int twins_equal(fixture_t *A, fixture_t *B);

static int t_swap(void) {
    fixture_t A, B;
    static uint8_t call[STK_LEN];
    uint8_t chain32[DNA_CHAIN_ID_LEN], d0[64], d1[64], got[64], intent[64];
    uint8_t vid0[64], vid_d[64], role = 0;
    uint64_t h = 0;
    const int kr0 = g_kr_runs;
    rowv_t rv;

    CHECK(E_LEN >= 12, "the fixture's edge precedes the first boundary");
    for (int c = R1; c < N_COINS; c++) g_amt[c] = FEE;
    for (int k = 0; k < N_ROT; k++) g_amt[g_sc[k]] = SMIN + FEE;
    g_amt[R6] = SMIN + FEE;               /* C6s: the STAKE of KC3        */
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "ca") == 0 && fx_open(&B, "cb") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");
    CHECK(dna_validator_id_migrated(vid0, chain32, g_k[V0].pk) == 0,
          "V0's migrated validator_id");

    /* ── C1. blocks 4..6: three generation-4 STAKEs (owner KO) ───────── */
    CHECK(run_to(&A, &B, &h, H14 - 1) == 0, "blocks 1..3 (the edge)");
    for (int k = 0; k < N_ROT; k++) {
        const uint64_t hb = H14 + (uint64_t)k;
        CHECK(stake2_call(call, chain32, g_ck[k], hb + 100, SMIN)
                  == STK_LEN, "STAKE call");
        CHECK(env_ok(&A, &B, hb, DNA_SYSRULE_STAKE, call, STK_LEN, g_sc[k],
                     intent) == 0, "the STAKE applies");
        CHECK(vid_expect(chain32, intent, g_rid[k]) == 0, "validator_id");
        h = hb;
    }

    /* ── C1b. blocks 7..9: three REAL ROTATEs (6b's exec) ─────────────
     * F = the first boundary >= the commit height = E (khan A1). */
    for (int k = 0; k < N_ROT; k++) {
        const uint64_t hb = H14 + (uint64_t)N_ROT + (uint64_t)k;
        CHECK(rot_call(call, chain32, g_rid[k], g_k[KO].fp, g_tk[k],
                       g_ck[k], hb + 100, CS_OK) == ROT_LEN, "ROTATE call");
        CHECK(env_ok(&A, &B, hb, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call,
                     ROT_LEN, R1 + k, NULL) == 0, "the ROTATE applies");
        h = hb;
        CHECK(row_view(A.w, g_rid[k], g_ck[k], g_tk[k], &rv) == 0 &&
              rv.cur_is && rv.pend_is && rv.epoch == E_LEN &&
              rv.epoch == first_boundary(hb),
              "the row: current key kept, pending = target, F = E");
        CHECK(key_of(A.w, g_k[g_tk[k]].pk, got, &role) == 0 &&
              memcmp(got, g_rid[k], 64) == 0 &&
              role == NODUS_V2_KEY_ROLE_PENDING, "target reserved, role 2");
    }

    /* ── C1c. (e) the ruleset-1 bridge of the predecessor (A only,
     * ROLLED BACK). The first generation-4 freeze, at E, reads the
     * genesis S(E) — ruleset 1, all-zero ids — as S(F). A genesis seat
     * cannot ROTATE in this fixture (Foundation-owned), so V1's roles row
     * is given a pending key inside a savepoint and the freeze of S(2E)
     * is PREVIEWED (the core commit_next runs). With S(E) as stored,
     * [10M × 7] raw: P_F = 70M, V1 alone 60M > floor(140M/3) = 46666666 —
     * accepted (and in S(2E), also [10M × 7], the same). With V1's S(E)
     * entry raised to 100M (P_F = 160M, 60M > floor(320M/3) = 106666666
     * fails) it WAITS — which it can only do if the bridge found V1 in
     * S(E) by dna_validator_id_migrated(chain, entry pubkey) and counted
     * its power: an unlocated candidate would add 0 and be accepted.
     * Run at block E−1: the builder's tiebreak seed is the committed
     * block at e_start − E − 1 = E − 1 (nodus_witness_committee.c
     * compute_for_epoch), which does not exist before it. */
    CHECK(run_to(&A, &B, &h, E_LEN - 1) == 0, "to block E-1");
    {
        uint8_t vid1[64];
        dna_vset_snapshot_t *se = NULL, *pv = NULL;
        CHECK(dna_validator_id_migrated(vid1, chain32, g_k[V1].pk) == 0,
              "V1's migrated validator_id");
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(A.w->db,
                      "UPDATE v2_validator_roles SET "
                      "pending_consensus_pubkey = ?1, "
                      "consensus_key_effective_epoch = ?2 "
                      "WHERE validator_id = ?3", -1, &st, NULL) == SQLITE_OK,
                  "prepare");
            sqlite3_bind_blob(st, 1, g_k[KX].pk, (int)PK_LEN,
                              SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)E_LEN);
            sqlite3_bind_blob(st, 3, vid1, 64, SQLITE_TRANSIENT);
            int ok = sqlite3_step(st) == SQLITE_DONE &&
                     sqlite3_changes(A.w->db) == 1;
            sqlite3_finalize(st);
            CHECK(ok, "V1 pending KX, F = E (plant, rolled back)");
        }
        CHECK(nodus_witness_vset_get(A.w, E_LEN, &se, NULL) == 0 && se &&
              se->selection_ruleset == DNA_VSET_RULESET_TOPN_V1 &&
              se->active_count == N_VAL,
              "FIXTURE GUARD: S(E) is the genesis ruleset-1 set of seven");
        for (uint16_t j = 0; j < se->active_count; j++)
            CHECK(se->entries[j].total_stake == TEN_M,
                  "FIXTURE GUARD: S(E) = [10M x 7] raw");
        CHECK(nodus_witness_vset_preview_next(A.w, E_LEN,
                                              NODUS_RT_GEN_STORAGE, &pv)
                  == 0 && pv && pv->active_count == N_VAL,
              "preview of S(2E): the seven genesis seats");
        {
            uint64_t pw[DNA_MAX_ACTIVE_VALIDATORS];
            CHECK(nodus_witness_vset_powers(A.w, pv, pw) == 0,
                  "S(2E)'s counted powers");
            for (uint16_t j = 0; j < pv->active_count; j++)
                CHECK(pw[j] == 10000000ULL,
                      "FIXTURE GUARD: S(2E) counted = [10M x 7]");
        }
        {
            int j = snap_idx(pv, vid1);
            CHECK(j >= 0 && memcmp(pv->entries[j].pubkey, g_k[KX].pk,
                                   PK_LEN) == 0,
                  "V1 located in the v1 S(E) by the bridge, 60M > 46666666 "
                  "in both sets: accepted, its S(2E) entry carries KX");
        }
        dna_vset_free(&pv);
        for (uint16_t j = 0; j < se->active_count; j++)
            if (memcmp(se->entries[j].pubkey, g_k[V1].pk, PK_LEN) == 0)
                se->entries[j].total_stake = 10u * TEN_M;
        CHECK(snap_store(A.w, se) == 0, "S(E): V1's entry at 100M");
        dna_vset_free(&se);
        CHECK(nodus_witness_vset_preview_next(A.w, E_LEN,
                                              NODUS_RT_GEN_STORAGE, &pv)
                  == 0 && pv, "preview again");
        {
            int j = snap_idx(pv, vid1);
            CHECK(j >= 0 && memcmp(pv->entries[j].pubkey, g_k[V1].pk,
                                   PK_LEN) == 0,
                  "V1 at 100M in S(F): 160M - 100M = 60M is not > "
                  "106666666 — it WAITS under its current key (the bridge "
                  "counted its S(F) power)");
        }
        dna_vset_free(&pv);
        CHECK(v2x_sql(A.w->db, "ROLLBACK") == 0, "rollback");
        A.w->cached_committee_epoch_start = UINT64_MAX;
    }

    /* ── C2. rotate_apply's exact-row checks (A only, ROLLED BACK) ─────
     * Runs on V_A's real pending state; nothing here reaches the chain:
     * the transaction is rolled back before the next block. */
    CHECK(ledger_digest(A.w, d0) == 0, "digest");
    CHECK(nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC1].pk,
                                          g_k[KN].pk) == -1,
          "autocommit: refused");
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "autocommit: nothing written");
    CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC2].pk,
                                          g_k[KN].pk) == -1,
          "a wrong old key: refused");
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "a wrong old key: nothing written (step 1 is the first write)");
    CHECK(nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC1].pk,
                                          g_k[KC1].pk) == -1,
          "new == old: refused");
    /* step 1 matches in the next two calls and step 2 refuses: the
     * caller rolls back (here a savepoint, on a node the block) */
    CHECK(v2x_sql(A.w->db, "SAVEPOINT t_c2") == 0, "savepoint");
    CHECK(nodus_validator_v2_rotate_apply(A.w, vid0, g_k[V0].pk,
                                          g_k[KX].pk) == -1,
          "a validator with no pending key: refused at step 2");
    CHECK(v2x_sql(A.w->db, "ROLLBACK TO SAVEPOINT t_c2") == 0 &&
          v2x_sql(A.w->db, "RELEASE SAVEPOINT t_c2") == 0, "rollback");
    CHECK(v2x_sql(A.w->db, "SAVEPOINT t_c2") == 0, "savepoint");
    CHECK(nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC1].pk,
                                          g_k[KN2].pk) == -1,
          "a key that is not the row's pending key: refused at step 2");
    CHECK(v2x_sql(A.w->db, "ROLLBACK TO SAVEPOINT t_c2") == 0 &&
          v2x_sql(A.w->db, "RELEASE SAVEPOINT t_c2") == 0, "rollback");
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "the caller's rollback leaves the pending state");
    /* step 3 refuses: the pending key is set but its role-2 reservation
     * is missing (removed inside a savepoint) */
    CHECK(v2x_sql(A.w->db, "SAVEPOINT t_c2") == 0, "savepoint");
    CHECK(v2x_sql(A.w->db, "DELETE FROM v2_consensus_keys WHERE role = 2")
              == 0 &&
          nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC1].pk,
                                          g_k[KN].pk) == -1,
          "the pending key without its role-2 reservation: refused at "
          "step 3");
    CHECK(v2x_sql(A.w->db, "ROLLBACK TO SAVEPOINT t_c2") == 0 &&
          v2x_sql(A.w->db, "RELEASE SAVEPOINT t_c2") == 0, "rollback");
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "rolled back to the pending state");
    CHECK(nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC1].pk,
                                          g_k[KN].pk) == 0,
          "the swap applies");
    CHECK(row_view(A.w, g_rid[RA], KN, -1, &rv) == 0 && rv.cur_is &&
          rv.pend_is && rv.epoch == 0,
          "the row: consensus key KN, pending 2592 x 0x00, epoch 0");
    CHECK(key_of(A.w, g_k[KN].pk, got, &role) == 0 &&
          memcmp(got, g_rid[RA], 64) == 0 &&
          role == NODUS_V2_KEY_ROLE_ACTIVE, "KN promoted: role 2 -> role 1");
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 0 &&
          memcmp(got, g_rid[RA], 64) == 0 &&
          role == NODUS_V2_KEY_ROLE_ACTIVE,
          "rotate_apply leaves the old key's role-1 row (its caller, the "
          "swap, decides: A8 at U or the sweep at U+E, A2)");
    CHECK(keys_naming(A.w, g_rid[RA], NODUS_V2_KEY_ROLE_ACTIVE) == 2 &&
          keys_naming(A.w, g_rid[RA], NODUS_V2_KEY_ROLE_PENDING) == 0,
          "after rotate_apply alone: two role-1 rows name V_A, no role-2 "
          "row");
    CHECK(nodus_validator_v2_rotate_apply(A.w, g_rid[RA], g_k[KC1].pk,
                                          g_k[KN].pk) == -1,
          "a replayed swap: refused (the old key is no longer the row's)");
    CHECK(v2x_sql(A.w->db, "ROLLBACK") == 0, "rollback");
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0,
              "C2 rolled back: A is byte-identical to its untouched twin");
    }

    /* ── C3. boundary E (F of the three): (c) not seated ⇒ WAIT ────────
     * The first generation-4 freeze builds S(2E). The STAKEd rows are not
     * tenured for it (active_since 4..6, + 2E > 2E), so the pass finds
     * each candidate absent from the provisional S(2E) and leaves it
     * pending; nothing is written, F stays E (khan A1). The swap step at
     * E reads S(E) — the genesis ruleset-1 set, which can seat no pending
     * key — and returns: the rows are untouched (this is the only
     * coverage of that arm, and it is indistinguishable here from "not
     * seated"). */
    CHECK(run_to(&A, &B, &h, E_LEN) == 0, "to boundary E");
    for (int k = 0; k < N_ROT; k++) {
        dna_vset_snapshot_t *s = NULL;
        CHECK(nodus_witness_vset_get(A.w, 2 * E_LEN, &s, NULL) == 0 && s &&
              s->selection_ruleset == DNA_VSET_RULESET_TOPN_V2,
              "S(2E) is ruleset 2");
        int j = snap_idx(s, g_rid[k]);
        dna_vset_free(&s);
        CHECK(j < 0, "(c) a candidate not seated in S(2E) is not seated "
              "by the pass either");
        CHECK(row_view(A.w, g_rid[k], g_ck[k], g_tk[k], &rv) == 0 &&
              rv.cur_is && rv.pend_is && rv.epoch == E_LEN,
              "(c) it WAITS: current key, pending key, F = E unchanged");
    }

    /* ── C4. boundary 2E: accepted, (d) absent from S(F) adds 0 ─────────
     * S(3E) seats the three (tenured). S(F) = S(2E) does not: each adds
     * 0 to the predecessor's party (A3), and the successor S(3E) =
     * [10M x 7, 2M x 3] counted, P_U = 76M, floor(2P_U/3) = 50666666,
     * party 6M: 70M > 50666666 — all three accepted in validator_id ASC.
     * S(3E) carries each pending key with the voter_id it derives. */
    CHECK(run_to(&A, &B, &h, 2 * E_LEN) == 0, "to boundary 2E");
    {
        dna_vset_snapshot_t *s = NULL;
        uint64_t pw[DNA_MAX_ACTIVE_VALIDATORS], P = 0;
        CHECK(nodus_witness_vset_get(A.w, 3 * E_LEN, &s, NULL) == 0 && s &&
              s->active_count == N_VAL + N_ROT &&
              nodus_witness_vset_powers(A.w, s, pw) == 0,
              "S(3E): ten seats, powers computed");
        for (uint16_t j = 0; j < s->active_count; j++) {
            int rot = 0;
            for (int k = 0; k < N_ROT; k++)
                rot |= memcmp(s->entries[j].validator_id, g_rid[k], 64) == 0;
            CHECK(pw[j] == (rot ? 2000000ULL : 10000000ULL),
                  "FIXTURE GUARD: counted [10M x 7, 2M x 3]");
            P += pw[j];
        }
        dna_vset_free(&s);
        CHECK(P == 76000000ULL && P * 2 / 3 == 50666666ULL &&
              P - 6000000ULL > P * 2 / 3, "the successor budget holds");
    }
    for (int k = 0; k < N_ROT; k++) {
        CHECK(seats_under(A.w, 3 * E_LEN, g_rid[k], g_tk[k]) == 1,
              "S(3E) carries the pending key (voter_id re-derived)");
        CHECK(row_view(A.w, g_rid[k], g_ck[k], g_tk[k], &rv) == 0 &&
              rv.cur_is && rv.pend_is && rv.epoch == E_LEN,
              "nothing written at F: the row is still pending, F = E");
    }
    /* §12g at generation 4 with pending rotations: the preview Rule N
     * would build at 2E equals the stored S(3E), byte for byte */
    {
        uint8_t *pb = NULL, *sb = NULL;
        size_t pl = 0, sl = 0;
        int ok = preview_bytes(A.w, 2 * E_LEN, &pb, &pl) == 0 &&
                 stored_bytes(A.w, 3 * E_LEN, &sb, &sl) == 0 &&
                 pl == sl && memcmp(pb, sb, pl) == 0;
        free(pb);
        free(sb);
        CHECK(ok, "preview_next(2E) == stored S(3E) (the one core)");
    }

    /* ── C4b. probes on S(F) = S(2E), A only, each ROLLED BACK ─────────
     *  (d) every S(2E) entry at 1 coin: P_F = 7, floor(14/3) = 4 — a
     *      candidate absent from S(F) that added its 2M there would be
     *      refused; it adds 0, so all three are still accepted;
     *  (f) S(2E) deleted: with the three candidates the freeze FAULTS;
     *      with their pending keys cleared it builds without reading S(F)
     *      — and its bytes are the stored S(3E)'s with the three entries
     *      under their current keys (no pending row ⇒ the pre-6d bytes);
     *  (h) one S(2E) entry below one whole coin (ruleset 2: the power
     *      helper refuses it): with candidates the freeze FAULTS; without
     *      them the helper is never called and it builds. */
    {
        dna_vset_snapshot_t *sf = NULL;
        uint8_t *pb = NULL, *eb = NULL;
        size_t pl = 0, el = 0;
        static const char *const clear_pending =
            "UPDATE v2_validator_roles SET "
            "pending_consensus_pubkey = zeroblob(2592), "
            "consensus_key_effective_epoch = 0 "
            "WHERE pending_consensus_pubkey != zeroblob(2592)";

        /* (d) */
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(nodus_witness_vset_get(A.w, 2 * E_LEN, &sf, NULL) == 0 && sf,
              "S(2E)");
        for (uint16_t j = 0; j < sf->active_count; j++) {
            sf->entries[j].total_stake = (uint64_t)DNAC_DECIMAL_UNIT;
            sf->entries[j].self_bond = (uint64_t)DNAC_DECIMAL_UNIT;
        }
        CHECK(snap_store(A.w, sf) == 0, "S(2E) at 1 coin per seat");
        dna_vset_free(&sf);
        {
            dna_vset_snapshot_t *pv = NULL;
            CHECK(nodus_witness_vset_preview_next(A.w, 2 * E_LEN,
                                                  NODUS_RT_GEN_STORAGE, &pv)
                      == 0 && pv, "preview over the tiny S(F)");
            for (int k = 0; k < N_ROT; k++) {
                int j = snap_idx(pv, g_rid[k]);
                CHECK(j >= 0 && memcmp(pv->entries[j].pubkey,
                                       g_k[g_tk[k]].pk, PK_LEN) == 0,
                      "(d) P_F = 7: still accepted — a candidate absent "
                      "from S(F) contributes 0 there");
            }
            dna_vset_free(&pv);
        }
        CHECK(v2x_sql(A.w->db, "ROLLBACK") == 0, "rollback");

        /* (f) */
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        {
            char sql[128];
            snprintf(sql, sizeof(sql), "DELETE FROM validator_set_snapshots "
                     "WHERE epoch_start = %llu",
                     (unsigned long long)(2 * E_LEN));
            CHECK(v2x_sql(A.w->db, sql) == 0 &&
                  sqlite3_changes(A.w->db) == 1, "delete S(2E)");
        }
        A.w->cached_committee_epoch_start = UINT64_MAX;
        {
            dna_vset_snapshot_t *gone = NULL;
            CHECK(nodus_witness_vset_get(A.w, 2 * E_LEN, &gone, NULL) == 1,
                  "S(2E) is absent");
        }
        CHECK(preview_bytes(A.w, 2 * E_LEN, &pb, &pl) == -1,
              "(f) S(F) absent with candidates: the freeze FAULTS");
        CHECK(v2x_sql(A.w->db, clear_pending) == 0, "pending cleared");
        CHECK(preview_bytes(A.w, 2 * E_LEN, &pb, &pl) == 0,
              "(f) without candidates S(F) is never read: it builds");
        {
            dna_vset_snapshot_t *x = NULL;
            CHECK(nodus_witness_vset_get(A.w, 3 * E_LEN, &x, NULL) == 0 && x,
                  "stored S(3E)");
            for (int k = 0; k < N_ROT; k++) {
                int j = snap_idx(x, g_rid[k]);
                CHECK(j >= 0 && nodus_chain_config_derive_witness_id(
                                    g_k[g_ck[k]].pk, x->entries[j].voter_id)
                                    == 0, "entry back to its current key");
                memcpy(x->entries[j].pubkey, g_k[g_ck[k]].pk, PK_LEN);
            }
            CHECK(snap_bytes(x, &eb, &el) == 0, "expected bytes");
            dna_vset_free(&x);
        }
        CHECK(pl == el && memcmp(pb, eb, pl) == 0,
              "no pending row: the pre-6d bytes (S(3E) under current keys)");
        free(pb); pb = NULL;
        free(eb); eb = NULL;
        CHECK(v2x_sql(A.w->db, "ROLLBACK") == 0, "rollback");
        A.w->cached_committee_epoch_start = UINT64_MAX;

        /* (h) */
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(nodus_witness_vset_get(A.w, 2 * E_LEN, &sf, NULL) == 0 && sf,
              "S(2E)");
        sf->entries[0].total_stake = 1;
        sf->entries[0].self_bond = 1;
        CHECK(snap_store(A.w, sf) == 0, "S(2E) entry 0 at 1 raw unit");
        dna_vset_free(&sf);
        CHECK(preview_bytes(A.w, 2 * E_LEN, &pb, &pl) == -1,
              "(h) the power helper refuses S(F) with candidates: FAULT");
        CHECK(v2x_sql(A.w->db, clear_pending) == 0, "pending cleared");
        CHECK(preview_bytes(A.w, 2 * E_LEN, &pb, &pl) == 0,
              "(h) without candidates the helper is never called: builds");
        free(pb); pb = NULL;
        CHECK(v2x_sql(A.w->db, "ROLLBACK") == 0, "rollback");
        A.w->cached_committee_epoch_start = UINT64_MAX;
        {
            uint8_t da[64], db[64];
            CHECK(v2x_db_digest(A.w, da) == 0 &&
                  v2x_db_digest(B.w, db) == 0 && memcmp(da, db, 64) == 0,
                  "the probes rolled back: A is byte-identical to B");
        }
    }

    /* ── C5. block 2E+1: V_B UNSTAKEs (a REAL generation-4 UNSTAKE) ────
     * It stays seated in S(3E) — under its PENDING key KN2 — frozen at
     * 2E while it was bonded. */
    memcpy(call, g_rid[RB], 64);
    CHECK(env_ok(&A, &B, 2 * E_LEN + 1, DNA_SYSRULE_UNSTAKE, call, 64,
                 R1 + N_ROT, NULL) == 0, "block 2E+1: the UNSTAKE applies");
    h = 2 * E_LEN + 1;
    CHECK(row_view(A.w, g_rid[RB], KC2, KN2, &rv) == 0 && rv.cur_is &&
          rv.pend_is && rv.status == DNAC_VALIDATOR_RETIRING,
          "V_B RETIRING, its pending key kept");

    /* ── C6a. the previous voter's attendance row (khan A8) ─────────────
     * "No seat in S(F)" is not "never signed": a validator seated in an
     * earlier set, out of S(F) and back in S(U), keeps its old voter's
     * attendance row (the reset zeroes it, never deletes it). This
     * fixture cannot seat a STAKEd row before S(3E), so that row is
     * PLANTED — identically on BOTH twins (a fixture device, not a probe:
     * the digest of 3E folds it on both, so the twins stay equal) — for
     * KC1's voter_id at block 2E+1. No reader sees it before 3E: the
     * distribution and Rule N at 3E read S(2E)'s seats, and KC1 is not one.
     * At 3E the swap releases KC1 (V_A has no seat in S(2E)) and records
     * its voter_id; the sweep (3d, after the digest and the reset)
     * deletes the row. KC2 / KC3 have none (0 rows deleted, the sweep's
     * 0-or-1 rule). */
    {
        uint8_t vo[32];
        CHECK(nodus_chain_config_derive_witness_id(g_k[KC1].pk, vo) == 0,
              "KC1's voter_id");
        fixture_t *tw[2] = { &A, &B };
        for (int t = 0; t < 2; t++) {
            sqlite3_stmt *st = NULL;
            int ok = sqlite3_prepare_v2(tw[t]->w->db,
                         "INSERT INTO v2_attendance (voter_id, signed_count, "
                         "last_signed_height) VALUES (?1, 1, ?2)", -1, &st,
                         NULL) == SQLITE_OK &&
                     sqlite3_bind_blob(st, 1, vo, 32, SQLITE_TRANSIENT)
                         == SQLITE_OK &&
                     sqlite3_bind_int64(st, 2, (sqlite3_int64)h) == SQLITE_OK &&
                     sqlite3_step(st) == SQLITE_DONE &&
                     sqlite3_changes(tw[t]->w->db) == 1;
            if (st) sqlite3_finalize(st);
            CHECK(ok, "KC1's old voter row planted on both twins");
        }
        CHECK(att_rows(A.w, KC1) == 1 && att_rows(A.w, KC2) == 0 &&
              att_rows(A.w, KC3) == 0, "attendance rows before 3E");
    }

    /* ── C6. boundary 3E (U): THE SWAP, then the by-id readers ─────────
     * S(3E) carries the three pending keys, so step 1d switches all three
     * rows — the RETIRING V_B too (S(3E) seats it under KN2, the key
     * Comet uses from 3E+2). None of the three has a seat in S(F) =
     * S(2E): khan A8 — each previous key's role-1 row is deleted IN THE
     * SWAP (A2's window protects a duty these keys never had), so each
     * validator holds ONE role-1 row (its new key) and the sweep at 3E
     * has no candidate. The flips activate V_A / V_C, the graduation
     * defers V_B (both by validator_id).
     * F62 first (HF-6 6e), on A alone: boundary 3E with a fault injected
     * after the sweep — a node FAULT with the whole database rolled back:
     * the swap's A8 deletes did not survive either (three previous keys
     * still role 1, still pending, KC1's planted row there). */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN - 1) == 0, "to block 3E-1");
    CHECK(inject_boundary(&A, 3 * E_LEN, V2AP_FAIL_AFTER_ROTATE_SWEEP) == 0,
          "F62: boundary 3E faults after the sweep and rolls back whole");
    for (int k = 0; k < N_ROT; k++)
        CHECK(row_view(A.w, g_rid[k], g_ck[k], g_tk[k], &rv) == 0 &&
              rv.cur_is && rv.pend_is &&
              key_of(A.w, g_k[g_ck[k]].pk, got, &role) == 0 &&
              memcmp(got, g_rid[k], 64) == 0 &&
              role == NODUS_V2_KEY_ROLE_ACTIVE,
              "F62 at 3E: not swapped, the previous key still role 1");
    CHECK(att_rows(A.w, KC1) == 1,
          "F62 at 3E: the planted attendance row survived the rollback");
    CHECK(run_to(&A, &B, &h, 3 * E_LEN) == 0,
          "boundary 3E applies on both twins");
    CHECK(twins_equal(&A, &B) == 0,
          "F62: the replayed 3E is byte-identical to the unfaulted twin's");
    for (int k = 0; k < N_ROT; k++) {
        CHECK(row_view(A.w, g_rid[k], g_tk[k], -1, &rv) == 0 && rv.cur_is &&
              rv.pend_is && rv.epoch == 0,
              "swapped at U: consensus key = the target, pending 2592 x "
              "0x00, epoch 0");
        CHECK(key_of(A.w, g_k[g_tk[k]].pk, got, &role) == 0 &&
              memcmp(got, g_rid[k], 64) == 0 &&
              role == NODUS_V2_KEY_ROLE_ACTIVE &&
              key_of(A.w, g_k[g_ck[k]].pk, got, &role) == 1 &&
              keys_naming(A.w, g_rid[k], NODUS_V2_KEY_ROLE_ACTIVE) == 1 &&
              keys_naming(A.w, g_rid[k], NODUS_V2_KEY_ROLE_PENDING) == 0,
              "khan A8: the new key role 1, the previous key released in "
              "the swap (no seat in S(2E)) — one role-1 row");
        CHECK(att_rows(A.w, g_ck[k]) == 0,
              "khan A8: no previous voter's attendance row after 3E (KC1's "
              "planted row deleted at 3d)");
    }
    CHECK(row_view(A.w, g_rid[RA], KN, -1, &rv) == 0 &&
          rv.status == DNAC_VALIDATOR_ACTIVE &&
          row_view(A.w, g_rid[RC], KN1, -1, &rv) == 0 &&
          rv.status == DNAC_VALIDATOR_ACTIVE,
          "V_A and V_C flipped ACTIVE by validator_id");
    CHECK(row_view(A.w, g_rid[RB], KN2, -1, &rv) == 0 &&
          rv.status == DNAC_VALIDATOR_RETIRING,
          "V_B deferred at 3E by validator_id: still RETIRING");

    /* ── C6k. the key-reservation self-check at 3E, no tolerance (A8) ──
     * Every row is derived: the three rotators hold only their new keys
     * (current, role 1) — exactly a new entrant's rows. 0 differences on
     * both twins. Each single extra role-1 row is one difference: the A3
     * rotator's own previous key KC1 put back (the row khan A3 used to
     * leave until U+E and the check could only tolerate — now seen), an
     * arbitrary key naming V_A, an arbitrary key naming V0 (seated in
     * S(2E) and S(3E) under one key). All on A, ROLLED BACK. */
    {
        uint8_t junk[64], kc1[64];
        memset(junk, 0x5A, sizeof(junk));
        CHECK(kh_of(KC1, kc1) == 0, "KC1's hash");
        CHECK(kr_diff(A.w, 3 * E_LEN) == 0 && kr_diff(B.w, 3 * E_LEN) == 0,
              "self-check at 3E: 0 differences, nothing tolerated");
        CHECK(kr_probe(A.w, 3 * E_LEN, KR_SQL_ADD, kc1, g_rid[RA]) == 1,
              "V_A's released previous key KC1 back at role 1: 1 difference "
              "(the former A3 blind spot, now detected)");
        CHECK(kr_probe(A.w, 3 * E_LEN, KR_SQL_ADD, junk, g_rid[RA]) == 1,
              "an extra role-1 row on an A3 rotator: 1 difference");
        CHECK(kr_probe(A.w, 3 * E_LEN, KR_SQL_ADD, junk, vid0) == 1,
              "an extra role-1 row on a validator S(2E) seats: 1 "
              "difference");
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0 && kr_diff(A.w, 3 * E_LEN) == 0,
              "C6k rolled back: A == B, 0 differences");
    }

    /* ── C6s. the released key is free from the next block (khan A8) ───
     * Block 3E+1: a REAL generation-4 STAKE (owner KO, coin R6) of a NEW
     * validator under KC3 — V_C's previous key, released by the swap at
     * 3E — with KC3's own consent (stake2_call signs the op-1 consent
     * with KC3: binding a key to another validator needs that key's
     * consent, design §3 "(A8)" / G2). It APPLIES: KC3 is reserved to the
     * new validator_id at role 1. Its counterpart for a seated rotator
     * (khan A2: the old key is still reserved until U+E) is D4s. */
    {
        CHECK(stake2_call(call, chain32, KC3, 3 * E_LEN + 1 + 100, SMIN)
                  == STK_LEN, "STAKE call (KC3)");
        CHECK(env_ok(&A, &B, 3 * E_LEN + 1, DNA_SYSRULE_STAKE, call,
                     STK_LEN, R6, intent) == 0,
              "block 3E+1: a STAKE under V_C's released key KC3 APPLIES");
        h = 3 * E_LEN + 1;
        CHECK(vid_expect(chain32, intent, vid_d) == 0, "the new validator_id");
        CHECK(key_of(A.w, g_k[KC3].pk, got, &role) == 0 &&
              memcmp(got, vid_d, 64) == 0 &&
              role == NODUS_V2_KEY_ROLE_ACTIVE &&
              memcmp(vid_d, g_rid[RC], 64) != 0,
              "KC3 reserved to the NEW validator_id, role 1");
    }

    /* ── C7. (3E, 4E]: V_C's seated key KN1 signs from block 3E+3 (the
     * commit of 3E+2 — cometbft applies S(U) at U+2); KN (V_A) never
     * signs. The host hands the engine any vote list (no address check
     * on the attendance credit, nodus_witness_v2_apply.c:5860). */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN + 2) == 0, "blocks 3E+1, 3E+2");
    CHECK(vote_slot(0, KN1, (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT) == 0,
          "KN1's vote address");
    g_nvote = N_VAL + 1;

    /* ── C7b. the distribution still refuses a THIRD key ───────────────
     * On A alone, immediately before the BOUNDARY block 4E (SYSTEM
     * declared touched, :5915): S(3E)'s entry for V4 (no rotation, no
     * pending key) is given KX; boundary 4E must FAULT (the host rolls it
     * back); the entry is put back, byte for byte — again immediately
     * before block 4E — and A must be identical to B. */
    CHECK(run_to(&A, &B, &h, 4 * E_LEN - 1) == 0, "to block 4E-1");
    {
        uint8_t vid4[64], da[64], db[64];
        nodus_v2_block_t bk;
        CHECK(dna_validator_id_migrated(vid4, chain32, g_k[V4].pk) == 0,
              "V4's validator_id");
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0 &&
              snap_rekey(A.w, 3 * E_LEN, vid4, KX) == 0 &&
              v2x_sql(A.w->db, "COMMIT") == 0,
              "S(3E)'s V4 entry names a third key");
        mk_block(&bk, 4 * E_LEN, NULL, 0);
        CHECK(v2x_cmt_apply(A.w, &bk) == NODUS_V2_INTERNAL_FAULT,
              "boundary 4E faults: an entry key that is neither the row's "
              "key nor its pending key");
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0 &&
              snap_rekey(A.w, 3 * E_LEN, vid4, V4) == 0 &&
              v2x_sql(A.w->db, "COMMIT") == 0, "V4's entry restored");
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0,
              "after the rolled-back probe A is byte-identical to B");
    }

    /* ── C7c. the sweep refuses a shape no swap explains ───────────────
     * On A alone, immediately before BOUNDARY block 4E, two rounds:
     *  (1) ONE extra role-1 row naming V_A (an arbitrary key hash): V_A
     *      then has the two-row A2 shape (KN + the stray). The boundary-
     *      start self-check's core — the set derived as of 3E, which
     *      step 0 of boundary 4E compares, log-only — counts it as ONE
     *      difference. The sweep at 4E reads V_A as swapped at 3E (S(3E)
     *      seats it under KN) but S(2E) does not seat V_A at all (khan
     *      A8 released its previous key at 3E), so no previous key can be
     *      due: the boundary FAULTS — it does not release the stray
     *      silently as a "previous key" (operator 2026-10-13).
     *  (2) TWO extra rows (three in all): key_sweep_previous's own shape
     *      check faults.
     * The rows are removed again before block 4E each time. */
    for (int nj = 1; nj <= 2; nj++) {
        uint8_t junk[2][64];
        nodus_v2_block_t bk;
        memset(junk[0], 0x77, sizeof(junk[0]));
        memset(junk[1], 0x78, sizeof(junk[1]));
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        for (int j = 0; j < nj; j++)
            CHECK(nodus_validator_v2_key_insert(A.w, junk[j], g_rid[RA],
                                                NODUS_V2_KEY_ROLE_ACTIVE) == 0,
                  "an extra role-1 row names V_A");
        CHECK(v2x_sql(A.w->db, "COMMIT") == 0, "commit");
        if (nj == 1)
            CHECK(kr_diff(A.w, 3 * E_LEN) == 1,
                  "the boundary-start check (derivation of 3E) sees the "
                  "stray row: 1 difference");
        mk_block(&bk, 4 * E_LEN, NULL, 0);
        CHECK(v2x_cmt_apply(A.w, &bk) == NODUS_V2_INTERNAL_FAULT,
              nj == 1 ? "boundary 4E faults: one stray row beside the "
                        "current key, no S(2E) seat — never released "
                        "silently"
                      : "boundary 4E faults: three role-1 rows on a "
                        "swapped validator");
        for (int j = 0; j < nj; j++) {
            sqlite3_stmt *st = NULL;
            int ok = sqlite3_prepare_v2(A.w->db,
                         "DELETE FROM v2_consensus_keys "
                         "WHERE consensus_pk_hash = ?1", -1, &st, NULL)
                         == SQLITE_OK &&
                     sqlite3_bind_blob(st, 1, junk[j], 64, SQLITE_TRANSIENT)
                         == SQLITE_OK &&
                     sqlite3_step(st) == SQLITE_DONE &&
                     sqlite3_changes(A.w->db) == 1;
            if (st) sqlite3_finalize(st);
            CHECK(ok, "a junk row removed (autocommit)");
        }
        CHECK(twins_equal(&A, &B) == 0,
              "after the rolled-back probe A is byte-identical to B");
    }

    /* ── C8. boundary 4E (U+E) ─────────────────────────────────────────
     * The distribution pays S(3E) against the swapped rows (strict key
     * equality holds — the B4 {pubkey, pending} relaxation is not needed
     * on this path any more). V_B graduates: key_release takes KN2 (its
     * current key) — its previous key KC2 went in the swap at 3E (khan
     * A8), so V_B holds no reservation afterwards and is no sweep
     * candidate (the graduated arm needs one role-1 row). The sweep at 4E
     * has no candidate at all: KC1 / KC3 went at 3E too, and V_A / V_C
     * hold one role-1 row each. */
    CHECK(att_rows(A.w, KC1) == 0 && att_rows(A.w, KC3) == 0,
          "no attendance rows for KC1 / KC3 before 4E");
    CHECK(run_to(&A, &B, &h, 4 * E_LEN) == 0,
          "boundary 4E applies on both twins (no -2)");
    CHECK(row_view(A.w, g_rid[RB], KN2, -1, &rv) == 0 && rv.cur_is &&
          rv.pend_is && rv.epoch == 0 &&
          rv.status == DNAC_VALIDATOR_UNSTAKED,
          "V_B graduated at 4E: UNSTAKED under KN2, no pending key");
    CHECK(key_of(A.w, g_k[KC2].pk, got, &role) == 1 &&
          key_of(A.w, g_k[KN2].pk, got, &role) == 1 &&
          keys_naming(A.w, g_rid[RB], NODUS_V2_KEY_ROLE_ACTIVE) == 0 &&
          keys_naming(A.w, g_rid[RB], NODUS_V2_KEY_ROLE_PENDING) == 0,
          "both of V_B's keys released (KC2 by the swap at 3E — A8, KN2 by "
          "the graduation at 4E)");
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 1 &&
          key_of(A.w, g_k[KC3].pk, got, &role) == 0 &&
          memcmp(got, vid_d, 64) == 0 &&
          role == NODUS_V2_KEY_ROLE_ACTIVE &&
          keys_naming(A.w, g_rid[RA], NODUS_V2_KEY_ROLE_ACTIVE) == 1 &&
          keys_naming(A.w, g_rid[RC], NODUS_V2_KEY_ROLE_ACTIVE) == 1 &&
          key_of(A.w, g_k[KN].pk, got, &role) == 0 &&
          role == NODUS_V2_KEY_ROLE_ACTIVE &&
          key_of(A.w, g_k[KN1].pk, got, &role) == 0 &&
          role == NODUS_V2_KEY_ROLE_ACTIVE,
          "KC1 free, KC3 the C6s validator's; V_A / V_C one role-1 row "
          "each (KN / KN1)");
    /* Rule N at 4E: duty S(3E), found by validator_id; attendance read
     * on the duty ENTRY's key (= the swapped row's key) */
    CHECK(row_view(A.w, g_rid[RA], KN, -1, &rv) == 0 && rv.missed == 1,
          "V_A: KN never signed — counter 1");
    CHECK(row_view(A.w, g_rid[RC], KN1, -1, &rv) == 0 && rv.missed == 0,
          "V_C: KN1 signed the epoch — counter 0");
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
    }
    CHECK(g_kr_runs - kr0 == 2 * (int)(h / E_LEN),
          "the key-reservation self-check compared, and found nothing, at "
          "every boundary on both twins");
    votes_reset();
    fx_close(&A);
    fx_close(&B);
    return 0;
}

/* ══ D. slice 6d — the budget, one rotation through F / U / U+E ═══════
 *
 * Three generation-4 STAKEs of 12M (owner KO) — big enough that the
 * budget binds: S(3E) and S(4E) are [12M x 3, 10M x 7] whole coins,
 * counted unchanged (the water-fill's first cap c_0 = floor(3000 · 94M /
 * 10000) = 28.2M >= 12M), P = 106M, floor(2P/3) = 70666666:
 *   party {o0}        106M − 12M = 94M > 70666666   accepted
 *   party {o0,o1}     106M − 24M = 82M > 70666666   accepted
 *   party {o0,o1,o2}  106M − 36M = 70M ≤ 70666666   o2 WAITS
 * in BOTH sets (all three are seated in S(F) = S(3E) as well, so the
 * predecessor binds exactly like the successor) — o0, o1, o2 the three in
 * validator_id ASC. ROTATEs in (2E, 3E] give F = 3E for all three. At 4E
 * o2 is re-evaluated with its F kept, and — khan A7 (2026-10-13, the
 * BUGS Z-27 case itself) — it WAITS AGAIN: S(F) = S(4E) carries o0 and
 * o1 under their new keys, changed against S(3E), so the predecessor
 * party starts at 24M and {o0,o1 carried, o2} leaves 70M ≤ 70666666.
 * Before A7 it was accepted here (94M) — two parties sharing S(4E)'s
 * third. At 5E S(5E) carries no key change against S(4E) (the swap at 4E
 * copied the keys S(4E) already had), the carry is 0, o2 is accepted
 * (94M); U = 6E, U+E = 7E.
 *
 * Votes (the host hands the engine any list): the three STAKEd keys sign
 * from block 3E+3 (S(3E) takes effect at 3E, Comet applies it at 3E+2).
 * In (3E, 4E] o1's OLD key is ABSENT, o0's and o2's sign. Rule N at 4E
 * judges duty S(3E) by validator_id on the OLD keys: o0 counter 0 (a
 * read of the new key would miss), o1 counter 1 (a "no duty" reading
 * would reset it to 0). The old keys of o0 / o1 sign the precommits of 4E
 * and 4E+1 (credited at 4E+1, 4E+2), their new keys from 4E+3; o2's old
 * key signs through 6E+1, its new key from 6E+3. */
static int64_t ko_value(nodus_witness_t *w) {
    uint64_t acc = 0, utx = 0;
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_prepare_v2(w->db,
                 "SELECT COALESCE(SUM(amount), 0) FROM v2_reward_accrual "
                 "WHERE owner_fp = ?1", -1, &st, NULL) == SQLITE_OK &&
             sqlite3_bind_blob(st, 1, g_k[KO].fp, 64, SQLITE_TRANSIENT)
                 == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_ROW;
    if (ok) acc = (uint64_t)sqlite3_column_int64(st, 0);
    if (st) sqlite3_finalize(st);
    st = NULL;
    ok = ok &&
         sqlite3_prepare_v2(w->db,
             "SELECT COALESCE(SUM(amount), 0) FROM utxo_set "
             "WHERE owner = ?1", -1, &st, NULL) == SQLITE_OK &&
         sqlite3_bind_text(st, 1, g_k[KO].hex, 128, SQLITE_TRANSIENT)
             == SQLITE_OK &&
         sqlite3_step(st) == SQLITE_ROW;
    if (ok) utx = (uint64_t)sqlite3_column_int64(st, 0);
    if (st) sqlite3_finalize(st);
    if (!ok || acc > (uint64_t)INT64_MAX - utx) return -1;
    return (int64_t)(acc + utx);
}

/* HF-6 6e — the boundary block `h` on twin A alone with fault point `pt`
 * injected: the engine returns a node FAULT labelled by phase 6e (the
 * boundary), and the WHOLE database is byte-identical afterwards
 * (v2x_cmt_fault). Routed around v2x_cmt_injected: its class table
 * (v2_genesis_fixture.h) does not list F61 / F62. 0 / -1. */
static int inject_boundary(fixture_t *A, uint64_t h, nodus_v2_apply_fail_t pt) {
    nodus_v2_block_t bk;
    mk_block(&bk, h, NULL, 0);
    bk.fail_at = pt;
    if (v2x_cmt_fault(A->w, &bk) != 0) return -1;
    return v2x_reason_is(&bk, V2X_FAULT, "phase 6e");
}

/* the twins' whole databases byte-identical: 0 / -1 */
static int twins_equal(fixture_t *A, fixture_t *B) {
    uint8_t da[64], db[64];
    if (v2x_db_digest(A->w, da) != 0 || v2x_db_digest(B->w, db) != 0)
        return -1;
    return memcmp(da, db, 64) == 0 ? 0 : -1;
}

static int t_budget(void) {
    fixture_t A, B;
    static uint8_t call[STK_LEN];
    uint8_t chain32[DNA_CHAIN_ID_LEN], got[64], intent[64], role = 0;
    const uint64_t BIG = 12000000ULL * (uint64_t)DNAC_DECIMAL_UNIT;
    uint64_t h = 0;
    const int kr0 = g_kr_runs;
    int o[N_ROT];                      /* indices into g_rid, id ASC */
    rowv_t rv;

    CHECK(E_LEN >= 12, "the fixture's edge precedes the first boundary");
    CHECK(DNAC_HF6_POWER_CAP_BPS_DEFAULT == 3000u,
          "the cap arithmetic is derived at 3000 bps");
    for (int c = R1; c < N_COINS; c++) g_amt[c] = FEE;
    for (int k = 0; k < N_ROT; k++) g_amt[g_sc[k]] = BIG + FEE;
    g_amt[R6] = SMIN + FEE;           /* D4s / D5s: the STAKE of o0's old key */
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "da") == 0 && fx_open(&B, "db") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    /* ── D1. blocks 4..6: three 12M STAKEs (keys KC1 / KC2 / KC3) ─────── */
    CHECK(run_to(&A, &B, &h, H14 - 1) == 0, "blocks 1..3 (the edge)");
    for (int k = 0; k < N_ROT; k++) {
        const uint64_t hb = H14 + (uint64_t)k;
        CHECK(stake2_call(call, chain32, g_ck[k], hb + 100, BIG) == STK_LEN,
              "STAKE call");
        CHECK(env_ok(&A, &B, hb, DNA_SYSRULE_STAKE, call, STK_LEN, g_sc[k],
                     intent) == 0, "the 12M STAKE applies");
        CHECK(vid_expect(chain32, intent, g_rid[k]) == 0, "validator_id");
        h = hb;
    }
    /* o[] = the three in validator_id ASC */
    for (int k = 0; k < N_ROT; k++) o[k] = k;
    for (int a = 1; a < N_ROT; a++)
        for (int b = a; b > 0 && memcmp(g_rid[o[b - 1]], g_rid[o[b]], 64) > 0;
             b--) {
            int t = o[b];
            o[b] = o[b - 1];
            o[b - 1] = t;
        }

    /* ── D2. blocks 2E+1..2E+3: three ROTATEs, F = 3E ────────────────── */
    CHECK(run_to(&A, &B, &h, 2 * E_LEN) == 0, "to boundary 2E");
    for (int k = 0; k < N_ROT; k++) {
        const uint64_t hb = 2 * E_LEN + 1 + (uint64_t)k;
        CHECK(rot_call(call, chain32, g_rid[k], g_k[KO].fp, g_tk[k],
                       g_ck[k], hb + 100, CS_OK) == ROT_LEN, "ROTATE call");
        CHECK(env_ok(&A, &B, hb, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call,
                     ROT_LEN, R1 + k, NULL) == 0, "the ROTATE applies");
        h = hb;
        CHECK(row_view(A.w, g_rid[k], g_ck[k], g_tk[k], &rv) == 0 &&
              rv.epoch == 3 * E_LEN, "pending, F = 3E");
    }

    /* ── D3. boundary 3E (F): the budget ─────────────────────────────── */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN) == 0, "boundary 3E");
    {
        static const uint64_t ep[2] = { 3, 4 };
        for (int s = 0; s < 2; s++) {
            dna_vset_snapshot_t *x = NULL;
            uint64_t pw[DNA_MAX_ACTIVE_VALIDATORS], P = 0;
            CHECK(nodus_witness_vset_get(A.w, ep[s] * E_LEN, &x, NULL) == 0 &&
                  x && x->active_count == N_VAL + N_ROT &&
                  nodus_witness_vset_powers(A.w, x, pw) == 0,
                  "S(3E) / S(4E): ten seats, counted powers");
            for (uint16_t j = 0; j < x->active_count; j++) {
                int rot = 0;
                for (int k = 0; k < N_ROT; k++)
                    rot |= memcmp(x->entries[j].validator_id, g_rid[k], 64)
                           == 0;
                CHECK(pw[j] == (rot ? 12000000ULL : 10000000ULL),
                      "FIXTURE GUARD: counted [12M x 3, 10M x 7]");
                P += pw[j];
            }
            dna_vset_free(&x);
            CHECK(P == 106000000ULL && P * 2 / 3 == 70666666ULL,
                  "P = 106M, floor(2P/3) = 70666666");
            CHECK(P - 12000000ULL > P * 2 / 3 &&
                  P - 24000000ULL > P * 2 / 3 &&
                  !(P - 36000000ULL > P * 2 / 3),
                  "parties of one and two fit, three does not");
        }
    }
    CHECK(seats_under(A.w, 4 * E_LEN, g_rid[o[0]], g_tk[o[0]]) == 1 &&
          seats_under(A.w, 4 * E_LEN, g_rid[o[1]], g_tk[o[1]]) == 1,
          "(b) the first two in validator_id ASC: S(4E) carries their new "
          "keys");
    CHECK(seats_under(A.w, 4 * E_LEN, g_rid[o[2]], g_ck[o[2]]) == 1,
          "(b) the third WAITS: S(4E) seats it under its current key");
    {
        uint8_t *pb = NULL, *sb = NULL;
        size_t pl = 0, sl = 0;
        int ok = preview_bytes(A.w, 3 * E_LEN, &pb, &pl) == 0 &&
                 stored_bytes(A.w, 4 * E_LEN, &sb, &sl) == 0 &&
                 pl == sl && memcmp(pb, sb, pl) == 0;
        free(pb);
        free(sb);
        CHECK(ok, "(a) preview_next(3E) == stored S(4E), byte for byte");
    }

    /* ── votes for (3E, 4E] ───────────────────────────────────────────── */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN + 2) == 0, "blocks 3E+1, 3E+2");
    CHECK(vote_slot(0, g_ck[o[0]], (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
              == 0 &&
          vote_slot(1, g_ck[o[1]], (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT)
              == 0 &&
          vote_slot(2, g_ck[o[2]], (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
              == 0, "old keys: o0 signs, o1 absent, o2 signs");
    g_nvote = N_VAL + N_XVOTE;
    CHECK(run_to(&A, &B, &h, 4 * E_LEN - 1) == 0, "to block 4E-1");

    /* ── D4. boundary 4E (U of o0, o1; F again for o2) ─────────────────
     * F61 first (HF-6 6e): on A alone, boundary 4E with a fault injected
     * after the swap step — a node FAULT, the whole database rolled back
     * (o0 / o1 still on their old keys with their pending keys and
     * role-2 reservations); the clean 4E then applies on both twins and A
     * equals B byte for byte. Then the distribution at 4E pays S(3E) (old
     * keys, rows not yet swapped at 1b) — KO, the owner of the three, is
     * credited */
    CHECK(inject_boundary(&A, 4 * E_LEN, V2AP_FAIL_AFTER_ROTATE_SWAP) == 0,
          "F61: boundary 4E faults after the swap and rolls back whole");
    for (int s = 0; s < 2; s++) {
        const int k = o[s];
        CHECK(row_view(A.w, g_rid[k], g_ck[k], g_tk[k], &rv) == 0 &&
              rv.cur_is && rv.pend_is && rv.epoch == 3 * E_LEN &&
              keys_naming(A.w, g_rid[k], NODUS_V2_KEY_ROLE_ACTIVE) == 1 &&
              keys_naming(A.w, g_rid[k], NODUS_V2_KEY_ROLE_PENDING) == 1,
              "F61: the swap's writes did not survive the rollback");
    }
    {
        int64_t v0 = ko_value(A.w);
        CHECK(v0 >= 0, "KO's value before 4E");
        CHECK(run_to(&A, &B, &h, 4 * E_LEN) == 0,
              "boundary 4E applies on both twins (no -2)");
        int64_t v1 = ko_value(A.w);
        CHECK(v1 > v0, "(a) the distribution at U paid the owner");
    }
    CHECK(twins_equal(&A, &B) == 0,
          "F61: the replayed 4E is byte-identical to the unfaulted twin's");
    for (int s = 0; s < 2; s++) {
        const int k = o[s];
        CHECK(row_view(A.w, g_rid[k], g_tk[k], -1, &rv) == 0 && rv.cur_is &&
              rv.pend_is && rv.epoch == 0,
              "(a) the swap at U: new consensus key, no pending key");
        CHECK(key_of(A.w, g_k[g_tk[k]].pk, got, &role) == 0 &&
              role == NODUS_V2_KEY_ROLE_ACTIVE &&
              key_of(A.w, g_k[g_ck[k]].pk, got, &role) == 0 &&
              role == NODUS_V2_KEY_ROLE_ACTIVE &&
              keys_naming(A.w, g_rid[k], NODUS_V2_KEY_ROLE_ACTIVE) == 2,
              "(a) KEYRES: new key role 2 -> 1, old key kept role 1");
    }
    CHECK(row_view(A.w, g_rid[o[2]], g_ck[o[2]], g_tk[o[2]], &rv) == 0 &&
          rv.cur_is && rv.pend_is && rv.epoch == 3 * E_LEN,
          "the waiting third: not swapped, its F (3E) not rewritten");
    /* ── D4k. the key-reservation self-check at 4E, every row derivable ─
     * o0 / o1 were seated in S(3E) under their old keys and S(4E) seats
     * them under the new ones: their previous keys are DERIVED (S(3E)'s
     * keys), o2's pending key is derived from its roles row. Each
     * single-row corruption — on A, ROLLED BACK — is exactly one
     * difference: o0's previous key deleted (missing), o0's current key
     * flipped to role 2 (other role), o2's pending key flipped to role 1
     * (other role), o1's previous key re-assigned to o2 (other validator),
     * a spare role-1 row naming o2 (extra). */
    {
        uint8_t prev0[64], cur0[64], pend2[64], prev1[64], junk[64];
        memset(junk, 0x3C, sizeof(junk));
        CHECK(kh_of(g_ck[o[0]], prev0) == 0 && kh_of(g_tk[o[0]], cur0) == 0 &&
              kh_of(g_tk[o[2]], pend2) == 0 && kh_of(g_ck[o[1]], prev1) == 0,
              "the probed key hashes");
        CHECK(kr_diff(A.w, 4 * E_LEN) == 0 && kr_diff(B.w, 4 * E_LEN) == 0,
              "self-check at 4E: 0 differences (two derived previous "
              "keys, one pending key)");
        CHECK(kr_probe(A.w, 4 * E_LEN, KR_SQL_DEL, prev0, NULL) == 1,
              "o0's previous key deleted: 1 difference (missing)");
        CHECK(kr_probe(A.w, 4 * E_LEN, KR_SQL_ROLE, cur0, NULL) == 1,
              "o0's current key as role 2: 1 difference");
        CHECK(kr_probe(A.w, 4 * E_LEN, KR_SQL_ROLE, pend2, NULL) == 1,
              "o2's pending key as role 1: 1 difference");
        CHECK(kr_probe(A.w, 4 * E_LEN, KR_SQL_VID, prev1, g_rid[o[2]]) == 1,
              "o1's previous key naming o2: 1 difference");
        CHECK(kr_probe(A.w, 4 * E_LEN, KR_SQL_ADD, junk, g_rid[o[2]]) == 1,
              "a spare role-1 row naming o2: 1 difference (extra)");
        CHECK(twins_equal(&A, &B) == 0 && kr_diff(A.w, 4 * E_LEN) == 0,
              "D4k rolled back: A == B, 0 differences");
    }
    CHECK(row_view(A.w, g_rid[o[0]], g_tk[o[0]], -1, &rv) == 0 &&
          rv.missed == 0,
          "(a) Rule N at U: o0 judged on its OLD key (signed) — counter 0");
    CHECK(row_view(A.w, g_rid[o[1]], g_tk[o[1]], -1, &rv) == 0 &&
          rv.missed == 1,
          "(a) Rule N at U: o1's duty found by id, its OLD key absent — "
          "counter 1, not a reset");
    CHECK(seats_under(A.w, 5 * E_LEN, g_rid[o[0]], g_tk[o[0]]) == 1 &&
          seats_under(A.w, 5 * E_LEN, g_rid[o[1]], g_tk[o[1]]) == 1,
          "U's freeze copied the NEW keys into S(5E)");
    CHECK(seats_under(A.w, 5 * E_LEN, g_rid[o[2]], g_ck[o[2]]) == 1 &&
          seats_under(A.w, 5 * E_LEN, g_rid[o[2]], g_tk[o[2]]) == 0,
          "(b) A7: the third WAITS again — S(4E) carries o0 / o1's "
          "rotations (24M), + 12M leaves 70M <= 70666666");
    {
        uint8_t *pb = NULL, *sb = NULL;
        size_t pl = 0, sl = 0;
        int ok = preview_bytes(A.w, 4 * E_LEN, &pb, &pl) == 0 &&
                 stored_bytes(A.w, 5 * E_LEN, &sb, &sl) == 0 &&
                 pl == sl && memcmp(pb, sb, pl) == 0;
        free(pb);
        free(sb);
        CHECK(ok, "preview_next(4E) == stored S(5E), byte for byte (the "
              "carry is read alike by both)");
    }

    /* ── votes for (4E, 5E]: old keys of o0 / o1 sign 4E+1, 4E+2 ──────── */
    CHECK(vote_slot(1, g_ck[o[1]], (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
              == 0, "o1's old key signs U, U+1");

    /* ── D4s. the seated rotator's old key stays reserved (khan A2) ────
     * Block 4E+1: a REAL generation-4 STAKE of a new validator under o0's
     * previous key, with that key's own consent and coin R6 (SMIN + FEE).
     * o0 was seated in S(F) = S(3E), so its old key — which still signs
     * U and U+1 — keeps its role-1 row until the sweep at U+E: the STAKE
     * is REFUSED at exec (§4, the key reserved by another validator), the
     * ledger tables byte-identical, R6 unspent. The same call after 5E is
     * D5s. The unseated counterpart (A8: free from U+1) is C6s. */
    CHECK(stake2_call(call, chain32, g_ck[o[0]], 4 * E_LEN + 1 + 100, SMIN)
              == STK_LEN, "STAKE call (o0's old key)");
    CHECK(env_refused(&A, &B, 4 * E_LEN + 1, DNA_SYSRULE_STAKE, call,
                      STK_LEN, R6) == 0,
          "block 4E+1: a STAKE under o0's kept previous key is REFUSED");
    h = 4 * E_LEN + 1;
    CHECK(key_of(A.w, g_k[g_ck[o[0]]].pk, got, &role) == 0 &&
          memcmp(got, g_rid[o[0]], 64) == 0 &&
          role == NODUS_V2_KEY_ROLE_ACTIVE,
          "o0's previous key still reserved to o0 (A2 window)");
    CHECK(run_to(&A, &B, &h, 4 * E_LEN + 2) == 0, "block 4E+2");
    CHECK(vote_slot(0, g_tk[o[0]], (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
              == 0 &&
          vote_slot(1, g_tk[o[1]], (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
              == 0, "o0 / o1: the new keys sign from 4E+3");
    CHECK(run_to(&A, &B, &h, 5 * E_LEN - 1) == 0, "to block 5E-1");
    CHECK(att_rows(A.w, g_ck[o[0]]) == 1 && att_rows(A.w, g_ck[o[1]]) == 1,
          "the old voters' attendance rows exist before U+E");

    /* ── D5. boundary 5E (U+E of o0, o1; F again for o2) ───────────────
     * F62 first (HF-6 6e): on A alone, boundary 5E with a fault injected
     * after the sweep step — rolled back whole (the old voters' attendance
     * rows and role-1 rows still there); the clean 5E then applies on both
     * twins and A equals B. o2 is not swapped at 5E on either path (A7: it
     * waited at 4E, so S(5E) seats its old key). */
    CHECK(inject_boundary(&A, 5 * E_LEN, V2AP_FAIL_AFTER_ROTATE_SWEEP) == 0,
          "F62: boundary 5E faults after the sweep and rolls back whole");
    CHECK(att_rows(A.w, g_ck[o[0]]) == 1 && att_rows(A.w, g_ck[o[1]]) == 1 &&
          keys_naming(A.w, g_rid[o[0]], NODUS_V2_KEY_ROLE_ACTIVE) == 2 &&
          keys_naming(A.w, g_rid[o[1]], NODUS_V2_KEY_ROLE_ACTIVE) == 2,
          "F62: the sweep's deletes did not survive the rollback");
    CHECK(row_view(A.w, g_rid[o[2]], g_ck[o[2]], g_tk[o[2]], &rv) == 0 &&
          rv.cur_is && rv.pend_is && rv.epoch == 3 * E_LEN,
          "F62: o2 untouched — still pending, F = 3E");
    {
        int64_t v0 = ko_value(A.w);
        CHECK(v0 >= 0, "KO's value before 5E");
        CHECK(run_to(&A, &B, &h, 5 * E_LEN) == 0,
              "boundary 5E applies on both twins (no -2)");
        int64_t v1 = ko_value(A.w);
        CHECK(v1 > v0, "(a) the distribution at U+E paid the owner");
    }
    CHECK(twins_equal(&A, &B) == 0,
          "F62: the replayed 5E is byte-identical to the unfaulted twin's");
    for (int s = 0; s < 2; s++) {
        const int k = o[s];
        CHECK(att_rows(A.w, g_ck[k]) == 0,
              "(a) the sweep at U+E deleted the old voter's attendance row");
        CHECK(key_of(A.w, g_k[g_ck[k]].pk, got, &role) == 1 &&
              keys_naming(A.w, g_rid[k], NODUS_V2_KEY_ROLE_ACTIVE) == 1,
              "(a) the sweep at U+E released the old key's role-1 row (A2)");
        CHECK(row_view(A.w, g_rid[k], g_tk[k], -1, &rv) == 0 &&
              rv.missed == 0, "Rule N at U+E: the new key signed");
    }
    CHECK(row_view(A.w, g_rid[o[2]], g_ck[o[2]], g_tk[o[2]], &rv) == 0 &&
          rv.cur_is && rv.pend_is && rv.epoch == 3 * E_LEN &&
          keys_naming(A.w, g_rid[o[2]], NODUS_V2_KEY_ROLE_ACTIVE) == 1 &&
          keys_naming(A.w, g_rid[o[2]], NODUS_V2_KEY_ROLE_PENDING) == 1,
          "o2 not swapped at 5E (S(5E) seats its old key), its F (3E) not "
          "rewritten");
    CHECK(seats_under(A.w, 6 * E_LEN, g_rid[o[2]], g_tk[o[2]]) == 1,
          "(b) A7: accepted at 5E — S(5E) carries no key change against "
          "S(4E), carry 0, party {o2}: 94M > 70666666");

    /* ── D5s. the same STAKE after U+E (D4s's control) ─────────────────
     * Block 5E+1: the D4s call (o0's previous key, its consent, coin R6)
     * APPLIES — the sweep at 5E released the key — so D4s's refusal was
     * the reservation and nothing else in the call. */
    CHECK(stake2_call(call, chain32, g_ck[o[0]], 5 * E_LEN + 1 + 100, SMIN)
              == STK_LEN, "STAKE call (o0's old key, again)");
    CHECK(env_ok(&A, &B, 5 * E_LEN + 1, DNA_SYSRULE_STAKE, call, STK_LEN,
                 R6, intent) == 0,
          "block 5E+1: the STAKE under o0's released previous key APPLIES");
    h = 5 * E_LEN + 1;
    {
        uint8_t vid_n[64];
        CHECK(vid_expect(chain32, intent, vid_n) == 0, "the new validator_id");
        CHECK(key_of(A.w, g_k[g_ck[o[0]]].pk, got, &role) == 0 &&
              memcmp(got, vid_n, 64) == 0 &&
              role == NODUS_V2_KEY_ROLE_ACTIVE,
              "o0's previous key reserved to the NEW validator_id, role 1");
    }

    /* ── votes for (5E, 6E]: o2's OLD key keeps signing (S(5E) duty) ─── */
    CHECK(run_to(&A, &B, &h, 6 * E_LEN - 1) == 0, "to block 6E-1");

    /* ── D5x. a stray role-1 row on a STEADY validator (A only) ────────
     * Before BOUNDARY block 6E: one extra role-1 row naming V0 (genesis,
     * never rotated, seated in S(4E) and S(5E) under one key). Before the
     * operator's 2026-10-13 rule the sweep at 6E released it silently as
     * a "previous key" (two rows, one the current key's; S(5E) seats V0
     * under it). Now: the boundary-start check's core (derivation of 5E)
     * counts it as one difference, and the sweep FAULTS — S(4E) seats V0
     * under its CURRENT key, so no previous key is due. Removed, A == B. */
    {
        uint8_t vidv0[64], junk[64];
        nodus_v2_block_t bk;
        memset(junk, 0x5C, sizeof(junk));
        CHECK(dna_validator_id_migrated(vidv0, chain32, g_k[V0].pk) == 0,
              "V0's validator_id");
        CHECK(v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0 &&
              nodus_validator_v2_key_insert(A.w, junk, vidv0,
                                            NODUS_V2_KEY_ROLE_ACTIVE) == 0 &&
              v2x_sql(A.w->db, "COMMIT") == 0,
              "a stray role-1 row names V0");
        CHECK(kr_diff(A.w, 5 * E_LEN) == 1,
              "the boundary-start check (derivation of 5E) sees it: 1 "
              "difference");
        mk_block(&bk, 6 * E_LEN, NULL, 0);
        CHECK(v2x_cmt_apply(A.w, &bk) == NODUS_V2_INTERNAL_FAULT,
              "boundary 6E faults: a stray beside a steady validator's key "
              "is never released as a previous key");
        {
            sqlite3_stmt *st = NULL;
            int ok = sqlite3_prepare_v2(A.w->db,
                         "DELETE FROM v2_consensus_keys "
                         "WHERE consensus_pk_hash = ?1", -1, &st, NULL)
                         == SQLITE_OK &&
                     sqlite3_bind_blob(st, 1, junk, 64, SQLITE_TRANSIENT)
                         == SQLITE_OK &&
                     sqlite3_step(st) == SQLITE_DONE &&
                     sqlite3_changes(A.w->db) == 1;
            if (st) sqlite3_finalize(st);
            CHECK(ok, "the stray row removed (autocommit)");
        }
        CHECK(twins_equal(&A, &B) == 0,
              "after the rolled-back probe A is byte-identical to B");
    }

    /* ── D6. boundary 6E (U of o2) ───────────────────────────────────── */
    CHECK(run_to(&A, &B, &h, 6 * E_LEN) == 0, "boundary 6E");
    CHECK(row_view(A.w, g_rid[o[2]], g_tk[o[2]], -1, &rv) == 0 &&
          rv.cur_is && rv.pend_is && rv.epoch == 0 &&
          keys_naming(A.w, g_rid[o[2]], NODUS_V2_KEY_ROLE_ACTIVE) == 2,
          "o2 swapped at 6E; the sweep at 6E keeps its old key (swapped at "
          "this boundary)");
    CHECK(rv.missed == 0,
          "Rule N at 6E: o2 judged on S(5E) by id, its OLD key signed");

    /* ── votes for (6E, 7E] and D7. boundary 7E: o2's sweep ──────────── */
    CHECK(run_to(&A, &B, &h, 6 * E_LEN + 2) == 0, "blocks 6E+1, 6E+2");
    CHECK(vote_slot(2, g_tk[o[2]], (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
              == 0, "o2: the new key signs from 6E+3");
    CHECK(run_to(&A, &B, &h, 7 * E_LEN) == 0, "boundary 7E");
    CHECK(att_rows(A.w, g_ck[o[2]]) == 0 &&
          key_of(A.w, g_k[g_ck[o[2]]].pk, got, &role) == 1 &&
          keys_naming(A.w, g_rid[o[2]], NODUS_V2_KEY_ROLE_ACTIVE) == 1,
          "o2's old key and attendance row released at its U+E (7E)");
    CHECK(row_view(A.w, g_rid[o[2]], g_tk[o[2]], -1, &rv) == 0 &&
          rv.missed == 0, "Rule N at 7E: o2's new key signed");
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "(i) twin databases byte-identical");
    }
    CHECK(g_kr_runs - kr0 == 2 * (int)(h / E_LEN),
          "the key-reservation self-check compared, and found nothing, at "
          "every boundary on both twins");
    votes_reset();
    fx_close(&A);
    fx_close(&B);
    return 0;
}

/* ══ E. slice 6e — a validator swapped at U that graduates at U+E ═════
 *
 * Design rev 6 §3 (the previous voter's attendance row is deleted at U+E,
 * after that epoch's digest) + khan A2 (the previous key's reservation
 * released at the same boundary). One 12M STAKE (owner KO, key KC1) at
 * block 4, seated from S(3E); ROTATE to KN at 2E+1 (F = 3E) — accepted at
 * 3E (S(3E) = S(4E) = [12M, 10M x 7], P = 82M: 70M > 54666666); KC1
 * signs from 3E+3; UNSTAKE at 3E+3, i.e. RETIRING before U's freeze, so
 * S(5E) does not seat it: swapped at U = 4E (status is not a condition),
 * its graduation deferred at 4E (seated in S(4E)), it graduates at
 * U+E = 5E. KC1 signs 4E and 4E+1 (credited 4E+1, 4E+2), KN from 4E+3.
 * Before 6e the graduation's key_release took KC1's kept role-1 row and
 * the sweep never saw the validator: KC1's attendance row stayed for ever.
 * Now the sweep at 5E releases both, after the digest. F62 is injected at
 * 5E on A first (the graduation and the sweep roll back together). */
static int t_grad_sweep(void) {
    fixture_t A, B;
    static uint8_t call[STK_LEN];
    uint8_t chain32[DNA_CHAIN_ID_LEN], vid[64], intent[64], got[64];
    uint8_t role = 0;
    const uint64_t BIG = 12000000ULL * (uint64_t)DNAC_DECIMAL_UNIT;
    uint64_t h = 0;
    const int kr0 = g_kr_runs;
    rowv_t rv;

    CHECK(E_LEN >= 12, "the fixture's edge precedes the first boundary");
    for (int c = 0; c < N_COINS; c++) g_amt[c] = FEE;
    g_amt[S1] = BIG + FEE;
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "ea") == 0 && fx_open(&B, "eb") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    /* ── E1. block 4: the 12M STAKE (KC1); block 2E+1: ROTATE to KN ─── */
    CHECK(run_to(&A, &B, &h, H14 - 1) == 0, "blocks 1..3 (the edge)");
    CHECK(stake2_call(call, chain32, KC1, H14 + 100, BIG) == STK_LEN,
          "STAKE call");
    CHECK(env_ok(&A, &B, H14, DNA_SYSRULE_STAKE, call, STK_LEN, S1,
                 intent) == 0, "the 12M STAKE applies");
    CHECK(vid_expect(chain32, intent, vid) == 0, "validator_id");
    h = H14;
    CHECK(run_to(&A, &B, &h, 2 * E_LEN) == 0, "to boundary 2E");
    CHECK(rot_call(call, chain32, vid, g_k[KO].fp, KN, KC1,
                   2 * E_LEN + 1 + 100, CS_OK) == ROT_LEN, "ROTATE call");
    CHECK(env_ok(&A, &B, 2 * E_LEN + 1, DNA_SYSRULE_ROTATE_CONSENSUS_KEY,
                 call, ROT_LEN, R1, NULL) == 0, "the ROTATE applies");
    h = 2 * E_LEN + 1;

    /* ── E2. boundary 3E (F): accepted ──────────────────────────────── */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN) == 0, "boundary 3E");
    CHECK(seats_under(A.w, 3 * E_LEN, vid, KC1) == 1,
          "FIXTURE GUARD: S(F) = S(3E) seats it under KC1 (it will sign)");
    CHECK(seats_under(A.w, 4 * E_LEN, vid, KN) == 1,
          "the freeze at 3E accepted the rotation: S(4E) seats KN");

    /* ── E3. KC1 signs from 3E+3; UNSTAKE at 3E+3 (before U's freeze) ─ */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN + 2) == 0, "blocks 3E+1, 3E+2");
    CHECK(vote_slot(0, KC1, (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT) == 0,
          "KC1 signs");
    g_nvote = N_VAL + 1;
    memcpy(call, vid, 64);
    CHECK(env_ok(&A, &B, 3 * E_LEN + 3, DNA_SYSRULE_UNSTAKE, call, 64, R2,
                 NULL) == 0, "block 3E+3: the UNSTAKE applies");
    h = 3 * E_LEN + 3;
    CHECK(row_view(A.w, vid, KC1, KN, &rv) == 0 && rv.cur_is && rv.pend_is &&
          rv.status == DNAC_VALIDATOR_RETIRING,
          "RETIRING before U's freeze, its pending key kept");

    /* ── E4. boundary 4E (U): swapped, graduation deferred, not in S(5E) */
    CHECK(run_to(&A, &B, &h, 4 * E_LEN) == 0, "boundary 4E");
    CHECK(row_view(A.w, vid, KN, -1, &rv) == 0 && rv.cur_is && rv.pend_is &&
          rv.epoch == 0 && rv.status == DNAC_VALIDATOR_RETIRING,
          "swapped at U while RETIRING; its graduation deferred (seated in "
          "S(4E))");
    CHECK(keys_naming(A.w, vid, NODUS_V2_KEY_ROLE_ACTIVE) == 2,
          "KN role 1, KC1 kept role 1 (khan A2)");
    CHECK(seats_under(A.w, 5 * E_LEN, vid, KN) == 0 &&
          seats_under(A.w, 5 * E_LEN, vid, KC1) == 0,
          "S(5E) does not seat it: it graduates at U+E = 5E");

    /* ── KC1 signs 4E, 4E+1 (credited 4E+1, 4E+2); KN from 4E+3 ──────── */
    CHECK(run_to(&A, &B, &h, 4 * E_LEN + 2) == 0, "blocks 4E+1, 4E+2");
    CHECK(vote_slot(0, KN, (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT) == 0,
          "KN signs from 4E+3");
    CHECK(run_to(&A, &B, &h, 5 * E_LEN - 1) == 0, "to block 5E-1");
    CHECK(att_rows(A.w, KC1) == 1,
          "FIXTURE GUARD: the previous voter's attendance row exists before "
          "U+E");

    /* ── E5. boundary 5E (U+E): F62 on A, then the graduation + sweep ── */
    CHECK(inject_boundary(&A, 5 * E_LEN, V2AP_FAIL_AFTER_ROTATE_SWEEP) == 0,
          "F62: boundary 5E faults after the sweep and rolls back whole");
    CHECK(att_rows(A.w, KC1) == 1 &&
          keys_naming(A.w, vid, NODUS_V2_KEY_ROLE_ACTIVE) == 2 &&
          row_view(A.w, vid, KN, -1, &rv) == 0 &&
          rv.status == DNAC_VALIDATOR_RETIRING,
          "F62: the graduation and the sweep rolled back together");
    CHECK(run_to(&A, &B, &h, 5 * E_LEN) == 0,
          "boundary 5E applies on both twins (no -2)");
    CHECK(row_view(A.w, vid, KN, -1, &rv) == 0 && rv.cur_is && rv.pend_is &&
          rv.status == DNAC_VALIDATOR_UNSTAKED,
          "it graduated at U+E: UNSTAKED under KN, no pending key");
    CHECK(att_rows(A.w, KC1) == 0,
          "the previous voter's attendance row is deleted at U+E");
    CHECK(keys_naming(A.w, vid, NODUS_V2_KEY_ROLE_ACTIVE) == 0 &&
          keys_naming(A.w, vid, NODUS_V2_KEY_ROLE_PENDING) == 0 &&
          key_of(A.w, g_k[KC1].pk, got, &role) == 1 &&
          key_of(A.w, g_k[KN].pk, got, &role) == 1,
          "no reservation survives: KN by the graduation, KC1 by the sweep");
    CHECK(twins_equal(&A, &B) == 0,
          "twin databases byte-identical (the faulted 5E replayed on A)");
    CHECK(g_kr_runs - kr0 == 2 * (int)(h / E_LEN),
          "the key-reservation self-check compared, and found nothing, at "
          "every boundary on both twins");
    votes_reset();
    fx_close(&A);
    fx_close(&B);
    return 0;
}

/* ══ F. khan A7 — the cumulative predecessor budget (BUGS Z-27) ════════
 *
 * Design §3 "(A7) Birikimli bütçe" (khan 2026-10-13): at the freeze of
 * S(f + E) the predecessor party R_F starts from the counted power of the
 * entries of S(f) whose key differs from the same validator_id's entry in
 * S(f − E) — a ruleset-1 S(f − E) matched through the migrated-id bridge
 * (dna_validator_id_migrated over its entry keys); 0 when S(f − E) is
 * absent; an unreadable S(f − E) is a fault. The seven genesis seats of a fresh twin (no STAKE) are
 * [10M × 7] in every snapshot: P = 70M, floor(2P/3) = 46666666 — a party
 * of 2 seats leaves 50M (fits), of 3 leaves 40M (does not).
 *
 * Genesis seats are Foundation-owned (no test can sign their ROTATE), so
 * every probe is the C1c device on twin A inside a ROLLED-BACK
 * transaction: S(f)'s stored entries re-keyed (snap_rekey — a rotation
 * the previous freeze "accepted"), two pending rows planted with F = f,
 * and the freeze of S(f + E) PREVIEWED (the core commit_next runs). Then
 * A == B, byte for byte.
 *   F1 f = 3E (S(3E), S(2E) both ruleset 2):
 *      (a) no re-key: both candidates accepted — carry 0, the pre-A7
 *          answer;
 *      (b) V0, V1 re-keyed in S(3E) (carry 20M = 2/7): both WAIT
 *          (20M + 10M leaves 40M) — the Z-27 scenario;
 *      (c) V0 alone re-keyed (carry 10M): the id-smaller candidate is
 *          accepted (20M), the other waits (30M) — exactly as much as the
 *          carry leaves (A3: skip, keep walking);
 *      (d) V0, V1 re-keyed in S(3E) AND V0's seat removed from S(2E):
 *          carry 10M (V1 only — an entry with no seat in S(f − E) is not a
 *          rotation): as (c);
 *      (e) V0, V1 re-keyed in S(3E), S(2E) DELETED: carry 0 (absent ⇒ 0),
 *          both accepted;
 *      (f) V0, V1 re-keyed, S(2E)'s stored hash broken: with candidates the
 *          freeze FAULTS (unreadable ≠ absent); with none it builds (the
 *          pass reads nothing then);
 *      (g) V0, V1, V2 re-keyed in S(3E) (carry 30M = 3/7, 40M left ≤
 *          46666666 — a carry over its budget, the broken invariant):
 *          with candidates the freeze FAULTS; with none it builds.
 *   F2 f = 2E (S(2E) ruleset 2, its predecessor S(E) the genesis ruleset
 *      1 — the first generation-4 freeze accepts rotations into S(2E)
 *      against it through the bridge, C1c): V0, V1 re-keyed in S(2E) —
 *      the bridge matches them in S(E), carry 2/7, both candidates WAIT;
 *      V0 alone — carry 1/7, the id-smaller accepted, the other waits.
 *
 * HOW IT CAN LIE: the re-keyed snapshots are hand-written (the hash
 * re-derived): they prove the pass on those bytes, not that a chain
 * reaches them (D does that for (b)). F1 (d) and (e) assume the committee
 * compute of S(4E) does not read S(2E) (as C4b (f) shows for S(3E) with
 * S(2E) deleted); if it did, they would fault rather than pass. */

/* the roles row of `vid`: pending := g_k[key].pk, F := ep. 0 / -1 */
static int plant_pending(nodus_witness_t *w, const uint8_t vid[64], int key,
                         uint64_t ep) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_validator_roles SET pending_consensus_pubkey = ?1, "
            "consensus_key_effective_epoch = ?2 WHERE validator_id = ?3",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ok = sqlite3_bind_blob(st, 1, g_k[key].pk, (int)PK_LEN,
                               SQLITE_TRANSIENT) == SQLITE_OK &&
             sqlite3_bind_int64(st, 2, (sqlite3_int64)ep) == SQLITE_OK &&
             sqlite3_bind_blob(st, 3, vid, 64, SQLITE_TRANSIENT)
                 == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_DONE &&
             sqlite3_changes(w->db) == 1;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* the STORED S(epoch) without the seat of `vid` (order kept). 0 / -1 */
static int snap_drop(nodus_witness_t *w, uint64_t epoch,
                     const uint8_t vid[64]) {
    dna_vset_snapshot_t *s = NULL, *d = NULL;
    if (nodus_witness_vset_get(w, epoch, &s, NULL) != 0 || !s) return -1;
    int ok = -1, j = snap_idx(s, vid);
    if (j >= 0 && s->active_count > 1 &&
        (d = dna_vset_alloc((uint16_t)(s->active_count - 1))) != NULL) {
        d->epoch = s->epoch;
        d->selection_ruleset = s->selection_ruleset;
        memcpy(d->sortition_seed, s->sortition_seed, DNA_VSET_SEED_LEN);
        uint16_t n = 0;
        for (uint16_t i = 0; i < s->active_count; i++)
            if ((int)i != j) d->entries[n++] = s->entries[i];
        ok = snap_store(w, d);
    }
    dna_vset_free(&d);
    dna_vset_free(&s);
    return ok;
}

/* the predecessor S(f − E) edits a probe makes before the preview */
enum { CUM_PRED_KEEP, CUM_PRED_DROP_V0, CUM_PRED_DELETE, CUM_PRED_BREAK };

/* One rolled-back probe on twin A: re-key `nrk` seats of S(f) (vids
 * rk[0..nrk) to KC1, KC2, KC3; nrk <= 3), edit S(f − E) per `pred`, plant the pending
 * keys KN / KN2 on cand[0] / cand[1] with F = f (ncand of them), preview
 * the freeze of S(f + E). *rc = the preview's rc; acc[c] = 1 the
 * candidate's S(f + E) entry carries its pending key / 0 its current key
 * (= vk[c]) / -1 neither. 0 the probe ran (and rolled back) / -1. */
static int cum_probe(nodus_witness_t *w, uint64_t f,
                     const uint8_t (*rk)[64], int nrk, int pred,
                     const uint8_t (*cand)[64], const int *vk, int ncand,
                     int *rc, int acc[2]) {
    static const int rkey[3] = { KC1, KC2, KC3 };
    static const int pkey[2] = { KN, KN2 };
    dna_vset_snapshot_t *pv = NULL;
    int ok = 1;
    acc[0] = acc[1] = -1;
    if (v2x_sql(w->db, "BEGIN IMMEDIATE") != 0) return -1;
    for (int i = 0; ok && i < nrk; i++)
        ok = snap_rekey(w, f, rk[i], rkey[i]) == 0;
    if (ok && pred == CUM_PRED_DROP_V0)
        ok = snap_drop(w, f - E_LEN, rk[0]) == 0;
    if (ok && pred == CUM_PRED_DELETE) {
        char sql[160];
        snprintf(sql, sizeof(sql), "DELETE FROM validator_set_snapshots "
                 "WHERE epoch_start = %llu",
                 (unsigned long long)(f - E_LEN));
        ok = v2x_sql(w->db, sql) == 0 && sqlite3_changes(w->db) == 1;
    }
    if (ok && pred == CUM_PRED_BREAK) {
        char sql[160];
        snprintf(sql, sizeof(sql), "UPDATE validator_set_snapshots SET "
                 "snapshot_hash = zeroblob(64) WHERE epoch_start = %llu",
                 (unsigned long long)(f - E_LEN));
        ok = v2x_sql(w->db, sql) == 0 && sqlite3_changes(w->db) == 1;
    }
    w->cached_committee_epoch_start = UINT64_MAX;
    for (int c = 0; ok && c < ncand; c++)
        ok = plant_pending(w, cand[c], pkey[c], f) == 0;
    if (ok) {
        *rc = nodus_witness_vset_preview_next(w, f, NODUS_RT_GEN_STORAGE,
                                              &pv);
        for (int c = 0; *rc == 0 && pv && c < ncand; c++) {
            int j = snap_idx(pv, cand[c]);
            if (j < 0) continue;
            if (memcmp(pv->entries[j].pubkey, g_k[pkey[c]].pk, PK_LEN) == 0)
                acc[c] = 1;
            else if (memcmp(pv->entries[j].pubkey, g_k[vk[c]].pk,
                            PK_LEN) == 0)
                acc[c] = 0;
        }
        dna_vset_free(&pv);
    }
    if (v2x_sql(w->db, "ROLLBACK") != 0) ok = 0;
    w->cached_committee_epoch_start = UINT64_MAX;
    return ok ? 0 : -1;
}

static int t_cumulative(void) {
    fixture_t A, B;
    uint8_t chain32[DNA_CHAIN_ID_LEN], vid[N_VAL][64];
    uint8_t rk[3][64], cd[2][64];
    int vk[2], acc[2], rc = 0;
    uint64_t h = 0;
    const int kr0 = g_kr_runs;

    CHECK(E_LEN >= 12, "the fixture's edge precedes the first boundary");
    for (int c = 0; c < N_COINS; c++) g_amt[c] = FEE;
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "fa") == 0 && fx_open(&B, "fb") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");
    for (int i = 0; i < N_VAL; i++)
        CHECK(dna_validator_id_migrated(vid[i], chain32, g_k[V0 + i].pk)
                  == 0, "genesis seat's migrated validator_id");
    /* the re-keyed seats V0, V1; the candidates V2, V3 in validator_id
     * ASC (cd[0] the smaller), vk[] their current keys */
    memcpy(rk[0], vid[0], 64);
    memcpy(rk[1], vid[1], 64);
    memcpy(rk[2], vid[2], 64);              /* (g) only: three re-keys */
    {
        const int lo = memcmp(vid[2], vid[3], 64) < 0 ? 2 : 3;
        const int hi = lo == 2 ? 3 : 2;
        memcpy(cd[0], vid[lo], 64);
        memcpy(cd[1], vid[hi], 64);
        vk[0] = V0 + lo;
        vk[1] = V0 + hi;
    }

    /* ── F2. f = 2E: S(f − E) = S(E) is the genesis ruleset-1 set ────── */
    CHECK(run_to(&A, &B, &h, 2 * E_LEN) == 0, "to boundary 2E");
    {
        dna_vset_snapshot_t *x = NULL;
        CHECK(nodus_witness_vset_get(A.w, E_LEN, &x, NULL) == 0 && x &&
              x->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
              "FIXTURE GUARD: S(E) is ruleset 1");
        dna_vset_free(&x);
        for (int s = 2; s <= 3; s++) {
            uint64_t pw[DNA_MAX_ACTIVE_VALIDATORS], P = 0;
            dna_vset_snapshot_t *y = NULL;
            CHECK(nodus_witness_vset_get(A.w, (uint64_t)s * E_LEN, &y, NULL)
                      == 0 && y &&
                  y->selection_ruleset == DNA_VSET_RULESET_TOPN_V2 &&
                  y->active_count == N_VAL &&
                  nodus_witness_vset_powers(A.w, y, pw) == 0,
                  "FIXTURE GUARD: S(2E) / S(3E) ruleset 2, seven seats");
            for (uint16_t j = 0; j < y->active_count; j++) {
                CHECK(pw[j] == 10000000ULL,
                      "FIXTURE GUARD: counted [10M x 7]");
                P += pw[j];
            }
            dna_vset_free(&y);
            CHECK(P == 70000000ULL && P * 2 / 3 == 46666666ULL &&
                  P - 20000000ULL > P * 2 / 3 &&
                  !(P - 30000000ULL > P * 2 / 3),
                  "P = 70M: a party of two fits, of three does not");
        }
    }
    CHECK(cum_probe(A.w, 2 * E_LEN, (const uint8_t (*)[64])rk, 2,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0,
          "F2: probe ran, preview built");
    CHECK(acc[0] == 0 && acc[1] == 0,
          "F2: the bridge finds V0, V1 in the ruleset-1 S(E) — carry 2/7, "
          "both WAIT");
    CHECK(cum_probe(A.w, 2 * E_LEN, (const uint8_t (*)[64])rk, 1,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0 && acc[0] == 1 && acc[1] == 0,
          "F2: V0 alone through the bridge — carry 1/7, the id-smaller "
          "accepted, the other waits");
    CHECK(twins_equal(&A, &B) == 0, "F2 rolled back: A == B");

    /* ── F2k. the self-check's ruleset-1 bridge (S(E) has no ids) ───────
     * At 2E, S(2E) (ruleset 2) against S(E) (ruleset 1, matched through
     * dna_validator_id_migrated). On A, ROLLED BACK: S(2E)'s V0 entry
     * re-keyed to KX. The bridge finds V0 in S(E) under a DIFFERENT key,
     * so S(E)'s key (V0's own, still its current role-1 key) is derived a
     * second time as a previous key: exactly one difference (a key derived
     * twice). Without the bridge V0 would have no S(E) seat and — KX not
     * being its row's key — no tolerance either: 0 differences. */
    {
        CHECK(kr_diff(A.w, 2 * E_LEN) == 0,
              "self-check at 2E: 0 differences");
        long n = -1;
        if (v2x_sql(A.w->db, "BEGIN IMMEDIATE") == 0) {
            if (snap_rekey(A.w, 2 * E_LEN, vid[0], KX) == 0)
                n = kr_diff(A.w, 2 * E_LEN);
            if (v2x_sql(A.w->db, "ROLLBACK") != 0) n = -1;
            A.w->cached_committee_epoch_start = UINT64_MAX;
        }
        CHECK(n == 1, "F2k: the bridge matched V0 in the ruleset-1 S(E): "
              "1 difference");
        CHECK(twins_equal(&A, &B) == 0 && kr_diff(A.w, 2 * E_LEN) == 0,
              "F2k rolled back: A == B, 0 differences");
    }

    /* ── F1. f = 3E: S(3E), S(2E) both ruleset 2 ──────────────────────── */
    CHECK(run_to(&A, &B, &h, 3 * E_LEN) == 0, "boundary 3E");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 0,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0 && acc[0] == 1 && acc[1] == 1,
          "(a) no rotation carried: both accepted (carry 0, as before A7)");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 2,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0 && acc[0] == 0 && acc[1] == 0,
          "(b) S(3E) carries V0, V1 (2/7): + one more is 3/7 — both WAIT");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 1,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0 && acc[0] == 1 && acc[1] == 0,
          "(c) carry 1/7: the id-smaller candidate accepted, the other "
          "waits");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 2,
                    CUM_PRED_DROP_V0, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0 && acc[0] == 1 && acc[1] == 0,
          "(d) V0 has no seat in S(2E): not counted — carry 1/7 (V1)");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 2,
                    CUM_PRED_DELETE, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == 0 && acc[0] == 1 && acc[1] == 1,
          "(e) S(2E) absent: carry 0, both accepted");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 2,
                    CUM_PRED_BREAK, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == -1,
          "(f) S(2E) unreadable, with candidates: the freeze FAULTS");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 2,
                    CUM_PRED_BREAK, (const uint8_t (*)[64])cd, vk, 0, &rc,
                    acc) == 0 && rc == 0,
          "(f) S(2E) unreadable, no candidate: builds (nothing read)");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 3,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 2, &rc,
                    acc) == 0 && rc == -1,
          "(g) a carry of 3/7 exceeds its budget: with candidates the "
          "freeze FAULTS");
    CHECK(cum_probe(A.w, 3 * E_LEN, (const uint8_t (*)[64])rk, 3,
                    CUM_PRED_KEEP, (const uint8_t (*)[64])cd, vk, 0, &rc,
                    acc) == 0 && rc == 0,
          "(g) the same S(3E), no candidate: builds (nothing read)");
    CHECK(twins_equal(&A, &B) == 0, "F1 rolled back: A == B");
    CHECK(g_kr_runs - kr0 == 2 * (int)(h / E_LEN),
          "the key-reservation self-check compared, and found nothing, at "
          "every boundary on both twins");

    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "table_op10_owned",      t_table },
        { "hooks_gen4_rotate",     t_hooks },
        { "engine_gen4_rotate",    t_engine },
        { "swap_by_validator_id",  t_swap },
        { "freeze_budget_sweep",   t_budget },
        { "graduate_prev_key",     t_grad_sweep },
        { "cumulative_budget_a7",  t_cumulative },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0 || desc_make() != 0) {
        fprintf(stderr, "test_hf6_rotate: key / descriptor setup failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_rotate: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
