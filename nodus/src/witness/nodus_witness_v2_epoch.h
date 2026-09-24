/**
 * @file nodus_witness_v2_epoch.h
 * @brief Ledger V2 O12 S2 — the ENGINE-MANDATORY epoch-boundary state
 *        transition for the (still INACTIVE) V2 apply engine.
 *
 * ONE entry point, called from nodus_witness_v2_apply_block INSIDE the
 * one block transaction (after the S6 claim phase, the S7 pool phase and
 * the in-block DomainHead lifecycle re-scan; before the supply gate and
 * the domain-roots phase). Nothing here opens or closes a transaction —
 * the whole witness DB layer's convention (nodus_witness_vset.h:33-35).
 *
 * ════════════════════════════════════════════════════════════════════
 * STILL INACTIVE. No live consensus path calls this module: the V2 apply
 * engine itself has no live caller, and the LEGACY boundary
 * (apply_epoch_boundary_transitions, nodus_witness_bft.c:2352) is
 * byte-untouched and remains the only boundary a running chain executes.
 * This is the V2-lane MIRROR of that transition, not a replacement.
 * ════════════════════════════════════════════════════════════════════
 *
 * ── FAULT, never VERDICT ────────────────────────────────────────────
 * The boundary consumes NO caller-supplied, consensus-classifiable
 * input. It is a pure function of committed state and the block height,
 * so there is no "the block lied" class here: every failure — a DB
 * error, a malformed committed row, an arithmetic bound, a snapshot
 * conflict — means THIS NODE could not compute the transition, and the
 * only safe answer is -2 (node-local fault). A witness that cannot
 * compute its own boundary must not vote; it must not convert its
 * inability into a rejection of a block its peers may apply fine.
 * (The FAULT/VERDICT contract: nodus_witness_v2_apply.h:482-491.)
 *
 * ── THE TRANSITION ORDER (mirror of the shipped legacy boundary) ────
 * Source: apply_epoch_boundary_transitions, nodus_witness_bft.c:2310-2660,
 * plus the S3 vset finale documented at nodus_witness_vset.h:14-17
 * (flips then commit_next as the FINAL steps of that function).
 *
 *   0. GATE — no-op (0) unless global_height > 0 &&
 *      global_height % DNAC_EPOCH_LENGTH == 0. Exact mirror of
 *      nodus_witness_bft.c:2358. Height only: no clock, no timestamp.
 *   1. PENDING COMMISSION ACTIVATION — bft.c:2379-2402 verbatim shape.
 *   1b. REWARD DISTRIBUTION (tokenomics-v3 P2, P2-6) —
 *      nodus_witness_v2_settlement_apply(w, H): payout = reward_pool >>
 *      16 over snapshot(H−E) pro rata to its power, inner split on the
 *      source copy src(H) = H−2E (0 below 2E) after a consistency gate
 *      against the snapshot entry (P2 revision 2, design §7.1),
 *      credited to `v2_reward_accrual`, reward_pool debited by exactly
 *      what was credited. Contract: nodus_witness_v2_econ.h.
 *   1c. PAYDAY (P2-7) — nodus_witness_v2_payday_apply(w, H, interval):
 *      at (H / E) % payout_interval_epochs == 0 every accrual row
 *      becomes one CORE UTXO and is deleted; a no-op otherwise. Runs
 *      AFTER 1b so the epoch that just ended is included in the pay.
 *   2. GRADUATION — tokenomics-v3 P1 (D-11): candidates are every row
 *      whose status is RETIRING **or AUTO_RETIRED** (widened from
 *      RETIRING-only; an AUTO_RETIRED member's bond is RETURNED, never
 *      cut — decision §3, 2026-09-23), selected ORDER BY pubkey ASC
 *      (bft.c:2416-2422; the order is load-bearing and is a stable total
 *      key on every node), bounded by DNAC_MAX_VALIDATORS.
 *
 *      ROUND 5 DEFERRAL (decision file §3 2026-09-23, "ayrılan
 *      validatorun MEZUNİYETİ … ertelenir"; O6 red-team L1-1): a
 *      candidate graduates at boundary H ONLY IF its pubkey is NOT an
 *      entry of `nodus_witness_v2_epoch_authority_for_epoch(w, H)` — the
 *      snapshot TAKING EFFECT at H. If it is still an entry (a member
 *      that unstaked during the just-ended epoch, whose exit snapshot(H)
 *      predates), it is left UNTOUCHED for a LATER boundary; no counter,
 *      no status change, no fault. Before this round graduation ran with
 *      no height condition at all: a member frozen into snapshot(H) at
 *      H-E (before it ever unstaked) is still an entry cometbft votes
 *      with until H+2, so releasing its bond and dropping its row at H
 *      let it (and its operator) walk away while still owed a vote —
 *      measured trigger: >=1/3 of a 7-member set leaving in the same
 *      epoch and shutting their nodes down at graduation halts the chain
 *      with no boundary able to recover, because the boundary that would
 *      exclude them (H+E) never arrives without their vote. Absent/
 *      unreadable snapshot(H) -> -2 (a boundary has no verdict class),
 *      same fail-closed rule R5-1 gives Rule N. Practical consequence: an
 *      exiting validator remains seated — and must keep signing — for
 *      ONE FULL EXTRA EPOCH past its own UNSTAKE; its unlock height
 *      starts counting from the boundary at which it actually graduates,
 *      not the one at which UNSTAKE was requested.
 *
 *      Per graduate, in the legacy order (bft.c:2465-2560): release UTXO
 *      → validators row → active_count — EXCEPT active_count is
 *      decremented only for a graduate whose status WAS RETIRING; Rule N
 *      already decremented it for AUTO_RETIRED at the boundary that
 *      retired it, and decrementing twice would poison
 *      `nodus_validator_active_count` for every later reader.
 *   (2b — the O15J EPOCH SETTLEMENT — is GONE from this position:
 *      tokenomics-v3 P2 replaced it with the distribution at 1b.)
 *   3. RULE N (liveness / AUTO_RETIRED) — REWRITTEN by tokenomics-v3 P1
 *      (D-3); see the labelled section below.
 *   3b. ATTENDANCE DIGEST (S-2) — `v2ep_attendance_digest`: hashes every
 *      `v2_attendance` row of the epoch that just ended (voter_id ASC)
 *      into ONE digest, written to `v2_attendance_epoch`. This is the
 *      ONLY point at which the out-of-root attendance table's contents
 *      enter `system_state_root` (the `attendance_root` leg,
 *      shared/dnac/ledger_roots_v2.c) — a divergence between two nodes'
 *      `v2_attendance` rows is invisible until this digest, and certain
 *      here.
 *   3c. ATTENDANCE RESET — `UPDATE v2_attendance SET signed_count = 0`
 *      (keeping `last_signed_height`, the P2 watermark Rule N's NEXT
 *      boundary needs). MUST run AFTER 3b: resetting before hashing would
 *      digest all zeros and hide every divergence the leg exists to
 *      catch.
 *   4. BOUNDARY FLIPS — nodus_witness_vset_apply_boundary_flips(w, H).
 *   5. NEXT SNAPSHOT — nodus_witness_vset_commit_next(w, H).
 *   6. BALANCE COPY (tokenomics-v3 P2, P2-5) —
 *      nodus_witness_v2_balance_copy_write(w, H): the bonded balances as
 *      they stand AFTER every one of this boundary's transitions, pruned
 *      to the H−E and H copies. Out of every root.
 *
 * ── WHY THE DISTRIBUTION SITS AT 1b (tokenomics-v3 P2) ──────────────
 * Three inputs decide it, and each fixes a bound on its position:
 *   - ATTENDANCE: the shared participation predicate reads
 *     `v2_attendance.signed_count` for the epoch that just ended, and
 *     step 3c zeroes that column — the distribution must run BEFORE 3c
 *     (the O15J settlement's own reason for sitting at 2b; running after
 *     3c would forfeit every honest share, every epoch, on every node).
 *   - NO LIVE STAKE (P2 revision 2, design §7.1): the amounts come from
 *     the governing snapshot(H−E) and the source copy, never from the
 *     live `validators` / `delegations` stakes; the only live read is
 *     whether a member's `validators` row exists, and no boundary step
 *     deletes one (step 2 zeroes a graduate's self_stake and sets
 *     UNSTAKED). Running before step 2 is kept, and is no longer what
 *     pays a leaving validator for its last seated epoch — its snapshot
 *     entry does (the decision file §3 graduation deferral: it keeps
 *     signing that epoch and loses the share only by missing the bar).
 *   - THE FROZEN SIDE: the source copy src(H) = copy(H−2E) was written
 *     at the END of boundary H−2E (step 6), right after the commit_next
 *     that built snapshot(H−E); boundary H−E's prune kept it, and THIS
 *     boundary's step 6 prune deletes it. So the distribution MUST run
 *     before step 6. copy(H) is written last and is not read here.
 * Rule N (3), the digest (3b) and the flips (4) write only statuses,
 * counters, `v2_attendance_epoch` and snapshots; none is read by 1b or
 * 1c, and neither 1b nor 1c writes anything they read (1b writes
 * `v2_reward_accrual` and `supply_tracking.reward_pool`, 1c `utxo_set`
 * and `v2_reward_accrual`). The payday (1c) sits right after 1b so the
 * epoch just credited is included in a paying boundary.
 *
 * ── WHY THE BALANCE COPY SITS LAST (step 6) ─────────────────────────
 * The copy freezes the balances the NEXT epoch starts from. Of this
 * boundary's steps only the graduation (2) moves a stake (it zeroes a
 * graduate's self_stake, which drops it from the copy); Rule N and the
 * flips move statuses only, and the copy carries no status. Writing it
 * after step 5 therefore captures the post-boundary state, and it adds
 * nothing between Rule N and commit_next — the window Rule N's weight
 * floor argument (v2ep_rule_n) requires to stay free of writes to
 * committee inputs.
 *
 * ── RULE N: REWRITTEN (tokenomics-v3 P1, D-3) ───────────────────────
 * The legacy boundary's third transition (liveness-based AUTO_RETIRED,
 * bft.c:2559-2660) reads a per-validator attendance watermark. O12
 * deferred it because the V2 lane had no writer; O15C supplied one keyed
 * on the committed header PROPOSER. Operator O4 (2026-09-23) replaced
 * that source: participation is now REAL signature attendance, counted
 * ONLY from cometbft's `decided_last_commit`
 * (`nodus_witness_v2_attendance_credit`, below) — the proposer identity
 * never enters the count. No base-leader blame (the legacy/O15C rule
 * blamed only the epoch's one designated "base leader" slot; that
 * concept is gone). Two independent predicates, BOTH required (decision
 * §1 "birlikte aranacak"), evaluated by ONE exported function,
 * `nodus_witness_v2_attendance_meets_bar` (below — tokenomics-v3 P1
 * round 3, operator 2026-09-23):
 *   P1 (50% bar)   signed_count * 10000 >= DNAC_EPOCH_LENGTH *
 *                  DNAC_LIVENESS_THRESHOLD_BPS  (8000 -> 5000, round 3 —
 *                  deliberately below cometbft's structural ~67-73%
 *                  attendance FLOOR — round 5 correction, see the
 *                  constant's own comment in dnac.h for the direction
 *                  fix and why 80% was unsafe)
 *   P2 (recency)   last_signed_height > 0 &&
 *                  last_signed_height >= (H > W ? H - W : 0),
 *                  W = DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS
 * `miss = !(P1 && P2)`.
 *
 * ── ROUND 5: WHO HAS A DUTY (O6 verifier V-1, red-team L3-1/L3-2) ────
 * `miss` is only CHARGED to a member with a DUTY this boundary: an entry
 * of the COMMITTED snapshot that governed the epoch just ending,
 * `nodus_witness_v2_epoch_authority_for_epoch(w, H-E)` (the set flipped
 * ACTIVE at boundary H-E, the one cometbft has used since H-E+2), AND
 * currently `status = ACTIVE`. RETIRING rows are never scanned (an
 * exiting member cannot be auto-retired a second time). Every OTHER
 * bonded row (ACTIVE without a duty this boundary — a mid-epoch STAKE
 * seated after snapshot(H-E) was frozen — or ELIGIBLE) has its counter
 * RESET to 0 instead: an epoch without a duty breaks the chain of
 * consecutive misses. Before this round every ACTIVE row was evaluated
 * regardless of duty, which (a) charged a brand-new staker a miss it
 * had no way to avoid, and (b) let a counter earned in one duty epoch
 * survive into a later, unrelated one, turning two NON-consecutive
 * misses into a retirement — both measured (verifier V-1). Absent/
 * unreadable duty snapshot -> -2 (a boundary has no verdict class).
 *
 * ── ROUND 6: THE WEIGHT FLOOR (decision file §3 2026-09-23 "Rule N
 * TABANI WEIGHT ÜZERİNDEN", replacing round 5's count floor "Rule N
 * TABANI = 4", now marked invalid) ─────────────────────────────────
 * Why a floor exists at all (unchanged): the round-3 "no floor" call
 * rested on an argument the ORCHESTRATOR had written backwards (average
 * attendance is AT LEAST ~67 %, a floor, not a ceiling — corrected in the
 * decision file §3, 2026-09-23) and on a "3 of 7" bound that ignored the
 * recency window; red-team L3-2 showed the bar and the 120-block window
 * can fail DIFFERENT members at the same boundary (5 of a 7-member
 * committee in one worked example, every block still committing), and
 * departing members still vote one more epoch while Rule N evaluates only
 * seated ones — so retiring everyone past the threshold can leave a next
 * set that cannot survive losing one member, or no set at all.
 *
 * What it measures (round 6): with every row that reached
 * DNAC_AUTO_RETIRE_EPOCHS provisionally AUTO_RETIRED inside a SAVEPOINT,
 * Rule N builds — without storing — the snapshot this same boundary's
 * `nodus_witness_vset_commit_next` will store for H+E
 * (`nodus_witness_vset_preview_next`, nodus_witness_vset.h). Power per
 * entry = `total_stake / DNAC_DECIMAL_UNIT` (the unit the §A
 * ValidatorUpdate diff reports, nodus_witness_cmt_app.c:1569); P = the
 * checked sum, max = the largest entry. The retirement stands iff
 * P > 0 AND (P − max) > P * 2 / 3 — cometbft's own integer commit form
 * (shared/dnac/cmt_validation.c:298): the next set must still commit
 * with its single largest member gone. An EMPTY next set (preview rc 1)
 * is never allowed. Otherwise the boundary ROLLS BACK TO the savepoint
 * and retires NOBODY: counters keep their incremented values (the
 * members go at the first boundary where the survivors can carry them),
 * active_count does not move, one QGP_LOG_WARN names the boundary, the
 * would-be count, P and max. A preview FAULT (rc -1) fails the boundary
 * (-2), never a verdict. All-or-nothing — never a partial or ranked
 * retirement — the same precedent as `nodus_witness_domreg_exclusions_at`
 * (nodus_witness_domreg.h:239-246).
 *
 * Why weight, not count (the count floor's defects, O6 verifier + the
 * operator): it counted bonded rows the tenure gate will not seat next
 * epoch (`nodus_validator_top_n`, nodus_witness_validator.c:311 — 7
 * members + 1 fresh staker, 4 retired: count 4, next set 3 seats), and a
 * 4-member set where one member holds 40 % stalls on that member alone.
 * The weight inequality forces max < P/3, so it implies at least four
 * seatable members — the old count bound follows from it.
 *
 * What it does NOT do (open operator questions, decision file §3): it
 * does not cap how MANY may be retired at one boundary in a large set
 * (100 equal members, 96 retired → 4 equal left → allowed); and if one
 * member already holds at least a third of the next set's power it
 * allows no retirement at all (stake concentration, tied to the open
 * pre-testnet power-cap decision).
 *
 * Why the preview IS the stored snapshot: between Rule N and
 * commit_next the boundary runs only the attendance digest, the
 * attendance reset and the flips; none of them writes an input of
 * `nodus_committee_compute_for_epoch(H+E)` (the per-input argument, with
 * file:line, is the comment above the floor in v2ep_rule_n,
 * nodus_witness_v2_epoch.c). Re-check it if that ordering ever moves.
 *
 * ── THE SAME PREDICATE BINDS THE REWARD BAR (round 3) ────────────────
 * `nodus_witness_v2_attendance_meets_bar` is not Rule N's alone: the
 * settlement liveness bar (`nodus_witness_v2_econ.c`) calls the SAME
 * function, so a validator's ACTIVE-set membership and its epoch payout
 * are decided by the identical P1 && P2 test at the identical rate. This
 * is not a design choice this package invented — it is decision §1
 * line 79's own parenthetical, "Aynı oran ödül hak edişi için de
 * geçerli: tek kural, iki tüketici" ("the same rate applies to reward
 * eligibility too: one rule, two consumers"), and §3's last entry states
 * the mechanism explicitly: "ödül ve çıkarılma TEK kurala bağlanır" /
 * "settlement barının kendi formülü yerine Rule N'in yüklemini
 * çağırması" (the settlement bar calls Rule N's PREDICATE, not a
 * formula of its own). Before round 3 the settlement bar had its own
 * `signed_count * committee_count * 10000 >= E * BPS` formula — the
 * `× committee_count` factor was a leftover normalisation from the
 * retired PROPOSER-credit era (a proposer could only ever propose about
 * E / committee_count blocks) that, once attendance switched to
 * signature counting, made the reward bar's EFFECTIVE rate ~11% while
 * Rule N's was 80%: two different answers to one question. Round 3
 * deletes that factor along with the divergence.
 *
 * ── ACTIVATION OBLIGATION 1: legacy-malformed validator rows ────────
 * `validators` is SHARED with the live legacy lane. A row whose
 * unstake_destination_fp is not exactly 128 lowercase hex characters
 * (NUL-terminated), or whose numeric columns exceed the SQLite INTEGER
 * storage bound, or whose status byte is undefined, is REFUSED here:
 * the boundary returns -2 rather than paying out to an unparseable
 * destination or writing a row that would round-trip negative. This
 * mirrors the O11 write-freeze discipline (nodus_witness_rt_native.c
 * rtn_val_rec_ok, :3899-3933) with ONE deliberate difference: O11's
 * write-freeze is a deterministic VERDICT because a caller chose to
 * touch that row, whereas the boundary touches every RETIRING row
 * unconditionally, so the same condition can only be a fault.
 * BEFORE the V2 lane goes live on a chain that already ran the legacy
 * lane, malformed legacy rows MUST be reconciled — otherwise one bad
 * row halts every boundary. Same obligation class as the O11 season's
 * validators/delegations/validator_stats note.
 *
 * ── ACTIVATION OBLIGATION 2: the snapshot's legacy seed source ──────
 * nodus_witness_vset_commit_next → nodus_witness_vset_build_for_epoch →
 * nodus_committee_compute_for_epoch reads, for e_start >=
 * DNAC_EPOCH_LENGTH + 1, the LEGACY `blocks` row at
 * e_start − DNAC_EPOCH_LENGTH − 1 for its state_seed tiebreak
 * (nodus_witness_committee.c:116-125). At a boundary H the built epoch
 * is e_start = H + DNAC_EPOCH_LENGTH, so the lookback row is at H − 1 —
 * a LEGACY block row, which a pure-V2 chain does not produce. O12
 * mirrors the source EXACTLY rather than inventing a V2-native seed;
 * choosing the V2-native seed source (v2_blocks? the global root?) is a
 * consensus decision owned by the activation season. Tests supply the
 * legacy row explicitly (test_v2_epoch.c), which is an honest fixture,
 * not a claim that the seam is closed.
 *
 * ── GRAD_ID: the canonical per-record graduation identity ───────────
 *   grad_id = SHA3-512( "DNA.EPGRAD.v1" zero-padded to exactly 16 bytes
 *                     ‖ chain_id[32]
 *                     ‖ u32be(DNA_DOMAIN_CORE)
 *                     ‖ u64be(global_height)
 *                     ‖ pubkey_hash[64] )
 * where pubkey_hash = SHA3-512(0x02 ‖ validator_pubkey) — the SOURCE
 * validators-table key derivation (NODUS_TREE_TAG_VALIDATOR = 0x02,
 * nodus/include/nodus/nodus_types.h:189; documented at
 * nodus_witness_validator.h:31-37; the same shape rt_native.c's
 * rtn_tag_key computes). The 16-byte-tag hashing idiom is the repo's
 * (shared/dnac/pool_wire.c:21-35). The tag string "DNA.EPGRAD.v1" was
 * collision-scanned repo-wide before adoption: no other consumer.
 *
 * WHY THIS SUPERSEDES THE LEGACY DERIVATION. The legacy lane derives
 * ONE per-block pseudo hash SHA3-512("dnac_epoch_graduation_v1" padded
 * to 32 ‖ u64be(height)) (bft.c:2362-2376) and separates graduates by
 * output_index 200 + i (bft.c:2492-2507), so a graduate's payout
 * identity depends on its RANK inside the boundary's candidate list.
 * That is correct only while the ORDER BY is honoured everywhere, and it
 * makes the identity a function of who ELSE retired in the same block.
 * The V2 derivation binds the RECORD instead: the identity is a function
 * of (chain, domain, height, validator) alone, so it is ordering-
 * independent by construction, carries chain and domain context (no
 * cross-chain or cross-domain reuse), and needs no index allocation. The
 * legacy derivation is UNTOUCHED and keeps owning the legacy lane — the
 * two lanes never share a graduation row.
 *
 * The utxo_set row's identity column is `nullifier` (schema:
 * nodus_witness_v2_schema.c:198-212), NOT tx_hash, so the row key is
 * derived with the SOURCE synthetic-UTXO derivation
 * (emit_synthetic_utxo_for_fp, bft.c:1772-1781):
 *   nullifier = SHA3-512( grad_id[64] ‖ 0x10 ‖ u32be(200) )
 * kind byte 0x10 and output_index 200 are the legacy graduation values
 * (bft.c:2506-2507); the index is the FIXED 200, never 200 + i, because
 * grad_id already separates graduates. A grad_id (or its nullifier)
 * already present in utxo_set is -2: the SHA3 input domains of the CORE
 * spend derivation, the O11 SYSFUND release and this tag are disjoint,
 * so a collision cannot arise from ordinary operation and can only mean
 * local corruption.
 *
 * ── ENGINE-SIDE OBLIGATION OF THE CALLER (touched declaration) ──────
 * A fired boundary MUTATES consensus state that feeds domain roots:
 * `validators` and `validator_set_snapshots` are both legs of
 * system_state_root (nodus_witness_roots_v2.c:279-311), and a graduation
 * release writes `utxo_set`, a leg of core_state_root. The apply
 * engine's untouched-domain guard (nodus_witness_v2_apply.c:1583-1589)
 * therefore REQUIRES the caller to declare SYSTEM touched whenever the
 * boundary fired, and CORE touched when (and only when) at least one
 * graduate released, the distribution credited something or the payday
 * paid something (tokenomics-v3 P2 — `v2_reward_accrual`,
 * `supply_tracking` and `utxo_set` are all CORE legs) — declaring CORE
 * on a boundary that moved none of them would trip the "declared but
 * changed nothing" reject. That is why this function reports `fired`,
 * `n_graduates`, `dist_accrued` and `n_payday_utxos`.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_EPOCH_H
#define NODUS_WITNESS_V2_EPOCH_H

#include "witness/nodus_witness.h"
#include "dnac/ledger_ids.h"        /* DNA_CHAIN_ID_LEN, DNA_DOMAIN_*,
                                     * dna_bft_quorum                   */
#include "dnac/dnac.h"              /* DNAC_EPOCH_LENGTH                */
#include "dnac/validator.h"         /* dnac_validator_record_t          */
#include "dnac/vset_wire.h"         /* dna_vset_snapshot_t              */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The graduation's WRITABLE-SHAPE predicate on a committed validators
 * row — the SAME conditions stage 2 (RETIRING → UNSTAKED) enforces
 * before it will pay a graduate out. Exported for O15J L2-F4: a row that
 * fails this predicate passes genesis (the validator merkle leaf legally
 * hashes an all-zero fingerprint) and then FAULTS -2 at the first
 * graduation boundary — a deterministic chain halt with no recovery. A
 * producer of validator rows (the pure-V2 genesis builder) must be able
 * to refuse such a row BEFORE it is committed, against this one
 * authority rather than a copy that can drift out of step with it.
 *
 * Pure; touches no database. NULL is 0.
 *
 * @return 1 the row is writable-shaped; 0 it is not.
 */
int nodus_witness_v2_epoch_val_rec_ok(const dnac_validator_record_t *v);

/** The 16-byte graduation-identity tag (zero-padded, exactly 16 B). */
#define NODUS_V2_EPGRAD_TAG      "DNA.EPGRAD.v1"
#define NODUS_V2_EPGRAD_TAG_LEN  16u

/** The graduation release UTXO's legacy-mirrored slot (bft.c:2506-2507).
 *  The index is FIXED, never 200 + rank: grad_id separates graduates. */
#define NODUS_V2_EPGRAD_KIND     ((uint8_t)0x10)
#define NODUS_V2_EPGRAD_OUT_IDX  ((uint32_t)200)

/**
 * Deterministic fault-injection stages of the boundary, mapped by the
 * apply engine onto its own append-only fault ids F39-F45
 * (nodus_witness_v2_apply.h). Mirrors the S7 pool module's stage-callback
 * convention (nodus_witness_v2_apply.c:626-656) — the module knows its
 * stages, the engine owns the numbering.
 */
typedef enum {
    NODUS_V2_EPST_NONE            = 0,
    NODUS_V2_EPST_COMMISSIONS     = 1,  /* pending commissions activated */
    NODUS_V2_EPST_GRAD_RELEASE    = 2,  /* graduate[i] release UTXO in   */
    NODUS_V2_EPST_GRAD_APPLIED    = 3,  /* graduate[i] row + counter done*/
    NODUS_V2_EPST_GRAD_BATCH      = 4,  /* every graduate applied        */
    NODUS_V2_EPST_BOUNDARY_FLIPS  = 5,  /* membership flips applied      */
    NODUS_V2_EPST_SNAPSHOT_BUILD  = 6,  /* build INPUTS final (see note) */
    NODUS_V2_EPST_SNAPSHOT_PERSIST= 7,  /* next snapshot built+persisted */
    /* O15C — APPENDED (values above are pinned by shipped tests; the
     * stage runs BETWEEN graduation and the flips in execution order,
     * the O15B enum-append discipline). */
    NODUS_V2_EPST_RULE_N          = 8,  /* Rule N settlement applied     */
    /* O15J Faz 2 — APPENDED for the same reason. Both stages run
     * BETWEEN graduation and Rule N in execution order; the numbers are
     * append-only and the engine maps them BY NAME. */
    /* 9 and 10 are RETIRED by tokenomics-v3 P2 with the burning O15J
     * settlement they bracketed (payout UTXOs written / burn recorded +
     * epoch row retired); never fired, never reused. */
    NODUS_V2_EPST_SETTLE_EMITTED  = 9,  /* RETIRED (P2)                  */
    NODUS_V2_EPST_SETTLE_APPLIED  = 10, /* RETIRED (P2)                  */
    /* tokenomics-v3 P1 (D-4, S-2) — APPENDED for the same reason. Both
     * stages run BETWEEN Rule N and the boundary flips in execution
     * order: 11 fires with the digest row written to
     * `v2_attendance_epoch` and nothing reset; 12 after
     * `v2_attendance.signed_count` has been reset for every row. */
    NODUS_V2_EPST_ATTENDANCE_DIGEST = 11, /* digest row written          */
    NODUS_V2_EPST_ATTENDANCE_RESET  = 12, /* signed_count reset          */
    /* tokenomics-v3 P2 — APPENDED (values above are pinned by shipped
     * tests). In EXECUTION order the distribution and the payday run
     * FIRST, right after the commission activation and BEFORE the
     * graduation, and the balance copy runs LAST, after the next
     * snapshot — see the transition order in the file header. */
    NODUS_V2_EPST_DIST_ACCRUED    = 13, /* every accrual row credited,
                                         * reward_pool not yet debited   */
    NODUS_V2_EPST_DIST_APPLIED    = 14, /* reward_pool debited           */
    NODUS_V2_EPST_PAYDAY_EMITTED  = 15, /* every payday UTXO written,
                                         * accrual rows not yet deleted  */
    NODUS_V2_EPST_PAYDAY_APPLIED  = 16, /* accrual rows deleted          */
    NODUS_V2_EPST_BALANCE_COPY    = 17  /* copy(H) written, older pruned */
    /* The numbers are append-only and NOT in firing order any more
     * (13-16 fire before 2); they are module-internal: the engine maps
     * them onto its own frozen fault ids BY NAME
     * (nodus_witness_v2_apply.c epoch_stage_fault), so nothing outside
     * this header depends on the numbers. */
} nodus_v2_epoch_stage_t;

/*
 * HONEST LABEL on the two snapshot stages. The SOURCE function
 * nodus_witness_vset_commit_next builds AND persists the next epoch's
 * snapshot atomically from the caller's point of view; splitting it
 * would mean editing nodus_witness_vset.c, which this slice deliberately
 * does not touch (the S3 lane stays byte-identical). So:
 *   NODUS_V2_EPST_SNAPSHOT_BUILD fires with every INPUT to the build
 *     final (graduations applied, flips applied) and NOTHING built or
 *     persisted — the proof obligation is that an interrupt there leaves
 *     no snapshot row at all;
 *   NODUS_V2_EPST_SNAPSHOT_PERSIST fires after commit_next returned —
 *     the snapshot row EXISTS in the transaction and the proof
 *     obligation is that the rollback removes it byte-identically.
 * Two genuinely distinct rollback windows; the names are the engine's
 * F44/F45 names, and this comment is the honest description of where
 * they actually sit.
 */

/**
 * Stage fault callback. Return non-zero to abort the boundary at that
 * stage. `graduate_index` is the zero-based index in the candidate list
 * for the per-graduate stages and UINT32_MAX for every other stage.
 */
typedef int (*nodus_v2_epoch_fault_fn)(void *ud,
                                       nodus_v2_epoch_stage_t stage,
                                       uint32_t graduate_index);

/** What the boundary did — the caller's touched-declaration input. */
typedef struct {
    int      fired;         /* 1 = this height IS an epoch boundary     */
    uint32_t n_graduates;   /* RETIRING rows graduated (0 on a no-op)   */
    /* tokenomics-v3 P2 — the distribution's and the payday's
     * contributions to the SAME decision. The distribution writes
     * `v2_reward_accrual` and `supply_tracking.reward_pool`, the payday
     * writes `utxo_set` and deletes accrual rows — all CORE state-root
     * legs — so CORE must be declared touched exactly when
     * (n_graduates > 0 || dist_accrued > 0 || n_payday_utxos > 0). A
     * boundary that credits nothing and pays nothing moves none of them
     * and must NOT declare CORE — the engine rejects a declared no-op
     * just as hard as an undeclared mutation (nodus_witness_v2_apply.c
     * phases 8-9). The balance copy is OUT of every root and never
     * decides a declaration. */
    uint64_t dist_accrued;  /* Σ credited to v2_reward_accrual          */
    uint32_t n_payday_utxos;/* payday UTXOs emitted at this boundary    */
} nodus_v2_epoch_result_t;

/**
 * Apply the epoch-boundary transition for `global_height`.
 *
 * Runs inside the caller's transaction. A no-op (return 0, *out zeroed)
 * on every non-boundary height, so the caller may call it every block.
 *
 * @param w             witness handle (open DB).
 * @param global_height the block's GLOBAL height (block count).
 * @param chain_id      the DERIVED 32-byte V2 chain id
 *                      (nodus_witness_v2_chain_id) — binds every grad_id
 *                      to this chain.
 * @param fault         optional stage-fault callback (NULL = none).
 * @param fault_ud      opaque cookie for `fault`.
 * @param out           required; receives what fired.
 *
 * @return 0 applied (or non-boundary no-op);
 *         -2 NODE-LOCAL FAULT — the caller MUST roll the block back and
 *            must NOT vote. There is no -1: see the FAULT/VERDICT block
 *            at the top of this header. An injected stage fault also
 *            returns -2 (it simulates exactly this class).
 */
int nodus_witness_v2_epoch_boundary_apply(nodus_witness_t *w,
                                          uint64_t global_height,
                                          const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                          nodus_v2_epoch_fault_fn fault,
                                          void *fault_ud,
                                          nodus_v2_epoch_result_t *out);

/**
 * tokenomics-v3 P1 (D-2, D-4, Q1) — the V2 attendance writer. REPLACES
 * the O15C proposer-credit writer (`nodus_witness_v2_record_attendance`,
 * DELETED with this change — its "credit whoever proposed" source is not
 * the decision this package binds: D-2 is explicit that "Teklifçi
 * kimliği katılım sayımına GİRMEZ", a proposer identity never enters the
 * count).
 *
 * Credits every vote in `addresses`/`block_id_flags` (parallel arrays,
 * `n_votes` entries — copied verbatim by the app from cometbft's
 * `decided_last_commit`, nodus_witness_v2_apply.h
 * `nodus_v2_block_cmt_t.votes_address` / `.votes_block_id_flag`) whose
 * flag is EXACTLY `CMT_PB_BLOCK_ID_FLAG_COMMIT` (shared/dnac/cmt_pb.h;
 * Q1, 2026-09-23 O4: NIL and ABSENT do not count). Upserts, in the
 * out-of-root `v2_attendance` table (S15), `signed_count += 1` and
 * `last_signed_height = global_height - 1` — a block at height H carries
 * the commit FOR height H-1 (state/execution.go BuildLastCommitInfo). No
 * status filter, no join against `validators`: an address this chain
 * never seated is stored anyway (cheap, out of every root, and never
 * read back except by address). `n_votes == 0` (the initial height,
 * execution.go:451-455) writes nothing.
 *
 * MUST be called inside the apply engine's single block transaction
 * BEFORE any root computation, and NOWHERE else — in particular never
 * from a sync/replay side path (the O15B.1 post-root-mutation
 * invariant). Unlike the writer it replaces, this phase declares NO
 * domain touched: `v2_attendance` is not a leg of any root, so a credit
 * here moves no state_root byte until the epoch boundary's digest leg
 * (`nodus_witness_v2_epoch_boundary_apply` step 5, S-2) commits its
 * SUMMARY of the ended epoch.
 *
 * @return 0 (including n_votes == 0); -2 node-local fault (DB/hash — a
 *         validator's signature is consensus data, never a verdict; see
 *         nodus/CLAUDE.md "A DB failure is never a value").
 */
int nodus_witness_v2_attendance_credit(nodus_witness_t *w,
                                       uint64_t global_height,
                                       const uint8_t (*addresses)[32],
                                       const int32_t *block_id_flags,
                                       size_t n_votes);

/**
 * tokenomics-v3 P1 — read one validator's out-of-root attendance row by
 * PUBKEY. Derives the lookup key with `nodus_chain_config_derive_witness_id`
 * (nodus/nodus_chain_config.h) — the SAME nodus-side function
 * `nodus_witness_vset.c:365` already uses to populate a snapshot entry's
 * `voter_id`, byte-identical to `cmt_address_hash` (shared/dnac/
 * cmt_tmhash.h) and to the cometbft address this table is keyed on: ONE
 * derivation, reused, never re-implemented.
 *
 * Used directly by `nodus_witness_v2_attendance_meets_bar` (below), the
 * ONE predicate both Rule N and the settlement liveness bar now call —
 * this function itself is no longer read by either caller directly
 * (round 3, tokenomics-v3 P1).
 *
 * @param signed_count_out      optional.
 * @param last_signed_height_out optional.
 * @return 0 found (out params written); 1 absent — HONEST ZERO, not a
 *         fault (an epoch with no writer yet, or a validator that never
 *         signed; out params are NOT written on 1, callers must treat
 *         absence as signed_count 0 / last_signed_height 0 themselves);
 *        -2 node-local fault (bad argument, hash failure, DB error).
 */
int nodus_witness_v2_attendance_get(nodus_witness_t *w,
                                    const uint8_t pubkey[DNAC_PUBKEY_SIZE],
                                    uint64_t *signed_count_out,
                                    uint64_t *last_signed_height_out);

/**
 * tokenomics-v3 P1 round 3 (operator 2026-09-23) — THE shared
 * participation predicate. ONE function, TWO callers: Rule N's
 * AUTO_RETIRE test (`v2ep_rule_n`, this file) and the settlement reward
 * bar (`nodus_witness_v2_settlement_apply`, `nodus_witness_v2_econ.c`).
 * Evaluates BOTH P1 and P2 for every caller — the decision text binds
 * them together as ONE participation criterion, not two independently
 * selectable halves: decision §1 line 79's parenthetical ("Aynı oran
 * ödül hak edişi için de geçerli: tek kural, iki tüketici" — the same
 * rate applies to reward eligibility too, one rule, two consumers) and
 * §3's last entry ("settlement barının kendi formülü yerine Rule N'in
 * yüklemini çağırması" — the settlement bar calls Rule N's PREDICATE,
 * not a formula of its own). Neither caller may opt out of P2: the
 * decision's own participation sentence ("Epoch boyunca en az %50
 * katılım VE son 120 blokta en az bir imza şartları BİRLİKTE aranacak")
 * governs participation as such, with no separate clause for rewards.
 *
 *   P1 (bar)      signed_count * 10000 >= DNAC_EPOCH_LENGTH *
 *                 DNAC_LIVENESS_THRESHOLD_BPS
 *   P2 (recency)  last_signed_height > 0 &&
 *                 last_signed_height >= (boundary_height > W ?
 *                                        boundary_height - W : 0),
 *                 W = DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS
 *
 * `boundary_height` is the epoch-boundary height H the caller is
 * evaluating AT (Rule N: the boundary it is currently running at, H
 * itself — the epoch that just accumulated attendance is (H-E, H]. The
 * reward distribution: the SAME H, which it is called with since
 * tokenomics-v3 P2).
 *
 * Reads via `nodus_witness_v2_attendance_get`; an ABSENT row (arc == 1)
 * is the honest zero (never signed) that P1/P2 both fail on, not a
 * caller-visible distinction. There is NO genesis carve-out anywhere
 * (removed in P1 round 5); this function has no epoch-0 special case.
 *
 * @param out  1 == both predicates pass (present); 0 == miss. Written
 *             only on a 0 return.
 * @return 0 (`*out` written); -2 node-local fault (bad argument or
 *         `nodus_witness_v2_attendance_get`'s own -2 — a validator's
 *         signature history is consensus data, never a verdict).
 */
int nodus_witness_v2_attendance_meets_bar(nodus_witness_t *w,
                                          const uint8_t
                                              pubkey[DNAC_PUBKEY_SIZE],
                                          uint64_t boundary_height,
                                          int *out);

/**
 * The canonical graduation identity, exposed so a test (or a future
 * indexer) can re-derive it INDEPENDENTLY of the apply path rather than
 * reading it back out of the row it wrote. Pure function, no DB.
 *
 * @param validator_pubkey DNAC_PUBKEY_SIZE bytes.
 * @return 0 / -2 (hash backend failure — a node fault, never a value).
 */
int nodus_witness_v2_epoch_grad_id(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                   uint64_t global_height,
                                   const uint8_t *validator_pubkey,
                                   uint8_t out_grad_id[64]);

/**
 * The utxo_set row key for a graduation release, derived from its
 * grad_id with the SOURCE synthetic-UTXO derivation (bft.c:1772-1781).
 * Pure function, no DB.
 *
 * @return 0 / -2.
 */
int nodus_witness_v2_epoch_grad_nullifier(const uint8_t grad_id[64],
                                          uint8_t out_nullifier[64]);

/* ════════════════════════════════════════════════════════════════════
 * O12 S3 — THE SNAPSHOT AUTHORITY RESOLVER (INACTIVE)
 *
 * "Who could vote on this height, and how many of them must agree?"
 * answered EXCLUSIVELY from the committed validator_set_snapshots row
 * for the height's own epoch.
 *
 * ── STILL INACTIVE, and narrower than it looks ──────────────────────
 * This is a STATE/QUERY boundary only. No live QC verification, no BFT
 * vote tabulation, no certificate check calls it; wiring it into those
 * paths is a separate, not-yet-approved slice. What it provides today
 * is the authoritative ANSWER, not its enforcement.
 *
 * ── WHAT MAKES A CALLER-SUPPLIED N STRUCTURALLY IMPOSSIBLE ──────────
 * There is NO n parameter and NO quorum parameter, on any function
 * here, by construction. N comes from ONE place — the resolved
 * snapshot's `active_count` — and the quorum is then
 * dna_bft_quorum(N) = (2N)/3+1 (shared/dnac/ledger_ids.h:110-112).
 * A transaction, a runtime, a QC, a peer message or a config row
 * cannot propose, hint or override either number: there is no argument
 * through which to say it. This is the whole point of the API shape —
 * a validated `n` parameter would still be a parameter.
 *
 * ── ONE CANONICAL KEY ───────────────────────────────────────────────
 * All three questions the season names — a target epoch, a global block
 * height, and a historical certification height — collapse to the SAME
 * key:  epoch_start = floor(h / DNAC_EPOCH_LENGTH) * DNAC_EPOCH_LENGTH.
 * That is the shipped derivation (nodus_witness_sync.c:916-917), and it
 * is computed purely by division and multiplication in u64 — this path
 * contains NO `h + E` anywhere, so no height can overflow it.
 * `_for_epoch` REJECTS an epoch_start that is not a multiple of E: two
 * spellings of one epoch would be two cache keys and two answers.
 *
 * ── rc 1 IS TERMINAL. THIS IS NOT THE LEGACY FALLBACK CHAIN ─────────
 * nodus_witness_sync.c:900-913 documents a FOUR-SOURCE chain for the
 * historical-quorum question: (1) the snapshot row, (2) a deterministic
 * committee recompute, (3) the genesis chain_def seat count, (4) the
 * legacy roster quorum. Sources (2)-(4) exist because that path must
 * verify pre-S3 history that has no snapshot row at all.
 *
 * This resolver is PRECISELY WHAT THAT IS NOT. Absence here returns 1
 * and STOPS. The caller must fail closed. It must NOT fall back to the
 * current validator set, to a recompute, to a chain_def count, or to a
 * roster — every one of those answers the question "who is voting now",
 * and substituting it for "who could vote THEN" is how a joining node
 * with a transient 9-peer mesh comes to demand 7 signatures from a
 * 7-member epoch's 5-signature block. The current set is UNREACHABLE
 * through this API for a historical height: nothing here reads the
 * `validators` table, at any height, ever.
 *
 * ── RETURN-CODE CONVENTION (deliberately NOT the transition's) ──────
 * The boundary transition above returns 0/-2 because it runs inside a
 * block transaction and -2 means "roll back and do not vote". This
 * resolver is a read-only query with no block to fail, so it uses the
 * ordinary witness query convention 0 / 1 / -1 and propagates
 * nodus_witness_vset_get's -1 unchanged. Two lanes, two conventions,
 * both explicit.
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Resolve the authoritative validator set governing `epoch_start`.
 *
 * Served ONLY by nodus_witness_vset_get, whose fail-closed integrity
 * work (re-hash of the stored bytes, strict decode, and the
 * blob-epoch / blob-count / row-count cross-check) all happens BEFORE
 * any value is returned — so a corrupt row is -1 here, never a number.
 *
 * @param epoch_start MUST be a multiple of DNAC_EPOCH_LENGTH.
 * @param snap_out    optional; on rc 0 receives the heap snapshot the
 *                    caller must release with dna_vset_free. NULL means
 *                    "I only want N and the quorum" and the snapshot is
 *                    released internally.
 * @param n_out       optional; the resolved set size (active_count).
 * @param quorum_out  optional; dna_bft_quorum(n).
 *
 * @return 0 resolved;
 *         1 NO COMMITTED AUTHORITY for that epoch — TERMINAL, see the
 *           fallback-chain block above; the caller fails closed;
 *        -1 fault (bad argument, non-canonical key, DB error, hash
 *           mismatch, decode failure, row/blob disagreement).
 * On any non-zero return NO output parameter is written.
 */
int nodus_witness_v2_epoch_authority_for_epoch(nodus_witness_t *w,
                                               uint64_t epoch_start,
                                               dna_vset_snapshot_t **snap_out,
                                               uint32_t *n_out,
                                               uint32_t *quorum_out);

/**
 * The same resolution keyed by a GLOBAL BLOCK HEIGHT — the form a
 * historical certification check wants. Identical contract; the height
 * is reduced to its epoch key and handed to _for_epoch, so a height and
 * its epoch can never disagree.
 *
 * Any height is accepted, including 0 and UINT64_MAX: the reduction is
 * a division, so it cannot overflow and cannot fail.
 */
int nodus_witness_v2_epoch_authority_for_height(nodus_witness_t *w,
                                                uint64_t global_height,
                                                dna_vset_snapshot_t **snap_out,
                                                uint32_t *n_out,
                                                uint32_t *quorum_out);

/**
 * The canonical epoch key of a global height:
 *   floor(h / DNAC_EPOCH_LENGTH) * DNAC_EPOCH_LENGTH
 * Pure, total, overflow-free (the result is always <= h). Exposed so a
 * caller and a test can agree on the key without re-spelling it.
 */
static inline uint64_t nodus_v2_epoch_start_for_height(uint64_t h) {
    return (h / (uint64_t)DNAC_EPOCH_LENGTH) * (uint64_t)DNAC_EPOCH_LENGTH;
}

/**
 * L(h) — THE POWER EXIT BOUNDARY of a stake change executed in block h
 * (tokenomics-v3 P2-10; design docs/plans/2026-09-23-tokenomics-v3-
 * consensus-binding-design.md §7.1; decision docs/plans/decisions/
 * 2026-09-22-nodus-tokenomics-v3-operator.md §1 "Stake çözme" and §3
 * 2026-09-24 "DELEGATOR = VALIDATOR GİBİ"): the first boundary at which
 * a validator set that NO LONGER counts the changed stake takes effect.
 * With E = DNAC_EPOCH_LENGTH:
 *
 *   nb(h) = ceil(h / E) · E        (h itself when h is a boundary)
 *   L(h)  = nb(h) + E
 *
 * DERIVATION, from the code in this tree:
 *   1. A block's transactions run BEFORE its own boundary: the envelopes
 *      execute with ctx.global_height = blk->global_height
 *      (nodus_witness_v2_apply.c:1307, called at :3640) and the boundary
 *      is phase 6e, later in the same block (:4163). So the FIRST
 *      boundary whose commit_next sees a change made in block h is nb(h)
 *      — h itself when h is a boundary, because block h's transactions
 *      are already applied when block h's boundary runs.
 *   2. commit_next reads the LIVE stake, self_stake + external_delegated
 *      (nodus_witness_committee.c:338-339, the bootstrap twin :481-482).
 *   3. The set commit_next builds at boundary B is keyed B + E
 *      (nodus_witness_vset.c:703) — it governs (B+E, B+2E], not
 *      (B, B+E]. The boundary builds it at nodus_witness_v2_epoch.c:1348
 *      and writes the frozen balance copy right after (:1359), with no
 *      stake movement in between.
 *   So the set built at nb(h) is the first that excludes the change, and
 *   it takes effect at nb(h) + E = L(h). cometbft's own two-height
 *   ValidatorUpdate delay is NOT included (decision §3 S-1).
 *
 * The UNDELEGATE release UTXO is born locked to L(h) +
 * DNAC_UNDELEGATE_LOCK_EPOCHS · E (nodus_witness_rt_native.c
 * rtn_sysfund_exec); the spend gates refuse it while unlock >= height.
 *
 * P3 NOTE: when P3's "okuma B" (the selection reads the frozen copy of
 * the PREVIOUS boundary) lands, a stake change is first seen by the set
 * built one boundary later, and L(h) becomes nb(h) + 2E. THREE things
 * move together, never this function alone (P2 rev 2 red-team,
 * 2026-09-24): (1) this function; (2) the distribution's source copy,
 * nodus_witness_v2_econ.c v2ec_source_copy — it must name the copy the
 * governing snapshot was BUILT from (H−3E instead of H−2E), or the
 * consistency gate faults on every honest node at the first boundary
 * after any delegation; (3) the copy retention in
 * nodus_witness_v2_balance_copy_write — it prunes below epoch_start − E
 * today, so copy(H−3E) would already be gone. D-9 also wants a status
 * column the copy does not carry.
 *
 * Pure height arithmetic: no clock, no database, identical on every
 * node for the same h.
 *
 * @param out  required; written only on 0.
 * @return 0; -1 when L(h) does not fit in 64 bits (or out is NULL).
 */
int nodus_v2_power_exit_boundary(uint64_t h, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_EPOCH_H */
