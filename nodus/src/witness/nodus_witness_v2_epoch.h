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
 *   2. RETIRING → UNSTAKED GRADUATION — candidates selected
 *      ORDER BY pubkey ASC (bft.c:2416-2422; the order is load-bearing
 *      and is a stable total key on every node), bounded by
 *      DNAC_MAX_VALIDATORS. Per graduate, in the legacy order
 *      (bft.c:2465-2560): release UTXO → validators row → active_count.
 *   3. RULE N (liveness / AUTO_RETIRED) — DELIBERATELY NOT MIGRATED.
 *      See the labelled section below.
 *   4. BOUNDARY FLIPS — nodus_witness_vset_apply_boundary_flips(w, H).
 *   5. NEXT SNAPSHOT — nodus_witness_vset_commit_next(w, H).
 *
 * NOT done here, deliberately: no epoch_state mutation. Reward accrual
 * and push-settlement are OUT of the O12 scope; the epoch_state table is
 * left byte-untouched by this module.
 *
 * ── RULE N: NOT MIGRATED (labelled, not forgotten) ──────────────────
 * The legacy boundary's third transition (liveness-based AUTO_RETIRED,
 * bft.c:2559-2660) reads the per-validator attendance watermark
 * `last_signed_block`, which is written EXCLUSIVELY by the live BFT
 * commit path (nodus_witness_record_attendance, called after cert_store).
 * The inactive V2 engine has no block-signature evidence at all — it
 * never sees a certificate — so it has NO SOURCE for that watermark.
 * Migrating the rule would mean inventing an attendance oracle, which is
 * exactly the class of fabrication this tree forbids. Rule N is
 * therefore DEFERRED to the live-integration season, when the V2 engine
 * is wired behind the real BFT commit path and the watermark exists.
 * Until then the legacy lane owns Rule N and this module does not touch
 * `consecutive_missed_epochs` or `last_signed_block`.
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
 * graduate released — declaring CORE on a graduate-free boundary would
 * trip the "declared but changed nothing" reject at :1600-1601. That is
 * why this function reports `fired` and `n_graduates`.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_EPOCH_H
#define NODUS_WITNESS_V2_EPOCH_H

#include "witness/nodus_witness.h"
#include "dnac/ledger_ids.h"        /* DNA_CHAIN_ID_LEN, DNA_DOMAIN_*,
                                     * dna_bft_quorum                   */
#include "dnac/dnac.h"              /* DNAC_EPOCH_LENGTH                */
#include "dnac/vset_wire.h"         /* dna_vset_snapshot_t              */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

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
    NODUS_V2_EPST_SNAPSHOT_PERSIST= 7   /* next snapshot built+persisted */
    /* Values ascend in FIRING order. They are module-internal: the
     * engine maps them onto its own frozen F39-F45 ids BY NAME
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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_EPOCH_H */
