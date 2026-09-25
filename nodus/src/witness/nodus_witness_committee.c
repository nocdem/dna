/**
 * Nodus — Witness Committee Election (Phase 10)
 *
 * Implements the deterministic committee election defined by design
 * §3.6. See nodus_witness_committee.h for the algorithm summary.
 *
 * All 7 witness nodes MUST produce bit-identical committees from the
 * same committed state — the post-commit lookback plus the state_seeded
 * tiebreak are sufficient for determinism.
 *
 * @file nodus_witness_committee.c
 */

#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"   /* S3: snapshot-as-authority */
#include "witness/nodus_witness_v2_econ.h" /* tokenomics-v3 P3-1: the frozen
                                            * copy the selection ranks by */

#include "nodus/nodus_types.h"       /* NODUS_TREE_TAG_VALIDATOR */
#include "nodus/nodus_chain_config.h" /* nodus_chain_config_get_u64 */
#include "dnac/dnac.h"                /* DNAC_* constants */
#include "dnac/validator.h"
#include "dnac/block_v2.h"            /* DNA_BH2_ID_LEN — the v2_blocks
                                       * block_id column width, still the
                                       * successor's committed identity
                                       * column at S14 */
#include "witness/nodus_witness_cmt_store.h" /* R3 W3 delta 10 — the Comet
                                              * blockstore, the header's
                                              * real home at S14 */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>   /* S3: sqlite_master probe in get_for_block */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_COMMITTEE"

/* Per-validator work record used while sorting. Holds a pointer into
 * the caller's candidates[] array plus the pre-computed tiebreak hash
 * so qsort can run on POD entries without extra SHA3 calls.
 *
 * tokenomics-v3 P3-1: `total_stake` and `self_stake` are the values the
 * member is RANKED by and EMITTED with — the FROZEN totals of the copy on
 * the post-bootstrap path ("okuma B"), the live row's on the bootstrap
 * path. `rec` still supplies the pubkey and the LIVE commission. */
typedef struct {
    const dnac_validator_record_t *rec;
    uint64_t total_stake;
    uint64_t self_stake;
    uint8_t  tiebreak[64];
} committee_work_t;

/* SHA3-512(0x02 || pubkey || state_seed). state_seed is 64 bytes
 * (NODUS_T3_TX_HASH_LEN / the block's state_root column width). */
static void compute_tiebreak_hash(const uint8_t pubkey[DNAC_PUBKEY_SIZE],
                                    const uint8_t state_seed[64],
                                    uint8_t out[64]) {
    uint8_t buf[1 + DNAC_PUBKEY_SIZE + 64];
    buf[0] = NODUS_TREE_TAG_VALIDATOR;   /* 0x02 */
    memcpy(&buf[1], pubkey, DNAC_PUBKEY_SIZE);
    memcpy(&buf[1 + DNAC_PUBKEY_SIZE], state_seed, 64);
    qgp_sha3_512(buf, sizeof(buf), out);
}

/* qsort comparator: tiebreak ASC (byte-lex). Used within tied stake
 * groups only. The primary ordering (stake DESC) is imposed by the
 * calling loop. */
static int cmp_tiebreak_asc(const void *pa, const void *pb) {
    const committee_work_t *a = (const committee_work_t *)pa;
    const committee_work_t *b = (const committee_work_t *)pb;
    return memcmp(a->tiebreak, b->tiebreak, 64);
}

/* tokenomics-v3 P3-1 qsort comparator: FROZEN total DESC, then the SAME
 * seeded tiebreak ASC. This is exactly the total order the pre-P3 path
 * produced in two steps (top_n's stake DESC, then the in-group
 * cmp_tiebreak_asc re-sort — the group re-sort erased the pubkey ASC
 * secondary), expressed as one comparator because the candidate list no
 * longer arrives pre-sorted by the stake it is ranked on. Two distinct
 * pubkeys have distinct tiebreak hashes (SHA3-512 over distinct inputs),
 * so the order is total and qsort's instability is unobservable. */
static int cmp_frozen_desc_tiebreak_asc(const void *pa, const void *pb) {
    const committee_work_t *a = (const committee_work_t *)pa;
    const committee_work_t *b = (const committee_work_t *)pb;
    if (a->total_stake != b->total_stake)
        return a->total_stake > b->total_stake ? -1 : 1;
    return memcmp(a->tiebreak, b->tiebreak, 64);
}

/* S3 — the epoch's target active-set size.
 *
 * Keyed on `e_start`, the epoch START height, NOT on the height being
 * queried: every block of the epoch must read the same value, otherwise a
 * chain_config row with a mid-epoch effective_block would resize a live
 * committee. Deterministic cross-node because
 * nodus_chain_config_get_u64 answers from committed chain_config_history
 * rows — the same source the INFLATION_START_BLOCK consumer uses inside
 * finalize_block (nodus_witness_bft.c).
 *
 * The default — the target when no governance row applies — is
 * DNAC_TARGET_ACTIVE_DEFAULT (32) since tokenomics-v3 P3-7 (decision file
 * §3 2026-09-24 "P3 soruları" (4); it was DNAC_COMMITTEE_SIZE = 7, which
 * stays the governed MINIMUM). The clamp is the release ceiling,
 * defence-in-depth on top of the apply-side range check in
 * nodus_chain_config_apply.
 *
 * O15J Block 2 (A2) — FAIL CLOSED. The lookup is three-valued now, and
 * `1` (genuinely no governance row) keeps the historical behaviour
 * byte-for-byte: the default seat count. `-1` means this node cannot
 * determine how many seats the epoch has, and a node that does not know
 * the seat count does not know the committee — it must not select one,
 * because a peer that CAN read the override would select a different
 * set and the two would disagree on validator_set_root / snapshot_hash
 * and therefore on state_root.
 *
 * @param target_out [out] written only on success.
 * @return 0 target determined, -1 cannot determine. */
static int committee_target_for_epoch(nodus_witness_t *w, uint64_t e_start,
                                      int *target_out) {
    uint64_t target = 0;
    int crc = nodus_chain_config_get_u64(
        w, (uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT, e_start,
        (uint64_t)DNAC_TARGET_ACTIVE_DEFAULT, &target);
    if (crc < 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: TARGET_ACTIVE_COUNT is "
                      "unreadable — refusing to select a committee on a "
                      "guessed seat count",
                      (unsigned long long)e_start);
        return -1;
    }
    if (target < 1) target = 1;
    if (target > (uint64_t)DNAC_MAX_ACTIVE_VALIDATORS)
        target = (uint64_t)DNAC_MAX_ACTIVE_VALIDATORS;
    /* O15F Task 1 — a successor's active set is capped at
     * NODUS_V2_ACTIVE_SET_MAX (the seam sets v2_successor before genesis
     * seeding, so this fires during seeding too). Legacy chains keep the
     * 128 ceiling above. Mirrors vset_target_for_epoch. */
    if (w->v2_successor && target > (uint64_t)NODUS_V2_ACTIVE_SET_MAX)
        target = (uint64_t)NODUS_V2_ACTIVE_SET_MAX;
    *target_out = (int)target;
    return 0;
}

/* ── O15E Faz A, R3 W3 delta 10 — the successor's committed seed row ────
 *
 * On a SUCCESSOR chain the state_seed's authoritative block-identity
 * source is the committed `v2_blocks` BlockID at the lookback height
 * (64 bytes — the exact width the tiebreak preimage already consumes).
 * This closes ACTIVATION OBLIGATION 2 (nodus_witness_v2_epoch.h): the
 * terminal legacy `blocks` table is NEVER consulted for live successor
 * committee authority, and an unusable seed row FAILS CLOSED before any
 * committee is emitted.
 *
 * THE HEADER MOVED (R3 W3 delta 10, live defect found by the short-epoch
 * harness at E=15, evidence /tmp/stagef-20260917T114650Z): this reader
 * used to `SELECT block_id, header FROM v2_blocks` and strict-decode a
 * 413-byte `dna_bh2` header out of the `header` column. Schema S14
 * DROPPED `v2_blocks.header` (and `qc`, `commit_cert` — R3 W1's
 * migration, nodus_witness_v2_schema.c, D-17 rev 5): on the Comet lane
 * `v2_blocks.block_id` is the Comet HEADER HASH verbatim (R3-C1a-10,
 * nodus_witness_v2_apply.c's ten-column insert), and the header itself
 * lives in the Comet blockstore (`H:<height>` BlockMeta,
 * nodus_witness_cmt_store.c) — so the old `SELECT ... header` prepare
 * failed ("no such column: header") on every version-3 chain, and the
 * first epoch boundary needing a lookback seed (`e_start = 2E`, lookback
 * `E - 1`) halted every node. D-17 rev 10 (9) also closes the pre-Comet
 * successor lane in this same wave — the `dna_bh2` decode this reader
 * used to run is for a lane that no longer produces blocks — so the fix
 * is not a branch, it is reading the identity from where it actually
 * lives now: the Comet store, the same move the preflight's own check 5
 * made this morning (delta 8) for the identical reason.
 *
 * Fail-closed classes, each -1, same shape as before, over the store
 * that actually holds the header now:
 *   - MISSING: no committed `v2_blocks` row at the height, OR no
 *     BlockMeta at that height in the Comet blockstore (a successor
 *     produces every height contiguously on both, so absence in either
 *     is a real fault);
 *   - MALFORMED: `v2_blocks.block_id` not exactly 64 B, or the loaded
 *     BlockMeta's own header height disagreeing with the row's key;
 *   - WRONG CHAIN: the BlockMeta header's `chain_id` (cmt_pb_header_t
 *     field 2, `chain_id`/`chain_id_len`, shared/dnac/cmt_pb.h:258,
 *     `CMT_PB_CHAINID_MAX` 32 at :131) must equal the node's derived
 *     successor chain id (`w->v2_chain32`, exactly 32 bytes both sides);
 *   - FORGED: the BlockMeta's own `block_id.hash` (cmt_pb_block_id_t
 *     field 1, `hash`/`hash_len`, `CMT_PB_HASH_MAX` 64 at cmt_pb.h:129)
 *     must equal `v2_blocks.block_id` — the same row, told twice, by two
 *     different tables that are supposed to agree.
 *   - Height 0: UNREACHABLE on this lane, and now genuinely so rather
 *     than merely a comment's claim — every real caller passes a
 *     multiple of E (`e_start`), and a version-3 chain writes NO
 *     height-0 `v2_blocks` row at all (D-19 rev 6 withdraws the genesis
 *     block; the genesis document is the identity instead,
 *     nodus_witness_v2_gen.h). A height-0 request here therefore always
 *     finds no row — MISSING, fail closed, the same class as any other
 *     absent height. The old genesis special-case (an all-zero chain_id
 *     branch reading a `dna_bh2` genesis header) is deleted with it. */
static int v2_seed_block_id(nodus_witness_t *w, uint64_t height,
                            uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (int64_t)height);
    if (sqlite3_step(st) != SQLITE_ROW) {          /* MISSING */
        sqlite3_finalize(st);
        return -1;
    }
    const void *id = sqlite3_column_blob(st, 0);
    int idl        = sqlite3_column_bytes(st, 0);
    uint8_t row_id[DNA_BH2_ID_LEN];
    if (!id || idl != DNA_BH2_ID_LEN) {            /* MALFORMED */
        sqlite3_finalize(st);
        return -1;
    }
    memcpy(row_id, id, DNA_BH2_ID_LEN);
    sqlite3_finalize(st);

    /* Height 0 always finds no BlockMeta on a version-3 chain (there is
     * no block 0), so it would fail as MISSING below anyway — the
     * explicit check just names why, rather than relying on the store
     * lookup to fail closed for the right reason by accident. */
    if (height == 0) return -1;

    nodus_cmt_store_t s;
    if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) return -1;
    nodus_cmt_block_meta_t meta;
    bool found = false;
    memset(&meta, 0, sizeof(meta));
    int rc = nodus_cmt_bs_load_block_meta(&s, (int64_t)height, &meta,
                                          &found);
    nodus_cmt_store_release(&s);
    if (rc != CMT_OK || !found) return -1;                    /* MISSING */
    if (meta.header.height != (int64_t)height) return -1;     /* MALFORMED */
    if (meta.header.chain_id_len != 32 ||
        memcmp(meta.header.chain_id, w->v2_chain32, 32) != 0)
        return -1;                                            /* WRONG CHAIN */
    if (meta.block_id.hash_len != DNA_BH2_ID_LEN ||
        memcmp(meta.block_id.hash, row_id, DNA_BH2_ID_LEN) != 0)
        return -1;                                            /* FORGED */

    memcpy(out, row_id, DNA_BH2_ID_LEN);
    return 0;
}

/* Copy a work entry into the public member struct. */
static void emit_member(const committee_work_t *w_in,
                         nodus_committee_member_t *out) {
    memcpy(out->pubkey, w_in->rec->pubkey, DNAC_PUBKEY_SIZE);
    out->total_stake    = w_in->total_stake;
    out->self_stake     = w_in->self_stake;        /* S3: snapshot self_bond
                                                    * (P3-1: frozen)       */
    out->commission_bps = w_in->rec->commission_bps; /* LIVE, as before   */
}

int nodus_committee_compute_for_epoch(nodus_witness_t *w,
                                        uint64_t e_start,
                                        nodus_committee_member_t *out,
                                        int max_entries,
                                        int *count_out) {
    if (!w || !out || !count_out || max_entries <= 0) return -1;
    *count_out = 0;

    /* Bootstrap path: lookback would underflow. Task 52 handles it. */
    if (e_start < (uint64_t)DNAC_EPOCH_LENGTH + 1ULL) {
        return nodus_committee_bootstrap_for_epoch(w, e_start, out,
                                                    max_entries, count_out);
    }

    /* S3 — the epoch's target set size, from committed chain state.
     * O15J A2: unreadable ⇒ no committee, not a default-sized one. */
    int target = 0;
    if (committee_target_for_epoch(w, e_start, &target) != 0) return -1;
    if (target < max_entries) max_entries = target;

    uint64_t lookback_block = e_start - (uint64_t)DNAC_EPOCH_LENGTH - 1ULL;

    /* state_seed = the authoritative block identity at lookback_block.
     *
     * O15E Faz A (locked consensus decision): on a SUCCESSOR the source
     * is the committed v2_blocks BlockID at the SAME lookback height —
     * lookback distance, the tiebreak preimage and the selection
     * algorithm are all UNCHANGED; only the identity source moves.
     * Missing/malformed/wrong-chain rows fail closed; there is NO
     * fallback to the terminal legacy `blocks` table on a successor.
     * Legacy chains keep the byte-identical legacy read below. */
    uint8_t state_seed[64];
    if (w->v2_successor) {
        if (v2_seed_block_id(w, lookback_block, state_seed) != 0) {
            fprintf(stderr, "%s: compute_for_epoch: V2 seed row at %llu "
                    "missing or unusable — failing closed\n",
                    LOG_TAG, (unsigned long long)lookback_block);
            return -1;
        }
    } else {
        nodus_witness_block_t block_info;
        if (nodus_witness_block_get(w, lookback_block, &block_info) != 0) {
            fprintf(stderr, "%s: compute_for_epoch: block_get(%llu) failed\n",
                    LOG_TAG, (unsigned long long)lookback_block);
            return -1;
        }
        memcpy(state_seed, block_info.state_root, sizeof(state_seed));
    }

    /* ── tokenomics-v3 P3-1: "OKUMA B" ────────────────────────────────
     * Decision file docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-
     * operator.md §1 "Seçimde bir epoch önce dondurulan stake bakiyeleri
     * kullanılacak", read as B (§3 2026-09-23) and pinned by §3
     * 2026-09-24 "P3 soruları" (1): BALANCES from the frozen copy of the
     * previous boundary, STATUS and TENURE from the live row. Design §8
     * P3-1.
     *
     * The set stored for e_start = B + E is built at boundary B
     * (nodus_witness_vset_commit_next), so the previous boundary's copy is
     * copy(B − E) = copy(e_start − 2E). At B = E (e_start = 2E) that is
     * copy(0), written by the engine genesis from the genesis rows
     * (nodus_witness_v2_apply.c, both nodus_witness_v2_balance_copy_write
     * (w, 0) calls). The bootstrap path above (e_start < E + 1, the
     * genesis snapshots 0 and E) is UNCHANGED and ranks the live genesis
     * rows — copy(0) does not exist yet when those two are built, and it
     * holds the same rows.
     *
     * THE KEY, written so it cannot wrap: copy_epoch = the epoch start of
     * the LOOKBACK block (e_start − E − 1, the height the tiebreak seed
     * is read from above). For every production e_start — a multiple of
     * E, >= 2E — that is exactly B − E: the lookback block B − 1 lies in
     * the epoch [B − E, B). For the non-multiple keys only unit fixtures
     * pass (e_start in (E, 2E) — the post-bootstrap cutoff is E + 1) it is
     * copy(0), the copy of the epoch the seed block lies in; no
     * subtraction below the lookback, which is already >= 0 here.
     *
     * THE CANDIDATE SET is fetched WHOLE (nodus_validator_bonded_tenured
     * — live status IN (ACTIVE, ELIGIBLE), live tenure), not a
     * live-stake-ranked, LIMITed prefix: the ranking key is the frozen
     * total, so a LIMIT on the live stake (what nodus_validator_top_n
     * does, with the old 3 × target "widen" heuristic) could cut a
     * candidate whose frozen total ranks it in. It is bounded by
     * DNAC_MAX_VALIDATORS through STAKE's Rule M (P3 fix round,
     * nodus_witness_rt_native.c rtn_stake_exec): ACTIVE + ELIGIBLE rows
     * are a subset of validator_stats.active_count, which Rule M keeps
     * <= 128 after every STAKE, fresh or revived. A 129th row is
     * therefore a broken invariant, not a value: it faults (-1), as
     * v2ep_rule_n does on the same condition at the same boundary.
     *
     * THE RANKING KEY, per candidate, from copy(e_start − 2E)
     * (nodus_witness_v2_balance_copy_frozen, nodus_witness_v2_econ.c):
     * frozen total = its own row + Σ its delegator rows, absent = 0.
     * The emitted entry carries the frozen total as total_stake and the
     * frozen own row as self_bond (so cometbft's power, Rule N's weight
     * floor and the reward distribution all see the frozen values; the
     * distribution's consistency gate re-reads the same copy rows at
     * src = e_start − 2E, nodus_witness_v2_econ.c v2ec_source_copy);
     * commission_bps stays the LIVE row's, as before.
     *
     * A candidate whose frozen total is 0 is NOT SEATED. It has no stake
     * in the copy the set is ranked by, so its voting power would be 0 —
     * a cometbft ValidatorUpdate with power 0 is a REMOVAL, not a seat.
     * On an honest chain the tenure gate makes this unreachable for
     * every later joiner (active_since + 2E <= B + E puts its STAKE at or
     * before block B − E, whose own transactions run before boundary
     * B − E writes copy(B − E) — nodus_v2_power_exit_boundary's
     * derivation, steps 1-2); the one reachable case is the tenure
     * carve-out `active_since_block <= 1` meeting a STAKE executed IN
     * block 1 (after genesis wrote copy(0)): skipping it seats it one
     * boundary later, from copy(E), instead of faulting every node on a
     * condition any staker could trigger.
     *
     * THE TIEBREAK is unchanged: SHA3-512(0x02 ‖ pubkey ‖ state_seed),
     * ASC, inside equal frozen totals (cmp_frozen_desc_tiebreak_asc).
     *
     * CALL SITES (both through ONE core, so the snapshot Rule N judges
     * and the snapshot commit_next stores are built by the same code):
     *   - nodus_witness_vset_commit_next → vset_build_and_store →
     *     nodus_witness_vset_build_for_epoch → vset_build_snapshot →
     *     here (nodus_witness_vset.c);
     *   - nodus_witness_vset_preview_next → vset_build_snapshot → here
     *     (Rule N's weight floor, nodus_witness_v2_epoch.c v2ep_rule_n);
     *   - nodus_committee_get_for_block's cache-miss recompute below, for
     *     an epoch with no snapshot row (none >= E on a version-3 chain,
     *     where every epoch's snapshot is stored one epoch ahead). */
    const uint64_t copy_epoch = (lookback_block / (uint64_t)DNAC_EPOCH_LENGTH)
                                * (uint64_t)DNAC_EPOCH_LENGTH;

    dnac_validator_record_t *candidates =
        calloc((size_t)DNAC_MAX_VALIDATORS, sizeof(*candidates));
    if (!candidates) return -1;

    /* ── S3 tenure anchor fix (found by the 7→9→7 harness) ──────────────
     * The tenure gate used to compare against LOOKBACK_BLOCK
     * (e_start − E − 1). That predicate is unsatisfiable in the "gap
     * epochs": for e_start ∈ (E, 3E] it demands
     * active_since + 2E ≤ e_start − E − 1, which even the genesis-seeded
     * validators (active_since = 1) cannot meet — epoch 2E's committee
     * computed EMPTY. Pre-S3 that empty result silently fell back to the
     * gossip roster (F17 A5) and was never noticed because no chain had
     * reached epoch 2E (live devnet: E = 720, height ≈ 350). S3's
     * fail-closed commit_next turned it into a deterministic stall at
     * the first boundary that builds a gap-epoch snapshot.
     *
     * The Rule R intent is "two full epochs bonded BY THE EPOCH START",
     * so the tenure anchor is e_start; the state_seed still comes from
     * the lookback block above (unchanged, grinding resistance intact).
     * Genesis-seeded validators (active_since ≤ the genesis block) are
     * the chain's constitutional seed set and are always tenured —
     * Rule R exists to gate LATER joiners, and without the carve-out
     * even the anchor fix leaves epoch 2E empty (1 + 2E ≤ 2E fails by
     * exactly the one block genesis occupies). */
    int cand_count = 0;
    if (nodus_validator_bonded_tenured(w, e_start, candidates,
                                       DNAC_MAX_VALIDATORS,
                                       &cand_count) != 0) {
        free(candidates);
        return -1;
    }

    if (cand_count == 0) {
        free(candidates);
        return 0;   /* empty committee — count_out already 0 */
    }

    /* Build the work table: frozen totals + pre-computed tiebreaks. */
    committee_work_t *work =
        calloc((size_t)cand_count, sizeof(*work));
    if (!work) { free(candidates); return -1; }

    int n_work = 0;
    for (int i = 0; i < cand_count; i++) {
        uint64_t frozen_self = 0, frozen_total = 0;
        if (nodus_witness_v2_balance_copy_frozen(w, copy_epoch,
                                                 candidates[i].pubkey,
                                                 &frozen_self,
                                                 &frozen_total) != 0) {
            /* A copy that cannot be read is never "absent, rank at 0". */
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: frozen copy %llu unreadable "
                          "for a candidate — failing closed",
                          (unsigned long long)e_start,
                          (unsigned long long)copy_epoch);
            free(work);
            free(candidates);
            return -1;
        }
        if (frozen_total == 0) {
            /* not seatable — see the P3-1 block above */
            QGP_LOG_DEBUG(LOG_TAG, "epoch %llu: a bonded, tenured candidate "
                          "has no stake in copy(%llu) — not seated",
                          (unsigned long long)e_start,
                          (unsigned long long)copy_epoch);
            continue;
        }
        work[n_work].rec         = &candidates[i];
        work[n_work].total_stake = frozen_total;
        work[n_work].self_stake  = frozen_self;   /* <= total: own row is
                                                   * one of the summands  */
        compute_tiebreak_hash(candidates[i].pubkey, state_seed,
                              work[n_work].tiebreak);
        n_work++;
    }

    /* ONE total order: frozen total DESC, seeded tiebreak ASC. */
    if (n_work > 1)
        qsort(work, (size_t)n_work, sizeof(work[0]),
              cmp_frozen_desc_tiebreak_asc);

    int final_count = (n_work < max_entries) ? n_work : max_entries;
    for (int i = 0; i < final_count; i++) {
        emit_member(&work[i], &out[i]);
    }
    *count_out = final_count;

    free(work);
    free(candidates);
    return 0;
}

/* Bootstrap — Phase 10 / Task 52.
 *
 * Fires for e_start < EPOCH_LENGTH + 1, where the post-commit lookback
 * (e_start - EPOCH_LENGTH - 1) would underflow. Two bootstrap concerns:
 *
 *   1. state_seed: no usable lookback block. We read the genesis block
 *      (height 0) state_root as seed. This is deterministic — every
 *      witness sees the same genesis state_root once the genesis TX
 *      has been committed.
 *
 *   2. MIN_TENURE gate: validators seeded at genesis have
 *      active_since_block = 1, and with MIN_TENURE = 240 they cannot
 *      satisfy `active_since + 240 <= lookback_block` for any small
 *      lookback — no one would qualify. Design §3.6 explicitly carves
 *      out this case (the chain_def bootstrap path). Until
 *      chain_def.initial_validators lands (Task 56), we approximate
 *      the carve-out by passing lookback = INT64_MAX to
 *      nodus_validator_top_n, which effectively disables the tenure
 *      filter (active_since + 240 is never greater than INT64_MAX
 *      for any realistic active_since). INT64_MAX (not UINT64_MAX)
 *      because the helper binds its lookback parameter via
 *      sqlite3_bind_int64 (signed).
 *
 * Task 56 (Phase 12) will replace the INT64_MAX path with a read
 * from the genesis block's chain_def_blob, which names the initial
 * validator set explicitly.
 */
int nodus_committee_bootstrap_for_epoch(nodus_witness_t *w,
                                          uint64_t e_start,
                                          nodus_committee_member_t *out,
                                          int max_entries,
                                          int *count_out) {
    if (!w || !out || !count_out || max_entries <= 0) return -1;
    *count_out = 0;

    /* S3 — the bootstrap epoch reads the SAME target at the SAME key
     * (e_start) as the post-lookback path, so the two never disagree on
     * how many seats the epoch has. At genesis no chain_config_history
     * row for DNAC_CFG_TARGET_ACTIVE_COUNT exists, so this is the default
     * DNAC_TARGET_ACTIVE_DEFAULT (32 since tokenomics-v3 P3-7; the seven
     * genesis validators of a version-3 chain all fit under it).
     *
     * CORRECTED (O15J Faz 2 Block 2C): this used to read "no
     * chain_config_history row exists" — the pure-V2 builder now seeds
     * the economic parameters at effective_block 0
     * (nodus_witness_v2_gen.c gen_seed_state). None of them is
     * DNAC_CFG_TARGET_ACTIVE_COUNT, the only id
     * committee_target_for_epoch reads (:81-83), so the conclusion is
     * unchanged — it just no longer rests on the table being empty.
     * e_start is otherwise unused here: bootstrap always seeds its
     * tiebreak from the genesis block's state_root.
     *
     * O15J A2: same fail-closed rule as the post-lookback path. Note
     * this does NOT make a pre-genesis node fail — an EMPTY (or not yet
     * migrated) chain_config_history answers 1/absent, not -1. */
    {
        int target = 0;
        if (committee_target_for_epoch(w, e_start, &target) != 0) return -1;
        if (target < max_entries) max_entries = target;
    }

    /* state_seed from genesis block. If genesis block is not present
     * (fresh DB / pre-genesis state) fall back to an all-zero seed —
     * any committee we compute in that state is advisory and will be
     * discarded once the real genesis commits. */
    uint8_t state_seed[64];
    nodus_witness_block_t genesis_block;
    int rc = nodus_witness_block_get(w, 0, &genesis_block);
    if (rc == 0) {
        memcpy(state_seed, genesis_block.state_root, 64);
    } else {
        memset(state_seed, 0, sizeof(state_seed));
    }

    /* Admit every ACTIVE validator regardless of MIN_TENURE. The SQL
     * predicate in nodus_validator_top_n binds lookback_block via
     * sqlite3_bind_int64 (signed), so the upper bound we can safely
     * pass is INT64_MAX. active_since_block + 240 is <= INT64_MAX for
     * any realistic active_since — effectively disables the tenure
     * filter.
     *
     * Fetch the full table to keep behavior well-defined when N is
     * small: bootstrap chains may have only a handful of validators. */
    dnac_validator_record_t *candidates =
        calloc((size_t)DNAC_MAX_VALIDATORS, sizeof(*candidates));
    if (!candidates) return -1;

    int cand_count = 0;
    if (nodus_validator_top_n(w, DNAC_MAX_VALIDATORS,
                               (uint64_t)INT64_MAX,
                               candidates, &cand_count) != 0) {
        free(candidates);
        return -1;
    }

    if (cand_count == 0) {
        free(candidates);
        return 0;
    }

    /* Build the work table and apply the state_seed tiebreak sort.
     * Same in-group re-sort as the normal path — top_n established
     * stake DESC + pubkey ASC; we only replace the secondary. */
    committee_work_t *work =
        calloc((size_t)cand_count, sizeof(*work));
    if (!work) { free(candidates); return -1; }

    for (int i = 0; i < cand_count; i++) {
        work[i].rec = &candidates[i];
        /* bootstrap = the genesis snapshots: the LIVE genesis rows (the
         * same rows copy(0) is later written from) */
        work[i].total_stake =
            candidates[i].self_stake + candidates[i].external_delegated;
        work[i].self_stake = candidates[i].self_stake;
        compute_tiebreak_hash(candidates[i].pubkey, state_seed,
                              work[i].tiebreak);
    }
    for (int i = 0; i < cand_count; ) {
        int j = i + 1;
        while (j < cand_count &&
               work[j].total_stake == work[i].total_stake) {
            j++;
        }
        if (j - i > 1) {
            qsort(&work[i], (size_t)(j - i), sizeof(work[0]),
                  cmp_tiebreak_asc);
        }
        i = j;
    }

    int final_count = (cand_count < max_entries) ? cand_count : max_entries;
    for (int i = 0; i < final_count; i++) {
        emit_member(&work[i], &out[i]);
    }
    *count_out = final_count;

    free(work);
    free(candidates);
    return 0;
}

/* Cache accessor — Phase 10 / Task 53.
 *
 * Returns the committee active for `block_height`, computing + caching
 * on the first call within a given epoch and serving subsequent calls
 * from the cache. Cache lives on nodus_witness_t and is invalidated
 * implicitly when e_start changes (the lookup key differs).
 *
 * Consumers within a single block (apply_accumulator_update, BFT
 * roster — Task 59) call this rather than nodus_committee_compute_for_epoch
 * directly to amortise the SQL + SHA3 cost.
 *
 * Cache invalidation semantics (design §3.6):
 *   - Epoch-boundary transitions (Task 46) can change the committee,
 *     but the NEW committee applies to the NEXT epoch, so the cache
 *     for the current e_start stays valid until the caller advances
 *     to a new e_start.
 *   - STAKE/DELEGATE during the epoch alters rankings but NOT the
 *     frozen committee — the cache intentionally ignores them.
 */
int nodus_committee_get_for_block(nodus_witness_t *w,
                                    uint64_t block_height,
                                    nodus_committee_member_t *out,
                                    int max_entries,
                                    int *count_out) {
    if (!w || !out || !count_out || max_entries <= 0) return -1;

    /* Epoch boundary: block_height / EPOCH_LENGTH rounded down, times
     * EPOCH_LENGTH. Block 0..EPOCH_LENGTH-1 share e_start = 0, etc. */
    uint64_t e_start = (block_height / (uint64_t)DNAC_EPOCH_LENGTH)
                       * (uint64_t)DNAC_EPOCH_LENGTH;

    /* Cache hit. */
    if (w->cached_committee_epoch_start == e_start &&
        w->cached_committee_count >= 0) {
        int n = w->cached_committee_count < max_entries
                ? w->cached_committee_count : max_entries;
        for (int i = 0; i < n; i++) {
            memcpy(out[i].pubkey, w->cached_committee_pubkeys[i],
                   DNAC_PUBKEY_SIZE);
            out[i].total_stake    = w->cached_committee_stakes[i];
            /* S3 — the real bond, from the parallel array populated on the
             * miss path below. A cache HIT and a cache MISS must produce
             * the same member; the old 0-pin here made them differ and
             * forced nodus_witness_vset_build_for_epoch to bypass the
             * cache. */
            out[i].self_stake     = w->cached_committee_self_stakes[i];
            out[i].commission_bps = w->cached_committee_commission_bps[i];
        }
        *count_out = n;
        return 0;
    }

    /* Cache miss — compute and store.
     *
     * S3: DNAC_MAX_ACTIVE_VALIDATORS members are ~334 KB, so the scratch
     * buffer is HEAP, never a stack array. It is requested at the release
     * ceiling; compute_for_epoch narrows the result to the epoch's
     * chain-derived target itself. */
    nodus_committee_member_t *tmp =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*tmp));
    if (!tmp) {
        w->cached_committee_epoch_start = UINT64_MAX;
        w->cached_committee_count = 0;
        *count_out = 0;
        return -1;
    }
    int tmp_count = 0;

    /* ── S3 (ORCHESTRATOR integration): THE PERSISTED SNAPSHOT IS THE
     * COMMITTEE AUTHORITY for any epoch that has one. ───────────────────
     *
     * The row for e_start was frozen ONE EPOCH EARLIER inside the
     * boundary block's transaction (nodus_witness_vset_commit_next), so
     * it is committed, byte-identical chain state on every node. Serving
     * it here (a) makes the voting committee, the boundary status flips
     * and QC-V2 historical verification consume ONE set — without this,
     * a mid-epoch DELEGATE/UNSTAKE would let the recompute drift from the
     * frozen snapshot and the epoch's signers would not match its
     * committed set; and (b) removes a pre-existing hazard where a node
     * that restarts mid-epoch recomputed its committee from the CURRENT
     * table while its peers served their epoch-start cache — two answers
     * from one chain state.
     *
     * Epochs with NO row (pre-S3 history, hand-rolled test fixtures
     * without the table, pre-genesis) keep the legacy recompute path
     * byte-identically. A missing TABLE is probed via sqlite_master so a
     * legacy fixture is "absent", not "fault"; a row that exists but
     * fails integrity/decoding is a FAULT and the lookup fails closed —
     * a node that cannot know its committee must not vote.
     *
     * Deploy note: consensus deploys are stop-all
     * (feedback_consensus_deploy_stop_all); a mixed-version cluster where
     * only some nodes serve from snapshots could disagree on member ORDER
     * (leader election) if ranking inputs changed mid-epoch. */
    int served_from_snapshot = 0;
    if (w->db) {
        int have_table = 0;
        sqlite3_stmt *pr = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='validator_set_snapshots'", -1, &pr, NULL)
            != SQLITE_OK) {
            /* sqlite_master itself unreadable — a real DB fault. */
            free(tmp);
            w->cached_committee_epoch_start = UINT64_MAX;
            w->cached_committee_count = 0;
            *count_out = 0;
            return -1;
        }
        int prc = sqlite3_step(pr);
        sqlite3_finalize(pr);
        if (prc == SQLITE_ROW) {
            have_table = 1;
        } else if (prc != SQLITE_DONE) {
            free(tmp);
            w->cached_committee_epoch_start = UINT64_MAX;
            w->cached_committee_count = 0;
            *count_out = 0;
            return -1;
        }

        if (have_table) {
            dna_vset_snapshot_t *snap = NULL;
            int g = nodus_witness_vset_get(w, e_start, &snap, NULL);
            if (g == 0) {
                /* decode caps active_count at DNA_MAX_ACTIVE_VALIDATORS,
                 * and the shared/dnac ceiling equals the dnac one
                 * (pinned in serialize.c), so this cannot overflow tmp. */
                for (uint16_t i = 0; i < snap->active_count; i++) {
                    memcpy(tmp[i].pubkey, snap->entries[i].pubkey,
                           DNAC_PUBKEY_SIZE);
                    tmp[i].total_stake    = snap->entries[i].total_stake;
                    tmp[i].self_stake     = snap->entries[i].self_bond;
                    tmp[i].commission_bps = snap->entries[i].commission_bps;
                }
                tmp_count = (int)snap->active_count;
                dna_vset_free(&snap);
                served_from_snapshot = 1;
            } else if (g != 1) {
                /* Row exists but is corrupt / DB fault: never fall back
                 * to a recomputation — that would be the current-set
                 * substitution the design forbids. */
                free(tmp);
                w->cached_committee_epoch_start = UINT64_MAX;
                w->cached_committee_count = 0;
                *count_out = 0;
                return -1;
            }
            /* g == 1: no snapshot for this epoch — legacy recompute. */
        }
    }

    if (!served_from_snapshot) {
        int rc = nodus_committee_compute_for_epoch(w, e_start, tmp,
                                                      DNAC_MAX_ACTIVE_VALIDATORS,
                                                      &tmp_count);
        if (rc != 0) {
            /* Leave the cache invalid so the next call retries. */
            free(tmp);
            w->cached_committee_epoch_start = UINT64_MAX;
            w->cached_committee_count = 0;
            *count_out = 0;
            return rc;
        }
    }
    if (tmp_count < 0 || tmp_count > DNAC_MAX_ACTIVE_VALIDATORS) {
        /* Cannot happen — compute_for_epoch clamps to max_entries. Fail
         * closed rather than write past the cache arrays. */
        free(tmp);
        w->cached_committee_epoch_start = UINT64_MAX;
        w->cached_committee_count = 0;
        *count_out = 0;
        return -1;
    }

    for (int i = 0; i < tmp_count; i++) {
        memcpy(w->cached_committee_pubkeys[i], tmp[i].pubkey,
               DNAC_PUBKEY_SIZE);
        w->cached_committee_stakes[i]           = tmp[i].total_stake;
        w->cached_committee_self_stakes[i]      = tmp[i].self_stake;
        w->cached_committee_commission_bps[i]   = tmp[i].commission_bps;
    }
    w->cached_committee_count = tmp_count;
    w->cached_committee_epoch_start = e_start;

    int n = tmp_count < max_entries ? tmp_count : max_entries;
    for (int i = 0; i < n; i++) {
        out[i] = tmp[i];
    }
    *count_out = n;
    free(tmp);
    return 0;
}

int nodus_committee_get_for_block_alloc(nodus_witness_t *w,
                                          uint64_t block_height,
                                          nodus_committee_member_t **members_out,
                                          int *count_out) {
    if (!members_out || !count_out) return -1;
    *members_out = NULL;
    *count_out   = 0;

    nodus_committee_member_t *members =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*members));
    if (!members) return -1;

    int count = 0;
    if (nodus_committee_get_for_block(w, block_height, members,
                                        DNAC_MAX_ACTIVE_VALIDATORS,
                                        &count) != 0) {
        free(members);
        return -1;
    }

    *members_out = members;
    *count_out   = count;
    return 0;
}
