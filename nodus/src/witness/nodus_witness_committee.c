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

#include "nodus/nodus_types.h"       /* NODUS_TREE_TAG_VALIDATOR */
#include "nodus/nodus_chain_config.h" /* nodus_chain_config_get_u64 */
#include "dnac/dnac.h"                /* DNAC_* constants */
#include "dnac/validator.h"
#include "dnac/block_v2.h"            /* O15E: successor seed row checks */
#include "crypto/hash/qgp_sha3.h"

#include <sqlite3.h>   /* S3: sqlite_master probe in get_for_block */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_COMMITTEE"

/* Per-validator work record used while sorting. Holds a pointer into
 * the caller's candidates[] array plus the pre-computed tiebreak hash
 * so qsort can run on POD entries without extra SHA3 calls. */
typedef struct {
    const dnac_validator_record_t *rec;
    uint64_t total_stake;
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

/* S3 — the epoch's target active-set size.
 *
 * Keyed on `e_start`, the epoch START height, NOT on the height being
 * queried: every block of the epoch must read the same value, otherwise a
 * chain_config row with a mid-epoch effective_block would resize a live
 * committee. Deterministic cross-node because
 * nodus_chain_config_get_u64 answers from committed chain_config_history
 * rows (nodus_witness_chain_config.c:240-268) — the same source the
 * INFLATION_START_BLOCK consumer uses inside finalize_block
 * (nodus_witness_bft.c:3230-3234).
 *
 * The default is DNAC_COMMITTEE_SIZE, so a chain with no governance row
 * (every chain today) selects exactly as it did before S3. The clamp is
 * the release ceiling, defence-in-depth on top of the apply-side range
 * check in nodus_chain_config_apply. */
static int committee_target_for_epoch(nodus_witness_t *w, uint64_t e_start) {
    uint64_t target = nodus_chain_config_get_u64(
        w, (uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT, e_start,
        (uint64_t)DNAC_COMMITTEE_SIZE);
    if (target < 1) target = 1;
    if (target > (uint64_t)DNAC_MAX_ACTIVE_VALIDATORS)
        target = (uint64_t)DNAC_MAX_ACTIVE_VALIDATORS;
    /* O15F Task 1 — a successor's active set is capped at
     * NODUS_V2_ACTIVE_SET_MAX (the seam sets v2_successor before genesis
     * seeding, so this fires during seeding too). Legacy chains keep the
     * 128 ceiling above. Mirrors vset_target_for_epoch. */
    if (w->v2_successor && target > (uint64_t)NODUS_V2_ACTIVE_SET_MAX)
        target = (uint64_t)NODUS_V2_ACTIVE_SET_MAX;
    return (int)target;
}

/* ── O15E Faz A — the successor's committed seed row ──────────────────
 *
 * On a SUCCESSOR chain the state_seed's authoritative block-identity
 * source is the committed `v2_blocks` BlockID at the lookback height
 * (64 bytes — the exact width the tiebreak preimage already consumes).
 * This closes ACTIVATION OBLIGATION 2 (nodus_witness_v2_epoch.h): the
 * terminal legacy `blocks` table is NEVER consulted for live successor
 * committee authority, and an unusable seed row FAILS CLOSED before any
 * committee is emitted.
 *
 * Fail-closed classes, each -1:
 *   - MISSING: no committed row at the height (a successor produces
 *     every height contiguously, so absence is a real fault);
 *   - MALFORMED: block_id not exactly 64 B, header not exactly the
 *     canonical 413 B, strict-decode reject (retired v2 and unknown
 *     versions are both rejects inside dna_bh2_decode), or a header
 *     height disagreeing with the row's key;
 *   - WRONG CHAIN / FORGED (height > 0): header chain_id must equal the
 *     node's derived successor chain id, and the BlockID recomputed
 *     from the stored canonical header must equal the stored block_id.
 *   - Height 0 (reachable only via a direct e_start == E+1 call — every
 *     real caller passes epoch starts that are multiples of E): the
 *     genesis header carries an ALL-ZERO chain_id by construction (the
 *     identity-circularity break, nodus_witness_v2_apply.c genesis
 *     path), and its block_id is dna_bh2_genesis_block_id over the
 *     manifest bytes, NOT header-recomputable here. The arm checks the
 *     zero chain_id + height and takes the stored id; the committed
 *     genesis row's authenticity is established by the post-open gate
 *     probe on every database open (witness_post_open_gate). */
static int v2_seed_block_id(nodus_witness_t *w, uint64_t height,
                            uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id, header FROM v2_blocks WHERE global_height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (int64_t)height);
    if (sqlite3_step(st) != SQLITE_ROW) {          /* MISSING */
        sqlite3_finalize(st);
        return -1;
    }
    const void *id = sqlite3_column_blob(st, 0);
    int idl        = sqlite3_column_bytes(st, 0);
    const void *hd = sqlite3_column_blob(st, 1);
    int hdl        = sqlite3_column_bytes(st, 1);
    if (!id || idl != DNA_BH2_ID_LEN ||
        !hd || hdl != DNA_BH2_ENC_SIZE) {          /* MALFORMED */
        sqlite3_finalize(st);
        return -1;
    }

    dna_block_header_v2_t hdr;
    if (dna_bh2_decode(hd, (size_t)hdl, &hdr) != 0 ||   /* wrong type */
        hdr.block_height != height) {                   /* wrong row  */
        sqlite3_finalize(st);
        return -1;
    }

    if (height == 0) {
        static const uint8_t zero32[32] = {0};
        if (memcmp(hdr.chain_id, zero32, sizeof(zero32)) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
    } else {
        uint8_t recomputed[DNA_BH2_ID_LEN];
        if (memcmp(hdr.chain_id, w->v2_chain32, 32) != 0 ||  /* WRONG CHAIN */
            dna_bh2_block_id(&hdr, recomputed) != 0 ||
            memcmp(recomputed, id, DNA_BH2_ID_LEN) != 0) {   /* FORGED */
            sqlite3_finalize(st);
            return -1;
        }
    }

    memcpy(out, id, DNA_BH2_ID_LEN);
    sqlite3_finalize(st);
    return 0;
}

/* Copy a work entry into the public member struct. */
static void emit_member(const committee_work_t *w_in,
                         nodus_committee_member_t *out) {
    memcpy(out->pubkey, w_in->rec->pubkey, DNAC_PUBKEY_SIZE);
    out->total_stake    = w_in->total_stake;
    out->self_stake     = w_in->rec->self_stake;   /* S3: snapshot self_bond */
    out->commission_bps = w_in->rec->commission_bps;
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

    /* S3 — the epoch's target set size, from committed chain state. */
    int target = committee_target_for_epoch(w, e_start);
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

    /* Widen the initial candidate set so we can re-apply the state_seed
     * tiebreak to any ties that the DB sort (pubkey ASC) resolved
     * differently. 3× max_entries is a heuristic: enough slack to
     * capture tied-group ripples without exploding the SHA3 bill.
     * Capped at DNAC_MAX_VALIDATORS (the full table). */
    int widen = max_entries * 3;
    if (widen > DNAC_MAX_VALIDATORS) widen = DNAC_MAX_VALIDATORS;

    dnac_validator_record_t *candidates =
        calloc((size_t)widen, sizeof(*candidates));
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
    if (nodus_validator_top_n(w, widen, e_start,
                               candidates, &cand_count) != 0) {
        free(candidates);
        return -1;
    }

    if (cand_count == 0) {
        free(candidates);
        return 0;   /* empty committee — count_out already 0 */
    }

    /* Build the work table with pre-computed tiebreaks. */
    committee_work_t *work =
        calloc((size_t)cand_count, sizeof(*work));
    if (!work) { free(candidates); return -1; }

    for (int i = 0; i < cand_count; i++) {
        work[i].rec = &candidates[i];
        work[i].total_stake =
            candidates[i].self_stake + candidates[i].external_delegated;
        compute_tiebreak_hash(candidates[i].pubkey, state_seed,
                              work[i].tiebreak);
    }

    /* top_n already sorted by stake DESC + pubkey ASC. Walk consecutive
     * groups with identical total_stake and re-sort each group by
     * tiebreak ASC. The primary order is preserved because we never
     * swap across groups. */
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
     * row for DNAC_CFG_TARGET_ACTIVE_COUNT exists, so this is
     * DNAC_COMMITTEE_SIZE and the bootstrap committee is exactly what it
     * was before S3.
     *
     * CORRECTED (O15J Faz 2 Block 2C): this used to read "no
     * chain_config_history row exists" — the pure-V2 builder now seeds
     * the economic parameters at effective_block 0
     * (nodus_witness_v2_gen.c gen_seed_state). None of them is
     * DNAC_CFG_TARGET_ACTIVE_COUNT, the only id
     * committee_target_for_epoch reads (:81-83), so the conclusion is
     * unchanged — it just no longer rests on the table being empty.
     * e_start is otherwise unused here: bootstrap always seeds its
     * tiebreak from the genesis block's state_root. */
    {
        int target = committee_target_for_epoch(w, e_start);
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
        work[i].total_stake =
            candidates[i].self_stake + candidates[i].external_delegated;
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
