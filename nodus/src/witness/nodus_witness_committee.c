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

#include "nodus/nodus_types.h"       /* NODUS_TREE_TAG_VALIDATOR */
#include "dnac/dnac.h"                /* DNAC_* constants */
#include "dnac/validator.h"
#include "crypto/hash/qgp_sha3.h"

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

/* Copy a work entry into the public member struct. */
static void emit_member(const committee_work_t *w_in,
                         nodus_committee_member_t *out) {
    memcpy(out->pubkey, w_in->rec->pubkey, DNAC_PUBKEY_SIZE);
    out->total_stake    = w_in->total_stake;
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

    uint64_t lookback_block = e_start - (uint64_t)DNAC_EPOCH_LENGTH - 1ULL;

    /* state_seed = state_root at lookback_block. */
    nodus_witness_block_t block_info;
    if (nodus_witness_block_get(w, lookback_block, &block_info) != 0) {
        fprintf(stderr, "%s: compute_for_epoch: block_get(%llu) failed\n",
                LOG_TAG, (unsigned long long)lookback_block);
        return -1;
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

    int cand_count = 0;
    if (nodus_validator_top_n(w, widen, lookback_block,
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
        compute_tiebreak_hash(candidates[i].pubkey, block_info.state_root,
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
    (void)e_start;   /* unused: bootstrap always seeds from genesis */

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

/* Cache accessor — Task 53 implements. Same weak-stub rationale. */
int __attribute__((weak))
nodus_committee_get_for_block(nodus_witness_t *w,
                                uint64_t block_height,
                                nodus_committee_member_t *out,
                                int max_entries,
                                int *count_out) {
    /* Default: uncached recompute at the epoch start for the block. */
    if (!w || !out || !count_out || max_entries <= 0) return -1;
    uint64_t e_start = (block_height / (uint64_t)DNAC_EPOCH_LENGTH)
                       * (uint64_t)DNAC_EPOCH_LENGTH;
    return nodus_committee_compute_for_epoch(w, e_start, out,
                                               max_entries, count_out);
}
