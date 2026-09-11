/**
 * @file shared/dnac/cmt_state.c
 * @brief cometbft @709fd12b `state/state.go` in C — see cmt_state.h for
 *        the contract, the storage rules and the taşınmadı list.
 *
 * THE ONLY CLOCK IN THIS FILE is the one the reference has at
 * types/genesis.go:102, reached through the caller's `cmt_now_fn` by
 * `cmt_state_make_genesis`. `MedianTime` and `MakeBlock` read no clock.
 * Nothing here allocates.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_state.h"

#include <string.h>

/* ══ init / IsEmpty ═══════════════════════════════════════════════════ */

int cmt_state_init(cmt_state_t *state, cmt_state_storage_t *storage)
{
    if (state == NULL || storage == NULL) {
        return CMT_FAULT;
    }
    memset(state, 0, sizeof(*state));
    state->storage = storage;
    /* The three sets are left UNBOUND — every `validators` pointer is
     * NULL, which is the reference's nil and what IsEmpty reports. They
     * are bound by make_genesis and copy. See cmt_state.h. */
    state->last_block_time      = CMT_TIME_ZERO;
    state->last_block_id.hash_len = 0u;
    return CMT_OK;
}

/* cometbft@709fd12b state/state.go:129-131 — (state State) IsEmpty() */
bool cmt_state_is_empty(const cmt_state_t *state)
{
    if (state == NULL) {
        return true;
    }
    return state->validators.validators == NULL;                 /* :130 */
}

/* Bind one of the state's sets to its slice of the caller's storage. */
static int bind_set(cmt_validator_set_t *vs, cmt_validator_t *storage)
{
    return cmt_validator_set_init(vs, storage, (size_t)CMT_VALSET_MAX);
}

/* ══ Copy ═════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b state/state.go:83-106 — (state State) Copy() */
int cmt_state_copy(const cmt_state_t *src, cmt_state_t *dst)
{
    cmt_state_storage_t *storage;
    int                  rc;

    if (src == NULL || dst == NULL) {
        return CMT_FAULT;
    }
    if (dst->storage == NULL || src->storage == NULL) {
        return CMT_FAULT;
    }
    if (dst->storage == src->storage) {
        /* A copy sharing the source's storage would not be a copy. */
        return CMT_FAULT;
    }
    if (cmt_state_is_empty(src)) {
        /* :94-96 would nil-dereference on `state.Validators.Copy()`. The
         * reference never reaches it; this refuses rather than invent. */
        return CMT_FAULT;
    }
    storage = dst->storage;

    /* Every scalar of :85-104, in the reference's order. */
    dst->version        = src->version;                       /* :86    */
    memcpy(dst->chain_id, src->chain_id, sizeof(dst->chain_id));/* :87  */
    dst->chain_id_len   = src->chain_id_len;
    dst->initial_height = src->initial_height;                /* :88    */

    dst->last_block_height = src->last_block_height;           /* :90    */
    dst->last_block_id     = src->last_block_id;               /* :91    */
    dst->last_block_time   = src->last_block_time;             /* :92    */

    /* :94-96 — the three DEEP copies, into dst's OWN storage. */
    rc = bind_set(&dst->next_validators, storage->next_validators);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_copy(&src->next_validators,
                                &dst->next_validators);        /* :94    */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = bind_set(&dst->validators, storage->validators);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_copy(&src->validators, &dst->validators);/* :95 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = bind_set(&dst->last_validators, storage->last_validators);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_copy(&src->last_validators,
                                &dst->last_validators);        /* :96    */
    if (rc != CMT_OK) {
        return rc;
    }
    dst->last_height_validators_changed =
        src->last_height_validators_changed;                   /* :97    */

    dst->consensus_params = src->consensus_params;             /* :99    */
    dst->last_height_consensus_params_changed =
        src->last_height_consensus_params_changed;             /* :100   */

    /* :102, :104 — Go SHARES these slices; C copies the bytes. Same
     * values; a C copy simply cannot alias. See cmt_state.h. */
    memcpy(dst->app_hash, src->app_hash, sizeof(dst->app_hash));
    dst->app_hash_len = src->app_hash_len;
    memcpy(dst->last_results_hash, src->last_results_hash,
           sizeof(dst->last_results_hash));
    dst->last_results_hash_len = src->last_results_hash_len;

    dst->storage = storage;
    return CMT_OK;
}

/* ══ MedianTime ═══════════════════════════════════════════════════════ */

/* cometbft@709fd12b state/state.go:269-286 — MedianTime().
 * BFT-time's block time; reads NO clock. */
int cmt_state_median_time(const cmt_commit_t *commit,
                          const cmt_validator_set_t *vals,
                          cmt_time_t *out)
{
    cmt_weighted_time_t        times[CMT_VALSET_MAX];
    const cmt_weighted_time_t *slots[CMT_VALSET_MAX];
    int64_t                    total = 0;                        /* :271 */
    size_t                     n;
    size_t                     i;
    int                        rc;

    if (commit == NULL || vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    n = cmt_commit_size(commit);
    if (n > (size_t)CMT_VALSET_MAX) {
        /* A capacity rule of this port: the reference sizes the array at
         * :270 dynamically, and nothing here allocates. It cannot fire on
         * a commit whose signature count equals a set size, since a set
         * holds at most CMT_VALSET_MAX. */
        return CMT_REJECT;
    }
    if (n != 0u && commit->signatures == NULL) {
        return CMT_FAULT;
    }
    /* :270 — one slot per signature, LEFT AS HOLES where the reference
     * leaves nil. */
    for (i = 0; i < n; i++) {
        slots[i] = NULL;
    }

    for (i = 0; i < n; i++) {                                 /* :273-283 */
        const cmt_commit_sig_t *cs = &commit->signatures[i];
        cmt_validator_t         val;
        int32_t                 idx;

        if (cs->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT) {
            continue;                                         /* :274-276 */
        }
        /* :277 — BY ADDRESS, not by index. */
        rc = cmt_validator_set_get_by_address(vals, cs->validator_address,
                                              cs->validator_address_len,
                                              &idx, &val);
        if (rc != CMT_OK) {
            return rc;
        }
        if (idx < 0) {
            /* :278-279 — the reference's own comment: without this test a
             * test panicked; "not needed normally". A signer the set does
             * not contain contributes NOTHING, silently. */
            continue;
        }
        total = total + val.voting_power;                        /* :280 */
        rc = cmt_new_weighted_time(cs->timestamp, val.voting_power,
                                   &times[i]);                   /* :281 */
        if (rc != CMT_OK) {
            return rc;
        }
        slots[i] = &times[i];
    }
    /* :285 — and the median itself, including the zero-time fallback when
     * nothing was selected. */
    return cmt_weighted_median(slots, n, total, out);
}

/* ══ MakeBlock ════════════════════════════════════════════════════════ */

/* cometbft@709fd12b state/state.go:234-263 — (state State) MakeBlock() */
int cmt_state_make_block(const cmt_state_t *state,
                         int64_t height,
                         const cmt_data_t *data,
                         cmt_commit_t *last_commit,
                         const cmt_evidence_data_t *evidence,
                         const uint8_t *proposer_address,
                         size_t proposer_address_len,
                         cmt_state_block_scratch_t *scratch,
                         cmt_block_t *out)
{
    uint8_t    val_hash[CMT_TMHASH_SIZE];
    uint8_t    next_val_hash[CMT_TMHASH_SIZE];
    uint8_t    cons_hash[CMT_TMHASH_SIZE];
    cmt_time_t timestamp;
    int        rc;

    if (state == NULL || scratch == NULL || out == NULL) {
        return CMT_FAULT;
    }
    /* :243 — the base block, which ends in fillHeader (test_util.go:121).
     * Version{Block, App} are the STATE's, not a compile-time constant
     * (D-19 rev 6 item 1). */
    rc = cmt_make_block(height, state->version.consensus.block,
                        state->version.consensus.app,
                        data, last_commit, evidence, out);
    if (rc != CMT_OK) {
        return rc;
    }

    /* :246-251 — the TIMESTAMP. */
    if (height == state->initial_height) {
        timestamp = state->last_block_time;   /* :248 the genesis time   */
    } else {
        if (last_commit == NULL) {
            /* :250 would nil-dereference inside MedianTime (:270). */
            return CMT_FAULT;
        }
        rc = cmt_state_median_time(last_commit, &state->last_validators,
                                   &timestamp);                  /* :250 */
        if (rc != CMT_OK) {
            return rc;
        }
    }

    /* :257 — the two set hashes. */
    rc = cmt_validator_set_hash(&state->validators, scratch->leaves,
                                sizeof(scratch->leaves), scratch->items,
                                (size_t)CMT_VALSET_MAX, val_hash);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_hash(&state->next_validators, scratch->leaves,
                                sizeof(scratch->leaves), scratch->items,
                                (size_t)CMT_VALSET_MAX, next_val_hash);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :258 — ConsensusHash, a FLAT hash of HashedParams (params.go:272). */
    rc = cmt_consensus_params_hash(&state->consensus_params, cons_hash);
    if (rc != CMT_OK) {
        return rc;
    }

    /* :254-260 — Populate fills the ten state-derived header fields. It
     * deliberately does not touch Height (MakeBlock set it) nor the three
     * fillHeader computed. */
    return cmt_header_populate(&out->header,
                               &state->version.consensus,        /* :255 */
                               state->chain_id, state->chain_id_len,
                               timestamp,                        /* :256 */
                               &state->last_block_id,
                               val_hash, (size_t)CMT_TMHASH_SIZE,/* :257 */
                               next_val_hash, (size_t)CMT_TMHASH_SIZE,
                               cons_hash, (size_t)CMT_TMHASH_SIZE,/* :258 */
                               state->app_hash, state->app_hash_len,
                               state->last_results_hash,
                               state->last_results_hash_len,
                               proposer_address,                 /* :259 */
                               proposer_address_len);
}

/* ══ MakeGenesisState ═════════════════════════════════════════════════ */

/* cometbft@709fd12b state/state.go:317-355 — MakeGenesisState() */
int cmt_state_make_genesis(cmt_genesis_doc_t *gen_doc,
                           cmt_now_fn now, void *now_ctx,
                           cmt_valset_scratch_t *scratch,
                           cmt_state_t *out)
{
    cmt_state_storage_t *storage;
    size_t               i;
    int                  rc;

    if (gen_doc == NULL || scratch == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (out->storage == NULL) {
        return CMT_FAULT;
    }
    if (gen_doc->validators == NULL && gen_doc->validators_len != 0u) {
        /* A NULL list with a non-zero count is this representation's own
         * error (a Go nil slice has length 0); ValidateAndComplete below
         * would read through it. */
        return CMT_FAULT;
    }
    storage = out->storage;

    /* :318-321 — and the ONLY clock in this file, which this chain never
     * reaches (D-18 rev 2 makes genesis_time mandatory). */
    rc = cmt_genesis_doc_validate_and_complete(gen_doc, now, now_ctx);
    if (rc != CMT_OK) {
        return rc;
    }
    if (gen_doc->validators_len > (size_t)CMT_VALSET_MAX) {
        return CMT_REJECT;      /* the port's capacity rule (R1C-5)      */
    }

    rc = bind_set(&out->validators, storage->validators);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = bind_set(&out->next_validators, storage->next_validators);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = bind_set(&out->last_validators, storage->last_validators);
    if (rc != CMT_OK) {
        return rc;
    }

    if (gen_doc->validators == NULL) {
        /* :324-326 — `genDoc.Validators == nil`: two EMPTY BUT NOT NIL
         * sets. A NULL list pointer IS the reference's nil slice; a
         * non-NULL list of length zero is the reference's EMPTY slice and
         * takes the other branch below, where :333 panics and this port
         * REJECTs (Delta D-1; see cmt_state.h). */
        rc = cmt_validator_set_new(&out->validators, NULL, 0u, scratch);
        if (rc != CMT_OK) {
            return rc;
        }
        rc = cmt_validator_set_new(&out->next_validators, NULL, 0u,
                                   scratch);
        if (rc != CMT_OK) {
            return rc;
        }
    } else {
        /* :328-331 — one Validator per entry, its ADDRESS DERIVED FROM THE
         * KEY by NewValidator; the document's Address field is not read. */
        for (i = 0; i < gen_doc->validators_len; i++) {
            rc = cmt_validator_new(&gen_doc->validators[i].pub_key,
                                   gen_doc->validators[i].power,
                                   &storage->validators[i]);     /* :330 */
            if (rc != CMT_OK) {
                return rc;
            }
        }
        /* :332 — NewValidatorSet, which sorts and increments once.
         *
         * NOTE the deliberate aliasing, the same one cmt_genesis.c relies
         * on: `storage->validators` is both the list the set is BUILT FROM
         * and the set's own storage. It is safe because processChanges
         * DEEP COPIES its input into the scratch (validator_set.go:410)
         * before anything writes back. */
        rc = cmt_validator_set_new(&out->validators, storage->validators,
                                   gen_doc->validators_len, scratch);
        if (rc != CMT_OK) {
            return rc;
        }
        /* :333 — the NEXT set is the same validators after ONE increment,
         * so the proposer for the block after genesis is already elected.
         * With an EMPTY (non-nil) list the reference PANICS here —
         * IncrementProposerPriority refuses an empty set
         * (validator_set.go:132-134) — and the C increment returns
         * CMT_REJECT at the same check (INVARIANT 7495d337: panic →
         * REJECT). Nothing is added for it; the port's own function
         * carries the verdict. */
        rc = cmt_validator_set_copy_increment_proposer_priority(
                 &out->validators, &out->next_validators, 1);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    /* :347 — LastValidators is an EMPTY set, not a nil one: at height 0
     * there is no previous commit to validate. */
    rc = cmt_validator_set_new(&out->last_validators, NULL, 0u, scratch);
    if (rc != CMT_OK) {
        return rc;
    }

    /* :337 — InitStateVersion (:30-36): the block protocol, App 0, and the
     * software string. See CMT_SOFTWARE_VERSION in cmt_state.h — it is
     * store-only, and since 2026-09-10 it is this node's own Nodus version,
     * supplied by the build rather than compiled in as the reference's
     * literal (atlas-dec-157739c22040e385e1096932fc7d3a63). */
    out->version.consensus.block = (uint64_t)CMT_BLOCK_PROTOCOL;  /* :32  */
    out->version.consensus.app   = 0u;                            /* :33  */
    memset(out->version.software, 0, sizeof(out->version.software));
    memcpy(out->version.software, CMT_SOFTWARE_VERSION,
           sizeof(CMT_SOFTWARE_VERSION) - 1u);                    /* :35  */

    memcpy(out->chain_id, gen_doc->chain_id, sizeof(out->chain_id));/* :338 */
    out->chain_id_len   = gen_doc->chain_id_len;
    out->initial_height = gen_doc->initial_height;                /* :339 */

    out->last_block_height = 0;                                   /* :341 */
    cmt_pb_block_id_init(&out->last_block_id);                    /* :342 */
    out->last_block_time = gen_doc->genesis_time;                 /* :343 */

    out->last_height_validators_changed = gen_doc->initial_height;/* :348 */

    /* :350 — `*genDoc.ConsensusParams`, which ValidateAndComplete has
     * made non-nil (genesis.go:83-87). If it somehow is not, that is a
     * broken invariant of this process, not a property of the document. */
    if (!gen_doc->has_consensus_params) {
        return CMT_FAULT;
    }
    out->consensus_params = gen_doc->consensus_params;
    out->last_height_consensus_params_changed =
        gen_doc->initial_height;                                  /* :351 */

    memset(out->app_hash, 0, sizeof(out->app_hash));
    if (gen_doc->app_hash_len > sizeof(out->app_hash)) {
        return CMT_REJECT;
    }
    if (gen_doc->app_hash_len != 0u) {
        memcpy(out->app_hash, gen_doc->app_hash, gen_doc->app_hash_len);
    }
    out->app_hash_len = gen_doc->app_hash_len;                    /* :353 */

    /* The reference leaves LastResultsHash at its zero value here — it is
     * not in the struct literal at :336-354 — and consensus/replay.go:368
     * is where the first block's H("") comes from. Left EMPTY, not
     * invented. */
    memset(out->last_results_hash, 0, sizeof(out->last_results_hash));
    out->last_results_hash_len = 0u;

    return CMT_OK;
}
