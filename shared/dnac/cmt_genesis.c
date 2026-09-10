/**
 * @file shared/dnac/cmt_genesis.c
 * @brief cometbft @709fd12b types/genesis.go in C — see cmt_genesis.h.
 *
 * The ONLY clock read in this file is the one the reference has at
 * genesis.go:102, and it goes through the caller's cmt_now_fn. Nothing
 * here links a clock.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_genesis.h"

#include <string.h>

/* `cmt_time_is_zero` moved to cmt_time.c in wave R1-D — it is a property of
 * a time, and cmt_block.c had a private second copy of it. Reached from
 * here through cmt_genesis.h -> cmt_time.h; the call at :101 below is
 * unchanged. */

/* genesis.go:58-65 — ValidatorHash() */
int cmt_genesis_doc_validator_hash(const cmt_genesis_doc_t *gen_doc,
                                   cmt_validator_t *vals_storage,
                                   size_t vals_cap,
                                   cmt_valset_scratch_t *scratch,
                                   uint8_t *hash_scratch,
                                   size_t hash_scratch_cap,
                                   cmt_merkle_item_t *items, size_t items_cap,
                                   uint8_t out[CMT_TMHASH_SIZE])
{
    cmt_validator_set_t vset;
    size_t              i;
    int                 rc;

    if (gen_doc == NULL || out == NULL || scratch == NULL) {
        return CMT_FAULT;
    }
    if (gen_doc->validators_len > vals_cap) {
        return CMT_REJECT;
    }
    if (gen_doc->validators_len != 0 &&
        (vals_storage == NULL || gen_doc->validators == NULL)) {
        return CMT_FAULT;
    }
    /* :59-62 — one Validator per genesis entry, its ADDRESS DERIVED FROM
     * THE KEY by NewValidator. The document's own Address field is not
     * consulted here; ValidateAndComplete is what reconciles the two. */
    for (i = 0; i < gen_doc->validators_len; i++) {
        rc = cmt_validator_new(&gen_doc->validators[i].pub_key,
                               gen_doc->validators[i].power,
                               &vals_storage[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    /* :63 — NewValidatorSet, which sorts and increments once. The
     * reference panics inside it on any error; here it is a return code.
     *
     * NOTE the deliberate aliasing: `vals_storage` is both the list the
     * set is BUILT FROM and the set's own storage, which the reference
     * gets for free because Go's slice header and the []*Validator are
     * separate objects. It is safe here because processChanges DEEP
     * COPIES its input into the scratch (validator_set.go:410) before
     * anything writes to the set, so every source value is already
     * elsewhere by the time the write-back happens. */
    rc = cmt_validator_set_init(&vset, vals_storage, vals_cap);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_new(&vset, vals_storage, gen_doc->validators_len,
                               scratch);
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_validator_set_hash(&vset, hash_scratch, hash_scratch_cap,
                                  items, items_cap, out);    /* :64 */
}

/* genesis.go:69-106 — ValidateAndComplete() */
int cmt_genesis_doc_validate_and_complete(cmt_genesis_doc_t *gen_doc,
                                          cmt_now_fn now, void *now_ctx)
{
    size_t i;
    int    rc;

    if (gen_doc == NULL) {
        return CMT_FAULT;
    }
    if (gen_doc->chain_id_len == 0) {                        /* :70-72 */
        return CMT_REJECT;
    }
    if (gen_doc->chain_id_len > CMT_GENESIS_MAX_CHAIN_ID_LEN) { /* :73-75 */
        return CMT_REJECT;
    }
    if (gen_doc->chain_id_len > CMT_PB_CHAINID_MAX) {
        /* ⚠ STRICTER THAN THE REFERENCE, and reachable. MaxChainIDLen is
         * 50 (cmt_genesis.h:89) while this port's chain id buffer is 32
         * (cmt_pb.h:131), so a chain id of 33..50 bytes passes the
         * reference's check at :73-75 and is refused here. It is a
         * CAPACITY refusal, not a consensus rule: such an id cannot be
         * represented in this tree's chain id field at all, and refusing
         * it is the only alternative to truncating it silently. */
        return CMT_REJECT;
    }
    if (gen_doc->initial_height < 0) {                       /* :76-78 */
        return CMT_REJECT;
    }
    if (gen_doc->initial_height == 0) {                      /* :79-81 */
        gen_doc->initial_height = 1;
    }
    if (!gen_doc->has_consensus_params) {                    /* :83-84 */
        cmt_default_consensus_params(&gen_doc->consensus_params);
        gen_doc->has_consensus_params = true;
    } else {                                                 /* :85-87 */
        rc = cmt_consensus_params_validate_basic(&gen_doc->consensus_params);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    for (i = 0; i < gen_doc->validators_len; i++) {          /* :89-99 */
        cmt_genesis_validator_t *v = &gen_doc->validators[i];
        uint8_t                  derived[CMT_PB_ADDRESS_MAX];

        if (v->power == 0) {                                 /* :90-92 */
            return CMT_REJECT;
        }
        /* NOTE: a NEGATIVE power is deliberately NOT refused here — the
         * reference tests only for zero. Validator.ValidateBasic
         * (validator.go:45-47) catches it later, on the way through
         * ValidatorHash. Faithfulness, not an omission. */
        rc = cmt_pub_key_address(&v->pub_key, derived);      /* :93 / :97 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (v->address_len > 0) {                            /* :93-95 */
            if (v->address_len != CMT_PB_ADDRESS_MAX ||
                memcmp(v->address, derived, CMT_PB_ADDRESS_MAX) != 0) {
                return CMT_REJECT;
            }
        } else {                                             /* :96-98 */
            memcpy(v->address, derived, CMT_PB_ADDRESS_MAX);
            v->address_len = CMT_PB_ADDRESS_MAX;
        }
    }
    if (cmt_time_is_zero(gen_doc->genesis_time)) {           /* :101 */
        if (now == NULL) {
            /* This chain never gets here — D-18 rev 2 makes genesis_time
             * mandatory (see the header). A time is NEVER invented. */
            return CMT_FAULT;
        }
        rc = now(now_ctx, &gen_doc->genesis_time);           /* :102 */
        if (rc != CMT_OK) {
            return rc;
        }
    }
    return CMT_OK;                                           /* :105 */
}
