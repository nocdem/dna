/**
 * @file shared/dnac/cmt_results.c
 * @brief cometbft @709fd12b types/results.go in C — see cmt_results.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_results.h"

#include <string.h>

/* results.go:47-54 — deterministicExecTxResult(). The identity in this
 * port; see the header for why, and for why it exists anyway. */
int cmt_deterministic_exec_tx_result(const cmt_pb_exec_tx_result_t *response,
                                     cmt_pb_exec_tx_result_t *out)
{
    if (response == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_exec_tx_result_init(out);
    out->code       = response->code;        /* :49 */
    out->data       = response->data;        /* :50 */
    out->gas_wanted = response->gas_wanted;  /* :51 */
    out->gas_used   = response->gas_used;    /* :52 */
    return CMT_OK;
}

/* results.go:13-19 — NewResults() */
int cmt_new_results(const cmt_pb_exec_tx_result_t *responses, size_t n,
                    cmt_abci_results_t *out)
{
    size_t i;
    int    rc;

    if (out == NULL || (responses == NULL && n != 0)) {
        return CMT_FAULT;
    }
    if (n > out->results_cap) {
        return CMT_REJECT;
    }
    for (i = 0; i < n; i++) {                /* :15-17 */
        rc = cmt_deterministic_exec_tx_result(&responses[i], &out->results[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    out->results_len = n;                    /* :14 */
    return CMT_OK;                           /* :18 */
}

/* results.go:32-43 — toByteSlices() */
int cmt_abci_results_to_byte_slices(const cmt_abci_results_t *a,
                                    uint8_t *scratch, size_t scratch_cap,
                                    cmt_merkle_item_t *items,
                                    size_t items_cap)
{
    size_t off = 0, i;
    int    rc;

    if (a == NULL || (items == NULL && a->results_len != 0)) {
        return CMT_FAULT;
    }
    if (a->results_len > items_cap) {
        return CMT_REJECT;
    }
    if (a->results_len != 0 && (a->results == NULL || scratch == NULL)) {
        return CMT_FAULT;
    }
    for (i = 0; i < a->results_len; i++) {   /* :35-41 */
        size_t len = 0;

        if (off > scratch_cap) {
            return CMT_REJECT;
        }
        rc = cmt_pb_exec_tx_result_marshal(&a->results[i], scratch + off,
                                           scratch_cap - off, &len); /* :36 */
        if (rc != CMT_OK) {
            return rc;                       /* :37-39 the reference panics */
        }
        /* A wholly zero result marshals to ZERO bytes; the leaf is then
         * the nil leaf and hashes to H(0x00). That is the reference's
         * result too — see the header. */
        items[i].data = (len == 0) ? NULL : scratch + off;
        items[i].len  = len;
        off += len;
    }
    return CMT_OK;                           /* :42 */
}

/* results.go:22-24 — Hash() */
int cmt_abci_results_hash(const cmt_abci_results_t *a,
                          uint8_t *scratch, size_t scratch_cap,
                          cmt_merkle_item_t *items, size_t items_cap,
                          uint8_t out[CMT_TMHASH_SIZE])
{
    int rc;

    if (a == NULL || out == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_abci_results_to_byte_slices(a, scratch, scratch_cap, items,
                                         items_cap);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :23 — an empty list gives the empty tree's root, H(""). */
    return cmt_merkle_hash_from_byte_slices(items, a->results_len, out);
}

/* results.go:27-30 — ProveResult() */
int cmt_abci_results_prove_result(const cmt_abci_results_t *a, size_t i,
                                  uint8_t *scratch, size_t scratch_cap,
                                  cmt_merkle_item_t *items, size_t items_cap,
                                  cmt_proof_t *proofs, size_t proofs_cap,
                                  cmt_proof_t *out)
{
    int rc;

    if (a == NULL || out == NULL) {
        return CMT_FAULT;
    }
    /* :29 indexes proofs[i] with no check — a Go index panic. Made
     * explicit (INVARIANT 7495d337); an empty list rejects every i. */
    if (i >= a->results_len) {
        return CMT_REJECT;
    }
    if (a->results_len > proofs_cap || proofs == NULL) {
        return CMT_REJECT;
    }
    rc = cmt_abci_results_to_byte_slices(a, scratch, scratch_cap, items,
                                         items_cap);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_merkle_proofs_from_byte_slices(items, a->results_len, NULL,
                                            proofs);          /* :28 */
    if (rc != CMT_OK) {
        return rc;
    }
    *out = proofs[i];                                          /* :29 */
    return CMT_OK;
}
