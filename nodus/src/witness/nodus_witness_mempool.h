/**
 * Nodus — Witness Mempool
 *
 * Fee-ordered queue of pending DNAC transactions awaiting inclusion
 * in a BFT consensus round. Leader accumulates TXs here and proposes
 * batches at block intervals.
 *
 * @file nodus_witness_mempool.h
 */

#ifndef NODUS_WITNESS_MEMPOOL_H
#define NODUS_WITNESS_MEMPOOL_H

#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nodus_tcp_conn;

/* ── Mempool entry (single pending TX) ──────────────────────────── */

typedef struct {
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
    uint8_t     nullifier_count;
    uint8_t     tx_type;
    uint8_t    *tx_data;                              /* heap-allocated */
    uint32_t    tx_len;
    uint8_t     client_pubkey[NODUS_PK_BYTES];
    uint8_t     client_sig[NODUS_SIG_BYTES];
    uint64_t    fee;

    /* Client response routing */
    struct nodus_tcp_conn *client_conn;
    uint32_t    client_txn_id;
    bool        is_forwarded;
    uint8_t     forwarder_id[NODUS_T3_WITNESS_ID_LEN];
} nodus_witness_mempool_entry_t;

/* ── Mempool ────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_mempool_entry_t *entries[NODUS_W_MAX_MEMPOOL];
    int         count;
    uint64_t    last_block_time_ms;   /* timestamp of last block proposal (ms) */
} nodus_witness_mempool_t;

/* ── Operations ─────────────────────────────────────────────────── */

/** Initialize mempool (zero state). */
void nodus_witness_mempool_init(nodus_witness_mempool_t *mp);

/**
 * Add entry to mempool in fee-sorted order (highest fee first).
 * Takes ownership of entry pointer. Rejects duplicates (same tx_hash).
 *
 * @return 0 on success, -1 if full, -2 if duplicate
 */
int nodus_witness_mempool_add(nodus_witness_mempool_t *mp,
                               nodus_witness_mempool_entry_t *entry);

/**
 * Pop up to max entries from the head (highest fee).
 * Popped pointers are written to out[]. Caller takes ownership.
 *
 * @return number of entries popped
 */
int nodus_witness_mempool_pop_batch(nodus_witness_mempool_t *mp,
                                     nodus_witness_mempool_entry_t **out,
                                     int max);

/**
 * Remove all entries associated with a client connection.
 * Called when connection is closed. Frees removed entries.
 */
void nodus_witness_mempool_remove_by_conn(nodus_witness_mempool_t *mp,
                                            struct nodus_tcp_conn *conn);

/** Free all entries and reset count. */
void nodus_witness_mempool_clear(nodus_witness_mempool_t *mp);

/** Free a single mempool entry (including tx_data). */
void nodus_witness_mempool_entry_free(nodus_witness_mempool_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_MEMPOOL_H */
