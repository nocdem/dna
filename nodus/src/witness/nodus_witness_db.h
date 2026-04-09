/**
 * Nodus — Witness Database Layer
 *
 * SQLite operations for DNAC witness state: nullifiers, ledger,
 * UTXO set, blocks, genesis, supply tracking.
 * All functions take nodus_witness_t* (use witness->db).
 *
 * Ported from dnac/src/witness/{nullifier,ledger,utxo_set,block}.c
 *
 * @file nodus_witness_db.h
 */

#ifndef NODUS_WITNESS_DB_H
#define NODUS_WITNESS_DB_H

#include "witness/nodus_witness.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Nullifier operations ────────────────────────────────────────── */

bool nodus_witness_nullifier_exists(nodus_witness_t *w, const uint8_t *nullifier);
int  nodus_witness_nullifier_add(nodus_witness_t *w, const uint8_t *nullifier,
                                  const uint8_t *tx_hash);

/* ── UTXO set operations ─────────────────────────────────────────── */

int  nodus_witness_utxo_lookup(nodus_witness_t *w, const uint8_t *nullifier,
                                uint64_t *amount_out, char *owner_out);
int  nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height,
                              const uint8_t *token_id);
int  nodus_witness_utxo_remove(nodus_witness_t *w, const uint8_t *nullifier);
int  nodus_witness_utxo_count(nodus_witness_t *w, uint64_t *count_out);
int  nodus_witness_utxo_sum(nodus_witness_t *w, uint64_t *sum_out);

/**
 * Compute SHA3-512 checksum of the entire UTXO set.
 * Hashes all nullifiers in sorted order for cross-witness validation.
 *
 * @param w             Witness context
 * @param checksum_out  Output 64-byte hash (NODUS_KEY_BYTES)
 * @return 0 on success, -1 on error
 */
int nodus_witness_utxo_checksum(nodus_witness_t *w, uint8_t *checksum_out);

/* Query UTXOs by owner fingerprint */
typedef struct {
    uint8_t     nullifier[NODUS_T3_NULLIFIER_LEN];
    char        owner[129];     /* fingerprint */
    uint64_t    amount;
    uint8_t     token_id[64];   /* 64 bytes — zeros = native DNAC */
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint32_t    output_index;
    uint64_t    block_height;
} nodus_witness_utxo_entry_t;

int  nodus_witness_utxo_by_owner(nodus_witness_t *w, const char *owner,
                                   nodus_witness_utxo_entry_t *out,
                                   int max_entries, int *count_out);

/* ── Token registry operations ──────────────────────────────────── */

int  nodus_witness_token_add(nodus_witness_t *w, const uint8_t *token_id,
                               const char *name, const char *symbol,
                               uint8_t decimals, uint64_t supply,
                               const char *creator_fp, uint8_t flags,
                               uint64_t block_height);
int  nodus_witness_token_exists(nodus_witness_t *w, const uint8_t *token_id);
int  nodus_witness_token_get(nodus_witness_t *w, const uint8_t *token_id,
                               char *name_out, char *symbol_out,
                               uint8_t *decimals_out, uint64_t *supply_out,
                               char *creator_fp_out);

/* ── Ledger operations ───────────────────────────────────────────── */

typedef struct {
    uint64_t    sequence;
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     tx_type;
    uint64_t    epoch;
    uint64_t    timestamp;
    uint8_t     nullifier_count;
} nodus_witness_ledger_entry_t;

int  nodus_witness_ledger_add(nodus_witness_t *w, const uint8_t *tx_hash,
                                uint8_t tx_type, uint8_t nullifier_count);
int  nodus_witness_ledger_get(nodus_witness_t *w, uint64_t seq,
                                nodus_witness_ledger_entry_t *out);
int  nodus_witness_ledger_get_by_hash(nodus_witness_t *w, const uint8_t *tx_hash,
                                        nodus_witness_ledger_entry_t *out);
int  nodus_witness_ledger_get_range(nodus_witness_t *w, uint64_t from, uint64_t to,
                                      nodus_witness_ledger_entry_t *out,
                                      int max_entries, int *count_out);
uint64_t nodus_witness_ledger_count(nodus_witness_t *w);

/* ── Block operations ────────────────────────────────────────────── */

typedef struct {
    uint64_t    height;
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     tx_type;
    uint64_t    timestamp;
    uint8_t     proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     prev_hash[NODUS_T3_TX_HASH_LEN];  /* SHA3-512 of previous block */
} nodus_witness_block_t;

int  nodus_witness_block_add(nodus_witness_t *w, const uint8_t *tx_hash,
                               uint8_t tx_type, uint64_t timestamp,
                               const uint8_t *proposer_id);
int  nodus_witness_block_get(nodus_witness_t *w, uint64_t height,
                               nodus_witness_block_t *out);
int  nodus_witness_block_get_latest(nodus_witness_t *w,
                                      nodus_witness_block_t *out);
int  nodus_witness_block_get_range(nodus_witness_t *w,
                                      uint64_t from_height, uint64_t to_height,
                                      nodus_witness_block_t *out,
                                      int max_entries, int *count_out);
uint64_t nodus_witness_block_height(nodus_witness_t *w);

/* ── Genesis state ───────────────────────────────────────────────── */

typedef struct {
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint64_t    total_supply;
    uint64_t    timestamp;
} nodus_witness_genesis_t;

bool nodus_witness_genesis_exists(nodus_witness_t *w);
int  nodus_witness_genesis_set(nodus_witness_t *w, const uint8_t *tx_hash,
                                 uint64_t total_supply,
                                 const uint8_t *commitment);
int  nodus_witness_genesis_get(nodus_witness_t *w,
                                 nodus_witness_genesis_t *out);

/* ── Supply tracking ─────────────────────────────────────────────── */

typedef struct {
    uint64_t    genesis_supply;
    uint64_t    total_burned;
    uint64_t    current_supply;
    uint64_t    last_sequence;
} nodus_witness_supply_t;

int  nodus_witness_supply_init(nodus_witness_t *w, uint64_t total_supply,
                                 const uint8_t *genesis_tx_hash);
int  nodus_witness_supply_get(nodus_witness_t *w,
                                nodus_witness_supply_t *out);
int  nodus_witness_supply_add_burned(nodus_witness_t *w, uint64_t fee,
                                       const uint8_t *tx_hash);

/* ── Transaction history by owner ────────────────────────────────── */

#define NODUS_WITNESS_MAX_TX_OUTPUTS 8

typedef struct {
    char        owner_fp[129];
    uint64_t    amount;
    uint32_t    output_index;
} nodus_witness_tx_output_t;

typedef struct {
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     tx_type;
    char        sender_fp[129];
    uint64_t    fee;
    uint64_t    block_height;
    uint64_t    timestamp;
    nodus_witness_tx_output_t outputs[NODUS_WITNESS_MAX_TX_OUTPUTS];
    int         output_count;
} nodus_witness_tx_history_entry_t;

int  nodus_witness_tx_by_owner(nodus_witness_t *w, const char *owner_fp,
                                 nodus_witness_tx_history_entry_t *out,
                                 int max_entries, int *count_out);

/* ── TX output storage ──────────────────────────────────────────── */

int  nodus_witness_tx_output_add(nodus_witness_t *w, const uint8_t *tx_hash,
                                   uint32_t output_index, const char *owner_fp,
                                   uint64_t amount);

/* ── Committed transaction storage ───────────────────────────────── */

int  nodus_witness_tx_store(nodus_witness_t *w, const uint8_t *tx_hash,
                              uint8_t tx_type, const uint8_t *tx_data,
                              uint32_t tx_len, uint64_t block_height,
                              const char *sender_fp, uint64_t fee);
int  nodus_witness_tx_get(nodus_witness_t *w, const uint8_t *tx_hash,
                            uint8_t *tx_type_out, uint8_t **tx_data_out,
                            uint32_t *tx_len_out, uint64_t *block_height_out);

/* ── Commit certificate operations ──────────────────────────────── */

int  nodus_witness_cert_store(nodus_witness_t *w, uint64_t block_height,
                                const nodus_witness_vote_record_t *votes,
                                int vote_count);
int  nodus_witness_cert_get(nodus_witness_t *w, uint64_t block_height,
                              nodus_witness_vote_record_t *votes_out,
                              int max_votes, int *count_out);

/* ── DB transaction wrappers ─────────────────────────────────────── */

int  nodus_witness_db_begin(nodus_witness_t *w);
int  nodus_witness_db_commit(nodus_witness_t *w);
int  nodus_witness_db_rollback(nodus_witness_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DB_H */
