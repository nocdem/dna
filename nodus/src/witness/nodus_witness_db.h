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
                                uint64_t *amount_out, char *owner_out,
                                uint8_t *token_id_out);
int  nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height,
                              const uint8_t *token_id);
int  nodus_witness_utxo_remove(nodus_witness_t *w, const uint8_t *nullifier);
int  nodus_witness_utxo_count(nodus_witness_t *w, uint64_t *count_out);
int  nodus_witness_utxo_sum(nodus_witness_t *w, uint64_t *sum_out);

/**
 * Sum UTXO amounts for a specific token_id.
 * @param token_id  64-byte token ID (zeros = native DNAC, NULL = same as zeros)
 * @param sum_out   [out] Total amount for this token
 * @return 0 on success, -1 on error
 */
int  nodus_witness_utxo_sum_by_token(nodus_witness_t *w,
                                       const uint8_t *token_id,
                                       uint64_t *sum_out);

/* Phase 10 / Task 10.2 — nodus_witness_utxo_checksum DELETED.
 * State root computation now lives in nodus_witness_merkle.c as
 * nodus_witness_merkle_compute_utxo_root (RFC 6962 Merkle tree). */

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

/** Token list entry for query results */
typedef struct {
    uint8_t  token_id[64];
    char     name[64];
    char     symbol[16];
    uint8_t  decimals;
    uint64_t supply;
    char     creator_fp[129];
} nodus_witness_token_entry_t;

/**
 * List all registered tokens.
 *
 * @param w           Witness context
 * @param out         Output array (caller-allocated)
 * @param max_entries Array capacity
 * @param count_out   [out] Number of entries written
 * @return 0 on success, -1 on error
 */
int  nodus_witness_token_list(nodus_witness_t *w,
                                nodus_witness_token_entry_t *out,
                                int max_entries, int *count_out);

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
    uint8_t     tx_root[NODUS_T3_TX_HASH_LEN];     /* RFC 6962 Merkle root over the block's TX hashes */
    uint32_t    tx_count;                          /* Number of TXs the block carries */
    uint64_t    timestamp;
    uint8_t     proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     prev_hash[NODUS_T3_TX_HASH_LEN];   /* SHA3-512 of previous block header */
    uint8_t     state_root[NODUS_T3_TX_HASH_LEN];  /* SHA3-512 over the UTXO set after this block */
} nodus_witness_block_t;

/* nodus_witness_block_add — adds a finalized block row.
 *
 * Multi-tx block refactor (Phase 1 / Task 1.2):
 *   tx_root    — RFC 6962 Merkle root over the block's TX hashes (Phase 2
 *                introduces nodus_witness_merkle_tx_root which computes it).
 *   tx_count   — number of TXs in the block (1..NODUS_W_MAX_BLOCK_TXS).
 *
 * Per-TX type lives in committed_transactions.tx_type and is no longer
 * stored on the block row. */
int  nodus_witness_block_add(nodus_witness_t *w, const uint8_t *tx_root,
                               uint32_t tx_count, uint64_t timestamp,
                               const uint8_t *proposer_id,
                               const uint8_t *state_root);
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
#define NODUS_WITNESS_MEMO_MAX       256

typedef struct {
    char        owner_fp[129];
    uint64_t    amount;
    uint32_t    output_index;
    uint8_t     token_id[64];
    /* Memo attached to this output. Not persisted in the tx_outputs
     * table — re-parsed from the raw TX blob stored via
     * nodus_witness_tx_store() whenever a history query asks for it. */
    char        memo[NODUS_WITNESS_MEMO_MAX];
    uint8_t     memo_len;
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
                                   uint64_t amount, const uint8_t *token_id);

/* ── Committed transaction storage ───────────────────────────────── */

int  nodus_witness_tx_store(nodus_witness_t *w, const uint8_t *tx_hash,
                              uint8_t tx_type, const uint8_t *tx_data,
                              uint32_t tx_len, uint64_t block_height,
                              const char *sender_fp, uint64_t fee,
                              const uint8_t *client_pubkey,
                              const uint8_t *client_sig);
int  nodus_witness_tx_get(nodus_witness_t *w, const uint8_t *tx_hash,
                            uint8_t *tx_type_out, uint8_t **tx_data_out,
                            uint32_t *tx_len_out, uint64_t *block_height_out);

/* Lookup (block_height, tx_index) for a committed tx_hash — used by
 * dnac_spend_replay to reconstruct a fresh spndrslt receipt without
 * pulling the tx_data blob. Returns 0 on found, -1 otherwise. */
int  nodus_witness_get_committed_coords(nodus_witness_t *w,
                                         const uint8_t *tx_hash,
                                         uint64_t *block_height_out,
                                         uint32_t *tx_index_out);

/* Phase 11 / Task 11.1 — multi-tx block fetch.
 *
 * Single TX-row fetched from committed_transactions ordered by tx_index.
 * tx_data is heap-allocated; caller frees each entry via
 * nodus_witness_block_tx_row_free(). */
typedef struct {
    uint8_t   tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t   tx_type;
    uint8_t  *tx_data;
    uint32_t  tx_len;
    /* Phase 11 follow-up — heap-allocated client_pubkey + client_sig
     * if present in committed_transactions, NULL otherwise. Sync replay
     * serves zero pad when NULL. */
    uint8_t  *client_pubkey;   /* NODUS_PK_BYTES if non-NULL */
    uint8_t  *client_sig;      /* NODUS_SIG_BYTES if non-NULL */
} nodus_witness_block_tx_row_t;

/** Free heap fields on a single block_tx_row. Idempotent on NULL. */
void nodus_witness_block_tx_row_free(nodus_witness_block_tx_row_t *row);

/**
 * Fetch all committed TXs for a given block_height, ordered by
 * tx_index. The caller passes a fixed-size array (NODUS_W_MAX_BLOCK_TXS
 * is the natural ceiling) and the function fills it up to
 * max_entries.
 *
 * On success, *count_out is the number of rows populated. Each row's
 * tx_data is malloc'd; the caller MUST free each via
 * nodus_witness_block_tx_row_free() (or rely on a sweep wrapper).
 *
 * Returns 0 on success, -1 on DB error.
 */
int  nodus_witness_block_txs_get(nodus_witness_t *w, uint64_t block_height,
                                   nodus_witness_block_tx_row_t *out,
                                   int max_entries, int *count_out);

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

/* Savepoint wrappers (Phase 0 / Task 0.15).
 *
 * Required by Phase 6 commit_batch attribution replay (Task 6.2): when a
 * multi-tx batch's finalize_block fails, the attribution loop replays each
 * TX in isolation under a savepoint to identify which one violated the
 * supply invariant.
 *
 * Caller is responsible for ensuring `name` is a valid SQL identifier
 * (alphanumeric + underscores). Names are inlined into the generated SQL —
 * SQLite SAVEPOINT does not accept parameter binding.
 */
int  nodus_witness_db_savepoint(nodus_witness_t *w, const char *name);
int  nodus_witness_db_rollback_to_savepoint(nodus_witness_t *w, const char *name);

/* Block hash computation (Phase 5 / Task 5.1).
 *
 * Pure function — no DB access. Computes the canonical block hash
 * preimage and returns its SHA3-512 digest. Single source of truth
 * for both the block-add path (writes the hash) and the sync path
 * (recomputes the hash to verify a peer's block).
 *
 * Preimage layout (244 bytes, little-endian per project convention):
 *   height(8) || prev_hash(64) || state_root(64) || tx_root(64)
 *            || tx_count(4)   || timestamp(8)   || proposer_id(32)
 *
 * Caller passes every field by value — the helper does NOT touch any
 * witness state. This makes it trivial to unit-test and lets sync
 * verifications happen without a live witness DB.
 */
void nodus_witness_compute_block_hash(uint64_t height,
                                       const uint8_t prev_hash[64],
                                       const uint8_t state_root[64],
                                       const uint8_t tx_root[64],
                                       uint32_t tx_count,
                                       uint64_t timestamp,
                                       const uint8_t proposer_id[32],
                                       uint8_t out[64]);

/* Schema migration umbrella (Phase 1 / Task 1.1, originally named v12).
 *
 * Runs all additive schema migrations in order:
 *   - v12: tx_index column + composite idx_ctx_block index on
 *          committed_transactions (multi-tx block refactor)
 *   - v13: client_pubkey + client_sig columns on committed_transactions
 *          (Phase 11 client binding)
 *   - v14: chain_def_blob column on blocks (Phase 2 / Task 7 — anchored
 *          merkle proofs; NULL on non-genesis blocks)
 *
 * Idempotent: safe to run on a fresh DB or on a DB that already has any
 * of the above shapes. Returns 0 on success. On unrecoverable SQLite
 * error the function triggers WITNESS_DB_MIGRATION_FATAL (logs
 * MIGRATION FAILURE then abort()), so callers can assume success on
 * return.
 */
int  nodus_witness_db_migrate_v12(nodus_witness_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DB_H */
