/**
 * Nodus — Witness Database Layer Implementation
 *
 * Consolidated SQLite operations for DNAC witness state.
 * Ported from dnac/src/witness/{nullifier,ledger,utxo_set,block}.c
 *
 * Key differences from DNAC originals:
 * - All functions take nodus_witness_t* instead of void* user_data
 * - Uses witness->db instead of global sqlite3* handles
 * - Single-zone (no zone.c abstraction)
 * - Uses fprintf logging (nodus convention)
 * - Simplified ledger (no Merkle tree — proof generation deferred)
 */

#include "witness/nodus_witness_db.h"
#include "crypto/nodus_sign.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS_DB"

/* ── Nullifier operations ────────────────────────────────────────── */

bool nodus_witness_nullifier_exists(nodus_witness_t *w, const uint8_t *nullifier) {
    /* HIGH-10: Fail-closed — DB errors assume spent to prevent double-spend */
    if (!w || !w->db || !nullifier) return true;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM nullifiers WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: nullifier query prepare failed - assuming spent (fail-closed)\n",
                LOG_TAG);
        return true;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

int nodus_witness_nullifier_add(nodus_witness_t *w, const uint8_t *nullifier,
                                  const uint8_t *tx_hash) {
    if (!w || !w->db || !nullifier || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO nullifiers (nullifier, tx_hash, added_at) "
        "VALUES (?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: nullifier insert prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: nullifier insert failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* ── UTXO set operations ─────────────────────────────────────────── */

int nodus_witness_utxo_lookup(nodus_witness_t *w, const uint8_t *nullifier,
                                uint64_t *amount_out, char *owner_out,
                                uint8_t *token_id_out) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT amount, owner, token_id FROM utxo_set WHERE nullifier = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (amount_out)
        *amount_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    if (owner_out) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) {
            strncpy(owner_out, fp, 128);
            owner_out[128] = '\0';
        }
    }

    if (token_id_out) {
        const void *tid = sqlite3_column_blob(stmt, 2);
        int tid_len = sqlite3_column_bytes(stmt, 2);
        if (tid && tid_len >= 64) {
            memcpy(token_id_out, tid, 64);
        } else {
            memset(token_id_out, 0, 64);  /* Default: native DNAC */
        }
    }

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height,
                              const uint8_t *token_id) {
    if (!w || !w->db || !nullifier || !owner || !tx_hash) return -1;

    /* Default to native DNAC (64 zero bytes) when token_id is NULL */
    static const uint8_t zero_token[64] = {0};
    const uint8_t *tid = token_id ? token_id : zero_token;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO utxo_set "
        "(nullifier, owner, amount, token_id, tx_hash, output_index, block_height, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: utxo add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)amount);
    sqlite3_bind_blob(stmt, 4, tid, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, (int)index);
    sqlite3_bind_int64(stmt, 7, (int64_t)block_height);
    sqlite3_bind_int64(stmt, 8, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: utxo add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

int nodus_witness_utxo_remove(nodus_witness_t *w, const uint8_t *nullifier) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "DELETE FROM utxo_set WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(w->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;
    if (changes == 0) return -1;  /* Not found */
    return 0;
}

int nodus_witness_utxo_count(nodus_witness_t *w, uint64_t *count_out) {
    if (!w || !w->db || !count_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COUNT(*) FROM utxo_set", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    if (sqlite3_step(stmt) == SQLITE_ROW)
        *count_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_sum(nodus_witness_t *w, uint64_t *sum_out) {
    if (!w || !w->db || !sum_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COALESCE(SUM(amount), 0) FROM utxo_set", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *sum_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_sum_by_token(nodus_witness_t *w,
                                       const uint8_t *token_id,
                                       uint64_t *sum_out) {
    if (!w || !w->db || !sum_out) return -1;

    /* NULL token_id or all-zeros = native DNAC */
    uint8_t zeros[64];
    memset(zeros, 0, sizeof(zeros));
    const uint8_t *tid = token_id ? token_id : zeros;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COALESCE(SUM(amount), 0) FROM utxo_set WHERE token_id = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tid, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *sum_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_checksum(nodus_witness_t *w, uint8_t *checksum_out) {
    if (!w || !w->db || !checksum_out) return -1;

    /* Query all UTXO nullifiers in sorted order */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT nullifier FROM utxo_set ORDER BY nullifier ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: utxo checksum prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    /* Incrementally hash all nullifiers using SHA3-512 */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) { sqlite3_finalize(stmt); return -1; }

    if (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(md);
        sqlite3_finalize(stmt);
        return -1;
    }

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blen = sqlite3_column_bytes(stmt, 0);
        if (blob && blen == NODUS_T3_NULLIFIER_LEN) {
            EVP_DigestUpdate(md, blob, NODUS_T3_NULLIFIER_LEN);
            count++;
        }
    }
    sqlite3_finalize(stmt);

    /* If no UTXOs, hash empty input (deterministic zero-state) */
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(md, checksum_out, &hash_len) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    EVP_MD_CTX_free(md);

    return 0;
}

int nodus_witness_utxo_by_owner(nodus_witness_t *w, const char *owner,
                                   nodus_witness_utxo_entry_t *out,
                                   int max_entries, int *count_out) {
    if (!w || !w->db || !owner || !out || !count_out || max_entries <= 0)
        return -1;

    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, block_height "
        "FROM utxo_set WHERE owner = ? LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        nodus_witness_utxo_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        const void *blob;
        int blen;

        blob = sqlite3_column_blob(stmt, 0);
        blen = sqlite3_column_bytes(stmt, 0);
        if (blob && blen == NODUS_T3_NULLIFIER_LEN)
            memcpy(e->nullifier, blob, NODUS_T3_NULLIFIER_LEN);

        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) { strncpy(e->owner, fp, sizeof(e->owner) - 1); }

        e->amount = (uint64_t)sqlite3_column_int64(stmt, 2);

        blob = sqlite3_column_blob(stmt, 3);
        blen = sqlite3_column_bytes(stmt, 3);
        if (blob && blen == 64)
            memcpy(e->token_id, blob, 64);

        blob = sqlite3_column_blob(stmt, 4);
        blen = sqlite3_column_bytes(stmt, 4);
        if (blob && blen == NODUS_T3_TX_HASH_LEN)
            memcpy(e->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

        e->output_index = (uint32_t)sqlite3_column_int(stmt, 5);
        e->block_height = (uint64_t)sqlite3_column_int64(stmt, 6);
        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── Ledger operations ───────────────────────────────────────────── */

int nodus_witness_ledger_add(nodus_witness_t *w, const uint8_t *tx_hash,
                                uint8_t tx_type, uint8_t nullifier_count) {
    if (!w || !w->db || !tx_hash) return -1;

    uint64_t now = (uint64_t)time(NULL);
    uint64_t epoch = now / NODUS_T3_EPOCH_DURATION_SEC;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO ledger_entries (tx_hash, tx_type, epoch, timestamp, nullifier_count) "
        "VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ledger add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, tx_type);
    sqlite3_bind_int64(stmt, 3, (int64_t)epoch);
    sqlite3_bind_int64(stmt, 4, (int64_t)now);
    sqlite3_bind_int(stmt, 5, nullifier_count);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: ledger add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

static int ledger_from_row(sqlite3_stmt *stmt, nodus_witness_ledger_entry_t *out) {
    memset(out, 0, sizeof(*out));
    out->sequence = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

    out->tx_type = (uint8_t)sqlite3_column_int(stmt, 2);
    out->epoch = (uint64_t)sqlite3_column_int64(stmt, 3);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 4);
    out->nullifier_count = (uint8_t)sqlite3_column_int(stmt, 5);
    return 0;
}

int nodus_witness_ledger_get(nodus_witness_t *w, uint64_t seq,
                                nodus_witness_ledger_entry_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT sequence, tx_hash, tx_type, epoch, timestamp, nullifier_count "
        "FROM ledger_entries WHERE sequence = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)seq);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    ledger_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_ledger_get_by_hash(nodus_witness_t *w, const uint8_t *tx_hash,
                                        nodus_witness_ledger_entry_t *out) {
    if (!w || !w->db || !tx_hash || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT sequence, tx_hash, tx_type, epoch, timestamp, nullifier_count "
        "FROM ledger_entries WHERE tx_hash = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    ledger_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_ledger_get_range(nodus_witness_t *w, uint64_t from, uint64_t to,
                                      nodus_witness_ledger_entry_t *out,
                                      int max_entries, int *count_out) {
    if (!w || !w->db || !out || !count_out || max_entries <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT sequence, tx_hash, tx_type, epoch, timestamp, nullifier_count "
        "FROM ledger_entries WHERE sequence >= ? AND sequence <= ? "
        "ORDER BY sequence ASC LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)from);
    sqlite3_bind_int64(stmt, 2, (int64_t)to);
    sqlite3_bind_int(stmt, 3, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        ledger_from_row(stmt, &out[count]);
        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

uint64_t nodus_witness_ledger_count(nodus_witness_t *w) {
    if (!w || !w->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COUNT(*) FROM ledger_entries", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    uint64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return count;
}

/* ── Block operations ────────────────────────────────────────────── */

int nodus_witness_block_add(nodus_witness_t *w, const uint8_t *tx_hash,
                               uint8_t tx_type, uint64_t timestamp,
                               const uint8_t *proposer_id) {
    if (!w || !w->db || !tx_hash) return -1;

    /* Compute prev_hash = SHA3-512(height || tx_hash || timestamp || prev_hash) of latest block */
    uint8_t prev_hash[NODUS_T3_TX_HASH_LEN] = {0};
    nodus_witness_block_t prev_block;
    if (nodus_witness_block_get_latest(w, &prev_block) == 0) {
        uint8_t hash_input[8 + NODUS_T3_TX_HASH_LEN + 8 + NODUS_T3_TX_HASH_LEN];
        size_t off = 0;
        memcpy(hash_input + off, &prev_block.height, 8);    off += 8;
        memcpy(hash_input + off, prev_block.tx_hash, NODUS_T3_TX_HASH_LEN); off += NODUS_T3_TX_HASH_LEN;
        memcpy(hash_input + off, &prev_block.timestamp, 8); off += 8;
        memcpy(hash_input + off, prev_block.prev_hash, NODUS_T3_TX_HASH_LEN); off += NODUS_T3_TX_HASH_LEN;

        unsigned int hash_len = 0;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
        EVP_DigestUpdate(mdctx, hash_input, off);
        EVP_DigestFinal_ex(mdctx, prev_hash, &hash_len);
        EVP_MD_CTX_free(mdctx);
    }
    /* Genesis block: prev_hash stays all zeros */

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO blocks (tx_hash, tx_type, timestamp, proposer_id, prev_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: block add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, tx_type);
    sqlite3_bind_int64(stmt, 3, (int64_t)timestamp);
    if (proposer_id)
        sqlite3_bind_blob(stmt, 4, proposer_id, NODUS_T3_WITNESS_ID_LEN, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 4);
    sqlite3_bind_blob(stmt, 5, prev_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: block add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

static int block_from_row(sqlite3_stmt *stmt, nodus_witness_block_t *out) {
    memset(out, 0, sizeof(*out));
    out->height = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

    out->tx_type = (uint8_t)sqlite3_column_int(stmt, 2);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 3);

    blob = sqlite3_column_blob(stmt, 4);
    blen = sqlite3_column_bytes(stmt, 4);
    if (blob && blen == NODUS_T3_WITNESS_ID_LEN)
        memcpy(out->proposer_id, blob, NODUS_T3_WITNESS_ID_LEN);

    blob = sqlite3_column_blob(stmt, 5);
    blen = sqlite3_column_bytes(stmt, 5);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->prev_hash, blob, NODUS_T3_TX_HASH_LEN);

    return 0;
}

int nodus_witness_block_get(nodus_witness_t *w, uint64_t height,
                               nodus_witness_block_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_hash, tx_type, timestamp, proposer_id, prev_hash "
        "FROM blocks WHERE height = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)height);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_block_get_latest(nodus_witness_t *w,
                                      nodus_witness_block_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_hash, tx_type, timestamp, proposer_id, prev_hash "
        "FROM blocks ORDER BY height DESC LIMIT 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_block_get_range(nodus_witness_t *w,
                                      uint64_t from_height, uint64_t to_height,
                                      nodus_witness_block_t *out,
                                      int max_entries, int *count_out) {
    if (!w || !w->db || !out || !count_out || max_entries <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_hash, tx_type, timestamp, proposer_id, prev_hash "
        "FROM blocks WHERE height >= ? AND height <= ? "
        "ORDER BY height ASC LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)from_height);
    sqlite3_bind_int64(stmt, 2, (int64_t)to_height);
    sqlite3_bind_int(stmt, 3, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        block_from_row(stmt, &out[count]);
        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

uint64_t nodus_witness_block_height(nodus_witness_t *w) {
    if (!w || !w->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT MAX(height) FROM blocks", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    uint64_t height = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        height = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return height;
}

/* ── Genesis state ───────────────────────────────────────────────── */

bool nodus_witness_genesis_exists(nodus_witness_t *w) {
    if (!w || !w->db) return false;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM genesis_state WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

int nodus_witness_genesis_set(nodus_witness_t *w, const uint8_t *tx_hash,
                                 uint64_t total_supply,
                                 const uint8_t *commitment) {
    if (!w || !w->db || !tx_hash) return -1;

    if (nodus_witness_genesis_exists(w)) {
        fprintf(stderr, "%s: genesis already exists\n", LOG_TAG);
        return -2;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO genesis_state (id, tx_hash, total_supply, commitment, created_at) "
        "VALUES (1, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    if (commitment)
        sqlite3_bind_blob(stmt, 3, commitment, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    fprintf(stderr, "%s: genesis recorded: supply=%llu\n",
            LOG_TAG, (unsigned long long)total_supply);
    return 0;
}

int nodus_witness_genesis_get(nodus_witness_t *w,
                                 nodus_witness_genesis_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT tx_hash, total_supply, created_at "
        "FROM genesis_state WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    const void *blob = sqlite3_column_blob(stmt, 0);
    int blen = sqlite3_column_bytes(stmt, 0);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

    out->total_supply = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 2);

    sqlite3_finalize(stmt);
    return 0;
}

/* ── Supply tracking ─────────────────────────────────────────────── */

int nodus_witness_supply_init(nodus_witness_t *w, uint64_t total_supply,
                                 const uint8_t *genesis_tx_hash) {
    if (!w || !w->db || !genesis_tx_hash) return -1;

    /* Check if already initialized */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  /* Already initialized */
    }
    sqlite3_finalize(stmt);

    /* Need the supply_tracking table */
    sqlite3_exec(w->db,
        "CREATE TABLE IF NOT EXISTS supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");", NULL, NULL, NULL);

    rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "current_supply, last_tx_hash, last_sequence) VALUES (1, ?, 0, ?, ?, 1)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)total_supply);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    sqlite3_bind_blob(stmt, 3, genesis_tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int nodus_witness_supply_get(nodus_witness_t *w,
                                nodus_witness_supply_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT genesis_supply, total_burned, current_supply, last_sequence "
        "FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->genesis_supply = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->total_burned = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->current_supply = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->last_sequence = (uint64_t)sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_supply_add_burned(nodus_witness_t *w, uint64_t fee,
                                       const uint8_t *tx_hash) {
    if (!w || !w->db || fee == 0) return 0;
    if (!tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE supply_tracking SET total_burned = total_burned + ?, "
        "current_supply = current_supply - ?, last_tx_hash = ?, "
        "last_sequence = last_sequence + 1 WHERE id = 1",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)fee);
    sqlite3_bind_int64(stmt, 2, (int64_t)fee);
    sqlite3_bind_blob(stmt, 3, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    if (sqlite3_changes(w->db) != 1) return -1;  /* supply_tracking row missing */
    return 0;
}

/* ── Transaction history by owner ────────────────────────────────── */

int nodus_witness_tx_by_owner(nodus_witness_t *w, const char *owner_fp,
                                 nodus_witness_tx_history_entry_t *out,
                                 int max_entries, int *count_out) {
    if (!w || !w->db || !owner_fp || !out || !count_out || max_entries <= 0)
        return -1;

    *count_out = 0;

    /* Step 1: Find distinct TX hashes where owner is sender or output owner.
     * JOIN committed_transactions with tx_outputs to match on either side. */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT DISTINCT t.tx_hash, t.tx_type, t.sender_fp, t.fee, "
        "t.block_height, t.timestamp "
        "FROM committed_transactions t "
        "LEFT JOIN tx_outputs o ON o.tx_hash = t.tx_hash "
        "WHERE t.sender_fp = ? OR o.owner_fp = ? "
        "ORDER BY t.timestamp DESC LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, owner_fp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        nodus_witness_tx_history_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        const void *blob = sqlite3_column_blob(stmt, 0);
        int blen = sqlite3_column_bytes(stmt, 0);
        if (blob && blen == NODUS_T3_TX_HASH_LEN)
            memcpy(e->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

        e->tx_type = (uint8_t)sqlite3_column_int(stmt, 1);

        const char *sfp = (const char *)sqlite3_column_text(stmt, 2);
        if (sfp) strncpy(e->sender_fp, sfp, 128);

        e->fee          = (uint64_t)sqlite3_column_int64(stmt, 3);
        e->block_height = (uint64_t)sqlite3_column_int64(stmt, 4);
        e->timestamp    = (uint64_t)sqlite3_column_int64(stmt, 5);
        count++;
    }
    sqlite3_finalize(stmt);

    /* Step 2: For each TX, fetch its outputs from tx_outputs */
    for (int i = 0; i < count; i++) {
        sqlite3_stmt *ostmt;
        rc = sqlite3_prepare_v2(w->db,
            "SELECT output_index, owner_fp, amount, token_id FROM tx_outputs "
            "WHERE tx_hash = ? ORDER BY output_index ASC", -1, &ostmt, NULL);
        if (rc != SQLITE_OK) continue;

        sqlite3_bind_blob(ostmt, 1, out[i].tx_hash,
                           NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

        int oc = 0;
        while (sqlite3_step(ostmt) == SQLITE_ROW &&
               oc < NODUS_WITNESS_MAX_TX_OUTPUTS) {
            nodus_witness_tx_output_t *o = &out[i].outputs[oc];
            o->output_index = (uint32_t)sqlite3_column_int(ostmt, 0);
            const char *ofp = (const char *)sqlite3_column_text(ostmt, 1);
            if (ofp) strncpy(o->owner_fp, ofp, 128);
            o->amount = (uint64_t)sqlite3_column_int64(ostmt, 2);
            const void *tid_blob = sqlite3_column_blob(ostmt, 3);
            int tid_len = sqlite3_column_bytes(ostmt, 3);
            if (tid_blob && tid_len == 64)
                memcpy(o->token_id, tid_blob, 64);
            oc++;
        }
        out[i].output_count = oc;
        sqlite3_finalize(ostmt);
    }

    *count_out = count;
    return 0;
}

/* ── TX output storage ──────────────────────────────────────────── */

int nodus_witness_tx_output_add(nodus_witness_t *w, const uint8_t *tx_hash,
                                   uint32_t output_index, const char *owner_fp,
                                   uint64_t amount, const uint8_t *token_id) {
    if (!w || !w->db || !tx_hash || !owner_fp) return -1;

    /* NULL token_id → native DNAC (all zeros) */
    static const uint8_t zero_token[64] = {0};
    const uint8_t *tid = token_id ? token_id : zero_token;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO tx_outputs "
        "(tx_hash, output_index, owner_fp, amount, token_id) "
        "VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)output_index);
    sqlite3_bind_text(stmt, 3, owner_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (int64_t)amount);
    sqlite3_bind_blob(stmt, 5, tid, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ── Committed transaction storage ───────────────────────────────── */

int nodus_witness_tx_store(nodus_witness_t *w, const uint8_t *tx_hash,
                              uint8_t tx_type, const uint8_t *tx_data,
                              uint32_t tx_len, uint64_t block_height,
                              const char *sender_fp, uint64_t fee) {
    if (!w || !w->db || !tx_hash || !tx_data || tx_len == 0) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO committed_transactions "
        "(tx_hash, tx_type, tx_data, tx_len, block_height, timestamp, "
        "sender_fp, fee) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: tx_store prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, tx_type);
    sqlite3_bind_blob(stmt, 3, tx_data, (int)tx_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, (int)tx_len);
    sqlite3_bind_int64(stmt, 5, (int64_t)block_height);
    sqlite3_bind_int64(stmt, 6, (int64_t)time(NULL));

    if (sender_fp && sender_fp[0])
        sqlite3_bind_text(stmt, 7, sender_fp, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 7);

    sqlite3_bind_int64(stmt, 8, (int64_t)fee);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: tx_store failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

int nodus_witness_tx_get(nodus_witness_t *w, const uint8_t *tx_hash,
                            uint8_t *tx_type_out, uint8_t **tx_data_out,
                            uint32_t *tx_len_out, uint64_t *block_height_out) {
    if (!w || !w->db || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT tx_type, tx_data, tx_len, block_height "
        "FROM committed_transactions WHERE tx_hash = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (tx_type_out)
        *tx_type_out = (uint8_t)sqlite3_column_int(stmt, 0);

    int blob_len = sqlite3_column_bytes(stmt, 1);
    const void *blob = sqlite3_column_blob(stmt, 1);

    if (tx_data_out && blob && blob_len > 0) {
        *tx_data_out = malloc((size_t)blob_len);
        if (*tx_data_out)
            memcpy(*tx_data_out, blob, (size_t)blob_len);
    }

    if (tx_len_out)
        *tx_len_out = (uint32_t)sqlite3_column_int(stmt, 2);

    if (block_height_out)
        *block_height_out = (uint64_t)sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return 0;
}

/* ── Commit certificate operations ──────────────────────────────── */

int nodus_witness_cert_store(nodus_witness_t *w, uint64_t block_height,
                               const nodus_witness_vote_record_t *votes,
                               int vote_count) {
    if (!w || !w->db || !votes) return -1;

    for (int i = 0; i < vote_count; i++) {
        if (votes[i].vote != NODUS_W_VOTE_APPROVE) continue;

        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(w->db,
            "INSERT OR IGNORE INTO commit_certificates "
            "(block_height, voter_id, vote, signature) VALUES (?, ?, ?, ?)",
            -1, &stmt, NULL);
        if (rc != SQLITE_OK) return -1;

        sqlite3_bind_int64(stmt, 1, (int64_t)block_height);
        sqlite3_bind_blob(stmt, 2, votes[i].voter_id,
                          NODUS_T3_WITNESS_ID_LEN, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, votes[i].vote);
        sqlite3_bind_blob(stmt, 4, votes[i].signature,
                          NODUS_SIG_BYTES, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

int nodus_witness_cert_get(nodus_witness_t *w, uint64_t block_height,
                             nodus_witness_vote_record_t *votes_out,
                             int max_votes, int *count_out) {
    if (!w || !w->db || !votes_out || !count_out) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT voter_id, vote, signature FROM commit_certificates "
        "WHERE block_height = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)block_height);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_votes) {
        const void *vid = sqlite3_column_blob(stmt, 0);
        int vid_len = sqlite3_column_bytes(stmt, 0);
        if (vid && vid_len == NODUS_T3_WITNESS_ID_LEN)
            memcpy(votes_out[count].voter_id, vid, NODUS_T3_WITNESS_ID_LEN);

        votes_out[count].vote = (nodus_witness_vote_t)sqlite3_column_int(stmt, 1);

        const void *sig = sqlite3_column_blob(stmt, 2);
        int sig_len = sqlite3_column_bytes(stmt, 2);
        if (sig && sig_len == NODUS_SIG_BYTES)
            memcpy(votes_out[count].signature, sig, NODUS_SIG_BYTES);

        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── Token registry operations ──────────────────────────────────── */

int nodus_witness_token_add(nodus_witness_t *w, const uint8_t *token_id,
                               const char *name, const char *symbol,
                               uint8_t decimals, uint64_t supply,
                               const char *creator_fp, uint8_t flags,
                               uint64_t block_height) {
    if (!w || !w->db || !token_id || !name || !symbol || !creator_fp)
        return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO tokens "
        "(token_id, name, symbol, decimals, supply, creator_fp, flags, "
        "block_height, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: token add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, token_id, 64, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, symbol, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, decimals);
    sqlite3_bind_int64(stmt, 5, (int64_t)supply);
    sqlite3_bind_text(stmt, 6, creator_fp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, flags);
    sqlite3_bind_int64(stmt, 8, (int64_t)block_height);
    sqlite3_bind_int64(stmt, 9, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: token add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

int nodus_witness_token_exists(nodus_witness_t *w, const uint8_t *token_id) {
    if (!w || !w->db || !token_id) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM tokens WHERE token_id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_blob(stmt, 1, token_id, 64, SQLITE_STATIC);
    int exists = (sqlite3_step(stmt) == SQLITE_ROW) ? 1 : 0;
    sqlite3_finalize(stmt);
    return exists;
}

int nodus_witness_token_get(nodus_witness_t *w, const uint8_t *token_id,
                               char *name_out, char *symbol_out,
                               uint8_t *decimals_out, uint64_t *supply_out,
                               char *creator_fp_out) {
    if (!w || !w->db || !token_id) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT name, symbol, decimals, supply, creator_fp "
        "FROM tokens WHERE token_id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, token_id, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (name_out) {
        const char *n = (const char *)sqlite3_column_text(stmt, 0);
        if (n) { strncpy(name_out, n, 63); name_out[63] = '\0'; }
    }
    if (symbol_out) {
        const char *s = (const char *)sqlite3_column_text(stmt, 1);
        if (s) { strncpy(symbol_out, s, 15); symbol_out[15] = '\0'; }
    }
    if (decimals_out)
        *decimals_out = (uint8_t)sqlite3_column_int(stmt, 2);
    if (supply_out)
        *supply_out = (uint64_t)sqlite3_column_int64(stmt, 3);
    if (creator_fp_out) {
        const char *c = (const char *)sqlite3_column_text(stmt, 4);
        if (c) { strncpy(creator_fp_out, c, 128); creator_fp_out[128] = '\0'; }
    }

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_token_list(nodus_witness_t *w,
                               nodus_witness_token_entry_t *out,
                               int max_entries, int *count_out) {
    if (!w || !w->db || !out || !count_out) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT token_id, name, symbol, decimals, supply, creator_fp "
        "FROM tokens ORDER BY rowid LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        nodus_witness_token_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        const void *tid = sqlite3_column_blob(stmt, 0);
        int tid_len = sqlite3_column_bytes(stmt, 0);
        if (tid && tid_len == 64)
            memcpy(e->token_id, tid, 64);

        const char *n = (const char *)sqlite3_column_text(stmt, 1);
        if (n) { strncpy(e->name, n, sizeof(e->name) - 1); }

        const char *s = (const char *)sqlite3_column_text(stmt, 2);
        if (s) { strncpy(e->symbol, s, sizeof(e->symbol) - 1); }

        e->decimals = (uint8_t)sqlite3_column_int(stmt, 3);
        e->supply = (uint64_t)sqlite3_column_int64(stmt, 4);

        const char *c = (const char *)sqlite3_column_text(stmt, 5);
        if (c) { strncpy(e->creator_fp, c, sizeof(e->creator_fp) - 1); }

        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── DB transaction wrappers ─────────────────────────────────────── */

int nodus_witness_db_begin(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "BEGIN TRANSACTION", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: BEGIN failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_commit(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "COMMIT", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: COMMIT failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_rollback(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ROLLBACK failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}
