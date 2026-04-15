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

/*
 * Pinned migration failure log literal for rollback trigger #9.
 * Phase 1.1 will introduce a real schema migration path that invokes this
 * macro from every ALTER/CREATE step. The literal MIGRATION FAILURE is the
 * exact pattern operators grep journalctl for when deciding whether to roll
 * back a deploy. Keep this macro in sync with nodus/docs/DEPLOY_RUNBOOK.md.
 */
#define WITNESS_DB_MIGRATION_FATAL(step_name, rc)                                  \
    do {                                                                           \
        fprintf(stderr, "MIGRATION FAILURE: %s failed with sqlite error %d: %s\n", \
                (step_name), (int)(rc), sqlite3_errmsg(w->db));                    \
        abort();                                                                   \
    } while (0)

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

/* Phase 10 / Task 10.2 — nodus_witness_utxo_checksum DELETED. Replaced
 * by the RFC 6962 nodus_witness_merkle_compute_utxo_root in
 * nodus_witness_merkle.c. */

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

int nodus_witness_block_add(nodus_witness_t *w, const uint8_t *tx_root,
                               uint32_t tx_count, uint64_t timestamp,
                               const uint8_t *proposer_id,
                               const uint8_t *state_root) {
    if (!w || !w->db || !tx_root || !state_root) return -1;

    /* Phase 5 / Task 5.2: prev_hash via the shared compute_block_hash
     * helper. Single source of truth with nodus_witness_sync.c. */
    uint8_t prev_hash[NODUS_T3_TX_HASH_LEN] = {0};
    nodus_witness_block_t prev_block;
    if (nodus_witness_block_get_latest(w, &prev_block) == 0) {
        nodus_witness_compute_block_hash(prev_block.height,
                                          prev_block.prev_hash,
                                          prev_block.state_root,
                                          prev_block.tx_root,
                                          prev_block.tx_count,
                                          prev_block.timestamp,
                                          prev_block.proposer_id,
                                          prev_hash);
    }
    /* Genesis block: prev_hash stays all zeros */

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO blocks (tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: block add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_root, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)tx_count);
    sqlite3_bind_int64(stmt, 3, (int64_t)timestamp);
    if (proposer_id)
        sqlite3_bind_blob(stmt, 4, proposer_id, NODUS_T3_WITNESS_ID_LEN, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 4);
    sqlite3_bind_blob(stmt, 5, prev_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, state_root, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: block add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* SELECT column order is: height, tx_root, tx_count, timestamp,
 * proposer_id, prev_hash, state_root. Schema v12 (Phase 1 / Task 1.2)
 * dropped the legacy tx_type column from blocks; per-TX type now lives
 * on committed_transactions. */
static int block_from_row(sqlite3_stmt *stmt, nodus_witness_block_t *out) {
    memset(out, 0, sizeof(*out));
    out->height = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_root, blob, NODUS_T3_TX_HASH_LEN);

    out->tx_count = (uint32_t)sqlite3_column_int(stmt, 2);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 3);

    blob = sqlite3_column_blob(stmt, 4);
    blen = sqlite3_column_bytes(stmt, 4);
    if (blob && blen == NODUS_T3_WITNESS_ID_LEN)
        memcpy(out->proposer_id, blob, NODUS_T3_WITNESS_ID_LEN);

    blob = sqlite3_column_blob(stmt, 5);
    blen = sqlite3_column_bytes(stmt, 5);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->prev_hash, blob, NODUS_T3_TX_HASH_LEN);

    blob = sqlite3_column_blob(stmt, 6);
    blen = sqlite3_column_bytes(stmt, 6);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->state_root, blob, NODUS_T3_TX_HASH_LEN);

    return 0;
}

int nodus_witness_block_get(nodus_witness_t *w, uint64_t height,
                               nodus_witness_block_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root "
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
        "SELECT height, tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root "
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
        "SELECT height, tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root "
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

/* Parse memos out of a raw committed TX blob and stamp them onto the
 * outputs of `entry` by matching output_index. Silently tolerates
 * malformed blobs — missing memo leaves output memo_len at 0. Blob
 * layout mirrors the writer in nodus_witness_bft.c (TX wire format).
 */
static void fill_memos_from_raw_tx(nodus_witness_t *w,
                                    nodus_witness_tx_history_entry_t *entry) {
    if (!w || !entry) return;

    uint8_t tx_type = 0;
    uint8_t *tx_data = NULL;
    uint32_t tx_len = 0;
    uint64_t bh = 0;
    if (nodus_witness_tx_get(w, entry->tx_hash, &tx_type, &tx_data,
                              &tx_len, &bh) != 0 || !tx_data || tx_len < 75) {
        free(tx_data);
        return;
    }

    size_t off = 74; /* header: version+type+timestamp+tx_hash */
    if (off >= tx_len) { free(tx_data); return; }
    uint8_t in_count = tx_data[off++];
    off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
    if (off >= tx_len) { free(tx_data); return; }

    uint8_t out_count = tx_data[off++];
    for (int oi = 0; oi < out_count; oi++) {
        if (off + 235 > tx_len) break;
        off += 1;     /* version */
        off += 129;   /* fingerprint */
        off += 8;     /* amount */
        off += 64;    /* token_id */
        off += 32;    /* seed */
        if (off >= tx_len) break;
        uint8_t ml = tx_data[off++];
        if (off + ml > tx_len) break;

        /* Match output_index to entry->outputs[] and copy memo. The
         * tx_outputs SELECT orders by output_index ASC and uses oi as
         * the raw blob index, so the on-chain output_index equals the
         * parse position `oi`. */
        for (int k = 0; k < entry->output_count; k++) {
            if (entry->outputs[k].output_index == (uint32_t)oi) {
                uint8_t copy = ml < NODUS_WITNESS_MEMO_MAX - 1
                                 ? ml : NODUS_WITNESS_MEMO_MAX - 1;
                if (copy > 0) {
                    memcpy(entry->outputs[k].memo, tx_data + off, copy);
                }
                entry->outputs[k].memo[copy] = '\0';
                entry->outputs[k].memo_len = copy;
                break;
            }
        }
        off += ml;
    }

    free(tx_data);
}

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

        /* Step 3: memo is not persisted in the tx_outputs table —
         * re-parse it out of the stored raw TX blob. Best-effort;
         * entries without a recoverable memo just keep memo_len=0. */
        fill_memos_from_raw_tx(w, &out[i]);
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
                              const char *sender_fp, uint64_t fee,
                              const uint8_t *client_pubkey,
                              const uint8_t *client_sig) {
    if (!w || !w->db || !tx_hash || !tx_data || tx_len == 0) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO committed_transactions "
        "(tx_hash, tx_type, tx_data, tx_len, block_height, timestamp, "
        "sender_fp, fee, client_pubkey, client_sig) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
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

    /* Phase 11 follow-up — persist client_pubkey + client_sig so sync
     * replay can serve real values. NULL inputs (e.g. genesis) bind
     * SQL NULL. */
    if (client_pubkey)
        sqlite3_bind_blob(stmt, 9, client_pubkey, NODUS_PK_BYTES, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 9);
    if (client_sig)
        sqlite3_bind_blob(stmt, 10, client_sig, NODUS_SIG_BYTES, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 10);

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

/* Lookup (block_height, tx_index) coordinates for a committed tx_hash.
 * Used by dnac_spend_replay (Fix #4 B) to reconstruct a spndrslt receipt
 * without pulling the full tx_data blob. Returns 0 on found, -1 otherwise. */
int nodus_witness_get_committed_coords(nodus_witness_t *w,
                                        const uint8_t *tx_hash,
                                        uint64_t *block_height_out,
                                        uint32_t *tx_index_out) {
    if (!w || !w->db || !tx_hash) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT block_height, tx_index FROM committed_transactions "
        "WHERE tx_hash = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    if (block_height_out)
        *block_height_out = (uint64_t)sqlite3_column_int64(stmt, 0);
    if (tx_index_out)
        *tx_index_out = (uint32_t)sqlite3_column_int(stmt, 1);

    sqlite3_finalize(stmt);
    return 0;
}

/* Phase 11 / Task 11.1 — multi-tx block fetch helpers */

void nodus_witness_block_tx_row_free(nodus_witness_block_tx_row_t *row) {
    if (!row) return;
    free(row->tx_data);
    free(row->client_pubkey);
    free(row->client_sig);
    row->tx_data = NULL;
    row->tx_len = 0;
    row->client_pubkey = NULL;
    row->client_sig = NULL;
}

int nodus_witness_block_txs_get(nodus_witness_t *w, uint64_t block_height,
                                  nodus_witness_block_tx_row_t *out,
                                  int max_entries, int *count_out) {
    if (!w || !w->db || !out || !count_out || max_entries <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT tx_hash, tx_type, tx_data, tx_len, client_pubkey, client_sig "
        "FROM committed_transactions "
        "WHERE block_height = ? "
        "ORDER BY tx_index ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)block_height);

    int n = 0;
    while (n < max_entries && sqlite3_step(stmt) == SQLITE_ROW) {
        nodus_witness_block_tx_row_t *row = &out[n];
        memset(row, 0, sizeof(*row));

        const void *hash_blob = sqlite3_column_blob(stmt, 0);
        int hash_len = sqlite3_column_bytes(stmt, 0);
        if (!hash_blob || hash_len != NODUS_T3_TX_HASH_LEN) continue;
        memcpy(row->tx_hash, hash_blob, NODUS_T3_TX_HASH_LEN);

        row->tx_type = (uint8_t)sqlite3_column_int(stmt, 1);

        const void *data_blob = sqlite3_column_blob(stmt, 2);
        int data_len = sqlite3_column_bytes(stmt, 2);
        if (data_blob && data_len > 0) {
            row->tx_data = malloc((size_t)data_len);
            if (row->tx_data) {
                memcpy(row->tx_data, data_blob, (size_t)data_len);
                row->tx_len = (uint32_t)data_len;
            }
        }

        const void *pk_blob = sqlite3_column_blob(stmt, 4);
        int pk_len = sqlite3_column_bytes(stmt, 4);
        if (pk_blob && pk_len == NODUS_PK_BYTES) {
            row->client_pubkey = malloc(NODUS_PK_BYTES);
            if (row->client_pubkey)
                memcpy(row->client_pubkey, pk_blob, NODUS_PK_BYTES);
        }

        const void *sig_blob = sqlite3_column_blob(stmt, 5);
        int sig_len = sqlite3_column_bytes(stmt, 5);
        if (sig_blob && sig_len == NODUS_SIG_BYTES) {
            row->client_sig = malloc(NODUS_SIG_BYTES);
            if (row->client_sig)
                memcpy(row->client_sig, sig_blob, NODUS_SIG_BYTES);
        }

        n++;
    }
    sqlite3_finalize(stmt);
    *count_out = n;
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

/* Reject anything but [A-Za-z0-9_] in savepoint names — they go straight
 * into SQL with no binding, and SQLite SAVEPOINT does not accept ?. */
static bool savepoint_name_safe(const char *name) {
    if (!name || !*name) return false;
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }
    return true;
}

int nodus_witness_db_savepoint(nodus_witness_t *w, const char *name) {
    if (!w || !w->db || !savepoint_name_safe(name)) return -1;
    char sql[128];
    snprintf(sql, sizeof(sql), "SAVEPOINT %s", name);
    char *err = NULL;
    int rc = sqlite3_exec(w->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: SAVEPOINT %s failed: %s\n", LOG_TAG, name, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_rollback_to_savepoint(nodus_witness_t *w, const char *name) {
    if (!w || !w->db || !savepoint_name_safe(name)) return -1;
    char sql[128];
    snprintf(sql, sizeof(sql), "ROLLBACK TO SAVEPOINT %s", name);
    char *err = NULL;
    int rc = sqlite3_exec(w->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ROLLBACK TO SAVEPOINT %s failed: %s\n", LOG_TAG, name, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Block hash computation (Phase 5 / Task 5.1).
 *
 * Canonical preimage shared by block_add (writer side) and
 * sync compute_prev_hash (verifier side). Before Phase 5 each side
 * had its own inline SHA3-512 with the same formula — two copies of
 * the same logic is a bug magnet. Now both call this helper. */
static void enc_u64_le(uint64_t v, uint8_t out[8]) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)((v >> (i * 8)) & 0xff);
}
static void enc_u32_le_v(uint32_t v, uint8_t out[4]) {
    for (int i = 0; i < 4; i++) out[i] = (uint8_t)((v >> (i * 8)) & 0xff);
}

void nodus_witness_compute_block_hash(uint64_t height,
                                       const uint8_t prev_hash[64],
                                       const uint8_t state_root[64],
                                       const uint8_t tx_root[64],
                                       uint32_t tx_count,
                                       uint64_t timestamp,
                                       const uint8_t proposer_id[32],
                                       uint8_t out[64]) {
    uint8_t buf[8 + 64 + 64 + 64 + 4 + 8 + 32];  /* 244 bytes */
    uint8_t *p = buf;

    enc_u64_le(height, p);        p += 8;
    memcpy(p, prev_hash, 64);     p += 64;
    memcpy(p, state_root, 64);    p += 64;
    memcpy(p, tx_root, 64);       p += 64;
    enc_u32_le_v(tx_count, p);    p += 4;
    enc_u64_le(timestamp, p);     p += 8;
    memcpy(p, proposer_id, 32);

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(md, buf, sizeof(buf));
    unsigned int n = 0;
    EVP_DigestFinal_ex(md, out, &n);
    EVP_MD_CTX_free(md);
}

/* Schema v12 migration (Phase 1 / Task 1.1).
 *
 * Idempotent. ALTER TABLE ADD COLUMN is silently retried on duplicate-
 * column errors so a second run on an already-migrated DB succeeds.
 * Index DROP/CREATE both use IF EXISTS / IF NOT EXISTS for the same
 * reason. Real SQLite errors (out of memory, disk full, lock contention)
 * trigger WITNESS_DB_MIGRATION_FATAL → abort().
 */
static void nodus_witness_db_migrate_v13_client_fields(nodus_witness_t *w);
static void nodus_witness_db_migrate_v14_chain_def(nodus_witness_t *w);

int nodus_witness_db_migrate_v12(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* tx_index column: idempotent via duplicate-column tolerance.
     * sqlite3 returns SQLITE_ERROR with errmsg "duplicate column name" on
     * re-run; treat it as success. */
    {
        char *err = NULL;
        int rc = sqlite3_exec(w->db,
            "ALTER TABLE committed_transactions "
            "ADD COLUMN tx_index INTEGER NOT NULL DEFAULT 0",
            NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            const char *msg = err ? err : "(null)";
            if (!strstr(msg, "duplicate column name")) {
                /* Real failure — log and abort with the pinned literal */
                fprintf(stderr, "MIGRATION FAILURE: ALTER ADD tx_index failed "
                                "with sqlite error %d: %s\n", rc, msg);
                if (err) sqlite3_free(err);
                abort();
            }
            if (err) sqlite3_free(err);
        }
    }

    /* Drop legacy single-column index — IF EXISTS makes it safe on fresh DBs */
    {
        char *err = NULL;
        int rc = sqlite3_exec(w->db,
            "DROP INDEX IF EXISTS idx_ctx_height",
            NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "MIGRATION FAILURE: DROP INDEX idx_ctx_height failed "
                            "with sqlite error %d: %s\n", rc, err ? err : "(null)");
            if (err) sqlite3_free(err);
            abort();
        }
    }

    /* Create composite index — IF NOT EXISTS for idempotence */
    {
        char *err = NULL;
        int rc = sqlite3_exec(w->db,
            "CREATE INDEX IF NOT EXISTS idx_ctx_block "
            "ON committed_transactions(block_height, tx_index)",
            NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "MIGRATION FAILURE: CREATE INDEX idx_ctx_block failed "
                            "with sqlite error %d: %s\n", rc, err ? err : "(null)");
            if (err) sqlite3_free(err);
            abort();
        }
    }

    /* Phase 11 follow-up — client_pubkey + client_sig columns. */
    nodus_witness_db_migrate_v13_client_fields(w);

    /* Phase 2 / Task 7 (anchored merkle proofs) — chain_def_blob column. */
    nodus_witness_db_migrate_v14_chain_def(w);

    return 0;
}

/* Phase 11 follow-up — additive ALTER for client_pubkey + client_sig.
 * Split out so the migration body in v12 stays focused. */
static void nodus_witness_db_migrate_v13_client_fields(nodus_witness_t *w) {
    static const char *cols[2];
    cols[0] = "ALTER TABLE committed_transactions ADD COLUMN client_pubkey BLOB";
    cols[1] = "ALTER TABLE committed_transactions ADD COLUMN client_sig BLOB";
    for (int i = 0; i < 2; i++) {
        char *err = NULL;
        int rc = sqlite3_exec(w->db, cols[i], NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            const char *msg = err ? err : "(null)";
            if (!strstr(msg, "duplicate column name")) {
                fprintf(stderr,
                        "MIGRATION FAILURE: ALTER ADD client field [%d] "
                        "sqlite error %d: %s\n", i, rc, msg);
                if (err) sqlite3_free(err);
                abort();
            }
            if (err) sqlite3_free(err);
        }
    }
}

/* Schema v14 migration (Phase 2 / Task 7 - anchored merkle proofs).
 *
 * Adds the chain_def_blob column to the blocks table. Nullable; only
 * populated for genesis blocks (height=0) and stores the serialized
 * dnac_chain_definition_t. Idempotent via duplicate-column tolerance. */
static void nodus_witness_db_migrate_v14_chain_def(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE blocks ADD COLUMN chain_def_blob BLOB",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name")) {
            fprintf(stderr,
                    "MIGRATION FAILURE: ALTER ADD chain_def_blob "
                    "sqlite error %d: %s\n", rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}
