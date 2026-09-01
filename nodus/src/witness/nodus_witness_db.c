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
#include "nodus/nodus_chain_config.h"  /* Hard-Fork v1 schema migration */
#include "crypto/nodus_sign.h"
#include "dnac/transaction.h"          /* DNAC_TX_HEADER_SIZE (v0.17.1) */
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#include "crypto/utils/qgp_bench.h"         /* perf harness — ((void)0) in production */
#include "crypto/utils/qgp_log.h"           /* QGP_LOG_* (new code; legacy lines use fprintf) */

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
    int rc_step = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    /* HIGH-10: fail-closed — step errors (BUSY/LOCKED/IOERR/CORRUPT) assume spent */
    if (rc_step == SQLITE_ROW) return true;
    if (rc_step == SQLITE_DONE) return false;
    fprintf(stderr, "%s: nullifier step failed rc=%d - assuming spent (fail-closed)\n",
            LOG_TAG, rc_step);
    return true;
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

int nodus_witness_utxo_lookup_ex(nodus_witness_t *w, const uint8_t *nullifier,
                                   uint64_t *amount_out, char *owner_out,
                                   uint8_t *token_id_out,
                                   uint64_t *unlock_block_out) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT amount, owner, token_id, unlock_block FROM utxo_set "
        "WHERE nullifier = ?",
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

    if (unlock_block_out)
        *unlock_block_out = (uint64_t)sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_lookup(nodus_witness_t *w, const uint8_t *nullifier,
                                uint64_t *amount_out, char *owner_out,
                                uint8_t *token_id_out) {
    return nodus_witness_utxo_lookup_ex(w, nullifier, amount_out, owner_out,
                                         token_id_out, NULL);
}

int nodus_witness_utxo_add_locked(nodus_witness_t *w, const uint8_t *nullifier,
                                    const char *owner, uint64_t amount,
                                    const uint8_t *tx_hash, uint32_t index,
                                    uint64_t block_height,
                                    const uint8_t *token_id,
                                    uint64_t unlock_block) {
    if (!w || !w->db || !nullifier || !owner || !tx_hash) return -1;

    /* Default to native DNAC (64 zero bytes) when token_id is NULL */
    static const uint8_t zero_token[64] = {0};
    const uint8_t *tid = token_id ? token_id : zero_token;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO utxo_set "
        "(nullifier, owner, amount, token_id, tx_hash, output_index, "
        " block_height, created_at, unlock_block) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
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
    sqlite3_bind_int64(stmt, 9, (int64_t)unlock_block);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: utxo add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

int nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height,
                              const uint8_t *token_id) {
    /* Legacy path: unlock_block == 0 means UTXO is already spendable. */
    return nodus_witness_utxo_add_locked(w, nullifier, owner, amount,
                                          tx_hash, index, block_height,
                                          token_id, 0);
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
        /* O15B §7: unlock_block is SELECTed so the caller can tell a
         * spendable coin from one still inside its post-UNSTAKE cooldown.
         * Omitting it is what let the wallet build transactions consensus
         * was guaranteed to reject (Rule D, nodus_witness_verify.c:730). */
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "block_height, unlock_block "
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

        /* O15B §7 — a NEGATIVE stored integer must never surface as a huge
         * u64. The same fail-closed discipline the native adapter row
         * readers already apply (nodus_witness_rt_native.c, review round R4):
         * a malformed row is reported as locked-forever rather than as
         * spendable, because the failure mode of guessing wrong here is a
         * transaction every validator rejects. */
        sqlite3_int64 ub = sqlite3_column_int64(stmt, 7);
        e->unlock_block = (ub < 0) ? UINT64_MAX : (uint64_t)ub;
        count++;
    }

    /* O15B §7 — a mid-scan SQLITE_IOERR/SQLITE_CORRUPT used to truncate the
     * result set and still return success, so a wallet could sync a PARTIAL
     * UTXO list and believe it complete. Fail closed instead: an incomplete
     * answer is not an answer. (nodus/CLAUDE.md, "A DB failure is never a
     * value" — the unguarded `while (sqlite3_step(...) == SQLITE_ROW)` shape.) */
    int step_rc = sqlite3_reset(stmt);
    sqlite3_finalize(stmt);
    if (step_rc != SQLITE_OK) {
        *count_out = 0;
        return -1;
    }

    *count_out = count;
    return 0;
}

/* ── Ledger operations ───────────────────────────────────────────── */

int nodus_witness_ledger_add(nodus_witness_t *w, const uint8_t *tx_hash,
                                uint8_t tx_type, uint8_t nullifier_count,
                                uint64_t block_height,
                                uint64_t block_timestamp) {
    if (!w || !w->db || !tx_hash) return -1;

    /* Determinism: epoch is the consensus-agreed block height divided
     * by the chain-config epoch length (each block is in exactly one
     * epoch). timestamp is the consensus-agreed block timestamp from
     * the proposer's header (set at propose time, replicated unchanged
     * to followers, sync_rsp echoes it on replay). Both values are
     * byte-identical across all nodes for a given block. */
    uint64_t epoch = (block_height == 0) ? 0
                                          : (block_height - 1) / DNAC_EPOCH_LENGTH;

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
    sqlite3_bind_int64(stmt, 4, (int64_t)block_timestamp);
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
                               const uint8_t *state_root,
                               const uint8_t *chain_def_blob,
                               size_t chain_def_blob_len) {
    if (!w || !w->db || !tx_root || !state_root) return -1;
    /* chain_def_blob is optional: non-NULL + non-zero only for genesis
     * blocks (height 0). See header comment for details. */
    if (chain_def_blob && chain_def_blob_len == 0) return -1;
    if (!chain_def_blob && chain_def_blob_len != 0) return -1;

    /* Phase 5 / Task 5.2: prev_hash via the shared compute_block_hash
     * helper. Single source of truth with nodus_witness_sync.c. */
    uint8_t prev_hash[NODUS_T3_TX_HASH_LEN] = {0};
    nodus_witness_block_t prev_block;
    if (nodus_witness_block_get_latest(w, &prev_block) == 0) {
        /* If prev_block is genesis (height 0), its block hash includes
         * chain_def. Load the stored chain_def_blob so the prev_hash
         * computation matches. For non-genesis prev blocks, pass NULL. */
        const uint8_t *prev_cd_blob = NULL;
        size_t prev_cd_len = 0;
        uint8_t *prev_cd_alloc = NULL;
        if (prev_block.height == 0) {
            /* One-shot query: SELECT chain_def_blob FROM blocks WHERE height = 0 */
            sqlite3_stmt *cdst;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT chain_def_blob FROM blocks WHERE height = 0",
                    -1, &cdst, NULL) == SQLITE_OK) {
                if (sqlite3_step(cdst) == SQLITE_ROW) {
                    const void *blob = sqlite3_column_blob(cdst, 0);
                    int blen = sqlite3_column_bytes(cdst, 0);
                    if (blob && blen > 0) {
                        prev_cd_alloc = malloc((size_t)blen);
                        if (prev_cd_alloc) {
                            memcpy(prev_cd_alloc, blob, (size_t)blen);
                            prev_cd_blob = prev_cd_alloc;
                            prev_cd_len = (size_t)blen;
                        }
                    }
                }
                sqlite3_finalize(cdst);
            }
        }
        nodus_witness_compute_block_hash_ex(prev_block.height,
                                              prev_block.prev_hash,
                                              prev_block.state_root,
                                              prev_block.tx_root,
                                              prev_block.tx_count,
                                              prev_block.proposer_id,
                                              prev_cd_blob, prev_cd_len,
                                              prev_hash);
        free(prev_cd_alloc);
    }
    /* Genesis block: prev_hash stays all zeros */

    /* Phase 2 / Task 11 — chain_def_blob column added in schema v14.
     * Nullable; only genesis blocks populate it. NOTE: this write site
     * is the sole producer for now. Readers (block_get*, block_get_range)
     * intentionally skip the column until Task 36 adds handle_dnac_genesis. */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO blocks (tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root, created_at, chain_def_blob) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
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
    if (chain_def_blob && chain_def_blob_len > 0)
        sqlite3_bind_blob(stmt, 8, chain_def_blob, (int)chain_def_blob_len,
                          SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 8);

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

/* Phase 2 / Task 36 — genesis block fetch with chain_def_blob.
 *
 * Returns the genesis block row (height == 0) including the
 * chain_def_blob column. The blob is returned via malloc'd
 * *blob_out; caller owns and must free(). If the block has no
 * chain_def_blob (non-genesis or missing), *blob_out = NULL and
 * *blob_len_out = 0.
 *
 * Returns 0 on success (genesis row found), -1 on error / not found.
 */
int nodus_witness_block_get_genesis(nodus_witness_t *w,
                                      nodus_witness_block_t *out,
                                      uint8_t **blob_out,
                                      size_t *blob_len_out) {
    if (!w || !w->db || !out || !blob_out || !blob_len_out) return -1;
    *blob_out = NULL;
    *blob_len_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root, chain_def_blob "
        "FROM blocks WHERE height = 0", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);

    const void *blob = sqlite3_column_blob(stmt, 7);
    int blen = sqlite3_column_bytes(stmt, 7);
    if (blob && blen > 0) {
        uint8_t *copy = (uint8_t *)malloc((size_t)blen);
        if (!copy) {
            sqlite3_finalize(stmt);
            return -1;
        }
        memcpy(copy, blob, (size_t)blen);
        *blob_out = copy;
        *blob_len_out = (size_t)blen;
    }

    sqlite3_finalize(stmt);
    return 0;
}

/* O15O Faz 1 — the real query, with the fault kept distinguishable from
 * the value. Full contract on the declaration in nodus_witness_db.h.
 *
 * Both branches now separate the three sqlite outcomes the old body
 * collapsed into a bare 0:
 *   prepare failure                  -> FAULT (includes "no such table")
 *   step != SQLITE_ROW/SQLITE_DONE   -> FAULT (SQLITE_BUSY, _CORRUPT, …)
 *   SQLITE_ROW with a NULL / absent aggregate, or SQLITE_DONE
 *                                    -> SUCCESS, height 0 (empty chain)
 * SQLITE_DONE cannot occur for either statement — a bare aggregate always
 * yields exactly one row — but it is admitted rather than treated as a
 * fault so a future non-aggregate rewrite of either query degrades to
 * "empty" rather than to "halt". */
int nodus_witness_block_height_checked(nodus_witness_t *w, uint64_t *out) {
    if (!out) return -1;
    if (!w) return -1;

    /* ── A MISSING HANDLE IS NOT ALWAYS A FAULT — the O15L DG-1 matrix ──
     *
     * `w->db == NULL` does NOT mean one thing, and answering it with a
     * single verdict is wrong in one direction or the other. The split
     * below is the SAME one nodus_witness_bft.c's load_committee_at_height
     * makes at :673-683, drawn with the SAME 32-byte comparison, so the
     * two gates cannot disagree about which row of the matrix a node is
     * in:
     *
     *   chain_id == 0, db == NULL   GENUINE PRE-GENESIS. There is no
     *                               chain, so height 0 is a TRUE COMMITTED
     *                               ANSWER — the same status
     *                               load_committee_at_height gives
     *                               "count 0" there, and the same status
     *                               an empty `blocks` table gives 0 below.
     *                               Every consumer is documented to take
     *                               the gossip-roster bootstrap in this
     *                               window (F17 A5).
     *   chain_id != 0, db == NULL   DG-1 ROW 2 — this node HOLDS a chain
     *                               and cannot read it. Here 0 is the
     *                               FAIL-OPEN this function exists to
     *                               remove: it is not an answer, it is the
     *                               ABSENCE of one, and consumers of that
     *                               0 went on to resolve a committee at
     *                               height 1.
     *
     * WHY THE FIRST ARM IS LOAD-BEARING, not a courtesy. A node running
     * the genesis round is in it BY CONSTRUCTION:
     * nodus_witness_commit_genesis is what CREATES the chain database
     * (nodus_witness_bft.c, nodus_witness_commit_genesis — its opening
     * `if (!w->db)` bootstrap, which calls nodus_witness_create_chain_db;
     * cited by FUNCTION because comments of this length are exactly what
     * shifts the line numbers around them), so `db` is
     * NULL until genesis commits.
     * Answering -1 there makes nodus_witness_bft_is_leader refuse to lead,
     * bft_start_round_internal refuse to open the round, and
     * handle_propose / handle_commit refuse the genesis proposal — on
     * EVERY node at once, because every node is in that state at the same
     * moment. A fresh cluster would never produce genesis and the chain
     * would never start. load_committee_at_height's comment (:622-655)
     * calls this arm "preserved BYTE-IDENTICALLY" for exactly that reason.
     *
     * ⚠ THESE TWO GATES ARE ONE RULE IN TWO PLACES. A change to either
     * MUST change the other. If this function ever says "pre-genesis" for
     * a node load_committee_at_height calls row 2 (or the reverse), a node
     * gets its height from one row of the matrix and its committee from
     * the other — the two would then disagree about whether the node has
     * a chain at all. Grep DG-1 before touching either. */
    if (!w->db) {
        static const uint8_t zero_chain[32] = {0};
        if (memcmp(w->chain_id, zero_chain, 32) == 0) {
            /* Deliberately NOT logged. This is a normal, expected state
             * on a fresh cluster, and the consumers reading it run at
             * tick rate — the sibling gate declines to log here for the
             * same reason (nodus_witness_bft.c:657-661). */
            *out = 0;
            return 0;
        }
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: this node HOLDS a chain (chain_id set) but its "
            "database is not open — refusing to answer 0 (DG-1 row 2: an "
            "absent answer is not height 0)");
        return -1;
    }

    /* O15D — on a SUCCESSOR chain the chain height IS the committed V2
     * height: the legacy `blocks` table is empty by construction and
     * stays empty forever (the legacy production lane refuses on a
     * successor), so every consumer of "this chain's height" — the
     * round anchors, IDENT advertisements, RPC status, forward routing —
     * must see the v2_blocks tip. Legacy chains take the branch below
     * byte-identically (v2_successor is false there). */
    if (w->v2_successor) {
        sqlite3_stmt *v2 = NULL;
        int vrc = sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
                -1, &v2, NULL);
        if (vrc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG,
                "block_height: v2_blocks prepare failed (rc=%d): %s",
                vrc, sqlite3_errmsg(w->db));
            return -1;
        }
        vrc = sqlite3_step(v2);
        if (vrc != SQLITE_ROW && vrc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG,
                "block_height: v2_blocks step failed (rc=%d): %s",
                vrc, sqlite3_errmsg(w->db));
            sqlite3_finalize(v2);
            return -1;
        }
        uint64_t vh = 0;
        /* COALESCE guarantees non-NULL, but the type test costs nothing
         * and keeps this branch's success rule identical to the legacy
         * one below: a NULL aggregate is an EMPTY chain, never a fault. */
        if (vrc == SQLITE_ROW &&
            sqlite3_column_type(v2, 0) != SQLITE_NULL)
            vh = (uint64_t)sqlite3_column_int64(v2, 0);
        sqlite3_finalize(v2);
        *out = vh;
        return 0;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT MAX(height) FROM blocks", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: blocks prepare failed (rc=%d): %s",
            rc, sqlite3_errmsg(w->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: blocks step failed (rc=%d): %s",
            rc, sqlite3_errmsg(w->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    uint64_t height = 0;
    /* MAX() over an empty table yields one row holding NULL — a genuinely
     * empty chain, and the one case where 0 is the honest answer. */
    if (rc == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        height = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    *out = height;
    return 0;
}

/* ── THE FAIL-OPEN FORM — for callers whose answer decides nothing ────
 *
 * O15O Faz 1. This wrapper preserves the pre-O15O behaviour EXACTLY: a
 * DB fault still yields 0, indistinguishable from an empty chain to the
 * caller. That is safe ONLY where the value labels or advises and never
 * decides, so every consensus consumer was moved to the checked form.
 *
 * What the wrapper adds is that the fault can no longer be SILENT. The
 * checked form logs the sqlite error text; this line names the FAIL-OPEN
 * itself, so an operator sees "we answered 0 because the read failed"
 * instead of inferring it from a chain that appears to be at genesis.
 * Both reach stderr in a nodus-server build: QGP_LOG_* resolves to
 * nodus/src/nodus_log_shim.c there, whose qgp_log_ring_add writes
 * straight to stderr with an [ERR/tag] prefix — the real qgp_log.c, whose
 * ring buffer nodus never enables, is only linked in the messenger tree.
 *
 * THE CALLERS DELIBERATELY LEFT ON THIS FORM (O15O Faz 1 classification;
 * a bogus 0 at each is either harmless or conservative). Named by their
 * FUNCTION as well as their line, because prose like this one is what
 * shifts line numbers: if the two disagree, the function name wins and
 * the line is stale.
 *
 *   bft.c supply_invariant_violated (:1634)
 *       — advisory; that site's own comment says the invariant stays
 *         advisory until the lock/pool aggregation lands.
 *   bft.c bft_handle_vote_inner, commit tail (:6755)
 *       — labels a legacy commit-certificate row.
 *   bft.c nodus_witness_bft_handle_commit cert store (:7322)
 *       — same, on the remote-COMMIT path.
 *   bft.c nodus_witness_bft_check_timeout, P1 round release (:10863)
 *       — fail-safe at 0: the block is gated on `block_height != 0`, so
 *         `0 >= round_height` is false and no round is released. This is
 *         the LAST remaining fail-open in check_timeout; its sibling, the
 *         P3 tip-frozen window, was CONVERTED (see the O15O comment
 *         there), because P3's 0 was NOT fail-safe under a sustained
 *         fault and could rotate the view against an unread tip.
 *   nodus_witness_sync.c 471, 698, 989, 1425, 1510
 *       — a bogus 0 makes this node believe it is empty and sync from
 *         scratch: wasteful, and the conservative direction.
 *   nodus_witness_handlers.c 475, 1214, 2896 — RPC / display.
 *   nodus_witness_peer.c:435 — the height advertised in IDENT.
 *   nodus_server.c:3800      — RPC status field.
 *
 * NOT CLASSIFIED by O15O Faz 1, and therefore untouched rather than
 * deliberately left: nodus_witness_bft.c nodus_witness_bft_handle_commit
 * (:7406), which fills the client-visible committed_block_height on the
 * remote-COMMIT reply path, and nodus_witness_cert.c:169, outside this
 * phase's file whitelist. */
uint64_t nodus_witness_block_height(nodus_witness_t *w) {
    uint64_t h = 0;
    if (nodus_witness_block_height_checked(w, &h) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: READ FAULTED — answering 0 on the FAIL-OPEN "
            "accessor. If this height reaches a consensus decision, that "
            "call site belongs on nodus_witness_block_height_checked");
        return 0;
    }
    return h;
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
    /* created_at deterministic = 0 (informational only; was time(NULL)
     * which produces different values on each node — bootstrap-replayed
     * nodes ran genesis at a later wall-clock moment than original BFT
     * nodes, diverging this row. Even though the field is not in
     * state_root today, the row content is read by debug/forensic
     * queries that downstream code may eventually fold into consensus.
     * Determinism-by-default per PRIMARY OBJECTIVE: DETERMINISM. */
    sqlite3_bind_int64(stmt, 4, 0);

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

    /* Schema first, "already initialized" probe SECOND (2026-07-31).
     *
     * The order used to be the other way round, which made the ALTER
     * below unreachable on exactly the DB that needed it: the probe
     * returns -2 the moment it sees the id = 1 row, so a DB that already
     * held the row but predated the total_minted column could never gain
     * it — and under the D1/D2/D3 fail-close chain a missing column now
     * rejects every block (see migrate_v17_supply_total_minted, which is
     * the belt to this suspenders: it runs on every chain-DB open, while
     * this path only runs when commit_genesis calls us).
     *
     * Both statements are idempotent, so running them before the probe
     * costs nothing on an already-initialized DB: CREATE TABLE IF NOT
     * EXISTS is a no-op, and the ALTER returns "duplicate column name"
     * which is ignored via the NULL errmsg. */
    sqlite3_exec(w->db,
        "CREATE TABLE IF NOT EXISTS supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  total_minted INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");", NULL, NULL, NULL);

    /* Migration: add total_minted to pre-v0.16 DBs. The ALTER silently
     * fails when the column already exists (ignored via NULL errmsg). */
    sqlite3_exec(w->db,
        "ALTER TABLE supply_tracking ADD COLUMN total_minted "
        "INTEGER NOT NULL DEFAULT 0", NULL, NULL, NULL);

    /* Check if already initialized */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  /* Already initialized */
    }
    sqlite3_finalize(stmt);

    rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO supply_tracking "
        "(id, genesis_supply, total_burned, total_minted, "
        " current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, ?, 0, 0, ?, ?, 1)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)total_supply);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    sqlite3_bind_blob(stmt, 3, genesis_tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* D1 (2026-07-31) — three-valued so callers can tell "pre-genesis" from
 * "DB error". Conflating the two let a transient fault masquerade as a
 * legitimate empty state and reach state_root / the supply gate. Full
 * contract on the declaration in nodus_witness_db.h. */
int nodus_witness_supply_get(nodus_witness_t *w,
                                nodus_witness_supply_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT genesis_supply, total_burned, total_minted, current_supply, "
        "       last_sequence "
        "FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Includes "no such table: supply_tracking" and "no such column:
         * total_minted", both of which are real errors here, NOT an absent
         * row — the caller must not read them as "pre-genesis".
         *
         * MERGE NOTE (2026-07-31): this comment used to say the table is
         * "created lazily by supply_init". That stopped being true in the
         * same round — supply_tracking is now part of WITNESS_DB_SCHEMA
         * (nodus_witness.c), so it exists from the moment the chain DB is
         * opened and only a genuinely missing/older DB can land here. The
         * total_minted column is back-filled by
         * nodus_witness_db_migrate_v17_supply_total_minted on every open. */
        QGP_LOG_ERROR(LOG_TAG, "supply_get: prepare failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        if (rc == SQLITE_DONE) return 1;   /* row genuinely absent */
        QGP_LOG_ERROR(LOG_TAG, "supply_get: step failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->genesis_supply = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->total_burned   = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->total_minted   = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->current_supply = (uint64_t)sqlite3_column_int64(stmt, 3);
    out->last_sequence  = (uint64_t)sqlite3_column_int64(stmt, 4);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_supply_add_minted(nodus_witness_t *w, uint64_t mint) {
    if (!w || !w->db) return -1;
    if (mint == 0) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE supply_tracking SET total_minted = total_minted + ?, "
        "current_supply = current_supply + ? WHERE id = 1",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Table might not exist yet on pre-genesis witness DBs (unit
         * test fixtures). Treat as advisory no-op. */
        return 0;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)mint);
    sqlite3_bind_int64(stmt, 2, (int64_t)mint);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    /* sqlite3_changes == 0 means no supply_tracking row yet (pre-genesis
     * fixture). Production path always initializes it in commit_genesis
     * before the first finalize_block call; we tolerate the gap here
     * so unit tests that bypass genesis still exercise the mint path. */
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
                              &tx_len, &bh) != 0 || !tx_data || tx_len < DNAC_TX_HEADER_SIZE + 1) {
        free(tx_data);
        return;
    }

    size_t off = DNAC_TX_HEADER_SIZE; /* v0.17.1: ver+type+ts+tx_hash+committed_fee = 82 */
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
                              uint64_t block_timestamp,
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
    /* Determinism: block_timestamp is the consensus-agreed block
     * timestamp from the proposer's header. Pre-fix used time(NULL)
     * which produced different per-node values on the same TX. */
    sqlite3_bind_int64(stmt, 6, (int64_t)block_timestamp);

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

        /* F17 A1 — pubkey is NOT persisted in commit_certificates schema.
         * Explicit zero so callers see a deterministic zero field rather
         * than stack garbage. Sync verification (verify_sync_certs) does
         * not consult this field — it resolves pubkey via the roster
         * keyed on voter_id. */
        memset(votes_out[count].pubkey, 0, DNAC_PUBKEY_SIZE);

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
    /* Phase 9 / Task 47 — upgraded to BEGIN IMMEDIATE per design F-STATE-02.
     *
     * IMMEDIATE acquires the RESERVED lock synchronously: any concurrent
     * write attempt fails fast instead of waiting for the commit barrier.
     * This makes "nested begin" bugs (re-entrant block commits) surface as
     * loud SQLITE_BUSY on the second BEGIN rather than silently succeeding.
     *
     * The block commit path (commit_genesis / commit_batch / replay_block)
     * is the sole writer, so IMMEDIATE never contends in production; the
     * upgrade is a correctness guard, not a performance change. */
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: BEGIN IMMEDIATE failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    w->in_block_transaction = true;
    return 0;
}

int nodus_witness_db_commit(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    QGP_BENCH_START(QGP_BENCH_SQLITE_COMMIT);
    int rc = sqlite3_exec(w->db, "COMMIT", NULL, NULL, &err);
    QGP_BENCH_END(QGP_BENCH_SQLITE_COMMIT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: COMMIT failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    w->in_block_transaction = false;
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
    w->in_block_transaction = false;
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
                                       const uint8_t proposer_id[32],
                                       uint8_t out[64]) {
    nodus_witness_compute_block_hash_ex(height, prev_hash, state_root,
                                          tx_root, tx_count,
                                          proposer_id, NULL, 0, out);
}

void nodus_witness_compute_block_hash_ex(uint64_t height,
                                           const uint8_t prev_hash[64],
                                           const uint8_t state_root[64],
                                           const uint8_t tx_root[64],
                                           uint32_t tx_count,
                                           const uint8_t proposer_id[32],
                                           const uint8_t *chain_def_blob,
                                           size_t chain_def_blob_len,
                                           uint8_t out[64]) {
    /* PR 2 (2026-05-03): timestamp dropped from preimage. Buffer shrunk
     * from 244 to 236 bytes. See header comment for rationale. */
    uint8_t buf[8 + 64 + 64 + 64 + 4 + 32];  /* 236 bytes standard header */
    uint8_t *p = buf;

    enc_u64_le(height, p);        p += 8;
    memcpy(p, prev_hash, 64);     p += 64;
    /* state_root may be NULL on the cert-preimage path (sync_handle_rsp
     * recomputes block_hash before knowing state_root, then verifies
     * against the wire's certs). The original sync.c comment claimed
     * this helper accepts NULL but the implementation here was missing
     * the guard, segfaulting on the first sync that took the
     * cert-preimage branch. Treat NULL as 64 zero bytes — same hash
     * input as the all-zero case the legacy code wrote into the buffer
     * stack-memory before this fix when it happened to be zeroed. */
    if (state_root)
        memcpy(p, state_root, 64);
    else
        memset(p, 0, 64);
    p += 64;
    memcpy(p, tx_root, 64);       p += 64;
    enc_u32_le_v(tx_count, p);    p += 4;
    memcpy(p, proposer_id, 32);

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(md, buf, sizeof(buf));

    /* Anchored genesis: append chain_def bytes verbatim to the preimage.
     * These bytes are produced by dnac_chain_def_encode and are byte-
     * identical to the sub-sequence dnac_block_compute_hash appends for
     * genesis blocks. Both sides hash the same bytes → same block_hash. */
    if (chain_def_blob && chain_def_blob_len > 0) {
        EVP_DigestUpdate(md, chain_def_blob, chain_def_blob_len);
    }

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
static void nodus_witness_db_migrate_v15_stake_delegation(nodus_witness_t *w);
static void nodus_witness_db_migrate_v16_pbft_state(nodus_witness_t *w);
static void nodus_witness_db_migrate_v17_supply_total_minted(nodus_witness_t *w);

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

    /* Task 11 (stake delegation) — utxo_set.unlock_block column. */
    nodus_witness_db_migrate_v15_stake_delegation(w);

    /* Hard-Fork v1 — chain_config_history table (CREATE TABLE IF NOT EXISTS). */
    nodus_chain_config_db_migrate(w);

    /* PR 3 Yol B — pbft_state singleton table (current_view + last_prepared). */
    nodus_witness_db_migrate_v16_pbft_state(w);

    /* 2026-07-31 — supply_tracking.total_minted back-fill, made reachable
     * on every open (it was unreachable inside supply_init). */
    nodus_witness_db_migrate_v17_supply_total_minted(w);

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

/* Schema v15 migration (Task 11 — stake/delegation).
 *
 * Adds the unlock_block column to the utxo_set table. Used to lock
 * stake/delegation UTXOs until a future block height (unbonding
 * cooldown). Default 0 means "already spendable"; zero value preserves
 * pre-Task-11 semantics for every existing UTXO. Idempotent via
 * duplicate-column tolerance. */
static void nodus_witness_db_migrate_v15_stake_delegation(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE utxo_set "
        "ADD COLUMN unlock_block INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name")) {
            fprintf(stderr,
                    "MIGRATION FAILURE: ALTER ADD unlock_block "
                    "sqlite error %d: %s\n", rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}

/* ── PR 3 Yol B / H-5 PBFT state persistence ─────────────────────── */

/* Schema v16 migration: singleton pbft_state table.
 *
 * Holds two pieces of BFT runtime state. They are written together and
 * read back together, but as of O15P Faz 1 only ONE of them is restored
 * into consensus state — see nodus_witness_db_load_pbft_state below,
 * which carries the argument:
 *
 *   current_view       INTEGER  BFT view number. WRITTEN on every view
 *                               move and READ by operators and by the
 *                               stagef harness as the "a view change
 *                               completed" probe — but NOT loaded back
 *                               into w->current_view. A witness comes up
 *                               at view 0 and pulls a VIEW_OK proof from
 *                               a peer that is ahead.
 *   last_prepared_blob BLOB     Serialized PBFT-prepared certificate
 *                               from the most recent PREVOTE quorum
 *                               this witness observed locally. RESTORED,
 *                               and it MUST stay that way: it is the
 *                               prepared-value lock's memory, and the
 *                               quorum-intersection safety argument
 *                               depends on that lock surviving a restart.
 *
 * The original H-5 reasoning — recorded because the column outlived it:
 * without persistence a HAVE_CHAIN restart re-entered consensus at view
 * 0 and found its votes rejected by peers that had already advanced past
 * it (A15 in the PR 3 design threat model), and the cluster stalled until
 * that node re-entered via VIEW_CHANGE. O15N Faz 2C2 removed the stall by
 * giving the counter a single write site behind a verified VIEW_OK proof
 * and a pull path for a node that is behind (nodus_witness_bft.c:5746,
 * :10411), so "behind" became a state the protocol recovers from rather
 * than one it hangs on. That is what makes discarding the stored view
 * safe; the blob's half of the argument is untouched and still stands.
 *
 * Singleton via CHECK(id = 1) — same pattern as genesis_state. The
 * UPSERT in nodus_witness_db_save_pbft_state ensures only one row
 * ever exists. Idempotent: CREATE TABLE IF NOT EXISTS. */
static void nodus_witness_db_migrate_v16_pbft_state(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "CREATE TABLE IF NOT EXISTS pbft_state ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  current_view INTEGER,"
        "  last_prepared_blob BLOB"
        ")",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr,
                "MIGRATION FAILURE: CREATE TABLE pbft_state "
                "sqlite error %d: %s\n", rc, err ? err : "(null)");
        if (err) sqlite3_free(err);
        abort();
    }
}

/* Schema v17 migration (2026-07-31) — supply_tracking.total_minted.
 *
 * The column arrived in v0.16 with an ALTER inside
 * nodus_witness_supply_init. That ALTER is UNREACHABLE on exactly the DB
 * that needs it: supply_init returns -2 ("already initialized") as soon
 * as it sees the id = 1 row, several statements BEFORE the ALTER. A DB
 * that already held the row but predated the column could never gain it.
 *
 * That was survivable while supply_get treated a failed prepare as
 * "pre-genesis". It is not any more: supply_get now returns a hard -1 on
 * prepare failure (D1), the epoch_state leaf loader fails closed on that
 * (D3), and compute_state_root fails closed on that (D2) — so a missing
 * column would make the node reject every block and produce no
 * state_root at all.
 *
 * Running it here makes it reachable on EVERY chain-DB open. Inside
 * supply_init it would only be reachable on a genesis (re-)commit —
 * commit_genesis is supply_init's sole production caller
 * (nodus_witness_bft.c:5924), so a plain restart would never repair the
 * DB.
 *
 * HONEST SCOPE: I could not prove such a DB still exists — the chain was
 * wiped. This is a cheap guard, not the repair of a demonstrated
 * incident.
 *
 * Two tolerated sqlite errors, neither fatal:
 *   "duplicate column name" — the normal case on every current DB.
 *   "no such table"         — supply_tracking is created by
 *                             WITNESS_DB_SCHEMA (which runs before this
 *                             in witness_db_open_path) and, on older
 *                             DBs, by supply_init; but hand-built
 *                             fixtures legitimately lack it (see
 *                             setup_pre_v12 in
 *                             tests/test_schema_migration.c:26-65).
 *                             Aborting the process over an absent table
 *                             would be a far worse failure than skipping
 *                             a back-fill that has nothing to back-fill.
 */
static void nodus_witness_db_migrate_v17_supply_total_minted(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE supply_tracking "
        "ADD COLUMN total_minted INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name") &&
            !strstr(msg, "no such table")) {
            fprintf(stderr,
                    "MIGRATION FAILURE: ALTER ADD supply_tracking.total_minted "
                    "sqlite error %d: %s\n", rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}

/* Save current BFT runtime state (current_view + last_prepared) into
 * the pbft_state singleton row.
 *
 * Serialization: w->last_prepared is dumped as raw struct bytes. This
 * is acceptable because the BLOB never crosses a binary version
 * boundary — it is written and read back by the SAME nodus binary
 * across a restart. If a future schema change resizes/reorders
 * last_prepared fields, that change MUST also bump the BLOB encoding
 * (e.g., add a 4-byte version prefix and tolerate version mismatch by
 * loading present=false). For now, raw bytes keep the implementation
 * minimal. last_prepared.present == false is encoded as a NULL BLOB
 * to avoid persisting stale slot bytes. */
int nodus_witness_db_save_pbft_state(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO pbft_state (id, current_view, last_prepared_blob) "
        "VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "  current_view = excluded.current_view, "
        "  last_prepared_blob = excluded.last_prepared_blob",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[H-5] prepare save_pbft_state failed: %s\n",
                sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)w->current_view);
    if (w->last_prepared.present) {
        sqlite3_bind_blob(stmt, 2, &w->last_prepared,
                          (int)sizeof(w->last_prepared), SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 2);
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[H-5] save_pbft_state step failed: %s\n",
                sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* Load BFT runtime state from the pbft_state singleton row.
 *
 * TWO FIELDS, TWO OPPOSITE ANSWERS — and the asymmetry is the point:
 * `last_prepared` IS restored, `current_view` is NOT. Idempotent for
 * fresh DBs (no row → view 0 and w->last_prepared.present at false).
 * The intended call site is the chain-DB open (nodus_witness.c
 * witness_db_open_attempt) AFTER schema migration but BEFORE the witness
 * registers for any T3 dispatch.
 *
 * ── O15P Faz 1 — THE VIEW COUNTER COMES UP AT 0, ALWAYS ──────────────
 *
 * WHAT THIS REPLACES, AND WHY IT IS NOT A TIDY-UP. Every node coming up
 * at the same view is what makes a fleet-wide restart converge, and until
 * now that guarantee was a HUMAN REMEMBERING A MANUAL STEP: the mandatory
 * stop-all deploy tells the operator to `DELETE FROM pbft_state`
 * (docs/DEPLOY_RUNBOOK.md §2.1), so every node came up at 0 together and
 * nobody needed rescuing. That step is load-bearing TOGETHER with a
 * second fact — `w->viewok_proof`, the evidence that justified this
 * node's last view move, is memory-only (nodus/BUGS.md O15N-R2), so a
 * restarted node holds no proof and can rescue nobody. Drop the runbook
 * step without persisting the proof and the fleet comes up split across
 * views with nothing able to serve a proof, converging only through the
 * slow escalation ladder. Resetting here makes "everyone starts from the
 * same point" a property the CODE owns, and the runbook step becomes
 * belt-and-braces instead of the whole belt.
 *
 * WHY DISCARDING IT IS SAFE IN BOTH DIRECTIONS — the whole argument:
 *
 *   A NODE RESTARTING ALONE drops to view 0, is therefore BEHIND its
 *   peers, and PULLS the proof from one of them. That path already
 *   exists and is driven by ordinary traffic, at two call sites, each
 *   gated on the sender being strictly ahead of us:
 *     - nodus_witness_bft.c:5746 — handle_propose, when a PROPOSE names a
 *       view above ours;
 *     - nodus_witness_bft.c:10411 — handle_newview, on the same condition.
 *   Both call bft_viewok_send_request; a verified VIEW_OK proof then
 *   moves the counter through bft_viewok_apply, which is its ONLY other
 *   write site. Being behind is the state the recovery machinery is
 *   built for, so this hands it the case it already handles.
 *
 *   A NODE RESTARTING WITH EVERYONE ELSE finds every peer at 0 too.
 *   Nobody is ahead, nobody needs a proof, and the fleet is already
 *   converged — which is exactly the outcome the runbook step was buying.
 *
 * `last_prepared` IS STILL LOADED, and that is not incidental. It is the
 * prepared-value lock's memory, consulted by
 * nodus_witness_bft_prepared_lock_blocks (nodus_witness_bft.c:10961) —
 * the refusal the quorum-intersection safety argument depends on. That
 * function gates on `present`, `height` and `tx_hash` ONLY; it never
 * reads `current_view`, so zeroing the counter cannot disable it. Nor
 * does it degrade C5: the cert's own `view` travels inside the blob and
 * is what feeds `view_changes[].prepared.view` (:8351) and the outbound
 * VIEW_CHANGE (:8519), so the canonical (height, view, tx_hash)
 * selection still ranks on the view the certificate was PREPARED in,
 * never on the counter this node happens to hold.
 *
 * THE ROW IS NOT TOUCHED — READ-ONLY, DELIBERATELY. This function must
 * not become the runbook's DELETE. witness_db_open_attempt documents its
 * own re-entry after a failed attempt as safe because "load_pbft_state
 * only reads" (nodus_witness.c:454), and the stagef harness reads the
 * stored column as its view-change-completed probe
 * (tests/integration/stagef/tests/test_vset_grow_shrink.sh:129). The
 * SAVE side is likewise unchanged: bft_view_move_finish still persists
 * every view move (:9377). The column keeps its writer and its reader;
 * it simply stops being an INPUT to this node's consensus state.
 *
 * WHAT A RESTART NOW COSTS: one round in which this node declines a
 * PROPOSE for a view it no longer holds and asks for the proof. That is
 * a liveness cost, the same trade every fail-closed gate in the consensus
 * path makes, and it is paid only by a node restarting alone. */
int nodus_witness_db_load_pbft_state(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* Before the query, so "comes up at 0" holds even when the SELECT
     * itself fails: a node that cannot read the row must not be left
     * holding whatever view happened to be in memory. */
    w->current_view = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT current_view, last_prepared_blob "
        "FROM pbft_state WHERE id = 1",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[H-5] prepare load_pbft_state failed: %s\n",
                sqlite3_errmsg(w->db));
        return -1;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            /* READ AND DISCARDED. The column is still selected because
             * the operator is owed the number: without this line a node
             * that had reached view 9 would come up at 0 in silence, and
             * the persisted row — which the harness and the runbook both
             * read — would disagree with the node's live view with
             * nothing in the log explaining why. */
            uint32_t stored = (uint32_t)sqlite3_column_int64(stmt, 0);
            if (stored != 0) {
                fprintf(stderr,
                    "[O15P] stored view %u DISCARDED — this node enters "
                    "consensus at view 0 and pulls a VIEW_OK proof from a "
                    "peer that is ahead; the counter moves only on a "
                    "verified proof\n", stored);
            }
        }
        if (sqlite3_column_type(stmt, 1) != SQLITE_NULL) {
            const void *blob = sqlite3_column_blob(stmt, 1);
            int blob_len = sqlite3_column_bytes(stmt, 1);
            if (blob && blob_len == (int)sizeof(w->last_prepared)) {
                memcpy(&w->last_prepared, blob, sizeof(w->last_prepared));
            } else if (blob && blob_len > 0) {
                /* Size mismatch — likely a schema change between this
                 * binary and the one that wrote the row. Treat as
                 * absent to avoid corrupting in-memory state. */
                fprintf(stderr,
                    "[H-5] last_prepared blob size mismatch (%d vs %zu) "
                    "— ignoring, present=false\n",
                    blob_len, sizeof(w->last_prepared));
                memset(&w->last_prepared, 0, sizeof(w->last_prepared));
            }
        }
    } else if (rc != SQLITE_DONE) {
        fprintf(stderr, "[H-5] load_pbft_state step failed: %s\n",
                sqlite3_errmsg(w->db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}
