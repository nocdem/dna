/**
 * Nodus — Witness Delegation CRUD implementation (Task 13)
 *
 * CRUD primitives over the `delegations` table (design §3.7). See
 * nodus_witness_delegation.h for scope and composite-PK hashing rules.
 *
 * Hashing:
 *     delegator_hash = SHA3-512(0x03 || delegator_pubkey)
 *     validator_hash = SHA3-512(0x03 || validator_pubkey)
 *
 * Both use the same NODUS_TREE_TAG_DELEGATION (0x03) tag — these are
 * per-row index hashes, not the Merkle delegation-tree leaf key, which
 * additionally concatenates the validator pubkey per §3.3. The leaf
 * key matters for the subtree state_root (Phase 8+); the DB PK is only
 * used for row identity and the two O(log N) indexes.
 *
 * All column orders below match the schema in nodus_witness.c
 * WITNESS_DB_SCHEMA exactly. Breaking that alignment corrupts reads.
 */

#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_merkle.h"   /* nodus_merkle_leaf_key */
#include "nodus/nodus_types.h"               /* NODUS_TREE_TAG_DELEGATION */

#include "crypto/utils/qgp_log.h"   /* the HF-6 3a v2 functions log through
                                     * QGP_LOG_*, the project rule; the
                                     * older functions keep fprintf */

#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "WITNESS_DELEGATION"

#define NODUS_DELEGATION_HASH_LEN    64   /* SHA3-512 */
#define NODUS_DELEGATION_PUBKEY_LEN  DNAC_PUBKEY_SIZE

/**
 * Compute the 64-byte tag-prefixed SHA3-512 of a single pubkey, used
 * as either delegator_hash or validator_hash in the delegations table.
 * Pure function — wraps nodus_merkle_leaf_key with the delegation tag.
 */
static void delegation_row_hash(const uint8_t *pubkey,
                                uint8_t out_hash[NODUS_DELEGATION_HASH_LEN]) {
    nodus_merkle_leaf_key(NODUS_TREE_TAG_DELEGATION,
                          pubkey, NODUS_DELEGATION_PUBKEY_LEN, out_hash);
}

/* ── Insert ──────────────────────────────────────────────────────── */

int nodus_delegation_insert(nodus_witness_t *w,
                             const dnac_delegation_record_t *d) {
    if (!w || !w->db || !d) return -1;

    uint8_t delegator_hash[NODUS_DELEGATION_HASH_LEN];
    uint8_t validator_hash[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(d->delegator_pubkey, delegator_hash);
    delegation_row_hash(d->validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO delegations "
        "(delegator_hash, validator_hash, delegator_pubkey, validator_pubkey, "
        " amount, delegated_at_block) "
        "VALUES (?, ?, ?, ?, ?, ?)";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: insert prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, delegator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, validator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, d->delegator_pubkey,
                      NODUS_DELEGATION_PUBKEY_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, d->validator_pubkey,
                      NODUS_DELEGATION_PUBKEY_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)d->amount);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)d->delegated_at_block);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) return 0;
    if (rc == SQLITE_CONSTRAINT) return -2;

    fprintf(stderr, "%s: insert step failed rc=%d: %s\n",
            LOG_TAG, rc, sqlite3_errmsg(w->db));
    return -1;
}

/* ── Helper: populate record from a prepared SELECT row ──────────── */

static void delegation_row_read(sqlite3_stmt *stmt,
                                dnac_delegation_record_t *out) {
    /* Column order matches SELECT used in get/list below:
     *   0: delegator_pubkey (BLOB 2592)
     *   1: validator_pubkey (BLOB 2592)
     *   2: amount            (INTEGER)
     *   3: delegated_at_block(INTEGER)
     */
    memset(out, 0, sizeof(*out));

    const void *dp = sqlite3_column_blob(stmt, 0);
    int dp_len = sqlite3_column_bytes(stmt, 0);
    if (dp && dp_len == NODUS_DELEGATION_PUBKEY_LEN) {
        memcpy(out->delegator_pubkey, dp, NODUS_DELEGATION_PUBKEY_LEN);
    }

    const void *vp = sqlite3_column_blob(stmt, 1);
    int vp_len = sqlite3_column_bytes(stmt, 1);
    if (vp && vp_len == NODUS_DELEGATION_PUBKEY_LEN) {
        memcpy(out->validator_pubkey, vp, NODUS_DELEGATION_PUBKEY_LEN);
    }

    out->amount = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->delegated_at_block = (uint64_t)sqlite3_column_int64(stmt, 3);
}

/* ── Get by (delegator, validator) ──────────────────────────────── */

int nodus_delegation_get(nodus_witness_t *w,
                          const uint8_t *delegator_pubkey,
                          const uint8_t *validator_pubkey,
                          dnac_delegation_record_t *out) {
    if (!w || !w->db || !delegator_pubkey || !validator_pubkey || !out) {
        return -1;
    }

    uint8_t delegator_hash[NODUS_DELEGATION_HASH_LEN];
    uint8_t validator_hash[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(delegator_pubkey, delegator_hash);
    delegation_row_hash(validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT delegator_pubkey, validator_pubkey, amount, "
        "       delegated_at_block "
        "FROM delegations "
        "WHERE delegator_hash = ? AND validator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: get prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, delegator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, validator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        delegation_row_read(stmt, out);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        fprintf(stderr, "%s: get step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }

    sqlite3_finalize(stmt);
    return ret;
}

/* ── Delete ──────────────────────────────────────────────────────── */

int nodus_delegation_delete(nodus_witness_t *w,
                             const uint8_t *delegator_pubkey,
                             const uint8_t *validator_pubkey) {
    if (!w || !w->db || !delegator_pubkey || !validator_pubkey) return -1;

    uint8_t delegator_hash[NODUS_DELEGATION_HASH_LEN];
    uint8_t validator_hash[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(delegator_pubkey, delegator_hash);
    delegation_row_hash(validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "DELETE FROM delegations "
        "WHERE delegator_hash = ? AND validator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: delete prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, delegator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, validator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: delete step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        return -1;
    }

    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}

/* ── Count by delegator (DELEGATE verify rule G) ────────────────── */

int nodus_delegation_count_by_delegator(nodus_witness_t *w,
                                         const uint8_t *delegator_pubkey,
                                         int *count_out) {
    if (!w || !w->db || !delegator_pubkey || !count_out) return -1;

    uint8_t delegator_hash[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(delegator_pubkey, delegator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT COUNT(*) FROM delegations WHERE delegator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: count prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, delegator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        *count_out = sqlite3_column_int(stmt, 0);
        ret = 0;
    } else {
        fprintf(stderr, "%s: count step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }

    sqlite3_finalize(stmt);
    return ret;
}

/* Phase 8 Task 42 — count delegations targeting the given validator.
 * Feeds UNSTAKE Rule A (require NO delegation records exist with
 * validator == signer[0]). */
int nodus_delegation_count_by_validator(nodus_witness_t *w,
                                         const uint8_t *validator_pubkey,
                                         int *count_out) {
    if (!w || !w->db || !validator_pubkey || !count_out) return -1;

    uint8_t validator_hash[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT COUNT(*) FROM delegations WHERE validator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: count_by_validator prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, validator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        *count_out = sqlite3_column_int(stmt, 0);
        ret = 0;
    } else {
        fprintf(stderr, "%s: count_by_validator step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }

    sqlite3_finalize(stmt);
    return ret;
}

/* ── List by hash column (shared impl) ──────────────────────────── */

/**
 * O15O Faz 7 — the LIMIT now truncates against a TOTAL ORDER.
 *
 * WHAT WAS WRONG. The query was "... WHERE %s = ? LIMIT ?" with no
 * ORDER BY at all, so when the filtered set was larger than
 * max_entries the rows that SURVIVED were whichever ones SQLite's scan
 * reached first — index-scan order, i.e. physical row layout. Two
 * witnesses holding the SAME logical rows written in a different order
 * (a resync, a replay, a VACUUM, a table rebuild) keep DIFFERENT
 * subsets. The consumer that made this a chain split was the O15J epoch
 * snapshot's by-validator read (nodus_witness_epoch.c, DELETED by
 * tokenomics-v3 P2 together with nodus_delegation_list_by_validator,
 * its only caller): a differing delegator set there was a differing
 * snapshot_hash, hence a differing state_root.
 *
 * WHY `order_col` IS A PARAMETER. The order key must be the pubkey
 * column that is NOT the filtered one — filtered on delegator_hash ⇒
 * order by validator_pubkey. One caller remains
 * (nodus_delegation_list_by_delegator below, whose live consumer is the
 * witness delegations query in nodus_witness_handlers.c — no consensus
 * path); both strings come from it and from nowhere else (the function
 * is file-static), so the set of values that can reach this snprintf is
 * closed and consists of caller-supplied constants only.
 *
 * WHY THAT IS A TOTAL ORDER. `delegations` is keyed
 * PRIMARY KEY (delegator_hash, validator_hash) (nodus_witness.c:196),
 * and every writer derives those hashes from the pubkey columns with
 * the same tag-prefixed SHA3-512 — this file's delegation_row_hash for
 * the legacy lane, and rtn_del_rec_ok (nodus_witness_rt_native.c:4127)
 * which REFUSES any Ledger V2 effect whose key does not hash from its
 * own pubkeys. So (delegator_pubkey, validator_pubkey) is unique, and
 * once one of the pair is pinned by the WHERE clause the other is
 * distinct across the whole result set. The ordering itself is
 * SQLite's memcmp over BLOBs (collating sequences apply to TEXT only)
 * and both pubkeys are fixed-length, so it is byte order and nothing
 * else. The assumption edge, stated rather than hidden: this rests on
 * SHA3-512 being collision-free, since two pubkeys sharing a hash
 * would share a PK slot.
 *
 * ⚠ NOT A ROWID ORDER, DELIBERATELY. rowid reflects the order rows were
 * WRITTEN, which is exactly the quantity a resync or a replay is free
 * to change, so ordering by it would re-state the bug rather than fix
 * it.
 *
 * REACHABILITY, honestly: the remaining caller passes the query's own
 * `max_results`, so a caller asking for fewer rows than a delegator
 * holds DOES truncate — and gets the same, byte-ordered prefix from
 * every witness it asks.
 */
static int delegation_list_by_hash(nodus_witness_t *w,
                                   const char *hash_col,
                                   const char *order_col,
                                   const uint8_t *hash,
                                   dnac_delegation_record_t *out,
                                   int max_entries,
                                   int *count_out) {
    if (!w || !w->db || !hash_col || !order_col || !hash || !out ||
        !count_out || max_entries <= 0) {
        return -1;
    }

    char sql[256];
    int sql_len = snprintf(sql, sizeof(sql),
        "SELECT delegator_pubkey, validator_pubkey, amount, "
        "       delegated_at_block "
        "FROM delegations WHERE %s = ? ORDER BY %s ASC LIMIT ?",
        hash_col, order_col);
    /* A silent snprintf truncation that cut the tail back to "... = ?"
     * would still PREPARE, and would reinstate the unordered LIMIT this
     * function exists to remove. The buffer is comfortably large for
     * both call sites; this guard is what keeps that a fact rather than
     * an assumption. */
    if (sql_len < 0 || (size_t)sql_len >= sizeof(sql)) {
        fprintf(stderr, "%s: list SQL did not fit (%d bytes) — refusing to "
                "run a query whose ORDER BY may be truncated\n",
                LOG_TAG, sql_len);
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: list prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, max_entries);

    int n = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && n < max_entries) {
        delegation_row_read(stmt, &out[n]);
        n++;
    }

    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "%s: list step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    *count_out = n;
    return 0;
}

int nodus_delegation_list_by_delegator(nodus_witness_t *w,
                                        const uint8_t *delegator_pubkey,
                                        dnac_delegation_record_t *out,
                                        int max_entries,
                                        int *count_out) {
    if (!delegator_pubkey) return -1;
    uint8_t h[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(delegator_pubkey, h);
    /* Filtered on the DELEGATOR, so validator_pubkey is the column that
     * varies across the result set and is therefore the total order. */
    return delegation_list_by_hash(w, "delegator_hash", "validator_pubkey",
                                   h, out, max_entries, count_out);
}

/* ══ HF-6 sub-slice 3a — v2 delegation access ═══════════════════════════
 * Contract: nodus_witness_delegation.h. Keys are bound as given (never
 * hashed); logging through QGP_LOG_*. The functions above are untouched. */

/* Decode one "SELECT delegator_hash, validator_hash, amount,
 * delegated_at_block" row. 0 = well formed, -1 = malformed. */
static int delegation_v2_row_read(sqlite3_stmt *st,
                                  nodus_v2_delegation_row_t *out) {
    memset(out, 0, sizeof(*out));
    const void *d = sqlite3_column_blob(st, 0);
    int dl = sqlite3_column_bytes(st, 0);
    const void *v = sqlite3_column_blob(st, 1);
    int vl = sqlite3_column_bytes(st, 1);
    sqlite3_int64 amount = sqlite3_column_int64(st, 2);
    sqlite3_int64 at = sqlite3_column_int64(st, 3);
    if (!d || dl != (int)NODUS_V2_DELEGATION_KEY_LEN ||
        !v || vl != (int)NODUS_V2_DELEGATION_KEY_LEN ||
        sqlite3_column_type(st, 2) != SQLITE_INTEGER || amount <= 0 ||
        sqlite3_column_type(st, 3) != SQLITE_INTEGER || at < 0) {
        QGP_LOG_ERROR(LOG_TAG, "v2 delegation row malformed (keys %d/%d "
                      "bytes, amount %lld, at %lld)", dl, vl,
                      (long long)amount, (long long)at);
        return -1;
    }
    memcpy(out->delegator_fp, d, NODUS_V2_DELEGATION_KEY_LEN);
    memcpy(out->validator_id, v, NODUS_V2_DELEGATION_KEY_LEN);
    out->amount = (uint64_t)amount;
    out->delegated_at_block = (uint64_t)at;
    return 0;
}

int nodus_delegation_v2_get(nodus_witness_t *w,
                            const uint8_t delegator_fp[NODUS_V2_DELEGATION_KEY_LEN],
                            const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN],
                            nodus_v2_delegation_row_t *out) {
    if (!w || !w->db || !delegator_fp || !validator_id || !out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT delegator_hash, validator_hash, amount, "
            "       delegated_at_block "
            "FROM delegations "
            "WHERE delegator_hash = ? AND validator_hash = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 get prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, delegator_fp, NODUS_V2_DELEGATION_KEY_LEN,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, validator_id, NODUS_V2_DELEGATION_KEY_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) {
        ret = delegation_v2_row_read(st, out) == 0 ? 0 : -1;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "v2 get step failed (rc=%d): %s", rc,
                      sqlite3_errmsg(w->db));
        ret = -1;
    }
    sqlite3_finalize(st);   /* (delegator_hash, validator_hash) is the PK */
    return ret;
}

int nodus_delegation_v2_delete(nodus_witness_t *w,
                               const uint8_t delegator_fp[NODUS_V2_DELEGATION_KEY_LEN],
                               const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN]) {
    if (!w || !w->db || !delegator_fp || !validator_id) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "DELETE FROM delegations "
            "WHERE delegator_hash = ? AND validator_hash = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 delete prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, delegator_fp, NODUS_V2_DELEGATION_KEY_LEN,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, validator_id, NODUS_V2_DELEGATION_KEY_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    int changes = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2 delete step failed (rc=%d): %s", rc,
                      sqlite3_errmsg(w->db));
        return -1;
    }
    return changes == 0 ? 1 : 0;
}

int nodus_delegation_v2_count_by_validator(nodus_witness_t *w,
                                           const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN],
                                           int *count_out) {
    if (!w || !w->db || !validator_id || !count_out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM delegations WHERE validator_hash = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 count_by_validator prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, validator_id, NODUS_V2_DELEGATION_KEY_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) {
        sqlite3_int64 n = sqlite3_column_int64(st, 0);
        if (n >= 0 && n <= INT_MAX) {
            *count_out = (int)n;
            ret = 0;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "v2 count_by_validator: count %lld out "
                          "of range", (long long)n);
        }
    } else {
        QGP_LOG_ERROR(LOG_TAG, "v2 count_by_validator step failed (rc=%d): "
                      "%s", rc, sqlite3_errmsg(w->db));
    }
    sqlite3_finalize(st);
    return ret;
}

int nodus_delegation_v2_list_by_validator(nodus_witness_t *w,
                                          const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN],
                                          nodus_v2_delegation_row_t *out,
                                          int cap,
                                          int *count_out) {
    if (!w || !w->db || !validator_id || !out || !count_out || cap <= 0)
        return -1;
    *count_out = 0;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT delegator_hash, validator_hash, amount, "
            "       delegated_at_block "
            "FROM delegations WHERE validator_hash = ? "
            "ORDER BY delegator_hash ASC",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 list_by_validator prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, validator_id, NODUS_V2_DELEGATION_KEY_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int n = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            QGP_LOG_ERROR(LOG_TAG, "v2 list_by_validator: more than %d rows "
                          "— refusing a truncated set", cap);
            sqlite3_finalize(st);
            return -1;
        }
        if (delegation_v2_row_read(st, &out[n]) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2 list_by_validator step failed (rc=%d)",
                      rc);
        return -1;
    }
    *count_out = n;
    return 0;
}

/* ══ HF-6 sub-slice 3d — the §6.4 leaf body and the full scan ══════════
 * Contract: nodus_witness_delegation.h. */

static void delegation_v2_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

int nodus_delegation_v2_leaf_encode(const nodus_v2_delegation_row_t *row,
                                    uint8_t out[NODUS_V2_DELEGATION_LEAF_BODY_LEN]) {
    if (!row || !out) return -1;
    if (row->amount == 0 || row->amount > (uint64_t)INT64_MAX ||
        row->delegated_at_block > (uint64_t)INT64_MAX)
        return -1;
    memcpy(out, row->delegator_fp, NODUS_V2_DELEGATION_KEY_LEN);
    memcpy(out + 64, row->validator_id, NODUS_V2_DELEGATION_KEY_LEN);
    delegation_v2_put64(out + 128, row->amount);
    delegation_v2_put64(out + 136, row->delegated_at_block);
    return 0;
}

int nodus_delegation_v2_scan(nodus_witness_t *w,
                             nodus_v2_delegation_visit_fn fn, void *ud) {
    if (!w || !w->db || !fn) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT delegator_hash, validator_hash, amount, "
            "       delegated_at_block "
            "FROM delegations "
            "ORDER BY validator_hash ASC, delegator_hash ASC",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 scan prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    nodus_v2_delegation_row_t row;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (delegation_v2_row_read(st, &row) != 0 || fn(&row, ud) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2 scan aborted mid-stream (rc=%d) — a scan "
                      "fault is never a shorter set", rc);
        return -1;
    }
    return 0;
}
