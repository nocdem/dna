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

/* ── Update (amount, delegated_at_block) ────────────────────────── */

int nodus_delegation_update(nodus_witness_t *w,
                             const dnac_delegation_record_t *d) {
    if (!w || !w->db || !d) return -1;

    uint8_t delegator_hash[NODUS_DELEGATION_HASH_LEN];
    uint8_t validator_hash[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(d->delegator_pubkey, delegator_hash);
    delegation_row_hash(d->validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE delegations "
        "SET amount = ?, delegated_at_block = ? "
        "WHERE delegator_hash = ? AND validator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: update prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)d->amount);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)d->delegated_at_block);
    sqlite3_bind_blob(stmt, 3, delegator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, validator_hash, NODUS_DELEGATION_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: update step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        return -1;
    }

    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
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

static int delegation_list_by_hash(nodus_witness_t *w,
                                   const char *hash_col,
                                   const uint8_t *hash,
                                   dnac_delegation_record_t *out,
                                   int max_entries,
                                   int *count_out) {
    if (!w || !w->db || !hash_col || !hash || !out || !count_out ||
        max_entries <= 0) {
        return -1;
    }

    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT delegator_pubkey, validator_pubkey, amount, "
        "       delegated_at_block "
        "FROM delegations WHERE %s = ? LIMIT ?", hash_col);

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
    return delegation_list_by_hash(w, "delegator_hash", h, out, max_entries,
                                   count_out);
}

int nodus_delegation_list_by_validator(nodus_witness_t *w,
                                        const uint8_t *validator_pubkey,
                                        dnac_delegation_record_t *out,
                                        int max_entries,
                                        int *count_out) {
    if (!validator_pubkey) return -1;
    uint8_t h[NODUS_DELEGATION_HASH_LEN];
    delegation_row_hash(validator_pubkey, h);
    return delegation_list_by_hash(w, "validator_hash", h, out, max_entries,
                                   count_out);
}
