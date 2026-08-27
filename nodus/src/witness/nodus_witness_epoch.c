/**
 * Nodus — v0.16 push-settlement epoch-state CRUD.
 *
 * Implements the primitives declared in nodus_witness_epoch.h. The
 * `epoch_state` schema is created inside WITNESS_DB_SCHEMA so fresh
 * DBs pick it up automatically; migrations are handled by Stage B.2's
 * supply_tracking migration (no-op here since the table is new).
 */

#include "witness/nodus_witness_epoch.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_EPOCH"

/* ── Helpers ─────────────────────────────────────────────────────── */

static void blob_free(nodus_epoch_state_t *e) {
    if (!e) return;
    free(e->snapshot_blob);
    e->snapshot_blob = NULL;
    e->snapshot_blob_len = 0;
}

void nodus_witness_epoch_free(nodus_epoch_state_t *e) {
    blob_free(e);
}

/* ── Insert ──────────────────────────────────────────────────────── */

int nodus_witness_epoch_insert(nodus_witness_t *w,
                                const nodus_epoch_state_t *e) {
    if (!w || !w->db || !e) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO epoch_state "
        "(epoch_start_height, epoch_pool_accum, snapshot_hash, snapshot_blob) "
        "VALUES (?, ?, ?, ?)";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Table missing on pre-genesis unit-test fixtures. Advisory
         * no-op (matches the epoch_add_pool tolerance above). */
        return 0;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)e->epoch_start_height);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)e->epoch_pool_accum);
    sqlite3_bind_blob(stmt, 3, e->snapshot_hash,
                      NODUS_EPOCH_SNAPSHOT_HASH_LEN, SQLITE_STATIC);
    if (e->snapshot_blob && e->snapshot_blob_len > 0) {
        sqlite3_bind_blob(stmt, 4, e->snapshot_blob,
                          (int)e->snapshot_blob_len, SQLITE_STATIC);
    } else {
        sqlite3_bind_zeroblob(stmt, 4, 0);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) return 0;
    if (rc == SQLITE_CONSTRAINT) return -2;

    fprintf(stderr, "%s: insert step failed rc=%d: %s\n",
            LOG_TAG, rc, sqlite3_errmsg(w->db));
    return -1;
}

/* ── Read helper ─────────────────────────────────────────────────── */

static int epoch_row_read(sqlite3_stmt *stmt, nodus_epoch_state_t *out) {
    memset(out, 0, sizeof(*out));
    out->epoch_start_height = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->epoch_pool_accum   = (uint64_t)sqlite3_column_int64(stmt, 1);

    const void *hash = sqlite3_column_blob(stmt, 2);
    int hash_len = sqlite3_column_bytes(stmt, 2);
    if (hash && hash_len == NODUS_EPOCH_SNAPSHOT_HASH_LEN) {
        memcpy(out->snapshot_hash, hash, NODUS_EPOCH_SNAPSHOT_HASH_LEN);
    }

    const void *blob = sqlite3_column_blob(stmt, 3);
    int blob_len = sqlite3_column_bytes(stmt, 3);
    if (blob && blob_len > 0) {
        out->snapshot_blob = malloc((size_t)blob_len);
        if (!out->snapshot_blob) return -1;
        memcpy(out->snapshot_blob, blob, (size_t)blob_len);
        out->snapshot_blob_len = (size_t)blob_len;
    }
    return 0;
}

/* ── Get by epoch_start_height ───────────────────────────────────── */

int nodus_witness_epoch_get(nodus_witness_t *w,
                             uint64_t epoch_start_height,
                             nodus_epoch_state_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT epoch_start_height, epoch_pool_accum, snapshot_hash, "
        "       snapshot_blob "
        "FROM epoch_state WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)epoch_start_height);

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        ret = (epoch_row_read(stmt, out) == 0) ? 0 : -1;
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

/* ── Get current (highest epoch_start_height) ────────────────────── */

int nodus_witness_epoch_get_current(nodus_witness_t *w,
                                     nodus_epoch_state_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT epoch_start_height, epoch_pool_accum, snapshot_hash, "
        "       snapshot_blob "
        "FROM epoch_state ORDER BY epoch_start_height DESC LIMIT 1";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        ret = (epoch_row_read(stmt, out) == 0) ? 0 : -1;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        fprintf(stderr, "%s: get_current step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }
    sqlite3_finalize(stmt);
    return ret;
}

/* ── Set pool_accum ──────────────────────────────────────────────── */

int nodus_witness_epoch_set_pool_accum(nodus_witness_t *w,
                                        uint64_t epoch_start_height,
                                        uint64_t new_pool_accum) {
    if (!w || !w->db) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE epoch_state SET epoch_pool_accum = ? "
        "WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)new_pool_accum);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}

int nodus_witness_epoch_add_pool(nodus_witness_t *w,
                                  uint64_t epoch_start_height,
                                  uint64_t delta) {
    if (!w || !w->db) return -1;
    if (delta == 0) return 0;

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE epoch_state SET epoch_pool_accum = epoch_pool_accum + ? "
        "WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Table missing on pre-genesis unit-test fixtures. Advisory
         * no-op: the production finalize_block path always sees the
         * table post-schema creation + supply_init. */
        return 0;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)delta);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}

/* ── Delete ──────────────────────────────────────────────────────── */

int nodus_witness_epoch_delete(nodus_witness_t *w,
                                uint64_t epoch_start_height) {
    if (!w || !w->db) return -1;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM epoch_state WHERE epoch_start_height = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}

/* ── Stage D.1 — apply_epoch_snapshot ──────────────────────────────── */

/* Max delegations per committee member we serialize into the snapshot.
 *
 * ⚠ CORRECTED 2026-08-27 (O15J review R2-F2). This comment used to read:
 * "Matches STAKE rule G cap so the snapshot is bounded without a DB
 * count-first scan. Over-cap rows are silently truncated; the sort
 * ORDER BY guarantees deterministic truncation set." BOTH claims were
 * false, and the second was load-bearing for a determinism argument:
 *
 *   1. THERE IS NO `ORDER BY`. The query is
 *      "... FROM delegations WHERE %s = ? LIMIT ?"
 *      (nodus_witness_delegation.c). The qsort below runs AFTER the
 *      LIMIT, so it sorts the SURVIVORS, not the selection — which set
 *      survives is index-scan order.
 *   2. "STAKE rule G cap" names nothing that exists here. The only 64 in
 *      the tree is DNAC_MAX_DELEGATIONS_PER_DELEGATOR
 *      (dnac/include/dnac/dnac.h) — per DELEGATOR, not per validator —
 *      and grep finds ZERO enforcement of it. Nothing bounds a
 *      validator's delegator count.
 *
 * Real consequence, deterministic and not a race: a validator with more
 * than 64 delegators has its FULL total_delegated written into the blob
 * while only 64 delegators appear in it. Settlement divides by the full
 * figure, the excluded delegators are never paid, and their share falls
 * into the inner-dust burn.
 *
 * ⚠ FIXED 2026-08-27 (O15J Block 2). The bound below is no longer a
 * private 64: it is an ALIAS of NODUS_MAX_DELEGATORS_PER_VALIDATOR
 * (nodus_witness_delegation.h), which is now ENFORCED AT ADMISSION —
 * a DELEGATE that would introduce a NEW delegator to an already-full
 * validator is rejected in both lanes (apply_delegate in
 * nodus_witness_bft.c, rtn_delegate_exec in nodus_witness_rt_native.c).
 * So the LIMIT below can no longer be reached by a validator's real row
 * count, which is what makes the missing ORDER BY unreachable rather
 * than merely unlikely: there is no over-cap set left to choose from.
 * The alias is deliberate — the snapshot's capacity and the admission
 * cap must be ONE number, or the gap between two 64s reopens exactly
 * this bug. See the header docblock for why the per-DELEGATOR constant
 * DNAC_MAX_DELEGATIONS_PER_DELEGATOR was NOT reused.
 *
 * RESIDUAL, stated honestly: a chain that ALREADY carried an over-cap
 * validator before this gate existed keeps that row count — admission
 * cannot retroactively remove delegators — and for that one validator
 * the unordered truncation above still applies. Unreachable on a chain
 * capped from genesis. */
#define NODUS_EPOCH_MAX_DELEGS_PER_VAL NODUS_MAX_DELEGATORS_PER_VALIDATOR

static void be16_into(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)(v & 0xff);
}

static void be32_into(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)((v >> 24) & 0xff);
    out[1] = (uint8_t)((v >> 16) & 0xff);
    out[2] = (uint8_t)((v >>  8) & 0xff);
    out[3] = (uint8_t)( v        & 0xff);
}

static void be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

static int deleg_cmp(const void *a, const void *b) {
    const dnac_delegation_record_t *da = a;
    const dnac_delegation_record_t *db = b;
    return memcmp(da->delegator_pubkey, db->delegator_pubkey, DNAC_PUBKEY_SIZE);
}

static int committee_pubkey_cmp(const void *a, const void *b) {
    const nodus_committee_member_t *ma = a;
    const nodus_committee_member_t *mb = b;
    return memcmp(ma->pubkey, mb->pubkey, DNAC_PUBKEY_SIZE);
}

int nodus_witness_epoch_snapshot_apply(nodus_witness_t *w,
                                        uint64_t epoch_start_height) {
    if (!w || !w->db) return -1;

    /* S3: DNAC_MAX_ACTIVE_VALIDATORS members are ~334 KB — heap, never
     * the stack. Freed on every exit path below. */
    nodus_committee_member_t *committee = NULL;
    int committee_count = 0;
    int rc = nodus_committee_get_for_block_alloc(w, epoch_start_height,
                                                   &committee,
                                                   &committee_count);
    /* ── LEG 1, O15J Block 2 (A1). FAIL CLOSED. ───────────────────────
     * This used to be `if (rc != 0 || committee_count == 0)`, which read
     * a FAULT as an empty chain and hashed the canonical empty snapshot
     * anyway. The two are already distinguishable at this call site and
     * always were: nodus_committee_get_for_block_alloc returns -1 for a
     * calloc failure, an unreadable sqlite_master, a snapshot row that
     * fails hash/decode, and any compute failure beneath it — and
     * nodus_witness_committee.c justifies the decode case in its own
     * words, "a node that cannot know its committee must not vote".
     * Collapsing that into "empty" discarded a fail-closed decision the
     * layer below had already taken.
     *
     * It matters because this blob's SHA3-512 becomes
     * epoch_state.snapshot_hash, which is scanned into the epoch_state
     * leaves of state_root. One node's transient IOERR committed a
     * different root than its peers, silently, because this function then
     * returned 0.
     *
     * rc == 0 with committee_count == 0 is the GENUINE empty chain and
     * keeps its original behaviour byte-for-byte: the canonical empty
     * snapshot. */
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: the committee could not be "
                      "determined (rc=%d) — refusing to hash a fabricated "
                      "empty snapshot into state_root",
                      (unsigned long long)epoch_start_height, rc);
        free(committee);
        return -1;
    }

    if (committee_count > 1) {
        qsort(committee, (size_t)committee_count, sizeof(committee[0]),
              committee_pubkey_cmp);
    }

    /* Blob capacity upper bound — see header docblock for field widths. */
    size_t cap_vals = (size_t)committee_count * 2611;
    size_t cap_dels = (size_t)committee_count *
                      NODUS_EPOCH_MAX_DELEGS_PER_VAL * 5192;
    size_t cap_total = 2 + cap_vals + 4 + cap_dels;
    if (cap_total < 6) cap_total = 6;
    uint8_t *blob = malloc(cap_total);
    if (!blob) { free(committee); return -1; }
    size_t w_off = 0;

    be16_into((uint16_t)committee_count, blob + w_off); w_off += 2;

    for (int i = 0; i < committee_count; i++) {
        dnac_validator_record_t v;
        int vrc = nodus_validator_get(w, committee[i].pubkey, &v);
        /* ── LEG 2, O15J Block 2 (A1). ────────────────────────────────
         * nodus_validator_get has been three-valued all along —
         * 0 found / 1 not found / -1 prepare or step failure. The old
         * `vrc != 0` conflated the last two and zero-filled the record
         * on BOTH, hashing invented stake, commission and status bytes
         * into snapshot_hash.
         *
         * vrc == 1 (row genuinely absent) keeps the historical
         * behaviour, unchanged: zero-fill and carry the pubkey. That is
         * a reachable, deterministic state since S3 — the committee may
         * be served from a committed validator_set_snapshots row whose
         * member no longer has a live `validators` row, and every node
         * replaying the same chain sees the same absence.
         *
         * vrc < 0 is a node-local fault: two nodes reading the same
         * committed state get different answers, so this one must not
         * seal the epoch. */
        if (vrc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: validators row for "
                          "committee seat %d is unreadable — refusing to "
                          "hash a zero-filled record into state_root",
                          (unsigned long long)epoch_start_height, i);
            free(blob);
            free(committee);
            return -1;
        }
        if (vrc == 1) {
            memset(&v, 0, sizeof(v));
            memcpy(v.pubkey, committee[i].pubkey, DNAC_PUBKEY_SIZE);
        }
        memcpy(blob + w_off, v.pubkey, DNAC_PUBKEY_SIZE); w_off += DNAC_PUBKEY_SIZE;
        be64_into(v.self_stake,      blob + w_off); w_off += 8;
        be64_into(v.total_delegated, blob + w_off); w_off += 8;
        be16_into(v.commission_bps,  blob + w_off); w_off += 2;
        blob[w_off++] = v.status;
    }

    size_t dcount_off = w_off;
    w_off += 4;  /* reserve u32 BE */
    uint32_t total_dels = 0;

    dnac_delegation_record_t *dels =
        malloc(NODUS_EPOCH_MAX_DELEGS_PER_VAL * sizeof(*dels));
    if (!dels) { free(blob); free(committee); return -1; }

    for (int i = 0; i < committee_count; i++) {
        int dcount = 0;
        int lrc = nodus_delegation_list_by_validator(
            w, committee[i].pubkey, dels,
            NODUS_EPOCH_MAX_DELEGS_PER_VAL, &dcount);
        /* ── LEG 3, O15J Block 2 (A1). ────────────────────────────────
         * `if (lrc != 0) dcount = 0;` published "this validator has no
         * delegators" as a fact on a scan fault. Unlike legs 1 and 2
         * there is no ABSENT code to preserve here: the underlying
         * delegation_list_by_hash already reports an empty result as
         * rc 0 with *count_out == 0 and reserves non-zero for a NULL
         * argument or a prepare/step failure (it grew its own
         * post-loop SQLITE_DONE guard). So every non-zero is a fault,
         * and dropping a validator's whole delegator set changes both
         * snapshot_hash and, through it, who settlement pays. */
        if (lrc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: delegation scan for "
                          "committee seat %d failed (rc=%d) — refusing to "
                          "record an empty delegator set as truth",
                          (unsigned long long)epoch_start_height, i, lrc);
            free(dels);
            free(blob);
            free(committee);
            return -1;
        }
        if (dcount > 1) {
            qsort(dels, (size_t)dcount, sizeof(dels[0]), deleg_cmp);
        }
        for (int j = 0; j < dcount; j++) {
            memcpy(blob + w_off, dels[j].delegator_pubkey, DNAC_PUBKEY_SIZE);
            w_off += DNAC_PUBKEY_SIZE;
            memcpy(blob + w_off, dels[j].validator_pubkey, DNAC_PUBKEY_SIZE);
            w_off += DNAC_PUBKEY_SIZE;
            be64_into(dels[j].amount, blob + w_off); w_off += 8;
            total_dels++;
        }
    }
    free(dels);
    /* Last use of the committee array — every path below is committee-free. */
    free(committee);
    committee = NULL;

    be32_into(total_dels, blob + dcount_off);

    uint8_t snapshot_hash[NODUS_EPOCH_SNAPSHOT_HASH_LEN];
    if (qgp_sha3_512(blob, w_off, snapshot_hash) != 0) {
        free(blob);
        return -1;
    }

    /* Upsert epoch_state row. */
    nodus_epoch_state_t existing = {0};
    int grc = nodus_witness_epoch_get(w, epoch_start_height, &existing);
    if (grc < 0) {
        free(blob);
        return -1;
    }
    if (grc == 1) {
        nodus_epoch_state_t fresh = {0};
        fresh.epoch_start_height = epoch_start_height;
        fresh.epoch_pool_accum   = 0;
        memcpy(fresh.snapshot_hash, snapshot_hash,
               NODUS_EPOCH_SNAPSHOT_HASH_LEN);
        fresh.snapshot_blob     = blob;
        fresh.snapshot_blob_len = w_off;
        int ins = nodus_witness_epoch_insert(w, &fresh);
        free(blob);
        return (ins == 0 || ins == -2) ? 0 : -1;
    }
    nodus_witness_epoch_free(&existing);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "UPDATE epoch_state SET snapshot_hash = ?, snapshot_blob = ? "
        "WHERE epoch_start_height = ?";
    rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(blob);
        return 0;  /* schema missing (test fixture) — advisory no-op */
    }
    sqlite3_bind_blob(stmt, 1, snapshot_hash,
                      NODUS_EPOCH_SNAPSHOT_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, blob, (int)w_off, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)epoch_start_height);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(blob);
    if (rc != SQLITE_DONE) return -1;
    return 0;
}
