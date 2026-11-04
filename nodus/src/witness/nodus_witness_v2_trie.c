/**
 * @file nodus_witness_v2_trie.c
 * @brief HF-9 WP2 — the eight keyed Patricia tries over SQLite. Contract:
 *        nodus_witness_v2_trie.h. Plan docs/plans/approved/2026-11-04-hf9.md
 *        §4 (legs), §5 (integration), §7.2 step 4 / §7.4 (build from rows).
 */

#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_merkle.h"   /* nodus_witness_merkle_leaf_hash */
#include "witness/nodus_witness_v2_schema.h"

#include "evm/trie/evm_trie.h"
#include "evm/trie/evm_trie_full.h"

#include "dnac/dnac.h"                      /* DNAC_PUBKEY_SIZE            */
#include "dnac/ledger_ids.h"                /* DNA_DOMAIN_CORE             */
#include "dnac/ledger_roots_v2.h"
#include "dnac/manifest_wire.h"             /* dna_claims_entry_t / leaf   */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2TRIE"

/* ── the node store (plan §5.1) ───────────────────────────────────────
 * The EVM store contract (evm_trie.h STORE CONTRACT) over v2_trie_nodes.
 * Every sqlite3_bind_* result is checked before the statement is stepped
 * (HF-9 review row Z-51): a discarded bind leaves the parameter NULL and
 * the step then runs with the wrong key or value. */

static int ts_get(void *ctx, const uint8_t digest[64], uint8_t **rlp,
                  size_t *len) {
    sqlite3 *db = (sqlite3 *)ctx;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT rlp FROM v2_trie_nodes WHERE digest = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    if (sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -2;
    }
    int rc = sqlite3_step(st);
    int ret = -2;
    if (rc == SQLITE_DONE) {
        ret = 1;
    } else if (rc == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        const void *b = sqlite3_column_blob(st, 0);
        if (n > 0 && b) {
            uint8_t *c = malloc((size_t)n);
            if (c) {
                memcpy(c, b, (size_t)n);
                *rlp = c;
                *len = (size_t)n;
                ret = 0;
            }
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* INSERT if absent; an existing digest must hold the SAME bytes — a
 * different node under one digest is this node's corruption (FAULT). */
static int ts_put(void *ctx, const uint8_t digest[64], const uint8_t *rlp,
                  size_t len) {
    sqlite3 *db = (sqlite3 *)ctx;
    sqlite3_stmt *st = NULL;
    if (len == 0 || len > INT32_MAX) return -2;
    if (sqlite3_prepare_v2(db,
            "SELECT rlp FROM v2_trie_nodes WHERE digest = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    if (sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -2;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        int same = (size_t)sqlite3_column_bytes(st, 0) == len &&
                   memcmp(sqlite3_column_blob(st, 0), rlp, len) == 0;
        sqlite3_finalize(st);
        if (!same) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "trie node store: one digest, two bodies");
            return -2;
        }
        return 0;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -2;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO v2_trie_nodes (digest, rlp) VALUES (?1, ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    if (sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, rlp, (int)len, SQLITE_TRANSIENT)
            != SQLITE_OK) {
        sqlite3_finalize(st);
        return -2;
    }
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -2;
}

static void store_of(nodus_witness_t *w, evm_trie_store_t *s) {
    s->ctx = w->db;
    s->get = ts_get;
    s->put = ts_put;
}

/* ── the legs: table, primary key, SELECT, row reader ─────────────────── */

typedef struct {
    uint8_t key[64];       /* canonical key bytes (names: 3..36, others
                            * 64 or 8)                                    */
    size_t  key_len;
    uint8_t val[64];       /* the leg's leaf value                         */
    int     selected;      /* 0 = the row is not part of this leg (claims
                            * of another domain): treated as absent       */
} v2t_item_t;

static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)v; v >>= 8; }
}

/* an integer-keyed leg: the dirty key and the lookup parameter are INTEGER
 * (segments, vset, attendance); the others are BLOB */
static int leg_int_keyed(int leg) { return leg >= 6; }

static int leg_valid(int leg) {
    return leg >= NODUS_V2_TRIE_LEG_UTXO && leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
}

/* the SELECT of each leg (column order = its reader's) and the primary-key
 * column for the point lookup */
static const struct {
    const char *select;
    const char *pk;
} LEG_SQL[NODUS_V2_TRIE_LEGS + 1] = {
    [0] = { NULL, NULL },
    [NODUS_V2_TRIE_LEG_UTXO] = {
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "unlock_block FROM utxo_set", "nullifier" },
    [NODUS_V2_TRIE_LEG_TOKENS] = {
        "SELECT token_id, name, symbol, decimals, supply, creator_fp, "
        "flags, block_height FROM tokens", "token_id" },
    [NODUS_V2_TRIE_LEG_CLAIMS] = {
        "SELECT nullifier, manifest_hash, leaf_index, amount, "
        "claimed_height, target_domain_id FROM v2_claims_spent",
        "nullifier" },
    [NODUS_V2_TRIE_LEG_NAMES] = {
        "SELECT name, owner, registered_height, typeof(name), "
        "typeof(owner), typeof(registered_height) FROM v2_names", "name" },
    [NODUS_V2_TRIE_LEG_REGISTRY] = {
        "SELECT node_fp, node_pk, payee_fp, bond, status, "
        "registered_height, exit_height, fail_streak, grace_until, "
        "typeof(node_fp), typeof(node_pk), typeof(payee_fp), typeof(bond), "
        "typeof(status), typeof(registered_height), typeof(exit_height), "
        "typeof(fail_streak), typeof(grace_until) FROM v2_storage_nodes",
        "node_fp" },
    [NODUS_V2_TRIE_LEG_SEGMENTS] = {
        "SELECT k, root, published_height FROM v2_storage_segments", "k" },
    [NODUS_V2_TRIE_LEG_VSET] = {
        "SELECT epoch_start, snapshot_hash FROM validator_set_snapshots",
        "epoch_start" },
    [NODUS_V2_TRIE_LEG_ATTENDANCE] = {
        "SELECT epoch_start, digest FROM v2_attendance_epoch",
        "epoch_start" }
};

/* L1 utxo. Mirror of load_utxo_leaves (nodus_witness_merkle.c:193-304):
 * the same columns, the negative-unlock check and the 64-byte checks; the
 * trie value is the OUTER hash SHA3-512(0x00 ‖ D) (decision D21), D the
 * unchanged nodus_witness_merkle_leaf_hash output. */
static int rd_utxo(sqlite3_stmt *st, v2t_item_t *it) {
    const uint8_t *nullifier = sqlite3_column_blob(st, 0);
    int nlen = sqlite3_column_bytes(st, 0);
    const char *owner = (const char *)sqlite3_column_text(st, 1);
    uint64_t amount = (uint64_t)sqlite3_column_int64(st, 2);
    const uint8_t *token_id = sqlite3_column_blob(st, 3);
    int tlen = sqlite3_column_bytes(st, 3);
    const uint8_t *tx_hash = sqlite3_column_blob(st, 4);
    int thlen = sqlite3_column_bytes(st, 4);
    uint32_t output_index = (uint32_t)sqlite3_column_int(st, 5);
    sqlite3_int64 unlock_raw = sqlite3_column_int64(st, 6);
    if (unlock_raw < 0) {
        QGP_LOG_ERROR(LOG_TAG, "utxo row: negative unlock_block %lld",
                      (long long)unlock_raw);
        return -1;
    }
    if (!nullifier || nlen != 64 || !owner || !token_id || tlen != 64 ||
        !tx_hash || thlen != 64) {
        QGP_LOG_ERROR(LOG_TAG, "utxo row malformed (nlen=%d tlen=%d "
                      "thlen=%d owner=%s)", nlen, tlen, thlen,
                      owner ? "present" : "NULL");
        return -1;
    }
    uint8_t pre[65];
    pre[0] = 0x00;
    if (nodus_witness_merkle_leaf_hash(nullifier, owner, amount, token_id,
                                       tx_hash, output_index, pre + 1,
                                       (uint64_t)unlock_raw) != 0)
        return -1;
    if (qgp_sha3_512(pre, sizeof(pre), it->val) != 0) return -1;
    memcpy(it->key, nullifier, 64);
    it->key_len = 64;
    it->selected = 1;
    return 0;
}

/* L2 tokens. Mirror of nodus_witness_token_root_v2
 * (nodus_witness_roots_v2.c:37-140): the NULL checks, the 64-byte id, the
 * decimals / flags range check; timestamp is not read (D7). */
static int rd_tokens(sqlite3_stmt *st, v2t_item_t *it) {
    const void *tid = sqlite3_column_blob(st, 0);
    int tid_len = sqlite3_column_bytes(st, 0);
    const unsigned char *name = sqlite3_column_text(st, 1);
    const unsigned char *symbol = sqlite3_column_text(st, 2);
    const unsigned char *cfp = sqlite3_column_text(st, 5);
    if (!tid || tid_len != DNA_V2_TOKEN_ID_LEN || !name || !symbol || !cfp) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "token row malformed");
        return -1;
    }
    int dec = sqlite3_column_int(st, 3);
    int flg = sqlite3_column_int(st, 6);
    if (dec < 0 || dec > 255 || flg < 0 || flg > 255) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "token row out-of-range decimals/flags");
        return -1;
    }
    dna_v2_token_leaf_t L;
    memset(&L, 0, sizeof(L));
    memcpy(L.token_id, tid, DNA_V2_TOKEN_ID_LEN);
    L.name = (const char *)name;       L.name_len = strlen(L.name);
    L.symbol = (const char *)symbol;   L.symbol_len = strlen(L.symbol);
    L.creator_fp = (const char *)cfp;  L.creator_fp_len = strlen(L.creator_fp);
    L.decimals = (uint8_t)dec;
    L.supply = (uint64_t)sqlite3_column_int64(st, 4);
    L.flags = (uint8_t)flg;
    L.block_height = (uint64_t)sqlite3_column_int64(st, 7);
    if (dna_v2_token_leaf_hash(&L, it->val) != 0) return -1;
    memcpy(it->key, tid, DNA_V2_TOKEN_ID_LEN);
    it->key_len = DNA_V2_TOKEN_ID_LEN;
    it->selected = 1;
    return 0;
}

/* L3 claims (CORE). Mirror of nodus_witness_claims_root_v2
 * (nodus_witness_v2_claims.c:126-188) for the one domain that has a
 * caller, CORE: a row of another target_domain_id is not part of the leg
 * (selected = 0, not validated — the loader's WHERE filter); a CORE row
 * is checked exactly as the loader does. */
static int rd_claims(sqlite3_stmt *st, v2t_item_t *it) {
    sqlite3_int64 dom = sqlite3_column_int64(st, 5);
    if (dom != (sqlite3_int64)DNA_DOMAIN_CORE) {
        it->selected = 0;
        return 0;
    }
    const void *nul = sqlite3_column_blob(st, 0);
    const void *mh = sqlite3_column_blob(st, 1);
    sqlite3_int64 idx = sqlite3_column_int64(st, 2);
    sqlite3_int64 amt = sqlite3_column_int64(st, 3);
    sqlite3_int64 hgt = sqlite3_column_int64(st, 4);
    if (!nul || sqlite3_column_bytes(st, 0) != 64 ||
        !mh || sqlite3_column_bytes(st, 1) != 64 ||
        idx < 0 || amt < 1 || hgt < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "claim row malformed");
        return -1;
    }
    dna_claims_entry_t e;
    memset(&e, 0, sizeof(e));
    memcpy(e.nullifier, nul, 64);
    memcpy(e.manifest_hash, mh, 64);
    e.target_domain_id = DNA_DOMAIN_CORE;
    e.leaf_index = (uint64_t)idx;
    e.amount = (uint64_t)amt;
    e.claimed_height = (uint64_t)hgt;
    if (dna_claims_leaf_hash(&e, it->val) != 0) return -1;
    memcpy(it->key, nul, 64);
    it->key_len = 64;
    it->selected = 1;
    return 0;
}

/* L4 names. Mirror of names_root_v2 (nodus_witness_roots_v2.c:254-320):
 * storage types, lengths 3..36 / 64, height >= 1, the a-z0-9 alphabet. */
static int rd_names(sqlite3_stmt *st, v2t_item_t *it) {
    const uint8_t *nm = sqlite3_column_blob(st, 0);
    int nl = sqlite3_column_bytes(st, 0);
    const uint8_t *ow = sqlite3_column_blob(st, 1);
    int ol = sqlite3_column_bytes(st, 1);
    sqlite3_int64 h = sqlite3_column_int64(st, 2);
    const char *tn = (const char *)sqlite3_column_text(st, 3);
    const char *to = (const char *)sqlite3_column_text(st, 4);
    const char *th = (const char *)sqlite3_column_text(st, 5);
    int ok = nm && ow && tn && to && th &&
             strcmp(tn, "blob") == 0 && strcmp(to, "blob") == 0 &&
             strcmp(th, "integer") == 0 &&
             nl >= 3 && nl <= (int)DNA_V2_NAME_MAX_LEN && ol == 64 &&
             h >= 1;
    for (int i = 0; ok && i < nl; i++)
        ok = (nm[i] >= 'a' && nm[i] <= 'z') ||
             (nm[i] >= '0' && nm[i] <= '9');
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_names row malformed");
        return -1;
    }
    dna_v2_name_row_t r;
    memset(&r, 0, sizeof(r));
    r.name_len = (uint8_t)nl;
    memcpy(r.name, nm, (size_t)nl);
    memcpy(r.owner, ow, 64);
    r.registered_height = (uint64_t)h;
    if (dna_v2_name_leaf_hash(&r, it->val) != 0) return -1;
    memcpy(it->key, nm, (size_t)nl);
    it->key_len = (size_t)nl;
    it->selected = 1;
    return 0;
}

/* L5 registry (every row, RELEASED included). Mirror of storage_scan
 * (nodus_witness_roots_v2.c:440-533): typed columns, lengths, ranges, and
 * node_fp = SHA3-512(node_pk). */
#define REG_COLS 9
static int rd_registry(sqlite3_stmt *st, v2t_item_t *it) {
    static const char *const want_type[REG_COLS] = {
        "blob", "blob", "blob", "integer", "integer", "integer", "integer",
        "integer", "integer"
    };
    int ok = 1;
    for (int c = 0; c < REG_COLS && ok; c++) {
        const char *t = (const char *)sqlite3_column_text(st, REG_COLS + c);
        ok = t && strcmp(t, want_type[c]) == 0;
    }
    const uint8_t *fp = sqlite3_column_blob(st, 0);
    const uint8_t *pk = sqlite3_column_blob(st, 1);
    const uint8_t *py = sqlite3_column_blob(st, 2);
    sqlite3_int64 bond = sqlite3_column_int64(st, 3);
    sqlite3_int64 stat = sqlite3_column_int64(st, 4);
    sqlite3_int64 rh = sqlite3_column_int64(st, 5);
    sqlite3_int64 eh = sqlite3_column_int64(st, 6);
    sqlite3_int64 fs = sqlite3_column_int64(st, 7);
    sqlite3_int64 gu = sqlite3_column_int64(st, 8);
    ok = ok && fp && pk && py &&
         sqlite3_column_bytes(st, 0) == 64 &&
         sqlite3_column_bytes(st, 1) == DNAC_PUBKEY_SIZE &&
         sqlite3_column_bytes(st, 2) == 64 &&
         bond >= 0 && rh >= 1 && eh >= 0 &&
         fs >= 0 && fs <= (sqlite3_int64)UINT32_MAX && gu >= 0 &&
         stat >= (sqlite3_int64)DNA_V2_STORAGE_ACTIVE &&
         stat <= (sqlite3_int64)DNA_V2_STORAGE_RELEASED;
    if (ok) {
        uint8_t want_fp[64];
        if (qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, want_fp) != 0) return -1;
        ok = memcmp(want_fp, fp, 64) == 0;
    }
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_nodes row malformed");
        return -1;
    }
    dna_v2_storage_node_row_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.node_fp, fp, 64);
    memcpy(r.payee_fp, py, 64);
    r.bond = (uint64_t)bond;
    r.status = (uint8_t)stat;
    r.registered_height = (uint64_t)rh;
    r.exit_height = (uint64_t)eh;
    r.fail_streak = (uint32_t)fs;
    r.grace_until = (uint64_t)gu;
    if (dna_v2_storage_node_leaf_hash(&r, it->val) != 0) return -1;
    memcpy(it->key, fp, 64);
    it->key_len = 64;
    it->selected = 1;
    return 0;
}

/* L6 segments. Mirror of st_segments_load's row checks
 * (nodus_witness_v2_storage.c:352-411): typed INTEGER k and
 * published_height in 1..INT64_MAX, a 64-byte BLOB root. The loader's
 * k == 1..n contiguity is a whole-table property, checked in the build
 * scan. */
static int rd_segments(sqlite3_stmt *st, v2t_item_t *it) {
    if (sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
        sqlite3_column_type(st, 2) != SQLITE_INTEGER ||
        sqlite3_column_type(st, 1) != SQLITE_BLOB ||
        sqlite3_column_bytes(st, 1) != 64) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_segments row malformed");
        return -1;
    }
    sqlite3_int64 k = sqlite3_column_int64(st, 0);
    sqlite3_int64 ph = sqlite3_column_int64(st, 2);
    const void *root = sqlite3_column_blob(st, 1);
    if (k < 1 || ph < 1 || !root) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_segments row out of range");
        return -1;
    }
    if (dna_v2_segment_leaf_hash_v2((uint64_t)k, root, (uint64_t)ph,
                                    it->val) != 0)
        return -1;
    put_be64((uint64_t)k, it->key);
    it->key_len = 8;
    it->selected = 1;
    return 0;
}

/* L7 vset. Mirror of nodus_witness_vset_root (nodus_witness_vset.c:
 * 298-366): a non-NULL 64-byte snapshot_hash; epoch_start as the loader
 * casts it. */
static int rd_vset(sqlite3_stmt *st, v2t_item_t *it) {
    const void *h = sqlite3_column_blob(st, 1);
    int hl = sqlite3_column_bytes(st, 1);
    if (!h || hl != DNA_V2_ROOT_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "vset row hash malformed (%d B)", hl);
        return -1;
    }
    uint64_t epoch = (uint64_t)sqlite3_column_int64(st, 0);
    if (dna_v2_vset_leaf_hash(epoch, h, it->val) != 0) return -1;
    put_be64(epoch, it->key);
    it->key_len = 8;
    it->selected = 1;
    return 0;
}

/* L8 attendance. Mirror of nodus_witness_attendance_root
 * (nodus_witness_roots_v2.c:615-660): a non-NULL 64-byte digest. */
static int rd_attendance(sqlite3_stmt *st, v2t_item_t *it) {
    const void *dg = sqlite3_column_blob(st, 1);
    int dg_len = sqlite3_column_bytes(st, 1);
    if (!dg || dg_len != 64) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "attendance row digest malformed");
        return -1;
    }
    uint64_t es = (uint64_t)sqlite3_column_int64(st, 0);
    if (dna_v2_attendance_leaf_hash(es, dg, it->val) != 0) return -1;
    put_be64(es, it->key);
    it->key_len = 8;
    it->selected = 1;
    return 0;
}

static int leg_read(int leg, sqlite3_stmt *st, v2t_item_t *it) {
    memset(it, 0, sizeof(*it));
    switch (leg) {
    case NODUS_V2_TRIE_LEG_UTXO:       return rd_utxo(st, it);
    case NODUS_V2_TRIE_LEG_TOKENS:     return rd_tokens(st, it);
    case NODUS_V2_TRIE_LEG_CLAIMS:     return rd_claims(st, it);
    case NODUS_V2_TRIE_LEG_NAMES:      return rd_names(st, it);
    case NODUS_V2_TRIE_LEG_REGISTRY:   return rd_registry(st, it);
    case NODUS_V2_TRIE_LEG_SEGMENTS:   return rd_segments(st, it);
    case NODUS_V2_TRIE_LEG_VSET:       return rd_vset(st, it);
    case NODUS_V2_TRIE_LEG_ATTENDANCE: return rd_attendance(st, it);
    default:                           return -1;
    }
}

/* ── v2_trie_roots ───────────────────────────────────────────────────── */

/* The committed root of `leg`. A missing row, a root that is not a
 * 64-byte BLOB or a read fault is -1. */
static int roots_read(nodus_witness_t *w, int leg, uint8_t root[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT root, typeof(root) FROM v2_trie_roots WHERE leg = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_bind_int(st, 1, leg) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 1);
        const void *b = sqlite3_column_blob(st, 0);
        if (t && strcmp(t, "blob") == 0 && b &&
            sqlite3_column_bytes(st, 0) == 64) {
            memcpy(root, b, 64);
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int count_leg_dirty(nodus_witness_t *w, int leg, int64_t *n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM v2_trie_dirty WHERE leg = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_bind_int(st, 1, leg) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *n = (int64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

int nodus_witness_v2_trie_dirty_count(nodus_witness_t *w, int64_t *n) {
    if (!w || !w->db || !n) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM v2_trie_dirty", -1,
                           &st, NULL) != SQLITE_OK)
        return -1;
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *n = (int64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

int nodus_witness_v2_trie_leg_root(nodus_witness_t *w, int leg,
                                   uint8_t root[64]) {
    if (!w || !w->db || !root || !leg_valid(leg)) return -1;
    int64_t pending = 0;
    if (count_leg_dirty(w, leg, &pending) != 0) return -1;
    if (pending != 0) {
        /* plan §5.3, the head_activate guard: a stale root is never
         * returned */
        QGP_LOG_ERROR(LOG_TAG, "leg %d root read with %lld dirty key(s) "
                      "pending", leg, (long long)pending);
        return -1;
    }
    return roots_read(w, leg, root);
}

int nodus_witness_v2_trie_set_capture(nodus_witness_t *w, int capture) {
    if (!w || !w->db || (capture != 0 && capture != 1)) return -1;
    if (sqlite3_get_autocommit(w->db)) return -1;     /* inside a txn only */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_trie_state SET capture = ?1 WHERE id = 1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_bind_int(st, 1, capture) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) return -1;
    return 0;
}

/* ── build from rows ─────────────────────────────────────────────────── */

typedef struct {
    uint8_t key[64];
    size_t  key_len;
    uint8_t val[64];
} kv_t;

int nodus_witness_v2_trie_build_leg(nodus_witness_t *w, int leg,
                                    uint8_t root_inc[64],
                                    uint8_t root_full[64]) {
    if (!w || !w->db || !root_inc || !root_full || !leg_valid(leg))
        return -1;
    evm_trie_store_t store;
    store_of(w, &store);
    uint8_t empty[64];
    if (evm_trie_empty_root(empty) != 0) return -1;
    evm_trie_t *t = NULL;
    if (evm_trie_open(&store, empty, &t) != 0) return -1;

    char sql[1100];
    int nw = snprintf(sql, sizeof(sql), "%s ORDER BY %s ASC",
                      LEG_SQL[leg].select, LEG_SQL[leg].pk);
    if (nw <= 0 || (size_t)nw >= sizeof(sql)) { evm_trie_close(t); return -1; }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "leg %d scan prepare failed: %s", leg,
                      sqlite3_errmsg(w->db));
        evm_trie_close(t);
        return -1;
    }
    kv_t *kv = NULL;
    size_t n = 0, cap = 0;
    int rc, fail = 0;
    uint64_t expect_k = 1;                    /* L6: k must be exactly 1..n */
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        v2t_item_t it;
        if (leg_read(leg, st, &it) != 0) { fail = 1; break; }
        if (!it.selected) continue;
        if (leg == NODUS_V2_TRIE_LEG_SEGMENTS) {
            uint64_t k = 0;
            for (int i = 0; i < 8; i++) k = (k << 8) | it.key[i];
            if (k != expect_k) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_segments are not "
                              "contiguous 1..n");
                fail = 1;
                break;
            }
            expect_k++;
        }
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 64;
            kv_t *nk = realloc(kv, nc * sizeof(*kv));
            if (!nk) { fail = 1; break; }
            kv = nk;
            cap = nc;
        }
        memcpy(kv[n].key, it.key, it.key_len);
        kv[n].key_len = it.key_len;
        memcpy(kv[n].val, it.val, 64);
        if (evm_trie_set(t, it.key, it.key_len, it.val, 64) != 0) {
            fail = 1;
            break;
        }
        n++;
    }
    /* an interrupted scan is never a shorter tree */
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "leg %d scan aborted mid-stream (rc=%d)",
                      leg, rc);
        fail = 1;
    }
    sqlite3_finalize(st);

    int ret = -1;
    evm_trie_full_kv *fk = NULL;
    if (!fail && evm_trie_commit(t, root_inc) == 0) {
        fk = n ? malloc(n * sizeof(*fk)) : NULL;
        if (n == 0 || fk) {
            for (size_t i = 0; i < n; i++) {
                fk[i].key = kv[i].key;
                fk[i].key_len = kv[i].key_len;
                fk[i].val = kv[i].val;
                fk[i].val_len = 64;
            }
            if (evm_trie_full_root(fk, n, 1, EVM_TRIE_FULL_SHA3_512,
                                   root_full) == 0)
                ret = 0;
        }
    }
    free(fk);
    free(kv);
    evm_trie_close(t);
    return ret;
}

int nodus_witness_v2_trie_build_all(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    uint8_t roots[NODUS_V2_TRIE_LEGS][64];
    for (int leg = NODUS_V2_TRIE_LEG_UTXO; leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
         leg++) {
        uint8_t full[64];
        if (nodus_witness_v2_trie_build_leg(w, leg, roots[leg - 1], full) != 0)
            return -1;
        if (memcmp(roots[leg - 1], full, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "leg %d: incremental root != full "
                          "rebuild", leg);
            return -1;
        }
    }
    for (int leg = NODUS_V2_TRIE_LEG_UTXO; leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
         leg++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT OR REPLACE INTO v2_trie_roots (leg, root) "
                "VALUES (?1, ?2)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_bind_int(st, 1, leg) != SQLITE_OK ||
            sqlite3_bind_blob(st, 2, roots[leg - 1], 64, SQLITE_STATIC)
                != SQLITE_OK) {
            sqlite3_finalize(st);
            return -1;
        }
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* ── the flush (plan §5.3) ───────────────────────────────────────────── */

static int flush_leg(nodus_witness_t *w, int leg) {
    int64_t pending = 0;
    if (count_leg_dirty(w, leg, &pending) != 0) return -1;
    if (pending == 0) return 0;               /* nothing to change          */

    uint8_t root[64];
    if (roots_read(w, leg, root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "leg %d has dirty keys but no committed "
                      "root row", leg);
        return -1;
    }
    evm_trie_store_t store;
    store_of(w, &store);
    evm_trie_t *t = NULL;
    if (evm_trie_open(&store, root, &t) != 0) return -1;

    char sql[1200];
    int nw = snprintf(sql, sizeof(sql), "%s WHERE %s = ?1",
                      LEG_SQL[leg].select, LEG_SQL[leg].pk);
    sqlite3_stmt *dq = NULL, *rq = NULL;
    int ret = -1;
    do {
        if (nw <= 0 || (size_t)nw >= sizeof(sql)) break;
        if (sqlite3_prepare_v2(w->db,
                "SELECT key, typeof(key) FROM v2_trie_dirty WHERE leg = ?1 "
                "ORDER BY key ASC", -1, &dq, NULL) != SQLITE_OK) break;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK) break;
        if (sqlite3_bind_int(dq, 1, leg) != SQLITE_OK) break;

        const int is_int = leg_int_keyed(leg);
        int rc, bad = 0;
        while ((rc = sqlite3_step(dq)) == SQLITE_ROW) {
            const char *ty = (const char *)sqlite3_column_text(dq, 1);
            uint8_t kb[64];
            size_t kl = 0;
            int bind_ok;
            if (sqlite3_reset(rq) != SQLITE_OK ||
                sqlite3_clear_bindings(rq) != SQLITE_OK) { bad = 1; break; }
            if (is_int) {
                if (!ty || strcmp(ty, "integer") != 0) { bad = 1; break; }
                sqlite3_int64 kv = sqlite3_column_int64(dq, 0);
                put_be64((uint64_t)kv, kb);
                kl = 8;
                bind_ok = sqlite3_bind_int64(rq, 1, kv) == SQLITE_OK;
            } else {
                if (!ty || strcmp(ty, "blob") != 0) { bad = 1; break; }
                int bl = sqlite3_column_bytes(dq, 0);
                const void *bp = sqlite3_column_blob(dq, 0);
                if (bl < 1 || bl > 64 || !bp) { bad = 1; break; }
                memcpy(kb, bp, (size_t)bl);
                kl = (size_t)bl;
                bind_ok = sqlite3_bind_blob(rq, 1, kb, (int)kl,
                                            SQLITE_STATIC) == SQLITE_OK;
            }
            if (!bind_ok) { bad = 1; break; }

            v2t_item_t it;
            int rr = sqlite3_step(rq);
            if (rr == SQLITE_ROW) {
                if (leg_read(leg, rq, &it) != 0) { bad = 1; break; }
                /* a second row would be a table without its key */
                if (sqlite3_step(rq) != SQLITE_DONE) { bad = 1; break; }
                if (it.selected) {
                    if (it.key_len != kl || memcmp(it.key, kb, kl) != 0) {
                        bad = 1;       /* the row's key is not the dirty key */
                        break;
                    }
                    if (evm_trie_set(t, kb, kl, it.val, 64) != 0) {
                        bad = 1;
                        break;
                    }
                    continue;
                }
            } else if (rr != SQLITE_DONE) {
                bad = 1;
                break;
            }
            /* row absent, or present but not part of the leg */
            if (evm_trie_delete(t, kb, kl) != 0) { bad = 1; break; }
        }
        if (bad || rc != SQLITE_DONE) break;
        sqlite3_finalize(dq); dq = NULL;
        sqlite3_finalize(rq); rq = NULL;

        uint8_t nroot[64];
        if (evm_trie_commit(t, nroot) != 0) break;

        sqlite3_stmt *up = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_trie_roots SET root = ?1 WHERE leg = ?2", -1, &up,
                NULL) != SQLITE_OK) break;
        int ok = sqlite3_bind_blob(up, 1, nroot, 64, SQLITE_STATIC)
                     == SQLITE_OK &&
                 sqlite3_bind_int(up, 2, leg) == SQLITE_OK &&
                 sqlite3_step(up) == SQLITE_DONE &&
                 sqlite3_changes(w->db) == 1;
        sqlite3_finalize(up);
        if (!ok) break;

        sqlite3_stmt *del = NULL;
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM v2_trie_dirty WHERE leg = ?1", -1, &del, NULL)
            != SQLITE_OK) break;
        ok = sqlite3_bind_int(del, 1, leg) == SQLITE_OK &&
             sqlite3_step(del) == SQLITE_DONE;
        sqlite3_finalize(del);
        if (!ok) break;
        ret = 0;
    } while (0);
    sqlite3_finalize(dq);
    sqlite3_finalize(rq);
    evm_trie_close(t);
    if (ret != 0)
        QGP_LOG_ERROR(LOG_TAG, "leg %d flush FAULT — the host rolls the "
                      "block back", leg);
    return ret;
}

int nodus_witness_v2_trie_flush(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    if (sqlite3_get_autocommit(w->db)) return -1;      /* inside a txn only */
    for (int leg = NODUS_V2_TRIE_LEG_UTXO; leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
         leg++)
        if (flush_leg(w, leg) != 0) return -1;
    return 0;
}
