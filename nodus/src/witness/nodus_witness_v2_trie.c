/**
 * @file nodus_witness_v2_trie.c
 * @brief HF-9 WP2 — the eight keyed Patricia tries over SQLite. Contract:
 *        nodus_witness_v2_trie.h. Plan docs/plans/approved/2026-11-04-hf9.md
 *        §4 (legs), §5 (integration), §7.2 step 4 / §7.4 (build from rows).
 */

#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_merkle.h"   /* nodus_witness_merkle_leaf_hash */
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_storage.h"   /* g_nodus_storage_work (T-9) */

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

/* HF-9 WP5 (plan §5.3, §11): the shadow run updates its tries with THIS
 * code against the node-local shadow node table. The store context says
 * which table; the SQL text of the consensus store is unchanged. */
typedef struct {
    sqlite3 *db;
    int      shadow;       /* 0 = v2_trie_nodes, 1 = v2_trie_shadow_nodes */
} ts_ctx_t;

static const char *const TS_SQL_SELECT[2] = {
    "SELECT rlp FROM v2_trie_nodes WHERE digest = ?1",
    "SELECT rlp FROM v2_trie_shadow_nodes WHERE digest = ?1"
};
static const char *const TS_SQL_INSERT[2] = {
    "INSERT INTO v2_trie_nodes (digest, rlp) VALUES (?1, ?2)",
    "INSERT INTO v2_trie_shadow_nodes (digest, rlp) VALUES (?1, ?2)"
};

static int ts_get(void *ctx, const uint8_t digest[64], uint8_t **rlp,
                  size_t *len) {
    const ts_ctx_t *c = (const ts_ctx_t *)ctx;
    sqlite3 *db = c->db;
    sqlite3_stmt *st = NULL;
    /* T-9: nodes loaded by the CONSENSUS path only; the shadow's loads
     * are node-local work outside block processing */
    if (!c->shadow) g_nodus_storage_work.trie_nodes_loaded++;
    if (sqlite3_prepare_v2(db, TS_SQL_SELECT[c->shadow ? 1 : 0],
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
    const ts_ctx_t *c = (const ts_ctx_t *)ctx;
    sqlite3 *db = c->db;
    sqlite3_stmt *st = NULL;
    if (len == 0 || len > INT32_MAX) return -2;
    if (sqlite3_prepare_v2(db, TS_SQL_SELECT[c->shadow ? 1 : 0],
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
    if (sqlite3_prepare_v2(db, TS_SQL_INSERT[c->shadow ? 1 : 0],
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

/* `c` must outlive the store (the trie handle keeps the pointer). */
static void store_of(nodus_witness_t *w, int shadow, ts_ctx_t *c,
                     evm_trie_store_t *s) {
    c->db = w->db;
    c->shadow = shadow ? 1 : 0;
    s->ctx = c;
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
        /* column 5 is the historical predicate evaluated by SQL itself
         * (`target_domain_id = <CORE>`, nodus_witness_v2_claims.c:139):
         * 1 or 0, no integer coercion of the stored value */
        "SELECT nullifier, manifest_hash, leaf_index, amount, "
        "claimed_height, (target_domain_id = 1) FROM v2_claims_spent",
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
_Static_assert(DNA_DOMAIN_CORE == 1,
               "LEG_SQL spells the CORE domain id literally in the claims "
               "selection");
static int rd_claims(sqlite3_stmt *st, v2t_item_t *it) {
    /* the SQL equality, not sqlite3_column_int64 of the stored value: a
     * REAL 1.5 would coerce to 1 and enter the leg (Sol verifier row 1) */
    if (sqlite3_column_type(st, 5) != SQLITE_INTEGER ||
        sqlite3_column_int64(st, 5) != 1) {
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
static int roots_read(nodus_witness_t *w, int shadow, int leg,
                      uint8_t root[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, shadow
            ? "SELECT root, typeof(root) FROM v2_trie_shadow_roots "
              "WHERE leg = ?1"
            : "SELECT root, typeof(root) FROM v2_trie_roots WHERE leg = ?1",
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

int nodus_witness_v2_trie_dirty_clear(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    if (sqlite3_get_autocommit(w->db)) return -1;     /* inside a txn only */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "DELETE FROM v2_trie_dirty", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
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
    return roots_read(w, 0, leg, root);
}

int nodus_witness_v2_trie_shadow_leg_root(nodus_witness_t *w, int leg,
                                          uint8_t root[64]) {
    if (!w || !w->db || !root || !leg_valid(leg)) return -1;
    return roots_read(w, 1, leg, root);
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

/* The per-leg scan (plan §7.2 step 4): every row ORDER BY primary key with
 * the reader's row checks and the post-loop SQLITE_DONE check; the rows
 * the leg selects go to `fn` in that order. Used by the build (consensus
 * and shadow) and by the shadow's row comparison (plan §11), so both read
 * the rows through the one set of readers. */
int nodus_witness_v2_trie_scan_leg(nodus_witness_t *w, int leg,
                                   nodus_v2_trie_row_fn fn, void *fn_ctx) {
    if (!w || !w->db || !fn || !leg_valid(leg)) return -1;
    char sql[1100];
    int nw = snprintf(sql, sizeof(sql), "%s ORDER BY %s ASC",
                      LEG_SQL[leg].select, LEG_SQL[leg].pk);
    if (nw <= 0 || (size_t)nw >= sizeof(sql)) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "leg %d scan prepare failed: %s", leg,
                      sqlite3_errmsg(w->db));
        return -1;
    }
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
        if (fn(fn_ctx, it.key, it.key_len, it.val) != 0) { fail = 1; break; }
    }
    /* an interrupted scan is never a shorter tree */
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "leg %d scan aborted mid-stream (rc=%d)",
                      leg, rc);
        fail = 1;
    }
    sqlite3_finalize(st);
    return fail ? -1 : 0;
}

typedef struct {
    evm_trie_t *t;
    kv_t       *kv;
    size_t      n, cap;
    nodus_v2_trie_row_fn sink;      /* the shadow seeding's row copy      */
    void                *sink_ctx;
} build_ctx_t;

static int build_row(void *vctx, const uint8_t *key, size_t key_len,
                     const uint8_t val[64]) {
    build_ctx_t *b = (build_ctx_t *)vctx;
    if (b->n == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 64;
        kv_t *nk = realloc(b->kv, nc * sizeof(*b->kv));
        if (!nk) return -1;
        b->kv = nk;
        b->cap = nc;
    }
    memcpy(b->kv[b->n].key, key, key_len);
    b->kv[b->n].key_len = key_len;
    memcpy(b->kv[b->n].val, val, 64);
    if (evm_trie_set(b->t, key, key_len, val, 64) != 0) return -1;
    if (b->sink && b->sink(b->sink_ctx, key, key_len, val) != 0) return -1;
    b->n++;
    return 0;
}

/* The build of one leg into the consensus store (shadow = 0) or the
 * shadow node table (shadow = 1) - the one code path of the edge's build
 * and the shadow seeding (plan §11: "the same build function as the
 * edge"). `sink` (shadow seeding only) sees each selected row. */
static int build_leg_impl(nodus_witness_t *w, int leg, int shadow,
                          nodus_v2_trie_row_fn sink, void *sink_ctx,
                          uint8_t root_inc[64], uint8_t root_full[64]) {
    if (!w || !w->db || !root_inc || !root_full || !leg_valid(leg))
        return -1;
    ts_ctx_t tctx;
    evm_trie_store_t store;
    store_of(w, shadow, &tctx, &store);
    uint8_t empty[64];
    if (evm_trie_empty_root(empty) != 0) return -1;
    evm_trie_t *t = NULL;
    if (evm_trie_open(&store, empty, &t) != 0) return -1;

    build_ctx_t b;
    memset(&b, 0, sizeof(b));
    b.t = t;
    b.sink = sink;
    b.sink_ctx = sink_ctx;
    kv_t *kv = NULL;
    size_t n = 0;
    int fail = nodus_witness_v2_trie_scan_leg(w, leg, build_row, &b) != 0;
    kv = b.kv;
    n = b.n;

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

int nodus_witness_v2_trie_build_leg(nodus_witness_t *w, int leg,
                                    uint8_t root_inc[64],
                                    uint8_t root_full[64]) {
    return build_leg_impl(w, leg, 0, NULL, NULL, root_inc, root_full);
}

int nodus_witness_v2_trie_shadow_build_leg(nodus_witness_t *w, int leg,
                                           nodus_v2_trie_row_fn sink,
                                           void *sink_ctx,
                                           uint8_t root_inc[64],
                                           uint8_t root_full[64]) {
    return build_leg_impl(w, leg, 1, sink, sink_ctx, root_inc, root_full);
}

#ifdef QGP_FAULT_INJECT
/* HF-9 WP3 T-6: an incremental / full-rebuild mismatch hook for
 * nodus_witness_v2_trie_build_all, compiled only under QGP_FAULT_INJECT.
 * While armed with a leg (1..8), build_all flips one bit of that leg's
 * FULL-rebuild root before comparing, so the leg reads as a mismatch.
 * Arming 0 disarms. Test-only: no consensus path calls it, and a build
 * without the flag has neither the variable nor the function. */
static int g_test_corrupt_full_leg;
int nodus_witness_v2_trie_test_corrupt_full(int leg);
int nodus_witness_v2_trie_test_corrupt_full(int leg) {
    if (leg < 0 || leg > NODUS_V2_TRIE_LEGS) return -1;
    g_test_corrupt_full_leg = leg;
    return 0;
}
#endif

int nodus_witness_v2_trie_build_all(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    uint8_t roots[NODUS_V2_TRIE_LEGS][64];
    for (int leg = NODUS_V2_TRIE_LEG_UTXO; leg <= NODUS_V2_TRIE_LEG_ATTENDANCE;
         leg++) {
        uint8_t full[64];
        if (nodus_witness_v2_trie_build_leg(w, leg, roots[leg - 1], full) != 0)
            return -1;
#ifdef QGP_FAULT_INJECT
        if (g_test_corrupt_full_leg == leg) full[0] ^= 0x01;
#endif
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

/* The update of one key against an open trie (plan §5.3: "read row, set
 * or delete") - THE code the consensus flush and the shadow run share.
 * `rq` is the leg's point-lookup statement (the leg's SELECT WHERE pk = ?1),
 * `kb`/`kl` the canonical key bytes and `ikey` the integer primary key of
 * an integer-keyed leg. The row is re-read with the reader's row checks:
 * present and selected -> evm_trie_set, absent or not selected ->
 * evm_trie_delete. @return 0 / -1. */
static int apply_key(int leg, sqlite3_stmt *rq, evm_trie_t *t,
                     const uint8_t *kb, size_t kl, sqlite3_int64 ikey) {
    if (sqlite3_reset(rq) != SQLITE_OK ||
        sqlite3_clear_bindings(rq) != SQLITE_OK) return -1;
    int bind_ok = leg_int_keyed(leg)
        ? sqlite3_bind_int64(rq, 1, ikey) == SQLITE_OK
        : sqlite3_bind_blob(rq, 1, kb, (int)kl, SQLITE_STATIC) == SQLITE_OK;
    if (!bind_ok) return -1;

    v2t_item_t it;
    int rr = sqlite3_step(rq);
    if (rr == SQLITE_ROW) {
        if (leg_read(leg, rq, &it) != 0) return -1;
        /* a second row would be a table without its key */
        if (sqlite3_step(rq) != SQLITE_DONE) return -1;
        if (it.selected) {
            if (it.key_len != kl || memcmp(it.key, kb, kl) != 0)
                return -1;         /* the row's key is not the dirty key */
            return evm_trie_set(t, kb, kl, it.val, 64) == 0 ? 0 : -1;
        }
    } else if (rr != SQLITE_DONE) {
        return -1;
    }
    /* row absent, or present but not part of the leg */
    return evm_trie_delete(t, kb, kl) == 0 ? 0 : -1;
}

/* HF-9 WP5 (plan §11): the shadow's trie update. The sorted changed-key
 * list comes from the post-commit row comparison; every key then goes
 * through apply_key, exactly as the consensus flush does, against the
 * SHADOW node table, starting at `root_in` and ending at `root_out`
 * (committed to v2_trie_shadow_nodes; the caller stores the root). */
int nodus_witness_v2_trie_shadow_update_leg(nodus_witness_t *w, int leg,
                                            const nodus_v2_trie_key_t *keys,
                                            size_t n,
                                            const uint8_t root_in[64],
                                            uint8_t root_out[64]) {
    if (!w || !w->db || !root_in || !root_out || !leg_valid(leg) ||
        (n && !keys))
        return -1;
    ts_ctx_t tctx;
    evm_trie_store_t store;
    store_of(w, 1, &tctx, &store);
    evm_trie_t *t = NULL;
    if (evm_trie_open(&store, root_in, &t) != 0) return -1;

    char sql[1200];
    int nw = snprintf(sql, sizeof(sql), "%s WHERE %s = ?1",
                      LEG_SQL[leg].select, LEG_SQL[leg].pk);
    sqlite3_stmt *rq = NULL;
    int ret = -1;
    do {
        if (nw <= 0 || (size_t)nw >= sizeof(sql)) break;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK) break;
        size_t i;
        for (i = 0; i < n; i++) {
            sqlite3_int64 ik = 0;
            if (leg_int_keyed(leg)) {
                if (keys[i].len != 8) break;
                uint64_t u = 0;
                for (int b = 0; b < 8; b++) u = (u << 8) | keys[i].b[b];
                ik = (sqlite3_int64)u;
            } else if (keys[i].len < 1 || keys[i].len > 64) {
                break;
            }
            if (apply_key(leg, rq, t, keys[i].b, keys[i].len, ik) != 0) break;
        }
        if (i != n) break;
        if (evm_trie_commit(t, root_out) != 0) break;
        ret = 0;
    } while (0);
    sqlite3_finalize(rq);
    evm_trie_close(t);
    if (ret != 0)
        QGP_LOG_ERROR(LOG_TAG, "leg %d shadow update FAULT", leg);
    return ret;
}

static int flush_leg(nodus_witness_t *w, int leg) {
    int64_t pending = 0;
    if (count_leg_dirty(w, leg, &pending) != 0) return -1;
    if (pending == 0) return 0;               /* nothing to change          */

    uint8_t root[64];
    if (roots_read(w, 0, leg, root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "leg %d has dirty keys but no committed "
                      "root row", leg);
        return -1;
    }
    ts_ctx_t tctx;
    evm_trie_store_t store;
    store_of(w, 0, &tctx, &store);
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
            sqlite3_int64 ikey = 0;
            if (is_int) {
                if (!ty || strcmp(ty, "integer") != 0) { bad = 1; break; }
                ikey = sqlite3_column_int64(dq, 0);
                put_be64((uint64_t)ikey, kb);
                kl = 8;
            } else {
                if (!ty || strcmp(ty, "blob") != 0) { bad = 1; break; }
                int bl = sqlite3_column_bytes(dq, 0);
                const void *bp = sqlite3_column_blob(dq, 0);
                if (bl < 1 || bl > 64 || !bp) { bad = 1; break; }
                memcpy(kb, bp, (size_t)bl);
                kl = (size_t)bl;
            }
            if (apply_key(leg, rq, t, kb, kl, ikey) != 0) { bad = 1; break; }
        }
        if (bad || rc != SQLITE_DONE) break;
        /* T-9 "rows read": the work EXAMINED by the source queries (the
         * dirty-key list and the per-key row lookup), not only what they
         * return - a lookup that scans the source table steps once per
         * row */
        g_nodus_storage_work.flush_source_vm_steps += (uint64_t)
            sqlite3_stmt_status(dq, SQLITE_STMTSTATUS_VM_STEP, 0) +
            (uint64_t)sqlite3_stmt_status(rq, SQLITE_STMTSTATUS_VM_STEP, 0);
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
