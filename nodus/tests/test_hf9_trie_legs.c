/**
 * @file nodus/tests/test_hf9_trie_legs.c
 * @brief HF-9 T-5 (WP2 part) — the eight keyed Patricia tries: S20 schema,
 *        SQLite node store, dirty-capture triggers, flush, leg roots,
 *        build from rows. Plan docs/plans/approved/2026-11-04-hf9.md §4,
 *        §5, §12 row T-5.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. INERT. With v2_trie_state.capture = 0 (the S20 migration's value and
 *     the only one this build's generations allow) a row written to each
 *     of the eight tables leaves v2_trie_dirty empty.
 *  B. BUILD FROM ROWS. nodus_witness_v2_trie_build_leg: for every leg the
 *     incremental root equals evm_trie_full_root over the same list AND
 *     equals this test's OWN recomputation from SELECTs (own key bytes:
 *     64-byte blobs raw, names raw, k / epoch_start 8-byte big-endian; own
 *     leaf values from the public leaf-hash functions; UTXO value =
 *     SHA3-512(0x00 ‖ D)). An empty table gives the empty root
 *     SHA3-512(0x80). A malformed row (utxo nullifier of 3 bytes, token
 *     decimals 300, a claim of the CORE domain with amount 0, a registry
 *     row whose node_fp is not SHA3-512(node_pk), segments k = 1, 3,
 *     a vset snapshot_hash of 3 bytes, an attendance digest of 3 bytes)
 *     is -1 — never a shorter trie. A claim of another domain is not part
 *     of the CORE leg (the root does not move).
 *  C. TRIGGERS + FLUSH. With capture = 1 inside a transaction: inserts,
 *     updates (including a primary-key change), and deletes on every
 *     table put exactly the OLD / NEW keys in v2_trie_dirty (duplicates
 *     collapsed); a leg root read with a key pending is -1; the flush
 *     writes v2_trie_roots; afterwards the dirty table is empty and every
 *     leg root equals the oracle recomputation and the build-from-rows
 *     root (the trie is a function of the rows). A key written and
 *     restored inside one block (a utxo created and deleted) leaves the
 *     root as it was.
 *  D. ROLLBACK. An item SAVEPOINT rolled back removes its dirty rows and
 *     leaves the roots; a whole transaction rolled back after a flush
 *     restores the roots row, the node store and the dirty rows (they are
 *     in the transaction).
 *  E. RESTART. After closing and reopening the SQLite file the next flush
 *     continues from the stored roots and equals the oracle.
 *  F. FAULTS. A corrupted stored node (digest unchanged, body altered) is
 *     -1 at the next flush that touches it, and after the host's rollback
 *     the roots row is unchanged. A leg with dirty keys but no
 *     v2_trie_roots row is -1. set_capture refuses outside a transaction
 *     and for a value outside {0, 1}; flush refuses outside a transaction.
 *  G. SCHEMA. All 24 triggers, the five tables and the status index pass
 *     nodus_witness_db_s20_trie_shape_ok; a dropped trigger, an altered
 *     trigger and a dropped table each make it 0 and make the open-time
 *     re-seed refuse (-1); the capture reader is -1 for a missing row and
 *     for a value outside {0, 1} (a table recreated without its CHECK).
 *  H. BLOCK-START CAPTURE CHECK (real chain, the engine's own block
 *     entry): an idle block commits at capture 0; with capture 1, a
 *     missing state row or a value outside {0, 1} the block is a FAULT
 *     (rolled back, no block row written) before any item runs.
 *     A chain database with a dropped trigger is refused by the production
 *     open path.
 *  I. dna_v2_vset_leaf_hash: equals the documented bytes SHA3-512(
 *     "NDS.VSLEAF.v1" zero-padded to 16 ‖ epoch(8 BE) ‖ hash[64]) built
 *     here from the tag text, and dna_v2_vset_root over two fixture
 *     leaves equals the documented composition (one leaf = the leaf; two
 *     = SHA3-512("NDS.VSNODE.v1" padded ‖ l0 ‖ l1)) — byte-identical to
 *     the inline computation it replaced.
 *
 * ── NOT COVERED (deferred to WP3 with the generation, plan §13) ─────────
 *  The generation >= 6 rows of T-5: the flush on the live block path
 *  (phase 8-pre), the dirty-empty end-of-block assertion, the
 *  head_activate guard's engine call site (the getter guard itself is
 *  tested in C), "generation >= 6 with capture 0" and "generation <= 5
 *  with capture 1" as a generation pair (only the <= 5 half exists:
 *  H). Writers exercised: SQL INSERT / UPDATE / DELETE of the plan §4.3
 *  statement shapes for every table; the engine writers (rtn_core_mutate, claim_spend_insert,
 *  st_publish, vset_insert, v2ep_attendance_digest ...) are NOT driven
 *  here — the triggers are on the tables, not on the writers, which is
 *  the design (plan §5.2), and the full-rebuild comparison catches a
 *  divergence; a per-writer coverage list belongs to the WP3 block tests.
 *  The HF-9 store bind-failure test (T-3 part) needs -DQGP_FAULT_INJECT=ON
 *  and a hook this package does not add.
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  register_witness_test (NODUS_WITNESS_INTERNAL_API); only where
 *  NODUS_EVM_ENABLED (the trie is EVM-only). No fault injection, no epoch
 *  constants, no environment.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 *  /tmp/test_hf9_trie_XXXXXX and /tmp/v2x_hf9trie_XXXXXX directories,
 *  removed on exit (a crash leaves one).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - The oracle shares the public leaf-hash functions and the key
 *    convention with the code under test; it proves "incremental =
 *    full rebuild of the rows" (T-5), NOT the byte choices — those are
 *    T-4's independent KAT (hf9_kat.json, follow-up).
 *  - A trigger or a flush that wrote nothing would fail C (dirty rows and
 *    roots are asserted non-empty / changed before they are compared).
 *  - Section B's malformed-row cases rely on the table accepting the
 *    malformed value; the tables with CHECK constraints (names, registry,
 *    segments) cannot hold a bad type, so those cases use the values the
 *    CHECKs allow.
 *  - H passes vacuously if the idle block would fault anyway; the control
 *    (the first idle block commits) and the restore (the next idle block
 *    commits again) bracket every refusal.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_trie.h"

#include "evm/trie/evm_trie.h"
#include "evm/trie/evm_trie_full.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/manifest_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

/* ── fixture ───────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    char             path[256];
} fx_t;

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n  %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static sqlite3_int64 q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_int64 v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void rmrf(const char *dir) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int fx_open(fx_t *fx) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));          /* multi-MB — heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf9_trie_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t id16[16];
    memset(id16, 0x39, sizeof(id16));
    if (nodus_witness_create_chain_db(fx->w, id16) != 0) return -1;
    if (nodus_witness_db_migrate_v2s20(fx->w) != 0) return -1;
    const char *fn = sqlite3_db_filename(fx->w->db, "main");
    if (!fn || strlen(fn) >= sizeof(fx->path)) return -1;
    snprintf(fx->path, sizeof(fx->path), "%s", fn);
    return 0;
}

static void fx_close(fx_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/* the SQLite handle of a witness is closed and the same file opened again
 * (a node restart for everything this module holds) */
static int fx_restart(fx_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(fx->path, &db, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;                       /* never creates a new file       */
    }
    fx->w->db = db;
    return 0;
}

/* ── row writers (statement shapes of plan §4.3) ───────────────────── */

#define NB(n) "CAST(zeroblob(63)||x'" n "' AS BLOB)"

static int utxo_sql(sqlite3 *db, int nb, long long amount) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) VALUES (CAST(zeroblob(63)||x'%02x' AS BLOB), 'own%d', "
        "%lld, zeroblob(64), CAST(zeroblob(63)||x'%02x' AS BLOB), 1, 5, 0, "
        "0, 1)", nb, nb, amount, nb);
    return run_sql(db, sql);
}

static int token_sql(sqlite3 *db, int nb, int decimals) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO tokens (token_id, name, symbol, decimals, supply, "
        "creator_fp, flags, block_height, timestamp) VALUES (CAST("
        "zeroblob(63)||x'%02x' AS BLOB), 'tok%d', 'T%d', %d, 1000, "
        "'fp%d', 1, 7, 99)", nb, nb, nb, decimals, nb);
    return run_sql(db, sql);
}

static int claim_sql(sqlite3 *db, int nb, int domain, long long amount) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO v2_claims_spent (nullifier, manifest_hash, "
        "target_domain_id, target_asset_ref, leaf_index, amount, "
        "claimed_height, output_id) VALUES (CAST(zeroblob(63)||x'%02x' AS "
        "BLOB), CAST(zeroblob(63)||x'ee' AS BLOB), %d, zeroblob(64), 2, "
        "%lld, 9, zeroblob(64))", nb, domain, amount);
    return run_sql(db, sql);
}

static int name_sql(sqlite3 *db, const char *name, int owner_nb) {
    char sql[400];
    snprintf(sql, sizeof(sql),
        "INSERT INTO v2_names (name, owner, registered_height) VALUES "
        "(CAST('%s' AS BLOB), CAST(zeroblob(63)||x'%02x' AS BLOB), 11)",
        name, owner_nb);
    return run_sql(db, sql);
}

/* a registry row whose node_fp is SHA3-512(node_pk), node_pk = 2592 bytes
 * of `fill` (computed in SQL by the caller through the C hash) */
static int node_sql(nodus_witness_t *w, int fill, long long bond,
                    int status) {
    uint8_t pk[DNAC_PUBKEY_SIZE], fp[64];
    memset(pk, fill, sizeof(pk));
    if (qgp_sha3_512(pk, sizeof(pk), fp) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, zeroblob(64), ?3, ?4, 3, 0, 0, 0)",
            -1, &st, NULL) != SQLITE_OK) return -1;
    int ok = sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC) == SQLITE_OK &&
             sqlite3_bind_blob(st, 2, pk, sizeof(pk), SQLITE_STATIC)
                 == SQLITE_OK &&
             sqlite3_bind_int64(st, 3, bond) == SQLITE_OK &&
             sqlite3_bind_int(st, 4, status) == SQLITE_OK &&
             sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int seg_sql(sqlite3 *db, int k) {
    char sql[300];
    snprintf(sql, sizeof(sql),
        "INSERT INTO v2_storage_segments (k, root, published_height) "
        "VALUES (%d, CAST(zeroblob(63)||x'%02x' AS BLOB), %d)", k, k, 100 + k);
    return run_sql(db, sql);
}

static int vset_sql(sqlite3 *db, int epoch) {
    char sql[400];
    snprintf(sql, sizeof(sql),
        "INSERT INTO validator_set_snapshots (epoch_start, active_count, "
        "snapshot_hash, snapshot_blob, created_at_height) VALUES (%d, 1, "
        "CAST(zeroblob(63)||x'%02x' AS BLOB), x'00', 1)", epoch, epoch & 255);
    return run_sql(db, sql);
}

static int att_sql(sqlite3 *db, int epoch) {
    char sql[300];
    snprintf(sql, sizeof(sql),
        "INSERT INTO v2_attendance_epoch (epoch_start, digest) VALUES "
        "(%d, CAST(zeroblob(63)||x'%02x' AS BLOB))", epoch, (epoch + 1) & 255);
    return run_sql(db, sql);
}

/* one row in every table (a first population) */
static int populate(fx_t *fx, int base) {
    sqlite3 *db = fx->w->db;
    return utxo_sql(db, base + 1, 100 + base) == 0 &&
           token_sql(db, base + 1, 8) == 0 &&
           claim_sql(db, base + 1, 1, 50) == 0 &&
           name_sql(db, base == 0 ? "alice" : "bobby", base + 1) == 0 &&
           node_sql(fx->w, base + 1, 5000 + base, 1) == 0 &&
           seg_sql(db, base + 1) == 0 &&
           vset_sql(db, 720 * (base + 1)) == 0 &&
           att_sql(db, 720 * (base + 1)) == 0 ? 0 : -1;
}

/* ── the oracle: leaf values from SELECTs, root by the full rebuild ── */

typedef struct {
    uint8_t key[64];
    size_t  klen;
    uint8_t val[64];
} okv_t;

static void be64(uint64_t v, uint8_t *o) {
    for (int i = 7; i >= 0; i--) { o[i] = (uint8_t)v; v >>= 8; }
}

static int oracle_root(sqlite3 *db, int leg, uint8_t out[64]) {
    static const char *const sel[9] = {
        NULL,
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "unlock_block FROM utxo_set",
        "SELECT token_id, name, symbol, decimals, supply, creator_fp, "
        "flags, block_height FROM tokens",
        "SELECT nullifier, manifest_hash, leaf_index, amount, "
        "claimed_height FROM v2_claims_spent WHERE target_domain_id = 1",
        "SELECT name, owner, registered_height FROM v2_names",
        "SELECT node_fp, payee_fp, bond, status, registered_height, "
        "exit_height, fail_streak, grace_until FROM v2_storage_nodes",
        "SELECT k, root, published_height FROM v2_storage_segments",
        "SELECT epoch_start, snapshot_hash FROM validator_set_snapshots",
        "SELECT epoch_start, digest FROM v2_attendance_epoch"
    };
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sel[leg], -1, &st, NULL) != SQLITE_OK)
        return -1;
    okv_t *kv = NULL;
    size_t n = 0;
    int fail = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        okv_t *nk = realloc(kv, (n + 1) * sizeof(*kv));
        if (!nk) { fail = 1; break; }
        kv = nk;
        okv_t *e = &kv[n];
        memset(e, 0, sizeof(*e));
        switch (leg) {
        case 1: {
            uint8_t d[64], pre[65];
            if (nodus_witness_merkle_leaf_hash(
                    sqlite3_column_blob(st, 0),
                    (const char *)sqlite3_column_text(st, 1),
                    (uint64_t)sqlite3_column_int64(st, 2),
                    sqlite3_column_blob(st, 3), sqlite3_column_blob(st, 4),
                    (uint32_t)sqlite3_column_int(st, 5), d,
                    (uint64_t)sqlite3_column_int64(st, 6)) != 0) fail = 1;
            pre[0] = 0;
            memcpy(pre + 1, d, 64);
            if (qgp_sha3_512(pre, 65, e->val) != 0) fail = 1;
            memcpy(e->key, sqlite3_column_blob(st, 0), 64);
            e->klen = 64;
            break;
        }
        case 2: {
            dna_v2_token_leaf_t L;
            memset(&L, 0, sizeof(L));
            memcpy(L.token_id, sqlite3_column_blob(st, 0), 64);
            L.name = (const char *)sqlite3_column_text(st, 1);
            L.name_len = strlen(L.name);
            L.symbol = (const char *)sqlite3_column_text(st, 2);
            L.symbol_len = strlen(L.symbol);
            L.creator_fp = (const char *)sqlite3_column_text(st, 5);
            L.creator_fp_len = strlen(L.creator_fp);
            L.decimals = (uint8_t)sqlite3_column_int(st, 3);
            L.supply = (uint64_t)sqlite3_column_int64(st, 4);
            L.flags = (uint8_t)sqlite3_column_int(st, 6);
            L.block_height = (uint64_t)sqlite3_column_int64(st, 7);
            if (dna_v2_token_leaf_hash(&L, e->val) != 0) fail = 1;
            memcpy(e->key, L.token_id, 64);
            e->klen = 64;
            break;
        }
        case 3: {
            dna_claims_entry_t c;
            memset(&c, 0, sizeof(c));
            memcpy(c.nullifier, sqlite3_column_blob(st, 0), 64);
            memcpy(c.manifest_hash, sqlite3_column_blob(st, 1), 64);
            c.target_domain_id = 1;
            c.leaf_index = (uint64_t)sqlite3_column_int64(st, 2);
            c.amount = (uint64_t)sqlite3_column_int64(st, 3);
            c.claimed_height = (uint64_t)sqlite3_column_int64(st, 4);
            if (dna_claims_leaf_hash(&c, e->val) != 0) fail = 1;
            memcpy(e->key, c.nullifier, 64);
            e->klen = 64;
            break;
        }
        case 4: {
            dna_v2_name_row_t r;
            memset(&r, 0, sizeof(r));
            r.name_len = (uint8_t)sqlite3_column_bytes(st, 0);
            memcpy(r.name, sqlite3_column_blob(st, 0), r.name_len);
            memcpy(r.owner, sqlite3_column_blob(st, 1), 64);
            r.registered_height = (uint64_t)sqlite3_column_int64(st, 2);
            if (dna_v2_name_leaf_hash(&r, e->val) != 0) fail = 1;
            memcpy(e->key, r.name, r.name_len);
            e->klen = r.name_len;
            break;
        }
        case 5: {
            dna_v2_storage_node_row_t r;
            memset(&r, 0, sizeof(r));
            memcpy(r.node_fp, sqlite3_column_blob(st, 0), 64);
            memcpy(r.payee_fp, sqlite3_column_blob(st, 1), 64);
            r.bond = (uint64_t)sqlite3_column_int64(st, 2);
            r.status = (uint8_t)sqlite3_column_int(st, 3);
            r.registered_height = (uint64_t)sqlite3_column_int64(st, 4);
            r.exit_height = (uint64_t)sqlite3_column_int64(st, 5);
            r.fail_streak = (uint32_t)sqlite3_column_int64(st, 6);
            r.grace_until = (uint64_t)sqlite3_column_int64(st, 7);
            if (dna_v2_storage_node_leaf_hash(&r, e->val) != 0) fail = 1;
            memcpy(e->key, r.node_fp, 64);
            e->klen = 64;
            break;
        }
        case 6: {
            uint64_t k = (uint64_t)sqlite3_column_int64(st, 0);
            if (dna_v2_segment_leaf_hash_v2(k, sqlite3_column_blob(st, 1),
                    (uint64_t)sqlite3_column_int64(st, 2), e->val) != 0)
                fail = 1;
            be64(k, e->key);
            e->klen = 8;
            break;
        }
        case 7: {
            uint64_t ep = (uint64_t)sqlite3_column_int64(st, 0);
            if (dna_v2_vset_leaf_hash(ep, sqlite3_column_blob(st, 1),
                                      e->val) != 0) fail = 1;
            be64(ep, e->key);
            e->klen = 8;
            break;
        }
        default: {
            uint64_t ep = (uint64_t)sqlite3_column_int64(st, 0);
            if (dna_v2_attendance_leaf_hash(ep, sqlite3_column_blob(st, 1),
                                            e->val) != 0) fail = 1;
            be64(ep, e->key);
            e->klen = 8;
            break;
        }
        }
        n++;
        if (fail) break;
    }
    sqlite3_finalize(st);
    int rc = -1;
    if (!fail) {
        evm_trie_full_kv *fk = n ? malloc(n * sizeof(*fk)) : NULL;
        if (n == 0 || fk) {
            for (size_t i = 0; i < n; i++) {
                fk[i].key = kv[i].key;
                fk[i].key_len = kv[i].klen;
                fk[i].val = kv[i].val;
                fk[i].val_len = 64;
            }
            rc = evm_trie_full_root(fk, n, 1, EVM_TRIE_FULL_SHA3_512, out)
                     == 0 ? 0 : -1;
        }
        free(fk);
    }
    free(kv);
    return rc;
}

/* every leg's stored root equals the oracle and the build-from-rows root */
static int roots_equal_oracle(fx_t *fx, const char *what) {
    for (int leg = 1; leg <= 8; leg++) {
        uint8_t stored[64], orc[64], inc[64], full[64];
        if (nodus_witness_v2_trie_leg_root(fx->w, leg, stored) != 0) {
            fprintf(stderr, "%s: leg %d root unreadable\n", what, leg);
            return -1;
        }
        if (oracle_root(fx->w->db, leg, orc) != 0 ||
            memcmp(stored, orc, 64) != 0) {
            fprintf(stderr, "%s: leg %d stored root != oracle\n", what, leg);
            return -1;
        }
        if (nodus_witness_v2_trie_build_leg(fx->w, leg, inc, full) != 0 ||
            memcmp(inc, orc, 64) != 0 || memcmp(full, orc, 64) != 0) {
            fprintf(stderr, "%s: leg %d build-from-rows != oracle\n", what,
                    leg);
            return -1;
        }
    }
    return 0;
}

static int dirty_of(sqlite3 *db, int leg) {
    char sql[120];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_trie_dirty WHERE "
             "leg = %d", leg);
    return (int)q1(db, sql);
}

static int set_capture1(fx_t *fx) {
    if (run_sql(fx->w->db, "BEGIN") != 0) return -1;
    int rc = nodus_witness_v2_trie_set_capture(fx->w, 1);
    if (rc != 0) { run_sql(fx->w->db, "ROLLBACK"); return -1; }
    return run_sql(fx->w->db, "COMMIT");
}

/* ── A, B: inert triggers, build from rows ──────────────────────────── */
static int test_build(fx_t *fx) {
    sqlite3 *db = fx->w->db;
    uint8_t empty[64], inc[64], full[64];
    CHECK(evm_trie_empty_root(empty) == 0, "empty root");

    /* B0: every empty table gives the empty root; v2_trie_state row is 0 */
    int cap = -1;
    CHECK(nodus_witness_db_s20_trie_capture(fx->w, &cap) == 0 && cap == 0,
          "B0: capture starts at 0");
    for (int leg = 1; leg <= 8; leg++) {
        CHECK(nodus_witness_v2_trie_build_leg(fx->w, leg, inc, full) == 0 &&
              memcmp(inc, empty, 64) == 0 && memcmp(full, empty, 64) == 0,
              "B0: an empty leg is SHA3-512(0x80)");
    }

    /* A: capture 0 — nothing is captured */
    CHECK(populate(fx, 0) == 0, "A: first population");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "A: capture 0 leaves v2_trie_dirty empty");

    /* B1: root == oracle for every leg, and a second row each */
    CHECK(populate(fx, 1) == 0, "B1: second population");
    CHECK(run_sql(db, "BEGIN") == 0, "B1: begin");
    CHECK(nodus_witness_v2_trie_build_all(fx->w) == 0, "B1: build_all");
    CHECK(run_sql(db, "COMMIT") == 0, "B1: commit");
    CHECK(roots_equal_oracle(fx, "B1") == 0,
          "B1: every leg: incremental = full rebuild = oracle");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_roots") == 8, "B1: 8 roots");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_nodes") > 0,
          "B1: nodes were written");

    /* B2: a claim of another domain is not part of the CORE leg */
    uint8_t before[64], after[64];
    CHECK(nodus_witness_v2_trie_build_leg(fx->w, 3, before, full) == 0,
          "B2: leg 3 before");
    CHECK(claim_sql(db, 0x40, 2, 77) == 0, "B2: a domain-2 claim");
    CHECK(nodus_witness_v2_trie_build_leg(fx->w, 3, after, full) == 0 &&
          memcmp(before, after, 64) == 0,
          "B2: another domain's claim does not move the CORE leg");
    CHECK(run_sql(db, "DELETE FROM v2_claims_spent WHERE target_domain_id "
                      "= 2") == 0, "B2: cleanup");

    /* B3: malformed rows are -1 (never a shorter trie) */
    struct { int leg; const char *add; const char *undo; } bad[] = {
        { 1, "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
             "tx_hash, output_index, block_height, created_at, unlock_block, "
             "domain_id) VALUES (x'010203', 'o', 1, zeroblob(64), "
             "zeroblob(64), 0, 0, 0, 0, 1)",
             "DELETE FROM utxo_set WHERE nullifier = x'010203'" },
        { 2, "INSERT INTO tokens (token_id, name, symbol, decimals, supply, "
             "creator_fp) VALUES (CAST(zeroblob(63)||x'99' AS BLOB), 'n', "
             "'s', 300, 1, 'f')",
             "DELETE FROM tokens WHERE decimals = 300" },
        { 3, "INSERT INTO v2_claims_spent (nullifier, manifest_hash, "
             "target_domain_id, target_asset_ref, leaf_index, amount, "
             "claimed_height, output_id) VALUES (CAST(zeroblob(63)||x'98' "
             "AS BLOB), zeroblob(64), 1, zeroblob(64), 0, 0, 1, "
             "zeroblob(64))",
             "DELETE FROM v2_claims_spent WHERE amount = 0" },
        { 6, "INSERT INTO v2_storage_segments (k, root, published_height) "
             "VALUES (5, zeroblob(64), 9)",
             "DELETE FROM v2_storage_segments WHERE k = 5" },
        { 7, "INSERT INTO validator_set_snapshots (epoch_start, "
             "active_count, snapshot_hash, snapshot_blob, "
             "created_at_height) VALUES (99999, 1, x'010203', x'00', 1)",
             "DELETE FROM validator_set_snapshots WHERE epoch_start = 99999" },
        { 8, "INSERT INTO v2_attendance_epoch (epoch_start, digest) VALUES "
             "(99999, x'010203')",
             "DELETE FROM v2_attendance_epoch WHERE epoch_start = 99999" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(run_sql(db, bad[i].add) == 0, "B3: plant the malformed row");
        CHECK(nodus_witness_v2_trie_build_leg(fx->w, bad[i].leg, inc, full)
              == -1, "B3: a malformed row is a fault");
        CHECK(run_sql(db, bad[i].undo) == 0, "B3: remove it");
        CHECK(nodus_witness_v2_trie_build_leg(fx->w, bad[i].leg, inc, full)
              == 0, "B3: the leg builds again");
    }
    /* a registry row whose fingerprint is not the hash of its key */
    CHECK(run_sql(db,
        "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, bond, "
        "status, registered_height, exit_height, fail_streak, grace_until) "
        "VALUES (zeroblob(64), zeroblob(2592), zeroblob(64), 1, 1, 1, 0, "
        "0, 0)") == 0, "B3: registry row with a wrong fingerprint");
    CHECK(nodus_witness_v2_trie_build_leg(fx->w, 5, inc, full) == -1,
          "B3: node_fp != SHA3-512(node_pk) is a fault");
    CHECK(run_sql(db, "DELETE FROM v2_storage_nodes WHERE node_fp = "
                      "zeroblob(64)") == 0, "B3: remove it");
    /* segments must be exactly 1..n */
    CHECK(run_sql(db, "DELETE FROM v2_storage_segments WHERE k = 1") == 0,
          "B3: a gap in k");
    CHECK(nodus_witness_v2_trie_build_leg(fx->w, 6, inc, full) == -1,
          "B3: non-contiguous segments are a fault");
    CHECK(seg_sql(db, 1) == 0 &&
          nodus_witness_v2_trie_build_leg(fx->w, 6, inc, full) == 0,
          "B3: restored");
    CHECK(run_sql(db, "DELETE FROM v2_trie_dirty") == 0, "B3: tidy");
    return 0;
}

/* ── C, D, E, F: capture, flush, rollback, restart, faults ──────────── */
static int test_flush(fx_t *fx) {
    sqlite3 *db = fx->w->db;
    uint8_t r_before[8][64], r_now[64];

    CHECK(set_capture1(fx) == 0, "C0: capture to 1 inside a transaction");
    int cap = -1;
    CHECK(nodus_witness_db_s20_trie_capture(fx->w, &cap) == 0 && cap == 1,
          "C0: capture is 1");
    CHECK(nodus_witness_v2_trie_set_capture(fx->w, 0) == -1,
          "F0: set_capture outside a transaction is refused");
    CHECK(nodus_witness_v2_trie_flush(fx->w) == -1,
          "F0: flush outside a transaction is refused");

    /* C1: block 1 — every kind of write */
    for (int leg = 1; leg <= 8; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(fx->w, leg, r_before[leg - 1])
              == 0, "C1: roots readable before the block");

    CHECK(run_sql(db, "BEGIN") == 0, "C1: begin");
    /* (nodus_witness_utxo_add_locked is not used: its INSERT OR IGNORE
     * names no domain_id, which is NOT NULL without a default since S5, so
     * it silently inserts nothing — plan §4.3 calls it unreached) */
    CHECK(utxo_sql(db, 0x71, 777) == 0, "C1: utxo insert");
    CHECK(utxo_sql(db, 0x61, 10) == 0, "C1: utxo created ...");
    CHECK(run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                      NB("61")) == 0, "C1: ... and spent in the same block");
    CHECK(run_sql(db, "UPDATE utxo_set SET amount = amount + 5 WHERE "
                      "nullifier = " NB("01")) == 0, "C1: utxo update");
    CHECK(run_sql(db, "UPDATE utxo_set SET nullifier = " NB("7f") " WHERE "
                      "nullifier = " NB("02")) == 0,
          "C1: a primary-key change");
    CHECK(token_sql(db, 0x62, 6) == 0 &&
          run_sql(db, "UPDATE tokens SET supply = 5 WHERE token_id = "
                      NB("01")) == 0, "C1: tokens");
    CHECK(claim_sql(db, 0x63, 1, 12) == 0 &&
          claim_sql(db, 0x64, 3, 13) == 0, "C1: claims (CORE and another)");
    CHECK(name_sql(db, "carol", 0x65) == 0 &&
          run_sql(db, "DELETE FROM v2_names WHERE name = CAST('bobby' AS "
                      "BLOB)") == 0, "C1: names");
    CHECK(node_sql(fx->w, 0x66, 900, 1) == 0 &&
          run_sql(db, "UPDATE v2_storage_nodes SET status = 3, bond = 0 "
                      "WHERE bond = 5000") == 0, "C1: registry");
    CHECK(seg_sql(db, 4) == 0 && seg_sql(db, 3) == 0,
          "C1: segments inserted out of order");
    CHECK(vset_sql(db, 5000) == 0 && vset_sql(db, 2880) == 0 &&
          att_sql(db, 4000) == 0,
          "C1: vset / attendance inserted out of order");
    CHECK(run_sql(db, "UPDATE v2_attendance_epoch SET digest = CAST("
                      "zeroblob(63)||x'c3' AS BLOB) WHERE epoch_start = "
                      "1440") == 0, "C1: attendance update");

    /* dirty contents: the keys, once each */
    CHECK(dirty_of(db, 1) == 5 &&           /* 71, 61 (created+spent), 01,
                                             * 02 (OLD), 7f (NEW)         */
          dirty_of(db, 2) == 2 && dirty_of(db, 3) == 2 &&
          dirty_of(db, 4) == 2 && dirty_of(db, 5) == 2 &&
          dirty_of(db, 6) == 2 && dirty_of(db, 7) == 2 &&
          dirty_of(db, 8) == 2,
          "C1: the dirty keys are the OLD / NEW keys, duplicates collapsed");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty WHERE leg = 6 AND "
                 "typeof(key) = 'integer'") == 2,
          "C1: integer legs hold the integer key");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty WHERE leg = 1 AND "
                 "typeof(key) = 'blob' AND length(key) = 64") == 5,
          "C1: blob legs hold the blob key");
    CHECK(nodus_witness_v2_trie_leg_root(fx->w, 1, r_now) == -1,
          "C1: a root read with keys pending is refused");
    CHECK(nodus_witness_v2_trie_leg_root(fx->w, 3, r_now) == -1,
          "C1: ... on every leg with keys pending");
    int64_t nd = -1;
    CHECK(nodus_witness_v2_trie_dirty_count(fx->w, &nd) == 0 && nd == 19,
          "C1: dirty_count");

    CHECK(nodus_witness_v2_trie_flush(fx->w) == 0, "C1: flush");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "C1: the dirty table is empty after the flush");
    CHECK(run_sql(db, "COMMIT") == 0, "C1: commit");
    CHECK(roots_equal_oracle(fx, "C1") == 0,
          "C1: every leg: flushed root = oracle = build from rows");
    int moved = 0;
    for (int leg = 1; leg <= 8; leg++) {
        CHECK(nodus_witness_v2_trie_leg_root(fx->w, leg, r_now) == 0,
              "C1: root readable");
        if (memcmp(r_now, r_before[leg - 1], 64) != 0) moved++;
    }
    CHECK(moved == 8, "C1: every leg's root moved");

    /* C2: a block that only restores what it wrote leaves the roots */
    for (int leg = 1; leg <= 8; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(fx->w, leg, r_before[leg - 1])
              == 0, "C2: roots before");
    CHECK(run_sql(db, "BEGIN") == 0 && utxo_sql(db, 0x81, 3) == 0 &&
          run_sql(db, "DELETE FROM utxo_set WHERE nullifier = " NB("81"))
          == 0 && dirty_of(db, 1) == 1, "C2: created and spent");
    CHECK(nodus_witness_v2_trie_flush(fx->w) == 0 &&
          run_sql(db, "COMMIT") == 0, "C2: flush + commit");
    CHECK(nodus_witness_v2_trie_leg_root(fx->w, 1, r_now) == 0 &&
          memcmp(r_now, r_before[0], 64) == 0,
          "C2: the root is as it was (a delete of an absent key)");

    /* D: rollback */
    CHECK(run_sql(db, "BEGIN") == 0, "D1: begin");
    CHECK(utxo_sql(db, 0x90, 1) == 0, "D1: block write");
    CHECK(run_sql(db, "SAVEPOINT item") == 0 && utxo_sql(db, 0x91, 2) == 0 &&
          seg_sql(db, 5) == 0, "D1: item writes");
    CHECK(dirty_of(db, 1) == 2 && dirty_of(db, 6) == 1, "D1: captured");
    CHECK(run_sql(db, "ROLLBACK TO item; RELEASE item") == 0,
          "D1: item rolled back");
    CHECK(dirty_of(db, 1) == 1 && dirty_of(db, 6) == 0,
          "D1: the item's dirty rows left with its writes");
    CHECK(nodus_witness_v2_trie_flush(fx->w) == 0, "D1: flush");
    CHECK(run_sql(db, "ROLLBACK") == 0, "D2: whole block rolled back");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
          nodus_witness_v2_trie_leg_root(fx->w, 1, r_now) == 0 &&
          memcmp(r_now, r_before[0], 64) == 0,
          "D2: roots and dirty rows as before the block");
    CHECK(roots_equal_oracle(fx, "D2") == 0, "D2: roots equal the rows");

    /* E: restart */
    CHECK(fx_restart(fx) == 0, "E1: the SQLite file reopened");
    db = fx->w->db;
    CHECK(run_sql(db, "BEGIN") == 0 && utxo_sql(db, 0xA0, 9) == 0 &&
          att_sql(db, 2160) == 0 &&
          nodus_witness_v2_trie_flush(fx->w) == 0 &&
          run_sql(db, "COMMIT") == 0, "E1: a block after the restart");
    CHECK(roots_equal_oracle(fx, "E1") == 0,
          "E1: roots after the restart equal the rows");

    /* F: a corrupted stored node */
    for (int leg = 1; leg <= 8; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(fx->w, leg, r_before[leg - 1])
              == 0, "F1: roots before");
    CHECK(run_sql(db,
        "UPDATE v2_trie_nodes SET rlp = x'c0' WHERE digest = (SELECT root "
        "FROM v2_trie_roots WHERE leg = 1)") == 0, "F1: corrupt the root "
        "node of leg 1");
    CHECK(run_sql(db, "BEGIN") == 0 && utxo_sql(db, 0xA1, 9) == 0,
          "F1: a block touching leg 1");
    CHECK(nodus_witness_v2_trie_flush(fx->w) == -1,
          "F1: a corrupted node is a fault at the next touch");
    CHECK(run_sql(db, "ROLLBACK") == 0, "F1: the host rolls back");
    CHECK(nodus_witness_v2_trie_leg_root(fx->w, 1, r_now) == 0 &&
          memcmp(r_now, r_before[0], 64) == 0, "F1: leg 1 root unchanged");
    /* put the node back (the real body is the oracle's rebuilt node) */
    CHECK(run_sql(db, "DELETE FROM v2_trie_nodes") == 0, "F1: wipe nodes");
    CHECK(run_sql(db, "BEGIN") == 0 &&
          nodus_witness_v2_trie_build_all(fx->w) == 0 &&
          run_sql(db, "COMMIT") == 0, "F1: rebuild from rows");
    CHECK(roots_equal_oracle(fx, "F1") == 0, "F1: healthy again");

    /* F2: dirty keys but no roots row */
    CHECK(run_sql(db, "BEGIN") == 0 && utxo_sql(db, 0xA2, 4) == 0 &&
          run_sql(db, "DELETE FROM v2_trie_roots WHERE leg = 1") == 0,
          "F2: drop the roots row");
    CHECK(nodus_witness_v2_trie_flush(fx->w) == -1,
          "F2: dirty keys without a committed root are a fault");
    CHECK(run_sql(db, "ROLLBACK") == 0, "F2: rolled back");
    CHECK(nodus_witness_v2_trie_leg_root(fx->w, 1, r_now) == 0,
          "F2: the row is back");
    CHECK(nodus_witness_v2_trie_leg_root(fx->w, 0, r_now) == -1 &&
          nodus_witness_v2_trie_leg_root(fx->w, 9, r_now) == -1,
          "F2: a leg outside 1..8 is refused");
    return 0;
}

/* ── G: schema ──────────────────────────────────────────────────────── */
static int test_schema(fx_t *fx) {
    sqlite3 *db = fx->w->db;
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 1,
          "G0: shape ok at the start");
    CHECK(q1(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                 "AND name LIKE 'v2_trie_l%'") == 24, "G0: 24 triggers");
    CHECK(q1(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' "
                 "AND name = 'v2_storage_nodes_by_status'") == 1,
          "G0: the registry index");

    CHECK(run_sql(db, "DROP TRIGGER v2_trie_l4_upd") == 0, "G1: drop one");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 0,
          "G1: a dropped trigger is noticed");
    CHECK(nodus_witness_db_s20_reseed(fx->w) == -1,
          "G1: the open-time check refuses it (and does not recreate it)");
    CHECK(q1(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                 "AND name = 'v2_trie_l4_upd'") == 0,
          "G1: it was not silently recreated");
    CHECK(run_sql(db, "CREATE TRIGGER v2_trie_l4_upd AFTER UPDATE ON "
                      "v2_names BEGIN SELECT 1; END") == 0,
          "G2: an altered trigger of the same name");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 0,
          "G2: an altered trigger is noticed");
    CHECK(run_sql(db, "DROP TRIGGER v2_trie_l4_upd; CREATE TRIGGER "
                      "v2_trie_l4_upd AFTER UPDATE ON v2_names WHEN (SELECT "
                      "capture FROM v2_trie_state WHERE id = 1) = 1 BEGIN "
                      "INSERT OR IGNORE INTO v2_trie_dirty(leg, key) VALUES "
                      "(4, OLD.name); INSERT OR IGNORE INTO "
                      "v2_trie_dirty(leg, key) VALUES (4, NEW.name); END;")
          == 0, "G3: the exact text restored");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 1 &&
          nodus_witness_db_s20_reseed(fx->w) == 0,
          "G3: and accepted again");

    CHECK(run_sql(db, "DROP INDEX v2_storage_nodes_by_status") == 0,
          "G4: drop the index");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 0,
          "G4: a missing index is noticed");
    CHECK(run_sql(db, "CREATE INDEX v2_storage_nodes_by_status ON "
                      "v2_storage_nodes(status, node_fp)") == 0,
          "G4: restored");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 1, "G4: ok");

    /* the capture reader: missing row, value outside {0, 1} */
    int cap = -1;
    CHECK(run_sql(db, "DELETE FROM v2_trie_state") == 0, "G5: no row");
    CHECK(nodus_witness_db_s20_trie_capture(fx->w, &cap) == -1,
          "G5: a missing capture row is -1");
    CHECK(run_sql(db, "DROP TABLE v2_trie_state; CREATE TABLE "
                      "v2_trie_state(id INTEGER PRIMARY KEY, capture); "
                      "INSERT INTO v2_trie_state VALUES (1, 2)") == 0,
          "G5: a table without its CHECK holding 2");
    CHECK(nodus_witness_db_s20_trie_capture(fx->w, &cap) == -1,
          "G5: a value outside {0, 1} is -1");
    CHECK(run_sql(db, "UPDATE v2_trie_state SET capture = '1'") == 0 &&
          nodus_witness_db_s20_trie_capture(fx->w, &cap) == -1,
          "G5: a TEXT value is -1");
    CHECK(nodus_witness_db_s20_trie_shape_ok(fx->w) == 0,
          "G5: the altered state table is noticed by the shape check");
    return 0;
}

/* ── H: the block-start capture check on a real chain ───────────────── */
static int test_block_start(void) {
    v2x_chain_t c;
    CHECK(v2x_chain_open(&c, "hf9trie", 0x3C) == 0, "H0: chain fixture");
    nodus_witness_t *w = c.w;
    uint32_t ver = 0;
    CHECK(nodus_witness_db_schema_version(w, &ver) == 0 &&
          ver == NODUS_V2_SCHEMA_VERSION_S20, "H0: the chain is S20");
    CHECK(nodus_witness_db_s20_trie_shape_ok(w) == 1, "H0: trie shape ok");

    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = 1;
    b.epoch = nodus_v2_epoch_for_height(1);
    CHECK(v2x_cmt_apply_ok(w, &b) == 0,
          "H1: control: an idle block commits at capture 0");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "H1: the committed block captured nothing");

    CHECK(run_sql(w->db, "UPDATE v2_trie_state SET capture = 1") == 0,
          "H2: capture 1 under a generation <= 5");
    memset(&b, 0, sizeof(b));
    b.global_height = 2;
    b.epoch = nodus_v2_epoch_for_height(2);
    CHECK(v2x_cmt_apply(w, &b) != 0, "H2: the block is a fault");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM v2_blocks WHERE global_height = 2")
          == 0, "H2: no block row was written");
    CHECK(run_sql(w->db, "UPDATE v2_trie_state SET capture = 0") == 0,
          "H2: back to 0");

    CHECK(run_sql(w->db, "DELETE FROM v2_trie_state") == 0, "H3: no row");
    memset(&b, 0, sizeof(b));
    b.global_height = 2;
    b.epoch = nodus_v2_epoch_for_height(2);
    CHECK(v2x_cmt_apply(w, &b) != 0, "H3: a missing row is a fault");
    CHECK(run_sql(w->db, "INSERT INTO v2_trie_state (id, capture) VALUES "
                         "(1, 0)") == 0, "H3: restored");
    memset(&b, 0, sizeof(b));
    b.global_height = 2;
    b.epoch = nodus_v2_epoch_for_height(2);
    CHECK(v2x_cmt_apply_ok(w, &b) == 0,
          "H3: the next idle block commits again");

    /* a dropped trigger: the production open path refuses the database */
    CHECK(run_sql(w->db, "DROP TRIGGER v2_trie_l1_del") == 0, "H4: drop");
    sqlite3_close(w->db);
    w->db = NULL;
    memset(w, 0, sizeof(*w));
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", c.dir);
    CHECK(nodus_witness_create_chain_db(w, c.chain32) != 0,
          "H4: the open path refuses a database with a missing trigger");

    /* a value outside {0, 1}: recreate the state table without its CHECK
     * on a fresh chain (the refused database above is closed) */
    v2x_chain_close(&c);
    CHECK(v2x_chain_open(&c, "hf9trie2", 0x3D) == 0, "H5: second chain");
    CHECK(run_sql(c.w->db, "DROP TABLE v2_trie_state; CREATE TABLE "
                           "v2_trie_state(id INTEGER PRIMARY KEY, capture); "
                           "INSERT INTO v2_trie_state VALUES (1, 2)") == 0,
          "H5: capture 2");
    memset(&b, 0, sizeof(b));
    b.global_height = 1;
    b.epoch = nodus_v2_epoch_for_height(1);
    CHECK(v2x_cmt_apply(c.w, &b) != 0,
          "H5: a value outside {0, 1} is a fault");
    v2x_chain_close(&c);
    return 0;
}

/* ── I: the factored-out vset leaf ──────────────────────────────────── */
static int test_vset_leaf(void) {
    uint8_t h0[64], h1[64], l0[64], l1[64], want[64], root[64];
    memset(h0, 0x11, 64);
    memset(h1, 0x22, 64);
    /* the documented bytes: tag "NDS.VSLEAF.v1" zero-padded to 16, the
     * epoch as 8 bytes big-endian, the 64-byte snapshot hash */
    uint8_t pre[16 + 8 + 64];
    memset(pre, 0, sizeof(pre));
    memcpy(pre, "NDS.VSLEAF.v1", 13);
    be64(720, pre + 16);
    memcpy(pre + 24, h0, 64);
    CHECK(qgp_sha3_512(pre, sizeof(pre), want) == 0, "I: oracle leaf");
    CHECK(dna_v2_vset_leaf_hash(720, h0, l0) == 0 &&
          memcmp(l0, want, 64) == 0, "I: the leaf equals the documented bytes");
    be64(1440, pre + 16);
    memcpy(pre + 24, h1, 64);
    CHECK(qgp_sha3_512(pre, sizeof(pre), want) == 0 &&
          dna_v2_vset_leaf_hash(1440, h1, l1) == 0 &&
          memcmp(l1, want, 64) == 0, "I: second leaf");
    CHECK(dna_v2_vset_leaf_hash(1, NULL, l0) == -1 &&
          dna_v2_vset_leaf_hash(1, h0, NULL) == -1, "I: NULL refused");

    /* the root over one leaf is the leaf; over two the documented node */
    uint64_t eps[2] = { 720, 1440 };
    uint8_t hs[2][64];
    memcpy(hs[0], h0, 64);
    memcpy(hs[1], h1, 64);
    CHECK(dna_v2_vset_root(eps, (const uint8_t (*)[64])hs, 1, root) == 0 &&
          memcmp(root, l0, 64) == 0, "I: root over one leaf = the leaf");
    uint8_t node[16 + 128];
    memset(node, 0, sizeof(node));
    memcpy(node, "NDS.VSNODE.v1", 13);
    memcpy(node + 16, l0, 64);
    memcpy(node + 80, l1, 64);
    CHECK(qgp_sha3_512(node, sizeof(node), want) == 0 &&
          dna_v2_vset_root(eps, (const uint8_t (*)[64])hs, 2, root) == 0 &&
          memcmp(root, want, 64) == 0,
          "I: root over two leaves = the documented node hash");
    return 0;
}

int main(void) {
    fx_t fx;
    if (fx_open(&fx) != 0) {
        fprintf(stderr, "test_hf9_trie_legs: fixture failed\n");
        return 1;
    }
    int rc = test_build(&fx);
    if (!rc) rc = test_flush(&fx);
    if (!rc) rc = test_schema(&fx);
    fx_close(&fx);
    if (!rc) rc = test_vset_leaf();
    if (!rc) rc = test_block_start();
    if (rc) {
        fprintf(stderr, "test_hf9_trie_legs: FAILED\n");
        return 1;
    }
    printf("test_hf9_trie_legs: %d checks passed\n", g_checks);
    return 0;
}
