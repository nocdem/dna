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
 *     of the CORE leg (the root does not move). A claim whose stored
 *     target_domain_id is REAL 1.5 (the column is not STRICT) is not part
 *     of it either, in the build (B2b) and in the flush (end of F, "G0"):
 *     the selection is the historical SQL predicate `target_domain_id =
 *     1`, never an integer coercion of the stored value (Sol verifier
 *     row 1).
 *  C. TRIGGERS + FLUSH. With capture = 1 inside a transaction: inserts,
 *     updates (including a primary-key change), and deletes on every
 *     table put exactly the OLD / NEW keys in v2_trie_dirty (duplicates
 *     collapsed); a leg root read with a key pending is -1; the flush
 *     writes v2_trie_roots; afterwards the dirty table is empty and every
 *     leg root equals the oracle recomputation and the build-from-rows
 *     root (the trie is a function of the rows). A key written and
 *     restored inside one block (a utxo created and deleted) leaves the
 *     root as it was.
 *  C3. ALL 24 TRIGGER OPERATIONS (Sol verifier row 2). With capture 1, for
 *     each of the eight tables, one INSERT, one UPDATE of a non-key column
 *     and one DELETE of the same row, each in its own transaction: the
 *     dirty table holds exactly the operation's key (queried by value,
 *     blob or integer) and nothing else, and after the flush every leg
 *     root equals the oracle recomputation and the build-from-rows root.
 *     A trigger body that records the wrong key, no key, or none (a
 *     no-op) fails here; the shape check (G) cannot see that, because it
 *     compares the stored SQL with SQL generated from the same constants.
 *  D. ROLLBACK. An item SAVEPOINT rolled back removes its dirty rows and
 *     leaves the roots; a whole transaction rolled back after a flush
 *     restores the roots row, the dirty rows AND the complete node table:
 *     the table is dumped (digest and body of every row) before the block,
 *     the flush is asserted to have changed it (control), and the dump
 *     after the rollback is compared byte for byte BEFORE any oracle call
 *     (the oracle rebuilds the tries and writes nodes; Sol verifier
 *     row 3).
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
 *  J. GENERATION 6 ON THE LIVE BLOCK PATH (HF-9 WP3, plan §5.2, §5.3, §12
 *     T-5 generation-6 rows): a real chain climbing 2 -> 6 through the
 *     engine's own edges (params 9 / 14 / 18 / 22 / 24, direct rows),
 *     blocks 14 and 15 committed under generation 6. J0: capture 1, 24
 *     triggers, every stored leg root equals the oracle and the rows.
 *     J1 (block-start capture consistency, the generation >= 6 half; the
 *     <= 5 half is H): capture 0, a missing state row and ONE dropped
 *     trigger each fault the block before any item runs with the database
 *     byte-identical, and the block commits once restored (the trigger
 *     from its stored SQL). J2: a writer that fires in phase 13 (a SQLite
 *     trigger on v2_blocks inserting a token) makes the dirty-empty
 *     assertion fault the block ("phase 13-bis"), nothing of it survives,
 *     and the same block commits without the writer. J3: a stored node
 *     body altered (digest unchanged) is a node FAULT at the phase-8-pre
 *     flush that touches it (the node does not vote), the database byte-
 *     identical; restored, the block commits and the roots equal the
 *     rows. J4: the head_activate guard's getter — a trie-leg root read
 *     with a dirty key of its leg pending refuses, another leg reads.
 *     J5: a state value outside {0, 1} faults under generation 6 (run
 *     last: the table is recreated without its CHECK).
 *
 *  K. THE ENGINE'S OWN WRITERS UNDER GENERATION 6 (HF-9 WP3, Sol verifier
 *     row 6; plan §4.3, §12 T-5): the J ladder again (params 9 / 14 / 18 /
 *     22 / 24, the edge at block 13), then blocks carrying REAL signed
 *     transactions and claims, each followed by: v2_trie_dirty empty,
 *     exactly the expected legs moved (and no other), every stored leg
 *     root equal to the oracle recomputation and the build-from-rows root.
 *      K1 NAME_REGISTER  (rtn_core_mutate: utxo DELETE + INSERT, v2_names
 *         INSERT)                                        -> legs 1, 4
 *      K2 TOKEN_CREATE   (rtn_core_mutate: tokens INSERT, utxo DELETE +
 *         INSERTs; the governed fee read from chain_config) -> legs 1, 2
 *      K3 SPEND          (rtn_core_mutate: utxo DELETE + 2 INSERTs)
 *                                                        -> leg 1
 *      K4 rollback: a SPEND block that faults after the flush and phase 8
 *         (V2AP_FAIL_AFTER_DOMAIN_ROOTS) leaves the database byte-
 *         identical, the coin unspent, no dirty key, the node table and
 *         every leg root as before; K4b an ITEM refused in exec (a spend
 *         of a spent coin) leaves no dirty key and moves no root; K4c the
 *         faulted spend, applied for real, moves leg 1.
 *      K5 the first EPOCH BOUNDARY under generation 6 (idle blocks to
 *         DNAC_EPOCH_LENGTH): nodus_witness_vset_insert and
 *         v2ep_attendance_digest write a snapshot and a digest; legs 7
 *         and 8 moved.                                   -> legs 7, 8
 *      K6 CLAIM RELEASE on a chain whose genesis manifest commits a three-
 *         leaf distribution to CORE (nodus_rt_core_claim_apply: utxo
 *         INSERT; claim_spend_insert: v2_claims_spent INSERT): a claim
 *         block faulting after the flush is rolled back whole; then two
 *         claims in one block and a third in the next    -> legs 1, 3
 *      K7 EPOCH RELEASES (v2ep_release_utxo, nodus_witness_v2_epoch.c:998
 *         the graduation bond, :679 the delegation release): a chain with
 *         one extra bonded RETIRING validator outside the frozen
 *         snapshots and one delegation to it (seeded after the document's
 *         seven seats, test_v2_epoch.c's late-joiner shape, genesis flag
 *         V2X_SEED_NOT_REAL_STATUSES). The first boundary is applied
 *         twice with an injection (after the first graduate's release,
 *         after its delegation release): each a node FAULT, database
 *         byte-identical, dirty empty, node table and leg roots as before
 *         and equal to the oracle; then for real: the bond UTXO (index
 *         200) and the delegation UTXO (index 0x40000000) exist, the
 *         delegation row is gone, legs 1, 7 and 8 moved, every leg root
 *         equals the oracle and the rows.
 *      K4d (inside K4) the engine's ITEM rollback after captured writes: a
 *         SPEND stopped after its effect 1 (V2AP_FAIL_AFTER_EFFECT_APPLY)
 *         is refused, the block applies; read inside the block's
 *         transaction after the flush: the coin is back, no dirty key,
 *         every leg root as before and equal to the oracle.
 *
 * ── NOT COVERED ─────────────────────────────────────────────────────────
 *  Writers exercised: SQL INSERT / UPDATE / DELETE of the plan §4.3
 *  statement shapes for every table (A-J), plus the engine's own writers
 *  in the blocks above: the genesis seed, the edge's build, and (K)
 *  rtn_core_mutate (spend, token create, name register),
 *  nodus_rt_core_claim_apply, nodus_witness_v2_claim_spend_insert,
 *  nodus_witness_vset_insert and v2ep_attendance_digest. NOT driven here:
 *   - the storage exit release (nodus_witness_v2_storage.c:1180-1183,
 *     through nodus_witness_v2_epoch_release_utxo): WP4;
 *   - the storage writers (v2_storage_nodes, v2_storage_segments, the
 *     storage exit release): HF-9 package WP4 (storage work excluded);
 *   - the storage boundary under generation 6, the head_activate guard's
 *     engine call site (an in-block domain activation under generation 6;
 *     the getter guard itself is C and J4) and a restart of the process
 *     across the edge: the harness's (T-13, WP7).
 *  J3 and the pending-key flush of J4 read the same node store the edge
 *  test (test_hf9_edge.c) fills. The HF-9 store bind-failure test (T-3
 *  part) is test_evm_trie_store_fault.c (-DQGP_FAULT_INJECT=ON).
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  register_witness_test (NODUS_WITNESS_INTERNAL_API); only where
 *  NODUS_EVM_ENABLED (the trie is EVM-only). No fault injection (the
 *  injection points K4 / K6 use are the engine's own block fields, no
 *  compile flag), no environment. J and K assume no epoch boundary among
 *  the heights they drive before K5 and require DNAC_EPOCH_LENGTH > 40
 *  (CHECKed: a short-epoch build fails the guard instead of running the
 *  wrong scenario); K5 applies DNAC_EPOCH_LENGTH blocks, one at a time.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 *  /tmp/test_hf9_trie_XXXXXX, /tmp/test_hf9_trie_g6_XXXXXX,
 *  /tmp/test_hf9_trie_k_XXXXXX and /tmp/v2x_hf9trie_XXXXXX directories,
 *  removed on exit (a crash leaves one).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - The oracle shares the public leaf-hash functions and the key
 *    convention with the code under test; it proves "incremental =
 *    full rebuild of the rows" (T-5), NOT the byte choices — those are
 *    T-4's independent KAT (hf9_kat.json, follow-up).
 *  - A trigger or a flush that wrote nothing would fail C (dirty rows and
 *    roots are asserted non-empty / changed before they are compared).
 *  - C3 compares keys and roots for one row per table; an operation whose
 *    trigger is correct for that row but wrong for another shape of row
 *    (for example a key change by UPDATE, covered separately in C1 for
 *    utxo_set only) is not covered for the other seven tables.
 *  - B2b / G0 pass vacuously if the REAL value were stored as an integer;
 *    the typeof(...) = 'real' and `target_domain_id = 1` controls in B2b
 *    assert the premise.
 *  - Section B's malformed-row cases rely on the table accepting the
 *    malformed value; the tables with CHECK constraints (names, registry,
 *    segments) cannot hold a bad type, so those cases use the values the
 *    CHECKs allow.
 *  - H passes vacuously if the idle block would fault anyway; the control
 *    (the first idle block commits) and the restore (the next idle block
 *    commits again) bracket every refusal.
 *  - K proves "the stored leg roots equal the oracle's recomputation from
 *    the rows" and "exactly the expected legs moved"; the oracle shares
 *    the leaf-hash functions and the key convention with the code under
 *    test (see above), so K does not prove the byte choices (T-4's KAT).
 *    The expected-moved masks are this test's reading of each writer's
 *    tables (K1 0x09, K2 0x03, K3 / K4c 0x01, K6 0x05, exact: a writer
 *    that also touched another leg, or one that wrote nothing, fails the
 *    mask). K5 and K7 are NOT exact: they require the named legs to move
 *    (K5 legs 7 and 8; K7 legs 1, 7 and 8) and do not require any other
 *    leg to stay unchanged; their guard against a stray leg is the
 *    full-rebuild comparison, which proves consistency with the rows,
 *    not absence of other changes. The transactions are built
 *    with the sender's key and applied through the cometbft lane (the
 *    quorum of a SYSTEM operation is not involved: CORE legs only).
 *  - K5's boundary carries no votes: the first boundary leaves every
 *    validator at one missed epoch (the retirement threshold is
 *    DNAC_AUTO_RETIRE_EPOCHS = 2), so the validator set is unchanged; the
 *    snapshot and the digest rows are asserted by count, not by content.
 *  - K4b's refusal is a spend of an already spent coin; it proves the
 *    item-level rollback leaves no dirty key for a refusal that happens
 *    before any write, not for one that happens after a captured write
 *    (the SAVEPOINT removal of captured keys is D's SQL case).
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "evm/trie/evm_trie.h"
#include "evm/trie/evm_trie_full.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/effect_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/manifest_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

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

/* The whole node table as one string (digest and body of every row, in
 * digest order); the caller frees it. NULL on any fault. */
static char *nodes_dump(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hex(digest) || ':' || hex(rlp) FROM v2_trie_nodes "
            "ORDER BY digest", -1, &st, NULL) != SQLITE_OK)
        return NULL;
    size_t cap = 1024, len = 0;
    char *out = malloc(cap);
    int rc;
    while (out && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        size_t n = t ? strlen(t) : 0;
        if (len + n + 2 > cap) {
            while (len + n + 2 > cap) cap *= 2;
            char *no = realloc(out, cap);
            if (!no) { free(out); out = NULL; break; }
            out = no;
        }
        memcpy(out + len, t, n);
        len += n;
        out[len++] = '\n';
    }
    if (out && rc != SQLITE_DONE) { free(out); out = NULL; }
    sqlite3_finalize(st);
    if (out) out[len] = 0;
    return out;
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

    /* B2b (Sol verifier row 1): the selection is the historical SQL
     * predicate `target_domain_id = 1`, with no integer coercion. The
     * column is INTEGER-affinity but not STRICT, so a REAL 1.5 stays REAL;
     * sqlite3_column_int64 would turn it into 1 and let the row in. */
    CHECK(run_sql(db,
        "INSERT INTO v2_claims_spent (nullifier, manifest_hash, "
        "target_domain_id, target_asset_ref, leaf_index, amount, "
        "claimed_height, output_id) VALUES (CAST(zeroblob(63)||x'41' AS "
        "BLOB), CAST(zeroblob(63)||x'ee' AS BLOB), 1.5, zeroblob(64), 2, "
        "5, 9, zeroblob(64))") == 0, "B2b: a claim with a REAL domain");
    CHECK(q1(db, "SELECT typeof(target_domain_id) = 'real' FROM "
                 "v2_claims_spent WHERE nullifier = " NB("41")) == 1,
          "B2b: the value is stored as REAL (control)");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_claims_spent WHERE "
                 "target_domain_id = 1 AND nullifier = " NB("41")) == 0,
          "B2b: the historical predicate excludes it (control)");
    CHECK(nodus_witness_v2_trie_build_leg(fx->w, 3, after, full) == 0 &&
          memcmp(before, after, 64) == 0,
          "B2b: a REAL-domain claim does not enter the CORE leg (build)");
    CHECK(run_sql(db, "DELETE FROM v2_claims_spent WHERE nullifier = "
                      NB("41")) == 0, "B2b: cleanup");

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
    char *nodes0 = nodes_dump(db);
    CHECK(nodes0 != NULL && nodes0[0] != 0, "D0: the node table, non-empty");
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
    {
        char *nodes1 = nodes_dump(db);
        CHECK(nodes1 != NULL && strcmp(nodes1, nodes0) != 0,
              "D1: the flush wrote new nodes (control: the rollback has "
              "something to undo)");
        free(nodes1);
    }
    CHECK(run_sql(db, "ROLLBACK") == 0, "D2: whole block rolled back");
    {
        /* compared BEFORE any oracle call: roots_equal_oracle rebuilds
         * the tries and writes nodes */
        char *nodes2 = nodes_dump(db);
        CHECK(nodes2 != NULL && strcmp(nodes2, nodes0) == 0,
              "D2: the complete node table is as before the block");
        free(nodes2);
    }
    free(nodes0);
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

    /* G0 (Sol verifier row 1, flush side): a claim with a REAL domain
     * written under capture is not selected by the flush either */
    CHECK(run_sql(db, "BEGIN") == 0 &&
          run_sql(db,
            "INSERT INTO v2_claims_spent (nullifier, manifest_hash, "
            "target_domain_id, target_asset_ref, leaf_index, amount, "
            "claimed_height, output_id) VALUES (CAST(zeroblob(63)||x'42' "
            "AS BLOB), CAST(zeroblob(63)||x'ee' AS BLOB), 1.5, "
            "zeroblob(64), 2, 5, 9, zeroblob(64))") == 0 &&
          dirty_of(db, 3) == 1, "G0: a REAL-domain claim is captured");
    CHECK(nodus_witness_v2_trie_flush(fx->w) == 0 &&
          run_sql(db, "COMMIT") == 0, "G0: flush");
    CHECK(roots_equal_oracle(fx, "G0") == 0,
          "G0: the flushed leg 3 root excludes the REAL-domain claim");
    return 0;
}

/* ── C3 (Sol verifier row 2): all 24 trigger operations with capture 1 ─ */
typedef struct {
    int   leg;
    int (*ins)(fx_t *);       /* insert the row (key K)                    */
    const char *upd;          /* UPDATE of a non-key column of that row    */
    const char *del;          /* DELETE of that row                        */
    const char *key;          /* SQL expression of K as stored in the dirty
                               * table (blob literal or integer)           */
} trig_case_t;

static int ti_utxo(fx_t *f)  { return utxo_sql(f->w->db, 0xD0, 5); }
static int ti_token(fx_t *f) { return token_sql(f->w->db, 0xD0, 8); }
static int ti_claim(fx_t *f) { return claim_sql(f->w->db, 0xD0, 1, 5); }
static int ti_name(fx_t *f)  { return name_sql(f->w->db, "dave", 0xD0); }
static int ti_node(fx_t *f)  { return node_sql(f->w, 0xD0, 70, 1); }
static int ti_seg(fx_t *f)   { return seg_sql(f->w->db, 5); }
static int ti_vset(fx_t *f)  { return vset_sql(f->w->db, 9000); }
static int ti_att(fx_t *f)   { return att_sql(f->w->db, 9000); }

static int test_all_triggers(fx_t *fx) {
    sqlite3 *db = fx->w->db;
    /* the registry key is SHA3-512(node_pk): spelled as a blob literal */
    char fp_key[160];
    {
        uint8_t pk[DNAC_PUBKEY_SIZE], fp[64];
        memset(pk, 0xD0, sizeof(pk));
        CHECK(qgp_sha3_512(pk, sizeof(pk), fp) == 0, "C3: node_fp");
        size_t o = (size_t)snprintf(fp_key, sizeof(fp_key), "x'");
        for (int i = 0; i < 64; i++)
            o += (size_t)snprintf(fp_key + o, sizeof(fp_key) - o, "%02x",
                                  fp[i]);
        snprintf(fp_key + o, sizeof(fp_key) - o, "'");
    }
    const trig_case_t cases[8] = {
        { 1, ti_utxo,
          "UPDATE utxo_set SET owner = 'zz' WHERE nullifier = " NB("d0"),
          "DELETE FROM utxo_set WHERE nullifier = " NB("d0"), NB("d0") },
        { 2, ti_token,
          "UPDATE tokens SET supply = 9 WHERE token_id = " NB("d0"),
          "DELETE FROM tokens WHERE token_id = " NB("d0"), NB("d0") },
        { 3, ti_claim,
          "UPDATE v2_claims_spent SET amount = 6 WHERE nullifier = "
          NB("d0"),
          "DELETE FROM v2_claims_spent WHERE nullifier = " NB("d0"),
          NB("d0") },
        { 4, ti_name,
          "UPDATE v2_names SET registered_height = 12 WHERE name = "
          "CAST('dave' AS BLOB)",
          "DELETE FROM v2_names WHERE name = CAST('dave' AS BLOB)",
          "CAST('dave' AS BLOB)" },
        { 5, ti_node, NULL, NULL, NULL },      /* statements built below */
        { 6, ti_seg,
          "UPDATE v2_storage_segments SET published_height = 300 WHERE k = 5",
          "DELETE FROM v2_storage_segments WHERE k = 5", "5" },
        { 7, ti_vset,
          "UPDATE validator_set_snapshots SET snapshot_hash = CAST("
          "zeroblob(63)||x'aa' AS BLOB) WHERE epoch_start = 9000",
          "DELETE FROM validator_set_snapshots WHERE epoch_start = 9000",
          "9000" },
        { 8, ti_att,
          "UPDATE v2_attendance_epoch SET digest = CAST(zeroblob(63)||"
          "x'bb' AS BLOB) WHERE epoch_start = 9000",
          "DELETE FROM v2_attendance_epoch WHERE epoch_start = 9000",
          "9000" },
    };
    char node_upd[200], node_del[200];
    snprintf(node_upd, sizeof(node_upd), "UPDATE v2_storage_nodes SET bond "
             "= 71 WHERE node_fp = %s", fp_key);
    snprintf(node_del, sizeof(node_del), "DELETE FROM v2_storage_nodes "
             "WHERE node_fp = %s", fp_key);

    CHECK(nodus_witness_db_s20_trie_capture(fx->w, &(int){-1}) == 0 &&
          q1(db, "SELECT capture FROM v2_trie_state WHERE id = 1") == 1,
          "C3: capture is 1");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "C3: nothing pending");

    for (int c = 0; c < 8; c++) {
        const int leg = cases[c].leg;
        const char *key = leg == 5 ? fp_key : cases[c].key;
        for (int op = 0; op < 3; op++) {
            /* one operation per transaction: the dirty set is exactly
             * the operation's key, then the flushed root equals the rows */
            CHECK(run_sql(db, "BEGIN") == 0, "C3: begin");
            if (op == 0) {
                CHECK(cases[c].ins(fx) == 0, "C3: insert");
            } else if (op == 1) {
                CHECK(run_sql(db, leg == 5 ? node_upd : cases[c].upd) == 0,
                      "C3: update");
            } else {
                CHECK(run_sql(db, leg == 5 ? node_del : cases[c].del) == 0,
                      "C3: delete");
            }
            char sql[400];
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_trie_dirty "
                     "WHERE leg = %d AND key = %s", leg, key);
            CHECK(q1(db, sql) == 1,
                  "C3: the operation's key is in the dirty table");
            CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty") == 1,
                  "C3: and it is the only dirty key");
            CHECK(nodus_witness_v2_trie_flush(fx->w) == 0, "C3: flush");
            CHECK(run_sql(db, "COMMIT") == 0, "C3: commit");
            CHECK(roots_equal_oracle(fx, "C3") == 0,
                  "C3: every leg root equals the rows after the operation");
        }
    }
    /* after insert, update and delete of the same key the table is as it
     * was: a wrong trigger body would leave a stale leaf or a stale key */
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "C3: nothing pending at the end");
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

/* ── J: GENERATION 6 on the live block path (HF-9 WP3, plan §5.2, §5.3) ──
 * A real chain climbing generations 2 -> 6 through the engine's own edges
 * (params 9 / 14 / 18 / 22 / 24 at 3 / 5 / 8 / 11 / 14, direct rows, the
 * shape of test_hf9_edge.c), then blocks under generation 6. */

#define J_A   14u        /* param 24: generation 6 from block 14; edge 13   */

static int j_cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                    uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
} jfx_t;

static void jfx_close(jfx_t *f) {
    if (!f->w) return;
    f->w->v2_runtime_table = NULL;
    f->w->v2_runtime_table_n = 0;
    if (f->w->db) sqlite3_close(f->w->db);
    free(f->w);
    f->w = NULL;
    rmrf(f->dir);
}

static int j_apply_ok(jfx_t *f, uint64_t h) {
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch = nodus_v2_epoch_for_height(h);
    return v2x_cmt_apply_ok(f->w, &b);
}

/* faults the block at `h` as a node FAULT with `why` in the reason and the
 * whole database byte-identical; the block is NOT committed */
static int j_fault(jfx_t *f, uint64_t h, const char *why) {
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch = nodus_v2_epoch_for_height(h);
    return v2x_cmt_fault_why(f->w, &b, V2X_FAULT, why);
}

/* a chain at generation 6: ladder to the edge block 13, block A = 14, one
 * more block 15 (so the next block to apply is 16). */
static int j_open(jfx_t *f) {
    memset(f, 0, sizeof(*f));
    f->w = calloc(1, sizeof(*f->w));            /* multi-MB — heap */
    if (!f->w) return -1;
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_hf9_trie_g6_XXXXXX");
    if (!mkdtemp(f->dir)) { free(f->w); f->w = NULL; return -1; }
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t id16[16];
    memset(id16, 0x6A, sizeof(id16));
    if (v2x_seed_prepare(f->w, id16, 0) != 0) return -1;
    if (j_cc_row(f->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN2,
                 (uint64_t)DNAC_CFG_RULESET_GEN2_D2, 3, 12) != 0 ||
        j_cc_row(f->w, DNAC_CFG_EVM_ACTIVE,
                 (uint64_t)DNAC_CFG_EVM_ACTIVE_D, 5, 14) != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN_ROLES,
                 (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, 8, 13) != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN_ROOTS,
                 (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 11, 15) != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN_TRIE,
                 (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, J_A, 16) != 0)
        return -1;
    if (v2x_seed_genesis(f->w, id16, 0, NULL, 0, NULL) != 0) return -1;
    for (uint64_t h = 1; h <= J_A - 2u; h++)
        if (j_apply_ok(f, h) != 0) return -1;
    /* rows between blocks with capture 0 (silent triggers): two tokens, two
     * names, two segments, one RELEASED registry node (its bond is not in
     * the running bond total) — so the edge's build has nodes to store */
    if (token_sql(f->w->db, 0xA1, 8) != 0 || token_sql(f->w->db, 0xA2, 8)
            != 0 ||
        name_sql(f->w->db, "alice", 0xB1) != 0 ||
        name_sql(f->w->db, "bobby", 0xB2) != 0 ||
        seg_sql(f->w->db, 1) != 0 || seg_sql(f->w->db, 2) != 0 ||
        node_sql(f->w, 0x5E, 1000, 3) != 0)
        return -1;
    for (uint64_t h = J_A - 1u; h <= J_A + 1u; h++)
        if (j_apply_ok(f, h) != 0) return -1;
    return 0;
}

/* every leg's stored root equals the oracle recomputation (this file's
 * own, from SELECTs) and the build-from-rows root */
static int j_roots_ok(jfx_t *f, const char *what) {
    fx_t fx;
    memset(&fx, 0, sizeof(fx));
    fx.w = f->w;
    return roots_equal_oracle(&fx, what);
}

static int test_gen6(void) {
    jfx_t f;
    nodus_v2_block_t unused;
    (void)unused;
    CHECK(DNAC_EPOCH_LENGTH > J_A + 8, "J0: no epoch boundary among the "
          "probed heights");
    CHECK(j_open(&f) == 0, "J0: a chain at generation 6 (edge at block 13, "
          "blocks 14 and 15 committed)");
    uint32_t gen = 0;
    CHECK(nodus_witness_v2_key_generation(f.w, &gen) == 0 &&
          gen == NODUS_RT_GEN_TRIE, "J0: the registry resolves generation 6");
    CHECK(q1(f.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "J0: capture is 1 under generation 6");
    CHECK(nodus_witness_db_s20_trie_shape_ok(f.w) == 1,
          "J0: the 24 triggers are in place");
    CHECK(j_roots_ok(&f, "J0 after the edge") == 0,
          "J0: every stored leg root equals the oracle and the rows");
    uint64_t next = J_A + 2u;                  /* 16 */

    /* ── J1: capture consistency at the block start, generation >= 6 ── */
    CHECK(run_sql(f.w->db, "UPDATE v2_trie_state SET capture = 0") == 0,
          "J1: capture 0 under generation 6");
    CHECK(j_fault(&f, next, "needs it 1") == 0,
          "J1: generation >= 6 with capture 0 faults before any item runs, "
          "the database byte-identical");
    CHECK(run_sql(f.w->db, "UPDATE v2_trie_state SET capture = 1") == 0,
          "J1: restored");
    CHECK(run_sql(f.w->db, "DELETE FROM v2_trie_state") == 0,
          "J1: no state row");
    CHECK(j_fault(&f, next, "missing or unreadable") == 0,
          "J1: a missing state row faults under generation 6");
    CHECK(run_sql(f.w->db, "INSERT INTO v2_trie_state (id, capture) VALUES "
                           "(1, 1)") == 0, "J1: restored");
    /* one dropped trigger (its stored SQL kept, then re-created) */
    {
        sqlite3_stmt *st = NULL;
        char *sql = NULL;
        CHECK(sqlite3_prepare_v2(f.w->db,
                  "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND "
                  "name = 'v2_trie_l5_upd'", -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW, "J1: the trigger's SQL");
        sql = strdup((const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
        CHECK(sql != NULL && run_sql(f.w->db,
                  "DROP TRIGGER v2_trie_l5_upd") == 0, "J1: dropped");
        int rc = j_fault(&f, next, "24 dirty-capture triggers");
        int rs = run_sql(f.w->db, sql);
        free(sql);
        CHECK(rc == 0, "J1: a dropped trigger faults under generation 6");
        CHECK(rs == 0 && nodus_witness_db_s20_trie_shape_ok(f.w) == 1,
              "J1: restored from its stored SQL");
    }
    CHECK(j_apply_ok(&f, next) == 0,
          "J1: with everything restored the block commits");
    next++;

    /* ── J2: the dirty-empty assertion faults a late writer ── */
    CHECK(run_sql(f.w->db,
              "CREATE TRIGGER hf9_late_writer AFTER INSERT ON v2_blocks "
              "BEGIN INSERT INTO tokens (token_id, name, symbol, decimals, "
              "supply, creator_fp, flags, block_height, timestamp) VALUES "
              "(CAST(zeroblob(63)||x'f7' AS BLOB), 'late', 'LT', 8, 1, "
              "'fpL', 1, 1, 1); END") == 0,
          "J2: a writer that fires in phase 13 (after the roots)");
    CHECK(j_fault(&f, next, "phase 13-bis") == 0,
          "J2: the dirty-empty assertion faults the block that wrote a "
          "migrated table after phase 8, the database byte-identical "
          "(the dirty row and the token row are rolled back with it)");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
          q1(f.w->db, "SELECT COUNT(*) FROM tokens WHERE name = 'late'")
              == 0, "J2: nothing of the rolled-back block survives");
    CHECK(run_sql(f.w->db, "DROP TRIGGER hf9_late_writer") == 0,
          "J2: the writer is removed");
    CHECK(j_apply_ok(&f, next) == 0, "J2: the same block now commits");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "J2: the dirty table is empty after the block");
    CHECK(j_roots_ok(&f, "J2 after the block") == 0,
          "J2: roots equal the rows");
    next++;

    /* ── J3: one corrupted stored node -> FAULT at the next touch ── */
    {
        uint8_t root2[64];
        CHECK(nodus_witness_v2_trie_leg_root(f.w, 2, root2) == 0,
              "J3: leg 2's committed root");
        CHECK(run_sql(f.w->db, "INSERT INTO tokens (token_id, name, "
                               "symbol, decimals, supply, creator_fp, "
                               "flags, block_height, timestamp) VALUES "
                               "(CAST(zeroblob(63)||x'f8' AS BLOB), "
                               "'tokx', 'TX', 8, 5, 'fpX', 1, 1, 1)") == 0,
              "J3: a token row (capture on: one dirty key of leg 2)");
        /* corrupt the stored body of leg 2's root node (the digest
         * unchanged; the original body kept to restore it): the flush
         * must load it */
        sqlite3_stmt *st = NULL;
        uint8_t body[2048], bad[2048];
        size_t blen = 0;
        CHECK(sqlite3_prepare_v2(f.w->db,
                  "SELECT rlp FROM v2_trie_nodes WHERE digest = ?1", -1,
                  &st, NULL) == SQLITE_OK &&
              sqlite3_bind_blob(st, 1, root2, 64, SQLITE_STATIC)
                  == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_BLOB &&
              sqlite3_column_bytes(st, 0) > 0 &&
              (size_t)sqlite3_column_bytes(st, 0) <= sizeof(body),
              "J3: leg 2's root node is stored (two token rows)");
        blen = (size_t)sqlite3_column_bytes(st, 0);
        memcpy(body, sqlite3_column_blob(st, 0), blen);
        sqlite3_finalize(st);
        memcpy(bad, body, blen);
        bad[blen - 1] ^= 0x01;
        CHECK(sqlite3_prepare_v2(f.w->db,
                  "UPDATE v2_trie_nodes SET rlp = ?2 WHERE digest = ?1",
                  -1, &st, NULL) == SQLITE_OK &&
              sqlite3_bind_blob(st, 1, root2, 64, SQLITE_STATIC)
                  == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, bad, (int)blen, SQLITE_STATIC)
                  == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE &&
              sqlite3_changes(f.w->db) == 1, "J3: a node body altered");
        sqlite3_finalize(st);
        CHECK(j_fault(&f, next, "phase 8-pre") == 0,
              "J3: the flush that touches the corrupted node is a node "
              "FAULT (the node does not vote), the database byte-"
              "identical");
        /* restore: the original body back, the token row deleted again */
        CHECK(sqlite3_prepare_v2(f.w->db,
                  "UPDATE v2_trie_nodes SET rlp = ?2 WHERE digest = ?1",
                  -1, &st, NULL) == SQLITE_OK &&
              sqlite3_bind_blob(st, 1, root2, 64, SQLITE_STATIC)
                  == SQLITE_OK &&
              sqlite3_bind_blob(st, 2, body, (int)blen, SQLITE_STATIC)
                  == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE,
              "J3: the node body restored");
        sqlite3_finalize(st);
        CHECK(run_sql(f.w->db, "DELETE FROM tokens WHERE name = 'tokx'")
              == 0, "J3: the token row deleted again");
        CHECK(j_apply_ok(&f, next) == 0,
              "J3: with the node restored and the key written and "
              "restored, the block commits");
        CHECK(j_roots_ok(&f, "J3 after the block") == 0,
              "J3: roots equal the rows");
        next++;
    }

    /* ── J4: the head_activate guard's getter, on the live chain ── */
    {
        uint8_t r[64];
        CHECK(run_sql(f.w->db, "INSERT INTO v2_names (name, owner, "
                               "registered_height) VALUES (CAST('guard' AS "
                               "BLOB), CAST(zeroblob(63)||x'd9' AS BLOB), "
                               "5)") == 0, "J4: a name row (dirty key)");
        CHECK(nodus_witness_v2_trie_leg_root(f.w, 4, r) != 0,
              "J4: a trie-leg getter called with a dirty key of its leg "
              "pending refuses (never a stale root)");
        CHECK(nodus_witness_v2_trie_leg_root(f.w, 1, r) == 0,
              "J4: a leg without a pending key is readable");
        CHECK(run_sql(f.w->db, "DELETE FROM v2_names WHERE name = "
                               "CAST('guard' AS BLOB)") == 0,
              "J4: the row deleted again");
        CHECK(j_apply_ok(&f, next) == 0,
              "J4: the flush clears the written-and-restored key");
        next++;
    }

    /* ── J5: a state value outside {0, 1} under generation 6 (last: the
     *        recreated table no longer has the CHECK) ── */
    CHECK(run_sql(f.w->db, "DROP TABLE v2_trie_state; CREATE TABLE "
                           "v2_trie_state(id INTEGER PRIMARY KEY, capture); "
                           "INSERT INTO v2_trie_state VALUES (1, 2)") == 0,
          "J5: capture 2");
    CHECK(j_fault(&f, next, "needs it 1") == 0,
          "J5: a value outside {0, 1} faults under generation 6");
    jfx_close(&f);
    return 0;
}

/* ── K: THE ENGINE'S OWN WRITERS UNDER GENERATION 6 (HF-9 WP3, Sol
 * verifier row 6; plan §4.3, §5.3, §12 T-5 "every writer path through the
 * real functions; after each block incremental leg root = full rebuild of
 * rows") ──
 * Blocks carrying REAL signed transactions and claims, and an epoch
 * boundary, on a chain that climbed to generation 6 through the engine's
 * own edge (the J ladder). After every block: v2_trie_dirty is empty, the
 * legs the writer touches moved and no other leg did, and every stored leg
 * root equals the oracle recomputation and the build-from-rows root. */

#define K_FEE     ((uint64_t)DNAC_MIN_FEE_RAW)
#define K_P4      ((uint64_t)DNAC_NAME_PRICE_4P_DEFAULT)
#define K_CHG     700000000ULL
#define K_TOK_CHG 3000000ULL
#define K_SPEND   5000000ULL          /* the two plain-spend coins          */
#define K_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

enum { K_COIN_N, K_COIN_T, K_COIN_S1, K_COIN_S2, K_N_COINS };

static uint8_t k_pk[QGP_DSA87_PUBLICKEYBYTES];
static uint8_t k_sk[QGP_DSA87_SECRETKEYBYTES];
static char    k_hex[129];            /* the sender's 128-hex fingerprint   */
static char    k_hex_to[129];         /* a second owner, the spend's payee  */
static uint8_t k_nul[K_N_COINS][64];
static uint64_t k_amt[K_N_COINS];

static void k_hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int k_keys(void) {
    uint8_t seed[32], fp[64];
    memset(seed, 0x71, sizeof(seed));
    if (qgp_dsa87_keypair_derand(k_pk, k_sk, seed) != 0) return -1;
    if (qgp_sha3_512(k_pk, sizeof(k_pk), fp) != 0) return -1;
    k_hex_of(fp, k_hex);
    static const uint8_t to_src[8] = { 'p', 'a', 'y', 'e', 'e', 0, 0, 1 };
    if (qgp_sha3_512(to_src, sizeof(to_src), fp) != 0) return -1;
    k_hex_of(fp, k_hex_to);
    return 0;
}

/* one spendable native coin of the sender; nullifier = SHA3-512(owner128
 * || seed32), the output-identity derivation (test_hf4_names_engine.c
 * seed_coin's shape) */
static int k_seed_coin(nodus_witness_t *w, int c, uint64_t amount,
                       uint8_t seed_byte) {
    uint8_t pre[160];
    memcpy(pre, k_hex, 128);
    memset(pre + 128, seed_byte, 32);
    if (qgp_sha3_512(pre, sizeof(pre), k_nul[c]) != 0) return -1;
    k_amt[c] = amount;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, k_nul[c], 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, k_hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* the distribution leaves of the claim chain (test_v2_claims.c keys_init's
 * shape): three DNA-native claimants, conversion 3/2 FLOOR, sum 32 */
#define K_N_LEAVES 3
static uint8_t         k_lpk[K_N_LEAVES][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t         k_lsk[K_N_LEAVES][QGP_DSA87_SECRETKEYBYTES];
static dna_dist_leaf_t k_leaf[K_N_LEAVES];
static uint8_t         k_leaf_hash[K_N_LEAVES][64];
static uint8_t         k_snapshot_root[64];
static const uint8_t   k_native_asset[64] = {0};
static const uint64_t  k_src_amount[K_N_LEAVES] = { 10, 5, 7 };
static const char     *k_src_id[K_N_LEAVES] =
    { "src-alpha", "src-beta", "src-gamma" };

static int k_leaves(void) {
    for (int i = 0; i < K_N_LEAVES; i++) {
        uint8_t seed[32];
        memset(seed, 0x40 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(k_lpk[i], k_lsk[i], seed) != 0)
            return -1;
        memset(&k_leaf[i], 0, sizeof(k_leaf[i]));
        k_leaf[i].leaf_version = DNA_DIST_VERSION;
        k_leaf[i].source_id_len = (uint16_t)strlen(k_src_id[i]);
        memcpy(k_leaf[i].source_id, k_src_id[i], k_leaf[i].source_id_len);
        k_leaf[i].source_amount = k_src_amount[i];
        if (qgp_sha3_512(k_lpk[i], QGP_DSA87_PUBLICKEYBYTES,
                         k_leaf[i].dest_binding) != 0)
            return -1;
        if (dna_dist_leaf_hash(&k_leaf[i], k_leaf_hash[i]) != 0) return -1;
    }
    if (dna_dist_snapshot_root(k_leaf, K_N_LEAVES, k_snapshot_root) != 0)
        return -1;
    return dna_dist_check_totals(k_leaf, K_N_LEAVES, 3, 2,
                                 DNA_DISTROUND_FLOOR, 32);
}

static int k_claim(dna_claim_t *c, int leaf, const uint8_t chain[32],
                   const uint8_t manifest_hash[64]) {
    memset(c, 0, sizeof(*c));
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, chain, 32);
    memcpy(c->manifest_hash, manifest_hash, 64);
    c->leaf_index = (uint64_t)leaf;
    c->source_id_len = k_leaf[leaf].source_id_len;
    memcpy(c->source_id, k_leaf[leaf].source_id, c->source_id_len);
    c->source_amount = k_leaf[leaf].source_amount;
    memcpy(c->dest_binding, k_leaf[leaf].dest_binding, 64);
    uint16_t ns = 0;
    if (dna_dist_proof_build((const uint8_t (*)[64])k_leaf_hash,
                             K_N_LEAVES, (uint64_t)leaf, c->siblings, &ns)
        != 0)
        return -1;
    c->n_siblings = ns;
    c->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, k_lpk[leaf], QGP_DSA87_PUBLICKEYBYTES);
    uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t pre_len = 0;
    if (dna_claim_preimage(c, pre, &pre_len) != 0) return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(c->signature, &siglen, pre, pre_len, k_lsk[leaf])
            != 0 || siglen != DNA_CLAIM_SIG_LEN)
        return -1;
    return 0;
}

/* The chain: the J ladder (params 9 / 14 / 18 / 22 / 24 at 3 / 5 / 8 / 11 /
 * 14, direct rows) over (dist == 0) a genesis with four spendable coins of
 * the sender, or (dist == 1) a genesis whose manifest commits a three-leaf
 * claim distribution to the CORE runtime (window [2, 40]); blocks 1..15
 * committed, so the edge ran at block 13 and block 14 / 15 were judged under
 * generation 6. The next block to apply is 16. */
static int k_open(jfx_t *f, int dist, uint8_t chain32[32],
                  uint8_t mh[64]) {
    memset(f, 0, sizeof(*f));
    f->w = calloc(1, sizeof(*f->w));            /* multi-MB - heap */
    if (!f->w) return -1;
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_hf9_trie_k_XXXXXX");
    if (!mkdtemp(f->dir)) { free(f->w); f->w = NULL; return -1; }
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t id16[16];
    memset(id16, 0x6B, sizeof(id16));
    if (v2x_seed_prepare(f->w, id16, 0) != 0) return -1;
    if (j_cc_row(f->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN2,
                 (uint64_t)DNAC_CFG_RULESET_GEN2_D2, 3, 12) != 0 ||
        j_cc_row(f->w, DNAC_CFG_EVM_ACTIVE,
                 (uint64_t)DNAC_CFG_EVM_ACTIVE_D, 5, 14) != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN_ROLES,
                 (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, 8, 13) != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN_ROOTS,
                 (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 11, 15) != 0 ||
        j_cc_row(f->w, DNAC_CFG_RULESET_GEN_TRIE,
                 (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, J_A, 16) != 0)
        return -1;
    if (dist == 2) {
        /* the graduation chain (test_v2_epoch.c's late-joiner shape): the
         * document's seven seats and the snapshots 0 / E first, THEN one
         * more bonded validator in status RETIRING - not an entry of any
         * frozen snapshot, so the first boundary graduates it at once -
         * and one delegation to it; the supply gains exactly the bond and
         * the delegated amount; the genesis names the departure
         * (V2X_SEED_NOT_REAL_STATUSES recomputes active_count). */
        if (v2x_seed_rows(f->w, 0) != 0) return -1;
        uint8_t gpk[QGP_DSA87_PUBLICKEYBYTES];
        uint8_t gsk[QGP_DSA87_SECRETKEYBYTES];
        uint8_t gseed[32];
        memset(gseed, 0x7A, sizeof(gseed));
        if (qgp_dsa87_keypair_derand(gpk, gsk, gseed) != 0) return -1;
        const uint64_t bond = (uint64_t)DNAC_SELF_STAKE_AMOUNT;
        const uint64_t dam = 2u * (uint64_t)DNAC_MIN_DELEGATION;
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, gpk, DNAC_PUBKEY_SIZE);
        memcpy(v.unstake_destination_pubkey, k_pk, DNAC_PUBKEY_SIZE);
        memcpy(v.unstake_destination_fp, k_hex, 128);
        v.self_stake          = bond;
        v.commission_bps      = 100;
        v.status              = DNAC_VALIDATOR_RETIRING;
        v.active_since_block  = 1;
        v.unstake_commit_block = 3;
        if (nodus_validator_insert(f->w, &v) != 0) return -1;
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, k_pk, DNAC_PUBKEY_SIZE);
        memcpy(d.validator_pubkey, gpk, DNAC_PUBKEY_SIZE);
        d.amount = dam;
        if (nodus_delegation_insert(f->w, &d) != 0) return -1;
        if (nodus_validator_get(f->w, gpk, &v) != 0) return -1;
        v.total_delegated    += dam;
        v.external_delegated += dam;
        if (nodus_validator_update(f->w, &v) != 0) return -1;
        char sql[224];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = current_supply "
                 "+ %llu WHERE id = 1",
                 (unsigned long long)(bond + dam),
                 (unsigned long long)(bond + dam));
        if (run_sql(f->w->db, sql) != 0) return -1;
        v2x_seed_not_real(V2X_SEED_NOT_REAL_STATUSES);
        if (v2x_seed_genesis(f->w, id16, 0, NULL, 0, chain32) != 0)
            return -1;
    } else if (!dist) {
        uint64_t tokfee = 0;
        if (nodus_chain_config_get_u64(f->w,
                (uint8_t)DNAC_CFG_TOKEN_CREATE_FEE_RAW, 1, 0, &tokfee) != 0
            || tokfee == 0)
            return -1;
        if (k_seed_coin(f->w, K_COIN_N, K_P4 + K_FEE + K_CHG, 0xC1) != 0 ||
            k_seed_coin(f->w, K_COIN_T, tokfee + K_TOK_CHG, 0xC2) != 0 ||
            k_seed_coin(f->w, K_COIN_S1, K_SPEND, 0xC3) != 0 ||
            k_seed_coin(f->w, K_COIN_S2, K_SPEND, 0xC4) != 0)
            return -1;
        v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
        if (v2x_seed_genesis(f->w, id16, 0, NULL, 0, chain32) != 0)
            return -1;
    } else {
        /* test_v2_claims.c dist_genesis: the supply row and the one
         * non-claimable genesis UTXO, the registry committed first, the
         * manifest naming the real DomainManifest hashes */
        const uint64_t total = 32;
        char sql[640];
        snprintf(sql, sizeof(sql),
            "INSERT INTO supply_tracking (id, genesis_supply, "
            "total_burned, total_minted, current_supply, last_tx_hash, "
            "last_sequence) VALUES (1, 1000, 0, 0, 1000, x'00', 0)");
        if (run_sql(f->w->db, sql) != 0) return -1;
        snprintf(sql, sizeof(sql),
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES (zeroblob(63)||x'01', "
            "'genesis', %llu, zeroblob(64), zeroblob(63)||x'aa', 0, 0, 0, "
            "0, 1)", (unsigned long long)(1000 - total));
        if (run_sql(f->w->db, sql) != 0) return -1;
        if (v2x_seed_rows(f->w, 0) != 0) return -1;
        if (nodus_witness_domreg_init_genesis(f->w) != 0) return -1;
        dna_domain_manifest_t sm, cm;
        uint8_t sys_h[64], core_h[64];
        if (nodus_witness_domreg_get(f->w, DNA_DOMAIN_SYSTEM, NULL, &sm,
                                     NULL) != 0 ||
            dna_domman_hash(&sm, sys_h) != 0 ||
            nodus_witness_domreg_get(f->w, DNA_DOMAIN_CORE, NULL, &cm,
                                     NULL) != 0 ||
            dna_domman_hash(&cm, core_h) != 0)
            return -1;
        nodus_witness_supply_t sup;
        memset(&sup, 0, sizeof(sup));
        if (nodus_witness_supply_get(f->w, &sup) != 0) return -1;
        dna_gman_t m;
        memset(&m, 0, sizeof(m));
        m.manifest_version = DNA_GMAN_VERSION;
        m.genesis_supply_raw = sup.genesis_supply;
        m.domain_count = 2;
        m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
        memcpy(m.domains[0].manifest_hash, sys_h, 64);
        m.domains[1].domain_id = DNA_DOMAIN_CORE;
        memcpy(m.domains[1].manifest_hash, core_h, 64);
        m.dist_present = 1;
        m.dist_version = DNA_DIST_VERSION;
        m.target_domain_id = DNA_DOMAIN_CORE;
        m.target_asset_len = 64;
        memcpy(m.target_asset_ref, k_native_asset, 64);
        m.source_tag_len = (uint16_t)strlen("testnet-generic");
        memcpy(m.source_tag, "testnet-generic", m.source_tag_len);
        m.source_commit_len = 16;
        memset(m.source_commit, 0x77, 16);
        memcpy(m.snapshot_root, k_snapshot_root, 64);
        m.leaf_count = K_N_LEAVES;
        m.conv_numerator = 3;
        m.conv_denominator = 2;
        m.rounding_mode = DNA_DISTROUND_FLOOR;
        m.excluded_amount = 4;
        m.total_claimable = total;
        m.claim_start_height = 2;
        m.claim_end_height = 40;
        m.auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
        m.fee_mode = DNA_CLAIMFEE_NONE;
        m.post_deadline_mode = DNA_POSTDL_RETAIN;
        uint8_t mbytes[8192];
        size_t mlen = 0;
        if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0 ||
            dna_gman_hash(&m, mh) != 0)
            return -1;
        v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
        if (v2x_seed_genesis(f->w, id16, 0, mbytes, mlen, chain32) != 0)
            return -1;
    }
    for (uint64_t h = 1; h <= J_A + 1u; h++)
        if (j_apply_ok(f, h) != 0) return -1;
    return 0;
}

/* One one-leg CORE envelope, really signed by the sender over the
 * engine-derived leg digest at height `h` (nodus_v2_env_sign_one_key: the
 * two-pass build nodus-cli uses), built against the registry's CURRENT
 * CORE manifest. n_reads >= 0: units = nodus_v2_spend_ceiling over this
 * envelope under the generation-6 SYSTEM policy; n_reads < 0: the flat
 * 200000 units test_v2_native.c env_build_signed declares. 0 / -1. */
static int k_env(nodus_witness_t *w, uint64_t h, uint32_t op,
                 const uint8_t *call, uint32_t call_len, uint64_t fee,
                 uint32_t effects, uint32_t effect_bytes, int n_reads,
                 uint8_t **out, size_t *out_len) {
    dna_domain_manifest_t core;
    const nodus_domain_runtime_t *sys =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_SYSTEM);
    uint8_t auth[K_AUTH_LEN];
    memset(auth, 0, sizeof(auth));
    *out = NULL;
    if (!sys || !sys->meter_policy) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_CORE;
    leg.hdr.runtime_op           = op;
    leg.hdr.ruleset_version      = core.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len             = call_len;
    leg.hdr.auth_len             = K_AUTH_LEN;
    leg.hdr.res_max_effects      = effects;
    leg.hdr.res_max_effect_bytes = effect_bytes;
    leg.call_data = call;
    leg.auth_data = auth;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = fee;
    /* inside the D2 window [h, h + 720] of the block that carries it (0
     * is refused, phase 0d); h + 5 as test_hf7_edge.c case A3 sets
     * (:667 "expiry A + 5") */
    in.expiry_height = h + 5u;
    in.leg_count  = 1;
    in.legs       = &leg;
    if (n_reads >= 0) {
        uint64_t units = 0;
        if (nodus_v2_spend_ceiling(&in, sys->meter_policy,
                                   (uint32_t)n_reads, &units) != 0)
            return -1;
        in.res_max_total_units = units;
    } else {
        in.res_max_total_units = 200000;
    }
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = core.ruleset_version;
    memcpy(lctx.ruleset_hash, core.ruleset_hash, 64);
    uint8_t *auths[1] = { auth };
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    nodus_v2_spend_err_t err;
    memset(&err, 0, sizeof(err));
    int rc = nodus_v2_env_sign_one_key(&in, auths, &lctx, w->v2_chain32,
                                       h - 1u, k_pk, k_sk, out, out_len, pf,
                                       &err);
    free(pf);
    return rc == NODUS_V2_SPEND_OK ? 0 : -1;
}

/* NAME_REGISTER of `name` by the sender spending coin `c`, change back to
 * the sender (the call layout and the effect declaration are
 * test_hf4_names_engine.c reg_env's) */
static int k_name_env(nodus_witness_t *w, uint64_t h, const char *name,
                      int c, uint8_t **out, size_t *out_len) {
    static uint8_t call[1 + 36 + 8 + 1 + 64 + 1 + NODUS_V2_SPEND_OUT_LEN];
    const size_t nl = strlen(name);
    const uint64_t change = k_amt[c] - K_FEE - K_P4;
    const uint32_t n_out = change > 0 ? 1u : 0u;
    size_t off = 0;
    call[off++] = (uint8_t)nl;
    memcpy(call + off, name, nl);               off += nl;
    for (int i = 0; i < 8; i++)
        call[off + i] = (uint8_t)(K_P4 >> (56 - 8 * i));
    off += 8;
    call[off++] = 1;
    memcpy(call + off, k_nul[c], 64);           off += 64;
    call[off++] = (uint8_t)n_out;
    if (n_out) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + c), sizeof(seed));
        nodus_v2_xfer_out_put(call + off, k_hex, change, NULL, seed);
        off += NODUS_V2_SPEND_OUT_LEN;
    }
    const uint32_t effects = 1u + n_out + 2u;
    const uint32_t bytes = (uint32_t)DNA_EFFECT_FIXED_HEAD +
        (uint32_t)DNA_EFFECT_RECORD_LEN * effects +
        n_out * (64u + 284u) + ((uint32_t)nl + 72u) + (1u + 8u) + 64u;
    return k_env(w, h, DNA_CORERULE_NAME_REGISTER, call, (uint32_t)off,
                 K_FEE, effects, bytes, 1 + 3, out, out_len);
}

/* TOKEN_CREATE of `tok` paying the governed fee `fee` from coin `c`; the
 * token output (777 units) and the native change go to the sender
 * (test_v2_native.c tc_call_build's layout) */
static int k_token_env(nodus_witness_t *w, uint64_t h, const uint8_t tok[64],
                       int c, uint64_t fee, uint8_t **out, size_t *out_len) {
    static uint8_t call[64 + 1 + 8 + 1 + 4 + 1 + 2 + 64 +
                        2 * NODUS_V2_SPEND_OUT_LEN];
    size_t off = 0;
    memcpy(call, tok, 64);                      off = 64;
    call[off++] = 8;
    memcpy(call + off, "KTokenOne", 8);         off += 8;
    call[off++] = 2;
    memcpy(call + off, "K1", 2);                off += 2;
    call[off++] = 8;                            /* decimals               */
    call[off++] = 1;                            /* one input              */
    memcpy(call + off, k_nul[c], 64);           off += 64;
    call[off++] = 2;                            /* two outputs            */
    uint8_t seed[32];
    memset(seed, 0x61, sizeof(seed));
    nodus_v2_xfer_out_put(call + off, k_hex, 777, tok, seed);
    off += NODUS_V2_SPEND_OUT_LEN;
    memset(seed, 0x62, sizeof(seed));
    nodus_v2_xfer_out_put(call + off, k_hex, k_amt[c] - fee, NULL, seed);
    off += NODUS_V2_SPEND_OUT_LEN;
    return k_env(w, h, DNA_CORERULE_TOKEN_CREATE, call, (uint32_t)off, fee,
                 40, 16384, -1, out, out_len);
}

/* a plain SPEND of coin `c`: 3 000 000 to the payee, the rest of the coin
 * minus the fee back to the sender; `seed_base` makes the output ids */
static int k_spend_env(nodus_witness_t *w, uint64_t h, int c,
                       uint8_t seed_base, uint8_t **out, size_t *out_len) {
    static uint8_t call[2 + 64 + 2 * NODUS_V2_SPEND_OUT_LEN];
    size_t off = 0;
    call[off++] = 1;
    memcpy(call + off, k_nul[c], 64);           off += 64;
    call[off++] = 2;
    uint8_t seed[32];
    memset(seed, seed_base, sizeof(seed));
    nodus_v2_xfer_out_put(call + off, k_hex_to, 3000000, NULL, seed);
    off += NODUS_V2_SPEND_OUT_LEN;
    memset(seed, (uint8_t)(seed_base + 1u), sizeof(seed));
    nodus_v2_xfer_out_put(call + off, k_hex, k_amt[c] - 3000000 - K_FEE,
                          NULL, seed);
    off += NODUS_V2_SPEND_OUT_LEN;
    uint32_t effects = 0, bytes = 0;
    nodus_v2_spend_effect_decl(1, 2, &effects, &bytes);
    return k_env(w, h, DNA_CORERULE_SPEND, call, (uint32_t)off, K_FEE,
                 effects, bytes, 1 + 1, out, out_len);
}

static void k_mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
}

static int k_read_legs(nodus_witness_t *w, uint8_t r[8][64]) {
    for (int leg = 1; leg <= 8; leg++)
        if (nodus_witness_v2_trie_leg_root(w, leg, r[leg - 1]) != 0)
            return -1;
    return 0;
}

/* bit i of `mask` = leg i+1 moved between `a` and `b` (exactly) */
static unsigned k_moved(const uint8_t a[8][64], const uint8_t b[8][64]) {
    unsigned m = 0;
    for (int i = 0; i < 8; i++)
        if (memcmp(a[i], b[i], 64) != 0) m |= 1u << i;
    return m;
}

static int k_utxo_live(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "nullifier = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_STATIC);
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* apply one single-envelope block */
static int k_apply_env(jfx_t *f, uint64_t h, const uint8_t *env,
                       size_t len) {
    nodus_v2_envelope_t e = { env, len };
    nodus_v2_block_t b;
    k_mk_block(&b, h);
    b.envs = &e;
    b.n_envs = 1;
    return v2x_cmt_apply_ok(f->w, &b);
}

/* after a committed block: the dirty table is empty, exactly the legs in
 * `mask` moved against `before`, and every stored leg root equals the
 * oracle and the rows. `now` receives the leg roots. */
static int k_after_block(jfx_t *f, const uint8_t before[8][64],
                         uint8_t now[8][64], unsigned mask,
                         const char *what) {
    if (q1(f->w->db, "SELECT COUNT(*) FROM v2_trie_dirty") != 0) {
        fprintf(stderr, "%s: the dirty table is not empty\n", what);
        return -1;
    }
    if (k_read_legs(f->w, now) != 0) return -1;
    unsigned moved = k_moved(before, now);
    if (moved != mask) {
        fprintf(stderr, "%s: legs moved 0x%02x, expected 0x%02x\n", what,
                moved, mask);
        return -1;
    }
    return j_roots_ok(f, what);
}

static int test_gen6_writers(void) {
    jfx_t f;
    CHECK(DNAC_EPOCH_LENGTH > 40, "K: no epoch boundary among blocks "
          "1..19 (the boundary case drives to DNAC_EPOCH_LENGTH itself)");
    CHECK(k_keys() == 0, "K: sender keys");
    CHECK(k_open(&f, 0, NULL, NULL) == 0, "K: a chain at generation 6 with "
          "four spendable coins (blocks 1..15 committed)");
    CHECK(q1(f.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "K: capture is 1");
    uint8_t L0[8][64], L1[8][64], L2[8][64];
    CHECK(k_read_legs(f.w, L0) == 0, "K: leg roots before");
    uint8_t *env = NULL;
    size_t elen = 0;

    /* K1: NAME_REGISTER (rtn_core_mutate: the utxo input DELETE, the
     * change INSERT, the v2_names INSERT) -> legs 1 and 4 */
    CHECK(k_name_env(f.w, 16, "punk", K_COIN_N, &env, &elen) == 0,
          "K1: a signed NAME_REGISTER");
    CHECK(k_apply_env(&f, 16, env, elen) == 0, "K1: block 16 commits");
    free(env);
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_names WHERE name = "
                      "CAST('punk' AS BLOB)") == 1 &&
          k_utxo_live(f.w, k_nul[K_COIN_N]) == 0,
          "K1: the name row exists and the input coin is spent");
    CHECK(k_after_block(&f, L0, L1, 0x09u, "K1 name register") == 0,
          "K1: legs 1 and 4 moved, no other; every leg root equals the "
          "oracle and the rows; dirty empty");

    /* K2: TOKEN_CREATE (rtn_core_mutate: the tokens INSERT, the utxo
     * DELETE / INSERTs) -> legs 1 and 2 */
    {
        uint64_t tokfee = 0;
        uint8_t tok[64];
        memset(tok, 0x6C, sizeof(tok));
        CHECK(nodus_chain_config_get_u64(f.w,
                  (uint8_t)DNAC_CFG_TOKEN_CREATE_FEE_RAW, 17, 0, &tokfee)
                  == 0 && tokfee + K_TOK_CHG == k_amt[K_COIN_T],
              "K2: the governed creation fee is the one the coin was "
              "sized for");
        CHECK(k_token_env(f.w, 17, tok, K_COIN_T, tokfee, &env, &elen)
                  == 0, "K2: a signed TOKEN_CREATE");
        CHECK(k_apply_env(&f, 17, env, elen) == 0, "K2: block 17 commits");
        free(env);
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM tokens") == 1 &&
              k_utxo_live(f.w, k_nul[K_COIN_T]) == 0,
              "K2: the token row exists and the funding coin is spent");
        CHECK(k_after_block(&f, L1, L2, 0x03u, "K2 token create") == 0,
              "K2: legs 1 and 2 moved, no other; roots equal the oracle");
        memcpy(L1, L2, sizeof(L1));
    }

    /* K3: SPEND (rtn_core_mutate: the utxo DELETE and two INSERTs) -> leg 1 */
    CHECK(k_spend_env(f.w, 18, K_COIN_S1, 0x70, &env, &elen) == 0,
          "K3: a signed SPEND");
    CHECK(k_apply_env(&f, 18, env, elen) == 0, "K3: block 18 commits");
    free(env);
    CHECK(k_utxo_live(f.w, k_nul[K_COIN_S1]) == 0,
          "K3: the input coin is spent");
    CHECK(k_after_block(&f, L1, L2, 0x01u, "K3 spend") == 0,
          "K3: only leg 1 moved; roots equal the oracle");
    memcpy(L1, L2, sizeof(L1));

    /* K4: rollback. A second SPEND of coin S2 in a block that FAULTS after
     * the flush and the roots (V2AP_FAIL_AFTER_DOMAIN_ROOTS): the whole
     * block, its dirty keys, its trie nodes and its leg roots are rolled
     * back. */
    {
        nodus_v2_block_t b;
        const sqlite3_int64 nodes0 =
            q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_nodes");
        CHECK(k_spend_env(f.w, 19, K_COIN_S2, 0x72, &env, &elen) == 0,
              "K4: a signed SPEND of coin S2");
        nodus_v2_envelope_t e = { env, elen };
        k_mk_block(&b, 19);
        b.envs = &e;
        b.n_envs = 1;
        b.fail_at = V2AP_FAIL_AFTER_DOMAIN_ROOTS;
        CHECK(v2x_cmt_injected(f.w, &b) == 0,
              "K4: the block faulting after the flush is a FAULT naming "
              "the injection, the whole database byte-identical");
        CHECK(k_utxo_live(f.w, k_nul[K_COIN_S2]) == 1 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == nodes0,
              "K4: the coin is unspent, no dirty key, the node table as "
              "it was");
        CHECK(k_read_legs(f.w, L2) == 0 && k_moved(L1, L2) == 0,
              "K4: every leg root is as before the block");
        CHECK(j_roots_ok(&f, "K4 after the rolled-back block") == 0,
              "K4: and equals the oracle");

        /* K4b: an ITEM refused after its writes were captured? - a spend
         * of the already spent coin S1 is refused in exec (no row to
         * read): the block commits, the item's savepoint leaves no dirty
         * key and no root moves */
        nodus_v2_envelope_t e2;
        uint8_t *env2 = NULL;
        size_t elen2 = 0;
        CHECK(k_spend_env(f.w, 19, K_COIN_S1, 0x74, &env2, &elen2) == 0,
              "K4b: a signed SPEND of the spent coin S1");
        e2.env_bytes = env2;
        e2.env_len = elen2;
        k_mk_block(&b, 19);
        b.envs = &e2;
        b.n_envs = 1;
        uint32_t code = 0;
        CHECK(v2x_cmt_refused_probe(f.w, &b, 0, &code) == 0 &&
              code != NODUS_V2_TX_OK,
              "K4b: the spend of a spent coin is refused in exec, the "
              "ledger byte-identical");
        free(env2);
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              k_read_legs(f.w, L2) == 0 && k_moved(L1, L2) == 0,
              "K4b: no dirty key and no leg root moved");

        /* K4d: the engine's ITEM rollback after captured writes (Sol
         * verifier, second round, row 2). The S2 spend is stopped inside
         * its own item savepoint after its effect at index 1 was applied
         * (V2AP_FAIL_AFTER_EFFECT_APPLY: the input DELETE and an output
         * INSERT have run and the triggers have captured their keys): the
         * item is refused, the block still applies. Read INSIDE the
         * block's transaction, after the engine (phase 8-pre flush
         * included): the coin is back, no dirty key, every leg root as
         * before and equal to the oracle; then the host rolls back. */
        nodus_v2_envelope_t e3 = { env, elen };
        k_mk_block(&b, 19);
        b.envs = &e3;
        b.n_envs = 1;
        b.fail_at = V2AP_FAIL_AFTER_EFFECT_APPLY;
        b.fail_env_index = 0;
        b.fail_effect_index = 1;
        CHECK(v2x_cmt_host(f.w, &b, 1) == 0 &&
              b.cmt.results[0].code != NODUS_V2_TX_OK,
              "K4d: the item stopped after a real writer ran is refused, "
              "the block applies");
        CHECK(k_utxo_live(f.w, k_nul[K_COIN_S2]) == 1,
              "K4d: the engine's item rollback restored the input coin");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
              "K4d: no dirty key survives the refused item");
        CHECK(k_read_legs(f.w, L2) == 0 && k_moved(L1, L2) == 0,
              "K4d: every persisted leg root is as before the block");
        CHECK(j_roots_ok(&f, "K4d inside the block after the refusal") == 0,
              "K4d: and equals the oracle and the full rebuild");
        CHECK(run_sql(f.w->db, "ROLLBACK") == 0, "K4d: the host rolls back");

        /* K4c: the same S2 spend, committed for real, moves leg 1 */
        CHECK(k_apply_env(&f, 19, env, elen) == 0,
              "K4c: the S2 spend commits at block 19");
        free(env);
        CHECK(k_after_block(&f, L1, L2, 0x01u, "K4c spend") == 0,
              "K4c: only leg 1 moved; roots equal the oracle");
        memcpy(L1, L2, sizeof(L1));
    }

    /* K5: the first EPOCH BOUNDARY under generation 6 (idle blocks to
     * DNAC_EPOCH_LENGTH): nodus_witness_vset_insert (leg 7) and
     * v2ep_attendance_digest (leg 8) write inside the block, the flush
     * puts them into the tries */
    {
        const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
        for (uint64_t h = 20; h < E; h++)
            CHECK(j_apply_ok(&f, h) == 0, "K5: an idle block before the "
                  "boundary");
        const sqlite3_int64 vs0 =
            q1(f.w->db, "SELECT COUNT(*) FROM validator_set_snapshots");
        const sqlite3_int64 at0 =
            q1(f.w->db, "SELECT COUNT(*) FROM v2_attendance_epoch");
        CHECK(k_read_legs(f.w, L1) == 0, "K5: roots before the boundary");
        CHECK(j_apply_ok(&f, E) == 0, "K5: the boundary block commits");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM validator_set_snapshots")
                  > vs0 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_attendance_epoch") > at0,
              "K5: the boundary wrote a validator-set snapshot and an "
              "attendance digest");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              k_read_legs(f.w, L2) == 0, "K5: dirty empty, roots read");
        CHECK((k_moved(L1, L2) & 0xC0u) == 0xC0u,
              "K5: legs 7 (vset) and 8 (attendance) moved");
        CHECK(j_roots_ok(&f, "K5 epoch boundary") == 0,
              "K5: every leg root equals the oracle and the rows");
    }
    jfx_close(&f);
    return 0;
}

static int test_gen6_claims(void) {
    jfx_t f;
    uint8_t chain[32], mh[64];
    CHECK(DNAC_EPOCH_LENGTH > 40, "K6: no epoch boundary among the heights");
    CHECK(k_leaves() == 0, "K6: the distribution leaves");
    CHECK(k_open(&f, 1, chain, mh) == 0, "K6: a chain at generation 6 whose "
          "genesis commits a three-leaf claim distribution (blocks 1..15 "
          "committed)");
    CHECK(q1(f.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "K6: capture is 1");
    uint8_t L0[8][64], L1[8][64], L2[8][64];
    CHECK(k_read_legs(f.w, L0) == 0, "K6: leg roots before");
    dna_claim_t c[K_N_LEAVES];
    for (int i = 0; i < K_N_LEAVES; i++)
        CHECK(k_claim(&c[i], i, chain, mh) == 0, "K6: a signed claim");

    /* a claim block that FAULTS after the flush: nothing of it survives */
    {
        nodus_v2_block_t b;
        const sqlite3_int64 nodes0 =
            q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_nodes");
        k_mk_block(&b, 16);
        b.claims = c;
        b.n_claims = 2;
        b.fail_at = V2AP_FAIL_AFTER_DOMAIN_ROOTS;
        CHECK(v2x_cmt_injected(f.w, &b) == 0,
              "K6: a claim block faulting after the flush is a FAULT, the "
              "whole database byte-identical");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_claims_spent") == 0 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == nodes0,
              "K6: no claim row, no dirty key, the node table as it was");
        CHECK(k_read_legs(f.w, L1) == 0 && k_moved(L0, L1) == 0,
              "K6: every leg root is as before the block");
    }

    /* claim release (nodus_rt_core_claim_apply: the utxo INSERT;
     * nodus_witness_v2_claim_spend_insert: the v2_claims_spent INSERT)
     * -> legs 1 and 3 */
    {
        nodus_v2_block_t b;
        k_mk_block(&b, 16);
        b.claims = c;
        b.n_claims = 2;
        CHECK(v2x_cmt_apply_ok(f.w, &b) == 0, "K6: block 16 carrying two "
              "claims commits");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_claims_spent WHERE "
                          "target_domain_id = 1") == 2,
              "K6: two claim rows");
        CHECK(k_after_block(&f, L0, L1, 0x05u, "K6 two claims") == 0,
              "K6: legs 1 and 3 moved, no other; roots equal the oracle");
        k_mk_block(&b, 17);
        b.claims = &c[2];
        b.n_claims = 1;
        CHECK(v2x_cmt_apply_ok(f.w, &b) == 0, "K6: block 17 carrying the "
              "third claim commits");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_claims_spent WHERE "
                          "target_domain_id = 1") == 3,
              "K6: three claim rows");
        CHECK(k_after_block(&f, L1, L2, 0x05u, "K6 third claim") == 0,
              "K6: legs 1 and 3 moved again; roots equal the oracle");
    }
    jfx_close(&f);
    return 0;
}

/* K7: the epoch releases of a graduation at the first boundary under
 * generation 6 (Sol verifier, second round, row 1): v2ep_release_utxo
 * called for the graduate's bond (output index NODUS_V2_EPGRAD_OUT_IDX) and
 * for its delegation (index NODUS_V2_GRAD_DELEG_OUT_IDX_BASE + rank). The
 * boundary is first applied with an injection after each release (a node
 * FAULT, rolled back whole: dirty empty, node table and leg roots as
 * before, equal to the oracle), then for real. Storage releases are not
 * driven (WP4). */
static int test_gen6_releases(void) {
    jfx_t f;
    CHECK(DNAC_EPOCH_LENGTH > 40, "K7: no epoch boundary among the heights");
    CHECK(k_keys() == 0, "K7: sender keys");
    CHECK(k_open(&f, 2, NULL, NULL) == 0, "K7: a chain at generation 6 "
          "holding one RETIRING validator outside the snapshots and one "
          "delegation to it (blocks 1..15 committed)");
    CHECK(q1(f.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "K7: capture is 1");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM delegations") == 1 &&
          q1(f.w->db, "SELECT COUNT(*) FROM validators") == 8,
          "K7: eight validator rows and the delegation row are in place");
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    for (uint64_t h = 16; h < E; h++)
        CHECK(j_apply_ok(&f, h) == 0, "K7: an idle block before the "
              "boundary");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM utxo_set WHERE output_index = "
                      "200") == 0, "K7: no bond release yet");
    uint8_t L1[8][64], L2[8][64];
    CHECK(k_read_legs(f.w, L1) == 0, "K7: roots before the boundary");
    const sqlite3_int64 nodes0 =
        q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_nodes");

    static const nodus_v2_apply_fail_t pts[2] = {
        V2AP_FAIL_AFTER_FIRST_GRAD_RELEASE,
        V2AP_FAIL_AFTER_FIRST_GRAD_DELEG_RELEASE };
    for (int i = 0; i < 2; i++) {
        nodus_v2_block_t b;
        k_mk_block(&b, E);
        b.fail_at = pts[i];
        CHECK(v2x_cmt_injected(f.w, &b) == 0,
              "K7: the boundary faulting after a release is a node FAULT, "
              "the whole database byte-identical");
        CHECK(q1(f.w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                          "output_index = 200") == 0 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == nodes0,
              "K7: no release row, no dirty key, the node table as it was");
        CHECK(k_read_legs(f.w, L2) == 0 && k_moved(L1, L2) == 0,
              "K7: every leg root is as before the faulted boundary");
        CHECK(j_roots_ok(&f, "K7 after the rolled-back boundary") == 0,
              "K7: and equals the oracle and the rows");
    }

    CHECK(j_apply_ok(&f, E) == 0, "K7: the boundary block commits");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM utxo_set WHERE output_index = "
                      "200") == 1,
          "K7: the graduation released the bond (index 200)");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM utxo_set WHERE output_index >= "
                      "1073741824") == 1 &&
          q1(f.w->db, "SELECT COUNT(*) FROM delegations") == 0,
          "K7: the delegation was released (index 0x40000000 + rank) and "
          "its row deleted");
    CHECK(q1(f.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
          k_read_legs(f.w, L2) == 0, "K7: dirty empty, roots read");
    CHECK((k_moved(L1, L2) & 0xC1u) == 0xC1u,
          "K7: legs 1 (the two releases), 7 and 8 moved");
    CHECK(j_roots_ok(&f, "K7 graduation boundary") == 0,
          "K7: every leg root equals the oracle and the rows");
    jfx_close(&f);
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
    if (!rc) rc = test_all_triggers(&fx);
    if (!rc) rc = test_schema(&fx);
    fx_close(&fx);
    if (!rc) rc = test_vset_leaf();
    if (!rc) rc = test_block_start();
    if (!rc) rc = test_gen6();
    if (!rc) rc = test_gen6_writers();
    if (!rc) rc = test_gen6_claims();
    if (!rc) rc = test_gen6_releases();
    if (rc) {
        fprintf(stderr, "test_hf9_trie_legs: FAILED\n");
        return 1;
    }
    printf("test_hf9_trie_legs: %d checks passed\n", g_checks);
    return 0;
}
