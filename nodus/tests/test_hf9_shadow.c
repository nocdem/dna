/**
 * @file nodus/tests/test_hf9_shadow.c
 * @brief HF-9 WP5, plan row T-10 - the shadow run (plan docs/plans/approved/
 *        2026-11-04-hf9.md §11, §12 T-10; decisions D9, D12, D16, D17; the
 *        operator's answer to Q1, "Tamam, 3 ile devam et." = Option C).
 *        Code: nodus_witness_v2_shadow.c; the shared trie update:
 *        nodus_witness_v2_trie.c.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. ROW COMPARISON = TRIGGER CAPTURE, BY ROOTS (plan T-10, operator "2
 *     duzelt"). Two scratch S20 databases get the same row history. S runs
 *     the shadow (capture 0: nodus_witness_v2_shadow_build, then after each
 *     round nodus_witness_v2_shadow_sync = the post-commit row comparison
 *     and the shadow trie update). T runs the consensus path (build_all,
 *     capture 1 inside a transaction, the 24 triggers, nodus_witness_v2_
 *     trie_flush). After every round, for all eight legs, S's shadow root
 *     == T's committed root == the full rebuild of the rows (build_leg's
 *     root_full on T). The rounds hold inserts, updates, primary-key
 *     changes, deletes on every table, a claim of another domain (not part
 *     of the leg), and - round 3 - a key created and spent in ONE round and
 *     a value changed and changed back: T's triggers capture those keys
 *     (T's dirty table is asserted non-empty inside the transaction),
 *     S's row comparison cannot see them, and the ROOTS are equal anyway.
 *     The key lists are not compared. Rounds 5-7 are applied to S without a
 *     pass and caught up by ONE sync (the catch-up: state based, a change
 *     is never applied twice), then compared with T, which flushed each
 *     round. A restart (the SQLite file closed and opened again) between
 *     rounds changes nothing. `full` mode (the evm_trie_full_root check) is
 *     run on S.
 *  B. ISOLATION. On S, with capture 0: v2_trie_dirty stays empty through
 *     every row write (the triggers are silent), v2_trie_nodes and
 *     v2_trie_roots stay empty, v2_trie_state is still (1, 0) - the shadow
 *     writes only its own tables.
 *  C. FAULTS WITHIN A PASS (-DQGP_FAULT_INJECT=ON). With a row change
 *     pending, an injected fault at the row comparison (point 1), the shadow
 *     trie update (point 2) and the full check (point 4) makes sync return
 *     -1; after the caller's ROLLBACK the shadow roots and the row copy are
 *     byte-identical to before; the same sync without the injection then
 *     succeeds and equals T (so the change really was pending).
 *  D. THE CHAIN. A real generation-5 -> 6 chain (the engine's block path,
 *     the ladder of test_hf9_edge.c: params 9 / 14 / 18 / 22 / 24 at
 *     3 / 5 / 8 / 11 / 14, edge block 13), the node's hook
 *     nodus_witness_v2_shadow_after_commit called after every block as the
 *     host does:
 *      - hf9_shadow off (a zero config): nothing, at any generation;
 *      - below generation 5: nothing, no shadow table exists;
 *      - on, first block of generation 5: SEEDED - status running, one log
 *        row at that height; a second seed is refused and changes nothing;
 *      - every later block: one log row at that height, v2_trie_dirty empty
 *        and capture 0 through the window (nothing shadow-related is
 *        written inside a block), the row counter moves;
 *      - the log row's CORE v4', STOR v3', SYS v7' and leg roots equal the
 *        consensus compositions of a SIMULATED activation of the same rows
 *        (build_all + nodus_witness_core_root_v4 / ... inside a transaction
 *        that is rolled back); GLOBAL v2' differs from the committed GLOBAL
 *        root (control: different compositions);
 *      - block A-1 (the edge): the hook sets STOPPED, reads no row (the
 *        counter does not move), the log gets no new row; capture is 1 (the
 *        edge's), unchanged by the hook; a re-seed attempt is refused, a
 *        hook call with hf9_shadow = on again (a restart) changes nothing;
 *      - the generation-6 node's leg roots and global roots at A-1 and A
 *        equal a twin chain that never ran the shadow;
 *      - after the window the shadow tables' presence changes nothing the
 *        twin has.
 *  E. FAULTS ON THE CHAIN (-DQGP_FAULT_INJECT=ON). With a row change made
 *     after a committed block (tokens row), a fault in the seeding (point
 *     5), in the shadow trie update (2) or in the log write (3) - and in the
 *     full check (4) with hf9_shadow = full - each: the hook returns; the
 *     status is FAULTED; the committed tables (blocks, heads, the trie
 *     tables, the eight source tables) are byte-identical to before the
 *     hook; the shadow's own tables are rolled back (a faulted seeding
 *     leaves no shadow table at all; a faulted pass leaves the row copy,
 *     roots and log as they were); no later hook call writes anything; the
 *     NEXT block commits and its global root equals the twin's. (That the
 *     same row change IS picked up without the injection is F and C.)
 *  F. CATCH-UP ON THE CHAIN. Two blocks applied without the hook, one row
 *     change, one hook call: ONE new log row at the tip (no row for the
 *     missed height), and its legs equal the full rebuild of the rows (the
 *     rebuild inside a rolled-back transaction: the consensus node table
 *     stays empty on the pre-edge chain).
 *  H. REAL FAILURES (Sol verify rows 4-6, no flag needed): an unreadable
 *     committed generation (the runtime table overridden so the registry
 *     tuple resolves to nothing) writes nothing while never seeded and
 *     FAULTS a running shadow (stored FAULTED); a seeding and a pass that
 *     cannot begin their transaction (a second connection holds the write
 *     lock, busy timeout 0) are faults, and because the same lock refuses
 *     the FAULTED write the witness-local latch holds: the status reads
 *     FAULTED while the stored row still says RUNNING, and no further step,
 *     row read or log row follows. D7 (generation 6, NO status row): seeding
 *     is refused and the hook does not seed, nothing written; D5 now also
 *     closes and reopens the database (a real restart) and F reopens inside
 *     the window.
 *  G. THE dnac_hf9_shadow REPLY DECODER (nodus_dnac_hf9_shadow_decode, no
 *     network): hand-encoded replies - a found reply with all fifteen keys
 *     and a not-found reply with st / found only decode; a 63-byte root, a
 *     duplicate key, a found reply with one key missing, a not-found reply
 *     with an extra root and a truncated reply are each refused with the
 *     output zeroed; the request encodes and a too-small buffer is refused.
 *     (The injected faults through the host's apply path are
 *     test_cmt_app.c hyb_shadow_fault_host.)
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (the tries and generations 3-6 exist only
 * there; the target is registered only in that configuration). Sections C
 * and E need -DQGP_FAULT_INJECT=ON (the hooks nodus_witness_v2_shadow_test_
 * fault / _hits); they are ABSENT otherwise: a build without the flag has
 * missing coverage for them, not a pass. No environment. The heights assume
 * no epoch boundary among 1..16 (DNAC_EPOCH_LENGTH 720); the test CHECKs
 * that, so a short-epoch build fails the guard instead of running the
 * wrong scenario (precedent test_hf9_edge.c).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * /tmp/test_hf9_shadow_<tag>_XXXXXX directories, removed at the end of every
 * case (a crash leaves one).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - A and the "full rebuild" oracle share the leg readers with the code
 *    under test (nodus_witness_v2_trie.c); they prove "shadow == trigger
 *    capture == full rebuild of what the readers select", not that the
 *    readers select the right rows (test_hf9_trie_legs.c, test_hf9_kat.c).
 *  - The chain cases make row changes by SQL after a committed block (a
 *    real block would trip the untouched-domain guard on a raw change and
 *    no real transaction fixture is built here): they prove the hook, the
 *    window and the isolation, not a transaction-by-transaction mapping.
 *    The writers' mapping is test_hf9_trie_legs.c (T-5), the hook through
 *    the host is test_cmt_app.c (T-15 iv).
 *  - GLOBAL v2' is checked only against a control (it differs from the
 *    committed root) and across chains by the cross-node tool; its recipe
 *    is the header text of nodus_witness_roots_v2.h and is not re-derived by
 *    an independent oracle here.
 *  - The edge/stop case depends on the first generation-5 block being the
 *    ladder's H5 - 1; the test derives the window from the registry and
 *    then asserts that height.
 *  - E depends on the injection point being reached: every case asserts
 *    nodus_witness_v2_shadow_test_hits() == 1.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_v2_shadow.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus.h"                      /* the dnac_hf9_shadow codec */
#include "dnac/cmt_conr.h"                    /* the reactor's wait_sync */
#include "protocol/nodus_cbor.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)

/* the ladder of test_hf9_edge.c */
#define H9    3u
#define HE    5u
#define HS    8u
#define H5   11u    /* generation 5 from block 11; first committed at 10    */
#define HA   14u    /* param 24: generation 6 from block A = 14; edge = 13  */

/* ══ common helpers ═══════════════════════════════════════════════════ */

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

static int table_exists(sqlite3 *db, const char *name) {
    sqlite3_stmt *st = NULL;
    int r = -1;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                           "type = 'table' AND name = ?1", -1, &st, NULL)
        != SQLITE_OK) return -1;
    if (sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        r = sqlite3_column_int(st, 0) > 0;
    sqlite3_finalize(st);
    return r;
}

/* SHA3-512 over the rows of the listed tables (every column of every row,
 * ordered by all columns; a table that does not exist digests as ABSENT) */
static int tabs_digest(sqlite3 *db, const char *const *tabs, size_t nt,
                       uint8_t out[64]) {
    size_t cap = 1u << 16, n = 0;
    uint8_t *buf = malloc(cap);
    int bad = buf == NULL;
    for (size_t t = 0; t < nt && !bad; t++) {
        size_t tl = strlen(tabs[t]);
        while (n + tl + 2 > cap) {
            cap *= 2;
            uint8_t *nb = realloc(buf, cap);
            if (!nb) { bad = 1; break; }
            buf = nb;
        }
        if (bad) break;
        memcpy(buf + n, tabs[t], tl + 1);
        n += tl + 1;
        if (table_exists(db, tabs[t]) != 1) {
            buf[n++] = 0xAB;                              /* ABSENT */
            continue;
        }
        char sql[600];
        sqlite3_stmt *st = NULL;
        snprintf(sql, sizeof(sql), "SELECT * FROM %s LIMIT 0", tabs[t]);
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
            bad = 1;
            break;
        }
        int cols = sqlite3_column_count(st);
        sqlite3_finalize(st);
        size_t off = (size_t)snprintf(sql, sizeof(sql),
                                      "SELECT * FROM %s ORDER BY ", tabs[t]);
        for (int c = 1; c <= cols && off < sizeof(sql) - 8; c++)
            off += (size_t)snprintf(sql + off, sizeof(sql) - off,
                                    c > 1 ? ",%d" : "%d", c);
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
            bad = 1;
            break;
        }
        int rc;
        while (!bad && (rc = sqlite3_step(st)) == SQLITE_ROW) {
            for (int c = 0; c < cols && !bad; c++) {
                int ty = sqlite3_column_type(st, c);
                int len = ty == SQLITE_NULL ? 0 : sqlite3_column_bytes(st, c);
                const void *p = ty == SQLITE_BLOB ? sqlite3_column_blob(st, c)
                    : ty == SQLITE_NULL ? NULL
                    : (const void *)sqlite3_column_text(st, c);
                while (n + 6 + (size_t)len > cap) {
                    cap *= 2;
                    uint8_t *nb = realloc(buf, cap);
                    if (!nb) { bad = 1; break; }
                    buf = nb;
                }
                if (bad) break;
                buf[n++] = (uint8_t)ty;
                for (int i = 0; i < 4; i++) buf[n++] = (uint8_t)(len >> (8 * i));
                if (p && len > 0) {
                    memcpy(buf + n, p, (size_t)len);
                    n += (size_t)len;
                }
            }
            if (!bad) buf[n++] = 0xFF;
        }
        if (!bad && rc != SQLITE_DONE) bad = 1;
        sqlite3_finalize(st);
    }
    int ret = -1;
    if (!bad && qgp_sha3_512(buf, n, out) == 0) ret = 0;
    free(buf);
    return ret;
}

/* the tables the shadow must NEVER write */
static const char *const CONSENSUS_TABS[] = {
    "v2_blocks", "v2_domain_heads", "v2_trie_nodes", "v2_trie_roots",
    "v2_trie_dirty", "v2_trie_state", "utxo_set", "tokens", "v2_names",
    "v2_claims_spent", "v2_storage_nodes", "v2_storage_segments",
    "validator_set_snapshots", "v2_attendance_epoch"
};
#define N_CONSENSUS_TABS (sizeof(CONSENSUS_TABS) / sizeof(CONSENSUS_TABS[0]))

#ifdef QGP_FAULT_INJECT
/* the shadow's own tables (used by the fault cases only) */
static const char *const SHADOW_TABS[] = {
    "v2_trie_shadow_state", "v2_trie_shadow_nodes", "v2_trie_shadow_roots",
    "v2_trie_shadow_rows", "v2_trie_shadow_log"
};
#define N_SHADOW_TABS (sizeof(SHADOW_TABS) / sizeof(SHADOW_TABS[0]))

/* ... without the status row (a fault changes that row on purpose) */
static const char *const SHADOW_DATA_TABS[] = {
    "v2_trie_shadow_nodes", "v2_trie_shadow_roots", "v2_trie_shadow_rows",
    "v2_trie_shadow_log"
};
#define N_SHADOW_DATA_TABS (sizeof(SHADOW_DATA_TABS) / sizeof(SHADOW_DATA_TABS[0]))
#endif

/* ══ scratch databases (A, B, C) - test_hf9_trie_legs.c's fixture ═════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    char             path[256];
} sx_t;

static int sx_open(sx_t *x, const char *tag) {
    memset(x, 0, sizeof(*x));
    x->w = calloc(1, sizeof(*x->w));            /* multi-MB - heap */
    if (!x->w) return -1;
    snprintf(x->dir, sizeof(x->dir), "/tmp/test_hf9_shadow_%s_XXXXXX", tag);
    if (!mkdtemp(x->dir)) { free(x->w); x->w = NULL; return -1; }
    snprintf(x->w->data_path, sizeof(x->w->data_path), "%s", x->dir);
    uint8_t id16[16];
    memset(id16, 0x3A, sizeof(id16));
    if (nodus_witness_create_chain_db(x->w, id16) != 0) return -1;
    if (nodus_witness_db_migrate_v2s20(x->w) != 0) return -1;
    const char *fn = sqlite3_db_filename(x->w->db, "main");
    if (!fn || strlen(fn) >= sizeof(x->path)) return -1;
    snprintf(x->path, sizeof(x->path), "%s", fn);
    return 0;
}

static void sx_close(sx_t *x) {
    if (!x->w) return;
    if (x->w->db) sqlite3_close(x->w->db);
    free(x->w);
    x->w = NULL;
    rmrf(x->dir);
}

static int sx_restart(sx_t *x) {
    sqlite3_close(x->w->db);
    x->w->db = NULL;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(x->path, &db, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    x->w->db = db;
    return 0;
}

/* the row writers (statement shapes of plan §4.3, as test_hf9_trie_legs.c) */
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

/* the population both scratch databases start from: a row in every table */
static int populate(sx_t *x) {
    sqlite3 *db = x->w->db;
    return utxo_sql(db, 0x01, 100) == 0 && utxo_sql(db, 0x02, 200) == 0 &&
           token_sql(db, 0x01, 8) == 0 &&
           claim_sql(db, 0x01, 1, 50) == 0 &&
           name_sql(db, "alice", 0x01) == 0 && name_sql(db, "bobby", 0x02) == 0 &&
           node_sql(x->w, 0x01, 5000, 1) == 0 &&
           seg_sql(db, 1) == 0 &&
           vset_sql(db, 720) == 0 && att_sql(db, 720) == 0 ? 0 : -1;
}

/* One round of row writes, applied identically to S and T. Rounds:
 *  1 inserts, updates, a primary-key change, a claim of another domain;
 *  2 deletes and updates (and the segment / vset / attendance growth);
 *  3 a key created and spent in the round, a value changed and changed
 *    back, a token created and removed - nothing a row comparison sees;
 *  4 nothing;
 *  5 7  three rounds that S catches up in one sync. */
static int round_sql(sx_t *x, int n) {
    sqlite3 *db = x->w->db;
    switch (n) {
    case 1:
        return utxo_sql(db, 0x71, 777) == 0 && utxo_sql(db, 0x72, 5) == 0 &&
               run_sql(db, "UPDATE utxo_set SET amount = amount + 5 WHERE "
                           "nullifier = " NB("01")) == 0 &&
               run_sql(db, "UPDATE utxo_set SET nullifier = " NB("7f")
                           " WHERE nullifier = " NB("02")) == 0 &&
               token_sql(db, 0x62, 6) == 0 &&
               run_sql(db, "UPDATE tokens SET supply = 5 WHERE token_id = "
                           NB("01")) == 0 &&
               claim_sql(db, 0x63, 1, 12) == 0 &&
               claim_sql(db, 0x64, 3, 13) == 0 &&   /* another domain */
               name_sql(db, "carol", 0x65) == 0 &&
               node_sql(x->w, 0x66, 900, 1) == 0 &&
               seg_sql(db, 2) == 0 &&
               vset_sql(db, 1440) == 0 && att_sql(db, 1440) == 0 ? 0 : -1;
    case 2:
        return run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                           NB("71")) == 0 &&
               run_sql(db, "DELETE FROM tokens WHERE token_id = "
                           NB("62")) == 0 &&
               run_sql(db, "DELETE FROM v2_names WHERE name = CAST('bobby' "
                           "AS BLOB)") == 0 &&
               run_sql(db, "UPDATE v2_storage_nodes SET status = 3, bond = 0 "
                           "WHERE bond = 5000") == 0 &&
               run_sql(db, "UPDATE v2_attendance_epoch SET digest = CAST("
                           "zeroblob(63)||x'c3' AS BLOB) WHERE epoch_start = "
                           "720") == 0 &&
               run_sql(db, "DELETE FROM v2_claims_spent WHERE nullifier = "
                           NB("63")) == 0 &&
               seg_sql(db, 3) == 0 && vset_sql(db, 2880) == 0 ? 0 : -1;
    case 3:
        return utxo_sql(db, 0x81, 10) == 0 &&
               run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                           NB("81")) == 0 &&              /* created+spent */
               run_sql(db, "UPDATE utxo_set SET amount = amount + 5 WHERE "
                           "nullifier = " NB("72")) == 0 &&
               run_sql(db, "UPDATE utxo_set SET amount = amount - 5 WHERE "
                           "nullifier = " NB("72")) == 0 &&  /* and back */
               token_sql(db, 0x82, 6) == 0 &&
               run_sql(db, "DELETE FROM tokens WHERE token_id = "
                           NB("82")) == 0 ? 0 : -1;
    case 4:
        return 0;
    case 5:
        return utxo_sql(db, 0x91, 91) == 0 && token_sql(db, 0x91, 4) == 0 ? 0
                                                                          : -1;
    case 6:
        return run_sql(db, "UPDATE utxo_set SET amount = 5000 WHERE "
                           "nullifier = " NB("91")) == 0 &&
               name_sql(db, "dave", 0x92) == 0 && seg_sql(db, 4) == 0 ? 0 : -1;
    case 7:
        return run_sql(db, "DELETE FROM utxo_set WHERE nullifier = "
                           NB("01")) == 0 &&
               att_sql(db, 2160) == 0 ? 0 : -1;
    default:
        return -1;
    }
}

/* S: the round's writes (autocommit, capture 0 - the triggers are silent),
 * then - unless `pass` is 0 - the post-commit row comparison in its own
 * transaction */
static int s_round(sx_t *S, int n, int pass, int full) {
    if (round_sql(S, n) != 0) return -1;
    if (!pass) return 0;
    if (run_sql(S->w->db, "BEGIN IMMEDIATE") != 0) return -1;
    if (nodus_witness_v2_shadow_sync(S->w, full) != 0) {
        run_sql(S->w->db, "ROLLBACK");
        return -1;
    }
    return run_sql(S->w->db, "COMMIT");
}

/* T: the round's writes inside a transaction, the consensus flush before
 * its COMMIT; returns the dirty count the triggers captured through
 * `dirty` (read before the flush) */
static int t_round(sx_t *T, int n, int64_t *dirty) {
    if (run_sql(T->w->db, "BEGIN") != 0) return -1;
    if (round_sql(T, n) != 0) { run_sql(T->w->db, "ROLLBACK"); return -1; }
    if (dirty && nodus_witness_v2_trie_dirty_count(T->w, dirty) != 0) {
        run_sql(T->w->db, "ROLLBACK");
        return -1;
    }
    if (nodus_witness_v2_trie_flush(T->w) != 0) {
        run_sql(T->w->db, "ROLLBACK");
        return -1;
    }
    return run_sql(T->w->db, "COMMIT");
}

/* S's shadow roots == T's committed roots == the full rebuild of T's rows
 * (build_leg's root_full) */
static int legs_equal(sx_t *S, sx_t *T) {
    for (int leg = 1; leg <= 8; leg++) {
        uint8_t sh[64], tc[64], inc[64], full[64];
        if (nodus_witness_v2_trie_shadow_leg_root(S->w, leg, sh) != 0)
            return -leg;
        if (nodus_witness_v2_trie_leg_root(T->w, leg, tc) != 0) return -leg;
        if (nodus_witness_v2_trie_build_leg(T->w, leg, inc, full) != 0)
            return -leg;
        if (memcmp(sh, tc, 64) != 0 || memcmp(sh, full, 64) != 0 ||
            memcmp(inc, full, 64) != 0)
            return leg;
    }
    return 0;
}

/* S and T opened on the same population, ready for round 1 */
static int twin_open(sx_t *S, sx_t *T) {
    if (sx_open(S, "S") != 0 || sx_open(T, "T") != 0) return -1;
    if (populate(S) != 0 || populate(T) != 0) return -1;
    /* S: the shadow seeding step (capture 0, its own transaction) */
    if (run_sql(S->w->db, "BEGIN IMMEDIATE") != 0 ||
        nodus_witness_v2_shadow_build(S->w) != 0 ||
        run_sql(S->w->db, "COMMIT") != 0) return -1;
    /* T: the consensus build and capture 1 (the edge's two steps) */
    if (run_sql(T->w->db, "BEGIN") != 0 ||
        nodus_witness_v2_trie_build_all(T->w) != 0 ||
        nodus_witness_v2_trie_set_capture(T->w, 1) != 0 ||
        run_sql(T->w->db, "COMMIT") != 0) return -1;
    return 0;
}

/* ══ A, B: roots equal the trigger capture; isolation ═════════════════ */

static int t_equality_and_isolation(void) {
    sx_t S, T;
    int64_t dirty = 0;
    CHECK(twin_open(&S, &T) == 0, "A0: the twin scratch databases");
    CHECK(legs_equal(&S, &T) == 0, "A0: seeded roots = trigger twin = full "
          "rebuild");

    /* rounds 1-4, each compared; round 3 is the created-and-spent round */
    for (int n = 1; n <= 4; n++) {
        CHECK(s_round(&S, n, 1, n == 3) == 0, "A: the shadow round "
              "(round 3 in full mode)");
        CHECK(t_round(&T, n, &dirty) == 0, "A: the trigger round");
        if (n == 3)
            CHECK(dirty == 3, "A3: the triggers captured exactly the three "
                  "keys the row comparison cannot see: the utxo created and "
                  "spent (0x81), the utxo changed and changed back (0x72) "
                  "and the token created and removed (0x82)");
        CHECK(legs_equal(&S, &T) == 0, "A: after the round, shadow roots = "
              "trigger roots = full rebuild, all eight legs");
        /* B: nothing shadow-related reached the consensus tables */
        CHECK(q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == 0 &&
              q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0 &&
              q1(S.w->db, "SELECT capture FROM v2_trie_state") == 0 &&
              q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_state") == 1,
              "B: capture 0, no dirty key, no consensus node / root row");
    }
    CHECK(q1(T.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "A: T's dirty table is empty after the flushes");

    /* a restart between rounds changes nothing */
    CHECK(sx_restart(&S) == 0 && sx_restart(&T) == 0, "A5: restart both");
    CHECK(legs_equal(&S, &T) == 0, "A5: reopened roots still equal");

    /* rounds 5-7: S catches up in ONE sync, T flushed each */
    CHECK(s_round(&S, 5, 0, 0) == 0 && s_round(&S, 6, 0, 0) == 0 &&
          s_round(&S, 7, 0, 0) == 0, "A6: three rounds without a pass");
    CHECK(t_round(&T, 5, NULL) == 0 && t_round(&T, 6, NULL) == 0 &&
          t_round(&T, 7, NULL) == 0, "A6: the trigger twin flushed each");
    CHECK(legs_equal(&S, &T) != 0, "A6: control - before the catch-up the "
          "shadow is behind (the roots differ)");
    CHECK(run_sql(S.w->db, "BEGIN IMMEDIATE") == 0 &&
          nodus_witness_v2_shadow_sync(S.w, 0) == 0 &&
          run_sql(S.w->db, "COMMIT") == 0, "A6: ONE sync");
    CHECK(legs_equal(&S, &T) == 0, "A6: the catch-up reaches the trigger "
          "roots and the full rebuild");
    /* and a second sync with nothing new changes nothing */
    {
        uint8_t before[8][64], after[8][64];
        for (int leg = 1; leg <= 8; leg++)
            CHECK(nodus_witness_v2_trie_shadow_leg_root(S.w, leg,
                                                        before[leg - 1]) == 0,
                  "A7: root read");
        CHECK(run_sql(S.w->db, "BEGIN IMMEDIATE") == 0 &&
              nodus_witness_v2_shadow_sync(S.w, 1) == 0 &&
              run_sql(S.w->db, "COMMIT") == 0, "A7: a sync with no change "
              "(full mode)");
        for (int leg = 1; leg <= 8; leg++)
            CHECK(nodus_witness_v2_trie_shadow_leg_root(S.w, leg,
                                                        after[leg - 1]) == 0,
                  "A7: root read");
        CHECK(memcmp(before, after, sizeof(before)) == 0,
              "A7: nothing is applied twice");
    }
    CHECK(q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
          q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == 0 &&
          q1(S.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0 &&
          q1(S.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "B: still no dirty key, node or root row, capture 0");
    sx_close(&S);
    sx_close(&T);
    return 0;
}

#ifdef QGP_FAULT_INJECT
/* C. faults within a pass roll back */
static int t_faults_within_pass(void) {
    static const int points[] = { 1, 2, 4 };
    for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
        sx_t S, T;
        uint8_t d0[64], d1[64];
        const int hits0 = nodus_witness_v2_shadow_test_hits();
        CHECK(twin_open(&S, &T) == 0, "C0: twin");
        CHECK(round_sql(&S, 1) == 0 && t_round(&T, 1, NULL) == 0,
              "C0: a change pending in S, flushed in T");
        CHECK(tabs_digest(S.w->db, SHADOW_TABS, N_SHADOW_TABS, d0) == 0,
              "C0: digest of the shadow tables");
        CHECK(nodus_witness_v2_shadow_test_fault(points[i]) == 0,
              "C0: arm the point");
        CHECK(run_sql(S.w->db, "BEGIN IMMEDIATE") == 0, "C: begin");
        CHECK(nodus_witness_v2_shadow_sync(S.w, 1) == -1,
              "C: the injected fault makes the sync fail");
        CHECK(run_sql(S.w->db, "ROLLBACK") == 0, "C: the caller rolls back");
        CHECK(nodus_witness_v2_shadow_test_hits() == hits0 + 1,
              "C: the injection point was reached (false-pass guard)");
        CHECK(tabs_digest(S.w->db, SHADOW_TABS, N_SHADOW_TABS, d1) == 0 &&
              memcmp(d0, d1, 64) == 0,
              "C: after the rollback the shadow tables are byte-identical");
        CHECK(legs_equal(&S, &T) != 0,
              "C: control - the shadow did not move");
        /* disarmed: the same sync succeeds and equals the trigger twin */
        CHECK(run_sql(S.w->db, "BEGIN IMMEDIATE") == 0 &&
              nodus_witness_v2_shadow_sync(S.w, 1) == 0 &&
              run_sql(S.w->db, "COMMIT") == 0, "C: the same sync, no fault");
        CHECK(legs_equal(&S, &T) == 0,
              "C: ... equals the trigger twin (the change was pending)");
        sx_close(&S);
        sx_close(&T);
    }
    return 0;
}
#endif

/* ══ chain fixture (D, E, F) - the ladder of test_hf9_edge.c ══════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    fx->w->v2_runtime_table = NULL;
    fx->w->v2_runtime_table_n = 0;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
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

/* HF-2 on from 1, the generation ladder; `ha` != 0 also votes generation 6
 * at block `ha` (the edge is block ha-1). An S20 chain, engine genesis. */
static int fx_open(fixture_t *fx, const char *tag, uint64_t ha) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB - ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf9_shadow_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x59, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    {
        uint32_t ver = 0;
        if (nodus_witness_db_migrate_v2s20(fx->w) != 0 ||
            nodus_witness_db_schema_version(fx->w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S20)
            return -1;
    }
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN2,
               (uint64_t)DNAC_CFG_RULESET_GEN2_D2, H9, 12) != 0 ||
        cc_row(fx->w, DNAC_CFG_EVM_ACTIVE,
               (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE, 14) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, HS, 13) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROOTS,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, H5, 15) != 0)
        return -1;
    if (ha && cc_row(fx->w, DNAC_CFG_RULESET_GEN_TRIE,
                     (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, ha, 16) != 0)
        return -1;
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

/* A RESTART: the SQLite handle is closed (its result checked) and the same
 * file opened again in a FRESH, zero-initialised witness context - what the
 * production init does (nodus_witness_init memsets the witness,
 * nodus_witness.c:2814) - so every in-memory state (the failure latch, the
 * caches, the config) is gone; only the data path and the `hf9_shadow`
 * setting (re-read from nodus.json at a real start) are re-applied. */
static int fx_reopen(fixture_t *fx) {
    nodus_witness_t *old = fx->w;
    const char *fn = sqlite3_db_filename(old->db, "main");
    char path[512];
    if (!fn || strlen(fn) >= sizeof(path)) return -1;
    snprintf(path, sizeof(path), "%s", fn);
    const int cfg = old->config.hf9_shadow;
    if (sqlite3_close(old->db) != SQLITE_OK) return -1;
    old->db = NULL;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    nodus_witness_t *nw = calloc(1, sizeof(*nw));     /* multi-MB - heap */
    if (!nw) {
        sqlite3_close(db);
        return -1;
    }
    snprintf(nw->data_path, sizeof(nw->data_path), "%s", old->data_path);
    nw->db = db;
    nw->config.hf9_shadow = cfg;
    free(old);
    fx->w = nw;
    return 0;
}

static int apply_block(fixture_t *fx, uint64_t h) {
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch = nodus_v2_epoch_for_height(h);
    return v2x_cmt_apply_ok(fx->w, &b);
}

static uint32_t committed_gen(nodus_witness_t *w) {
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 0, &rt) != 0 || !rt)
        return 0;
    return rt->generation;
}

static int shadow_status(nodus_witness_t *w) {
    int st = 99;
    if (nodus_witness_v2_shadow_status(w, &st) != 0) return 98;
    return st;
}

static int log_rows(nodus_witness_t *w) {
    if (table_exists(w->db, "v2_trie_shadow_log") != 1) return -1;
    return (int)q1(w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log");
}

static int block_global(nodus_witness_t *w, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT global_root FROM v2_blocks WHERE "
                           "global_height = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(out, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int stored_roots(nodus_witness_t *w, uint8_t roots[8][64]) {
    for (int leg = 1; leg <= 8; leg++)
        if (nodus_witness_v2_trie_leg_root(w, leg, roots[leg - 1]) != 0)
            return -1;
    return 0;
}

/* The expected GLOBAL v2' (plan §6 :217 "DomainHead v2, domains_root,
 * GLOBAL v2 (replay leg) - unchanged", §11 :424 "the compositions computed
 * post-commit from the committed state with the shadow legs"): the
 * COMMITTED v2_domain_heads rows (head blob decoded here from the layout of
 * ledger_roots_v2.h, last_upd_hash column as stored), the SYSTEM and CORE
 * domain_state_root replaced by `sys` / `core`, the committed replay root,
 * composed by the shared dnac primitives dna_v2_domains_root_v2 and
 * dna_v2_global_root_v2 - NOT by global_root_v2_impl / global_compose. */
static int expected_glob(nodus_witness_t *w, const uint8_t core[64],
                         const uint8_t sys[64], uint8_t out[64]) {
    dna_v2_domain_head_t heads[8];
    uint8_t luh[8][64];
    size_t n = 0;
    sqlite3_stmt *st = NULL;
    int rc, ok = 1;
    if (sqlite3_prepare_v2(w->db, "SELECT head, last_upd_hash, "
            "typeof(last_upd_hash) FROM v2_domain_heads ORDER BY domain_id "
            "ASC", -1, &st, NULL) != SQLITE_OK) return -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const uint8_t *b = sqlite3_column_blob(st, 0);
        const char *ty = (const char *)sqlite3_column_text(st, 2);
        if (n >= 8 || !b || sqlite3_column_bytes(st, 0) != DNA_V2_DOMHEAD_ENC_LEN ||
            !ty || strcmp(ty, "blob") != 0 ||
            sqlite3_column_bytes(st, 1) != 64) { ok = 0; break; }
        dna_v2_domain_head_t *h = &heads[n];
        memset(h, 0, sizeof(*h));
        h->domain_id = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                       ((uint32_t)b[2] << 8) | b[3];
        memcpy(h->domain_state_root, b + 4, 64);
        for (int i = 0; i < 8; i++)
            h->domain_height = (h->domain_height << 8) | b[68 + i];
        for (int i = 0; i < 8; i++)
            h->last_updated_global_height =
                (h->last_updated_global_height << 8) | b[76 + i];
        h->ruleset_version = ((uint32_t)b[84] << 24) | ((uint32_t)b[85] << 16) |
                             ((uint32_t)b[86] << 8) | b[87];
        h->status = b[88];
        if (h->domain_id == DNA_DOMAIN_SYSTEM)
            memcpy(h->domain_state_root, sys, 64);
        else if (h->domain_id == DNA_DOMAIN_CORE)
            memcpy(h->domain_state_root, core, 64);
        memcpy(luh[n], sqlite3_column_blob(st, 1), 64);
        n++;
    }
    if (rc != SQLITE_DONE) ok = 0;
    sqlite3_finalize(st);
    if (!ok || n == 0) return -1;
    uint8_t domains[64], replay[64];
    if (dna_v2_domains_root_v2(heads, (const uint8_t (*)[64])luh, n, domains)
            != 0 || nodus_witness_replay_root(w, replay) != 0)
        return -1;
    return dna_v2_global_root_v2(domains, replay, out) == 0 ? 0 : -1;
}

/* The log row of `height` against the expected values, all 64 bytes of each:
 * the eight legs and CORE v4' / STOR v3' / SYS v7' as the CONSENSUS code
 * computes them after a simulated activation of the same rows (build_all +
 * the consensus compositions inside a transaction that is rolled back), and
 * GLOBAL v2' from expected_glob. 0 = all equal, else a code. */
static int log_row_matches(nodus_witness_t *w, uint64_t height) {
    nodus_v2_shadow_log_t row;
    uint8_t core[64], stor[64], sys[64], glob[64], stored[8][64];
    if (nodus_witness_v2_shadow_log_read(w, height, &row) != 1) return 1;
    if (run_sql(w->db, "BEGIN") != 0) return 2;
    int ok = nodus_witness_v2_trie_build_all(w) == 0 &&
             stored_roots(w, stored) == 0 &&
             nodus_witness_core_root_v4(w, core) == 0 &&
             nodus_witness_storage_root_v3(w, stor) == 0 &&
             nodus_witness_system_root_v7(w, sys) == 0;
    if (run_sql(w->db, "ROLLBACK") != 0) return 3;
    if (!ok) return 4;
    for (int leg = 0; leg < 8; leg++)
        if (memcmp(row.leg[leg], stored[leg], 64) != 0) return 10 + leg;
    if (memcmp(row.core, core, 64) != 0) return 20;
    if (memcmp(row.stor, stor, 64) != 0) return 21;
    if (memcmp(row.sys, sys, 64) != 0) return 22;
    if (expected_glob(w, core, sys, glob) != 0) return 23;
    if (memcmp(row.glob, glob, 64) != 0) return 24;
    return 0;
}

/* The row copy v2_trie_shadow_rows against the CURRENT rows (plan :424
 * "v2_trie_shadow_rows is updated to the current rows"): for every leg, each
 * row the build's own scan selects (nodus_witness_v2_trie_scan_leg: canonical
 * key, 64-byte leaf hash) is in the copy with the same value, and the copy
 * holds no other row of that leg. The expected side is the scan, never the
 * copy. */
typedef struct {
    sqlite3_stmt *q;
    int           leg;
    long          n, bad;
} copy_cmp_t;

static int copy_cmp_row(void *vctx, const uint8_t *key, size_t key_len,
                        const uint8_t val[64]) {
    copy_cmp_t *c = (copy_cmp_t *)vctx;
    c->n++;
    if (sqlite3_reset(c->q) != SQLITE_OK ||
        sqlite3_clear_bindings(c->q) != SQLITE_OK ||
        sqlite3_bind_int(c->q, 1, c->leg) != SQLITE_OK ||
        sqlite3_bind_blob(c->q, 2, key, (int)key_len, SQLITE_STATIC)
            != SQLITE_OK) {
        c->bad++;
        return 0;
    }
    if (sqlite3_step(c->q) != SQLITE_ROW ||
        sqlite3_column_bytes(c->q, 0) != 64 ||
        memcmp(sqlite3_column_blob(c->q, 0), val, 64) != 0)
        c->bad++;
    return 0;
}

/* 0 = the copy equals the selected rows of all eight legs */
static int shadow_rows_match(nodus_witness_t *w) {
    for (int leg = 1; leg <= 8; leg++) {
        copy_cmp_t c;
        char sql[96];
        memset(&c, 0, sizeof(c));
        c.leg = leg;
        if (sqlite3_prepare_v2(w->db, "SELECT value FROM v2_trie_shadow_rows "
                "WHERE leg = ?1 AND key = ?2", -1, &c.q, NULL) != SQLITE_OK)
            return -1;
        int rc = nodus_witness_v2_trie_scan_leg(w, leg, copy_cmp_row, &c);
        sqlite3_finalize(c.q);
        if (rc != 0 || c.bad != 0) return leg;
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_trie_shadow_rows "
                 "WHERE leg = %d", leg);
        if (q1(w->db, sql) != c.n) return 100 + leg;
    }
    return 0;
}

static int add_token_row(nodus_witness_t *w, int nb) {
    return token_sql(w->db, nb, 8);
}

/* ══ D. the chain: window, seeding, passes, stop, equality ════════════ */

static int t_chain_window(void) {
    fixture_t fx, twin;
    uint8_t d_consensus_before[64], d_consensus_after[64];
    int seed_h = 0, rows_before;
    uint64_t scanned_before;
    CHECK(E_LEN > HA + 2u, "no epoch boundary among heights 1..A+2");
    CHECK(fx_open(&fx, "chain", HA) == 0, "the generation-6 ladder chain");
    CHECK(fx.w->config.hf9_shadow == NODUS_HF9_SHADOW_OFF,
          "a zero-initialised config is off");

    /* blocks 1..H5-1 with the shadow OFF, hook called: nothing, ever */
    for (uint64_t h = 1; h <= H5 - 1u; h++) {
        CHECK(apply_block(&fx, h) == 0, "block");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_NONE &&
              table_exists(fx.w->db, "v2_trie_shadow_log") == 0,
              "D1: off - the hook writes nothing (no status, no table)");
    }
    CHECK(committed_gen(fx.w) == NODUS_RT_GEN_ROOTS,
          "D1: generation 5 is committed after block H5-1");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_NONE,
          "D1: off at generation 5 - still nothing");

    /* on: seeded at the first generation-5 height */
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    nodus_witness_v2_shadow_after_commit(fx.w);
    seed_h = (int)(H5 - 1u);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING,
          "D2: on - seeded, status running");
    {
        nodus_v2_shadow_log_t row;
        CHECK(nodus_witness_v2_shadow_log_read(fx.w, (uint64_t)seed_h, &row)
              == 1 && row.height == (uint64_t)seed_h &&
              log_rows(fx.w) == 1, "D2: one log row, at the seeded height");
        CHECK(nodus_witness_v2_shadow_log_read(fx.w, 0, &row) == 1 &&
              row.height == (uint64_t)seed_h, "D2: height 0 = the newest");
        CHECK(nodus_witness_v2_shadow_log_read(fx.w, 99, &row) == 0,
              "D2: no row at another height");
    }
    CHECK(nodus_witness_v2_shadow_seed(fx.w) == -1 && log_rows(fx.w) == 1 &&
          shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING,
          "D2: a second seed is refused and changes nothing");

    /* the window: one log row per block, nothing in the consensus tables */
    for (uint64_t h = H5; h <= HA - 2u; h++) {
        uint64_t s0 = nodus_witness_v2_shadow_rows_scanned();
        CHECK(apply_block(&fx, h) == 0, "block");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 0,
              "D3: inside the block transaction nothing shadow-related: "
              "no dirty key, capture 0");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING,
              "D3: still running");
        {
            nodus_v2_shadow_log_t row;
            CHECK(nodus_witness_v2_shadow_log_read(fx.w, h, &row) == 1,
                  "D3: a log row at this height");
        }
        CHECK(nodus_witness_v2_shadow_rows_scanned() > s0,
              "D3: the pass read the rows (the counter moved)");
        CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0 &&
              q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == 0 &&
              q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_roots") == 0,
              "D3: the pass wrote no consensus trie table");
    }
    CHECK(log_rows(fx.w) == (int)(HA - 2u - (H5 - 1u) + 1u),
          "D3: one row per height from the seed to A-2");

    /* the log row = the consensus compositions of a simulated activation */
    {
        nodus_v2_shadow_log_t row;
        uint8_t core[64], stor[64], sys[64], glob_c[64];
        uint8_t stored[8][64];
        CHECK(nodus_witness_v2_shadow_log_read(fx.w, HA - 2u, &row) == 1,
              "D4: the newest row");
        CHECK(tabs_digest(fx.w->db, CONSENSUS_TABS, N_CONSENSUS_TABS,
                          d_consensus_before) == 0, "D4: digest");
        CHECK(run_sql(fx.w->db, "BEGIN") == 0 &&
              nodus_witness_v2_trie_build_all(fx.w) == 0 &&
              stored_roots(fx.w, stored) == 0 &&
              nodus_witness_core_root_v4(fx.w, core) == 0 &&
              nodus_witness_storage_root_v3(fx.w, stor) == 0 &&
              nodus_witness_system_root_v7(fx.w, sys) == 0,
              "D4: the simulated activation (build_all, the consensus "
              "compositions)");
        CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "D4: rolled back");
        for (int leg = 0; leg < 8; leg++)
            CHECK(memcmp(row.leg[leg], stored[leg], 64) == 0,
                  "D4: shadow leg root = the activation's leg root");
        CHECK(memcmp(row.core, core, 64) == 0 &&
              memcmp(row.stor, stor, 64) == 0 &&
              memcmp(row.sys, sys, 64) == 0,
              "D4: CORE v4' / STOR v3' / SYS v7' = the consensus "
              "compositions over the same rows");
        CHECK(block_global(fx.w, HA - 2u, glob_c) == 0 &&
              memcmp(row.glob, glob_c, 64) != 0,
              "D4: GLOBAL v2' differs from the committed global root "
              "(control: other compositions)");
        CHECK(log_row_matches(fx.w, HA - 2u) == 0,
              "D4: the logged legs, CORE / STOR / SYS and the GLOBAL v2' "
              "(independently composed) equal the expected values, all 64 "
              "bytes");
        CHECK(tabs_digest(fx.w->db, CONSENSUS_TABS, N_CONSENSUS_TABS,
                          d_consensus_after) == 0 &&
              memcmp(d_consensus_before, d_consensus_after, 64) == 0,
              "D4: the simulated activation left the consensus tables "
              "byte-identical");
    }

    /* the edge block A-1: STOPPED, no row read, capture the edge's */
    scanned_before = nodus_witness_v2_shadow_rows_scanned();
    rows_before = log_rows(fx.w);
    CHECK(apply_block(&fx, HA - 1u) == 0, "the edge block A-1");
    CHECK(committed_gen(fx.w) == NODUS_RT_GEN_TRIE, "generation 6 committed");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "D5: the edge set capture 1");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_STOPPED,
          "D5: after A-1 the hook sets STOPPED");
    CHECK(nodus_witness_v2_shadow_rows_scanned() == scanned_before,
          "D5: ... and reads no row");
    CHECK(log_rows(fx.w) == rows_before, "D5: ... and logs nothing");
    CHECK(q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "D5: the hook did not touch capture");
    CHECK(nodus_witness_v2_shadow_seed(fx.w) == -1 &&
          shadow_status(fx.w) == NODUS_V2_SHADOW_STOPPED &&
          q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "D5: a re-seed attempt at generation 6 is refused, status and "
          "capture unchanged");
    CHECK(apply_block(&fx, HA) == 0, "block A");
    nodus_witness_v2_shadow_after_commit(fx.w);   /* another call, on again */
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_STOPPED &&
          nodus_witness_v2_shadow_rows_scanned() == scanned_before &&
          log_rows(fx.w) == rows_before &&
          q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "D5: after A, with hf9_shadow = on again: never starts again, "
          "no row read, capture 1");
    /* a REAL restart: the SQLite file closed and opened again, the config
     * still on: the stored status (STOPPED) survives and decides */
    CHECK(fx_reopen(&fx) == 0, "D5: the database is reopened");
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_STOPPED &&
          nodus_witness_v2_shadow_rows_scanned() == scanned_before &&
          log_rows(fx.w) == rows_before &&
          q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "D5: after a restart with hf9_shadow = on: still STOPPED, no row "
          "read, no log row, capture 1");
    CHECK(nodus_witness_v2_shadow_seed(fx.w) == -1 &&
          q1(fx.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "D5: a re-seed after the restart is refused, capture unchanged");
    (void)seed_h;

    /* D6: a node that never ran the shadow reaches the same roots */
    {
        uint8_t ra[8][64], rb[8][64], ga1[64], ga[64], gb1[64], gb[64];
        CHECK(fx_open(&twin, "twin", HA) == 0, "the twin chain (no shadow)");
        for (uint64_t h = 1; h <= HA; h++)
            CHECK(apply_block(&twin, h) == 0, "twin block");
        CHECK(stored_roots(fx.w, ra) == 0 && stored_roots(twin.w, rb) == 0 &&
              memcmp(ra, rb, sizeof(ra)) == 0,
              "D6: the generation-6 leg roots equal a node that never ran "
              "the shadow");
        CHECK(block_global(fx.w, HA - 1u, ga1) == 0 &&
              block_global(fx.w, HA, ga) == 0 &&
              block_global(twin.w, HA - 1u, gb1) == 0 &&
              block_global(twin.w, HA, gb) == 0 &&
              memcmp(ga1, gb1, 64) == 0 && memcmp(ga, gb, 64) == 0,
              "D6: ... and the global roots at A-1 and A");
        /* seeding at generation 6 with NO status row (the existing-row
         * refusal cannot mask the generation refusal here) */
        twin.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
        CHECK(committed_gen(twin.w) == NODUS_RT_GEN_TRIE &&
              shadow_status(twin.w) == NODUS_V2_SHADOW_NONE,
              "D7: the twin is at generation 6 and has no shadow status row");
        CHECK(nodus_witness_v2_shadow_seed(twin.w) == -1,
              "D7: seeding at generation 6 is refused");
        nodus_witness_v2_shadow_after_commit(twin.w);
        CHECK(shadow_status(twin.w) == NODUS_V2_SHADOW_NONE &&
              table_exists(twin.w->db, "v2_trie_shadow_log") == 0 &&
              table_exists(twin.w->db, "v2_trie_shadow_rows") == 0 &&
              q1(twin.w->db, "SELECT capture FROM v2_trie_state") == 1,
              "D7: ... nothing was written (no status row, no shadow table), "
              "and the hook does not seed at generation 6 either; capture "
              "unchanged");
        fx_close(&twin);
    }
    fx_close(&fx);
    return 0;
}

/* F. catch-up on the chain; a row change picked up by the pass */
static int t_chain_catch_up(void) {
    fixture_t fx;
    uint8_t before[8][64], after[8][64];
    CHECK(fx_open(&fx, "catch", 0) == 0, "a generation-5 chain, no vote");
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    for (uint64_t h = 1; h <= H5 - 1u; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    /* the node's consensus reactor: live (wait_sync false) while it seeds */
    cmt_conr_t *conr = calloc(1, sizeof(*conr));
    CHECK(conr != NULL, "alloc");
    conr->wait_sync = false;
    fx.w->cmt_conr = conr;
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING &&
          log_rows(fx.w) == 1, "F0: seeded at H5-1");
    for (int leg = 1; leg <= 8; leg++)
        CHECK(nodus_witness_v2_trie_shadow_leg_root(fx.w, leg, before[leg - 1])
              == 0, "F0: roots");
    /* BLOCK SYNC (operator 2026-11-05, "canli zincir"): the reactor waits
     * for block sync, two blocks apply and the hook is called after each,
     * then a change - the shadow does NOTHING (no pass, no row read, no log
     * row, no root moved) */
    conr->wait_sync = true;
    {
        const uint64_t scanned = nodus_witness_v2_shadow_rows_scanned();
        uint8_t mid[8][64];
        CHECK(apply_block(&fx, H5) == 0, "F1: block sync block 1");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(apply_block(&fx, H5 + 1u) == 0, "F1: block sync block 2");
        CHECK(add_token_row(fx.w, 0xA7) == 0, "F1: a row change");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(nodus_witness_v2_shadow_pass(fx.w) == 0, "F1: the pass call");
        for (int leg = 1; leg <= 8; leg++)
            CHECK(nodus_witness_v2_trie_shadow_leg_root(fx.w, leg, mid[leg - 1])
                  == 0, "F1: roots");
        CHECK(log_rows(fx.w) == 1 &&
              nodus_witness_v2_shadow_rows_scanned() == scanned &&
              memcmp(before, mid, sizeof(before)) == 0,
              "F1: while block-syncing no pass ran: no log row, no row read, "
              "no shadow root moved");
    }
    /* a REAL restart (fresh witness context, file closed and reopened)
     * while still syncing: still nothing */
    CHECK(fx_reopen(&fx) == 0, "F1: restart");
    fx.w->cmt_conr = conr;
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(log_rows(fx.w) == 1, "F1: after the restart, still syncing: nothing");
    /* the switch to consensus: the FIRST call covers every missed change in
     * one step */
    conr->wait_sync = false;
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(log_rows(fx.w) == 2, "F1: ONE new log row after the switch");
    {
        nodus_v2_shadow_log_t row;
        CHECK(nodus_witness_v2_shadow_log_read(fx.w, H5 + 1u, &row) == 1 &&
              nodus_witness_v2_shadow_log_read(fx.w, H5, &row) == 0,
              "F1: at the tip, none for the missed height");
        CHECK(shadow_rows_match(fx.w) == 0,
              "F1: the row copy v2_trie_shadow_rows equals the selected rows "
              "(keys and leaf hashes, every leg) after the catch-up pass - "
              "including the new token row");
        CHECK(log_row_matches(fx.w, H5 + 1u) == 0,
              "F1: the logged legs, CORE / STOR / SYS and GLOBAL v2' equal "
              "the expected values (all 64 bytes) after the committed change");
    }
    /* the full rebuild writes nodes to the CONSENSUS v2_trie_nodes: inside a
     * transaction that is rolled back, so the pre-edge chain keeps it empty */
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "F1: begin");
    for (int leg = 1; leg <= 8; leg++) {
        uint8_t inc[64], full[64];
        CHECK(nodus_witness_v2_trie_shadow_leg_root(fx.w, leg, after[leg - 1])
              == 0, "F1: roots");
        CHECK(nodus_witness_v2_trie_build_leg(fx.w, leg, inc, full) == 0 &&
              memcmp(after[leg - 1], full, 64) == 0,
              "F1: every leg equals the full rebuild of the rows");
    }
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_nodes") == 0,
          "F1: the rebuild was rolled back, v2_trie_nodes is still empty");
    CHECK(memcmp(before[1], after[1], 64) != 0,
          "F1: control - the tokens leg moved (the change was caught up)");
    CHECK(memcmp(before[0], after[0], 64) == 0,
          "F1: ... a leg without a change did not");
    fx.w->cmt_conr = NULL;
    free(conr);
    fx_close(&fx);
    return 0;
}

/* H. real failures of the job: an UNREADABLE generation and a transaction
 * that cannot begin are faults (never "inactive" or "skipped"), and a
 * FAULTED status that cannot be written is latched (no flag needed). */

/* an all-zero runtime entry: used as the witness's table override it
 * matches no registered tuple, so nodus_witness_v2_runtime_for fails */
static nodus_domain_runtime_t g_no_runtime;

static int open_second(const char *path, sqlite3 **db2) {
    if (sqlite3_open_v2(path, db2, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return -1;
    return run_sql(*db2, "BEGIN IMMEDIATE");   /* holds the write lock */
}

static int t_chain_failures(void) {
    fixture_t fx;
    char path[512];
    sqlite3 *db2 = NULL;

    /* H1 / H2: the generation cannot be read */
    CHECK(fx_open(&fx, "unread", 0) == 0, "H: chain");
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    for (uint64_t h = 1; h <= H5 - 1u; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    fx.w->v2_runtime_table = &g_no_runtime;
    fx.w->v2_runtime_table_n = 1;
    CHECK(committed_gen(fx.w) == 0, "H1: control - the generation reads as "
          "unresolvable with the override");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(nodus_witness_v2_shadow_pass(fx.w) == -1,
          "H1: the pass reports the unreadable generation as a failure (-1), "
          "which idle (0) would not");
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_NONE &&
          table_exists(fx.w->db, "v2_trie_shadow_log") == 0 &&
          fx.w->hf9_shadow_latched == 0,
          "H1: never seeded and unreadable: nothing written, no status, no "
          "latch (no run to invalidate)");
    fx.w->v2_runtime_table = NULL;
    fx.w->v2_runtime_table_n = 0;
    CHECK(nodus_witness_v2_shadow_pass(fx.w) == 0,
          "H1: control - readable and never seeded, the pass is idle (0)");
    fx.w->v2_runtime_table = &g_no_runtime;
    fx.w->v2_runtime_table_n = 1;
    fx.w->v2_runtime_table = NULL;
    fx.w->v2_runtime_table_n = 0;
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING,
          "H2: readable again - seeded");
    CHECK(apply_block(&fx, H5) == 0, "block");
    fx.w->v2_runtime_table = &g_no_runtime;
    fx.w->v2_runtime_table_n = 1;
    nodus_witness_v2_shadow_after_commit(fx.w);
    fx.w->v2_runtime_table = NULL;
    fx.w->v2_runtime_table_n = 0;
    CHECK(q1(fx.w->db, "SELECT status FROM v2_trie_shadow_state") ==
              NODUS_V2_SHADOW_FAULTED && log_rows(fx.w) == 1,
          "H2: a RUNNING shadow whose generation is unreadable is FAULTED "
          "(stored), not idle");
    fx_close(&fx);

    /* H3: seeding cannot begin its transaction (another connection holds
     * the write lock) */
    CHECK(fx_open(&fx, "lockseed", 0) == 0, "H: chain");
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    for (uint64_t h = 1; h <= H5 - 1u; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    {
        const char *fn = sqlite3_db_filename(fx.w->db, "main");
        CHECK(fn && strlen(fn) < sizeof(path), "path");
        snprintf(path, sizeof(path), "%s", fn);
    }
    sqlite3_busy_timeout(fx.w->db, 0);
    CHECK(open_second(path, &db2) == 0, "H3: a second connection holds the "
          "write lock");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(fx.w->hf9_shadow_latched == 1 &&
          shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED,
          "H3: the seeding that cannot begin is a FAULT, and since the lock "
          "also refuses the FAULTED write it is latched and reported "
          "FAULTED");
    CHECK(run_sql(db2, "ROLLBACK") == 0, "H3: release");
    sqlite3_close(db2);
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED &&
          table_exists(fx.w->db, "v2_trie_shadow_log") == 0 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_state") == 0,
          "H3: the latch holds after the lock is gone: no step, no seeding, "
          "no stored row");
    fx_close(&fx);

    /* H4: a pass cannot begin; the stored RUNNING row cannot be replaced */
    CHECK(fx_open(&fx, "lockpass", 0) == 0, "H: chain");
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    for (uint64_t h = 1; h <= H5 - 1u; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING, "H4: seeded");
    {
        const char *fn = sqlite3_db_filename(fx.w->db, "main");
        CHECK(fn && strlen(fn) < sizeof(path), "path");
        snprintf(path, sizeof(path), "%s", fn);
    }
    CHECK(apply_block(&fx, H5) == 0, "block");
    sqlite3_busy_timeout(fx.w->db, 0);
    CHECK(open_second(path, &db2) == 0, "H4: a second connection holds the "
          "write lock");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(run_sql(db2, "ROLLBACK") == 0, "H4: release");
    sqlite3_close(db2);
    CHECK(q1(fx.w->db, "SELECT status FROM v2_trie_shadow_state") ==
              NODUS_V2_SHADOW_RUNNING,
          "H4: control - the stored row still says RUNNING (the FAULTED "
          "write was refused)");
    CHECK(fx.w->hf9_shadow_latched == 1 &&
          shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED,
          "H4: ... but the shadow reports FAULTED (the latch)");
    {
        const int rows = log_rows(fx.w);
        const uint64_t scanned = nodus_witness_v2_shadow_rows_scanned();
        CHECK(apply_block(&fx, H5 + 1u) == 0, "block");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(log_rows(fx.w) == rows &&
              nodus_witness_v2_shadow_rows_scanned() == scanned,
              "H4: the invalidated evidence does not resume: no pass, no "
              "row read, no log row");
    }
    fx_close(&fx);

    /* H5: the STATUS itself is unreadable (its table is renamed away) while
     * a run exists: the run is invalidated - the FAULTED write fails too, so
     * the latch holds and the status reads FAULTED once the table is back */
    CHECK(fx_open(&fx, "statusread", 0) == 0, "H: chain");
    fx.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    for (uint64_t h = 1; h <= H5 - 1u; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING, "H5: seeded");
    CHECK(apply_block(&fx, H5) == 0, "block");
    CHECK(run_sql(fx.w->db, "ALTER TABLE v2_trie_shadow_state RENAME TO "
                            "v2_trie_shadow_state_away") == 0,
          "H5: the status table becomes unreadable");
    nodus_witness_v2_shadow_after_commit(fx.w);
    CHECK(fx.w->hf9_shadow_latched == 1,
          "H5: an unreadable status invalidates the run (latched: the "
          "FAULTED write cannot succeed either)");
    CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED,
          "H5: while the status table is STILL unreadable the shadow reports "
          "FAULTED (the accessor consults the latch before reading)");
    CHECK(run_sql(fx.w->db, "ALTER TABLE v2_trie_shadow_state_away RENAME TO "
                            "v2_trie_shadow_state") == 0,
          "H5: the status table is readable again");
    CHECK(q1(fx.w->db, "SELECT status FROM v2_trie_shadow_state") ==
              NODUS_V2_SHADOW_RUNNING &&
          shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED,
          "H5: the stored row still says RUNNING, the shadow reports FAULTED");
    {
        const int rows = log_rows(fx.w);
        CHECK(apply_block(&fx, H5 + 1u) == 0, "block");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(log_rows(fx.w) == rows,
              "H5: the run does not resume once reads recover");
    }
    fx_close(&fx);
    return 0;
}

#ifdef QGP_FAULT_INJECT
/* E. faults on the chain */
static int e_case(int point, int mode, const char *tag) {
    fixture_t fx, twin;
    uint8_t dc0[64], dc1[64], ds0[64], ds1[64], g_a[64], g_b[64];
    memset(ds0, 0, sizeof(ds0));
    memset(ds1, 0, sizeof(ds1));
    CHECK(fx_open(&fx, tag, 0) == 0 && fx_open(&twin, "etwin", 0) == 0,
          "E0: chain and twin");
    fx.w->config.hf9_shadow = mode;
    for (uint64_t h = 1; h <= H5 - 1u; h++) {
        CHECK(apply_block(&fx, h) == 0 && apply_block(&twin, h) == 0,
              "block");
    }
    if (point == 5) {
        /* the seeding itself faults */
        CHECK(tabs_digest(fx.w->db, CONSENSUS_TABS, N_CONSENSUS_TABS, dc0)
              == 0, "E: digest");
        int hits5 = nodus_witness_v2_shadow_test_hits();
        CHECK(nodus_witness_v2_shadow_test_fault(5) == 0, "E: arm");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(nodus_witness_v2_shadow_test_hits() == hits5 + 1,
              "E: the seeding fault point was reached (false-pass guard)");
        CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED,
              "E5: status FAULTED");
        CHECK(table_exists(fx.w->db, "v2_trie_shadow_log") == 0 &&
              table_exists(fx.w->db, "v2_trie_shadow_rows") == 0,
              "E5: the seeding was rolled back - no shadow table at all");
        CHECK(tabs_digest(fx.w->db, CONSENSUS_TABS, N_CONSENSUS_TABS, dc1)
              == 0 && memcmp(dc0, dc1, 64) == 0,
              "E5: the committed tables are byte-identical");
    } else {
        int hits0;
        nodus_witness_v2_shadow_after_commit(fx.w);        /* seeds */
        CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_RUNNING &&
              log_rows(fx.w) == 1, "E0: seeded");
        CHECK(apply_block(&fx, H5) == 0 && apply_block(&twin, H5) == 0,
              "E: the next block");
        CHECK(add_token_row(fx.w, 0xB1) == 0, "E: a row change after the "
              "committed block");
        CHECK(tabs_digest(fx.w->db, CONSENSUS_TABS, N_CONSENSUS_TABS, dc0)
              == 0 &&
              tabs_digest(fx.w->db, SHADOW_DATA_TABS, N_SHADOW_DATA_TABS,
                          ds0) == 0,
              "E: digests before the hook");
        hits0 = nodus_witness_v2_shadow_test_hits();
        CHECK(nodus_witness_v2_shadow_test_fault(point) == 0, "E: arm");
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(nodus_witness_v2_shadow_test_hits() == hits0 + 1,
              "E: the injection point was reached (false-pass guard)");
        CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED,
              "E: status FAULTED");
        CHECK(tabs_digest(fx.w->db, CONSENSUS_TABS, N_CONSENSUS_TABS, dc1)
              == 0 && memcmp(dc0, dc1, 64) == 0,
              "E: the committed tables are byte-identical to before the hook");
        /* the shadow's own data tables: the faulted pass was rolled back
         * (only the status row changed) */
        CHECK(tabs_digest(fx.w->db, SHADOW_DATA_TABS, N_SHADOW_DATA_TABS,
                          ds1) == 0 && memcmp(ds0, ds1, 64) == 0 &&
              log_rows(fx.w) == 1,
              "E: the faulted pass left the shadow nodes, roots, row copy "
              "and log byte-identical (rolled back)");
    }
    /* later hook calls write nothing; the next block commits like the twin's */
    {
        int rows_now = log_rows(fx.w);
        uint64_t s_now = nodus_witness_v2_shadow_rows_scanned();
        nodus_witness_v2_shadow_after_commit(fx.w);
        CHECK(shadow_status(fx.w) == NODUS_V2_SHADOW_FAULTED &&
              log_rows(fx.w) == rows_now &&
              nodus_witness_v2_shadow_rows_scanned() == s_now,
              "E: faulted stays faulted - no further pass");
    }
    if (point != 5) {
        /* remove the change the test made, so the next block's guard is
         * quiet, then the block commits exactly like the twin's */
        CHECK(run_sql(fx.w->db, "DELETE FROM tokens WHERE token_id = "
                                "CAST(zeroblob(63)||x'b1' AS BLOB)") == 0,
              "E: undo the raw change");
    }
    {
        uint64_t next = point == 5 ? H5 : H5 + 1u;
        CHECK(apply_block(&fx, next) == 0, "E: the next block commits");
        CHECK(apply_block(&twin, next) == 0, "twin block");
        CHECK(block_global(fx.w, next, g_a) == 0 &&
              block_global(twin.w, next, g_b) == 0 &&
              memcmp(g_a, g_b, 64) == 0,
              "E: ... and its global root equals the twin's (the shadow "
              "cannot move consensus)");
    }
    fx_close(&twin);
    fx_close(&fx);
    return 0;
}

static int t_chain_faults(void) {
    CHECK(e_case(5, NODUS_HF9_SHADOW_ON, "e5") == 0, "E: point 5 (seeding)");
    CHECK(e_case(2, NODUS_HF9_SHADOW_ON, "e2") == 0, "E: point 2 (update)");
    CHECK(e_case(3, NODUS_HF9_SHADOW_ON, "e3") == 0, "E: point 3 (log)");
    CHECK(e_case(4, NODUS_HF9_SHADOW_FULL, "e4") == 0,
          "E: point 4 (full check, mode full)");
    return 0;
}
#endif

/* ══ G. the dnac_hf9_shadow reply decoder (client side) ═════════════════ */

static void fill_root(uint8_t r[64], int idx) {
    for (int i = 0; i < 64; i++)
        r[i] = (uint8_t)(idx * 37 + i * 11 + (i >> 3) * 5 + 1);
}

/* A hand-encoded reply {"t","y":"r","q","r": {...}} (no network). `skip`
 * drops one key, `dup` emits that key a second time, `short_leg` makes "l1"
 * a 63-byte string, `extra` adds "l1" to a not-found reply. */
static size_t build_reply(uint8_t *buf, size_t cap, int found,
                          const char *skip, const char *dup, int short_leg,
                          int extra) {
    static const char *const names[15] = {
        "st", "found", "h", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8",
        "core", "stor", "sys", "glob"
    };
    const char *emit[20];
    size_t n = 0;
    for (size_t i = 0; i < (found ? 15u : 2u); i++)
        if (!skip || strcmp(skip, names[i]) != 0) emit[n++] = names[i];
    if (!found && extra) emit[n++] = "l1";
    if (dup) emit[n++] = dup;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y");  cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, "dnac_hf9_shadow");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, n);
    for (size_t i = 0; i < n; i++) {
        cbor_encode_cstr(&enc, emit[i]);
        if (strcmp(emit[i], "st") == 0) cbor_encode_uint(&enc, 1);
        else if (strcmp(emit[i], "found") == 0) cbor_encode_bool(&enc, found);
        else if (strcmp(emit[i], "h") == 0) cbor_encode_uint(&enc, 7);
        else {
            uint8_t root[64];
            int idx = 0;
            for (int k = 0; k < 15; k++)
                if (strcmp(emit[i], names[k]) == 0) idx = k;
            fill_root(root, idx);
            cbor_encode_bstr(&enc, root,
                             short_leg && strcmp(emit[i], "l1") == 0 ? 63u
                                                                     : 64u);
        }
    }
    return cbor_encoder_len(&enc);
}

/* every field of a reply gets its OWN 64 distinct, non-uniform bytes, so a
 * swapped or shifted field decodes to a different value */
static int root_is(const uint8_t got[64], int idx) {
    uint8_t want[64];
    fill_root(want, idx);
    return memcmp(got, want, 64) == 0;
}

static int t_decoder(void) {
    uint8_t buf[2048];
    nodus_dnac_hf9_shadow_t r;
    size_t len;
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    uint8_t req[256];
    size_t rlen = 0;

    len = build_reply(buf, sizeof(buf), 1, NULL, NULL, 0, 0);
    CHECK(len > 0 && nodus_dnac_hf9_shadow_decode(buf, len, &r) == 0 &&
          r.found && r.status == 1 && r.height == 7,
          "G1: a found reply with all fifteen keys decodes");
    for (int l = 0; l < 8; l++)
        CHECK(root_is(r.leg[l], 3 + l), "G1: leg l1..l8 each carries its own "
              "64 bytes (indices 3..10)");
    CHECK(root_is(r.core, 11) && root_is(r.stor, 12) && root_is(r.sys, 13) &&
          root_is(r.glob, 14),
          "G1: core / stor / sys / glob each carry their own 64 bytes - a "
          "swapped destination would fail");
    len = build_reply(buf, sizeof(buf), 0, NULL, NULL, 0, 0);
    CHECK(len > 0 && nodus_dnac_hf9_shadow_decode(buf, len, &r) == 0 &&
          !r.found && r.status == 1 && r.height == 0,
          "G2: a not-found reply with only st and found decodes");
    len = build_reply(buf, sizeof(buf), 1, NULL, NULL, 1, 0);
    CHECK(len > 0 && nodus_dnac_hf9_shadow_decode(buf, len, &r) == -1,
          "G3: a 63-byte root is refused");
    len = build_reply(buf, sizeof(buf), 1, NULL, "core", 0, 0);
    CHECK(len > 0 && nodus_dnac_hf9_shadow_decode(buf, len, &r) == -1,
          "G4: a duplicate key is refused");
    len = build_reply(buf, sizeof(buf), 1, "glob", NULL, 0, 0);
    CHECK(len > 0 && nodus_dnac_hf9_shadow_decode(buf, len, &r) == -1,
          "G5: found with one key missing is refused");
    len = build_reply(buf, sizeof(buf), 0, NULL, NULL, 0, 1);
    CHECK(len > 0 && nodus_dnac_hf9_shadow_decode(buf, len, &r) == -1,
          "G6: not found with an extra root is refused");
    len = build_reply(buf, sizeof(buf), 1, NULL, NULL, 0, 0);
    CHECK(nodus_dnac_hf9_shadow_decode(buf, len - 1, &r) == -1,
          "G7: a truncated reply is refused");
    CHECK(r.found == false && r.height == 0, "G7: the output is zeroed on "
          "a refusal");
    memset(token, 0x11, sizeof(token));
    CHECK(nodus_dnac_hf9_shadow_request_encode(5, token, 9, req, sizeof(req),
                                               &rlen) == 0 && rlen > 0 &&
          nodus_dnac_hf9_shadow_request_encode(5, token, 9, req, 8, &rlen)
              == -1, "G8: the request encodes, and a too-small buffer is "
          "refused");
    return 0;
}

int main(void) {
    int rc = 0;
    if (!rc) rc = t_decoder();
    if (!rc) rc = t_equality_and_isolation();
#ifdef QGP_FAULT_INJECT
    if (!rc) rc = t_faults_within_pass();
#endif
    if (!rc) rc = t_chain_window();
    if (!rc) rc = t_chain_catch_up();
    if (!rc) rc = t_chain_failures();
#ifdef QGP_FAULT_INJECT
    if (!rc) rc = t_chain_faults();
#endif
    if (rc) {
        fprintf(stderr, "test_hf9_shadow: FAILED\n");
        return 1;
    }
    printf("test_hf9_shadow: all cases passed, %d checks%s\n", g_checks,
#ifdef QGP_FAULT_INJECT
           " (incl. the QGP_FAULT_INJECT cases C and E)"
#else
           " (the QGP_FAULT_INJECT cases C and E not compiled)"
#endif
           );
    return 0;
}
