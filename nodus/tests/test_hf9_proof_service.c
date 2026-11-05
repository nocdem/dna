/**
 * @file nodus/tests/test_hf9_proof_service.c
 * @brief HF-9 T-11 (WP6): the `dnac_state_proof` service - batch proof and
 *        composition proof to the committed AppHash, the reader threads, the
 *        node-wide admission, and the per-leg worst-case cost measurement.
 *
 * Plan docs/plans/approved/2026-11-04-hf9.md §10.2, §10.3, §10.4, §12 row
 * T-11, §17 (the numeric limits are measured here and then the operator's),
 * Kurultay 55 A10 - A13.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *  A. Request decoding (nodus_state_proof_request_decode, through the client
 *     encoder and hand-made frames): a valid request; leg 0 / 9, a missing or
 *     repeated "leg", missing keys, 0 keys, 129 keys, a repeated key, a key
 *     of a length its leg cannot hold (leg 1: 63; leg 4: 2 and 37; leg 6: 7)
 *     are NODUS_ERR_PROTOCOL_ERROR; leg 4 with 3 and 36 bytes, leg 6 with 8
 *     and an unknown key are accepted.
 *  B. On a real generation-6 chain (the edge ladder of test_hf9_edge.c, the
 *     fixture of test_hf9_shadow.c) with every one of the eight legs
 *     populated and flushed through the production flush
 *     (nodus_witness_v2_trie_flush): for each leg 1..8 a request of present
 *     and absent keys, answered by nodus_state_proof_build on a private
 *     read-only context, decoded by the client decoder, then VERIFIED from the
 *     outside: the nodes and results against the response's leg root
 *     (evm_trie_proof_verify_batch), every present value equal to the leaf
 *     value the PRODUCTION row reader gives (nodus_witness_v2_trie_scan_leg),
 *     and the composition chain (dna_v2_state_proof_cp_verify) from the leg
 *     root to the tip row's global_root - the AppHash of header h + 1, read
 *     here from v2_blocks, not from the response. The response's "h" is the
 *     tip. Damage to one composition byte, one node byte, a result and the
 *     leg root is refused. An empty leg (claims, never populated) proves
 *     absence with an empty bundle and the same composition chain. A chain
 *     committed at generation 5 answers NODUS_ERR_NOT_FOUND.
 *  C. The service (nodus_state_proof_service_*): not enabled (zero readers or
 *     zero rate) refuses every request RATE_LIMITED with no read; an enabled
 *     service answers a request with the byte-identical frame the direct
 *     build gives (one snapshot, deterministic), built on a thread that is
 *     not the calling (loop) thread; with every reader busy (answers not yet
 *     polled) the next request is RATE_LIMITED; a flood of 1000 requests at
 *     one instant against a node-wide rate of 2 hands off exactly 2, refuses
 *     998 RATE_LIMITED, and the readers start exactly 2 builds (counted):
 *     refused requests reach no store read, and the loop thread only decoded,
 *     admitted and handed off (loop_builds = 0); a flood of 1000 malformed
 *     requests starts no build; the limiter admits again one second later;
 *     freeing the service with an undelivered answer hands the tag back
 *     dropped.
 *  D. The worst-case cost per leg (printed, not asserted - see below).
 *
 * ── THE COST MEASUREMENT (plan §10.4, §17) ─────────────────────────────
 *  For two table sizes, each on a fresh generation-6 chain:
 *    live   utxo 4316, tokens 1, claims 1, names 13, registry 5, segments 30,
 *           validator-set snapshots 735, attendance 733 (plan §4.2, EU-5
 *           height 528234 and the Kurultay facts);
 *    grown  utxo 100000, tokens 20000, claims 20000, names 20000, registry
 *           1000, segments 10000, snapshots 10000, attendance 10000, and 20000
 *           extra chain_config_history rows (a labelled fixture row of a
 *           parameter no rule reads; DF-5: the root scan reads every row).
 *  For each leg 1..8 one request of 128 keys (the worst case of D26), as many
 *  present rows as the table holds up to 128, spread evenly over the key
 *  order so the paths diverge, the rest absent. Printed per leg: rows in the
 *  leg, keys requested / present, the trie nodes loaded, nodes in the
 *  bundle, the frame bytes, and the wall time (CLOCK_MONOTONIC, in this TEST
 *  only; the service itself reads no clock for the build) of the build
 *  (three runs, the first one cold) and of the sibling-leg load alone
 *  (nodus_witness_proof_legs_load, which includes the chain_config_history
 *  scan). Lines start with "COST ". These numbers are input for the
 *  operator's limits (rate, reader count, per-request work bound); nothing
 *  here chooses them.
 *  HOW MAIN RUNS IT: build the target, run `./test_hf9_proof_service` once
 *  and read the "COST " lines; it needs no argument and no environment. The
 *  grown fixture inserts about 190000 rows and flushes them through the
 *  production trie path: expect minutes, not seconds.
 *
 * ── FLAGS / ENVIRONMENT ────────────────────────────────────────────────
 *  register_witness_test (NODUS_WITNESS_INTERNAL_API); EVM-only (the trie
 *  module and the proof service). No compile flag, no environment. The
 *  numeric limits used by the tests (readers 2 / 4, rates 1000 / 2) are the
 *  TEST's own and say nothing about production: no production code enables
 *  the service.
 *
 * ── LEAVES BEHIND ──────────────────────────────────────────────────────
 *  /tmp/test_hf9_proof_service_*_XXXXXX directories, removed at exit (a
 *  crash leaves them).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ────────────────────────────────────
 *  - FIXTURE CONSISTENCY: the populated rows are written by SQL and flushed
 *    by the production flush, then the SYSTEM and CORE heads' state roots and
 *    the tip row's global_root are REWRITTEN here to the composed values (a
 *    labelled test fixture: the proof service reads the committed tip, and
 *    the rows were not produced by blocks). So B proves the service and the
 *    verifiers agree on a consistent snapshot; it does not prove that a
 *    block-produced AppHash equals it (WP3's T-5 / T-6 and the harness do).
 *  - The expected leaf values come from the production row reader
 *    (scan_leg), the expected AppHash from the tip row: both independent of
 *    the proof code, but neither independent of the SQL fixture.
 *  - The asynchronous waits poll for the readers' answers up to a bound and
 *    then ASSERT (no retry masks a missing answer).
 *  - The binding of the connection (slot + generation) and the send are the
 *    glue of nodus_witness_state_proof_handle / _poll, which needs a live
 *    transport and is NOT exercised here (harness / WP7).
 *  - Timing numbers are not assertions; a run that prints COST lines proves
 *    only that the builds succeeded.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_trie.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_state_proof.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "protocol/nodus_cbor.h"

#include "evm/trie/evm_trie_proof.h"
#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_genesis_fixture.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

/* the ladder of test_hf9_edge.c: generation 6 from block A = 14, edge 13 */
#define H9    3u
#define HE    5u
#define HS    8u
#define H5   11u
#define HA   14u

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

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ══ the chain fixture (test_hf9_shadow.c: the ladder of test_hf9_edge.c) ═ */

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

/* HF-2 on from 1, the generation ladder; generation 6 voted for block HA
 * (the edge is block HA - 1). An S20 chain, engine genesis. */
static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB - ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf9_proof_service_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x5a, sizeof(fx->chain16));
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
               (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, H5, 15) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_TRIE,
               (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, HA, 16) != 0)
        return -1;
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
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

static const char *db_path(fixture_t *fx) {
    return sqlite3_db_filename(fx->w->db, "main");
}

/* ══ rows: prepared-statement writers (the shapes of test_hf9_trie_legs.c) ═ */

static void key64(char tag, uint32_t i, uint8_t out[64]) {
    uint8_t b[5] = { (uint8_t)tag, (uint8_t)(i >> 24), (uint8_t)(i >> 16),
                     (uint8_t)(i >> 8), (uint8_t)i };
    if (qgp_sha3_512(b, sizeof(b), out) != 0) memset(out, 0, 64);
}

static void be64(uint64_t v, uint8_t o[8]) {
    for (int i = 7; i >= 0; i--) { o[i] = (uint8_t)v; v >>= 8; }
}

static int bind_blob(sqlite3_stmt *st, int idx, const uint8_t *p, size_t n) {
    return sqlite3_bind_blob(st, idx, p, (int)n, SQLITE_TRANSIENT);
}

/* n rows of leg `leg` (the rows of THIS test: epoch-like keys start far above
 * any genesis row). 0 / -1. */
static int insert_rows(sqlite3 *db, int leg, uint32_t n) {
    static const char *const SQL[9] = {
        NULL,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, tx_hash, "
        "output_index, block_height, created_at, unlock_block, domain_id) "
        "VALUES (?1, ?2, ?3, zeroblob(64), ?4, 1, 5, 0, 0, 1)",
        "INSERT INTO tokens (token_id, name, symbol, decimals, supply, "
        "creator_fp, flags, block_height, timestamp) VALUES (?1, ?2, ?3, 8, "
        "1000, ?4, 1, 7, 99)",
        "INSERT INTO v2_claims_spent (nullifier, manifest_hash, "
        "target_domain_id, target_asset_ref, leaf_index, amount, "
        "claimed_height, output_id) VALUES (?1, ?2, 1, zeroblob(64), 2, 50, "
        "9, ?3)",
        "INSERT INTO v2_names (name, owner, registered_height) VALUES "
        "(CAST(?1 AS BLOB), ?2, 11)",
        "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, bond, "
        "status, registered_height, exit_height, fail_streak, grace_until) "
        "VALUES (?1, ?2, zeroblob(64), ?3, 1, 3, 0, 0, 0)",
        "INSERT INTO v2_storage_segments (k, root, published_height) VALUES "
        "(?1, ?2, ?3)",
        "INSERT INTO validator_set_snapshots (epoch_start, active_count, "
        "snapshot_hash, snapshot_blob, created_at_height) VALUES (?1, 1, ?2, "
        "x'00', 1)",
        "INSERT INTO v2_attendance_epoch (epoch_start, digest) VALUES (?1, ?2)"
    };
    sqlite3_stmt *st = NULL;
    uint8_t pk[DNAC_PUBKEY_SIZE];
    if (sqlite3_prepare_v2(db, SQL[leg], -1, &st, NULL) != SQLITE_OK)
        return -1;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t k[64], k2[64], k3[64];
        char txt[48], txt2[48], txt3[48];
        int ok = 1;
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        switch (leg) {
        case 1:
            key64('U', i, k); key64('H', i, k2);
            snprintf(txt, sizeof(txt), "own%u", i);
            ok = bind_blob(st, 1, k, 64) == SQLITE_OK &&
                 sqlite3_bind_text(st, 2, txt, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                 sqlite3_bind_int64(st, 3, 100 + (sqlite3_int64)i) == SQLITE_OK &&
                 bind_blob(st, 4, k2, 64) == SQLITE_OK;
            break;
        case 2:
            key64('T', i, k); key64('F', i, k2);
            snprintf(txt, sizeof(txt), "tok%u", i);
            snprintf(txt2, sizeof(txt2), "T%u", i);
            snprintf(txt3, sizeof(txt3), "fp%u", i);
            ok = bind_blob(st, 1, k, 64) == SQLITE_OK &&
                 sqlite3_bind_text(st, 2, txt, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                 sqlite3_bind_text(st, 3, txt2, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                 sqlite3_bind_text(st, 4, txt3, -1, SQLITE_TRANSIENT) == SQLITE_OK;
            break;
        case 3:
            key64('C', i, k); key64('M', i, k2); key64('O', i, k3);
            ok = bind_blob(st, 1, k, 64) == SQLITE_OK &&
                 bind_blob(st, 2, k2, 64) == SQLITE_OK &&
                 bind_blob(st, 3, k3, 64) == SQLITE_OK;
            break;
        case 4:
            key64('W', i, k);
            snprintf(txt, sizeof(txt), "nm%07u", i);
            ok = sqlite3_bind_text(st, 1, txt, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                 bind_blob(st, 2, k, 64) == SQLITE_OK;
            break;
        case 5:
            memset(pk, 0x11, sizeof(pk));
            pk[0] = (uint8_t)(i >> 24); pk[1] = (uint8_t)(i >> 16);
            pk[2] = (uint8_t)(i >> 8);  pk[3] = (uint8_t)i;
            ok = qgp_sha3_512(pk, sizeof(pk), k) == 0 &&
                 bind_blob(st, 1, k, 64) == SQLITE_OK &&
                 bind_blob(st, 2, pk, sizeof(pk)) == SQLITE_OK &&
                 sqlite3_bind_int64(st, 3, 5000 + (sqlite3_int64)i) == SQLITE_OK;
            break;
        case 6:
            key64('S', i, k);
            ok = sqlite3_bind_int64(st, 1, 1 + (sqlite3_int64)i) == SQLITE_OK &&
                 bind_blob(st, 2, k, 64) == SQLITE_OK &&
                 sqlite3_bind_int64(st, 3, 100 + (sqlite3_int64)i) == SQLITE_OK;
            break;
        case 7:
            key64('V', i, k);
            ok = sqlite3_bind_int64(st, 1, 720 * (1000 + (sqlite3_int64)i))
                     == SQLITE_OK && bind_blob(st, 2, k, 64) == SQLITE_OK;
            break;
        case 8:
            key64('A', i, k);
            ok = sqlite3_bind_int64(st, 1, 720 * (1000 + (sqlite3_int64)i))
                     == SQLITE_OK && bind_blob(st, 2, k, 64) == SQLITE_OK;
            break;
        }
        if (!ok || sqlite3_step(st) != SQLITE_DONE) {
            fprintf(stderr, "insert_rows: leg %d row %u failed: %s\n", leg, i,
                    sqlite3_errmsg(db));
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return 0;
}

/* The generation-6 chain, populated: the ladder to the edge block, `n[leg]`
 * rows in each leg (0 = leave the leg as the chain has it), flushed through
 * the production flush; then the fixture consistency (header comment). */
static int make_consistent(nodus_witness_t *w) {
    nodus_witness_proof_legs_t p;
    uint8_t core[64], sys[64];
    if (nodus_witness_proof_legs_load(w, &p) != 0) return -1;
    int ok = dna_v2_core_root_v4(p.core[0], p.core[1], p.core[2], p.core[3],
                                 p.core[4], p.core[5], p.core[6], core) == 0 &&
             dna_v2_system_root_v7(p.sys[0], p.sys[1], p.sys[2], p.sys[3],
                                   p.sys[4], p.sys[5], p.sys[6], p.sys[7],
                                   p.sys[8], p.sys[9], p.sys[10], p.sys[11],
                                   sys) == 0;
    nodus_witness_proof_legs_free(&p);
    if (!ok) return -1;
    const struct { uint32_t dom; const uint8_t *root; } up[2] = {
        { DNA_DOMAIN_SYSTEM, sys }, { DNA_DOMAIN_CORE, core } };
    for (int i = 0; i < 2; i++) {
        /* the 89-byte head: id(4) ‖ state root(64) ‖ ...; only bytes 4..67
         * change, patched here in C and written back whole */
        sqlite3_stmt *st = NULL;
        uint8_t head[DNA_V2_DOMHEAD_ENC_LEN];
        if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                "domain_id = ?1", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)up[i].dom);
        int good = sqlite3_step(st) == SQLITE_ROW &&
                   sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN;
        if (good) memcpy(head, sqlite3_column_blob(st, 0), sizeof(head));
        sqlite3_finalize(st);
        if (!good) return -1;
        memcpy(head + 4, up[i].root, 64);
        if (sqlite3_prepare_v2(w->db, "UPDATE v2_domain_heads SET head = ?1 "
                "WHERE domain_id = ?2", -1, &st, NULL) != SQLITE_OK)
            return -1;
        good = bind_blob(st, 1, head, sizeof(head)) == SQLITE_OK &&
               sqlite3_bind_int64(st, 2, (sqlite3_int64)up[i].dom)
                   == SQLITE_OK &&
               sqlite3_step(st) == SQLITE_DONE &&
               sqlite3_changes(w->db) == 1;
        sqlite3_finalize(st);
        if (!good) return -1;
    }
    if (nodus_witness_proof_legs_load(w, &p) != 0) return -1;
    sqlite3_stmt *st = NULL;
    int good = sqlite3_prepare_v2(w->db,
        "UPDATE v2_blocks SET global_root = ?1 WHERE global_height = "
        "(SELECT MAX(global_height) FROM v2_blocks)", -1, &st, NULL)
        == SQLITE_OK && bind_blob(st, 1, p.global_root, 64) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) == 1;
    sqlite3_finalize(st);
    nodus_witness_proof_legs_free(&p);
    return good ? 0 : -1;
}

static int build_chain(fixture_t *fx, const char *tag, const uint32_t n[9],
                       uint32_t extra_cc_rows) {
    if (fx_open(fx, tag) != 0) return -1;
    for (uint64_t h = 1; h <= HA - 1u; h++)
        if (apply_block(fx, h) != 0) return -1;
    if (committed_gen(fx->w) != NODUS_RT_GEN_TRIE) return -1;
    if (run_sql(fx->w->db, "BEGIN") != 0) return -1;
    for (int leg = 1; leg <= 8; leg++)
        if (n[leg] && insert_rows(fx->w->db, leg, n[leg]) != 0) return -1;
    for (uint32_t i = 0; i < extra_cc_rows; i++)
        if (cc_row(fx->w, 250, i, 1000000u + i, 1000u + i) != 0) return -1;
    if (nodus_witness_v2_trie_flush(fx->w) != 0 ||
        run_sql(fx->w->db, "COMMIT") != 0)
        return -1;
    return make_consistent(fx->w);
}

/* ══ the rows the production reader gives (the expected values) ═══════ */

typedef struct {
    size_t   n, cap;
    uint8_t (*key)[64];
    size_t  *klen;
    uint8_t (*val)[64];
} rows_t;

static int rows_cb(void *ctx, const uint8_t *key, size_t key_len,
                   const uint8_t val[64]) {
    rows_t *r = ctx;
    if (key_len == 0 || key_len > 64) return -1;
    if (r->n == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 1024;
        uint8_t (*nk)[64] = realloc(r->key, nc * sizeof(*nk));
        if (nk) r->key = nk;
        size_t *nl = realloc(r->klen, nc * sizeof(*nl));
        if (nl) r->klen = nl;
        uint8_t (*nv)[64] = realloc(r->val, nc * sizeof(*nv));
        if (nv) r->val = nv;
        if (!nk || !nl || !nv) return -1;
        r->cap = nc;
    }
    memcpy(r->key[r->n], key, key_len);
    r->klen[r->n] = key_len;
    memcpy(r->val[r->n], val, 64);
    r->n++;
    return 0;
}

static void rows_free(rows_t *r) {
    free(r->key); free(r->klen); free(r->val);
    memset(r, 0, sizeof(*r));
}

/* an ABSENT key of the right length for `leg` (j distinct) */
static size_t absent_key(int leg, uint32_t j, uint8_t out[64]) {
    memset(out, 0, 64);
    switch (leg) {
    case 1: case 2: case 3: case 5:
        key64('X', j, out);
        return 64;
    case 4:
        snprintf((char *)out, 64, "zz%06u", j);
        return 8;
    default:
        be64(9000000000ull + j, out);
        return 8;
    }
}

/* the request: up to `want_present` present rows spread evenly over the key
 * order, then absent keys up to `total` */
static void pick_keys(int leg, const rows_t *r, size_t want_present,
                      size_t total, nodus_state_proof_req_t *req,
                      size_t *n_present) {
    memset(req, 0, sizeof(*req));
    req->leg = leg;
    size_t np = r->n < want_present ? r->n : want_present;
    for (size_t i = 0; i < np; i++) {
        size_t idx = np ? (i * r->n) / np : 0;
        memcpy(req->keys[req->n_keys], r->key[idx], r->klen[idx]);
        req->key_len[req->n_keys] = r->klen[idx];
        req->n_keys++;
    }
    *n_present = np;
    for (uint32_t j = 0; req->n_keys < total; j++) {
        req->key_len[req->n_keys] = absent_key(leg, j, req->keys[req->n_keys]);
        req->n_keys++;
    }
}

/* ══ verification from the outside ════════════════════════════════════ */

static void to_step(const nodus_dnac_state_proof_step_t *a,
                    dna_v2_proof_step_t *b) {
    memset(b, 0, sizeof(*b));
    b->t = a->t;
    memcpy(b->tag, a->tag, 16);
    memcpy(b->legs, a->legs, sizeof(b->legs));
    b->n_legs = a->n_legs;
    b->i = a->i;
    memcpy(b->head, a->head, sizeof(b->head));
    memcpy(b->luh, a->luh, 64);
    b->n = a->n;
    b->n_sib = a->n_sib;
    memcpy(b->sib, a->sib, sizeof(b->sib));
}

/* the tip row's global_root: the AppHash of header h + 1 */
static int tip_global(sqlite3 *db, uint64_t *h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT global_height, global_root FROM "
            "v2_blocks ORDER BY global_height DESC LIMIT 1", -1, &st, NULL)
        != SQLITE_OK) return -1;
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 1) == 64;
    if (ok) {
        *h = (uint64_t)sqlite3_column_int64(st, 0);
        memcpy(out, sqlite3_column_blob(st, 1), 64);
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* damage selector for verify_frame */
enum { DMG_NONE = 0, DMG_CP, DMG_NODE, DMG_LR };

/* Decode `frame` and verify it against the AppHash `app` and the expected
 * rows. Returns 0 if everything verifies; 1 if the frame is refused or does
 * not verify (the caller asserts which it expects). `expect_present` = how
 * many of the requested keys are rows (the first ones). */
static int verify_frame(const nodus_state_proof_req_t *req, const uint8_t *frame,
                        size_t flen, const uint8_t app[64], uint64_t tip,
                        const rows_t *rows, size_t expect_present, int dmg,
                        int expect_empty_leg) {
    nodus_dnac_state_proof_t p;
    uint8_t (*paths)[64] = calloc(req->n_keys, 64);
    evm_trie_proof_result_t *res = calloc(req->n_keys, sizeof(*res));
    dna_v2_proof_step_t *steps = calloc(DNA_V2_PROOF_STEPS_MAX, sizeof(*steps));
    uint8_t *copy = malloc(flen);
    int rc = 1;
    if (!paths || !res || !steps || !copy) goto out;
    memcpy(copy, frame, flen);
    if (nodus_dnac_state_proof_decode(copy, flen, req->n_keys, &p) != 0)
        goto out;
    if (p.height != tip) goto fail;
    if (expect_empty_leg && p.n_nodes != 0) goto fail;
    for (size_t k = 0; k < req->n_keys; k++)
        if (evm_trie_proof_path_of_key(req->keys[k], req->key_len[k],
                                       paths[k]) != 0)
            goto fail;
    uint8_t lr[64];
    memcpy(lr, p.lr, 64);
    if (dmg == DMG_LR) lr[0] ^= 1;
    uint8_t *flipped = NULL;
    const uint8_t **np = p.nodes;
    if (dmg == DMG_NODE && p.n_nodes > 0) {
        flipped = malloc(p.node_lens[0]);
        if (!flipped) goto fail;
        memcpy(flipped, p.nodes[0], p.node_lens[0]);
        flipped[p.node_lens[0] / 2] ^= 1;
        np = malloc(p.n_nodes * sizeof(*np));
        if (!np) { free(flipped); goto fail; }
        memcpy(np, p.nodes, p.n_nodes * sizeof(*np));
        np[0] = flipped;
    }
    int vrc = evm_trie_proof_verify_batch(lr, np, p.node_lens, p.n_nodes,
                                          (const uint8_t (*)[64])paths,
                                          req->n_keys, res);
    if (np != p.nodes) free(np);
    free(flipped);
    if (vrc != 0) goto fail;
    for (size_t k = 0; k < req->n_keys; k++) {
        int want = k < expect_present;
        if ((res[k].found != 0) != want || p.found[k] != (uint8_t)want)
            goto fail;
        if (want) {
            /* the value the PRODUCTION reader gives for that row */
            size_t j;
            for (j = 0; j < rows->n; j++)
                if (rows->klen[j] == req->key_len[k] &&
                    memcmp(rows->key[j], req->keys[k], req->key_len[k]) == 0)
                    break;
            if (j == rows->n || res[k].val_len != 64 ||
                memcmp(res[k].val, rows->val[j], 64) != 0 ||
                memcmp(p.val[k], res[k].val, 64) != 0)
                goto fail;
        }
    }
    for (size_t s = 0; s < p.n_cp; s++) to_step(&p.cp[s], &steps[s]);
    if (dmg == DMG_CP && p.n_cp > 0) steps[p.n_cp - 1].legs[1][0] ^= 1;
    if (dna_v2_state_proof_cp_verify(req->leg, lr, steps, p.n_cp, app) != 0)
        goto fail;
    rc = 0;
fail:
    nodus_dnac_state_proof_free(&p);
out:
    free(paths); free(res); free(steps); free(copy);
    return rc;
}

/* a hand-made request frame (the T2 query map) for the decode tests */
static size_t mkreq(uint8_t *buf, size_t cap, long leg, int dup_leg,
                    long n_keys, size_t klen, int dup_keys, int unknown) {
    cbor_encoder_t e;
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0, sizeof(token));
    cbor_encoder_init(&e, buf, cap);
    cbor_encode_map(&e, 5);
    cbor_encode_cstr(&e, "t");   cbor_encode_uint(&e, 7);
    cbor_encode_cstr(&e, "y");   cbor_encode_cstr(&e, "q");
    cbor_encode_cstr(&e, "q");   cbor_encode_cstr(&e, "dnac_state_proof");
    cbor_encode_cstr(&e, "tok"); cbor_encode_bstr(&e, token, sizeof(token));
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, (size_t)((leg >= 0) + (dup_leg ? 1 : 0) +
                                 (n_keys >= 0) + (unknown ? 1 : 0)));
    if (leg >= 0) { cbor_encode_cstr(&e, "leg"); cbor_encode_uint(&e, (uint64_t)leg); }
    if (dup_leg) { cbor_encode_cstr(&e, "leg"); cbor_encode_uint(&e, 1); }
    if (n_keys >= 0) {
        cbor_encode_cstr(&e, "keys");
        cbor_encode_array(&e, (size_t)n_keys);
        for (long i = 0; i < n_keys; i++) {
            uint8_t k[128];
            memset(k, 0, sizeof(k));
            k[0] = dup_keys ? 7 : (uint8_t)(i + 1);
            k[1] = dup_keys ? 0 : (uint8_t)((i + 1) >> 8);
            cbor_encode_bstr(&e, k, klen);
        }
    }
    if (unknown) { cbor_encode_cstr(&e, "zz"); cbor_encode_uint(&e, 7); }
    return cbor_encoder_len(&e);
}

/* ══ A. request decoding ═══════════════════════════════════════════════ */

static int dec_case(const char *what, long leg, int dup_leg, long n_keys,
                    size_t klen, int dup_keys, int unknown, int want_ok) {
    uint8_t buf[16384];
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    int ec = 0;
    char em[96];
    size_t len = mkreq(buf, sizeof(buf), leg, dup_leg, n_keys, klen, dup_keys,
                       unknown);
    if (!req || len == 0) { free(req); fprintf(stderr, "dec_case %s\n", what); return 1; }
    int rc = nodus_state_proof_request_decode(buf, len, req, &ec, em, sizeof(em));
    int good = want_ok ? rc == 0 && req->n_keys == (size_t)n_keys
                       : rc == -1 && ec == NODUS_ERR_PROTOCOL_ERROR;
    free(req);
    if (!good) fprintf(stderr, "decode case failed: %s (rc %d ec %d)\n", what, rc, ec);
    CHECK(good, what);
    return 0;
}

static int test_request_decode(void) {
    /* through the client encoder */
    uint8_t buf[16384], k1[64], k2[64];
    size_t len = 0;
    memset(k1, 1, sizeof(k1)); memset(k2, 2, sizeof(k2));
    const uint8_t *keys[2] = { k1, k2 };
    size_t lens[2] = { 64, 64 };
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0, sizeof(token));
    CHECK(nodus_dnac_state_proof_request_encode(9, token, 1, keys, lens, 2,
                                                buf, sizeof(buf), &len) == 0,
          "the client encodes a request");
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    int ec = 0;
    char em[96];
    CHECK(req != NULL, "allocation");
    CHECK(nodus_state_proof_request_decode(buf, len, req, &ec, em, sizeof(em))
              == 0 && req->leg == 1 && req->n_keys == 2 &&
          req->key_len[0] == 64 && memcmp(req->keys[1], k2, 64) == 0,
          "the node decodes what the client encodes");
    free(req);
    CHECK(nodus_dnac_state_proof_request_encode(9, token, 0, keys, lens, 2,
              buf, sizeof(buf), &len) == -1 &&
          nodus_dnac_state_proof_request_encode(9, token, 1, keys, lens, 0,
              buf, sizeof(buf), &len) == -1 &&
          nodus_dnac_state_proof_request_encode(9, token, 1, keys, lens, 129,
              buf, sizeof(buf), &len) == -1,
          "the client refuses leg 0, 0 keys, 129 keys");

    if (dec_case("valid leg 1, 3 keys", 1, 0, 3, 64, 0, 0, 1)) return 1;
    if (dec_case("unknown key skipped", 1, 0, 2, 64, 0, 1, 1)) return 1;
    if (dec_case("128 keys", 1, 0, 128, 64, 0, 0, 1)) return 1;
    if (dec_case("leg 4, 3 bytes", 4, 0, 2, 3, 0, 0, 1)) return 1;
    if (dec_case("leg 4, 36 bytes", 4, 0, 2, 36, 0, 0, 1)) return 1;
    if (dec_case("leg 6, 8 bytes", 6, 0, 2, 8, 0, 0, 1)) return 1;
    if (dec_case("leg 0", 0, 0, 2, 64, 0, 0, 0)) return 1;
    if (dec_case("leg 9", 9, 0, 2, 64, 0, 0, 0)) return 1;
    if (dec_case("no leg", -1, 0, 2, 64, 0, 0, 0)) return 1;
    if (dec_case("leg twice", 1, 1, 2, 64, 0, 0, 0)) return 1;
    if (dec_case("no keys", 1, 0, -1, 64, 0, 0, 0)) return 1;
    if (dec_case("0 keys", 1, 0, 0, 64, 0, 0, 0)) return 1;
    if (dec_case("129 keys", 1, 0, 129, 64, 0, 0, 0)) return 1;
    if (dec_case("a repeated key", 1, 0, 3, 64, 1, 0, 0)) return 1;
    if (dec_case("leg 1, 63 bytes", 1, 0, 2, 63, 0, 0, 0)) return 1;
    if (dec_case("leg 4, 2 bytes", 4, 0, 2, 2, 0, 0, 0)) return 1;
    if (dec_case("leg 4, 37 bytes", 4, 0, 2, 37, 0, 0, 0)) return 1;
    if (dec_case("leg 6, 7 bytes", 6, 0, 2, 7, 0, 0, 0)) return 1;
    if (dec_case("a key above 64 bytes", 1, 0, 2, 65, 0, 0, 0)) return 1;
    return 0;
}

/* ══ the delivery sink and the waits ═══════════════════════════════════ */

typedef struct {
    size_t   n, dropped;
    uint8_t *frame[8];
    size_t   len[8];
    int      ec[8];
    uint64_t tag[8];
} sink_t;

static void sink_done(void *user, void *tag, uint8_t *frame, size_t flen,
                      int ec, const char *em,
                      const nodus_state_proof_stats_t *st, int dropped) {
    sink_t *s = user;
    (void)em; (void)st;
    if (dropped) s->dropped++;
    if (s->n < 8) {
        s->frame[s->n] = frame;
        s->len[s->n] = flen;
        s->ec[s->n] = ec;
        s->tag[s->n] = (uint64_t)(uintptr_t)tag;
        s->n++;
    } else {
        free(frame);
    }
}

static void sink_free(sink_t *s) {
    for (size_t i = 0; i < s->n; i++) free(s->frame[i]);
    memset(s, 0, sizeof(*s));
}

/* the answers of the readers: a BOUNDED poll of an expected asynchronous
 * condition (5 ms steps, at most 20 s), then an assertion by the caller */
static size_t wait_answers(nodus_state_proof_service_t *svc, sink_t *s,
                           size_t want) {
    for (int i = 0; i < 4000 && s->n < want; i++) {
        nodus_state_proof_poll(svc, sink_done, s);
        if (s->n < want) usleep(5000);
    }
    return s->n;
}

/* ══ B. the proofs on a generation-6 chain ════════════════════════════ */

static int test_proofs(fixture_t *fx, const rows_t *rows /* [9] */) {
    nodus_witness_t *ctx = nodus_state_proof_ctx_open(db_path(fx));
    uint64_t tip = 0;
    uint8_t app[64];
    CHECK(ctx != NULL, "a private read-only context");
    CHECK(tip_global(fx->w->db, &tip, app) == 0 && tip == HA - 1u,
          "the committed tip is the edge block and carries a global root");

    for (int leg = 1; leg <= 8; leg++) {
        nodus_state_proof_req_t *req = malloc(sizeof(*req));
        uint8_t *frame = NULL;
        size_t flen = 0, np = 0;
        int ec = 0;
        char em[96];
        nodus_state_proof_stats_t st;
        CHECK(req != NULL, "allocation");
        const int empty_leg = rows[leg].n == 0;
        pick_keys(leg, &rows[leg], 6, 9, req, &np);
        CHECK(nodus_state_proof_build(ctx, req, 41, &frame, &flen, &st, &ec,
                                      em, sizeof(em)) == 0 && frame,
              "the proof builds");
        CHECK(st.height == tip && st.frame_bytes == flen,
              "the stats carry the snapshot height and the frame size");
        if (verify_frame(req, frame, flen, app, tip, &rows[leg], np,
                         DMG_NONE, empty_leg) != 0) {
            fprintf(stderr, "leg %d: the proof does not verify\n", leg);
            return 1;
        }
        CHECK(verify_frame(req, frame, flen, app, tip, &rows[leg], np,
                           DMG_CP, empty_leg) == 1,
              "a damaged composition step is refused");
        CHECK(verify_frame(req, frame, flen, app, tip, &rows[leg], np,
                           DMG_LR, empty_leg) == 1,
              "a damaged leg root is refused");
        if (!empty_leg && np > 0)
            CHECK(verify_frame(req, frame, flen, app, tip, &rows[leg], np,
                               DMG_NODE, empty_leg) == 1,
                  "a node with a flipped byte is refused");
        {   /* a wrong AppHash (the light client's value for another chain) */
            uint8_t wrong[64];
            memcpy(wrong, app, 64);
            wrong[5] ^= 1;
            CHECK(verify_frame(req, frame, flen, wrong, tip, &rows[leg], np,
                               DMG_NONE, empty_leg) == 1,
                  "a different AppHash is refused");
        }
        {   /* the same snapshot builds the same bytes */
            uint8_t *frame2 = NULL;
            size_t flen2 = 0;
            CHECK(nodus_state_proof_build(ctx, req, 41, &frame2, &flen2, NULL,
                                          &ec, em, sizeof(em)) == 0 &&
                  flen2 == flen && memcmp(frame, frame2, flen) == 0,
                  "the answer is a function of the snapshot");
            free(frame2);
        }
        free(frame);
        free(req);
    }
    nodus_state_proof_ctx_close(ctx);
    return 0;
}

static int test_below_generation_6(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, "g5") == 0, "a ladder chain");
    for (uint64_t h = 1; h <= H5; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    CHECK(committed_gen(fx.w) == NODUS_RT_GEN_ROOTS,
          "generation 5 is committed, generation 6 is not");
    nodus_witness_t *ctx = nodus_state_proof_ctx_open(db_path(&fx));
    nodus_state_proof_req_t *req = calloc(1, sizeof(*req));
    CHECK(ctx && req, "context and request");
    req->leg = 1;
    req->n_keys = 1;
    key64('X', 1, req->keys[0]);
    req->key_len[0] = 64;
    uint8_t *frame = NULL;
    size_t flen = 0;
    int ec = 0;
    char em[96];
    CHECK(nodus_state_proof_build(ctx, req, 1, &frame, &flen, NULL, &ec, em,
                                  sizeof(em)) == -1 && frame == NULL &&
          ec == NODUS_ERR_NOT_FOUND,
          "below generation 6 the answer is NODUS_ERR_NOT_FOUND");
    free(req);
    nodus_state_proof_ctx_close(ctx);
    fx_close(&fx);
    return 0;
}

/* ══ C. the service ════════════════════════════════════════════════════ */

static int test_service(fixture_t *fx, const rows_t *rows) {
    const char *path = db_path(fx);
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    uint8_t token[NODUS_SESSION_TOKEN_LEN], buf[16384], bad[16];
    size_t np = 0, len = 0;
    int ec = 0;
    char em[96];
    CHECK(req != NULL, "allocation");
    memset(token, 0, sizeof(token));
    memset(bad, 0xFF, sizeof(bad));
    pick_keys(2, &rows[2], 3, 4, req, &np);
    {
        const uint8_t *kp[NODUS_STATE_PROOF_MAX_KEYS];
        for (size_t i = 0; i < req->n_keys; i++) kp[i] = req->keys[i];
        CHECK(nodus_dnac_state_proof_request_encode(77, token, req->leg, kp,
                  req->key_len, req->n_keys, buf, sizeof(buf), &len) == 0,
              "the request frame");
    }

    /* C1 not enabled: refused RATE_LIMITED, no read */
    {
        nodus_state_proof_limits_t lim[2] = { {0, 1000}, {2, 0} };
        for (int i = 0; i < 2; i++) {
            nodus_state_proof_service_t *svc =
                nodus_state_proof_service_new(path, &lim[i]);
            CHECK(svc != NULL, "a service with a zero limit");
            CHECK(nodus_state_proof_submit(svc, 1000000000LL, buf, len, 77,
                      (void *)1, &ec, em, sizeof(em)) == -1 &&
                  ec == NODUS_ERR_RATE_LIMITED, "not enabled: RATE_LIMITED");
            nodus_state_proof_counters_t c = nodus_state_proof_service_counters(svc);
            CHECK(c.decoded == 1 && c.refused_rate == 1 && c.handed_off == 0 &&
                  c.builds_started == 0, "not enabled: no hand-off, no read");
            nodus_state_proof_service_free(svc, sink_done, NULL);
        }
    }

    /* C2 enabled: the answer is the direct build's bytes, built off-loop */
    {
        nodus_state_proof_limits_t lim = { 2, 1000 };
        nodus_state_proof_service_t *svc = nodus_state_proof_service_new(path, &lim);
        sink_t sk;
        memset(&sk, 0, sizeof(sk));
        CHECK(svc != NULL, "the service starts");
        CHECK(nodus_state_proof_submit(svc, 1000000000LL, buf, len, 77,
                  (void *)(uintptr_t)5, &ec, em, sizeof(em)) == 0,
              "a valid request is handed off");
        CHECK(wait_answers(svc, &sk, 1) == 1 && sk.frame[0] && sk.ec[0] == 0 &&
              sk.tag[0] == 5, "the answer comes back with its tag");
        nodus_witness_t *ctx = nodus_state_proof_ctx_open(path);
        uint8_t *direct = NULL;
        size_t dlen = 0;
        CHECK(ctx && nodus_state_proof_build(ctx, req, 77, &direct, &dlen,
                  NULL, &ec, em, sizeof(em)) == 0, "the direct build");
        CHECK(dlen == sk.len[0] && memcmp(direct, sk.frame[0], dlen) == 0,
              "the service's frame is byte-identical to the direct build");
        free(direct);
        nodus_state_proof_ctx_close(ctx);
        int off_loop = 0;
        for (unsigned r = 0; r < 2; r++) {
            pthread_t t;
            if (nodus_state_proof_service_last_builder(svc, r, &t) == 0) {
                CHECK(!pthread_equal(t, pthread_self()),
                      "the build ran on a reader thread, not the loop thread");
                off_loop = 1;
            }
        }
        CHECK(off_loop, "a reader recorded the build");
        nodus_state_proof_counters_t c = nodus_state_proof_service_counters(svc);
        CHECK(c.loop_builds == 0 && c.builds_started == 1 &&
              c.builds_done == 1 && c.handed_off == 1,
              "one build, none on the loop");
        sink_free(&sk);
        nodus_state_proof_service_free(svc, sink_done, NULL);
    }

    /* C3 every reader busy (answers not yet polled): RATE_LIMITED */
    {
        nodus_state_proof_limits_t lim = { 2, 1000 };
        nodus_state_proof_service_t *svc = nodus_state_proof_service_new(path, &lim);
        sink_t sk;
        memset(&sk, 0, sizeof(sk));
        CHECK(svc != NULL, "the service starts");
        CHECK(nodus_state_proof_submit(svc, 1000000000LL, buf, len, 1,
                  (void *)1, &ec, em, sizeof(em)) == 0 &&
              nodus_state_proof_submit(svc, 1000000000LL, buf, len, 2,
                  (void *)2, &ec, em, sizeof(em)) == 0,
              "two readers take two requests");
        CHECK(nodus_state_proof_submit(svc, 1000000000LL, buf, len, 3,
                  (void *)3, &ec, em, sizeof(em)) == -1 &&
              ec == NODUS_ERR_RATE_LIMITED, "the third request: RATE_LIMITED");
        nodus_state_proof_counters_t c = nodus_state_proof_service_counters(svc);
        CHECK(c.refused_busy == 1 && c.handed_off == 2, "counted as busy");
        CHECK(wait_answers(svc, &sk, 2) == 2, "both answers come back");
        c = nodus_state_proof_service_counters(svc);
        CHECK(c.builds_started == 2 && c.builds_done == 2,
              "the refused request started no build");
        sink_free(&sk);
        nodus_state_proof_service_free(svc, sink_done, NULL);
    }

    /* C4 a flood at one instant against a node-wide rate of 2 */
    {
        nodus_state_proof_limits_t lim = { 4, 2 };
        nodus_state_proof_service_t *svc = nodus_state_proof_service_new(path, &lim);
        sink_t sk;
        memset(&sk, 0, sizeof(sk));
        CHECK(svc != NULL, "the service starts");
        for (int i = 0; i < 1000; i++)
            (void)nodus_state_proof_submit(svc, 1000000000LL, buf, len,
                                           (uint32_t)i, (void *)(uintptr_t)(i + 1),
                                           &ec, em, sizeof(em));
        nodus_state_proof_counters_t c = nodus_state_proof_service_counters(svc);
        CHECK(c.decoded == 1000 && c.handed_off == 2 && c.refused_rate == 998 &&
              c.refused_busy == 0 && c.refused_protocol == 0,
              "1000 requests at one instant: 2 handed off, 998 RATE_LIMITED");
        CHECK(wait_answers(svc, &sk, 2) == 2, "the two admitted come back");
        c = nodus_state_proof_service_counters(svc);
        CHECK(c.builds_started == 2 && c.builds_done == 2 && c.loop_builds == 0,
              "exactly two builds started: refused requests reached no read, "
              "the loop built nothing");
        /* malformed flood: decoded and refused on the loop, no build */
        for (int i = 0; i < 1000; i++)
            CHECK(nodus_state_proof_submit(svc, 1000000000LL, bad, sizeof(bad),
                      1, NULL, &ec, em, sizeof(em)) == -1 &&
                  ec == NODUS_ERR_PROTOCOL_ERROR, "malformed: PROTOCOL_ERROR");
        c = nodus_state_proof_service_counters(svc);
        CHECK(c.refused_protocol == 1000 && c.builds_started == 2,
              "1000 malformed requests started no build");
        /* one second later the limiter admits again */
        CHECK(nodus_state_proof_submit(svc, 2000000000LL, buf, len, 9,
                  (void *)9, &ec, em, sizeof(em)) == 0, "admitted again later");
        CHECK(wait_answers(svc, &sk, 3) == 3, "the third answer");
        sink_free(&sk);
        nodus_state_proof_service_free(svc, sink_done, NULL);
    }

    /* C5 freeing with an undelivered answer hands the tag back dropped */
    {
        nodus_state_proof_limits_t lim = { 1, 1000 };
        nodus_state_proof_service_t *svc = nodus_state_proof_service_new(path, &lim);
        sink_t sk;
        memset(&sk, 0, sizeof(sk));
        CHECK(svc != NULL, "the service starts");
        CHECK(nodus_state_proof_submit(svc, 1000000000LL, buf, len, 1,
                  (void *)4, &ec, em, sizeof(em)) == 0, "handed off");
        nodus_state_proof_service_free(svc, sink_done, &sk);
        CHECK(sk.dropped == 1 && sk.n == 1 && sk.tag[0] == 4 &&
              sk.frame[0] == NULL, "the undelivered tag is dropped, not lost");
    }
    free(req);
    return 0;
}

/* ══ D. the cost measurement ═══════════════════════════════════════════ */

static int measure(const char *name, const uint32_t n[9], uint32_t extra_cc) {
    fixture_t fx;
    double t0 = now_ms();
    if (build_chain(&fx, name, n, extra_cc) != 0) {
        fprintf(stderr, "measure: the %s chain failed to build\n", name);
        fx_close(&fx);
        return 1;
    }
    printf("COST size=%s fixture_build_ms=%.0f chain_config_history_rows=%lld\n",
           name, now_ms() - t0, (long long)q1(fx.w->db,
               "SELECT COUNT(*) FROM chain_config_history"));
    nodus_witness_t *ctx = nodus_state_proof_ctx_open(db_path(&fx));
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    if (!ctx || !req) { fx_close(&fx); return 1; }

    /* the sibling legs alone (includes the chain_config_history scan) */
    {
        double ts[3];
        for (int i = 0; i < 3; i++) {
            nodus_witness_proof_legs_t p;
            double a = now_ms();
            if (run_sql(ctx->db, "BEGIN") != 0 ||
                nodus_witness_proof_legs_load(ctx, &p) != 0) {
                fx_close(&fx);
                return 1;
            }
            nodus_witness_proof_legs_free(&p);
            run_sql(ctx->db, "ROLLBACK");
            ts[i] = now_ms() - a;
        }
        printf("COST size=%s sibling_legs_load_ms=[%.1f %.1f %.1f] "
               "(first run cold)\n", name, ts[0], ts[1], ts[2]);
    }
    for (int leg = 1; leg <= 8; leg++) {
        rows_t rows;
        size_t np = 0;
        memset(&rows, 0, sizeof(rows));
        if (nodus_witness_v2_trie_scan_leg(fx.w, leg, rows_cb, &rows) != 0) {
            fx_close(&fx);
            return 1;
        }
        pick_keys(leg, &rows, 128, 128, req, &np);
        double ts[3];
        nodus_state_proof_stats_t st;
        memset(&st, 0, sizeof(st));
        for (int i = 0; i < 3; i++) {
            uint8_t *frame = NULL;
            size_t flen = 0;
            int ec = 0;
            char em[96];
            double a = now_ms();
            if (nodus_state_proof_build(ctx, req, 1, &frame, &flen, &st, &ec,
                                        em, sizeof(em)) != 0) {
                fprintf(stderr, "measure: leg %d build failed (%d: %s)\n",
                        leg, ec, em);
                rows_free(&rows);
                fx_close(&fx);
                return 1;
            }
            ts[i] = now_ms() - a;
            free(frame);
        }
        printf("COST size=%s leg=%d rows=%zu keys=%zu present=%zu "
               "nodes_loaded=%zu nodes=%zu frame_bytes=%zu "
               "build_ms=[%.1f %.1f %.1f]\n", name, leg, rows.n, req->n_keys,
               np, st.nodes_loaded, st.nodes, st.frame_bytes, ts[0], ts[1],
               ts[2]);
        rows_free(&rows);
    }
    free(req);
    nodus_state_proof_ctx_close(ctx);
    fx_close(&fx);
    return 0;
}

int main(void) {
    int rc = 0;
    if (test_request_decode() != 0) return 1;
    if (test_below_generation_6() != 0) return 1;

    /* B and C on a small populated chain; claims left EMPTY (empty leg) */
    {
        fixture_t fx;
        uint32_t n[9] = { 0, 40, 30, 0, 25, 12, 30, 20, 20 };
        rows_t rows[9];
        memset(rows, 0, sizeof(rows));
        CHECK(build_chain(&fx, "main", n, 0) == 0,
              "the populated generation-6 chain");
        for (int leg = 1; leg <= 8; leg++)
            CHECK(nodus_witness_v2_trie_scan_leg(fx.w, leg, rows_cb,
                                                 &rows[leg]) == 0,
                  "the production row reader scans the leg");
        CHECK(rows[3].n == 0, "the claims leg is empty");
        CHECK(rows[1].n >= 40 && rows[2].n >= 30 && rows[6].n >= 12,
              "the legs hold the populated rows");
        rc = test_proofs(&fx, rows);
        if (!rc) rc = test_service(&fx, rows);
        for (int leg = 1; leg <= 8; leg++) rows_free(&rows[leg]);
        fx_close(&fx);
        if (rc) return 1;
    }

    /* D: the worst-case cost per leg at the live and the grown sizes */
    {
        const uint32_t live[9]  = { 0, 4316, 1, 0, 13, 5, 30, 735, 733 };
        const uint32_t grown[9] = { 0, 100000, 20000, 20000, 20000, 1000,
                                    10000, 10000, 10000 };
        /* live claims: 1 row (the plan's count) */
        uint32_t live_c[9];
        memcpy(live_c, live, sizeof(live_c));
        live_c[3] = 1;
        if (measure("live", live_c, 0) != 0) return 1;
        if (measure("grown", grown, 20000) != 0) return 1;
    }
    printf("test_hf9_proof_service: %d checks passed\n", g_checks);
    return 0;
}
