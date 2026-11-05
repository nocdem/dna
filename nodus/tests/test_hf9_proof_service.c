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
 *     and an unknown key are accepted; a final unknown argument with no value
 *     or with a truncated array value is refused (PROTOCOL_ERROR); so is a
 *     final top-level key with no value, and an args map whose KEY is an
 *     array holding "leg" / "keys" or an integer (a non-text key). A request
 *     of 4097 keys passes the Tier-2 receive decoder (nodus_t2_decode, limit
 *     raised for the dnac_state_proof REQUEST only) and the proof decoder
 *     answers PROTOCOL_ERROR; the same bytes under another method are refused
 *     by the generic 4,096 limit as before. The request limit is the frame
 *     ceiling (no array in a frame holds more items than bytes): 16769
 *     64-byte keys and 2,000,000 one-byte keys (about 4 MB) both reach the
 *     proof decoder and get PROTOCOL_ERROR; under another method both are
 *     refused by the generic decoder.
 *     The IPC delivery case (E2) waits for the answers to be PUBLISHED
 *     (JOB_DONE, via nodus_state_proof_service_published), a bounded wait on
 *     the state that fails if it never arrives, before its single production
 *     poll; it no longer waits on the builds_done counter.
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
 *  E. Who asked (fake transport objects): a pending completion reaches the
 *     connection that asked; after a disconnect it reaches nobody; after
 *     slot reuse by a replacement with generation 0 (the witness IPC
 *     transport, whose serial is stamped into conn->user_data at accept,
 *     nodus_witness_ipc.c) it is NOT delivered to the replacement; a
 *     connection being closed gets nothing; session-mode replacements differ
 *     by generation; a connection with neither generation nor serial has no
 *     identity. NOT covered: that the IPC listener really stamps the serial
 *     (needs a live socket; mutation below) and the send itself.
 *  F. Malformed RESPONSES through the production decoder
 *     (nodus_dnac_state_proof_decode): f = false with a "v", f = true without
 *     one or with two, a repeated "f" / "h", no "cp", fewer results than keys,
 *     a 63-byte leg root, an empty and a 1,061-byte node, a COMPOSE step
 *     without legs are refused; 5000 and 16768 nodes (above the generic CBOR
 *     decoder's 4,096) are accepted and 16769 refused (the receive path
 *     in front of this decoder is F2).
 *  E2. A real IPC accept and the PRODUCTION delivery (a unix socket listener
 *     nodus_witness_ipc_new_tools, real client connections, the production
 *     nodus_witness_state_proof_handle / _poll): client 1 asks and
 *     disconnects before its answer is delivered; client 2 connects into the
 *     same slot (asserted) with another accept serial (generation is 0 on
 *     this transport) and asks; after both answers are built one production
 *     poll delivers: client 2 receives exactly its own answer (txn 22), never
 *     the first. Kills: removing the accept stamp (no identity -> client 2 is
 *     refused), comparing only the generation in nodus_state_proof_conn_alive
 *     (client 2 gets both answers). NOT covered: the exhaustion branch of the
 *     serial (the counter is private to the listener). The handler table also
 *     carries two do-nothing stubs, cc_collect and status, only because
 *     nodus_witness_ipc_new returns NULL without them; this test never
 *     reaches them (tool connections, dnac_state_proof only); dispatch_dnac
 *     is a recorder that hands the request to the production handler.
 *  F2. The client RECEIVE path: nodus_t2_decode (the first call of
 *     client_on_frame, nodus_client.c:419) takes 5000 and 16768 nodes for the
 *     dnac_state_proof reply, refuses 16769, and keeps the generic 4,096-item
 *     limit for another method (4000 accepted, 5000 refused). Not the whole
 *     client_on_frame (a live client object is not built here).
 *  G. One snapshot per answer: between the committed-height read and the
 *     legs a committed change (a token row deleted, flushed, the fixture
 *     anchor rewritten) lands on the writer connection; the answer verifies
 *     wholly to the OLD tip, legs and AppHash; a later build verifies to the
 *     new AppHash and not to the old. The stored tip root: corrupted ->
 *     refused INTERNAL (never trusted); restored. A chain with NO populated
 *     rows whose tip root was produced by the real blocks of the ladder
 *     (never rewritten): every leg 1..8 proves to that unmodified anchor. A
 *     domain registry that cannot be read is INTERNAL, not NOT_FOUND.
 *  H. The worst-case cost per leg (printed, not asserted - see below).
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
 *  For each leg 1..8 two requests of 128 keys (the ceiling of D26):
 *   "deepest": EVERY row of the leg is proved once to count the nodes on its
 *     path; the 128 rows with the most path nodes are requested (all rows if
 *     the leg has fewer; the rest absent). The line "selection=deepest_paths"
 *     prints the rows counted, the largest per-key path and the SUM of the
 *     128 largest paths, which is an UPPER BOUND on the trie nodes any
 *     128-present-key request can touch (shared nodes count once). The
 *     measured request is the deepest-paths one; it is not proven to be the
 *     slowest request, only the one whose path bound is largest.
 *   "absent128": 128 absent keys of the leg's key shape, a fixed SAMPLE (the
 *     depth of absent paths is not enumerated).
 *  Printed per request: rows in the leg, keys requested / present, the trie
 *  nodes loaded, nodes in the bundle, the frame bytes, and the wall time (CLOCK_MONOTONIC, in this TEST
 *  only; the service itself reads no clock for the build) of the build
 *  (one build on a FRESH reader connection - empty SQLite page and statement
 *  caches, the operating system's file cache is not dropped - then three on
 *  the connection that has just counted every row's path, so those three are
 *  "after path counting", not cold) and of the sibling-leg load alone
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
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "witness/nodus_witness_ipc.h"

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
    cbor_encode_map(&e, unknown == 4 ? 6 : 5);
    cbor_encode_cstr(&e, "t");   cbor_encode_uint(&e, 7);
    cbor_encode_cstr(&e, "y");   cbor_encode_cstr(&e, "q");
    cbor_encode_cstr(&e, "q");   cbor_encode_cstr(&e, "dnac_state_proof");
    cbor_encode_cstr(&e, "tok"); cbor_encode_bstr(&e, token, sizeof(token));
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, (size_t)((leg >= 0) + (dup_leg ? 1 : 0) +
                                 (n_keys >= 0) +
                                 ((unknown >= 1 && unknown <= 3) ? 1 : 0)));
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
    /* unknown: 1 = "zz": 7; 2 = "zz" with NO value (the frame ends);
     * 3 = "zz": an array that claims 3 elements and holds one */
    if (unknown == 1) { cbor_encode_cstr(&e, "zz"); cbor_encode_uint(&e, 7); }
    if (unknown == 2) { cbor_encode_cstr(&e, "zz"); }
    if (unknown == 3) {
        cbor_encode_cstr(&e, "zz");
        cbor_encode_array(&e, 3);
        cbor_encode_uint(&e, 1);
    }
    /* 4 = a complete request followed by a final TOP-LEVEL key "zz" with no
     * value (the outer map claims 6 entries) */
    if (unknown == 4) cbor_encode_cstr(&e, "zz");
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
    if (dec_case("a final unknown argument with no value", 1, 0, 2, 64, 0, 2,
                 0)) return 1;
    if (dec_case("a final unknown argument with a truncated array", 1, 0, 2,
                 64, 0, 3, 0)) return 1;
    if (dec_case("a final top-level key with no value", 1, 0, 2, 64, 0, 4,
                 0)) return 1;
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

/* A request whose args map has a NON-TEXT key: the contents of an array key
 * ("leg", 1, "keys", [K]) must never become arguments. */
static int nontext_case(const char *what, int array_key) {
    uint8_t buf[4096], token[NODUS_SESSION_TOKEN_LEN], k[64];
    cbor_encoder_t e;
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    int ec = 0;
    char em[96];
    CHECK(req != NULL, "allocation");
    memset(token, 0, sizeof(token));
    memset(k, 9, sizeof(k));
    cbor_encoder_init(&e, buf, sizeof(buf));
    cbor_encode_map(&e, 5);
    cbor_encode_cstr(&e, "t");   cbor_encode_uint(&e, 7);
    cbor_encode_cstr(&e, "y");   cbor_encode_cstr(&e, "q");
    cbor_encode_cstr(&e, "q");   cbor_encode_cstr(&e, "dnac_state_proof");
    cbor_encode_cstr(&e, "tok"); cbor_encode_bstr(&e, token, sizeof(token));
    cbor_encode_cstr(&e, "a");
    cbor_encode_map(&e, 3);
    if (array_key) {
        cbor_encode_array(&e, 5);              /* the key: an array ... */
        cbor_encode_cstr(&e, "x");
        cbor_encode_cstr(&e, "leg");           /* ... holding "leg" and "keys" */
        cbor_encode_uint(&e, 1);
        cbor_encode_cstr(&e, "keys");
        cbor_encode_array(&e, 1);
        cbor_encode_bstr(&e, k, sizeof(k));
    } else {
        cbor_encode_uint(&e, 5);               /* the key: an integer */
    }
    cbor_encode_uint(&e, 0);                   /* its value */
    cbor_encode_cstr(&e, "u"); cbor_encode_uint(&e, 0);
    cbor_encode_cstr(&e, "v"); cbor_encode_uint(&e, 0);
    size_t len = cbor_encoder_len(&e);
    CHECK(len > 0, "frame");
    int rc = nodus_state_proof_request_decode(buf, len, req, &ec, em, sizeof(em));
    free(req);
    CHECK(rc == -1 && ec == NODUS_ERR_PROTOCOL_ERROR, what);
    return 0;
}

/* More than 4,096 keys: the Tier-2 receive decoder (nodus_t2_decode) accepts
 * the frame of a dnac_state_proof REQUEST, so the proof decoder answers
 * PROTOCOL_ERROR (plan §10.2); every other method keeps the generic limit. */
static int test_request_limits(void) {
    const size_t cap = (size_t)NODUS_MAX_FRAME_TCP + 64 * 1024;
    uint8_t *buf = malloc(cap);
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    nodus_tier2_msg_t msg;
    int ec = 0;
    char em[96];
    CHECK(buf && req, "allocation");
    if (nontext_case("a non-text (array) argument key is refused", 1)) return 1;
    if (nontext_case("a non-text (integer) argument key is refused", 0)) return 1;

    size_t len = mkreq(buf, cap, 1, 0, 4097, 64, 0, 0);
    CHECK(len > 0 && len < NODUS_MAX_FRAME_TCP, "a 4097-key request frame");
    memset(&msg, 0, sizeof(msg));
    CHECK(nodus_t2_decode(buf, len, &msg) == 0 &&
          strcmp(msg.method, "dnac_state_proof") == 0 && msg.type == 'q',
          "the receive decoder takes a 4097-key dnac_state_proof request");
    nodus_t2_msg_free(&msg);
    CHECK(nodus_state_proof_request_decode(buf, len, req, &ec, em,
                                           sizeof(em)) == -1 &&
          ec == NODUS_ERR_PROTOCOL_ERROR,
          "...and the proof decoder answers PROTOCOL_ERROR");
    {   /* the same bytes under another method: the generic limit refuses */
        static const char M[] = "dnac_state_proof";
        for (size_t i = 0; i + 16 <= len; i++)
            if (memcmp(buf + i, M, 16) == 0) { buf[i + 15] = 'G'; break; }
        memset(&msg, 0, sizeof(msg));
        CHECK(nodus_t2_decode(buf, len, &msg) == -1,
              "another method with 4097 items is refused as before");
    }
    /* above the reply's 16,768 and up to the frame ceiling (every item takes
     * at least one byte, so no request array inside a frame is out of reach):
     * 16769 keys of 64 bytes, and 2,000,000 one-byte keys (about 4 MB) */
    static const struct { long n; size_t klen; } big[2] = {
        { 16769, 64 }, { 2000000, 1 } };
    for (int b = 0; b < 2; b++) {
        len = mkreq(buf, cap, 1, 0, big[b].n, big[b].klen, 0, 0);
        CHECK(len > 0 && len < (size_t)NODUS_MAX_FRAME_TCP,
              "a large request frame inside the frame ceiling");
        memset(&msg, 0, sizeof(msg));
        CHECK(nodus_t2_decode(buf, len, &msg) == 0 &&
              strcmp(msg.method, "dnac_state_proof") == 0,
              "the receive decoder takes it");
        nodus_t2_msg_free(&msg);
        CHECK(nodus_state_proof_request_decode(buf, len, req, &ec, em,
                                               sizeof(em)) == -1 &&
              ec == NODUS_ERR_PROTOCOL_ERROR,
              "...and the proof decoder answers PROTOCOL_ERROR");
        {
            static const char M[] = "dnac_state_proof";
            for (size_t i = 0; i + 16 <= len; i++)
                if (memcmp(buf + i, M, 16) == 0) { buf[i + 15] = 'G'; break; }
            memset(&msg, 0, sizeof(msg));
            CHECK(nodus_t2_decode(buf, len, &msg) == -1,
                  "another method with that many items is refused as before");
        }
    }
    free(buf);
    free(req);
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
        s->tag[s->n] = 0;
        if (tag) memcpy(&s->tag[s->n], tag, sizeof(uint64_t));   /* the copy */
        s->n++;
    } else {
        free(frame);
    }
}

/* submit with a 64-bit tag value (copied by the service) */
static int sub(nodus_state_proof_service_t *svc, int64_t now,
               const uint8_t *buf, size_t len, uint32_t txn, uint64_t tagv,
               int *ec, char *em, size_t cap) {
    return nodus_state_proof_submit(svc, now, buf, len, txn, &tagv,
                                    sizeof(tagv), ec, em, cap);
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
            CHECK(sub(svc, 1000000000LL, buf, len, 77, 1, &ec, em,
                      sizeof(em)) == -1 &&
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
        CHECK(sub(svc, 1000000000LL, buf, len, 77, 5, &ec, em,
                  sizeof(em)) == 0, "a valid request is handed off");
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
        CHECK(sub(svc, 1000000000LL, buf, len, 1, 1, &ec, em,
                  sizeof(em)) == 0 &&
              sub(svc, 1000000000LL, buf, len, 2, 2, &ec, em,
                  sizeof(em)) == 0,
              "two readers take two requests");
        CHECK(sub(svc, 1000000000LL, buf, len, 3, 3, &ec, em,
                  sizeof(em)) == -1 &&
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
            (void)sub(svc, 1000000000LL, buf, len, (uint32_t)i,
                      (uint64_t)(i + 1), &ec, em, sizeof(em));
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
                      1, NULL, 0, &ec, em, sizeof(em)) == -1 &&
                  ec == NODUS_ERR_PROTOCOL_ERROR, "malformed: PROTOCOL_ERROR");
        c = nodus_state_proof_service_counters(svc);
        CHECK(c.refused_protocol == 1000 && c.builds_started == 2,
              "1000 malformed requests started no build");
        /* one second later the limiter admits again */
        CHECK(sub(svc, 2000000000LL, buf, len, 9, 9, &ec, em,
                  sizeof(em)) == 0, "admitted again later");
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
        CHECK(sub(svc, 1000000000LL, buf, len, 1, 4, &ec, em,
                  sizeof(em)) == 0, "handed off");
        nodus_state_proof_service_free(svc, sink_done, &sk);
        CHECK(sk.dropped == 1 && sk.n == 1 && sk.tag[0] == 4 &&
              sk.frame[0] == NULL, "the undelivered tag is dropped, not lost");
    }
    free(req);
    return 0;
}

/* ══ E. who asked: the connection identity of a pending completion ═══════ */

static nodus_tcp_conn_t *fake_conn(nodus_tcp_t *tcp, int slot, uint64_t gen,
                                   uint64_t serial) {
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->tcp_parent = tcp;
    c->slot = slot;
    c->generation = gen;
    c->user_data = (void *)(uintptr_t)serial;
    return c;
}

static int test_conn_identity(void) {
    nodus_tcp_t *tcp = calloc(1, sizeof(*tcp));
    nodus_state_proof_conn_id_t ida, idb, idd;
    CHECK(tcp != NULL, "allocation");

    /* the witness IPC transport: generation 0, only the accept serial differs */
    nodus_tcp_conn_t *a = fake_conn(tcp, 3, 0, 1);
    nodus_tcp_conn_t *b = fake_conn(tcp, 3, 0, 2);
    CHECK(a && b, "allocation");
    tcp->pool[3] = a;
    CHECK(nodus_state_proof_conn_id_of(a, &ida) == 0, "A has an identity");
    CHECK(nodus_state_proof_conn_alive(&ida) == a,
          "a pending completion finds the connection that asked");
    tcp->pool[3] = NULL;                                  /* disconnect */
    CHECK(nodus_state_proof_conn_alive(&ida) == NULL,
          "after the disconnect the completion finds nobody");
    tcp->pool[3] = b;                                     /* slot reuse */
    CHECK(nodus_state_proof_conn_alive(&ida) == NULL,
          "slot reuse (same slot, generation 0): the old completion is NOT "
          "delivered to the replacement");
    CHECK(nodus_state_proof_conn_id_of(b, &idb) == 0 &&
          nodus_state_proof_conn_alive(&idb) == b,
          "the replacement's own completion reaches it");
    b->close_pending = true;
    CHECK(nodus_state_proof_conn_alive(&idb) == NULL,
          "a connection being closed receives nothing");
    b->close_pending = false;

    /* session mode: the generation tells them apart */
    nodus_tcp_conn_t *d1 = fake_conn(tcp, 5, 11, 0);
    nodus_tcp_conn_t *d2 = fake_conn(tcp, 5, 12, 0);
    CHECK(d1 && d2, "allocation");
    tcp->pool[5] = d1;
    CHECK(nodus_state_proof_conn_id_of(d1, &idd) == 0 &&
          nodus_state_proof_conn_alive(&idd) == d1, "session connection");
    tcp->pool[5] = d2;
    CHECK(nodus_state_proof_conn_alive(&idd) == NULL,
          "a session replacement has another generation");

    /* a connection with neither is refused: it cannot be told from a
     * replacement */
    nodus_tcp_conn_t *n = fake_conn(tcp, 7, 0, 0);
    CHECK(n != NULL, "allocation");
    CHECK(nodus_state_proof_conn_id_of(n, &idd) == -1,
          "no generation and no serial: no identity");
    idb.slot = -1;
    CHECK(nodus_state_proof_conn_alive(&idb) == NULL, "slot -1");
    idb.slot = NODUS_TCP_MAX_CONNS;
    CHECK(nodus_state_proof_conn_alive(&idb) == NULL, "slot beyond the pool");

    free(a); free(b); free(d1); free(d2); free(n); free(tcp);
    return 0;
}

/* ══ F. malformed RESPONSES through the production decoder ════════════ */

enum { RV_OK = 0, RV_FALSE_WITH_V, RV_TRUE_NO_V, RV_DUP_V, RV_DUP_H, RV_NO_CP,
       RV_RES_SHORT, RV_SHORT_LR, RV_EMPTY_NODE, RV_BIG_NODE, RV_BAD_STEP,
       RV_DUP_F };

static size_t mkresp(uint8_t *buf, size_t cap, int variant, size_t n_nodes) {
    cbor_encoder_t e;
    uint8_t v64[64], head[89], luh[64], big[1061];
    memset(v64, 0x11, sizeof(v64)); memset(head, 0x22, sizeof(head));
    memset(luh, 0x33, sizeof(luh)); memset(big, 0x44, sizeof(big));
    size_t rcount = 5 + (variant == RV_DUP_H ? 1 : 0) - (variant == RV_NO_CP);
    cbor_encoder_init(&e, buf, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 7);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_state_proof");
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, rcount);
    cbor_encode_cstr(&e, "h"); cbor_encode_uint(&e, 1000);
    if (variant == RV_DUP_H) { cbor_encode_cstr(&e, "h"); cbor_encode_uint(&e, 1001); }
    cbor_encode_cstr(&e, "lr");
    cbor_encode_bstr(&e, v64, variant == RV_SHORT_LR ? 63 : 64);
    cbor_encode_cstr(&e, "nodes"); cbor_encode_array(&e, n_nodes);
    for (size_t i = 0; i < n_nodes; i++) {
        uint8_t one = (uint8_t)i;
        if (i == 0 && variant == RV_EMPTY_NODE) cbor_encode_bstr(&e, &one, 0);
        else if (i == 0 && variant == RV_BIG_NODE) cbor_encode_bstr(&e, big, 1061);
        else cbor_encode_bstr(&e, &one, 1);
    }
    cbor_encode_cstr(&e, "res");
    cbor_encode_array(&e, variant == RV_RES_SHORT ? 1 : 2);
    if (variant == RV_FALSE_WITH_V) {
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, false);
        cbor_encode_cstr(&e, "v"); cbor_encode_bstr(&e, v64, 64);
    } else if (variant == RV_DUP_F) {
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, false);
        cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, false);
    } else {
        cbor_encode_map(&e, 1);
        cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, false);
    }
    if (variant != RV_RES_SHORT) {
        if (variant == RV_TRUE_NO_V) {
            cbor_encode_map(&e, 1);
            cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, true);
        } else if (variant == RV_DUP_V) {
            cbor_encode_map(&e, 3);
            cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, true);
            cbor_encode_cstr(&e, "v"); cbor_encode_bstr(&e, v64, 64);
            cbor_encode_cstr(&e, "v"); cbor_encode_bstr(&e, v64, 64);
        } else {
            cbor_encode_map(&e, 2);
            cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, true);
            cbor_encode_cstr(&e, "v"); cbor_encode_bstr(&e, v64, 64);
        }
    }
    if (variant != RV_NO_CP) {
        uint8_t tag[16];
        memset(tag, 0x55, sizeof(tag));
        cbor_encode_cstr(&e, "cp"); cbor_encode_array(&e, 1);
        if (variant == RV_BAD_STEP) {      /* a COMPOSE step without "legs" */
            cbor_encode_map(&e, 3);
            cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 1);
            cbor_encode_cstr(&e, "tag"); cbor_encode_bstr(&e, tag, 16);
            cbor_encode_cstr(&e, "i"); cbor_encode_uint(&e, 0);
        } else {
            cbor_encode_map(&e, 3);
            cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 2);
            cbor_encode_cstr(&e, "head"); cbor_encode_bstr(&e, head, 89);
            cbor_encode_cstr(&e, "luh"); cbor_encode_bstr(&e, luh, 64);
        }
    }
    return cbor_encoder_len(&e);
}

static int resp_case(const char *what, int variant, size_t n_nodes,
                     int want_ok) {
    const size_t cap = 256 * 1024;
    uint8_t *buf = malloc(cap);
    nodus_dnac_state_proof_t *p = malloc(sizeof(*p));
    CHECK(buf && p, "allocation");
    size_t len = mkresp(buf, cap, variant, n_nodes);
    CHECK(len > 0, "the response frame encodes");
    int rc = nodus_dnac_state_proof_decode(buf, len, 2, p);
    int good = want_ok ? rc == 0 && p->n_nodes == n_nodes && p->n_res == 2 &&
                         p->found[0] == 0 && p->found[1] == 1
                       : rc == -1 && p->nodes == NULL && p->n_nodes == 0;
    if (rc == 0) nodus_dnac_state_proof_free(p);
    free(buf);
    free(p);
    if (!good) fprintf(stderr, "response case failed: %s (rc %d)\n", what, rc);
    CHECK(good, what);
    return 0;
}

static int test_response_decode(void) {
    if (resp_case("a well-formed response", RV_OK, 3, 1)) return 1;
    if (resp_case("f = false with a v is refused", RV_FALSE_WITH_V, 3, 0)) return 1;
    if (resp_case("f = true without a v is refused", RV_TRUE_NO_V, 3, 0)) return 1;
    if (resp_case("f = true with a repeated v is refused", RV_DUP_V, 3, 0)) return 1;
    if (resp_case("a repeated f is refused", RV_DUP_F, 3, 0)) return 1;
    if (resp_case("a repeated h is refused", RV_DUP_H, 3, 0)) return 1;
    if (resp_case("a missing cp is refused", RV_NO_CP, 3, 0)) return 1;
    if (resp_case("fewer results than keys is refused", RV_RES_SHORT, 3, 0)) return 1;
    if (resp_case("a 63-byte leg root is refused", RV_SHORT_LR, 3, 0)) return 1;
    if (resp_case("an empty node is refused", RV_EMPTY_NODE, 3, 0)) return 1;
    if (resp_case("a 1,061-byte node is refused", RV_BIG_NODE, 3, 0)) return 1;
    if (resp_case("a COMPOSE step without legs is refused", RV_BAD_STEP, 3, 0)) return 1;
    /* the plan's node ceiling 128 x 131 = 16,768 is above the generic CBOR
     * decoder's 4,096 items: this reply's decoder takes the plan's bound */
    if (resp_case("5000 nodes (above NODUS_CBOR_MAX_ITEMS)", RV_OK, 5000, 1))
        return 1;
    if (resp_case("16768 nodes (the plan's ceiling)", RV_OK, 16768, 1)) return 1;
    if (resp_case("16769 nodes is refused", RV_OK, 16769, 0)) return 1;
    return 0;
}

/* ══ F2. the client RECEIVE path: nodus_t2_decode (what client_on_frame calls
 *        first, nodus_client.c:419) takes the plan's node ceiling for the
 *        dnac_state_proof reply only ══════════════════════════════════════ */

static int t2_case(const char *what, int patch_method, size_t n_nodes,
                   int want_ok) {
    const size_t cap = 256 * 1024;
    uint8_t *buf = malloc(cap);
    nodus_tier2_msg_t msg;
    CHECK(buf != NULL, "allocation");
    size_t len = mkresp(buf, cap, RV_OK, n_nodes);
    CHECK(len > 0, "frame");
    if (patch_method) {                  /* "dnac_state_proof" -> "dnac_state_prooG" */
        static const char M[] = "dnac_state_proof";
        for (size_t i = 0; i + 16 <= len; i++)
            if (memcmp(buf + i, M, 16) == 0) { buf[i + 15] = 'G'; break; }
    }
    memset(&msg, 0, sizeof(msg));
    int rc = nodus_t2_decode(buf, len, &msg);
    int good = want_ok ? rc == 0 && msg.type == 'r' && msg.txn_id == 7
                       : rc == -1;
    if (rc == 0) nodus_t2_msg_free(&msg);
    free(buf);
    if (!good) fprintf(stderr, "receive-path case failed: %s (rc %d)\n", what, rc);
    CHECK(good, what);
    return 0;
}

static int test_receive_path(void) {
    if (t2_case("dnac_state_proof reply, 5000 nodes", 0, 5000, 1)) return 1;
    if (t2_case("dnac_state_proof reply, 16768 nodes (the plan's ceiling)", 0,
                16768, 1)) return 1;
    if (t2_case("dnac_state_proof reply, 16769 nodes is refused", 0, 16769,
                0)) return 1;
    /* every other message keeps the generic 4,096-item limit */
    if (t2_case("another method, 4000 nodes (below the generic limit)", 1,
                4000, 1)) return 1;
    if (t2_case("another method, 5000 nodes is refused", 1, 5000, 0)) return 1;
    return 0;
}

/* ══ E2. a real IPC accept and the production delivery ═════════════════ */

static nodus_pubkey_t g_ipc_own;
static const nodus_pubkey_t *ipc_own_pk(void *c) { (void)c; return &g_ipc_own; }

/* Test stubs: nodus_witness_ipc_new refuses a handler table without
 * cc_collect and status (nodus_witness_ipc.c:511). This test sends only
 * `ipc_tool` connections with dnac_state_proof requests, so neither is ever
 * called: cc_collect would serve dnac_cc_collect, status the control
 * connection's ipc_status. They do nothing. */
static void ipc_cc_collect_stub(void *ctx, struct nodus_tcp_conn *conn,
                                const uint8_t client_pk[NODUS_PK_BYTES],
                                const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                const uint8_t *payload, size_t len,
                                uint32_t txn_id) {
    (void)ctx; (void)conn; (void)client_pk; (void)token; (void)payload;
    (void)len; (void)txn_id;
}

static void ipc_status_stub(void *ctx, nodus_witness_ipc_status_t *out) {
    (void)ctx; (void)out;
}

typedef struct {
    nodus_witness_t *w;
    int64_t          now;
    int              calls;
    int              slot[4];
    uint64_t         serial[4];
} ipc_ctx_t;

static void ipc_dispatch(void *ctx, struct nodus_tcp_conn *conn,
                         const uint8_t *payload, size_t len,
                         const char *method, uint32_t txn) {
    ipc_ctx_t *c = ctx;
    (void)method;
    if (c->calls < 4) {
        c->slot[c->calls] = conn->slot;
        c->serial[c->calls] = (uint64_t)(uintptr_t)conn->user_data;
    }
    c->calls++;
    c->now += 2000000000LL;
    nodus_witness_state_proof_handle(c->w, conn, payload, len, txn, c->now);
}

typedef struct { int frames; uint32_t txn; int is_reply; } ipc_cli_t;

static void ipc_cli_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                          size_t len, void *ctx) {
    ipc_cli_t *c = ctx;
    nodus_tier2_msg_t m;
    (void)conn;
    memset(&m, 0, sizeof(m));
    c->frames++;
    if (nodus_t2_decode(payload, len, &m) == 0) {
        c->txn = m.txn_id;
        c->is_reply = m.type == 'r';
    }
    nodus_t2_msg_free(&m);
}

static void ipc_pump(nodus_witness_ipc_t *ipc, nodus_tcp_t *a, int rounds) {
    for (int i = 0; i < rounds; i++) {
        nodus_witness_ipc_poll(ipc, 5);
        if (a) nodus_tcp_poll(a, 5);
    }
}

/* A bounded wait for an expected asynchronous state: `want` answers are
 * PUBLISHED (JOB_DONE, set under the service mutex after the answer is
 * stored), so the next poll delivers exactly those. The wait fails (0) when
 * that state never arrives; it is a wait on the state itself, not on the
 * builds_done counter, which is incremented BEFORE the answer is published. */
static int wait_published(nodus_witness_t *w, size_t want) {
    for (int i = 0; i < 4000; i++) {
        if (nodus_state_proof_service_published(w->state_proof) >= want)
            return 1;
        usleep(5000);
    }
    return 0;
}

static int test_ipc_delivery(fixture_t *fx, const rows_t *rows) {
    char sock[200];
    uint8_t first[64], f11[8192], f22[8192];
    size_t n_first = 0, l11 = 0, l22 = 0, np = 0;
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    nodus_state_proof_limits_t lim = { 2, 1000 };
    ipc_ctx_t ic;
    nodus_tcp_t cli1, cli2;
    ipc_cli_t s1, s2;
    CHECK(req != NULL, "allocation");
    snprintf(sock, sizeof(sock), "%s/witness.sock", fx->dir);
    memset(token, 0, sizeof(token));
    memset(&ic, 0, sizeof(ic));
    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    for (int i = 0; i < NODUS_PK_BYTES; i++) g_ipc_own.bytes[i] = (uint8_t)(i * 7 + 3);

    pick_keys(2, &rows[2], 3, 4, req, &np);
    {
        const uint8_t *kp[NODUS_STATE_PROOF_MAX_KEYS];
        for (size_t i = 0; i < req->n_keys; i++) kp[i] = req->keys[i];
        CHECK(nodus_dnac_state_proof_request_encode(11, token, req->leg, kp,
                  req->key_len, req->n_keys, f11, sizeof(f11), &l11) == 0 &&
              nodus_dnac_state_proof_request_encode(22, token, req->leg, kp,
                  req->key_len, req->n_keys, f22, sizeof(f22), &l22) == 0,
              "the two request frames");
    }
    {   /* {"q": "ipc_tool"} */
        cbor_encoder_t e;
        cbor_encoder_init(&e, first, sizeof(first));
        cbor_encode_map(&e, 1);
        cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, NODUS_WITNESS_IPC_Q_TOOL);
        n_first = cbor_encoder_len(&e);
        CHECK(n_first > 0, "first frame");
    }

    CHECK(nodus_witness_state_proof_enable(fx->w, &lim) == 0,
          "the service is enabled on the witness (the test's own limits)");
    ic.w = fx->w;
    nodus_witness_ipc_handlers_t h;
    memset(&h, 0, sizeof(h));
    h.dispatch_dnac = ipc_dispatch;
    h.cc_collect = ipc_cc_collect_stub;
    h.status = ipc_status_stub;
    h.own_pk = ipc_own_pk;
    h.ctx = &ic;
    nodus_witness_ipc_t *ipc = nodus_witness_ipc_new_tools(&h);
    CHECK(ipc != NULL && nodus_witness_ipc_listen(ipc, sock) == 0,
          "a real IPC listener");

    /* client 1 asks, then goes away before the answer is delivered */
    CHECK(nodus_tcp_init(&cli1, -1) == 0, "client transport");
    cli1.on_frame = ipc_cli_frame;
    cli1.cb_ctx = &s1;
    nodus_tcp_conn_t *c1 = nodus_tcp_unix_connect(&cli1, sock,
                                                  NODUS_TCP_UNIX_UID_SELF);
    CHECK(c1 != NULL, "client 1 connects");
    nodus_tcp_send(c1, first, n_first);
    nodus_tcp_send(c1, f11, l11);
    ipc_pump(ipc, &cli1, 30);
    CHECK(ic.calls == 1 && ic.serial[0] != 0, "the request reached the "
          "dispatcher on an accepted connection with an accept serial");
    CHECK(wait_published(fx->w, 1), "the first answer is published");
    nodus_tcp_close(&cli1);                       /* disconnect, NOT polled */
    ipc_pump(ipc, NULL, 40);                      /* the listener sees EOF  */

    /* client 2 connects: a NEW connection in the same slot */
    CHECK(nodus_tcp_init(&cli2, -1) == 0, "client 2 transport");
    cli2.on_frame = ipc_cli_frame;
    cli2.cb_ctx = &s2;
    nodus_tcp_conn_t *c2 = nodus_tcp_unix_connect(&cli2, sock,
                                                  NODUS_TCP_UNIX_UID_SELF);
    CHECK(c2 != NULL, "client 2 connects");
    nodus_tcp_send(c2, first, n_first);
    nodus_tcp_send(c2, f22, l22);
    ipc_pump(ipc, &cli2, 30);
    CHECK(ic.calls == 2, "client 2's request reached the dispatcher");
    CHECK(ic.slot[0] == ic.slot[1],
          "slot reuse is real: the replacement connection sits in the slot "
          "of the one that asked first");
    CHECK(ic.serial[1] != 0 && ic.serial[1] != ic.serial[0],
          "the replacement carries another accept serial (generation is 0 "
          "on this transport)");
    CHECK(wait_published(fx->w, 2), "both answers are published");

    /* the production delivery: the old answer must NOT reach client 2 */
    nodus_witness_state_proof_poll(fx->w);          /* the ONE delivery */
    for (int i = 0; i < 4000 && s2.frames < 1; i++)  /* bounded, then asserts */
        ipc_pump(ipc, &cli2, 1);
    ipc_pump(ipc, &cli2, 40);        /* anything sent by the same poll too */
    CHECK(s2.frames == 1 && s2.is_reply && s2.txn == 22,
          "client 2 received exactly its own answer (txn 22), not the answer "
          "of the connection that asked before it");
    ipc_pump(ipc, &cli2, 20);
    CHECK(s2.frames == 1, "nothing more arrives");

    nodus_tcp_close(&cli2);
    nodus_witness_ipc_free(ipc);
    nodus_witness_state_proof_disable(fx->w);
    free(req);
    return 0;
}

/* ══ G. one snapshot per answer; the stored anchor; resolution faults ═════ */

typedef struct {
    fixture_t *fx;
    int        ran;
    int        rc;
} hook_t;

/* between the committed-height read and the legs of the build, a COMMITTED
 * change on the writer connection: a token row is deleted, flushed through
 * the production flush, and the fixture anchor rewritten */
static void snapshot_hook(void *p) {
    hook_t *h = p;
    h->ran = 1;
    h->rc = run_sql(h->fx->w->db, "BEGIN") == 0 &&
            run_sql(h->fx->w->db, "DELETE FROM tokens WHERE rowid = "
                    "(SELECT MIN(rowid) FROM tokens)") == 0 &&
            nodus_witness_v2_trie_flush(h->fx->w) == 0 &&
            run_sql(h->fx->w->db, "COMMIT") == 0 &&
            make_consistent(h->fx->w) == 0 ? 0 : -1;
}

static int test_snapshot_and_anchor(fixture_t *fx) {
    uint64_t tip = 0, tip2 = 0;
    uint8_t app_old[64], app_new[64];
    rows_t old_rows, new_rows;
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    uint8_t *frame = NULL, *frame2 = NULL, *frame3 = NULL;
    size_t flen = 0, flen2 = 0, flen3 = 0, np = 0;
    int ec = 0;
    char em[96];
    memset(&old_rows, 0, sizeof(old_rows));
    memset(&new_rows, 0, sizeof(new_rows));
    CHECK(req != NULL, "allocation");
    nodus_witness_t *ctx = nodus_state_proof_ctx_open(db_path(fx));
    CHECK(ctx != NULL, "context");

    /* the stored tip root is the anchor: a stored root that disagrees with
     * the recomputation is refused, never trusted either way */
    CHECK(tip_global(fx->w->db, &tip, app_old) == 0, "the tip");
    CHECK(nodus_witness_v2_trie_scan_leg(fx->w, 2, rows_cb, &old_rows) == 0 &&
          old_rows.n >= 30, "the token rows");
    pick_keys(2, &old_rows, 6, 8, req, &np);
    CHECK(run_sql(fx->w->db, "UPDATE v2_blocks SET global_root = "
                  "CAST(zeroblob(64) AS BLOB) WHERE global_height = "
                  "(SELECT MAX(global_height) FROM v2_blocks)") == 0,
          "corrupt the stored tip root");
    CHECK(nodus_state_proof_build(ctx, req, 5, &frame, &flen, NULL, &ec, em,
                                  sizeof(em)) == -1 && frame == NULL &&
          ec == NODUS_ERR_INTERNAL_ERROR,
          "a stored tip root that disagrees with the recomputation: refused");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx->w->db, "UPDATE v2_blocks SET global_root "
                  "= ?1 WHERE global_height = ?2", -1, &st, NULL) == SQLITE_OK &&
              bind_blob(st, 1, app_old, 64) == SQLITE_OK &&
              sqlite3_bind_int64(st, 2, (sqlite3_int64)tip) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_DONE, "restore the stored tip root");
        sqlite3_finalize(st);
    }

    /* one snapshot: the committed change lands after the height was read */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_int64 jm = -1;
        CHECK(sqlite3_prepare_v2(fx->w->db, "PRAGMA journal_mode=WAL", -1, &st,
                                 NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW, "journal mode");
        CHECK(strcmp((const char *)sqlite3_column_text(st, 0), "wal") == 0,
              "the fixture database is in WAL mode (a writer commits while "
              "a reader holds its snapshot)");
        (void)jm;
        sqlite3_finalize(st);
    }
    hook_t hk = { fx, 0, 0 };
    nodus_state_proof_set_stage_hook(snapshot_hook, &hk);
    int brc = nodus_state_proof_build(ctx, req, 5, &frame2, &flen2, NULL, &ec,
                                      em, sizeof(em));
    nodus_state_proof_set_stage_hook(NULL, NULL);
    CHECK(hk.ran == 1 && hk.rc == 0, "the writer committed between the stages");
    CHECK(brc == 0 && frame2, "the build in its snapshot succeeds");
    CHECK(verify_frame(req, frame2, flen2, app_old, tip, &old_rows, np,
                       DMG_NONE, 0) == 0,
          "the answer is wholly the OLD snapshot: the old height, the old "
          "legs, the old AppHash (a build without the read transaction "
          "would mix the old height with the new legs)");

    /* a build after the commit sees the new state */
    CHECK(tip_global(fx->w->db, &tip2, app_new) == 0 && tip2 == tip &&
          memcmp(app_new, app_old, 64) != 0, "the committed change moved the "
          "anchor");
    CHECK(nodus_witness_v2_trie_scan_leg(fx->w, 2, rows_cb, &new_rows) == 0 &&
          new_rows.n + 1 == old_rows.n, "one token row less");
    pick_keys(2, &new_rows, 6, 8, req, &np);
    CHECK(nodus_state_proof_build(ctx, req, 5, &frame3, &flen3, NULL, &ec, em,
                                  sizeof(em)) == 0 && frame3, "a new build");
    CHECK(verify_frame(req, frame3, flen3, app_new, tip, &new_rows, np,
                       DMG_NONE, 0) == 0, "...verifies to the new AppHash");
    CHECK(verify_frame(req, frame3, flen3, app_old, tip, &new_rows, np,
                       DMG_NONE, 0) == 1, "...and not to the old one");
    free(frame); free(frame2); free(frame3);
    rows_free(&old_rows); rows_free(&new_rows);
    free(req);
    nodus_state_proof_ctx_close(ctx);
    return 0;
}

/* A chain with NO populated rows: its tip root was produced by the real
 * blocks of the ladder (the edge block A - 1), never rewritten here. The
 * service's recomputation from the legs must equal it. Also: a SYSTEM runtime
 * that cannot be resolved is a fault (INTERNAL), not "below generation 6". */
static int test_block_anchor(void) {
    fixture_t fx;
    uint64_t tip = 0;
    uint8_t app[64];
    CHECK(fx_open(&fx, "blk") == 0, "a ladder chain");
    for (uint64_t h = 1; h <= HA - 1u; h++)
        CHECK(apply_block(&fx, h) == 0, "block");
    CHECK(committed_gen(fx.w) == NODUS_RT_GEN_TRIE, "generation 6 committed");
    CHECK(tip_global(fx.w->db, &tip, app) == 0 && tip == HA - 1u,
          "the tip row written by the edge block");
    nodus_witness_t *ctx = nodus_state_proof_ctx_open(db_path(&fx));
    nodus_state_proof_req_t *req = malloc(sizeof(*req));
    CHECK(ctx && req, "context");
    for (int leg = 1; leg <= 8; leg++) {
        rows_t rows;
        size_t np = 0;
        uint8_t *frame = NULL;
        size_t flen = 0;
        int ec = 0;
        char em[96];
        memset(&rows, 0, sizeof(rows));
        CHECK(nodus_witness_v2_trie_scan_leg(fx.w, leg, rows_cb, &rows) == 0,
              "scan");
        pick_keys(leg, &rows, 4, 6, req, &np);
        if (nodus_state_proof_build(ctx, req, 3, &frame, &flen, NULL, &ec, em,
                                    sizeof(em)) != 0) {
            fprintf(stderr, "leg %d: the build on the block-produced anchor "
                    "failed (%d: %s)\n", leg, ec, em);
            return 1;
        }
        CHECK(verify_frame(req, frame, flen, app, tip, &rows, np, DMG_NONE,
                           rows.n == 0) == 0,
              "the proof verifies to the tip root the BLOCKS produced");
        free(frame);
        rows_free(&rows);
    }
    /* resolution fault: the domain registry cannot be read */
    CHECK(run_sql(fx.w->db, "ALTER TABLE domain_registry RENAME TO "
                  "domain_registry_x") == 0, "hide the registry");
    {
        uint8_t *frame = NULL;
        size_t flen = 0, np = 0;
        int ec = 0;
        char em[96];
        rows_t rows;
        memset(&rows, 0, sizeof(rows));
        pick_keys(1, &rows, 0, 1, req, &np);
        CHECK(nodus_state_proof_build(ctx, req, 3, &frame, &flen, NULL, &ec,
                                      em, sizeof(em)) == -1 &&
              ec == NODUS_ERR_INTERNAL_ERROR,
              "a SYSTEM runtime that cannot be resolved is INTERNAL_ERROR, "
              "not NOT_FOUND");
    }
    CHECK(run_sql(fx.w->db, "ALTER TABLE domain_registry_x RENAME TO "
                  "domain_registry") == 0, "restore the registry");
    free(req);
    nodus_state_proof_ctx_close(ctx);
    fx_close(&fx);
    return 0;
}

/* ══ D. the cost measurement ═══════════════════════════════════════════ */

/* a read-only node store for counting path nodes (this test's own, over the
 * reader context's connection) */
typedef struct { sqlite3_stmt *st; } pstore_t;

static int pstore_get(void *c, const uint8_t d[64], uint8_t **rlp, size_t *len) {
    pstore_t *s = c;
    sqlite3_reset(s->st);
    if (sqlite3_bind_blob(s->st, 1, d, 64, SQLITE_TRANSIENT) != SQLITE_OK)
        return -2;
    int rc = sqlite3_step(s->st);
    if (rc == SQLITE_DONE) return 1;
    if (rc != SQLITE_ROW) return -2;
    int n = sqlite3_column_bytes(s->st, 0);
    if (n <= 0) return -2;
    uint8_t *p = malloc((size_t)n);
    if (!p) return -2;
    memcpy(p, sqlite3_column_blob(s->st, 0), (size_t)n);
    *rlp = p;
    *len = (size_t)n;
    return 0;
}

static int pstore_put(void *c, const uint8_t d[64], const uint8_t *r, size_t n) {
    (void)c; (void)d; (void)r; (void)n;
    return -2;
}

typedef struct { size_t depth, idx; } depth_t;

static int depth_cmp(const void *a, const void *b) {
    const depth_t *x = a, *y = b;
    if (x->depth != y->depth) return x->depth < y->depth ? 1 : -1;  /* desc */
    return x->idx < y->idx ? -1 : x->idx > y->idx;                  /* asc  */
}

/* The request of the 128 rows with the most nodes on their proof path; the
 * count of path nodes of every row is measured by proving it. `*max_path` is
 * the largest per-key path, `*sum_bound` the sum of the 128 largest (an upper
 * bound on the nodes of any 128-present-key request). 0 / -1. */
static int deepest_request(nodus_witness_t *ctx, int leg, const rows_t *r,
                           nodus_state_proof_req_t *req, size_t *n_present,
                           size_t *max_path, size_t *sum_bound) {
    uint8_t lr[64];
    pstore_t ps = { NULL };
    depth_t *d = r->n ? malloc(r->n * sizeof(*d)) : NULL;
    int rc = -1;
    *max_path = *sum_bound = 0;
    if ((r->n && !d) || nodus_witness_v2_trie_leg_root(ctx, leg, lr) != 0 ||
        sqlite3_prepare_v2(ctx->db,
            "SELECT rlp FROM v2_trie_nodes WHERE digest = ?1", -1, &ps.st,
            NULL) != SQLITE_OK)
        goto out;
    {
        evm_trie_store_t st = { &ps, pstore_get, pstore_put };
        for (size_t i = 0; i < r->n; i++) {
            uint8_t path[64];
            evm_trie_proof_set_t s = {0};
            if (evm_trie_proof_path_of_key(r->key[i], r->klen[i], path) != 0 ||
                evm_trie_prove_path(&st, lr, path, &s) != 0) {
                evm_trie_proof_set_free(&s);
                goto out;
            }
            d[i].depth = s.n;
            d[i].idx = i;
            evm_trie_proof_set_free(&s);
        }
    }
    if (r->n) qsort(d, r->n, sizeof(*d), depth_cmp);
    memset(req, 0, sizeof(*req));
    req->leg = leg;
    size_t np = r->n < 128 ? r->n : 128;
    for (size_t i = 0; i < np; i++) {
        memcpy(req->keys[req->n_keys], r->key[d[i].idx], r->klen[d[i].idx]);
        req->key_len[req->n_keys] = r->klen[d[i].idx];
        req->n_keys++;
        *sum_bound += d[i].depth;
        if (d[i].depth > *max_path) *max_path = d[i].depth;
    }
    *n_present = np;
    for (uint32_t j = 0; req->n_keys < 128; j++) {
        req->key_len[req->n_keys] = absent_key(leg, j, req->keys[req->n_keys]);
        req->n_keys++;
    }
    rc = 0;
out:
    if (ps.st) sqlite3_finalize(ps.st);
    free(d);
    return rc;
}

/* three timed builds of `req` and one COST line */
static int time_request(const char *name, int leg, const char *label,
                        const char *path, nodus_witness_t *ctx,
                        const nodus_state_proof_req_t *req, size_t np,
                        size_t rows) {
    double ts[3], cold = -1.0;
    nodus_state_proof_stats_t st;
    memset(&st, 0, sizeof(st));
    {   /* one build on a FRESH reader connection (empty SQLite page cache and
         * statement cache; the operating system's file cache is whatever the
         * run left - this is not a drop-caches measurement) */
        nodus_witness_t *fresh = nodus_state_proof_ctx_open(path);
        uint8_t *frame = NULL;
        size_t flen = 0;
        int ec = 0;
        char em[96];
        double a = now_ms();
        if (!fresh || nodus_state_proof_build(fresh, req, 1, &frame, &flen,
                                              NULL, &ec, em, sizeof(em)) != 0) {
            fprintf(stderr, "measure: leg %d %s fresh-connection build "
                    "failed\n", leg, label);
            nodus_state_proof_ctx_close(fresh);
            return 1;
        }
        cold = now_ms() - a;
        free(frame);
        nodus_state_proof_ctx_close(fresh);
    }
    for (int i = 0; i < 3; i++) {
        uint8_t *frame = NULL;
        size_t flen = 0;
        int ec = 0;
        char em[96];
        double a = now_ms();
        if (nodus_state_proof_build(ctx, req, 1, &frame, &flen, &st, &ec, em,
                                    sizeof(em)) != 0) {
            fprintf(stderr, "measure: leg %d %s build failed (%d: %s)\n", leg,
                    label, ec, em);
            return 1;
        }
        ts[i] = now_ms() - a;
        free(frame);
    }
    printf("COST size=%s leg=%d request=%s rows=%zu keys=%zu present=%zu "
           "nodes_loaded=%zu nodes=%zu frame_bytes=%zu "
           "build_ms_fresh_connection=%.1f "
           "build_ms_same_connection_after_path_counting=[%.1f %.1f %.1f]\n",
           name, leg, label, rows, req->n_keys, np, st.nodes_loaded, st.nodes,
           st.frame_bytes, cold, ts[0], ts[1], ts[2]);
    return 0;
}

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
               "(the first run is on the fresh reader connection the "
               "measurement opened; the OS file cache is warm)\n", name, ts[0],
               ts[1], ts[2]);
    }
    for (int leg = 1; leg <= 8; leg++) {
        rows_t rows;
        size_t np = 0;
        memset(&rows, 0, sizeof(rows));
        if (nodus_witness_v2_trie_scan_leg(fx.w, leg, rows_cb, &rows) != 0) {
            fx_close(&fx);
            return 1;
        }
        /* Two requests per leg. (1) "deepest": EVERY row of the leg is proved
         * once to count the nodes on its path; the 128 rows with the most
         * path nodes are requested (all rows if the leg has fewer, the rest
         * absent). The sum of the 128 largest path lengths is an UPPER BOUND
         * on the nodes any 128-present-key request can touch (shared nodes
         * are counted once, so the request itself touches at most that
         * many); the measured request is the deepest-paths request, NOT a
         * proven maximum of the build time. (2) "absent128": 128 absent keys
         * of the leg's key shape, a fixed sample: the depth of absent paths
         * is not enumerated, so this line is a sample, not a bound. */
        size_t max_path = 0, sum_bound = 0;
        if (deepest_request(ctx, leg, &rows, req, &np, &max_path,
                            &sum_bound) != 0) {
            fprintf(stderr, "measure: leg %d path counting failed\n", leg);
            rows_free(&rows);
            fx_close(&fx);
            return 1;
        }
        printf("COST size=%s leg=%d selection=deepest_paths rows_counted=%zu "
               "path_nodes_max=%zu path_nodes_sum_upper_bound=%zu\n", name,
               leg, rows.n, max_path, sum_bound);
        if (time_request(name, leg, "deepest", db_path(&fx), ctx, req, np,
                         rows.n) != 0) {
            rows_free(&rows);
            fx_close(&fx);
            return 1;
        }
        pick_keys(leg, &rows, 0, 128, req, &np);
        if (time_request(name, leg, "absent128", db_path(&fx), ctx, req, np,
                         rows.n) != 0) {
            rows_free(&rows);
            fx_close(&fx);
            return 1;
        }
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
    if (test_request_limits() != 0) return 1;
    if (test_response_decode() != 0) return 1;
    if (test_receive_path() != 0) return 1;
    if (test_conn_identity() != 0) return 1;
    if (test_below_generation_6() != 0) return 1;
    if (test_block_anchor() != 0) return 1;

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
        if (!rc) rc = test_ipc_delivery(&fx, rows);
        if (!rc) rc = test_snapshot_and_anchor(&fx);   /* mutates the chain */
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
