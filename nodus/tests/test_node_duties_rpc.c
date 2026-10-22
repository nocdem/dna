/**
 * @file nodus/tests/test_node_duties_rpc.c
 * @brief dnac_node_duties (packages design docs/plans/2026-10-22-nodus-
 *        packages-design.md §3) driven through the REAL dispatcher
 *        (nodus_witness_handle_dnac) over a socketpair against a planted
 *        version-3 schema, and the client SDK's decoder
 *        (nodus_dnac_node_duties_decode) over the bytes the node answers
 *        and over crafted replies.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 * Governing records: the design above; decisions 2026-10-22-nodus-
 * packages-add-remove.md and 2026-10-22-kurultay-36-summary.md; wire:
 * include/nodus/nodus.h beside nodus_client_dnac_node_duties. With
 * E = DNAC_EPOCH_LENGTH and the planted tip T = 3E + 1 (B = 3E):
 *  t_auth        a session authenticated as ANOTHER key, and one with no
 *                authenticated identity, get NODUS_ERR_NOT_AUTHENTICATED
 *                and no state; the node's own key is answered.
 *  t_clear       no row, no seat, no storage row: state CLEAR, no blocker,
 *                no owner; ch = T, cid / bh = the planted values; fresh
 *                false with its inputs (no reactor: ws 0, cs 0, np 0,
 *                mph 0) and the decoder accepts the bytes.
 *  t_witness     a validators row with the node's key: ACTIVE ->
 *                WITNESS_REGISTERED (eh 0, the owner listed); RETIRING ->
 *                WITNESS_LEAVING with eh = B + E, and B + 2E once the key
 *                is an entry of the frozen snapshot(B + E) (which also
 *                gives SEATED_NEXT); UNSTAKED -> no WITNESS_* blocker.
 *  t_seated      the key an entry of snapshot(B) -> SEATED_NOW, eh B + E;
 *                of snapshot(B + E) alone -> SEATED_NEXT, eh B + 2E.
 *  t_transition  at tip B - 1 and B (T + 1 in {B, B + 1}) with the key an
 *                entry of snapshot(B - E) -> CMT_TRANSITION, eh B + 1; at
 *                T = 3E + 1 (T + 1 = B + 2) the same snapshot gives none.
 *  t_storage     the node's storage row ACTIVE -> STORAGE_REGISTERED (eh 0,
 *                payee listed); EXITING -> STORAGE_LEAVING with eh = the
 *                first multiple of E >= T + 1; RELEASED -> none.
 *  t_overlap     the node displaced from storage_set(2E) by storage_set(3E)
 *                with a published segment it was assigned -> ARCHIVE_
 *                OVERLAP, eh H + E (H = 3E); a member of storage_set(3E)
 *                as well -> eh H + 2E.
 *  t_report      the node seat 1 of snapshot(2E) (P = B - E), storage_set(
 *                2E) non-empty, the report window open, no report (2E, 1)
 *                -> STORAGE_REPORT with eh P + E + E/2; the report planted
 *                -> none.
 *  t_faults      a snapshot that must exist missing, and the storage
 *                registry table gone -> a SUCCESS reply with state UNKNOWN, a
 *                "why", no blocker and no owner (never CLEAR).
 *  t_next_snapshot  snapshot(B + E) absent: while T + 1 = B (block B, which
 *                freezes it, is not committed) it is "not an entry" (CLEAR;
 *                a RETIRING row still ends at B + E); at T + 1 > B it is a
 *                fault (UNKNOWN with a why, for the seat check and for the
 *                leaving row alike). The base fixture therefore plants
 *                snapshot(4E) at T = 3E + 1.
 *  t_storage_sets  with chain_config param 18 (the storage activation)
 *                planted: storage_set(H = 3E) absent and the param in
 *                effect at H -> UNKNOWN; storage_set(P = 2E) absent, the
 *                node a seat of snapshot(P) and the param in effect at P ->
 *                UNKNOWN; the same absences with the param not yet in effect
 *                (activation after H, or at H for P) or not planted at all
 *                -> no duty (CLEAR); with the sets planted the real answer
 *                (STORAGE_REPORT) comes back.
 *  t_prev_set    archive overlap also reads storage_set(H - E) (H = 3E):
 *                set(H) planted, set(H - E) absent and param 18 in effect at
 *                H - E -> UNKNOWN ("previous epoch" in the why); param 18 in
 *                effect only from H -> CLEAR; with set(H - E) planted ->
 *                CLEAR.
 *                NOT TESTED: st_status_row's sqlite3_bind_blob failure
 *                branch. The statement has one parameter and a fixed 64-byte
 *                blob, so a bind cannot be made to fail from this fixture
 *                (no fault injection hook, no allocator failure); the
 *                branch is covered by reading only.
 *  t_readonly    sqlite3_total_changes of the witness database is the same
 *                before and after EVERY handler call above.
 *  t_decoder     crafted replies: a valid one for each state decodes; a
 *                duplicate key, a missing key, a wrong width (cid 31, bh
 *                63, owner 127 chars), "fresh" not equal to its inputs,
 *                blockers out of order / a code outside 1..9 / eh 0 on a
 *                non-registered code / eh <= ch, CLEAR with a blocker,
 *                BLOCKED without one, UNKNOWN without "why", a "why" on a
 *                non-UNKNOWN state, owners not ascending, np / mph
 *                disagreeing are all refused (-1, `out` zeroed); an unknown
 *                key is skipped.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (register_witness_test:
 * NODUS_WITNESS_INTERNAL_API, links libnodus — the decoder is public). The
 * cases are written against the symbolic DNAC_EPOCH_LENGTH (E >= 8 for the
 * report window case: T + 1 = 3E + 2 must lie in (3E, 3E + E/2]).
 * Environment: none. No network: one AF_UNIX socketpair per fixture.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_node_duties_rpc_*` directory per fixture (the chain
 * database), removed at close; left behind when a CHECK aborts.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. Rows are planted by SQL / the module's own writers; no STAKE,
 *     STORAGE_REGISTER, boundary or report transaction is applied. The
 *     snapshots are ruleset-1 snapshots of two keys (the node's and a
 *     filler), planted through nodus_witness_vset_insert.
 *  2. There is no consensus reactor in the fixture: `fresh` is exercised
 *     only as "false with zero inputs"; the peer-table read (cmt_conr
 *     peers[], cmt_ps_get_round_state) is NOT driven by any case. The
 *     decoder's fresh-equals-inputs rule is pinned over crafted replies.
 *  3. ARCHIVE_OVERLAP depends on nodus_witness_storage_holders placing a
 *     one-member set's only member among the holders of a segment (the
 *     header says R = 3 holders over the set); the case would fail rather
 *     than lie if that were not so.
 *  4. The "a second block is committed while reading" arm (tip read twice)
 *     is not drivable on the one thread; it is not tested.
 *  5. The client request function (nodus_client_dnac_node_duties) is not
 *     round-tripped (no client session); its decoder is, over the node's
 *     real bytes.
 *  6. Nothing here was RUN by its author (BUILDER: compile only). Every
 *     expectation is an expectation.
 *  7. The sqlite3_bind_* return-code checks (validators query, block-id
 *     query) are not driven: a bind fails only on SQLITE_RANGE / NOMEM,
 *     which a fixture cannot provoke. The storage-set rule is written
 *     against the chain_config table the real boundary reads (param 18);
 *     the boundary itself (st_freeze) is not run here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sqlite3.h>

#include "nodus/nodus.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_host.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_produce.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_roots_v2.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"

static int g_checks = 0;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        g_checks++;                                                       \
    } while (0)

#define E_LEN  ((uint64_t)DNAC_EPOCH_LENGTH)

static void hex64(const uint8_t raw[64], char out[129])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 0x0F];
    }
    out[128] = '\0';
}

/* ── fixture: a version-3 schema, the node's identity, a session ─────── */

typedef struct {
    char                 dir[256];
    nodus_witness_t     *w;
    nodus_identity_t    *id;          /* THIS node                       */
    nodus_identity_t    *foreign;     /* another key                     */
    nodus_witness_host_t host;
    uint8_t              other_pk[NODUS_PK_BYTES];   /* a filler key      */
    uint8_t              my_fp[64];
    int                  sv[2];       /* [0] the node's end, [1] ours    */
    nodus_tcp_conn_t    *conn;
} fx_t;

static void run_sql(fx_t *f, const char *sql)
{
    char *err = NULL;
    if (sqlite3_exec(f->w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        printf("SQL failed: %s\n  %s\n", err ? err : "?", sql);
        exit(1);
    }
}

static void fx_open(fx_t *f, const char *tag)
{
    uint8_t seed[32];
    memset(f, 0, sizeof(*f));
    f->sv[0] = f->sv[1] = -1;
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_node_duties_rpc_%s_XXXXXX",
             tag);
    CHECK(mkdtemp(f->dir) != NULL, "mkdtemp");
    f->w = calloc(1, sizeof(*f->w));      /* multi-MB — never the stack */
    f->id = calloc(1, sizeof(*f->id));
    f->foreign = calloc(1, sizeof(*f->foreign));
    CHECK(f->w && f->id && f->foreign, "alloc");
    memset(seed, 0x11, sizeof(seed));
    CHECK(nodus_identity_from_seed(seed, f->id) == 0, "node identity");
    memset(seed, 0x22, sizeof(seed));
    CHECK(nodus_identity_from_seed(seed, f->foreign) == 0, "foreign key");
    CHECK(memcmp(f->id->pk.bytes, f->foreign->pk.bytes, NODUS_PK_BYTES) != 0,
          "two different keys");
    memset(f->other_pk, 0x77, sizeof(f->other_pk));
    CHECK(qgp_sha3_512(f->id->pk.bytes, NODUS_PK_BYTES, f->my_fp) == 0,
          "node fingerprint");

    f->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t chain_id16[16];
    memset(chain_id16, 0x7a, sizeof(chain_id16));
    CHECK(nodus_witness_create_chain_db(f->w, chain_id16) == 0,
          "chain database");
    f->w->v2_successor = 1;
    CHECK(nodus_witness_db_migrate_v2s16(f->w) == 0, "v2 schema");
    /* the chain id the handler reads (the cache contract of
     * nodus_witness_v2_chain_id) */
    memset(f->w->v2_chain32, 0xC1, sizeof(f->w->v2_chain32));
    f->w->v2_chain32_valid = true;

    f->host.identity = f->id;
    f->w->host = (const struct nodus_witness_host *)&f->host;

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0, "socketpair");
    CHECK(fcntl(f->sv[0], F_SETFL, O_NONBLOCK) == 0 &&
          fcntl(f->sv[1], F_SETFL, O_NONBLOCK) == 0, "nonblocking");
    f->conn = calloc(1, sizeof(*f->conn));
    CHECK(f->conn != NULL, "conn alloc");
    f->conn->fd = f->sv[0];
    f->conn->state = NODUS_CONN_CONNECTED;
    /* the session is authenticated as THIS node */
    memcpy(f->conn->peer_pk.bytes, f->id->pk.bytes, NODUS_PK_BYTES);
    f->conn->peer_id_set = true;
}

static void fx_close(fx_t *f)
{
    char cmd[300];
    if (f->conn) {
        free(f->conn->wbuf);
        free(f->conn->rbuf);
        free(f->conn);
    }
    if (f->sv[0] >= 0) close(f->sv[0]);
    if (f->sv[1] >= 0) close(f->sv[1]);
    if (f->w) {
        if (f->w->db) sqlite3_close(f->w->db);
        free(f->w);
    }
    free(f->id);
    free(f->foreign);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->dir);
    if (system(cmd) != 0) printf("note: could not remove %s\n", f->dir);
    memset(f, 0, sizeof(*f));
}

/* ── planting ─────────────────────────────────────────────────────────── */

/* The committed tip: ONE v2_blocks row at height T (MAX(global_height) is
 * the tip; the row's block_id is the "bh" the handler answers). */
static void set_tip(fx_t *f, uint64_t T, uint8_t bh_out[64])
{
    sqlite3_stmt *st = NULL;
    run_sql(f, "DELETE FROM v2_blocks");
    /* the table has a NOT NULL `header` column only on a chain database that
     * went through the S9 rebuild: try the row with it, then without */
    if (sqlite3_prepare_v2(f->w->db,
            "INSERT INTO v2_blocks (global_height, block_id, prev_block_id, "
            "epoch, tx_root, domain_updates_root, domains_root, global_root, "
            "vset_hash, tx_count, header) VALUES (?1, ?2, zeroblob(64), 0, "
            "zeroblob(64), zeroblob(64), zeroblob(64), zeroblob(64), "
            "zeroblob(64), 0, zeroblob(8))", -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        st = NULL;
        CHECK(sqlite3_prepare_v2(f->w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, global_root, vset_hash, tx_count) VALUES "
                "(?1, ?2, zeroblob(64), 0, zeroblob(64), zeroblob(64), "
                "zeroblob(64), zeroblob(64), zeroblob(64), 0)", -1, &st,
                NULL) == SQLITE_OK, "prepare tip");
    }
    memset(bh_out, 0x42, 64);
    for (int i = 0; i < 8; i++) bh_out[i] = (uint8_t)(T >> (8 * i));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)T);
    sqlite3_bind_blob(st, 2, bh_out, 64, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "tip planted");
    sqlite3_finalize(st);
}

/* snapshot(epoch): the filler key first, then the node's key when `me`
 * (so the node is seat 1; seat 0 alone otherwise). Replaces a row. */
static void plant_snapshot(fx_t *f, uint64_t epoch, bool me)
{
    const uint16_t n = me ? 2 : 1;
    dna_vset_snapshot_t *snap = dna_vset_alloc(n);
    CHECK(snap != NULL, "snapshot alloc");
    snap->epoch = epoch;
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &snap->entries[i];
        const uint8_t *pk = i == 0 ? f->other_pk : f->id->pk.bytes;
        uint8_t h[64];
        CHECK(qgp_sha3_512(pk, NODUS_PK_BYTES, h) == 0, "voter id");
        memcpy(e->voter_id, h, DNA_VSET_VOTER_ID_LEN);
        memcpy(e->pubkey, pk, DNA_VSET_PUBKEY_LEN);
        e->total_stake = 1000;
        e->self_bond = 1000;
        e->commission_bps = 500;
    }
    size_t len = dna_vset_encoded_len(snap);
    uint8_t *blob = malloc(len);
    uint8_t hash[DNA_VSET_HASH_LEN];
    size_t written = 0;
    CHECK(blob && len > 0 &&
          dna_vset_encode(snap, blob, len, &written) == 0 && written == len &&
          dna_vset_hash(snap, hash) == 0, "snapshot encodes");
    char sql[160];
    snprintf(sql, sizeof(sql),
             "DELETE FROM validator_set_snapshots WHERE epoch_start = %llu",
             (unsigned long long)epoch);
    run_sql(f, sql);
    CHECK(nodus_witness_vset_insert(f->w, epoch, blob, len, hash, 1) == 0,
          "snapshot stored");
    free(blob);
    dna_vset_free(&snap);
}

static void drop_snapshot(fx_t *f, uint64_t epoch)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "DELETE FROM validator_set_snapshots WHERE epoch_start = %llu",
             (unsigned long long)epoch);
    run_sql(f, sql);
}

/* The node's validators row (consensus key = the node's), re-keyed to a
 * validator_id with its roles row (the test_v2_valrow.c shape). */
static const uint8_t VID[64] = { [0 ... 63] = 0x5A };
static const uint8_t OWNER_V[64] = { [0 ... 63] = 0xA1 };

static void plant_validator(fx_t *f, int status)
{
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, f->id->pk.bytes, DNAC_PUBKEY_SIZE);
    v.self_stake = 1000000000000000ULL;
    v.commission_bps = 500;
    v.status = (uint8_t)status;
    v.active_since_block = 1;
    memset(v.unstake_destination_fp, 'a', 128);
    v.unstake_destination_fp[128] = '\0';
    memset(v.unstake_destination_pubkey, 0x77, DNAC_PUBKEY_SIZE);
    CHECK(nodus_validator_insert(f->w, &v) == 0, "validator row");

    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(f->w->db, "UPDATE validators SET pubkey_hash "
          "= ? WHERE pubkey = ?", -1, &st, NULL) == SQLITE_OK, "rekey");
    sqlite3_bind_blob(st, 1, VID, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, v.pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    CHECK(sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(f->w->db) == 1,
          "rekeyed");
    sqlite3_finalize(st);
    st = NULL;
    CHECK(sqlite3_prepare_v2(f->w->db, "INSERT INTO v2_validator_roles "
          "(validator_id, owner_fp, pending_consensus_pubkey, "
          "consensus_key_effective_epoch) VALUES (?, ?, zeroblob(2592), 0)",
          -1, &st, NULL) == SQLITE_OK, "roles");
    sqlite3_bind_blob(st, 1, VID, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, OWNER_V, 64, SQLITE_STATIC);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "roles row");
    sqlite3_finalize(st);
}

static void set_validator_status(fx_t *f, int status)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "UPDATE validators SET status = %d", status);
    run_sql(f, sql);
}

static void drop_validator(fx_t *f)
{
    run_sql(f, "DELETE FROM validators; DELETE FROM v2_validator_roles");
}

static const uint8_t PAYEE[64] = { [0 ... 63] = 0xB2 };

/* The node's storage registry row (status 1 ACTIVE / 2 EXITING / 3
 * RELEASED), payee = PAYEE. */
static void plant_storage_row(fx_t *f, int status)
{
    static uint8_t pk[2592];
    sqlite3_stmt *st = NULL;
    run_sql(f, "DELETE FROM v2_storage_nodes");
    CHECK(sqlite3_prepare_v2(f->w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, bond, "
            "status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, ?3, 1000, ?4, 1, 0, 0, 0)",
            -1, &st, NULL) == SQLITE_OK, "prepare row insert");
    sqlite3_bind_blob(st, 1, f->my_fp, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, pk, sizeof(pk), SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, PAYEE, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, status);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "storage row planted");
    sqlite3_finalize(st);
}

/* storage_set(epoch) with ONE member: the node (`me`) or a filler fp. */
static void plant_storage_set(fx_t *f, uint64_t epoch, bool me)
{
    uint8_t filler[64];
    uint8_t fps[1][64];
    uint8_t sh[64];
    char sql[200];
    memset(filler, 0xEE, sizeof(filler));
    memcpy(fps[0], me ? f->my_fp : filler, 64);
    CHECK(dna_v2_storage_set_hash(epoch, (const uint8_t (*)[64])fps, 1, sh)
          == 0, "set hash");
    snprintf(sql, sizeof(sql),
             "DELETE FROM v2_storage_set_members WHERE epoch_start = %llu; "
             "DELETE FROM v2_storage_sets WHERE epoch_start = %llu",
             (unsigned long long)epoch, (unsigned long long)epoch);
    run_sql(f, sql);

    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(f->w->db, "INSERT INTO v2_storage_sets "
          "(epoch_start, set_hash, member_count) VALUES (?1, ?2, 1)", -1,
          &st, NULL) == SQLITE_OK, "set insert");
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch);
    sqlite3_bind_blob(st, 2, sh, 64, SQLITE_STATIC);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "set header");
    sqlite3_finalize(st);
    st = NULL;
    CHECK(sqlite3_prepare_v2(f->w->db, "INSERT INTO v2_storage_set_members "
          "(epoch_start, node_fp, fail_streak, grace_until) VALUES "
          "(?1, ?2, 0, 0)", -1, &st, NULL) == SQLITE_OK, "member insert");
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch);
    sqlite3_bind_blob(st, 2, fps[0], 64, SQLITE_STATIC);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "set member");
    sqlite3_finalize(st);
}

static void drop_storage_set(fx_t *f, uint64_t epoch)
{
    char sql[200];
    snprintf(sql, sizeof(sql),
             "DELETE FROM v2_storage_set_members WHERE epoch_start = %llu; "
             "DELETE FROM v2_storage_sets WHERE epoch_start = %llu",
             (unsigned long long)epoch, (unsigned long long)epoch);
    run_sql(f, sql);
}

static void plant_segment(fx_t *f)
{
    run_sql(f, "DELETE FROM v2_storage_segments; "
               "INSERT INTO v2_storage_segments (k, root, published_height) "
               "VALUES (1, zeroblob(64), 1)");
}

static void plant_report(fx_t *f, uint64_t epoch, uint32_t seat)
{
    char sql[220];
    snprintf(sql, sizeof(sql),
             "INSERT INTO v2_storage_reports (epoch_start, seat, set_hash, "
             "bitmap) VALUES (%llu, %u, zeroblob(64), x'00')",
             (unsigned long long)epoch, (unsigned)seat);
    run_sql(f, sql);
}

/* ── requests and replies ────────────────────────────────────────────── */

static uint8_t g_req[512];
static uint8_t g_rx[1 << 16];

typedef struct {
    uint8_t  payload[1 << 16];
    size_t   len;
    char     type;             /* 'r' / 'e' */
    int      code;
} reply_t;

static reply_t g_rep;

/* {t:77, y:"q", q:"dnac_node_duties", a:{}} */
static size_t build_req(void)
{
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_req, sizeof(g_req));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 77);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "dnac_node_duties");
    cbor_encode_cstr(&enc, "a"); cbor_encode_map(&enc, 0);
    size_t len = cbor_encoder_len(&enc);
    CHECK(len > 0, "request encodes");
    return len;
}

/* Dispatch one request and read its ONE framed reply off our end (bytes
 * the node's socket did not take are drained as the poll loop would).
 * The witness database's total_changes must not move across the call. */
static reply_t *call(fx_t *f)
{
    size_t have = 0;
    nodus_frame_t fr;
    size_t req_len = build_req();
    const int changes_before = sqlite3_total_changes(f->w->db);

    nodus_witness_handle_dnac(f->w, f->conn, g_req, req_len,
                              "dnac_node_duties", 77);
    CHECK(sqlite3_total_changes(f->w->db) == changes_before,
          "the handler wrote NOTHING to the database");
    for (;;) {
        ssize_t n = read(f->sv[1], g_rx + have, sizeof(g_rx) - have);
        if (n > 0) { have += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (f->conn->wpos < f->conn->wlen) {
            ssize_t w = write(f->sv[0], f->conn->wbuf + f->conn->wpos,
                              f->conn->wlen - f->conn->wpos);
            if (w > 0) { f->conn->wpos += (size_t)w; continue; }
            CHECK(w < 0 && (errno == EAGAIN || errno == EINTR),
                  "drain write");
            continue;
        }
        break;
    }
    CHECK(have > 0, "the node answered");
    CHECK(nodus_frame_decode(g_rx, have, &fr) == (int)have,
          "exactly one complete frame");
    memset(&g_rep, 0, sizeof(g_rep));
    memcpy(g_rep.payload, fr.payload, fr.payload_len);
    g_rep.len = fr.payload_len;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    CHECK(nodus_t2_decode(g_rep.payload, g_rep.len, &msg) == 0,
          "reply decodes as the client decodes it");
    g_rep.type = msg.type;
    g_rep.code = msg.error_code;
    nodus_t2_msg_free(&msg);
    return &g_rep;
}

/* A successful reply, decoded by the SDK's decoder. */
static void ask(fx_t *f, nodus_dnac_node_duties_t *d)
{
    reply_t *r = call(f);
    CHECK(r->type == 'r', "a success reply");
    CHECK(nodus_dnac_node_duties_decode(r->payload, r->len, d) == 0,
          "the SDK decoder accepts the node's bytes");
}

static const nodus_dnac_duty_blocker_t *find_bl(
        const nodus_dnac_node_duties_t *d, unsigned code)
{
    for (size_t i = 0; i < d->n_blockers; i++)
        if (d->blockers[i].code == code) return &d->blockers[i];
    return NULL;
}

/* The state is BLOCKED with exactly the codes in `codes` (ascending). */
static void expect_codes(const nodus_dnac_node_duties_t *d,
                         const unsigned *codes, size_t n)
{
    CHECK(d->state == NODUS_DNAC_DUTIES_BLOCKED, "state BLOCKED");
    CHECK(d->n_blockers == n, "the number of blockers");
    for (size_t i = 0; i < n; i++)
        CHECK(d->blockers[i].code == codes[i], "the blocker codes, in order");
}

static void expect_clear(const nodus_dnac_node_duties_t *d)
{
    CHECK(d->state == NODUS_DNAC_DUTIES_CLEAR, "state CLEAR");
    CHECK(d->n_blockers == 0 && d->n_owners == 0, "no blocker, no owner");
}

/* The fixture every case starts from: tip T = 3E + 1, snapshots 2E, 3E and
 * 4E holding only the filler key. snapshot(4E) = snapshot(B + E) is frozen
 * inside block B = 3E, which is committed at this tip, so it exists. */
static uint8_t g_bh[64];
static uint64_t base_tip(void) { return 3u * E_LEN + 1u; }

static void base_state(fx_t *f)
{
    set_tip(f, base_tip(), g_bh);
    plant_snapshot(f, 2u * E_LEN, false);
    plant_snapshot(f, 3u * E_LEN, false);
    plant_snapshot(f, 4u * E_LEN, false);
}

/* chain_config param 18 (RULESET_GEN_ROLES, the storage activation) in
 * effect from block `eff` on. The handler reads it through the chain-config
 * cache, so the cache is dropped to re-read the table. */
static void plant_storage_activation(fx_t *f, uint64_t eff)
{
    char sql[300];
    snprintf(sql, sizeof(sql),
             "DELETE FROM chain_config_history WHERE param_id = %d; "
             "INSERT INTO chain_config_history (param_id, new_value, "
             "effective_block, commit_block, tx_hash, proposal_nonce, "
             "created_at_unix) VALUES (%d, 1, %llu, 1, zeroblob(64), 1, 0)",
             (int)DNAC_CFG_RULESET_GEN_ROLES, (int)DNAC_CFG_RULESET_GEN_ROLES,
             (unsigned long long)eff);
    run_sql(f, sql);
    f->w->chain_config_cache_warm = false;
}

static void drop_storage_activation(fx_t *f)
{
    char sql[120];
    snprintf(sql, sizeof(sql),
             "DELETE FROM chain_config_history WHERE param_id = %d",
             (int)DNAC_CFG_RULESET_GEN_ROLES);
    run_sql(f, sql);
    f->w->chain_config_cache_warm = false;
}

/* ── cases ────────────────────────────────────────────────────────────── */

static void t_auth(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    fx_open(&f, "auth");
    base_state(&f);

    /* another key */
    memcpy(f.conn->peer_pk.bytes, f.foreign->pk.bytes, NODUS_PK_BYTES);
    reply_t *r = call(&f);
    CHECK(r->type == 'e' && r->code == NODUS_ERR_NOT_AUTHENTICATED,
          "a foreign session is refused");
    /* no authenticated identity at all, though the key bytes are the node's */
    memcpy(f.conn->peer_pk.bytes, f.id->pk.bytes, NODUS_PK_BYTES);
    f.conn->peer_id_set = false;
    r = call(&f);
    CHECK(r->type == 'e' && r->code == NODUS_ERR_NOT_AUTHENTICATED,
          "an unauthenticated session is refused");
    /* the node's own identity */
    f.conn->peer_id_set = true;
    ask(&f, &d);
    CHECK(d.committed_height == base_tip(), "answered for the own key");
    fx_close(&f);
    printf("[auth] ok\n");
}

static void t_clear(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    fx_open(&f, "clear");
    base_state(&f);
    ask(&f, &d);
    expect_clear(&d);
    CHECK(d.committed_height == base_tip(), "ch = the planted tip");
    CHECK(memcmp(d.block_hash, g_bh, 64) == 0, "bh = the planted block id");
    for (int i = 0; i < 32; i++) CHECK(d.chain_id[i] == 0xC1, "cid");
    CHECK(!d.fresh && !d.wait_sync && !d.cs_started && d.n_peers == 0 &&
          d.max_peer_height == 0, "no reactor: not fresh, zero inputs");
    fx_close(&f);
    printf("[clear] ok\n");
}

static void t_witness(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    char owner_hex[129];
    const unsigned reg[] = { NODUS_DNAC_DUTY_WITNESS_REGISTERED };
    const unsigned leave[] = { NODUS_DNAC_DUTY_WITNESS_LEAVING };
    const unsigned leave_next[] = { NODUS_DNAC_DUTY_WITNESS_LEAVING,
                                    NODUS_DNAC_DUTY_SEATED_NEXT };
    const unsigned next_only[] = { NODUS_DNAC_DUTY_SEATED_NEXT };
    const uint64_t B = 3u * E_LEN;
    hex64(OWNER_V, owner_hex);
    fx_open(&f, "witness");
    base_state(&f);

    plant_validator(&f, DNAC_VALIDATOR_ACTIVE);
    ask(&f, &d);
    expect_codes(&d, reg, 1);
    CHECK(d.blockers[0].end_height == 0, "registered: until the owner leaves");
    CHECK(d.n_owners == 1 && strcmp(d.owners[0], owner_hex) == 0,
          "the owner of the row is named");

    set_validator_status(&f, DNAC_VALIDATOR_ELIGIBLE);
    ask(&f, &d);
    expect_codes(&d, reg, 1);

    set_validator_status(&f, DNAC_VALIDATOR_RETIRING);
    ask(&f, &d);
    expect_codes(&d, leave, 1);
    CHECK(d.blockers[0].end_height == B + E_LEN,
          "leaving, not in snapshot(B+E): ends at B + E");
    CHECK(d.n_owners == 1, "the owner is named");

    set_validator_status(&f, DNAC_VALIDATOR_AUTO_RETIRED);
    ask(&f, &d);
    expect_codes(&d, leave, 1);

    plant_snapshot(&f, 4u * E_LEN, true);       /* frozen next, node in it */
    ask(&f, &d);
    expect_codes(&d, leave_next, 2);
    CHECK(find_bl(&d, NODUS_DNAC_DUTY_WITNESS_LEAVING)->end_height ==
          B + 2u * E_LEN, "leaving while in snapshot(B+E): ends at B + 2E");
    CHECK(find_bl(&d, NODUS_DNAC_DUTY_SEATED_NEXT)->end_height ==
          B + 2u * E_LEN, "seated next: ends at B + 2E");

    set_validator_status(&f, DNAC_VALIDATOR_UNSTAKED);
    ask(&f, &d);
    expect_codes(&d, next_only, 1);              /* only the seat remains */
    CHECK(d.n_owners == 0, "an UNSTAKED row names no owner");
    plant_snapshot(&f, 4u * E_LEN, false);       /* the node leaves it    */
    ask(&f, &d);
    expect_clear(&d);

    drop_validator(&f);
    fx_close(&f);
    printf("[witness] ok\n");
}

static void t_seated(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const unsigned now[] = { NODUS_DNAC_DUTY_SEATED_NOW };
    const unsigned next[] = { NODUS_DNAC_DUTY_SEATED_NEXT };
    const uint64_t B = 3u * E_LEN;
    fx_open(&f, "seated");
    base_state(&f);

    plant_snapshot(&f, B, true);
    ask(&f, &d);
    expect_codes(&d, now, 1);
    CHECK(d.blockers[0].end_height == B + E_LEN, "seated now ends at B + E");
    plant_snapshot(&f, B, false);

    plant_snapshot(&f, B + E_LEN, true);
    ask(&f, &d);
    expect_codes(&d, next, 1);
    CHECK(d.blockers[0].end_height == B + 2u * E_LEN,
          "seated next ends at B + 2E");
    fx_close(&f);
    printf("[seated] ok\n");
}

static void t_transition(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const unsigned tr[] = { NODUS_DNAC_DUTY_CMT_TRANSITION };
    const uint64_t B = 3u * E_LEN;
    fx_open(&f, "transition");
    base_state(&f);
    plant_snapshot(&f, B - E_LEN, true);   /* the node sat in snapshot(B-E) */

    /* T + 1 = B + 2: past the transition */
    ask(&f, &d);
    expect_clear(&d);
    /* T + 1 = B */
    set_tip(&f, B - 1u, g_bh);
    ask(&f, &d);
    expect_codes(&d, tr, 1);
    CHECK(d.blockers[0].end_height == B + 1u, "transition ends at B + 1");
    /* T + 1 = B + 1 */
    set_tip(&f, B, g_bh);
    ask(&f, &d);
    expect_codes(&d, tr, 1);
    fx_close(&f);
    printf("[transition] ok\n");
}

static void t_storage(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    char payee_hex[129];
    const unsigned reg[] = { NODUS_DNAC_DUTY_STORAGE_REGISTERED };
    const unsigned leave[] = { NODUS_DNAC_DUTY_STORAGE_LEAVING };
    hex64(PAYEE, payee_hex);
    fx_open(&f, "storage");
    base_state(&f);

    plant_storage_row(&f, 1);                              /* ACTIVE */
    ask(&f, &d);
    expect_codes(&d, reg, 1);
    CHECK(d.blockers[0].end_height == 0, "registered: until the owner leaves");
    CHECK(d.n_owners == 1 && strcmp(d.owners[0], payee_hex) == 0,
          "the payee is named");

    plant_storage_row(&f, 2);                              /* EXITING */
    ask(&f, &d);
    expect_codes(&d, leave, 1);
    CHECK(d.blockers[0].end_height == 4u * E_LEN,
          "leaving: the first multiple of E at or after T + 1");
    set_tip(&f, 4u * E_LEN - 1u, g_bh);                    /* T + 1 = 4E */
    plant_snapshot(&f, 4u * E_LEN, false);
    plant_snapshot(&f, 3u * E_LEN, true);
    ask(&f, &d);
    CHECK(find_bl(&d, NODUS_DNAC_DUTY_STORAGE_LEAVING) != NULL &&
          find_bl(&d, NODUS_DNAC_DUTY_STORAGE_LEAVING)->end_height ==
              4u * E_LEN,
          "leaving with T + 1 = B: ends at B itself");
    set_tip(&f, base_tip(), g_bh);
    plant_snapshot(&f, 3u * E_LEN, false);
    plant_snapshot(&f, 4u * E_LEN, false);

    plant_storage_row(&f, 3);                              /* RELEASED */
    ask(&f, &d);
    expect_clear(&d);
    fx_close(&f);
    printf("[storage] ok\n");
}

static void t_overlap(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const unsigned ov[] = { NODUS_DNAC_DUTY_ARCHIVE_OVERLAP };
    const uint64_t H = 3u * E_LEN;
    fx_open(&f, "overlap");
    base_state(&f);

    /* displaced: in set(2E), not in set(3E); segment 1 published at 1 */
    plant_storage_set(&f, 2u * E_LEN, true);
    plant_storage_set(&f, H, false);
    ask(&f, &d);
    expect_clear(&d);                                /* no segment yet   */
    plant_segment(&f);
    ask(&f, &d);
    expect_codes(&d, ov, 1);
    CHECK(d.blockers[0].end_height == H + E_LEN,
          "displaced holder: the overlap ends at H + E");

    /* still a member of set(3E): the overlap runs one epoch longer */
    plant_storage_set(&f, H, true);
    ask(&f, &d);
    expect_codes(&d, ov, 1);
    CHECK(d.blockers[0].end_height == H + 2u * E_LEN,
          "member of set(H): ends at H + 2E");
    fx_close(&f);
    printf("[overlap] ok\n");
}

static void t_report(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const unsigned rep[] = { NODUS_DNAC_DUTY_STORAGE_REPORT };
    const uint64_t P = 2u * E_LEN;
    fx_open(&f, "report");
    base_state(&f);
    plant_snapshot(&f, P, true);                 /* the node is seat 1   */

    /* storage_set(P) absent: no report is owed */
    ask(&f, &d);
    expect_clear(&d);
    plant_storage_set(&f, P, false);
    ask(&f, &d);
    expect_codes(&d, rep, 1);
    CHECK(d.blockers[0].end_height == P + E_LEN + E_LEN / 2u,
          "the report window's close");

    plant_report(&f, P, 0);                      /* another seat's       */
    ask(&f, &d);
    expect_codes(&d, rep, 1);
    plant_report(&f, P, 1);                      /* the node's own       */
    ask(&f, &d);
    expect_clear(&d);

    /* window not open yet: T + 1 = B */
    run_sql(&f, "DELETE FROM v2_storage_reports");
    set_tip(&f, 3u * E_LEN - 1u, g_bh);
    plant_snapshot(&f, 3u * E_LEN, false);
    ask(&f, &d);
    CHECK(find_bl(&d, NODUS_DNAC_DUTY_STORAGE_REPORT) == NULL,
          "no report owed before its window opens");
    fx_close(&f);
    printf("[report] ok\n");
}

static void t_faults(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    fx_open(&f, "faults");
    base_state(&f);

    /* a snapshot that must exist, missing */
    drop_snapshot(&f, 3u * E_LEN);
    ask(&f, &d);
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN, "missing snapshot: UNKNOWN");
    CHECK(d.n_blockers == 0 && d.n_owners == 0 && d.why[0] != '\0',
          "UNKNOWN carries a why and nothing else");
    plant_snapshot(&f, 3u * E_LEN, false);
    ask(&f, &d);
    expect_clear(&d);

    /* the storage registry gone */
    run_sql(&f, "DROP TABLE v2_storage_nodes");
    ask(&f, &d);
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN,
          "storage registry gone: UNKNOWN, never CLEAR");
    CHECK(d.n_blockers == 0 && d.n_owners == 0 && d.why[0] != '\0',
          "UNKNOWN carries a why and nothing else");
    fx_close(&f);
    printf("[faults] ok\n");
}

/* snapshot(B + E) is frozen inside block B: absent is "not an entry" only
 * while block B is not committed (T + 1 = B), a fault once it is. */
static void t_next_snapshot(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const unsigned leave[] = { NODUS_DNAC_DUTY_WITNESS_LEAVING };
    const uint64_t B = 3u * E_LEN;
    fx_open(&f, "nextsnap");
    base_state(&f);

    /* T + 1 > B, no validators row: the seat check reads snapshot(B+E) */
    drop_snapshot(&f, B + E_LEN);
    ask(&f, &d);
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN && d.why[0] != '\0' &&
          d.n_blockers == 0 && d.n_owners == 0,
          "T + 1 > B, snapshot(B+E) absent: UNKNOWN, never CLEAR");
    /* T + 1 = B: block B is not committed, the snapshot cannot exist yet */
    set_tip(&f, B - 1u, g_bh);
    ask(&f, &d);
    expect_clear(&d);

    /* the same two tips with a leaving row (it reads snapshot(B+E) too) */
    plant_validator(&f, DNAC_VALIDATOR_RETIRING);
    ask(&f, &d);                                  /* T + 1 = B           */
    expect_codes(&d, leave, 1);
    CHECK(d.blockers[0].end_height == B + E_LEN,
          "leaving, T + 1 = B, snapshot(B+E) absent: not an entry");
    set_tip(&f, base_tip(), g_bh);
    ask(&f, &d);                                  /* T + 1 > B           */
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN && d.why[0] != '\0' &&
          d.n_blockers == 0 && d.n_owners == 0,
          "leaving, T + 1 > B, snapshot(B+E) absent: UNKNOWN");
    plant_snapshot(&f, B + E_LEN, false);
    ask(&f, &d);
    expect_codes(&d, leave, 1);                   /* back to a real answer */
    drop_validator(&f);
    fx_close(&f);
    printf("[next_snapshot] ok\n");
}

/* A storage set that is absent where the chain always writes one is a
 * fault; before the storage activation (chain_config param 18) it is "no
 * storage duty". T = 3E + 1: H = 3E (archive overlap), P = 2E (report). */
static void t_storage_sets(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const unsigned rep[] = { NODUS_DNAC_DUTY_STORAGE_REPORT };
    const uint64_t H = 3u * E_LEN, P = 2u * E_LEN;
    fx_open(&f, "stsets");
    base_state(&f);
    plant_snapshot(&f, P, true);                  /* the node: seat 1     */

    /* before any activation: both sets absent -> no storage duty */
    ask(&f, &d);
    expect_clear(&d);

    /* activation after H: still nothing is owed at H or at P */
    plant_storage_activation(&f, H + 1u);
    ask(&f, &d);
    expect_clear(&d);

    /* activation at H (in effect at H, not at P): set(H) must exist */
    plant_storage_activation(&f, H);
    ask(&f, &d);
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN && d.why[0] != '\0' &&
          d.n_blockers == 0 && d.n_owners == 0,
          "param 18 in effect at H, storage_set(H) absent: UNKNOWN");
    plant_storage_set(&f, H, false);
    ask(&f, &d);                  /* set(P) absent but not yet active at P */
    expect_clear(&d);

    /* activation at P: set(P) must exist too (the node is seat 1 of P) */
    plant_storage_activation(&f, P);
    ask(&f, &d);
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN && d.why[0] != '\0' &&
          d.n_blockers == 0 && d.n_owners == 0,
          "param 18 in effect at P, storage_set(P) absent: UNKNOWN");
    plant_storage_set(&f, P, false);
    ask(&f, &d);
    expect_codes(&d, rep, 1);                     /* the real answer      */

    /* the activation row gone again: absent sets are "no duty" once more */
    drop_storage_set(&f, H);
    drop_storage_set(&f, P);
    drop_storage_activation(&f);
    ask(&f, &d);
    expect_clear(&d);
    fx_close(&f);
    printf("[storage_sets] ok\n");
}

/* Archive overlap reads storage_set(H - E) too: absent where param 18 was
 * in effect at H - E is a fault; not yet in effect there is "no duty".
 * T = 3E + 1: H = 3E, H - E = 2E. The node is NOT a seat of snapshot(2E),
 * so the report item cannot be the source of the UNKNOWN. */
static void t_prev_set(void)
{
    fx_t f;
    nodus_dnac_node_duties_t d;
    const uint64_t H = 3u * E_LEN, Q = 2u * E_LEN;
    fx_open(&f, "prevset");
    base_state(&f);
    plant_storage_set(&f, H, false);

    /* in effect at H only: set(H - E) absent is "no storage duty" */
    plant_storage_activation(&f, H);
    ask(&f, &d);
    expect_clear(&d);

    /* in effect at H - E: set(H) present, set(H - E) absent -> UNKNOWN */
    plant_storage_activation(&f, Q);
    ask(&f, &d);
    CHECK(d.state == NODUS_DNAC_DUTIES_UNKNOWN && d.why[0] != '\0' &&
          strstr(d.why, "previous epoch") != NULL &&
          d.n_blockers == 0 && d.n_owners == 0,
          "param 18 in effect at H - E, storage_set(H - E) absent: UNKNOWN");

    /* the set planted: the fault is gone */
    plant_storage_set(&f, Q, false);
    ask(&f, &d);
    expect_clear(&d);
    fx_close(&f);
    printf("[prev_set] ok\n");
}

/* ── the decoder over crafted replies ────────────────────────────────── */

typedef struct {
    uint64_t    ch;
    int         cid_len, bh_len;
    bool        fresh, ws, cs;
    uint64_t    np, mph;
    uint64_t    state;
    size_t      nbl;
    uint64_t    codes[4], ehs[4];
    size_t      nown;
    const char *owners[3];
    const char *why;               /* NULL = absent                    */
    const char *omit;              /* a key to leave out               */
    const char *dup;               /* a key to write twice             */
    bool        extra;             /* an unknown key                   */
} craft_t;

static const char OWN_A[129] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char OWN_B[129] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static craft_t base_craft(void)
{
    craft_t c;
    memset(&c, 0, sizeof(c));
    c.ch = 100;
    c.cid_len = 32;
    c.bh_len = 64;
    c.state = NODUS_DNAC_DUTIES_CLEAR;
    return c;
}

/* One key of the reply, honouring c->omit / c->dup. */
static void put_key(cbor_encoder_t *enc, const craft_t *c, const char *key)
{
    static const uint8_t zeros[64] = {0};
    int times = (c->dup && strcmp(c->dup, key) == 0) ? 2 : 1;
    if (c->omit && strcmp(c->omit, key) == 0) return;
    for (int t = 0; t < times; t++) {
        cbor_encode_cstr(enc, key);
        if (!strcmp(key, "ch"))         cbor_encode_uint(enc, c->ch);
        else if (!strcmp(key, "cid"))   cbor_encode_bstr(enc, zeros,
                                                         (size_t)c->cid_len);
        else if (!strcmp(key, "bh"))    cbor_encode_bstr(enc, zeros,
                                                         (size_t)c->bh_len);
        else if (!strcmp(key, "fresh")) cbor_encode_bool(enc, c->fresh);
        else if (!strcmp(key, "ws"))    cbor_encode_bool(enc, c->ws);
        else if (!strcmp(key, "cs"))    cbor_encode_bool(enc, c->cs);
        else if (!strcmp(key, "np"))    cbor_encode_uint(enc, c->np);
        else if (!strcmp(key, "mph"))   cbor_encode_uint(enc, c->mph);
        else if (!strcmp(key, "state")) cbor_encode_uint(enc, c->state);
        else if (!strcmp(key, "bl")) {
            cbor_encode_array(enc, c->nbl);
            for (size_t i = 0; i < c->nbl; i++) {
                cbor_encode_map(enc, 2);
                cbor_encode_cstr(enc, "c");  cbor_encode_uint(enc, c->codes[i]);
                cbor_encode_cstr(enc, "eh"); cbor_encode_uint(enc, c->ehs[i]);
            }
        } else if (!strcmp(key, "own")) {
            cbor_encode_array(enc, c->nown);
            for (size_t i = 0; i < c->nown; i++)
                cbor_encode_cstr(enc, c->owners[i]);
        } else if (!strcmp(key, "why")) {
            cbor_encode_cstr(enc, c->why);
        } else {
            cbor_encode_uint(enc, 7);                 /* an unknown key */
        }
    }
}

static size_t craft(uint8_t *buf, size_t cap, const craft_t *c)
{
    static const char *const KEYS[] = { "ch", "cid", "bh", "fresh", "ws",
        "cs", "np", "mph", "state", "bl", "own" };
    cbor_encoder_t enc;
    size_t keys = 11;
    if (c->omit) keys--;
    if (c->dup) keys++;
    if (c->why) keys++;
    if (c->extra) keys++;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 9);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "dnac_node_duties");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, keys);
    for (size_t i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++)
        put_key(&enc, c, KEYS[i]);
    if (c->why) put_key(&enc, c, "why");
    if (c->extra) put_key(&enc, c, "zz");
    size_t len = cbor_encoder_len(&enc);
    CHECK(len > 0, "crafted reply encodes");
    return len;
}

static int dec_of(const craft_t *c, nodus_dnac_node_duties_t *out)
{
    static uint8_t buf[4096];
    size_t n = craft(buf, sizeof(buf), c);
    return nodus_dnac_node_duties_decode(buf, n, out);
}

static void expect_refused(const craft_t *c, const char *what)
{
    nodus_dnac_node_duties_t d;
    memset(&d, 0xFF, sizeof(d));
    CHECK(dec_of(c, &d) == -1, what);
    nodus_dnac_node_duties_t z;
    memset(&z, 0, sizeof(z));
    CHECK(memcmp(&d, &z, sizeof(d)) == 0, "a refusal zeroes the output");
}

static void t_decoder(void)
{
    nodus_dnac_node_duties_t d;
    craft_t c;

    /* valid: CLEAR */
    c = base_craft();
    CHECK(dec_of(&c, &d) == 0 && d.state == NODUS_DNAC_DUTIES_CLEAR &&
          d.committed_height == 100, "valid CLEAR");

    /* valid: fresh with its inputs */
    c = base_craft();
    c.fresh = true; c.cs = true; c.np = 3; c.mph = 101;
    CHECK(dec_of(&c, &d) == 0 && d.fresh && d.n_peers == 3 &&
          d.max_peer_height == 101, "valid fresh (ch + 1 >= mph)");

    /* valid: BLOCKED, two blockers ascending, owners ascending */
    c = base_craft();
    c.state = NODUS_DNAC_DUTIES_BLOCKED;
    c.nbl = 2;
    c.codes[0] = NODUS_DNAC_DUTY_WITNESS_REGISTERED; c.ehs[0] = 0;
    c.codes[1] = NODUS_DNAC_DUTY_SEATED_NOW;         c.ehs[1] = 101;
    c.nown = 2; c.owners[0] = OWN_A; c.owners[1] = OWN_B;
    CHECK(dec_of(&c, &d) == 0 && d.n_blockers == 2 && d.n_owners == 2 &&
          d.blockers[1].end_height == 101 &&
          strcmp(d.owners[1], OWN_B) == 0, "valid BLOCKED");

    /* valid: UNKNOWN with its why */
    c = base_craft();
    c.state = NODUS_DNAC_DUTIES_UNKNOWN; c.why = "snapshot absent";
    CHECK(dec_of(&c, &d) == 0 && d.state == NODUS_DNAC_DUTIES_UNKNOWN &&
          strcmp(d.why, "snapshot absent") == 0, "valid UNKNOWN");

    /* an unknown key is skipped */
    c = base_craft(); c.extra = true;
    CHECK(dec_of(&c, &d) == 0, "an unknown key is skipped");

    /* duplicate keys */
    c = base_craft(); c.dup = "ch";    expect_refused(&c, "duplicate ch");
    c = base_craft(); c.dup = "bl";    expect_refused(&c, "duplicate bl");
    c = base_craft(); c.dup = "state"; expect_refused(&c, "duplicate state");
    /* missing keys */
    c = base_craft(); c.omit = "ch";   expect_refused(&c, "missing ch");
    c = base_craft(); c.omit = "own";  expect_refused(&c, "missing own");
    c = base_craft(); c.omit = "fresh"; expect_refused(&c, "missing fresh");
    /* wrong widths */
    c = base_craft(); c.cid_len = 31;  expect_refused(&c, "cid of 31");
    c = base_craft(); c.bh_len = 63;   expect_refused(&c, "bh of 63");
    c = base_craft();
    c.state = NODUS_DNAC_DUTIES_BLOCKED;
    c.nbl = 1; c.codes[0] = 1; c.ehs[0] = 0;
    c.nown = 1; c.owners[0] = "abc";
    expect_refused(&c, "an owner that is not 128 hex");

    /* fresh is exactly the conjunction of its inputs */
    c = base_craft(); c.fresh = true;
    expect_refused(&c, "fresh with no peers / no state machine");
    c = base_craft(); c.cs = true; c.np = 1; c.mph = 50;   /* would be fresh */
    expect_refused(&c, "not fresh though every input allows it");
    c = base_craft(); c.fresh = true; c.cs = true; c.np = 1; c.mph = 102;
    expect_refused(&c, "fresh though the peer is 2 blocks ahead");
    c = base_craft(); c.fresh = true; c.cs = true; c.ws = true;
    c.np = 1; c.mph = 100;
    expect_refused(&c, "fresh while waiting for block sync");
    c = base_craft(); c.np = 0; c.mph = 5;
    expect_refused(&c, "np 0 with a peer height");
    c = base_craft(); c.np = 2; c.mph = 0;
    expect_refused(&c, "peers with no height");

    /* blockers */
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 2;
    c.codes[0] = 3; c.ehs[0] = 200; c.codes[1] = 2; c.ehs[1] = 200;
    expect_refused(&c, "blockers out of order");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 2;
    c.codes[0] = 3; c.ehs[0] = 200; c.codes[1] = 3; c.ehs[1] = 200;
    expect_refused(&c, "a repeated blocker code");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 1;
    c.codes[0] = 10; c.ehs[0] = 200;
    expect_refused(&c, "a code past the last");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 1;
    c.codes[0] = 0; c.ehs[0] = 200;
    expect_refused(&c, "code 0");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 1;
    c.codes[0] = NODUS_DNAC_DUTY_WITNESS_LEAVING; c.ehs[0] = 0;
    expect_refused(&c, "eh 0 on a code that ends");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 1;
    c.codes[0] = NODUS_DNAC_DUTY_SEATED_NOW; c.ehs[0] = 100;
    expect_refused(&c, "eh not past ch");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 1;
    c.codes[0] = NODUS_DNAC_DUTY_STORAGE_REGISTERED; c.ehs[0] = 5;
    CHECK(dec_of(&c, &d) == -1, "a registered code with an end height <= ch");

    /* state / list agreement */
    c = base_craft(); c.nbl = 1; c.codes[0] = 3; c.ehs[0] = 200;
    expect_refused(&c, "CLEAR with a blocker");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED;
    expect_refused(&c, "BLOCKED without a blocker");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_UNKNOWN;
    expect_refused(&c, "UNKNOWN without why");
    c = base_craft(); c.why = "x";
    expect_refused(&c, "a why on CLEAR");
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_UNKNOWN; c.why = "x";
    c.nbl = 1; c.codes[0] = 3; c.ehs[0] = 200;
    expect_refused(&c, "UNKNOWN with a blocker");
    c = base_craft(); c.state = 3;
    expect_refused(&c, "a state past UNKNOWN");
    c = base_craft(); c.nown = 1; c.owners[0] = OWN_A;
    expect_refused(&c, "CLEAR with an owner");

    /* owners must be strictly ascending */
    c = base_craft(); c.state = NODUS_DNAC_DUTIES_BLOCKED; c.nbl = 1;
    c.codes[0] = 1; c.ehs[0] = 0;
    c.nown = 2; c.owners[0] = OWN_B; c.owners[1] = OWN_A;
    expect_refused(&c, "owners descending");
    c.owners[0] = OWN_A; c.owners[1] = OWN_A;
    expect_refused(&c, "owners repeated");

    printf("[decoder] ok\n");
}

int main(void)
{
    t_auth();
    t_clear();
    t_witness();
    t_seated();
    t_transition();
    t_storage();
    t_overlap();
    t_report();
    t_faults();
    t_next_snapshot();
    t_storage_sets();
    t_prev_set();
    t_decoder();
    printf("test_node_duties_rpc: %d checks passed\n", g_checks);
    return 0;
}
