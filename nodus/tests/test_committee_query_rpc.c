/**
 * Nodus — Task 62 dnac_committee_query RPC shape test
 *
 * The handler is thin glue over nodus_committee_get_for_block +
 * nodus_validator_get (for status) + the p2p host's signed ADDR records
 * (for endpoint, P2P-PORT F5). The committee computation itself is
 * covered end-to-end by test_committee_cache / test_committee_election.
 * This test validates the pieces the RPC adds:
 *
 *   1. epoch_start math: (target_h / EPOCH_LENGTH) * EPOCH_LENGTH.
 *   2. committee->validator status resolution — RETIRING propagates.
 *   3. with no p2p host, every member's address is empty (the held-
 *      record case is test_witness_p2p.c's).
 *   4. (HF-6 red-team round 1 close-out) the REAL handler, driven through
 *      nodus_witness_handle_dnac over a socketpair, answers six keys per
 *      entry, and its "power" is the engine's counted power: decoded by
 *      the client SDK's nodus_dnac_committee_decode, every entry has
 *      has_power = 1 and power == nodus_committee_get_for_block's member
 *      power (here the recompute arm, total / DNAC_DECIMAL_UNIT — 7 and 3,
 *      non-zero so a dropped field cannot pass as 0); the RETIRING seat is
 *      RETIRING on the wire too.
 *   5. the decoder over crafted replies: an entry WITH "power" sets
 *      power / has_power; an older node's entry WITHOUT it decodes, every
 *      other field intact, has_power = 0 and power = 0; a repeated
 *      top-level key is refused.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (register_witness_test).
 * Environment: none. No network: one AF_UNIX socketpair (case 4).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_committee_query_rpc_* directories, removed at the end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Case 4 runs on a chain database WITHOUT the version-3 tables: the
 *    handler takes its below-generation-4 arm (hf6_registry_roles answers
 *    0), and the committee comes from the bootstrap recompute, whose power
 *    is total / DNAC_DECIMAL_UNIT. The CAPPED ruleset-2 power reaches the
 *    wire through the same `committee[i].power` field, but no case here
 *    serves a ruleset-2 snapshot (test_hf6_power pins that member.power).
 *  - The client request function (nodus_client_dnac_committee) is not
 *    round-tripped; its decoder is, over the node's real bytes.
 *  - Nothing here was RUN by its author (BUILDER: compile only).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_p2p.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_emission.h"   /* DNAC_DECIMAL_UNIT */

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                            uint64_t active_since, uint64_t self_stake,
                            uint8_t status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake         = self_stake;
    v->commission_bps     = 500;
    v->status             = status;
    v->active_since_block = active_since;
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2*i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2*i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
}

static void insert_block_row(nodus_witness_t *w, uint64_t height,
                              const uint8_t state_seed[64]) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, "
        " prev_hash, state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    uint8_t zeros[64] = {0};
    uint8_t proposer[NODUS_T3_WITNESS_ID_LEN];
    memset(proposer, 0xBB, sizeof(proposer));
    sqlite3_bind_int64(stmt, 1, (int64_t)height);
    sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 6, state_seed, 64, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

/* ── case 4/5 helpers ─────────────────────────────────────────────── */

static uint8_t g_req[512];
static uint8_t g_rx[1 << 20];          /* one framed reply (~6 KB here)  */
static uint8_t g_payload[1 << 20];
static size_t  g_payload_len;
static char    g_reply_type;

/* {t:77, y:"q", q:"dnac_committee_query", a:{}} */
static size_t build_committee_req(void) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_req, sizeof(g_req));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 77);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "dnac_committee_query");
    cbor_encode_cstr(&enc, "a"); cbor_encode_map(&enc, 0);
    size_t len = cbor_encoder_len(&enc);
    CHECK(len > 0);
    return len;
}

/* Dispatch the request through the REAL dispatcher and read its ONE
 * framed reply off our end of the socketpair. Bytes the node's socket did
 * not take stay in conn->wbuf[wpos..wlen); they are written here, as the
 * poll loop's EPOLLOUT drain would (test_storage_by_owner.c's harness). */
static void call_committee(nodus_witness_t *w, nodus_tcp_conn_t *conn,
                           int sv0, int sv1) {
    size_t have = 0;
    nodus_frame_t fr;
    size_t req_len = build_committee_req();

    nodus_witness_handle_dnac(w, conn, g_req, req_len,
                              "dnac_committee_query", 77);
    for (;;) {
        ssize_t n = read(sv1, g_rx + have, sizeof(g_rx) - have);
        if (n > 0) { have += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (conn->wpos < conn->wlen) {
            ssize_t wr = write(sv0, conn->wbuf + conn->wpos,
                               conn->wlen - conn->wpos);
            if (wr > 0) { conn->wpos += (size_t)wr; continue; }
            CHECK(wr < 0 && (errno == EAGAIN || errno == EINTR));
            continue;
        }
        break;
    }
    CHECK(have > 0);
    CHECK(nodus_frame_decode(g_rx, have, &fr) == (int)have);
    CHECK(fr.payload_len <= sizeof(g_payload));
    memcpy(g_payload, fr.payload, fr.payload_len);
    g_payload_len = fr.payload_len;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    CHECK(nodus_t2_decode(g_payload, g_payload_len, &msg) == 0);
    g_reply_type = msg.type;
    nodus_t2_msg_free(&msg);
}

/* Count the keys of every "committee" entry of the reply in g_payload;
 * each must equal `want`. */
static void check_entry_key_counts(size_t want) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, g_payload, g_payload_len);
    cbor_item_t top = cbor_decode_next(&dec);
    CHECK(top.type == CBOR_ITEM_MAP);
    int seen = 0;
    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        CHECK(k.type == CBOR_ITEM_TSTR);
        if (!(k.tstr.len == 1 && k.tstr.ptr[0] == 'r')) {
            cbor_decode_skip(&dec);
            continue;
        }
        cbor_item_t r = cbor_decode_next(&dec);
        CHECK(r.type == CBOR_ITEM_MAP);
        for (size_t j = 0; j < r.count; j++) {
            cbor_item_t rk = cbor_decode_next(&dec);
            CHECK(rk.type == CBOR_ITEM_TSTR);
            if (rk.tstr.len == 9 && memcmp(rk.tstr.ptr, "committee", 9) == 0) {
                cbor_item_t arr = cbor_decode_next(&dec);
                CHECK(arr.type == CBOR_ITEM_ARRAY);
                for (size_t e = 0; e < arr.count; e++) {
                    cbor_item_t m = cbor_decode_next(&dec);
                    CHECK(m.type == CBOR_ITEM_MAP);
                    CHECK_EQ(m.count, want);
                    for (size_t f = 0; f < m.count * 2; f++)
                        cbor_decode_skip(&dec);
                    seen++;
                }
            } else {
                cbor_decode_skip(&dec);
            }
        }
    }
    CHECK(seen > 0);
}

/* (4) the real handler: "power" on the wire = the engine's member power. */
static void case_rpc_power(void) {
    char dir[] = "/tmp/test_committee_query_rpc_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB — heap */
    CHECK(w != NULL);
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    w->cached_committee_epoch_start = UINT64_MAX;
    uint8_t chain_id[16];
    memset(chain_id, 0xC6, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(w, chain_id), 0);

    /* 7 and 3 whole coins: the recompute arm's power is total /
     * DNAC_DECIMAL_UNIT, so non-zero — a dropped field cannot pass as 0 */
    dnac_validator_record_t va, vb;
    init_validator(&va, 0x33, 1, 7ULL * DNAC_DECIMAL_UNIT,
                   DNAC_VALIDATOR_ACTIVE);
    init_validator(&vb, 0x44, 1, 3ULL * DNAC_DECIMAL_UNIT,
                   DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(w, &va), 0);
    CHECK_EQ(nodus_validator_insert(w, &vb), 0);

    /* the engine's own answer for the block the handler serves: tip 0 on
     * this database (no blocks), so the next block, 1 */
    CHECK_EQ(nodus_witness_block_height(w), 0);
    nodus_committee_member_t ref[DNAC_COMMITTEE_SIZE];
    int ref_n = 0;
    CHECK_EQ(nodus_committee_get_for_block(w, 1, ref, DNAC_COMMITTEE_SIZE,
                                           &ref_n), 0);
    CHECK_EQ(ref_n, 2);
    uint64_t ref_sum = 0;
    for (int i = 0; i < ref_n; i++) {
        CHECK_EQ(ref[i].power, ref[i].total_stake / DNAC_DECIMAL_UNIT);
        CHECK(ref[i].power > 0);
        ref_sum += ref[i].power;
    }
    CHECK_EQ(ref_sum, 10);

    /* vb RETIRING in the table — the wire's status follows the row */
    vb.status = DNAC_VALIDATOR_RETIRING;
    CHECK_EQ(nodus_validator_update(w, &vb), 0);

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0 &&
          fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0);
    nodus_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    CHECK(conn != NULL);
    conn->fd = sv[0];
    conn->state = NODUS_CONN_CONNECTED;

    call_committee(w, conn, sv[0], sv[1]);
    CHECK(g_reply_type == 'r');
    check_entry_key_counts(6);

    nodus_dnac_committee_result_t *res = calloc(1, sizeof(*res));
    CHECK(res != NULL);
    CHECK_EQ(nodus_dnac_committee_decode(g_payload, g_payload_len, res), 0);
    CHECK_EQ(res->block_height, 1);
    CHECK_EQ(res->epoch_start, 0);
    CHECK_EQ(res->count, ref_n);
    for (int i = 0; i < res->count; i++) {
        const nodus_dnac_committee_entry_t *e = &res->entries[i];
        CHECK(memcmp(e->pubkey, ref[i].pubkey, DNAC_PUBKEY_SIZE) == 0);
        CHECK_EQ(e->has_power, 1);
        CHECK_EQ(e->power, ref[i].power);
        CHECK_EQ(e->total_stake, ref[i].total_stake);
        CHECK_EQ(e->status, e->pubkey[0] == 0x44
                                ? DNAC_VALIDATOR_RETIRING
                                : DNAC_VALIDATOR_ACTIVE);
    }
    fprintf(stderr, "[4/5] the handler's \"power\" = the engine's member "
            "power (7 + 3), six keys per entry OK\n");

    free(res);
    free(conn->wbuf);
    free(conn->rbuf);
    free(conn);
    close(sv[0]);
    close(sv[1]);
    sqlite3_close(w->db);
    free(w);
    rmrf(dir);
}

/* A crafted reply: one committee entry; `with_power` adds "power". */
static size_t craft_reply(uint8_t *buf, size_t cap, int with_power,
                          int dup_top_key) {
    static uint8_t pk[DNAC_PUBKEY_SIZE];
    memset(pk, 0x5A, sizeof(pk));
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 9);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "dnac_committee_query");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, dup_top_key ? 4 : 3);
    cbor_encode_cstr(&enc, "block_height"); cbor_encode_uint(&enc, 41);
    cbor_encode_cstr(&enc, "epoch_start");  cbor_encode_uint(&enc, 40);
    if (dup_top_key) {
        cbor_encode_cstr(&enc, "epoch_start"); cbor_encode_uint(&enc, 0);
    }
    cbor_encode_cstr(&enc, "committee");
    cbor_encode_array(&enc, 1);
    cbor_encode_map(&enc, with_power ? 6 : 5);
    cbor_encode_cstr(&enc, "pk");     cbor_encode_bstr(&enc, pk, sizeof(pk));
    cbor_encode_cstr(&enc, "stake");  cbor_encode_uint(&enc, 123456789);
    cbor_encode_cstr(&enc, "comm");   cbor_encode_uint(&enc, 250);
    cbor_encode_cstr(&enc, "status"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "addr");   cbor_encode_cstr(&enc, "10.0.0.1:4004");
    if (with_power) {
        cbor_encode_cstr(&enc, "power"); cbor_encode_uint(&enc, 25714285);
    }
    size_t len = cbor_encoder_len(&enc);
    CHECK(len > 0);
    return len;
}

/* (5) the decoder: with "power", without it (an older node), and a
 * repeated top-level key. */
static void case_decoder(void) {
    static uint8_t buf[8192];
    nodus_dnac_committee_result_t *res = calloc(1, sizeof(*res));
    CHECK(res != NULL);

    size_t n = craft_reply(buf, sizeof(buf), 1, 0);
    CHECK_EQ(nodus_dnac_committee_decode(buf, n, res), 0);
    CHECK_EQ(res->count, 1);
    CHECK_EQ(res->entries[0].has_power, 1);
    CHECK_EQ(res->entries[0].power, 25714285);

    n = craft_reply(buf, sizeof(buf), 0, 0);
    CHECK_EQ(nodus_dnac_committee_decode(buf, n, res), 0);
    CHECK_EQ(res->block_height, 41);
    CHECK_EQ(res->epoch_start, 40);
    CHECK_EQ(res->count, 1);
    CHECK_EQ(res->entries[0].has_power, 0);
    CHECK_EQ(res->entries[0].power, 0);
    CHECK_EQ(res->entries[0].pubkey[0], 0x5A);
    CHECK_EQ(res->entries[0].total_stake, 123456789);
    CHECK_EQ(res->entries[0].commission_bps, 250);
    CHECK_EQ(res->entries[0].status, 1);
    CHECK(strcmp(res->entries[0].address, "10.0.0.1:4004") == 0);

    n = craft_reply(buf, sizeof(buf), 1, 1);
    CHECK_EQ(nodus_dnac_committee_decode(buf, n, res), -1);
    CHECK_EQ(res->count, 0);

    free(res);
    fprintf(stderr, "[5/5] decoder: power, no power (older node), repeated "
            "key OK\n");
}

int main(void) {
    char data_path[] = "/tmp/test_committee_query_rpc_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0xC5, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* ── (1) epoch_start math ─────────────────────────────────────── */
    /* For target_h one past the first epoch boundary,
     * epoch_start = EPOCH_LENGTH. */
    uint64_t target_h      = (uint64_t)DNAC_EPOCH_LENGTH + 1;
    uint64_t epoch_start   = (target_h / (uint64_t)DNAC_EPOCH_LENGTH) *
                              (uint64_t)DNAC_EPOCH_LENGTH;
    CHECK_EQ(epoch_start, (uint64_t)DNAC_EPOCH_LENGTH);
    /* target_h == EPOCH_LENGTH (first block of epoch 1) -> epoch_start == EPOCH_LENGTH. */
    CHECK_EQ(((uint64_t)DNAC_EPOCH_LENGTH / (uint64_t)DNAC_EPOCH_LENGTH) *
             (uint64_t)DNAC_EPOCH_LENGTH,
             (uint64_t)DNAC_EPOCH_LENGTH);
    /* target_h < EPOCH_LENGTH -> epoch_start = 0. */
    CHECK_EQ((50ULL / (uint64_t)DNAC_EPOCH_LENGTH) * (uint64_t)DNAC_EPOCH_LENGTH,
             0ULL);
    fprintf(stderr, "[1/5] epoch_start math OK\n");

    /* ── (2) committee member status resolution ───────────────────── */
    /* Seed two ACTIVE validators so bootstrap admits both, then flip one
     * to RETIRING in the underlying table. The committee cache stays
     * frozen (per-epoch), but the handler ALWAYS re-fetches the
     * validator row to resolve status — so the RPC response must
     * surface the updated status even when the cached committee entry
     * still lists the validator. */
    dnac_validator_record_t v1, v2;
    init_validator(&v1, 0x11, 1, 10000000, DNAC_VALIDATOR_ACTIVE);
    init_validator(&v2, 0x22, 1, 20000000, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &v1), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v2), 0);

    /* Query committee for target_h = 1 (bootstrap path). */
    uint64_t q_height = 1;
    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int count = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, q_height, committee,
                                             DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK(count >= 2);

    /* Flip v2 to RETIRING directly in the validators table (simulates
     * the state post-UNSTAKE apply — test_retiring_committee_membership.c
     * used to exercise the same flip and is deleted with the closed
     * consensus lane, R3 W4; the RETIRING-membership property is now
     * structural, via the frozen validator_set_snapshots row, and no
     * version-3 test asserts it directly — a coverage gap, not
     * something this file substitutes for). */
    v2.status = DNAC_VALIDATOR_RETIRING;
    CHECK_EQ(nodus_validator_update(&w, &v2), 0);

    /* Mirror the handler's status-resolution path: each committee member
     * is re-fetched via nodus_validator_get; the status from the table
     * is what the RPC ships. Cached committee still lists v2 — but the
     * resolved status is now RETIRING. */
    int seen_retiring = 0, seen_active = 0;
    for (int i = 0; i < count; i++) {
        dnac_validator_record_t rec;
        CHECK_EQ(nodus_validator_get(&w, committee[i].pubkey, &rec), 0);
        if (rec.status == DNAC_VALIDATOR_RETIRING) seen_retiring++;
        if (rec.status == DNAC_VALIDATOR_ACTIVE)   seen_active++;
    }
    CHECK_EQ(seen_retiring, 1);
    CHECK_EQ(seen_active, 1);
    fprintf(stderr, "[2/5] status resolution OK (cache frozen, status live)\n");

    /* ── (3) endpoint lookup (P2P-PORT F5) ────────────────────────── */
    /* The transport roster this case used to seed is deleted: the RPC's
     * address is now the member's own signed ADDR record held by the p2p
     * host (nodus_witness_p2p_signed_addr — test_witness_p2p.c covers a
     * record that IS held). Here there is no p2p host, so every member's
     * address is empty — the handler's own rule for "no record". */
    CHECK(w.p2p == NULL);
    for (int i = 0; i < count; i++) {
        char addr[CMT_P2P_NETADDR_STR_MAX];
        addr[0] = '\0';
        CHECK(!nodus_witness_p2p_signed_addr(w.p2p, committee[i].pubkey,
                                             addr, sizeof(addr)));
        CHECK(addr[0] == '\0');
    }
    fprintf(stderr, "[3/5] endpoint lookup (no p2p host → empty) OK\n");

    (void)insert_block_row; /* reserved for future full-epoch lookback tests */

    sqlite3_close(w.db);
    rmrf(data_path);

    case_rpc_power();
    case_decoder();

    fprintf(stderr, "test_committee_query_rpc: all 5 scenarios passed\n");
    return 0;
}
