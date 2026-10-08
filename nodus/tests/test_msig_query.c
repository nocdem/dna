/**
 * @file nodus/tests/test_msig_query.c
 * @brief dnac_msig_utxo / dnac_msig_addr_history — a multisig VAULT
 *        MEMBER reads the vault address's coins and history — driven
 *        through the REAL dispatcher (nodus_witness_handle_dnac) over a
 *        socketpair, and the client SDK's decoders over the bytes it
 *        answers.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 * Governing records: docs/plans/2026-09-29-general-multisig-design.md §8
 * + §8.6 rev 2; docs/plans/decisions/2026-10-08-kurultay-15-vault-member-
 * query-summary.md (approved 2026-10-08). If any of these is false, the
 * matching case fails:
 *  t_member_coins    a session whose public key is one of the descriptor's
 *                    keys gets the address's coins: q = dnac_msig_utxo,
 *                    "r" = count / block_height / utxos / trunc (4 keys,
 *                    "trunc" last), every coin decoded by the client's
 *                    dnac_utxo decoder with "trunc" required.
 *  t_trunc           5 coins: max 3 → 3 coins, trunc true; max 5 → 5,
 *                    false; no max → 5, false; and the 3 returned are the
 *                    first 3 of the max-5 answer (amount DESC order).
 *  t_not_member      a valid descriptor of the target address, session
 *                    key NOT in it → NOT_AUTHENTICATED; a descriptor that
 *                    DOES hold the session key but whose address is not
 *                    `owner` → NOT_AUTHENTICATED; a disordered and a
 *                    truncated descriptor → NOT_AUTHENTICATED; all four
 *                    with the SAME message (nothing says which step).
 *  t_bad_args        owner uppercase / 127 / 129 chars / not a string,
 *                    owner or msig repeated, msig empty / oversize / a
 *                    text string / missing, max 0 / 101 / not a uint, a
 *                    non-text key → PROTOCOL_ERROR — each with a member
 *                    session, so the refusal is the argument's.
 *  t_unauth          peer_id_set false → NOT_AUTHENTICATED even for a
 *                    payload with no args map at all (checked before any
 *                    parse), for both methods.
 *  t_db_fault        the coin store unreadable (w->db NULL) → INTERNAL_
 *                    ERROR, never an empty success (§8.6 item 7).
 *  t_history         dnac_msig_addr_history: member → the gate PASSES and
 *                    the builder answers NOT_FOUND (this fixture serves no
 *                    version-3 chain); non-member → NOT_AUTHENTICATED;
 *                    repeated limit, limit 0 / 101, bi without before →
 *                    PROTOCOL_ERROR; a crafted dnac_msig_addr_history
 *                    reply decodes with nodus_dnac_addr_history_decode.
 *  t_builder_gate    the gate cannot be skipped by calling the history
 *                    builder directly: nodus_witness_msig_member_ok is
 *                    true for each member key and false for a non-member
 *                    key, an address that is not the descriptor's, a
 *                    disordered descriptor and every NULL input;
 *                    nodus_witness_msig_addr_history_build with a
 *                    non-member key, with NULL key or NULL descriptor →
 *                    NOT_AUTHENTICATED carrying the handler's exact text
 *                    (NODUS_WITNESS_MSIG_NOT_MEMBER) and no frame; a
 *                    malformed owner → PROTOCOL_ERROR before the gate; a
 *                    member key → NOT_FOUND (the gate passed; this
 *                    fixture serves no version-3 chain).
 *  t_dnac_utxo_same  REGRESSION: dnac_utxo with owner == session still
 *                    answers exactly 3 keys (no "trunc"), q = dnac_utxo;
 *                    its decoder still accepts it; the msig decoder
 *                    REFUSES it (no "trunc"); dnac_utxo for another owner
 *                    is still NOT_AUTHENTICATED (C11).
 *  t_error_mapping   the dispatcher's answer to an unknown dnac_* method
 *                    maps to NODUS_CLIENT_ERR_METHOD_UNSUPPORTED; a
 *                    PROTOCOL_ERROR with other text stays 7; a
 *                    NOT_AUTHENTICATED stays 1; a non-bool "trunc" is
 *                    refused by the decoder.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (the target compiles
 * src/client/nodus_client.c itself with NODUS_CLIENT_TEST_SEAM=1 and
 * defines NODUS_WITNESS_INTERNAL_API — nodus/CMakeLists.txt). Environment:
 * none. No network: one AF_UNIX socketpair per case.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_msig_query_*` directory per case (the chain database);
 * removed at close. A case that aborts through CHECK leaves it behind.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The descriptor keys are PATTERN bytes, not ML-DSA-87 keys: the gate
 *     compares bytes (dna_msig_desc_parse checks tag, order and the zero
 *     prefix, not key validity), so this is the gate's real input class,
 *     but no signature is ever made with them.
 *  2. The session identity is SET on the connection (peer_id_set,
 *     peer_pk), as nodus_auth.c / nodus_witness_ipc.c would; the AUTH
 *     handshake itself is not driven here.
 *  3. The history SUCCESS answer is not driven: this fixture has no
 *     version-3 chain, so a member reaches the shared builder and gets
 *     NOT_FOUND. That proves the gate passed and the msig builder ran
 *     (NOT_FOUND comes only from it); the rows it would read are pinned by
 *     test_addr_index.c (same builder, ai_history_build). The client side
 *     of a success is pinned with a crafted reply.
 *  4. The client request functions (nodus_client_dnac_msig_utxo /
 *     _addr_history) are not round-tripped (no client session); their
 *     decoders and their error mapping are, over the node's real bytes.
 *  5. Coins are planted in utxo_set by SQL with domain_id = CORE when the
 *     column exists; no block applies them.
 *  6. Nothing here was RUN by its author (BUILDER: compile only). Every
 *     expectation is an expectation.
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
#include "witness/nodus_witness_addr_index.h"   /* the builder + member gate */
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "dnac/msig_wire.h"
#include "dnac/ledger_ids.h"

/* NODUS_CLIENT_TEST_SEAM entry points (src/client/nodus_client.c) */
int nodus_client_test_parse_utxo(const uint8_t *raw, size_t raw_len,
                                 nodus_dnac_utxo_result_t *out);
int nodus_client_test_parse_msig_utxo(const uint8_t *raw, size_t raw_len,
                                      nodus_dnac_utxo_result_t *out,
                                      bool *trunc_out);
int nodus_client_test_msig_error_rc(const uint8_t *raw, size_t raw_len);

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

/* ── keys and descriptors ───────────────────────────────────────────── */

#define PK  DNA_MSIG_PUBKEY_LEN

/* Pattern key k: every byte (0x10 + k) — ascending in k, never a zero
 * prefix. Keys 0..3 are used; key 3 is a member of no descriptor. */
static void key_fill(int k, uint8_t out[PK])
{
    memset(out, 0x10 + k, PK);
}

static void hex64(const uint8_t raw[64], char out[129])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 0x0F];
    }
    out[128] = '\0';
}

typedef struct {
    uint8_t d[DNA_MSIG_MAX_DESC_LEN];
    size_t  len;
    char    owner[129];
} desc_t;

/* A 2-of-n descriptor over keys `ks` (ascending), its address as hex. */
static void desc_make(desc_t *o, const int *ks, uint8_t n)
{
    static uint8_t keys[DNA_MSIG_MAX_N * PK];
    uint8_t addr[DNA_MSIG_ADDR_LEN];
    for (uint8_t i = 0; i < n; i++) key_fill(ks[i], keys + (size_t)i * PK);
    CHECK(dna_msig_desc_encode(2, n, keys, o->d, sizeof(o->d),
                               &o->len) == 0, "descriptor encodes");
    CHECK(dna_msig_address(o->d, o->len, addr) == 0, "descriptor address");
    hex64(addr, o->owner);
}

/* ── fixture: a bare chain database + a socketpair session ───────────── */

typedef struct {
    char              dir[256];
    nodus_witness_t  *w;
    int               sv[2];       /* [0] the node's end, [1] ours */
    nodus_tcp_conn_t *conn;
} fx_t;

static void fx_session(fx_t *f, bool authed, int key)
{
    f->conn->peer_id_set = authed;
    memset(f->conn->peer_pk.bytes, 0, sizeof(f->conn->peer_pk.bytes));
    memset(f->conn->peer_id.bytes, 0, sizeof(f->conn->peer_id.bytes));
    if (authed && key >= 0) {
        key_fill(key, f->conn->peer_pk.bytes);
        /* a fingerprint-shaped id; dnac_utxo's C11 compares against it */
        memset(f->conn->peer_id.bytes, 0xA0 + key,
               sizeof(f->conn->peer_id.bytes));
    }
}

static void fx_open(fx_t *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    f->sv[0] = f->sv[1] = -1;
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_msig_query_%s_XXXXXX", tag);
    CHECK(mkdtemp(f->dir) != NULL, "mkdtemp");
    f->w = calloc(1, sizeof(*f->w));      /* multi-MB — never the stack */
    CHECK(f->w != NULL, "witness alloc");
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t chain_id16[16];
    memset(chain_id16, 0x3c, sizeof(chain_id16));
    CHECK(nodus_witness_create_chain_db(f->w, chain_id16) == 0,
          "chain database");

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0, "socketpair");
    CHECK(fcntl(f->sv[0], F_SETFL, O_NONBLOCK) == 0 &&
          fcntl(f->sv[1], F_SETFL, O_NONBLOCK) == 0, "nonblocking");
    f->conn = calloc(1, sizeof(*f->conn));
    CHECK(f->conn != NULL, "conn alloc");
    f->conn->fd = f->sv[0];
    f->conn->state = NODUS_CONN_CONNECTED;
    fx_session(f, true, 0);
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
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->dir);
    if (system(cmd) != 0) printf("note: could not remove %s\n", f->dir);
    memset(f, 0, sizeof(*f));
}

/* Plant one CORE coin of `owner` (128 hex). */
static void plant_coin(fx_t *f, const char *owner, uint8_t nf_byte,
                       uint64_t amount)
{
    sqlite3_stmt *ti = NULL;
    bool has_dom = false;
    CHECK(sqlite3_prepare_v2(f->w->db, "PRAGMA table_info(utxo_set)", -1,
                             &ti, NULL) == SQLITE_OK, "table_info");
    while (sqlite3_step(ti) == SQLITE_ROW) {
        const unsigned char *nm = sqlite3_column_text(ti, 1);
        if (nm && strcmp((const char *)nm, "domain_id") == 0)
            has_dom = true;
    }
    sqlite3_finalize(ti);

    sqlite3_stmt *st = NULL;
    const char *sql = has_dom
        ? "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
          "tx_hash, output_index, block_height, created_at, domain_id) "
          "VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, 0, ?6)"
        : "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
          "tx_hash, output_index, block_height, created_at) "
          "VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, 0)";
    CHECK(sqlite3_prepare_v2(f->w->db, sql, -1, &st, NULL) == SQLITE_OK,
          "prepare coin insert");
    uint8_t nf[64], tok[64], txh[64];
    memset(nf, nf_byte, sizeof(nf));
    memset(tok, 0, sizeof(tok));
    memset(txh, nf_byte ^ 0x5a, sizeof(txh));
    sqlite3_bind_blob(st, 1, nf, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    sqlite3_bind_blob(st, 4, tok, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, txh, 64, SQLITE_TRANSIENT);
    if (has_dom) sqlite3_bind_int64(st, 6, (sqlite3_int64)DNA_DOMAIN_CORE);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "coin planted");
    sqlite3_finalize(st);
}

/* ── requests ───────────────────────────────────────────────────────── */

typedef enum { A_TSTR, A_BSTR, A_UINT, A_UINTKEY } akind_t;
typedef struct {
    const char *key;      /* A_UINTKEY: ignored, the key is uint 7 */
    akind_t     kind;
    const void *p;
    size_t      len;
    uint64_t    u;
} arg_t;

static uint8_t g_req[64 * 1024];

/* {t, y:"q", q:method, a:{args}}; `no_args` = no "a" at all. */
static size_t build_req(const char *method, const arg_t *args, size_t n,
                        bool no_args)
{
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_req, sizeof(g_req));
    cbor_encode_map(&enc, no_args ? 3 : 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 77);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, method);
    if (!no_args) {
        cbor_encode_cstr(&enc, "a");
        cbor_encode_map(&enc, n);
        for (size_t i = 0; i < n; i++) {
            if (args[i].kind == A_UINTKEY) cbor_encode_uint(&enc, 7);
            else                           cbor_encode_cstr(&enc, args[i].key);
            switch (args[i].kind) {
            case A_TSTR:    cbor_encode_tstr(&enc, args[i].p, args[i].len); break;
            case A_BSTR:    cbor_encode_bstr(&enc, args[i].p, args[i].len); break;
            case A_UINT:
            case A_UINTKEY: cbor_encode_uint(&enc, args[i].u); break;
            }
        }
    }
    size_t len = cbor_encoder_len(&enc);
    CHECK(len > 0, "request encodes");
    return len;
}

#define ARG_T(k, s, l)  { (k), A_TSTR, (s), (l), 0 }
#define ARG_B(k, b, l)  { (k), A_BSTR, (b), (l), 0 }
#define ARG_U(k, v)     { (k), A_UINT, NULL, 0, (v) }

/* ── replies ────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  payload[1 << 20];
    size_t   len;
    char     type;             /* 'r' / 'e' */
    int      code;
    char     msg[128];
    char     q[64];
    size_t   rkeys;            /* entries of "r" (responses) */
    bool     has_trunc;
    char     last_rkey[16];
} reply_t;

static reply_t g_rep;
static uint8_t g_rx[1 << 20];

/* Dispatch one request and read its ONE framed reply off our end. */
static reply_t *call(fx_t *f, const char *method, size_t req_len)
{
    size_t have = 0;
    nodus_frame_t fr;

    nodus_witness_handle_dnac(f->w, f->conn, g_req, req_len, method, 77);
    for (;;) {
        ssize_t n = read(f->sv[1], g_rx + have, sizeof(g_rx) - have);
        if (n > 0) { have += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;                                 /* EAGAIN: all read */
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
    snprintf(g_rep.msg, sizeof(g_rep.msg), "%s", msg.error_msg);
    nodus_t2_msg_free(&msg);

    /* "q" and the "r" map's keys, walked here */
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, g_rep.payload, g_rep.len);
    cbor_item_t top = cbor_decode_next(&dec);
    CHECK(top.type == CBOR_ITEM_MAP, "reply is a map");
    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        CHECK(k.type == CBOR_ITEM_TSTR, "text keys");
        if (k.tstr.len == 1 && k.tstr.ptr[0] == 'q') {
            cbor_item_t v = cbor_decode_next(&dec);
            CHECK(v.type == CBOR_ITEM_TSTR && v.tstr.len < sizeof(g_rep.q),
                  "q is text");
            memcpy(g_rep.q, v.tstr.ptr, v.tstr.len);
        } else if (k.tstr.len == 1 && k.tstr.ptr[0] == 'r') {
            cbor_item_t r = cbor_decode_next(&dec);
            CHECK(r.type == CBOR_ITEM_MAP, "r is a map");
            g_rep.rkeys = r.count;
            for (size_t j = 0; j < r.count; j++) {
                cbor_item_t rk = cbor_decode_next(&dec);
                CHECK(rk.type == CBOR_ITEM_TSTR &&
                      rk.tstr.len < sizeof(g_rep.last_rkey), "r key");
                memset(g_rep.last_rkey, 0, sizeof(g_rep.last_rkey));
                memcpy(g_rep.last_rkey, rk.tstr.ptr, rk.tstr.len);
                if (rk.tstr.len == 5 && memcmp(rk.tstr.ptr, "trunc", 5) == 0)
                    g_rep.has_trunc = true;
                cbor_decode_skip(&dec);
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    return &g_rep;
}

static reply_t *msig_utxo(fx_t *f, const char *owner, const desc_t *d,
                          bool with_max, uint64_t max)
{
    arg_t a[3] = {
        ARG_T("owner", owner, strlen(owner)),
        ARG_B("msig", d->d, d->len),
        ARG_U("max", max),
    };
    return call(f, "dnac_msig_utxo",
                build_req("dnac_msig_utxo", a, with_max ? 3 : 2, false));
}

static void expect_err(const reply_t *r, int code, const char *what)
{
    if (r->type != 'e' || r->code != code)
        printf("  got type=%c code=%d msg=\"%s\" for: %s\n",
               r->type ? r->type : '?', r->code, r->msg, what);
    CHECK(r->type == 'e' && r->code == code, what);
}

/* ── cases ──────────────────────────────────────────────────────────── */

static const int K012[3] = {0, 1, 2};

static void t_member_coins(void)
{
    fx_t f; desc_t d;
    fx_open(&f, "member");
    desc_make(&d, K012, 3);
    plant_coin(&f, d.owner, 0x31, 700);
    plant_coin(&f, d.owner, 0x32, 500);

    for (int member = 0; member < 3; member++) {
        fx_session(&f, true, member);
        reply_t *r = msig_utxo(&f, d.owner, &d, false, 0);
        CHECK(r->type == 'r', "a member gets an answer");
        CHECK(strcmp(r->q, "dnac_msig_utxo") == 0, "q = dnac_msig_utxo");
        CHECK(r->rkeys == 4 && r->has_trunc &&
              strcmp(r->last_rkey, "trunc") == 0,
              "count / block_height / utxos, then trunc LAST");

        nodus_dnac_utxo_result_t res;
        bool trunc = true;
        CHECK(nodus_client_test_parse_msig_utxo(r->payload, r->len, &res,
                                                &trunc) == 0,
              "the client decodes it");
        CHECK(res.count == 2 && !trunc, "both coins, not truncated");
        CHECK(res.entries[0].amount == 700 && res.entries[1].amount == 500,
              "amount DESC");
        CHECK(strcmp(res.entries[0].owner, d.owner) == 0,
              "owner = the vault address");
        nodus_client_free_utxo_result(&res);
    }
    fx_close(&f);
}

static void t_trunc(void)
{
    fx_t f; desc_t d;
    fx_open(&f, "trunc");
    desc_make(&d, K012, 3);
    for (int c = 0; c < 5; c++)
        plant_coin(&f, d.owner, (uint8_t)(0x40 + c), 100u * (uint64_t)(c + 1));
    fx_session(&f, true, 1);

    nodus_dnac_utxo_result_t r5, r3;
    bool t = false;
    reply_t *r = msig_utxo(&f, d.owner, &d, true, 5);
    CHECK(nodus_client_test_parse_msig_utxo(r->payload, r->len, &r5, &t) == 0
          && r5.count == 5 && !t, "max 5 of 5: all, not truncated");

    r = msig_utxo(&f, d.owner, &d, true, 3);
    CHECK(nodus_client_test_parse_msig_utxo(r->payload, r->len, &r3, &t) == 0
          && r3.count == 3 && t, "max 3 of 5: 3 coins, trunc TRUE");
    for (int i = 0; i < 3; i++)
        CHECK(memcmp(r3.entries[i].nullifier, r5.entries[i].nullifier,
                     sizeof(r3.entries[i].nullifier)) == 0,
              "the page is the first max of the ordered list");
    nodus_client_free_utxo_result(&r3);
    nodus_client_free_utxo_result(&r5);

    r = msig_utxo(&f, d.owner, &d, false, 0);
    CHECK(nodus_client_test_parse_msig_utxo(r->payload, r->len, &r5, &t) == 0
          && r5.count == 5 && !t, "no max = 100: all 5, not truncated");
    nodus_client_free_utxo_result(&r5);
    fx_close(&f);
}

static void t_not_member(void)
{
    fx_t f; desc_t d, d_other;
    char msg0[128];
    fx_open(&f, "notmember");
    desc_make(&d, K012, 3);
    plant_coin(&f, d.owner, 0x51, 900);

    /* key 3 is in no descriptor */
    fx_session(&f, true, 3);
    reply_t *r = msig_utxo(&f, d.owner, &d, false, 0);
    expect_err(r, NODUS_ERR_NOT_AUTHENTICATED,
               "valid descriptor of the owner, session not a member");
    snprintf(msg0, sizeof(msg0), "%s", r->msg);

    /* the session IS in d_other, but d_other's address is not owner */
    static const int K03[2] = {0, 3};
    desc_make(&d_other, K03, 2);
    r = msig_utxo(&f, d.owner, &d_other, false, 0);
    expect_err(r, NODUS_ERR_NOT_AUTHENTICATED,
               "member of ANOTHER descriptor whose address != owner");
    CHECK(strcmp(r->msg, msg0) == 0, "same message (step not revealed)");

    /* a member of d, but d disordered (keys 0 and 1 swapped) */
    fx_session(&f, true, 0);
    desc_t bad = d;
    memcpy(bad.d + DNA_MSIG_HDR_LEN, d.d + DNA_MSIG_HDR_LEN + PK, PK);
    memcpy(bad.d + DNA_MSIG_HDR_LEN + PK, d.d + DNA_MSIG_HDR_LEN, PK);
    r = msig_utxo(&f, d.owner, &bad, false, 0);
    expect_err(r, NODUS_ERR_NOT_AUTHENTICATED, "disordered descriptor");
    CHECK(strcmp(r->msg, msg0) == 0, "same message (parse step)");

    /* a member of d, d truncated by one byte */
    bad = d;
    bad.len = d.len - 1;
    r = msig_utxo(&f, d.owner, &bad, false, 0);
    expect_err(r, NODUS_ERR_NOT_AUTHENTICATED, "truncated descriptor");
    CHECK(strcmp(r->msg, msg0) == 0, "same message (length step)");

    /* and the honest member still reads it */
    r = msig_utxo(&f, d.owner, &d, false, 0);
    CHECK(r->type == 'r', "the member of d still gets the answer");
    fx_close(&f);
}

static void t_bad_args(void)
{
    fx_t f; desc_t d;
    char own[130];
    static uint8_t big[DNA_MSIG_MAX_DESC_LEN + 1];
    fx_open(&f, "badargs");
    desc_make(&d, K012, 3);
    fx_session(&f, true, 0);

    /* uppercase */
    memcpy(own, d.owner, 129);
    for (int i = 0; i < 128; i++)
        if (own[i] >= 'a' && own[i] <= 'f') { own[i] = (char)(own[i] - 32); break; }
    CHECK(strcmp(own, d.owner) != 0, "an uppercase letter was made");
    expect_err(msig_utxo(&f, own, &d, false, 0), NODUS_ERR_PROTOCOL_ERROR,
               "uppercase owner");

    /* 127 and 129 characters */
    memcpy(own, d.owner, 127); own[127] = '\0';
    expect_err(msig_utxo(&f, own, &d, false, 0), NODUS_ERR_PROTOCOL_ERROR,
               "127-character owner");
    memcpy(own, d.owner, 128); own[128] = '0'; own[129] = '\0';
    expect_err(msig_utxo(&f, own, &d, false, 0), NODUS_ERR_PROTOCOL_ERROR,
               "129-character owner");

    /* max out of bounds */
    expect_err(msig_utxo(&f, d.owner, &d, true, 0), NODUS_ERR_PROTOCOL_ERROR,
               "max 0");
    expect_err(msig_utxo(&f, d.owner, &d, true, 101), NODUS_ERR_PROTOCOL_ERROR,
               "max 101");

    {   /* owner repeated (both copies valid) */
        arg_t a[3] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len),
                       ARG_T("owner", d.owner, 128) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 3, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "repeated owner");
    }
    {   /* msig repeated */
        arg_t a[3] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len),
                       ARG_B("msig", d.d, d.len) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 3, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "repeated msig");
    }
    {   /* max repeated */
        arg_t a[4] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len),
                       ARG_U("max", 3), ARG_U("max", 3) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 4, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "repeated max");
    }
    {   /* max not a uint */
        arg_t a[3] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len),
                       ARG_T("max", "3", 1) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 3, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "max as text");
    }
    {   /* owner not a string */
        arg_t a[2] = { ARG_B("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 2, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "owner as bytes");
    }
    {   /* msig empty */
        arg_t a[2] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, 0) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 2, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "empty msig");
    }
    {   /* msig one byte over the longest descriptor */
        memcpy(big, d.d, d.len);
        arg_t a[2] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", big, sizeof(big)) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 2, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "oversize msig");
    }
    {   /* msig as text */
        arg_t a[2] = { ARG_T("owner", d.owner, 128),
                       ARG_T("msig", "abc", 3) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 2, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "msig as text");
    }
    {   /* msig missing: NOT "absent = plain C11" */
        arg_t a[1] = { ARG_T("owner", d.owner, 128) };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 1, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "missing msig");
    }
    {   /* a non-text key */
        arg_t a[3] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len),
                       { NULL, A_UINTKEY, NULL, 0, 1 } };
        expect_err(call(&f, "dnac_msig_utxo",
                        build_req("dnac_msig_utxo", a, 3, false)),
                   NODUS_ERR_PROTOCOL_ERROR, "non-text key");
    }
    {   /* an unknown key is skipped: the request still answers */
        arg_t a[3] = { ARG_T("owner", d.owner, 128),
                       ARG_B("msig", d.d, d.len),
                       ARG_U("zz", 1) };
        reply_t *r = call(&f, "dnac_msig_utxo",
                          build_req("dnac_msig_utxo", a, 3, false));
        CHECK(r->type == 'r', "an unknown key is skipped");
    }
    fx_close(&f);
}

static void t_unauth(void)
{
    fx_t f; desc_t d;
    fx_open(&f, "unauth");
    desc_make(&d, K012, 3);
    fx_session(&f, false, -1);

    expect_err(msig_utxo(&f, d.owner, &d, false, 0),
               NODUS_ERR_NOT_AUTHENTICATED, "no session (valid request)");
    expect_err(call(&f, "dnac_msig_utxo",
                    build_req("dnac_msig_utxo", NULL, 0, true)),
               NODUS_ERR_NOT_AUTHENTICATED,
               "no session, NO args map: refused before any parse");
    expect_err(call(&f, "dnac_msig_addr_history",
                    build_req("dnac_msig_addr_history", NULL, 0, true)),
               NODUS_ERR_NOT_AUTHENTICATED,
               "history: no session, NO args map");

    /* with a session the same args-less request is a PROTOCOL_ERROR */
    fx_session(&f, true, 0);
    expect_err(call(&f, "dnac_msig_utxo",
                    build_req("dnac_msig_utxo", NULL, 0, true)),
               NODUS_ERR_PROTOCOL_ERROR, "session, no args map");
    fx_close(&f);
}

static void t_db_fault(void)
{
    fx_t f; desc_t d;
    fx_open(&f, "dbfault");
    desc_make(&d, K012, 3);
    plant_coin(&f, d.owner, 0x61, 10);
    fx_session(&f, true, 2);

    sqlite3 *db = f.w->db;
    f.w->db = NULL;                    /* the store cannot be read */
    expect_err(msig_utxo(&f, d.owner, &d, false, 0),
               NODUS_ERR_INTERNAL_ERROR,
               "a store fault is INTERNAL_ERROR, never an empty list");
    f.w->db = db;
    fx_close(&f);
}

static reply_t *msig_hist(fx_t *f, const desc_t *d, const char *owner,
                          const arg_t *extra, size_t n_extra)
{
    arg_t a[8];
    size_t n = 0;
    a[n++] = (arg_t)ARG_T("owner", owner, strlen(owner));
    a[n++] = (arg_t)ARG_B("msig", d->d, d->len);
    for (size_t i = 0; i < n_extra && n < 8; i++) a[n++] = extra[i];
    return call(f, "dnac_msig_addr_history",
                build_req("dnac_msig_addr_history", a, n, false));
}

static void t_history(void)
{
    fx_t f; desc_t d;
    fx_open(&f, "history");
    desc_make(&d, K012, 3);

    const arg_t lim10[1] = { ARG_U("limit", 10) };
    fx_session(&f, true, 1);
    reply_t *r = msig_hist(&f, &d, d.owner, lim10, 1);
    expect_err(r, NODUS_ERR_NOT_FOUND,
               "member: the gate passes and the builder answers NOT_FOUND "
               "(no version-3 chain in this fixture)");

    fx_session(&f, true, 3);
    char msg_nm[128];
    r = msig_hist(&f, &d, d.owner, lim10, 1);
    expect_err(r, NODUS_ERR_NOT_AUTHENTICATED, "history: non-member");
    snprintf(msg_nm, sizeof(msg_nm), "%s", r->msg);

    fx_session(&f, true, 0);
    {
        const arg_t two[2] = { ARG_U("limit", 10), ARG_U("limit", 10) };
        expect_err(msig_hist(&f, &d, d.owner, two, 2),
                   NODUS_ERR_PROTOCOL_ERROR, "history: repeated limit");
    }
    {
        const arg_t z[1] = { ARG_U("limit", 0) };
        expect_err(msig_hist(&f, &d, d.owner, z, 1),
                   NODUS_ERR_PROTOCOL_ERROR, "history: limit 0");
    }
    {
        const arg_t o[1] = { ARG_U("limit", NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT + 1) };
        expect_err(msig_hist(&f, &d, d.owner, o, 1),
                   NODUS_ERR_PROTOCOL_ERROR, "history: limit 101");
    }
    {
        const arg_t bi[2] = { ARG_U("limit", 10), ARG_U("bi", 1) };
        expect_err(msig_hist(&f, &d, d.owner, bi, 2),
                   NODUS_ERR_PROTOCOL_ERROR, "history: bi without before");
    }
    expect_err(msig_hist(&f, &d, d.owner, NULL, 0),
               NODUS_ERR_PROTOCOL_ERROR, "history: missing limit");

    /* the member gate on a descriptor whose address is not owner */
    {
        static const int K03[2] = {0, 3};
        desc_t d2;
        desc_make(&d2, K03, 2);
        r = msig_hist(&f, &d2, d.owner, lim10, 1);
        expect_err(r, NODUS_ERR_NOT_AUTHENTICATED,
                   "history: descriptor address != owner");
        CHECK(strcmp(r->msg, msg_nm) == 0, "history: same message");
    }

    /* the client decoder over a dnac_msig_addr_history reply */
    {
        uint8_t buf[512];
        cbor_encoder_t enc;
        nodus_dnac_addr_history_result_t hr;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 9);
        cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
        cbor_encode_cstr(&enc, "q");
        cbor_encode_cstr(&enc, "dnac_msig_addr_history");
        cbor_encode_cstr(&enc, "r");
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "count");       cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "enabled");     cbor_encode_bool(&enc, true);
        cbor_encode_cstr(&enc, "from_height"); cbor_encode_uint(&enc, 5);
        cbor_encode_cstr(&enc, "entries");     cbor_encode_array(&enc, 0);
        size_t blen = cbor_encoder_len(&enc);
        CHECK(blen > 0, "crafted history reply");
        CHECK(nodus_dnac_addr_history_decode(buf, blen, &hr) == 0 &&
              hr.count == 0 && hr.enabled && hr.from_height == 5,
              "the dnac_addr_history decoder reads a dnac_msig_addr_history "
              "reply");
        nodus_client_free_addr_history_result(&hr);
    }
    fx_close(&f);
}

/* The member gate lives in the builder itself: a caller that skips the
 * handler still has to present a member key. */
static void t_builder_gate(void)
{
    fx_t f; desc_t d, d_other;
    uint8_t owner_raw[64], other_raw[64], pk[PK];
    fx_open(&f, "buildergate");
    desc_make(&d, K012, 3);
    static const int K03[2] = {0, 3};
    desc_make(&d_other, K03, 2);
    CHECK(nodus_witness_owner_hex_to_raw(d.owner, 128, owner_raw) == 0,
          "owner raw");
    CHECK(nodus_witness_owner_hex_to_raw(d_other.owner, 128, other_raw) == 0,
          "other owner raw");

    /* nodus_witness_msig_member_ok */
    for (int k = 0; k < 3; k++) {
        key_fill(k, pk);
        CHECK(nodus_witness_msig_member_ok(pk, owner_raw, d.d, d.len),
              "each descriptor key is a member");
    }
    key_fill(3, pk);
    CHECK(!nodus_witness_msig_member_ok(pk, owner_raw, d.d, d.len),
          "key 3 is not a member of d");
    CHECK(nodus_witness_msig_member_ok(pk, other_raw, d_other.d,
                                       d_other.len),
          "key 3 is a member of d_other at d_other's address");
    CHECK(!nodus_witness_msig_member_ok(pk, owner_raw, d_other.d,
                                        d_other.len),
          "d_other's address is not owner");
    {
        desc_t bad = d;
        memcpy(bad.d + DNA_MSIG_HDR_LEN, d.d + DNA_MSIG_HDR_LEN + PK, PK);
        memcpy(bad.d + DNA_MSIG_HDR_LEN + PK, d.d + DNA_MSIG_HDR_LEN, PK);
        key_fill(0, pk);
        CHECK(!nodus_witness_msig_member_ok(pk, owner_raw, bad.d, bad.len),
              "a disordered descriptor admits nobody");
    }
    key_fill(0, pk);
    CHECK(!nodus_witness_msig_member_ok(NULL, owner_raw, d.d, d.len),
          "NULL key");
    CHECK(!nodus_witness_msig_member_ok(pk, NULL, d.d, d.len),
          "NULL owner");
    CHECK(!nodus_witness_msig_member_ok(pk, owner_raw, NULL, d.len),
          "NULL descriptor");
    CHECK(!nodus_witness_msig_member_ok(pk, owner_raw, d.d, 0),
          "empty descriptor");

    /* nodus_witness_msig_addr_history_build called directly */
    uint8_t *frame = NULL;
    size_t   frame_len = 0;
    int      ecode = 0;
    char     emsg[128];

    key_fill(3, pk);
    CHECK(nodus_witness_msig_addr_history_build(
              f.w, 7, pk, d.d, d.len, d.owner, NULL, 10, &frame,
              &frame_len, &ecode, emsg, sizeof(emsg)) == -1 &&
          ecode == NODUS_ERR_NOT_AUTHENTICATED && frame == NULL &&
          frame_len == 0 &&
          strcmp(emsg, NODUS_WITNESS_MSIG_NOT_MEMBER) == 0,
          "builder: non-member key refused with the handler's text");

    CHECK(nodus_witness_msig_addr_history_build(
              f.w, 7, NULL, d.d, d.len, d.owner, NULL, 10, &frame,
              &frame_len, &ecode, emsg, sizeof(emsg)) == -1 &&
          ecode == NODUS_ERR_NOT_AUTHENTICATED && frame == NULL &&
          strcmp(emsg, NODUS_WITNESS_MSIG_NOT_MEMBER) == 0,
          "builder: no key refused");

    key_fill(0, pk);
    CHECK(nodus_witness_msig_addr_history_build(
              f.w, 7, pk, NULL, 0, d.owner, NULL, 10, &frame,
              &frame_len, &ecode, emsg, sizeof(emsg)) == -1 &&
          ecode == NODUS_ERR_NOT_AUTHENTICATED && frame == NULL &&
          strcmp(emsg, NODUS_WITNESS_MSIG_NOT_MEMBER) == 0,
          "builder: no descriptor refused");

    CHECK(nodus_witness_msig_addr_history_build(
              f.w, 7, pk, d_other.d, d_other.len, d.owner, NULL, 10,
              &frame, &frame_len, &ecode, emsg, sizeof(emsg)) == -1 &&
          ecode == NODUS_ERR_NOT_AUTHENTICATED && frame == NULL &&
          strcmp(emsg, NODUS_WITNESS_MSIG_NOT_MEMBER) == 0,
          "builder: a member of another descriptor refused");

    {
        char upper[129];
        snprintf(upper, sizeof(upper), "%s", d.owner);
        for (int i = 0; i < 128; i++) {
            if (upper[i] >= 'a' && upper[i] <= 'f') {
                upper[i] = (char)(upper[i] - 'a' + 'A');
                break;
            }
        }
        CHECK(strcmp(upper, d.owner) != 0, "an uppercase letter was made");
        CHECK(nodus_witness_msig_addr_history_build(
                  f.w, 7, pk, d.d, d.len, upper, NULL, 10, &frame,
                  &frame_len, &ecode, emsg, sizeof(emsg)) == -1 &&
              ecode == NODUS_ERR_PROTOCOL_ERROR && frame == NULL,
              "builder: malformed owner is a PROTOCOL_ERROR");
    }

    CHECK(nodus_witness_msig_addr_history_build(
              f.w, 7, pk, d.d, d.len, d.owner, NULL, 10, &frame,
              &frame_len, &ecode, emsg, sizeof(emsg)) == -1 &&
          ecode == NODUS_ERR_NOT_FOUND && frame == NULL,
          "builder: a member passes the gate (NOT_FOUND: no version-3 "
          "chain in this fixture)");
    fx_close(&f);
}

static void t_dnac_utxo_same(void)
{
    fx_t f;
    char me[129];
    uint8_t raw[64];
    fx_open(&f, "dnacutxo");
    fx_session(&f, true, 2);
    memcpy(raw, f.conn->peer_id.bytes, 64);
    hex64(raw, me);
    plant_coin(&f, me, 0x71, 42);

    arg_t a[2] = { ARG_T("owner", me, 128), ARG_U("max", 10) };
    reply_t *r = call(&f, "dnac_utxo", build_req("dnac_utxo", a, 2, false));
    CHECK(r->type == 'r' && strcmp(r->q, "dnac_utxo") == 0,
          "dnac_utxo answers its owner, q = dnac_utxo");
    CHECK(r->rkeys == 3 && !r->has_trunc && strcmp(r->last_rkey, "utxos") == 0,
          "dnac_utxo: still exactly count / block_height / utxos");

    nodus_dnac_utxo_result_t res;
    bool t = false;
    CHECK(nodus_client_test_parse_utxo(r->payload, r->len, &res) == 0 &&
          res.count == 1 && res.entries[0].amount == 42,
          "dnac_utxo decoder unchanged");
    nodus_client_free_utxo_result(&res);
    CHECK(nodus_client_test_parse_msig_utxo(r->payload, r->len, &res, &t) ==
          NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL,
          "the msig decoder refuses a reply without trunc");

    /* C11 unchanged: another owner */
    desc_t d;
    desc_make(&d, K012, 3);
    arg_t b[2] = { ARG_T("owner", d.owner, 128), ARG_B("msig", d.d, d.len) };
    r = call(&f, "dnac_utxo", build_req("dnac_utxo", b, 2, false));
    expect_err(r, NODUS_ERR_NOT_AUTHENTICATED,
               "dnac_utxo ignores msig and keeps C11 (key 2 is a member, "
               "still refused there)");
    fx_close(&f);
}

static void t_error_mapping(void)
{
    fx_t f;
    fx_open(&f, "errmap");

    /* the dispatcher's own answer to a method it lacks */
    reply_t *r = call(&f, "dnac_no_such_method",
                      build_req("dnac_no_such_method", NULL, 0, true));
    expect_err(r, NODUS_ERR_PROTOCOL_ERROR, "unknown method answer");
    CHECK(strcmp(r->msg, NODUS_DNAC_UNKNOWN_METHOD_MSG) == 0,
          "the dispatcher sends the contract text");
    CHECK(nodus_client_test_msig_error_rc(r->payload, r->len) ==
          NODUS_CLIENT_ERR_METHOD_UNSUPPORTED,
          "the client maps it to METHOD_UNSUPPORTED");

    /* other PROTOCOL_ERROR text stays PROTOCOL_ERROR */
    r = call(&f, "dnac_msig_utxo", build_req("dnac_msig_utxo", NULL, 0, true));
    expect_err(r, NODUS_ERR_PROTOCOL_ERROR, "args-less msig_utxo");
    CHECK(nodus_client_test_msig_error_rc(r->payload, r->len) ==
          NODUS_ERR_PROTOCOL_ERROR, "another PROTOCOL_ERROR stays 7");

    /* NOT_AUTHENTICATED stays NOT_AUTHENTICATED */
    fx_session(&f, false, -1);
    r = call(&f, "dnac_msig_utxo", build_req("dnac_msig_utxo", NULL, 0, true));
    CHECK(nodus_client_test_msig_error_rc(r->payload, r->len) ==
          NODUS_ERR_NOT_AUTHENTICATED, "NOT_AUTHENTICATED stays 1");

    /* a non-bool trunc is refused */
    {
        uint8_t buf[256];
        cbor_encoder_t enc;
        nodus_dnac_utxo_result_t res;
        bool t = false;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 3);
        cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
        cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "dnac_msig_utxo");
        cbor_encode_cstr(&enc, "r");
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "count");        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "block_height"); cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "utxos");        cbor_encode_array(&enc, 0);
        cbor_encode_cstr(&enc, "trunc");        cbor_encode_uint(&enc, 1);
        size_t blen = cbor_encoder_len(&enc);
        CHECK(blen > 0, "crafted reply");
        CHECK(nodus_client_test_parse_msig_utxo(buf, blen, &res, &t) ==
              NODUS_ERR_PROTOCOL_ERROR, "trunc as a uint is refused");
    }
    fx_close(&f);
}

int main(void)
{
    printf("=== dnac_msig_utxo / dnac_msig_addr_history (vault member) ===\n");
    t_member_coins();
    t_trunc();
    t_not_member();
    t_bad_args();
    t_unauth();
    t_db_fault();
    t_history();
    t_builder_gate();
    t_dnac_utxo_same();
    t_error_mapping();
    printf("test_msig_query: ALL %d checks passed\n", g_checks);
    return 0;
}
