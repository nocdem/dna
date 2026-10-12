/**
 * @file nodus/tests/test_storage_by_owner.c
 * @brief HF-6 slice 7a — dnac_storage_by_owner (the storage nodes one
 *        OWNER registered) driven through the REAL dispatcher
 *        (nodus_witness_handle_dnac) over a socketpair, and the client
 *        SDK's decoder (nodus_dnac_storage_by_owner_decode) over the bytes
 *        it answers and over crafted replies.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 * Governing record: design docs/plans/2026-10-03-hf5-validator-owner-
 * stake-design.md rev 6 §9 / §11 (v2_storage_nodes.payee_fp = owner_fp
 * since HF-6 6b); wire: include/nodus/nodus.h beside
 * nodus_client_dnac_storage_by_owner. If any of these is false, the
 * matching case fails:
 *  t_empty       an owner without rows → a success reply, q =
 *                dnac_storage_by_owner, "r" = ch / total / nodes (3 keys),
 *                total 0, an empty list (never an error); the decoder
 *                gives count 0, nodes NULL.
 *  t_rows        owner A's three rows (planted in the order 0x30.., 0x10..,
 *                0x20.., statuses ACTIVE / EXITING / RELEASED) come back
 *                ALL, node_fp ASCENDING (0x10, 0x20, 0x30), each with its
 *                status / bond / exit height / registered height and payee
 *                = A; owner B's row, whose fp sorts BETWEEN A's, is not in
 *                A's list and B's list holds only it; every listed entry
 *                equals, field by field, the dnac_storage_status answer for
 *                that fp (the shared st_status_fill / st_status_encode);
 *                decoding A's reply while naming B as the owner is refused.
 *  t_cap         owner C with NODUS_DNAC_STORAGE_SET_MAX + 1 rows → total
 *                257, exactly 256 listed, the 256 lowest fps in order; the
 *                highest is absent.
 *  t_bad_args    owner uppercase / 127 / 129 chars / a non-hex char / a
 *                byte string / missing → PROTOCOL_ERROR.
 *  t_status_regression  dnac_storage_status after the refactor: a
 *                registered fp answers 15 keys and decodes found; an
 *                unknown fp answers 8 keys, found false.
 *  t_db_fault    the registry table gone → INTERNAL_ERROR, never an empty
 *                success.
 *  t_client_refusals  crafted replies the decoder must refuse: an entry
 *                "fp" of 127 chars; an entry without "fp"; 257 entries
 *                (bounded BEFORE allocation); fps out of order; |nodes| !=
 *                min(total, 256); an entry with found false; an entry whose
 *                "ch" differs from the reply's; a repeated "nodes"; and a
 *                well-formed control reply that decodes.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (register_witness_test:
 * NODUS_WITNESS_INTERNAL_API, links libnodus — the decoder is public).
 * Environment: none. No network: one AF_UNIX socketpair per case.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_storage_by_owner_*` directory per case (the chain
 * database); removed at close. A case that aborts through CHECK leaves it.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The fixture chain has NO block (v2_blocks empty: tip 0, so H = 0) —
 *     no storage_set(H), no membership and no eligible segments are
 *     exercised; those fields come from the same st_status_fill the
 *     single-node RPC uses and are pinned here only as "equal to
 *     dnac_storage_status". The set / segment reads themselves are not
 *     driven by any case in this file.
 *  2. Registry rows are planted by SQL (node_pk is 2592 zero bytes); no
 *     STORAGE_REGISTER is applied.
 *  3. A reply larger than the socket buffer is drained by writing the
 *     connection's remaining wbuf bytes here (what the poll loop's
 *     EPOLLOUT drain does); the server's event loop is not run.
 *  4. The client request function (nodus_client_dnac_storage_by_owner) is
 *     not round-tripped (no client session); its decoder is, over the
 *     node's real bytes.
 *  5. Nothing here was RUN by its author (BUILDER: compile only). Every
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
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_produce.h"
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

#define SET_MAX  NODUS_DNAC_STORAGE_SET_MAX

static void hex64(const uint8_t raw[64], char out[129])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 0x0F];
    }
    out[128] = '\0';
}

/* ── fixture: an empty version-3 schema + a socketpair session ───────── */

typedef struct {
    char              dir[256];
    nodus_witness_t  *w;
    int               sv[2];       /* [0] the node's end, [1] ours */
    nodus_tcp_conn_t *conn;
} fx_t;

static void fx_open(fx_t *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    f->sv[0] = f->sv[1] = -1;
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_storage_by_owner_%s_XXXXXX",
             tag);
    CHECK(mkdtemp(f->dir) != NULL, "mkdtemp");
    f->w = calloc(1, sizeof(*f->w));      /* multi-MB — never the stack */
    CHECK(f->w != NULL, "witness alloc");
    f->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t chain_id16[16];
    memset(chain_id16, 0x7a, sizeof(chain_id16));
    CHECK(nodus_witness_create_chain_db(f->w, chain_id16) == 0,
          "chain database");
    /* the version-3 tables (v2_blocks) — the path tests/v2_genesis_
     * fixture.h v2x_seed_prepare takes */
    f->w->v2_successor = 1;
    CHECK(nodus_witness_db_migrate_v2s16(f->w) == 0, "v2 schema");
    uint64_t tip = 1;
    CHECK(nodus_witness_v2_tip_height(f->w, &tip) == 0 && tip == 0,
          "an open version-3 chain without blocks: tip 0");

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0, "socketpair");
    CHECK(fcntl(f->sv[0], F_SETFL, O_NONBLOCK) == 0 &&
          fcntl(f->sv[1], F_SETFL, O_NONBLOCK) == 0, "nonblocking");
    f->conn = calloc(1, sizeof(*f->conn));
    CHECK(f->conn != NULL, "conn alloc");
    f->conn->fd = f->sv[0];
    f->conn->state = NODUS_CONN_CONNECTED;
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

/* Plant one registry row (node_pk = 2592 zero bytes). */
static void plant(fx_t *f, const uint8_t fp[64], const uint8_t owner[64],
                  int status, uint64_t bond, uint64_t rh, uint64_t xh)
{
    static uint8_t pk[2592];
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(f->w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, bond, "
            "status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0)",
            -1, &st, NULL) == SQLITE_OK, "prepare row insert");
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, pk, sizeof(pk), SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, owner, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)bond);
    sqlite3_bind_int64(st, 5, status);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)rh);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)xh);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "row planted");
    sqlite3_finalize(st);
}

/* ── requests ───────────────────────────────────────────────────────── */

static uint8_t g_req[4096];

/* {t, y:"q", q:method, a:{key: value}}; `bstr` = the value as a byte
 * string; key NULL = an empty "a". */
static size_t build_req(const char *method, const char *key,
                        const void *val, size_t vlen, bool bstr)
{
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_req, sizeof(g_req));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 77);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, method);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, key ? 1 : 0);
    if (key) {
        cbor_encode_cstr(&enc, key);
        if (bstr) cbor_encode_bstr(&enc, val, vlen);
        else      cbor_encode_tstr(&enc, val, vlen);
    }
    size_t len = cbor_encoder_len(&enc);
    CHECK(len > 0, "request encodes");
    return len;
}

/* ── replies ────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  payload[1 << 20];
    size_t   len;
    char     type;             /* 'r' / 'e' */
    int      code;
    char     q[64];
    size_t   rkeys;            /* entries of "r" (responses) */
} reply_t;

static reply_t g_rep;
static uint8_t g_rx[1 << 20];

/* Dispatch one request and read its ONE framed reply off our end. Bytes
 * the node's socket did not take stay in conn->wbuf[wpos..wlen); they are
 * written here, as the poll loop's drain would (HOW IT CAN LIE 3). */
static reply_t *call(fx_t *f, const char *method, size_t req_len)
{
    size_t have = 0;
    nodus_frame_t fr;

    nodus_witness_handle_dnac(f->w, f->conn, g_req, req_len, method, 77);
    for (;;) {
        ssize_t n = read(f->sv[1], g_rx + have, sizeof(g_rx) - have);
        if (n > 0) { have += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        /* EAGAIN: our end is empty — push what the node still holds */
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
            for (size_t j = 0; j < r.count * 2; j++) cbor_decode_skip(&dec);
        } else {
            cbor_decode_skip(&dec);
        }
    }
    return &g_rep;
}

static reply_t *by_owner(fx_t *f, const uint8_t owner[64])
{
    char hex[129];
    hex64(owner, hex);
    return call(f, "dnac_storage_by_owner",
                build_req("dnac_storage_by_owner", "owner", hex, 128, false));
}

static reply_t *status_of(fx_t *f, const char *fp_hex)
{
    return call(f, "dnac_storage_status",
                build_req("dnac_storage_status", "fp", fp_hex, 128, false));
}

static bool st_same(const nodus_dnac_storage_status_t *a,
                    const nodus_dnac_storage_status_t *b)
{
    return a->committed_height == b->committed_height &&
           a->epoch_start == b->epoch_start && a->found == b->found &&
           a->status == b->status && a->bond == b->bond &&
           a->fail_streak == b->fail_streak &&
           a->grace_until == b->grace_until &&
           a->registered_height == b->registered_height &&
           a->exit_height == b->exit_height &&
           strcmp(a->payee, b->payee) == 0 &&
           a->set_exists == b->set_exists && a->set_count == b->set_count &&
           a->member == b->member && a->n_segments == b->n_segments &&
           a->n_listed == b->n_listed &&
           memcmp(a->segments, b->segments,
                  a->n_listed * sizeof(a->segments[0])) == 0;
}

/* ── cases ──────────────────────────────────────────────────────────── */

static void t_empty(void)
{
    fx_t f;
    uint8_t owner[64];
    char hex[129];
    nodus_dnac_storage_by_owner_t r;

    fx_open(&f, "empty");
    memset(owner, 0xEE, sizeof(owner));
    hex64(owner, hex);
    reply_t *rep = by_owner(&f, owner);
    CHECK(rep->type == 'r', "no rows: a success reply, not an error");
    CHECK(strcmp(rep->q, "dnac_storage_by_owner") == 0, "q names the method");
    CHECK(rep->rkeys == 3, "r = ch / total / nodes");
    CHECK(nodus_dnac_storage_by_owner_decode(rep->payload, rep->len, hex,
                                             &r) == 0, "empty answer decodes");
    CHECK(r.total == 0 && r.count == 0 && r.nodes == NULL &&
          r.committed_height == 0, "total 0, empty list");
    nodus_dnac_storage_by_owner_free(&r);
    fx_close(&f);
}

static void t_rows(void)
{
    fx_t f;
    uint8_t A[64], B[64], fp[64];
    char ahex[129], bhex[129];
    nodus_dnac_storage_by_owner_t r;

    fx_open(&f, "rows");
    memset(A, 0xAA, sizeof(A));
    memset(B, 0xBB, sizeof(B));
    hex64(A, ahex);
    hex64(B, bhex);
    /* A's rows planted out of order; B's fp sorts between them */
    memset(fp, 0x30, 64); plant(&f, fp, A, 3, 0, 9, 40);   /* RELEASED  */
    memset(fp, 0x10, 64); plant(&f, fp, A, 1, 500, 7, 0);  /* ACTIVE    */
    memset(fp, 0x20, 64); plant(&f, fp, A, 2, 600, 8, 30); /* EXITING   */
    memset(fp, 0x15, 64); plant(&f, fp, B, 1, 700, 6, 0);

    reply_t *rep = by_owner(&f, A);
    CHECK(rep->type == 'r' && rep->rkeys == 3, "A: a success reply");
    CHECK(nodus_dnac_storage_by_owner_decode(rep->payload, rep->len, ahex,
                                             &r) == 0, "A: decodes");
    CHECK(r.total == 3 && r.count == 3 && r.nodes != NULL,
          "A: all three rows, every status");
    {
        static const uint8_t want_b[3]  = { 0x10, 0x20, 0x30 };
        static const uint8_t want_st[3] = { 1, 2, 3 };
        static const uint64_t want_bond[3] = { 500, 600, 0 };
        static const uint64_t want_rh[3] = { 7, 8, 9 };
        static const uint64_t want_xh[3] = { 0, 30, 40 };
        for (size_t i = 0; i < 3; i++) {
            char want[129];
            memset(fp, want_b[i], 64);
            hex64(fp, want);
            const nodus_dnac_storage_status_t *s = &r.nodes[i].st;
            CHECK(strcmp(r.nodes[i].node_fp, want) == 0,
                  "A: node_fp ascending (0x10, 0x20, 0x30)");
            CHECK(s->found && s->status == want_st[i] &&
                  s->bond == want_bond[i] &&
                  s->registered_height == want_rh[i] &&
                  s->exit_height == want_xh[i] &&
                  strcmp(s->payee, ahex) == 0,
                  "A: each row's fields and payee = A");
            CHECK(!s->set_exists && !s->member && s->epoch_start == 0,
                  "A: no set at tip 0");
        }
    }
    /* every entry == the dnac_storage_status answer for its fp */
    for (size_t i = 0; i < r.count; i++) {
        nodus_dnac_storage_status_t one;
        reply_t *sr = status_of(&f, r.nodes[i].node_fp);
        CHECK(sr->type == 'r', "status of a listed fp answers");
        CHECK(nodus_dnac_storage_status_decode(sr->payload, sr->len,
                                               &one) == 0,
              "status of a listed fp decodes");
        CHECK(st_same(&one, &r.nodes[i].st),
              "a list entry equals the single-node status answer");
    }
    /* A's bytes, B named as the owner: refused */
    {
        nodus_dnac_storage_by_owner_t x;
        reply_t *ra = by_owner(&f, A);
        CHECK(nodus_dnac_storage_by_owner_decode(ra->payload, ra->len, bhex,
                                                 &x) == -1 &&
              x.nodes == NULL && x.count == 0,
              "an entry whose payee is not the named owner is refused");
    }
    nodus_dnac_storage_by_owner_free(&r);

    /* B: only its own row */
    rep = by_owner(&f, B);
    CHECK(nodus_dnac_storage_by_owner_decode(rep->payload, rep->len, bhex,
                                             &r) == 0, "B: decodes");
    memset(fp, 0x15, 64);
    {
        char want[129];
        hex64(fp, want);
        CHECK(r.total == 1 && r.count == 1 &&
              strcmp(r.nodes[0].node_fp, want) == 0 &&
              r.nodes[0].st.bond == 700,
              "B: only B's row; A's rows are not B's");
    }
    nodus_dnac_storage_by_owner_free(&r);
    fx_close(&f);
}

static void t_cap(void)
{
    fx_t f;
    uint8_t C[64], fp[64];
    char chex[129];
    nodus_dnac_storage_by_owner_t r;

    fx_open(&f, "cap");
    memset(C, 0xCC, sizeof(C));
    hex64(C, chex);
    /* SET_MAX + 1 rows, planted highest first; fp = big-endian index */
    for (int i = (int)SET_MAX; i >= 0; i--) {
        memset(fp, 0x77, 64);
        fp[0] = (uint8_t)(i >> 8);
        fp[1] = (uint8_t)(i & 0xFF);
        plant(&f, fp, C, 3, 0, 1, 1);
    }
    reply_t *rep = by_owner(&f, C);
    CHECK(rep->type == 'r', "cap: a success reply");
    CHECK(nodus_dnac_storage_by_owner_decode(rep->payload, rep->len, chex,
                                             &r) == 0, "cap: decodes");
    CHECK(r.total == (uint64_t)SET_MAX + 1u && r.count == SET_MAX,
          "cap: total 257, exactly 256 listed");
    for (size_t i = 0; i < r.count; i++) {
        char want[129];
        memset(fp, 0x77, 64);
        fp[0] = (uint8_t)(i >> 8);
        fp[1] = (uint8_t)(i & 0xFF);
        hex64(fp, want);
        CHECK(strcmp(r.nodes[i].node_fp, want) == 0,
              "cap: the 256 lowest fps, ascending (the highest absent)");
    }
    nodus_dnac_storage_by_owner_free(&r);
    fx_close(&f);
}

static void expect_proto(fx_t *f, size_t req_len, const char *name)
{
    reply_t *rep = call(f, "dnac_storage_by_owner", req_len);
    CHECK(rep->type == 'e' && rep->code == NODUS_ERR_PROTOCOL_ERROR, name);
}

static void t_bad_args(void)
{
    fx_t f;
    char hex[130];
    uint8_t raw[64];

    fx_open(&f, "args");
    memset(hex, 'a', sizeof(hex));
    hex[129] = '\0';
    hex[0] = 'A';
    expect_proto(&f, build_req("dnac_storage_by_owner", "owner", hex, 128,
                               false), "uppercase owner refused");
    hex[0] = 'a';
    expect_proto(&f, build_req("dnac_storage_by_owner", "owner", hex, 127,
                               false), "127-char owner refused");
    expect_proto(&f, build_req("dnac_storage_by_owner", "owner", hex, 129,
                               false), "129-char owner refused");
    hex[64] = 'g';
    expect_proto(&f, build_req("dnac_storage_by_owner", "owner", hex, 128,
                               false), "non-hex owner refused");
    memset(raw, 0xAA, sizeof(raw));
    expect_proto(&f, build_req("dnac_storage_by_owner", "owner", raw, 64,
                               true), "owner as a byte string refused");
    expect_proto(&f, build_req("dnac_storage_by_owner", NULL, NULL, 0,
                               false), "missing owner refused");
    fx_close(&f);
}

static void t_status_regression(void)
{
    fx_t f;
    uint8_t A[64], fp[64];
    char fhex[129];
    nodus_dnac_storage_status_t s;

    fx_open(&f, "status");
    memset(A, 0xAA, sizeof(A));
    memset(fp, 0x42, sizeof(fp));
    plant(&f, fp, A, 1, 900, 5, 0);
    hex64(fp, fhex);
    reply_t *rep = status_of(&f, fhex);
    CHECK(rep->type == 'r' && rep->rkeys == 15 &&
          strcmp(rep->q, "dnac_storage_status") == 0,
          "status of a registered fp: 15 keys");
    CHECK(nodus_dnac_storage_status_decode(rep->payload, rep->len, &s) == 0 &&
          s.found && s.bond == 900 && s.registered_height == 5,
          "status of a registered fp decodes its row");
    memset(fp, 0x43, sizeof(fp));
    hex64(fp, fhex);
    rep = status_of(&f, fhex);
    CHECK(rep->type == 'r' && rep->rkeys == 8, "status of an unknown fp: 8 keys");
    CHECK(nodus_dnac_storage_status_decode(rep->payload, rep->len, &s) == 0 &&
          !s.found, "status of an unknown fp: found false");
    fx_close(&f);
}

static void t_db_fault(void)
{
    fx_t f;
    uint8_t A[64];

    fx_open(&f, "fault");
    memset(A, 0xAA, sizeof(A));
    CHECK(sqlite3_exec(f.w->db, "DROP TABLE v2_storage_nodes", NULL, NULL,
                       NULL) == SQLITE_OK, "drop the registry");
    reply_t *rep = by_owner(&f, A);
    CHECK(rep->type == 'e' && rep->code == NODUS_ERR_INTERNAL_ERROR,
          "registry unreadable → INTERNAL_ERROR, never an empty success");
    fx_close(&f);
}

/* ── crafted replies for the decoder ────────────────────────────────── */

static uint8_t g_frame[1 << 20];

enum { N_OK, N_NO_FP, N_FP127, N_NOT_FOUND };

/* One "nodes" entry: a found row of `payee`, at committed height `ch`. */
static void enc_node(cbor_encoder_t *e, const char *fp, int mode,
                     uint64_t ch, const char *payee)
{
    const bool found = (mode != N_NOT_FOUND);
    cbor_encode_map(e, (mode == N_NO_FP ? 0u : 1u) + 8u + (found ? 7u : 0u));
    if (mode != N_NO_FP) {
        cbor_encode_cstr(e, "fp");
        cbor_encode_tstr(e, fp, mode == N_FP127 ? 127 : 128);
    }
    cbor_encode_cstr(e, "ch");    cbor_encode_uint(e, ch);
    cbor_encode_cstr(e, "es");    cbor_encode_uint(e, 0);
    cbor_encode_cstr(e, "found"); cbor_encode_bool(e, found);
    if (found) {
        cbor_encode_cstr(e, "st");    cbor_encode_uint(e, 1);
        cbor_encode_cstr(e, "bond");  cbor_encode_uint(e, 5);
        cbor_encode_cstr(e, "fs");    cbor_encode_uint(e, 0);
        cbor_encode_cstr(e, "gu");    cbor_encode_uint(e, 0);
        cbor_encode_cstr(e, "rh");    cbor_encode_uint(e, 1);
        cbor_encode_cstr(e, "xh");    cbor_encode_uint(e, 0);
        cbor_encode_cstr(e, "payee"); cbor_encode_cstr(e, payee);
    }
    cbor_encode_cstr(e, "set");   cbor_encode_bool(e, false);
    cbor_encode_cstr(e, "sc");    cbor_encode_uint(e, 0);
    cbor_encode_cstr(e, "mem");   cbor_encode_bool(e, false);
    cbor_encode_cstr(e, "ns");    cbor_encode_uint(e, 0);
    cbor_encode_cstr(e, "segs");  cbor_encode_array(e, 0);
}

/* {t, y:"r", q, r:{ch: 10, total, nodes:[n entries]}}, entry i's fp =
 * big-endian i (`fp_desc` = reversed, descending); `bad_at` / `bad_mode`
 * = entry index and its mode (SIZE_MAX = none);
 * `ch_off_at` = the entry whose "ch" is 1 more; `dup_nodes` = a second
 * "nodes" key. */
static size_t craft(size_t n, uint64_t total, int fp_desc, size_t bad_at,
                    int bad_mode, size_t ch_off_at, bool dup_nodes,
                    const char *payee)
{
    cbor_encoder_t e;
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 42);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_storage_by_owner");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, dup_nodes ? 4 : 3);
    cbor_encode_cstr(&e, "ch");    cbor_encode_uint(&e, 10);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, total);
    for (int rep = 0; rep < (dup_nodes ? 2 : 1); rep++) {
        cbor_encode_cstr(&e, "nodes");
        cbor_encode_array(&e, n);
        for (size_t i = 0; i < n; i++) {
            uint8_t fp[64];
            char fhex[129];
            const size_t k = fp_desc ? n - 1 - i : i;
            memset(fp, 0x55, 64);
            fp[0] = (uint8_t)(k >> 8);
            fp[1] = (uint8_t)(k & 0xFF);
            hex64(fp, fhex);
            enc_node(&e, fhex, i == bad_at ? bad_mode : N_OK,
                     i == ch_off_at ? 11 : 10, payee);
        }
    }
    size_t len = cbor_encoder_len(&e);
    CHECK(len > 0, "crafted reply encodes");
    return len;
}

static void refused(size_t len, const char *owner, const char *name)
{
    nodus_dnac_storage_by_owner_t r;
    CHECK(nodus_dnac_storage_by_owner_decode(g_frame, len, owner, &r) == -1 &&
          r.nodes == NULL && r.count == 0 && r.total == 0, name);
}

static void t_client_refusals(void)
{
    uint8_t P[64];
    char phex[129];
    nodus_dnac_storage_by_owner_t r;
    const size_t NONE = (size_t)-1;

    memset(P, 0x99, sizeof(P));
    hex64(P, phex);

    /* control: well formed */
    size_t len = craft(3, 3, 0, NONE, N_OK, NONE, false, phex);
    CHECK(nodus_dnac_storage_by_owner_decode(g_frame, len, phex, &r) == 0 &&
          r.count == 3 && r.total == 3 && r.committed_height == 10,
          "control: a well-formed crafted reply decodes");
    nodus_dnac_storage_by_owner_free(&r);
    len = craft(3, 300, 0, NONE, N_OK, NONE, false, phex);
    refused(len, phex, "|nodes| 3 with total 300 (not min(total, 256)) refused");
    len = craft(3, 3, 0, 1, N_FP127, NONE, false, phex);
    refused(len, phex, "an entry fp of 127 chars refused");
    len = craft(3, 3, 0, 2, N_NO_FP, NONE, false, phex);
    refused(len, phex, "an entry without fp refused");
    len = craft(3, 3, 0, 0, N_NOT_FOUND, NONE, false, phex);
    refused(len, phex, "an entry with found false refused");
    len = craft(3, 3, 1, NONE, N_OK, NONE, false, phex);
    refused(len, phex, "fps descending refused");
    len = craft(3, 3, 0, NONE, N_OK, 1, false, phex);
    refused(len, phex, "an entry whose ch differs from the reply's refused");
    len = craft(2, 2, 0, NONE, N_OK, NONE, true, phex);
    refused(len, phex, "a repeated \"nodes\" refused");
    len = craft(SET_MAX + 1u, SET_MAX + 1u, 0, NONE, N_OK, NONE, false, phex);
    refused(len, phex, "257 entries refused (bounded before allocation)");
}

int main(void)
{
    t_empty();
    t_rows();
    t_cap();
    t_bad_args();
    t_status_regression();
    t_db_fault();
    t_client_refusals();
    printf("test_storage_by_owner: %d checks passed\n", g_checks);
    return 0;
}
