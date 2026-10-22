/**
 * Nodus — dnac_token_info and dnac_msig_utxo client decoders, strict forms
 * (mm-dex package B verifier findings 1 and 2, 2026-10-22)
 *
 * What it proves:
 *   - dnac_token_info: a reply is accepted only when every one of tid /
 *     name / sym / dec / supply / creator is present exactly once with its
 *     own type, name <= 32 and sym <= 8 bytes with no embedded NUL (judged
 *     on the wire length, not on the copy), dec <= 18 judged BEFORE the
 *     uint8_t narrowing (262 must not become 6), the returned tid equals
 *     the one asked, and nothing is truncated. Each refusal is
 *     NODUS_ERR_PROTOCOL_ERROR with a zeroed result.
 *   - dnac_msig_utxo (vault listing): an entry without a 64-byte "tid"
 *     refuses the whole answer (a missing id would read as a native coin);
 *     an entry with one decodes.
 *
 * Requires: a default standalone nodus build; no environment. nodus_client.c
 * is compiled into this test with NODUS_CLIENT_TEST_SEAM=1 (the
 * test_client_dup_array arrangement).
 * Leaves behind: nothing.
 * How it can lie: only the decoders are driven, over hand-built bytes; the
 * request path, the real server encoder and the wallet's use of the result
 * are not. Never run by its author (BUILDER: compile only).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus.h"
#include "protocol/nodus_cbor.h"
#include "crypto/utils/qgp_log.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_TOKEN_INFO_DECODE"

int nodus_client_test_parse_token_info(const uint8_t *raw, size_t raw_len,
                                       const uint8_t token_id[64],
                                       nodus_dnac_token_info_t *out);
int nodus_client_test_parse_msig_utxo(const uint8_t *raw, size_t raw_len,
                                      nodus_dnac_utxo_result_t *out,
                                      bool *trunc_out);

static int passed = 0;
static int failed = 0;

#define CHECK(cond, name) do {                                          \
    if (cond) { passed++; }                                             \
    else { failed++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s (%s:%d): %s",      \
                                   (name), __FILE__, __LINE__, #cond); } \
} while (0)

static uint8_t g_frame[4096];
static uint8_t g_tid[64];

static void reply_head(cbor_encoder_t *e, const char *method, size_t r_count) {
    cbor_encoder_init(e, g_frame, sizeof(g_frame));
    cbor_encode_map(e, 4);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, 42);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, "r");
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, method);
    cbor_encode_cstr(e, "r");
    cbor_encode_map(e, r_count);
}

/* the fields are written in the server's order; a NULL / flagged field is
 * left out or altered by the caller's choice */
typedef struct {
    bool        skip_tid, skip_name, skip_sym, skip_dec, skip_supply,
                skip_creator;
    const uint8_t *tid;      /* NULL = g_tid */
    size_t      tid_len;     /* 0 = 64 */
    const char *name; size_t name_len;
    const char *sym;  size_t sym_len;
    uint64_t    dec;
    bool        dup_sym;     /* write "sym" a second time (map count + 1) */
    bool        name_as_uint;
} info_t;

static size_t enc_info(const info_t *c) {
    cbor_encoder_t e;
    size_t n = 6;
    if (c->skip_tid) n--;
    if (c->skip_name) n--;
    if (c->skip_sym) n--;
    if (c->skip_dec) n--;
    if (c->skip_supply) n--;
    if (c->skip_creator) n--;
    if (c->dup_sym) n++;
    reply_head(&e, "dnac_token_info", n);
    if (!c->skip_tid) {
        cbor_encode_cstr(&e, "tid");
        cbor_encode_bstr(&e, c->tid ? c->tid : g_tid,
                         c->tid_len ? c->tid_len : 64);
    }
    if (!c->skip_name) {
        cbor_encode_cstr(&e, "name");
        if (c->name_as_uint) cbor_encode_uint(&e, 5);
        else cbor_encode_tstr(&e, c->name ? c->name : "Test USDT",
                              c->name ? c->name_len : 9);
    }
    if (!c->skip_sym) {
        cbor_encode_cstr(&e, "sym");
        cbor_encode_tstr(&e, c->sym ? c->sym : "tUSDT", c->sym ? c->sym_len : 5);
    }
    if (c->dup_sym) {
        cbor_encode_cstr(&e, "sym");
        cbor_encode_tstr(&e, "tUSDT", 5);
    }
    if (!c->skip_dec) {
        cbor_encode_cstr(&e, "dec"); cbor_encode_uint(&e, c->dec);
    }
    if (!c->skip_supply) {
        cbor_encode_cstr(&e, "supply"); cbor_encode_uint(&e, 1000000);
    }
    if (!c->skip_creator) {
        cbor_encode_cstr(&e, "creator");
        cbor_encode_tstr(&e, "abcdef", 6);
    }
    return cbor_encoder_len(&e);
}

static int parse_info(const info_t *c, nodus_dnac_token_info_t *out) {
    size_t len = enc_info(c);
    return nodus_client_test_parse_token_info(g_frame, len, g_tid, out);
}

static void test_token_info(void) {
    nodus_dnac_token_info_t t;
    info_t c;

    memset(&c, 0, sizeof(c)); c.dec = 6;
    CHECK(parse_info(&c, &t) == 0 && strcmp(t.name, "Test USDT") == 0 &&
          strcmp(t.symbol, "tUSDT") == 0 && t.decimals == 6 &&
          t.supply == 1000000 && memcmp(t.token_id, g_tid, 64) == 0,
          "token_info: a complete well-formed reply decodes");

    memset(&c, 0, sizeof(c)); c.dec = 18;
    CHECK(parse_info(&c, &t) == 0 && t.decimals == 18,
          "token_info: decimals 18 is the allowed maximum");

    memset(&c, 0, sizeof(c)); c.dec = 19;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR && t.decimals == 0,
          "token_info: decimals 19 refused");

    memset(&c, 0, sizeof(c)); c.dec = 262;   /* (uint8_t)262 == 6 */
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR && t.decimals == 0,
          "token_info: decimals 262 is refused, not narrowed to 6");

    memset(&c, 0, sizeof(c)); c.dec = 6;
    c.name = "Test USDT\0suffix"; c.name_len = 16;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR &&
          t.name[0] == '\0',
          "token_info: a name with an embedded NUL refused");

    memset(&c, 0, sizeof(c)); c.dec = 6;
    c.name = "0123456789012345678901234567890123"; c.name_len = 34;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: a 34-byte name (limit 32) refused, not truncated");

    memset(&c, 0, sizeof(c)); c.dec = 6;
    c.name = "01234567890123456789012345678901"; c.name_len = 32;
    CHECK(parse_info(&c, &t) == 0, "token_info: a 32-byte name accepted");

    memset(&c, 0, sizeof(c)); c.dec = 6;
    c.sym = "tUSDTtUSDT"; c.sym_len = 10;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: a 10-byte symbol (limit 8) refused");

    memset(&c, 0, sizeof(c)); c.dec = 6;
    c.sym = "tU\0DT"; c.sym_len = 5;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: a symbol with an embedded NUL refused");

    memset(&c, 0, sizeof(c)); c.dec = 6; c.skip_tid = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR, "token_info: no tid");
    memset(&c, 0, sizeof(c)); c.dec = 6; c.skip_name = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR, "token_info: no name");
    memset(&c, 0, sizeof(c)); c.dec = 6; c.skip_sym = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR, "token_info: no sym");
    memset(&c, 0, sizeof(c)); c.skip_dec = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR, "token_info: no dec");
    memset(&c, 0, sizeof(c)); c.dec = 6; c.skip_supply = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: no supply");
    memset(&c, 0, sizeof(c)); c.dec = 6; c.skip_creator = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: no creator");

    memset(&c, 0, sizeof(c)); c.dec = 6; c.dup_sym = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: a repeated key refused");

    memset(&c, 0, sizeof(c)); c.dec = 6; c.name_as_uint = true;
    CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
          "token_info: a mistyped name refused");

    {
        uint8_t other[64];
        memcpy(other, g_tid, 64); other[63] ^= 1;
        memset(&c, 0, sizeof(c)); c.dec = 6; c.tid = other;
        CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
              "token_info: another token's id in the reply refused");
        memset(&c, 0, sizeof(c)); c.dec = 6; c.tid = g_tid; c.tid_len = 63;
        CHECK(parse_info(&c, &t) == NODUS_ERR_PROTOCOL_ERROR,
              "token_info: a 63-byte tid refused");
    }

    /* a reply cut off mid-map: the map says 6 entries, the buffer ends */
    memset(&c, 0, sizeof(c)); c.dec = 6;
    {
        size_t len = enc_info(&c);
        CHECK(nodus_client_test_parse_token_info(g_frame, len - 4, g_tid, &t)
              == NODUS_ERR_PROTOCOL_ERROR,
              "token_info: a truncated reply refused");
    }
}

/* {count, block_height, utxos:[one entry], trunc:false}; the entry has a tid
 * only when `with_tid` (tid_len bytes) */
static size_t enc_vault(bool with_tid, size_t tid_len) {
    cbor_encoder_t e;
    uint8_t nul[NODUS_T3_NULLIFIER_LEN];
    memset(nul, 0x11, sizeof(nul));
    reply_head(&e, "dnac_msig_utxo", 4);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "block_height"); cbor_encode_uint(&e, 9);
    cbor_encode_cstr(&e, "utxos");
    cbor_encode_array(&e, 1);
    cbor_encode_map(&e, with_tid ? 3 : 2);
    cbor_encode_cstr(&e, "n");      cbor_encode_bstr(&e, nul, sizeof(nul));
    cbor_encode_cstr(&e, "amount"); cbor_encode_uint(&e, 5);
    if (with_tid) {
        cbor_encode_cstr(&e, "tid"); cbor_encode_bstr(&e, g_tid, tid_len);
    }
    cbor_encode_cstr(&e, "trunc"); cbor_encode_bool(&e, false);
    return cbor_encoder_len(&e);
}

static void test_vault_tid(void) {
    nodus_dnac_utxo_result_t res;
    bool trunc = true;
    size_t len;

    len = enc_vault(true, 64);
    CHECK(nodus_client_test_parse_msig_utxo(g_frame, len, &res, &trunc) == 0 &&
          res.count == 1 && res.entries[0].amount == 5 && !trunc &&
          memcmp(res.entries[0].token_id, g_tid, 64) == 0,
          "vault: an entry with a 64-byte tid decodes");
    nodus_client_free_utxo_result(&res);

    len = enc_vault(false, 0);
    CHECK(nodus_client_test_parse_msig_utxo(g_frame, len, &res, &trunc) ==
          NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL,
          "vault: an entry without a tid refuses the whole answer");
    nodus_client_free_utxo_result(&res);

    len = enc_vault(true, 63);
    CHECK(nodus_client_test_parse_msig_utxo(g_frame, len, &res, &trunc) ==
          NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL,
          "vault: a 63-byte tid refuses the whole answer");
    nodus_client_free_utxo_result(&res);
}

int main(void) {
    for (int i = 0; i < 64; i++) g_tid[i] = (uint8_t)(0xA0 + (i % 7));
    QGP_LOG_INFO(LOG_TAG, "=== token_info / vault utxo strict decoder tests ===");
    test_token_info();
    test_vault_tid();
    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===", passed, failed);
    return failed == 0 ? 0 : 1;
}
