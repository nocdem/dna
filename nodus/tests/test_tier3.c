/**
 * Nodus — Tier 3 message BODY codec tests (fleet P2P-PORT phase F5).
 *
 * The tier-3 envelope ({t, y, q, wh, a, wsig}), its per-message 0x03
 * signature, the roster / IDENT verbs and the consensus verbs 35-39 are
 * DELETED (nodus_tier3.h). What survives are the four message BODIES the
 * 4004 channels 0x70 (genesis bundle, the former verbs 24/25) and 0x71
 * (governance approval, the former verbs 40/41) carry — each the verb's
 * former `a` map, byte for byte.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · all four bodies round-trip through encode → decode, every field;
 *   · a 0x70 message is a RESPONSE exactly when it carries `t` or `d`, a
 *     0x71 message a REQUEST exactly when it carries `e` (R-P2P-48 — the
 *     kind is read from the key set, no byte is added);
 *   · the request body's bytes are the former `a` map's bytes (a pinned
 *     vector, hand-derived from RFC 8949: map(1) "e" bstr);
 *   · D-24 rev 4 (1): a 31- or 33-byte pin is a HARD decode error in both
 *     0x70 messages, never a zero-filled pin;
 *   · a chunk above NODUS_T3_V2_GBUNDLE_CHUNK_MAX is refused by the
 *     encoder AND the decoder;
 *   · the 0x71 decoders stay STRICT: an unknown key, a duplicated key, a
 *     key the `ok` value does not admit, a wrong-length signature — each
 *     refused;
 *   · a 0x71 response carries the REQUEST IDENTITY `rq` (decision
 *     2026-09-27-p2p-fix-2.md (2)): it round-trips in both forms, and a
 *     response without it (either form) or with a 63-byte one is refused
 *     (a well-formed control decodes, so each refusal is for its one
 *     defect);
 *   · a negative integer anywhere, a non-map top level, and trailing
 *     bytes after the one map are refused (D-22 rev 3's rule, kept).
 *
 * WHAT IT REQUIRES: nothing beyond a default nodus build. WHAT IT LEAVES
 * BEHIND: nothing. HOW IT CAN LIE: the vectors are this file's own
 * RFC 8949 derivations, not captured from a 0.19 node's wire; the
 * byte-identity with the former `a` maps rests on the encoders being the
 * former `enc_*_args` bodies unchanged (nodus_tier3.c).
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0;
static int failed = 0;

#define TEST(n)       do { printf("  %-60s", n); fflush(stdout); } while (0)
#define PASS()        do { printf("PASS\n"); passed++; } while (0)
#define FAIL(m)       do { printf("FAIL: %s\n", m); failed++; return; } while (0)

static void test_gbundle_q_roundtrip(void)
{
    nodus_t3_w_v2_gbundle_q_t in;
    nodus_t3_msg_t out;
    uint8_t buf[256];
    size_t len = 0;

    TEST("0x70 request round trip (kind 24)");
    memset(&in, 0, sizeof(in));
    memset(in.chain, 0x11, 32);
    memset(in.pin, 0x22, 32);
    in.offset = 4096;
    if (nodus_t3_gbundle_q_encode(&in, buf, sizeof(buf), &len) != 0) FAIL("encode");
    if (nodus_t3_gbundle_decode(buf, len, &out) != 0) FAIL("decode");
    if (out.type != NODUS_T3_V2_GBUNDLE_REQ) FAIL("kind is not the request");
    if (memcmp(out.w_v2_gbundle_q.chain, in.chain, 32) != 0 ||
        memcmp(out.w_v2_gbundle_q.pin, in.pin, 32) != 0 ||
        out.w_v2_gbundle_q.offset != in.offset) FAIL("field mismatch");
    PASS();
}

static void test_gbundle_r_roundtrip(void)
{
    nodus_t3_w_v2_gbundle_r_t in;
    nodus_t3_msg_t out;
    static uint8_t chunk[NODUS_T3_V2_GBUNDLE_CHUNK_MAX];
    static uint8_t buf[NODUS_T3_GBUNDLE_MSG_MAX];
    size_t len = 0, i;

    TEST("0x70 response round trip (kind 25), a full 48 KB chunk");
    for (i = 0; i < sizeof(chunk); i++) chunk[i] = (uint8_t)(i * 7u);
    memset(&in, 0, sizeof(in));
    memset(in.chain, 0x33, 32);
    memset(in.pin, 0x44, 32);
    in.total = 90000;
    in.offset = 4096;
    in.chunk = chunk;
    in.chunk_len = (uint32_t)sizeof(chunk);
    if (nodus_t3_gbundle_r_encode(&in, buf, sizeof(buf), &len) != 0) FAIL("encode");
    if (len > NODUS_T3_GBUNDLE_MSG_MAX) FAIL("exceeds the channel ceiling");
    if (nodus_t3_gbundle_decode(buf, len, &out) != 0) FAIL("decode");
    if (out.type != NODUS_T3_V2_GBUNDLE_RSP) FAIL("kind is not the response");
    if (memcmp(out.w_v2_gbundle_r.chain, in.chain, 32) != 0 ||
        memcmp(out.w_v2_gbundle_r.pin, in.pin, 32) != 0 ||
        out.w_v2_gbundle_r.total != in.total ||
        out.w_v2_gbundle_r.offset != in.offset ||
        out.w_v2_gbundle_r.chunk_len != in.chunk_len ||
        memcmp(out.w_v2_gbundle_r.chunk, chunk, sizeof(chunk)) != 0)
        FAIL("field mismatch");
    PASS();
}

static void test_gbundle_chunk_ceiling(void)
{
    nodus_t3_w_v2_gbundle_r_t in;
    nodus_t3_msg_t out;
    static uint8_t chunk[NODUS_T3_V2_GBUNDLE_CHUNK_MAX + 1];
    static uint8_t buf[NODUS_T3_GBUNDLE_MSG_MAX + 64];
    size_t len = 0;
    cbor_encoder_t enc;

    TEST("0x70 chunk above 48 KB refused (encoder and decoder)");
    memset(&in, 0, sizeof(in));
    in.chunk = chunk;
    in.chunk_len = (uint32_t)sizeof(chunk);
    if (nodus_t3_gbundle_r_encode(&in, buf, sizeof(buf), &len) == 0)
        FAIL("encoder emitted an oversize chunk");
    /* hand-built: the same map with the oversize chunk */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, chunk, 32);
    cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, chunk, 32);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, chunk, sizeof(chunk));
    len = cbor_encoder_len(&enc);
    if (len == 0) FAIL("fixture encode");
    if (nodus_t3_gbundle_decode(buf, len, &out) == 0)
        FAIL("decoder accepted an oversize chunk");
    PASS();
}

static size_t pin_probe(uint8_t *buf, size_t cap, bool rsp, size_t pin_len)
{
    uint8_t pin[40];
    cbor_encoder_t enc;

    memset(pin, 0x5a, sizeof(pin));
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, rsp ? 5 : 3);
    cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, pin, 32);
    cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, pin, pin_len);
    if (rsp) {
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 10);
    }
    cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, 0);
    if (rsp) {
        cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, pin, 4);
    }
    return cbor_encoder_len(&enc);
}

static void test_gbundle_pin_length(void)
{
    uint8_t buf[256];
    nodus_t3_msg_t out;
    int rsp;

    TEST("0x70 pin is exactly 32 bytes (31 / 33 = hard error)");
    for (rsp = 0; rsp < 2; rsp++) {
        size_t n = pin_probe(buf, sizeof(buf), rsp != 0, 32);
        if (nodus_t3_gbundle_decode(buf, n, &out) != 0) FAIL("32-byte pin refused");
        n = pin_probe(buf, sizeof(buf), rsp != 0, 31);
        if (nodus_t3_gbundle_decode(buf, n, &out) == 0) FAIL("31-byte pin accepted");
        n = pin_probe(buf, sizeof(buf), rsp != 0, 33);
        if (nodus_t3_gbundle_decode(buf, n, &out) == 0) FAIL("33-byte pin accepted");
    }
    PASS();
}

static void test_cc_appr_req_vector(void)
{
    static const uint8_t e[2] = { 0x01, 0x02 };
    /* RFC 8949: a1 (map 1) 61 65 ("e") 42 01 02 (bstr 2) */
    static const uint8_t want[] = { 0xa1, 0x61, 0x65, 0x42, 0x01, 0x02 };
    nodus_t3_cc_appr_req_t in;
    nodus_t3_msg_t out;
    uint8_t buf[64];
    size_t len = 0;

    TEST("0x71 request bytes = the former `a` map (pinned vector)");
    in.e = e;
    in.e_len = sizeof(e);
    if (nodus_t3_cc_appr_req_encode(&in, buf, sizeof(buf), &len) != 0) FAIL("encode");
    if (len != sizeof(want) || memcmp(buf, want, len) != 0) FAIL("bytes differ");
    if (nodus_t3_cc_appr_decode(buf, len, &out) != 0) FAIL("decode");
    if (out.type != NODUS_T3_CC_APPR_REQ || out.cc_appr_req.e_len != 2 ||
        memcmp(out.cc_appr_req.e, e, 2) != 0) FAIL("round trip");
    PASS();
}

static void test_cc_appr_rsp_roundtrip(void)
{
    nodus_t3_cc_appr_rsp_t ok_in, ref_in;
    nodus_t3_msg_t out;
    uint8_t buf[NODUS_T3_CC_APPR_RSP_MAX + 256];
    size_t len = 0;

    TEST("0x71 response round trip (approval and refusal, with `rq`)");
    memset(&ok_in, 0, sizeof(ok_in));
    ok_in.ok = true;
    ok_in.seat = 6;
    memset(ok_in.sig, 0x7c, sizeof(ok_in.sig));
    memset(ok_in.set_hash, 0x3d, sizeof(ok_in.set_hash));
    ok_in.epoch = 99;
    memset(ok_in.rq, 0x5e, sizeof(ok_in.rq));
    if (nodus_t3_cc_appr_rsp_encode(&ok_in, buf, sizeof(buf), &len) != 0) FAIL("encode ok");
    if (len > NODUS_T3_CC_APPR_RSP_MAX) FAIL("approval above NODUS_T3_CC_APPR_RSP_MAX");
    if (nodus_t3_cc_appr_decode(buf, len, &out) != 0) FAIL("decode ok");
    if (out.type != NODUS_T3_CC_APPR_RSP || !out.cc_appr_rsp.ok ||
        out.cc_appr_rsp.seat != 6 || out.cc_appr_rsp.epoch != 99 ||
        memcmp(out.cc_appr_rsp.sig, ok_in.sig, sizeof(ok_in.sig)) != 0 ||
        memcmp(out.cc_appr_rsp.set_hash, ok_in.set_hash, 64) != 0 ||
        memcmp(out.cc_appr_rsp.rq, ok_in.rq, NODUS_T3_CC_APPR_RQ_BYTES) != 0)
        FAIL("approval mismatch");

    memset(&ref_in, 0, sizeof(ref_in));
    ref_in.ok = false;
    snprintf(ref_in.reason, sizeof(ref_in.reason), "not a committee seat");
    memset(ref_in.rq, 0xa7, sizeof(ref_in.rq));
    if (nodus_t3_cc_appr_rsp_encode(&ref_in, buf, sizeof(buf), &len) != 0) FAIL("encode refusal");
    if (nodus_t3_cc_appr_decode(buf, len, &out) != 0) FAIL("decode refusal");
    if (out.type != NODUS_T3_CC_APPR_RSP || out.cc_appr_rsp.ok ||
        strcmp(out.cc_appr_rsp.reason, "not a committee seat") != 0 ||
        memcmp(out.cc_appr_rsp.rq, ref_in.rq, NODUS_T3_CC_APPR_RQ_BYTES) != 0)
        FAIL("refusal mismatch");
    PASS();
}

static void test_cc_appr_strict(void)
{
    uint8_t buf[8192];
    uint8_t sig[NODUS_SIG_BYTES];
    uint8_t sh[64];
    uint8_t rq[NODUS_T3_CC_APPR_RQ_BYTES];
    nodus_t3_msg_t out;
    cbor_encoder_t enc;
    size_t len;

    TEST("0x71 decoders stay strict (unknown / duplicate / ok-mismatch / rq)");
    memset(sig, 1, sizeof(sig));
    memset(sh, 2, sizeof(sh));
    memset(rq, 3, sizeof(rq));

    /* request with an extra key */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "e"); cbor_encode_bstr(&enc, sh, 4);
    cbor_encode_cstr(&enc, "x"); cbor_encode_uint(&enc, 1);
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("unknown key accepted");

    /* request with `e` twice */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "e"); cbor_encode_bstr(&enc, sh, 4);
    cbor_encode_cstr(&enc, "e"); cbor_encode_bstr(&enc, sh, 4);
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("duplicate key accepted");

    /* the control: a well-formed refusal WITH `rq` decodes — so each
     * refusal below is refused for its one defect */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, false);
    cbor_encode_cstr(&enc, "r");  cbor_encode_cstr(&enc, "no");
    cbor_encode_cstr(&enc, "rq"); cbor_encode_bstr(&enc, rq, sizeof(rq));
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) != 0) FAIL("well-formed refusal refused");

    /* ok=false carrying a signature */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, false);
    cbor_encode_cstr(&enc, "r");  cbor_encode_cstr(&enc, "no");
    cbor_encode_cstr(&enc, "s");  cbor_encode_bstr(&enc, sig, sizeof(sig));
    cbor_encode_cstr(&enc, "rq"); cbor_encode_bstr(&enc, rq, sizeof(rq));
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("ok=false with s accepted");

    /* ok=true with a short signature */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 6);
    cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, true);
    cbor_encode_cstr(&enc, "i");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");  cbor_encode_bstr(&enc, sig, sizeof(sig) - 1);
    cbor_encode_cstr(&enc, "sh"); cbor_encode_bstr(&enc, sh, 64);
    cbor_encode_cstr(&enc, "ep"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "rq"); cbor_encode_bstr(&enc, rq, sizeof(rq));
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("short signature accepted");

    /* decision 2026-09-27-p2p-fix-2.md (2): `rq` is REQUIRED in both
     * forms, and exactly 64 bytes */
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, true);
    cbor_encode_cstr(&enc, "i");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");  cbor_encode_bstr(&enc, sig, sizeof(sig));
    cbor_encode_cstr(&enc, "sh"); cbor_encode_bstr(&enc, sh, 64);
    cbor_encode_cstr(&enc, "ep"); cbor_encode_uint(&enc, 1);
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("approval without rq accepted");

    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, false);
    cbor_encode_cstr(&enc, "r");  cbor_encode_cstr(&enc, "no");
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("refusal without rq accepted");

    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, false);
    cbor_encode_cstr(&enc, "r");  cbor_encode_cstr(&enc, "no");
    cbor_encode_cstr(&enc, "rq"); cbor_encode_bstr(&enc, rq, sizeof(rq) - 1);
    len = cbor_encoder_len(&enc);
    if (nodus_t3_cc_appr_decode(buf, len, &out) == 0) FAIL("63-byte rq accepted");
    PASS();
}

static void test_framing_refusals(void)
{
    nodus_t3_w_v2_gbundle_q_t q;
    nodus_t3_msg_t out;
    uint8_t buf[256];
    size_t len = 0;
    cbor_encoder_t enc;

    TEST("negint / non-map / trailing bytes refused");
    memset(&q, 0, sizeof(q));
    if (nodus_t3_gbundle_q_encode(&q, buf, sizeof(buf) - 1, &len) != 0) FAIL("encode");
    buf[len] = 0x00;                                   /* one trailing item */
    if (nodus_t3_gbundle_decode(buf, len + 1, &out) == 0) FAIL("trailing byte accepted");
    if (nodus_t3_cc_appr_decode(buf, len + 1, &out) == 0) FAIL("trailing byte accepted (0x71)");

    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_array(&enc, 0);
    len = cbor_encoder_len(&enc);
    if (nodus_t3_gbundle_decode(buf, len, &out) == 0) FAIL("array accepted");

    /* {"o": -1} — 0xa1 0x61 'o' 0x20 */
    buf[0] = 0xa1; buf[1] = 0x61; buf[2] = 'o'; buf[3] = 0x20;
    if (nodus_t3_gbundle_decode(buf, 4, &out) == 0) FAIL("negative int accepted");
    PASS();
}

int main(void)
{
    printf("=== nodus tier-3 message bodies (channels 0x70 / 0x71) ===\n");
    test_gbundle_q_roundtrip();
    test_gbundle_r_roundtrip();
    test_gbundle_chunk_ceiling();
    test_gbundle_pin_length();
    test_cc_appr_req_vector();
    test_cc_appr_rsp_roundtrip();
    test_cc_appr_strict();
    test_framing_refusals();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
