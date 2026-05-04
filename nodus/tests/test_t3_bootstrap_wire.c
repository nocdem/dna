/**
 * Nodus — Tier 3 Bootstrap Wire Format Unit Test (PR 3 Yol B)
 *
 * Round-trip encode/decode test for the 4 witness auto-bootstrap message
 * types: w_chain_q (16), w_chain_r (17), w_genesis_req (18),
 * w_genesis_rsp (19).
 *
 * Coverage matrix:
 *   - method ↔ type mapping for all 4 new types
 *   - encode → decode → field equality roundtrip per type
 *   - nonce echo invariant: w_chain_q.nonce must equal w_chain_r.nonce
 *     when transmitted as a paired round
 *   - chain_def_blob hard cap: 64 KB accepted, 64 KB + 1 rejected at
 *     decode (H-2 mitigation against resource exhaustion)
 *
 * RED state: until A3 implements encode/decode dispatch + method strings,
 * all encode/roundtrip asserts fail. GREEN state arrives with A3.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", (name))
#define TEST_FAIL(name, msg) do { \
    fprintf(stderr, "  FAIL: %s — %s\n", (name), (msg)); \
    failures++; \
} while(0)

static int failures = 0;

/* Test identity (Dilithium5 keypair, generated once) */
static nodus_identity_t test_id;
static int identity_ready = 0;

static void ensure_identity(void) {
    if (identity_ready) return;
    if (nodus_identity_generate(&test_id) != 0) {
        fprintf(stderr, "FATAL: cannot generate test identity\n");
        exit(1);
    }
    identity_ready = 1;
}

static void fill_header(nodus_t3_header_t *hdr) {
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round = 0;            /* bootstrap is round-less */
    hdr->view = 0;
    memset(hdr->sender_id, 0xCC, NODUS_T3_WITNESS_ID_LEN);
    hdr->timestamp = 1709300000;
    hdr->nonce = 0xBADC0FFEE0DDF00DULL;
    memset(hdr->chain_id, 0xDD, 32);
}

static void check_header(const nodus_t3_header_t *a, const nodus_t3_header_t *b,
                         const char *test_name) {
    if (a->version != b->version ||
        a->round != b->round ||
        a->view != b->view ||
        memcmp(a->sender_id, b->sender_id, NODUS_T3_WITNESS_ID_LEN) != 0 ||
        a->timestamp != b->timestamp ||
        a->nonce != b->nonce ||
        memcmp(a->chain_id, b->chain_id, 32) != 0) {
        TEST_FAIL(test_name, "header mismatch");
    }
}

/* ── encode/decode roundtrip helper ──────────────────────────────── */

/* Provide enough room for max chain_def_blob plus envelope/signature. */
#define ENC_BUF_SIZE (NODUS_W_MAX_CHAIN_DEF_BLOB + 16 * 1024)
static uint8_t enc_buf[ENC_BUF_SIZE];

static int roundtrip(nodus_t3_msg_t *in, nodus_t3_msg_t *out) {
    ensure_identity();
    size_t len = 0;
    if (nodus_t3_encode(in, &test_id.sk, enc_buf, sizeof(enc_buf), &len) != 0)
        return -1;
    if (len == 0) return -1;
    if (nodus_t3_decode(enc_buf, len, out) != 0)
        return -2;
    return 0;
}

/* ── Test: method ↔ type mapping for new bootstrap types ─────────── */

static void test_method_type_mapping(void) {
    const char *name = "method_type_mapping";

    static const struct {
        nodus_t3_msg_type_t type;
        const char         *method;
    } cases[] = {
        { NODUS_T3_CHAIN_Q,     "w_chain_q" },
        { NODUS_T3_CHAIN_R,     "w_chain_r" },
        { NODUS_T3_GENESIS_REQ, "w_genesis_req" },
        { NODUS_T3_GENESIS_RSP, "w_genesis_rsp" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *m = nodus_t3_type_to_method(cases[i].type);
        if (!m || strcmp(m, cases[i].method) != 0) {
            TEST_FAIL(name, "type_to_method mapping wrong for new type");
            return;
        }
        if (nodus_t3_method_to_type(cases[i].method) != cases[i].type) {
            TEST_FAIL(name, "method_to_type mapping wrong for new method");
            return;
        }
    }

    TEST_PASS(name);
}

/* ── Test: w_chain_q encode/decode roundtrip ─────────────────────── */

static void test_w_chain_q_roundtrip(void) {
    const char *name = "w_chain_q_roundtrip";

    nodus_t3_msg_t in = {0};
    in.txn_id = 0x11223344;
    in.type = NODUS_T3_CHAIN_Q;
    fill_header(&in.header);
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        in.w_chain_q.nonce[i] = (uint8_t)(0x40 + i);

    nodus_t3_msg_t out = {0};
    int rc = roundtrip(&in, &out);
    if (rc != 0) {
        TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed");
        return;
    }

    if (out.type != NODUS_T3_CHAIN_Q) {
        TEST_FAIL(name, "decoded type wrong");
        return;
    }
    if (out.txn_id != in.txn_id) {
        TEST_FAIL(name, "txn_id mismatch");
        return;
    }
    check_header(&in.header, &out.header, name);
    if (memcmp(in.w_chain_q.nonce, out.w_chain_q.nonce,
               NODUS_W_BOOTSTRAP_NONCE_LEN) != 0) {
        TEST_FAIL(name, "nonce roundtrip mismatch");
        return;
    }
    TEST_PASS(name);
}

/* ── Test: w_chain_r encode/decode roundtrip + nonce echo ────────── */

static void test_w_chain_r_roundtrip(void) {
    const char *name = "w_chain_r_roundtrip";

    nodus_t3_msg_t in = {0};
    in.txn_id = 0x55667788;
    in.type = NODUS_T3_CHAIN_R;
    fill_header(&in.header);

    memset(in.w_chain_r.cid, 0xAB, 32);
    in.w_chain_r.tip = 9876543210ULL;
    memset(in.w_chain_r.gh, 0x01, NODUS_T3_TX_HASH_LEN);
    memset(in.w_chain_r.cdh, 0x02, NODUS_T3_TX_HASH_LEN);
    /* Nonce echo: same bytes the test expects to see in the response. */
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        in.w_chain_r.nonce[i] = (uint8_t)(0x40 + i);

    nodus_t3_msg_t out = {0};
    int rc = roundtrip(&in, &out);
    if (rc != 0) {
        TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed");
        return;
    }

    if (out.type != NODUS_T3_CHAIN_R) {
        TEST_FAIL(name, "decoded type wrong"); return;
    }
    check_header(&in.header, &out.header, name);
    if (memcmp(in.w_chain_r.cid, out.w_chain_r.cid, 32) != 0) {
        TEST_FAIL(name, "cid roundtrip mismatch"); return;
    }
    if (in.w_chain_r.tip != out.w_chain_r.tip) {
        TEST_FAIL(name, "tip roundtrip mismatch"); return;
    }
    if (memcmp(in.w_chain_r.gh, out.w_chain_r.gh, NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "gh roundtrip mismatch"); return;
    }
    if (memcmp(in.w_chain_r.cdh, out.w_chain_r.cdh, NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "cdh roundtrip mismatch"); return;
    }
    if (memcmp(in.w_chain_r.nonce, out.w_chain_r.nonce,
               NODUS_W_BOOTSTRAP_NONCE_LEN) != 0) {
        TEST_FAIL(name, "nonce echo roundtrip mismatch"); return;
    }
    TEST_PASS(name);
}

/* ── Test: nonce echo invariant across paired q/r round ──────────── */

static void test_nonce_echo_invariant(void) {
    const char *name = "nonce_echo_invariant";

    /* Simulate fresh node: random 16B nonce in q, peer echoes back in r. */
    nodus_t3_msg_t q = {0};
    q.type = NODUS_T3_CHAIN_Q;
    fill_header(&q.header);
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        q.w_chain_q.nonce[i] = (uint8_t)((i * 7 + 11) & 0xFF);

    nodus_t3_msg_t r = {0};
    r.type = NODUS_T3_CHAIN_R;
    fill_header(&r.header);
    memset(r.w_chain_r.cid, 0xCD, 32);
    r.w_chain_r.tip = 100;
    memset(r.w_chain_r.gh, 0x10, NODUS_T3_TX_HASH_LEN);
    memset(r.w_chain_r.cdh, 0x20, NODUS_T3_TX_HASH_LEN);
    /* The peer is expected to echo the q nonce verbatim. */
    memcpy(r.w_chain_r.nonce, q.w_chain_q.nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);

    nodus_t3_msg_t r_out = {0};
    int rc = roundtrip(&r, &r_out);
    if (rc != 0) {
        TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed");
        return;
    }
    if (memcmp(q.w_chain_q.nonce, r_out.w_chain_r.nonce,
               NODUS_W_BOOTSTRAP_NONCE_LEN) != 0) {
        TEST_FAIL(name, "echoed nonce did not survive wire roundtrip");
        return;
    }
    TEST_PASS(name);
}

/* ── Test: w_genesis_req encode/decode roundtrip ─────────────────── */

static void test_w_genesis_req_roundtrip(void) {
    const char *name = "w_genesis_req_roundtrip";

    nodus_t3_msg_t in = {0};
    in.type = NODUS_T3_GENESIS_REQ;
    fill_header(&in.header);
    memset(in.w_genesis_req.cid, 0x55, 32);

    nodus_t3_msg_t out = {0};
    int rc = roundtrip(&in, &out);
    if (rc != 0) {
        TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed");
        return;
    }
    if (out.type != NODUS_T3_GENESIS_REQ) {
        TEST_FAIL(name, "decoded type wrong"); return;
    }
    if (memcmp(in.w_genesis_req.cid, out.w_genesis_req.cid, 32) != 0) {
        TEST_FAIL(name, "cid roundtrip mismatch"); return;
    }
    check_header(&in.header, &out.header, name);
    TEST_PASS(name);
}

/* ── Test: w_genesis_rsp roundtrip with realistic cdb size ───────── */

static void test_w_genesis_rsp_roundtrip(void) {
    const char *name = "w_genesis_rsp_roundtrip";

    /* Realistic chain_def_blob size: 8 KB pseudo-random bytes. */
    static uint8_t cdb[8192];
    for (size_t i = 0; i < sizeof(cdb); i++)
        cdb[i] = (uint8_t)((i * 31 + 7) & 0xFF);

    nodus_t3_msg_t in = {0};
    in.type = NODUS_T3_GENESIS_RSP;
    fill_header(&in.header);

    memset(in.w_genesis_rsp.cid, 0x77, 32);
    in.w_genesis_rsp.cdb = cdb;
    in.w_genesis_rsp.cdb_len = (uint32_t)sizeof(cdb);
    memset(in.w_genesis_rsp.gth, 0x88, NODUS_T3_TX_HASH_LEN);
    in.w_genesis_rsp.gts = 1700000000ULL;
    memset(in.w_genesis_rsp.gpid, 0x99, NODUS_T3_WITNESS_ID_LEN);

    nodus_t3_msg_t out = {0};
    int rc = roundtrip(&in, &out);
    if (rc != 0) {
        TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed");
        return;
    }
    if (out.type != NODUS_T3_GENESIS_RSP) {
        TEST_FAIL(name, "decoded type wrong"); return;
    }
    check_header(&in.header, &out.header, name);
    if (memcmp(in.w_genesis_rsp.cid, out.w_genesis_rsp.cid, 32) != 0) {
        TEST_FAIL(name, "cid mismatch"); return;
    }
    if (out.w_genesis_rsp.cdb_len != in.w_genesis_rsp.cdb_len) {
        TEST_FAIL(name, "cdb_len mismatch"); return;
    }
    if (memcmp(out.w_genesis_rsp.cdb, cdb, sizeof(cdb)) != 0) {
        TEST_FAIL(name, "cdb bytes mismatch"); return;
    }
    if (memcmp(in.w_genesis_rsp.gth, out.w_genesis_rsp.gth,
               NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "gth mismatch"); return;
    }
    if (in.w_genesis_rsp.gts != out.w_genesis_rsp.gts) {
        TEST_FAIL(name, "gts mismatch"); return;
    }
    if (memcmp(in.w_genesis_rsp.gpid, out.w_genesis_rsp.gpid,
               NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "gpid mismatch"); return;
    }
    TEST_PASS(name);
}

/* ── Test: cdb at exactly NODUS_W_MAX_CHAIN_DEF_BLOB is accepted ─── */

static void test_w_genesis_rsp_cap_at_limit(void) {
    const char *name = "w_genesis_rsp_cap_at_limit";

    static uint8_t cdb[NODUS_W_MAX_CHAIN_DEF_BLOB];
    for (size_t i = 0; i < sizeof(cdb); i++)
        cdb[i] = (uint8_t)(i & 0xFF);

    nodus_t3_msg_t in = {0};
    in.type = NODUS_T3_GENESIS_RSP;
    fill_header(&in.header);
    memset(in.w_genesis_rsp.cid, 0x55, 32);
    in.w_genesis_rsp.cdb = cdb;
    in.w_genesis_rsp.cdb_len = (uint32_t)sizeof(cdb);
    memset(in.w_genesis_rsp.gth, 0x66, NODUS_T3_TX_HASH_LEN);
    in.w_genesis_rsp.gts = 1709300000ULL;
    memset(in.w_genesis_rsp.gpid, 0x77, NODUS_T3_WITNESS_ID_LEN);

    nodus_t3_msg_t out = {0};
    int rc = roundtrip(&in, &out);
    if (rc != 0) {
        TEST_FAIL(name, "exact-limit cdb (64 KB) should be accepted");
        return;
    }
    if (out.w_genesis_rsp.cdb_len != sizeof(cdb)) {
        TEST_FAIL(name, "exact-limit cdb_len mismatch on decode");
        return;
    }
    if (memcmp(out.w_genesis_rsp.cdb, cdb, sizeof(cdb)) != 0) {
        TEST_FAIL(name, "exact-limit cdb bytes mismatch");
        return;
    }
    TEST_PASS(name);
}

/* ── Test: cdb above NODUS_W_MAX_CHAIN_DEF_BLOB rejected at decode ─ */

static void test_w_genesis_rsp_cap_over_limit(void) {
    const char *name = "w_genesis_rsp_cap_over_limit";

    /* Allocate one byte above the cap. The encoder side, in the GREEN
     * implementation, will refuse to emit oversize cdb. The decoder
     * MUST also reject so a malicious encoder elsewhere on the network
     * cannot bypass the cap. We assert both paths reject. */
    static uint8_t cdb[NODUS_W_MAX_CHAIN_DEF_BLOB + 1];
    for (size_t i = 0; i < sizeof(cdb); i++)
        cdb[i] = (uint8_t)((i * 13 + 1) & 0xFF);

    nodus_t3_msg_t in = {0};
    in.type = NODUS_T3_GENESIS_RSP;
    fill_header(&in.header);
    memset(in.w_genesis_rsp.cid, 0x44, 32);
    in.w_genesis_rsp.cdb = cdb;
    in.w_genesis_rsp.cdb_len = (uint32_t)sizeof(cdb);
    memset(in.w_genesis_rsp.gth, 0x55, NODUS_T3_TX_HASH_LEN);
    in.w_genesis_rsp.gts = 1709300000ULL;
    memset(in.w_genesis_rsp.gpid, 0x66, NODUS_T3_WITNESS_ID_LEN);

    ensure_identity();
    size_t len = 0;
    int enc_rc = nodus_t3_encode(&in, &test_id.sk, enc_buf, sizeof(enc_buf), &len);
    if (enc_rc == 0) {
        TEST_FAIL(name, "encoder accepted cdb above 64 KB cap");
        return;
    }
    /* Encoder rejected — that's the correct behavior for senders. The
     * decoder-side adversarial path (custom encoder bypasses our cap on
     * the wire) is exercised separately by
     * test_w_genesis_rsp_decoder_strict_cap below. */
    TEST_PASS(name);
}

/* ── Test: A4 — decoder strict cap defends against custom encoders ── */

/* Build a minimal valid T3 envelope with arg "a" carrying a w_genesis_rsp
 * map whose "cdb" bstr is len bytes long. We bypass nodus_t3_encode (and
 * its enc_args cap) by calling cbor_encode_* primitives directly. wsig
 * is filled with zeros — nodus_t3_decode does NOT verify the signature,
 * it only parses, so the strict cap rejection happens at parse time. */
static int build_genesis_rsp_wire_with_cdb_len(uint8_t *out, size_t out_cap,
                                                 const uint8_t *cdb, size_t cdb_len,
                                                 size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, out, out_cap);

    /* Outer map: 6 keys (t, y, q, wh, a, wsig). */
    cbor_encode_map(&enc, 6);

    cbor_encode_cstr(&enc, "t");
    cbor_encode_uint(&enc, 0xDEADBEEF);

    cbor_encode_cstr(&enc, "y");
    cbor_encode_cstr(&enc, "q");

    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "w_genesis_rsp");

    /* Header — minimal valid wh map (7 keys to match decoder expectation). */
    cbor_encode_cstr(&enc, "wh");
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "v");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "rnd"); cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "vw");  cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "sid");
    static const uint8_t fake_sid[NODUS_T3_WITNESS_ID_LEN] = {0};
    cbor_encode_bstr(&enc, fake_sid, NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(&enc, "ts");  cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "nc");  cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "cid");
    static const uint8_t fake_cid[32] = {0};
    cbor_encode_bstr(&enc, fake_cid, 32);

    /* Args map — w_genesis_rsp with oversized cdb. */
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "cid");
    cbor_encode_bstr(&enc, fake_cid, 32);
    cbor_encode_cstr(&enc, "cdb");
    cbor_encode_bstr(&enc, cdb, cdb_len);  /* THE OVERSIZE PAYLOAD */
    cbor_encode_cstr(&enc, "gth");
    static const uint8_t fake_hash[NODUS_T3_TX_HASH_LEN] = {0};
    cbor_encode_bstr(&enc, fake_hash, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(&enc, "gts");
    cbor_encode_uint(&enc, 1709300000ULL);
    cbor_encode_cstr(&enc, "gpid");
    cbor_encode_bstr(&enc, fake_sid, NODUS_T3_WITNESS_ID_LEN);

    /* wsig — zeros. Decode does not verify; parse only. */
    cbor_encode_cstr(&enc, "wsig");
    static const uint8_t fake_wsig[NODUS_SIG_BYTES] = {0};
    cbor_encode_bstr(&enc, fake_wsig, NODUS_SIG_BYTES);

    if (enc.error) return -1;
    *out_len = cbor_encoder_len(&enc);
    return *out_len > 0 ? 0 : -1;
}

static void test_w_genesis_rsp_decoder_strict_cap(void) {
    const char *name = "w_genesis_rsp_decoder_strict_cap";

    /* Adversarial cdb: one byte above the cap. */
    static uint8_t big_cdb[NODUS_W_MAX_CHAIN_DEF_BLOB + 1];
    for (size_t i = 0; i < sizeof(big_cdb); i++)
        big_cdb[i] = (uint8_t)((i * 17 + 3) & 0xFF);

    size_t wire_len = 0;
    int build_rc = build_genesis_rsp_wire_with_cdb_len(
        enc_buf, sizeof(enc_buf), big_cdb, sizeof(big_cdb), &wire_len);
    if (build_rc != 0) {
        TEST_FAIL(name, "test wire builder failed (output buffer too small?)");
        return;
    }

    /* Decode MUST reject the oversize cdb before any further processing. */
    nodus_t3_msg_t out = {0};
    int dec_rc = nodus_t3_decode(enc_buf, wire_len, &out);
    if (dec_rc == 0) {
        TEST_FAIL(name, "decoder accepted cdb above 64 KB cap");
        return;
    }
    TEST_PASS(name);

    /* Sanity: same builder with cdb at exactly the cap MUST decode. */
    static uint8_t cap_cdb[NODUS_W_MAX_CHAIN_DEF_BLOB];
    for (size_t i = 0; i < sizeof(cap_cdb); i++)
        cap_cdb[i] = (uint8_t)(i & 0xFF);

    build_rc = build_genesis_rsp_wire_with_cdb_len(
        enc_buf, sizeof(enc_buf), cap_cdb, sizeof(cap_cdb), &wire_len);
    if (build_rc != 0) {
        TEST_FAIL(name, "exact-cap wire build failed");
        return;
    }
    nodus_t3_msg_t out2 = {0};
    dec_rc = nodus_t3_decode(enc_buf, wire_len, &out2);
    if (dec_rc != 0) {
        TEST_FAIL(name, "decoder rejected cdb at exact 64 KB cap");
        return;
    }
    if (out2.w_genesis_rsp.cdb_len != sizeof(cap_cdb)) {
        TEST_FAIL(name, "exact-cap decode lost cdb_len");
        return;
    }
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void) {
    fprintf(stderr, "test_t3_bootstrap_wire: PR 3 Yol B wire format\n");

    test_method_type_mapping();
    test_w_chain_q_roundtrip();
    test_w_chain_r_roundtrip();
    test_nonce_echo_invariant();
    test_w_genesis_req_roundtrip();
    test_w_genesis_rsp_roundtrip();
    test_w_genesis_rsp_cap_at_limit();
    test_w_genesis_rsp_cap_over_limit();
    test_w_genesis_rsp_decoder_strict_cap();

    if (failures > 0) {
        fprintf(stderr, "test_t3_bootstrap_wire: %d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_t3_bootstrap_wire: ALL PASS\n");
    return 0;
}
