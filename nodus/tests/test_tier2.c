/**
 * Nodus — Tier 2 Protocol Tests
 *
 * Tests encode/decode roundtrips for Client-Nodus messages.
 */

#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/enc/qgp_mlkem.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Large buffer for protocol messages (pubkeys are 2592 bytes) */
static uint8_t msgbuf[32768];

static nodus_identity_t test_id;

static void init_test_identity(void) {
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

static void test_hello_roundtrip(void) {
    TEST("hello encode/decode");
    size_t len = 0;
    int rc = nodus_t2_hello(1, &test_id.pk, &test_id.node_id,
                             msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 1 && msg.type == 'q' &&
        strcmp(msg.method, "hello") == 0 &&
        memcmp(msg.pk.bytes, test_id.pk.bytes, NODUS_PK_BYTES) == 0 &&
        nodus_key_cmp(&msg.fp, &test_id.node_id) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_challenge_roundtrip(void) {
    TEST("challenge encode/decode");
    uint8_t nonce[NODUS_NONCE_LEN];
    memset(nonce, 0xAA, sizeof(nonce));

    size_t len = 0;
    nodus_t2_challenge(1, nonce, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 1 && msg.type == 'r' &&
        strcmp(msg.method, "challenge") == 0 &&
        memcmp(msg.nonce, nonce, NODUS_NONCE_LEN) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_auth_roundtrip(void) {
    TEST("auth encode/decode");
    /* Sign a nonce (C2: domain-tagged AUTH_CHALLENGE) */
    uint8_t nonce[NODUS_NONCE_LEN];
    memset(nonce, 0xBB, sizeof(nonce));
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, nonce, &test_id.sk);

    size_t len = 0;
    nodus_t2_auth(2, &sig, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 2 && strcmp(msg.method, "auth") == 0 &&
        memcmp(msg.sig.bytes, sig.bytes, NODUS_SIG_BYTES) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_auth_ok_roundtrip(void) {
    TEST("auth_ok encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xCC, sizeof(token));

    size_t len = 0;
    nodus_t2_auth_ok(2, token, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 2 && strcmp(msg.method, "auth_ok") == 0 &&
        msg.has_token &&
        memcmp(msg.token, token, NODUS_SESSION_TOKEN_LEN) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

/* ── Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
 * migration.md) — N3/N6: optional mpk/mpk_sig/alg fields, and the
 * byte-identity requirement for legacy (no-mlkem) senders. The hand-built
 * reference maps below use the raw public CBOR encoder (nodus_cbor.h)
 * directly, reproducing exactly what nodus_t2_auth_ok_kyber()/
 * nodus_t2_key_init() emitted BEFORE this migration (mirrored from their
 * current source — enc_response_header/enc_query_header are file-static,
 * not exported, so this is the only way to pin the pre-migration shape). */

static void test_auth_ok_kyber_legacy_byte_identical(void) {
    TEST("auth_ok_kyber: no mlkem -> byte-identical to pre-Faz-1 4-key map");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x33, sizeof(token));
    uint8_t kyber_pk[NODUS_KYBER_PK_BYTES];
    memset(kyber_pk, 0x44, sizeof(kyber_pk));
    nodus_sig_t kpk_sig;
    memset(&kpk_sig, 0x55, sizeof(kpk_sig));

    size_t len = 0;
    int rc = nodus_t2_auth_ok_kyber(9, token, kyber_pk, &test_id.pk, &kpk_sig,
                                     NULL, NULL, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    static uint8_t refbuf[16384];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, refbuf, sizeof(refbuf));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t");  cbor_encode_uint(&enc, 9);
    cbor_encode_cstr(&enc, "y");  cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, "auth_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "tok");
    cbor_encode_bstr(&enc, token, NODUS_SESSION_TOKEN_LEN);
    cbor_encode_cstr(&enc, "kpk");
    cbor_encode_bstr(&enc, kyber_pk, NODUS_KYBER_PK_BYTES);
    cbor_encode_cstr(&enc, "spk");
    cbor_encode_bstr(&enc, test_id.pk.bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "kpk_sig");
    cbor_encode_bstr(&enc, kpk_sig.bytes, NODUS_SIG_BYTES);
    size_t reflen = cbor_encoder_len(&enc);

    if (reflen == len && memcmp(refbuf, msgbuf, len) == 0) {
        PASS();
    } else {
        FAIL("legacy auth_ok_kyber encoding changed shape/bytes");
    }
}

static void test_auth_ok_kyber_mlkem_roundtrip(void) {
    TEST("auth_ok_kyber: mpk/mpk_sig present -> decode roundtrip");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x33, sizeof(token));
    uint8_t kyber_pk[NODUS_KYBER_PK_BYTES];
    memset(kyber_pk, 0x44, sizeof(kyber_pk));
    nodus_sig_t kpk_sig;
    memset(&kpk_sig, 0x55, sizeof(kpk_sig));
    uint8_t mlkem_pk[NODUS_MLKEM_PK_BYTES];
    memset(mlkem_pk, 0x66, sizeof(mlkem_pk));
    nodus_sig_t mpk_sig;
    memset(&mpk_sig, 0x77, sizeof(mpk_sig));

    size_t len = 0;
    int rc = nodus_t2_auth_ok_kyber(9, token, kyber_pk, &test_id.pk, &kpk_sig,
                                     mlkem_pk, &mpk_sig,
                                     msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 &&
        msg.has_kyber_pk && memcmp(msg.kyber_pk, kyber_pk, NODUS_KYBER_PK_BYTES) == 0 &&
        msg.has_kpk_sig && memcmp(msg.kpk_sig.bytes, kpk_sig.bytes, NODUS_SIG_BYTES) == 0 &&
        msg.has_mlkem_pk && memcmp(msg.mlkem_pk, mlkem_pk, NODUS_MLKEM_PK_BYTES) == 0 &&
        msg.has_mpk_sig && memcmp(msg.mpk_sig.bytes, mpk_sig.bytes, NODUS_SIG_BYTES) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_key_init_legacy_byte_identical(void) {
    TEST("key_init: alg=0 -> byte-identical to pre-Faz-1 2-key map");

    uint8_t ct[NODUS_KYBER_CT_BYTES];
    memset(ct, 0x88, sizeof(ct));
    uint8_t nc[NODUS_NONCE_LEN];
    memset(nc, 0x99, sizeof(nc));

    size_t len = 0;
    int rc = nodus_t2_key_init(11, ct, nc, 0, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    static uint8_t refbuf[8192];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, refbuf, sizeof(refbuf));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t");  cbor_encode_uint(&enc, 11);
    cbor_encode_cstr(&enc, "y");  cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, "key_init");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ct");
    cbor_encode_bstr(&enc, ct, NODUS_KYBER_CT_BYTES);
    cbor_encode_cstr(&enc, "nc");
    cbor_encode_bstr(&enc, nc, NODUS_NONCE_LEN);
    size_t reflen = cbor_encoder_len(&enc);

    if (reflen == len && memcmp(refbuf, msgbuf, len) == 0) {
        PASS();
    } else {
        FAIL("legacy key_init encoding changed shape/bytes");
    }
}

static void test_key_init_mlkem_roundtrip(void) {
    TEST("key_init: alg=1 -> key_alg decodes as 1");

    uint8_t ct[NODUS_MLKEM_CT_BYTES];
    memset(ct, 0xAA, sizeof(ct));
    uint8_t nc[NODUS_NONCE_LEN];
    memset(nc, 0xBB, sizeof(nc));

    size_t len = 0;
    int rc = nodus_t2_key_init(12, ct, nc, 1, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.has_kyber_ct && msg.key_alg == 1 &&
        memcmp(msg.kyber_ct, ct, NODUS_MLKEM_CT_BYTES) == 0 &&
        msg.has_key_nonce && memcmp(msg.key_nonce, nc, NODUS_NONCE_LEN) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

/* D6 (N1 delta 1): the decoder must not truncate an out-of-range "alg"
 * value into an accidental 1 — (uint8_t)257 == 1, which the FIRST version
 * of this handler would have accepted as ML-KEM. Hand-built via the raw
 * CBOR encoder because nodus_t2_key_init()'s public API takes alg as a
 * uint8_t and only ever emits the literal value 1, so it cannot produce
 * these wire bytes itself. */
static void test_key_init_alg_out_of_range_decodes_as_zero(void) {
    TEST("key_init: alg=257 and alg=2 both decode as key_alg=0");

    uint8_t ct[NODUS_KYBER_CT_BYTES];
    memset(ct, 0xBC, sizeof(ct));
    uint8_t nc[NODUS_NONCE_LEN];
    memset(nc, 0xCD, sizeof(nc));

    uint64_t bad_values[] = { 257, 2 };
    bool all_ok = true;
    for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, msgbuf, sizeof(msgbuf));
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "t");  cbor_encode_uint(&enc, 90);
        cbor_encode_cstr(&enc, "y");  cbor_encode_cstr(&enc, "q");
        cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, "key_init");
        cbor_encode_cstr(&enc, "a");
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "ct"); cbor_encode_bstr(&enc, ct, NODUS_KYBER_CT_BYTES);
        cbor_encode_cstr(&enc, "nc"); cbor_encode_bstr(&enc, nc, NODUS_NONCE_LEN);
        cbor_encode_cstr(&enc, "alg"); cbor_encode_uint(&enc, bad_values[i]);
        size_t len = cbor_encoder_len(&enc);

        nodus_tier2_msg_t msg;
        int rc = nodus_t2_decode(msgbuf, len, &msg);
        if (rc != 0 || msg.key_alg != 0)
            all_ok = false;
        nodus_t2_msg_free(&msg);
    }

    if (all_ok) PASS(); else FAIL("out-of-range alg value not clamped to 0");
}

static void test_circ_open_e2e_legacy_default_alg(void) {
    TEST("circ_open_e2e: alg=0 -> e2e_alg decodes as 0 (default)");

    nodus_key_t peer_fp;
    memset(peer_fp.bytes, 0xCC, NODUS_KEY_BYTES);
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xDD, sizeof(token));
    uint8_t ect[NODUS_KYBER_CT_BYTES];
    memset(ect, 0xEE, sizeof(ect));

    size_t len = 0;
    int rc = nodus_t2_circ_open_e2e(13, token, 7, &peer_fp, ect, 0,
                                     msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.has_e2e_ct && msg.e2e_alg == 0 &&
        memcmp(msg.e2e_ct, ect, NODUS_KYBER_CT_BYTES) == 0 &&
        msg.circ_cid == 7 && nodus_key_cmp(&msg.circ_peer_fp, &peer_fp) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_circ_open_e2e_mlkem_roundtrip(void) {
    TEST("circ_open_e2e: alg=1 -> e2e_alg decodes as 1");

    nodus_key_t peer_fp;
    memset(peer_fp.bytes, 0x11, NODUS_KEY_BYTES);
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x22, sizeof(token));
    uint8_t ect[NODUS_MLKEM_CT_BYTES];
    memset(ect, 0x33, sizeof(ect));

    size_t len = 0;
    int rc = nodus_t2_circ_open_e2e(14, token, 8, &peer_fp, ect, 1,
                                     msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.has_e2e_ct && msg.e2e_alg == 1 &&
        memcmp(msg.e2e_ct, ect, NODUS_MLKEM_CT_BYTES) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_ri_open_e2e_mlkem_roundtrip(void) {
    TEST("ri_open_e2e: alg=1 -> e2e_alg decodes as 1");

    nodus_key_t src_fp, dst_fp;
    memset(src_fp.bytes, 0x44, NODUS_KEY_BYTES);
    memset(dst_fp.bytes, 0x55, NODUS_KEY_BYTES);
    uint8_t ect[NODUS_MLKEM_CT_BYTES];
    memset(ect, 0x66, sizeof(ect));

    size_t len = 0;
    int rc = nodus_t2_ri_open_e2e(15, 9, &src_fp, &dst_fp, ect, 1,
                                   msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.has_e2e_ct && msg.e2e_alg == 1 &&
        memcmp(msg.e2e_ct, ect, NODUS_MLKEM_CT_BYTES) == 0 &&
        msg.ri_ups_cid == 9 &&
        nodus_key_cmp(&msg.ri_src_fp, &src_fp) == 0 &&
        nodus_key_cmp(&msg.ri_dst_fp, &dst_fp) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_circ_inbound_e2e_mlkem_roundtrip(void) {
    TEST("circ_inbound_e2e: alg=1 -> e2e_alg decodes as 1");

    nodus_key_t peer_fp;
    memset(peer_fp.bytes, 0x77, NODUS_KEY_BYTES);
    uint8_t ect[NODUS_MLKEM_CT_BYTES];
    memset(ect, 0x88, sizeof(ect));

    size_t len = 0;
    int rc = nodus_t2_circ_inbound_e2e(16, 10, &peer_fp, ect, 1,
                                        msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.has_e2e_ct && msg.e2e_alg == 1 &&
        memcmp(msg.e2e_ct, ect, NODUS_MLKEM_CT_BYTES) == 0 &&
        msg.circ_cid == 10 && nodus_key_cmp(&msg.circ_peer_fp, &peer_fp) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_put_roundtrip(void) {
    TEST("put encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xDD, sizeof(token));

    nodus_key_t key;
    nodus_hash((const uint8_t *)"test:key", 8, &key);

    const uint8_t data[] = "test payload data";
    nodus_sig_t sig;
    memset(&sig, 0xEE, sizeof(sig));

    size_t len = 0;
    int rc = nodus_t2_put(10, token, &key, data, sizeof(data) - 1,
                           NODUS_VALUE_EPHEMERAL, 3600, 1, 5, &sig,
                           msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 10 && strcmp(msg.method, "put") == 0 &&
        msg.has_token &&
        nodus_key_cmp(&msg.key, &key) == 0 &&
        msg.data_len == sizeof(data) - 1 &&
        memcmp(msg.data, data, msg.data_len) == 0 &&
        msg.val_type == NODUS_VALUE_EPHEMERAL &&
        msg.ttl == 3600 && msg.vid == 1 && msg.seq == 5) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_get_roundtrip(void) {
    TEST("get encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x11, sizeof(token));

    nodus_key_t key;
    memset(key.bytes, 0x55, NODUS_KEY_BYTES);

    size_t len = 0;
    nodus_t2_get(20, token, &key, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 20 && strcmp(msg.method, "get") == 0 &&
        nodus_key_cmp(&msg.key, &key) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_listen_roundtrip(void) {
    TEST("listen encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x22, sizeof(token));

    nodus_key_t key;
    memset(key.bytes, 0x66, NODUS_KEY_BYTES);

    size_t len = 0;
    nodus_t2_listen(30, token, &key, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 30 && strcmp(msg.method, "listen") == 0 &&
        nodus_key_cmp(&msg.key, &key) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_error_roundtrip(void) {
    TEST("error encode/decode");
    size_t len = 0;
    nodus_t2_error(40, NODUS_ERR_NOT_FOUND, "key not found",
                    msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 40 && msg.type == 'e' &&
        msg.error_code == NODUS_ERR_NOT_FOUND &&
        strcmp(msg.error_msg, "key not found") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_result_with_value(void) {
    TEST("result with value encode/decode");

    nodus_key_t key;
    nodus_hash((const uint8_t *)"test:result", 11, &key);

    nodus_value_t *val = NULL;
    nodus_value_create(&key, (const uint8_t *)"result data", 11,
                        NODUS_VALUE_PERMANENT, 0, 1, 3, &test_id.pk, &val);
    nodus_value_sign(val, &test_id.sk);

    size_t len = 0;
    int rc = nodus_t2_result(50, val, msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); nodus_value_free(val); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 50 && msg.value != NULL &&
        msg.value->data_len == 11 &&
        memcmp(msg.value->data, "result data", 11) == 0 &&
        msg.value->seq == 3) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }

    nodus_value_free(val);
    nodus_t2_msg_free(&msg);
}

static void test_get_batch_roundtrip(void) {
    TEST("get_batch request encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xCC, sizeof(token));

    nodus_key_t keys[3];
    nodus_hash((const uint8_t *)"key:0", 5, &keys[0]);
    nodus_hash((const uint8_t *)"key:1", 5, &keys[1]);
    nodus_hash((const uint8_t *)"key:2", 5, &keys[2]);

    size_t len = 0;
    int rc = nodus_t2_get_batch(70, token, keys, 3,
                                 msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 70 && msg.type == 'q' &&
        strcmp(msg.method, "get_batch") == 0 &&
        msg.batch_key_count == 3 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[2], &keys[2]) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_get_batch_result_roundtrip(void) {
    TEST("get_batch result encode/decode");

    nodus_key_t keys[2];
    nodus_hash((const uint8_t *)"bk:0", 4, &keys[0]);
    nodus_hash((const uint8_t *)"bk:1", 4, &keys[1]);

    /* Create test values for key 0 (2 values) and key 1 (1 value) */
    nodus_value_t *v0a = NULL, *v0b = NULL, *v1a = NULL;
    nodus_value_create(&keys[0], (const uint8_t *)"val0a", 5,
                        NODUS_VALUE_PERMANENT, 0, 1, 1, &test_id.pk, &v0a);
    nodus_value_sign(v0a, &test_id.sk);
    nodus_value_create(&keys[0], (const uint8_t *)"val0b", 5,
                        NODUS_VALUE_PERMANENT, 0, 2, 1, &test_id.pk, &v0b);
    nodus_value_sign(v0b, &test_id.sk);
    nodus_value_create(&keys[1], (const uint8_t *)"val1a", 5,
                        NODUS_VALUE_PERMANENT, 0, 3, 1, &test_id.pk, &v1a);
    nodus_value_sign(v1a, &test_id.sk);

    nodus_value_t *k0_vals[] = {v0a, v0b};
    nodus_value_t *k1_vals[] = {v1a};
    nodus_value_t **vals_per_key[] = {k0_vals, k1_vals};
    size_t counts[] = {2, 1};

    size_t len = 0;
    int rc = nodus_t2_result_get_batch(71, keys, 2, vals_per_key, counts,
                                        msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) {
        FAIL("encode");
        nodus_value_free(v0a); nodus_value_free(v0b); nodus_value_free(v1a);
        return;
    }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.batch_key_count == 2 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0 &&
        msg.batch_val_counts[0] == 2 &&
        msg.batch_val_counts[1] == 1 &&
        msg.batch_vals[0][0]->data_len == 5 &&
        memcmp(msg.batch_vals[0][0]->data, "val0a", 5) == 0 &&
        msg.batch_vals[1][0]->data_len == 5 &&
        memcmp(msg.batch_vals[1][0]->data, "val1a", 5) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }

    nodus_value_free(v0a); nodus_value_free(v0b); nodus_value_free(v1a);
    nodus_t2_msg_free(&msg);
}

static void test_count_batch_roundtrip(void) {
    TEST("count_batch request encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xDD, sizeof(token));

    nodus_key_t keys[2];
    nodus_hash((const uint8_t *)"cnt:0", 5, &keys[0]);
    nodus_hash((const uint8_t *)"cnt:1", 5, &keys[1]);

    nodus_key_t caller_fp;
    nodus_hash((const uint8_t *)"caller", 6, &caller_fp);

    size_t len = 0;
    int rc = nodus_t2_count_batch(80, token, keys, 2, &caller_fp,
                                   msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 80 && msg.type == 'q' &&
        strcmp(msg.method, "cnt_batch") == 0 &&
        msg.batch_key_count == 2 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[1], &keys[1]) == 0 &&
        nodus_key_cmp(&msg.fp, &caller_fp) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_count_batch_result_roundtrip(void) {
    TEST("count_batch result encode/decode");

    nodus_key_t keys[3];
    nodus_hash((const uint8_t *)"cr:0", 4, &keys[0]);
    nodus_hash((const uint8_t *)"cr:1", 4, &keys[1]);
    nodus_hash((const uint8_t *)"cr:2", 4, &keys[2]);

    size_t counts[] = {42, 0, 7};
    bool has_mine[] = {true, false, true};

    size_t len = 0;
    int rc = nodus_t2_result_count_batch(81, keys, 3, counts, has_mine,
                                          msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.batch_key_count == 3 &&
        nodus_key_cmp(&msg.batch_keys[0], &keys[0]) == 0 &&
        nodus_key_cmp(&msg.batch_keys[2], &keys[2]) == 0 &&
        msg.batch_counts[0] == 42 &&
        msg.batch_counts[1] == 0 &&
        msg.batch_counts[2] == 7 &&
        msg.batch_has_mine[0] == true &&
        msg.batch_has_mine[1] == false &&
        msg.batch_has_mine[2] == true) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

static void test_pong_roundtrip(void) {
    TEST("pong encode/decode");
    size_t len = 0;
    nodus_t2_pong(60, msgbuf, sizeof(msgbuf), &len);

    nodus_tier2_msg_t msg;
    nodus_t2_decode(msgbuf, len, &msg);
    if (msg.txn_id == 60 && msg.type == 'r' &&
        strcmp(msg.method, "pong") == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

int main(void) {
    printf("=== Nodus Tier 2 Protocol Tests ===\n");
    init_test_identity();

    test_hello_roundtrip();
    test_challenge_roundtrip();
    test_auth_roundtrip();
    test_auth_ok_roundtrip();
    test_auth_ok_kyber_legacy_byte_identical();
    test_auth_ok_kyber_mlkem_roundtrip();
    test_key_init_legacy_byte_identical();
    test_key_init_mlkem_roundtrip();
    test_key_init_alg_out_of_range_decodes_as_zero();
    test_circ_open_e2e_legacy_default_alg();
    test_circ_open_e2e_mlkem_roundtrip();
    test_ri_open_e2e_mlkem_roundtrip();
    test_circ_inbound_e2e_mlkem_roundtrip();
    test_put_roundtrip();
    test_get_roundtrip();
    test_listen_roundtrip();
    test_error_roundtrip();
    test_result_with_value();
    test_get_batch_roundtrip();
    test_get_batch_result_roundtrip();
    test_count_batch_roundtrip();
    test_count_batch_result_roundtrip();
    test_pong_roundtrip();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    nodus_identity_clear(&test_id);
    return failed > 0 ? 1 : 0;
}
