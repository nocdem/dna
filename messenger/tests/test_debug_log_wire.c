#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/api/engine/dna_debug_log_wire.h"
#include "crypto/enc/qgp_kyber.h"

static void test_encode_decode_inner_roundtrip(void) {
    const char *hint = "alice-android-rc158";
    const uint8_t body[] = "[INFO] hello world\n[DEBUG] foo=42\n";
    size_t body_len = sizeof(body) - 1;

    uint8_t inner[256];
    size_t inner_len = 0;
    int rc = dna_debug_log_encode_inner(hint, strlen(hint), body, body_len,
                                         inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(inner_len == 6 + strlen(hint) + body_len);

    char hint_out[129] = {0};
    const uint8_t *body_out = NULL;
    size_t body_out_len = 0;
    rc = dna_debug_log_decode_inner(inner, inner_len,
                                     hint_out, sizeof(hint_out),
                                     &body_out, &body_out_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(strcmp(hint_out, hint) == 0);
    assert(body_out_len == body_len);
    assert(memcmp(body_out, body, body_len) == 0);
    printf("  OK: inner roundtrip\n");
}

static void test_encode_inner_oversize_body(void) {
    static uint8_t big[DNA_DEBUG_LOG_MAX_BODY_LEN + 1];
    uint8_t inner[32];
    size_t inner_len = 0;
    int rc = dna_debug_log_encode_inner("x", 1, big, sizeof(big),
                                         inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_ERR_OVERSIZE);
    printf("  OK: oversize body rejected\n");
}

static void test_encode_inner_oversize_hint(void) {
    char big_hint[DNA_DEBUG_LOG_MAX_HINT_LEN + 2];
    memset(big_hint, 'a', sizeof(big_hint) - 1);
    big_hint[sizeof(big_hint) - 1] = 0;
    uint8_t body[] = "x";
    uint8_t inner[256];
    size_t inner_len = 0;
    int rc = dna_debug_log_encode_inner(big_hint, sizeof(big_hint) - 1,
                                         body, 1, inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_ERR_HINT_INVALID);
    printf("  OK: oversize hint rejected\n");
}

static void test_decode_outer_bad_version(void) {
    uint8_t buf[1 + 1568 + 12 + 1 + 16] = {0};
    buf[0] = 0x02;  /* wrong version */
    const uint8_t *ct, *nonce, *enc, *tag;
    size_t enc_len = 0;
    int rc = dna_debug_log_decode_outer(buf, sizeof(buf),
                                         &ct, &nonce, &enc, &enc_len, &tag);
    assert(rc == DNA_DEBUG_LOG_ERR_VERSION);
    printf("  OK: bad version rejected\n");
}

static void test_decode_outer_truncated(void) {
    uint8_t buf[100] = { 0x01 };
    const uint8_t *ct, *nonce, *enc, *tag;
    size_t enc_len = 0;
    int rc = dna_debug_log_decode_outer(buf, sizeof(buf),
                                         &ct, &nonce, &enc, &enc_len, &tag);
    assert(rc == DNA_DEBUG_LOG_ERR_TRUNCATED);
    printf("  OK: truncated outer rejected\n");
}

static void test_encode_decode_outer_roundtrip(void) {
    uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN];
    uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN];
    uint8_t tag[DNA_DEBUG_LOG_GCM_TAG_LEN];
    for (size_t i = 0; i < sizeof(kyber_ct); i++) kyber_ct[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(nonce); i++)    nonce[i]    = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < sizeof(tag); i++)      tag[i]      = (uint8_t)(0x80 + i);
    uint8_t enc_inner[] = { 0xAA, 0xBB, 0xCC, 0xDD };

    uint8_t outer[2048];
    size_t outer_len = 0;
    int rc = dna_debug_log_encode_outer(kyber_ct, nonce, enc_inner, sizeof(enc_inner),
                                         tag, outer, sizeof(outer), &outer_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(outer_len == 1 + 1568 + 12 + sizeof(enc_inner) + 16);
    assert(outer[0] == DNA_DEBUG_LOG_WIRE_VERSION);

    const uint8_t *ct_p, *n_p, *enc_p, *tag_p;
    size_t enc_len_out = 0;
    rc = dna_debug_log_decode_outer(outer, outer_len, &ct_p, &n_p, &enc_p, &enc_len_out, &tag_p);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(memcmp(ct_p, kyber_ct, sizeof(kyber_ct)) == 0);
    assert(memcmp(n_p, nonce, sizeof(nonce)) == 0);
    assert(enc_len_out == sizeof(enc_inner));
    assert(memcmp(enc_p, enc_inner, sizeof(enc_inner)) == 0);
    assert(memcmp(tag_p, tag, sizeof(tag)) == 0);
    printf("  OK: outer roundtrip\n");
}

static void test_encrypt_decrypt_roundtrip(void) {
    uint8_t pub[QGP_KEM1024_PUBLICKEYBYTES], sk[QGP_KEM1024_SECRETKEYBYTES];
    int rc = qgp_kem1024_keypair(pub, sk);
    assert(rc == 0);

    const char *hint = "test-hint";
    const uint8_t body[] = "the quick brown fox";
    uint8_t inner[256];
    size_t inner_len = 0;
    rc = dna_debug_log_encode_inner(hint, strlen(hint), body, sizeof(body) - 1,
                                     inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_OK);

    uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN];
    uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN];
    uint8_t enc[256];
    uint8_t tag[DNA_DEBUG_LOG_GCM_TAG_LEN];
    rc = dna_debug_log_encrypt_inner(pub, inner, inner_len,
                                      kyber_ct, nonce, enc, sizeof(enc), tag);
    assert(rc == DNA_DEBUG_LOG_OK);

    uint8_t decrypted[256];
    size_t decrypted_len = 0;
    rc = dna_debug_log_decrypt_inner(sk, sizeof(sk), kyber_ct, nonce,
                                      enc, inner_len, tag,
                                      decrypted, sizeof(decrypted), &decrypted_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(decrypted_len == inner_len);
    assert(memcmp(decrypted, inner, inner_len) == 0);

    /* Tamper test */
    enc[0] ^= 0x01;
    rc = dna_debug_log_decrypt_inner(sk, sizeof(sk), kyber_ct, nonce,
                                      enc, inner_len, tag,
                                      decrypted, sizeof(decrypted), &decrypted_len);
    assert(rc == DNA_DEBUG_LOG_ERR_GCM_FAIL);
    printf("  OK: encrypt/decrypt roundtrip + tamper\n");
}

int main(void) {
    printf("test_debug_log_wire:\n");
    test_encode_decode_inner_roundtrip();
    test_encode_inner_oversize_body();
    test_encode_inner_oversize_hint();
    test_decode_outer_bad_version();
    test_decode_outer_truncated();
    test_encode_decode_outer_roundtrip();
    test_encrypt_decrypt_roundtrip();
    printf("ALL PASS\n");
    return 0;
}
