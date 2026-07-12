/*
 * test_call_signal.c — PQ VoIP Faz A canonical signal builder (dna_call_build_body).
 *
 * Verifies the fixed-order JSON body per kind (design §4.2): the empty "sig":""
 * slot is present, base64 payloads are encoded correctly, and the built body is
 * a valid input to the signer (build -> sign -> verify round-trip).
 */

#include "dna_call_crypto.h"
#include "crypto/utils/qgp_types.h"   /* qgp_base64_encode */
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

static const char *CALL_ID = "0102030405060708090a0b0c0d0e0f10";  /* 32 hex */
static const char *CALLER_FP =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";  /* 128 hex */

static void test_invite_body(void)
{
    printf("test_invite_body\n");
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(eph_pk, 0x11, sizeof(eph_pk));

    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_INVITE;
    s.call_id_hex = CALL_ID;
    s.seq = 1;
    s.caller_fp_hex = CALLER_FP;
    s.eph_pk = eph_pk;
    s.cap_json = NULL;   /* -> "{}" */

    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
    CHECK(rc == DNA_CALL_OK, "build returns OK");
    CHECK(out_len == strlen(out), "out_len matches strlen");

    /* Fixed prefix + fields. */
    CHECK(strncmp(out, "{\"type\":\"call_signal\",\"v\":1,\"call\":\"", 33) == 0,
          "canonical prefix");
    CHECK(strstr(out, "\"call\":\"0102030405060708090a0b0c0d0e0f10\"") != NULL, "call_id present");
    CHECK(strstr(out, "\"sig\":\"\"") != NULL, "empty sig slot present");
    CHECK(strstr(out, "\"seq\":1") != NULL, "seq present");
    CHECK(strstr(out, "\"kind\":\"INVITE\"") != NULL, "kind INVITE");
    CHECK(strstr(out, "\"caller\":\"0123456789abcdef") != NULL, "caller fp present");
    CHECK(strstr(out, "\"cap\":{}") != NULL, "cap defaults to {}");
    CHECK(out_len > 0 && out[out_len - 1] == '}', "closes with }");

    /* eph_pk base64 must match an independent encode. */
    size_t b64len = 0;
    char *b64 = qgp_base64_encode(eph_pk, sizeof(eph_pk), &b64len);
    CHECK(b64 != NULL && strstr(out, b64) != NULL, "eph_pk base64 matches independent encode");
    free(b64);
}

static void test_ringing_body(void)
{
    printf("test_ringing_body\n");
    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_RINGING;
    s.call_id_hex = CALL_ID;
    s.seq = 7;

    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
    CHECK(rc == DNA_CALL_OK, "build returns OK");
    CHECK(strstr(out, "\"kind\":\"RINGING\"") != NULL, "kind RINGING");
    CHECK(strstr(out, "\"seq\":7") != NULL, "seq present");
    CHECK(strstr(out, "\"sig\":\"\"") != NULL, "empty sig slot present");
    /* RINGING carries no eph_pk / reason. */
    CHECK(strstr(out, "eph_pk") == NULL && strstr(out, "reason") == NULL, "no extra fields");
}

static void test_accept_body(void)
{
    printf("test_accept_body\n");
    static uint8_t eph_ct[DNA_CALL_KYBER_PK_LEN], static_ct[DNA_CALL_KYBER_PK_LEN];
    memset(eph_ct, 0x22, sizeof(eph_ct));
    memset(static_ct, 0x33, sizeof(static_ct));

    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_ACCEPT;
    s.call_id_hex = CALL_ID;
    s.seq = 1;
    s.eph_ct = eph_ct;
    s.static_ct = static_ct;

    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
    CHECK(rc == DNA_CALL_OK, "build returns OK");
    CHECK(strstr(out, "\"kind\":\"ACCEPT\"") != NULL, "kind ACCEPT");
    CHECK(strstr(out, "\"eph_ct\":\"") != NULL, "eph_ct present");
    CHECK(strstr(out, "\"static_ct\":\"") != NULL, "static_ct present");

    size_t b1 = 0, b2 = 0;
    char *e1 = qgp_base64_encode(eph_ct, sizeof(eph_ct), &b1);
    char *e2 = qgp_base64_encode(static_ct, sizeof(static_ct), &b2);
    CHECK(e1 && strstr(out, e1) != NULL, "eph_ct base64 correct");
    CHECK(e2 && strstr(out, e2) != NULL, "static_ct base64 correct");
    free(e1); free(e2);
}

static void test_reason_body(void)
{
    printf("test_reason_body\n");
    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_REJECT;
    s.call_id_hex = CALL_ID;
    s.seq = 2;
    s.reason = 3;
    s.has_reason = 1;

    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
    CHECK(rc == DNA_CALL_OK, "build returns OK");
    CHECK(strstr(out, "\"kind\":\"REJECT\"") != NULL, "kind REJECT");
    CHECK(strstr(out, "\"reason\":3") != NULL, "reason present");
}

static void test_bad_input_rejected(void)
{
    printf("test_bad_input_rejected\n");
    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;

    dna_call_signal_t bad_id = {0};
    bad_id.kind = DNA_CALL_KIND_RINGING;
    bad_id.call_id_hex = "short";   /* not 32 hex */
    bad_id.seq = 1;
    CHECK(dna_call_build_body(&bad_id, out, sizeof(out), &out_len) != DNA_CALL_OK,
          "rejects wrong-length call_id");

    dna_call_signal_t no_kind = {0};
    no_kind.kind = NULL;
    no_kind.call_id_hex = CALL_ID;
    CHECK(dna_call_build_body(&no_kind, out, sizeof(out), &out_len) != DNA_CALL_OK,
          "rejects missing kind");

    /* Oversize: tiny buffer. */
    dna_call_signal_t ok = {0};
    ok.kind = DNA_CALL_KIND_RINGING; ok.call_id_hex = CALL_ID; ok.seq = 1;
    CHECK(dna_call_build_body(&ok, out, 8, &out_len) == DNA_CALL_ERR_OVERSIZE,
          "rejects undersized buffer");
}

static void test_build_sign_verify_roundtrip(void)
{
    printf("test_build_sign_verify_roundtrip\n");
    /* The builder's output must be a valid input to the signer. */
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(eph_pk, 0x44, sizeof(eph_pk));
    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_INVITE; s.call_id_hex = CALL_ID; s.seq = 1;
    s.caller_fp_hex = CALLER_FP; s.eph_pk = eph_pk;

    char body[DNA_CALL_SIG_MAX_BODY]; size_t body_len = 0;
    CHECK(dna_call_build_body(&s, body, sizeof(body), &body_len) == DNA_CALL_OK, "build");

    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { CHECK(0, "keypair"); return; }

    char signed_body[DNA_CALL_SIG_MAX_BODY]; size_t signed_len = 0;
    CHECK(dna_call_sign_body(body, body_len, sk, signed_body, sizeof(signed_body), &signed_len) == DNA_CALL_OK,
          "sign built body");
    CHECK(dna_call_verify_body(signed_body, signed_len, pk) == DNA_CALL_OK,
          "verify built+signed body");
}

int main(void)
{
    printf("=== test_call_signal (PQ VoIP Faz A) ===\n");
    test_invite_body();
    test_ringing_body();
    test_accept_body();
    test_reason_body();
    test_bad_input_rejected();
    test_build_sign_verify_roundtrip();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
