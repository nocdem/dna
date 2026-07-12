/*
 * test_call_parse.c — PQ VoIP Faz A signal parser (dna_call_parse_body).
 *
 * Parses a RECEIVED signal body (signed or unsigned) into typed fields, and
 * must be robust against arbitrary/adversarial input (no crash, error return).
 * Strongest check: build -> parse round-trips every field; plus a build -> sign
 * -> parse path (parser ignores the sig field), and malformed-input rejection.
 */

#include "dna_call_crypto.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

static const char *CALL_ID = "0102030405060708090a0b0c0d0e0f10";
static const char *CALLER_FP =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static void test_parse_invite_roundtrip(void)
{
    printf("test_parse_invite_roundtrip\n");
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    for (size_t i = 0; i < sizeof(eph_pk); i++) eph_pk[i] = (uint8_t)(i * 7 + 1);

    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_INVITE; s.call_id_hex = CALL_ID; s.seq = 42;
    s.caller_fp_hex = CALLER_FP; s.eph_pk = eph_pk;

    char body[DNA_CALL_SIG_MAX_BODY]; size_t blen = 0;
    dna_call_build_body(&s, body, sizeof(body), &blen);

    dna_call_parsed_t p;
    int rc = dna_call_parse_body(body, blen, &p);
    CHECK(rc == DNA_CALL_OK, "parse returns OK");
    CHECK(strcmp(p.kind, "INVITE") == 0, "kind INVITE");
    CHECK(strcmp(p.call_id_hex, CALL_ID) == 0, "call_id round-trips");
    CHECK(p.seq == 42, "seq round-trips");
    CHECK(p.has_caller && strcmp(p.caller_fp_hex, CALLER_FP) == 0, "caller fp round-trips");
    CHECK(p.has_eph_pk && memcmp(p.eph_pk, eph_pk, sizeof(eph_pk)) == 0, "eph_pk bytes round-trip");
    CHECK(!p.has_eph_ct && !p.has_reason, "no ACCEPT/reason fields for INVITE");
}

static void test_parse_accept_roundtrip(void)
{
    printf("test_parse_accept_roundtrip\n");
    static uint8_t eph_ct[DNA_CALL_KYBER_PK_LEN], static_ct[DNA_CALL_KYBER_PK_LEN];
    for (size_t i = 0; i < sizeof(eph_ct); i++) { eph_ct[i] = (uint8_t)(i * 3); static_ct[i] = (uint8_t)(i * 5 + 2); }

    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_ACCEPT; s.call_id_hex = CALL_ID; s.seq = 1;
    s.eph_ct = eph_ct; s.static_ct = static_ct;

    char body[DNA_CALL_SIG_MAX_BODY]; size_t blen = 0;
    dna_call_build_body(&s, body, sizeof(body), &blen);

    dna_call_parsed_t p;
    CHECK(dna_call_parse_body(body, blen, &p) == DNA_CALL_OK, "parse OK");
    CHECK(strcmp(p.kind, "ACCEPT") == 0, "kind ACCEPT");
    CHECK(p.has_eph_ct && memcmp(p.eph_ct, eph_ct, sizeof(eph_ct)) == 0, "eph_ct round-trips");
    CHECK(p.has_static_ct && memcmp(p.static_ct, static_ct, sizeof(static_ct)) == 0, "static_ct round-trips");
}

static void test_parse_reason(void)
{
    printf("test_parse_reason\n");
    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_END; s.call_id_hex = CALL_ID; s.seq = 9;
    s.reason = 5; s.has_reason = 1;
    char body[DNA_CALL_SIG_MAX_BODY]; size_t blen = 0;
    dna_call_build_body(&s, body, sizeof(body), &blen);

    dna_call_parsed_t p;
    CHECK(dna_call_parse_body(body, blen, &p) == DNA_CALL_OK, "parse OK");
    CHECK(strcmp(p.kind, "END") == 0, "kind END");
    CHECK(p.has_reason && p.reason == 5, "reason round-trips");
}

static void test_parse_signed_body(void)
{
    printf("test_parse_signed_body\n");
    /* Parser must extract fields from a SIGNED body (sig field present, base64
     * value with '+'/'/'); it ignores the sig field. */
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(eph_pk, 0x5a, sizeof(eph_pk));
    dna_call_signal_t s = {0};
    s.kind = DNA_CALL_KIND_INVITE; s.call_id_hex = CALL_ID; s.seq = 3;
    s.caller_fp_hex = CALLER_FP; s.eph_pk = eph_pk;
    char body[DNA_CALL_SIG_MAX_BODY]; size_t blen = 0;
    dna_call_build_body(&s, body, sizeof(body), &blen);

    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { CHECK(0, "keypair"); return; }
    char signed_body[DNA_CALL_SIG_MAX_BODY]; size_t slen = 0;
    dna_call_sign_body(body, blen, sk, signed_body, sizeof(signed_body), &slen);

    dna_call_parsed_t p;
    CHECK(dna_call_parse_body(signed_body, slen, &p) == DNA_CALL_OK, "parse signed body OK");
    CHECK(strcmp(p.kind, "INVITE") == 0 && p.seq == 3, "fields intact through signing");
    CHECK(p.has_eph_pk && memcmp(p.eph_pk, eph_pk, sizeof(eph_pk)) == 0, "eph_pk intact");
}

static void test_parse_rejects_malformed(void)
{
    printf("test_parse_rejects_malformed\n");
    dna_call_parsed_t p;
    /* Not JSON at all. */
    CHECK(dna_call_parse_body("garbage not json", 16, &p) != DNA_CALL_OK, "rejects non-json");
    /* Missing kind. */
    const char *no_kind = "{\"type\":\"call_signal\",\"v\":1,\"call\":\"0102030405060708090a0b0c0d0e0f10\",\"seq\":1}";
    CHECK(dna_call_parse_body(no_kind, strlen(no_kind), &p) != DNA_CALL_OK, "rejects missing kind");
    /* Bad call_id length. */
    const char *bad_id = "{\"kind\":\"RINGING\",\"call\":\"abcd\",\"seq\":1}";
    CHECK(dna_call_parse_body(bad_id, strlen(bad_id), &p) != DNA_CALL_OK, "rejects short call_id");
    /* INVITE with corrupt eph_pk base64 (too short to be 1568 bytes). */
    const char *bad_pk = "{\"kind\":\"INVITE\",\"call\":\"0102030405060708090a0b0c0d0e0f10\",\"seq\":1,"
                         "\"caller\":\"ab\",\"eph_pk\":\"AAAA\",\"cap\":{}}";
    CHECK(dna_call_parse_body(bad_pk, strlen(bad_pk), &p) != DNA_CALL_OK, "rejects wrong-size eph_pk");
    /* Truncated mid-value (must not crash). */
    const char *trunc = "{\"kind\":\"INVITE\",\"call\":\"0102030405060708090a0b0c0d0e0f10\",\"seq\":1,\"eph_pk\":\"AAA";
    CHECK(dna_call_parse_body(trunc, strlen(trunc), &p) != DNA_CALL_OK, "rejects truncated value");
    /* Empty. */
    CHECK(dna_call_parse_body("", 0, &p) != DNA_CALL_OK, "rejects empty");
}

int main(void)
{
    printf("=== test_call_parse (PQ VoIP Faz A) ===\n");
    test_parse_invite_roundtrip();
    test_parse_accept_roundtrip();
    test_parse_reason();
    test_parse_signed_body();
    test_parse_rejects_malformed();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
