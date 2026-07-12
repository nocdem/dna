/*
 * test_call_sign.c — PQ VoIP Faz A canonical call-signal signer/verifier.
 *
 * Validates dna_call_sign_body / dna_call_verify_body: Dilithium5 over the
 * exact signal bytes with an empty sig slot, base64 spliced in; verification
 * over the EXACT received bytes (blank the sig value, verify) so it is immune
 * to JSON encoder differences (design §4.2, red-team F-SIG / F-JSON).
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

static const char *BODY =
    "{\"type\":\"call_signal\",\"v\":1,\"call\":\"0102030405060708090a0b0c0d0e0f10\","
    "\"sig\":\"\",\"kind\":\"INVITE\"}";

static void test_sign_verify_roundtrip(void)
{
    printf("test_sign_verify_roundtrip\n");
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { CHECK(0, "keypair"); return; }

    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    int rc = dna_call_sign_body(BODY, strlen(BODY), sk, out, sizeof(out), &out_len);
    CHECK(rc == DNA_CALL_OK, "sign returns OK");
    CHECK(out_len > strlen(BODY), "signed body grew (sig spliced in)");
    CHECK(strstr(out, "\"sig\":\"\"") == NULL, "empty sig slot is filled");
    CHECK(dna_call_verify_body(out, out_len, pk) == DNA_CALL_OK, "verify accepts genuine sig");
}

static void test_verify_rejects_tamper(void)
{
    printf("test_verify_rejects_tamper\n");
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { CHECK(0, "keypair"); return; }

    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    dna_call_sign_body(BODY, strlen(BODY), sk, out, sizeof(out), &out_len);

    /* Flip a byte in the "kind" value (outside the sig slot). */
    char *k = strstr(out, "INVITE");
    CHECK(k != NULL, "found tamper target");
    if (k) k[0] = 'X';
    CHECK(dna_call_verify_body(out, out_len, pk) != DNA_CALL_OK, "verify rejects tampered body");
}

static void test_verify_rejects_wrong_key(void)
{
    printf("test_verify_rejects_wrong_key\n");
    uint8_t pk1[QGP_DSA87_PUBLICKEYBYTES], sk1[QGP_DSA87_SECRETKEYBYTES];
    uint8_t pk2[QGP_DSA87_PUBLICKEYBYTES], sk2[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk1, sk1) != 0 || qgp_dsa87_keypair(pk2, sk2) != 0) {
        CHECK(0, "keypair"); return;
    }
    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    dna_call_sign_body(BODY, strlen(BODY), sk1, out, sizeof(out), &out_len);
    CHECK(dna_call_verify_body(out, out_len, pk2) != DNA_CALL_OK, "verify rejects wrong signer key");
    CHECK(dna_call_verify_body(out, out_len, pk1) == DNA_CALL_OK, "verify accepts correct key");
}

static void test_sig_value_base64_specials(void)
{
    printf("test_sig_value_base64_specials\n");
    /* Dilithium sigs base64 to ~6169 chars containing '+' and '/'. The verifier
     * must read the value to the closing quote and never re-encode — proving the
     * F-JSON '/'-escaping hazard is avoided. */
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { CHECK(0, "keypair"); return; }
    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    dna_call_sign_body(BODY, strlen(BODY), sk, out, sizeof(out), &out_len);
    /* The spliced value virtually always contains base64 specials; verify anyway. */
    CHECK(dna_call_verify_body(out, out_len, pk) == DNA_CALL_OK,
          "verify handles base64 sig containing '+' and '/'");
}

static void test_verify_operates_on_received_bytes(void)
{
    printf("test_verify_operates_on_received_bytes\n");
    /* Inserting a byte outside the sig slot (as a different encoder's whitespace
     * would) changes the signed content ⇒ verify must fail. Proves verification
     * is over exact received bytes, not logical JSON. */
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { CHECK(0, "keypair"); return; }
    char out[DNA_CALL_SIG_MAX_BODY];
    size_t out_len = 0;
    dna_call_sign_body(BODY, strlen(BODY), sk, out, sizeof(out), &out_len);

    /* Build a variant with an extra space after the first '{' (encoder diff). */
    char variant[DNA_CALL_SIG_MAX_BODY];
    variant[0] = out[0];         /* '{' */
    variant[1] = ' ';            /* injected whitespace */
    memcpy(variant + 2, out + 1, out_len - 1);
    size_t vlen = out_len + 1;
    CHECK(dna_call_verify_body(variant, vlen, pk) != DNA_CALL_OK,
          "verify rejects a byte-different (re-encoded) body");
}

int main(void)
{
    printf("=== test_call_sign (PQ VoIP Faz A) ===\n");
    test_sign_verify_roundtrip();
    test_verify_rejects_tamper();
    test_verify_rejects_wrong_key();
    test_sig_value_base64_specials();
    test_verify_operates_on_received_bytes();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
