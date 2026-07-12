/*
 * Test dna_verify_seal_authorship (v0.11.10) — DM sender authentication.
 *
 * Covers audit findings C2/C3 Phase 1: the receiver resolves the sender's
 * Dilithium pubkey (from the keyserver, by fingerprint — here we use the known
 * sender pubkey directly) and verifies:
 *   (a) a genuine message verifies,
 *   (b) a tampered plaintext is rejected,
 *   (c) a pubkey that does not hash to the claimed fingerprint is rejected
 *       (the spoofing that C2/C3 rely on),
 *   guard: a wrong-length pubkey is rejected.
 *
 * The message wire format carries NO pubkey (v0.07 removed it), so the pubkey
 * is supplied by the caller after keyserver resolution — mirrored here by
 * passing the sender's real pubkey (dsa_pub).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../dna_api.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#define FAIL(msg) do { fprintf(stderr, "\n\xE2\x9D\x8C FAIL: %s\n", msg); return 1; } while (0)

int main(void) {
    printf("=== Seal Authorship Verification Test ===\n\n");

    uint8_t kyber_pub[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t kyber_priv[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t dsa_pub[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t dsa_priv[QGP_DSA87_SECRETKEYBYTES];
    /* Attacker signing key (a different, valid Dilithium keypair). */
    uint8_t att_pub[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t att_priv[QGP_DSA87_SECRETKEYBYTES];

    if (qgp_kem1024_keypair(kyber_pub, kyber_priv) != 0) FAIL("kyber keypair");
    if (qgp_dsa87_keypair(dsa_pub, dsa_priv) != 0) FAIL("dsa keypair");
    if (qgp_dsa87_keypair(att_pub, att_priv) != 0) FAIL("attacker keypair");

    dna_context_t *ctx = dna_context_new();
    if (!ctx) FAIL("context");

    const char *msg = "authentic message body";
    size_t msg_len = strlen(msg);

    uint8_t *enc = NULL; size_t enc_len = 0;
    if (dna_encrypt_message_raw(ctx, (const uint8_t*)msg, msg_len,
                                kyber_pub, dsa_pub, dsa_priv,
                                (uint64_t)time(NULL), &enc, &enc_len) != DNA_OK)
        FAIL("encrypt");

    uint8_t *pt = NULL; size_t pt_len = 0;
    uint8_t *fp = NULL; size_t fp_len = 0;      /* 64-byte fingerprint from payload */
    uint8_t *sig = NULL; size_t sig_len = 0;
    uint64_t ts = 0;

    if (dna_decrypt_message_raw(ctx, enc, enc_len, kyber_priv,
                                &pt, &pt_len, &fp, &fp_len, &sig, &sig_len, &ts) != DNA_OK)
        FAIL("decrypt");

    /* Sanity: the fingerprint returned by decrypt is SHA3-512 of the sender's
     * pubkey (this is the binding the receiver relies on after resolving the
     * pubkey from the keyserver). */
    uint8_t h[64];
    qgp_sha3_512(dsa_pub, QGP_DSA87_PUBLICKEYBYTES, h);
    if (fp_len != 64 || memcmp(h, fp, 64) != 0) FAIL("fingerprint != SHA3-512(sender pubkey)");
    printf("[0] fingerprint binds to sender pubkey: OK\n");

    /* (a) genuine message verifies under the resolved (sender) pubkey. */
    char vfp[129];
    if (dna_verify_seal_authorship(pt, pt_len, sig, sig_len, dsa_pub, QGP_DSA87_PUBLICKEYBYTES, fp, vfp) != DNA_OK)
        FAIL("(a) genuine message should verify");
    char expect_fp[129];
    for (int i = 0; i < 64; i++) snprintf(expect_fp + i*2, 3, "%02x", fp[i]);
    expect_fp[128] = '\0';
    if (strcmp(vfp, expect_fp) != 0) FAIL("(a) verified fp mismatch");
    printf("[a] genuine message verifies, fp correct: OK\n");

    /* (b) tampered plaintext must be rejected. */
    uint8_t *tampered = malloc(pt_len);
    memcpy(tampered, pt, pt_len);
    tampered[0] ^= 0xFF;
    if (dna_verify_seal_authorship(tampered, pt_len, sig, sig_len, dsa_pub, QGP_DSA87_PUBLICKEYBYTES, fp, vfp) != DNA_ERROR_VERIFY)
        FAIL("(b) tampered plaintext should be rejected");
    free(tampered);
    printf("[b] tampered plaintext rejected: OK\n");

    /* (c) a pubkey that does not hash to the claimed fingerprint is rejected —
     * an attacker presenting their own key while the message claims the
     * victim's fingerprint (the C2/C3 spoof). */
    if (dna_verify_seal_authorship(pt, pt_len, sig, sig_len, att_pub, QGP_DSA87_PUBLICKEYBYTES, fp, vfp) != DNA_ERROR_VERIFY)
        FAIL("(c) mismatched pubkey/fingerprint should be rejected");
    printf("[c] pubkey/fingerprint mismatch rejected: OK\n");

    /* guard: wrong pubkey length rejected. */
    if (dna_verify_seal_authorship(pt, pt_len, sig, sig_len, dsa_pub, 100, fp, vfp) != DNA_ERROR_VERIFY)
        FAIL("guard: wrong pubkey length should be rejected");
    printf("[guard] wrong pubkey length rejected: OK\n");

    free(enc); free(pt); free(fp); free(sig);
    dna_context_free(ctx);

    printf("\n\xE2\x9C\x85 SUCCESS: all authorship checks passed\n");
    return 0;
}
