/* Generator for the Kyber round-3 LEGACY known-answer fixture.
 * Compiles ONLY against the pre-port vendored sources (commit c86cad72,
 * shared/crypto/enc/kem/* + kyber_deterministic.c). Deterministic: the RNG
 * feeding crypto_kem_enc is SHAKE256("kyber-r3-legacy-kat-rng" || counter).
 * Output: C header with hex-string vectors. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "kem.h"
#include "params.h"
#include "fips202_kyber.h"
#include "crypto/enc/kyber_deterministic.h"

static uint64_t g_ctr = 0;
int qgp_randombytes(uint8_t *buf, size_t len) {
    uint8_t in[32 + 8];
    memcpy(in, "kyber-r3-legacy-kat-rng\0\0\0\0\0\0\0\0\0", 32);
    for (int i = 0; i < 8; i++) in[32 + i] = (uint8_t)(g_ctr >> (8 * i));
    g_ctr++;
    shake256(buf, len, in, sizeof(in));
    return 0;
}
static void hex(FILE *f, const uint8_t *b, size_t n) {
    fputc('"', f);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fputc('"', f);
}
#define NV 24
int main(void) {
    uint8_t seed[32], pk[KYBER_PUBLICKEYBYTES], sk[KYBER_SECRETKEYBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES], ss[32], ss2[32], ssbad[32], hpk[32], hsk[32];
    printf("/* Kyber round-3 LEGACY KAT — GENERATED 2026-09-23 from commit c86cad72 vendored\n"
           " * sources (pq-crystals Kyber round-3, pre-Dec-2023 snapshot) by\n"
           " * messenger/tests/fixtures/gen_kyber_r3_legacy_kat.c. SELF-CONSISTENT fixture:\n"
           " * it pins TODAY's behaviour, it is not a Plonky3/NIST-grounded vector set.\n"
           " * Per vector: seed(32) -> crypto_kem_keypair_derand -> pk,sk (recorded as\n"
           " * SHA3-256 hashes); crypto_kem_enc(pk) with the deterministic RNG -> ct, ss;\n"
           " * ct_bad = ct with byte (i %% 1568) XOR 0x01 (NOT stored — the test flips it);\n"
           " * ss_bad = crypto_kem_dec(sk, ct_bad) (round-3 implicit rejection\n"
           " * SHAKE256(z || H(ct_bad))). All values hex strings. DO NOT REGENERATE against\n"
           " * post-port sources; regenerate only if the c86cad72 sources are rebuilt. */\n"
           "#ifndef KYBER_R3_LEGACY_KAT_H\n#define KYBER_R3_LEGACY_KAT_H\n"
           "#define KYBER_R3_LEGACY_KAT_COUNT %d\n"
           "typedef struct { const char *seed, *pk_sha3_256, *sk_sha3_256, *ct, *ss, *ss_bad; int bad_byte; } kyber_r3_legacy_kat_t;\n"
           "static const kyber_r3_legacy_kat_t kyber_r3_legacy_kat[KYBER_R3_LEGACY_KAT_COUNT] = {\n", NV);
    for (int i = 0; i < NV; i++) {
        uint8_t in[32 + 8];
        memcpy(in, "kyber-r3-legacy-kat-seed\0\0\0\0\0\0\0\0", 32);
        for (int k = 0; k < 8; k++) in[32 + k] = (uint8_t)((uint64_t)i >> (8 * k));
        shake256(seed, 32, in, sizeof(in));
        crypto_kem_keypair_derand(pk, sk, seed);
        sha3_256(hpk, pk, sizeof(pk));
        sha3_256(hsk, sk, sizeof(sk));
        crypto_kem_enc(ct, ss, pk);
        crypto_kem_dec(ss2, ct, sk);
        if (memcmp(ss, ss2, 32) != 0) { fprintf(stderr, "SANITY FAIL vec %d\n", i); return 1; }
        int bad = i % KYBER_CIPHERTEXTBYTES;
        ct[bad] ^= 0x01;
        crypto_kem_dec(ssbad, ct, sk);
        if (memcmp(ss, ssbad, 32) == 0) { fprintf(stderr, "SANITY FAIL bad vec %d\n", i); return 1; }
        ct[bad] ^= 0x01;
        printf("  { ");
        hex(stdout, seed, 32); printf(",\n    "); hex(stdout, hpk, 32); printf(",\n    "); hex(stdout, hsk, 32);
        printf(",\n    "); hex(stdout, ct, sizeof(ct)); printf(",\n    "); hex(stdout, ss, 32);
        printf(",\n    "); hex(stdout, ssbad, 32); printf(", %d },\n", bad);
    }
    printf("};\n#endif /* KYBER_R3_LEGACY_KAT_H */\n");
    return 0;
}
