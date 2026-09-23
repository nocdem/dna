/* Public test mnemonics only, read on stdin. Independent native derivation path
 * for the Ixios ML-DSA-87 signing key (docs/plans/decisions/2026-09-23-ixios-separate-mldsa-key.md)
 * and hedged signing (docs/plans/decisions/2026-09-23-web-wallet-mldsa-hedged-signing.md).
 * Mirrors crypto/nodus-native-vector.c; the only differences are the SHAKE256
 * domain-separation label ("ixios-mldsa87-v1" instead of "qgp-signing-v1") and
 * that a fixed-rnd signature is produced and verified natively.
 */
#include <stdio.h>
#include <string.h>
#include "crypto/key/bip39/bip39.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/sign/dsa/sign.h"
#include "crypto/sign/dsa/fips202.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_random.h"

#ifndef IXIOS_SOURCE_COMMIT
#define IXIOS_SOURCE_COMMIT "unknown"
#endif

void qgp_secure_memzero(void *data, size_t size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
void qgp_log_message(qgp_log_level_t level, const char *tag, const char *format, ...) {}
bool qgp_log_should_log(qgp_log_level_t level, const char *tag) { return false; }
void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...) {}
void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {}

/* Dead code, never called — see crypto/mldsa87-sign-wasm.c for the full explanation.
 * We reach crypto_sign_verify (via qgp_dsa87_verify) but never crypto_sign_keypair
 * or crypto_sign_signature (the external, non-_internal wrapper), so this symbol
 * should be eliminated by --gc-sections; kept as a defensive definition so the
 * link never falls back to a real RNG.
 */
int qgp_randombytes(uint8_t *buf, size_t len) {
    (void)buf;
    (void)len;
    __builtin_trap();
}

static void hex_encode(const unsigned char *data, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

int main(void) {
    char phrase[512];
    char pk_hex[2 * QGP_DSA87_PUBLICKEYBYTES + 1];
    char addr_hex[2 * 48 + 1];
    char sig_hex[2 * QGP_DSA87_SIGNATURE_BYTES + 1];
    unsigned char master[BIP39_SEED_SIZE];
    unsigned char label_input[BIP39_SEED_SIZE + 16];
    unsigned char signing_seed[32];
    unsigned char pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    unsigned char digest[QGP_SHA3_512_DIGEST_LENGTH];
    unsigned char sig[QGP_DSA87_SIGNATURE_BYTES];
    char hash_hex[2 * 32 + 1], rnd_hex[2 * 32 + 1];

    /* Fixed, published test vector inputs (not secrets): hash = 0x00..0x1f,
     * rnd = 0x20..0x3f. */
    unsigned char hash[32], rnd[32];
    for (int i = 0; i < 32; i++) { hash[i] = (unsigned char)i; rnd[i] = (unsigned char)(0x20 + i); }
    hex_encode(hash, sizeof(hash), hash_hex);
    hex_encode(rnd, sizeof(rnd), rnd_hex);

    printf("{\n  \"sourceCommit\": \"%s\",\n  \"label\": \"ixios-mldsa87-v1\",\n  \"hash\": \"%s\",\n  \"rnd\": \"%s\",\n  \"vectors\": [\n",
           IXIOS_SOURCE_COMMIT, hash_hex, rnd_hex);

    int first = 1;
    while (fgets(phrase, sizeof(phrase), stdin)) {
        phrase[strcspn(phrase, "\r\n")] = 0;
        if (phrase[0] == '\0') continue;

        int rc = bip39_mnemonic_to_seed(phrase, "", master);
        if (!rc) {
            memcpy(label_input, master, BIP39_SEED_SIZE);
            memcpy(label_input + BIP39_SEED_SIZE, "ixios-mldsa87-v1", 16);
            shake256(signing_seed, sizeof(signing_seed), label_input, sizeof(label_input));
        }
        if (!rc) rc = qgp_dsa87_keypair_derand(pk, sk, signing_seed);
        if (!rc) rc = qgp_sha3_512(pk, sizeof(pk), digest);

        size_t siglen = 0;
        static const unsigned char pre[2] = {0x00, 0x00};
        if (!rc) rc = crypto_sign_signature_internal(sig, &siglen, hash, sizeof(hash), pre, sizeof(pre), rnd, sk);
        if (!rc && siglen != QGP_DSA87_SIGNATURE_BYTES) rc = -1;
        if (!rc) rc = qgp_dsa87_verify(sig, siglen, hash, sizeof(hash), pk);

        if (!rc) {
            hex_encode(pk, sizeof(pk), pk_hex);
            hex_encode(digest + 16, 48, addr_hex);
            hex_encode(sig, sizeof(sig), sig_hex);
            printf("%s    { \"phrase\": \"%s\", \"publicKey\": \"%s\", \"address\": \"%s\", \"signature\": \"%s\" }",
                   first ? "" : ",\n", phrase, pk_hex, addr_hex, sig_hex);
            first = 0;
        }

        qgp_secure_memzero(phrase, sizeof(phrase));
        qgp_secure_memzero(master, sizeof(master));
        qgp_secure_memzero(label_input, sizeof(label_input));
        qgp_secure_memzero(signing_seed, sizeof(signing_seed));
        qgp_secure_memzero(sk, sizeof(sk));
        if (rc) return 1;
    }
    printf("\n  ]\n}\n");
    return 0;
}
