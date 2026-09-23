/* Public test mnemonics only, read on stdin. Independent native derivation path. */
#include <stdio.h>
#include <string.h>
#include "crypto/key/bip39/bip39.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

void qgp_secure_memzero(void *data, size_t size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
void qgp_log_message(qgp_log_level_t level, const char *tag, const char *format, ...) {}
bool qgp_log_should_log(qgp_log_level_t level, const char *tag) { return false; }
void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...) {}
void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {}

int main(void) {
    char phrase[512], address[129];
    unsigned char signing[32], encryption[32];
    unsigned char pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    if (!fgets(phrase, sizeof(phrase), stdin)) return 1;
    phrase[strcspn(phrase, "\r\n")] = 0;
    int rc = qgp_derive_seeds_from_mnemonic(phrase, "", signing, encryption);
    if (!rc) rc = qgp_dsa87_keypair_derand(pk, sk, signing);
    if (!rc) rc = qgp_sha3_512_fingerprint(pk, sizeof(pk), address);
    qgp_secure_memzero(phrase, sizeof(phrase));
    qgp_secure_memzero(signing, sizeof(signing));
    qgp_secure_memzero(encryption, sizeof(encryption));
    qgp_secure_memzero(sk, sizeof(sk));
    if (rc) return 1;
    puts(address);
    return 0;
}
