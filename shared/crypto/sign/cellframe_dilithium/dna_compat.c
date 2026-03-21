#include "dna_crypto_common.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include "crypto/utils/qgp_random.h"

// SHA3-256 implementation using OpenSSL
void SHA3_256(unsigned char *output, const unsigned char *input, size_t len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, input, len);
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Randombytes - delegates to qgp_randombytes (getrandom/BCryptGenRandom).
// WARNING: Aborts on RNG failure rather than using zero entropy.
void randombytes(unsigned char *out, size_t len) {
    if (qgp_randombytes(out, len) != 0) {
        abort();
    }
}
