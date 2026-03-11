#include "dna_crypto_common.h"
#include <openssl/evp.h>

// SHA3-256 implementation using OpenSSL
void SHA3_256(unsigned char *output, const unsigned char *input, size_t len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, input, len);
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Randombytes implementation - use /dev/urandom
void randombytes(unsigned char *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        size_t read = fread(out, 1, len, fp);
        fclose(fp);
        // Zero remaining buffer if partial read (shouldn't happen with urandom)
        if (read < len) {
            memset(out + read, 0, len - read);
        }
    } else {
        // Fallback: zero the buffer if urandom unavailable
        memset(out, 0, len);
    }
}
