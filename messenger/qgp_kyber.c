#include "qgp_kyber.h"
#include "crypto/kem/kem.h"
#include <string.h>

// QGP KEM-1024 API (ML-KEM-1024)
// Wrapper for vendored pq-crystals/kyber reference implementation
// FIPS 203 compliant - ML-KEM-1024 (NIST Level 5 / Category 5 security)

int qgp_kem1024_keypair(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return -1;
    }

    return crypto_kem_keypair(pk, sk);
}

int qgp_kem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!ct || !ss || !pk) {
        return -1;
    }

    return crypto_kem_enc(ct, ss, pk);
}

int qgp_kem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!ss || !ct || !sk) {
        return -1;
    }

    return crypto_kem_dec(ss, ct, sk);
}
