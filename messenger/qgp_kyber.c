#include "qgp_kyber.h"
#include "crypto/kyber512/kem.h"
#include <string.h>

int qgp_kyber512_keypair(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return -1;
    }

    return crypto_kem_keypair(pk, sk);
}

int qgp_kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!ct || !ss || !pk) {
        return -1;
    }

    return crypto_kem_enc(ct, ss, pk);
}

int qgp_kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!ss || !ct || !sk) {
        return -1;
    }

    return crypto_kem_dec(ss, ct, sk);
}
