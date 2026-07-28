#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/kem/kem.h"
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

// QGP KEM-1024 API — Kyber1024 (round-3 / v3.x), NIST Level 5 / Category 5
// Wrapper for the vendored pq-crystals/kyber reference implementation.
//
// ⚠ NOT ML-KEM-1024, NOT FIPS 203 — this header claimed both until 2026-07-28 and
// the claim was false. The vendored code keeps round-3's final KDF
// (kem/kem.c:73-75, ss = SHAKE256(K' || H(c)), which FIPS 203 removed) and feeds
// keygen's G 32 bytes rather than G(d || k) (kem/indcpa.c:231-232). Shared
// secrets therefore differ from ML-KEM and will not interoperate with a FIPS 203
// peer. Full explanation and the migration caveat: qgp_kyber.h.

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
