#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/kyber_r3_legacy.h"

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

// QGP KEM-1024 API — Kyber1024 round-3, LEGACY (see qgp_kyber.h). These
// names are UNCHANGED so every existing caller keeps round-3 behaviour
// bit-for-bit (Faz 0 — docs/plans/decisions/2026-09-23-kem-mlkem-migration.md);
// they now route to kyber_r3_legacy.c, a verbatim transplant of what used to
// be here directly.

int qgp_kem1024_keypair(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) {
        return -1;
    }

    return kyber_r3_keypair(pk, sk);
}

int qgp_kem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!ct || !ss || !pk) {
        return -1;
    }

    return kyber_r3_encapsulate(ct, ss, pk);
}

int qgp_kem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!ss || !ct || !sk) {
        return -1;
    }

    return kyber_r3_decapsulate(ss, ct, sk);
}
