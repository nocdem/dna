#ifndef QGP_MLDSA_PRIVATE_API_H
#define QGP_MLDSA_PRIVATE_API_H
#include "qgp_mldsa.h"
#define QGP_MLDSA_DECLARE(prefix) \
int prefix##_get_params(qgp_mldsa_params *out); \
int prefix##_keypair_from_seed(uint8_t *, uint8_t *, const uint8_t *); \
int prefix##_signature_internal(uint8_t *, size_t *, const uint8_t *, size_t, \
    const uint8_t *, size_t, const uint8_t *, const uint8_t *); \
int prefix##_verify_internal(const uint8_t *, size_t, const uint8_t *, size_t, \
    const uint8_t *, size_t, const uint8_t *)
QGP_MLDSA_DECLARE(qgp_mldsa44_private);
QGP_MLDSA_DECLARE(qgp_mldsa65_private);
#undef QGP_MLDSA_DECLARE
#endif
