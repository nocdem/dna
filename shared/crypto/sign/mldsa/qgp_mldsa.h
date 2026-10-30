#ifndef QGP_MLDSA_H
#define QGP_MLDSA_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct qgp_mldsa_params {
    size_t public_key_bytes, secret_key_bytes, signature_bytes;
    size_t seed_bytes, random_bytes;
} qgp_mldsa_params;
/* Parameters are 44 or 65. Returns 0 on success, nonzero on failure.
 * Key, seed, randomness and signature input sizes must be exact. Signing
 * capacity must hold signature_bytes. Output/input buffers, including sig_len,
 * must be disjoint; overlap is unsupported. Outputs publish only on success;
 * a valid sig_len is zeroed on error. NULL messages/contexts require length 0.
 * Contexts are at most 255 bytes. Explicit rnd is always required (32 bytes);
 * supply all zeros for deterministic signing. No system randomness is used.
 * Internal interfaces use an empty prefix; public interfaces implement pure
 * ML-DSA with context. HashML-DSA is not provided.
 */
int qgp_mldsa_get_params(int param, qgp_mldsa_params *out);
int qgp_mldsa_keypair_from_seed(int param, uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len, const uint8_t *seed, size_t seed_len);
int qgp_mldsa_sign_internal(int param, uint8_t *sig, size_t cap,
    size_t *sig_len, const uint8_t *message, size_t message_len,
    const uint8_t *sk, size_t sk_len, const uint8_t *rnd, size_t rnd_len);
int qgp_mldsa_verify_internal(int param, const uint8_t *sig, size_t sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *pk, size_t pk_len);
int qgp_mldsa_sign(int param, uint8_t *sig, size_t cap, size_t *sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *sk, size_t sk_len, const uint8_t *rnd, size_t rnd_len);
int qgp_mldsa_verify(int param, const uint8_t *sig, size_t sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *pk, size_t pk_len);
#ifdef __cplusplus
}
#endif
#endif
