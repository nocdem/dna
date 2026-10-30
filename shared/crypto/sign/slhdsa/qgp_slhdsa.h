#ifndef QGP_SLHDSA_H
#define QGP_SLHDSA_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Local selectors, never CKB wire IDs. Buffers must not overlap.
 * NULL message/context is permitted only at length zero.
 * Pure SLH-DSA only: context framing is 00 || len(ctx) || ctx || message.
 * Internal functions take an already-framed message. Optrand is exactly N
 * caller-provided bytes: PK.seed for deterministic signing, CSPRNG otherwise.
 * No implicit randomness, prehashing, or HashSLH-DSA is provided.
 * All functions return zero on success and nonzero on failure. */
enum qgp_slhdsa_param {
 QGP_SLHDSA_SHA2_128F=0, QGP_SLHDSA_SHA2_128S,
 QGP_SLHDSA_SHA2_192F, QGP_SLHDSA_SHA2_192S,
 QGP_SLHDSA_SHA2_256F, QGP_SLHDSA_SHA2_256S,
 QGP_SLHDSA_SHAKE_128F, QGP_SLHDSA_SHAKE_128S,
 QGP_SLHDSA_SHAKE_192F, QGP_SLHDSA_SHAKE_192S,
 QGP_SLHDSA_SHAKE_256F, QGP_SLHDSA_SHAKE_256S
};
typedef struct {
 size_t public_key_bytes, secret_key_bytes, signature_bytes, seed_bytes, optrand_bytes;
} qgp_slhdsa_params;
int qgp_slhdsa_get_params(int param,qgp_slhdsa_params *out);
int qgp_slhdsa_keypair_from_seed(int param,uint8_t *pk,size_t pk_len,uint8_t *sk,size_t sk_len,const uint8_t *seed,size_t seed_len);
int qgp_slhdsa_sign_internal(int param,uint8_t *sig,size_t sig_capacity,size_t *sig_len,const uint8_t *message,size_t message_len,const uint8_t *sk,size_t sk_len,const uint8_t *optrand,size_t optrand_len);
int qgp_slhdsa_verify_internal(int param,const uint8_t *sig,size_t sig_len,const uint8_t *message,size_t message_len,const uint8_t *pk,size_t pk_len);
int qgp_slhdsa_sign(int param,uint8_t *sig,size_t cap,size_t *sig_len,const uint8_t *message,size_t message_len,const uint8_t *ctx,size_t ctx_len,const uint8_t *sk,size_t sk_len,const uint8_t *optrand,size_t optrand_len);
int qgp_slhdsa_verify(int param,const uint8_t *sig,size_t sig_len,const uint8_t *message,size_t message_len,const uint8_t *ctx,size_t ctx_len,const uint8_t *pk,size_t pk_len);
#ifdef __cplusplus
}
#endif
#endif
