#ifndef QGP_TIDECOIN_FALCON_H
#define QGP_TIDECOIN_FALCON_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Pinned api.h sizes; legacy maximum: 1 + 40 + (690 - 40 - 3). */
#define QGP_TIDECOIN_FALCON_PUBLICKEYBYTES 897
#define QGP_TIDECOIN_FALCON_SECRETKEYBYTES 1281
#define QGP_TIDECOIN_FALCON_SEEDBYTES 48
#define QGP_TIDECOIN_FALCON_SIGNATURE_MAXBYTES 688
typedef int (*qgp_tidecoin_random_fn)(void *ctx, uint8_t *out, size_t len);
#if defined(__GNUC__) || defined(__clang__)
#define QGP_TIDECOIN_API __attribute__((visibility("default")))
#else
#define QGP_TIDECOIN_API
#endif
/* All APIs return 0 on success, -1 on failure. Inputs and outputs must be
 * disjoint, including sig_len. NULL message is allowed only at length zero.
 * Keys and seed require exact lengths. Sign requires maximum capacity and an
 * explicit RNG (0 success). On failure outputs are unchanged except *sig_len=0.
 * Verification follows legacy acceptance, without a facade maximum-length cap.
 */
QGP_TIDECOIN_API int qgp_tidecoin_falcon_keypair_from_seed(uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len, const uint8_t *seed, size_t seed_len);
QGP_TIDECOIN_API int qgp_tidecoin_falcon_sign(uint8_t *sig, size_t sig_capacity, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk, size_t sk_len,
    qgp_tidecoin_random_fn rng, void *rng_ctx);
QGP_TIDECOIN_API int qgp_tidecoin_falcon_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk, size_t pk_len);
#ifdef __cplusplus
}
#endif
#endif
