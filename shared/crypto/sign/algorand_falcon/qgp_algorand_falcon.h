#ifndef QGP_ALGORAND_FALCON_H
#define QGP_ALGORAND_FALCON_H

#include <stddef.h>
#include <stdint.h>
#include "upstream/deterministic.h"

#define QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE FALCON_DET1024_PUBKEY_SIZE
#define QGP_ALGORAND_FALCON_SECRET_KEY_SIZE FALCON_DET1024_PRIVKEY_SIZE
#define QGP_ALGORAND_FALCON_SIGNATURE_MAX_SIZE FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
#define QGP_ALGORAND_FALCON_SIGNATURE_CT_SIZE FALCON_DET1024_SIG_CT_SIZE
#define QGP_ALGORAND_FALCON_COMPRESSED_HEADER FALCON_DET1024_SIG_COMPRESSED_HEADER
#define QGP_ALGORAND_FALCON_CT_HEADER FALCON_DET1024_SIG_CT_HEADER
#define QGP_ALGORAND_FALCON_SALT_VERSION FALCON_DET1024_CURRENT_SALT_VERSION

#ifdef __cplusplus
extern "C" {
#endif

/* All functions return 0 on success, a negative Falcon error on failure.
 * Output and input buffers (including sig_len) must be disjoint; overlap is
 * unsupported. Key lengths must be exact. Signing requires MAX_SIZE capacity;
 * CT conversion requires CT_SIZE capacity. Only successful operations publish
 * output bytes. A valid sig_len is set to zero on every signing failure.
 * NULL message/seed pointers are allowed only for zero length. Seed bytes are
 * used directly, without chain derivation, mnemonic decoding or system RNG.
 */
int qgp_algorand_falcon_keypair_from_seed(uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len, const uint8_t *seed, size_t seed_len);
int qgp_algorand_falcon_sign(uint8_t *sig, size_t sig_capacity,
    size_t *sig_len, const uint8_t *msg, size_t msg_len,
    const uint8_t *sk, size_t sk_len);
int qgp_algorand_falcon_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk, size_t pk_len);
int qgp_algorand_falcon_to_ct(uint8_t *out, size_t out_capacity,
    const uint8_t *compressed, size_t compressed_len);
int qgp_algorand_falcon_verify_ct(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk, size_t pk_len);

#ifdef __cplusplus
}
#endif
#endif
