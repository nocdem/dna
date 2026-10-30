#ifndef QGP_CKB_SPHINCS_H
#define QGP_CKB_SPHINCS_H
#include <stddef.h>
#include <stdint.h>
#include "qgp_slhdsa.h"
#ifdef __cplusplus
extern "C" {
#endif
/* IDs48..59 only; flag packing belongs to the chain integration.
 * Preimage bytes are already serialized by the caller. All buffers must be
 * nonoverlapping. Digest length is exactly32. Returns zero on success except
 * param_from_id, which returns a local selector or -1. */
int qgp_ckb_sphincs_param_from_id(uint8_t id);
int qgp_ckb_sphincs_message_hash(uint8_t *digest,size_t digest_len,const uint8_t *preimage,size_t preimage_len);
int qgp_ckb_sphincs_sign_digest(uint8_t id,uint8_t *sig,size_t cap,size_t *sig_len,const uint8_t *digest,size_t digest_len,const uint8_t *sk,size_t sk_len,const uint8_t *optrand,size_t optrand_len);
int qgp_ckb_sphincs_verify_digest(uint8_t id,const uint8_t *sig,size_t sig_len,const uint8_t *digest,size_t digest_len,const uint8_t *pk,size_t pk_len);
#ifdef __cplusplus
}
#endif
#endif
