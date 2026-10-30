#include "qgp_algorand_falcon.h"
#include "crypto/sign/dsa/secure_clear.h"
#include <string.h>

static const uint8_t empty_input = 0;

int qgp_algorand_falcon_keypair_from_seed(uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len, const uint8_t *seed, size_t seed_len)
{
    shake256_context rng;
    uint8_t temporary_pk[QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE];
    uint8_t temporary_sk[QGP_ALGORAND_FALCON_SECRET_KEY_SIZE];
    int result;
    if (!pk || !sk || (!seed && seed_len)) return FALCON_ERR_BADARG;
    if (pk_len != sizeof temporary_pk || sk_len != sizeof temporary_sk)
        return FALCON_ERR_SIZE;
    shake256_init_prng_from_seed(&rng, seed ? seed : &empty_input, seed_len);
    result = falcon_det1024_keygen(&rng, temporary_sk, temporary_pk);
    if (result == 0) {
        memcpy(pk, temporary_pk, sizeof temporary_pk);
        memcpy(sk, temporary_sk, sizeof temporary_sk);
    }
    dilithium_secure_clear(&rng, sizeof rng);
    dilithium_secure_clear(temporary_sk, sizeof temporary_sk);
    dilithium_secure_clear(temporary_pk, sizeof temporary_pk);
    return result;
}

int qgp_algorand_falcon_sign(uint8_t *sig, size_t sig_capacity,
    size_t *sig_len, const uint8_t *msg, size_t msg_len,
    const uint8_t *sk, size_t sk_len)
{
    uint8_t temporary[QGP_ALGORAND_FALCON_SIGNATURE_MAX_SIZE];
    size_t length = 0;
    int result;
    if (!sig_len) return FALCON_ERR_BADARG;
    *sig_len = 0;
    if (!sig || !sk || (!msg && msg_len)) return FALCON_ERR_BADARG;
    if (sk_len != QGP_ALGORAND_FALCON_SECRET_KEY_SIZE ||
        sig_capacity < sizeof temporary) return FALCON_ERR_SIZE;
    result = falcon_det1024_sign_compressed(temporary, &length, sk,
        msg ? msg : &empty_input, msg_len);
    if (result == 0) {
        memcpy(sig, temporary, length);
        *sig_len = length;
    }
    dilithium_secure_clear(temporary, sizeof temporary);
    return result;
}

int qgp_algorand_falcon_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk, size_t pk_len)
{
    if (!sig || !pk || (!msg && msg_len)) return FALCON_ERR_BADARG;
    if (pk_len != QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE || sig_len < 2 ||
        sig_len > QGP_ALGORAND_FALCON_SIGNATURE_MAX_SIZE)
        return FALCON_ERR_SIZE;
    return falcon_det1024_verify_compressed(sig, sig_len, pk,
        msg ? msg : &empty_input, msg_len);
}

int qgp_algorand_falcon_to_ct(uint8_t *out, size_t out_capacity,
    const uint8_t *compressed, size_t compressed_len)
{
    uint8_t temporary[QGP_ALGORAND_FALCON_SIGNATURE_CT_SIZE];
    int result;
    if (!out || !compressed) return FALCON_ERR_BADARG;
    if (out_capacity < sizeof temporary || compressed_len < 2 ||
        compressed_len > QGP_ALGORAND_FALCON_SIGNATURE_MAX_SIZE)
        return FALCON_ERR_SIZE;
    result = falcon_det1024_convert_compressed_to_ct(temporary,
        compressed, compressed_len);
    if (result == 0) memcpy(out, temporary, sizeof temporary);
    dilithium_secure_clear(temporary, sizeof temporary);
    return result;
}

int qgp_algorand_falcon_verify_ct(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk, size_t pk_len)
{
    if (!sig || !pk || (!msg && msg_len)) return FALCON_ERR_BADARG;
    if (pk_len != QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE ||
        sig_len != QGP_ALGORAND_FALCON_SIGNATURE_CT_SIZE)
        return FALCON_ERR_SIZE;
    return falcon_det1024_verify_ct(sig, pk, msg ? msg : &empty_input, msg_len);
}
