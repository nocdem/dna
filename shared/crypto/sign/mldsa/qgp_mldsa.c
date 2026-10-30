#include "private_api.h"
#include "crypto/sign/dsa/secure_clear.h"
#include <string.h>

static const uint8_t empty_input = 0;

int qgp_mldsa_get_params(int param, qgp_mldsa_params *out)
{
    if (!out) return -1;
    if (param == 44) return qgp_mldsa44_private_get_params(out);
    if (param == 65) return qgp_mldsa65_private_get_params(out);
    return -1;
}

int qgp_mldsa_keypair_from_seed(int param, uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len, const uint8_t *seed, size_t seed_len)
{
    qgp_mldsa_params p;
    uint8_t temporary_pk[1952], temporary_sk[4032];
    int result;
    if (qgp_mldsa_get_params(param, &p) || !pk || !sk || !seed ||
        pk_len != p.public_key_bytes || sk_len != p.secret_key_bytes ||
        seed_len != p.seed_bytes) return -1;
    result = param == 44 ?
        qgp_mldsa44_private_keypair_from_seed(temporary_pk, temporary_sk, seed) :
        qgp_mldsa65_private_keypair_from_seed(temporary_pk, temporary_sk, seed);
    if (result == 0) {
        memcpy(pk, temporary_pk, p.public_key_bytes);
        memcpy(sk, temporary_sk, p.secret_key_bytes);
    }
    dilithium_secure_clear(temporary_sk, sizeof temporary_sk);
    dilithium_secure_clear(temporary_pk, sizeof temporary_pk);
    return result;
}

static int sign_prefix(int param, uint8_t *sig, size_t cap, size_t *sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *pre, size_t pre_len,
    const uint8_t *sk, size_t sk_len, const uint8_t *rnd, size_t rnd_len)
{
    qgp_mldsa_params p;
    uint8_t temporary[3309];
    size_t length = 0;
    int result;
    if (!sig_len) return -1;
    *sig_len = 0;
    if (qgp_mldsa_get_params(param, &p) || !sig || !sk || !rnd ||
        (!message && message_len) || cap < p.signature_bytes ||
        sk_len != p.secret_key_bytes || rnd_len != p.random_bytes) return -1;
    message = message ? message : &empty_input;
    result = param == 44 ?
        qgp_mldsa44_private_signature_internal(temporary, &length, message,
            message_len, pre, pre_len, rnd, sk) :
        qgp_mldsa65_private_signature_internal(temporary, &length, message,
            message_len, pre, pre_len, rnd, sk);
    if (result == 0 && length != p.signature_bytes) result = -1;
    if (result == 0) {
        memcpy(sig, temporary, length);
        *sig_len = length;
    }
    dilithium_secure_clear(temporary, sizeof temporary);
    return result;
}

static int verify_prefix(int param, const uint8_t *sig, size_t sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *pre, size_t pre_len,
    const uint8_t *pk, size_t pk_len)
{
    qgp_mldsa_params p;
    if (qgp_mldsa_get_params(param, &p) || !sig || !pk ||
        (!message && message_len) || sig_len != p.signature_bytes ||
        pk_len != p.public_key_bytes) return -1;
    message = message ? message : &empty_input;
    return param == 44 ?
        qgp_mldsa44_private_verify_internal(sig, sig_len, message, message_len,
            pre, pre_len, pk) :
        qgp_mldsa65_private_verify_internal(sig, sig_len, message, message_len,
            pre, pre_len, pk);
}

int qgp_mldsa_sign_internal(int param, uint8_t *sig, size_t cap,
    size_t *sig_len, const uint8_t *message, size_t message_len,
    const uint8_t *sk, size_t sk_len, const uint8_t *rnd, size_t rnd_len)
{
    return sign_prefix(param, sig, cap, sig_len, message, message_len,
        &empty_input, 0, sk, sk_len, rnd, rnd_len);
}

int qgp_mldsa_verify_internal(int param, const uint8_t *sig, size_t sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *pk, size_t pk_len)
{
    return verify_prefix(param, sig, sig_len, message, message_len,
        &empty_input, 0, pk, pk_len);
}

int qgp_mldsa_sign(int param, uint8_t *sig, size_t cap, size_t *sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *sk, size_t sk_len, const uint8_t *rnd, size_t rnd_len)
{
    uint8_t pre[257];
    if (sig_len) *sig_len = 0;
    if ((!ctx && ctx_len) || ctx_len > 255) return -1;
    pre[0] = 0;
    pre[1] = (uint8_t)ctx_len;
    memcpy(pre + 2, ctx ? ctx : &empty_input, ctx_len);
    return sign_prefix(param, sig, cap, sig_len, message, message_len,
        pre, ctx_len + 2, sk, sk_len, rnd, rnd_len);
}

int qgp_mldsa_verify(int param, const uint8_t *sig, size_t sig_len,
    const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctx_len,
    const uint8_t *pk, size_t pk_len)
{
    uint8_t pre[257];
    if ((!ctx && ctx_len) || ctx_len > 255) return -1;
    pre[0] = 0;
    pre[1] = (uint8_t)ctx_len;
    memcpy(pre + 2, ctx ? ctx : &empty_input, ctx_len);
    return verify_prefix(param, sig, sig_len, message, message_len,
        pre, ctx_len + 2, pk, pk_len);
}
