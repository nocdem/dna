#include "qgp_tidecoin_falcon.h"
#include "private_namespace.h"
#include "upstream/pq/falcon-512/api.h"
#include "upstream/pq/cleanse.h"
#include <string.h>

int tidecoin_falcon512_sign_legacy(uint8_t *, size_t *, const uint8_t *, size_t,
                                 const uint8_t *, size_t);
int tidecoin_falcon512_verify(const uint8_t *, size_t, const uint8_t *, size_t,
                            const uint8_t *, size_t, int);
struct entropy_frame {
    qgp_tidecoin_random_fn fn;
    void *ctx;
    int failed;
};
static _Thread_local struct entropy_frame *active_entropy;
static const uint8_t empty_message;

/* No default entropy source. Nested calls restore their caller's frame. */
int randombytes(uint8_t *out, size_t len)
{
    struct entropy_frame *frame = active_entropy;
    if (!frame || frame->failed || !frame->fn ||
        frame->fn(frame->ctx, out, len) != 0) {
        if (frame) frame->failed = 1;
        pq_cleanse(out, len);
        return -1;
    }
    return 0;
}

int qgp_tidecoin_falcon_keypair_from_seed(uint8_t *pk, size_t pk_len,
    uint8_t *sk, size_t sk_len, const uint8_t *seed, size_t seed_len)
{
    uint8_t public_tmp[QGP_TIDECOIN_FALCON_PUBLICKEYBYTES];
    uint8_t secret_tmp[QGP_TIDECOIN_FALCON_SECRETKEYBYTES];
    int result;
    if (!pk || !sk || !seed || pk_len != sizeof public_tmp ||
        sk_len != sizeof secret_tmp || seed_len != QGP_TIDECOIN_FALCON_SEEDBYTES)
        return -1;
    result = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(
        public_tmp, secret_tmp, seed, seed_len);
    if (result == 0) {
        memcpy(pk, public_tmp, sizeof public_tmp);
        memcpy(sk, secret_tmp, sizeof secret_tmp);
    }
    pq_cleanse(public_tmp, sizeof public_tmp);
    pq_cleanse(secret_tmp, sizeof secret_tmp);
    return result == 0 ? 0 : -1;
}

int qgp_tidecoin_falcon_sign(uint8_t *sig, size_t sig_capacity, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk, size_t sk_len,
    qgp_tidecoin_random_fn rng, void *rng_ctx)
{
    uint8_t staged[QGP_TIDECOIN_FALCON_SIGNATURE_MAXBYTES];
    size_t staged_len = 0;
    struct entropy_frame frame = {rng, rng_ctx, 0};
    struct entropy_frame *previous;
    int result;
    if (!sig_len) return -1;
    *sig_len = 0;
    if (!sig || !sk || !rng || (!msg && msg_len) ||
        sig_capacity < sizeof staged || sk_len != QGP_TIDECOIN_FALCON_SECRETKEYBYTES)
        return -1;
    previous = active_entropy;
    active_entropy = &frame;
    result = tidecoin_falcon512_sign_legacy(staged, &staged_len,
        msg ? msg : &empty_message, msg_len, sk, sk_len);
    active_entropy = previous;
    if (result == 0 && !frame.failed && staged_len <= sizeof staged) {
        memcpy(sig, staged, staged_len);
        *sig_len = staged_len;
    } else {
        result = -1;
    }
    pq_cleanse(staged, sizeof staged);
    pq_cleanse(&frame, sizeof frame);
    return result == 0 ? 0 : -1;
}

int qgp_tidecoin_falcon_verify(const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *pk, size_t pk_len)
{
    if (!sig || !pk || (!msg && msg_len) ||
        pk_len != QGP_TIDECOIN_FALCON_PUBLICKEYBYTES) return -1;
    return tidecoin_falcon512_verify(sig, sig_len,
        msg ? msg : &empty_message, msg_len, pk, pk_len, 1) == 0 ? 0 : -1;
}
