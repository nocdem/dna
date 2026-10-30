#include <string.h>
#include "api.h"
#include "randombytes.h"
#if defined(_MSC_VER)
#define QGP_TLS __declspec(thread)
#else
#define QGP_TLS _Thread_local
#endif
static QGP_TLS struct {
    const unsigned char *bytes;
    size_t length;
    unsigned calls;
    int failed;
} entropy;
static void clear_bytes(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}
void randombytes(unsigned char *out, unsigned long long length) {
    entropy.calls++;
    if (!entropy.bytes || entropy.calls != 1 || length != entropy.length) {
        entropy.failed = 1;
        memset(out, 0, (size_t)length);
        return;
    }
    memcpy(out, entropy.bytes, (size_t)length);
}
int SPX_NAMESPACE(seeded)(unsigned char *pk, unsigned char *sk, const unsigned char *seed) {
    return crypto_sign_seed_keypair(pk, sk, seed);
}
int SPX_NAMESPACE(detached)(unsigned char *sig, size_t *len,
    const unsigned char *m, size_t mlen, const unsigned char *sk,
    const unsigned char *optrand) {
    int result;
    if (entropy.bytes) return -1;
    entropy.bytes = optrand;
    entropy.length = SPX_N;
    entropy.calls = 0;
    entropy.failed = 0;
    result = crypto_sign_signature(sig, len, m, mlen, sk);
    if (entropy.failed || entropy.calls != 1) result = -1;
    clear_bytes(&entropy, sizeof(entropy));
    return result;
}
int SPX_NAMESPACE(check)(const unsigned char *sig, size_t len,
    const unsigned char *m, size_t mlen, const unsigned char *pk) {
    return crypto_sign_verify(sig, len, m, mlen, pk);
}
void SPX_NAMESPACE(sizes)(size_t *v) {
    v[0] = SPX_PK_BYTES; v[1] = SPX_SK_BYTES; v[2] = SPX_BYTES;
    v[3] = 3 * SPX_N; v[4] = SPX_N;
}
