/* Browser bridge to hedged (randomized) ML-DSA-87 signing.
 * Reference: shared/crypto/sign/dsa/sign.c:146-250 (crypto_sign_signature_internal),
 * sign.c:282-286 (pre = {0x00, ctxlen} prefix an empty-context crypto_sign_signature
 * builds; we reproduce pre = {0x00, 0x00} directly since we never carry a context
 * string), shared/crypto/sign/qgp_dilithium.c:30-81 (qgp_dsa87_keypair_derand).
 * Decision: docs/plans/decisions/2026-09-23-web-wallet-mldsa-hedged-signing.md.
 *
 * sk never leaves this module. seed/hash/rnd/sk are wiped on every path; pk/sig
 * are additionally wiped on failure. No signing key is generated here — the
 * caller supplies the already-derived seed (see src/ixios/derive.js).
 */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/sign/dsa/sign.h"
#include "crypto/utils/qgp_random.h"

static unsigned char seed[32];
static unsigned char hash[32];
static unsigned char rnd[32];
static unsigned char pk[QGP_DSA87_PUBLICKEYBYTES];
static unsigned char sig[QGP_DSA87_SIGNATURE_BYTES];
static unsigned char sk[QGP_DSA87_SECRETKEYBYTES];

static void wipe(unsigned char *data, unsigned long size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}

unsigned char *mldsa_seed(void) { return seed; }
unsigned char *mldsa_hash(void) { return hash; }
unsigned char *mldsa_rnd(void)  { return rnd; }
unsigned char *mldsa_pk(void)   { return pk; }
unsigned char *mldsa_sig(void)  { return sig; }

/* Dead code, never called. sign.c's crypto_sign_keypair() and crypto_sign_signature()
 * (the external, non-_internal wrapper) reference randombytes() -> qgp_randombytes()
 * under DILITHIUM_RANDOMIZED_SIGNING (dsa/config.h:6). This module calls ONLY
 * crypto_sign_signature_internal() (explicit rnd argument, below) and
 * qgp_dsa87_keypair_derand() (explicit seed argument), neither of which reaches
 * randombytes(); -ffunction-sections + --gc-sections drop the unreferenced wrapper
 * functions before their relocation against qgp_randombytes is ever resolved. This
 * definition exists only so the module compiles to ZERO imports even if that
 * elimination does not happen for some reason: it is unreachable at runtime, and
 * traps rather than fabricate randomness if it is ever reached.
 */
int qgp_randombytes(uint8_t *buf, size_t len) {
    (void)buf;
    (void)len;
    __builtin_trap();
}

int mldsa_sign(void) {
    int result = qgp_dsa87_keypair_derand(pk, sk, seed);
    if (result == 0) {
        static const unsigned char pre[2] = {0x00, 0x00};
        size_t siglen = 0;
        result = crypto_sign_signature_internal(sig, &siglen, hash, sizeof(hash), pre, sizeof(pre), rnd, sk);
        if (result == 0 && siglen != QGP_DSA87_SIGNATURE_BYTES) result = -1;
    }
    wipe(seed, sizeof(seed));
    wipe(hash, sizeof(hash));
    wipe(rnd, sizeof(rnd));
    wipe(sk, sizeof(sk));
    if (result != 0) {
        wipe(pk, sizeof(pk));
        wipe(sig, sizeof(sig));
    }
    return result;
}
