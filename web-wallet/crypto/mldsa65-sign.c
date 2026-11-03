/* Single-use ML-DSA-65 signing bridge. Not a transaction builder or broadcaster.
 * Selector 0 is empty FIPS context (XION/Asentum); 1 is Splendor's transaction context.
 * Both pinned protocols require deterministic signing (all-zero FIPS randomness).
 */
#include <stdint.h>
#include <stddef.h>
#include "crypto/sign/mldsa/qgp_mldsa.h"
#define MSG_MAX 65536
static uint8_t seed[32], message[MSG_MAX], pk[1952], sig[3309], secret[4032];
static const uint8_t splendor_ctx[] = "SPLENDOR-QC-TX-v1";
static void wipe(uint8_t *p, size_t n) { volatile uint8_t *v=p; while (n--) *v++=0; }
uint8_t *mldsa65_seed(void) { return seed; }
uint8_t *mldsa65_message(void) { return message; }
uint8_t *mldsa65_public_key(void) { return pk; }
uint8_t *mldsa65_signature(void) { return sig; }
void mldsa65_clear(void) {
    wipe(seed,sizeof seed); wipe(message,sizeof message); wipe(pk,sizeof pk);
    wipe(sig,sizeof sig); wipe(secret,sizeof secret);
}
int mldsa65_sign(int length, int context) {
    static const uint8_t rnd[32] = {0};
    const uint8_t *ctx = NULL; size_t ctx_len=0, sig_len=0;
    int result=-1;
    wipe(pk,sizeof pk); wipe(sig,sizeof sig);
    if (length < 0 || length > MSG_MAX || (context != 0 && context != 1)) goto done;
    if (context == 1) { ctx=splendor_ctx; ctx_len=sizeof splendor_ctx-1; }
    if (qgp_mldsa_keypair_from_seed(65,pk,sizeof pk,secret,sizeof secret,seed,sizeof seed)) goto done;
    if (qgp_mldsa_sign(65,sig,sizeof sig,&sig_len,message,(size_t)length,ctx,ctx_len,secret,sizeof secret,rnd,sizeof rnd) || sig_len != sizeof sig) goto done;
    result=0;
done:
    wipe(seed,sizeof seed); wipe(secret,sizeof secret); wipe(message,sizeof message);
    if (result) { wipe(pk,sizeof pk); wipe(sig,sizeof sig); }
    return result;
}

/* Public-input verification for exact signed-payload recovery. */
int mldsa65_verify(int length, int context) {
    const uint8_t *ctx = NULL; size_t ctx_len = 0;
    if (length < 0 || length > MSG_MAX || (context != 0 && context != 1)) return -1;
    if (context == 1) { ctx=splendor_ctx; ctx_len=sizeof splendor_ctx-1; }
    return qgp_mldsa_verify(65,sig,sizeof sig,message,(size_t)length,ctx,ctx_len,pk,sizeof pk);
}
