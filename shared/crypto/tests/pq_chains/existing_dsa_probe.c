/* Link and NIST regression probe for existing mode 5 beside the new modes.
 * No production RNG is linked: this test uses explicit seed/rnd only. */
#include "vector_io.h"
#include "sign.h"
int qgp_randombytes(uint8_t *out,size_t n) { (void)out;(void)n;return -1; }
unsigned long test_existing_dsa(const vector *v) {
    unsigned long before=checks;const blob *f=v->f;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES],sig[CRYPTO_BYTES];size_t n;
    CHECK(v->param==87);CHECK(sizeof pk==2592&&sizeof sk==4896&&sizeof sig==4627);
    if(v->flags&KEYGEN) {
        CHECK(f[SEED].n==32&&f[PK].n==sizeof pk&&f[SK].n==sizeof sk);
        CHECK(crypto_sign_keypair_from_seed(pk,sk,f[SEED].p)==0);
        CHECK(memcmp(pk,f[PK].p,sizeof pk)==0&&memcmp(sk,f[SK].p,sizeof sk)==0);
        if(!f[SIGNATURE].n)return checks-before;
    }
    CHECK((crypto_sign_verify_internal(f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,(const uint8_t*)"",0,f[PK].p)==0)==!!(v->flags&VALID));
    if(v->flags&SIGN) {
        CHECK(f[SK].n==sizeof sk&&f[RANDOM].n==32);
        CHECK(crypto_sign_signature_internal(sig,&n,f[MESSAGE].p,f[MESSAGE].n,(const uint8_t*)"",0,f[RANDOM].p,f[SK].p)==0);
        CHECK(n==f[SIGNATURE].n&&memcmp(sig,f[SIGNATURE].p,n)==0);
    }
    if(v->flags&EXTERNAL)CHECK((crypto_sign_verify(f[SIGNATURE].p,f[SIGNATURE].n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[PK].p)==0)==!!(v->flags&VALID));
    return checks-before;
}
