/* Native allocation fault injection for SLH/CKB staging and pure framing.
 * Every allocation site is failed separately; no signature/key is published. */
#include "vector_io.h"
#include "qgp_slhdsa.h"
#include "qgp_ckb_sphincs.h"
static unsigned fail_at,calls;
void *__real_malloc(size_t n);
void *__wrap_malloc(size_t n) {if(fail_at&&++calls==fail_at)return NULL;return __real_malloc(n);}
static void arm(unsigned n) {calls=0;fail_at=n;}
static void disarm(unsigned n) {fail_at=0;CHECK(calls==n);}
static void unchanged(const uint8_t *p,size_t n) {for(size_t i=0;i<n;i++)CHECK(p[i]==0xA5);}
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *in=fopen(argv[1],"rb");CHECK(in);char magic[8];CHECK(fread(magic,1,8,in)==8&&memcmp(magic,"PQPORT01",8)==0);CHECK(read32(in)>0);
    vector v;read_vector(in,&v);CHECK(fclose(in)==0);blob *f=v.f;
    CHECK(v.scheme==3&&v.param==QGP_SLHDSA_SHA2_128S&&(v.flags&EXTERNAL));
    CHECK(qgp_slhdsa_verify_internal((int)v.param,f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)==0);
    uint8_t pk[32],sk[64],sig[7856],digest[32]={0};size_t n;
    memset(pk,0xA5,sizeof pk);memset(sk,0xA5,sizeof sk);memset(sig,0xA5,sizeof sig);
    arm(1);int r=qgp_slhdsa_keypair_from_seed((int)v.param,pk,sizeof pk,sk,sizeof sk,f[SEED].p,f[SEED].n);disarm(1);
    CHECK(r!=0);unchanged(pk,sizeof pk);unchanged(sk,sizeof sk);
    arm(1);n=99;r=qgp_slhdsa_sign_internal((int)v.param,sig,sizeof sig,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n);disarm(1);
    CHECK(r!=0&&n==0);unchanged(sig,sizeof sig);
    for(unsigned fail=1;fail<=2;fail++) {
        arm(fail);n=99;r=qgp_slhdsa_sign((int)v.param,sig,sizeof sig,&n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n);disarm(fail);
        CHECK(r!=0&&n==0);unchanged(sig,sizeof sig);
        arm(fail);n=99;r=qgp_ckb_sphincs_sign_digest(49,sig,sizeof sig,&n,digest,32,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n);disarm(fail);
        CHECK(r!=0&&n==0);unchanged(sig,sizeof sig);
    }
    arm(1);r=qgp_slhdsa_verify((int)v.param,f[SIGNATURE].p,f[SIGNATURE].n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[PK].p,f[PK].n);disarm(1);CHECK(r!=0);
    CHECK(qgp_slhdsa_verify((int)v.param,f[SIGNATURE].p,f[SIGNATURE].n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[PK].p,f[PK].n)==0);
    free_vector(&v);printf("PASS allocation failure staging/recovery checks=%lu\n",checks);return 0;
}
