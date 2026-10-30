/* Test oracle compiled against pristine Tidecoin sources, never against our port.
 * LEGACY_REFERENCE selects the historical implementation as an additional
 * independent verifier-compatibility corpus, not a keygen equivalence claim. */
#include "vector_io.h"
#ifdef LEGACY_REFERENCE
#include "api.h"
#include "randombytes.h"
#else
#include "pq/falcon-512/api.h"
#include "pq/falcon-512/inner.h"
#include "pq/randombytes.h"
int tidecoin_falcon512_sign_legacy(uint8_t*,size_t*,const uint8_t*,size_t,const uint8_t*,size_t);
int tidecoin_falcon512_verify(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,int);
#endif
static uint8_t entropy[131072];static size_t used;
int randombytes(uint8_t *out,size_t n) {
    CHECK(n<=sizeof entropy-used);memcpy(out,entropy+used,n);used+=n;return 0;
}
int main(int argc,char **argv) {
    const size_t lengths[]={0,1,31,32,33,40,63,64,65,135,136,137,255,256,1024,4096};
    CHECK(argc>=2);FILE *out=fopen(argv[1],"wb");CHECK(out);
    CHECK(fwrite("PQPORT01",1,8,out)==8);
#ifdef LEGACY_REFERENCE
    write32(out,16);
#else
    write32(out,17);
#endif
    for(unsigned i=0;i<16;i++) {
        uint8_t seed[48],pk[897],sk[1281],msg[4096],sig[752];size_t n;
        for(size_t j=0;j<sizeof seed;j++)seed[j]=(uint8_t)(i*17+j);
        for(size_t j=0;j<sizeof msg;j++)msg[j]=(uint8_t)(i+j*7);
        for(size_t j=0;j<sizeof entropy;j++)entropy[j]=(uint8_t)(j*13+i*19);
        used=0;
#ifdef LEGACY_REFERENCE
        memcpy(entropy,seed,sizeof seed);
        CHECK(PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk,sk)==0);
        used=0;for(size_t j=0;j<sizeof entropy;j++)entropy[j]=(uint8_t)(j*13+i*19);
        int r;
        do { r=PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig,&n,msg,lengths[i],sk); } while(r!=0);
        CHECK(PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig,n,msg,lengths[i],pk)==0);
        unsigned flags=VALID;
#else
        CHECK(PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(pk,sk,seed,sizeof seed)==0);
        CHECK(tidecoin_falcon512_sign_legacy(sig,&n,msg,lengths[i],sk,sizeof sk)==0);
        CHECK(tidecoin_falcon512_verify(sig,n,msg,lengths[i],pk,sizeof pk,1)==0);
        unsigned flags=KEYGEN|SIGN|VALID;
#endif
        write32(out,2);write32(out,512);write32(out,i);write32(out,flags);
        write_blob(out,seed,sizeof seed);write_blob(out,msg,lengths[i]);write_blob(out,NULL,0);
        write_blob(out,pk,sizeof pk);write_blob(out,sk,sizeof sk);write_blob(out,sig,n);
        write_blob(out,entropy,used);write_blob(out,NULL,0);
    }
#ifndef LEGACY_REFERENCE
    /* Synthetic verifier boundary, not a generated secret/public key pair.
     * s2=260*(1+x+...+x^511), s1=0, squared norm=34,611,200.
     * In Z_12289[x]/(x^512+1), its inverse is (1-x)/520.
     * Choose h=H(nonce||m)/s2. This is above the standard bound and below
     * the historical bound. The pristine upstream must confirm BOTH answers. */
    {
        uint8_t pk[897],sig[800]={0},msg[32]={0}; uint16_t hm[512],h[512];int16_t s2[512];
        union {uint64_t align;uint8_t b[1024];} tmp;
        inner_shake256_context sc;uint32_t inv=1;
        while ((inv*520)%12289!=1) inv++;
        inner_shake256_init(&sc);inner_shake256_inject(&sc,sig+1,40);
        inner_shake256_inject(&sc,msg,sizeof msg);inner_shake256_flip(&sc);
        PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc,hm,9,tmp.b);inner_shake256_ctx_release(&sc);
        for(unsigned j=0;j<512;j++) {
            uint32_t v=j ? (uint32_t)hm[j]+12289-hm[j-1] : (uint32_t)hm[0]+hm[511];
            h[j]=(uint16_t)((v*inv)%12289);s2[j]=260;
        }
        pk[0]=9;sig[0]=0x39;
        CHECK(PQCLEAN_FALCON512_CLEAN_modq_encode(pk+1,896,h,9)==896);
        size_t n=PQCLEAN_FALCON512_CLEAN_comp_encode(sig+41,sizeof sig-41,s2,9);CHECK(n);n+=41;
        CHECK(tidecoin_falcon512_verify(sig,n,msg,sizeof msg,pk,sizeof pk,1)==0);
        CHECK(tidecoin_falcon512_verify(sig,n,msg,sizeof msg,pk,sizeof pk,0)!=0);
        write32(out,2);write32(out,512);write32(out,1000);write32(out,VALID);
        write_blob(out,NULL,0);write_blob(out,msg,sizeof msg);write_blob(out,NULL,0);
        write_blob(out,pk,sizeof pk);write_blob(out,NULL,0);write_blob(out,sig,n);
        write_blob(out,NULL,0);write_blob(out,NULL,0);
        puts("Synthetic legacy norm boundary: legacy accepts; standard rejects");
    }
    if(argc==3) {
        FILE *in=fopen(argv[2],"rb");CHECK(in);char magic[8];CHECK(fread(magic,1,8,in)==8);
        CHECK(memcmp(magic,"PQPORT01",8)==0);uint32_t count=read32(in);unsigned strict_rejects=0;
        for(uint32_t i=0;i<count;i++) {
            vector v;read_vector(in,&v);blob *f=v.f;
            CHECK(tidecoin_falcon512_verify(f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n,1)==0);
            strict_rejects+=tidecoin_falcon512_verify(f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n,0)!=0;
            free_vector(&v);
        }
        CHECK(fclose(in)==0);
        printf("Historical Tidecoin: %u verified, %u rejected by standard verification (legacy control)\n",count,strict_rejects);
    }
#endif
    CHECK(fclose(out)==0);
    printf("Tidecoin reference: 16 signing vectors plus current-only boundary; %lu checks\n",checks);return 0;
}
