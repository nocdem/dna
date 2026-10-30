/* Parent-authored red-team oracle. Linked ONLY to pinned upstream sources. */
#include "mutation_cases.h"
#if defined(ORACLE_ALGORAND)
#include "deterministic.h"
static int verify(const vector *v,const mutation *m) {
    if(m->pk.n!=FALCON_DET1024_PUBKEY_SIZE)return -1;
    if(v->flags&CT) {
        if(m->sig.n!=FALCON_DET1024_SIG_CT_SIZE)return -1;
        return falcon_det1024_verify_ct(m->sig.p,m->pk.p,m->msg.p,m->msg.n);
    }
    return falcon_det1024_verify_compressed(m->sig.p,m->sig.n,m->pk.p,m->msg.p,m->msg.n);
}
#elif defined(ORACLE_TIDECOIN)
#include "pq/falcon-512/api.h"
int randombytes(uint8_t *p,size_t n) {(void)p;(void)n;return -1;}
int tidecoin_falcon512_verify(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,int);
static int verify(const vector *v,const mutation *m) {
    (void)v;return tidecoin_falcon512_verify(m->sig.p,m->sig.n,m->msg.p,m->msg.n,m->pk.p,m->pk.n,1);
}
#elif defined(ORACLE_SLHDSA)
#include "api.h"
void randombytes(unsigned char *p,unsigned long long n) {(void)p;(void)n;CHECK(0);}
static int verify(const vector *v,const mutation *m) {
    (void)v;if(m->pk.n!=CRYPTO_PUBLICKEYBYTES)return -1;
    return crypto_sign_verify(m->sig.p,m->sig.n,m->msg.p,m->msg.n,m->pk.p);
}
#elif defined(ORACLE_MLDSA)
#include "sign.h"
void randombytes(uint8_t *p,size_t n) {(void)p;(void)n;CHECK(0);}
static int verify(const vector *v,const mutation *m) {
    (void)v;if(m->pk.n!=CRYPTO_PUBLICKEYBYTES)return -1;
    return crypto_sign_verify_internal(m->sig.p,m->sig.n,m->msg.p,m->msg.n,(const uint8_t*)"",0,m->pk.p);
}
#else
#error Select a pinned reference
#endif
int main(int argc,char **argv) {
    CHECK(argc==3);FILE *in=fopen(argv[1],"rb"),*out=fopen(argv[2],"wb");CHECK(in&&out);
    char magic[8];CHECK(fread(magic,1,8,in)==8&&memcmp(magic,"PQPORT01",8)==0);
    uint32_t count=read32(in);CHECK(count>0);
    CHECK(fwrite("PQPORT01",1,8,out)==8);write32(out,count);
    for(uint32_t j=0;j<count;j++) {
        vector v;read_vector(in,&v);uint8_t answers[MUTATION_COUNT];unsigned rejects=0;
        for(unsigned i=0;i<MUTATION_COUNT;i++) {
            mutation m=make_mutation(&v,i);answers[i]=verify(&v,&m)==0;free_mutation(&m);rejects+=!answers[i];
        }
        CHECK(answers[0]&&rejects>70);
        write32(out,v.scheme);write32(out,v.param);write32(out,v.id);write32(out,DIFFERENTIAL|(v.flags&CT));
        for(unsigned i=0;i<FIELD_COUNT;i++)write_blob(out,i==AUX?answers:v.f[i].p,i==AUX?sizeof answers:v.f[i].n);
        printf("Reference scheme=%u param=%u ct=%u: %u/%u rejected\n",v.scheme,v.param,!!(v.flags&CT),rejects,MUTATION_COUNT);
        free_vector(&v);
    }
    CHECK(fgetc(in)==EOF);CHECK(fclose(in)==0&&fclose(out)==0);return 0;
}
