/* Native linker fault injection: public Tidecoin operations must not terminate
 * the process if heap allocation is unavailable. Uses only public test keys. */
#include "vector_io.h"
#include "qgp_tidecoin_falcon.h"
static int deny_alloc;static unsigned allocations;static const blob *random_tape;static size_t consumed;
void *__real_malloc(size_t n);
void *__wrap_malloc(size_t n) {if(deny_alloc){allocations++;return NULL;}return __real_malloc(n);}
static int rng(void *ctx,uint8_t *out,size_t n) {
    (void)ctx;if(n>random_tape->n-consumed)return -1;memcpy(out,random_tape->p+consumed,n);consumed+=n;return 0;
}
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *in=fopen(argv[1],"rb");CHECK(in);char magic[8];CHECK(fread(magic,1,8,in)==8&&memcmp(magic,"PQPORT01",8)==0);CHECK(read32(in)>0);
    vector v;read_vector(in,&v);CHECK(fclose(in)==0);blob *f=v.f;
    CHECK(v.scheme==2&&(v.flags&(KEYGEN|SIGN|VALID))==(KEYGEN|SIGN|VALID));
    uint8_t pk[897],sk[1281],sig[688];size_t n;random_tape=&f[RANDOM];
    deny_alloc=1;
    CHECK(qgp_tidecoin_falcon_keypair_from_seed(pk,sizeof pk,sk,sizeof sk,f[SEED].p,f[SEED].n)==0);
    CHECK(memcmp(pk,f[PK].p,sizeof pk)==0&&memcmp(sk,f[SK].p,sizeof sk)==0);
    CHECK(qgp_tidecoin_falcon_sign(sig,sizeof sig,&n,f[MESSAGE].p,f[MESSAGE].n,sk,sizeof sk,rng,NULL)==0);
    CHECK(n==f[SIGNATURE].n&&memcmp(sig,f[SIGNATURE].p,n)==0&&consumed==random_tape->n);
    CHECK(qgp_tidecoin_falcon_verify(sig,n,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)==0);
    CHECK(allocations==0);deny_alloc=0;free_vector(&v);
    printf("PASS Tidecoin no-heap keygen/sign/verify checks=%lu\n",checks);return 0;
}
