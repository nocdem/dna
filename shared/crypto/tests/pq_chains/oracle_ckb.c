/* Pinned SPHINCS+ reference oracle. Input contains a source NIST key, explicit
 * optrand, and Python hashlib's independently calculated personalized digest.
 * No port code is linked. The CKB 00 00 prefix follows pinned root-lock.c. */
#include "vector_io.h"
#include "api.h"
static const uint8_t *rnd;static size_t rndlen,consumed;
void randombytes(unsigned char *out,unsigned long long n) {
    CHECK(n<=rndlen-consumed);memcpy(out,rnd+consumed,(size_t)n);consumed+=(size_t)n;
}
int main(int argc,char **argv) {
    CHECK(argc==3);FILE *in=fopen(argv[1],"rb"),*out=fopen(argv[2],"wb");CHECK(in&&out);
    char magic[8];CHECK(fread(magic,1,8,in)==8);CHECK(memcmp(magic,"PQPORT01",8)==0);CHECK(read32(in)==1);
    vector v;read_vector(in,&v);blob *f=v.f;
    CHECK(f[PK].n==CRYPTO_PUBLICKEYBYTES&&f[SK].n==CRYPTO_SECRETKEYBYTES);
    CHECK(f[AUX].n==32);uint8_t final[34]={0};memcpy(final+2,f[AUX].p,32);
    uint8_t sig[CRYPTO_BYTES];size_t n=0;rnd=f[RANDOM].p;rndlen=f[RANDOM].n;consumed=0;
    CHECK(crypto_sign_signature(sig,&n,final,sizeof final,f[SK].p)==0);CHECK(n==CRYPTO_BYTES&&consumed==rndlen);
    CHECK(crypto_sign_verify(sig,n,final,sizeof final,f[PK].p)==0);
    CHECK(fwrite("PQPORT01",1,8,out)==8);write32(out,1);
    write32(out,v.scheme);write32(out,v.param);write32(out,v.id);write32(out,v.flags);
    for(unsigned i=0;i<FIELD_COUNT;i++)write_blob(out,i==SIGNATURE?sig:f[i].p,i==SIGNATURE?n:f[i].n);
    free_vector(&v);CHECK(fclose(in)==0);CHECK(fclose(out)==0);return 0;
}
