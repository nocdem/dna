/* Compiled with each chain's pristine ML-DSA reference, never with the port. */
#include "vector_io.h"
#include "sign.h"
#include "randombytes.h"
static uint8_t seed[32];
void randombytes(uint8_t *out,size_t n) { CHECK(n==sizeof seed);memcpy(out,seed,n); }
int main(int argc,char **argv) {
    const size_t lengths[]={0,1,32,64,135,136,255,1024};
    CHECK(argc==2);FILE *out=fopen(argv[1],"wb");CHECK(out);
    CHECK(fwrite("PQPORT01",1,8,out)==8);write32(out,8);
    for(unsigned i=0;i<8;i++) {
        uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES],sig[CRYPTO_BYTES],msg[1024],rnd[32],framed[1026]={0};size_t n;
        for(unsigned j=0;j<32;j++) { seed[j]=(uint8_t)(i*7+j);rnd[j]=(uint8_t)(i*13+j); }
        for(unsigned j=0;j<1024;j++)msg[j]=(uint8_t)(i+j*3);
        CHECK(crypto_sign_keypair(pk,sk)==0);
        memcpy(framed+2,msg,lengths[i]);
        CHECK(crypto_sign_signature_internal(sig,&n,msg,lengths[i],framed,2,rnd,sk)==0);
        CHECK(n==sizeof sig);CHECK(crypto_sign_verify(sig,n,msg,lengths[i],NULL,0,pk)==0);
        write32(out,5);write32(out,44);write32(out,2000+i);write32(out,KEYGEN|SIGN|VALID|EXTERNAL);
        write_blob(out,seed,32);write_blob(out,framed,lengths[i]+2);write_blob(out,NULL,0);
        write_blob(out,pk,sizeof pk);write_blob(out,sk,sizeof sk);write_blob(out,sig,n);
        write_blob(out,rnd,32);write_blob(out,msg,lengths[i]);
    }
    CHECK(fclose(out)==0);printf("Chain ML-DSA-44 oracle: 8 cases, %lu checks\n",checks);return 0;
}
