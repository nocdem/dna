/* QTC's unmodified reference selects FORS ordering with the fips205 flag. */
#include "vector_io.h"
#include "api.h"
#include "randombytes.h"
static uint8_t optrand[16];
void randombytes(unsigned char *out,unsigned long long n) {CHECK(n==16);memcpy(out,optrand,16);}
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *out=fopen(argv[1],"wb");CHECK(out);
    CHECK(fwrite("PQPORT01",1,8,out)==8);write32(out,8);
    for(unsigned i=0;i<4;i++) {
        uint8_t seed[48],pk[32],sk[64],sig[7856],msg[34]={0};size_t n;
        for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(i*11+j);
        for(unsigned j=0;j<16;j++)optrand[j]=(uint8_t)(i*17+j);
        for(unsigned j=2;j<34;j++)msg[j]=(uint8_t)(i+j);
        CHECK(crypto_sign_seed_keypair(pk,sk,seed)==0);
        for(int fips=0;fips<=1;fips++) {
            CHECK(crypto_sign_signature(sig,&n,msg,sizeof msg,sk,fips)==0);CHECK(n==sizeof sig);
            CHECK(crypto_sign_verify(sig,n,msg,sizeof msg,pk,fips)==0);
            CHECK(crypto_sign_verify(sig,n,msg,sizeof msg,pk,!fips)!=0);
            write32(out,3);write32(out,7);write32(out,3000+i*2+fips);
            write32(out,fips ? KEYGEN|SIGN|VALID|EXTERNAL : 0);
            write_blob(out,seed,48);write_blob(out,msg,sizeof msg);write_blob(out,NULL,0);
            write_blob(out,pk,sizeof pk);write_blob(out,sk,sizeof sk);write_blob(out,sig,n);
            write_blob(out,optrand,16);write_blob(out,msg+2,32);
        }
    }
    CHECK(fclose(out)==0);printf("QTC SLH-DSA oracle: 4 FIPS and 4 incompatible FORS-order controls, %lu checks\n",checks);return 0;
}
