/* Compile against independent upstream algorand/falcon 19f185792c39326bebc173b2a100c2c247423be3.
 * Synthetic seed 00..1f only. stdin is public protocol preimage, stdout pk/signature hex.
 */
#include <stdio.h>
#include <stdint.h>
#include "deterministic.h"
int main(void) {
    uint8_t seed[32],pk[FALCON_DET1024_PUBKEY_SIZE],sk[FALCON_DET1024_PRIVKEY_SIZE];
    uint8_t msg[4096],sig[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
    for(int i=0;i<32;i++)seed[i]=(uint8_t)i;
    size_t len=fread(msg,1,sizeof msg,stdin),slen=0;
    if(!len || len==sizeof msg || ferror(stdin))return 1;
    shake256_context rng;shake256_init_prng_from_seed(&rng,seed,sizeof seed);
    if(falcon_det1024_keygen(&rng,sk,pk))return 2;
    if(falcon_det1024_sign_compressed(sig,&slen,sk,msg,len))return 3;
    if(falcon_det1024_verify_compressed(sig,slen,pk,msg,len))return 4;
    for(size_t i=0;i<sizeof pk;i++)printf("%02x",pk[i]);puts("");
    for(size_t i=0;i<slen;i++)printf("%02x",sig[i]);puts("");
    return 0;
}
