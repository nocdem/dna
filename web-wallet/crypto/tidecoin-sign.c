/* Offline Tidecoin legacy Falcon-512 bridge; not a transaction builder.
 * Pinned source entropy contract: nonce40 then signing seed48, exact88 bytes.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "crypto/sign/tidecoin_falcon/qgp_tidecoin_falcon.h"
static uint8_t seed[48],message[32],entropy[88],pk[897],sig[688],sk[1281];
static size_t siglen,used;
static void wipe(uint8_t *p,size_t n){volatile uint8_t *v=p;while(n--)*v++=0;}
uint8_t *tdc_seed(void){return seed;} uint8_t *tdc_message(void){return message;}
uint8_t *tdc_random(void){return entropy;} uint8_t *tdc_public_key(void){return pk;}
uint8_t *tdc_signature(void){return sig;} unsigned tdc_signature_length(void){return (unsigned)siglen;}
void tdc_clear(void){wipe(seed,sizeof seed);wipe(message,sizeof message);wipe(entropy,sizeof entropy);wipe(pk,sizeof pk);wipe(sig,sizeof sig);wipe(sk,sizeof sk);siglen=used=0;}
static int random_bytes(void *ctx,uint8_t *out,size_t n){(void)ctx;if(n>sizeof entropy-used)return -1;memcpy(out,entropy+used,n);used+=n;return 0;}
int tdc_verify(unsigned len){if(len>sizeof sig)return -1;return qgp_tidecoin_falcon_verify(sig,len,message,sizeof message,pk,sizeof pk);}
int tdc_sign(void){
 int result=-1;used=siglen=0;wipe(pk,sizeof pk);wipe(sig,sizeof sig);
 if(qgp_tidecoin_falcon_keypair_from_seed(pk,sizeof pk,sk,sizeof sk,seed,sizeof seed))goto done;
 if(qgp_tidecoin_falcon_sign(sig,sizeof sig,&siglen,message,sizeof message,sk,sizeof sk,random_bytes,NULL)||used!=88||siglen>688||sig[0]!=0x39||tdc_verify((unsigned)siglen))goto done;
 result=0;
 done: wipe(seed,sizeof seed);wipe(sk,sizeof sk);wipe(message,sizeof message);wipe(entropy,sizeof entropy);
 if(result){wipe(pk,sizeof pk);wipe(sig,sizeof sig);siglen=0;}return result;
}
