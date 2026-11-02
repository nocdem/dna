/* QTC: pure ML-DSA-44, empty FIPS context over a 32-byte P2MR digest.
 * Randomness is supplied explicitly by the host. A fresh instance per operation.
 */
#include <stdint.h>
#include <stddef.h>
#include "crypto/sign/mldsa/qgp_mldsa.h"
static uint8_t seed[32], message[32], random_bytes[32], pk[1312], sig[2420], secret[2560];
static void wipe(uint8_t *p, size_t n) { volatile uint8_t *v=p; while(n--) *v++=0; }
uint8_t *mldsa44_seed(void) { return seed; }
uint8_t *mldsa44_message(void) { return message; }
uint8_t *mldsa44_random(void) { return random_bytes; }
uint8_t *mldsa44_public_key(void) { return pk; }
uint8_t *mldsa44_signature(void) { return sig; }
void mldsa44_clear(void) { wipe(seed,sizeof seed); wipe(message,sizeof message); wipe(random_bytes,sizeof random_bytes); wipe(pk,sizeof pk); wipe(sig,sizeof sig); wipe(secret,sizeof secret); }
int mldsa44_verify(void) { return qgp_mldsa_verify(44,sig,sizeof sig,message,sizeof message,NULL,0,pk,sizeof pk); }
int mldsa44_sign(void) {
  size_t length=0; int result=-1;
  wipe(pk,sizeof pk); wipe(sig,sizeof sig);
  if(qgp_mldsa_keypair_from_seed(44,pk,sizeof pk,secret,sizeof secret,seed,sizeof seed)) goto done;
  if(qgp_mldsa_sign(44,sig,sizeof sig,&length,message,sizeof message,NULL,0,secret,sizeof secret,random_bytes,sizeof random_bytes) || length!=sizeof sig) goto done;
  if(mldsa44_verify()) goto done;
  result=0;
done:
  wipe(seed,sizeof seed); wipe(secret,sizeof secret); wipe(message,sizeof message); wipe(random_bytes,sizeof random_bytes);
  if(result) { wipe(pk,sizeof pk); wipe(sig,sizeof sig); }
  return result;
}
