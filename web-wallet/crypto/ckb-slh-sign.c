/* CKB SHA2-256s pure SLH-DSA, empty FIPS context over TX_MESSAGE_ALL.
 * Randomness is supplied explicitly by the host. A fresh instance per operation.
 */
#include <stdint.h>
#include <stddef.h>
#include "crypto/sign/slhdsa/qgp_slhdsa.h"
static uint8_t seed[96], message[32], random_bytes[32], pk[64], sig[29792], secret[128];
static void wipe(uint8_t *p, size_t n) { volatile uint8_t *v=p; while(n--) *v++=0; }
uint8_t *ckb_slh_seed(void) { return seed; }
uint8_t *ckb_slh_message(void) { return message; }
uint8_t *ckb_slh_random(void) { return random_bytes; }
uint8_t *ckb_slh_public_key(void) { return pk; }
uint8_t *ckb_slh_signature(void) { return sig; }
void ckb_slh_clear(void) { wipe(seed,sizeof seed); wipe(message,sizeof message); wipe(random_bytes,sizeof random_bytes); wipe(pk,sizeof pk); wipe(sig,sizeof sig); wipe(secret,sizeof secret); }
int ckb_slh_verify(void) { return qgp_slhdsa_verify(5,sig,sizeof sig,message,sizeof message,NULL,0,pk,sizeof pk); }
int ckb_slh_sign(void) {
  size_t length=0; int result=-1;
  wipe(pk,sizeof pk); wipe(sig,sizeof sig);
  if(qgp_slhdsa_keypair_from_seed(5,pk,sizeof pk,secret,sizeof secret,seed,sizeof seed)) goto done;
  if(qgp_slhdsa_sign(5,sig,sizeof sig,&length,message,sizeof message,NULL,0,secret,sizeof secret,random_bytes,sizeof random_bytes) || length!=sizeof sig) goto done;
  if(ckb_slh_verify()) goto done;
  result=0;
done:
  wipe(seed,sizeof seed); wipe(secret,sizeof secret); wipe(message,sizeof message); wipe(random_bytes,sizeof random_bytes);
  if(result) { wipe(pk,sizeof pk); wipe(sig,sizeof sig); }
  return result;
}
