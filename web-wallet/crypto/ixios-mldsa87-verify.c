// Public-input verification only, for explicit Ixios exact-payload recovery.
#include <stdint.h>
#include <stddef.h>
#include "crypto/sign/qgp_dilithium.h"
static uint8_t message[32],pk[QGP_DSA87_PUBLICKEYBYTES],sig[QGP_DSA87_SIGNATURE_BYTES];
uint8_t *ixios_message(void){return message;}
uint8_t *ixios_public_key(void){return pk;}
uint8_t *ixios_signature(void){return sig;}
int ixios_verify(void){return qgp_dsa87_verify(sig,sizeof sig,message,sizeof message,pk);}
void ixios_clear(void){volatile uint8_t *p=message;for(size_t i=0;i<sizeof message;i++)p[i]=0;p=pk;for(size_t i=0;i<sizeof pk;i++)p[i]=0;p=sig;for(size_t i=0;i<sizeof sig;i++)p[i]=0;}
// Signing/keygen entry points are dead-stripped; never fabricate randomness.
int qgp_randombytes(uint8_t *p,size_t n){(void)p;(void)n;__builtin_trap();}
