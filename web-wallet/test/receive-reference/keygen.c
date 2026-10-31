/* Parent oracle compiled separately against pristine chain sources only.
 * stdin is an exact seed, stdout a raw public key. No port code is linked. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef TIDE
#include "pq/falcon-512/api.h"
#define SEEDLEN 48
#define PKLEN 897
#define SKLEN 1281
#elif defined(MLDSA)
#include "sign.h"
#define SEEDLEN 32
#define PKLEN CRYPTO_PUBLICKEYBYTES
#define SKLEN CRYPTO_SECRETKEYBYTES
#else
#include "api.h"
#define SEEDLEN CRYPTO_SEEDBYTES
#define PKLEN CRYPTO_PUBLICKEYBYTES
#define SKLEN CRYPTO_SECRETKEYBYTES
#endif
static uint8_t seed[SEEDLEN];
#ifdef MLDSA
void randombytes(uint8_t *out, size_t n) { if(n!=SEEDLEN) abort(); memcpy(out,seed,n); }
#elif defined(TIDE)
int randombytes(uint8_t *out,size_t n) { (void)out;(void)n;abort(); }
#else
void randombytes(unsigned char *out,unsigned long long n) { (void)out;(void)n;abort(); }
#endif
int main(void) {
 uint8_t pk[PKLEN],sk[SKLEN];int rc;
 if(fread(seed,1,sizeof seed,stdin)!=sizeof seed || fgetc(stdin)!=EOF) return 2;
#ifdef TIDE
 rc=PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(pk,sk,seed,sizeof seed);
#elif defined(MLDSA)
 rc=crypto_sign_keypair(pk,sk);
#else
 rc=crypto_sign_seed_keypair(pk,sk,seed);
#endif
 if(rc) return 3;
 return fwrite(pk,1,sizeof pk,stdout)==sizeof pk ? 0 : 4;
}
