/* Deterministic Algorand Falcon1024 compressed signing. Secret keys never leave
 * this bridge. Input is the already derived PQK/f1 32-byte keygen seed and raw
 * protocol signing bytes (TX || canonical transaction), NOT the transaction ID.
 * One fresh WASM instance per call; caller additionally wipes all linear memory.
 */
#include "crypto/sign/algorand_falcon/qgp_algorand_falcon.h"
static uint8_t seed[32], message[4096];
static uint8_t secret[QGP_ALGORAND_FALCON_SECRET_KEY_SIZE];
static uint8_t public_key[QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE];
static uint8_t signature[QGP_ALGORAND_FALCON_SIGNATURE_MAX_SIZE];
static size_t signature_length;
static void wipe(uint8_t *p, size_t n) { volatile uint8_t *v=p; while(n--) *v++=0; }
uint8_t *algo_seed(void) { return seed; }
uint8_t *algo_message(void) { return message; }
uint8_t *algo_public_key(void) { return public_key; }
uint8_t *algo_signature(void) { return signature; }
int algo_signature_length(void) { return (int)signature_length; }
void algo_clear(void) {
    wipe(seed,sizeof seed); wipe(message,sizeof message); wipe(secret,sizeof secret);
    wipe(public_key,sizeof public_key); wipe(signature,sizeof signature); signature_length=0;
}
int algo_sign(int length) {
    int result=-1;
    wipe(public_key,sizeof public_key); wipe(signature,sizeof signature); signature_length=0;
    if(length < 1 || (size_t)length > sizeof message) goto cleanup;
    result=qgp_algorand_falcon_keypair_from_seed(public_key,sizeof public_key,
        secret,sizeof secret,seed,sizeof seed);
    if(result) goto cleanup;
    result=qgp_algorand_falcon_sign(signature,sizeof signature,&signature_length,
        message,(size_t)length,secret,sizeof secret);
    if(!result) result=qgp_algorand_falcon_verify(signature,signature_length,
        message,(size_t)length,public_key,sizeof public_key);
cleanup:
    wipe(seed,sizeof seed); wipe(message,sizeof message); wipe(secret,sizeof secret);
    if(result) { wipe(public_key,sizeof public_key); wipe(signature,sizeof signature); signature_length=0; }
    return result;
}
