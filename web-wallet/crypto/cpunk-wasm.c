// Browser bridge only. Key generation implementation is the unmodified repository C.
#include "dilithium_params.h"
#include "fips202.h"
static unsigned char input[32], output[1184];
void SHA3_256(unsigned char *out, const unsigned char *in, size_t len) { sha3_256(out, in, len); }
void randombytes(unsigned char *out, size_t len) { (void)out; (void)len; abort(); } // Seed is mandatory.
unsigned char *cpunk_input(void) { return input; }
unsigned char *cpunk_output(void) { return output; }
int cpunk_derive(void) {
    dilithium_public_key_t pk = {0}; dilithium_private_key_t sk = {0};
    int result = dilithium_crypto_sign_keypair(&pk, &sk, MODE_1, input, 32);
    if (!result && pk.kind == MODE_1) memcpy(output, pk.data, 1184); else result = -1;
    if (sk.data) { volatile unsigned char *p = sk.data; for (int i=0;i<2800;i++) p[i]=0; }
    dilithium_private_key_delete(&sk); dilithium_public_key_delete(&pk);
    memset(input, 0, sizeof(input)); return result;
}
