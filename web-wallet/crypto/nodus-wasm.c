/* Browser bridge to the unchanged native ML-DSA-87 implementation.
 * Reference: shared/crypto/sign/qgp_dilithium.c at b9a1a813a46223cf5ff0226d461721f35bbfae17.
 * Only the public key leaves this module. No signing or random key generation.
 */
#include "crypto/sign/qgp_dilithium.h"

static unsigned char input[32];
static unsigned char output[QGP_DSA87_PUBLICKEYBYTES];
static unsigned char secret[QGP_DSA87_SECRETKEYBYTES];

static void wipe(unsigned char *data, unsigned long size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}

unsigned char *nodus_input(void) { return input; }
unsigned char *nodus_output(void) { return output; }
int nodus_derive(void) {
    int result = qgp_dsa87_keypair_derand(output, secret, input);
    wipe(input, sizeof(input));
    wipe(secret, sizeof(secret));
    if (result) wipe(output, sizeof(output));
    return result;
}
