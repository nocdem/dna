#ifndef KYBER_DETERMINISTIC_H
#define KYBER_DETERMINISTIC_H

#include <stdint.h>
#include <stddef.h>

// Deterministic Kyber512 keypair generation from seed
// seed must be 32 bytes
int crypto_kem_keypair_derand(unsigned char *pk, unsigned char *sk, const uint8_t *seed);

#endif // KYBER_DETERMINISTIC_H
