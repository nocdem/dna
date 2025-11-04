#ifndef QGP_KYBER_H
#define QGP_KYBER_H

#include <stdint.h>
#include <stddef.h>

/**
 * Kyber1024 Key Encapsulation Mechanism (KEM)
 *
 * NIST FIPS 203 (ML-KEM-1024) implementation
 * Reference: pq-crystals/kyber
 * Security level: NIST Level 5 / Category 5 (256-bit post-quantum security)
 */

#define QGP_KYBER512_PUBLICKEYBYTES  1568
#define QGP_KYBER512_SECRETKEYBYTES  3168
#define QGP_KYBER512_CIPHERTEXTBYTES 1568
#define QGP_KYBER512_BYTES           32

/**
 * Generate Kyber1024 keypair
 *
 * @param pk Output public key (1568 bytes)
 * @param sk Output secret key (3168 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kyber512_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Encapsulation: Generate shared secret and ciphertext
 *
 * @param ct Output ciphertext (1568 bytes)
 * @param ss Output shared secret (32 bytes)
 * @param pk Input public key (1568 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * Decapsulation: Recover shared secret from ciphertext
 *
 * @param ss Output shared secret (32 bytes)
 * @param ct Input ciphertext (1568 bytes)
 * @param sk Input secret key (3168 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* QGP_KYBER_H */
