/*
 * QGP Random Number Generation
 *
 * Cryptographically secure random number generation for QGP.
 * Uses getrandom() syscall (Linux 3.17+) with /dev/urandom fallback.
 */

#ifndef QGP_RANDOM_H
#define QGP_RANDOM_H

#include <stdint.h>
#include <stddef.h>

/**
 * Generate cryptographically secure random bytes
 *
 * @param buf Output buffer for random bytes
 * @param len Number of random bytes to generate
 * @return 0 on success, -1 on error
 *
 * Uses getrandom() syscall if available (Linux 3.17+),
 * falls back to /dev/urandom otherwise.
 */
int qgp_randombytes(uint8_t *buf, size_t len);

#endif /* QGP_RANDOM_H */
