/*
 * QGP Random Number Generation (Cross-Platform)
 *
 * Implementation of cryptographically secure random number generation
 * using platform abstraction layer.
 *
 * Platform-specific implementations:
 * - Linux: getrandom() syscall or /dev/urandom
 * - Windows: BCryptGenRandom() (CNG API)
 */

#include "qgp_random.h"
#include "qgp_platform.h"
#include <stdio.h>

/**
 * Generate cryptographically secure random bytes
 *
 * This function delegates to platform-specific implementation:
 * - Linux: qgp_platform_random() uses getrandom() or /dev/urandom
 * - Windows: qgp_platform_random() uses BCryptGenRandom()
 *
 * Security: Both implementations provide cryptographically secure randomness
 * suitable for key generation and cryptographic operations.
 */
int qgp_randombytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

    return qgp_platform_random(buf, len);
}
