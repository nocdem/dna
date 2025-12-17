/**
 * @file fuzz_common.h
 * @brief Common utilities for libFuzzer harnesses
 *
 * Provides deterministic fake key generation for fuzz testing.
 * These keys are NOT cryptographically valid - they're just
 * deterministic byte sequences for coverage testing.
 */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stdint.h>
#include <stddef.h>

/* Key sizes from the crypto library */
#define FUZZ_KYBER1024_PRIVKEY_SIZE 3168
#define FUZZ_KYBER1024_PUBKEY_SIZE 1568
#define FUZZ_DILITHIUM5_PRIVKEY_SIZE 4896
#define FUZZ_DILITHIUM5_PUBKEY_SIZE 2592
#define FUZZ_FINGERPRINT_SIZE 64

/**
 * Generate a deterministic fake Kyber1024 private key
 * NOT cryptographically valid - for fuzzing only
 *
 * @param key Output buffer (3168 bytes)
 * @param seed Seed for deterministic generation
 */
void fuzz_generate_fake_kyber_privkey(uint8_t *key, size_t seed);

/**
 * Generate a deterministic fake Dilithium5 private key
 * NOT cryptographically valid - for fuzzing only
 *
 * @param key Output buffer (4896 bytes)
 * @param seed Seed for deterministic generation
 */
void fuzz_generate_fake_dilithium_privkey(uint8_t *key, size_t seed);

/**
 * Generate a deterministic fake fingerprint (binary)
 * NOT a real SHA3-512 hash - for fuzzing only
 *
 * @param fp Output buffer (64 bytes)
 * @param seed Seed for deterministic generation
 */
void fuzz_generate_fake_fingerprint(uint8_t *fp, size_t seed);

/**
 * Generate a deterministic fake fingerprint (hex string)
 * NOT a real SHA3-512 hash - for fuzzing only
 *
 * @param fp Output buffer (129 bytes, null-terminated)
 * @param seed Seed for deterministic generation
 */
void fuzz_generate_fake_fingerprint_hex(char *fp, size_t seed);

#endif /* FUZZ_COMMON_H */
