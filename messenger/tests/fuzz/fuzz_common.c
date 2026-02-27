/**
 * @file fuzz_common.c
 * @brief Common utilities for libFuzzer harnesses
 */

#include "fuzz_common.h"
#include <string.h>
#include <stdio.h>

void fuzz_generate_fake_kyber_privkey(uint8_t *key, size_t seed) {
    for (size_t i = 0; i < FUZZ_KYBER1024_PRIVKEY_SIZE; i++) {
        key[i] = (uint8_t)((seed + i * 7) & 0xFF);
    }
}

void fuzz_generate_fake_dilithium_privkey(uint8_t *key, size_t seed) {
    for (size_t i = 0; i < FUZZ_DILITHIUM5_PRIVKEY_SIZE; i++) {
        key[i] = (uint8_t)((seed + i * 13) & 0xFF);
    }
}

void fuzz_generate_fake_fingerprint(uint8_t *fp, size_t seed) {
    for (size_t i = 0; i < FUZZ_FINGERPRINT_SIZE; i++) {
        fp[i] = (uint8_t)((seed + i * 3) & 0xFF);
    }
}

void fuzz_generate_fake_fingerprint_hex(char *fp, size_t seed) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 128; i++) {
        fp[i] = hex[(seed + i) & 0x0F];
    }
    fp[128] = '\0';
}
