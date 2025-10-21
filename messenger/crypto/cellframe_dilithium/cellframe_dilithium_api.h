#ifndef CELLFRAME_DILITHIUM_API_H
#define CELLFRAME_DILITHIUM_API_H

#include <stddef.h>
#include <stdint.h>

// MODE_1 (Cellframe default: K=4, L=3 - DILITHIUM_MAX_SPEED)
#define pqcrystals_cellframe_dilithium_PUBLICKEYBYTES 1184
#define pqcrystals_cellframe_dilithium_SECRETKEYBYTES 2800
#define pqcrystals_cellframe_dilithium_BYTES 2044

// Simple wrapper API matching pqcrystals interface
int pqcrystals_cellframe_dilithium_signature(uint8_t *sig, size_t *siglen,
                                              const uint8_t *m, size_t mlen,
                                              const uint8_t *ctx, size_t ctxlen,
                                              const uint8_t *sk);

int pqcrystals_cellframe_dilithium_verify(const uint8_t *sig, size_t siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *ctx, size_t ctxlen,
                                           const uint8_t *pk);

#endif /* CELLFRAME_DILITHIUM_API_H */
