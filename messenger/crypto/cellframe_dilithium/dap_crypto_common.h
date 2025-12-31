#ifndef DAP_CRYPTO_COMMON_H
#define DAP_CRYPTO_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Type definitions
typedef unsigned char byte_t;

// DAP memory allocation macros - simplified wrappers
#define DAP_NEW_Z(type) ((type*)calloc(1, sizeof(type)))
#define DAP_NEW_Z_SIZE(type, size) ((type*)calloc(1, (size)))
#define DAP_DEL_Z(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)
#define DAP_DEL_MULTY(...) do { \
    void *_ptrs[] = {__VA_ARGS__}; \
    for (size_t _i = 0; _i < sizeof(_ptrs)/sizeof(void*); _i++) { \
        if (_ptrs[_i]) free(_ptrs[_i]); \
    } \
} while(0)

// DAP utility macros - compatibility layer for Cellframe framework
#define dap_return_if_pass(cond) do { if (cond) return; } while(0)

// External dependencies - provided by OpenSSL and qgp_random
void SHA3_256(unsigned char *output, const unsigned char *input, size_t len);
void randombytes(unsigned char *out, size_t len);

#endif /* DAP_CRYPTO_COMMON_H */
