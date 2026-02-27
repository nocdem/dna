#ifndef DNA_CRYPTO_COMMON_H
#define DNA_CRYPTO_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Type definitions
typedef unsigned char byte_t;

// DNA memory allocation macros
#define DNA_NEW_Z(type) ((type*)calloc(1, sizeof(type)))
#define DNA_NEW_Z_SIZE(type, size) ((type*)calloc(1, (size)))
#define DNA_DEL_Z(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

// DNA utility macros
#define DNA_RETURN_IF_NULL(ptr) do { if (!(ptr)) return; } while(0)

// External dependencies - provided by OpenSSL and qgp_random
void SHA3_256(unsigned char *output, const unsigned char *input, size_t len);
void randombytes(unsigned char *out, size_t len);

#endif /* DNA_CRYPTO_COMMON_H */
