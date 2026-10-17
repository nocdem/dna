#ifndef DILITHIUM_SECURE_CLEAR_H
#define DILITHIUM_SECURE_CLEAR_H

#include <stddef.h>

/* Volatile stores keep cleanup observable to the compiler. Header-only so
 * the native library and the standalone, import-free WASM builds share it.
 * Clears named memory buffers; does not promise erasure of register spills. */
static inline void dilithium_secure_clear(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while(len--)
    *p++ = 0;
}

#endif
