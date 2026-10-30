/* Test-only, bounded binary fixture reader. Never part of a production library. */
#ifndef PQ_TEST_VECTOR_IO_H
#define PQ_TEST_VECTOR_IO_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); \
} } while (0)
enum { SEED, MESSAGE, CONTEXT, PK, SK, SIGNATURE, RANDOM, AUX, FIELD_COUNT };
enum { KEYGEN = 1, SIGN = 2, VALID = 4, CT = 8, EXTERNAL = 16 };
typedef struct { uint8_t *p; size_t n; } blob;
typedef struct { uint32_t scheme, param, id, flags; blob f[FIELD_COUNT]; } vector;

static inline uint32_t read32(FILE *f) {
    uint8_t b[4]; CHECK(fread(b, 1, 4, f) == 4);
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 |
           (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static inline void read_vector(FILE *f, vector *v) {
    v->scheme = read32(f); v->param = read32(f);
    v->id = read32(f); v->flags = read32(f);
    for (unsigned i = 0; i < FIELD_COUNT; i++) {
        v->f[i].n = read32(f);
        CHECK(v->f[i].n <= 1024 * 1024);
        v->f[i].p = calloc(v->f[i].n + 1, 1);
        CHECK(v->f[i].p != NULL);
        CHECK(fread(v->f[i].p, 1, v->f[i].n, f) == v->f[i].n);
    }
}
static inline void free_vector(vector *v) {
    for (unsigned i = 0; i < FIELD_COUNT; i++) free(v->f[i].p);
}
static inline void write32(FILE *f, uint32_t n) {
    uint8_t b[4] = {n, n >> 8, n >> 16, n >> 24};
    CHECK(fwrite(b, 1, 4, f) == 4);
}
static inline void write_blob(FILE *f, const void *p, size_t n) {
    CHECK(n <= UINT32_MAX); write32(f, (uint32_t)n);
    if (n) CHECK(fwrite(p, 1, n, f) == n);
}
#endif
