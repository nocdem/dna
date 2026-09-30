/**
 * @file fuzz_driver.c
 * @brief Standalone driver for fuzz targets on toolchains without libFuzzer.
 *
 * Emscripten has no libFuzzer runtime, so the wasm32 build (32-bit size_t,
 * what the browser runs) links each LLVMFuzzerTestOneInput() harness with
 * this main() instead. It is also usable for a plain `-m32` native build.
 *
 * Usage:
 *   <target> [-mutate=N] [-seed=S] <file-or-dir>...
 *
 *   Every file argument, and every regular file directly inside a directory
 *   argument (names sorted with strcmp, so the order is the same on every
 *   host), is passed once to LLVMFuzzerTestOneInput(). With -mutate=N each
 *   input is additionally run N times with small mutations drawn from an
 *   xorshift64 generator seeded with S (default 1): same inputs + same N +
 *   same S = the same byte sequences, on every run and every host.
 *
 * This is replay plus a small, deterministic mutation pass — NOT coverage
 * guided. Coverage-guided search is the native libFuzzer build; this driver
 * exists to execute the same inputs (seeds, libFuzzer's crash files and
 * corpus) with 32-bit size_t and pointer arithmetic, under ASan where the
 * toolchain has it (emcc -fsanitize=address).
 *
 * Exit status: 0 when every input ran, 1 on a usage or I/O error. A memory
 * error aborts through the sanitizer, not through this exit status.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "FUZZ_DRIVER"

/* Largest input read from disk (matches libFuzzer's default -max_len scale
 * for these targets with a wide margin; a larger file is refused, not cut). */
#define FUZZ_DRIVER_MAX_INPUT (8u * 1024u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t g_rng_state = 1;

static uint64_t rng_next(void) {
    /* xorshift64 (Marsaglia 2003), state never 0 */
    uint64_t x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rng_state = x;
    return x;
}

/* 32-bit length values that sit on overflow edges of 32-bit size_t
 * arithmetic (len + header, offset + len) */
static const uint32_t k_edge_u32[] = {
    0x00000000u, 0x00000001u, 0x0000FFFFu, 0x00010000u,
    0x7FFFFFFFu, 0x80000000u, 0xFFFFFFF0u, 0xFFFFFFFFu
};

static void run_one(const uint8_t *data, size_t size) {
    /* Copy into an exact-size heap buffer so ASan sees the real bound */
    uint8_t *copy = malloc(size ? size : 1);
    if (!copy) {
        return;
    }
    if (size) {
        memcpy(copy, data, size);
    }
    LLVMFuzzerTestOneInput(copy, size);
    free(copy);
}

static void mutate_and_run(const uint8_t *data, size_t size, unsigned long rounds) {
    size_t cap = size + 8;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        return;
    }
    for (unsigned long r = 0; r < rounds; r++) {
        memcpy(buf, data, size);
        size_t len = size;
        uint64_t op = rng_next() % 5;
        if (op == 0 && len > 0) {                       /* flip one bit */
            size_t at = (size_t)(rng_next() % len);
            buf[at] ^= (uint8_t)(1u << (rng_next() % 8));
        } else if (op == 1 && len > 0) {                /* set one byte */
            size_t at = (size_t)(rng_next() % len);
            buf[at] = (uint8_t)rng_next();
        } else if (op == 2 && len >= 4) {               /* 32-bit edge value, big-endian */
            size_t at = (size_t)(rng_next() % (len - 3));
            uint32_t v = k_edge_u32[rng_next() % (sizeof(k_edge_u32) / sizeof(k_edge_u32[0]))];
            buf[at]     = (uint8_t)(v >> 24);
            buf[at + 1] = (uint8_t)(v >> 16);
            buf[at + 2] = (uint8_t)(v >> 8);
            buf[at + 3] = (uint8_t)v;
        } else if (op == 3 && len >= 4) {               /* 32-bit edge value, little-endian */
            size_t at = (size_t)(rng_next() % (len - 3));
            uint32_t v = k_edge_u32[rng_next() % (sizeof(k_edge_u32) / sizeof(k_edge_u32[0]))];
            buf[at]     = (uint8_t)v;
            buf[at + 1] = (uint8_t)(v >> 8);
            buf[at + 2] = (uint8_t)(v >> 16);
            buf[at + 3] = (uint8_t)(v >> 24);
        } else if (len > 0) {                           /* truncate */
            len = (size_t)(rng_next() % len);
        }
        run_one(buf, len);
    }
    free(buf);
}

static int run_file(const char *path, unsigned long rounds, unsigned long *count) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "cannot open %s", path);
        return -1;
    }
    uint8_t *data = malloc(FUZZ_DRIVER_MAX_INPUT);
    if (!data) {
        fclose(f);
        return -1;
    }
    size_t n = fread(data, 1, FUZZ_DRIVER_MAX_INPUT, f);
    int extra = fgetc(f);
    int err = ferror(f);
    fclose(f);
    if (err || extra != EOF) {
        QGP_LOG_ERROR(LOG_TAG, "%s: read error or larger than %u bytes", path,
                      (unsigned)FUZZ_DRIVER_MAX_INPUT);
        free(data);
        return -1;
    }
    run_one(data, n);
    (*count)++;
    if (rounds) {
        mutate_and_run(data, n, rounds);
        *count += rounds;
    }
    free(data);
    return 0;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int run_dir(const char *dir, unsigned long rounds, unsigned long *count) {
    DIR *d = opendir(dir);
    if (!d) {
        QGP_LOG_ERROR(LOG_TAG, "cannot open directory %s", dir);
        return -1;
    }
    size_t cap = 64, n = 0;
    char **names = malloc(cap * sizeof(char *));
    if (!names) {
        closedir(d);
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') {
            continue;   /* ".", "..", and dotfiles such as .gitkeep */
        }
        if (n == cap) {
            char **grown = realloc(names, cap * 2 * sizeof(char *));
            if (!grown) {
                break;
            }
            names = grown;
            cap *= 2;
        }
        names[n] = strdup(e->d_name);
        if (names[n]) {
            n++;
        }
    }
    closedir(d);
    qsort(names, n, sizeof(char *), cmp_str);

    int rc = 0;
    for (size_t i = 0; i < n; i++) {
        size_t plen = strlen(dir) + 1 + strlen(names[i]) + 1;
        char *path = malloc(plen);
        if (path) {
            snprintf(path, plen, "%s/%s", dir, names[i]);
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                if (run_file(path, rounds, count) != 0) {
                    rc = -1;
                }
            }
            free(path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

int main(int argc, char **argv) {
    unsigned long rounds = 0;
    int inputs = 0;
    int rc = 0;
    unsigned long count = 0;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-mutate=", 8) == 0) {
            rounds = strtoul(argv[i] + 8, NULL, 10);
        } else if (strncmp(argv[i], "-seed=", 6) == 0) {
            g_rng_state = strtoull(argv[i] + 6, NULL, 10);
            if (g_rng_state == 0) {
                g_rng_state = 1;
            }
        }
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            continue;
        }
        inputs++;
        struct stat st;
        if (stat(argv[i], &st) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "no such file or directory: %s", argv[i]);
            rc = 1;
        } else if (S_ISDIR(st.st_mode)) {
            if (run_dir(argv[i], rounds, &count) != 0) {
                rc = 1;
            }
        } else if (run_file(argv[i], rounds, &count) != 0) {
            rc = 1;
        }
    }

    if (inputs == 0) {
        QGP_LOG_ERROR(LOG_TAG, "usage: %s [-mutate=N] [-seed=S] <file-or-dir>...", argv[0]);
        return 1;
    }
    QGP_LOG_INFO(LOG_TAG, "executed %lu inputs (size_t is %u bits)", count,
                 (unsigned)(sizeof(size_t) * 8));
    return rc;
}
