/**
 * @file fuzz_dht_stub.c
 * @brief Test doubles for the nodus_ops read/write seam (see fuzz_dht_stub.h).
 *
 * Signatures are the ones declared in messenger/dht/shared/nodus_ops.h
 * (nodus_ops_put_str :76, nodus_ops_put_str_exclusive :98,
 * nodus_ops_get_str :116, nodus_ops_get_all_str :140, nodus_ops_value_id
 * :266); the header is included so the compiler checks them.
 */

#include "fuzz_dht_stub.h"

#include <stdlib.h>
#include <string.h>

#include "dht/shared/nodus_ops.h"

static uint8_t *g_values[FUZZ_DHT_STUB_MAX_VALUES];
static size_t   g_lens[FUZZ_DHT_STUB_MAX_VALUES];
static size_t   g_count;

static uint8_t *g_put;
static size_t   g_put_len;

void fuzz_dht_stub_reset(void) {
    for (size_t i = 0; i < g_count; i++) {
        free(g_values[i]);
        g_values[i] = NULL;
        g_lens[i] = 0;
    }
    g_count = 0;
    free(g_put);
    g_put = NULL;
    g_put_len = 0;
}

void fuzz_dht_stub_load(const uint8_t *const *values, const size_t *lens, size_t count) {
    fuzz_dht_stub_reset();
    if (count > FUZZ_DHT_STUB_MAX_VALUES) {
        count = FUZZ_DHT_STUB_MAX_VALUES;
    }
    for (size_t i = 0; i < count; i++) {
        /* exact-size heap copy so ASan sees the real bound of each value */
        g_values[i] = malloc(lens[i] ? lens[i] : 1);
        if (!g_values[i]) {
            break;
        }
        if (lens[i]) {
            memcpy(g_values[i], values[i], lens[i]);
        }
        g_lens[i] = lens[i];
        g_count = i + 1;
    }
}

const uint8_t *fuzz_dht_stub_last_put(size_t *len_out) {
    if (len_out) {
        *len_out = g_put_len;
    }
    return g_put;
}

static int capture_put(const uint8_t *data, size_t data_len) {
    free(g_put);
    g_put = malloc(data_len ? data_len : 1);
    if (!g_put) {
        g_put_len = 0;
        return -1;
    }
    if (data_len) {
        memcpy(g_put, data, data_len);
    }
    g_put_len = data_len;
    return 0;
}

int nodus_ops_put_str(const char *str_key,
                      const uint8_t *data, size_t data_len,
                      uint32_t ttl, uint64_t vid) {
    (void)str_key;
    (void)ttl;
    (void)vid;
    return capture_put(data, data_len);
}

int nodus_ops_put_str_exclusive(const char *str_key,
                                const uint8_t *data, size_t data_len,
                                uint64_t vid) {
    (void)str_key;
    (void)vid;
    return capture_put(data, data_len);
}

int nodus_ops_get_str(const char *str_key,
                      uint8_t **data_out, size_t *len_out) {
    (void)str_key;
    if (!data_out || !len_out || g_count == 0) {
        return -1;
    }
    uint8_t *copy = malloc(g_lens[0] ? g_lens[0] : 1);
    if (!copy) {
        return -1;
    }
    if (g_lens[0]) {
        memcpy(copy, g_values[0], g_lens[0]);
    }
    *data_out = copy;
    *len_out = g_lens[0];
    return 0;
}

int nodus_ops_get_all_str(const char *str_key,
                          uint8_t ***values_out, size_t **lens_out,
                          size_t *count_out) {
    (void)str_key;
    if (!values_out || !lens_out || !count_out) {
        return -1;
    }
    *values_out = NULL;
    *lens_out = NULL;
    *count_out = 0;
    if (g_count == 0) {
        return 0;
    }
    uint8_t **vals = calloc(g_count, sizeof(uint8_t *));
    size_t *lens = calloc(g_count, sizeof(size_t));
    if (!vals || !lens) {
        free(vals);
        free(lens);
        return -1;
    }
    for (size_t i = 0; i < g_count; i++) {
        vals[i] = malloc(g_lens[i] ? g_lens[i] : 1);
        if (!vals[i]) {
            for (size_t j = 0; j < i; j++) {
                free(vals[j]);
            }
            free(vals);
            free(lens);
            return -1;
        }
        if (g_lens[i]) {
            memcpy(vals[i], g_values[i], g_lens[i]);
        }
        lens[i] = g_lens[i];
    }
    *values_out = vals;
    *lens_out = lens;
    *count_out = g_count;
    return 0;
}

uint64_t nodus_ops_value_id(void) {
    return 1;
}
