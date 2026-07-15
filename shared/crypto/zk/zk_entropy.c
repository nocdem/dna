/**
 * @file zk_entropy.c
 * @brief Production draw-stream filler — see zk_entropy.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "zk_entropy.h"

#include <errno.h>
#include <stdio.h>

#include "field_goldilocks.h"

#if defined(__linux__)
#include <sys/random.h>
#endif

/* OS entropy into buf[0..len). Mirrors the semantics of the shared
 * qgp_platform_random (shared/crypto/utils/qgp_platform_linux.c:28-73) —
 * getrandom(2) with flags=0 (blocks only until the pool is first
 * initialized; no EAGAIN), EINTR retry, partial-read loop, /dev/urandom
 * fallback on ENOSYS — but kept dependency-free so the parked, standalone zk
 * Makefile does not pull in the platform logging chain. Returns 0 / -1. */
static int zk_os_random(uint8_t *buf, size_t len) {
    size_t done = 0;
#if defined(__linux__)
    while (done < len) {
        ssize_t r = getrandom(buf + done, len - done, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break; /* ENOSYS or other -> fall through to /dev/urandom */
        }
        done += (size_t)r;
    }
    if (done == len) return 0;
#endif
    /* fallback: /dev/urandom */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) return -1;
    size_t got = fread(buf + done, 1, len - done, f);
    fclose(f);
    return (done + got == len) ? 0 : -1;
}

int dnac_zk_fill_draws(uint64_t *out, size_t n) {
    if (out == NULL && n > 0) return -1;
    for (size_t i = 0; i < n;) {
        uint8_t b[8];
        if (zk_os_random(b, sizeof b) != 0) {
            return -1; /* fail-close: never zero-fill / partial-fill */
        }
        /* little-endian decode (byte-order is distribution-irrelevant for
         * uniform bytes; LE matches the challenger convention). */
        uint64_t v = 0;
        for (int k = 7; k >= 0; k--) v = (v << 8) | b[k];
        /* rejection sampling — accept iff canonical (goldilocks.rs:184-193);
         * reduce-mod-p FORBIDDEN. */
        if (v < GOLDILOCKS_P) {
            out[i++] = v;
        }
    }
    return 0;
}
