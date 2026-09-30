/**
 * @file fuzz_wasm_platform.c
 * @brief qgp_platform_random / qgp_secure_memzero for the wasm32 FUZZ build.
 *
 * TEST CODE ONLY — linked into the wasm32 fuzz programs built by
 * build_wasm32.sh (nodus and messenger), never into anything shipped.
 *
 * The shared sources call qgp_platform_random and qgp_secure_memzero
 * (declared in shared/crypto/utils/qgp_platform.h:35 and :152); their real
 * definitions live in qgp_platform_<os>.c, which the wasm32 fuzz build does
 * not link — the same situation, and the same two symbols, as the web
 * wallet's module (web-wallet/crypto/nodus-send-wasm.c:132-165). The
 * messenger build also needs qgp_platform_home_dir (qgp_platform.h:121).
 *
 * qgp_platform_random here is a deterministic xorshift64 stream with a fixed
 * start state, NOT a CSPRNG: a fuzz run must replay identically (the
 * project's determinism rule), and nothing a fuzz harness produces is a
 * secret. The decoders under test do not draw randomness at all; the draws
 * come from signing / encapsulation inside the harnesses that build their
 * own valid input (hedged ML-DSA rnd, KEM coins).
 */

#include <stdint.h>
#include <stddef.h>

#include "crypto/utils/qgp_platform.h"

static uint64_t g_fuzz_rng = 0x9E3779B97F4A7C15ull;

int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        uint64_t x = g_fuzz_rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        g_fuzz_rng = x;
        buf[i] = (uint8_t)(x >> 32);
    }
    return 0;
}

/* dna_context_new (messenger/dna_api.c:139) formats this into a keyring path
 * string; the decoders never open anything under it. A fixed value keeps the
 * run independent of the host's $HOME. */
const char *qgp_platform_home_dir(void) {
    return "/fuzz-home";
}

void qgp_secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    if (!p) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}
