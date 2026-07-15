/**
 * @file conf_txbind.c
 * @brief tx_binding for the confidential sandbox — rejection map + tx-bound root.
 *
 * See conf_txbind.h. The byte→Goldilocks map mirrors the DNAC challenger
 * rejection convention (transcript.c:380-388); SHA3-512 via the grounded
 * keccak_ref; the fold reuses conf_root_air_fold_step.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_txbind.h"

#include <stdlib.h>
#include <string.h>

#include "conf_root_air.h"
#include "field_goldilocks.h"
#include "keccak_ref.h"

/* Domain separator, includes the trailing NUL (design v3.1 §1b). */
static const uint8_t SANDBOX_DOMAIN[] = {
    'D', 'N', 'A', 'C', '_', 'B', '1', '_', 'S', 'A',
    'N', 'D', 'B', 'O', 'X', '_', 'V', '3', '\0'};
#define SANDBOX_DOMAIN_LEN (sizeof(SANDBOX_DOMAIN)) /* 19 (incl. NUL) */

static uint64_t le_u64(const uint8_t *b) {
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
           ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) |
           ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) |
           ((uint64_t)b[7] << 56);
}

bool conf_txbind_map(const uint8_t sighash[CONF_TXBIND_SIGHASH_LEN],
                     uint64_t out[CONF_TXBIND_LANES]) {
    size_t n = 0;
    for (size_t g = 0; g < CONF_TXBIND_SIGHASH_LEN / 8 && n < CONF_TXBIND_LANES; g++) {
        uint64_t u = le_u64(sighash + g * 8);
        if (u < GOLDILOCKS_P) out[n++] = u; /* accept canonical; else skip */
    }
    return n == CONF_TXBIND_LANES; /* fail-close if < 4 accepted */
}

void conf_txbind_sandbox_sighash(const uint8_t *ctx, size_t ctx_len,
                                 uint8_t out[CONF_TXBIND_SIGHASH_LEN]) {
    uint8_t *buf = (uint8_t *)malloc(SANDBOX_DOMAIN_LEN + ctx_len);
    if (!buf) { /* fail-close: zero the output */
        memset(out, 0, CONF_TXBIND_SIGHASH_LEN);
        return;
    }
    memcpy(buf, SANDBOX_DOMAIN, SANDBOX_DOMAIN_LEN);
    if (ctx_len) memcpy(buf + SANDBOX_DOMAIN_LEN, ctx, ctx_len);
    keccak_ref_sha3_512(buf, SANDBOX_DOMAIN_LEN + ctx_len, out);
    free(buf);
}

void conf_txbind_bound_root(const uint64_t commitment_root[CONF_TXBIND_LANES],
                            const uint64_t tx_binding[CONF_TXBIND_LANES],
                            uint64_t out[CONF_TXBIND_LANES]) {
    conf_root_air_fold_step(commitment_root, tx_binding, out);
}
