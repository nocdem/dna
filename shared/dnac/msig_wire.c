/**
 * @file shared/dnac/msig_wire.c
 * @brief General multisig descriptor codec + address (contract:
 *        msig_wire.h; decision 2026-09-29-general-multisig.md; design
 *        §7 rev 2).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "msig_wire.h"

#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/** "DNA.MSIG.v1" (11 chars) + 5 zero bytes — collision-scanned against
 *  the "DNA.*" tag namespace of this tree at introduction (no other tag
 *  spells it). */
static const uint8_t TAG_MSIG[DNA_MSIG_TAG_LEN] = {
    'D','N','A','.','M','S','I','G','.','v','1', 0, 0, 0, 0, 0
};

_Static_assert(DNA_MSIG_MAX_DESC_LEN == 18162u,
               "maximal descriptor length drifted (18 + 7 x 2592)");
_Static_assert(DNA_MSIG_MAX_DESC_LEN <= 0xFFFFu,
               "a maximal descriptor no longer fits the u16 dlen field");

/* The zero-key rule: first 32 bytes all zero marks a null key — the
 * auth_kind-1 signer discipline (nodus_witness_rt_native.c
 * rtn_auth_submitters, citing verify.c:657). Design §7 pins descriptor
 * keys to the SAME rule. */
static int msig_zero_key(const uint8_t *pk) {
    for (int k = 0; k < 32; k++)
        if (pk[k] != 0) return 0;
    return 1;
}

/* Shared shape rule over (m, n, keys): bounds, zero key, strict order. */
static int msig_keys_ok(uint8_t m, uint8_t n, const uint8_t *keys) {
    if (n < DNA_MSIG_MIN_N || n > DNA_MSIG_MAX_N) return -1;
    if (m < 1 || m > n) return -1;
    for (uint8_t i = 0; i < n; i++) {
        const uint8_t *pk = keys + (size_t)i * DNA_MSIG_PUBKEY_LEN;
        if (msig_zero_key(pk)) return -1;
        if (i > 0 && memcmp(pk - DNA_MSIG_PUBKEY_LEN, pk,
                            DNA_MSIG_PUBKEY_LEN) >= 0)
            return -1;                   /* duplicate or disorder        */
    }
    return 0;
}

int dna_msig_desc_encode(uint8_t m, uint8_t n, const uint8_t *pubkeys,
                         uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!pubkeys || !out || !out_len) return -1;
    if (msig_keys_ok(m, n, pubkeys) != 0) return -1;
    size_t need = DNA_MSIG_DESC_LEN(n);
    if (out_cap < need) return -1;
    memcpy(out, TAG_MSIG, DNA_MSIG_TAG_LEN);
    out[DNA_MSIG_TAG_LEN]      = m;
    out[DNA_MSIG_TAG_LEN + 1u] = n;
    memcpy(out + DNA_MSIG_HDR_LEN, pubkeys, (size_t)n * DNA_MSIG_PUBKEY_LEN);
    *out_len = need;
    return 0;
}

int dna_msig_desc_parse(const uint8_t *d, size_t len, uint8_t *m_out,
                        uint8_t *n_out, const uint8_t **keys_out) {
    if (!d || len < DNA_MSIG_HDR_LEN) return -1;
    if (memcmp(d, TAG_MSIG, DNA_MSIG_TAG_LEN) != 0) return -1;
    uint8_t m = d[DNA_MSIG_TAG_LEN];
    uint8_t n = d[DNA_MSIG_TAG_LEN + 1u];
    if (n < DNA_MSIG_MIN_N || n > DNA_MSIG_MAX_N) return -1;
    if (len != DNA_MSIG_DESC_LEN(n)) return -1;   /* exact, no trailing  */
    if (msig_keys_ok(m, n, d + DNA_MSIG_HDR_LEN) != 0) return -1;
    if (m_out) *m_out = m;
    if (n_out) *n_out = n;
    if (keys_out) *keys_out = d + DNA_MSIG_HDR_LEN;
    return 0;
}

int dna_msig_address(const uint8_t *d, size_t len,
                     uint8_t out[DNA_MSIG_ADDR_LEN]) {
    if (!out) return -1;
    if (dna_msig_desc_parse(d, len, NULL, NULL, NULL) != 0) return -1;
    return qgp_sha3_512(d, len, out) == 0 ? 0 : -2;
}
