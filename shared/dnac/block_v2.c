/**
 * @file shared/dnac/block_v2.c
 * @brief Ledger V2 Season 2 — BlockHeader V2 codec implementation.
 *
 * INACTIVE — see block_v2.h for the byte layout and BlockID preimages.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "block_v2.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* 16-byte zero-padded tag: "DNA.BLOCK.v3" (12) + 4 zeros incl. impl. NUL.
 * DISTINCT from the retired "DNA.BLOCK.v2" tag — cross-version domain
 * separation, verified repo-wide against every other DNA.* tag. */
static const uint8_t TAG_BLOCK[16] = "DNA.BLOCK.v3\0\0\0";

_Static_assert(DNA_BH2_ENC_SIZE ==
               1 + 32 + 8 + 8 + 64 + 64 + 64 + 64 + 64 + 4 + 32 + 8,
               "header v3 size drift");
_Static_assert(DNA_BH2_BOUND_SIZE == DNA_BH2_ENC_SIZE - 8,
               "bound size = encoded minus timestamp");
_Static_assert(DNA_BH2_VERSION != DNA_BH2_VERSION_RETIRED,
               "current and retired header versions must differ");

static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static uint32_t get_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] << 8)  |  (uint32_t)in[3];
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint64_t get_be64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)in[i];
    return v;
}

/* Serialize the 405 BlockID-bound bytes (offsets [0,405): everything except
 * the trailing timestamp). Shared by encode and both BlockID paths so the
 * wire form and the preimage can never drift. */
static int bh2_put_bound(const dna_block_header_v2_t *h,
                         uint8_t out[DNA_BH2_BOUND_SIZE]) {
    if (h->header_version != DNA_BH2_VERSION) return -1;
    out[0] = h->header_version;
    memcpy(out + 1, h->chain_id, 32);
    put_be64(h->block_height, out + 33);
    put_be64(h->epoch, out + 41);
    memcpy(out + 49,  h->prev_block_id,       64);
    memcpy(out + 113, h->global_state_root,   64);
    memcpy(out + 177, h->tx_root,             64);
    memcpy(out + 241, h->domain_updates_root, 64);
    memcpy(out + 305, h->validator_set_hash,  64);
    put_be32(h->tx_count, out + 369);
    memcpy(out + 373, h->proposer_id, 32);
    return 0;
}

int dna_bh2_encode(const dna_block_header_v2_t *h,
                   uint8_t out[DNA_BH2_ENC_SIZE]) {
    if (!h || !out) return -1;
    if (bh2_put_bound(h, out) != 0) return -1;
    put_be64(h->timestamp, out + DNA_BH2_BOUND_SIZE);
    return 0;
}

int dna_bh2_decode(const uint8_t *src, size_t src_len,
                   dna_block_header_v2_t *out) {
    if (!src || !out) return -1;
    if (src_len != (size_t)DNA_BH2_ENC_SIZE) return -1;  /* strict: rejects
                                                          * truncation AND
                                                          * trailing bytes */
    /* Fail closed on BOTH the retired version and any unknown version.
     * They are one branch here but two distinct test classes: a retired
     * version must never be reinterpreted under the new layout, and an
     * unknown version must never be guessed at. */
    if (src[0] != DNA_BH2_VERSION) return -1;
    memset(out, 0, sizeof(*out));
    out->header_version = src[0];
    memcpy(out->chain_id, src + 1, 32);
    out->block_height = get_be64(src + 33);
    out->epoch        = get_be64(src + 41);
    memcpy(out->prev_block_id,       src + 49,  64);
    memcpy(out->global_state_root,   src + 113, 64);
    memcpy(out->tx_root,             src + 177, 64);
    memcpy(out->domain_updates_root, src + 241, 64);
    memcpy(out->validator_set_hash,  src + 305, 64);
    out->tx_count = get_be32(src + 369);
    memcpy(out->proposer_id, src + 373, 32);
    out->timestamp = get_be64(src + DNA_BH2_BOUND_SIZE);
    return 0;
}

int dna_bh2_block_id(const dna_block_header_v2_t *h,
                     uint8_t out[DNA_BH2_ID_LEN]) {
    if (!h || !out) return -1;
    uint8_t pre[16 + DNA_BH2_BOUND_SIZE];
    memcpy(pre, TAG_BLOCK, 16);
    if (bh2_put_bound(h, pre + 16) != 0) return -1;
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_bh2_genesis_block_id(const dna_block_header_v2_t *h,
                             const uint8_t *manifest_bytes,
                             size_t manifest_len,
                             uint8_t out[DNA_BH2_ID_LEN]) {
    if (!h || !manifest_bytes || !out) return -1;
    if (manifest_len == 0 || manifest_len > (size_t)DNA_BH2_MANIFEST_MAX)
        return -1;
    /* Explicit genesis semantics, matching the SOURCE rules the engine
     * enforces on the stored row, so the hashed header and the row can
     * never disagree:
     *   height 0                    — the definition of genesis
     *   chain_id all-zero           — the id does not exist yet; zeroing it
     *                                 in the preimage breaks the circularity
     *   epoch 0                     — nodus_v2_epoch_for_height(0) == 0
     *                                 (nodus_witness_v2_apply.c:480 rejects
     *                                 any other caller value)
     *   prev_block_id all-zero      — genesis has no parent; the engine
     *                                 binds zero64 (apply.c:592-595)
     * Without the last two, two implementations could derive DIFFERENT
     * genesis BlockIDs — and therefore different chain ids — from the
     * "same" genesis. proposer_id is deliberately NOT constrained: the
     * engine stores no proposer for genesis, so it carries no source rule. */
    if (h->block_height != 0) return -1;
    if (h->epoch != 0) return -1;
    static const uint8_t zero32[32] = { 0 };
    static const uint8_t zero64[DNA_BH2_ID_LEN] = { 0 };
    if (memcmp(h->chain_id, zero32, 32) != 0) return -1;
    if (memcmp(h->prev_block_id, zero64, DNA_BH2_ID_LEN) != 0) return -1;

    /* Preimage: tag ‖ bound bytes (chain_id region all-zero) ‖ manifest.
     * Fixed-size stack prefix + the caller's manifest streamed after it. */
    size_t pre_len = 16 + (size_t)DNA_BH2_BOUND_SIZE + manifest_len;
    uint8_t fixed[16 + DNA_BH2_BOUND_SIZE];
    memcpy(fixed, TAG_BLOCK, 16);
    if (bh2_put_bound(h, fixed + 16) != 0) return -1;

    /* One-shot hash over a heap buffer (manifest is caller-bounded). */
    uint8_t *pre = (uint8_t *)malloc(pre_len);
    if (!pre) return -1;
    memcpy(pre, fixed, sizeof(fixed));
    memcpy(pre + sizeof(fixed), manifest_bytes, manifest_len);
    int rc = qgp_sha3_512(pre, pre_len, out);
    memset(pre, 0, pre_len);
    free(pre);
    return rc == 0 ? 0 : -1;
}

int dna_bh2_derive_chain_id(const uint8_t genesis_block_id[DNA_BH2_ID_LEN],
                            uint8_t chain_id_out[DNA_CHAIN_ID_LEN]) {
    if (!genesis_block_id || !chain_id_out) return -1;
    memcpy(chain_id_out, genesis_block_id, DNA_CHAIN_ID_LEN);  /* FULL 32B */
    return 0;
}

int dna_bh2_check_chain(const dna_block_header_v2_t *h,
                        const uint8_t expected_chain_id[DNA_CHAIN_ID_LEN]) {
    if (!h || !expected_chain_id) return -1;
    return memcmp(h->chain_id, expected_chain_id, DNA_CHAIN_ID_LEN) == 0
               ? 0 : -1;
}
