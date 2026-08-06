/**
 * @file shared/dnac/pool_wire.c
 * @brief Ledger V2 Season 7 — canonical shielded-pool state commitments
 *        implementation. Contract, tag table and exact preimages:
 *        pool_wire.h.
 *
 * INACTIVE: no live consensus path calls anything here (S7 charter).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "pool_wire.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* All tags are EXACTLY 16 bytes, zero-padded ASCII (S2 rule). */
#define TAG_LEN 16
_Static_assert(TAG_LEN == DNA_POOL_TAG_LEN, "tag width mirror drifted");

static const uint8_t TAG_POOLCFG[TAG_LEN]  = "DNA.POOLCFG.v1\0";
static const uint8_t TAG_POOLLEAF[TAG_LEN] = "DNA.POOLLEAF.v1";
static const uint8_t TAG_POOLNODE[TAG_LEN] = "DNA.POOLNODE.v1";
static const uint8_t TAG_PNUL[TAG_LEN]     = "DNA.PNUL.v1\0\0\0\0";
static const uint8_t TAG_E_PNUL[TAG_LEN]   = "DNA.E.PNUL.v1\0\0";
static const uint8_t TAG_PHIST[TAG_LEN]    = "DNA.PHIST.v1\0\0\0";
static const uint8_t TAG_E_PHIST[TAG_LEN]  = "DNA.E.PHIST.v1\0";
/* The EMPTY pools_root tag is the frozen S2 "DNA.E.POOLS.v1" — reused
 * byte-identically so a zero-pool runtime reproduces every pre-S7 root.
 * Mirrored here (rather than calling dna_v2_empty_root) to keep this
 * translation unit self-contained; test_v2_pools pins the identity. */
static const uint8_t TAG_E_POOLS[TAG_LEN]  = "DNA.E.POOLS.v1\0";

static void put_be16(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8); out[1] = (uint8_t)v;
}
static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint64_t get_be64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
}

int dna_pool_lanes_canonical(const uint8_t b[DNA_POOL_NOTE_LEN]) {
    if (!b) return 0;
    for (int lane = 0; lane < 4; lane++)
        if (get_be64(b + lane * 8) >= DNA_POOL_FE_P) return 0;
    return 1;
}

/* ── Configuration hash ─────────────────────────────────────────────── */

int dna_pool_config_hash(const dna_pool_config_t *cfg,
                         uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!cfg || !out) return -1;
    if (cfg->asset_ref_len == 0 ||
        cfg->asset_ref_len > DNA_POOL_ASSETREF_MAX)
        return -1;
    if (cfg->history_limit == 0 || cfg->tree_depth == 0) return -1;

    uint8_t pre[DNA_POOL_CFG_PREIMAGE_FIXED_LEN + DNA_POOL_ASSETREF_MAX];
    size_t off = 0;
    memcpy(pre + off, TAG_POOLCFG, TAG_LEN);     off += TAG_LEN;
    put_be32(cfg->domain_id, pre + off);         off += 4;
    put_be32(cfg->pool_id, pre + off);           off += 4;
    put_be32(cfg->config_version, pre + off);    off += 4;
    pre[off++] = cfg->tree_depth;
    put_be32(cfg->history_limit, pre + off);     off += 4;
    put_be16(cfg->asset_ref_len, pre + off);     off += 2;
    /* fixed-part length proof: every field above, tag included */
    if (off != DNA_POOL_CFG_PREIMAGE_FIXED_LEN) return -1;
    memcpy(pre + off, cfg->asset_ref, cfg->asset_ref_len);
    off += cfg->asset_ref_len;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

/* ── Pool state leaf ────────────────────────────────────────────────── */

int dna_pool_leaf_hash(const dna_pool_leaf_t *leaf,
                       uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!leaf || !out) return -1;
    if (!dna_pool_lanes_canonical(leaf->note_root)) return -1;

    /* The COMPLETE hashed preimage is tag(16) + the 272-byte field
     * payload = 288 bytes — pinned at compile time and re-checked at
     * the final write offset below. */
    uint8_t pre[DNA_POOL_LEAF_PREIMAGE_LEN];
    _Static_assert(sizeof(pre) ==
                       TAG_LEN + 4 + 4 + 64 + 32 + 8 + 64 + 8 + 8 + 64 +
                           8 + 8,
                   "pool-leaf preimage length drifted");
    _Static_assert(DNA_POOL_LEAF_PAYLOAD_LEN == 272 &&
                       DNA_POOL_LEAF_PREIMAGE_LEN == 288,
                   "pool-leaf declared lengths drifted");
    size_t off = 0;
    memcpy(pre + off, TAG_POOLLEAF, TAG_LEN);            off += TAG_LEN;
    put_be32(leaf->domain_id, pre + off);                off += 4;
    put_be32(leaf->pool_id, pre + off);                  off += 4;
    memcpy(pre + off, leaf->config_hash, 64);            off += 64;
    memcpy(pre + off, leaf->note_root, 32);              off += 32;
    put_be64(leaf->note_count, pre + off);               off += 8;
    memcpy(pre + off, leaf->nul_root, 64);               off += 64;
    put_be64(leaf->nul_count, pre + off);                off += 8;
    put_be64(leaf->balance, pre + off);                  off += 8;
    memcpy(pre + off, leaf->hist_commit, 64);            off += 64;
    put_be64(leaf->hist_count, pre + off);               off += 8;
    put_be64(leaf->hist_next_seq, pre + off);            off += 8;
    /* final-offset proof: the bytes written are EXACTLY the declared
     * 288-byte preimage — a drifted field width cannot hash silently */
    if (off != DNA_POOL_LEAF_PREIMAGE_LEN) return -1;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

/* Same RFC6962-style rules as every S2 tree (ledger_roots_v2.c:75-97):
 * inner = SHA3-512(node_tag ‖ L ‖ R); odd node PROMOTED; n==1 → leaf. */
static int tagged_merkle(const uint8_t node_tag[TAG_LEN],
                         uint8_t (*level)[DNA_POOL_ROOT_LEN], size_t n,
                         uint8_t out[DNA_POOL_ROOT_LEN]) {
    while (n > 1) {
        size_t next = 0;
        for (size_t i = 0; i + 1 < n; i += 2) {
            uint8_t pre[TAG_LEN + 2 * DNA_POOL_ROOT_LEN];
            memcpy(pre, node_tag, TAG_LEN);
            memcpy(pre + TAG_LEN, level[i], DNA_POOL_ROOT_LEN);
            memcpy(pre + TAG_LEN + DNA_POOL_ROOT_LEN, level[i + 1],
                   DNA_POOL_ROOT_LEN);
            if (qgp_sha3_512(pre, sizeof(pre), level[next]) != 0)
                return -1;
            next++;
        }
        if (n & 1) {
            memcpy(level[next], level[n - 1], DNA_POOL_ROOT_LEN);
            next++;
        }
        n = next;
    }
    memcpy(out, level[0], DNA_POOL_ROOT_LEN);
    return 0;
}

int dna_pools_root(uint32_t domain_id, const dna_pool_leaf_t *leaves,
                   size_t n, uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!out || (n > 0 && !leaves)) return -1;
    if (n == 0)
        return qgp_sha3_512(TAG_E_POOLS, TAG_LEN, out) == 0 ? 0 : -1;

    uint8_t (*level)[DNA_POOL_ROOT_LEN] = malloc(n * DNA_POOL_ROOT_LEN);
    if (!level) return -1;
    int rc = -1;
    for (size_t i = 0; i < n; i++) {
        if (leaves[i].domain_id != domain_id) goto done; /* foreign pool */
        if (i > 0 && leaves[i - 1].pool_id >= leaves[i].pool_id)
            goto done;               /* duplicate / non-canonical order  */
        if (dna_pool_leaf_hash(&leaves[i], level[i]) != 0) goto done;
    }
    rc = tagged_merkle(TAG_POOLNODE, level, n, out);
done:
    free(level);
    return rc;
}

/* ── Nullifier-set accumulator ──────────────────────────────────────── */

int dna_pool_nul_empty_root(uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!out) return -1;
    return qgp_sha3_512(TAG_E_PNUL, TAG_LEN, out) == 0 ? 0 : -1;
}

int dna_pool_nul_step(const uint8_t prev[DNA_POOL_ROOT_LEN],
                      uint64_t position,
                      const uint8_t nullifier[DNA_POOL_NULLIFIER_LEN],
                      uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!prev || !nullifier || !out) return -1;
    if (!dna_pool_lanes_canonical(nullifier)) return -1;

    uint8_t pre[TAG_LEN + DNA_POOL_ROOT_LEN + 8 + DNA_POOL_NULLIFIER_LEN];
    memcpy(pre, TAG_PNUL, TAG_LEN);
    memcpy(pre + TAG_LEN, prev, DNA_POOL_ROOT_LEN);
    put_be64(position, pre + TAG_LEN + DNA_POOL_ROOT_LEN);
    memcpy(pre + TAG_LEN + DNA_POOL_ROOT_LEN + 8, nullifier,
           DNA_POOL_NULLIFIER_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* ── Finalized-root-history commitment ──────────────────────────────── */

int dna_pool_hist_empty(uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!out) return -1;
    return qgp_sha3_512(TAG_E_PHIST, TAG_LEN, out) == 0 ? 0 : -1;
}

int dna_pool_hist_step(const uint8_t prev[DNA_POOL_ROOT_LEN],
                       uint64_t seq,
                       const uint8_t note_root[DNA_POOL_NOTE_LEN],
                       uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!prev || !note_root || !out) return -1;
    if (!dna_pool_lanes_canonical(note_root)) return -1;

    uint8_t pre[TAG_LEN + DNA_POOL_ROOT_LEN + 8 + DNA_POOL_NOTE_LEN];
    memcpy(pre, TAG_PHIST, TAG_LEN);
    memcpy(pre + TAG_LEN, prev, DNA_POOL_ROOT_LEN);
    put_be64(seq, pre + TAG_LEN + DNA_POOL_ROOT_LEN);
    memcpy(pre + TAG_LEN + DNA_POOL_ROOT_LEN + 8, note_root,
           DNA_POOL_NOTE_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_pool_hist_commit(const uint64_t *seqs,
                         const uint8_t (*roots)[DNA_POOL_NOTE_LEN],
                         size_t n, uint8_t out[DNA_POOL_ROOT_LEN]) {
    if (!out || (n > 0 && (!seqs || !roots))) return -1;
    uint8_t acc[DNA_POOL_ROOT_LEN];
    if (dna_pool_hist_empty(acc) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && seqs[i] != seqs[i - 1] + 1)
            return -1;   /* retained window must be contiguous ascending */
        if (dna_pool_hist_step(acc, seqs[i], roots[i], acc) != 0)
            return -1;
    }
    memcpy(out, acc, DNA_POOL_ROOT_LEN);
    return 0;
}
