/**
 * @file shared/dnac/ledger_roots_v2.c
 * @brief Ledger V2 Season 2 — tagged state-root hierarchy implementation.
 *
 * INACTIVE: no live consensus path calls anything here (S2 charter). See
 * ledger_roots_v2.h for the exact tag table, preimages, and Merkle rules.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "ledger_roots_v2.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* All tags are EXACTLY 16 bytes, zero-padded ASCII. */
#define TAG_LEN 16

static const uint8_t TAG_SYS[TAG_LEN]     = "DNA.SYS.v1\0\0\0\0\0";
static const uint8_t TAG_CORE[TAG_LEN]    = "DNA.CORE.v1\0\0\0\0";
static const uint8_t TAG_GLOBAL[TAG_LEN]  = "DNA.GLOBAL.v1\0\0";
static const uint8_t TAG_SUPPLY[TAG_LEN]  = "DNA.SUPPLY.v1\0\0";
static const uint8_t TAG_TOKLEAF[TAG_LEN] = "DNA.TOKLEAF.v1\0";
static const uint8_t TAG_TOKNODE[TAG_LEN] = "DNA.TOKNODE.v1\0";
static const uint8_t TAG_EPOCH[TAG_LEN]   = "DNA.EPOCH.v2\0\0\0";
static const uint8_t TAG_EPNODE[TAG_LEN]  = "DNA.EPNODE.v2\0\0";
static const uint8_t TAG_DOMHEAD[TAG_LEN] = "DNA.DOMHEAD.v1\0";
static const uint8_t TAG_DOMNODE[TAG_LEN] = "DNA.DOMNODE.v1\0";
static const uint8_t TAG_VSLEAF[TAG_LEN]  = "DNA.VSLEAF.v1\0\0";
static const uint8_t TAG_VSNODE[TAG_LEN]  = "DNA.VSNODE.v1\0\0";

static const uint8_t TAG_EMPTY[DNA_V2_EMPTY__COUNT][TAG_LEN] = {
    "DNA.E.VSET.v1\0\0",   /* DNA_V2_EMPTY_VSET     */
    "DNA.E.DOMREG.v1",     /* DNA_V2_EMPTY_DOMREG   */
    "DNA.E.MANIF.v1\0",    /* DNA_V2_EMPTY_MANIFEST */
    "DNA.E.POOLS.v1\0",    /* DNA_V2_EMPTY_POOLS    */
    "DNA.E.CLAIMS.v1",     /* DNA_V2_EMPTY_CLAIMS   */
    "DNA.E.NAMES.v1\0",    /* DNA_V2_EMPTY_NAMES    */
    "DNA.E.TOKENS.v1",     /* DNA_V2_EMPTY_TOKENS   */
    "DNA.E.EPOCH.v2\0",    /* DNA_V2_EMPTY_EPOCH_V2 */
};

static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

int dna_v2_empty_root(dna_v2_empty_kind_t kind, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (int)kind < 0 || kind >= DNA_V2_EMPTY__COUNT) return -1;
    return qgp_sha3_512(TAG_EMPTY[kind], TAG_LEN, out) == 0 ? 0 : -1;
}

int dna_v2_supply_root(uint64_t genesis_supply_raw,
                       uint64_t total_minted_raw,
                       uint64_t total_burned_raw,
                       uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out) return -1;
    uint8_t pre[TAG_LEN + 24];
    memcpy(pre, TAG_SUPPLY, TAG_LEN);
    put_be64(genesis_supply_raw, pre + TAG_LEN);
    put_be64(total_minted_raw,   pre + TAG_LEN + 8);
    put_be64(total_burned_raw,   pre + TAG_LEN + 16);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* ── Generic RFC6962-style tree over already-tagged 64-byte leaves ────
 * inner = SHA3-512(node_tag ‖ L ‖ R); odd node PROMOTED (never
 * duplicated); n==1 → the leaf itself. Caller guarantees n >= 1. */
static int tagged_merkle(const uint8_t node_tag[TAG_LEN],
                         uint8_t (*level)[DNA_V2_ROOT_LEN], size_t n,
                         uint8_t out[DNA_V2_ROOT_LEN]) {
    while (n > 1) {
        size_t next = 0;
        for (size_t i = 0; i + 1 < n; i += 2) {
            uint8_t pre[TAG_LEN + 2 * DNA_V2_ROOT_LEN];
            memcpy(pre, node_tag, TAG_LEN);
            memcpy(pre + TAG_LEN, level[i], DNA_V2_ROOT_LEN);
            memcpy(pre + TAG_LEN + DNA_V2_ROOT_LEN, level[i + 1],
                   DNA_V2_ROOT_LEN);
            if (qgp_sha3_512(pre, sizeof(pre), level[next]) != 0) return -1;
            next++;
        }
        if (n & 1) {                       /* promote the unpaired node */
            memcpy(level[next], level[n - 1], DNA_V2_ROOT_LEN);
            next++;
        }
        n = next;
    }
    memcpy(out, level[0], DNA_V2_ROOT_LEN);
    return 0;
}

/* ── token_root ─────────────────────────────────────────────────────── */

int dna_v2_token_leaf_hash(const dna_v2_token_leaf_t *leaf,
                           uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!leaf || !out) return -1;
    if (!leaf->name || !leaf->symbol || !leaf->creator_fp) return -1;
    if (leaf->name_len > DNA_V2_TOKEN_STR_MAX ||
        leaf->symbol_len > DNA_V2_TOKEN_STR_MAX ||
        leaf->creator_fp_len > DNA_V2_TOKEN_STR_MAX)
        return -1;

    size_t pre_len = TAG_LEN + DNA_V2_TOKEN_ID_LEN + 1 + 1 + 8 + 8
                   + 2 + leaf->name_len + 2 + leaf->symbol_len
                   + 2 + leaf->creator_fp_len;
    uint8_t *pre = (uint8_t *)malloc(pre_len);
    if (!pre) return -1;
    uint8_t *p = pre;
    memcpy(p, TAG_TOKLEAF, TAG_LEN);               p += TAG_LEN;
    memcpy(p, leaf->token_id, DNA_V2_TOKEN_ID_LEN); p += DNA_V2_TOKEN_ID_LEN;
    *p++ = leaf->decimals;
    *p++ = leaf->flags;
    put_be64(leaf->supply, p);       p += 8;
    put_be64(leaf->block_height, p); p += 8;
    p[0] = (uint8_t)(leaf->name_len >> 8); p[1] = (uint8_t)leaf->name_len;
    p += 2;
    memcpy(p, leaf->name, leaf->name_len);          p += leaf->name_len;
    p[0] = (uint8_t)(leaf->symbol_len >> 8); p[1] = (uint8_t)leaf->symbol_len;
    p += 2;
    memcpy(p, leaf->symbol, leaf->symbol_len);      p += leaf->symbol_len;
    p[0] = (uint8_t)(leaf->creator_fp_len >> 8);
    p[1] = (uint8_t)leaf->creator_fp_len;
    p += 2;
    memcpy(p, leaf->creator_fp, leaf->creator_fp_len);
    p += leaf->creator_fp_len;

    int rc = qgp_sha3_512(pre, (size_t)(p - pre), out);
    free(pre);
    return rc == 0 ? 0 : -1;
}

int dna_v2_token_root(const dna_v2_token_leaf_t *leaves, size_t n,
                      uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !leaves)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_TOKENS, out);

    /* Strictly ascending token_id: rejects duplicates AND any
     * non-canonical order, so no input ordering can influence the root. */
    for (size_t i = 1; i < n; i++) {
        if (memcmp(leaves[i - 1].token_id, leaves[i].token_id,
                   DNA_V2_TOKEN_ID_LEN) >= 0)
            return -1;
    }
    uint8_t (*hashes)[DNA_V2_ROOT_LEN] =
        malloc(n * sizeof(*hashes));
    if (!hashes) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_token_leaf_hash(&leaves[i], hashes[i]) != 0) {
            free(hashes);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_TOKNODE, hashes, n, out);
    free(hashes);
    return rc;
}

/* ── epoch_state_root_v2 ────────────────────────────────────────────── */

int dna_v2_epoch_leaf_hash(uint64_t epoch_start_height,
                           uint64_t epoch_pool_accum,
                           const uint8_t snapshot_hash[64],
                           uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!snapshot_hash || !out) return -1;
    uint8_t pre[TAG_LEN + 8 + 8 + 64];
    memcpy(pre, TAG_EPOCH, TAG_LEN);
    put_be64(epoch_start_height, pre + TAG_LEN);
    put_be64(epoch_pool_accum,   pre + TAG_LEN + 8);
    memcpy(pre + TAG_LEN + 16, snapshot_hash, 64);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_epoch_root(const uint64_t *epoch_starts,
                      const uint8_t (*leaf_hashes)[DNA_V2_ROOT_LEN],
                      size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!epoch_starts || !leaf_hashes))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_EPOCH_V2, out);
    for (size_t i = 1; i < n; i++)
        if (epoch_starts[i - 1] >= epoch_starts[i]) return -1;
    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    memcpy(level, leaf_hashes, n * sizeof(*level));
    int rc = tagged_merkle(TAG_EPNODE, level, n, out);
    free(level);
    return rc;
}

/* ── validator_set_root (S3) ────────────────────────────────────────── */

int dna_v2_vset_root(const uint64_t *epochs,
                     const uint8_t (*snapshot_hashes)[DNA_V2_ROOT_LEN],
                     size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!epochs || !snapshot_hashes))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_VSET, out);

    /* Strictly ascending epoch: rejects duplicates AND any non-canonical
     * order, so no input ordering can influence the root. */
    for (size_t i = 1; i < n; i++)
        if (epochs[i - 1] >= epochs[i]) return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t pre[TAG_LEN + 8 + DNA_V2_ROOT_LEN];
        memcpy(pre, TAG_VSLEAF, TAG_LEN);
        put_be64(epochs[i], pre + TAG_LEN);
        memcpy(pre + TAG_LEN + 8, snapshot_hashes[i], DNA_V2_ROOT_LEN);
        if (qgp_sha3_512(pre, sizeof(pre), level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_VSNODE, level, n, out);
    free(level);
    return rc;
}

/* ── DomainHead + domains_root ──────────────────────────────────────── */

int dna_v2_domain_head_encode(const dna_v2_domain_head_t *head,
                              uint8_t out[DNA_V2_DOMHEAD_ENC_LEN]) {
    if (!head || !out) return -1;
    put_be32(head->domain_id, out);
    memcpy(out + 4, head->domain_state_root, DNA_V2_ROOT_LEN);
    put_be64(head->domain_height, out + 68);
    put_be64(head->last_updated_global_height, out + 76);
    put_be32(head->ruleset_version, out + 84);
    out[88] = head->status;
    return 0;
}

int dna_v2_domain_head_hash(const dna_v2_domain_head_t *head,
                            uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!head || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_DOMHEAD_ENC_LEN];
    memcpy(pre, TAG_DOMHEAD, TAG_LEN);
    if (dna_v2_domain_head_encode(head, pre + TAG_LEN) != 0) return -1;
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_domains_root(const dna_v2_domain_head_t *heads, size_t n,
                        uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!heads || !out || n == 0) return -1;   /* SYSTEM mandatory — an
                                                * empty list is an ERROR,
                                                * not an empty tree. */
    if (heads[0].domain_id != DNA_DOMAIN_SYSTEM) return -1;
    for (size_t i = 1; i < n; i++)
        if (heads[i - 1].domain_id >= heads[i].domain_id) return -1;
    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_domain_head_hash(&heads[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_DOMNODE, level, n, out);
    free(level);
    return rc;
}

/* ── Composition ────────────────────────────────────────────────────── */

int dna_v2_system_root(const uint8_t validator_root[64],
                       const uint8_t delegation_root[64],
                       const uint8_t epoch_state_root_v2[64],
                       const uint8_t chain_config_root[64],
                       const uint8_t validator_set_root[64],
                       const uint8_t domain_registry_root[64],
                       const uint8_t manifest_root[64],
                       const uint8_t supply_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!validator_root || !delegation_root || !epoch_state_root_v2 ||
        !chain_config_root || !validator_set_root || !domain_registry_root ||
        !manifest_root || !supply_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 8 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_SYS, TAG_LEN);
    const uint8_t *parts[8] = {
        validator_root, delegation_root, epoch_state_root_v2,
        chain_config_root, validator_set_root, domain_registry_root,
        manifest_root, supply_root
    };
    for (int i = 0; i < 8; i++)
        memcpy(pre + TAG_LEN + (size_t)i * DNA_V2_ROOT_LEN, parts[i],
               DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_core_root(const uint8_t utxo_root[64],
                     const uint8_t token_root[64],
                     const uint8_t pools_root[64],
                     const uint8_t claims_root[64],
                     const uint8_t name_root[64],
                     uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!utxo_root || !token_root || !pools_root || !claims_root ||
        !name_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 5 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_CORE, TAG_LEN);
    const uint8_t *parts[5] = {
        utxo_root, token_root, pools_root, claims_root, name_root
    };
    for (int i = 0; i < 5; i++)
        memcpy(pre + TAG_LEN + (size_t)i * DNA_V2_ROOT_LEN, parts[i],
               DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_global_root(const uint8_t domains_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!domains_root || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_GLOBAL, TAG_LEN);
    memcpy(pre + TAG_LEN, domains_root, DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* ── SYSTEM payload root (S5 genesis cycle break) ───────────────────── */

static const uint8_t TAG_SYSPAYL[TAG_LEN] = "DNA.SYSPAYL.v1\0";

int dna_v2_system_payload_root(const uint8_t validator_root[64],
                               const uint8_t delegation_root[64],
                               const uint8_t epoch_state_root_v2[64],
                               const uint8_t chain_config_root[64],
                               const uint8_t validator_set_root[64],
                               const uint8_t supply_root[64],
                               uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!validator_root || !delegation_root || !epoch_state_root_v2 ||
        !chain_config_root || !validator_set_root || !supply_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 6 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_SYSPAYL, TAG_LEN);
    const uint8_t *parts[6] = {
        validator_root, delegation_root, epoch_state_root_v2,
        chain_config_root, validator_set_root, supply_root
    };
    for (int i = 0; i < 6; i++)
        memcpy(pre + TAG_LEN + (size_t)i * DNA_V2_ROOT_LEN, parts[i],
               DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}
