/**
 * @file shared/dnac/ledger_roots_v2.c
 * @brief Ledger V2 Season 2 — tagged state-root hierarchy implementation.
 *
 * The version-3 chain's state root (its global_state_root is the block
 * app_hash — ledger_roots_v2.h ACTIVATION). See ledger_roots_v2.h for the
 * exact tag table, preimages, and Merkle rules.
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

/* tokenomics-v3 P1 (D-4, S-2): "NDS.SYS.v1" -> "NDS.SYS.v2" — the 8th
 * leg (attendance_root). Root-layout round (K2, 2026-09-25):
 * "NDS.SYS.v2" -> "NDS.SYS.v3" — the epoch_state leg is removed (7
 * legs). Final pre-testnet wipe (W-A): "NDS.SYS.v3" -> "NDS.SYS.v4" —
 * treasury_root appended as the 8th and last leg. A changed preimage is
 * never hashed under the OLD tag. */
static const uint8_t TAG_SYS[TAG_LEN]     = "NDS.SYS.v4\0\0\0\0\0";
/* tokenomics-v3 P2 (P2-8): "NDS.CORE.v1" -> "NDS.CORE.v2" — the 7th leg
 * (accrual_root) changes the composition; "NDS.SUPPLY.v1" ->
 * "NDS.SUPPLY.v2" — the leaf gained reward_pool. A changed preimage is
 * never hashed under the OLD tag. */
static const uint8_t TAG_CORE[TAG_LEN]    = "NDS.CORE.v2\0\0\0\0";
static const uint8_t TAG_GLOBAL[TAG_LEN]  = "NDS.GLOBAL.v1\0\0";
static const uint8_t TAG_SUPPLY[TAG_LEN]  = "NDS.SUPPLY.v2\0\0";
static const uint8_t TAG_TOKLEAF[TAG_LEN] = "NDS.TOKLEAF.v1\0";
static const uint8_t TAG_TOKNODE[TAG_LEN] = "NDS.TOKNODE.v1\0";
/* Root-layout round (K2): TAG_EPOCH "NDS.EPOCH.v2" and TAG_EPNODE
 * "NDS.EPNODE.v2" DELETED with the epoch_state leg — retired, never
 * reused (ledger_roots_v2.h TAG TABLE). */
static const uint8_t TAG_DOMHEAD[TAG_LEN] = "NDS.DOMHEAD.v1\0";
static const uint8_t TAG_DOMNODE[TAG_LEN] = "NDS.DOMNODE.v1\0";
static const uint8_t TAG_VSLEAF[TAG_LEN]  = "NDS.VSLEAF.v1\0\0";
static const uint8_t TAG_VSNODE[TAG_LEN]  = "NDS.VSNODE.v1\0\0";
/* tokenomics-v3 P1 (D-4, S-2) — collision-scanned against every NDS.*
 * tag in the tree before adoption (see the ledger_roots_v2.h "TAG TABLE"
 * comment and the P1 executor report's grep). */
static const uint8_t TAG_ATTEP[TAG_LEN]   = "NDS.ATTEP.v1\0\0\0";
static const uint8_t TAG_ATLEAF[TAG_LEN]  = "NDS.ATLEAF.v1\0\0";
static const uint8_t TAG_ATNODE[TAG_LEN]  = "NDS.ATNODE.v1\0\0";
/* tokenomics-v3 P2 (P2-8) — collision-scanned against every NDS.* tag in
 * the tree before adoption (grep "NDS\.AC", "NDS\.E\.ACC": no other
 * consumer). SELF-CONSISTENT, not externally referenced — the P1 ATTEP
 * precedent (ledger_roots_v2_attendance_oracle.py PROVENANCE). */
static const uint8_t TAG_ACLEAF[TAG_LEN]  = "NDS.ACLEAF.v1\0\0";
static const uint8_t TAG_ACNODE[TAG_LEN]  = "NDS.ACNODE.v1\0\0";
/* Final pre-testnet wipe, W-A (decision
 * 2026-09-28-treasury-pools-and-exact-self-stake.md answer 12, operator
 * "1 ok") — collision-scanned against every NDS.* tag in the tree before
 * adoption (git grep "NDS\.TR", "NDS\.E\.TREAS", "TRLEAF", "TRNODE": no
 * prior use). SELF-CONSISTENT, not externally referenced — proven by an
 * independent oracle KAT, the ACLEAF precedent above. */
/* HF-4 (decision 2026-10-02-onchain-names.md item 18, operator "4 ok";
 * collision scan 2026-10-02: no other "NDS.NM" tag in the tree). */
static const uint8_t TAG_NMLEAF[TAG_LEN]  = "NDS.NMLEAF.v1\0\0";
static const uint8_t TAG_NMNODE[TAG_LEN]  = "NDS.NMNODE.v1\0\0";
static const uint8_t TAG_TRLEAF[TAG_LEN]  = "NDS.TRLEAF.v1\0\0";
static const uint8_t TAG_TRNODE[TAG_LEN]  = "NDS.TRNODE.v1\0\0";

static const uint8_t TAG_EMPTY[DNA_V2_EMPTY__COUNT][TAG_LEN] = {
    "NDS.E.VSET.v1\0\0",   /* DNA_V2_EMPTY_VSET     */
    "NDS.E.DOMREG.v1",     /* DNA_V2_EMPTY_DOMREG   */
    "NDS.E.MANIF.v1\0",    /* DNA_V2_EMPTY_MANIFEST */
    "NDS.E.POOLS.v1\0",    /* DNA_V2_EMPTY_POOLS    */
    "NDS.E.CLAIMS.v1",     /* DNA_V2_EMPTY_CLAIMS   */
    "NDS.E.NAMES.v1\0",    /* DNA_V2_EMPTY_NAMES    */
    "NDS.E.TOKENS.v1",     /* DNA_V2_EMPTY_TOKENS   */
    /* "NDS.E.EPOCH.v2" — DELETED, root-layout round K2 */
    "NDS.E.ATTND.v1\0",   /* DNA_V2_EMPTY_ATTENDANCE (P1) */
    "NDS.E.ACCRU.v1\0",    /* DNA_V2_EMPTY_ACCRUAL (P2)    */
    "NDS.E.TREAS.v1\0",    /* DNA_V2_EMPTY_TREASURY (W-A)  */
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
                       uint64_t reward_pool_raw,
                       uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out) return -1;
    uint8_t pre[TAG_LEN + 32];
    memcpy(pre, TAG_SUPPLY, TAG_LEN);
    put_be64(genesis_supply_raw, pre + TAG_LEN);
    put_be64(total_minted_raw,   pre + TAG_LEN + 8);
    put_be64(total_burned_raw,   pre + TAG_LEN + 16);
    put_be64(reward_pool_raw,    pre + TAG_LEN + 24);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* Nodus EVM — the EVM generation's supply leaf (contract: ledger_roots_v2.h). */
int dna_v2_supply_root_evm(uint64_t genesis_supply_raw,
                           uint64_t total_minted_raw,
                           uint64_t total_burned_raw,
                           uint64_t reward_pool_raw,
                           uint64_t evm_reserve_raw,
                           uint8_t out[DNA_V2_ROOT_LEN]) {
    static const char tag_src[] = DNA_V2_SUPPLY_TAG_EVM;
    _Static_assert(sizeof(tag_src) - 1 < TAG_LEN,
                   "the EVM supply tag must fit 16 bytes with padding");
    if (!out) return -1;
    uint8_t pre[TAG_LEN + 40];
    memset(pre, 0, TAG_LEN);
    memcpy(pre, tag_src, sizeof(tag_src) - 1);
    put_be64(genesis_supply_raw, pre + TAG_LEN);
    put_be64(total_minted_raw,   pre + TAG_LEN + 8);
    put_be64(total_burned_raw,   pre + TAG_LEN + 16);
    put_be64(reward_pool_raw,    pre + TAG_LEN + 24);
    put_be64(evm_reserve_raw,    pre + TAG_LEN + 32);
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

/* ── attendance_root (tokenomics-v3 P1, D-4 / S-2) ────────────────────
 * Contract, both layers: ledger_roots_v2.h. */

int dna_v2_attendance_digest(uint64_t epoch_start,
                             const dna_v2_attendance_row_t *rows, size_t n,
                             uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !rows)) return -1;
    if (n > UINT32_MAX) return -1;
    for (size_t i = 1; i < n; i++)
        if (memcmp(rows[i - 1].voter_id, rows[i].voter_id, 32) >= 0)
            return -1;                    /* strictly ascending, no dups */

    size_t pre_len = (size_t)TAG_LEN + 8 + 4 + n * 48;
    uint8_t *pre = malloc(pre_len);
    if (!pre) return -1;
    size_t off = 0;
    memcpy(pre + off, TAG_ATTEP, TAG_LEN); off += TAG_LEN;
    put_be64(epoch_start, pre + off);      off += 8;
    put_be32((uint32_t)n, pre + off);      off += 4;
    for (size_t i = 0; i < n; i++) {
        memcpy(pre + off, rows[i].voter_id, 32);        off += 32;
        put_be64(rows[i].signed_count, pre + off);      off += 8;
        put_be64(rows[i].last_signed_height, pre + off); off += 8;
    }
    int rc = qgp_sha3_512(pre, pre_len, out) == 0 ? 0 : -1;
    free(pre);
    return rc;
}

int dna_v2_attendance_leaf_hash(uint64_t epoch_start,
                                const uint8_t digest[DNA_V2_ROOT_LEN],
                                uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!digest || !out) return -1;
    uint8_t pre[TAG_LEN + 8 + DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_ATLEAF, TAG_LEN);
    put_be64(epoch_start, pre + TAG_LEN);
    memcpy(pre + TAG_LEN + 8, digest, DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_attendance_root(const uint64_t *epoch_starts,
                           const uint8_t (*digests)[DNA_V2_ROOT_LEN],
                           size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!epoch_starts || !digests))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_ATTENDANCE, out);
    for (size_t i = 1; i < n; i++)
        if (epoch_starts[i - 1] >= epoch_starts[i]) return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_attendance_leaf_hash(epoch_starts[i], digests[i],
                                        level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_ATNODE, level, n, out);
    free(level);
    return rc;
}

/* ── accrual_root (tokenomics-v3 P2, P2-8) ────────────────────────────
 * Contract: ledger_roots_v2.h. */

int dna_v2_accrual_leaf_hash(const uint8_t owner_fp[DNA_V2_ROOT_LEN],
                             uint64_t amount,
                             uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!owner_fp || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_ROOT_LEN + 8];
    memcpy(pre, TAG_ACLEAF, TAG_LEN);
    memcpy(pre + TAG_LEN, owner_fp, DNA_V2_ROOT_LEN);
    put_be64(amount, pre + TAG_LEN + DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_accrual_root(const uint8_t (*owner_fps)[DNA_V2_ROOT_LEN],
                        const uint64_t *amounts, size_t n,
                        uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!owner_fps || !amounts))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_ACCRUAL, out);
    /* Strictly ascending owner_fp: rejects duplicates AND any
     * non-canonical order, so no input ordering can influence the root. */
    for (size_t i = 1; i < n; i++)
        if (memcmp(owner_fps[i - 1], owner_fps[i], DNA_V2_ROOT_LEN) >= 0)
            return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_accrual_leaf_hash(owner_fps[i], amounts[i],
                                     level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_ACNODE, level, n, out);
    free(level);
    return rc;
}

/* ── name_root (HF-4) ─────────────────────────────────────────────────
 * Contract: ledger_roots_v2.h. */

int dna_v2_name_cmp(const uint8_t *a, size_t a_len,
                    const uint8_t *b, size_t b_len) {
    size_t m = a_len < b_len ? a_len : b_len;
    int c = m ? memcmp(a, b, m) : 0;
    if (c != 0) return c;
    if (a_len == b_len) return 0;
    return a_len < b_len ? -1 : 1;
}

int dna_v2_name_leaf_hash(const dna_v2_name_row_t *row,
                          uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!row || !out) return -1;
    if (row->name_len == 0 || row->name_len > DNA_V2_NAME_MAX_LEN) return -1;
    uint8_t pre[TAG_LEN + 1 + DNA_V2_NAME_MAX_LEN + DNA_V2_ROOT_LEN + 8];
    size_t off = 0;
    memcpy(pre, TAG_NMLEAF, TAG_LEN);              off += TAG_LEN;
    pre[off++] = row->name_len;
    memcpy(pre + off, row->name, row->name_len);   off += row->name_len;
    memcpy(pre + off, row->owner, DNA_V2_ROOT_LEN); off += DNA_V2_ROOT_LEN;
    put_be64(row->registered_height, pre + off);   off += 8;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int dna_v2_names_root(const dna_v2_name_row_t *rows, size_t n,
                      uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !rows)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_NAMES, out);
    for (size_t i = 1; i < n; i++)
        if (dna_v2_name_cmp(rows[i - 1].name, rows[i - 1].name_len,
                            rows[i].name, rows[i].name_len) >= 0)
            return -1;                     /* strictly ascending only    */
    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_name_leaf_hash(&rows[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_NMNODE, level, n, out);
    free(level);
    return rc;
}

/* ── treasury_root (final pre-testnet wipe, W-A) ──────────────────────
 * Contract: ledger_roots_v2.h. The accrual leg's exact shape. */

int dna_v2_treasury_leaf_hash(uint32_t pool_id, uint64_t balance,
                              uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out) return -1;
    uint8_t pre[TAG_LEN + 4 + 8];
    memcpy(pre, TAG_TRLEAF, TAG_LEN);
    put_be32(pool_id, pre + TAG_LEN);
    put_be64(balance, pre + TAG_LEN + 4);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_treasury_root(const uint32_t *pool_ids, const uint64_t *balances,
                         size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!pool_ids || !balances))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_TREASURY, out);
    /* Strictly ascending pool_id: rejects duplicates AND any
     * non-canonical order, so no input ordering can influence the root. */
    for (size_t i = 1; i < n; i++)
        if (pool_ids[i - 1] >= pool_ids[i]) return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_treasury_leaf_hash(pool_ids[i], balances[i],
                                      level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_TRNODE, level, n, out);
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

/* supply_root is a CORE leg, never a SYSTEM leg: native issuance is the
 * DNA_CORE runtime's asset commitment (header ownership note). */
int dna_v2_system_root(const uint8_t validator_root[64],
                       const uint8_t delegation_root[64],
                       const uint8_t chain_config_root[64],
                       const uint8_t validator_set_root[64],
                       const uint8_t domain_registry_root[64],
                       const uint8_t manifest_root[64],
                       const uint8_t attendance_root[64],
                       const uint8_t treasury_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!validator_root || !delegation_root ||
        !chain_config_root || !validator_set_root || !domain_registry_root ||
        !manifest_root || !attendance_root || !treasury_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 8 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_SYS, TAG_LEN);
    /* W-A: treasury_root is the 8th and LAST leg ("NDS.SYS.v4"). */
    const uint8_t *parts[8] = {
        validator_root, delegation_root, chain_config_root,
        validator_set_root, domain_registry_root, manifest_root,
        attendance_root, treasury_root
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
                     const uint8_t supply_root[64],
                     const uint8_t accrual_root[64],
                     uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!utxo_root || !token_root || !pools_root || !claims_root ||
        !name_root || !supply_root || !accrual_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 7 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_CORE, TAG_LEN);
    const uint8_t *parts[7] = {
        utxo_root, token_root, pools_root, claims_root, name_root,
        supply_root, accrual_root
    };
    for (int i = 0; i < 7; i++)
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

/* Root-layout round (K2): "NDS.SYSPAYL.v1" (5 legs) -> "NDS.SYSPAYL.v2"
 * (4 legs, the epoch_state leg removed). Final pre-testnet wipe (W-A):
 * "NDS.SYSPAYL.v2" -> "NDS.SYSPAYL.v3" (5 legs, treasury_root appended
 * LAST — the treasury is seeded at genesis). */
static const uint8_t TAG_SYSPAYL[TAG_LEN] = "NDS.SYSPAYL.v3\0";

int dna_v2_system_payload_root(const uint8_t validator_root[64],
                               const uint8_t delegation_root[64],
                               const uint8_t chain_config_root[64],
                               const uint8_t validator_set_root[64],
                               const uint8_t treasury_root[64],
                               uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!validator_root || !delegation_root ||
        !chain_config_root || !validator_set_root || !treasury_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 5 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_SYSPAYL, TAG_LEN);
    const uint8_t *parts[5] = {
        validator_root, delegation_root, chain_config_root,
        validator_set_root, treasury_root
    };
    for (int i = 0; i < 5; i++)
        memcpy(pre + TAG_LEN + (size_t)i * DNA_V2_ROOT_LEN, parts[i],
               DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}
