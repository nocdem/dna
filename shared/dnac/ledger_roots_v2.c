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
/* Storage reward v1 (decision 2026-10-04-storage-reward-approved.md;
 * bytes doc docs/plans/2026-10-04-storage-reward-bytes.md items 1-6) —
 * collision scan 2026-10-04: `git grep -F` of each tag over the whole
 * tree and every branch, no prior use. SELF-CONSISTENT, not externally
 * referenced — proven by an independent oracle KAT before merge. */
static const uint8_t TAG_SYS_V5[TAG_LEN]   = "NDS.SYS.v5\0\0\0\0\0";
/* Archive reward (decision 2026-10-05-archive-reward-bytes-approved.md;
 * bytes doc docs/plans/2026-10-05-archive-reward-bytes.md items 4-5):
 * "NDS.STOR.v1" (3 legs) and "NDS.STLEAF.v1" (no fail_streak) were
 * replaced before any activation — retired, never reused. */
static const uint8_t TAG_STOR[TAG_LEN]     = "NDS.STOR.v2\0\0\0\0";
static const uint8_t TAG_STLEAF[TAG_LEN]   = "NDS.STLEAF.v2\0\0";
static const uint8_t TAG_STRNODE[TAG_LEN]  = "NDS.STRNODE.v1\0";
static const uint8_t TAG_STSET[TAG_LEN]    = "NDS.STSET.v1\0\0\0";
static const uint8_t TAG_STSLEAF[TAG_LEN]  = "NDS.STSLEAF.v1\0";
static const uint8_t TAG_STSNODE[TAG_LEN]  = "NDS.STSNODE.v1\0";
static const uint8_t TAG_STREP[TAG_LEN]    = "NDS.STREP.v1\0\0\0";
static const uint8_t TAG_STRPNODE[TAG_LEN] = "NDS.STRPNODE.v1";
static const uint8_t TAG_STEXIT[TAG_LEN]   = "NDS.STEXIT.v1\0\0";
/* Archive reward (bytes doc 2026-10-05 items 1-3, §6) — collision scan
 * 2026-10-05: `git grep -E` over the tree (oracle vectors excluded), no
 * prior use. SELF-CONSISTENT; the independent oracle KAT
 * (nodus/tests/vectors/archive_reward_kat.json) is the proof. */
static const uint8_t TAG_STSEG[TAG_LEN]    = "NDS.STSEG.v1\0\0\0\0";
static const uint8_t TAG_STSGLEAF[TAG_LEN] = "NDS.STSGLEAF.v1";
static const uint8_t TAG_STSGNODE[TAG_LEN] = "NDS.STSGNODE.v1";
static const uint8_t TAG_STASGN[TAG_LEN]   = "NDS.STASGN.v1\0\0\0";
static const uint8_t TAG_STSAMP[TAG_LEN]   = "NDS.STSAMP.v1\0\0\0";

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
    "NDS.E.STREG.v1\0",    /* DNA_V2_EMPTY_STORAGE_REG     */
    "NDS.E.STSET.v1\0",    /* DNA_V2_EMPTY_STORAGE_SETS    */
    "NDS.E.STREP.v1\0",    /* DNA_V2_EMPTY_STORAGE_REPORTS */
    "NDS.E.STSEG.v1\0",    /* DNA_V2_EMPTY_STORAGE_SEGS (archive) */
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

/* ── storage_root (storage reward v1) ─────────────────────────────────
 * Contract: ledger_roots_v2.h ("Composition preimages", storage block). */

int dna_v2_storage_node_leaf_hash(const dna_v2_storage_node_row_t *row,
                                  uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!row || !out) return -1;
    if (row->status < DNA_V2_STORAGE_ACTIVE ||
        row->status > DNA_V2_STORAGE_RELEASED)
        return -1;                         /* 0 / unknown: never hashed  */
    /* archive bytes item 4: the v1 preimage + fail_streak(4 BE), then
     * (K9, decision 2026-10-05-storage-reward-is-for-archive.md)
     * grace_until(8 BE), last — 181 bytes */
    uint8_t pre[TAG_LEN + 2 * DNA_V2_ROOT_LEN + 8 + 1 + 8 + 8 + 4 + 8];
    size_t off = 0;
    memcpy(pre + off, TAG_STLEAF, TAG_LEN);              off += TAG_LEN;
    memcpy(pre + off, row->node_fp, DNA_V2_ROOT_LEN);    off += DNA_V2_ROOT_LEN;
    memcpy(pre + off, row->payee_fp, DNA_V2_ROOT_LEN);   off += DNA_V2_ROOT_LEN;
    put_be64(row->bond, pre + off);                      off += 8;
    pre[off++] = row->status;
    put_be64(row->registered_height, pre + off);         off += 8;
    put_be64(row->exit_height, pre + off);               off += 8;
    put_be32(row->fail_streak, pre + off);               off += 4;
    put_be64(row->grace_until, pre + off);               off += 8;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int dna_v2_storage_registry_root(const dna_v2_storage_node_row_t *rows,
                                 size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !rows)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_STORAGE_REG, out);
    /* Strictly ascending node_fp: rejects duplicates AND any
     * non-canonical order, so no input ordering can influence the root. */
    for (size_t i = 1; i < n; i++)
        if (memcmp(rows[i - 1].node_fp, rows[i].node_fp,
                   DNA_V2_ROOT_LEN) >= 0)
            return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_storage_node_leaf_hash(&rows[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_STRNODE, level, n, out);
    free(level);
    return rc;
}

int dna_v2_storage_set_hash(uint64_t epoch_start,
                            const uint8_t (*node_fps)[DNA_V2_ROOT_LEN],
                            size_t count, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (count > 0 && !node_fps)) return -1;
    if (count > DNA_V2_STORAGE_SET_MAX) return -1;
    for (size_t i = 1; i < count; i++)
        if (memcmp(node_fps[i - 1], node_fps[i], DNA_V2_ROOT_LEN) >= 0)
            return -1;                    /* strictly ascending, no dups */

    /* Bounded preimage: 16 + 8 + 4 + 256 × 64 = 16412 bytes. */
    size_t pre_len = (size_t)TAG_LEN + 8 + 4 + count * DNA_V2_ROOT_LEN;
    uint8_t *pre = malloc(pre_len);
    if (!pre) return -1;
    size_t off = 0;
    memcpy(pre + off, TAG_STSET, TAG_LEN);  off += TAG_LEN;
    put_be64(epoch_start, pre + off);       off += 8;
    put_be32((uint32_t)count, pre + off);   off += 4;
    for (size_t i = 0; i < count; i++) {
        memcpy(pre + off, node_fps[i], DNA_V2_ROOT_LEN);
        off += DNA_V2_ROOT_LEN;
    }
    int rc = qgp_sha3_512(pre, pre_len, out) == 0 ? 0 : -1;
    free(pre);
    return rc;
}

int dna_v2_storage_sets_leaf_hash(uint64_t epoch_start,
                                  const uint8_t set_hash[DNA_V2_ROOT_LEN],
                                  uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!set_hash || !out) return -1;
    uint8_t pre[TAG_LEN + 8 + DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_STSLEAF, TAG_LEN);
    put_be64(epoch_start, pre + TAG_LEN);
    memcpy(pre + TAG_LEN + 8, set_hash, DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_storage_sets_root(const uint64_t *epoch_starts,
                             const uint8_t (*set_hashes)[DNA_V2_ROOT_LEN],
                             size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!epoch_starts || !set_hashes))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_STORAGE_SETS, out);
    for (size_t i = 1; i < n; i++)
        if (epoch_starts[i - 1] >= epoch_starts[i]) return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_storage_sets_leaf_hash(epoch_starts[i], set_hashes[i],
                                          level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_STSNODE, level, n, out);
    free(level);
    return rc;
}

int dna_v2_storage_report_leaf_hash(const dna_v2_storage_report_t *rep,
                                    uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!rep || !out) return -1;
    if (rep->bitmap_len > DNA_V2_STORAGE_BITMAP_MAX) return -1;
    uint8_t pre[TAG_LEN + 8 + 4 + DNA_V2_ROOT_LEN + 2
                + DNA_V2_STORAGE_BITMAP_MAX];
    size_t off = 0;
    memcpy(pre + off, TAG_STREP, TAG_LEN);              off += TAG_LEN;
    put_be64(rep->epoch_start, pre + off);              off += 8;
    put_be32(rep->seat, pre + off);                     off += 4;
    memcpy(pre + off, rep->set_hash, DNA_V2_ROOT_LEN);  off += DNA_V2_ROOT_LEN;
    pre[off]     = (uint8_t)(rep->bitmap_len >> 8);
    pre[off + 1] = (uint8_t)rep->bitmap_len;            off += 2;
    memcpy(pre + off, rep->bitmap, rep->bitmap_len);    off += rep->bitmap_len;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int dna_v2_storage_reports_root(const dna_v2_storage_report_t *reps,
                                size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !reps)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_STORAGE_REPORTS, out);
    /* Strictly ascending (epoch_start, seat), lexicographic: an equal
     * pair (the duplicate (H, seat)) or any descending step rejects. */
    for (size_t i = 1; i < n; i++) {
        const dna_v2_storage_report_t *a = &reps[i - 1], *b = &reps[i];
        if (a->epoch_start > b->epoch_start) return -1;
        if (a->epoch_start == b->epoch_start && a->seat >= b->seat)
            return -1;
    }

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_storage_report_leaf_hash(&reps[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_STRPNODE, level, n, out);
    free(level);
    return rc;
}

int dna_v2_storage_root(const uint8_t registry_root[DNA_V2_ROOT_LEN],
                        const uint8_t sets_root[DNA_V2_ROOT_LEN],
                        const uint8_t reports_root[DNA_V2_ROOT_LEN],
                        const uint8_t segments_root[DNA_V2_ROOT_LEN],
                        uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!registry_root || !sets_root || !reports_root || !segments_root ||
        !out)
        return -1;
    /* archive bytes item 5: leg order registry, sets, reports, segments */
    uint8_t pre[TAG_LEN + 4 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_STOR, TAG_LEN);
    memcpy(pre + TAG_LEN, registry_root, DNA_V2_ROOT_LEN);
    memcpy(pre + TAG_LEN + DNA_V2_ROOT_LEN, sets_root, DNA_V2_ROOT_LEN);
    memcpy(pre + TAG_LEN + 2 * DNA_V2_ROOT_LEN, reports_root,
           DNA_V2_ROOT_LEN);
    memcpy(pre + TAG_LEN + 3 * DNA_V2_ROOT_LEN, segments_root,
           DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* ── archive reward (storage reward v1 rev 4) ──────────────────────────
 * Contract: ledger_roots_v2.h ("Composition preimages", archive block). */

int dna_v2_segment_root(uint64_t k,
                        const uint8_t (*hashes)[DNA_V2_ROOT_LEN],
                        uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!hashes || !out) return -1;
    if (k == 0) return -1;                       /* height 0: no segment */
    if (k > UINT64_MAX / DNA_V2_SEGMENT_BLOCKS) return -1;   /* k·P fits */
    /* tag(16) ‖ k(8) ‖ count(4) ‖ 17280 × 64 = 1,105,948 bytes */
    const size_t pre_len = (size_t)TAG_LEN + 8 + 4 +
                           (size_t)DNA_V2_SEGMENT_BLOCKS * DNA_V2_ROOT_LEN;
    uint8_t *pre = malloc(pre_len);
    if (!pre) return -1;
    size_t off = 0;
    memcpy(pre + off, TAG_STSEG, TAG_LEN);              off += TAG_LEN;
    put_be64(k, pre + off);                             off += 8;
    put_be32(DNA_V2_SEGMENT_BLOCKS, pre + off);         off += 4;
    memcpy(pre + off, hashes,
           (size_t)DNA_V2_SEGMENT_BLOCKS * DNA_V2_ROOT_LEN);
    int rc = qgp_sha3_512(pre, pre_len, out) == 0 ? 0 : -1;
    free(pre);
    return rc;
}

int dna_v2_segment_leaf_hash(uint64_t k,
                             const uint8_t root[DNA_V2_ROOT_LEN],
                             uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!root || !out) return -1;
    uint8_t pre[TAG_LEN + 8 + DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_STSGLEAF, TAG_LEN);
    put_be64(k, pre + TAG_LEN);
    memcpy(pre + TAG_LEN + 8, root, DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_v2_segments_root(const uint64_t *ks,
                         const uint8_t (*roots)[DNA_V2_ROOT_LEN],
                         size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && (!ks || !roots))) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_STORAGE_SEGS, out);
    for (size_t i = 1; i < n; i++)
        if (ks[i - 1] >= ks[i]) return -1;   /* strictly ascending k     */

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_v2_segment_leaf_hash(ks[i], roots[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_STSGNODE, level, n, out);
    free(level);
    return rc;
}

int dna_v2_segment_assign_key(const uint8_t root[DNA_V2_ROOT_LEN],
                              uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!root || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_STASGN, TAG_LEN);
    memcpy(pre + TAG_LEN, root, DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* XOR distance of member i, written to d (64 bytes, big-endian integer:
 * memcmp order IS the unsigned integer order). */
static void seg_distance(const uint8_t a[DNA_V2_ROOT_LEN],
                         const uint8_t fp[DNA_V2_ROOT_LEN],
                         uint8_t d[DNA_V2_ROOT_LEN]) {
    for (size_t b = 0; b < DNA_V2_ROOT_LEN; b++) d[b] = a[b] ^ fp[b];
}

int dna_v2_segment_holders(const uint8_t a_key[DNA_V2_ROOT_LEN],
                           const uint8_t (*node_fps)[DNA_V2_ROOT_LEN],
                           const uint32_t *fail_streaks, size_t n,
                           size_t out_idx[DNA_V2_STORAGE_HOLDERS],
                           size_t *n_out) {
    if (!a_key || !out_idx || !n_out) return -1;
    if (n > 0 && (!node_fps || !fail_streaks)) return -1;
    if (n > DNA_V2_STORAGE_SET_MAX) return -1;
    *n_out = 0;
    /* duplicates: no tie rule exists (bytes item 3 relies on distinct
     * node hashes), so any equal pair refuses — every member, eligible
     * or not, is checked. O(n^2) over n <= 256. */
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (memcmp(node_fps[i], node_fps[j], DNA_V2_ROOT_LEN) == 0)
                return -1;

    /* Selection of the R smallest distances by insertion into a sorted
     * array of at most R — the order is a TOTAL order (distinct fps give
     * distinct distances under XOR with one key), so the result does not
     * depend on the input order. */
    uint8_t best_d[DNA_V2_STORAGE_HOLDERS][DNA_V2_ROOT_LEN];
    size_t best_i[DNA_V2_STORAGE_HOLDERS];
    size_t nb = 0;
    for (size_t i = 0; i < n; i++) {
        if (fail_streaks[i] >= DNA_V2_STORAGE_FAIL_LIMIT) continue;
        uint8_t d[DNA_V2_ROOT_LEN];
        seg_distance(a_key, node_fps[i], d);
        size_t pos = nb;
        while (pos > 0 &&
               memcmp(best_d[pos - 1], d, DNA_V2_ROOT_LEN) > 0)
            pos--;
        if (pos >= DNA_V2_STORAGE_HOLDERS) continue;   /* not in the top R */
        size_t last = nb < DNA_V2_STORAGE_HOLDERS ? nb
                                                  : DNA_V2_STORAGE_HOLDERS - 1;
        for (size_t s = last; s > pos; s--) {
            memcpy(best_d[s], best_d[s - 1], DNA_V2_ROOT_LEN);
            best_i[s] = best_i[s - 1];
        }
        memcpy(best_d[pos], d, DNA_V2_ROOT_LEN);
        best_i[pos] = i;
        if (nb < DNA_V2_STORAGE_HOLDERS) nb++;
    }
    for (size_t s = 0; s < nb; s++) out_idx[s] = best_i[s];
    *n_out = nb;
    return 0;
}

int dna_v2_storage_sample_x(const uint8_t nonce[DNA_V2_STORAGE_NONCE_LEN],
                            const uint8_t target_fp[DNA_V2_ROOT_LEN],
                            uint32_t i, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!nonce || !target_fp || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_STORAGE_NONCE_LEN + DNA_V2_ROOT_LEN + 4];
    size_t off = 0;
    memcpy(pre + off, TAG_STSAMP, TAG_LEN);           off += TAG_LEN;
    memcpy(pre + off, nonce, DNA_V2_STORAGE_NONCE_LEN);
    off += DNA_V2_STORAGE_NONCE_LEN;
    memcpy(pre + off, target_fp, DNA_V2_ROOT_LEN);    off += DNA_V2_ROOT_LEN;
    put_be32(i, pre + off);                           off += 4;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int dna_v2_storage_sample_index(const uint8_t x[DNA_V2_ROOT_LEN],
                                uint64_t eligible_blocks,
                                uint32_t parts_total,
                                uint64_t *block_index,
                                uint32_t *part_index) {
    if (!x) return -1;
    if (eligible_blocks == 0 || parts_total == 0) return -1;
    uint64_t b = 0;
    for (int j = 0; j < 8; j++) b = (b << 8) | x[j];
    uint32_t p = ((uint32_t)x[8] << 24) | ((uint32_t)x[9] << 16) |
                 ((uint32_t)x[10] << 8) | (uint32_t)x[11];
    if (block_index) *block_index = b % eligible_blocks;
    if (part_index)  *part_index = p % parts_total;
    return 0;
}

/* The EPGRAD identity pattern (nodus_witness_v2_epoch.c grad_id /
 * grad_nullifier) with its own tag, kind byte and output index. node_fp
 * is SHA3-512(node_pk) as given — no tree-tag prefix. */
int dna_v2_storage_exit_id(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                           uint64_t release_height,
                           const uint8_t node_fp[DNA_V2_ROOT_LEN],
                           uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!chain_id || !node_fp || !out) return -1;
    /* tag(16) ‖ chain_id(32) ‖ domain(4) ‖ height(8) ‖ node_fp(64) */
    uint8_t pre[TAG_LEN + DNA_CHAIN_ID_LEN + 4 + 8 + DNA_V2_ROOT_LEN];
    size_t off = 0;
    memcpy(pre + off, TAG_STEXIT, TAG_LEN);           off += TAG_LEN;
    memcpy(pre + off, chain_id, DNA_CHAIN_ID_LEN);    off += DNA_CHAIN_ID_LEN;
    put_be32(DNA_DOMAIN_CORE, pre + off);             off += 4;
    put_be64(release_height, pre + off);              off += 8;
    memcpy(pre + off, node_fp, DNA_V2_ROOT_LEN);      off += DNA_V2_ROOT_LEN;
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int dna_v2_storage_exit_nullifier(const uint8_t exit_id[DNA_V2_ROOT_LEN],
                                  uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!exit_id || !out) return -1;
    uint8_t pre[DNA_V2_ROOT_LEN + 1 + 4];
    memcpy(pre, exit_id, DNA_V2_ROOT_LEN);
    pre[DNA_V2_ROOT_LEN] = DNA_V2_STORAGE_EXIT_KIND;
    put_be32(DNA_V2_STORAGE_EXIT_OUT_IDX, pre + DNA_V2_ROOT_LEN + 1);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
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

/* Storage reward v1: "NDS.SYS.v5" — the 8 v4 legs in v4 order, then
 * storage_root. dna_v2_system_root above ("NDS.SYS.v4") is untouched. */
int dna_v2_system_root_v5(const uint8_t validator_root[64],
                          const uint8_t delegation_root[64],
                          const uint8_t chain_config_root[64],
                          const uint8_t validator_set_root[64],
                          const uint8_t domain_registry_root[64],
                          const uint8_t manifest_root[64],
                          const uint8_t attendance_root[64],
                          const uint8_t treasury_root[64],
                          const uint8_t storage_root[64],
                          uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!validator_root || !delegation_root ||
        !chain_config_root || !validator_set_root || !domain_registry_root ||
        !manifest_root || !attendance_root || !treasury_root ||
        !storage_root || !out)
        return -1;
    uint8_t pre[TAG_LEN + 9 * DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_SYS_V5, TAG_LEN);
    const uint8_t *parts[9] = {
        validator_root, delegation_root, chain_config_root,
        validator_set_root, domain_registry_root, manifest_root,
        attendance_root, treasury_root, storage_root
    };
    for (int i = 0; i < 9; i++)
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
