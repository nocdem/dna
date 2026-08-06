/**
 * @file shared/dnac/manifest_wire.c
 * @brief Ledger V2 Season 6 — generic genesis/distribution manifest,
 *        snapshot tree and claim codec implementation (INACTIVE).
 *        Contract: manifest_wire.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "manifest_wire.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* All tags are EXACTLY 16 bytes, zero-padded ASCII. */
#define TAG_LEN 16

static const uint8_t TAG_GMAN[TAG_LEN]    = "DNA.GMAN.v1\0\0\0\0";
static const uint8_t TAG_MANLEAF[TAG_LEN] = "DNA.MANLEAF.v1\0";
static const uint8_t TAG_MANNODE[TAG_LEN] = "DNA.MANNODE.v1\0";
static const uint8_t TAG_DSLEAF[TAG_LEN]  = "DNA.DSLEAF.v1\0\0";
static const uint8_t TAG_DSNODE[TAG_LEN]  = "DNA.DSNODE.v1\0\0";
static const uint8_t TAG_CLAIM[TAG_LEN]   = "DNA.CLAIM.v1\0\0\0";
static const uint8_t TAG_CLNUL[TAG_LEN]   = "DNA.CLNUL.v1\0\0\0";
static const uint8_t TAG_CLLEAF[TAG_LEN]  = "DNA.CLLEAF.v1\0\0";
static const uint8_t TAG_CLNODE[TAG_LEN]  = "DNA.CLNODE.v1\0\0";
static const uint8_t TAG_CLUTXO[TAG_LEN]  = "DNA.CLUTXO.v1\0\0";

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
static uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ── Generic RFC6962-style tree over already-tagged 64-byte leaves ────
 * inner = SHA3-512(node_tag ‖ L ‖ R); odd node PROMOTED (never
 * duplicated); n==1 → the leaf itself. Caller guarantees n >= 1.
 * (Same construction as ledger_roots_v2.c / domain_wire.c — kept local
 * so this file compiles standalone into both trees.) */
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

/* ══════════════════════════════════════════════════════════════════════
 * 1. GenesisManifest v1
 * ════════════════════════════════════════════════════════════════════ */

/* Fixed byte counts (header layout table). */
#define GMAN_HEAD_LEN        14   /* version(4) + supply(8) + count(2)   */
#define GMAN_DOMREF_LEN      68   /* id(4) + hash(64)                    */
#define GMAN_DIST_FIXED_LEN  138  /* everything in the dist section
                                   * except the three variable byte runs
                                   * (target_asset_ref / source_tag /
                                   * source_commit)                      */

int dna_gman_validate(const dna_gman_t *m) {
    if (!m) return -1;
    if (m->manifest_version != DNA_GMAN_VERSION) return -1;
    if (m->domain_count < 1 || m->domain_count > DNA_GMAN_MAX_DOMAINS)
        return -1;
    if (m->domains[0].domain_id != DNA_DOMAIN_SYSTEM) return -1;
    for (uint16_t i = 1; i < m->domain_count; i++)
        if (m->domains[i - 1].domain_id >= m->domains[i].domain_id)
            return -1;

    if (m->dist_present == 0) {
        /* NO hidden defaults: an absent section must be ALL zero. */
        static const uint8_t zroot[DNA_V2_ROOT_LEN] = {0};
        static const uint8_t ztag[DNA_GMAN_SRCTAG_MAX] = {0};
        static const uint8_t zcommit[DNA_GMAN_SRCCOMMIT_MAX] = {0};
        static const uint8_t zasset[DNA_GMAN_ASSETREF_MAX] = {0};
        if (m->dist_version != 0 || m->source_tag_len != 0 ||
            m->source_commit_len != 0 || m->leaf_count != 0 ||
            m->conv_numerator != 0 || m->conv_denominator != 0 ||
            m->rounding_mode != 0 || m->excluded_amount != 0 ||
            m->total_claimable != 0 || m->claim_start_height != 0 ||
            m->claim_end_height != 0 || m->auth_mode != 0 ||
            m->fee_mode != 0 || m->post_deadline_mode != 0 ||
            m->target_domain_id != 0 || m->target_asset_len != 0)
            return -1;
        if (memcmp(m->snapshot_root, zroot, sizeof(zroot)) != 0) return -1;
        if (memcmp(m->source_tag, ztag, sizeof(ztag)) != 0) return -1;
        if (memcmp(m->source_commit, zcommit, sizeof(zcommit)) != 0)
            return -1;
        if (memcmp(m->target_asset_ref, zasset, sizeof(zasset)) != 0)
            return -1;
        return 0;
    }
    if (m->dist_present != 1) return -1;       /* unknown presence value */

    if (m->dist_version != DNA_DIST_VERSION) return -1;
    /* target_domain_id: any registered u32 — registration, activation and
     * runtime compatibility are witness-side fail-closed checks; the
     * codec commits the EXPLICIT value (no structural default exists). */
    if (m->target_asset_len < 1 ||
        m->target_asset_len > DNA_GMAN_ASSETREF_MAX)
        return -1;
    if (m->source_tag_len < 1 || m->source_tag_len > DNA_GMAN_SRCTAG_MAX)
        return -1;
    if (m->source_commit_len > DNA_GMAN_SRCCOMMIT_MAX) return -1;
    if (m->leaf_count < 1 || m->leaf_count > DNA_DIST_MAX_LEAVES) return -1;
    if (m->conv_numerator < 1 || m->conv_denominator < 1) return -1;
    if (m->rounding_mode != DNA_DISTROUND_FLOOR) return -1;
    if (m->total_claimable < 1) return -1;
    /* NO total_claimable ⋚ genesis_supply comparison here: the two are
     * denominated in DIFFERENT units unless the target asset happens to
     * be the chain's native one — one asset equation is never applied
     * to heterogeneous targets. The native backing of a NATIVE-asset
     * distribution is enforced by the target runtime's conservation
     * invariant (supply gate), which rejects a lying manifest at
     * commit/genesis time. */
    if (m->claim_start_height > m->claim_end_height) return -1;
    if (m->auth_mode != DNA_CLAIMAUTH_DNA_NATIVE) return -1;
    if (m->fee_mode != DNA_CLAIMFEE_NONE) return -1;
    if (m->post_deadline_mode != DNA_POSTDL_RETAIN) return -1;
    return 0;
}

size_t dna_gman_encoded_len(const dna_gman_t *m) {
    if (dna_gman_validate(m) != 0) return 0;
    size_t len = GMAN_HEAD_LEN +
                 (size_t)m->domain_count * GMAN_DOMREF_LEN + 1;
    if (m->dist_present == 1)
        len += GMAN_DIST_FIXED_LEN + m->target_asset_len +
               m->source_tag_len + m->source_commit_len;
    return len;
}

int dna_gman_encode(const dna_gman_t *m,
                    uint8_t *dst, size_t cap, size_t *written) {
    if (!dst) return -1;
    size_t need = dna_gman_encoded_len(m);
    if (need == 0 || cap < need) return -1;

    uint8_t *p = dst;
    put_be32(m->manifest_version, p);      p += 4;
    put_be64(m->genesis_supply_raw, p);    p += 8;
    put_be16(m->domain_count, p);          p += 2;
    for (uint16_t i = 0; i < m->domain_count; i++) {
        put_be32(m->domains[i].domain_id, p);            p += 4;
        memcpy(p, m->domains[i].manifest_hash, 64);      p += 64;
    }
    *p++ = m->dist_present;
    if (m->dist_present == 1) {
        put_be32(m->dist_version, p);                    p += 4;
        put_be32(m->target_domain_id, p);                p += 4;
        put_be16(m->target_asset_len, p);                p += 2;
        memcpy(p, m->target_asset_ref, m->target_asset_len);
        p += m->target_asset_len;
        put_be16(m->source_tag_len, p);                  p += 2;
        memcpy(p, m->source_tag, m->source_tag_len);
        p += m->source_tag_len;
        put_be16(m->source_commit_len, p);               p += 2;
        memcpy(p, m->source_commit, m->source_commit_len);
        p += m->source_commit_len;
        memcpy(p, m->snapshot_root, 64);                 p += 64;
        put_be64(m->leaf_count, p);                      p += 8;
        put_be64(m->conv_numerator, p);                  p += 8;
        put_be64(m->conv_denominator, p);                p += 8;
        *p++ = m->rounding_mode;
        put_be64(m->excluded_amount, p);                 p += 8;
        put_be64(m->total_claimable, p);                 p += 8;
        put_be64(m->claim_start_height, p);              p += 8;
        put_be64(m->claim_end_height, p);                p += 8;
        *p++ = m->auth_mode;
        *p++ = m->fee_mode;
        *p++ = m->post_deadline_mode;
    }
    if ((size_t)(p - dst) != need) return -1;   /* internal invariant */
    if (written) *written = need;
    return 0;
}

int dna_gman_decode(const uint8_t *src, size_t len, dna_gman_t *out) {
    if (!src || !out) return -1;
    memset(out, 0, sizeof(*out));

    size_t off = 0;
    if (len < GMAN_HEAD_LEN) return -1;
    out->manifest_version = get_be32(src);       off += 4;
    out->genesis_supply_raw = get_be64(src + 4); off += 8;
    out->domain_count = get_be16(src + 12);      off += 2;
    if (out->domain_count < 1 || out->domain_count > DNA_GMAN_MAX_DOMAINS)
        return -1;
    if (len - off < (size_t)out->domain_count * GMAN_DOMREF_LEN + 1)
        return -1;
    for (uint16_t i = 0; i < out->domain_count; i++) {
        out->domains[i].domain_id = get_be32(src + off);       off += 4;
        memcpy(out->domains[i].manifest_hash, src + off, 64);  off += 64;
    }
    out->dist_present = src[off++];
    if (out->dist_present == 1) {
        if (len - off < 4 + 4 + 2) return -1;
        out->dist_version = get_be32(src + off);   off += 4;
        out->target_domain_id = get_be32(src + off); off += 4;
        out->target_asset_len = get_be16(src + off); off += 2;
        if (out->target_asset_len < 1 ||
            out->target_asset_len > DNA_GMAN_ASSETREF_MAX)
            return -1;
        if (len - off < (size_t)out->target_asset_len + 2) return -1;
        memcpy(out->target_asset_ref, src + off, out->target_asset_len);
        off += out->target_asset_len;
        out->source_tag_len = get_be16(src + off); off += 2;
        if (out->source_tag_len < 1 ||
            out->source_tag_len > DNA_GMAN_SRCTAG_MAX)
            return -1;
        if (len - off < (size_t)out->source_tag_len + 2) return -1;
        memcpy(out->source_tag, src + off, out->source_tag_len);
        off += out->source_tag_len;
        out->source_commit_len = get_be16(src + off); off += 2;
        if (out->source_commit_len > DNA_GMAN_SRCCOMMIT_MAX) return -1;
        /* remaining fixed bytes after the three variable runs:
         * 138 total fixed − ver(4) − target_dom(4) − assetlen(2)
         * − taglen(2) − commitlen(2) = 124 */
        if (len - off < (size_t)out->source_commit_len + 124) return -1;
        memcpy(out->source_commit, src + off, out->source_commit_len);
        off += out->source_commit_len;
        memcpy(out->snapshot_root, src + off, 64);   off += 64;
        out->leaf_count = get_be64(src + off);       off += 8;
        out->conv_numerator = get_be64(src + off);   off += 8;
        out->conv_denominator = get_be64(src + off); off += 8;
        out->rounding_mode = src[off++];
        out->excluded_amount = get_be64(src + off);  off += 8;
        out->total_claimable = get_be64(src + off);  off += 8;
        out->claim_start_height = get_be64(src + off); off += 8;
        out->claim_end_height = get_be64(src + off);   off += 8;
        out->auth_mode = src[off++];
        out->fee_mode = src[off++];
        out->post_deadline_mode = src[off++];
    } else if (out->dist_present != 0) {
        return -1;                              /* unknown presence value */
    }
    if (off != len) return -1;                  /* trailing bytes reject  */
    return dna_gman_validate(out);
}

int dna_gman_hash(const dna_gman_t *m, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!m || !out) return -1;
    size_t need = dna_gman_encoded_len(m);
    if (need == 0) return -1;
    uint8_t *pre = (uint8_t *)malloc(TAG_LEN + need);
    if (!pre) return -1;
    memcpy(pre, TAG_GMAN, TAG_LEN);
    size_t written = 0;
    if (dna_gman_encode(m, pre + TAG_LEN, need, &written) != 0 ||
        written != need) {
        free(pre);
        return -1;
    }
    int rc = qgp_sha3_512(pre, TAG_LEN + need, out);
    free(pre);
    return rc == 0 ? 0 : -1;
}

int dna_v2_manifest_root(const uint8_t (*manifest_hashes)[DNA_V2_ROOT_LEN],
                         size_t n, uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !manifest_hashes)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST, out);

    /* Strictly ascending manifest_hash bytes — the COMMITTED identity is
     * the canonical sort key (a database sequence number is a local
     * locator and never enters a consensus commitment). Rejects
     * duplicates AND any non-canonical order, so no input ordering can
     * influence the root. */
    for (size_t i = 1; i < n; i++)
        if (memcmp(manifest_hashes[i - 1], manifest_hashes[i],
                   DNA_V2_ROOT_LEN) >= 0)
            return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t pre[TAG_LEN + DNA_V2_ROOT_LEN];
        memcpy(pre, TAG_MANLEAF, TAG_LEN);
        memcpy(pre + TAG_LEN, manifest_hashes[i], DNA_V2_ROOT_LEN);
        if (qgp_sha3_512(pre, sizeof(pre), level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_MANNODE, level, n, out);
    free(level);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. DistributionLeaf v1 + snapshot tree + inclusion proofs
 * ════════════════════════════════════════════════════════════════════ */

int dna_dist_leaf_cmp(const dna_dist_leaf_t *a, const dna_dist_leaf_t *b) {
    uint16_t min = a->source_id_len < b->source_id_len
                       ? a->source_id_len : b->source_id_len;
    int c = memcmp(a->source_id, b->source_id, min);
    if (c != 0) return c;
    if (a->source_id_len < b->source_id_len) return -1;
    if (a->source_id_len > b->source_id_len) return 1;
    return 0;
}

int dna_dist_leaf_hash(const dna_dist_leaf_t *leaf,
                       uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!leaf || !out) return -1;
    if (leaf->leaf_version != DNA_DIST_VERSION) return -1;
    if (leaf->source_id_len < 1 ||
        leaf->source_id_len > DNA_DIST_SRCID_MAX)
        return -1;
    if (leaf->source_amount < 1) return -1;

    uint8_t pre[TAG_LEN + 4 + 2 + DNA_DIST_SRCID_MAX + 8 +
                DNA_V2_ROOT_LEN];
    uint8_t *p = pre;
    memcpy(p, TAG_DSLEAF, TAG_LEN);              p += TAG_LEN;
    put_be32(leaf->leaf_version, p);             p += 4;
    put_be16(leaf->source_id_len, p);            p += 2;
    memcpy(p, leaf->source_id, leaf->source_id_len);
    p += leaf->source_id_len;
    put_be64(leaf->source_amount, p);            p += 8;
    memcpy(p, leaf->dest_binding, DNA_V2_ROOT_LEN);
    p += DNA_V2_ROOT_LEN;
    return qgp_sha3_512(pre, (size_t)(p - pre), out) == 0 ? 0 : -1;
}

int dna_dist_converted(uint64_t source_amount,
                       uint64_t conv_numerator,
                       uint64_t conv_denominator,
                       uint8_t  rounding_mode,
                       uint64_t *out) {
    if (!out) return -1;
    if (source_amount < 1 || conv_numerator < 1 || conv_denominator < 1)
        return -1;
    if (rounding_mode != DNA_DISTROUND_FLOOR) return -1;   /* fail-closed */
    /* CHECKED multiply: overflow is a deterministic v1 reject. */
    if (source_amount > UINT64_MAX / conv_numerator) return -1;
    uint64_t v = (source_amount * conv_numerator) / conv_denominator;
    if (v < 1) return -1;         /* zero-value claims cannot exist       */
    *out = v;
    return 0;
}

int dna_dist_snapshot_root(const dna_dist_leaf_t *leaves, size_t n,
                           uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!leaves || !out || n < 1 || (uint64_t)n > DNA_DIST_MAX_LEAVES)
        return -1;
    /* Strictly ascending canonical source_id order: rejects duplicates
     * AND non-canonical order — insertion order can never influence the
     * root because the only accepted order is the sorted one. */
    for (size_t i = 1; i < n; i++)
        if (dna_dist_leaf_cmp(&leaves[i - 1], &leaves[i]) >= 0) return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_dist_leaf_hash(&leaves[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_DSNODE, level, n, out);
    free(level);
    return rc;
}

int dna_dist_check_totals(const dna_dist_leaf_t *leaves, size_t n,
                          uint64_t conv_numerator,
                          uint64_t conv_denominator,
                          uint8_t  rounding_mode,
                          uint64_t total_claimable) {
    if (!leaves || n < 1) return -1;
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t v = 0;
        if (dna_dist_converted(leaves[i].source_amount, conv_numerator,
                               conv_denominator, rounding_mode, &v) != 0)
            return -1;
        if (v > UINT64_MAX - sum) return -1;    /* checked add           */
        sum += v;
    }
    return sum == total_claimable ? 0 : -1;
}

int dna_dist_proof_build(const uint8_t (*leaf_hashes)[DNA_V2_ROOT_LEN],
                         size_t n, uint64_t index,
                         uint8_t (*siblings)[DNA_V2_ROOT_LEN],
                         uint16_t *n_siblings) {
    if (!leaf_hashes || !siblings || !n_siblings) return -1;
    if (n < 1 || (uint64_t)n > DNA_DIST_MAX_LEAVES || index >= (uint64_t)n)
        return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    memcpy(level, leaf_hashes, n * sizeof(*level));

    size_t w = n, pos = (size_t)index;
    uint16_t ns = 0;
    while (w > 1) {
        if ((pos & 1) == 1) {                       /* sibling on the left */
            if (ns >= DNA_DIST_PROOF_MAX) { free(level); return -1; }
            memcpy(siblings[ns++], level[pos - 1], DNA_V2_ROOT_LEN);
        } else if (pos + 1 < w) {                   /* sibling on the right */
            if (ns >= DNA_DIST_PROOF_MAX) { free(level); return -1; }
            memcpy(siblings[ns++], level[pos + 1], DNA_V2_ROOT_LEN);
        }
        /* else: promoted — no sibling at this level */

        size_t next = 0;
        for (size_t i = 0; i + 1 < w; i += 2) {
            uint8_t pre[TAG_LEN + 2 * DNA_V2_ROOT_LEN];
            memcpy(pre, TAG_DSNODE, TAG_LEN);
            memcpy(pre + TAG_LEN, level[i], DNA_V2_ROOT_LEN);
            memcpy(pre + TAG_LEN + DNA_V2_ROOT_LEN, level[i + 1],
                   DNA_V2_ROOT_LEN);
            if (qgp_sha3_512(pre, sizeof(pre), level[next]) != 0) {
                free(level);
                return -1;
            }
            next++;
        }
        if (w & 1) {
            memcpy(level[next], level[w - 1], DNA_V2_ROOT_LEN);
            next++;
        }
        pos >>= 1;
        w = next;
    }
    free(level);
    *n_siblings = ns;
    return 0;
}

int dna_dist_proof_verify(const uint8_t root[DNA_V2_ROOT_LEN],
                          const uint8_t leaf_hash[DNA_V2_ROOT_LEN],
                          uint64_t index, uint64_t leaf_count,
                          const uint8_t (*siblings)[DNA_V2_ROOT_LEN],
                          uint16_t n_siblings) {
    if (!root || !leaf_hash || (n_siblings > 0 && !siblings)) return -1;
    if (leaf_count < 1 || leaf_count > DNA_DIST_MAX_LEAVES) return -1;
    if (index >= leaf_count) return -1;
    if (n_siblings > DNA_DIST_PROOF_MAX) return -1;

    uint8_t cur[DNA_V2_ROOT_LEN];
    memcpy(cur, leaf_hash, DNA_V2_ROOT_LEN);

    uint64_t w = leaf_count, pos = index;
    uint16_t used = 0;
    while (w > 1) {
        /* The tree SHAPE (pair vs promote) is a pure function of
         * (pos, w) — the proof supplies hashes only, never structure. */
        if ((pos & 1) == 1) {                       /* we are the right   */
            if (used >= n_siblings) return -1;
            uint8_t pre[TAG_LEN + 2 * DNA_V2_ROOT_LEN];
            memcpy(pre, TAG_DSNODE, TAG_LEN);
            memcpy(pre + TAG_LEN, siblings[used], DNA_V2_ROOT_LEN);
            memcpy(pre + TAG_LEN + DNA_V2_ROOT_LEN, cur, DNA_V2_ROOT_LEN);
            if (qgp_sha3_512(pre, sizeof(pre), cur) != 0) return -1;
            used++;
        } else if (pos + 1 < w) {                   /* we are the left    */
            if (used >= n_siblings) return -1;
            uint8_t pre[TAG_LEN + 2 * DNA_V2_ROOT_LEN];
            memcpy(pre, TAG_DSNODE, TAG_LEN);
            memcpy(pre + TAG_LEN, cur, DNA_V2_ROOT_LEN);
            memcpy(pre + TAG_LEN + DNA_V2_ROOT_LEN, siblings[used],
                   DNA_V2_ROOT_LEN);
            if (qgp_sha3_512(pre, sizeof(pre), cur) != 0) return -1;
            used++;
        }
        /* else: promoted unchanged — consume nothing */
        pos >>= 1;
        w = (w >> 1) + (w & 1);
    }
    if (used != n_siblings) return -1;          /* count must match shape */
    return memcmp(cur, root, DNA_V2_ROOT_LEN) == 0 ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * 3. Claim v1
 * ════════════════════════════════════════════════════════════════════ */

int dna_claim_validate(const dna_claim_t *c) {
    if (!c) return -1;
    if (c->claim_version != DNA_CLAIM_VERSION) return -1;
    if (c->source_id_len < 1 || c->source_id_len > DNA_DIST_SRCID_MAX)
        return -1;
    if (c->source_amount < 1) return -1;
    if (c->n_siblings > DNA_DIST_PROOF_MAX) return -1;
    if (c->auth_mode != DNA_CLAIMAUTH_DNA_NATIVE) return -1;
    return 0;
}

size_t dna_claim_encoded_len(const dna_claim_t *c) {
    if (dna_claim_validate(c) != 0) return 0;
    return (size_t)DNA_CLAIM_FIXED_LEN + c->source_id_len +
           (size_t)c->n_siblings * DNA_V2_ROOT_LEN;
}

int dna_claim_encode(const dna_claim_t *c,
                     uint8_t *dst, size_t cap, size_t *written) {
    if (!dst) return -1;
    size_t need = dna_claim_encoded_len(c);
    if (need == 0 || cap < need) return -1;

    uint8_t *p = dst;
    put_be32(c->claim_version, p);                     p += 4;
    memcpy(p, c->chain_id, DNA_CHAIN_ID_LEN);          p += DNA_CHAIN_ID_LEN;
    memcpy(p, c->manifest_hash, DNA_V2_ROOT_LEN);      p += DNA_V2_ROOT_LEN;
    put_be64(c->leaf_index, p);                        p += 8;
    put_be16(c->source_id_len, p);                     p += 2;
    memcpy(p, c->source_id, c->source_id_len);         p += c->source_id_len;
    put_be64(c->source_amount, p);                     p += 8;
    memcpy(p, c->dest_binding, DNA_V2_ROOT_LEN);       p += DNA_V2_ROOT_LEN;
    put_be16(c->n_siblings, p);                        p += 2;
    for (uint16_t i = 0; i < c->n_siblings; i++) {
        memcpy(p, c->siblings[i], DNA_V2_ROOT_LEN);
        p += DNA_V2_ROOT_LEN;
    }
    *p++ = c->auth_mode;
    memcpy(p, c->pubkey, DNA_CLAIM_PUBKEY_LEN);        p += DNA_CLAIM_PUBKEY_LEN;
    memcpy(p, c->signature, DNA_CLAIM_SIG_LEN);        p += DNA_CLAIM_SIG_LEN;
    if ((size_t)(p - dst) != need) return -1;
    if (written) *written = need;
    return 0;
}

int dna_claim_decode(const uint8_t *src, size_t len, dna_claim_t *out) {
    if (!src || !out) return -1;
    memset(out, 0, sizeof(*out));

    size_t off = 0;
    if (len < 4 + DNA_CHAIN_ID_LEN + DNA_V2_ROOT_LEN + 8 + 2) return -1;
    out->claim_version = get_be32(src);          off += 4;
    memcpy(out->chain_id, src + off, DNA_CHAIN_ID_LEN);
    off += DNA_CHAIN_ID_LEN;
    memcpy(out->manifest_hash, src + off, DNA_V2_ROOT_LEN);
    off += DNA_V2_ROOT_LEN;
    out->leaf_index = get_be64(src + off);       off += 8;
    out->source_id_len = get_be16(src + off);    off += 2;
    if (out->source_id_len < 1 || out->source_id_len > DNA_DIST_SRCID_MAX)
        return -1;
    if (len - off < (size_t)out->source_id_len + 8 + DNA_V2_ROOT_LEN + 2)
        return -1;
    memcpy(out->source_id, src + off, out->source_id_len);
    off += out->source_id_len;
    out->source_amount = get_be64(src + off);    off += 8;
    memcpy(out->dest_binding, src + off, DNA_V2_ROOT_LEN);
    off += DNA_V2_ROOT_LEN;
    out->n_siblings = get_be16(src + off);       off += 2;
    if (out->n_siblings > DNA_DIST_PROOF_MAX) return -1;
    if (len - off < (size_t)out->n_siblings * DNA_V2_ROOT_LEN + 1 +
                        DNA_CLAIM_PUBKEY_LEN + DNA_CLAIM_SIG_LEN)
        return -1;
    for (uint16_t i = 0; i < out->n_siblings; i++) {
        memcpy(out->siblings[i], src + off, DNA_V2_ROOT_LEN);
        off += DNA_V2_ROOT_LEN;
    }
    out->auth_mode = src[off++];
    memcpy(out->pubkey, src + off, DNA_CLAIM_PUBKEY_LEN);
    off += DNA_CLAIM_PUBKEY_LEN;
    memcpy(out->signature, src + off, DNA_CLAIM_SIG_LEN);
    off += DNA_CLAIM_SIG_LEN;
    if (off != len) return -1;                  /* trailing bytes reject  */
    return dna_claim_validate(out);
}

int dna_claim_preimage(const dna_claim_t *c,
                       uint8_t out[DNA_CLAIM_PREIMAGE_MAX],
                       size_t *out_len) {
    if (!c || !out || !out_len) return -1;
    if (dna_claim_validate(c) != 0) return -1;

    uint8_t *p = out;
    memcpy(p, TAG_CLAIM, TAG_LEN);                     p += TAG_LEN;
    put_be32(c->claim_version, p);                     p += 4;
    memcpy(p, c->chain_id, DNA_CHAIN_ID_LEN);          p += DNA_CHAIN_ID_LEN;
    memcpy(p, c->manifest_hash, DNA_V2_ROOT_LEN);      p += DNA_V2_ROOT_LEN;
    put_be64(c->leaf_index, p);                        p += 8;
    put_be16(c->source_id_len, p);                     p += 2;
    memcpy(p, c->source_id, c->source_id_len);         p += c->source_id_len;
    put_be64(c->source_amount, p);                     p += 8;
    memcpy(p, c->dest_binding, DNA_V2_ROOT_LEN);       p += DNA_V2_ROOT_LEN;
    *out_len = (size_t)(p - out);
    return 0;
}

int dna_claim_nullifier(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                        const uint8_t manifest_hash[DNA_V2_ROOT_LEN],
                        uint32_t target_domain_id,
                        const uint8_t *target_asset_ref,
                        uint16_t target_asset_len,
                        const uint8_t leaf_hash[DNA_V2_ROOT_LEN],
                        uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!chain_id || !manifest_hash || !target_asset_ref || !leaf_hash ||
        !out)
        return -1;
    if (target_asset_len < 1 || target_asset_len > DNA_GMAN_ASSETREF_MAX)
        return -1;
    uint8_t pre[TAG_LEN + DNA_CHAIN_ID_LEN + DNA_V2_ROOT_LEN + 4 + 2 +
                DNA_GMAN_ASSETREF_MAX + DNA_V2_ROOT_LEN];
    uint8_t *p = pre;
    memcpy(p, TAG_CLNUL, TAG_LEN);               p += TAG_LEN;
    memcpy(p, chain_id, DNA_CHAIN_ID_LEN);       p += DNA_CHAIN_ID_LEN;
    memcpy(p, manifest_hash, DNA_V2_ROOT_LEN);   p += DNA_V2_ROOT_LEN;
    put_be32(target_domain_id, p);               p += 4;
    put_be16(target_asset_len, p);               p += 2;
    memcpy(p, target_asset_ref, target_asset_len);
    p += target_asset_len;
    memcpy(p, leaf_hash, DNA_V2_ROOT_LEN);       p += DNA_V2_ROOT_LEN;
    return qgp_sha3_512(pre, (size_t)(p - pre), out) == 0 ? 0 : -1;
}

int dna_claim_utxo_id(const uint8_t nullifier[DNA_V2_ROOT_LEN],
                      uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!nullifier || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_ROOT_LEN];
    memcpy(pre, TAG_CLUTXO, TAG_LEN);
    memcpy(pre + TAG_LEN, nullifier, DNA_V2_ROOT_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * 4. claims_root
 * ════════════════════════════════════════════════════════════════════ */

int dna_claims_leaf_hash(const dna_claims_entry_t *e,
                         uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!e || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_V2_ROOT_LEN + DNA_V2_ROOT_LEN + 4 + 8 + 8 +
                8];
    uint8_t *p = pre;
    memcpy(p, TAG_CLLEAF, TAG_LEN);                    p += TAG_LEN;
    memcpy(p, e->nullifier, DNA_V2_ROOT_LEN);          p += DNA_V2_ROOT_LEN;
    memcpy(p, e->manifest_hash, DNA_V2_ROOT_LEN);      p += DNA_V2_ROOT_LEN;
    put_be32(e->target_domain_id, p);                  p += 4;
    put_be64(e->leaf_index, p);                        p += 8;
    put_be64(e->amount, p);                            p += 8;
    put_be64(e->claimed_height, p);                    p += 8;
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_claims_root(const dna_claims_entry_t *entries, size_t n,
                    uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !entries)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, out);

    /* Strictly ascending nullifier bytes: rejects duplicates AND any
     * non-canonical order — the root is insertion-order independent
     * because the only accepted order is the sorted one. */
    for (size_t i = 1; i < n; i++)
        if (memcmp(entries[i - 1].nullifier, entries[i].nullifier,
                   DNA_V2_ROOT_LEN) >= 0)
            return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    for (size_t i = 0; i < n; i++) {
        if (dna_claims_leaf_hash(&entries[i], level[i]) != 0) {
            free(level);
            return -1;
        }
    }
    int rc = tagged_merkle(TAG_CLNODE, level, n, out);
    free(level);
    return rc;
}
