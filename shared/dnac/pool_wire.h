/**
 * @file shared/dnac/pool_wire.h
 * @brief Ledger V2 Season 7 — canonical shielded-pool state commitments
 *        (INACTIVE).
 *
 * Canonical hashing for per-domain/per-pool shielded-pool state: the
 * versioned pool configuration hash, the pool state leaf, the per-domain
 * pools_root Merkle, the incremental nullifier-set commitment and the
 * bounded finalized-root-history commitment.
 *
 * ACTIVATION: nothing in live consensus calls any function here. Type 11
 * remains consensus-REJECTED (C3 stop); tx types 12-14 stay UNASSIGNED.
 * The V2 hierarchy activates only with the Ledger V2 devnet reset.
 *
 * Conventions (S2 charter, ledger_roots_v2.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, big-endian;
 *   - no native struct serialization;
 *   - iterated collections sorted by their canonical key, duplicates
 *     reject;
 *   - EMPTY sets are TAGGED roots (SHA3-512 of the tag alone);
 *   - any missing/unreadable component fails the whole computation (-1).
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded) ────────────────────
 *   "DNA.POOLCFG.v1"   pool configuration hash
 *   "DNA.POOLLEAF.v1"  pool state leaf
 *   "DNA.POOLNODE.v1"  pools Merkle inner node
 *   "DNA.PNUL.v1"      nullifier-set accumulator step
 *   "DNA.E.PNUL.v1"    EMPTY nullifier-set root
 *   "DNA.PHIST.v1"     root-history accumulator step
 *   "DNA.E.PHIST.v1"   EMPTY root-history commitment
 *   (the EMPTY pools_root is the frozen S2 "DNA.E.POOLS.v1" —
 *    dna_v2_empty_root(DNA_V2_EMPTY_POOLS), ledger_roots_v2.h)
 *
 * ── Note-root representation ──────────────────────────────────────────
 * A D=24 note-tree root/commitment/nullifier is 4 Goldilocks lanes.
 * Canonical byte form everywhere in this codec: 32 bytes = 4 × u64
 * BIG-ENDIAN, every lane canonical (< GOLDILOCKS_P) — the SAME encoding
 * the shielded TX wire uses for anchor/nf_set/output_commit lanes
 * (dnac/include/dnac/transaction.h:81-114). The empty D=24 root is the
 * shielded_tree E_24 value (shared/crypto/zk/shielded_tree.h) encoded
 * this way; this codec treats all three as OPAQUE canonical 32-byte
 * values and never recomputes the inner Poseidon2 hash.
 *
 * ── Exact preimages ───────────────────────────────────────────────────
 *   config_hash = SHA3-512("DNA.POOLCFG.v1" ‖ domain_id(4 BE)
 *       ‖ pool_id(4 BE) ‖ config_version(4 BE) ‖ tree_depth(1)
 *       ‖ history_limit(4 BE) ‖ asset_ref_len(2 BE) ‖ asset_ref)
 *       — hashed preimage INCLUDING the 16-byte tag =
 *         16+4+4+4+1+4+2 = 35 fixed bytes + asset_ref_len bytes
 *         (DNA_POOL_CFG_PREIMAGE_FIXED_LEN); the initial 64-byte
 *         asset reference yields 99 bytes total
 *   pool leaf   = SHA3-512("DNA.POOLLEAF.v1" ‖ domain_id(4 BE)
 *       ‖ pool_id(4 BE) ‖ config_hash[64] ‖ note_root[32]
 *       ‖ note_count(8 BE) ‖ nul_root[64] ‖ nul_count(8 BE)
 *       ‖ balance(8 BE) ‖ hist_commit[64] ‖ hist_count(8 BE)
 *       ‖ hist_next_seq(8 BE))
 *       — field payload EXCLUDING the tag: 4+4+64+32+8+64+8+8+64+8+8
 *         = 272 bytes; the COMPLETE hashed preimage INCLUDING the
 *         16-byte tag = 288 bytes (DNA_POOL_LEAF_PREIMAGE_LEN;
 *         compile-time-asserted and runtime-checked in pool_wire.c)
 *   pools inner = SHA3-512("DNA.POOLNODE.v1" ‖ left[64] ‖ right[64])
 *   nul step    = SHA3-512("DNA.PNUL.v1" ‖ prev_root[64]
 *       ‖ position(8 BE) ‖ nullifier[32])
 *   empty nul   = SHA3-512("DNA.E.PNUL.v1" tag alone)
 *   hist step   = SHA3-512("DNA.PHIST.v1" ‖ prev[64] ‖ seq(8 BE)
 *       ‖ note_root[32])
 *   empty hist  = SHA3-512("DNA.E.PHIST.v1" tag alone)
 *
 * The nullifier-set commitment is an INCREMENTAL sequential accumulator:
 * O(1) per insertion, chained over the canonical insertion order
 * (position 0,1,2,…) — never an unbounded full-set rehash per block.
 * The history commitment chains over the RETAINED window (≤ the
 * consensus-committed history_limit entries, ascending seq) starting
 * from the empty commitment — bounded per block by construction.
 *
 * ── Merkle construction (pools_root, per domain) ──────────────────────
 * Same rules as every S2 tree (ledger_roots_v2.h): leaves are the
 * already-tagged pool leaf hashes in STRICTLY ascending pool_id order
 * (equal or descending neighbours reject); inner nodes use
 * "DNA.POOLNODE.v1"; an unpaired odd node is PROMOTED unchanged;
 * n == 1 → the single leaf; n == 0 → the frozen S2 tagged-empty
 * pools_root (DNA_V2_EMPTY_POOLS) so a runtime with zero pools is
 * byte-identical to every pre-S7 chain.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_POOL_WIRE_H
#define SHARED_DNAC_POOL_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNA_POOL_ROOT_LEN      64  /* SHA3-512 outer commitments          */
#define DNA_POOL_NOTE_LEN      32  /* 4 Goldilocks lanes, u64 BE          */
#define DNA_POOL_NULLIFIER_LEN 32  /* 4 Goldilocks lanes, u64 BE          */
#define DNA_POOL_ASSETREF_MAX  64  /* bounded opaque target_asset_ref     */

/** Canonical tag width (S2 rule — every preimage starts with a FIXED
 *  16-byte zero-padded ASCII tag). */
#define DNA_POOL_TAG_LEN       16

/** Pool-leaf FIELD payload, tag EXCLUDED:
 *  domain(4)+pool(4)+config_hash(64)+note_root(32)+note_count(8)
 *  +nul_root(64)+nul_count(8)+balance(8)+hist_commit(64)
 *  +hist_count(8)+hist_next_seq(8) = 272. */
#define DNA_POOL_LEAF_PAYLOAD_LEN \
    (4 + 4 + 64 + 32 + 8 + 64 + 8 + 8 + 64 + 8 + 8)

/** Complete hashed pool-leaf preimage, tag INCLUDED (= 288). */
#define DNA_POOL_LEAF_PREIMAGE_LEN \
    (DNA_POOL_TAG_LEN + DNA_POOL_LEAF_PAYLOAD_LEN)

/** Fixed part of the config-hash preimage, tag INCLUDED, asset_ref
 *  EXCLUDED: 16+4+4+4+1+4+2 = 35. The complete hashed preimage is
 *  35 + asset_ref_len bytes (99 for the initial 64-byte asset). */
#define DNA_POOL_CFG_PREIMAGE_FIXED_LEN \
    (DNA_POOL_TAG_LEN + 4 + 4 + 4 + 1 + 4 + 2)

/** The Goldilocks modulus the 4-lane canonicality check pins. Value
 *  mirrors shared/crypto/zk/field_goldilocks.h:36 (GOLDILOCKS_P); this
 *  header stays zk-include-free, and nodus_witness_v2_pools.c carries a
 *  _Static_assert proving the two literals are identical. */
#define DNA_POOL_FE_P ((uint64_t)0xFFFFFFFF00000001ULL)

/** The D=24 note-tree depth this codec's v1 pools commit. Mirrors
 *  SHIELDED_TREE_DEPTH (shared/crypto/zk/shielded_tree.h:46); pinned by
 *  a _Static_assert in nodus_witness_v2_pools.c. */
#define DNA_POOL_TREE_DEPTH_V1 24

/** Devnet-locked finalized-root-history window (S7): 720 DISTINCT
 *  finalized note roots retained per pool. Consensus-committed through
 *  the pool's versioned configuration (config_hash → pool leaf →
 *  pools_root). The MAINNET value remains OPEN (measurement-dependent)
 *  — S7 deliberately selects no mainnet number. */
#define DNA_POOL_HISTORY_DEVNET_V1 720u

/** @return 1 when the 32-byte value decodes as 4 canonical (< p)
 *  Goldilocks u64 BE lanes, 0 otherwise (NULL is 0). */
int dna_pool_lanes_canonical(const uint8_t b[DNA_POOL_NOTE_LEN]);

/* ── Versioned pool configuration ───────────────────────────────────── */

typedef struct {
    uint32_t domain_id;                 /* owning domain                 */
    uint32_t pool_id;                   /* unique INSIDE its domain      */
    uint32_t config_version;            /* pool-state/config version     */
    uint8_t  tree_depth;                /* D (v1: 24)                    */
    uint32_t history_limit;             /* retained finalized roots (R)  */
    uint16_t asset_ref_len;             /* 1..DNA_POOL_ASSETREF_MAX      */
    uint8_t  asset_ref[DNA_POOL_ASSETREF_MAX]; /* opaque, runtime-owned  */
} dna_pool_config_t;

/** Canonical config hash (preimage above). Fail-closed: NULL, zero or
 *  over-cap asset_ref_len, zero history_limit or zero tree_depth all
 *  reject. @return 0 / -1. */
int dna_pool_config_hash(const dna_pool_config_t *cfg,
                         uint8_t out[DNA_POOL_ROOT_LEN]);

/* ── Pool state leaf ────────────────────────────────────────────────── */

typedef struct {
    uint32_t domain_id;
    uint32_t pool_id;                   /* canonical pools_root key      */
    uint8_t  config_hash[DNA_POOL_ROOT_LEN];
    uint8_t  note_root[DNA_POOL_NOTE_LEN];   /* current D=24 root        */
    uint64_t note_count;                /* appended leaves == next pos   */
    uint8_t  nul_root[DNA_POOL_ROOT_LEN];    /* nullifier accumulator    */
    uint64_t nul_count;                 /* inserted nullifiers           */
    uint64_t balance;                   /* public aggregate pool balance */
    uint8_t  hist_commit[DNA_POOL_ROOT_LEN]; /* retained-window commit   */
    uint64_t hist_count;                /* retained entries (≤ limit)    */
    uint64_t hist_next_seq;             /* total finalized-root updates  */
} dna_pool_leaf_t;

/** Pool leaf hash (preimage above). @return 0 / -1. */
int dna_pool_leaf_hash(const dna_pool_leaf_t *leaf,
                       uint8_t out[DNA_POOL_ROOT_LEN]);

/**
 * pools_root over one domain's pool leaves. `leaves` MUST be strictly
 * ascending by pool_id (equal or descending neighbours reject — a
 * duplicate pool id and a non-canonical order are both rejected, so
 * insertion order can never influence the root). Every leaf's
 * domain_id must equal `domain_id` (a foreign domain's pool state can
 * never enter this root). n == 0 yields the frozen S2 tagged-empty
 * pools_root (DNA_V2_EMPTY_POOLS) byte-identically. @return 0 / -1.
 */
int dna_pools_root(uint32_t domain_id, const dna_pool_leaf_t *leaves,
                   size_t n, uint8_t out[DNA_POOL_ROOT_LEN]);

/* ── Nullifier-set accumulator ──────────────────────────────────────── */

/** Empty nullifier-set root = SHA3-512("DNA.E.PNUL.v1"). @return 0/-1. */
int dna_pool_nul_empty_root(uint8_t out[DNA_POOL_ROOT_LEN]);

/** One accumulator step: out = SHA3-512("DNA.PNUL.v1" ‖ prev ‖
 *  position(8 BE) ‖ nullifier[32]). The nullifier MUST be canonical
 *  (dna_pool_lanes_canonical) — a non-canonical value rejects.
 *  `out` may alias `prev`. @return 0 / -1. */
int dna_pool_nul_step(const uint8_t prev[DNA_POOL_ROOT_LEN],
                      uint64_t position,
                      const uint8_t nullifier[DNA_POOL_NULLIFIER_LEN],
                      uint8_t out[DNA_POOL_ROOT_LEN]);

/* ── Finalized-root-history commitment ──────────────────────────────── */

/** Empty history commitment = SHA3-512("DNA.E.PHIST.v1"). @return 0/-1. */
int dna_pool_hist_empty(uint8_t out[DNA_POOL_ROOT_LEN]);

/** One history step: out = SHA3-512("DNA.PHIST.v1" ‖ prev ‖ seq(8 BE) ‖
 *  note_root[32]). The root MUST be canonical. `out` may alias `prev`.
 *  @return 0 / -1. */
int dna_pool_hist_step(const uint8_t prev[DNA_POOL_ROOT_LEN],
                       uint64_t seq,
                       const uint8_t note_root[DNA_POOL_NOTE_LEN],
                       uint8_t out[DNA_POOL_ROOT_LEN]);

/**
 * Commitment over a RETAINED history window: seqs/roots must be
 * strictly ascending by seq and CONTIGUOUS (seq[i+1] == seq[i]+1 — the
 * retained window is always a contiguous newest-N range; a gap means a
 * non-canonical eviction and rejects). n == 0 yields the empty history
 * commitment. Every root must be canonical. @return 0 / -1.
 */
int dna_pool_hist_commit(const uint64_t *seqs,
                         const uint8_t (*roots)[DNA_POOL_NOTE_LEN],
                         size_t n, uint8_t out[DNA_POOL_ROOT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_POOL_WIRE_H */
