/**
 * @file shared/dnac/ledger_roots_v2.h
 * @brief Ledger V2 Season 2 — the tagged state-root hierarchy (INACTIVE).
 *
 * Canonical hashing for the V2 hierarchy: SYSTEM/CORE composition, the
 * generic DomainHead + domains_root Merkle, global_state_root, supply_root,
 * token_root, and the v2 epoch leaf (supply counters relocated OUT of the
 * epoch leaves into supply_root — committed exactly once).
 *
 * ACTIVATION: nothing in live consensus calls any function here. The active
 * chain keeps the v3 five-input state_root (nodus_witness_merkle.c) and the
 * V1 block hash byte-identical. The V2 hierarchy activates only with the
 * Ledger V2 devnet reset (Season 11).
 *
 * Conventions (architecture report §5.1, S2 charter §1):
 *   - SHA3-512 everywhere (qgp_sha3_512 — same digest in both trees);
 *   - every preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, big-endian;
 *   - no native struct serialization;
 *   - iterated collections sorted by their canonical key, duplicates reject;
 *   - EMPTY subtrees are TAGGED roots (SHA3-512 of the tag alone), never
 *     all-zero placeholders;
 *   - any missing/unreadable component fails the whole computation (-1) —
 *     no partial or fallback root is ever produced.
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded) ────────────────────
 *   composition   "DNA.SYS.v1"      system_state_root
 *                 "DNA.CORE.v1"     core_state_root
 *                 "DNA.GLOBAL.v1"   global_state_root
 *   supply        "DNA.SUPPLY.v1"   supply_root (leafless single hash)
 *   tokens        "DNA.TOKLEAF.v1"  token leaf
 *                 "DNA.TOKNODE.v1"  token Merkle inner node
 *   epoch (v2)    "DNA.EPOCH.v2"    epoch leaf (NO supply counters)
 *                 "DNA.EPNODE.v2"   epoch Merkle inner node
 *   domains       "DNA.DOMHEAD.v1"  DomainHead hash
 *                 "DNA.DOMNODE.v1"  domains Merkle inner node
 *   vset (S3)     "DNA.VSLEAF.v1"   validator-set snapshot leaf
 *                 "DNA.VSNODE.v1"   validator-set Merkle inner node
 *   empty roots   "DNA.E.VSET.v1"   validator_set_root   (EMPTY vset table)
 *                 "DNA.E.DOMREG.v1" domain_registry_root (until S4)
 *                 "DNA.E.MANIF.v1"  manifest_root        (until S6)
 *                 "DNA.E.POOLS.v1"  pools_root           (until S7)
 *                 "DNA.E.CLAIMS.v1" claims_root          (until S6)
 *                 "DNA.E.NAMES.v1"  name_root            (timing open, O-7)
 *                 "DNA.E.TOKENS.v1" token_root of an EMPTY registry
 *                 "DNA.E.EPOCH.v2"  epoch_root_v2 of an EMPTY epoch table
 *   (domains_root has NO empty tag: SYSTEM must always be present — an
 *    empty domain list is a hard error, not an empty tree.)
 *
 * ── Composition preimages (exact) ─────────────────────────────────────
 *   system_state_root = SHA3-512("DNA.SYS.v1"  ‖ validator_root[64]
 *       ‖ delegation_root[64] ‖ epoch_state_root_v2[64]
 *       ‖ chain_config_root[64] ‖ validator_set_root[64]
 *       ‖ domain_registry_root[64] ‖ manifest_root[64] ‖ supply_root[64])
 *   core_state_root   = SHA3-512("DNA.CORE.v1" ‖ utxo_root[64]
 *       ‖ token_root[64] ‖ pools_root[64] ‖ claims_root[64] ‖ name_root[64])
 *   global_state_root = SHA3-512("DNA.GLOBAL.v1" ‖ domains_root[64])
 *   supply_root       = SHA3-512("DNA.SUPPLY.v1" ‖ genesis_supply_raw(8 BE)
 *       ‖ total_minted_raw(8 BE) ‖ total_burned_raw(8 BE))
 *   DomainHead hash   = SHA3-512("DNA.DOMHEAD.v1" ‖ domain_id(4 BE)
 *       ‖ domain_state_root[64] ‖ domain_height(8 BE)
 *       ‖ last_updated_global_height(8 BE) ‖ ruleset_version(4 BE)
 *       ‖ status(1))                                  — 105-byte payload
 *   token leaf hash   = SHA3-512("DNA.TOKLEAF.v1" ‖ token_id[64]
 *       ‖ decimals(1) ‖ flags(1) ‖ supply(8 BE) ‖ block_height(8 BE)
 *       ‖ name_len(2 BE) ‖ name ‖ symbol_len(2 BE) ‖ symbol
 *       ‖ creator_len(2 BE) ‖ creator_fp)
 *     (tokens.timestamp is EXCLUDED: it is bound from the LOCAL wall clock
 *      at apply time (nodus_witness_db.c token_add time(NULL)) and is
 *      therefore node-divergent — hashing it would fork the root.)
 *   epoch v2 leaf     = SHA3-512("DNA.EPOCH.v2" ‖ epoch_start_height(8 BE)
 *       ‖ epoch_pool_accum(8 BE) ‖ snapshot_hash[64])
 *   vset leaf (S3)    = SHA3-512("DNA.VSLEAF.v1" ‖ epoch(8 BE)
 *       ‖ snapshot_hash[64])       — `epoch` is the EPOCH START HEIGHT and
 *       `snapshot_hash` is dna_vset_hash of the canonical snapshot bytes
 *       (shared/dnac/vset_wire.h). The snapshot BODY is never re-hashed
 *       here: the leaf binds the already-tagged snapshot commitment.
 *
 * ── Merkle construction (RFC6962-style, per tree) ─────────────────────
 *   leaves  = the already-tagged 64-byte hashes (DomainHead / token leaf /
 *             epoch leaf), in strictly ascending canonical-key order;
 *   inner   = SHA3-512(NODE_TAG[16] ‖ left[64] ‖ right[64]);
 *   an unpaired (odd) node is PROMOTED to the next level unchanged —
 *   the final leaf is NEVER duplicated;
 *   n == 1  → root = the single leaf hash;
 *   n == 0  → the tree's tagged EMPTY root (tokens/epoch) or an error
 *             (domains — SYSTEM mandatory).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_LEDGER_ROOTS_V2_H
#define SHARED_DNAC_LEDGER_ROOTS_V2_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNA_V2_ROOT_LEN 64

/* ── Tagged empty roots ─────────────────────────────────────────────── */
typedef enum {
    DNA_V2_EMPTY_VSET = 0,     /* validator_set_root   (S3)  */
    DNA_V2_EMPTY_DOMREG,       /* domain_registry_root (S4)  */
    DNA_V2_EMPTY_MANIFEST,     /* manifest_root        (S6)  */
    DNA_V2_EMPTY_POOLS,        /* pools_root           (S7)  */
    DNA_V2_EMPTY_CLAIMS,       /* claims_root          (S6)  */
    DNA_V2_EMPTY_NAMES,        /* name_root            (O-7) */
    DNA_V2_EMPTY_TOKENS,       /* empty token registry       */
    DNA_V2_EMPTY_EPOCH_V2,     /* empty epoch table          */
    DNA_V2_EMPTY__COUNT
} dna_v2_empty_kind_t;

/** SHA3-512 of the kind's 16-byte tag alone. @return 0 / -1. */
int dna_v2_empty_root(dna_v2_empty_kind_t kind, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── supply_root ────────────────────────────────────────────────────── */
int dna_v2_supply_root(uint64_t genesis_supply_raw,
                       uint64_t total_minted_raw,
                       uint64_t total_burned_raw,
                       uint8_t out[DNA_V2_ROOT_LEN]);

/* ── token_root ─────────────────────────────────────────────────────── */
#define DNA_V2_TOKEN_ID_LEN   64
#define DNA_V2_TOKEN_STR_MAX  1024  /* per-string sanity cap (name/symbol/fp) */

typedef struct {
    uint8_t     token_id[DNA_V2_TOKEN_ID_LEN];  /* canonical key */
    const char *name;        size_t name_len;
    const char *symbol;      size_t symbol_len;
    const char *creator_fp;  size_t creator_fp_len;
    uint8_t     decimals;
    uint8_t     flags;
    uint64_t    supply;
    uint64_t    block_height;
} dna_v2_token_leaf_t;

/** Leaf hash per the header table. @return 0 / -1 (NULL, over-cap string). */
int dna_v2_token_leaf_hash(const dna_v2_token_leaf_t *leaf,
                           uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * token_root over leaves that MUST be strictly ascending by token_id
 * (byte-lexicographic). Equal or descending neighbors reject (duplicate /
 * non-canonical order — insertion order can never influence the root
 * because the only accepted order is the sorted one). n == 0 yields the
 * tagged empty-tokens root. @return 0 / -1.
 */
int dna_v2_token_root(const dna_v2_token_leaf_t *leaves, size_t n,
                      uint8_t out[DNA_V2_ROOT_LEN]);

/* ── epoch_state_root_v2 (supply counters relocated to supply_root) ──── */
int dna_v2_epoch_leaf_hash(uint64_t epoch_start_height,
                           uint64_t epoch_pool_accum,
                           const uint8_t snapshot_hash[64],
                           uint8_t out[DNA_V2_ROOT_LEN]);

/** Root over v2 epoch leaf hashes, strictly ascending epoch_start order
 *  enforced by the caller passing key array; duplicates reject. n == 0
 *  yields the tagged empty-epoch root. */
int dna_v2_epoch_root(const uint64_t *epoch_starts,
                      const uint8_t (*leaf_hashes)[DNA_V2_ROOT_LEN],
                      size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── validator_set_root (S3) ────────────────────────────────────────── */

/**
 * Merkle root over the per-epoch validator-set snapshot commitments.
 *
 * leaf  = SHA3-512("DNA.VSLEAF.v1" ‖ epoch(8 BE) ‖ snapshot_hash[64])
 * inner = SHA3-512("DNA.VSNODE.v1" ‖ left[64] ‖ right[64])
 *
 * Same Merkle rules as every other tree here: `epochs` must be STRICTLY
 * ASCENDING (equal or descending neighbours reject — that covers both a
 * duplicate epoch and a non-canonical order, so insertion order can never
 * influence the root); an unpaired odd node is PROMOTED unchanged, never
 * duplicated; n == 1 yields the single leaf; n == 0 yields the existing
 * tagged empty root DNA_V2_EMPTY_VSET.
 *
 * `snapshot_hashes[i]` is the dna_vset_hash of the snapshot governing
 * epoch `epochs[i]`. This function never decodes a snapshot — it commits
 * to the hash the persistence layer already verified.
 *
 * @return 0 / -1 (NULL args, bad order, allocation or digest failure).
 */
int dna_v2_vset_root(const uint64_t *epochs,
                     const uint8_t (*snapshot_hashes)[DNA_V2_ROOT_LEN],
                     size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── DomainHead + domains_root ──────────────────────────────────────── */
typedef struct {
    uint32_t domain_id;
    uint8_t  domain_state_root[DNA_V2_ROOT_LEN];
    uint64_t domain_height;
    uint64_t last_updated_global_height;
    uint32_t ruleset_version;
    uint8_t  status;
} dna_v2_domain_head_t;

#define DNA_V2_DOMHEAD_ENC_LEN 89  /* id(4)+root(64)+h(8)+lu(8)+rv(4)+st(1) */

/** Canonical 89-byte field encoding (no tag; the tag joins in the hash). */
int dna_v2_domain_head_encode(const dna_v2_domain_head_t *head,
                              uint8_t out[DNA_V2_DOMHEAD_ENC_LEN]);

/** SHA3-512("DNA.DOMHEAD.v1" ‖ the 89 encoded bytes). */
int dna_v2_domain_head_hash(const dna_v2_domain_head_t *head,
                            uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * domains_root over a GENERIC domain list (any count ≥ 1 — never
 * hard-coded to two): strictly ascending domain_id (duplicates reject),
 * heads[0].domain_id MUST be DNA_DOMAIN_SYSTEM (SYSTEM always present).
 * Leaves are the DomainHead hashes; tree per the header's Merkle rules
 * with the "DNA.DOMNODE.v1" inner tag. @return 0 / -1.
 */
int dna_v2_domains_root(const dna_v2_domain_head_t *heads, size_t n,
                        uint8_t out[DNA_V2_ROOT_LEN]);

/* ── Composition ────────────────────────────────────────────────────── */
int dna_v2_system_root(const uint8_t validator_root[64],
                       const uint8_t delegation_root[64],
                       const uint8_t epoch_state_root_v2[64],
                       const uint8_t chain_config_root[64],
                       const uint8_t validator_set_root[64],
                       const uint8_t domain_registry_root[64],
                       const uint8_t manifest_root[64],
                       const uint8_t supply_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]);

int dna_v2_core_root(const uint8_t utxo_root[64],
                     const uint8_t token_root[64],
                     const uint8_t pools_root[64],
                     const uint8_t claims_root[64],
                     const uint8_t name_root[64],
                     uint8_t out[DNA_V2_ROOT_LEN]);

int dna_v2_global_root(const uint8_t domains_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]);

/* ── SYSTEM runtime-owned genesis payload root (Ledger V2 S5) ─────────
 *
 * Tag "DNA.SYSPAYL.v1" (16 bytes, zero-padded — S5 JUDGMENT tag).
 *
 *   system_payload_root = SHA3-512("DNA.SYSPAYL.v1" ‖ validator_root
 *       ‖ delegation_root ‖ epoch_state_root_v2 ‖ chain_config_root
 *       ‖ validator_set_root ‖ supply_root)
 *
 * This is dna_v2_system_root MINUS the two container legs
 * (domain_registry_root, manifest_root) under a DISTINCT tag. It exists
 * to break the genesis cycle: a DomainManifest's `genesis_state_root` is
 * defined as the domain's RUNTIME-OWNED genesis payload root — it never
 * covers a structure that commits that domain's own manifest, so
 *   payload → manifest hash → registry root → FINAL system root
 * is a DAG, not a cycle. (DNA_CORE has no such self-reference: its
 * payload root IS its full core_state_root — the generic rule holds
 * trivially.) The FINAL SYSTEM DomainHead.state_root remains the full
 * 8-leg dna_v2_system_root. */
int dna_v2_system_payload_root(const uint8_t validator_root[64],
                               const uint8_t delegation_root[64],
                               const uint8_t epoch_state_root_v2[64],
                               const uint8_t chain_config_root[64],
                               const uint8_t validator_set_root[64],
                               const uint8_t supply_root[64],
                               uint8_t out[DNA_V2_ROOT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_LEDGER_ROOTS_V2_H */
