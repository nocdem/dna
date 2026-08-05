/**
 * @file shared/dnac/manifest_wire.h
 * @brief Ledger V2 Season 6 — generic genesis/distribution manifest,
 *        distribution snapshot tree, and generic claim codec (INACTIVE).
 *
 * One canonical shared implementation compiled identically into libdna and
 * libnodus (the chain_config_wire / tx_wire / domain_wire single-source
 * pattern). Five canonical objects:
 *
 *   1. GenesisManifest v1        — the versioned, chain-defining genesis
 *                                  manifest. Its canonical bytes are the
 *                                  EXPLICIT input of the genesis BlockID
 *                                  (block_v2.h) and therefore of the
 *                                  32-byte chain_id. Because chain_id is
 *                                  DERIVED from a hash over these bytes,
 *                                  the manifest deliberately contains NO
 *                                  chain_id field — embedding one would be
 *                                  circular.
 *   2. DistributionLeaf v1       — one generic snapshot entry: an opaque
 *                                  length-prefixed source identifier, a
 *                                  source amount, and a destination
 *                                  binding. Source-network metadata is
 *                                  OPAQUE COMMITTED DATA: consensus never
 *                                  imports or verifies source-chain
 *                                  cryptography.
 *   3. Inclusion proofs          — Merkle paths against the committed
 *                                  snapshot root; the path SHAPE is fully
 *                                  derived from (leaf_index, leaf_count),
 *                                  so proofs carry sibling hashes only
 *                                  (no malleable direction bytes).
 *   4. Claim v1                  — the generic claim object: leaf +
 *                                  proof + DNA-native authorization.
 *   5. claims_root / manifest_root — tagged Merkle commitments over the
 *                                  spent-claim set and the committed
 *                                  manifest set (empty sets reproduce the
 *                                  frozen S2 tagged-empty roots
 *                                  byte-identically).
 *
 * ACTIVATION: nothing in live consensus calls anything here. The active
 * chain keeps the v3 five-input state_root and the V1 block hash
 * byte-identical; Type 11 stays REJECT-only; types 12-14 stay UNASSIGNED
 * and inert. The claim path activates only with the Ledger V2 devnet
 * reset.
 *
 * GENERICITY (locked): Ledger V2 is strictly consumer-neutral. Only
 * SYSTEM and DNA_CORE exist initially. A future project supplies its own
 * manifest OUTSIDE Ledger V2; this codec validates it through the same
 * generic versioned path available to every project. No consumer name,
 * domain, allocation, policy value or special case appears here. Claim
 * authorization, fee handling, deadlines and post-deadline behavior are
 * VERSIONED MANIFEST PARAMETERS; unknown versions, modes or policy
 * values FAIL CLOSED.
 *
 * Conventions (identical discipline to domain_wire.h / vset_wire.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every hash preimage starts with a FIXED 16-byte zero-padded ASCII
 *     tag; fixed-width unsigned integers, BIG-ENDIAN; explicit lengths
 *     for every variable collection;
 *   - iterated sets strictly ascending by their canonical key (rejects
 *     duplicates AND non-canonical order — insertion order can never
 *     influence a root);
 *   - no native struct serialization; strict decode (truncation and
 *     trailing bytes both reject); presence bytes control field
 *     EXISTENCE — no hidden defaults;
 *   - unknown mandatory enum values are a DECODE reject (fail-closed);
 *     enum value 0 is INVALID everywhere (zeroed memory never decodes);
 *   - all arithmetic is CHECKED (mul/add overflow and underflow reject);
 *   - every failure path returns -1 and produces NO partial result.
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded; S6 JUDGMENT tags) ──
 *   "DNA.GMAN.v1"     genesis-manifest hash
 *   "DNA.MANLEAF.v1"  manifest_root leaf
 *   "DNA.MANNODE.v1"  manifest_root inner node
 *   "DNA.DSLEAF.v1"   distribution snapshot leaf
 *   "DNA.DSNODE.v1"   distribution snapshot inner node
 *   "DNA.CLAIM.v1"    claim signed preimage
 *   "DNA.CLNUL.v1"    spent-claim nullifier derivation
 *   "DNA.CLLEAF.v1"   claims_root leaf
 *   "DNA.CLNODE.v1"   claims_root inner node
 *   "DNA.CLUTXO.v1"   claim-output UTXO identity derivation
 *   "DNA.E.MANIF.v1"  EMPTY manifest_root (frozen since S2 —
 *                     dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST))
 *   "DNA.E.CLAIMS.v1" EMPTY claims_root (frozen since S2 —
 *                     dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS))
 *
 * ── GenesisManifest v1 canonical layout (BE, strict) ──────────────────
 *   off  0  manifest_version    u32  (= 1)
 *   off  4  genesis_supply_raw  u64  (raw base units; cross-checked
 *                                     against supply_tracking at commit)
 *   off 12  domain_count        u16  (1..DNA_GMAN_MAX_DOMAINS; the FIRST
 *                                     entry MUST be DNA_DOMAIN_SYSTEM;
 *                                     strictly ascending domain_id)
 *   off 14  [ domain_id u32 ‖ manifest_hash[64] ] × domain_count
 *            — the DomainManifest v1 hashes ("DNA.DOMMAN.v1",
 *              domain_wire.h — layout UNCHANGED by S6) of every initial
 *              domain. Initially exactly SYSTEM and DNA_CORE.
 *   then    dist_present        u8   (0 = no distribution section: NONE
 *                                     of the fields below exist on the
 *                                     wire AND the in-memory fields must
 *                                     be all-zero; 1 = all fields below
 *                                     present; any other value rejects)
 *   ── distribution section (present IFF dist_present == 1) ───────────
 *   dist_version        u32  (= 1)
 *   source_tag_len      u16  (1..DNA_GMAN_SRCTAG_MAX) ‖ source_tag
 *                            (OPAQUE source-network tag)
 *   source_commit_len   u16  (0..DNA_GMAN_SRCCOMMIT_MAX) ‖ source_commit
 *                            (OPAQUE source commitment metadata)
 *   snapshot_root[64]        (distribution snapshot tree root)
 *   leaf_count          u64  (1..DNA_DIST_MAX_LEAVES)
 *   conv_numerator      u64  (>= 1)
 *   conv_denominator    u64  (>= 1)
 *   rounding_mode       u8   (1 = FLOOR; only value in v1)
 *   excluded_amount     u64  (source units excluded from the snapshot —
 *                            committed reconstruction data)
 *   total_claimable     u64  (>= 1, destination base units; MUST equal
 *                            the checked sum of every leaf's converted
 *                            amount AND MUST be <= genesis_supply_raw)
 *   claim_start_height  u64  ┐ inclusive claim window
 *   claim_end_height    u64  ┘ (start <= end required)
 *   auth_mode           u8   (1 = DNA-native Dilithium5; only value)
 *   fee_mode            u8   (1 = NONE — a claim pays no fee; only value)
 *   post_deadline_mode  u8   (1 = RETAIN — late claims reject, the
 *                            remaining distribution state is retained
 *                            unchanged; only value. No automatic burn /
 *                            transfer / disposition exists in v1: any
 *                            such behavior is a FUTURE versioned mode
 *                            and this build fails closed on it.)
 *   manifest_hash = SHA3-512("DNA.GMAN.v1" ‖ the canonical bytes)
 *
 * ── manifest_root ─────────────────────────────────────────────────────
 *   leaf  = SHA3-512("DNA.MANLEAF.v1" ‖ manifest_seq u32 BE
 *                    ‖ manifest_hash[64])
 *   inner = SHA3-512("DNA.MANNODE.v1" ‖ left[64] ‖ right[64])
 *   leaves strictly ascending manifest_seq; odd node PROMOTED unchanged;
 *   n == 1 → the leaf; n == 0 → dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST)
 *   — byte-identical to the S2/S5 placeholder, so every pre-manifest
 *   chain's system_state_root is unchanged.
 *
 * ── DistributionLeaf v1 ───────────────────────────────────────────────
 *   leaf_hash = SHA3-512("DNA.DSLEAF.v1" ‖ leaf_version u32 (= 1)
 *       ‖ source_id_len u16 ‖ source_id (1..DNA_DIST_SRCID_MAX opaque
 *       bytes) ‖ source_amount u64 (>= 1) ‖ dest_binding[64])
 *   dest_binding = SHA3-512(recipient DNA-native Dilithium5 public key)
 *   — the same 64-byte identity whose lowercase-hex form is the existing
 *   128-char owner fingerprint (dnac wallet discipline).
 *
 *   Canonical order: length-aware byte-lexicographic on source_id
 *   (memcmp over the common prefix; a strict prefix sorts FIRST; equal
 *   bytes AND equal length = duplicate = reject).
 *
 *   Converted claim amount (v1, FLOOR):
 *     converted = floor(source_amount × conv_numerator / conv_denominator)
 *   computed with CHECKED u64 arithmetic — the multiplication rejects on
 *   overflow (a committed v1 limit, deterministic on every node) and the
 *   result MUST be >= 1 (a leaf that would round to zero belongs in
 *   excluded_amount, never in the snapshot).
 *
 * ── Snapshot tree + inclusion proofs ──────────────────────────────────
 *   leaves  = leaf hashes in canonical source_id order;
 *   inner   = SHA3-512("DNA.DSNODE.v1" ‖ left[64] ‖ right[64]);
 *   odd node PROMOTED unchanged (never duplicated); n == 1 → the leaf.
 *   A proof is the bottom-up sibling hash sequence; at every level the
 *   verifier derives from (position, width) whether a sibling exists
 *   (promoted nodes have none) and consumes EXACTLY the derived number
 *   of siblings — a count mismatch rejects.
 *   HONEST LABEL (pinned by test): promote-equivalent leaf counts (e.g.
 *   3 vs 4 at index 0 — the last sibling is a promoted leaf in one
 *   shape, an inner node in the other, with an IDENTICAL hash chain)
 *   verify identically. This is harmless by construction: leaf_count is
 *   COMMITTED manifest data (never claimer-supplied), it bounds
 *   leaf_index, and membership still requires hashing to the committed
 *   root. Shape-different counts reject via the sibling-count check.
 *
 * ── Claim v1 canonical layout (BE, strict) ────────────────────────────
 *   off  0  claim_version   u32 (= 1)
 *   off  4  chain_id[32]        (dna_bh2_derive_chain_id of the genesis
 *                                BlockID — binds the claim to ONE chain)
 *   off 36  manifest_seq    u32 (identifies the committed manifest)
 *   off 40  leaf_index      u64 (< the manifest's leaf_count)
 *   off 48  source_id_len   u16 ‖ source_id (1..DNA_DIST_SRCID_MAX)
 *   then    source_amount   u64
 *           dest_binding[64]
 *           n_siblings      u16 (0..DNA_DIST_PROOF_MAX) ‖ sibling[64] × n
 *           auth_mode       u8  (1 = DNA-native Dilithium5; must equal
 *                                the manifest's committed mode)
 *           pubkey[2592]        (ML-DSA-87 public key; SHA3-512(pubkey)
 *                                MUST equal the leaf's dest_binding —
 *                                destination substitution rejects)
 *           signature[4627]     (ML-DSA-87 over the signed preimage)
 *
 *   Signed preimage (variable length, tag-prefixed):
 *     "DNA.CLAIM.v1"(16) ‖ claim_version u32 ‖ chain_id[32]
 *     ‖ manifest_seq u32 ‖ leaf_index u64 ‖ source_id_len u16
 *     ‖ source_id ‖ source_amount u64 ‖ dest_binding[64]
 *   (The Merkle proof and the key material are NOT signed: the proof is
 *   verified against the committed snapshot root and the key is
 *   authenticated by hashing to dest_binding.)
 *
 *   Nullifier (spent-claim key) — derived from the COMMITTED LEAF
 *   CONTEXT only, independent of proof bytes and key material:
 *     SHA3-512("DNA.CLNUL.v1" ‖ chain_id[32] ‖ manifest_seq u32
 *              ‖ source_id_len u16 ‖ source_id)
 *   One leaf ⇒ one nullifier ⇒ claimable exactly once per chain and
 *   manifest; replay across chains or manifests changes the nullifier
 *   AND invalidates the signature.
 *
 *   Claim-output UTXO identity (deterministic):
 *     SHA3-512("DNA.CLUTXO.v1" ‖ nullifier[64])
 *
 * ── claims_root ───────────────────────────────────────────────────────
 *   leaf  = SHA3-512("DNA.CLLEAF.v1" ‖ nullifier[64] ‖ manifest_seq u32
 *                    ‖ leaf_index u64 ‖ amount u64 ‖ claimed_height u64)
 *   inner = SHA3-512("DNA.CLNODE.v1" ‖ left[64] ‖ right[64])
 *   leaves strictly ascending by nullifier bytes (so the root is
 *   INSERTION-ORDER INDEPENDENT by construction); odd node PROMOTED;
 *   n == 1 → the leaf; n == 0 → dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS) —
 *   byte-identical to the S2/S5 placeholder.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_MANIFEST_WIRE_H
#define SHARED_DNAC_MANIFEST_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"
#include "ledger_roots_v2.h"   /* DNA_V2_ROOT_LEN, tagged empty roots */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field widths / caps ────────────────────────────────────────────── */
#define DNA_GMAN_VERSION        1u
#define DNA_GMAN_MAX_DOMAINS    64
#define DNA_GMAN_SRCTAG_MAX     64
#define DNA_GMAN_SRCCOMMIT_MAX  256
#define DNA_DIST_VERSION        1u
#define DNA_DIST_SRCID_MAX      128
#define DNA_DIST_MAX_LEAVES     (1ull << 32)
#define DNA_DIST_PROOF_MAX      64     /* covers 2^32 leaves + promotion */
#define DNA_CLAIM_VERSION       1u
#define DNA_CLAIM_PUBKEY_LEN    2592   /* ML-DSA-87 public key           */
#define DNA_CLAIM_SIG_LEN       4627   /* ML-DSA-87 signature            */

/* ── Enums — 0 is INVALID everywhere (fail-closed on zeroed memory) ─── */
#define DNA_DISTROUND_INVALID   ((uint8_t)0)
#define DNA_DISTROUND_FLOOR     ((uint8_t)1)   /* only value in v1 */

#define DNA_CLAIMAUTH_INVALID   ((uint8_t)0)
#define DNA_CLAIMAUTH_DNA_NATIVE ((uint8_t)1)  /* Dilithium5; only value */

#define DNA_CLAIMFEE_INVALID    ((uint8_t)0)
#define DNA_CLAIMFEE_NONE       ((uint8_t)1)   /* only value in v1 */

#define DNA_POSTDL_INVALID      ((uint8_t)0)
#define DNA_POSTDL_RETAIN       ((uint8_t)1)   /* only value in v1 */

/* ══════════════════════════════════════════════════════════════════════
 * 1. GenesisManifest v1
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t domain_id;
    uint8_t  manifest_hash[DNA_V2_ROOT_LEN];   /* DNA.DOMMAN.v1 hash */
} dna_gman_domain_ref_t;

typedef struct {
    uint32_t manifest_version;                 /* must be 1               */
    uint64_t genesis_supply_raw;
    uint16_t domain_count;                     /* 1..DNA_GMAN_MAX_DOMAINS */
    dna_gman_domain_ref_t domains[DNA_GMAN_MAX_DOMAINS];
    uint8_t  dist_present;                     /* 0/1                     */
    /* distribution section — MUST be all-zero when dist_present == 0 */
    uint32_t dist_version;                     /* must be 1 when present  */
    uint16_t source_tag_len;                   /* 1..DNA_GMAN_SRCTAG_MAX  */
    uint8_t  source_tag[DNA_GMAN_SRCTAG_MAX];
    uint16_t source_commit_len;                /* 0..DNA_GMAN_SRCCOMMIT_MAX */
    uint8_t  source_commit[DNA_GMAN_SRCCOMMIT_MAX];
    uint8_t  snapshot_root[DNA_V2_ROOT_LEN];
    uint64_t leaf_count;                       /* 1..DNA_DIST_MAX_LEAVES  */
    uint64_t conv_numerator;                   /* >= 1                    */
    uint64_t conv_denominator;                 /* >= 1                    */
    uint8_t  rounding_mode;                    /* DNA_DISTROUND_*         */
    uint64_t excluded_amount;
    uint64_t total_claimable;                  /* >= 1, <= genesis supply */
    uint64_t claim_start_height;
    uint64_t claim_end_height;                 /* >= claim_start_height   */
    uint8_t  auth_mode;                        /* DNA_CLAIMAUTH_*         */
    uint8_t  fee_mode;                         /* DNA_CLAIMFEE_*          */
    uint8_t  post_deadline_mode;               /* DNA_POSTDL_*            */
} dna_gman_t;

/** Structural + canonical validation (the exact rule set encode and
 *  decode share — header table). @return 0 valid / -1. */
int dna_gman_validate(const dna_gman_t *m);

/** Exact encoded size of a VALID manifest, or 0 if encode would reject. */
size_t dna_gman_encoded_len(const dna_gman_t *m);

/** Canonical encode. Rejects (-1, dst untouched) anything validate
 *  rejects, plus a short dst. @param written optional. */
int dna_gman_encode(const dna_gman_t *m,
                    uint8_t *dst, size_t cap, size_t *written);

/** Strict decode: `len` must EXACTLY equal the length implied by the
 *  encoded counts and presence byte (truncation and trailing bytes both
 *  reject), then the full validate rule set applies. @return 0 / -1. */
int dna_gman_decode(const uint8_t *src, size_t len, dna_gman_t *out);

/** manifest_hash = SHA3-512("DNA.GMAN.v1" ‖ canonical bytes).
 *  Rejects an invalid manifest. @return 0 / -1. */
int dna_gman_hash(const dna_gman_t *m, uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * manifest_root over committed manifests, strictly ascending
 * manifest_seq (duplicates reject); n == 0 yields the frozen S2
 * tagged-empty root (DNA_V2_EMPTY_MANIFEST). @return 0 / -1.
 */
int dna_v2_manifest_root(const uint32_t *seqs,
                         const uint8_t (*manifest_hashes)[DNA_V2_ROOT_LEN],
                         size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/* ══════════════════════════════════════════════════════════════════════
 * 2. DistributionLeaf v1 + snapshot tree + inclusion proofs
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t leaf_version;                     /* must be 1               */
    uint16_t source_id_len;                    /* 1..DNA_DIST_SRCID_MAX   */
    uint8_t  source_id[DNA_DIST_SRCID_MAX];    /* OPAQUE                  */
    uint64_t source_amount;                    /* >= 1 (source units)     */
    uint8_t  dest_binding[DNA_V2_ROOT_LEN];    /* SHA3-512(recipient pk)  */
} dna_dist_leaf_t;

/** Canonical order: length-aware byte-lexicographic on source_id.
 *  @return <0, 0, >0 (0 = duplicate). Undefined only on NULL. */
int dna_dist_leaf_cmp(const dna_dist_leaf_t *a, const dna_dist_leaf_t *b);

/** leaf_hash per the header table. Rejects (-1) NULL, bad version,
 *  zero/over-cap source_id_len, zero source_amount. */
int dna_dist_leaf_hash(const dna_dist_leaf_t *leaf,
                       uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * Converted claim amount (v1 FLOOR rule, checked arithmetic).
 * Rejects (-1): NULL out, zero amount/numerator/denominator, unknown
 * rounding mode, u64 multiplication overflow, converted result == 0.
 */
int dna_dist_converted(uint64_t source_amount,
                       uint64_t conv_numerator,
                       uint64_t conv_denominator,
                       uint8_t  rounding_mode,
                       uint64_t *out);

/**
 * snapshot_root over leaves that MUST be strictly ascending in the
 * canonical source_id order (dna_dist_leaf_cmp < 0 between neighbours —
 * rejects duplicates AND non-canonical order). n must be >= 1: an empty
 * snapshot cannot be committed (dist_present == 0 is the way to commit
 * "no distribution"). @return 0 / -1.
 */
int dna_dist_snapshot_root(const dna_dist_leaf_t *leaves, size_t n,
                           uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * Checked-total consistency: Σ dna_dist_converted(leaf) over all leaves
 * (checked add) MUST equal total_claimable. @return 0 / -1 (any leaf
 * conversion failure, sum overflow, or mismatch).
 */
int dna_dist_check_totals(const dna_dist_leaf_t *leaves, size_t n,
                          uint64_t conv_numerator,
                          uint64_t conv_denominator,
                          uint8_t  rounding_mode,
                          uint64_t total_claimable);

/**
 * Build the inclusion proof for leaf `index` out of the n leaf hashes
 * (test/fixture helper — consensus only VERIFIES). `siblings` must hold
 * DNA_DIST_PROOF_MAX entries. @return 0 with *n_siblings set / -1.
 */
int dna_dist_proof_build(const uint8_t (*leaf_hashes)[DNA_V2_ROOT_LEN],
                         size_t n, uint64_t index,
                         uint8_t (*siblings)[DNA_V2_ROOT_LEN],
                         uint16_t *n_siblings);

/**
 * Verify an inclusion proof: recompute the root from (leaf_hash, index,
 * leaf_count) consuming EXACTLY the derived number of siblings (the
 * promoted-node shape is a function of index and leaf_count, so the
 * proof carries no direction bytes and a sibling-count mismatch
 * rejects). @return 0 valid / -1.
 */
int dna_dist_proof_verify(const uint8_t root[DNA_V2_ROOT_LEN],
                          const uint8_t leaf_hash[DNA_V2_ROOT_LEN],
                          uint64_t index, uint64_t leaf_count,
                          const uint8_t (*siblings)[DNA_V2_ROOT_LEN],
                          uint16_t n_siblings);

/* ══════════════════════════════════════════════════════════════════════
 * 3. Claim v1
 * ════════════════════════════════════════════════════════════════════ */

/* preimage = tag(16) + ver(4) + chain(32) + seq(4) + idx(8) + len(2)
 *          + source_id + amount(8) + dest(64) */
#define DNA_CLAIM_PREIMAGE_MAX \
    (16 + 4 + 32 + 4 + 8 + 2 + DNA_DIST_SRCID_MAX + 8 + 64)

#define DNA_CLAIM_FIXED_LEN \
    (4 + 32 + 4 + 8 + 2 + 8 + 64 + 2 + 1 + DNA_CLAIM_PUBKEY_LEN + \
     DNA_CLAIM_SIG_LEN)
#define DNA_CLAIM_MAX_WIRE \
    ((size_t)DNA_CLAIM_FIXED_LEN + DNA_DIST_SRCID_MAX + \
     (size_t)DNA_DIST_PROOF_MAX * DNA_V2_ROOT_LEN)

typedef struct {
    uint32_t claim_version;                    /* must be 1               */
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint32_t manifest_seq;
    uint64_t leaf_index;
    uint16_t source_id_len;                    /* 1..DNA_DIST_SRCID_MAX   */
    uint8_t  source_id[DNA_DIST_SRCID_MAX];
    uint64_t source_amount;
    uint8_t  dest_binding[DNA_V2_ROOT_LEN];
    uint16_t n_siblings;                       /* 0..DNA_DIST_PROOF_MAX   */
    uint8_t  siblings[DNA_DIST_PROOF_MAX][DNA_V2_ROOT_LEN];
    uint8_t  auth_mode;                        /* DNA_CLAIMAUTH_*         */
    uint8_t  pubkey[DNA_CLAIM_PUBKEY_LEN];
    uint8_t  signature[DNA_CLAIM_SIG_LEN];
} dna_claim_t;

/** Structural validation (versions, lengths, enum values). 0 / -1. */
int dna_claim_validate(const dna_claim_t *c);

/** Exact encoded size of a VALID claim, or 0 if encode would reject. */
size_t dna_claim_encoded_len(const dna_claim_t *c);

/** Canonical encode; rejects anything validate rejects + short dst. */
int dna_claim_encode(const dna_claim_t *c,
                     uint8_t *dst, size_t cap, size_t *written);

/** Strict decode (exact length; full validation). @return 0 / -1. */
int dna_claim_decode(const uint8_t *src, size_t len, dna_claim_t *out);

/** Build the tag-prefixed signed preimage. `out` must hold
 *  DNA_CLAIM_PREIMAGE_MAX. @return 0 with *out_len set / -1. */
int dna_claim_preimage(const dna_claim_t *c,
                       uint8_t out[DNA_CLAIM_PREIMAGE_MAX],
                       size_t *out_len);

/** Nullifier = SHA3-512("DNA.CLNUL.v1" ‖ chain_id ‖ manifest_seq
 *  ‖ source_id_len ‖ source_id). @return 0 / -1. */
int dna_claim_nullifier(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                        uint32_t manifest_seq,
                        const uint8_t *source_id, uint16_t source_id_len,
                        uint8_t out[DNA_V2_ROOT_LEN]);

/** Deterministic claim-output UTXO identity:
 *  SHA3-512("DNA.CLUTXO.v1" ‖ nullifier[64]). @return 0 / -1. */
int dna_claim_utxo_id(const uint8_t nullifier[DNA_V2_ROOT_LEN],
                      uint8_t out[DNA_V2_ROOT_LEN]);

/* ══════════════════════════════════════════════════════════════════════
 * 4. claims_root
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  nullifier[DNA_V2_ROOT_LEN];       /* canonical key           */
    uint32_t manifest_seq;
    uint64_t leaf_index;
    uint64_t amount;                           /* converted (dest units)  */
    uint64_t claimed_height;
} dna_claims_entry_t;

/** leaf = SHA3-512("DNA.CLLEAF.v1" ‖ the entry fields, header table). */
int dna_claims_leaf_hash(const dna_claims_entry_t *e,
                         uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * claims_root over entries STRICTLY ascending by nullifier bytes
 * (duplicates reject — so the root is insertion-order independent);
 * n == 0 yields the frozen S2 tagged-empty root (DNA_V2_EMPTY_CLAIMS).
 * @return 0 / -1.
 */
int dna_claims_root(const dna_claims_entry_t *entries, size_t n,
                    uint8_t out[DNA_V2_ROOT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_MANIFEST_WIRE_H */
