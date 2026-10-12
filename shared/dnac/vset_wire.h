/**
 * @file shared/dnac/vset_wire.h
 * @brief Ledger V2 Season 3 — canonical validator-set snapshot codec (INACTIVE).
 *
 * A validator-set snapshot is the authoritative, hash-committed answer to
 * "who could vote on this block, and with which key". It is the object a
 * QC V2 certificate set is checked against (see qc_v2.h): a historical
 * block is verifiable forever because the KEY each voter used is frozen in
 * the snapshot the block header committed to, not looked up in the mutable
 * validators table.
 *
 * ACTIVATION (historical note, S3): when written, nothing in the live
 * consensus path called anything here and the chain kept the legacy
 * commit certificate and the five-input state_root. The five-input root
 * is DELETED (root-layout round K3, 2026-09-25); the snapshot hash now
 * reaches the chain's state root through validator_set_root, a leg of
 * the SYSTEM root ("NDS.SYS.v3", shared/dnac/ledger_roots_v2.h).
 *
 * Conventions (identical discipline to shared/dnac/ledger_roots_v2.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every hash preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, BIG-ENDIAN; counts are u16;
 *   - no native struct serialization — the wire layout below is the format;
 *   - malformed/oversized input is rejected BEFORE any allocation;
 *   - every failure path returns -1 and produces NO partial result.
 *
 * ── TAG ────────────────────────────────────────────────────────────────
 *   "NDS.VSET.v1"  (16 bytes, zero-padded) — snapshot hash domain.
 *
 * ── Canonical wire layout ──────────────────────────────────────────────
 *   header (DNA_VSET_HDR_LEN = 78 bytes)
 *     epoch              u64 BE      (8)
 *     active_count       u16 BE      (2)
 *     selection_ruleset  u32 BE      (4)
 *     sortition_seed     bytes      (64)
 *   then active_count × entry (DNA_VSET_ENTRY_LEN = 2642 bytes)
 *     voter_id           bytes      (32)
 *     pubkey             bytes    (2592)   Dilithium5 / ML-DSA-87
 *     total_stake        u64 BE      (8)
 *     self_bond          u64 BE      (8)
 *     commission_bps     u16 BE      (2)
 *
 *   snapshot_hash = SHA3-512("NDS.VSET.v1" ‖ the canonical bytes above)
 *
 * ── `epoch` SEMANTICS ──────────────────────────────────────────────────
 * `epoch` is the EPOCH START HEIGHT — the project's canonical epoch key,
 * the same value stored in validator_set_snapshots.epoch_start (schema:
 * nodus/src/witness/nodus_witness.c) and passed as `e_start` to
 * nodus_committee_compute_for_epoch. It is NOT an epoch ordinal.
 *
 * ── selection_ruleset ──────────────────────────────────────────────────
 * Records HOW the set was chosen, so a historical verifier can tell which
 * rule produced it without re-deriving state:
 *   0                          INVALID — never encoded, always rejected.
 *                              Zeroed memory must not decode as a valid
 *                              ruleset (fail-closed).
 *   DNA_VSET_RULESET_TOPN_V1   deterministic top-N by stake (the shipped
 *                              committee rule: stake DESC + state-seeded
 *                              tiebreak, nodus_witness_committee.c).
 *   DNA_VSET_RULESET_TOPN_V2   HF-6 validator-role set (design
 *                              2026-10-03-hf5-validator-owner-stake §6.5).
 *                              INERT: only the `_ex` functions with
 *                              max_ruleset = 2 accept it; the legacy
 *                              functions below still reject it.
 *   ≥ 3                        RESERVED. Not accepted by this release.
 *
 * `sortition_seed` is a committed-but-reserved 64-byte slot. Under
 * DNA_VSET_RULESET_TOPN_V1 the top-N rule consumes no seed, so the slot
 * MUST be all-zero — a nonzero seed under TOPN_V1 is rejected by both
 * encode and decode. The field exists now so that adding sortition later
 * changes the ruleset value, not the wire layout. TOPN_V2 keeps the same
 * rule (Kurultay #14 K6: 64 zero bytes, nonzero REJECTED).
 *
 * ── Ruleset 2 (TOPN_V2) — INERT, HF-6 slice 1 ─────────────────────────
 *   tag "NDS.VSET.v2" (16 bytes, zero-padded) — a v2 snapshot hashes
 *   under its own domain; the tag is chosen from the header's ruleset.
 *   header: identical 78-byte layout, selection_ruleset = 2.
 *   then active_count × entry (DNA_VSET_ENTRY_LEN_V2 = 2770 bytes)
 *     voter_id           bytes      (32)   = SHA3-512(consensus_pk)[0..31]
 *     validator_id       bytes      (64)
 *     owner_fp           bytes      (64)
 *     consensus_pk       bytes    (2592)   (the entry's `pubkey` field)
 *     total_stake        u64 BE      (8)
 *     self_bond          u64 BE      (8)
 *     commission_bps     u16 BE      (2)
 *   Encode AND decode reject: a duplicated voter_id, validator_id or
 *   consensus_pk; an all-zero validator_id or owner_fp (both are SHA3-512
 *   outputs in every legal state); a voter_id that is not
 *   SHA3-512(consensus_pk)[0..31] (recomputed, never repaired). Ruleset 1 does NOT recompute voter_id
 *   (unchanged behaviour), and its encoder rejects a nonzero
 *   validator_id / owner_fp (v1 has no slot for them — fail closed, never
 *   dropped silently); the v1 decoder leaves both zero.
 *
 * ── HONEST LABEL: what decode does NOT check ───────────────────────────
 * Rank-order canonicality (entries ordered by stake DESC with the
 * state-seed tiebreak) is NOT decode-checkable: the tiebreak hash needs
 * the lookback block's state_root, which is not carried in the snapshot.
 * A decoder therefore CANNOT tell a correctly ranked set from a permuted
 * one. Two mechanisms carry that property instead:
 *   (1) the witness-side builder (nodus_witness_vset_build_for_epoch)
 *       constructs entries straight from nodus_committee_compute_for_epoch,
 *       so the order is the committee order by construction; and
 *   (2) persistence conflict-detection — nodus_witness_vset_insert rejects
 *       (-2) any second snapshot for the same epoch whose hash or bytes
 *       differ, so a divergent ordering on one node is a hard, visible
 *       fault rather than a silently different root.
 * What decode DOES enforce structurally: bounds, exact length, ruleset,
 * seed reservation, and distinctness of every voter_id and every pubkey.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_VSET_WIRE_H
#define SHARED_DNAC_VSET_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field widths ───────────────────────────────────────────────────── */
#define DNA_VSET_TAG_LEN        16
#define DNA_VSET_VOTER_ID_LEN   32
#define DNA_VSET_PUBKEY_LEN   2592   /* Dilithium5 (ML-DSA-87) public key */
#define DNA_VSET_SEED_LEN       64
#define DNA_VSET_HASH_LEN       64   /* SHA3-512 */
#define DNA_VSET_VALIDATOR_ID_LEN 64 /* ruleset 2: validator_id            */
#define DNA_VSET_OWNER_FP_LEN   64   /* ruleset 2: owner fingerprint        */

/** Selection rulesets. 0 is INVALID by design (zeroed memory fails closed). */
#define DNA_VSET_RULESET_INVALID   ((uint32_t)0)
#define DNA_VSET_RULESET_TOPN_V1   ((uint32_t)1)
#define DNA_VSET_RULESET_TOPN_V2   ((uint32_t)2)   /* INERT (HF-6 slice 1) */

/* ── Encoded sizes ──────────────────────────────────────────────────── */
#define DNA_VSET_HDR_LEN     78     /* 8 + 2 + 4 + 64                    */
#define DNA_VSET_ENTRY_LEN 2642     /* 32 + 2592 + 8 + 8 + 2             */
#define DNA_VSET_ENTRY_LEN_V2 2770  /* 32 + 64 + 64 + 2592 + 8 + 8 + 2   */

/** Largest ruleset-1 encoding (the legacy functions' ceiling). */
#define DNA_VSET_MAX_ENC_LEN \
    ((size_t)DNA_VSET_HDR_LEN + \
     (size_t)DNA_MAX_ACTIVE_VALIDATORS * (size_t)DNA_VSET_ENTRY_LEN)

/** Largest ruleset-2 encoding (78 + 128 × 2770 = 354638). */
#define DNA_VSET_MAX_ENC_LEN_V2 \
    ((size_t)DNA_VSET_HDR_LEN + \
     (size_t)DNA_MAX_ACTIVE_VALIDATORS * (size_t)DNA_VSET_ENTRY_LEN_V2)

/* ── One active validator ───────────────────────────────────────────── */
typedef struct {
    uint8_t  voter_id[DNA_VSET_VOTER_ID_LEN];  /* SHA3-512(pubkey)[0..31] */
    uint8_t  pubkey[DNA_VSET_PUBKEY_LEN];      /* ruleset 2: consensus_pk */
    uint64_t total_stake;      /* self_bond + external delegations (raw)  */
    uint64_t self_bond;        /* the validator's own bond (raw)          */
    uint16_t commission_bps;
    /* Ruleset 2 only. Under ruleset 1 both MUST be all-zero (the v1
     * encoder rejects otherwise; the v1 decoder leaves them zero). */
    uint8_t  validator_id[DNA_VSET_VALIDATOR_ID_LEN];
    uint8_t  owner_fp[DNA_VSET_OWNER_FP_LEN];
} dna_vset_entry_t;

/**
 * A decoded snapshot. `entries` is ALWAYS heap-owned (128 entries are
 * ~357 KB — never a stack object) and holds exactly active_count items.
 * Allocate with dna_vset_alloc, release with dna_vset_free.
 */
typedef struct {
    uint64_t          epoch;              /* EPOCH START HEIGHT            */
    uint16_t          active_count;
    uint32_t          selection_ruleset;
    uint8_t           sortition_seed[DNA_VSET_SEED_LEN];
    dna_vset_entry_t *entries;            /* heap, active_count items      */
} dna_vset_snapshot_t;

/* ── Lifecycle ──────────────────────────────────────────────────────── */

/**
 * Allocate a zeroed snapshot with `active_count` zeroed entries.
 * `selection_ruleset` is preset to DNA_VSET_RULESET_TOPN_V1 (the only
 * value the legacy encoder accepts); the caller still owns every other
 * field. Entries are zeroed, so validator_id / owner_fp start all-zero
 * as ruleset 1 requires.
 *
 * @return NULL if active_count is 0, exceeds DNA_MAX_ACTIVE_VALIDATORS,
 *         or allocation fails.
 */
dna_vset_snapshot_t *dna_vset_alloc(uint16_t active_count);

/** NULL-safe release. Frees entries + the snapshot and zeroes *snap. */
void dna_vset_free(dna_vset_snapshot_t **snap);

/* ── Codec ──────────────────────────────────────────────────────────── */

/**
 * Encoded length of a STRUCTURALLY VALID snapshot.
 * @return byte length, or 0 if the snapshot would be rejected by encode
 *         (a valid encoding is never 0 bytes, so 0 is unambiguous).
 */
size_t dna_vset_encoded_len(const dna_vset_snapshot_t *snap);

/**
 * Encode canonical bytes into dst.
 *
 * Rejects (-1, dst untouched): NULL arguments; entries == NULL;
 * active_count == 0 or > DNA_MAX_ACTIVE_VALIDATORS; selection_ruleset !=
 * DNA_VSET_RULESET_TOPN_V1; a nonzero sortition_seed byte under TOPN_V1;
 * a duplicated voter_id; a duplicated pubkey; a nonzero validator_id or
 * owner_fp byte (no ruleset-1 slot); cap smaller than the encoding.
 *
 * @param written [out] bytes written on success (may be NULL).
 * @return 0 / -1.
 */
int dna_vset_encode(const dna_vset_snapshot_t *snap,
                    uint8_t *dst, size_t cap, size_t *written);

/**
 * Decode canonical bytes. `len` must be EXACTLY the encoded length implied
 * by the header's active_count — both truncation and trailing bytes are
 * rejected. Bounds, ruleset and the exact length are all validated BEFORE
 * the entry array is allocated; the same structural rejects as encode are
 * then applied to the decoded content.
 *
 * @param out [out] receives a heap snapshot on success; untouched on
 *            failure. Release with dna_vset_free.
 * @return 0 / -1.
 */
int dna_vset_decode(const uint8_t *src, size_t len,
                    dna_vset_snapshot_t **out);

/* ── Hashing ────────────────────────────────────────────────────────── */

/** snapshot_hash = SHA3-512("NDS.VSET.v1" ‖ canonical bytes). @return 0/-1. */
int dna_vset_hash(const dna_vset_snapshot_t *snap,
                  uint8_t out[DNA_VSET_HASH_LEN]);

/**
 * Bytes-level variant: SHA3-512("NDS.VSET.v1" ‖ buf[0..len)). Used to
 * re-derive the hash of a STORED blob without decoding it — the integrity
 * check on the persistence path. Rejects len > DNA_VSET_MAX_ENC_LEN.
 * @return 0 / -1.
 */
int dna_vset_hash_bytes(const uint8_t *buf, size_t len,
                        uint8_t out[DNA_VSET_HASH_LEN]);

/* ── Ruleset-explicit variants (HF-6 slice 1, INERT) ───────────────────
 *
 * Each takes `max_ruleset`, the highest selection_ruleset the caller
 * accepts: DNA_VSET_RULESET_TOPN_V1 or DNA_VSET_RULESET_TOPN_V2. Any
 * other value is rejected (-1 / 0). A snapshot or header whose ruleset
 * is 0 or greater than max_ruleset is rejected. The layout, the hash tag
 * and the structural rules are selected by the snapshot's / header's own
 * selection_ruleset, never by max_ruleset.
 *
 * The legacy functions above are these with max_ruleset = 1
 * (dna_vset_encoded_len / encode / decode / hash), except
 * dna_vset_hash_bytes, which keeps its pre-HF-6 body: it hashes ANY
 * buffer of 1..DNA_VSET_MAX_ENC_LEN bytes under the v1 tag without
 * reading the header. dna_vset_hash_bytes_ex(…, 1) is stricter (needs a
 * full header whose ruleset is 1).
 */

/** As dna_vset_encoded_len; 0 on reject or bad max_ruleset. */
size_t dna_vset_encoded_len_ex(const dna_vset_snapshot_t *snap,
                               uint32_t max_ruleset);

/** As dna_vset_encode, rulesets 1..max_ruleset. @return 0 / -1. */
int dna_vset_encode_ex(const dna_vset_snapshot_t *snap, uint32_t max_ruleset,
                       uint8_t *dst, size_t cap, size_t *written);

/**
 * As dna_vset_decode, rulesets 1..max_ruleset. The header's ruleset picks
 * the entry length; count, ruleset and exact length are checked BEFORE
 * allocation. @return 0 / -1 (*out untouched on failure).
 */
int dna_vset_decode_ex(const uint8_t *src, size_t len, uint32_t max_ruleset,
                       dna_vset_snapshot_t **out);

/** Ruleset 1 → "NDS.VSET.v1" tag, ruleset 2 → "NDS.VSET.v2". @return 0/-1. */
int dna_vset_hash_ex(const dna_vset_snapshot_t *snap, uint32_t max_ruleset,
                     uint8_t out[DNA_VSET_HASH_LEN]);

/**
 * Bytes-level hash: reads selection_ruleset from the header (offset 10,
 * u32 BE) to pick the tag. Rejects len < DNA_VSET_HDR_LEN, ruleset 0 or
 * > max_ruleset, and len above that ruleset's maximum encoding
 * (DNA_VSET_MAX_ENC_LEN / DNA_VSET_MAX_ENC_LEN_V2). @return 0 / -1.
 */
int dna_vset_hash_bytes_ex(const uint8_t *buf, size_t len,
                           uint32_t max_ruleset,
                           uint8_t out[DNA_VSET_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_VSET_WIRE_H */
