/**
 * @file shared/dnac/ledger_ids.h
 * @brief Ledger V2 — canonical protocol ID types and reserved initial values.
 *
 * Season 1 (2026-08-05, Ledger V2 architecture report + decision addenda #1/#2).
 * Header-only, self-contained (no dnac/nodus includes) so it compiles into
 * both libdna and libnodus without cross-tree dependencies — same discipline
 * as shared/dnac/chain_config_wire.h.
 *
 * Canonical widths (wire encoding is ALWAYS fixed-width big-endian for
 * multi-byte integers; native struct layout is never a wire format):
 *   chain_id            32 bytes  (Ledger V2 execution/hash context)
 *   domain_id           u32
 *   pool_id             u32       (0 = no shielded pool)
 *   ruleset_version     u32
 *   statement_version   u32       (0 = no ZK statement applies)
 *   expiry_height       u64       (0 = no expiry)
 *   tx_type             u8
 *   wire_version        u8
 *
 * ACTIVATION NOTE (S1): every constant here describes the Ledger V2 target.
 * Nothing in the live V2-wire consensus path reads these values yet — the
 * active chain still runs the legacy wire (version byte 2) and rejects all
 * other versions. V3 activates only with the Ledger V2 devnet reset.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_LEDGER_IDS_H
#define SHARED_DNAC_LEDGER_IDS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Canonical field widths (bytes, wire encoding) ─────────────────── */
#define DNA_CHAIN_ID_LEN          32
#define DNA_DOMAIN_ID_WIRE_LEN     4   /* u32 BE */
#define DNA_POOL_ID_WIRE_LEN       4   /* u32 BE */
#define DNA_RULESET_VER_WIRE_LEN   4   /* u32 BE */
#define DNA_STMT_VER_WIRE_LEN      4   /* u32 BE */
#define DNA_EXPIRY_WIRE_LEN        8   /* u64 BE */

/* ── Locked initial execution domains (architecture report §4-§5;
 *    locked by the Season-1 charter). Only SYSTEM and DNA_CORE are
 *    assigned initially; Ledger V2 is consumer-neutral and any further
 *    domain arrives through the generic domain-registry path, never as
 *    a compile-time constant. ── */
#define DNA_DOMAIN_SYSTEM   ((uint32_t)0)
#define DNA_DOMAIN_CORE     ((uint32_t)1)

/* ── Pool identifiers ──────────────────────────────────────────────── */
/** No shielded pool (every non-pool transaction). */
#define DNA_POOL_NONE       ((uint32_t)0)
/** First DNAC shielded pool. The architecture record did not previously fix
 *  a numeric value; 1 is the S1 assignment (documented per the Season-1
 *  charter §5 — no compatibility conflict exists: no pool id is serialized
 *  anywhere in the live chain today). */
#define DNAC_SHIELDED_POOL_V1  ((uint32_t)1)

/* ── Transaction-type ownership metadata (INFORMATIONAL in S1) ─────────
 * Records which domain owns each existing numeric tx type. Domain ROUTING
 * IS NOT ENFORCED in S1 — admission still runs the legacy per-type checks;
 * enforcement arrives with the domain registry (Season 4). Numeric type
 * values mirror dnac_tx_type_t (dnac/include/dnac/dnac.h) and are pinned by
 * _Static_asserts at the dnac side (serialize.c).
 *
 *   type  0 GENESIS           protocol bootstrap special case (no domain)
 *   type  1 SPEND             DNA_CORE
 *   type  2 BURN              DNA_CORE
 *   type  3 TOKEN_CREATE      DNA_CORE
 *   type  4 STAKE             SYSTEM
 *   type  5 DELEGATE          SYSTEM
 *   type  6 UNSTAKE           SYSTEM
 *   type  7 UNDELEGATE        SYSTEM
 *   type  8 (retired)         — was CLAIM_REWARD, removed v0.16; stays retired
 *   type  9 VALIDATOR_UPDATE  SYSTEM
 *   type 10 CHAIN_CONFIG      SYSTEM
 *   type 11 SHIELDED          DNA_CORE (pool DNAC_SHIELDED_POOL_V1; REJECT-only
 *                             until C3 — admission gate untouched by S1)
 *   type 12 SHIELD            DNA_CORE (pool DNAC_SHIELDED_POOL_V1) — transparent
 *                             → shielded boundary crossing. V3-ONLY: never valid
 *                             on the legacy V2 wire (acceptance set frozen at
 *                             0..11); REJECT-only until activation
 *   type 13 UNSHIELD          DNA_CORE (pool DNAC_SHIELDED_POOL_V1) — shielded
 *                             → transparent boundary crossing. V3-ONLY, same
 *                             freeze and REJECT-only posture as type 12
 *   type 14                   UNASSIGNED
 */
#define DNA_TX_OWNER_NONE     ((uint32_t)0xFFFFFFFFu) /* bootstrap / unassigned */

/* ── Validator-set scaling (Ledger V2 S3) ──────────────────────────────
 * 128 is the CURRENT RELEASE's safety/resource ceiling on the active
 * validator set (architecture report §7.1 row 3, Addendum #1 A4): it
 * bounds memory/wire/DoS sizing for this software release and matches
 * the existing wire provisioning (NODUS_T3_MAX_WITNESSES). It is NOT a
 * permanent protocol maximum — every encoded count is u16; raising the
 * ceiling is a coordinated software upgrade plus new benchmarks, never
 * a wire-format change. */
#define DNA_MAX_ACTIVE_VALIDATORS  128

/** BFT quorum for an active set of n validators: floor(2n/3) + 1.
 *  Identical to the shipped witness formula (nodus_witness_bft.c
 *  nodus_witness_bft_config_init) — n=7 yields the legacy quorum 5.
 *  Always derive n from the validator-set snapshot governing the
 *  signed height/epoch, never from a compile-time committee size.
 *
 *  ── IT DOES NOT AGREE WITH nodus_witness_bft_config_init FOR SMALL n,
 *  AND THAT IS CORRECT. DO NOT RECONCILE THEM.
 *
 *  For n below NODUS_T3_MIN_WITNESSES (5) that initialiser writes
 *  quorum = 0 while this function keeps applying the formula: n=4 gives
 *  0 there and 3 here. The two answer different questions.
 *
 *  THIS function is the pure formula — "for a set of n validators, how
 *  many must agree" — and it is asked about sets that ALREADY decided
 *  something: the committee governing a signed height, a historical
 *  validator-set snapshot, the seat count in a genesis chain_def. Those
 *  questions have an answer regardless of how large the set is or
 *  whether any node is currently participating.
 *
 *  THAT function additionally decides whether the LOCAL NODE takes part
 *  at all, and below the minimum the answer is no. Its 0 is not a small
 *  threshold; it is the sentinel nodus_witness_bft_consensus_active
 *  reads, and it must stay 0.
 *
 *  Making this function return 0 below the minimum would corrupt every
 *  historical threshold derived from it — a 4-member epoch's committed
 *  blocks would verify against a threshold of 0, i.e. against nothing.
 *  Making that one return 3 for n=4 would silently re-enable consensus
 *  on a cluster too small to be safe. See the reciprocal note at
 *  nodus_witness_bft_config_init, and the O15O Faz 2 guards it lists:
 *  because 0 is a sentinel, `x < quorum` is VACUOUS at 0, so every
 *  threshold comparison against the witness config must handle 0
 *  explicitly. Comparisons against THIS function's result never need
 *  that — it returns at least 1 for every n, including 0. */
static inline uint32_t dna_bft_quorum(uint32_t n) {
    return (2u * n) / 3u + 1u;
}

/** @return owning domain for a numeric tx type, or DNA_TX_OWNER_NONE for
 *  GENESIS (bootstrap special case), retired type 8, and unassigned types.
 *  Pure metadata — NOT an admission or routing gate in S1. */
static inline uint32_t dna_tx_type_owner(uint8_t tx_type) {
    switch (tx_type) {
        case 1: case 2: case 3: case 11:
        case 12: case 13:                return DNA_DOMAIN_CORE;
        case 4: case 5: case 6: case 7:
        case 9: case 10:                 return DNA_DOMAIN_SYSTEM;
        default:                         return DNA_TX_OWNER_NONE;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_LEDGER_IDS_H */
