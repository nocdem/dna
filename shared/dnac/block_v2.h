/**
 * @file shared/dnac/block_v2.h
 * @brief Ledger V2 Season 2 — BlockHeader V2 codec + BlockID V2 (INACTIVE).
 *
 * One canonical shared implementation (no client/witness mirror). Nothing
 * in live consensus calls these functions: the active chain keeps the V1
 * 236-byte block-hash preimage (dnac/src/transaction/block.c) byte-
 * identical. V2 activates only with the Ledger V2 devnet reset.
 *
 * ── VERSION 3 (Ledger V2 O13) ─────────────────────────────────────────
 * The version BYTE is now 3. Version 2 is RETIRED: it resolves nothing
 * and decode rejects it, exactly as an unknown version is rejected (two
 * distinct fail-closed classes, both tested). This follows the house
 * precedent for a semantic change to a committed structure (SYSTEM
 * ruleset v1→2→3→4, CORE v1→2→3 — each retired on the bump).
 *
 * NOTE ON THE SYMBOL FAMILY: `DNA_BH2_*` / `dna_bh2_*` names the MODULE
 * ("block header, Ledger V2"), not the version byte. The two happened to
 * coincide at v2 and now diverge. Renaming the family would churn every
 * consumer for no consensus benefit, so the names are stable and the
 * version lives in DNA_BH2_VERSION alone.
 *
 * WHY 3: v2 committed no domain-update commitment, so the set of
 * DomainUpdates a block produced was bound by NOTHING in the identity
 * chain — global_state_root derives solely from domains_root
 * (dna_v2_global_root, ledger_roots_v2.h), which commits the RESULTING
 * DomainHeads, not the transition set that produced them. v3 binds it
 * directly. See the commitment note below.
 *
 * ── Canonical header encoding (DNA_BH2_ENC_SIZE = 413 bytes) ──────────
 *   off   0  header_version      u8  = 3
 *   off   1  chain_id[32]
 *   off  33  block_height        u64 BE
 *   off  41  epoch               u64 BE
 *   off  49  prev_block_id[64]
 *   off 113  global_state_root[64]
 *   off 177  tx_root[64]
 *   off 241  domain_updates_root[64]  (v3 — dna_v2_domain_updates_root,
 *                                      domain_wire.h; the TOUCHED-domain
 *                                      transition set)
 *   off 305  validator_set_hash[64]   (the governing snapshot's
 *                                      dna_vset_hash — a COMMITMENT that
 *                                      must EQUAL the independently
 *                                      resolved authority, never a source
 *                                      of it)
 *   off 369  tx_count            u32 BE
 *   off 373  proposer_id[32]
 *   off 405  timestamp           u64 BE  (informational — EXCLUDED from
 *                                         BlockID, PR2 discipline)
 *   total 413
 *
 * ── Why domain_updates_root is a DIRECT field ─────────────────────────
 * It is NOT transitively committed. Proof: the only path from the header
 * to domain state is global_state_root, and
 *   dna_v2_global_root(domains_root)            [ledger_roots_v2.h]
 *   dna_v2_domains_root(DomainHead leaves)      [ledger_roots_v2.h]
 * hash the RESULTING per-domain heads (id/root/height/last_updated/
 * ruleset_version/status). The DomainUpdate set — which additionally
 * binds each touched domain's pre_root, tx_batch_root, ruleset identity
 * and consumed resources, and which distinguishes a zero-envelope block
 * (tagged empty root "DNA.E.DUPD.v1") from a missing body — appears in
 * no preimage reachable from the header. Binding it here closes that
 * hole, and TRANSITIVELY binds each touched domain's ruleset_version and
 * ruleset_hash (they are fields of the DomainUpdate leaf).
 *
 * ── BlockID V3 (normal block) ─────────────────────────────────────────
 *   SHA3-512( "DNA.BLOCK.v3"+4×00 (16 B)
 *             ‖ encoded header bytes [0,405) )        — 421-byte preimage
 *   i.e. every field above EXCEPT timestamp is bound.
 *   The tag is DISTINCT from "DNA.BLOCK.v2", so a v2 and a v3 header can
 *   never produce the same id even if a caller could construct matching
 *   field bytes; the version byte inside the preimage binds it a second
 *   time. A QC is deliberately NOT part of the id it certifies.
 *
 * ── Genesis BlockID + 32-byte chain-id derivation ─────────────────────
 *   Explicit genesis semantics required: block_height MUST be 0 and the
 *   header's chain_id field MUST be all-zero (the value is not known yet —
 *   zeroing it in the preimage breaks the circularity).
 *   genesis_block_id = SHA3-512( tag ‖ header bytes [0,405) with the
 *       all-zero chain_id ‖ canonical genesis-manifest bytes )
 *   chain_id = genesis_block_id[0..31]   — the FULL 32-byte prefix; no
 *       byte is zeroed (fixes the legacy 16-byte-entropy truncation).
 *   The manifest bytes are an EXPLICIT input: Season 6 owns the manifest
 *   schema; S2 hashes whatever canonical bytes it is handed and any
 *   single-byte change changes both genesis BlockID and chain id.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_BLOCK_V2_H
#define SHARED_DNAC_BLOCK_V2_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNA_BH2_VERSION       3
/** Retired header version — decode MUST reject it. Kept as a named
 *  constant so the rejection is explicit and testable, never a bare 2. */
#define DNA_BH2_VERSION_RETIRED 2
#define DNA_BH2_ENC_SIZE      413
#define DNA_BH2_BOUND_SIZE    405   /* encoded bytes bound into BlockID */
#define DNA_BH2_ID_LEN        64
/** Sanity cap on genesis-manifest bytes fed into the genesis BlockID
 *  preimage (S6 owns the real schema; this only bounds the hash input). */
#define DNA_BH2_MANIFEST_MAX  (1024u * 1024u)

typedef struct {
    uint8_t  header_version;               /* must be 3 */
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint64_t block_height;
    uint64_t epoch;
    uint8_t  prev_block_id[DNA_BH2_ID_LEN];
    uint8_t  global_state_root[DNA_BH2_ID_LEN];
    uint8_t  tx_root[DNA_BH2_ID_LEN];
    uint8_t  domain_updates_root[DNA_BH2_ID_LEN];  /* v3 */
    uint8_t  validator_set_hash[DNA_BH2_ID_LEN];
    uint32_t tx_count;
    uint8_t  proposer_id[32];
    uint64_t timestamp;                    /* info-only, not in BlockID */
} dna_block_header_v2_t;

/** Canonical 413-byte encode. Rejects NULL / header_version != 3. */
int dna_bh2_encode(const dna_block_header_v2_t *h,
                   uint8_t out[DNA_BH2_ENC_SIZE]);

/** Strict decode: src_len must be EXACTLY 413 (truncation and trailing
 *  bytes both reject); version byte must be 3 — the retired 2 and any
 *  unknown version both fail closed. */
int dna_bh2_decode(const uint8_t *src, size_t src_len,
                   dna_block_header_v2_t *out);

/** BlockID V3 of a NON-genesis header (421-byte preimage; timestamp
 *  excluded). Rejects header_version != 3. */
int dna_bh2_block_id(const dna_block_header_v2_t *h,
                     uint8_t out[DNA_BH2_ID_LEN]);

/**
 * Genesis BlockID: requires EXPLICIT genesis semantics — block_height == 0
 * AND an all-zero chain_id field (rejects otherwise); appends the caller-
 * supplied canonical manifest bytes (non-NULL, 1..DNA_BH2_MANIFEST_MAX).
 */
int dna_bh2_genesis_block_id(const dna_block_header_v2_t *h,
                             const uint8_t *manifest_bytes,
                             size_t manifest_len,
                             uint8_t out[DNA_BH2_ID_LEN]);

/** chain_id = genesis_block_id[0..31] — the full 32-byte prefix. */
int dna_bh2_derive_chain_id(const uint8_t genesis_block_id[DNA_BH2_ID_LEN],
                            uint8_t chain_id_out[DNA_CHAIN_ID_LEN]);

/** Non-genesis chain binding: the header's chain_id must equal the trusted
 *  chain context. @return 0 match, -1 mismatch/NULL. */
int dna_bh2_check_chain(const dna_block_header_v2_t *h,
                        const uint8_t expected_chain_id[DNA_CHAIN_ID_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_BLOCK_V2_H */
