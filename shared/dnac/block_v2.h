/**
 * @file shared/dnac/block_v2.h
 * @brief Ledger V2 Season 2 — BlockHeader V2 codec + BlockID V2 (INACTIVE).
 *
 * One canonical shared implementation (no client/witness mirror). Nothing
 * in live consensus calls these functions: the active chain keeps the V1
 * 236-byte block-hash preimage (dnac/src/transaction/block.c) byte-
 * identical. V2 activates only with the Ledger V2 devnet reset.
 *
 * ── Canonical header encoding (DNA_BH2_ENC_SIZE = 349 bytes) ──────────
 *   off   0  header_version      u8  = 2
 *   off   1  chain_id[32]
 *   off  33  block_height        u64 BE
 *   off  41  epoch               u64 BE
 *   off  49  prev_block_id[64]
 *   off 113  global_state_root[64]
 *   off 177  tx_root[64]
 *   off 241  validator_set_hash[64]   (opaque required 64B in S2; real
 *                                      snapshot semantics land in S3)
 *   off 305  tx_count            u32 BE
 *   off 309  proposer_id[32]
 *   off 341  timestamp           u64 BE  (informational — EXCLUDED from
 *                                         BlockID, PR2 discipline)
 *   total 349
 *
 * ── BlockID V2 (normal block) ─────────────────────────────────────────
 *   SHA3-512( "DNA.BLOCK.v2"+3×00 (16 B)
 *             ‖ encoded header bytes [0,341) )        — 357-byte preimage
 *   i.e. every field above EXCEPT timestamp is bound.
 *
 * ── Genesis BlockID + 32-byte chain-id derivation ─────────────────────
 *   Explicit genesis semantics required: block_height MUST be 0 and the
 *   header's chain_id field MUST be all-zero (the value is not known yet —
 *   zeroing it in the preimage breaks the circularity).
 *   genesis_block_id = SHA3-512( tag ‖ header bytes [0,341) with the
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

#define DNA_BH2_VERSION       2
#define DNA_BH2_ENC_SIZE      349
#define DNA_BH2_BOUND_SIZE    341   /* encoded bytes bound into BlockID */
#define DNA_BH2_ID_LEN        64
/** Sanity cap on genesis-manifest bytes fed into the genesis BlockID
 *  preimage (S6 owns the real schema; this only bounds the hash input). */
#define DNA_BH2_MANIFEST_MAX  (1024u * 1024u)

typedef struct {
    uint8_t  header_version;               /* must be 2 */
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint64_t block_height;
    uint64_t epoch;
    uint8_t  prev_block_id[DNA_BH2_ID_LEN];
    uint8_t  global_state_root[DNA_BH2_ID_LEN];
    uint8_t  tx_root[DNA_BH2_ID_LEN];
    uint8_t  validator_set_hash[DNA_BH2_ID_LEN];
    uint32_t tx_count;
    uint8_t  proposer_id[32];
    uint64_t timestamp;                    /* info-only, not in BlockID */
} dna_block_header_v2_t;

/** Canonical 349-byte encode. Rejects NULL / header_version != 2. */
int dna_bh2_encode(const dna_block_header_v2_t *h,
                   uint8_t out[DNA_BH2_ENC_SIZE]);

/** Strict decode: src_len must be EXACTLY 349 (truncation and trailing
 *  bytes both reject); version byte must be 2. */
int dna_bh2_decode(const uint8_t *src, size_t src_len,
                   dna_block_header_v2_t *out);

/** BlockID V2 of a NON-genesis header (357-byte preimage; timestamp
 *  excluded). Rejects header_version != 2. */
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
