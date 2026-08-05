/**
 * @file shared/dnac/tx_wire.h
 * @brief Ledger V2 Season 1 — the ONE shared transaction wire codec.
 *
 * Three things live here, all compiled identically into libdna (client) and
 * libnodus (witness) — the chain_config_wire.{h,c} single-source pattern:
 *
 *   1. ExecutionContext — the canonical replay-protection tuple + its
 *      fixed-width encoding (50 bytes).
 *   2. Transaction Wire V3 — the versioned Ledger V2 header codec and the
 *      "DNAC_TX_V5" tx-hash preimage. INACTIVE on the live chain: every
 *      active consensus path still gates on wire version byte 2 — the
 *      deserialize version gate (`buffer[0] != DNAC_PROTOCOL_VERSION` in
 *      dnac_tx_deserialize, serialize.c) and witness Check 0
 *      (`tx_data[0] != DNAC_PROTOCOL_VERSION`, nodus_witness_verify.c) —
 *      and therefore rejects V3 bytes. Activation is the Ledger V2 devnet
 *      reset (Season 11) — S1 ships the codec and its tests only.
 *   3. The LEGACY (wire-version-2 / shielded V4) tx-hash preimage — the
 *      exact algorithm previously duplicated by libdna's struct walk
 *      (dnac/src/transaction/transaction.c dnac_tx_compute_hash) and the
 *      witness's hand-written wire walk (nodus_witness_recompute_tx_hash).
 *      Both now call dnac_txw_legacy_tx_hash(); the independent witness
 *      mirror is retired. Byte identity with the pre-S1 algorithm is pinned
 *      by fixed KATs (nodus/tests/test_tx_hash_kat.c) and the independent
 *      third implementation in test_witness_tx_hash_parity.c.
 *
 * Self-contained: constants are mirrored here (no dnac/ or nodus/ includes)
 * and pinned by _Static_asserts at both consumer sides so drift between the
 * trees is a compile error, never a silent consensus break.
 *
 * ── ExecutionContext canonical encoding (DNA_EXEC_CTX_WIRE_LEN = 50 B) ──
 *   off  0  chain_id[32]
 *   off 32  domain_id          u32 BE
 *   off 36  pool_id            u32 BE   (0 = no pool)
 *   off 40  tx_type            u8
 *   off 41  wire_version       u8
 *   off 42  ruleset_version    u32 BE
 *   off 46  statement_version  u32 BE   (0 = no ZK statement)
 *   total 50
 *
 * ── Transaction Wire V3 layout (header 106 B + body framing) ──────────
 *   off   0  wire_version       u8  = 3
 *   off   1  tx_type            u8
 *   off   2  domain_id          u32 BE
 *   off   6  pool_id            u32 BE
 *   off  10  ruleset_version    u32 BE
 *   off  14  statement_version  u32 BE
 *   off  18  expiry_height      u64 BE  (0 = no expiry)
 *   off  26  committed_fee      u64 BE
 *   off  34  timestamp          u64 BE  (width 8 matches the legacy wire's
 *                                        timestamp field; V3 pins it BE)
 *   off  42  tx_hash[64]
 *   off 106  body_len           u32 BE  (S1 framing; canonical type-specific
 *                                        body layouts land with their
 *                                        activation seasons)
 *   off 110  body[body_len]
 *   TOTAL = 110 + body_len, exact — any trailing byte is a decode reject.
 *
 * ── V3 tx-hash preimage ("V5" domain — wire version and hash-domain
 *    version are intentionally distinct, per the architecture report) ──
 *   DNAC_TXW_V5_TAG[16]           ("DNAC_TX_V5" zero-padded to 16 bytes)
 *   ‖ chain_id[32]                (preimage-only — NOT serialized on the wire)
 *   ‖ wire_version(1) ‖ tx_type(1) ‖ domain_id(4 BE) ‖ pool_id(4 BE)
 *   ‖ ruleset_version(4 BE) ‖ statement_version(4 BE)
 *   ‖ expiry_height(8 BE) ‖ committed_fee(8 BE) ‖ timestamp(8 BE)
 *   ‖ body_len(4 BE) ‖ body[body_len]
 *   hash = SHA3-512(preimage)     (qgp_sha3_512)
 *   tx_hash[64] on the wire is EXCLUDED from its own preimage.
 *
 * ── Legacy (V2/V4) tx-hash preimage — UNCHANGED byte-for-byte ─────────
 *   tag ("DNAC_TX_V2\0" for types 0-10, "DNAC_TX_V4\0" for type 11; 11 B)
 *   ‖ version(1) ‖ type(1) ‖ timestamp(8 BE) ‖ chain_id[32]
 *   ‖ committed_fee(8 BE)
 *   ‖ inputs[]:  nullifier(64) ‖ amount(8 BE) ‖ token_id(64)
 *   ‖ outputs[]: version(1) ‖ fp(129) ‖ amount(8 BE) ‖ token_id(64)
 *                ‖ seed(32) ‖ memo_len(1) ‖ memo[memo_len]
 *   ‖ signer_count(1) ‖ signer_pubkeys[count × 2592]
 *   ‖ type-specific appended fields (see dnac serialize.c; CHAIN_CONFIG
 *     votes and the 330-B shielded statement included, FRI blob excluded)
 *   Input/output counts, witness section, signer signatures, and the
 *   genesis chain_def trailer are NOT part of the preimage (unchanged).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_TX_WIRE_H
#define SHARED_DNAC_TX_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Mirrored size constants (pinned by _Static_asserts in
 *    dnac/src/transaction/serialize.c and nodus_witness_verify.c) ────── */
#define DNAC_TXW_HASH_LEN        64    /* SHA3-512 */
#define DNAC_TXW_NULLIFIER_LEN   64
#define DNAC_TXW_TOKEN_ID_LEN    64
#define DNAC_TXW_FP_LEN          129
#define DNAC_TXW_SEED_LEN        32
#define DNAC_TXW_PK_LEN          2592  /* Dilithium5 pubkey */
#define DNAC_TXW_SIG_LEN         4627  /* Dilithium5 signature */
#define DNAC_TXW_MAX_INPUTS      16
#define DNAC_TXW_MAX_OUTPUTS     16
#define DNAC_TXW_MAX_SIGNERS     4
#define DNAC_TXW_LEGACY_HEADER   82    /* legacy v2 header size */
#define DNAC_TXW_TYPE_SHIELDED   11    /* selects the V4 preimage tag */
/** Shielded wire section: 330 statement bytes + u32 fri_proof_len
 *  (mirror of DNAC_TX_SHIELDED_FIXED_SIZE; pinned by serialize.c). */
#define DNAC_TXW_SHIELDED_FIXED  334
/** STAKE appended tail: commission(2) + unstake_dest_fp(64) + purpose_tag(17)
 *  (pinned by serialize.c against the dnac constants). */
#define DNAC_TXW_STAKE_TAIL      83
/** CHAIN_CONFIG fixed section before votes[] (mirror of
 *  DNAC_CC_WIRE_FIXED_LEN; pinned by serialize.c). */
#define DNAC_TXW_CC_FIXED        42
/** CHAIN_CONFIG vote-count bound inside the legacy hash walk — mirrors the
 *  pre-S1 witness bound (NODUS_T3_MAX_WITNESSES), NOT the 7-slot decode
 *  cap, preserving the exact legacy accept/reject surface (pinned by a
 *  _Static_assert in nodus_witness_verify.c). */
#define DNAC_TXW_CC_VOTE_BOUND   128

/* ══════════════════════════════════════════════════════════════════════
 * 1. ExecutionContext
 * ════════════════════════════════════════════════════════════════════ */

#define DNA_EXEC_CTX_WIRE_LEN  50

typedef struct {
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint32_t domain_id;
    uint32_t pool_id;            /* DNA_POOL_NONE (0) when no pool applies */
    uint8_t  tx_type;
    uint8_t  wire_version;
    uint32_t ruleset_version;
    uint32_t statement_version;  /* 0 when no ZK statement applies */
} dna_exec_context_t;

/**
 * Fully initialize + validate an ExecutionContext (no partial construction).
 *
 * CANONICAL/STRUCTURAL validation ONLY (S1 correction #1 — layering):
 *   - wire_version must be DNAC_TXW3_WIRE_VERSION (3), the only version
 *     this context model covers; anything else fails closed.
 * The generic codec deliberately does NOT judge domain_id, pool_id,
 * tx_type assignment, or statement_version values: future
 * manifest-registered domains/pools/proof-bearing types must encode
 * canonically WITHOUT a codec change. Whether a value is admissible on a
 * given chain is RUNTIME/ADMISSION policy (domain registry status, type
 * ownership, pool ownership, accepted statement versions) — Season 4/9
 * work, not the codec's.
 *
 * @return 0 on success (ctx fully written), -1 on NULL/invalid (ctx zeroed).
 */
int dna_exec_context_init(dna_exec_context_t *ctx,
                          const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                          uint32_t domain_id, uint32_t pool_id,
                          uint8_t tx_type, uint8_t wire_version,
                          uint32_t ruleset_version, uint32_t statement_version);

/** Re-run the init-time STRUCTURAL validation on an existing context.
 *  0 = structurally valid. Carries no policy judgment. */
int dna_exec_context_validate(const dna_exec_context_t *ctx);

/**
 * INITIAL-NETWORK POLICY helper — separate from the canonical codec, with
 * ZERO production callers (tests only, verified). Expresses the initial
 * Ledger V2 assignment set as a preview of the Season-4/9 admission rules:
 *   - domain_id ∈ {DNA_DOMAIN_SYSTEM, DNA_DOMAIN_CORE};
 *   - pool_id == DNA_POOL_NONE unless tx_type is the shielded type (11),
 *     whose pool must be DNAC_SHIELDED_POOL_V1;
 *   - statement_version == 0 unless tx_type is the shielded type.
 * Real admission lands with the domain registry (S4) and C3 (S9); this
 * helper must NEVER be wired into encode/decode/hash paths.
 * @return 0 if the context matches the initial policy, -1 otherwise.
 */
int dna_exec_context_check_initial_policy(const dna_exec_context_t *ctx);

/** Canonical 50-byte encoding (layout in the header comment). Rejects an
 *  invalid context (same rules as init). @return 0 / -1. */
int dna_exec_context_encode(const dna_exec_context_t *ctx,
                            uint8_t out[DNA_EXEC_CTX_WIRE_LEN]);

/** Strict decode: exactly DNA_EXEC_CTX_WIRE_LEN bytes, then the same
 *  fail-closed validation. @return 0 / -1. */
int dna_exec_context_decode(const uint8_t *in, size_t in_len,
                            dna_exec_context_t *out);

/* ══════════════════════════════════════════════════════════════════════
 * 2. Transaction Wire V3 (INACTIVE until the Ledger V2 devnet reset)
 * ════════════════════════════════════════════════════════════════════ */

#define DNAC_TXW3_WIRE_VERSION   3
#define DNAC_TXW3_HEADER_LEN     106  /* through tx_hash */
#define DNAC_TXW3_BODYLEN_OFF    106
#define DNAC_TXW3_BODY_OFF       110
#define DNAC_TXW3_TXHASH_OFF     42
/** ONE authoritative serialized-transaction size limit (S1 correction #2).
 *  Mirror of NODUS_T3_MAX_TX_SIZE = 65536 (nodus/include/nodus/nodus_types.h),
 *  the cap every live admission path enforces on serialized TX bytes:
 *  tier3 decode (nodus_tier3.c dnac_spend/fwd bstr gates), witness peer
 *  forward (nodus_witness_peer.c), witness handler admission
 *  (nodus_witness_handlers.c), BFT batch parse (nodus_witness_bft.c).
 *  Pinned by a _Static_assert in nodus_witness_verify.c. The layers above
 *  it (T3 msg 128 KB, TCP frame 5 MB) bound MESSAGES, not one TX. */
#define DNAC_TXW3_MAX_TX_SIZE    65536u
/** Body cap = the authoritative TX limit minus the fixed V3 overhead
 *  (110 = header 106 + body_len 4), so no V3 transaction can exceed the
 *  same wire limit legacy transactions live under. Checked arithmetic in
 *  dnac_txw3_encoded_size keeps encode and decode on this one bound. */
#define DNAC_TXW3_MAX_BODY_LEN   (DNAC_TXW3_MAX_TX_SIZE - DNAC_TXW3_BODY_OFF)

/** 16-byte zero-padded V5 hash-domain tag ("DNAC_TX_V5"). */
extern const uint8_t DNAC_TXW_V5_TAG[16];

typedef struct {
    /* ExecutionContext-carried fields (chain_id is preimage-only) */
    uint8_t  wire_version;       /* must be 3 */
    uint8_t  tx_type;
    uint32_t domain_id;
    uint32_t pool_id;
    uint32_t ruleset_version;
    uint32_t statement_version;
    /* header-only fields */
    uint64_t expiry_height;      /* 0 = no expiry */
    uint64_t committed_fee;
    uint64_t timestamp;
    uint8_t  tx_hash[DNAC_TXW_HASH_LEN];
} dnac_txw3_header_t;

/** Exact encoded size for a body of body_len bytes, with checked
 *  arithmetic. @return 0 on success (size in *out), -1 on overflow or
 *  body_len > DNAC_TXW3_MAX_BODY_LEN. */
int dnac_txw3_encoded_size(uint32_t body_len, size_t *out);

/**
 * Canonical V3 encode: header + body_len framing + body.
 * Rejects: NULL args (body may be NULL only when body_len==0),
 * wire_version != 3, body_len over cap, short dst.
 * @return 0 on success (*written_out = 110 + body_len), -1 otherwise.
 */
int dnac_txw3_encode(const dnac_txw3_header_t *hdr,
                     const uint8_t *body, uint32_t body_len,
                     uint8_t *dst, size_t dst_cap, size_t *written_out);

/**
 * Strict canonical V3 decode.
 * Rejects: NULL args, src_len < 110, wire_version != 3, body_len over cap,
 * and any length mismatch — src_len MUST equal 110 + body_len exactly
 * (truncated AND trailing-garbage inputs both fail).
 * On success fills *hdr and returns a pointer INTO src for the body
 * (*body_out, *body_len_out) — no allocation.
 * @return 0 / -1.
 */
int dnac_txw3_decode(const uint8_t *src, size_t src_len,
                     dnac_txw3_header_t *hdr,
                     const uint8_t **body_out, uint32_t *body_len_out);

/**
 * V3 tx-hash: SHA3-512 over the V5 preimage (layout in the header comment).
 * chain_id is bound into the preimage but never serialized on the wire.
 * @return 0 on success (hash_out[64] filled), -1 on NULL/invalid input
 *         (wire_version != 3, body_len over cap, body NULL with len > 0).
 */
int dnac_txw3_tx_hash(const dnac_txw3_header_t *hdr,
                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                      const uint8_t *body, uint32_t body_len,
                      uint8_t hash_out[DNAC_TXW_HASH_LEN]);

/* ══════════════════════════════════════════════════════════════════════
 * 3. Legacy (wire v2 / shielded V4) tx-hash — the ONE implementation
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Compute the legacy transaction hash from serialized wire bytes.
 *
 * Exact port of the algorithm that lived in
 * nodus_witness_recompute_tx_hash (nodus_witness_verify.c, pre-S1) —
 * which was itself the byte-match of libdna's struct walk. Semantics are
 * IDENTICAL to the pre-S1 witness function, including:
 *   - signer_pubkeys/signer_count are CALLER-SUPPLIED (count × 2592-byte
 *     concatenation) and are what gets hashed — the wire's own signers
 *     section is length-walked but not hashed (unchanged behavior);
 *   - the wire timestamp/amount fields are read with the legacy
 *     host-order memcpy convention (LE hosts; pre-existing portability
 *     posture, unchanged);
 *   - trailing bytes after the type-specific section (the genesis
 *     chain_def trailer) are ignored, exactly as before;
 *   - all bound checks and fail paths mirror the original walk.
 *
 * @param chain_id        32-byte chain identifier bound into the preimage
 * @param tx_data         serialized legacy transaction bytes
 * @param tx_len          length of tx_data
 * @param signer_pubkeys  signer_count × 2592-byte pubkey concatenation
 *                        (NULL allowed iff signer_count == 0)
 * @param signer_count    0..DNAC_TXW_MAX_SIGNERS
 * @param hash_out        [out] 64-byte SHA3-512 transaction hash
 * @return 0 on success, -1 on any malformed/truncated input or hash failure
 */
int dnac_txw_legacy_tx_hash(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                            const uint8_t *tx_data, size_t tx_len,
                            const uint8_t *signer_pubkeys,
                            uint8_t signer_count,
                            uint8_t hash_out[DNAC_TXW_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_TX_WIRE_H */
