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

/* ══════════════════════════════════════════════════════════════════════
 * 4. V3 shielded body codec (Ledger V2 Season 8 — INACTIVE)
 *
 * The canonical fixed 359-byte shielded statement section carried in a
 * Transaction Wire V3 body (§2), followed by the opaque FRI blob. It is a
 * NEW section, not a re-versioning of anything: the legacy 334-byte V2
 * shielded section (DNAC_TXW_SHIELDED_FIXED, dnac
 * DNAC_TX_SHIELDED_FIXED_SIZE) is FROZEN byte-for-byte and its type-11
 * transactions stay unconditionally rejected by live consensus. Nothing
 * here is reachable from any live path.
 *
 * Sections 1-3 above are UNCHANGED by S8 — no generic helper
 * (dna_exec_context_*, dnac_txw3_encode/_decode/_tx_hash) grew a
 * transaction-type branch, and no legacy byte moved.
 *
 * ── V3 shielded body layout (offsets from the START of the V3 body;
 *    every multi-byte integer BIG-ENDIAN) ─────────────────────────────
 *   off   0  len   1  sect_version      = DNAC_TXW3_SECT_VERSION (0x02)
 *   off   1  len  32  anchor[4]           (4 × u64 BE lanes)
 *   off  33  len   1  num_input           (0..4)
 *   off  34  len 128  nf_set[4][4]        (slots ≥ num_input all-zero)
 *   off 162  len   1  num_output          (0..4)
 *   off 163  len 128  output_commit[4][4] (slots ≥ num_output all-zero)
 *   off 291  len   8  fee            u64 BE
 *   off 299  len   8  boundary_in    u64 BE
 *   off 307  len   8  boundary_out   u64 BE
 *   off 315  len   8  expiry_height  u64 BE
 *   off 323  len  32  tx_binding[4]
 *   off 355  len   4  fri_len        u32 BE
 *   off 359  len fri_len  FRI proof blob
 *   body_len == DNAC_TXW3_SHIELDED_FIXED + fri_len, EXACT — a short body
 *   and a body with trailing bytes are both decode rejects.
 *
 * ── Field authority (fee / expiry_height) ─────────────────────────────
 * The V3 HEADER is AUTHORITATIVE for committed_fee and expiry_height —
 * it is what the fee-pool and expiry logic read, and it is what the V5
 * tx-hash binds. The section's `fee` / `expiry_height` are FAIL-CLOSED
 * MIRRORS: they exist because the proof statement binds them (they are
 * inside the sighash_v5 preimage), and dnac_txw3_shielded_check_header()
 * must agree before a statement may be admitted. Direction is one-way:
 * a mismatch REJECTS; the section never overrides the header.
 *
 * ── Canonicality (identical on encode and decode) ─────────────────────
 *   - sect_version == 0x02;
 *   - num_input ≤ 4, num_output ≤ 4 (num_input == 0 is LEGAL — the
 *     shield case — and is NOT a reject);
 *   - all 40 lanes (anchor 4, nf_set 16, output_commit 16, tx_binding 4)
 *     canonical Goldilocks elements (< p = 0xFFFFFFFF00000001);
 *   - every lane of an UNUSED slot (index ≥ its count) is zero;
 *   - num_input == 0 ⇒ anchor is all-zero (FROZEN: a zero-input
 *     statement proves no membership, so it carries no anchor);
 *   - boundary_in < 2^63 and boundary_out < 2^63 (FROZEN verifier-side
 *     range enforcement — the transparent-leg amounts stay well inside
 *     the signed range every downstream sum uses);
 *   - fri_len != 0.
 * ════════════════════════════════════════════════════════════════════ */

/** Shielded statement section version carried at body offset 0. */
#define DNAC_TXW3_SECT_VERSION   2
/** Lanes per anchor/nullifier/commitment/tx_binding value (mirror of
 *  DNAC_SHIELDED_LANES, dnac/include/dnac/transaction.h). */
#define DNAC_TXW3_SHIELDED_LANES        4
/** Aggregate statement slot bounds (mirrors of DNAC_SHIELDED_MAX_INPUTS /
 *  DNAC_SHIELDED_MAX_OUTPUTS — a wire bound above the AIR's would accept
 *  a set no proof can bind). */
#define DNAC_TXW3_SHIELDED_MAX_INPUTS   4
#define DNAC_TXW3_SHIELDED_MAX_OUTPUTS  4
/** Fixed (proof-independent) size of the V3 shielded section:
 *  1+32+1+128+1+128+8+8+8+8+32+4 = 359. Pinned by a _Static_assert in
 *  tx_wire.c. Distinct from — and no replacement for — the frozen legacy
 *  334-byte section (DNAC_TXW_SHIELDED_FIXED). */
#define DNAC_TXW3_SHIELDED_FIXED 359

typedef struct {
    uint8_t  sect_version;                 /* must be 2                    */
    uint64_t anchor[DNAC_TXW3_SHIELDED_LANES];
    uint8_t  num_input;                    /* 0..4                         */
    uint64_t nf_set[DNAC_TXW3_SHIELDED_MAX_INPUTS][DNAC_TXW3_SHIELDED_LANES];
    uint8_t  num_output;                   /* 0..4                         */
    uint64_t output_commit[DNAC_TXW3_SHIELDED_MAX_OUTPUTS][DNAC_TXW3_SHIELDED_LANES];
    uint64_t fee;                          /* mirror of header committed_fee */
    uint64_t boundary_in;                  /* transparent → pool, < 2^63   */
    uint64_t boundary_out;                 /* pool → transparent, < 2^63   */
    uint64_t expiry_height;                /* mirror of header expiry_height */
    uint64_t tx_binding[DNAC_TXW3_SHIELDED_LANES];
    uint32_t fri_len;                      /* blob length; the bytes are
                                            * passed separately and are NOT
                                            * owned by this struct         */
} dnac_txw3_shielded_t;

/**
 * Canonical encode of the shielded section + FRI blob.
 * `fri_len` MUST equal st->fri_len (a disagreement between the two is a
 * reject, never a silent pick). Refuses to emit a non-canonical section:
 * every rule in the canonicality list above is enforced here exactly as
 * decode enforces it.
 * Rejects: NULL args (fri included — fri_len == 0 is not canonical),
 * fri_len != st->fri_len, any canonicality violation, dst_cap short.
 * @return 0 on success (*written_out = 359 + fri_len), -1 otherwise.
 */
int dnac_txw3_shielded_encode(const dnac_txw3_shielded_t *st,
                              const uint8_t *fri, uint32_t fri_len,
                              uint8_t *dst, size_t dst_cap,
                              size_t *written_out);

/**
 * Strict canonical decode of a V3 shielded body.
 * On success fills *out and returns a pointer INTO `body` for the FRI
 * bytes (*fri_out, *fri_len_out) — no allocation, mirroring
 * dnac_txw3_decode. On any rejection *out is zeroed (fail closed).
 * @return 0 / -1.
 */
int dnac_txw3_shielded_decode(const uint8_t *body, uint32_t body_len,
                              dnac_txw3_shielded_t *out,
                              const uint8_t **fri_out, uint32_t *fri_len_out);

/**
 * Fee/expiry mirror equality between the AUTHORITATIVE V3 header and the
 * shielded section (authority direction documented above).
 * @return 0 only when hdr->committed_fee == st->fee AND
 *         hdr->expiry_height == st->expiry_height; -1 otherwise
 *         (NULL included).
 */
int dnac_txw3_shielded_check_header(const dnac_txw3_header_t *hdr,
                                    const dnac_txw3_shielded_t *st);

/* ══════════════════════════════════════════════════════════════════════
 * 5. sighash_v5 — the canonical proof-binding preimage (S8, INACTIVE)
 *
 * The ONE preimage a Ledger V2 shielded statement is bound to. It is a
 * NEW domain: the frozen sighash_v4 (DNAC_SIGHASH_DOMAIN_V4,
 * dnac_tx_shielded_sighash) is untouched and keeps binding the legacy
 * type-11 statement.
 *
 * ── sighash_v5 preimage (581 bytes, absolute offsets; every multi-byte
 *    integer BIG-ENDIAN) ──────────────────────────────────────────────
 *   off   0  len 16  DNAC_SIGHASH_V5_TAG ("DNAC_SIGHASH_V5" + one 0x00)
 *   off  16  len 50  ExecutionContext, canonical encoding produced by
 *                    dna_exec_context_encode (§1 — NOT re-implemented):
 *                      off  16  chain_id[32]
 *                      off  48  domain_id          u32 BE
 *                      off  52  pool_id            u32 BE
 *                      off  56  tx_type            u8
 *                      off  57  wire_version       u8
 *                      off  58  ruleset_version    u32 BE
 *                      off  62  statement_version  u32 BE
 *   off  66  len  1  sect_version   (0x02 for this statement)
 *   off  67  len 64  ruleset_hash   (caller-supplied — the active
 *                    registry/runtime ruleset digest; the codec never
 *                    derives or judges it)
 *   off 131  len 32  anchor[4]
 *   off 163  len  1  num_input
 *   off 164  len128  nf_set[4][4]        (slots ≥ num_input all-zero)
 *   off 292  len  1  num_output
 *   off 293  len128  output_commit[4][4] (slots ≥ num_output all-zero)
 *   off 421  len  8  boundary_in    u64 BE
 *   off 429  len  8  boundary_out   u64 BE
 *   off 437  len  8  fee            u64 BE
 *   off 445  len  8  expiry_height  u64 BE
 *   off 453  len 64  tleg_commit    (transparent-leg commitment)
 *   off 517  len 64  ct_commit      (ciphertext commitment)
 *   total 581 = DNAC_SIGHASH_V5_PREIMAGE_LEN
 *   hash = SHA3-512(preimage)   (qgp_sha3_512)
 *
 * NOTE the field ORDER differs from the wire section's (§4): the section
 * carries fee ‖ boundary_in ‖ boundary_out, the preimage carries
 * boundary_in ‖ boundary_out ‖ fee. Both layouts are frozen as written —
 * neither is derived from the other.
 *
 * tx_binding is deliberately ABSENT from the preimage: tx_binding is the
 * mapped image of this sighash, so including it would be circular.
 *
 * Domain/pool are NEVER hardcoded here: every one of them arrives through
 * the caller's ExecutionContext.
 *
 * ── S8 tagged-empty commitments ───────────────────────────────────────
 * S8 always uses the EMPTY transparent-leg and ciphertext commitments.
 * Following the S2 tagged-empty convention (pool_wire.h), an empty set is
 * SHA3-512 of its 16-byte zero-padded tag ALONE — never an all-zero
 * digest, which no tag can produce:
 *   "DNA.E.TLEG.v1"   empty transparent-leg commitment
 *   "DNA.E.CTC.v1"    empty ciphertext commitment
 * ════════════════════════════════════════════════════════════════════ */

#define DNAC_SIGHASH_V5_TAG_LEN 16
/** 16-byte zero-padded V5 sighash-domain tag ("DNAC_SIGHASH_V5" + one
 *  0x00 pad). Distinct from DNAC_TXW_V5_TAG: one tag per hash purpose. */
extern const uint8_t DNAC_SIGHASH_V5_TAG[DNAC_SIGHASH_V5_TAG_LEN];

/** Exact sighash_v5 preimage length (= 581; pinned by a _Static_assert
 *  in tx_wire.c and re-checked at the final write offset there). */
#define DNAC_SIGHASH_V5_PREIMAGE_LEN                                       \
    (DNAC_SIGHASH_V5_TAG_LEN + DNA_EXEC_CTX_WIRE_LEN + 1 + 64 + 32 + 1 +   \
     128 + 1 + 128 + 8 + 8 + 8 + 8 + 64 + 64)

/**
 * Canonical shielded statement sighash (preimage above).
 *
 * Fail-closed on: any NULL argument; a context failing
 * dna_exec_context_validate; num_input > 4; num_output > 4; any anchor /
 * nf_set / output_commit lane ≥ the Goldilocks modulus; any nonzero lane
 * in a slot at or beyond its count; boundary_in ≥ 2^63; boundary_out ≥
 * 2^63; a preimage that did not land exactly on
 * DNAC_SIGHASH_V5_PREIMAGE_LEN.
 *
 * st->tx_binding, st->sect_version and st->fri_len are NOT read (the
 * preimage's sect_version is the explicit parameter, and tx_binding is
 * this hash's image) — so this function's accept set is deliberately a
 * superset of dnac_txw3_shielded_encode's: the wire codec is the stricter
 * of the two, never the looser.
 *
 * @return 0 on success (out_sighash[64] filled), -1 otherwise.
 */
int dnac_sighash_v5(const dna_exec_context_t *ctx, uint8_t sect_version,
                    const uint8_t ruleset_hash[DNAC_TXW_HASH_LEN],
                    const dnac_txw3_shielded_t *st,
                    const uint8_t tleg_commit[DNAC_TXW_HASH_LEN],
                    const uint8_t ct_commit[DNAC_TXW_HASH_LEN],
                    uint8_t out_sighash[DNAC_TXW_HASH_LEN]);

/** Empty transparent-leg commitment = SHA3-512("DNA.E.TLEG.v1" tag
 *  alone, 16 bytes). @return 0 / -1. */
int dnac_tleg_commit_empty(uint8_t out[DNAC_TXW_HASH_LEN]);

/** Empty ciphertext commitment = SHA3-512("DNA.E.CTC.v1" tag alone,
 *  16 bytes). @return 0 / -1. */
int dnac_ct_commit_empty(uint8_t out[DNAC_TXW_HASH_LEN]);

/* ══════════════════════════════════════════════════════════════════════
 * 6. Transparent-leg section v1 (Ledger V2 Season 9 — INACTIVE)
 *
 * The canonical variable-length transparent section a Transaction Wire V3
 * body may carry AHEAD of the §4 shielded section. It is a NEW section:
 * nothing above it moved, the frozen §4 layout is untouched, and no live
 * consensus path decodes a V3 body at all.
 *
 * ── POLICY NEUTRALITY (S8 §C.10 discipline, tx_wire.h:144-158) ─────────
 * This codec has NO transaction-type, domain, or pool branch and MUST NOT
 * grow one. It enforces STRUCTURE only:
 *   - the version byte, the three structural caps, the input ordering rule
 *     and the zero-amount rule.
 * Per-type COUNT WINDOWS are NOT codec rules and are deliberately absent —
 * "this type needs at least one transparent input", "this type carries
 * exactly one output", "this type may not carry signers" are NATIVE
 * (runtime/admission) rules that live at the type-specific call sites. A
 * structurally canonical leg that no transaction type would accept still
 * encodes, decodes and commits here; rejecting it is the caller's job.
 *
 * ── Layout (offsets from the START of the leg; integers BIG-ENDIAN) ────
 *   off 0    len 1              tleg_version = DNAC_TXW3_TLEG_VERSION (1)
 *   off 1    len 1              num_tin          (≤ DNAC_TXW_MAX_INPUTS)
 *   off 2    len 64·num_tin     tin nullifiers, each 64 B, STRICTLY
 *                               ASCENDING lexicographic (memcmp) — equal
 *                               or descending neighbours are non-canonical,
 *                               which makes an in-leg duplicate spend a
 *                               decode reject for free
 *            len 1              num_tout         (≤ DNAC_TXW_MAX_OUTPUTS)
 *            per tout, 169 B:   fp[129] ‖ amount u64 BE ‖ seed[32]
 *                               amount MUST be ≥ 1 (a zero-value output is
 *                               a reject, never an encoding). NO token_id
 *                               (the asset is native-pinned) and NO memo.
 *            len 1              num_signers      (≤ DNAC_TXW_MAX_SIGNERS)
 *            per signer, 7219 B: pubkey[2592] ‖ signature[4627]
 *
 *   LEG_LEN = DNAC_TXW3_TLEG_FIXED (4 = version + the three count bytes)
 *           + 64·num_tin + 169·num_tout + 7219·num_signers
 *   The three counts determine the length exactly; the decoder walks it.
 *
 * ── PREFIX decode (unlike §2/§4, which are EXACT-length) ───────────────
 * dnac_txw3_tleg_decode walks exactly ONE leg starting at body[0] and
 * reports how many bytes it consumed. It does NOT require
 * consumed == body_len, because the leg is a PREFIX of a larger body: the
 * caller hands the remainder (body + consumed, body_len − consumed) to
 * dnac_txw3_shielded_decode, whose own EXACT length equality is what
 * rejects a truncated or trailing-byte body. Splitting the body is a
 * type-specific (native-layer) step, not something this codec decides.
 *
 * ── Unused array slots ────────────────────────────────────────────────
 * The struct holds fixed arrays sized at the caps, but only the first
 * num_* entries of each exist on the wire and in the commitment. Slots at
 * or beyond a count are NOT emitted, NOT hashed, and NOT judged — decode
 * zeroes the whole struct first, so a decoded leg always re-encodes
 * byte-identically.
 * ════════════════════════════════════════════════════════════════════ */

/** Transparent-leg section version carried at leg offset 0. */
#define DNAC_TXW3_TLEG_VERSION      1
/** Per-output wire size: fp(129) + amount(8) + nullifier_seed(32) = 169. */
#define DNAC_TXW3_TLEG_TOUT_LEN     (DNAC_TXW_FP_LEN + 8 + DNAC_TXW_SEED_LEN)
/** Per-signer wire size: pubkey(2592) + signature(4627) = 7219. Same pair
 *  the legacy signers section carries (TXW_SIGNER_SIZE, tx_wire.c:269). */
#define DNAC_TXW3_TLEG_SIGNER_LEN   (DNAC_TXW_PK_LEN + DNAC_TXW_SIG_LEN)
/** Count-independent overhead: tleg_version + num_tin + num_tout +
 *  num_signers = 4 bytes. A 0/0/0 leg is exactly these 4 bytes. */
#define DNAC_TXW3_TLEG_FIXED        4
/** Largest structurally legal leg (16 in / 16 out / 4 signers):
 *  4 + 1024 + 2704 + 28876 = 32608. Pinned by a _Static_assert in
 *  tx_wire.c; it is what bounds every length computation here. */
#define DNAC_TXW3_TLEG_MAX_LEN                                             \
    ((size_t)DNAC_TXW3_TLEG_FIXED                                          \
     + (size_t)DNAC_TXW_MAX_INPUTS  * DNAC_TXW_NULLIFIER_LEN               \
     + (size_t)DNAC_TXW_MAX_OUTPUTS * DNAC_TXW3_TLEG_TOUT_LEN              \
     + (size_t)DNAC_TXW_MAX_SIGNERS * DNAC_TXW3_TLEG_SIGNER_LEN)

/** One transparent output: owner fingerprint, amount, nullifier seed.
 *  Mirrors the legacy transparent output MINUS version/token_id/memo. */
typedef struct {
    uint8_t  fp[DNAC_TXW_FP_LEN];               /* 129 — owner fingerprint */
    uint64_t amount;                            /* MUST be >= 1            */
    uint8_t  nullifier_seed[DNAC_TXW_SEED_LEN]; /* 32                      */
} dnac_txw3_tout_t;

/** One transparent signer: the authorizing Dilithium5 keypair material.
 *  The PUBKEY is committed (dnac_tleg_commit); the SIGNATURE is not. */
typedef struct {
    uint8_t pubkey[DNAC_TXW_PK_LEN];      /* 2592 */
    uint8_t signature[DNAC_TXW_SIG_LEN];  /* 4627 */
} dnac_txw3_signer_t;

/**
 * A decoded transparent leg.
 *
 * SIZE: the arrays are fixed at the structural caps, so one of these is
 * roughly 32 KB of storage (1024 B of nullifiers + 16 padded outputs +
 * 4 × 7219 B of signer material). That is fine on a desktop/server stack
 * but is NOT something to place on a small thread stack (Android bionic
 * gives a pthread 1 MB by default) — heap-allocate it if in doubt, and
 * never put two of them in one frame casually.
 */
typedef struct {
    uint8_t  tleg_version;                      /* must be 1 */
    uint8_t  num_tin;                           /* 0..16     */
    uint8_t  tin_nullifier[DNAC_TXW_MAX_INPUTS][DNAC_TXW_NULLIFIER_LEN];
    uint8_t  num_tout;                          /* 0..16     */
    dnac_txw3_tout_t tout[DNAC_TXW_MAX_OUTPUTS];
    uint8_t  num_signers;                       /* 0..4      */
    dnac_txw3_signer_t signer[DNAC_TXW_MAX_SIGNERS];
} dnac_txw3_tleg_t;

/**
 * Exact encoded leg size for the three counts, with the structural caps
 * enforced (they are what makes the sum unable to overflow: it is bounded
 * by DNAC_TXW3_TLEG_MAX_LEN).
 * @return 0 on success (size in *out), -1 on NULL *out or any count over
 *         its cap (*out set to 0 first, so a caller that ignores the
 *         return value cannot read a stale length).
 */
int dnac_txw3_tleg_encoded_size(uint8_t num_tin, uint8_t num_tout,
                                uint8_t num_signers, size_t *out);

/**
 * Canonical encode of one transparent leg.
 * Refuses to emit anything the decoder would reject — the SAME ordered
 * rule list runs on both entries (tleg_version != 1, a count over its cap,
 * a non-ascending or duplicate input nullifier, a zero-amount output), so
 * a leg that decodes always re-encodes byte-identically and one that would
 * not is never produced.
 * Rejects additionally: NULL args, dst_cap short of the exact length.
 * @return 0 on success (*written_out = LEG_LEN), -1 otherwise.
 */
int dnac_txw3_tleg_encode(const dnac_txw3_tleg_t *t,
                          uint8_t *dst, size_t dst_cap, size_t *written_out);

/**
 * Strict canonical PREFIX decode of one transparent leg from body[0].
 *
 * On success fills *out and reports the consumed length in *consumed_out;
 * body_len may exceed it (see the PREFIX note above) — the bytes past
 * *consumed_out are neither read nor judged here.
 * On ANY rejection *out is zeroed (fail closed — the zeroing happens
 * FIRST, before the first byte is examined, so no reject path can leave
 * caller memory partially populated) and *consumed_out is untouched.
 * Rejects: NULL args, truncation at any field boundary, tleg_version != 1,
 * a count over its cap, non-ascending or duplicate input nullifiers, a
 * zero-amount output.
 * @return 0 / -1.
 */
int dnac_txw3_tleg_decode(const uint8_t *body, size_t body_len,
                          dnac_txw3_tleg_t *out, size_t *consumed_out);

/**
 * POPULATED transparent-leg commitment — the value that fills the frozen
 * sighash_v5 slot at preimage offset 453 when a transaction carries a
 * transparent leg. (An ABSENT leg uses dnac_tleg_commit_empty and its own
 * "DNA.E.TLEG.v1" tag: two distinct domains, so an empty leg and a
 * populated-but-empty-looking one can never collide.)
 *
 * ── Preimage (exact bytes) ────────────────────────────────────────────
 *   "DNA.TLEG.v1" + 5×0x00                        (16)
 *   ‖ num_tin u8  ‖ nullifier[64] × num_tin       (ascending, as on wire)
 *   ‖ num_tout u8 ‖ (fp[129] ‖ amount u64 BE ‖ seed[32]) × num_tout
 *   ‖ num_signers u8 ‖ pubkey[2592] × num_signers
 *   hash = SHA3-512(preimage) → the 64-byte commitment
 *
 * ── Two deliberate exclusions ─────────────────────────────────────────
 *   - SIGNATURES are NOT committed; signer PUBKEYS are. This is the frozen
 *     legacy tx-hash discipline (tx_wire.h:80-82): a signature cannot
 *     cover itself, and the commitment must be computable BEFORE signing
 *     because it is what the signers sign (through sighash_v5).
 *   - tleg_version is NOT committed: it is wire framing, and the wire
 *     bytes it frames are re-derived from this struct on every path.
 *     tx_type is NOT committed either: sighash_v5 binds it once, in its
 *     ExecutionContext block (preimage offset 56) — one source, so a
 *     type-12 leg replayed as type-13 already yields a different sighash.
 *
 * A non-canonical leg MUST NOT hash: this runs the same rule list as
 * encode/decode and fails closed first.
 * @return 0 on success (out[64] filled), -1 otherwise (NULL included).
 */
int dnac_tleg_commit(const dnac_txw3_tleg_t *t, uint8_t out[DNAC_TXW_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_TX_WIRE_H */
