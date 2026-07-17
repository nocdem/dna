/**
 * @file serialize.c
 * @brief Transaction serialization (v2: committed_fee + delegation_amount)
 *
 * v2 Wire Format (design: dnac/docs/plans/2026-04-22-committed-fee-wire-field-design.md):
 * - Header (DNAC_TX_HEADER_SIZE = 82 B):
 *     version(1) + type(1) + timestamp(8) + tx_hash(64) + committed_fee(8, BE)
 * - Inputs:   count(1) + [nullifier(64) + amount(8) + token_id(64)]...
 * - Outputs:  count(1) + [version(1) + fingerprint(129) + amount(8) + token_id(64) + seed(32) + memo_len(1) + memo(n)]...
 * - Witnesses: count(1) + [witness_id(32) + signature(4627) + timestamp(8) + server_pubkey(2592)]...
 * - Signers:   count(1) + [pubkey(2592) + signature(4627)]...
 * - Type-specific appended fields:
 *     STAKE        : commission_bps(u16 BE) + unstake_destination_fp(64) + purpose_tag(17)
 *     DELEGATE     : validator_pubkey(2592) + delegation_amount(u64 BE)   [delegation_amount NEW in v2]
 *     UNDELEGATE   : validator_pubkey(2592) + amount(u64 BE)
 *     VALIDATOR_UPDATE : new_commission_bps(u16 BE) + signed_at_block(u64 BE)
 *     CHAIN_CONFIG : (see shared/dnac/chain_config_wire.h)
 * - Optional trailer: has_chain_def flag + chain_def blob (genesis only)
 *
 * v1 serializer + deserializer have been DELETED. Dead chains stay on disk under
 * /var/lib/nodus/data.pre-v0.17.1/ for forensic inspection; use
 * `git checkout 7893f1fa` to decode them.
 */

#include "dnac/transaction.h"
#include "dnac/chain_def_codec.h"  /* for optional genesis chain_def payload */
#include "dnac/chain_config_wire.h"  /* shared CHAIN_CONFIG extension codec */
#include <string.h>
#include <stdlib.h>
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#include "crypto/hash/qgp_sha3.h"           /* dual-mode S5: sighash_v4 (SHA3-512) */

/* Pin shared wire constants against dnac's authoritative values — any
 * drift between libnodus and libdna would silently break consensus. */
_Static_assert(DNAC_CC_WIRE_SIGNATURE_SIZE == DNAC_SIGNATURE_SIZE,
               "chain_config signature size drift");
_Static_assert(DNAC_CC_WIRE_COMMITTEE_SIZE == DNAC_COMMITTEE_SIZE,
               "chain_config committee size drift");
_Static_assert(DNAC_CC_WIRE_MIN_SIGS == DNAC_CHAIN_CONFIG_MIN_SIGS,
               "chain_config min-sigs drift");

/* Helper macros for serialization */
#define WRITE_U8(buf, val) do { *(buf)++ = (uint8_t)(val); } while(0)
#define WRITE_U64(buf, val) do { \
    uint64_t v = (val); \
    memcpy(buf, &v, 8); \
    buf += 8; \
} while(0)
#define WRITE_BLOB(buf, src, len) do { \
    memcpy(buf, src, len); \
    buf += (len); \
} while(0)

/* Helper macros for deserialization */
#define READ_U8(buf, val) do { (val) = *(buf)++; } while(0)
#define READ_U64(buf, val) do { \
    memcpy(&(val), buf, 8); \
    buf += 8; \
} while(0)
#define READ_BLOB(buf, dst, len) do { \
    memcpy(dst, buf, len); \
    buf += (len); \
} while(0)

/* Big-endian u64 helpers for Phase 5 appended-field encoding (design §2.3).
 * Local to serialize.c so the wire encoding is BE even on LE hosts. */
static inline void be64_to_bytes(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static inline uint64_t be64_from_bytes(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) { v = (v << 8) | (uint64_t)in[i]; }
    return v;
}

/* Calculate v2 transaction size */
static size_t calc_tx_size(const dnac_transaction_t *tx) {
    size_t size = 0;

    /* Header (82 bytes in v2) */
    size += DNAC_TX_HEADER_SIZE;
    /* = version(1) + type(1) + timestamp(8) + tx_hash(64) + committed_fee(8) */

    /* Inputs */
    size += 1;  /* input_count */
    size += tx->input_count * (DNAC_NULLIFIER_SIZE + 8 + DNAC_TOKEN_ID_SIZE);  /* nullifier(64) + amount(8) + token_id(64) */

    /* Outputs (Gap 25: v0.6.0 - now includes memo) */
    size += 1;  /* output_count */
    for (int i = 0; i < tx->output_count; i++) {
        size += 1 + DNAC_FINGERPRINT_SIZE + 8 + DNAC_TOKEN_ID_SIZE + 32;  /* version(1) + fp(129) + amount(8) + token_id(64) + seed(32) */
        size += 1;  /* memo_len */
        size += tx->outputs[i].memo_len;  /* memo data */
    }

    /* Witnesses */
    size += 1;  /* witness_count */
    size += tx->witness_count * (32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE);  /* witness_id(32) + sig(4627) + timestamp(8) + pubkey(2592) */

    /* Signers */
    size += 1;  /* signer_count */
    size += tx->signer_count * (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE);

    /* Type-specific appended fields (Phase 5 Task 16). STAKE carries
     * commission_bps(2) + unstake_destination_fp(64) + purpose_tag(17). */
    if (tx->type == DNAC_TX_STAKE) {
        size += 2 + DNAC_STAKE_UNSTAKE_DEST_FP_SIZE + DNAC_STAKE_PURPOSE_TAG_LEN;
    }
    /* Phase 5 Task 17. DELEGATE carries validator_pubkey(2592) + delegation_amount(u64 BE, v0.17.1+). */
    if (tx->type == DNAC_TX_DELEGATE) {
        size += DNAC_PUBKEY_SIZE + 8;
    }
    /* Phase 5 Task 18. UNDELEGATE carries validator_pubkey(2592) + amount(u64). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        size += DNAC_PUBKEY_SIZE + 8;
    }
    /* Phase 5 Task 19. VALIDATOR_UPDATE carries new_commission_bps(u16) +
     * signed_at_block(u64). */
    if (tx->type == DNAC_TX_VALIDATOR_UPDATE) {
        size += 2 + 8;
    }
    /* Hard-Fork v1. CHAIN_CONFIG fixed header + votes — see shared
     * dnac/chain_config_wire.h for the authoritative layout. */
    if (tx->type == DNAC_TX_CHAIN_CONFIG) {
        uint8_t n = tx->chain_config_fields.committee_sig_count;
        if (n > DNAC_CC_WIRE_COMMITTEE_SIZE) n = DNAC_CC_WIRE_COMMITTEE_SIZE;
        size += DNAC_CC_WIRE_FIXED_LEN +
                (size_t)n * DNAC_CC_WIRE_PER_VOTE;
    }
    /* Dual-mode S5. Shielded section (only for DNAC_TX_SHIELDED). */
    if (tx->type == DNAC_TX_SHIELDED) {
        size += (size_t)DNAC_TX_SHIELDED_FIXED_SIZE +
                tx->shielded_fields.fri_proof_len;
    }

    /* Optional anchored-genesis chain_def trailer (v2 wire extension).
     * Only present when has_chain_def is true (always 0 for non-genesis).
     * Layout: flag(1) [|| chain_def_len(4 LE) || chain_def_bytes] */
    size += 1;  /* has_chain_def flag byte */
    if (tx->has_chain_def) {
        size += 4;  /* chain_def_len */
        size += dnac_chain_def_encoded_size(&tx->chain_def);
    }

    return size;
}

/* ── Dual-mode S5 — shielded section (BIG-ENDIAN lanes; DET-S5-1). ── */
#define DNAC_SHIELDED_GOLDILOCKS_P 0xFFFFFFFF00000001ULL /* 2^64-2^32+1 */

static void write_shielded_section(uint8_t **pp,
                                   const dnac_tx_shielded_fields_t *sf) {
    uint8_t *ptr = *pp;
    uint8_t be[8];
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        be64_to_bytes(sf->anchor[j], be); WRITE_BLOB(ptr, be, 8);
    }
    WRITE_U8(ptr, sf->num_input);
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            be64_to_bytes(sf->nf_set[s][j], be); WRITE_BLOB(ptr, be, 8);
        }
    WRITE_U8(ptr, sf->num_output);
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            be64_to_bytes(sf->output_commit[s][j], be); WRITE_BLOB(ptr, be, 8);
        }
    be64_to_bytes(sf->fee, be); WRITE_BLOB(ptr, be, 8);
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        be64_to_bytes(sf->tx_binding[j], be); WRITE_BLOB(ptr, be, 8);
    }
    uint8_t lb[4] = { (uint8_t)(sf->fri_proof_len >> 24), (uint8_t)(sf->fri_proof_len >> 16),
                      (uint8_t)(sf->fri_proof_len >> 8),  (uint8_t)(sf->fri_proof_len) };
    WRITE_BLOB(ptr, lb, 4);
    if (sf->fri_proof_len && sf->fri_proof)
        WRITE_BLOB(ptr, sf->fri_proof, sf->fri_proof_len);
    *pp = ptr;
}

/* Reject non-canonical lanes (A-9: each 8-byte lane MUST be < p). */
static int shielded_lane_bad(uint64_t v) { return v >= DNAC_SHIELDED_GOLDILOCKS_P; }

static int read_shielded_section(const uint8_t **pp, const uint8_t *end,
                                 dnac_tx_shielded_fields_t *sf) {
    const uint8_t *ptr = *pp;
    if ((size_t)(end - ptr) < (size_t)DNAC_TX_SHIELDED_FIXED_SIZE) return -1;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        sf->anchor[j] = be64_from_bytes(ptr); ptr += 8;
        if (shielded_lane_bad(sf->anchor[j])) return -1;
    }
    READ_U8(ptr, sf->num_input);
    if (sf->num_input > DNAC_SHIELDED_MAX_INPUTS) return -1;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            sf->nf_set[s][j] = be64_from_bytes(ptr); ptr += 8;
            if (shielded_lane_bad(sf->nf_set[s][j])) return -1;
            /* DET-S5-3: unused slots (s >= num_input) MUST be zero (canonical). */
            if (s >= sf->num_input && sf->nf_set[s][j] != 0) return -1;
        }
    READ_U8(ptr, sf->num_output);
    if (sf->num_output > DNAC_SHIELDED_MAX_OUTPUTS) return -1;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            sf->output_commit[s][j] = be64_from_bytes(ptr); ptr += 8;
            if (shielded_lane_bad(sf->output_commit[s][j])) return -1;
            if (s >= sf->num_output && sf->output_commit[s][j] != 0) return -1;
        }
    sf->fee = be64_from_bytes(ptr); ptr += 8;
    if (shielded_lane_bad(sf->fee)) return -1;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        sf->tx_binding[j] = be64_from_bytes(ptr); ptr += 8;
        if (shielded_lane_bad(sf->tx_binding[j])) return -1;
    }
    uint32_t len = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16)
                 | ((uint32_t)ptr[2] << 8)  | (uint32_t)ptr[3];
    ptr += 4;
    if ((size_t)(end - ptr) < (size_t)len) return -1;
    sf->fri_proof_len = len;
    if (len) {
        sf->fri_proof = (uint8_t *)malloc(len);
        if (!sf->fri_proof) return -1;
        memcpy(sf->fri_proof, ptr, len);
        ptr += len;
    } else {
        sf->fri_proof = NULL;
    }
    *pp = ptr;
    return 0;
}

int dnac_tx_serialize(const dnac_transaction_t *tx,
                      uint8_t *buffer,
                      size_t buffer_len,
                      size_t *written_out) {
    if (!tx || !buffer || !written_out) return DNAC_ERROR_INVALID_PARAM;

    size_t needed = calc_tx_size(tx);
    if (buffer_len < needed) {
        *written_out = needed;  /* Return needed size */
        return DNAC_ERROR_INVALID_PARAM;
    }

    uint8_t *ptr = buffer;

    /* Header (v2: 82 bytes, see DNAC_TX_HEADER_SIZE) */
    WRITE_U8(ptr, tx->version);
    WRITE_U8(ptr, tx->type);
    WRITE_U64(ptr, tx->timestamp);
    WRITE_BLOB(ptr, tx->tx_hash, DNAC_TX_HASH_SIZE);
    /* committed_fee: 8 bytes, big-endian (v0.17.1+) */
    {
        uint8_t fee_be[8];
        be64_to_bytes(tx->committed_fee, fee_be);
        WRITE_BLOB(ptr, fee_be, 8);
    }

    /* Inputs */
    WRITE_U8(ptr, tx->input_count);
    for (int i = 0; i < tx->input_count; i++) {
        WRITE_BLOB(ptr, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        WRITE_U64(ptr, tx->inputs[i].amount);
        WRITE_BLOB(ptr, tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* Outputs (Gap 25: v0.6.0 - now includes memo) */
    WRITE_U8(ptr, tx->output_count);
    for (int i = 0; i < tx->output_count; i++) {
        WRITE_U8(ptr, tx->outputs[i].version);
        WRITE_BLOB(ptr, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        WRITE_U64(ptr, tx->outputs[i].amount);
        WRITE_BLOB(ptr, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
        WRITE_BLOB(ptr, tx->outputs[i].nullifier_seed, 32);
        WRITE_U8(ptr, tx->outputs[i].memo_len);
        if (tx->outputs[i].memo_len > 0) {
            WRITE_BLOB(ptr, tx->outputs[i].memo, tx->outputs[i].memo_len);
        }
    }

    /* Witnesses */
    WRITE_U8(ptr, tx->witness_count);
    for (int i = 0; i < tx->witness_count; i++) {
        WRITE_BLOB(ptr, tx->witnesses[i].witness_id, 32);
        WRITE_BLOB(ptr, tx->witnesses[i].signature, DNAC_SIGNATURE_SIZE);
        WRITE_U64(ptr, tx->witnesses[i].timestamp);
        WRITE_BLOB(ptr, tx->witnesses[i].server_pubkey, DNAC_PUBKEY_SIZE);
    }

    /* Signers */
    WRITE_U8(ptr, tx->signer_count);
    for (int i = 0; i < tx->signer_count; i++) {
        WRITE_BLOB(ptr, tx->signers[i].pubkey, DNAC_PUBKEY_SIZE);
        WRITE_BLOB(ptr, tx->signers[i].signature, DNAC_SIGNATURE_SIZE);
    }

    /* Type-specific appended fields (Phase 5 Task 16).
     * STAKE: commission_bps(u16 BE) || unstake_destination_fp[64] ||
     *        purpose_tag[17] ("DNAC_VALIDATOR_v1"). */
    if (tx->type == DNAC_TX_STAKE) {
        ptr[0] = (uint8_t)((tx->stake_fields.commission_bps >> 8) & 0xff);
        ptr[1] = (uint8_t)(tx->stake_fields.commission_bps & 0xff);
        ptr += 2;
        WRITE_BLOB(ptr, tx->stake_fields.unstake_destination_fp,
                   DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);
        WRITE_BLOB(ptr, DNAC_STAKE_PURPOSE_TAG, DNAC_STAKE_PURPOSE_TAG_LEN);
    }
    /* Phase 5 Task 17 + v0.17.1. DELEGATE: validator_pubkey[2592] || delegation_amount(u64 BE). */
    if (tx->type == DNAC_TX_DELEGATE) {
        WRITE_BLOB(ptr, tx->delegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
        uint8_t amount_be[8];
        be64_to_bytes(tx->delegate_fields.delegation_amount, amount_be);
        WRITE_BLOB(ptr, amount_be, 8);
    }
    /* Phase 5 Task 18. UNDELEGATE: validator_pubkey[2592] || amount(u64 BE). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        WRITE_BLOB(ptr, tx->undelegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
        uint8_t amount_be[8];
        be64_to_bytes(tx->undelegate_fields.amount, amount_be);
        WRITE_BLOB(ptr, amount_be, 8);
    }
    /* Phase 5 Task 19. VALIDATOR_UPDATE: new_commission_bps(u16 BE) ||
     *        signed_at_block(u64 BE). */
    if (tx->type == DNAC_TX_VALIDATOR_UPDATE) {
        ptr[0] = (uint8_t)((tx->validator_update_fields.new_commission_bps >> 8) & 0xff);
        ptr[1] = (uint8_t)(tx->validator_update_fields.new_commission_bps & 0xff);
        ptr += 2;
        uint8_t block_be[8];
        be64_to_bytes(tx->validator_update_fields.signed_at_block, block_be);
        WRITE_BLOB(ptr, block_be, 8);
    }
    /* Hard-Fork v1. CHAIN_CONFIG — delegated to shared encoder so drift
     * between libdna and libnodus cannot silently break consensus. See
     * shared/dnac/chain_config_wire.h for the byte layout. */
    if (tx->type == DNAC_TX_CHAIN_CONFIG) {
        const dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
        dnac_cc_wire_ext_t wire = {
            .param_id               = cc->param_id,
            .new_value              = cc->new_value,
            .effective_block_height = cc->effective_block_height,
            .proposal_nonce         = cc->proposal_nonce,
            .signed_at_block        = cc->signed_at_block,
            .valid_before_block     = cc->valid_before_block,
            .committee_sig_count    = cc->committee_sig_count,
        };
        uint8_t n_wire = wire.committee_sig_count;
        if (n_wire > DNAC_CC_WIRE_COMMITTEE_SIZE)
            n_wire = DNAC_CC_WIRE_COMMITTEE_SIZE;
        for (uint8_t i = 0; i < n_wire; i++) {
            memcpy(wire.votes[i].witness_id,
                   cc->committee_votes[i].witness_id,
                   DNAC_CC_WIRE_WITNESS_ID_SIZE);
            memcpy(wire.votes[i].signature,
                   cc->committee_votes[i].signature,
                   DNAC_CC_WIRE_SIGNATURE_SIZE);
        }
        size_t written = 0;
        size_t cap = buffer_len - (size_t)(ptr - buffer);
        if (dnac_cc_wire_encode(&wire, ptr, cap, &written) != 0)
            return DNAC_ERROR_INVALID_PARAM;
        ptr += written;
    }

    /* Dual-mode S5. Shielded section (only DNAC_TX_SHIELDED; additive trailer,
     * placed after all type-appended fields, before the chain_def trailer). */
    if (tx->type == DNAC_TX_SHIELDED) {
        write_shielded_section(&ptr, &tx->shielded_fields);
    }

    /* Anchored-genesis chain_def trailer (optional, genesis TX only). */
    WRITE_U8(ptr, tx->has_chain_def ? 1 : 0);
    if (tx->has_chain_def) {
        size_t cd_len = dnac_chain_def_encoded_size(&tx->chain_def);
        /* Write len as u32 LE (match existing codec convention) */
        ptr[0] = (uint8_t)(cd_len & 0xff);
        ptr[1] = (uint8_t)((cd_len >> 8) & 0xff);
        ptr[2] = (uint8_t)((cd_len >> 16) & 0xff);
        ptr[3] = (uint8_t)((cd_len >> 24) & 0xff);
        ptr += 4;
        size_t written = 0;
        int rc = dnac_chain_def_encode(&tx->chain_def, ptr,
                                         buffer_len - (ptr - buffer), &written);
        if (rc != 0 || written != cd_len) return DNAC_ERROR_INVALID_PARAM;
        ptr += written;
    }

    *written_out = (size_t)(ptr - buffer);
    return DNAC_SUCCESS;
}

int dnac_tx_deserialize(const uint8_t *buffer,
                        size_t buffer_len,
                        dnac_transaction_t **tx_out) {
    /* v2 header minimum (SEC-02: length check MUST precede any offset
     * read including the committed_fee at offset 74). */
    if (!buffer || !tx_out || buffer_len < DNAC_TX_HEADER_SIZE) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    /* v2 version gate (SEC-02): reject v1 (and unknown future versions)
     * BEFORE reading any wire field beyond byte 0. */
    if (buffer[0] != DNAC_PROTOCOL_VERSION) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_transaction_t *tx = calloc(1, sizeof(dnac_transaction_t));
    if (!tx) return DNAC_ERROR_OUT_OF_MEMORY;

    const uint8_t *ptr = buffer;
    const uint8_t *end = buffer + buffer_len;

    /* Header (v2: 82 bytes) */
    READ_U8(ptr, tx->version);
    READ_U8(ptr, tx->type);
    /* M-32: Validate tx_type is within known range.
     * Phase 5 Task 16 admitted stake/delegation types (4..9).
     * Hard-Fork v1 adds DNAC_TX_CHAIN_CONFIG (10).
     * Dual-mode S5 adds DNAC_TX_SHIELDED (11) — additive: a node built WITHOUT
     * this change still rejects type 11 (fail-closed), so V4 stays inert on the
     * live chain until S6. */
    if (tx->type > DNAC_TX_SHIELDED) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    READ_U64(ptr, tx->timestamp);
    READ_BLOB(ptr, tx->tx_hash, DNAC_TX_HASH_SIZE);
    /* committed_fee: 8 bytes, big-endian (v0.17.1+) */
    tx->committed_fee = be64_from_bytes(ptr);
    ptr += 8;

    /* Inputs */
    if (ptr + 1 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }  /* audit L2 */
    uint8_t input_count;
    READ_U8(ptr, input_count);
    if (input_count > DNAC_TX_MAX_INPUTS) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    /* D7.1 transparent-exclusion: a shielded TX carries NO transparent inputs —
     * all value movement lives in the shielded section (no plaintext to smuggle). */
    if (tx->type == DNAC_TX_SHIELDED && input_count != 0) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    tx->input_count = input_count;

    for (int i = 0; i < input_count; i++) {
        if (ptr + DNAC_NULLIFIER_SIZE + 8 + DNAC_TOKEN_ID_SIZE > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        READ_U64(ptr, tx->inputs[i].amount);
        READ_BLOB(ptr, tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* Outputs */
    if (ptr + 1 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }  /* audit L2 */
    uint8_t output_count;
    READ_U8(ptr, output_count);
    if (output_count > DNAC_TX_MAX_OUTPUTS) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    /* D7.1 transparent-exclusion: a shielded TX carries NO transparent outputs. */
    if (tx->type == DNAC_TX_SHIELDED && output_count != 0) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    tx->output_count = output_count;

    for (int i = 0; i < output_count; i++) {
        /* Check minimum output size (without memo) */
        size_t out_size = 1 + DNAC_FINGERPRINT_SIZE + 8 + DNAC_TOKEN_ID_SIZE + 32 + 1;  /* +1 for memo_len */
        if (ptr + out_size > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_U8(ptr, tx->outputs[i].version);
        READ_BLOB(ptr, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        READ_U64(ptr, tx->outputs[i].amount);
        READ_BLOB(ptr, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
        READ_BLOB(ptr, tx->outputs[i].nullifier_seed, 32);
        /* Gap 25: v0.6.0 - read memo */
        READ_U8(ptr, tx->outputs[i].memo_len);
        if (tx->outputs[i].memo_len > 0) {
            /* memo_len is uint8_t (max 255), buffer is DNAC_MEMO_MAX_SIZE (256) — always fits */
            if (ptr + tx->outputs[i].memo_len > end) {
                free(tx);
                return DNAC_ERROR_INVALID_PARAM;
            }
            READ_BLOB(ptr, tx->outputs[i].memo, tx->outputs[i].memo_len);
        }
    }

    /* Witnesses */
    if (ptr + 1 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }  /* audit L2 */
    uint8_t witness_count;
    READ_U8(ptr, witness_count);
    if (witness_count > DNAC_TX_MAX_WITNESSES) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    tx->witness_count = witness_count;

    for (int i = 0; i < witness_count; i++) {
        size_t witness_size = 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE;
        if (ptr + witness_size > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->witnesses[i].witness_id, 32);
        READ_BLOB(ptr, tx->witnesses[i].signature, DNAC_SIGNATURE_SIZE);
        READ_U64(ptr, tx->witnesses[i].timestamp);
        READ_BLOB(ptr, tx->witnesses[i].server_pubkey, DNAC_PUBKEY_SIZE);
    }

    /* Signers */
    if (ptr + 1 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
    uint8_t signer_count;
    READ_U8(ptr, signer_count);
    if (signer_count > DNAC_TX_MAX_SIGNERS) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
    tx->signer_count = signer_count;

    for (int i = 0; i < signer_count; i++) {
        if (ptr + DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->signers[i].pubkey, DNAC_PUBKEY_SIZE);
        READ_BLOB(ptr, tx->signers[i].signature, DNAC_SIGNATURE_SIZE);
    }

    /* Type-specific appended fields (Phase 5 Task 16).
     * STAKE: commission_bps(u16 BE) || unstake_destination_fp[64] ||
     *        purpose_tag[17]. Purpose tag MUST match exactly —
     *        cross-protocol reuse defense (F-CRYPTO-05). */
    if (tx->type == DNAC_TX_STAKE) {
        const size_t stake_appended_len = 2 + DNAC_STAKE_UNSTAKE_DEST_FP_SIZE
                                        + DNAC_STAKE_PURPOSE_TAG_LEN;
        if (ptr + stake_appended_len > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        tx->stake_fields.commission_bps =
            ((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1];
        ptr += 2;
        READ_BLOB(ptr, tx->stake_fields.unstake_destination_fp,
                  DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);
        if (memcmp(ptr, DNAC_STAKE_PURPOSE_TAG,
                   DNAC_STAKE_PURPOSE_TAG_LEN) != 0) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        ptr += DNAC_STAKE_PURPOSE_TAG_LEN;
    }
    /* Phase 5 Task 17 + v0.17.1. DELEGATE: validator_pubkey[2592] || delegation_amount(u64 BE). */
    if (tx->type == DNAC_TX_DELEGATE) {
        if (ptr + DNAC_PUBKEY_SIZE + 8 > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->delegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
        tx->delegate_fields.delegation_amount = be64_from_bytes(ptr);
        ptr += 8;
    }
    /* Phase 5 Task 18. UNDELEGATE: validator_pubkey[2592] || amount(u64 BE). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        if (ptr + DNAC_PUBKEY_SIZE + 8 > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->undelegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
        tx->undelegate_fields.amount = be64_from_bytes(ptr);
        ptr += 8;
    }
    /* Phase 5 Task 19. VALIDATOR_UPDATE: new_commission_bps(u16 BE) ||
     *        signed_at_block(u64 BE). */
    if (tx->type == DNAC_TX_VALIDATOR_UPDATE) {
        if (ptr + 2 + 8 > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        tx->validator_update_fields.new_commission_bps =
            ((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1];
        ptr += 2;
        tx->validator_update_fields.signed_at_block = be64_from_bytes(ptr);
        ptr += 8;
    }
    /* Hard-Fork v1. CHAIN_CONFIG — delegated to shared decoder. */
    if (tx->type == DNAC_TX_CHAIN_CONFIG) {
        dnac_cc_wire_ext_t wire;
        size_t consumed = 0;
        if (dnac_cc_wire_decode(ptr, (size_t)(end - ptr),
                                 &wire, &consumed) != 0) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
        cc->param_id               = wire.param_id;
        cc->new_value              = wire.new_value;
        cc->effective_block_height = wire.effective_block_height;
        cc->proposal_nonce         = wire.proposal_nonce;
        cc->signed_at_block        = wire.signed_at_block;
        cc->valid_before_block     = wire.valid_before_block;
        cc->committee_sig_count    = wire.committee_sig_count;
        for (uint8_t i = 0; i < wire.committee_sig_count; i++) {
            memcpy(cc->committee_votes[i].witness_id,
                   wire.votes[i].witness_id,
                   DNAC_CC_WIRE_WITNESS_ID_SIZE);
            memcpy(cc->committee_votes[i].signature,
                   wire.votes[i].signature,
                   DNAC_CC_WIRE_SIGNATURE_SIZE);
        }
        ptr += consumed;
    }

    /* Dual-mode S5. Shielded section (only DNAC_TX_SHIELDED; read after the
     * type-appended fields, before the chain_def trailer — matches serialize). */
    if (tx->type == DNAC_TX_SHIELDED) {
        if (read_shielded_section(&ptr, end, &tx->shielded_fields) != 0) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
    }

    /* Optional anchored-genesis chain_def trailer.
     *
     * Backward compat: if ptr reached end, this is a legacy v1 TX with
     * no trailer — leave has_chain_def = false (already zero via calloc).
     * If ptr + 1 > end, same thing. Only actively parse when the flag
     * byte is present. */
    if (ptr < end) {
        uint8_t has_cd;
        READ_U8(ptr, has_cd);
        if (has_cd) {
            if (ptr + 4 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
            uint32_t cd_len = (uint32_t)ptr[0]
                            | ((uint32_t)ptr[1] << 8)
                            | ((uint32_t)ptr[2] << 16)
                            | ((uint32_t)ptr[3] << 24);
            ptr += 4;
            if (ptr + cd_len > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
            if (dnac_chain_def_decode(ptr, cd_len, &tx->chain_def) != 0) {
                free(tx);
                return DNAC_ERROR_INVALID_PARAM;
            }
            tx->has_chain_def = true;
            ptr += cd_len;
        }
    }

    *tx_out = tx;
    return DNAC_SUCCESS;
}

void dnac_tx_free(dnac_transaction_t *tx) {
    if (!tx) return;
    /* Only DNAC_TX_SHIELDED owns a separate heap blob; NULL elsewhere. */
    if (tx->shielded_fields.fri_proof) {
        free(tx->shielded_fields.fri_proof);
        tx->shielded_fields.fri_proof = NULL;
    }
    free(tx);
}

int dnac_tx_shielded_sighash(const dnac_tx_shielded_fields_t *sf,
                             const uint8_t chain_id[32],
                             uint8_t out_sighash[QGP_SHA3_512_DIGEST_LENGTH]) {
    if (!sf || !chain_id || !out_sighash) return DNAC_ERROR_INVALID_PARAM;

    /* sighash_v4 preimage (design D3), all lanes BIG-ENDIAN, canonical fixed-width:
     *   DNAC_SIGHASH_V4\0 ‖ chain_id[32] ‖ num_input(1) ‖ nf_set[MI][4]
     *   ‖ num_output(1) ‖ output_commit[MO][4] ‖ fee(8) ‖ anchor[4].
     * Its OWN tag (A-4, distinct from the tx-hash preimage tag). Prover and verifier
     * hash the SAME canonical wire form (unused slots zero, DET-S5-3) → equal
     * sighash → tx_binding = conf_txbind_map(sighash) matches (mapping at S6/prover). */
    uint8_t pre[DNAC_SIGHASH_DOMAIN_V4_LEN + 32 + 1
                + DNAC_SHIELDED_MAX_INPUTS * DNAC_SHIELDED_LANES * 8 + 1
                + DNAC_SHIELDED_MAX_OUTPUTS * DNAC_SHIELDED_LANES * 8 + 8
                + DNAC_SHIELDED_LANES * 8];
    uint8_t *p = pre;
    memcpy(p, DNAC_SIGHASH_DOMAIN_V4, DNAC_SIGHASH_DOMAIN_V4_LEN);
    p += DNAC_SIGHASH_DOMAIN_V4_LEN;
    memcpy(p, chain_id, 32); p += 32;
    *p++ = sf->num_input;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            be64_to_bytes(sf->nf_set[s][j], p); p += 8;
        }
    *p++ = sf->num_output;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            be64_to_bytes(sf->output_commit[s][j], p); p += 8;
        }
    be64_to_bytes(sf->fee, p); p += 8;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        be64_to_bytes(sf->anchor[j], p); p += 8;
    }
    return qgp_sha3_512(pre, (size_t)(p - pre), out_sighash) == 0
               ? DNAC_SUCCESS : DNAC_ERROR_INVALID_PARAM;
}

/* dnac_tx_read_committed_fee moved to dnac/transaction.h as static inline
 * so libnodus (nodus_witness_*.c) can use it without linking libdna. */
