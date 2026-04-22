/**
 * @file transaction.h
 * @brief DNAC Transaction types and functions
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_TRANSACTION_H
#define DNAC_TRANSACTION_H

#include "dnac.h"
#include "block.h"  /* for dnac_chain_definition_t (genesis-only field) */
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Transaction Wire Format Constants
 * ========================================================================== */

#define DNAC_TX_MAX_INPUTS          16
#define DNAC_TX_MAX_OUTPUTS         16
#define DNAC_TX_MAX_WITNESSES       3
#define DNAC_TX_MAX_SIGNERS         4

/* v0.17.1+ wire format (see dnac/docs/plans/2026-04-22-committed-fee-wire-field-design.md).
 *
 *   Header (DNAC_TX_HEADER_SIZE = 82 B):
 *     offset  0  version(1)        — must equal DNAC_PROTOCOL_VERSION (= DNAC_PROTOCOL_V2 = 2)
 *     offset  1  type(1)
 *     offset  2  timestamp(8, host-endian memcpy — legacy)
 *     offset 10  tx_hash(64)       — SHA3-512 of preimage (v2 domain separator + body)
 *     offset 74  committed_fee(8, BE)
 *     offset 82  — body starts here (input_count ...)
 *
 *   Version byte: use DNAC_PROTOCOL_VERSION (from dnac.h) — single source of truth. */
#define DNAC_TX_HEADER_SIZE         82   /* v1 was 74; bumped +8 for committed_fee */
#define DNAC_TX_COMMITTED_FEE_OFF   74   /* offset of committed_fee in header */
#define DNAC_TX_BODY_OFF            82   /* offset where input_count starts */
#define DNAC_TX_INPUT_RECORD_SIZE   136  /* nullifier(64) + amount(8) + token_id(64) */

/* Preimage domain separator (SEC-06): prepended to every v2 preimage before hashing.
 * Prevents cross-version preimage collisions if a future v3 format reorders fields. */
#define DNAC_TX_PREIMAGE_DOMAIN_V2   "DNAC_TX_V2\0"
#define DNAC_TX_PREIMAGE_DOMAIN_V2_LEN  11   /* sizeof("DNAC_TX_V2") + 1 NUL */

/* STAKE TX appended fields — wire & preimage constants
 * (design §2.3, Phase 5 Task 16).
 *
 * Wire field `unstake_destination_fp` is the **raw 64-byte binary
 * fingerprint hash** (SHA3-512 truncated or full digest per §2.3),
 * NOT the 129-byte hex string used for UTXO ownership elsewhere. */
#define DNAC_STAKE_UNSTAKE_DEST_FP_SIZE   64

/* Purpose tag bound into the STAKE TX preimage (F-CRYPTO-05 defense
 * against cross-protocol signature reuse). Design §2.3 specifies the
 * literal string "DNAC_VALIDATOR_v1" — 17 ASCII bytes with no NUL
 * terminator, padding, or truncation. The design text says
 * `purpose_tag[16]` but that is an internal inconsistency: the literal
 * string is 17 characters and cannot fit in 16 bytes. We implement the
 * literal string at its natural 17-byte length, preserving the spec's
 * intended identifier verbatim. */
#define DNAC_STAKE_PURPOSE_TAG_LEN        17
extern const uint8_t DNAC_STAKE_PURPOSE_TAG[DNAC_STAKE_PURPOSE_TAG_LEN];

/**
 * @brief STAKE TX appended fields (design §2.3)
 *
 * Populated only when `dnac_transaction_t.type == DNAC_TX_STAKE`.
 * Serialized on the wire and bound into the TX hash preimage along
 * with a fixed `DNAC_STAKE_PURPOSE_TAG` suffix.
 *
 * `unstake_destination_fp` is IMMUTABLE post-STAKE (Rule T) — no TX
 * type may update it; the raw fingerprint hash is signed into the
 * STAKE preimage and becomes a permanent validator property.
 */
typedef struct {
    uint16_t commission_bps;                                    /**< 0..10000 */
    uint8_t  unstake_destination_fp[DNAC_STAKE_UNSTAKE_DEST_FP_SIZE];
                                                                /**< raw 64B fingerprint hash */
} dnac_tx_stake_fields_t;

/**
 * @brief DELEGATE TX appended fields (design §2.3, Phase 5 Task 17)
 *
 * Populated only when `dnac_transaction_t.type == DNAC_TX_DELEGATE`.
 * Serialized on the wire and bound into the TX hash preimage.
 *
 * The validator_pubkey identifies which validator the delegator is
 * staking onto. Amount is carried by the TX inputs/outputs, not by
 * the appended fields.
 */
typedef struct {
    uint8_t validator_pubkey[DNAC_PUBKEY_SIZE];   /**< Dilithium5 pubkey (2592B) */
    uint64_t delegation_amount;                   /**< Explicit state amount (v0.17.1+, BE on wire).
                                                   *   verify_tx enforces:
                                                   *     delegation_amount >= 1
                                                   *     delegation_amount <= DNAC_DEFAULT_TOTAL_SUPPLY
                                                   *     Σ(native_in) == Σ(native_out) + committed_fee + delegation_amount */
} dnac_tx_delegate_fields_t;

/**
 * @brief UNDELEGATE TX appended fields (design §2.3, Phase 5 Task 18)
 *
 * Populated only when `dnac_transaction_t.type == DNAC_TX_UNDELEGATE`.
 * The validator_pubkey identifies the validator the delegator is
 * unbonding from; amount is the base-units delegation quantity to
 * withdraw. Both bound into the TX hash preimage.
 */
typedef struct {
    uint8_t  validator_pubkey[DNAC_PUBKEY_SIZE];  /**< Dilithium5 pubkey */
    uint64_t amount;                              /**< Undelegate amount (base units) */
} dnac_tx_undelegate_fields_t;

/**
 * @brief VALIDATOR_UPDATE TX appended fields (design §2.3, Phase 5 Task 19)
 *
 * Populated only when `dnac_transaction_t.type == DNAC_TX_VALIDATOR_UPDATE`.
 *
 * `new_commission_bps` is the validator's updated commission (0..10000 =
 * 0..100%). `signed_at_block` anchors the update to a specific block
 * height so replay of an old update-TX is detectable by witnesses
 * (they reject if signed_at_block < current validator.last_update_block).
 */
typedef struct {
    uint16_t new_commission_bps;   /**< 0..10000 */
    uint64_t signed_at_block;      /**< Block height at signing */
} dnac_tx_validator_update_fields_t;

/* ============================================================================
 * Chain-Config TX fields (hard-fork mechanism v1, design §5.3)
 * ========================================================================== */

/** Chain-Config purpose-tag bytes, bound into the proposal preimage.
 *  Literal ASCII "DNAC_CC_v1" NUL-padded to 16 bytes (design §5.3). */
#define DNAC_CHAIN_CONFIG_PURPOSE_TAG_LEN   16
extern const uint8_t DNAC_CHAIN_CONFIG_PURPOSE_TAG[DNAC_CHAIN_CONFIG_PURPOSE_TAG_LEN];

/** One committee member's vote on a chain-config proposal (design §5.3). */
typedef struct {
    uint8_t witness_id[32];                  /**< first 32B of SHA3-512(pubkey) */
    uint8_t signature[DNAC_SIGNATURE_SIZE];  /**< Dilithium5 over proposal preimage */
} dnac_chain_config_vote_t;

/**
 * @brief CHAIN_CONFIG TX appended fields (design §5.3, §5.4, §5.5).
 *
 * Populated only when `dnac_transaction_t.type == DNAC_TX_CHAIN_CONFIG`.
 * Committee members independently sign the proposal preimage
 *   (DNAC_CHAIN_CONFIG_PURPOSE_TAG || chain_id || param_id || new_value_BE ||
 *    effective_block_BE || proposal_nonce_BE || signed_at_block_BE ||
 *    valid_before_block_BE)
 * and the proposer aggregates >=5 votes before submitting.
 *
 * `committee_sig_count` is the number of occupied slots in
 * `committee_votes[]`. Must land in [DNAC_CHAIN_CONFIG_MIN_SIGS,
 * DNAC_CHAIN_CONFIG_MAX_SIGS] = [5, 7]. Unused trailing slots are zero.
 *
 * `signed_at_block` is bound into the proposal preimage (CC-AUDIT-004 / Q2)
 * so a vote cannot be replayed onto a different commit window than signers
 * intended.
 */
typedef struct {
    uint8_t                  param_id;                              /**< dnac_chain_config_param_id_t */
    uint64_t                 new_value;                             /**< BE-encoded in preimages */
    uint64_t                 effective_block_height;                /**< BE-encoded in preimages */
    uint64_t                 proposal_nonce;                        /**< BE-encoded; preimage entropy */
    uint64_t                 signed_at_block;                       /**< BE-encoded; sign-time anchor */
    uint64_t                 valid_before_block;                    /**< BE-encoded; freshness window */
    uint8_t                  committee_sig_count;                   /**< 5..7 */
    dnac_chain_config_vote_t committee_votes[DNAC_COMMITTEE_SIZE];  /**< canonical subset (Q13) */
} dnac_tx_chain_config_fields_t;

/**
 * @brief Transaction signer (authorization)
 *
 * Each signer provides a Dilithium5 pubkey and signature over tx_hash.
 * Single-party transactions use signers[0]. Multi-party (atomic swap)
 * uses 2+ signers. Each input's owner must match some signer's pubkey.
 */
typedef struct {
    uint8_t pubkey[DNAC_PUBKEY_SIZE];       /**< Dilithium5 public key (2592B) */
    uint8_t signature[DNAC_SIGNATURE_SIZE]; /**< Dilithium5 signature (4627B) */
} dnac_tx_signer_t;

/* ============================================================================
 * Transaction Structures
 * ========================================================================== */

/**
 * @brief Transaction input
 *
 * Inputs reference UTXOs by nullifier (hides which UTXO is spent).
 */
typedef struct {
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];     /**< Nullifier (SHA3-512 hash) */
    uint64_t amount;                             /**< Amount (v1 only, for verification) */
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];       /**< Token ID (zeros = native DNAC) */
} dnac_tx_input_t;

/**
 * @brief Transaction output (v1 transparent)
 *
 * Protocol v1: Amount is plaintext.
 * v2 will add PQ ZK fields when STARKs are integrated.
 */
typedef struct {
    uint8_t version;                             /**< Output version */
    char owner_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Recipient's fingerprint */
    uint64_t amount;                             /**< Amount in smallest units */
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];        /**< Token ID (zeros = native DNAC) */
    uint8_t nullifier_seed[32];                  /**< Seed for recipient to derive nullifier */
    char memo[DNAC_MEMO_MAX_SIZE];               /**< Optional memo (Gap 25: v0.6.0) */
    uint8_t memo_len;                            /**< Memo length */
} dnac_tx_output_internal_t;

/**
 * @brief Witness signature (attestation)
 *
 * Signatures from 2+ witness servers prevent double-spending.
 *
 * Phase 12 / Task 13.1 — the receipt now binds the block_height,
 * tx_index, and chain_id the witness committed against. These fields
 * are required for client-side preimage reconstruction (the witness
 * Dilithium5-signs the 221-byte spndrslt preimage that includes them).
 * They are NOT serialized into the on-chain TX; serialize.c only
 * persists witness_id/signature/timestamp/server_pubkey.
 */
typedef struct {
    uint8_t witness_id[32];                      /**< Witness server ID */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Dilithium5 signature */
    uint8_t server_pubkey[DNAC_PUBKEY_SIZE];     /**< Server's Dilithium5 public key */
    uint64_t timestamp;                          /**< Witness timestamp */
    /* Receipt-only fields (not in TX serialization) */
    uint64_t block_height;                       /**< Block the TX committed in */
    uint32_t tx_index;                           /**< Per-block tx_index */
    uint8_t  chain_id[32];                       /**< Chain identifier */
} dnac_witness_sig_t;

/**
 * @brief Full transaction structure
 *
 * Protocol v1: Transparent amounts.
 * v2 will add PQ ZK fields when STARKs are integrated.
 */
struct dnac_transaction {
    /* Header */
    uint8_t version;                             /**< Protocol version (DNAC_TX_VERSION = 2 in v0.17.1+) */
    dnac_tx_type_t type;                         /**< MINT, SPEND, or BURN */
    uint64_t timestamp;                          /**< Unix timestamp */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< SHA3-512 of preimage */
    uint64_t committed_fee;                      /**< Explicit native-DNAC fee (v0.17.1+, BE on wire).
                                                  *   MUST be 0 for GENESIS, >= DNAC_MIN_FEE_RAW otherwise.
                                                  *   verify_tx enforces:
                                                  *     Σ(native_in) == Σ(native_out) + committed_fee + state_amount(tx_type) */

    /* Inputs */
    dnac_tx_input_t inputs[DNAC_TX_MAX_INPUTS];
    int input_count;

    /* Outputs */
    dnac_tx_output_internal_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;

    /* Witness signatures (1 required, BFT mode) */
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count;

    /* Signer authorization (Dilithium5 signatures) */
    dnac_tx_signer_t signers[DNAC_TX_MAX_SIGNERS];
    uint8_t signer_count;

    /* Anchored genesis chain definition (genesis TX only, optional).
     * When has_chain_def is true AND type == DNAC_TX_GENESIS, the TX
     * serialization appends the encoded chain_def bytes after the
     * sender signature. Witnesses read these bytes and include them
     * verbatim in the genesis block hash preimage — this is how the
     * single hardcoded chain_id in the client maps to a specific
     * witness roster + consensus parameters.
     *
     * For non-genesis TXs or legacy non-anchored genesis, has_chain_def
     * remains false and the serialization is byte-identical to v0. */
    bool                    has_chain_def;
    dnac_chain_definition_t chain_def;

    /* Chain_id bound into the TX hash preimage (design §2.3, F-CRYPTO-10).
     * Set by builder from dnac_get_chain_id(ctx); zero on freshly created TX
     * until populated. Not serialized on the wire — witnesses already know
     * their chain_id from the chain context. */
    uint8_t chain_id[32];

    /* Per-type appended fields (design §2.3, Phase 5 Tasks 16-20).
     * Only the arm matching `type` is populated; others are zero. A union
     * can replace this struct layout later when more TX types ship. */
    dnac_tx_stake_fields_t            stake_fields;            /**< valid when type == DNAC_TX_STAKE */
    dnac_tx_delegate_fields_t         delegate_fields;         /**< valid when type == DNAC_TX_DELEGATE */
    dnac_tx_undelegate_fields_t       undelegate_fields;       /**< valid when type == DNAC_TX_UNDELEGATE */
    dnac_tx_validator_update_fields_t validator_update_fields; /**< valid when type == DNAC_TX_VALIDATOR_UPDATE */
    dnac_tx_chain_config_fields_t     chain_config_fields;     /**< valid when type == DNAC_TX_CHAIN_CONFIG */
};

/* ============================================================================
 * Transaction Functions
 * ========================================================================== */

/**
 * @brief Create new transaction
 *
 * @param type Transaction type
 * @return New transaction or NULL on failure
 */
dnac_transaction_t* dnac_tx_create(dnac_tx_type_t type);

/**
 * @brief Add input to transaction
 *
 * @param tx Transaction
 * @param utxo UTXO being spent
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_input(dnac_transaction_t *tx, const dnac_utxo_t *utxo);

/**
 * @brief Add output to transaction (v1 transparent)
 *
 * @param tx Transaction
 * @param recipient_fingerprint Recipient's fingerprint
 * @param amount Amount to send
 * @param nullifier_seed_out Output nullifier seed for recipient (32 bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_output(dnac_transaction_t *tx,
                       const char *recipient_fingerprint,
                       uint64_t amount,
                       uint8_t *nullifier_seed_out);

/**
 * @brief Add output to transaction with memo (Gap 25: v0.6.0)
 *
 * @param tx Transaction
 * @param recipient_fingerprint Recipient's fingerprint
 * @param amount Amount to send
 * @param nullifier_seed_out Output nullifier seed for recipient (32 bytes)
 * @param memo Optional memo (can be NULL)
 * @param memo_len Memo length (0 if no memo)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_output_with_memo(dnac_transaction_t *tx,
                                  const char *recipient_fingerprint,
                                  uint64_t amount,
                                  uint8_t *nullifier_seed_out,
                                  const char *memo,
                                  uint8_t memo_len);

/**
 * @brief Finalize transaction
 *
 * Computes hash and signs with sender's Dilithium5 key.
 * Verifies sum(inputs) == sum(outputs).
 *
 * @param tx Transaction
 * @param sender_privkey Sender's Dilithium5 private key
 * @param sender_pubkey Sender's Dilithium5 public key
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_finalize(dnac_transaction_t *tx,
                     const uint8_t *sender_privkey,
                     const uint8_t *sender_pubkey);

/**
 * @brief Add witness signature to transaction
 *
 * @param tx Transaction
 * @param witness Witness signature from witness server
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_witness(dnac_transaction_t *tx, const dnac_witness_sig_t *witness);

/**
 * @brief Add signer to transaction
 *
 * @param tx Transaction
 * @param pubkey Signer's Dilithium5 public key (DNAC_PUBKEY_SIZE bytes)
 * @param signature Signer's signature over tx_hash (DNAC_SIGNATURE_SIZE bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_signer(dnac_transaction_t *tx,
                       const uint8_t *pubkey,
                       const uint8_t *signature);

/**
 * @brief Verify STAKE-type rules only (design §2.4, Phase 6 Task 22)
 *
 * Runs the locally-verifiable STAKE rule subset without exercising the
 * witness-signature or signer-signature paths. Intended primarily for
 * unit tests and pre-flight client checks.
 *
 * Rules enforced:
 *   - tx->type == DNAC_TX_STAKE
 *   - signer_count == 1
 *   - stake_fields.commission_bps <= DNAC_COMMISSION_BPS_MAX (10000)
 *   - Σ DNAC inputs >= DNAC_SELF_STAKE_AMOUNT + Σ DNAC outputs
 *
 * Rules requiring witness-side DB access (Rule I / Rule M / exact fee)
 * are NOT checked here — they run at state-apply time in the witness.
 *
 * @param tx Transaction (must be STAKE type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_stake_rules(const dnac_transaction_t *tx);

/**
 * @brief Verify DELEGATE-type rules only (design §2.4, Phase 6 Task 23)
 *
 * Runs the locally-verifiable DELEGATE rule subset without exercising the
 * witness-signature or signer-signature paths. Intended primarily for
 * unit tests and pre-flight client checks.
 *
 * Rules enforced:
 *   - tx->type == DNAC_TX_DELEGATE
 *   - signer_count == 1
 *   - signer[0].pubkey != delegate_fields.validator_pubkey (Rule S)
 *   - Σ DNAC inputs − Σ DNAC outputs >= DNAC_MIN_DELEGATION (Rule J)
 *
 * Rules requiring witness-side DB access (Rule B validator status,
 * Rule G 64-cap per delegator, exact fee) are NOT checked here — they
 * run at state-apply time in the witness.
 *
 * @param tx Transaction (must be DELEGATE type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_delegate_rules(const dnac_transaction_t *tx);

/**
 * @brief Verify UNSTAKE-type rules only (design §2.4, Phase 6 Task 24)
 *
 * Runs the locally-verifiable UNSTAKE rule subset. UNSTAKE has no
 * appended fields, so the local check is minimal:
 *
 *   - tx->type == DNAC_TX_UNSTAKE
 *   - signer_count == 1
 *
 * Rule A (NO delegation records with validator == signer[0]; literal
 * drain-before-exit), validator status gate, and fee checks require
 * witness-side DB access and run at state-apply time (Phase 8 Task 42).
 *
 * @param tx Transaction (must be UNSTAKE type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_unstake_rules(const dnac_transaction_t *tx);

/**
 * @brief Verify UNDELEGATE-type rules only (design §2.4, Phase 6 Task 25)
 *
 * Runs the locally-verifiable UNDELEGATE rule subset:
 *
 *   - tx->type == DNAC_TX_UNDELEGATE
 *   - signer_count == 1
 *   - undelegate_fields.amount > 0
 *
 * Rules requiring delegation_record state (delegation existence,
 * amount <= delegation.amount, Rule O hold duration current_block −
 * delegated_at_block >= EPOCH_LENGTH) are NOT checked here — they run
 * at state-apply time in the witness (Phase 8 Task 43).
 *
 * @param tx Transaction (must be UNDELEGATE type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_undelegate_rules(const dnac_transaction_t *tx);

/**
 * @brief Verify VALIDATOR_UPDATE-type rules only (design §2.4, Phase 6 Task 27)
 *
 * Runs the locally-verifiable VALIDATOR_UPDATE rule subset:
 *
 *   - tx->type == DNAC_TX_VALIDATOR_UPDATE
 *   - signer_count == 1
 *   - validator_update_fields.new_commission_bps <= DNAC_COMMISSION_BPS_MAX
 *   - validator_update_fields.signed_at_block > 0
 *
 * Rules requiring chain state (validator status ∈ {ACTIVE, RETIRING},
 * Rule K freshness current_block − signed_at_block < 32, EPOCH_LENGTH
 * cooldown, pending-commission increase/decrease logic) are NOT checked
 * here — they run at state-apply time in the witness (Phase 8 Task 45).
 *
 * @param tx Transaction (must be VALIDATOR_UPDATE type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_validator_update_rules(const dnac_transaction_t *tx);

/**
 * @brief Verify CHAIN_CONFIG-type local rules (design §6.3, Hard-Fork v1).
 *
 * Runs the locally-verifiable CHAIN_CONFIG rule subset — rules that don't
 * require witness chain state. Enforced:
 *
 *   - tx->type == DNAC_TX_CHAIN_CONFIG
 *   - signer_count == 1
 *   - chain_config_fields.param_id ∈ {1..DNAC_CFG_PARAM_MAX_ID}
 *   - chain_config_fields.new_value in per-param range (design §5.2)
 *   - chain_config_fields.signed_at_block > 0
 *   - chain_config_fields.valid_before_block > chain_config_fields.effective_block_height
 *   - chain_config_fields.valid_before_block > chain_config_fields.signed_at_block
 *   - chain_config_fields.committee_sig_count ∈ [5, 7]
 *   - committee_votes[0..sig_count-1].witness_id pairwise distinct
 *
 * Rules requiring chain state (current committee membership, signature
 * verification against committee pubkeys, current_block freshness, epoch
 * grace period) run witness-side only (design §6.4, Stage B).
 *
 * @param tx Transaction (must be CHAIN_CONFIG type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_chain_config_rules(const dnac_transaction_t *tx);

/**
 * @brief Verify GENESIS-type rules only (design §2.4 / §5.2 Rule P, full
 *        spec enforced as of Phase 12 Task 56).
 *
 * Runs the locally-verifiable GENESIS rule subset — the supply invariance,
 * initial-validator-count, and distinctness checks that a fresh client can
 * perform without touching chain state.
 *
 * Rules enforced:
 *   - tx->type == DNAC_TX_GENESIS
 *   - tx->input_count == 0 (no spends; genesis creates coins)
 *   - If tx->has_chain_def (new TXs, required for Task 56+):
 *     - chain_def.initial_validator_count == DNAC_COMMITTEE_SIZE (7)
 *     - Σ outputs (native DNAC) + 7 × DNAC_SELF_STAKE_AMOUNT ==
 *       DNAC_DEFAULT_TOTAL_SUPPLY
 *     - initial_validators[0..6].pubkey pairwise distinct
 *   - Else (legacy archive replay):
 *     - Σ outputs.amount (native DNAC) == DNAC_DEFAULT_TOTAL_SUPPLY
 *
 * @param tx Transaction (must be GENESIS type)
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify_genesis_rules(const dnac_transaction_t *tx);

/**
 * @brief Serialize transaction to bytes
 *
 * @param tx Transaction
 * @param buffer Output buffer
 * @param buffer_len Buffer length
 * @param written_out Bytes written
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_serialize(const dnac_transaction_t *tx,
                      uint8_t *buffer,
                      size_t buffer_len,
                      size_t *written_out);

/**
 * @brief Deserialize transaction from bytes
 *
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param tx_out Output transaction
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_deserialize(const uint8_t *buffer,
                        size_t buffer_len,
                        dnac_transaction_t **tx_out);

/**
 * @brief Compute transaction hash
 *
 * @param tx Transaction
 * @param hash_out Output hash (DNAC_TX_HASH_SIZE bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_compute_hash(const dnac_transaction_t *tx, uint8_t *hash_out);

/**
 * @brief Get total input amount (v1 only)
 *
 * @param tx Transaction
 * @return Total input amount
 */
uint64_t dnac_tx_total_input(const dnac_transaction_t *tx);

/**
 * @brief Get total output amount (v1 only)
 *
 * @param tx Transaction
 * @return Total output amount
 */
uint64_t dnac_tx_total_output(const dnac_transaction_t *tx);

/**
 * @brief Canonical reader for the committed_fee wire field (v0.17.1+).
 *
 * Single source of truth for parsing the committed_fee from a serialized
 * TX buffer. All consumers (client verify, witness verify, apply_*, fee
 * routing) MUST call this helper rather than reading offset 74 directly.
 * Centralises the length check + version gate so a malformed v1 buffer
 * cannot cause an out-of-bounds read (SEC-02).
 *
 * Defined `static inline` here so both libdna and libnodus compile their
 * own copy against the same header-owned constants — no cross-library
 * link dependency.
 *
 * @param tx_data    serialized TX bytes (wire format)
 * @param tx_len     length of tx_data in bytes
 * @param fee_out    [out] committed_fee in raw DNAC base units
 * @return 0 on success, -1 if:
 *           - tx_data is NULL, tx_len < DNAC_TX_HEADER_SIZE, OR
 *           - tx_data[0] != DNAC_PROTOCOL_VERSION (i.e. v1 or unknown version)
 *         On -1 the out value is left untouched.
 *
 * Big-endian decoding per §3 of the committed_fee design doc.
 */
static inline int dnac_tx_read_committed_fee(const uint8_t *tx_data,
                                              size_t tx_len,
                                              uint64_t *fee_out) {
    if (!tx_data || !fee_out) return -1;
    if (tx_len < DNAC_TX_HEADER_SIZE) return -1;
    if (tx_data[0] != DNAC_PROTOCOL_VERSION) return -1;
    uint64_t v = 0;
    const uint8_t *p = tx_data + DNAC_TX_COMMITTED_FEE_OFF;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    *fee_out = v;
    return 0;
}

/* ============================================================================
 * Genesis Transactions (v0.5.0)
 *
 * MINT transactions have been removed. All token creation happens via
 * a one-time GENESIS event. See include/dnac/genesis.h for the Genesis API.
 *
 * - dnac_tx_create_genesis()    - Create genesis with multiple recipients
 * - dnac_tx_authorize_genesis() - Get unanimous (N/N) BFT witness approval
 * - dnac_tx_broadcast_genesis() - Send genesis tokens via DHT
 * ========================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_TRANSACTION_H */
