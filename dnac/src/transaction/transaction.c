/**
 * @file transaction.c
 * @brief Transaction creation and management
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OpenSSL for SHA3-512 */
#include <openssl/evp.h>

/* libdna crypto utilities */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_log.h"
#include "dnac/safe_math.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "DNAC_TX"

/* STAKE TX purpose-tag constant (design §2.3, F-CRYPTO-05).
 *
 * 17-byte literal. The design spec text says "purpose_tag[16]" but the
 * literal value "DNAC_VALIDATOR_v1" is 17 ASCII characters and cannot
 * fit in a 16-byte field. We preserve the literal identifier verbatim
 * at its natural length (17 bytes, no NUL terminator, no padding) —
 * the cryptographic purpose of the tag is the unique byte sequence,
 * not the array size. Flagged as a design-doc inconsistency. */
const uint8_t DNAC_STAKE_PURPOSE_TAG[DNAC_STAKE_PURPOSE_TAG_LEN] = {
    'D','N','A','C','_','V','A','L','I','D','A','T','O','R','_','v','1'
};

/* Forward declarations for verification functions (verify.c) */
extern int verify_witnesses(const dnac_transaction_t *tx);
extern int verify_signers(const dnac_transaction_t *tx);
extern int dnac_tx_verify_stake_rules_internal(const dnac_transaction_t *tx);
extern int dnac_tx_verify_delegate_rules_internal(const dnac_transaction_t *tx);
extern int dnac_tx_verify_unstake_rules_internal(const dnac_transaction_t *tx);
extern int dnac_tx_verify_undelegate_rules_internal(const dnac_transaction_t *tx);
extern int dnac_tx_verify_claim_reward_rules_internal(const dnac_transaction_t *tx);
extern int dnac_tx_verify_validator_update_rules_internal(const dnac_transaction_t *tx);

dnac_transaction_t* dnac_tx_create(dnac_tx_type_t type) {
    dnac_transaction_t *tx = calloc(1, sizeof(dnac_transaction_t));
    if (!tx) return NULL;

    tx->version = DNAC_PROTOCOL_VERSION;
    tx->type = type;
    tx->timestamp = (uint64_t)time(NULL);
    tx->input_count = 0;
    tx->output_count = 0;
    tx->witness_count = 0;

    return tx;
}

int dnac_tx_add_input(dnac_transaction_t *tx, const dnac_utxo_t *utxo) {
    if (!tx || !utxo) return DNAC_ERROR_INVALID_PARAM;
    if (tx->input_count >= DNAC_TX_MAX_INPUTS) return DNAC_ERROR_INVALID_PARAM;

    dnac_tx_input_t *input = &tx->inputs[tx->input_count];
    memcpy(input->nullifier, utxo->nullifier, DNAC_NULLIFIER_SIZE);
    input->amount = utxo->amount;  /* v1: store amount for verification */
    memcpy(input->token_id, utxo->token_id, DNAC_TOKEN_ID_SIZE);

    tx->input_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_add_output(dnac_transaction_t *tx,
                       const char *recipient_fingerprint,
                       uint64_t amount,
                       uint8_t *nullifier_seed_out) {
    return dnac_tx_add_output_with_memo(tx, recipient_fingerprint, amount,
                                         nullifier_seed_out, NULL, 0);
}

int dnac_tx_add_output_with_memo(dnac_transaction_t *tx,
                                  const char *recipient_fingerprint,
                                  uint64_t amount,
                                  uint8_t *nullifier_seed_out,
                                  const char *memo,
                                  uint8_t memo_len) {
    if (!tx || !recipient_fingerprint || amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (tx->output_count >= DNAC_TX_MAX_OUTPUTS) return DNAC_ERROR_INVALID_PARAM;
    /* memo_len is uint8_t (max 255), buffer is DNAC_MEMO_MAX_SIZE (256) — always fits */

    dnac_tx_output_internal_t *output = &tx->outputs[tx->output_count];
    output->version = tx->version;
    strncpy(output->owner_fingerprint, recipient_fingerprint, DNAC_FINGERPRINT_SIZE - 1);
    output->owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    output->amount = amount;

    /* Generate random nullifier seed for recipient */
    if (nullifier_seed_out) {
        if (qgp_randombytes(nullifier_seed_out, 32) != 0) {
            return DNAC_ERROR_RANDOM_FAILED;
        }
        memcpy(output->nullifier_seed, nullifier_seed_out, 32);
    }

    /* Gap 25: v0.6.0 - Set memo if provided */
    output->memo_len = 0;
    memset(output->memo, 0, DNAC_MEMO_MAX_SIZE);
    if (memo && memo_len > 0) {
        memcpy(output->memo, memo, memo_len);
        output->memo_len = memo_len;
    }

    tx->output_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_finalize(dnac_transaction_t *tx,
                     const uint8_t *sender_privkey,
                     const uint8_t *sender_pubkey) {
    if (!tx || !sender_privkey || !sender_pubkey) return DNAC_ERROR_INVALID_PARAM;

    /* v0.8.0: sum(inputs) >= sum(outputs), difference is burned fee */
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);

    if (total_in < total_out) {
        return DNAC_ERROR_INVALID_PROOF;  /* Outputs exceed inputs */
    }

    /* Store sender's public key BEFORE hash (signers[0].pubkey is part of tx_hash) */
    memcpy(tx->signers[0].pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);
    tx->signer_count = 1;

    /* Compute transaction hash (includes signer pubkeys) */
    int result = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (result != DNAC_SUCCESS) {
        return result;
    }

    /* Sign transaction hash with Dilithium5 */
    size_t sig_len = 0;
    int sign_result = qgp_dsa87_sign(tx->signers[0].signature, &sig_len,
                                     tx->tx_hash, DNAC_TX_HASH_SIZE,
                                     sender_privkey);
    if (sign_result != 0) {
        return DNAC_ERROR_SIGN_FAILED;
    }

    return DNAC_SUCCESS;
}

int dnac_tx_add_witness(dnac_transaction_t *tx, const dnac_witness_sig_t *witness) {
    if (!tx || !witness) return DNAC_ERROR_INVALID_PARAM;
    if (tx->witness_count >= DNAC_TX_MAX_WITNESSES) return DNAC_ERROR_INVALID_PARAM;

    memcpy(&tx->witnesses[tx->witness_count], witness, sizeof(dnac_witness_sig_t));
    tx->witness_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_add_signer(dnac_transaction_t *tx,
                       const uint8_t *pubkey,
                       const uint8_t *signature) {
    if (!tx || !pubkey || !signature) return DNAC_ERROR_INVALID_PARAM;
    if (tx->signer_count >= DNAC_TX_MAX_SIGNERS) return DNAC_ERROR_INVALID_PARAM;

    memcpy(tx->signers[tx->signer_count].pubkey, pubkey, DNAC_PUBKEY_SIZE);
    memcpy(tx->signers[tx->signer_count].signature, signature, DNAC_SIGNATURE_SIZE);
    tx->signer_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_verify(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* STAKE-type rules (design §2.4, Phase 6 Task 22) — runs before the
     * generic balance/witness/signer checks so rule violations surface with
     * specific error codes (e.g. commission > 10000) rather than being
     * masked by the weaker "inputs >= outputs" check. */
    if (tx->type == DNAC_TX_STAKE) {
        int rc = dnac_tx_verify_stake_rules_internal(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* DELEGATE-type rules (design §2.4, Phase 6 Task 23). */
    if (tx->type == DNAC_TX_DELEGATE) {
        int rc = dnac_tx_verify_delegate_rules_internal(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* UNSTAKE-type rules (design §2.4, Phase 6 Task 24). */
    if (tx->type == DNAC_TX_UNSTAKE) {
        int rc = dnac_tx_verify_unstake_rules_internal(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* UNDELEGATE-type rules (design §2.4, Phase 6 Task 25). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        int rc = dnac_tx_verify_undelegate_rules_internal(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* CLAIM_REWARD-type rules (design §2.4, Phase 6 Task 26). */
    if (tx->type == DNAC_TX_CLAIM_REWARD) {
        int rc = dnac_tx_verify_claim_reward_rules_internal(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* VALIDATOR_UPDATE-type rules (design §2.4, Phase 6 Task 27). */
    if (tx->type == DNAC_TX_VALIDATOR_UPDATE) {
        int rc = dnac_tx_verify_validator_update_rules_internal(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* Genesis: 0 inputs, outputs create coins (witness-authorized) */
    if (tx->type == DNAC_TX_GENESIS) {
        if (tx->input_count != 0) {
            QGP_LOG_ERROR(LOG_TAG, "verify failed: genesis must have 0 inputs");
            return DNAC_ERROR_INVALID_PROOF;
        }
    } else {
        /* v0.8.0: sum(inputs) >= sum(outputs), difference is burned fee */
        uint64_t total_in = dnac_tx_total_input(tx);
        uint64_t total_out = dnac_tx_total_output(tx);

        QGP_LOG_DEBUG(LOG_TAG, "verify: total_in=%llu, total_out=%llu",
                      (unsigned long long)total_in, (unsigned long long)total_out);

        if (total_in < total_out) {
            QGP_LOG_ERROR(LOG_TAG, "verify failed: outputs exceed inputs");
            return DNAC_ERROR_INVALID_PROOF;
        }
    }

    /* Verify we have enough witnesses
     * BFT mode: 1 attestation proves consensus (quorum agreement happened internally) */
    QGP_LOG_DEBUG(LOG_TAG, "verify: witness_count=%d (BFT: 1 sufficient)", tx->witness_count);
    if (tx->witness_count < 1) {
        QGP_LOG_ERROR(LOG_TAG, "verify failed: no witnesses");
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /* Verify witness signatures */
    int rc = verify_witnesses(tx);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "verify failed: witness sig verify rc=%d", rc);
        return rc;
    }

    /* Sender signature (skip for genesis - witnesses authorize) */
    if (tx->type != DNAC_TX_GENESIS) {
        rc = verify_signers(tx);
        if (rc != DNAC_SUCCESS) {
            QGP_LOG_ERROR(LOG_TAG, "verify failed: signer sig verify rc=%d", rc);
            return rc;
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "verify OK");
    return DNAC_SUCCESS;
}

/* Big-endian serialization helpers for the canonical TX hash preimage.
 * Design §2.3 (F-CRYPTO-10) requires multi-byte integers in the preimage
 * to be big-endian so signatures are platform-independent. */
static void tx_be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

int dnac_tx_compute_hash(const dnac_transaction_t *tx, uint8_t *hash_out) {
    if (!tx || !hash_out) return DNAC_ERROR_INVALID_PARAM;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return DNAC_ERROR_CRYPTO;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return DNAC_ERROR_CRYPTO;
    }

    /* ──────────────────────────────────────────────────────────────────
     * Canonical TX hash preimage (design §2.3, F-CRYPTO-10):
     *
     *   version (u8) || type (u8) || timestamp (u64 BE) || chain_id[32] ||
     *   inputs[0..input_count]      each: nullifier(64) || amount(u64 BE) || token_id(32) ||
     *   outputs[0..output_count]    each: version(u8) || fp(129) || amount(u64 BE) ||
     *                                     token_id(32) || seed(32) || memo_len(u8) || memo(memo_len) ||
     *   signer_count (u8) || signers[0..signer_count].pubkey ||
     *   type_specific_appended_fields
     *
     * All multi-byte integers are BIG-ENDIAN so the hash is identical
     * across platforms. Byte-arrays (nullifier, token_id, pubkey, fp,
     * seed, memo) are hashed verbatim (no endianness).
     * ────────────────────────────────────────────────────────────────── */

    /* Header: version, type, timestamp (BE), chain_id */
    uint8_t type_byte = (uint8_t)tx->type;
    uint8_t ts_be[8];
    tx_be64_into(tx->timestamp, ts_be);
    EVP_DigestUpdate(ctx, &tx->version, sizeof(tx->version));
    EVP_DigestUpdate(ctx, &type_byte, sizeof(type_byte));
    EVP_DigestUpdate(ctx, ts_be, sizeof(ts_be));
    EVP_DigestUpdate(ctx, tx->chain_id, sizeof(tx->chain_id));

    /* Inputs: nullifier || amount (BE) || token_id */
    for (int i = 0; i < tx->input_count; i++) {
        uint8_t amt_be[8];
        tx_be64_into(tx->inputs[i].amount, amt_be);
        EVP_DigestUpdate(ctx, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        EVP_DigestUpdate(ctx, amt_be, sizeof(amt_be));
        EVP_DigestUpdate(ctx, tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* Outputs: version || fp || amount (BE) || token_id || seed || memo_len || memo */
    for (int i = 0; i < tx->output_count; i++) {
        uint8_t amt_be[8];
        tx_be64_into(tx->outputs[i].amount, amt_be);
        EVP_DigestUpdate(ctx, &tx->outputs[i].version, sizeof(uint8_t));
        EVP_DigestUpdate(ctx, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        EVP_DigestUpdate(ctx, amt_be, sizeof(amt_be));
        EVP_DigestUpdate(ctx, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
        EVP_DigestUpdate(ctx, tx->outputs[i].nullifier_seed, 32);
        EVP_DigestUpdate(ctx, &tx->outputs[i].memo_len, sizeof(uint8_t));
        if (tx->outputs[i].memo_len > 0) {
            EVP_DigestUpdate(ctx, tx->outputs[i].memo, tx->outputs[i].memo_len);
        }
    }

    /* Signers: count || pubkeys (truncated at signer_count — fixed-array
     * tail bytes are NOT hashed, so mutating signers[signer_count..] does
     * not change the preimage). */
    EVP_DigestUpdate(ctx, &tx->signer_count, sizeof(uint8_t));
    for (int i = 0; i < tx->signer_count; i++) {
        EVP_DigestUpdate(ctx, tx->signers[i].pubkey, DNAC_PUBKEY_SIZE);
    }

    /* Type-specific appended fields (STAKE, DELEGATE, etc.) land here in
     * Phase 5 Tasks 16-20 of the stake-delegation plan. For v1 TX types
     * (GENESIS/SPEND/BURN/TOKEN_CREATE) the appended section is empty. */
    if (tx->type == DNAC_TX_STAKE) {
        /* commission_bps: u16 big-endian */
        uint8_t commission_be[2];
        commission_be[0] = (uint8_t)((tx->stake_fields.commission_bps >> 8) & 0xff);
        commission_be[1] = (uint8_t)(tx->stake_fields.commission_bps & 0xff);
        EVP_DigestUpdate(ctx, commission_be, sizeof(commission_be));
        /* unstake_destination_fp: raw 64-byte fingerprint hash */
        EVP_DigestUpdate(ctx, tx->stake_fields.unstake_destination_fp,
                         DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);
        /* purpose_tag: 17-byte literal "DNAC_VALIDATOR_v1" (F-CRYPTO-05) */
        EVP_DigestUpdate(ctx, DNAC_STAKE_PURPOSE_TAG, DNAC_STAKE_PURPOSE_TAG_LEN);
    }
    /* Phase 5 Task 17. DELEGATE: validator_pubkey[2592]. */
    if (tx->type == DNAC_TX_DELEGATE) {
        EVP_DigestUpdate(ctx, tx->delegate_fields.validator_pubkey,
                         DNAC_PUBKEY_SIZE);
    }
    /* Phase 5 Task 18. UNDELEGATE: validator_pubkey[2592] || amount(u64 BE). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        EVP_DigestUpdate(ctx, tx->undelegate_fields.validator_pubkey,
                         DNAC_PUBKEY_SIZE);
        uint8_t amount_be[8];
        tx_be64_into(tx->undelegate_fields.amount, amount_be);
        EVP_DigestUpdate(ctx, amount_be, sizeof(amount_be));
    }
    /* Phase 5 Task 18. CLAIM_REWARD: target_validator[2592] ||
     *        max_pending_amount(u64 BE) || valid_before_block(u64 BE). */
    if (tx->type == DNAC_TX_CLAIM_REWARD) {
        EVP_DigestUpdate(ctx, tx->claim_reward_fields.target_validator,
                         DNAC_PUBKEY_SIZE);
        uint8_t be[8];
        tx_be64_into(tx->claim_reward_fields.max_pending_amount, be);
        EVP_DigestUpdate(ctx, be, sizeof(be));
        tx_be64_into(tx->claim_reward_fields.valid_before_block, be);
        EVP_DigestUpdate(ctx, be, sizeof(be));
    }
    /* Phase 5 Task 19. VALIDATOR_UPDATE: new_commission_bps(u16 BE) ||
     *        signed_at_block(u64 BE). */
    if (tx->type == DNAC_TX_VALIDATOR_UPDATE) {
        uint8_t commission_be[2];
        commission_be[0] = (uint8_t)((tx->validator_update_fields.new_commission_bps >> 8) & 0xff);
        commission_be[1] = (uint8_t)(tx->validator_update_fields.new_commission_bps & 0xff);
        EVP_DigestUpdate(ctx, commission_be, sizeof(commission_be));
        uint8_t block_be[8];
        tx_be64_into(tx->validator_update_fields.signed_at_block, block_be);
        EVP_DigestUpdate(ctx, block_be, sizeof(block_be));
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash_out, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return DNAC_ERROR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);
    return DNAC_SUCCESS;
}

uint64_t dnac_tx_total_input(const dnac_transaction_t *tx) {
    if (!tx) return 0;

    uint64_t total = 0;
    for (int i = 0; i < tx->input_count; i++) {
        if (safe_add_u64(total, tx->inputs[i].amount, &total) != 0) {
            return UINT64_MAX;  /* Overflow sentinel */
        }
    }
    return total;
}

uint64_t dnac_tx_total_output(const dnac_transaction_t *tx) {
    if (!tx) return 0;

    uint64_t total = 0;
    for (int i = 0; i < tx->output_count; i++) {
        if (safe_add_u64(total, tx->outputs[i].amount, &total) != 0) {
            return UINT64_MAX;  /* Overflow sentinel */
        }
    }
    return total;
}

void dnac_free_transaction(dnac_transaction_t *tx) {
    free(tx);
}
