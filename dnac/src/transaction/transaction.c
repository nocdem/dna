/**
 * @file transaction.c
 * @brief Transaction creation and management
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/tx_wire.h"   /* S1: shared legacy tx-hash (dnac_txw_legacy_tx_hash) */
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* libdna crypto utilities */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_log.h"
#include "dnac/safe_math.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "DNAC_TX"

/* DNAC_STAKE_PURPOSE_TAG lives in serialize.c (the wire layer that owns the
 * on-wire tag bytes) so serialize.c stays standalone-linkable without this
 * file's Dilithium/EVP dependencies — see the definition there. Both files
 * are compiled together at every real link site (libdna, nodus-cli). */

/* CHAIN_CONFIG TX purpose-tag constant (design §5.3, Hard-Fork v1).
 *
 * 16-byte literal "DNAC_CC_v1" NUL-padded. Bound into the proposal preimage
 * that committee members sign (see §5.4). Domain-separates chain_config
 * votes from other Dilithium5 signatures in the system. */
const uint8_t DNAC_CHAIN_CONFIG_PURPOSE_TAG[DNAC_CHAIN_CONFIG_PURPOSE_TAG_LEN] = {
    'D','N','A','C','_','C','C','_','v','1',0,0,0,0,0,0
};

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

int dnac_tx_compute_hash(const dnac_transaction_t *tx, uint8_t *hash_out) {
    if (!tx || !hash_out) return DNAC_ERROR_INVALID_PARAM;

    /* S1 (Ledger V2): the struct-walk preimage builder that lived here was
     * RETIRED — the client now serializes the TX and calls the single
     * shared canonical implementation (shared/dnac/tx_wire.c,
     * dnac_txw_legacy_tx_hash), the same code the witness recompute runs.
     * One preimage implementation, two callers. Byte identity with the
     * pre-S1 struct walk is pinned by test_tx_hash_kat (fixed literals
     * captured from the pre-S1 algorithm before this rewire).
     *
     * Sound because the preimage never includes the wire's embedded
     * tx_hash field — serializing with a stale/zero tx->tx_hash cannot
     * perturb the digest. Signer PUBKEYS are passed from the struct
     * exactly as the old walk hashed them (signatures never enter the
     * preimage).
     *
     * Documented non-canonical-input edge (S1): a CHAIN_CONFIG struct
     * with committee_sig_count above the 7-slot wire cap serializes
     * CLAMPED, so its hash now reflects the clamped wire form; the old
     * struct walk hashed the raw count byte plus 7 votes. Every decode
     * and rule path rejects such counts (chain_config_wire.c decode cap,
     * [5,7] committee range), so no admissible TX's hash changes. */
    size_t need = 0;
    uint8_t probe;
    (void)dnac_tx_serialize(tx, &probe, 0, &need);   /* size query */
    if (need == 0) return DNAC_ERROR_INVALID_PARAM;
    uint8_t *wire = malloc(need);
    if (!wire) return DNAC_ERROR_OUT_OF_MEMORY;
    size_t written = 0;
    if (dnac_tx_serialize(tx, wire, need, &written) != DNAC_SUCCESS) {
        free(wire);
        return DNAC_ERROR_INVALID_PARAM;
    }

    uint8_t signer_pubkeys[DNAC_TX_MAX_SIGNERS * DNAC_PUBKEY_SIZE];
    uint8_t signer_count = tx->signer_count;
    if (signer_count > DNAC_TX_MAX_SIGNERS) {
        free(wire);
        return DNAC_ERROR_INVALID_PARAM;
    }
    for (uint8_t i = 0; i < signer_count; i++)
        memcpy(signer_pubkeys + (size_t)i * DNAC_PUBKEY_SIZE,
               tx->signers[i].pubkey, DNAC_PUBKEY_SIZE);

    int rc = dnac_txw_legacy_tx_hash(tx->chain_id, wire, written,
                                     signer_count ? signer_pubkeys : NULL,
                                     signer_count, hash_out);
    memset(wire, 0, written);
    free(wire);
    return rc == 0 ? DNAC_SUCCESS : DNAC_ERROR_CRYPTO;
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
