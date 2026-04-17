/**
 * Nodus — Witness Transaction Verification
 *
 * Full transaction verification for BFT consensus PREVOTE.
 * Recomputes tx_hash, verifies sender signature, checks balance
 * against UTXO DB, validates fee, and checks double-spend.
 *
 * Wire format (from dnac/src/transaction/serialize.c):
 *   Header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74 bytes
 *   Inputs: count(1) + [nullifier(64) + amount(8) + token_id(64)]*N
 *   Outputs: count(1) + [version(1) + fingerprint(129) + amount(8) + token_id(64) + seed(32) + memo_len(1) + memo(n)]*M
 *   Witnesses: count(1) + [witness_id(32) + sig(4627) + timestamp(8) + pubkey(2592)]*W
 *   Signers: count(1) + [pubkey(2592) + sig(4627)]*S
 *
 * Hash covers: version + type + timestamp + signer_count + signer_pubkeys + inputs + outputs
 *              (no counts for inputs/outputs, no embedded hash, no signer signatures)
 *
 * @file nodus_witness_verify.c
 */

#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_db.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-VERIFY"

/* Wire format constants */
#define TX_HEADER_SIZE      74  /* version(1)+type(1)+timestamp(8)+tx_hash(64) */
#define TX_VERSION_OFF      0
#define TX_TYPE_OFF         1
#define TX_TIMESTAMP_OFF    2
#define TX_HASH_OFF         10  /* After version+type+timestamp */
#define TX_INPUTS_OFF       74  /* After header */

#define INPUT_NULLIFIER_LEN 64
#define INPUT_AMOUNT_LEN    8
#define INPUT_TOKEN_ID_LEN  64
#define INPUT_SIZE          (INPUT_NULLIFIER_LEN + INPUT_AMOUNT_LEN + INPUT_TOKEN_ID_LEN) /* 136 */

#define OUTPUT_VERSION_LEN  1
#define OUTPUT_FP_LEN       129
#define OUTPUT_AMOUNT_LEN   8
#define OUTPUT_TOKEN_ID_LEN 64
#define OUTPUT_SEED_LEN     32
#define OUTPUT_MEMO_LEN_LEN 1
#define OUTPUT_FIXED_SIZE   (OUTPUT_VERSION_LEN + OUTPUT_FP_LEN + OUTPUT_AMOUNT_LEN + \
                             OUTPUT_TOKEN_ID_LEN + OUTPUT_SEED_LEN + OUTPUT_MEMO_LEN_LEN) /* 235 */

/* Fee: 0.1% (10 basis points), minimum 1 unit */
#define FEE_RATE_BPS 10

/* Multi-signer constants */
#define NODUS_T3_MAX_TX_SIGNERS 4
#define SIGNER_SIZE (NODUS_PK_BYTES + NODUS_SIG_BYTES)

/* ════════════════════════════════════════════════════════════════════
 * Recompute TX hash from serialized data
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_recompute_tx_hash(const uint8_t *tx_data, uint32_t tx_len,
                                     const uint8_t *signer_pubkeys,
                                     uint8_t signer_count,
                                     uint8_t *hash_out) {
    if (!tx_data || !hash_out || tx_len < TX_HEADER_SIZE + 1)
        return -1;
    if (!signer_pubkeys && signer_count > 0)
        return -1;

    /* Allocate buffer to assemble hash input (tx_len + signer_count + all signer pubkeys) */
    uint8_t *buf = malloc(tx_len + 1 + NODUS_T3_MAX_TX_SIGNERS * NODUS_PK_BYTES);
    if (!buf) return -1;

    size_t buf_pos = 0;
    const uint8_t *p = tx_data;
    size_t remaining = tx_len;

    /* Copy version(1) + type(1) + timestamp(8) = 10 bytes */
    if (remaining < 10) { free(buf); return -1; }
    memcpy(buf + buf_pos, p, 10);
    buf_pos += 10;
    p += 10;
    remaining -= 10;

    /* Include signer_count + all signer pubkeys in hash */
    buf[buf_pos++] = signer_count;
    for (int i = 0; i < signer_count; i++) {
        memcpy(buf + buf_pos, signer_pubkeys + i * NODUS_PK_BYTES, NODUS_PK_BYTES);
        buf_pos += NODUS_PK_BYTES;
    }

    /* Skip embedded tx_hash (64 bytes) */
    if (remaining < 64) { free(buf); return -1; }
    p += 64;
    remaining -= 64;

    /* Parse input_count (NOT copied to hash buffer) */
    if (remaining < 1) { free(buf); return -1; }
    uint8_t input_count = *p;
    p++;
    remaining--;

    if (input_count > NODUS_T3_MAX_TX_INPUTS) { free(buf); return -1; }

    /* Copy each input's nullifier(64) + amount(8) + token_id(64) */
    for (int i = 0; i < input_count; i++) {
        if (remaining < INPUT_SIZE) { free(buf); return -1; }
        memcpy(buf + buf_pos, p, INPUT_SIZE);
        buf_pos += INPUT_SIZE;
        p += INPUT_SIZE;
        remaining -= INPUT_SIZE;
    }

    /* Parse output_count (NOT copied to hash buffer) */
    if (remaining < 1) { free(buf); return -1; }
    uint8_t output_count = *p;
    p++;
    remaining--;

    if (output_count > NODUS_T3_MAX_TX_OUTPUTS) { free(buf); return -1; }

    /* Copy each output's fields */
    for (int i = 0; i < output_count; i++) {
        if (remaining < OUTPUT_FIXED_SIZE) { free(buf); return -1; }

        /* Read memo_len (at offset OUTPUT_FIXED_SIZE - 1 within the output) */
        uint8_t memo_len = p[OUTPUT_FIXED_SIZE - 1];
        size_t output_total = OUTPUT_FIXED_SIZE + memo_len;

        if (remaining < output_total) { free(buf); return -1; }

        memcpy(buf + buf_pos, p, output_total);
        buf_pos += output_total;
        p += output_total;
        remaining -= output_total;
    }

    /* Hash the assembled buffer with SHA3-512 */
    nodus_key_t hash;
    int rc = nodus_hash(buf, buf_pos, &hash);
    free(buf);

    if (rc != 0) return -1;

    memcpy(hash_out, hash.bytes, NODUS_KEY_BYTES);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Parse output amounts from tx_data (for balance check)
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Parse outputs: compute total and optionally the "send amount"
 * (sum of outputs NOT owned by sender_fp).
 *
 * @param sender_fp   If non-NULL, compute send_amount (non-sender outputs)
 * @param send_out    Output: sum of non-sender outputs (if sender_fp provided)
 */
static int parse_output_total(const uint8_t *tx_data, uint32_t tx_len,
                               uint64_t *total_out, uint8_t *output_count_out,
                               const char *sender_fp, uint64_t *send_out) {
    if (tx_len < TX_HEADER_SIZE + 1) return -1;

    const uint8_t *p = tx_data + TX_INPUTS_OFF;
    size_t remaining = tx_len - TX_INPUTS_OFF;

    /* Skip inputs */
    if (remaining < 1) return -1;
    uint8_t input_count = *p;
    p++;
    remaining--;

    size_t inputs_size = (size_t)input_count * INPUT_SIZE;
    if (remaining < inputs_size) return -1;
    p += inputs_size;
    remaining -= inputs_size;

    /* Parse output_count */
    if (remaining < 1) return -1;
    uint8_t output_count = *p;
    p++;
    remaining--;

    if (output_count_out) *output_count_out = output_count;

    /* Sum output amounts */
    uint64_t total = 0;
    uint64_t send_total = 0;
    for (int i = 0; i < output_count; i++) {
        if (remaining < OUTPUT_FIXED_SIZE) return -1;

        /* fingerprint at offset version(1), 129 bytes */
        const char *out_fp = (const char *)(p + OUTPUT_VERSION_LEN);

        /* amount is at offset version(1) + fingerprint(129) = 130 */
        uint64_t amount;
        memcpy(&amount, p + OUTPUT_VERSION_LEN + OUTPUT_FP_LEN, sizeof(uint64_t));
        if (total + amount < total) return -1;  /* Overflow */
        total += amount;

        /* Non-sender output = transfer amount */
        if (sender_fp && strncmp(out_fp, sender_fp, 128) != 0) {
            send_total += amount;
        }

        uint8_t memo_len = p[OUTPUT_FIXED_SIZE - 1];
        size_t output_total = OUTPUT_FIXED_SIZE + memo_len;
        if (remaining < output_total) return -1;
        p += output_total;
        remaining -= output_total;
    }

    *total_out = total;
    if (send_out) *send_out = send_total;
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Parse signers section from serialized tx_data
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Parse signers section from serialized tx_data.
 * Skips: header -> inputs -> outputs -> witnesses -> reads signers.
 *
 * Returns signer_count and pointer to first signer in tx_data.
 * Caller gets pointers INTO tx_data (no copies).
 */
static int parse_signers_from_tx_data(const uint8_t *tx_data, uint32_t tx_len,
                                       uint8_t *signer_count_out,
                                       const uint8_t **signers_start_out) {
    if (!tx_data || tx_len < TX_HEADER_SIZE + 1) return -1;

    const uint8_t *p = tx_data + TX_INPUTS_OFF;
    size_t remaining = tx_len - TX_INPUTS_OFF;

    /* Skip inputs */
    if (remaining < 1) return -1;
    uint8_t input_count = *p++; remaining--;
    if (input_count > NODUS_T3_MAX_TX_INPUTS) return -1;
    size_t inputs_size = (size_t)input_count * INPUT_SIZE;
    if (remaining < inputs_size) return -1;
    p += inputs_size; remaining -= inputs_size;

    /* Skip outputs */
    if (remaining < 1) return -1;
    uint8_t output_count = *p++; remaining--;
    if (output_count > NODUS_T3_MAX_TX_OUTPUTS) return -1;
    for (int i = 0; i < output_count; i++) {
        if (remaining < OUTPUT_FIXED_SIZE) return -1;
        uint8_t memo_len = p[OUTPUT_FIXED_SIZE - 1];
        size_t out_total = OUTPUT_FIXED_SIZE + memo_len;
        if (remaining < out_total) return -1;
        p += out_total; remaining -= out_total;
    }

    /* Skip witnesses */
    if (remaining < 1) return -1;
    uint8_t witness_count = *p++; remaining--;
    size_t witness_size = 32 + NODUS_SIG_BYTES + 8 + NODUS_PK_BYTES;  /* id+sig+ts+pk */
    size_t witnesses_total = (size_t)witness_count * witness_size;
    if (remaining < witnesses_total) return -1;
    p += witnesses_total; remaining -= witnesses_total;

    /* Read signer_count */
    if (remaining < 1) return -1;
    uint8_t sc = *p++; remaining--;
    if (sc > NODUS_T3_MAX_TX_SIGNERS) return -1;

    /* Validate remaining space for signers */
    size_t signers_total = (size_t)sc * SIGNER_SIZE;
    if (remaining < signers_total) return -1;

    *signer_count_out = sc;
    *signers_start_out = p;  /* Points to first signer's pubkey */
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Full transaction verification
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_verify_transaction(nodus_witness_t *w,
                                      const uint8_t *tx_data, uint32_t tx_len,
                                      const uint8_t *tx_hash, uint8_t tx_type,
                                      const uint8_t *nullifiers, uint8_t nullifier_count,
                                      const uint8_t *client_pubkey,
                                      const uint8_t *client_signature,
                                      uint64_t declared_fee,
                                      char *reject_reason, size_t reason_size) {
    if (!w || !tx_data || !tx_hash) {
        if (reject_reason)
            snprintf(reject_reason, reason_size, "null parameter");
        return -1;
    }

    bool is_genesis = (tx_type == NODUS_W_TX_GENESIS);
    bool is_token_create = (tx_type == NODUS_W_TX_TOKEN_CREATE);

    /* ── Check 1: Duplicate nullifiers within TX ───────────────── */
    if (!is_genesis && nullifiers && nullifier_count > 1) {
        for (int i = 0; i < nullifier_count; i++) {
            for (int j = i + 1; j < nullifier_count; j++) {
                if (memcmp(nullifiers + i * NODUS_T3_NULLIFIER_LEN,
                           nullifiers + j * NODUS_T3_NULLIFIER_LEN,
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    snprintf(reject_reason, reason_size,
                             "duplicate nullifier in TX (input %d == %d)", i, j);
                    return -1;
                }
            }
        }
    }

    /* ── Check 2: TX hash integrity ────────────────────────────── */
    if (tx_len < TX_HEADER_SIZE + 1) {
        snprintf(reject_reason, reason_size,
                 "tx_data truncated (%u bytes, need >= %d)", tx_len, TX_HEADER_SIZE + 1);
        return -1;
    }

    uint8_t computed_hash[NODUS_KEY_BYTES];
    /* Extract signer pubkeys for hash computation */
    uint8_t hash_signer_count = 0;
    const uint8_t *hash_signers = NULL;
    uint8_t signer_pubkeys_buf[NODUS_T3_MAX_TX_SIGNERS * NODUS_PK_BYTES];

    /* Parse signers from tx_data for ALL tx types (including genesis).
     * Genesis TX now carries signer_count=1 (creator signs phase1). */
    if (parse_signers_from_tx_data(tx_data, tx_len, &hash_signer_count, &hash_signers) != 0) {
        /* Pre-genesis fresh chain: no signers section possible if tx_data is minimal.
         * Fall back to signer_count=0 for hash computation. */
        hash_signer_count = 0;
    } else {
        /* Copy pubkeys only (skip signatures) */
        for (int s = 0; s < hash_signer_count; s++) {
            memcpy(signer_pubkeys_buf + s * NODUS_PK_BYTES,
                   hash_signers + s * SIGNER_SIZE, NODUS_PK_BYTES);
        }
    }

    if (nodus_witness_recompute_tx_hash(tx_data, tx_len,
                                         hash_signer_count > 0 ? signer_pubkeys_buf : NULL,
                                         hash_signer_count,
                                         computed_hash) != 0) {
        snprintf(reject_reason, reason_size, "tx_hash recomputation failed (truncated tx_data)");
        return -1;
    }

    if (memcmp(computed_hash, tx_hash, NODUS_T3_TX_HASH_LEN) != 0) {
        snprintf(reject_reason, reason_size, "tx_hash mismatch (data tampered)");
        return -1;
    }

    /* Genesis transactions skip signature, balance, and fee checks.
     * Witnesses authorize genesis by consensus alone. */
    if (is_genesis)
        return 0;

    /* ── Check 3: Signer signatures ───────────────────────────── */
    if (!hash_signers || hash_signer_count == 0) {
        snprintf(reject_reason, reason_size, "no signers in transaction");
        return -1;
    }

    for (int s = 0; s < hash_signer_count; s++) {
        const uint8_t *spk = hash_signers + s * SIGNER_SIZE;
        const uint8_t *ssig = hash_signers + s * SIGNER_SIZE + NODUS_PK_BYTES;

        /* Check pubkey not all-zero */
        bool pk_zero = true;
        for (int k = 0; k < 32 && pk_zero; k++) {
            if (spk[k] != 0) pk_zero = false;
        }
        if (pk_zero) {
            snprintf(reject_reason, reason_size, "signer %d pubkey is zero", s);
            return -1;
        }

        nodus_sig_t sig;
        nodus_pubkey_t pk;
        memcpy(sig.bytes, ssig, NODUS_SIG_BYTES);
        memcpy(pk.bytes, spk, NODUS_PK_BYTES);

        if (nodus_verify(&sig, tx_hash, NODUS_T3_TX_HASH_LEN, &pk) != 0) {
            snprintf(reject_reason, reason_size, "signer %d signature invalid", s);
            return -1;
        }
    }

    /* ── Check 4: Balance ──────────────────────────────────────── */
    if (!nullifiers || nullifier_count == 0) {
        snprintf(reject_reason, reason_size, "no inputs for non-genesis TX");
        return -1;
    }

    /* Compute fingerprints for all signers */
    uint8_t parsed_signer_count = 0;
    const uint8_t *signers_data = NULL;
    char signer_fps[NODUS_T3_MAX_TX_SIGNERS][129];
    int n_signer_fps = 0;

    if (parse_signers_from_tx_data(tx_data, tx_len, &parsed_signer_count, &signers_data) == 0) {
        for (int s = 0; s < parsed_signer_count; s++) {
            nodus_pubkey_t spk;
            memcpy(spk.bytes, signers_data + s * SIGNER_SIZE, NODUS_PK_BYTES);
            if (nodus_fingerprint_hex(&spk, signer_fps[n_signer_fps]) == 0)
                n_signer_fps++;
        }
    }

    /* Use first signer as "sender" for fee calculation (change output detection) */
    char sender_fp[129] = {0};
    if (n_signer_fps > 0) {
        memcpy(sender_fp, signer_fps[0], 128);
        sender_fp[128] = '\0';
    }

    uint64_t total_input = 0;

    for (int i = 0; i < nullifier_count; i++) {
        const uint8_t *nul = nullifiers + i * NODUS_T3_NULLIFIER_LEN;
        uint64_t utxo_amount = 0;
        char owner[129] = {0};
        uint8_t utxo_token_id[64] = {0};

        if (nodus_witness_utxo_lookup(w, nul, &utxo_amount, owner,
                                       is_token_create ? NULL : utxo_token_id) != 0) {
            snprintf(reject_reason, reason_size,
                     "input %d: UTXO not found in set", i);
            return -1;
        }

        /* CRITICAL-4: Verify UTXO is owned by some signer */
        if (owner[0] != '\0') {
            bool owned = false;
            for (int s = 0; s < n_signer_fps; s++) {
                if (strcmp(owner, signer_fps[s]) == 0) { owned = true; break; }
            }
            if (!owned) {
                snprintf(reject_reason, reason_size,
                         "input %d: UTXO not owned by any signer", i);
                return -1;
            }
        }

        if (total_input + utxo_amount < total_input) {
            snprintf(reject_reason, reason_size,
                     "input amount overflow at %d", i);
            return -1;
        }
        total_input += utxo_amount;
    }

    uint64_t total_output = 0;
    uint64_t send_amount = 0;
    if (parse_output_total(tx_data, tx_len, &total_output, NULL,
                            sender_fp[0] ? sender_fp : NULL,
                            &send_amount) != 0) {
        snprintf(reject_reason, reason_size, "failed to parse outputs from tx_data");
        return -1;
    }

    if (is_token_create) {
        /* ── TOKEN_CREATE: custom balance/fee check ────────────── */
        /* Inputs are DNAC (fee payment). Outputs include a genesis
         * UTXO for the new token (different denomination) so standard
         * total_input >= total_output does NOT apply.
         * Verify: DNAC inputs cover the creation fee. */
        if (total_input < NODUS_W_TOKEN_CREATE_FEE) {
            snprintf(reject_reason, reason_size,
                     "insufficient DNAC for token creation fee: input=%lu < required=%lu",
                     (unsigned long)total_input,
                     (unsigned long)NODUS_W_TOKEN_CREATE_FEE);
            return -1;
        }
        if (declared_fee < NODUS_W_TOKEN_CREATE_FEE) {
            snprintf(reject_reason, reason_size,
                     "token create fee too low: declared=%lu < required=%lu",
                     (unsigned long)declared_fee,
                     (unsigned long)NODUS_W_TOKEN_CREATE_FEE);
            return -1;
        }
    } else {
        /* ── Standard SPEND/BURN balance check ─────────────────── */
        if (total_input < total_output) {
            snprintf(reject_reason, reason_size,
                     "insufficient balance: input=%lu < output=%lu",
                     (unsigned long)total_input, (unsigned long)total_output);
            return -1;
        }

        /* ── Check 5: Fee ──────────────────────────────────────── */
        uint64_t actual_fee = total_input - total_output;
        /* Fee = 0.1% of send amount (non-change outputs), min 1 */
        uint64_t fee_basis = (send_amount > 0) ? send_amount : total_output;
        uint64_t min_fee = fee_basis / 1000;
        if (min_fee == 0) min_fee = 1;

        if (actual_fee < min_fee) {
            snprintf(reject_reason, reason_size,
                     "fee too low: actual=%lu < min=%lu (output=%lu)",
                     (unsigned long)actual_fee, (unsigned long)min_fee,
                     (unsigned long)total_output);
            return -1;
        }

        if (actual_fee != declared_fee) {
            snprintf(reject_reason, reason_size,
                     "fee mismatch: actual=%lu != declared=%lu",
                     (unsigned long)actual_fee, (unsigned long)declared_fee);
            return -1;
        }
    }

    /* ── Check 6: Double-spend ─────────────────────────────────── */
    for (int i = 0; i < nullifier_count; i++) {
        const uint8_t *nul = nullifiers + i * NODUS_T3_NULLIFIER_LEN;
        if (nodus_witness_nullifier_exists(w, nul)) {
            snprintf(reject_reason, reason_size,
                     "nullifier %d already spent (double-spend)", i);
            return -2;
        }
    }

    return 0;
}
