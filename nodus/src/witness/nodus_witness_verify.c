/**
 * Nodus v5 — Witness Transaction Verification
 *
 * Full transaction verification for BFT consensus PREVOTE.
 * Recomputes tx_hash, verifies sender signature, checks balance
 * against UTXO DB, validates fee, and checks double-spend.
 *
 * Wire format (from dnac/src/transaction/serialize.c):
 *   Header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74 bytes
 *   Inputs: count(1) + [nullifier(64) + amount(8)]*N
 *   Outputs: count(1) + [version(1) + fingerprint(129) + amount(8) + seed(32) + memo_len(1) + memo(n)]*M
 *
 * Hash covers: version + type + timestamp + inputs + outputs (no counts, no embedded hash)
 *
 * @file nodus_witness_verify.c
 */

#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_db.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
#define INPUT_SIZE          (INPUT_NULLIFIER_LEN + INPUT_AMOUNT_LEN) /* 72 */

#define OUTPUT_VERSION_LEN  1
#define OUTPUT_FP_LEN       129
#define OUTPUT_AMOUNT_LEN   8
#define OUTPUT_SEED_LEN     32
#define OUTPUT_MEMO_LEN_LEN 1
#define OUTPUT_FIXED_SIZE   (OUTPUT_VERSION_LEN + OUTPUT_FP_LEN + OUTPUT_AMOUNT_LEN + \
                             OUTPUT_SEED_LEN + OUTPUT_MEMO_LEN_LEN) /* 171 */

/* Fee: 0.1% (10 basis points), minimum 1 unit */
#define FEE_RATE_BPS 10

/* ════════════════════════════════════════════════════════════════════
 * Recompute TX hash from serialized data
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_recompute_tx_hash(const uint8_t *tx_data, uint32_t tx_len,
                                     const uint8_t *client_pubkey,
                                     uint8_t *hash_out) {
    if (!tx_data || !hash_out || !client_pubkey || tx_len < TX_HEADER_SIZE + 1)
        return -1;

    /* Allocate buffer to assemble hash input (tx_len + pubkey) */
    uint8_t *buf = malloc(tx_len + NODUS_PK_BYTES);
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

    /* Include sender_pubkey in hash (binds TX to sender identity) */
    memcpy(buf + buf_pos, client_pubkey, NODUS_PK_BYTES);
    buf_pos += NODUS_PK_BYTES;

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

    /* Copy each input's nullifier(64) + amount(8) */
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

static int parse_output_total(const uint8_t *tx_data, uint32_t tx_len,
                               uint64_t *total_out, uint8_t *output_count_out) {
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
    for (int i = 0; i < output_count; i++) {
        if (remaining < OUTPUT_FIXED_SIZE) return -1;

        /* amount is at offset version(1) + fingerprint(129) = 130 */
        uint64_t amount;
        memcpy(&amount, p + OUTPUT_VERSION_LEN + OUTPUT_FP_LEN, sizeof(uint64_t));
        if (total + amount < total) return -1;  /* Overflow */
        total += amount;

        uint8_t memo_len = p[OUTPUT_FIXED_SIZE - 1];
        size_t output_total = OUTPUT_FIXED_SIZE + memo_len;
        if (remaining < output_total) return -1;
        p += output_total;
        remaining -= output_total;
    }

    *total_out = total;
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
    /* Use all-zero pubkey for genesis (no sender), actual pubkey for spends */
    const uint8_t *hash_pubkey = client_pubkey;
    uint8_t zero_pk[NODUS_PK_BYTES];
    if (is_genesis) {
        memset(zero_pk, 0, NODUS_PK_BYTES);
        hash_pubkey = zero_pk;
    }
    if (nodus_witness_recompute_tx_hash(tx_data, tx_len, hash_pubkey, computed_hash) != 0) {
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

    /* ── Check 3: Sender signature ─────────────────────────────── */
    if (!client_pubkey || !client_signature) {
        snprintf(reject_reason, reason_size,
                 "missing sender pubkey or signature");
        return -1;
    }

    /* Check pubkey is not all-zero (unset) */
    {
        bool pk_zero = true;
        for (int i = 0; i < 32 && pk_zero; i++) {
            if (client_pubkey[i] != 0) pk_zero = false;
        }
        if (pk_zero) {
            snprintf(reject_reason, reason_size, "sender pubkey is zero (unset)");
            return -1;
        }
    }

    /* Copy into typed structs to avoid aliasing issues */
    nodus_sig_t sig;
    nodus_pubkey_t pk;
    memcpy(sig.bytes, client_signature, NODUS_SIG_BYTES);
    memcpy(pk.bytes, client_pubkey, NODUS_PK_BYTES);

    if (nodus_verify(&sig, tx_hash, NODUS_T3_TX_HASH_LEN, &pk) != 0) {
        snprintf(reject_reason, reason_size, "sender signature invalid");
        return -1;
    }

    /* ── Check 4: Balance ──────────────────────────────────────── */
    if (!nullifiers || nullifier_count == 0) {
        snprintf(reject_reason, reason_size, "no inputs for non-genesis TX");
        return -1;
    }

    /* Compute sender fingerprint from pubkey for ownership check */
    char sender_fp[129] = {0};
    {
        nodus_pubkey_t sender_pk;
        memcpy(sender_pk.bytes, client_pubkey, NODUS_PK_BYTES);
        if (nodus_fingerprint_hex(&sender_pk, sender_fp) != 0) {
            snprintf(reject_reason, reason_size,
                     "failed to compute sender fingerprint");
            return -1;
        }
    }

    uint64_t total_input = 0;
    for (int i = 0; i < nullifier_count; i++) {
        const uint8_t *nul = nullifiers + i * NODUS_T3_NULLIFIER_LEN;
        uint64_t utxo_amount = 0;
        char owner[129] = {0};

        if (nodus_witness_utxo_lookup(w, nul, &utxo_amount, owner) != 0) {
            snprintf(reject_reason, reason_size,
                     "input %d: UTXO not found in set", i);
            return -1;
        }

        /* CRITICAL-4: Verify UTXO is owned by the sender */
        if (owner[0] != '\0' && strcmp(owner, sender_fp) != 0) {
            snprintf(reject_reason, reason_size,
                     "input %d: UTXO not owned by sender", i);
            return -1;
        }

        if (total_input + utxo_amount < total_input) {
            snprintf(reject_reason, reason_size,
                     "input amount overflow at %d", i);
            return -1;
        }
        total_input += utxo_amount;
    }

    uint64_t total_output = 0;
    if (parse_output_total(tx_data, tx_len, &total_output, NULL) != 0) {
        snprintf(reject_reason, reason_size, "failed to parse outputs from tx_data");
        return -1;
    }

    if (total_input < total_output) {
        snprintf(reject_reason, reason_size,
                 "insufficient balance: input=%lu < output=%lu",
                 (unsigned long)total_input, (unsigned long)total_output);
        return -1;
    }

    /* ── Check 5: Fee ──────────────────────────────────────────── */
    uint64_t actual_fee = total_input - total_output;
    /* Use total_output/1000 instead of (total_output*10)/10000 to avoid overflow */
    uint64_t min_fee = total_output / 1000;
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
