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
 * F-CONS-06 — Mandatory independent verification on PREVOTE:
 *   Functions in this file are the ONLY consensus primitives a follower
 *   runs before broadcasting PREVOTE APPROVE. They recompute every
 *   security-relevant value from the raw TX bytes (tx_hash, signer
 *   signatures, nullifier state, fee, ownership) — no field is trusted
 *   from the leader's PROPOSE message without independent recompute.
 *
 *   Post-commit state_root binding is enforced separately in
 *   nodus_witness_bft.c::nodus_witness_bft_handle_commit, where each
 *   follower independently computes state_root via
 *   nodus_witness_merkle_compute_state_root() and compares the result
 *   against the leader's COMMIT-message state_root. A compromised
 *   leader therefore cannot force followers to adopt an invalid
 *   post-block state. See tests/test_prevote_state_root_mutation.c for
 *   the regression guard.
 *
 * @file nodus_witness_verify.c
 */

#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_db.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/dnac.h"            /* DNAC_PROTOCOL_VERSION, DNAC_MIN_FEE_RAW */
#include "dnac/transaction.h"     /* DNAC_TX_HEADER_SIZE, dnac_tx_read_committed_fee */
#include "dnac/safe_math.h"       /* safe_add_u64 (SEC-01 consistency check) */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-VERIFY"

/* Wire format constants */
/* TX_HEADER_SIZE kept for backward-compat within this file; v0.17.1 bumped to 82
 * (committed_fee added). Single source of truth is DNAC_TX_HEADER_SIZE in
 * dnac/transaction.h — this local define mirrors it. */
#define TX_HEADER_SIZE      DNAC_TX_HEADER_SIZE
#define TX_VERSION_OFF      0
#define TX_TYPE_OFF         1
#define TX_TIMESTAMP_OFF    2
#define TX_HASH_OFF         10  /* After version+type+timestamp */
#define TX_INPUTS_OFF       TX_HEADER_SIZE  /* After header (82 in v0.17.1: hdr74 + committed_fee(8)) */

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

/* DNAC TX type codes (mirror messenger tree — kept local to avoid a
 * cross-tree dependency). Values MUST match dnac/include/dnac/transaction.h
 * and nodus_witness.h NODUS_W_TX_* above. */
#define TX_TYPE_GENESIS              NODUS_W_TX_GENESIS            /* 0 */
#define TX_TYPE_SPEND                NODUS_W_TX_SPEND              /* 1 */
#define TX_TYPE_BURN                 NODUS_W_TX_BURN               /* 2 */
#define TX_TYPE_TOKEN_CREATE         NODUS_W_TX_TOKEN_CREATE       /* 3 */
#define TX_TYPE_STAKE                NODUS_W_TX_STAKE              /* 4 */
#define TX_TYPE_DELEGATE             NODUS_W_TX_DELEGATE           /* 5 */
#define TX_TYPE_UNSTAKE              NODUS_W_TX_UNSTAKE            /* 6 */
#define TX_TYPE_UNDELEGATE           NODUS_W_TX_UNDELEGATE         /* 7 */
/* 8 was CLAIM_REWARD — removed in v0.16 reward redesign. */
#define TX_TYPE_VALIDATOR_UPDATE     NODUS_W_TX_VALIDATOR_UPDATE   /* 9 */
#define TX_TYPE_CHAIN_CONFIG         NODUS_W_TX_CHAIN_CONFIG       /* 10 */

/* F-CRYPTO-05: "DNAC_VALIDATOR_v1" — 17 bytes, no padding. Matches
 * dnac/include/dnac/transaction.h DNAC_STAKE_PURPOSE_TAG_LEN = 17. */
#define TX_STAKE_PURPOSE_TAG_LEN     17
#define TX_STAKE_UNSTAKE_DEST_FP_LEN 64

/* Chain ID length (matches DNAC chain_id[32]). */
#define TX_CHAIN_ID_LEN              32

/* Big-endian u64 writer for preimage encoding. Matches
 * dnac/src/transaction/transaction.c::tx_be64_into. */
static void be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

/* LE u64 reader for parsing wire-format timestamp and amounts. The wire
 * format uses native (LE on x86) via memcpy — see
 * dnac/src/transaction/serialize.c WRITE_U64/READ_U64. */
static uint64_t le64_read(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

int nodus_witness_recompute_tx_hash(const uint8_t *chain_id,
                                     const uint8_t *tx_data, uint32_t tx_len,
                                     const uint8_t *signer_pubkeys,
                                     uint8_t signer_count,
                                     uint8_t *hash_out) {
    if (!chain_id || !tx_data || !hash_out || tx_len < TX_HEADER_SIZE + 1)
        return -1;
    if (!signer_pubkeys && signer_count > 0)
        return -1;
    if (signer_count > NODUS_T3_MAX_TX_SIGNERS)
        return -1;

    /* Assemble the canonical preimage in a single growable buffer, then
     * SHA3-512 it. Upper bound: tx_len (all wire bytes we may echo) +
     * chain_id(32) + 1 + signer_count * NODUS_PK_BYTES + tx_len (type-spec). */
    size_t upper = (size_t)tx_len + TX_CHAIN_ID_LEN + 1
                 + (size_t)NODUS_T3_MAX_TX_SIGNERS * NODUS_PK_BYTES
                 + (size_t)tx_len;
    uint8_t *buf = malloc(upper);
    if (!buf) return -1;

    size_t buf_pos = 0;
    const uint8_t *p = tx_data;
    size_t remaining = tx_len;

    /* ── Domain separator "DNAC_TX_V2\0" (SEC-06, 11 bytes) ────── */
    memcpy(buf + buf_pos, DNAC_TX_PREIMAGE_DOMAIN_V2,
           DNAC_TX_PREIMAGE_DOMAIN_V2_LEN);
    buf_pos += DNAC_TX_PREIMAGE_DOMAIN_V2_LEN;

    /* ── Header: version(u8) || type(u8) || timestamp(u64 BE) || chain_id[32] ── */
    if (remaining < 10) goto fail;
    uint8_t version_byte = p[0];
    uint8_t type_byte    = p[1];
    uint64_t timestamp   = le64_read(p + 2);
    p += 10;
    remaining -= 10;

    buf[buf_pos++] = version_byte;
    buf[buf_pos++] = type_byte;
    be64_into(timestamp, buf + buf_pos);
    buf_pos += 8;
    memcpy(buf + buf_pos, chain_id, TX_CHAIN_ID_LEN);
    buf_pos += TX_CHAIN_ID_LEN;

    /* Skip embedded tx_hash (64 bytes) */
    if (remaining < 64) goto fail;
    p += 64;
    remaining -= 64;

    /* ── committed_fee (u64 BE, v0.17.1+) — read from wire, add to preimage ── */
    if (remaining < 8) goto fail;
    uint64_t committed_fee = 0;
    for (int i = 0; i < 8; i++)
        committed_fee = (committed_fee << 8) | (uint64_t)p[i];
    be64_into(committed_fee, buf + buf_pos);
    buf_pos += 8;
    p += 8;
    remaining -= 8;

    /* ── Inputs: nullifier(64) || amount(u64 BE) || token_id(64) ── */
    if (remaining < 1) goto fail;
    uint8_t input_count = *p++;
    remaining--;
    if (input_count > NODUS_T3_MAX_TX_INPUTS) goto fail;

    for (int i = 0; i < input_count; i++) {
        if (remaining < INPUT_SIZE) goto fail;
        /* nullifier */
        memcpy(buf + buf_pos, p, INPUT_NULLIFIER_LEN);
        buf_pos += INPUT_NULLIFIER_LEN;
        /* amount: read LE from wire, encode BE into preimage */
        uint64_t amt = le64_read(p + INPUT_NULLIFIER_LEN);
        be64_into(amt, buf + buf_pos);
        buf_pos += 8;
        /* token_id */
        memcpy(buf + buf_pos, p + INPUT_NULLIFIER_LEN + 8, INPUT_TOKEN_ID_LEN);
        buf_pos += INPUT_TOKEN_ID_LEN;

        p += INPUT_SIZE;
        remaining -= INPUT_SIZE;
    }

    /* ── Outputs: version(u8) || fp(129) || amount(u64 BE) || token_id(64) ||
     *           seed(32) || memo_len(u8) || memo(memo_len) ── */
    if (remaining < 1) goto fail;
    uint8_t output_count = *p++;
    remaining--;
    if (output_count > NODUS_T3_MAX_TX_OUTPUTS) goto fail;

    for (int i = 0; i < output_count; i++) {
        if (remaining < OUTPUT_FIXED_SIZE) goto fail;

        uint8_t memo_len = p[OUTPUT_FIXED_SIZE - 1];
        size_t output_total = OUTPUT_FIXED_SIZE + memo_len;
        if (remaining < output_total) goto fail;

        /* version */
        buf[buf_pos++] = p[0];
        /* fp(129) */
        memcpy(buf + buf_pos, p + OUTPUT_VERSION_LEN, OUTPUT_FP_LEN);
        buf_pos += OUTPUT_FP_LEN;
        /* amount: LE on wire → BE in preimage */
        uint64_t amt = le64_read(p + OUTPUT_VERSION_LEN + OUTPUT_FP_LEN);
        be64_into(amt, buf + buf_pos);
        buf_pos += 8;
        /* token_id + seed */
        memcpy(buf + buf_pos,
               p + OUTPUT_VERSION_LEN + OUTPUT_FP_LEN + OUTPUT_AMOUNT_LEN,
               OUTPUT_TOKEN_ID_LEN + OUTPUT_SEED_LEN);
        buf_pos += OUTPUT_TOKEN_ID_LEN + OUTPUT_SEED_LEN;
        /* memo_len */
        buf[buf_pos++] = memo_len;
        /* memo bytes */
        if (memo_len > 0) {
            memcpy(buf + buf_pos, p + OUTPUT_FIXED_SIZE, memo_len);
            buf_pos += memo_len;
        }

        p += output_total;
        remaining -= output_total;
    }

    /* ── Signers: signer_count(u8) || signer_pubkeys[0..signer_count] ──
     * The caller supplies the pubkey concatenation (already extracted from
     * tx_data). This matches the client-side preimage exactly: signatures
     * are NOT hashed. */
    buf[buf_pos++] = signer_count;
    for (int i = 0; i < signer_count; i++) {
        memcpy(buf + buf_pos,
               signer_pubkeys + (size_t)i * NODUS_PK_BYTES,
               NODUS_PK_BYTES);
        buf_pos += NODUS_PK_BYTES;
    }

    /* ── Type-specific appended fields ──
     * At this point the wire cursor `p` is already positioned after signers
     * (we walked inputs/outputs above but NOT the wire signers/witnesses
     * sections — the wire has witnesses then signers between outputs and
     * the type-specific tail). Rather than re-walk, we jump the wire cursor
     * past witnesses + signers to reach the appended section. */

    /* Skip witnesses(count + count * (32+sig+8+pk)) on the wire */
    if (remaining < 1) goto fail;
    uint8_t witness_count = *p++;
    remaining--;
    {
        size_t witness_size = 32 + NODUS_SIG_BYTES + 8 + NODUS_PK_BYTES;
        size_t witnesses_total = (size_t)witness_count * witness_size;
        if (remaining < witnesses_total) goto fail;
        p += witnesses_total;
        remaining -= witnesses_total;
    }

    /* Skip signers on the wire */
    if (remaining < 1) goto fail;
    uint8_t wire_signer_count = *p++;
    remaining--;
    if (wire_signer_count > NODUS_T3_MAX_TX_SIGNERS) goto fail;
    {
        size_t signers_total = (size_t)wire_signer_count * SIGNER_SIZE;
        if (remaining < signers_total) goto fail;
        p += signers_total;
        remaining -= signers_total;
    }

    /* Per-type appended — wire already encodes u16/u64 BE here, so we can
     * memcpy directly into the preimage. */
    if (type_byte == TX_TYPE_STAKE) {
        size_t need = 2 + TX_STAKE_UNSTAKE_DEST_FP_LEN + TX_STAKE_PURPOSE_TAG_LEN;
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need;
        p += need;
        remaining -= need;
    } else if (type_byte == TX_TYPE_DELEGATE) {
        /* v0.17.1+: DELEGATE appended = validator_pubkey(2592) + delegation_amount(u64 BE). */
        size_t need = NODUS_PK_BYTES + 8;
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need;
        p += need;
        remaining -= need;
    } else if (type_byte == TX_TYPE_UNDELEGATE) {
        size_t need = NODUS_PK_BYTES + 8;
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need;
        p += need;
        remaining -= need;
    } else if (type_byte == TX_TYPE_VALIDATOR_UPDATE) {
        size_t need = 2 + 8;
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need;
        p += need;
        remaining -= need;
    } else if (type_byte == TX_TYPE_CHAIN_CONFIG) {
        /* Hard-Fork v1 CHAIN_CONFIG variable-length appended:
         *   param_id(1) + new_value(8) + effective_block(8) +
         *   proposal_nonce(8) + signed_at_block(8) + valid_before_block(8) +
         *   committee_sig_count(1) + votes[n] each: witness_id(32) +
         *   signature(DNAC_SIGNATURE_SIZE = NODUS_SIG_BYTES).
         * All BE integers on both wire and preimage so we can memcpy. */
        size_t fixed = 1 + 8 + 8 + 8 + 8 + 8 + 1;
        if (remaining < fixed) goto fail;
        memcpy(buf + buf_pos, p, fixed);
        buf_pos += fixed;
        uint8_t cc_sig_count = p[fixed - 1];
        p += fixed;
        remaining -= fixed;
        /* Bound check: <= compile-time committee cap, matches client. */
        if (cc_sig_count > NODUS_T3_MAX_WITNESSES) goto fail;
        size_t per_vote = 32 + NODUS_SIG_BYTES;
        size_t votes_total = (size_t)cc_sig_count * per_vote;
        if (remaining < votes_total) goto fail;
        if (votes_total > 0) {
            memcpy(buf + buf_pos, p, votes_total);
            buf_pos += votes_total;
            p += votes_total;
            remaining -= votes_total;
        }
    }
    /* UNSTAKE, GENESIS, SPEND, BURN, TOKEN_CREATE: no appended fields. */

    /* Suppress unused-variable warnings for optimized paths. */
    (void)version_byte;

    /* Hash the assembled buffer with SHA3-512 */
    nodus_key_t hash;
    int rc = nodus_hash(buf, buf_pos, &hash);
    free(buf);

    if (rc != 0) return -1;

    memcpy(hash_out, hash.bytes, NODUS_KEY_BYTES);
    return 0;

fail:
    free(buf);
    return -1;
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

    /* ── Check 0: v0.17.1 wire version + min-fee (cheap DoS gate).
     * Runs BEFORE Dilithium5 signer verification (PERF-04): version-byte
     * mismatch and sub-minimum fee don't deserve 300–500 µs/signer of
     * wasted CPU. dnac_tx_read_committed_fee() also validates the header
     * length, so an 82-byte-short buffer cannot leak via the offset-74
     * read (SEC-02). */
    if (tx_len >= 1 && tx_data[0] != DNAC_PROTOCOL_VERSION) {
        snprintf(reject_reason, reason_size,
                 "wrong TX wire version (got %u, expected %u)",
                 (unsigned)tx_data[0], (unsigned)DNAC_PROTOCOL_VERSION);
        return -1;
    }
    if (!is_genesis) {
        uint64_t committed_fee = 0;
        if (dnac_tx_read_committed_fee(tx_data, tx_len, &committed_fee) != 0) {
            snprintf(reject_reason, reason_size,
                     "committed_fee unreadable (malformed header)");
            return -1;
        }
        if (committed_fee < DNAC_MIN_FEE_RAW) {
            snprintf(reject_reason, reason_size,
                     "committed_fee %llu below minimum %llu",
                     (unsigned long long)committed_fee,
                     (unsigned long long)DNAC_MIN_FEE_RAW);
            return -1;
        }
    }

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

    if (nodus_witness_recompute_tx_hash(w->chain_id, tx_data, tx_len,
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

    /* Task 29 (Rule D): SPEND rejects locked UTXO inputs. The current
     * chain tip (block height of the last committed block) is the cutoff:
     * a UTXO with unlock_block > current_block is still in its post-UNSTAKE
     * cooldown window and cannot be spent yet. UTXOs with unlock_block == 0
     * are the normal unlocked case (default for all non-UNSTAKE outputs). */
    uint64_t current_block = nodus_witness_block_height(w);

    for (int i = 0; i < nullifier_count; i++) {
        const uint8_t *nul = nullifiers + i * NODUS_T3_NULLIFIER_LEN;
        uint64_t utxo_amount = 0;
        char owner[129] = {0};
        uint8_t utxo_token_id[64] = {0};
        uint64_t utxo_unlock_block = 0;

        if (nodus_witness_utxo_lookup_ex(w, nul, &utxo_amount, owner,
                                          is_token_create ? NULL : utxo_token_id,
                                          &utxo_unlock_block) != 0) {
            snprintf(reject_reason, reason_size,
                     "input %d: UTXO not found in set", i);
            return -1;
        }

        /* Rule D: locked UTXO (unlock_block > current chain height) — reject. */
        if (utxo_unlock_block > current_block) {
            snprintf(reject_reason, reason_size,
                     "input %d: UTXO locked (unlock_block=%lu > current=%lu)",
                     i,
                     (unsigned long)utxo_unlock_block,
                     (unsigned long)current_block);
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

        /* ── Check 5: Dynamic fee (DNAC-only) ─────────────────── */
        uint64_t actual_fee = total_input - total_output;
        /* Dynamic fee: base * (1 + mempool_count / surge_step)
         * Surge increases fee as mempool fills up. */
        int mp_count = w ? w->mempool.count : 0;
        uint64_t min_fee = NODUS_W_BASE_TX_FEE * (1 + (uint64_t)mp_count / NODUS_W_FEE_SURGE_STEP);

        if (actual_fee < min_fee) {
            snprintf(reject_reason, reason_size,
                     "fee too low: actual=%lu < min=%lu (mempool=%d)",
                     (unsigned long)actual_fee, (unsigned long)min_fee,
                     mp_count);
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
