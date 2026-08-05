/**
 * @file shared/dnac/tx_wire.c
 * @brief Ledger V2 Season 1 — shared transaction wire codec implementation.
 *
 * See tx_wire.h for the byte layouts. Three sections:
 *   1. ExecutionContext encode/decode/validate
 *   2. Transaction Wire V3 codec + V5-preimage hash (inactive until the
 *      Ledger V2 devnet reset — no live consensus path accepts version 3)
 *   3. The legacy (V2/V4) tx-hash — exact port of the witness wire walk
 *      that both libdna and libnodus now share
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "tx_wire.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"   /* qgp_sha3_512 — same digest both trees */

/* ── Local BE helpers (wire encoding is BE; never native memcpy) ────── */
static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static uint32_t get_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] << 8)  |  (uint32_t)in[3];
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint64_t get_be64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)in[i];
    return v;
}
/* Legacy wire convention: timestamp/amounts were written with a native
 * memcpy (LE on every supported host). Pre-existing posture, unchanged —
 * see tx_wire.h §3 and the original le64_read in nodus_witness_verify.c. */
static uint64_t legacy_le64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

/* ══════════════════════════════════════════════════════════════════════
 * 1. ExecutionContext
 * ════════════════════════════════════════════════════════════════════ */

/* CANONICAL/STRUCTURAL rules only (S1 correction #1): the generic codec
 * judges encoding legality, never network policy. Future manifest-
 * registered domains/pools/proof-bearing types MUST encode without a codec
 * change; admissibility is Season-4/9 runtime work. */
static int exec_ctx_structural_ok(uint8_t wire_version) {
    return wire_version == DNAC_TXW3_WIRE_VERSION;   /* fail closed */
}

int dna_exec_context_init(dna_exec_context_t *ctx,
                          const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                          uint32_t domain_id, uint32_t pool_id,
                          uint8_t tx_type, uint8_t wire_version,
                          uint32_t ruleset_version, uint32_t statement_version) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    if (!chain_id) return -1;
    if (!exec_ctx_structural_ok(wire_version))
        return -1;
    memcpy(ctx->chain_id, chain_id, DNA_CHAIN_ID_LEN);
    ctx->domain_id         = domain_id;
    ctx->pool_id           = pool_id;
    ctx->tx_type           = tx_type;
    ctx->wire_version      = wire_version;
    ctx->ruleset_version   = ruleset_version;
    ctx->statement_version = statement_version;
    return 0;
}

int dna_exec_context_validate(const dna_exec_context_t *ctx) {
    if (!ctx) return -1;
    return exec_ctx_structural_ok(ctx->wire_version) ? 0 : -1;
}

int dna_exec_context_check_initial_policy(const dna_exec_context_t *ctx) {
    /* INITIAL-NETWORK POLICY (preview of S4/S9 admission; ZERO production
     * callers — tests only). NEVER wired into encode/decode/hash. */
    if (!ctx) return -1;
    if (dna_exec_context_validate(ctx) != 0) return -1;
    if (ctx->domain_id != DNA_DOMAIN_SYSTEM &&
        ctx->domain_id != DNA_DOMAIN_CORE)
        return -1;
    if (ctx->tx_type == DNAC_TXW_TYPE_SHIELDED) {
        if (ctx->pool_id != DNAC_SHIELDED_POOL_V1) return -1;
    } else {
        if (ctx->pool_id != DNA_POOL_NONE) return -1;
        if (ctx->statement_version != 0) return -1;
    }
    return 0;
}

int dna_exec_context_encode(const dna_exec_context_t *ctx,
                            uint8_t out[DNA_EXEC_CTX_WIRE_LEN]) {
    if (!ctx || !out) return -1;
    if (dna_exec_context_validate(ctx) != 0) return -1;
    memcpy(out, ctx->chain_id, DNA_CHAIN_ID_LEN);
    put_be32(ctx->domain_id,         out + 32);
    put_be32(ctx->pool_id,           out + 36);
    out[40] = ctx->tx_type;
    out[41] = ctx->wire_version;
    put_be32(ctx->ruleset_version,   out + 42);
    put_be32(ctx->statement_version, out + 46);
    return 0;
}

int dna_exec_context_decode(const uint8_t *in, size_t in_len,
                            dna_exec_context_t *out) {
    if (!in || !out) return -1;
    if (in_len != DNA_EXEC_CTX_WIRE_LEN) return -1;   /* strict, no slack */
    memset(out, 0, sizeof(*out));
    memcpy(out->chain_id, in, DNA_CHAIN_ID_LEN);
    out->domain_id         = get_be32(in + 32);
    out->pool_id           = get_be32(in + 36);
    out->tx_type           = in[40];
    out->wire_version      = in[41];
    out->ruleset_version   = get_be32(in + 42);
    out->statement_version = get_be32(in + 46);
    if (dna_exec_context_validate(out) != 0) {
        memset(out, 0, sizeof(*out));                 /* fail closed */
        return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. Transaction Wire V3
 * ════════════════════════════════════════════════════════════════════ */

const uint8_t DNAC_TXW_V5_TAG[16] = {
    'D','N','A','C','_','T','X','_','V','5', 0, 0, 0, 0, 0, 0
};

int dnac_txw3_encoded_size(uint32_t body_len, size_t *out) {
    if (!out) return -1;
    if (body_len > DNAC_TXW3_MAX_BODY_LEN) return -1;
    /* 110 + body_len cannot overflow size_t after the cap check, but keep
     * the checked shape so a future cap raise cannot silently regress. */
    size_t total = (size_t)DNAC_TXW3_BODY_OFF;
    if (body_len > SIZE_MAX - total) return -1;
    *out = total + body_len;
    return 0;
}

/* Serialize the 42 non-hash header bytes (wire_version..timestamp,
 * i.e. bytes [0,42)). Shared by encode + hash so the wire form and the
 * preimage can never drift. */
static int txw3_put_prefix(const dnac_txw3_header_t *hdr, uint8_t out[42]) {
    if (hdr->wire_version != DNAC_TXW3_WIRE_VERSION) return -1;
    out[0] = hdr->wire_version;
    out[1] = hdr->tx_type;
    put_be32(hdr->domain_id,         out + 2);
    put_be32(hdr->pool_id,           out + 6);
    put_be32(hdr->ruleset_version,   out + 10);
    put_be32(hdr->statement_version, out + 14);
    put_be64(hdr->expiry_height,     out + 18);
    put_be64(hdr->committed_fee,     out + 26);
    put_be64(hdr->timestamp,         out + 34);
    return 0;
}

int dnac_txw3_encode(const dnac_txw3_header_t *hdr,
                     const uint8_t *body, uint32_t body_len,
                     uint8_t *dst, size_t dst_cap, size_t *written_out) {
    if (!hdr || !dst || !written_out) return -1;
    if (!body && body_len != 0) return -1;
    size_t need = 0;
    if (dnac_txw3_encoded_size(body_len, &need) != 0) return -1;
    if (dst_cap < need) return -1;

    if (txw3_put_prefix(hdr, dst) != 0) return -1;
    memcpy(dst + DNAC_TXW3_TXHASH_OFF, hdr->tx_hash, DNAC_TXW_HASH_LEN);
    put_be32(body_len, dst + DNAC_TXW3_BODYLEN_OFF);
    if (body_len)
        memcpy(dst + DNAC_TXW3_BODY_OFF, body, body_len);
    *written_out = need;
    return 0;
}

int dnac_txw3_decode(const uint8_t *src, size_t src_len,
                     dnac_txw3_header_t *hdr,
                     const uint8_t **body_out, uint32_t *body_len_out) {
    if (!src || !hdr || !body_out || !body_len_out) return -1;
    if (src_len < (size_t)DNAC_TXW3_BODY_OFF) return -1;      /* truncated */
    if (src[0] != DNAC_TXW3_WIRE_VERSION) return -1;          /* unknown ver */

    uint32_t body_len = get_be32(src + DNAC_TXW3_BODYLEN_OFF);
    size_t need = 0;
    if (dnac_txw3_encoded_size(body_len, &need) != 0) return -1; /* over cap */
    if (src_len != need) return -1;   /* truncated OR trailing garbage */

    memset(hdr, 0, sizeof(*hdr));
    hdr->wire_version      = src[0];
    hdr->tx_type           = src[1];
    hdr->domain_id         = get_be32(src + 2);
    hdr->pool_id           = get_be32(src + 6);
    hdr->ruleset_version   = get_be32(src + 10);
    hdr->statement_version = get_be32(src + 14);
    hdr->expiry_height     = get_be64(src + 18);
    hdr->committed_fee     = get_be64(src + 26);
    hdr->timestamp         = get_be64(src + 34);
    memcpy(hdr->tx_hash, src + DNAC_TXW3_TXHASH_OFF, DNAC_TXW_HASH_LEN);

    *body_out     = (body_len != 0) ? src + DNAC_TXW3_BODY_OFF : NULL;
    *body_len_out = body_len;
    return 0;
}

int dnac_txw3_tx_hash(const dnac_txw3_header_t *hdr,
                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                      const uint8_t *body, uint32_t body_len,
                      uint8_t hash_out[DNAC_TXW_HASH_LEN]) {
    if (!hdr || !chain_id || !hash_out) return -1;
    if (!body && body_len != 0) return -1;
    if (body_len > DNAC_TXW3_MAX_BODY_LEN) return -1;

    /* Preimage: tag(16) ‖ chain_id(32) ‖ prefix(42) ‖ body_len(4 BE) ‖ body.
     * The prefix bytes are produced by the SAME serializer the wire encode
     * uses, so wire form and preimage cannot drift. */
    uint8_t fixed[16 + DNA_CHAIN_ID_LEN + 42 + 4];
    memcpy(fixed, DNAC_TXW_V5_TAG, 16);
    memcpy(fixed + 16, chain_id, DNA_CHAIN_ID_LEN);
    if (txw3_put_prefix(hdr, fixed + 16 + DNA_CHAIN_ID_LEN) != 0) return -1;
    put_be32(body_len, fixed + 16 + DNA_CHAIN_ID_LEN + 42);

    size_t pre_len = sizeof(fixed) + (size_t)body_len;
    uint8_t *pre = (uint8_t *)malloc(pre_len);
    if (!pre) return -1;
    memcpy(pre, fixed, sizeof(fixed));
    if (body_len)
        memcpy(pre + sizeof(fixed), body, body_len);

    int rc = qgp_sha3_512(pre, pre_len, hash_out);
    /* Transaction material hygiene: wipe the temporary preimage. */
    memset(pre, 0, pre_len);
    free(pre);
    return (rc == 0) ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * 3. Legacy (V2/V4) tx-hash — the ONE preimage implementation
 *
 * Exact port of nodus_witness_recompute_tx_hash (nodus_witness_verify.c,
 * pre-S1). Every bound, order, endianness conversion, and fail path is
 * preserved; byte identity is pinned by test_tx_hash_kat +
 * test_witness_tx_hash_parity (independent third implementation).
 * ════════════════════════════════════════════════════════════════════ */

/* Legacy preimage domain tags (mirror dnac/include/dnac/transaction.h
 * DNAC_TX_PREIMAGE_DOMAIN_V2/V4 — 11 bytes each incl. the NUL). */
static const uint8_t TXW_TAG_V2[11] = {'D','N','A','C','_','T','X','_','V','2',0};
static const uint8_t TXW_TAG_V4[11] = {'D','N','A','C','_','T','X','_','V','4',0};

/* Wire section sizes (mirrors; pinned by consumer-side _Static_asserts). */
#define TXW_INPUT_SIZE      (DNAC_TXW_NULLIFIER_LEN + 8 + DNAC_TXW_TOKEN_ID_LEN) /* 136 */
#define TXW_OUTPUT_FIXED    (1 + DNAC_TXW_FP_LEN + 8 + DNAC_TXW_TOKEN_ID_LEN + \
                             DNAC_TXW_SEED_LEN + 1)                              /* 235 */
#define TXW_WITNESS_SIZE    (32 + DNAC_TXW_SIG_LEN + 8 + DNAC_TXW_PK_LEN)        /* 7259 */
#define TXW_SIGNER_SIZE     (DNAC_TXW_PK_LEN + DNAC_TXW_SIG_LEN)                 /* 7219 */
#define TXW_CC_VOTE_BOUND   DNAC_TXW_CC_VOTE_BOUND
#define TXW_CC_FIXED        DNAC_TXW_CC_FIXED                                    /* 42 */
#define TXW_CC_PER_VOTE     (32 + DNAC_TXW_SIG_LEN)                              /* 4659 */
#define TXW_SHIELDED_FIXED  DNAC_TXW_SHIELDED_FIXED                              /* 334 */
#define TXW_SHIELDED_STMT   (TXW_SHIELDED_FIXED - 4)                             /* 330 */

/* Legacy tx type codes used by the walk (mirror dnac_tx_type_t). */
#define TXW_T_STAKE             4
#define TXW_T_DELEGATE          5
#define TXW_T_UNDELEGATE        7
#define TXW_T_VALIDATOR_UPDATE  9
#define TXW_T_CHAIN_CONFIG      10

int dnac_txw_legacy_tx_hash(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                            const uint8_t *tx_data, size_t tx_len,
                            const uint8_t *signer_pubkeys,
                            uint8_t signer_count,
                            uint8_t hash_out[DNAC_TXW_HASH_LEN]) {
    if (!chain_id || !tx_data || !hash_out ||
        tx_len < (size_t)DNAC_TXW_LEGACY_HEADER + 1)
        return -1;
    if (!signer_pubkeys && signer_count > 0)
        return -1;
    if (signer_count > DNAC_TXW_MAX_SIGNERS)
        return -1;
    /* Checked upper bound for the preimage buffer (original formula:
     * tx_len + chain_id + count byte + max signer pubkeys + tx_len). */
    if (tx_len > (SIZE_MAX / 2) - (DNA_CHAIN_ID_LEN + 1 +
                  (size_t)DNAC_TXW_MAX_SIGNERS * DNAC_TXW_PK_LEN))
        return -1;
    size_t upper = tx_len + DNA_CHAIN_ID_LEN + 1
                 + (size_t)DNAC_TXW_MAX_SIGNERS * DNAC_TXW_PK_LEN
                 + tx_len;
    uint8_t *buf = (uint8_t *)malloc(upper);
    if (!buf) return -1;

    size_t buf_pos = 0;
    const uint8_t *p = tx_data;
    size_t remaining = tx_len;

    /* ── Domain separator: type-11 hashes under its own V4 tag. ─────── */
    if (tx_data[1] == DNAC_TXW_TYPE_SHIELDED) {
        memcpy(buf + buf_pos, TXW_TAG_V4, sizeof(TXW_TAG_V4));
        buf_pos += sizeof(TXW_TAG_V4);
    } else {
        memcpy(buf + buf_pos, TXW_TAG_V2, sizeof(TXW_TAG_V2));
        buf_pos += sizeof(TXW_TAG_V2);
    }

    /* ── Header: version ‖ type ‖ timestamp(BE) ‖ chain_id[32] ───────── */
    if (remaining < 10) goto fail;
    uint8_t version_byte = p[0];
    uint8_t type_byte    = p[1];
    uint64_t timestamp   = legacy_le64(p + 2);
    p += 10;
    remaining -= 10;

    buf[buf_pos++] = version_byte;
    buf[buf_pos++] = type_byte;
    put_be64(timestamp, buf + buf_pos);
    buf_pos += 8;
    memcpy(buf + buf_pos, chain_id, DNA_CHAIN_ID_LEN);
    buf_pos += DNA_CHAIN_ID_LEN;

    /* Skip the embedded tx_hash (64 bytes). */
    if (remaining < 64) goto fail;
    p += 64;
    remaining -= 64;

    /* ── committed_fee (u64 BE on wire) → preimage BE ────────────────── */
    if (remaining < 8) goto fail;
    {
        uint64_t committed_fee = get_be64(p);
        put_be64(committed_fee, buf + buf_pos);
        buf_pos += 8;
        p += 8;
        remaining -= 8;
    }

    /* ── Inputs: nullifier(64) ‖ amount(u64 BE) ‖ token_id(64) ───────── */
    if (remaining < 1) goto fail;
    uint8_t input_count = *p++;
    remaining--;
    if (input_count > DNAC_TXW_MAX_INPUTS) goto fail;

    for (int i = 0; i < input_count; i++) {
        if (remaining < (size_t)TXW_INPUT_SIZE) goto fail;
        memcpy(buf + buf_pos, p, DNAC_TXW_NULLIFIER_LEN);
        buf_pos += DNAC_TXW_NULLIFIER_LEN;
        put_be64(legacy_le64(p + DNAC_TXW_NULLIFIER_LEN), buf + buf_pos);
        buf_pos += 8;
        memcpy(buf + buf_pos, p + DNAC_TXW_NULLIFIER_LEN + 8,
               DNAC_TXW_TOKEN_ID_LEN);
        buf_pos += DNAC_TXW_TOKEN_ID_LEN;
        p += TXW_INPUT_SIZE;
        remaining -= TXW_INPUT_SIZE;
    }

    /* ── Outputs: version ‖ fp(129) ‖ amount(BE) ‖ token_id ‖ seed ‖
     *            memo_len ‖ memo ─────────────────────────────────────── */
    if (remaining < 1) goto fail;
    uint8_t output_count = *p++;
    remaining--;
    if (output_count > DNAC_TXW_MAX_OUTPUTS) goto fail;

    for (int i = 0; i < output_count; i++) {
        if (remaining < (size_t)TXW_OUTPUT_FIXED) goto fail;
        uint8_t memo_len = p[TXW_OUTPUT_FIXED - 1];
        size_t output_total = (size_t)TXW_OUTPUT_FIXED + memo_len;
        if (remaining < output_total) goto fail;

        buf[buf_pos++] = p[0];                                 /* version */
        memcpy(buf + buf_pos, p + 1, DNAC_TXW_FP_LEN);         /* fp */
        buf_pos += DNAC_TXW_FP_LEN;
        put_be64(legacy_le64(p + 1 + DNAC_TXW_FP_LEN), buf + buf_pos);
        buf_pos += 8;
        memcpy(buf + buf_pos, p + 1 + DNAC_TXW_FP_LEN + 8,
               DNAC_TXW_TOKEN_ID_LEN + DNAC_TXW_SEED_LEN);     /* token+seed */
        buf_pos += DNAC_TXW_TOKEN_ID_LEN + DNAC_TXW_SEED_LEN;
        buf[buf_pos++] = memo_len;
        if (memo_len > 0) {
            memcpy(buf + buf_pos, p + TXW_OUTPUT_FIXED, memo_len);
            buf_pos += memo_len;
        }
        p += output_total;
        remaining -= output_total;
    }

    /* ── Signers into the preimage: count ‖ caller-supplied pubkeys ──── */
    buf[buf_pos++] = signer_count;
    for (int i = 0; i < signer_count; i++) {
        memcpy(buf + buf_pos,
               signer_pubkeys + (size_t)i * DNAC_TXW_PK_LEN,
               DNAC_TXW_PK_LEN);
        buf_pos += DNAC_TXW_PK_LEN;
    }

    /* ── Wire cursor: skip witnesses + signers to reach the type tail ── */
    if (remaining < 1) goto fail;
    {
        uint8_t witness_count = *p++;
        remaining--;
        size_t witnesses_total = (size_t)witness_count * TXW_WITNESS_SIZE;
        if (remaining < witnesses_total) goto fail;
        p += witnesses_total;
        remaining -= witnesses_total;
    }
    if (remaining < 1) goto fail;
    {
        uint8_t wire_signer_count = *p++;
        remaining--;
        if (wire_signer_count > DNAC_TXW_MAX_SIGNERS) goto fail;
        size_t signers_total = (size_t)wire_signer_count * TXW_SIGNER_SIZE;
        if (remaining < signers_total) goto fail;
        p += signers_total;
        remaining -= signers_total;
    }

    /* ── Type-specific appended fields (BE on wire → verbatim copy) ──── */
    if (type_byte == TXW_T_STAKE) {
        size_t need = DNAC_TXW_STAKE_TAIL;   /* commission ‖ dest_fp ‖ tag */
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need; p += need; remaining -= need;
    } else if (type_byte == TXW_T_DELEGATE || type_byte == TXW_T_UNDELEGATE) {
        size_t need = (size_t)DNAC_TXW_PK_LEN + 8;
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need; p += need; remaining -= need;
    } else if (type_byte == TXW_T_VALIDATOR_UPDATE) {
        size_t need = 2 + 8;
        if (remaining < need) goto fail;
        memcpy(buf + buf_pos, p, need);
        buf_pos += need; p += need; remaining -= need;
    } else if (type_byte == TXW_T_CHAIN_CONFIG) {
        size_t fixed = TXW_CC_FIXED;
        if (remaining < fixed) goto fail;
        memcpy(buf + buf_pos, p, fixed);
        buf_pos += fixed;
        uint8_t cc_sig_count = p[fixed - 1];
        p += fixed;
        remaining -= fixed;
        if (cc_sig_count > TXW_CC_VOTE_BOUND) goto fail;
        size_t votes_total = (size_t)cc_sig_count * TXW_CC_PER_VOTE;
        if (remaining < votes_total) goto fail;
        if (votes_total > 0) {
            memcpy(buf + buf_pos, p, votes_total);
            buf_pos += votes_total;
            p += votes_total;
            remaining -= votes_total;
        }
    } else if (type_byte == DNAC_TXW_TYPE_SHIELDED) {
        /* Statement bytes hashed verbatim; fri_proof_len + blob excluded
         * (a re-randomized proof of the same statement is the same TX),
         * but the blob bounds are still enforced (fail-close on a
         * truncated shielded wire). */
        if (remaining < (size_t)TXW_SHIELDED_FIXED) goto fail;
        memcpy(buf + buf_pos, p, TXW_SHIELDED_STMT);
        buf_pos += TXW_SHIELDED_STMT;
        uint32_t fri_len = get_be32(p + TXW_SHIELDED_STMT);
        p += TXW_SHIELDED_FIXED;
        remaining -= TXW_SHIELDED_FIXED;
        if (remaining < fri_len) goto fail;
        p += fri_len;
        remaining -= fri_len;
    }
    /* UNSTAKE / GENESIS / SPEND / BURN / TOKEN_CREATE: no appended fields.
     * Trailing bytes (the genesis chain_def trailer) are ignored — they are
     * not part of the preimage, exactly as before. */

    (void)version_byte;

    if (qgp_sha3_512(buf, buf_pos, hash_out) != 0) goto fail;
    memset(buf, 0, buf_pos);   /* transaction-material hygiene */
    free(buf);
    return 0;

fail:
    memset(buf, 0, buf_pos);
    free(buf);
    return -1;
}
