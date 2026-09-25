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
     * not part of the preimage, exactly as before.
     *
     * There is deliberately NO terminal `else` that rejects: this chain is a
     * HASH WALKER, not an admission gate. Any type byte without a branch —
     * the no-appended-field types above, and equally every UNASSIGNED byte
     * (14, 15, 16 and 17..255) — hashes header ‖ inputs ‖ outputs ‖ signers
     * and ignores whatever trails it. Adding a reject here would break the
     * legitimate no-appended-field types, so admission is NOT this function's
     * job: the acceptance set is enforced by the callers (the dnac
     * deserializer's `type > 11` gate and the witness's named rejects).
     * O15J removed the type 15/16 branches, which returns those two bytes to
     * this same unassigned treatment; types 0..11 are untouched. */

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

/* ══════════════════════════════════════════════════════════════════════
 * 4. V3 shielded body codec (Season 8) + 5. sighash_v5
 *
 * INACTIVE: nothing live reaches either. The legacy section above is
 * untouched — the frozen 334-byte V2 shielded section and its V4 tag
 * keep their exact pre-S8 behavior, and no generic §1/§2 helper grew a
 * transaction-type branch. Layouts: tx_wire.h §4/§5.
 * ════════════════════════════════════════════════════════════════════ */

/* Preimage/section arithmetic is pinned, not assumed. */
_Static_assert(DNAC_TXW3_SHIELDED_FIXED ==
                   1 + 32 + 1 + 128 + 1 + 128 + 8 + 8 + 8 + 8 + 32 + 4,
               "V3 shielded section layout drifted from 359 bytes");
_Static_assert(DNAC_TXW3_SHIELDED_FIXED == 359,
               "V3 shielded section length drifted");
_Static_assert(DNAC_SIGHASH_V5_PREIMAGE_LEN == 581,
               "sighash_v5 preimage length drifted from 581 bytes");
/* The lane counts the 32/128-byte spans above encode. */
_Static_assert(DNAC_TXW3_SHIELDED_LANES == 4 &&
                   DNAC_TXW3_SHIELDED_MAX_INPUTS == 4 &&
                   DNAC_TXW3_SHIELDED_MAX_OUTPUTS == 4,
               "shielded lane/slot mirrors drifted from the AIR bounds");
/* The legacy section stays frozen alongside — a change to either constant
 * must be a deliberate, visible break, never a silent one. */
_Static_assert(DNAC_TXW_SHIELDED_FIXED == 334,
               "frozen legacy shielded section size moved");

/** Goldilocks modulus. Mirrors GOLDILOCKS_P
 *  (shared/crypto/zk/field_goldilocks.h) and DNA_POOL_FE_P
 *  (shared/dnac/pool_wire.h:133); kept local so this translation unit
 *  stays include-free of both trees. */
#define TXW3_FE_P            ((uint64_t)0xFFFFFFFF00000001ULL)
/** FROZEN verifier-side bound on the transparent-leg boundary amounts:
 *  both MUST be < 2^63, so every downstream signed sum stays in range. */
#define TXW3_BOUNDARY_BOUND  ((uint64_t)1 << 63)
/** fri_len offset inside the fixed section (= 355, the last 4 bytes). */
#define TXW3_SECT_FRILEN_OFF (DNAC_TXW3_SHIELDED_FIXED - 4)
_Static_assert(TXW3_SECT_FRILEN_OFF == 355, "fri_len offset drifted");

/* S2 tagged-empty commitments — the tag ALONE is hashed (never an
 * all-zero digest, which no tag can produce). Each tag is EXACTLY 16
 * bytes, zero-padded ASCII, same rule as pool_wire.c. */
static const uint8_t TAG_E_TLEG[DNAC_SIGHASH_V5_TAG_LEN] = "DNA.E.TLEG.v1\0\0";
static const uint8_t TAG_E_CTC[DNAC_SIGHASH_V5_TAG_LEN]  = "DNA.E.CTC.v1\0\0\0";

const uint8_t DNAC_SIGHASH_V5_TAG[DNAC_SIGHASH_V5_TAG_LEN] = {
    'D','N','A','C','_','S','I','G','H','A','S','H','_','V','5', 0
};

/* Write 4 Goldilocks lanes as 32 bytes, u64 BE per lane. */
static void txw3_put_lanes(const uint64_t lanes[DNAC_TXW3_SHIELDED_LANES],
                           uint8_t *out) {
    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
        put_be64(lanes[j], out + (size_t)j * 8);
}

/* Read 4 Goldilocks lanes from 32 bytes, u64 BE per lane. */
static void txw3_get_lanes(const uint8_t *in,
                           uint64_t lanes[DNAC_TXW3_SHIELDED_LANES]) {
    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
        lanes[j] = get_be64(in + (size_t)j * 8);
}

/**
 * Canonicality rules shared by sighash_v5 and the section codec — the
 * statement fields that appear in BOTH the preimage and the wire, in the
 * order tx_wire.h documents them:
 *   counts ≤ 4 · anchor/nf_set/output_commit lanes < p · unused slots
 *   all-zero · boundary_in/out < 2^63.
 * @return 0 / -1.
 */
static int txw3_stmt_common_ok(const dnac_txw3_shielded_t *st) {
    if (st->num_input  > DNAC_TXW3_SHIELDED_MAX_INPUTS)  return -1;
    if (st->num_output > DNAC_TXW3_SHIELDED_MAX_OUTPUTS) return -1;

    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
        if (st->anchor[j] >= TXW3_FE_P) return -1;

    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++) {
            if (st->nf_set[s][j] >= TXW3_FE_P) return -1;
            if (s >= (unsigned)st->num_input && st->nf_set[s][j] != 0)
                return -1;
        }

    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++) {
            if (st->output_commit[s][j] >= TXW3_FE_P) return -1;
            if (s >= (unsigned)st->num_output && st->output_commit[s][j] != 0)
                return -1;
        }

    if (st->boundary_in  >= TXW3_BOUNDARY_BOUND) return -1;
    if (st->boundary_out >= TXW3_BOUNDARY_BOUND) return -1;
    return 0;
}

/**
 * Full section canonicality — the shared rules PLUS the wire-only ones.
 * The complete ordered reject list (encode and decode run the identical
 * sequence, so a section that decodes always re-encodes byte-identically
 * and one that would not is never emitted):
 *   1. sect_version != 2
 *   2. num_input > 4 / num_output > 4        (txw3_stmt_common_ok)
 *   3. anchor/nf_set/output_commit lane ≥ p  (txw3_stmt_common_ok)
 *   4. nonzero lane in an unused slot        (txw3_stmt_common_ok)
 *   5. boundary_in ≥ 2^63 / boundary_out ≥ 2^63 (txw3_stmt_common_ok)
 *   6. tx_binding lane ≥ p
 *   7. num_input == 0 with a nonzero anchor lane
 *   8. fri_len == 0
 * num_input == 0 is LEGAL (the shield case) and is never a reject on its
 * own — only a zero-input statement carrying a nonzero anchor is.
 * @return 0 / -1.
 */
static int txw3_section_ok(const dnac_txw3_shielded_t *st) {
    if (st->sect_version != DNAC_TXW3_SECT_VERSION) return -1;
    if (txw3_stmt_common_ok(st) != 0) return -1;

    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
        if (st->tx_binding[j] >= TXW3_FE_P) return -1;

    /* FROZEN: a zero-input statement proves no membership, so it carries
     * no anchor — the all-zero anchor is the only canonical form. */
    if (st->num_input == 0)
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
            if (st->anchor[j] != 0) return -1;

    if (st->fri_len == 0) return -1;
    return 0;
}

int dnac_txw3_shielded_encode(const dnac_txw3_shielded_t *st,
                              const uint8_t *fri, uint32_t fri_len,
                              uint8_t *dst, size_t dst_cap,
                              size_t *written_out) {
    if (!st || !fri || !dst || !written_out) return -1;
    /* The struct's fri_len and the passed length are two statements of
     * one fact: a disagreement rejects, neither side silently wins. */
    if (fri_len != st->fri_len) return -1;
    if (txw3_section_ok(st) != 0) return -1;   /* covers fri_len == 0 */

    /* Checked arithmetic, same shape as dnac_txw3_encoded_size. */
    size_t fixed = (size_t)DNAC_TXW3_SHIELDED_FIXED;
    if (fri_len > SIZE_MAX - fixed) return -1;
    size_t need = fixed + (size_t)fri_len;
    if (dst_cap < need) return -1;

    uint8_t *p = dst;
    *p++ = st->sect_version;                            /* off   0 */
    txw3_put_lanes(st->anchor, p);           p += 32;   /* off   1 */
    *p++ = st->num_input;                               /* off  33 */
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++) {
        txw3_put_lanes(st->nf_set[s], p);    p += 32;   /* off  34 */
    }
    *p++ = st->num_output;                              /* off 162 */
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++) {
        txw3_put_lanes(st->output_commit[s], p); p += 32; /* off 163 */
    }
    put_be64(st->fee, p);                    p += 8;    /* off 291 */
    put_be64(st->boundary_in, p);            p += 8;    /* off 299 */
    put_be64(st->boundary_out, p);           p += 8;    /* off 307 */
    put_be64(st->expiry_height, p);          p += 8;    /* off 315 */
    txw3_put_lanes(st->tx_binding, p);       p += 32;   /* off 323 */
    put_be32(fri_len, p);                    p += 4;    /* off 355 */
    /* final-offset proof: the fixed section is EXACTLY 359 bytes — a
     * drifted field width cannot be emitted silently */
    if ((size_t)(p - dst) != (size_t)DNAC_TXW3_SHIELDED_FIXED) return -1;

    memcpy(dst + DNAC_TXW3_SHIELDED_FIXED, fri, fri_len); /* off 359 */
    *written_out = need;
    return 0;
}

int dnac_txw3_shielded_decode(const uint8_t *body, uint32_t body_len,
                              dnac_txw3_shielded_t *out,
                              const uint8_t **fri_out, uint32_t *fri_len_out) {
    /* Fail closed FIRST (S9 W2 repair, widened by the O6 verifier's C5):
     * the header promises "on ANY rejection *out is zeroed". The length
     * rejects below used to return with *out untouched, and the NULL-argument
     * check used to run BEFORE the memset — so a call with a valid `out` but
     * a NULL `fri_out`/`fri_len_out` also left stale statement fields behind.
     * `out` is now NULL-checked on its own, zeroed immediately, and only then
     * are the remaining arguments judged: every reject below this point,
     * including the NULL-argument one, leaves *out zeroed. */
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!body || !fri_out || !fri_len_out) return -1;
    if (body_len < (uint32_t)DNAC_TXW3_SHIELDED_FIXED) return -1;  /* short */

    uint32_t fri_len = get_be32(body + TXW3_SECT_FRILEN_OFF);   /* off 355 */
    /* Subtraction (never 359 + fri_len) so the length equality cannot be
     * defeated by a wrapping u32: truncated AND trailing-byte bodies both
     * fail here. */
    if (body_len - (uint32_t)DNAC_TXW3_SHIELDED_FIXED != fri_len) return -1;

    const uint8_t *p = body;
    out->sect_version = *p++;                            /* off   0 */
    txw3_get_lanes(p, out->anchor);          p += 32;    /* off   1 */
    out->num_input = *p++;                               /* off  33 */
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++) {
        txw3_get_lanes(p, out->nf_set[s]);   p += 32;    /* off  34 */
    }
    out->num_output = *p++;                              /* off 162 */
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++) {
        txw3_get_lanes(p, out->output_commit[s]); p += 32; /* off 163 */
    }
    out->fee           = get_be64(p);        p += 8;     /* off 291 */
    out->boundary_in   = get_be64(p);        p += 8;     /* off 299 */
    out->boundary_out  = get_be64(p);        p += 8;     /* off 307 */
    out->expiry_height = get_be64(p);        p += 8;     /* off 315 */
    txw3_get_lanes(p, out->tx_binding);      p += 32;    /* off 323 */
    out->fri_len       = get_be32(p);        p += 4;     /* off 355 */

    if ((size_t)(p - body) != (size_t)DNAC_TXW3_SHIELDED_FIXED ||
        txw3_section_ok(out) != 0) {
        memset(out, 0, sizeof(*out));                    /* fail closed */
        return -1;
    }

    *fri_out     = body + DNAC_TXW3_SHIELDED_FIXED;      /* off 359 */
    *fri_len_out = fri_len;
    return 0;
}

int dnac_txw3_shielded_check_header(const dnac_txw3_header_t *hdr,
                                    const dnac_txw3_shielded_t *st) {
    /* One-way: the HEADER is authoritative for both numbers (tx_wire.h
     * §4 "Field authority"). A mismatch rejects; the section's mirrors
     * never override the header. */
    if (!hdr || !st) return -1;
    if (hdr->committed_fee != st->fee) return -1;
    if (hdr->expiry_height != st->expiry_height) return -1;
    return 0;
}

int dnac_sighash_v5(const dna_exec_context_t *ctx, uint8_t sect_version,
                    const uint8_t ruleset_hash[DNAC_TXW_HASH_LEN],
                    const dnac_txw3_shielded_t *st,
                    const uint8_t tleg_commit[DNAC_TXW_HASH_LEN],
                    const uint8_t ct_commit[DNAC_TXW_HASH_LEN],
                    uint8_t out_sighash[DNAC_TXW_HASH_LEN]) {
    if (!ctx || !ruleset_hash || !st || !tleg_commit || !ct_commit ||
        !out_sighash)
        return -1;
    if (dna_exec_context_validate(ctx) != 0) return -1;
    if (txw3_stmt_common_ok(st) != 0) return -1;

    uint8_t pre[DNAC_SIGHASH_V5_PREIMAGE_LEN];
    uint8_t *p = pre;
    memcpy(p, DNAC_SIGHASH_V5_TAG, DNAC_SIGHASH_V5_TAG_LEN);       /* off   0 */
    p += DNAC_SIGHASH_V5_TAG_LEN;
    /* The ONE ExecutionContext encoder (§1) — domain, pool and chain all
     * arrive from the caller's context; nothing is hardcoded here. */
    if (dna_exec_context_encode(ctx, p) != 0) return -1;           /* off  16 */
    p += DNA_EXEC_CTX_WIRE_LEN;
    *p++ = sect_version;                                           /* off  66 */
    memcpy(p, ruleset_hash, DNAC_TXW_HASH_LEN);
    p += DNAC_TXW_HASH_LEN;                                        /* off  67 */
    txw3_put_lanes(st->anchor, p);            p += 32;             /* off 131 */
    *p++ = st->num_input;                                          /* off 163 */
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++) {
        txw3_put_lanes(st->nf_set[s], p);     p += 32;             /* off 164 */
    }
    *p++ = st->num_output;                                         /* off 292 */
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++) {
        txw3_put_lanes(st->output_commit[s], p); p += 32;          /* off 293 */
    }
    /* NOTE the order: the preimage carries boundary_in ‖ boundary_out ‖
     * fee, the wire section carries fee first. Both are frozen. */
    put_be64(st->boundary_in, p);             p += 8;              /* off 421 */
    put_be64(st->boundary_out, p);            p += 8;              /* off 429 */
    put_be64(st->fee, p);                     p += 8;              /* off 437 */
    put_be64(st->expiry_height, p);           p += 8;              /* off 445 */
    memcpy(p, tleg_commit, DNAC_TXW_HASH_LEN);
    p += DNAC_TXW_HASH_LEN;                                        /* off 453 */
    memcpy(p, ct_commit, DNAC_TXW_HASH_LEN);
    p += DNAC_TXW_HASH_LEN;                                        /* off 517 */
    /* final-offset proof: the bytes written are EXACTLY the declared
     * 581-byte preimage — a drifted field width cannot hash silently */
    if ((size_t)(p - pre) != (size_t)DNAC_SIGHASH_V5_PREIMAGE_LEN) return -1;

    return qgp_sha3_512(pre, DNAC_SIGHASH_V5_PREIMAGE_LEN, out_sighash) == 0
               ? 0 : -1;
}

int dnac_tleg_commit_empty(uint8_t out[DNAC_TXW_HASH_LEN]) {
    if (!out) return -1;
    return qgp_sha3_512(TAG_E_TLEG, DNAC_SIGHASH_V5_TAG_LEN, out) == 0
               ? 0 : -1;
}

int dnac_ct_commit_empty(uint8_t out[DNAC_TXW_HASH_LEN]) {
    if (!out) return -1;
    return qgp_sha3_512(TAG_E_CTC, DNAC_SIGHASH_V5_TAG_LEN, out) == 0
               ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * 6. Transparent-leg section v1 + its commitment (Season 9 — INACTIVE)
 *
 * Layout, canonicality and the commitment preimage: tx_wire.h §6. Nothing
 * above this point moved for S9 except the fail-close repair inside
 * dnac_txw3_shielded_decode (the memset now runs before the first reject);
 * the §4 layout and the §5 preimage are byte-unchanged.
 *
 * POLICY-NEUTRAL by construction: not one function below reads a
 * transaction type, domain or pool. Per-type count windows are native
 * rules and are enforced by the type-specific caller, never here.
 *
 * This block lives at the END of the file DELIBERATELY: growing prose or
 * code above shifts every `tx_wire.c:NNN` citation in the tests and design
 * docs and silently staleness them. New sections append.
 * ════════════════════════════════════════════════════════════════════ */

/* Leg arithmetic is pinned, not assumed. */
_Static_assert(DNAC_TXW3_TLEG_TOUT_LEN == 169,
               "transparent output size drifted from fp+amount+seed = 169");
/* Identical to the legacy signers section's pair (TXW_SIGNER_SIZE,
 * tx_wire.c:269) — deliberately the same Dilithium5 material. */
_Static_assert(DNAC_TXW3_TLEG_SIGNER_LEN == 7219,
               "transparent signer size drifted from pubkey+signature = 7219");
_Static_assert(DNAC_TXW3_TLEG_FIXED == 1 + 1 + 1 + 1,
               "leg overhead drifted from version + three count bytes");
_Static_assert(DNAC_TXW3_TLEG_MAX_LEN == 32608,
               "worst-case leg length drifted from 4+1024+2704+28876");
/* The structural caps are what bound every length sum below by
 * DNAC_TXW3_TLEG_MAX_LEN, so none of them can overflow. A worst-case leg
 * must additionally still leave room for the §4 section inside a V3 body —
 * if this ever fails, no 12/13 transaction could be framed at all. */
_Static_assert(DNAC_TXW3_TLEG_MAX_LEN + DNAC_TXW3_SHIELDED_FIXED
                   < DNAC_TXW3_MAX_BODY_LEN,
               "worst-case leg + shielded section no longer fits a V3 body");

/* POPULATED transparent-leg tag — EXACTLY 16 bytes, zero-padded ASCII,
 * same rule as TAG_E_TLEG (tx_wire.c:535). The two are DISTINCT domains:
 * "DNA.E.TLEG.v1" commits the ABSENCE of a leg, "DNA.TLEG.v1" commits a
 * present one, so no leg can ever collide with the empty commitment. */
static const uint8_t TAG_TLEG[DNAC_SIGHASH_V5_TAG_LEN] = "DNA.TLEG.v1\0\0\0\0";

/**
 * The ONE transparent-leg canonicality rule list — encode, decode and the
 * commitment all run it, so the three can never disagree about which legs
 * exist. Ordered exactly as tx_wire.h §6 documents:
 *   1. tleg_version != 1
 *   2. num_tin > 16 / num_tout > 16 / num_signers > 4   (structural caps)
 *   3. input nullifiers not STRICTLY ascending (memcmp) — this single
 *      comparison rejects both a mis-ordered set and an in-leg duplicate
 *   4. an output with amount == 0
 * Deliberately ABSENT: any per-type count window (native-layer rule) and
 * any judgment of slots at or beyond a count (they are not on the wire).
 * @return 0 / -1.
 */
static int txw3_tleg_ok(const dnac_txw3_tleg_t *t) {
    if (t->tleg_version != DNAC_TXW3_TLEG_VERSION) return -1;
    if (t->num_tin     > DNAC_TXW_MAX_INPUTS)      return -1;
    if (t->num_tout    > DNAC_TXW_MAX_OUTPUTS)     return -1;
    if (t->num_signers > DNAC_TXW_MAX_SIGNERS)     return -1;

    for (unsigned i = 1; i < (unsigned)t->num_tin; i++)
        if (memcmp(t->tin_nullifier[i - 1], t->tin_nullifier[i],
                   DNAC_TXW_NULLIFIER_LEN) >= 0)
            return -1;   /* equal (duplicate) or descending */

    for (unsigned i = 0; i < (unsigned)t->num_tout; i++)
        if (t->tout[i].amount == 0) return -1;

    return 0;
}

int dnac_txw3_tleg_encoded_size(uint8_t num_tin, uint8_t num_tout,
                                uint8_t num_signers, size_t *out) {
    if (!out) return -1;
    *out = 0;   /* no stale length survives a reject */
    if (num_tin     > DNAC_TXW_MAX_INPUTS)  return -1;
    if (num_tout    > DNAC_TXW_MAX_OUTPUTS) return -1;
    if (num_signers > DNAC_TXW_MAX_SIGNERS) return -1;
    /* Bounded by DNAC_TXW3_TLEG_MAX_LEN (32608) by the caps just checked —
     * the _Static_asserts above are what make this addition safe. */
    *out = (size_t)DNAC_TXW3_TLEG_FIXED
         + (size_t)num_tin     * DNAC_TXW_NULLIFIER_LEN
         + (size_t)num_tout    * DNAC_TXW3_TLEG_TOUT_LEN
         + (size_t)num_signers * DNAC_TXW3_TLEG_SIGNER_LEN;
    return 0;
}

int dnac_txw3_tleg_encode(const dnac_txw3_tleg_t *t,
                          uint8_t *dst, size_t dst_cap, size_t *written_out) {
    if (!t || !dst || !written_out) return -1;
    if (txw3_tleg_ok(t) != 0) return -1;   /* never emit a non-canonical leg */

    size_t need = 0;
    if (dnac_txw3_tleg_encoded_size(t->num_tin, t->num_tout, t->num_signers,
                                    &need) != 0)
        return -1;
    if (dst_cap < need) return -1;

    uint8_t *p = dst;
    *p++ = t->tleg_version;                                    /* off 0 */
    *p++ = t->num_tin;                                         /* off 1 */
    for (unsigned i = 0; i < (unsigned)t->num_tin; i++) {      /* off 2 */
        memcpy(p, t->tin_nullifier[i], DNAC_TXW_NULLIFIER_LEN);
        p += DNAC_TXW_NULLIFIER_LEN;
    }
    *p++ = t->num_tout;
    for (unsigned i = 0; i < (unsigned)t->num_tout; i++) {
        memcpy(p, t->tout[i].fp, DNAC_TXW_FP_LEN);   p += DNAC_TXW_FP_LEN;
        put_be64(t->tout[i].amount, p);              p += 8;
        memcpy(p, t->tout[i].nullifier_seed, DNAC_TXW_SEED_LEN);
        p += DNAC_TXW_SEED_LEN;
    }
    *p++ = t->num_signers;
    for (unsigned i = 0; i < (unsigned)t->num_signers; i++) {
        memcpy(p, t->signer[i].pubkey, DNAC_TXW_PK_LEN);  p += DNAC_TXW_PK_LEN;
        memcpy(p, t->signer[i].signature, DNAC_TXW_SIG_LEN);
        p += DNAC_TXW_SIG_LEN;
    }
    /* final-offset proof: the walk landed EXACTLY on the length the three
     * counts predict — a drifted field width cannot be emitted silently */
    if ((size_t)(p - dst) != need) return -1;

    *written_out = need;
    return 0;
}

int dnac_txw3_tleg_decode(const uint8_t *body, size_t body_len,
                          dnac_txw3_tleg_t *out, size_t *consumed_out) {
    /* Fail closed FIRST: every reject below leaves *out fully zeroed, so a
     * caller can never read a half-walked leg. This also zeroes the slots
     * at or beyond each count, which is what makes a decoded leg re-encode
     * byte-identically. The walk copies fields into *out as it goes, so a
     * reject discovered AFTER a copy re-zeroes through `goto fail` — a bare
     * `return -1` past this point would leave the copied prefix visible.
     * O6 verifier C5: `out` is NULL-checked ALONE and zeroed before the
     * other arguments are judged, so even a NULL `body`/`consumed_out`
     * reject honours the header's "on ANY rejection" contract. */
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!body || !consumed_out) return -1;

    /* The two leading bytes are what the whole walk is sized from. */
    if (body_len < 2) return -1;
    if (body[0] != DNAC_TXW3_TLEG_VERSION) return -1;
    uint8_t num_tin = body[1];
    if (num_tin > DNAC_TXW_MAX_INPUTS) return -1;   /* cap before indexing */

    /* Bound checks use the SUBTRACTION form (never off + need) against the
     * invariant off <= body_len, so no length arithmetic can wrap. */
    size_t off  = 2;
    size_t need = (size_t)num_tin * DNAC_TXW_NULLIFIER_LEN;
    if (body_len - off < need) return -1;
    for (unsigned i = 0; i < (unsigned)num_tin; i++)
        memcpy(out->tin_nullifier[i],
               body + off + (size_t)i * DNAC_TXW_NULLIFIER_LEN,
               DNAC_TXW_NULLIFIER_LEN);
    off += need;

    if (body_len - off < 1) goto fail;
    uint8_t num_tout = body[off++];
    if (num_tout > DNAC_TXW_MAX_OUTPUTS) goto fail;
    need = (size_t)num_tout * DNAC_TXW3_TLEG_TOUT_LEN;
    if (body_len - off < need) goto fail;
    for (unsigned i = 0; i < (unsigned)num_tout; i++) {
        const uint8_t *q = body + off + (size_t)i * DNAC_TXW3_TLEG_TOUT_LEN;
        memcpy(out->tout[i].fp, q, DNAC_TXW_FP_LEN);
        out->tout[i].amount = get_be64(q + DNAC_TXW_FP_LEN);
        memcpy(out->tout[i].nullifier_seed, q + DNAC_TXW_FP_LEN + 8,
               DNAC_TXW_SEED_LEN);
    }
    off += need;

    if (body_len - off < 1) goto fail;
    uint8_t num_signers = body[off++];
    if (num_signers > DNAC_TXW_MAX_SIGNERS) goto fail;
    need = (size_t)num_signers * DNAC_TXW3_TLEG_SIGNER_LEN;
    if (body_len - off < need) goto fail;
    for (unsigned i = 0; i < (unsigned)num_signers; i++) {
        const uint8_t *q = body + off + (size_t)i * DNAC_TXW3_TLEG_SIGNER_LEN;
        memcpy(out->signer[i].pubkey, q, DNAC_TXW_PK_LEN);
        memcpy(out->signer[i].signature, q + DNAC_TXW_PK_LEN, DNAC_TXW_SIG_LEN);
    }
    off += need;

    out->tleg_version = body[0];
    out->num_tin      = num_tin;
    out->num_tout     = num_tout;
    out->num_signers  = num_signers;

    /* Same rule list encode runs — ordering/duplicates and zero amounts are
     * only decidable once the fields are in hand. */
    size_t expect = 0;
    if (dnac_txw3_tleg_encoded_size(num_tin, num_tout, num_signers,
                                    &expect) != 0 ||
        expect != off || txw3_tleg_ok(out) != 0) {
        goto fail;
    }

    /* PREFIX decode: body_len may legitimately exceed `off` — the bytes
     * past it belong to the shielded section the caller decodes next, and
     * are neither read nor judged here (tx_wire.h §6). */
    *consumed_out = off;
    return 0;

fail:
    /* The ONE reject exit for every check that can fire after a field has
     * been copied into *out. Re-zeroing here is what makes the header's
     * "on ANY rejection *out is zeroed" true for a leg truncated in the
     * middle of its walk — the leading memset alone cannot, because the
     * nullifier/output/signer copies happen before these checks run. */
    memset(out, 0, sizeof(*out));
    return -1;
}

int dnac_tleg_commit(const dnac_txw3_tleg_t *t,
                     uint8_t out[DNAC_TXW_HASH_LEN]) {
    if (!t || !out) return -1;
    if (txw3_tleg_ok(t) != 0) return -1;   /* a non-canonical leg must not hash */

    /* Preimage (tx_wire.h §6): tag ‖ counts ‖ inputs ‖ outputs ‖ signer
     * PUBKEYS. Signatures and tleg_version are deliberately excluded.
     * Worst case 16 + 1 + 1024 + 1 + 2704 + 1 + 10368 = 14115 bytes —
     * heap, not stack, matching dnac_txw3_tx_hash (tx_wire.c:237). */
    size_t pre_len = (size_t)DNAC_SIGHASH_V5_TAG_LEN
                   + 1 + (size_t)t->num_tin     * DNAC_TXW_NULLIFIER_LEN
                   + 1 + (size_t)t->num_tout    * DNAC_TXW3_TLEG_TOUT_LEN
                   + 1 + (size_t)t->num_signers * DNAC_TXW_PK_LEN;
    uint8_t *pre = (uint8_t *)malloc(pre_len);
    if (!pre) return -1;

    uint8_t *p = pre;
    memcpy(p, TAG_TLEG, DNAC_SIGHASH_V5_TAG_LEN);
    p += DNAC_SIGHASH_V5_TAG_LEN;
    *p++ = t->num_tin;
    for (unsigned i = 0; i < (unsigned)t->num_tin; i++) {
        memcpy(p, t->tin_nullifier[i], DNAC_TXW_NULLIFIER_LEN);
        p += DNAC_TXW_NULLIFIER_LEN;
    }
    *p++ = t->num_tout;
    for (unsigned i = 0; i < (unsigned)t->num_tout; i++) {
        memcpy(p, t->tout[i].fp, DNAC_TXW_FP_LEN);   p += DNAC_TXW_FP_LEN;
        put_be64(t->tout[i].amount, p);              p += 8;
        memcpy(p, t->tout[i].nullifier_seed, DNAC_TXW_SEED_LEN);
        p += DNAC_TXW_SEED_LEN;
    }
    *p++ = t->num_signers;
    for (unsigned i = 0; i < (unsigned)t->num_signers; i++) {
        /* PUBKEY ONLY — the signature is excluded (tx_wire.h §6). */
        memcpy(p, t->signer[i].pubkey, DNAC_TXW_PK_LEN);
        p += DNAC_TXW_PK_LEN;
    }
    /* final-offset proof: the preimage is EXACTLY the declared length —
     * a drifted field width cannot hash silently */
    if ((size_t)(p - pre) != pre_len) {
        memset(pre, 0, pre_len);
        free(pre);
        return -1;
    }

    int rc = qgp_sha3_512(pre, pre_len, out);
    /* Transaction material hygiene: wipe the temporary preimage. */
    memset(pre, 0, pre_len);
    free(pre);
    return (rc == 0) ? 0 : -1;
}
