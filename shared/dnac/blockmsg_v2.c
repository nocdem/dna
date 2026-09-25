/**
 * @file shared/dnac/blockmsg_v2.c
 * @brief Ledger V2 O15B — canonical BlockMessage v1 codec.
 *
 * Layout, the one-encoding-per-block argument, and the honest label on
 * claim/pool carriage are in blockmsg_v2.h. Read that first.
 *
 * This file computes NO consensus value. It has no access to committed
 * state, no hash call, and no notion of validity beyond structure and
 * bounds. That is deliberate: every authoritative commitment is re-derived
 * by the one engine downstream and compared against what the sender
 * claimed.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "blockmsg_v2.h"

#include <stdlib.h>
#include <string.h>

/* ── Bounded cursor ───────────────────────────────────────────────────
 *
 * Every read goes through this. `need()` is the ONLY place a length is
 * compared against what is left, and it compares by SUBTRACTION on the
 * remaining count rather than by adding to the offset — `off + n` could
 * wrap on a hostile length, `left - n` cannot, because `left` is derived
 * from the real buffer size and n is checked against it first.
 */
typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         off;
} cur_t;

static int need(const cur_t *c, size_t n) {
    return (c->len - c->off) >= n;
}

static uint8_t rd_u8(cur_t *c) {
    return c->p[c->off++];
}

static uint32_t rd_u32(cur_t *c) {
    uint32_t v = ((uint32_t)c->p[c->off] << 24) |
                 ((uint32_t)c->p[c->off + 1] << 16) |
                 ((uint32_t)c->p[c->off + 2] << 8) |
                 ((uint32_t)c->p[c->off + 3]);
    c->off += 4;
    return v;
}

static uint64_t rd_u64(cur_t *c) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | c->p[c->off + (size_t)i];
    c->off += 8;
    return v;
}

static void wr_u8(uint8_t **d, uint8_t v)  { *(*d)++ = v; }

static void wr_u32(uint8_t **d, uint32_t v) {
    *(*d)++ = (uint8_t)(v >> 24); *(*d)++ = (uint8_t)(v >> 16);
    *(*d)++ = (uint8_t)(v >> 8);  *(*d)++ = (uint8_t)v;
}

static void wr_u64(uint8_t **d, uint64_t v) {
    for (int i = 7; i >= 0; i--) *(*d)++ = (uint8_t)(v >> (8 * i));
}

const char *dnac_blkmsg_v2_status_name(dnac_blkmsg_status_t s) {
    switch (s) {
    case DNAC_BLKW_OK:               return "OK";
    case DNAC_BLKW_ERR_ARG:          return "ERR_ARG";
    case DNAC_BLKW_ERR_TRUNCATED:    return "ERR_TRUNCATED";
    case DNAC_BLKW_ERR_VERSION:      return "ERR_VERSION";
    case DNAC_BLKW_ERR_BODY_VERSION: return "ERR_BODY_VERSION";
    case DNAC_BLKW_ERR_HEADER_LEN:   return "ERR_HEADER_LEN";
    case DNAC_BLKW_ERR_QC_LEN:       return "ERR_QC_LEN";
    case DNAC_BLKW_ERR_ENV_COUNT:    return "ERR_ENV_COUNT";
    case DNAC_BLKW_ERR_ENV_LEN:      return "ERR_ENV_LEN";
    case DNAC_BLKW_ERR_UNSUPPORTED:  return "ERR_UNSUPPORTED";
    case DNAC_BLKW_ERR_TRAILING:     return "ERR_TRAILING";
    case DNAC_BLKW_ERR_OVERFLOW:     return "ERR_OVERFLOW";
    }
    return "UNKNOWN";
}

dnac_blkmsg_status_t dnac_blkmsg_v2_decode(const uint8_t *src, size_t len,
                                           dnac_blkmsg_v2_t *out) {
    if (!out) return DNAC_BLKW_ERR_ARG;
    /* Zero FIRST, unconditionally: a rejected message must never leave a
     * half-filled view that a caller could mistake for a decoded one. */
    memset(out, 0, sizeof(*out));
    if (!src) return DNAC_BLKW_ERR_ARG;

    cur_t c = { src, len, 0 };

    if (!need(&c, DNA_BLKW_PREFIX_LEN)) return DNAC_BLKW_ERR_TRUNCATED;

    /* Version dispatch comes FIRST, before any length is believed. An
     * unknown version must never be reinterpreted under this layout — the
     * same discipline the header applies to its retired v2. */
    uint8_t msg_ver = rd_u8(&c);
    if (msg_ver != DNA_BLKW_VERSION) return DNAC_BLKW_ERR_VERSION;

    uint8_t body_ver = rd_u8(&c);
    if (body_ver != DNA_BLKW_BODY_VERSION) return DNAC_BLKW_ERR_BODY_VERSION;

    uint32_t header_len = rd_u32(&c);
    if (header_len != (uint32_t)DNA_BH2_ENC_SIZE)
        return DNAC_BLKW_ERR_HEADER_LEN;

    if (!need(&c, (size_t)header_len)) return DNAC_BLKW_ERR_TRUNCATED;
    const uint8_t *header = c.p + c.off;
    c.off += header_len;

    if (!need(&c, 4)) return DNAC_BLKW_ERR_TRUNCATED;
    uint32_t qc_len = rd_u32(&c);
    /* A zero-length QC is not "no certificate" — it is a malformed one. A
     * block travels WITH its certificate or it does not travel. */
    if (qc_len == 0 || (size_t)qc_len > DNA_QC_V2_MAX_ENC_LEN)
        return DNAC_BLKW_ERR_QC_LEN;
    if (!need(&c, (size_t)qc_len)) return DNAC_BLKW_ERR_TRUNCATED;
    const uint8_t *qc = c.p + c.off;
    c.off += qc_len;

    if (!need(&c, 4)) return DNAC_BLKW_ERR_TRUNCATED;
    uint32_t env_count = rd_u32(&c);
    if (env_count > DNA_BLKW_MAX_ENVS) return DNAC_BLKW_ERR_ENV_COUNT;

    for (uint32_t i = 0; i < env_count; i++) {
        if (!need(&c, 4)) return DNAC_BLKW_ERR_TRUNCATED;
        uint32_t elen = rd_u32(&c);
        /* Bound BEFORE advancing. A zero-length envelope is rejected
         * rather than tolerated: it would decode to an empty batch slot
         * that the engine must then refuse anyway, and admitting it would
         * give one block two encodings (present-but-empty vs absent). */
        if (elen == 0 || (size_t)elen > (size_t)DNA_ENV_MAX_TOTAL_LEN)
            return DNAC_BLKW_ERR_ENV_LEN;
        if (!need(&c, (size_t)elen)) return DNAC_BLKW_ERR_TRUNCATED;
        out->env[i].bytes = c.p + c.off;
        out->env[i].len   = elen;
        c.off += elen;
    }

    /* Claim and pool carriage: DECLARED, and required to be empty. See the
     * BODY COMPLETENESS section in the header — a block carrying either
     * cannot be expressed by v1 and must not be silently read as a block
     * that carries neither. */
    if (!need(&c, 8)) return DNAC_BLKW_ERR_TRUNCATED;
    uint32_t claim_count = rd_u32(&c);
    uint32_t pool_count  = rd_u32(&c);
    if (claim_count != 0 || pool_count != 0)
        return DNAC_BLKW_ERR_UNSUPPORTED;

    if (!need(&c, 32)) return DNAC_BLKW_ERR_TRUNCATED;
    memcpy(out->proposer_id, c.p + c.off, 32);
    c.off += 32;

    if (!need(&c, 8)) return DNAC_BLKW_ERR_TRUNCATED;
    uint64_t ts = rd_u64(&c);

    /* TRAILING BYTES ARE A REJECT. Accepting them would give every block
     * unboundedly many encodings and let a sender smuggle bytes past a
     * length-based frame budget. */
    if (c.off != c.len) {
        memset(out, 0, sizeof(*out));
        return DNAC_BLKW_ERR_TRAILING;
    }

    out->msg_version  = msg_ver;
    out->body_version = body_ver;
    out->header       = header;
    out->qc           = qc;
    out->qc_len       = qc_len;
    out->env_count    = env_count;
    out->timestamp    = ts;
    out->consumed     = c.off;
    return DNAC_BLKW_OK;
}

size_t dnac_blkmsg_v2_encoded_len(const dnac_blkmsg_v2_t *m) {
    if (!m) return 0;
    if (m->env_count > DNA_BLKW_MAX_ENVS) return 0;
    if (m->qc_len == 0 || (size_t)m->qc_len > DNA_QC_V2_MAX_ENC_LEN) return 0;

    size_t n = (size_t)DNA_BLKW_PREFIX_LEN + (size_t)DNA_BH2_ENC_SIZE +
               4u + (size_t)m->qc_len + 4u;
    for (uint32_t i = 0; i < m->env_count; i++) {
        if (m->env[i].len == 0 ||
            (size_t)m->env[i].len > (size_t)DNA_ENV_MAX_TOTAL_LEN)
            return 0;
        n += 4u + (size_t)m->env[i].len;
    }
    n += 4u + 4u + 32u + 8u;
    return n;
}

dnac_blkmsg_status_t dnac_blkmsg_v2_encode(const dnac_blkmsg_v2_t *m,
                                           uint8_t *dst, size_t cap,
                                           size_t *out_len) {
    if (!m || !dst || !out_len) return DNAC_BLKW_ERR_ARG;
    *out_len = 0;
    if (!m->header || !m->qc) return DNAC_BLKW_ERR_ARG;
    if (m->msg_version != DNA_BLKW_VERSION) return DNAC_BLKW_ERR_VERSION;
    if (m->body_version != DNA_BLKW_BODY_VERSION)
        return DNAC_BLKW_ERR_BODY_VERSION;

    size_t need_len = dnac_blkmsg_v2_encoded_len(m);
    if (need_len == 0) return DNAC_BLKW_ERR_ARG;
    if (cap < need_len) return DNAC_BLKW_ERR_ARG;

    uint8_t *d = dst;
    wr_u8(&d, m->msg_version);
    wr_u8(&d, m->body_version);
    wr_u32(&d, (uint32_t)DNA_BH2_ENC_SIZE);
    memcpy(d, m->header, (size_t)DNA_BH2_ENC_SIZE); d += DNA_BH2_ENC_SIZE;
    wr_u32(&d, m->qc_len);
    memcpy(d, m->qc, (size_t)m->qc_len); d += m->qc_len;
    wr_u32(&d, m->env_count);
    for (uint32_t i = 0; i < m->env_count; i++) {
        if (!m->env[i].bytes) return DNAC_BLKW_ERR_ARG;
        wr_u32(&d, m->env[i].len);
        memcpy(d, m->env[i].bytes, (size_t)m->env[i].len);
        d += m->env[i].len;
    }
    wr_u32(&d, 0u);                       /* claim_count      — always 0 */
    wr_u32(&d, 0u);                       /* pool_batch_count — always 0 */
    memcpy(d, m->proposer_id, 32); d += 32;
    wr_u64(&d, m->timestamp);

    *out_len = (size_t)(d - dst);
    return (*out_len == need_len) ? DNAC_BLKW_OK : DNAC_BLKW_ERR_OVERFLOW;
}

int dnac_blkmsg_v2_reencode_equals(const uint8_t *src, size_t len) {
    dnac_blkmsg_v2_t m;
    if (dnac_blkmsg_v2_decode(src, len, &m) != DNAC_BLKW_OK) return 0;

    size_t want = dnac_blkmsg_v2_encoded_len(&m);
    if (want == 0 || want != len) return 0;

    uint8_t *buf = malloc(want);
    /* Allocation failure means we could not CHECK canonicality. Reporting
     * "canonical" here would turn a local resource problem into acceptance
     * of a message we never validated. */
    if (!buf) return 0;

    size_t wrote = 0;
    int ok = (dnac_blkmsg_v2_encode(&m, buf, want, &wrote) == DNAC_BLKW_OK) &&
             wrote == len && memcmp(buf, src, len) == 0;
    free(buf);
    return ok ? 1 : 0;
}
