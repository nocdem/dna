/**
 * @file shared/dnac/evm_call_wire.c
 * @brief Nodus EVM call-bytes codec — see evm_call_wire.h for the layouts and
 *        the node consumers that decode through it (one codec).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "evm_call_wire.h"

#include <string.h>

/* ── big-endian helpers ─────────────────────────────────────────────── */

static void put_be(uint8_t *p, uint64_t v, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        p[i] = (uint8_t)(v >> (8u * (n - 1u - i)));
}

static uint64_t get_be(const uint8_t *p, unsigned n) {
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

/* ── access list ─────────────────────────────────────────────────────
 * The bound discipline of rtevm decode_access: each entry needs 34 bytes
 * before its keys, and its key count is checked against the bytes that
 * remain BEFORE any multiplication. */

int dna_evm_access_walk(const uint8_t *body, size_t avail, uint16_t n_access,
                        size_t *used_out, uint64_t *keys_out) {
    if (used_out) *used_out = 0;
    if (keys_out) *keys_out = 0;
    if (!body && (avail != 0 || n_access != 0)) return -1;
    size_t o = 0;
    uint64_t keys = 0;
    for (uint32_t i = 0; i < n_access; i++) {
        if (avail - o < 34) return -1;
        uint32_t nk = (uint32_t)get_be(body + o + 32, 2);
        o += 34;
        if ((avail - o) / 32 < nk) return -1;
        o += (size_t)nk * 32;
        keys += nk;
    }
    if (used_out) *used_out = o;
    if (keys_out) *keys_out = keys;
    return 0;
}

/* ONE cursor step (red-team 1 F3: the former per-index reader re-walked
 * the whole body for every entry — quadratic in the entry count). The
 * bound discipline of dna_evm_access_walk: 34 bytes before the keys, the
 * key count checked against the bytes that remain BEFORE the
 * multiplication. */
int dna_evm_access_next(const uint8_t *body, size_t len, size_t *off,
                        const uint8_t **addr_out, uint16_t *n_keys_out,
                        const uint8_t **keys_out) {
    if (!off || !addr_out || !n_keys_out || !keys_out) return -1;
    *addr_out = NULL;
    *n_keys_out = 0;
    *keys_out = NULL;
    if (!body || *off > len) return -1;
    size_t o = *off;
    if (len - o < 34) return -1;
    uint16_t nk = (uint16_t)get_be(body + o + 32, 2);
    if ((len - o - 34) / 32 < nk) return -1;
    *addr_out = body + o;
    *n_keys_out = nk;
    *keys_out = nk ? body + o + 34 : NULL;
    *off = o + 34 + (size_t)nk * 32;
    return 0;
}

int dna_evm_access_put(uint8_t *dst, size_t cap, size_t *off,
                       const uint8_t addr[DNA_EVM_ADDR_LEN], uint16_t n_keys,
                       const uint8_t *keys) {
    if (!dst || !off || !addr || (n_keys && !keys) || *off > cap) return -1;
    const size_t need = 34 + (size_t)n_keys * 32;
    if (cap - *off < need) return -1;
    memcpy(dst + *off, addr, 32);
    put_be(dst + *off + 32, n_keys, 2);
    if (n_keys) memcpy(dst + *off + 34, keys, (size_t)n_keys * 32);
    *off += need;
    return 0;
}

/* ── the EVM leg ────────────────────────────────────────────────────── */

/* The access body of `c` must be EXACTLY n_access well-formed entries. */
static int access_ok(const dna_evm_call_t *c) {
    if (!c->access && c->access_len) return -1;
    size_t used = 0;
    if (dna_evm_access_walk(c->access, c->access_len, c->n_access, &used,
                            NULL) != 0 ||
        used != c->access_len)
        return -1;
    return 0;
}

int dna_evm_call_encoded_size(const dna_evm_call_t *c, size_t *out) {
    if (!out) return -1;
    *out = 0;
    if (!c) return -1;
    switch (c->op) {
        case DNA_EVM_OP_CALL:
        case DNA_EVM_OP_CREATE: {
            if (access_ok(c) != 0) return -1;
            if (!c->data && c->data_len) return -1;
            if (c->op == DNA_EVM_OP_CREATE &&
                c->data_len > DNA_EVM_MAX_INITCODE)
                return -1;
            size_t n = 1 + (c->op == DNA_EVM_OP_CALL ? 32u : 0u) + 32 + 8 +
                       8 + 2;
            /* subtraction form: no addition below can wrap */
            if (c->access_len > SIZE_MAX - n - 4) return -1;
            n += c->access_len + 4;
            if ((size_t)c->data_len > SIZE_MAX - n) return -1;
            *out = n + c->data_len;
            return 0;
        }
        case DNA_EVM_OP_DEPOSIT:  *out = DNA_EVM_DEPOSIT_CALL_LEN;  return 0;
        case DNA_EVM_OP_WITHDRAW: *out = DNA_EVM_WITHDRAW_CALL_LEN; return 0;
        case DNA_EVM_OP_REDEEM:   *out = DNA_EVM_REDEEM_CALL_LEN;   return 0;
        default: return -1;
    }
}

int dna_evm_call_encode(const dna_evm_call_t *c, uint8_t *dst, size_t dst_cap,
                        size_t *written_out) {
    if (!written_out) return -1;
    *written_out = 0;
    size_t n = 0;
    if (!c || !dst || dna_evm_call_encoded_size(c, &n) != 0 || dst_cap < n)
        return -1;
    size_t o = 0;
    dst[o++] = (uint8_t)DNA_EVM_CALL_VER;
    switch (c->op) {
        case DNA_EVM_OP_CALL:
        case DNA_EVM_OP_CREATE:
            if (c->op == DNA_EVM_OP_CALL) {
                memcpy(dst + o, c->to, 32);
                o += 32;
            }
            memcpy(dst + o, c->value_wei, 32);
            o += 32;
            put_be(dst + o, c->gas_limit, 8);
            o += 8;
            put_be(dst + o, c->nonce, 8);
            o += 8;
            put_be(dst + o, c->n_access, 2);
            o += 2;
            if (c->access_len) memcpy(dst + o, c->access, c->access_len);
            o += c->access_len;
            put_be(dst + o, c->data_len, 4);
            o += 4;
            if (c->data_len) memcpy(dst + o, c->data, c->data_len);
            o += c->data_len;
            break;
        case DNA_EVM_OP_DEPOSIT:
            put_be(dst + o, c->amount_raw, 8);
            put_be(dst + o + 8, c->nonce, 8);
            o += 16;
            break;
        case DNA_EVM_OP_WITHDRAW:
            put_be(dst + o, c->amount_raw, 8);
            put_be(dst + o + 8, c->nonce, 8);
            memcpy(dst + o + 16, c->dest_fp, 64);
            o += 80;
            break;
        case DNA_EVM_OP_REDEEM:
            memcpy(dst + o, c->ticket_id, 64);
            put_be(dst + o + 64, c->amount_raw, 8);
            memcpy(dst + o + 72, c->dest_fp, 64);
            o += 136;
            break;
        default:
            return -1;
    }
    if (o != n) return -1;                 /* the size identity            */
    *written_out = o;
    return 0;
}

int dna_evm_call_head(uint32_t op, const uint8_t *c, size_t len,
                      dna_evm_head_t *k) {
    if (!k) return -1;
    memset(k, 0, sizeof(*k));
    k->op = op;
    if (!c || len < 1 || c[0] != DNA_EVM_CALL_VER) return -1;
    switch (op) {
        case DNA_EVM_OP_CALL:
            /* ver ‖ to[32] ‖ value[32] ‖ gas_limit ‖ nonce */
            if (len < 1u + 32u + 32u + 8u + 8u) return -1;
            k->to = c + 1;
            k->value = c + 33;
            k->gas_limit = get_be(c + 65, 8);
            k->nonce = get_be(c + 73, 8);
            k->rest_off = 81;
            return 0;
        case DNA_EVM_OP_CREATE:
            /* ver ‖ value[32] ‖ gas_limit ‖ nonce */
            if (len < 1u + 32u + 8u + 8u) return -1;
            k->value = c + 1;
            k->gas_limit = get_be(c + 33, 8);
            k->nonce = get_be(c + 41, 8);
            k->rest_off = 49;
            return 0;
        case DNA_EVM_OP_DEPOSIT:
            if (len != DNA_EVM_DEPOSIT_CALL_LEN) return -1;
            k->amount_raw = get_be(c + 1, 8);
            k->nonce = get_be(c + 9, 8);
            k->rest_off = len;
            return 0;
        case DNA_EVM_OP_WITHDRAW:
            if (len != DNA_EVM_WITHDRAW_CALL_LEN) return -1;
            k->amount_raw = get_be(c + 1, 8);
            k->nonce = get_be(c + 9, 8);
            k->dest_fp = c + 17;
            k->rest_off = len;
            return 0;
        case DNA_EVM_OP_REDEEM:
            if (len != DNA_EVM_REDEEM_CALL_LEN) return -1;
            k->ticket_id = c + 1;
            k->amount_raw = get_be(c + 65, 8);
            k->dest_fp = c + 73;
            k->rest_off = len;
            return 0;
        default:
            return -1;
    }
}

int dna_evm_call_decode(uint32_t op, const uint8_t *src, size_t len,
                        dna_evm_call_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    /* the fixed head through the ONE head decoder every consumer shares */
    dna_evm_head_t h;
    if (dna_evm_call_head(op, src, len, &h) != 0) return -1;
    dna_evm_call_t k;
    memset(&k, 0, sizeof(k));
    k.op = op;
    k.gas_limit = h.gas_limit;
    k.nonce = h.nonce;
    k.amount_raw = h.amount_raw;
    if (h.to) memcpy(k.to, h.to, 32);
    if (h.value) memcpy(k.value_wei, h.value, 32);
    if (h.dest_fp) memcpy(k.dest_fp, h.dest_fp, 64);
    if (h.ticket_id) memcpy(k.ticket_id, h.ticket_id, 64);
    if (op == DNA_EVM_OP_CALL || op == DNA_EVM_OP_CREATE) {
        /* CALL / CREATE continue past the head: access list, data */
        size_t off = h.rest_off;
        if (len - off < 2) return -1;
        k.n_access = (uint16_t)get_be(src + off, 2);
        off += 2;
        size_t used = 0;
        if (dna_evm_access_walk(src + off, len - off, k.n_access, &used,
                                &k.n_access_keys) != 0)
            return -1;
        k.access = used ? src + off : NULL;
        k.access_len = used;
        off += used;
        if (len - off < 4) return -1;
        uint32_t dl = (uint32_t)get_be(src + off, 4);
        off += 4;
        if (len - off != dl) return -1;       /* exact: no trailing byte */
        if (op == DNA_EVM_OP_CREATE && dl > DNA_EVM_MAX_INITCODE)
            return -1;                        /* EIP-3860                */
        k.data = dl ? src + off : NULL;
        k.data_len = dl;
    }
    *out = k;
    return 0;
}

/* ── the CORE EVMFUND leg ───────────────────────────────────────────── */

uint8_t dna_evmfund_role_for_op(uint32_t op) {
    switch (op) {
        case DNA_EVM_OP_CALL:
        case DNA_EVM_OP_CREATE:   return (uint8_t)DNA_EVMFUND_ROLE_FEE;
        case DNA_EVM_OP_DEPOSIT:  return (uint8_t)DNA_EVMFUND_ROLE_DEPOSIT;
        case DNA_EVM_OP_WITHDRAW:
        case DNA_EVM_OP_REDEEM:   return (uint8_t)DNA_EVMFUND_ROLE_RELEASE;
        default:                  return 0;
    }
}

uint32_t dna_evmfund_reads(uint8_t role, uint8_t n_in) {
    switch (role) {
        case DNA_EVMFUND_ROLE_FEE:     return (uint32_t)n_in + 1u;
        case DNA_EVMFUND_ROLE_DEPOSIT:
        case DNA_EVMFUND_ROLE_RELEASE: return (uint32_t)n_in + 2u;
        default:                       return 0;
    }
}

static int fund_role_ok(uint8_t r) {
    return r == DNA_EVMFUND_ROLE_FEE || r == DNA_EVMFUND_ROLE_DEPOSIT ||
           r == DNA_EVMFUND_ROLE_RELEASE;
}

/* One 232-byte change record: lowercase-hex owner, amount > 0, native. */
static int fund_out_ok(const uint8_t *r) {
    for (unsigned i = 0; i < 128; i++)
        if (!((r[i] >= '0' && r[i] <= '9') || (r[i] >= 'a' && r[i] <= 'f')))
            return 0;
    if (get_be(r + 128, 8) == 0) return 0;
    for (unsigned i = 136; i < 200; i++)
        if (r[i] != 0) return 0;
    return 1;
}

/* Shape of the inputs and outputs, shared by encode and decode. */
static int fund_sections_ok(const dna_evmfund_call_t *c) {
    if (!fund_role_ok(c->role)) return 0;
    if (c->n_in < 1 || c->n_in > DNA_EVMFUND_MAX_IN || !c->in_nul) return 0;
    if (c->n_out > DNA_EVMFUND_MAX_OUT || (c->n_out && !c->outs)) return 0;
    for (unsigned i = 1; i < c->n_in; i++)
        if (memcmp(c->in_nul + (size_t)(i - 1) * 64, c->in_nul + (size_t)i * 64,
                   64) >= 0)
            return 0;                        /* strictly ascending         */
    for (unsigned o = 0; o < c->n_out; o++)
        if (!fund_out_ok(c->outs + (size_t)o * DNA_EVMFUND_OUT_LEN)) return 0;
    return 1;
}

int dna_evmfund_encoded_size(const dna_evmfund_call_t *c, size_t *out) {
    if (!out) return -1;
    *out = 0;
    if (!c || !fund_sections_ok(c)) return -1;
    *out = 3 + (size_t)c->n_in * 64 + 1 +
           (size_t)c->n_out * DNA_EVMFUND_OUT_LEN;
    return 0;
}

int dna_evmfund_encode(const dna_evmfund_call_t *c, uint8_t *dst,
                       size_t dst_cap, size_t *written_out) {
    if (!written_out) return -1;
    *written_out = 0;
    size_t n = 0;
    if (!c || !dst || dna_evmfund_encoded_size(c, &n) != 0 || dst_cap < n)
        return -1;
    size_t o = 0;
    dst[o++] = (uint8_t)DNA_EVMFUND_VER;
    dst[o++] = c->role;
    dst[o++] = c->n_in;
    memcpy(dst + o, c->in_nul, (size_t)c->n_in * 64);
    o += (size_t)c->n_in * 64;
    dst[o++] = c->n_out;
    if (c->n_out)
        memcpy(dst + o, c->outs, (size_t)c->n_out * DNA_EVMFUND_OUT_LEN);
    o += (size_t)c->n_out * DNA_EVMFUND_OUT_LEN;
    if (o != n) return -1;
    *written_out = o;
    return 0;
}

int dna_evmfund_decode(const uint8_t *src, size_t len,
                       dna_evmfund_call_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!src || len < 3 || src[0] != DNA_EVMFUND_VER) return -1;
    dna_evmfund_call_t k;
    memset(&k, 0, sizeof(k));
    k.role = src[1];
    k.n_in = src[2];
    if (k.n_in < 1 || k.n_in > DNA_EVMFUND_MAX_IN) return -1;
    size_t off = 3;
    if ((len - off) / 64 < k.n_in) return -1;
    k.in_nul = src + off;
    off += (size_t)k.n_in * 64;
    if (len - off < 1) return -1;
    k.n_out = src[off++];
    if (k.n_out > DNA_EVMFUND_MAX_OUT) return -1;
    if (len - off != (size_t)k.n_out * DNA_EVMFUND_OUT_LEN) return -1;
    k.outs = k.n_out ? src + off : NULL;
    if (!fund_sections_ok(&k)) return -1;
    *out = k;
    return 0;
}

/* ── the canonical receipt (design §7) ─────────────────────────────── */

/* "NDS.EVMRCPT.v1" + two zero bytes (nodus_witness_rt_evm.c TAG_EVMRCPT) */
static const uint8_t RCPT_TAG[DNA_EVM_RCPT_TAG_LEN] = {
    'N', 'D', 'S', '.', 'E', 'V', 'M', 'R', 'C', 'P', 'T', '.', 'v', '1',
    0, 0
};

/* Walk one log entry at p[*o], at most `end` bytes. @return 0 / -1. */
static int rcpt_log_walk(const uint8_t *p, size_t end, size_t *o) {
    if (end - *o < 33) return -1;
    uint8_t nt = p[*o + 32];
    if (nt > DNA_EVM_RCPT_MAX_TOPICS) return -1;
    *o += 33;
    if (end - *o < (size_t)nt * 32 + 4) return -1;
    *o += (size_t)nt * 32;
    uint32_t dl = (uint32_t)get_be(p + *o, 4);
    *o += 4;
    if (end - *o < dl) return -1;
    *o += dl;
    return 0;
}

int dna_evm_rcpt_decode(const uint8_t *src, size_t len, dna_evm_rcpt_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!src || len < DNA_EVM_RCPT_TAG_LEN + 1 + 1 + 8 + 32 + 4 ||
        memcmp(src, RCPT_TAG, DNA_EVM_RCPT_TAG_LEN) != 0)
        return -1;
    dna_evm_rcpt_t r;
    memset(&r, 0, sizeof(r));
    size_t o = DNA_EVM_RCPT_TAG_LEN;
    r.status = src[o++];
    if (r.status > 1) return -1;
    r.op = src[o++];
    r.gas_used = get_be(src + o, 8);
    o += 8;
    r.created = src + o;
    o += 32;
    r.output_len = (uint32_t)get_be(src + o, 4);
    o += 4;
    if (len - o < r.output_len) return -1;
    r.output = src + o;
    o += r.output_len;
    if (len - o < 4) return -1;
    r.n_logs = (uint32_t)get_be(src + o, 4);
    o += 4;
    r.logs = src + o;
    for (uint32_t i = 0; i < r.n_logs; i++)
        if (rcpt_log_walk(src, len, &o) != 0) return -1;
    r.logs_len = (size_t)(src + o - r.logs);
    if (len - o < 32 + 2) return -1;
    r.wei_destroyed = src + o;
    o += 32;
    r.n_tickets = (uint16_t)get_be(src + o, 2);
    o += 2;
    if ((len - o) / 64 < r.n_tickets || len - o != (size_t)r.n_tickets * 64)
        return -1;                            /* exact: no trailing byte */
    r.tickets = r.n_tickets ? src + o : NULL;
    *out = r;
    return 0;
}

int dna_evm_rcpt_log_next(const dna_evm_rcpt_t *r, size_t *cursor,
                          const uint8_t **addr_out, uint8_t *n_topics_out,
                          const uint8_t **topics_out,
                          const uint8_t **data_out, uint32_t *data_len_out) {
    if (!r || !cursor || !addr_out || !n_topics_out || !topics_out ||
        !data_out || !data_len_out || *cursor >= r->logs_len)
        return -1;
    size_t o = *cursor;
    if (rcpt_log_walk(r->logs, r->logs_len, &o) != 0) return -1;
    const uint8_t *e = r->logs + *cursor;
    *addr_out = e;
    *n_topics_out = e[32];
    *topics_out = e[32] ? e + 33 : NULL;
    *data_len_out = (uint32_t)get_be(e + 33 + (size_t)e[32] * 32, 4);
    *data_out = e + 33 + (size_t)e[32] * 32 + 4;
    *cursor = o;
    return 0;
}
