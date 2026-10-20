/**
 * @file nodus_witness_storage_fetch_wire.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the channel 0x73 segment fetch: the WIRE alone (request and
 *        answer encode / decode, the request id, the shape rule).
 *        Contract and layout: nodus_witness_storage_fetch.h "THE WIRE".
 *        The wire is approved (decision K6b, 2026-10-07).
 *
 * Moved unchanged out of nodus_witness_storage_fetch.c by package P-B2
 * (design docs/plans/2026-10-19-windows-light-storage-design.md §3 B2):
 * the light node's header pass (storage/nodus_light_hashlist.c) speaks
 * this wire and must compile on Windows, while the serving side
 * (nodus_witness_storage_fetch.c: the piece from a block / state store,
 * the admission) needs a full node's store and stays in the Linux-only
 * source list. Bytes, bounds and refusals are those of the file it left.
 *
 * Nothing here reads a clock, draws randomness or allocates; the only
 * writes are into the caller's output buffer.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_fetch.h"

#include "crypto/hash/qgp_sha3.h"

#include <string.h>

#define SF_P  ((uint64_t)DNA_V2_SEGMENT_BLOCKS)

/* ── byte helpers ────────────────────────────────────────────────────── */

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void sf_tag(uint8_t out[NODUS_STFETCH_TAG_LEN]) {
    memset(out, 0, NODUS_STFETCH_TAG_LEN);
    memcpy(out, NODUS_STFETCH_TAG, sizeof(NODUS_STFETCH_TAG) - 1);
}
_Static_assert(sizeof(NODUS_STFETCH_TAG) - 1 <= NODUS_STFETCH_TAG_LEN,
               "the tag fits its 16 bytes");

/* ══════════════════════════════════════════════════════════════════════
 * The request
 * ════════════════════════════════════════════════════════════════════ */

/* What decode refuses, on the decoded fields. */
bool nodus_stfetch_req_valid(const nodus_stfetch_req_t *r) {
    if (!r) return false;
    if (r->k == 0 || r->k > ((uint64_t)INT64_MAX - 1u) / SF_P - 1u)
        return false;
    const uint64_t first = (r->k - 1u) * SF_P + 1u, last = r->k * SF_P;
    if (r->h < first || r->h > last) return false;
    if (r->part == NODUS_SEG_PART_COMMIT || r->part == NODUS_SEG_PART_VALSET) {
        if (r->h != last) return false;
    } else if (r->part >= CMT_PART_SET_MAX_PARTS) {
        return false;
    }
    return r->cont == NODUS_STFETCH_CONT_FIRST ||
           r->cont == NODUS_STFETCH_CONT_HAVE_HDR;
}

static void req_body(const nodus_stfetch_req_t *r,
                     uint8_t b[NODUS_STFETCH_REQ_LEN]) {
    sf_tag(b);
    put64(b + 16, r->k);
    put64(b + 24, r->h);
    put32(b + 32, r->part);
    b[36] = r->cont;
}

int nodus_stfetch_req_encode(const nodus_stfetch_req_t *req,
                             uint8_t out[NODUS_STFETCH_REQ_MSG_LEN]) {
    if (!req || !out || !nodus_stfetch_req_valid(req)) return -1;
    out[0] = NODUS_STFETCH_KIND_REQ;
    req_body(req, out + 1);
    return 0;
}

int nodus_stfetch_req_decode(const uint8_t *msg, size_t len,
                             nodus_stfetch_req_t *out) {
    if (!msg || !out || len != NODUS_STFETCH_REQ_MSG_LEN) return -1;
    if (msg[0] != NODUS_STFETCH_KIND_REQ) return -1;
    uint8_t tag[NODUS_STFETCH_TAG_LEN];
    sf_tag(tag);
    const uint8_t *b = msg + 1;
    if (memcmp(b, tag, NODUS_STFETCH_TAG_LEN) != 0) return -1;
    nodus_stfetch_req_t r;
    r.k = get64(b + 16);
    r.h = get64(b + 24);
    r.part = get32(b + 32);
    r.cont = b[36];
    if (!nodus_stfetch_req_valid(&r)) return -1;
    *out = r;
    return 0;
}

int nodus_stfetch_req_id(const nodus_stfetch_req_t *req, uint8_t rq[64]) {
    if (!req || !rq) return -1;
    uint8_t b[NODUS_STFETCH_REQ_LEN];
    req_body(req, b);
    return qgp_sha3_512(b, sizeof(b), rq) == 0 ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * The answer
 * ════════════════════════════════════════════════════════════════════ */

int nodus_stfetch_ans_refusal(const uint8_t rq[64], uint8_t code,
                              uint8_t out[NODUS_STFETCH_REFUSAL_LEN]) {
    if (!rq || !out || code == NODUS_STFETCH_OK) return -1;
    out[0] = NODUS_STFETCH_KIND_ANS;
    memcpy(out + 1, rq, 64);
    out[65] = code;
    return 0;
}

int nodus_stfetch_ans_encode(const uint8_t rq[64],
                             const uint8_t *hdr, size_t hdr_len,
                             const uint8_t *body, size_t body_len,
                             const uint8_t *proof, size_t proof_len,
                             uint8_t *out, size_t cap, size_t *len_out) {
    if (!rq || !out || !len_out || (!hdr && hdr_len) ||
        (!body && body_len) || (!proof && proof_len) ||
        hdr_len > NODUS_SEG_HEADER_MAX || body_len > NODUS_STFETCH_BODY_MAX ||
        proof_len > NODUS_STPROBE_PROOF_MAX)
        return -1;
    const size_t need = NODUS_STFETCH_REFUSAL_LEN + 12u + hdr_len +
                        body_len + proof_len;
    if (cap < need) return -1;
    size_t o = 0;
    out[o++] = NODUS_STFETCH_KIND_ANS;
    memcpy(out + o, rq, 64);  o += 64;
    out[o++] = NODUS_STFETCH_OK;
    put32(out + o, (uint32_t)hdr_len);   o += 4;
    if (hdr_len) memcpy(out + o, hdr, hdr_len);
    o += hdr_len;
    put32(out + o, (uint32_t)body_len);  o += 4;
    if (body_len) memcpy(out + o, body, body_len);
    o += body_len;
    put32(out + o, (uint32_t)proof_len); o += 4;
    if (proof_len) memcpy(out + o, proof, proof_len);
    o += proof_len;
    *len_out = o;
    return 0;
}

int nodus_stfetch_ans_decode(const uint8_t *msg, size_t len,
                             nodus_stfetch_ans_view_t *out) {
    if (!msg || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (len < NODUS_STFETCH_REFUSAL_LEN || len > NODUS_STFETCH_MSG_MAX)
        return -1;
    if (msg[0] != NODUS_STFETCH_KIND_ANS) return -1;
    memcpy(out->rq, msg + 1, 64);
    out->code = msg[65];
    if (out->code != NODUS_STFETCH_OK) {
        /* Only a defined refusal is an answer; 5 is retired (K6a) and
         * 7..255 are undefined — both are a malformed answer. */
        switch (out->code) {
        case NODUS_STFETCH_REF_NOT_MEMBER:
        case NODUS_STFETCH_REF_UNKNOWN_SET:
        case NODUS_STFETCH_REF_NOT_PUBLISHED:
        case NODUS_STFETCH_REF_NOT_HELD:
        case NODUS_STFETCH_REF_FAULT:
            break;
        default:
            return -1;
        }
        return len == NODUS_STFETCH_REFUSAL_LEN ? 0 : -1;
    }
    const uint32_t bounds[3] = { NODUS_SEG_HEADER_MAX, NODUS_STFETCH_BODY_MAX,
                                 NODUS_STPROBE_PROOF_MAX };
    const uint8_t *ptr[3] = { NULL, NULL, NULL };
    uint32_t lens[3] = { 0, 0, 0 };
    size_t off = NODUS_STFETCH_REFUSAL_LEN;
    for (int f = 0; f < 3; f++) {
        if (len - off < 4) return -1;
        const uint32_t l = get32(msg + off);
        off += 4;
        if (l > bounds[f] || (size_t)l > len - off) return -1;
        ptr[f] = l ? msg + off : NULL;
        lens[f] = l;
        off += l;
    }
    if (off != len) return -1;               /* no trailing byte */
    out->hdr = ptr[0];   out->hdr_len = lens[0];
    out->body = ptr[1];  out->body_len = lens[1];
    out->proof = ptr[2]; out->proof_len = lens[2];
    return 0;
}

bool nodus_stfetch_ans_shape_ok(const nodus_stfetch_req_t *req,
                                const nodus_stfetch_ans_view_t *a) {
    if (!req || !a || a->code != NODUS_STFETCH_OK) return false;
    if ((req->cont == NODUS_STFETCH_CONT_FIRST) != (a->hdr_len > 0))
        return false;
    if (req->part == NODUS_SEG_PART_COMMIT)
        return a->body_len > 0 && a->proof_len == 0;
    if (req->part == NODUS_SEG_PART_VALSET)
        return a->body_len > 0 && a->body_len <= NODUS_SEG_VALSET_MAX &&
               a->proof_len == 0;
    return a->body_len <= CMT_BLOCK_PART_SIZE_BYTES && a->proof_len > 0;
}
