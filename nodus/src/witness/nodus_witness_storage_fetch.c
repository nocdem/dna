/**
 * @file nodus_witness_storage_fetch.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the channel 0x73 segment fetch: the wire and the serving side.
 *        Contract, layout, admission and the determinism statement:
 *        nodus_witness_storage_fetch.h. The wire is approved (decision
 *        K6b, 2026-10-07).
 *
 * Nothing here reads a clock or draws randomness; the only writes are
 * into the caller's output buffer.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_fetch.h"
#include "witness/nodus_witness_storage_probe.h"   /* epoch_for_tip      */
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_v2_produce.h"      /* tip height          */

#include "dnac/cmt_pb.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STFETCH"

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
static bool req_valid(const nodus_stfetch_req_t *r) {
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
    if (!req || !out || !req_valid(req)) return -1;
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
    if (!req_valid(&r)) return -1;
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
    if (out->code != NODUS_STFETCH_OK)
        return len == NODUS_STFETCH_REFUSAL_LEN ? 0 : -1;
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

/* ══════════════════════════════════════════════════════════════════════
 * The piece
 * ════════════════════════════════════════════════════════════════════ */

/* From the block store. @return OK / NOT_HELD (anything missing) /
 * FAULT. */
static nodus_stfetch_code_t piece_from_store(nodus_cmt_store_t *s,
                                             const nodus_stfetch_req_t *r,
                                             uint8_t *out, size_t cap,
                                             size_t *len_out) {
    const int64_t base = nodus_cmt_bs_base(s);
    const int64_t top = nodus_cmt_bs_height(s);
    if (base < 1 || (uint64_t)base > r->h || top < 1 ||
        (uint64_t)top < r->h + 1u)
        return NODUS_STFETCH_REF_NOT_HELD;

    nodus_stfetch_code_t ret = NODUS_STFETCH_REF_FAULT;
    nodus_cmt_block_meta_t *meta = malloc(sizeof(*meta));
    cmt_part_t *part = malloc(sizeof(*part));
    uint8_t *pbuf = malloc(CMT_BLOCK_PART_SIZE_BYTES);
    uint8_t *hbuf = malloc(NODUS_SEG_HEADER_MAX);
    uint8_t *prf = malloc(NODUS_STPROBE_PROOF_MAX);
    uint8_t rq[64];
    size_t hl = 0;
    bool found = false;
    if (!meta || !part || !pbuf || !hbuf || !prf ||
        nodus_stfetch_req_id(r, rq) != 0)
        goto done;
    if (nodus_cmt_bs_load_block_meta(s, (int64_t)(r->h + 1u), meta, &found)
            != CMT_OK)
        goto done;
    if (!found) { ret = NODUS_STFETCH_REF_NOT_HELD; goto done; }
    if (r->cont == NODUS_STFETCH_CONT_FIRST &&
        (cmt_pb_header_marshal(&meta->header, hbuf, NODUS_SEG_HEADER_MAX,
                               &hl) != CMT_OK || hl == 0))
        goto done;

    if (r->part == NODUS_SEG_PART_COMMIT) {
        char key[NODUS_CMT_STORE_KEY_MAX];
        const uint8_t *v = NULL;
        size_t vl = 0;
        snprintf(key, sizeof(key), "C:%" PRId64, (int64_t)r->h);
        if (nodus_cmt_store_get(s, false, key, &v, &vl) != CMT_OK) goto done;
        if (vl == 0) { ret = NODUS_STFETCH_REF_NOT_HELD; goto done; }
        if (vl > NODUS_STFETCH_BODY_MAX) goto done;
        if (nodus_stfetch_ans_encode(rq, hl ? hbuf : NULL, hl, v, vl, NULL,
                                     0, out, cap, len_out) != 0)
            goto done;
        ret = NODUS_STFETCH_OK;
        goto done;
    }
    if (r->part >= meta->header.last_block_id.part_set_header.total) {
        ret = NODUS_STFETCH_REF_NOT_HELD;     /* no such part: nothing held */
        goto done;
    }
    cmt_pb_arena_t ar = { pbuf, CMT_BLOCK_PART_SIZE_BYTES, 0 };
    if (nodus_cmt_bs_load_block_part(s, (int64_t)r->h, (int)r->part, &ar,
                                     part, &found) != CMT_OK)
        goto done;
    if (!found) { ret = NODUS_STFETCH_REF_NOT_HELD; goto done; }
    size_t pl = 0;
    if (cmt_pb_proof_marshal(&part->proof, prf, NODUS_STPROBE_PROOF_MAX,
                             &pl) != CMT_OK || pl == 0)
        goto done;
    if (nodus_stfetch_ans_encode(rq, hl ? hbuf : NULL, hl, part->bytes.data,
                                 part->bytes.len, prf, pl, out, cap,
                                 len_out) != 0)
        goto done;
    ret = NODUS_STFETCH_OK;
done:
    free(prf);
    free(hbuf);
    free(pbuf);
    free(part);
    free(meta);
    return ret;
}

/* The set piece from the STATE table (K8a): validators(k·P) when this node
 * still has them — not gated on the block store's base, the state table
 * is pruned on its own schedule — with header(k·P+1) from the block store
 * when cont == 0. @return OK / NOT_HELD (anything missing) / FAULT. */
static nodus_stfetch_code_t valset_from_store(nodus_cmt_store_t *s,
                                              const nodus_stfetch_req_t *r,
                                              uint8_t *out, size_t cap,
                                              size_t *len_out) {
    nodus_stfetch_code_t ret = NODUS_STFETCH_REF_FAULT;
    nodus_cmt_block_meta_t *meta = NULL;
    uint8_t *hbuf = NULL;
    uint8_t *vb = malloc(NODUS_SEG_VALSET_MAX);
    uint8_t rq[64];
    size_t hl = 0, vl = 0;
    if (!vb || nodus_stfetch_req_id(r, rq) != 0) goto done;
    int rc = nodus_seg_valset_from_store(s, r->h, vb, NODUS_SEG_VALSET_MAX,
                                         &vl);
    if (rc < 0) goto done;
    if (rc > 0) { ret = NODUS_STFETCH_REF_NOT_HELD; goto done; }
    if (r->cont == NODUS_STFETCH_CONT_FIRST) {
        bool found = false;
        meta = malloc(sizeof(*meta));
        hbuf = malloc(NODUS_SEG_HEADER_MAX);
        if (!meta || !hbuf ||
            nodus_cmt_bs_load_block_meta(s, (int64_t)(r->h + 1u), meta,
                                         &found) != CMT_OK)
            goto done;
        if (!found) { ret = NODUS_STFETCH_REF_NOT_HELD; goto done; }
        if (cmt_pb_header_marshal(&meta->header, hbuf, NODUS_SEG_HEADER_MAX,
                                  &hl) != CMT_OK || hl == 0)
            goto done;
    }
    if (nodus_stfetch_ans_encode(rq, hl ? hbuf : NULL, hl, vb, vl, NULL, 0,
                                 out, cap, len_out) != 0)
        goto done;
    ret = NODUS_STFETCH_OK;
done:
    free(hbuf);
    free(meta);
    free(vb);
    return ret;
}

/* From the held segment file. @return OK / NOT_HELD / FAULT. */
static nodus_stfetch_code_t piece_from_file(const char *dir,
                                            const nodus_stfetch_req_t *r,
                                            uint8_t *out, size_t cap,
                                            size_t *len_out) {
    nodus_seg_reader_t *rd = NULL;
    int rc = nodus_seg_reader_open(dir, r->k, &rd);
    if (rc == 1) return NODUS_STFETCH_REF_NOT_HELD;
    if (rc != 0) return NODUS_STFETCH_REF_FAULT;

    nodus_stfetch_code_t ret = NODUS_STFETCH_REF_FAULT;
    uint8_t *hbuf = malloc(NODUS_SEG_HEADER_MAX);
    uint8_t *body = malloc(NODUS_STFETCH_BODY_MAX);
    uint8_t *proto = malloc(NODUS_SEG_PART_PROTO_MAX);
    uint8_t *prf = malloc(NODUS_STPROBE_PROOF_MAX);
    uint8_t rq[64];
    size_t hl = 0, bl = 0, pl = 0, protol = 0;
    uint32_t n = 0;
    if (!hbuf || !body || !proto || !prf || nodus_stfetch_req_id(r, rq) != 0)
        goto done;
    const bool want_hdr = r->cont == NODUS_STFETCH_CONT_FIRST;

    if (r->part == NODUS_SEG_PART_COMMIT || r->part == NODUS_SEG_PART_VALSET) {
        if (nodus_seg_reader_get(rd, r->h, want_hdr ? hbuf : NULL, &hl, &n, 0,
                                 NULL, NULL) != 0)
            goto done;
        if ((r->part == NODUS_SEG_PART_COMMIT
                 ? nodus_seg_reader_commit(rd, body, NODUS_STFETCH_BODY_MAX,
                                           &bl)
                 : nodus_seg_reader_valset(rd, body, NODUS_STFETCH_BODY_MAX,
                                           &bl)) != 0)
            goto done;
        if (nodus_stfetch_ans_encode(rq, want_hdr ? hbuf : NULL,
                                     want_hdr ? hl : 0, body, bl, NULL, 0,
                                     out, cap, len_out) != 0)
            goto done;
        ret = NODUS_STFETCH_OK;
        goto done;
    }
    rc = nodus_seg_reader_get(rd, r->h, want_hdr ? hbuf : NULL, &hl, &n,
                              r->part, proto, &protol);
    if (rc == 1) { ret = NODUS_STFETCH_REF_NOT_HELD; goto done; }
    if (rc != 0) goto done;
    if (nodus_seg_part_split(proto, protol, body, &bl, prf, &pl, NULL) != 0)
        goto done;
    if (nodus_stfetch_ans_encode(rq, want_hdr ? hbuf : NULL,
                                 want_hdr ? hl : 0, body, bl, prf, pl, out,
                                 cap, len_out) != 0)
        goto done;
    ret = NODUS_STFETCH_OK;
done:
    free(prf);
    free(proto);
    free(body);
    free(hbuf);
    nodus_seg_reader_close(rd);
    return ret;
}

nodus_stfetch_code_t nodus_stfetch_answer_build(
        nodus_cmt_store_t *store, const char *seg_dir,
        const nodus_stfetch_req_t *req, uint8_t *out, size_t cap,
        size_t *len_out) {
    if (!req || !out || !len_out || !req_valid(req))
        return NODUS_STFETCH_REF_FAULT;
    *len_out = 0;
    nodus_stfetch_code_t c = NODUS_STFETCH_REF_NOT_HELD;
    if (store)
        c = req->part == NODUS_SEG_PART_VALSET
                ? valset_from_store(store, req, out, cap, len_out)
                : piece_from_store(store, req, out, cap, len_out);
    if (c == NODUS_STFETCH_REF_NOT_HELD && seg_dir && seg_dir[0])
        c = piece_from_file(seg_dir, req, out, cap, len_out);
    if (c != NODUS_STFETCH_OK) *len_out = 0;
    return c;
}

/* ══════════════════════════════════════════════════════════════════════
 * Admission
 * ════════════════════════════════════════════════════════════════════ */

/* The live registry row of `fp` is ACTIVE. @return 1 / 0 / -1 */
static int registry_active(nodus_witness_t *w, const uint8_t fp[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT status FROM v2_storage_nodes WHERE node_fp = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int ret = 0;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        ret = (sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
               sqlite3_column_int64(st, 0) == (sqlite3_int64)
                                              DNA_V2_STORAGE_ACTIVE) ? 1 : 0;
    } else if (rc != SQLITE_DONE) {
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* Segment k is published. @return 1 / 0 / -1 */
static int segment_published(nodus_witness_t *w, uint64_t k) {
    sqlite3_stmt *st = NULL;
    if (k > (uint64_t)INT64_MAX) return 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_storage_segments WHERE k = ?1", -1, &st, NULL)
            != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

nodus_stfetch_code_t nodus_witness_stfetch_serve(
        nodus_witness_t *w, nodus_cmt_store_t *store, const char *seg_dir,
        const uint8_t sender_fp[64], const nodus_stfetch_req_t *req,
        uint64_t E, uint8_t *out, size_t cap, size_t *len_out) {
    if (!w || !w->db || !sender_fp || !req || !out || !len_out || E == 0)
        return NODUS_STFETCH_REF_FAULT;
    *len_out = 0;

    /* 1. the requester: an ACTIVE member of the CURRENT frozen set */
    uint64_t tip = 0, H = 0;
    if (nodus_witness_v2_tip_height(w, &tip) != 0)
        return NODUS_STFETCH_REF_FAULT;
    if (nodus_stprobe_epoch_for_tip(tip, E, &H) != 0)
        return NODUS_STFETCH_REF_UNKNOWN_SET;
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    if (!set) return NODUS_STFETCH_REF_FAULT;
    nodus_stfetch_code_t c = NODUS_STFETCH_REF_FAULT;
    int rc = nodus_witness_storage_set_get(w, H, set);
    if (rc == 1) { c = NODUS_STFETCH_REF_UNKNOWN_SET; goto done; }
    if (rc != 0) goto done;
    {
        bool member = false;
        for (uint32_t i = 0; i < set->count && !member; i++)
            member = memcmp(set->fps[i], sender_fp, 64) == 0;
        if (!member) { c = NODUS_STFETCH_REF_NOT_MEMBER; goto done; }
    }
    rc = registry_active(w, sender_fp);
    if (rc < 0) goto done;
    if (rc == 0) { c = NODUS_STFETCH_REF_NOT_MEMBER; goto done; }

    /* 2. an archive segment, published */
    rc = segment_published(w, req->k);
    if (rc < 0) goto done;
    if (rc == 0) { c = NODUS_STFETCH_REF_NOT_PUBLISHED; goto done; }

    /* 3. the piece */
    c = nodus_stfetch_answer_build(store, seg_dir, req, out, cap, len_out);
done:
    free(set);
    return c;
}
