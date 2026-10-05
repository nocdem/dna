/**
 * @file nodus_witness_storage_probe.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-1 —
 *        the transport-independent half of the archive probe. Contract,
 *        wire layout, the checks and the determinism statement:
 *        nodus_witness_storage_probe.h.
 *
 * Nothing here reads a clock or draws randomness: the caller hands in the
 * nonce, the wall-clock and monotonic readings. Nothing here writes
 * consensus state; the report builder only produces bytes the caller
 * submits to the mempool like any client would.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_probe.h"
#include "witness/nodus_witness_v2_storage.h"   /* nodus_storage_eligible_height */
#include "witness/nodus_witness_runtime.h"      /* NODUS_RT_AUTHKIND_*,
                                                 * DNA_SYSRULE_STORAGE_REPORT */

#include "dnac/cmt_block.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_pb.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STPROBE"

#define STP_PK_LEN    ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define STP_AUTH_LEN  (1u + NODUS_RT_AUTH_SIGNER_LEN)

_Static_assert(STP_PK_LEN == 2592u, "the node key is ML-DSA-87");
_Static_assert(NODUS_STPROBE_REPORT_CALL_MAX == 110u,
               "the report call bound is rt_native.c RTN_STREP_CALL_MAX");

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

static void stp_tag(uint8_t out[NODUS_STPROBE_TAG_LEN]) {
    memset(out, 0, NODUS_STPROBE_TAG_LEN);
    memcpy(out, NODUS_STPROBE_TAG, sizeof(NODUS_STPROBE_TAG) - 1);
}
_Static_assert(sizeof(NODUS_STPROBE_TAG) - 1 <= NODUS_STPROBE_TAG_LEN,
               "the tag fits its 16 bytes");

/* ══════════════════════════════════════════════════════════════════════
 * The request
 * ════════════════════════════════════════════════════════════════════ */

/* The 288 body bytes, in the bytes doc §6 order. */
static void req_body(const nodus_stprobe_req_t *r,
                     uint8_t b[NODUS_STPROBE_REQ_LEN]) {
    size_t off = 0;
    stp_tag(b);                                 off += NODUS_STPROBE_TAG_LEN;
    memcpy(b + off, r->chain_id, DNA_CHAIN_ID_LEN); off += DNA_CHAIN_ID_LEN;
    put64(b + off, r->epoch_start);             off += 8;
    memcpy(b + off, r->set_hash, 64);           off += 64;
    memcpy(b + off, r->target_fp, 64);          off += 64;
    memcpy(b + off, r->reporter_fp, 64);        off += 64;
    memcpy(b + off, r->nonce, DNA_V2_STORAGE_NONCE_LEN);
    off += DNA_V2_STORAGE_NONCE_LEN;
    put64(b + off, r->deadline_ms);
}

int nodus_stprobe_req_encode(const nodus_stprobe_req_t *req,
                             uint8_t out[NODUS_STPROBE_REQ_MSG_LEN]) {
    if (!req || !out) return -1;
    out[0] = NODUS_STPROBE_KIND_REQ;
    req_body(req, out + 1);
    return 0;
}

int nodus_stprobe_req_decode(const uint8_t *msg, size_t len,
                             nodus_stprobe_req_t *out) {
    if (!msg || !out || len != NODUS_STPROBE_REQ_MSG_LEN) return -1;
    if (msg[0] != NODUS_STPROBE_KIND_REQ) return -1;
    uint8_t tag[NODUS_STPROBE_TAG_LEN];
    stp_tag(tag);
    const uint8_t *b = msg + 1;
    if (memcmp(b, tag, NODUS_STPROBE_TAG_LEN) != 0) return -1;
    size_t off = NODUS_STPROBE_TAG_LEN;
    memcpy(out->chain_id, b + off, DNA_CHAIN_ID_LEN); off += DNA_CHAIN_ID_LEN;
    out->epoch_start = get64(b + off);                off += 8;
    memcpy(out->set_hash, b + off, 64);               off += 64;
    memcpy(out->target_fp, b + off, 64);              off += 64;
    memcpy(out->reporter_fp, b + off, 64);            off += 64;
    memcpy(out->nonce, b + off, DNA_V2_STORAGE_NONCE_LEN);
    off += DNA_V2_STORAGE_NONCE_LEN;
    out->deadline_ms = get64(b + off);
    return 0;
}

int nodus_stprobe_req_id(const nodus_stprobe_req_t *req, uint8_t rq[64]) {
    if (!req || !rq) return -1;
    uint8_t b[NODUS_STPROBE_REQ_LEN];
    req_body(req, b);
    return qgp_sha3_512(b, sizeof(b), rq) == 0 ? 0 : -1;
}

nodus_stprobe_code_t nodus_stprobe_req_check(const nodus_stprobe_req_t *req,
                                             const uint8_t own_fp[64],
                                             const uint8_t own_chain[DNA_CHAIN_ID_LEN],
                                             const uint8_t sender_fp[64],
                                             uint64_t E,
                                             uint64_t now_wall_ms) {
    if (!req || !own_fp || !own_chain || !sender_fp || E == 0)
        return NODUS_STPROBE_REF_FAULT;
    if (memcmp(req->chain_id, own_chain, DNA_CHAIN_ID_LEN) != 0)
        return NODUS_STPROBE_REF_WRONG_CHAIN;
    if (memcmp(req->target_fp, own_fp, 64) != 0)
        return NODUS_STPROBE_REF_NOT_ADDRESSED;
    /* the request is the authenticated sender's own: no third party can
     * spend a reporter's identity on this node's work */
    if (memcmp(req->reporter_fp, sender_fp, 64) != 0)
        return NODUS_STPROBE_REF_NOT_REPORTER;
    if (req->epoch_start < E || (req->epoch_start % E) != 0)
        return NODUS_STPROBE_REF_MALFORMED;
    if (now_wall_ms > req->deadline_ms)
        return NODUS_STPROBE_REF_LATE;
    return NODUS_STPROBE_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * The samples
 * ════════════════════════════════════════════════════════════════════ */

int nodus_stprobe_samples(const uint8_t nonce[DNA_V2_STORAGE_NONCE_LEN],
                          const uint8_t target_fp[64],
                          const uint64_t *ks, size_t n,
                          uint8_t x_out[DNA_V2_STORAGE_SAMPLES][64],
                          uint64_t h_out[DNA_V2_STORAGE_SAMPLES]) {
    if (!nonce || !target_fp || !ks || !x_out || !h_out) return -1;
    if (n == 0 || n > NODUS_STPROBE_MAX_SEGS) return -1;
    const uint64_t B = (uint64_t)n * (uint64_t)DNA_V2_SEGMENT_BLOCKS;
    for (uint32_t i = 0; i < DNA_V2_STORAGE_SAMPLES; i++) {
        uint64_t pos = 0;
        if (dna_v2_storage_sample_x(nonce, target_fp, i, x_out[i]) != 0)
            return -1;
        /* parts_total is not known before header(h+1) is read: 1 here
         * gives the block index alone (x mod B is independent of it) */
        if (dna_v2_storage_sample_index(x_out[i], B, 1u, &pos, NULL) != 0)
            return -1;
        if (nodus_storage_eligible_height(ks, n, pos, &h_out[i]) != 0)
            return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * The answer
 * ════════════════════════════════════════════════════════════════════ */

int nodus_stprobe_ans_refusal(const uint8_t rq[64], uint8_t code,
                              uint8_t out[NODUS_STPROBE_REFUSAL_LEN]) {
    if (!rq || !out || code == NODUS_STPROBE_OK) return -1;
    out[0] = NODUS_STPROBE_KIND_ANS;
    memcpy(out + 1, rq, 64);
    out[65] = code;
    return 0;
}

int nodus_stprobe_ans_decode(const uint8_t *msg, size_t len,
                             nodus_stprobe_ans_view_t *out) {
    if (!msg || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (len < NODUS_STPROBE_REFUSAL_LEN || len > NODUS_STPROBE_MSG_MAX)
        return -1;
    if (msg[0] != NODUS_STPROBE_KIND_ANS) return -1;
    memcpy(out->rq, msg + 1, 64);
    out->code = msg[65];
    if (out->code != NODUS_STPROBE_OK)
        return len == NODUS_STPROBE_REFUSAL_LEN ? 0 : -1;
    size_t off = NODUS_STPROBE_REFUSAL_LEN;
    for (uint32_t i = 0; i < DNA_V2_STORAGE_SAMPLES; i++) {
        nodus_stprobe_sample_view_t *s = &out->s[i];
        const uint32_t bounds[3] = { NODUS_STPROBE_HEADER_MAX,
                                     CMT_BLOCK_PART_SIZE_BYTES,
                                     NODUS_STPROBE_PROOF_MAX };
        const uint8_t *ptr[3] = { NULL, NULL, NULL };
        uint32_t lens[3] = { 0, 0, 0 };
        for (int f = 0; f < 3; f++) {
            if (len - off < 4) return -1;
            uint32_t l = get32(msg + off);
            off += 4;
            if (l > bounds[f] || (size_t)l > len - off) return -1;
            ptr[f] = msg + off;
            lens[f] = l;
            off += l;
        }
        if (lens[0] == 0 || lens[2] == 0) return -1;
        s->header = ptr[0]; s->header_len = lens[0];
        s->part = ptr[1];   s->part_len = lens[1];
        s->proof = ptr[2];  s->proof_len = lens[2];
    }
    return off == len ? 0 : -1;              /* no trailing byte */
}

int nodus_stprobe_answer_begin(const uint8_t rq[64], uint8_t *out,
                               size_t cap, size_t *off) {
    if (!rq || !out || !off || cap < NODUS_STPROBE_REFUSAL_LEN) return -1;
    out[0] = NODUS_STPROBE_KIND_ANS;
    memcpy(out + 1, rq, 64);
    out[65] = NODUS_STPROBE_OK;
    *off = NODUS_STPROBE_REFUSAL_LEN;
    return 0;
}

int nodus_stprobe_sample_put(uint8_t *out, size_t cap, size_t *off,
                             const uint8_t *hdr, size_t hdr_len,
                             const uint8_t *part, size_t part_len,
                             const uint8_t *proof, size_t proof_len) {
    if (!out || !off || !hdr || !proof || (!part && part_len) ||
        *off > cap || hdr_len == 0 || hdr_len > NODUS_STPROBE_HEADER_MAX ||
        part_len > CMT_BLOCK_PART_SIZE_BYTES || proof_len == 0 ||
        proof_len > NODUS_STPROBE_PROOF_MAX)
        return -1;
    if (cap - *off < 12u + hdr_len + part_len + proof_len) return -1;
    size_t o = *off;
    put32(out + o, (uint32_t)hdr_len);    o += 4;
    memcpy(out + o, hdr, hdr_len);         o += hdr_len;
    put32(out + o, (uint32_t)part_len);   o += 4;
    if (part_len) memcpy(out + o, part, part_len);
    o += part_len;
    put32(out + o, (uint32_t)proof_len);  o += 4;
    memcpy(out + o, proof, proof_len);     o += proof_len;
    *off = o;
    return 0;
}

nodus_stprobe_code_t nodus_stprobe_sample_from_store(
        nodus_cmt_store_t *store, const uint8_t x[64], uint64_t B,
        uint64_t h, uint8_t *out, size_t cap, size_t *off) {
    if (!store || !x || !out || !off || B == 0 || *off > cap)
        return NODUS_STPROBE_REF_FAULT;
    if (h == 0 || h >= (uint64_t)INT64_MAX) return NODUS_STPROBE_REF_FAULT;

    nodus_stprobe_code_t ret = NODUS_STPROBE_REF_FAULT;
    nodus_cmt_block_meta_t *meta = malloc(sizeof(*meta));
    cmt_part_t *part = malloc(sizeof(*part));
    uint8_t *pbuf = malloc(CMT_BLOCK_PART_SIZE_BYTES);
    uint8_t *hbuf = malloc(NODUS_STPROBE_HEADER_MAX);
    uint8_t *prf = malloc(NODUS_STPROBE_PROOF_MAX);
    if (!meta || !part || !pbuf || !hbuf || !prf) goto done;

    bool found = false;
    /* header(h+1): its last_block_id IS block_id(h) with the parts root
     * (cmt_pb.h header field 5) */
    if (nodus_cmt_bs_load_block_meta(store, (int64_t)(h + 1), meta,
                                     &found) != CMT_OK)
        goto done;
    if (!found) { ret = NODUS_STPROBE_REF_NOT_HELD; goto done; }
    const uint32_t total = meta->header.last_block_id.part_set_header.total;
    if (total == 0 || total > CMT_PART_SET_MAX_PARTS) {
        ret = NODUS_STPROBE_REF_NOT_HELD;
        goto done;
    }
    uint32_t pi = 0;
    if (dna_v2_storage_sample_index(x, B, total, NULL, &pi) != 0) goto done;

    /* header(h+1) proto */
    size_t hl = 0;
    if (cmt_pb_header_marshal(&meta->header, hbuf, NODUS_STPROBE_HEADER_MAX,
                              &hl) != CMT_OK || hl == 0)
        goto done;

    /* the part and its proof, as stored */
    cmt_pb_arena_t arena = { pbuf, CMT_BLOCK_PART_SIZE_BYTES, 0 };
    if (nodus_cmt_bs_load_block_part(store, (int64_t)h, (int)pi, &arena,
                                     part, &found) != CMT_OK)
        goto done;
    if (!found) { ret = NODUS_STPROBE_REF_NOT_HELD; goto done; }
    if (part->bytes.len > CMT_BLOCK_PART_SIZE_BYTES) goto done;
    size_t pl = 0;
    if (cmt_pb_proof_marshal(&part->proof, prf, NODUS_STPROBE_PROOF_MAX,
                             &pl) != CMT_OK || pl == 0)
        goto done;
    if (nodus_stprobe_sample_put(out, cap, off, hbuf, hl, part->bytes.data,
                                 part->bytes.len, prf, pl) != 0)
        goto done;
    ret = NODUS_STPROBE_OK;
done:
    free(prf);
    free(hbuf);
    free(pbuf);
    free(part);
    free(meta);
    return ret;
}

nodus_stprobe_code_t nodus_stprobe_answer_build(
        nodus_cmt_store_t *store, const uint8_t rq[64],
        const uint8_t x[DNA_V2_STORAGE_SAMPLES][64],
        const uint64_t h[DNA_V2_STORAGE_SAMPLES], uint64_t B,
        uint8_t *out, size_t cap, size_t *len_out) {
    if (!store || !rq || !x || !h || !out || !len_out || B == 0 ||
        cap < NODUS_STPROBE_REFUSAL_LEN)
        return NODUS_STPROBE_REF_FAULT;
    *len_out = 0;
    size_t off = 0;
    if (nodus_stprobe_answer_begin(rq, out, cap, &off) != 0)
        return NODUS_STPROBE_REF_FAULT;
    for (uint32_t i = 0; i < DNA_V2_STORAGE_SAMPLES; i++) {
        nodus_stprobe_code_t c = nodus_stprobe_sample_from_store(
            store, x[i], B, h[i], out, cap, &off);
        if (c != NODUS_STPROBE_OK) return c;
    }
    *len_out = off;
    return NODUS_STPROBE_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * The verification chain (bytes doc §6 checks)
 * ════════════════════════════════════════════════════════════════════ */

nodus_stprobe_verify_t nodus_stprobe_verify_sample(
        const uint8_t x[64], uint64_t B, uint64_t h,
        const uint8_t hash_h[64], const uint8_t hash_h1[64],
        const nodus_stprobe_sample_view_t *s) {
    if (!x || !hash_h || !hash_h1 || !s || B == 0 ||
        h == 0 || h >= (uint64_t)INT64_MAX)
        return NODUS_STPROBE_V_FAULT;
    if (!s->header || s->header_len == 0 ||
        s->header_len > NODUS_STPROBE_HEADER_MAX ||
        (!s->part && s->part_len != 0) ||
        s->part_len > CMT_BLOCK_PART_SIZE_BYTES ||
        !s->proof || s->proof_len == 0 ||
        s->proof_len > NODUS_STPROBE_PROOF_MAX)
        return NODUS_STPROBE_V_BOUNDS;

    nodus_stprobe_verify_t ret = NODUS_STPROBE_V_FAULT;
    cmt_pb_header_t *hdr = malloc(sizeof(*hdr));
    cmt_part_t *part = malloc(sizeof(*part));
    if (!hdr || !part) goto done;

    /* 1. header(h+1) is the one this node committed at h+1 */
    cmt_pb_header_init(hdr);
    if (cmt_pb_header_unmarshal(s->header, s->header_len, hdr) != CMT_OK) {
        ret = NODUS_STPROBE_V_HEADER_DECODE;
        goto done;
    }
    {
        uint8_t hh[CMT_TMHASH_SIZE];
        int rc = cmt_header_hash(hdr, hh);
        if (rc == CMT_FAULT) goto done;
        if (rc != CMT_OK || memcmp(hh, hash_h1, 64) != 0) {
            ret = NODUS_STPROBE_V_HEADER_HASH;
            goto done;
        }
    }
    if (hdr->height != (int64_t)(h + 1)) {
        ret = NODUS_STPROBE_V_HEADER_HEIGHT;
        goto done;
    }

    /* 2. its last_block_id is block_id(h) */
    const cmt_pb_block_id_t *bid = &hdr->last_block_id;
    if (bid->hash_len != 64 || memcmp(bid->hash, hash_h, 64) != 0) {
        ret = NODUS_STPROBE_V_BLOCK_ID;
        goto done;
    }
    const uint32_t total = bid->part_set_header.total;
    if (total == 0 || total > CMT_PART_SET_MAX_PARTS ||
        bid->part_set_header.hash_len != CMT_TMHASH_SIZE) {
        ret = NODUS_STPROBE_V_PART_TOTAL;
        goto done;
    }

    /* 3. the sampled part index, from x and THIS header's part count */
    uint32_t pi = 0;
    if (dna_v2_storage_sample_index(x, B, total, NULL, &pi) != 0) goto done;

    /* 4. the proof: decodes, is basic-valid, names that part of that set */
    memset(part, 0, sizeof(*part));
    cmt_pb_proof_init(&part->proof);
    if (cmt_pb_proof_unmarshal(s->proof, s->proof_len, &part->proof)
            != CMT_OK ||
        cmt_proof_validate_basic(&part->proof) != CMT_OK) {
        ret = NODUS_STPROBE_V_PROOF_DECODE;
        goto done;
    }
    if (part->proof.index != (int64_t)pi) {
        ret = NODUS_STPROBE_V_PART_INDEX;
        goto done;
    }
    if (part->proof.total != (int64_t)total) {
        ret = NODUS_STPROBE_V_PROOF_TOTAL;
        goto done;
    }

    /* 5. the reference's Part.ValidateBasic (part_set.go:45-60: size,
     *    full parts but the last, index == proof index) */
    part->index = pi;
    part->bytes.data = s->part;
    part->bytes.len = s->part_len;
    {
        int rc = cmt_part_validate_basic(part);
        if (rc == CMT_FAULT) goto done;
        if (rc != CMT_OK) {
            ret = NODUS_STPROBE_V_PART_BASIC;
            goto done;
        }
    }

    /* 6. the part is in block h's part set */
    {
        int rc = cmt_proof_verify(&part->proof,
                                  bid->part_set_header.hash,
                                  s->part, s->part_len);
        if (rc == CMT_FAULT) goto done;
        if (rc != CMT_OK) {
            ret = NODUS_STPROBE_V_PROOF;
            goto done;
        }
    }
    ret = NODUS_STPROBE_V_OK;
done:
    free(part);
    free(hdr);
    return ret;
}

bool nodus_stprobe_answer_ok(const nodus_stprobe_ans_view_t *a,
                             const uint8_t expect_rq[64],
                             const uint8_t x[DNA_V2_STORAGE_SAMPLES][64],
                             uint64_t B,
                             const uint64_t h[DNA_V2_STORAGE_SAMPLES],
                             const uint8_t hash_h[DNA_V2_STORAGE_SAMPLES][64],
                             const uint8_t hash_h1[DNA_V2_STORAGE_SAMPLES][64],
                             int64_t now_mono_ms, int64_t deadline_mono_ms) {
    if (!a || !expect_rq || !x || !h || !hash_h || !hash_h1) return false;
    if (now_mono_ms > deadline_mono_ms) return false;        /* late       */
    if (memcmp(a->rq, expect_rq, 64) != 0) return false;
    if (a->code != NODUS_STPROBE_OK) return false;
    for (uint32_t i = 0; i < DNA_V2_STORAGE_SAMPLES; i++) {
        nodus_stprobe_verify_t v = nodus_stprobe_verify_sample(
            x[i], B, h[i], hash_h[i], hash_h1[i], &a->s[i]);
        if (v != NODUS_STPROBE_V_OK) {
            QGP_LOG_DEBUG(LOG_TAG, "sample %u at height %llu refused (%d)",
                          (unsigned)i, (unsigned long long)h[i], (int)v);
            return false;
        }
    }
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * The report
 * ════════════════════════════════════════════════════════════════════ */

int nodus_stprobe_report_call(uint64_t epoch_start, uint32_t seat,
                              const uint8_t set_hash[64],
                              const bool *ok, uint32_t count,
                              uint8_t out[NODUS_STPROBE_REPORT_CALL_MAX],
                              size_t *len_out) {
    if (!set_hash || !out || !len_out) return -1;
    if (count > DNA_V2_STORAGE_SET_MAX) return -1;
    if (count > 0 && !ok) return -1;
    const uint16_t bl = (uint16_t)((count + 7u) / 8u);
    put64(out, epoch_start);
    put32(out + 8, seat);
    memcpy(out + 12, set_hash, 64);
    out[76] = (uint8_t)(bl >> 8);
    out[77] = (uint8_t)bl;
    memset(out + 78, 0, bl);
    for (uint32_t i = 0; i < count; i++)
        if (ok[i]) out[78 + i / 8u] |= (uint8_t)(1u << (i % 8u));
    *len_out = 78u + bl;
    return 0;
}

int nodus_stprobe_report_env(const uint8_t chain32[DNA_CHAIN_ID_LEN],
                             uint32_t sys_version,
                             const uint8_t sys_hash[64],
                             uint64_t applying_height, uint64_t expiry,
                             const uint8_t *call, size_t call_len,
                             const uint8_t *pk, const uint8_t *sk,
                             uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (!chain32 || !sys_hash || !call || !pk || !sk) return -1;
    if (call_len < 78u || call_len > NODUS_STPROBE_REPORT_CALL_MAX) return -1;
    if (applying_height == 0 || expiry < applying_height) return -1;

    uint8_t *auth = calloc(1, STP_AUTH_LEN);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    uint8_t *bytes = NULL;
    int ret = -1;
    if (!auth || !pf) goto done;

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_STORAGE_REPORT;
    leg.hdr.ruleset_version = sys_version;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len = (uint32_t)call_len;
    leg.hdr.auth_len = STP_AUTH_LEN;
    leg.hdr.res_max_effects = NODUS_STPROBE_REPORT_EFFECTS;
    leg.hdr.res_max_effect_bytes = NODUS_STPROBE_REPORT_EFFECT_BYTES;
    leg.call_data = call;
    leg.auth_data = auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height = expiry;
    in.fee_amount = 0;                       /* no SYSTEM fee sink       */
    in.res_max_total_units = NODUS_STPROBE_REPORT_UNITS;
    in.leg_count = 1;
    in.legs = &leg;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys_version;
    memcpy(lctx.ruleset_hash, sys_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(&leg, 1, &len) != 0 || len == 0) goto done;
    bytes = malloc(len);
    if (!bytes) goto done;
    /* encode with a zero signer, preflight for the leg's auth digest,
     * sign it, encode again — the signature covers the digest, not the
     * auth bytes (env_preflight.h step 8) */
    if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) goto done;
    if (dna_env_preflight(bytes, len, chain32, applying_height, &lctx, 1,
                          pf) != DNA_ENV_PF_OK)
        goto done;
    {
        size_t sl = 0;
        auth[0] = 1;                         /* one signer               */
        memcpy(auth + 1, pk, STP_PK_LEN);
        if (qgp_dsa87_sign(auth + 1 + STP_PK_LEN, &sl, pf->auth_digest[0],
                           64, sk) != 0 ||
            sl != (size_t)QGP_DSA87_SIGNATURE_BYTES)
            goto done;
    }
    if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) goto done;
    *out = bytes;
    *out_len = len;
    bytes = NULL;
    ret = 0;
done:
    free(bytes);
    free(pf);
    if (auth) {
        memset(auth, 0, STP_AUTH_LEN);
        free(auth);
    }
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * Epoch arithmetic
 * ════════════════════════════════════════════════════════════════════ */

int nodus_stprobe_epoch_for_tip(uint64_t tip, uint64_t E, uint64_t *H_out) {
    if (!H_out || E == 0) return -1;
    const uint64_t H = (tip / E) * E;
    if (H < E) return -1;
    *H_out = H;
    return 0;
}

uint64_t nodus_stprobe_slot_height(uint64_t H, uint64_t E, size_t j,
                                   size_t n) {
    if (n == 0 || j >= n) return H;
    const uint64_t span = (E / 4u) * 3u + ((E % 4u) * 3u) / 4u; /* ⌊3E/4⌋ */
    /* j < n <= 256 and span <= E: the product cannot wrap for any epoch
     * length a chain could carry (E < 2^55) */
    return H + ((uint64_t)j * span) / (uint64_t)n;
}

int nodus_stprobe_report_window(uint64_t H, uint64_t E, uint64_t tip,
                                uint64_t *expiry_out) {
    if (!expiry_out || E == 0) return -1;
    if (H > UINT64_MAX - E || H + E > UINT64_MAX - E / 2u) return -1;
    if (tip == UINT64_MAX) return -1;
    const uint64_t open = H + E, close = H + E + E / 2u;
    const uint64_t app = tip + 1u;
    if (app <= open) return 1;
    if (app > close) return -1;
    uint64_t exp = close;
    if (tip <= UINT64_MAX - NODUS_CMT_APP_MAX_EXPIRY_AHEAD &&
        tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD < exp)
        exp = tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD;
    *expiry_out = exp;
    return 0;
}
