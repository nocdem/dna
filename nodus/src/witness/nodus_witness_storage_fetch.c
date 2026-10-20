/**
 * @file nodus_witness_storage_fetch.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the channel 0x73 segment fetch: the serving side (the piece
 *        from this node's block / state store or its held file, and the
 *        admission). Contract, layout, admission and the determinism
 *        statement: nodus_witness_storage_fetch.h. The wire is approved
 *        (decision K6b, 2026-10-07); its encode / decode is
 *        nodus_witness_storage_fetch_wire.c (portable, package P-B2).
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

#include "crypto/utils/qgp_log.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STFETCH"

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
    if (!req || !out || !len_out || !nodus_stfetch_req_valid(req))
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

/* The live registry row of `fp` is ACTIVE. @return 1 / 0 / -1
 * A row whose status is not an INTEGER is a malformed committed row —
 * a FAULT (-1), never a value. */
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
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER)
            ret = -1;
        else
            ret = sqlite3_column_int64(st, 0) == (sqlite3_int64)
                                                 DNA_V2_STORAGE_ACTIVE ? 1 : 0;
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
