/**
 * @file nodus_witness_storage_segment_export.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the STORE-BACKED half of the segment file: export a segment from
 *        this node's cometbft block store, and validators(k·P) from its
 *        state store (the K8a set record). Declared in
 *        nodus_witness_storage_segment.h ("export from this node's block
 *        store", "helpers shared with the wire").
 *
 * Split out of nodus_witness_storage_segment.c by package P-B4 (design
 * docs/plans/2026-10-19-windows-light-storage-design.md §3 "Rev 1
 * corrections", B4): the file format, the build, the reader and the
 * deletion are portable and compile on Windows; this half needs a full
 * node's block / state store and stays in the Linux-only source list. It
 * drives the build only through its public calls (nodus_seg_build_next /
 * _put_*), so every piece passes the build's verification exactly as
 * before the split.
 *
 * Nothing here reads a clock, draws randomness or writes the database: the
 * block store and the state store are READ; the only writes are the
 * build's own (its segment file).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_segment.h"

#include "dnac/cmt_pb.h"

#include "crypto/utils/qgp_log.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STSEG"

#define SEG_P  ((uint64_t)NODUS_SEG_COUNT)

/* The scratch for the set and the terminal commit: the widest of the two
 * (the build's own I/O scratch had this size). */
#define EXPORT_TAIL_CAP  ((size_t)NODUS_SEG_COMMIT_MAX)

bool nodus_seg_store_has(const nodus_cmt_store_t *store, uint64_t k) {
    if (!store || k == 0 || k > ((uint64_t)INT64_MAX - 1u) / SEG_P - 1u)
        return false;
    const int64_t base = nodus_cmt_bs_base(store);
    const int64_t height = nodus_cmt_bs_height(store);
    return base >= 1 && (uint64_t)base <= (k - 1u) * SEG_P + 1u &&
           height >= 1 && (uint64_t)height >= k * SEG_P + 1u;
}

/* A raw block-store value (the store's own key strings, store.go:632-640
 * as nodus_witness_cmt_store.h maps them). *v valid until the next get on
 * that table. @return 0 found / 1 absent / -1 */
static int store_raw(nodus_cmt_store_t *s, const char *key,
                     const uint8_t **v, size_t *n) {
    if (nodus_cmt_store_get(s, false, key, v, n) != CMT_OK) return -1;
    return *n == 0 ? 1 : 0;
}

/* What the build needs next, while it is still on a height: 1 and *h /
 * *part / *hdr_needed (nodus_seg_build_next), or 0 once every height is
 * written (the set, the commit or nothing is next). */
static int on_height(const nodus_seg_build_t *b, uint64_t *h, uint32_t *part,
                     bool *hdr_needed) {
    return nodus_seg_build_next(b, h, part, hdr_needed) == 0 &&
           *part < NODUS_SEG_PART_VALSET;
}

int nodus_seg_export_step(nodus_seg_build_t *b, nodus_cmt_store_t *store,
                          uint32_t max_heights, nodus_seg_v_t *why_out) {
    if (why_out) *why_out = NODUS_SEG_V_OK;
    uint64_t h = 0;
    uint32_t part = 0;
    bool hdr_needed = false;
    /* -1 from next: the resume scan is not over */
    if (!b || !store || nodus_seg_build_next(b, &h, &part, &hdr_needed) < 0)
        return -1;
    const uint64_t last = nodus_seg_build_k(b) * SEG_P;
    nodus_cmt_block_meta_t *meta = malloc(sizeof(*meta));
    uint8_t *hb = malloc(NODUS_SEG_HEADER_MAX);
    uint8_t *tail = NULL;
    int ret = -1;
    nodus_seg_v_t v = NODUS_SEG_V_OK;
    uint64_t at_h = last + 1u;          /* the build's height, for the log */
    char key[NODUS_CMT_STORE_KEY_MAX];
    if (!meta || !hb) goto done;

    for (uint32_t n = 0; n < max_heights &&
                         on_height(b, &h, &part, &hdr_needed); n++) {
        const uint64_t hh = h;
        at_h = hh;
        if (hdr_needed) {
            bool found = false;
            size_t hl = 0;
            if (nodus_cmt_bs_load_block_meta(store, (int64_t)(hh + 1u), meta,
                                             &found) != CMT_OK)
                goto done;
            if (!found) {
                QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": block meta %"
                             PRIu64 " not in the block store",
                             nodus_seg_build_k(b), hh + 1u);
                goto done;
            }
            if (cmt_pb_header_marshal(&meta->header, hb, NODUS_SEG_HEADER_MAX,
                                      &hl) != CMT_OK || hl == 0)
                goto done;
            v = nodus_seg_build_put_header(b, hh, hb, hl);
            if (v != NODUS_SEG_V_OK) goto done;
        }
        /* the parts of hh, in index order, until the build moves on */
        while (on_height(b, &h, &part, &hdr_needed) && h == hh) {
            const uint8_t *val = NULL;
            size_t vl = 0;
            snprintf(key, sizeof(key), "P:%" PRId64 ":%d", (int64_t)hh,
                     (int)part);
            int r = store_raw(store, key, &val, &vl);
            if (r < 0) goto done;
            if (r > 0) {
                QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": %s not in the "
                             "block store", nodus_seg_build_k(b), key);
                goto done;
            }
            /* put copies the value into the build before any other get */
            v = nodus_seg_build_put_part_proto(b, hh, part, val, vl);
            if (v != NODUS_SEG_V_OK) goto done;
        }
    }
    if (on_height(b, &h, &part, &hdr_needed)) { ret = 0; goto done; }
    at_h = last + 1u;

    if (nodus_seg_build_next(b, &h, &part, &hdr_needed) == 0 &&
        part == NODUS_SEG_PART_VALSET) {
        /* validators(k·P) from the state table (K8a); a pruned state store
         * cannot finish the export — the holder fetches the set */
        size_t vl = 0;
        tail = malloc(EXPORT_TAIL_CAP);
        if (!tail) goto done;
        int r = nodus_seg_valset_from_store(store, last, tail,
                                            EXPORT_TAIL_CAP, &vl);
        if (r < 0) goto done;
        if (r > 0) {
            QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": validators(%" PRIu64
                         ") not in this node's state store — the export "
                         "cannot verify the terminal commit, the set is "
                         "fetched", nodus_seg_build_k(b), last);
            goto done;
        }
        v = nodus_seg_build_put_valset(b, tail, vl);
        if (v != NODUS_SEG_V_OK) goto done;
    }
    if (nodus_seg_build_next(b, &h, &part, &hdr_needed) == 0 &&
        part == NODUS_SEG_PART_COMMIT) {
        const uint8_t *val = NULL;
        size_t vl = 0;
        snprintf(key, sizeof(key), "C:%" PRId64, (int64_t)last);
        int r = store_raw(store, key, &val, &vl);
        if (r < 0) goto done;
        if (r > 0) {
            QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": %s not in the block "
                         "store", nodus_seg_build_k(b), key);
            goto done;
        }
        /* `val` points into the store's block-table copy buffer, valid
         * until the next block-table get. Copied into this step's own
         * scratch all the same, so no store call can ever move it (the set
         * is already held in the build's own buffer). */
        if (vl > EXPORT_TAIL_CAP) { v = NODUS_SEG_V_BOUNDS; goto done; }
        if (!tail && !(tail = malloc(EXPORT_TAIL_CAP))) goto done;
        memcpy(tail, val, vl);
        v = nodus_seg_build_put_commit(b, tail, vl);
        if (v != NODUS_SEG_V_OK) goto done;
    }
    ret = 1;
done:
    if (ret < 0 && v != NODUS_SEG_V_OK)
        QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": export refused at "
                      "height %" PRIu64 " (%s) — this node's block store "
                      "disagrees with the build's trusted block hashes "
                      "(v2_blocks on the ledger source)",
                      nodus_seg_build_k(b), at_h, nodus_seg_v_str(v));
    if (why_out) *why_out = v;
    free(tail);
    free(hb);
    free(meta);
    return ret;
}

int nodus_seg_valset_from_store(nodus_cmt_store_t *store, uint64_t height,
                                uint8_t *out, size_t cap, size_t *len) {
    if (!store || !out || !len || height == 0 ||
        height > (uint64_t)INT64_MAX)
        return -1;
    int ret = -1;
    cmt_validator_t        *vals = calloc(CMT_VALSET_MAX, sizeof(*vals));
    cmt_pb_validator_t     *pbv = calloc(CMT_VALSET_MAX, sizeof(*pbv));
    cmt_pb_validator_set_t *pb = calloc(1, sizeof(*pb));
    cmt_validator_set_t vs;
    if (!vals || !pbv || !pb ||
        cmt_validator_set_init(&vs, vals, CMT_VALSET_MAX) != CMT_OK)
        goto done;
    /* LoadValidators (the port in nodus_witness_cmt_store.c): the set at
     * `height`, also when its row is not a checkpoint */
    int rc = nodus_cmt_ss_load_validators(store, (int64_t)height, &vs);
    if (rc == CMT_FAULT) goto done;
    if (rc != CMT_OK) { ret = 1; goto done; }
    pb->validators = pbv;
    pb->validators_cap = CMT_VALSET_MAX;
    size_t n = 0;
    if (cmt_validator_set_to_proto(&vs, pb) != CMT_OK ||
        cmt_pb_validator_set_marshal(pb, out, cap, &n) != CMT_OK ||
        n == 0 || n > NODUS_SEG_VALSET_MAX)
        goto done;
    *len = n;
    ret = 0;
done:
    free(pb);
    free(pbv);
    free(vals);
    return ret;
}
