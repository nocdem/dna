/**
 * @file nodus_witness_role_prune.c
 * @brief Role-based block retention — the decision and its inputs.
 *        Contract: nodus_witness_role_prune.h.
 *
 * Single-threaded: called by the application's Commit on the witness
 * thread, after the COMMIT, outside any transaction.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_role_prune.h"
#include "witness/nodus_witness_cmt_app.h"         /* the retain formula  */
#include "witness/nodus_witness_storage_holder.h"  /* must hold, the dir  */
#include "witness/nodus_witness_storage_segment.h" /* nodus_seg_held      */
#include "witness/nodus_witness_storage_probe.h"   /* epoch_for_tip       */
#include "witness/nodus_witness_host.h"            /* this node's key     */

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <inttypes.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_PRUNE"

/* ══════════════════════════════════════════════════════════════════════
 * The decision (pure)
 * ════════════════════════════════════════════════════════════════════ */

int64_t nodus_role_prune_base(const nodus_prune_in_t *in) {
    if (!in) return 0;
    switch (in->cfg) {
    case NODUS_PRUNE_CFG_EXPLICIT:
        return in->cfg_blocks > 0 ? in->cfg_blocks : 0;
    case NODUS_PRUNE_CFG_AUTO:
        if (!in->is_validator && !in->is_storage) return 0;
        return in->auto_blocks > 0 ? in->auto_blocks : 0;
    case NODUS_PRUNE_CFG_ARCHIVE:
    default:
        return 0;
    }
}

int64_t nodus_role_prune_retain_height(const nodus_prune_in_t *in) {
    if (!in || in->fault || in->cfg == NODUS_PRUNE_CFG_ARCHIVE) return 0;
    const int64_t base = nodus_role_prune_base(in);
    if (base <= 0) return 0;
    int64_t r = nodus_cmt_app_retain_height(in->height, base);
    if (r <= 0) return 0;
    if (in->is_storage) {
        if (in->keep_from_segment > 0 && in->keep_from_segment < r)
            r = in->keep_from_segment;
        if (in->keep_from_unpublished < r)
            r = in->keep_from_unpublished;
    }
    /* R = 1 keeps every block; a clamp below 1 is not a height */
    return r > 1 ? r : 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * The inputs
 * ════════════════════════════════════════════════════════════════════ */

/* 1 a bonded validator (a `validators` row with this consensus pubkey,
 * status ACTIVE or ELIGIBLE — validator.h: the two BONDED states; the
 * column, not pubkey_hash, which is the validator_id under HF-6), 0 not,
 * -1 read error. */
static int read_is_validator(nodus_witness_t *w, const uint8_t *pk) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM validators WHERE pubkey = ?1 AND status IN "
            "(?2, ?3) LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, pk, NODUS_PK_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(st, 3, (int)DNAC_VALIDATOR_ELIGIBLE);
    const int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* 1 a storage member (registry row node_fp = me, status ACTIVE or
 * EXITING), 0 not, -1 read error. */
static int read_is_storage(nodus_witness_t *w, const uint8_t me[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT status FROM v2_storage_nodes WHERE node_fp = ?1", -1,
            &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, me, 64, SQLITE_STATIC);
    int ret;
    const int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW &&
               sqlite3_column_type(st, 0) == SQLITE_INTEGER) {
        const int64_t s = sqlite3_column_int64(st, 0);
        ret = (s == DNA_V2_STORAGE_ACTIVE || s == DNA_V2_STORAGE_EXITING)
                  ? 1 : 0;
    } else {
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* The highest published segment k (0 = none). @return 0 / -1. */
static int read_max_published(nodus_witness_t *w, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT MAX(k) FROM v2_storage_segments",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
            ret = 0;
        } else if (sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                   sqlite3_column_int64(st, 0) >= 1) {
            *out = (uint64_t)sqlite3_column_int64(st, 0);
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* (k−1)·P + 1 — the first height of segment k — as int64 (k >= 1).
 * @return 0 / -1 (past INT64_MAX). */
static int seg_first(uint64_t k, int64_t *out) {
    const uint64_t P = (uint64_t)DNA_V2_SEGMENT_BLOCKS;
    if (k == 0 || k - 1u > ((uint64_t)INT64_MAX - 1u) / P) return -1;
    *out = (int64_t)((k - 1u) * P + 1u);
    return 0;
}

/* Fill rt's must-hold cache for (H, maxk). @return 0 / -1. */
static int cache_fill(nodus_witness_t *w, nodus_role_prune_rt_t *rt,
                      const uint8_t me[64], uint64_t H, uint64_t maxk) {
    rt->have_cache = false;
    free(rt->ks);
    rt->ks = NULL;
    rt->n_ks = 0;
    rt->first_open = 0;
    rt->cache_no_set = false;
    uint64_t *ks = calloc(NODUS_STHOLD_MAX_SEGS, sizeof(*ks));
    size_t n = 0;
    if (!ks) return -1;
    const int rc = nodus_witness_sthold_must_hold(w, H, me, ks,
                                                  NODUS_STHOLD_MAX_SEGS, &n);
    if (rc < 0) {
        free(ks);
        return -1;
    }
    if (rc == 1) {                 /* no storage_set(H): nothing known  */
        free(ks);
        ks = NULL;
        n = 0;
        rt->cache_no_set = true;
    } else if (n == 0) {
        free(ks);
        ks = NULL;
    }
    rt->ks = ks;
    rt->n_ks = n;
    rt->cache_H = H;
    rt->cache_maxk = maxk;
    rt->have_cache = true;
    return 0;
}

/* Advance first_open past every complete file. @return 0 / -1 (a marker
 * that cannot be read: a fault, not "incomplete"). */
static int cache_advance(nodus_witness_t *w, nodus_role_prune_rt_t *rt) {
    if (rt->first_open >= rt->n_ks) return 0;
    char dir[NODUS_SEG_PATH_MAX];
    if (nodus_witness_sthold_dir(w, dir, sizeof(dir)) != 0) return -1;
    while (rt->first_open < rt->n_ks) {
        const int h = nodus_seg_held(dir, rt->ks[rt->first_open]);
        if (h < 0) return -1;
        if (h == 0) break;
        rt->first_open++;
    }
    return 0;
}

static const char *cfg_name(nodus_prune_cfg_t c) {
    return c == NODUS_PRUNE_CFG_AUTO ? "AUTO"
         : c == NODUS_PRUNE_CFG_ARCHIVE ? "ARCHIVE" : "retain_blocks";
}

/* One INFO line whenever the effective mode differs from the last one. */
static void log_mode(nodus_role_prune_rt_t *rt, const nodus_prune_in_t *in,
                     uint64_t open_k, bool no_set) {
    const int64_t base = nodus_role_prune_base(in);
    const int64_t unpub = in->is_storage ? in->keep_from_unpublished : 0;
    if (rt->logged && rt->last_cfg == (int)in->cfg &&
        rt->last_val == in->is_validator && rt->last_sto == in->is_storage &&
        rt->last_fault == in->fault && rt->last_base == base &&
        rt->last_open_k == open_k && rt->last_unpub == unpub)
        return;
    rt->logged = true;
    rt->last_cfg = (int)in->cfg;
    rt->last_val = in->is_validator;
    rt->last_sto = in->is_storage;
    rt->last_fault = in->fault;
    rt->last_base = base;
    rt->last_open_k = open_k;
    rt->last_unpub = unpub;
    if (in->fault) return;          /* logged by the fault path          */

    if (in->cfg == NODUS_PRUNE_CFG_ARCHIVE) {
        QGP_LOG_INFO(LOG_TAG, "%s", "retain: ARCHIVE (retain_blocks 0) — "
                     "every block is kept");
        return;
    }
    const char *role = in->is_validator && in->is_storage
                           ? "validator + storage"
                     : in->is_validator ? "validator"
                     : in->is_storage   ? "storage" : "no role";
    if (base <= 0) {
        if (in->cfg == NODUS_PRUNE_CFG_AUTO &&
            (in->is_validator || in->is_storage))
            QGP_LOG_INFO(LOG_TAG, "retain: AUTO (%s) keeps everything — "
                         "7 paydays does not exceed this chain's evidence "
                         "window (see the start log)", role);
        else
            QGP_LOG_INFO(LOG_TAG, "retain: AUTO (%s) keeps everything",
                         role);
        return;
    }
    if (!in->is_storage) {
        QGP_LOG_INFO(LOG_TAG, "retain: %s (%s) %" PRId64,
                     cfg_name(in->cfg), role, base);
        return;
    }
    if (no_set) {
        QGP_LOG_INFO(LOG_TAG, "retain: %s (%s) %" PRId64 ", guarded: no "
                     "storage set frozen for this epoch yet — every block "
                     "is kept", cfg_name(in->cfg), role, base);
    } else if (open_k != 0) {
        QGP_LOG_INFO(LOG_TAG, "retain: %s (%s) %" PRId64 ", guarded: "
                     "segment %" PRIu64 " incomplete, keep from height %"
                     PRId64 " (unpublished period from %" PRId64 ")",
                     cfg_name(in->cfg), role, base, open_k,
                     in->keep_from_segment, in->keep_from_unpublished);
    } else {
        QGP_LOG_INFO(LOG_TAG, "retain: %s (%s) %" PRId64 ", guarded: every "
                     "assigned segment complete, keep from height %" PRId64
                     " at the latest (the period not yet published)",
                     cfg_name(in->cfg), role, base,
                     in->keep_from_unpublished);
    }
}

static int64_t fault(nodus_role_prune_rt_t *rt, nodus_prune_in_t *in,
                     const char *why) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t ep = in->height > 0 ? (uint64_t)in->height / E : 0;
    if (!rt->fault_logged || rt->fault_epoch != ep) {
        rt->fault_logged = true;
        rt->fault_epoch = ep;
        QGP_LOG_WARN(LOG_TAG, "retain: %s at height %" PRId64 " — nothing "
                     "is pruned until it reads (logged once per epoch)",
                     why, in->height);
    }
    in->fault = true;
    log_mode(rt, in, 0, false);
    return 0;
}

int64_t nodus_role_prune_commit(nodus_witness_t *w, nodus_role_prune_rt_t *rt,
                                int64_t height) {
    if (!w || !rt) return 0;
    nodus_prune_in_t in;
    memset(&in, 0, sizeof(in));
    in.height = height;
    in.auto_blocks = rt->auto_blocks;
    if (w->config.retain_blocks > 0) {
        in.cfg = NODUS_PRUNE_CFG_EXPLICIT;
        in.cfg_blocks = w->config.retain_blocks;
    } else if (w->config.retain_blocks == 0 && w->config.retain_blocks_auto) {
        in.cfg = NODUS_PRUNE_CFG_AUTO;
    } else {
        in.cfg = NODUS_PRUNE_CFG_ARCHIVE;
    }
    if (in.cfg == NODUS_PRUNE_CFG_ARCHIVE) {
        log_mode(rt, &in, 0, false);
        return 0;
    }
    if (!w->db || !w->host || !w->host->identity)
        return fault(rt, &in, "this node's key is not available");

    const uint8_t *pk = w->host->identity->pk.bytes;
    uint8_t me[64];
    if (qgp_sha3_512(pk, NODUS_PK_BYTES, me) != 0)
        return fault(rt, &in, "the node fingerprint did not hash");

    if (in.cfg == NODUS_PRUNE_CFG_AUTO) {
        const int v = read_is_validator(w, pk);
        if (v < 0) return fault(rt, &in, "the validators table is unreadable");
        in.is_validator = v == 1;
    }
    const int s = read_is_storage(w, me);
    if (s < 0) return fault(rt, &in, "the storage registry is unreadable");
    in.is_storage = s == 1;

    uint64_t open_k = 0;
    bool no_set = false;
    if (in.is_storage) {
        uint64_t maxk = 0;
        if (read_max_published(w, &maxk) != 0)
            return fault(rt, &in, "the published segment list is unreadable");
        if (maxk == 0) {
            in.keep_from_unpublished = 1;
        } else if (seg_first(maxk + 1u, &in.keep_from_unpublished) != 0) {
            return fault(rt, &in, "a segment height does not fit");
        }
        uint64_t H = 0;
        if (height <= 0 ||
            nodus_stprobe_epoch_for_tip((uint64_t)height,
                                        (uint64_t)DNAC_EPOCH_LENGTH, &H) != 0) {
            /* below the first epoch: no assignment can exist — keep all */
            no_set = true;
            in.keep_from_segment = 1;
        } else {
            if (!rt->have_cache || rt->cache_H != H || rt->cache_maxk != maxk) {
                if (cache_fill(w, rt, me, H, maxk) != 0)
                    return fault(rt, &in, "the must-hold list is unreadable");
            }
            if (rt->cache_no_set) {
                no_set = true;
                in.keep_from_segment = 1;
            } else {
                if (cache_advance(w, rt) != 0)
                    return fault(rt, &in, "a segment file's marker is "
                                 "unreadable");
                if (rt->first_open < rt->n_ks) {
                    open_k = rt->ks[rt->first_open];
                    if (seg_first(open_k, &in.keep_from_segment) != 0)
                        return fault(rt, &in, "a segment height does not "
                                     "fit");
                }
            }
        }
    }
    log_mode(rt, &in, open_k, no_set);
    return nodus_role_prune_retain_height(&in);
}

void nodus_role_prune_rt_free(nodus_role_prune_rt_t *rt) {
    if (!rt) return;
    free(rt->ks);
    rt->ks = NULL;
    rt->n_ks = 0;
    rt->first_open = 0;
    rt->have_cache = false;
}
