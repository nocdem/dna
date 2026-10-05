/**
 * @file nodus_witness_storage_holder.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the holder's runtime: must-hold, export, the 0x73 fetch client
 *        and serving side, deletion after the overlap, the retain_blocks
 *        warning. Contract: nodus_witness_storage_holder.h.
 *
 * Single-threaded: everything runs on the witness thread — the tick from
 * nodus_witness_tick, a message from the 4004 host's receive callback
 * (inside nodus_witness_p2p_poll on the same thread).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_holder.h"
#include "witness/nodus_witness_storage_segment.h"
#include "witness/nodus_witness_storage_fetch.h"
#include "witness/nodus_witness_storage_probe.h"   /* epoch_for_tip       */
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_v2_produce.h"      /* tip height          */
#include "witness/nodus_witness_cmt_node.h"        /* the store           */
#include "witness/nodus_witness_p2p.h"             /* channel 0x73        */
#include "witness/nodus_witness_host.h"            /* this node's identity */

#include "dnac/dnac.h"
#include "dnac/cmt_conr.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <dirent.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STHOLD"

enum { JOB_NONE = 0, JOB_SCAN, JOB_EXPORT, JOB_FETCH };

struct nodus_sthold_rt {
    int64_t   last_tick_ms;
    /* the assignment of epoch assign_H */
    bool      have_assign;
    uint64_t  assign_H;
    uint64_t *want;                     /* k ascending                   */
    uint8_t  *held;                     /* parallel: 1 = held            */
    size_t    n_want;
    uint64_t  no_export_k;              /* an export that failed: fetch  */
    /* the job */
    nodus_seg_build_t *job;
    int       mode;
    int       next_mode;                /* after the resume scan         */
    /* the fetch client */
    bool      out;
    char      peer[CMT_P2P_ID_CAP];
    uint8_t   rq[64];
    nodus_stfetch_req_t req;
    int64_t   deadline_ms;
    size_t    cand;                     /* the next candidate index      */
    bool      progressed;               /* a verified piece this round   */
    int64_t   retry_at_ms;
    /* the serving side */
    nodus_stfetch_budget_t budget[NODUS_STFETCH_SERVE_SLOTS];
};

static int64_t mono_ms(void) {
    return nodus_p2p_mono_ns(NULL) / 1000000;
}

static void fp_to_peer_id(const uint8_t fp[64], char out[CMT_P2P_ID_CAP]) {
    static const char hexd[] = "0123456789abcdef";
    _Static_assert(CMT_P2P_ID_CAP == 2 * 32 + 1,
                   "a p2p ID is the hex of SHA3-512(pk)[0..31]");
    for (int i = 0; i < 32; i++) {
        out[2 * i] = hexd[fp[i] >> 4];
        out[2 * i + 1] = hexd[fp[i] & 0x0F];
    }
    out[64] = '\0';
}

static int own_fp(nodus_witness_t *w, uint8_t out[64]) {
    if (!w->host || !w->host->identity) return -1;
    return qgp_sha3_512(w->host->identity->pk.bytes, NODUS_PK_BYTES, out)
               == 0 ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * The directory
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_sthold_dir(nodus_witness_t *w, char *out, size_t cap) {
    if (!w || !out || !w->data_path[0]) return -1;
    const char *name = w->config.segment_dir[0] ? w->config.segment_dir
                                                : NODUS_SEG_DIR_DEFAULT;
    if (strchr(name, '/') || strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0 ||
        strnlen(name, NODUS_SEG_DIR_NAME_MAX) >= NODUS_SEG_DIR_NAME_MAX)
        return -1;
    int n = snprintf(out, cap, "%s/%s", w->data_path, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Must hold
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t k;
    uint8_t  root[64];
    uint64_t published;
} sh_seg_t;

/* Every published segment, k ASC (typed). *out malloc'd (NULL when none).
 * @return 0 / -1 */
static int segs_load(nodus_witness_t *w, sh_seg_t **out, size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT k, root, published_height FROM v2_storage_segments "
            "ORDER BY k ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    size_t n = 0, cap = 16;
    sh_seg_t *s = malloc(cap * sizeof(*s));
    int rc, bad = 0;
    if (!s) { sqlite3_finalize(st); return -1; }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
            sqlite3_column_int64(st, 0) < 1 ||
            sqlite3_column_type(st, 1) != SQLITE_BLOB ||
            sqlite3_column_bytes(st, 1) != 64 ||
            sqlite3_column_type(st, 2) != SQLITE_INTEGER ||
            sqlite3_column_int64(st, 2) < 1) {
            bad = 1;
            break;
        }
        if (n == cap) {
            sh_seg_t *ns = realloc(s, cap * 2 * sizeof(*s));
            if (!ns) { bad = 1; break; }
            s = ns;
            cap *= 2;
        }
        s[n].k = (uint64_t)sqlite3_column_int64(st, 0);
        memcpy(s[n].root, sqlite3_column_blob(st, 1), 64);
        s[n].published = (uint64_t)sqlite3_column_int64(st, 2);
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE) { free(s); return -1; }
    if (n == 0) { free(s); s = NULL; }
    *out = s;
    *n_out = n;
    return 0;
}

static bool in_holders(const nodus_storage_set_t *set, const uint8_t root[64],
                       const uint8_t me[64], int *err) {
    uint8_t hf[DNA_V2_STORAGE_HOLDERS][64];
    size_t nh = 0;
    if (set->count == 0) return false;
    if (nodus_witness_storage_holders(set, root, hf, &nh) != 0) {
        *err = 1;
        return false;
    }
    for (size_t j = 0; j < nh; j++)
        if (memcmp(hf[j], me, 64) == 0) return true;
    return false;
}

int nodus_witness_sthold_must_hold(nodus_witness_t *w, uint64_t H,
                                   const uint8_t me[64], uint64_t *ks,
                                   size_t cap, size_t *n_out) {
    if (!w || !w->db || !me || !n_out || (cap && !ks)) return -1;
    *n_out = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (H == 0 || (H % E) != 0) return -1;
    nodus_storage_set_t *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *prev = calloc(1, sizeof(*prev));
    sh_seg_t *segs = NULL;
    size_t n_segs = 0, n = 0;
    int ret = -1;
    if (!cur || !prev) goto done;
    int rc = nodus_witness_storage_set_get(w, H, cur);
    if (rc != 0) { ret = rc == 1 ? 1 : -1; goto done; }
    rc = H > E ? nodus_witness_storage_set_get(w, H - E, prev) : 1;
    if (rc < 0) goto done;
    if (rc == 1) prev->count = 0;
    if (segs_load(w, &segs, &n_segs) != 0) goto done;
    for (size_t s = 0; s < n_segs; s++) {
        int err = 0;
        bool want = in_holders(cur, segs[s].root, me, &err);
        if (!want && H > E && segs[s].published <= H - E)
            want = in_holders(prev, segs[s].root, me, &err);
        if (err) goto done;
        if (!want) continue;
        if (n >= cap) goto done;
        ks[n++] = segs[s].k;
    }
    *n_out = n;
    ret = 0;
done:
    free(segs);
    free(prev);
    free(cur);
    return ret;
}

static bool k_in(const uint64_t *ks, size_t n, uint64_t k) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ks[mid] == k) return true;
        if (ks[mid] < k) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

int nodus_witness_sthold_gc(nodus_witness_t *w, const char *dir, uint64_t H,
                            const uint8_t me[64]) {
    if (!w || !dir || !me) return -1;
    uint64_t *ks = calloc(NODUS_STHOLD_MAX_SEGS, sizeof(*ks));
    sh_seg_t *segs = NULL;
    size_t n = 0, n_segs = 0;
    int deleted = -1;
    if (!ks) return -1;
    if (nodus_witness_sthold_must_hold(w, H, me, ks, NODUS_STHOLD_MAX_SEGS,
                                       &n) != 0 ||
        segs_load(w, &segs, &n_segs) != 0)
        goto done;
    const uint64_t max_pub = n_segs ? segs[n_segs - 1].k : 0;

    /* collect first (the directory is not modified while it is read) */
    DIR *d = opendir(dir);
    if (!d) { deleted = 0; goto done; }          /* nothing held yet */
    uint64_t *del = NULL;
    size_t n_del = 0, cap_del = 0;
    struct dirent *e;
    int bad = 0;
    while ((e = readdir(d)) != NULL) {
        uint64_t k = 0;
        if (nodus_seg_name_parse(e->d_name, &k) != 0) continue;
        /* k beyond the published list is not a segment of this chain
         * yet — left alone (never deleted on a guess) */
        if (k > max_pub || k_in(ks, n, k)) continue;
        bool dup = false;
        for (size_t i = 0; i < n_del && !dup; i++) dup = del[i] == k;
        if (dup) continue;
        if (n_del == cap_del) {
            size_t nc = cap_del ? cap_del * 2 : 8;
            uint64_t *nd = realloc(del, nc * sizeof(*nd));
            if (!nd) { bad = 1; break; }
            del = nd;
            cap_del = nc;
        }
        del[n_del++] = k;
    }
    closedir(d);
    if (bad) { free(del); goto done; }
    deleted = 0;
    for (size_t i = 0; i < n_del; i++) {
        if (nodus_seg_delete(dir, del[i]) == 0) {
            deleted++;
            QGP_LOG_INFO(LOG_TAG, "segment %" PRIu64 " deleted: no longer "
                         "a holder and the overlap epoch has passed "
                         "(H=%" PRIu64 ")", del[i], H);
        } else {
            QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": delete incomplete",
                         del[i]);
        }
    }
    free(del);
done:
    free(segs);
    free(ks);
    return deleted;
}

/* ══════════════════════════════════════════════════════════════════════
 * The runtime
 * ════════════════════════════════════════════════════════════════════ */

static struct nodus_sthold_rt *rt_get(nodus_witness_t *w) {
    if (!w->sthold) w->sthold = calloc(1, sizeof(struct nodus_sthold_rt));
    return w->sthold;
}

static void job_close(struct nodus_sthold_rt *rt, bool discard) {
    if (discard) nodus_seg_build_discard(rt->job);
    else nodus_seg_build_free(rt->job);
    rt->job = NULL;
    rt->mode = JOB_NONE;
    rt->out = false;
    rt->cand = 0;
    rt->progressed = false;
    rt->retry_at_ms = 0;
}

static void mark_held(struct nodus_sthold_rt *rt, uint64_t k) {
    for (size_t i = 0; i < rt->n_want; i++)
        if (rt->want[i] == k) rt->held[i] = 1;
}

/* Recompute must-hold for epoch H, delete what is no longer held, warn
 * about retain_blocks. */
static void assign(nodus_witness_t *w, struct nodus_sthold_rt *rt,
                   const char *dir, uint64_t H, const uint8_t me[64]) {
    uint64_t *ks = calloc(NODUS_STHOLD_MAX_SEGS, sizeof(*ks));
    size_t n = 0;
    if (!ks) return;
    int rc = nodus_witness_sthold_must_hold(w, H, me, ks,
                                            NODUS_STHOLD_MAX_SEGS, &n);
    if (rc != 0) {
        if (rc < 0)
            QGP_LOG_WARN(LOG_TAG, "must-hold at H=%" PRIu64 " unreadable — "
                         "nothing deleted, retried next epoch", H);
        free(ks);
        rt->have_assign = true;          /* retried at the next epoch */
        rt->assign_H = H;
        return;
    }
    uint8_t *held = n ? calloc(n, 1) : NULL;
    if (n && !held) { free(ks); return; }
    size_t n_missing = 0;
    for (size_t i = 0; i < n; i++) {
        held[i] = nodus_seg_held(dir, ks[i]) == 1 ? 1 : 0;
        if (!held[i]) n_missing++;
    }
    free(rt->want);
    free(rt->held);
    rt->want = ks;
    rt->held = held;
    rt->n_want = n;
    rt->have_assign = true;
    rt->assign_H = H;
    rt->no_export_k = 0;

    /* the job's segment is no longer wanted: drop it before the GC */
    if (rt->job && !k_in(rt->want, rt->n_want, nodus_seg_build_k(rt->job)))
        job_close(rt, true);
    (void)nodus_witness_sthold_gc(w, dir, H, me);

    QGP_LOG_INFO(LOG_TAG, "epoch H=%" PRIu64 ": %zu segment(s) to hold, %zu "
                 "not complete yet", H, n, n_missing);
    if (w->config.retain_blocks > 0 && n_missing > 0) {
        uint64_t first = 0;
        for (size_t i = 0; i < n; i++)
            if (!held[i]) { first = ks[i]; break; }
        QGP_LOG_WARN(LOG_TAG, "retain_blocks=%" PRId64 " is set while %zu "
                     "assigned segment(s) are not complete (first: %" PRIu64
                     ") — a pruned block of an incomplete segment fails "
                     "every probe of it until the segment is fetched "
                     "(decision 2026-10-03-block-pruning-7-paydays.md, "
                     "rollout change)", w->config.retain_blocks, n_missing,
                     first);
    }
}

/* ── the fetch client ────────────────────────────────────────────────── */

/* The i-th candidate peer for segment k (header "THE FETCH CLIENT").
 * @return true and `out`, false when i is past the list. */
static bool candidate(nodus_witness_t *w, uint64_t H, uint64_t k,
                      const uint8_t me[64], size_t i,
                      char out[CMT_P2P_ID_CAP]) {
    char list[2 * DNA_V2_STORAGE_HOLDERS + 64][CMT_P2P_ID_CAP];
    size_t n = 0;
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    sh_seg_t *segs = NULL;
    size_t n_segs = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (set && segs_load(w, &segs, &n_segs) == 0) {
        const uint8_t *root = NULL;
        for (size_t s = 0; s < n_segs; s++)
            if (segs[s].k == k) root = segs[s].root;
        for (int pass = 0; root && pass < 2; pass++) {
            if (pass == 1 && H <= E) break;
            const uint64_t X = pass == 0 ? H : H - E;
            uint8_t hf[DNA_V2_STORAGE_HOLDERS][64];
            size_t nh = 0;
            if (nodus_witness_storage_set_get(w, X, set) != 0 ||
                nodus_witness_storage_holders(set, root, hf, &nh) != 0)
                continue;
            for (size_t j = 0; j < nh; j++) {
                if (memcmp(hf[j], me, 64) == 0) continue;
                char id[CMT_P2P_ID_CAP];
                fp_to_peer_id(hf[j], id);
                if (!nodus_witness_p2p_has_peer(w->p2p, id)) continue;
                bool dup = false;
                for (size_t q = 0; q < n && !dup; q++)
                    dup = strcmp(list[q], id) == 0;
                if (!dup) memcpy(list[n++], id, CMT_P2P_ID_CAP);
            }
        }
    }
    free(segs);
    free(set);
    const int np = nodus_witness_p2p_peer_count(w->p2p);
    for (int p = 0; p < np && n < sizeof(list) / sizeof(list[0]); p++) {
        char id[CMT_P2P_ID_CAP];
        if (!nodus_witness_p2p_peer_id_at(w->p2p, p, id)) continue;
        bool dup = false;
        for (size_t q = 0; q < n && !dup; q++) dup = strcmp(list[q], id) == 0;
        if (!dup) memcpy(list[n++], id, CMT_P2P_ID_CAP);
    }
    if (i >= n) return false;
    memcpy(out, list[i], CMT_P2P_ID_CAP);
    return true;
}

/* The next peer: candidate `cand` (wrapping). A full round without
 * progress arms the retry wait. */
static void rotate(struct nodus_sthold_rt *rt, const char *why) {
    QGP_LOG_INFO(LOG_TAG, "segment %" PRIu64 ": fetch from %.16s.. %s — "
                 "next peer", nodus_seg_build_k(rt->job), rt->peer, why);
    rt->out = false;
    rt->cand++;
}

/* Send the next request of the job. @return true sent / false nothing
 * sent this time. */
static bool fetch_send(nodus_witness_t *w, struct nodus_sthold_rt *rt,
                       const uint8_t me[64], uint64_t H, int64_t now) {
    uint64_t h = 0;
    uint32_t part = 0;
    bool need_hdr = false;
    if (nodus_seg_build_next(rt->job, &h, &part, &need_hdr) != 0)
        return false;
    const uint64_t k = nodus_seg_build_k(rt->job);
    if (!candidate(w, H, k, me, rt->cand, rt->peer)) {
        /* past the end of the list (the cursor only moves on a
         * failure): a round with progress starts over at once; a round
         * without any, or nobody connected, waits first */
        const bool progressed = rt->progressed;
        rt->cand = 0;
        rt->progressed = false;
        if (!progressed || !candidate(w, H, k, me, 0, rt->peer)) {
            QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": no peer served a "
                         "whole round — retry in %d s", k,
                         NODUS_STFETCH_RETRY_MS / 1000);
            rt->retry_at_ms = now + NODUS_STFETCH_RETRY_MS;
            return false;
        }
    }
    rt->req.k = nodus_seg_build_k(rt->job);
    rt->req.h = h;
    rt->req.part = part;
    rt->req.cont = need_hdr ? NODUS_STFETCH_CONT_FIRST
                            : NODUS_STFETCH_CONT_HAVE_HDR;
    uint8_t msg[NODUS_STFETCH_REQ_MSG_LEN];
    if (nodus_stfetch_req_encode(&rt->req, msg) != 0 ||
        nodus_stfetch_req_id(&rt->req, rt->rq) != 0)
        return false;
    if (!nodus_witness_p2p_send(w->p2p, rt->peer, NODUS_P2P_CH_STFETCH, msg,
                                sizeof(msg))) {
        rotate(rt, "not reachable on 0x73");
        return false;
    }
    rt->out = true;
    rt->deadline_ms = now + NODUS_STFETCH_TIMEOUT_MS;
    return true;
}

/* Publish a complete job. */
static void job_finish(struct nodus_sthold_rt *rt) {
    const uint64_t k = nodus_seg_build_k(rt->job);
    if (nodus_seg_build_finish(rt->job) == 0) {
        rt->job = NULL;                  /* freed by the publish */
        mark_held(rt, k);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": publish failed — the "
                      "partial file is kept and resumed", k);
    }
    job_close(rt, false);
}

/* An answer to the outstanding request. */
static void take_answer(nodus_witness_t *w, struct nodus_sthold_rt *rt,
                        const nodus_stfetch_ans_view_t *a) {
    if (a->code != NODUS_STFETCH_OK) {
        char why[32];
        snprintf(why, sizeof(why), "refused (code %u)", (unsigned)a->code);
        rotate(rt, why);
        return;
    }
    if (!nodus_stfetch_ans_shape_ok(&rt->req, a)) {
        rotate(rt, "answered another shape");
        return;
    }
    nodus_seg_v_t v = NODUS_SEG_V_OK;
    if (a->hdr_len > 0)
        v = nodus_seg_build_put_header(rt->job, rt->req.h, a->hdr, a->hdr_len);
    if (v == NODUS_SEG_V_OK) {
        if (rt->req.part == NODUS_SEG_PART_COMMIT) {
            nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
            v = nodus_seg_build_put_commit(
                rt->job, a->body, a->body_len,
                (node && node->store_ready) ? &node->store : NULL);
        } else {
            v = nodus_seg_build_put_part(rt->job, rt->req.h, rt->req.part,
                                         a->body, a->body_len, a->proof,
                                         a->proof_len);
        }
    }
    if (v == NODUS_SEG_V_IO || v == NODUS_SEG_V_FAULT ||
        v == NODUS_SEG_V_NO_LEDGER || v == NODUS_SEG_V_ORDER) {
        /* this node, not the peer: close (the partial file stays) */
        QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": %s while writing a "
                      "fetched piece — job closed, resumed later",
                      nodus_seg_build_k(rt->job), nodus_seg_v_str(v));
        job_close(rt, false);
        return;
    }
    if (v != NODUS_SEG_V_OK) {
        QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": piece from %.16s.. "
                     "refused at height %" PRIu64 " (%s)",
                     nodus_seg_build_k(rt->job), rt->peer, rt->req.h,
                     nodus_seg_v_str(v));
        rotate(rt, "sent a piece that does not verify");
        return;
    }
    rt->out = false;
    rt->progressed = true;
    uint64_t h = 0;
    uint32_t p = 0;
    bool nh = false;
    if (nodus_seg_build_next(rt->job, &h, &p, &nh) == 1) {
        job_finish(rt);
        return;
    }
    uint8_t me[64];
    uint64_t tip = 0, H = 0;
    if (own_fp(w, me) == 0 && nodus_witness_v2_tip_height(w, &tip) == 0 &&
        nodus_stprobe_epoch_for_tip(tip, (uint64_t)DNAC_EPOCH_LENGTH, &H)
            == 0)
        (void)fetch_send(w, rt, me, H, mono_ms());
}

/* ── the serving side ────────────────────────────────────────────────── */

static void serve_request(nodus_witness_t *w, struct nodus_sthold_rt *rt,
                          const char *peer_id, const uint8_t sender_fp[64],
                          const nodus_stfetch_req_t *req) {
    uint8_t rq[64], refusal[NODUS_STFETCH_REFUSAL_LEN];
    uint64_t tip = 0, H = 0;
    char dir[NODUS_SEG_PATH_MAX];
    if (nodus_stfetch_req_id(req, rq) != 0) return;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    const bool have_H = nodus_witness_v2_tip_height(w, &tip) == 0 &&
                        nodus_stprobe_epoch_for_tip(tip, E, &H) == 0;

    nodus_stfetch_code_t c;
    uint8_t *ans = NULL;
    size_t len = 0;
    if (have_H && nodus_stfetch_budget_spent(rt->budget,
                                             NODUS_STFETCH_SERVE_SLOTS,
                                             sender_fp, H)) {
        c = NODUS_STFETCH_REF_BUDGET;
    } else {
        nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
        ans = malloc(NODUS_STFETCH_MSG_MAX);
        c = !ans ? NODUS_STFETCH_REF_FAULT
                 : nodus_witness_stfetch_serve(
                       w, (node && node->store_ready) ? &node->store : NULL,
                       nodus_witness_sthold_dir(w, dir, sizeof(dir)) == 0
                           ? dir : NULL,
                       sender_fp, req, E, ans, NODUS_STFETCH_MSG_MAX, &len);
        /* charge an admitted requester (a non-member never takes a slot) */
        if (have_H && c != NODUS_STFETCH_REF_NOT_MEMBER &&
            c != NODUS_STFETCH_REF_UNKNOWN_SET) {
            uint64_t cost = c == NODUS_STFETCH_OK && len > NODUS_STFETCH_COST_MIN
                                ? (uint64_t)len : NODUS_STFETCH_COST_MIN;
            if (nodus_stfetch_budget_take(rt->budget,
                                          NODUS_STFETCH_SERVE_SLOTS,
                                          sender_fp, H, cost) != 0)
                c = NODUS_STFETCH_REF_BUDGET;
        }
    }
    if (c == NODUS_STFETCH_OK) {
        if (!nodus_witness_p2p_send(w->p2p, peer_id, NODUS_P2P_CH_STFETCH,
                                    ans, len))
            QGP_LOG_DEBUG(LOG_TAG, "fetch answer to %s not queued", peer_id);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "fetch k=%" PRIu64 " h=%" PRIu64 " from %s "
                      "refused (code %u)", req->k, req->h, peer_id,
                      (unsigned)c);
        if (nodus_stfetch_ans_refusal(rq, (uint8_t)c, refusal) == 0)
            (void)nodus_witness_p2p_send(w->p2p, peer_id,
                                         NODUS_P2P_CH_STFETCH, refusal,
                                         sizeof(refusal));
    }
    free(ans);
}

int nodus_witness_sthold_on_msg(nodus_witness_t *w, const char *peer_id,
                                const uint8_t sender_fp[64],
                                const uint8_t *msg, size_t len) {
    if (!w || !peer_id || !sender_fp || !msg || len == 0) return -1;
    struct nodus_sthold_rt *rt = rt_get(w);
    if (!rt) return 0;                        /* out of memory: dropped */
    if (msg[0] == NODUS_STFETCH_KIND_REQ) {
        nodus_stfetch_req_t req;
        if (nodus_stfetch_req_decode(msg, len, &req) != 0) return -1;
        if (!w->v2_successor || !w->db) return 0;    /* no chain: dropped */
        serve_request(w, rt, peer_id, sender_fp, &req);
        return 0;
    }
    if (msg[0] == NODUS_STFETCH_KIND_ANS) {
        nodus_stfetch_ans_view_t a;
        if (nodus_stfetch_ans_decode(msg, len, &a) != 0) return -1;
        if (!rt->job || rt->mode != JOB_FETCH || !rt->out ||
            strcmp(rt->peer, peer_id) != 0 || memcmp(rt->rq, a.rq, 64) != 0) {
            QGP_LOG_DEBUG(LOG_TAG, "unsolicited fetch answer from %s dropped",
                          peer_id);
            return 0;
        }
        take_answer(w, rt, &a);
        return 0;
    }
    return -1;
}

/* ── the tick ────────────────────────────────────────────────────────── */

void nodus_witness_sthold_tick(nodus_witness_t *w) {
    if (!w || !w->running || !w->v2_successor || !w->cmt_live || !w->p2p ||
        !w->db || !w->host || !w->host->identity)
        return;
    nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
    cmt_conr_t *conr = (cmt_conr_t *)w->cmt_conr;
    if (!node || !node->store_ready || !conr || cmt_conr_wait_sync(conr))
        return;                                 /* block-syncing          */

    struct nodus_sthold_rt *rt = rt_get(w);
    if (!rt) return;
    const int64_t now = mono_ms();
    if (rt->last_tick_ms != 0 && now >= rt->last_tick_ms &&
        now - rt->last_tick_ms < NODUS_STHOLD_TICK_MS)
        return;
    rt->last_tick_ms = now;

    char dir[NODUS_SEG_PATH_MAX];
    uint8_t me[64];
    uint64_t tip = 0, H = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (nodus_witness_sthold_dir(w, dir, sizeof(dir)) != 0 ||
        own_fp(w, me) != 0 || nodus_witness_v2_tip_height(w, &tip) != 0 ||
        nodus_stprobe_epoch_for_tip(tip, E, &H) != 0)
        return;

    if (!rt->have_assign || rt->assign_H != H)
        assign(w, rt, dir, H, me);

    /* open the next job: the smallest must-hold k not held */
    if (!rt->job) {
        for (size_t i = 0; i < rt->n_want; i++) {
            if (rt->held[i]) continue;
            if (nodus_seg_held(dir, rt->want[i]) == 1) {
                rt->held[i] = 1;
                continue;
            }
            if (nodus_seg_build_open(dir, rt->want[i], w->db, &rt->job) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": cannot open its "
                              "build in %s", rt->want[i], dir);
                return;
            }
            rt->next_mode = (rt->no_export_k != rt->want[i] &&
                             nodus_seg_store_has(&node->store, rt->want[i]))
                                ? JOB_EXPORT : JOB_FETCH;
            rt->mode = JOB_SCAN;
            QGP_LOG_INFO(LOG_TAG, "segment %" PRIu64 ": %s", rt->want[i],
                         rt->next_mode == JOB_EXPORT
                             ? "exporting from this node's block store"
                             : "fetching over 0x73 (the block store no "
                               "longer has the range)");
            break;
        }
        if (!rt->job) return;
    }

    if (rt->mode == JOB_SCAN) {
        int rc = nodus_seg_build_resume_step(rt->job, NODUS_STHOLD_SCAN_HEIGHTS);
        if (rc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": resume scan fault",
                          nodus_seg_build_k(rt->job));
            job_close(rt, false);
            return;
        }
        if (rc == 0) return;
        rt->mode = rt->next_mode;
    }

    if (rt->mode == JOB_EXPORT) {
        nodus_seg_v_t why = NODUS_SEG_V_OK;
        int rc = nodus_seg_export_step(rt->job, &node->store,
                                       NODUS_STHOLD_EXPORT_HEIGHTS, &why);
        if (rc == 1) {
            job_finish(rt);
        } else if (rc < 0) {
            /* the store lost the range (pruned meanwhile) or disagrees
             * with v2_blocks: keep what is verified, fetch the rest */
            rt->no_export_k = nodus_seg_build_k(rt->job);
            rt->mode = JOB_FETCH;
            QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": export stopped "
                         "(%s) — the rest is fetched", rt->no_export_k,
                         nodus_seg_v_str(why));
        }
        return;
    }

    if (rt->mode == JOB_FETCH) {
        if (rt->out && now > rt->deadline_ms) rotate(rt, "timed out");
        if (rt->out) return;
        if (rt->retry_at_ms != 0) {
            if (now < rt->retry_at_ms) return;
            rt->retry_at_ms = 0;
        }
        uint64_t h = 0;
        uint32_t p = 0;
        bool nh = false;
        if (nodus_seg_build_next(rt->job, &h, &p, &nh) == 1) {
            job_finish(rt);
            return;
        }
        (void)fetch_send(w, rt, me, H, now);
    }
}

void nodus_witness_sthold_free(nodus_witness_t *w) {
    if (!w || !w->sthold) return;
    struct nodus_sthold_rt *rt = w->sthold;
    nodus_seg_build_free(rt->job);
    free(rt->want);
    free(rt->held);
    free(rt);
    w->sthold = NULL;
}
