/**
 * @file nodus_witness_storage_reporter.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-1 —
 *        the archive probe's runtime: the serving side and the reporter.
 *        Contract: nodus_witness_storage_reporter.h; wire and checks:
 *        nodus_witness_storage_probe.h.
 *
 * Single-threaded: everything runs on the witness thread — the tick from
 * nodus_witness_tick, a message from the 4004 host's receive callback
 * (inside nodus_witness_p2p_poll on the same thread).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_reporter.h"
#include "witness/nodus_witness_storage_probe.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_v2_epoch.h"     /* snapshot authority      */
#include "witness/nodus_witness_v2_claims.h"    /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_produce.h"   /* nodus_witness_v2_tip_height */
#include "witness/nodus_witness_domreg.h"       /* the SYSTEM manifest     */
#include "witness/nodus_witness_cmt_node.h"     /* the store, the mempool  */
#include "witness/nodus_witness_p2p.h"          /* channel 0x72            */
#include "witness/nodus_witness_host.h"         /* this node's identity    */
#include "crypto/nodus_sign.h"                  /* nodus_random            */

#include "dnac/dnac.h"
#include "dnac/vset_wire.h"
#include "dnac/cmt_conr.h"
#include "dnac/cmt_mem.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STPROBE"

/* ── per-target probe state ──────────────────────────────────────────── */

enum {
    STP_PENDING = 0,   /* not sent yet                                     */
    STP_SENT,          /* request out, answer awaited                      */
    STP_OK,
    STP_FAIL,          /* refused, failed a check, late, never reached     */
    STP_NOPROBE        /* B == 0 or this node itself: bit 0, nothing sent  */
};

typedef struct {
    uint8_t   fp[64];                    /* the REGISTERED node_fp        */
    char      peer_id[CMT_P2P_ID_CAP];   /* hex(fp[0..31])                */
    uint8_t   status;
    uint64_t  slot;                      /* first tip it is tried at      */
    uint64_t *ks;                        /* eligible segments, k ascending*/
    size_t    n_ks;
    uint64_t  B;
    uint8_t   rq[64];
    int64_t   deadline_mono_ms;
    uint8_t   x[DNA_V2_STORAGE_SAMPLES][64];
    uint64_t  h[DNA_V2_STORAGE_SAMPLES];
    uint8_t   hash_h[DNA_V2_STORAGE_SAMPLES][64];
    uint8_t   hash_h1[DNA_V2_STORAGE_SAMPLES][64];
} stp_target_t;

typedef struct {
    bool                 active;
    uint64_t             H;
    uint32_t             seat;
    nodus_storage_set_t *set;           /* heap                          */
    stp_target_t        *t;             /* heap, set->count entries      */
    /* reporting */
    bool                 done;          /* committed, or given up         */
    bool                 submitted;
    bool                 last_ok;       /* the last CheckTx accepted it   */
    uint64_t             last_expiry;
    uint64_t             last_try_tip;
} stp_epoch_t;

typedef struct {
    char     id[CMT_P2P_ID_CAP];        /* "" = free                      */
    int64_t  last_ms;                    /* monotonic                     */
} stp_serve_t;

struct nodus_stprobe_rt {
    int64_t      last_tick_ms;
    bool         opened_any;
    uint64_t     last_opened_H;
    stp_epoch_t  cur;                    /* probing                       */
    stp_epoch_t  fin;                    /* reporting                     */
    stp_serve_t  serve[NODUS_STPROBE_SERVE_SLOTS];
};

static int64_t mono_ms(void) {
    return nodus_p2p_mono_ns(NULL) / 1000000;
}

static uint64_t wall_ms(void) {
    int64_t ns = nodus_p2p_wall_ns(NULL);
    return ns > 0 ? (uint64_t)ns / 1000000u : 0;
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

static void epoch_free(stp_epoch_t *e) {
    if (e->t && e->set) {
        for (uint32_t i = 0; i < e->set->count; i++) free(e->t[i].ks);
    }
    free(e->t);
    free(e->set);
    memset(e, 0, sizeof(*e));
}

/* this node's own v2_blocks.block_id at `h` (64 bytes). @return 0 / -1 */
static int own_block_id(nodus_witness_t *w, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (h == 0 || h > (uint64_t)INT64_MAX) return -1;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* Is a STORAGE_REPORT for (H, seat) committed? @return 1 / 0 / -1. */
static int report_committed(nodus_witness_t *w, uint64_t H, uint32_t seat) {
    sqlite3_stmt *st = NULL;
    if (H > (uint64_t)INT64_MAX) return -1;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_storage_reports "
            "WHERE epoch_start = ?1 AND seat = ?2", -1, &st, NULL)
            != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)seat);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

/* The seat of the key whose SHA3-512 is `fp` in snapshot(H).
 * @return 0 (*seat_out) / 1 not seated / -1 fault. */
static int seat_of(nodus_witness_t *w, uint64_t H, const uint8_t fp[64],
                   uint32_t *seat_out) {
    dna_vset_snapshot_t *snap = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(w, H, &snap, NULL,
                                                   NULL) != 0 || !snap) {
        dna_vset_free(&snap);
        return -1;
    }
    int ret = 1;
    for (uint32_t s = 0; s < snap->active_count; s++) {
        uint8_t sfp[64];
        if (qgp_sha3_512(snap->entries[s].pubkey, DNAC_PUBKEY_SIZE, sfp)
                != 0) {
            ret = -1;
            break;
        }
        if (memcmp(sfp, fp, 64) == 0) {
            if (seat_out) *seat_out = s;
            ret = 0;
            break;
        }
    }
    dna_vset_free(&snap);
    return ret;
}

static int own_fp(nodus_witness_t *w, uint8_t out[64]) {
    if (!w->host || !w->host->identity) return -1;
    return qgp_sha3_512(w->host->identity->pk.bytes, NODUS_PK_BYTES, out)
               == 0 ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * The serving side
 * ════════════════════════════════════════════════════════════════════ */

nodus_stprobe_code_t nodus_witness_stprobe_serve(
        nodus_witness_t *w, nodus_cmt_store_t *store,
        const uint8_t sender_fp[64], const nodus_stprobe_req_t *req,
        uint64_t E, uint64_t now_wall_ms,
        uint8_t *out, size_t cap, size_t *len_out) {
    if (!w || !w->db || !sender_fp || !req || !out || !len_out)
        return NODUS_STPROBE_REF_FAULT;
    *len_out = 0;
    uint8_t me[64], chain[DNA_CHAIN_ID_LEN];
    if (own_fp(w, me) != 0 || nodus_witness_v2_chain_id(w, chain) != 0)
        return NODUS_STPROBE_REF_FAULT;

    /* 1. what the request alone decides */
    nodus_stprobe_code_t c = nodus_stprobe_req_check(req, me, chain,
                                                     sender_fp, E,
                                                     now_wall_ms);
    if (c != NODUS_STPROBE_OK) return c;

    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    uint64_t *ks = calloc(NODUS_STPROBE_MAX_SEGS, sizeof(*ks));
    if (!set || !ks) { c = NODUS_STPROBE_REF_FAULT; goto done; }

    /* 2. storage_set(H) here, the same S(H), this node a member */
    int rc = nodus_witness_storage_set_get(w, req->epoch_start, set);
    if (rc == 1) { c = NODUS_STPROBE_REF_UNKNOWN_SET; goto done; }
    if (rc != 0) { c = NODUS_STPROBE_REF_FAULT; goto done; }
    if (memcmp(set->set_hash, req->set_hash, 64) != 0) {
        c = NODUS_STPROBE_REF_SET_MISMATCH;
        goto done;
    }
    {
        bool member = false;
        for (uint32_t i = 0; i < set->count && !member; i++)
            member = memcmp(set->fps[i], me, 64) == 0;
        if (!member) { c = NODUS_STPROBE_REF_NOT_MEMBER; goto done; }
    }

    /* 3. this node's own eligible blocks in (H, H+E] — the sampled
     *    heights can only ever be blocks it is assigned (a peer cannot
     *    make it read any other block) */
    size_t n = 0;
    rc = nodus_witness_storage_eligible_segments(w, req->epoch_start, me, ks,
                                                 NODUS_STPROBE_MAX_SEGS, &n);
    if (rc == 1) { c = NODUS_STPROBE_REF_UNKNOWN_SET; goto done; }
    if (rc != 0) { c = NODUS_STPROBE_REF_FAULT; goto done; }
    if (n == 0) { c = NODUS_STPROBE_REF_NO_BLOCKS; goto done; }

    /* 4. the requester holds a seat in snapshot(H) — only the reporters
     *    the settlement counts may spend this node's work */
    rc = seat_of(w, req->epoch_start, sender_fp, NULL);
    if (rc == 1) { c = NODUS_STPROBE_REF_NOT_SEATED; goto done; }
    if (rc != 0) { c = NODUS_STPROBE_REF_FAULT; goto done; }

    /* 5. the samples, from this node's block store */
    {
        uint8_t x[DNA_V2_STORAGE_SAMPLES][64];
        uint64_t h[DNA_V2_STORAGE_SAMPLES];
        uint8_t rq[64];
        if (!store ||
            nodus_stprobe_samples(req->nonce, me, ks, n, x, h) != 0 ||
            nodus_stprobe_req_id(req, rq) != 0) {
            c = NODUS_STPROBE_REF_FAULT;
            goto done;
        }
        c = nodus_stprobe_answer_build(store, rq,
                                       (const uint8_t (*)[64])x, h,
                                       (uint64_t)n * DNA_V2_SEGMENT_BLOCKS,
                                       out, cap, len_out);
    }
done:
    free(ks);
    free(set);
    return c;
}

/* The per-requester gap (monotonic). true = serve, slot stamped. */
static bool serve_allow(struct nodus_stprobe_rt *rt, const char *peer_id,
                        int64_t now) {
    int free_i = -1, stale_i = -1;
    if (!peer_id[0] || strlen(peer_id) >= CMT_P2P_ID_CAP) return false;
    for (int i = 0; i < (int)NODUS_STPROBE_SERVE_SLOTS; i++) {
        stp_serve_t *e = &rt->serve[i];
        /* a clock that went back reads as "just served" */
        int64_t el = now >= e->last_ms ? now - e->last_ms : 0;
        if (e->id[0] == '\0') {
            if (free_i < 0) free_i = i;
            continue;
        }
        if (strcmp(e->id, peer_id) == 0) {
            if (el < (int64_t)NODUS_STPROBE_SERVE_GAP_MS) return false;
            e->last_ms = now;
            return true;
        }
        if (el >= (int64_t)NODUS_STPROBE_SERVE_GAP_MS && stale_i < 0)
            stale_i = i;
    }
    int t = free_i >= 0 ? free_i : stale_i;
    if (t < 0) return false;            /* every slot served inside its gap */
    memcpy(rt->serve[t].id, peer_id, strlen(peer_id) + 1);
    rt->serve[t].last_ms = now;
    return true;
}

static struct nodus_stprobe_rt *rt_get(nodus_witness_t *w) {
    if (!w->stprobe) w->stprobe = calloc(1, sizeof(struct nodus_stprobe_rt));
    return w->stprobe;
}

static void serve_request(nodus_witness_t *w, struct nodus_stprobe_rt *rt,
                          const char *peer_id, const uint8_t sender_fp[64],
                          const nodus_stprobe_req_t *req) {
    uint8_t rq[64];
    uint8_t refusal[NODUS_STPROBE_REFUSAL_LEN];
    if (nodus_stprobe_req_id(req, rq) != 0) return;

    nodus_stprobe_code_t c;
    uint8_t *ans = NULL;
    size_t len = 0;
    if (!serve_allow(rt, peer_id, mono_ms())) {
        c = NODUS_STPROBE_REF_RATE;
    } else {
        nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
        ans = malloc(NODUS_STPROBE_MSG_MAX);
        c = !ans ? NODUS_STPROBE_REF_FAULT
                 : nodus_witness_stprobe_serve(
                       w, (node && node->store_ready) ? &node->store : NULL,
                       sender_fp, req, (uint64_t)DNAC_EPOCH_LENGTH,
                       wall_ms(), ans, NODUS_STPROBE_MSG_MAX, &len);
    }
    if (c == NODUS_STPROBE_OK) {
        if (!nodus_witness_p2p_send(w->p2p, peer_id, NODUS_P2P_CH_STPROBE,
                                    ans, len))
            QGP_LOG_DEBUG(LOG_TAG, "probe answer to %s not queued", peer_id);
        else
            QGP_LOG_DEBUG(LOG_TAG, "probe for H=%llu answered to %s "
                          "(%zu bytes)",
                          (unsigned long long)req->epoch_start, peer_id, len);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "probe for H=%llu from %s refused (code %u)",
                      (unsigned long long)req->epoch_start, peer_id,
                      (unsigned)c);
        if (nodus_stprobe_ans_refusal(rq, (uint8_t)c, refusal) == 0)
            (void)nodus_witness_p2p_send(w->p2p, peer_id,
                                         NODUS_P2P_CH_STPROBE, refusal,
                                         sizeof(refusal));
    }
    free(ans);
}

/* ══════════════════════════════════════════════════════════════════════
 * The reporter — answers
 * ════════════════════════════════════════════════════════════════════ */

/* A SENT target of `e` this answer belongs to: same rq AND the sender is
 * the registered identity (all 64 bytes). */
static stp_target_t *find_sent(stp_epoch_t *e, const uint8_t rq[64],
                               const uint8_t sender_fp[64]) {
    if (!e->active || !e->t || !e->set) return NULL;
    for (uint32_t i = 0; i < e->set->count; i++) {
        stp_target_t *t = &e->t[i];
        if (t->status == STP_SENT && memcmp(t->rq, rq, 64) == 0 &&
            memcmp(t->fp, sender_fp, 64) == 0)
            return t;
    }
    return NULL;
}

static void take_answer(struct nodus_stprobe_rt *rt, const char *peer_id,
                        const uint8_t sender_fp[64],
                        const nodus_stprobe_ans_view_t *a) {
    stp_target_t *t = find_sent(&rt->cur, a->rq, sender_fp);
    if (!t) t = find_sent(&rt->fin, a->rq, sender_fp);
    if (!t) {
        QGP_LOG_DEBUG(LOG_TAG, "unsolicited probe answer from %s dropped",
                      peer_id);
        return;
    }
    bool ok = nodus_stprobe_answer_ok(a, t->rq,
                                      (const uint8_t (*)[64])t->x, t->B,
                                      t->h,
                                      (const uint8_t (*)[64])t->hash_h,
                                      (const uint8_t (*)[64])t->hash_h1,
                                      mono_ms(), t->deadline_mono_ms);
    t->status = ok ? STP_OK : STP_FAIL;
    QGP_LOG_INFO(LOG_TAG, "probe of %.16s.. %s (code %u)", t->peer_id,
                 ok ? "OK" : "NOT OK", (unsigned)a->code);
}

int nodus_witness_stprobe_on_msg(nodus_witness_t *w, const char *peer_id,
                                 const uint8_t sender_fp[64],
                                 const uint8_t *msg, size_t len) {
    if (!w || !peer_id || !sender_fp || !msg || len == 0) return -1;
    struct nodus_stprobe_rt *rt = rt_get(w);
    if (!rt) return 0;                       /* out of memory: dropped */
    if (msg[0] == NODUS_STPROBE_KIND_REQ) {
        nodus_stprobe_req_t req;
        if (nodus_stprobe_req_decode(msg, len, &req) != 0) return -1;
        if (!w->v2_successor || !w->db) return 0;    /* no chain: dropped */
        serve_request(w, rt, peer_id, sender_fp, &req);
        return 0;
    }
    if (msg[0] == NODUS_STPROBE_KIND_ANS) {
        nodus_stprobe_ans_view_t a;
        if (nodus_stprobe_ans_decode(msg, len, &a) != 0) return -1;
        take_answer(rt, peer_id, sender_fp, &a);
        return 0;
    }
    return -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * The reporter — the epoch
 * ════════════════════════════════════════════════════════════════════ */

/* Open the probing epoch H (header "THE REPORTER"). Leaves `e` inactive
 * when this node holds no seat in snapshot(H), no set or an empty one
 * exists, or a read faults. */
static void epoch_open(nodus_witness_t *w, stp_epoch_t *e, uint64_t H) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint8_t me[64];
    uint32_t seat = 0;
    memset(e, 0, sizeof(*e));
    if (own_fp(w, me) != 0) return;
    if (seat_of(w, H, me, &seat) != 0) return;     /* not a reporter here */
    e->set = calloc(1, sizeof(*e->set));
    if (!e->set) return;
    if (nodus_witness_storage_set_get(w, H, e->set) != 0 ||
        e->set->count == 0) {
        epoch_free(e);
        return;
    }
    e->t = calloc(e->set->count, sizeof(*e->t));
    uint64_t *ks = calloc(NODUS_STPROBE_MAX_SEGS, sizeof(*ks));
    if (!e->t || !ks) {
        free(ks);
        epoch_free(e);
        return;
    }
    const uint32_t n = e->set->count;
    for (uint32_t i = 0; i < n; i++) {
        stp_target_t *t = &e->t[i];
        memcpy(t->fp, e->set->fps[i], 64);
        fp_to_peer_id(t->fp, t->peer_id);
        /* pacing order rotated by this node's seat, so the reporters of
         * one epoch do not all start with the same target (local only) */
        t->slot = nodus_stprobe_slot_height(H, E, (i + seat) % n, n);
        if (memcmp(t->fp, me, 64) == 0) {      /* F2: never itself       */
            t->status = STP_NOPROBE;
            continue;
        }
        size_t nk = 0;
        int rc = nodus_witness_storage_eligible_segments(
            w, H, t->fp, ks, NODUS_STPROBE_MAX_SEGS, &nk);
        if (rc != 0 || nk == 0) {
            if (rc != 0)
                QGP_LOG_WARN(LOG_TAG, "eligible segments of %.16s.. at "
                             "H=%llu unreadable (rc=%d) — bit 0",
                             t->peer_id, (unsigned long long)H, rc);
            t->status = STP_NOPROBE;            /* B == 0 → no probe     */
            continue;
        }
        t->ks = malloc(nk * sizeof(*t->ks));
        if (!t->ks) { t->status = STP_NOPROBE; continue; }
        memcpy(t->ks, ks, nk * sizeof(*ks));
        t->n_ks = nk;
        t->B = (uint64_t)nk * DNA_V2_SEGMENT_BLOCKS;
        t->status = STP_PENDING;
    }
    free(ks);
    e->H = H;
    e->seat = seat;
    e->active = true;
    QGP_LOG_INFO(LOG_TAG, "probing epoch H=%llu: seat %u, %u storage "
                 "member(s)", (unsigned long long)H, (unsigned)seat,
                 (unsigned)n);
}

/* Send one probe. @return true sent (status SENT / FAIL decided), false
 * the target is not reachable now (stays PENDING for a later pass). */
static bool probe_send(nodus_witness_t *w, stp_epoch_t *e, stp_target_t *t) {
    if (!nodus_witness_p2p_has_peer(w->p2p, t->peer_id)) return false;

    nodus_stprobe_req_t req;
    memset(&req, 0, sizeof(req));
    uint8_t msg[NODUS_STPROBE_REQ_MSG_LEN];
    if (nodus_witness_v2_chain_id(w, req.chain_id) != 0 ||
        own_fp(w, req.reporter_fp) != 0 ||
        nodus_random(req.nonce, sizeof(req.nonce)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "probe of %.16s..: chain id / identity / "
                      "nonce unavailable — NOT OK", t->peer_id);
        t->status = STP_FAIL;
        return true;
    }
    req.epoch_start = e->H;
    memcpy(req.set_hash, e->set->set_hash, 64);
    memcpy(req.target_fp, t->fp, 64);
    req.deadline_ms = wall_ms() + NODUS_STPROBE_BUDGET_MS;

    /* the samples and this node's own hashes BEFORE the request leaves */
    if (nodus_stprobe_samples(req.nonce, t->fp, t->ks, t->n_ks, t->x,
                              t->h) != 0) {
        t->status = STP_FAIL;
        return true;
    }
    for (uint32_t i = 0; i < DNA_V2_STORAGE_SAMPLES; i++) {
        if (own_block_id(w, t->h[i], t->hash_h[i]) != 0 ||
            own_block_id(w, t->h[i] + 1, t->hash_h1[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "probe of %.16s..: own v2_blocks has no "
                          "row at %llu/%llu — NOT OK", t->peer_id,
                          (unsigned long long)t->h[i],
                          (unsigned long long)(t->h[i] + 1));
            t->status = STP_FAIL;
            return true;
        }
    }
    if (nodus_stprobe_req_id(&req, t->rq) != 0 ||
        nodus_stprobe_req_encode(&req, msg) != 0) {
        t->status = STP_FAIL;
        return true;
    }
    if (!nodus_witness_p2p_send(w->p2p, t->peer_id, NODUS_P2P_CH_STPROBE,
                                msg, sizeof(msg)))
        return false;             /* queue full / channel not listed     */
    t->deadline_mono_ms = mono_ms() + (int64_t)NODUS_STPROBE_BUDGET_MS;
    t->status = STP_SENT;
    return true;
}

static void probes_due(nodus_witness_t *w, stp_epoch_t *e, uint64_t tip) {
    uint32_t sent = 0;
    if (!e->active) return;
    for (uint32_t i = 0; i < e->set->count &&
                         sent < NODUS_STPROBE_SENDS_PER_TICK; i++) {
        stp_target_t *t = &e->t[i];
        if (t->status != STP_PENDING || t->slot > tip) continue;
        if (probe_send(w, e, t)) sent++;
    }
}

/* SENT past its deadline → FAIL; with `closing`, PENDING → FAIL (the
 * epoch ended before the target was reached). @return SENT still out. */
static uint32_t expire(stp_epoch_t *e, int64_t now, bool closing) {
    uint32_t out = 0;
    if (!e->active) return 0;
    for (uint32_t i = 0; i < e->set->count; i++) {
        stp_target_t *t = &e->t[i];
        if (t->status == STP_SENT) {
            if (now > t->deadline_mono_ms) {
                t->status = STP_FAIL;
                QGP_LOG_INFO(LOG_TAG, "probe of %.16s.. unanswered by its "
                             "deadline — NOT OK", t->peer_id);
            } else {
                out++;
            }
        } else if (closing && t->status == STP_PENDING) {
            t->status = STP_FAIL;
            QGP_LOG_INFO(LOG_TAG, "storage member %.16s.. was never "
                         "reachable on 0x72 in epoch H=%llu — NOT OK",
                         t->peer_id, (unsigned long long)e->H);
        }
    }
    return out;
}

/* Build, sign and hand the report to this node's own mempool. */
static void report_submit(nodus_witness_t *w, stp_epoch_t *e, uint64_t tip,
                          uint64_t expiry) {
    nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
    const uint32_t n = e->set->count;
    bool *ok = calloc(n, sizeof(*ok));
    uint8_t call[NODUS_STPROBE_REPORT_CALL_MAX];
    size_t call_len = 0;
    uint8_t *env = NULL;
    size_t env_len = 0;
    dna_domain_manifest_t sys;
    uint8_t chain[DNA_CHAIN_ID_LEN];

    e->submitted = true;
    e->last_try_tip = tip;
    e->last_ok = false;
    if (!ok || !node || !node->mem_ready) goto done;
    for (uint32_t i = 0; i < n; i++) ok[i] = e->t[i].status == STP_OK;
    if (nodus_stprobe_report_call(e->H, e->seat, e->set->set_hash, ok, n,
                                  call, &call_len) != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
            != 0 ||
        nodus_witness_v2_chain_id(w, chain) != 0 ||
        nodus_stprobe_report_env(chain, sys.ruleset_version,
                                 sys.ruleset_hash, tip + 1, expiry, call,
                                 call_len, w->host->identity->pk.bytes,
                                 w->host->identity->sk.bytes, &env,
                                 &env_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "report for H=%llu could not be built",
                      (unsigned long long)e->H);
        goto done;
    }
    {
        cmt_mem_tx_info_t           info;
        cmt_mem_response_check_tx_t res;
        cmt_mem_error_t             err;
        memset(&info, 0, sizeof(info));     /* sender_id 0 = local     */
        memset(&res, 0, sizeof(res));
        memset(&err, 0, sizeof(err));
        int rc = cmt_mem_check_tx(node->mem, env, env_len, &info, &res,
                                  &err);
        e->last_ok = rc == CMT_OK && res.code == CMT_MEM_CODE_TYPE_OK;
        e->last_expiry = expiry;
        uint32_t n_ok = 0;
        for (uint32_t i = 0; i < n; i++) n_ok += ok[i] ? 1u : 0u;
        if (e->last_ok)
            QGP_LOG_INFO(LOG_TAG, "report for H=%llu submitted: seat %u, "
                         "%u/%u OK, expiry %llu",
                         (unsigned long long)e->H, (unsigned)e->seat,
                         (unsigned)n_ok, (unsigned)n,
                         (unsigned long long)expiry);
        else
            QGP_LOG_WARN(LOG_TAG, "report for H=%llu refused by CheckTx "
                         "(rc=%d code=%u kind=%d) — retried in %u blocks",
                         (unsigned long long)e->H, rc, (unsigned)res.code,
                         (int)err.kind, (unsigned)NODUS_STPROBE_RESUBMIT_GAP);
    }
done:
    free(env);
    free(ok);
}

static void report_step(nodus_witness_t *w, stp_epoch_t *e, uint64_t tip) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t expiry = 0;
    if (!e->active || e->done) return;
    int win = nodus_stprobe_report_window(e->H, E, tip, &expiry);
    if (win == 1) return;                       /* not open yet          */
    if (win != 0) {
        int c = report_committed(w, e->H, e->seat);
        if (c != 1)
            QGP_LOG_WARN(LOG_TAG, "report window for H=%llu closed with no "
                         "committed report from seat %u",
                         (unsigned long long)e->H, (unsigned)e->seat);
        e->done = true;
        return;
    }
    int c = report_committed(w, e->H, e->seat);
    if (c == 1) {
        QGP_LOG_INFO(LOG_TAG, "report for H=%llu committed",
                     (unsigned long long)e->H);
        e->done = true;
        return;
    }
    if (c < 0) return;                          /* read fault: next pass */
    if (!e->submitted ||
        (e->last_ok && tip >= e->last_expiry) ||
        (!e->last_ok && tip >= e->last_try_tip + NODUS_STPROBE_RESUBMIT_GAP))
        report_submit(w, e, tip, expiry);
}

void nodus_witness_stprobe_tick(nodus_witness_t *w) {
    if (!w || !w->running || !w->v2_successor || !w->cmt_live || !w->p2p ||
        !w->db || !w->host || !w->host->identity)
        return;
    nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
    cmt_conr_t *conr = (cmt_conr_t *)w->cmt_conr;
    if (!node || !node->mem_ready || !conr || cmt_conr_wait_sync(conr))
        return;                                 /* block-syncing          */

    struct nodus_stprobe_rt *rt = rt_get(w);
    if (!rt) return;
    const int64_t now = mono_ms();
    if (rt->last_tick_ms != 0 && now >= rt->last_tick_ms &&
        now - rt->last_tick_ms < NODUS_STPROBE_TICK_MS)
        return;
    rt->last_tick_ms = now;

    uint64_t tip = 0, H = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return;

    /* the probing epoch ends at tip >= H + E: it becomes the reporting
     * one (an older reporting epoch still open is dropped — its window
     * closed long before) */
    (void)expire(&rt->cur, now, false);
    if (rt->cur.active && tip >= rt->cur.H + E) {
        (void)expire(&rt->cur, now, true);
        epoch_free(&rt->fin);
        rt->fin = rt->cur;
        memset(&rt->cur, 0, sizeof(rt->cur));
    }
    if (nodus_stprobe_epoch_for_tip(tip, E, &H) == 0 && !rt->cur.active &&
        (!rt->opened_any || H != rt->last_opened_H) &&
        (!rt->fin.active || H > rt->fin.H)) {
        rt->opened_any = true;
        rt->last_opened_H = H;
        epoch_open(w, &rt->cur, H);
    }
    probes_due(w, &rt->cur, tip);

    /* the report waits until no probe of its epoch is still out */
    if (rt->fin.active) {
        if (expire(&rt->fin, now, true) == 0) report_step(w, &rt->fin, tip);
        if (rt->fin.done) epoch_free(&rt->fin);
    }
}

void nodus_witness_stprobe_free(nodus_witness_t *w) {
    if (!w || !w->stprobe) return;
    struct nodus_stprobe_rt *rt = w->stprobe;
    epoch_free(&rt->cur);
    epoch_free(&rt->fin);
    free(rt);
    w->stprobe = NULL;
}
