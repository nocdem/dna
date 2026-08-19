/**
 * @file nodus/src/witness/nodus_witness_v2_sync2.c
 * @brief Ledger V2 O15B — bounded catch-up, replay and restart.
 *
 * Contract and the one-engine argument are in nodus_witness_v2_sync2.h.
 * Read that first.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_sync2.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_ingress.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_bundle.h"  /* O15E Faz D genesis bundle */
#include "witness/nodus_witness_bft.h"    /* nodus_witness_bft_broadcast */
#include "server/nodus_server.h"          /* identity for signed sends   */
#include "transport/nodus_tcp.h"

#include "dnac/block_v2.h"
#include "dnac/blockmsg_v2.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2SYNC2"

/* ── O15E Faz B local policy knobs (never consensus) ─────────────────── */
#define V2SYNC_HEAD_INTERVAL_MS    10000u /* head-hint broadcast cadence  */
#define V2SYNC_REQ_TIMEOUT_MS      15000u /* in-flight range expiry       */
#define V2SYNC_SERVE_MIN_GAP_MS      100u /* H-1 sign-amplification guard */
#define V2SYNC_QCFETCH_INTERVAL_MS  5000u /* missing-QC fetch cadence     */

static uint64_t v2sync_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Committed V2 head, or 0. -1 on fault is impossible for a u64 return, so
 * `ok_out` carries the distinction — "no blocks" and "could not read" must
 * not be the same answer when the result decides whether to sync. */
static uint64_t v2_head(nodus_witness_t *w, int *ok_out) {
    *ok_out = 0;
    if (!w || !w->db) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    uint64_t h = 0;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v > 0) h = (uint64_t)v;
        *ok_out = 1;
    }
    sqlite3_finalize(st);
    return h;
}

int nodus_witness_v2_sync_peer_compatible(nodus_witness_t *w,
                                          const nodus_v2_head_hint_t *hint) {
    if (!w || !hint) return 0;

    /* A protocol version this build does not implement is not "probably
     * fine" — nothing about the frames that would follow is predictable. */
    if (hint->protocol_version != (uint32_t)DNA_BLKW_VERSION) return 0;

    /* Genesis identity is the chain's root fact; chain_id is DERIVED from
     * it (chain_id = genesis_block_id[0..31], block_v2.h:81). Checking both
     * is not redundant — it also rejects a peer whose two fields disagree
     * with each other, which no honest peer produces. */
    uint8_t derived[32];
    if (dna_bh2_derive_chain_id(hint->genesis_block_id, derived) != 0)
        return 0;
    if (memcmp(derived, hint->chain_id, 32) != 0) return 0;

    uint8_t mine[32];
    /* A fault deriving OUR identity means we cannot tell. Not "yes". */
    if (nodus_witness_v2_chain_id(w, mine) != 0) return 0;
    if (memcmp(mine, hint->chain_id, 32) != 0) return 0;

    return 1;
}

int nodus_witness_v2_sync_plan_range(nodus_witness_t *w,
                                     const nodus_v2_head_hint_t *hint,
                                     uint64_t *from_out,
                                     uint32_t *count_out) {
    if (from_out)  *from_out  = 0;
    if (count_out) *count_out = 0;
    if (!w || !hint || !from_out || !count_out) return -1;

    if (!nodus_witness_v2_activation_permitted(w))
        return NODUS_V2_NOT_ACTIVE;

    if (!nodus_witness_v2_sync_peer_compatible(w, hint)) return -1;

    int ok = 0;
    uint64_t head = v2_head(w, &ok);
    if (!ok) return -1;

    /* The hint is a HINT. A peer claiming to be behind us, or level, gives
     * us nothing to ask for — and a peer claiming an absurd head does not
     * get to make us request an unbounded range, because the count is
     * clamped to NODUS_V2_SYNC_MAX_RANGE_BLOCKS regardless of what it
     * claims. */
    if (hint->head_height <= head) return 0;

    uint64_t gap = hint->head_height - head;
    uint32_t want = (gap > (uint64_t)NODUS_V2_SYNC_MAX_RANGE_BLOCKS)
                        ? NODUS_V2_SYNC_MAX_RANGE_BLOCKS
                        : (uint32_t)gap;

    *from_out  = head + 1;
    *count_out = want;
    return 0;
}

int nodus_witness_v2_sync_apply_range(nodus_witness_t *w,
                                      const uint8_t *peer_id,
                                      const uint8_t *const *frames,
                                      const size_t *lens,
                                      uint32_t n,
                                      nodus_v2_sync_range_result_t *out) {
    nodus_v2_sync_range_result_t local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    out->stop_reason = NODUS_V2_ACCEPTED;
    out->stop_index  = n;

    if (!w) return NODUS_V2_INTERNAL_FAULT;

    if (!nodus_witness_v2_activation_permitted(w)) {
        out->stop_reason = NODUS_V2_NOT_ACTIVE;
        out->stop_index  = 0;
        return NODUS_V2_NOT_ACTIVE;
    }

    if (!frames || !lens) {
        out->stop_reason = NODUS_V2_INTERNAL_FAULT;
        out->stop_index  = 0;
        return NODUS_V2_INTERNAL_FAULT;
    }

    /* An over-cap range is refused WHOLE, before the first block is
     * touched. Applying a prefix and refusing the tail would let a peer
     * choose how much work we do by how much it oversends.
     *
     * REFUSED, NOT JUDGED. These are LOCAL resource limits (sync2.h: "All
     * LOCAL resource policy; none is consensus"), so a node with a larger
     * budget accepts the same range. Reporting them as CONSENSUS_INVALID —
     * as an earlier draft did — would blame a peer for our own policy, and
     * an honest peer answering OUR 16-block request with large-but-legal
     * blocks could trip the byte budget and be marked invalid for it.
     * Review R2 found this. INTERNAL_FAULT carries the honest meaning:
     * this node did not evaluate the range. */
    if (n > NODUS_V2_SYNC_MAX_RANGE_BLOCKS) {
        QGP_LOG_WARN(LOG_TAG,
                     "range of %u blocks exceeds this node's LOCAL cap of "
                     "%u — refused without judging the peer",
                     n, (unsigned)NODUS_V2_SYNC_MAX_RANGE_BLOCKS);
        out->stop_reason = NODUS_V2_INTERNAL_FAULT;
        out->stop_index  = 0;
        out->faults++;
        return NODUS_V2_INTERNAL_FAULT;
    }

    /* Byte budget, summed BEFORE anything is applied, with a checked add. */
    uint64_t total = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (lens[i] > NODUS_V2_SYNC_MAX_RANGE_BYTES) {
            out->stop_reason = NODUS_V2_INTERNAL_FAULT;
            out->stop_index  = i;
            out->faults++;
            return NODUS_V2_INTERNAL_FAULT;
        }
        total += (uint64_t)lens[i];
        if (total > NODUS_V2_SYNC_MAX_RANGE_BYTES) {
            QGP_LOG_WARN(LOG_TAG,
                         "range bytes exceed this node's LOCAL budget at "
                         "index %u — refused without judging the peer", i);
            out->stop_reason = NODUS_V2_INTERNAL_FAULT;
            out->stop_index  = i;
            out->faults++;
            return NODUS_V2_INTERNAL_FAULT;
        }
    }

    for (uint32_t i = 0; i < n; i++) {
        nodus_v2_ingress_outcome_t oc;
        /* THE SAME ADAPTER, THE SAME ENGINE, THE SAME CHECKS as a block
         * arriving live. There is deliberately no "historical" variant:
         * a shortcut here would be a second acceptance path, and the whole
         * point of this module is that there is only one. */
        int rc = nodus_witness_v2_ingress_block(w, peer_id,
                                                frames[i], lens[i], &oc);

        if (rc == NODUS_V2_ACCEPTED || rc == NODUS_V2_ACCEPTED_PRECACHE) {
            out->applied++;
            continue;
        }
        if (rc == NODUS_V2_IDEMPOTENT_REPLAY) {
            /* Already committed. NOT a stop: re-sending is ordinary during
             * catch-up, and a duplicate has no second effect. */
            out->duplicates++;
            continue;
        }

        /* Everything else stops the range at THIS index. A range claims
         * contiguous history, so once one block does not apply, every
         * later block's parent is unverified — continuing would apply
         * blocks on top of a link we never established. */
        out->stop_index  = i;
        out->stop_reason = (nodus_v2_result_t)rc;
        if (rc == NODUS_V2_NOT_YET_LINKABLE)        out->deferred++;
        else if (nodus_v2_result_blames_peer(rc))   out->rejected++;
        else                                        out->faults++;

        QGP_LOG_WARN(LOG_TAG,
                     "range stopped at index %u: result %d (peer action %s)",
                     i, rc, nodus_v2_peer_action_name(oc.peer));
        return rc;
    }

    return 0;
}

int nodus_witness_v2_sync_serve_block(nodus_witness_t *w, uint64_t height,
                                      uint8_t **buf_out, size_t *len_out) {
    if (buf_out) *buf_out = NULL;
    if (len_out) *len_out = 0;
    if (!w || !w->db || !buf_out || !len_out) return -1;

    if (!nodus_witness_v2_activation_permitted(w))
        return NODUS_V2_NOT_ACTIVE;

    /* Height 0 is the pinned-genesis path's business, never a
     * BlockMessage (no QC exists for it by construction). */
    if (height == 0) return 1;

    /* ── the committed row: header + qc ─────────────────────────────── */
    uint8_t header[DNA_BH2_ENC_SIZE];
    uint8_t *qc = NULL;
    size_t qc_len = 0;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT header, qc FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
        int rc = sqlite3_step(st);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(st);
            return (rc == SQLITE_DONE) ? 1 : -1;   /* absent / fault    */
        }
        if (sqlite3_column_bytes(st, 0) != DNA_BH2_ENC_SIZE) {
            sqlite3_finalize(st);
            return -1;                              /* malformed row     */
        }
        memcpy(header, sqlite3_column_blob(st, 0), DNA_BH2_ENC_SIZE);
        const void *q = sqlite3_column_blob(st, 1);
        int ql = sqlite3_column_bytes(st, 1);
        if (!q || ql <= 0) {
            /* committed-but-uncertified: the live lane's legal window
             * (produce.h) — NOT servable, NOT a fault. */
            sqlite3_finalize(st);
            return 1;
        }
        if ((size_t)ql > DNA_QC_V2_MAX_ENC_LEN) {
            sqlite3_finalize(st);
            return -1;
        }
        qc = malloc((size_t)ql);
        if (!qc) { sqlite3_finalize(st); return -1; }
        memcpy(qc, q, (size_t)ql);
        qc_len = (size_t)ql;
        sqlite3_finalize(st);
    }

    /* ── the stored header carries tx_count / proposer / timestamp ──── */
    dna_block_header_v2_t hdr;
    if (dna_bh2_decode(header, sizeof(header), &hdr) != 0 ||
        hdr.block_height != height ||
        hdr.tx_count > DNA_BLKW_MAX_ENVS) {
        free(qc);
        return -1;
    }

    /* ── the canonical envelope bytes, in batch order ────────────────── */
    uint8_t *envs[DNA_BLKW_MAX_ENVS];
    uint32_t env_lens[DNA_BLKW_MAX_ENVS];
    uint32_t n_env = 0;
    memset(envs, 0, sizeof(envs));
    int rc_out = -1;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT global_index, env FROM v2_tx_bytes "
                "WHERE global_height = ?1 ORDER BY global_index ASC",
                -1, &st, NULL) != SQLITE_OK)
            goto out;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
        int rc;
        int bad = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            sqlite3_int64 gi = sqlite3_column_int64(st, 0);
            const void *e = sqlite3_column_blob(st, 1);
            int el = sqlite3_column_bytes(st, 1);
            if (n_env >= DNA_BLKW_MAX_ENVS ||
                gi != (sqlite3_int64)n_env ||          /* contiguous 0.. */
                !e || el <= 0 ||
                (size_t)el > DNA_ENV_MAX_TOTAL_LEN) {
                bad = 1;
                break;
            }
            envs[n_env] = malloc((size_t)el);
            if (!envs[n_env]) { bad = 1; break; }
            memcpy(envs[n_env], e, (size_t)el);
            env_lens[n_env] = (uint32_t)el;
            n_env++;
        }
        sqlite3_finalize(st);
        if (bad || (rc != SQLITE_DONE && rc != SQLITE_ROW)) goto out;
    }

    /* Count agreement with the committed header — a pre-S11 height has
     * zero byte rows for a non-zero tx_count: UNAVAILABLE, fail-closed
     * (never reconstructed, never invented). */
    if ((uint32_t)hdr.tx_count != n_env) {
        rc_out = 1;
        goto out;
    }

    /* ── assemble + encode the canonical BlockMessage v1 ─────────────── */
    {
        dnac_blkmsg_v2_t m;
        memset(&m, 0, sizeof(m));
        m.msg_version  = (uint8_t)DNA_BLKW_VERSION;
        m.body_version = (uint8_t)DNA_BLKW_BODY_VERSION;
        m.header       = header;
        m.qc           = qc;
        m.qc_len       = (uint32_t)qc_len;
        m.env_count    = n_env;
        for (uint32_t i = 0; i < n_env; i++) {
            m.env[i].bytes = envs[i];
            m.env[i].len   = env_lens[i];
        }
        memcpy(m.proposer_id, hdr.proposer_id, sizeof(m.proposer_id));
        m.timestamp = hdr.timestamp;

        size_t need = dnac_blkmsg_v2_encoded_len(&m);
        if (need == 0) goto out;
        uint8_t *buf = malloc(need);
        if (!buf) goto out;
        size_t written = 0;
        if (dnac_blkmsg_v2_encode(&m, buf, need, &written) != DNAC_BLKW_OK
            || written != need) {
            free(buf);
            goto out;
        }
        *buf_out = buf;
        *len_out = written;
        rc_out = 0;
    }

out:
    for (uint32_t i = 0; i < n_env; i++) free(envs[i]);
    free(qc);
    return rc_out;
}

/* ── O15E Faz B — the network seam (verbs 20-23) ─────────────────────── */

/* Successor + open gate + armed: the ONE predicate every handler and
 * the driver ask first. Anything else answers nothing (no residue). */
static int v2sync_ready(nodus_witness_t *w) {
    return w && w->db && w->v2_successor &&
           nodus_witness_v2_activation_permitted(w) &&
           nodus_witness_v2_ingress_is_armed(w);
}

/* Signed unicast on an existing connection (the chain_r response
 * pattern, but through the 1 MB heap encode path the range frames
 * need). */
static void v2sync_send(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                        nodus_t3_msg_t *msg) {
    if (!conn) return;
    const char *method = nodus_t3_type_to_method(msg->type);
    if (method)
        snprintf(msg->method, sizeof(msg->method), "%s", method);
    msg->header.version = 1;
    memcpy(msg->header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg->header.timestamp = (uint64_t)time(NULL);
    memcpy(msg->header.chain_id, w->chain_id, 32);

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) return;
    size_t len = 0;
    if (nodus_t3_encode(msg, &w->server->identity.sk, buf,
                        NODUS_W_MAX_SYNC_RSP_SIZE, &len) == 0)
        (void)nodus_tcp_send(conn, buf, len);
    free(buf);
}

/* Our own committed genesis BlockID (the head hint's root fact). */
static int v2sync_genesis_id(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = 0",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* Emit ONE bounded range request at `conn` and arm the in-flight slot. */
static void v2sync_request_range(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t sender_id[32],
                                 uint64_t from, uint32_t count) {
    nodus_t3_msg_t req;
    memset(&req, 0, sizeof(req));
    req.type = NODUS_T3_V2_RANGE_REQ;
    memcpy(req.w_v2_range_q.chain, w->v2_chain32, 32);
    if (v2sync_genesis_id(w, req.w_v2_range_q.genesis_id) != 0) return;
    req.w_v2_range_q.from  = from;
    req.w_v2_range_q.count = count;
    v2sync_send(w, conn, &req);

    memcpy(w->v2_sync.req_peer, sender_id, NODUS_T3_WITNESS_ID_LEN);
    w->v2_sync.req_from    = from;
    w->v2_sync.req_count   = count;
    w->v2_sync.req_sent_ms = v2sync_monotonic_ms();
}

void nodus_witness_v2_sync_handle_head(nodus_witness_t *w,
                                       struct nodus_tcp_conn *conn,
                                       const nodus_t3_msg_t *msg) {
    if (!v2sync_ready(w) || !msg) return;

    nodus_v2_head_hint_t hint;
    memset(&hint, 0, sizeof(hint));
    memcpy(hint.chain_id, msg->w_v2_head.chain, 32);
    memcpy(hint.genesis_block_id, msg->w_v2_head.genesis_id, 64);
    hint.head_height      = msg->w_v2_head.head;
    hint.protocol_version = msg->w_v2_head.proto;

    uint64_t from = 0;
    uint32_t count = 0;
    if (nodus_witness_v2_sync_plan_range(w, &hint, &from, &count) != 0)
        return;
    if (count == 0) return;                     /* level or ahead        */

    uint64_t now = v2sync_monotonic_ms();
    if (w->v2_sync.req_sent_ms != 0 &&
        now - w->v2_sync.req_sent_ms < V2SYNC_REQ_TIMEOUT_MS)
        return;                                 /* one in flight         */

    QGP_LOG_INFO(LOG_TAG, "behind a compatible peer (their head %llu) — "
                 "requesting %u block(s) from %llu",
                 (unsigned long long)hint.head_height, count,
                 (unsigned long long)from);
    v2sync_request_range(w, conn, msg->header.sender_id, from, count);
}

/* Serve up to `count` frames ascending from `from` into a range_r reply.
 * Stops at the first unavailable height or budget edge; sends nothing at
 * all when not a single frame is servable (the requester's timeout is
 * the retry policy — no error verb exists to abuse). */
static void v2sync_serve(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                         uint64_t from, uint32_t count) {
    uint64_t now = v2sync_monotonic_ms();
    if (w->v2_sync.last_serve_ms != 0 &&
        now - w->v2_sync.last_serve_ms < V2SYNC_SERVE_MIN_GAP_MS)
        return;                                 /* H-1 guard             */

    if (count > NODUS_T3_V2_RANGE_MAX_FRAMES)
        count = NODUS_T3_V2_RANGE_MAX_FRAMES;
    if (count > NODUS_V2_SYNC_MAX_RANGE_BLOCKS)
        count = NODUS_V2_SYNC_MAX_RANGE_BLOCKS;

    uint8_t *packed = malloc(NODUS_T3_V2_RANGE_MAX_BYTES);
    if (!packed) return;
    uint32_t frame_len[NODUS_T3_V2_RANGE_MAX_FRAMES];
    uint32_t n = 0;
    size_t used = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint8_t *frame = NULL;
        size_t flen = 0;
        int rc = nodus_witness_v2_sync_serve_block(w, from + i,
                                                   &frame, &flen);
        if (rc != 0) break;                     /* unavailable / fault   */
        if (flen == 0 ||
            flen > (size_t)NODUS_T3_V2_RANGE_MAX_BYTES - used) {
            free(frame);
            break;                              /* budget edge           */
        }
        memcpy(packed + used, frame, flen);
        frame_len[n] = (uint32_t)flen;
        used += flen;
        n++;
        free(frame);
    }

    if (n == 0) { free(packed); return; }

    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_V2_RANGE_RSP;
    memcpy(rsp.w_v2_range_r.chain, w->v2_chain32, 32);
    rsp.w_v2_range_r.from = from;
    rsp.w_v2_range_r.n    = n;
    for (uint32_t i = 0; i < n; i++)
        rsp.w_v2_range_r.frame_len[i] = frame_len[i];
    rsp.w_v2_range_r.frames     = packed;
    rsp.w_v2_range_r.frames_len = (uint32_t)used;
    v2sync_send(w, conn, &rsp);
    free(packed);

    w->v2_sync.last_serve_ms = now;
    QGP_LOG_INFO(LOG_TAG, "served %u block frame(s) from %llu (%zu bytes)",
                 n, (unsigned long long)from, used);
}

void nodus_witness_v2_sync_handle_range_q(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg) {
    if (!v2sync_ready(w) || !msg || !conn) return;

    /* Chain + genesis binding: a request for another chain, or one
     * whose two identity fields disagree, is not ours to answer. */
    if (memcmp(msg->w_v2_range_q.chain, w->v2_chain32, 32) != 0) return;
    uint8_t gid[64];
    if (v2sync_genesis_id(w, gid) != 0) return;
    if (memcmp(msg->w_v2_range_q.genesis_id, gid, 64) != 0) return;
    if (msg->w_v2_range_q.from == 0) return;    /* genesis: pinned path  */
    if (msg->w_v2_range_q.count == 0) return;

    v2sync_serve(w, conn, msg->w_v2_range_q.from, msg->w_v2_range_q.count);
}

void nodus_witness_v2_sync_handle_block_q(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg) {
    if (!v2sync_ready(w) || !msg || !conn) return;

    if (memcmp(msg->w_v2_block_q.chain, w->v2_chain32, 32) != 0) return;
    uint64_t h = msg->w_v2_block_q.height;
    if (h == 0) return;

    /* The request names the exact BlockID it wants (the QC-recovery
     * binding). Serve ONLY when our committed row carries that id. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
        int match = 0;
        if (sqlite3_step(st) == SQLITE_ROW &&
            sqlite3_column_bytes(st, 0) == 64 &&
            memcmp(sqlite3_column_blob(st, 0),
                   msg->w_v2_block_q.block_id, 64) == 0)
            match = 1;
        sqlite3_finalize(st);
        if (!match) return;
    }

    v2sync_serve(w, conn, h, 1);
}

void nodus_witness_v2_sync_handle_gbundle_q(nodus_witness_t *w,
                                            struct nodus_tcp_conn *conn,
                                            const nodus_t3_msg_t *msg) {
    if (!v2sync_ready(w) || !msg || !conn) return;

    /* The chain field AND the pin must both name THIS successor: the pin
     * is the joiner's requested genesis BlockID, and we only serve the
     * bundle for the genesis WE committed. */
    if (memcmp(msg->w_v2_gbundle_q.chain, w->v2_chain32, 32) != 0) return;
    uint8_t gid[64];
    if (v2sync_genesis_id(w, gid) != 0) return;
    if (memcmp(msg->w_v2_gbundle_q.pin, gid, 64) != 0) return;

    /* Rate-limit (H-1 sign-amplification). */
    uint64_t now = v2sync_monotonic_ms();
    if (w->v2_sync.last_serve_ms != 0 &&
        now - w->v2_sync.last_serve_ms < V2SYNC_SERVE_MIN_GAP_MS)
        return;

    uint8_t *bundle = NULL;
    size_t blen = 0;
    if (nodus_witness_v2_bundle_get(w, &bundle, &blen) != 0) return;

    uint64_t off = msg->w_v2_gbundle_q.offset;
    if (off > blen) { free(bundle); return; }
    size_t remain = blen - (size_t)off;
    uint32_t chunk = (remain > NODUS_T3_V2_GBUNDLE_CHUNK_MAX)
                         ? NODUS_T3_V2_GBUNDLE_CHUNK_MAX
                         : (uint32_t)remain;

    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_V2_GBUNDLE_RSP;
    memcpy(rsp.w_v2_gbundle_r.chain, w->v2_chain32, 32);
    memcpy(rsp.w_v2_gbundle_r.pin, gid, 64);
    rsp.w_v2_gbundle_r.total     = (uint64_t)blen;
    rsp.w_v2_gbundle_r.offset    = off;
    rsp.w_v2_gbundle_r.chunk     = bundle + off;
    rsp.w_v2_gbundle_r.chunk_len = chunk;
    v2sync_send(w, conn, &rsp);
    free(bundle);
    w->v2_sync.last_serve_ms = now;
    QGP_LOG_INFO(LOG_TAG, "served genesis bundle chunk @%llu (%u/%zu bytes)",
                 (unsigned long long)off, chunk, blen);
}

void nodus_witness_v2_sync_handle_range_r(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg) {
    if (!v2sync_ready(w) || !msg) return;

    const nodus_t3_w_v2_range_r_t *r = &msg->w_v2_range_r;
    if (memcmp(r->chain, w->v2_chain32, 32) != 0) return;
    if (r->n == 0 || r->n > NODUS_T3_V2_RANGE_MAX_FRAMES) return;

    /* TWO responses are processed, and nothing else:
     *
     * (a) a CATCH-UP range we asked for — same peer, same starting
     *     height, inside the in-flight window; applied and continued;
     * (b) a QC-RECOVERY single block: n == 1 whose `from` is a height we
     *     have COMMITTED but whose QC is still NULL. It heals through
     *     finalize's idempotent replay and does NOT continue.
     *
     * Everything else is ignored unexamined — an unsolicited range is a
     * free way to make a node burn engine work otherwise. Case (b) is
     * bounded to a single already-committed height with a genuinely
     * missing certificate, so it cannot be used to drive arbitrary
     * engine work either. */
    int is_catchup =
        (w->v2_sync.req_sent_ms != 0 &&
         memcmp(msg->header.sender_id, w->v2_sync.req_peer,
                NODUS_T3_WITNESS_ID_LEN) == 0 &&
         r->from == w->v2_sync.req_from &&
         r->n <= w->v2_sync.req_count);
    int is_qc_recovery = 0;
    if (!is_catchup && r->n == 1 && r->from > 0) {
        uint64_t miss = 0;
        if (nodus_witness_v2_qc_first_missing(w, &miss) == 0 &&
            miss == r->from)
            is_qc_recovery = 1;
    }
    if (!is_catchup && !is_qc_recovery) return;

    const uint8_t *frames[NODUS_T3_V2_RANGE_MAX_FRAMES];
    size_t lens[NODUS_T3_V2_RANGE_MAX_FRAMES];
    size_t off = 0;
    for (uint32_t i = 0; i < r->n; i++) {
        frames[i] = r->frames + off;
        lens[i]   = r->frame_len[i];
        off      += r->frame_len[i];
    }

    nodus_v2_sync_range_result_t res;
    int rc = nodus_witness_v2_sync_apply_range(w, msg->header.sender_id,
                                               frames, lens, r->n, &res);
    if (is_catchup) w->v2_sync.req_sent_ms = 0;  /* catch-up slot freed  */

    QGP_LOG_INFO(LOG_TAG, "range from %llu: applied=%u dup=%u deferred=%u "
                 "rejected=%u faults=%u (rc=%d)",
                 (unsigned long long)r->from, res.applied, res.duplicates,
                 res.deferred, res.rejected, res.faults, rc);

    /* Continuation applies only to catch-up: a fully-consumed range
     * re-arms immediately at the same peer (one in-flight at a time; a
     * peer with nothing newer simply doesn't answer and the timeout
     * frees the slot). A QC-recovery response heals in place and stops. */
    if (is_catchup && rc == 0 && res.applied > 0 && conn) {
        int ok = 0;
        uint64_t head = v2_head(w, &ok);
        if (ok)
            v2sync_request_range(w, conn, msg->header.sender_id,
                                 head + 1, NODUS_T3_V2_RANGE_MAX_FRAMES);
    }
}

int nodus_witness_v2_qc_first_missing(nodus_witness_t *w,
                                      uint64_t *height_out) {
    if (height_out) *height_out = 0;
    if (!w || !w->db || !height_out) return -1;
    sqlite3_stmt *st = NULL;
    /* Height 0 (genesis) has no QC by construction — EXCLUDE it. */
    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MIN(global_height),0) FROM v2_blocks "
            "WHERE qc IS NULL AND global_height > 0",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
        *height_out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return (rc == SQLITE_ROW) ? 0 : -1;
}

/* O15E Faz C — request the block at `height` from a live peer so its QC
 * can be recovered. The request BINDS our committed BlockID at that
 * height (a peer serving any other block for it is refused server-side,
 * and our finalize would reject it anyway). Round-robins across
 * identified peers so a single dead peer cannot stall recovery. */
static void v2sync_fetch_qc(nodus_witness_t *w, uint64_t height) {
    uint8_t bid[64];
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
        int got = (sqlite3_step(st) == SQLITE_ROW &&
                   sqlite3_column_bytes(st, 0) == 64);
        if (got) memcpy(bid, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        if (!got) return;
    }

    /* Pick ONE identified peer this round (round-robin cursor). */
    struct nodus_tcp_conn *conn = NULL;
    if (w->peer_count > 0) {
        for (int k = 0; k < w->peer_count; k++) {
            int idx = (int)((w->v2_sync.qc_rr + (uint32_t)k) %
                            (uint32_t)w->peer_count);
            if (w->peers[idx].conn && w->peers[idx].identified) {
                conn = w->peers[idx].conn;
                w->v2_sync.qc_rr = (uint32_t)idx + 1;
                break;
            }
        }
    }
    if (!conn) return;

    nodus_t3_msg_t req;
    memset(&req, 0, sizeof(req));
    req.type = NODUS_T3_V2_BLOCK;
    memcpy(req.w_v2_block_q.chain, w->v2_chain32, 32);
    req.w_v2_block_q.height = height;
    memcpy(req.w_v2_block_q.block_id, bid, 64);
    v2sync_send(w, conn, &req);
    QGP_LOG_INFO(LOG_TAG, "QC-recovery: requested block %llu for its "
                 "missing certificate", (unsigned long long)height);
}

void nodus_witness_v2_sync_tick(nodus_witness_t *w) {
    if (!v2sync_ready(w)) return;

    uint64_t now = v2sync_monotonic_ms();

    /* Expire a timed-out in-flight range request. */
    if (w->v2_sync.req_sent_ms != 0 &&
        now - w->v2_sync.req_sent_ms >= V2SYNC_REQ_TIMEOUT_MS)
        w->v2_sync.req_sent_ms = 0;

    /* The head hint broadcast — HOW peers learn someone is behind. */
    if (w->v2_sync.last_head_ms == 0 ||
        now - w->v2_sync.last_head_ms >= V2SYNC_HEAD_INTERVAL_MS) {
        int ok = 0;
        uint64_t head = v2_head(w, &ok);
        if (ok) {
            nodus_t3_msg_t m;
            memset(&m, 0, sizeof(m));
            m.type = NODUS_T3_V2_HEAD;
            memcpy(m.w_v2_head.chain, w->v2_chain32, 32);
            if (v2sync_genesis_id(w, m.w_v2_head.genesis_id) == 0) {
                m.w_v2_head.head  = head;
                m.w_v2_head.proto = (uint32_t)DNA_BLKW_VERSION;
                (void)nodus_witness_bft_broadcast(w, &m);
                w->v2_sync.last_head_ms = now;
            }
        }
    }

    /* O15E Faz C — bounded missing-QC recovery. One fetch per interval
     * for the lowest committed height whose QC is still NULL; the
     * response heals it through finalize's idempotent-replay path. A
     * fully-certified chain does nothing. */
    if (w->v2_sync.last_qcfetch_ms == 0 ||
        now - w->v2_sync.last_qcfetch_ms >= V2SYNC_QCFETCH_INTERVAL_MS) {
        uint64_t miss = 0;
        if (nodus_witness_v2_qc_first_missing(w, &miss) == 0 && miss > 0) {
            v2sync_fetch_qc(w, miss);
            w->v2_sync.last_qcfetch_ms = now;
        }
    }
}

int nodus_witness_v2_sync_restart_check(nodus_witness_t *w,
                                        uint64_t *bad_height_out) {
    if (bad_height_out) *bad_height_out = 0;
    if (!w || !w->db) return -2;

    if (!nodus_witness_v2_activation_permitted(w))
        return NODUS_V2_NOT_ACTIVE;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT global_height, block_id, header FROM v2_blocks "
            "ORDER BY global_height ASC",
            -1, &st, NULL) != SQLITE_OK)
        return -2;

    /* Carried across rows so the CHAIN is checked, not just each row in
     * isolation. Review R2: verifying only "this header reproduces this id"
     * accepts a set of internally consistent rows that do not link to one
     * another, and accepts a valid height-7 header stored under key 5 —
     * and then reports "intact". A corruption check that cannot see a
     * broken chain is not checking the chain. */
    int      have_prev = 0;
    uint8_t  prev_id[DNA_BH2_ID_LEN];
    uint64_t prev_height = 0;

    int rc, verdict = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint64_t h = (uint64_t)sqlite3_column_int64(st, 0);

        const void *idb = sqlite3_column_blob(st, 1);
        int idn = sqlite3_column_bytes(st, 1);
        const void *hdb = sqlite3_column_blob(st, 2);
        int hdn = sqlite3_column_bytes(st, 2);

        /* A row whose widths are wrong is CORRUPT, not merely odd. Stop at
         * the first one — never skip it to keep going, because a skipped
         * bad record is a silent acceptance. */
        if (!idb || idn != DNA_BH2_ID_LEN ||
            !hdb || hdn != (int)DNA_BH2_ENC_SIZE) {
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        /* THE PROPERTY THE O14 `header` COLUMN EXISTS FOR: re-derive the
         * identity from the STORED canonical bytes and require it to equal
         * the STORED id. The decomposed columns cannot reconstruct a
         * header, so before that column this was uncheckable. */
        dna_block_header_v2_t hdr;
        if (dna_bh2_decode((const uint8_t *)hdb, (size_t)DNA_BH2_ENC_SIZE,
                           &hdr) != 0) {
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        /* THE ROW KEY MUST MATCH THE HEADER. A perfectly self-consistent
         * height-7 header stored under key 5 would otherwise pass — the
         * header reproduces its own id, and nothing looked at where it
         * was filed. */
        if (hdr.block_height != h) {
            QGP_LOG_ERROR(LOG_TAG,
                          "v2_blocks row keyed %llu holds a header for "
                          "height %llu",
                          (unsigned long long)h,
                          (unsigned long long)hdr.block_height);
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        if (h == 0) {
            /* Genesis identity needs the manifest bytes, which this row
             * does not carry, so it is NOT re-derived here — deriving it
             * from an input we do not have is the fabrication this tree
             * forbids. It is covered instead by the preflight's
             * GENESIS_IDENTITY_MISMATCH check, which HAS the committed
             * manifest. Width and decode were already verified above. */
            have_prev   = 1;
            prev_height = h;
            memcpy(prev_id, idb, DNA_BH2_ID_LEN);
            continue;
        }

        uint8_t id[DNA_BH2_ID_LEN];
        if (dna_bh2_block_id(&hdr, id) != 0) {
            if (bad_height_out) *bad_height_out = h;
            verdict = -2;      /* a hash failure is OURS, not corruption */
            break;
        }
        if (memcmp(id, idb, DNA_BH2_ID_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "stored header at height %llu does not reproduce "
                          "its stored BlockID",
                          (unsigned long long)h);
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        /* PARENT LINKAGE. Consecutive rows must actually form a chain:
         * this header's prev_block_id must equal the previous row's stored
         * id, and the heights must be contiguous. Without this, a set of
         * individually valid blocks that link to nothing reports "intact". */
        if (have_prev) {
            if (h != prev_height + 1) {
                QGP_LOG_ERROR(LOG_TAG,
                              "v2_blocks jumps from height %llu to %llu",
                              (unsigned long long)prev_height,
                              (unsigned long long)h);
                if (bad_height_out) *bad_height_out = h;
                verdict = -1;
                break;
            }
            if (memcmp(hdr.prev_block_id, prev_id, DNA_BH2_ID_LEN) != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "block at height %llu does not link to the "
                              "committed block at %llu",
                              (unsigned long long)h,
                              (unsigned long long)prev_height);
                if (bad_height_out) *bad_height_out = h;
                verdict = -1;
                break;
            }
        }
        have_prev   = 1;
        prev_height = h;
        memcpy(prev_id, id, DNA_BH2_ID_LEN);
    }

    /* A scan that ended for any reason other than DONE did not verify the
     * rows it never reached. Report that as "could not perform", never as
     * "intact" — the fail-closed shape nodus/CLAUDE.md requires of every
     * `while (sqlite3_step(...) == SQLITE_ROW)` loop. */
    if (verdict == 0 && rc != SQLITE_DONE) verdict = -2;

    sqlite3_finalize(st);
    return verdict;
}
