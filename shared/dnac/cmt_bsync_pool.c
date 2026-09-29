/**
 * @file shared/dnac/cmt_bsync_pool.c
 * @brief cometbft `blocksync/pool.go` in C (pin v0.38.26 since 2026-09-30;
 *        unmarked line cites are still @709fd12b — see the header's
 *        "REFERENCE PIN") — see cmt_bsync_pool.h for the goroutine → tick
 *        statement, the clock list, the labelled deviations BS-1..BS-4 and
 *        the own fix BS-10 (R1-2).
 *
 * NOTHING HERE READS A CLOCK: every time is the caller's `now_ns`.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_bsync_pool.h"

#include "crypto/utils/qgp_log.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_BSYNC_POOL"

/* Go's `math.E` (math/const.go), the factor of pool.go:593. Spelled out
 * because M_E is not ISO C. */
#define BSYNC_MATH_E 2.71828182845904523536028747135266249775724709369995957496696763

/* ══ helpers ══════════════════════════════════════════════════════════ */

static bool id_ok(const char *id)
{
    return id != NULL && strlen(id) < (size_t)CMT_P2P_ID_CAP;
}

static bool id_eq(const char *a, const char *b)
{
    return strcmp(a, b) == 0;
}

static void id_set(char dst[CMT_P2P_ID_CAP], const char *src)
{
    snprintf(dst, CMT_P2P_ID_CAP, "%s", src != NULL ? src : "");
}

static void deadline_min(int64_t *earliest, int64_t t)
{
    if (earliest != NULL && t < *earliest) {
        *earliest = t;
    }
}

void cmt_bsync_block_free(cmt_bsync_block_t *b)
{
    if (b == NULL) {
        return;
    }
    free(b->txs);
    free(b->arena_buf);
    free(b->evidence);
    free(b->sigs);
    free(b->ext_sigs);
    free(b->ext_arena_buf);
    free(b);
}

/* The requester for `height`, or NULL (a Go map miss). */
static cmt_bsync_requester_t *req_at(const cmt_bsync_pool_t *pool,
                                     int64_t height)
{
    int64_t off;

    if (height < pool->height) {
        return NULL;
    }
    off = height - pool->height;
    if ((uint64_t)off >= (uint64_t)pool->n_requesters) {
        return NULL;
    }
    return pool->requesters[off];
}

static int find_peer(const cmt_bsync_pool_t *pool, const char *id)
{
    size_t i;

    for (i = 0; i < pool->n_peers; i++) {
        if (id_eq(pool->peers[i]->id, id)) {
            return (int)i;
        }
    }
    return -1;
}

/* ══ bpPeer (:560-631) ════════════════════════════════════════════════ */

/* :591-595 resetMonitor() */
static void peer_reset_monitor(cmt_bsync_peer_t *peer, int64_t now_ns)
{
    cmt_flowrate_init(&peer->recv_monitor, CMT_BSYNC_MONITOR_SAMPLE_NS,
                      CMT_BSYNC_MONITOR_WINDOW_NS, now_ns);        /* :592 */
    cmt_flowrate_set_rema(&peer->recv_monitor,
                          (double)CMT_BSYNC_MIN_RECV_RATE *
                              BSYNC_MATH_E);                       /* :593-594 */
    peer->monitor_made = true;
}

/* :597-603 resetTimeout(): AfterFunc on the first call, Reset after. */
static void peer_reset_timeout(const cmt_bsync_pool_t *pool,
                               cmt_bsync_peer_t *peer, int64_t now_ns)
{
    peer->timeout_armed = true;
    peer->timeout_at_ns = now_ns + pool->peer_timeout_ns;
}

/* :605-611 incrPending() */
static void peer_incr_pending(const cmt_bsync_pool_t *pool,
                              cmt_bsync_peer_t *peer, int64_t now_ns)
{
    if (peer->num_pending == 0) {
        peer_reset_monitor(peer, now_ns);                          /* :607 */
        peer_reset_timeout(pool, peer, now_ns);                    /* :608 */
    }
    peer->num_pending++;                                           /* :610 */
}

/* :613-621 decrPending(recvSize) — BS-4 for the two guards; BS-10 for the
 * third: at 0 nothing changes and the timeout is NOT re-armed (the
 * reference would go to −1 and re-arm it, v0.38.26 pool.go:643-651). */
static void peer_decr_pending(const cmt_bsync_pool_t *pool,
                              cmt_bsync_peer_t *peer, size_t recv_size,
                              int64_t now_ns)
{
    if (peer->num_pending <= 0) {
        return;                                                    /* BS-10 */
    }
    peer->num_pending--;                                           /* :614 */
    if (peer->num_pending == 0) {
        peer->timeout_armed = false;                               /* :616 */
    } else {
        if (peer->monitor_made) {
            int n = recv_size > (size_t)INT_MAX ? INT_MAX : (int)recv_size;

            (void)cmt_flowrate_update(&peer->recv_monitor, n, now_ns); /* :618 */
        }
        peer_reset_timeout(pool, peer, now_ns);                    /* :619 */
    }
}

/* ══ requests / errors to the reactor (:523-535) ══════════════════════ */

static void send_request(const cmt_bsync_pool_t *pool, int64_t height,
                         const char *peer_id)
{
    if (!pool->running) {                                          /* :524 */
        return;
    }
    pool->host.send_request(pool->host.ctx, height, peer_id);      /* :527 */
}

static void send_error(const cmt_bsync_pool_t *pool, const char *peer_id,
                       cmt_bsync_peer_err_t err)
{
    if (!pool->running) {                                          /* :531 */
        return;
    }
    pool->host.send_error(pool->host.ctx, peer_id, err);           /* :534 */
}

/* ══ bpRequester's helpers (:681-834) ═════════════════════════════════ */

/* What rq_set_block did (BS-10 splits the reference's `true`). */
typedef enum {
    RQ_SET_NO_MATCH  = 0,  /* :684-687 false — the sender was not asked     */
    RQ_SET_HELD      = 1,  /* :688-691 true — a block is held; `b` NOT taken */
    RQ_SET_STORED    = 2,  /* :693-701 true — `b` stored and taken          */
    RQ_SET_DUPLICATE = 3   /* BS-10 — a held block, and this slot has
                            * already delivered: `b` NOT taken, no counter  */
} rq_set_t;

/* :682-703 setBlock() (v0.38.26 pool.go:712-733), with the BS-10 slot
 * flags. `*out_first` is true when the matching slot delivers for the
 * FIRST time since its assignment — the only case its peer is
 * decremented. */
static rq_set_t rq_set_block(cmt_bsync_requester_t *r, cmt_bsync_block_t *b,
                             const char *peer_id, bool *out_first)
{
    bool *delivered;

    *out_first = false;
    if (id_eq(r->peer_id, peer_id)) {
        delivered = &r->peer_delivered;
    } else if (id_eq(r->second_peer_id, peer_id)) {
        delivered = &r->second_delivered;
    } else {
        return RQ_SET_NO_MATCH;                                    /* :684-687 */
    }
    if (r->block != NULL) {                                        /* :688-691 */
        if (*delivered) {
            return RQ_SET_DUPLICATE;                               /* BS-10 */
        }
        *delivered = true;
        *out_first = true;
        return RQ_SET_HELD;
    }
    *out_first = !*delivered;
    *delivered = true;
    r->block = b;                                                  /* :693-694 */
    id_set(r->got_block_from, peer_id);                            /* :695 */
    r->got_block_ch = true;          /* :698-701 — a full channel drops it */
    return RQ_SET_STORED;
}

/* :732-736 didRequestFrom() */
static bool rq_did_request_from(const cmt_bsync_requester_t *r,
                                const char *peer_id)
{
    return id_eq(r->peer_id, peer_id) || id_eq(r->second_peer_id, peer_id);
}

/* :718-729 requestedFrom() — only its length is ever used (:878). */
static size_t rq_requested_from_len(const cmt_bsync_requester_t *r)
{
    return (r->peer_id[0] != '\0' ? 1u : 0u) +
           (r->second_peer_id[0] != '\0' ? 1u : 0u);
}

/* :746-766 reset(peerID) — the header's quirks are reproduced. */
static bool rq_reset(cmt_bsync_pool_t *pool, cmt_bsync_requester_t *r,
                     const char *peer_id)
{
    bool removed = false;
    char pid[CMT_P2P_ID_CAP];

    id_set(pid, peer_id);          /* `peer_id` may alias r's own field */
    if (id_eq(r->got_block_from, pid)) {                           /* :751 */
        cmt_bsync_block_free(r->block);                            /* :752-753 */
        r->block = NULL;
        r->got_block_from[0] = '\0';                               /* :754 */
        removed = true;                                            /* :755 */
        pool->num_pending++;                                       /* :756 */
    }
    if (id_eq(r->peer_id, pid)) {                                  /* :759 */
        r->peer_id[0] = '\0';
        r->peer_delivered = false;                                 /* BS-10 */
    } else {
        r->second_peer_id[0] = '\0';                               /* :762 */
        r->second_delivered = false;                               /* BS-10 */
    }
    return removed;
}

/* :771-776 redo(peerID) — nonblocking; a second redo before the first is
 * served is dropped. */
static void rq_redo(cmt_bsync_requester_t *r, const char *peer_id)
{
    if (!r->redo_ch) {
        r->redo_ch = true;
        id_set(r->redo_peer, peer_id);
    }
}

/* :829-834 newHeight(height) */
static void rq_new_height(cmt_bsync_requester_t *r, int64_t height)
{
    if (!r->new_height_ch) {
        r->new_height_ch = true;
        r->new_height_val = height;
    }
}

/* ══ BlockPool internals ══════════════════════════════════════════════ */

/* :500-507 sortPeers() — STABLE, curRate descending (header, D3). */
static void sort_peers(cmt_bsync_pool_t *pool)
{
    size_t i;

    for (i = 1; i < pool->n_sorted; i++) {
        cmt_bsync_peer_t *p = pool->sorted_peers[i];
        size_t            j = i;

        while (j > 0 && pool->sorted_peers[j - 1]->cur_rate < p->cur_rate) {
            pool->sorted_peers[j] = pool->sorted_peers[j - 1];
            j--;
        }
        pool->sorted_peers[j] = p;
    }
}

/* cometbft@v0.38.26 blocksync/pool.go:467-482 updateMaxPeerHeight() */
static void update_max_peer_height(cmt_bsync_pool_t *pool)
{
    int64_t max = 0;
    size_t  i;

    for (i = 0; i < pool->n_peers; i++) {
        if (pool->height > 0 && pool->peers[i]->base > pool->height) {
            /* v0.38.26 :471-476 — "Blocks a malicious peer from poisoning
             * maxPeerHeight with an inflated base/height pair no peer can
             * actually serve, which would stall IsCaughtUp forever." */
            continue;
        }
        if (pool->peers[i]->height > max) {
            max = pool->peers[i]->height;
        }
    }
    pool->max_peer_height = max;
}

/* :413-441 removePeer() — CONTRACT: the caller holds the pool. */
static void remove_peer_locked(cmt_bsync_pool_t *pool, const char *peer_id)
{
    char   pid[CMT_P2P_ID_CAP];
    int    idx;
    size_t i;

    id_set(pid, peer_id);
    for (i = 0; i < pool->n_requesters; i++) {                     /* :415 */
        if (rq_did_request_from(pool->requesters[i], pid)) {
            rq_redo(pool->requesters[i], pid);                     /* :417 */
        }
    }
    idx = find_peer(pool, pid);
    if (idx < 0) {
        return;                                                    /* :422 */
    }
    {
        cmt_bsync_peer_t *peer = pool->peers[idx];
        bool              was_max = (peer->height == pool->max_peer_height);

        peer->timeout_armed = false;                               /* :423-425 */
        memmove(&pool->peers[idx], &pool->peers[idx + 1],
                (pool->n_peers - (size_t)idx - 1u) * sizeof(pool->peers[0]));
        pool->n_peers--;                                           /* :427 */
        for (i = 0; i < pool->n_sorted; i++) {                     /* :428-433 */
            if (pool->sorted_peers[i] == peer) {
                memmove(&pool->sorted_peers[i], &pool->sorted_peers[i + 1],
                        (pool->n_sorted - i - 1u) *
                            sizeof(pool->sorted_peers[0]));
                pool->n_sorted--;
                break;
            }
        }
        free(peer);
        if (was_max) {                                             /* :437 */
            update_max_peer_height(pool);                          /* :438 */
        }
    }
}

/* :461-465 isPeerBanned() — an ID never banned reads as the zero time,
 * so `time.Since` is huge and the answer is false. */
static bool is_peer_banned_locked(const cmt_bsync_pool_t *pool,
                                  const char *peer_id, int64_t now_ns)
{
    size_t i;

    for (i = 0; i < pool->n_banned; i++) {
        if (id_eq(pool->banned_ids[i], peer_id)) {
            return now_ns - pool->banned_at_ns[i] < CMT_BSYNC_BAN_NS; /* :464 */
        }
    }
    return false;
}

/* :467-471 banPeer() */
static int ban_peer_locked(cmt_bsync_pool_t *pool, const char *peer_id,
                           int64_t now_ns)
{
    size_t i;

    QGP_LOG_DEBUG(LOG_TAG, "Banning peer %s", peer_id);            /* :469 */
    for (i = 0; i < pool->n_banned; i++) {
        if (id_eq(pool->banned_ids[i], peer_id)) {
            pool->banned_at_ns[i] = now_ns;                        /* :470 */
            return CMT_OK;
        }
    }
    if (pool->n_banned == pool->cap_banned) {
        size_t  ncap = pool->cap_banned ? pool->cap_banned * 2u : 8u;
        char  (*ni)[CMT_P2P_ID_CAP];
        int64_t *nt;

        ni = realloc(pool->banned_ids, ncap * sizeof(*ni));
        if (ni == NULL) {
            return CMT_FAULT;
        }
        pool->banned_ids = ni;
        nt = (int64_t *)realloc(pool->banned_at_ns, ncap * sizeof(*nt));
        if (nt == NULL) {
            return CMT_FAULT;
        }
        pool->banned_at_ns = nt;
        pool->cap_banned = ncap;
    }
    id_set(pool->banned_ids[pool->n_banned], peer_id);
    pool->banned_at_ns[pool->n_banned] = now_ns;                   /* :470 */
    pool->n_banned++;
    return CMT_OK;
}

/* :158-191 removeTimedoutPeers() */
static void remove_timedout_peers(cmt_bsync_pool_t *pool, int64_t now_ns)
{
    size_t i = 0;

    while (i < pool->n_peers) {                                    /* :162 */
        cmt_bsync_peer_t *peer = pool->peers[i];

        if (!peer->did_timeout && peer->num_pending > 0) {         /* :163 */
            int64_t cur_rate = 0;

            if (peer->monitor_made) {
                cmt_flowrate_status_t st;

                cmt_flowrate_status(&peer->recv_monitor, now_ns, &st);
                cur_rate = st.cur_rate;                            /* :164 */
            }
            /* :165-166 "curRate can be 0 on start" */
            if (cur_rate != 0 && cur_rate < CMT_BSYNC_MIN_RECV_RATE) {
                send_error(pool, peer->id, CMT_BSYNC_PEER_ERR_SLOW); /* :167-168 */
                QGP_LOG_ERROR(LOG_TAG, "SendTimeout peer %s: peer is not "
                              "sending us data fast enough (curRate %lld "
                              "KB/s, minRate %d KB/s)", peer->id,
                              (long long)(cur_rate / 1024),
                              CMT_BSYNC_MIN_RECV_RATE / 1024);     /* :169-172 */
                peer->did_timeout = true;                          /* :173 */
            }
            peer->cur_rate = cur_rate;                             /* :176 */
        }
        if (peer->did_timeout) {                                   /* :179 */
            remove_peer_locked(pool, peer->id);                    /* :180 */
            continue;        /* the array shifted into slot i */
        }
        i++;
    }

    i = 0;
    while (i < pool->n_banned) {                                   /* :184-188 */
        if (!is_peer_banned_locked(pool, pool->banned_ids[i], now_ns)) {
            memmove(&pool->banned_ids[i], &pool->banned_ids[i + 1],
                    (pool->n_banned - i - 1u) * sizeof(pool->banned_ids[0]));
            memmove(&pool->banned_at_ns[i], &pool->banned_at_ns[i + 1],
                    (pool->n_banned - i - 1u) * sizeof(pool->banned_at_ns[0]));
            pool->n_banned--;
            continue;
        }
        i++;
    }
    sort_peers(pool);                                              /* :190 */
}

/* :473-498 pickIncrAvailablePeer() — BS-2: every remaining peer is
 * visited once. */
static cmt_bsync_peer_t *pick_incr_available_peer(cmt_bsync_pool_t *pool,
                                                  int64_t height,
                                                  const char *exclude,
                                                  int64_t now_ns)
{
    size_t i = 0;

    while (i < pool->n_sorted) {                                   /* :479 */
        cmt_bsync_peer_t *peer = pool->sorted_peers[i];

        if (id_eq(peer->id, exclude)) {                            /* :480 */
            i++;
            continue;
        }
        if (peer->did_timeout) {                                   /* :483 */
            remove_peer_locked(pool, peer->id);                    /* :484 */
            continue;        /* sorted_peers shifted into slot i */
        }
        if (peer->num_pending >= CMT_BSYNC_MAX_PENDING_REQUESTS_PER_PEER) {
            i++;                                                   /* :487-489 */
            continue;
        }
        if (height < peer->base || height > peer->height) {        /* :490-492 */
            i++;
            continue;
        }
        peer_incr_pending(pool, peer, now_ns);                     /* :493 */
        return peer;                                               /* :494 */
    }
    return NULL;                                                   /* :497 */
}

/* :509-521 makeNextRequester() */
static int make_next_requester(cmt_bsync_pool_t *pool, int64_t next_height)
{
    cmt_bsync_requester_t *r;

    if (pool->n_requesters == pool->cap_requesters) {
        size_t                  ncap = pool->cap_requesters ?
                                       pool->cap_requesters * 2u : 64u;
        cmt_bsync_requester_t **nr;

        nr = (cmt_bsync_requester_t **)realloc(pool->requesters,
                                               ncap * sizeof(*nr));
        if (nr == NULL) {
            return CMT_FAULT;
        }
        pool->requesters = nr;
        pool->cap_requesters = ncap;
    }
    r = (cmt_bsync_requester_t *)calloc(1, sizeof(*r));            /* :513 */
    if (r == NULL) {
        return CMT_FAULT;
    }
    r->height = next_height;                                       /* :663 */
    r->state  = CMT_BSYNC_RQ_PICK;   /* :518 Start → :677 requestRoutine */
    pool->requesters[pool->n_requesters++] = r;                    /* :515 */
    pool->num_pending++;                                           /* :516 */
    return CMT_OK;
}

/* :806-826 pickSecondPeerAndSendRequest() */
static bool rq_pick_second_peer_and_send_request(cmt_bsync_pool_t *pool,
                                                 cmt_bsync_requester_t *r,
                                                 int64_t now_ns)
{
    cmt_bsync_peer_t *second;

    if (r->second_peer_id[0] != '\0') {                            /* :808-811 */
        return false;
    }
    second = pick_incr_available_peer(pool, r->height, r->peer_id, now_ns); /* :815 */
    if (second != NULL) {
        id_set(r->second_peer_id, second->id);                     /* :818 */
        r->second_delivered = false;                  /* BS-10: a new assignment */
        send_request(pool, r->height, second->id);                 /* :821 */
        return true;
    }
    return false;                                                  /* :825 */
}

/* :838-902 requestRoutine(), as a step run until it would wait (header).
 * BS-1: the ready channels are served in the order gotBlock, redo,
 * newHeight, retryTimer. */
static void rq_step(cmt_bsync_pool_t *pool, cmt_bsync_requester_t *r,
                    int64_t now_ns, int64_t *earliest)
{
    for (;;) {
        if (!pool->running) {                                      /* :786, :855 */
            return;
        }
        if (r->state == CMT_BSYNC_RQ_PICK) {
            /* :843 pickPeerAndSendRequest (:778-802). */
            cmt_bsync_peer_t *peer;
            char              second[CMT_P2P_ID_CAP];

            if (now_ns < r->pick_not_before_ns) {                  /* :792 sleep */
                deadline_min(earliest, r->pick_not_before_ns);
                return;
            }
            id_set(second, r->second_peer_id);                     /* :779-781 */
            peer = pick_incr_available_peer(pool, r->height, second, now_ns); /* :789 */
            if (peer == NULL) {
                QGP_LOG_DEBUG(LOG_TAG, "No peers currently available; will "
                              "retry shortly (height %lld)",
                              (long long)r->height);               /* :791 */
                r->pick_not_before_ns = now_ns + CMT_BSYNC_REQUEST_INTERVAL_NS;
                deadline_min(earliest, r->pick_not_before_ns);     /* :792-793 */
                return;
            }
            id_set(r->peer_id, peer->id);                          /* :797-799 */
            r->peer_delivered = false;                /* BS-10: a new assignment */
            send_request(pool, r->height, peer->id);               /* :801 */

            /* :845-848 */
            if (r->height - pool->height < CMT_BSYNC_MIN_BLOCKS_FOR_SINGLE_REQUEST) {
                (void)rq_pick_second_peer_and_send_request(pool, r, now_ns);
            }
            r->retry_armed = true;                                 /* :850 */
            r->retry_at_ns = now_ns + CMT_BSYNC_REQUEST_RETRY_NS;
            r->state = CMT_BSYNC_RQ_WAIT;
        }

        /* :853-900 — the inner select, BS-1's order. */
        if (r->got_block_ch) {                                     /* :895 */
            r->got_block_ch = false;
            r->got_block = true;                                   /* :896 */
        }
        if (r->redo_ch) {                                          /* :869 */
            char pid[CMT_P2P_ID_CAP];

            r->redo_ch = false;
            id_set(pid, r->redo_peer);
            if (rq_did_request_from(r, pid)) {                     /* :870 */
                if (rq_reset(pool, r, pid)) {                      /* :871 */
                    r->got_block = false;                          /* :872-874 */
                }
            }
            if (rq_requested_from_len(r) == 0) {                   /* :878 */
                r->retry_armed = false;                            /* :879 */
                r->state = CMT_BSYNC_RQ_PICK;                      /* :880 */
                r->pick_not_before_ns = 0;
                continue;
            }
        }
        if (r->new_height_ch) {                                    /* :882 */
            int64_t nh = r->new_height_val;

            r->new_height_ch = false;
            if (!r->got_block &&
                r->height - nh < CMT_BSYNC_MIN_BLOCKS_FOR_SINGLE_REQUEST) { /* :883 */
                if (rq_pick_second_peer_and_send_request(pool, r, now_ns)) {
                    r->retry_armed = true;                         /* :889-892 */
                    r->retry_at_ns = now_ns + CMT_BSYNC_REQUEST_RETRY_NS;
                }
            }
        }
        if (r->retry_armed && now_ns >= r->retry_at_ns) {          /* :862 */
            r->retry_armed = false;          /* a Timer fires once */
            if (!r->got_block) {                                   /* :863 */
                char p1[CMT_P2P_ID_CAP];
                char p2[CMT_P2P_ID_CAP];

                QGP_LOG_DEBUG(LOG_TAG, "Retrying block request(s) after "
                              "timeout (height %lld)",
                              (long long)r->height);               /* :864 */
                id_set(p1, r->peer_id);
                id_set(p2, r->second_peer_id);
                (void)rq_reset(pool, r, p1);                       /* :865 */
                (void)rq_reset(pool, r, p2);                       /* :866 */
                r->state = CMT_BSYNC_RQ_PICK;                      /* :867 */
                r->pick_not_before_ns = 0;
                continue;
            }
        }
        if (r->retry_armed) {
            deadline_min(earliest, r->retry_at_ns);
        }
        return;
    }
}

/* :120-156 makeRequestersRoutine(), one iteration per 2 ms (header). */
static int make_requesters_step(cmt_bsync_pool_t *pool, int64_t now_ns,
                                int64_t *earliest)
{
    bool    max_requesters_created;
    int64_t next_height;
    bool    max_peer_height_reached;

    /* :126-132 — the peerConnWait sleep. */
    if (now_ns - pool->start_time_ns < CMT_BSYNC_PEER_CONN_WAIT_NS) {
        deadline_min(earliest, pool->start_time_ns + CMT_BSYNC_PEER_CONN_WAIT_NS);
        return CMT_OK;
    }
    if (now_ns < pool->mr_not_before_ns) {
        deadline_min(earliest, pool->mr_not_before_ns);
        return CMT_OK;
    }
    if (pool->mr_next == CMT_BSYNC_MR_REMOVE_TIMEDOUT) {
        remove_timedout_peers(pool, now_ns);                       /* :146 */
        pool->mr_next = CMT_BSYNC_MR_EVALUATE;
    }

    max_requesters_created = pool->n_requesters >=
        pool->n_peers * (size_t)CMT_BSYNC_MAX_PENDING_REQUESTS_PER_PEER; /* :136 */
    next_height = pool->height + (int64_t)pool->n_requesters;     /* :138 */
    max_peer_height_reached = next_height > pool->max_peer_height;  /* :139 */

    if (max_requesters_created) {                                  /* :144 */
        pool->mr_next = CMT_BSYNC_MR_REMOVE_TIMEDOUT;              /* :145-146 */
    } else if (max_peer_height_reached) {                          /* :147 */
        /* :148 — wait for a bit */
    } else {
        if (make_next_requester(pool, next_height) != CMT_OK) {    /* :151 */
            return CMT_FAULT;
        }
    }
    pool->mr_not_before_ns = now_ns + CMT_BSYNC_REQUEST_INTERVAL_NS; /* :145/:148/:153 */
    deadline_min(earliest, pool->mr_not_before_ns);
    return CMT_OK;
}

/* ══ public API ═══════════════════════════════════════════════════════ */

/* :93-109 NewBlockPool() */
int cmt_bsync_pool_init(cmt_bsync_pool_t *pool, int64_t start,
                        const cmt_bsync_pool_host_t *host)
{
    if (pool == NULL || host == NULL || host->send_request == NULL ||
        host->send_error == NULL) {
        return CMT_FAULT;
    }
    memset(pool, 0, sizeof(*pool));
    pool->height          = start;                                 /* :100 */
    pool->start_height    = start;                                 /* :101 */
    pool->num_pending     = 0;                                     /* :102 */
    pool->host            = *host;                                 /* :104-105 */
    pool->peer_timeout_ns = CMT_BSYNC_PEER_TIMEOUT_NS;             /* :57 */
    pool->mr_next         = CMT_BSYNC_MR_EVALUATE;
    return CMT_OK;
}

static void free_requesters(cmt_bsync_pool_t *pool)
{
    size_t i;

    for (i = 0; i < pool->n_requesters; i++) {
        cmt_bsync_block_free(pool->requesters[i]->block);
        free(pool->requesters[i]);
    }
    pool->n_requesters = 0;
}

void cmt_bsync_pool_free(cmt_bsync_pool_t *pool)
{
    size_t i;

    if (pool == NULL) {
        return;
    }
    free_requesters(pool);
    free(pool->requesters);
    for (i = 0; i < pool->n_peers; i++) {
        free(pool->peers[i]);
    }
    free(pool->peers);
    free(pool->sorted_peers);
    free(pool->banned_ids);
    free(pool->banned_at_ns);
    memset(pool, 0, sizeof(*pool));
}

/* :113-117 OnStart() */
int cmt_bsync_pool_start(cmt_bsync_pool_t *pool, int64_t now_ns)
{
    if (pool == NULL) {
        return CMT_FAULT;
    }
    if (pool->running) {
        return CMT_OK;                            /* ErrAlreadyStarted */
    }
    pool->running          = true;
    pool->start_time_ns    = now_ns;                               /* :114 */
    pool->mr_not_before_ns = 0;
    pool->mr_next          = CMT_BSYNC_MR_EVALUATE;
    return CMT_OK;                                /* :115 go makeRequesters */
}

void cmt_bsync_pool_stop(cmt_bsync_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    pool->running = false;
    free_requesters(pool);                                         /* BS-3 */
}

bool cmt_bsync_pool_is_running(const cmt_bsync_pool_t *pool)
{
    return pool != NULL && pool->running;
}

int cmt_bsync_pool_tick(cmt_bsync_pool_t *pool, int64_t now_ns,
                        int64_t *out_deadline_ns)
{
    int64_t earliest = INT64_MAX;
    size_t  i;

    if (out_deadline_ns != NULL) {
        *out_deadline_ns = INT64_MAX;
    }
    if (pool == NULL) {
        return CMT_FAULT;
    }
    if (!pool->running) {
        return CMT_OK;
    }
    /* makeRequestersRoutine (:120-156) */
    if (make_requesters_step(pool, now_ns, &earliest) != CMT_OK) {
        return CMT_FAULT;
    }
    /* every peer's AfterFunc timer (:597-603) → onTimeout (:623-631) */
    for (i = 0; i < pool->n_peers; i++) {
        cmt_bsync_peer_t *peer = pool->peers[i];

        if (!peer->timeout_armed) {
            continue;
        }
        if (now_ns >= peer->timeout_at_ns) {
            peer->timeout_armed = false;                 /* fired: spent */
            send_error(pool, peer->id, CMT_BSYNC_PEER_ERR_TIMEOUT); /* :627-628 */
            QGP_LOG_ERROR(LOG_TAG, "SendTimeout peer %s: peer did not send "
                          "us anything (timeout %lld ms)", peer->id,
                          (long long)(pool->peer_timeout_ns /
                                      CMT_BSYNC_NS_PER_MS));       /* :629 */
            peer->did_timeout = true;                              /* :630 */
        } else {
            deadline_min(&earliest, peer->timeout_at_ns);
        }
    }
    /* every requester's requestRoutine (:838-902), in height order */
    for (i = 0; i < pool->n_requesters; i++) {
        rq_step(pool, pool->requesters[i], now_ns, &earliest);
    }
    if (out_deadline_ns != NULL) {
        *out_deadline_ns = earliest;
    }
    return CMT_OK;
}

/* :193-200 GetStatus() */
void cmt_bsync_pool_get_status(const cmt_bsync_pool_t *pool, int64_t *height,
                               int32_t *num_pending, size_t *len_requesters)
{
    if (pool == NULL) {
        return;
    }
    if (height != NULL) {
        *height = pool->height;
    }
    if (num_pending != NULL) {
        *num_pending = pool->num_pending;
    }
    if (len_requesters != NULL) {
        *len_requesters = pool->n_requesters;
    }
}

/* cometbft@v0.38.26 blocksync/pool.go:202-213 HasPendingRequestFrom() —
 * every requester, in height order (the reference's map order does not
 * matter: the answer is an OR). */
bool cmt_bsync_pool_has_pending_request_from(const cmt_bsync_pool_t *pool,
                                             const char *peer_id)
{
    size_t i;

    if (pool == NULL || !id_ok(peer_id)) {
        return false;
    }
    for (i = 0; i < pool->n_requesters; i++) {                     /* :207 */
        if (rq_did_request_from(pool->requesters[i], peer_id)) {   /* :208 */
            return true;                                           /* :209 */
        }
    }
    return false;                                                  /* :212 */
}

/* :202-223 IsCaughtUp() */
bool cmt_bsync_pool_is_caught_up(const cmt_bsync_pool_t *pool, int64_t now_ns)
{
    bool received_block_or_timed_out;
    bool our_chain_is_longest_among_peers;

    if (pool == NULL) {
        return false;
    }
    if (pool->n_peers == 0) {                                      /* :209 */
        QGP_LOG_DEBUG(LOG_TAG, "Blockpool has no peers");          /* :210 */
        return false;
    }
    received_block_or_timed_out = pool->height > 0 ||
        now_ns - pool->start_time_ns > CMT_BSYNC_CAUGHT_UP_WAIT_NS; /* :219 */
    our_chain_is_longest_among_peers = pool->max_peer_height == 0 ||
        pool->height >= pool->max_peer_height - 1;                 /* :220 */
    return received_block_or_timed_out &&
           our_chain_is_longest_among_peers;                       /* :221-222 */
}

/* :225-244 PeekTwoBlocks() */
void cmt_bsync_pool_peek_two_blocks(const cmt_bsync_pool_t *pool,
                                    cmt_bsync_block_t **first,
                                    cmt_bsync_block_t **second)
{
    cmt_bsync_requester_t *r;

    if (first != NULL) {
        *first = NULL;
    }
    if (second != NULL) {
        *second = NULL;
    }
    if (pool == NULL) {
        return;
    }
    r = req_at(pool, pool->height);
    if (r != NULL && first != NULL) {
        *first = r->block;                                         /* :237-238 */
    }
    r = req_at(pool, pool->height + 1);
    if (r != NULL && second != NULL) {
        *second = r->block;                                        /* :241 */
    }
}

/* :246-267 PopRequest() */
int cmt_bsync_pool_pop_request(cmt_bsync_pool_t *pool,
                               cmt_bsync_block_t **out_block)
{
    cmt_bsync_requester_t *r;
    size_t                 i;

    if (out_block != NULL) {
        *out_block = NULL;
    }
    if (pool == NULL) {
        return CMT_FAULT;
    }
    r = req_at(pool, pool->height);                                /* :251 */
    if (r == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "Expected requester to pop, got nothing at "
                      "height %lld", (long long)pool->height);     /* :252-254 */
        return CMT_FAULT;
    }
    if (out_block != NULL) {
        *out_block = r->block;           /* ownership to the caller */
    } else {
        cmt_bsync_block_free(r->block);
    }
    r->block = NULL;
    free(r);                                                       /* :256-259 */
    memmove(&pool->requesters[0], &pool->requesters[1],
            (pool->n_requesters - 1u) * sizeof(pool->requesters[0]));
    pool->n_requesters--;
    pool->height++;                                                /* :260 */
    /* cometbft@v0.38.26 blocksync/pool.go:275-276 — "Re-evaluate
     * maxPeerHeight: peers whose pruned base was just beyond the previous
     * pool.height may now be able to contribute". */
    update_max_peer_height(pool);
    /* :262-266 */
    for (i = 0; i < (size_t)CMT_BSYNC_MIN_BLOCKS_FOR_SINGLE_REQUEST &&
                i < pool->n_requesters; i++) {
        rq_new_height(pool->requesters[i], pool->height);
    }
    return CMT_OK;
}

/* :269-282 RemovePeerAndRedoAllPeerRequests() */
int cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
        cmt_bsync_pool_t *pool, int64_t height, int64_t now_ns,
        char out_peer_id[CMT_P2P_ID_CAP])
{
    cmt_bsync_requester_t *r;
    char                   pid[CMT_P2P_ID_CAP];

    if (out_peer_id != NULL) {
        out_peer_id[0] = '\0';
    }
    if (pool == NULL) {
        return CMT_FAULT;
    }
    r = req_at(pool, height);                                      /* :276 */
    if (r == NULL) {
        /* :277 dereferences the nil requester — a Go panic. */
        QGP_LOG_ERROR(LOG_TAG, "no requester at height %lld to redo",
                      (long long)height);
        return CMT_FAULT;
    }
    id_set(pid, r->got_block_from);                                /* :277 */
    remove_peer_locked(pool, pid);                                 /* :279 */
    if (ban_peer_locked(pool, pid, now_ns) != CMT_OK) {            /* :280 */
        return CMT_FAULT;
    }
    if (out_peer_id != NULL) {
        id_set(out_peer_id, pid);                                  /* :281 */
    }
    return CMT_OK;
}

/* :297-300 RedoRequest() — deprecated alias. */
int cmt_bsync_pool_redo_request(cmt_bsync_pool_t *pool, int64_t height,
                                int64_t now_ns,
                                char out_peer_id[CMT_P2P_ID_CAP])
{
    return cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
               pool, height, now_ns, out_peer_id);                 /* :299 */
}

/* :284-295 RedoRequestFrom() */
void cmt_bsync_pool_redo_request_from(cmt_bsync_pool_t *pool, int64_t height,
                                      const char *peer_id)
{
    cmt_bsync_requester_t *r;

    if (pool == NULL || !id_ok(peer_id)) {
        return;
    }
    r = req_at(pool, height);                                      /* :290 */
    if (r != NULL && rq_did_request_from(r, peer_id)) {            /* :291 */
        rq_redo(r, peer_id);                                       /* :292 */
    }
}

/* :302-351 AddBlock() — takes ownership of `b` in every case. */
int cmt_bsync_pool_add_block(cmt_bsync_pool_t *pool, const char *peer_id,
                             cmt_bsync_block_t *b, int64_t now_ns)
{
    cmt_bsync_requester_t *r;
    int64_t                height;
    size_t                 size;
    rq_set_t               set;
    bool                   first = false;
    int                    pidx;

    if (pool == NULL || b == NULL || !id_ok(peer_id)) {
        cmt_bsync_block_free(b);
        return CMT_FAULT;
    }
    height = b->block.header.height;
    size   = b->size;

    if (b->has_ext_commit && height != b->ext_commit.height) {     /* :315 */
        QGP_LOG_ERROR(LOG_TAG, "block height %lld != extCommit height %lld",
                      (long long)height, (long long)b->ext_commit.height);
        send_error(pool, peer_id, CMT_BSYNC_PEER_ERR_EXT_HEIGHT);  /* :318 */
        cmt_bsync_block_free(b);
        return CMT_REJECT;                                         /* :319 */
    }

    r = req_at(pool, height);                                      /* :322 */
    if (r == NULL) {
        cmt_bsync_block_free(b);
        if (height > pool->height || height < pool->start_height) { /* :328 */
            QGP_LOG_ERROR(LOG_TAG, "peer sent us block #%lld we didn't "
                          "expect (current height: %lld, start height: %lld)",
                          (long long)height, (long long)pool->height,
                          (long long)pool->start_height);          /* :329-330 */
            send_error(pool, peer_id, CMT_BSYNC_PEER_ERR_UNEXPECTED); /* :331 */
            return CMT_REJECT;
        }
        QGP_LOG_DEBUG(LOG_TAG, "got an already committed block #%lld "
                      "(possibly from the slow peer %s)", (long long)height,
                      peer_id);                                    /* :335 */
        return CMT_REJECT;
    }

    set = rq_set_block(r, b, peer_id, &first);                     /* :338 */
    if (set == RQ_SET_NO_MATCH) {
        QGP_LOG_ERROR(LOG_TAG, "requested block #%lld from %s/%s, not %s",
                      (long long)height, r->peer_id, r->second_peer_id,
                      peer_id);                                    /* :339 */
        send_error(pool, peer_id, CMT_BSYNC_PEER_ERR_WRONG_SENDER); /* :340 */
        cmt_bsync_block_free(b);
        return CMT_REJECT;
    }
    if (set == RQ_SET_DUPLICATE) {
        /* BS-10: this slot already delivered and a block is held — the
         * copy changes nothing and blames nobody. */
        QGP_LOG_DEBUG(LOG_TAG, "dropping a repeated block #%lld from %s",
                      (long long)height, peer_id);
        cmt_bsync_block_free(b);
        return CMT_OK;
    }
    if (set == RQ_SET_HELD) {
        /* :690 "getting a block from both peers is not an error" — the
         * second copy is not kept. */
        cmt_bsync_block_free(b);
    }

    /* The reference decrements both counters for every copy (v0.38.26
     * pool.go:360-364); BS-10: the pool counter only for the stored
     * copy, the peer once per assignment. */
    if (set == RQ_SET_STORED) {
        pool->num_pending--;                                       /* :344 */
    }
    if (first) {
        pidx = find_peer(pool, peer_id);                           /* :345 */
        if (pidx >= 0) {
            peer_decr_pending(pool, pool->peers[pidx], size, now_ns); /* :347 */
        }
    }
    return CMT_OK;                                                 /* :350 */
}

/* :353-358 Height() */
int64_t cmt_bsync_pool_height(const cmt_bsync_pool_t *pool)
{
    return pool != NULL ? pool->height : 0;
}

/* :360-365 MaxPeerHeight() */
int64_t cmt_bsync_pool_max_peer_height(const cmt_bsync_pool_t *pool)
{
    return pool != NULL ? pool->max_peer_height : 0;
}

/* :367-402 SetPeerRange() */
int cmt_bsync_pool_set_peer_range(cmt_bsync_pool_t *pool, const char *peer_id,
                                  int64_t base, int64_t height, int64_t now_ns)
{
    int idx;

    if (pool == NULL || !id_ok(peer_id)) {
        return CMT_FAULT;
    }
    /* cometbft@v0.38.26 blocksync/pool.go:388-396 — "A peer whose own
     * reported base exceeds its own height is structurally impossible and
     * treated as malicious." */
    if (base > height) {
        QGP_LOG_INFO(LOG_TAG, "Peer %s reporting base greater than height "
                     "(base %lld, height %lld)", peer_id, (long long)base,
                     (long long)height);                           /* :390 */
        if (find_peer(pool, peer_id) >= 0) {                       /* :391 */
            remove_peer_locked(pool, peer_id);                     /* :392 */
        }
        return ban_peer_locked(pool, peer_id, now_ns);             /* :394-395 */
    }
    idx = find_peer(pool, peer_id);                                /* :372 */
    if (idx >= 0) {
        cmt_bsync_peer_t *peer = pool->peers[idx];

        if (base < peer->base || height < peer->height) {          /* :374 */
            QGP_LOG_INFO(LOG_TAG, "Peer %s is reporting height/base that is "
                         "lower than what it previously reported (height "
                         "%lld base %lld, prev %lld/%lld)", peer_id,
                         (long long)height, (long long)base,
                         (long long)peer->height,
                         (long long)peer->base);                   /* :375-378 */
            remove_peer_locked(pool, peer_id);                     /* :380 */
            return ban_peer_locked(pool, peer_id, now_ns);         /* :381-382 */
        }
        peer->base   = base;                                       /* :384 */
        peer->height = height;                                     /* :385 */
    } else {
        cmt_bsync_peer_t *peer;

        if (is_peer_banned_locked(pool, peer_id, now_ns)) {        /* :387 */
            QGP_LOG_DEBUG(LOG_TAG, "Ignoring banned peer %s", peer_id); /* :388 */
            return CMT_OK;
        }
        if (pool->n_peers == pool->cap_peers) {
            size_t             ncap = pool->cap_peers ? pool->cap_peers * 2u : 16u;
            cmt_bsync_peer_t **np;
            cmt_bsync_peer_t **ns;

            np = (cmt_bsync_peer_t **)realloc(pool->peers, ncap * sizeof(*np));
            if (np == NULL) {
                return CMT_FAULT;
            }
            pool->peers = np;
            ns = (cmt_bsync_peer_t **)realloc(pool->sorted_peers,
                                              ncap * sizeof(*ns));
            if (ns == NULL) {
                return CMT_FAULT;
            }
            pool->sorted_peers = ns;
            pool->cap_peers = ncap;
        }
        peer = (cmt_bsync_peer_t *)calloc(1, sizeof(*peer));       /* :391 newBPPeer */
        if (peer == NULL) {
            return CMT_FAULT;
        }
        id_set(peer->id, peer_id);                                 /* :578 */
        peer->base   = base;                                       /* :579 */
        peer->height = height;                                     /* :580 */
        pool->peers[pool->n_peers++] = peer;                       /* :393 */
        /* :394-396 — at the FRONT of the sorted list. */
        memmove(&pool->sorted_peers[1], &pool->sorted_peers[0],
                pool->n_sorted * sizeof(pool->sorted_peers[0]));
        pool->sorted_peers[0] = peer;
        pool->n_sorted++;
    }
    update_max_peer_height(pool);           /* cometbft@v0.38.26 pool.go:425 */
    return CMT_OK;
}

/* :404-411 RemovePeer() */
void cmt_bsync_pool_remove_peer(cmt_bsync_pool_t *pool, const char *peer_id)
{
    if (pool == NULL || !id_ok(peer_id)) {
        return;
    }
    remove_peer_locked(pool, peer_id);                             /* :410 */
}

/* :454-459 IsPeerBanned() */
bool cmt_bsync_pool_is_peer_banned(const cmt_bsync_pool_t *pool,
                                   const char *peer_id, int64_t now_ns)
{
    if (pool == NULL || !id_ok(peer_id)) {
        return false;
    }
    return is_peer_banned_locked(pool, peer_id, now_ns);           /* :458 */
}

const cmt_bsync_peer_t *cmt_bsync_pool_peer(const cmt_bsync_pool_t *pool,
                                            const char *peer_id)
{
    int idx;

    if (pool == NULL || !id_ok(peer_id)) {
        return NULL;
    }
    idx = find_peer(pool, peer_id);
    return idx >= 0 ? pool->peers[idx] : NULL;
}

const cmt_bsync_requester_t *cmt_bsync_pool_requester(
        const cmt_bsync_pool_t *pool, int64_t height)
{
    return pool != NULL ? req_at(pool, height) : NULL;
}
