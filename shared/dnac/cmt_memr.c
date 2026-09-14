/**
 * @file shared/dnac/cmt_memr.c
 * @brief cometbft @709fd12b `mempool/reactor.go` in C — see the header
 *        for the goroutine → tick statement that shapes `cmt_memr_tick`.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_memr.h"

#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_MEMR"

/* ══ helpers ══════════════════════════════════════════════════════════ */

static bool slot_ok(int slot)
{
    return slot >= 0 && slot < (int)CMT_MEM_MAX_PEERS;
}

/* The semaphore a peer's routine goes through (:94-102). */
static cmt_memr_semaphore_t choose_semaphore(const cmt_memr_t *memR,
                                             const cmt_memr_peer_t *p)
{
    if (p->is_unconditional) {                                     /* :95 */
        return CMT_MEMR_SEM_NONE;
    }
    if (p->is_persistent &&
        memR->config->experimental_max_gossip_connections_to_persistent_peers > 0) {
        return CMT_MEMR_SEM_PERSISTENT;                            /* :98-99 */
    }
    if (!p->is_persistent &&
        memR->config->experimental_max_gossip_connections_to_non_persistent_peers > 0) {
        return CMT_MEMR_SEM_NON_PERSISTENT;                        /* :100-101 */
    }
    return CMT_MEMR_SEM_NONE;
}

/* semaphore.Acquire(ctx, 1) (:111): true when a slot was free. */
static bool semaphore_try_acquire(cmt_memr_t *memR, cmt_memr_semaphore_t s)
{
    switch (s) {
    case CMT_MEMR_SEM_PERSISTENT:
        if (memR->active_persistent_peers <
            memR->config->experimental_max_gossip_connections_to_persistent_peers) {
            memR->active_persistent_peers++;
            return true;
        }
        return false;
    case CMT_MEMR_SEM_NON_PERSISTENT:
        if (memR->active_non_persistent_peers <
            memR->config->experimental_max_gossip_connections_to_non_persistent_peers) {
            memR->active_non_persistent_peers++;
            return true;
        }
        return false;
    default:
        return true;
    }
}

/* semaphore.Release(1) (:119). */
static void semaphore_release(cmt_memr_t *memR, cmt_memr_semaphore_t s)
{
    switch (s) {
    case CMT_MEMR_SEM_PERSISTENT:
        if (memR->active_persistent_peers > 0) {
            memR->active_persistent_peers--;
        }
        break;
    case CMT_MEMR_SEM_NON_PERSISTENT:
        if (memR->active_non_persistent_peers > 0) {
            memR->active_non_persistent_peers--;
        }
        break;
    default:
        break;
    }
}

/* Move a peer's cursor reference (cmt_clist.h). */
static void peer_set_next(cmt_memr_peer_t *p, cmt_clist_elem_t *e)
{
    cmt_clist_elem_t *old = p->next;

    cmt_clist_elem_ref(e);
    p->next = e;
    cmt_clist_elem_unref(old);
}

/* The routine returns (:192, :205-207, :254-256): cursor released,
 * semaphore given back (the deferred Release of :119). */
static void routine_end(cmt_memr_t *memR, cmt_memr_peer_t *p)
{
    if (p->state == CMT_MEMR_ROUTINE_RUNNING) {
        semaphore_release(memR, p->semaphore);
    }
    peer_set_next(p, NULL);
    p->state         = CMT_MEMR_ROUTINE_NONE;
    p->semaphore     = CMT_MEMR_SEM_NONE;
    p->waiting_next  = false;
    p->sleeping      = false;
    p->not_before_ns = 0;
}

/* :186 — the routine's first line: the peer's mempool id. */
static void routine_start(cmt_memr_t *memR, int slot, cmt_memr_peer_t *p)
{
    p->peer_id       = cmt_mem_ids_get_for_peer(&memR->ids, slot);  /* :186 */
    p->state         = CMT_MEMR_ROUTINE_RUNNING;
    p->waiting_next  = false;
    p->sleeping      = false;
    p->not_before_ns = 0;
    peer_set_next(p, NULL);                                        /* :187 */
}

/* ══ construction (:36-47) ════════════════════════════════════════════ */

int cmt_memr_init(cmt_memr_t *memR, const cmt_mempool_config_t *config,
                  cmt_mem_t *mempool, const cmt_memr_host_t *host)
{
    cmt_memr_channel_descriptor_t d;

    if (memR == NULL || config == NULL || mempool == NULL || host == NULL) {
        return CMT_FAULT;
    }
    if (config->max_tx_bytes < 0) {
        return CMT_FAULT;
    }
    memset(memR, 0, sizeof(*memR));
    memR->config  = config;                                        /* :38 */
    memR->mempool = mempool;                                       /* :39 */
    memR->host    = host;
    if (cmt_mem_ids_init(&memR->ids) != CMT_OK) {                  /* :40 */
        return CMT_FAULT;
    }
    /* :43-44 — the two semaphores' capacities are read from the config
     * at every acquire; the held counts start at zero. */

    /* The decode / send storage of the header, sized from :71-89. */
    if (cmt_memr_get_channels(memR, &d) != CMT_OK) {
        return CMT_FAULT;
    }
    memR->recv_message_capacity = d.recv_message_capacity;
    memR->arena_buf = (uint8_t *)malloc(memR->recv_message_capacity + 1u);
    memR->rx_slots_cap = memR->recv_message_capacity / 2u + 1u;
    memR->rx_slots = (cmt_pb_bytes_t *)calloc(memR->rx_slots_cap,
                                              sizeof(*memR->rx_slots));
    memR->tx_buf_cap = memR->recv_message_capacity + 1u;
    memR->tx_buf = (uint8_t *)malloc(memR->tx_buf_cap);
    if (memR->arena_buf == NULL || memR->rx_slots == NULL ||
        memR->tx_buf == NULL) {
        free(memR->arena_buf);
        free(memR->rx_slots);
        free(memR->tx_buf);
        memset(memR, 0, sizeof(*memR));
        return CMT_FAULT;
    }
    memR->arena.buf  = memR->arena_buf;
    memR->arena.cap  = memR->recv_message_capacity + 1u;
    memR->arena.used = 0;
    return CMT_OK;                                                 /* :46 */
}

void cmt_memr_free(cmt_memr_t *memR)
{
    size_t i;

    if (memR == NULL) {
        return;
    }
    for (i = 0; i < CMT_MEM_MAX_PEERS; i++) {
        routine_end(memR, &memR->peers[i]);
    }
    free(memR->arena_buf);
    free(memR->rx_slots);
    free(memR->tx_buf);
    memset(memR, 0, sizeof(*memR));
}

/* :50-53 — InitPeer(peer) */
int cmt_memr_init_peer(cmt_memr_t *memR, int peer_slot)
{
    if (memR == NULL) {
        return CMT_FAULT;
    }
    return cmt_mem_ids_reserve_for_peer(&memR->ids, peer_slot);    /* :51 */
}

/* :62-67 — OnStart() */
int cmt_memr_start(cmt_memr_t *memR)
{
    if (memR == NULL) {
        return CMT_FAULT;
    }
    memR->running = true;
    if (!memR->config->broadcast) {                                /* :63 */
        QGP_LOG_INFO(LOG_TAG, "Tx broadcasting is disabled");      /* :64 */
    }
    return CMT_OK;                                                 /* :66 */
}

int cmt_memr_stop(cmt_memr_t *memR)
{
    size_t i;

    if (memR == NULL) {
        return CMT_FAULT;
    }
    memR->running = false;
    for (i = 0; i < CMT_MEM_MAX_PEERS; i++) {                     /* :206-207, :255-256 */
        routine_end(memR, &memR->peers[i]);
    }
    return CMT_OK;
}

/* :71-89 — GetChannels() */
int cmt_memr_get_channels(const cmt_memr_t *memR,
                          cmt_memr_channel_descriptor_t *out)
{
    cmt_pb_bytes_t           largest;
    cmt_pb_mempool_message_t batch;

    if (memR == NULL || out == NULL || memR->config == NULL) {
        return CMT_FAULT;
    }
    /* :72 — make([]byte, MaxTxBytes): only the LENGTH matters to Size(). */
    largest.data = NULL;
    largest.len  = (size_t)memR->config->max_tx_bytes;
    /* :73-77 — Message{Sum: &Message_Txs{Txs: &Txs{Txs: [largestTx]}}}.
     * The slot fields are set BEFORE `_init`, which preserves exactly
     * those two and zeroes the rest (cmt_pb.c:1901-1914). */
    batch.txs.txs     = &largest;
    batch.txs.txs_cap = 1;
    cmt_pb_mempool_message_init(&batch);
    batch.sum         = CMT_PB_MEMPOOL_MSG_TXS;
    batch.txs.txs_len = 1;

    out->id                    = (uint8_t)CMT_MEM_CHANNEL;         /* :81 */
    out->priority              = 5;                                /* :82 */
    out->recv_message_capacity = cmt_pb_mempool_message_size(&batch); /* :83 */
    return CMT_OK;
}

/* ══ peers (:91-136) ══════════════════════════════════════════════════ */

/* :91-130 — AddPeer(peer) */
int cmt_memr_add_peer(cmt_memr_t *memR, int peer_slot, bool is_persistent,
                      bool is_unconditional)
{
    cmt_memr_peer_t *p;

    if (memR == NULL) {
        return CMT_FAULT;
    }
    if (!slot_ok(peer_slot)) {
        return CMT_REJECT;
    }
    p = &memR->peers[peer_slot];
    if (p->present) {
        /* No reference analogue: a Go peer is a distinct object and the
         * switch adds each once. A slot re-added without removal is the
         * host's defect — CMT_FAULT (node-local). */
        return CMT_FAULT;
    }
    memset(p, 0, sizeof(*p));
    p->present          = true;
    p->is_persistent    = is_persistent;
    p->is_unconditional = is_unconditional;

    if (!memR->config->broadcast) {                                /* :92 */
        return CMT_OK;
    }
    /* :93-128 — the goroutine: choose the semaphore, acquire or wait,
     * then broadcastTxRoutine. */
    p->semaphore = choose_semaphore(memR, p);                      /* :94-102 */
    if (p->semaphore == CMT_MEMR_SEM_NONE ||
        semaphore_try_acquire(memR, p->semaphore)) {               /* :104, :111 */
        routine_start(memR, peer_slot, p);                         /* :127 */
    } else {
        p->state = CMT_MEMR_ROUTINE_WAITING;                       /* :105-121 */
    }
    return CMT_OK;
}

/* :133-136 — RemovePeer(peer, _) */
int cmt_memr_remove_peer(cmt_memr_t *memR, int peer_slot)
{
    cmt_memr_peer_t *p;
    int              rc;

    if (memR == NULL) {
        return CMT_FAULT;
    }
    if (!slot_ok(peer_slot)) {
        return CMT_REJECT;
    }
    rc = cmt_mem_ids_reclaim(&memR->ids, peer_slot);               /* :134 */
    if (rc != CMT_OK) {
        return rc;
    }
    p = &memR->peers[peer_slot];
    routine_end(memR, p);                                          /* :135 */
    p->present = false;
    return CMT_OK;
}

/* ══ receive (:140-177) ═══════════════════════════════════════════════ */

int cmt_memr_receive(cmt_memr_t *memR, int peer_slot,
                     const uint8_t *bytes, size_t len,
                     const uint8_t *peer_p2p_id, size_t peer_p2p_id_len)
{
    cmt_pb_mempool_message_t    msg;
    const cmt_pb_mempool_txs_t *txs;
    cmt_mem_tx_info_t           info;
    size_t                      k;

    if (memR == NULL || (bytes == NULL && len != 0)) {
        return CMT_FAULT;
    }
    if (memR->host == NULL || memR->host->stop_peer_for_error == NULL) {
        return CMT_FAULT;
    }
    if (!slot_ok(peer_slot)) {
        return CMT_REJECT;
    }

    /* The transport's RecvMessageCapacity (header), then p2p/peer.go
     * :407-412 (unmarshal) and :417-422 (Unwrap): a failure stops the
     * peer for error. */
    if (len > memR->recv_message_capacity) {
        QGP_LOG_ERROR(LOG_TAG, "mempool message of %zu bytes exceeds the"
                      " channel capacity %zu; stopping peer %d", len,
                      memR->recv_message_capacity, peer_slot);
        memR->host->stop_peer_for_error(memR->host->ctx, peer_slot);
        return CMT_REJECT;
    }
    memR->arena.used = 0;
    msg.txs.txs     = memR->rx_slots;      /* slots first: `_init` keeps them */
    msg.txs.txs_cap = memR->rx_slots_cap;
    cmt_pb_mempool_message_init(&msg);
    if (cmt_pb_mempool_message_unmarshal(bytes, len, &msg,
                                         &memR->arena) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "unmarshaling mempool message from peer %d"
                      " failed; stopping peer", peer_slot);        /* peer.go:411 */
        memR->host->stop_peer_for_error(memR->host->ctx, peer_slot);
        return CMT_REJECT;
    }
    if (cmt_pb_mempool_message_unwrap(&msg, &txs) != CMT_OK) {
        /* peer.go:420 "unwrapping message", and reactor.go:170-173's
         * default branch: the same host row either way. */
        QGP_LOG_ERROR(LOG_TAG, "unknown message type from peer %d;"
                      " stopping peer", peer_slot);                /* :171 */
        memR->host->stop_peer_for_error(memR->host->ctx, peer_slot); /* :172 */
        return CMT_REJECT;
    }

    /* :141 debug log; :143 — the Txs branch. */
    if (txs->txs_len == 0) {                                       /* :145 */
        QGP_LOG_ERROR(LOG_TAG, "received empty txs from peer %d",
                      peer_slot);                                  /* :146 */
        return CMT_OK;                                             /* :147 */
    }
    info.sender_id         = cmt_mem_ids_get_for_peer(&memR->ids, peer_slot); /* :149 */
    info.sender_p2p_id     = peer_p2p_id;                          /* :150-152 */
    info.sender_p2p_id_len = (peer_p2p_id == NULL) ? 0 : peer_p2p_id_len;

    for (k = 0; k < txs->txs_len; k++) {                           /* :155 */
        cmt_mem_error_t err;
        int             rc;

        rc = cmt_mem_check_tx(memR->mempool, txs->txs[k].data,
                              txs->txs[k].len, &info, NULL, &err); /* :157 */
        if (rc == CMT_FAULT) {
            return CMT_FAULT;
        }
        if (rc == CMT_REJECT) {                                    /* :158 */
            switch (err.kind) {
            case CMT_MEM_ERR_TX_IN_CACHE:                          /* :160 */
                QGP_LOG_DEBUG(LOG_TAG, "Tx already exists in cache (len %zu)",
                              txs->txs[k].len);                    /* :161 */
                break;
            case CMT_MEM_ERR_MEMPOOL_IS_FULL:                      /* :162 */
                QGP_LOG_DEBUG(LOG_TAG, "mempool is full: number of txs %lld"
                              " (max: %lld), total txs bytes %lld (max:"
                              " %lld)", (long long)err.num_txs,
                              (long long)err.max_txs,
                              (long long)err.txs_bytes,
                              (long long)err.max_txs_bytes);       /* :164 */
                break;
            default:                                               /* :165 */
                QGP_LOG_INFO(LOG_TAG, "Could not check tx (len %zu, err"
                             " kind %d)", txs->txs[k].len,
                             (int)err.kind);                       /* :166 */
                break;
            }
        }
    }
    /* :176 — "broadcasting happens from go routines per peer" */
    return CMT_OK;
}

/* ══ broadcastTxRoutine (:185-259) as a tick ══════════════════════════ */

/* One peer's pass. `now_ns` is the clock read once per tick. Returns
 * CMT_OK; CMT_FAULT on a NULL host row. */
static int routine_pass(cmt_memr_t *memR, int slot, cmt_memr_peer_t *p,
                        int64_t now_ns, int64_t *earliest, bool *has_earliest)
{
    const cmt_memr_host_t *host = memR->host;

    for (;;) {                                                     /* :189 */
        bool                known;
        int64_t             peer_h;
        const cmt_mem_tx_t *mem_tx;

        /* :190-193 — reactor or peer stopped: the routine returns. */
        if (!memR->running || !p->present) {
            routine_end(memR, p);
            return CMT_OK;
        }

        /* Parked in the select of :249-257: resume there. Ready →
         * advance (:252) and go round to :189; not ready → still
         * parked, the pass ends. The element the routine sits on has
         * already been sent (or skipped) and is not looked at again. */
        if (p->waiting_next) {
            if (!cmt_clist_elem_next_wait_ready(p->next)) {        /* :250 */
                return CMT_OK;
            }
            p->waiting_next = false;
            peer_set_next(p, cmt_clist_elem_next(p->next));        /* :252 */
            continue;
        }

        /* R3-M-1 — a sleep still in force ends the pass. */
        if (p->sleeping) {
            if (now_ns < p->not_before_ns) {
                if (!*has_earliest || p->not_before_ns < *earliest) {
                    *earliest     = p->not_before_ns;
                    *has_earliest = true;
                }
                return CMT_OK;
            }
            p->sleeping = false;
        }

        /* :195-209 — no cursor: wait for a tx, start from the front. */
        if (p->next == NULL) {
            cmt_clist_elem_t *front = cmt_mem_txs_front(memR->mempool); /* :201 */

            if (front == NULL) {
                return CMT_OK;   /* :200 — TxsWaitChan: next tick re-reads */
            }
            peer_set_next(p, front);
        }

        /* :211-221 — the peer must have a state. */
        known  = false;
        peer_h = host->peer_height(host->ctx, slot, &known);       /* :212 */
        if (!known) {                                              /* :213 */
            p->sleeping      = true;                               /* :219 */
            p->not_before_ns = now_ns + CMT_MEMR_PEER_CATCHUP_SLEEP_NS;
            continue;                                              /* :220 */
        }

        /* :223-233 — a peer more than one block behind waits. */
        mem_tx = (const cmt_mem_tx_t *)cmt_clist_elem_value(p->next); /* :229 */
        if (mem_tx == NULL) {
            return CMT_FAULT;
        }
        if (peer_h < cmt_mem_tx_height(mem_tx) - 1) {              /* :230 */
            p->sleeping      = true;                               /* :231 */
            p->not_before_ns = now_ns + CMT_MEMR_PEER_CATCHUP_SLEEP_NS;
            continue;                                              /* :232 */
        }

        /* :235-247 — one tx per message; not back to its sender. */
        if (!cmt_mem_tx_is_sender(mem_tx, p->peer_id)) {           /* :238 */
            cmt_pb_bytes_t           one;
            cmt_pb_mempool_message_t env;
            size_t                   n = 0;
            bool                     success = false;

            one.data = mem_tx->tx;
            one.len  = mem_tx->tx_len;
            env.txs.txs     = &one;        /* slots first: `_init` keeps them */
            env.txs.txs_cap = 1;
            cmt_pb_mempool_message_init(&env);
            env.sum         = CMT_PB_MEMPOOL_MSG_TXS;               /* :239-242, peer.go:277-279 Wrap */
            env.txs.txs_len = 1;
            if (cmt_pb_mempool_message_marshal(&env, memR->tx_buf,
                                               memR->tx_buf_cap,
                                               &n) == CMT_OK) {    /* peer.go:280 */
                success = host->send(host->ctx, slot,
                                     (uint8_t)CMT_MEM_CHANNEL,
                                     memR->tx_buf, n);             /* :239, peer.go:285 */
            } else {
                QGP_LOG_ERROR(LOG_TAG, "marshaling message to send");  /* peer.go:282 */
            }
            if (!success) {                                        /* :243 */
                p->sleeping      = true;                           /* :244 */
                p->not_before_ns = now_ns + CMT_MEMR_PEER_CATCHUP_SLEEP_NS;
                continue;                                          /* :245 */
            }
        }

        /* :249-257 — wait for the next element: park in the select when
         * it is not there yet; otherwise advance and go round. */
        if (!cmt_clist_elem_next_wait_ready(p->next)) {            /* :250 */
            p->waiting_next = true;
            return CMT_OK;   /* the pass ends; next tick resumes here */
        }
        peer_set_next(p, cmt_clist_elem_next(p->next));            /* :252 */
    }
}

int cmt_memr_tick(cmt_memr_t *memR, int64_t *out_next_deadline_ns,
                  bool *out_has_deadline)
{
    cmt_time_t t;
    int64_t    now_ns;
    int64_t    earliest     = 0;
    bool       has_earliest = false;
    size_t     i;

    if (out_has_deadline != NULL) {
        *out_has_deadline = false;
    }
    if (out_next_deadline_ns != NULL) {
        *out_next_deadline_ns = 0;
    }
    if (memR == NULL || memR->host == NULL) {
        return CMT_FAULT;
    }
    if (memR->host->send == NULL || memR->host->peer_height == NULL ||
        memR->host->now == NULL) {
        return CMT_FAULT;
    }
    if (memR->host->now(memR->host->ctx, &t) != CMT_OK) {
        return CMT_FAULT;
    }
    now_ns = cmt_time_unix_nano(t);

    for (i = 0; i < CMT_MEM_MAX_PEERS; i++) {
        cmt_memr_peer_t *p = &memR->peers[i];
        int              rc;

        if (!p->present) {
            continue;
        }
        /* :104-121 — a routine blocked on the semaphore tries again. */
        if (p->state == CMT_MEMR_ROUTINE_WAITING) {
            if (!memR->running) {                                  /* :105 peer.IsRunning, and the reactor's quit */
                routine_end(memR, p);
                continue;
            }
            if (!semaphore_try_acquire(memR, p->semaphore)) {      /* :111 */
                continue;                                          /* :114-116 */
            }
            routine_start(memR, (int)i, p);                        /* :120, :127 */
        }
        if (p->state != CMT_MEMR_ROUTINE_RUNNING) {
            continue;
        }
        rc = routine_pass(memR, (int)i, p, now_ns, &earliest, &has_earliest);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    if (out_has_deadline != NULL) {
        *out_has_deadline = has_earliest;
    }
    if (out_next_deadline_ns != NULL && has_earliest) {
        *out_next_deadline_ns = earliest;
    }
    return CMT_OK;
}

cmt_memr_routine_state_t cmt_memr_peer_routine_state(const cmt_memr_t *memR,
                                                     int peer_slot)
{
    if (memR == NULL || !slot_ok(peer_slot)) {
        return CMT_MEMR_ROUTINE_NONE;
    }
    return memR->peers[peer_slot].state;
}

const cmt_clist_elem_t *cmt_memr_peer_cursor(const cmt_memr_t *memR,
                                             int peer_slot)
{
    if (memR == NULL || !slot_ok(peer_slot)) {
        return NULL;
    }
    return memR->peers[peer_slot].next;
}
