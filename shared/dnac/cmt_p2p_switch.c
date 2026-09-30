/**
 * @file shared/dnac/cmt_p2p_switch.c
 * @brief cometbft @v0.38.26 `p2p/switch.go` in C — the Switch as one
 *        event-loop pass.
 *
 * Contract, the goroutine → loop mapping and the deviations:
 * cmt_p2p_switch.h. Functions in the reference's order; each names its Go
 * lines.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_switch.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_P2P_SWITCH"

static void stop_and_remove_peer(cmt_p2p_switch_t *sw, cmt_p2p_peer_t *p,
                                 int reason);
static int  add_peer(cmt_p2p_switch_t *sw, cmt_p2p_peer_t *p);
static void reconnect_to_peer(cmt_p2p_switch_t *sw,
                              const cmt_p2p_netaddr_t *addr);

/* ══ small helpers ════════════════════════════════════════════════════ */

static int64_t sw_now(const cmt_p2p_switch_t *sw)
{
    return sw->transport->host.now_ns(sw->transport->host.ctx);
}

/* Grow a dynamic array by one element. */
static void *grow(void *arr, int *cap, int n, size_t elem)
{
    if (n < *cap) {
        return arr;
    }
    {
        int ncap = *cap == 0 ? 8 : *cap * 2;
        void *na = realloc(arr, (size_t)ncap * elem);

        if (na == NULL) {
            return NULL;
        }
        *cap = ncap;
        return na;
    }
}

/* The peer leaves the switch's hands: it is freed at the end of the tick
 * (never inside one of its own callbacks). */
static void bury(cmt_p2p_switch_t *sw, cmt_p2p_peer_t *p)
{
    if (p == NULL || p->buried) {
        return;
    }
    p->buried = true;
    p->next_buried = sw->graveyard;
    sw->graveyard = p;
}

static void free_graveyard(cmt_p2p_switch_t *sw)
{
    while (sw->graveyard != NULL) {
        cmt_p2p_peer_t *p = sw->graveyard;

        sw->graveyard = p->next_buried;
        cmt_p2p_peer_free(p);
    }
}

/* switch.go:566-569 randomSleep — the delay, not the sleep. */
static int64_t random_sleep_ns(cmt_p2p_switch_t *sw, int64_t interval_ns)
{
    int64_t r = sw->host.rand_int63n(sw->host.ctx,
                                     CMT_P2P_DIAL_RANDOMIZER_INTERVAL_MS);

    if (r < 0 || r >= CMT_P2P_DIAL_RANDOMIZER_INTERVAL_MS) {
        r = 0;
    }
    return r * 1000LL * 1000LL + interval_ns;
}

/* ══ setup (switch.go:111-229) ════════════════════════════════════════ */

void cmt_p2p_switch_default_config(cmt_p2p_switch_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cfg->max_num_inbound_peers = CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS;
    cfg->max_num_outbound_peers = CMT_P2P_DEFAULT_MAX_NUM_OUTBOUND_PEERS;
    cfg->allow_duplicate_ip = false;
}

/* switch.go:112-145 */
int cmt_p2p_switch_init(cmt_p2p_switch_t *sw, const cmt_p2p_switch_config_t *cfg,
                        cmt_p2p_transport_t *transport,
                        const cmt_p2p_switch_host_t *host)
{
    if (sw == NULL || cfg == NULL || transport == NULL || host == NULL ||
        host->rand_int63n == NULL || transport->host.now_ns == NULL) {
        return CMT_FAULT;
    }
    memset(sw, 0, sizeof(*sw));
    sw->cfg = *cfg;
    sw->host = *host;
    sw->transport = transport;
    memset(sw->reactor_by_ch, -1, sizeof(sw->reactor_by_ch));
    cmt_p2p_peer_set_init(&sw->peers);
    return CMT_OK;
}

void cmt_p2p_switch_free(cmt_p2p_switch_t *sw)
{
    if (sw == NULL) {
        return;
    }
    if (sw->started && !sw->stopped) {
        cmt_p2p_switch_stop(sw);
    }
    while (sw->peers.n > 0) {             /* never started: nothing to stop */
        cmt_p2p_peer_t *p = sw->peers.list[sw->peers.n - 1];

        cmt_p2p_transport_cleanup(sw->transport, p);
        cmt_p2p_peer_stop(p);
        (void)cmt_p2p_peer_set_remove(&sw->peers, p);
        bury(sw, p);
    }
    free_graveyard(sw);
    cmt_p2p_peer_set_free(&sw->peers);
    free(sw->dialing);
    free(sw->reconnecting);
    free(sw->async_dials);
    free(sw->persistent);
    free(sw->unconditional);
    free(sw->private_ids);
    memset(sw, 0, sizeof(*sw));
}

/* switch.go:167-181 AddReactor */
int cmt_p2p_switch_add_reactor(cmt_p2p_switch_t *sw,
                               const cmt_p2p_reactor_t *reactor)
{
    const cmt_p2p_ch_desc_t *d;
    int n = 0, i, idx;

    if (sw == NULL || reactor == NULL || reactor->get_channels == NULL ||
        reactor->add_peer == NULL || reactor->remove_peer == NULL ||
        reactor->receive == NULL || sw->n_reactors >= CMT_P2P_SWITCH_MAX_REACTORS) {
        return CMT_FAULT;
    }
    d = reactor->get_channels(reactor->ctx, &n);
    if (n < 0 || (n > 0 && d == NULL)) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {                              /* :170-173 */
        int j;

        if (sw->reactor_by_ch[d[i].id] >= 0) {
            QGP_LOG_ERROR(LOG_TAG, "Channel %02X has multiple reactors", d[i].id);
            return CMT_FAULT;
        }
        for (j = 0; j < i; j++) {
            if (d[j].id == d[i].id) {
                return CMT_FAULT;
            }
        }
    }
    idx = sw->n_reactors++;
    sw->reactors[idx] = *reactor;
    for (i = 0; i < n; i++) {
        sw->ch_descs[sw->n_ch_descs++] = d[i];              /* :174 */
        sw->reactor_by_ch[d[i].id] = (int8_t)idx;           /* :175 */
    }
    return CMT_OK;                                          /* :178-180 */
}

/* switch.go:185-199 RemoveReactor */
void cmt_p2p_switch_remove_reactor(cmt_p2p_switch_t *sw, const char *name)
{
    int idx, i, c;

    if (sw == NULL || name == NULL) {
        return;
    }
    for (idx = 0; idx < sw->n_reactors; idx++) {
        if (sw->reactors[idx].name != NULL &&
            strcmp(sw->reactors[idx].name, name) == 0) {
            break;
        }
    }
    if (idx == sw->n_reactors) {
        return;
    }
    for (i = 0; i < sw->n_ch_descs;) {                     /* :186-196 */
        if (sw->reactor_by_ch[sw->ch_descs[i].id] == idx) {
            sw->reactor_by_ch[sw->ch_descs[i].id] = -1;
            memmove(&sw->ch_descs[i], &sw->ch_descs[i + 1],
                    (size_t)(sw->n_ch_descs - i - 1) * sizeof(sw->ch_descs[0]));
            sw->n_ch_descs--;
        } else {
            i++;
        }
    }
    memmove(&sw->reactors[idx], &sw->reactors[idx + 1],
            (size_t)(sw->n_reactors - idx - 1) * sizeof(sw->reactors[0]));
    sw->n_reactors--;
    for (c = 0; c < 256; c++) {                            /* re-index */
        if (sw->reactor_by_ch[c] > idx) {
            sw->reactor_by_ch[c]--;
        }
    }
}

void cmt_p2p_switch_set_addr_book(cmt_p2p_switch_t *sw,
                                  const cmt_p2p_addr_book_t *book)
{
    if (sw != NULL) {
        sw->addr_book = book;
    }
}

const cmt_p2p_ch_desc_t *cmt_p2p_switch_ch_descs(const cmt_p2p_switch_t *sw,
                                                 int *n)
{
    if (n != NULL) {
        *n = sw != NULL ? sw->n_ch_descs : 0;
    }
    return sw != NULL ? sw->ch_descs : NULL;
}

/* ══ service (switch.go:235-264) ══════════════════════════════════════ */

int cmt_p2p_switch_start(cmt_p2p_switch_t *sw)
{
    int i;

    if (sw == NULL) {
        return CMT_FAULT;
    }
    if (sw->started || sw->stopped) {
        return CMT_REJECT;
    }
    for (i = 0; i < sw->n_reactors; i++) {                 /* :237-242 */
        if (sw->reactors[i].start != NULL &&
            sw->reactors[i].start(sw->reactors[i].ctx) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "failed to start reactor %s",
                          sw->reactors[i].name != NULL ? sw->reactors[i].name : "?");
            return CMT_REJECT;
        }
    }
    sw->started = true;                                    /* :245 acceptRoutine */
    return CMT_OK;
}

void cmt_p2p_switch_stop(cmt_p2p_switch_t *sw)
{
    int i;

    if (sw == NULL || !sw->started || sw->stopped) {
        return;
    }
    sw->stopped = true;
    while (sw->peers.n > 0) {                              /* :253-255 */
        stop_and_remove_peer(sw, sw->peers.list[0], 0);
    }
    for (i = 0; i < sw->n_reactors; i++) {                 /* :259-263 */
        if (sw->reactors[i].stop != NULL) {
            sw->reactors[i].stop(sw->reactors[i].ctx);
        }
    }
}

bool cmt_p2p_switch_is_running(const cmt_p2p_switch_t *sw)
{
    return sw != NULL && sw->started && !sw->stopped;
}

/* ══ peers (switch.go:269-461) ════════════════════════════════════════ */

/* switch.go:275-297 Broadcast (R-P2P-30) */
int cmt_p2p_switch_broadcast(cmt_p2p_switch_t *sw, uint8_t ch_id,
                             const uint8_t *msg, size_t len)
{
    int i, ok = 0;

    if (sw == NULL) {
        return 0;
    }
    for (i = 0; i < sw->peers.n; i++) {
        if (cmt_p2p_peer_send(sw->peers.list[i], ch_id, msg, len)) {
            ok++;
        }
    }
    return ok;
}

/* switch.go:301-316 NumPeers */
void cmt_p2p_switch_num_peers(cmt_p2p_switch_t *sw, int *outbound,
                              int *inbound, int *dialing)
{
    int i, o = 0, in = 0;

    if (sw != NULL) {
        for (i = 0; i < sw->peers.n; i++) {
            cmt_p2p_peer_t *p = sw->peers.list[i];

            if (cmt_p2p_switch_is_peer_unconditional(sw, p->id)) {
                continue;
            }
            if (p->outbound) {
                o++;
            } else {
                in++;
            }
        }
    }
    if (outbound != NULL) {
        *outbound = o;
    }
    if (inbound != NULL) {
        *inbound = in;
    }
    if (dialing != NULL) {
        *dialing = sw != NULL ? sw->n_dialing : 0;          /* :314 */
    }
}

/* switch.go:318-321 (+ R-P2P-7) */
bool cmt_p2p_switch_is_peer_unconditional(const cmt_p2p_switch_t *sw,
                                          const char *id)
{
    int i;

    if (sw == NULL || id == NULL) {
        return false;
    }
    for (i = 0; i < sw->n_unconditional; i++) {
        if (strcmp(sw->unconditional[i].id, id) == 0) {
            return true;
        }
    }
    return sw->host.is_bonded != NULL && sw->host.is_bonded(sw->host.ctx, id);
}

int cmt_p2p_switch_max_num_outbound_peers(const cmt_p2p_switch_t *sw)
{
    return sw != NULL ? sw->cfg.max_num_outbound_peers : 0;
}

const cmt_p2p_peer_set_t *cmt_p2p_switch_peers(const cmt_p2p_switch_t *sw)
{
    return sw != NULL ? &sw->peers : NULL;
}

/* switch.go:336-359 StopPeerForError */
void cmt_p2p_switch_stop_peer_for_error(cmt_p2p_switch_t *sw,
                                        cmt_p2p_peer_t *p, int reason)
{
    cmt_p2p_netaddr_t addr;

    if (sw == NULL || p == NULL || !cmt_p2p_peer_is_running(p)) {
        return;                                            /* :337-339 */
    }
    QGP_LOG_WARN(LOG_TAG, "Stopping peer %s for error %d", p->id, reason);
    stop_and_remove_peer(sw, p, reason != 0 ? reason : -1);  /* :342 */
    if (p->persistent) {                                   /* :344-358 */
        if (p->outbound) {
            addr = p->socket_addr;
        } else if (cmt_p2p_node_info_net_address(p->node_info, &addr) !=
                   CMT_P2P_ERR_NONE) {
            QGP_LOG_ERROR(LOG_TAG, "Wanted to reconnect to inbound peer %s, but "
                          "self-reported address is wrong", p->id);
            return;
        }
        reconnect_to_peer(sw, &addr);
    }
}

/* switch.go:363-366 StopPeerGracefully */
void cmt_p2p_switch_stop_peer_gracefully(cmt_p2p_switch_t *sw,
                                         cmt_p2p_peer_t *p)
{
    if (sw == NULL || p == NULL) {
        return;
    }
    QGP_LOG_INFO(LOG_TAG, "Stopping peer %s gracefully", p->id);
    stop_and_remove_peer(sw, p, 0);
}

/* switch.go:368-389 stopAndRemovePeer */
static void stop_and_remove_peer(cmt_p2p_switch_t *sw, cmt_p2p_peer_t *p,
                                 int reason)
{
    int i;

    cmt_p2p_transport_cleanup(sw->transport, p);           /* :369 */
    cmt_p2p_peer_stop(p);                                  /* :370-372 */
    for (i = 0; i < sw->n_reactors; i++) {                 /* :374-376 */
        sw->reactors[i].remove_peer(sw->reactors[i].ctx, p, reason);
    }
    if (!cmt_p2p_peer_set_remove(&sw->peers, p)) {         /* :382-388 */
        QGP_LOG_DEBUG(LOG_TAG, "error on peer removal %s", p->id);
    }
    bury(sw, p);
}

/* ══ reconnectToPeer (switch.go:400-448) as a timed record ════════════ */

static int reconnect_index(const cmt_p2p_switch_t *sw, const char *id)
{
    int i;

    for (i = 0; i < sw->n_reconnecting; i++) {
        if (strcmp(sw->reconnecting[i].addr.id, id) == 0) {
            return i;
        }
    }
    return -1;
}

static void reconnect_delete(cmt_p2p_switch_t *sw, int i)
{
    memmove(&sw->reconnecting[i], &sw->reconnecting[i + 1],
            (size_t)(sw->n_reconnecting - i - 1) * sizeof(sw->reconnecting[0]));
    sw->n_reconnecting--;
}

/* :400-408 — `go reconnectToPeer(addr)`; the first dial is immediate. */
static void reconnect_to_peer(cmt_p2p_switch_t *sw,
                              const cmt_p2p_netaddr_t *addr)
{
    cmt_p2p_sw_reconnect_t *r;
    void *na;

    if (reconnect_index(sw, addr->id) >= 0) {
        return;                                            /* :401-403 */
    }
    na = grow(sw->reconnecting, &sw->cap_reconnecting, sw->n_reconnecting,
              sizeof(*sw->reconnecting));
    if (na == NULL) {
        return;
    }
    sw->reconnecting = (cmt_p2p_sw_reconnect_t *)na;
    r = &sw->reconnecting[sw->n_reconnecting++];           /* :404 */
    memset(r, 0, sizeof(*r));
    r->addr = *addr;
    r->phase = 0;
    r->i = 0;
    r->start = sw_now(sw);                                 /* :407 */
    r->next_at = r->start;
    QGP_LOG_INFO(LOG_TAG, "Reconnecting to peer %s", addr->id);
}

/* The outcome of one reconnect dial (:415-425, :439-445). */
static void reconnect_result(cmt_p2p_switch_t *sw, const char *id, int err)
{
    int i = reconnect_index(sw, id);
    cmt_p2p_sw_reconnect_t *r;

    if (i < 0 || !sw->reconnecting[i].awaiting) {
        return;
    }
    r = &sw->reconnecting[i];
    r->awaiting = false;
    if (err == CMT_P2P_ERR_NONE ||
        err == CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING) {
        reconnect_delete(sw, i);                           /* :416-420, :440-444 */
        return;
    }
    QGP_LOG_INFO(LOG_TAG, "Error reconnecting to peer %s (%s). Trying again",
                 id, cmt_p2p_err_str(err));
    if (r->phase == 0) {
        r->i++;
        r->next_at = sw_now(sw) + random_sleep_ns(sw, CMT_P2P_RECONNECT_INTERVAL_NS); /* :424 */
    } else {
        r->i++;
        if (r->i > CMT_P2P_RECONNECT_BACKOFF_ATTEMPTS) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to reconnect to peer %s. Giving up", id);
            reconnect_delete(sw, i);                       /* :447 */
            return;
        }
        if (!cmt_p2p_switch_is_running(sw)) {              /* :431-433, before the sleep */
            reconnect_delete(sw, i);
            return;
        }
        {
            int64_t secs = 1;
            int k;

            for (k = 0; k < r->i; k++) {                   /* :436 math.Pow(3, i) */
                secs *= CMT_P2P_RECONNECT_BACKOFF_BASE_SECONDS;
            }
            r->next_at = sw_now(sw) + random_sleep_ns(sw, secs * CMT_P2P_NS_PER_SEC);
        }
    }
}

static void reconnect_timers(cmt_p2p_switch_t *sw)
{
    int64_t now = sw_now(sw);
    int i;

    for (i = 0; i < sw->n_reconnecting;) {
        cmt_p2p_sw_reconnect_t *r = &sw->reconnecting[i];
        char id[CMT_P2P_ID_CAP];
        cmt_p2p_netaddr_t addr;
        int err;

        if (r->awaiting || now < r->next_at) {
            i++;
            continue;
        }
        /* :411-413 — the fixed-interval loop checks before each dial; the
         * transition below is backoff attempt 1's check (:431-433), made
         * BEFORE its sleep. A backoff record firing here has already
         * passed its check before the sleep (reconnect_result), so it
         * dials without another one, as :436-439 does. */
        if (r->phase == 0 && !cmt_p2p_switch_is_running(sw)) {
            reconnect_delete(sw, i);
            continue;
        }
        if (r->phase == 0 && r->i >= CMT_P2P_RECONNECT_ATTEMPTS) {
            /* :428-430 into the backoff loop; its first sleep (:436-437)
             * comes before its first dial. */
            int64_t secs = CMT_P2P_RECONNECT_BACKOFF_BASE_SECONDS;

            QGP_LOG_ERROR(LOG_TAG, "Failed to reconnect to peer %s. Beginning "
                          "exponential backoff", r->addr.id);
            r->phase = 1;
            r->i = 1;
            r->next_at = now + random_sleep_ns(sw, secs * CMT_P2P_NS_PER_SEC);
            i++;
            continue;
        }
        memcpy(id, r->addr.id, sizeof(id));
        addr = r->addr;
        r->awaiting = true;
        err = cmt_p2p_switch_dial_peer_with_address(sw, &addr);  /* :415, :439 */
        if (err != CMT_P2P_ERR_NONE) {
            reconnect_result(sw, id, err);
        }
        /* the record may have moved or gone: restart from its index */
        {
            int j = reconnect_index(sw, id);

            i = (j >= 0) ? j + 1 : i;
        }
    }
}

/* switch.go:457-461 */
void cmt_p2p_switch_mark_peer_as_good(cmt_p2p_switch_t *sw,
                                      const cmt_p2p_peer_t *p)
{
    if (sw == NULL || p == NULL) {
        return;
    }
    if (sw->addr_book != NULL && sw->addr_book->mark_good != NULL) {
        sw->addr_book->mark_good(sw->addr_book->ctx, p->id);
    }
}

/* ══ dialing (switch.go:475-634) ══════════════════════════════════════ */

/* NewNetAddressStrings (netaddress.go:116-128) + the "first error that is
 * not ErrNetAddressLookup" rule (switch.go:482-492, :585-595). */
static int parse_addrs(const char *const *strs, int n, cmt_p2p_netaddr_t **out,
                       int *n_out)
{
    cmt_p2p_netaddr_t *arr;
    int i, k = 0, first_err = CMT_P2P_ERR_NONE;

    *out = NULL;
    *n_out = 0;
    if (n <= 0) {
        return CMT_P2P_ERR_NONE;
    }
    arr = (cmt_p2p_netaddr_t *)calloc((size_t)n, sizeof(*arr));
    if (arr == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {
        int rc;

        if (strs[i] == NULL) {
            continue;
        }
        rc = cmt_p2p_netaddr_new_string(strs[i], strlen(strs[i]), &arr[k]);
        if (rc == CMT_P2P_ERR_NONE) {
            k++;
            continue;
        }
        QGP_LOG_ERROR(LOG_TAG, "Error in peer's address %s: %s", strs[i],
                      cmt_p2p_err_str(rc));
        if (rc != CMT_P2P_ERR_NETADDR_LOOKUP && first_err == CMT_P2P_ERR_NONE) {
            first_err = rc;
        }
    }
    if (first_err != CMT_P2P_ERR_NONE) {
        free(arr);
        return first_err;
    }
    *out = arr;
    *n_out = k;
    return CMT_P2P_ERR_NONE;
}

/* switch.go:480-495 DialPeersAsync + :497-548 dialPeersAsync */
int cmt_p2p_switch_dial_peers_async(cmt_p2p_switch_t *sw,
                                    const char *const *peers, int n)
{
    cmt_p2p_netaddr_t *addrs;
    const cmt_p2p_netaddr_t *our;
    int n_addrs, rc, i;
    int *perm;
    int64_t now;

    if (sw == NULL || (peers == NULL && n > 0)) {
        return CMT_FAULT;
    }
    rc = parse_addrs(peers, n, &addrs, &n_addrs);
    if (rc != CMT_P2P_ERR_NONE) {
        return rc;
    }
    if (n_addrs == 0) {
        free(addrs);
        return CMT_P2P_ERR_NONE;
    }
    our = cmt_p2p_transport_net_address(sw->transport);
    /* :504-521 the AddrBook */
    if (sw->addr_book != NULL) {
        for (i = 0; i < n_addrs; i++) {
            if (!cmt_p2p_netaddr_same(&addrs[i], our) &&
                sw->addr_book->add_address != NULL &&
                sw->addr_book->add_address(sw->addr_book->ctx, &addrs[i], our) != 0) {
                QGP_LOG_DEBUG(LOG_TAG, "Can't add peer's address to addrbook");
            }
        }
        if (sw->addr_book->save != NULL) {
            sw->addr_book->save(sw->addr_book->ctx);
        }
    }
    /* :524 perm := sw.rng.Perm(len(netAddrs)) — Go math/rand Perm
     * (rand.go:229-242) over the host's rand. */
    perm = (int *)calloc((size_t)n_addrs, sizeof(int));
    if (perm == NULL) {
        free(addrs);
        return CMT_FAULT;
    }
    for (i = 0; i < n_addrs; i++) {
        int j = (int)sw->host.rand_int63n(sw->host.ctx, (int64_t)i + 1);

        if (j < 0 || j > i) {
            j = i;
        }
        perm[i] = perm[j];
        perm[j] = i;
    }
    now = sw_now(sw);
    for (i = 0; i < n_addrs; i++) {                        /* :525-547 */
        const cmt_p2p_netaddr_t *a = &addrs[perm[i]];
        void *na;

        if (cmt_p2p_netaddr_same(a, our)) {                /* :530-533 */
            QGP_LOG_DEBUG(LOG_TAG, "Ignore attempt to connect to ourselves");
            continue;
        }
        na = grow(sw->async_dials, &sw->cap_async, sw->n_async,
                  sizeof(*sw->async_dials));
        if (na == NULL) {
            break;
        }
        sw->async_dials = (cmt_p2p_sw_async_dial_t *)na;
        sw->async_dials[sw->n_async].addr = *a;
        sw->async_dials[sw->n_async].at = now + random_sleep_ns(sw, 0);  /* :535 */
        sw->n_async++;
    }
    free(perm);
    free(addrs);
    return CMT_P2P_ERR_NONE;
}

static void async_dial_timers(cmt_p2p_switch_t *sw)
{
    int64_t now = sw_now(sw);
    int i;

    for (i = 0; i < sw->n_async;) {
        cmt_p2p_netaddr_t a;
        int err;

        if (now < sw->async_dials[i].at) {
            i++;
            continue;
        }
        a = sw->async_dials[i].addr;
        memmove(&sw->async_dials[i], &sw->async_dials[i + 1],
                (size_t)(sw->n_async - i - 1) * sizeof(sw->async_dials[0]));
        sw->n_async--;
        err = cmt_p2p_switch_dial_peer_with_address(sw, &a);   /* :537 */
        if (err != CMT_P2P_ERR_NONE) {
            QGP_LOG_DEBUG(LOG_TAG, "Error dialing peer %s: %s", a.id,
                          cmt_p2p_err_str(err));
        }
    }
}

static int dialing_index(const cmt_p2p_switch_t *sw, const char *id)
{
    int i;

    for (i = 0; i < sw->n_dialing; i++) {
        if (strcmp(sw->dialing[i].id, id) == 0) {
            return i;
        }
    }
    return -1;
}

static void dialing_delete(cmt_p2p_switch_t *sw, const char *id)
{
    int i = dialing_index(sw, id);

    if (i < 0) {
        return;
    }
    memmove(&sw->dialing[i], &sw->dialing[i + 1],
            (size_t)(sw->n_dialing - i - 1) * sizeof(sw->dialing[0]));
    sw->n_dialing--;
}

/* switch.go:752-781 — addOutboundPeerWithConfig after `transport.Dial`
 * returned; :560 `defer sw.dialing.Delete` runs here. */
static int dial_finish(cmt_p2p_switch_t *sw, const cmt_p2p_netaddr_t *addr,
                       cmt_p2p_conn_t *conn, int err);

/* The peer config every wrap uses (:638-646, :743-751). */
static void sw_on_peer_error(void *ctx, cmt_p2p_peer_t *p, int reason);
static void sw_on_receive(void *ctx, cmt_p2p_peer_t *p, uint8_t ch_id,
                          const uint8_t *msg, size_t len);
static bool sw_is_persistent(void *ctx, const cmt_p2p_netaddr_t *na);

static cmt_p2p_peer_config_t peer_config(cmt_p2p_switch_t *sw)
{
    cmt_p2p_peer_config_t pc;

    memset(&pc, 0, sizeof(pc));
    pc.ctx = sw;
    pc.ch_descs = sw->ch_descs;
    pc.n_ch_descs = sw->n_ch_descs;
    pc.on_peer_error = sw_on_peer_error;
    pc.on_receive = sw_on_receive;
    pc.is_persistent = sw_is_persistent;
    return pc;
}

/* switch.go:554-563 DialPeerWithAddress (started) */
int cmt_p2p_switch_dial_peer_with_address(cmt_p2p_switch_t *sw,
                                          const cmt_p2p_netaddr_t *addr)
{
    void *na;
    int rc;

    if (sw == NULL || addr == NULL) {
        return CMT_FAULT;
    }
    if (cmt_p2p_switch_is_dialing_or_existing_address(sw, addr)) {
        return CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING;  /* :555-557 */
    }
    na = grow(sw->dialing, &sw->cap_dialing, sw->n_dialing, sizeof(*sw->dialing));
    if (na == NULL) {
        return CMT_FAULT;
    }
    sw->dialing = (cmt_p2p_netaddr_t *)na;
    sw->dialing[sw->n_dialing++] = *addr;                  /* :559 */
    QGP_LOG_DEBUG(LOG_TAG, "Dialing peer %s", addr->id);
    rc = cmt_p2p_transport_dial(sw->transport, addr);      /* :743 */
    if (rc != CMT_P2P_ERR_NONE) {
        return dial_finish(sw, addr, NULL, rc);
    }
    return CMT_P2P_ERR_NONE;
}

static int dial_outcome(cmt_p2p_switch_t *sw, const cmt_p2p_netaddr_t *addr,
                        cmt_p2p_conn_t *conn, int err);

/* The reference's return value of DialPeerWithAddress, handed to the
 * dial observer (cmt_p2p_switch_set_dial_observer). */
static int dial_finish(cmt_p2p_switch_t *sw, const cmt_p2p_netaddr_t *addr,
                       cmt_p2p_conn_t *conn, int err)
{
    cmt_p2p_netaddr_t a = *addr;         /* `addr` may live in `dialing` */
    int rc = dial_outcome(sw, &a, conn, err);

    if (sw->dial_observer != NULL) {
        sw->dial_observer(sw->dial_observer_ctx, &a, rc);
    }
    return rc;
}

void cmt_p2p_switch_set_dial_observer(cmt_p2p_switch_t *sw,
    void (*fn)(void *ctx, const cmt_p2p_netaddr_t *addr, int err), void *ctx)
{
    if (sw != NULL) {
        sw->dial_observer = fn;
        sw->dial_observer_ctx = ctx;
    }
}

static int dial_outcome(cmt_p2p_switch_t *sw, const cmt_p2p_netaddr_t *addr,
                        cmt_p2p_conn_t *conn, int err)
{
    cmt_p2p_peer_config_t pc;
    cmt_p2p_peer_t *p;
    int rc;

    dialing_delete(sw, addr->id);                          /* :560 */
    if (conn == NULL) {                                    /* :752-771 */
        if (err == CMT_P2P_ERR_REJECTED_SELF) {
            if (sw->addr_book != NULL) {                   /* :757-758 */
                if (sw->addr_book->remove_address != NULL) {
                    sw->addr_book->remove_address(sw->addr_book->ctx, addr);
                }
                if (sw->addr_book->add_our_address != NULL) {
                    sw->addr_book->add_our_address(sw->addr_book->ctx, addr);
                }
            }
            return err;                                    /* :760 */
        }
        if (cmt_p2p_switch_is_peer_persistent(sw, addr)) { /* :766-768 */
            reconnect_to_peer(sw, addr);
        }
        return err;
    }
    pc = peer_config(sw);
    p = cmt_p2p_transport_wrap_peer(sw->transport, conn, &pc);
    if (p == NULL) {
        return CMT_FAULT;
    }
    rc = add_peer(sw, p);                                  /* :773 */
    if (rc != CMT_P2P_ERR_NONE) {
        cmt_p2p_transport_cleanup(sw->transport, p);       /* :774 */
        if (cmt_p2p_peer_is_running(p)) {
            cmt_p2p_peer_stop(p);                          /* :775-777 */
        }
        bury(sw, p);
        return rc;
    }
    return CMT_P2P_ERR_NONE;
}

/* switch.go:573-577 */
bool cmt_p2p_switch_is_dialing_or_existing_address(const cmt_p2p_switch_t *sw,
                                                   const cmt_p2p_netaddr_t *addr)
{
    if (sw == NULL || addr == NULL) {
        return false;
    }
    return dialing_index(sw, addr->id) >= 0 ||
           cmt_p2p_peer_set_has(&sw->peers, addr->id) ||
           (!sw->cfg.allow_duplicate_ip &&
            cmt_p2p_peer_set_has_ip(&sw->peers, &addr->ip));
}

/* switch.go:582-598 */
int cmt_p2p_switch_add_persistent_peers(cmt_p2p_switch_t *sw,
                                        const char *const *addrs, int n)
{
    cmt_p2p_netaddr_t *arr;
    int k, rc;

    if (sw == NULL || (addrs == NULL && n > 0)) {
        return CMT_FAULT;
    }
    rc = parse_addrs(addrs, n, &arr, &k);
    if (rc != CMT_P2P_ERR_NONE) {
        return rc;
    }
    free(sw->persistent);
    sw->persistent = arr;                                  /* :596 */
    sw->n_persistent = k;
    return CMT_P2P_ERR_NONE;
}

static int add_ids(cmt_p2p_sw_id_t **list, int *n, const char *const *ids,
                   int count, bool keep_prefix)
{
    int i;

    for (i = 0; i < count; i++) {
        cmt_p2p_sw_id_t *nl;
        size_t len;

        if (ids[i] == NULL) {
            return CMT_P2P_ERR_NETADDR_INVALID;
        }
        len = strlen(ids[i]);
        if (cmt_p2p_validate_id(ids[i], len) != CMT_P2P_ERR_NONE) {
            return CMT_P2P_ERR_NETADDR_INVALID;            /* :603-606 / :615-618 */
        }
        if (!keep_prefix) {
            continue;
        }
        nl = (cmt_p2p_sw_id_t *)realloc(*list, (size_t)(*n + 1) * sizeof(**list));
        if (nl == NULL) {
            return CMT_FAULT;
        }
        *list = nl;
        memcpy((*list)[*n].id, ids[i], len + 1);
        (*n)++;
    }
    return CMT_P2P_ERR_NONE;
}

/* switch.go:600-610 — IDs before a bad one stay added (:602-608). */
int cmt_p2p_switch_add_unconditional_peer_ids(cmt_p2p_switch_t *sw,
                                              const char *const *ids, int n)
{
    if (sw == NULL || (ids == NULL && n > 0)) {
        return CMT_FAULT;
    }
    return add_ids(&sw->unconditional, &sw->n_unconditional, ids, n, true);
}

/* switch.go:612-625 — all validated first, then handed over (:613-622). */
int cmt_p2p_switch_add_private_peer_ids(cmt_p2p_switch_t *sw,
                                        const char *const *ids, int n)
{
    int rc;

    if (sw == NULL || (ids == NULL && n > 0)) {
        return CMT_FAULT;
    }
    rc = add_ids(NULL, NULL, ids, n, false);
    if (rc != CMT_P2P_ERR_NONE) {
        return rc;
    }
    rc = add_ids(&sw->private_ids, &sw->n_private, ids, n, true);
    if (rc != CMT_P2P_ERR_NONE) {
        return rc;
    }
    if (sw->addr_book != NULL && sw->addr_book->add_private_ids != NULL) {
        sw->addr_book->add_private_ids(sw->addr_book->ctx, ids, n);   /* :622 */
    }
    return CMT_P2P_ERR_NONE;
}

bool cmt_p2p_switch_is_private_peer_id(const cmt_p2p_switch_t *sw,
                                       const char *id)
{
    int i;

    if (sw == NULL || id == NULL) {
        return false;
    }
    for (i = 0; i < sw->n_private; i++) {
        if (strcmp(sw->private_ids[i].id, id) == 0) {
            return true;
        }
    }
    return false;
}

/* switch.go:627-634 */
bool cmt_p2p_switch_is_peer_persistent(const cmt_p2p_switch_t *sw,
                                       const cmt_p2p_netaddr_t *na)
{
    int i;

    if (sw == NULL || na == NULL) {
        return false;
    }
    for (i = 0; i < sw->n_persistent; i++) {
        if (cmt_p2p_netaddr_equals(&sw->persistent[i], na)) {
            return true;
        }
    }
    return false;
}

bool cmt_p2p_switch_is_reconnecting(const cmt_p2p_switch_t *sw,
                                    const char *id)
{
    return sw != NULL && id != NULL && reconnect_index(sw, id) >= 0;
}

/* ══ the peer callbacks ═══════════════════════════════════════════════ */

static void sw_on_peer_error(void *ctx, cmt_p2p_peer_t *p, int reason)
{
    cmt_p2p_switch_stop_peer_for_error((cmt_p2p_switch_t *)ctx, p, reason);
}

/* peer.go:400-438 — reactorsByCh[chID]; nil → panic → onPeerError. */
static void sw_on_receive(void *ctx, cmt_p2p_peer_t *p, uint8_t ch_id,
                          const uint8_t *msg, size_t len)
{
    cmt_p2p_switch_t *sw = (cmt_p2p_switch_t *)ctx;
    int idx = sw->reactor_by_ch[ch_id];

    if (idx < 0) {
        cmt_p2p_switch_stop_peer_for_error(sw, p, CMT_P2P_PEER_ERR_UNKNOWN_CHANNEL);
        return;
    }
    sw->reactors[idx].receive(sw->reactors[idx].ctx, p, ch_id, msg, len);
}

static bool sw_is_persistent(void *ctx, const cmt_p2p_netaddr_t *na)
{
    return cmt_p2p_switch_is_peer_persistent((const cmt_p2p_switch_t *)ctx, na);
}

/* ══ acceptRoutine / addPeer (switch.go:636-866) ══════════════════════ */

/* switch.go:636-724 — one accepted connection (or accept error). */
static void accept_one(cmt_p2p_switch_t *sw, const cmt_p2p_transport_result_t *r)
{
    cmt_p2p_peer_config_t pc;
    cmt_p2p_peer_t *p;
    int rc;

    if (r->conn == NULL) {                                 /* :647-692 */
        if (r->err == CMT_P2P_ERR_REJECTED_SELF && sw->addr_book != NULL) {
            if (sw->addr_book->remove_address != NULL) {   /* :653-655 */
                sw->addr_book->remove_address(sw->addr_book->ctx, &r->addr);
            }
            if (sw->addr_book->add_our_address != NULL) {
                sw->addr_book->add_our_address(sw->addr_book->ctx, &r->addr);
            }
        }
        QGP_LOG_INFO(LOG_TAG, "Inbound Peer rejected: %s (numPeers %d)",
                     cmt_p2p_err_str(r->err), sw->peers.n);
        return;
    }
    pc = peer_config(sw);
    p = cmt_p2p_transport_wrap_peer(sw->transport, r->conn, &pc);
    if (p == NULL) {
        return;
    }
    if (!cmt_p2p_switch_is_peer_unconditional(sw, p->id)) {   /* :694-710 */
        int in = 0;

        cmt_p2p_switch_num_peers(sw, NULL, &in, NULL);
        if (in >= sw->cfg.max_num_inbound_peers) {
            QGP_LOG_INFO(LOG_TAG, "Ignoring inbound connection: already have "
                         "enough inbound peers (have %d, max %d)", in,
                         sw->cfg.max_num_inbound_peers);
            cmt_p2p_transport_cleanup(sw->transport, p);   /* :705 */
            bury(sw, p);
            return;
        }
    }
    rc = add_peer(sw, p);                                  /* :712 */
    if (rc != CMT_P2P_ERR_NONE) {
        cmt_p2p_transport_cleanup(sw->transport, p);       /* :713 */
        if (cmt_p2p_peer_is_running(p)) {
            cmt_p2p_peer_stop(p);                          /* :714-716 */
        }
        bury(sw, p);
        QGP_LOG_INFO(LOG_TAG, "Ignoring inbound connection: error while adding "
                     "peer %s: %s", p->id, cmt_p2p_err_str(rc));
    }
}

/* switch.go:784-810 filterPeer (+ R-P2P-23). */
static int filter_peer(cmt_p2p_switch_t *sw, cmt_p2p_peer_t *p)
{
    cmt_p2p_peer_t *q = cmt_p2p_peer_set_get(&sw->peers, p->id);
    const char *our = cmt_p2p_transport_id(sw->transport);

    if (q == NULL) {
        return CMT_P2P_ERR_NONE;
    }
    if (q->outbound != p->outbound) {
        const char *dialer_p = p->outbound ? our : p->id;
        const char *dialer_q = q->outbound ? our : q->id;

        if (strcmp(dialer_p, dialer_q) < 0) {
            QGP_LOG_INFO(LOG_TAG, "cross-dial with %s: keeping the connection "
                         "dialed by %s", p->id, dialer_p);
            cmt_p2p_switch_stop_peer_gracefully(sw, q);
            return CMT_P2P_ERR_NONE;
        }
    }
    return CMT_P2P_ERR_REJECTED_DUPLICATE;                 /* :786-788 */
}

/* switch.go:814-866 addPeer */
static int add_peer(cmt_p2p_switch_t *sw, cmt_p2p_peer_t *p)
{
    int i, rc;

    rc = filter_peer(sw, p);                               /* :815-817 */
    if (rc != CMT_P2P_ERR_NONE) {
        return rc;
    }
    if (!cmt_p2p_switch_is_running(sw)) {                  /* :823-827, R-P2P-29 */
        QGP_LOG_ERROR(LOG_TAG, "Won't start a peer - switch is not running");
        return CMT_P2P_ERR_NOT_RUNNING;
    }
    for (i = 0; i < sw->n_reactors; i++) {                 /* :830-832 */
        if (sw->reactors[i].init_peer != NULL) {
            sw->reactors[i].init_peer(sw->reactors[i].ctx, p);
        }
    }
    if (cmt_p2p_peer_start(p) != CMT_OK) {                 /* :837-842 */
        QGP_LOG_ERROR(LOG_TAG, "Error starting peer %s", p->id);
        return CMT_P2P_ERR_NOT_RUNNING;
    }
    rc = cmt_p2p_peer_set_add(&sw->peers, p);              /* :847-855 */
    if (rc != CMT_P2P_ERR_NONE) {
        return rc;
    }
    for (i = 0; i < sw->n_reactors; i++) {                 /* :859-861 */
        sw->reactors[i].add_peer(sw->reactors[i].ctx, p);
    }
    QGP_LOG_DEBUG(LOG_TAG, "Added peer %s", p->id);
    return CMT_P2P_ERR_NONE;
}

/* ══ the loop ═════════════════════════════════════════════════════════ */

void cmt_p2p_switch_tick(cmt_p2p_switch_t *sw)
{
    cmt_p2p_transport_result_t r;

    if (sw == NULL) {
        return;
    }
    cmt_p2p_transport_tick(sw->transport);
    while (cmt_p2p_transport_next_result(sw->transport, &r)) {
        if (r.outbound) {
            char id[CMT_P2P_ID_CAP];
            int err;

            memcpy(id, r.addr.id, sizeof(id));
            err = dial_finish(sw, &r.addr, r.conn, r.err);
            reconnect_result(sw, id, err);
        } else if (cmt_p2p_switch_is_running(sw)) {
            accept_one(sw, &r);
        } else if (r.conn != NULL) {
            cmt_p2p_transport_discard(sw->transport, r.conn);
        }
    }
    async_dial_timers(sw);
    reconnect_timers(sw);
    free_graveyard(sw);
}
