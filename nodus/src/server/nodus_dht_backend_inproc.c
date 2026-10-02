/**
 * Nodus — DHT backend, in-process implementation
 *
 * The DHT / storage half runs inside this process (the combined
 * nodus-server). Every operation calls the dht/nodus_dht.h function that
 * holds the code the server ran at that call site before the S4 seam
 * (decision 2026-10-01-nodus-component-split.md); the server reaches the
 * DHT through server/nodus_dht_backend.h only.
 *
 * @file nodus_dht_backend_inproc.c
 */

#include "server/nodus_dht_backend.h"

#include <stdlib.h>

typedef struct {
    nodus_dht_backend_t base;   /* first member: ops */
    nodus_dht_t         dht;
} inproc_backend_t;

static nodus_dht_t *inproc_dht(nodus_dht_backend_t *b) {
    return &((inproc_backend_t *)b)->dht;
}

/* The decoded message is what the DHT reads; the frame bytes are what an
 * IPC backend would carry. */
static void inproc_client_frame(nodus_dht_backend_t *b, int slot,
                                const nodus_key_t *client_fp,
                                const nodus_pubkey_t *client_pk,
                                const uint8_t *payload, size_t len,
                                nodus_tier2_msg_t *msg) {
    (void)payload;
    (void)len;
    nodus_dht_client_request(inproc_dht(b), slot, client_fp, client_pk, msg);
}

static void inproc_inter_frame(nodus_dht_backend_t *b, int slot,
                               const nodus_key_t *peer_fp, const char *peer_ip,
                               const uint8_t *payload, size_t len,
                               nodus_tier2_msg_t *msg) {
    (void)peer_fp;   /* the IPC backend's preface carries them */
    (void)peer_ip;
    nodus_dht_inter_request(inproc_dht(b), slot, payload, len, msg);
}

static void inproc_inter_t1(nodus_dht_backend_t *b, int slot,
                            const nodus_key_t *peer_fp, const char *peer_ip,
                            const uint8_t *payload, size_t len,
                            nodus_tier1_msg_t *t1) {
    (void)payload;
    (void)len;
    nodus_dht_inter_t1(inproc_dht(b), slot, peer_fp, peer_ip, t1);
}

static void inproc_udp_frame(nodus_dht_backend_t *b, const char *from_ip,
                             uint16_t from_port, const uint8_t *payload,
                             size_t len, nodus_tier1_msg_t *msg) {
    (void)payload;
    (void)len;
    nodus_dht_udp_request(inproc_dht(b), from_ip, from_port, msg);
}

static void inproc_peer_seen(nodus_dht_backend_t *b, nodus_dht_peer_seen_t kind,
                             const nodus_key_t *node_id, const char *ip,
                             uint16_t udp_port, uint16_t tcp_port) {
    nodus_dht_peer_seen(inproc_dht(b), kind, node_id, ip, udp_port, tcp_port);
}

static void inproc_peer_dead(nodus_dht_backend_t *b, const nodus_key_t *node_id) {
    nodus_dht_peer_dead(inproc_dht(b), node_id);
}

static void inproc_session_opened(nodus_dht_backend_t *b,
                                  nodus_dht_origin_t origin) {
    nodus_dht_session_opened(inproc_dht(b), origin);
}

static void inproc_session_closed(nodus_dht_backend_t *b,
                                  nodus_dht_origin_t origin) {
    nodus_dht_session_closed(inproc_dht(b), origin);
}

static int inproc_hint_store(nodus_dht_backend_t *b, const nodus_key_t *node_id,
                             const char *ip, uint16_t port,
                             const uint8_t *frame, size_t len) {
    return nodus_dht_hint_store(inproc_dht(b), node_id, ip, port, frame, len);
}

static int inproc_routing_snapshot(nodus_dht_backend_t *b,
                                   nodus_dht_peer_addr_t *out, int max) {
    return nodus_dht_routing_snapshot(inproc_dht(b), out, max);
}

/* No transport of its own: the server loop's poll timings stay as they
 * were. */
static bool inproc_read_pending(nodus_dht_backend_t *b) {
    (void)b;
    return false;
}

static void inproc_evict_tick(nodus_dht_backend_t *b) {
    nodus_dht_evict_tick(inproc_dht(b));
}

static void inproc_tick(nodus_dht_backend_t *b) {
    nodus_dht_tick(inproc_dht(b));
}

static void inproc_stop(nodus_dht_backend_t *b) {
    nodus_dht_stop(inproc_dht(b));
}

static void inproc_close(nodus_dht_backend_t *b) {
    nodus_dht_close(inproc_dht(b));
    free(b);
}

static const nodus_dht_backend_ops_t inproc_ops = {
    .client_frame     = inproc_client_frame,
    .inter_frame      = inproc_inter_frame,
    .inter_t1         = inproc_inter_t1,
    .udp_frame        = inproc_udp_frame,
    .peer_seen        = inproc_peer_seen,
    .peer_dead        = inproc_peer_dead,
    .session_opened   = inproc_session_opened,
    .session_closed   = inproc_session_closed,
    .hint_store       = inproc_hint_store,
    .routing_snapshot = inproc_routing_snapshot,
    .read_pending     = inproc_read_pending,
    .evict_tick       = inproc_evict_tick,
    .tick             = inproc_tick,
    .stop             = inproc_stop,
    .close            = inproc_close,
};

int nodus_dht_backend_inproc_new(const nodus_dht_host_t *host,
                                 nodus_dht_backend_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!host) return -1;

    inproc_backend_t *ib = calloc(1, sizeof(*ib));
    if (!ib) return -2;
    ib->base.ops = &inproc_ops;
    if (nodus_dht_init(&ib->dht, host) != 0) {
        free(ib);
        return -1;
    }
    *out = &ib->base;
    return 0;
}

int nodus_dht_backend_inproc_open(nodus_dht_backend_t *b, const char *data_path,
                                  const char *self_ip, uint16_t self_peer_port) {
    if (!b) return -1;
    return nodus_dht_open(inproc_dht(b), data_path, self_ip, self_peer_port);
}

nodus_dht_t *nodus_dht_backend_inproc_state(nodus_dht_backend_t *b) {
    return b ? inproc_dht(b) : NULL;
}
