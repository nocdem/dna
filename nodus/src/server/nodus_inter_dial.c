/* Shared pinned 4002 pool helpers. The handshake and the only send gate
 * live in nodus_inter_session (approved build plan 4.1 e). */
#include "server/nodus_inter_dial.h"
#include "server/nodus_inter_session.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_wire.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>

nodus_tcp_conn_t *nodus_inter_pool_find(nodus_tcp_t *pool, const char *ip,
                                        uint16_t port,
                                        const nodus_key_t *expected_node_id) {
    if (!pool || !ip) return NULL;
    /* No pin requested: the first pool entry for ip:port, as before. */
    if (!expected_node_id)
        return nodus_tcp_find_by_addr(pool, ip, port);
    /* Pinned: only a conn WE dialed whose identity is the requested one —
     * never an accepted conn (its peer chose to call us; the pin was never
     * checked on it), never a dial pinned to another node_id, never a conn
     * proven for another node_id. Every identity the conn carries must
     * match (expected and, once proven, peer_id) and at least one must be
     * set. Pool slot order: the first such conn. */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = pool->pool[i];
        if (!c || c->is_unix || c->port != port || strcmp(c->ip, ip) != 0)
            continue;
        if (!c->auth_initiated_by_us) continue;
        bool exp_eq = c->expected_peer_id_set &&
                      nodus_key_cmp(&c->expected_peer_id, expected_node_id) == 0;
        bool proven_eq = c->peer_id_set &&
                         nodus_key_cmp(&c->peer_id, expected_node_id) == 0;
        if (c->expected_peer_id_set && !exp_eq) continue;
        if (c->peer_id_set && !proven_eq) continue;
        if (exp_eq || proven_eq) return c;
    }
    return NULL;
}


nodus_tcp_conn_t *nodus_inter_pool_dial(nodus_tcp_t *pool, const char *ip,
                                        uint16_t port,
                                        const nodus_key_t *expected_node_id) {
    if (!pool || !expected_node_id ||
        !nodus_inter_session_chain_ready(pool->session_mode)) return NULL;
    nodus_tcp_conn_t *c = nodus_inter_pool_find(pool, ip, port, expected_node_id);
    if (c) return c;
    c = nodus_tcp_connect_pinned(pool, ip, port, expected_node_id);
    if (c) c->is_nodus = true;
    return c;
}

int nodus_inter_pool_send_framed(nodus_tcp_t *pool, const char *ip,
                                 uint16_t port, const nodus_key_t *expected_node_id,
                                 const uint8_t *frame, size_t flen) {
    if (!frame) return -1;
    nodus_frame_t f;
    memset(&f,0,sizeof(f));
    int used = nodus_frame_decode(frame,flen,&f);
    if (used <= 0 || (size_t)used != flen || !nodus_frame_validate(&f,false)) return -1;
    nodus_tcp_conn_t *c = nodus_inter_pool_dial(pool,ip,port,expected_node_id);
    if (!c) return -1;
    int rc = nodus_tcp_send_progress(c,f.payload,f.payload_len,NULL,NULL);
    if (rc != 0) {
        QGP_LOG_WARN("INTER","slow consumer %s:%u, disconnecting",ip,(unsigned)port);
        nodus_tcp_disconnect(pool,c);
    }
    return rc;
}

void nodus_inter_pool_sweep(nodus_tcp_t *pool, uint64_t now) {
    if (!pool) return;
    for (int i=0; i<NODUS_TCP_MAX_CONNS; ++i) {
        nodus_tcp_conn_t *c=pool->pool[i];
        if (c && c->state==NODUS_CONN_CONNECTED &&
            now-c->last_activity > NODUS_INTER_POOL_IDLE_SEC)
            nodus_tcp_disconnect(pool,c);
    }
}

bool nodus_inter_frame_is_replication(const uint8_t *payload, size_t len) {
    if (!payload) return false;
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, payload, len);
    cbor_item_t top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return false;
    bool is_query = false, is_repl = false, saw_y = false, saw_q = false;
    for (size_t i = 0; i < top.count && !dec.error && !(saw_y && saw_q); i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return false;
        if (k.tstr.len == 1 && (k.tstr.ptr[0] == 'y' || k.tstr.ptr[0] == 'q')) {
            char which = k.tstr.ptr[0];
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type != CBOR_ITEM_TSTR) return false;
            if (which == 'y') {
                saw_y = true;
                is_query = v.tstr.len == 1 && v.tstr.ptr[0] == 'q';
            } else {
                saw_q = true;
                is_repl = (v.tstr.len == 2 && memcmp(v.tstr.ptr, "sv", 2) == 0) ||
                          (v.tstr.len == 4 && memcmp(v.tstr.ptr, "m_sv", 4) == 0);
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    return !dec.error && is_query && is_repl;
}
