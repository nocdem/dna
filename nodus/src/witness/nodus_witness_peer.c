/**
 * Nodus — Witness Peer Mesh Implementation
 *
 * Manages TCP connections to peer witnesses. Ported from
 * dnac/src/bft/peer.c (552 lines) and dnac/src/bft/roster.c (526 lines).
 *
 * Key adaptations from DNAC:
 *   - No pthreads (reconnection via tick function in epoll loop)
 *   - No global state (all state in nodus_witness_t)
 *   - Connections via nodus_tcp_connect() (reuses server inter-node TCP pool)
 *   - IDENT exchange via Tier 3 CBOR (not custom binary protocol)
 *   - Roster file loading only (DHT persistence not needed — we ARE the DHT)
 */

#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_handlers.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_tier2.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define LOG_TAG "WITNESS-PEER"

/* (Reconnect constants removed — Kademlia manages inter-node connections) */

/* ── Peer lookup helpers ─────────────────────────────────────────── */

/** Find peer by witness_id. Returns index or -1. */
static int find_peer_by_id(const nodus_witness_t *w,
                            const uint8_t *witness_id) {
    for (int i = 0; i < w->peer_count; i++) {
        if (memcmp(w->peers[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return i;
    }
    return -1;
}

/** Find peer by address string. Returns index or -1. */
static int find_peer_by_addr(const nodus_witness_t *w,
                              const char *address) {
    for (int i = 0; i < w->peer_count; i++) {
        if (strcmp(w->peers[i].address, address) == 0)
            return i;
    }
    return -1;
}

/** Find peer by TCP connection pointer. Returns index or -1. */
static int find_peer_by_conn(const nodus_witness_t *w,
                              const struct nodus_tcp_conn *conn) {
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn == conn)
            return i;
    }
    return -1;
}

/* (connect_to_entry removed — Kademlia manages inter-node connections) */

/* ── Roster sort helper ──────────────────────────────────────────── */

static int roster_cmp(const void *a, const void *b) {
    const nodus_witness_roster_entry_t *ea = (const nodus_witness_roster_entry_t *)a;
    const nodus_witness_roster_entry_t *eb = (const nodus_witness_roster_entry_t *)b;
    return memcmp(ea->witness_id, eb->witness_id, NODUS_T3_WITNESS_ID_LEN);
}

/* ── Build roster from TCP 4002 connections ──────────────────────── */

int nodus_witness_rebuild_roster_from_peers(nodus_witness_t *w,
                                            nodus_witness_roster_t *out) {
    if (!w || !out) return -1;

    memset(out, 0, sizeof(*out));

    /* Add self first */
    nodus_witness_roster_entry_t *self = &out->witnesses[0];
    memcpy(self->witness_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(self->pubkey, w->server->identity.pk.bytes, NODUS_PK_BYTES);
    /* Address: use server's external_ip (or bind_ip) + peer_port */
    const char *ip = w->server->config.external_ip[0]
                   ? w->server->config.external_ip
                   : w->server->config.bind_ip;
    snprintf(self->address, sizeof(self->address), "%s:%u",
             ip, w->server->config.peer_port);
    self->active = true;
    out->n_witnesses = 1;

    /* Add all connected+identified inter_tcp peers */
    nodus_tcp_t *itcp = &w->server->inter_tcp;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS && out->n_witnesses < NODUS_T3_MAX_WITNESSES; i++) {
        nodus_tcp_conn_t *conn = itcp->pool[i];
        if (!conn) continue;
        if (conn->state != NODUS_CONN_CONNECTED) continue;
        if (!conn->peer_id_set) continue;

        /* Duplicate check by peer_id (first 32 bytes = witness_id) */
        bool dup = false;
        for (uint32_t j = 0; j < out->n_witnesses; j++) {
            if (memcmp(out->witnesses[j].witness_id,
                       conn->peer_id.bytes, NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        nodus_witness_roster_entry_t *entry =
            &out->witnesses[out->n_witnesses];
        memcpy(entry->witness_id, conn->peer_id.bytes, NODUS_T3_WITNESS_ID_LEN);
        memcpy(entry->pubkey, conn->peer_pk.bytes, NODUS_PK_BYTES);
        snprintf(entry->address, sizeof(entry->address), "%s:%u",
                 conn->ip, conn->port);
        entry->active = true;
        out->n_witnesses++;
    }

    /* Sort deterministically by witness_id for consistent leader election */
    if (out->n_witnesses > 1) {
        qsort(out->witnesses, out->n_witnesses,
              sizeof(nodus_witness_roster_entry_t), roster_cmp);
    }

    out->version = w->roster.version + 1;
    return (int)out->n_witnesses;
}

/* ── Send IDENT ──────────────────────────────────────────────────── */

int nodus_witness_peer_send_ident(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn) {
    if (!w || !conn) return -1;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_IDENT;
    msg.txn_id = ++w->next_txn_id;
    snprintf(msg.method, sizeof(msg.method), "w_ident");

    /* Fill identity fields */
    msg.ident.witness_id = w->my_id;
    msg.ident.pubkey = w->server->identity.pk.bytes;
    const char *ident_ip = w->server->config.external_ip[0]
                         ? w->server->config.external_ip
                         : w->server->config.bind_ip;
    snprintf(msg.ident.address, sizeof(msg.ident.address),
             "%s:%u", ident_ip, w->server->config.peer_port);

    /* Fill header */
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    msg.header.round = 0;
    msg.header.view = 0;
    memcpy(msg.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&msg.header.nonce, sizeof(msg.header.nonce));
    memcpy(msg.header.chain_id, w->chain_id, 32);

    /* Encode and sign */
    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode w_ident\n", LOG_TAG);
        return -1;
    }

    return nodus_tcp_send(conn, buf, len);
}

/* ── Handle IDENT ────────────────────────────────────────────────── */

int nodus_witness_peer_handle_ident(nodus_witness_t *w,
                                    struct nodus_tcp_conn *conn,
                                    const nodus_t3_msg_t *msg) {
    if (!w || !conn || !msg) return -1;

    const nodus_t3_ident_t *ident = &msg->ident;
    if (!ident->witness_id || !ident->pubkey) {
        fprintf(stderr, "%s: w_ident missing required fields\n", LOG_TAG);
        return -1;
    }

    /* Check if this is an inbound connection (no existing peer for this conn) */
    bool is_inbound = (find_peer_by_conn(w, conn) < 0);

    /* Try to find in roster by witness_id */
    int roster_idx = nodus_witness_roster_find(&w->roster,
                                                 ident->witness_id);

    if (roster_idx < 0 && ident->address[0]) {
        /* Not in roster by ID — check by address (placeholder entry) */
        for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
            if (strcmp(w->roster.witnesses[i].address,
                       ident->address) == 0) {
                roster_idx = (int)i;
                /* Update placeholder ID and pubkey with real identity */
                memcpy(w->roster.witnesses[i].witness_id,
                       ident->witness_id, NODUS_T3_WITNESS_ID_LEN);
                memcpy(w->roster.witnesses[i].pubkey,
                       ident->pubkey, NODUS_PK_BYTES);
                w->roster.version++;
                fprintf(stderr, "%s: updated roster %d identity at %s\n",
                        LOG_TAG, roster_idx, ident->address);
                break;
            }
        }
    }

    if (roster_idx < 0) {
        /* Unknown witness — add to roster if space */
        nodus_witness_roster_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.witness_id, ident->witness_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(entry.pubkey, ident->pubkey, NODUS_PK_BYTES);
        snprintf(entry.address, sizeof(entry.address),
                 "%s", ident->address);
        entry.active = true;

        if (nodus_witness_roster_add(w, &entry) == 0) {
            roster_idx = nodus_witness_roster_find(&w->roster,
                                                     ident->witness_id);
        }
    }

    /* Update or create peer record.
     * Search by real ID first, then by address (placeholder entries). */
    int pi = find_peer_by_id(w, ident->witness_id);
    if (pi < 0 && ident->address[0])
        pi = find_peer_by_addr(w, ident->address);
    if (pi < 0 && w->peer_count < NODUS_T3_MAX_WITNESSES) {
        pi = w->peer_count++;
        memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
    }

    if (pi >= 0) {
        memcpy(w->peers[pi].witness_id, ident->witness_id,
               NODUS_T3_WITNESS_ID_LEN);
        snprintf(w->peers[pi].address, sizeof(w->peers[pi].address),
                 "%s", ident->address);
        w->peers[pi].conn = conn;
        w->peers[pi].identified = true;
        w->peers[pi].connect_failures = 0;
    }

    fprintf(stderr, "%s: w_ident from roster %d at %s "
            "(peers=%d, connected=%d)\n",
            LOG_TAG, roster_idx, ident->address,
            w->peer_count, nodus_witness_peer_connected_count(w));

    /* Send our own IDENT back for inbound connections */
    if (is_inbound) {
        nodus_witness_peer_send_ident(w, conn);
    }

    return 0;
}

/* ── Forward request (non-leader → leader) ───────────────────────── */

int nodus_witness_peer_handle_fwd_req(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_fwd_req_t *fwd = &msg->fwd_req;

    /* Only leader handles forward requests */
    if (!nodus_witness_bft_is_leader(w)) {
        fprintf(stderr, "%s: w_fwd_req but not leader\n", LOG_TAG);
        return -1;
    }

    if (!fwd->tx_data || fwd->tx_len == 0 ||
        fwd->tx_len > NODUS_T3_MAX_TX_SIZE) {
        fprintf(stderr, "%s: w_fwd_req invalid tx_data\n", LOG_TAG);
        return -1;
    }

    fprintf(stderr, "%s: w_fwd_req (tx_len=%u, fee=%lu)\n",
            LOG_TAG, fwd->tx_len, (unsigned long)fwd->fee);

    /* Track forwarder for response routing */
    w->round_state.is_forwarded = true;
    memcpy(w->round_state.forwarder_id, fwd->forwarder_id,
           NODUS_T3_WITNESS_ID_LEN);
    w->round_state.client_conn = NULL;  /* No direct client conn */

    /* Extract nullifiers from tx_data (same format as dnac_spend handler).
     * DNAC serialization: [version(1)] [type(1)] [timestamp(8)] [tx_hash(64)]
     *                     [input_count(1)] [inputs...]
     * Each input: [nullifier(64)] [amount(8)] */
    const size_t input_count_offset = 1 + 1 + 8 + NODUS_T3_TX_HASH_LEN;

    if (fwd->tx_len < 2) return -1;
    uint8_t tx_type = fwd->tx_data[1];
    uint8_t nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
    uint8_t nullifier_count = 0;

    if (tx_type != NODUS_W_TX_GENESIS) {
        if (fwd->tx_len < input_count_offset + 1) return -1;
        nullifier_count = fwd->tx_data[input_count_offset];
        if (nullifier_count > NODUS_T3_MAX_TX_INPUTS) return -1;

        size_t offset = input_count_offset + 1;
        for (int i = 0; i < nullifier_count; i++) {
            if (offset + NODUS_T3_NULLIFIER_LEN > fwd->tx_len)
                return -1;
            memcpy(nullifiers[i], fwd->tx_data + offset,
                   NODUS_T3_NULLIFIER_LEN);
            /* Skip rest of input: nullifier(64) + amount(8) */
            offset += NODUS_T3_NULLIFIER_LEN + 8;
        }
    }

    /* Start BFT consensus round */
    int rc = nodus_witness_bft_start_round(w, fwd->tx_hash,
                                              nullifiers,
                                              nullifier_count,
                                              tx_type,
                                              fwd->tx_data,
                                              fwd->tx_len,
                                              fwd->client_pubkey,
                                              fwd->client_sig,
                                              fwd->fee);

    if (rc != 0) {
        fprintf(stderr, "%s: fwd_req consensus start failed: %d\n",
                LOG_TAG, rc);
    }

    return rc;
}

/* ── Forward response (leader → forwarder) ───────────────────────── */

int nodus_witness_peer_handle_fwd_rsp(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_fwd_rsp_t *rsp = &msg->fwd_rsp;

    fprintf(stderr, "%s: w_fwd_rsp status=%u (%u witness sigs)\n",
            LOG_TAG, rsp->status, rsp->witness_count);

    /* Match pending forward by tx_hash */
    if (!w->pending_forward.active ||
        memcmp(w->pending_forward.tx_hash, rsp->tx_hash,
               NODUS_T3_TX_HASH_LEN) != 0) {
        fprintf(stderr, "%s: w_fwd_rsp no matching pending forward\n",
                LOG_TAG);
        return -1;
    }

    struct nodus_tcp_conn *client_conn = w->pending_forward.client_conn;
    uint32_t client_txn_id = w->pending_forward.client_txn_id;

    /* Clear pending forward */
    w->pending_forward.active = false;
    w->pending_forward.client_conn = NULL;

    if (!client_conn) {
        fprintf(stderr, "%s: w_fwd_rsp client conn gone\n", LOG_TAG);
        return -1;
    }

    /* Send spend result to original client */
    if (rsp->status == 0) {
        /* Use the round_state temporarily to build the response */
        struct nodus_tcp_conn *saved_conn = w->round_state.client_conn;
        uint32_t saved_txn = w->round_state.client_txn_id;
        uint8_t saved_hash[NODUS_T3_TX_HASH_LEN];
        memcpy(saved_hash, w->round_state.tx_hash, NODUS_T3_TX_HASH_LEN);

        w->round_state.client_conn = client_conn;
        w->round_state.client_txn_id = client_txn_id;
        memcpy(w->round_state.tx_hash, rsp->tx_hash, NODUS_T3_TX_HASH_LEN);

        nodus_witness_send_spend_result(w, 0, NULL);

        w->round_state.client_conn = saved_conn;
        w->round_state.client_txn_id = saved_txn;
        memcpy(w->round_state.tx_hash, saved_hash, NODUS_T3_TX_HASH_LEN);
    } else {
        /* Send error response */
        uint8_t err_buf[512];
        size_t err_len = 0;
        nodus_t2_error(client_txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "consensus rejected",
                        err_buf, sizeof(err_buf), &err_len);
        if (err_len > 0)
            nodus_tcp_send(client_conn, err_buf, err_len);
    }

    fprintf(stderr, "%s: forwarded spend result to client (txn=%u)\n",
            LOG_TAG, client_txn_id);
    return 0;
}

/* ── Roster query ────────────────────────────────────────────────── */

int nodus_witness_peer_handle_rost_q(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     const nodus_t3_msg_t *msg) {
    if (!w || !conn || !msg) return -1;

    /* Build roster response */
    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_ROST_R;
    rsp.txn_id = ++w->next_txn_id;
    snprintf(rsp.method, sizeof(rsp.method), "w_rost_r");

    rsp.rost_r.version = w->roster.version;
    rsp.rost_r.n_witnesses = w->roster.n_witnesses;

    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        rsp.rost_r.witnesses[i].witness_id =
            w->roster.witnesses[i].witness_id;
        rsp.rost_r.witnesses[i].pubkey =
            w->roster.witnesses[i].pubkey;
        snprintf(rsp.rost_r.witnesses[i].address,
                 sizeof(rsp.rost_r.witnesses[i].address),
                 "%s", w->roster.witnesses[i].address);
        rsp.rost_r.witnesses[i].joined_epoch =
            w->roster.witnesses[i].joined_epoch;
        rsp.rost_r.witnesses[i].active =
            w->roster.witnesses[i].active;
    }

    /* Fill header */
    rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    rsp.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&rsp.header.nonce, sizeof(rsp.header.nonce));
    memcpy(rsp.header.chain_id, w->chain_id, 32);

    /* Encode and send */
    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&rsp, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode w_rost_r\n", LOG_TAG);
        return -1;
    }

    return nodus_tcp_send(conn, buf, len);
}

/* ── Roster response ─────────────────────────────────────────────── */

int nodus_witness_peer_handle_rost_r(nodus_witness_t *w,
                                     const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_rost_r_t *r = &msg->rost_r;

    /* Only accept if newer version */
    if (r->version <= w->roster.version) {
        return 0;
    }

    fprintf(stderr, "%s: received roster v%u with %u witnesses\n",
            LOG_TAG, r->version, r->n_witnesses);

    /* Merge entries we don't have */
    for (uint32_t i = 0; i < r->n_witnesses; i++) {
        if (!r->witnesses[i].witness_id) continue;

        nodus_witness_roster_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.witness_id, r->witnesses[i].witness_id,
               NODUS_T3_WITNESS_ID_LEN);
        if (r->witnesses[i].pubkey)
            memcpy(entry.pubkey, r->witnesses[i].pubkey, NODUS_PK_BYTES);
        snprintf(entry.address, sizeof(entry.address),
                 "%s", r->witnesses[i].address);
        entry.joined_epoch = r->witnesses[i].joined_epoch;
        entry.active = r->witnesses[i].active;

        nodus_witness_roster_add(w, &entry);
    }

    return 0;
}

/* ── Peer mesh initialization ────────────────────────────────────── */

int nodus_witness_peer_init(nodus_witness_t *w) {
    if (!w) return -1;

    /* Dynamic roster — initial build from current inter_tcp connections.
     * At init time, inter_tcp connections may not be established yet.
     * Full roster will be built on first epoch tick (60s). */
    nodus_witness_rebuild_roster_from_peers(w, &w->roster);
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);

    /* Update my_index in roster */
    w->my_index = -1;
    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        if (memcmp(w->roster.witnesses[i].witness_id,
                   w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
            w->my_index = (int)i;
            break;
        }
    }

    fprintf(stderr, "%s: peer mesh init (roster=%u witnesses, my_index=%d)\n",
            LOG_TAG, w->roster.n_witnesses, w->my_index);
    return 0;
}

/* ── Periodic tick ───────────────────────────────────────────────── */

void nodus_witness_peer_tick(nodus_witness_t *w) {
    if (!w || !w->running) return;

    /* Scan inter_tcp for connected peers that need IDENT exchange */
    nodus_tcp_t *itcp = &w->server->inter_tcp;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *conn = itcp->pool[i];
        if (!conn) continue;
        if (conn->state != NODUS_CONN_CONNECTED) continue;

        /* Check if we already track this connection as a peer */
        int pi = find_peer_by_conn(w, conn);
        if (pi >= 0) {
            /* Already tracked — send IDENT if not yet identified */
            if (!w->peers[pi].identified) {
                nodus_witness_peer_send_ident(w, conn);
                w->peers[pi].identified = true;
            }
            continue;
        }

        /* New connection — add to peers and send IDENT */
        if (w->peer_count < NODUS_T3_MAX_WITNESSES) {
            pi = w->peer_count++;
            memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
            w->peers[pi].conn = conn;
            w->peers[pi].last_attempt = nodus_time_now();

            nodus_witness_peer_send_ident(w, conn);
            w->peers[pi].identified = true;
        }
    }

    /* Clean up peers with dead connections */
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CLOSED) {
            w->peers[i].conn = NULL;
            w->peers[i].identified = false;
        }
    }
}

/* ── Connected count ─────────────────────────────────────────────── */

int nodus_witness_peer_connected_count(const nodus_witness_t *w) {
    if (!w) return 0;

    int count = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CONNECTED &&
            w->peers[i].identified)
            count++;
    }
    return count;
}

/* ── Connection closed notification ──────────────────────────────── */

void nodus_witness_peer_conn_closed(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn) {
    if (!w || !conn) return;

    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn == conn) {
            w->peers[i].conn = NULL;
            w->peers[i].identified = false;
        }
    }

    /* Also clear any BFT round state referencing this conn */
    if (w->round_state.client_conn == conn)
        w->round_state.client_conn = NULL;
}

/* ── Close ───────────────────────────────────────────────────────── */

void nodus_witness_peer_close(nodus_witness_t *w) {
    if (!w) return;

    /* Peer connections are managed by the server's TCP transport
       and will be cleaned up when the server shuts down.
       Just clear our references. */
    for (int i = 0; i < w->peer_count; i++) {
        w->peers[i].conn = NULL;
        w->peers[i].identified = false;
    }
    w->peer_count = 0;

    fprintf(stderr, "%s: peer mesh closed\n", LOG_TAG);
}
