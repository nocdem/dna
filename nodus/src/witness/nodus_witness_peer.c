/**
 * Nodus — Witness Peer Mesh Implementation
 *
 * Manages TCP connections to peer witnesses. Ported from
 * dnac/src/bft/peer.c (552 lines) and dnac/src/bft/roster.c (526 lines).
 *
 * Key adaptations from DNAC:
 *   - No pthreads (reconnection via tick function in epoll loop)
 *   - No global state (all state in nodus_witness_t)
 *   - Connections via nodus_tcp_connect() (dedicated witness TCP port 4004)
 *   - IDENT exchange via Tier 3 CBOR (not custom binary protocol)
 *   - Roster file loading only (DHT persistence not needed — we ARE the DHT)
 */

#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_handlers.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_tier2.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_storage.h"
#include "core/nodus_value.h"
#include "witness/nodus_witness_sync.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define LOG_TAG "WITNESS-PEER"

/* Reconnect timing */
#define RECONNECT_BASE_SEC   5
#define RECONNECT_MAX_SHIFT  5      /* Max exponential backoff: 2^5 = 32x */

/* ── Address parsing ─────────────────────────────────────────────── */

static int parse_address(const char *addr, char *ip_out, size_t ip_cap,
                          uint16_t *port_out) {
    if (!addr || !addr[0]) return -1;

    const char *colon = strrchr(addr, ':');
    if (!colon || colon == addr) return -1;

    size_t ip_len = (size_t)(colon - addr);
    if (ip_len >= ip_cap) return -1;

    memcpy(ip_out, addr, ip_len);
    ip_out[ip_len] = '\0';

    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;

    *port_out = (uint16_t)port;
    return 0;
}

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

/* ── Ensure peer entry for inbound connection ────────────────────── */

/**
 * Create or update a peer entry for a roster-verified sender arriving
 * on an inbound TCP connection.  This makes the mesh bidirectional:
 * nodes that connected TO us can now also be reached for broadcasts.
 *
 * Rules:
 *  - Skip self
 *  - If peer exists with an active outbound conn, keep it (prefer outbound)
 *  - If peer exists with a dead/null conn, update conn + mark identified
 *  - If peer not found and space available, create new entry from roster
 */
void nodus_witness_peer_ensure(nodus_witness_t *w,
                                const uint8_t *witness_id,
                                struct nodus_tcp_conn *conn) {
    if (!w || !witness_id || !conn) return;

    /* Skip self */
    if (memcmp(witness_id, w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0)
        return;

    int pi = find_peer_by_id(w, witness_id);

    if (pi >= 0) {
        /* Peer exists — keep active outbound conn, update dead one */
        if (w->peers[pi].conn &&
            w->peers[pi].conn->state == NODUS_CONN_CONNECTED)
            return;  /* Already has a live connection — prefer outbound */

        /* Dead or null conn — adopt this inbound connection */
        w->peers[pi].conn = conn;
        w->peers[pi].identified = true;
        w->peers[pi].connect_failures = 0;
        return;
    }

    /* Not found — create new peer entry if space available */
    if (w->peer_count >= NODUS_T3_MAX_WITNESSES) return;

    int ri = nodus_witness_roster_find(&w->roster, witness_id);
    pi = w->peer_count++;
    memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
    memcpy(w->peers[pi].witness_id, witness_id, NODUS_T3_WITNESS_ID_LEN);
    w->peers[pi].conn = conn;
    w->peers[pi].identified = true;

    /* Copy address from roster if available (use memcpy to avoid
     * restrict-overlap warning — both src and dst live inside *w) */
    if (ri >= 0 && w->roster.witnesses[ri].address[0]) {
        size_t alen = strlen(w->roster.witnesses[ri].address);
        if (alen >= sizeof(w->peers[pi].address))
            alen = sizeof(w->peers[pi].address) - 1;
        memcpy(w->peers[pi].address, w->roster.witnesses[ri].address, alen);
        w->peers[pi].address[alen] = '\0';
    }
}

/* find_peer_by_addr and find_peer_by_conn removed — DHT is primary discovery */

/* (connect_to_entry removed — reconnection handled in peer_tick) */

/* ── Roster sort helper ──────────────────────────────────────────── */

static int roster_cmp(const void *a, const void *b) {
    const nodus_witness_roster_entry_t *ea = (const nodus_witness_roster_entry_t *)a;
    const nodus_witness_roster_entry_t *eb = (const nodus_witness_roster_entry_t *)b;
    return memcmp(ea->witness_id, eb->witness_id, NODUS_T3_WITNESS_ID_LEN);
}

/* ── Build roster from DHT pubkey registry + TCP peers ────────────── */

static const char NODUS_PK_REGISTRY_KEY[] = "nodus:pk";

int nodus_witness_rebuild_roster_from_peers(nodus_witness_t *w,
                                            nodus_witness_roster_t *out) {
    if (!w || !out) return -1;

    memset(out, 0, sizeof(*out));

    /* Add self first */
    nodus_witness_roster_entry_t *self = &out->witnesses[0];
    memcpy(self->witness_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(self->pubkey, w->server->identity.pk.bytes, NODUS_PK_BYTES);
    const char *my_ip = w->server->config.external_ip[0]
                      ? w->server->config.external_ip
                      : w->server->config.bind_ip;
    uint16_t my_wport = w->server->config.witness_port
                      ? w->server->config.witness_port
                      : NODUS_DEFAULT_WITNESS_PORT;
    snprintf(self->address, sizeof(self->address), "%s:%u",
             my_ip, my_wport);
    self->active = true;
    out->n_witnesses = 1;

    /* ── Primary source: DHT pubkey registry ──────────────────────── */
    nodus_key_t pk_key;
    nodus_hash((const uint8_t *)NODUS_PK_REGISTRY_KEY,
               sizeof(NODUS_PK_REGISTRY_KEY) - 1, &pk_key);

    nodus_value_t **vals = NULL;
    size_t val_count = 0;
    if (nodus_storage_get_all(&w->server->storage, &pk_key,
                                &vals, &val_count) == 0 && vals) {
        for (size_t vi = 0; vi < val_count && out->n_witnesses < NODUS_T3_MAX_WITNESSES; vi++) {
            nodus_value_t *val = vals[vi];
            if (!val || !val->data || val->data_len == 0) continue;

            /* Verify signature */
            if (nodus_value_verify(val) != 0) continue;

            /* Skip expired */
            if (nodus_value_is_expired(val, (uint64_t)time(NULL))) continue;

            /* Decode CBOR payload: { "id": node_id, "pk": pubkey, "ip": ip, "port": port } */
            cbor_decoder_t dec;
            cbor_decoder_init(&dec, val->data, val->data_len);
            cbor_item_t top = cbor_decode_next(&dec);
            if (top.type != CBOR_ITEM_MAP) continue;

            uint8_t node_id[NODUS_KEY_BYTES] = {0};
            uint8_t pubkey[NODUS_PK_BYTES] = {0};
            char ip[64] = {0};
            uint16_t port = 0;
            bool has_id = false, has_pk = false;

            for (size_t m = 0; m < top.count; m++) {
                cbor_item_t k = cbor_decode_next(&dec);
                if (k.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

                if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "id", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES) {
                        memcpy(node_id, v.bstr.ptr, NODUS_KEY_BYTES);
                        has_id = true;
                    }
                } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "pk", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_PK_BYTES) {
                        memcpy(pubkey, v.bstr.ptr, NODUS_PK_BYTES);
                        has_pk = true;
                    }
                } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "ip", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_TSTR && v.tstr.len < sizeof(ip)) {
                        memcpy(ip, v.tstr.ptr, v.tstr.len);
                        ip[v.tstr.len] = '\0';
                    }
                } else if (k.tstr.len == 4 && memcmp(k.tstr.ptr, "port", 4) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT)
                        port = (uint16_t)v.uint_val;
                } else {
                    cbor_decode_skip(&dec);
                }
            }

            if (!has_id || !has_pk) continue;

            /* Skip self */
            if (memcmp(node_id, w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0)
                continue;

            /* Duplicate check */
            bool dup = false;
            for (uint32_t j = 0; j < out->n_witnesses; j++) {
                if (memcmp(out->witnesses[j].witness_id,
                           node_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            nodus_witness_roster_entry_t *entry =
                &out->witnesses[out->n_witnesses];
            memcpy(entry->witness_id, node_id, NODUS_T3_WITNESS_ID_LEN);
            memcpy(entry->pubkey, pubkey, NODUS_PK_BYTES);
            if (ip[0] && port)
                snprintf(entry->address, sizeof(entry->address), "%s:%u", ip, port);
            entry->active = true;
            out->n_witnesses++;
        }

        /* Free values */
        for (size_t vi = 0; vi < val_count; vi++)
            nodus_value_free(vals[vi]);
        free(vals);
    }

    /* ── Fallback: w_ident peers not already in roster ────────────── */
    static const uint8_t zero_id[NODUS_T3_WITNESS_ID_LEN] = {0};
    for (int i = 0; i < w->peer_count && out->n_witnesses < NODUS_T3_MAX_WITNESSES; i++) {
        nodus_witness_peer_t *peer = &w->peers[i];
        if (!peer->identified) continue;
        if (!peer->conn || peer->conn->state != NODUS_CONN_CONNECTED) continue;
        if (memcmp(peer->witness_id, zero_id, NODUS_T3_WITNESS_ID_LEN) == 0)
            continue;

        bool dup = false;
        for (uint32_t j = 0; j < out->n_witnesses; j++) {
            if (memcmp(out->witnesses[j].witness_id,
                       peer->witness_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        nodus_witness_roster_entry_t *entry =
            &out->witnesses[out->n_witnesses];
        memcpy(entry->witness_id, peer->witness_id, NODUS_T3_WITNESS_ID_LEN);
        int ri = nodus_witness_roster_find(&w->roster, peer->witness_id);
        if (ri >= 0)
            memcpy(entry->pubkey, w->roster.witnesses[ri].pubkey, NODUS_PK_BYTES);
        snprintf(entry->address, sizeof(entry->address), "%s", peer->address);
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
    uint16_t ident_wport = w->server->config.witness_port
                         ? w->server->config.witness_port
                         : NODUS_DEFAULT_WITNESS_PORT;
    snprintf(msg.ident.address, sizeof(msg.ident.address),
             "%s:%u", ident_ip, ident_wport);

    /* Block height and UTXO checksum for sync detection */
    msg.ident.block_height = nodus_witness_block_height(w);
    if (w->cached_utxo_checksum_valid) {
        memcpy(msg.ident.utxo_checksum, w->cached_utxo_checksum, NODUS_KEY_BYTES);
    } else {
        nodus_witness_utxo_checksum(w, msg.ident.utxo_checksum);
    }
    msg.ident.has_block_height = true;

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

    /* Update or create peer record (dedup by witness_id, then conn) */
    int pi = find_peer_by_id(w, ident->witness_id);
    if (pi < 0) {
        /* Check if existing peer uses this connection (e.g., seed peer
         * with zero witness_id). Reuse slot instead of creating duplicate. */
        for (int j = 0; j < w->peer_count; j++) {
            if (w->peers[j].conn == conn) {
                pi = j;
                break;
            }
        }
    }
    if (pi < 0 && w->peer_count < NODUS_T3_MAX_WITNESSES) {
        pi = w->peer_count++;
        memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
    }

    if (pi >= 0) {
        memcpy(w->peers[pi].witness_id, ident->witness_id,
               NODUS_T3_WITNESS_ID_LEN);
        snprintf(w->peers[pi].address, sizeof(w->peers[pi].address),
                 "%s", ident->address);
        /* Only update conn if existing one is dead — prefer outbound.
         * handle_ident runs on inbound conns; blindly overwriting would
         * replace a working outbound conn with an inbound one, breaking
         * bidirectional broadcast for nodes behind high-latency links. */
        if (!w->peers[pi].conn ||
            w->peers[pi].conn->state != NODUS_CONN_CONNECTED)
            w->peers[pi].conn = conn;
        w->peers[pi].identified = true;
        w->peers[pi].connect_failures = 0;

        /* Store peer's chain state for sync decisions */
        if (ident->has_block_height) {
            w->peers[pi].remote_height = ident->block_height;
            memcpy(w->peers[pi].remote_checksum, ident->utxo_checksum,
                   NODUS_KEY_BYTES);
        }
    }

    /* Trigger sync check — peer may be ahead of us */
    nodus_witness_sync_check(w);

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

    /* Dynamic roster — initial build from DHT registry + witness peers.
     * At init time, witness TCP connections may not be established yet.
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

    /* Bootstrap: connect to all seed nodes on witness TCP port (4004).
     * Seed nodes are configured as IP:UDP_port, witness_port = UDP + 4.
     * This establishes the initial mesh; w_ident exchange populates the roster. */
    nodus_tcp_t *wtcp = (nodus_tcp_t *)w->tcp;
    for (int i = 0; i < w->server->config.seed_count; i++) {
        uint16_t seed_witness_port = w->server->config.seed_ports[i] + 4;
        const char *seed_ip = w->server->config.seed_nodes[i];

        /* Skip if already connected */
        nodus_tcp_conn_t *existing = nodus_tcp_find_by_addr(
            wtcp, seed_ip, seed_witness_port);
        if (existing && existing->state == NODUS_CONN_CONNECTED)
            continue;

        nodus_tcp_conn_t *conn = nodus_tcp_connect(wtcp, seed_ip, seed_witness_port);
        if (conn) {
            /* Create peer record (witness_id unknown until w_ident) */
            if (w->peer_count < NODUS_T3_MAX_WITNESSES) {
                int pi = w->peer_count++;
                memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
                w->peers[pi].conn = conn;
                w->peers[pi].last_attempt = nodus_time_now();
                snprintf(w->peers[pi].address, sizeof(w->peers[pi].address),
                         "%s:%u", seed_ip, seed_witness_port);
            }
        }
    }

    fprintf(stderr, "%s: peer mesh init (roster=%u witnesses, seeds=%d, "
            "peers=%d)\n",
            LOG_TAG, w->roster.n_witnesses,
            w->server->config.seed_count, w->peer_count);
    return 0;
}

/* ── Periodic tick ───────────────────────────────────────────────── */

void nodus_witness_peer_tick(nodus_witness_t *w) {
    if (!w || !w->running) return;

    uint64_t now = nodus_time_now();
    nodus_tcp_t *wtcp = (nodus_tcp_t *)w->tcp;

    /* Clean up peers with dead connections */
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CLOSED) {
            w->peers[i].conn = NULL;
            w->peers[i].identified = false;
        }
    }

    /* Reconnect to roster peers that have no active connection.
     * Witness TCP 4004 connections are NOT managed by Kademlia (which uses UDP 4000),
     * so the witness module must actively connect to discovered peers. */
    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        if ((int)i == w->my_index) continue;
        if (!w->roster.witnesses[i].active) continue;
        if (!w->roster.witnesses[i].address[0]) continue;

        /* Check if we already have a connected peer for this roster entry */
        int pi = find_peer_by_id(w, w->roster.witnesses[i].witness_id);
        if (pi >= 0 && w->peers[pi].conn &&
            w->peers[pi].conn->state == NODUS_CONN_CONNECTED)
            continue;

        /* Apply exponential backoff */
        if (pi >= 0) {
            uint64_t backoff = RECONNECT_BASE_SEC;
            if (w->peers[pi].connect_failures > 0) {
                int shift = w->peers[pi].connect_failures > RECONNECT_MAX_SHIFT
                            ? RECONNECT_MAX_SHIFT
                            : w->peers[pi].connect_failures;
                backoff <<= shift;
            }
            if (now - w->peers[pi].last_attempt < backoff) continue;
        }

        char ip[64];
        uint16_t port;
        if (parse_address(w->roster.witnesses[i].address,
                          ip, sizeof(ip), &port) != 0)
            continue;

        /* Check if already connected via witness TCP */
        nodus_tcp_conn_t *existing = nodus_tcp_find_by_addr(wtcp, ip, port);
        if (existing && existing->state == NODUS_CONN_CONNECTED) {
            if (pi >= 0) {
                w->peers[pi].conn = existing;
                w->peers[pi].identified = true;
                w->peers[pi].connect_failures = 0;
            }
            continue;
        }

        /* Initiate witness TCP connection (port 4004) */
        nodus_tcp_conn_t *conn = nodus_tcp_connect(wtcp, ip, port);
        if (!conn) {
            if (pi >= 0) {
                w->peers[pi].connect_failures++;
                w->peers[pi].last_attempt = now;
            }
            continue;
        }

        /* Before creating a new peer, check if an existing peer matches
         * by address (e.g., seed peer created with zero witness_id).
         * Merge by updating witness_id instead of creating a duplicate. */
        if (pi < 0) {
            for (int j = 0; j < w->peer_count; j++) {
                if (strcmp(w->peers[j].address,
                           w->roster.witnesses[i].address) == 0) {
                    pi = j;
                    memcpy(w->peers[j].witness_id,
                           w->roster.witnesses[i].witness_id,
                           NODUS_T3_WITNESS_ID_LEN);
                    break;
                }
            }
        }

        if (pi < 0 && w->peer_count < NODUS_T3_MAX_WITNESSES) {
            pi = w->peer_count++;
            memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
            memcpy(w->peers[pi].witness_id,
                   w->roster.witnesses[i].witness_id,
                   NODUS_T3_WITNESS_ID_LEN);
            snprintf(w->peers[pi].address, sizeof(w->peers[pi].address),
                     "%s", w->roster.witnesses[i].address);
        }

        if (pi >= 0) {
            w->peers[pi].conn = conn;
            w->peers[pi].connect_failures = 0;
            w->peers[pi].last_attempt = now;
        }
    }

    /* Mark peers as identified when their TCP connection is established.
     * No w_ident exchange needed — roster already has witness_id and pubkey
     * from DHT registry. We match by IP address from the roster entry.
     * Skip peers with zero witness_id (seed peers not yet matched to roster). */
    static const uint8_t zero_id2[NODUS_T3_WITNESS_ID_LEN] = {0};
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].identified) continue;
        if (!w->peers[i].conn) continue;
        if (w->peers[i].conn->state != NODUS_CONN_CONNECTED) continue;
        if (memcmp(w->peers[i].witness_id, zero_id2,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            continue;

        /* C-02: Send hello for Dilithium5 auth before w_ident.
         * If auth_state is NONE, start auth. If AUTH_OK, send w_ident. */
        if (w->peers[i].auth_state == PEER_AUTH_NONE) {
            /* Send hello with our identity */
            nodus_server_t *srv = (nodus_server_t *)w->server;
            uint8_t buf[8192];
            size_t len = 0;
            nodus_t2_hello(0, &srv->identity.pk, &srv->identity.node_id,
                           buf, sizeof(buf), &len);
            nodus_tcp_send(w->peers[i].conn, buf, len);
            w->peers[i].auth_state = PEER_AUTH_HELLO_SENT;
            continue;  /* Wait for challenge response */
        }

        if (w->peers[i].auth_state != PEER_AUTH_OK)
            continue;  /* Still authenticating */

        /* Connection established + authenticated — peer is identified via roster */
        w->peers[i].identified = true;

        /* Announce ourselves so the remote side can register us as a peer */
        nodus_witness_peer_send_ident(w, w->peers[i].conn);
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

    /* H-15: Clear pending forward if it references this connection */
    if (w->pending_forward.active && w->pending_forward.client_conn == conn) {
        w->pending_forward.active = false;
        w->pending_forward.client_conn = NULL;
    }
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
