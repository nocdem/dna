/**
 * Nodus — Channel Ring Management
 *
 * Implements ring_check/ring_ack/ring_evict protocol for channel
 * responsibility changes when PBFT detects node failures.
 *
 * @file nodus_ring_mgmt.c
 */

#include "channel/nodus_ring_mgmt.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#define LOG_TAG "RING_MGMT"

/* Response buffer for ring protocol messages (small — no bulk data) */
#define RING_RESP_BUF_SIZE 4096

/* ── Internal helpers ────────────────────────────────────────────── */

/**
 * Find a tracked channel by UUID.
 * Returns index or -1 if not found.
 */
static int find_channel(const nodus_ring_mgmt_t *mgmt,
                         const uint8_t uuid[NODUS_UUID_BYTES]) {
    for (int i = 0; i < NODUS_RING_MGMT_MAX_CHANNELS; i++) {
        if (mgmt->channels[i].active &&
            memcmp(mgmt->channels[i].channel_uuid, uuid, NODUS_UUID_BYTES) == 0)
            return i;
    }
    return -1;
}

/**
 * Send a wire-framed CBOR message to a peer via a short-lived TCP connection.
 * Same pattern as nodus_replication.c send_to_peer().
 * Returns 0 on success, -1 on failure.
 */
static int send_to_peer(const char *ip, uint16_t port,
                         const uint8_t *cbor_payload, size_t cbor_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Non-blocking connect with 2s timeout */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (rc < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        rc = poll(&pfd, 1, 2000);
        if (rc <= 0 || !(pfd.revents & POLLOUT)) {
            close(fd);
            return -1;
        }
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            close(fd);
            return -1;
        }
    }

    /* Switch back to blocking for send */
    fcntl(fd, F_SETFL, flags);

    /* Build wire frame: header + CBOR payload */
    size_t frame_cap = NODUS_FRAME_HEADER_SIZE + cbor_len;
    uint8_t *frame_buf = malloc(frame_cap);
    if (!frame_buf) { close(fd); return -1; }

    size_t frame_len = nodus_frame_encode(frame_buf, frame_cap,
                                           cbor_payload, (uint32_t)cbor_len);
    if (frame_len == 0) { free(frame_buf); close(fd); return -1; }

    /* Send with 2s timeout */
    struct timeval tv = { .tv_sec = 2 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ssize_t sent = 0;
    while ((size_t)sent < frame_len) {
        ssize_t n = send(fd, frame_buf + sent, frame_len - (size_t)sent, MSG_NOSIGNAL);
        if (n <= 0) { free(frame_buf); close(fd); return -1; }
        sent += n;
    }

    free(frame_buf);
    close(fd);
    return 0;
}

/**
 * Check if self is in the responsible set for a channel.
 */
static bool self_is_responsible(const nodus_ring_mgmt_t *mgmt,
                                 const nodus_responsible_set_t *rset) {
    nodus_server_t *srv = mgmt->srv;
    for (int i = 0; i < rset->count; i++) {
        if (nodus_key_cmp(&rset->nodes[i].node_id, &srv->identity.node_id) == 0)
            return true;
    }
    return false;
}

/**
 * Find peer info in PBFT by node_id.
 * Returns pointer to peer or NULL.
 */
static nodus_cluster_peer_t *find_pbft_peer(nodus_ring_mgmt_t *mgmt,
                                              const nodus_key_t *node_id) {
    nodus_pbft_t *pbft = &mgmt->srv->pbft;
    for (int i = 0; i < pbft->peer_count; i++) {
        if (nodus_key_cmp(&pbft->peers[i].node_id, node_id) == 0)
            return &pbft->peers[i];
    }
    return NULL;
}

/**
 * Find the "other" responsible peer (not self, not the dead node).
 * Used to send ring_check to the other remaining responsible node.
 * Returns pointer to the ring member, or NULL.
 */
static const nodus_ring_member_t *find_other_responsible(
        const nodus_ring_mgmt_t *mgmt,
        const nodus_responsible_set_t *rset,
        const nodus_key_t *dead_node_id) {
    nodus_server_t *srv = mgmt->srv;
    for (int i = 0; i < rset->count; i++) {
        if (nodus_key_cmp(&rset->nodes[i].node_id, &srv->identity.node_id) == 0)
            continue;
        if (nodus_key_cmp(&rset->nodes[i].node_id, dead_node_id) == 0)
            continue;
        return &rset->nodes[i];
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────────── */

void nodus_ring_mgmt_init(nodus_ring_mgmt_t *mgmt, struct nodus_server *srv) {
    memset(mgmt, 0, sizeof(*mgmt));
    mgmt->srv = srv;
    mgmt->last_check_tick = nodus_time_now();
}

int nodus_ring_mgmt_track(nodus_ring_mgmt_t *mgmt,
                            const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    /* Check if already tracked */
    if (find_channel(mgmt, channel_uuid) >= 0)
        return 0;

    /* Find empty slot */
    for (int i = 0; i < NODUS_RING_MGMT_MAX_CHANNELS; i++) {
        if (!mgmt->channels[i].active) {
            memcpy(mgmt->channels[i].channel_uuid, channel_uuid, NODUS_UUID_BYTES);
            mgmt->channels[i].active = true;
            mgmt->channels[i].ring_version = 0;
            mgmt->channels[i].check_pending = false;
            mgmt->channel_count++;
            fprintf(stderr, "%s: tracking channel (total=%d)\n",
                    LOG_TAG, mgmt->channel_count);
            return 0;
        }
    }

    fprintf(stderr, "%s: cannot track channel — max channels reached (%d)\n",
            LOG_TAG, NODUS_RING_MGMT_MAX_CHANNELS);
    return -1;
}

void nodus_ring_mgmt_untrack(nodus_ring_mgmt_t *mgmt,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    int idx = find_channel(mgmt, channel_uuid);
    if (idx >= 0) {
        mgmt->channels[idx].active = false;
        mgmt->channels[idx].check_pending = false;
        mgmt->channel_count--;
        fprintf(stderr, "%s: untracked channel (total=%d)\n",
                LOG_TAG, mgmt->channel_count);
    }
}

bool nodus_ring_mgmt_is_tracked(const nodus_ring_mgmt_t *mgmt,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    return find_channel(mgmt, channel_uuid) >= 0;
}

void nodus_ring_mgmt_tick(nodus_ring_mgmt_t *mgmt) {
    uint64_t now = nodus_time_now();

    /* Only run every NODUS_RING_MGMT_TICK_SEC seconds */
    if (now - mgmt->last_check_tick < NODUS_RING_MGMT_TICK_SEC)
        return;
    mgmt->last_check_tick = now;

    nodus_server_t *srv = mgmt->srv;

    for (int i = 0; i < NODUS_RING_MGMT_MAX_CHANNELS; i++) {
        nodus_ring_channel_t *ch = &mgmt->channels[i];
        if (!ch->active) continue;

        /* Handle timeout on pending check */
        if (ch->check_pending) {
            if (now - ch->check_sent_at > NODUS_RING_CHECK_TIMEOUT_SEC) {
                fprintf(stderr, "%s: ring_check timed out, clearing pending\n", LOG_TAG);
                ch->check_pending = false;
            }
            continue;  /* Don't start new check while one is pending */
        }

        /* Get responsible set for this channel */
        nodus_responsible_set_t rset;
        if (nodus_hashring_responsible(&srv->ring, ch->channel_uuid, &rset) != 0)
            continue;

        /* Check if self is still responsible */
        if (!self_is_responsible(mgmt, &rset))
            continue;

        /* Check each responsible peer (not self) for DEAD state */
        for (int j = 0; j < rset.count; j++) {
            if (nodus_key_cmp(&rset.nodes[j].node_id, &srv->identity.node_id) == 0)
                continue;

            nodus_cluster_peer_t *peer = find_pbft_peer(mgmt, &rset.nodes[j].node_id);
            if (!peer || peer->state != NODUS_NODE_DEAD)
                continue;

            /* Peer is DEAD — find the other responsible node to confirm */
            const nodus_ring_member_t *other = find_other_responsible(
                    mgmt, &rset, &rset.nodes[j].node_id);
            if (!other) {
                /* We're the only remaining node — can't get confirmation.
                 * In a 2-node cluster, just proceed with the eviction. */
                fprintf(stderr, "%s: dead peer detected but no other responsible node\n", LOG_TAG);
                continue;
            }

            /* Send ring_check to the other responsible peer */
            uint8_t buf[RING_RESP_BUF_SIZE];
            size_t len = 0;
            uint32_t txn = (uint32_t)(now & 0xFFFFFFFF);
            int rc = nodus_t2_ring_check(txn, &rset.nodes[j].node_id,
                                           ch->channel_uuid, "dead",
                                           buf, sizeof(buf), &len);
            if (rc != 0) continue;

            rc = send_to_peer(other->ip, other->tcp_port, buf, len);
            if (rc == 0) {
                ch->check_pending = true;
                ch->check_node_id = rset.nodes[j].node_id;
                ch->check_is_dead = true;
                ch->check_sent_at = now;
                fprintf(stderr, "%s: sent ring_check(dead) to peer for channel\n", LOG_TAG);
            } else {
                fprintf(stderr, "%s: failed to send ring_check to peer\n", LOG_TAG);
            }

            break;  /* Only one check at a time per channel */
        }
    }
}

void nodus_ring_mgmt_handle_check(nodus_ring_mgmt_t *mgmt,
                                    nodus_tcp_conn_t *conn,
                                    const nodus_key_t *node_id,
                                    const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                    const char *status,
                                    uint32_t txn_id) {
    bool is_dead_check = (strcmp(status, "dead") == 0);

    /* Look up the queried node in own PBFT state */
    nodus_cluster_peer_t *peer = find_pbft_peer(mgmt, node_id);
    bool agree = false;

    if (peer) {
        if (is_dead_check && peer->state == NODUS_NODE_DEAD) {
            agree = true;
        } else if (!is_dead_check && peer->state == NODUS_NODE_ALIVE) {
            agree = true;
        }
    } else {
        /* Unknown node — agree with dead, disagree with alive */
        agree = is_dead_check;
    }

    /* Respond with ring_ack */
    uint8_t buf[RING_RESP_BUF_SIZE];
    size_t len = 0;
    int rc = nodus_t2_ring_ack(txn_id, channel_uuid, agree, buf, sizeof(buf), &len);
    if (rc == 0 && len > 0) {
        nodus_tcp_send(conn, buf, len);
    }

    fprintf(stderr, "%s: handle_check status=%s agree=%s\n",
            LOG_TAG, status, agree ? "true" : "false");
}

void nodus_ring_mgmt_handle_ack(nodus_ring_mgmt_t *mgmt,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  bool agree,
                                  uint32_t txn_id) {
    (void)txn_id;

    int idx = find_channel(mgmt, channel_uuid);
    if (idx < 0) {
        fprintf(stderr, "%s: ring_ack for untracked channel, ignoring\n", LOG_TAG);
        return;
    }

    nodus_ring_channel_t *ch = &mgmt->channels[idx];
    if (!ch->check_pending) {
        fprintf(stderr, "%s: ring_ack but no check pending, ignoring\n", LOG_TAG);
        return;
    }

    ch->check_pending = false;

    if (!agree) {
        fprintf(stderr, "%s: ring_ack disagree — will retry on next tick\n", LOG_TAG);
        return;
    }

    nodus_server_t *srv = mgmt->srv;

    if (ch->check_is_dead) {
        /* Peer confirmed dead — remove from hashring */
        fprintf(stderr, "%s: consensus reached — removing dead node from ring\n", LOG_TAG);

        nodus_hashring_remove(&srv->ring, &ch->check_node_id);

        /* Increment ring version */
        ch->ring_version++;

        /* Announce new responsible set to DHT */
        nodus_ring_announce_to_dht(mgmt, ch->channel_uuid, ch->ring_version);

        /* Send ring_evict to the dead node (best-effort, likely unreachable) */
        nodus_cluster_peer_t *dead_peer = find_pbft_peer(mgmt, &ch->check_node_id);
        if (dead_peer) {
            uint8_t buf[RING_RESP_BUF_SIZE];
            size_t len = 0;
            int rc = nodus_t2_ring_evict(0, ch->channel_uuid,
                                           ch->ring_version,
                                           buf, sizeof(buf), &len);
            if (rc == 0) {
                send_to_peer(dead_peer->ip, dead_peer->tcp_port, buf, len);
            }
        }

        fprintf(stderr, "%s: ring updated, version=%u\n", LOG_TAG, ch->ring_version);
    }
}

void nodus_ring_mgmt_handle_evict(nodus_ring_mgmt_t *mgmt,
                                    const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                    uint32_t version,
                                    uint32_t txn_id,
                                    nodus_tcp_conn_t *conn) {
    nodus_server_t *srv = mgmt->srv;

    fprintf(stderr, "%s: received ring_evict version=%u\n", LOG_TAG, version);

    /* Notify connected 4003 clients subscribed to this channel */
    for (int i = 0; i < NODUS_MAX_CH_SESSIONS; i++) {
        nodus_ch_session_t *cs = &srv->ch_sessions[i];
        if (!cs->conn || !cs->authenticated) continue;

        for (int s = 0; s < cs->ch_sub_count; s++) {
            if (memcmp(cs->ch_subs[s], channel_uuid, NODUS_UUID_BYTES) == 0) {
                /* Send ch_ring_changed notification */
                uint8_t buf[RING_RESP_BUF_SIZE];
                size_t len = 0;
                int rc = nodus_t2_ch_ring_changed(0, channel_uuid, version,
                                                    buf, sizeof(buf), &len);
                if (rc == 0 && len > 0) {
                    nodus_tcp_send(cs->conn, buf, len);
                }
                break;
            }
        }
    }

    /* Untrack the channel — we're no longer responsible */
    nodus_ring_mgmt_untrack(mgmt, channel_uuid);

    /* Acknowledge receipt */
    uint8_t ack_buf[RING_RESP_BUF_SIZE];
    size_t ack_len = 0;
    int rc = nodus_t2_ring_ack(txn_id, channel_uuid, true,
                                 ack_buf, sizeof(ack_buf), &ack_len);
    if (rc == 0 && ack_len > 0 && conn) {
        nodus_tcp_send(conn, ack_buf, ack_len);
    }
}

int nodus_ring_announce_to_dht(nodus_ring_mgmt_t *mgmt,
                                 const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                 uint32_t version) {
    nodus_server_t *srv = mgmt->srv;

    /* Compute DHT key: SHA3-512("dna:channel:nodes:" + channel_uuid) */
    uint8_t key_input[256];
    const char *prefix = "dna:channel:nodes:";
    size_t prefix_len = strlen(prefix);
    memcpy(key_input, prefix, prefix_len);
    memcpy(key_input + prefix_len, channel_uuid, NODUS_UUID_BYTES);

    nodus_key_t dht_key;
    if (nodus_hash(key_input, prefix_len + NODUS_UUID_BYTES, &dht_key) != 0) {
        fprintf(stderr, "%s: failed to compute DHT key for announcement\n", LOG_TAG);
        return -1;
    }

    /* Get responsible set from hashring */
    nodus_responsible_set_t rset;
    if (nodus_hashring_responsible(&srv->ring, channel_uuid, &rset) != 0) {
        fprintf(stderr, "%s: failed to get responsible set for announcement\n", LOG_TAG);
        return -1;
    }

    /* Encode CBOR value: {"version": N, "nodes": [{"ip": "...", "port": 4003, "nid": <key>}, ...]} */
    uint8_t cbor_buf[2048];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, cbor_buf, sizeof(cbor_buf));

    cbor_encode_map(&enc, 2);

    cbor_encode_cstr(&enc, "version");
    cbor_encode_uint(&enc, version);

    cbor_encode_cstr(&enc, "nodes");
    cbor_encode_array(&enc, (size_t)rset.count);

    uint16_t ch_port = srv->config.ch_port ? srv->config.ch_port : NODUS_DEFAULT_CH_PORT;

    for (int i = 0; i < rset.count; i++) {
        cbor_encode_map(&enc, 3);

        /* Use external_ip if configured and this is self, otherwise use the ring member's IP */
        const char *ip = rset.nodes[i].ip;
        if (nodus_key_cmp(&rset.nodes[i].node_id, &srv->identity.node_id) == 0 &&
            srv->config.external_ip[0]) {
            ip = srv->config.external_ip;
        }

        cbor_encode_cstr(&enc, "ip");
        cbor_encode_cstr(&enc, ip);

        cbor_encode_cstr(&enc, "port");
        cbor_encode_uint(&enc, ch_port);

        cbor_encode_cstr(&enc, "nid");
        cbor_encode_bstr(&enc, rset.nodes[i].node_id.bytes, NODUS_KEY_BYTES);
    }

    size_t cbor_len = cbor_encoder_len(&enc);
    if (cbor_len == 0) {
        fprintf(stderr, "%s: CBOR encode failed for DHT announcement\n", LOG_TAG);
        return -1;
    }

    /* Create a nodus_value_t, sign with server identity, store locally */
    nodus_value_t *val = NULL;
    uint64_t vid = (uint64_t)version;
    uint64_t seq = (uint64_t)version;
    int rc = nodus_value_create(&dht_key, cbor_buf, cbor_len,
                                 NODUS_VALUE_EPHEMERAL,
                                 NODUS_DEFAULT_TTL,
                                 vid, seq,
                                 &srv->identity.pk,
                                 &val);
    if (rc != 0 || !val) {
        fprintf(stderr, "%s: failed to create DHT value for announcement\n", LOG_TAG);
        return -1;
    }

    rc = nodus_value_sign(val, &srv->identity.sk);
    if (rc != 0) {
        fprintf(stderr, "%s: failed to sign DHT announcement value\n", LOG_TAG);
        nodus_value_free(val);
        return -1;
    }

    rc = nodus_storage_put(&srv->storage, val);
    if (rc != 0) {
        fprintf(stderr, "%s: failed to store DHT announcement\n", LOG_TAG);
        nodus_value_free(val);
        return -1;
    }

    nodus_value_free(val);
    fprintf(stderr, "%s: announced channel to DHT (version=%u, nodes=%d)\n",
            LOG_TAG, version, rset.count);
    return 0;
}
