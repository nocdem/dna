/**
 * Nodus — Async Channel Replication
 *
 * Replicates channel posts from Primary to Backup nodes.
 * Uses simple blocking TCP for replication sends.
 * Queues to hinted handoff on failure.
 */

#include "channel/nodus_replication.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

/* ── Internal helpers ────────────────────────────────────────────── */

/**
 * Send a wire-framed CBOR message to a peer via a short-lived TCP connection.
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
        /* Wait for connect with poll */
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
 * Serialize a channel post into a CBOR ch_rep message.
 * Caller must free *out.
 */
static int serialize_ch_rep(const uint8_t uuid[NODUS_UUID_BYTES],
                             const nodus_channel_post_t *post,
                             const nodus_pubkey_t *author_pk,
                             uint8_t **out, size_t *out_len) {
    /* Allocate enough for post with Dilithium5 sig + optional pk (2592B) */
    size_t cap = 8192 + post->body_len + NODUS_PK_BYTES + 16;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;

    size_t len = 0;
    int rc = nodus_t2_ch_replicate(0, uuid, post, author_pk, buf, cap, &len);
    if (rc != 0) { free(buf); return -1; }

    *out = buf;
    *out_len = len;
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────── */

void nodus_replication_init(nodus_replication_t *rep, nodus_server_t *srv) {
    memset(rep, 0, sizeof(*rep));
    rep->srv = srv;
    rep->last_retry = nodus_time_now();
}

void nodus_replication_send(nodus_replication_t *rep,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             const nodus_channel_post_t *post,
                             const nodus_pubkey_t *author_pk) {
    nodus_server_t *srv = rep->srv;

    /* Get responsible set for this channel */
    nodus_responsible_set_t rset;
    if (nodus_hashring_responsible(&srv->ring, uuid, &rset) != 0)
        return;  /* Empty ring — no backups */

    /* Serialize the post once for all backups */
    uint8_t *cbor = NULL;
    size_t cbor_len = 0;
    if (serialize_ch_rep(uuid, post, author_pk, &cbor, &cbor_len) != 0)
        return;

    /* Send to each backup (skip self) */
    for (int i = 0; i < rset.count; i++) {
        if (nodus_key_cmp(&rset.nodes[i].node_id, &srv->identity.node_id) == 0)
            continue;  /* Skip self */

        int rc = send_to_peer(rset.nodes[i].ip, rset.nodes[i].tcp_port,
                               cbor, cbor_len);
        if (rc != 0) {
            /* Queue to hinted handoff */
            nodus_hinted_insert(&srv->ch_store,
                                 &rset.nodes[i].node_id,
                                 uuid, cbor, cbor_len);
        }
    }

    free(cbor);
}

void nodus_replication_retry(nodus_replication_t *rep) {
    nodus_server_t *srv = rep->srv;
    uint64_t now = nodus_time_now();

    /* Only retry every NODUS_HINTED_RETRY_SEC seconds */
    if (now - rep->last_retry < NODUS_HINTED_RETRY_SEC)
        return;
    rep->last_retry = now;

    /* Cleanup expired entries first */
    nodus_hinted_cleanup(&srv->ch_store);

    /* Get ring members and try to send their pending entries */
    for (int m = 0; m < srv->ring.count; m++) {
        nodus_ring_member_t *peer = &srv->ring.members[m];
        if (nodus_key_cmp(&peer->node_id, &srv->identity.node_id) == 0)
            continue;  /* Skip self */

        nodus_hinted_entry_t *entries = NULL;
        size_t count = 0;
        if (nodus_hinted_get(&srv->ch_store, &peer->node_id,
                               100, &entries, &count) != 0 || count == 0)
            continue;

        for (size_t i = 0; i < count; i++) {
            int rc = send_to_peer(peer->ip, peer->tcp_port,
                                    entries[i].post_data,
                                    entries[i].post_data_len);
            if (rc == 0) {
                nodus_hinted_delete(&srv->ch_store, entries[i].id);
            } else {
                nodus_hinted_retry(&srv->ch_store, entries[i].id);
                break;  /* Peer still down, stop trying */
            }
        }

        nodus_hinted_entries_free(entries, count);
    }
}

int nodus_replication_receive(nodus_channel_store_t *ch_store,
                               nodus_channel_post_t *post) {
    if (!ch_store || !post) return -1;

    /* Create channel table if it doesn't exist (idempotent) */
    nodus_channel_create(ch_store, post->channel_uuid);

    /* Store the post */
    return nodus_channel_post(ch_store, post);
}
