/**
 * Nodus -- Channel Server (TCP 4003 Session Management)
 *
 * Handles client and node session lifecycle on the dedicated channel port.
 * Auth flow, message dispatch, subscriber notification, heartbeat ticks.
 *
 * @file nodus_channel_server.c
 */

#include "channel/nodus_channel_server.h"
#include "channel/nodus_channel_primary.h"
#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_ring.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>
#include <stdio.h>

#define LOG_TAG "CH_SERVER"

/* ---- Internal helpers -------------------------------------------------- */

static void client_session_clear(nodus_ch_client_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
}

static void node_session_clear(nodus_ch_node_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
}

/**
 * Find an empty client slot. Returns index, or -1 if full.
 */
static int find_empty_client_slot(nodus_channel_server_t *cs) {
    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        if (!cs->clients[i].conn)
            return i;
    }
    return -1;
}

/**
 * Find which client slot owns a given connection.
 */
nodus_ch_client_session_t *nodus_ch_find_client(nodus_channel_server_t *cs,
                                                 nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_CH_MAX_CLIENT_SESSIONS)
        return NULL;
    nodus_ch_client_session_t *s = &cs->clients[conn->slot];
    return (s->conn == conn) ? s : NULL;
}

/**
 * Find a node session by connection pointer.
 */
nodus_ch_node_session_t *nodus_ch_find_node(nodus_channel_server_t *cs,
                                             nodus_tcp_conn_t *conn) {
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        if (cs->nodes[i].conn == conn)
            return &cs->nodes[i];
    }
    return NULL;
}

/**
 * Find an empty node slot. Returns index, or -1 if full.
 */
static int find_empty_node_slot(nodus_channel_server_t *cs) {
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        if (!cs->nodes[i].conn)
            return i;
    }
    return -1;
}

/* ---- Subscription management ------------------------------------------- */

int nodus_ch_client_add_sub(nodus_ch_client_session_t *sess,
                             const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    if (sess->ch_sub_count >= NODUS_CH_MAX_SUBS_PER_CLIENT)
        return -1;
    /* Reject duplicates */
    for (int i = 0; i < sess->ch_sub_count; i++) {
        if (memcmp(sess->ch_subs[i], channel_uuid, NODUS_UUID_BYTES) == 0)
            return -1;
    }
    memcpy(sess->ch_subs[sess->ch_sub_count], channel_uuid, NODUS_UUID_BYTES);
    sess->ch_sub_count++;
    return 0;
}

void nodus_ch_client_remove_sub(nodus_ch_client_session_t *sess,
                                 const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    for (int i = 0; i < sess->ch_sub_count; i++) {
        if (memcmp(sess->ch_subs[i], channel_uuid, NODUS_UUID_BYTES) == 0) {
            /* Swap with last */
            memcpy(sess->ch_subs[i],
                   sess->ch_subs[--sess->ch_sub_count], NODUS_UUID_BYTES);
            return;
        }
    }
}

/* ---- Subscriber notification ------------------------------------------- */

void nodus_ch_notify_subscribers(nodus_channel_server_t *cs,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post) {
    uint8_t buf[8192];
    size_t len = 0;
    if (nodus_t2_ch_post_notify(0, channel_uuid, post,
                                 buf, sizeof(buf), &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode post notification");
        return;
    }

    int notified = 0;
    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        nodus_ch_client_session_t *cl = &cs->clients[i];
        if (!cl->conn || !cl->authenticated)
            continue;
        for (int j = 0; j < cl->ch_sub_count; j++) {
            if (memcmp(cl->ch_subs[j], channel_uuid, NODUS_UUID_BYTES) == 0) {
                nodus_tcp_send(cl->conn, buf, len);
                notified++;
                break;
            }
        }
    }
    QGP_LOG_DEBUG(LOG_TAG, "Notified %d subscribers", notified);
}

void nodus_ch_notify_ring_changed(nodus_channel_server_t *cs,
                                   const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                   uint32_t new_version) {
    uint8_t buf[256];
    size_t len = 0;
    if (nodus_t2_ch_ring_changed(0, channel_uuid, new_version,
                                  buf, sizeof(buf), &len) != 0)
        return;

    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        nodus_ch_client_session_t *cl = &cs->clients[i];
        if (!cl->conn || !cl->authenticated)
            continue;
        for (int j = 0; j < cl->ch_sub_count; j++) {
            if (memcmp(cl->ch_subs[j], channel_uuid, NODUS_UUID_BYTES) == 0) {
                nodus_tcp_send(cl->conn, buf, len);
                break;
            }
        }
    }
}

/* ---- Auth handlers ----------------------------------------------------- */

static void handle_client_hello(nodus_channel_server_t *cs,
                                 nodus_ch_client_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    (void)cs;
    uint8_t buf[8192];

    /* Verify fingerprint matches pubkey */
    nodus_key_t expected_fp;
    nodus_fingerprint(&msg->pk, &expected_fp);
    if (nodus_key_cmp(&expected_fp, &msg->fp) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "fingerprint mismatch", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    sess->client_pk = msg->pk;
    sess->client_fp = msg->fp;

    /* Generate challenge nonce */
    nodus_random(sess->nonce, NODUS_NONCE_LEN);
    sess->nonce_pending = true;

    size_t len = 0;
    nodus_t2_challenge(msg->txn_id, sess->nonce, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
}

static void handle_client_auth(nodus_channel_server_t *cs,
                                nodus_ch_client_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    (void)cs;
    uint8_t buf[8192];

    if (!sess->nonce_pending) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "no pending challenge", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    /* Verify signature over nonce */
    if (nodus_verify(&msg->sig, sess->nonce, NODUS_NONCE_LEN,
                      &sess->client_pk) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "invalid signature", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    sess->authenticated = true;
    sess->nonce_pending = false;
    nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);

    QGP_LOG_INFO(LOG_TAG, "Client authenticated: slot=%d", sess->conn->slot);

    size_t len = 0;
    nodus_t2_auth_ok(msg->txn_id, sess->token, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
}

static void handle_node_hello(nodus_channel_server_t *cs,
                               nodus_ch_node_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    (void)cs;
    uint8_t buf[8192];

    /* Verify fingerprint matches pubkey */
    nodus_key_t expected_fp;
    nodus_fingerprint(&msg->pk, &expected_fp);
    if (nodus_key_cmp(&expected_fp, &msg->fp) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "fingerprint mismatch", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    sess->node_pk = msg->pk;
    sess->node_id = msg->fp;
    sess->ring_version = msg->ring_version;

    /* Generate challenge nonce */
    nodus_random(sess->nonce, NODUS_NONCE_LEN);
    sess->nonce_pending = true;

    size_t len = 0;
    nodus_t2_challenge(msg->txn_id, sess->nonce, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
}

/**
 * Handle auth response for a node session. On success, promote the
 * connection from the temporary client slot to a proper node slot
 * and send node_auth_ok with current ring state.
 */
static void handle_node_auth(nodus_channel_server_t *cs,
                              nodus_ch_node_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    uint8_t buf[16384];

    if (!sess->nonce_pending) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "no pending challenge", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    /* Verify signature over nonce */
    if (nodus_verify(&msg->sig, sess->nonce, NODUS_NONCE_LEN,
                      &sess->node_pk) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "invalid signature", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    sess->authenticated = true;
    sess->nonce_pending = false;
    nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);
    sess->last_heartbeat_recv = nodus_time_now_ms();

    QGP_LOG_INFO(LOG_TAG, "Node authenticated: ring_version=%u", sess->ring_version);

    /* Send node_auth_ok with current ring state */
    size_t len = 0;
    nodus_t2_ch_node_auth_ok(msg->txn_id, sess->token, NODUS_SESSION_TOKEN_LEN,
                              cs->ring ? cs->ring->version : 0,
                              cs->ring ? cs->ring->members : NULL,
                              cs->ring ? cs->ring->count : 0,
                              buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
}

/* ---- Stub handlers (client channel operations) ------------------------- */

static void handle_ch_create(nodus_channel_server_t *cs,
                              nodus_ch_client_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    nodus_ch_primary_handle_create(cs, sess, msg);
}

static void handle_ch_post(nodus_channel_server_t *cs,
                            nodus_ch_client_session_t *sess,
                            nodus_tier2_msg_t *msg) {
    nodus_ch_primary_handle_post(cs, sess, msg);
}

static void handle_ch_get(nodus_channel_server_t *cs,
                           nodus_ch_client_session_t *sess,
                           nodus_tier2_msg_t *msg) {
    nodus_ch_primary_handle_get(cs, sess, msg);
}

static void handle_ch_subscribe(nodus_channel_server_t *cs,
                                 nodus_ch_client_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    nodus_ch_primary_handle_subscribe(cs, sess, msg);
}

static void handle_ch_unsubscribe(nodus_channel_server_t *cs,
                                   nodus_ch_client_session_t *sess,
                                   nodus_tier2_msg_t *msg) {
    nodus_ch_primary_handle_unsubscribe(cs, sess, msg);
}

/* ---- Stub handlers (node operations) ----------------------------------- */

static void handle_ch_replicate(nodus_channel_server_t *cs,
                                 nodus_ch_node_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    /* Build post from flat msg fields (ch_rep encodes post as individual fields,
     * NOT as a "posts" array — so msg->ch_posts is empty) */
    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, msg->channel_uuid, NODUS_UUID_BYTES);
    memcpy(post.post_uuid, msg->post_uuid_ch, NODUS_UUID_BYTES);
    post.author_fp = msg->fp;
    post.timestamp = msg->ch_timestamp;
    post.received_at = msg->ch_received_at;
    post.body = (char *)msg->data;
    post.body_len = msg->data_len;
    memcpy(post.signature.bytes, msg->sig.bytes, NODUS_SIG_BYTES);

    if (cs->ch_replication_ptr) {
        nodus_ch_replication_t *rep = (nodus_ch_replication_t *)cs->ch_replication_ptr;
        nodus_ch_replication_receive(rep, msg->channel_uuid, &post);
        QGP_LOG_INFO(LOG_TAG, "ch_rep: stored replicated post from %s:%u",
                     sess->conn->ip, (unsigned)sess->conn->port);
    }
    if (cs->on_replicate) {
        cs->on_replicate(cs, msg->channel_uuid, &post);
    }
    uint8_t buf[256];
    size_t len = 0;
    nodus_t2_ch_rep_ok(msg->txn_id, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
}

static void handle_heartbeat(nodus_channel_server_t *cs,
                              nodus_ch_node_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    (void)cs;
    sess->last_heartbeat_recv = nodus_time_now_ms();
    uint8_t buf[64];
    size_t len = 0;
    nodus_t2_ch_heartbeat_ack(msg->txn_id, buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);
}

static void handle_heartbeat_ack(nodus_channel_server_t *cs,
                                  nodus_ch_node_session_t *sess,
                                  nodus_tier2_msg_t *msg) {
    (void)cs;
    (void)msg;
    sess->last_heartbeat_recv = nodus_time_now_ms();
}

static void handle_sync_request(nodus_channel_server_t *cs,
                                 nodus_ch_node_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    if (cs->ch_replication_ptr) {
        nodus_ch_replication_t *rep = (nodus_ch_replication_t *)cs->ch_replication_ptr;
        nodus_ch_replication_handle_sync_request(rep, sess,
                                                  msg->channel_uuid,
                                                  msg->ch_received_at);
    } else {
        /* Fallback: empty response */
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_ch_sync_response(msg->txn_id, msg->channel_uuid,
                                   NULL, 0, buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
    }
}

static void handle_ring_check(nodus_channel_server_t *cs,
                               nodus_ch_node_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    if (cs->ch_ring_ptr) {
        nodus_ch_ring_t *rm = (nodus_ch_ring_t *)cs->ch_ring_ptr;
        nodus_ch_ring_handle_check(rm, sess, &msg->ring_node_id,
                                    msg->channel_uuid);
    }
}

static void handle_ring_ack(nodus_channel_server_t *cs,
                             nodus_ch_node_session_t *sess,
                             nodus_tier2_msg_t *msg) {
    (void)sess;
    if (cs->ch_ring_ptr) {
        nodus_ch_ring_t *rm = (nodus_ch_ring_t *)cs->ch_ring_ptr;
        nodus_ch_ring_handle_ack(rm, msg->channel_uuid, msg->ring_agree);
    }
}

static void handle_ring_evict(nodus_channel_server_t *cs,
                               nodus_ch_node_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    (void)sess;
    if (cs->ch_ring_ptr) {
        nodus_ch_ring_t *rm = (nodus_ch_ring_t *)cs->ch_ring_ptr;
        nodus_ch_ring_handle_evict(rm, msg->channel_uuid, msg->ring_version);
    }
}

static void handle_ring_rejoin(nodus_channel_server_t *cs,
                                nodus_ch_node_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    if (cs->ch_ring_ptr) {
        nodus_ch_ring_t *rm = (nodus_ch_ring_t *)cs->ch_ring_ptr;
        nodus_ch_ring_handle_rejoin(rm, sess, &msg->ring_node_id,
                                     msg->ring_version);
    }
}

/* ---- Message dispatch -------------------------------------------------- */

/**
 * Dispatch an authenticated client message to the correct handler.
 */
static void dispatch_client_msg(nodus_channel_server_t *cs,
                                 nodus_ch_client_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    if (strcmp(msg->method, "ch_create") == 0)
        handle_ch_create(cs, sess, msg);
    else if (strcmp(msg->method, "ch_post") == 0)
        handle_ch_post(cs, sess, msg);
    else if (strcmp(msg->method, "ch_get") == 0)
        handle_ch_get(cs, sess, msg);
    else if (strcmp(msg->method, "ch_sub") == 0)
        handle_ch_subscribe(cs, sess, msg);
    else if (strcmp(msg->method, "ch_unsub") == 0)
        handle_ch_unsubscribe(cs, sess, msg);
    else
        QGP_LOG_WARN(LOG_TAG, "Unknown client method: %s", msg->method);
}

/**
 * Dispatch an authenticated node message to the correct handler.
 */
static void dispatch_node_msg(nodus_channel_server_t *cs,
                               nodus_ch_node_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    if (strcmp(msg->method, "ch_rep") == 0)
        handle_ch_replicate(cs, sess, msg);
    else if (strcmp(msg->method, "ch_hb") == 0)
        handle_heartbeat(cs, sess, msg);
    else if (strcmp(msg->method, "ch_hb_ack") == 0)
        handle_heartbeat_ack(cs, sess, msg);
    else if (strcmp(msg->method, "ch_sync_req") == 0)
        handle_sync_request(cs, sess, msg);
    else if (strcmp(msg->method, "ring_check") == 0)
        handle_ring_check(cs, sess, msg);
    else if (strcmp(msg->method, "ring_ack") == 0)
        handle_ring_ack(cs, sess, msg);
    else if (strcmp(msg->method, "ring_evict") == 0)
        handle_ring_evict(cs, sess, msg);
    else if (strcmp(msg->method, "ring_rejoin") == 0)
        handle_ring_rejoin(cs, sess, msg);
    else if (strcmp(msg->method, "ch_rep_ok") == 0)
        { /* Replication ack — fire-and-forget, ignore */ }
    else if (strcmp(msg->method, "ch_sync_resp") == 0) {
        if (cs->ch_replication_ptr) {
            nodus_ch_replication_t *rep = (nodus_ch_replication_t *)cs->ch_replication_ptr;
            nodus_ch_replication_handle_sync_response(rep, msg->channel_uuid,
                                                       msg->ch_posts, msg->ch_post_count);
        }
    }
    else
        QGP_LOG_WARN(LOG_TAG, "Unknown node method: %s", msg->method);
}

/* ---- TCP callbacks ----------------------------------------------------- */

/**
 * Outbound connection completed (connect to peer on TCP 4003).
 * Allocate into a node slot and start node_hello handshake.
 */
static void on_ch_connect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_channel_server_t *cs = (nodus_channel_server_t *)ctx;

    /* Find pending outbound info for this IP:port */
    nodus_ch_pending_outbound_t *po = NULL;
    for (int i = 0; i < NODUS_CH_MAX_PENDING_OUTBOUND; i++) {
        if (cs->pending_outbound[i].active &&
            strcmp(cs->pending_outbound[i].ip, conn->ip) == 0 &&
            cs->pending_outbound[i].port == conn->port) {
            po = &cs->pending_outbound[i];
            break;
        }
    }
    if (!po) {
        QGP_LOG_WARN(LOG_TAG, "No pending info for outbound %s:%u",
                     conn->ip, (unsigned)conn->port);
        nodus_tcp_disconnect(&cs->tcp, conn);
        return;
    }

    int slot = find_empty_node_slot(cs);
    if (slot < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Node pool full, dropping outbound connection");
        po->active = false;
        nodus_tcp_disconnect(&cs->tcp, conn);
        return;
    }

    nodus_ch_node_session_t *ns = &cs->nodes[slot];
    node_session_clear(ns);
    ns->conn = conn;
    ns->node_id = po->node_id;
    po->active = false;  /* Consumed */

    /* Send node_hello with our identity */
    uint8_t buf[8192];
    size_t len = 0;
    uint32_t ring_ver = cs->ring ? cs->ring->version : 0;
    nodus_t2_ch_node_hello(0, &cs->identity->pk,
                            &cs->identity->node_id,
                            ring_ver, buf, sizeof(buf), &len);
    nodus_tcp_send(conn, buf, len);

    QGP_LOG_INFO(LOG_TAG, "Outbound node connection: sent node_hello to %s:%u",
                 conn->ip, (unsigned)conn->port);
}

static void on_ch_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_channel_server_t *cs = (nodus_channel_server_t *)ctx;

    /* Allocate into a client slot by default.
     * If the first message is "node_hello", we promote to node slot. */
    int slot = find_empty_client_slot(cs);
    if (slot < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Session pool full, rejecting connection");
        nodus_tcp_disconnect(&cs->tcp, conn);
        return;
    }

    nodus_ch_client_session_t *sess = &cs->clients[slot];
    client_session_clear(sess);
    sess->conn = conn;
    /* Override conn->slot so we can find this session by connection later */
    conn->slot = slot;

    QGP_LOG_DEBUG(LOG_TAG, "Accepted connection: slot=%d ip=%s", slot, conn->ip);
}

static void on_ch_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_channel_server_t *cs = (nodus_channel_server_t *)ctx;

    /* Check if it's a node session */
    nodus_ch_node_session_t *ns = nodus_ch_find_node(cs, conn);
    if (ns) {
        QGP_LOG_INFO(LOG_TAG, "Node disconnected");
        node_session_clear(ns);
        return;
    }

    /* Otherwise check client session */
    nodus_ch_client_session_t *cl = nodus_ch_find_client(cs, conn);
    if (cl) {
        QGP_LOG_DEBUG(LOG_TAG, "Client disconnected: slot=%d", conn->slot);
        client_session_clear(cl);
    }
}

/**
 * Handle an incoming frame on the channel port.
 * New connections start as "untyped" client slots.
 * "hello" -> client auth flow
 * "node_hello" -> promote to node session, node auth flow
 * Everything else requires authentication.
 */
static void on_ch_frame(nodus_tcp_conn_t *conn,
                         const uint8_t *data, size_t len, void *ctx) {
    nodus_channel_server_t *cs = (nodus_channel_server_t *)ctx;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(data, len, &msg) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to decode frame");
        return;
    }

    /* Check if this is a node session */
    nodus_ch_node_session_t *ns = nodus_ch_find_node(cs, conn);
    if (ns) {
        if (strcmp(msg.method, "auth") == 0 && !ns->authenticated) {
            /* Inbound node completing auth (they connected to us) */
            handle_node_auth(cs, ns, &msg);
        } else if (strcmp(msg.method, "challenge") == 0 && !ns->authenticated) {
            /* Outbound: peer sent challenge in response to our node_hello.
             * Sign the nonce and send auth response. */
            QGP_LOG_DEBUG(LOG_TAG, "Outbound: received challenge from %s:%u",
                         conn->ip, (unsigned)conn->port);
            nodus_sig_t sig;
            if (nodus_sign(&sig, msg.nonce, NODUS_NONCE_LEN,
                            &cs->identity->sk) == 0) {
                uint8_t buf[8192];
                size_t out_len = 0;
                nodus_t2_auth(msg.txn_id, &sig,
                               buf, sizeof(buf), &out_len);
                nodus_tcp_send(conn, buf, out_len);
                QGP_LOG_DEBUG(LOG_TAG, "Outbound: sent auth to %s:%u",
                             conn->ip, (unsigned)conn->port);
            }
        } else if ((strcmp(msg.method, "auth_ok") == 0 ||
                     strcmp(msg.method, "node_auth_ok") == 0) &&
                    !ns->authenticated) {
            /* Outbound: peer accepted our auth. Session is now live. */
            ns->authenticated = true;
            ns->last_heartbeat_recv = nodus_time_now_ms();
            if (msg.has_token)
                memcpy(ns->token, msg.token, NODUS_SESSION_TOKEN_LEN);
            QGP_LOG_INFO(LOG_TAG, "Outbound node authenticated to %s:%u",
                         conn->ip, (unsigned)conn->port);
        } else if (ns->authenticated) {
            dispatch_node_msg(cs, ns, &msg);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Node not authenticated, method=%s", msg.method);
            uint8_t buf[256];
            size_t out_len = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                            "not authenticated", buf, sizeof(buf), &out_len);
            nodus_tcp_send(conn, buf, out_len);
        }
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Client session path */
    nodus_ch_client_session_t *cl = nodus_ch_find_client(cs, conn);
    if (!cl) {
        QGP_LOG_WARN(LOG_TAG, "No session for connection");
        nodus_t2_msg_free(&msg);
        return;
    }

    /* "hello" -> client auth */
    if (strcmp(msg.method, "hello") == 0) {
        handle_client_hello(cs, cl, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* "node_hello" -> promote to node session */
    if (strcmp(msg.method, "node_hello") == 0) {
        int nslot = find_empty_node_slot(cs);
        if (nslot < 0) {
            QGP_LOG_ERROR(LOG_TAG, "Node session pool full");
            uint8_t buf[256];
            size_t out_len = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_RATE_LIMITED,
                            "node pool full", buf, sizeof(buf), &out_len);
            nodus_tcp_send(conn, buf, out_len);
            nodus_t2_msg_free(&msg);
            return;
        }

        /* Move connection from client slot to node slot */
        nodus_tcp_conn_t *saved_conn = cl->conn;
        client_session_clear(cl);

        nodus_ch_node_session_t *new_ns = &cs->nodes[nslot];
        node_session_clear(new_ns);
        new_ns->conn = saved_conn;

        handle_node_hello(cs, new_ns, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* "auth" -> complete client auth */
    if (strcmp(msg.method, "auth") == 0) {
        handle_client_auth(cs, cl, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* All other messages require authentication */
    if (!cl->authenticated) {
        QGP_LOG_WARN(LOG_TAG, "Client not authenticated, method=%s", msg.method);
        uint8_t buf[256];
        size_t out_len = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                        "not authenticated", buf, sizeof(buf), &out_len);
        nodus_tcp_send(conn, buf, out_len);
        nodus_t2_msg_free(&msg);
        return;
    }

    dispatch_client_msg(cs, cl, &msg);
    nodus_t2_msg_free(&msg);
}

/* ---- Public API -------------------------------------------------------- */

int nodus_channel_server_init(nodus_channel_server_t *cs) {
    memset(cs, 0, sizeof(*cs));
    return 0;
}

int nodus_channel_server_listen(nodus_channel_server_t *cs,
                                 const char *bind_ip, uint16_t port) {
    int rc = nodus_tcp_init(&cs->tcp, -1);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "TCP init failed");
        return -1;
    }

    cs->tcp.on_accept     = on_ch_accept;
    cs->tcp.on_connect     = on_ch_connect;
    cs->tcp.on_disconnect  = on_ch_disconnect;
    cs->tcp.on_frame       = on_ch_frame;
    cs->tcp.cb_ctx         = cs;

    rc = nodus_tcp_listen(&cs->tcp, bind_ip, port);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "TCP listen failed on port %u", (unsigned)port);
        nodus_tcp_close(&cs->tcp);
        return -1;
    }

    cs->port = port;
    QGP_LOG_INFO(LOG_TAG, "Listening on %s:%u", bind_ip, (unsigned)port);
    return 0;
}

void nodus_channel_server_poll(nodus_channel_server_t *cs, int timeout_ms) {
    nodus_tcp_poll(&cs->tcp, timeout_ms);
}

void nodus_channel_server_tick(nodus_channel_server_t *cs, uint64_t now_ms) {
    /* Send heartbeats to all authenticated node sessions.
     * NOTE: Dead detection (heartbeat timeout -> eviction) is handled
     * entirely by nodus_ch_ring_tick(). Do NOT disconnect/clear here —
     * ring_tick needs the session to identify which node died. */
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        nodus_ch_node_session_t *ns = &cs->nodes[i];
        if (!ns->conn || !ns->authenticated)
            continue;

        /* Send heartbeat at interval */
        if ((now_ms - ns->last_heartbeat_sent) >= NODUS_CH_HEARTBEAT_INTERVAL_MS) {
            uint8_t buf[64];
            size_t len = 0;
            nodus_t2_ch_heartbeat(0, buf, sizeof(buf), &len);
            nodus_tcp_send(ns->conn, buf, len);
            ns->last_heartbeat_sent = now_ms;
        }
    }
}

int nodus_ch_server_connect_to_peer(nodus_channel_server_t *cs,
                                      const char *ip, uint16_t port,
                                      const nodus_key_t *node_id) {
    if (!cs || !ip || !cs->identity || !node_id) return -1;

    /* Check if we already have a node session for this node_id */
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        nodus_ch_node_session_t *ns = &cs->nodes[i];
        if (ns->conn && nodus_key_cmp(&ns->node_id, node_id) == 0)
            return 0;  /* Already connected or connecting */
    }

    /* Check if already pending */
    for (int i = 0; i < NODUS_CH_MAX_PENDING_OUTBOUND; i++) {
        if (cs->pending_outbound[i].active &&
            nodus_key_cmp(&cs->pending_outbound[i].node_id, node_id) == 0)
            return 0;  /* Already connecting */
    }

    /* Find empty pending slot */
    int slot = -1;
    for (int i = 0; i < NODUS_CH_MAX_PENDING_OUTBOUND; i++) {
        if (!cs->pending_outbound[i].active) { slot = i; break; }
    }
    if (slot < 0) return -1;

    /* Store pending info */
    nodus_ch_pending_outbound_t *po = &cs->pending_outbound[slot];
    strncpy(po->ip, ip, sizeof(po->ip) - 1);
    po->port = port;
    po->node_id = *node_id;
    po->active = true;

    /* Initiate non-blocking connect. on_ch_connect will handle handshake. */
    nodus_tcp_conn_t *conn = nodus_tcp_connect(&cs->tcp, ip, port);
    if (!conn) {
        po->active = false;
        QGP_LOG_WARN(LOG_TAG, "Failed to initiate connect to %s:%u", ip, port);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Connecting to peer %s:%u (TCP 4003)", ip, port);
    return 0;
}

void nodus_channel_server_close(nodus_channel_server_t *cs) {
    nodus_tcp_close(&cs->tcp);

    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++)
        client_session_clear(&cs->clients[i]);
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++)
        node_session_clear(&cs->nodes[i]);

    QGP_LOG_INFO(LOG_TAG, "Channel server closed");
}
