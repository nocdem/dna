/**
 * Nodus — Client SDK Implementation
 *
 * Provides connect/auth/DHT/channel operations with multi-server
 * failover and auto-reconnect (exponential backoff 1s-30s).
 *
 * @file nodus_client.c
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <unistd.h>
  #include <sys/socket.h>
#endif

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "NODUS_CLIENT"

/* ── Internal state ─────────────────────────────────────────────── */

/* Buffer sizes for building protocol messages.
 * CLIENT_BUF_SIZE: used for most operations (auth, get, listen, etc.)
 * CLIENT_BUF_SIZE_PUT: used for PUT — must accommodate max value (1MB) + sig + CBOR.
 * Previous 256KB CLIENT_BUF_SIZE was too small for PUT with >245KB data. */
#define CLIENT_BUF_SIZE       (256 * 1024)
#define CLIENT_BUF_SIZE_PUT   (NODUS_MAX_VALUE_SIZE + 65536)

extern void qgp_secure_memzero(void *ptr, size_t len);

/* ── Forward declarations ───────────────────────────────────────── */

static void client_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx);
static void client_on_disconnect(nodus_tcp_conn_t *conn, void *ctx);
static void client_on_connect(nodus_tcp_conn_t *conn, void *ctx);
static uint64_t now_ms(void);
static nodus_pending_t *alloc_pending(nodus_client_t *client, uint32_t txn);
static void free_pending(nodus_client_t *client, nodus_pending_t *p);
static int send_request(nodus_client_t *client, const uint8_t *buf, size_t len);
static int send_request_progress(nodus_client_t *client, const uint8_t *buf, size_t len,
                                  nodus_tcp_progress_cb progress_cb, void *user_data);
static void set_state(nodus_client_t *client, nodus_client_state_t new_state);
static int  do_connect_one(nodus_client_t *client, int server_idx);
static int  do_auth(nodus_client_t *client);
static bool wait_response(nodus_client_t *client, nodus_pending_t *req, int timeout_ms);
static int  send_request(nodus_client_t *client, const uint8_t *payload, size_t len);
static int  resubscribe_all(nodus_client_t *client);
static int  try_reconnect(nodus_client_t *client);

/* ── Cross-platform millisecond sleep ──────────────────────────── */

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

/* ── Internal read thread ──────────────────────────────────────── */

static void *read_thread_fn(void *arg) {
    nodus_client_t *client = (nodus_client_t *)arg;
    QGP_LOG_INFO(LOG_TAG, "Read thread started");

    while (!atomic_load(&client->read_thread_stop)) {
        pthread_mutex_lock(&client->poll_mutex);

        /* Handle reconnect */
        if (client->state == NODUS_CLIENT_RECONNECTING) {
            if (atomic_load(&client->suspended)) {
                /* App in background — don't reconnect, just idle */
                pthread_mutex_unlock(&client->poll_mutex);
                sleep_ms(500);
                continue;
            }
            try_reconnect(client);
            if (client->state != NODUS_CLIENT_READY && client->tcp) {
                nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
                nodus_tcp_poll(tcp, 100);
            }
            pthread_mutex_unlock(&client->poll_mutex);
            continue;
        }

        if (!client->conn || !client->tcp) {
            pthread_mutex_unlock(&client->poll_mutex);
            sleep_ms(100);
            continue;
        }

        nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
        int rc = nodus_tcp_poll(tcp, 100);

        /* Keepalive ping every 60s to prevent server idle sweep */
        if (client->state == NODUS_CLIENT_READY) {
            uint64_t now = now_ms();
            if (now - client->last_ping_ms >= 60000) {
                client->last_ping_ms = now;
                uint8_t ping_buf[128];
                size_t ping_len = 0;
                uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
                if (nodus_t2_ping(txn, client->token, ping_buf, sizeof(ping_buf), &ping_len) == 0) {
                    nodus_tcp_send(client->conn, ping_buf, ping_len);
                }
            }
        }

        pthread_mutex_unlock(&client->poll_mutex);

        if (rc < 0 && atomic_load(&client->read_thread_stop))
            break;
        if (client->state == NODUS_CLIENT_DISCONNECTED)
            sleep_ms(100);
    }

    QGP_LOG_INFO(LOG_TAG, "Read thread stopped");
    return NULL;
}

static void start_read_thread(nodus_client_t *client) {
    if (atomic_load(&client->read_thread_running)) return;
    atomic_store(&client->read_thread_stop, false);
    if (pthread_create(&client->read_thread, NULL, read_thread_fn, client) == 0) {
        atomic_store(&client->read_thread_running, true);
        QGP_LOG_INFO(LOG_TAG, "Read thread launched");
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create read thread");
    }
}

static void stop_read_thread(nodus_client_t *client) {
    if (!atomic_load(&client->read_thread_running)) return;
    atomic_store(&client->read_thread_stop, true);
    pthread_join(client->read_thread, NULL);
    atomic_store(&client->read_thread_running, false);
    QGP_LOG_INFO(LOG_TAG, "Read thread joined");
}

/* ── Helpers ────────────────────────────────────────────────────── */

static uint64_t now_ms(void) {
    return nodus_time_now() * 1000ULL;
}

static void set_state(nodus_client_t *client, nodus_client_state_t new_state) {
    if (client->state == new_state) return;
    nodus_client_state_t old = client->state;
    client->state = new_state;
    if (client->config.on_state_change)
        client->config.on_state_change(old, new_state, client->config.callback_data);
}

static int send_request(nodus_client_t *client, const uint8_t *payload, size_t len) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
    if (!conn) return -1;
    pthread_mutex_lock(&client->send_mutex);
    int rc = nodus_tcp_send(conn, payload, len);
    pthread_mutex_unlock(&client->send_mutex);
    return rc;
}

static int send_request_progress(nodus_client_t *client, const uint8_t *payload, size_t len,
                                  nodus_tcp_progress_cb progress_cb, void *user_data) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
    if (!conn) return -1;
    pthread_mutex_lock(&client->send_mutex);
    int rc = nodus_tcp_send_progress(conn, payload, len, progress_cb, user_data);
    pthread_mutex_unlock(&client->send_mutex);
    return rc;
}

/* ── Pending slot management ───────────────────────────────────── */

static nodus_pending_t *alloc_pending(nodus_client_t *client, uint32_t txn) {
    /* Retry with exponential backoff if all slots are busy (startup burst) */
    const int max_retries = 5;
    int backoff_ms = 10;

    for (int attempt = 0; attempt <= max_retries; attempt++) {
        pthread_mutex_lock(&client->pending_mutex);
        for (int i = 0; i < NODUS_MAX_PENDING; i++) {
            if (!client->pending[i].in_use) {
                nodus_pending_t *p = &client->pending[i];
                memset(p, 0, sizeof(*p));
                p->txn = txn;
                p->response = calloc(1, sizeof(nodus_tier2_msg_t));
                p->in_use = true;
                pthread_mutex_unlock(&client->pending_mutex);
                if (attempt > 0) {
                    QGP_LOG_DEBUG(LOG_TAG, "Pending slot acquired after %d retries", attempt);
                }
                return p;
            }
        }
        pthread_mutex_unlock(&client->pending_mutex);

        if (attempt < max_retries) {
            QGP_LOG_WARN(LOG_TAG, "All %d pending slots busy, retry %d/%d in %dms",
                         NODUS_MAX_PENDING, attempt + 1, max_retries, backoff_ms);
            struct timespec ts = { .tv_sec = 0, .tv_nsec = backoff_ms * 1000000L };
            nanosleep(&ts, NULL);
            backoff_ms *= 2;  /* 10, 20, 40, 80, 160ms */
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "No pending slots available (max %d) after %d retries",
                  NODUS_MAX_PENDING, max_retries);
    return NULL;
}

static void free_pending(nodus_client_t *client, nodus_pending_t *p) {
    if (!p) return;
    pthread_mutex_lock(&client->pending_mutex);
    if (p->response) {
        nodus_t2_msg_free((nodus_tier2_msg_t *)p->response);
        free(p->response);
    }
    free(p->raw_response);
    p->in_use = false;
    pthread_mutex_unlock(&client->pending_mutex);
}

static bool wait_response(nodus_client_t *client, nodus_pending_t *req, int timeout_ms) {
    int elapsed = 0;

    while (!atomic_load(&req->ready) && elapsed < timeout_ms) {
        if (!client->conn && client->state != NODUS_CLIENT_RECONNECTING)
            return false;

        if (atomic_load(&client->read_thread_running) &&
            !pthread_equal(pthread_self(), client->read_thread)) {
            /* Read thread handles TCP — just wait for ready flag */
            sleep_ms(10);
            elapsed += 10;
        } else {
            /* We ARE the read thread (reconnect path), or no thread — poll directly */
            nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
            if (tcp) nodus_tcp_poll(tcp, 50);
            elapsed += 50;
        }
    }
    return atomic_load(&req->ready);
}

/* ── TCP Callbacks ──────────────────────────────────────────────── */

static void client_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx) {
    (void)conn;
    nodus_client_t *client = (nodus_client_t *)ctx;

    /* Decode into a temporary struct first to check if it's a push notification.
     * Push notifications must NOT clobber the pending_response — multiple frames
     * can arrive in a single TCP read, and a push following a synchronous response
     * would zero the response data before the caller reads it. */
    nodus_tier2_msg_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    if (nodus_t2_decode(payload, len, &tmp) != 0)
        return;

    /* Push notifications (async — not a response to a request) */
    if (strcmp(tmp.method, "value_changed") == 0) {
        if (client->config.on_value_changed && tmp.value)
            client->config.on_value_changed(&tmp.key, tmp.value,
                                             client->config.callback_data);
        nodus_t2_msg_free(&tmp);
        return;
    }

    if (strcmp(tmp.method, "ch_ntf") == 0) {
        if (client->config.on_ch_post) {
            /* ch_ntf encodes post fields individually in args, not as posts array.
             * Construct a temporary post from decoded fields. */
            nodus_channel_post_t post;
            memset(&post, 0, sizeof(post));
            memcpy(post.channel_uuid, tmp.channel_uuid, NODUS_UUID_BYTES);
            memcpy(post.post_uuid, tmp.post_uuid_ch, NODUS_UUID_BYTES);
            post.author_fp = tmp.fp;
            post.timestamp = tmp.ch_timestamp;
            post.received_at = tmp.ch_received_at;
            post.signature = tmp.sig;
            post.body = (char *)tmp.data;
            post.body_len = tmp.data_len;
            client->config.on_ch_post(tmp.channel_uuid, &post,
                                       client->config.callback_data);
        }
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Circuit push notifications (Faz 1) */
    if (strcmp(tmp.method, "circ_inbound") == 0 && tmp.has_circ) {
        pthread_mutex_lock(&client->circuits_mutex);
        nodus_circuit_handle_t *h = NULL;
        for (int i = 0; i < NODUS_CLIENT_MAX_CIRCUITS; i++) {
            if (!client->circuits[i].in_use) {
                h = &client->circuits[i];
                memset(h, 0, sizeof(*h));
                h->client = client;
                h->cid = tmp.circ_cid;
                h->in_use = true;
                break;
            }
        }
        pthread_mutex_unlock(&client->circuits_mutex);
        /* E2E: if circ_inbound has e2e_ct, decapsulate and init per-circuit crypto */
        if (h && tmp.has_e2e_ct && client->identity.has_kyber) {
            uint8_t e2e_ss[NODUS_KYBER_SS_BYTES];
            if (qgp_kem1024_decapsulate(e2e_ss, tmp.e2e_ct, client->identity.kyber_sk) == 0) {
                uint8_t nc[32], ns[32];
                memcpy(nc, tmp.circ_peer_fp.bytes, 32);  /* src = peer */
                memcpy(ns, client->identity.node_id.bytes, 32);  /* dst = us */
                nodus_channel_crypto_init(&h->e2e_crypto, e2e_ss, nc, ns);
                h->e2e_active = true;
                QGP_LOG_INFO(LOG_TAG, "Circuit E2E: inbound onion layer active (cid=%llu)",
                             (unsigned long long)h->cid);
            }
            qgp_secure_memzero(e2e_ss, sizeof(e2e_ss));
        }
        if (h && client->on_circuit_inbound) {
            client->on_circuit_inbound(client, &tmp.circ_peer_fp, h,
                                        client->circuit_inbound_user);
        }
        nodus_t2_msg_free(&tmp);
        return;
    }
    if (strcmp(tmp.method, "circ_data") == 0 && tmp.has_circ) {
        pthread_mutex_lock(&client->circuits_mutex);
        nodus_circuit_handle_t *h = NULL;
        for (int i = 0; i < NODUS_CLIENT_MAX_CIRCUITS; i++) {
            if (client->circuits[i].in_use && client->circuits[i].cid == tmp.circ_cid) {
                h = &client->circuits[i];
                break;
            }
        }
        nodus_circuit_data_cb cb = h ? h->on_data : NULL;
        void *user = h ? h->user : NULL;
        bool e2e = h ? h->e2e_active : false;
        pthread_mutex_unlock(&client->circuits_mutex);

        /* E2E decrypt if onion layer active */
        if (cb && e2e && tmp.circ_data && tmp.circ_data_len > NODUS_CHANNEL_OVERHEAD) {
            size_t pt_cap = tmp.circ_data_len - NODUS_CHANNEL_OVERHEAD;
            uint8_t *pt = malloc(pt_cap > 0 ? pt_cap : 1);
            if (pt) {
                size_t pt_len = 0;
                if (nodus_channel_decrypt(&h->e2e_crypto, tmp.circ_data, tmp.circ_data_len,
                                           pt, pt_cap, &pt_len) == 0) {
                    cb(h, pt, pt_len, user);
                } else {
                    QGP_LOG_ERROR(LOG_TAG, "Circuit E2E decrypt failed (cid=%llu)",
                                 (unsigned long long)h->cid);
                }
                free(pt);
            }
        } else if (cb) {
            cb(h, tmp.circ_data, tmp.circ_data_len, user);
        }
        nodus_t2_msg_free(&tmp);
        return;
    }
    if (strcmp(tmp.method, "circ_close") == 0 && tmp.has_circ) {
        pthread_mutex_lock(&client->circuits_mutex);
        nodus_circuit_handle_t *h = NULL;
        nodus_circuit_close_cb cb = NULL;
        void *user = NULL;
        for (int i = 0; i < NODUS_CLIENT_MAX_CIRCUITS; i++) {
            if (client->circuits[i].in_use && client->circuits[i].cid == tmp.circ_cid) {
                h = &client->circuits[i];
                cb = h->on_close;
                user = h->user;
                h->closed = true;
                h->in_use = false;
                break;
            }
        }
        pthread_mutex_unlock(&client->circuits_mutex);
        if (cb) cb(h, 0, user);
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Find pending slot by txn ID */
    pthread_mutex_lock(&client->pending_mutex);
    nodus_pending_t *slot = NULL;
    for (int i = 0; i < NODUS_MAX_PENDING; i++) {
        if (client->pending[i].in_use && client->pending[i].txn == tmp.txn_id) {
            slot = &client->pending[i];
            break;
        }
    }
    if (!slot) {
        pthread_mutex_unlock(&client->pending_mutex);
        QGP_LOG_WARN(LOG_TAG, "Response for unknown txn %u (no pending slot)", tmp.txn_id);
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Save raw payload for DNAC-specific CBOR decoding */
    free(slot->raw_response);
    slot->raw_response = malloc(len);
    if (slot->raw_response) {
        memcpy(slot->raw_response, payload, len);
        slot->raw_response_len = len;
    } else {
        slot->raw_response_len = 0;
    }

    /* Move decoded response into slot */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)slot->response;
    nodus_t2_msg_free(resp);
    *resp = tmp;  /* Transfer ownership (shallow copy, no double-free) */
    slot->ready = true;
    pthread_mutex_unlock(&client->pending_mutex);
}

static void client_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_client_t *client = (nodus_client_t *)ctx;
    int sock_err = 0;
#ifdef _WIN32
    int elen = sizeof(sock_err);
    if (conn && conn->fd >= 0)
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (char *)&sock_err, &elen);
#else
    socklen_t elen = sizeof(sock_err);
    if (conn && conn->fd >= 0)
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &sock_err, &elen);
#endif
    QGP_LOG_WARN(LOG_TAG, "[DISCONNECT] server=%s:%d sock_err=%d idle=%lums",
                 conn && conn->ip[0] ? conn->ip : "?",
                 conn ? conn->port : 0,
                 sock_err,
                 conn ? (unsigned long)(now_ms() - conn->last_activity * 1000) : 0);
    client->conn = NULL;

    if (client->state == NODUS_CLIENT_READY ||
        client->state == NODUS_CLIENT_AUTHENTICATING) {
        if (client->config.auto_reconnect) {
            set_state(client, NODUS_CLIENT_RECONNECTING);
            client->backoff_ms = client->config.reconnect_min_ms;
            client->reconnect_at = now_ms() + client->backoff_ms;
        } else {
            set_state(client, NODUS_CLIENT_DISCONNECTED);
        }
    }
}

static void client_on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

int nodus_client_init(nodus_client_t *client,
                       const nodus_client_config_t *config,
                       const nodus_identity_t *identity) {
    if (!client || !config || !identity) return -1;
    if (config->server_count <= 0 || config->server_count > NODUS_CLIENT_MAX_SERVERS)
        return -1;

    memset(client, 0, sizeof(*client));
    client->config = *config;
    client->identity = *identity;
    client->state = NODUS_CLIENT_DISCONNECTED;
    atomic_store(&client->next_txn, 1);
    client->server_idx = 0;

    /* Apply defaults */
    if (client->config.connect_timeout_ms <= 0)
        client->config.connect_timeout_ms = 5000;
    if (client->config.request_timeout_ms <= 0)
        client->config.request_timeout_ms = 10000;
    if (client->config.reconnect_min_ms <= 0)
        client->config.reconnect_min_ms = 1000;
    if (client->config.reconnect_max_ms <= 0)
        client->config.reconnect_max_ms = 30000;
    /* auto_reconnect defaults to false since memset zeroed it — caller must opt in */

    /* Initialize concurrency primitives */
    pthread_mutex_init(&client->pending_mutex, NULL);
    pthread_mutex_init(&client->send_mutex, NULL);
    pthread_mutex_init(&client->poll_mutex, NULL);
    pthread_mutex_init(&client->circuits_mutex, NULL);

    /* Initialize circuit state (Faz 1) */
    memset(client->circuits, 0, sizeof(client->circuits));
    client->on_circuit_inbound = NULL;
    client->circuit_inbound_user = NULL;
    atomic_store(&client->next_client_cid, 1);
    atomic_store(&client->read_thread_running, false);
    atomic_store(&client->read_thread_stop, false);

    /* Initialize TCP transport */
    nodus_tcp_t *tcp = calloc(1, sizeof(nodus_tcp_t));
    if (!tcp) {
        pthread_mutex_destroy(&client->pending_mutex);
        pthread_mutex_destroy(&client->send_mutex);
        pthread_mutex_destroy(&client->poll_mutex);
        pthread_mutex_destroy(&client->circuits_mutex);
        return -1;
    }
    nodus_tcp_init(tcp, -1);
    tcp->on_frame = client_on_frame;
    tcp->on_disconnect = client_on_disconnect;
    tcp->on_connect = client_on_connect;
    tcp->cb_ctx = client;
    client->tcp = tcp;

    return 0;
}

int nodus_client_connect(nodus_client_t *client) {
    if (!client || !client->tcp) return -1;

    /* Try each server in order */
    for (int i = 0; i < client->config.server_count; i++) {
        int idx = (client->server_idx + i) % client->config.server_count;
        if (do_connect_one(client, idx) == 0) {
            client->server_idx = idx;
            client->backoff_ms = client->config.reconnect_min_ms;
            /* Start internal read thread for continuous TCP reading */
            start_read_thread(client);
            return 0;
        }
    }

    set_state(client, NODUS_CLIENT_DISCONNECTED);
    return -1;
}

static int do_connect_one(nodus_client_t *client, int server_idx) {
    nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
    nodus_server_endpoint_t *ep = &client->config.servers[server_idx];

    QGP_LOG_INFO(LOG_TAG, "Connecting to %s:%d ...", ep->ip, ep->port);
    fprintf(stderr, "[NODUS_CLIENT] Connecting to %s:%d ...\n", ep->ip, ep->port);
    set_state(client, NODUS_CLIENT_CONNECTING);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(tcp, ep->ip, ep->port);
    if (!conn) {
        QGP_LOG_ERROR(LOG_TAG, "TCP connect failed to %s:%d (socket error)", ep->ip, ep->port);
        fprintf(stderr, "[NODUS_CLIENT] TCP connect failed to %s:%d (socket error)\n", ep->ip, ep->port);
        return -1;
    }
    client->conn = conn;

    /* Wait for TCP connection to establish.
     * Note: nodus_tcp_poll() may free conn via on_disconnect callback
     * (which sets client->conn = NULL), so check client->conn after
     * each poll iteration to avoid use-after-free on the local ptr. */
    int elapsed = 0;
    while (client->conn && conn->state == NODUS_CONN_CONNECTING &&
           elapsed < client->config.connect_timeout_ms) {
        nodus_tcp_poll(tcp, 50);
        elapsed += 50;
        conn = (nodus_tcp_conn_t *)client->conn;  /* re-read (may be NULL) */
        if (!conn) break;
    }

    if (!client->conn || conn == NULL || conn->state != NODUS_CONN_CONNECTED) {
        QGP_LOG_ERROR(LOG_TAG, "TCP connect to %s:%d failed after %dms (state=%d)",
                      ep->ip, ep->port, elapsed,
                      conn ? (int)conn->state : -1);
        fprintf(stderr, "[NODUS_CLIENT] TCP connect to %s:%d FAILED after %dms (state=%d)\n",
                ep->ip, ep->port, elapsed, conn ? (int)conn->state : -1);
        if (client->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)client->conn);
            client->conn = NULL;
        }
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "TCP connected to %s:%d, authenticating...", ep->ip, ep->port);
    fprintf(stderr, "[NODUS_CLIENT] TCP connected to %s:%d, authenticating...\n", ep->ip, ep->port);

    /* Authenticate */
    set_state(client, NODUS_CLIENT_AUTHENTICATING);
    if (do_auth(client) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth failed to %s:%d", ep->ip, ep->port);
        fprintf(stderr, "[NODUS_CLIENT] Auth FAILED to %s:%d\n", ep->ip, ep->port);
        if (client->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)client->conn);
            client->conn = NULL;
        }
        return -1;
    }

    client->last_ping_ms = now_ms();
    set_state(client, NODUS_CLIENT_READY);

    /* Re-subscribe after reconnect */
    resubscribe_all(client);
    return 0;
}

static int do_auth(nodus_client_t *client) {
    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    int result = -1;

    /* Step 1: HELLO */
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_hello(txn, &client->identity.pk, &client->identity.node_id,
                    buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: HELLO send failed");
        free_pending(client, req);
        free(buf);
        return -1;
    }

    if (!wait_response(client, req, client->config.connect_timeout_ms)) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: no response to HELLO (timeout %dms)", client->config.connect_timeout_ms);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (strcmp(resp->method, "challenge") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'challenge', got '%s'", resp->method);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    /* Step 2: Sign nonce and send AUTH.
     * Save nonce for later verification of server's kpk_sig. */
    uint8_t auth_nonce[NODUS_NONCE_LEN];
    memcpy(auth_nonce, resp->nonce, NODUS_NONCE_LEN);
    nodus_sig_t sig;
    nodus_sign(&sig, auth_nonce, NODUS_NONCE_LEN, &client->identity.sk);
    free_pending(client, req);

    len = 0;
    txn = atomic_fetch_add(&client->next_txn, 1);
    req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_auth(txn, &sig, buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: AUTH send failed");
        free_pending(client, req);
        free(buf);
        return -1;
    }

    if (!wait_response(client, req, client->config.connect_timeout_ms)) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: no response to AUTH (timeout %dms)", client->config.connect_timeout_ms);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    resp = (nodus_tier2_msg_t *)req->response;
    if (strcmp(resp->method, "auth_ok") != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'auth_ok', got '%s'", resp->method);
        free_pending(client, req);
        free(buf);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Auth: success");
    memcpy(client->token, resp->token, NODUS_SESSION_TOKEN_LEN);

    /* Channel encryption: use server Kyber pubkey (from auth_ok or cache) */
    bool has_kpk = resp->has_kyber_pk;
    uint8_t server_kyber_pk[NODUS_KYBER_PK_BYTES];
    if (has_kpk) {
        memcpy(server_kyber_pk, resp->kyber_pk, NODUS_KYBER_PK_BYTES);

        /* Verify server's Kyber PK signature (MITM protection).
         * Server signs (kyber_pk || nonce) with its Dilithium5 key. */
        if (resp->has_kpk_sig && resp->has_server_pk) {
            uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
            memcpy(sign_data, resp->kyber_pk, NODUS_KYBER_PK_BYTES);
            memcpy(sign_data + NODUS_KYBER_PK_BYTES, auth_nonce, NODUS_NONCE_LEN);

            if (nodus_verify(&resp->kpk_sig, sign_data, sizeof(sign_data),
                              &resp->server_pk) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Auth: ⚠ Kyber PK signature INVALID — possible MITM!");
                free_pending(client, req);
                free(buf);
                return -1;
            }
            QGP_LOG_INFO(LOG_TAG, "Auth: server Kyber PK signature verified ✓");

            /* Cache server's Dilithium PK for TOFU */
            client->server_dil_pk = resp->server_pk;
            client->has_server_dil_pk = true;
        } else {
            QGP_LOG_WARN(LOG_TAG, "Auth: server did not sign Kyber PK (legacy server)");
        }
    } else if (client->has_cached_server_kyber) {
        /* Reconnect: server didn't send kpk (old proto?) but we have cache */
        memcpy(server_kyber_pk, client->cached_server_kyber_pk, NODUS_KYBER_PK_BYTES);
        has_kpk = true;
        QGP_LOG_INFO(LOG_TAG, "Auth: using cached server Kyber pubkey");
    }

    free_pending(client, req);

    if (has_kpk) {
        QGP_LOG_INFO(LOG_TAG, "Auth: server supports channel encryption, initiating Kyber handshake");

        /* Encapsulate: shared_secret = Kyber_encap(ct, server_pk) */
        uint8_t ct[NODUS_KYBER_CT_BYTES];
        uint8_t shared_secret[NODUS_KYBER_SS_BYTES];
        if (qgp_kem1024_encapsulate(ct, shared_secret, server_kyber_pk) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: Kyber encapsulation failed");
            free(buf);
            return -1;
        }

        /* Generate client nonce */
        uint8_t nonce_c[NODUS_NONCE_LEN];
        nodus_random(nonce_c, NODUS_NONCE_LEN);

        /* Send KEY_INIT */
        len = 0;
        txn = atomic_fetch_add(&client->next_txn, 1);
        req = alloc_pending(client, txn);
        if (!req) {
            qgp_secure_memzero(shared_secret, sizeof(shared_secret));
            free(buf);
            return -1;
        }

        nodus_t2_key_init(txn, ct, nonce_c, buf, CLIENT_BUF_SIZE, &len);
        if (send_request(client, buf, len) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: KEY_INIT send failed");
            qgp_secure_memzero(shared_secret, sizeof(shared_secret));
            free_pending(client, req);
            free(buf);
            return -1;
        }

        if (!wait_response(client, req, client->config.connect_timeout_ms)) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: no response to KEY_INIT");
            qgp_secure_memzero(shared_secret, sizeof(shared_secret));
            free_pending(client, req);
            free(buf);
            return -1;
        }

        resp = (nodus_tier2_msg_t *)req->response;
        if (strcmp(resp->method, "key_ack") != 0 || !resp->has_key_nonce) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: expected 'key_ack', got '%s'", resp->method);
            qgp_secure_memzero(shared_secret, sizeof(shared_secret));
            free_pending(client, req);
            free(buf);
            return -1;
        }

        /* Init channel crypto */
        if (nodus_channel_crypto_init(&client->channel_crypto, shared_secret,
                                       nonce_c, resp->key_nonce) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: channel crypto init failed");
            qgp_secure_memzero(shared_secret, sizeof(shared_secret));
            free_pending(client, req);
            free(buf);
            return -1;
        }

        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        free_pending(client, req);

        /* Attach crypto to connection */
        ((nodus_tcp_conn_t *)client->conn)->crypto = &client->channel_crypto;

        /* Cache server Kyber pubkey for reconnect */
        memcpy(client->cached_server_kyber_pk, server_kyber_pk, NODUS_KYBER_PK_BYTES);
        client->has_cached_server_kyber = true;

        QGP_LOG_INFO(LOG_TAG, "Auth: channel encrypted (Kyber1024+AES-256-GCM)");
    }

    result = 0;
    free(buf);
    return result;
}

static int resubscribe_all(nodus_client_t *client) {
    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;

    /* Fire-and-forget: send all LISTEN/CH_SUBSCRIBE requests without waiting.
     * Previous implementation blocked 2s per listener (wait_response), which
     * stalled the read thread during reconnect — notifications were delayed.
     * Server processes them async; if any fail, ping timeout will re-trigger. */

    /* Re-subscribe DHT listeners */
    for (int i = 0; i < client->listen_count; i++) {
        size_t len = 0;
        uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
        nodus_t2_listen(txn, client->token, &client->listen_keys[i],
                         buf, CLIENT_BUF_SIZE, &len);
        send_request(client, buf, len);
        /* No wait — server will send listen_ok which read thread discards
         * (no pending slot → "unknown txn" warning, harmless) */
    }

    /* Re-subscribe channels */
    for (int i = 0; i < client->ch_sub_count; i++) {
        size_t len = 0;
        uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
        nodus_t2_ch_subscribe(txn, client->token, client->ch_subs[i],
                               buf, CLIENT_BUF_SIZE, &len);
        send_request(client, buf, len);
    }

    QGP_LOG_INFO(LOG_TAG, "Re-subscribed %d listeners + %d channels (fire-and-forget)",
                 client->listen_count, client->ch_sub_count);

    free(buf);
    return 0;
}

static int try_reconnect(nodus_client_t *client) {
    if (client->state != NODUS_CLIENT_RECONNECTING) return -1;
    if (now_ms() < client->reconnect_at) return -1;

    /* Try next server in rotation */
    int start_idx = (client->server_idx + 1) % client->config.server_count;
    for (int i = 0; i < client->config.server_count; i++) {
        int idx = (start_idx + i) % client->config.server_count;
        if (do_connect_one(client, idx) == 0) {
            client->server_idx = idx;
            client->backoff_ms = client->config.reconnect_min_ms;
            return 0;
        }
    }

    /* Exponential backoff */
    client->backoff_ms *= 2;
    if (client->backoff_ms > client->config.reconnect_max_ms)
        client->backoff_ms = client->config.reconnect_max_ms;
    client->reconnect_at = now_ms() + client->backoff_ms;
    set_state(client, NODUS_CLIENT_RECONNECTING);

    return -1;
}

int nodus_client_poll(nodus_client_t *client, int timeout_ms) {
    if (!client || !client->tcp) return -1;

    /* Read thread handles all TCP reading — external callers are no-ops */
    if (atomic_load(&client->read_thread_running))
        return 0;

    pthread_mutex_lock(&client->poll_mutex);

    /* Handle reconnect */
    if (client->state == NODUS_CLIENT_RECONNECTING) {
        try_reconnect(client);
        if (client->state != NODUS_CLIENT_READY) {
            nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
            int rc = nodus_tcp_poll(tcp, timeout_ms < 100 ? timeout_ms : 100);
            pthread_mutex_unlock(&client->poll_mutex);
            return rc;
        }
    }

    if (!client->conn) {
        pthread_mutex_unlock(&client->poll_mutex);
        return 0;
    }

    nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
    int rc = nodus_tcp_poll(tcp, timeout_ms);
    pthread_mutex_unlock(&client->poll_mutex);
    return rc;
}

bool nodus_client_is_ready(const nodus_client_t *client) {
    return client && client->state == NODUS_CLIENT_READY;
}

nodus_client_state_t nodus_client_state(const nodus_client_t *client) {
    return client ? client->state : NODUS_CLIENT_DISCONNECTED;
}

void nodus_client_suspend(nodus_client_t *client) {
    if (!client) return;
    atomic_store(&client->suspended, true);
    QGP_LOG_INFO(LOG_TAG, "Suspended (app background) — closing TCP, no auto-reconnect");

    /* Gracefully close the connection — read thread stays alive but idle */
    pthread_mutex_lock(&client->poll_mutex);
    if (client->conn && client->tcp) {
        nodus_tcp_disconnect((nodus_tcp_t *)client->tcp,
                              (nodus_tcp_conn_t *)client->conn);
        client->conn = NULL;
    }
    client->state = NODUS_CLIENT_DISCONNECTED;
    pthread_mutex_unlock(&client->poll_mutex);
}

void nodus_client_resume(nodus_client_t *client) {
    if (!client) return;
    atomic_store(&client->suspended, false);
    QGP_LOG_INFO(LOG_TAG, "Resumed (app foreground) — triggering reconnect");

    if (client->state == NODUS_CLIENT_DISCONNECTED ||
        client->state == NODUS_CLIENT_RECONNECTING) {
        client->state = NODUS_CLIENT_RECONNECTING;
        client->backoff_ms = client->config.reconnect_min_ms;
        client->reconnect_at = now_ms(); /* Immediate */
    }
}

void nodus_client_force_disconnect(nodus_client_t *client) {
    if (!client) return;
    /* Signal read thread to stop */
    atomic_store(&client->read_thread_stop, true);
    /* Close socket FIRST — breaks epoll_wait so read thread exits quickly */
    if (client->conn) {
        nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
        if (conn->fd >= 0) {
#ifdef _WIN32
            shutdown(conn->fd, SD_BOTH);
            closesocket(conn->fd);
#else
            shutdown(conn->fd, SHUT_RDWR);
            close(conn->fd);
#endif
            conn->fd = -1;
        }
        client->conn = NULL;
    }
    client->state = NODUS_CLIENT_DISCONNECTED;
    /* Now join the read thread (it should exit fast since socket is closed) */
    stop_read_thread(client);
}

void nodus_client_close(nodus_client_t *client) {
    if (!client) return;

    /* Stop read thread before tearing down TCP */
    stop_read_thread(client);

    if (client->conn && client->tcp) {
        nodus_tcp_disconnect((nodus_tcp_t *)client->tcp,
                              (nodus_tcp_conn_t *)client->conn);
        client->conn = NULL;
    }

    if (client->tcp) {
        nodus_tcp_close((nodus_tcp_t *)client->tcp);
        free(client->tcp);
        client->tcp = NULL;
    }

    /* Free all pending slots */
    for (int i = 0; i < NODUS_MAX_PENDING; i++) {
        nodus_pending_t *p = &client->pending[i];
        if (p->in_use) {
            if (p->response) {
                nodus_t2_msg_free((nodus_tier2_msg_t *)p->response);
                free(p->response);
            }
            free(p->raw_response);
            p->in_use = false;
        }
    }

    pthread_mutex_destroy(&client->pending_mutex);
    pthread_mutex_destroy(&client->send_mutex);
    pthread_mutex_destroy(&client->poll_mutex);
    pthread_mutex_destroy(&client->circuits_mutex);

    client->state = NODUS_CLIENT_DISCONNECTED;
    client->listen_count = 0;
    client->ch_sub_count = 0;
    nodus_identity_clear(&client->identity);
}

/* ── DHT Operations ─────────────────────────────────────────────── */

int nodus_client_put(nodus_client_t *client,
                      const nodus_key_t *key,
                      const uint8_t *data, size_t data_len,
                      nodus_value_type_t type, uint32_t ttl,
                      uint64_t vid, uint64_t seq,
                      const nodus_sig_t *sig) {
    if (!nodus_client_is_ready(client)) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE_PUT);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_put(txn, client->token, key, data, data_len,
                      type, ttl, vid, seq, sig,
                      buf, CLIENT_BUF_SIZE_PUT, &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "PUT encode failed (data_len=%zu, buf=%d)", data_len, CLIENT_BUF_SIZE_PUT);
        free_pending(client, req); free(buf); return -1;
    }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    int rc = (resp->type == 'e') ? resp->error_code : 0;
    free_pending(client, req);
    return rc;
}

int nodus_client_get(nodus_client_t *client,
                      const nodus_key_t *key,
                      nodus_value_t **val_out) {
    if (!nodus_client_is_ready(client) || !val_out) return -1;
    *val_out = NULL;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_get(txn, client->token, key,
                  buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->value) {
        *val_out = resp->value;
        resp->value = NULL;
    } else {
        free_pending(client, req);
        return NODUS_ERR_NOT_FOUND;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_get_all(nodus_client_t *client,
                          const nodus_key_t *key,
                          nodus_value_t ***vals_out,
                          size_t *count_out) {
    if (!nodus_client_is_ready(client) || !vals_out || !count_out) return -1;
    *vals_out = NULL;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_get_all(txn, client->token, key,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->values && resp->value_count > 0) {
        /* Transfer ownership */
        *vals_out = resp->values;
        *count_out = resp->value_count;
        resp->values = NULL;
        resp->value_count = 0;
    }
    free_pending(client, req);
    return 0;
}

/* ── Batch DHT Operations ──────────────────────────────────────── */

int nodus_client_get_batch(nodus_client_t *client,
                            const nodus_key_t *keys, int key_count,
                            nodus_batch_result_t **results_out,
                            int *result_count_out) {
    if (!nodus_client_is_ready(client) || !keys || !results_out || !result_count_out)
        return -1;
    if (key_count < 1 || key_count > NODUS_MAX_BATCH_KEYS) return -1;
    *results_out = NULL;
    *result_count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_get_batch(txn, client->token, keys, key_count,
                        buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->batch_keys && resp->batch_key_count > 0) {
        int n = resp->batch_key_count;
        nodus_batch_result_t *results = calloc((size_t)n, sizeof(nodus_batch_result_t));
        if (results) {
            for (int i = 0; i < n; i++) {
                memcpy(&results[i].key, &resp->batch_keys[i], sizeof(nodus_key_t));
                results[i].vals = resp->batch_vals ? resp->batch_vals[i] : NULL;
                results[i].count = resp->batch_val_counts ? resp->batch_val_counts[i] : 0;
                /* Transfer ownership */
                if (resp->batch_vals) resp->batch_vals[i] = NULL;
                if (resp->batch_val_counts) resp->batch_val_counts[i] = 0;
            }
            *results_out = results;
            *result_count_out = n;
        }
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_count_batch(nodus_client_t *client,
                              const nodus_key_t *keys, int key_count,
                              const nodus_key_t *my_fp,
                              nodus_count_result_t **results_out,
                              int *result_count_out) {
    if (!nodus_client_is_ready(client) || !keys || !results_out || !result_count_out)
        return -1;
    if (key_count < 1 || key_count > NODUS_MAX_BATCH_KEYS) return -1;
    *results_out = NULL;
    *result_count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_count_batch(txn, client->token, keys, key_count, my_fp,
                          buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->batch_keys && resp->batch_key_count > 0) {
        int n = resp->batch_key_count;
        nodus_count_result_t *results = calloc((size_t)n, sizeof(nodus_count_result_t));
        if (results) {
            for (int i = 0; i < n; i++) {
                memcpy(&results[i].key, &resp->batch_keys[i], sizeof(nodus_key_t));
                results[i].count = resp->batch_counts ? resp->batch_counts[i] : 0;
                results[i].has_mine = resp->batch_has_mine ? resp->batch_has_mine[i] : false;
            }
            *results_out = results;
            *result_count_out = n;
        }
    }
    free_pending(client, req);
    return 0;
}

void nodus_client_free_batch_result(nodus_batch_result_t *results, int count) {
    if (!results) return;
    for (int i = 0; i < count; i++) {
        if (results[i].vals) {
            for (size_t j = 0; j < results[i].count; j++)
                nodus_value_free(results[i].vals[j]);
            free(results[i].vals);
        }
    }
    free(results);
}

void nodus_client_free_count_result(nodus_count_result_t *results, int count) {
    (void)count;
    free(results);
}

int nodus_client_listen(nodus_client_t *client, const nodus_key_t *key) {
    if (!nodus_client_is_ready(client) || !key) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_listen(txn, client->token, key,
                     buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Track subscription for re-subscribe on reconnect */
    if (client->listen_count < NODUS_CLIENT_MAX_LISTENS) {
        /* Check for duplicate */
        bool found = false;
        for (int i = 0; i < client->listen_count; i++) {
            if (nodus_key_cmp(&client->listen_keys[i], key) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            client->listen_keys[client->listen_count++] = *key;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_unlisten(nodus_client_t *client, const nodus_key_t *key) {
    if (!nodus_client_is_ready(client) || !key) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_unlisten(txn, client->token, key,
                       buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Remove from tracking */
    for (int i = 0; i < client->listen_count; i++) {
        if (nodus_key_cmp(&client->listen_keys[i], key) == 0) {
            client->listen_keys[i] = client->listen_keys[--client->listen_count];
            break;
        }
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_get_servers(nodus_client_t *client,
                              nodus_server_endpoint_t *endpoints_out,
                              int max_count, int *count_out) {
    if (!nodus_client_is_ready(client) || !endpoints_out || !count_out) return -1;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_servers(txn, client->token,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    int n = resp->server_count < max_count ? resp->server_count : max_count;
    for (int i = 0; i < n; i++) {
        memset(&endpoints_out[i], 0, sizeof(endpoints_out[i]));
        strncpy(endpoints_out[i].ip, resp->servers[i].ip,
                sizeof(endpoints_out[i].ip) - 1);
        endpoints_out[i].port = resp->servers[i].tcp_port;
    }
    *count_out = n;
    free_pending(client, req);
    return 0;
}

/* ── Channel Operations ─────────────────────────────────────────── */

int nodus_client_ch_create(nodus_client_t *client,
                            const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_create(txn, client->token, uuid, false,
                        NULL, NULL, false,
                        buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_get(nodus_client_t *client,
                         const uint8_t uuid[NODUS_UUID_BYTES],
                         nodus_channel_meta_t *meta_out) {
    if (!nodus_client_is_ready(client) || !uuid || !meta_out) return -1;
    memset(meta_out, 0, sizeof(*meta_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_get(txn, client->token, uuid,
                     buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Response uses ch_list_ok format with count=1 */
    if (resp->ch_metas && resp->ch_meta_count > 0) {
        *meta_out = resp->ch_metas[0];
        free(resp->ch_metas);
        resp->ch_metas = NULL;
        resp->ch_meta_count = 0;
    } else {
        free_pending(client, req);
        return NODUS_ERR_NOT_FOUND;
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_ch_list(nodus_client_t *client,
                          int offset, int limit,
                          nodus_channel_meta_t **metas_out,
                          size_t *count_out) {
    if (!nodus_client_is_ready(client) || !metas_out || !count_out) return -1;
    *metas_out = NULL;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_list(txn, client->token, offset, limit,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Transfer ownership of metas array to caller */
    if (resp->ch_metas && resp->ch_meta_count > 0) {
        *metas_out = resp->ch_metas;
        *count_out = resp->ch_meta_count;
        resp->ch_metas = NULL;  /* Prevent msg_free from freeing */
        resp->ch_meta_count = 0;
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_ch_search(nodus_client_t *client,
                            const char *query,
                            int offset, int limit,
                            nodus_channel_meta_t **metas_out,
                            size_t *count_out) {
    if (!nodus_client_is_ready(client) || !query || !metas_out || !count_out) return -1;
    *metas_out = NULL;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_search(txn, client->token, query, offset, limit,
                        buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Transfer ownership of metas array to caller */
    if (resp->ch_metas && resp->ch_meta_count > 0) {
        *metas_out = resp->ch_metas;
        *count_out = resp->ch_meta_count;
        resp->ch_metas = NULL;
        resp->ch_meta_count = 0;
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_ch_post(nodus_client_t *client,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const uint8_t post_uuid[NODUS_UUID_BYTES],
                          const uint8_t *body, size_t body_len,
                          uint64_t timestamp, const nodus_sig_t *sig,
                          uint64_t *received_at_out) {
    if (!nodus_client_is_ready(client) || !ch_uuid || !body) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_post(txn, client->token, ch_uuid, post_uuid,
                      body, body_len, timestamp, sig,
                      buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (received_at_out) *received_at_out = resp->ch_received_at;
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_get_posts(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES],
                               uint64_t since_received_at, int max_count,
                               nodus_channel_post_t **posts_out,
                               size_t *count_out) {
    if (!nodus_client_is_ready(client) || !uuid || !posts_out || !count_out)
        return -1;
    *posts_out = NULL;
    *count_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_get_posts(txn, client->token, uuid, since_received_at, max_count,
                           buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    if (resp->ch_posts && resp->ch_post_count > 0) {
        /* Transfer ownership */
        *posts_out = resp->ch_posts;
        *count_out = resp->ch_post_count;
        resp->ch_posts = NULL;
        resp->ch_post_count = 0;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_subscribe(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_subscribe(txn, client->token, uuid,
                           buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Track for re-subscribe on reconnect */
    if (client->ch_sub_count < NODUS_CLIENT_MAX_CH_SUBS) {
        bool found = false;
        for (int i = 0; i < client->ch_sub_count; i++) {
            if (memcmp(client->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            memcpy(client->ch_subs[client->ch_sub_count], uuid, NODUS_UUID_BYTES);
            client->ch_sub_count++;
        }
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_ch_unsubscribe(nodus_client_t *client,
                                 const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_client_is_ready(client) || !uuid) return -1;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_unsubscribe(txn, client->token, uuid,
                              buf, CLIENT_BUF_SIZE, &len);
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Remove from tracking */
    for (int i = 0; i < client->ch_sub_count; i++) {
        if (memcmp(client->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
            memcpy(client->ch_subs[i], client->ch_subs[--client->ch_sub_count],
                   NODUS_UUID_BYTES);
            break;
        }
    }
    free_pending(client, req);
    return 0;
}

/* ── Utility ────────────────────────────────────────────────────── */

const char *nodus_client_fingerprint(const nodus_client_t *client) {
    return client ? client->identity.fingerprint : NULL;
}

void nodus_client_free_posts(nodus_channel_post_t *posts, size_t count) {
    if (!posts) return;
    for (size_t i = 0; i < count; i++)
        free(posts[i].body);
    free(posts);
}

/* ── Presence Operations ─────────────────────────────────────────── */

int nodus_client_presence_query(nodus_client_t *client,
                                  const nodus_key_t *fps, int count,
                                  nodus_presence_result_t *result) {
    if (!nodus_client_is_ready(client) || !fps || !result || count <= 0)
        return -1;
    if (count > NODUS_PRESENCE_MAX_QUERY)
        count = NODUS_PRESENCE_MAX_QUERY;

    memset(result, 0, sizeof(*result));
    result->total_queried = count;

    /* Encode pq request using T2 encoder */
    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t buf_len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_presence_query(txn, client->token,
                                  fps, count, buf, CLIENT_BUF_SIZE, &buf_len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }

    if (send_request(client, buf, buf_len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Parse result from T2-decoded fields */
    if (resp->pq_fps && resp->pq_count > 0) {
        result->online_count = resp->pq_count;
        result->entries = calloc((size_t)resp->pq_count,
                                   sizeof(nodus_presence_entry_result_t));
        if (result->entries) {
            for (int i = 0; i < resp->pq_count; i++) {
                result->entries[i].fp = resp->pq_fps[i];
                result->entries[i].online = resp->pq_online ? resp->pq_online[i] : true;
                result->entries[i].peer_index = resp->pq_peers ? resp->pq_peers[i] : 0;
                result->entries[i].last_seen = resp->pq_last_seen ? resp->pq_last_seen[i] : 0;
            }
        }
    }

    /* Parse offline-seen entries */
    if (resp->os_fps && resp->os_count > 0) {
        result->offline_seen_count = resp->os_count;
        result->offline_seen = calloc((size_t)resp->os_count,
                                        sizeof(nodus_presence_entry_result_t));
        if (result->offline_seen) {
            for (int i = 0; i < resp->os_count; i++) {
                result->offline_seen[i].fp = resp->os_fps[i];
                result->offline_seen[i].online = false;
                result->offline_seen[i].last_seen = resp->os_last_seen ? resp->os_last_seen[i] : 0;
            }
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_presence_result(nodus_presence_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->online_count = 0;
    free(result->offline_seen);
    result->offline_seen = NULL;
    result->offline_seen_count = 0;
}

/* ── Media Operations ──────────────────────────────────────────────── */

int nodus_client_media_put(nodus_client_t *client,
                           const uint8_t content_hash[64],
                           uint32_t chunk_index, uint32_t chunk_count,
                           uint64_t total_size, uint8_t media_type,
                           bool encrypted, uint32_t ttl,
                           const uint8_t *data, size_t data_len,
                           const nodus_sig_t *sig,
                           bool *complete_out,
                           nodus_media_progress_cb progress_cb,
                           void *progress_user_data) {
    if (!nodus_client_is_ready(client)) {
        QGP_LOG_ERROR(LOG_TAG, "media_put: client not ready");
        return -1;
    }
    if (!content_hash || !data || !sig) {
        QGP_LOG_ERROR(LOG_TAG, "media_put: NULL param (hash=%p, data=%p, sig=%p)",
                      (void*)content_hash, (void*)data, (void*)sig);
        return -1;
    }
    if (complete_out) *complete_out = false;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE_PUT);
    if (!buf) {
        QGP_LOG_ERROR(LOG_TAG, "media_put: malloc failed (%d bytes)", CLIENT_BUF_SIZE_PUT);
        return -1;
    }
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) {
        QGP_LOG_ERROR(LOG_TAG, "media_put: alloc_pending failed (all slots busy)");
        free(buf); return -1;
    }

    if (nodus_t2_media_put(txn, client->token, content_hash,
                           chunk_index, chunk_count, total_size,
                           media_type, ttl, encrypted,
                           data, data_len, sig,
                           buf, CLIENT_BUF_SIZE_PUT, &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "media_put encode failed (chunk=%u, data_len=%zu)",
                      chunk_index, data_len);
        free_pending(client, req); free(buf); return -1;
    }
    QGP_LOG_DEBUG(LOG_TAG, "media_put: encoded %zu bytes for chunk %u/%u",
                  len, chunk_index, chunk_count);
    if (send_request_progress(client, buf, len,
                              (nodus_tcp_progress_cb)progress_cb,
                              progress_user_data) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "media_put: send failed (chunk=%u, encoded_len=%zu)",
                      chunk_index, len);
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    /* Dynamic timeout: base 30s + ~20KB/s for data payload */
    int media_timeout = client->config.request_timeout_ms;
    if (media_timeout < 30000) media_timeout = 30000;
    media_timeout += (int)(data_len / 50);  /* +20ms per KB */
    QGP_LOG_DEBUG(LOG_TAG, "media_put: waiting for response (timeout=%dms, data_len=%zu)",
                  media_timeout, data_len);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, media_timeout)) {
        QGP_LOG_ERROR(LOG_TAG, "media_put: client timeout after %dms (chunk=%u)",
                      media_timeout, chunk_index);
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code;
        QGP_LOG_ERROR(LOG_TAG, "media_put: server error %d for chunk %u", rc, chunk_index);
        free_pending(client, req); return rc;
    }
    if (complete_out) *complete_out = resp->media_complete;
    free_pending(client, req);
    return 0;
}

int nodus_client_media_get_meta(nodus_client_t *client,
                                const uint8_t content_hash[64],
                                nodus_media_meta_t *meta_out) {
    if (!nodus_client_is_ready(client) || !content_hash || !meta_out)
        return -1;
    memset(meta_out, 0, sizeof(*meta_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_media_get_meta(txn, client->token, content_hash,
                                buf, CLIENT_BUF_SIZE, &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "media_get_meta encode failed");
        free_pending(client, req); free(buf); return -1;
    }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code;
        free_pending(client, req); return rc;
    }

    memcpy(meta_out->content_hash, resp->media_hash, 64);
    meta_out->media_type   = resp->media_type;
    meta_out->total_size   = resp->media_total_size;
    meta_out->chunk_count  = resp->media_chunk_count;
    meta_out->encrypted    = resp->media_encrypted;
    meta_out->ttl          = resp->ttl;
    meta_out->complete     = resp->media_complete;

    free_pending(client, req);
    return 0;
}

int nodus_client_media_get_chunk(nodus_client_t *client,
                                 const uint8_t content_hash[64],
                                 uint32_t chunk_index,
                                 uint8_t **data_out, size_t *data_len_out) {
    if (!nodus_client_is_ready(client) || !content_hash || !data_out || !data_len_out)
        return -1;
    *data_out = NULL;
    *data_len_out = 0;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_media_get_chunk(txn, client->token, content_hash, chunk_index,
                                 buf, CLIENT_BUF_SIZE, &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "media_get_chunk encode failed (chunk=%u)", chunk_index);
        free_pending(client, req); free(buf); return -1;
    }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code;
        free_pending(client, req); return rc;
    }

    /* Copy data before freeing response (resp->data freed by nodus_t2_msg_free) */
    if (resp->data && resp->data_len > 0) {
        *data_out = malloc(resp->data_len);
        if (!*data_out) { free_pending(client, req); return -1; }
        memcpy(*data_out, resp->data, resp->data_len);
        *data_len_out = resp->data_len;
    } else {
        free_pending(client, req);
        return NODUS_ERR_NOT_FOUND;
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_media_exists(nodus_client_t *client,
                              const uint8_t content_hash[64],
                              bool *exists_out) {
    if (!client || !content_hash || !exists_out) return -1;
    *exists_out = false;

    nodus_media_meta_t meta;
    int rc = nodus_client_media_get_meta(client, content_hash, &meta);
    if (rc == 0) {
        *exists_out = true;
        return 0;
    }
    if (rc == NODUS_ERR_NOT_FOUND) {
        *exists_out = false;
        return 0;
    }
    return rc;
}

/* ── DNAC Operations ─────────────────────────────────────────────── */

/**
 * Helper: find the "r" response map in raw CBOR payload.
 * On success, decoder is positioned at first entry of "r" map.
 * Returns 0 on success, -1 if "r" not found or not a map.
 */
static int find_response_map(const uint8_t *raw, size_t raw_len,
                              cbor_decoder_t *dec, size_t *map_count) {
    cbor_decoder_init(dec, raw, raw_len);
    cbor_item_t top = cbor_decode_next(dec);
    if (top.type != CBOR_ITEM_MAP) return -1;

    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type == CBOR_ITEM_TSTR &&
            key.tstr.len == 1 && key.tstr.ptr[0] == 'r') {
            cbor_item_t rmap = cbor_decode_next(dec);
            if (rmap.type != CBOR_ITEM_MAP) return -1;
            *map_count = rmap.count;
            return 0;
        }
        cbor_decode_skip(dec);
    }
    return -1;
}

/** Helper: encode DNAC query header + token + args map start */
static void enc_dnac_query(cbor_encoder_t *enc, uint32_t txn,
                            const uint8_t *token, const char *method,
                            size_t args_count) {
    cbor_encode_map(enc, 5);  /* t, y, q, tok, a */
    cbor_encode_cstr(enc, "t");   cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y");   cbor_encode_cstr(enc, "q");
    cbor_encode_cstr(enc, "q");   cbor_encode_cstr(enc, method);
    cbor_encode_cstr(enc, "tok"); cbor_encode_bstr(enc, token, NODUS_SESSION_TOKEN_LEN);
    cbor_encode_cstr(enc, "a");   cbor_encode_map(enc, args_count);
}

int nodus_client_dnac_spend(nodus_client_t *client,
                              const uint8_t *tx_hash,
                              const uint8_t *tx_data, uint32_t tx_len,
                              const nodus_pubkey_t *sender_pk,
                              const nodus_sig_t *sender_sig,
                              uint64_t fee,
                              nodus_dnac_spend_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !tx_data ||
        !sender_pk || !sender_sig || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_spend", 5);

    cbor_encode_cstr(&enc, "tx");
    cbor_encode_bstr(&enc, tx_data, tx_len);
    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(&enc, "pk");
    cbor_encode_bstr(&enc, sender_pk->bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sender_sig->bytes, NODUS_SIG_BYTES);
    cbor_encode_cstr(&enc, "fee");
    cbor_encode_uint(&enc, fee);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    /* BFT consensus can take up to 30s */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 30000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Decode spend result from raw response */
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "status", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->status = (nodus_dnac_status_t)v.uint_val;
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "wid", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(result_out->witness_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "wpk", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_PK_BYTES)
                memcpy(result_out->witness_pubkey, v.bstr.ptr, NODUS_PK_BYTES);
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "wsig", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_SIG_BYTES)
                memcpy(result_out->signature, v.bstr.ptr, NODUS_SIG_BYTES);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_nullifier(nodus_client_t *client,
                                  const uint8_t *nullifier,
                                  nodus_dnac_nullifier_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !nullifier || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_nullifier", 1);

    cbor_encode_cstr(&enc, "nullifier");
    cbor_encode_bstr(&enc, nullifier, NODUS_T3_NULLIFIER_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "spent", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->is_spent = v.bool_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_ledger(nodus_client_t *client,
                               const uint8_t *tx_hash,
                               nodus_dnac_ledger_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_ledger", 1);

    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->found = v.bool_val;
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "seq", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->sequence = v.uint_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "hash", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "type", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_type = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "epoch", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->epoch = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "nc", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->nullifier_count = v.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_supply(nodus_client_t *client,
                               nodus_dnac_supply_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_supply", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "genesis", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->genesis_supply = v.uint_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "burned", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_burned = v.uint_val;
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "current", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->current_supply = v.uint_val;
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "last_seq", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->last_sequence = v.uint_val;
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "chain_id", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 32)
                memcpy(result_out->chain_id, v.bstr.ptr, 32);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_utxo(nodus_client_t *client,
                             const char *owner,
                             int max_results,
                             nodus_dnac_utxo_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !owner || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));
    if (max_results <= 0) max_results = NODUS_DNAC_MAX_UTXO_RESULTS;
    if (max_results > NODUS_DNAC_MAX_UTXO_RESULTS)
        max_results = NODUS_DNAC_MAX_UTXO_RESULTS;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_utxo", 2);

    cbor_encode_cstr(&enc, "owner");
    cbor_encode_cstr(&enc, owner);
    cbor_encode_cstr(&enc, "max");
    cbor_encode_uint(&enc, (uint64_t)max_results);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    int count = 0;
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                count = (int)v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "utxos", 5) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            if (arr.count > 0) {
                result_out->entries = calloc(arr.count,
                                              sizeof(nodus_dnac_utxo_entry_t));
                if (!result_out->entries) { free_pending(client, req); return NODUS_ERR_INTERNAL_ERROR; }
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;

                nodus_dnac_utxo_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (ek.tstr.len == 1 && ek.tstr.ptr[0] == 'n') {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_NULLIFIER_LEN)
                            memcpy(e->nullifier, v.bstr.ptr,
                                   NODUS_T3_NULLIFIER_LEN);
                    } else if (ek.tstr.len == 5 &&
                               memcmp(ek.tstr.ptr, "owner", 5) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(e->owner) - 1 ?
                                        v.tstr.len : sizeof(e->owner) - 1;
                            memcpy(e->owner, v.tstr.ptr, cl);
                            e->owner[cl] = '\0';
                        }
                    } else if (ek.tstr.len == 6 &&
                               memcmp(ek.tstr.ptr, "amount", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->amount = v.uint_val;
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(e->tx_hash, v.bstr.ptr,
                                   NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 3 &&
                               memcmp(ek.tstr.ptr, "idx", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->output_index = (uint32_t)v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "bh", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->block_height = v.uint_val;
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    (void)count;  /* Server count for cross-check, not used */
    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_ledger_range(nodus_client_t *client,
                                     uint64_t from_seq, uint64_t to_seq,
                                     nodus_dnac_range_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_ledger_range", 2);

    cbor_encode_cstr(&enc, "from");
    cbor_encode_uint(&enc, from_seq);
    cbor_encode_cstr(&enc, "to");
    cbor_encode_uint(&enc, to_seq);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "total", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_entries = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->count = (int)v.uint_val;
        } else if (key.tstr.len == 7 &&
                   memcmp(key.tstr.ptr, "entries", 7) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            if (arr.count > 0) {
                result_out->entries = calloc(arr.count,
                                              sizeof(nodus_dnac_range_entry_t));
                if (!result_out->entries) { free_pending(client, req); return NODUS_ERR_INTERNAL_ERROR; }
                result_out->count = 0;
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;

                nodus_dnac_range_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (ek.tstr.len == 3 &&
                        memcmp(ek.tstr.ptr, "seq", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->sequence = v.uint_val;
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(e->tx_hash, v.bstr.ptr,
                                   NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "type", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->tx_type = (uint8_t)v.uint_val;
                    } else if (ek.tstr.len == 5 &&
                               memcmp(ek.tstr.ptr, "epoch", 5) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->epoch = v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "ts", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->timestamp = v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "nc", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->nullifier_count = v.uint_val;
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_roster(nodus_client_t *client,
                               nodus_dnac_roster_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_roster", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "version", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->version = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 5 &&
                   memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->count = (int)v.uint_val;
        } else if (key.tstr.len == 9 &&
                   memcmp(key.tstr.ptr, "witnesses", 9) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            result_out->count = 0;
            for (size_t j = 0;
                 j < arr.count && result_out->count < NODUS_T3_MAX_WITNESSES;
                 j++) {
                cbor_item_t wmap = cbor_decode_next(&dec);
                if (wmap.type != CBOR_ITEM_MAP) continue;

                nodus_dnac_roster_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < wmap.count; k++) {
                    cbor_item_t wk = cbor_decode_next(&dec);
                    if (wk.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (wk.tstr.len == 3 &&
                        memcmp(wk.tstr.ptr, "wid", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(e->witness_id, v.bstr.ptr,
                                   NODUS_T3_WITNESS_ID_LEN);
                    } else if (wk.tstr.len == 2 &&
                               memcmp(wk.tstr.ptr, "pk", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_PK_BYTES)
                            memcpy(e->pubkey, v.bstr.ptr, NODUS_PK_BYTES);
                    } else if (wk.tstr.len == 4 &&
                               memcmp(wk.tstr.ptr, "addr", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(e->address) - 1 ?
                                        v.tstr.len : sizeof(e->address) - 1;
                            memcpy(e->address, v.tstr.ptr, cl);
                            e->address[cl] = '\0';
                        }
                    } else if (wk.tstr.len == 6 &&
                               memcmp(wk.tstr.ptr, "active", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BOOL)
                            e->active = v.bool_val;
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_utxo_result(nodus_dnac_utxo_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
}

void nodus_client_free_range_result(nodus_dnac_range_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
}

/* ── TX Query (v0.10.0 hub/spoke) ───────────────────────────────── */

int nodus_client_dnac_tx(nodus_client_t *client,
                           const uint8_t *tx_hash,
                           nodus_dnac_tx_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !tx_hash || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_tx", 1);

    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->found = v.bool_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "hash", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "type", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_type = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "tx", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len > 0) {
                result_out->tx_data = malloc(v.bstr.len);
                if (result_out->tx_data) {
                    memcpy(result_out->tx_data, v.bstr.ptr, v.bstr.len);
                    result_out->tx_len = (uint32_t)v.bstr.len;
                }
            }
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "len", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            /* tx_len already set from blob, this is informational */
            (void)v;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "bh", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->block_height = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_tx_result(nodus_dnac_tx_result_t *result) {
    if (!result) return;
    free(result->tx_data);
    result->tx_data = NULL;
    result->tx_len = 0;
}

/* ── Block Query (v0.10.0 hub/spoke) ────────────────────────────── */

int nodus_client_dnac_block(nodus_client_t *client,
                              uint64_t height,
                              nodus_dnac_block_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_block", 1);

    cbor_encode_cstr(&enc, "height");
    cbor_encode_uint(&enc, height);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL)
                result_out->found = v.bool_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "height", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->height = v.uint_val;
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "hash", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "type", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_type = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "proposer", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(result_out->proposer_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

/* ── Block Range Query (v0.10.0 hub/spoke) ──────────────────────── */

int nodus_client_dnac_block_range(nodus_client_t *client,
                                    uint64_t from_height, uint64_t to_height,
                                    nodus_dnac_block_range_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_block_range", 2);

    cbor_encode_cstr(&enc, "from");
    cbor_encode_uint(&enc, from_height);
    cbor_encode_cstr(&enc, "to");
    cbor_encode_uint(&enc, to_height);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 10000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "total", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_blocks = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->count = (int)v.uint_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "blocks", 6) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            if (arr.count > 0) {
                result_out->blocks = calloc(arr.count,
                                              sizeof(nodus_dnac_block_result_t));
                if (!result_out->blocks) continue;
            }

            result_out->count = 0;
            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) {
                    cbor_decode_skip(&dec);
                    continue;
                }

                nodus_dnac_block_result_t *b =
                    &result_out->blocks[result_out->count];
                b->found = true;

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec);
                        continue;
                    }

                    if (ek.tstr.len == 6 && memcmp(ek.tstr.ptr, "height", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) b->height = v.uint_val;
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(b->tx_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "type", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) b->tx_type = (uint8_t)v.uint_val;
                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "ts", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) b->timestamp = v.uint_val;
                    } else if (ek.tstr.len == 8 && memcmp(ek.tstr.ptr, "proposer", 8) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(b->proposer_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
                    } else {
                        cbor_decode_skip(&dec);
                    }
                }
                result_out->count++;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_block_range_result(nodus_dnac_block_range_result_t *result) {
    if (!result) return;
    free(result->blocks);
    result->blocks = NULL;
    result->count = 0;
}

/* ── Channel Connection (TCP 4003) Implementation ──────────────── */

#define LOG_TAG_CH  "NODUS_CH_CONN"
#define CH_CONN_BUF_SIZE  (256 * 1024)
#define CH_CONN_CONNECT_TIMEOUT  5000
#define CH_CONN_REQUEST_TIMEOUT  10000

/* ── ch_conn helpers ───────────────────────────────────────────── */

static nodus_ch_pending_t *ch_conn_alloc_pending(nodus_ch_conn_t *ch, uint32_t txn) {
    const int max_retries = 5;
    int backoff_ms = 10;

    for (int attempt = 0; attempt <= max_retries; attempt++) {
        pthread_mutex_lock(&ch->pending_mutex);
        for (int i = 0; i < NODUS_CH_MAX_PENDING; i++) {
            if (!ch->pending[i].in_use) {
                nodus_ch_pending_t *p = &ch->pending[i];
                memset(p, 0, sizeof(*p));
                p->txn = txn;
                p->response = calloc(1, sizeof(nodus_tier2_msg_t));
                p->in_use = true;
                pthread_mutex_unlock(&ch->pending_mutex);
                return p;
            }
        }
        pthread_mutex_unlock(&ch->pending_mutex);

        if (attempt < max_retries) {
            QGP_LOG_WARN(LOG_TAG_CH, "All %d pending slots busy, retry %d/%d in %dms",
                         NODUS_CH_MAX_PENDING, attempt + 1, max_retries, backoff_ms);
            struct timespec ts = { .tv_sec = 0, .tv_nsec = backoff_ms * 1000000L };
            nanosleep(&ts, NULL);
            backoff_ms *= 2;
        }
    }

    QGP_LOG_ERROR(LOG_TAG_CH, "No pending slots available (max %d)", NODUS_CH_MAX_PENDING);
    return NULL;
}

static void ch_conn_free_pending(nodus_ch_conn_t *ch, nodus_ch_pending_t *p) {
    if (!p) return;
    pthread_mutex_lock(&ch->pending_mutex);
    if (p->response) {
        nodus_t2_msg_free((nodus_tier2_msg_t *)p->response);
        free(p->response);
        p->response = NULL;
    }
    p->in_use = false;
    pthread_mutex_unlock(&ch->pending_mutex);
}

static int ch_conn_send(nodus_ch_conn_t *ch, const uint8_t *payload, size_t len) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)ch->conn;
    if (!conn) return -1;
    pthread_mutex_lock(&ch->send_mutex);
    int rc = nodus_tcp_send(conn, payload, len);
    pthread_mutex_unlock(&ch->send_mutex);
    return rc;
}

static bool ch_conn_wait_response(nodus_ch_conn_t *ch, nodus_ch_pending_t *req, int timeout_ms) {
    int elapsed = 0;

    while (!atomic_load(&req->ready) && elapsed < timeout_ms) {
        if (!ch->conn)
            return false;

        if (atomic_load(&ch->read_thread_running) &&
            !pthread_equal(pthread_self(), ch->read_thread)) {
            /* Read thread handles TCP — just wait for ready flag */
            sleep_ms(10);
            elapsed += 10;
        } else {
            /* We ARE the read thread (auth path), or no thread — poll directly */
            nodus_tcp_t *tcp = (nodus_tcp_t *)ch->tcp;
            if (tcp) nodus_tcp_poll(tcp, 50);
            elapsed += 50;
        }
    }
    return atomic_load(&req->ready);
}

/* ── ch_conn TCP callbacks ─────────────────────────────────────── */

static void ch_conn_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                              size_t len, void *ctx) {
    (void)conn;
    nodus_ch_conn_t *ch = (nodus_ch_conn_t *)ctx;

    nodus_tier2_msg_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    if (nodus_t2_decode(payload, len, &tmp) != 0)
        return;

    /* Push notification: channel post notify */
    if (strcmp(tmp.method, "ch_ntf") == 0) {
        if (ch->on_ch_post) {
            nodus_channel_post_t post;
            memset(&post, 0, sizeof(post));
            memcpy(post.channel_uuid, tmp.channel_uuid, NODUS_UUID_BYTES);
            memcpy(post.post_uuid, tmp.post_uuid_ch, NODUS_UUID_BYTES);
            post.author_fp = tmp.fp;
            post.timestamp = tmp.ch_timestamp;
            post.received_at = tmp.ch_received_at;
            post.signature = tmp.sig;
            post.body = (char *)tmp.data;
            post.body_len = tmp.data_len;
            ch->on_ch_post(tmp.channel_uuid, &post, ch->cb_data);
        }
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Push notification: ring changed — client should reconnect */
    if (strcmp(tmp.method, "ch_ring") == 0) {
        if (ch->on_ring_changed) {
            ch->on_ring_changed(tmp.channel_uuid, tmp.ring_version, ch->ring_changed_data);
        }
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Find pending slot by txn ID */
    pthread_mutex_lock(&ch->pending_mutex);
    nodus_ch_pending_t *slot = NULL;
    for (int i = 0; i < NODUS_CH_MAX_PENDING; i++) {
        if (ch->pending[i].in_use && ch->pending[i].txn == tmp.txn_id) {
            slot = &ch->pending[i];
            break;
        }
    }
    if (!slot) {
        pthread_mutex_unlock(&ch->pending_mutex);
        QGP_LOG_WARN(LOG_TAG_CH, "Response for unknown txn %u", tmp.txn_id);
        nodus_t2_msg_free(&tmp);
        return;
    }

    /* Move decoded response into slot */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)slot->response;
    nodus_t2_msg_free(resp);
    *resp = tmp;
    atomic_store(&slot->ready, true);
    pthread_mutex_unlock(&ch->pending_mutex);
}

static void ch_conn_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn;
    nodus_ch_conn_t *ch = (nodus_ch_conn_t *)ctx;
    ch->conn = NULL;
    /* If we had subscriptions, enter reconnecting state to auto-recover */
    if (ch->ch_sub_count > 0 && !atomic_load(&ch->read_thread_stop)) {
        ch->backoff_ms = 2000;  /* Initial 2s backoff */
        ch->reconnect_at = now_ms() + ch->backoff_ms;
        ch->state = NODUS_CH_RECONNECTING;
        QGP_LOG_WARN(LOG_TAG_CH, "Disconnected from %s:%d — will reconnect in %ums",
                     ch->host, ch->port, ch->backoff_ms);
    } else {
        ch->state = NODUS_CH_DISCONNECTED;
        QGP_LOG_WARN(LOG_TAG_CH, "Disconnected from %s:%d", ch->host, ch->port);
    }
}

static void ch_conn_on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
}

/* Forward declaration for reconnect */
static int ch_conn_do_auth(nodus_ch_conn_t *ch);

/* ── ch_conn reconnect ─────────────────────────────────────────── */

#define CH_CONN_RECONNECT_MIN_MS  2000
#define CH_CONN_RECONNECT_MAX_MS  30000

/**
 * Re-subscribe all tracked channel subscriptions after reconnect.
 * Fire-and-forget (same pattern as main client's resubscribe_all).
 */
static int ch_conn_resubscribe_all(nodus_ch_conn_t *ch) {
    if (ch->ch_sub_count == 0) return 0;

    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;

    for (int i = 0; i < ch->ch_sub_count; i++) {
        size_t len = 0;
        uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
        nodus_t2_ch_subscribe(txn, ch->token, ch->ch_subs[i],
                               buf, CH_CONN_BUF_SIZE, &len);
        ch_conn_send(ch, buf, len);
    }

    QGP_LOG_INFO(LOG_TAG_CH, "Re-subscribed %d channel(s) after reconnect",
                 ch->ch_sub_count);
    free(buf);
    return 0;
}

/**
 * Attempt to reconnect a channel connection.
 * Called from read thread when in RECONNECTING state.
 * @return 0 on success, -1 on failure (will retry with backoff)
 */
static int ch_conn_try_reconnect(nodus_ch_conn_t *ch) {
    if (ch->state != NODUS_CH_RECONNECTING) return -1;
    if (now_ms() < ch->reconnect_at) return -1;

    nodus_tcp_t *tcp = (nodus_tcp_t *)ch->tcp;
    if (!tcp) return -1;

    QGP_LOG_INFO(LOG_TAG_CH, "Reconnecting to %s:%d ...", ch->host, ch->port);
    ch->state = NODUS_CH_CONNECTING;

    nodus_tcp_conn_t *conn = nodus_tcp_connect(tcp, ch->host, ch->port);
    if (!conn) {
        QGP_LOG_WARN(LOG_TAG_CH, "Reconnect TCP failed to %s:%d", ch->host, ch->port);
        goto fail;
    }
    ch->conn = conn;

    /* Wait for TCP connection */
    int elapsed = 0;
    while (ch->conn && conn->state == NODUS_CONN_CONNECTING &&
           elapsed < CH_CONN_CONNECT_TIMEOUT) {
        nodus_tcp_poll(tcp, 50);
        elapsed += 50;
        conn = (nodus_tcp_conn_t *)ch->conn;
        if (!conn) break;
    }

    if (!ch->conn || conn == NULL || conn->state != NODUS_CONN_CONNECTED) {
        QGP_LOG_WARN(LOG_TAG_CH, "Reconnect handshake failed to %s:%d", ch->host, ch->port);
        if (ch->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)ch->conn);
            ch->conn = NULL;
        }
        goto fail;
    }

    /* Authenticate */
    ch->state = NODUS_CH_AUTHENTICATING;
    if (ch_conn_do_auth(ch) != 0) {
        QGP_LOG_WARN(LOG_TAG_CH, "Reconnect auth failed to %s:%d", ch->host, ch->port);
        if (ch->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)ch->conn);
            ch->conn = NULL;
        }
        goto fail;
    }

    ch->state = NODUS_CH_READY;
    ch->backoff_ms = CH_CONN_RECONNECT_MIN_MS;

    /* Re-subscribe all tracked channels */
    ch_conn_resubscribe_all(ch);

    QGP_LOG_INFO(LOG_TAG_CH, "Reconnected to %s:%d successfully", ch->host, ch->port);
    return 0;

fail:
    /* Exponential backoff */
    ch->backoff_ms *= 2;
    if (ch->backoff_ms > CH_CONN_RECONNECT_MAX_MS)
        ch->backoff_ms = CH_CONN_RECONNECT_MAX_MS;
    ch->reconnect_at = now_ms() + ch->backoff_ms;
    ch->state = NODUS_CH_RECONNECTING;
    QGP_LOG_INFO(LOG_TAG_CH, "Reconnect failed — retry in %ums", ch->backoff_ms);
    return -1;
}

/* ── ch_conn read thread ───────────────────────────────────────── */

static void *ch_conn_read_thread_fn(void *arg) {
    nodus_ch_conn_t *ch = (nodus_ch_conn_t *)arg;
    QGP_LOG_INFO(LOG_TAG_CH, "Read thread started for %s:%d", ch->host, ch->port);

    while (!atomic_load(&ch->read_thread_stop)) {
        /* Handle reconnect attempts */
        if (ch->state == NODUS_CH_RECONNECTING) {
            ch_conn_try_reconnect(ch);
            if (ch->state != NODUS_CH_READY) {
                sleep_ms(200);
                continue;
            }
        }

        if (ch->state == NODUS_CH_DISCONNECTED) {
            sleep_ms(200);
            continue;
        }

        if (!ch->conn || !ch->tcp) {
            sleep_ms(100);
            continue;
        }

        nodus_tcp_t *tcp = (nodus_tcp_t *)ch->tcp;
        int rc = nodus_tcp_poll(tcp, 100);

        if (rc < 0 && atomic_load(&ch->read_thread_stop))
            break;
    }

    QGP_LOG_INFO(LOG_TAG_CH, "Read thread stopped for %s:%d", ch->host, ch->port);
    return NULL;
}

static void ch_conn_start_read_thread(nodus_ch_conn_t *ch) {
    if (atomic_load(&ch->read_thread_running)) return;
    atomic_store(&ch->read_thread_stop, false);
    if (pthread_create(&ch->read_thread, NULL, ch_conn_read_thread_fn, ch) == 0) {
        atomic_store(&ch->read_thread_running, true);
        QGP_LOG_INFO(LOG_TAG_CH, "Read thread launched for %s:%d", ch->host, ch->port);
    } else {
        QGP_LOG_ERROR(LOG_TAG_CH, "Failed to create read thread");
    }
}

static void ch_conn_stop_read_thread(nodus_ch_conn_t *ch) {
    if (!atomic_load(&ch->read_thread_running)) return;
    atomic_store(&ch->read_thread_stop, true);
    pthread_join(ch->read_thread, NULL);
    atomic_store(&ch->read_thread_running, false);
    QGP_LOG_INFO(LOG_TAG_CH, "Read thread joined for %s:%d", ch->host, ch->port);
}

/* ── ch_conn auth ──────────────────────────────────────────────── */

static int ch_conn_do_auth(nodus_ch_conn_t *ch) {
    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;

    /* Step 1: HELLO */
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
    nodus_ch_pending_t *req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_hello(txn, &ch->identity.pk, &ch->identity.node_id,
                    buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth: HELLO send failed");
        ch_conn_free_pending(ch, req);
        free(buf);
        return -1;
    }

    if (!ch_conn_wait_response(ch, req, CH_CONN_CONNECT_TIMEOUT)) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth: no response to HELLO");
        ch_conn_free_pending(ch, req);
        free(buf);
        return -1;
    }

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (strcmp(resp->method, "challenge") != 0) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth: expected 'challenge', got '%s'", resp->method);
        ch_conn_free_pending(ch, req);
        free(buf);
        return -1;
    }

    /* Step 2: Sign nonce and send AUTH */
    nodus_sig_t sig;
    nodus_sign(&sig, resp->nonce, NODUS_NONCE_LEN, &ch->identity.sk);
    ch_conn_free_pending(ch, req);

    len = 0;
    txn = atomic_fetch_add(&ch->next_txn, 1);
    req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_auth(txn, &sig, buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth: AUTH send failed");
        ch_conn_free_pending(ch, req);
        free(buf);
        return -1;
    }

    if (!ch_conn_wait_response(ch, req, CH_CONN_CONNECT_TIMEOUT)) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth: no response to AUTH");
        ch_conn_free_pending(ch, req);
        free(buf);
        return -1;
    }

    resp = (nodus_tier2_msg_t *)req->response;
    if (strcmp(resp->method, "auth_ok") != 0) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth: expected 'auth_ok', got '%s'", resp->method);
        ch_conn_free_pending(ch, req);
        free(buf);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG_CH, "Auth: success on %s:%d", ch->host, ch->port);
    memcpy(ch->token, resp->token, NODUS_SESSION_TOKEN_LEN);

    ch_conn_free_pending(ch, req);
    free(buf);
    return 0;
}

/* ── Public API: Channel Connection ────────────────────────────── */

int nodus_channel_init(nodus_ch_conn_t *ch,
                       const char *host, uint16_t port,
                       const nodus_identity_t *identity,
                       nodus_on_ch_post_fn on_post, void *cb_data) {
    if (!ch || !host || !identity) return -1;

    memset(ch, 0, sizeof(*ch));
    strncpy(ch->host, host, sizeof(ch->host) - 1);
    ch->port = port;
    ch->state = NODUS_CH_DISCONNECTED;
    ch->identity = *identity;
    ch->on_ch_post = on_post;
    ch->cb_data = cb_data;
    ch->on_ring_changed = NULL;
    ch->ring_changed_data = NULL;
    atomic_store(&ch->next_txn, 1);

    pthread_mutex_init(&ch->pending_mutex, NULL);
    pthread_mutex_init(&ch->send_mutex, NULL);
    atomic_store(&ch->read_thread_running, false);
    atomic_store(&ch->read_thread_stop, false);

    /* Initialize TCP transport */
    nodus_tcp_t *tcp = calloc(1, sizeof(nodus_tcp_t));
    if (!tcp) {
        pthread_mutex_destroy(&ch->pending_mutex);
        pthread_mutex_destroy(&ch->send_mutex);
        return -1;
    }
    nodus_tcp_init(tcp, -1);
    tcp->on_frame = ch_conn_on_frame;
    tcp->on_disconnect = ch_conn_on_disconnect;
    tcp->on_connect = ch_conn_on_connect;
    tcp->cb_ctx = ch;
    ch->tcp = tcp;

    return 0;
}

int nodus_channel_connect(nodus_ch_conn_t *ch) {
    if (!ch || !ch->tcp) return -1;

    nodus_tcp_t *tcp = (nodus_tcp_t *)ch->tcp;

    QGP_LOG_INFO(LOG_TAG_CH, "Connecting to %s:%d ...", ch->host, ch->port);
    ch->state = NODUS_CH_CONNECTING;

    nodus_tcp_conn_t *conn = nodus_tcp_connect(tcp, ch->host, ch->port);
    if (!conn) {
        QGP_LOG_ERROR(LOG_TAG_CH, "TCP connect failed to %s:%d", ch->host, ch->port);
        ch->state = NODUS_CH_DISCONNECTED;
        return -1;
    }
    ch->conn = conn;

    /* Wait for TCP connection to establish */
    int elapsed = 0;
    while (ch->conn && conn->state == NODUS_CONN_CONNECTING &&
           elapsed < CH_CONN_CONNECT_TIMEOUT) {
        nodus_tcp_poll(tcp, 50);
        elapsed += 50;
        conn = (nodus_tcp_conn_t *)ch->conn;
        if (!conn) break;
    }

    if (!ch->conn || conn == NULL || conn->state != NODUS_CONN_CONNECTED) {
        QGP_LOG_ERROR(LOG_TAG_CH, "TCP connect to %s:%d failed after %dms",
                      ch->host, ch->port, elapsed);
        if (ch->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)ch->conn);
            ch->conn = NULL;
        }
        ch->state = NODUS_CH_DISCONNECTED;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG_CH, "TCP connected to %s:%d, authenticating...", ch->host, ch->port);

    /* Authenticate */
    ch->state = NODUS_CH_AUTHENTICATING;
    if (ch_conn_do_auth(ch) != 0) {
        QGP_LOG_ERROR(LOG_TAG_CH, "Auth failed to %s:%d", ch->host, ch->port);
        if (ch->conn) {
            nodus_tcp_disconnect(tcp, (nodus_tcp_conn_t *)ch->conn);
            ch->conn = NULL;
        }
        ch->state = NODUS_CH_DISCONNECTED;
        return -1;
    }

    ch->state = NODUS_CH_READY;

    /* Start read thread for push notifications */
    ch_conn_start_read_thread(ch);
    return 0;
}

bool nodus_channel_is_ready(const nodus_ch_conn_t *ch) {
    return ch && ch->state == NODUS_CH_READY;
}

void nodus_channel_close(nodus_ch_conn_t *ch) {
    if (!ch) return;

    /* Stop read thread before tearing down TCP */
    ch_conn_stop_read_thread(ch);

    if (ch->conn && ch->tcp) {
        nodus_tcp_disconnect((nodus_tcp_t *)ch->tcp,
                              (nodus_tcp_conn_t *)ch->conn);
        ch->conn = NULL;
    }

    if (ch->tcp) {
        nodus_tcp_close((nodus_tcp_t *)ch->tcp);
        free(ch->tcp);
        ch->tcp = NULL;
    }

    /* Free all pending slots */
    for (int i = 0; i < NODUS_CH_MAX_PENDING; i++) {
        nodus_ch_pending_t *p = &ch->pending[i];
        if (p->in_use) {
            if (p->response) {
                nodus_t2_msg_free((nodus_tier2_msg_t *)p->response);
                free(p->response);
            }
            p->in_use = false;
        }
    }

    pthread_mutex_destroy(&ch->pending_mutex);
    pthread_mutex_destroy(&ch->send_mutex);

    ch->state = NODUS_CH_DISCONNECTED;
    ch->ch_sub_count = 0;

    nodus_identity_clear(&ch->identity);
}

int nodus_ch_conn_create(nodus_ch_conn_t *ch,
                         const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_channel_is_ready(ch) || !uuid) return -1;

    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
    nodus_ch_pending_t *req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_create(txn, ch->token, uuid, false,
                        NULL, NULL, false,
                        buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) { ch_conn_free_pending(ch, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!ch_conn_wait_response(ch, req, CH_CONN_REQUEST_TIMEOUT)) { ch_conn_free_pending(ch, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; ch_conn_free_pending(ch, req); return rc; }
    ch_conn_free_pending(ch, req);
    return 0;
}

int nodus_ch_conn_post(nodus_ch_conn_t *ch,
                       const uint8_t ch_uuid[NODUS_UUID_BYTES],
                       const uint8_t post_uuid[NODUS_UUID_BYTES],
                       const uint8_t *body, size_t body_len,
                       uint64_t timestamp, const nodus_sig_t *sig,
                       uint64_t *received_at_out) {
    if (!nodus_channel_is_ready(ch) || !ch_uuid || !body) return -1;

    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
    nodus_ch_pending_t *req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_post(txn, ch->token, ch_uuid, post_uuid,
                      body, body_len, timestamp, sig,
                      buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) { ch_conn_free_pending(ch, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!ch_conn_wait_response(ch, req, CH_CONN_REQUEST_TIMEOUT)) { ch_conn_free_pending(ch, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; ch_conn_free_pending(ch, req); return rc; }

    if (received_at_out) *received_at_out = resp->ch_received_at;
    ch_conn_free_pending(ch, req);
    return 0;
}

int nodus_ch_conn_get_posts(nodus_ch_conn_t *ch,
                            const uint8_t uuid[NODUS_UUID_BYTES],
                            uint64_t since_received_at, int max_count,
                            nodus_channel_post_t **posts_out,
                            size_t *count_out) {
    if (!nodus_channel_is_ready(ch) || !uuid || !posts_out || !count_out)
        return -1;
    *posts_out = NULL;
    *count_out = 0;

    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
    nodus_ch_pending_t *req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_get_posts(txn, ch->token, uuid, since_received_at, max_count,
                           buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) { ch_conn_free_pending(ch, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!ch_conn_wait_response(ch, req, CH_CONN_REQUEST_TIMEOUT)) { ch_conn_free_pending(ch, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; ch_conn_free_pending(ch, req); return rc; }

    if (resp->ch_posts && resp->ch_post_count > 0) {
        *posts_out = resp->ch_posts;
        *count_out = resp->ch_post_count;
        resp->ch_posts = NULL;
        resp->ch_post_count = 0;
    }
    ch_conn_free_pending(ch, req);
    return 0;
}

int nodus_ch_conn_subscribe(nodus_ch_conn_t *ch,
                            const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_channel_is_ready(ch) || !uuid) return -1;

    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
    nodus_ch_pending_t *req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_subscribe(txn, ch->token, uuid,
                           buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) { ch_conn_free_pending(ch, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!ch_conn_wait_response(ch, req, CH_CONN_REQUEST_TIMEOUT)) { ch_conn_free_pending(ch, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; ch_conn_free_pending(ch, req); return rc; }

    /* Track for potential re-subscribe */
    if (ch->ch_sub_count < NODUS_CH_CONN_MAX_SUBS) {
        bool found = false;
        for (int i = 0; i < ch->ch_sub_count; i++) {
            if (memcmp(ch->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            memcpy(ch->ch_subs[ch->ch_sub_count], uuid, NODUS_UUID_BYTES);
            ch->ch_sub_count++;
        }
    }
    ch_conn_free_pending(ch, req);
    return 0;
}

int nodus_ch_conn_unsubscribe(nodus_ch_conn_t *ch,
                              const uint8_t uuid[NODUS_UUID_BYTES]) {
    if (!nodus_channel_is_ready(ch) || !uuid) return -1;

    uint8_t *buf = malloc(CH_CONN_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&ch->next_txn, 1);
    nodus_ch_pending_t *req = ch_conn_alloc_pending(ch, txn);
    if (!req) { free(buf); return -1; }

    nodus_t2_ch_unsubscribe(txn, ch->token, uuid,
                              buf, CH_CONN_BUF_SIZE, &len);
    if (ch_conn_send(ch, buf, len) != 0) { ch_conn_free_pending(ch, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!ch_conn_wait_response(ch, req, CH_CONN_REQUEST_TIMEOUT)) { ch_conn_free_pending(ch, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; ch_conn_free_pending(ch, req); return rc; }

    /* Remove from tracking */
    for (int i = 0; i < ch->ch_sub_count; i++) {
        if (memcmp(ch->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
            memcpy(ch->ch_subs[i], ch->ch_subs[--ch->ch_sub_count],
                   NODUS_UUID_BYTES);
            break;
        }
    }
    ch_conn_free_pending(ch, req);
    return 0;
}

/* ── Circuit operations (Faz 1) ─────────────────────────────────── */

int nodus_circuit_open(nodus_client_t *client, const nodus_key_t *peer_fp,
                        nodus_circuit_data_cb on_data,
                        nodus_circuit_close_cb on_close,
                        void *user,
                        nodus_circuit_handle_t **out) {
    if (!client || !peer_fp || !out) return -1;
    if (!nodus_client_is_ready(client)) return -1;

    /* Allocate handle */
    uint64_t cid = (uint64_t)atomic_fetch_add(&client->next_client_cid, 1);
    pthread_mutex_lock(&client->circuits_mutex);
    nodus_circuit_handle_t *h = NULL;
    for (int i = 0; i < NODUS_CLIENT_MAX_CIRCUITS; i++) {
        if (!client->circuits[i].in_use) {
            h = &client->circuits[i];
            memset(h, 0, sizeof(*h));
            h->client = client;
            h->cid = cid;
            h->in_use = true;
            break;
        }
    }
    pthread_mutex_unlock(&client->circuits_mutex);
    if (!h) return NODUS_ERR_CIRCUIT_LIMIT;
    h->on_data = on_data;
    h->on_close = on_close;
    h->user = user;

    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) {
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }

    uint8_t buf[4096]; size_t blen = 0;
    if (nodus_t2_circ_open(txn, client->token, cid, peer_fp,
                            buf, sizeof(buf), &blen) != 0) {
        free_pending(client, req);
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }
    if (send_request(client, buf, blen) != 0) {
        free_pending(client, req);
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    /* Circuit open uses a shorter bounded timeout than request_timeout_ms:
     * a slow/malicious peer nodus could otherwise hold the pending slot for
     * the full request_timeout_ms (potentially 60s). */
    int timeout_ms = NODUS_CIRCUIT_OPEN_TIMEOUT_MS;
    if (client->config.request_timeout_ms > 0 &&
        client->config.request_timeout_ms < timeout_ms) {
        timeout_ms = client->config.request_timeout_ms;
    }
    if (!wait_response(client, req, timeout_ms)) {
        free_pending(client, req);
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return NODUS_ERR_TIMEOUT;
    }

    int rc = 0;
    if (strcmp(resp->method, "circ_open_err") == 0) {
        rc = resp->circ_err_code ? resp->circ_err_code : NODUS_ERR_INTERNAL_ERROR;
    } else if (strcmp(resp->method, "circ_open") != 0) {
        rc = NODUS_ERR_PROTOCOL_ERROR;
    }
    free_pending(client, req);

    if (rc != 0) {
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return rc;
    }

    *out = h;
    return 0;
}

int nodus_circuit_open_e2e(nodus_client_t *client, const nodus_key_t *peer_fp,
                            const uint8_t *peer_kyber_pk,
                            nodus_circuit_data_cb on_data,
                            nodus_circuit_close_cb on_close,
                            void *user,
                            nodus_circuit_handle_t **out) {
    if (!client || !peer_fp || !peer_kyber_pk || !out) return -1;
    if (!nodus_client_is_ready(client)) return -1;

    /* Kyber encapsulate → per-circuit shared secret */
    uint8_t e2e_ct[NODUS_KYBER_CT_BYTES];
    uint8_t e2e_ss[NODUS_KYBER_SS_BYTES];
    if (qgp_kem1024_encapsulate(e2e_ct, e2e_ss, peer_kyber_pk) != 0)
        return -1;

    /* Allocate handle */
    uint64_t cid = (uint64_t)atomic_fetch_add(&client->next_client_cid, 1);
    pthread_mutex_lock(&client->circuits_mutex);
    nodus_circuit_handle_t *h = NULL;
    for (int i = 0; i < NODUS_CLIENT_MAX_CIRCUITS; i++) {
        if (!client->circuits[i].in_use) {
            h = &client->circuits[i];
            memset(h, 0, sizeof(*h));
            h->client = client;
            h->cid = cid;
            h->in_use = true;
            break;
        }
    }
    pthread_mutex_unlock(&client->circuits_mutex);
    if (!h) {
        qgp_secure_memzero(e2e_ss, sizeof(e2e_ss));
        return NODUS_ERR_CIRCUIT_LIMIT;
    }
    h->on_data = on_data;
    h->on_close = on_close;
    h->user = user;

    /* Init per-circuit E2E crypto — use src_fp||dst_fp as nonces (deterministic) */
    uint8_t nc[32], ns[32];
    memcpy(nc, client->identity.node_id.bytes, 32);
    memcpy(ns, peer_fp->bytes, 32);
    if (nodus_channel_crypto_init(&h->e2e_crypto, e2e_ss, nc, ns) != 0) {
        qgp_secure_memzero(e2e_ss, sizeof(e2e_ss));
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }
    h->e2e_active = true;
    qgp_secure_memzero(e2e_ss, sizeof(e2e_ss));

    /* Send circ_open with e2e_ct */
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) {
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }

    uint8_t buf[4096]; size_t blen = 0;
    if (nodus_t2_circ_open_e2e(txn, client->token, cid, peer_fp, e2e_ct,
                                buf, sizeof(buf), &blen) != 0) {
        free_pending(client, req);
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }
    if (send_request(client, buf, blen) != 0) {
        free_pending(client, req);
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return -1;
    }

    int timeout_ms = NODUS_CIRCUIT_OPEN_TIMEOUT_MS;
    if (client->config.request_timeout_ms > 0 &&
        client->config.request_timeout_ms < timeout_ms) {
        timeout_ms = client->config.request_timeout_ms;
    }
    if (!wait_response(client, req, timeout_ms)) {
        free_pending(client, req);
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return NODUS_ERR_TIMEOUT;
    }

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    int rc = 0;
    if (strcmp(resp->method, "circ_open_err") == 0) {
        rc = resp->circ_err_code ? resp->circ_err_code : NODUS_ERR_INTERNAL_ERROR;
    } else if (strcmp(resp->method, "circ_open") != 0) {
        rc = NODUS_ERR_PROTOCOL_ERROR;
    }
    free_pending(client, req);

    if (rc != 0) {
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
        return rc;
    }

    *out = h;
    QGP_LOG_INFO(LOG_TAG, "Circuit E2E opened (cid=%llu, onion layer active)",
                 (unsigned long long)cid);
    return 0;
}

void nodus_circuit_set_inbound_cb(nodus_client_t *client,
                                    nodus_circuit_inbound_cb cb, void *user) {
    if (!client) return;
    client->on_circuit_inbound = cb;
    client->circuit_inbound_user = user;
}

int nodus_circuit_attach(nodus_circuit_handle_t *h,
                          nodus_circuit_data_cb on_data,
                          nodus_circuit_close_cb on_close,
                          void *user) {
    if (!h || !h->in_use) return -1;
    h->on_data = on_data;
    h->on_close = on_close;
    h->user = user;
    return 0;
}

int nodus_circuit_send(nodus_circuit_handle_t *h, const uint8_t *data, size_t len) {
    if (!h || !h->in_use || h->closed) return -1;
    if (len > NODUS_MAX_CIRCUIT_PAYLOAD) return NODUS_ERR_TOO_LARGE;
    nodus_client_t *client = h->client;
    if (!client) return -1;

    const uint8_t *send_data = data;
    size_t send_len = len;
    uint8_t *enc_data = NULL;

    /* E2E encrypt if onion layer active */
    if (h->e2e_active) {
        size_t enc_cap = len + NODUS_CHANNEL_OVERHEAD;
        enc_data = malloc(enc_cap);
        if (!enc_data) return -1;
        size_t enc_out = 0;
        if (nodus_channel_encrypt(&h->e2e_crypto, data, len, enc_data, enc_cap, &enc_out) != 0) {
            free(enc_data);
            return -1;
        }
        send_data = enc_data;
        send_len = enc_out;
    }

    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    size_t cap = send_len + 256;
    uint8_t *buf = malloc(cap);
    if (!buf) { free(enc_data); return -1; }
    size_t blen = 0;
    int rc = nodus_t2_circ_data(txn, client->token, h->cid, send_data, send_len,
                                  buf, cap, &blen);
    if (rc == 0) {
        rc = send_request(client, buf, blen);
    }
    free(buf);
    free(enc_data);
    return rc;
}

int nodus_circuit_close(nodus_circuit_handle_t *h) {
    if (!h || !h->in_use) return -1;
    nodus_client_t *client = h->client;
    if (client && !h->closed) {
        uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
        uint8_t buf[256]; size_t blen = 0;
        if (nodus_t2_circ_close(txn, client->token, h->cid,
                                 buf, sizeof(buf), &blen) == 0) {
            send_request(client, buf, blen);
        }
        h->closed = true;
    }
    if (client) {
        pthread_mutex_lock(&client->circuits_mutex);
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
    } else {
        h->in_use = false;
    }
    return 0;
}
