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
#include "protocol/nodus_tier3.h"     /* NODUS_T3_CC_APPR_E_MAX (dnac_cc_collect) */
#include "crypto/nodus_sign.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"
#include "client/nodus_client_strict.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <unistd.h>
  #include <sys/socket.h>
#endif
#ifdef __EMSCRIPTEN__
  #include <emscripten.h>
#endif

#include "crypto/utils/qgp_log.h"

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
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
static int  find_response_map(const uint8_t *raw, size_t raw_len,
                              cbor_decoder_t *dec, size_t *map_count);

/* ── Cross-platform millisecond sleep ──────────────────────────── */

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep(ms);
#elif defined(__EMSCRIPTEN__)
    /* Browser: give control back to the event loop (nanosleep would spin
     * the only thread and SOCKFS would never deliver a byte). */
    emscripten_sleep((unsigned int)ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

#ifdef __EMSCRIPTEN__
/* Browser build (design 2026-09-25 rev 2 §0a.3 (c1)): there is no read
 * thread, and nodus_tcp_poll never waits (nodus_tcp.c, __EMSCRIPTEN__
 * poll loop). Every thread-less poll loop in this file calls this after
 * each poll so the browser can run its event loop — SOCKFS delivers
 * received bytes only when control returns to it (spike S0: a loop without
 * the yield receives 0 bytes). Needs ASYNCIFY or JSPI at link time. */
#define CLIENT_WASM_YIELD_MS 10
static void client_yield(void) {
    emscripten_sleep(CLIENT_WASM_YIELD_MS);
}
#endif

/* Keepalive ping every 60 s so the server's idle sweep (180 s for an
 * authenticated client) never closes a live session. Caller holds
 * poll_mutex. Run by the read thread, or by nodus_client_tick where there
 * is no read thread (browser build). */
static void keepalive_if_due(nodus_client_t *client) {
    if (client->state != NODUS_CLIENT_READY) return;
    uint64_t now = now_ms();
    if (now - client->last_ping_ms < 60000) return;
    client->last_ping_ms = now;
    uint8_t ping_buf[128];
    size_t ping_len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    if (nodus_t2_ping(txn, client->token, ping_buf, sizeof(ping_buf), &ping_len) == 0)
        send_request(client, ping_buf, ping_len);
}

/* ── Internal read thread ──────────────────────────────────────── */

#ifndef __EMSCRIPTEN__   /* the browser build has no read thread */
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
        keepalive_if_due(client);

        pthread_mutex_unlock(&client->poll_mutex);

        if (rc < 0 && atomic_load(&client->read_thread_stop))
            break;
        if (client->state == NODUS_CLIENT_DISCONNECTED)
            sleep_ms(100);
    }

    QGP_LOG_INFO(LOG_TAG, "Read thread stopped");
    return NULL;
}
#endif /* !__EMSCRIPTEN__ */

static void start_read_thread(nodus_client_t *client) {
#ifdef __EMSCRIPTEN__
    /* Browser build: one thread (decision 2026-09-25-web-wallet-nodus-
     * send-transport.md "Çalışma modeli"). Requests poll directly in
     * wait_response; the page drives keepalive + reconnect through
     * nodus_client_tick. */
    (void)client;
#else
    if (atomic_load(&client->read_thread_running)) return;
    atomic_store(&client->read_thread_stop, false);
    if (pthread_create(&client->read_thread, NULL, read_thread_fn, client) == 0) {
        atomic_store(&client->read_thread_running, true);
        QGP_LOG_INFO(LOG_TAG, "Read thread launched");
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create read thread");
    }
#endif
}

static void stop_read_thread(nodus_client_t *client) {
    if (!atomic_load(&client->read_thread_running)) return;
    atomic_store(&client->read_thread_stop, true);
    pthread_join(client->read_thread, NULL);
    atomic_store(&client->read_thread_running, false);
    QGP_LOG_INFO(LOG_TAG, "Read thread joined");
}

/* ── Helpers ────────────────────────────────────────────────────── */

/* Monotonic milliseconds: every client wait, timeout, backoff and keepalive
 * interval is measured with this, so a wall-clock step cannot stretch or cut
 * one short. Never compare it with a unix timestamp (nodus_time_now*). */
static uint64_t now_ms(void) {
    return nodus_time_mono_ms();
}

/* Milliseconds from `start` (a now_ms() value) until now. */
static uint64_t elapsed_since(uint64_t start) {
    uint64_t now = now_ms();
    return now > start ? now - start : 0;
}

/* true when at least `limit_ms` have passed since `start`. A limit <= 0 has
 * always passed (it must never turn into a huge unsigned wait). */
static bool deadline_passed(uint64_t start, int limit_ms) {
    if (limit_ms <= 0) return true;
    return elapsed_since(start) >= (uint64_t)limit_ms;
}

static void set_state(nodus_client_t *client, nodus_client_state_t new_state) {
    if (client->state == new_state) return;
    nodus_client_state_t old = client->state;
    client->state = new_state;
    if (client->config.on_state_change)
        client->config.on_state_change(old, new_state, client->config.callback_data);
}

/* The transport's write lock (nodus_tcp_set_write_lock): ctx is the
 * owner's wbuf_mutex. Taken by the transport only, never by this file. */
static void client_wbuf_lock(void *ctx, bool lock) {
    pthread_mutex_t *m = (pthread_mutex_t *)ctx;
    if (lock) pthread_mutex_lock(m);
    else      pthread_mutex_unlock(m);
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

/* Tear down an inbound circuit we are not accepting. Sent when the application
 * registered no circuit-inbound handler (default-deny) or the per-session
 * circuit table is full — so the originator stops forwarding data against a
 * cid we never established, rather than us silently black-holing its frames. */
static void circuit_reject(nodus_client_t *client, uint64_t cid) {
    uint8_t buf[256];
    size_t  len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    if (nodus_t2_circ_close(txn, client->token, cid, buf, sizeof(buf), &len) == 0) {
        send_request(client, buf, len);
    }
}

/* ── Pending slot management ───────────────────────────────────── */

/* O15C-D — the request/result correlation rule, in one place.
 *
 * A response is matched to a pending entry ONLY when that entry is
 * in_use AND its txn is exactly the response's txn_id. Two properties
 * follow, and together they are why the late "unknown txn" warnings are
 * an attribution gap rather than a delivery defect:
 *
 *   - No misdelivery. A response can only ever reach the entry holding
 *     its own txn; there is no positional or fallback match.
 *   - No capture after release. free_pending clears in_use but leaves
 *     txn set, so a reply that arrives after the caller gave up matches
 *     nothing — including the case where the slot has since been reused
 *     for a different request.
 *
 * Ids cannot collide within a session: next_txn is monotonic and is
 * only ever reset in nodus_client_init.
 *
 * Caller holds pending_mutex. */
nodus_pending_t *nodus_client_pending_find(nodus_client_t *client,
                                             uint32_t txn) {
    if (!client) return NULL;
    for (int i = 0; i < NODUS_MAX_PENDING; i++) {
        if (client->pending[i].in_use && client->pending[i].txn == txn)
            return &client->pending[i];
    }
    return NULL;
}

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
    /* The limit is measured on the monotonic clock, not by counting loop
     * turns: nodus_tcp_poll returns early whenever an event arrives, so a
     * turn is not 50 ms (RT1 L3 F8). */
    uint64_t start = now_ms();

    while (!atomic_load(&req->ready) && !deadline_passed(start, timeout_ms)) {
        if (!client->conn && client->state != NODUS_CLIENT_RECONNECTING)
            return false;

        if (atomic_load(&client->read_thread_running) &&
            !pthread_equal(pthread_self(), client->read_thread)) {
            /* Read thread handles TCP — just wait for ready flag */
            sleep_ms(10);
        } else {
            /* We ARE the read thread (reconnect path), or no thread — poll directly */
            nodus_tcp_t *tcp = (nodus_tcp_t *)client->tcp;
            if (tcp) nodus_tcp_poll(tcp, 50);
            else sleep_ms(10);
#ifdef __EMSCRIPTEN__
            if (tcp) client_yield();
#endif
        }
    }
    int elapsed = (int)elapsed_since(start);
    /* O15C-D — terminal reason for the pending entry, so a later
     * "unknown txn" warning is attributable to the request that gave up
     * rather than left unexplained. One line per abandoned request. */
    if (!atomic_load(&req->ready)) {
        QGP_LOG_WARN(LOG_TAG,
                     "Pending txn %u abandoned: reason=%s after %dms "
                     "(limit %dms) — a later reply will log as unknown txn",
                     req->txn,
                     (!client->conn &&
                      client->state != NODUS_CLIENT_RECONNECTING)
                         ? "disconnected" : "timeout",
                     elapsed, timeout_ms);
        return false;
    }
    return true;
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
    if (nodus_t2_decode(payload, len, &tmp) != 0) {
        /* nodus_t2_decode() already freed a refused frame; this keeps the
         * server's "free after every decode" pattern and is a no-op. */
        nodus_t2_msg_free(&tmp);
        return;
    }

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
        /* G2 default-deny: an application that registered no circuit-inbound
         * handler does not accept circuits. Never allocate a slot (this closes
         * the slot-exhaustion DoS vector) and never establish E2E crypto — tell
         * the originator to tear the circuit down at once. */
        if (!client->on_circuit_inbound) {
            circuit_reject(client, tmp.circ_cid);
            nodus_t2_msg_free(&tmp);
            return;
        }
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
        /* Circuit table full — reject rather than silently drop the frames the
         * originator will send against a cid we never accepted. */
        if (!h) {
            circuit_reject(client, tmp.circ_cid);
            nodus_t2_msg_free(&tmp);
            return;
        }
        /* E2E: if circ_inbound has e2e_ct, decapsulate and init per-circuit
         * crypto. e2e_alg (Faz 1 KEM migration) selects the algorithm the
         * ORIGINATOR encapsulated with — it was relayed opaquely by the
         * server, so it must match here.
         *
         * D4 (N1 delta 1) — FAIL CLOSED, never plaintext: if e2e_ct is
         * present but this identity has no matching key, OR decapsulation
         * fails, the circuit is REFUSED (same circuit_reject() path as the
         * "no handler" / "table full" refusals above), never delivered to
         * on_circuit_inbound with e2e_active left false. Before this fix,
         * that fall-through case reached on_circuit_inbound() with
         * e2e_active=false, and nodus_circuit_send()'s encrypt gate
         * (`if (h->e2e_active)`) only skips encryption — it never blocks
         * sending — so the responder's own replies on that "E2E" circuit
         * would go out as PLAINTEXT. Pre-existing for a missing Kyber key;
         * Faz 1 makes it the common case once a peer starts sending
         * e2e_alg=1 to a client that has no ML-KEM identity yet. */
        bool e2e_refuse = false;
        if (tmp.has_e2e_ct) {
            bool e2e_have_key = (tmp.e2e_alg == 1) ? client->identity.has_mlkem
                                                     : client->identity.has_kyber;
            if (!e2e_have_key) {
                e2e_refuse = true;
            } else {
                uint8_t e2e_ss[NODUS_KYBER_SS_BYTES];
                int dec_rc = (tmp.e2e_alg == 1)
                    ? qgp_mlkem1024_decapsulate(e2e_ss, tmp.e2e_ct, client->identity.mlkem_sk)
                    : qgp_kem1024_decapsulate(e2e_ss, tmp.e2e_ct, client->identity.kyber_sk);
                if (dec_rc == 0) {
                    uint8_t nc[32], ns[32];
                    memcpy(nc, tmp.circ_peer_fp.bytes, 32);  /* src = peer */
                    memcpy(ns, client->identity.node_id.bytes, 32);  /* dst = us */
                    /* We ACCEPTED this circuit (circ_inbound) → responder. */
                    nodus_channel_crypto_init(&h->e2e_crypto, e2e_ss, nc, ns,
                                              NODUS_CHANNEL_ROLE_RESPONDER);
                    h->e2e_active = true;
                    QGP_LOG_INFO(LOG_TAG, "Circuit E2E: inbound onion layer active (cid=%llu)",
                                 (unsigned long long)h->cid);
                } else {
                    e2e_refuse = true;
                }
                qgp_secure_memzero(e2e_ss, sizeof(e2e_ss));
            }
        }

        if (e2e_refuse) {
            QGP_LOG_ERROR(LOG_TAG,
                          "Circuit E2E: inbound e2e_ct present (alg=%u) but no "
                          "matching local key or decapsulation failed (cid=%llu) "
                          "— refusing (never falling back to plaintext)",
                          (unsigned)tmp.e2e_alg, (unsigned long long)h->cid);
            pthread_mutex_lock(&client->circuits_mutex);
            h->in_use = false;
            pthread_mutex_unlock(&client->circuits_mutex);
            circuit_reject(client, tmp.circ_cid);
            nodus_t2_msg_free(&tmp);
            return;
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

        /* H11/RX-lock: the AEAD decrypt runs HERE, still holding circuits_mutex.
         * It used to run after the unlock, reading &h->e2e_crypto unlocked —
         * which raced nodus_circuit_close() wiping the key (H11) and
         * nodus_circuit_open() memset-recycling the fixed-array slot under the
         * decrypting thread, i.e. a torn key read. Holding the lock across the
         * decrypt is safe: it is a few microseconds of AES-GCM and takes no
         * other lock. What must NEVER happen under this mutex is invoking the
         * app CALLBACK — that re-enters nodus_circuit_close/open and would
         * self-deadlock the non-recursive mutex — so the callback is deferred to
         * after the unlock below.
         *
         * CRIT-3 — AEAD completeness: gate on (cb && e2e) FIRST so an e2e-active
         * circuit can never fall through to the raw delivery path; a short frame,
         * an alloc failure or a decrypt failure DROPS. Boundary is
         * '>= NODUS_CHANNEL_OVERHEAD' (28 B == valid empty AEAD frame, see
         * tests/test_channel_crypto_aead_complete.c). The non-e2e passthrough
         * stays length-agnostic: plain circuits legitimately carry raw bytes of
         * any length. */
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        bool deliver_pt = false;

        if (cb && e2e) {
            if (!tmp.circ_data || tmp.circ_data_len < NODUS_CHANNEL_OVERHEAD) {
                QGP_LOG_WARN(LOG_TAG,
                             "Circuit e2e short frame dropped (cid=%llu len=%zu < overhead=%u)",
                             (unsigned long long)h->cid,
                             tmp.circ_data ? tmp.circ_data_len : (size_t)0,
                             (unsigned)NODUS_CHANNEL_OVERHEAD);
            } else {
                /* Safe: length checked above, subtraction cannot underflow. */
                size_t pt_cap = tmp.circ_data_len - NODUS_CHANNEL_OVERHEAD;
                pt = malloc(pt_cap > 0 ? pt_cap : 1);
                if (!pt) {
                    QGP_LOG_ERROR(LOG_TAG,
                                  "Circuit e2e alloc failed, frame dropped (cid=%llu)",
                                  (unsigned long long)h->cid);
                } else if (nodus_channel_decrypt(&h->e2e_crypto,
                                                 tmp.circ_data, tmp.circ_data_len,
                                                 pt, pt_cap, &pt_len) == 0) {
                    deliver_pt = true;
                } else {
                    QGP_LOG_ERROR(LOG_TAG, "Circuit E2E decrypt failed (cid=%llu)",
                                 (unsigned long long)h->cid);
                    free(pt);
                    pt = NULL;
                }
            }
        }
        pthread_mutex_unlock(&client->circuits_mutex);

        /* Callbacks are invoked OUTSIDE circuits_mutex (they re-enter the
         * circuit API). */
        if (deliver_pt) {
            cb(h, pt, pt_len, user);
        } else if (cb && !e2e) {
            cb(h, tmp.circ_data, tmp.circ_data_len, user);
        }
        free(pt);
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
                /* H11: same wipe on the peer-initiated close path — the key must
                 * not outlive the circuit here either. Under the lock, before the
                 * slot is released; the callback runs after the unlock. */
                nodus_channel_crypto_clear(&h->e2e_crypto);
                h->e2e_active = false;
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
    nodus_pending_t *slot = nodus_client_pending_find(client, tmp.txn_id);
    if (!slot) {
        pthread_mutex_unlock(&client->pending_mutex);
        /* O15C-D — correlation itself is sound: next_txn is monotonic per
         * client (only reset in nodus_client_init) and the match above
         * also requires in_use, so a response can never be delivered to
         * the WRONG request. What was missing was attribution: with only
         * the txn id, a late post-timeout response was indistinguishable
         * from a deliberate fire-and-forget reply (resubscribe_all sends
         * LISTEN / CH_SUBSCRIBE with no pending slot by design) or from a
         * server-side correlation bug. Log the method, the response type
         * and the highest txn allocated so far — bounded, no payload, no
         * secret material. next_txn > txn_id means we DID issue it and
         * gave up on it; next_txn <= txn_id means the id is not ours. */
        QGP_LOG_WARN(LOG_TAG,
                     "Response for unknown txn %u (no pending slot): "
                     "method=%s type=%c next_txn=%u — %s",
                     tmp.txn_id,
                     tmp.method[0] ? tmp.method : "(none)",
                     tmp.type ? tmp.type : '?',
                     (unsigned)atomic_load(&client->next_txn),
                     (tmp.txn_id < (uint32_t)atomic_load(&client->next_txn))
                         ? "late reply to a request we already abandoned"
                         : "txn id never issued by this client");
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
                 /* last_activity is the transport's unix-seconds stamp
                  * (nodus_time_now), so this stays on the wall clock —
                  * now_ms() is monotonic and not comparable with it. */
                 (conn && conn->last_activity > 0)
                     ? (unsigned long)(nodus_time_now_ms() - conn->last_activity * 1000)
                     : 0UL);
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
    /* Server key pin: a count without a list, or a negative count, is a
     * broken pin — refuse it rather than silently run unpinned. */
    if (config->pinned_server_fp_count < 0 ||
        (config->pinned_server_fp_count > 0 && !config->pinned_server_fps)) {
        QGP_LOG_ERROR(LOG_TAG, "init: invalid server pin list (count=%d, list=%s)",
                      config->pinned_server_fp_count,
                      config->pinned_server_fps ? "set" : "NULL");
        return -1;
    }

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
    pthread_mutex_init(&client->wbuf_mutex, NULL);
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
        pthread_mutex_destroy(&client->wbuf_mutex);
        pthread_mutex_destroy(&client->circuits_mutex);
        return -1;
    }
    nodus_tcp_init(tcp, -1);
    tcp->on_frame = client_on_frame;
    tcp->on_disconnect = client_on_disconnect;
    tcp->on_connect = client_on_connect;
    tcp->cb_ctx = client;
    /* Callers send on their own thread while the read thread polls: both
     * touch the connection's write buffer, so the transport serialises
     * them on wbuf_mutex. Without it one PUT left the socket twice. */
    nodus_tcp_set_write_lock(tcp, client_wbuf_lock, &client->wbuf_mutex);
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
    uint64_t start = now_ms();
    while (client->conn && conn->state == NODUS_CONN_CONNECTING &&
           !deadline_passed(start, client->config.connect_timeout_ms)) {
        nodus_tcp_poll(tcp, 50);
#ifdef __EMSCRIPTEN__
        client_yield();
#endif
        conn = (nodus_tcp_conn_t *)client->conn;  /* re-read (may be NULL) */
        if (!conn) break;
    }
    int elapsed = (int)elapsed_since(start);

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

/* Server key pin (config.pinned_server_fps) — the AUTH_OK checks that run
 * BEFORE the channel-key handling in do_auth, only when a pin is set.
 * Returns 0 when the AUTH_OK may proceed, -1 to refuse the connection.
 *
 * Every weak path of the unpinned handshake is closed here or right after:
 *   - no kpk: unpinned, either an UNENCRYPTED session (has_kpk false) or
 *     the cached-key reconnect branch — the live server signed nothing
 *     this round, so there is no key to hold against the pin → refused;
 *   - kpk without spk/kpk_sig ("legacy server") → refused here;
 *   - fingerprint(spk) not in the pin list → refused here;
 *   - kpk_sig invalid → refused by do_auth (as without a pin);
 *   - no mpk, or mpk without mpk_sig → refused here; mpk_sig invalid →
 *     refused by do_auth instead of the Kyber round-3 fallback.
 * A pinned client therefore speaks ML-KEM-1024 ONLY (operator 2026-09-29,
 * browser wallet "5 evet"; decision 2026-09-25-web-wallet-nodus-send-
 * transport.md addendum): nothing signs the ABSENCE of mpk, so an on-path
 * party could otherwise strip mpk + mpk_sig and force Kyber round-3. The
 * unpinned client keeps the round-3 fallback (decision 2026-09-23-kem-
 * mlkem-migration.md K1 rev 2). */
static int pin_check_auth_ok(const nodus_client_t *client,
                              const nodus_tier2_msg_t *resp) {
    if (!resp->has_kyber_pk) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: pinned client — server sent no channel key "
                      "(no unencrypted or cached-key session under a pin)");
        return -1;
    }
    if (!resp->has_kpk_sig || !resp->has_server_pk) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: pinned client — server key or kpk_sig missing "
                      "(unsigned channel key refused)");
        return -1;
    }
    if (!resp->has_mlkem_pk || !resp->has_mpk_sig) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: pinned client — no signed ML-KEM key "
                      "(ML-KEM-1024 only, no Kyber round-3 session)");
        return -1;
    }

    nodus_key_t fp;
    if (nodus_fingerprint(&resp->server_pk, &fp) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Auth: pinned client — server fingerprint failed");
        return -1;
    }
    for (int i = 0; i < client->config.pinned_server_fp_count; i++) {
        if (nodus_key_cmp(&fp, &client->config.pinned_server_fps[i]) == 0)
            return 0;
    }
    QGP_LOG_ERROR(LOG_TAG, "Auth: pinned client — server key %02x%02x%02x%02x... "
                  "is not in the pin list", fp.bytes[0], fp.bytes[1],
                  fp.bytes[2], fp.bytes[3]);
    return -1;
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
    /* C2: domain-tagged AUTH_CHALLENGE sign (client-side, always outbound) */
    nodus_sign_auth_challenge(&sig, auth_nonce, &client->identity.sk);
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

    /* Pinned: every AUTH_OK that passes here reaches the kpk_sig branch
     * below, which sets server_dil_pk to THIS session's key. Unpinned: the
     * field keeps its previous (TOFU) semantics — messenger reads it
     * (nodus_init.c state callback) and its behaviour must not change. */
    const bool pinned = client->config.pinned_server_fp_count > 0;
    if (pinned && pin_check_auth_ok(client, resp) != 0) {
        free_pending(client, req);
        free(buf);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Auth: success");
    memcpy(client->token, resp->token, NODUS_SESSION_TOKEN_LEN);

    /* Channel encryption: use server Kyber pubkey (from auth_ok or cache),
     * upgraded to ML-KEM-1024 when the server advertised + signed one
     * (Faz 1 KEM migration, docs/plans/decisions/2026-09-23-kem-mlkem-
     * migration.md). */
    bool has_kpk = resp->has_kyber_pk;
    uint8_t server_kyber_pk[NODUS_KYBER_PK_BYTES];
    bool has_mpk = false;
    uint8_t server_mlkem_pk[NODUS_MLKEM_PK_BYTES];
    if (has_kpk) {
        memcpy(server_kyber_pk, resp->kyber_pk, NODUS_KYBER_PK_BYTES);

        /* Verify server's Kyber PK signature (MITM protection).
         * Server signs (kyber_pk || nonce) with its Dilithium5 key. */
        if (resp->has_kpk_sig && resp->has_server_pk) {
            uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
            memcpy(sign_data, resp->kyber_pk, NODUS_KYBER_PK_BYTES);
            memcpy(sign_data + NODUS_KYBER_PK_BYTES, auth_nonce, NODUS_NONCE_LEN);

            /* C2: KYBER_BIND domain verify */
            if (nodus_verify_kyber_bind(&resp->kpk_sig, sign_data, sizeof(sign_data),
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

            /* Faz 1 KEM migration: if the server ALSO advertised a signed
             * ML-KEM-1024 pubkey, verify it under MLKEM_BIND against the
             * SAME server_pk (just trusted above via kpk_sig) and prefer
             * it over Kyber round-3. Any failure here (missing fields, bad
             * signature) falls back to Kyber — never fails the connection. */
            if (resp->has_mlkem_pk && resp->has_mpk_sig) {
                uint8_t msign_data[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
                memcpy(msign_data, resp->mlkem_pk, NODUS_MLKEM_PK_BYTES);
                memcpy(msign_data + NODUS_MLKEM_PK_BYTES, auth_nonce, NODUS_NONCE_LEN);
                if (nodus_verify_mlkem_bind(&resp->mpk_sig, msign_data, sizeof(msign_data),
                                             &resp->server_pk) == 0) {
                    memcpy(server_mlkem_pk, resp->mlkem_pk, NODUS_MLKEM_PK_BYTES);
                    has_mpk = true;
                    QGP_LOG_INFO(LOG_TAG, "Auth: server ML-KEM PK signature verified ✓");
                } else if (pinned) {
                    /* Pinned client: a bad mpk_sig is a failed handshake,
                     * not a reason to drop to Kyber round-3. */
                    QGP_LOG_ERROR(LOG_TAG,
                                  "Auth: server ML-KEM PK signature INVALID — "
                                  "pinned client refuses the Kyber fallback");
                    free_pending(client, req);
                    free(buf);
                    return -1;
                } else {
                    QGP_LOG_WARN(LOG_TAG,
                                 "Auth: server ML-KEM PK signature INVALID — "
                                 "falling back to Kyber round-3");
                }
            }

            /* D5 (N1 delta 1) — cache hygiene: this AUTH_OK is FRESH
             * (server sent kpk directly, not read from our own cache) and
             * SIGNED (kpk_sig just verified above). If it did not also
             * carry a verified mpk, the live server is the authority here
             * — clear any stale cached ML-KEM pubkey from a previous
             * session rather than silently keep using it. Two legitimate
             * ways to reach this: the server was rolled back to a
             * pre-Faz-1 build (identity.has_mlkem reverted to false), or
             * this connection landed on a DIFFERENT cluster server
             * (server_idx failover) that has not generated an ML-KEM key
             * yet. The reconnect-only cache branch below
             * (!resp->has_kyber_pk) is unaffected — it never heard from a
             * live server this round, so it keeps whatever it cached
             * last time. */
            if (!has_mpk) {
                client->has_cached_server_mlkem = false;
            }
        } else {
            /* Unpinned only — pin_check_auth_ok refused this AUTH_OK. */
            QGP_LOG_WARN(LOG_TAG, "Auth: server did not sign Kyber PK (legacy server)");
        }
    } else if (client->has_cached_server_kyber) {
        /* Unpinned only — pin_check_auth_ok refuses an AUTH_OK without kpk.
         * Reconnect: server didn't send kpk (old proto?) but we have cache */
        memcpy(server_kyber_pk, client->cached_server_kyber_pk, NODUS_KYBER_PK_BYTES);
        has_kpk = true;
        QGP_LOG_INFO(LOG_TAG, "Auth: using cached server Kyber pubkey");
        if (client->has_cached_server_mlkem) {
            memcpy(server_mlkem_pk, client->cached_server_mlkem_pk, NODUS_MLKEM_PK_BYTES);
            has_mpk = true;
            QGP_LOG_INFO(LOG_TAG, "Auth: using cached server ML-KEM pubkey");
        }
    }

    free_pending(client, req);

    /* has_kpk false = the session stays UNENCRYPTED. Unpinned only: with a
     * pin set, pin_check_auth_ok guaranteed a signed kpk above. */
    if (has_kpk) {
        uint8_t alg = has_mpk ? 1 : 0;
        QGP_LOG_INFO(LOG_TAG, "Auth: server supports channel encryption, initiating %s handshake",
                     has_mpk ? "ML-KEM-1024" : "Kyber round-3");

        /* Encapsulate: shared_secret = KEM_encap(ct, server_pk). Ciphertext
         * and shared-secret sizes are byte-identical between the two KEMs
         * (NODUS_KYBER_* == NODUS_MLKEM_* today), so one buffer pair
         * serves both. */
        uint8_t ct[NODUS_KYBER_CT_BYTES];
        uint8_t shared_secret[NODUS_KYBER_SS_BYTES];
        int enc_rc = has_mpk
            ? qgp_mlkem1024_encapsulate(ct, shared_secret, server_mlkem_pk)
            : qgp_kem1024_encapsulate(ct, shared_secret, server_kyber_pk);
        if (enc_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: KEM encapsulation failed");
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

        nodus_t2_key_init(txn, ct, nonce_c, alg, buf, CLIENT_BUF_SIZE, &len);
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

        /* Init channel crypto.
         * B3 fix — init the per-conn channel_crypto directly; storage is
         * now owned by the conn struct, no separate alias to attach. */
        /* We DIALED the server → initiator. */
        if (nodus_channel_crypto_init(&((nodus_tcp_conn_t *)client->conn)->channel_crypto,
                                       shared_secret, nonce_c, resp->key_nonce,
                                       NODUS_CHANNEL_ROLE_INITIATOR) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Auth: channel crypto init failed");
            qgp_secure_memzero(shared_secret, sizeof(shared_secret));
            free_pending(client, req);
            free(buf);
            return -1;
        }

        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        free_pending(client, req);

        /* Cache server pubkey(s) for reconnect */
        memcpy(client->cached_server_kyber_pk, server_kyber_pk, NODUS_KYBER_PK_BYTES);
        client->has_cached_server_kyber = true;
        if (has_mpk) {
            memcpy(client->cached_server_mlkem_pk, server_mlkem_pk, NODUS_MLKEM_PK_BYTES);
            client->has_cached_server_mlkem = true;
        }

        QGP_LOG_INFO(LOG_TAG, "Auth: channel encrypted (%s+AES-256-GCM)",
                     has_mpk ? "ML-KEM-1024" : "Kyber1024");
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
            int wait_ms = timeout_ms < 100 ? timeout_ms : 100;
            int rc = nodus_tcp_poll(tcp, wait_ms);
#ifdef __EMSCRIPTEN__
            /* nodus_tcp_poll does not wait in the browser build — the wait
             * the caller asked for is a yield to the event loop. */
            if (wait_ms > 0) emscripten_sleep((unsigned int)wait_ms);
#endif
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
#ifdef __EMSCRIPTEN__
    if (timeout_ms > 0) emscripten_sleep((unsigned int)timeout_ms);   /* see above */
#endif
    pthread_mutex_unlock(&client->poll_mutex);
    return rc;
}

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_KEEPALIVE
#endif
int nodus_client_tick(nodus_client_t *client) {
    if (!client || !client->tcp) return -1;

    /* A read thread already sends the keepalive and runs reconnect. */
    if (atomic_load(&client->read_thread_running))
        return 0;

    pthread_mutex_lock(&client->poll_mutex);
    keepalive_if_due(client);
    pthread_mutex_unlock(&client->poll_mutex);

    /* timeout 0: no wait of its own. A due reconnect still runs the full
     * connect + handshake, which yields (client_yield) while it waits — so
     * in the browser build this export must be called the async way
     * (Asyncify/JSPI), like every other export that can reach the network. */
    return nodus_client_poll(client, 0);
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
    pthread_mutex_destroy(&client->wbuf_mutex);
    pthread_mutex_destroy(&client->circuits_mutex);

    client->state = NODUS_CLIENT_DISCONNECTED;
    client->listen_count = 0;
    client->ch_sub_count = 0;
    nodus_identity_clear(&client->identity);
}

/* ── DHT Operations ─────────────────────────────────────────────── */

int nodus_client_put_ex(nodus_client_t *client,
                         const nodus_key_t *key,
                         const uint8_t *data, size_t data_len,
                         nodus_value_type_t type, uint32_t ttl,
                         uint64_t vid, uint64_t seq,
                         const nodus_sig_t *sig,
                         int timeout_ms) {
    if (!nodus_client_is_ready(client)) return -1;

    if (timeout_ms <= 0) timeout_ms = client->config.request_timeout_ms;

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
    if (!wait_response(client, req, timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    int rc = (resp->type == 'e') ? resp->error_code : 0;
    free_pending(client, req);
    return rc;
}

int nodus_client_put(nodus_client_t *client,
                      const nodus_key_t *key,
                      const uint8_t *data, size_t data_len,
                      nodus_value_type_t type, uint32_t ttl,
                      uint64_t vid, uint64_t seq,
                      const nodus_sig_t *sig) {
    return nodus_client_put_ex(client, key, data, data_len,
                                type, ttl, vid, seq, sig, 0);
}

/* Shared by nodus_client_get and nodus_client_get_strict. `strict` only
 * changes the answer when no value decoded: the lenient path returns
 * NODUS_ERR_NOT_FOUND as it always has; the strict path first checks, in the
 * raw reply the pending slot kept (client_on_frame), whether the node sent a
 * "val" at all (nodus_client_strict.h). */
static int client_get_impl(nodus_client_t *client, const nodus_key_t *key,
                           nodus_value_t **val_out, bool strict) {
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
        int rc = NODUS_ERR_NOT_FOUND;
        if (strict) {
            nodus_reply_value_shape_t shape;
            if (!req->raw_response ||
                nodus_client_reply_value_shape(req->raw_response,
                                               req->raw_response_len,
                                               &shape) != 0 ||
                shape.has_val) {
                QGP_LOG_WARN(LOG_TAG, "GET: the node sent a value that did "
                             "not decode (or the reply was not kept) — "
                             "reported as a protocol error, not as absent");
                rc = NODUS_ERR_PROTOCOL_ERROR;
            }
        }
        free_pending(client, req);
        return rc;
    }
    free_pending(client, req);
    return 0;
}

int nodus_client_get(nodus_client_t *client,
                      const nodus_key_t *key,
                      nodus_value_t **val_out) {
    return client_get_impl(client, key, val_out, false);
}

int nodus_client_get_strict(nodus_client_t *client,
                            const nodus_key_t *key,
                            nodus_value_t **val_out) {
    return client_get_impl(client, key, val_out, true);
}

/* Shared by nodus_client_get_all and nodus_client_get_all_strict.
 * `undecodable_out` NULL = the lenient path (unchanged behaviour). */
static int client_get_all_impl(nodus_client_t *client, const nodus_key_t *key,
                               nodus_value_t ***vals_out, size_t *count_out,
                               size_t *undecodable_out) {
    if (!nodus_client_is_ready(client) || !vals_out || !count_out) return -1;
    *vals_out = NULL;
    *count_out = 0;
    if (undecodable_out) *undecodable_out = 0;

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

    if (undecodable_out) {
        /* Everything the node put in "vals" that is not among the decoded
         * values: non-bstr items, refused values, items past the cap. */
        nodus_reply_value_shape_t shape;
        if (!req->raw_response ||
            nodus_client_reply_value_shape(req->raw_response,
                                           req->raw_response_len,
                                           &shape) != 0) {
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }
        size_t decoded = resp->values ? resp->value_count : 0;
        *undecodable_out = shape.vals_total > decoded
                               ? shape.vals_total - decoded : 0;
    }

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

int nodus_client_get_all(nodus_client_t *client,
                          const nodus_key_t *key,
                          nodus_value_t ***vals_out,
                          size_t *count_out) {
    return client_get_all_impl(client, key, vals_out, count_out, NULL);
}

int nodus_client_get_all_strict(nodus_client_t *client,
                                const nodus_key_t *key,
                                nodus_value_t ***vals_out,
                                size_t *count_out,
                                size_t *undecodable_out) {
    if (!undecodable_out) return -1;
    return client_get_all_impl(client, key, vals_out, count_out,
                               undecodable_out);
}

/* ── DHT Package A: owner-filtered get + paged get_all (client) ────
 *
 * New entry points only; nodus_client_get / get_all / get_batch above keep
 * their frames and answers (docs/plans/decisions/2026-09-29-dna-connect-
 * frozen.md). Wire: protocol/nodus_tier2.h "DHT Package A".
 *
 * ROLLING DEPLOY: a node that predates Package A skips "own", "pg" and
 * "after" and answers as before. The reply handling below therefore
 * re-applies every filter the request asked for:
 *   - a get_all reply without "more" is complete (more = 0);
 *   - rows whose key_hash is not the asked key are dropped;
 *   - with an owner filter, rows of other owners are dropped;
 *   - with a cursor, rows at or before it (signed PK order) are dropped;
 *   - with more = true, rows past "next" are dropped (they come back on the
 *     next page; the node trims to "next" itself, nodus_dht_page_finish).
 * The reply handlers are pure functions of the decoded reply — no clock, no
 * I/O — and are fed crafted replies by test_client_get_owner_page.c through
 * the NODUS_CLIENT_TEST_SEAM wrappers below. */

/* Storage primary-key order: owner_fp bytewise, then value_id as SIGNED
 * int64 (SQLite INTEGER). Mirrors nodus_dht_pk_cmp (nodus_server.c), which
 * the client library cannot link. */
static int client_pk_cmp(const nodus_key_t *a_owner, uint64_t a_vid,
                         const nodus_key_t *b_owner, uint64_t b_vid) {
    int c = memcmp(a_owner->bytes, b_owner->bytes, NODUS_KEY_BYTES);
    if (c != 0) return c;
    int64_t a = (int64_t)a_vid;
    int64_t b = (int64_t)b_vid;
    return (a > b) - (a < b);
}

/* Single owner-filtered GET reply. Takes the decoded value out of resp on
 * success. A row of another owner means the node ignored "own" (it predates
 * Package A): the owner's row may still exist, so this is NOT "not found" —
 * it is NODUS_ERR_UNAVAILABLE (the node could not answer the question). */
static int client_owner_result(nodus_tier2_msg_t *resp, const nodus_key_t *key,
                               const nodus_key_t *own, nodus_value_t **val_out) {
    *val_out = NULL;
    if (resp->type == 'e') return resp->error_code;
    if (!resp->value) return NODUS_ERR_NOT_FOUND;

    if (nodus_key_cmp(&resp->value->key_hash, key) != 0) {
        QGP_LOG_WARN(LOG_TAG, "GET(owner): the node returned a row of another "
                     "key — reported as a protocol error");
        return NODUS_ERR_PROTOCOL_ERROR;
    }
    if (nodus_key_cmp(&resp->value->owner_fp, own) != 0) {
        QGP_LOG_WARN(LOG_TAG, "GET(owner): the node returned a row of another "
                     "owner (it ignores the owner filter) — reported as "
                     "unavailable, not as absent");
        return NODUS_ERR_UNAVAILABLE;
    }
    *val_out = resp->value;
    resp->value = NULL;
    return 0;
}

/* Paged GET_ALL reply. On success takes the kept rows out of resp (the
 * dropped ones are freed) and sets more / next; on failure every output
 * stays empty. */
static int client_page_result(nodus_tier2_msg_t *resp, const nodus_key_t *key,
                              const nodus_key_t *own,
                              const nodus_dht_page_cursor_t *after,
                              nodus_value_t ***vals_out, size_t *count_out,
                              bool *more_out,
                              nodus_dht_page_cursor_t *cursor_out) {
    *vals_out = NULL;
    *count_out = 0;
    *more_out = false;
    memset(cursor_out, 0, sizeof(*cursor_out));
    if (resp->type == 'e') return resp->error_code;

    /* No "more" = a node that predates Package A: its reply is the whole
     * (legacy) get_all, i.e. complete. */
    bool more = resp->has_more && resp->more;
    if (more && !resp->has_next) {
        QGP_LOG_WARN(LOG_TAG, "GET_ALL(page): more=true without a next "
                     "cursor — protocol error");
        return NODUS_ERR_PROTOCOL_ERROR;
    }
    if (more && after &&
        client_pk_cmp(&resp->next.owner, resp->next.vid,
                      &after->owner_fp, after->value_id) <= 0) {
        /* A cursor that does not advance would page forever. */
        QGP_LOG_WARN(LOG_TAG, "GET_ALL(page): next cursor does not advance "
                     "past the request cursor — protocol error");
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    size_t kept = 0, dropped = 0;
    size_t n = resp->values ? resp->value_count : 0;
    for (size_t i = 0; i < n; i++) {
        nodus_value_t *v = resp->values[i];
        resp->values[i] = NULL;
        if (!v) continue;
        bool drop =
            nodus_key_cmp(&v->key_hash, key) != 0 ||
            (own && nodus_key_cmp(&v->owner_fp, own) != 0) ||
            (after && client_pk_cmp(&v->owner_fp, v->value_id,
                                    &after->owner_fp, after->value_id) <= 0) ||
            (more && client_pk_cmp(&v->owner_fp, v->value_id,
                                   &resp->next.owner, resp->next.vid) > 0);
        if (drop) {
            nodus_value_free(v);
            dropped++;
            continue;
        }
        resp->values[kept++] = v;
    }
    resp->value_count = kept;
    if (dropped > 0)
        QGP_LOG_DEBUG(LOG_TAG, "GET_ALL(page): dropped %zu row(s) outside "
                      "the asked key / owner / page", dropped);

    if (kept > 0) {
        /* Transfer ownership */
        *vals_out = resp->values;
        *count_out = kept;
        resp->values = NULL;
        resp->value_count = 0;
    }
    *more_out = more;
    if (more) {
        cursor_out->owner_fp = resp->next.owner;
        cursor_out->value_id = resp->next.vid;
    }
    return 0;
}

int nodus_client_get_owner(nodus_client_t *client,
                            const nodus_key_t *key,
                            const nodus_key_t *owner_fp,
                            nodus_value_t **val_out) {
    if (!nodus_client_is_ready(client) || !key || !owner_fp || !val_out) return -1;
    *val_out = NULL;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_get_owner(txn, client->token, key, owner_fp,
                            buf, CLIENT_BUF_SIZE, &len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    int rc = client_owner_result(resp, key, owner_fp, val_out);
    free_pending(client, req);
    return rc;
}

int nodus_client_get_all_page(nodus_client_t *client,
                               const nodus_key_t *key,
                               const nodus_key_t *owner_fp,
                               const nodus_dht_page_cursor_t *after,
                               nodus_value_t ***vals_out,
                               size_t *count_out,
                               bool *more_out,
                               nodus_dht_page_cursor_t *cursor_out) {
    if (!nodus_client_is_ready(client) || !key || !vals_out || !count_out ||
        !more_out || !cursor_out)
        return -1;
    *vals_out = NULL;
    *count_out = 0;
    *more_out = false;
    memset(cursor_out, 0, sizeof(*cursor_out));

    nodus_t2_cursor_t t2_after;
    nodus_t2_read_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.own = owner_fp;
    opts.page = true;
    if (after) {
        t2_after.owner = after->owner_fp;
        t2_after.vid = after->value_id;
        opts.after = &t2_after;
    }

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    size_t len = 0;
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    if (nodus_t2_get_all_ex(txn, client->token, key, &opts,
                             buf, CLIENT_BUF_SIZE, &len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    int rc = client_page_result(resp, key, owner_fp, after, vals_out, count_out,
                                more_out, cursor_out);
    free_pending(client, req);
    return rc;
}

#ifdef NODUS_CLIENT_TEST_SEAM
/* Test-only entry points to the two reply handlers above
 * (tests/test_client_get_owner_page.c). Same arrangement as the DNAC decoder
 * seam further down: compiled ONLY when a test target builds this TU itself
 * with NODUS_CLIENT_TEST_SEAM=1, never into libnodus. They decode the reply
 * bytes exactly as client_on_frame does (nodus_t2_decode) and run the same
 * handler the request function runs; they bypass nothing. A reply that does
 * not decode is NODUS_ERR_PROTOCOL_ERROR here (the live client drops such a
 * frame and the request times out). */
int nodus_client_test_owner_reply(const uint8_t *raw, size_t raw_len,
                                  const nodus_key_t *key,
                                  const nodus_key_t *owner_fp,
                                  nodus_value_t **val_out);
int nodus_client_test_page_reply(const uint8_t *raw, size_t raw_len,
                                 const nodus_key_t *key,
                                 const nodus_key_t *owner_fp,
                                 const nodus_dht_page_cursor_t *after,
                                 nodus_value_t ***vals_out, size_t *count_out,
                                 bool *more_out,
                                 nodus_dht_page_cursor_t *cursor_out);

int nodus_client_test_owner_reply(const uint8_t *raw, size_t raw_len,
                                  const nodus_key_t *key,
                                  const nodus_key_t *owner_fp,
                                  nodus_value_t **val_out) {
    *val_out = NULL;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(raw, raw_len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        return NODUS_ERR_PROTOCOL_ERROR;
    }
    int rc = client_owner_result(&msg, key, owner_fp, val_out);
    nodus_t2_msg_free(&msg);
    return rc;
}

int nodus_client_test_page_reply(const uint8_t *raw, size_t raw_len,
                                 const nodus_key_t *key,
                                 const nodus_key_t *owner_fp,
                                 const nodus_dht_page_cursor_t *after,
                                 nodus_value_t ***vals_out, size_t *count_out,
                                 bool *more_out,
                                 nodus_dht_page_cursor_t *cursor_out) {
    *vals_out = NULL;
    *count_out = 0;
    *more_out = false;
    memset(cursor_out, 0, sizeof(*cursor_out));
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(raw, raw_len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        return NODUS_ERR_PROTOCOL_ERROR;
    }
    int rc = client_page_result(&msg, key, owner_fp, after, vals_out,
                                count_out, more_out, cursor_out);
    nodus_t2_msg_free(&msg);
    return rc;
}
#endif /* NODUS_CLIENT_TEST_SEAM */

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

/* Track subscription in client->listen_keys[] so resubscribe_all() retries
 * it after reconnect. Safe to call from both success and timeout paths. */
static void track_listen_key(nodus_client_t *client, const nodus_key_t *key) {
    if (client->listen_count >= NODUS_CLIENT_MAX_LISTENS) return;
    for (int i = 0; i < client->listen_count; i++) {
        if (nodus_key_cmp(&client->listen_keys[i], key) == 0) return;
    }
    client->listen_keys[client->listen_count++] = *key;
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
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        /* Timeout: the LISTEN may or may not have been processed by the
         * server. Track the key anyway so (a) push events that arrive
         * before listen_ok are dispatched correctly, and (b) the next
         * reconnect resubscribes via resubscribe_all(). The alternative
         * is silent push loss until the caller retries by some other
         * code path. */
        track_listen_key(client, key);
        free_pending(client, req);
        return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        /* Server actively rejected — do NOT track. */
        int rc = resp->error_code;
        free_pending(client, req);
        return rc;
    }

    track_listen_key(client, key);
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

int nodus_client_reply_value_shape(const uint8_t *raw, size_t raw_len,
                                   nodus_reply_value_shape_t *out) {
    if (!raw || !out) return -1;
    memset(out, 0, sizeof(*out));

    cbor_decoder_t top_dec;
    cbor_decoder_init(&top_dec, raw, raw_len);
    if (cbor_decode_peek(&top_dec) != CBOR_ITEM_MAP) return -1;

    cbor_decoder_t dec;
    size_t n = 0;
    if (find_response_map(raw, raw_len, &dec, &n) != 0)
        return 0;                           /* a map without "r": no result */
    out->has_r = true;

    for (size_t i = 0; i < n; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type == CBOR_ITEM_ERROR || k.type == CBOR_ITEM_END) return -1;
        if (k.type == CBOR_ITEM_TSTR && k.tstr.len == 3 &&
            memcmp(k.tstr.ptr, "val", 3) == 0) {
            out->has_val = true;
            cbor_item_type_t t = cbor_decode_peek(&dec);
            if (t == CBOR_ITEM_BSTR) {
                out->val_is_bstr = true;
                cbor_decode_next(&dec);
            } else if (t == CBOR_ITEM_ERROR || t == CBOR_ITEM_END) {
                return -1;
            } else {
                cbor_decode_skip(&dec);
            }
        } else if (k.type == CBOR_ITEM_TSTR && k.tstr.len == 4 &&
                   memcmp(k.tstr.ptr, "vals", 4) == 0) {
            if (cbor_decode_peek(&dec) != CBOR_ITEM_ARRAY) {
                cbor_decode_skip(&dec);
                continue;
            }
            cbor_item_t arr = cbor_decode_next(&dec);
            out->has_vals = true;
            out->vals_total = arr.count;
            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_type_t t = cbor_decode_peek(&dec);
                if (t == CBOR_ITEM_ERROR || t == CBOR_ITEM_END) return -1;
                if (t == CBOR_ITEM_BSTR) {
                    out->vals_bstr++;
                    cbor_decode_next(&dec);
                } else {
                    cbor_decode_skip(&dec);
                }
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    return 0;
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

    /* Mempool block timer (5s) + BFT round + mesh stabilization */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, 60000)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    /* Decode spend result from raw response */
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* status 0 is APPROVED and result_out is zeroed above, so a reply
     * without a readable "status" must not read as acceptance. */
    bool has_status = false;
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "status", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) {
                result_out->status = (nodus_dnac_status_t)v.uint_val;
                has_status = true;
            }
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
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "bnr", 3) == 0) {
            /* Phase 13 / Task 13.2 — block_height the TX committed at */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->block_height = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ti", 2) == 0) {
            /* Phase 13 / Task 13.2 — tx_index within the block */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_index = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "cid", 3) == 0) {
            /* Phase 13 / Task 13.2 — chain_id binding */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 32)
                memcpy(result_out->chain_id, v.bstr.ptr, 32);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    if (!has_status) return NODUS_ERR_PROTOCOL_ERROR;
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

int nodus_client_dnac_chain_id32(nodus_client_t *client, bool *has_out,
                                 uint8_t chain_id32_out[32]) {
    if (!nodus_client_is_ready(client) || !has_out || !chain_id32_out)
        return -1;
    *has_out = false;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    /* SAME request as nodus_client_dnac_supply — the additive key rides
     * the existing dnac_supply reply (nodus_witness_handlers.c
     * handle_dnac_supply); this accessor just reads a different key out
     * of it, without touching that call's result struct. */
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

        if (key.tstr.len == 10 && memcmp(key.tstr.ptr, "chain_id32", 10) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 32) {
                memcpy(chain_id32_out, v.bstr.ptr, 32);
                *has_out = true;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

int nodus_client_dnac_fee_info(nodus_client_t *client,
                                nodus_dnac_fee_info_t *result_out) {
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

    enc_dnac_query(&enc, txn, client->token, "dnac_fee_info", 0);

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

        if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "base_fee", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->base_fee = v.uint_val;
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "mempool", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->mempool_count = v.uint_val;
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "min_fee", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->min_fee = v.uint_val;
        } else if (key.tstr.len == 9 && memcmp(key.tstr.ptr, "gas_price", 9) == 0) {
            /* HF-1: absent on an older server -> stays 0 (memset above),
             * which means "the price rule is off". */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->gas_price = v.uint_val;
        } else if (key.tstr.len == 16 &&
                   memcmp(key.tstr.ptr, "token_create_fee", 16) == 0) {
            /* W-C: absent on an older server -> stays 0 (memset above);
             * the caller then falls back to NODUS_W_TOKEN_CREATE_FEE. */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->token_create_fee = v.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

/* Response decoders split from their request functions so the decode can be
 * fed a crafted reply without a network (test_client_dup_array.c, through
 * the NODUS_CLIENT_TEST_SEAM wrappers at the end of the DNAC section). */
static int dnac_utxo_parse(const uint8_t *raw, size_t raw_len,
                           nodus_dnac_utxo_result_t *result_out);
static int dnac_ledger_range_parse(const uint8_t *raw, size_t raw_len,
                                   nodus_dnac_range_result_t *result_out);
static int dnac_block_parse(const uint8_t *raw, size_t raw_len,
                            nodus_dnac_block_result_t *result_out);

int nodus_client_dnac_utxo(nodus_client_t *client,
                             const char *owner,
                             int max_results,
                             nodus_dnac_utxo_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !owner || !result_out) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_utxo: precondition fail: ready=%d owner=%p result=%p",
                client ? nodus_client_is_ready(client) : 0, (void*)owner, (void*)result_out);
        return -1;
    }

    size_t olen = strlen(owner);
    QGP_LOG_DEBUG(LOG_TAG, "dnac_utxo: owner_start=%.8s owner_end=%.8s len=%zu max=%d",
                  owner, olen > 8 ? owner + olen - 8 : owner, olen, max_results);

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
    if (resp->type == 'e') {
        QGP_LOG_ERROR(LOG_TAG, "dnac_utxo: error response code=%d", resp->error_code);
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    QGP_LOG_DEBUG(LOG_TAG, "dnac_utxo: got response raw_len=%zu", req->raw_response_len);

    int prc = dnac_utxo_parse(req->raw_response, req->raw_response_len,
                              result_out);
    free_pending(client, req);
    return prc;
}

/* Decode a dnac_utxo reply ("r": {"count", "block_height", "utxos"}).
 * Returns 0, NODUS_ERR_PROTOCOL_ERROR (malformed: missing "r", a repeated
 * key) or NODUS_ERR_INTERNAL_ERROR (allocation); on any error no heap
 * array is left behind (nodus_client_free_utxo_result: entries NULL, count
 * 0 — scalar fields may hold what was decoded). P0-B (2026-09-28): a second "utxos" used to re-calloc
 * entries without resetting count and write at entries[count] — a heap
 * overflow driven by any server the client talks to. Every key of the
 * response map is now accepted once, and each entry write is bounded by the
 * capacity actually allocated. */
static int dnac_utxo_parse(const uint8_t *raw, size_t raw_len,
                           nodus_dnac_utxo_result_t *result_out) {
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(raw, raw_len, &dec, &mc) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_utxo: find_response_map failed");
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    QGP_LOG_DEBUG(LOG_TAG, "dnac_utxo: response map entries=%zu", mc);

    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    int count = 0;
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_utxo: repeated key in response — refused");
            nodus_client_free_utxo_result(result_out);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                count = (int)v.uint_val;
        } else if (key.tstr.len == 12 &&
                   memcmp(key.tstr.ptr, "block_height", 12) == 0) {
            /* Phase 7 / Task 38: latest committed block_height — anchor
             * target for each UTXO's state_root proof. Pre-Phase 7
             * witnesses omit this; result_out->block_height stays 0. */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->block_height = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "utxos", 5) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            size_t cap = arr.count;
            if (cap > 0) {
                result_out->entries = calloc(cap,
                                              sizeof(nodus_dnac_utxo_entry_t));
                if (!result_out->entries) return NODUS_ERR_INTERNAL_ERROR;
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_utxo_result(result_out);
                    return NODUS_ERR_PROTOCOL_ERROR;
                }

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
                               memcmp(ek.tstr.ptr, "tid", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 64)
                            memcpy(e->token_id, v.bstr.ptr, 64);
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
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "ub", 2) == 0) {
                        /* O15B §7 — cooldown lock height. Absent from a
                         * pre-O15B witness, in which case the memset above
                         * leaves it 0; see nodus_types.h for why 0 is the
                         * right default and what it does and does not mean. */
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->unlock_block = v.uint_val;
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "pr_s", 4) == 0) {
                        /* Phase 7 / Task 38: flat sibling buffer
                         * (depth * 64 bytes). Capped at struct capacity
                         * — oversize payloads are treated as missing. */
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len <= sizeof(e->proof_siblings)) {
                            memcpy(e->proof_siblings, v.bstr.ptr, v.bstr.len);
                        }
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "pr_p", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->proof_positions = (uint32_t)v.uint_val;
                    } else if (ek.tstr.len == 4 &&
                               memcmp(ek.tstr.ptr, "pr_d", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT &&
                            v.uint_val <= NODUS_DNAC_PROOF_MAX_DEPTH)
                            e->proof_depth = (uint32_t)v.uint_val;
                    } else if (ek.tstr.len == 2 &&
                               memcmp(ek.tstr.ptr, "sr", 2) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_DNAC_PROOF_HASH_LEN)
                            memcpy(e->proof_root, v.bstr.ptr,
                                   NODUS_DNAC_PROOF_HASH_LEN);
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

    QGP_LOG_DEBUG(LOG_TAG, "dnac_utxo: parsed server_count=%d result_count=%d",
                  count, result_out->count);

    (void)count;  /* Server count for cross-check, not used */
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

    int prc = dnac_ledger_range_parse(req->raw_response,
                                      req->raw_response_len, result_out);
    free_pending(client, req);
    return prc;
}

/* Decode a dnac_ledger_range reply ("r": {"total", "count", "entries"}).
 * Return values and cleanup as dnac_utxo_parse. P0-B (2026-09-28): a
 * "count" AFTER "entries" used to overwrite the decoded count with any
 * server-chosen value, so callers walked entries[] past its allocation.
 * result_out->count is now only ever the number of entries decoded; the
 * server's "count" is informational (the node writes it equal to the array
 * length, nodus_witness_handlers.c handle_dnac_ledger_range). */
static int dnac_ledger_range_parse(const uint8_t *raw, size_t raw_len,
                                   nodus_dnac_range_result_t *result_out) {
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(raw, raw_len, &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_ledger_range: repeated key in response — refused");
            nodus_client_free_range_result(result_out);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "total", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_entries = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            (void)v;   /* informational — the count is the decoded length */
        } else if (key.tstr.len == 7 &&
                   memcmp(key.tstr.ptr, "entries", 7) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            size_t cap = arr.count;
            if (cap > 0) {
                result_out->entries = calloc(cap,
                                              sizeof(nodus_dnac_range_entry_t));
                if (!result_out->entries) return NODUS_ERR_INTERNAL_ERROR;
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_range_result(result_out);
                    return NODUS_ERR_PROTOCOL_ERROR;
                }

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

    /* P0-B (2026-09-28): every response key once; "count" is informational
     * — a server "count" after "witnesses" used to overwrite the decoded
     * count and send callers past entries[NODUS_T3_MAX_WITNESSES]. */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_roster: repeated key in response — refused");
            memset(result_out, 0, sizeof(*result_out));
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "version", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->version = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 5 &&
                   memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            (void)v;   /* informational — the count is the decoded length */
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

void nodus_client_free_history_result(nodus_dnac_history_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
}

/* ── Transaction History Query ─────────────────────────────────── */

int nodus_client_dnac_history(nodus_client_t *client,
                                const char *owner,
                                int limit,
                                nodus_dnac_history_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !owner || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));
    if (limit <= 0) limit = NODUS_DNAC_MAX_HISTORY_RESULTS;
    if (limit > NODUS_DNAC_MAX_HISTORY_RESULTS)
        limit = NODUS_DNAC_MAX_HISTORY_RESULTS;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_history", 2);

    cbor_encode_cstr(&enc, "owner");
    cbor_encode_cstr(&enc, owner);
    cbor_encode_cstr(&enc, "limit");
    cbor_encode_uint(&enc, (uint64_t)limit);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* P0-B (2026-09-28): every response key once (a second "entries" used
     * to re-calloc without resetting count, then write past the new
     * allocation); entry writes bounded by the capacity allocated. */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_history: repeated key in response — refused");
            nodus_client_free_history_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            (void)v; /* count is informational */
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "entries", 7) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            size_t cap = arr.count;
            if (cap > 0) {
                result_out->entries = calloc(cap,
                                              sizeof(nodus_dnac_history_entry_t));
                if (!result_out->entries) { free_pending(client, req); return NODUS_ERR_INTERNAL_ERROR; }
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_history_result(result_out);
                    free_pending(client, req);
                    return NODUS_ERR_PROTOCOL_ERROR;
                }

                nodus_dnac_history_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }
                    if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "hash", 4) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_BSTR && ev.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(e->tx_hash, ev.bstr.ptr, NODUS_T3_TX_HASH_LEN);
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "type", 4) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT)
                            e->tx_type = (uint8_t)ev.uint_val;
                    } else if (ek.tstr.len == 6 && memcmp(ek.tstr.ptr, "sender", 6) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_TSTR && ev.tstr.len < 129) {
                            memcpy(e->sender_fp, ev.tstr.ptr, ev.tstr.len);
                            e->sender_fp[ev.tstr.len] = '\0';
                        }
                    } else if (ek.tstr.len == 3 && memcmp(ek.tstr.ptr, "fee", 3) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT) e->fee = ev.uint_val;
                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "bh", 2) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT) e->block_height = ev.uint_val;
                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "ts", 2) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT) e->timestamp = ev.uint_val;
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "pr_s", 4) == 0) {
                        /* Phase 7 / Task 39: per-TX tx_root proof siblings. */
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_BSTR &&
                            ev.bstr.len <= sizeof(e->proof_siblings)) {
                            memcpy(e->proof_siblings, ev.bstr.ptr, ev.bstr.len);
                        }
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "pr_p", 4) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT)
                            e->proof_positions = (uint32_t)ev.uint_val;
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "pr_d", 4) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT &&
                            ev.uint_val <= NODUS_DNAC_PROOF_MAX_DEPTH)
                            e->proof_depth = (uint32_t)ev.uint_val;
                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "tr", 2) == 0) {
                        /* Phase 7 / Task 39: tx_root (matches block.tx_root). */
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_BSTR &&
                            ev.bstr.len == NODUS_DNAC_PROOF_HASH_LEN)
                            memcpy(e->proof_root, ev.bstr.ptr,
                                   NODUS_DNAC_PROOF_HASH_LEN);
                    } else if (ek.tstr.len == 7 && memcmp(ek.tstr.ptr, "outputs", 7) == 0) {
                        cbor_item_t oarr = cbor_decode_next(&dec);
                        if (oarr.type != CBOR_ITEM_ARRAY) continue;
                        for (size_t oi = 0; oi < oarr.count; oi++) {
                            cbor_item_t omap = cbor_decode_next(&dec);
                            if (omap.type != CBOR_ITEM_MAP) continue;
                            nodus_dnac_history_output_t *o = NULL;
                            if (e->output_count < NODUS_DNAC_MAX_TX_OUTPUTS)
                                o = &e->outputs[e->output_count];
                            for (size_t om = 0; om < omap.count; om++) {
                                cbor_item_t ok = cbor_decode_next(&dec);
                                if (ok.type != CBOR_ITEM_TSTR) {
                                    cbor_decode_skip(&dec); continue;
                                }
                                if (ok.tstr.len == 2 && memcmp(ok.tstr.ptr, "fp", 2) == 0) {
                                    cbor_item_t ov = cbor_decode_next(&dec);
                                    if (o && ov.type == CBOR_ITEM_TSTR && ov.tstr.len < 129) {
                                        memcpy(o->owner_fp, ov.tstr.ptr, ov.tstr.len);
                                        o->owner_fp[ov.tstr.len] = '\0';
                                    }
                                } else if (ok.tstr.len == 3 && memcmp(ok.tstr.ptr, "amt", 3) == 0) {
                                    cbor_item_t ov = cbor_decode_next(&dec);
                                    if (o && ov.type == CBOR_ITEM_UINT) o->amount = ov.uint_val;
                                } else if (ok.tstr.len == 3 && memcmp(ok.tstr.ptr, "idx", 3) == 0) {
                                    cbor_item_t ov = cbor_decode_next(&dec);
                                    if (o && ov.type == CBOR_ITEM_UINT) o->output_index = (uint32_t)ov.uint_val;
                                } else if (ok.tstr.len == 3 && memcmp(ok.tstr.ptr, "tid", 3) == 0) {
                                    cbor_item_t ov = cbor_decode_next(&dec);
                                    if (o && ov.type == CBOR_ITEM_BSTR && ov.bstr.len == 64)
                                        memcpy(o->token_id, ov.bstr.ptr, 64);
                                } else if (ok.tstr.len == 4 && memcmp(ok.tstr.ptr, "memo", 4) == 0) {
                                    cbor_item_t ov = cbor_decode_next(&dec);
                                    if (o && ov.type == CBOR_ITEM_BSTR && ov.bstr.len > 0) {
                                        size_t mc = ov.bstr.len < sizeof(o->memo) - 1
                                                      ? ov.bstr.len : sizeof(o->memo) - 1;
                                        memcpy(o->memo, ov.bstr.ptr, mc);
                                        o->memo[mc] = '\0';
                                        o->memo_len = (uint8_t)mc;
                                    }
                                } else {
                                    cbor_decode_skip(&dec);
                                }
                            }
                            if (o) e->output_count++;
                        }
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

/* ── My Delegations Query (stake-delegation v1) ─────────────────── */

void nodus_client_free_delegations_result(nodus_dnac_delegations_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
}

int nodus_client_dnac_delegations(nodus_client_t *client,
                                    const uint8_t *delegator_pubkey,
                                    size_t pubkey_len,
                                    int max_results,
                                    nodus_dnac_delegations_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !delegator_pubkey || !result_out)
        return -1;
    /* Pubkey size is a protocol invariant — fail fast on any mismatch
     * rather than shipping a malformed frame that would be rejected
     * server-side with a less actionable error. */
    if (pubkey_len != NODUS_PK_BYTES)
        return -1;

    memset(result_out, 0, sizeof(*result_out));
    if (max_results <= 0) max_results = NODUS_DNAC_MAX_DELEGATIONS_RESULTS;
    if (max_results > NODUS_DNAC_MAX_DELEGATIONS_RESULTS)
        max_results = NODUS_DNAC_MAX_DELEGATIONS_RESULTS;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_delegations", 2);

    cbor_encode_cstr(&enc, "pubkey");
    cbor_encode_bstr(&enc, delegator_pubkey, pubkey_len);
    cbor_encode_cstr(&enc, "limit");
    cbor_encode_uint(&enc, (uint64_t)max_results);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* P0-B (2026-09-28): every response key once; entry writes bounded by
     * the capacity allocated (see nodus_client_dnac_history). */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_delegations: repeated key in response — refused");
            nodus_client_free_delegations_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            (void)v; /* informational — real count comes from array len below */
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "entries", 7) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            size_t cap = arr.count;
            if (cap > 0) {
                result_out->entries = calloc(cap,
                                              sizeof(nodus_dnac_delegation_entry_t));
                if (!result_out->entries) {
                    free_pending(client, req);
                    return NODUS_ERR_INTERNAL_ERROR;
                }
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_delegations_result(result_out);
                    free_pending(client, req);
                    return NODUS_ERR_PROTOCOL_ERROR;
                }

                nodus_dnac_delegation_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }
                    if (ek.tstr.len == 9 &&
                        memcmp(ek.tstr.ptr, "validator", 9) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_TSTR && ev.tstr.len < 129) {
                            memcpy(e->validator_fp, ev.tstr.ptr, ev.tstr.len);
                            e->validator_fp[ev.tstr.len] = '\0';
                        }
                    } else if (ek.tstr.len == 6 &&
                               memcmp(ek.tstr.ptr, "amount", 6) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT) e->amount = ev.uint_val;
                    } else if (ek.tstr.len == 5 &&
                               memcmp(ek.tstr.ptr, "block", 5) == 0) {
                        cbor_item_t ev = cbor_decode_next(&dec);
                        if (ev.type == CBOR_ITEM_UINT)
                            e->delegated_at_block = ev.uint_val;
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

    /* P0-B (2026-09-28): every response key once — a second "tx" used to
     * malloc over (and leak) the first tx_data. */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_tx: repeated key in response — refused");
            nodus_client_free_tx_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

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

/* ── Spend Replay (Fix #4 B) ─────────────────────────────────────── */

/* Request a fresh spndrslt receipt for a previously-committed TX. Used by
 * DNAC clients that timed out on dnac_spend and want to recover the
 * receipt instead of retrying the spend (which would trigger
 * DOUBLE_SPEND). Returns 0 on found and populated, NODUS_ERR_NOT_FOUND
 * if the TX is not in the committed ledger, other NODUS_ERR_* otherwise. */
int nodus_client_dnac_spend_replay(nodus_client_t *client,
                                    const uint8_t *tx_hash,
                                    nodus_dnac_spend_result_t *result_out) {
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

    enc_dnac_query(&enc, txn, client->token, "dnac_spend_replay", 1);
    cbor_encode_cstr(&enc, "h");
    cbor_encode_bstr(&enc, tx_hash, NODUS_T3_TX_HASH_LEN);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req);
        return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code;
        free_pending(client, req);
        return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    bool found = false;
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL) found = v.bool_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "status", 6) == 0) {
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
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "bnr", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->block_height = v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ti", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_index = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "cid", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 32)
                memcpy(result_out->chain_id, v.bstr.ptr, 32);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "wsig", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_SIG_BYTES)
                memcpy(result_out->signature, v.bstr.ptr, NODUS_SIG_BYTES);
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return found ? 0 : NODUS_ERR_NOT_FOUND;
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

    int prc = dnac_block_parse(req->raw_response, req->raw_response_len,
                               result_out);
    free_pending(client, req);
    return prc;
}

/* Decode a dnac_block reply. Return values and cleanup as dnac_utxo_parse.
 * P0-B (2026-09-28): a second "commit_cert" used to re-calloc the array
 * WITHOUT resetting commit_cert_count, so a shorter second array was
 * written past its end. Every key of the response map is now accepted
 * once, and each signature write is bounded by the capacity allocated. */
static int dnac_block_parse(const uint8_t *raw, size_t raw_len,
                            nodus_dnac_block_result_t *result_out) {
    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(raw, raw_len, &dec, &mc) != 0)
        return NODUS_ERR_PROTOCOL_ERROR;

    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_block: repeated key in response — refused");
            nodus_client_free_block_result(result_out);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

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
        } else if (key.tstr.len == 9 && memcmp(key.tstr.ptr, "prev_hash", 9) == 0) {
            /* Phase 7 / Task 37 extended fields. */
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->prev_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 10 && memcmp(key.tstr.ptr, "state_root", 10) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->state_root, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "tx_root", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_root, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "tx_count", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_count = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 11 && memcmp(key.tstr.ptr, "commit_cert", 11) == 0) {
            /* Phase 7 / Task 37: array of {signer_id, sig} maps.
             * Pre-Phase 7 witnesses omit this — commit_cert stays NULL. */
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) { continue; }
            if (arr.count > 0 && arr.count <= NODUS_T3_MAX_WITNESSES) {
                result_out->commit_cert = calloc(arr.count,
                                                   sizeof(nodus_dnac_commit_sig_t));
                if (result_out->commit_cert) {
                    for (size_t ci = 0; ci < arr.count; ci++) {
                        cbor_item_t cmap = cbor_decode_next(&dec);
                        if (cmap.type != CBOR_ITEM_MAP) continue;
                        if ((size_t)result_out->commit_cert_count >= arr.count) {
                            nodus_client_free_block_result(result_out);
                            return NODUS_ERR_PROTOCOL_ERROR;
                        }
                        nodus_dnac_commit_sig_t *sig =
                            &result_out->commit_cert[result_out->commit_cert_count];
                        bool have_signer = false, have_sig = false;
                        for (size_t cm = 0; cm < cmap.count; cm++) {
                            cbor_item_t ck = cbor_decode_next(&dec);
                            if (ck.type != CBOR_ITEM_TSTR) {
                                cbor_decode_skip(&dec); continue;
                            }
                            if (ck.tstr.len == 9 &&
                                memcmp(ck.tstr.ptr, "signer_id", 9) == 0) {
                                cbor_item_t cv = cbor_decode_next(&dec);
                                if (cv.type == CBOR_ITEM_BSTR &&
                                    cv.bstr.len == NODUS_T3_WITNESS_ID_LEN) {
                                    memcpy(sig->signer_id, cv.bstr.ptr,
                                           NODUS_T3_WITNESS_ID_LEN);
                                    have_signer = true;
                                }
                            } else if (ck.tstr.len == 3 &&
                                       memcmp(ck.tstr.ptr, "sig", 3) == 0) {
                                cbor_item_t cv = cbor_decode_next(&dec);
                                if (cv.type == CBOR_ITEM_BSTR &&
                                    cv.bstr.len == NODUS_SIG_BYTES) {
                                    memcpy(sig->signature, cv.bstr.ptr,
                                           NODUS_SIG_BYTES);
                                    have_sig = true;
                                }
                            } else {
                                cbor_decode_skip(&dec);
                            }
                        }
                        if (have_signer && have_sig)
                            result_out->commit_cert_count++;
                    }
                } else {
                    /* calloc failed — skip the array contents. */
                    for (size_t ci = 0; ci < arr.count; ci++)
                        cbor_decode_skip(&dec);
                }
            } else {
                for (size_t ci = 0; ci < arr.count; ci++)
                    cbor_decode_skip(&dec);
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

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

    /* P0-B (2026-09-28): every response key once; "count" is informational
     * (a "count" after "blocks" used to overwrite the decoded count — and on
     * a failed calloc it was the ONLY count, beside a NULL blocks array);
     * block writes bounded by the capacity allocated. */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_block_range: repeated key in response — refused");
            nodus_client_free_block_range_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "total", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->total_blocks = v.uint_val;
        } else if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "count", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            (void)v;   /* informational — the count is the decoded length */
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "blocks", 6) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            size_t cap = arr.count;
            if (cap > 0) {
                result_out->blocks = calloc(cap,
                                              sizeof(nodus_dnac_block_result_t));
                if (!result_out->blocks) {
                    free_pending(client, req);
                    return NODUS_ERR_INTERNAL_ERROR;
                }
            }

            result_out->count = 0;
            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) {
                    cbor_decode_skip(&dec);
                    continue;
                }
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_block_range_result(result_out);
                    free_pending(client, req);
                    return NODUS_ERR_PROTOCOL_ERROR;
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
                    } else if (ek.tstr.len == 7 && memcmp(ek.tstr.ptr, "tx_root", 7) == 0) {
                        /* 2026-08-04: explicit tx_root key (the legacy
                         * "hash" key lands in tx_hash above). Pre-fix
                         * servers omit it — tx_root stays zeroed. */
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                            memcpy(b->tx_root, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
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

void nodus_client_free_block_result(nodus_dnac_block_result_t *result) {
    if (!result) return;
    free(result->commit_cert);
    result->commit_cert = NULL;
    result->commit_cert_count = 0;
}

/* ── Genesis Block Query (Phase 2 / Task 36) ────────────────────── */

int nodus_client_dnac_genesis(nodus_client_t *client,
                                nodus_dnac_genesis_result_t *result_out) {
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

    /* Request: "a" map has no args — pass map_count=0 to enc_dnac_query. */
    enc_dnac_query(&enc, txn, client->token, "dnac_genesis", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* P0-B (2026-09-28): every response key once — a second "chain_def"
     * used to malloc over (and leak) the first blob. */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_genesis: repeated key in response — refused");
            nodus_client_free_genesis_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 5 && memcmp(key.tstr.ptr, "found", 5) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BOOL) result_out->found = v.bool_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "height", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->height = v.uint_val;
        } else if (key.tstr.len == 9 && memcmp(key.tstr.ptr, "prev_hash", 9) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->prev_hash, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 10 && memcmp(key.tstr.ptr, "state_root", 10) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->state_root, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "tx_root", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(result_out->tx_root, v.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "tx_count", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->tx_count = (uint32_t)v.uint_val;
        } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ts", 2) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->timestamp = v.uint_val;
        } else if (key.tstr.len == 8 && memcmp(key.tstr.ptr, "proposer", 8) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(result_out->proposer_id, v.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        } else if (key.tstr.len == 9 && memcmp(key.tstr.ptr, "chain_def", 9) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len > 0) {
                result_out->chain_def_blob = malloc(v.bstr.len);
                if (result_out->chain_def_blob) {
                    memcpy(result_out->chain_def_blob, v.bstr.ptr, v.bstr.len);
                    result_out->chain_def_blob_len = v.bstr.len;
                }
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_genesis_result(nodus_dnac_genesis_result_t *result) {
    if (!result) return;
    free(result->chain_def_blob);
    result->chain_def_blob = NULL;
    result->chain_def_blob_len = 0;
}

/* ── Token query functions ───────────────────────────────────────── */

int nodus_client_dnac_token_list(nodus_client_t *client,
                                   nodus_dnac_token_list_result_t *result_out) {
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

    enc_dnac_query(&enc, txn, client->token, "dnac_token_list", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* P0-B (2026-09-28): every response key once; token writes bounded by
     * the capacity allocated (see nodus_client_dnac_history). */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_token_list: repeated key in response — refused");
            nodus_client_free_token_list_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "tokens", 6) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;

            size_t cap = arr.count;
            if (cap > 0) {
                result_out->tokens = calloc(cap,
                                              sizeof(nodus_dnac_token_info_t));
                if (!result_out->tokens) { free_pending(client, req); return NODUS_ERR_INTERNAL_ERROR; }
            }

            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_token_list_result(result_out);
                    free_pending(client, req);
                    return NODUS_ERR_PROTOCOL_ERROR;
                }

                nodus_dnac_token_info_t *t =
                    &result_out->tokens[result_out->count];
                memset(t, 0, sizeof(*t));

                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }

                    if (ek.tstr.len == 3 && memcmp(ek.tstr.ptr, "tid", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 64)
                            memcpy(t->token_id, v.bstr.ptr, 64);
                    } else if (ek.tstr.len == 4 && memcmp(ek.tstr.ptr, "name", 4) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(t->name) - 1 ?
                                        v.tstr.len : sizeof(t->name) - 1;
                            memcpy(t->name, v.tstr.ptr, cl);
                        }
                    } else if (ek.tstr.len == 3 && memcmp(ek.tstr.ptr, "sym", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(t->symbol) - 1 ?
                                        v.tstr.len : sizeof(t->symbol) - 1;
                            memcpy(t->symbol, v.tstr.ptr, cl);
                        }
                    } else if (ek.tstr.len == 3 && memcmp(ek.tstr.ptr, "dec", 3) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            t->decimals = (uint8_t)v.uint_val;
                    } else if (ek.tstr.len == 6 && memcmp(ek.tstr.ptr, "supply", 6) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            t->supply = v.uint_val;
                    } else if (ek.tstr.len == 7 && memcmp(ek.tstr.ptr, "creator", 7) == 0) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(t->creator_fp) - 1 ?
                                        v.tstr.len : sizeof(t->creator_fp) - 1;
                            memcpy(t->creator_fp, v.tstr.ptr, cl);
                        }
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

int nodus_client_dnac_token_info(nodus_client_t *client,
                                   const uint8_t *token_id,
                                   nodus_dnac_token_info_t *result_out) {
    if (!nodus_client_is_ready(client) || !token_id || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_token_info", 1);

    cbor_encode_cstr(&enc, "tid");
    cbor_encode_bstr(&enc, token_id, 64);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

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

        if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "tid", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 64)
                memcpy(result_out->token_id, v.bstr.ptr, 64);
        } else if (key.tstr.len == 4 && memcmp(key.tstr.ptr, "name", 4) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_TSTR) {
                size_t cl = v.tstr.len < sizeof(result_out->name) - 1 ?
                            v.tstr.len : sizeof(result_out->name) - 1;
                memcpy(result_out->name, v.tstr.ptr, cl);
            }
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "sym", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_TSTR) {
                size_t cl = v.tstr.len < sizeof(result_out->symbol) - 1 ?
                            v.tstr.len : sizeof(result_out->symbol) - 1;
                memcpy(result_out->symbol, v.tstr.ptr, cl);
            }
        } else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "dec", 3) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->decimals = (uint8_t)v.uint_val;
        } else if (key.tstr.len == 6 && memcmp(key.tstr.ptr, "supply", 6) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT)
                result_out->supply = v.uint_val;
        } else if (key.tstr.len == 7 && memcmp(key.tstr.ptr, "creator", 7) == 0) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_TSTR) {
                size_t cl = v.tstr.len < sizeof(result_out->creator_fp) - 1 ?
                            v.tstr.len : sizeof(result_out->creator_fp) - 1;
                memcpy(result_out->creator_fp, v.tstr.ptr, cl);
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    free_pending(client, req);
    return 0;
}

void nodus_client_free_token_list_result(nodus_dnac_token_list_result_t *result) {
    if (!result) return;
    free(result->tokens);
    result->tokens = NULL;
    result->count = 0;
}

/* ── Phase 14 / stake-delegation v1 RPCs (Task 64) ────────────────── */

/* CBOR key-string match helper, mirrors roster-query pattern. */
#define KEY_EQ(k, s) \
    ((k).tstr.len == (sizeof(s) - 1) && \
     memcmp((k).tstr.ptr, (s), sizeof(s) - 1) == 0)

/* v0.16: nodus_client_dnac_pending_rewards +
 * nodus_client_free_pending_rewards_result removed with the
 * dnac_pending_rewards_query RPC. Settlement distributes rewards as
 * UTXOs so the client has no pending balance to query. */

int nodus_client_dnac_committee(nodus_client_t *client,
                                  nodus_dnac_committee_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out) return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_committee_query", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* P0-B (2026-09-28): every response key once. The entry writes are
     * already bounded by the fixed entries[] capacity below. */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_committee: repeated key in response — refused");
            memset(result_out, 0, sizeof(*result_out));
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (KEY_EQ(key, "block_height")) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->block_height = v.uint_val;
        } else if (KEY_EQ(key, "epoch_start")) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->epoch_start = v.uint_val;
        } else if (KEY_EQ(key, "committee")) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;
            size_t cap = sizeof(result_out->entries) /
                          sizeof(result_out->entries[0]);
            for (size_t j = 0; j < arr.count && result_out->count < (int)cap; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                nodus_dnac_committee_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));
                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }
                    if (KEY_EQ(ek, "pk")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_PK_BYTES) {
                            memcpy(e->pubkey, v.bstr.ptr, NODUS_PK_BYTES);
                        }
                    } else if (KEY_EQ(ek, "stake")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) e->total_stake = v.uint_val;
                    } else if (KEY_EQ(ek, "comm")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->commission_bps = (uint16_t)v.uint_val;
                    } else if (KEY_EQ(ek, "status")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->status = (uint8_t)v.uint_val;
                    } else if (KEY_EQ(ek, "addr")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_TSTR) {
                            size_t cl = v.tstr.len < sizeof(e->address) - 1 ?
                                        v.tstr.len : sizeof(e->address) - 1;
                            memcpy(e->address, v.tstr.ptr, cl);
                            e->address[cl] = '\0';
                        }
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

/* ── dnac_cc_collect (decision 2026-09-26-cc-approval-via-own-node.md) ── */

int nodus_dnac_cc_collect_decode(const uint8_t *raw, size_t raw_len,
                                 nodus_dnac_cc_collect_result_t *result_out) {
    if (!raw || !result_out) return -1;
    memset(result_out, 0, sizeof(*result_out));

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(raw, raw_len, &dec, &mc) != 0) return -1;

    bool have_res = false;
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        /* cbor_decode_next reports running off the buffer as
         * CBOR_ITEM_END WITHOUT setting dec.error (nodus_cbor.c:195-197),
         * so a map short of its claimed pairs must be caught here. */
        if (key.type == CBOR_ITEM_END || key.type == CBOR_ITEM_ERROR)
            return -1;
        if (key.type != CBOR_ITEM_TSTR || !KEY_EQ(key, "res")) {
            cbor_decode_skip(&dec);
            continue;
        }
        /* One "res" key only. A second one would append its entries after
         * the first's (`count` runs on across both) and index past
         * `entries[]` — the node's encoder writes exactly one (no
         * reference counterpart: a nodus 4001 reply). */
        if (have_res) return -1;
        cbor_item_t arr = cbor_decode_next(&dec);
        size_t cap = sizeof(result_out->entries) / sizeof(result_out->entries[0]);
        if (arr.type != CBOR_ITEM_ARRAY || arr.count > cap) return -1;
        for (size_t j = 0; j < arr.count; j++) {
            cbor_item_t emap = cbor_decode_next(&dec);
            if (emap.type != CBOR_ITEM_MAP) return -1;
            nodus_dnac_cc_collect_entry_t *e = &result_out->entries[j];
            bool have_i = false, have_st = false;
            for (size_t k = 0; k < emap.count; k++) {
                cbor_item_t ek = cbor_decode_next(&dec);
                if (ek.type == CBOR_ITEM_END || ek.type == CBOR_ITEM_ERROR)
                    return -1;
                if (ek.type != CBOR_ITEM_TSTR) {
                    cbor_decode_skip(&dec);
                    continue;
                }
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_END) return -1;
                if (KEY_EQ(ek, "i") && v.type == CBOR_ITEM_UINT &&
                    v.uint_val <= UINT16_MAX) {
                    e->seat = (uint16_t)v.uint_val;
                    have_i = true;
                } else if (KEY_EQ(ek, "st") && v.type == CBOR_ITEM_UINT &&
                           v.uint_val <= UINT8_MAX) {
                    e->status = (uint8_t)v.uint_val;
                    have_st = true;
                } else if (KEY_EQ(ek, "ok") && v.type == CBOR_ITEM_BOOL) {
                    e->ok = v.bool_val;
                } else if (KEY_EQ(ek, "rs") && v.type == CBOR_ITEM_UINT &&
                           v.uint_val <= UINT16_MAX) {
                    e->rsp_seat = (uint16_t)v.uint_val;
                } else if (KEY_EQ(ek, "s") && v.type == CBOR_ITEM_BSTR &&
                           v.bstr.len == NODUS_SIG_BYTES) {
                    memcpy(e->sig, v.bstr.ptr, NODUS_SIG_BYTES);
                } else if (KEY_EQ(ek, "sh") && v.type == CBOR_ITEM_BSTR &&
                           v.bstr.len == 64) {
                    memcpy(e->set_hash, v.bstr.ptr, 64);
                } else if (KEY_EQ(ek, "ep") && v.type == CBOR_ITEM_UINT) {
                    e->epoch = v.uint_val;
                } else if (KEY_EQ(ek, "r") && v.type == CBOR_ITEM_TSTR) {
                    size_t cl = v.tstr.len < sizeof(e->reason) - 1 ?
                                v.tstr.len : sizeof(e->reason) - 1;
                    memcpy(e->reason, v.tstr.ptr, cl);
                    e->reason[cl] = '\0';
                } else if (v.type == CBOR_ITEM_ARRAY || v.type == CBOR_ITEM_MAP ||
                           v.type == CBOR_ITEM_ERROR) {
                    return -1;     /* no entry value is a container */
                }
            }
            if (!have_i || !have_st) return -1;
            result_out->count++;
        }
        have_res = true;
    }
    /* A truncated argument or payload sets the decoder's sticky flag;
     * running off the END of the buffer does not (CBOR_ITEM_END, checked
     * at each key read above) — ORCHESTRATOR repair, test_cc_collect
     * decode_hardening RED on the first cut. */
    if (dec.error) return -1;
    return have_res ? 0 : -1;
}

int nodus_client_dnac_cc_collect(nodus_client_t *client,
                                 const uint8_t *env_bytes, size_t env_len,
                                 nodus_dnac_cc_collect_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !env_bytes || env_len == 0 ||
        env_len > NODUS_T3_CC_APPR_E_MAX || !result_out)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    /* Sized to the envelope — an approval envelope for a large committee
     * exceeds CLIENT_BUF_SIZE. 512 bytes cover the header, the token and
     * the key. */
    size_t cap = env_len + 512;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_cc_collect", 1);
    cbor_encode_cstr(&enc, "e");
    cbor_encode_bstr(&enc, env_bytes, env_len);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    /* The node answers when every asked seat answered or its own
     * collection deadline passed — never sooner than it can; wait past
     * that deadline (NODUS_DNAC_CC_COLLECT_TIMEOUT_MS). */
    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    int wait_ms = client->config.request_timeout_ms > NODUS_DNAC_CC_COLLECT_TIMEOUT_MS
                  ? client->config.request_timeout_ms
                  : NODUS_DNAC_CC_COLLECT_TIMEOUT_MS;
    if (!wait_response(client, req, wait_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        QGP_LOG_WARN(LOG_TAG, "dnac_cc_collect refused by the node: %s",
                     resp->error_msg);
        int rc = resp->error_code; free_pending(client, req); return rc;
    }
    int drc = nodus_dnac_cc_collect_decode(req->raw_response,
                                           req->raw_response_len, result_out);
    free_pending(client, req);
    return drc == 0 ? 0 : NODUS_ERR_PROTOCOL_ERROR;
}

/* ── dnac_v3_block (scan-v3; wire: nodus.h) ───────────────────────────
 *
 * The decoder treats the reply as HOSTILE (design G4): every read checks
 * CBOR_ITEM_END / CBOR_ITEM_ERROR (nodus_cbor.c reports running off the
 * buffer as END WITHOUT setting dec.error — the nodus_dnac_cc_collect_
 * decode lesson), every container count is bounded against the bytes
 * left BEFORE it is walked, every map refuses a duplicate key, unknown
 * keys are skipped by a walker that itself refuses truncation, and
 * dec.error is checked at the end. */

/** Keys seen in one map — a duplicate (or more than V3D_MAX_KEYS keys)
 *  refuses the reply. */
#define V3D_MAX_KEYS 32
typedef struct {
    const char *p[V3D_MAX_KEYS];
    size_t      l[V3D_MAX_KEYS];
    size_t      n;
} v3d_keys_t;

static int v3d_key_add(v3d_keys_t *ks, const cbor_item_t *k)
{
    for (size_t j = 0; j < ks->n; j++)
        if (ks->l[j] == k->tstr.len &&
            memcmp(ks->p[j], k->tstr.ptr, k->tstr.len) == 0)
            return -1;                           /* duplicate key       */
    if (ks->n >= V3D_MAX_KEYS) return -1;
    ks->p[ks->n] = k->tstr.ptr;
    ks->l[ks->n] = k->tstr.len;
    ks->n++;
    return 0;
}

static size_t v3d_left(const cbor_decoder_t *d)
{
    return d->pos < d->len ? d->len - d->pos : 0;
}

static int v3d_next(cbor_decoder_t *d, cbor_item_t *it)
{
    *it = cbor_decode_next(d);
    if (it->type == CBOR_ITEM_END || it->type == CBOR_ITEM_ERROR || d->error)
        return -1;
    /* a container can never claim more elements than bytes remain */
    if (it->type == CBOR_ITEM_ARRAY && it->count > v3d_left(d)) return -1;
    if (it->type == CBOR_ITEM_MAP && it->count > v3d_left(d) / 2) return -1;
    return 0;
}

/** Skip one value, refusing truncation anywhere inside it. */
static int v3d_skip(cbor_decoder_t *d, int depth)
{
    cbor_item_t it;
    if (depth > 8 || v3d_next(d, &it) != 0) return -1;
    if (it.type == CBOR_ITEM_ARRAY) {
        for (size_t j = 0; j < it.count; j++)
            if (v3d_skip(d, depth + 1) != 0) return -1;
    } else if (it.type == CBOR_ITEM_MAP) {
        for (size_t j = 0; j < it.count * 2; j++)
            if (v3d_skip(d, depth + 1) != 0) return -1;
    }
    return 0;
}

/** The next map KEY: a text string, not seen before in this map. */
static int v3d_key(cbor_decoder_t *d, v3d_keys_t *ks, cbor_item_t *k)
{
    if (v3d_next(d, k) != 0 || k->type != CBOR_ITEM_TSTR) return -1;
    return v3d_key_add(ks, k);
}

static int v3d_u64(cbor_decoder_t *d, uint64_t max, uint64_t *out)
{
    cbor_item_t v;
    if (v3d_next(d, &v) != 0 || v.type != CBOR_ITEM_UINT ||
        v.uint_val > max)
        return -1;
    *out = v.uint_val;
    return 0;
}

static int v3d_b64(cbor_decoder_t *d, uint8_t out[64])
{
    cbor_item_t v;
    if (v3d_next(d, &v) != 0 || v.type != CBOR_ITEM_BSTR ||
        v.bstr.len != 64)
        return -1;
    memcpy(out, v.bstr.ptr, 64);
    return 0;
}

/** A fingerprint: exactly 128 lowercase hex characters. */
static int v3d_hex128(cbor_decoder_t *d, char out[129])
{
    cbor_item_t v;
    if (v3d_next(d, &v) != 0 || v.type != CBOR_ITEM_TSTR ||
        v.tstr.len != 128)
        return -1;
    for (size_t j = 0; j < 128; j++) {
        char ch = v.tstr.ptr[j];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            return -1;
    }
    memcpy(out, v.tstr.ptr, 128);
    out[128] = '\0';
    return 0;
}

static int v3d_coin(cbor_decoder_t *d, nodus_dnac_v3_coin_t *c)
{
    cbor_item_t m, k;
    v3d_keys_t  ks;
    unsigned    have = 0;

    memset(&ks, 0, sizeof(ks));
    if (v3d_next(d, &m) != 0 || m.type != CBOR_ITEM_MAP) return -1;
    for (size_t j = 0; j < m.count; j++) {
        if (v3d_key(d, &ks, &k) != 0) return -1;
        if (KEY_EQ(k, "id")) {
            if (v3d_b64(d, c->id) != 0) return -1;
            have |= 1u;
        } else if (KEY_EQ(k, "o")) {
            if (v3d_hex128(d, c->owner) != 0) return -1;
            have |= 2u;
        } else if (KEY_EQ(k, "a")) {
            if (v3d_u64(d, UINT64_MAX, &c->amount) != 0) return -1;
            have |= 4u;
        } else if (KEY_EQ(k, "t")) {
            if (v3d_b64(d, c->token_id) != 0) return -1;
            have |= 8u;
        } else if (KEY_EQ(k, "u")) {
            if (v3d_u64(d, UINT64_MAX, &c->unlock_block) != 0) return -1;
            have |= 16u;
        } else if (v3d_skip(d, 0) != 0) {
            return -1;
        }
    }
    return have == 31u ? 0 : -1;
}

static int v3d_record(cbor_decoder_t *d, nodus_dnac_v3_item_t *it)
{
    cbor_item_t m, k;
    v3d_keys_t  ks;
    uint64_t    v;

    memset(&ks, 0, sizeof(ks));
    if (v3d_next(d, &m) != 0 || m.type != CBOR_ITEM_MAP) return -1;
    for (size_t j = 0; j < m.count; j++) {
        if (v3d_key(d, &ks, &k) != 0) return -1;
        if (KEY_EQ(k, "k")) {
            if (v3d_u64(d, NODUS_DNAC_V3_REC_CHAIN_CONFIG, &v) != 0 ||
                v == NODUS_DNAC_V3_REC_NONE)
                return -1;
            it->rec_kind = (uint8_t)v;
        } else if (KEY_EQ(k, "v")) {
            if (v3d_hex128(d, it->rec_validator_fp) != 0) return -1;
        } else if (KEY_EQ(k, "d")) {
            if (v3d_hex128(d, it->rec_delegator_fp) != 0) return -1;
        } else if (KEY_EQ(k, "ds")) {
            if (v3d_hex128(d, it->rec_dest_fp) != 0) return -1;
        } else if (KEY_EQ(k, "a")) {
            if (v3d_u64(d, UINT64_MAX, &it->rec_amount) != 0) return -1;
        } else if (KEY_EQ(k, "cm")) {
            if (v3d_u64(d, UINT16_MAX, &v) != 0) return -1;
            it->rec_commission_bps = (uint16_t)v;
        } else if (KEY_EQ(k, "p")) {
            if (v3d_u64(d, UINT8_MAX, &v) != 0) return -1;
            it->cc_param_id = (uint8_t)v;
        } else if (KEY_EQ(k, "nv")) {
            if (v3d_u64(d, UINT64_MAX, &it->cc_new_value) != 0) return -1;
        } else if (KEY_EQ(k, "ef")) {
            if (v3d_u64(d, UINT64_MAX, &it->cc_effective) != 0) return -1;
        } else if (v3d_skip(d, 0) != 0) {
            return -1;
        }
    }
    return it->rec_kind != NODUS_DNAC_V3_REC_NONE ? 0 : -1;
}

static int v3d_item(cbor_decoder_t *d, nodus_dnac_v3_item_t *it)
{
    cbor_item_t m, k, a;
    v3d_keys_t  ks;
    uint64_t    v;
    unsigned    have = 0;                /* 1 i, 2 k, 4 c, 8 sp, 16 cr   */

    memset(&ks, 0, sizeof(ks));
    if (v3d_next(d, &m) != 0 || m.type != CBOR_ITEM_MAP) return -1;
    for (size_t j = 0; j < m.count; j++) {
        if (v3d_key(d, &ks, &k) != 0) return -1;
        if (KEY_EQ(k, "i")) {
            if (v3d_u64(d, UINT32_MAX, &v) != 0) return -1;
            it->index = (uint32_t)v;
            have |= 1u;
        } else if (KEY_EQ(k, "k")) {
            if (v3d_u64(d, NODUS_DNAC_V3_KIND_CLAIM, &v) != 0) return -1;
            it->kind = (uint8_t)v;
            have |= 2u;
        } else if (KEY_EQ(k, "c")) {
            if (v3d_u64(d, UINT32_MAX, &v) != 0) return -1;
            it->code = (uint32_t)v;
            have |= 4u;
        } else if (KEY_EQ(k, "w")) {
            if (v3d_b64(d, it->wire_id) != 0) return -1;
            it->has_wire_id = true;
        } else if (KEY_EQ(k, "in")) {
            if (v3d_b64(d, it->intent_id) != 0) return -1;
            it->has_intent_id = true;
        } else if (KEY_EQ(k, "f")) {
            if (v3d_u64(d, UINT64_MAX, &it->fee) != 0) return -1;
            it->has_fee = true;
        } else if (KEY_EQ(k, "op")) {
            cbor_item_t s;
            if (v3d_next(d, &s) != 0 || s.type != CBOR_ITEM_TSTR ||
                s.tstr.len == 0 || s.tstr.len > NODUS_DNAC_V3_OP_MAX)
                return -1;
            for (size_t c = 0; c < s.tstr.len; c++) {
                char ch = s.tstr.ptr[c];
                if (!((ch >= 'a' && ch <= 'z') || ch == '_')) return -1;
            }
            memcpy(it->op, s.tstr.ptr, s.tstr.len);
            it->op[s.tstr.len] = '\0';
        } else if (KEY_EQ(k, "sp")) {
            if (v3d_next(d, &a) != 0 || a.type != CBOR_ITEM_ARRAY ||
                a.count > NODUS_DNAC_V3_ITEM_MAX_IN)
                return -1;
            for (size_t c = 0; c < a.count; c++)
                if (v3d_b64(d, it->consumed[c]) != 0) return -1;
            it->n_consumed = (uint8_t)a.count;
            have |= 8u;
        } else if (KEY_EQ(k, "cr")) {
            if (v3d_next(d, &a) != 0 || a.type != CBOR_ITEM_ARRAY ||
                a.count > NODUS_DNAC_V3_ITEM_MAX_OUT)
                return -1;
            for (size_t c = 0; c < a.count; c++)
                if (v3d_coin(d, &it->created[c]) != 0) return -1;
            it->n_created = (uint8_t)a.count;
            have |= 16u;
        } else if (KEY_EQ(k, "bu")) {
            if (v3d_u64(d, UINT64_MAX, &it->burned) != 0) return -1;
        } else if (KEY_EQ(k, "rc")) {
            if (v3d_record(d, it) != 0) return -1;
        } else if (v3d_skip(d, 0) != 0) {
            return -1;
        }
    }
    if ((have & 7u) != 7u) return -1;          /* i, k, c are required  */
    /* effects come as a pair, and only on an applied item */
    it->has_effects = (have & 24u) == 24u;
    if ((have & 24u) != 0 && (!it->has_effects || it->code != 0))
        return -1;
    if (!it->has_effects &&
        (it->burned != 0 || it->rec_kind != NODUS_DNAC_V3_REC_NONE))
        return -1;
    return 0;
}

void nodus_client_free_v3_block_result(nodus_dnac_v3_block_result_t *result)
{
    if (!result) return;
    free(result->items);
    memset(result, 0, sizeof(*result));
}

int nodus_dnac_v3_block_decode(const uint8_t *raw, size_t raw_len,
                               nodus_dnac_v3_block_result_t *result_out)
{
    cbor_decoder_t dec;
    size_t         mc;
    v3d_keys_t     ks;
    cbor_item_t    k;
    uint64_t       v;
    unsigned       have = 0;
    bool           have_items = false;

    if (!raw || !result_out) return -1;
    memset(result_out, 0, sizeof(*result_out));
    memset(&ks, 0, sizeof(ks));
    if (find_response_map(raw, raw_len, &dec, &mc) != 0) return -1;
    if (mc > V3D_MAX_KEYS || mc > v3d_left(&dec) / 2) return -1;

    for (size_t i = 0; i < mc; i++) {
        if (v3d_key(&dec, &ks, &k) != 0) goto bad;
        if (KEY_EQ(k, "h")) {
            if (v3d_u64(&dec, UINT64_MAX, &result_out->height) != 0) goto bad;
            have |= 1u;
        } else if (KEY_EQ(k, "bid")) {
            if (v3d_b64(&dec, result_out->block_id) != 0) goto bad;
            have |= 2u;
        } else if (KEY_EQ(k, "pb")) {
            if (v3d_b64(&dec, result_out->prev_block_id) != 0) goto bad;
            have |= 4u;
        } else if (KEY_EQ(k, "tm")) {
            if (v3d_u64(&dec, UINT64_MAX, &result_out->time_ms) != 0) goto bad;
            have |= 8u;
        } else if (KEY_EQ(k, "pa")) {
            cbor_item_t b;
            if (v3d_next(&dec, &b) != 0 || b.type != CBOR_ITEM_BSTR ||
                b.bstr.len == 0 || b.bstr.len > sizeof(result_out->proposer))
                goto bad;
            memcpy(result_out->proposer, b.bstr.ptr, b.bstr.len);
            result_out->proposer_len = b.bstr.len;
            have |= 16u;
        } else if (KEY_EQ(k, "gr")) {
            if (v3d_b64(&dec, result_out->global_root) != 0) goto bad;
            have |= 32u;
        } else if (KEY_EQ(k, "ac")) {
            if (v3d_u64(&dec, UINT64_MAX, &result_out->applied_count) != 0)
                goto bad;
            have |= 64u;
        } else if (KEY_EQ(k, "n")) {
            if (v3d_u64(&dec, UINT32_MAX, &v) != 0) goto bad;
            result_out->total_items = (uint32_t)v;
            have |= 128u;
        } else if (KEY_EQ(k, "tip")) {
            if (v3d_u64(&dec, UINT64_MAX, &result_out->tip) != 0) goto bad;
            have |= 256u;
        } else if (KEY_EQ(k, "nx")) {
            if (v3d_u64(&dec, UINT32_MAX, &v) != 0) goto bad;
            result_out->next_index = (uint32_t)v;
            result_out->has_next = true;
        } else if (KEY_EQ(k, "it")) {
            cbor_item_t a;
            if (v3d_next(&dec, &a) != 0 || a.type != CBOR_ITEM_ARRAY ||
                a.count > NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS)
                goto bad;
            result_out->items = calloc(a.count ? a.count : 1,
                                       sizeof(*result_out->items));
            if (!result_out->items) goto bad;
            for (size_t j = 0; j < a.count; j++) {
                if (v3d_item(&dec, &result_out->items[j]) != 0) goto bad;
                result_out->count = j + 1;
            }
            have_items = true;
        } else if (v3d_skip(&dec, 0) != 0) {
            goto bad;
        }
    }
    if (dec.error || have != 511u || !have_items) goto bad;

    /* consistency: a page is a contiguous, ascending run of the block's
     * items; "nx" names the item right after it; no "nx" = the block's
     * last item is on this page */
    if (result_out->height == 0 || result_out->tip < result_out->height)
        goto bad;
    for (size_t j = 0; j < result_out->count; j++) {
        uint32_t idx = result_out->items[j].index;
        if (idx >= result_out->total_items) goto bad;
        if (j > 0 && idx != result_out->items[j - 1].index + 1) goto bad;
    }
    if (result_out->count == 0) {
        if (result_out->total_items != 0 || result_out->has_next) goto bad;
    } else {
        uint32_t last = result_out->items[result_out->count - 1].index;
        if (result_out->has_next) {
            if (result_out->next_index != last + 1 ||
                result_out->next_index >= result_out->total_items)
                goto bad;
        } else if (last + 1 != result_out->total_items) {
            goto bad;
        }
    }
    return 0;

bad:
    nodus_client_free_v3_block_result(result_out);
    return -1;
}

int nodus_client_dnac_v3_block(nodus_client_t *client, uint64_t height,
                               uint32_t from_index, uint32_t budget,
                               nodus_dnac_v3_block_result_t *result_out)
{
    if (!nodus_client_is_ready(client) || !result_out || height == 0)
        return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_v3_block", 3);
    cbor_encode_cstr(&enc, "h");
    cbor_encode_uint(&enc, height);
    cbor_encode_cstr(&enc, "i");
    cbor_encode_uint(&enc, from_index);
    cbor_encode_cstr(&enc, "b");
    cbor_encode_uint(&enc, budget);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }
    int drc = nodus_dnac_v3_block_decode(req->raw_response,
                                         req->raw_response_len, result_out);
    free_pending(client, req);
    if (drc != 0) return NODUS_ERR_PROTOCOL_ERROR;
    /* the node answers the height it was asked for, never another */
    if (result_out->height != height ||
        (result_out->count > 0 && result_out->items[0].index != from_index)) {
        nodus_client_free_v3_block_result(result_out);
        return NODUS_ERR_PROTOCOL_ERROR;
    }
    return 0;
}

int nodus_client_dnac_supply_tip(nodus_client_t *client, bool *has_out,
                                 uint64_t *tip_out)
{
    if (!nodus_client_is_ready(client) || !has_out || !tip_out)
        return -1;
    *has_out = false;

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    /* SAME request as nodus_client_dnac_supply — the additive key rides
     * the existing dnac_supply reply (nodus_witness_handlers.c
     * handle_dnac_supply); nodus_client_dnac_chain_id32's pattern. */
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
        if (key.type == CBOR_ITEM_END || key.type == CBOR_ITEM_ERROR) {
            *has_out = false;
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (KEY_EQ(key, "tip")) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) {
                *tip_out = v.uint_val;
                *has_out = true;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    if (dec.error) {
        *has_out = false;
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    free_pending(client, req);
    return 0;
}

/* ── dnac_supply buckets (decision 2026-09-30-scan-supply-buckets.md;
 * wire: nodus.h) — on the v3d_* readers above (END/ERROR, duplicate-key
 * and truncation discipline). */

int nodus_dnac_supply_buckets_decode(const uint8_t *raw, size_t raw_len,
                                     nodus_dnac_supply_buckets_t *out)
{
    cbor_decoder_t dec;
    size_t         mc;
    v3d_keys_t     ks;
    cbor_item_t    k;
    bool           have_cur = false, have_rp = false, have_tr = false,
                   have_un = false;

    if (!raw || !out) return -1;
    memset(out, 0, sizeof(*out));
    memset(&ks, 0, sizeof(ks));
    if (find_response_map(raw, raw_len, &dec, &mc) != 0) return -1;
    if (mc > V3D_MAX_KEYS || mc > v3d_left(&dec) / 2) return -1;

    for (size_t i = 0; i < mc; i++) {
        if (v3d_key(&dec, &ks, &k) != 0) goto bad;
        if (KEY_EQ(k, "current")) {
            if (v3d_u64(&dec, UINT64_MAX, &out->current_supply) != 0)
                goto bad;
            have_cur = true;
        } else if (KEY_EQ(k, "reward_pool")) {
            if (v3d_u64(&dec, UINT64_MAX, &out->reward_pool) != 0) goto bad;
            have_rp = true;
        } else if (KEY_EQ(k, "treasury")) {
            cbor_item_t a;
            if (v3d_next(&dec, &a) != 0 || a.type != CBOR_ITEM_ARRAY ||
                a.count != NODUS_DNAC_TREASURY_POOLS)
                goto bad;
            for (size_t j = 0; j < NODUS_DNAC_TREASURY_POOLS; j++)
                if (v3d_u64(&dec, UINT64_MAX, &out->treasury[j]) != 0)
                    goto bad;
            have_tr = true;
        } else if (KEY_EQ(k, "unclaimed")) {
            if (v3d_u64(&dec, UINT64_MAX, &out->unclaimed) != 0) goto bad;
            have_un = true;
        } else if (v3d_skip(&dec, 0) != 0) {
            goto bad;
        }
    }
    if (dec.error || !have_cur) goto bad;
    /* all three or none: a reply with some of them is no node's */
    if (have_rp != have_tr || have_rp != have_un) goto bad;
    if (!have_rp) {
        memset(out, 0, sizeof(*out));
        return 0;                              /* an older node */
    }
    out->has = true;
    return 0;

bad:
    memset(out, 0, sizeof(*out));
    return -1;
}

int nodus_client_dnac_supply_buckets(nodus_client_t *client,
                                     nodus_dnac_supply_buckets_t *out)
{
    if (!nodus_client_is_ready(client) || !out)
        return -1;
    memset(out, 0, sizeof(*out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    /* SAME request as nodus_client_dnac_supply — the additive keys ride
     * the existing dnac_supply reply (nodus_witness_handlers.c
     * handle_dnac_supply); nodus_client_dnac_chain_id32's pattern. */
    enc_dnac_query(&enc, txn, client->token, "dnac_supply", 0);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) { free_pending(client, req); free(buf); return -1; }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) { free_pending(client, req); return NODUS_ERR_TIMEOUT; }
    if (resp->type == 'e') { int rc = resp->error_code; free_pending(client, req); return rc; }

    int drc = nodus_dnac_supply_buckets_decode(req->raw_response,
                                               req->raw_response_len, out);
    free_pending(client, req);
    return drc == 0 ? 0 : NODUS_ERR_PROTOCOL_ERROR;
}

/* ── dnac_balance (scan-v3; wire: nodus.h) ────────────────────────────
 * Hostile-reply decoder on the v3d_* readers above (the same END/ERROR,
 * container-count, duplicate-key and truncation discipline). */

static int bald_token(cbor_decoder_t *d, nodus_dnac_balance_token_t *t)
{
    cbor_item_t m, k;
    v3d_keys_t  ks;
    unsigned    have = 0;

    memset(&ks, 0, sizeof(ks));
    if (v3d_next(d, &m) != 0 || m.type != CBOR_ITEM_MAP ||
        m.count > V3D_MAX_KEYS)
        return -1;
    for (size_t j = 0; j < m.count; j++) {
        if (v3d_key(d, &ks, &k) != 0) return -1;
        if (KEY_EQ(k, "t")) {
            if (v3d_b64(d, t->token_id) != 0) return -1;
            have |= 1u;
        } else if (KEY_EQ(k, "a")) {
            if (v3d_u64(d, UINT64_MAX, &t->total) != 0) return -1;
            have |= 2u;
        } else if (KEY_EQ(k, "s")) {
            if (v3d_u64(d, UINT64_MAX, &t->spendable) != 0) return -1;
            have |= 4u;
        } else if (KEY_EQ(k, "c")) {
            if (v3d_u64(d, UINT64_MAX, &t->coins) != 0) return -1;
            have |= 8u;
        } else if (v3d_skip(d, 0) != 0) {
            return -1;
        }
    }
    if (have != 15u) return -1;
    if (t->spendable > t->total || t->coins == 0) return -1;
    return 0;
}

void nodus_client_free_balance_result(nodus_dnac_balance_result_t *result)
{
    if (!result) return;
    free(result->tokens);
    memset(result, 0, sizeof(*result));
}

int nodus_dnac_balance_decode(const uint8_t *raw, size_t raw_len,
                              nodus_dnac_balance_result_t *result_out)
{
    cbor_decoder_t dec;
    size_t         mc;
    v3d_keys_t     ks;
    cbor_item_t    k;
    bool           have_tip = false, have_tk = false;

    if (!raw || !result_out) return -1;
    memset(result_out, 0, sizeof(*result_out));
    memset(&ks, 0, sizeof(ks));
    if (find_response_map(raw, raw_len, &dec, &mc) != 0) return -1;
    if (mc > V3D_MAX_KEYS || mc > v3d_left(&dec) / 2) return -1;

    for (size_t i = 0; i < mc; i++) {
        if (v3d_key(&dec, &ks, &k) != 0) goto bad;
        if (KEY_EQ(k, "tip")) {
            if (v3d_u64(&dec, UINT64_MAX, &result_out->tip) != 0) goto bad;
            have_tip = true;
        } else if (KEY_EQ(k, "tk")) {
            cbor_item_t a;
            if (v3d_next(&dec, &a) != 0 || a.type != CBOR_ITEM_ARRAY ||
                a.count > NODUS_DNAC_BALANCE_MAX_TOKENS)
                goto bad;
            if (a.count > 0) {
                result_out->tokens = calloc(a.count,
                                            sizeof(*result_out->tokens));
                if (!result_out->tokens) goto bad;
            }
            for (size_t j = 0; j < a.count; j++) {
                nodus_dnac_balance_token_t *t = &result_out->tokens[j];
                if (bald_token(&dec, t) != 0) goto bad;
                /* strictly ascending token ids: one entry per token, in
                 * the node's ORDER BY token_id */
                if (j > 0 &&
                    memcmp(result_out->tokens[j - 1].token_id,
                           t->token_id, 64) >= 0)
                    goto bad;
                result_out->count = j + 1;
            }
            have_tk = true;
        } else if (v3d_skip(&dec, 0) != 0) {
            goto bad;
        }
    }
    if (dec.error || !have_tip || !have_tk) goto bad;
    return 0;

bad:
    nodus_client_free_balance_result(result_out);
    return -1;
}

int nodus_client_dnac_balance(nodus_client_t *client, const char *owner_hex,
                              nodus_dnac_balance_result_t *result_out)
{
    if (!nodus_client_is_ready(client) || !owner_hex || !result_out)
        return -1;
    memset(result_out, 0, sizeof(*result_out));

    /* the node refuses anything but 128 lowercase hex — refuse it here
     * first, before a round trip */
    size_t olen = strnlen(owner_hex, 129);
    if (olen != 128) return -1;
    for (size_t i = 0; i < 128; i++) {
        char ch = owner_hex[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            return -1;
    }

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_balance", 1);
    cbor_encode_cstr(&enc, "owner");
    cbor_encode_cstr(&enc, owner_hex);

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }
    int drc = nodus_dnac_balance_decode(req->raw_response,
                                        req->raw_response_len, result_out);
    free_pending(client, req);
    return drc == 0 ? 0 : NODUS_ERR_PROTOCOL_ERROR;
}

/* ── dnac_addr_history (node-local address index; wire: nodus.h) ──────
 * Hostile-reply decoder on the v3d_* readers above (the same END/ERROR,
 * container-count, duplicate-key and truncation discipline). */

static const char *const AHD_KINDS[] = {
    "spend_out", "spend_in", "burn", "token_create", "claim", "stake",
    "delegate", "undelegate", "unstake", "validator_update", "payout",
    "release", "fee"
};

/* (a) strictly after (b) in the newest-first order, i.e. a < b. */
static bool ahd_older(const nodus_dnac_addr_history_entry_t *a,
                      const nodus_dnac_addr_history_entry_t *b)
{
    if (a->h != b->h) return a->h < b->h;
    if (a->i != b->i) return a->i < b->i;
    return a->q < b->q;
}

static int ahd_entry(cbor_decoder_t *d, nodus_dnac_addr_history_entry_t *e)
{
    cbor_item_t m, k, v;
    v3d_keys_t  ks;
    unsigned    have = 0;
    uint64_t    u;

    memset(&ks, 0, sizeof(ks));
    if (v3d_next(d, &m) != 0 || m.type != CBOR_ITEM_MAP ||
        m.count > V3D_MAX_KEYS)
        return -1;
    for (size_t j = 0; j < m.count; j++) {
        if (v3d_key(d, &ks, &k) != 0) return -1;
        if (KEY_EQ(k, "h")) {
            if (v3d_u64(d, UINT64_MAX, &e->h) != 0) return -1;
            have |= 1u;
        } else if (KEY_EQ(k, "i")) {
            if (v3d_u64(d, UINT32_MAX, &u) != 0) return -1;
            e->i = (uint32_t)u;
            have |= 2u;
        } else if (KEY_EQ(k, "q")) {
            if (v3d_u64(d, UINT32_MAX, &u) != 0) return -1;
            e->q = (uint32_t)u;
            have |= 4u;
        } else if (KEY_EQ(k, "kind")) {
            bool known = false;
            if (v3d_next(d, &v) != 0 || v.type != CBOR_ITEM_TSTR ||
                v.tstr.len == 0 || v.tstr.len >= sizeof(e->kind))
                return -1;
            for (size_t n = 0;
                 n < sizeof(AHD_KINDS) / sizeof(AHD_KINDS[0]); n++) {
                if (strlen(AHD_KINDS[n]) == v.tstr.len &&
                    memcmp(AHD_KINDS[n], v.tstr.ptr, v.tstr.len) == 0) {
                    known = true;
                    break;
                }
            }
            if (!known) return -1;
            memcpy(e->kind, v.tstr.ptr, v.tstr.len);
            e->kind[v.tstr.len] = '\0';
            have |= 8u;
        } else if (KEY_EQ(k, "amount")) {
            if (v3d_u64(d, UINT64_MAX, &e->amount) != 0) return -1;
            have |= 16u;
        } else if (KEY_EQ(k, "token")) {
            if (v3d_b64(d, e->token_id) != 0) return -1;
            have |= 32u;
        } else if (KEY_EQ(k, "fee")) {
            if (v3d_u64(d, UINT64_MAX, &e->fee) != 0) return -1;
            have |= 64u;
        } else if (KEY_EQ(k, "peer")) {
            if (v3d_next(d, &v) != 0 || v.type != CBOR_ITEM_TSTR) return -1;
            if (v.tstr.len == 0) {
                e->peer[0] = '\0';
            } else {
                if (v.tstr.len != 128) return -1;
                for (size_t n = 0; n < 128; n++) {
                    char ch = v.tstr.ptr[n];
                    if (!((ch >= '0' && ch <= '9') ||
                          (ch >= 'a' && ch <= 'f')))
                        return -1;
                }
                memcpy(e->peer, v.tstr.ptr, 128);
                e->peer[128] = '\0';
            }
            have |= 128u;
        } else if (KEY_EQ(k, "wire")) {
            if (v3d_next(d, &v) != 0 || v.type != CBOR_ITEM_BSTR) return -1;
            if (v.bstr.len == 64) {
                memcpy(e->wire_id, v.bstr.ptr, 64);
                e->has_wire = true;
            } else if (v.bstr.len != 0) {
                return -1;
            }
            have |= 256u;
        } else if (KEY_EQ(k, "ts")) {
            if (v3d_u64(d, UINT64_MAX, &e->ts) != 0) return -1;
            have |= 512u;
        } else if (v3d_skip(d, 0) != 0) {
            return -1;
        }
    }
    return have == 1023u ? 0 : -1;
}

void nodus_client_free_addr_history_result(nodus_dnac_addr_history_result_t *result)
{
    if (!result) return;
    free(result->entries);
    memset(result, 0, sizeof(*result));
}

int nodus_dnac_addr_history_decode(const uint8_t *raw, size_t raw_len,
                                   nodus_dnac_addr_history_result_t *result_out)
{
    cbor_decoder_t dec;
    size_t         mc;
    v3d_keys_t     ks;
    cbor_item_t    k, v;
    uint64_t       count = 0;
    bool           have_count = false, have_en = false, have_from = false,
                   have_ent = false;

    if (!raw || !result_out) return -1;
    memset(result_out, 0, sizeof(*result_out));
    memset(&ks, 0, sizeof(ks));
    if (find_response_map(raw, raw_len, &dec, &mc) != 0) return -1;
    if (mc > V3D_MAX_KEYS || mc > v3d_left(&dec) / 2) return -1;

    for (size_t i = 0; i < mc; i++) {
        if (v3d_key(&dec, &ks, &k) != 0) goto bad;
        if (KEY_EQ(k, "count")) {
            if (v3d_u64(&dec, NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT, &count) != 0)
                goto bad;
            have_count = true;
        } else if (KEY_EQ(k, "enabled")) {
            if (v3d_next(&dec, &v) != 0 || v.type != CBOR_ITEM_BOOL)
                goto bad;
            result_out->enabled = v.bool_val;
            have_en = true;
        } else if (KEY_EQ(k, "from_height")) {
            if (v3d_u64(&dec, UINT64_MAX, &result_out->from_height) != 0)
                goto bad;
            have_from = true;
        } else if (KEY_EQ(k, "entries")) {
            cbor_item_t a;
            if (v3d_next(&dec, &a) != 0 || a.type != CBOR_ITEM_ARRAY ||
                a.count > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT)
                goto bad;
            if (a.count > 0) {
                result_out->entries = calloc(a.count,
                                             sizeof(*result_out->entries));
                if (!result_out->entries) goto bad;
            }
            for (size_t j = 0; j < a.count; j++) {
                nodus_dnac_addr_history_entry_t *e = &result_out->entries[j];
                if (ahd_entry(&dec, e) != 0) goto bad;
                if (j > 0 && !ahd_older(e, &result_out->entries[j - 1]))
                    goto bad;
                result_out->count = j + 1;
            }
            have_ent = true;
        } else if (v3d_skip(&dec, 0) != 0) {
            goto bad;
        }
    }
    if (dec.error || !have_count || !have_en || !have_from || !have_ent ||
        count != result_out->count)
        goto bad;
    return 0;

bad:
    nodus_client_free_addr_history_result(result_out);
    return -1;
}

int nodus_client_dnac_addr_history(nodus_client_t *client,
                                   const char *owner_hex,
                                   const nodus_dnac_addr_history_cursor_t *before,
                                   uint32_t limit,
                                   nodus_dnac_addr_history_result_t *result_out)
{
    if (!nodus_client_is_ready(client) || !owner_hex || !result_out)
        return -1;
    memset(result_out, 0, sizeof(*result_out));
    if (limit < 1 || limit > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT) return -1;

    /* the node refuses anything but 128 lowercase hex — refuse it here
     * first, before a round trip */
    size_t olen = strnlen(owner_hex, 129);
    if (olen != 128) return -1;
    for (size_t i = 0; i < 128; i++) {
        char ch = owner_hex[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            return -1;
    }

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    enc_dnac_query(&enc, txn, client->token, "dnac_addr_history",
                   before ? 5 : 2);
    cbor_encode_cstr(&enc, "owner");
    cbor_encode_cstr(&enc, owner_hex);
    cbor_encode_cstr(&enc, "limit");
    cbor_encode_uint(&enc, limit);
    if (before) {
        cbor_encode_cstr(&enc, "before");
        cbor_encode_uint(&enc, before->h);
        cbor_encode_cstr(&enc, "bi");
        cbor_encode_uint(&enc, before->i);
        cbor_encode_cstr(&enc, "bq");
        cbor_encode_uint(&enc, before->q);
    }

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }
    int drc = nodus_dnac_addr_history_decode(req->raw_response,
                                             req->raw_response_len,
                                             result_out);
    free_pending(client, req);
    return drc == 0 ? 0 : NODUS_ERR_PROTOCOL_ERROR;
}

int nodus_client_dnac_validator_list(nodus_client_t *client,
                                       int filter_status,
                                       int offset,
                                       int limit,
                                       nodus_dnac_validator_list_result_t *result_out) {
    if (!nodus_client_is_ready(client) || !result_out) return -1;

    memset(result_out, 0, sizeof(*result_out));

    uint8_t *buf = malloc(CLIENT_BUF_SIZE);
    if (!buf) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, CLIENT_BUF_SIZE);
    uint32_t txn = atomic_fetch_add(&client->next_txn, 1);
    nodus_pending_t *req = alloc_pending(client, txn);
    if (!req) { free(buf); return -1; }

    /* status encoded as UINT when specific; omitted to mean "all". */
    int args_count = 2; /* limit, offset always present */
    if (filter_status >= 0) args_count = 3;
    enc_dnac_query(&enc, txn, client->token,
                    "dnac_validator_list_query", (size_t)args_count);
    if (filter_status >= 0) {
        cbor_encode_cstr(&enc, "status");
        cbor_encode_uint(&enc, (uint64_t)filter_status);
    }
    cbor_encode_cstr(&enc, "limit");
    cbor_encode_uint(&enc, (uint64_t)(limit > 0 ? limit : 100));
    cbor_encode_cstr(&enc, "offset");
    cbor_encode_uint(&enc, (uint64_t)(offset > 0 ? offset : 0));

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { free_pending(client, req); free(buf); return -1; }
    if (send_request(client, buf, len) != 0) {
        free_pending(client, req); free(buf); return -1;
    }
    free(buf);

    nodus_tier2_msg_t *resp = (nodus_tier2_msg_t *)req->response;
    if (!wait_response(client, req, client->config.request_timeout_ms)) {
        free_pending(client, req); return NODUS_ERR_TIMEOUT;
    }
    if (resp->type == 'e') {
        int rc = resp->error_code; free_pending(client, req); return rc;
    }

    cbor_decoder_t dec;
    size_t mc;
    if (find_response_map(req->raw_response, req->raw_response_len,
                           &dec, &mc) != 0) {
        free_pending(client, req);
        return NODUS_ERR_PROTOCOL_ERROR;
    }

    /* P0-B (2026-09-28): every response key once; entry writes bounded by
     * the capacity allocated (see nodus_client_dnac_history). */
    nodus_map_keys_t ks;
    memset(&ks, 0, sizeof(ks));
    for (size_t i = 0; i < mc; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
        if (nodus_map_key_once(&ks, key.tstr.ptr, key.tstr.len) != 0) {
            QGP_LOG_WARN(LOG_TAG, "dnac_validator_list: repeated key in response — refused");
            nodus_client_free_validator_list_result(result_out);
            free_pending(client, req);
            return NODUS_ERR_PROTOCOL_ERROR;
        }

        if (KEY_EQ(key, "count")) {
            cbor_item_t v = cbor_decode_next(&dec);
            /* parsed per-array below — consume and continue */
            (void)v;
        } else if (KEY_EQ(key, "total")) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type == CBOR_ITEM_UINT) result_out->total = (int)v.uint_val;
        } else if (KEY_EQ(key, "validators")) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) continue;
            size_t cap = arr.count;
            if (cap > 0) {
                result_out->entries =
                    calloc(cap, sizeof(nodus_dnac_validator_list_entry_t));
                if (!result_out->entries) {
                    free_pending(client, req);
                    return NODUS_ERR_INTERNAL_ERROR;
                }
            }
            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t emap = cbor_decode_next(&dec);
                if (emap.type != CBOR_ITEM_MAP) continue;
                if ((size_t)result_out->count >= cap) {
                    nodus_client_free_validator_list_result(result_out);
                    free_pending(client, req);
                    return NODUS_ERR_PROTOCOL_ERROR;
                }
                nodus_dnac_validator_list_entry_t *e =
                    &result_out->entries[result_out->count];
                memset(e, 0, sizeof(*e));
                for (size_t k = 0; k < emap.count; k++) {
                    cbor_item_t ek = cbor_decode_next(&dec);
                    if (ek.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(&dec); continue;
                    }
                    if (KEY_EQ(ek, "pk")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_PK_BYTES)
                            memcpy(e->pubkey, v.bstr.ptr, NODUS_PK_BYTES);
                    } else if (KEY_EQ(ek, "self")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) e->self_stake = v.uint_val;
                    } else if (KEY_EQ(ek, "total")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) e->total_delegated = v.uint_val;
                    } else if (KEY_EQ(ek, "ext")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) e->external_delegated = v.uint_val;
                    } else if (KEY_EQ(ek, "comm")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->commission_bps = (uint16_t)v.uint_val;
                    } else if (KEY_EQ(ek, "status")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT)
                            e->status = (uint8_t)v.uint_val;
                    } else if (KEY_EQ(ek, "since")) {
                        cbor_item_t v = cbor_decode_next(&dec);
                        if (v.type == CBOR_ITEM_UINT) e->active_since_block = v.uint_val;
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

void nodus_client_free_validator_list_result(nodus_dnac_validator_list_result_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0;
    result->total = 0;
}

#ifdef NODUS_CLIENT_TEST_SEAM
/* Test-only entry points to the split response decoders above
 * (tests/test_client_dup_array.c). Compiled ONLY when a test target builds
 * this TU itself with NODUS_CLIENT_TEST_SEAM=1 — never into libnodus — the
 * arrangement nodus/CMakeLists.txt uses for NODUS_V2_TEST_SUPPLY: libnodus
 * is static, so the test's own object satisfies every symbol and the
 * archive member is never pulled. These only decode bytes; they bypass
 * nothing. The request functions zero result_out before decoding; so do
 * these. */
int nodus_client_test_parse_utxo(const uint8_t *raw, size_t raw_len,
                                 nodus_dnac_utxo_result_t *out);
int nodus_client_test_parse_ledger_range(const uint8_t *raw, size_t raw_len,
                                         nodus_dnac_range_result_t *out);
int nodus_client_test_parse_block(const uint8_t *raw, size_t raw_len,
                                  nodus_dnac_block_result_t *out);

int nodus_client_test_parse_utxo(const uint8_t *raw, size_t raw_len,
                                 nodus_dnac_utxo_result_t *out) {
    memset(out, 0, sizeof(*out));
    return dnac_utxo_parse(raw, raw_len, out);
}

int nodus_client_test_parse_ledger_range(const uint8_t *raw, size_t raw_len,
                                         nodus_dnac_range_result_t *out) {
    memset(out, 0, sizeof(*out));
    return dnac_ledger_range_parse(raw, raw_len, out);
}

int nodus_client_test_parse_block(const uint8_t *raw, size_t raw_len,
                                  nodus_dnac_block_result_t *out) {
    memset(out, 0, sizeof(*out));
    return dnac_block_parse(raw, raw_len, out);
}
#endif /* NODUS_CLIENT_TEST_SEAM */

#undef KEY_EQ

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
    /* Monotonic deadline, not a count of loop turns (see wait_response). */
    uint64_t start = now_ms();

    while (!atomic_load(&req->ready) && !deadline_passed(start, timeout_ms)) {
        if (!ch->conn)
            return false;

        if (atomic_load(&ch->read_thread_running) &&
            !pthread_equal(pthread_self(), ch->read_thread)) {
            /* Read thread handles TCP — just wait for ready flag */
            sleep_ms(10);
        } else {
            /* We ARE the read thread (auth path), or no thread — poll directly */
            nodus_tcp_t *tcp = (nodus_tcp_t *)ch->tcp;
            if (tcp) nodus_tcp_poll(tcp, 50);
            else sleep_ms(10);
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
    if (nodus_t2_decode(payload, len, &tmp) != 0) {
        nodus_t2_msg_free(&tmp);   /* no-op: the decoder freed it already */
        return;
    }

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
    uint64_t start = now_ms();
    while (ch->conn && conn->state == NODUS_CONN_CONNECTING &&
           !deadline_passed(start, CH_CONN_CONNECT_TIMEOUT)) {
        nodus_tcp_poll(tcp, 50);
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

    /* Step 2: Sign nonce and send AUTH (C2: domain-tagged, channel client always outbound) */
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, resp->nonce, &ch->identity.sk);
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
    pthread_mutex_init(&ch->wbuf_mutex, NULL);
    atomic_store(&ch->read_thread_running, false);
    atomic_store(&ch->read_thread_stop, false);

    /* Initialize TCP transport */
    nodus_tcp_t *tcp = calloc(1, sizeof(nodus_tcp_t));
    if (!tcp) {
        pthread_mutex_destroy(&ch->pending_mutex);
        pthread_mutex_destroy(&ch->send_mutex);
        pthread_mutex_destroy(&ch->wbuf_mutex);
        return -1;
    }
    nodus_tcp_init(tcp, -1);
    tcp->on_frame = ch_conn_on_frame;
    tcp->on_disconnect = ch_conn_on_disconnect;
    tcp->on_connect = ch_conn_on_connect;
    tcp->cb_ctx = ch;
    /* Same two-thread shape as nodus_client_t: see nodus_client_init. */
    nodus_tcp_set_write_lock(tcp, client_wbuf_lock, &ch->wbuf_mutex);
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
    uint64_t start = now_ms();
    while (ch->conn && conn->state == NODUS_CONN_CONNECTING &&
           !deadline_passed(start, CH_CONN_CONNECT_TIMEOUT)) {
        nodus_tcp_poll(tcp, 50);
        conn = (nodus_tcp_conn_t *)ch->conn;
        if (!conn) break;
    }
    int elapsed = (int)elapsed_since(start);

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
    pthread_mutex_destroy(&ch->wbuf_mutex);

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

/* Shared body for plain and keyed circuit open. k_call != NULL enables the
 * per-circuit E2E channel crypto using that externally-agreed 32-byte secret
 * (from call signaling, Faz A) — no in-circuit Kyber handshake; a plain
 * circ_open is sent and every circ_data payload is transparently AES-256-GCM
 * encrypted. k_call == NULL is a plaintext relay (relay sees cleartext). */
static int circuit_open_impl(nodus_client_t *client, const nodus_key_t *peer_fp,
                             const uint8_t *k_call,
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

    /* Keyed E2E: derive the per-circuit channel key from the pre-agreed K_call.
     * Nonces = (caller_fp, callee_fp), matching the inbound side (see
     * nodus_circuit_attach_keyed and the circ_inbound e2e path). */
    if (k_call) {
        uint8_t nc[32], ns[32];
        memcpy(nc, client->identity.node_id.bytes, 32);  /* own = caller */
        memcpy(ns, peer_fp->bytes, 32);                    /* peer = callee */
        /* We OPENED this circuit → initiator. */
        if (nodus_channel_crypto_init(&h->e2e_crypto, k_call, nc, ns,
                                       NODUS_CHANNEL_ROLE_INITIATOR) != 0) {
            pthread_mutex_lock(&client->circuits_mutex);
            h->in_use = false;
            pthread_mutex_unlock(&client->circuits_mutex);
            return -1;
        }
        h->e2e_active = true;
    }

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

int nodus_circuit_open(nodus_client_t *client, const nodus_key_t *peer_fp,
                        nodus_circuit_data_cb on_data,
                        nodus_circuit_close_cb on_close,
                        void *user,
                        nodus_circuit_handle_t **out) {
    return circuit_open_impl(client, peer_fp, NULL, on_data, on_close, user, out);
}

int nodus_circuit_open_keyed(nodus_client_t *client, const nodus_key_t *peer_fp,
                             const uint8_t k_call[32],
                             nodus_circuit_data_cb on_data,
                             nodus_circuit_close_cb on_close,
                             void *user,
                             nodus_circuit_handle_t **out) {
    if (!k_call) return -1;
    return circuit_open_impl(client, peer_fp, k_call, on_data, on_close, user, out);
}

int nodus_circuit_open_e2e_alg(nodus_client_t *client, const nodus_key_t *peer_fp,
                                const uint8_t *peer_pk, uint8_t peer_alg,
                                nodus_circuit_data_cb on_data,
                                nodus_circuit_close_cb on_close,
                                void *user,
                                nodus_circuit_handle_t **out) {
    if (!client || !peer_fp || !peer_pk || !out) return -1;
    if (!nodus_client_is_ready(client)) return -1;

    /* KEM encapsulate → per-circuit shared secret. Ciphertext and
     * shared-secret sizes are byte-identical between the two KEMs
     * (NODUS_KYBER_* == NODUS_MLKEM_* today), so one buffer pair serves
     * both (Faz 1 KEM migration). */
    uint8_t e2e_ct[NODUS_KYBER_CT_BYTES];
    uint8_t e2e_ss[NODUS_KYBER_SS_BYTES];
    int enc_rc = (peer_alg == 1)
        ? qgp_mlkem1024_encapsulate(e2e_ct, e2e_ss, peer_pk)
        : qgp_kem1024_encapsulate(e2e_ct, e2e_ss, peer_pk);
    if (enc_rc != 0)
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
    /* We OPENED this circuit → initiator. */
    if (nodus_channel_crypto_init(&h->e2e_crypto, e2e_ss, nc, ns,
                                   NODUS_CHANNEL_ROLE_INITIATOR) != 0) {
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
    if (nodus_t2_circ_open_e2e(txn, client->token, cid, peer_fp, e2e_ct, peer_alg,
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

int nodus_circuit_open_e2e(nodus_client_t *client, const nodus_key_t *peer_fp,
                            const uint8_t *peer_kyber_pk,
                            nodus_circuit_data_cb on_data,
                            nodus_circuit_close_cb on_close,
                            void *user,
                            nodus_circuit_handle_t **out) {
    /* Faz 1 KEM migration: unchanged behaviour, always Kyber round-3
     * (alg 0). Existing callers (nodus/tools/nodus-circ.c and three tests)
     * are untouched by this dispatch. */
    return nodus_circuit_open_e2e_alg(client, peer_fp, peer_kyber_pk, 0,
                                       on_data, on_close, user, out);
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

int nodus_circuit_attach_keyed(nodus_circuit_handle_t *h,
                               const nodus_key_t *caller_fp,
                               const uint8_t k_call[32],
                               nodus_circuit_data_cb on_data,
                               nodus_circuit_close_cb on_close,
                               void *user) {
    if (!h || !h->in_use || !caller_fp || !k_call || !h->client) return -1;
    /* Callee side: use the pre-agreed K_call (from signaling) as the per-circuit
     * channel secret. Nonces = (caller_fp, callee_fp) — same order the caller's
     * nodus_circuit_open_keyed uses, so both ends derive the identical key. */
    uint8_t nc[32], ns[32];
    memcpy(nc, caller_fp->bytes, 32);                          /* caller */
    memcpy(ns, h->client->identity.node_id.bytes, 32);         /* us = callee */
    /* C1 re-init guard (callsite-owned — init() cannot tell a live channel from
     * uninitialised memory). This is a public API and a handle is long-lived and
     * zeroed at claim, so a second attach on an already-keyed circuit would
     * re-key it in place and reset tx_counter to 0 under a key that may repeat —
     * an immediate (key, nonce) reuse. Fail closed; the caller must close the
     * circuit and open a fresh one. */
    if (h->e2e_crypto.established) {
        QGP_LOG_ERROR(LOG_TAG,
                      "attach_keyed: circuit already keyed (cid=%llu) — refusing "
                      "to re-key in place",
                      (unsigned long long)h->cid);
        return -1;
    }

    /* We ATTACHED to an inbound circuit → responder. */
    if (nodus_channel_crypto_init(&h->e2e_crypto, k_call, nc, ns,
                                   NODUS_CHANNEL_ROLE_RESPONDER) != 0) return -1;
    h->e2e_active = true;
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

    /* E2E encrypt if onion layer active.
     *
     * H2/C1: nodus_channel_encrypt does an unsynchronised tx_counter++ and
     * derives the nonce from it. send_request's send_mutex only serialises the
     * TCP write — it is taken AFTER this, so two threads sending on the same
     * handle (e.g. VoIP media + control) could both read tx_counter=N, both
     * build nonce N, and both encrypt under (key, nonce N): the exact
     * same-direction (key, nonce) reuse the role-in-nonce fix exists to prevent.
     * The role byte does NOT help here — both frames carry OUR role.
     *
     * So read+increment+encrypt must be atomic. circuits_mutex is reused rather
     * than a per-handle mutex because handles are memset(0) on claim, which
     * would zero an embedded pthread_mutex_t. The critical section is a few
     * microseconds of AES-GCM and takes no other lock; the network I/O
     * (send_request) stays OUTSIDE it, so no lock-order inversion with
     * send_mutex and no I/O under circuits_mutex. */
    if (h->e2e_active) {
        size_t enc_cap = len + NODUS_CHANNEL_OVERHEAD;
        enc_data = malloc(enc_cap);
        if (!enc_data) return -1;
        size_t enc_out = 0;
        pthread_mutex_lock(&client->circuits_mutex);
        int erc = nodus_channel_encrypt(&h->e2e_crypto, data, len,
                                        enc_data, enc_cap, &enc_out);
        pthread_mutex_unlock(&client->circuits_mutex);
        if (erc != 0) {
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
        /* H11: wipe the per-circuit AES key + counters before releasing the slot.
         * Closing only cleared in_use, so the key lingered in the fixed-array
         * slot until some later open() happened to memset it — key material must
         * never outlive the circuit. Safe to do under the lock now that the RX
         * decrypt also runs under it (it used to race this wipe and tear the key
         * mid-read); nodus_channel_crypto_clear takes no lock and no callback is
         * invoked here. */
        nodus_channel_crypto_clear(&h->e2e_crypto);
        h->e2e_active = false;
        h->in_use = false;
        pthread_mutex_unlock(&client->circuits_mutex);
    } else {
        nodus_channel_crypto_clear(&h->e2e_crypto);
        h->e2e_active = false;
        h->in_use = false;
    }
    return 0;
}
