/**
 * 4002 session transport, approved build plan 2026-10-29, section 3.3.
 *
 * Every case uses real ML-DSA-87 / ML-KEM-1024 identities, an explicitly
 * test-owned chain, kernel-chosen loopback ports, and a fake monotonic clock.
 * Jobs are taken and run by this test, independently of the socket loop;
 * worker_thread also exercises the module's thread and pollable wake.
 *
 * Cases below state their individual assertions. Compile flags: none;
 * backpressure/lifetime checks also require the orchestrator's supported
 * AddressSanitizer/UndefinedBehaviorSanitizer build. Environment: none.
 * Leaves nothing: sockets, workers and identities are released; no files.
 * False passes: failing to run workers must FAIL the positive handshake
 * assertions. Raw-peer wire checks require HELLO's literal port-version
 * bytes and complete sealed frames, so plaintext cannot pass unnoticed.
 * Socket waits poll for 1 ms and stop after ROUNDS consecutive rounds without
 * a delivered frame, moved byte, connection/gate change or handshake job.
 * Progress resets that counter; readiness, poll generations and budget resets
 * do not. The quiet gate checks require 20 consecutive rounds without progress.
 * These waits prove the asserted asynchronous condition eventually arrives;
 * a false pass would require an incorrect completion predicate or callback
 * evidence, so every payload, ordering and state assertion remains required.
 * Unrelated continued progress can postpone failure, but cannot pass a wait.
 * Poll time does not advance the fake clock used by the deadline assertions.
 * Including the server header also checks that its per-peer session type
 * can coexist with the shared module's type in one translation unit.
 */
#include "server/nodus_inter_session.h"
#include "server/nodus_server.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/enc/qgp_kyber.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_tier2.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)
#define ROUNDS 10000
#define POLL_MS 1

static nodus_identity_t ids[2];
static const uint8_t chain[CMT_P2P_SC_CHAIN_ID_SIZE] = {0x42, 0x19};
static uint64_t progress;

typedef struct {
    uint64_t progress;
    unsigned idle;
} wait_t;

static void wait_observe(wait_t *wait) {
    if (wait->progress == progress) wait->idle++;
    else { wait->progress = progress; wait->idle = 0; }
}

#define WAIT_WHILE(condition) \
    for (wait_t wait = {.progress = progress}; \
         (condition) && wait.idle < ROUNDS; wait_observe(&wait))

typedef struct {
    nodus_tcp_t tcp;
    nodus_inter_session_module_t *session;
    nodus_tcp_conn_t *conn;
    uint64_t now;
    unsigned accepts, connects, authenticated, closed, frames, fallback;
    unsigned jobs[5];
    bool auto_open;
    uint32_t next;
} endpoint_t;

static uint64_t now_ms(void *ctx) { return ((endpoint_t *)ctx)->now; }
static void accepted(nodus_tcp_conn_t *c, void *ctx) {
    endpoint_t *e = ctx; e->conn = c; e->accepts++; progress++;
}
static void connected(nodus_tcp_conn_t *c, void *ctx) {
    endpoint_t *e = ctx; e->conn = c; e->connects++; progress++;
}
static void disconnected(nodus_tcp_conn_t *c, void *ctx) {
    endpoint_t *e = ctx;
    if (e->conn == c) e->conn = NULL;
    e->closed++; progress++;
}
static void authenticated(nodus_tcp_conn_t *c, const nodus_pubkey_t *pk, void *ctx) {
    endpoint_t *e = ctx;
    CHECK(c->authenticated && memcmp(pk->bytes, c->peer_pk.bytes, NODUS_PK_BYTES) == 0);
    CHECK(!c->channel_crypto.established);
    e->authenticated++; progress++;
    if (e->auto_open) CHECK(nodus_inter_session_open(c) == 0);
}
static void frame(nodus_tcp_conn_t *c, const uint8_t *p, size_t n, void *ctx) {
    endpoint_t *e = ctx;
    CHECK(nodus_inter_session_is_open(c));
    CHECK(n >= sizeof(uint32_t));
    uint32_t seq;
    memcpy(&seq, p, sizeof(seq));
    CHECK(seq == e->next++);
    for (size_t i = sizeof(seq); i < n; ++i) CHECK(p[i] == (uint8_t)seq);
    e->frames++; progress++;
}
static void full(nodus_tcp_conn_t *c, const uint8_t *p, size_t n, void *ctx) {
    endpoint_t *e = ctx;
    (void)c;
    CHECK(n == sizeof(uint32_t));
    uint32_t seq; memcpy(&seq, p, sizeof(seq));
    CHECK(seq == UINT32_MAX);  /* deliberately diverted, never expected on wire */
    e->fallback++; progress++;
}
static void endpoint_init(endpoint_t *e, unsigned identity, size_t in, size_t out,
                          unsigned workers) {
    memset(e, 0, sizeof(*e));
    e->now = 100;
    CHECK(nodus_tcp_init(&e->tcp, -1) == 0);
    e->tcp.on_accept = accepted;
    e->tcp.on_connect = connected;
    e->tcp.on_disconnect = disconnected;
    e->tcp.on_frame = frame;
    e->tcp.cb_ctx = e;
    nodus_inter_session_config_t cfg = {
        .identity = &ids[identity], .chain_id = chain,
        .inbound_depth = in, .outbound_depth = out, .workers = workers,
        .now_ms = now_ms, .now_ctx = e,
        .on_authenticated = authenticated, .auth_ctx = e
    };
    e->session = nodus_inter_session_new(&e->tcp, &cfg);
    CHECK(e->session != NULL);
}
static void endpoint_free(endpoint_t *e) {
    nodus_tcp_close(&e->tcp);
    nodus_inter_session_free(e->session);
}
typedef struct {
    size_t queued[2];
    struct {
        uint64_t generation, enqueued, drained;
        nodus_conn_state_t state;
        bool authenticated, open;
        size_t rlen, wlen, wpos, pending_len, pending_count, pending_bytes, wire_room;
    } conns[NODUS_TCP_MAX_CONNS];
} endpoint_progress_t;

static void endpoint_progress(endpoint_t *e, endpoint_progress_t *out) {
    /* Zero padding too: compare only explicitly observed state, never an
     * entire connection with clocks, poll generations or mutable budgets. */
    memset(out, 0, sizeof(*out));
    out->queued[0] = nodus_inter_session_job_queued(e->session, false);
    out->queued[1] = nodus_inter_session_job_queued(e->session, true);
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; ++i) {
        nodus_tcp_conn_t *c = e->tcp.pool[i];
        if (!c) continue;
        out->conns[i].generation = c->generation;
        out->conns[i].enqueued = c->pending_enqueued_count;
        out->conns[i].drained = c->pending_drained_count;
        out->conns[i].state = c->state;
        out->conns[i].authenticated = c->authenticated;
        out->conns[i].open = nodus_inter_session_is_open(c);
        out->conns[i].rlen = c->rlen;
        out->conns[i].wlen = c->wlen;
        out->conns[i].wpos = c->wpos;
        out->conns[i].pending_len = c->pending_len;
        out->conns[i].pending_count = c->pending_count;
        out->conns[i].pending_bytes = c->pending_bytes;
        (void)nodus_inter_session_read_buf(c, &out->conns[i].wire_room);
    }
}

static void poll_endpoint(endpoint_t *e) {
    endpoint_progress_t before, after;
    endpoint_progress(e, &before);
    CHECK(nodus_tcp_poll(&e->tcp, POLL_MS) >= 0);
    endpoint_progress(e, &after);
    if (memcmp(&before, &after, sizeof(before)) != 0) progress++;
}
static void run_jobs(endpoint_t *e) {
    nodus_inter_session_job_t *j;
    while ((j = nodus_inter_session_job_take(e->session)) != NULL) {
        CHECK(j->work.kind > CMT_P2P_SC_JOB_NONE && j->work.kind <= CMT_P2P_SC_JOB_VERIFY);
        e->jobs[j->work.kind]++;
        progress++;
        nodus_inter_session_job_run(j);
        CHECK(nodus_inter_session_job_done(e->session, j) == CMT_OK);
    }
}
static void step(endpoint_t *a, endpoint_t *b) {
    poll_endpoint(a); poll_endpoint(b); run_jobs(a); run_jobs(b);
}
static void pair(endpoint_t *a, endpoint_t *b, unsigned a_id) {
    endpoint_init(a, a_id, 8, 8, 0);
    endpoint_init(b, 1, 8, 8, 0);
    CHECK(nodus_tcp_listen(&b->tcp, "127.0.0.1", 0) == 0);
    a->conn = nodus_tcp_connect_pinned(&a->tcp, "127.0.0.1", b->tcp.port,
                                      &ids[1].node_id);
    CHECK(a->conn != NULL);
}
static void wait_auth(endpoint_t *a, endpoint_t *b) {
    WAIT_WHILE(!a->authenticated || !b->authenticated)
        step(a, b);
    CHECK(a->authenticated == 1 && b->authenticated == 1);
}
static void send_seq(nodus_tcp_conn_t *c, uint32_t seq, size_t n) {
    uint8_t *p = malloc(n); CHECK(p != NULL && n >= sizeof(seq));
    memset(p, (uint8_t)seq, n); memcpy(p, &seq, sizeof(seq));
    CHECK(nodus_tcp_send(c, p, n) == 0);
    free(p);
}

/* 1: both roles authenticate, both gates retain plaintext and preserve order. */
static void happy_path(void) {
    endpoint_t a, b; pair(&a, &b, 0);
    send_seq(a.conn, 0, 4); send_seq(a.conn, 1, 19);
    wait_auth(&a, &b);
    send_seq(b.conn, 0, 4); send_seq(b.conn, 1, 29);
    for (wait_t wait = {.progress = progress}; wait.idle < 20; wait_observe(&wait)) step(&a, &b);
    CHECK(a.frames == 0 && b.frames == 0);
    CHECK(a.conn->pending_len > 0 && b.conn->pending_len > 0);
    CHECK(nodus_inter_session_open(a.conn) == 0);
    CHECK(nodus_inter_session_open(b.conn) == 0);
    send_seq(a.conn, 2, 4097); send_seq(b.conn, 2, 2000);
    WAIT_WHILE(a.frames != 3 || b.frames != 3) step(&a, &b);
    CHECK(a.frames == 3 && b.frames == 3);
    CHECK(nodus_tcp_decrypt_fail_total(&a.tcp) == 0);
    CHECK(nodus_tcp_decrypt_fail_total(&b.tcp) == 0);
    endpoint_free(&a); endpoint_free(&b);
}

/* Raw machine peer: records every transport byte before it is interpreted. */
typedef struct {
    int fd;
    cmt_p2p_sc_t sc;
    cmt_p2p_sc_host_t host;
    uint8_t input[4 * CMT_P2P_SC_OUT_CAP];
    size_t len;
    uint8_t wire[8 * CMT_P2P_SC_OUT_CAP];
    size_t wire_len;
    bool eof;
} raw_t;
static int raw_sign(void *ctx, const uint8_t *p, size_t n, uint8_t *out) {
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, p, n, &((nodus_identity_t *)ctx)->sk);
    if (rc == 0) memcpy(out, sig.bytes, sizeof(sig.bytes));
    return rc;
}
static int raw_verify(void *ctx, const uint8_t *s, const uint8_t *p, size_t n,
                      const uint8_t *k) {
    (void)ctx;
    nodus_sig_t sig; nodus_pubkey_t pk;
    memcpy(sig.bytes, s, sizeof(sig.bytes)); memcpy(pk.bytes, k, sizeof(pk.bytes));
    return nodus_verify_session_auth(&sig, p, n, &pk);
}
static int raw_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    return fd;
}
static void raw_init(raw_t *r, int fd, cmt_p2p_sc_role_t role,
                     unsigned identity, uint32_t version, const uint8_t *cid) {
    memset(r, 0, sizeof(*r)); r->fd = fd;
    r->host.ctx = &ids[identity]; r->host.sign = raw_sign; r->host.verify = raw_verify;
    CHECK(cmt_p2p_sc_init(&r->sc, role, &r->host, ids[identity].pk.bytes,
          role == CMT_P2P_SC_ROLE_RESPONDER ? ids[identity].mlkem_pk : NULL,
          role == CMT_P2P_SC_ROLE_RESPONDER ? ids[identity].mlkem_sk : NULL,
          version, cid) == CMT_OK);
}
static void raw_send(raw_t *r, const uint8_t *p, size_t n) {
    size_t off = 0;
    WAIT_WHILE(off < n) {
        struct pollfd fd = {.fd = r->fd, .events = POLLOUT};
        CHECK(poll(&fd, 1, POLL_MS) >= 0);
        ssize_t w = send(r->fd, p + off, n - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; progress++; }
        else CHECK(w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
    }
    CHECK(off == n);
}
static void raw_output(raw_t *r) {
    size_t n; const uint8_t *p = cmt_p2p_sc_out(&r->sc, &n);
    if (n) { raw_send(r, p, n); cmt_p2p_sc_out_consume(&r->sc, n); }
}
static void raw_read(raw_t *r) {
    for (;;) {
        CHECK(r->len < sizeof(r->input));
        ssize_t n = recv(r->fd, r->input + r->len, sizeof(r->input) - r->len, 0);
        if (n > 0) {
            CHECK(r->wire_len + (size_t)n <= sizeof(r->wire));
            memcpy(r->wire + r->wire_len, r->input + r->len, (size_t)n);
            r->wire_len += (size_t)n; r->len += (size_t)n; progress++;
        } else if (n == 0) {
            if (!r->eof) progress++;
            r->eof = true; return;
        }
        else {
            if (errno == ECONNRESET) {
                if (!r->eof) progress++;
                r->eof = true; return;
            }
            CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
            return;
        }
    }
}
static void raw_consume(raw_t *r, size_t n) {
    CHECK(n <= r->len); r->len -= n; memmove(r->input, r->input + n, r->len);
    if (n) progress++;
}
static void raw_recv_hs(raw_t *r) {
    size_t used = 0;
    CHECK(cmt_p2p_sc_recv(&r->sc, r->input, r->len, &used) == CMT_OK);
    raw_consume(r, used);
}
static void raw_jobs(raw_t *r) {
    const cmt_p2p_sc_job_t *j;
    while ((j = cmt_p2p_sc_job(&r->sc)) != NULL) {
        CHECK(cmt_p2p_sc_job_done(&r->sc, cmt_p2p_sc_job_run(j, &r->host)) == CMT_OK);
        progress++;
    }
}
static void raw_step(endpoint_t *e, raw_t *r) {
    raw_output(r); poll_endpoint(e); run_jobs(e); raw_read(r);
    if (!cmt_p2p_sc_is_authenticated(&r->sc)) { raw_recv_hs(r); raw_jobs(r); }
}
static void raw_acceptor(endpoint_t *e, raw_t *r, uint32_t ver, const uint8_t *cid) {
    endpoint_init(e, 1, 8, 8, 0);
    CHECK(nodus_tcp_listen(&e->tcp, "127.0.0.1", 0) == 0);
    raw_init(r, raw_socket(e->tcp.port), CMT_P2P_SC_ROLE_INITIATOR, 0, ver, cid);
}
static void raw_free(raw_t *r) { close(r->fd); cmt_p2p_sc_clear(&r->sc); }
static size_t prefix(const uint8_t *p, size_t n, size_t *body) {
    size_t v = 0;
    for (size_t i = 0; i < CMT_P2P_SC_UVARINT_MAX && i < n; ++i) {
        v |= (size_t)(p[i] & 127) << (7 * i);
        if (!(p[i] & 128)) { *body = v; return i + 1; }
    }
    CHECK(false); return 0;
}

/* 1/2: outbound HELLO bytes, sealed-only application stream, early pin. */
static void wire_and_pin(bool wrong_pin) {
    endpoint_t e; endpoint_init(&e, 0, 8, 8, 0);
    int listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(listener >= 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    CHECK(listen(listener, 1) == 0);
    socklen_t sl = sizeof(sa); CHECK(getsockname(listener, (struct sockaddr *)&sa, &sl) == 0);
    e.conn = nodus_tcp_connect_pinned(&e.tcp, "127.0.0.1", ntohs(sa.sin_port),
                                     &ids[wrong_pin ? 0 : 1].node_id);
    CHECK(e.conn != NULL);
    int fd = accept(listener, NULL, NULL); CHECK(fd >= 0); close(listener);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    raw_t *r = calloc(1, sizeof(*r)); CHECK(r != NULL);
    raw_init(r, fd, CMT_P2P_SC_ROLE_RESPONDER, 1, CMT_P2P_SC_PROTO_VER_4002, chain);
    WAIT_WHILE(r->sc.state == CMT_P2P_SC_ST_WAIT_HELLO) {
        poll_endpoint(&e); raw_read(r); raw_recv_hs(r);
    }
    CHECK(r->sc.state == CMT_P2P_SC_ST_WAIT_KEYX);
    size_t body; size_t pfx = prefix(r->wire, r->wire_len, &body);
    CHECK(body == CMT_P2P_SC_HELLO_BODY && r->wire[pfx] == 0x01);
    const uint8_t version[] = {0x0f, 0xa2, 0x00, 0x01};
    CHECK(memcmp(r->wire + pfx + 1 + CMT_P2P_SC_DSA_PK_SIZE + CMT_P2P_SC_NONCE_SIZE,
                 version, sizeof(version)) == 0);
    size_t hello_len = pfx + body;
    if (wrong_pin) {
        raw_output(r);
        WAIT_WHILE(!e.closed || !r->eof) {
            poll_endpoint(&e); run_jobs(&e); raw_read(r);
        }
        CHECK(e.closed == 1 && r->eof && r->wire_len == hello_len);
        CHECK(e.jobs[CMT_P2P_SC_JOB_ENCAPS] == 0 && e.jobs[CMT_P2P_SC_JOB_SIGN] == 0);
    } else {
        WAIT_WHILE(!e.authenticated || !cmt_p2p_sc_is_authenticated(&r->sc))
            raw_step(&e, r);
        CHECK(e.authenticated == 1 && cmt_p2p_sc_is_authenticated(&r->sc));
        raw_output(r); CHECK(nodus_inter_session_open(e.conn) == 0);
        uint8_t expected[31]; memset(expected, 0x5a, sizeof(expected));
        CHECK(nodus_tcp_send(e.conn, expected, sizeof(expected)) == 0);
        size_t got = 0; uint8_t plaintext[128];
        WAIT_WHILE(got < sizeof(expected) + NODUS_FRAME_HEADER_SIZE) {
            poll_endpoint(&e); raw_read(r);
            size_t used = 0, n = 0;
            CHECK(cmt_p2p_sc_read(&r->sc, r->input, r->len, &used,
                                  plaintext + got, sizeof(plaintext) - got, &n) == CMT_OK);
            raw_consume(r, used); got += n;
        }
        nodus_frame_t f;
        CHECK(nodus_frame_decode(plaintext, got, &f) == (int)got);
        CHECK(f.payload_len == sizeof(expected) && memcmp(f.payload, expected, sizeof(expected)) == 0);
        size_t key_body; size_t kp = prefix(r->wire + hello_len, r->wire_len - hello_len, &key_body);
        CHECK(key_body == CMT_P2P_SC_KEYX_BODY);
        CHECK((r->wire_len - hello_len - kp - key_body) % CMT_P2P_SC_SEALED_FRAME_SIZE == 0);
        CHECK(r->wire_len > hello_len + kp + key_body + CMT_P2P_SC_AUTHSIG_FRAMES_MAX * CMT_P2P_SC_SEALED_FRAME_SIZE);
    }
    CHECK(e.frames == 0); raw_free(r); free(r); endpoint_free(&e);
}

/* 3: refused before allocation, connect callback or any socket write. */
static void no_pin(void) {
    endpoint_t e; endpoint_init(&e, 0, 1, 1, 0);
    int listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(listener >= 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(listener, 1) == 0);
    socklen_t sl = sizeof(sa); CHECK(getsockname(listener, (struct sockaddr *)&sa, &sl) == 0);
    CHECK(fcntl(listener, F_SETFL, O_NONBLOCK) == 0);
    CHECK(nodus_tcp_connect(&e.tcp, "127.0.0.1", ntohs(sa.sin_port)) == NULL);
    CHECK(nodus_tcp_connect_pinned(&e.tcp, "127.0.0.1", ntohs(sa.sin_port), NULL) == NULL);
    CHECK(e.tcp.count == 0 && e.connects == 0);
    CHECK(accept(listener, NULL, NULL) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    close(listener);
    endpoint_free(&e);
}
/* 4: matching identities never reach admission or frame dispatch, either role.
 * Hold both VERIFY results so each role rejects self first in turn; the peer's
 * completion after EOF must be rejected, without reviving either connection. */
static void reject_self(void) {
    for (int first = 0; first < 2; ++first) {
        endpoint_t a, b; pair(&a, &b, 1);
        endpoint_t *ends[] = {&a, &b};
        nodus_inter_session_job_t *verify[2] = {NULL, NULL};
        WAIT_WHILE(!verify[0] || !verify[1]) {
            for (int k = 0; k < 2; ++k) {
                endpoint_t *e = ends[k];
                poll_endpoint(e);
                nodus_inter_session_job_t *j;
                while (!verify[k] && (j = nodus_inter_session_job_take(e->session)) != NULL) {
                    CHECK(j->work.kind > CMT_P2P_SC_JOB_NONE && j->work.kind <= CMT_P2P_SC_JOB_VERIFY);
                    e->jobs[j->work.kind]++;
                    progress++;
                    if (j->work.kind == CMT_P2P_SC_JOB_VERIFY) { verify[k] = j; break; }
                    nodus_inter_session_job_run(j);
                    CHECK(nodus_inter_session_job_done(e->session, j) == CMT_OK);
                }
            }
        }
        CHECK(verify[0] && verify[1] && a.closed == 0 && b.closed == 0);
        for (int k = 0; k < 2; ++k) {
            nodus_inter_session_job_run(verify[k]);
            CHECK(verify[k]->work.rc == 0);
        }
        CHECK(nodus_inter_session_job_done(ends[first]->session, verify[first]) == CMT_OK);
        WAIT_WHILE(!ends[first]->closed) poll_endpoint(ends[first]);
        CHECK(ends[first]->closed == 1);
        endpoint_t *peer = ends[1 - first];
        WAIT_WHILE(!peer->closed) poll_endpoint(peer);
        CHECK(peer->closed == 1);
        CHECK(a.conn == NULL && b.conn == NULL && a.tcp.count == 0 && b.tcp.count == 0);
        CHECK(a.authenticated == 0 && b.authenticated == 0 && a.frames == 0 && b.frames == 0);
        CHECK(nodus_inter_session_job_done(peer->session, verify[1 - first]) == CMT_REJECT);
        CHECK(a.closed == 1 && b.closed == 1 && a.frames == 0 && b.frames == 0);
        CHECK(a.authenticated == 0 && b.authenticated == 0);
        CHECK(a.conn == NULL && b.conn == NULL && a.tcp.count == 0 && b.tcp.count == 0);
        endpoint_free(&a); endpoint_free(&b);
    }
}
/* 5: mismatched version/chain fail before any acceptor asymmetric job. */
static void mismatch(uint32_t ver, bool bad_chain) {
    endpoint_t e; raw_t *r = calloc(1, sizeof(*r)); CHECK(r != NULL);
    uint8_t cid[sizeof(chain)]; memcpy(cid, chain, sizeof(cid)); if (bad_chain) cid[0] ^= 1;
    raw_acceptor(&e, r, ver, cid); raw_output(r);
    WAIT_WHILE(!e.closed) poll_endpoint(&e);
    CHECK(e.closed == 1 && e.authenticated == 0 && e.frames == 0);
    for (int j = 1; j < 5; ++j) CHECK(e.jobs[j] == 0);
    CHECK(nodus_inter_session_job_take(e.session) == NULL);
    raw_free(r); free(r); endpoint_free(&e);
}
/* 6/11: old framed hello and a 1 MiB junk flood close before dispatch. */
static void old_or_flood(bool flood) {
    endpoint_t e; endpoint_init(&e, 1, 8, 8, 0);
    CHECK(nodus_tcp_listen(&e.tcp, "127.0.0.1", 0) == 0);
    int fd = raw_socket(e.tcp.port);
    WAIT_WHILE(!e.conn) poll_endpoint(&e);
    CHECK(e.conn && e.conn->rcap <= CMT_P2P_SC_HS_MSG_MAX);
    uint8_t *p = malloc(1024 * 1024); CHECK(p != NULL);
    size_t n;
    if (flood) { memset(p, 0xff, 1024 * 1024); n = 1024 * 1024; }
    else {
        uint8_t hello[4096]; size_t hn = 0;
        CHECK(nodus_t2_hello(1, &ids[0].pk, &ids[0].node_id, hello, sizeof(hello), &hn) == 0);
        n = nodus_frame_encode(p, 1024 * 1024, hello, (uint32_t)hn); CHECK(n > 0);
    }
    size_t off = 0;
    WAIT_WHILE(!e.closed) {
        if (off < n) {
            ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
            if (w > 0) { off += (size_t)w; progress++; }
        }
        poll_endpoint(&e);
        if (e.conn) CHECK(e.conn->rlen <= CMT_P2P_SC_HS_MSG_MAX && e.conn->rcap <= CMT_P2P_SC_HS_MSG_MAX);
    }
    CHECK(e.closed == 1 && e.frames == 0 && e.authenticated == 0);
    CHECK(nodus_inter_session_job_take(e.session) == NULL);
    free(p); close(fd); endpoint_free(&e);
}

/* Advance raw initiator through HELLO_R, leaving ENCAPS outstanding. */
static void raw_to_encaps(endpoint_t *e, raw_t *r) {
    raw_acceptor(e, r, CMT_P2P_SC_PROTO_VER_4002, chain); raw_output(r);
    WAIT_WHILE(!cmt_p2p_sc_job(&r->sc)) {
        poll_endpoint(e); raw_read(r); raw_recv_hs(r);
    }
    CHECK(cmt_p2p_sc_job(&r->sc) && cmt_p2p_sc_job(&r->sc)->kind == CMT_P2P_SC_JOB_ENCAPS);
}
/* 7/8: repeated KEYX, or a round-3 ciphertext, cannot produce a session. */
static void bad_keyx(bool round3) {
    endpoint_t e; raw_t *r = calloc(1, sizeof(*r)); CHECK(r != NULL);
    raw_to_encaps(&e, r);
    const cmt_p2p_sc_job_t *j = cmt_p2p_sc_job(&r->sc);
    int rc = round3 ? qgp_kem1024_encapsulate(j->kem_ct_out, j->kem_ss_out, j->kem_pk)
                    : cmt_p2p_sc_job_run(j, &r->host);
    CHECK(rc == 0 && cmt_p2p_sc_job_done(&r->sc, rc) == CMT_OK);
    if (!round3) {
        size_t n; const uint8_t *p = cmt_p2p_sc_out(&r->sc, &n);
        CHECK(n > CMT_P2P_SC_KEYX_BODY);
        raw_send(r, p, n); raw_send(r, p, n); cmt_p2p_sc_out_consume(&r->sc, n);
    } else { raw_jobs(r); raw_output(r); }
    WAIT_WHILE(!e.closed) { poll_endpoint(&e); run_jobs(&e); }
    CHECK(e.closed == 1 && e.authenticated == 0 && e.frames == 0);
    raw_free(r); free(r); endpoint_free(&e);
}

/* 9: a legal AUTHSIG's last sealed frame also carries one nodus frame.
 * Fixture uses the machine's own writer with a COPY at row 9, counter 4;
 * no separate cipher/nonce implementation can mask a production error. */
static void trailing_authsig(void) {
    endpoint_t e; raw_t *r = calloc(1, sizeof(*r)); CHECK(r != NULL);
    raw_to_encaps(&e, r); raw_jobs(r);
    size_t n, body; const uint8_t *p = cmt_p2p_sc_out(&r->sc, &n);
    size_t kp = prefix(p, n, &body); CHECK(body == CMT_P2P_SC_KEYX_BODY);
    size_t keyx = kp + body;
    CHECK(n == keyx + 5 * CMT_P2P_SC_SEALED_FRAME_SIZE);
    raw_send(r, p, keyx + 4 * CMT_P2P_SC_SEALED_FRAME_SIZE);
    uint8_t auth[CMT_P2P_SC_AUTHSIG_WIRE_MAX + 32];
    size_t v = CMT_P2P_SC_AUTHSIG_BODY, ap = 0;
    do { auth[ap++] = (uint8_t)((v & 127) | (v > 127 ? 128 : 0)); v >>= 7; } while (v);
    auth[ap++] = CMT_P2P_SC_MSG_AUTHSIG;
    memcpy(auth + ap, r->sc.local_sig, CMT_P2P_SC_SIG_SIZE); ap += CMT_P2P_SC_SIG_SIZE;
    uint32_t seq = 0;
    size_t fn = nodus_frame_encode(auth + ap, sizeof(auth) - ap, (uint8_t *)&seq, sizeof(seq));
    CHECK(fn > 0);
    cmt_p2p_sc_t *writer = malloc(sizeof(*writer)); CHECK(writer != NULL);
    memcpy(writer, &r->sc, sizeof(*writer));
    writer->state = CMT_P2P_SC_ST_AUTHENTICATED; writer->send_counter = 4;
    uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE]; size_t sealed_n;
    CHECK(cmt_p2p_sc_write(writer, auth + 4 * CMT_P2P_SC_DATA_MAX_SIZE,
          ap + fn - 4 * CMT_P2P_SC_DATA_MAX_SIZE, sealed, sizeof(sealed), &sealed_n) == CMT_OK);
    CHECK(sealed_n == sizeof(sealed)); cmt_p2p_sc_clear(writer); free(writer);
    raw_send(r, sealed, sealed_n); cmt_p2p_sc_out_consume(&r->sc, n);
    nodus_inter_session_job_t *verify = NULL;
    WAIT_WHILE(!verify) {
        poll_endpoint(&e);
        nodus_inter_session_job_t *job;
        while ((job = nodus_inter_session_job_take(e.session)) != NULL) {
            progress++;
            if (job->work.kind == CMT_P2P_SC_JOB_VERIFY) { verify = job; break; }
            nodus_inter_session_job_run(job);
            CHECK(nodus_inter_session_job_done(e.session, job) == CMT_OK);
        }
    }
    CHECK(verify && e.frames == 0 && e.authenticated == 0);
    for (wait_t wait = {.progress = progress}; wait.idle < 20; wait_observe(&wait)) poll_endpoint(&e);
    CHECK(e.frames == 0);
    nodus_inter_session_job_run(verify);
    CHECK(nodus_inter_session_job_done(e.session, verify) == CMT_OK);
    WAIT_WHILE(!e.authenticated) poll_endpoint(&e);
    CHECK(e.authenticated == 1 && e.frames == 0);
    CHECK(nodus_inter_session_open(e.conn) == 0);
    WAIT_WHILE(!e.frames) poll_endpoint(&e);
    CHECK(e.frames == 1);
    raw_free(r); free(r); endpoint_free(&e);
}

/* 10: silent, HELLO-only, and authenticated-but-not-open share ONE deadline. */
static void deadlines(void) {
    for (int stage = 0; stage < 3; ++stage) {
        endpoint_t e; raw_t *r = calloc(1, sizeof(*r)); CHECK(r != NULL);
        raw_acceptor(&e, r, CMT_P2P_SC_PROTO_VER_4002, chain);
        if (stage == 1) raw_output(r);
        WAIT_WHILE(stage == 2 ? !e.authenticated : !e.accepts) {
            if (stage == 2) raw_step(&e, r); else poll_endpoint(&e);
        }
        CHECK(e.accepts == 1 && e.conn != NULL);
        if (stage == 2) CHECK(e.authenticated == 1);
        e.now = 3099; poll_endpoint(&e); CHECK(e.closed == 0);
        e.now = 3100; poll_endpoint(&e); CHECK(e.closed == 1 && e.frames == 0);
        raw_free(r); free(r); endpoint_free(&e);
    }
    endpoint_t a, b; pair(&a, &b, 0); wait_auth(&a, &b);
    a.now = 3099; poll_endpoint(&a); CHECK(a.closed == 0);
    a.now = 3100; poll_endpoint(&a); CHECK(a.closed == 1 && a.frames == 0);
    endpoint_free(&a); endpoint_free(&b);
}

/* Buffered sealed/plaintext frames resume across a one-frame budget with
 * no socket input, in both directions. The production writer supplies the
 * fixture through the receive staging API; no socket write can hide a lost
 * pending-read trigger. Flags/environment/cleanup as above. */
static void buffered_reads(void) {
    for (unsigned direction = 0; direction < 2; ++direction) {
        endpoint_t a, b; pair(&a, &b, 0); wait_auth(&a, &b);
        CHECK(nodus_inter_session_open(a.conn) == 0 && nodus_inter_session_open(b.conn) == 0);
        endpoint_t *sender = direction ? &b : &a;
        endpoint_t *receiver = direction ? &a : &b;
        receiver->tcp.read_budget_frames = 1;
        for (uint32_t seq = 0; seq < 3; ++seq) {
            uint8_t plain[NODUS_FRAME_HEADER_SIZE + sizeof(seq)];
            size_t n = nodus_frame_encode(plain, sizeof(plain), (uint8_t *)&seq, sizeof(seq));
            CHECK(n == sizeof(plain));
            size_t room = 0, written = 0;
            uint8_t *wire = nodus_inter_session_read_buf(receiver->conn, &room);
            CHECK(wire && room >= CMT_P2P_SC_SEALED_FRAME_SIZE);
            CHECK(nodus_inter_session_seal(sender->conn, plain, n, wire, room, &written) == CMT_OK);
            CHECK(written == CMT_P2P_SC_SEALED_FRAME_SIZE);
            nodus_inter_session_read_done(receiver->conn, written);
        }
        nodus_tcp_session_resume(receiver->conn);
        for (unsigned expected = 1; expected <= 3; ++expected) {
            struct pollfd fd = {.fd = receiver->conn->fd, .events = POLLIN};
            CHECK(poll(&fd, 1, 0) == 0);
            CHECK(receiver->frames == expected - 1);
            poll_endpoint(receiver);
            CHECK(receiver->conn && receiver->frames == expected);
            CHECK(receiver->conn->read_pending == (expected < 3));
            CHECK(receiver->tcp.read_count == (expected < 3 ? 1 : 0));
        }
        CHECK(receiver->conn->rlen == 0 && a.closed == 0 && b.closed == 0);
        CHECK(nodus_tcp_decrypt_fail_total(&receiver->tcp) == 0);
        endpoint_free(&a); endpoint_free(&b);
    }
}

/* 12: real socket backpressure, FIFO, full diversion, then counter continuity.
 * Payload storage is freed immediately after send (borrowed-buffer check). */
static void backpressure(void) {
    endpoint_t a, b; pair(&a, &b, 0); wait_auth(&a, &b);
    CHECK(nodus_inter_session_open(a.conn) == 0 && nodus_inter_session_open(b.conn) == 0);
    int small = 4096; CHECK(setsockopt(a.conn->fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    a.tcp.on_pending_full = full; a.tcp.pending_full_ctx = &a;
    unsigned count = 0;
    while (a.conn->pending_count < NODUS_PENDING_MAX_FRAMES && count < 20000) {
        send_seq(a.conn, count++, 64 * 1024);
    }
    CHECK(a.conn->pending_count == NODUS_PENDING_MAX_FRAMES && a.fallback == 0);
    uint32_t diverted = UINT32_MAX;
    CHECK(nodus_tcp_send(a.conn, (uint8_t *)&diverted, sizeof(diverted)) == 0);
    CHECK(a.fallback == 1);
    WAIT_WHILE(b.frames != count) step(&a, &b);
    if (b.frames != count || a.closed || b.closed) {
        /* Failure-only evidence: distinguish queued writes, buffered reads
         * and kernel readiness without consuming data or extending the wait. */
        fprintf(stderr, "backpressure: sent=%u received=%u closed=%u/%u\n",
                count, b.frames, a.closed, b.closed);
        endpoint_t *ends[] = {&a, &b};
        for (unsigned k = 0; k < 2; ++k) {
            nodus_tcp_conn_t *c = ends[k]->conn;
            if (!c) continue;
            struct pollfd fd = {.fd = c->fd, .events = POLLIN | POLLOUT};
            int ready = poll(&fd, 1, 0);
            nodus_frame_t buffered = {0};
            int decoded = nodus_frame_decode(c->rbuf, c->rlen, &buffered);
            size_t frame_need = c->rlen >= NODUS_FRAME_HEADER_SIZE
                              ? NODUS_FRAME_HEADER_SIZE + (size_t)buffered.payload_len : 0;
            size_t wire_room = 0;
            (void)nodus_inter_session_read_buf(c, &wire_room);
            fprintf(stderr, "backpressure endpoint=%u open=%d wpos=%zu wlen=%zu "
                    "pending=%zu bytes=%zu enqueued=%llu drained=%llu "
                    "rlen=%zu frame_decode=%d frame_need=%zu wire_room=%zu "
                    "read_pending=%d read_count=%d ready=%d revents=%x\n",
                    k, nodus_inter_session_is_open(c), c->wpos, c->wlen,
                    c->pending_count, c->pending_bytes,
                    (unsigned long long)c->pending_enqueued_count,
                    (unsigned long long)c->pending_drained_count,
                    c->rlen, decoded, frame_need, wire_room,
                    c->read_pending, ends[k]->tcp.read_count,
                    ready, (unsigned)fd.revents);
        }
    }
    CHECK(b.frames == count && a.closed == 0 && b.closed == 0);
    CHECK(a.conn->pending_count == 0);
    send_seq(a.conn, count, 17);
    WAIT_WHILE(b.frames != count + 1) step(&a, &b);
    CHECK(b.frames == count + 1 && nodus_tcp_decrypt_fail_total(&b.tcp) == 0);
    endpoint_free(&a); endpoint_free(&b);
}

/* 13: each class is bounded; a completed job for a reused slot is discarded. */
static void full_queue_and_generation(void) {
    for (int outbound = 0; outbound < 2; ++outbound) {
        endpoint_t a, b, c;
        endpoint_init(&a, 0, 1, 1, 0); endpoint_init(&b, 1, 1, 1, 0);
        endpoint_init(&c, 1, 1, 1, 0);
        CHECK(nodus_tcp_listen(&b.tcp, "127.0.0.1", 0) == 0);
        a.conn = nodus_tcp_connect_pinned(&a.tcp, "127.0.0.1", b.tcp.port, &ids[1].node_id);
        CHECK(a.conn != NULL);
        endpoint_t *victim = outbound ? &a : &b;
        WAIT_WHILE(!nodus_inter_session_job_queued(victim->session, outbound)) {
            poll_endpoint(&a); poll_endpoint(&b);
            if (!outbound) run_jobs(&a);
        }
        CHECK(nodus_inter_session_job_queued(victim->session, outbound) == 1);
        int slot = victim->conn->slot;
        uint64_t old_gen = victim->conn->generation;
        nodus_tcp_disconnect(&victim->tcp, victim->tcp.pool[slot]);
        /* First job stays QUEUED while a new handshake needs the same class. */
        nodus_tcp_conn_t *fresh;
        if (outbound) {
            CHECK(nodus_tcp_listen(&c.tcp, "127.0.0.1", 0) == 0);
            fresh = nodus_tcp_connect_pinned(&a.tcp, "127.0.0.1", c.tcp.port, &ids[1].node_id);
        } else {
            fresh = nodus_tcp_connect_pinned(&c.tcp, "127.0.0.1", b.tcp.port, &ids[1].node_id);
        }
        CHECK(fresh != NULL);
        unsigned before = victim->closed;
        WAIT_WHILE(victim->closed == before) {
            poll_endpoint(&a); poll_endpoint(&b); poll_endpoint(&c);
            if (!outbound) run_jobs(&c);
        }
        CHECK(victim->closed == before + 1);
        nodus_inter_session_job_t *held = nodus_inter_session_job_take(victim->session);
        CHECK(held && held->work.gen == old_gen);
        /* Reuse the slot once more, leaving the fresh machine waiting for
         * HELLO / HELLO_R. A stale completion must leave it live. */
        int raw_fd = -1;
        if (outbound) {
            fresh = nodus_tcp_connect_pinned(&a.tcp, "127.0.0.1", b.tcp.port, &ids[1].node_id);
            CHECK(fresh && fresh->slot == slot);
            WAIT_WHILE(fresh->state != NODUS_CONN_CONNECTED) poll_endpoint(&a);
        } else {
            raw_fd = raw_socket(b.tcp.port);
            WAIT_WHILE(!victim->conn) poll_endpoint(victim);
            fresh = victim->conn;
        }
        CHECK(fresh && fresh->slot == slot && fresh->session && fresh->generation != old_gen);
        nodus_inter_session_job_run(held);
        CHECK(nodus_inter_session_job_done(victim->session, held) == CMT_REJECT);
        CHECK(victim->tcp.pool[slot] == fresh && fresh->state == NODUS_CONN_CONNECTED);
        if (raw_fd >= 0) close(raw_fd);
        CHECK(a.frames == 0 && b.frames == 0 && c.frames == 0);
        endpoint_free(&a); endpoint_free(&b); endpoint_free(&c);
    }
}

/* 14: listener guard in both directions; no Unix socket is created here. */
static void mode_guard(void) {
    endpoint_t e; endpoint_init(&e, 0, 1, 1, 0);
    CHECK(nodus_tcp_ws_listen(&e.tcp, 0) == -1);
    CHECK(nodus_tcp_unix_listen(&e.tcp, "/unused-session-guard.sock", NODUS_TCP_UNIX_UID_SELF) == -1);
    endpoint_free(&e);
    for (int unix_listener = 0; unix_listener < 2; ++unix_listener) {
        nodus_tcp_t tcp; CHECK(nodus_tcp_init(&tcp, -1) == 0);
        int unix_fd = -1;
        if (unix_listener) {
            /* A real listener in Linux's abstract namespace: no socket file.
             * The fixture installs the descriptor in the transport entry
             * inspected by the mode guard; no application traffic uses it. */
            unix_fd = socket(AF_UNIX, SOCK_STREAM, 0); CHECK(unix_fd >= 0);
            struct sockaddr_un sa = {.sun_family = AF_UNIX};
            int name_len = snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1,
                                     "nodus-inter-session-%ld", (long)getpid());
            CHECK(name_len > 0 && (size_t)name_len < sizeof(sa.sun_path) - 1);
            socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + (size_t)name_len);
            CHECK(bind(unix_fd, (struct sockaddr *)&sa, len) == 0 && listen(unix_fd, 1) == 0);
            tcp.unix_listen_fd = unix_fd;
        } else CHECK(nodus_tcp_ws_listen(&tcp, 0) == 0);
        nodus_inter_session_config_t cfg = {
            .identity = &ids[0], .chain_id = chain, .inbound_depth = 1,
            .outbound_depth = 1, .workers = 0
        };
        CHECK(nodus_inter_session_new(&tcp, &cfg) == NULL);
        if (unix_fd >= 0) { tcp.unix_listen_fd = -1; close(unix_fd); }
        nodus_tcp_close(&tcp);
    }
}

/* Worker touches copies only; wake becomes readable before loop applies jobs. */
static void worker_thread(void) {
    endpoint_t a, b;
    endpoint_init(&a, 0, 8, 8, 1); endpoint_init(&b, 1, 8, 8, 1);
    a.auto_open = b.auto_open = true;
    CHECK(nodus_tcp_listen(&b.tcp, "127.0.0.1", 0) == 0);
    a.conn = nodus_tcp_connect_pinned(&a.tcp, "127.0.0.1", b.tcp.port, &ids[1].node_id);
    CHECK(a.conn);
    bool woke = false;
    WAIT_WHILE(!a.authenticated || !b.authenticated) {
        poll_endpoint(&a); poll_endpoint(&b);
        struct pollfd fds[2] = {
            {.fd = nodus_inter_session_wake_fd(a.session), .events = POLLIN},
            {.fd = nodus_inter_session_wake_fd(b.session), .events = POLLIN}
        };
        int rc = poll(fds, 2, 10); CHECK(rc >= 0);
        if (fds[0].revents & POLLIN || fds[1].revents & POLLIN) woke = true;
    }
    CHECK(woke && a.authenticated == 1 && b.authenticated == 1);
    send_seq(a.conn, 0, 37);
    WAIT_WHILE(!b.frames) { poll_endpoint(&a); poll_endpoint(&b); }
    CHECK(b.frames == 1);
    endpoint_free(&a); endpoint_free(&b);
}

int main(void) {
    CHECK(nodus_identity_generate(&ids[0]) == 0 && nodus_identity_generate(&ids[1]) == 0);
    happy_path(); wire_and_pin(false); wire_and_pin(true); no_pin(); reject_self();
    mismatch(CMT_P2P_SC_PROTO_VER_4004, false); mismatch(8, false);
    mismatch(CMT_P2P_SC_PROTO_VER_4002, true);
    old_or_flood(false); bad_keyx(false); bad_keyx(true); trailing_authsig();
    deadlines(); old_or_flood(true); buffered_reads(); backpressure(); full_queue_and_generation();
    mode_guard(); worker_thread();
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]);
    puts("test_inter_session: all cases passed");
    return 0;
}
