/**
 * 4001 session glue (approved plan 2026-11-02-4001-ws-session-build-plan,
 * sections 2.1 a-e, 2.1 h and 4.1), transport level.
 *
 * What it proves (each assertion would be false if the behaviour were absent):
 *   1. Trusted list (D3): an initiator without any ML-KEM key reaches a
 *      responder whose key is listed at any position of a list of several;
 *      a list that does not hold the responder aborts the client before it
 *      encapsulates or signs (its ENCAPS and SIGN job counters stay 0).
 *   2. An empty or missing list is refused by the dial before any socket
 *      exists (D4), for the list form and for the one-key pinned form.
 *   3. Wire: the first bytes a 4001 initiator writes are a HELLO whose
 *      proto_ver bytes are 0F A1 00 01, and nothing else follows until the
 *      peer answers.
 *   4. proto_ver 4002 against a 4001 responder, and a chain id that differs
 *      by one byte, are refused before any KEM or signing job runs.
 *   5. Reject-self: a dialer holding the responder's own key gets no
 *      authenticated session and the responder delivers no frame.
 *   6. An initiator-only module takes no inbound connection.
 *   7. A responder whose chain is not known closes at accept with zero bytes
 *      written; a connection already open stays open (answer 3).
 *   8. One owner per machine (2.1 e): with a write lock installed, two
 *      threads send while the owner polls; every frame arrives, in each
 *      thread's send order, and the owner thread alone seals (the sealed
 *      stream decrypts in strict order, which a second machine caller would
 *      break: the counters would collide and the AEAD would fail).
 *
 *   Part B, a real nodus_server_t (ports 15500-15505, chain id set on the
 *   server directly) driven by a raw-machine client:
 *   9. A raw 4001 client authenticates; the node serves its request carrying
 *      a zero token (A6); the client key is the session identity; every byte
 *      the node writes after the handshake is whole 1044-byte sealed frames.
 *  10. The old T2 hello frame gets zero bytes back and a closed connection.
 *  11. The node's own key (reflection), proto_ver 4002 and a chain id one
 *      byte off never authenticate.
 *  12. The fifth session of one identity evicts the oldest (limit 4).
 *  13. No chain id known -> a new connection is closed at accept, zero bytes.
 *   Part C, the real nodus_client_t against that server (polled by a thread
 *   of this test):
 *  14. A config without a trusted list, with a negative count, or without a
 *      chain id is refused at nodus_client_init (D4, A3).
 *  15. A list that does not hold the node never becomes ready; a list that
 *      holds it at the second position does, answers a request, reports the
 *      node's key as server_dil_pk, and a new connection to the same node
 *      reports a larger generation (nodus_client_conn_generation).
 *
 * Compile flags: none. Orchestrator also runs it under ASan/UBSan (case 8
 * is a borrowed-buffer / threading case). Environment: none; Part A uses
 * kernel-chosen loopback ports, Part B the fixed ports above and a
 * /tmp/nodus_client_session_<pid> directory it removes. Leaves nothing
 * behind: sockets, workers, identities freed.
 * How it can falsely pass: jobs are taken and run by this test; if it did
 * not run them every positive case would FAIL (no authentication), so a
 * pass needs the handshake to complete. Waits count rounds without
 * progress, never wall time; they never pass by waiting.
 */
#include "server/nodus_inter_session.h"
#include "crypto/nodus_identity.h"
#include "protocol/nodus_wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)
#define ROUNDS 20000
#define POLL_MS 1

static nodus_identity_t ids[3];
static const uint8_t chain[CMT_P2P_SC_CHAIN_ID_SIZE] = {0x42, 0x19};
static uint64_t progress;

typedef struct { uint64_t progress; unsigned idle; } wait_t;
static void wait_observe(wait_t *w) {
    if (w->progress == progress) w->idle++;
    else { w->progress = progress; w->idle = 0; }
}
#define WAIT_WHILE(cond) \
    for (wait_t wait = {.progress = progress}; (cond) && wait.idle < ROUNDS; wait_observe(&wait))

typedef struct {
    nodus_tcp_t tcp;
    nodus_inter_session_module_t *mod;
    nodus_tcp_conn_t *conn;
    unsigned accepts, connects, authenticated, closed, frames;
    unsigned jobs[5];
    bool chain_known;
    /* case 8: per-sender-thread next expected sequence */
    uint32_t next_seq[2];
    unsigned bad_order;
} ep_t;

static void on_accept(nodus_tcp_conn_t *c, void *ctx) { ep_t *e = ctx; e->conn = c; e->accepts++; progress++; }
static void on_connect(nodus_tcp_conn_t *c, void *ctx) { ep_t *e = ctx; e->conn = c; e->connects++; progress++; }
static void on_disconnect(nodus_tcp_conn_t *c, void *ctx) {
    ep_t *e = ctx; if (e->conn == c) e->conn = NULL; e->closed++; progress++;
}
static void on_authed(nodus_tcp_conn_t *c, const nodus_pubkey_t *pk, void *ctx) {
    ep_t *e = ctx;
    CHECK(c->authenticated && memcmp(pk->bytes, c->peer_pk.bytes, NODUS_PK_BYTES) == 0);
    e->authenticated++; progress++;
    CHECK(nodus_inter_session_open(c) == 0);
}
static void on_frame(nodus_tcp_conn_t *c, const uint8_t *p, size_t n, void *ctx) {
    ep_t *e = ctx;
    CHECK(nodus_inter_session_is_open(c));
    if (n >= 5 && p[0] < 2) {   /* case 8 payload: thread id, u32 seq */
        uint32_t seq; memcpy(&seq, p + 1, sizeof(seq));
        if (seq != e->next_seq[p[0]]++) e->bad_order++;
    }
    e->frames++; progress++;
}
static bool status_cb(void *ctx, uint8_t ci[32], uint64_t *h) {
    ep_t *e = ctx; if (!e->chain_known) return false;
    memcpy(ci, chain, 32); *h = 1; return true;
}

typedef struct {
    const nodus_identity_t *id;
    uint32_t proto;
    bool initiator_only;
    const uint8_t *chain;   /* NULL = use status callback */
} ep_cfg_t;

static void ep_init(ep_t *e, const ep_cfg_t *c) {
    memset(e, 0, sizeof(*e));
    CHECK(nodus_tcp_init(&e->tcp, -1) == 0);
    e->tcp.on_accept = on_accept; e->tcp.on_connect = on_connect;
    e->tcp.on_disconnect = on_disconnect; e->tcp.on_frame = on_frame;
    e->tcp.cb_ctx = e;
    nodus_inter_session_config_t cfg = {
        .identity = c->id, .proto_ver = c->proto, .initiator_only = c->initiator_only,
        .chain_id = c->chain, .inbound_depth = 8, .outbound_depth = 8, .workers = 0,
        .on_authenticated = on_authed, .auth_ctx = e
    };
    if (!c->chain) { cfg.status = status_cb; cfg.admission_ctx = e; e->chain_known = true; }
    e->mod = nodus_inter_session_new(&e->tcp, &cfg);
    CHECK(e->mod != NULL);
}
static void ep_free(ep_t *e) { nodus_tcp_close(&e->tcp); nodus_inter_session_free(e->mod); }

static void run_jobs(ep_t *e) {
    nodus_inter_session_job_t *j;
    while ((j = nodus_inter_session_job_take(e->mod)) != NULL) {
        CHECK(j->work.kind > CMT_P2P_SC_JOB_NONE && j->work.kind <= CMT_P2P_SC_JOB_VERIFY);
        e->jobs[j->work.kind]++; progress++;
        nodus_inter_session_job_run(j);
        CHECK(nodus_inter_session_job_done(e->mod, j) == CMT_OK);
    }
}
static void step(ep_t *a, ep_t *b) {
    CHECK(nodus_tcp_poll(&a->tcp, POLL_MS) >= 0); CHECK(nodus_tcp_poll(&b->tcp, POLL_MS) >= 0);
    run_jobs(a); run_jobs(b);
}
/* Server (responder, listening) + client (initiator-only, no ML-KEM). */
static void pair(ep_t *cli, ep_t *srv, const nodus_identity_t *cli_id, const nodus_identity_t *srv_id,
                 uint32_t cli_proto, const uint8_t *cli_chain,
                 const nodus_key_t *list, size_t count) {
    ep_cfg_t sc = {.id = srv_id, .proto = CMT_P2P_SC_PROTO_VER_4001, .chain = chain};
    ep_cfg_t cc = {.id = cli_id, .proto = cli_proto, .initiator_only = true, .chain = cli_chain};
    ep_init(srv, &sc); ep_init(cli, &cc);
    CHECK(nodus_tcp_listen(&srv->tcp, "127.0.0.1", 0) == 0);
    cli->conn = nodus_tcp_connect_trusted(&cli->tcp, "127.0.0.1", srv->tcp.port, list, count);
    CHECK(cli->conn != NULL);
}

static nodus_identity_t client_identity;   /* ids[0] without any ML-KEM key */

static void send_frame(nodus_tcp_conn_t *c, uint8_t tid, uint32_t seq) {
    uint8_t p[40]; memset(p, 0x5a, sizeof(p)); p[0] = tid; memcpy(p + 1, &seq, sizeof(seq));
    CHECK(nodus_tcp_send(c, p, sizeof(p)) == 0);
}

/* 1: trusted list, any position, no client ML-KEM key. */
static void trusted_list(void) {
    nodus_key_t list[3] = {ids[2].node_id, ids[0].node_id, ids[1].node_id};  /* real node last */
    ep_t cli, srv;
    pair(&cli, &srv, &client_identity, &ids[1], CMT_P2P_SC_PROTO_VER_4001, chain, list, 3);
    WAIT_WHILE(!cli.authenticated || !srv.authenticated) step(&cli, &srv);
    CHECK(cli.authenticated == 1 && srv.authenticated == 1);
    CHECK(memcmp(srv.conn->peer_pk.bytes, client_identity.pk.bytes, NODUS_PK_BYTES) == 0);
    send_frame(cli.conn, 0, 0);
    WAIT_WHILE(!srv.frames) step(&cli, &srv);
    CHECK(srv.frames == 1);
    ep_free(&cli); ep_free(&srv);
}

/* 1b: the responder is not listed -> abort before encapsulation and signing. */
static void not_listed(void) {
    nodus_key_t list[2] = {ids[2].node_id, ids[0].node_id};
    ep_t cli, srv;
    pair(&cli, &srv, &client_identity, &ids[1], CMT_P2P_SC_PROTO_VER_4001, chain, list, 2);
    WAIT_WHILE(!cli.closed || !srv.closed) step(&cli, &srv);
    CHECK(cli.closed == 1 && srv.closed == 1);
    CHECK(cli.authenticated == 0 && srv.authenticated == 0);
    CHECK(cli.jobs[CMT_P2P_SC_JOB_ENCAPS] == 0 && cli.jobs[CMT_P2P_SC_JOB_SIGN] == 0);
    CHECK(srv.frames == 0);
    ep_free(&cli); ep_free(&srv);
}

/* 2: no list, no socket. */
static void empty_list(void) {
    ep_t cli;
    ep_cfg_t cc = {.id = &client_identity, .proto = CMT_P2P_SC_PROTO_VER_4001,
                   .initiator_only = true, .chain = chain};
    ep_init(&cli, &cc);
    nodus_key_t one = ids[1].node_id;
    CHECK(nodus_tcp_connect_trusted(&cli.tcp, "127.0.0.1", 9, NULL, 0) == NULL);
    CHECK(nodus_tcp_connect_trusted(&cli.tcp, "127.0.0.1", 9, &one, 0) == NULL);
    CHECK(nodus_tcp_connect_trusted(&cli.tcp, "127.0.0.1", 9, NULL, 1) == NULL);
    CHECK(nodus_tcp_connect_pinned(&cli.tcp, "127.0.0.1", 9, NULL) == NULL);
    CHECK(nodus_tcp_connect(&cli.tcp, "127.0.0.1", 9) == NULL);
    CHECK(cli.tcp.count == 0 && cli.connects == 0);
    ep_free(&cli);
}

/* 3: literal HELLO proto_ver bytes of a 4001 initiator, nothing after it. */
static void wire_hello(void) {
    ep_t cli; ep_cfg_t cc = {.id = &client_identity, .proto = CMT_P2P_SC_PROTO_VER_4001,
                             .initiator_only = true, .chain = chain};
    ep_init(&cli, &cc);
    int lf = socket(AF_INET, SOCK_STREAM, 0); CHECK(lf >= 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(lf, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(lf, 1) == 0);
    socklen_t sl = sizeof(sa); CHECK(getsockname(lf, (struct sockaddr *)&sa, &sl) == 0);
    nodus_key_t list[1] = {ids[1].node_id};
    cli.conn = nodus_tcp_connect_trusted(&cli.tcp, "127.0.0.1", ntohs(sa.sin_port), list, 1);
    CHECK(cli.conn);
    int fd = accept(lf, NULL, NULL); CHECK(fd >= 0); close(lf);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    uint8_t buf[CMT_P2P_SC_OUT_CAP * 2]; size_t got = 0;
    size_t want = 0, pfx = 0;   /* uvarint prefix + HELLO body, known once the prefix is in */
    WAIT_WHILE(!want || got < want) {
        CHECK(nodus_tcp_poll(&cli.tcp, POLL_MS) >= 0);
        ssize_t r = recv(fd, buf + got, sizeof(buf) - got, 0);
        if (r > 0) { got += (size_t)r; progress++; }
        else CHECK(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
        for (size_t i = 0; !want && i < got && i < CMT_P2P_SC_UVARINT_MAX; ++i) {
            if (!(buf[i] & 0x80)) {
                size_t body = 0;
                for (size_t k = 0; k <= i; ++k) body |= (size_t)(buf[k] & 0x7f) << (7 * k);
                pfx = i + 1; want = pfx + body;
            }
        }
    }
    CHECK(want == pfx + CMT_P2P_SC_HELLO_BODY);
    CHECK(buf[pfx] == 0x01);
    const uint8_t version[] = {0x0f, 0xa1, 0x00, 0x01};
    CHECK(memcmp(buf + pfx + 1 + CMT_P2P_SC_DSA_PK_SIZE + CMT_P2P_SC_NONCE_SIZE, version, 4) == 0);
    /* nothing more is written until the peer answers */
    for (int i = 0; i < 50; ++i) {
        CHECK(nodus_tcp_poll(&cli.tcp, POLL_MS) >= 0);
        uint8_t extra[8]; ssize_t r = recv(fd, extra, sizeof(extra), 0);
        CHECK(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    }
    CHECK(got == want);
    close(fd); ep_free(&cli);
}

/* 4: 4002 client vs 4001 responder, and a chain id one byte off. */
static void mismatches(void) {
    nodus_key_t list[1] = {ids[1].node_id};
    for (int variant = 0; variant < 2; ++variant) {
        uint8_t other[CMT_P2P_SC_CHAIN_ID_SIZE]; memcpy(other, chain, sizeof(other)); other[31] ^= 1;
        ep_t cli, srv;
        pair(&cli, &srv, &client_identity, &ids[1],
             variant ? CMT_P2P_SC_PROTO_VER_4001 : CMT_P2P_SC_PROTO_VER_4002,
             variant ? other : chain, list, 1);
        WAIT_WHILE(!cli.closed || !srv.closed) step(&cli, &srv);
        CHECK(cli.closed == 1 && srv.closed == 1);
        CHECK(cli.authenticated == 0 && srv.authenticated == 0 && srv.frames == 0);
        for (int k = CMT_P2P_SC_JOB_NONE + 1; k <= CMT_P2P_SC_JOB_VERIFY; ++k)
            CHECK(cli.jobs[k] == 0 && srv.jobs[k] == 0);
        ep_free(&cli); ep_free(&srv);
    }
}

/* 5: a dialer holding the responder's own key. */
static void reject_self(void) {
    nodus_key_t list[1] = {ids[1].node_id};
    ep_t cli, srv;
    pair(&cli, &srv, &ids[1], &ids[1], CMT_P2P_SC_PROTO_VER_4001, chain, list, 1);
    WAIT_WHILE(!cli.closed || !srv.closed) step(&cli, &srv);
    CHECK(cli.closed == 1 && srv.closed == 1);
    CHECK(srv.frames == 0 && cli.frames == 0);
    ep_free(&cli); ep_free(&srv);
}

/* 6: an initiator-only module takes no inbound connection. */
static void initiator_only_refuses_inbound(void) {
    ep_t e; ep_cfg_t c = {.id = &client_identity, .proto = CMT_P2P_SC_PROTO_VER_4001,
                          .initiator_only = true, .chain = chain};
    ep_init(&e, &c);
    CHECK(nodus_tcp_listen(&e.tcp, "127.0.0.1", 0) == 0);
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(e.tcp.port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    bool eof = false;
    WAIT_WHILE(!eof) {
        CHECK(nodus_tcp_poll(&e.tcp, POLL_MS) >= 0);
        uint8_t b[16]; ssize_t r = recv(fd, b, sizeof(b), 0);
        CHECK(r <= 0);   /* zero bytes may ever be written */
        if (r == 0 || (r < 0 && errno == ECONNRESET)) { eof = true; progress++; }
    }
    CHECK(eof && e.accepts == 0 && e.tcp.count == 0);
    close(fd); ep_free(&e);
}

/* 7: chain unknown -> closed at accept, nothing written; open stays open. */
static void chain_unknown(void) {
    nodus_key_t list[1] = {ids[1].node_id};
    ep_t cli, srv;
    ep_cfg_t sc = {.id = &ids[1], .proto = CMT_P2P_SC_PROTO_VER_4001};   /* status callback */
    ep_cfg_t cc = {.id = &client_identity, .proto = CMT_P2P_SC_PROTO_VER_4001,
                   .initiator_only = true, .chain = chain};
    ep_init(&srv, &sc); ep_init(&cli, &cc);
    CHECK(nodus_tcp_listen(&srv.tcp, "127.0.0.1", 0) == 0);
    cli.conn = nodus_tcp_connect_trusted(&cli.tcp, "127.0.0.1", srv.tcp.port, list, 1);
    CHECK(cli.conn);
    WAIT_WHILE(!cli.authenticated || !srv.authenticated) step(&cli, &srv);
    CHECK(cli.authenticated == 1 && srv.authenticated == 1);
    srv.chain_known = false;
    /* a new connection: refused at accept, no byte written to it */
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(srv.tcp.port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    bool eof = false;
    WAIT_WHILE(!eof) {
        step(&cli, &srv);
        uint8_t b[16]; ssize_t r = recv(fd, b, sizeof(b), 0);
        CHECK(r <= 0);
        if (r == 0 || (r < 0 && errno == ECONNRESET)) { eof = true; progress++; }
    }
    CHECK(eof);
    send_frame(cli.conn, 0, 0);   /* the open session still carries traffic */
    WAIT_WHILE(!srv.frames) step(&cli, &srv);
    CHECK(srv.frames == 1 && srv.closed == 0);
    close(fd); ep_free(&cli); ep_free(&srv);
}

/* 8: write lock installed: any thread queues, the owner alone seals. */
static pthread_mutex_t wlock = PTHREAD_MUTEX_INITIALIZER;
static void lock_fn(void *ctx, bool lock) {
    (void)ctx; if (lock) pthread_mutex_lock(&wlock); else pthread_mutex_unlock(&wlock);
}
typedef struct { nodus_tcp_conn_t *conn; uint8_t tid; unsigned n; } sender_t;
static void *sender_fn(void *arg) {
    sender_t *s = arg;
    for (unsigned i = 0; i < s->n; ++i) {
        uint8_t p[40]; memset(p, 0x77, sizeof(p)); p[0] = s->tid; memcpy(p + 1, &i, sizeof(i));
        if (nodus_tcp_send(s->conn, p, sizeof(p)) != 0) return (void *)1;
    }
    return NULL;
}
static void write_lock_owner(void) {
    nodus_key_t list[1] = {ids[1].node_id};
    ep_t cli, srv;
    ep_cfg_t sc = {.id = &ids[1], .proto = CMT_P2P_SC_PROTO_VER_4001, .chain = chain};
    ep_cfg_t cc = {.id = &client_identity, .proto = CMT_P2P_SC_PROTO_VER_4001,
                   .initiator_only = true, .chain = chain};
    ep_init(&srv, &sc);
    memset(&cli, 0, sizeof(cli));
    CHECK(nodus_tcp_init(&cli.tcp, -1) == 0);
    nodus_tcp_set_write_lock(&cli.tcp, lock_fn, NULL);   /* lock BEFORE the module */
    cli.tcp.on_connect = on_connect; cli.tcp.on_disconnect = on_disconnect;
    cli.tcp.on_frame = on_frame; cli.tcp.cb_ctx = &cli;
    nodus_inter_session_config_t cfg = {
        .identity = cc.id, .proto_ver = cc.proto, .initiator_only = true, .chain_id = chain,
        .inbound_depth = 8, .outbound_depth = 8, .workers = 0,
        .on_authenticated = on_authed, .auth_ctx = &cli
    };
    cli.mod = nodus_inter_session_new(&cli.tcp, &cfg);
    CHECK(cli.mod != NULL);
    CHECK(nodus_tcp_listen(&srv.tcp, "127.0.0.1", 0) == 0);
    cli.conn = nodus_tcp_connect_trusted(&cli.tcp, "127.0.0.1", srv.tcp.port, list, 1);
    CHECK(cli.conn);
    WAIT_WHILE(!cli.authenticated || !srv.authenticated) step(&cli, &srv);
    CHECK(cli.authenticated == 1 && srv.authenticated == 1);
    enum { PER_THREAD = 60 };
    sender_t s[2] = {{cli.conn, 0, PER_THREAD}, {cli.conn, 1, PER_THREAD}};
    pthread_t th[2];
    for (int i = 0; i < 2; ++i) CHECK(pthread_create(&th[i], NULL, sender_fn, &s[i]) == 0);
    WAIT_WHILE(srv.frames < 2 * PER_THREAD) step(&cli, &srv);
    for (int i = 0; i < 2; ++i) { void *rc; CHECK(pthread_join(th[i], &rc) == 0 && rc == NULL); }
    CHECK(srv.frames == 2 * PER_THREAD && srv.bad_order == 0);
    CHECK(srv.closed == 0 && cli.closed == 0);
    CHECK(nodus_tcp_decrypt_fail_total(&srv.tcp) == 0);
    ep_free(&cli); ep_free(&srv);
}

/* ══ Part B: a real nodus_server_t, driven by a raw-machine client ═════
 * (plan 4.1, "driven by a raw-machine client first"). The server's own
 * transport is polled from this thread. Its chain id is set directly on the
 * server (the fields core's refresh fills), so no witness is needed. */
#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include <sys/stat.h>

static nodus_server_t g_srv;   /* static: far too large for the stack */
static void srv_pump(void) { CHECK(nodus_tcp_poll(&g_srv.tcp, POLL_MS) >= 0); }

typedef struct {
    int fd;
    cmt_p2p_sc_t sc;
    cmt_p2p_sc_host_t host;
    const nodus_identity_t *id;
    uint8_t in[1 << 15]; size_t in_len;
    size_t bytes_after_auth;      /* socket bytes received once authenticated */
    bool eof;
} raw_t;

static int raw_sign(void *ctx, const uint8_t *p, size_t n, uint8_t *out) {
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, p, n, &((nodus_identity_t *)ctx)->sk);
    if (rc == 0) memcpy(out, sig.bytes, sizeof(sig.bytes));
    return rc;
}
static int raw_verify(void *ctx, const uint8_t *s, const uint8_t *p, size_t n, const uint8_t *k) {
    (void)ctx;
    nodus_sig_t sig; nodus_pubkey_t pk;
    memcpy(sig.bytes, s, sizeof(sig.bytes)); memcpy(pk.bytes, k, sizeof(pk.bytes));
    return nodus_verify_session_auth(&sig, p, n, &pk);
}
static void raw_out(raw_t *r) {
    size_t n; const uint8_t *p = cmt_p2p_sc_out(&r->sc, &n);
    if (!n) return;
    size_t off = 0;
    WAIT_WHILE(off < n) {
        ssize_t w = send(r->fd, p + off, n - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; progress++; }
        else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { r->eof = true; break; }
        else srv_pump();
    }
    cmt_p2p_sc_out_consume(&r->sc, n);
}
static void raw_in(raw_t *r) {
    for (;;) {
        CHECK(r->in_len < sizeof(r->in));
        ssize_t n = recv(r->fd, r->in + r->in_len, sizeof(r->in) - r->in_len, 0);
        if (n > 0) {
            r->in_len += (size_t)n; progress++;
            if (cmt_p2p_sc_is_authenticated(&r->sc)) r->bytes_after_auth += (size_t)n;
            continue;
        }
        if (n == 0 || errno == ECONNRESET) { if (!r->eof) progress++; r->eof = true; }
        else CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
        return;
    }
}
static void raw_consume(raw_t *r, size_t used) {
    CHECK(used <= r->in_len); r->in_len -= used; memmove(r->in, r->in + used, r->in_len);
    if (used) progress++;
}
static void raw_jobs(raw_t *r) {
    const cmt_p2p_sc_job_t *j;
    while ((j = cmt_p2p_sc_job(&r->sc)) != NULL) {
        if (cmt_p2p_sc_job_done(&r->sc, cmt_p2p_sc_job_run(j, &r->host)) != CMT_OK) return;
        progress++;
    }
}
static void raw_open(raw_t *r, const nodus_identity_t *id, uint32_t version, const uint8_t *cid) {
    memset(r, 0, sizeof(*r)); r->id = id;
    r->fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(r->fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(g_srv.tcp.port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
    CHECK(connect(r->fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(fcntl(r->fd, F_SETFL, O_NONBLOCK) == 0);
    r->host.ctx = (void *)id; r->host.sign = raw_sign; r->host.verify = raw_verify;
    CHECK(cmt_p2p_sc_init(&r->sc, CMT_P2P_SC_ROLE_INITIATOR, &r->host, id->pk.bytes,
                          NULL, NULL, version, cid) == CMT_OK);
}
static void raw_close(raw_t *r) { close(r->fd); cmt_p2p_sc_clear(&r->sc); }
/* One round: node loop, client machine. */
static void raw_step(raw_t *r) {
    raw_out(r); srv_pump(); raw_in(r);
    if (!cmt_p2p_sc_is_authenticated(&r->sc) && !r->eof) {
        size_t used = 0;
        if (r->in_len && cmt_p2p_sc_recv(&r->sc, r->in, r->in_len, &used) != CMT_OK) r->eof = true;
        raw_consume(r, used); raw_jobs(r);
    }
}
static void raw_auth(raw_t *r) {
    WAIT_WHILE(!cmt_p2p_sc_is_authenticated(&r->sc) && !r->eof) raw_step(r);
    CHECK(cmt_p2p_sc_is_authenticated(&r->sc) && !r->eof);
    raw_out(r);   /* nothing left; the node opens on its side after verifying */
}
static void raw_until_eof(raw_t *r) {
    WAIT_WHILE(!r->eof) raw_step(r);
    CHECK(r->eof);
}
static bool srv_has_session_of(const nodus_identity_t *id) {
    for (int i = 0; i < NODUS_MAX_SESSIONS; ++i)
        if (g_srv.sessions[i].authenticated && g_srv.sessions[i].conn &&
            nodus_key_cmp(&g_srv.sessions[i].client_fp, &id->node_id) == 0) return true;
    return false;
}
/* Send one request on the sealed stream, read one sealed reply. */
static void raw_request(raw_t *r, const uint8_t *payload, size_t n, nodus_tier2_msg_t *reply) {
    uint8_t plain[256], sealed[CMT_P2P_SC_SEALED_FRAME_SIZE * 2]; size_t written = 0;
    size_t pn = nodus_frame_encode(plain, sizeof(plain), payload, (uint32_t)n); CHECK(pn);
    CHECK(cmt_p2p_sc_write(&r->sc, plain, pn, sealed, sizeof(sealed), &written) == CMT_OK);
    CHECK(written > 0 && written % CMT_P2P_SC_SEALED_FRAME_SIZE == 0);
    size_t off = 0;
    WAIT_WHILE(off < written) {
        ssize_t w = send(r->fd, sealed + off, written - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; progress++; } else srv_pump();
    }
    uint8_t got[512]; size_t gl = 0;
    nodus_frame_t f; int used = 0;
    WAIT_WHILE(used <= 0) {
        srv_pump(); raw_in(r);
        size_t cu = 0, pl = 0;
        CHECK(cmt_p2p_sc_read(&r->sc, r->in, r->in_len, &cu, got + gl, sizeof(got) - gl, &pl) == CMT_OK);
        raw_consume(r, cu); gl += pl;
        used = nodus_frame_decode(got, gl, &f);
    }
    CHECK(used > 0);
    memset(reply, 0, sizeof(*reply));
    CHECK(nodus_t2_decode(f.payload, f.payload_len, reply) == 0);
}

/* N1: the 4001 handshake with a raw client; the node serves a request that
 * carries a zero token (A6); the client key is the session identity; every
 * byte the node writes after the handshake is whole sealed frames. */
static void node_session(void) {
    raw_t *r = calloc(1, sizeof(*r)); CHECK(r);
    raw_open(r, &ids[0], CMT_P2P_SC_PROTO_VER_4001, chain);
    raw_auth(r);
    WAIT_WHILE(!srv_has_session_of(&ids[0])) raw_step(r);
    CHECK(srv_has_session_of(&ids[0]));
    uint8_t buf[256], zero_token[NODUS_SESSION_TOKEN_LEN] = {0}; size_t n = 0;
    CHECK(nodus_t2_ping(7, zero_token, buf, sizeof(buf), &n) == 0);
    nodus_tier2_msg_t reply;
    r->bytes_after_auth = 0;
    raw_request(r, buf, n, &reply);
    CHECK(reply.type == 'r' && reply.txn_id == 7);
    CHECK(r->bytes_after_auth > 0 && r->bytes_after_auth % CMT_P2P_SC_SEALED_FRAME_SIZE == 0);
    nodus_t2_msg_free(&reply);
    CHECK(!r->eof);
    raw_close(r); free(r);
    for (int i = 0; i < 50; ++i) srv_pump();
}

/* N2: the old T2 handshake gets nothing: closed, zero bytes written. */
static void node_old_handshake(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(g_srv.tcp.port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    uint8_t p[8192], fr[8300]; size_t pn = 0;
    CHECK(nodus_t2_hello(1, &ids[0].pk, &ids[0].node_id, p, sizeof(p), &pn) == 0);
    size_t fn = nodus_frame_encode(fr, sizeof(fr), p, (uint32_t)pn); CHECK(fn);
    CHECK(send(fd, fr, fn, MSG_NOSIGNAL) == (ssize_t)fn);
    bool eof = false; size_t total = 0;
    WAIT_WHILE(!eof) {
        srv_pump();
        uint8_t b[64]; ssize_t r = recv(fd, b, sizeof(b), 0);
        if (r > 0) { total += (size_t)r; progress++; }
        else if (r == 0 || (r < 0 && errno == ECONNRESET)) { eof = true; progress++; }
    }
    CHECK(eof && total == 0);
    close(fd);
}

/* N3: reflection (the node's own key) and a different port-version. */
static void node_refusals(void) {
    raw_t *r = calloc(1, sizeof(*r)); CHECK(r);
    raw_open(r, &g_srv.identity, CMT_P2P_SC_PROTO_VER_4001, chain);
    raw_until_eof(r);
    CHECK(!srv_has_session_of(&g_srv.identity));
    raw_close(r);
    raw_open(r, &ids[0], CMT_P2P_SC_PROTO_VER_4002, chain);
    raw_until_eof(r);
    CHECK(!cmt_p2p_sc_is_authenticated(&r->sc));
    raw_close(r);
    uint8_t other[CMT_P2P_SC_CHAIN_ID_SIZE]; memcpy(other, chain, sizeof(other)); other[0] ^= 1;
    raw_open(r, &ids[0], CMT_P2P_SC_PROTO_VER_4001, other);
    raw_until_eof(r);
    CHECK(!cmt_p2p_sc_is_authenticated(&r->sc));
    raw_close(r); free(r);
}

/* N4: the fifth session of one identity evicts the oldest (limit 4). */
static void node_eviction(void) {
    raw_t *rs[NODUS_MAX_SESSIONS_PER_IDENTITY + 1];
    for (int i = 0; i <= NODUS_MAX_SESSIONS_PER_IDENTITY; ++i) {
        rs[i] = calloc(1, sizeof(raw_t)); CHECK(rs[i]);
        raw_open(rs[i], &ids[2], CMT_P2P_SC_PROTO_VER_4001, chain);
        raw_auth(rs[i]);
        /* let the node apply the identity before the next one starts */
        for (int k = 0; k < 20; ++k) { srv_pump(); raw_in(rs[i]); }
    }
    WAIT_WHILE(!rs[0]->eof) { srv_pump(); raw_in(rs[0]); }
    CHECK(rs[0]->eof);
    for (int i = 1; i <= NODUS_MAX_SESSIONS_PER_IDENTITY; ++i) {
        for (int k = 0; k < 20; ++k) { srv_pump(); raw_in(rs[i]); }
        CHECK(!rs[i]->eof);
    }
    for (int i = 0; i <= NODUS_MAX_SESSIONS_PER_IDENTITY; ++i) { raw_close(rs[i]); free(rs[i]); }
}

/* N5: no chain id -> a new connection is closed at accept, zero bytes. */
static void node_chain_unknown(void) {
    g_srv.inter_chain_id_valid = false;
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(g_srv.tcp.port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    bool eof = false; size_t total = 0;
    WAIT_WHILE(!eof) {
        srv_pump();
        uint8_t b[64]; ssize_t r = recv(fd, b, sizeof(b), 0);
        if (r > 0) { total += (size_t)r; progress++; }
        else if (r == 0 || (r < 0 && errno == ECONNRESET)) { eof = true; progress++; }
    }
    CHECK(eof && total == 0);
    close(fd);
    g_srv.inter_chain_id_valid = true;
}

/* ══ Part C: the real client library against the real server ════════
 * (build-order step 4: "the tests switch to the real client"). The node is
 * polled by a thread of this test while the client runs its own read thread. */
#include "nodus/nodus.h"

static volatile bool g_pump_stop;
static void *pump_thread(void *arg) {
    (void)arg;
    while (!g_pump_stop) nodus_tcp_poll(&g_srv.tcp, 5);
    return NULL;
}

static void client_config(nodus_client_config_t *cfg, const nodus_key_t *list, int count) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->servers[0].port = g_srv.tcp.port;
    snprintf(cfg->servers[0].ip, sizeof(cfg->servers[0].ip), "127.0.0.1");
    cfg->server_count = 1;
    cfg->connect_timeout_ms = 5000;
    cfg->request_timeout_ms = 5000;
    cfg->pinned_server_fps = list;
    cfg->pinned_server_fp_count = count;
    memcpy(cfg->chain_id, chain, sizeof(chain));
    cfg->has_chain_id = true;
}

static void real_client(void) {
    nodus_client_t *c = calloc(1, sizeof(*c)); CHECK(c);
    nodus_client_config_t cfg;
    nodus_key_t list[2] = {ids[2].node_id, g_srv.identity.node_id};   /* the node at position 2 */

    /* D4: no list / no chain id -> refused at init, before any socket. */
    client_config(&cfg, NULL, 0);
    CHECK(nodus_client_init(c, &cfg, &ids[0]) == -1);
    client_config(&cfg, list, 2); cfg.has_chain_id = false;
    CHECK(nodus_client_init(c, &cfg, &ids[0]) == -1);
    client_config(&cfg, list, 2); cfg.pinned_server_fp_count = -1;
    CHECK(nodus_client_init(c, &cfg, &ids[0]) == -1);

    /* The node is not in the list: the client aborts, never becomes ready. */
    nodus_key_t wrong[1] = {ids[2].node_id};
    client_config(&cfg, wrong, 1);
    memset(c, 0, sizeof(*c));
    CHECK(nodus_client_init(c, &cfg, &ids[0]) == 0);
    CHECK(nodus_client_connect(c) != 0 && !nodus_client_is_ready(c));
    nodus_client_close(c);

    /* Listed at any position: ready, a request is answered, generation set. */
    client_config(&cfg, list, 2);
    memset(c, 0, sizeof(*c));
    CHECK(nodus_client_init(c, &cfg, &ids[0]) == 0);
    CHECK(nodus_client_connect(c) == 0 && nodus_client_is_ready(c));
    uint64_t gen1 = nodus_client_conn_generation(c);
    CHECK(gen1 != 0);
    CHECK(c->has_server_dil_pk &&
          memcmp(c->server_dil_pk.bytes, g_srv.identity.pk.bytes, NODUS_PK_BYTES) == 0);
    nodus_server_endpoint_t eps[8]; int n = 0;
    CHECK(nodus_client_get_servers(c, eps, 8, &n) == 0);
    /* A new connection to the SAME server is a different generation. */
    nodus_client_force_disconnect(c);
    CHECK(nodus_client_connect(c) == 0 && nodus_client_is_ready(c));
    CHECK(nodus_client_conn_generation(c) > gen1);
    CHECK(nodus_client_get_servers(c, eps, 8, &n) == 0);
    nodus_client_close(c);
    free(c);
}

static void node_cases(void) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port = 15500; config.tcp_port = 15501; config.peer_port = 15502;
    config.ch_port = 15503; config.witness_port = 15504;
    config.require_peer_auth = true;
    snprintf(config.data_path, sizeof(config.data_path), "/tmp/nodus_client_session_%d", (int)getpid());
    CHECK(mkdir(config.data_path, 0700) == 0);
    CHECK(nodus_server_init(&g_srv, &config) == 0);
    memcpy(g_srv.inter_chain_id, chain, sizeof(chain));
    g_srv.inter_chain_known = g_srv.inter_chain_id_valid = true;
    node_session(); node_old_handshake(); node_refusals(); node_eviction(); node_chain_unknown();
    pthread_t pt;
    g_pump_stop = false;
    CHECK(pthread_create(&pt, NULL, pump_thread, NULL) == 0);
    real_client();
    g_pump_stop = true;
    CHECK(pthread_join(pt, NULL) == 0);
    nodus_server_close(&g_srv);
    char cmd[320];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", config.data_path);
    CHECK(system(cmd) == 0);
}

int main(void) {
    for (int i = 0; i < 3; ++i) CHECK(nodus_identity_generate(&ids[i]) == 0);
    client_identity = ids[0];
    memset(client_identity.mlkem_pk, 0, sizeof(client_identity.mlkem_pk));
    memset(client_identity.mlkem_sk, 0, sizeof(client_identity.mlkem_sk));
    client_identity.has_mlkem = false;
    trusted_list(); not_listed(); empty_list(); wire_hello(); mismatches();
    reject_self(); initiator_only_refuses_inbound(); chain_unknown(); write_lock_owner();
    node_cases();
    for (int i = 0; i < 3; ++i) nodus_identity_clear(&ids[i]);
    puts("test_client_session: all cases passed");
    return 0;
}
