/**
 * Session over the WebSocket entry (approved plan 2026-11-02-4001-ws-session-
 * build-plan, sections 2.1 f, 2.1 h and 4.1 "test_ws_session.c"), transport
 * level: a bare nodus_tcp_t with the session module and a WebSocket listener,
 * driven by a raw WebSocket client that runs the cmt_p2p_sc machine itself.
 *
 * What it proves (each assertion would be false if the behaviour were absent):
 *   1. After the HTTP Upgrade the machine runs inside binary WebSocket frames:
 *      the whole handshake works with the client's bytes split into 7-byte
 *      WebSocket frames, and an application frame sent sealed in a WebSocket
 *      frame is delivered to on_frame as the bare nodus frame (A11).
 *   2. Machine bytes written before the Upgrade completes open no session:
 *      the connection is closed and on_frame/on_authenticated never run.
 *   3. The 3 s deadline starts at Upgrade completion, not at TCP accept: a
 *      connection that waited 2.9 s (fake clock) before its Upgrade is not
 *      closed; once upgraded it closes at 3 s and not before.
 *   4. Capacity-aware feeding: the client's KEYX plus its whole sealed
 *      AUTHSIG (more than the 4,232-byte wire buffer) arrives in ONE
 *      WebSocket frame while the node's decapsulation job is held pending;
 *      the connection stays open with the surplus held (ws_pend_len > 0) and
 *      nothing is delivered; after the job is released the session
 *      authenticates and opens.
 *   5. A post-authentication request larger than the wire buffer, sealed and
 *      sent in one WebSocket frame, is delivered whole.
 *   6. Application data does not reach on_frame before authentication
 *      completes (frames stays 0 until the open callback).
 *
 * Added with the verifier's findings (plan 4.1 rows 9 and 10 and the
 * trailing case):
 *   7. Reflection through WebSocket frames: a client holding the node's own
 *      key gets no session and delivers nothing.
 *   8. A request packed with the client's AUTHSIG in one WebSocket frame is
 *      delivered after the node verified and opened, never before.
 *   9. The client's HELLO written in the same send as the Upgrade request
 *      (it trails the request head): the handshake completes. The 5,220-byte
 *      sealed AUTHSIG itself cannot trail the Upgrade request: it needs the
 *      node's HELLO_R and a KEM encapsulation first, so the held-job case
 *      (4) is the one that carries it; the trailing path is exercised with
 *      the only machine bytes that exist at that time.
 *
 * Plan 4.1 rows through WebSocket frames (added by the second verifier pass):
 *  10. (row 4) ws_wire: the node's first machine bytes carry 0F A1 00 01; every
 *      byte after the handshake is a whole number of 1044-byte sealed frames.
 *  11. (row 5) ws_other_version: a 4002 and a 4004 proto_ver client never
 *      authenticate, no handshake job runs.
 *  12. (row 7) ws_old_handshake: a T2 hello frame in a WebSocket frame gives no
 *      session and no dispatch.
 *  Rows 1 and 2 of the plan are about the CLIENT's trusted list. Row 1 here is
 *  every positive case above (a client with no ML-KEM key reaches the node
 *  through WebSocket frames). Row 2 (a client whose list lacks the node aborts
 *  at ENCAPS) is client logic with no effect the node can observe over the
 *  WebSocket; it runs on the module in test_client_session.c (not_listed), and
 *  the browser client is the wasm build (build-order step 6, tested through
 *  Caddy by web-wallet/test/browser-nodus-caddy.js).
 *
 * Not covered here (later steps of the same package): the node's own
 * 4001 request path, a real client, the 10 s Upgrade limit (covered by
 * test_ws_server), a request packed with the AUTHSIG (the raw initiator cannot
 * seal application data before it is itself authenticated).
 *
 * Compile flags: none; ASan/UBSan run by the orchestrator. Environment: none,
 * kernel-chosen loopback ports. Leaves nothing behind.
 * How it can falsely pass: jobs are taken and run by this test, so a node that
 * never completes the handshake FAILS the positive cases; the held-job case
 * asserts the pending job and held bytes explicitly, so an implementation that
 * silently dropped surplus bytes fails at authentication. Waits count rounds
 * without progress, never wall time.
 */
#include "server/nodus_inter_session.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_tier2.h"
#include "transport/nodus_ws.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

static nodus_identity_t ids[2];
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
    uint64_t now;
    bool hold;                       /* do not take jobs while set */
    unsigned accepts, authenticated, closed, frames, jobs;   /* jobs: handshake jobs the test took */
    size_t last_len;
} srv_t;

static uint64_t now_ms(void *ctx) { return ((srv_t *)ctx)->now; }
static void on_accept(nodus_tcp_conn_t *c, void *ctx) { srv_t *s = ctx; s->conn = c; s->accepts++; progress++; }
static void on_disconnect(nodus_tcp_conn_t *c, void *ctx) {
    srv_t *s = ctx; if (s->conn == c) s->conn = NULL; s->closed++; progress++;
}
static void on_authed(nodus_tcp_conn_t *c, const nodus_pubkey_t *pk, void *ctx) {
    srv_t *s = ctx; (void)pk;
    s->authenticated++; progress++;
    CHECK(nodus_inter_session_open(c) == 0);
}
static void on_frame(nodus_tcp_conn_t *c, const uint8_t *p, size_t n, void *ctx) {
    srv_t *s = ctx; (void)p;
    CHECK(nodus_inter_session_is_open(c) && s->authenticated == 1);
    s->frames++; s->last_len = n; progress++;
}

/* Plan 2.1 f: session mode is allowed on a transport that already has its
 * WebSocket listener, and the listener is allowed after the module. g_ws_first
 * selects the first order (the other is the one the node itself uses). */
static bool g_ws_first;

static void srv_init(srv_t *s) {
    memset(s, 0, sizeof(*s));
    s->now = 100;
    CHECK(nodus_tcp_init(&s->tcp, -1) == 0);
    s->tcp.on_accept = on_accept; s->tcp.on_disconnect = on_disconnect;
    s->tcp.on_frame = on_frame; s->tcp.cb_ctx = s;
    if (g_ws_first) CHECK(nodus_tcp_ws_listen(&s->tcp, 0) == 0 && s->tcp.ws_port != 0);
    nodus_inter_session_config_t cfg = {
        .identity = &ids[1], .proto_ver = CMT_P2P_SC_PROTO_VER_4001, .chain_id = chain,
        .inbound_depth = 8, .outbound_depth = 8, .workers = 0,
        .now_ms = now_ms, .now_ctx = s, .on_authenticated = on_authed, .auth_ctx = s
    };
    s->mod = nodus_inter_session_new(&s->tcp, &cfg);
    CHECK(s->mod != NULL);
    if (!g_ws_first) CHECK(nodus_tcp_ws_listen(&s->tcp, 0) == 0 && s->tcp.ws_port != 0);
}
static void srv_free(srv_t *s) { nodus_tcp_close(&s->tcp); nodus_inter_session_free(s->mod); }
static void srv_step(srv_t *s) {
    CHECK(nodus_tcp_poll(&s->tcp, POLL_MS) >= 0);
    nodus_inter_session_job_t *j;
    while (!s->hold && (j = nodus_inter_session_job_take(s->mod)) != NULL) {
        progress++; s->jobs++;
        nodus_inter_session_job_run(j);
        /* stale completion of a closed connection's job is CMT_REJECT by
         * design (nodus_inter_session.h); a live connection's must be OK */
        const int slot = j->work.slot;
        const uint64_t gen = j->work.gen;
        const nodus_tcp_conn_t *cn = slot >= 0 && slot < NODUS_TCP_MAX_CONNS ? s->tcp.pool[slot] : NULL;
        const bool alive = cn && cn->generation == gen && cn->session;
        CHECK(nodus_inter_session_job_done(s->mod, j) == (alive ? CMT_OK : CMT_REJECT));
    }
}

/* ── raw WebSocket client carrying the raw machine ─────────────────── */
typedef struct {
    int fd;
    cmt_p2p_sc_t sc;
    cmt_p2p_sc_host_t host;
    uint8_t rx[1 << 17]; size_t rx_len;      /* socket bytes */
    uint8_t in[1 << 17]; size_t in_len;      /* unframed machine bytes */
    bool eof;
    bool hello_sent;                         /* the HELLO already left (trailing mode) */
} cli_t;

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
static void cli_send(cli_t *c, const uint8_t *p, size_t n) {
    size_t off = 0;
    WAIT_WHILE(off < n) {
        struct pollfd pf = {.fd = c->fd, .events = POLLOUT};
        CHECK(poll(&pf, 1, POLL_MS) >= 0);
        ssize_t w = send(c->fd, p + off, n - off, MSG_NOSIGNAL);
        if (w > 0) { off += (size_t)w; progress++; }
        else CHECK(w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
    }
    CHECK(off == n);
}
/* One masked client binary WebSocket frame (RFC 6455 5.2/5.3). */
static void cli_ws_frame(cli_t *c, const uint8_t *p, size_t n) {
    static const uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t *f = malloc(n + 16); CHECK(f != NULL);
    size_t o = 0;
    f[o++] = 0x82;
    if (n < 126) f[o++] = (uint8_t)(0x80 | n);
    else if (n < 65536) { f[o++] = 0x80 | 126; f[o++] = (uint8_t)(n >> 8); f[o++] = (uint8_t)n; }
    else { f[o++] = 0x80 | 127; for (int i = 7; i >= 0; --i) f[o++] = (uint8_t)((uint64_t)n >> (8 * i)); }
    memcpy(f + o, key, 4); o += 4;
    for (size_t i = 0; i < n; ++i) f[o + i] = p[i] ^ key[i & 3];
    cli_send(c, f, o + n);
    free(f);
}
static void cli_ws_chunks(cli_t *c, const uint8_t *p, size_t n, size_t chunk) {
    for (size_t off = 0; off < n; off += chunk)
        cli_ws_frame(c, p + off, n - off < chunk ? n - off : chunk);
}
/* Read socket bytes and move complete server binary frames into `in`. */
static void cli_pump(cli_t *c) {
    for (;;) {
        CHECK(c->rx_len < sizeof(c->rx));
        ssize_t r = recv(c->fd, c->rx + c->rx_len, sizeof(c->rx) - c->rx_len, 0);
        if (r > 0) { c->rx_len += (size_t)r; progress++; continue; }
        if (r == 0 || (r < 0 && errno == ECONNRESET)) { if (!c->eof) progress++; c->eof = true; break; }
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
        break;
    }
    size_t off = 0;
    while (c->rx_len - off >= 2) {
        const uint8_t *b = c->rx + off;
        CHECK(!(b[1] & 0x80));                    /* server frames are never masked */
        uint64_t len = b[1] & 0x7f; size_t h = 2;
        if (len == 126) { if (c->rx_len - off < 4) break; len = ((uint64_t)b[2] << 8) | b[3]; h = 4; }
        else if (len == 127) {
            if (c->rx_len - off < 10) break;
            len = 0; for (int i = 0; i < 8; ++i) len = (len << 8) | b[2 + i]; h = 10;
        }
        if (c->rx_len - off < h + len) break;
        CHECK((b[0] & 0x0f) == 0x02);             /* only binary frames after the 101 */
        CHECK(c->in_len + len <= sizeof(c->in));
        memcpy(c->in + c->in_len, b + h, len); c->in_len += len;
        off += h + (size_t)len; progress++;
    }
    if (off) { c->rx_len -= off; memmove(c->rx, c->rx + off, c->rx_len); }
}
static void cli_jobs(cli_t *c) {
    const cmt_p2p_sc_job_t *j;
    while ((j = cmt_p2p_sc_job(&c->sc)) != NULL) {
        CHECK(cmt_p2p_sc_job_done(&c->sc, cmt_p2p_sc_job_run(j, &c->host)) == CMT_OK);
        progress++;
    }
}
static size_t cli_take_out(cli_t *c, uint8_t *dst) {
    size_t n; const uint8_t *p = cmt_p2p_sc_out(&c->sc, &n);
    if (n) { memcpy(dst, p, n); cmt_p2p_sc_out_consume(&c->sc, n); }
    return n;
}
static void cli_recv_hs(cli_t *c) {
    if (cmt_p2p_sc_is_authenticated(&c->sc) || !c->in_len) return;
    size_t used = 0;
    CHECK(cmt_p2p_sc_recv(&c->sc, c->in, c->in_len, &used) == CMT_OK);
    if (used) { c->in_len -= used; memmove(c->in, c->in + used, c->in_len); progress++; }
}

static int tcp_connect_ws(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
    CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    return fd;
}
static int g_cli_id = 0;    /* which identity the raw client holds (1 = the node's own key) */
static uint32_t g_cli_proto = CMT_P2P_SC_PROTO_VER_4001;   /* the client's proto_ver */
static void cli_init(cli_t *c, int fd) {
    memset(c, 0, sizeof(*c)); c->fd = fd;
    c->host.ctx = &ids[g_cli_id]; c->host.sign = raw_sign; c->host.verify = raw_verify;
    CHECK(cmt_p2p_sc_init(&c->sc, CMT_P2P_SC_ROLE_INITIATOR, &c->host, ids[g_cli_id].pk.bytes,
                          NULL, NULL, g_cli_proto, chain) == CMT_OK);
}
static void cli_free(cli_t *c) { close(c->fd); cmt_p2p_sc_clear(&c->sc); }

#define KEY_RFC "dGhlIHNhbXBsZSBub25jZQ=="
/* The HTTP Upgrade. `trailing`: the client's HELLO, as one masked binary
 * WebSocket frame, is written in the SAME send as the request, so it trails
 * the request head in the node's first read (plan 2.1 f: bytes trailing the
 * Upgrade request are machine input). Anything the node sends after the 101 in
 * the same recv is handed to the frame reader. */
static void cli_upgrade_ex(cli_t *c, srv_t *s, bool trailing) {
    uint8_t req[1024];
    int w = snprintf((char *)req, sizeof(req),
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: " KEY_RFC "\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\nX-Forwarded-For: 198.51.100.7\r\n\r\n");
    CHECK(w > 0 && (size_t)w < sizeof(req) - 200);
    size_t total = (size_t)w;
    if (trailing) {
        uint8_t hello[CMT_P2P_SC_OUT_CAP]; size_t hn = cli_take_out(c, hello);
        CHECK(hn > 0 && hn < 126 + 8000);
        static const uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
        static uint8_t big[CMT_P2P_SC_OUT_CAP + 1100];
        memcpy(big, req, total);
        size_t o = total;
        big[o++] = 0x82;
        if (hn < 126) big[o++] = (uint8_t)(0x80 | hn);
        else { big[o++] = 0x80 | 126; big[o++] = (uint8_t)(hn >> 8); big[o++] = (uint8_t)hn; }
        memcpy(big + o, key, 4); o += 4;
        for (size_t i = 0; i < hn; ++i) big[o + i] = hello[i] ^ key[i & 3];
        cli_send(c, big, o + hn);
        c->hello_sent = true;
    } else cli_send(c, req, total);
    uint8_t head[1024]; size_t hl = 0; bool done = false; size_t head_end = 0;
    WAIT_WHILE(!done) {
        srv_step(s);
        ssize_t r = recv(c->fd, head + hl, sizeof(head) - hl, 0);
        if (r > 0) { hl += (size_t)r; progress++; }
        else CHECK(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
        for (size_t i = 0; !done && i + 4 <= hl; ++i)
            if (!memcmp(head + i, "\r\n\r\n", 4)) { done = true; head_end = i + 4; }
    }
    CHECK(done && !memcmp(head, "HTTP/1.1 101", 12));
    if (hl > head_end) {                       /* frames that followed the 101 */
        CHECK(c->rx_len + (hl - head_end) <= sizeof(c->rx));
        memcpy(c->rx + c->rx_len, head + head_end, hl - head_end);
        c->rx_len += hl - head_end;
    }
}
static void cli_upgrade(cli_t *c, srv_t *s) { cli_upgrade_ex(c, s, false); }

/* Handshake from the client side after the HELLO was sent: runs until both
 * machines are authenticated. `single` = send the KEYX+AUTHSIG output in one
 * WebSocket frame while the node's job is held (case 4), else 7-byte frames. */
static void drive_handshake(cli_t *c, srv_t *s, bool single) {
    static uint8_t out[1 << 15];
    size_t n = 0;
    if (!c->hello_sent) {                          /* HELLO (not already sent trailing the Upgrade) */
        n = cli_take_out(c, out);
        CHECK(n > 0);
        if (single) cli_ws_frame(c, out, n); else cli_ws_chunks(c, out, n, 7);
    }
    bool sent_rest = false;
    WAIT_WHILE(!cmt_p2p_sc_is_authenticated(&c->sc) || !s->authenticated) {
        srv_step(s); cli_pump(c); cli_recv_hs(c);
        if (!sent_rest) {
            if (!cmt_p2p_sc_job(&c->sc)) continue;   /* node's HELLO_R not in yet */
            /* ENCAPS and SIGN run; the output is KEYX plus the sealed AUTHSIG */
            cli_jobs(c);
            n = cli_take_out(c, out);
            CHECK(n > CMT_P2P_SC_HS_MSG_MAX);        /* more than the node's wire buffer */
            sent_rest = true;
            if (single) {
                s->hold = true;                      /* the node's DECAPS stays pending */
                cli_ws_frame(c, out, n);
                /* surplus is held, the job is pending, nothing is delivered */
                WAIT_WHILE(nodus_inter_session_job_queued(s->mod, false) == 0) srv_step(s);
                for (int i = 0; i < 100; ++i) srv_step(s);
                CHECK(s->conn && s->conn->ws_pend_len > 0);
                CHECK(s->authenticated == 0 && s->frames == 0 && s->closed == 0);
                s->hold = false;
            } else cli_ws_chunks(c, out, n, 7);
        } else {
            cli_jobs(c);
            n = cli_take_out(c, out);
            if (n) cli_ws_chunks(c, out, n, 7);
        }
    }
    CHECK(cmt_p2p_sc_is_authenticated(&c->sc) && s->authenticated == 1);
}

static void send_app(cli_t *c, srv_t *s, size_t payload_len, size_t ws_chunk) {
    uint8_t *payload = malloc(payload_len), *plain = malloc(payload_len + 64);
    CHECK(payload && plain);
    memset(payload, 0xa5, payload_len);
    size_t plain_len = nodus_frame_encode(plain, payload_len + 64, payload, (uint32_t)payload_len);
    CHECK(plain_len == payload_len + NODUS_FRAME_HEADER_SIZE);
    size_t cap = ((plain_len + CMT_P2P_SC_DATA_MAX_SIZE - 1) / CMT_P2P_SC_DATA_MAX_SIZE) *
                 CMT_P2P_SC_SEALED_FRAME_SIZE;
    uint8_t *sealed = malloc(cap); CHECK(sealed);
    size_t written = 0;
    CHECK(cmt_p2p_sc_write(&c->sc, plain, plain_len, sealed, cap, &written) == CMT_OK && written == cap);
    unsigned before = s->frames;
    cli_ws_chunks(c, sealed, written, ws_chunk);
    WAIT_WHILE(s->frames == before) { srv_step(s); cli_pump(c); }
    CHECK(s->frames == before + 1 && s->last_len == payload_len);
    free(payload); free(plain); free(sealed);
}

/* 1/4/5/6 */
static void ws_session(bool single, bool trailing) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    int fd = tcp_connect_ws(s.tcp.ws_port);
    cli_init(c, fd);
    cli_upgrade_ex(c, &s, trailing);
    drive_handshake(c, &s, single);
    CHECK(s.frames == 0);                       /* nothing delivered before open */
    /* a small request, then one larger than the node's wire buffer */
    send_app(c, &s, 31, single ? 1 << 20 : 7);
    send_app(c, &s, 20000, 1 << 20);
    CHECK(s.closed == 0);
    cli_free(c); free(c); srv_free(&s);
}

/* Row 10 through WebSocket frames: a client holding the node's own key never
 * gets a session (reject-self), nothing is delivered. */
static void ws_reflection(void) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    g_cli_id = 1;                               /* ids[1] is the node's key */
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    cli_upgrade(c, &s);
    static uint8_t out[1 << 15];
    size_t n = cli_take_out(c, out); CHECK(n > 0);
    cli_ws_chunks(c, out, n, 7);
    bool sent_rest = false;
    WAIT_WHILE(!s.closed) {
        srv_step(&s); cli_pump(c);
        if (c->eof) break;
        cli_recv_hs(c); cli_jobs(c);
        n = cli_take_out(c, out);
        if (n) { cli_ws_chunks(c, out, n, 7); sent_rest = true; }
    }
    g_cli_id = 0;
    WAIT_WHILE(!s.closed) srv_step(&s);
    CHECK(sent_rest && s.closed == 1 && s.authenticated == 0 && s.frames == 0);
    cli_free(c); free(c); srv_free(&s);
}

/* Row 9 through WebSocket frames: a request packed with the client's AUTHSIG
 * (one WebSocket frame). The client withholds its sealed AUTHSIG until it is
 * itself authenticated, seals a ping, and sends AUTHSIG + ping together. The
 * node must not deliver the ping before it verified the AUTHSIG and opened the
 * session (frames stays 0 until on_authenticated ran: on_frame itself asserts
 * the session is open and authenticated == 1), and delivers it after. */
static void ws_packed_request(void) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    cli_upgrade(c, &s);
    static uint8_t out[1 << 15], held[1 << 15];
    size_t held_len = 0, n = cli_take_out(c, out); CHECK(n > 0);
    cli_ws_chunks(c, out, n, 7);                          /* HELLO */
    bool keyx_sent = false;
    WAIT_WHILE(!cmt_p2p_sc_is_authenticated(&c->sc) && !c->eof) {
        srv_step(&s); cli_pump(c); cli_recv_hs(c);
        const cmt_p2p_sc_job_t *j;
        while ((j = cmt_p2p_sc_job(&c->sc)) != NULL) {
            CHECK(cmt_p2p_sc_job_done(&c->sc, cmt_p2p_sc_job_run(j, &c->host)) == CMT_OK);
            progress++;
            n = cli_take_out(c, out);
            if (!n) continue;
            if (!keyx_sent) { cli_ws_chunks(c, out, n, 7); keyx_sent = true; }
            else { CHECK(held_len + n <= sizeof(held)); memcpy(held + held_len, out, n); held_len += n; }
        }
    }
    CHECK(cmt_p2p_sc_is_authenticated(&c->sc) && held_len > 0);
    CHECK(s.authenticated == 0 && s.frames == 0);        /* the node has not seen our AUTHSIG */
    uint8_t payload[64]; memset(payload, 0x6b, sizeof(payload));
    uint8_t plain[128], pack[1 << 15];
    size_t pl = nodus_frame_encode(plain, sizeof(plain), payload, (uint32_t)sizeof(payload));
    CHECK(pl == sizeof(payload) + NODUS_FRAME_HEADER_SIZE);
    memcpy(pack, held, held_len);
    size_t written = 0;
    CHECK(cmt_p2p_sc_write(&c->sc, plain, pl, pack + held_len, sizeof(pack) - held_len, &written) == CMT_OK);
    cli_ws_frame(c, pack, held_len + written);            /* AUTHSIG and the request, ONE frame */
    WAIT_WHILE(s.frames == 0) { srv_step(&s); cli_pump(c); }
    CHECK(s.authenticated == 1 && s.frames == 1 && s.last_len == sizeof(payload) && s.closed == 0);
    cli_free(c); free(c); srv_free(&s);
}

/* 2: machine bytes before the Upgrade open no session. */
static void bytes_before_upgrade(void) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    uint8_t out[CMT_P2P_SC_OUT_CAP]; size_t n = cli_take_out(c, out); CHECK(n > 0);
    cli_send(c, out, n);                        /* HELLO as raw bytes, not HTTP */
    /* The HTTP parser has no end of head (no CRLFCRLF) in these bytes, so it
     * waits for more (nodus_ws.c nodus_ws_handshake_parse: NEED_MORE until
     * 8 KiB). Nothing starts a machine and nothing is written back; the 10 s
     * Upgrade limit (nodus_tcp_ws_sweep, called by the server loop) is what
     * closes it. Run a bounded number of passes, assert that, then drive the
     * sweep with a synthetic clock as test_ws_server.c does. */
    for (int i = 0; i < 200; ++i) { srv_step(&s); cli_pump(c); }
    CHECK(s.closed == 0 && s.conn != NULL && s.conn->session == NULL && !s.conn->ws_open);
    CHECK(s.authenticated == 0 && s.frames == 0 && c->rx_len == 0 && !c->eof);
    CHECK(nodus_tcp_ws_sweep(&s.tcp, nodus_time_now() + NODUS_WS_HANDSHAKE_TIMEOUT_S + 1) == 1);
    CHECK(s.closed == 1 && s.authenticated == 0 && s.frames == 0);
    cli_free(c); free(c); srv_free(&s);
}

/* 3: the deadline starts at Upgrade completion. */
/* Row 4 through WebSocket frames (wire): the node's first machine bytes inside
 * the WebSocket frames carry proto_ver 0F A1 00 01, and after the handshake
 * every byte the node sends is a whole number of 1044-byte sealed frames (no
 * plaintext session). */
static void ws_wire(void) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    cli_upgrade(c, &s);
    static uint8_t out[1 << 15];
    size_t n = cli_take_out(c, out); CHECK(n > 0);
    cli_ws_chunks(c, out, n, 7);
    c->hello_sent = true;
    for (int i = 0; i < 60; ++i) { srv_step(&s); cli_pump(c); }   /* the node's HELLO answer, unread by the machine */
    static const uint8_t version[] = {0x0f, 0xa1, 0x00, 0x01};
    bool found = false;
    for (size_t i = 0; i + 4 <= c->in_len; ++i) if (!memcmp(c->in + i, version, 4)) found = true;
    CHECK(c->in_len > 0 && found);
    drive_handshake(c, &s, false);
    CHECK(c->in_len == 0 && s.conn != NULL);
    uint8_t p[31]; memset(p, 0x5a, sizeof(p));
    CHECK(nodus_tcp_send(s.conn, p, sizeof(p)) == 0);
    for (int i = 0; i < 60; ++i) { srv_step(&s); cli_pump(c); }
    CHECK(c->in_len > 0 && c->in_len % CMT_P2P_SC_SEALED_FRAME_SIZE == 0);
    cli_free(c); free(c); srv_free(&s);
}

/* Row 5 through WebSocket frames: a client whose proto_ver is the 4002 or the
 * 4004 value never authenticates; the connection is closed before any
 * handshake job and nothing is delivered. */
static void ws_other_version(uint32_t proto) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    g_cli_proto = proto;
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    g_cli_proto = CMT_P2P_SC_PROTO_VER_4001;
    cli_upgrade(c, &s);
    static uint8_t out[1 << 15];
    size_t n = cli_take_out(c, out); CHECK(n > 0);
    cli_ws_chunks(c, out, n, 7);
    WAIT_WHILE(!s.closed) { srv_step(&s); cli_pump(c); }
    CHECK(s.closed == 1 && s.authenticated == 0 && s.frames == 0 && s.jobs == 0);
    cli_free(c); free(c); srv_free(&s);
}

/* Row 7 through WebSocket frames: the old T2 hello frame, sent in a binary
 * WebSocket frame after the Upgrade, gives no session and no dispatch. */
static void ws_old_handshake(void) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    cli_upgrade(c, &s);
    uint8_t p[8192], fr[8300]; size_t pn = 0;
    CHECK(nodus_t2_hello(1, &ids[0].pk, &ids[0].node_id, p, sizeof(p), &pn) == 0);
    size_t fn = nodus_frame_encode(fr, sizeof(fr), p, (uint32_t)pn); CHECK(fn);
    cli_ws_frame(c, fr, fn);
    WAIT_WHILE(!s.closed) { srv_step(&s); cli_pump(c); }
    CHECK(s.closed == 1 && s.authenticated == 0 && s.frames == 0 && s.jobs == 0);
    cli_free(c); free(c); srv_free(&s);
}

static void deadline_from_upgrade(void) {
    srv_t s; srv_init(&s);
    cli_t *c = calloc(1, sizeof(*c)); CHECK(c);
    cli_init(c, tcp_connect_ws(s.tcp.ws_port));
    for (int i = 0; i < 20; ++i) srv_step(&s);
    s.now += 2900;                              /* 2.9 s after accept, no Upgrade yet */
    for (int i = 0; i < 20; ++i) srv_step(&s);
    CHECK(s.closed == 0 && s.conn != NULL);
    cli_upgrade(c, &s);                         /* machine starts here */
    s.now += 2999;
    for (int i = 0; i < 20; ++i) { srv_step(&s); cli_pump(c); }
    CHECK(s.closed == 0 && s.conn != NULL);     /* not before 3 s from the Upgrade */
    s.now += 1;
    WAIT_WHILE(!s.closed) { srv_step(&s); cli_pump(c); }
    CHECK(s.closed == 1 && s.authenticated == 0);
    cli_free(c); free(c); srv_free(&s);
}

int main(void) {
    for (int i = 0; i < 2; ++i) CHECK(nodus_identity_generate(&ids[i]) == 0);
    ws_session(false, false); ws_session(true, false);
    ws_session(false, true);     /* the HELLO trails the Upgrade request in one write */
    g_ws_first = true;           /* plan 2.1 f: the listener first, the module second */
    ws_session(false, false);
    g_ws_first = false;
    ws_reflection(); ws_packed_request();
    ws_wire(); ws_other_version(CMT_P2P_SC_PROTO_VER_4002); ws_other_version(CMT_P2P_SC_PROTO_VER_4004);
    ws_old_handshake();
    bytes_before_upgrade(); deadline_from_upgrade();
    for (int i = 0; i < 2; ++i) nodus_identity_clear(&ids[i]);
    puts("test_ws_session: all cases passed");
    return 0;
}
