/**
 * @file faucet_http.c
 * @brief nodus-faucet HTTP (see faucet_http.h).
 */
#define _GNU_SOURCE
#include "faucet_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "FAUCET_HTTP"

/* ── request parser ─────────────────────────────────────────────────── */

static const char *find_crlfcrlf(const char *buf, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 4 <= len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n') return buf + i;
    return NULL;
}

int faucet_http_parse(const char *buf, size_t len, faucet_http_req_t *req) {
    memset(req, 0, sizeof(*req));
    size_t scan = len < FH_MAX_HEADER_BLOCK + 4 ? len : FH_MAX_HEADER_BLOCK + 4;
    const char *end = find_crlfcrlf(buf, scan);
    if (!end) return len > FH_MAX_HEADER_BLOCK ? -431 : 0;
    size_t head_len = (size_t)(end - buf);            /* without the blank line */
    if (head_len > FH_MAX_HEADER_BLOCK) return -431;

    /* the header block is text: no NUL, every LF preceded by CR */
    for (size_t i = 0; i < head_len; i++) {
        if (buf[i] == '\0') return -400;
        if (buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r')) return -400;
        if (buf[i] == '\r' && buf[i + 1] != '\n') return -400;  /* i+1 <= head_len+3 */
    }

    /* request line */
    const char *p = buf;
    const char *eol = memchr(p, '\r', head_len);
    size_t line_len = eol ? (size_t)(eol - p) : head_len;
    if (line_len > FH_MAX_REQUEST_LINE) return -400;
    char line[FH_MAX_REQUEST_LINE + 1];
    memcpy(line, p, line_len);
    line[line_len] = '\0';
    char *sp1 = strchr(line, ' ');
    if (!sp1) return -400;
    *sp1 = '\0';
    char *path = sp1 + 1;
    char *sp2 = strchr(path, ' ');
    if (!sp2) return -400;
    *sp2 = '\0';
    char *ver = sp2 + 1;
    if (strcmp(ver, "HTTP/1.1") && strcmp(ver, "HTTP/1.0")) return -400;
    int is_get = !strcmp(line, "GET"), is_post = !strcmp(line, "POST");
    if (!is_get && !is_post) return -405;
    size_t plen = strlen(path);
    if (plen == 0 || plen >= FH_MAX_PATH || path[0] != '/') return -400;
    for (size_t i = 0; i < plen; i++) {
        unsigned char ch = (unsigned char)path[i];
        if (ch < 0x21 || ch > 0x7e || ch == '?' || ch == '#') return -400;
    }
    snprintf(req->method, sizeof(req->method), "%s", is_get ? "GET" : "POST");
    snprintf(req->path, sizeof(req->path), "%s", path);

    /* header lines */
    long clen = -1;
    int nhdr = 0;
    const char *cur = eol ? eol + 2 : buf + head_len;
    while (cur < buf + head_len) {
        const char *le = memchr(cur, '\r', (size_t)(buf + head_len - cur));
        size_t hl = le ? (size_t)(le - cur) : (size_t)(buf + head_len - cur);
        if (hl > FH_MAX_HEADER_LINE) return -431;
        if (++nhdr > FH_MAX_HEADERS) return -431;
        const char *colon = memchr(cur, ':', hl);
        if (!colon || colon == cur) return -400;
        size_t nlen = (size_t)(colon - cur);
        if (nlen == 14 && !strncasecmp(cur, "content-length", 14)) {
            if (clen >= 0) return -400;                 /* duplicate */
            const char *v = colon + 1;
            const char *ve = cur + hl;
            while (v < ve && (*v == ' ' || *v == '\t')) v++;
            if (v == ve || ve - v > 6) return -400;
            long n = 0;
            for (; v < ve; v++) {
                if (*v < '0' || *v > '9') return -400;
                n = n * 10 + (*v - '0');
            }
            if (n > FH_MAX_BODY) return -413;
            clen = n;
        } else if (nlen == 17 && !strncasecmp(cur, "transfer-encoding", 17)) {
            return -501;
        }
        cur = le ? le + 2 : buf + head_len;
    }
    if (is_get && clen > 0) return -400;
    if (is_post && clen < 0) return -411;
    if (clen < 0) clen = 0;

    size_t body_off = head_len + 4;
    if (len < body_off + (size_t)clen) return 0;        /* body still coming */
    req->body = buf + body_off;
    req->body_len = (size_t)clen;
    return 1;
}

/* ── JSON ───────────────────────────────────────────────────────────── */

static void skip_ws(const char **p, const char *end) {
    while (*p < end && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n'))
        (*p)++;
}

int faucet_json_parse_claim(const char *body, size_t len, char addr_out[129]) {
    const char *p = body, *end = body + len;
    skip_ws(&p, end);
    if (p >= end || *p++ != '{') return -1;
    skip_ws(&p, end);
    static const char key[] = "\"address\"";
    if ((size_t)(end - p) < sizeof(key) - 1 || memcmp(p, key, sizeof(key) - 1))
        return -1;
    p += sizeof(key) - 1;
    skip_ws(&p, end);
    if (p >= end || *p++ != ':') return -1;
    skip_ws(&p, end);
    if (p >= end || *p++ != '"') return -1;
    if ((size_t)(end - p) < 129) return -1;
    for (int i = 0; i < 128; i++) {
        char ch = p[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return -1;
    }
    if (p[128] != '"') return -1;
    memcpy(addr_out, p, 128);
    addr_out[128] = '\0';
    p += 129;
    skip_ws(&p, end);
    if (p >= end || *p++ != '}') return -1;
    skip_ws(&p, end);
    return p == end ? 0 : -1;
}

typedef struct { char *out; size_t cap; size_t n; int bad; } jbuf_t;

static void j_raw(jbuf_t *j, const char *s) {
    size_t l = strlen(s);
    if (j->n + l + 1 > j->cap) { j->bad = 1; return; }
    memcpy(j->out + j->n, s, l + 1);
    j->n += l;
}

static void j_str(jbuf_t *j, const char *s) {
    j_raw(j, "\"");
    for (; *s; s++) {
        char t[8];
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') { t[0] = '\\'; t[1] = (char)ch; t[2] = 0; }
        else if (ch < 0x20 || ch >= 0x7f) snprintf(t, sizeof(t), "\\u%04x", ch);
        else { t[0] = (char)ch; t[1] = 0; }
        j_raw(j, t);
    }
    j_raw(j, "\"");
}

int faucet_json_answer(const faucet_answer_t *a, char *out, size_t cap) {
    jbuf_t j = { out, cap, 0, 0 };
    if (cap) out[0] = '\0';
    j_raw(&j, "{\"claim_id\":");  j_str(&j, a->claim_id);
    j_raw(&j, ",\"state\":");     j_str(&j, a->state);
    j_raw(&j, ",\"kind\":");      j_str(&j, a->kind);
    j_raw(&j, ",\"message\":");   j_str(&j, a->message);
    j_raw(&j, "}");
    return j.bad ? -1 : (int)j.n;
}

int faucet_json_status(const faucet_status_t *s, char *out, size_t cap) {
    jbuf_t j = { out, cap, 0, 0 };
    char num[32];
    if (cap) out[0] = '\0';
    j_raw(&j, "{\"open\":");       j_raw(&j, s->open ? "true" : "false");
    j_raw(&j, ",\"paused\":");     j_raw(&j, s->paused ? "true" : "false");
    snprintf(num, sizeof(num), "%llu", (unsigned long long)s->full_left);
    j_raw(&j, ",\"full_left\":");  j_raw(&j, num);
    snprintf(num, sizeof(num), "%llu", (unsigned long long)s->start_left);
    j_raw(&j, ",\"start_left\":"); j_raw(&j, num);
    j_raw(&j, ",\"message\":");    j_str(&j, s->message);
    j_raw(&j, "}");
    return j.bad ? -1 : (int)j.n;
}

/* ── routing ────────────────────────────────────────────────────────── */

static void answer_json(int http, const char *state, const char *msg,
                        int *status, char *body, size_t cap) {
    faucet_answer_t a;
    memset(&a, 0, sizeof(a));
    a.http = http;
    snprintf(a.claim_id, sizeof(a.claim_id), "%s", FAUCET_NO_CLAIM_ID);
    snprintf(a.state, sizeof(a.state), "%s", state);
    snprintf(a.kind, sizeof(a.kind), "none");
    snprintf(a.message, sizeof(a.message), "%s", msg);
    *status = http;
    if (faucet_json_answer(&a, body, cap) < 0) { *status = 500; body[0] = '\0'; }
}

static void route_inner(faucet_core_t *core, const faucet_http_req_t *req,
                        uint64_t deadline_ms, int *status, char *body,
                        size_t cap) {
    static const char P_CLAIM[] = "/faucet/claim";
    static const char P_CLAIM_ID[] = "/faucet/claim/";
    static const char P_STATUS[] = "/faucet/status";
    const int is_get = !strcmp(req->method, "GET");
    const int is_post = !strcmp(req->method, "POST");

    if (!strcmp(req->path, P_CLAIM)) {
        if (!is_post) { answer_json(405, "refused", "use POST", status, body, cap); return; }
        char addr[129];
        if (faucet_json_parse_claim(req->body, req->body_len, addr) != 0) {
            answer_json(400, "refused", "body must be {\"address\":\"<128 lowercase hex>\"}",
                        status, body, cap);
            return;
        }
        faucet_answer_t a;
        faucet_api_claim(core, addr, deadline_ms, &a);
        *status = a.http;
        if (faucet_json_answer(&a, body, cap) < 0) { *status = 500; body[0] = '\0'; }
        return;
    }
    if (!strncmp(req->path, P_CLAIM_ID, sizeof(P_CLAIM_ID) - 1)) {
        if (!is_get) { answer_json(405, "refused", "use GET", status, body, cap); return; }
        faucet_answer_t a;
        faucet_api_get_claim(core, req->path + sizeof(P_CLAIM_ID) - 1, &a);
        *status = a.http;
        if (faucet_json_answer(&a, body, cap) < 0) { *status = 500; body[0] = '\0'; }
        return;
    }
    if (!strcmp(req->path, P_STATUS)) {
        if (!is_get) { answer_json(405, "refused", "use GET", status, body, cap); return; }
        faucet_status_t s;
        faucet_api_status(core, &s);
        *status = 200;
        if (faucet_json_status(&s, body, cap) < 0) { *status = 500; body[0] = '\0'; }
        return;
    }
    answer_json(404, "refused", "not found", status, body, cap);
}

/* The handler runs inside the single poll loop: every journal call of this
 * request (mutex wait and SQLite busy wait) is bounded by the connection's
 * deadline, so a slow disk cannot stall the other connections or the
 * deadline sweep. The thread's deadline is cleared before returning. */
void faucet_http_route(faucet_core_t *core, const faucet_http_req_t *req,
                       uint64_t deadline_ms, int *status, char *body,
                       size_t cap) {
    faucet_journal_thread_deadline(deadline_ms);
    route_inner(core, req, deadline_ms, status, body, cap);
    faucet_journal_thread_deadline(FJ_NO_DEADLINE);
}

/* ── the server ─────────────────────────────────────────────────────── */

#define FH_BUF_MAX  (FH_MAX_HEADER_BLOCK + 4 + FH_MAX_BODY)
#define FH_CONN_HARD_MAX 256

#define FH_RESP_BUF (FH_RESPONSE_MAX + 256)   /* head + body, bounded        */

/* One connection. The request is read into buf; the answer is built ONCE
 * into resp and sent from resp_off until resp_len — a short write or EAGAIN
 * leaves the connection in `writing` and the rest goes out through POLLOUT,
 * all within the connection's deadline. */
typedef struct {
    int      fd;
    size_t   len;
    uint64_t deadline_ms;
    int      writing;
    size_t   resp_len, resp_off;
    char     resp[FH_RESP_BUF];
    char     buf[FH_BUF_MAX];
} fh_conn_t;

/* 0 = send as much as the socket takes (production). A test sets a small
 * number to prove the POLLOUT continuation: at most that many bytes leave
 * per flush. */
static size_t g_max_send_chunk = 0;

void faucet_http_set_max_send_chunk(size_t n) { g_max_send_chunk = n; }

struct faucet_http {
    int                    lfd;
    int                    conn_cap;
    int                    timeout_ms;
    faucet_http_handler_fn handler;
    void                  *ctx;
    int                    nconn;
    fh_conn_t             *conns[FH_CONN_HARD_MAX];
};

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static const char *reason(int s) {
    switch (s) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Internal Server Error";
    }
}

/* Format one complete answer into out[cap]. @return its length, 0 when it
 * does not fit. */
static size_t format_response(char *out, size_t cap, int status, const char *body) {
    size_t bl = body ? strlen(body) : 0;
    int n = snprintf(out, cap,
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                     "Connection: close\r\n\r\n%s",
                     status, reason(status), bl, body ? body : "");
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

static void error_body(char *body, size_t cap, const char *msg) {
    snprintf(body, cap,
             "{\"claim_id\":\"00000000000000000000000000000000\","
             "\"state\":\"refused\",\"kind\":\"none\",\"message\":\"%s\"}", msg);
}

/* BEST-EFFORT single send, for the two answers that owe the peer nothing:
 * the over-the-cap 503 (no slot is kept for that socket) and the 408 of a
 * client that already missed its deadline. Every other answer goes through
 * the connection's buffered, POLLOUT-driven path below. */
static void send_once(int fd, int status, const char *msg) {
    char body[256], resp[FH_RESP_BUF];
    error_body(body, sizeof(body), msg);
    size_t n = format_response(resp, sizeof(resp), status, body);
    if (n) (void)send(fd, resp, n, MSG_NOSIGNAL | MSG_DONTWAIT);
}

/* Build the answer into the connection and start sending it. */
static void begin_response(fh_conn_t *c, int status, const char *body) {
    size_t n = format_response(c->resp, sizeof(c->resp), status, body);
    if (!n) n = format_response(c->resp, sizeof(c->resp), 500, "");
    c->resp_len = n;
    c->resp_off = 0;
    c->writing = 1;
}

/* Send what the socket takes. @return 1 everything sent, 0 more to send
 * (wait for POLLOUT), -1 the peer is gone. */
static int flush_conn(fh_conn_t *c) {
    while (c->resp_off < c->resp_len) {
        size_t want = c->resp_len - c->resp_off;
        if (g_max_send_chunk && want > g_max_send_chunk) want = g_max_send_chunk;
        ssize_t r = send(c->fd, c->resp + c->resp_off, want,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        c->resp_off += (size_t)r;
        if (g_max_send_chunk) break;            /* one chunk per flush (test) */
    }
    return c->resp_off >= c->resp_len ? 1 : 0;
}

static void drop(faucet_http_t *h, int idx) {
    close(h->conns[idx]->fd);
    free(h->conns[idx]);
    h->conns[idx] = h->conns[--h->nconn];
    h->conns[h->nconn] = NULL;
}

int faucet_http_open(uint16_t port, int conn_cap, int timeout_ms,
                     faucet_http_handler_fn handler, void *ctx,
                     faucet_http_t **out, uint16_t *bound) {
    if (!handler || !out || conn_cap < 1 || conn_cap > FH_CONN_HARD_MAX ||
        timeout_ms < 1) return -1;
    *out = NULL;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);       /* 127.0.0.1 ONLY */
    sa.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot listen on 127.0.0.1:%u: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (bound) {
        socklen_t sl = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) { close(fd); return -1; }
        *bound = ntohs(sa.sin_port);
    }
    faucet_http_t *h = calloc(1, sizeof(*h));
    if (!h) { close(fd); return -1; }
    h->lfd = fd;
    h->conn_cap = conn_cap;
    h->timeout_ms = timeout_ms;
    h->handler = handler;
    h->ctx = ctx;
    *out = h;
    return 0;
}

int faucet_http_connections(const faucet_http_t *h) { return h->nconn; }

/* After begin_response: push it out now; a connection whose answer is not
 * fully sent stays (writing) until POLLOUT or its deadline. */
static void answer_conn(faucet_http_t *h, int idx, int status, const char *body) {
    fh_conn_t *c = h->conns[idx];
    begin_response(c, status, body);
    if (flush_conn(c) != 0) drop(h, idx);       /* done, or the peer is gone */
}

static void serve_conn(faucet_http_t *h, int idx) {
    fh_conn_t *c = h->conns[idx];
    if (c->writing) {                           /* POLLOUT: the rest of the answer */
        if (flush_conn(c) != 0) drop(h, idx);
        return;
    }
    ssize_t r = recv(c->fd, c->buf + c->len, sizeof(c->buf) - c->len, 0);
    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        drop(h, idx);
        return;
    }
    if (r < 0) return;
    c->len += (size_t)r;

    char body[FH_RESPONSE_MAX];
    faucet_http_req_t req;
    int pr = faucet_http_parse(c->buf, c->len, &req);
    if (pr == 0) {
        if (c->len >= sizeof(c->buf)) {
            error_body(body, sizeof(body), "request too large");
            answer_conn(h, idx, 413, body);
        }
        return;
    }
    if (pr < 0) {
        error_body(body, sizeof(body), "request refused");
        answer_conn(h, idx, -pr, body);
        return;
    }
    int status = 500;
    body[0] = '\0';
    /* The handler is bounded by THIS connection's deadline (it may only
     * wait on the node until then — faucet_node.h); it is the only place a
     * request spends time that the deadline sweep below cannot interrupt. */
    h->handler(h->ctx, &req, c->deadline_ms, &status, body, sizeof(body));
    answer_conn(h, idx, status, body);
}

int faucet_http_poll(faucet_http_t *h, int wait_ms) {
    struct pollfd pfd[FH_CONN_HARD_MAX + 1];
    const int nold = h->nconn;      /* connections pfd[1..nold] describe */
    pfd[0].fd = h->lfd;
    pfd[0].events = POLLIN;
    for (int i = 0; i < h->nconn; i++) {
        pfd[i + 1].fd = h->conns[i]->fd;
        pfd[i + 1].events = h->conns[i]->writing ? POLLOUT : POLLIN;
    }
    int n = poll(pfd, (nfds_t)(h->nconn + 1), wait_ms);
    if (n < 0 && errno != EINTR) return -1;

    if (n > 0 && (pfd[0].revents & POLLIN)) {
        for (int k = 0; k < 16; k++) {
            int cfd = accept4(h->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (cfd < 0) break;
            if (h->nconn >= h->conn_cap) {
                send_once(cfd, 503, "too many connections");
                close(cfd);
                continue;
            }
            fh_conn_t *c = calloc(1, sizeof(*c));
            if (!c) { close(cfd); continue; }
            c->fd = cfd;
            c->deadline_ms = now_ms() + (uint64_t)h->timeout_ms;
            h->conns[h->nconn++] = c;
        }
    }
    /* The connections that were polled (the first nold; accepts above only
     * append). A drop swaps the LAST connection into the dropped slot, so
     * walking backwards never revisits or skips a polled one. */
    if (n > 0)
        for (int i = nold - 1; i >= 0; i--)
            if (pfd[i + 1].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR))
                serve_conn(h, i);

    /* the per-connection deadline: a client that has not finished its
     * request gets a best-effort 408; an answer still not fully sent is cut
     * (the peer is too slow to take 1.3 KB within the deadline) */
    uint64_t now = now_ms();
    for (int i = h->nconn - 1; i >= 0; i--) {
        if (now >= h->conns[i]->deadline_ms) {
            if (!h->conns[i]->writing)
                send_once(h->conns[i]->fd, 408, "request timeout");
            drop(h, i);
        }
    }
    return 0;
}

void faucet_http_close(faucet_http_t *h) {
    if (!h) return;
    while (h->nconn > 0) drop(h, h->nconn - 1);
    close(h->lfd);
    free(h);
}
