/**
 * test_faucet_http.c — the faucet's HTTP layer: parser bounds, JSON shapes,
 * routing and the real loopback server.
 *
 * Governing: docs/plans/2026-10-22-testnet-faucet-design.md section 6.8 and
 * the build plan's HTTP API (docs/plans/2026-10-22-mm-dex-build-plan.md,
 * package C: POST /faucet/claim, GET /faucet/claim/<id>, GET /faucet/status).
 *
 * WHAT IT PROVES
 *   P*  the request parser enforces every bound: request line <= 256 bytes,
 *       header block <= 4096, <= 32 header lines of <= 512, body <=
 *       Content-Length <= 1024 (1024 accepted, 1025 refused), no
 *       Transfer-Encoding, no duplicate or non-numeric Content-Length, only
 *       GET and POST, no query string, POST needs a length, GET must not
 *       carry a body, no NUL and no bare LF; a request split across reads
 *       asks for more instead of failing;
 *   J*  the claim body parser accepts exactly {"address":"<128 lowercase
 *       hex>"} (whitespace allowed) and refuses extra keys, uppercase,
 *       short or long hex, escapes, trailing bytes; the answer and status
 *       encoders emit EXACTLY the shapes of the build plan, escape text,
 *       and refuse a too-small buffer;
 *   R*  routing: POST claim -> 200 + claim shape; bad body 400; wrong method
 *       405; unknown path 404; GET claim/<id>; GET status;
 *   R6  the connection's deadline reaches the claim handler (a POST past its
 *       deadline is 503 with no node call; a live deadline is handed to the
 *       node reads); GET status and GET claim make no node call at all;
 *   R7  the journal wait is bounded by that deadline: with the journal's
 *       write lock held by another connection a POST answers 503 "busy, try
 *       again" and no claim exists afterwards; with the lock gone the same
 *       request creates it;
 *   R8  GET /faucet/status is 200 only on success: a busy journal (deadline
 *       already past) is 503 "busy, try again", a live deadline is 200 with
 *       the usual body; R9 a journal fault (unstatable -wal path) is 503
 *       "the faucet journal is unavailable";
 *   V*  the real server over 127.0.0.1: answers, a refused oversized request
 *       is answered at once, a slow client gets 408 after the deadline, the
 *       connection cap answers 503 and never grows past the cap; V8: an
 *       answer the socket takes only in pieces (16 bytes per flush through
 *       the test seam) is completed through POLLOUT, whole and intact, and
 *       the slot is released.
 * WHAT IT REQUIRES: a default build; a loopback listener on a kernel-chosen
 *   port (no fixed port); a mkdtemp directory for the stub core's journal.
 * LEAVES BEHIND: nothing (sockets closed, directory removed).
 * HOW IT CAN LIE: client and server run in ONE thread (the test drives
 *   faucet_http_poll), so concurrency between connections is not exercised.
 *   V8 forces short writes with the seam (a loopback socket takes 1.3 KB at
 *   once); that an unfinished answer is cut AT the connection deadline is
 *   not tested (it would need a sleeping, timing-dependent test).
 */
#define _GNU_SOURCE
#include "test_faucet_stub.c"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "faucet_http.h"

/* ── parser ─────────────────────────────────────────────────────────── */

static int parse(const char *s, faucet_http_req_t *r) {
    return faucet_http_parse(s, strlen(s), r);
}

static void test_parser(void) {
    faucet_http_req_t r;
    CHECK(parse("GET /faucet/status HTTP/1.1\r\nHost: x\r\n\r\n", &r) == 1 &&
          !strcmp(r.method, "GET") && !strcmp(r.path, "/faucet/status") && r.body_len == 0,
          "P1 a GET parses");
    CHECK(parse("POST /faucet/claim HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", &r) == 1 &&
          r.body_len == 5 && !memcmp(r.body, "hello", 5), "P2 a POST with its body parses");
    CHECK(parse("POST /faucet/claim HTTP/1.1\r\ncontent-LENGTH: 5\r\n\r\nhello", &r) == 1,
          "P2 header names are case-insensitive");
    CHECK(parse("GET /faucet/status HTTP/1.1\r\nHost: x\r\n", &r) == 0, "P3 an incomplete header block asks for more");
    CHECK(parse("POST /faucet/claim HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel", &r) == 0,
          "P3 an incomplete body asks for more");
    CHECK(parse("PUT /faucet/claim HTTP/1.1\r\n\r\n", &r) == -405, "P4 PUT is refused (405)");
    CHECK(parse("DELETE /x HTTP/1.1\r\n\r\n", &r) == -405, "P4 DELETE is refused (405)");
    CHECK(parse("POST /faucet/claim HTTP/1.1\r\nHost: x\r\n\r\n", &r) == -411, "P5 POST without Content-Length (411)");
    CHECK(parse("GET /faucet/status HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", &r) == -400, "P5 a GET with a body is refused");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello", &r) == -400,
          "P5 a duplicate Content-Length is refused");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: 5x\r\n\r\nhello", &r) == -400, "P5 a non-numeric Content-Length is refused");
    CHECK(parse("POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &r) == -400, "P5 a negative Content-Length is refused");
    CHECK(parse("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &r) == -501, "P6 Transfer-Encoding is refused (501)");
    CHECK(parse("GET /x?a=1 HTTP/1.1\r\n\r\n", &r) == -400, "P7 a query string is refused");
    CHECK(parse("GET x HTTP/1.1\r\n\r\n", &r) == -400, "P7 a path without a leading slash is refused");
    CHECK(parse("GET /x HTTP/2.0\r\n\r\n", &r) == -400, "P7 an unknown HTTP version is refused");
    CHECK(parse("GET /x HTTP/1.1\nHost: y\r\n\r\n", &r) == -400, "P8 a bare LF is refused");
    {
        static const char nul_req[] = "GET /x HTTP/1.1\r\nA: b\0c\r\n\r\n";
        CHECK(faucet_http_parse(nul_req, sizeof(nul_req) - 1, &r) == -400, "P8 a NUL byte is refused");
    }

    /* body bound: 1024 accepted, 1025 refused */
    {
        char *big = malloc(8192);
        int n = snprintf(big, 8192, "POST /x HTTP/1.1\r\nContent-Length: 1024\r\n\r\n");
        memset(big + n, 'a', 1024);
        CHECK(faucet_http_parse(big, (size_t)n + 1024, &r) == 1 && r.body_len == 1024, "P9 a 1024-byte body is accepted");
        n = snprintf(big, 8192, "POST /x HTTP/1.1\r\nContent-Length: 1025\r\n\r\n");
        memset(big + n, 'a', 1025);
        CHECK(faucet_http_parse(big, (size_t)n + 1025, &r) == -413, "P9 a 1025-byte body is refused (413)");
        n = snprintf(big, 8192, "POST /x HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n");
        CHECK(faucet_http_parse(big, (size_t)n, &r) < 0, "P9 an absurd Content-Length is refused before any body");

        /* request line > 256 */
        n = snprintf(big, 8192, "GET /");
        memset(big + n, 'a', 300);
        n += 300;
        n += snprintf(big + n, 100, " HTTP/1.1\r\n\r\n");
        CHECK(faucet_http_parse(big, (size_t)n, &r) < 0, "P10 a request line over 256 bytes is refused");

        /* header line > 512 */
        n = snprintf(big, 8192, "GET /x HTTP/1.1\r\nX: ");
        memset(big + n, 'b', 600);
        n += 600;
        n += snprintf(big + n, 100, "\r\n\r\n");
        CHECK(faucet_http_parse(big, (size_t)n, &r) == -431, "P10 a header line over 512 bytes is refused (431)");

        /* 33 header lines */
        n = snprintf(big, 8192, "GET /x HTTP/1.1\r\n");
        for (int i = 0; i < 33; i++) n += snprintf(big + n, 64, "H%d: v\r\n", i);
        n += snprintf(big + n, 8, "\r\n");
        CHECK(faucet_http_parse(big, (size_t)n, &r) == -431, "P10 more than 32 header lines is refused (431)");
        n = snprintf(big, 8192, "GET /x HTTP/1.1\r\n");
        for (int i = 0; i < 32; i++) n += snprintf(big + n, 64, "H%d: v\r\n", i);
        n += snprintf(big + n, 8, "\r\n");
        CHECK(faucet_http_parse(big, (size_t)n, &r) == 1, "P10 exactly 32 header lines is accepted");

        /* header block > 4096 with no end: asks for more up to the bound, then refuses */
        n = snprintf(big, 8192, "GET /x HTTP/1.1\r\n");
        for (int i = 0; n < 4200; i++) n += snprintf(big + n, 64, "Hh%d: vvvvvvvvvvvvvvvv\r\n", i);
        CHECK(faucet_http_parse(big, 4000, &r) == 0, "P11 a header block below 4096 without its end asks for more");
        CHECK(faucet_http_parse(big, (size_t)n, &r) == -431, "P11 a header block over 4096 is refused (431)");
        free(big);
    }
}

/* ── JSON ───────────────────────────────────────────────────────────── */

static void test_json(void) {
    char addr[129], body[512], out[512];
    char good[129];
    make_addr(good, 3);
    char a_ok[256], a_ws[300];
    snprintf(a_ok, sizeof(a_ok), "{\"address\":\"%s\"}", good);
    snprintf(a_ws, sizeof(a_ws), "  {\n \"address\" :\t\"%s\" }\n", good);
    CHECK(faucet_json_parse_claim(a_ok, strlen(a_ok), addr) == 0 && !strcmp(addr, good), "J1 the exact body parses");
    CHECK(faucet_json_parse_claim(a_ws, strlen(a_ws), addr) == 0, "J1 whitespace is allowed");
    snprintf(body, sizeof(body), "{\"address\":\"%s\",\"x\":1}", good);
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 an extra key is refused");
    snprintf(body, sizeof(body), "{\"addr\":\"%s\"}", good);
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 a different key is refused");
    snprintf(body, sizeof(body), "{\"address\":\"%s\"} x", good);
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 trailing bytes are refused");
    snprintf(body, sizeof(body), "{\"address\":\"%.127s\"}", good);
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 a 127-char address is refused");
    snprintf(body, sizeof(body), "{\"address\":\"%sa\"}", good);
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 a 129-char address is refused");
    snprintf(body, sizeof(body), "{\"address\":\"%s\"}", good);
    body[14] = 'A';
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 uppercase hex is refused");
    snprintf(body, sizeof(body), "{\"address\":\"\\u0061%.122s\"}", good);
    CHECK(faucet_json_parse_claim(body, strlen(body), addr) != 0, "J2 an escape sequence is refused");
    CHECK(faucet_json_parse_claim("", 0, addr) != 0 && faucet_json_parse_claim("{}", 2, addr) != 0,
          "J2 empty and empty-object bodies are refused");

    faucet_answer_t a;
    memset(&a, 0, sizeof(a));
    snprintf(a.claim_id, sizeof(a.claim_id), "%s", FAUCET_NO_CLAIM_ID);
    snprintf(a.state, sizeof(a.state), "refused");
    snprintf(a.kind, sizeof(a.kind), "none");
    snprintf(a.message, sizeof(a.message), "no");
    CHECK(faucet_json_answer(&a, out, sizeof(out)) > 0 &&
          !strcmp(out, "{\"claim_id\":\"00000000000000000000000000000000\",\"state\":\"refused\","
                       "\"kind\":\"none\",\"message\":\"no\"}"), "J3 the claim answer has EXACTLY the build-plan shape");
    snprintf(a.message, sizeof(a.message), "say \"hi\" \\ and \n");
    faucet_json_answer(&a, out, sizeof(out));
    CHECK(strstr(out, "say \\\"hi\\\" \\\\ and \\u000a") != NULL, "J3 quotes, backslashes and control characters are escaped");
    CHECK(faucet_json_answer(&a, out, 20) == -1, "J3 a too-small buffer is refused, not truncated");

    faucet_status_t s;
    memset(&s, 0, sizeof(s));
    s.open = 1; s.paused = 0; s.full_left = 7; s.start_left = 190;
    snprintf(s.message, sizeof(s.message), "ok");
    CHECK(faucet_json_status(&s, out, sizeof(out)) > 0 &&
          !strcmp(out, "{\"open\":true,\"paused\":false,\"full_left\":7,\"start_left\":190,\"message\":\"ok\"}"),
          "J4 the status answer has EXACTLY the build-plan shape");
}

/* ── routing (stub core) ────────────────────────────────────────────── */

static void route(env_t *e, const char *method, const char *path, const char *body,
                  int *status, char *out, size_t cap) {
    faucet_http_req_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.method, sizeof(r.method), "%s", method);
    snprintf(r.path, sizeof(r.path), "%s", path);
    r.body = body;
    r.body_len = body ? strlen(body) : 0;
    faucet_http_route(&e->core, &r, FAUCET_NODE_NO_DEADLINE, status, out, cap);
}

static void test_routes(void) {
    env_t e;
    env_open(&e, 64ULL << 20);
    char addr[129], body[256], out[1024];
    make_addr(addr, 9);
    snprintf(body, sizeof(body), "{\"address\":\"%s\"}", addr);
    e.st.name_found = 0;
    e.st.bal_native = 0;
    int status = 0;

    route(&e, "POST", "/faucet/claim", body, &status, out, sizeof(out));
    CHECK(status == 200 && strstr(out, "\"state\":\"planned\"") && strstr(out, "\"kind\":\"start\"") &&
          strstr(out, "\"claim_id\":\""), "R1 POST /faucet/claim creates a START claim");
    char id[33];
    const char *p = strstr(out, "\"claim_id\":\"") + 12;
    memcpy(id, p, 32);
    id[32] = '\0';
    route(&e, "POST", "/faucet/claim", "{\"address\":\"zz\"}", &status, out, sizeof(out));
    CHECK(status == 400, "R2 a bad body is 400");
    route(&e, "GET", "/faucet/claim", NULL, &status, out, sizeof(out));
    CHECK(status == 405, "R2 GET on the claim path is 405");
    route(&e, "POST", "/faucet/status", "{}", &status, out, sizeof(out));
    CHECK(status == 405, "R2 POST on the status path is 405");
    route(&e, "GET", "/faucet/nothing", NULL, &status, out, sizeof(out));
    CHECK(status == 404, "R3 an unknown path is 404");
    char path[96];
    snprintf(path, sizeof(path), "/faucet/claim/%s", id);
    route(&e, "GET", path, NULL, &status, out, sizeof(out));
    CHECK(status == 200 && strstr(out, id) && strstr(out, "\"state\":\"planned\""), "R4 GET /faucet/claim/<id>");
    route(&e, "GET", "/faucet/claim/00000000000000000000000000000001", NULL, &status, out, sizeof(out));
    CHECK(status == 404, "R4 an unknown claim id is 404");
    route(&e, "GET", "/faucet/status", NULL, &status, out, sizeof(out));
    CHECK(status == 200 && strstr(out, "\"open\":true") && strstr(out, "\"full_left\":") &&
          strstr(out, "\"start_left\":") && strstr(out, "\"paused\":false"), "R5 GET /faucet/status");

    /* R6: the request's deadline rides down to the claim; GET status and GET
     * claim never call the node */
    {
        char addr2[129], body2[256];
        make_addr(addr2, 10);
        snprintf(body2, sizeof(body2), "{\"address\":\"%s\"}", addr2);
        faucet_http_req_t r;
        memset(&r, 0, sizeof(r));
        snprintf(r.method, sizeof(r.method), "POST");
        snprintf(r.path, sizeof(r.path), "/faucet/claim");
        r.body = body2;
        r.body_len = strlen(body2);
        int calls = e.st.node_calls;
        faucet_http_route(&e.core, &r, faucet_now_ms() - 1, &status, out, sizeof(out));
        CHECK(status == 503 && strstr(out, "\"state\":\"refused\"") && e.st.node_calls == calls,
              "R6 POST past its deadline is 503 without a node call");
        uint64_t live = faucet_now_ms() + 60000;
        faucet_http_route(&e.core, &r, live, &status, out, sizeof(out));
        CHECK(status == 200 && e.st.last_deadline == live, "R6 a live deadline reaches the node reads");
        calls = e.st.node_calls;
        route(&e, "GET", "/faucet/status", NULL, &status, out, sizeof(out));
        route(&e, "GET", path, NULL, &status, out, sizeof(out));
        CHECK(e.st.node_calls == calls, "R6 GET status and GET claim make no node call");
    }

    /* R7: the journal wait is bounded by the request's deadline. Another
     * connection holds the journal's write lock (it is never released while
     * the request runs), so the claim can only end as "busy" — whatever the
     * machine's speed — and must leave no claim behind. */
    {
        char addr3[129], body3[256];
        make_addr(addr3, 11);
        snprintf(body3, sizeof(body3), "{\"address\":\"%s\"}", addr3);
        faucet_http_req_t r;
        memset(&r, 0, sizeof(r));
        snprintf(r.method, sizeof(r.method), "POST");
        snprintf(r.path, sizeof(r.path), "/faucet/claim");
        r.body = body3;
        r.body_len = strlen(body3);
        sqlite3 *lk = NULL;
        CHECK(sqlite3_open_v2(e.jpath, &lk, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK &&
              sqlite3_exec(lk, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK,
              "R7 (setup) another connection holds the journal's write lock");
        faucet_http_route(&e.core, &r, faucet_now_ms() + 200, &status, out, sizeof(out));
        CHECK(status == 503 && strstr(out, "busy, try again") && strstr(out, "\"state\":\"refused\""),
              "R7 a claim that cannot take the journal by its deadline answers 503 busy");
        sqlite3_exec(lk, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(lk);
        faucet_claim_t none;
        CHECK(faucet_journal_claim_by_address(e.j, addr3, &none) == 1,
              "R7 ... and no claim was created");
        faucet_http_route(&e.core, &r, faucet_now_ms() + 60000, &status, out, sizeof(out));
        CHECK(status == 200 && strstr(out, "\"state\":\"planned\""),
              "R7 with the lock gone the same request creates the claim");
    }

    /* R8: /faucet/status is 200 ONLY on success. A deadline already past
     * (the journal cannot be taken in time: FJ_BUSY, no timing involved)
     * answers 503 "busy, try again"; a live deadline answers 200 with the
     * usual body. */
    {
        faucet_http_req_t r;
        memset(&r, 0, sizeof(r));
        snprintf(r.method, sizeof(r.method), "GET");
        snprintf(r.path, sizeof(r.path), "/faucet/status");
        faucet_http_route(&e.core, &r, faucet_now_ms() - 1, &status, out, sizeof(out));
        CHECK(status == 503 && strstr(out, "busy, try again") && strstr(out, "\"state\":\"refused\"") &&
              !strstr(out, "\"full_left\""),
              "R8 GET /faucet/status with a busy journal is 503 busy, not a 200 message");
        faucet_http_route(&e.core, &r, faucet_now_ms() + 60000, &status, out, sizeof(out));
        CHECK(status == 200 && strstr(out, "\"open\":true") && strstr(out, "\"full_left\":") &&
              strstr(out, "\"start_left\":") && strstr(out, "\"paused\":false"),
              "R8 ... with time left the same request is 200 with the usual body");
    }
    env_close(&e);

    /* R9: a journal FAULT is 503 "the faucet journal is unavailable", never
     * a 200. The fault: the -wal path cannot be stat()ed (a symlink loop),
     * which the storage measure reports as -1 (as in the journal's J10). */
    {
        env_t f;
        env_open(&f, 64ULL << 20);
        char wal[128];
        snprintf(wal, sizeof(wal), "%s-wal", f.jpath);
        unlink(wal);
        CHECK(symlink("journal.db-wal", wal) == 0, "R9 (setup) a -wal path that cannot be stat()ed");
        route(&f, "GET", "/faucet/status", NULL, &status, out, sizeof(out));
        CHECK(status == 503 && strstr(out, "the faucet journal is unavailable") &&
              strstr(out, "\"state\":\"refused\""),
              "R9 GET /faucet/status on a journal fault is 503 unavailable");
        unlink(wal);
        env_close(&f);
    }
}

/* ── the real server ────────────────────────────────────────────────── */

static int cli_connect(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Drive the server until the client socket is readable or `rounds` polls
 * passed, then read until EOF. @return bytes read (0 = nothing came). */
static int await_response(faucet_http_t *h, int fd, char *buf, size_t cap, int rounds, int round_ms) {
    for (int i = 0; i < rounds; i++) {
        faucet_http_poll(h, round_ms);
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 0) > 0) break;
    }
    size_t n = 0;
    for (;;) {
        ssize_t r = recv(fd, buf + n, cap - 1 - n, 0);
        if (r <= 0) break;
        n += (size_t)r;
    }
    buf[n] = '\0';
    return (int)n;
}

static void handler_cb(void *ctx, const faucet_http_req_t *req, uint64_t deadline_ms,
                       int *status, char *body, size_t cap) {
    faucet_http_route((faucet_core_t *)ctx, req, deadline_ms, status, body, cap);
}

static void test_server(void) {
    env_t e;
    env_open(&e, 64ULL << 20);
    e.st.name_found = 0;
    e.st.bal_native = 0;
    faucet_http_t *h = NULL;
    uint16_t port = 0;
    CHECK(faucet_http_open(0, 2, 300, handler_cb, &e.core, &h, &port) == 0 && port != 0,
          "V0 the server listens on a kernel-chosen loopback port");
    char buf[4096];

    int fd = cli_connect(port);
    const char *get = "GET /faucet/status HTTP/1.1\r\nHost: x\r\n\r\n";
    send(fd, get, strlen(get), 0);
    int n = await_response(h, fd, buf, sizeof(buf), 20, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 200 OK", 15) && strstr(buf, "Connection: close") &&
          strstr(buf, "Content-Type: application/json") && strstr(buf, "\"open\":true"),
          "V1 GET /faucet/status over a real socket");
    close(fd);

    char addr[129], req[600];
    make_addr(addr, 5);
    char body[200];
    snprintf(body, sizeof(body), "{\"address\":\"%s\"}", addr);
    snprintf(req, sizeof(req), "POST /faucet/claim HTTP/1.1\r\nContent-Length: %zu\r\n\r\n%s",
             strlen(body), body);
    fd = cli_connect(port);
    send(fd, req, strlen(req), 0);
    n = await_response(h, fd, buf, sizeof(buf), 20, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 200 OK", 15) && strstr(buf, "\"kind\":\"start\""),
          "V2 POST /faucet/claim over a real socket");
    close(fd);

    /* split across two sends */
    fd = cli_connect(port);
    send(fd, req, 20, 0);
    faucet_http_poll(h, 25);                   /* accepts */
    faucet_http_poll(h, 25);                   /* reads 20 bytes: asks for more */
    send(fd, req + 20, strlen(req) - 20, 0);
    n = await_response(h, fd, buf, sizeof(buf), 20, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 200 OK", 15), "V3 a request split across reads is served");
    close(fd);

    /* oversized body: refused from the header alone */
    fd = cli_connect(port);
    const char *big = "POST /faucet/claim HTTP/1.1\r\nContent-Length: 5000\r\n\r\n";
    send(fd, big, strlen(big), 0);
    n = await_response(h, fd, buf, sizeof(buf), 20, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 413", 12), "V4 an oversized body is answered 413 without waiting for it");
    close(fd);

    /* a slow client: the deadline (300 ms) answers 408 and closes */
    fd = cli_connect(port);
    send(fd, "GET /faucet/st", 14, 0);
    n = await_response(h, fd, buf, sizeof(buf), 40, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 408", 12), "V5 a client that never finishes gets 408 at the deadline");
    close(fd);
    for (int i = 0; i < 4; i++) faucet_http_poll(h, 10);
    CHECK(faucet_http_connections(h) == 0, "V5 the connection slot is released");

    /* connection cap 2: two idle clients hold the slots, the third gets 503 */
    int c1 = cli_connect(port), c2 = cli_connect(port);
    for (int i = 0; i < 4; i++) faucet_http_poll(h, 10);
    int c3 = cli_connect(port);
    n = await_response(h, c3, buf, sizeof(buf), 20, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 503", 12), "V6 the connection cap answers 503 to the third client");
    CHECK(faucet_http_connections(h) <= 2, "V6 the open connections never exceed the cap");
    close(c3); close(c2); close(c1);

    /* Transfer-Encoding */
    for (int i = 0; i < 8; i++) faucet_http_poll(h, 10);
    fd = cli_connect(port);
    const char *te = "POST /faucet/claim HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    send(fd, te, strlen(te), 0);
    n = await_response(h, fd, buf, sizeof(buf), 20, 25);
    CHECK(n > 0 && !strncmp(buf, "HTTP/1.1 501", 12), "V7 Transfer-Encoding is answered 501");
    close(fd);

    /* V8: an answer the socket takes only in pieces is finished through
     * POLLOUT — 16 bytes leave per flush (the test seam), so the whole answer
     * needs many polls, and arrives complete and intact */
    for (int i = 0; i < 8; i++) faucet_http_poll(h, 10);
    faucet_http_set_max_send_chunk(16);
    fd = cli_connect(port);
    send(fd, get, strlen(get), 0);
    size_t got = 0;
    int rounds = 0, eof = 0;
    while (!eof && rounds < 2000) {
        faucet_http_poll(h, 10);
        rounds++;
        for (;;) {
            ssize_t r = recv(fd, buf + got, sizeof(buf) - 1 - got, MSG_DONTWAIT);
            if (r > 0) { got += (size_t)r; continue; }
            if (r == 0) eof = 1;
            break;
        }
    }
    buf[got] = '\0';
    faucet_http_set_max_send_chunk(0);
    size_t clen = 0;
    const char *cl_h = strstr(buf, "Content-Length: ");
    const char *body_at = strstr(buf, "\r\n\r\n");
    if (cl_h) clen = (size_t)strtoul(cl_h + 16, NULL, 10);
    CHECK(eof && !strncmp(buf, "HTTP/1.1 200 OK", 15) && body_at && cl_h &&
          strlen(body_at + 4) == clen && clen > 0 && buf[got - 1] == '}',
          "V8 a partially written answer is completed through POLLOUT, whole and intact");
    CHECK(rounds > (int)(got / 16) / 2, "V8 it really took many flushes (one chunk each)");
    close(fd);
    for (int i = 0; i < 4; i++) faucet_http_poll(h, 10);
    CHECK(faucet_http_connections(h) == 0, "V8 the connection slot is released after the answer");

    faucet_http_close(h);
    env_close(&e);
}

int main(void) {
    printf("test_faucet_http\n");
    test_parser();
    test_json();
    test_routes();
    test_server();
    free(g_id);
    printf("%s (%d checks, %d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
