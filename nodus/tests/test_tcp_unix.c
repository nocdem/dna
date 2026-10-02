/**
 * Nodus — TCP transport, Unix domain socket entry
 *
 * Component split S2 (decision docs/plans/decisions/2026-10-01-nodus-
 * component-split.md item 7: IPC = Unix domain socket, mode 0600, the
 * connecting process checked with SO_PEERCRED). Proves:
 *   - the socket file is a socket with mode exactly 0600, even when the
 *     process umask is 0 (the transport, not the caller's umask, decides);
 *   - a frame round-trips both ways over nodus_tcp_unix_listen /
 *     nodus_tcp_unix_connect, and both ends are marked is_unix with the
 *     NODUS_TCP_UNIX_PEER_IP label and port 0; the accepted end records
 *     the peer's SO_PEERCRED uid/pid;
 *   - a peer whose uid is not the allowed uid is closed before a
 *     connection is allocated (on_accept never runs). An unprivileged test
 *     cannot connect from a second uid, so this runs the REAL accept path
 *     with the listener configured to allow geteuid()+1 — the same-process
 *     peer is then the "wrong uid". The decision function itself is also
 *     tested with injected credentials (nodus_tcp_unix_peercred_ok);
 *   - a regular file at the path is refused and left untouched; a stale
 *     socket file is replaced; a live listener's socket is refused and the
 *     live listener keeps working; a too-long path is refused;
 *   - nodus_tcp_close removes the socket file it created.
 *
 * Requires: a default build; no environment. Uses a mkdtemp directory under
 * /tmp and leaves nothing behind (directory removed at the end).
 * How it can lie: the poll loops are bounded; a loop that ends without its
 * event FAILs the case (it never passes on a timeout).
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp under -std=c11 */

#include "transport/nodus_tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static char g_dir[64];

/* Shared callback state */
static int accepted_count = 0;
static int connected_count = 0;
static int disconnected_count = 0;
static int frame_count = 0;
static uint8_t received_payload[256];
static size_t received_len = 0;
static nodus_tcp_conn_t *last_accepted = NULL;
static nodus_tcp_conn_t *last_frame_conn = NULL;

static void on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    accepted_count++;
    last_accepted = conn;
}

static void on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    connected_count++;
}

static void on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    disconnected_count++;
}

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                     size_t len, void *ctx) {
    (void)ctx;
    if (len <= sizeof(received_payload)) {
        memcpy(received_payload, payload, len);
        received_len = len;
    }
    last_frame_conn = conn;
    frame_count++;
}

static void reset_counters(void) {
    accepted_count = 0;
    connected_count = 0;
    disconnected_count = 0;
    frame_count = 0;
    received_len = 0;
    last_accepted = NULL;
    last_frame_conn = NULL;
    memset(received_payload, 0, sizeof(received_payload));
}

static void sock_path(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "%s/%s", g_dir, name);
}

static void setup_pair(nodus_tcp_t *server, nodus_tcp_t *client) {
    nodus_tcp_init(server, -1);
    nodus_tcp_init(client, -1);
    server->on_accept = on_accept;
    server->on_frame = on_frame;
    server->on_disconnect = on_disconnect;
    client->on_connect = on_connect;
    client->on_frame = on_frame;
    client->on_disconnect = on_disconnect;
}

/* Poll both transports until *counter reaches want (bounded). */
static void poll_until(nodus_tcp_t *a, nodus_tcp_t *b, const int *counter, int want) {
    for (int i = 0; i < 200 && *counter < want; i++) {
        nodus_tcp_poll(a, 10);
        nodus_tcp_poll(b, 10);
    }
}

static void test_peercred_decision(void) {
    TEST("peercred decision with injected credentials");
    bool same    = nodus_tcp_unix_peercred_ok(1000, 1000);
    bool root    = nodus_tcp_unix_peercred_ok(0, 0);
    bool other   = nodus_tcp_unix_peercred_ok(1001, 1000);
    bool root_in = nodus_tcp_unix_peercred_ok(0, 1000);
    bool self    = nodus_tcp_unix_peercred_ok(NODUS_TCP_UNIX_UID_SELF,
                                              NODUS_TCP_UNIX_UID_SELF);
    if (same && root && !other && !root_in && !self)
        PASS();
    else
        FAIL("wrong admission decision");
}

static void test_mode_0600(void) {
    TEST("socket file is a socket with mode 0600 (umask 0)");
    char path[128];
    sock_path(path, sizeof(path), "m.sock");

    mode_t old = umask(0);   /* worst case: would give 0777 if not forced */
    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    int rc = nodus_tcp_unix_listen(&tcp, path, NODUS_TCP_UNIX_UID_SELF);
    umask(old);

    struct stat st;
    int st_rc = lstat(path, &st);
    bool ok = rc == 0 && st_rc == 0 && S_ISSOCK(st.st_mode) &&
              (st.st_mode & 07777) == 0600 &&
              tcp.unix_allowed_uid == (uint32_t)geteuid();
    nodus_tcp_close(&tcp);
    if (ok) PASS();
    else    FAIL("socket missing, not a socket, mode != 0600 or uid not resolved");
}

static void test_roundtrip(void) {
    TEST("frame round-trip client->server->client over AF_UNIX");
    reset_counters();
    char path[128];
    sock_path(path, sizeof(path), "r.sock");

    nodus_tcp_t server, client;
    setup_pair(&server, &client);
    if (nodus_tcp_unix_listen(&server, path, NODUS_TCP_UNIX_UID_SELF) != 0) {
        FAIL("listen failed");
        nodus_tcp_close(&client);
        nodus_tcp_close(&server);
        return;
    }

    nodus_tcp_conn_t *cc = nodus_tcp_unix_connect(&client, path);
    bool client_ok = cc && cc->state == NODUS_CONN_CONNECTED && cc->is_unix &&
                     cc->port == 0 && strcmp(cc->ip, NODUS_TCP_UNIX_PEER_IP) == 0 &&
                     connected_count == 1 && cc->auth_initiated_by_us;

    poll_until(&server, &client, &accepted_count, 1);
    nodus_tcp_conn_t *sc = last_accepted;
    bool server_ok = accepted_count == 1 && sc && sc->is_unix && sc->port == 0 &&
                     strcmp(sc->ip, NODUS_TCP_UNIX_PEER_IP) == 0 &&
                     sc->peer_cred_set && sc->peer_uid == (uint32_t)geteuid() &&
                     sc->peer_pid == (int32_t)getpid() &&
                     !sc->channel_crypto.established;

    bool up_ok = false, down_ok = false;
    if (client_ok && server_ok) {
        const uint8_t up[] = "ipc up";
        nodus_tcp_send(cc, up, sizeof(up) - 1);
        poll_until(&client, &server, &frame_count, 1);
        up_ok = frame_count == 1 && last_frame_conn == sc &&
                received_len == sizeof(up) - 1 &&
                memcmp(received_payload, up, sizeof(up) - 1) == 0;

        const uint8_t down[] = "ipc down";
        nodus_tcp_send(sc, down, sizeof(down) - 1);
        poll_until(&server, &client, &frame_count, 2);
        down_ok = frame_count == 2 && last_frame_conn == cc &&
                  received_len == sizeof(down) - 1 &&
                  memcmp(received_payload, down, sizeof(down) - 1) == 0;
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
    if (!client_ok)      FAIL("client conn not connected/is_unix/labelled");
    else if (!server_ok) FAIL("accepted conn wrong (is_unix/label/peercred/plaintext)");
    else if (!up_ok)     FAIL("client->server frame not received");
    else if (!down_ok)   FAIL("server->client frame not received");
    else                 PASS();
}

static void test_wrong_uid_rejected(void) {
    TEST("peer with a uid other than the allowed one is closed");
    reset_counters();
    char path[128];
    sock_path(path, sizeof(path), "u.sock");

    nodus_tcp_t server, client;
    setup_pair(&server, &client);
    uint32_t other_uid = (uint32_t)geteuid() + 1u;
    if (nodus_tcp_unix_listen(&server, path, other_uid) != 0) {
        FAIL("listen failed");
        nodus_tcp_close(&client);
        nodus_tcp_close(&server);
        return;
    }

    /* The kernel completes the connect (it is queued on the backlog); the
     * refusal happens at accept, on the server's poll. */
    nodus_tcp_conn_t *cc = nodus_tcp_unix_connect(&client, path);
    if (!cc) {
        FAIL("client connect failed before the uid check could run");
        nodus_tcp_close(&client);
        nodus_tcp_close(&server);
        return;
    }
    poll_until(&server, &client, &disconnected_count, 1);

    bool ok = accepted_count == 0 && server.count == 0 &&
              disconnected_count == 1 && client.count == 0;
    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
    if (ok) PASS();
    else    FAIL("wrong-uid peer was accepted or not closed");
}

static void test_regular_file_refused(void) {
    TEST("regular file at the path is refused and untouched");
    char path[128];
    sock_path(path, sizeof(path), "f.sock");
    FILE *f = fopen(path, "wb");
    if (!f) { FAIL("cannot create fixture file"); return; }
    fputs("data", f);
    fclose(f);
    struct stat before;
    lstat(path, &before);

    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    int rc = nodus_tcp_unix_listen(&tcp, path, NODUS_TCP_UNIX_UID_SELF);
    nodus_tcp_close(&tcp);

    struct stat after;
    int st_rc = lstat(path, &after);
    bool ok = rc == -1 && st_rc == 0 && S_ISREG(after.st_mode) &&
              after.st_ino == before.st_ino && after.st_size == 4;
    unlink(path);
    if (ok) PASS();
    else    FAIL("listen did not refuse, or the file was changed");
}

static void test_stale_socket_replaced(void) {
    TEST("stale socket file (no listener) is replaced");
    char path[128];
    sock_path(path, sizeof(path), "s.sock");

    /* Leave a socket file behind with nobody listening on it. */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    int brc = (fd >= 0) ? bind(fd, (struct sockaddr *)&sa, sizeof(sa)) : -1;
    if (fd >= 0) close(fd);
    struct stat stale;
    if (brc != 0 || lstat(path, &stale) != 0) {
        FAIL("cannot create stale socket fixture");
        unlink(path);
        return;
    }

    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    int rc = nodus_tcp_unix_listen(&tcp, path, NODUS_TCP_UNIX_UID_SELF);
    struct stat now;
    int st_rc = lstat(path, &now);
    bool ok = rc == 0 && st_rc == 0 && S_ISSOCK(now.st_mode) &&
              (now.st_mode & 07777) == 0600 &&
              (uint64_t)now.st_ino == tcp.unix_ino;
    nodus_tcp_close(&tcp);
    if (ok) PASS();
    else    FAIL("stale socket not replaced by a fresh 0600 listener");
}

static void test_live_listener_kept(void) {
    TEST("live listener's socket is refused, live listener unaffected");
    reset_counters();
    char path[128];
    sock_path(path, sizeof(path), "l.sock");

    nodus_tcp_t server, client, second;
    setup_pair(&server, &client);
    nodus_tcp_init(&second, -1);
    int rc1 = nodus_tcp_unix_listen(&server, path, NODUS_TCP_UNIX_UID_SELF);
    int rc2 = nodus_tcp_unix_listen(&second, path, NODUS_TCP_UNIX_UID_SELF);
    nodus_tcp_close(&second);   /* never bound: must not remove server's file */

    /* The second listen's liveness probe is itself a connection to the
     * live listener (connect, then close at once), which the server may
     * accept and then see close — so the accept count is not asserted
     * exactly. What is asserted: the live listener still serves cc. */
    nodus_tcp_conn_t *cc = nodus_tcp_unix_connect(&client, path);
    bool frame_ok = false;
    if (cc) {
        const uint8_t msg[] = "still alive";
        nodus_tcp_send(cc, msg, sizeof(msg) - 1);
        poll_until(&client, &server, &frame_count, 1);
        frame_ok = frame_count == 1 && received_len == sizeof(msg) - 1 &&
                   memcmp(received_payload, msg, sizeof(msg) - 1) == 0 &&
                   last_frame_conn != NULL && last_frame_conn->is_unix;
    }
    bool ok = rc1 == 0 && rc2 == -1 && cc != NULL && accepted_count >= 1 && frame_ok;

    /* A second listen on the SAME transport is refused too. */
    char other[128];
    sock_path(other, sizeof(other), "l2.sock");
    bool again_refused = nodus_tcp_unix_listen(&server, other, NODUS_TCP_UNIX_UID_SELF) == -1;
    struct stat st;
    bool other_absent = lstat(other, &st) != 0 && errno == ENOENT;

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
    if (!ok)                 FAIL("live socket replaced or live listener broken");
    else if (!again_refused) FAIL("second listen on one transport accepted");
    else if (!other_absent)  FAIL("refused second listen created a file");
    else                     PASS();
}

static void test_bad_paths(void) {
    TEST("too-long / missing path refused, nothing allocated");
    char longp[200];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[0] = '/';
    longp[sizeof(longp) - 1] = '\0';

    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    int lrc = nodus_tcp_unix_listen(&tcp, longp, NODUS_TCP_UNIX_UID_SELF);
    nodus_tcp_conn_t *c1 = nodus_tcp_unix_connect(&tcp, longp);

    char missing[128];
    sock_path(missing, sizeof(missing), "none.sock");
    nodus_tcp_conn_t *c2 = nodus_tcp_unix_connect(&tcp, missing);

    bool ok = lrc == -1 && c1 == NULL && c2 == NULL && tcp.count == 0 &&
              tcp.unix_listen_fd == -1;
    nodus_tcp_close(&tcp);
    if (ok) PASS();
    else    FAIL("bad path accepted or a connection leaked");
}

static void test_close_unlinks(void) {
    TEST("nodus_tcp_close removes the socket file it created");
    char path[128];
    sock_path(path, sizeof(path), "c.sock");
    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    int rc = nodus_tcp_unix_listen(&tcp, path, NODUS_TCP_UNIX_UID_SELF);
    struct stat st;
    bool present = lstat(path, &st) == 0;
    nodus_tcp_close(&tcp);
    bool gone = lstat(path, &st) != 0 && errno == ENOENT;
    if (rc == 0 && present && gone && tcp.unix_listen_fd == -1) PASS();
    else FAIL("socket file not removed on close");
}

int main(void) {
    printf("=== Nodus TCP Unix-socket Tests ===\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/ntu_XXXXXX");
    if (!mkdtemp(g_dir)) {
        printf("cannot create temp dir\n");
        return 1;
    }

    test_peercred_decision();
    test_mode_0600();
    test_roundtrip();
    test_wrong_uid_rejected();
    test_regular_file_refused();
    test_stale_socket_replaced();
    test_live_listener_kept();
    test_bad_paths();
    test_close_unlinks();

    if (rmdir(g_dir) != 0)
        printf("warning: %s not empty after tests\n", g_dir);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
