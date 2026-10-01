/**
 * Concurrent sends on one nodus_client against its own read thread.
 *
 * What it proves: every request a caller hands to nodus_client reaches the
 * node EXACTLY ONCE while the client's read thread is polling the same
 * connection. Before the transport's write lock (nodus_tcp_set_write_lock)
 * a caller's nodus_tcp_send and the read thread's write drain both flushed
 * the same wbuf range with no common lock: the same frame left the socket
 * twice (the node answered twice, the second answer logged "unknown txn"),
 * and a realloc under the other thread's write crashed the process. Found by
 * the Nodus Connect fault matrix under load (nodus/BUGS.md).
 *
 * How: a fake node (nodus_tcp on its own thread) answers hello / auth / put
 * and counts every PUT by its txn id. SENDERS threads each issue PUTS large
 * PUTs (PAYLOAD bytes — far above one write(2), so the read thread's drain
 * gets work) through one connected client. Every put must return 0, every
 * txn must arrive exactly once, and the total must be SENDERS * PUTS.
 *
 * Requires: a default build; no environment. Leaves nothing behind (one
 * loopback port, closed at exit).
 * How it can lie: the race needs the drain and a send to overlap; on an idle
 * machine with an enormous socket buffer one run could pass on the old code
 * too. ROUNDS repeats the whole burst so the window is crossed many times;
 * the old code failed every run under the Connect fault matrix's load.
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SENDERS   4
#define PUTS      16
#define ROUNDS    4
#define PAYLOAD   (192 * 1024)
#define MAX_TXN   4096
#define FAKE_BUF  4096

static int g_pass, g_fail;
#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  PASS %s\n", name); } \
    else { g_fail++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static struct {
    nodus_tcp_t  *tcp;
    uint8_t      *buf;
    pthread_t     tid;
    atomic_bool   stop;
    atomic_int    seen[MAX_TXN];
    atomic_int    puts;
    atomic_int    out_of_range;
} g_fake;

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                     size_t len, void *ctx) {
    (void)ctx;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) { nodus_t2_msg_free(&msg); return; }
    size_t out = 0;
    if (strcmp(msg.method, "hello") == 0) {
        uint8_t nonce[NODUS_NONCE_LEN];
        nodus_random(nonce, NODUS_NONCE_LEN);
        if (nodus_t2_challenge(msg.txn_id, nonce, g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "auth") == 0) {
        uint8_t token[NODUS_SESSION_TOKEN_LEN];
        memset(token, 0x5a, sizeof(token));
        if (nodus_t2_auth_ok(msg.txn_id, token, g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "put") == 0) {
        atomic_fetch_add(&g_fake.puts, 1);
        if (msg.txn_id < MAX_TXN) atomic_fetch_add(&g_fake.seen[msg.txn_id], 1);
        else atomic_fetch_add(&g_fake.out_of_range, 1);
        if (nodus_t2_put_ok(msg.txn_id, g_fake.buf, FAKE_BUF, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    }
    nodus_t2_msg_free(&msg);
}

static void *fake_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_fake.stop)) nodus_tcp_poll(g_fake.tcp, 20);
    return NULL;
}

typedef struct {
    nodus_client_t *client;
    int             failures;
} sender_t;

static void *sender_fn(void *arg) {
    sender_t *s = (sender_t *)arg;
    uint8_t *data = malloc(PAYLOAD);
    if (!data) { s->failures = PUTS; return NULL; }
    nodus_key_t key;
    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    for (int i = 0; i < PUTS; i++) {
        memset(data, (int)(i & 0xff), PAYLOAD);
        memset(&key, (int)(i + 1), sizeof(key));
        if (nodus_client_put_ex(s->client, &key, data, PAYLOAD,
                                NODUS_VALUE_EPHEMERAL, 60, 1, (uint64_t)i + 1,
                                &sig, 0) != 0)
            s->failures++;
    }
    free(data);
    return NULL;
}

int main(void) {
    printf("=== client concurrent send vs read-thread drain ===\n");

    g_fake.tcp = calloc(1, sizeof(nodus_tcp_t));
    g_fake.buf = malloc(FAKE_BUF);
    if (!g_fake.tcp || !g_fake.buf || nodus_tcp_init(g_fake.tcp, -1) != 0) {
        printf("FATAL: fake node\n");
        return 1;
    }
    g_fake.tcp->on_frame = on_frame;
    if (nodus_tcp_listen(g_fake.tcp, "127.0.0.1", 0) != 0 ||
        pthread_create(&g_fake.tid, NULL, fake_thread, NULL) != 0) {
        printf("FATAL: fake node listen\n");
        return 1;
    }

    nodus_identity_t *id = calloc(1, sizeof(*id));
    nodus_client_t *client = calloc(1, sizeof(*client));
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = g_fake.tcp->port;
    cfg.server_count = 1;
    cfg.connect_timeout_ms = 3000;
    cfg.request_timeout_ms = 20000;
    if (!id || !client || nodus_identity_generate(id) != 0 ||
        nodus_client_init(client, &cfg, id) != 0 ||
        nodus_client_connect(client) != 0 || !nodus_client_is_ready(client)) {
        printf("FATAL: client did not connect to the fake node\n");
        return 1;
    }

    int failures = 0;
    for (int r = 0; r < ROUNDS; r++) {
        pthread_t th[SENDERS];
        sender_t st[SENDERS];
        for (int i = 0; i < SENDERS; i++) {
            st[i].client = client;
            st[i].failures = 0;
            if (pthread_create(&th[i], NULL, sender_fn, &st[i]) != 0) {
                printf("FATAL: sender thread\n");
                return 1;
            }
        }
        for (int i = 0; i < SENDERS; i++) {
            pthread_join(th[i], NULL);
            failures += st[i].failures;
        }
    }

    int total = SENDERS * PUTS * ROUNDS;
    int dup = 0, missing = 0;
    /* txn ids start after hello (1) and auth (2); every put gets its own */
    int seen_total = 0;
    for (int t = 0; t < MAX_TXN; t++) {
        int c = atomic_load(&g_fake.seen[t]);
        if (c > 1) dup++;
        seen_total += c > 0 ? 1 : 0;
    }
    missing = total - seen_total;

    CHECK(failures == 0, "every PUT returned 0 (its reply arrived)");
    CHECK(atomic_load(&g_fake.out_of_range) == 0, "every txn id within the counted range");
    CHECK(dup == 0, "no PUT reached the node twice");
    CHECK(missing == 0, "every PUT reached the node");
    CHECK(atomic_load(&g_fake.puts) == total, "frames received == PUTs sent");
    printf("  [info] sent=%d received=%d distinct=%d duplicated_txns=%d failures=%d\n",
           total, atomic_load(&g_fake.puts), seen_total, dup, failures);

    nodus_client_close(client);
    free(client);
    nodus_identity_clear(id);
    free(id);
    atomic_store(&g_fake.stop, true);
    pthread_join(g_fake.tid, NULL);
    nodus_tcp_close(g_fake.tcp);
    free(g_fake.tcp);
    free(g_fake.buf);

    printf("=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
