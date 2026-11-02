/**
 * Nodus — Client SDK trusted node list + monotonic timeout tests
 *
 * REWRITTEN for the 4001 secret connection (approved 4001 plan 4.2, build-
 * order step 7). The AUTH_OK pinning cases (unsigned kpk, cached key, Kyber
 * round-3 fallback, mpk stripping: the former W1-W6 / C1 / C2) tested a
 * handshake that no longer exists; their subject is gone. What replaces them:
 * the responder's key must hash to a fingerprint in the client's trusted list
 * (design D3/D4) or the client aborts at the key exchange.
 *
 * Governing: docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md
 * ("Sunucu doğrulama"), docs/plans/approved/2026-10-28-encrypted-sessions.md
 * (D3, D4, A3), plan docs/plans/approved/2026-11-02-4001-ws-session-build-plan.md.
 *
 * What it proves — nodus_client_config_t.pinned_server_fps + chain_id:
 *   P1  init refuses: no list (count 0 / NULL pointer), a negative count, and
 *       a config without a chain id.
 *   P2  real nodus_server_t (fake chain backend, test chain id), list = its
 *       fingerprint → READY over the secret connection, server_dil_pk is that
 *       server's key.
 *   P2b the matching fingerprint is not the first list entry → READY.
 *   P3  real server, list holding only OTHER fingerprints → refused (never
 *       READY).
 *   P4  real server, right list but a chain id that differs by one byte →
 *       refused.
 *   T1  nodus_time_mono_ms() never goes back and advances at least as far as
 *       a sleep.
 *   T2  a peer that accepts TCP and never answers: the connect fails and at
 *       least connect_timeout_ms of MONOTONIC time passed (the wait for the
 *       session to open). Lower bound only — no upper bound is asserted (a
 *       timing assertion that fails under load; CLAUDE.md DETERMINISM).
 *
 * Compile flags: none. Environment: none. Ports: real server 15400-15404
 * (test-unique, see the parallel-safety note in nodus/CMakeLists.txt); the
 * silent peer listens on 127.0.0.1:0. Data dir /tmp/nodus_client_pin_test_<pid>,
 * removed at the end. Leaves nothing behind (server thread joined).
 *
 * How it can lie:
 *   - P3/P4 prove the refusal, not WHICH check refused; the reason is in the
 *     client's log. P2 above P3 (same server, same chain) is the control: a
 *     broken server would fail P2 too.
 *   - T2 cannot step the wall clock (needs root); it proves the wait lasted
 *     its full limit on the monotonic clock.
 *   - Native build only: the __EMSCRIPTEN__ branches are compiled by
 *     web-wallet/scripts/check-nodus-client-wasm.sh, not run here.
 */

#include "nodus/nodus.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_identity.h"
#include "nodus_test_session.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int passed, failed;
#define CHECK(cond, name) do { \
    if (cond) { passed++; printf("  PASS %s\n", name); } \
    else { failed++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

/* ── the real node ─────────────────────────────────────────────── */
static nodus_server_t g_server;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static bool g_done, g_ready;
static char g_dir[128];

static void *server_thread(void *arg) {
    (void)arg;
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port = 15400; config.tcp_port = 15401; config.peer_port = 15402;
    config.ch_port = 15403; config.witness_port = 15404;
    config.require_peer_auth = true;
    snprintf(config.data_path, sizeof(config.data_path), "%s", g_dir);
    nodus_server_backends_t be;
    nts_fake_chain_be(&be);
    bool ok = nodus_server_init_ex(&g_server, &config, &be) == 0;
    pthread_mutex_lock(&g_lock);
    g_ready = ok; g_done = true;
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);
    if (!ok) return NULL;
    nodus_server_run(&g_server);
    nodus_server_close(&g_server);
    return NULL;
}

static void client_cfg(nodus_client_config_t *cfg, uint16_t port,
                       const nodus_key_t *list, int count) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->servers[0].ip, sizeof(cfg->servers[0].ip), "127.0.0.1");
    cfg->servers[0].port = port;
    cfg->server_count = 1;
    cfg->connect_timeout_ms = 3000;
    cfg->pinned_server_fps = list;
    cfg->pinned_server_fp_count = count;
    memcpy(cfg->chain_id, NODUS_TEST_CHAIN, 32);
    cfg->has_chain_id = true;
}

/* init + connect; true when the client became READY */
static bool try_client(const nodus_client_config_t *cfg, nodus_identity_t *id,
                       bool *server_key_matches) {
    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) return false;
    bool ok = nodus_client_init(c, cfg, id) == 0 &&
              nodus_client_connect(c) == 0 && nodus_client_is_ready(c);
    if (server_key_matches)
        *server_key_matches = ok && c->has_server_dil_pk &&
            memcmp(c->server_dil_pk.bytes, g_server.identity.pk.bytes, NODUS_PK_BYTES) == 0;
    nodus_client_close(c);
    free(c);
    return ok;
}

int main(void) {
    printf("=== client trusted list / chain id / monotonic timeouts ===\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/nodus_client_pin_test_%d", (int)getpid());
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", g_dir);
    if (system(cmd) != 0) return 1;

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_thread, NULL) != 0) return 1;
    pthread_mutex_lock(&g_lock);
    while (!g_done) pthread_cond_wait(&g_cond, &g_lock);
    bool ready = g_ready;
    pthread_mutex_unlock(&g_lock);
    if (!ready) { printf("FATAL: server did not start\n"); return 1; }

    nodus_identity_t *id = calloc(1, sizeof(*id));
    nodus_identity_t *other = calloc(1, sizeof(*other));
    if (!id || !other || nodus_identity_generate(id) != 0 ||
        nodus_identity_generate(other) != 0) return 1;
    nodus_key_t own[1] = {g_server.identity.node_id};
    nodus_key_t others[1] = {other->node_id};
    nodus_key_t second[2] = {other->node_id, g_server.identity.node_id};

    /* P1 */
    {
        nodus_client_t *c = calloc(1, sizeof(*c));
        nodus_client_config_t cfg;
        client_cfg(&cfg, 15401, own, 0);
        CHECK(nodus_client_init(c, &cfg, id) != 0, "P1 count 0 refused");
        client_cfg(&cfg, 15401, NULL, 1);
        CHECK(nodus_client_init(c, &cfg, id) != 0, "P1 NULL list refused");
        client_cfg(&cfg, 15401, own, -1);
        CHECK(nodus_client_init(c, &cfg, id) != 0, "P1 negative count refused");
        client_cfg(&cfg, 15401, own, 1); cfg.has_chain_id = false;
        CHECK(nodus_client_init(c, &cfg, id) != 0, "P1 no chain id refused");
        free(c);
    }

    nodus_client_config_t cfg;
    bool key_ok = false;
    client_cfg(&cfg, 15401, own, 1);
    CHECK(try_client(&cfg, id, &key_ok) && key_ok, "P2 listed node -> READY, server key reported");
    client_cfg(&cfg, 15401, second, 2);
    CHECK(try_client(&cfg, id, NULL), "P2b matching entry is the second one -> READY");
    client_cfg(&cfg, 15401, others, 1);
    CHECK(!try_client(&cfg, id, NULL), "P3 list without the node -> refused");
    client_cfg(&cfg, 15401, own, 1); cfg.chain_id[31] ^= 1;
    CHECK(!try_client(&cfg, id, NULL), "P4 chain id one byte off -> refused");

    /* T1 */
    {
        uint64_t a = nodus_time_mono_ms();
        struct timespec ts = {0, 50 * 1000000L};
        nanosleep(&ts, NULL);
        uint64_t b = nodus_time_mono_ms();
        CHECK(b >= a && b - a >= 40, "T1 monotonic clock advances over a sleep");
    }

    /* T2: a peer that accepts and never answers */
    {
        int lf = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t sl = sizeof(sa);
        bool up = lf >= 0 && bind(lf, (struct sockaddr *)&sa, sizeof(sa)) == 0 &&
                  listen(lf, 4) == 0 && getsockname(lf, (struct sockaddr *)&sa, &sl) == 0;
        if (up) {
            client_cfg(&cfg, ntohs(sa.sin_port), own, 1);
            cfg.connect_timeout_ms = 1200;
            uint64_t t0 = nodus_time_mono_ms();
            bool ok = try_client(&cfg, id, NULL);
            uint64_t dt = nodus_time_mono_ms() - t0;
            CHECK(!ok && dt >= 1200, "T2 silent peer: connect fails after >= connect_timeout_ms (monotonic)");
        } else CHECK(false, "T2 silent peer setup");
        if (lf >= 0) close(lf);
    }

    nodus_server_stop(&g_server);
    pthread_join(tid, NULL);
    nodus_identity_clear(id); free(id);
    nodus_identity_clear(other); free(other);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) printf("cleanup failed\n");
    printf("=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
