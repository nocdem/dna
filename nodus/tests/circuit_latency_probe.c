/**
 * Nodus — Circuit Latency Probe (PQ-VoIP Faz 0, netem characterization)
 *
 * NOT a ctest. A manual measurement harness for the council's 2nd kill-criterion:
 * how does the existing TCP circuit relay behave for a paced real-time audio
 * stream under emulated packet loss / jitter?
 *
 * Two in-process nodus servers on 127.0.0.1 (same topology as
 * test_circuit_cross_live). User1 on server A opens an E2E circuit to User2 on
 * server B, then sends N small frames (≈one 20 ms Opus frame) at a fixed
 * interval. Each frame carries [seq, send-timestamp]; the receiver stamps
 * arrival with the same CLOCK_MONOTONIC, so true ONE-WAY latency is measured
 * (both endpoints share this process's clock).
 *
 * Run it INSIDE a network namespace with netem on that namespace's own `lo`
 * (see tests/run_circuit_netem.sh) so the host loopback is untouched. Over TCP,
 * emulated loss surfaces as latency spikes (head-of-line blocking), not dropped
 * frames — so the p95 / max one-way latency, not frame loss, is the signal.
 *
 * KILL-CRITERION (pre-registered): p95 one-way > 250 ms ⇒ TCP-MVP is not viable,
 * promote the UDP fast path (Faz C) ahead of libopus MVP work.
 */

#include "server/nodus_server.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include "consensus/nodus_cluster.h"
#include "core/nodus_routing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

/* ── Probe parameters (env-overridable) ─────────────────────────── */
#define DEF_FRAMES      500      /* number of frames to send                */
#define DEF_INTERVAL_MS 20       /* pacing: one 20 ms Opus frame per tick    */
#define DEF_FRAME_BYTES 160      /* ≈ Opus 20 ms @ ~64 kbps                   */
#define KILL_P95_MS     250      /* pre-registered kill threshold            */
#define MAX_FRAMES      20000

static long env_long(const char *k, long dflt) {
    const char *v = getenv(k);
    if (!v || !*v) return dflt;
    long n = strtol(v, NULL, 10);
    return n > 0 ? n : dflt;
}
static uint64_t now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

/* ── Server threads (mirror test_circuit_cross_live) ────────────── */
static nodus_server_t srv_a, srv_b;
static volatile bool srv_a_ready = false, srv_b_ready = false;

static void *srv_a_thread(void *arg) {
    (void)arg;
    nodus_server_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.udp_port = 16000; cfg.tcp_port = 16001; cfg.peer_port = 16002;
    cfg.ch_port = 16003; cfg.witness_port = 16004; cfg.require_peer_auth = false;
    snprintf(cfg.data_path, sizeof(cfg.data_path), "/tmp/nodus_lat_a_%d", getpid());
    char cmd[256]; snprintf(cmd, sizeof(cmd), "mkdir -p %s", cfg.data_path); if (system(cmd)) {}
    if (nodus_server_init(&srv_a, &cfg) != 0) { fprintf(stderr, "srv_a init failed\n"); return NULL; }
    srv_a_ready = true;
    nodus_server_run(&srv_a);
    nodus_server_close(&srv_a);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.data_path); if (system(cmd)) {}
    return NULL;
}
static void *srv_b_thread(void *arg) {
    (void)arg;
    nodus_server_config_t cfg; memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.udp_port = 17000; cfg.tcp_port = 17001; cfg.peer_port = 17002;
    cfg.ch_port = 17003; cfg.witness_port = 17004; cfg.require_peer_auth = false;
    snprintf(cfg.data_path, sizeof(cfg.data_path), "/tmp/nodus_lat_b_%d", getpid());
    char cmd[256]; snprintf(cmd, sizeof(cmd), "mkdir -p %s", cfg.data_path); if (system(cmd)) {}
    if (nodus_server_init(&srv_b, &cfg) != 0) { fprintf(stderr, "srv_b init failed\n"); return NULL; }
    srv_b_ready = true;
    nodus_server_run(&srv_b);
    nodus_server_close(&srv_b);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.data_path); if (system(cmd)) {}
    return NULL;
}

/* ── Latency capture ────────────────────────────────────────────── */
typedef struct {
    uint64_t *send_ns;      /* indexed by seq */
    uint64_t *recv_ns;
    bool     *got;
    long      n;
    volatile long received;
    nodus_circuit_handle_t *inbound_handle;
    volatile bool got_inbound;
} probe_ctx_t;

static void on_data_cb(nodus_circuit_handle_t *h, const uint8_t *d, size_t n, void *u) {
    (void)h;
    probe_ctx_t *c = (probe_ctx_t *)u;
    uint64_t rx = now_ns();
    if (n < 16) return;
    uint64_t seq = 0, ts = 0;
    memcpy(&seq, d, 8); memcpy(&ts, d + 8, 8);
    if (seq >= (uint64_t)c->n || c->got[seq]) return;
    c->got[seq] = true;
    c->send_ns[seq] = ts;
    c->recv_ns[seq] = rx;
    __sync_fetch_and_add(&c->received, 1);
}
static void on_close_cb(nodus_circuit_handle_t *h, int r, void *u) { (void)h; (void)r; (void)u; }
static void on_inbound_cb(struct nodus_client *cl, const nodus_key_t *peer_fp,
                          nodus_circuit_handle_t *h, void *u) {
    (void)cl; (void)peer_fp;
    probe_ctx_t *c = (probe_ctx_t *)u;
    c->inbound_handle = h;
    c->got_inbound = true;
    nodus_circuit_attach(h, on_data_cb, on_close_cb, u);
}
static bool wait_for(volatile bool *f, int ms) {
    int e = 0; while (!*f && e < ms) { struct timespec t = {0, 10*1000*1000}; nanosleep(&t, NULL); e += 10; }
    return *f;
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(void) {
    long frames   = env_long("PROBE_FRAMES",   DEF_FRAMES);
    long interval = env_long("PROBE_INTERVAL_MS", DEF_INTERVAL_MS);
    long fbytes   = env_long("PROBE_FRAME_BYTES", DEF_FRAME_BYTES);
    if (frames > MAX_FRAMES) frames = MAX_FRAMES;
    if (fbytes < 16) fbytes = 16;
    if (fbytes > NODUS_MAX_CIRCUIT_PAYLOAD) fbytes = NODUS_MAX_CIRCUIT_PAYLOAD;

    printf("=== Circuit Latency Probe ===\n");
    printf("frames=%ld interval=%ldms frame_bytes=%ld kill_p95=%dms\n",
           frames, interval, fbytes, KILL_P95_MS);

    pthread_t tid_a, tid_b;
    pthread_create(&tid_a, NULL, srv_a_thread, NULL);
    pthread_create(&tid_b, NULL, srv_b_thread, NULL);
    int waited = 0;
    while ((!srv_a_ready || !srv_b_ready) && waited < 5000) {
        struct timespec t = {0, 10*1000*1000}; nanosleep(&t, NULL); waited += 10;
    }
    if (!srv_a_ready || !srv_b_ready) { fprintf(stderr, "servers not ready\n"); return 2; }
    struct timespec settle = {0, 200*1000*1000}; nanosleep(&settle, NULL);

    /* Cluster-peer + routing (same as cross-live harness) */
    nodus_cluster_add_peer(&srv_a.cluster, &srv_b.identity.node_id, "127.0.0.1", 17000, 17002);
    srv_a.cluster.peers[0].state = NODUS_NODE_ALIVE; srv_a.cluster.peers[0].last_seen = (uint64_t)time(NULL);
    nodus_cluster_add_peer(&srv_b.cluster, &srv_a.identity.node_id, "127.0.0.1", 16000, 16002);
    srv_b.cluster.peers[0].state = NODUS_NODE_ALIVE; srv_b.cluster.peers[0].last_seen = (uint64_t)time(NULL);
    nodus_peer_t rp_b = {0}; rp_b.node_id = srv_b.identity.node_id;
    snprintf(rp_b.ip, sizeof(rp_b.ip), "127.0.0.1"); rp_b.udp_port = 17000; rp_b.tcp_port = 17002;
    rp_b.last_seen = (uint64_t)time(NULL); nodus_routing_insert(&srv_a.routing, &rp_b);
    nodus_peer_t rp_a = {0}; rp_a.node_id = srv_a.identity.node_id;
    snprintf(rp_a.ip, sizeof(rp_a.ip), "127.0.0.1"); rp_a.udp_port = 16000; rp_a.tcp_port = 16002;
    rp_a.last_seen = (uint64_t)time(NULL); nodus_routing_insert(&srv_b.routing, &rp_a);

    nodus_identity_t id_u1, id_u2;
    uint8_t s1[32], s2[32]; memset(s1, 0x33, 32); memset(s2, 0x44, 32);
    nodus_identity_from_seed(s1, &id_u1); nodus_identity_from_seed(s2, &id_u2);

    nodus_client_config_t cfg_a, cfg_b; memset(&cfg_a, 0, sizeof(cfg_a));
    strncpy(cfg_a.servers[0].ip, "127.0.0.1", 63);
    cfg_a.servers[0].port = 16001; cfg_a.server_count = 1; cfg_a.request_timeout_ms = 8000;
    memcpy(&cfg_b, &cfg_a, sizeof(cfg_a)); cfg_b.servers[0].port = 17001;

    nodus_client_t cl_u1, cl_u2; memset(&cl_u1, 0, sizeof(cl_u1)); memset(&cl_u2, 0, sizeof(cl_u2));
    int rc = 3;
    if (nodus_client_init(&cl_u1, &cfg_a, &id_u1) != 0 || nodus_client_connect(&cl_u1) != 0) {
        fprintf(stderr, "u1 connect failed\n"); goto cleanup;
    }
    if (nodus_client_init(&cl_u2, &cfg_b, &id_u2) != 0 || nodus_client_connect(&cl_u2) != 0) {
        fprintf(stderr, "u2 connect failed\n"); goto cleanup;
    }
    srv_a.presence.last_sync = 0; srv_b.presence.last_sync = 0;
    struct timespec sw = {0, 500*1000*1000}; nanosleep(&sw, NULL);

    probe_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.n = frames;
    ctx.send_ns = calloc(frames, sizeof(uint64_t));
    ctx.recv_ns = calloc(frames, sizeof(uint64_t));
    ctx.got     = calloc(frames, sizeof(bool));
    if (!ctx.send_ns || !ctx.recv_ns || !ctx.got) { fprintf(stderr, "oom\n"); goto cleanup; }
    nodus_circuit_set_inbound_cb(&cl_u2, on_inbound_cb, &ctx);

    nodus_circuit_handle_t *h = NULL;
    if (nodus_circuit_open_e2e(&cl_u1, &id_u2.node_id, id_u2.kyber_pk,
                               on_data_cb, on_close_cb, &ctx, &h) != 0 || !h) {
        fprintf(stderr, "circuit open failed\n"); goto cleanup;
    }
    if (!wait_for(&ctx.got_inbound, 3000)) { fprintf(stderr, "no inbound\n"); goto cleanup; }

    /* Paced send loop — one frame every `interval` ms, seq + send-ts embedded. */
    uint8_t *frame = malloc(fbytes);
    if (!frame) { fprintf(stderr, "oom\n"); goto cleanup; }
    memset(frame, 0xA5, fbytes);
    printf("streaming %ld frames (%ld ms each ≈ %.1fs)...\n",
           frames, interval, (double)frames * interval / 1000.0);
    for (long seq = 0; seq < frames; seq++) {
        uint64_t ts = now_ns();
        memcpy(frame, &seq, 8); memcpy(frame + 8, &ts, 8);
        nodus_circuit_send(h, frame, fbytes);
        struct timespec ti = { interval / 1000, (interval % 1000) * 1000000L };
        nanosleep(&ti, NULL);
    }
    free(frame);
    /* Drain: wait up to 3s for stragglers held by retransmit/HOL blocking. */
    for (int i = 0; i < 300 && ctx.received < frames; i++) {
        struct timespec t = {0, 10*1000*1000}; nanosleep(&t, NULL);
    }

    /* ── Stats ──────────────────────────────────────────────────── */
    long recvd = ctx.received;
    uint64_t *lat = calloc(recvd > 0 ? recvd : 1, sizeof(uint64_t));
    long m = 0;
    for (long i = 0; i < frames; i++) if (ctx.got[i]) lat[m++] = ctx.recv_ns[i] - ctx.send_ns[i];
    rc = 0;
    printf("\n--- Results ---\n");
    printf("sent=%ld received=%ld loss=%.2f%%  (TCP: loss surfaces as latency, not drops)\n",
           frames, recvd, frames ? 100.0 * (frames - recvd) / frames : 0.0);
    if (m > 0) {
        qsort(lat, m, sizeof(uint64_t), cmp_u64);
        double p50 = lat[(long)(m * 0.50)] / 1e6;
        double p95 = lat[(long)(m * 0.95)] / 1e6;
        double p99 = lat[(long)(m * 0.99)] / 1e6;
        double mx  = lat[m - 1] / 1e6;
        printf("one-way latency ms: p50=%.1f p95=%.1f p99=%.1f max=%.1f\n", p50, p95, p99, mx);
        printf("VERDICT: p95=%.1fms vs kill=%dms → %s\n", p95, KILL_P95_MS,
               p95 > KILL_P95_MS ? "TCP-MVP KILL (promote UDP/Faz C)" : "TCP-MVP viable at this profile");
    } else {
        printf("no frames received — circuit path broken under this profile\n");
        rc = 1;
    }
    free(lat);

cleanup:
    nodus_client_close(&cl_u1); nodus_client_close(&cl_u2);
    nodus_server_stop(&srv_a); nodus_server_stop(&srv_b);
    pthread_join(tid_a, NULL); pthread_join(tid_b, NULL);
    free(ctx.send_ns); free(ctx.recv_ns); free(ctx.got);
    return rc;
}
