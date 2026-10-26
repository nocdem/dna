/*
 * nodus-circ — circuit liveness / latency tester.
 *
 * Opens a real per-circuit E2E (Kyber1024 + AES-256-GCM) circuit between two
 * Nodus clients THROUGH a running server cluster, and measures round-trip
 * latency. Unlike the in-process tests, this uses two separate client processes
 * over real sockets, so it exercises the actual deployment path (G4 liveness).
 *
 * Both roles derive their identity from a FIXED seed, so the caller can
 * reconstruct the callee's node_id + Kyber pubkey with no out-of-band exchange.
 *
 * Usage (two terminals, same machine is fine):
 *   nodus-circ -s <server[:port]> listen              # callee (echoes)
 *   nodus-circ -s <server[:port]> call [-n <count>]   # caller (measures RTT)
 *
 * For a real 3-hop cross-nodus test, point the two roles at DIFFERENT cluster
 * nodes. Same node = 2-hop local bridge.
 */

#include "nodus/nodus.h"
#include "crypto/nodus_identity.h"
#include "client/nodus_tool_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

/* Fixed role seeds — deterministic identities. */
static const uint8_t SEED_CALLER[32] = { [0 ... 31] = 0x11 };
static const uint8_t SEED_CALLEE[32] = { [0 ... 31] = 0x22 };

/* Keyed mode (-k): a fixed pre-agreed K_call, as if agreed via call signaling
 * (Faz A). Exercises nodus_circuit_open_keyed / nodus_circuit_attach_keyed. */
static const uint8_t TEST_K_CALL[32] = { [0 ... 31] = 0xC7 };
static int g_keyed = 0;

#define PROBE_LEN 12   /* [seq u32 LE][send_ts_us u64 LE] */

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

/* ── callee (echo) ── */

static void callee_on_data(nodus_circuit_handle_t *h, const uint8_t *data,
                           size_t len, void *user)
{
    (void)user;
    nodus_circuit_send(h, data, len);   /* echo back through the E2E circuit */
}

static void callee_on_close(nodus_circuit_handle_t *h, int reason, void *user)
{
    (void)h; (void)user;
    printf("[callee] circuit closed (reason=%d)\n", reason);
}

static void callee_on_inbound(struct nodus_client *client, const nodus_key_t *peer_fp,
                              nodus_circuit_handle_t *h, void *user)
{
    (void)client; (void)user;
    printf("[callee] inbound circuit from %02x%02x%02x%02x...  (accepting, %s echo mode)\n",
           peer_fp->bytes[0], peer_fp->bytes[1], peer_fp->bytes[2], peer_fp->bytes[3],
           g_keyed ? "keyed" : "e2e/plain");
    if (g_keyed)
        nodus_circuit_attach_keyed(h, peer_fp, TEST_K_CALL,
                                   callee_on_data, callee_on_close, NULL);
    else
        nodus_circuit_attach(h, callee_on_data, callee_on_close, NULL);
}

/* ── caller (RTT) ── */

static volatile int   g_got_echo = 0;
static volatile double g_rtt_ms = 0.0;

static void caller_on_data(nodus_circuit_handle_t *h, const uint8_t *data,
                           size_t len, void *user)
{
    (void)h; (void)user;
    if (len >= PROBE_LEN) {
        uint64_t sent;
        memcpy(&sent, data + 4, 8);
        g_rtt_ms = (double)(now_us() - sent) / 1000.0;
        g_got_echo = 1;
    }
}

static void caller_on_close(nodus_circuit_handle_t *h, int reason, void *user)
{
    (void)h; (void)user;
    printf("[caller] circuit closed (reason=%d)\n", reason);
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

/* ── setup ── */

/* The tool network identity (pins live here for the process). */
static nodus_tool_net_t g_net;

static int connect_ready(nodus_client_t *client, const char *ip, uint16_t port,
                         const nodus_identity_t *id)
{
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", ip);
    cfg.servers[0].port = port;
    cfg.server_count = 1;

    /* DHT v2 package 3c: pin + chain id from the tool network file / flags
     * (nodus_tool_network.h); none -> refuse before any socket. */
    char nerr[NODUS_TOOL_NET_ERR_SIZE];
    if (nodus_tool_net_fill(&g_net, &cfg, nerr, sizeof(nerr)) != 0) {
        fprintf(stderr, "nodus-circ: %s\n", nerr);
        return -1;
    }
    if (nodus_client_init(client, &cfg, id) != 0) { fprintf(stderr, "client_init failed\n"); return -1; }
    if (nodus_client_connect(client) != 0) {
        fprintf(stderr, "connect failed (%s:%u)\n", ip, port);
        nodus_client_close(client);         /* init succeeded: close owed */
        return -1;
    }

    for (int i = 0; i < 100 && !nodus_client_is_ready(client); i++)
        nodus_client_poll(client, 100);
    if (!nodus_client_is_ready(client)) {
        fprintf(stderr, "not ready after 10s\n");
        nodus_client_close(client);
        return -1;
    }
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr, "Usage: %s -s <server[:port]> [--network <file>] [--chain <hex64>] "
            "[--pin <hex128>] {listen | call} [-n count]\n", p);
    fprintf(stderr, "  The node's pin and the chain id come from the tool network file "
            "(--network or NODUS_NETWORK;\n  see nodus-cli --help) with --pin / --chain "
            "over it. Neither -> refused before any socket.\n");
}

int main(int argc, char **argv)
{
    const char *server = NULL;
    uint16_t port = 4001;
    int count = 50;
    const char *net_file = NULL, *net_pin = NULL, *net_chain = NULL;
    int opt;
    static const struct option longopts[] = {
        { "network", required_argument, NULL, 'N' },
        { "chain",   required_argument, NULL, 'C' },
        { "pin",     required_argument, NULL, 'P' },
        { NULL, 0, NULL, 0 }
    };
    while ((opt = getopt_long(argc, argv, "+s:n:kh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'N': net_file = optarg; break;
        case 'C': net_chain = optarg; break;
        case 'P': net_pin = optarg; break;
        case 'k': g_keyed = 1; break;
        case 's': {
            char *c = strchr(optarg, ':');
            static char host[256];
            if (c) { size_t n = (size_t)(c - optarg); if (n >= sizeof(host)) n = sizeof(host)-1;
                     memcpy(host, optarg, n); host[n] = '\0'; server = host; port = (uint16_t)atoi(c+1); }
            else server = optarg;
            break;
        }
        case 'n': count = atoi(optarg); break;
        default: usage(argv[0]); return 1;
        }
    }
    const char *mode = (optind < argc) ? argv[optind] : NULL;
    if (!server || !mode) { usage(argv[0]); return 1; }
    {
        char nerr[NODUS_TOOL_NET_ERR_SIZE];
        nodus_tool_net_init(&g_net);
        if (nodus_tool_net_open(&g_net, net_file, net_pin, net_chain, nerr,
                                sizeof(nerr)) != 0) {
            fprintf(stderr, "nodus-circ: %s\n", nerr);
            return 1;
        }
    }

    nodus_identity_t id_caller, id_callee;
    if (nodus_identity_from_seed(SEED_CALLER, &id_caller) != 0 ||
        nodus_identity_from_seed(SEED_CALLEE, &id_callee) != 0) {
        fprintf(stderr, "identity derivation failed\n"); return 1;
    }

    nodus_client_t client;

    if (strcmp(mode, "listen") == 0) {
        if (connect_ready(&client, server, port, &id_callee) != 0) return 1;
        nodus_circuit_set_inbound_cb(&client, callee_on_inbound, NULL);
        printf("[callee] listening as %.16s...  (Ctrl-C to stop)\n", id_callee.fingerprint);
        for (;;) nodus_client_poll(&client, 200);
        return 0;
    }

    if (strcmp(mode, "call") == 0) {
        if (connect_ready(&client, server, port, &id_caller) != 0) return 1;
        printf("[caller] %.16s... opening E2E circuit to %.16s...\n",
               id_caller.fingerprint, id_callee.fingerprint);

        nodus_circuit_handle_t *h = NULL;
        int rc = g_keyed
            ? nodus_circuit_open_keyed(&client, &id_callee.node_id, TEST_K_CALL,
                                       caller_on_data, caller_on_close, NULL, &h)
            : nodus_circuit_open_e2e(&client, &id_callee.node_id, id_callee.kyber_pk,
                                     caller_on_data, caller_on_close, NULL, &h);
        if (rc != 0 || !h) { fprintf(stderr, "circuit open failed (rc=%d) — callee online?\n", rc); return 1; }
        printf("[caller] circuit open. sending %d probes...\n", count);

        double *rtts = calloc((size_t)count, sizeof(double));
        int recv = 0;
        for (int i = 0; i < count; i++) {
            uint8_t probe[PROBE_LEN];
            uint32_t seq = (uint32_t)i;
            uint64_t ts = now_us();
            memcpy(probe, &seq, 4);
            memcpy(probe + 4, &ts, 8);
            g_got_echo = 0;
            if (nodus_circuit_send(h, probe, sizeof(probe)) != 0) { fprintf(stderr, "send failed\n"); break; }

            uint64_t start = now_us();
            while (!g_got_echo && (now_us() - start) < 2000000ull)
                nodus_client_poll(&client, 5);
            if (g_got_echo) rtts[recv++] = g_rtt_ms;
            usleep(20000);   /* 20ms pacing */
        }

        nodus_circuit_close(h);

        if (recv == 0) { printf("\n[result] 0/%d echoes — circuit not live.\n", count); free(rtts); return 1; }
        qsort(rtts, (size_t)recv, sizeof(double), cmp_double);
        double sum = 0; for (int i = 0; i < recv; i++) sum += rtts[i];
        printf("\n[result] round-trip over real cluster: %d/%d echoes (%.0f%% loss)\n",
               recv, count, 100.0 * (count - recv) / count);
        printf("  min=%.1fms  p50=%.1fms  p95=%.1fms  max=%.1fms  mean=%.1fms\n",
               rtts[0], rtts[recv/2], rtts[(int)(recv*0.95)], rtts[recv-1], sum/recv);
        free(rtts);
        return 0;
    }

    usage(argv[0]);
    return 1;
}
