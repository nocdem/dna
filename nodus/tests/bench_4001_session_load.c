/**
 * Load measurement of the 4001 key-exchange line (approved 4001 plan,
 * section 4.5 and build-order step 8). A MEASUREMENT DRIVER, not a test: it is
 * built by CMake as bench_4001_session_load, is NOT registered with ctest, and
 * asserts nothing. The orchestrator runs it and takes the numbers to the
 * operator, who sets the 4001 queue depth and worker count; this file sets
 * none and neither does the code it measures (NODUS_CLIENT_SESSION_*_
 * PROVISIONAL are placeholders, nodus_server.h).
 *
 * What it does. It forks a node child: a real nodus_server_t (same code as
 * nodus-server's client port) polled by that child alone, with the 4001 line's
 * queue depth and worker count taken from the command line. The parent opens
 * raw-machine initiators (cmt_p2p_sc_* driven directly) from DISTINCT
 * loopback source addresses (127.0.0.0/8 is all local, `ip route show table
 * local`), so the 20-per-IP limit is not what is measured (on the WebSocket
 * path each connection also carries a distinct X-Forwarded-For address, the
 * real-IP key of that entry):
 *   - honest clients: complete the handshake, then keep the connection until
 *     the NODE has opened it: after their AUTHSIG they send one sealed
 *     request, a T2 "ping" (nodus_t2_ping), and finish when the sealed "pong"
 *     arrives (the connection-complete time is the arrival of that answer).
 *     The node dispatches "ping" in nodus_server.c dispatch_t2 (:1282; the
 *     method chain at :1439-1440) to handle_t2_ping (:857-862), which answers with
 *     nodus_t2_pong and touches neither the chain backend nor the DHT, so it
 *     is answered in every layout and on both paths. The node delivers
 *     application data only after it opened the session
 *     (nodus_inter_session.h "read delivers plaintext only after open"), so
 *     an answer is proof the node opened THIS connection (design
 *     2026-10-28-encrypted-sessions.md separates local authentication from
 *     proof that the peer opened). Why the node's "opened" counter equals the
 *     honest opened count in a cooperative run: an honest connection is
 *     closed only after its pong, never earlier, so every connection the node
 *     opens stays until it is answered; attackers never complete the
 *     handshake and are never opened; so opened(node) = answered(honest) +
 *     the honest connections the node opened but whose pong had not yet
 *     arrived when the run ended (the "unfinished" count). The driver prints
 *     both numbers and a consistency line; a run with unfinished honest
 *     connections (time limit reached) is flagged and its two numbers may
 *     differ by exactly that count.
 *     Arrival as one burst or at a steady rate;
 *   - attackers: a valid HELLO, then a KEYX whose ciphertext is replaced by
 *     random bytes (decapsulation of an invalid ciphertext still returns
 *     success, so the node decapsulates and signs), then silence. Their size
 *     is --attack-count (all at once) and/or --attack-rate per second; with
 *     --reconnect a connection the node closed is replaced at once, so the
 *     offered load is a standing population plus reconnections.
 *   --path plain|ws selects the plain 4001 path or the WebSocket entry (the
 *   machine inside binary WebSocket frames after an HTTP Upgrade).
 *   --layout combined|witness-split|three:
 *   combined = one node process, the chain id set on it directly (no witness
 *   work);
 *   witness-split = the node's core reaches a separate stand-in WITNESS PROCESS
 *   over <data>/witness.sock (witness_external), as the live nodes' core does;
 *   three = the live shape: the node core (nodus_server_backends_ipc, both
 *   witness_external and storage_external), the real nodus-storage binary
 *   (found next to this driver) and the stand-in witness process, three
 *   processes plus the driver. THE WITNESS WORKLOAD OF THE LAST TWO LAYOUTS IS
 *   NONE: the stand-in answers only ipc_status (open chain, the id the session
 *   uses) and has no consensus, 4004 or block work. THE STORAGE WORKLOAD OF
 *   `three` IS NONE TOO: the real nodus-storage runs idle (no seeds, no DHT
 *   request, no peer), so it only shows its own idle load on the machine and
 *   the core without an in-process DHT. Conclusions are limited to the layouts
 *   measured; the live layout with a real witness under consensus load and a
 *   storage under DHT traffic is NOT measured by this file.
 *
 * Recorded and printed (one block per run, parameters first):
 *   offered: honest and attacker connections started and the offered rates.
 *   honest: connections, opened (= answered by the node's pong), closed
 *     before 3 s without opening, closed at or after 3 s, unfinished; wall
 *     time from TCP connect to the arrival of the pong: min, p50, p95, p99,
 *     max, and the count over 3 s.
 *     The driver's own processor time is NEVER subtracted from these times
 *     (driver and node share the machine).
 *   node (exact, from the module's own counters): sessions started and opened,
 *     key-exchange jobs refused because the queue was full, connections that
 *     ran past the 3 s handshake deadline.
 *   node job queue (inbound class, sampled every ms): peak and mean, and the
 *     queue OVER TIME: per 100 ms window since the node was ready, the largest
 *     value and the mean of the 1 ms samples (printed as at most ~60 rows).
 *   accept-to-open per connection, measured AT THE NODE in
 *     nodus_inter_session_open (machine start to open, on the module's own
 *     deadline clock, ms): count, mean, maximum, and a 100 ms-bucket histogram
 *     from which p50/p95/p99 are printed as bucket upper edges (the last bucket
 *     is everything from 3,100 ms, past the 3 s deadline's own cut). Only
 *     sessions that OPENED are in it; connections the node closed are the
 *     "honest closed" counts and the deadline counter. Unlike the driver-side
 *     wall times below, it contains no driver scheduling.
 *   processor time of the node child, the stand-in witness and the storage
 *     process (if any) and the driver, apart; peak resident memory (VmHWM) of
 *     the node child.
 *   unloaded per-kind job run times (encapsulate, decapsulate, sign, verify):
 *     cmt_p2p_sc_job_run on this build before the load starts (mean PROCESSOR
 *     ms per job, clock()).
 *   per-kind job run times UNDER load, from the module's own stats
 *     (nodus_inter_session_stats): count, mean and maximum WALL ms around
 *     cmt_p2p_sc_job_run on the worker that ran it, queue wait excluded. Wall,
 *     not processor, time: a worker preempted by the other workers, the owner
 *     and the driver shows it here, so these exceed the unloaded numbers when
 *     the machine is busy.
 *
 * Not covered: mobile browsers; a real witness's consensus work; a storage
 * process under DHT traffic. A reduced load proves logic, not production magnitude
 * (CLAUDE.md TESTS). Candidate queue depths and worker counts are given by
 * repeated runs (--depth, --workers).
 *
 * Usage: bench_4001_session_load --n N --workers W --depth D
 *          [--path plain|ws] [--layout combined|witness-split|three]
 *          [--pattern burst|steady] [--rate R]       honest arrivals, R/s
 *          [--attack-count A] [--attack-rate AR] [--reconnect]
 *          [--seconds S]                             run limit (default 30)
 * Fixed ports 15510-15515 and a /tmp/bench_4001_<pid> directory (removed).
 * Run it alone: it uses all CPUs and must not overlap builds, browser tests
 * or the harness (CLAUDE.md SESSIONS). Production build flags (Release).
 * How it can mislead: the driver's initiators are single-threaded and do their
 * own ML-KEM/ML-DSA work, so at large N the driver, not the node, can be the
 * slow side; compare the processor times printed. Honest "closed before 3 s"
 * is a full-queue refusal only when the node's queue_refused counter says so.
 */
#define _GNU_SOURCE 1
#include "server/nodus_server.h"
#include "server/nodus_inter_session.h"
#include "witness/nodus_witness_ipc.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_tier2.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PORT_BASE 15510          /* udp +0, tcp +1, peer +2, channel +3, witness +4, ws +5 */
#define HANDSHAKE_LIMIT_MS 3000
#define ATK_MAX 4096

static const uint8_t chain[CMT_P2P_SC_CHAIN_ID_SIZE] = {0x42, 0x19, 0x77};

static uint64_t mono_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static uint64_t cpu_ms_self(void) {
    struct timespec ts; clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static double ts_ms(const struct timeval *tv) { return tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0; }

/* ── options ─────────────────────────────────────────────────────── */
typedef struct {
    unsigned n, workers, depth, rate, attack_count, attack_rate, seconds;
    int steady, ws, split, reconnect;
    int three;                        /* split + the real nodus-storage process */
} opts_t;

static char g_dir[96];

/* ── the stand-in witness process (layout witness-split) ─────────── */
static volatile sig_atomic_t g_stop;
static void on_term(int s) { (void)s; g_stop = 1; }

static void wh_dispatch(void *ctx, nodus_tcp_conn_t *c, const uint8_t *p, size_t n,
                        const char *m, uint32_t t) { (void)ctx; (void)c; (void)p; (void)n; (void)m; (void)t; }
static void wh_collect(void *ctx, nodus_tcp_conn_t *c, const uint8_t pk[NODUS_PK_BYTES],
                       const uint8_t tk[NODUS_SESSION_TOKEN_LEN], const uint8_t *p, size_t n,
                       uint32_t t) { (void)ctx; (void)c; (void)pk; (void)tk; (void)p; (void)n; (void)t; }
static void wh_status(void *ctx, nodus_witness_ipc_status_t *out) {
    (void)ctx;
    memset(out, 0, sizeof(*out));
    out->chain_open = true; out->height = 1;
    memcpy(out->chain_id_v3, chain, sizeof(chain)); out->chain_id_v3_valid = true;
}

static int witness_child(int report_fd) {
    nodus_witness_ipc_handlers_t h = {
        .dispatch_dnac = wh_dispatch, .cc_collect = wh_collect, .status = wh_status
    };
    nodus_witness_ipc_t *ipc = nodus_witness_ipc_new(&h);
    char sock[160];
    if (!ipc || nodus_witness_ipc_sock_path(g_dir, sock, sizeof(sock)) != 0 ||
        nodus_witness_ipc_listen(ipc, sock) != 0) return 1;
    signal(SIGTERM, on_term);
    if (write(report_fd, "w", 1) != 1) return 1;
    while (!g_stop) nodus_witness_ipc_poll(ipc, 5);
    struct rusage ru; getrusage(RUSAGE_SELF, &ru);
    char out[64]; int n = snprintf(out, sizeof(out), "%.1f", ts_ms(&ru.ru_utime) + ts_ms(&ru.ru_stime));
    if (write(report_fd, out, (size_t)n) < 0) return 1;
    nodus_witness_ipc_free(ipc);
    return 0;
}

/* ── the node child ──────────────────────────────────────────────── */
typedef struct { uint64_t peak, sum, samples; } occupancy_t;

/* The inbound queue over time: per 100 ms window since "ready", the largest
 * value, the sum and the count of the 1 ms samples. Windows past the last
 * one are folded into it. */
#define OCC_WINDOW_MS 100u
#define OCC_WINDOWS   1200u
static uint64_t g_win_max[OCC_WINDOWS], g_win_sum[OCC_WINDOWS], g_win_n[OCC_WINDOWS];

static int node_child(const opts_t *o, int report_fd) {
    static nodus_server_t srv;
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port = PORT_BASE; config.tcp_port = PORT_BASE + 1;
    config.peer_port = PORT_BASE + 2; config.ch_port = PORT_BASE + 3;
    config.witness_port = PORT_BASE + 4; config.ws_port = PORT_BASE + 5;
    config.require_peer_auth = true;
    config.witness_external = o->split ? true : false;
    config.client_session_depth = o->depth;       /* the line under test */
    config.client_session_workers = o->workers;
    snprintf(config.data_path, sizeof(config.data_path), "%s", g_dir);
    if (o->three) {
        /* nodus-core's shape: the IPC-only table, DHT in nodus-storage, chain
         * in the witness. The core creates the identity files the storage
         * process then reads (decision item 10); main() made the directory. */
        config.storage_external = true;
        snprintf(config.identity_path, sizeof(config.identity_path), "%s/identity", g_dir);
        if (nodus_server_init_ex(&srv, &config, &nodus_server_backends_ipc) != 0) return 1;
    } else if (nodus_server_init(&srv, &config) != 0) return 1;
    if (!o->split) {
        memcpy(srv.inter_chain_id, chain, sizeof(chain));
        srv.inter_chain_known = srv.inter_chain_id_valid = true;
    } else {
        /* the run loop's per-pass work, driven here: the chain answers come
         * from the witness process over witness.sock */
        for (int i = 0; i < 1000 && !srv.inter_chain_id_valid; ++i) {
            if (srv.chain) srv.chain->ops->tick(srv.chain);
            nodus_tcp_poll(&srv.tcp, 5);
            nodus_server_inter_chain_refresh(&srv);
        }
        if (!srv.inter_chain_id_valid) return 1;
    }
    /* "ready": the node is up and knows its chain id */
    if (write(report_fd, "n", 1) != 1) return 1;
    signal(SIGTERM, on_term);
    occupancy_t occ = {0};
    uint64_t last = 0, last_chain = 0, t_ready = mono_ms();
    while (!g_stop) {
        nodus_tcp_poll(&srv.tcp, 1);
        uint64_t now = mono_ms();
        if (o->split && now - last_chain >= 10) {
            last_chain = now;
            if (srv.chain) srv.chain->ops->tick(srv.chain);
            nodus_server_inter_chain_refresh(&srv);
        }
        if (now != last) {
            last = now;
            uint64_t q = nodus_inter_session_job_queued(srv.client_session, false);
            if (q > occ.peak) occ.peak = q;
            occ.sum += q; occ.samples++;
            uint64_t w = (now - t_ready) / OCC_WINDOW_MS;
            if (w >= OCC_WINDOWS) w = OCC_WINDOWS - 1;
            if (q > g_win_max[w]) g_win_max[w] = q;
            g_win_sum[w] += q; g_win_n[w]++;
        }
    }
    const uint64_t n_win = (mono_ms() - t_ready) / OCC_WINDOW_MS + 1 > OCC_WINDOWS
                               ? OCC_WINDOWS : (mono_ms() - t_ready) / OCC_WINDOW_MS + 1;
    nodus_inter_session_stats_t st;
    nodus_inter_session_stats(srv.client_session, &st);
    struct rusage ru; getrusage(RUSAGE_SELF, &ru);
    char vm[64] = "unknown";
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    while (f && fgets(line, sizeof(line), f))
        if (!strncmp(line, "VmHWM:", 6)) { snprintf(vm, sizeof(vm), "%s", line + 6); break; }
    if (f) fclose(f);
    size_t ln = strlen(vm); while (ln && (vm[ln-1] == '\n' || vm[ln-1] == ' ')) vm[--ln] = 0;
    static char out[65536];
    int n = snprintf(out, sizeof(out), "%llu %llu %llu %.1f %llu %llu %llu %llu|%s|",
                     (unsigned long long)occ.peak, (unsigned long long)occ.sum,
                     (unsigned long long)occ.samples, ts_ms(&ru.ru_utime) + ts_ms(&ru.ru_stime),
                     (unsigned long long)st.started, (unsigned long long)st.opened,
                     (unsigned long long)st.queue_refused, (unsigned long long)st.deadline_closed, vm);
    /* per-kind job stats: count, total ns, max ns for kinds 1..4 */
    for (int k = 1; k <= 4 && n > 0 && (size_t)n < sizeof(out); ++k)
        n += snprintf(out + n, sizeof(out) - (size_t)n, " %llu %llu %llu",
                      (unsigned long long)st.job_count[k], (unsigned long long)st.job_ns_total[k],
                      (unsigned long long)st.job_ns_max[k]);
    /* accept-to-open at the node: " O total_ms max_ms" then " H" + the buckets */
    if (n > 0 && (size_t)n < sizeof(out))
        n += snprintf(out + n, sizeof(out) - (size_t)n, " O %llu %llu H",
                      (unsigned long long)st.open_ms_total, (unsigned long long)st.open_ms_max);
    for (unsigned b = 0; b < NODUS_INTER_OPEN_BUCKETS && n > 0 && (size_t)n < sizeof(out); ++b)
        n += snprintf(out + n, sizeof(out) - (size_t)n, " %llu", (unsigned long long)st.open_hist[b]);
    /* the queue over time: " W <windows>" then max sum count per window */
    if (n > 0 && (size_t)n < sizeof(out))
        n += snprintf(out + n, sizeof(out) - (size_t)n, " W %llu", (unsigned long long)n_win);
    for (uint64_t w = 0; w < n_win && n > 0 && (size_t)n < sizeof(out); ++w)
        n += snprintf(out + n, sizeof(out) - (size_t)n, " %llu %llu %llu",
                      (unsigned long long)g_win_max[w], (unsigned long long)g_win_sum[w],
                      (unsigned long long)g_win_n[w]);
    if (n < 0 || (size_t)n >= sizeof(out)) return 1;
    for (int off = 0; off < n; ) {                 /* the pipe may take it in pieces */
        ssize_t w = write(report_fd, out + off, (size_t)(n - off));
        if (w <= 0) return 1;
        off += (int)w;
    }
    nodus_server_close(&srv);
    return 0;
}

/* ── raw-machine initiators ──────────────────────────────────────── */
enum { C_IDLE = 0, C_LIVE, C_DONE };
typedef struct {
    int state, fd;
    bool attacker, sent_keyx, authed, closed, replaced;
    bool pinged;                      /* honest: the sealed ping was written */
    uint8_t plain[512]; size_t plain_len;   /* honest: decrypted bytes of the answer */
    int ws_state;                     /* 0 not ws / 1 upgrade sent / 2 open */
    uint64_t t_start, t_end;
    cmt_p2p_sc_t sc;
    cmt_p2p_sc_host_t host;
    uint8_t obuf[2 * CMT_P2P_SC_OUT_CAP + 64]; size_t olen, ooff;
    uint8_t in[2 * CMT_P2P_SC_OUT_CAP]; size_t in_len;      /* unframed machine bytes */
    uint8_t rx[4 * CMT_P2P_SC_OUT_CAP]; size_t rx_len;      /* socket bytes (ws only) */
} conn_t;

static nodus_identity_t g_client_id;
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

/* distinct loopback source per connection: 127.<net>.<hi>.<lo> */
static void source_for(unsigned index, bool attacker, struct sockaddr_in *sa) {
    memset(sa, 0, sizeof(*sa)); sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl((127u << 24) | ((attacker ? 2u : 1u) << 16) |
                                (((index / 250u) & 0xffu) << 8) | (1u + index % 250u));
}

/* Append machine bytes to the output, in binary WebSocket frames (masked,
 * RFC 6455 5.2/5.3) on the WebSocket path. */
static void queue_bytes(conn_t *c, const uint8_t *p, size_t n) {
    if (!n) return;
    if (c->ws_state != 2) {
        if (c->olen + n <= sizeof(c->obuf)) { memcpy(c->obuf + c->olen, p, n); c->olen += n; }
        return;
    }
    static const uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t hdr[14]; size_t h = 0;
    hdr[h++] = 0x82;
    if (n < 126) hdr[h++] = (uint8_t)(0x80 | n);
    else { hdr[h++] = 0x80 | 126; hdr[h++] = (uint8_t)(n >> 8); hdr[h++] = (uint8_t)n; }
    memcpy(hdr + h, key, 4); h += 4;
    if (c->olen + h + n > sizeof(c->obuf)) return;
    memcpy(c->obuf + c->olen, hdr, h); c->olen += h;
    for (size_t i = 0; i < n; ++i) c->obuf[c->olen + i] = p[i] ^ key[i & 3];
    c->olen += n;
}

static bool conn_open(conn_t *c, unsigned index, bool attacker, bool ws) {
    memset(c, 0, sizeof(*c));
    c->attacker = attacker;
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) return false;
    struct sockaddr_in src, dst = {.sin_family = AF_INET,
                                   .sin_port = htons((uint16_t)(PORT_BASE + (ws ? 5 : 1)))};
    source_for(index, attacker, &src);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    if (bind(c->fd, (struct sockaddr *)&src, sizeof(src)) != 0) { close(c->fd); return false; }
    fcntl(c->fd, F_SETFL, O_NONBLOCK);
    if (connect(c->fd, (struct sockaddr *)&dst, sizeof(dst)) != 0 && errno != EINPROGRESS) {
        close(c->fd); return false;
    }
    c->host.ctx = &g_client_id; c->host.sign = raw_sign; c->host.verify = raw_verify;
    if (cmt_p2p_sc_init(&c->sc, CMT_P2P_SC_ROLE_INITIATOR, &c->host, g_client_id.pk.bytes,
                        NULL, NULL, CMT_P2P_SC_PROTO_VER_4001, chain) != CMT_OK) {
        close(c->fd); return false;
    }
    if (ws) {
        /* the HTTP Upgrade; the real client address is the X-Forwarded-For
         * (198.51.<net>.<host>), distinct per connection */
        int w = snprintf((char *)c->obuf, sizeof(c->obuf),
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: binary\r\nX-Forwarded-For: 198.%u.%u.%u\r\n\r\n",
            attacker ? 52u : 51u, (index / 250u) & 0xffu, 1u + index % 250u);
        c->olen = (size_t)w; c->ws_state = 1;
    }
    c->t_start = mono_ms(); c->state = C_LIVE;
    return true;
}

static void conn_finish(conn_t *c, bool closed_by_peer) {
    c->t_end = mono_ms(); c->closed = closed_by_peer; c->state = C_DONE;
    close(c->fd); cmt_p2p_sc_clear(&c->sc);
}

static void take_out(conn_t *c) {
    size_t n; const uint8_t *p = cmt_p2p_sc_out(&c->sc, &n);
    if (n) { queue_bytes(c, p, n); cmt_p2p_sc_out_consume(&c->sc, n); }
}

/* socket bytes -> machine input (unframing server WebSocket frames) */
static void feed_in(conn_t *c, const uint8_t *p, size_t n) {
    if (!c->ws_state) {
        if (c->in_len + n <= sizeof(c->in)) { memcpy(c->in + c->in_len, p, n); c->in_len += n; }
        return;
    }
    if (c->rx_len + n > sizeof(c->rx)) { c->rx_len = 0; return; }
    memcpy(c->rx + c->rx_len, p, n); c->rx_len += n;
    if (c->ws_state == 1) {
        for (size_t i = 0; i + 4 <= c->rx_len; ++i)
            if (!memcmp(c->rx + i, "\r\n\r\n", 4)) {
                size_t head = i + 4;
                c->rx_len -= head; memmove(c->rx, c->rx + head, c->rx_len);
                c->ws_state = 2;
                /* the machine's HELLO leaves only after the Upgrade */
                take_out(c);
                break;
            }
    }
    size_t off = 0;
    while (c->ws_state == 2 && c->rx_len - off >= 2) {
        const uint8_t *b = c->rx + off;
        uint64_t len = b[1] & 0x7f; size_t h = 2;
        if (len == 126) { if (c->rx_len - off < 4) break; len = ((uint64_t)b[2] << 8) | b[3]; h = 4; }
        else if (len == 127) { if (c->rx_len - off < 10) break; len = 0;
            for (int i = 0; i < 8; ++i) len = (len << 8) | b[2 + i]; h = 10; }
        if (c->rx_len - off < h + len) break;
        if ((b[0] & 0x0f) == 0x02 && c->in_len + len <= sizeof(c->in)) {
            memcpy(c->in + c->in_len, b + h, len); c->in_len += (size_t)len;
        }
        off += h + (size_t)len;
    }
    if (off) { c->rx_len -= off; memmove(c->rx, c->rx + off, c->rx_len); }
}

/* One non-blocking step. Returns true while the connection is still live. */
static bool conn_step(conn_t *c) {
    if (c->state != C_LIVE) return false;
    int err = 0; socklen_t el = sizeof(err);
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err) { conn_finish(c, true); return false; }
    if (c->ws_state != 1) take_out(c);
    while (c->ooff < c->olen) {
        ssize_t w = send(c->fd, c->obuf + c->ooff, c->olen - c->ooff, MSG_NOSIGNAL);
        if (w > 0) c->ooff += (size_t)w;
        else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN)) break;
        else if (w < 0 && errno != EINTR) { conn_finish(c, true); return false; }
    }
    if (c->ooff == c->olen) c->ooff = c->olen = 0;
    for (;;) {
        uint8_t buf[8192];
        ssize_t r = recv(c->fd, buf, sizeof(buf), 0);
        if (r > 0) feed_in(c, buf, (size_t)r);
        else if (r == 0) { conn_finish(c, true); return false; }
        else { if (errno == EINTR) continue;
               if (errno != EAGAIN && errno != EWOULDBLOCK) { conn_finish(c, true); return false; }
               break; }
    }
    if (c->ws_state == 1) return true;                  /* waiting for the 101 */
    if (c->sent_keyx && c->attacker) return true;       /* silent from here on */
    if (!cmt_p2p_sc_is_authenticated(&c->sc)) {
        size_t used = 0;
        if (c->in_len && cmt_p2p_sc_recv(&c->sc, c->in, c->in_len, &used) != CMT_OK) {
            conn_finish(c, false); return false;
        }
        if (used) { c->in_len -= used; memmove(c->in, c->in + used, c->in_len); }
        const cmt_p2p_sc_job_t *j;
        while ((j = cmt_p2p_sc_job(&c->sc)) != NULL) {
            const int kind = (int)j->kind;     /* the job is gone after job_done */
            int rc = cmt_p2p_sc_job_run(j, &c->host);
            if (cmt_p2p_sc_job_done(&c->sc, rc) != CMT_OK) { conn_finish(c, false); return false; }
            if (c->attacker && kind == CMT_P2P_SC_JOB_ENCAPS) {
                /* the KEYX is now in the machine's output: swap the ciphertext
                 * for random bytes (offset: 2-byte length prefix + type), send,
                 * and go silent — the node decapsulates and signs regardless */
                size_t n; const uint8_t *p = cmt_p2p_sc_out(&c->sc, &n);
                if (n == 3 + CMT_P2P_SC_KEM_CT_SIZE) {
                    uint8_t keyx[3 + CMT_P2P_SC_KEM_CT_SIZE];
                    memcpy(keyx, p, n);
                    nodus_random(keyx + 3, CMT_P2P_SC_KEM_CT_SIZE);
                    queue_bytes(c, keyx, n);
                    cmt_p2p_sc_out_consume(&c->sc, n);
                    c->sent_keyx = true;
                    return true;
                }
            }
        }
        take_out(c);
    }
    if (!cmt_p2p_sc_is_authenticated(&c->sc)) return true;
    /* Locally authenticated (the node's AUTHSIG verified): NOT yet proof that
     * the node opened this connection — the node opens only after it verified
     * OUR AUTHSIG. The sealed AUTHSIG left through take_out above; now one
     * sealed ping, then wait for the pong. */
    if (!c->pinged) {
        uint8_t token[NODUS_SESSION_TOKEN_LEN] = {0};
        uint8_t req[128], plain[160], sealed[CMT_P2P_SC_SEALED_FRAME_SIZE * 2];
        size_t rn = 0, written = 0;
        if (nodus_t2_ping(9, token, req, sizeof(req), &rn) != 0) { conn_finish(c, false); return false; }
        size_t pn = nodus_frame_encode(plain, sizeof(plain), req, (uint32_t)rn);
        if (!pn || cmt_p2p_sc_write(&c->sc, plain, pn, sealed, sizeof(sealed), &written) != CMT_OK || !written) {
            conn_finish(c, false); return false;
        }
        take_out(c);                 /* the AUTHSIG, if still in the output, goes first */
        queue_bytes(c, sealed, written);
        c->pinged = true;
    }
    if (c->in_len) {
        size_t cu = 0, pl = 0;
        if (cmt_p2p_sc_read(&c->sc, c->in, c->in_len, &cu, c->plain + c->plain_len,
                            sizeof(c->plain) - c->plain_len, &pl) != CMT_OK) {
            conn_finish(c, false); return false;
        }
        if (cu) { c->in_len -= cu; memmove(c->in, c->in + cu, c->in_len); }
        c->plain_len += pl;
        nodus_frame_t f;
        if (nodus_frame_decode(c->plain, c->plain_len, &f) > 0) {
            nodus_tier2_msg_t reply; memset(&reply, 0, sizeof(reply));
            bool pong = nodus_t2_decode(f.payload, f.payload_len, &reply) == 0 &&
                        reply.type == 'r' && reply.txn_id == 9;
            nodus_t2_msg_free(&reply);
            if (pong) c->authed = true;      /* answered: the node opened this connection */
            conn_finish(c, false);           /* sets t_end */
            return false;
        }
    }
    return true;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* unloaded per-kind job run times on this build */
static void unloaded_job_times(void) {
    static nodus_identity_t a, b;
    nodus_identity_generate(&a); nodus_identity_generate(&b);
    cmt_p2p_sc_host_t ha = {.ctx = &a, .sign = raw_sign, .verify = raw_verify};
    cmt_p2p_sc_host_t hb = {.ctx = &b, .sign = raw_sign, .verify = raw_verify};
    enum { REPS = 20 };
    double total[5] = {0}; unsigned count[5] = {0};
    for (int r = 0; r < REPS; ++r) {
        cmt_p2p_sc_t *i = calloc(1, sizeof(*i)), *s = calloc(1, sizeof(*s));
        if (!i || !s) { free(i); free(s); break; }
        cmt_p2p_sc_init(i, CMT_P2P_SC_ROLE_INITIATOR, &ha, a.pk.bytes, NULL, NULL,
                        CMT_P2P_SC_PROTO_VER_4001, chain);
        cmt_p2p_sc_init(s, CMT_P2P_SC_ROLE_RESPONDER, &hb, b.pk.bytes, b.mlkem_pk, b.mlkem_sk,
                        CMT_P2P_SC_PROTO_VER_4001, chain);
        for (int guard = 0; guard < 64; ++guard) {
            cmt_p2p_sc_t *m[2] = {i, s};
            for (int k = 0; k < 2; ++k) {
                cmt_p2p_sc_t *me = m[k], *other = m[1 - k];
                size_t n; const uint8_t *p = cmt_p2p_sc_out(me, &n);
                if (n) {
                    uint8_t tmp[CMT_P2P_SC_OUT_CAP]; memcpy(tmp, p, n);
                    cmt_p2p_sc_out_consume(me, n);
                    size_t off = 0, used = 0;
                    while (off < n) {
                        if (cmt_p2p_sc_is_authenticated(other)) break;
                        if (cmt_p2p_sc_recv(other, tmp + off, n - off, &used) != CMT_OK || !used) break;
                        off += used;
                    }
                }
                const cmt_p2p_sc_job_t *j;
                while ((j = cmt_p2p_sc_job(me)) != NULL) {
                    const int kind = (int)j->kind;
                    uint64_t t0 = (uint64_t)clock();
                    int rc = cmt_p2p_sc_job_run(j, me == i ? &ha : &hb);
                    double ms = (double)((uint64_t)clock() - t0) * 1000.0 / CLOCKS_PER_SEC;
                    if (kind >= 1 && kind <= 4) { total[kind] += ms; count[kind]++; }
                    if (cmt_p2p_sc_job_done(me, rc) != CMT_OK) break;
                }
            }
        }
        cmt_p2p_sc_clear(i); cmt_p2p_sc_clear(s); free(i); free(s);
    }
    static const char *names[5] = {"none", "encapsulate", "decapsulate", "sign", "verify"};
    printf("unloaded job run time (mean CPU ms per job, same build):");
    for (int k = 1; k <= 4; ++k)
        if (count[k]) printf("  %s %.2f (n=%u)", names[k], total[k] / count[k], count[k]);
    printf("\n");
    nodus_identity_clear(&a); nodus_identity_clear(&b);
}

static unsigned atoi_u(const char *s) { return (unsigned)atoi(s); }

int main(int argc, char **argv) {
    opts_t o = {.n = 64, .workers = 2, .depth = 64, .seconds = 30};
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (!strcmp(a, "--n") && i + 1 < argc) o.n = atoi_u(argv[++i]);
        else if (!strcmp(a, "--workers") && i + 1 < argc) o.workers = atoi_u(argv[++i]);
        else if (!strcmp(a, "--depth") && i + 1 < argc) o.depth = atoi_u(argv[++i]);
        else if (!strcmp(a, "--rate") && i + 1 < argc) o.rate = atoi_u(argv[++i]);
        else if (!strcmp(a, "--attack-count") && i + 1 < argc) o.attack_count = atoi_u(argv[++i]);
        else if (!strcmp(a, "--attack-rate") && i + 1 < argc) o.attack_rate = atoi_u(argv[++i]);
        else if (!strcmp(a, "--seconds") && i + 1 < argc) o.seconds = atoi_u(argv[++i]);
        else if (!strcmp(a, "--pattern") && i + 1 < argc) o.steady = !strcmp(argv[++i], "steady");
        else if (!strcmp(a, "--path") && i + 1 < argc) o.ws = !strcmp(argv[++i], "ws");
        else if (!strcmp(a, "--layout") && i + 1 < argc) {
            const char *l = argv[++i];
            if (!strcmp(l, "combined")) { o.split = 0; o.three = 0; }
            else if (!strcmp(l, "witness-split")) { o.split = 1; o.three = 0; }
            else if (!strcmp(l, "three")) { o.split = 1; o.three = 1; }
            else { fprintf(stderr, "bad layout: %s\n", l); return 2; }
        }
        else if (!strcmp(a, "--reconnect")) o.reconnect = 1;
        else { fprintf(stderr, "bad argument: %s\n", a); return 2; }
    }
    if (!o.n || !o.workers || !o.depth || o.n > 1000 || (o.steady && !o.rate) ||
        o.attack_count > ATK_MAX) {
        fprintf(stderr, "need n 1..1000, workers, depth; steady needs --rate; attack-count <= %d\n", ATK_MAX);
        return 2;
    }
    snprintf(g_dir, sizeof(g_dir), "/tmp/bench_4001_%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) return 2;
    if (o.three) {
        char idir[160];
        snprintf(idir, sizeof(idir), "%s/identity", g_dir);
        if (mkdir(idir, 0700) != 0) return 2;
    }
    nodus_identity_generate(&g_client_id);

    int wpipe[2] = {-1, -1}, npipe[2];
    pid_t wchild = -1;
    if (o.split) {
        if (pipe(wpipe) != 0) return 2;
        wchild = fork();
        if (wchild < 0) return 2;
        if (wchild == 0) { close(wpipe[0]); _exit(witness_child(wpipe[1])); }
        close(wpipe[1]);
        char r;
        if (read(wpipe[0], &r, 1) != 1) { fprintf(stderr, "the stand-in witness did not start\n"); return 1; }
    }
    if (pipe(npipe) != 0) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) { close(npipe[0]); _exit(node_child(&o, npipe[1])); }
    close(npipe[1]);
    char ready;
    if (read(npipe[0], &ready, 1) != 1) {
        fprintf(stderr, "the node did not start\n"); kill(child, SIGTERM); return 1;
    }
    pid_t schild = -1;
    if (o.three) {
        /* The real nodus-storage, next to this driver, on the identity the core
         * just created. Flags as stagef_spawn_storage gives them, without a
         * config file and without seeds (no peer, no DHT request: idle). */
        char exe[400], bin[420], peer[16], idir[160], log[160];
        ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (el <= 0) { fprintf(stderr, "cannot find the driver's own path\n"); kill(child, SIGTERM); return 1; }
        exe[el] = 0;
        char *slash = strrchr(exe, '/');
        if (slash) *slash = 0;
        snprintf(bin, sizeof(bin), "%s/nodus-storage", exe);
        snprintf(peer, sizeof(peer), "%d", PORT_BASE + 2);
        snprintf(idir, sizeof(idir), "%s/identity", g_dir);
        snprintf(log, sizeof(log), "%s/storage.log", g_dir);
        schild = fork();
        if (schild < 0) { kill(child, SIGTERM); return 2; }
        if (schild == 0) {
            int lf = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); close(lf); }
            execl(bin, bin, "--storage-external", "-b", "127.0.0.1", "-p", peer,
                  "-i", idir, "-d", g_dir, (char *)NULL);
            _exit(127);
        }
        char sockp[200]; struct stat sb;
        snprintf(sockp, sizeof(sockp), "%s/storage.sock", g_dir);
        int up = 0;
        for (int i = 0; i < 200 && !up; ++i) {      /* up to 10 s for the socket to exist */
            if (stat(sockp, &sb) == 0) { up = 1; break; }
            if (waitpid(schild, NULL, WNOHANG) == schild) break;
            usleep(50000);
        }
        if (!up) {
            fprintf(stderr, "nodus-storage did not come up (%s; log %s)\n", bin, log);
            kill(child, SIGTERM); return 1;
        }
    }

    printf("bench_4001_session_load: n=%u workers=%u depth=%u path=%s layout=%s pattern=%s rate=%u "
           "attack_count=%u attack_rate=%u reconnect=%s build=%s\n",
           o.n, o.workers, o.depth, o.ws ? "ws" : "plain", o.three ? "three" : o.split ? "witness-split" : "combined",
           o.steady ? "steady" : "burst", o.rate, o.attack_count, o.attack_rate,
           o.reconnect ? "yes" : "no",
#ifdef NDEBUG
           "release"
#else
           "NOT-release"
#endif
    );
    if (o.split)
        printf("layout note: separate stand-in witness PROCESS (ipc_status only, no consensus/4004/block work); "
               "%s\n", o.three ? "the real nodus-storage process runs idle beside it (no DHT traffic, no peers); "
                                  "the node core has no in-process DHT"
                                : "DHT/storage stays in the node process");
    unloaded_job_times();
    usleep(200000);

    conn_t *honest = calloc(o.n, sizeof(conn_t));
    conn_t *atk = calloc(ATK_MAX, sizeof(conn_t));
    if (!honest || !atk) return 2;
    unsigned started = 0, atk_started = 0, finished = 0, atk_reconnects = 0;
    uint64_t t0 = mono_ms(), cpu0 = cpu_ms_self(), next_atk = t0;
    /* a standing attacker population, all at once */
    for (unsigned i = 0; i < o.attack_count; ++i)
        if (conn_open(&atk[atk_started], atk_started, true, o.ws)) atk_started++;
    unsigned standing = atk_started;
    while (mono_ms() - t0 < (uint64_t)o.seconds * 1000u && finished < o.n) {
        uint64_t now = mono_ms();
        unsigned want = o.steady ? (unsigned)(((now - t0) * o.rate) / 1000u) + 1u : o.n;
        while (started < o.n && started < want) {
            if (!conn_open(&honest[started], started, false, o.ws)) { honest[started].state = C_DONE; honest[started].t_end = now; }
            started++;
        }
        if (o.attack_rate) {
            while (next_atk <= now && atk_started < ATK_MAX) {
                if (conn_open(&atk[atk_started], atk_started, true, o.ws)) atk_started++;
                else break;
                next_atk += 1000u / o.attack_rate ? 1000u / o.attack_rate : 1u;
            }
        }
        finished = 0;
        for (unsigned i = 0; i < started; ++i) { conn_step(&honest[i]); if (honest[i].state == C_DONE) finished++; }
        for (unsigned i = 0; i < atk_started; ++i) {
            conn_step(&atk[i]);
            /* reconnection: the node closed this attacker -> a fresh one in its place */
            if (o.reconnect && atk[i].state == C_DONE && !atk[i].replaced && atk_started < ATK_MAX) {
                atk[i].replaced = true;      /* one replacement per closed attacker */
                if (conn_open(&atk[atk_started], atk_started, true, o.ws)) { atk_started++; atk_reconnects++; }
            }
        }
        usleep(500);
    }
    uint64_t driver_cpu = cpu_ms_self() - cpu0, wall = mono_ms() - t0;

    unsigned opened = 0, early_closed = 0, deadline = 0, unfinished = 0, over3s = 0;
    uint64_t *times = calloc(o.n, sizeof(uint64_t)); unsigned nt = 0;
    for (unsigned i = 0; i < started; ++i) {
        conn_t *c = &honest[i];
        uint64_t dt = c->t_end > c->t_start ? c->t_end - c->t_start : 0;
        if (c->state != C_DONE) unfinished++;
        else if (c->authed) { opened++; times[nt++] = dt; if (dt >= HANDSHAKE_LIMIT_MS) over3s++; }
        else if (dt >= HANDSHAKE_LIMIT_MS) deadline++;
        else early_closed++;
    }
    qsort(times, nt, sizeof(uint64_t), cmp_u64);
    printf("offered: honest %u (%s)  attackers %u started (%u standing + rate %u/s, reconnections %u) over %llu ms\n",
           started, o.steady ? "steady" : "burst", atk_started, standing, o.attack_rate, atk_reconnects,
           (unsigned long long)wall);
    printf("honest: started %u  opened %u  closed<3s-without-opening %u  closed>=3s %u  unfinished %u\n",
           started, opened, early_closed, deadline, unfinished);
    if (nt)
        printf("honest connect->authenticated wall ms: min %llu p50 %llu p95 %llu p99 %llu max %llu  over-3s %u (of %u)\n",
               (unsigned long long)times[0], (unsigned long long)times[nt / 2],
               (unsigned long long)times[(nt * 95) / 100 >= nt ? nt - 1 : (nt * 95) / 100],
               (unsigned long long)times[(nt * 99) / 100 >= nt ? nt - 1 : (nt * 99) / 100],
               (unsigned long long)times[nt - 1], over3s, nt);

    for (unsigned i = 0; i < started; ++i) if (honest[i].state == C_LIVE) conn_finish(&honest[i], false);
    for (unsigned i = 0; i < atk_started; ++i) if (atk[i].state == C_LIVE) conn_finish(&atk[i], false);
    kill(child, SIGTERM);
    static char rep[65536];
    ssize_t rn = 0;
    for (;;) {                                    /* until the child closes its end */
        ssize_t r = read(npipe[0], rep + rn, sizeof(rep) - 1 - (size_t)rn);
        if (r <= 0) break;
        rn += r;
    }
    rep[rn > 0 ? rn : 0] = 0;
    int status = 0; struct rusage cru;
    wait4(child, &status, 0, &cru);
    double scpu = 0;
    if (o.three) {
        struct rusage sru;
        kill(schild, SIGTERM);
        if (wait4(schild, &status, 0, &sru) == schild) scpu = ts_ms(&sru.ru_utime) + ts_ms(&sru.ru_stime);
    }
    double wcpu = 0;
    if (o.split) {
        kill(wchild, SIGTERM);
        char wr[64] = {0};
        if (read(wpipe[0], wr, sizeof(wr) - 1) > 0) wcpu = atof(wr);
        waitpid(wchild, &status, 0);
    }
    unsigned long long peak = 0, sum = 0, samples = 0, st_started = 0, st_opened = 0, st_refused = 0, st_deadline = 0;
    double node_cpu = 0; char vm[64] = "unknown";
    if (rn > 0 && sscanf(rep, "%llu %llu %llu %lf %llu %llu %llu %llu|%63[^|]", &peak, &sum, &samples,
                         &node_cpu, &st_started, &st_opened, &st_refused, &st_deadline, vm) >= 8) {
        printf("node counters: sessions started %llu  opened %llu  key-exchange jobs refused (queue full) %llu  "
               "past the 3 s deadline %llu\n", st_started, st_opened, st_refused, st_deadline);
        /* honest connections are closed only after the node's pong, so the node's
         * count may exceed the honest count only by the connections it opened
         * whose pong had not arrived at the end of the run (header) */
        if (st_opened == opened)
            printf("consistency: node opened %llu = honest opened %u\n", st_opened, opened);
        else
            printf("consistency: node opened %llu, honest opened %u, honest unfinished %u -- %s\n",
                   st_opened, opened, unfinished,
                   (st_opened >= opened && st_opened - opened <= unfinished)
                       ? "the difference is within the unfinished honest connections (time limit)"
                       : "MISMATCH beyond the unfinished connections: do not use this run's open counts");
        printf("node job queue (inbound class, sampled every ms): peak %llu  mean %.2f over %llu samples\n",
               peak, samples ? (double)sum / (double)samples : 0.0, samples);
        /* per-kind job run times under load: "<vm>|" is followed by 4 x (count total_ns max_ns) */
        const char *jp = strchr(rep, '|');
        jp = jp ? strchr(jp + 1, '|') : NULL;
        static const char *names[5] = {"none", "encapsulate", "decapsulate", "sign", "verify"};
        printf("job run time under load (wall ms around cmt_p2p_sc_job_run, queue wait excluded):");
        for (int k = 1; k <= 4 && jp; ++k) {
            unsigned long long cnt, tot, mx; int used = 0;
            if (sscanf(jp + 1, "%llu %llu %llu%n", &cnt, &tot, &mx, &used) != 3) break;
            jp += 1 + used;
            if (cnt) printf("  %s mean %.2f max %.2f (n=%llu)", names[k],
                            (double)tot / (double)cnt / 1e6, (double)mx / 1e6, cnt);
            else printf("  %s n=0", names[k]);
        }
        printf("\n");

        /* accept (or Upgrade) to open, measured at the node's open */
        unsigned long long hist[NODUS_INTER_OPEN_BUCKETS] = {0}, o_total = 0, o_max = 0, o_count = 0;
        unsigned long long nw = 0;
        static unsigned long long wmax[OCC_WINDOWS], wsum[OCC_WINDOWS], wn[OCC_WINDOWS];
        bool have_open = false, have_win = false;
        if (jp) {
            char *e = NULL;
            while (*jp == ' ') jp++;
            if (*jp == 'O') {
                jp++; o_total = strtoull(jp, &e, 10); jp = e; o_max = strtoull(jp, &e, 10); jp = e;
                while (*jp == ' ') jp++;
                if (*jp == 'H') {
                    jp++;
                    for (unsigned b = 0; b < NODUS_INTER_OPEN_BUCKETS; ++b) {
                        hist[b] = strtoull(jp, &e, 10); jp = e; o_count += hist[b];
                    }
                    have_open = true;
                }
            }
            while (*jp == ' ') jp++;
            if (have_open && *jp == 'W') {
                jp++; nw = strtoull(jp, &e, 10); jp = e;
                if (nw > OCC_WINDOWS) nw = OCC_WINDOWS;
                for (unsigned long long w = 0; w < nw; ++w) {
                    wmax[w] = strtoull(jp, &e, 10); jp = e;
                    wsum[w] = strtoull(jp, &e, 10); jp = e;
                    wn[w] = strtoull(jp, &e, 10); jp = e;
                }
                have_win = true;
            }
        }
        if (have_open) {
            if (!o_count) printf("accept-to-open at the node: no session opened\n");
            else {
                unsigned long long acc = 0, p50 = 0, p95 = 0, p99 = 0;
                for (unsigned b = 0; b < NODUS_INTER_OPEN_BUCKETS; ++b) {
                    acc += hist[b];
                    const unsigned long long edge = (unsigned long long)(b + 1) * NODUS_INTER_OPEN_BUCKET_MS;
                    if (!p50 && acc * 100 >= o_count * 50) p50 = edge;
                    if (!p95 && acc * 100 >= o_count * 95) p95 = edge;
                    if (!p99 && acc * 100 >= o_count * 99) p99 = edge;
                }
                printf("accept-to-open at the node (ms, module deadline clock; n=%llu): mean %.1f max %llu  "
                       "p50 <= %llu  p95 <= %llu  p99 <= %llu (bucket upper edges, %u ms buckets; the last "
                       "bucket is >= %u ms)\n", o_count, (double)o_total / (double)o_count, o_max, p50, p95, p99,
                       NODUS_INTER_OPEN_BUCKET_MS, (NODUS_INTER_OPEN_BUCKETS - 1) * NODUS_INTER_OPEN_BUCKET_MS);
                printf("accept-to-open histogram (bucket start ms: count, nonzero only):");
                for (unsigned b = 0; b < NODUS_INTER_OPEN_BUCKETS; ++b)
                    if (hist[b]) printf("  %u: %llu", b * NODUS_INTER_OPEN_BUCKET_MS, hist[b]);
                printf("\n");
            }
        }
        if (have_win && nw) {
            /* at most ~60 lines: merge consecutive windows (max of max, mean of the samples) */
            unsigned long long per = (nw + 59) / 60;
            printf("node job queue over time (inbound class; each row %llu ms from node ready, 1 ms samples):\n",
                   per * OCC_WINDOW_MS);
            for (unsigned long long w0 = 0; w0 < nw; w0 += per) {
                unsigned long long mx = 0, sm = 0, cn = 0;
                for (unsigned long long w = w0; w < w0 + per && w < nw; ++w) {
                    if (wmax[w] > mx) mx = wmax[w];
                    sm += wsum[w]; cn += wn[w];
                }
                printf("  t=%6llu ms  max %3llu  mean %6.2f\n", w0 * OCC_WINDOW_MS, mx,
                       cn ? (double)sm / (double)cn : 0.0);
            }
        }
    }
    printf("processor time: node child %.0f ms (rusage)%s, driver %llu ms (process CPU), wall %llu ms\n",
           node_cpu, o.split ? " (stand-in witness process measured apart below)" : "",
           (unsigned long long)driver_cpu, (unsigned long long)wall);
    if (o.split) printf("processor time: stand-in witness process %.0f ms\n", wcpu);
    if (o.three) printf("processor time: nodus-storage process %.0f ms (idle: no DHT traffic)\n", scpu);
    printf("node resident memory peak (VmHWM): %s\n", vm);
    char cmd[128]; snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) fprintf(stderr, "cleanup of %s failed\n", g_dir);
    free(honest); free(atk); free(times);
    nodus_identity_clear(&g_client_id);
    return 0;
}
