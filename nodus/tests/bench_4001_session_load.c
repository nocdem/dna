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
 * nodus-server's client port; the node's chain id is set on the server
 * directly, no witness) polled by that child alone, with the 4001 line's
 * queue depth and worker count taken from the command line. The parent opens
 * raw-machine initiators (cmt_p2p_sc_* driven directly) from DISTINCT
 * loopback source addresses (127.0.0.0/8 is all local, `ip route show table
 * local`), so the 20-per-IP limit is not what is measured:
 *   - honest clients: complete the handshake; arrival as one burst or at a
 *     steady rate;
 *   - attackers (--attack-rate per second, replaced as the node closes them):
 *     a valid HELLO, then a KEYX whose ciphertext is replaced by random bytes
 *     (decapsulation of an invalid ciphertext still returns success, so the
 *     node decapsulates and signs), and then silence. Plain 4001 path only;
 *     the WebSocket path is not driven by this file (see below).
 *
 * Recorded and printed (one block per run, parameters first):
 *   honest: connections, opened, closed before 3 s without opening (a full
 *     queue or an error), closed at/after 3 s (deadline), unfinished; the
 *     wall time from TCP connect to the client's authenticated state: min,
 *     p50, p95, p99, max, count over 3 s. The driver's own processor time is
 *     NEVER subtracted from these wall times (driver and node share the
 *     machine).
 *   node child: job queue occupancy over time (peak and mean of the inbound
 *     class, sampled every 2 ms), its processor time (wait4 rusage) and its
 *     peak resident memory (VmHWM from /proc/<pid>/status), apart from the
 *     driver's (CLOCK_PROCESS_CPUTIME_ID of the parent).
 *   unloaded per-kind job run times (decapsulate, sign, verify): a loop over
 *     cmt_p2p_sc_job_run on this build, before the load starts. The node's
 *     per-job times UNDER load are not instrumented by this file (the module
 *     has no hook for them): the load figures above are the observable.
 *
 * Not covered: the WebSocket path (this driver speaks plain 4001 only), the
 * separate core / storage / witness process layout of the live nodes (the node
 * here is the combined server with no witness workload), mobile browsers.
 * Conclusions are limited to what a run measured; a reduced load proves logic,
 * not production magnitude (CLAUDE.md TESTS).
 *
 * Usage: bench_4001_session_load --n N --workers W --depth D
 *          [--pattern burst|steady] [--rate R]        honest arrivals, R/s
 *          [--attack-rate A] [--seconds S]            attackers/s, run length
 * Defaults: n 64, workers 2, depth 64, burst, no attackers, 30 s limit.
 * Fixed ports 15510-15515 and a /tmp/bench_4001_<pid> directory (removed).
 * Run it alone: it uses all CPUs and must not overlap builds, browser tests
 * or the harness (CLAUDE.md SESSIONS). Production build flags (Release).
 * How it can mislead: the driver's initiators are single-threaded and do their
 * own ML-KEM/ML-DSA work, so at large N the driver, not the node, can be the
 * slow side; compare the two processor times printed.
 */
#define _GNU_SOURCE 1
#include "server/nodus_server.h"
#include "server/nodus_inter_session.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_wire.h"

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

#define PORT_BASE 15510
#define HANDSHAKE_LIMIT_MS 3000

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
    unsigned n, workers, depth, rate, attack_rate, seconds;
    int steady;
} opts_t;

/* ── the node child ──────────────────────────────────────────────── */
static volatile sig_atomic_t g_child_stop;
static void on_term(int s) { (void)s; g_child_stop = 1; }

typedef struct { uint64_t peak, sum, samples; } occupancy_t;

static int node_child(const opts_t *o, int report_fd) {
    static nodus_server_t srv;
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port = PORT_BASE; config.tcp_port = PORT_BASE + 1;
    config.peer_port = PORT_BASE + 2; config.ch_port = PORT_BASE + 3;
    config.witness_port = PORT_BASE + 4;
    config.require_peer_auth = true;
    config.client_session_depth = o->depth;       /* the line under test */
    config.client_session_workers = o->workers;
    snprintf(config.data_path, sizeof(config.data_path), "/tmp/bench_4001_%d", (int)getppid());
    if (nodus_server_init(&srv, &config) != 0) return 1;
    memcpy(srv.inter_chain_id, chain, sizeof(chain));
    srv.inter_chain_known = srv.inter_chain_id_valid = true;
    /* "ready": the node's fingerprint, so the parent knows the child is up */
    if (write(report_fd, srv.identity.node_id.bytes, NODUS_KEY_BYTES) != NODUS_KEY_BYTES) return 1;
    signal(SIGTERM, on_term);
    occupancy_t occ = {0};
    uint64_t last = 0;
    while (!g_child_stop) {
        nodus_tcp_poll(&srv.tcp, 1);
        uint64_t now = mono_ms();
        if (now != last) {
            last = now;
            uint64_t q = nodus_inter_session_job_queued(srv.client_session, false);
            if (q > occ.peak) occ.peak = q;
            occ.sum += q; occ.samples++;
        }
    }
    struct rusage ru; getrusage(RUSAGE_SELF, &ru);
    char vm[64] = "unknown";
    FILE *st = fopen("/proc/self/status", "r");
    char line[256];
    while (st && fgets(line, sizeof(line), st))
        if (!strncmp(line, "VmHWM:", 6)) { snprintf(vm, sizeof(vm), "%s", line + 6); break; }
    if (st) fclose(st);
    size_t ln = strlen(vm); while (ln && (vm[ln-1] == '\n' || vm[ln-1] == ' ')) vm[--ln] = 0;
    char out[256];
    int n = snprintf(out, sizeof(out), "%llu %llu %llu %.1f %s",
                     (unsigned long long)occ.peak,
                     (unsigned long long)occ.sum, (unsigned long long)occ.samples,
                     ts_ms(&ru.ru_utime) + ts_ms(&ru.ru_stime), vm);
    if (write(report_fd, out, (size_t)n) < 0) return 1;
    nodus_server_close(&srv);
    return 0;
}

/* ── raw-machine initiators ──────────────────────────────────────── */
enum { C_IDLE = 0, C_LIVE, C_DONE };
typedef struct {
    int state, fd;
    bool attacker, sent_keyx, authed, closed;
    uint64_t t_start, t_end;
    cmt_p2p_sc_t sc;
    cmt_p2p_sc_host_t host;
    uint8_t obuf[2 * CMT_P2P_SC_OUT_CAP]; size_t olen, ooff;
    uint8_t in[2 * CMT_P2P_SC_OUT_CAP]; size_t in_len;
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

static bool conn_open(conn_t *c, unsigned index, bool attacker) {
    memset(c, 0, sizeof(*c));
    c->attacker = attacker;
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) return false;
    struct sockaddr_in src, dst = {.sin_family = AF_INET, .sin_port = htons(PORT_BASE + 1)};
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
    c->t_start = mono_ms(); c->state = C_LIVE;
    return true;
}

static void conn_finish(conn_t *c, bool closed_by_peer) {
    c->t_end = mono_ms(); c->closed = closed_by_peer; c->state = C_DONE;
    close(c->fd); cmt_p2p_sc_clear(&c->sc);
}

static void take_out(conn_t *c) {
    size_t n; const uint8_t *p = cmt_p2p_sc_out(&c->sc, &n);
    if (n && c->olen + n <= sizeof(c->obuf)) {
        memcpy(c->obuf + c->olen, p, n); c->olen += n;
        cmt_p2p_sc_out_consume(&c->sc, n);
    }
}

/* One non-blocking step. Returns true while the connection is still live. */
static bool conn_step(conn_t *c) {
    if (c->state != C_LIVE) return false;
    /* a connect still in progress reports through SO_ERROR */
    int err = 0; socklen_t el = sizeof(err);
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err) { conn_finish(c, true); return false; }
    take_out(c);
    while (c->ooff < c->olen) {
        ssize_t w = send(c->fd, c->obuf + c->ooff, c->olen - c->ooff, MSG_NOSIGNAL);
        if (w > 0) c->ooff += (size_t)w;
        else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN)) break;
        else if (w < 0 && errno != EINTR) { conn_finish(c, true); return false; }
    }
    if (c->ooff == c->olen) c->ooff = c->olen = 0;
    for (;;) {
        if (c->in_len >= sizeof(c->in)) break;
        ssize_t r = recv(c->fd, c->in + c->in_len, sizeof(c->in) - c->in_len, 0);
        if (r > 0) c->in_len += (size_t)r;
        else if (r == 0) { conn_finish(c, true); return false; }
        else { if (errno == EINTR) continue;
               if (errno != EAGAIN && errno != EWOULDBLOCK) { conn_finish(c, true); return false; }
               break; }
    }
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
                if (n == 3 + CMT_P2P_SC_KEM_CT_SIZE && c->olen + n <= sizeof(c->obuf)) {
                    memcpy(c->obuf + c->olen, p, n);
                    nodus_random(c->obuf + c->olen + 3, CMT_P2P_SC_KEM_CT_SIZE);
                    c->olen += n;
                    cmt_p2p_sc_out_consume(&c->sc, n);
                    c->sent_keyx = true;
                    return true;
                }
            }
        }
        take_out(c);
        if (cmt_p2p_sc_is_authenticated(&c->sc)) {
            c->authed = true; c->t_end = mono_ms();
            /* the node opens after verifying our AUTHSIG; the client side is
             * "authenticated" once the node's AUTHSIG verified: done */
            conn_finish(c, false);
            c->state = C_DONE;
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
        /* pump the two machines against each other, timing every job */
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
                    uint64_t t0 = (uint64_t)clock();
                    int rc = cmt_p2p_sc_job_run(j, me == i ? &ha : &hb);
                    double ms = (double)((uint64_t)clock() - t0) * 1000.0 / CLOCKS_PER_SEC;
                    if (j->kind <= CMT_P2P_SC_JOB_VERIFY) { total[j->kind] += ms; count[j->kind]++; }
                    if (cmt_p2p_sc_job_done(me, rc) != CMT_OK) break;
                }
            }
        }
        cmt_p2p_sc_clear(i); cmt_p2p_sc_clear(s); free(i); free(s);
    }
    static const char *names[5] = {"none", "encapsulate", "decapsulate", "sign", "verify"};
    printf("unloaded job run time (mean over %u..%u runs, CPU ms):", count[2], count[3]);
    for (int k = 1; k <= 4; ++k)
        if (count[k]) printf("  %s %.2f", names[k], total[k] / count[k]);
    printf("\n");
    nodus_identity_clear(&a); nodus_identity_clear(&b);
}

int main(int argc, char **argv) {
    opts_t o = {.n = 64, .workers = 2, .depth = 64, .rate = 0, .attack_rate = 0, .seconds = 30};
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) o.n = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--workers") && i + 1 < argc) o.workers = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--depth") && i + 1 < argc) o.depth = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rate") && i + 1 < argc) o.rate = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--attack-rate") && i + 1 < argc) o.attack_rate = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) o.seconds = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pattern") && i + 1 < argc) o.steady = !strcmp(argv[++i], "steady");
        else { fprintf(stderr, "bad argument: %s\n", argv[i]); return 2; }
    }
    if (!o.n || !o.workers || !o.depth || o.n > 1000 || (o.steady && !o.rate)) {
        fprintf(stderr, "need n 1..1000, workers, depth; steady needs --rate\n"); return 2;
    }
    char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/bench_4001_%d", (int)getpid());
    if (mkdir(dir, 0700) != 0) return 2;
    nodus_identity_generate(&g_client_id);

    int pipefd[2];
    if (pipe(pipefd) != 0) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) { close(pipefd[0]); _exit(node_child(&o, pipefd[1])); }
    close(pipefd[1]);
    uint8_t node_fp[NODUS_KEY_BYTES];
    if (read(pipefd[0], node_fp, sizeof(node_fp)) != (ssize_t)sizeof(node_fp)) {
        fprintf(stderr, "the node did not start\n"); kill(child, SIGTERM); return 1;
    }
    (void)node_fp;   /* the raw initiators accept any responder: the trusted list is not under test */

    printf("bench_4001_session_load: n=%u workers=%u depth=%u pattern=%s rate=%u attack_rate=%u build=%s\n",
           o.n, o.workers, o.depth, o.steady ? "steady" : "burst", o.rate, o.attack_rate,
#ifdef NDEBUG
           "release"
#else
           "NOT-release"
#endif
    );
    unloaded_job_times();
    usleep(200000);

    conn_t *honest = calloc(o.n, sizeof(conn_t));
    enum { ATK_MAX = 4096 };
    conn_t *atk = calloc(ATK_MAX, sizeof(conn_t));
    if (!honest || !atk) return 2;
    unsigned started = 0, atk_started = 0, finished = 0;
    uint64_t t0 = mono_ms(), cpu0 = cpu_ms_self(), next_atk = t0;
    while (mono_ms() - t0 < (uint64_t)o.seconds * 1000u && finished < o.n) {
        uint64_t now = mono_ms();
        unsigned want = o.steady ? (unsigned)(((now - t0) * o.rate) / 1000u) + 1u : o.n;
        while (started < o.n && started < want) {
            if (!conn_open(&honest[started], started, false)) { honest[started].state = C_DONE; honest[started].t_end = now; }
            started++;
        }
        if (o.attack_rate) {
            while (next_atk <= now && atk_started < ATK_MAX) {
                if (conn_open(&atk[atk_started], atk_started, true)) atk_started++;
                else break;
                next_atk += 1000u / o.attack_rate ? 1000u / o.attack_rate : 1u;
            }
        }
        finished = 0;
        for (unsigned i = 0; i < started; ++i) { conn_step(&honest[i]); if (honest[i].state == C_DONE) finished++; }
        for (unsigned i = 0; i < atk_started; ++i) conn_step(&atk[i]);
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
    printf("honest: started %u  opened %u  closed<3s-without-opening %u  closed>=3s %u  unfinished %u\n",
           started, opened, early_closed, deadline, unfinished);
    if (nt)
        printf("connect->authenticated wall ms: min %llu p50 %llu p95 %llu p99 %llu max %llu  over-3s %u (of %u)\n",
               (unsigned long long)times[0], (unsigned long long)times[nt / 2],
               (unsigned long long)times[(nt * 95) / 100 >= nt ? nt - 1 : (nt * 95) / 100],
               (unsigned long long)times[(nt * 99) / 100 >= nt ? nt - 1 : (nt * 99) / 100],
               (unsigned long long)times[nt - 1], over3s, nt);
    printf("attackers started %u over %llu ms (offered %u/s)\n", atk_started,
           (unsigned long long)wall, o.attack_rate);

    for (unsigned i = 0; i < started; ++i) if (honest[i].state == C_LIVE) conn_finish(&honest[i], false);
    for (unsigned i = 0; i < atk_started; ++i) if (atk[i].state == C_LIVE) conn_finish(&atk[i], false);
    kill(child, SIGTERM);
    char rep[256] = {0};
    ssize_t rn = read(pipefd[0], rep, sizeof(rep) - 1);
    int status = 0; struct rusage cru;
    wait4(child, &status, 0, &cru);
    unsigned long long peak = 0, sum = 0, samples = 0; double node_cpu = 0; char vm[64] = "unknown";
    if (rn > 0 && sscanf(rep, "%llu %llu %llu %lf %63[^\n]", &peak, &sum, &samples, &node_cpu, vm) >= 4)
        printf("node job queue (inbound class, sampled every ms): peak %llu  mean %.2f over %llu samples\n",
               peak, samples ? (double)sum / (double)samples : 0.0, samples);
    printf("processor time: node child %.0f ms (rusage), driver %llu ms (process CPU), wall %llu ms\n",
           node_cpu, (unsigned long long)driver_cpu, (unsigned long long)wall);
    printf("node resident memory peak (VmHWM): %s\n", vm);
    char cmd[96]; snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) fprintf(stderr, "cleanup of %s failed\n", dir);
    free(honest); free(atk); free(times);
    nodus_identity_clear(&g_client_id);
    return 0;
}
