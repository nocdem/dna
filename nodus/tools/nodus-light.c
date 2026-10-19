/**
 * @file nodus/tools/nodus-light.c
 * @brief nodus-light — the light client as a program: it follows the
 *        Nodus chain over pinned TCP 4001 sessions with the cometbft
 *        light client port (shared/dnac/cmt_light_client.h), executing
 *        no block.
 *
 * Usage:
 *   nodus-light run --data <dir> [--trust-height H --trust-hash HEX]
 *                   [--node host:port:pinfp]... [--interval S] [--chain-id HEX]
 *   nodus-light status --data <dir> [--chain-id HEX]
 *   nodus-light clear-attack --data <dir> [--node host:port:pinfp]... [--chain-id HEX]
 *   (--chain-id: 64 hex; default the compiled testnet chain — another chain,
 *    e.g. a local harness or a new genesis, passes its id with its --node list)
 *
 * ── WHAT IT IS BUILT ON ────────────────────────────────────────────────
 *   · the light client (cmt_light_client.{h,c}) with its detector, the
 *     SQLite light store (cmt_light_store.{h,c}) and the pinned provider
 *     over `dnac_light_block` (nodus/src/client/nodus_light_provider.h).
 *   · ONE nodus_client_t per node, each with exactly ONE server and that
 *     server's key pin; the provider refuses an unpinned client (Kurultay
 *     #25 item 8, "never an unpinned provider"). The provider identity the
 *     light client counts agreement by is the pin (item 9 R2).
 *   · the session's own identity is a fresh ML-DSA-87 key generated in
 *     memory for each run and never written: it only authenticates THIS
 *     client to the node; trust comes from the pins and the light client's
 *     checks, never from it.
 *
 * ── GOVERNING RECORDS ──────────────────────────────────────────────────
 * docs/plans/decisions/2026-10-16-kurultay-25-summary.md:
 *   · K25-1 trust root = BOTH the release default checkpoint
 *     (nodus_light_checkpoint.h — empty in this build) AND operator input
 *     (--trust-height / --trust-hash, from any source the operator
 *     chooses). The "≥ 2 peers agree" init rule is a consistency check
 *     inside the library, never the root.
 *   · K25-2 trusting period 48 h (NODUS_LIGHT_TRUSTING_PERIOD_NS).
 *   · item 8 pinned 4001 providers only.
 *   · item 9 / D20 ONE client object per store prefix: `run` and
 *     `clear-attack` hold an exclusive lock on <dir> for their lifetime
 *     (qgp_platform_acquire_identity_lock — <dir>/identity.lock), so two
 *     processes can never open two client objects on the same store.
 *   · K25-10 a detected attack locks the client until the operator runs
 *     `clear-attack`; `run` keeps calling Update while locked, because a
 *     record whose store write failed is written again at the start of
 *     every locked call (cmt_light_client.h D20).
 * docs/plans/decisions/2026-10-16-dnac-light-block-rpc.md — the RPC.
 *
 * ── THE STORE ──────────────────────────────────────────────────────────
 * <dir>/light.db, one SQLite file; the store prefix is the 32-byte chain
 * id, so a file is bound to one chain.
 *
 * ── THE CLOCK ──────────────────────────────────────────────────────────
 * `now` for the light client is this machine's wall clock (C11
 * timespec_get, UTC) — what cometbft's light client takes from
 * time.Now(). It decides only what THIS light client trusts and when it
 * calls again; it is node-local and on no consensus path. The loop's
 * waits (the Update interval, the reconnect pacing) are on the monotonic
 * clock (nodus_time_mono_ms) and decide nothing.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here enters a block, a vote, a state root or replication.
 * Nodes are visited in table order; the primary is the first that
 * connects at start.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include "client/nodus_light_provider.h"
#include "transport/nodus_tcp.h"            /* nodus_time_mono_ms          */
#include "dnac/cmt_block.h"                 /* CMT_BLOCK_PROTOCOL,
                                               cmt_header_hash            */
#include "dnac/cmt_light_block.h"
#include "dnac/cmt_light_client.h"
#include "dnac/cmt_light_detector.h"        /* the attack record's fields  */
#include "dnac/cmt_light_store.h"
#include "dnac/cmt_time.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_safe_string.h"   /* unsafe-string poison guard  */
#include "nodus_light_checkpoint.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "NODUS_LIGHT"

/* ── constants ───────────────────────────────────────────────────────── */

/** K25-2 (operator 2026-10-16, "48 saat"): the trusting period, an
 *  operational freshness limit (not a safety bound — nothing punishes a
 *  double signer today, BUGS Z-12). Go time.Duration = nanoseconds. */
#define NODUS_LIGHT_TRUSTING_PERIOD_NS ((int64_t)48 * 3600 * 1000000000LL)

/* The four caps of cmt_light_client.h D3, which have NO default.
 *
 * MEMORY is bounded by max_verify_steps alone: one forward verification
 * keeps about 2 light-block buffers per verify step, and one buffer is
 * sizeof(cmt_light_block_buf_t) = 945 856 bytes (cmt_light_client.h D3,
 * read there from a compile-time diagnostic), so ~1.8 MiB per step.
 *
 * max_verify_steps = 32 → at most ~58 MiB per Update, well under 100 MiB.
 *   Skipping verification bisects at 9/16 (client.go:28-32): across the
 *   48 h trusting period (~35 000 blocks at a ~5 s pace) the bisection
 *   depth to reach any height is ~16 when the trusted set keeps 1/3 of
 *   the power, so 32 leaves the other half for re-runs after a primary
 *   replacement (counted against the same cap, D3). Reaching it is a
 *   named refusal (CAP_VERIFY_STEPS), never a silent stop. */
#define NODUS_LIGHT_MAX_VERIFY_STEPS    32u
/* max_trace_len = 64: the trace holds pointers into the pool, not
 *   buffers (D3), so it costs nothing; a skipping trace has at most
 *   verify steps + 1 entries, so 2 × steps is never the binding cap.
 *   (Sequential mode, where the trace is the whole gap, is not used.) */
#define NODUS_LIGHT_MAX_TRACE_LEN       64u
/* max_skipping_cache = 64: the bisection cache holds pointers; Q1
 *   appends a fetched pivot TWICE (client.go:754 and :765), so it needs
 *   2 × max_verify_steps to never bind before the step cap does. */
#define NODUS_LIGHT_MAX_SKIPPING_CACHE  64u
/* max_backwards_steps = 1024: a backwards walk uses four buffers whatever
 *   its length (D3), so this is a TIME cap, not a memory cap: 1024
 *   fetches at a node's 4/s dnac_light_block limit
 *   (NODUS_LIGHT_BLOCK_RATE_PER_SEC) is ~4.3 minutes. `run` only calls
 *   Update, which never walks backwards; the value is set because the
 *   library refuses a zero cap. */
#define NODUS_LIGHT_MAX_BACKWARDS_STEPS 1024u
/* max_clock_drift and max_block_lag are the reference defaults set by
 * cmt_light_client_options_default: 10 s each (client.go:38, :41 —
 * CMT_LIGHT_CLIENT_DEFAULT_MAX_CLOCK_DRIFT / _MAX_BLOCK_LAG). The lagging
 * witness wait is 2 × drift + lag = 30 s (detector.go:168). */

/** Default Update interval, seconds. */
#define NODUS_LIGHT_DEFAULT_INTERVAL_S  10u
#define NODUS_LIGHT_MAX_INTERVAL_S      86400u
/** The loop sleeps in slices so a stop request is seen promptly. */
#define NODUS_LIGHT_SLEEP_SLICE_MS      200u
/** A node that could not be reached at start has no read thread and so
 *  no auto-reconnect (nodus_client_connect, nodus_client.c); the loop
 *  tries it again at most this often. */
#define NODUS_LIGHT_RETRY_CONNECT_MS    60000u
/** At least two nodes: a primary and one witness (the library refuses
 *  zero witnesses, client.go:242-244; item 9 needs two agreeing ids). */
#define NODUS_LIGHT_MIN_NODES           2u
#define NODUS_LIGHT_MAX_NODES           16u
#define NODUS_LIGHT_HOST_MAX            64u   /* nodus_server_endpoint_t.ip */
#define NODUS_LIGHT_CHAIN_ID_LEN        32u
#define NODUS_LIGHT_STORE_FILE          "light.db"
/** Header-hash bytes shown in a status line (hex 16 characters). */
#define NODUS_LIGHT_HASH_PREFIX_BYTES   8u

/* ── stop flag ───────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;

#ifdef _WIN32
/* Set when main has freed everything; the console handler waits for it on
 * a close / logoff / shutdown event, after which Windows ends the
 * process as soon as the handler returns. */
static volatile LONG g_done = 0;

static BOOL WINAPI light_console_handler(DWORD type)
{
    g_stop = 1;
    if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT ||
        type == CTRL_SHUTDOWN_EVENT) {
        /* Windows allows a handler about 5 s for these events. */
        for (int i = 0; i < 45 && InterlockedCompareExchange(&g_done, 0, 0) == 0; i++) {
            Sleep(100);
        }
    }
    return TRUE;
}
#else
static void light_on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}
#endif

static void light_install_stop_handlers(void)
{
#ifdef _WIN32
    SetConsoleCtrlHandler(light_console_handler, TRUE);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = light_on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif
}

static void light_mark_done(void)
{
#ifdef _WIN32
    InterlockedExchange(&g_done, 1);
#endif
}

/* ── small helpers ───────────────────────────────────────────────────── */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode exactly `want` bytes from `hex` (2 × want characters). */
static int hex_decode_exact(const char *hex, uint8_t *out, size_t want)
{
    if (hex == NULL || strlen(hex) != want * 2u) return -1;
    for (size_t i = 0; i < want; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int parse_u64(const char *s, uint64_t max, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || *s == '\0' || *s == '-' || *s == '+') return -1;
    v = strtoull(s, &end, 10);
    if (end == NULL || *end != '\0' || v > max) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* The wall clock as the light client's `now` (see the file header). */
static int wall_now(cmt_time_t *out)
{
    struct timespec ts;

    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) return -1;
    out->seconds = (int64_t)ts.tv_sec;
    out->nanos   = (int32_t)ts.tv_nsec;
    return cmt_time_validate(*out) == CMT_OK ? 0 : -1;
}

static void format_utc(int64_t seconds, char *buf, size_t cap)
{
    time_t     t = (time_t)seconds;
    struct tm *tm = gmtime(&t);

    if (tm == NULL || strftime(buf, cap, "%Y-%m-%d %H:%M:%S UTC", tm) == 0) {
        snprintf(buf, cap, "%lld (unix seconds)", (long long)seconds);
    }
}

/* ── the node list ───────────────────────────────────────────────────── */

typedef struct {
    char        label[16];
    char        host[NODUS_LIGHT_HOST_MAX];
    uint16_t    port;
    nodus_key_t pin;     /* pinned_server_fps points here: must outlive
                            the client (nodus.h, not copied)            */
} light_node_t;

/* `host:port:pinfp`, parsed from the right so a host may hold colons. */
static int parse_node_arg(const char *arg, light_node_t *out)
{
    const char *pin_sep;
    const char *port_sep;
    char        port_buf[8];
    size_t      host_len;
    size_t      port_len;
    uint64_t    port;

    memset(out, 0, sizeof(*out));
    pin_sep = strrchr(arg, ':');
    if (pin_sep == NULL || pin_sep == arg) return -1;
    port_sep = pin_sep - 1;
    while (port_sep > arg && *port_sep != ':') port_sep--;
    if (*port_sep != ':' || port_sep == arg) return -1;

    host_len = (size_t)(port_sep - arg);
    port_len = (size_t)(pin_sep - port_sep - 1);
    if (host_len >= sizeof(out->host) || port_len == 0 ||
        port_len >= sizeof(port_buf)) {
        return -1;
    }
    memcpy(out->host, arg, host_len);
    out->host[host_len] = '\0';
    memcpy(port_buf, port_sep + 1, port_len);
    port_buf[port_len] = '\0';
    if (parse_u64(port_buf, 65535u, &port) != 0 || port == 0) return -1;
    out->port = (uint16_t)port;
    if (hex_decode_exact(pin_sep + 1, out->pin.bytes,
                         sizeof(out->pin.bytes)) != 0) {
        return -1;
    }
    snprintf(out->label, sizeof(out->label), "node");
    return 0;
}

static int load_default_nodes(light_node_t *nodes, size_t cap, size_t *n)
{
    *n = 0;
    for (size_t i = 0; i < NODUS_LIGHT_DEFAULT_NODE_COUNT && i < cap; i++) {
        const nodus_light_default_node_t *d = &NODUS_LIGHT_DEFAULT_NODES[i];
        light_node_t *o = &nodes[*n];
        memset(o, 0, sizeof(*o));
        snprintf(o->label, sizeof(o->label), "%s", d->label);
        snprintf(o->host, sizeof(o->host), "%s", d->host);
        o->port = d->port;
        if (hex_decode_exact(d->pin_hex, o->pin.bytes,
                             sizeof(o->pin.bytes)) != 0) {
            fprintf(stderr, "internal: default pin of %s does not decode\n",
                    d->label);
            return -1;
        }
        (*n)++;
    }
    return 0;
}

/* ── command line ────────────────────────────────────────────────────── */

typedef struct {
    const char  *data_dir;
    bool         have_trust_height;
    uint64_t     trust_height;
    const char  *trust_hash_hex;
    const char  *chain_id_hex;     /* --chain-id, else the compiled testnet id */
    light_node_t nodes[NODUS_LIGHT_MAX_NODES];
    size_t       n_nodes;
    uint64_t     interval_s;
} light_args_t;

static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  nodus-light run --data <dir> [--trust-height H --trust-hash HEX]\n"
        "                  [--node host:port:pinfp]... [--interval S]\n"
        "  nodus-light status --data <dir>\n"
        "  nodus-light clear-attack --data <dir> [--node host:port:pinfp]...\n"
        "\n"
        "  run           follow the chain as a light client (Ctrl-C stops)\n"
        "  status        the last trusted block, the lock, the attack records\n"
        "  clear-attack  the operator's clear of an attack lock\n"
        "\n"
        "  --data DIR        the light store directory (DIR/" NODUS_LIGHT_STORE_FILE ")\n"
        "  --trust-height H  the trust root: a block height you trust ...\n"
        "  --trust-hash HEX  ... and its header hash (128 hex), from any source\n"
        "                    you choose; needed on an empty store, and to re-root\n"
        "                    a store whose block is older than 48 h\n"
        "  --node H:P:FP     a node (host, TCP port, 128-hex server key pin);\n"
        "                    repeat; default: the %u compiled testnet nodes on 4001\n"
        "  --interval S      seconds between updates (default %u)\n"
        "  --chain-id HEX    the chain id (64 hex); default: the compiled testnet\n"
        "                    chain. Pass the matching --node list with it.\n",
        (unsigned)NODUS_LIGHT_DEFAULT_NODE_COUNT,
        (unsigned)NODUS_LIGHT_DEFAULT_INTERVAL_S);
}

static int parse_args(int argc, char **argv, int first, bool allow_trust,
                      bool allow_nodes, bool allow_interval,
                      light_args_t *a)
{
    memset(a, 0, sizeof(*a));
    a->interval_s   = NODUS_LIGHT_DEFAULT_INTERVAL_S;
    a->chain_id_hex = NODUS_LIGHT_CHAIN_ID_HEX;

    for (int i = first; i < argc; i++) {
        const char *opt = argv[i];
        const char *val = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strcmp(opt, "--data") == 0 && val) {
            a->data_dir = val; i++;
        } else if (strcmp(opt, "--chain-id") == 0 && val) {
            a->chain_id_hex = val; i++;
        } else if (allow_trust && strcmp(opt, "--trust-height") == 0 && val) {
            if (parse_u64(val, (uint64_t)INT64_MAX, &a->trust_height) != 0 ||
                a->trust_height == 0) {
                fprintf(stderr, "--trust-height: a height >= 1 is required\n");
                return -1;
            }
            a->have_trust_height = true; i++;
        } else if (allow_trust && strcmp(opt, "--trust-hash") == 0 && val) {
            a->trust_hash_hex = val; i++;
        } else if (allow_nodes && strcmp(opt, "--node") == 0 && val) {
            if (a->n_nodes >= NODUS_LIGHT_MAX_NODES) {
                fprintf(stderr, "--node: at most %u nodes\n",
                        (unsigned)NODUS_LIGHT_MAX_NODES);
                return -1;
            }
            if (parse_node_arg(val, &a->nodes[a->n_nodes]) != 0) {
                fprintf(stderr, "--node %s: expected host:port:pinfp with a "
                        "128-hex pin\n", val);
                return -1;
            }
            snprintf(a->nodes[a->n_nodes].label,
                     sizeof(a->nodes[a->n_nodes].label), "node%u",
                     (unsigned)(a->n_nodes + 1));
            a->n_nodes++; i++;
        } else if (allow_interval && strcmp(opt, "--interval") == 0 && val) {
            if (parse_u64(val, NODUS_LIGHT_MAX_INTERVAL_S, &a->interval_s) != 0 ||
                a->interval_s == 0) {
                fprintf(stderr, "--interval: 1..%u seconds\n",
                        (unsigned)NODUS_LIGHT_MAX_INTERVAL_S);
                return -1;
            }
            i++;
        } else {
            fprintf(stderr, "unknown or incomplete option: %s\n", opt);
            return -1;
        }
    }
    if (a->data_dir == NULL) {
        fprintf(stderr, "--data <dir> is required\n");
        return -1;
    }
    if (a->have_trust_height != (a->trust_hash_hex != NULL)) {
        fprintf(stderr, "--trust-height and --trust-hash go together\n");
        return -1;
    }
    if (allow_nodes && a->n_nodes == 0 &&
        load_default_nodes(a->nodes, NODUS_LIGHT_MAX_NODES, &a->n_nodes) != 0) {
        return -1;
    }
    if (allow_nodes && a->n_nodes < NODUS_LIGHT_MIN_NODES) {
        fprintf(stderr, "at least %u nodes are needed (a primary and a "
                "witness); give another --node\n",
                (unsigned)NODUS_LIGHT_MIN_NODES);
        return -1;
    }
    return 0;
}

/* ── error text ──────────────────────────────────────────────────────── */

static const char *client_err_name(int code)
{
    switch (code) {
    case CMT_LIGHT_CLIENT_ERR_NONE:                      return "none";
    case CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_OPTIONS:     return "invalid trust options";
    case CMT_LIGHT_CLIENT_ERR_NO_WITNESSES:              return "no witnesses left";
    case CMT_LIGHT_CLIENT_ERR_WITNESS_WRONG_CHAIN:       return "a witness is on another chain";
    case CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_LEVEL:       return "invalid trust level";
    case CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS:           return "invalid options";
    case CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED:       return "verification failed";
    case CMT_LIGHT_CLIENT_ERR_VERIFIER:                  return "verifier refused";
    case CMT_LIGHT_CLIENT_ERR_PROVIDER:                  return "provider error";
    case CMT_LIGHT_CLIENT_ERR_INVALID_LIGHT_BLOCK:       return "invalid light block";
    case CMT_LIGHT_CLIENT_ERR_HASH_MISMATCH:             return "the block at the trust height has another hash";
    case CMT_LIGHT_CLIENT_ERR_INVALID_COMMIT:            return "invalid commit";
    case CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS:       return "a witness holds a conflicting header";
    case CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE: return "a witness's proposer priorities differ";
    case CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT:      return "too few nodes agree on the trust root block";
    case CMT_LIGHT_CLIENT_ERR_NO_HEADERS:                return "no trusted headers";
    case CMT_LIGHT_CLIENT_ERR_UNVERIFIED_HEIGHT:         return "unverified height";
    case CMT_LIGHT_CLIENT_ERR_BAD_HEIGHT:                return "bad height";
    case CMT_LIGHT_CLIENT_ERR_NOT_FOUND:                 return "not found";
    case CMT_LIGHT_CLIENT_ERR_STORE:                     return "unreadable store row";
    case CMT_LIGHT_CLIENT_ERR_REFUSED_CLEANUP:           return "cleanup refused";
    case CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK:       return "LIGHT CLIENT ATTACK";
    case CMT_LIGHT_CLIENT_ERR_SHORT_TRACE:               return "short trace";
    case CMT_LIGHT_CLIENT_ERR_CAP_TRACE:                 return "trace cap reached";
    case CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS:          return "verify-step cap reached";
    case CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE:        return "skipping-cache cap reached";
    case CMT_LIGHT_CLIENT_ERR_CAP_BACKWARDS_STEPS:       return "backwards-step cap reached";
    case CMT_LIGHT_CLIENT_ERR_FAILED_HEADER_CROSS_REFERENCING:
                                                         return "no witness holds the same block";
    case CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND:            return "a witness is behind";
    case CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED:             return "locked by an attack record";
    default:                                             return "unknown";
    }
}

static const char *provider_err_name(int code)
{
    switch (code) {
    case CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH:
        return "the node has no block at that height yet";
    case CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND:
        return "the node does not hold that block (pruned or not held)";
    case CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE:
        return "no answer (unreachable, timed out or at its rate limit)";
    case CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK:
        return "the node sent an invalid light block";
    default:
        return "the node refused";
    }
}

static bool err_is_expired(const cmt_light_client_error_t *e)
{
    return (e->code == CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED &&
            e->reason == CMT_LIGHT_CLIENT_REASON_VERIFIER &&
            e->verify.code == CMT_LIGHT_ERR_OLD_HEADER_EXPIRED) ||
           (e->code == CMT_LIGHT_CLIENT_ERR_VERIFIER &&
            e->verify.code == CMT_LIGHT_ERR_OLD_HEADER_EXPIRED);
}

/* ── the light block line ────────────────────────────────────────────── */

static int block_summary(const cmt_light_block_buf_t *b, int64_t *height,
                         uint8_t hash[CMT_TMHASH_SIZE], cmt_time_t *t)
{
    const cmt_header_t *h;

    if (b == NULL || b->lb.signed_header == NULL ||
        b->lb.signed_header->header == NULL) {
        return -1;
    }
    h = b->lb.signed_header->header;
    if (cmt_header_hash(h, hash) != CMT_OK) return -1;
    *height = h->height;
    *t      = h->time;
    return 0;
}

static void print_block_line(const char *what, const cmt_light_block_buf_t *b,
                             size_t n_witnesses)
{
    int64_t    height = 0;
    uint8_t    hash[CMT_TMHASH_SIZE];
    cmt_time_t t;
    char       when[64];

    if (block_summary(b, &height, hash, &t) != 0) {
        printf("%s: (the block could not be read)\n", what);
        return;
    }
    format_utc(t.seconds, when, sizeof(when));
    printf("%s height %lld hash ", what, (long long)height);
    print_hex(hash, NODUS_LIGHT_HASH_PREFIX_BYTES);
    printf("... time %s witnesses %u\n", when, (unsigned)n_witnesses);
    fflush(stdout);
}

/* ── the network side: one pinned client + provider per node ─────────── */

typedef struct {
    size_t                   n;
    light_node_t            *nodes;     /* borrowed: the args' table     */
    nodus_client_t          *clients;
    bool                    *inited;
    bool                    *started;   /* a read thread is running      */
    nodus_light_provider_t  *providers;
    cmt_light_provider_t    *tables;
    cmt_light_client_peer_t *witnesses; /* every node but the primary   */
    cmt_light_client_peer_t  primary;
    size_t                   primary_idx;
    uint64_t                 last_retry_ms;
} light_net_t;

static void net_free(light_net_t *net)
{
    if (net->clients && net->inited) {
        for (size_t i = 0; i < net->n; i++) {
            if (net->inited[i]) nodus_client_close(&net->clients[i]);
        }
    }
    free(net->clients);
    free(net->inited);
    free(net->started);
    free(net->providers);
    free(net->tables);
    free(net->witnesses);
    memset(net, 0, sizeof(*net));
}

/* Initialise every client and provider; nothing connects here. */
static int net_init(light_net_t *net, light_node_t *nodes, size_t n,
                    const uint8_t chain_id[NODUS_LIGHT_CHAIN_ID_LEN])
{
    nodus_identity_t *id;
    int               rc = -1;

    memset(net, 0, sizeof(*net));
    net->n         = n;
    net->nodes     = nodes;
    net->clients   = calloc(n, sizeof(*net->clients));
    net->inited    = calloc(n, sizeof(*net->inited));
    net->started   = calloc(n, sizeof(*net->started));
    net->providers = calloc(n, sizeof(*net->providers));
    net->tables    = calloc(n, sizeof(*net->tables));
    net->witnesses = calloc(n, sizeof(*net->witnesses));
    id             = calloc(1, sizeof(*id));
    if (!net->clients || !net->inited || !net->started || !net->providers ||
        !net->tables || !net->witnesses || !id) {
        fprintf(stderr, "out of memory\n");
        goto out;
    }
    /* The session key: in memory only (see the file header). */
    if (nodus_identity_generate(id) != 0) {
        fprintf(stderr, "could not generate the session key\n");
        goto out;
    }
    for (size_t i = 0; i < n; i++) {
        nodus_client_config_t cfg;
        int                   prc;

        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s",
                 nodes[i].host);
        cfg.servers[0].port        = nodes[i].port;
        cfg.server_count           = 1;
        cfg.auto_reconnect         = true;
        cfg.pinned_server_fps      = &nodes[i].pin;   /* item 8 */
        cfg.pinned_server_fp_count = 1;
        if (nodus_client_init(&net->clients[i], &cfg, id) != 0) {
            fprintf(stderr, "%s (%s:%u): client init failed\n",
                    nodes[i].label, nodes[i].host, (unsigned)nodes[i].port);
            goto out;
        }
        net->inited[i] = true;
        prc = nodus_light_provider_init(&net->providers[i], &net->clients[i],
                                        chain_id, NODUS_LIGHT_CHAIN_ID_LEN,
                                        CMT_BLOCK_PROTOCOL, &net->tables[i]);
        if (prc != CMT_OK) {
            fprintf(stderr, "%s: the light provider refused the client "
                    "(rc %d)\n", nodes[i].label, prc);
            goto out;
        }
    }
    rc = 0;
out:
    if (id) {
        nodus_identity_clear(id);
        free(id);
    }
    if (rc != 0) net_free(net);
    return rc;
}

/* Fill `primary` / `witnesses` with node `p` as the primary and every
 * other node, in table order, as a witness. */
static void net_assign(light_net_t *net, size_t p)
{
    size_t w = 0;

    net->primary_idx      = p;
    net->primary.provider = net->tables[p];
    net->primary.id       = net->nodes[p].pin.bytes;
    net->primary.id_len   = sizeof(net->nodes[p].pin.bytes);
    for (size_t i = 0; i < net->n; i++) {
        if (i == p) continue;
        net->witnesses[w].provider = net->tables[i];
        net->witnesses[w].id       = net->nodes[i].pin.bytes;
        net->witnesses[w].id_len   = sizeof(net->nodes[i].pin.bytes);
        w++;
    }
}

/* Connect every node in table order; the first that connects is the
 * primary. A node that does not connect stays a witness (its provider
 * answers NO_RESPONSE, the benign class) and is retried by the loop. */
static int net_connect(light_net_t *net)
{
    bool have_primary = false;

    for (size_t i = 0; i < net->n && !g_stop; i++) {
        light_node_t *nd = &net->nodes[i];
        if (nodus_client_connect(&net->clients[i]) == 0) {
            net->started[i] = true;
            printf("connected: %s %s:%u (pinned)\n", nd->label, nd->host,
                   (unsigned)nd->port);
            if (!have_primary) {
                net_assign(net, i);
                have_primary = true;
            }
        } else {
            printf("not reachable now: %s %s:%u (will retry)\n", nd->label,
                   nd->host, (unsigned)nd->port);
        }
        fflush(stdout);
    }
    net->last_retry_ms = nodus_time_mono_ms();
    if (!have_primary) {
        fprintf(stderr, "no node could be reached; nothing to follow\n");
        return -1;
    }
    return 0;
}

static void net_retry_unstarted(light_net_t *net)
{
    uint64_t now_ms = nodus_time_mono_ms();

    if (now_ms - net->last_retry_ms < NODUS_LIGHT_RETRY_CONNECT_MS) return;
    net->last_retry_ms = now_ms;
    for (size_t i = 0; i < net->n && !g_stop; i++) {
        if (net->started[i]) continue;
        if (nodus_client_connect(&net->clients[i]) == 0) {
            net->started[i] = true;
            printf("connected: %s %s:%u (pinned)\n", net->nodes[i].label,
                   net->nodes[i].host, (unsigned)net->nodes[i].port);
            fflush(stdout);
        }
    }
}

static const char *net_label_of_id(const light_net_t *net, const uint8_t *id,
                                   size_t id_len)
{
    for (size_t i = 0; i < net->n; i++) {
        if (id_len == sizeof(net->nodes[i].pin.bytes) &&
            memcmp(id, net->nodes[i].pin.bytes, id_len) == 0) {
            return net->nodes[i].label;
        }
    }
    return "?";
}

/* ── store + directory lock ──────────────────────────────────────────── */

typedef struct {
    char                 *path;
    cmt_light_store_db_t *db;
    cmt_light_store_t     store;
} light_store_t;

static int store_open(light_store_t *s, const char *dir,
                      const uint8_t chain_id[NODUS_LIGHT_CHAIN_ID_LEN])
{
    int rc;

    memset(s, 0, sizeof(*s));
    s->path = qgp_platform_join_path(dir, NODUS_LIGHT_STORE_FILE);
    if (s->path == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    rc = cmt_light_store_db_open(s->path, chain_id, NODUS_LIGHT_CHAIN_ID_LEN,
                                 CMT_BLOCK_PROTOCOL, &s->db);
    if (rc != CMT_OK) {
        fprintf(stderr, "cannot open the light store %s (%s)\n", s->path,
                rc == CMT_REJECT ? "its block count does not match its rows"
                                 : "SQLite failure or the file is busy");
        free(s->path);
        s->path = NULL;
        return -1;
    }
    cmt_light_store_db_bind(s->db, &s->store);
    return 0;
}

static void store_close(light_store_t *s)
{
    cmt_light_store_db_close(s->db);
    free(s->path);
    memset(s, 0, sizeof(*s));
}

/* D20 — ONE client object per store: an exclusive lock on the directory
 * for the life of the process. */
static intptr_t dir_lock(const char *dir)
{
    intptr_t lk = qgp_platform_acquire_identity_lock(dir);

    if (lk < 0) {
        fprintf(stderr, "%s is in use by another nodus-light (or its lock "
                "file cannot be opened): one light client per store. Stop "
                "the other one first.\n", dir);
    }
    return lk;
}

static void print_attack_counts(const light_store_t *s)
{
    uint64_t total = 0, uncleared = 0;

    if (cmt_light_store_db_attack_records(s->db, &total, &uncleared) == CMT_OK) {
        printf("attack records: %llu (uncleared %llu)\n",
               (unsigned long long)total, (unsigned long long)uncleared);
    } else {
        printf("attack records: (unreadable)\n");
    }
}

static void print_clear_hint(const char *dir)
{
    printf("The light client is LOCKED: it verifies and saves nothing until "
           "the operator clears it.\n"
           "Inspect the record (nodus-light status --data %s), then stop this "
           "program and run:\n"
           "  nodus-light clear-attack --data %s\n", dir, dir);
    fflush(stdout);
}

static void print_attack(const cmt_light_client_t *c, const light_net_t *net)
{
    const cmt_light_attack_record_t *r = cmt_light_client_attack_record(c);

    printf("*** ATTACK DETECTED: a witness holds a conflicting block that "
           "verifies. Nothing was saved; nothing was sent to any node.\n");
    if (r != NULL) {
        printf("    primary %s (pin ", net_label_of_id(net, r->primary_id,
                                                       r->primary_id_len));
        print_hex(r->primary_id, r->primary_id_len < 8 ? r->primary_id_len : 8);
        printf("...), witness %s (pin ", net_label_of_id(net, r->witness_id,
                                                         r->witness_id_len));
        print_hex(r->witness_id, r->witness_id_len < 8 ? r->witness_id_len : 8);
        printf("...)\n");
        if ((r->missing & CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY) == 0) {
            printf("    common height %lld, byzantine validators named %u\n",
                   (long long)r->against_primary.common_height,
                   (unsigned)r->against_primary.n_byzantine);
        }
        printf("    record %s\n", r->durable
               ? "written to the light store"
               : "NOT yet written to the store (retried on every call; the "
                 "clear refuses until it is)");
    }
    fflush(stdout);
}

/* ── run ─────────────────────────────────────────────────────────────── */

static bool confirm_reroot(void *ctx, int action, int64_t a, int64_t b)
{
    (void)ctx;
    /* The operator gave this trust root on the command line, which is
     * the confirmation (client.go:320-324, :344-347). */
    if (action == CMT_LIGHT_CLIENT_ACTION_ROLLBACK) {
        printf("re-rooting: removing stored blocks above %lld (up to %lld)\n",
               (long long)a, (long long)b);
    } else {
        printf("re-rooting: the stored block at %lld does not match the "
               "given root; removing all stored blocks\n", (long long)a);
    }
    fflush(stdout);
    return true;
}

static void print_construct_error(const char *what,
                                  const cmt_light_client_error_t *e,
                                  const light_net_t *net, const char *dir)
{
    fprintf(stderr, "%s refused: %s (code %d)\n", what,
            client_err_name(e->code), e->code);
    switch (e->code) {
    case CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED:
        fprintf(stderr, "The store holds an uncleared attack record. Inspect "
                "it (nodus-light status --data %s) and clear it with "
                "nodus-light clear-attack --data %s first.\n", dir, dir);
        break;
    case CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT:
        fprintf(stderr, "Only %u distinct node(s) returned the same block at "
                "the trust height; at least %u are needed (a consistency "
                "check, the root is your hash). Retry when more nodes are "
                "reachable.\n", (unsigned)e->agreeing,
                (unsigned)CMT_LIGHT_CLIENT_MIN_INIT_AGREEMENT);
        break;
    case CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS:
    case CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE:
        if (e->witness_index < net->n - 1u) {
            const cmt_light_client_peer_t *w = &net->witnesses[e->witness_index];
            fprintf(stderr, "Disagreeing node: %s. Nothing was saved; decide "
                    "which source to trust.\n",
                    net_label_of_id(net, w->id, w->id_len));
        }
        break;
    case CMT_LIGHT_CLIENT_ERR_HASH_MISMATCH:
        fprintf(stderr, "The primary's block at --trust-height has another "
                "hash than --trust-hash. Check the root you were given.\n");
        break;
    case CMT_LIGHT_CLIENT_ERR_PROVIDER:
        fprintf(stderr, "The primary did not deliver the trust-height block: "
                "%s (provider error %d).%s\n",
                provider_err_name(e->provider.code), e->provider.code,
                e->provider.code == CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND
                    ? " Choose a more recent trust root." : "");
        break;
    default:
        break;
    }
}

static int cmd_run(int argc, char **argv)
{
    light_args_t               *a;
    uint8_t                     chain_id[NODUS_LIGHT_CHAIN_ID_LEN];
    uint8_t                     trust_hash[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t   trust;
    bool                        use_trust = false;
    const char                 *root_source = NULL;
    intptr_t                    lk = -1;
    light_store_t               st;
    bool                        st_open = false;
    light_net_t                 net;
    bool                        net_up = false;
    cmt_light_client_options_t  opts;
    cmt_light_client_t         *c = NULL;
    cmt_light_client_error_t    err;
    cmt_light_block_buf_t      *out = NULL;
    int64_t                     stored_last = -1;
    int                         ret = 1;
    int                         rc;

    memset(&net, 0, sizeof(net));
    memset(&st, 0, sizeof(st));
    memset(&trust, 0, sizeof(trust));
    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    if (parse_args(argc, argv, 2, true, true, true, a) != 0) {
        usage();
        free(a);
        return 2;
    }
    if (hex_decode_exact(a->chain_id_hex, chain_id,
                         sizeof(chain_id)) != 0) {
        fprintf(stderr, "--chain-id: 64 hex characters (32 bytes) required\n");
        goto done;
    }
    if (a->trust_hash_hex != NULL &&
        hex_decode_exact(a->trust_hash_hex, trust_hash,
                         sizeof(trust_hash)) != 0) {
        fprintf(stderr, "--trust-hash: %u hex characters (the block's header "
                "hash) are required\n", (unsigned)(2u * sizeof(trust_hash)));
        ret = 2;
        goto done;
    }

    if (!qgp_platform_is_directory(a->data_dir) &&
        qgp_platform_mkdir(a->data_dir) != 0) {
        fprintf(stderr, "cannot create %s\n", a->data_dir);
        goto done;
    }
    lk = dir_lock(a->data_dir);
    if (lk < 0) goto done;
    if (store_open(&st, a->data_dir, chain_id) != 0) goto done;
    st_open = true;
    if (cmt_light_store_db_last_light_block_height(st.db, &stored_last) != CMT_OK) {
        fprintf(stderr, "the light store cannot be read\n");
        goto done;
    }

    /* The trust root (K25-1): the operator's, else the stored block, else
     * the release default — refused before any network call. */
    if (a->have_trust_height) {
        use_trust   = true;
        root_source = "operator input";
        trust.height = (int64_t)a->trust_height;
        trust.hash   = trust_hash;
    } else if (stored_last > 0) {
        root_source = "the light store";
    } else if (NODUS_LIGHT_RELEASE_CHECKPOINT.height > 0) {
        if (hex_decode_exact(NODUS_LIGHT_RELEASE_CHECKPOINT.hash_hex,
                             trust_hash, sizeof(trust_hash)) != 0) {
            fprintf(stderr, "internal: the release checkpoint hash does not "
                    "decode\n");
            goto done;
        }
        use_trust    = true;
        root_source  = "the release default checkpoint";
        trust.height = NODUS_LIGHT_RELEASE_CHECKPOINT.height;
        trust.hash   = trust_hash;
    } else {
        fprintf(stderr,
            "The light store in %s is empty and this build carries no "
            "default checkpoint.\n"
            "Give a trust root from a source you choose:\n"
            "  nodus-light run --data %s --trust-height <H> --trust-hash "
            "<128-hex header hash of block H>\n",
            a->data_dir, a->data_dir);
        ret = 2;
        goto done;
    }
    if (use_trust) {
        trust.period   = NODUS_LIGHT_TRUSTING_PERIOD_NS;   /* K25-2 */
        trust.hash_len = sizeof(trust_hash);
    }

    cmt_light_client_options_default(&opts);
    opts.max_trace_len       = NODUS_LIGHT_MAX_TRACE_LEN;
    opts.max_verify_steps    = NODUS_LIGHT_MAX_VERIFY_STEPS;
    opts.max_skipping_cache  = NODUS_LIGHT_MAX_SKIPPING_CACHE;
    opts.max_backwards_steps = NODUS_LIGHT_MAX_BACKWARDS_STEPS;
    opts.confirm             = confirm_reroot;
    opts.confirm_ctx         = NULL;

    out = cmt_light_block_buf_new();
    if (out == NULL) {
        fprintf(stderr, "out of memory\n");
        goto done;
    }

    light_install_stop_handlers();
    if (net_init(&net, a->nodes, a->n_nodes, chain_id) != 0) goto done;
    net_up = true;
    if (net_connect(&net) != 0) goto done;
    if (g_stop) { ret = 0; goto done; }

    memset(&err, 0, sizeof(err));
    if (use_trust) {
        rc = cmt_light_client_new(chain_id, sizeof(chain_id), &trust,
                                  &net.primary, net.witnesses, net.n - 1u,
                                  &st.store, &opts, &c, &err);
    } else {
        rc = cmt_light_client_new_from_trusted_store(
                chain_id, sizeof(chain_id), NODUS_LIGHT_TRUSTING_PERIOD_NS,
                &net.primary, net.witnesses, net.n - 1u, &st.store, &opts,
                &c, &err);
    }
    if (rc != CMT_OK) {
        if (rc == CMT_REJECT) {
            print_construct_error("starting the light client", &err, &net,
                                  a->data_dir);
        } else {
            fprintf(stderr, "starting the light client failed (a local "
                    "fault: store, allocation or provider)\n");
        }
        goto done;
    }
    QGP_LOG_INFO(LOG_TAG, "light client started: root from %s, %u nodes",
                 root_source, (unsigned)net.n);
    printf("nodus-light: chain ");
    print_hex(chain_id, NODUS_LIGHT_HASH_PREFIX_BYTES);
    printf("..., root from %s, primary %s, %u witness(es), trusting period "
           "48 h, update every %llu s\n", root_source,
           net.nodes[net.primary_idx].label,
           (unsigned)cmt_light_client_witness_count(c),
           (unsigned long long)a->interval_s);
    if (cmt_light_client_trusted_light_block(c, 0, out, &err) == CMT_OK) {
        print_block_line("trusted", out, cmt_light_client_witness_count(c));
    }
    if (cmt_light_client_attack_locked(c)) {
        print_attack_counts(&st);
        print_clear_hint(a->data_dir);
    }

    /* ── the loop ── */
    {
        int     last_rc   = CMT_OK;
        int     last_code = CMT_LIGHT_CLIENT_ERR_NONE;
        size_t  last_wc   = cmt_light_client_witness_count(c);
        const uint8_t *pid = NULL;
        size_t  pid_len   = 0;
        const char *last_primary = net.nodes[net.primary_idx].label;

        while (!g_stop) {
            cmt_time_t now;
            bool       advanced = false;
            size_t     wc;

            net_retry_unstarted(&net);
            if (g_stop) break;
            if (wall_now(&now) != 0) {
                fprintf(stderr, "the wall clock cannot be read; stopping\n");
                goto done;
            }
            memset(&err, 0, sizeof(err));
            rc = cmt_light_client_update(c, now, out, &advanced, &err);
            wc = cmt_light_client_witness_count(c);

            if (cmt_light_client_primary_id(c, &pid, &pid_len) == CMT_OK) {
                const char *lbl = net_label_of_id(&net, pid, pid_len);
                if (strcmp(lbl, last_primary) != 0) {
                    printf("primary replaced: now %s\n", lbl);
                    last_primary = lbl;
                }
            }
            if (rc == CMT_OK) {
                if (advanced || wc != last_wc) {
                    if (advanced) {
                        print_block_line("trusted", out, wc);
                    } else {
                        printf("witnesses %u\n", (unsigned)wc);
                    }
                }
                if (last_rc != CMT_OK) {
                    printf("updates resume\n");
                }
            } else if (rc == CMT_REJECT &&
                       (rc != last_rc || err.code != last_code)) {
                switch (err.code) {
                case CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND:
                    printf("a witness is behind: waiting (the same target "
                           "block is judged once 2 x clock drift + block lag "
                           "= 30 s have passed)\n");
                    break;
                case CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK:
                    QGP_LOG_WARN(LOG_TAG, "light client attack detected; "
                                 "the client is locked until the operator "
                                 "clears it (K25-10)");
                    print_attack(c, &net);
                    print_attack_counts(&st);
                    print_clear_hint(a->data_dir);
                    break;
                case CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED:
                    print_clear_hint(a->data_dir);
                    break;
                case CMT_LIGHT_CLIENT_ERR_NO_WITNESSES:
                    fprintf(stderr, "every witness was removed for bad "
                            "answers; no cross-check is possible. Stopping "
                            "(a restart rebuilds the node list).\n");
                    goto done;
                default:
                    if (err_is_expired(&err)) {
                        printf("the trusted block is older than the 48 h "
                               "trusting period. Re-root with a fresh trust "
                               "root from a source you choose:\n"
                               "  nodus-light run --data %s --trust-height "
                               "<H> --trust-hash <HEX>\n", a->data_dir);
                    } else {
                        printf("update refused: %s (code %d",
                               client_err_name(err.code), err.code);
                        if (err.code == CMT_LIGHT_CLIENT_ERR_PROVIDER ||
                            err.reason == CMT_LIGHT_CLIENT_REASON_PROVIDER) {
                            printf(", provider: %s",
                                   provider_err_name(err.provider.code));
                        }
                        printf("); retrying every %llu s\n",
                               (unsigned long long)a->interval_s);
                    }
                    break;
                }
            } else if (rc != CMT_OK && rc != CMT_REJECT) {
                QGP_LOG_ERROR(LOG_TAG, "update: local fault rc=%d", rc);
                fprintf(stderr, "update failed: a local fault (store or "
                        "allocation); see the log\n");
            }
            fflush(stdout);
            last_rc   = rc;
            last_code = (rc == CMT_REJECT) ? err.code : CMT_LIGHT_CLIENT_ERR_NONE;
            last_wc   = wc;

            for (uint64_t slept = 0;
                 !g_stop && slept < a->interval_s * 1000u;
                 slept += NODUS_LIGHT_SLEEP_SLICE_MS) {
                qgp_platform_sleep_ms(NODUS_LIGHT_SLEEP_SLICE_MS);
            }
        }
    }
    printf("stopping\n");
    ret = 0;

done:
    cmt_light_client_free(c);
    if (net_up) net_free(&net);
    cmt_light_block_buf_free(out);
    if (st_open) store_close(&st);
    qgp_platform_release_identity_lock(lk);
    free(a);
    light_mark_done();
    return ret;
}

/* ── status ──────────────────────────────────────────────────────────── */

static int cmd_status(int argc, char **argv)
{
    light_args_t          *a;
    uint8_t                chain_id[NODUS_LIGHT_CHAIN_ID_LEN];
    light_store_t          st;
    bool                   st_open = false;
    cmt_light_block_buf_t *b = NULL;
    char                  *path = NULL;
    int64_t                first = -1, last = -1;
    uint64_t               size = 0, total = 0, uncleared = 0;
    int                    ret = 1;

    memset(&st, 0, sizeof(st));
    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    if (parse_args(argc, argv, 2, false, false, false, a) != 0) {
        usage();
        free(a);
        return 2;
    }
    if (hex_decode_exact(a->chain_id_hex, chain_id,
                         sizeof(chain_id)) != 0) {
        goto done;
    }
    /* Opening creates a file; status must not, so look first. */
    path = qgp_platform_join_path(a->data_dir, NODUS_LIGHT_STORE_FILE);
    if (path == NULL || !qgp_platform_file_exists(path)) {
        printf("no light store in %s\n", a->data_dir);
        ret = path ? 0 : 1;
        goto done;
    }
    if (store_open(&st, a->data_dir, chain_id) != 0) goto done;
    st_open = true;
    if (cmt_light_store_db_last_light_block_height(st.db, &last) != CMT_OK ||
        cmt_light_store_db_first_light_block_height(st.db, &first) != CMT_OK ||
        cmt_light_store_db_size(st.db, &size) != CMT_OK ||
        cmt_light_store_db_attack_records(st.db, &total, &uncleared) != CMT_OK) {
        fprintf(stderr, "the light store cannot be read\n");
        goto done;
    }

    printf("store:          %s\n", st.path);
    printf("chain:          ");
    print_hex(chain_id, NODUS_LIGHT_HASH_PREFIX_BYTES);
    printf("...\n");
    if (last <= 0) {
        printf("trusted block:  none\n");
    } else {
        bool        found = false;
        int64_t     h = 0;
        uint8_t     hash[CMT_TMHASH_SIZE];
        cmt_time_t  t, now, until;
        char        when[64], until_s[64];

        b = cmt_light_block_buf_new();
        if (b == NULL ||
            cmt_light_store_db_light_block(st.db, last, b, &found) != CMT_OK ||
            !found || block_summary(b, &h, hash, &t) != 0) {
            fprintf(stderr, "the trusted block at %lld cannot be read\n",
                    (long long)last);
            goto done;
        }
        format_utc(t.seconds, when, sizeof(when));
        until = cmt_time_add_ns(t, NODUS_LIGHT_TRUSTING_PERIOD_NS);
        format_utc(until.seconds, until_s, sizeof(until_s));
        printf("trusted height: %lld\n", (long long)h);
        printf("trusted hash:   ");
        print_hex(hash, sizeof(hash));
        printf("\n");
        printf("block time:     %s\n", when);
        /* HeaderExpired: expiry == now is already expired. */
        if (wall_now(&now) == 0) {
            printf("trusted until:  %s (48 h trusting period)%s\n", until_s,
                   cmt_time_after(until, now) ? "" : " — EXPIRED, re-root "
                   "with --trust-height/--trust-hash");
        } else {
            printf("trusted until:  %s (48 h trusting period)\n", until_s);
        }
        printf("stored blocks:  %llu (heights %lld .. %lld)\n",
               (unsigned long long)size, (long long)first, (long long)last);
    }
    printf("lock:           %s\n", uncleared > 0
           ? "LOCKED by an attack record (nodus-light clear-attack)"
           : "not locked");
    printf("attack records: %llu, uncleared %llu\n",
           (unsigned long long)total, (unsigned long long)uncleared);
    ret = 0;

done:
    cmt_light_block_buf_free(b);
    if (st_open) store_close(&st);
    free(path);
    free(a);
    return ret;
}

/* ── clear-attack ────────────────────────────────────────────────────── */

static int cmd_clear_attack(int argc, char **argv)
{
    light_args_t               *a;
    uint8_t                     chain_id[NODUS_LIGHT_CHAIN_ID_LEN];
    char                       *path = NULL;
    intptr_t                    lk = -1;
    light_store_t               st;
    bool                        st_open = false;
    light_net_t                 net;
    bool                        net_up = false;
    cmt_light_client_options_t  opts;
    cmt_light_client_t         *c = NULL;
    cmt_light_client_error_t    err;
    int                         ret = 1;
    int                         rc;

    memset(&st, 0, sizeof(st));
    memset(&net, 0, sizeof(net));
    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    if (parse_args(argc, argv, 2, false, true, false, a) != 0) {
        usage();
        free(a);
        return 2;
    }
    if (hex_decode_exact(a->chain_id_hex, chain_id,
                         sizeof(chain_id)) != 0) {
        goto done;
    }
    path = qgp_platform_join_path(a->data_dir, NODUS_LIGHT_STORE_FILE);
    if (path == NULL || !qgp_platform_file_exists(path)) {
        fprintf(stderr, "no light store in %s\n", a->data_dir);
        goto done;
    }
    lk = dir_lock(a->data_dir);
    if (lk < 0) goto done;
    if (store_open(&st, a->data_dir, chain_id) != 0) goto done;
    st_open = true;
    print_attack_counts(&st);

    /* The clear goes through the client (cmt_light_client_attack_clear),
     * which refuses while a record is not durable. Its constructor needs
     * providers but asks them only for their configured chain id, so the
     * clients are initialised and never connected: nothing is sent. */
    cmt_light_client_options_default(&opts);
    opts.max_trace_len       = NODUS_LIGHT_MAX_TRACE_LEN;
    opts.max_verify_steps    = NODUS_LIGHT_MAX_VERIFY_STEPS;
    opts.max_skipping_cache  = NODUS_LIGHT_MAX_SKIPPING_CACHE;
    opts.max_backwards_steps = NODUS_LIGHT_MAX_BACKWARDS_STEPS;
    if (net_init(&net, a->nodes, a->n_nodes, chain_id) != 0) goto done;
    net_up = true;
    net_assign(&net, 0);

    memset(&err, 0, sizeof(err));
    rc = cmt_light_client_new_from_trusted_store(
            chain_id, sizeof(chain_id), NODUS_LIGHT_TRUSTING_PERIOD_NS,
            &net.primary, net.witnesses, net.n - 1u, &st.store, &opts, &c,
            &err);
    if (rc != CMT_OK) {
        if (rc == CMT_REJECT) {
            print_construct_error("opening the light client", &err, &net,
                                  a->data_dir);
        } else {
            fprintf(stderr, "opening the light client failed (a local "
                    "fault: store or allocation)\n");
        }
        goto done;
    }
    if (!cmt_light_client_attack_locked(c)) {
        printf("not locked: there is no uncleared attack record\n");
        ret = 0;
        goto done;
    }
    rc = cmt_light_client_attack_clear(c);
    if (rc == CMT_REJECT) {
        fprintf(stderr, "clear refused: an attack record is not yet written "
                "to the store; the client stays locked\n");
        goto done;
    }
    if (rc != CMT_OK) {
        fprintf(stderr, "clear failed (store failure); the client stays "
                "locked\n");
        goto done;
    }
    printf("cleared: the light client is unlocked (every record is kept, "
           "marked cleared)\n");
    print_attack_counts(&st);
    ret = 0;

done:
    cmt_light_client_free(c);
    if (net_up) net_free(&net);
    if (st_open) store_close(&st);
    qgp_platform_release_identity_lock(lk);
    free(path);
    free(a);
    return ret;
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 2;
    }
    if (strcmp(argv[1], "run") == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "status") == 0) return cmd_status(argc, argv);
    if (strcmp(argv[1], "clear-attack") == 0) return cmd_clear_attack(argc, argv);
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "help") == 0) {
        usage();
        return 0;
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    usage();
    return 2;
}
