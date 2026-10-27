/*
 * stagef_rpc_flood — TEST-ONLY localhost load tool for the Nodus Genesis
 * Protocol harness.
 *
 * PURPOSE (defensive measurement of OUR OWN node). It asks one question:
 * does a high volume of ordinary client chain requests to ONE node delay
 * that node's own consensus participation? It opens S client sessions to
 * a single node's client port (127.0.0.1 only), runs T synchronous
 * request loops per session for D seconds, and counts what the node
 * answered. It asserts NO threshold; the window comparison and the
 * verdict are the bench script's job (bench_rpc_flood.sh). It never
 * targets a live node — the caller points it at a localhost harness
 * cluster (stagef_up_v2.sh).
 *
 * It is NOT a scenario and is never added to genesis_protocol_v2.sh.
 *
 * THREE MODES (the kind of ordinary request to repeat):
 *   spend-invalid  one well-formed CORE SPEND envelope per session that
 *                  the node REFUSES at CheckTx after doing its full work:
 *                  a fabricated input nullifier (random 64 bytes — not a
 *                  real coin), a valid kind-1 signature by the session's
 *                  EPHEMERAL key, fee at the chain floor. The envelope is
 *                  built by the SAME shared builder nodus-cli's
 *                  `v2-envelope spend` uses (nodus_v2_spend_plan +
 *                  nodus_v2_spend_build, nodus/src/client/nodus_v2_spend.c)
 *                  over a single FABRICATED coin, so every field the chain
 *                  parses is as a real spend's — only the input does not
 *                  exist, so exec (rtn_xfer_exec) rejects it AFTER the
 *                  signature verify and the envelope decode. A refused tx
 *                  is removed from the mempool cache (keep_invalid_txs_in_
 *                  cache is false, shared/dnac/cmt_mem.c:1308; the node
 *                  never sets it true), so each resubmission re-runs the
 *                  full CheckTx. The first submission's refusal text/code
 *                  is printed at start to PROVE the requests reach CheckTx
 *                  (a "CheckTx code N" error frame) rather than failing
 *                  early (parse error, rate limit); a first answer that is
 *                  not a CheckTx refusal aborts the tool (exit 2).
 *   v3-block       repeated dnac_v3_block(height H, from_index 0, budget
 *                  1 MiB) — the read-only block query Scan uses
 *                  (decision 2026-09-28-scan-v3-query.md item 1).
 *   balance        repeated dnac_balance(owner) — the public transparent
 *                  balance query (decision 2026-09-28-scan-v3-query.md
 *                  item 3a, APPROVED 2026-10-13).
 *
 * IDENTITIES ARE EPHEMERAL, generated in memory (nodus_identity_generate)
 * — never read from or written to any identity file. The server allows
 * NODUS_MAX_SESSIONS_PER_IDENTITY (4, nodus_server.h:608) sessions per
 * identity and NODUS_MAX_CONNS_PER_IP (20, nodus_tcp.h:29) connections
 * per IPv4 address, so the tool uses ceil(S/4) identities with <= 4
 * sessions each and refuses S > 19 (one connection left under the per-IP
 * cap).
 *
 * THE SDK IS THREAD-SAFE for concurrent in-flight requests: each request
 * takes a pending slot keyed by a monotonic txn id (client->next_txn,
 * _Atomic), the single reader thread dispatches each response to its slot
 * (nodus_client.c read_thread_fn / client_on_frame), and the calling
 * thread waits on its own slot. At most NODUS_MAX_PENDING (64) requests
 * are in flight per client, so T <= 64 threads share one client safely.
 *
 * PIPELINE (non-waiting) MODE — `--pipeline N` (spend-invalid only). A
 * client that does not wait for answers: ONE sender thread per session
 * encodes the SAME dnac_spend request as spend-invalid (same envelope /
 * tx_hash / pk / sig) with a FRESH txn id each time (atomic_fetch_add on
 * client->next_txn), using the SAME bytes the SDK emits (enc_dnac_query +
 * five args, nodus_client.c:3142-3199, replicated in encode_spend_frame),
 * and sends it with nodus_tcp_send under client->send_mutex — the body of
 * the SDK's own send_request (nodus_client.c:237) — WITHOUT a pending slot
 * and WITHOUT waiting. The node still answers (one CheckTx-refusal error
 * frame per request); the SDK reader thread receives each, finds NO
 * pending slot for its txn, logs ONE WARN and discards it (client_on_frame
 * :654). So ANSWERS CANNOT BE COUNTED in pipeline mode (no public hook, no
 * counter) — it counts ONLY frames sent and send failures (nodus_tcp_send
 * != 0). The nodus standalone log shim (nodus_log_shim.c) has no level
 * setter — its threshold is hardcoded at INFO — so to stop the per-frame
 * WARN from flooding, the tool redirects its own stderr to /dev/null for
 * the flood (after the proof has printed to stdout). The send rate is paced OPEN-LOOP
 * to `--rate R` frames/s per session in bursts of N (the SDK cannot report
 * the node's drain rate, so the node's inbound queue is driven at a KNOWN
 * rate, not held at a measured outstanding depth). It exercises the core's
 * per-session read budget (NODUS_TCP_READ_BUDGET_FRAMES = 256,
 * nodus_tcp.h:38) and the core->witness IPC queue bound (nodus_witness_ipc.h).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <stdatomic.h>

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "crypto/nodus_identity.h"          /* nodus_identity_generate      */
#include "crypto/nodus_sign.h"              /* nodus_sign, nodus_random     */
#include "crypto/hash/qgp_sha3.h"           /* qgp_sha3_512                 */
#include "crypto/utils/qgp_fingerprint.h"   /* qgp_fp_raw_to_hex            */
#include "witness/nodus_witness_runtime.h"  /* compiled ruleset table       */
#include "dnac/ledger_ids.h"                /* DNA_DOMAIN_*, DNA_CHAIN_ID_LEN*/
#include "dnac/dnac.h"                       /* DNAC_MIN_FEE_RAW, PUBKEY_SIZE*/
#include "transport/nodus_tcp.h"             /* nodus_tcp_send (pipeline mode)*/
#include "protocol/nodus_cbor.h"             /* cbor_encode_* (pipeline mode) */

/* Output-seed randomness for the shared builder — never a global RNG; the
 * builder fills `len` bytes through this (nodus_v2_rand_fn). */
static int flood_rand(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    return nodus_random(buf, len);
}

/* ── parameters ──────────────────────────────────────────────────────── */
enum rpc_mode { MODE_SPEND_INVALID, MODE_V3_BLOCK, MODE_BALANCE };

/* The mempool lifetime rule (nodus-cli cli_env_expiry): expiry within
 * (tip, tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD], with the gossip margin. */
#define RPC_ENV_EXPIRY_AHEAD ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
/* A fabricated coin's value — far above the fee, so amount_all plans a
 * single 1-in/1-out spend (NODUS_V2_SPEND_ERR_NO_COIN_ALL otherwise). The
 * coin does not exist on chain; this is only the amount the builder sizes
 * the output and the fee against. */
#define RPC_FAKE_COIN_RAW    ((uint64_t)1000000000000ULL)   /* 10^12 raw     */
#define RPC_V3_BUDGET        ((uint32_t)(1u << 20))          /* 1 MiB         */

struct counters {
    uint64_t sent;        /* requests sent (pipeline mode: frames sent)      */
    uint64_t answered;    /* a definite answer from the node                 */
    uint64_t refused;     /* spend-invalid: a CheckTx refusal (expected)     */
    uint64_t accepted;    /* spend-invalid: CheckTx APPROVED (unexpected)    */
    uint64_t errors;      /* transport / protocol / rate-limit / other       */
    uint64_t timeouts;    /* no answer within the SDK's per-request wait      */
    uint64_t send_fail;   /* pipeline mode: nodus_tcp_send != 0              */
};

struct worker {
    pthread_t          tid;
    nodus_client_t    *client;
    enum rpc_mode      mode;
    /* spend-invalid: the one envelope and its outer spend-RPC auth */
    const uint8_t     *env;
    size_t             env_len;
    const uint8_t     *wire_id;        /* 64 bytes, the dnac_spend tx_hash   */
    const nodus_pubkey_t *spk;
    const nodus_sig_t    *ssig;
    /* v3-block / balance */
    uint64_t           height;
    const char        *owner_hex;
    /* pipeline (non-waiting) mode */
    int                is_pipeline;
    uint64_t           pipeline;       /* N: send burst size per session     */
    uint64_t           rate;           /* R: average frames/s per session    */
    struct counters    c;
};

static _Atomic bool g_running = true;
/* Set by SIGTERM / SIGINT so the bench script can stop the load at the
 * window boundary; the tool then aggregates and writes its stats and
 * exits 0 (a clean early stop, not a lost run). */
static volatile sig_atomic_t g_sig_stop = 0;
static void on_stop_signal(int sig) { (void)sig; g_sig_stop = 1; }

/* ── compiled ruleset table (mirrors nodus-cli cli_builtin_runtime /
 *    cli_select_runtimes / cli_ruleset_id — copied minimal, the compiled
 *    table so the ruleset cannot drift from a same-tree nodus-server) ──── */

static nodus_dnac_ruleset_info_t g_ri;
static int                       g_ri_valid = 0;
static uint32_t                  g_sel_gen  = 0;

static const nodus_domain_runtime_t *flood_builtin_runtime(uint32_t domain_id,
                                                           uint32_t generation) {
    for (uint32_t g = generation; g >= NODUS_RT_GEN_1; g--) {
        const nodus_domain_runtime_t *rt =
            nodus_runtime_for_generation(g, domain_id);
        if (rt) return rt;
    }
    return NULL;
}

/* Ask the node which rule-set generation governs its tip + 1 and pick the
 * compiled generation whose (SYSTEM, CORE) tuple EQUALS the answer — never
 * by height (nodus-cli cli_select_runtimes). Fail closed. @return 0 / -1. */
static int flood_select_ruleset(nodus_client_t *client,
                                nodus_v2_ruleset_id_t *rs_out) {
    nodus_dnac_ruleset_info_t ri;
    int rc = nodus_client_dnac_ruleset_info(client, &ri);
    if (rc != 0) {
        fprintf(stderr, "dnac_ruleset_info failed (rc=%d) — the node is "
                "older than this tool or did not answer\n", rc);
        return -1;
    }
    for (uint32_t g = 1; g <= nodus_runtime_generation_count(); g++) {
        const nodus_domain_runtime_t *s = flood_builtin_runtime(DNA_DOMAIN_SYSTEM, g);
        const nodus_domain_runtime_t *c = flood_builtin_runtime(DNA_DOMAIN_CORE, g);
        if (!s || !c) continue;
        if (s->ruleset_version == ri.sys_version &&
            memcmp(s->ruleset_hash, ri.sys_hash, 64) == 0 &&
            c->ruleset_version == ri.core_version &&
            memcmp(c->ruleset_hash, ri.core_hash, 64) == 0 &&
            s->meter_policy) {
            memset(rs_out, 0, sizeof(*rs_out));
            rs_out->core_ruleset_version = c->ruleset_version;
            memcpy(rs_out->core_ruleset_hash, c->ruleset_hash, 64);
            rs_out->meter_policy = s->meter_policy;
            g_ri = ri; g_ri_valid = 1; g_sel_gen = g;
            return 0;
        }
    }
    fprintf(stderr, "the node runs a rule-set generation this tool does not "
            "carry (generation %u: SYSTEM v%u, CORE v%u) — rebuild the tool "
            "from the node's tree\n", (unsigned)ri.generation,
            (unsigned)ri.sys_version, (unsigned)ri.core_version);
    return -1;
}

/* nodus-cli cli_env_expiry: tip + RPC_ENV_EXPIRY_AHEAD, clamped before a
 * committed generation-2 switch when the node still runs generation 1. */
static int flood_env_expiry(uint64_t tip, uint64_t *expiry_out) {
    uint64_t e = tip + RPC_ENV_EXPIRY_AHEAD, H = 0, hi = tip;
    int gen1 = 0;
    if (g_ri_valid) {
        H = g_ri.gen2_height;
        gen1 = (g_sel_gen == NODUS_RT_GEN_1);
        if (g_ri.tip > hi) hi = g_ri.tip;
    }
    if (gen1 && H != 0) {
        if (H - 1u < hi + 1u) {
            fprintf(stderr, "rule-set switch at height %" PRIu64 ": a "
                    "generation-1 envelope cannot expire at or before "
                    "%" PRIu64 " while the tip is %" PRIu64 "\n",
                    H, H - 1u, hi);
            return -1;
        }
        if (e > H - 1u) e = H - 1u;
    }
    *expiry_out = e;
    return 0;
}

/* Build ONE well-formed CORE SPEND envelope whose single input is a
 * FABRICATED nullifier (random 64 bytes), self-sent, amount_all, fee at
 * the floor — the shared builder's exact path (plan + build), differing
 * from a real spend only in that the input does not exist on chain. */
static int flood_build_invalid_spend(const nodus_identity_t *id,
                                      const nodus_v2_ruleset_id_t *rs,
                                      const uint8_t chain32[DNA_CHAIN_ID_LEN],
                                      uint64_t tip, uint64_t gas_price,
                                      nodus_v2_spend_built_t *built_out) {
    const uint64_t fee_floor = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                             ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;

    /* the sender fingerprint (self-send target): SHA3-512(pk) */
    uint8_t sender_raw[64];
    char    sender_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(id->pk.bytes, DNAC_PUBKEY_SIZE, sender_raw) != 0) return -1;
    qgp_fp_raw_to_hex(sender_raw, sender_fp);
    (void)sender_fp;

    /* ONE fabricated native coin */
    nodus_v2_coin_t coin;
    memset(&coin, 0, sizeof(coin));
    if (nodus_random(coin.nul, 64) != 0) return -1;
    coin.amount = RPC_FAKE_COIN_RAW;
    coin.kind   = 0;            /* native */
    coin.used   = 0;

    /* plan (amount_all, count 1, no dust sweep): 1-in/1-out, fee sized */
    nodus_v2_spend_plan_req_t preq;
    memset(&preq, 0, sizeof(preq));
    preq.rs         = rs;
    preq.order      = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
    preq.is_native  = 1;
    preq.amount     = 0;
    preq.amount_all = 1;
    preq.fee        = fee_floor;
    preq.fee_fixed  = 0;
    preq.gas_price  = gas_price;
    preq.count      = 1;
    preq.count_all  = 0;
    preq.no_dust_sweep = 1;

    nodus_v2_spend_plan_t *plans = NULL;
    long pcount = 0;
    uint64_t fee = fee_floor;
    nodus_v2_spend_err_t pe;
    memset(&pe, 0, sizeof(pe));
    int prc = nodus_v2_spend_plan(&preq, &coin, 1, &plans, &pcount, &fee, &pe);
    if (prc != NODUS_V2_SPEND_OK || pcount != 1 || !plans) {
        fprintf(stderr, "spend plan failed (rc=%d, pcount=%ld)\n", prc, pcount);
        free(plans);
        return -1;
    }

    nodus_v2_spend_build_req_t breq;
    memset(&breq, 0, sizeof(breq));
    breq.rs         = rs;
    breq.chain32    = chain32;
    breq.tip        = tip;
    if (flood_env_expiry(tip, &breq.expiry_height) != 0) { free(plans); return -1; }
    breq.pk         = id->pk.bytes;
    breq.sk         = id->sk.bytes;
    breq.to_fp      = sender_raw;          /* self-send (raw 64 bytes) */
    breq.token      = NULL;                /* native */
    breq.amount     = 0;
    breq.amount_all = 1;
    breq.fee        = fee;
    breq.gas_price  = gas_price;
    breq.coins      = &coin;
    breq.plan       = &plans[0];
    breq.rand       = flood_rand;          /* output seeds (nodus_random)   */
    breq.rand_ctx   = NULL;
    breq.shard_m    = 1;
    breq.shard_i    = 0;

    nodus_v2_spend_err_t be;
    memset(&be, 0, sizeof(be));
    int brc = nodus_v2_spend_build(&breq, built_out, &be);
    free(plans);
    if (brc != NODUS_V2_SPEND_OK) {
        fprintf(stderr, "spend build failed (rc=%d)\n", brc);
        return -1;
    }
    return 0;
}

/* ── per-request classification ──────────────────────────────────────── */

static void do_spend_once(struct worker *w) {
    nodus_pubkey_t spk = *w->spk;
    nodus_sig_t    ssig = *w->ssig;
    nodus_dnac_spend_result_t sres;
    memset(&sres, 0, sizeof(sres));
    char msg[128];
    msg[0] = '\0';
    int rc = nodus_client_dnac_spend_ex(w->client, w->wire_id, w->env,
                                        (uint32_t)w->env_len, &spk, &ssig,
                                        0, &sres, msg, sizeof(msg));
    w->c.sent++;
    if (rc == NODUS_ERR_TIMEOUT) {
        w->c.timeouts++;
    } else if (rc == 0) {
        /* CheckTx APPROVED — unexpected for a fabricated input */
        w->c.answered++;
        w->c.accepted++;
    } else if (strncmp(msg, "CheckTx", 7) == 0) {
        /* the node ran CheckTx and refused — the expected answer */
        w->c.answered++;
        w->c.refused++;
    } else {
        w->c.errors++;
    }
}

static void do_v3_block_once(struct worker *w) {
    nodus_dnac_v3_block_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = nodus_client_dnac_v3_block(w->client, w->height, 0,
                                        RPC_V3_BUDGET, &r);
    w->c.sent++;
    if (rc == 0) { w->c.answered++; nodus_client_free_v3_block_result(&r); }
    else if (rc == NODUS_ERR_TIMEOUT) w->c.timeouts++;
    else w->c.errors++;
}

static void do_balance_once(struct worker *w) {
    nodus_dnac_balance_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = nodus_client_dnac_balance(w->client, w->owner_hex, &r);
    w->c.sent++;
    if (rc == 0) { w->c.answered++; nodus_client_free_balance_result(&r); }
    else if (rc == NODUS_ERR_TIMEOUT) w->c.timeouts++;
    else w->c.errors++;
}

static void *worker_main(void *arg) {
    struct worker *w = (struct worker *)arg;
    while (atomic_load(&g_running)) {
        switch (w->mode) {
        case MODE_SPEND_INVALID: do_spend_once(w);   break;
        case MODE_V3_BLOCK:      do_v3_block_once(w); break;
        case MODE_BALANCE:       do_balance_once(w);  break;
        }
    }
    return NULL;
}

/* ── pipeline (non-waiting) sender ────────────────────────────────────── */

#define PIPELINE_BUF_SIZE (64 * 1024)   /* env ~7.6KB + pk 2592 + sig 4627  */

/* Encode ONE dnac_spend T2 request — the EXACT bytes
 * nodus_client_dnac_spend_ex emits (enc_dnac_query header, nodus_client.c
 * :3142-3151, then its five args :3190-3199) — with a fresh txn. 0 on a
 * buffer overrun (cbor_encoder_len is 0 when the encoder overflowed). */
static size_t encode_spend_frame(nodus_client_t *client, uint32_t txn,
                                 const struct worker *w,
                                 uint8_t *buf, size_t cap) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 5);                    /* t, y, q, tok, a */
    cbor_encode_cstr(&enc, "t");   cbor_encode_uint(&enc, txn);
    cbor_encode_cstr(&enc, "y");   cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");   cbor_encode_cstr(&enc, "dnac_spend");
    cbor_encode_cstr(&enc, "tok"); cbor_encode_bstr(&enc, client->token, NODUS_SESSION_TOKEN_LEN);
    cbor_encode_cstr(&enc, "a");   cbor_encode_map(&enc, 5);  /* tx,hash,pk,sig,fee */
    cbor_encode_cstr(&enc, "tx");   cbor_encode_bstr(&enc, w->env, (size_t)w->env_len);
    cbor_encode_cstr(&enc, "hash"); cbor_encode_bstr(&enc, w->wire_id, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(&enc, "pk");   cbor_encode_bstr(&enc, w->spk->bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "sig");  cbor_encode_bstr(&enc, w->ssig->bytes, NODUS_SIG_BYTES);
    cbor_encode_cstr(&enc, "fee");  cbor_encode_uint(&enc, 0);   /* fee is in the envelope */
    return cbor_encoder_len(&enc);
}

/* send_request's body (nodus_client.c:237): nodus_tcp_send under send_mutex,
 * with NO pending slot and NO wait. */
static int pipeline_send(nodus_client_t *client, const uint8_t *buf, size_t len) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
    if (!conn) return -1;
    pthread_mutex_lock(&client->send_mutex);
    int rc = nodus_tcp_send(conn, buf, len);
    pthread_mutex_unlock(&client->send_mutex);
    return rc;
}

static void *pipeline_sender_main(void *arg) {
    struct worker *w = (struct worker *)arg;
    uint8_t *buf = malloc(PIPELINE_BUF_SIZE);
    if (!buf) return NULL;
    const uint64_t burst = w->pipeline ? w->pipeline : 1;
    const uint64_t rate  = w->rate ? w->rate : 1;
    const uint64_t interval_ns = burst * 1000000000ULL / rate;   /* per burst */
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    while (atomic_load(&g_running) && !g_sig_stop) {
        for (uint64_t i = 0; i < burst; i++) {
            if (!atomic_load(&g_running) || g_sig_stop) break;
            uint32_t txn = atomic_fetch_add(&w->client->next_txn, 1);
            size_t len = encode_spend_frame(w->client, txn, w, buf, PIPELINE_BUF_SIZE);
            if (len == 0) { w->c.send_fail++; continue; }
            if (pipeline_send(w->client, buf, len) != 0) w->c.send_fail++;
            else w->c.sent++;
        }
        /* pace to the average rate R: the next burst at next += interval.
         * TIMER_ABSTIME with a time already past returns at once, so a
         * sender that cannot keep up never sleeps negative — it just runs
         * flat out (the honest ceiling of this host + one TCP socket). */
        next.tv_sec  += (time_t)(interval_ns / 1000000000ULL);
        next.tv_nsec += (long)(interval_ns % 1000000000ULL);
        if (next.tv_nsec >= 1000000000L) { next.tv_sec++; next.tv_nsec -= 1000000000L; }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }
    free(buf);
    return NULL;
}

/* ── usage / args ────────────────────────────────────────────────────── */

static void usage(void) {
    fprintf(stderr,
      "Usage: stagef_rpc_flood --host 127.0.0.1 --port <client port>\n"
      "                        --mode {spend-invalid|v3-block|balance}\n"
      "                        [--sessions S (1..19, default 19)]\n"
      "                        [--threads T (1..64 per session, default 32)]\n"
      "                        [--seconds D (default 20)]\n"
      "                        [--height H (v3-block; default the tip)]\n"
      "                        [--owner HEX128 (balance; required)]\n"
      "                        [--pipeline N (1..4096; non-waiting mode,\n"
      "                           spend-invalid only — fire frames, do not\n"
      "                           wait; answers are NOT counted)]\n"
      "                        [--rate R (pipeline frames/s per session,\n"
      "                           default 2000)]\n"
      "                        [--stats-file PATH]\n"
      "  TEST-ONLY localhost load. Asserts no threshold; it MEASURES.\n");
}

static int parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    if (!s || !*s) return -1;
    unsigned long long v = strtoull(s, &end, 10);
    if (!end || *end != '\0') return -1;
    *out = (uint64_t)v;
    return 0;
}

int main(int argc, char **argv) {
    /* line-buffered: bench_rpc_flood.sh waits for the [proof] / [info]
     * line in the redirected log; fully buffered, it appears only at exit */
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *host = "127.0.0.1";
    const char *mode_s = NULL, *owner_hex = NULL, *stats_path = NULL;
    uint64_t port = 0, sessions = 19, threads = 32, seconds = 20, height = 0;
    uint64_t pipeline = 0, rate = 2000;
    int have_height = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--host")   && i + 1 < argc) host = argv[++i];
        else if (!strcmp(a, "--port")   && i + 1 < argc) { if (parse_u64(argv[++i], &port))     { usage(); return 1; } }
        else if (!strcmp(a, "--mode")   && i + 1 < argc) mode_s = argv[++i];
        else if (!strcmp(a, "--sessions") && i + 1 < argc) { if (parse_u64(argv[++i], &sessions)) { usage(); return 1; } }
        else if (!strcmp(a, "--threads")  && i + 1 < argc) { if (parse_u64(argv[++i], &threads))  { usage(); return 1; } }
        else if (!strcmp(a, "--seconds")  && i + 1 < argc) { if (parse_u64(argv[++i], &seconds))  { usage(); return 1; } }
        else if (!strcmp(a, "--height")   && i + 1 < argc) { if (parse_u64(argv[++i], &height))   { usage(); return 1; } have_height = 1; }
        else if (!strcmp(a, "--owner")    && i + 1 < argc) owner_hex = argv[++i];
        else if (!strcmp(a, "--pipeline") && i + 1 < argc) { if (parse_u64(argv[++i], &pipeline)) { usage(); return 1; } }
        else if (!strcmp(a, "--rate")     && i + 1 < argc) { if (parse_u64(argv[++i], &rate))     { usage(); return 1; } }
        else if (!strcmp(a, "--stats-file") && i + 1 < argc) stats_path = argv[++i];
        else { fprintf(stderr, "unknown or incomplete argument: %s\n", a); usage(); return 1; }
    }

    enum rpc_mode mode;
    if      (mode_s && !strcmp(mode_s, "spend-invalid")) mode = MODE_SPEND_INVALID;
    else if (mode_s && !strcmp(mode_s, "v3-block"))      mode = MODE_V3_BLOCK;
    else if (mode_s && !strcmp(mode_s, "balance"))       mode = MODE_BALANCE;
    else { fprintf(stderr, "--mode must be spend-invalid | v3-block | balance\n"); usage(); return 1; }

    if (port == 0 || port > 65535) { fprintf(stderr, "--port must be 1..65535\n"); return 1; }
    if (sessions < 1 || sessions > 19) { fprintf(stderr, "--sessions must be 1..19 (20 connections per IP cap, nodus_tcp.c:1069)\n"); return 1; }
    if (threads < 1 || threads > NODUS_MAX_PENDING) { fprintf(stderr, "--threads must be 1..%d (NODUS_MAX_PENDING per client)\n", (int)NODUS_MAX_PENDING); return 1; }
    if (seconds < 1) { fprintf(stderr, "--seconds must be >= 1\n"); return 1; }
    if (mode == MODE_BALANCE && (!owner_hex || strlen(owner_hex) != 128)) {
        fprintf(stderr, "balance mode needs --owner <128 lowercase hex>\n");
        return 1;
    }
    if (pipeline != 0) {
        if (mode != MODE_SPEND_INVALID) {
            fprintf(stderr, "--pipeline is spend-invalid only (it fires the dnac_spend frame non-waiting)\n");
            return 1;
        }
        if (pipeline > 4096) { fprintf(stderr, "--pipeline N must be 1..4096\n"); return 1; }
        if (rate < 1) { fprintf(stderr, "--rate R must be >= 1\n"); return 1; }
    }

    const uint64_t S = sessions, T = threads;
    const uint64_t n_ident = (S + 3) / 4;   /* ceil(S/4): <= 4 sessions each */

    /* ── ephemeral identities (in memory only) ───────────────────────── */
    nodus_identity_t *ids = calloc(n_ident, sizeof(*ids));
    if (!ids) { fprintf(stderr, "out of memory\n"); return 1; }
    for (uint64_t i = 0; i < n_ident; i++) {
        if (nodus_identity_generate(&ids[i]) != 0) {
            fprintf(stderr, "ephemeral identity generation failed\n");
            for (uint64_t j = 0; j < i; j++) nodus_identity_clear(&ids[j]);
            free(ids);
            return 1;
        }
    }

    /* ── one client per session, connected and authenticated ─────────── */
    /* everything `cleanup` frees is declared here, before the first goto:
     * a session that fails to connect jumps there before the spend-mode
     * buffers below are set (Release -Wmaybe-uninitialized, 2026-10-14) */
    nodus_v2_spend_built_t *builts = NULL;
    nodus_pubkey_t *spks = NULL;
    nodus_sig_t    *ssigs = NULL;
    nodus_client_t *clients = calloc(S, sizeof(*clients));
    int *connected = calloc(S, sizeof(*connected));
    if (!clients || !connected) {
        fprintf(stderr, "out of memory\n");
        free(clients); free(connected);
        for (uint64_t i = 0; i < n_ident; i++) nodus_identity_clear(&ids[i]);
        free(ids);
        return 1;
    }
    int setup_rc = 1;
    for (uint64_t s = 0; s < S; s++) {
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", host);
        cfg.servers[0].port = (uint16_t)port;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        const nodus_identity_t *id = &ids[s / 4];   /* <= 4 sessions / id */
        if (nodus_client_init(&clients[s], &cfg, id) != 0) {
            fprintf(stderr, "session %" PRIu64 ": client_init failed\n", s);
            goto cleanup;
        }
        connected[s] = 1;   /* init owns a close */
        if (nodus_client_connect(&clients[s]) != 0) {
            fprintf(stderr, "session %" PRIu64 ": connect/auth failed (%s:%" PRIu64 ")\n", s, host, port);
            goto cleanup;
        }
    }

    /* ── mode-specific setup ─────────────────────────────────────────── */
    uint8_t chain32[DNA_CHAIN_ID_LEN];

    if (mode == MODE_SPEND_INVALID) {
        bool has32 = false;
        if (nodus_client_dnac_chain_id32(&clients[0], &has32, chain32) != 0 || !has32) {
            fprintf(stderr, "this node is not on a version-3 chain (no chain_id32)\n");
            goto cleanup;
        }
        bool has_tip = false;
        uint64_t tip = 0;
        if (nodus_client_dnac_supply_tip(&clients[0], &has_tip, &tip) != 0 || !has_tip || tip == 0) {
            fprintf(stderr, "could not read the committed tip (supply_tip)\n");
            goto cleanup;
        }
        nodus_v2_ruleset_id_t rs;
        if (flood_select_ruleset(&clients[0], &rs) != 0) goto cleanup;
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        if (nodus_client_dnac_fee_info(&clients[0], &fi) != 0) {
            fprintf(stderr, "dnac_fee_info failed — gas price unknown\n");
            goto cleanup;
        }
        uint64_t gas_price = fi.gas_price;

        builts = calloc(S, sizeof(*builts));
        spks   = calloc(S, sizeof(*spks));
        ssigs  = calloc(S, sizeof(*ssigs));
        if (!builts || !spks || !ssigs) { fprintf(stderr, "out of memory\n"); goto cleanup; }
        for (uint64_t s = 0; s < S; s++) {
            const nodus_identity_t *id = &ids[s / 4];
            if (flood_build_invalid_spend(id, &rs, chain32, tip, gas_price, &builts[s]) != 0) {
                fprintf(stderr, "session %" PRIu64 ": envelope build failed\n", s);
                goto cleanup;
            }
            memcpy(spks[s].bytes, id->pk.bytes, NODUS_PK_BYTES);
            nodus_sign(&ssigs[s], builts[s].wire_id, 64, &id->sk);
        }

        /* PROVE the request reaches CheckTx: submit session 0's envelope
         * once and read the node's answer. */
        {
            nodus_dnac_spend_result_t sres;
            memset(&sres, 0, sizeof(sres));
            char msg[128]; msg[0] = '\0';
            int rc = nodus_client_dnac_spend_ex(&clients[0], builts[0].wire_id,
                        builts[0].env, (uint32_t)builts[0].env_len,
                        &spks[0], &ssigs[0], 0, &sres, msg, sizeof(msg));
            if (rc != 0 && strncmp(msg, "CheckTx", 7) == 0) {
                printf("[proof] first submission reached CheckTx and was "
                       "refused: rc=%d node=\"%s\" (tip %" PRIu64 ", gas_price "
                       "%" PRIu64 ")\n", rc, msg, tip, gas_price);
            } else {
                fprintf(stderr, "[proof] first submission did NOT produce a "
                        "CheckTx refusal (rc=%d, node=\"%s\") — the load would "
                        "not prove CheckTx work; aborting\n", rc, msg);
                goto cleanup;
            }
        }
    } else if (mode == MODE_V3_BLOCK) {
        if (!have_height || height == 0) {
            bool has_tip = false; uint64_t tip = 0;
            if (nodus_client_dnac_supply_tip(&clients[0], &has_tip, &tip) != 0 || !has_tip || tip == 0) {
                fprintf(stderr, "v3-block: no --height and could not read the tip\n");
                goto cleanup;
            }
            height = tip;
        }
        printf("[info] v3-block mode: height %" PRIu64 ", budget %u bytes\n", height, (unsigned)RPC_V3_BUDGET);
    } else { /* balance */
        printf("[info] balance mode: owner %.16s...\n", owner_hex);
    }

    /* ── launch the load ─────────────────────────────────────────────── */
    /* pipeline mode: ONE sender thread per session; waiting modes: T worker
     * threads per session (S*T total). */
    const uint64_t W = S * T;
    const uint64_t NW = pipeline ? S : W;
    struct worker *workers = calloc(NW, sizeof(*workers));
    if (!workers) { fprintf(stderr, "out of memory\n"); goto cleanup; }
    if (pipeline) {
        for (uint64_t s = 0; s < S; s++) {
            struct worker *w = &workers[s];
            w->client      = &clients[s];
            w->mode        = mode;              /* spend-invalid (enforced)   */
            w->is_pipeline = 1;
            w->pipeline    = pipeline;
            w->rate        = rate;
            w->env     = builts[s].env;
            w->env_len = builts[s].env_len;
            w->wire_id = builts[s].wire_id;
            w->spk     = &spks[s];
            w->ssig    = &ssigs[s];
        }
    } else {
        for (uint64_t s = 0; s < S; s++) {
            for (uint64_t t = 0; t < T; t++) {
                struct worker *w = &workers[s * T + t];
                w->client = &clients[s];
                w->mode   = mode;
                w->height = height;
                w->owner_hex = owner_hex;
                if (mode == MODE_SPEND_INVALID) {
                    w->env     = builts[s].env;
                    w->env_len = builts[s].env_len;
                    w->wire_id = builts[s].wire_id;
                    w->spk     = &spks[s];
                    w->ssig    = &ssigs[s];
                }
            }
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* pipeline mode: the SDK reader thread logs one WARN per answer it
     * cannot correlate (no pending slot — nodus_client.c client_on_frame
     * :654), and the nodus standalone log shim (nodus_log_shim.c) has NO
     * level setter — its threshold is hardcoded at INFO, so WARN always
     * prints to stderr. At R frames/s per session that floods. The proof
     * (above) has already printed to STDOUT, so redirect THIS process's
     * stderr to /dev/null for the flood: it silences the SDK WARN flood at
     * the source (and, as a documented tradeoff, any genuine SDK ERROR the
     * reader thread might emit during the load — stdout keeps the stats). */
    if (pipeline) {
        fflush(stdout);
        if (!freopen("/dev/null", "w", stderr)) { /* keep going if it fails */ }
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    atomic_store(&g_running, true);
    uint64_t launched = 0;
    for (uint64_t i = 0; i < NW; i++) {
        void *(*fn)(void *) = pipeline ? pipeline_sender_main : worker_main;
        if (pthread_create(&workers[i].tid, NULL, fn, &workers[i]) != 0) {
            fprintf(stderr, "pthread_create failed at worker %" PRIu64 "\n", i);
            break;
        }
        launched++;
    }
    if (launched != NW) {
        atomic_store(&g_running, false);
        for (uint64_t i = 0; i < launched; i++) pthread_join(workers[i].tid, NULL);
        free(workers);
        goto cleanup;
    }

    /* run for D wall-seconds — this IS the measurement window length, not
     * a verdict wait; poll so we stop promptly */
    while (!g_sig_stop) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double el = (double)(now.tv_sec - t0.tv_sec) + (double)(now.tv_nsec - t0.tv_nsec) / 1e9;
        if (el >= (double)seconds) break;
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 100000000L };  /* 100 ms */
        nanosleep(&nap, NULL);
    }
    atomic_store(&g_running, false);
    for (uint64_t i = 0; i < NW; i++) pthread_join(workers[i].tid, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (elapsed < 1e-3) elapsed = 1e-3;

    /* ── aggregate ───────────────────────────────────────────────────── */
    struct counters tot;
    memset(&tot, 0, sizeof(tot));
    for (uint64_t i = 0; i < NW; i++) {
        tot.sent      += workers[i].c.sent;
        tot.answered  += workers[i].c.answered;
        tot.refused   += workers[i].c.refused;
        tot.accepted  += workers[i].c.accepted;
        tot.errors    += workers[i].c.errors;
        tot.timeouts  += workers[i].c.timeouts;
        tot.send_fail += workers[i].c.send_fail;
    }
    free(workers);

    double sent_ps = (double)tot.sent / elapsed;
    double ans_ps  = (double)tot.answered / elapsed;

    char out[4096];
    int n = snprintf(out, sizeof(out),
        "mode=%s\n""host=%s\n""port=%" PRIu64 "\n""sessions=%" PRIu64 "\n"
        "threads_per_session=%" PRIu64 "\n""identities=%" PRIu64 "\n"
        "pipeline=%" PRIu64 "\n""rate=%" PRIu64 "\n""answers_counted=%d\n"
        "seconds_requested=%" PRIu64 "\n""seconds_elapsed=%.3f\n"
        "sent=%" PRIu64 "\n""answered=%" PRIu64 "\n""refused=%" PRIu64 "\n"
        "accepted=%" PRIu64 "\n""errors=%" PRIu64 "\n""timeouts=%" PRIu64 "\n"
        "send_failures=%" PRIu64 "\n"
        "sent_per_s=%.1f\n""answered_per_s=%.1f\n""stopped_by_signal=%d\n",
        mode_s, host, port, S, (pipeline ? (uint64_t)1 : T), n_ident,
        pipeline, (pipeline ? rate : (uint64_t)0), (pipeline ? 0 : 1),
        seconds, elapsed,
        tot.sent, tot.answered, tot.refused, tot.accepted, tot.errors,
        tot.timeouts, tot.send_fail, sent_ps, ans_ps, (int)g_sig_stop);
    if (n < 0) n = 0;
    fputs(out, stdout);
    if (stats_path) {
        FILE *f = fopen(stats_path, "w");
        if (!f) {
            fprintf(stderr, "could not open --stats-file %s\n", stats_path);
        } else {
            fputs(out, f);
            fclose(f);
        }
    }

    setup_rc = 0;

cleanup:
    if (mode == MODE_SPEND_INVALID && builts) {
        for (uint64_t s = 0; s < S; s++) nodus_v2_spend_built_free(&builts[s]);
    }
    free(builts); free(spks); free(ssigs);
    for (uint64_t s = 0; s < S; s++) if (connected[s]) nodus_client_close(&clients[s]);
    free(clients); free(connected);
    for (uint64_t i = 0; i < n_ident; i++) nodus_identity_clear(&ids[i]);
    free(ids);
    return setup_rc;
}
