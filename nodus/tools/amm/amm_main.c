/**
 * @file amm_main.c
 * @brief nodus-amm: the swap bot service (USDT on Ethereum <-> NODUS).
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 10)
 * sections 4 (amm_main: wiring, single-instance lock before key access), 11,
 * 15 (settings), 17; the pattern of tools/faucet/faucet_main.c.
 *
 *   nodus-amm --config <file>
 *
 * ORDER OF START: config -> the single-instance lock -> the keys -> journal ->
 * the real seams (Nodus node session, Ethereum providers over libcurl, the ETH
 * price adapter) -> the watchers and payers -> the engine -> HTTP on
 * 127.0.0.1 -> the worker. The lock comes BEFORE any key is read (FAUCET.md:
 * 154), so two starts can never both use one key.
 *
 * Threads: the main thread serves HTTP (the price question, the signed
 * request, status); ONE worker thread runs the engine round and the ETH price
 * refresh. Every engine call (HTTP or worker) is serialised by one mutex:
 * the payers' quote/sign and the engine's reads are not documented as safe
 * for two threads at once (reported). The journal and the node session have
 * their own mutexes.
 *
 * REFUSALS TO START (nothing is invented around them): the settings file; a
 * second instance; a missing key; a Nodus address history that is off or
 * starts above nodus_start_height (amm_nodus_watch_start_check). The Ethereum
 * chain id is the setting eth_chain_id (givens item 77: Sepolia 11155111 in
 * the test phase); the watcher and the payer take it in their configuration.
 *
 * LIQUIDITY ADD (revision 12): the add question, the add route and the add's
 * counting and commit are wired; the Foundation's start pool enters through the
 * first add (plan section 14, givens item 91): without a committed add every
 * price question answers `unavailable`.
 *
 * LIQUIDITY WITHDRAW (plan sections 6.4.6, 14): POST /amm/liquidity/withdraw is
 * wired (be_withdraw); the engine acts on an accepted withdrawal after
 * liquidity_wait_eth_blocks Ethereum blocks and its two payouts go through the
 * NODUS and USDT payers like every other owed payout; a withdrawal with a side
 * that is nothing after its network fee is refused whole (amm_engine.h).
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"
#include "amm_cfg.h"
#include "amm_engine.h"
#include "amm_eth_rpc.h"
#include "amm_http.h"
#include "amm_node_real.h"
#include "amm_price.h"

#define LOG_TAG "AMM_MAIN"

static atomic_int g_stop = 0;
static void on_signal(int sig) { (void)sig; atomic_store(&g_stop, 1); }

static pthread_mutex_t g_eng_mu = PTHREAD_MUTEX_INITIALIZER;

static uint64_t unix_now(void *ctx) { (void)ctx; return (uint64_t)time(NULL); }

static uint64_t mono_s(void *ctx) {
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static int rand_fn(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    return nodus_random(buf, len);
}

/* ── the backend of the HTTP routes ───────────────────────────────────── */

typedef struct {
    amm_engine_t *eng;
    const amm_cfg_t *cfg;
    amm_journal_t *j;
} app_t;

static int be_quote(void *c, amm_dir_t dir, uint64_t amount, uint64_t dl, amm_quote_answer_t *o) {
    app_t *a = c;
    pthread_mutex_lock(&g_eng_mu);
    int rc = amm_engine_quote(a->eng, dir, amount, dl, o);
    pthread_mutex_unlock(&g_eng_mu);
    return rc;
}

static int map_acc(int acc, const amm_swap_t *s, uint32_t req_no, uint32_t *req_out, uint32_t *open_req) {
    switch (acc) {
    case AMM_ACC_RECEIVED:  *req_out = req_no; return AMM_HS_RECEIVED;
    case AMM_ACC_NO_NUMBER: return AMM_HS_NO_NUMBER;
    case AMM_ACC_AMOUNT:    return AMM_HS_AMOUNT;
    case AMM_ACC_REUSED:    return AMM_HS_REUSED;
    case AMM_ACC_OPEN:      *open_req = (uint32_t)s->req_no_bot; return AMM_HS_OPEN;
    case AMM_ACC_USED:      return AMM_HS_USED;
    case AMM_ACC_EXPIRED:   return AMM_HS_EXPIRED;
    default:                return AMM_HS_ERR;
    }
}

static int map_req(int rc) {
    switch (rc) {
    case AMM_REQ_FORMAT:    return AMM_HS_FORMAT;
    case AMM_REQ_CHAIN:     return AMM_HS_CHAIN;
    case AMM_REQ_ADDRESS:   return AMM_HS_ADDRESS;
    case AMM_REQ_SIGNATURE: return AMM_HS_SIGNATURE;
    case AMM_REQ_PAIR:      return AMM_HS_FORMAT;
    case AMM_REQ_REUSED:    return AMM_HS_REUSED;
    default:                return AMM_HS_ERR;
    }
}

static int be_swap_usdt(void *c, const amm_req_usdt_in_t *in, uint32_t *req_out, uint32_t *open_req) {
    app_t *a = c;
    amm_req_usdt_t r;
    memset(&r, 0, sizeof(r));
    int rc = amm_req_usdt_verify(a->cfg, a->j, in, &r);
    if (rc != AMM_REQ_OK) return map_req(rc);
    amm_swap_t s;
    memset(&s, 0, sizeof(s));
    pthread_mutex_lock(&g_eng_mu);
    int acc = amm_engine_accept_usdt(a->eng, &r, &s);
    pthread_mutex_unlock(&g_eng_mu);
    return map_acc(acc, &s, (uint32_t)r.request_number, req_out, open_req);
}

static int be_swap_nodus(void *c, const amm_req_nodus_in_t *in, uint32_t *req_out, uint32_t *open_req) {
    app_t *a = c;
    amm_req_nodus_to_usdt_t r;
    memset(&r, 0, sizeof(r));
    int rc = amm_req_nodus_to_usdt_verify(a->cfg, a->j, in, &r);
    if (rc != AMM_REQ_OK) return map_req(rc);
    amm_swap_t s;
    memset(&s, 0, sizeof(s));
    pthread_mutex_lock(&g_eng_mu);
    int acc = amm_engine_accept_nodus(a->eng, &r, &s);
    pthread_mutex_unlock(&g_eng_mu);
    return map_acc(acc, &s, (uint32_t)r.request_number, req_out, open_req);
}

static int be_add_question(void *c, amm_side_t side, uint64_t amount, uint64_t dl,
                           amm_add_answer_t *o) {
    app_t *a = c;
    pthread_mutex_lock(&g_eng_mu);
    int rc = amm_engine_add_question(a->eng, side, amount, dl, o);
    pthread_mutex_unlock(&g_eng_mu);
    return rc;
}

static int be_add_accept(void *c, const amm_req_liq_eth_in_t *eth, const amm_req_nodus_in_t *nodus,
                         uint32_t *req_out, uint32_t *open_req) {
    app_t *a = c;
    amm_req_liq_add_t r;
    memset(&r, 0, sizeof(r));
    int rc = amm_req_liquidity_add_verify(a->cfg, a->j, eth, nodus, &r);
    if (rc != AMM_REQ_OK) return map_req(rc);
    pthread_mutex_lock(&g_eng_mu);
    int acc = amm_engine_accept_add(a->eng, &r, open_req);
    pthread_mutex_unlock(&g_eng_mu);
    switch (acc) {
    case AMM_ACC_RECEIVED:  *req_out = (uint32_t)r.request_number; return AMM_HS_RECEIVED;
    case AMM_ACC_NO_NUMBER: return AMM_HS_NO_NUMBER;
    case AMM_ACC_AMOUNT:    return AMM_HS_AMOUNT;
    case AMM_ACC_REUSED:    return AMM_HS_REUSED;
    case AMM_ACC_OPEN:      return AMM_HS_OPEN;
    case AMM_ACC_USED:      return AMM_HS_USED;
    case AMM_ACC_EXPIRED:   return AMM_HS_EXPIRED;
    case AMM_ACC_DUP_TRANSFER: return AMM_HS_USED;
    default:                return AMM_HS_ERR;
    }
}

static int be_withdraw(void *c, const amm_req_nodus_in_t *in, uint64_t *req_out) {
    app_t *a = c;
    amm_req_liq_withdraw_t r;
    memset(&r, 0, sizeof(r));
    int rc = amm_req_liquidity_withdraw_verify(a->cfg, a->j, in, &r);
    if (rc != AMM_REQ_OK) return map_req(rc);
    pthread_mutex_lock(&g_eng_mu);
    int acc = amm_engine_accept_withdraw(a->eng, &r);
    pthread_mutex_unlock(&g_eng_mu);
    switch (acc) {
    case AMM_ACC_RECEIVED:    *req_out = r.request_number; return AMM_HS_RECEIVED;
    case AMM_ACC_REUSED:      return AMM_HS_REUSED;
    case AMM_ACC_PAUSED:      return AMM_HS_PAUSED;
    case AMM_ACC_NO_POSITION: return AMM_HS_NO_POSITION;
    case AMM_ACC_UNAVAILABLE: return AMM_HS_UNAVAILABLE;
    default:                  return AMM_HS_ERR;
    }
}

static int be_get_swap(void *c, uint32_t n, amm_swap_t *o) {
    app_t *a = c;
    return amm_journal_swap_by_botreq(a->j, n, o);
}

static int be_status(void *c, amm_engine_status_t *o) {
    app_t *a = c;
    pthread_mutex_lock(&g_eng_mu);
    int rc = amm_engine_status(a->eng, o);
    pthread_mutex_unlock(&g_eng_mu);
    return rc;
}

static void route_cb(void *ctx, const amm_http_req_t *req, uint64_t deadline_ms, int *status,
                     char *body, size_t cap) {
    amm_http_route(ctx, req, deadline_ms, status, body, cap);
}

/* ── the worker ───────────────────────────────────────────────────────── */

typedef struct {
    app_t *app;
    amm_price_t *price;
    uint64_t interval_ms;
} worker_t;

static void *worker_main(void *arg) {
    worker_t *w = arg;
    while (!atomic_load(&g_stop)) {
        (void)amm_price_poll(w->price, 0);
        pthread_mutex_lock(&g_eng_mu);
        amm_engine_step_t st;
        int rc = amm_engine_step(w->app->eng, 0, &st);
        pthread_mutex_unlock(&g_eng_mu);
        if (rc != 0) QGP_LOG_ERROR(LOG_TAG, "the engine round reported a journal fault");
        struct timespec ts = { (time_t)(w->interval_ms / 1000),
                               (long)((w->interval_ms % 1000) * 1000000L) };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* ── keys ─────────────────────────────────────────────────────────────── */

/* The bot's secp256k1 key: a file of exactly 64 hex digits (and an optional
 * newline), readable by its owner only. */
static int load_eth_key(const char *path, uint8_t sk[32]) {
    struct stat sb;
    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode) || (sb.st_mode & 077) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "the Ethereum key file is missing or readable by others: %s", path);
        return -1;
    }
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char buf[80];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
    int ok = n == 64;
    for (size_t i = 0; ok && i < 64; i++) ok = isxdigit((unsigned char)buf[i]) != 0;
    if (ok) {
        for (int i = 0; i < 32; i++) {
            unsigned v = 0;
            sscanf(buf + 2 * i, "%2x", &v);
            sk[i] = (uint8_t)v;
        }
    }
    memset(buf, 0, sizeof(buf));
    if (!ok) QGP_LOG_ERROR(LOG_TAG, "the Ethereum key file does not hold 64 hex digits");
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *cfg_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--config") && i + 1 < argc) cfg_path = argv[++i];
        else { fprintf(stderr, "usage: %s --config <file>\n", argv[0]); return 2; }
    }
    if (!cfg_path) { fprintf(stderr, "usage: %s --config <file>\n", argv[0]); return 2; }
    umask(077);

    amm_cfg_t cfg;
    char err[160];
    if (amm_cfg_load(cfg_path, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "config refused: %s\n", err);
        return 1;
    }

    int rc = 1, lock_fd = -1;
    uint8_t sk[32];
    nodus_identity_t id;
    memset(&id, 0, sizeof(id));
    memset(sk, 0, sizeof(sk));
    amm_journal_t *journal = NULL;
    amm_node_real_t *real = NULL;
    amm_node_t node;
    amm_rpc_curl_t *rpc_curl = NULL;
    amm_price_curl_t *price_curl = NULL;
    amm_eth_rpc_t *rpcs[AMM_MAX_PROVIDERS];
    amm_eth_provider_t provs[AMM_MAX_PROVIDERS];
    int n_rpc = 0;
    amm_price_t *price = NULL;
    amm_eth_watch_t *ew = NULL;
    amm_eth_pay_t *ep = NULL;
    amm_nodus_watch_t *nw = NULL;
    amm_nodus_pay_t *np = NULL;
    amm_engine_t *eng = NULL;
    amm_http_t *http = NULL;
    int worker_started = 0;
    pthread_t worker;
    worker_t wk;
    app_t app;
    amm_http_ctx_t hctx;
    memset(rpcs, 0, sizeof(rpcs));

    /* one instance only, taken BEFORE any key is read (FAUCET.md:154) */
    lock_fd = open(cfg.lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "another nodus-amm holds %s (or it cannot be opened) - refusing to start",
                      cfg.lock_path);
        goto done;
    }

    if (load_eth_key(cfg.eth_key_path, sk) != 0) goto done;
    if (nodus_identity_load_readonly(cfg.nodus_key_dir, &id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot load the Nodus identity from %s", cfg.nodus_key_dir);
        goto done;
    }
    if (amm_journal_open(cfg.journal_path, &journal) != 0) goto done;
    if (amm_node_real_open(&cfg, &id, &real, &node) != 0) goto done;

    /* Ethereum providers over libcurl */
    if (amm_rpc_curl_global_init() != 0) goto done;
    rpc_curl = amm_rpc_curl_new((uint32_t)cfg.rpc_timeout_ms);
    price_curl = amm_price_curl_new((uint32_t)cfg.rpc_timeout_ms);
    if (!rpc_curl || !price_curl) goto done;
    for (int i = 0; i < cfg.n_providers; i++) {
        amm_eth_rpc_cfg_t rc_;
        char nm[AMM_RPC_NAME_MAX];
        snprintf(nm, sizeof(nm), "provider-%d", i + 1);      /* the URL carries a key: never logged */
        memset(&rc_, 0, sizeof(rc_));
        rc_.url = cfg.eth_providers[i]; rc_.name = nm; rc_.post = amm_rpc_curl_post;
        rc_.post_ctx = rpc_curl; rc_.max_response = (size_t)cfg.eth_max_response;
        rpcs[n_rpc] = amm_eth_rpc_new(&rc_);
        if (!rpcs[n_rpc]) { QGP_LOG_ERROR(LOG_TAG, "provider %d refused", i + 1); goto done; }
        amm_eth_rpc_provider(rpcs[n_rpc], &provs[n_rpc]);
        n_rpc++;
    }

    /* the ETH price adapter */
    amm_price_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.get = amm_price_curl_get; pc.get_ctx = price_curl; pc.now_s = mono_s;
    pc.sources = cfg.eth_price_sources; pc.min_sources = cfg.eth_price_min_sources;
    pc.max_age_seconds = cfg.eth_price_max_age_seconds;
    price = amm_price_new(&pc);
    if (!price) goto done;
    amm_eth_price_t seam;
    amm_price_seam(price, &seam);

    amm_eth_pay_cfg_t epc;
    memset(&epc, 0, sizeof(epc));
    epc.providers = provs; epc.n_providers = n_rpc; epc.quorum = cfg.eth_quorum; epc.price = seam;
    epc.journal = journal; epc.chain_id = cfg.eth_chain_id; epc.sk = sk;
    memcpy(epc.usdt, cfg.usdt_contract, 20);
    epc.final_depth = cfg.payout_final_depth_eth; epc.payouts_paused = cfg.payouts_paused;
    ep = amm_eth_pay_new(&epc);
    if (!ep) { QGP_LOG_ERROR(LOG_TAG, "the Ethereum payer refused its configuration"); goto done; }
    uint8_t self_eth[20];
    amm_eth_pay_self(ep, self_eth);
    if (memcmp(self_eth, cfg.foundation_eth, 20) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "foundation_eth is not the address of the Ethereum key");
        goto done;
    }

    amm_eth_watch_cfg_t wc;
    memset(&wc, 0, sizeof(wc));
    wc.providers = provs; wc.n_providers = n_rpc; wc.quorum = cfg.eth_quorum;
    wc.chain_id = cfg.eth_chain_id;
    memcpy(wc.usdt, cfg.usdt_contract, 20); memcpy(wc.foundation, cfg.foundation_eth, 20);
    wc.conf_bound_usdt[0] = cfg.eth_conf_bound_1_usdt; wc.conf_bound_usdt[1] = cfg.eth_conf_bound_2_usdt;
    wc.conf_count[0] = cfg.eth_conf_count_1; wc.conf_count[1] = cfg.eth_conf_count_2;
    wc.conf_count[2] = cfg.eth_conf_count_3; wc.window_blocks = cfg.eth_reorg_window_blocks;
    wc.start_height = cfg.eth_start_height; wc.max_scan_blocks = (uint32_t)cfg.eth_max_scan_blocks;
    wc.journal = journal;
    ew = amm_eth_watch_new(&wc);
    if (!ew) { QGP_LOG_ERROR(LOG_TAG, "the Ethereum watcher refused its configuration"); goto done; }

    amm_nodus_pay_cfg_t npc;
    memset(&npc, 0, sizeof(npc));
    npc.node = &node; npc.journal = journal; npc.pk = id.pk.bytes; npc.sk = id.sk.bytes;
    npc.rand = rand_fn; memcpy(npc.chain_id, cfg.chain_id, 32);
    npc.expiry_ahead = cfg.nodus_expiry_ahead; npc.resubmit_blocks = cfg.nodus_resubmit_blocks;
    npc.scan_blocks = (uint32_t)cfg.nodus_scan_blocks; npc.payouts_paused = cfg.payouts_paused;
    np = amm_nodus_pay_new(&npc);
    if (!np) { QGP_LOG_ERROR(LOG_TAG, "the Nodus payer refused its configuration"); goto done; }
    if (strcmp(amm_nodus_pay_self(np), cfg.foundation_nodus) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "foundation_nodus is not the address of the Nodus key");
        goto done;
    }

    amm_nodus_watch_cfg_t nwc;
    memset(&nwc, 0, sizeof(nwc));
    nwc.node = &node; nwc.journal = journal;
    nwc.id_kind = AMM_NW_ID_WIRE;                /* plan 6.4.4: the wire id, agreed (givens 71) */
    nwc.start_height = cfg.nodus_start_height; nwc.liquidity_wait_blocks = cfg.liquidity_wait_nodus_blocks;
    nwc.page_limit = (uint32_t)cfg.nodus_page_limit; nwc.max_pages = (uint32_t)cfg.nodus_max_pages;
    nwc.inflight_max = cfg.inflight_max_usdt; nwc.held_keeps_room = cfg.held_keeps_room;
    nw = amm_nodus_watch_new(&nwc);
    if (!nw) { QGP_LOG_ERROR(LOG_TAG, "the Nodus watcher refused its configuration"); goto done; }
    {
        char why[160] = "";
        int sc = amm_nodus_watch_start_check(nw, 0, why, sizeof(why));
        if (sc != AMM_NW_OK) {
            QGP_LOG_ERROR(LOG_TAG, "the Nodus address history cannot serve the bot (%d): %s", sc, why);
            goto done;
        }
    }

    amm_engine_cfg_t ec;
    memset(&ec, 0, sizeof(ec));
    ec.cfg = &cfg; ec.journal = journal; ec.eth_watch = ew; ec.eth_pay = ep;
    ec.nodus_watch = nw; ec.nodus_pay = np; ec.node = node;
    ec.providers = provs; ec.n_providers = n_rpc; ec.quorum = cfg.eth_quorum; ec.price = seam;
    ec.now_unix = unix_now; ec.rand_fn = rand_fn;
    eng = amm_engine_new(&ec);
    if (!eng) { QGP_LOG_ERROR(LOG_TAG, "the engine refused its configuration"); goto done; }

    amm_pool_t pool;
    int pg = amm_journal_pool_get(journal, &pool);
    if (pg < 0) goto done;
    if (pg == 1)
        QGP_LOG_WARN(LOG_TAG, "the journal holds no ledger: every price question answers "
                     "unavailable until the Foundation's first liquidity add has committed "
                     "(plan section 14, givens item 91)");

    app.eng = eng; app.cfg = &cfg; app.j = journal;
    memset(&hctx, 0, sizeof(hctx));
    hctx.cfg = &cfg;
    hctx.be.ctx = &app; hctx.be.quote = be_quote; hctx.be.swap_usdt = be_swap_usdt;
    hctx.be.swap_nodus = be_swap_nodus; hctx.be.get_swap = be_get_swap; hctx.be.status = be_status;
    hctx.be.add_question = be_add_question; hctx.be.add_accept = be_add_accept;
    hctx.be.withdraw = be_withdraw;

    uint16_t bound = 0;
    if (amm_http_open((uint16_t)cfg.http_port, (int)cfg.http_conn_cap, (int)cfg.http_timeout_ms,
                      (size_t)cfg.http_max_body, (size_t)cfg.http_max_response, route_cb, &hctx,
                      &http, &bound) != 0) goto done;
    QGP_LOG_INFO(LOG_TAG, "listening on 127.0.0.1:%u", bound);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    wk.app = &app; wk.price = price; wk.interval_ms = cfg.worker_interval_ms;
    if (pthread_create(&worker, NULL, worker_main, &wk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot start the worker thread");
        goto done;
    }
    worker_started = 1;
    while (!atomic_load(&g_stop)) amm_http_poll(http, 500);
    rc = 0;

done:
    atomic_store(&g_stop, 1);
    if (worker_started) pthread_join(worker, NULL);
    amm_http_close(http);
    amm_engine_free(eng);
    amm_nodus_watch_free(nw);
    amm_nodus_pay_free(np);
    amm_eth_pay_free(ep);
    amm_eth_watch_free(ew);
    amm_price_free(price);
    for (int i = 0; i < n_rpc; i++) amm_eth_rpc_free(rpcs[i]);
    amm_price_curl_free(price_curl);
    amm_rpc_curl_free(rpc_curl);
    amm_node_real_close(real);
    amm_journal_close(journal);
    nodus_identity_clear(&id);
    memset(sk, 0, sizeof(sk));
    if (lock_fd >= 0) close(lock_fd);
    return rc;
}
