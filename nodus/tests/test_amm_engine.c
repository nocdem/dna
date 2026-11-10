/**
 * test_amm_engine.c -- the nodus-amm engine (amm_engine.c) with the REAL
 * journal, ledger, both watchers and both payers wired to STUB chains.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 10,
 * section 19 "test_amm_engine" as corrected by givens items 82-90):
 *   E1  the price question (givens items 66, 68, 82, 85, 86, 89): the answer
 *       carries the bot's number from the ledger (hand derived), the
 *       estimated network fee apart, a random 32-bit request number and the
 *       expiry (300 s); the approval row, its in-flight room and the number
 *       are written together; refusals: below swap_min_usdt (also measured on
 *       the USDT side of a NODUS amount), above swap_max_usdt, in-flight
 *       total, paused, stopped (a swap in unknown), the payout larger than
 *       what the bot's key holds (also less what it already owes), an
 *       unreadable fee or tip (never an approval, nothing written); a drawn
 *       number that is taken or zero is redrawn;
 *   E2  the signed request (givens items 83, 84, 87, 88): looked up by the
 *       request number, accepted only when direction and amount equal the
 *       answer, once; item 57 (same sender and amount) refuses the second
 *       with the open swap; an expired approval is refused; the delivery
 *       result is all the bot answers;
 *   E3  counting and payout: an Ethereum record that matches a signed
 *       approval moves it to paid_waiting_depth, a deep one to counted and,
 *       in the same step, to payout_pending with the ledger updated by the
 *       APPROVAL'S number although the depths changed after the question
 *       (hand derived); the NODUS payout is signed with gross = the number,
 *       the Nodus fee deducted (net + fee == gross) and submitted;
 *   E4  a record that matches no approval (another sender, another amount) is
 *       held; a number that cannot be applied (the output depth is below it)
 *       and a payment during swaps_paused are refunded, the ledger untouched;
 *   E5  a payout below the minimum after the fee becomes a refund and its
 *       ledger update is reversed (the reserves are the initial ones again);
 *       the USDT refund is signed with the REAL fee deducted (givens items
 *       51, 82);
 *   E6  DROPS (givens items 89, 90): a NODUS refund that is zero after the
 *       Nodus fee and a USDT refund whose Ethereum fee is not below its
 *       amount are not signed and not held: state dropped, no attempt;
 *   E7  release (plan section 13, givens item 54): the bot's clock passing the
 *       expiry releases NOTHING, signed or not; a NODUS -> USDT approval
 *       (signed or unsigned) expires only when the Nodus history was
 *       processed through a block time after the expiry; a USDT -> NODUS
 *       approval (signed or unsigned) only when the Ethereum window is fully
 *       observed; not before;
 *   E8  the network fee of a confirmed USDT payout is booked once to the
 *       Foundation AS USDT (givens items 80, 92); the pool is not touched; the
 *       booking is not stopped by 1,100 older paid rows (no lifetime row cap);
 *   E9  restart: the engine is rebuilt over the same journal after each
 *       stage and repeats nothing;
 *   E1b the funding check of a quote counts the refunds the bot owes in the
 *       payout asset, whatever the swap's direction (USDT refund of a USDT ->
 *       NODUS swap against a NODUS -> USDT quote, and the NODUS side);
 *   E10 a linked payment is counted only while its block time is within the
 *       approval's validity: moved outside by a reorganisation it matches no
 *       approval (swap unpaid again, record held); moved inside, counted;
 *   E11 a payment the watcher stored is matched after a downtime longer than
 *       the reorganisation window (the engine has no block window);
 *   E12 the setting eth_chain_id 11155111 reaches the watcher, the payer, the
 *       nonce key and the signature; providers on another chain than the
 *       setting are not used.
 * HAND VECTORS: pool 3*10^15 raw NODUS / 3*10^9 raw USDT. USDT -> NODUS of
 * 10^8 gives 93652445369406 (test_amm_ledger L3: 9*10^32 / 9.61*10^18);
 * NODUS -> USDT of 10^14 gives 93652445 (9*10^38 / 9.61*10^30). After the
 * first applied with the NODUS depth lowered to 2*10^15 meanwhile:
 * 2*10^15 - 93652445369406 = 1906347554630594 (not a recomputed quote).
 * FLAGS: a default build (the newest pinned rule-set generation), libcurl not
 * needed. ML-DSA-87 signing makes it slower than the other AMM tests. No
 * network, no real clock (the time and the tip are variables the test moves),
 * one mkdtemp directory per scenario under /tmp, removed.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN FALSELY PASS: the chains are scripted: the watchers' own reads
 * fail on purpose (the stubs answer an error for blocks and history) so the
 * records and rows the engine consumes are SEEDED into the journal the way the
 * watchers write them; the watchers' matching and depth logic is proved in
 * their own tests, not here. The Ethereum payout is proved up to the stored
 * signed transaction (its settlement by receipts is test_amm_eth_pay). The
 * fee figures come from stub seams. E8's 1,100 old paid rows are inserted by
 * SQL through a second connection (valid rows, no attempt), so it proves the
 * paged read, not the journal's own paid transitions; E10 moves a record by
 * rewriting its block fields in the journal, the way the watcher's reorg
 * handling does, it does not run the watcher's reorg detection; E11 sets the
 * stored tip cursor directly. The engine's own reads (balances, fee
 * estimate) do not check the providers' chain id (only the watcher and the
 * payer do): E12 does not exercise that.
 */
#include <dirent.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "amm_engine.h"
#include "crypto/nodus_identity.h"
#include "nodus/nodus_v2_spend.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── the world the stubs read ─────────────────────────────────────────── */

typedef struct {
    uint64_t now;                    /* wall clock, unix seconds              */
    uint64_t eth_tip, nodus_tip;
    uint64_t nodus_balance, usdt_balance;
    int      nodus_balance_rc;
    uint64_t price_fee;              /* USDT raw the price seam answers       */
    int      price_rc;
    uint32_t rq[8]; int rq_n, rq_i;  /* scripted request-number draws         */
    uint64_t rng;
    int      submits;
    uint8_t  chain[32];
    uint64_t eth_chain;              /* the chain id the Ethereum providers report */
} world_t;

static world_t W;

static uint64_t clock_fn(void *c) { (void)c; return W.now; }

static int rand_fn(void *c, uint8_t *buf, size_t len) {
    (void)c;
    if (W.rq_i < W.rq_n) {
        uint32_t v = W.rq[W.rq_i++];
        memset(buf, 0, len);
        buf[0] = (uint8_t)(v >> 24); buf[1] = (uint8_t)(v >> 16);
        buf[2] = (uint8_t)(v >> 8);  buf[3] = (uint8_t)v;
        for (size_t i = 4; i < len; i++) buf[i] = (uint8_t)(W.rng >> (i % 7));
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        W.rng ^= W.rng >> 12; W.rng ^= W.rng << 25; W.rng ^= W.rng >> 27;
        buf[i] = (uint8_t)((W.rng * 0x2545F4914F6CDD1DULL) >> 56);
    }
    if (len >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0) buf[3] = 1;
    return 0;
}

static int nrand(void *c, uint8_t *buf, size_t len) { return rand_fn(c, buf, len); }

/* the Nodus node */
static int n_chain(void *c, uint8_t out[32], uint64_t dl) {
    (void)c; (void)dl; memcpy(out, W.chain, 32); return AMM_NODE_OK;
}
static int n_ri(void *c, nodus_dnac_ruleset_info_t *out, uint64_t dl) {
    (void)c; (void)dl;
    memset(out, 0, sizeof(*out));
    uint32_t gen = nodus_v2_pins_generation_count();
    out->tip = W.nodus_tip;
    out->generation = gen;
    nodus_v2_pins_tuples(gen, &out->sys_version, out->sys_hash, &out->core_version, out->core_hash);
    return AMM_NODE_OK;
}
static int n_gas(void *c, uint64_t *out, uint64_t dl) { (void)c; (void)dl; *out = 0; return AMM_NODE_OK; }
static int n_btime(void *c, uint64_t h, uint64_t *t, uint64_t dl) {
    (void)c; (void)dl; (void)h; *t = 5000; return AMM_NODE_OK;
}
static int n_balance(void *c, const char *owner, const uint8_t token[64], uint64_t *tip,
                     uint64_t *total, uint64_t dl) {
    (void)c; (void)owner; (void)token; (void)dl;
    if (W.nodus_balance_rc) return W.nodus_balance_rc;
    *tip = W.nodus_tip; *total = W.nodus_balance;
    return AMM_NODE_OK;
}
static int n_coins(void *c, const uint8_t token[64], amm_coin_list_t *out, uint64_t dl) {
    (void)c; (void)token; (void)dl;
    memset(out, 0, sizeof(*out));
    out->n = 1;
    for (int i = 0; i < 64; i++) out->c[0].nul[i] = (uint8_t)(7 + i);
    out->c[0].amount = 1000000000000000ULL;      /* 10^15 raw                */
    out->tip = W.nodus_tip;
    return AMM_NODE_OK;
}
static int n_hist(void *c, unsigned limit, const nodus_dnac_addr_history_cursor_t *before,
                  nodus_dnac_addr_history_result_t *out, uint64_t dl) {
    (void)c; (void)limit; (void)before; (void)out; (void)dl;
    return AMM_NODE_ERR;                          /* the watcher reads fail on purpose */
}
static void n_hist_free(void *c, nodus_dnac_addr_history_result_t *r) { (void)c; (void)r; }
static int n_scan(void *c, uint64_t h, const uint8_t i[64], uint32_t *from, int *found, uint64_t dl) {
    (void)c; (void)h; (void)i; (void)from; (void)dl; *found = 0; return AMM_NODE_OK;
}
static int n_item(void *c, uint64_t h, const uint8_t w[64], uint8_t out[64], uint32_t *from,
                  int *found, uint64_t dl) {
    (void)c; (void)h; (void)w; (void)out; (void)from; (void)found; (void)dl;
    return AMM_NODE_ERR;
}
static int n_submit(void *c, const uint8_t w[64], const uint8_t *env, size_t len, char *msg,
                    size_t cap, uint64_t dl) {
    (void)c; (void)w; (void)env; (void)len; (void)dl;
    W.submits++;
    if (cap) snprintf(msg, cap, "stub");
    return 0;
}

/* the Ethereum providers (two identical, quorum 2) */
static int e_chain(void *c, uint64_t *o, uint64_t dl) { (void)c; (void)dl; *o = W.eth_chain; return AMM_ETH_OK; }
static int e_bn(void *c, uint64_t *o, uint64_t dl) { (void)c; (void)dl; *o = W.eth_tip; return AMM_ETH_OK; }
static int e_block(void *c, uint64_t n, amm_eth_block_t *o, uint64_t dl) {
    (void)c; (void)n; (void)o; (void)dl; return AMM_ETH_ERR;
}
static int e_logs(void *c, uint64_t b, const uint8_t k[20], const uint8_t t0[32], const uint8_t to[20],
                  amm_eth_log_t *o, int cap, int *n, uint64_t dl) {
    (void)c; (void)b; (void)k; (void)t0; (void)to; (void)o; (void)cap; (void)n; (void)dl;
    return AMM_ETH_ERR;
}
static int e_tx(void *c, const uint8_t h[32], amm_eth_tx_t *o, uint64_t dl) {
    (void)c; (void)h; (void)o; (void)dl; return AMM_ETH_ERR;
}
static int e_rcpt(void *c, const uint8_t h[32], amm_eth_receipt_t *o, uint64_t dl) {
    (void)c; (void)h; (void)o; (void)dl; return AMM_ETH_ERR;
}
static int e_bal(void *c, const uint8_t a[20], uint8_t out[32], uint64_t dl) {
    (void)c; (void)a; (void)dl;
    memset(out, 0, 32);
    out[24] = 0x0d; out[25] = 0xe0; out[26] = 0xb6; out[27] = 0xb3; out[28] = 0xa7; out[29] = 0x64;
    out[30] = 0x00; out[31] = 0x00;                         /* 10^18 wei       */
    return AMM_ETH_OK;
}
static int e_erc20(void *c, const uint8_t t[20], const uint8_t o[20], uint8_t out[32], uint64_t dl) {
    (void)c; (void)t; (void)o; (void)dl;
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(W.usdt_balance >> (8 * i));
    return AMM_ETH_OK;
}
static int e_count(void *c, const uint8_t a[20], int pending, uint64_t *o, uint64_t dl) {
    (void)c; (void)a; (void)pending; (void)dl; *o = 0; return AMM_ETH_OK;
}
static int e_est(void *c, const uint8_t f[20], const uint8_t t[20], const uint8_t *in, size_t n,
                 uint64_t *o, uint64_t dl) {
    (void)c; (void)f; (void)t; (void)in; (void)n; (void)dl; *o = 60000; return AMM_ETH_OK;
}
static int e_gasp(void *c, uint64_t *o, uint64_t dl) { (void)c; (void)dl; *o = 20000000000ULL; return AMM_ETH_OK; }
static int e_prio(void *c, uint64_t *o, uint64_t dl) { (void)c; (void)dl; *o = 1000000000ULL; return AMM_ETH_OK; }
static int e_send(void *c, const uint8_t *raw, size_t n, uint8_t h[32], uint64_t dl) {
    (void)c; (void)raw; (void)n; (void)h; (void)dl; return AMM_ETH_ERR;
}

static int price_fee(void *c, uint64_t gas, uint64_t maxfee, uint64_t *o, uint64_t dl) {
    (void)c; (void)gas; (void)maxfee; (void)dl;
    if (W.price_rc) return AMM_ETH_ERR;
    *o = W.price_fee;
    return AMM_ETH_OK;
}

/* ── the environment ──────────────────────────────────────────────────── */

typedef struct {
    char              dir[64], jpath[96];
    amm_journal_t    *j;
    amm_cfg_t         cfg;
    amm_node_t        node;
    amm_eth_provider_t prov[2];
    amm_eth_watch_t  *ew;
    amm_eth_pay_t    *ep;
    amm_nodus_watch_t *nw;
    amm_nodus_pay_t  *np;
    amm_engine_t     *eng;
    uint8_t           sk[32];
    uint8_t           foundation[20];
    amm_nodus_pay_cfg_t npc;
} env_t;

static nodus_identity_t *g_id;

static void ensure_id(void) {
    if (g_id) return;
    g_id = calloc(1, sizeof(*g_id));
    if (!g_id || nodus_identity_generate(g_id) != 0) { printf("FATAL: identity\n"); exit(2); }
}

static void build(env_t *e) {
    e->node.ctx = NULL;
    e->node.chain_id32 = n_chain; e->node.ruleset_info = n_ri; e->node.gas_price = n_gas;
    e->node.block_time = n_btime; e->node.balance = n_balance; e->node.coins = n_coins;
    e->node.addr_history = n_hist; e->node.addr_history_free = n_hist_free;
    e->node.scan_block = n_scan; e->node.item_intent = n_item; e->node.submit = n_submit;
    for (int i = 0; i < 2; i++) {
        amm_eth_provider_t p;
        memset(&p, 0, sizeof(p));
        p.name = "stub";
        p.chain_id = e_chain; p.block_number = e_bn; p.get_block = e_block; p.get_logs = e_logs;
        p.get_tx = e_tx; p.get_receipt = e_rcpt; p.get_balance = e_bal; p.erc20_balance = e_erc20;
        p.tx_count = e_count; p.estimate_gas = e_est; p.gas_price = e_gasp;
        p.max_priority_fee = e_prio; p.send_raw = e_send;
        e->prov[i] = p;
    }
    amm_eth_price_t price = { NULL, price_fee };

    amm_eth_pay_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    pc.providers = e->prov; pc.n_providers = 2; pc.quorum = 2; pc.price = price;
    pc.journal = e->j; pc.chain_id = e->cfg.eth_chain_id; pc.sk = e->sk;
    memcpy(pc.usdt, e->cfg.usdt_contract, 20);
    pc.final_depth = 3;
    e->ep = amm_eth_pay_new(&pc);
    if (!e->ep) { printf("FATAL: eth payer\n"); exit(2); }
    amm_eth_pay_self(e->ep, e->foundation);
    memcpy(e->cfg.foundation_eth, e->foundation, 20);

    amm_eth_watch_cfg_t wc;
    memset(&wc, 0, sizeof(wc));
    wc.providers = e->prov; wc.n_providers = 2; wc.quorum = 2;
    wc.chain_id = e->cfg.eth_chain_id;
    memcpy(wc.usdt, e->cfg.usdt_contract, 20); memcpy(wc.foundation, e->foundation, 20);
    wc.conf_bound_usdt[0] = e->cfg.eth_conf_bound_1_usdt; wc.conf_bound_usdt[1] = e->cfg.eth_conf_bound_2_usdt;
    wc.conf_count[0] = 3; wc.conf_count[1] = 5; wc.conf_count[2] = 33;
    wc.window_blocks = e->cfg.eth_reorg_window_blocks; wc.start_height = 900; wc.max_scan_blocks = 10;
    wc.journal = e->j;
    e->ew = amm_eth_watch_new(&wc);
    if (!e->ew) { printf("FATAL: eth watcher\n"); exit(2); }

    amm_nodus_watch_cfg_t nc;
    memset(&nc, 0, sizeof(nc));
    nc.node = &e->node; nc.journal = e->j; nc.id_kind = AMM_NW_ID_WIRE; nc.start_height = 1;
    nc.liquidity_wait_blocks = 3; nc.page_limit = 50; nc.max_pages = 4;
    e->nw = amm_nodus_watch_new(&nc);
    if (!e->nw) { printf("FATAL: nodus watcher\n"); exit(2); }

    memset(&e->npc, 0, sizeof(e->npc));
    e->npc.node = &e->node; e->npc.journal = e->j; e->npc.pk = g_id->pk.bytes; e->npc.sk = g_id->sk.bytes;
    e->npc.rand = nrand; memcpy(e->npc.chain_id, W.chain, 32);
    e->npc.expiry_ahead = 90; e->npc.resubmit_blocks = 3; e->npc.scan_blocks = 64;
    e->np = amm_nodus_pay_new(&e->npc);
    if (!e->np) { printf("FATAL: nodus payer\n"); exit(2); }
    memcpy(e->cfg.foundation_nodus, amm_nodus_pay_self(e->np), 129);

    amm_engine_cfg_t ec;
    memset(&ec, 0, sizeof(ec));
    ec.cfg = &e->cfg; ec.journal = e->j; ec.eth_watch = e->ew; ec.eth_pay = e->ep;
    ec.nodus_watch = e->nw; ec.nodus_pay = e->np; ec.node = e->node;
    ec.providers = e->prov; ec.n_providers = 2; ec.quorum = 2; ec.price = price;
    ec.now_unix = clock_fn; ec.rand_fn = rand_fn;
    e->eng = amm_engine_new(&ec);
    if (!e->eng) { printf("FATAL: engine\n"); exit(2); }
}

static void teardown(env_t *e) {
    amm_engine_free(e->eng);
    amm_nodus_pay_free(e->np);
    amm_nodus_watch_free(e->nw);
    amm_eth_pay_free(e->ep);
    amm_eth_watch_free(e->ew);
}

static void pool_set(env_t *e, uint64_t n, uint64_t u) {
    amm_pool_t p;
    evm_u256_from_u64(&p.depth_n, n); evm_u256_from_u64(&p.depth_u, u); evm_u256_from_u64(&p.units, 1);
    amm_journal_pool_put(e->j, &p);
}

static void env_open(env_t *e) {
    ensure_id();
    memset(e, 0, sizeof(*e));
    memset(&W, 0, sizeof(W));
    W.now = 10000; W.eth_tip = 1000; W.nodus_tip = 1000;
    W.nodus_balance = 1000000000000000ULL; W.usdt_balance = 1000000000000ULL;
    W.price_fee = 500000; W.rng = 0x9E3779B97F4A7C15ULL; W.eth_chain = 1;
    for (int i = 0; i < 32; i++) W.chain[i] = (uint8_t)(0xC0 + i);
    memset(e->sk, 1, 32);
    snprintf(e->dir, sizeof(e->dir), "/tmp/amm_eng_test_XXXXXX");
    if (!mkdtemp(e->dir)) { printf("FATAL: mkdtemp\n"); exit(2); }
    snprintf(e->jpath, sizeof(e->jpath), "%s/journal.db", e->dir);
    amm_cfg_defaults(&e->cfg);
    e->cfg.eth_reorg_window_blocks = 96;
    e->cfg.held_keeps_room = 0;
    if (amm_journal_open(e->jpath, &e->j) != 0) { printf("FATAL: journal\n"); exit(2); }
    pool_set(e, 3000000000000000ULL, 3000000000ULL);
    amm_journal_cursor_reset(e->j, "eth_tip", 1000);
    build(e);
}

/* Rebuild everything over the same journal file (a restart). */
static void env_restart(env_t *e) {
    teardown(e);
    amm_journal_close(e->j);
    if (amm_journal_open(e->jpath, &e->j) != 0) { printf("FATAL: reopen\n"); exit(2); }
    build(e);
}

static void env_close(env_t *e) {
    teardown(e);
    amm_journal_close(e->j);
    char p[160];
    snprintf(p, sizeof(p), "%s/journal.db", e->dir); unlink(p);
    snprintf(p, sizeof(p), "%s/journal.db-wal", e->dir); unlink(p);
    snprintf(p, sizeof(p), "%s/journal.db-shm", e->dir); unlink(p);
    rmdir(e->dir);
}

/* ── helpers ──────────────────────────────────────────────────────────── */

static int swap_of(env_t *e, uint32_t req, amm_swap_t *s) {
    return amm_journal_swap_by_botreq(e->j, req, s) == 0;
}
static int state_of(env_t *e, uint32_t req, const char *st) {
    amm_swap_t s;
    return swap_of(e, req, &s) && !strcmp(s.state, st);
}

static amm_req_usdt_t usdt_req(const amm_quote_answer_t *a, char sender_c, uint64_t minimum) {
    amm_req_usdt_t r;
    memset(&r, 0, sizeof(r));
    memset(r.sender, sender_c, 40);
    memset(r.destination, 'e', 128);
    r.amount = a->amount; r.minimum = minimum; r.request_number = a->request_number;
    for (int i = 0; i < 4; i++) r.req_no[31 - i] = (uint8_t)(a->request_number >> (8 * i));
    return r;
}

static amm_req_nodus_to_usdt_t nodus_req(const amm_quote_answer_t *a, char tid_c, uint64_t minimum) {
    amm_req_nodus_to_usdt_t r;
    memset(&r, 0, sizeof(r));
    memset(r.sender, 'c', 128);
    memset(r.destination, 'b', 40);
    memset(r.transfer_id, tid_c, 128);
    r.amount = a->amount; r.minimum = minimum; r.request_number = a->request_number;
    for (int i = 0; i < 4; i++) r.req_no[31 - i] = (uint8_t)(a->request_number >> (8 * i));
    return r;
}

static amm_rec_t mkrec(uint8_t t, uint64_t block, uint64_t ts, uint8_t from_c, uint64_t value,
                       const uint8_t to[20], const char *state) {
    amm_rec_t r;
    memset(&r, 0, sizeof(r));
    memset(r.tx, t, 32);
    r.block_number = block; r.block_ts = ts;
    memset(r.block_hash, t, 32);
    memset(r.from, from_c, 20);
    memcpy(r.to, to, 20);
    for (int i = 0; i < 8; i++) r.value[31 - i] = (uint8_t)(value >> (8 * i));
    snprintf(r.state, sizeof(r.state), "%s", state);
    return r;
}

static int pool_is(env_t *e, uint64_t n, uint64_t u) {
    amm_pool_t p;
    uint64_t pn = 0, pu = 0;
    return amm_journal_pool_get(e->j, &p) == 0 && amm_to_u64(&pn, &p.depth_n) == 0 &&
           amm_to_u64(&pu, &p.depth_u) == 0 && pn == n && pu == u;
}

static int step(env_t *e, amm_engine_step_t *o) {
    amm_engine_step_t local;
    return amm_engine_step(e->eng, 0, o ? o : &local);
}

#define POOL_N 3000000000000000ULL
#define POOL_U 3000000000ULL
#define OUT_UN 93652445369406ULL    /* 10^8 raw USDT -> NODUS (hand derived)   */
#define OUT_NU 93652445ULL          /* 10^14 raw NODUS -> USDT (hand derived)  */

/* ── E1 ───────────────────────────────────────────────────────────────── */

static void e1_quote(void) {
    printf("E1 the price question\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    W.rq[0] = 0x01020304; W.rq_n = 1;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK,
          "100 USDT -> NODUS answered");
    CHECK(a.number == OUT_UN && a.request_number == 0x01020304 && a.valid_until == 10300 &&
          a.amount == 100000000ULL, "the bot's number 93652445369406, request number, expiry now + 300");
    amm_np_quote_t nq;
    memset(&nq, 0, sizeof(nq));
    CHECK(amm_nodus_pay_quote(e.np, OUT_UN, 0, &nq) == AMM_NP_OK && a.est_fee == nq.fee,
          "the estimated fee is the planner's Nodus fee for that number, shown apart");
    char want[43] = "0x";
    for (int i = 0; i < 20; i++) snprintf(want + 2 + 2 * i, 3, "%02x", e.foundation[i]);
    CHECK(!strcmp(a.pay_to, want), "pay to the Foundation's Ethereum address");
    amm_swap_t s;
    uint64_t sum = 0;
    CHECK(swap_of(&e, 0x01020304, &s) && !strcmp(s.state, "approved") && !*s.sender &&
          s.quote_out == OUT_UN && s.value_usdt == 100000000ULL && s.expiry == 10300 &&
          s.approved_tip == 1000 && amm_journal_inflight_sum(e.j, 0, &sum) == 0 && sum == 100000000ULL,
          "approval row, room and number written together");

    /* NODUS -> USDT: 10^14 raw NODUS gives 93652445 raw USDT; est = the price seam's fee */
    memset(&a, 0, sizeof(a));
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK &&
          a.number == OUT_NU && a.est_fee == 500000 && !strcmp(a.pay_to, e.cfg.foundation_nodus),
          "NODUS -> USDT answered, Ethereum fee estimate 0.5 USDT, pay to the Foundation's Nodus address");
    CHECK(swap_of(&e, a.request_number, &s) && s.value_usdt == OUT_NU && s.approved_tip == 1000,
          "its value v is the USDT number");

    /* refusals */
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 999999ULL, 0, &a) == AMM_Q_BELOW_MIN,
          "below 1 USDT refused (givens item 89)");
    /* 10^12 raw NODUS: 9*10^36 / 9.006001*10^30 = 999333.7 -> 999333 raw USDT < 10^6 */
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 1000000000000ULL, 0, &a) == AMM_Q_BELOW_MIN,
          "a NODUS amount worth below 1 USDT refused on its USDT side");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000001ULL, 0, &a) == AMM_Q_ABOVE_MAX,
          "above 100 USDT refused");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 0, 0, &a) == AMM_Q_BAD &&
          amm_engine_quote(e.eng, (amm_dir_t)5, 5, 0, &a) == AMM_Q_BAD, "bad direction or amount");
    int cnt = 0;
    amm_journal_state_count(e.j, "approved", &cnt);
    CHECK(cnt == 2, "a refusal wrote nothing");

    /* the draw: a taken number and a zero are redrawn */
    W.rq[0] = 0x01020304; W.rq[1] = 0; W.rq[2] = 0x05060708; W.rq_n = 3; W.rq_i = 0;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 2000000ULL, 0, &a) == AMM_Q_OK &&
          a.request_number == 0x05060708, "a taken number and a zero redrawn");

    /* unreadable facts are never an approval */
    W.price_rc = 1;
    amm_journal_state_count(e.j, "approved", &cnt);
    int before = cnt;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_UNAVAILABLE,
          "the fee estimate unreadable: unavailable");
    W.price_rc = 0;
    W.nodus_balance_rc = AMM_NODE_ERR;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 2000000ULL, 0, &a) == AMM_Q_UNAVAILABLE,
          "the bot's balance unreadable: unavailable");
    W.nodus_balance_rc = 0;
    amm_journal_state_count(e.j, "approved", &cnt);
    CHECK(cnt == before, "  nothing was written");

    /* the payout must be within what the key holds, less what it owes */
    W.nodus_balance = OUT_UN + OUT_UN / 2;          /* the first quote (1e8) already owes OUT_UN */
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_CANNOT_PAY,
          "the bot's NODUS (1.5 x number) cannot cover a second number on top of the owed one");
    W.nodus_balance = 1000000000000000ULL;

    /* paused */
    env_t p;
    env_open(&p);
    p.cfg.swaps_paused = 1;
    env_restart(&p);
    CHECK(amm_engine_quote(p.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &a) == AMM_Q_PAUSED, "swaps paused");
    env_close(&p);

    /* stopped: a swap in unknown */
    env_t u;
    env_open(&u);
    {
        amm_approve_t ap;
        memset(&ap, 0, sizeof(ap));
        char snd[41], dst[129];
        memset(snd, 'd', 40); snd[40] = 0; memset(dst, 'e', 128); dst[128] = 0;
        ap.dir = AMM_USDT_TO_NODUS; ap.sender = snd; ap.dest = dst; ap.amount = 5; ap.minimum = 1;
        ap.value_usdt = 5; ap.approved_at = 1; ap.expiry = 2; ap.approved_tip = 1; ap.incoming_id = "";
        ap.req_no[31] = 9; ap.swap_max = 100000000ULL; ap.inflight_max = 500000000ULL;
        amm_swap_t s2;
        int ok = amm_journal_approve(u.j, &ap, &s2) == AMM_J_OK &&
                 amm_journal_swap_transition(u.j, s2.seq, "paid_waiting_depth", "nodus:zz", NULL, NULL) == 0 &&
                 amm_journal_swap_transition(u.j, s2.seq, "counted", NULL, NULL, NULL) == 0 &&
                 amm_journal_swap_transition(u.j, s2.seq, "payout_pending", NULL, NULL, NULL) == 0 &&
                 amm_journal_swap_transition(u.j, s2.seq, "unknown", NULL, NULL, NULL) == 0;
        CHECK(ok && amm_engine_quote(u.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &a) == AMM_Q_STOPPED,
              "a swap in unknown stops new approvals");
    }
    env_close(&u);

    /* in-flight total */
    env_t f;
    env_open(&f);
    f.cfg.inflight_max_usdt = 150000000ULL;
    env_restart(&f);
    CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK &&
          amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_INFLIGHT,
          "the second 100 USDT passes the 150 USDT in-flight total");
    env_close(&f);
    env_close(&e);
}

/* ── E2 ───────────────────────────────────────────────────────────────── */

static void e2_accept(void) {
    printf("E2 the signed request\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a, b, c;
    amm_swap_t s;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 50000000ULL, 0, &a) == AMM_Q_OK &&
          amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 50000000ULL, 0, &b) == AMM_Q_OK, "two approvals, same amount");

    amm_req_usdt_t r = usdt_req(&a, 'a', 5);
    r.request_number = 77777;
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_NO_NUMBER, "an unknown number");
    r.request_number = 0x1FFFFFFFFULL;
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_NO_NUMBER, "a number above 32 bits");
    r = usdt_req(&a, 'a', 5);
    r.amount += 1;
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_AMOUNT, "an amount other than the answer's (item 87)");
    r = usdt_req(&a, 'a', 5);
    CHECK(amm_engine_accept_usdt(e.eng, &r, &s) == AMM_ACC_RECEIVED && !strcmp(s.sender, r.sender) &&
          s.minimum == 5, "received: the bot has the request");
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_USED, "a number is accepted once");
    r = usdt_req(&b, 'a', 5);
    CHECK(amm_engine_accept_usdt(e.eng, &r, &s) == AMM_ACC_OPEN && s.req_no_bot == a.request_number,
          "item 57: same sender and amount, the open swap named");
    r = usdt_req(&b, 'b', 5);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "another sender accepted");

    /* NODUS -> USDT */
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &c) == AMM_Q_OK, "NODUS approval");
    amm_req_nodus_to_usdt_t nr = nodus_req(&c, 'f', 1);
    char inc[AMM_TID_MAX];
    snprintf(inc, sizeof(inc), "nodus:%s", nr.transfer_id);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, &s) == AMM_ACC_RECEIVED && !strcmp(s.incoming_id, inc),
          "NODUS request accepted, incoming id nodus:<transfer id>");
    amm_req_usdt_t wrong_kind = usdt_req(&c, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &wrong_kind, NULL) == AMM_ACC_USED, "a second request under the same number");

    /* an expired approval is not accepted */
    amm_quote_answer_t d;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 3000000ULL, 0, &d) == AMM_Q_OK, "approval to expire");
    W.now = 10301;
    r = usdt_req(&d, 'c', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_EXPIRED, "past its expiry: refused, nothing written");
    W.now = 10300;
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "at the expiry second still valid");
    env_close(&e);
}

/* ── E3 / E4 / E5: counting, ledger, payouts, refunds ────────────────── */

static void e3_count_and_payout(void) {
    printf("E3 matching, counting, the approval's number, the NODUS payout\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_swap_t s;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");
    pool_set(&e, 2000000000000000ULL, POOL_U);     /* the depths change after the question */

    amm_rec_t rec = mkrec(0x11, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK, "a seen record of the sender and amount");
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.matched == 1 && state_of(&e, a.request_number, "paid_waiting_depth"),
          "the record moves the approval to paid_waiting_depth");
    snprintf(rec.state, sizeof(rec.state), "deep");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK, "the record reaches its depth");
    CHECK(step(&e, &o) == 0 && o.counted >= 1 && state_of(&e, a.request_number, "payout_pending"),
          "counted and moved to payout_pending in the same step");
    /* 2*10^15 - 93652445369406 = 1906347554630594; depth_u + 10^8 */
    CHECK(pool_is(&e, 1906347554630594ULL, 3100000000ULL),
          "the ledger took the APPROVAL'S number, not a quote of the changed depths");
    CHECK(swap_of(&e, a.request_number, &s) && s.ledger_applied == 1, "the update is marked");
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_attempt_latest(e.j, s.seq, &at) == 0 && at.gross == OUT_UN &&
          at.net + at.fee == at.gross && at.net > 0,
          "the NODUS payout is signed: gross = the number, the real Nodus fee deducted");
    amm_attempt_free(&at);
    CHECK(W.submits >= 1, "and submitted");

    /* a restart repeats nothing */
    env_restart(&e);
    CHECK(step(&e, &o) == 0 && state_of(&e, a.request_number, "payout_pending") &&
          pool_is(&e, 1906347554630594ULL, 3100000000ULL), "after a restart: nothing repeated");
    env_close(&e);
}

static void e4_held_and_refunds(void) {
    printf("E4 held records, a number that cannot be applied, paused\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");

    amm_rec_t other = mkrec(0x21, 1001, 10100, 0xbb, 100000000ULL, e.foundation, "seen");
    amm_rec_t amt = mkrec(0x22, 1001, 10100, 0xaa, 99999999ULL, e.foundation, "seen");
    amm_journal_rec_put(e.j, &other);
    amm_journal_rec_put(e.j, &amt);
    snprintf(other.state, sizeof(other.state), "deep");
    snprintf(amt.state, sizeof(amt.state), "deep");
    amm_journal_rec_put(e.j, &other);
    amm_journal_rec_put(e.j, &amt);
    CHECK(step(&e, &o) == 0 && o.held_records == 2 && state_of(&e, a.request_number, "approved"),
          "another sender and another amount are held; the approval stays open");
    amm_rec_t g;
    CHECK(amm_journal_rec_get(e.j, other.tx, 0, &g) == 0 && !strcmp(g.state, "held"), "the record state is held");

    /* a number that cannot be applied: the NODUS depth is below it */
    amm_rec_t ok = mkrec(0x23, 1002, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    amm_journal_rec_put(e.j, &ok);
    snprintf(ok.state, sizeof(ok.state), "deep");
    amm_journal_rec_put(e.j, &ok);
    pool_set(&e, 1000, POOL_U);
    CHECK(step(&e, &o) == 0 && state_of(&e, a.request_number, "refund_pending") && pool_is(&e, 1000, POOL_U),
          "the number cannot be applied: refund, the ledger untouched");
    env_close(&e);

    /* paused: a payment for an approved swap is refunded */
    env_t p;
    env_open(&p);
    amm_quote_answer_t b;
    CHECK(amm_engine_quote(p.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &b) == AMM_Q_OK, "approval before the pause");
    r = usdt_req(&b, 'a', 1);
    CHECK(amm_engine_accept_usdt(p.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");
    p.cfg.swaps_paused = 1;
    env_restart(&p);
    amm_rec_t pr = mkrec(0x31, 1001, 10100, 0xaa, 100000000ULL, p.foundation, "seen");
    amm_journal_rec_put(p.j, &pr);
    snprintf(pr.state, sizeof(pr.state), "deep");
    amm_journal_rec_put(p.j, &pr);
    CHECK(step(&p, &o) == 0 && state_of(&p, b.request_number, "refund_pending") &&
          pool_is(&p, POOL_N, POOL_U), "during swaps_paused the payment is refunded, the ledger untouched");
    env_close(&p);
}

static void e5_below_minimum(void) {
    printf("E5 a payout below the minimum after the fee: a refund, the ledger reversed\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', OUT_UN + 1);          /* no fee can leave this satisfied */
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request with a high minimum");
    amm_rec_t rec = mkrec(0x41, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    amm_journal_rec_put(e.j, &rec);
    snprintf(rec.state, sizeof(rec.state), "deep");
    amm_journal_rec_put(e.j, &rec);
    CHECK(step(&e, &o) == 0 && state_of(&e, a.request_number, "refund_pending"),
          "net below the minimum: refund_pending");
    CHECK(pool_is(&e, POOL_N, POOL_U), "its ledger update is reversed: the reserves are the initial ones");
    amm_swap_t s;
    CHECK(swap_of(&e, a.request_number, &s) && s.ledger_applied == 0, "the mark is cleared");
    amm_eattempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_eth_attempt_latest(e.j, s.seq, &at) == 0 && at.gross == 100000000ULL &&
          at.fee == 500000 && at.net == 100000000ULL - 500000,
          "the USDT refund is signed with the REAL Ethereum fee deducted (0.5 USDT)");
    amm_eattempt_free(&at);
    env_close(&e);
}

/* ── E6 drops ─────────────────────────────────────────────────────────── */

static void e6_drops(void) {
    printf("E6 drops (givens items 89, 90)\n");
    /* a NODUS refund that is zero after the Nodus fee */
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "NODUS approval");
    amm_req_nodus_to_usdt_t nr = nodus_req(&a, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED, "signed request");
    amm_swap_t s;
    CHECK(swap_of(&e, a.request_number, &s), "row");
    /* the payment of ONE raw NODUS (below any fee) is refunded: the row's amount is
     * what the refund owes; the swap is walked to refund_pending as a counted payment */
    /* the seen payment is named by the transfer id the signed request stored
     * (amm_journal_swap_transition refuses paid_waiting_depth without it) */
    CHECK(amm_journal_swap_transition(e.j, s.seq, "paid_waiting_depth", s.incoming_id, NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "counted", NULL, NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "refund_pending", NULL, NULL, NULL) == 0,
          "a NODUS -> USDT swap in refund_pending");
    /* the refund owes s.amount = 10^14 raw NODUS: far above the fee, so it is SENT; prove
     * the contrary case on a row whose amount is 1 */
    amm_quote_answer_t tiny;
    memset(&tiny, 0, sizeof(tiny));
    {
        amm_quote_t q;
        memset(&q, 0, sizeof(q));
        q.dir = AMM_NODUS_TO_USDT; q.amount = 1; q.quote_out = 0; q.value_usdt = 1000000;
        q.approved_at = 10000; q.expiry = 10300; q.approved_tip = 1000; q.bot_req = 4242;
        for (int i = 0; i < 16; i++) q.rand16[i] = (uint8_t)(i + 90);
        q.swap_max = 100000000ULL; q.inflight_max = 500000000ULL;
        amm_swap_t ts;
        CHECK(amm_journal_quote_approve(e.j, &q, &ts) == AMM_J_OK, "an approval of 1 raw NODUS (seeded)");
        tiny.request_number = 4242; tiny.amount = 1;
        amm_req_nodus_to_usdt_t tr = nodus_req(&tiny, '9', 1);
        CHECK(amm_engine_accept_nodus(e.eng, &tr, NULL) == AMM_ACC_RECEIVED, "its signed request");
        CHECK(swap_of(&e, 4242, &ts) &&
              amm_journal_swap_transition(e.j, ts.seq, "paid_waiting_depth", ts.incoming_id, NULL, NULL) == 0 &&
              amm_journal_swap_transition(e.j, ts.seq, "counted", NULL, NULL, NULL) == 0 &&
              amm_journal_swap_transition(e.j, ts.seq, "refund_pending", NULL, NULL, NULL) == 0,
              "walked to refund_pending");
    }
    /* the first refund (10^14 NODUS) is the head and is signed; settle it so the tiny one is next */
    CHECK(step(&e, &o) == 0, "step 1");
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_attempt_latest(e.j, s.seq, &at) == 0 && at.gross == 100000000000000ULL,
          "the refund of 10^14 raw NODUS is signed (the head)");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_finish(e.j, s.seq, "confirmed") == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "refunded", NULL, NULL, NULL) == 0, "head settled");
    CHECK(step(&e, &o) == 0 && o.dropped == 1 && state_of(&e, 4242, "dropped"),
          "a NODUS refund that is zero after the Nodus fee is DROPPED");
    amm_swap_t ts2;
    CHECK(swap_of(&e, 4242, &ts2) && amm_journal_attempt_latest(e.j, ts2.seq, &at) == 1,
          "no envelope was signed for it, nothing is held");
    uint64_t sum = 1;
    CHECK(amm_journal_inflight_sum(e.j, 0, &sum) == 0 && sum == 0,
          "a dropped swap holds no room (the other swap was refunded)");
    env_close(&e);

    /* a USDT refund whose Ethereum fee is not below its amount */
    env_t u;
    env_open(&u);
    amm_quote_answer_t b;
    CHECK(amm_engine_quote(u.eng, AMM_USDT_TO_NODUS, 1000000ULL, 0, &b) == AMM_Q_OK, "1 USDT approval");
    amm_req_usdt_t r = usdt_req(&b, 'a', 1);
    CHECK(amm_engine_accept_usdt(u.eng, &r, &s) == AMM_ACC_RECEIVED, "signed request");
    CHECK(amm_journal_swap_transition(u.j, s.seq, "paid_waiting_depth", "eth:aa", NULL, NULL) == 0 &&
          amm_journal_swap_transition(u.j, s.seq, "counted", NULL, NULL, NULL) == 0 &&
          amm_journal_swap_transition(u.j, s.seq, "refund_pending", NULL, NULL, NULL) == 0,
          "a USDT refund pending");
    W.price_fee = 1000000;                                      /* fee 1 USDT = the whole amount */
    CHECK(step(&u, &o) == 0 && o.dropped == 1 && state_of(&u, b.request_number, "dropped"),
          "a USDT refund whose fee is not below its amount is DROPPED");
    amm_eattempt_t ea;
    CHECK(amm_journal_eth_attempt_latest(u.j, s.seq, &ea) == 1, "nothing signed, nothing broadcast");
    env_close(&u);
}

/* ── E7 release ───────────────────────────────────────────────────────── */

static void e7_release(void) {
    printf("E7 release of room\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a, b, c, d;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &a) == AMM_Q_OK &&
          amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK &&
          amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 20000000ULL, 0, &c) == AMM_Q_OK &&
          amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &d) == AMM_Q_OK,
          "four approvals: unsigned USDT -> NODUS, signed NODUS -> USDT, signed USDT -> NODUS, unsigned NODUS -> USDT");
    amm_req_nodus_to_usdt_t nr = nodus_req(&b, 'f', 1);
    amm_req_usdt_t ur = usdt_req(&c, 'a', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED &&
          amm_engine_accept_usdt(e.eng, &ur, NULL) == AMM_ACC_RECEIVED, "two of them signed");
    CHECK(step(&e, &o) == 0 && o.expired == 0, "before the expiry nothing is released");
    W.now = 10301;
    CHECK(step(&e, &o) == 0 && o.expired == 0 && state_of(&e, a.request_number, "approved") &&
          state_of(&e, b.request_number, "approved") && state_of(&e, c.request_number, "approved") &&
          state_of(&e, d.request_number, "approved"),
          "the bot's clock past the expiry releases NOTHING, not even an approval with no signed request");
    /* the Nodus history processed through a block time after the expiry: the
     * signed AND the unsigned NODUS -> USDT approval, by the same window rule */
    amm_journal_cursor_reset(e.j, "nodus_scan", 1000);
    amm_journal_cursor_reset(e.j, "nodus_scan_ts", 10400);
    CHECK(step(&e, &o) == 0 && o.expired == 2 && state_of(&e, b.request_number, "expired") &&
          state_of(&e, d.request_number, "expired") && state_of(&e, a.request_number, "approved") &&
          state_of(&e, c.request_number, "approved"),
          "the NODUS -> USDT approvals, signed and unsigned, expire once the history passed a block time after the expiry");
    /* the Ethereum window: a stored block after the expiry, deep enough, the cursor past it */
    amm_blk_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.height = 990; blk.ts = 10400; memset(blk.hash, 5, 32); memset(blk.parent, 4, 32);
    amm_journal_block_put(e.j, &blk);
    amm_journal_cursor_reset(e.j, "eth_scan", 995);
    CHECK(step(&e, &o) == 0 && o.expired == 2 && state_of(&e, c.request_number, "expired") &&
          state_of(&e, a.request_number, "expired"),
          "the USDT -> NODUS approvals, signed and unsigned, expire once the Ethereum window is fully observed");
    uint64_t sum = 1;
    CHECK(amm_journal_inflight_sum(e.j, 0, &sum) == 0 && sum == 0, "all room released");
    env_close(&e);
}

/* ── E8 the fee booking ───────────────────────────────────────────────── */

static void e8_fee_booking(void) {
    printf("E8 the network fee of a USDT payout is booked to the Foundation\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_nodus_to_usdt_t nr = nodus_req(&a, 'f', 1);
    amm_swap_t s;
    CHECK(amm_engine_accept_nodus(e.eng, &nr, &s) == AMM_ACC_RECEIVED, "signed request");
    CHECK(swap_of(&e, a.request_number, &s) &&
          amm_journal_swap_transition(e.j, s.seq, "paid_waiting_depth", s.incoming_id, NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "counted", NULL, NULL, NULL) == 0, "payment counted (as the watcher does)");
    CHECK(step(&e, &o) == 0 && state_of(&e, a.request_number, "payout_pending"), "payout_pending");
    /* 3*10^15 + 10^14 NODUS; 3*10^9 - 93652445 USDT */
    CHECK(pool_is(&e, 3100000000000000ULL, 2906347555ULL), "the approval's number left the USDT depth");
    amm_eattempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_eth_attempt_latest(e.j, s.seq, &at) == 0 && at.gross == OUT_NU &&
          at.fee == 500000 && at.net == OUT_NU - 500000,
          "the USDT payout is signed with the real fee deducted: 93652445 - 500000");
    amm_eattempt_free(&at);
    /* the payer settles by receipts (its own test); here the payout is confirmed */
    CHECK(amm_journal_eth_attempt_finish(e.j, s.seq, "confirmed") == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "paid", NULL, NULL, NULL) == 0, "payout confirmed");
    CHECK(step(&e, &o) == 0 && o.fees_booked == 1, "the fee is booked");
    uint64_t fee = 0;
    CHECK(pool_is(&e, 3100000000000000ULL, 2906347555ULL),
          "the pool is untouched by the fee: its USDT depth fell by the FULL gross payout, "
          "no USDT came back, no NODUS left (givens item 92)");
    CHECK(amm_journal_fee_booked(e.j, s.seq, &fee) == 0 && fee == 500000,
          "the fee is booked to the Foundation as USDT");
    uint64_t total = 0;
    CHECK(amm_journal_foundation_usdt(e.j, &total) == 0 && total == 500000, "the Foundation's USDT");
    env_restart(&e);
    CHECK(step(&e, &o) == 0 && o.fees_booked == 0 && pool_is(&e, 3100000000000000ULL, 2906347555ULL) &&
          amm_journal_foundation_usdt(e.j, &total) == 0 && total == 500000,
          "booked once, also after a restart");
    env_close(&e);

    /* No lifetime row cap: 1,100 older paid USDT payouts with no confirmed
     * attempt (nothing to book) sit before this payout. The engine once read
     * every paid row in one list of at most 1,024 and stopped booking for
     * good past that. The rows are seeded through a second connection (the
     * journal API would take 1,100 transactions of six steps). */
    env_t m;
    env_open(&m);
    {
        sqlite3 *db = NULL;
        CHECK(sqlite3_open(m.jpath, &db) == SQLITE_OK, "a second connection for the seed");
        sqlite3_busy_timeout(db, 5000);
        const char *sql =
            "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<1100) "
            "INSERT INTO swaps(id, dir, state, sender, dest, amount, minimum, value_usdt, "
            "approved_at, expiry, incoming_id, approved_tip, req_no_bot) "
            "SELECT printf('%032x', i + 1000000), 1, 'paid', "
            "'0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000', "
            "'0000000000000000000000000000000000000000', 1, 1, 1, 1, 2, "
            "printf('nodus:old%d', i), 1, i + 2000000 FROM c";
        CHECK(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK, "1,100 old paid rows seeded");
        sqlite3_close(db);
    }
    int old_paid = 0;
    CHECK(amm_journal_state_count(m.j, "paid", &old_paid) == 0 && old_paid == 1100, "1,100 paid rows");
    amm_quote_answer_t a2;
    CHECK(amm_engine_quote(m.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a2) == AMM_Q_OK, "approval");
    amm_req_nodus_to_usdt_t nr2 = nodus_req(&a2, 'f', 1);
    amm_swap_t s2;
    CHECK(amm_engine_accept_nodus(m.eng, &nr2, &s2) == AMM_ACC_RECEIVED &&
          swap_of(&m, a2.request_number, &s2) &&
          amm_journal_swap_transition(m.j, s2.seq, "paid_waiting_depth", s2.incoming_id, NULL, NULL) == 0 &&
          amm_journal_swap_transition(m.j, s2.seq, "counted", NULL, NULL, NULL) == 0, "payment counted");
    CHECK(step(&m, &o) == 0 && state_of(&m, a2.request_number, "payout_pending"), "payout_pending");
    CHECK(amm_journal_eth_attempt_finish(m.j, s2.seq, "confirmed") == 0 &&
          amm_journal_swap_transition(m.j, s2.seq, "paid", NULL, NULL, NULL) == 0, "payout confirmed");
    CHECK(step(&m, &o) == 0 && o.fees_booked == 1 &&
          amm_journal_fee_booked(m.j, s2.seq, &fee) == 0 && fee == 500000,
          "the fee is booked although 1,100 older paid rows come first (paged read, no row cap)");
    env_close(&m);
}

/* ── E1b funding counts refunds ───────────────────────────────────────── */

static void e1b_funding_refunds(void) {
    printf("E1b the funding check counts every amount owed in the payout asset, refunds included\n");
    amm_quote_answer_t a, b;
    amm_swap_t s;

    /* a USDT -> NODUS swap whose USDT payment must be refunded: the bot owes
     * 100 USDT (1e8 raw). A NODUS -> USDT quote of 93652445 raw USDT needs
     * 1e8 + 93652445 = 193652445 in the bot's USDT. */
    env_t e;
    env_open(&e);
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "100 USDT -> NODUS approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, &s) == AMM_ACC_RECEIVED &&
          amm_journal_swap_transition(e.j, s.seq, "paid_waiting_depth", "eth:bb", NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "counted", NULL, NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "refund_pending", NULL, NULL, NULL) == 0,
          "its payment is to be refunded (refund_pending)");
    W.usdt_balance = 150000000ULL;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_CANNOT_PAY,
          "1.5 USDT x 10^8 held: the owed 100 USDT refund plus 93.65 USDT cannot be paid");
    W.usdt_balance = 200000000ULL;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK,
          "200 USDT held covers the refund and the new number");
    env_close(&e);

    /* the other asset: a NODUS -> USDT swap whose NODUS payment must be refunded
     * (10^14 raw NODUS owed); a USDT -> NODUS quote of 93652445369406 raw NODUS
     * needs 10^14 + 93652445369406 in the bot's NODUS */
    env_t f;
    env_open(&f);
    CHECK(amm_engine_quote(f.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "NODUS -> USDT approval");
    amm_req_nodus_to_usdt_t nr = nodus_req(&a, 'f', 1);
    CHECK(amm_engine_accept_nodus(f.eng, &nr, &s) == AMM_ACC_RECEIVED && swap_of(&f, a.request_number, &s) &&
          amm_journal_swap_transition(f.j, s.seq, "paid_waiting_depth", s.incoming_id, NULL, NULL) == 0 &&
          amm_journal_swap_transition(f.j, s.seq, "counted", NULL, NULL, NULL) == 0 &&
          amm_journal_swap_transition(f.j, s.seq, "refund_pending", NULL, NULL, NULL) == 0,
          "its NODUS payment is to be refunded");
    W.nodus_balance = 150000000000000ULL;
    CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &b) == AMM_Q_CANNOT_PAY,
          "1.5 x 10^14 NODUS held: the owed 10^14 refund plus the new number cannot be paid");
    W.nodus_balance = 250000000000000ULL;
    CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &b) == AMM_Q_OK,
          "2.5 x 10^14 NODUS held covers both");
    env_close(&f);
}

/* ── E10 counting re-checks the validity ─────────────────────────────── */

static void e10_counting_validity(void) {
    printf("E10 a linked payment is counted only while its block time is within the validity\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a, b;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK &&
          amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &b) == AMM_Q_OK, "two approvals");
    amm_req_usdt_t ra = usdt_req(&a, 'a', 1), rb = usdt_req(&b, 'b', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &ra, NULL) == AMM_ACC_RECEIVED &&
          amm_engine_accept_usdt(e.eng, &rb, NULL) == AMM_ACC_RECEIVED, "both signed (expiry 10300)");
    amm_rec_t pa = mkrec(0x51, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    amm_rec_t pb = mkrec(0x52, 1001, 10100, 0xbb, 100000000ULL, e.foundation, "seen");
    CHECK(amm_journal_rec_put(e.j, &pa) == AMM_J_OK && amm_journal_rec_put(e.j, &pb) == AMM_J_OK &&
          step(&e, &o) == 0 && o.matched == 2 && state_of(&e, a.request_number, "paid_waiting_depth") &&
          state_of(&e, b.request_number, "paid_waiting_depth"), "both payments, in time, are linked");
    /* a reorganisation moved A's payment to a block time AFTER the expiry and B's
     * to another block still inside the validity; both reach their depth */
    pa.block_number = 1005; pa.block_ts = 10400; snprintf(pa.state, sizeof(pa.state), "deep");
    pb.block_number = 1006; pb.block_ts = 10200; snprintf(pb.state, sizeof(pb.state), "deep");
    CHECK(amm_journal_rec_put(e.j, &pa) == AMM_J_OK && amm_journal_rec_put(e.j, &pb) == AMM_J_OK,
          "the moved payments reach their depth");
    CHECK(step(&e, &o) == 0 && state_of(&e, b.request_number, "payout_pending"),
          "the payment moved inside the validity is counted (control)");
    CHECK(state_of(&e, a.request_number, "approved"),
          "the payment moved outside the validity is NOT counted: its approval is unpaid again");
    amm_rec_t g;
    amm_swap_t sa, sx;
    char key[AMM_TID_MAX];
    amm_journal_eth_key(pa.tx, key, sizeof(key));
    CHECK(amm_journal_rec_get(e.j, pa.tx, 0, &g) == 0 && !strcmp(g.state, "held") && o.held_records == 1,
          "its record is held (givens item 32)");
    CHECK(swap_of(&e, a.request_number, &sa) && !*sa.incoming_id && sa.ledger_applied == 0 &&
          amm_journal_swap_by_incoming(e.j, key, &sx) == 1,
          "the approval no longer carries the payment; its ledger was not updated");
    env_close(&e);
}

/* ── E11 restart after a long downtime ───────────────────────────────── */

static void e11_downtime_beyond_window(void) {
    printf("E11 a stored payment is read after a downtime longer than the reorganisation window\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");
    /* the watcher stored the payment (block 1001, in time) and the bot went
     * down before the engine matched it */
    amm_rec_t rec = mkrec(0x61, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK, "the payment is stored, unmatched");
    env_restart(&e);
    /* the chain is now 99,000 blocks further (window 96): block 1001 is far below tip - window */
    W.eth_tip = 100000;
    amm_journal_cursor_reset(e.j, "eth_tip", 100000);
    CHECK(step(&e, &o) == 0 && o.matched == 1 && state_of(&e, a.request_number, "paid_waiting_depth"),
          "the old payment is still matched to its approval (no block window)");
    snprintf(rec.state, sizeof(rec.state), "deep");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK &&
          step(&e, &o) == 0 && state_of(&e, a.request_number, "payout_pending"),
          "and counted when deep");
    env_close(&e);
}

/* ── E13 more unconsumed records than one page ─────────────────────── */

/* Proves: the engine pages through the unconsumed Ethereum records (Sol
 * verify 10, claim 6): 1,100 stray "seen" records that match nothing come
 * BEFORE the real payment in the list order (lower blocks), more than one
 * LIST_CAP page of 1,024, and the payment behind them is still matched. Can
 * falsely pass if LIST_CAP were raised above 1,100 (then one page holds all). */
static void e13_records_beyond_one_page(void) {
    printf("E13 a payment behind more than one page of unmatched records is still matched\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");
    int ok = 1;
    for (int i = 0; i < 1100 && ok; i++) {
        /* a stray transfer from another sender, lower block than the payment */
        amm_rec_t st = mkrec(0x10, 500 + (uint64_t)(i / 10), 10050, 0xbb, 7000000ULL, e.foundation, "seen");
        st.tx[0] = 0x10; st.tx[1] = (uint8_t)(i >> 8); st.tx[2] = (uint8_t)i;
        st.log_index = (uint32_t)(i % 10);
        ok = amm_journal_rec_put(e.j, &st) == AMM_J_OK;
    }
    CHECK(ok, "1,100 stray seen records stored before the payment");
    amm_rec_t rec = mkrec(0x62, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK, "the payment is stored after them");
    CHECK(step(&e, &o) == 0 && o.matched == 1 && state_of(&e, a.request_number, "paid_waiting_depth"),
          "the payment behind 1,100 stray records is matched (paged read)");
    env_close(&e);
}

/* ── E12 the Ethereum chain id is the setting ────────────────────────── */

static void e12_chain_id_setting(void) {
    printf("E12 eth_chain_id 11155111 (givens item 77) reaches the watcher, the payer, the nonce and the signature\n");
    env_t e;
    env_open(&e);
    e.cfg.eth_chain_id = 11155111ULL;
    W.eth_chain = 11155111ULL;
    env_restart(&e);
    amm_quote_answer_t a;
    amm_engine_step_t o;
    amm_swap_t s;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_nodus_to_usdt_t nr = nodus_req(&a, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, &s) == AMM_ACC_RECEIVED && swap_of(&e, a.request_number, &s) &&
          amm_journal_swap_transition(e.j, s.seq, "paid_waiting_depth", s.incoming_id, NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, s.seq, "counted", NULL, NULL, NULL) == 0, "payment counted");
    CHECK(step(&e, &o) == 0 && state_of(&e, a.request_number, "payout_pending"), "payout_pending");
    amm_eattempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_eth_attempt_latest(e.j, s.seq, &at) == 0 && at.chain_id == 11155111ULL,
          "the USDT payout is signed and stored under chain id 11155111 (providers on Sepolia are usable)");
    amm_eattempt_free(&at);
    env_close(&e);

    /* the providers report mainnet while the setting says Sepolia: nothing is signed */
    env_t m;
    env_open(&m);
    m.cfg.eth_chain_id = 11155111ULL;
    env_restart(&m);                                   /* W.eth_chain stays 1 */
    CHECK(amm_engine_quote(m.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "approval");
    nr = nodus_req(&a, 'f', 1);
    CHECK(amm_engine_accept_nodus(m.eng, &nr, &s) == AMM_ACC_RECEIVED && swap_of(&m, a.request_number, &s) &&
          amm_journal_swap_transition(m.j, s.seq, "paid_waiting_depth", s.incoming_id, NULL, NULL) == 0 &&
          amm_journal_swap_transition(m.j, s.seq, "counted", NULL, NULL, NULL) == 0, "payment counted");
    CHECK(step(&m, &o) == 0 && state_of(&m, a.request_number, "payout_pending") &&
          amm_journal_eth_attempt_latest(m.j, s.seq, &at) == 1,
          "providers on another chain than the setting: no payout is signed");
    env_close(&m);
}

int main(void) {
    printf("test_amm_engine\n");
    e1_quote();
    e1b_funding_refunds();
    e10_counting_validity();
    e11_downtime_beyond_window();
    e13_records_beyond_one_page();
    e12_chain_id_setting();
    e2_accept();
    e3_count_and_payout();
    e4_held_and_refunds();
    e5_below_minimum();
    e6_drops();
    e7_release();
    e8_fee_booking();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
