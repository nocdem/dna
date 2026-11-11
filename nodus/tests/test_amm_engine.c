/**
 * test_amm_engine.c -- the nodus-amm engine (amm_engine.c) with the REAL
 * journal, ledger, both watchers and both payers wired to STUB chains.
 *
 * REVISION 12 (plan sections 12-14, givens items 93-97): E3-E5 now prove the
 * DECISION (the output computed again from the depths of the moment, stored with
 * the signed payout and the ledger update in one transaction; a swap below its
 * minimum refunded with the depths unchanged and the next swap priced as if it
 * never existed); E1/E1b/E10/E7 prove that a question holds no room and the
 * balance estimate counts only seen payments; E14 the room from the seen payment
 * and the strict line; E15 paging; E16 the liquidity add. Where an older entry
 * below says "ledger updated at the count" or "reversed", read the decision.
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
 *   E20 an older NODUS payout whose attempt expired and cannot be replaced
 *       (the Nodus fee changed) does not hold a younger NODUS refund: the
 *       refund is signed in the same round over a coin the expired payout does
 *       not hold; the payout's replacement follows once the fee is the decided
 *       one again and spends its own expired coin (see the comment of E20).
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
    int      rcpt_ok;                /* 1: every provider answers a status-1 receipt */
    uint64_t rcpt_block;             /* ... in this block                      */
    uint8_t  rcpt_hash;              /* ... with this block hash (32 x byte)   */
    uint64_t gas;                    /* the Nodus gas price the node reports (0 = rule off) */
    int      ncoins;                 /* 0: the one default coin; else the scripted list     */
    uint8_t  coin_seed[4];           /* coin k's nullifier bytes are coin_seed[k] + i       */
    uint64_t coin_amt[4];
    uint64_t mono;                   /* the monotonic clock the questions' shared reads use, ms */
    uint64_t mono_step;              /* added to `mono` at every read of it (default 10000: no reuse) */
    int      reads;                  /* every node and provider read of the engine's seams (E22) */
    int      prov_reads;             /* the question path's Ethereum reads: balance, gas estimate, gas price */
    int      nbal_reads;             /* the Nodus balance reads */
    int      erc20_fail;             /* 1: every provider's USDT balance read fails (E28) */
} world_t;

static world_t W;
static int g_page;                   /* amm_engine_cfg_t.page of the next build (0 = default) */

static uint64_t clock_fn(void *c) { (void)c; return W.now; }

static uint64_t mono_fn(void *c) { (void)c; W.mono += W.mono_step; return W.mono; }

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
    W.reads++;
    memset(out, 0, sizeof(*out));
    uint32_t gen = nodus_v2_pins_generation_count();
    out->tip = W.nodus_tip;
    out->generation = gen;
    nodus_v2_pins_tuples(gen, &out->sys_version, out->sys_hash, &out->core_version, out->core_hash);
    return AMM_NODE_OK;
}
static int n_gas(void *c, uint64_t *out, uint64_t dl) { (void)c; (void)dl; W.reads++; *out = W.gas; return AMM_NODE_OK; }
static int n_btime(void *c, uint64_t h, uint64_t *t, uint64_t dl) {
    (void)c; (void)dl; (void)h; *t = 5000; return AMM_NODE_OK;
}
static int n_balance(void *c, const char *owner, const uint8_t token[64], uint64_t *tip,
                     uint64_t *total, uint64_t dl) {
    (void)c; (void)owner; (void)token; (void)dl;
    W.reads++; W.nbal_reads++;
    if (W.nodus_balance_rc) return W.nodus_balance_rc;
    *tip = W.nodus_tip; *total = W.nodus_balance;
    return AMM_NODE_OK;
}
static int n_coins(void *c, const uint8_t token[64], amm_coin_list_t *out, uint64_t dl) {
    (void)c; (void)token; (void)dl;
    memset(out, 0, sizeof(*out));
    if (W.ncoins > 0) {                           /* the scripted list (E20)  */
        out->n = W.ncoins;
        for (int k = 0; k < W.ncoins; k++) {
            for (int i = 0; i < 64; i++) out->c[k].nul[i] = (uint8_t)(W.coin_seed[k] + i);
            out->c[k].amount = W.coin_amt[k];
        }
        out->tip = W.nodus_tip;
        return AMM_NODE_OK;
    }
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
    (void)c; (void)h; (void)dl;
    if (!W.rcpt_ok) return AMM_ETH_ERR;      /* the default: receipts are unreadable */
    memset(o, 0, sizeof(*o));
    o->status = 1;
    o->block_number = W.rcpt_block;
    memset(o->block_hash, W.rcpt_hash, 32);
    return AMM_ETH_OK;
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
    W.reads++; W.prov_reads++;
    if (W.erc20_fail) return AMM_ETH_ERR;
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(W.usdt_balance >> (8 * i));
    return AMM_ETH_OK;
}
static int e_count(void *c, const uint8_t a[20], int pending, uint64_t *o, uint64_t dl) {
    (void)c; (void)a; (void)pending; (void)dl; *o = 0; return AMM_ETH_OK;
}
static int e_est(void *c, const uint8_t f[20], const uint8_t t[20], const uint8_t *in, size_t n,
                 uint64_t *o, uint64_t dl) {
    (void)c; (void)f; (void)t; (void)in; (void)n; (void)dl; W.reads++; W.prov_reads++; *o = 60000; return AMM_ETH_OK;
}
static int e_gasp(void *c, uint64_t *o, uint64_t dl) { (void)c; (void)dl; W.reads++; W.prov_reads++; *o = 20000000000ULL; return AMM_ETH_OK; }
static int e_prio(void *c, uint64_t *o, uint64_t dl) { (void)c; (void)dl; *o = 1000000000ULL; return AMM_ETH_OK; }
static int e_send(void *c, const uint8_t *raw, size_t n, uint8_t h[32], uint64_t dl) {
    (void)c; (void)raw; (void)n; (void)h; (void)dl; return AMM_ETH_ERR;
}

static int price_fee(void *c, uint64_t gas, uint64_t maxfee, uint64_t *o, uint64_t dl) {
    (void)c; (void)gas; (void)maxfee; (void)dl;
    W.reads++;
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
    nc.inflight_max = e->cfg.inflight_max_usdt; nc.held_keeps_room = e->cfg.held_keeps_room;
    e->nw = amm_nodus_watch_new(&nc);
    if (!e->nw) { printf("FATAL: nodus watcher\n"); exit(2); }

    memset(&e->npc, 0, sizeof(e->npc));
    e->npc.node = &e->node; e->npc.journal = e->j; e->npc.pk = g_id->pk.bytes; e->npc.sk = g_id->sk.bytes;
    e->npc.rand = nrand; memcpy(e->npc.chain_id, W.chain, 32);
    e->npc.expiry_ahead = 90; e->npc.resubmit_blocks = 3; e->npc.scan_blocks = 64;
    e->npc.payouts_paused = e->cfg.payouts_paused;     /* the payer is paused with the engine (E29) */
    e->np = amm_nodus_pay_new(&e->npc);
    if (!e->np) { printf("FATAL: nodus payer\n"); exit(2); }
    memcpy(e->cfg.foundation_nodus, amm_nodus_pay_self(e->np), 129);

    amm_engine_cfg_t ec;
    memset(&ec, 0, sizeof(ec));
    ec.cfg = &e->cfg; ec.journal = e->j; ec.eth_watch = e->ew; ec.eth_pay = e->ep;
    ec.nodus_watch = e->nw; ec.nodus_pay = e->np; ec.node = e->node;
    ec.providers = e->prov; ec.n_providers = 2; ec.quorum = 2; ec.price = price;
    ec.now_unix = clock_fn; ec.rand_fn = rand_fn;
    ec.page = g_page;
    ec.mono_ms = mono_fn;
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
    W.mono_step = 10000;             /* every read of the clock is 10 s later: no shared reads (E24 sets it to 0) */
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

/* The watcher's own transaction for a payment seen: the swap takes room (or
 * waits) and is then counted: used where a test needs a counted swap without
 * running a watcher. `took` = 1 when it holds room. */
static int seen_swap(env_t *e, const amm_swap_t *s, const char *key, int *took) {
    return amm_journal_swap_seen(e->j, s->seq, key, NULL, e->cfg.inflight_max_usdt,
                                 e->cfg.held_keeps_room, took) == 0;
}
static int seen_counted(env_t *e, const amm_swap_t *s, const char *key) {
    int took = 0;
    return seen_swap(e, s, key, &took) && took &&
           amm_journal_swap_transition(e->j, s->seq, "counted", NULL, NULL, NULL) == 0;
}

/* A deep Ethereum record of `value` from sender byte `from_c`. */
static amm_rec_t put_rec(env_t *e, uint8_t t, uint64_t block, uint8_t from_c, uint64_t value,
                         const char *state) {
    amm_rec_t r = mkrec(t, block, 10100, from_c, value, e->foundation, "seen");
    amm_journal_rec_put(e->j, &r);
    if (strcmp(state, "seen") != 0) {
        snprintf(r.state, sizeof(r.state), "%s", state);
        amm_journal_rec_put(e->j, &r);
    }
    return r;
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
          s.approved_tip == 1000 && !s.room && s.seen_seq == 0 &&
          amm_journal_inflight_sum(e.j, 0, &sum) == 0 && sum == 0,
          "approval row and number written; the question holds NO room (givens item 94)");

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

    /* the payout must be within what the key holds, less what it owes to swaps
     * whose payment is SEEN (an unpaid approval owes nothing, givens item 94) */
    W.nodus_balance = OUT_UN + OUT_UN / 2;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK,
          "1.5 x number held: the unpaid approvals already given owe nothing, a new question is answered");
    {
        /* make one of them seen: it now owes its indicative number */
        amm_swap_t o1;
        CHECK(swap_of(&e, 0x01020304, &o1), "the first approval");
        amm_req_usdt_t ro = usdt_req(&(amm_quote_answer_t){ .amount = 100000000ULL,
                                      .request_number = 0x01020304 }, 'a', 1);
        CHECK(amm_engine_accept_usdt(e.eng, &ro, &o1) == AMM_ACC_RECEIVED && seen_swap(&e, &o1, "eth:q1", &(int){0}),
              "its payment is seen");
        CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_CANNOT_PAY,
              "1.5 x number held: the SEEN payment's number is owed, a second number cannot be covered");
    }
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
                 seen_counted(&u, &s2, "nodus:zz") &&
                 amm_journal_swap_transition(u.j, s2.seq, "payout_pending", NULL, NULL, NULL) == 0 &&
                 amm_journal_swap_transition(u.j, s2.seq, "unknown", NULL, NULL, NULL) == 0;
        CHECK(ok && amm_engine_quote(u.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &a) == AMM_Q_STOPPED,
              "a swap in unknown stops new approvals");
    }
    env_close(&u);

    /* in-flight total (givens item 94): questions hold nothing, so two 100 USDT
     * questions are both answered under a 150 USDT total; once ONE payment is
     * seen it holds its room and the next question is refused */
    env_t f;
    env_open(&f);
    f.cfg.inflight_max_usdt = 150000000ULL;
    env_restart(&f);
    amm_quote_answer_t fa, fb, fc;
    CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &fa) == AMM_Q_OK &&
          amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &fb) == AMM_Q_OK,
          "two unpaid 100 USDT questions under a 150 USDT total: both answered");
    {
        amm_req_usdt_t fr = usdt_req(&fa, 'a', 1);
        amm_swap_t fs;
        CHECK(amm_engine_accept_usdt(f.eng, &fr, &fs) == AMM_ACC_RECEIVED && seen_swap(&f, &fs, "eth:f1", &(int){0}),
              "the first payment is seen: it holds 100 USDT of room");
        CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &fc) == AMM_Q_INFLIGHT,
              "the next 100 USDT question passes the 150 USDT total of the SEEN payments: refused");
    }
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

#define OUT_UN_CH 62434963579604ULL /* 10^8 raw USDT -> NODUS at depths 2*10^15 / 3*10^9:
                                     * 10^8*3*10^9*2*10^15 / (3.1*10^9)^2 = 6*10^32 /
                                     * 9.61*10^18 truncated (hand derived, python3 integer
                                     * division of the same formula) */

/* Proves (givens items 93, 94; plan section 12): the payment seen takes room and
 * a seen number, NOTHING is applied to the ledger before the decision, and the
 * decision computes the output AGAIN from the depths of that moment (not the
 * number of the question), stores the signed payout and the ledger update
 * together. FALSE PASS: the stubs answer fixed fees; the expected output is the
 * same formula as the ledger's, computed independently with integer division. */
static void e3_count_and_payout(void) {
    printf("E3 seen, counted, the decision: the output computed again, payout and ledger together\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_swap_t s;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK && a.number == OUT_UN,
          "approval: the indicative number at the depths of the question");
    amm_req_usdt_t r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");
    pool_set(&e, 2000000000000000ULL, POOL_U);     /* the depths change after the question */

    amm_rec_t rec = mkrec(0x11, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK, "a seen record of the sender and amount");
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.matched == 1 && state_of(&e, a.request_number, "paid_waiting_depth"),
          "the record moves the approval to paid_waiting_depth");
    CHECK(swap_of(&e, a.request_number, &s) && s.seen_seq == 1 && s.room == 1,
          "recorded as seen: seen number 1 and the room taken");
    uint64_t sum = 0;
    CHECK(amm_journal_inflight_sum(e.j, 0, &sum) == 0 && sum == 100000000ULL,
          "the seen payment holds its 100 USDT of room");
    CHECK(pool_is(&e, 2000000000000000ULL, POOL_U), "nothing is applied to the ledger before the decision");
    snprintf(rec.state, sizeof(rec.state), "deep");
    CHECK(amm_journal_rec_put(e.j, &rec) == AMM_J_OK, "the record reaches its depth");
    CHECK(step(&e, &o) == 0 && o.counted >= 1 && o.decided == 1 && state_of(&e, a.request_number, "payout_pending"),
          "counted and decided to a payout in the same step");
    /* 2*10^15 - 62434963579604 = 1937565036420396; depth_u + 10^8 */
    CHECK(pool_is(&e, 1937565036420396ULL, 3100000000ULL),
          "the ledger took the output computed AGAIN from the changed depths, not the question's number");
    CHECK(swap_of(&e, a.request_number, &s) && s.out_amount == OUT_UN_CH && s.out_paid + s.out_fee == s.out_amount &&
          s.out_paid > 0, "the decision's output, fee and amount paid are on the row");
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_attempt_latest(e.j, s.seq, &at) == 0 && at.gross == OUT_UN_CH &&
          at.net + at.fee == at.gross && at.net == s.out_paid && at.fee == s.out_fee && at.net > 0,
          "the NODUS payout is signed in the decision: gross = the output, the Nodus fee deducted");
    amm_attempt_free(&at);
    CHECK(W.submits >= 1, "and submitted");

    /* a restart repeats nothing */
    env_restart(&e);
    CHECK(step(&e, &o) == 0 && o.decided == 0 && state_of(&e, a.request_number, "payout_pending") &&
          pool_is(&e, 1937565036420396ULL, 3100000000ULL), "after a restart: nothing repeated");
    env_close(&e);

    /* the depths unchanged: the output equals the number of the question */
    env_t u;
    env_open(&u);
    CHECK(amm_engine_quote(u.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    r = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(u.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request");
    put_rec(&u, 0x12, 1001, 0xaa, 100000000ULL, "deep");
    CHECK(step(&u, &o) == 0 && swap_of(&u, a.request_number, &s) && !strcmp(s.state, "payout_pending") &&
          s.out_amount == OUT_UN && pool_is(&u, 2906347554630594ULL, 3100000000ULL),
          "nothing changed the depths in between: the output equals the question's number");
    env_close(&u);
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

    /* the output side almost empty when the swap is decided: its output (31 raw
     * NODUS: 10^8*3*10^9*1000/(3.1*10^9)^2 truncated) is nothing after the
     * Nodus fee, so the swap is REFUNDED in the decision, the ledger untouched */
    amm_rec_t ok = mkrec(0x23, 1002, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    amm_journal_rec_put(e.j, &ok);
    snprintf(ok.state, sizeof(ok.state), "deep");
    amm_journal_rec_put(e.j, &ok);
    pool_set(&e, 1000, POOL_U);
    CHECK(step(&e, &o) == 0 && o.to_refund == 1 && state_of(&e, a.request_number, "refund_pending") &&
          pool_is(&e, 1000, POOL_U),
          "an output that is nothing after the fee: refund, the ledger untouched");
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

/* Proves (givens items 93, 94; plan section 12): a swap below its signed minimum
 * after the network fee is REFUNDED in the decision with the depths UNCHANGED,
 * and a swap decided after it is priced as if the refunded one never existed (the
 * THORChain cache context that is discarded). FALSE PASS: the second swap's
 * expected output is derived from the untouched initial depths with the same
 * formula; if the refunded swap had changed the depths the figure would differ. */
static void e5_below_minimum(void) {
    printf("E5 below the minimum after the fee: a refund in the decision, the depths unchanged\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a, b;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t r = usdt_req(&a, 'a', OUT_UN + 1);          /* no fee can leave this satisfied */
    CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "signed request with a high minimum");
    amm_rec_t rec = mkrec(0x41, 1001, 10100, 0xaa, 100000000ULL, e.foundation, "seen");
    amm_journal_rec_put(e.j, &rec);
    snprintf(rec.state, sizeof(rec.state), "deep");
    amm_journal_rec_put(e.j, &rec);
    CHECK(step(&e, &o) == 0 && o.to_refund == 1 && state_of(&e, a.request_number, "refund_pending"),
          "net below the minimum: refund_pending");
    CHECK(pool_is(&e, POOL_N, POOL_U), "the depths are the initial ones: nothing was applied, nothing is reversed");
    amm_swap_t s;
    CHECK(swap_of(&e, a.request_number, &s) && s.out_amount == 0, "no output was decided for it");
    /* a swap decided after the refunded one is priced as if it never existed */
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &b) == AMM_Q_OK, "a second approval");
    amm_req_usdt_t rb = usdt_req(&b, 'b', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &rb, NULL) == AMM_ACC_RECEIVED, "second signed request");
    put_rec(&e, 0x42, 1003, 0xbb, 100000000ULL, "deep");
    amm_swap_t s2;
    CHECK(step(&e, &o) == 0 && swap_of(&e, b.request_number, &s2) && !strcmp(s2.state, "payout_pending") &&
          s2.out_amount == OUT_UN && pool_is(&e, 2906347554630594ULL, 3100000000ULL),
          "the next swap is priced from the untouched depths: 93652445369406, as if the refunded one never existed");
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
    CHECK(seen_counted(&e, &s, s.incoming_id) &&
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
        CHECK(swap_of(&e, 4242, &ts) && seen_counted(&e, &ts, ts.incoming_id) &&
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
    CHECK(seen_counted(&u, &s, "eth:aa") &&
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
    CHECK(swap_of(&e, a.request_number, &s) && seen_counted(&e, &s, s.incoming_id),
          "payment counted (as the watcher does)");
    CHECK(step(&e, &o) == 0 && state_of(&e, a.request_number, "payout_pending"), "payout_pending");
    /* 3*10^15 + 10^14 NODUS; 3*10^9 - 93652445 USDT */
    CHECK(pool_is(&e, 3100000000000000ULL, 2906347555ULL), "the decision's output left the USDT depth");
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
          swap_of(&m, a2.request_number, &s2) && seen_counted(&m, &s2, s2.incoming_id), "payment counted");
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
          seen_counted(&e, &s, "eth:bb") &&
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
          seen_counted(&f, &s, s.incoming_id) &&
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
    CHECK(swap_of(&e, a.request_number, &sa) && !*sa.incoming_id && sa.room == 0 && sa.seen_seq == 0 &&
          amm_journal_swap_by_incoming(e.j, key, &sx) == 1 && pool_is(&e, 2906347554630594ULL, 3100000000ULL),
          "the approval no longer carries the payment, holds no room and left the line; the ledger holds "
          "only the counted swap's decision");
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
          seen_counted(&e, &s, s.incoming_id), "payment counted");
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
          seen_counted(&m, &s, s.incoming_id), "payment counted");
    CHECK(step(&m, &o) == 0 && state_of(&m, a.request_number, "counted") &&
          amm_journal_eth_attempt_latest(m.j, s.seq, &at) == 1,
          "providers on another chain than the setting: no payout is signed, the swap stays counted undecided");
    env_close(&m);
}

/* ── E14 room from the seen payment (givens item 94, plan section 13) ───── */

/* Proves: a price question holds nothing (six unpaid 100 USDT questions are
 * answered and a sixth user's payment takes room); a payment that finds the room
 * full waits in line, is not counted, keeps its match after its approval's
 * expiry, takes room when a payout is done and is decided at the depths of THAT
 * moment (not its question's number); the line is strict in the seen order (a
 * later, smaller payment that would fit does not pass the head); the seen order
 * and the line are the same after a restart.
 * FALSE PASS: the NODUS payments are recorded as seen through the journal call the
 * Nodus watcher makes (the stub history cannot deliver rows), so the watcher's own
 * reading is test_amm_nodus_watch's; the sixth swap's output 69775761 is derived by
 * integer arithmetic outside the code (five 10^14 NODUS swaps decided before it). */
static void e14_room_line(void) {
    printf("E14 room from the seen payment: the line, strict, in seen order, across a restart\n");
    {
        env_t e;
        env_open(&e);
        amm_quote_answer_t q[6];
        amm_swap_t s;
        int ok = 1;
        for (int i = 0; i < 6 && ok; i++)
            ok = amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &q[i]) == AMM_Q_OK;
        CHECK(ok, "six unpaid 100 USDT questions are all answered: a question holds nothing");
        amm_req_usdt_t r = usdt_req(&q[5], 'f', 1);
        CHECK(amm_engine_accept_usdt(e.eng, &r, NULL) == AMM_ACC_RECEIVED, "the sixth user signs");
        put_rec(&e, 0x71, 1001, 0xff, 100000000ULL, "deep");
        amm_engine_step_t o;
        CHECK(step(&e, &o) == 0 && swap_of(&e, q[5].request_number, &s) && s.room == 1 && s.seen_seq == 1 &&
              !strcmp(s.state, "payout_pending"),
              "the sixth user's payment takes room (seen number 1) and is decided");
        int apr = 0;
        CHECK(amm_journal_state_count(e.j, "approved", &apr) == 0 && apr == 5,
              "the five unpaid approvals hold no room and are still open");
        env_close(&e);
    }

    env_t e;
    env_open(&e);
    e.cfg.inflight_max_usdt = 518262225ULL;      /* 5 x 93652445 + 50,000,000 */
    env_restart(&e);
    static const char SND[] = "123456789abcdef", TID[] = "fedcba987654321";
    const uint64_t amt[8] = {100000000000000ULL, 100000000000000ULL, 100000000000000ULL, 100000000000000ULL,
                             100000000000000ULL, 100000000000000ULL, 2000000000000ULL, 100000000000000ULL};
    amm_quote_answer_t q[8];
    amm_swap_t s[8];
    int ok = 1;
    for (int i = 0; i < 8 && ok; i++) {
        ok = amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, amt[i], 0, &q[i]) == AMM_Q_OK;
        amm_req_nodus_to_usdt_t nr = nodus_req(&q[i], TID[i], 1);
        memset(nr.sender, SND[i], 128);
        ok = ok && amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED &&
             swap_of(&e, q[i].request_number, &s[i]);
    }
    CHECK(ok && q[0].number == OUT_NU && q[6].number == 1997335ULL,
          "eight NODUS -> USDT swaps approved and signed (v = 93.652445 USDT five times, 1.997335 USDT, 93.652445 USDT)");
    int took[8] = {0};
    ok = 1;
    for (int i = 0; i < 8 && ok; i++) ok = seen_swap(&e, &s[i], s[i].incoming_id, &took[i]);
    CHECK(ok && took[0] && took[1] && took[2] && took[3] && took[4],
          "the first five payments seen take room: 468.262225 USDT of the 518.262225 USDT total");
    CHECK(!took[5] && !took[6] && !took[7],
          "the sixth (93.65) does not fit and waits; the seventh (1.997335) WOULD fit but does not pass the head of "
          "the line; the eighth waits");
    for (int i = 0; i < 5; i++)
        CHECK(amm_journal_swap_transition(e.j, s[i].seq, "counted", NULL, NULL, NULL) == 0, "a payment holding room is counted");
    CHECK(amm_journal_swap_transition(e.j, s[5].seq, "counted", NULL, NULL, NULL) == AMM_J_NO_ROOM,
          "a payment waiting for room cannot be counted");
    W.now = 10301;                                   /* past every approval's expiry */
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.decided == 5, "the five counted swaps are decided in the seen order");
    for (int i = 5; i < 8; i++) {
        amm_swap_t g;
        CHECK(swap_of(&e, q[i].request_number, &g) && !strcmp(g.state, "paid_waiting_depth") && g.room == 0 &&
              g.seen_seq == i + 1 && !strcmp(g.incoming_id, s[i].incoming_id),
              "a waiting payment: not counted, in the line at its seen number, its match kept after the expiry");
    }
    env_restart(&e);                                  /* the order and the line are rows, not memory */
    for (int i = 5; i < 8; i++) {
        amm_swap_t g;
        CHECK(swap_of(&e, q[i].request_number, &g) && g.room == 0 && g.seen_seq == i + 1,
              "after a restart: the same seen number and the same place in the line");
    }
    /* a payout done releases its room: the head of the line takes it first */
    amm_swap_t first;
    CHECK(swap_of(&e, q[0].request_number, &first) && !strcmp(first.state, "payout_pending") &&
          amm_journal_eth_attempt_finish(e.j, first.seq, "confirmed") == 0 &&
          amm_journal_swap_transition(e.j, first.seq, "paid", NULL, NULL, NULL) == 0, "the first payout is done");
    CHECK(step(&e, &o) == 0 && o.room_granted == 2, "the line takes the freed room: two payments");
    amm_swap_t g6, g7, g8;
    CHECK(swap_of(&e, q[5].request_number, &g6) && swap_of(&e, q[6].request_number, &g7) &&
          swap_of(&e, q[7].request_number, &g8) &&
          !strcmp(g6.state, "payout_pending") && !strcmp(g7.state, "payout_pending") &&
          !strcmp(g8.state, "paid_waiting_depth") && g8.room == 0,
          "the sixth then the seventh took room and were decided; the eighth, behind them, still waits");
    CHECK(g6.out_amount == 69775761ULL && g6.out_amount != q[5].number,
          "the sixth is decided at the depths of that moment (69775761 after five swaps), not its question's 93652445");
    env_close(&e);
}

/* ── E15 more rows than one page ─────────────────────────────────────── */

/* Proves: with the page set to 2, five approved rows are all walked (all five
 * expire in one step) and five counted swaps are all decided in one step: no list
 * the engine walks stops at a page. FALSE PASS: if the engine ignored the page
 * setting both would still pass; the page value reaches amm_journal_swap_page,
 * whose own test (test_amm_journal J-page) pins that a page returns at most `cap`
 * rows. */
static void e15_paging(void) {
    printf("E15 more rows than one page do not stop the engine\n");
    g_page = 2;
    env_t e;
    env_open(&e);
    amm_quote_answer_t q[5];
    int ok = 1;
    for (int i = 0; i < 5 && ok; i++)
        ok = amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &q[i]) == AMM_Q_OK;
    CHECK(ok, "five approved rows, a page of two");
    W.now = 10301;
    amm_journal_cursor_reset(e.j, "nodus_scan", 1000);
    amm_journal_cursor_reset(e.j, "nodus_scan_ts", 10400);
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.expired == 5, "all five approved rows expire in one step (three pages)");
    env_close(&e);

    env_t c;
    env_open(&c);
    static const char SND[] = "12345", TID[] = "54321";
    amm_swap_t s[5];
    ok = 1;
    for (int i = 0; i < 5 && ok; i++) {
        amm_quote_answer_t a;
        ok = amm_engine_quote(c.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK;
        amm_req_nodus_to_usdt_t nr = nodus_req(&a, TID[i], 1);
        memset(nr.sender, SND[i], 128);
        ok = ok && amm_engine_accept_nodus(c.eng, &nr, NULL) == AMM_ACC_RECEIVED &&
             swap_of(&c, a.request_number, &s[i]) && seen_counted(&c, &s[i], s[i].incoming_id);
    }
    CHECK(ok, "five counted swaps");
    CHECK(step(&c, &o) == 0 && o.decided == 5, "all five are decided in one step (three pages)");
    env_close(&c);
    g_page = 0;
}

/* ── E16 the liquidity add ───────────────────────────────────────────── */

static void drop_pool(env_t *e) {
    sqlite3 *db = NULL;
    if (sqlite3_open(e->jpath, &db) == SQLITE_OK) {
        sqlite3_busy_timeout(db, 5000);
        sqlite3_exec(db, "DELETE FROM pool", NULL, NULL, NULL);
        sqlite3_close(db);
    }
}

static amm_req_liq_add_t add_req(const amm_add_answer_t *a, char eth_c, char nodus_c, char tid_c) {
    amm_req_liq_add_t r;
    memset(&r, 0, sizeof(r));
    memset(r.ethereum_address, eth_c, 40);
    memset(r.nodus_address, nodus_c, 128);
    memset(r.transfer_id, tid_c, 128);
    r.usdt_amount = a->usdt_amount; r.nodus_amount = a->nodus_amount;
    r.request_number = a->request_number;
    for (int i = 0; i < 4; i++) r.req_no[31 - i] = (uint8_t)(a->request_number >> (8 * i));
    return r;
}

/* Both deposits of one signed add: the USDT record (deep, from the add's Ethereum
 * address) and the NODUS history row (peer = the add's Nodus address, wire id =
 * the transfer id). */
static void add_deposits(env_t *e, const amm_req_liq_add_t *r, uint8_t eth_byte, uint8_t wire_byte,
                         uint64_t eth_block, uint64_t nodus_height) {
    amm_rec_t rec = mkrec(eth_byte, eth_block, 10100, (uint8_t)0xaa, r->usdt_amount, e->foundation, "seen");
    memset(rec.from, 0, 20);
    for (int i = 0; i < 20; i++) {
        char hx[3] = { r->ethereum_address[2 * i], r->ethereum_address[2 * i + 1], 0 };
        rec.from[i] = (uint8_t)strtoul(hx, NULL, 16);
    }
    amm_journal_rec_put(e->j, &rec);
    snprintf(rec.state, sizeof(rec.state), "deep");
    amm_journal_rec_put(e->j, &rec);
    amm_nrow_t nr;
    memset(&nr, 0, sizeof(nr));
    nr.height = nodus_height; nr.item = 0; nr.seq = 0;
    memset(nr.wire, wire_byte, 64);
    memcpy(nr.peer, r->nodus_address, 128);
    nr.amount = r->nodus_amount; nr.ts = 10100;
    snprintf(nr.state, sizeof(nr.state), "%s", AMM_NR_HELD);
    snprintf(nr.reason, sizeof(nr.reason), "matches no approval");
    amm_journal_nrow_put(e->j, &nr);
}

/* Proves (givens items 91, 96, 25, 49; plan sections 6.4.6, 14): the price question
 * is refused until an add has committed; an add below 100,000 NODUS is refused at
 * the question and writes nothing, exactly 100,000 NODUS (and its 10 USDT at the
 * start ratio) is accepted; the Foundation's first add of 3,000 USDT + 30,000,000
 * NODUS is accepted and gives units = the NODUS raw amount (THORChain
 * handler_add_liquidity.go:444-448); the USDT side counts after 300 Ethereum
 * blocks (not at 299) and the NODUS side after 3 Nodus blocks (not at 2); a second
 * add into the non-empty pool gets units by THORChain's formula (hand derived:
 * equal ratios give P*r/R = 3*10^15 * 10^13 / 3*10^15 = 10^13); an add whose
 * Ethereum address and USDT amount equal an open swap approval is refused (6.4.6).
 * FALSE PASS: the receipts, tips and Nodus rows are scripted; the depth rules are
 * the watchers' (their tests) and are only asked here. */
static void e16_liquidity_add(void) {
    printf("E16 the liquidity add\n");
    env_t e;
    env_open(&e);
    drop_pool(&e);
    amm_quote_answer_t sq;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &sq) == AMM_Q_UNAVAILABLE,
          "no committed add: the price question is refused (givens item 91)");

    amm_add_answer_t aa;
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 9999999999999ULL, 0, &aa) == AMM_AQ_BELOW_MIN,
          "an add of 99,999.99999999 NODUS is refused below 100,000 NODUS (givens item 96)");
    amm_add_t row;
    int nrows = 0;
    amm_add_t rows[4];
    CHECK(amm_journal_add_page(e.j, "approved", 0, rows, 4, &nrows) == 0 && nrows == 0, "and nothing was written");
    W.rq[0] = 0x0A0B0C0D; W.rq_n = 1; W.rq_i = 0;
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK &&
          aa.nodus_amount == 10000000000000ULL && aa.usdt_amount == 10000000ULL && aa.request_number == 0x0A0B0C0D,
          "exactly 100,000 NODUS is accepted with its 10 USDT at the start ratio 3000 : 30,000,000");
    CHECK(amm_journal_add_by_botreq(e.j, 0x0A0B0C0D, &row) == 0 && !strcmp(row.state, "approved") &&
          row.eth_tip == 1000 && row.nodus_tip == 1000 && row.expiry == 10300,
          "the add's approval row: the exact pair, both tips, the expiry");

    /* the Foundation's first add */
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_USDT, 3000000000ULL, 0, &aa) == AMM_AQ_OK &&
          aa.usdt_amount == 3000000000ULL && aa.nodus_amount == 3000000000000000ULL &&
          !strcmp(aa.pay_nodus, e.cfg.foundation_nodus),
          "the Foundation's add question: 3,000 USDT -> 30,000,000 NODUS at the start ratio, pay to the Foundation");
    amm_req_liq_add_t lr = add_req(&aa, 'a', 'c', 'a');
    CHECK(amm_engine_accept_add(e.eng, &lr, NULL) == AMM_ACC_RECEIVED, "the signed pair is accepted");
    CHECK(amm_engine_accept_add(e.eng, &lr, NULL) == AMM_ACC_USED, "a number is accepted once");
    add_deposits(&e, &lr, 0x91, 0xaa, 1001, 1001);
    amm_engine_step_t o;
    W.eth_tip = 1400;
    CHECK(step(&e, &o) == 0 && o.adds_linked == 2, "both deposits are matched to the add");
    amm_pool_t pool;
    CHECK(amm_journal_pool_get(e.j, &pool) == 1, "receipts unreadable: nothing is counted, still no ledger");
    W.rcpt_ok = 1; W.rcpt_block = 1001; W.rcpt_hash = 0x91;
    W.eth_tip = 1300; W.nodus_tip = 1010;
    CHECK(step(&e, &o) == 0 && o.adds_committed == 0 && amm_journal_pool_get(e.j, &pool) == 1,
          "the USDT side at 299 blocks is not counted (300 wait, givens item 25)");
    W.eth_tip = 1301; W.nodus_tip = 1003;
    CHECK(step(&e, &o) == 0 && o.adds_committed == 0 && amm_journal_pool_get(e.j, &pool) == 1,
          "the NODUS side at 2 blocks is not counted (3 wait, givens item 49)");
    W.nodus_tip = 1004;
    CHECK(step(&e, &o) == 0 && o.adds_committed == 1, "both sides counted: the add commits");
    uint64_t pn = 0, pu = 0, pq = 0;
    CHECK(amm_journal_pool_get(e.j, &pool) == 0 && amm_to_u64(&pn, &pool.depth_n) == 0 &&
          amm_to_u64(&pu, &pool.depth_u) == 0 && amm_to_u64(&pq, &pool.units) == 0 &&
          pn == 3000000000000000ULL && pu == 3000000000ULL && pq == 3000000000000000ULL,
          "the ledger: 30,000,000 NODUS, 3,000 USDT, units = the NODUS raw amount 3*10^15");
    evm_u256 pos;
    char eth_hex[41], nodus_hex[129];
    memset(eth_hex, 'a', 40); eth_hex[40] = 0; memset(nodus_hex, 'c', 128); nodus_hex[128] = 0;
    uint64_t pu64 = 0;
    CHECK(amm_journal_position_get(e.j, eth_hex, nodus_hex, &pos) == 0 && amm_to_u64(&pu64, &pos) == 0 &&
          pu64 == 3000000000000000ULL, "the position (address pair -> units) holds 3*10^15");
    CHECK(amm_journal_add_by_botreq(e.j, aa.request_number, &row) == 0 && !strcmp(row.state, "committed"),
          "the add is committed");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &sq) == AMM_Q_OK,
          "after the first add has committed the price question is answered");

    /* 6.4.6: one USDT payment must not fit an open swap approval and an add */
    amm_quote_answer_t oq;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 10000000ULL, 0, &oq) == AMM_Q_OK, "a 10 USDT swap approval");
    amm_req_usdt_t ur = usdt_req(&oq, 'b', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &ur, NULL) == AMM_ACC_RECEIVED, "signed by sender bb..bb");
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK &&
          aa.usdt_amount == 10000000ULL, "an add of 10 USDT + 100,000 NODUS at the pool's ratio");
    amm_req_liq_add_t lb = add_req(&aa, 'b', 'd', 'b');
    uint32_t open_req = 0;
    CHECK(amm_engine_accept_add(e.eng, &lb, &open_req) == AMM_ACC_OPEN && open_req == oq.request_number,
          "the add of the same Ethereum address and USDT amount as an open swap approval is refused, the swap named");
    env_close(&e);

    /* the second add into the non-empty pool: units by THORChain's formula */
    env_t f;
    env_open(&f);
    {
        amm_pool_t p0;                               /* the pool after the first add: units = 3*10^15 */
        evm_u256_from_u64(&p0.depth_n, 3000000000000000ULL);
        evm_u256_from_u64(&p0.depth_u, 3000000000ULL);
        evm_u256_from_u64(&p0.units, 3000000000000000ULL);
        amm_journal_pool_put(f.j, &p0);
    }
    CHECK(amm_engine_add_question(f.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK &&
          aa.usdt_amount == 10000000ULL, "the pool's ratio gives 10 USDT for 100,000 NODUS");
    amm_req_liq_add_t l2 = add_req(&aa, 'e', 'f', 'e');
    CHECK(amm_engine_accept_add(f.eng, &l2, NULL) == AMM_ACC_RECEIVED, "signed");
    add_deposits(&f, &l2, 0x92, 0xee, 1001, 1001);
    W.eth_tip = 1400; W.nodus_tip = 1010; W.rcpt_ok = 1; W.rcpt_block = 1001; W.rcpt_hash = 0x92;
    CHECK(step(&f, &o) == 0 && o.adds_linked == 2 && o.adds_committed == 1, "linked and committed in the waits' order");
    /* P=3*10^15 R=3*10^15 A=3*10^9 r=10^13 a=10^7: inner = rA + aR + 2ra = 6.02*10^22,
     * den = rA + aR + 2RA = 1.806*10^25: P*inner/den = 10^13 (equal ratios) */
    memset(eth_hex, 'e', 40); memset(nodus_hex, 'f', 128);
    CHECK(amm_journal_position_get(f.j, eth_hex, nodus_hex, &pos) == 0 && amm_to_u64(&pu64, &pos) == 0 &&
          pu64 == 10000000000000ULL, "units of the second add by THORChain's formula: 10^13");
    CHECK(amm_journal_pool_get(f.j, &pool) == 0 && amm_to_u64(&pn, &pool.depth_n) == 0 &&
          amm_to_u64(&pu, &pool.depth_u) == 0 && amm_to_u64(&pq, &pool.units) == 0 &&
          pn == 3000000000000000ULL + 10000000000000ULL && pu == 3000000000ULL + 10000000ULL &&
          pq == 3000000000000000ULL + 10000000000000ULL, "the pool grew by the pair and the units");
    env_close(&f);
}

/* ── E17 a swap that cannot be decided writes nothing ───────────────── */

/* Proves (plan section 12; section 16): a counted NODUS -> USDT swap whose decision
 * cannot be completed -- the ETH price unreadable, the bot's USDT short, payouts
 * paused (the trading-halt refund too) -- writes NOTHING: it stays counted with its
 * room, no output, no attempt, the pool unchanged; once the fact is readable again
 * it is decided at the depths of that round. FALSE PASS: the stubs fail the reads on
 * demand; the same step decides the swap when the stub is restored, so a decision
 * that merely never runs would fail the last check of each case. */
static void e17_undecidable(void) {
    printf("E17 an undecidable swap writes nothing and stays counted with its room\n");
    env_t e;
    env_open(&e);
    amm_quote_answer_t a;
    amm_swap_t s;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_nodus_to_usdt_t nr = nodus_req(&a, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, &s) == AMM_ACC_RECEIVED && swap_of(&e, a.request_number, &s) &&
          seen_counted(&e, &s, s.incoming_id), "a counted swap");
    amm_eattempt_t at;
    amm_swap_t g;
    W.price_rc = 1;
    CHECK(step(&e, &o) == 0 && o.decided == 0 && o.undecided == 1 && swap_of(&e, a.request_number, &g) &&
          !strcmp(g.state, "counted") && g.room == 1 && g.out_amount == 0 && pool_is(&e, POOL_N, POOL_U) &&
          amm_journal_eth_attempt_latest(e.j, s.seq, &at) == 1,
          "price unreadable: nothing written, still counted with its room");
    W.price_rc = 0;
    W.usdt_balance = 1000;
    CHECK(step(&e, &o) == 0 && o.undecided == 1 && state_of(&e, a.request_number, "counted") &&
          pool_is(&e, POOL_N, POOL_U) && amm_journal_eth_attempt_latest(e.j, s.seq, &at) == 1,
          "the bot's USDT short: nothing written, still counted");
    W.usdt_balance = 1000000000000ULL;
    e.cfg.payouts_paused = 1;
    e.cfg.swaps_paused = 1;                          /* a trading-halt refund would be due */
    env_restart(&e);
    CHECK(step(&e, &o) == 0 && o.undecided == 1 && o.to_refund == 0 && state_of(&e, a.request_number, "counted") &&
          pool_is(&e, POOL_N, POOL_U), "payouts paused: no decision of any kind, the trading-halt refund included");
    e.cfg.payouts_paused = 0;
    env_restart(&e);
    CHECK(step(&e, &o) == 0 && o.to_refund == 1 && state_of(&e, a.request_number, "refund_pending"),
          "payouts running again: the swap is decided (swaps still paused: a refund)");
    env_close(&e);

    env_t f;
    env_open(&f);
    CHECK(amm_engine_quote(f.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK, "approval");
    nr = nodus_req(&a, 'f', 1);
    CHECK(amm_engine_accept_nodus(f.eng, &nr, &s) == AMM_ACC_RECEIVED && swap_of(&f, a.request_number, &s) &&
          seen_counted(&f, &s, s.incoming_id), "a counted swap");
    W.price_rc = 1;
    CHECK(step(&f, &o) == 0 && o.decided == 0, "price unreadable: undecided");
    W.price_rc = 0;
    CHECK(step(&f, &o) == 0 && o.decided == 1 && state_of(&f, a.request_number, "payout_pending"),
          "the price readable again: decided in the round that completes it");
    env_close(&f);
}

/* ── E18 liquidity adds beyond one page; E19 adds and swaps in one order ── */

/* Proves: with a page of 2, five unsigned add approvals expire in one step (the add
 * lists are walked by page); a ready add (seen number 1) commits BEFORE a swap seen
 * after it (seen number 2) is decided, so the swap is priced from the pool the add
 * changed (93672521996257, hand derived by integer arithmetic), not from the pool
 * before it (93652445369406). FALSE PASS: the order would also hold if the add were
 * always committed first; the seen numbers are read from the rows to show the add's
 * number is lower. */
static void e18_adds_paged_and_ordered(void) {
    printf("E18 liquidity adds: paged walk, one order with the swaps\n");
    g_page = 2;
    env_t e;
    env_open(&e);
    amm_add_answer_t aa;
    int ok = 1;
    for (int i = 0; i < 5 && ok; i++)
        ok = amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK;
    CHECK(ok, "five add approvals, a page of two");
    W.now = 10301;
    amm_journal_cursor_reset(e.j, "nodus_scan", 1000);
    amm_journal_cursor_reset(e.j, "nodus_scan_ts", 10400);
    amm_blk_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.height = 990; blk.ts = 10400; memset(blk.hash, 5, 32); memset(blk.parent, 4, 32);
    amm_journal_block_put(e.j, &blk);
    amm_journal_cursor_reset(e.j, "eth_scan", 995);
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.adds_expired == 5, "all five expire in one step (three pages)");
    env_close(&e);
    g_page = 0;

    env_t f;
    env_open(&f);
    {
        amm_pool_t p0;
        evm_u256_from_u64(&p0.depth_n, 3000000000000000ULL);
        evm_u256_from_u64(&p0.depth_u, 3000000000ULL);
        evm_u256_from_u64(&p0.units, 3000000000000000ULL);
        amm_journal_pool_put(f.j, &p0);
    }
    amm_quote_answer_t q;
    CHECK(amm_engine_add_question(f.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK, "add question");
    amm_req_liq_add_t lr = add_req(&aa, 'a', 'c', 'a');
    CHECK(amm_engine_accept_add(f.eng, &lr, NULL) == AMM_ACC_RECEIVED, "signed pair");
    add_deposits(&f, &lr, 0x93, 0xaa, 1001, 1001);
    W.eth_tip = 1400; W.nodus_tip = 1010;
    CHECK(step(&f, &o) == 0 && o.adds_linked == 2 && o.adds_committed == 0, "both deposits linked, receipts unreadable");
    amm_add_t ad;
    CHECK(amm_journal_add_by_botreq(f.j, aa.request_number, &ad) == 0 && ad.seen_seq == 1,
          "the add took seen number 1 when its second deposit was linked");
    CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &q) == AMM_Q_OK, "a swap approval");
    amm_req_usdt_t ur = usdt_req(&q, 'b', 1);
    CHECK(amm_engine_accept_usdt(f.eng, &ur, NULL) == AMM_ACC_RECEIVED, "signed request");
    /* the approval read the Ethereum tip 1400 (the stored cursor moved with the
     * first step), so its payment must be in a block above it */
    put_rec(&f, 0x94, 1500, 0xbb, 100000000ULL, "deep");
    W.rcpt_ok = 1; W.rcpt_block = 1001; W.rcpt_hash = 0x93;
    amm_swap_t s;
    CHECK(step(&f, &o) == 0 && o.adds_committed == 1 && o.decided == 1 && swap_of(&f, q.request_number, &s) &&
          s.seen_seq == 2 && !strcmp(s.state, "payout_pending") && s.out_amount == 93672521996257ULL,
          "the add (seen 1) commits before the swap (seen 2) is decided: the swap is priced from the changed pool");
    env_close(&f);
}

/* ── E19 the reverse order: the swap seen first is decided before the add ── */

/* Proves (plan section 13, line 575; the reverse of E18): a swap whose payment was
 * SEEN (seen number 1) before a liquidity add became ready (seen number 2) is decided
 * FIRST, at the pool WITHOUT the add (93652445369406), and the add commits after it;
 * the pool ends with both. If adds were always committed before the swaps, the swap
 * would be priced from the pool the add changed (93672521996257, E18) and this test
 * fails. FALSE PASS: the swap is held undecided in step 1 by payouts_paused (its
 * seen number is read from the row to show it is below the add's); the pause is lifted
 * by a restart, so the same step links the add, makes it ready and decides the swap. */
static void e19_swap_before_add(void) {
    printf("E19 a swap seen before an add is decided before it, priced without it\n");
    env_t f;
    env_open(&f);
    {
        amm_pool_t p0;
        evm_u256_from_u64(&p0.depth_n, 3000000000000000ULL);
        evm_u256_from_u64(&p0.depth_u, 3000000000ULL);
        evm_u256_from_u64(&p0.units, 3000000000000000ULL);
        amm_journal_pool_put(f.j, &p0);
    }
    amm_quote_answer_t q;
    amm_add_answer_t aa;
    CHECK(amm_engine_quote(f.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &q) == AMM_Q_OK, "a swap approval");
    amm_req_usdt_t ur = usdt_req(&q, 'b', 1);
    CHECK(amm_engine_accept_usdt(f.eng, &ur, NULL) == AMM_ACC_RECEIVED, "signed request");
    CHECK(amm_engine_add_question(f.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK, "an add question");
    amm_req_liq_add_t lr = add_req(&aa, 'a', 'c', 'a');
    CHECK(amm_engine_accept_add(f.eng, &lr, NULL) == AMM_ACC_RECEIVED, "signed pair");
    f.cfg.payouts_paused = 1;
    env_restart(&f);
    put_rec(&f, 0x95, 1001, 0xbb, 100000000ULL, "deep");
    amm_engine_step_t o;
    amm_swap_t s;
    CHECK(step(&f, &o) == 0 && swap_of(&f, q.request_number, &s) && s.seen_seq == 1 &&
          !strcmp(s.state, "counted") && o.decided == 0,
          "step 1: the swap's payment is seen (number 1), counted, undecided (payouts paused)");
    f.cfg.payouts_paused = 0;
    env_restart(&f);
    add_deposits(&f, &lr, 0x93, 0xaa, 1001, 1001);
    W.eth_tip = 1400; W.nodus_tip = 1010;
    W.rcpt_ok = 1; W.rcpt_block = 1001; W.rcpt_hash = 0x93;
    CHECK(step(&f, &o) == 0 && o.adds_linked == 2 && o.adds_committed == 1 && o.decided == 1,
          "step 2: the add is linked, ready and committed, the swap decided");
    amm_add_t ad;
    CHECK(amm_journal_add_by_botreq(f.j, aa.request_number, &ad) == 0 && ad.seen_seq == 2 &&
          !strcmp(ad.state, "committed") && swap_of(&f, q.request_number, &s) && s.seen_seq == 1,
          "the add took seen number 2, the swap holds 1");
    CHECK(!strcmp(s.state, "payout_pending") && s.out_amount == OUT_UN,
          "the swap was decided FIRST: priced at 93652445369406, without the add");
    CHECK(pool_is(&f, 3000000000000000ULL - OUT_UN + 10000000000000ULL, 3000000000ULL + 100000000ULL + 10000000ULL),
          "the pool holds the swap's update and then the add");
    env_close(&f);
}

/* ── E20 an expired payout that cannot be replaced does not hold the refunds ── */

static int att_has_seed(const amm_attempt_t *a, uint8_t seed) {
    for (int k = 0; k < a->n_in; k++)
        if (a->inputs[k][0] == seed && a->inputs[k][63] == (uint8_t)(seed + 63)) return 1;
    return 0;
}

/* PROVES (red team finding 1, fix 2): an older USDT -> NODUS payout whose attempt
 *   expired and whose replacement cannot be stored (the Nodus fee changed: only
 *   the decided fee is replaced, givens item 97) does not stop a younger
 *   NODUS -> USDT refund: in the same round the refund is signed, over a coin the
 *   expired payout does not hold (its input is reserved). While the refund's attempt
 *   is live the payout waits (one live attempt); once the refund is settled and the
 *   fee is the decided one again, the payout's replacement is stored and spends the
 *   expired attempt's coin.
 * FLAGS/ENVIRONMENT: a default build; scripted node (two coins: seed 7 = 10^15 raw,
 *   seed 90 = 5*10^14 raw; the tip moves 1000 -> 1100, the expiry is 1090; gas price
 *   0, then 100000 which lifts the fee above the floor). One mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the node answers the scripted coins and tip; the refund and the payout
 *   are walked by journal calls the way E6 does; settlement of the refund is done by
 *   the journal (attempt_finish / transition), not by a scanned block. Without the
 *   fix the first CHECK after the tip move fails (the refund has no attempt). */
static void e20_expired_payout_does_not_hold_refunds(void) {
    printf("E20 an expired payout that cannot be replaced does not hold a later refund\n");
    env_t e;
    env_open(&e);
    W.ncoins = 2;
    W.coin_seed[0] = 7;  W.coin_amt[0] = 1000000000000000ULL;
    W.coin_seed[1] = 90; W.coin_amt[1] = 500000000000000ULL;
    amm_quote_answer_t a, b;
    amm_engine_step_t o;
    amm_swap_t p, r;
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));

    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval of the USDT -> NODUS swap P");
    amm_req_usdt_t ur = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &ur, NULL) == AMM_ACC_RECEIVED, "signed request");
    put_rec(&e, 0x12, 1001, 0xaa, 100000000ULL, "deep");
    CHECK(step(&e, &o) == 0 && o.decided == 1 && swap_of(&e, a.request_number, &p) &&
          !strcmp(p.state, "payout_pending"), "P is decided to a payout");
    CHECK(amm_journal_attempt_latest(e.j, p.seq, &at) == 0 && att_has_seed(&at, 7) && !att_has_seed(&at, 90),
          "its attempt spends the largest coin (seed 7)");
    amm_attempt_free(&at);

    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK, "approval of the NODUS -> USDT swap R");
    amm_req_nodus_to_usdt_t nr = nodus_req(&b, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED && swap_of(&e, b.request_number, &r) &&
          seen_counted(&e, &r, r.incoming_id) &&
          amm_journal_swap_transition(e.j, r.seq, "refund_pending", NULL, NULL, NULL) == 0 && r.seq > p.seq,
          "R (younger than P) is in refund_pending");
    CHECK(step(&e, &o) == 0 && amm_journal_attempt_latest(e.j, r.seq, &at) == 1,
          "P's attempt is live: R is not signed (one live attempt)");

    W.nodus_tip = 1100;                                  /* past P's expiry 1090 */
    W.gas = 100000;                                      /* the fee changes: P's replacement is refused */
    CHECK(step(&e, &o) == 0 && amm_journal_attempt_latest(e.j, p.seq, &at) == 0 && at.n == 1 &&
          !strcmp(at.state, "expired"), "P's attempt expired and no replacement was stored (changed fee)");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_latest(e.j, r.seq, &at) == 0 &&
          (!strcmp(at.state, "signed") || !strcmp(at.state, "submitted")),
          "(a) R is signed in the SAME round although the older P cannot be replaced");
    CHECK(att_has_seed(&at, 90) && !att_has_seed(&at, 7), "R is planned over the coin P does not hold (seed 90): seed 7 is reserved");
    amm_attempt_free(&at);
    CHECK(state_of(&e, a.request_number, "payout_pending"), "P waits, unchanged");

    /* R settles; with the decided fee again P's replacement is stored over its own coin */
    CHECK(amm_journal_attempt_finish(e.j, r.seq, "confirmed") == 0 &&
          amm_journal_swap_transition(e.j, r.seq, "refunded", NULL, NULL, NULL) == 0, "R settled");
    W.gas = 0;
    CHECK(step(&e, &o) == 0 && amm_journal_attempt_latest(e.j, p.seq, &at) == 0 && at.n == 2 &&
          att_has_seed(&at, 7), "next round: P's replacement is stored and spends the expired attempt's coin");
    amm_attempt_free(&at);
    env_close(&e);
}

/* ── E21 more waiting expired payouts than one round's bound ── */

/* A stored attempt with a fake envelope and one input (seed byte `tag`) that is
 * in no coin list of the node: its replacement can never be funded. */
static int fake_expired_attempt(env_t *e, const amm_swap_t *s, uint8_t tag) {
    amm_attempt_t a;
    memset(&a, 0, sizeof(a));
    a.swap_seq = s->seq;
    snprintf(a.dest, sizeof(a.dest), "%s", s->dest);
    a.gross = 1000000; a.fee = 100; a.net = a.gross - a.fee;
    a.env_len = 300;
    a.env = malloc(a.env_len);
    if (!a.env) return 0;
    memset(a.env, tag, a.env_len);
    memset(a.wire_id, tag, 64);
    memset(a.intent_id, (uint8_t)(tag ^ 0xff), 64);
    a.n_in = 1;
    memset(a.inputs[0], tag, 64);
    a.build_tip = 900; a.expiry = 990; a.scan_next = 901;
    int ok = amm_journal_attempt_sign(e->j, &a) == AMM_J_OK &&
             amm_journal_attempt_finish(e->j, s->seq, "expired") == 0;
    amm_attempt_free(&a);
    return ok;
}

/* PROVES (verify 13, claim 4): with MORE waiting expired payouts than one round's
 *   work bound (8 steps), a younger NODUS refund with funds is still signed within a
 *   bounded number of rounds (here <= 3): the walk resumes after the last deferred
 *   swap and wraps, it does not restart at the oldest swap every round. Without the
 *   cursor the refund is never reached (the same eight oldest swaps take every round).
 * FLAGS/ENVIRONMENT: a default build; nine USDT -> NODUS swaps put into
 *   payout_pending by journal calls with fake expired attempts (inputs in no coin
 *   list: "no longer unspent", the replacement is refused and the swap waits); the
 *   node lists one 10^15 coin. One mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the attempts are fake (the payer never verifies the old envelope, only
 *   its stored inputs, gross and expiry); a different cause of waiting (funds, a
 *   changed fee) goes through the same `waiting` flag, proved in E20 and P15. */
static void e21_many_waiting_do_not_starve(void) {
    printf("E21 more waiting expired payouts than one round's bound do not starve a later refund\n");
    env_t e;
    env_open(&e);
    amm_engine_step_t o;
    amm_swap_t s[9], r;
    amm_quote_answer_t a, b;
    for (int i = 0; i < 9; i++) {
        char key[24];
        snprintf(key, sizeof(key), "eth:w%d", i);
        CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 1000000ULL, 0, &a) == AMM_Q_OK, "approval");
        /* the sender is 40 HEX characters: nine distinct hex digits (a letter past 'f' is not an address) */
        amm_req_usdt_t ur = usdt_req(&a, "abcdef012"[i], 1);
        CHECK(amm_engine_accept_usdt(e.eng, &ur, &s[i]) == AMM_ACC_RECEIVED &&
              seen_counted(&e, &s[i], key) &&
              amm_journal_swap_transition(e.j, s[i].seq, "payout_pending", NULL, NULL, NULL) == 0 &&
              amm_journal_swap_by_seq(e.j, s[i].seq, &s[i]) == 0 &&
              fake_expired_attempt(&e, &s[i], (uint8_t)(0x40 + i)),
              "a payout in payout_pending with an expired attempt");
    }
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK, "approval of the refund swap R");
    amm_req_nodus_to_usdt_t nr = nodus_req(&b, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED && swap_of(&e, b.request_number, &r) &&
          seen_counted(&e, &r, r.incoming_id) &&
          amm_journal_swap_transition(e.j, r.seq, "refund_pending", NULL, NULL, NULL) == 0 && r.seq > s[8].seq,
          "R (younger than all nine) is in refund_pending");
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    int rounds = 0, signed_r = 0;
    for (int k = 0; k < 3 && !signed_r; k++) {
        CHECK(step(&e, &o) == 0, "a round");
        rounds++;
        signed_r = amm_journal_attempt_latest(e.j, r.seq, &at) == 0;
        if (signed_r) amm_attempt_free(&at);
    }
    CHECK(signed_r, "R is signed within three rounds");
    printf("  info  R signed after %d round(s)\n", rounds);
    CHECK(rounds >= 2, "R was NOT reached in the first round: nine waiting payouts exceed the 8 steps of one round (the cursor is what reaches it)");
    for (int i = 0; i < 9; i++) {
        amm_swap_t g;
        CHECK(amm_journal_swap_by_seq(e.j, s[i].seq, &g) == 0 && !strcmp(g.state, "payout_pending") &&
              amm_journal_attempt_latest(e.j, s[i].seq, &at) == 0 && at.n == 1, "a waiting payout is unchanged");
        amm_attempt_free(&at);
    }
    env_close(&e);
}

/* ── E22 the limit on open unpaid questions (givens item 98) ── */

/* PROVES: with quote_open_max = 3 and three open questions (two price questions and
 *   one liquidity add question) the next price question, in either direction, and the
 *   next liquidity question are answered BUSY and no node or provider seam was called
 *   for them (W.reads unchanged) and nothing was written; a signed request for an open
 *   question is still accepted at the limit, its payment is seen and decided to a
 *   payout (the limit never refuses signed requests, payments, decisions or payouts);
 *   once that swap holds a payment it is no longer an open question and a new question
 *   is answered again.
 * FLAGS/ENVIRONMENT: a default build; quote_open_max 3 through the settings copy; the
 *   scripted world W; one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: "no read" is counted at the stubs the engine is wired to (node ruleset,
 *   balance, gas, Ethereum balance, gas estimate, gas price, price): a read through
 *   another seam would not be counted; the check inside the journal's insert (the same
 *   limit, repeated in the approval's transaction) is proved in test_amm_journal J28. */
static void e22_open_question_limit(void) {
    printf("E22 the limit on open unpaid questions\n");
    env_t e;
    env_open(&e);
    e.cfg.quote_open_max = 3;
    env_restart(&e);
    amm_quote_answer_t a1, a2, qx;
    amm_add_answer_t aa, ax;
    amm_engine_step_t o;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a1) == AMM_Q_OK &&
          amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a2) == AMM_Q_OK &&
          amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK,
          "three open questions: two price questions and one liquidity add question");
    int64_t open = 0;
    CHECK(amm_journal_open_questions(e.j, &open) == 0 && open == 3, "the journal counts three");
    const int reads = W.reads;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &qx) == AMM_Q_BUSY &&
          amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &qx) == AMM_Q_BUSY,
          "at the limit a price question, either direction, is answered busy");
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &ax) == AMM_AQ_BUSY &&
          amm_engine_add_question(e.eng, AMM_SIDE_USDT, 10000000ULL, 0, &ax) == AMM_AQ_BUSY,
          "and so is a liquidity question");
    CHECK(W.reads == reads, "no node or provider read was made for the refused questions");
    CHECK(amm_journal_open_questions(e.j, &open) == 0 && open == 3, "nothing was written");

    /* (b) a paid swap is still decided and paid while the questions are at the limit */
    amm_req_usdt_t ur = usdt_req(&a1, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &ur, NULL) == AMM_ACC_RECEIVED,
          "a signed request for an open question is accepted at the limit");
    put_rec(&e, 0x12, 1001, 0xaa, 100000000ULL, "deep");
    amm_swap_t s;
    CHECK(step(&e, &o) == 0 && o.decided == 1 && swap_of(&e, a1.request_number, &s) &&
          !strcmp(s.state, "payout_pending"), "its payment is decided to a payout at the limit");
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_journal_attempt_latest(e.j, s.seq, &at) == 0 && at.net > 0, "and its payout is signed");
    amm_attempt_free(&at);
    CHECK(amm_journal_open_questions(e.j, &open) == 0 && open == 2, "the swap with a payment is no longer an open question");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &qx) == AMM_Q_OK,
          "a question is answered again");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &qx) == AMM_Q_BUSY, "and the limit holds again");
    env_close(&e);
}

/* ── E23 unused expired questions are deleted ── */

/* PROVES: an unused expired price question and an unused expired add question are
 *   deleted by the round after the one that expired them (bounded by round_rows_max);
 *   a signed row that expired stays; the deleted questions' bot request numbers are
 *   marked: a redraw of the same number is refused (the next answer carries another
 *   number), also after a restart; a signed request carrying a deleted question's
 *   number is refused as expired (as for an expired one); the (sender, request
 *   number) of a signed row still refuses reuse; a payment that arrives later is held
 *   and matches nothing, for the retained expired row and the deleted question alike.
 * FLAGS/ENVIRONMENT: a default build; the request-number draws are scripted through
 *   the world's rq list (the test seam that already fixes the 32-bit draw); the
 *   questions are expired through journal calls (the window rule that does it in a
 *   round is E7 and E18); one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: a payment for an unsigned question can never match it (there is no
 *   sender to match), so the "payment later" check shows the record is held, as for
 *   the retained signed row, not a new matching path. */
static void e23_expired_questions_deleted(void) {
    printf("E23 unused expired questions are deleted, their numbers stay used\n");
    env_t e;
    env_open(&e);
    amm_engine_step_t o;
    amm_quote_answer_t u, s;
    amm_add_answer_t aa;
    amm_swap_t su, ss;
    W.rq[0] = 777; W.rq_n = 1; W.rq_i = 0;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &u) == AMM_Q_OK && u.request_number == 777,
          "an unsigned price question with the number 777");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &s) == AMM_Q_OK, "a second price question");
    amm_req_usdt_t sr = usdt_req(&s, 'b', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &sr, &ss) == AMM_ACC_RECEIVED, "signed (sender b): it carries a sender and a (sender, number) marker");
    W.rq[0] = 4242; W.rq_n = 1; W.rq_i = 0;
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK && aa.request_number == 4242,
          "an unsigned add question with the number 4242");
    amm_add_t ad;
    CHECK(swap_of(&e, 777, &su) && amm_journal_add_by_botreq(e.j, 4242, &ad) == 0, "both rows exist");
    CHECK(amm_journal_swap_transition(e.j, su.seq, "expired", NULL, NULL, NULL) == 0 &&
          amm_journal_swap_transition(e.j, ss.seq, "expired", NULL, NULL, NULL) == 0 &&
          amm_journal_add_expire(e.j, ad.seq) == 0, "the unsigned swap, the signed swap and the add are expired");

    CHECK(step(&e, &o) == 0 && o.questions_deleted == 2, "the round deletes the two unused expired questions");
    CHECK(!swap_of(&e, 777, &su) && amm_journal_add_by_botreq(e.j, 4242, &ad) == 1, "they are gone");
    CHECK(state_of(&e, s.request_number, "expired"), "the signed expired row stays");
    CHECK(amm_journal_bot_req_used(e.j, 0, 777) == 0 && amm_journal_bot_req_used(e.j, 1, 4242) == 0 &&
          amm_journal_bot_req_used(e.j, 0, 4242) == 1, "their numbers are marked used (per kind)");

    /* the numbers are not given out again: the redraw takes the next scripted number */
    /* a scripted draw takes the swap id's randomness from W.rng without advancing it: bump
     * W.rng before each scripted quote so two scripted quotes never share an id (swaps.id is unique) */
    W.rng += 0x9E3779B97F4A7C15ULL;
    W.rq[0] = 777; W.rq[1] = 5000; W.rq_n = 2; W.rq_i = 0;
    amm_quote_answer_t n1;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &n1) == AMM_Q_OK && n1.request_number == 5000,
          "a draw of 777 again is refused and redrawn: the new question carries 5000");
    W.rq[0] = 4242; W.rq[1] = 6000; W.rq_n = 2; W.rq_i = 0;
    amm_add_answer_t n2;
    CHECK(amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &n2) == AMM_AQ_OK && n2.request_number == 6000,
          "a draw of 4242 again is refused and redrawn: the new add question carries 6000");

    /* a signed request for a deleted question, and the retained (sender, number) */
    amm_quote_answer_t old_q;
    memset(&old_q, 0, sizeof(old_q));
    old_q.request_number = 777; old_q.amount = 100000000ULL;
    amm_req_usdt_t old_r = usdt_req(&old_q, 'c', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &old_r, NULL) == AMM_ACC_EXPIRED,
          "a signed request carrying the deleted question's number is refused as expired");
    amm_req_liq_add_t old_add = add_req(&aa, 'a', 'c', 'a');
    CHECK(amm_engine_accept_add(e.eng, &old_add, NULL) == AMM_ACC_EXPIRED,
          "so is a signed pair for the deleted add question");
    CHECK(amm_engine_accept_usdt(e.eng, &sr, NULL) != AMM_ACC_RECEIVED,
          "the retained signed row's request is not accepted again (its sender and number are still used)");

    /* a later payment is held, for the kept expired row and for the deleted question alike */
    put_rec(&e, 0x31, 1001, 0xbb, 100000000ULL, "deep");     /* sender b, the kept row's amount */
    put_rec(&e, 0x32, 1002, 0xaa, 100000000ULL, "deep");     /* the deleted question's amount   */
    CHECK(step(&e, &o) == 0 && o.matched == 0 && o.held_records == 2,
          "both payments match no approval and are held, exactly as for an expired question today");

    /* a restart keeps the markers */
    env_restart(&e);
    W.rng += 0x9E3779B97F4A7C15ULL;                  /* see above: a distinct swap id */
    W.rq[0] = 777; W.rq[1] = 7000; W.rq_n = 2; W.rq_i = 0;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &n1) == AMM_Q_OK && n1.request_number == 7000,
          "after a restart 777 is still not given out");
    CHECK(amm_engine_accept_usdt(e.eng, &old_r, NULL) == AMM_ACC_EXPIRED,
          "after a restart the signed request for the deleted question is still refused as expired");
    env_close(&e);
}

/* ── E24 shared reads of the question path ── */

/* PROVES: two price questions within quote_read_fresh_ms make ONE set of Ethereum
 *   provider reads (balance, gas estimate, gas price) and two Nodus-side questions one
 *   Nodus balance read; after the bound the reads are made again; a DECISION made while
 *   the shared reads are fresh still reads the providers itself.
 * FLAGS/ENVIRONMENT: a default build; the engine's monotonic clock is the world's
 *   (W.mono, stepped by the test, mono_step 0); quote_read_fresh_ms is the default
 *   3000; one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the reads are counted at the provider and node stubs; the decision
 *   check proves the decision's reads happen, not that its numbers differ (a changed
 *   balance in between is the refusal tests E1/E17). */
static void e24_shared_reads(void) {
    printf("E24 the question path reuses its provider reads for a short time\n");
    env_t e;
    env_open(&e);
    W.mono_step = 0;
    W.mono = 1000;
    amm_quote_answer_t a, b;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK && W.prov_reads > 0,
          "the first NODUS -> USDT question reads the providers");
    const int r1 = W.prov_reads;
    W.mono = 2000;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK &&
          W.prov_reads == r1 && b.est_fee == a.est_fee,
          "a second one 1000 ms later makes no provider read and shows the same estimated fee");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK && W.nbal_reads == 1,
          "the first USDT -> NODUS question reads the Nodus balance once");
    W.mono = 2500;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK && W.nbal_reads == 1,
          "the next one within the bound reads it no more");
    W.mono = 5000;                                   /* 4000 ms after the first read: past the bound */
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK && W.prov_reads == 2 * r1 &&
          amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &b) == AMM_Q_OK && W.nbal_reads == 2,
          "past the bound both are read again");

    /* a decision reads the providers itself while the shared reads are fresh */
    amm_quote_answer_t d;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &d) == AMM_Q_OK, "a question (fresh reads)");
    amm_req_nodus_to_usdt_t nr = nodus_req(&d, 'f', 1);
    amm_swap_t s;
    CHECK(amm_engine_accept_nodus(e.eng, &nr, &s) == AMM_ACC_RECEIVED && swap_of(&e, d.request_number, &s) &&
          seen_counted(&e, &s, s.incoming_id), "signed and counted");
    const int before = W.prov_reads;
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.decided == 1 && W.prov_reads > before,
          "the decision made its own provider reads although the shared ones were fresh");
    env_close(&e);
}

/* ── E25 bounded walks ── */

/* PROVES: with round_rows_max = 3 the release walk examines at most 3 open approved
 *   swaps per round and the add walks at most 3 add rows each, and ten approved swaps
 *   and five approved adds are all examined (and expire) over successive rounds: the
 *   walk resumes after the last row examined and begins again at the oldest at the end.
 * FLAGS/ENVIRONMENT: a default build; round_rows_max 3 through the settings copy; the
 *   window of both chains is made observed through the journal cursors and a stored
 *   block (as E7, E18); one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: `rows_examined` / `adds_examined` are the engine's own counters of the
 *   rows it walked; the expiry of every row (checked through the journal, not the
 *   counters) is what shows no row was skipped. */
static void e25_bounded_walks(void) {
    printf("E25 the per-round walks examine a bounded number of rows and resume\n");
    env_t e;
    env_open(&e);
    e.cfg.round_rows_max = 3;
    env_restart(&e);
    amm_quote_answer_t q[10];
    int ok = 1;
    for (int i = 0; i < 10 && ok; i++)
        ok = amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &q[i]) == AMM_Q_OK;
    amm_add_answer_t aa;
    for (int i = 0; i < 5 && ok; i++)
        ok = amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa) == AMM_AQ_OK;
    CHECK(ok, "ten approved swaps and five approved adds");
    W.now = 10301;
    amm_journal_cursor_reset(e.j, "nodus_scan", 1000);
    amm_journal_cursor_reset(e.j, "nodus_scan_ts", 10400);
    amm_blk_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.height = 990; blk.ts = 10400; memset(blk.hash, 5, 32); memset(blk.parent, 4, 32);
    amm_journal_block_put(e.j, &blk);
    amm_journal_cursor_reset(e.j, "eth_scan", 995);
    amm_engine_step_t o;
    int swaps_expired = 0, adds_expired = 0, bounded = 1, rounds = 0;
    for (int r = 0; r < 8 && (swaps_expired < 10 || adds_expired < 5); r++) {
        CHECK(step(&e, &o) == 0, "a round");
        rounds++;
        if (o.rows_examined > 3 || o.adds_examined > 3) bounded = 0;   /* only the approved-add walk has rows */
        swaps_expired += o.expired;
        adds_expired += o.adds_expired;
    }
    CHECK(bounded, "no round examined more than 3 swaps or 3 add rows");
    CHECK(swaps_expired == 10 && adds_expired == 5, "every swap and every add was examined and expired");
    printf("  info  all rows expired after %d rounds\n", rounds);
    CHECK(rounds >= 4, "(ten swaps at three per round need at least four rounds: the bound is real)");
    env_close(&e);
}

/* ── E26 a refund that cannot be stored does not hold a younger expired payout ── */

/* PROVES (verify 14, claim 7): an OLDER NODUS refund R whose first attempt cannot be
 *   stored (the bot's only coin is short of it, and that coin is also the reserved input
 *   of the younger payout's expired attempt) is deferred, and the younger expired payout P,
 *   whose replacement is funded from its own reserved coin, is replaced in the same round
 *   (so within ONE round after the expiry); R stays refund_pending with no attempt.
 *   With the old `if (sr != AMM_NP_OK) break;` the round ends at R and P is never replaced
 *   (checked by reading: the check "P's replacement is stored" needs the loop to go on
 *   past R's FUNDS refusal).
 * FLAGS/ENVIRONMENT: a default build; one scripted coin of 9.9*10^13 raw (the payout's
 *   gross 9.365*10^13 fits, the refund's 10^14 does not); tip 1000 -> 1100, expiry 1090,
 *   gas 0 (the replacement's fee equals the decided one); one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the shortage of R is the scripted coin list, not a real node's; R is short
 *   even without the reservation (10^14 > the coin), so the test proves the deferral, and
 *   the reservation is proved in E20/P15. */
static void e26_unfunded_refund_is_deferred(void) {
    printf("E26 a refund that cannot be stored is deferred, a younger expired payout is replaced\n");
    env_t e;
    env_open(&e);
    W.ncoins = 1;
    W.coin_seed[0] = 7; W.coin_amt[0] = 99000000000000ULL;
    amm_quote_answer_t b, a;
    amm_engine_step_t o;
    amm_swap_t r, p;
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK, "approval of the refund swap R");
    amm_req_nodus_to_usdt_t nr = nodus_req(&b, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED && swap_of(&e, b.request_number, &r) &&
          seen_counted(&e, &r, r.incoming_id) &&
          amm_journal_swap_transition(e.j, r.seq, "refund_pending", NULL, NULL, NULL) == 0,
          "R (older) is in refund_pending");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval of the payout swap P");
    amm_req_usdt_t ur = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &ur, NULL) == AMM_ACC_RECEIVED, "signed request");
    put_rec(&e, 0x12, 1001, 0xaa, 100000000ULL, "deep");
    CHECK(step(&e, &o) == 0 && o.decided == 1 && swap_of(&e, a.request_number, &p) && p.seq > r.seq &&
          amm_journal_attempt_latest(e.j, p.seq, &at) == 0 && at.n == 1, "P (younger) is decided and its payout signed over the coin");
    amm_attempt_free(&at);
    CHECK(amm_journal_attempt_latest(e.j, r.seq, &at) == 1, "P's attempt is live: R has none");
    W.nodus_tip = 1100;                                  /* past P's expiry 1090 */
    int stored = 0;
    for (int k = 0; k < 3 && !stored; k++) {            /* bounded: expected in the first round */
        CHECK(step(&e, &o) == 0, "a round");
        if (amm_journal_attempt_latest(e.j, p.seq, &at) == 0) {
            stored = at.n == 2;
            amm_attempt_free(&at);
        }
    }
    CHECK(stored, "P's replacement is stored within three rounds (past R's refusal)");
    CHECK(amm_journal_attempt_latest(e.j, p.seq, &at) == 0 && at.n == 2 && att_has_seed(&at, 7),
          "it spends P's own reserved coin");
    amm_attempt_free(&at);
    CHECK(state_of(&e, b.request_number, "refund_pending") && amm_journal_attempt_latest(e.j, r.seq, &at) == 1,
          "R stays refund_pending with no attempt");
    env_close(&e);
}

/* ── E27 only the stored cursor reaches the later rows ── */

/* PROVES (verify 14, claim 8): with round_rows_max = 3 and SIX open rows of each kind
 *   whose first three are NOT yet expirable (their window is not observed) and whose last
 *   three are, the first round examines and expires nothing, and the second round expires
 *   the last three: only the resumed cursor (release_after, adds_after) brings the walk to
 *   them. If the cursor were reset to 0 every round (the property removed), rounds 1 and 2
 *   would both examine the first three rows and the checks after round 2 fail (read: both
 *   walks restart at `after = e->release_after` / `e->adds_after[sti]`, which would stay 0).
 * FLAGS/ENVIRONMENT: a default build; round_rows_max 3; the first three rows of each kind
 *   are asked at W.now 30000 (expiry 30300), the last three at 10000 (expiry 10300); the
 *   Nodus history is processed to a block time 10400 and a stored Ethereum block of time
 *   10400 closes the Ethereum window, so only the 10300 rows are expirable; one mkdtemp
 *   directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the order of the rows is the order of their questions (seq); a different
 *   walk order would need other row times. */
static void e27_only_the_cursor_reaches_later_rows(void) {
    printf("E27 later open rows are reached only through the resumed cursor\n");
    env_t e;
    env_open(&e);
    e.cfg.round_rows_max = 3;
    env_restart(&e);
    amm_quote_answer_t q[6];
    amm_add_answer_t aa[6];
    int ok = 1;
    for (int i = 0; i < 6 && ok; i++) {
        W.now = i < 3 ? 30000 : 10000;
        ok = amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &q[i]) == AMM_Q_OK &&
             amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &aa[i]) == AMM_AQ_OK;
    }
    CHECK(ok, "six swaps and six adds, the first three of each far from expiry");
    amm_journal_cursor_reset(e.j, "nodus_scan", 1000);
    amm_journal_cursor_reset(e.j, "nodus_scan_ts", 10400);
    amm_blk_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.height = 990; blk.ts = 10400; memset(blk.hash, 5, 32); memset(blk.parent, 4, 32);
    amm_journal_block_put(e.j, &blk);
    amm_journal_cursor_reset(e.j, "eth_scan", 995);
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.expired == 0 && o.adds_expired == 0 && o.rows_examined == 3 && o.adds_examined == 3,
          "round 1 examines the first three rows of each kind: nothing is expirable");
    CHECK(step(&e, &o) == 0 && o.expired == 3 && o.adds_expired == 3 && o.rows_examined == 3 && o.adds_examined == 3,
          "round 2 examines the next three: they expire (only the cursor got there)");
    CHECK(state_of(&e, q[3].request_number, "expired") && state_of(&e, q[5].request_number, "expired") &&
          state_of(&e, q[0].request_number, "approved") && state_of(&e, q[2].request_number, "approved"),
          "the swaps 4-6 expired, 1-3 still open");
    amm_add_t ad;
    CHECK(amm_journal_add_by_botreq(e.j, aa[4].request_number, &ad) == 0 && !strcmp(ad.state, "expired") &&
          amm_journal_add_by_botreq(e.j, aa[1].request_number, &ad) == 0 && !strcmp(ad.state, "approved"),
          "the adds 4-6 expired, 1-3 still open");
    env_close(&e);
}

/* ── E28 a failed question read is not reused ── */

/* PROVES (verify 14): a question whose provider read (every provider's USDT balance) or
 *   Nodus balance read FAILS is answered unavailable and the failure is not stored: a
 *   second question inside quote_read_fresh_ms reads again (the seam call count grows);
 *   once the read works it is stored and the next question inside the bound reads nothing.
 * FLAGS/ENVIRONMENT: a default build; the monotonic clock is fixed (mono_step 0, 1000 ms);
 *   the failure is W.erc20_fail / W.nodus_balance_rc; one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: if a failed read were stored as valid, the second question would answer from
 *   the stored value and the counts would not grow: this is what the checks exclude. */
static void e28_failed_read_not_reused(void) {
    printf("E28 a failed question read is not reused\n");
    env_t e;
    env_open(&e);
    W.mono_step = 0;
    W.mono = 1000;
    amm_quote_answer_t a;
    W.erc20_fail = 1;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_UNAVAILABLE, "provider read fails: unavailable");
    int r1 = W.prov_reads;
    CHECK(r1 > 0 && amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_UNAVAILABLE &&
          W.prov_reads > r1, "a second question inside the bound reads the providers again");
    W.erc20_fail = 0;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK && W.prov_reads > r1,
          "the read works again: answered, read made");
    const int r3 = W.prov_reads;
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &a) == AMM_Q_OK && W.prov_reads == r3,
          "and now it is reused inside the bound");

    W.nodus_balance_rc = AMM_NODE_ERR;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_UNAVAILABLE && W.nbal_reads == 1,
          "the Nodus balance read fails: unavailable");
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_UNAVAILABLE && W.nbal_reads == 2,
          "a second question inside the bound reads it again");
    W.nodus_balance_rc = 0;
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK && W.nbal_reads == 3 &&
          amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK && W.nbal_reads == 3,
          "read once it works, then reused");
    env_close(&e);
}

/* A USDT -> NODUS swap in payout_pending with a fake expired attempt (as E21). */
static int mk_expired_payout(env_t *e, int i, amm_swap_t *s) {
    char key[24];
    amm_quote_answer_t a;
    snprintf(key, sizeof(key), "eth:p%d", i);
    if (amm_engine_quote(e->eng, AMM_USDT_TO_NODUS, 1000000ULL, 0, &a) != AMM_Q_OK) return 0;
    amm_req_usdt_t ur = usdt_req(&a, "abcdef012"[i], 1);
    return amm_engine_accept_usdt(e->eng, &ur, s) == AMM_ACC_RECEIVED && seen_counted(e, s, key) &&
           amm_journal_swap_transition(e->j, s->seq, "payout_pending", NULL, NULL, NULL) == 0 &&
           amm_journal_swap_by_seq(e->j, s->seq, s) == 0 && fake_expired_attempt(e, s, (uint8_t)(0x40 + i));
}

/* ── E29 paused payouts: nothing is signed or broadcast ── */

/* PROVES (verify 15): with payouts_paused a round over three owed payouts with expired
 *   attempts and a NODUS refund with no attempt signs nothing and broadcasts nothing (no
 *   attempt is stored for the refund, no payout gets an attempt 2, W.submits unchanged).
 *   The "stops at the first paused step" half is test_amm_nodus_pay P17 (a paused replacement
 *   is not `waiting`); the settlement scan of a live attempt while paused is the existing
 *   P11 ("... but the settlement scan continues", "... and settles a payout found on chain").
 * FLAGS/ENVIRONMENT: a default build; the payer is paused through the settings copy
 *   (e->npc.payouts_paused follows cfg.payouts_paused); one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the engine round's own number of payer steps is not observable from outside;
 *   P17 pins the flag the engine's stop depends on. */
static void e29_paused_signs_nothing(void) {
    printf("E29 payouts paused: nothing is signed or broadcast\n");
    env_t e;
    env_open(&e);
    amm_swap_t s[3], r;
    amm_quote_answer_t b;
    amm_engine_step_t o;
    int ok = 1;
    for (int i = 0; i < 3 && ok; i++) ok = mk_expired_payout(&e, i, &s[i]);
    CHECK(ok, "three payouts with expired attempts");
    CHECK(amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &b) == AMM_Q_OK, "approval of a refund swap");
    amm_req_nodus_to_usdt_t nr = nodus_req(&b, 'f', 1);
    CHECK(amm_engine_accept_nodus(e.eng, &nr, NULL) == AMM_ACC_RECEIVED && swap_of(&e, b.request_number, &r) &&
          seen_counted(&e, &r, r.incoming_id) &&
          amm_journal_swap_transition(e.j, r.seq, "refund_pending", NULL, NULL, NULL) == 0, "R in refund_pending, no attempt");
    e.cfg.payouts_paused = 1;
    env_restart(&e);
    const int submits = W.submits;
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    for (int k = 0; k < 2; k++) CHECK(step(&e, &o) == 0, "a paused round");
    CHECK(W.submits == submits, "nothing was broadcast");
    CHECK(amm_journal_attempt_latest(e.j, r.seq, &at) == 1, "no attempt was stored for the refund");
    int same = 1;
    for (int i = 0; i < 3; i++) {
        same = same && amm_journal_attempt_latest(e.j, s[i].seq, &at) == 0 && at.n == 1 && !strcmp(at.state, "expired");
        amm_attempt_free(&at);
    }
    CHECK(same, "no payout got a replacement");
    env_close(&e);
}

/* ── E30 the payout walk wraps ── */

/* PROVES (verify 15): a payout deferred in one round (its replacement is not possible:
 *   its coin is not in the node's list) is served again in a LATER round after the cursor
 *   has moved past it: the next round starts after it, finds nothing beyond, wraps to the
 *   oldest owed swap and stores the replacement as soon as the coin is back (here in the
 *   first round after the coin returns; the test allows three). With the wrap branch
 *   (`if (st.swap_seq == 0 && after > 0 && !wrapped)`) removed, every later round starts at
 *   the saved cursor, finds nothing and never revisits the swap: the check fails.
 * FLAGS/ENVIRONMENT: a default build; scripted coin list (seed 7 = the payout's coin, seed 90
 *   = another); tip 1000 -> 1100 (expiry 1090); gas 0; one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: "the coin returns" is the scripted list; a real node's change of unspent set
 *   is not exercised. */
static void e30_payout_walk_wraps(void) {
    printf("E30 a deferred payout is served again after the walk wraps\n");
    env_t e;
    env_open(&e);
    W.ncoins = 1;
    W.coin_seed[0] = 7; W.coin_amt[0] = 1000000000000000ULL;
    amm_quote_answer_t a;
    amm_engine_step_t o;
    amm_swap_t p;
    amm_attempt_t at;
    memset(&at, 0, sizeof(at));
    CHECK(amm_engine_quote(e.eng, AMM_USDT_TO_NODUS, 100000000ULL, 0, &a) == AMM_Q_OK, "approval");
    amm_req_usdt_t ur = usdt_req(&a, 'a', 1);
    CHECK(amm_engine_accept_usdt(e.eng, &ur, NULL) == AMM_ACC_RECEIVED, "signed request");
    put_rec(&e, 0x12, 1001, 0xaa, 100000000ULL, "deep");
    CHECK(step(&e, &o) == 0 && o.decided == 1 && swap_of(&e, a.request_number, &p), "decided, signed over coin 7");
    W.nodus_tip = 1100;
    W.coin_seed[0] = 90;                                 /* coin 7 is gone from the node's list */
    CHECK(step(&e, &o) == 0 && amm_journal_attempt_latest(e.j, p.seq, &at) == 0 && at.n == 1 &&
          !strcmp(at.state, "expired"), "round 1: the attempt expires and its replacement cannot be stored (deferred)");
    amm_attempt_free(&at);
    W.coin_seed[0] = 7;                                  /* the coin is back */
    int stored = 0;
    for (int k = 0; k < 3 && !stored; k++) {
        CHECK(step(&e, &o) == 0, "a later round");
        if (amm_journal_attempt_latest(e.j, p.seq, &at) == 0) {
            stored = at.n == 2 && att_has_seed(&at, 7);
            amm_attempt_free(&at);
        }
    }
    CHECK(stored, "the deferred payout is replaced after the wrap, over its own coin");
    env_close(&e);
}

/* ── E31 the maintenance walks start again at the oldest row ── */

/* PROVES (verify 15): with round_rows_max = 3 and FOUR open rows of each kind whose window
 *   is not yet observed, round 1 examines rows 1-3 and round 2 row 4 (the end of the list:
 *   the cursor goes back to 0); the window is then observed, and round 3 examines rows 1-3
 *   AGAIN and expires them: 3 swaps (release walk), 3 unsigned adds (approved-add walk) and
 *   3 signed adds (signed-add expiry walk, the third one) = 6 adds. With the end-of-list reset
 *   (`if (n < lim) { after = 0; break; }`) removed from those walks the cursor stays behind row
 *   4, round 3 examines nothing and the checks fail.
 * FLAGS/ENVIRONMENT: a default build; round_rows_max 3; all rows asked at W.now 30000
 *   (expiry 30300); the windows are observed only after round 2 (Nodus history to block time
 *   40000, a stored Ethereum block of time 40000); one mkdtemp directory.
 * LEAVES BEHIND: nothing.
 * FALSE PASS: the signed adds carry no deposit (none are matched), which is what makes the
 *   third walk expire them; the signed-add LINKING walk shares the same reset code. */
static void e31_maintenance_walks_wrap(void) {
    printf("E31 rows behind the cursor are examined again after the end-of-list reset\n");
    env_t e;
    env_open(&e);
    e.cfg.round_rows_max = 3;
    env_restart(&e);
    amm_quote_answer_t q[4];
    amm_add_answer_t ua[4], sa[4];
    int ok = 1;
    W.now = 30000;
    for (int i = 0; i < 4 && ok; i++)
        ok = amm_engine_quote(e.eng, AMM_NODUS_TO_USDT, 100000000000000ULL, 0, &q[i]) == AMM_Q_OK &&
             amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &ua[i]) == AMM_AQ_OK;
    for (int i = 0; i < 4 && ok; i++) {
        char c = "abcd"[i];
        amm_req_liq_add_t lr;
        ok = amm_engine_add_question(e.eng, AMM_SIDE_NODUS, 10000000000000ULL, 0, &sa[i]) == AMM_AQ_OK;
        lr = add_req(&sa[i], c, c, c);
        ok = ok && amm_engine_accept_add(e.eng, &lr, NULL) == AMM_ACC_RECEIVED;
    }
    CHECK(ok, "four swaps, four unsigned adds and four signed adds, none expirable yet");
    amm_engine_step_t o;
    CHECK(step(&e, &o) == 0 && o.expired == 0 && o.adds_expired == 0 && o.rows_examined == 3, "round 1: rows 1-3 examined, nothing expirable");
    CHECK(step(&e, &o) == 0 && o.expired == 0 && o.adds_expired == 0 && o.rows_examined == 1, "round 2: row 4 examined (the end: the cursors go back)");
    amm_journal_cursor_reset(e.j, "nodus_scan", 1000);
    amm_journal_cursor_reset(e.j, "nodus_scan_ts", 40000);
    amm_blk_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.height = 990; blk.ts = 40000; memset(blk.hash, 5, 32); memset(blk.parent, 4, 32);
    amm_journal_block_put(e.j, &blk);
    amm_journal_cursor_reset(e.j, "eth_scan", 995);
    CHECK(step(&e, &o) == 0 && o.expired == 3 && o.adds_expired == 6,
          "round 3: rows 1-3 of each walk are examined again and expire (3 swaps, 3 unsigned adds, 3 signed adds)");
    CHECK(state_of(&e, q[0].request_number, "expired") && state_of(&e, q[2].request_number, "expired") &&
          state_of(&e, q[3].request_number, "approved"), "swaps 1-3 expired, swap 4 not yet examined");
    env_close(&e);
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
    e14_room_line();
    e15_paging();
    e16_liquidity_add();
    e17_undecidable();
    e18_adds_paged_and_ordered();
    e19_swap_before_add();
    e20_expired_payout_does_not_hold_refunds();
    e21_many_waiting_do_not_starve();
    e22_open_question_limit();
    e23_expired_questions_deleted();
    e24_shared_reads();
    e25_bounded_walks();
    e26_unfunded_refund_is_deferred();
    e27_only_the_cursor_reaches_later_rows();
    e28_failed_read_not_reused();
    e29_paused_signs_nothing();
    e30_payout_walk_wraps();
    e31_maintenance_walks_wrap();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
