/**
 * test_amm_eth_pay.c -- the nodus-amm USDT payout and refund
 * (amm_eth_pay.c) against scriptable STUB providers behind the amm_eth.h seam
 * table, a STUB price behind amm_eth_price_t and a REAL journal; the
 * transaction encoder and the signer are the REAL ones (amm_eth_tx.c,
 * libsecp256k1 v0.8.0), so a stored transaction is a real signed
 * transaction.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 10 lines 263-272, section 17 write-ahead rule, section 19
 * "test_amm_eth_pay" line 393 and the fee lines of "test_amm_engine" line
 * 394; givens items 17, 34, 50, 52, 53, 58):
 *   E1  PERSISTED BEFORE BROADCAST: signing stores the transaction (hash,
 *       nonce, raw bytes) in the journal and broadcasts NOTHING; the
 *       broadcast happens in the next step, and at the moment a provider
 *       receives the bytes the journal already holds them (checked inside the
 *       stub's send call); the stored bytes are the transaction: chain id 1,
 *       to = the USDT contract, value 0, call data transfer(recipient, net),
 *       the nonce, gas and fees stored, and its signature recovers (ecrecover
 *       port) to the bot's address; the hash is keccak256 of the bytes;
 *   E2  RESTART BETWEEN STORE AND BROADCAST: the journal reopened and a NEW
 *       payer built, the step sends the SAME stored bytes (byte for byte), no
 *       estimate is asked again and no second attempt exists;
 *   E3  ESTIMATE FAILURE keeps the payout UNSENT and retried: a failing or
 *       reverting estimate (below the quorum), nothing stored, the swap
 *       unchanged; the same swap signs once the estimate answers again;
 *   E4  A STATUS-0 RECEIPT = FAILED SEND, at the final depth only: the
 *       attempt becomes `failed`, the swap stays, nothing is sent again; a
 *       receipt below the final depth changes nothing (status 1 or 0); a
 *       status-1 receipt at the final depth settles the swap in ONE
 *       transaction (payout -> paid, refund -> refunded);
 *       (a status-1 receipt of the stub carries the Transfer log the stored
 *       attempt would produce, see add_logs, unless a test says otherwise);
 *   E14 THE TRANSFER LOG (plan line 264): status 1 AND exactly one USDT
 *       Transfer log from the bot to the recipient with the value sent settles
 *       (payout and refund); no log, another recipient, two logs, more logs
 *       than the table keeps, another emitter, 31 bytes of data -> attempt and
 *       swap `unknown`, the journal then refuses approvals; a logged value
 *       below the value sent (the TetherToken fee shape, a second Transfer to
 *       the owner) -> swap `held`, attempt confirmed, the delivered value in
 *       the message; a held swap owes nothing more here;
 *   E15 THE DEPTH IS A JOINT VOTE (plan line 252): Q = 2, receipts from A and
 *       B at block 100, tips A = 102, B = 103, C = 103, depth 3: not settled
 *       (only B holds receipt and depth); A at 103: settled; receipts that
 *       differ in their logs have no quorum;
 *   E14b a Transfer log from the WRONG SENDER is unknown; an oversized logged
 *       value (2^64 + net) is held with its FULL 32-byte value as hex in the
 *       message; E15b receipts whose logs differ only in the whole-data digest
 *       are different receipts (no quorum);
 *   E16 THE GAS BUMP: (g x 125 + 99) / 100 rounds up (estimate 21001 ->
 *       26252, arithmetic in the test); an estimate above (UINT64_MAX - 99) /
 *       125 is UNKNOWN with nothing stored and the price never asked; exactly
 *       at the bound it does not wrap;
 *   E5  ORPHANED NONCE -> unknown: no receipt at the quorum and the confirmed
 *       nonce above the stored nonce -> attempt orphaned, swap `unknown`, and
 *       the journal then refuses new approvals (the bot stops); the confirmed
 *       nonce equal to the stored nonce is not an orphan;
 *   E6  BALANCE SHORT IS REFUSED before signing: USDT balanceOf minus the
 *       bot's own pending payouts (journal rows), and ether for gas
 *       (gas limit x max fee); nothing stored; the smallest answer of the
 *       providers is the balance;
 *   E7  FEE BELOW, AT AND ABOVE THE AMOUNT through the real flow and the
 *       ledger's saturating subtraction: fee < amount pays amount - fee;
 *       fee == amount - 1 pays 1; fee == amount and fee > amount sign and
 *       broadcast NOTHING: a payout moves to refund_pending (before any
 *       attempt), a refund is DROPPED (givens items 89, 90); the minimum is compared after the fee
 *       (net == minimum pays, net == minimum - 1 refunds, a minimum the gross
 *       would satisfy refunds); a pure table of amm_eth_pay_judge;
 *   E8  AN UNREADABLE PRICE IS NEVER ZERO: a price error leaves everything
 *       unsent and unchanged;
 *   E9  NONCE UNIQUENESS ACROSS A RESTART: nonce = max(Q-th largest pending
 *       count of the chain, the journal's highest stored nonce + 1), the
 *       second payout after a restart takes the next nonce though the chain
 *       still says 0; a higher chain count wins; the database refuses a
 *       duplicate hash or (chain, nonce);
 *   E10 THE FIXED POINT: the estimate depends on the call data, the call data
 *       on the net, the net on the fee: the stored gas limit is the stub's gas
 *       RAISED BY 25% ROUNDED UP (Boltz bumpGasLimit, EthereumUtils.ts:83-85;
 *       hand-computed rounds in the test) for the call data that is actually stored, the stored fee is the
 *       price for that gas, and the estimate was asked again after the first
 *       round; a case with no fixed point is UNKNOWN (unsent);
 *   E11 QUORUM: a provider on another chain id is not used; fewer usable
 *       providers than Q is UNKNOWN; receipts that disagree below Q are
 *       UNKNOWN; the tip and the counts are the Q-th largest answer; a
 *       broadcast goes to every usable provider, one acceptance is enough, a
 *       provider that answers another hash is not an acceptance, no
 *       acceptance leaves the attempt signed and the next step sends again;
 *   E12 payouts_paused: nothing is signed or broadcast, settlement continues;
 *       a submitted attempt is not rebroadcast;
 *   E13 guards: a swap that owes no USDT payout, a second sign of a swap, a
 *       zero gross, bad configurations are refused.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp
 *   (removed); no network. LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the providers' answers are scripted; a real node's mempool,
 *   its gas accounting and a chain reorganisation are not here. The stub's gas
 *   formula (base + 16 per non-zero byte of the amount) and fee formula are
 *   the test's own; the real conversion is DEFERRED with the price source.
 *   The signature is checked by the repository's ecrecover port, not by a
 *   node.
 */
#include <dirent.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_eth_pay.h"
#include "amm_eth_tx.h"
#include "amm_test_gate.h"
#include "crypto/hash/keccak256.h"
#include "evm/evm_internal.h"
#include "evm/trie/evm_trie_rlp.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── the stub providers ─────────────────────────────────────────────── */

/* the methods a group of the payer's helpers calls on every usable provider
 * (the gate and hold points of E18-E20) */
enum { PM_CHAIN, PM_TIP, PM_RCPT, PM_BAL, PM_ERC20, PM_EST, PM_N };

typedef struct {
    /* E18-E20 (plan 7.1.3): the stub's own index (the gate's provider index), an
     * optional gate per method, calls per method, and the optional hold: this
     * stub's hold_method calls wait until hold_ctr reaches hold_need per call
     * (the other providers' "unit done" counter, bumped by their unit_method
     * calls); hold_returned counts held calls that have returned. The gate and
     * counter objects are the test's; this struct only points at them. Each is
     * touched only by the thread that calls the stub (one provider's calls are
     * sequential) and by the test thread between steps. */
    int idx;
    amm_gate_t *gate[PM_N];
    int mcalls[PM_N];
    int hold_method, hold_need, hold_k;
    amm_ctr_t *hold_ctr;
    int unit_method;
    amm_ctr_t *unit_ctr;
    atomic_int hold_returned;
    uint64_t chain; int chain_rc;
    uint64_t tip; int tip_rc;
    uint64_t cnt_pending, cnt_latest; int cnt_rc;
    uint8_t  usdt[32], eth[32]; int usdt_rc, eth_rc;
    uint64_t gas_base; int gas_by_amount; uint64_t gas_per_nz; int est_rc; int est_calls;
    uint64_t gas_price, prio; int gp_rc, prio_rc;
    uint64_t base_fee; int bf_rc; int bf_calls;   /* the latest block's baseFeePerGas (eth_getBlockByNumber latest) */
    /* evm-fee work (E21-E27): a receipt for ONE transaction hash only (every other hash: no
     * receipt) and an error for ONE hash, so the attempts of a nonce group can be given
     * different receipts; est_cycle makes the estimate change at every call (no fixed point) */
    uint8_t  rc_only[32]; int rc_only_on;
    uint8_t  rc_err[32];  int rc_err_on;
    int      est_cycle;
    int      rc_mode;                 /* 0 no receipt, 1 found, 2 error        */
    amm_eth_receipt_t rc;
    int      log_mode;                /* what logs a status-1 receipt carries, see add_logs */
    int      rc_calls;
    int      send_rc; int send_wrong_hash; int send_calls;
    uint8_t  last_raw[512]; size_t last_raw_len;
} stub_t;

/* the send hook: runs inside the stub's send call with the bytes received */
static int (*g_on_send)(const uint8_t *raw, size_t n);

static void set_be(uint8_t o[32], uint64_t v) {
    memset(o, 0, 32);
    for (int i = 0; i < 8; i++) o[31 - i] = (uint8_t)(v >> (8 * i));
}

static int s_chain_impl(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->chain_rc) return s->chain_rc; *o = s->chain; return AMM_ETH_OK; }
static int s_tip_impl(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->tip_rc) return s->tip_rc; *o = s->tip; return AMM_ETH_OK; }
static void add_logs(stub_t *s, const uint8_t h[32], amm_eth_receipt_t *o);
static int s_receipt_impl(void *c, const uint8_t h[32], amm_eth_receipt_t *o, uint64_t d) {
    stub_t *s = c; (void)d;
    s->rc_calls++;
    if (s->rc_err_on && !memcmp(h, s->rc_err, 32)) return AMM_ETH_ERR;
    if (s->rc_only_on && memcmp(h, s->rc_only, 32) != 0) return AMM_ETH_NOT_FOUND;
    if (s->rc_mode == 2) return AMM_ETH_ERR;
    if (s->rc_mode == 0) return AMM_ETH_NOT_FOUND;
    *o = s->rc;
    if (o->status == 1) add_logs(s, h, o);
    return AMM_ETH_OK;
}
static int s_balance_impl(void *c, const uint8_t a[20], uint8_t o[32], uint64_t d) {
    stub_t *s = c; (void)d; (void)a;
    if (s->eth_rc) return s->eth_rc;
    memcpy(o, s->eth, 32);
    return AMM_ETH_OK;
}
static int s_erc20_impl(void *c, const uint8_t t[20], const uint8_t w[20], uint8_t o[32], uint64_t d) {
    stub_t *s = c; (void)d; (void)t; (void)w;
    if (s->usdt_rc) return s->usdt_rc;
    memcpy(o, s->usdt, 32);
    return AMM_ETH_OK;
}
static int s_count(void *c, const uint8_t a[20], int pending, uint64_t *o, uint64_t d) {
    stub_t *s = c; (void)d; (void)a;
    if (s->cnt_rc) return s->cnt_rc;
    *o = pending ? s->cnt_pending : s->cnt_latest;
    return AMM_ETH_OK;
}
static int nz_amount(const uint8_t *in, size_t n) {
    int k = 0;
    if (n >= 68) for (int i = 36; i < 68; i++) k += in[i] != 0;
    return k;
}
static int s_estimate_impl(void *c, const uint8_t f[20], const uint8_t t[20], const uint8_t *in,
                           size_t n, uint64_t *o, uint64_t d) {
    stub_t *s = c; (void)d; (void)f; (void)t;
    s->est_calls++;
    if (s->est_rc) return s->est_rc;                 /* "execution reverted" */
    if (s->est_cycle) { *o = s->gas_base + 1000ULL * (uint64_t)s->est_calls; return AMM_ETH_OK; }
    *o = s->gas_base + (s->gas_by_amount
        ? (s->gas_per_nz ? s->gas_per_nz : 16u) * (uint64_t)nz_amount(in, n) : 0);
    return AMM_ETH_OK;
}

/* The seam functions the providers expose: each runs the plain stub body
 * above between the optional gate (tests/amm_test_gate.h), the optional hold
 * (E19, E19b) and the per-method call counter. With no gate and no hold the
 * wrappers do nothing but count: no existing assertion changes. */
static const char *const PM_NAME[PM_N] = { "chain_id", "block_number", "get_receipt", "get_balance",
                                           "erc20_balance", "estimate_gas" };

/* wait (bounded) until the counter says the other providers' units are done */
static void st_hold(stub_t *s, int pm) {
    if (s->hold_method != pm || !s->hold_ctr) return;
    s->hold_k++;
    (void)amm_ctr_wait_ge(s->hold_ctr, s->hold_need * s->hold_k);
}

/* after the call: set this provider's "unit done" flag, count a held return */
static void st_after(stub_t *s, int pm) {
    if (s->unit_method == pm && s->unit_ctr) amm_ctr_inc(s->unit_ctr);
    if (s->hold_method == pm && s->hold_ctr) atomic_fetch_add(&s->hold_returned, 1);
}

#define ST_WRAP(PM, CALL)                                                    \
    stub_t *s = c;                                                           \
    int t = amm_gate_enter(s->gate[PM], s->idx);                             \
    st_hold(s, PM);                                                          \
    s->mcalls[PM]++;                                                         \
    int rc = (CALL);                                                         \
    st_after(s, PM);                                                         \
    amm_gate_leave(s->gate[PM], s->idx, t);                                  \
    return rc;

static int s_chain(void *c, uint64_t *o, uint64_t d) { ST_WRAP(PM_CHAIN, s_chain_impl(c, o, d)) }
static int s_tip(void *c, uint64_t *o, uint64_t d) { ST_WRAP(PM_TIP, s_tip_impl(c, o, d)) }
static int s_receipt(void *c, const uint8_t h[32], amm_eth_receipt_t *o, uint64_t d) {
    ST_WRAP(PM_RCPT, s_receipt_impl(c, h, o, d))
}
static int s_balance(void *c, const uint8_t a[20], uint8_t o[32], uint64_t d) {
    ST_WRAP(PM_BAL, s_balance_impl(c, a, o, d))
}
static int s_erc20(void *c, const uint8_t t_[20], const uint8_t w[20], uint8_t o[32], uint64_t d) {
    ST_WRAP(PM_ERC20, s_erc20_impl(c, t_, w, o, d))
}
static int s_estimate(void *c, const uint8_t f[20], const uint8_t t_[20], const uint8_t *in,
                      size_t n, uint64_t *o, uint64_t d) {
    ST_WRAP(PM_EST, s_estimate_impl(c, f, t_, in, n, o, d))
}
static int s_gasprice(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->gp_rc) return s->gp_rc; *o = s->gas_price; return AMM_ETH_OK; }
static int s_basefee(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; s->bf_calls++; if (s->bf_rc) return s->bf_rc; *o = s->base_fee; return AMM_ETH_OK; }
static int s_prio(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->prio_rc) return s->prio_rc; *o = s->prio; return AMM_ETH_OK; }
static int s_send(void *c, const uint8_t *raw, size_t n, uint8_t h[32], uint64_t d) {
    stub_t *s = c; (void)d;
    s->send_calls++;
    if (g_on_send) g_on_send(raw, n);
    if (n <= sizeof(s->last_raw)) { memcpy(s->last_raw, raw, n); s->last_raw_len = n; }
    if (s->send_rc) return s->send_rc;
    keccak256(raw, n, h);
    if (s->send_wrong_hash) h[0] ^= 0xff;
    return AMM_ETH_OK;
}

/* the price stub: mode 0 = a fixed fee, mode 1 = gas * mul, mode 2 = the CONVERSION of the real
 * seam, ceil(gas x max fee x p_e6 / 10^18) with the product in 128 bits (66,340 x 6e9 x 3e9 is
 * 1.2e24, above uint64), so every assertion about the deducted fee depends on the max fee per gas
 * (evm-fee plan 7.2) */
typedef struct { int mode; uint64_t fixed, mul, p_e6; int rc; int calls; uint64_t last_gas, last_max_fee; } price_t;
static int s_price(void *c, uint64_t gas, uint64_t mf, uint64_t *o, uint64_t d) {
    price_t *p = c; (void)d;
    p->calls++;
    p->last_gas = gas; p->last_max_fee = mf;
    if (p->rc) return p->rc;
    if (p->mode == 2) {
        const unsigned __int128 den = 1000000000000000000ULL;
        const unsigned __int128 v = (unsigned __int128)gas * mf * p->p_e6;
        const unsigned __int128 q = (v + den - 1) / den;
        if (q > UINT64_MAX) return AMM_ETH_ERR;
        *o = (uint64_t)q;
        return AMM_ETH_OK;
    }
    *o = p->mode == 0 ? p->fixed : gas * p->mul;
    return AMM_ETH_OK;
}

/* ── the environment ────────────────────────────────────────────────── */

#define NP 3

static char g_dir[64];
static char g_path[128];
static amm_journal_t *g_j;
static stub_t g_st[NP];
static amm_eth_provider_t g_prov[NP];
static price_t g_price;
static uint64_t g_pay_chain = 1;     /* the configured eth_chain_id (reset by fresh) */
static uint8_t g_key[32];
static uint8_t g_usdt[20];
static uint8_t g_self[20];

/* The logs a status-1 receipt of OUR payout carries, built from the journal's
 * stored attempt (what a chain that executed the transfer would log), unless
 * `log_mode` says otherwise:
 *   0 the correct log: Transfer(bot, recipient, net) by the USDT contract
 *   1 no logs                       2 Transfer to ANOTHER recipient
 *   3 TetherToken fee pattern (TetherToken.sol:123-134): Transfer(bot,
 *     recipient, net - 5) and Transfer(bot, owner, 5)
 *   4 the correct log twice         5 nine logs (more than the table keeps)
 *   6 the correct log from ANOTHER emitter
 *   7 the correct log with a 31-byte data field (not a Transfer log)
 *   8 the correct log from the WRONG SENDER (topic 1 is not the bot)
 *   9 an OVERSIZED value: 2^64 + net in the 32-byte data word
 *  10 the correct log whose data differs from mode 0 only in the digest of the
 *     whole data (what an adapter reports when the data has a longer tail) */
static const uint8_t T_TRANSFER[32] = {
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68,
    0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef};

static void mk_log(amm_eth_log_t *l, const uint8_t emitter[20], const uint8_t to[20],
                   uint64_t v, const amm_eth_receipt_t *r, const uint8_t tx[32], uint32_t idx) {
    memset(l, 0, sizeof(*l));
    memcpy(l->address, emitter, 20);
    l->n_topics = 3;
    memcpy(l->topics[0], T_TRANSFER, 32);
    memcpy(l->topics[1] + 12, g_self, 20);
    memcpy(l->topics[2] + 12, to, 20);
    for (int i = 0; i < 8; i++) l->data[31 - i] = (uint8_t)(v >> (8 * i));
    l->data_len = 32;
    l->log_index = idx;
    memcpy(l->tx, tx, 32);
    l->block_number = r->block_number;
    memcpy(l->block_hash, r->block_hash, 32);
    keccak256(l->data, 32, l->data_digest);       /* what the adapter reports for 32 bytes */
}

static void add_logs(stub_t *s, const uint8_t h[32], amm_eth_receipt_t *o) {
    amm_eattempt_t a;
    if (s->log_mode == 1 || amm_journal_eth_attempt_by_hash(g_j, h, &a) != 0) return;
    uint8_t to[20], owner[20], other[20];
    memcpy(to, a.recipient, 20);
    memset(owner, 0x0a, 20);
    memcpy(other, g_usdt, 20);
    other[0] ^= 0xff;
    uint64_t v = a.net;
    int n = 0;
    if (s->log_mode == 2) to[0] ^= 1;
    if (s->log_mode == 3) v = a.net - 5;
    mk_log(&o->logs[n++], s->log_mode == 6 ? other : g_usdt, to, v, o, h, 0);
    if (s->log_mode == 3) mk_log(&o->logs[n++], g_usdt, owner, 5, o, h, 1);
    if (s->log_mode == 4) mk_log(&o->logs[n++], g_usdt, to, v, o, h, 1);
    if (s->log_mode == 7) o->logs[0].data_len = 31;
    if (s->log_mode == 8) o->logs[0].topics[1][31] ^= 1;
    if (s->log_mode == 9) o->logs[0].data[23] = 1;
    if (s->log_mode == 10) o->logs[0].data_digest[0] ^= 1;
    o->n_logs = n;
    o->logs_total = n;
    if (s->log_mode == 5) {
        for (; n < AMM_ETH_RCPT_LOGS; n++) mk_log(&o->logs[n], g_usdt, owner, 1, o, h, (uint32_t)n);
        o->n_logs = AMM_ETH_RCPT_LOGS;
        o->logs_total = AMM_ETH_RCPT_LOGS + 1;
    }
    amm_eattempt_free(&a);
}

static void cleanup_dir(void) {
    DIR *d = opendir(g_dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", g_dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(g_dir);
}

static void defaults(stub_t *s) {
    memset(s, 0, sizeof(*s));
    s->chain = 1;
    s->tip = 1000;
    s->cnt_pending = 0; s->cnt_latest = 0;
    set_be(s->usdt, 1000000000000ULL);
    set_be(s->eth, 1000000000000000000ULL);
    s->gas_base = 60000;
    /* the fee rule F1 (evm-fee plan 2.1): max fee per gas = 2 x base fee + tip = 2 x 11 + 2 = 24 gwei.
     * `gas_price` (30 gwei) is deliberately DIFFERENT from it: the payer no longer reads it, so a
     * transaction signed with 30 gwei would fail every assertion on the fee fields. */
    s->gas_price = 30000000000ULL;
    s->base_fee = 11000000000ULL;
    s->prio = 2000000000ULL;
}

static void fresh(void) {
    if (g_j) { amm_journal_close(g_j); g_j = NULL; }
    unlink(g_path);
    char p[160];
    snprintf(p, sizeof(p), "%s-wal", g_path); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", g_path); unlink(p);
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL open\n"); exit(2); }
    for (int i = 0; i < NP; i++) {
        defaults(&g_st[i]);
        g_st[i].idx = i; g_st[i].hold_method = -1; g_st[i].unit_method = -1;
    }
    memset(&g_price, 0, sizeof(g_price));
    g_price.mode = 0; g_price.fixed = 100;
    g_on_send = NULL;
    g_pay_chain = 1;
}

static void reopen(void) {
    amm_journal_close(g_j);
    g_j = NULL;
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL reopen\n"); exit(2); }
}

static void init_env(void) {
    for (int i = 0; i < 32; i++) g_key[i] = (uint8_t)(i + 1);
    const char *u = "dac17f958d2ee523a2206206994597c13d831ec7";
    for (int i = 0; i < 20; i++) {
        int a = u[2 * i] <= '9' ? u[2 * i] - '0' : u[2 * i] - 'a' + 10;
        int b = u[2 * i + 1] <= '9' ? u[2 * i + 1] - '0' : u[2 * i + 1] - 'a' + 10;
        g_usdt[i] = (uint8_t)(a * 16 + b);
    }
    for (int i = 0; i < NP; i++)
        g_prov[i] = (amm_eth_provider_t){ .ctx = &g_st[i], .name = "stub",
            .chain_id = s_chain, .block_number = s_tip, .get_receipt = s_receipt,
            .get_balance = s_balance, .erc20_balance = s_erc20, .tx_count = s_count,
            .estimate_gas = s_estimate, .gas_price = s_gasprice, .base_fee = s_basefee,
            .max_priority_fee = s_prio, .send_raw = s_send };
}

static amm_eth_pay_t *new_pay_n(int n, int q, uint64_t depth, int paused) {
    amm_eth_pay_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.providers = g_prov; c.n_providers = n; c.quorum = q;
    c.price.ctx = &g_price; c.price.fee_usdt = s_price;
    c.chain_id = g_pay_chain;
    c.journal = g_j; c.sk = g_key; c.blind = NULL;
    memcpy(c.usdt, g_usdt, 20);
    c.final_depth = depth; c.payouts_paused = paused;
    amm_eth_pay_t *p = amm_eth_pay_new(&c);
    if (p) amm_eth_pay_self(p, g_self);
    return p;
}
static amm_eth_pay_t *new_pay(void) { return new_pay_n(1, 1, 3, 0); }

/* ── swap fixtures ──────────────────────────────────────────────────── */

static uint64_t g_ctr = 1;

/* Signing a swap's USDT payment. A NODUS -> USDT PAYOUT is signed by the engine's
 * decision since revision 12 (plan section 12): amm_eth_pay_prepare plans, estimates,
 * checks the funds and SIGNS without touching the journal, and the attempt is stored
 * by the caller -- here by this wrapper, as the decision does (the one transaction
 * with the ledger update is tested in test_amm_journal J27 and test_amm_engine E3).
 * The payer no longer moves a payout to refund_pending: ZERO and BELOW_MIN are only
 * RETURNED and the swap stays payout_pending. A USDT REFUND is signed by
 * amm_eth_pay_sign as before. Every amm_eth_pay_sign call of this file goes through
 * the wrapper (the macro below), which calls the real function for refunds. */
/* The decision writes the payout row's out_amount / out_fee / out_paid with the first attempt in
 * one transaction (amm_journal_swap_decide); this fixture stores the attempt alone, so the row's
 * three amounts are written here through a second connection. The journal refuses a later
 * attempt (re-send, replacement) of a payout row whose net exceeds its out_amount. */
static void set_out(int64_t seq, uint64_t gross, uint64_t fee, uint64_t net) {
    char sql[200];
    sqlite3 *db = NULL;
    snprintf(sql, sizeof(sql), "UPDATE swaps SET out_amount=%llu, out_fee=%llu, out_paid=%llu WHERE seq=%lld",
             (unsigned long long)gross, (unsigned long long)fee, (unsigned long long)net, (long long)seq);
    if (sqlite3_open(g_path, &db) == SQLITE_OK) {
        sqlite3_busy_timeout(db, 5000);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    sqlite3_close(db);
}

static int ep_sign_test(amm_eth_pay_t *p, int64_t swap_seq, uint64_t gross, uint64_t dl,
                        amm_ep_step_t *out) {
    amm_swap_t cur;
    if (amm_journal_swap_by_seq(g_j, swap_seq, &cur) == 0 && cur.dir == AMM_NODUS_TO_USDT &&
        !strcmp(cur.state, AMM_S_PAYOUT_PENDING)) {
        if (out) { memset(out, 0, sizeof(*out)); out->swap_seq = swap_seq; }
        if (gross == 0 || gross > (uint64_t)INT64_MAX) return AMM_EP_ERR;
        amm_eattempt_t prev;
        int ar = amm_journal_eth_attempt_latest(g_j, swap_seq, &prev);
        if (ar == 0) { amm_eattempt_free(&prev); return AMM_EP_ERR; }      /* an attempt exists */
        amm_ep_prepared_t pre;
        int rc = amm_eth_pay_prepare(p, cur.dest, gross, cur.minimum, dl, &pre);
        if (out) { out->fee = pre.fee; out->net = pre.net; snprintf(out->msg, sizeof(out->msg), "%s", pre.msg); }
        if (rc == AMM_EP_OK) {
            pre.attempt.swap_seq = swap_seq;
            if (amm_journal_eth_attempt_sign(g_j, &pre.attempt) == AMM_J_OK) {
                set_out(swap_seq, gross, pre.fee, pre.net);
                if (out) { out->worked = 1; out->signed_ = 1; }
            } else {
                rc = AMM_EP_ERR;
            }
        }
        amm_ep_prepared_free(&pre);
        return rc;
    }
    return (amm_eth_pay_sign)(p, swap_seq, gross, dl, out);
}
#define amm_eth_pay_sign ep_sign_test

/* a NODUS -> USDT swap (dir 1): sender 128 x c, dest 40 x d; or a USDT -> NODUS
 * swap (dir 0): sender 40 x c, dest 128 x d. Driven to payout_pending (dir 1) /
 * refund_pending (dir 0). */
static int new_swap(int dir, char c, char d, uint64_t minimum, amm_swap_t *out) {
    static char sb[64][129], db[64][129];
    static unsigned ri = 0;
    char *snd = sb[ri % 64], *dst = db[ri % 64];
    ri++;
    memset(snd, c, dir ? 128 : 40); snd[dir ? 128 : 40] = '\0';
    memset(dst, d, dir ? 40 : 128); dst[dir ? 40 : 128] = '\0';
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    a.dir = dir ? AMM_NODUS_TO_USDT : AMM_USDT_TO_NODUS;
    a.sender = snd; a.dest = dst;
    a.amount = 1000 + g_ctr; a.minimum = minimum; a.value_usdt = 1;
    a.approved_at = 1000; a.expiry = 2800; a.approved_tip = 100;
    a.incoming_id = "";
    uint64_t n = g_ctr++;
    for (int i = 0; i < 8; i++) a.req_no[31 - i] = (uint8_t)(n >> (8 * i));
    for (int i = 0; i < 16; i++) a.rand16[i] = (uint8_t)(n * 31 + i);
    a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    if (amm_journal_approve(g_j, &a, out) != AMM_J_OK) return 0;
    char inc[80];
    snprintf(inc, sizeof(inc), "nodus:%016llx", (unsigned long long)n);
    if (!dir) snprintf(inc, sizeof(inc), "eth:%064llx", (unsigned long long)n);
    if (amm_journal_swap_seen(g_j, out->seq, inc, NULL, 500000000ULL, 0, NULL) != 0 ||
        amm_journal_swap_transition(g_j, out->seq, "counted", NULL, NULL, NULL) != 0 ||
        amm_journal_swap_transition(g_j, out->seq, dir ? "payout_pending" : "refund_pending",
                                    NULL, NULL, NULL) != 0) return 0;
    return amm_journal_swap_by_seq(g_j, out->seq, out) == 0;
}

static int swap_state_is(int64_t seq, const char *st) {
    amm_swap_t s;
    return amm_journal_swap_by_seq(g_j, seq, &s) == 0 && !strcmp(s.state, st);
}

static int has_attempt(int64_t seq) {
    amm_eattempt_t a;
    int r = amm_journal_eth_attempt_latest(g_j, seq, &a);
    if (r == 0) amm_eattempt_free(&a);
    return r == 0;
}

static int sends(void) { int n = 0; for (int i = 0; i < NP; i++) n += g_st[i].send_calls; return n; }
static int ests(void) { int n = 0; for (int i = 0; i < NP; i++) n += g_st[i].est_calls; return n; }

/* ── decoding a stored transaction ──────────────────────────────────── */

typedef struct { uint8_t f[12][80]; size_t l[12]; } dec_t;

static int decode(const uint8_t *raw, size_t n, dec_t *d) {
    evm_trie_rlp_item top, it;
    if (n < 2 || raw[0] != 0x02 || evm_trie_rlp_decode_item(raw + 1, n - 1, &top) != 0 ||
        !top.is_list || top.total != n - 1) return -1;
    const uint8_t *p = top.payload;
    size_t left = top.len;
    for (int i = 0; i < 12; i++) {
        if (left == 0 || evm_trie_rlp_decode_item(p, left, &it) != 0) return -1;
        d->l[i] = it.len;
        if (it.len <= sizeof(d->f[i])) memcpy(d->f[i], it.payload, it.len);
        p += it.total;
        left -= it.total;
    }
    return left == 0 ? 0 : -1;
}

static uint64_t be_u64(const uint8_t *b, size_t n) { uint64_t v = 0; for (size_t i = 0; i < n; i++) v = (v << 8) | b[i]; return v; }

static int recovers_to_self(const uint8_t *raw, size_t n, const dec_t *d) {
    /* rebuild the signing hash from the decoded fields */
    amm_tx1559_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.chain_id = be_u64(d->f[0], d->l[0]);
    tx.nonce = be_u64(d->f[1], d->l[1]);
    tx.max_priority_fee_per_gas = be_u64(d->f[2], d->l[2]);
    tx.max_fee_per_gas = be_u64(d->f[3], d->l[3]);
    tx.gas = be_u64(d->f[4], d->l[4]);
    tx.has_to = (d->l[5] == 20);
    if (tx.has_to) memcpy(tx.to, d->f[5], 20);
    tx.data = d->f[7];
    tx.data_len = d->l[7];
    uint8_t sh[32], in[128], r[32] = {0}, s[32] = {0};
    (void)raw; (void)n;
    if (amm_tx1559_signing_hash(&tx, sh) != 0) return 0;
    memcpy(r + 32 - d->l[10], d->f[10], d->l[10]);
    memcpy(s + 32 - d->l[11], d->f[11], d->l[11]);
    memcpy(in, sh, 32);
    memset(in + 32, 0, 32);
    in[63] = (uint8_t)(27 + (d->l[9] ? d->f[9][0] : 0));
    memcpy(in + 64, r, 32);
    memcpy(in + 96, s, 32);
    evm_addr a;
    memset(&a, 0, sizeof(a));
    a.b[31] = 1;
    uint64_t gas = 1000000;
    evm_pc_result_t res;
    uint8_t *o = NULL;
    size_t ol = 0;
    int ok = evm_precompile_run(&a, in, sizeof(in), &gas, &res, &o, &ol) == 0 &&
             res == EVM_PC_OK && ol == 32 && !memcmp(o + 12, g_self, 20);
    free(o);
    return ok;
}

/* the hook of E1: at send time the journal already holds these bytes */
static int g_hook_calls, g_hook_ok;
static int64_t g_hook_swap;
static int hook_journal_has(const uint8_t *raw, size_t n) {
    amm_eattempt_t a;
    g_hook_calls++;
    if (amm_journal_eth_attempt_latest(g_j, g_hook_swap, &a) == 0) {
        if (a.raw_len == n && !memcmp(a.raw, raw, n)) g_hook_ok++;
        amm_eattempt_free(&a);
    }
    return 0;
}

/* ═══ scenarios ═══════════════════════════════════════════════════════ */

static void e1_persisted_before_broadcast(void) {
    printf("E1 persisted before broadcast; the stored transaction\n");
    fresh();
    amm_eth_pay_t *p = new_pay();
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup: a NODUS -> USDT swap in payout_pending, destination 0x1111..");
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK && o.signed_ == 1 && o.fee == 100 && o.net == 999900,
          "sign: stored, fee 100 deducted, net 999900");
    CHECK(sends() == 0, "signing broadcasts NOTHING");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "signed") &&
          a.nonce == 0 && a.gross == 1000000 && a.net == 999900 && a.fee == 100 && a.gas_limit == 75000 &&
          a.max_fee_per_gas == 24000000000ULL && a.max_priority_fee_per_gas == 2000000000ULL,
          "the attempt is in the journal (signed): nonce 0, gross, net, fee, gas limit, fees (max fee 2 x 11 + 2 = 24 gwei, priority 2 gwei)");
    uint8_t h[32];
    CHECK(keccak256(a.raw, a.raw_len, h) == 0 && !memcmp(h, a.hash, 32), "its hash is keccak256 of its bytes");
    dec_t d;
    CHECK(decode(a.raw, a.raw_len, &d) == 0, "the stored bytes decode as a type-2 transaction");
    uint8_t want[AMM_TX_TRANSFER_DATA_LEN], user[20];
    memset(user, 0x11, 20);
    amm_tx_transfer_calldata(user, 999900, want);
    CHECK(be_u64(d.f[0], d.l[0]) == 1 && be_u64(d.f[1], d.l[1]) == 0 && d.l[5] == 20 && !memcmp(d.f[5], g_usdt, 20) &&
          d.l[6] == 0 && d.l[7] == 68 && !memcmp(d.f[7], want, 68) && be_u64(d.f[4], d.l[4]) == 75000 &&
          be_u64(d.f[3], d.l[3]) == 24000000000ULL && be_u64(d.f[2], d.l[2]) == 2000000000ULL,
          "chain 1, to = USDT, value 0, call data transfer(destination, net), gas, fees");
    CHECK(recovers_to_self(a.raw, a.raw_len, &d), "the signature recovers (ecrecover port) to the bot's address");

    /* the broadcast: the journal already holds the bytes when a provider gets them */
    g_hook_calls = g_hook_ok = 0;
    g_hook_swap = s.seq;
    g_on_send = hook_journal_has;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1, "step: broadcast");
    CHECK(g_hook_calls == 1 && g_hook_ok == 1, "at the moment of the send the journal already held the same bytes");
    CHECK(g_st[0].last_raw_len == a.raw_len && !memcmp(g_st[0].last_raw, a.raw, a.raw_len), "the provider received exactly the stored bytes");
    amm_eattempt_t b;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &b) == 0 && !strcmp(b.state, "submitted") && b.last_submit_tip == 1000,
          "the attempt is now submitted, with the tip it was sent at");
    amm_eattempt_free(&b);
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);
    g_on_send = NULL;

    /* a USDT refund goes to the request's SENDER */
    fresh();
    p = new_pay();
    CHECK(p && new_swap(0, '2', 'e', 0, &s) && amm_eth_pay_sign(p, s.seq, 5000, 0, &o) == AMM_EP_OK,
          "a refund (USDT -> NODUS swap in refund_pending) is signed");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && decode(a.raw, a.raw_len, &d) == 0, "stored");
    memset(user, 0x22, 20);
    amm_tx_transfer_calldata(user, 4900, want);
    CHECK(!memcmp(d.f[7], want, 68), "the refund call data names the request's sender (0x2222..) and net 4900");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);
}

static void e2_restart_between_store_and_broadcast(void) {
    printf("E2 restart between store and broadcast\n");
    fresh();
    amm_eth_pay_t *p = new_pay();
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK, "signed and stored");
    amm_eattempt_t before;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &before) == 0, "read the stored bytes");
    amm_eth_pay_free(p);
    reopen();                                     /* the restart */
    int est0 = ests();
    p = new_pay();
    CHECK(p != NULL, "a new payer on the reopened journal");
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1, "the step broadcasts");
    CHECK(g_st[0].last_raw_len == before.raw_len && !memcmp(g_st[0].last_raw, before.raw, before.raw_len),
          "the SAME stored bytes were sent (nothing was rebuilt)");
    CHECK(ests() == est0, "no estimate was asked again");
    amm_eattempt_t after;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &after) == 0 && after.n == 1 && after.nonce == before.nonce &&
          !memcmp(after.hash, before.hash, 32), "still one attempt, the same nonce and hash");
    amm_eattempt_free(&after);
    amm_eattempt_free(&before);
    amm_eth_pay_free(p);
}

static void e3_estimate_failure(void) {
    printf("E3 estimate failure keeps the payout unsent\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup");
    for (int i = 0; i < NP; i++) g_st[i].est_rc = AMM_ETH_ERR;        /* "execution reverted" */
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN, "every estimate fails: UNKNOWN");
    CHECK(!has_attempt(s.seq) && swap_state_is(s.seq, "payout_pending") && sends() == 0 && g_price.calls == 0,
          "nothing stored, nothing sent, the swap unchanged, the price not even asked");
    g_st[0].est_rc = 0;                                                /* one answer < the quorum of 2 */
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN && !has_attempt(s.seq),
          "one answering provider is below the quorum: still unsent");
    g_st[1].est_rc = 0;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK && has_attempt(s.seq),
          "the estimate answers again: the SAME payout is signed (never lost)");
    amm_eth_pay_free(p);
}

static void e4_receipts(void) {
    printf("E4 receipts: failed send, final depth, settlement\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: signed and broadcast");
    /* status 0 below the final depth: nothing */
    g_st[0].rc_mode = 1;
    g_st[0].rc.status = 0; g_st[0].rc.block_number = 998; memset(g_st[0].rc.block_hash, 0x77, 32);
    g_st[0].tip = 1000;                                               /* depth 2 < 3 */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && !o.confirmed, "status 0 at depth 2 (< 3): waits");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "submitted"), "the attempt is still submitted");
    amm_eattempt_free(&a);
    g_st[0].tip = 1001;                                               /* depth 3 */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_FAILED && o.worked == 1, "status 0 at the final depth: FAILED");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "failed"), "the attempt is failed");
    amm_eattempt_free(&a);
    CHECK(swap_state_is(s.seq, "payout_pending"), "the swap stays payout_pending (nothing is paid, nothing is lost)");
    int sd = sends(), rc0 = g_st[0].rc_calls;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_FAILED && sends() == sd && g_st[0].rc_calls == rc0,
          "a failed payout is reported again with no read and no send");
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_ERR, "and is not signed a second time by this module");
    amm_eth_pay_free(p);

    /* status 1: depth 2 waits, depth 3 settles; payout -> paid */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: a payout broadcast");
    g_st[0].rc_mode = 1;
    g_st[0].rc.status = 1; g_st[0].rc.block_number = 998; memset(g_st[0].rc.block_hash, 0x77, 32);
    g_st[0].tip = 1000;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && swap_state_is(s.seq, "payout_pending"),
          "status 1 at depth 2: not final");
    g_st[0].tip = 1001;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid"),
          "status 1 at depth 3: the swap is paid");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "confirmed"), "the attempt is confirmed");
    amm_eattempt_free(&a);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ERR, "a paid swap owes nothing");
    amm_eth_pay_free(p);

    /* a refund -> refunded */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(0, '2', 'e', 0, &s) && amm_eth_pay_sign(p, s.seq, 9000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: a refund broadcast");
    g_st[0].rc_mode = 1; g_st[0].rc.status = 1; g_st[0].rc.block_number = 900;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "refunded"),
          "a refund with status 1 at the final depth: refunded");
    amm_eth_pay_free(p);

    /* the deep requirement: a receipt that is ABOVE the tip is not deep */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup");
    g_st[0].rc_mode = 1; g_st[0].rc.status = 1; g_st[0].rc.block_number = 2000;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && swap_state_is(s.seq, "payout_pending"),
          "a receipt above the tip (lagging provider) is not final, and does not wrap");
    amm_eth_pay_free(p);
}

static void e5_orphaned(void) {
    printf("E5 orphaned nonce\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: a payout with nonce 0, broadcast");
    g_st[0].cnt_latest = 0;                                              /* confirmed nonce == stored nonce */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && swap_state_is(s.seq, "payout_pending"),
          "no receipt and the confirmed nonce == the stored nonce: still pending, not an orphan");
    g_st[0].cnt_latest = 1;                                              /* the nonce was used by another transaction */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ORPHANED && o.worked == 1, "no receipt and the confirmed nonce above the stored one: ORPHANED");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "orphaned"), "the attempt is orphaned");
    amm_eattempt_free(&a);
    CHECK(swap_state_is(s.seq, "unknown"), "the swap is unknown (the bot stops, plan line 268)");
    amm_swap_t t;
    amm_approve_t ap;
    memset(&ap, 0, sizeof(ap));
    char snd[41], dst[129];
    memset(snd, 'a', 40); snd[40] = 0; memset(dst, 'b', 128); dst[128] = 0;
    ap.dir = AMM_USDT_TO_NODUS; ap.sender = snd; ap.dest = dst; ap.amount = 5; ap.minimum = 1;
    ap.value_usdt = 1; ap.approved_at = 1; ap.expiry = 100; ap.approved_tip = 5; ap.incoming_id = "";
    ap.req_no[31] = 99; ap.rand16[0] = 99; ap.swap_max = 100; ap.inflight_max = 100;
    CHECK(amm_journal_approve(g_j, &ap, &t) == AMM_J_STOPPED, "the journal now refuses new approvals");
    amm_eth_pay_free(p);

    /* a signed attempt that was never broadcast is orphaned the same way */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK, "setup: signed only");
    g_st[0].cnt_latest = 5;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ORPHANED && sends() == 0 && swap_state_is(s.seq, "unknown"),
          "orphaned without any broadcast: nothing is sent");
    amm_eth_pay_free(p);
}

static void e6_balances(void) {
    printf("E6 balance check before signing\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_swap_t s1, s2;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s1) && new_swap(1, 'd', '1', 0, &s2), "setup: two payouts");
    set_be(g_st[0].usdt, 999899);                                        /* net would be 999900 */
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_FUNDS, "USDT balance 999899 < net 999900: FUNDS");
    CHECK(!has_attempt(s1.seq) && swap_state_is(s1.seq, "payout_pending") && sends() == 0, "nothing stored, nothing sent");
    set_be(g_st[0].usdt, 999900);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_OK, "balance == net: signs");
    /* the bot's own pending payout is subtracted from the next one's balance */
    CHECK(amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s2.seq),
          "balanceOf 999900 minus the 999900 already pending = 0: the second payout is FUNDS");
    set_be(g_st[0].usdt, 999900 + 999899);
    CHECK(amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_FUNDS, "one raw unit short after the subtraction: FUNDS");
    set_be(g_st[0].usdt, 999900 + 999900);
    CHECK(amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_OK, "exactly enough after the subtraction: signs");
    amm_eth_pay_free(p);

    /* ether for gas: the estimate 60000 is raised by 25% rounded up (Boltz
     * bumpGasLimit): (60000 x 125 + 99) / 100 = 7,500,099 / 100 = 75000;
     * 75000 x max fee 24 gwei (2 x 11 + 2: the fee rule F1, 24,000,000,000) =
     * 1,800,000,000,000,000 wei; between 75000 x 13 gwei and 75000 x 24 gwei the check
     * must refuse (it would pass at the old 30 gwei price only above 75000 x 30 gwei) */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s1), "setup");
    set_be(g_st[0].eth, 75000ULL * 13000000000ULL);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s1.seq),
          "ether between gas x 13 gwei and gas x 24 gwei: FUNDS");
    set_be(g_st[0].eth, 1799999999999999ULL);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s1.seq), "ether 1 wei short of gas x max fee: FUNDS");
    set_be(g_st[0].eth, 1800000000000000ULL);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_OK, "ether exactly gas x max fee: signs");
    amm_eth_pay_free(p);

    /* an unreadable balance is unknown; the smallest answer is the balance */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s1), "setup");
    g_st[0].usdt_rc = AMM_ETH_ERR; g_st[1].usdt_rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN && !has_attempt(s1.seq), "one balance answer < Q: UNKNOWN, never zero, never enough");
    g_st[0].usdt_rc = 0; g_st[1].usdt_rc = 0;
    set_be(g_st[0].usdt, 5); set_be(g_st[1].usdt, 999900); set_be(g_st[2].usdt, 999900);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_FUNDS, "the SMALLEST balance answer counts: 5 < net");
    set_be(g_st[0].usdt, 999900);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_OK, "all agree on enough: signs");
    amm_eth_pay_free(p);
}

static void e7_fee(void) {
    printf("E7 fee below, at and above the amount; the minimum after the fee\n");
    uint64_t net = 99;
    CHECK(amm_eth_pay_judge(1000, 100, 0, &net) == AMM_EP_PAY && net == 900, "judge: fee below the amount");
    CHECK(amm_eth_pay_judge(1000, 999, 0, &net) == AMM_EP_PAY && net == 1, "judge: fee == amount - 1 leaves 1");
    CHECK(amm_eth_pay_judge(1000, 1000, 0, &net) == AMM_EP_NOTHING && net == 0, "judge: fee == amount: nothing");
    CHECK(amm_eth_pay_judge(5, 10, 0, &net) == AMM_EP_NOTHING && net == 0, "judge: fee above the amount saturates at zero, never wraps");
    CHECK(amm_eth_pay_judge(UINT64_MAX, 1, 0, &net) == AMM_EP_PAY && net == UINT64_MAX - 1, "judge: the largest amount");
    CHECK(amm_eth_pay_judge(1000, 100, 900, &net) == AMM_EP_PAY, "judge: net == minimum pays");
    CHECK(amm_eth_pay_judge(1000, 100, 901, &net) == AMM_EP_BELOW && net == 900, "judge: net == minimum - 1 is below");
    CHECK(amm_eth_pay_judge(1000, 100, 950, NULL) == AMM_EP_BELOW, "judge: the minimum is compared after the fee (the gross would satisfy 950)");
    CHECK(amm_eth_pay_judge(1000, 1000, 5, NULL) == AMM_EP_NOTHING, "judge: nothing left whatever the minimum");

    amm_swap_t s;
    amm_ep_step_t o;
    /* the real flow, fee as a fixed price */
    uint64_t fees[3] = { 999, 1000, 1500 };
    for (int k = 0; k < 3; k++) {
        fresh();
        amm_eth_pay_t *p = new_pay();
        g_price.fixed = fees[k];
        CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup: a payout of gross 1000");
        int rc = amm_eth_pay_sign(p, s.seq, 1000, 0, &o);
        if (k == 0) {
            amm_eattempt_t a;
            CHECK(rc == AMM_EP_OK && amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.net == 1 && a.fee == 999,
                  "fee 999 of 1000: pays 1");
            amm_eattempt_free(&a);
        } else {
            CHECK(rc == AMM_EP_ZERO && !has_attempt(s.seq) && swap_state_is(s.seq, "payout_pending"),
                  k == 1 ? "fee == amount: nothing signed, the verdict is returned (the engine refunds)"
                         : "fee above the amount: nothing signed, the verdict is returned (the engine refunds)");
            CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_NEED_SIGN && sends() == 0, "and nothing is ever broadcast");
        }
        amm_eth_pay_free(p);
    }
    /* a USDT refund with fee >= amount is NOT SENT (givens items 89, 90): the payer returns
     * AMM_EP_ZERO and moves nothing since the evm-fee work (evm-fee plan 6.10.2): the engine puts
     * its USDT in the pool and drops the swap in one journal transaction (test_amm_engine E26),
     * so here the swap is still refund_pending and has no attempt */
    for (int k = 1; k < 3; k++) {
        fresh();
        amm_eth_pay_t *p = new_pay();
        g_price.fixed = fees[k];
        CHECK(p && new_swap(0, '2', 'e', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_ZERO &&
              !has_attempt(s.seq) && swap_state_is(s.seq, "refund_pending") && o.worked == 0 && sends() == 0,
              k == 1 ? "refund, fee == amount: ZERO, nothing signed and nothing moved"
                     : "refund, fee above the amount: ZERO, nothing signed and nothing moved");
        amm_eth_pay_free(p);
    }
    /* the minimum after the fee (a payout; fee 100, gross 1000) */
    fresh();
    amm_eth_pay_t *p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 900, &s) && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_OK, "net 900 == minimum 900: pays");
    amm_eth_pay_free(p);                           /* before fresh() closes the journal it holds */
    fresh();
    p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 901, &s) && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_BELOW_MIN &&
          !has_attempt(s.seq) && swap_state_is(s.seq, "payout_pending"),
          "net 900 < minimum 901 (the gross 1000 would pass): nothing signed, the verdict is returned (the engine refunds)");
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_NEED_SIGN && sends() == 0, "and nothing is broadcast");
    amm_eth_pay_free(p);
}

static void e8_price(void) {
    printf("E8 an unreadable price is never zero\n");
    fresh();
    amm_eth_pay_t *p = new_pay();
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup");
    g_price.rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN, "the price cannot be read: UNKNOWN");
    CHECK(!has_attempt(s.seq) && swap_state_is(s.seq, "payout_pending") && sends() == 0 && g_price.calls >= 1,
          "nothing signed (not even at fee 0), nothing sent, the swap unchanged");
    g_price.rc = 0;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK && o.fee == 100, "the price reads again: signs, fee 100");
    CHECK(g_price.last_gas == 75000 && g_price.last_max_fee == 24000000000ULL,
          "the price seam was handed the gas limit and the max fee per gas the transaction carries");
    amm_eth_pay_free(p);
}

static void e9_nonces(void) {
    printf("E9 nonce allocation and uniqueness across a restart\n");
    fresh();
    amm_eth_pay_t *p = new_pay();
    amm_swap_t s1, s2, s3, s4;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s1) && new_swap(1, 'd', '1', 0, &s2) &&
          new_swap(1, 'e', '1', 0, &s3) && new_swap(1, 'f', '1', 0, &s4), "setup: four payouts");
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_OK, "the first payout is signed");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s1.seq, &a) == 0 && a.nonce == 0, "its nonce is 0");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);
    reopen();
    p = new_pay();
    CHECK(p && amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_journal_eth_attempt_latest(g_j, s2.seq, &a) == 0 && a.nonce == 1,
          "after a restart (the chain still says 0, nothing was broadcast) the next nonce is 1: the stored row is seen");
    amm_eattempt_free(&a);
    g_st[0].cnt_pending = 20;
    CHECK(amm_eth_pay_sign(p, s3.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_journal_eth_attempt_latest(g_j, s3.seq, &a) == 0 && a.nonce == 20,
          "the chain's pending count 20 is above the journal's next (2): 20");
    amm_eattempt_free(&a);
    CHECK(amm_eth_pay_sign(p, s4.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_journal_eth_attempt_latest(g_j, s4.seq, &a) == 0 && a.nonce == 21,
          "the chain still says 20, the journal says 21: 21");
    amm_eattempt_free(&a);
    /* the database's own refusal: a stored (chain, nonce) cannot be stored twice */
    amm_eattempt_t dup;
    CHECK(amm_journal_eth_attempt_latest(g_j, s2.seq, &dup) == 0, "read an attempt");
    dup.swap_seq = s1.seq;                         /* s1 already has an attempt: ILLEGAL */
    CHECK(amm_journal_eth_attempt_sign(g_j, &dup) == AMM_J_ILLEGAL, "a second attempt of a swap is refused");
    amm_eattempt_free(&dup);
    amm_eth_pay_free(p);

    /* pending nonce: the Q-th largest of the providers' answers */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s1), "setup: three providers, Q = 2");
    g_st[0].cnt_pending = 50; g_st[1].cnt_pending = 7; g_st[2].cnt_pending = 6;
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_journal_eth_attempt_latest(g_j, s1.seq, &a) == 0 && a.nonce == 7,
          "counts 50, 7, 6 with Q = 2: the 2nd largest, 7 (one liar cannot lift it)");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);
}

static void e10_fixed_point(void) {
    printf("E10 the gas / net fixed point\n");
    fresh();
    amm_eth_pay_t *p = new_pay();
    amm_swap_t s;
    amm_ep_step_t o;
    g_price.mode = 1; g_price.mul = 1;                     /* fee = gas */
    for (int i = 0; i < NP; i++) { g_st[i].gas_base = 21000; g_st[i].gas_by_amount = 1; }
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup: gas = 21000 + 16 x (non-zero bytes of the amount), fee = gas");
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK, "signs");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0, "stored");
    /* Boltz bumpGasLimit(g) = (g x 125 + 99) / 100 on every estimate.
     * round 1: a = 1,000,000 = 0x0f4240, 3 non-zero bytes: estimate 21000 + 16 x 3 = 21048;
     *   bumped (21048 x 125 + 99) / 100 = 2,631,099 / 100 = 26310; fee = gas x 1 = 26310;
     *   net = 1,000,000 - 26,310 = 973,690 != a, so a = 973,690.
     * round 2: 973,690 = 0x0edb7a, 3 non-zero bytes: estimate 21048, gas 26310, fee 26310,
     *   net 973,690 == a: fixed. */
    CHECK(a.gas_limit == 26310 && a.fee == 26310 && a.net == 973690 && a.gross == 1000000,
          "bumped gas 26310, fee 26310, net 973690 (hand-computed, see the comment)");
    dec_t d;
    uint8_t want[68], user[20];
    memset(user, 0x11, 20);
    amm_tx_transfer_calldata(user, a.net, want);
    CHECK(decode(a.raw, a.raw_len, &d) == 0 && !memcmp(d.f[7], want, 68) && be_u64(d.f[4], d.l[4]) == a.gas_limit,
          "the stored call data carries exactly the net that was estimated, and the gas limit is that estimate");
    CHECK(ests() == 2, "the estimate was asked twice (gross, then net): the first round did not settle");
    CHECK(g_price.last_gas == a.gas_limit, "the fee is the price of the final gas");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);

    /* three rounds (bump = (g x 125 + 99) / 100, fee = bumped gas):
     * 1: a = 16,843,009 = 0x01010101, 4 non-zero bytes: estimate 21000 + 64 = 21064;
     *    bumped (21064 x 125 + 99) / 100 = 2,633,099 / 100 = 26330; net = 16,843,009 - 26,330 = 16,816,679
     * 2: a = 16,816,679 = 0x01009a27, 3 non-zero bytes: estimate 21048; bumped 26310;
     *    net = 16,843,009 - 26,310 = 16,816,699
     * 3: a = 16,816,699 = 0x01009a3b, 3 non-zero bytes: estimate 21048; bumped 26310;
     *    net 16,816,699 == a: fixed */
    fresh();
    p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup");
    g_price.mode = 1; g_price.mul = 1;
    for (int i = 0; i < NP; i++) { g_st[i].gas_base = 21000; g_st[i].gas_by_amount = 1; }
    CHECK(amm_eth_pay_sign(p, s.seq, 16843009, 0, &o) == AMM_EP_OK && ests() == 3 &&
          amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.gas_limit == 26310 &&
          a.fee == 26310 && a.net == 16816699, "a three-round fixed point: gas 26310, fee 26310, net 16816699");
    amm_tx_transfer_calldata(user, a.net, want);
    CHECK(decode(a.raw, a.raw_len, &d) == 0 && !memcmp(d.f[7], want, 68), "the stored call data is the estimated one");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);

    /* no fixed point: gross 2^32 = 4,294,967,296, estimate 21000 + 16000 x (non-zero
     * bytes of the amount), bumped (g x 125 + 99) / 100, fee = bumped gas x 631:
     * 1: a = 4,294,967,296 (1 nz): est 37,000, gas 46,250, fee 29,183,750, net 4,265,783,546
     * 2: a = 4,265,783,546 (4 nz): est 85,000, gas 106,250, fee 67,043,750, net 4,227,923,546
     * 3: a = 4,227,923,546 (3 nz): est 69,000, gas 86,250, fee 54,423,750, net 4,240,543,546
     * 4: a = 4,240,543,546 (4 nz): est 85,000, gas 106,250, fee 67,043,750, net 4,227,923,546 != a
     * after AMM_EP_ITER_MAX = 4 rounds it is unsent, never a payout whose call
     * data differs from its estimate */
    fresh();
    p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup");
    g_price.mode = 1; g_price.mul = 631;
    for (int i = 0; i < NP; i++) { g_st[i].gas_base = 21000; g_st[i].gas_by_amount = 1; g_st[i].gas_per_nz = 16000; }
    CHECK(amm_eth_pay_sign(p, s.seq, 4294967296ULL, 0, &o) == AMM_EP_UNKNOWN && ests() == AMM_EP_ITER_MAX,
          "no fixed point in 4 rounds: UNKNOWN");
    CHECK(!has_attempt(s.seq) && swap_state_is(s.seq, "payout_pending") && sends() == 0, "nothing stored, nothing sent, the swap unchanged");
    amm_eth_pay_free(p);
}

static void e11_quorum(void) {
    printf("E11 providers, quorum, broadcast\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;

    /* the chain id is the SETTING (givens item 77): a payer configured for
     * Sepolia uses providers that report 11155111, keys its nonce on it and
     * signs with it. Fails with the constant 1: no provider would be usable
     * (UNKNOWN, nothing stored). */
    amm_eth_pay_free(p);
    fresh();
    g_pay_chain = 11155111ULL;
    for (int i = 0; i < NP; i++) g_st[i].chain = 11155111ULL;
    p = new_pay();
    amm_eattempt_t sa;
    dec_t sdec;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_journal_eth_attempt_latest(g_j, s.seq, &sa) == 0 && sa.chain_id == 11155111ULL &&
          decode(sa.raw, sa.raw_len, &sdec) == 0 && be_u64(sdec.f[0], sdec.l[0]) == 11155111ULL,
          "chain id setting 11155111: signed with it, the attempt keyed on it");
    amm_eattempt_free(&sa);
    uint64_t nn = 0;
    CHECK(amm_journal_eth_next_nonce(g_j, 11155111ULL, &nn) == 0 &&
          amm_journal_eth_next_nonce(g_j, 1, &nn) == 1, "the nonce key is the configured chain id, not chain 1");
    amm_eth_pay_free(p);
    /* providers on mainnet under a Sepolia setting are not used */
    fresh();
    g_pay_chain = 11155111ULL;
    p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN &&
          !has_attempt(s.seq), "providers reporting chain 1 under a Sepolia setting: nothing signed");
    amm_eth_pay_free(p);
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup: three providers, Q = 2");
    g_st[0].chain = 5;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK && g_st[0].est_calls == 0,
          "a provider on chain 5 is not used (no call reaches it); two usable >= Q");
    amm_eth_pay_free(p);
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup again");
    g_st[0].chain = 5; g_st[1].chain = 5;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN && !has_attempt(s.seq),
          "one usable provider < Q: UNKNOWN");
    amm_eth_pay_free(p);

    /* broadcast to every usable provider; acceptance */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK, "setup: signed");
    g_st[0].send_rc = AMM_ETH_ERR;                       /* "already known" / refused */
    g_st[1].send_wrong_hash = 1;                         /* a provider answers another hash */
    g_st[2].send_rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && sends() == 3, "sent to all three; none accepted: UNKNOWN");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "signed"), "the attempt stays signed");
    amm_eattempt_free(&a);
    g_st[2].send_rc = 0;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1 && sends() == 6,
          "the next step sends the same bytes again; one acceptance is enough");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "submitted"), "now submitted");
    amm_eattempt_free(&a);
    int sd = sends();
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd && o.worked == 0,
          "a submitted attempt with no receipt is not sent again within the same block (the latest block is "
          "not above its last broadcast tip; the once-per-new-block rebroadcast is E23)");

    /* receipts that disagree */
    g_st[0].rc_mode = 1; g_st[0].rc.status = 1; g_st[0].rc.block_number = 900;
    g_st[1].rc_mode = 1; g_st[1].rc.status = 0; g_st[1].rc.block_number = 900;
    g_st[2].rc_mode = 0;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && swap_state_is(s.seq, "payout_pending"),
          "status 1, status 0 and no receipt: no two agree: UNKNOWN, nothing moves");
    g_st[1].rc.status = 1;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid"),
          "two identical receipts (Q = 2) settle it");
    amm_eth_pay_free(p);

    /* the tip is the Q-th largest */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup");
    for (int i = 0; i < NP; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 900; }
    g_st[0].tip = 5000; g_st[1].tip = 901; g_st[2].tip = 901;        /* one liar high, two honest at depth 1 */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 0 && swap_state_is(s.seq, "payout_pending"),
          "tips 5000, 901, 901 with Q = 2: the 2nd largest is 901: depth 1, not final");
    g_st[1].tip = 903; g_st[2].tip = 903;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1, "depth 3 on the quorum: final");
    amm_eth_pay_free(p);
}

static void e12_paused(void) {
    printf("E12 payouts_paused\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 1);
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup: a paused payer");
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_PAUSED && !has_attempt(s.seq) && g_st[0].est_calls == 0,
          "paused: nothing is signed (no read is even made)");
    amm_eth_pay_free(p);
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK, "unpaused: signed");
    amm_eth_pay_free(p);
    p = new_pay_n(1, 1, 3, 1);
    CHECK(p && amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_PAUSED && sends() == 0, "paused: a signed attempt is not broadcast");
    g_st[0].rc_mode = 1; g_st[0].rc.status = 1; g_st[0].rc.block_number = 900;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid"),
          "settlement still runs while paused");
    amm_eth_pay_free(p);
}

static void e13_guards(void) {
    printf("E13 guards and configuration\n");
    fresh();
    amm_eth_pay_t *p = new_pay();
    amm_swap_t s, u;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup");
    CHECK(amm_eth_pay_sign(p, s.seq, 0, 0, &o) == AMM_EP_ERR, "a zero gross is refused");
    CHECK(amm_eth_pay_sign(p, 9999, 1000, 0, &o) == AMM_EP_ERR, "an unknown swap is refused");
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_NEED_SIGN, "no attempt yet: the step says NEED_SIGN");
    CHECK(amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_OK && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_ERR,
          "a second sign of the same swap is refused");
    /* a USDT -> NODUS swap in payout_pending is a NODUS payout */
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    char snd[41], dst[129];
    memset(snd, 'a', 40); snd[40] = 0; memset(dst, 'b', 128); dst[128] = 0;
    a.dir = AMM_USDT_TO_NODUS; a.sender = snd; a.dest = dst; a.amount = 5; a.minimum = 1; a.value_usdt = 1;
    a.approved_at = 1; a.expiry = 100; a.approved_tip = 5; a.incoming_id = ""; a.req_no[31] = 77; a.rand16[0] = 77;
    a.swap_max = 100; a.inflight_max = 100;
    CHECK(amm_journal_approve(g_j, &a, &u) == AMM_J_OK &&
          amm_journal_swap_seen(g_j, u.seq, "eth:77", NULL, 500000000ULL, 0, NULL) == 0 &&
          amm_journal_swap_transition(g_j, u.seq, "counted", NULL, NULL, NULL) == 0 &&
          amm_journal_swap_transition(g_j, u.seq, "payout_pending", NULL, NULL, NULL) == 0, "setup: a NODUS payout");
    CHECK(amm_eth_pay_sign(p, u.seq, 1000, 0, &o) == AMM_EP_ERR && amm_eth_pay_step(p, u.seq, 0, &o) == AMM_EP_ERR,
          "a swap that owes no USDT payout is refused");
    amm_eth_pay_free(p);

    amm_eth_pay_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.providers = g_prov; c.n_providers = 1; c.quorum = 1;
    c.price.ctx = &g_price; c.price.fee_usdt = s_price;
    c.chain_id = 1;
    c.journal = g_j; c.sk = g_key; memcpy(c.usdt, g_usdt, 20); c.final_depth = 3;
    amm_eth_pay_t *q = amm_eth_pay_new(&c);
    CHECK(q != NULL, "a good configuration builds");
    amm_eth_pay_free(q);
    amm_eth_pay_cfg_t b = c;
    b.chain_id = 0;  CHECK(amm_eth_pay_new(&b) == NULL, "no chain id (the setting eth_chain_id): refused");
    b.final_depth = 0;  CHECK(amm_eth_pay_new(&b) == NULL, "no final depth (a required setting, no default): refused");
    b = c; b.quorum = 2; CHECK(amm_eth_pay_new(&b) == NULL, "a quorum above the providers: refused");
    b = c; b.quorum = 0; CHECK(amm_eth_pay_new(&b) == NULL, "a quorum of zero: refused");
    b = c; b.price.fee_usdt = NULL; CHECK(amm_eth_pay_new(&b) == NULL, "no price seam: refused");
    b = c; b.journal = NULL; CHECK(amm_eth_pay_new(&b) == NULL, "no journal: refused");
    b = c; b.sk = NULL; CHECK(amm_eth_pay_new(&b) == NULL, "no key: refused");
    uint8_t zero[32] = {0};
    b = c; b.sk = zero; CHECK(amm_eth_pay_new(&b) == NULL, "an invalid secret key: refused");
    b = c; b.n_providers = 0; CHECK(amm_eth_pay_new(&b) == NULL, "no provider: refused");
    amm_eth_provider_t half = g_prov[0];
    half.send_raw = NULL;
    b = c; b.providers = &half; CHECK(amm_eth_pay_new(&b) == NULL, "a provider without the broadcast call: refused");
    half = g_prov[0]; half.estimate_gas = NULL;
    b = c; b.providers = &half; CHECK(amm_eth_pay_new(&b) == NULL, "a provider without the estimate call: refused");
    half = g_prov[0]; half.base_fee = NULL;
    b = c; b.providers = &half; CHECK(amm_eth_pay_new(&b) == NULL, "a provider without the base fee call (fee rule F1): refused");
    half = g_prov[0]; half.max_priority_fee = NULL;
    b = c; b.providers = &half; CHECK(amm_eth_pay_new(&b) == NULL, "a provider without the priority fee call: refused");
    half = g_prov[0]; half.gas_price = NULL;
    b = c; b.providers = &half;
    amm_eth_pay_t *nq = amm_eth_pay_new(&b);
    CHECK(nq != NULL, "a provider without eth_gasPrice builds: the payer no longer reads it");
    amm_eth_pay_free(nq);
}

/* a payout (dir 1) or refund (dir 0) of 1,000,000 signed, broadcast, then its
 * status-1 receipt (block 900, tip 1000, depth 100) with `mode` logs, one step */
static int settle(int mode, int dir, amm_swap_t *s, amm_ep_step_t *o) {
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    if (!p || !new_swap(dir, dir ? 'c' : '2', dir ? '1' : 'e', 0, s) ||
        amm_eth_pay_sign(p, s->seq, 1000000, 0, o) != AMM_EP_OK ||
        amm_eth_pay_step(p, s->seq, 0, o) != AMM_EP_OK) { amm_eth_pay_free(p); return -99; }
    g_st[0].rc_mode = 1;
    g_st[0].rc.status = 1; g_st[0].rc.block_number = 900;
    g_st[0].log_mode = mode;
    int rc = amm_eth_pay_step(p, s->seq, 0, o);
    amm_eth_pay_free(p);
    return rc;
}

static int attempt_state_is(int64_t seq, const char *st) {
    amm_eattempt_t a;
    int ok = amm_journal_eth_attempt_latest(g_j, seq, &a) == 0 && !strcmp(a.state, st);
    if (ok) amm_eattempt_free(&a);
    return ok;
}

static void e14_transfer_log(void) {
    printf("E14 the receipt's USDT Transfer log (plan line 264)\n");
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(settle(0, 1, &s, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid") &&
          attempt_state_is(s.seq, "confirmed"), "status 1 and the Transfer log (bot -> destination, the value sent): paid");
    CHECK(settle(0, 0, &s, &o) == AMM_EP_OK && swap_state_is(s.seq, "refunded"), "the same for a refund: refunded");

    struct { int mode; const char *what; } miss[] = {
        { 1, "no logs at all" },
        { 2, "a Transfer to ANOTHER recipient" },
        { 4, "two Transfers to the recipient (not exactly one)" },
        { 5, "more logs than the table keeps (the result cannot be shown)" },
        { 6, "a Transfer-shaped log of ANOTHER emitter" },
        { 7, "a log with 31 bytes of data (not a Transfer)" },
        { 8, "a Transfer from the WRONG SENDER (not the bot)" },
    };
    for (size_t i = 0; i < sizeof(miss) / sizeof(miss[0]); i++) {
        char m[160];
        snprintf(m, sizeof(m), "status 1 with %s: NO_LOG, the attempt and the swap are unknown", miss[i].what);
        int rc = settle(miss[i].mode, 1, &s, &o);
        CHECK(rc == AMM_EP_NO_LOG && o.worked == 1 && swap_state_is(s.seq, "unknown") &&
              attempt_state_is(s.seq, "unknown") && !o.confirmed, m);
    }
    /* the bot stops: unknown refuses new approvals */
    settle(1, 1, &s, &o);
    amm_swap_t t;
    amm_approve_t ap;
    memset(&ap, 0, sizeof(ap));
    char snd[41], dst[129];
    memset(snd, 'a', 40); snd[40] = 0; memset(dst, 'b', 128); dst[128] = 0;
    ap.dir = AMM_USDT_TO_NODUS; ap.sender = snd; ap.dest = dst; ap.amount = 5; ap.minimum = 1;
    ap.value_usdt = 1; ap.approved_at = 1; ap.expiry = 100; ap.approved_tip = 5; ap.incoming_id = "";
    ap.req_no[31] = 98; ap.rand16[0] = 98; ap.swap_max = 100; ap.inflight_max = 100;
    CHECK(amm_journal_approve(g_j, &ap, &t) == AMM_J_STOPPED, "and the journal refuses new approvals");
    CHECK(settle(1, 0, &s, &o) == AMM_EP_NO_LOG && swap_state_is(s.seq, "unknown"), "a refund without its log is unknown too");

    /* a TetherToken fee: the recipient gets less than was sent */
    int rc = settle(3, 1, &s, &o);
    amm_swap_t g;
    CHECK(rc == AMM_EP_HELD && o.worked == 1 && !o.confirmed && swap_state_is(s.seq, "held") &&
          attempt_state_is(s.seq, "confirmed"), "logged value below the value sent: the swap is HELD, the attempt confirmed");
    CHECK(amm_journal_swap_by_seq(g_j, s.seq, &g) == 0 && strstr(g.message, "999895") != NULL &&
          strstr(g.message, "999900") != NULL, "the message carries the delivered value (999895) and the value sent (999900)");
    CHECK(strstr(o.msg, "999895") != NULL, "and so does the step's message");
    CHECK(settle(3, 0, &s, &o) == AMM_EP_HELD && swap_state_is(s.seq, "held"), "a refund with a fee is held too");
    /* an oversized logged value (2^64 + 999,900): held, and the FULL value is in the message:
     * 32 bytes = 23 zero bytes (46 hex zeros), 0x01, then 0x00000000000f41dc (999,900 = 0xf41dc) */
    rc = settle(9, 1, &s, &o);
    CHECK(rc == AMM_EP_HELD && swap_state_is(s.seq, "held") &&
          amm_journal_swap_by_seq(g_j, s.seq, &g) == 0 &&
          strstr(g.message, "0x0000000000000000000000000000000000000000000000" "01" "00000000000f41dc") != NULL &&
          strstr(g.message, "999900") != NULL && strstr(o.msg, "00000000000f41dc") != NULL,
          "an oversized logged value is held with its full 32-byte value as hex in the message");
    {
        amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
        CHECK(p && amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ERR, "a held swap owes nothing more here (what follows is DEFERRED)");
        amm_eth_pay_free(p);
    }
}

static void e15_joint_depth(void) {
    printf("E15 settlement depth is a joint vote (plan line 252)\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: Q = 2, final depth 3, a payout broadcast");
    for (int i = 0; i < 2; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 100; }
    g_st[2].rc_mode = 0;                                   /* C has no receipt */
    g_st[0].tip = 102; g_st[1].tip = 103; g_st[2].tip = 103;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && !o.confirmed &&
          swap_state_is(s.seq, "payout_pending"),
          "receipts from A and B (block 100), tips A = 102, B = 103, C = 103: only B supports both: NOT settled");
    g_st[0].tip = 103;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid"),
          "A at 103 too: two providers hold the receipt AND the depth: settled");
    amm_eth_pay_free(p);

    /* receipts that differ in their logs are different receipts: no quorum */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup again");
    for (int i = 0; i < 2; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 100; }
    g_st[0].log_mode = 0; g_st[1].log_mode = 3;
    g_st[2].rc_mode = 0;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && swap_state_is(s.seq, "payout_pending"),
          "A logs the full value, B a smaller one, C nothing: no two agree: UNKNOWN, nothing moves");
    amm_eth_pay_free(p);

    /* receipts whose logs differ ONLY in the digest of the whole data (a tail
     * beyond the first 32 bytes): different receipts, no quorum */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: Q = 2");
    for (int i = 0; i < 2; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 100; }
    g_st[0].log_mode = 0; g_st[1].log_mode = 10;
    g_st[2].rc_mode = 0;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && swap_state_is(s.seq, "payout_pending"),
          "logs equal in the first 32 bytes but with different whole-data digests: not one group: UNKNOWN");
    g_st[1].log_mode = 0;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1, "identical logs (control): settles");
    amm_eth_pay_free(p);
}

static void e16_gas_bump(void) {
    printf("E16 the gas bump: rounding and the overflow guard\n");
    amm_swap_t s;
    amm_ep_step_t o;
    amm_eattempt_t a;
    /* Boltz bumpGasLimit (g x 125 + 99) / 100 with (g x 125) % 100 != 0: estimate
     * 21001 -> 21001 x 125 = 2,625,125; + 99 = 2,625,224; / 100 = 26,252 (the exact
     * 26,251.25 rounded UP). fee = gas x 1 = 26,252; net = 1,000,000 - 26,252 = 973,748;
     * the estimate does not depend on the amount, so round 2 gives the same: fixed. */
    fresh();
    amm_eth_pay_t *p = new_pay();
    g_price.mode = 1; g_price.mul = 1;
    for (int i = 0; i < NP; i++) g_st[i].gas_base = 21001;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.gas_limit == 26252 && a.fee == 26252 &&
          a.net == 973748 && g_price.last_gas == 26252,
          "estimate 21001 (x125 % 100 != 0): bumped to 26252 (rounded up), fee 26252, net 973748");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);

    /* the guard: (UINT64_MAX - 99) / 125 = 147,573,952,589,676,412 (125 x that =
     * 18,446,744,073,709,551,500, remainder 16); one above must not be multiplied */
    fresh();
    p = new_pay();
    for (int i = 0; i < NP; i++) g_st[i].gas_base = 147573952589676413ULL;
    CHECK(p && new_swap(1, 'c', '1', 0, &s), "setup");
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN && !has_attempt(s.seq) &&
          swap_state_is(s.seq, "payout_pending") && g_price.calls == 0 && sends() == 0,
          "an estimate one above (UINT64_MAX - 99) / 125: UNKNOWN, nothing stored, the price never asked");
    /* exactly at the bound the arithmetic does not wrap: bumped (g x 125 + 99) / 100 =
     * (18,446,744,073,709,551,500 + 99) / 100 = 184,467,440,737,095,515, which the bot
     * cannot pay in ether (x 30 gwei): FUNDS, not UNKNOWN, and not a wrapped small limit */
    for (int i = 0; i < NP; i++) g_st[i].gas_base = 147573952589676412ULL;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s.seq) &&
          g_price.last_gas == 184467440737095515ULL,
          "an estimate exactly at the bound: bumped to 184467440737095515 (no wrap), then FUNDS");
    amm_eth_pay_free(p);
}

/* E17: the gas estimate is the Q-th largest answer (Q = 2 of 3), as every other
 * quorum read: one provider can neither raise nor lower it alone. Honest 21000:
 * bumped (21000 x 125 + 99) / 100 = 2,625,099 / 100 = 26,250; fee = 26,250 x 1;
 * net = 1,000,000 - 26,250 = 973,750. A liar answering 10,000,000 (high) or 10
 * (low) leaves the 2nd largest at 21000. Two providers at 40,000 move it: the
 * 2nd largest is 40,000, bumped (40,000 x 125 + 99) / 100 = 5,000,099 / 100 = 50,000. */
static void e17_estimate_quorum(void) {
    printf("E17 the gas estimate: the Q-th largest answer\n");
    amm_swap_t s;
    amm_ep_step_t o;
    amm_eattempt_t a;
    static const uint64_t cases[3][3] = { { 21000, 21000, 10000000 }, { 10, 21000, 21000 },
                                          { 21000, 40000, 40000 } };
    static const uint64_t want[3] = { 26250, 26250, 50000 };
    static const char *what[3] = {
        "one provider estimates 10,000,000: the estimate stays 21000 (bumped 26250)",
        "one provider estimates 10: the estimate stays 21000 (bumped 26250)",
        "two providers estimate 40,000: the 2nd largest moves (bumped 50000)" };
    for (int c = 0; c < 3; c++) {
        fresh();
        amm_eth_pay_t *p = new_pay_n(NP, 2, 3, 0);              /* 3 providers, Q = 2 */
        g_price.mode = 1; g_price.mul = 1;
        for (int i = 0; i < NP; i++) g_st[i].gas_base = cases[c][i];
        int ok = p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
                 amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0;
        CHECK(ok && a.gas_limit == want[c] && g_price.last_gas == want[c] &&
              (c == 2 || (a.fee == 26250 && a.net == 973750)), what[c]);
        if (ok) amm_eattempt_free(&a);
        amm_eth_pay_free(p);
    }
}

/* ═══ E18-E20: the providers of a group are asked at the same time (plan
 *     docs/plans/approved/2026-11-12-bot-round-latency.md 6.2.3, 7.0, 7.1.3) ═══
 *
 * PROVES
 *   E18 arrival order changes nothing. Two scenarios (E10/E1 shape: sign with a
 *       two-round gas fixed point, broadcast, receipts at depth; E15 shape: the
 *       joint depth vote, not settled then settled) run once with no gate and
 *       once for each of chain_id, estimate_gas, erc20_balance, get_balance and
 *       get_receipt with a counting gate in REVERSE mode (tests/amm_test_gate.h:
 *       k = 3, the three providers' calls of a group are in flight at once and
 *       return in descending provider index). Equal in every pair: the returned
 *       codes and step results (fee, net, msg, flags), the stored attempt (raw
 *       bytes, hash, nonce, gas, fee, net, fee fields, state) and the swap state.
 *       timed_out == 0 in every gated run and the gate saw one generation per
 *       group. SCOPING (7.0): a method is gated in a scenario only when the
 *       ungated run shows every provider called it equally often; the test
 *       asserts that every method was gated in at least one scenario.
 *   E19 a provider that answers last with an error: in max_estimate (provider
 *       2's estimate waits until providers 0 and 1 returned theirs, then fails)
 *       and in read_receipt (provider 2's get_receipt waits, then fails): the
 *       verdicts, the stored attempt and the settlement equal those of the run
 *       where provider 2 fails at once.
 *   E19b the unit is the bound: with a receipt at every provider, provider 2's
 *       get_receipt returns at once and its block_number waits until providers
 *       0 and 1 have finished their units; the step returns only after that
 *       second request (provider 2's flag is set when the step returns) and the
 *       depth vote equals the ungated run's (serial code passes this too; it
 *       rules out a join that waits for each unit's first request only).
 *   E20 the joint depth vote under reverse arrival: E15's scenario with the gate
 *       on get_receipt: not settled while only one provider holds both the
 *       receipt and the depth, settled when two do (property 8).
 * FLAGS: none. ENVIRONMENT: none. LEAVES BEHIND: nothing.
 * HOW THEY CAN FALSELY PASS: a pair excluded by the scoping rule is not gated
 *   (the at-least-one assertion shows a method no scenario gated); E19/E19b pass
 *   on a serial implementation by construction; the price stub and the journal
 *   hook are not reached from a provider thread in these scenarios except the
 *   receipt stub's journal read (add_logs), which relies on no transaction region
 *   being open (plan 4.3 assumption 2); Part A does not touch the broadcast, so
 *   the send hook still runs on the calling thread. */
static amm_gate_t g_pg;
static amm_ctr_t  g_pc;
static int        g_pg_ready;

static void pg_ready(void) {
    if (g_pg_ready) return;
    amm_gate_init(&g_pg);
    amm_ctr_init(&g_pc);
    g_pg_ready = 1;
}

static void sig_add(char *sig, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void sig_add(char *sig, size_t cap, const char *fmt, ...) {
    size_t n = strlen(sig);
    if (n >= cap - 1) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(sig + n, cap - n, fmt, ap);
    va_end(ap);
}

static void sig_hex(char *sig, size_t cap, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) sig_add(sig, cap, "%02x", b[i]);
}

static void sig_step(char *sig, size_t cap, const char *tag, int rc, const amm_ep_step_t *o) {
    sig_add(sig, cap, "%s rc%d w%d s%d b%d c%d fee%llu net%llu msg[%s]\n", tag, rc, o->worked, o->signed_, o->submitted,
            o->confirmed, (unsigned long long)o->fee, (unsigned long long)o->net, o->msg);
}

static void sig_attempt(char *sig, size_t cap, int64_t seq) {
    amm_eattempt_t a;
    if (amm_journal_eth_attempt_latest(g_j, seq, &a) != 0) { sig_add(sig, cap, "A none\n"); return; }
    sig_add(sig, cap, "A %s n%d chain%llu nonce%llu gross%llu net%llu fee%llu gas%llu mf%llu mp%llu tip%llu hash=",
            a.state, a.n, (unsigned long long)a.chain_id, (unsigned long long)a.nonce, (unsigned long long)a.gross,
            (unsigned long long)a.net, (unsigned long long)a.fee, (unsigned long long)a.gas_limit,
            (unsigned long long)a.max_fee_per_gas, (unsigned long long)a.max_priority_fee_per_gas,
            (unsigned long long)a.last_submit_tip);
    sig_hex(sig, cap, a.hash, 32);
    sig_add(sig, cap, " raw=");
    sig_hex(sig, cap, a.raw, a.raw_len);
    sig_add(sig, cap, "\n");
    amm_eattempt_free(&a);
}

static void sig_swap(char *sig, size_t cap, int64_t seq) {
    amm_swap_t sw;
    sig_add(sig, cap, "W %s\n", amm_journal_swap_by_seq(g_j, seq, &sw) == 0 ? sw.state : "?");
}

typedef struct {
    char sig[16384];
    int  mcalls[PM_N][NP];
    int  timed_out, gens;
    int  c1, c2, paid1, paid2;          /* E15 shape: confirmed flags and settled states of its two last steps */
    int  returned, calls2;              /* E19: held calls of provider 2 returned / made */
} e18_out_t;

static e18_out_t g_e18_ref, g_e18_gat;

static void e18_counts(e18_out_t *out, int pm_held) {
    for (int i = 0; i < NP; i++)
        for (int m = 0; m < PM_N; m++) out->mcalls[m][i] = g_st[i].mcalls[m];
    out->returned = atomic_load(&g_st[2].hold_returned);
    /* the held calls MADE while the hold was armed (each entered st_hold), not
     * the run-wide mcalls: calls of the same method made before the hold was
     * armed (the sign and broadcast steps read tips and receipts too) are not
     * held calls and are never counted in hold_returned */
    out->calls2 = pm_held >= 0 ? g_st[2].hold_k : 0;
}

/* One run of scenario `scen` (0: E10 / E1 shape, 1: E15 shape); pm < 0: no gate,
 * else every provider's pm method goes through the reverse gate (k = 3). */
static void e18_run(int scen, int pm, e18_out_t *out) {
    memset(out, 0, sizeof(*out));
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    g_price.mode = 1; g_price.mul = 1;                         /* fee = gas */
    for (int i = 0; i < NP; i++) { g_st[i].gas_base = 21000; g_st[i].gas_by_amount = 1; }
    if (!p || !new_swap(1, 'c', '1', 0, &s)) { printf("FATAL e18 setup\n"); exit(2); }
    if (pm >= 0) {
        amm_gate_arm(&g_pg, 3, 1);
        for (int i = 0; i < NP; i++) g_st[i].gate[pm] = &g_pg;
    }
    int rc = amm_eth_pay_sign(p, s.seq, 1000000, 0, &o);
    sig_step(out->sig, sizeof(out->sig), "sign", rc, &o);
    sig_attempt(out->sig, sizeof(out->sig), s.seq);
    rc = amm_eth_pay_step(p, s.seq, 0, &o);                    /* the broadcast */
    sig_step(out->sig, sizeof(out->sig), "send", rc, &o);
    sig_attempt(out->sig, sizeof(out->sig), s.seq);
    if (scen == 0) {
        for (int i = 0; i < NP; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 900; }
        rc = amm_eth_pay_step(p, s.seq, 0, &o);                /* receipts at depth 100 */
        sig_step(out->sig, sizeof(out->sig), "settle", rc, &o);
    } else {
        for (int i = 0; i < 2; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 100; }
        g_st[2].rc_mode = 0;                                   /* C has no receipt */
        g_st[0].tip = 102; g_st[1].tip = 103; g_st[2].tip = 103;
        rc = amm_eth_pay_step(p, s.seq, 0, &o);                /* only B supports both: not settled */
        sig_step(out->sig, sizeof(out->sig), "joint1", rc, &o);
        out->c1 = o.confirmed;
        out->paid1 = swap_state_is(s.seq, "paid");
        g_st[0].tip = 103;
        rc = amm_eth_pay_step(p, s.seq, 0, &o);                /* A and B support both: settled */
        sig_step(out->sig, sizeof(out->sig), "joint2", rc, &o);
        out->c2 = o.confirmed;
        out->paid2 = swap_state_is(s.seq, "paid");
    }
    sig_attempt(out->sig, sizeof(out->sig), s.seq);
    sig_swap(out->sig, sizeof(out->sig), s.seq);
    if (pm >= 0) {
        amm_gate_disarm(&g_pg);
        out->timed_out = amm_gate_timed_out(&g_pg);
        out->gens = amm_gate_gens(&g_pg);
    }
    e18_counts(out, -1);
    amm_eth_pay_free(p);
}

static void e18_arrival_order(void) {
    printf("E18 the providers of a group in flight at once, returning in reverse order: nothing changes\n");
    pg_ready();
    static const int methods[] = { PM_CHAIN, PM_EST, PM_ERC20, PM_BAL, PM_RCPT };
    int gated_runs[PM_N] = { 0 };
    for (int scen = 0; scen < 2; scen++) {
        e18_run(scen, -1, &g_e18_ref);
        for (size_t k = 0; k < sizeof(methods) / sizeof(methods[0]); k++) {
            int pm = methods[k];
            const int *mc = g_e18_ref.mcalls[pm];
            if (mc[0] == 0 || mc[0] != mc[1] || mc[0] != mc[2]) continue;       /* the scoping rule of 7.0 */
            e18_run(scen, pm, &g_e18_gat);
            gated_runs[pm]++;
            char m[160];
            snprintf(m, sizeof(m), "scenario %d, %s gated: all three providers in flight at once (no timeout)", scen, PM_NAME[pm]);
            CHECK(g_e18_gat.timed_out == 0, m);
            snprintf(m, sizeof(m), "scenario %d, %s gated: one gate generation per group (%d)", scen, PM_NAME[pm], mc[0]);
            CHECK(g_e18_gat.gens == mc[0], m);
            snprintf(m, sizeof(m), "scenario %d, %s gated: codes, step results, stored attempt and swap state equal the ungated run",
                     scen, PM_NAME[pm]);
            CHECK(strcmp(g_e18_gat.sig, g_e18_ref.sig) == 0, m);
        }
    }
    for (size_t k = 0; k < sizeof(methods) / sizeof(methods[0]); k++) {
        char m[96];
        snprintf(m, sizeof(m), "%s was gated in at least one scenario", PM_NAME[methods[k]]);
        CHECK(gated_runs[methods[k]] > 0, m);
    }
}

/* E19 / E19b. variant 0: provider 2's estimate fails (E3 shape); 1: provider 2's
 * receipt is an error (E11 shape); 2: a receipt at every provider (E19b).
 * hold = 0: the reference (provider 2 answers at once); 1: it answers last. */
static void e19_run(int variant, int hold, e18_out_t *out) {
    memset(out, 0, sizeof(*out));
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    if (!p || !new_swap(1, 'c', '1', 0, &s)) { printf("FATAL e19 setup\n"); exit(2); }
    amm_ctr_reset(&g_pc);
    int pm_held = variant == 0 ? PM_EST : variant == 1 ? PM_RCPT : PM_TIP;
    int rc;
    if (variant == 0) {
        g_st[2].est_rc = AMM_ETH_ERR;                          /* the last provider fails */
        if (hold) {
            g_st[2].hold_method = pm_held; g_st[2].hold_need = 2; g_st[2].hold_ctr = &g_pc;
            for (int i = 0; i < 2; i++) { g_st[i].unit_method = pm_held; g_st[i].unit_ctr = &g_pc; }
        }
        rc = amm_eth_pay_sign(p, s.seq, 1000000, 0, &o);
        sig_step(out->sig, sizeof(out->sig), "sign", rc, &o);
        sig_attempt(out->sig, sizeof(out->sig), s.seq);
    } else {
        rc = amm_eth_pay_sign(p, s.seq, 1000000, 0, &o);
        sig_step(out->sig, sizeof(out->sig), "sign", rc, &o);
        rc = amm_eth_pay_step(p, s.seq, 0, &o);                /* the broadcast */
        sig_step(out->sig, sizeof(out->sig), "send", rc, &o);
        for (int i = 0; i < 3; i++) { g_st[i].rc_mode = 1; g_st[i].rc.status = 1; g_st[i].rc.block_number = 900; }
        if (variant == 1) g_st[2].rc_mode = 2;                 /* provider 2's receipt read fails */
        if (hold) {
            g_st[2].hold_method = pm_held; g_st[2].hold_need = 2; g_st[2].hold_ctr = &g_pc;
            for (int i = 0; i < 2; i++) { g_st[i].unit_method = pm_held; g_st[i].unit_ctr = &g_pc; }
        }
        rc = amm_eth_pay_step(p, s.seq, 0, &o);                /* receipts at depth 100 */
        sig_step(out->sig, sizeof(out->sig), "settle", rc, &o);
        out->c2 = o.confirmed;
        sig_attempt(out->sig, sizeof(out->sig), s.seq);
        sig_swap(out->sig, sizeof(out->sig), s.seq);
    }
    e18_counts(out, hold ? pm_held : -1);
    amm_eth_pay_free(p);
}

static void e19_late_provider(void) {
    printf("E19 a provider that answers last with an error: the group waits for it, nothing changes\n");
    pg_ready();
    for (int variant = 0; variant < 2; variant++) {
        const char *what = variant == 0 ? "max_estimate (estimate_gas)" : "read_receipt (get_receipt)";
        e19_run(variant, 0, &g_e18_ref);
        e19_run(variant, 1, &g_e18_gat);
        char m[160];
        snprintf(m, sizeof(m), "%s: provider 2 waited for providers 0 and 1 (no timeout)", what);
        CHECK(amm_ctr_timed_out(&g_pc) == 0 && g_e18_gat.calls2 > 0, m);
        snprintf(m, sizeof(m), "%s: the verdicts, the stored attempt and the settlement equal the immediate-error run", what);
        CHECK(strcmp(g_e18_gat.sig, g_e18_ref.sig) == 0, m);
        snprintf(m, sizeof(m), "%s: every held call of provider 2 had returned when the step returned", what);
        CHECK(g_e18_gat.returned == g_e18_gat.calls2, m);
    }
    printf("E19b the unit is the bound: provider 2's second request is waited for\n");
    e19_run(2, 0, &g_e18_ref);
    e19_run(2, 1, &g_e18_gat);
    CHECK(g_e18_ref.c2 == 1, "setup: a receipt at every provider at depth 100: settled (the ungated run)");
    CHECK(amm_ctr_timed_out(&g_pc) == 0 && g_e18_gat.calls2 > 0,
          "provider 2's block_number waited for providers 0 and 1 to finish their units (no timeout)");
    CHECK(strcmp(g_e18_gat.sig, g_e18_ref.sig) == 0 && g_e18_gat.c2 == 1,
          "the step's result, the attempt and the depth vote equal the ungated run (settled)");
    CHECK(g_e18_gat.returned == g_e18_gat.calls2,
          "the step returned only after provider 2's second request returned (its flag is set)");
}

static void e20_joint_depth_reverse(void) {
    printf("E20 the joint depth vote under reverse arrival\n");
    pg_ready();
    e18_run(1, PM_RCPT, &g_e18_gat);
    CHECK(g_e18_gat.timed_out == 0, "get_receipt gated (reverse, k = 3): all three providers in flight at once");
    CHECK(g_e18_gat.c1 == 0 && !g_e18_gat.paid1,
          "receipts from A and B, tips A = 102, B = C = 103: only B supports both: NOT settled");
    CHECK(g_e18_gat.c2 == 1 && g_e18_gat.paid2, "A at 103 too: two providers hold the receipt AND the depth: settled");
}

/* ═══ the Ethereum fee work (evm-fee plan docs/plans/approved/2026-11-13-evm-fee.md) ═══
 *
 * The stubs' fee quote is base fee 11 gwei, tip 2 gwei: the rule F1 signs max fee per gas = 2 x 11 +
 * 2 = 24 gwei (E1, E6, E8 above assert it; `gas_price`, 30 gwei, is a different number the payer
 * must not read). E21-E27 below: the pure functions, the planning functions, the same-bytes
 * broadcast, the stuck payout and its replacement, the re-send after a failure, the refund
 * threshold, the ether and USDT of pending payouts. Flags: none beyond the default build. They
 * leave nothing behind (the journal file is removed with the directory). They can falsely pass only
 * through their stubs: the providers' answers are scripted (a real node's mempool, its replacement
 * rule and a reorganisation are not here), the price is the test's own conversion (mode 2, the
 * seam's formula with a fixed price), the receipts are per hash by a stub switch. */

static void price_conv(uint64_t p_e6) { g_price.mode = 2; g_price.p_e6 = p_e6; }

static void all_base_fee(uint64_t v) { for (int i = 0; i < NP; i++) g_st[i].base_fee = v; }

/* attempt (swap, n) is in `state`, read from the state column through a second connection */
static int att_is(int64_t seq, int n, const char *state) {
    char sql[200];
    int ok = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    snprintf(sql, sizeof(sql), "SELECT 1 FROM eth_attempts WHERE swap_seq=%lld AND n=%d AND state='%s'",
             (long long)seq, n, state);
    if (sqlite3_open(g_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK)
        ok = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

static int head_n(int64_t seq) {
    amm_eattempt_t h;
    memset(&h, 0, sizeof(h));
    int n = amm_journal_eth_attempt_head(g_j, seq, &h) == 0 ? h.n : -1;
    amm_eattempt_free(&h);
    return n;
}

static int count_attempts(int64_t seq) {
    amm_eattempt_t grp[AMM_EA_GROUP_MAX];
    int n = 0;
    int unsettled = amm_journal_eth_attempt_group(g_j, seq, grp, AMM_EA_GROUP_MAX, &n) == 0 ? n : -1;
    for (int i = 0; i < n; i++) amm_eattempt_free(&grp[i]);
    return unsettled;
}

/* the payout row's amount in flight */
static int row_out(int64_t seq, uint64_t paid, uint64_t fee) {
    amm_swap_t s;
    return amm_journal_swap_by_seq(g_j, seq, &s) == 0 && s.out_paid == paid && s.out_fee == fee;
}

static void only_hash(int i, const uint8_t h[32]) { memcpy(g_st[i].rc_only, h, 32); g_st[i].rc_only_on = 1; }
static void rcpt_set(int i, int status, uint64_t block) {
    g_st[i].rc_mode = 1; g_st[i].rc.status = status; g_st[i].rc.block_number = block;
    memset(g_st[i].rc.block_hash, 0x77, 32);
}

static void e21_pure(void) {
    printf("E21 the fee formula and the replacement fields (pure)\n");
    uint64_t mf = 123, pr = 456;
    CHECK(amm_eth_pay_max_fee(11000000000ULL, 2000000000ULL, &mf) == 0 && mf == 24000000000ULL,
          "max fee = 2 x 11 gwei + 2 gwei = 24 gwei");
    CHECK(amm_eth_pay_max_fee(0, 5, &mf) == 0 && mf == 5, "a zero base fee with a tip: the result is the tip");
    mf = 123;
    CHECK(amm_eth_pay_max_fee(0, 0, &mf) != 0 && mf == 123, "a zero result is refused and writes nothing");
    CHECK(amm_eth_pay_max_fee(1, (uint64_t)INT64_MAX + 1, &mf) != 0 && mf == 123,
          "prio = INT64_MAX + 1 is refused (checked first: the bound below is an unsigned subtraction)");
    CHECK(amm_eth_pay_max_fee(0, (uint64_t)INT64_MAX, &mf) == 0 && mf == (uint64_t)INT64_MAX,
          "prio = INT64_MAX with base 0 is accepted");
    CHECK(amm_eth_pay_max_fee(1, (uint64_t)INT64_MAX, &mf) != 0 && mf == (uint64_t)INT64_MAX,
          "prio = INT64_MAX with base 1: 2 + INT64_MAX is above INT64_MAX: refused, nothing written");
    mf = 0;
    CHECK(amm_eth_pay_max_fee(((uint64_t)INT64_MAX - 1) / 2, 1, &mf) == 0 && mf == (uint64_t)INT64_MAX,
          "base = (INT64_MAX - prio) / 2 is accepted (the result is exactly INT64_MAX)");
    mf = 7;
    CHECK(amm_eth_pay_max_fee(((uint64_t)INT64_MAX - 1) / 2 + 1, 1, &mf) != 0 && mf == 7,
          "one above that base is refused");
    CHECK(amm_eth_pay_max_fee(1, 1, NULL) != 0, "a NULL output is refused");

    static const uint64_t in[] = {0, 1, 9, 10, 50, 122, 1000};
    static const uint64_t want[] = {1, 2, 10, 11, 55, 134, 1100};
    int all = 1;
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++)
        if (amm_eth_pay_bump(in[i], &pr) != 0 || pr != want[i]) all = 0;
    CHECK(all, "bump(x) = max(x + 1, floor(x x 110 / 100)): 0, 1, 9, 10, 50, 122, 1000 -> 1, 2, 10, 11, 55, 134, 1100");
    pr = 5;
    CHECK(amm_eth_pay_bump((uint64_t)INT64_MAX, &pr) != 0 && amm_eth_pay_bump((uint64_t)INT64_MAX + 1, &pr) != 0 && pr == 5,
          "a bump above INT64_MAX is refused, nothing written");
    CHECK(amm_eth_pay_bump(8000000000000000000ULL, &pr) == 0 && pr == 8800000000000000000ULL,
          "a large value does not overflow (8e18 -> 8.8e18)");

    uint64_t po = 0;
    /* base 100, tip 5; the old transaction had max fee 200, tip 50: tip max(5, 55) = 55, cap 2 x 100 + 55 = 255 >= bump(200) = 220 */
    CHECK(amm_eth_pay_replacement_fees(100, 5, 200, 50, &mf, &po) == 0 && po == 55 && mf == 255,
          "a fresh tip below bump(old tip) is raised to it (55), the cap follows the formula (255)");
    CHECK(amm_eth_pay_replacement_fees(100, 100, 200, 50, &mf, &po) == 0 && po == 100 && mf == 300,
          "a fresh tip already above bump(old tip) is kept (100), cap 300");
    mf = 9; po = 9;
    CHECK(amm_eth_pay_replacement_fees(10, 5, 200, 50, &mf, &po) != 0 && mf == 9 && po == 9,
          "a cap below bump(old cap) (75 < 220) is refused, nothing written");
    CHECK(amm_eth_pay_replacement_fees(100, 5, 200, (uint64_t)INT64_MAX, &mf, &po) != 0,
          "an old tip whose bump exceeds INT64_MAX is refused");
}

static void e22_plan(void) {
    printf("E22 the planning functions (read-only)\n");
    fresh();
    g_price.mode = 1; g_price.mul = 1;
    for (int i = 0; i < NP; i++) g_st[i].gas_by_amount = 1;       /* the gas depends on the amount: the loop matters */
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_ep_facts_t f;
    amm_ep_plan_t pl;
    amm_ep_prepared_t pre;
    uint8_t rcp[20];
    memset(rcp, 0x11, 20);
    CHECK(p && amm_eth_pay_fee_facts(p, 0, &f) == AMM_EP_OK && f.n_usable == 1 && f.base == 11000000000ULL &&
          f.prio == 2000000000ULL && f.max_fee == 24000000000ULL, "the fee facts: base 11 gwei, tip 2 gwei, max fee 24 gwei, one usable provider");
    int e0 = ests();
    uint64_t nn = 0;
    CHECK(amm_eth_pay_plan(p, &f, rcp, 1000000, 0, 0, &pl) == AMM_EP_OK && pl.verdict == AMM_EP_PAY && pl.fee > 0 &&
          pl.net == 1000000 - pl.fee && pl.gas > 0, "the plan of a payout of 1000000: a verdict PAY with a fee, net = gross - fee");
    CHECK(ests() - e0 == 2, "  the estimate was asked again after the first round (the amount changed): two rounds");
    CHECK(amm_journal_eth_next_nonce(g_j, 1, &nn) == 1 && sends() == 0 && g_price.last_max_fee == 24000000000ULL,
          "  it stored no attempt, allocated no nonce and sent nothing; the price seam was quoted the max fee 24 gwei");
    char r40[41];
    memset(r40, '1', 40);
    r40[40] = '\0';
    CHECK(amm_eth_pay_prepare(p, r40, 1000000, 0, 0, &pre) == AMM_EP_OK &&
          pre.fee == pl.fee && pre.net == pl.net && pre.attempt.gas_limit == pl.gas &&
          pre.attempt.max_fee_per_gas == f.max_fee, "the payout's own preparation gives the same fee, net, gas and max fee");
    amm_ep_prepared_free(&pre);

    CHECK(amm_eth_pay_plan(p, &f, rcp, 0, 0, 0, &pl) == AMM_EP_ERR, "a zero gross is refused (AMM_EP_ERR)");
    g_price.mode = 0; g_price.fixed = 100;
    CHECK(amm_eth_pay_plan(p, &f, rcp, 1000, 950, 0, &pl) == AMM_EP_OK && pl.verdict == AMM_EP_BELOW && pl.fee == 100 && pl.net == 900,
          "below the minimum after the fee: the verdict BELOW (net 900 < 950)");
    g_price.fixed = 1000;
    CHECK(amm_eth_pay_plan(p, &f, rcp, 1000, 0, 0, &pl) == AMM_EP_OK && pl.verdict == AMM_EP_NOTHING && pl.fee == 1000 && pl.net == 0,
          "a fee at the amount: the verdict NOTHING is an answer (readable), not UNKNOWN");
    g_price.fixed = 100;
    g_price.rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_plan(p, &f, rcp, 1000, 0, 0, &pl) == AMM_EP_UNKNOWN, "an unreadable price: UNKNOWN");
    g_price.rc = 0;
    g_st[0].est_rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_plan(p, &f, rcp, 1000, 0, 0, &pl) == AMM_EP_UNKNOWN, "a reverting estimate: UNKNOWN");
    g_st[0].est_rc = 0;
    g_price.mode = 1; g_price.mul = 1;
    g_st[0].est_cycle = 1;
    CHECK(amm_eth_pay_plan(p, &f, rcp, 1000000, 0, 0, &pl) == AMM_EP_UNKNOWN,
          "an estimate that changes at every call has no fixed point in AMM_EP_ITER_MAX rounds: UNKNOWN");
    g_st[0].est_cycle = 0;
    CHECK(!has_attempt(1) && sends() == 0, "none of the plans stored or sent anything");
    amm_eth_pay_free(p);

    /* the facts: below the quorum, a malformed fee, another chain */
    fresh();
    p = new_pay_n(3, 2, 3, 0);
    g_st[0].bf_rc = AMM_ETH_ERR; g_st[1].bf_rc = AMM_ETH_ERR;
    CHECK(p && amm_eth_pay_fee_facts(p, 0, &f) == AMM_EP_UNKNOWN, "the base fee readable from one provider of Q = 2: UNKNOWN");
    g_st[0].bf_rc = 0; g_st[1].bf_rc = 0;
    g_st[0].base_fee = 9000000000ULL; g_st[1].base_fee = 11000000000ULL; g_st[2].base_fee = 20000000000ULL;
    CHECK(amm_eth_pay_fee_facts(p, 0, &f) == AMM_EP_OK && f.base == 11000000000ULL && f.max_fee == 24000000000ULL,
          "base fees 9, 11 and 20 gwei with Q = 2: the 2nd largest (11) is used");
    g_st[0].base_fee = 0; g_st[1].base_fee = 0; g_st[2].base_fee = 0; g_st[0].prio = 0; g_st[1].prio = 0; g_st[2].prio = 0;
    CHECK(amm_eth_pay_fee_facts(p, 0, &f) == AMM_EP_UNKNOWN, "a base fee and a tip of 0 give a zero max fee: UNKNOWN (never a free transaction)");
    g_st[0].base_fee = 11000000000ULL; g_st[1].base_fee = 11000000000ULL; g_st[2].base_fee = 11000000000ULL;
    g_st[0].prio = 2000000000ULL; g_st[1].prio = 2000000000ULL; g_st[2].prio = 2000000000ULL;
    g_st[0].chain = 5; g_st[1].chain = 5;
    CHECK(amm_eth_pay_fee_facts(p, 0, &f) == AMM_EP_UNKNOWN && f.n_usable == 1, "one usable provider (the others on chain 5) < Q: UNKNOWN");
    amm_eth_pay_free(p);

    /* the pause does not stop the planning (the price question answers while payouts are paused) */
    fresh();
    p = new_pay_n(1, 1, 3, 1);
    CHECK(p && amm_eth_pay_fee_facts(p, 0, &f) == AMM_EP_OK && amm_eth_pay_plan(p, &f, rcp, 1000, 0, 0, &pl) == AMM_EP_OK &&
          pl.verdict == AMM_EP_PAY, "while payouts_paused is set the planning functions still answer");
    CHECK(amm_eth_pay_prepare(p, r40, 1000, 0, 0, &pre) == AMM_EP_PAUSED,
          "and the payout's preparation is PAUSED");
    amm_ep_prepared_free(&pre);
    amm_eth_pay_free(p);
}

static void e23_same_bytes(void) {
    printf("E23 a submitted attempt is sent again as the same bytes, once per new block\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1 && sends() == 3,
          "setup: signed, broadcast to the three providers at tip 1000 (submitted)");
    amm_eattempt_t a;
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.last_submit_tip == 1000, "its last broadcast tip is 1000");
    int sd = sends();
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd && o.worked == 0,
          "the same block (tip 1000): not sent again");
    for (int i = 0; i < NP; i++) g_st[i].tip = 1001;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd + 3 && o.worked == 1 && o.submitted == 0,
          "a new block (tip 1001): sent again to EVERY usable provider, the state unchanged");
    uint8_t raw0[512];
    size_t rl = g_st[0].last_raw_len;
    memcpy(raw0, g_st[0].last_raw, rl < sizeof(raw0) ? rl : sizeof(raw0));
    CHECK(rl == a.raw_len && !memcmp(raw0, a.raw, rl) && !memcmp(g_st[2].last_raw, a.raw, rl),
          "  the bytes are the SAME stored bytes (byte for byte), not a rebuilt transaction");
    amm_eattempt_free(&a);
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "submitted") && a.last_submit_tip == 1001 && a.n == 1,
          "  still submitted, attempt 1, last broadcast tip 1001");
    amm_eattempt_free(&a);
    sd = sends();
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd, "tip 1001 again: not sent again");
    for (int i = 0; i < NP; i++) { g_st[i].tip = 1002; g_st[i].send_rc = AMM_ETH_ERR; }
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd + 3,
          "tip 1002 with every provider refusing the bytes: sent, answers ignored");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && !strcmp(a.state, "submitted") && a.last_submit_tip == 1002,
          "  it stays submitted and the broadcast is recorded");
    amm_eattempt_free(&a);
    sd = sends();
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd, "tip 1002 again: not sent again even though nobody took it");
    amm_eth_pay_free(p);
    /* paused: a submitted attempt is not sent again either (payouts_paused broadcasts nothing) */
    p = new_pay_n(3, 2, 3, 1);
    for (int i = 0; i < NP; i++) { g_st[i].tip = 1003; g_st[i].send_rc = 0; }
    sd = sends();
    CHECK(p && amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && sends() == sd, "payouts_paused: no rebroadcast of a submitted attempt");
    amm_eth_pay_free(p);
}

/* A payout of `gross` signed at the stub quote (base 11 gwei, tip 2 gwei: max fee 24 gwei, gas 75000,
 * price conversion with P_e6 = 10^9: fee = 75000 x 24 gwei x 10^9 / 10^18 = 1,800,000 raw) and
 * broadcast (submitted at tip 1000). The payer is returned (the journal is the test's). */
static amm_eth_pay_t *stuck_payer(amm_swap_t *s, uint64_t gross) {
    fresh();
    price_conv(1000000000ULL);
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_ep_step_t o;
    if (!p || !new_swap(1, 'c', '1', 0, s) || amm_eth_pay_sign(p, s->seq, gross, 0, &o) != AMM_EP_OK ||
        amm_eth_pay_step(p, s->seq, 0, &o) != AMM_EP_OK || !o.submitted) {
        printf("FATAL stuck_payer\n");
        exit(2);
    }
    return p;
}

/* The same payout, stuck (base fee 30 gwei) and REPLACED: attempt 1 `replaced` (max fee 24 gwei, net
 * 98,200,000), attempt 2 `signed` (tip max(2 gwei, bump = 2.2 gwei) = 2.2 gwei, max fee 2 x 30 + 2.2 =
 * 62.2 gwei, fee 75000 x 62.2 gwei x 10^9 / 10^18 = 4,665,000, net 95,335,000). The hashes are returned. */
static amm_eth_pay_t *replaced_group(amm_swap_t *s, uint8_t h1[32], uint8_t h2[32]) {
    amm_eth_pay_t *p = stuck_payer(s, 100000000ULL);
    amm_ep_step_t o;
    all_base_fee(30000000000ULL);
    amm_eattempt_t g[AMM_EA_GROUP_MAX];
    int n = 0;
    if (amm_eth_pay_replace(p, s->seq, 0, &o) != AMM_EP_OK || !o.worked ||
        amm_journal_eth_attempt_group(g_j, s->seq, g, AMM_EA_GROUP_MAX, &n) != 0 || n != 2) {
        printf("FATAL replaced_group\n");
        exit(2);
    }
    memcpy(h1, g[0].hash, 32);
    memcpy(h2, g[1].hash, 32);
    for (int i = 0; i < n; i++) amm_eattempt_free(&g[i]);
    return p;
}

static void e24_stuck_replace(void) {
    printf("E24 a stuck payout is replaced with the same nonce\n");
    amm_swap_t s;
    amm_ep_step_t o;
    amm_eattempt_t a;
    uint8_t h1[32], h2[32];
    amm_eth_pay_t *p = stuck_payer(&s, 100000000ULL);
    CHECK(row_out(s.seq, 98200000, 1800000), "setup: a submitted payout, gross 100,000,000, fee 1,800,000, net 98,200,000");

    /* the trigger: the base fee strictly above the head's max fee per gas (24 gwei) */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "base fee 11 gwei: not stuck");
    all_base_fee(24000000000ULL);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "base fee 24 gwei == the max fee: not stuck (the transaction is valid at an equal base fee)");
    all_base_fee(24000000001ULL);
    int sd = sends();
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_STUCK && o.worked == 0 && sends() == sd && count_attempts(s.seq) == 1 &&
          att_is(s.seq, 1, "submitted"), "base fee 24 gwei + 1: STUCK, and the step wrote and sent nothing");
    for (int i = 0; i < NP; i++) g_st[i].bf_rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "a base fee that cannot be read replaces nothing (not STUCK)");
    for (int i = 0; i < NP; i++) g_st[i].bf_rc = 0;
    all_base_fee(11000000000ULL);
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && count_attempts(s.seq) == 1,
          "replace with a base fee back at 11 gwei: the trigger no longer holds, nothing stored");
    all_base_fee(30000000000ULL);
    rcpt_set(0, 1, 900);                                       /* the head has a receipt */
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && count_attempts(s.seq) == 1,
          "replace when a receipt exists for the head: not stuck, nothing stored");
    g_st[0].rc_mode = 0;
    g_st[0].cnt_latest = 1;                                    /* the nonce is used */
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && count_attempts(s.seq) == 1,
          "replace when the confirmed nonce is above the head's: nothing stored (the step orphans it)");
    g_st[0].cnt_latest = 0;

    /* the replacement */
    sd = sends();
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 1 && o.signed_ == 1 && o.fee == 4665000 &&
          o.net == 95335000 && sends() == sd, "replace at base 30 gwei: signed and stored, fee 4,665,000, net 95,335,000, nothing sent");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.n == 2 && a.nonce == 0 && a.gross == 100000000 &&
          a.net == 95335000 && a.fee == 4665000 && a.max_priority_fee_per_gas == 2200000000ULL &&
          a.max_fee_per_gas == 62200000000ULL && a.gas_limit == 75000 && !strcmp(a.state, "signed"),
          "attempt 2: the same nonce and gross, tip max(2, bump 2.2) = 2.2 gwei, max fee 2 x 30 + 2.2 = 62.2 gwei, state signed");
    dec_t d;
    CHECK(decode(a.raw, a.raw_len, &d) == 0 && be_u64(d.f[1], d.l[1]) == 0 && be_u64(d.f[3], d.l[3]) == 62200000000ULL &&
          be_u64(d.f[2], d.l[2]) == 2200000000ULL && recovers_to_self(a.raw, a.raw_len, &d),
          "  the stored bytes carry those fields and the old nonce, and recover to the bot");
    amm_eattempt_free(&a);
    CHECK(att_is(s.seq, 1, "replaced") && head_n(s.seq) == 2 && row_out(s.seq, 95335000, 4665000),
          "attempt 1 is `replaced`, the head is attempt 2, the row shows the amount in flight (95,335,000 / 4,665,000)");
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1 && sends() == sd + 1,
          "the next step broadcasts the replacement (one send to the one provider)");
    {
        amm_eattempt_t g2[AMM_EA_GROUP_MAX];
        int ng = 0;
        CHECK(amm_journal_eth_attempt_group(g_j, s.seq, g2, AMM_EA_GROUP_MAX, &ng) == 0 && ng == 2 &&
              g_st[0].last_raw_len == g2[1].raw_len && !memcmp(g_st[0].last_raw, g2[1].raw, g2[1].raw_len),
              "  the bytes sent are the replacement's stored bytes");
        for (int i = 0; i < ng; i++) amm_eattempt_free(&g2[i]);
    }
    amm_eth_pay_free(p);

    /* every settlement outcome of the group (the receipts are per hash) */
    p = replaced_group(&s, h1, h2);
    only_hash(0, h2); rcpt_set(0, 1, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid") &&
          att_is(s.seq, 2, "confirmed") && att_is(s.seq, 1, "voided") && row_out(s.seq, 95335000, 4665000),
          "the replacement lands: confirmed, the swap paid, the replaced attempt voided, out_paid = its net");
    amm_eth_pay_free(p);
    p = replaced_group(&s, h1, h2);
    only_hash(0, h1); rcpt_set(0, 1, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid") &&
          att_is(s.seq, 1, "confirmed") && att_is(s.seq, 2, "voided") && row_out(s.seq, 98200000, 1800000),
          "the REPLACED attempt lands: confirmed with its own net (98,200,000), the replacement voided");
    amm_eth_pay_free(p);
    p = replaced_group(&s, h1, h2);
    only_hash(0, h1); rcpt_set(0, 0, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_FAILED && o.worked == 1 && att_is(s.seq, 1, "failed") &&
          att_is(s.seq, 2, "voided") && head_n(s.seq) == 1 && swap_state_is(s.seq, "payout_pending"),
          "the replaced attempt lands and FAILS: it is `failed` (the head), the replacement voided, the swap owed");
    g_st[0].rc_only_on = 0; g_st[0].rc_mode = 0;
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_OK && o.signed_ == 1 && o.fee == 4650000 && o.net == 93550000 &&
          count_attempts(s.seq) == 1 && head_n(s.seq) == 3 &&
          amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.gross == 98200000 && a.nonce == 1,
          "the re-send takes gross = the replaced attempt's net (98,200,000), a new nonce 1, fee 4,650,000 at base 30 gwei");
    amm_eattempt_free(&a);
    amm_eth_pay_free(p);
    p = replaced_group(&s, h1, h2);
    memcpy(g_st[0].rc_err, h2, 32); g_st[0].rc_err_on = 1;
    sd = sends();
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && o.worked == 0 && sends() == sd &&
          att_is(s.seq, 1, "replaced") && att_is(s.seq, 2, "signed") && swap_state_is(s.seq, "payout_pending"),
          "a receipt not readable for one member: UNKNOWN, nothing changes, nothing sent");
    g_st[0].rc_err_on = 0;
    rcpt_set(0, 1, 900);                                       /* the same receipt for every hash: two members found */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && att_is(s.seq, 2, "signed") && att_is(s.seq, 1, "replaced"),
          "a receipt for TWO attempts of one nonce cannot both be true: UNKNOWN, nothing changes");
    g_st[0].rc_mode = 0;
    g_st[0].cnt_latest = 1;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ORPHANED && att_is(s.seq, 2, "orphaned") && att_is(s.seq, 1, "voided") &&
          swap_state_is(s.seq, "unknown"), "no receipt and the nonce used: the head orphaned, the replaced attempt voided, the swap unknown");
    amm_eth_pay_free(p);

    /* what stops a replacement */
    p = stuck_payer(&s, 4000000);                              /* fee 1,800,000 < 4,000,000: net 2,200,000 */
    all_base_fee(30000000000ULL);
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_ZERO && count_attempts(s.seq) == 1 && att_is(s.seq, 1, "submitted") &&
          head_n(s.seq) == 1, "nothing left after the replacement's fee (4,665,000 >= 4,000,000): ZERO, the old attempt stays");
    amm_eth_pay_free(p);
    p = stuck_payer(&s, 100000000ULL);
    all_base_fee(30000000000ULL);
    amm_eth_pay_t *pp = new_pay_n(1, 1, 3, 1);
    CHECK(pp && amm_eth_pay_replace(pp, s.seq, 0, &o) == AMM_EP_PAUSED && count_attempts(s.seq) == 1, "payouts_paused: PAUSED, nothing stored");
    amm_eth_pay_free(pp);
    set_be(g_st[0].eth, 4665000000000000ULL - 1);              /* 75000 x 62.2 gwei, one wei short */
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_FUNDS && count_attempts(s.seq) == 1,
          "ether one wei short of the replacement's gas x max fee: FUNDS, nothing stored (the old attempt's own 1.8e15 is not added)");
    set_be(g_st[0].eth, 4665000000000000ULL);
    price_conv(1);                                             /* the ETH price fell: the replacement's fee is 1, its net 99,999,999 > the head's 98,200,000 */
    set_be(g_st[0].usdt, 99999998ULL);
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_FUNDS && count_attempts(s.seq) == 1,
          "USDT 99,999,998 covers the head's net (98,200,000) but not the replacement's (99,999,999): the nonce is counted at the LARGER net: FUNDS");
    set_be(g_st[0].usdt, 99999999ULL);
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 1 && o.net == 99999999 && o.fee == 1,
          "USDT 99,999,999: the replacement is stored (fee 1)");
    amm_eth_pay_free(p);
    p = stuck_payer(&s, 100000000ULL);
    all_base_fee(30000000000ULL);
    for (int i = 0; i < NP; i++) g_st[i].bf_rc = AMM_ETH_ERR;
    CHECK(amm_eth_pay_replace(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 0 && count_attempts(s.seq) == 1,
          "a base fee that cannot be read at the quorum replaces nothing");
    amm_eth_pay_free(p);
}

static void e25_resend(void) {
    printf("E25 a failed payout or refund is sent again\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_swap_t s;
    amm_ep_step_t o;
    amm_eattempt_t a;
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1, "setup: a payout of 1,000,000 (fee 100, net 999,900) broadcast");
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_ERR && count_attempts(s.seq) == 1,
          "re-send while the head is submitted (not failed): AMM_EP_ERR, nothing stored");
    rcpt_set(0, 0, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_FAILED && att_is(s.seq, 1, "failed") && swap_state_is(s.seq, "payout_pending"),
          "attempt 1 fails in a block: FAILED, the swap stays payout_pending");
    int sd = sends();
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_OK && o.worked == 1 && o.signed_ == 1 && o.fee == 100 && o.net == 999800 &&
          sends() == sd, "re-send: stored (fee 100 again, net 999,800), nothing broadcast by it");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && a.n == 2 && a.gross == 999900 && a.net == 999800 && a.fee == 100 &&
          a.nonce == 1 && !strcmp(a.state, "signed") && a.max_fee_per_gas == 24000000000ULL,
          "attempt 2: gross = attempt 1's net (999,900), a NEW nonce (1), the minimum not compared again, max fee from the formula");
    amm_eattempt_free(&a);
    CHECK(att_is(s.seq, 1, "failed") && head_n(s.seq) == 2 && row_out(s.seq, 999800, 200),
          "attempt 1 stays failed, the head is attempt 2, the row shows 999,800 / 200 (both fees deducted)");
    g_st[0].rc_mode = 0;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.submitted == 1 && sends() == sd + 1,
          "the next step broadcasts attempt 2's stored bytes");
    CHECK(amm_journal_eth_attempt_latest(g_j, s.seq, &a) == 0 && g_st[0].last_raw_len == a.raw_len &&
          !memcmp(g_st[0].last_raw, a.raw, a.raw_len), "  the bytes sent are the stored bytes of attempt 2");
    amm_eattempt_free(&a);
    rcpt_set(0, 1, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK && o.confirmed == 1 && swap_state_is(s.seq, "paid") && row_out(s.seq, 999800, 200),
          "attempt 2 lands: the swap is paid, delivered 999,800 (the Transfer log is attempt 2's net)");

    /* a failure again; what cannot be re-sent */
    amm_eth_pay_free(p);
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: another payout broadcast");
    rcpt_set(0, 0, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_FAILED, "it fails");
    g_price.fixed = 999900;                                    /* the fee is at the remainder */
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_ZERO && count_attempts(s.seq) == 0 && head_n(s.seq) == 1 &&
          swap_state_is(s.seq, "payout_pending"), "a remainder (999,900) that cannot cover the fee: ZERO, nothing stored, the swap unmoved");
    g_price.fixed = 100;
    g_st[0].est_rc = AMM_ETH_ERR;
    int pc = g_price.calls;
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_UNKNOWN && head_n(s.seq) == 1 && g_price.calls == pc,
          "an estimate that reverts: UNKNOWN, nothing stored, no fee asked");
    g_st[0].est_rc = 0;
    set_be(g_st[0].usdt, 5);
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_FUNDS && head_n(s.seq) == 1, "the bot's USDT short: FUNDS, nothing stored");
    set_be(g_st[0].usdt, 1000000000000ULL);
    amm_eth_pay_t *pp = new_pay_n(1, 1, 3, 1);
    CHECK(pp && amm_eth_pay_resend(pp, s.seq, 0, &o) == AMM_EP_PAUSED && head_n(s.seq) == 1, "payouts_paused: PAUSED");
    amm_eth_pay_free(pp);
    CHECK(amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_OK && head_n(s.seq) == 2, "unpaused and readable: the SAME payout is stored again (never lost)");
    amm_eth_pay_free(p);

    /* a refund (USDT -> NODUS) is re-sent the same way */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(0, '2', 'e', 0, &s) && amm_eth_pay_sign(p, s.seq, 9000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: a refund of 9000 (fee 100) broadcast");
    rcpt_set(0, 0, 900);
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_FAILED && amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_OK &&
          o.net == 8800 && head_n(s.seq) == 2 && swap_state_is(s.seq, "refund_pending"),
          "a failed refund is re-sent: attempt 2 carries 8800 (9000 - 100 - 100), the swap stays refund_pending");
    amm_eth_pay_free(p);

    /* orphaned and unknown stop the bot: they are not re-sent */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK, "setup: a payout, signed");
    g_st[0].cnt_latest = 5;
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ORPHANED && amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_ERR &&
          count_attempts(s.seq) == 0, "an orphaned head (the swap unknown) is not re-sent");
    amm_eth_pay_free(p);
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK &&
          amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_OK, "setup: a payout, broadcast");
    rcpt_set(0, 1, 900);
    g_st[0].log_mode = 1;                                      /* status 1 and no Transfer log */
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_NO_LOG && amm_eth_pay_resend(p, s.seq, 0, &o) == AMM_EP_ERR &&
          swap_state_is(s.seq, "unknown"), "a head `unknown` (no Transfer log) is not re-sent");
    amm_eth_pay_free(p);
}

/* A USDT refund of `gross` signed at base fee `base` (tip 122 wei, P = 3,000 USD: P_e6 3,000,000,000, the
 * estimate 53,072 bumped to 66,340 gas). Returns amm_eth_pay_sign's result; the journal stays. */
static int refund_at(uint64_t base, uint64_t gross, amm_ep_step_t *o, amm_swap_t *s) {
    fresh();
    price_conv(3000000000ULL);
    for (int i = 0; i < NP; i++) { g_st[i].gas_base = 53072; g_st[i].prio = 122; }
    all_base_fee(base);
    amm_eth_pay_t *p = new_pay();
    int rc = p && new_swap(0, '2', 'e', 0, s) ? amm_eth_pay_sign(p, s->seq, gross, 0, o) : -9;
    amm_eth_pay_free(p);
    return rc;
}

/* E26 (evm-fee plan 7.2, B2): the deducted ceiling is gas limit x max fee, converted and rounded up. The hand
 * arithmetic (python3 -I, plan section 14): 66,340 x 6,000,000,122 x 3e9 / 1e18 = 1,194,120.02 -> 1,194,121;
 * 66,340 x 3,000,000,122 x 3e9 / 1e18 = 597,060.02 -> 597,061. WHAT IT PROVES: at base 3 gwei a 1 USDT
 * refund is ZERO (nothing stored, nothing sent, the swap unmoved, the price seam quoted max fee 6,000,000,122
 * and gas 66,340), at 1.5 gwei it is signed with net 402,939, and the exact boundary is gross == fee ->
 * ZERO, gross == fee + 1 -> net 1. HOW IT FALSELY PASSES: before the fee rule the max fee was the
 * `eth_gasPrice` stub (30 gwei here), so the same numbers cannot come out; a rounding that truncated would
 * give 1,194,120 and fail the boundary. */
static void e26_refund_threshold(void) {
    printf("E26 both sides of the refund threshold, at the F1 max fee\n");
    amm_swap_t s;
    amm_ep_step_t o;
    int rc = refund_at(3000000000ULL, 1000000, &o, &s);
    CHECK(rc == AMM_EP_ZERO && !has_attempt(s.seq) && swap_state_is(s.seq, "refund_pending") && sends() == 0 &&
          o.fee == 1194121 && g_price.last_max_fee == 6000000122ULL && g_price.last_gas == 66340,
          "base 3 gwei (max fee 6,000,000,122): fee 1,194,121; a 1 USDT refund is ZERO (nothing stored, nothing sent, the swap unmoved)");
    rc = refund_at(1500000000ULL, 1000000, &o, &s);
    CHECK(rc == AMM_EP_OK && o.fee == 597061 && o.net == 402939 && g_price.last_max_fee == 3000000122ULL &&
          has_attempt(s.seq), "base 1.5 gwei (max fee 3,000,000,122): fee 597,061, a 1 USDT refund is signed with net 402,939");
    rc = refund_at(3000000000ULL, 1194121, &o, &s);
    CHECK(rc == AMM_EP_ZERO && !has_attempt(s.seq), "the boundary at base 3 gwei: gross 1,194,121 == the fee: ZERO");
    rc = refund_at(3000000000ULL, 1194122, &o, &s);
    CHECK(rc == AMM_EP_OK && o.net == 1 && o.fee == 1194121 && has_attempt(s.seq),
          "gross 1,194,122: signed with net 1");
}

static void e27_pending_funds(void) {
    printf("E27 the ether and the USDT of every pending payout count once per nonce\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(1, 1, 3, 0);
    amm_swap_t s1, s2;
    amm_ep_step_t o;
    CHECK(p && new_swap(1, 'c', '1', 0, &s1) && new_swap(1, 'd', '1', 0, &s2), "setup: two payouts decided in one round");
    set_be(g_st[0].eth, 75000ULL * 24000000000ULL);            /* one payout's gas x max fee: 1.8e15 */
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_OK, "the first payout is signed (ether = its gas x max fee)");
    CHECK(amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s2.seq) && sends() == 0,
          "the second is FUNDS before the first is broadcast: the first's ether is counted");
    set_be(g_st[0].eth, 2 * 75000ULL * 24000000000ULL - 1);
    CHECK(amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_FUNDS, "one wei short of two payouts' ether: FUNDS");
    set_be(g_st[0].eth, 2 * 75000ULL * 24000000000ULL);
    CHECK(amm_eth_pay_sign(p, s2.seq, 1000000, 0, &o) == AMM_EP_OK, "exactly two payouts' ether: signed");
    amm_eth_pay_free(p);

    /* a replaced attempt and its replacement count once, at the larger maximum, in both sums */
    amm_swap_t g;
    uint8_t h1[32], h2[32];
    p = replaced_group(&g, h1, h2);                            /* nonce 0: ether max(1.8e15, 4.665e15), USDT max(98.2e6, 95.335e6) */
    CHECK(new_swap(1, 'd', '1', 0, &s2), "setup: a second payout, decided at base 30 gwei (max fee 62 gwei: gas x max fee 4.65e15, fee 4,650,000, net 95,350,000)");
    set_be(g_st[0].eth, 4665000000000000ULL + 4650000000000000ULL - 1);
    CHECK(amm_eth_pay_sign(p, s2.seq, 100000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s2.seq),
          "ether one wei short of 4.665e15 (the group, once) + 4.65e15: FUNDS");
    set_be(g_st[0].eth, 4665000000000000ULL + 4650000000000000ULL);
    set_be(g_st[0].usdt, 98200000ULL + 95350000ULL - 1);
    CHECK(amm_eth_pay_sign(p, s2.seq, 100000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s2.seq),
          "USDT one unit short of 98,200,000 (the group's larger net, once) + 95,350,000: FUNDS");
    set_be(g_st[0].usdt, 98200000ULL + 95350000ULL);
    CHECK(amm_eth_pay_sign(p, s2.seq, 100000000, 0, &o) == AMM_EP_OK && o.fee == 4650000 && o.net == 95350000,
          "exactly that much of both: signed (had the group been counted twice, this would be FUNDS)");
    amm_eth_pay_free(p);
}

/* E28 (plan 7.2, first payer row): the fee quote through the SIGNING path.
 * WHAT IT PROVES: with Q = 2 of 3 providers, a base fee answered by fewer than Q providers makes
 * amm_eth_pay_sign (a refund) and amm_eth_pay_prepare (a payout) return AMM_EP_UNKNOWN with no attempt
 * stored, no nonce used (the journal has none), nothing sent and no price asked; a quorum base fee above
 * (INT64_MAX - prio) / 2 (the formula's bound) is AMM_EP_UNKNOWN too, again with nothing stored or sent;
 * with the base fee readable again the same refund signs.
 * FLAGS: none. LEAVES BEHIND: nothing. HOW IT COULD FALSELY PASS: the quote is scripted per provider;
 * the unreadable-base case could also fail through another unreadable fact, which the final "signs"
 * check (only the base fee restored) excludes; the bound case uses base = bound + 1 on all providers so
 * the Q-th largest is above it, and the restored base 11 gwei is far below it. */
static void e28_fee_quote_signing_path(void) {
    printf("E28 the fee quote through the signing path\n");
    fresh();
    amm_eth_pay_t *p = new_pay_n(3, 2, 3, 0);
    amm_swap_t s, u;
    amm_ep_step_t o;
    amm_ep_prepared_t pre;
    uint64_t nn = 0;
    char r40[41];
    memset(r40, '1', 40);
    r40[40] = '\0';
    CHECK(p && new_swap(0, '2', 'e', 0, &s) && new_swap(1, 'c', '1', 0, &u), "setup: a refund and a payout swap, three providers, Q = 2");
    g_st[0].bf_rc = AMM_ETH_ERR; g_st[1].bf_rc = AMM_ETH_ERR;          /* one provider of Q = 2 answers */
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN && !has_attempt(s.seq) &&
          amm_journal_eth_next_nonce(g_j, 1, &nn) == 1 && sends() == 0 && g_price.calls == 0,
          "refund: the base fee below the quorum: UNKNOWN, nothing stored, no nonce used, nothing sent, no price asked");
    CHECK(amm_eth_pay_prepare(p, r40, 1000000, 0, 0, &pre) == AMM_EP_UNKNOWN && amm_journal_eth_next_nonce(g_j, 1, &nn) == 1 &&
          sends() == 0 && g_price.calls == 0, "payout: the same through amm_eth_pay_prepare");
    amm_ep_prepared_free(&pre);
    g_st[0].bf_rc = 0; g_st[1].bf_rc = 0;
    const uint64_t bound = ((uint64_t)INT64_MAX - 2000000000ULL) / 2;  /* prio is 2 gwei */
    for (int i = 0; i < NP; i++) g_st[i].base_fee = bound + 1;
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_UNKNOWN && !has_attempt(s.seq) &&
          amm_journal_eth_next_nonce(g_j, 1, &nn) == 1 && sends() == 0 && g_price.calls == 0,
          "refund: a quorum base fee above (INT64_MAX - prio) / 2: UNKNOWN, nothing stored or sent");
    CHECK(amm_eth_pay_prepare(p, r40, 1000000, 0, 0, &pre) == AMM_EP_UNKNOWN && sends() == 0 && g_price.calls == 0,
          "payout: the same through amm_eth_pay_prepare");
    amm_ep_prepared_free(&pre);
    all_base_fee(11000000000ULL);
    CHECK(amm_eth_pay_sign(p, s.seq, 1000000, 0, &o) == AMM_EP_OK && has_attempt(s.seq),
          "with the base fee readable and in range again the same refund signs");
    amm_eth_pay_free(p);
}

int main(void) {
    printf("test_amm_eth_pay\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/amm_ethpay_testXXXXXX");
    if (!mkdtemp(g_dir)) { printf("FATAL mkdtemp\n"); return 2; }
    snprintf(g_path, sizeof(g_path), "%s/journal.db", g_dir);
    init_env();

    e1_persisted_before_broadcast();
    e2_restart_between_store_and_broadcast();
    e3_estimate_failure();
    e4_receipts();
    e5_orphaned();
    e6_balances();
    e7_fee();
    e8_price();
    e9_nonces();
    e10_fixed_point();
    e11_quorum();
    e12_paused();
    e13_guards();
    e14_transfer_log();
    e15_joint_depth();
    e16_gas_bump();
    e17_estimate_quorum();
    e18_arrival_order();
    e19_late_provider();
    e20_joint_depth_reverse();
    e21_pure();
    e22_plan();
    e23_same_bytes();
    e24_stuck_replace();
    e25_resend();
    e26_refund_threshold();
    e27_pending_funds();
    e28_fee_quote_signing_path();

    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
