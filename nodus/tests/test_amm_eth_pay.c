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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_eth_pay.h"
#include "amm_eth_tx.h"
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

typedef struct {
    uint64_t chain; int chain_rc;
    uint64_t tip; int tip_rc;
    uint64_t cnt_pending, cnt_latest; int cnt_rc;
    uint8_t  usdt[32], eth[32]; int usdt_rc, eth_rc;
    uint64_t gas_base; int gas_by_amount; uint64_t gas_per_nz; int est_rc; int est_calls;
    uint64_t gas_price, prio; int gp_rc, prio_rc;
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

static int s_chain(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->chain_rc) return s->chain_rc; *o = s->chain; return AMM_ETH_OK; }
static int s_tip(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->tip_rc) return s->tip_rc; *o = s->tip; return AMM_ETH_OK; }
static void add_logs(stub_t *s, const uint8_t h[32], amm_eth_receipt_t *o);
static int s_receipt(void *c, const uint8_t h[32], amm_eth_receipt_t *o, uint64_t d) {
    stub_t *s = c; (void)d;
    s->rc_calls++;
    if (s->rc_mode == 2) return AMM_ETH_ERR;
    if (s->rc_mode == 0) return AMM_ETH_NOT_FOUND;
    *o = s->rc;
    if (o->status == 1) add_logs(s, h, o);
    return AMM_ETH_OK;
}
static int s_balance(void *c, const uint8_t a[20], uint8_t o[32], uint64_t d) {
    stub_t *s = c; (void)d; (void)a;
    if (s->eth_rc) return s->eth_rc;
    memcpy(o, s->eth, 32);
    return AMM_ETH_OK;
}
static int s_erc20(void *c, const uint8_t t[20], const uint8_t w[20], uint8_t o[32], uint64_t d) {
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
static int s_estimate(void *c, const uint8_t f[20], const uint8_t t[20], const uint8_t *in,
                      size_t n, uint64_t *o, uint64_t d) {
    stub_t *s = c; (void)d; (void)f; (void)t;
    s->est_calls++;
    if (s->est_rc) return s->est_rc;                 /* "execution reverted" */
    *o = s->gas_base + (s->gas_by_amount
        ? (s->gas_per_nz ? s->gas_per_nz : 16u) * (uint64_t)nz_amount(in, n) : 0);
    return AMM_ETH_OK;
}
static int s_gasprice(void *c, uint64_t *o, uint64_t d) { stub_t *s = c; (void)d; if (s->gp_rc) return s->gp_rc; *o = s->gas_price; return AMM_ETH_OK; }
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

/* the price stub: mode 0 = a fixed fee, mode 1 = gas * mul */
typedef struct { int mode; uint64_t fixed, mul; int rc; int calls; uint64_t last_gas, last_max_fee; } price_t;
static int s_price(void *c, uint64_t gas, uint64_t mf, uint64_t *o, uint64_t d) {
    price_t *p = c; (void)d;
    p->calls++;
    p->last_gas = gas; p->last_max_fee = mf;
    if (p->rc) return p->rc;
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
    s->gas_price = 30000000000ULL;
    s->prio = 2000000000ULL;
}

static void fresh(void) {
    if (g_j) { amm_journal_close(g_j); g_j = NULL; }
    unlink(g_path);
    char p[160];
    snprintf(p, sizeof(p), "%s-wal", g_path); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", g_path); unlink(p);
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL open\n"); exit(2); }
    for (int i = 0; i < NP; i++) defaults(&g_st[i]);
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
            .estimate_gas = s_estimate, .gas_price = s_gasprice,
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
    if (amm_journal_swap_transition(g_j, out->seq, "paid_waiting_depth", inc, NULL, NULL) != 0 ||
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
          a.max_fee_per_gas == 30000000000ULL && a.max_priority_fee_per_gas == 2000000000ULL,
          "the attempt is in the journal (signed): nonce 0, gross, net, fee, gas limit, fees");
    uint8_t h[32];
    CHECK(keccak256(a.raw, a.raw_len, h) == 0 && !memcmp(h, a.hash, 32), "its hash is keccak256 of its bytes");
    dec_t d;
    CHECK(decode(a.raw, a.raw_len, &d) == 0, "the stored bytes decode as a type-2 transaction");
    uint8_t want[AMM_TX_TRANSFER_DATA_LEN], user[20];
    memset(user, 0x11, 20);
    amm_tx_transfer_calldata(user, 999900, want);
    CHECK(be_u64(d.f[0], d.l[0]) == 1 && be_u64(d.f[1], d.l[1]) == 0 && d.l[5] == 20 && !memcmp(d.f[5], g_usdt, 20) &&
          d.l[6] == 0 && d.l[7] == 68 && !memcmp(d.f[7], want, 68) && be_u64(d.f[4], d.l[4]) == 75000 &&
          be_u64(d.f[3], d.l[3]) == 30000000000ULL && be_u64(d.f[2], d.l[2]) == 2000000000ULL,
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
     * 75000 x max fee 30 gwei (30,000,000,000) = 2,250,000,000,000,000 wei */
    fresh();
    p = new_pay_n(1, 1, 3, 0);
    CHECK(p && new_swap(1, 'c', '1', 0, &s1), "setup");
    set_be(g_st[0].eth, 2249999999999999ULL);
    CHECK(amm_eth_pay_sign(p, s1.seq, 1000000, 0, &o) == AMM_EP_FUNDS && !has_attempt(s1.seq), "ether 1 wei short of gas x max fee: FUNDS");
    set_be(g_st[0].eth, 2250000000000000ULL);
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
            CHECK(rc == AMM_EP_ZERO && !has_attempt(s.seq) && swap_state_is(s.seq, "refund_pending"),
                  k == 1 ? "fee == amount: nothing signed, the payout moves to refund_pending"
                         : "fee above the amount: nothing signed, the payout moves to refund_pending");
            CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ERR && sends() == 0, "and nothing is ever broadcast");
        }
        amm_eth_pay_free(p);
    }
    /* a USDT refund with fee >= amount is DROPPED, not held (givens items 89,
     * 90); it holds no room afterwards */
    for (int k = 1; k < 3; k++) {
        fresh();
        amm_eth_pay_t *p = new_pay();
        g_price.fixed = fees[k];
        CHECK(p && new_swap(0, '2', 'e', 0, &s) && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_ZERO &&
              !has_attempt(s.seq) && swap_state_is(s.seq, "dropped"),
              k == 1 ? "refund, fee == amount: dropped" : "refund, fee above the amount: dropped");
        amm_eth_pay_free(p);
    }
    /* the minimum after the fee (a payout; fee 100, gross 1000) */
    fresh();
    amm_eth_pay_t *p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 900, &s) && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_OK, "net 900 == minimum 900: pays");
    fresh();
    p = new_pay();
    CHECK(p && new_swap(1, 'c', '1', 901, &s) && amm_eth_pay_sign(p, s.seq, 1000, 0, &o) == AMM_EP_BELOW_MIN &&
          !has_attempt(s.seq) && swap_state_is(s.seq, "refund_pending"),
          "net 900 < minimum 901 (the gross 1000 would pass): nothing signed, refund_pending");
    CHECK(amm_eth_pay_step(p, s.seq, 0, &o) == AMM_EP_ERR && sends() == 0, "and nothing is broadcast");
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
    CHECK(g_price.last_gas == 75000 && g_price.last_max_fee == 30000000000ULL,
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
          "a submitted attempt with no receipt is not rebroadcast (the plan builds no replacement)");

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
          amm_journal_swap_transition(g_j, u.seq, "paid_waiting_depth", "eth:77", NULL, NULL) == 0 &&
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

    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
