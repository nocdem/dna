/**
 * test_amm_eth_watch.c -- the nodus-amm Ethereum watcher (amm_eth_watch.c)
 * against scriptable STUB providers behind the amm_eth.h seam table.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 19 "test_amm_eth_watch", section 9; givens items 17, 22, 54, 55,
 * 58):
 *   W1  quorum: a record counts only when at least Q distinct providers return
 *       it (three providers, Q = 2: one provider failing, or listing nothing,
 *       still reaches it); below the quorum it is a retained CANDIDATE and
 *       never `seen` or `deep`; a candidate is kept while it is unresolved
 *       and promoted when the quorum forms; a fake log listed by one provider
 *       alone is dropped when Q providers answer without it;
 *   W2  disagreement: two providers listing different values for the same
 *       log reach no quorum, nothing is counted, and a later agreement
 *       counts the agreed value;
 *   W3  a failed read is UNKNOWN, never zero: with fewer than Q providers
 *       answering the logs (or the receipts) of a block, the step reports
 *       AMM_W_UNKNOWN, writes no block, no record and does not move the
 *       cursor past it; after recovery the same block is read and the payment
 *       counts (it was not skipped);
 *   W4  chain id: a provider that does not report chain id 1 is not used (its
 *       bogus payment is never seen); with fewer usable providers than Q the
 *       step writes nothing;
 *   W5  depth: a payment in block 10 is `seen` at tip 12 (depth 2) and `deep`
 *       at tip 13 (depth 3); the stored tip is the Q-th largest reported tip
 *       (one provider reporting a high tip cannot move it);
 *   W6  ignored: transferFrom (another sender), a failed receipt, another
 *       token contract, another recipient, a zero amount, a log with the
 *       wrong topic: none is stored;
 *   W7  matching (pure): sender + exact logged value + block height ABOVE the
 *       tip read at approval + block time <= expiry = MATCH; another value =
 *       held (mismatched value); another sender = none; block time after the
 *       expiry = held; a block at or below the approval tip = held
 *       (HELD_EARLY, orchestrator's review finding (a): approval first, then
 *       payment, bound by chain height, no wall clock: height == tip is held,
 *       one above counts); a payment first read after the expiry time but
 *       within it by block time still MATCHes;
 *   W8  reorganisation: a parent-hash mismatch is detected, the changed
 *       heights are found, stored blocks above the common ancestor are
 *       replaced by a rescan; a transaction found again in ANOTHER block
 *       moves its record (state seen, new block hash);
 *   W9  a payment waiting for its depth whose transaction is no longer found
 *       at the quorum is DROPPED and its swap is unpaid again (approved);
 *   W10 reversal of a COUNTED payment and of a PAID payment (and of
 *       payout_pending): detected only through changed stub chain answers
 *       (parent-hash mismatch, then the transaction no longer found at the
 *       quorum), never by writing the `reversed` state: record and swap
 *       `reversed`, `reversal_pause` set (persisted, refuses new approvals);
 *   W11 restart between detection and the journal write: the commit of the
 *       reorganisation fails (test hook), the step reports an error, a
 *       REOPENED journal and a new watcher still hold the old state and the
 *       same mismatch is found again and written;
 *   W12 a reversal deeper than the retained window is NOT detected (the
 *       stated limit): the record below the window stays deep, its swap
 *       stays counted;
 *   W13 window observation (plan section 13, givens item 54): the payment
 *       window of an approval is observed only when the cursor has passed,
 *       on the quorum, a block later than the expiry that is at depth >=
 *       confirmations, and no candidate for that sender and amount is
 *       retained; not observed while reads fail, while the block is too
 *       shallow, or while a candidate is retained; observed after the
 *       candidate resolves; no clock is read (the stub chain advances, wall
 *       time does not matter);
 *   W14 order independence: the same scenario with the provider table
 *       permuted leaves the same records;
 *   W15 restart: a journal reopened and a new watcher continue from the
 *       stored cursor and rescan nothing already written;
 *   W17 depth votes (plan line 252): with Q = 2, providers A and B give the
 *       receipt and B and C report the high tip: only B does both, so the
 *       payment is NOT deep; it becomes deep when A reports a deep tip too;
 *   W18 a false below-quorum candidate (log 0) does not hide the genuine
 *       quorum record (log 1) of the same transaction, whether both are met in
 *       one block or the candidate was stored first; the genuine record
 *       stays after the cursor advanced;
 *   W19 (in W8) the transaction mined again under another log index moves its
 *       record (the old row is dropped, the new one is the only live record);
 *       a second reorganisation bringing the old index back revives it only
 *       after the live row was dropped: one live record per transaction;
 *   W20 a moved transaction takes the quorum's actual logged value of the new
 *       block (5 -> 6): the record carries 6 and matches no approval of 5
 *       (held); a swap waiting for its depth is unpaid again, a counted one
 *       is reversed with the pause;
 *   W21 the permanent marker is the transaction hash: a transaction reversed
 *       and re-mined under log index 1 is a live record again but a second
 *       swap naming it is refused (DUP_TRANSFER) already when it tries to
 *       wait on it, because the reversed swap still carries the id
 *       (review finding (b)); the marker is still held;
 *   W22 a candidate holds an approval's window only when its block time is
 *       within the validity (<= expiry) and its block is above the tip read at
 *       approval: block time 132 blocks expiry 132, not expiry 100; a
 *       candidate in block 11 holds nothing for an approval whose tip is 11 or
 *       12, and holds it for tip 10 (review finding (a));
 *   W6 also covers a self-authorised transferFrom (log from == transaction
 *       sender, selector 23b872dd) and a call without call data: ignored
 *       because the call data must start with the transfer selector a9059cbb
 *       (THORChain direct_erc20_transfer.go:172-174, utils.go:31-36);
 *   W23 the depth helper amm_eth_watch_depth_reached (used for the liquidity
 *       wait of 300) is the same joint vote: Q = 2, payment at height 10,
 *       receipts from A and B, tips A = 13 and B = C = 310: depth 3 is
 *       reached, depth 300 is NOT (the stored global tip minus the block
 *       would read 300), and it is reached once A also reports 310; fewer
 *       than Q usable providers is unknown, not a verdict;
 *   W21 also derives swap 2's marker from the re-mined record itself;
 *   W16 configuration: a quorum of 0 or above the provider count, a window
 *       below the confirmations, no provider function, a zero scan bound are
 *       refused (NULL); also (givens item 60) a window below the LARGEST
 *       count (32 refused, 33 accepted at counts 3 / 5 / 33), a zero count,
 *       a count that decreases, equal or descending bounds refused, equal
 *       counts accepted;
 *   W24 depth by amount (givens item 60, plan section 9; USDT raw units, 6
 *       decimals; "kadar" includes the bound, PLAN READING): the pure count
 *       is 3 for 1 raw unit, 99.999999 and exactly 100 USDT, 5 for 100.000001,
 *       999.999999 and exactly 1,000 USDT, 33 for 1,000.000001, 1,000,000,
 *       the largest u64 and an amount above 64 bits; and the watcher keeps a
 *       payment `seen` one block short of its count and makes it `deep` at
 *       the count (100 USDT 2 / 3, 100.000001 and 1,000 USDT 4 / 5,
 *       1,000.000001 USDT and above-64-bit 32 / 33);
 *   W25 the window rule (plan section 13) waits for the count of the
 *       approval's value v: with the block after the expiry at depth 2 / 3
 *       (v = 100 USDT), 4 / 5 (v = 1,000 USDT), 32 / 33 (v = 1,000.000001
 *       USDT) the window is not observed, then observed.
 * FLAGS: none (a default build; no fault injection, no epoch length).
 * FALSE PASS (W24 / W25): the stub chain is rebuilt with the same hashes at
 *   each step, so the rescan is a no-op and only depth moves; a payment value
 *   is overwritten in the stub log after ch_pay (ch_set_value), so a stub
 *   that ignored the log data would pass the pure count checks only; the
 *   older tests use values of at most 255 raw units, so they prove count 1
 *   (3) alone and say nothing about the other counts, which W24 / W25 prove.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp, removed
 *   at the end; no network, no clock reads by the code under test.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the stub answers what the test scripts; it proves the
 *   watcher's logic against those answers, not an Ethereum node's behaviour
 *   or any real JSON-RPC provider. Block hashes are single bytes repeated 32
 *   times. The commit failure is the journal's test-only pre-commit hook, not
 *   an operating-system fault. Stub providers share chain objects (or hold
 *   their own where a test needs disagreement); the real providers' latency
 *   and deadlines are not modelled (the deadline argument is passed through
 *   and ignored by the stub).
 */
#include <dirent.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_eth_watch.h"
#include "amm_test_gate.h"
#include "nodus_log_shim.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── the stub chain and providers ─────────────────────────────────────── */

#define NB 64
#define NT 16
#define NL 16

typedef struct { int exists; uint8_t hash[32], parent[32]; uint64_t ts; } sblk_t;
typedef struct {
    int used; uint8_t hash[32]; uint8_t from[20], to[20]; int has_to; int status;
    uint64_t bn; uint8_t bh[32];
    uint32_t input_len; uint8_t head[4];     /* call data: length and selector */
} stx_t;
typedef struct { int used; uint64_t block; amm_eth_log_t l; } slog_t;
typedef struct { sblk_t b[NB]; stx_t t[NT]; slog_t g[NL]; uint64_t tip; } chain_t;

typedef struct {
    chain_t *ch;
    uint64_t chain_id;
    int fail_all, fail_logs, fail_tx, fail_receipts, fail_blocks;
    uint64_t tip_override;      /* 0 = the chain's tip                         */
    int calls;
    int asked[64];              /* asked[n] != 0: get_logs was called for block n (W26) */
    int has_also;               /* the provider also holds the block of height also_blk with  */
    uint64_t also_blk;          /* the hash made of 32 bytes of also_byte (W31, W32)           */
    uint8_t also_byte;
    /* W33-W35 (plan 7.1.2): the stub's own index (the gate's provider index), an
     * optional gate per method, calls per method, and the optional hold: this
     * stub's hold_method calls wait until hold_ctr reaches hold_need per call
     * (the other providers' "unit done" counter, bumped by their unit_method
     * calls); hold_returned counts held calls that have returned. The gate and
     * counter objects are the test's; this struct only points at them. */
    int idx;
    amm_gate_t *gate[6];
    int mcalls[6];
    int hold_method, hold_need, hold_k;
    amm_ctr_t *hold_ctr;
    int unit_method;
    amm_ctr_t *unit_ctr;
    atomic_int hold_returned;
} sp_t;

static const uint8_t USDT_B = 0xAA, FOUND_B = 0xF0, OTHER_TOKEN_B = 0xBB,
                     OTHER_RCPT_B = 0xF1;

static const uint8_t TOPIC0[32] = {
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68,
    0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef};

static uint8_t hb(int h, int salt) { return (uint8_t)(h + 50 * salt); }

/* Blocks lo..hi; from `fork_at` on the hashes are those of `salt` (the parent
 * of the fork block is the old chain's block below it). ts = height * 12. */
static void ch_build(chain_t *c, int lo, int hi, int fork_at, int salt) {
    memset(c, 0, sizeof(*c));
    for (int h = lo; h <= hi; h++) {
        int hs = (fork_at && h >= fork_at) ? salt : 0;
        int ps = (fork_at && h - 1 >= fork_at) ? salt : 0;
        c->b[h].exists = 1;
        memset(c->b[h].hash, hb(h, hs), 32);
        memset(c->b[h].parent, hb(h - 1, ps), 32);
        c->b[h].ts = (uint64_t)h * 12;
    }
    c->tip = (uint64_t)hi;
}

/* A payment: a transaction and its log, in block `blk` of the CURRENT chain.
 * `log_from` is the Transfer `from`, `tx_from` the transaction's sender. */
static void ch_pay_full(chain_t *c, uint8_t txb, uint32_t li, int blk,
                        uint8_t log_from, uint8_t tx_from, uint8_t token,
                        uint8_t rcpt, uint8_t value, int status,
                        const uint8_t *topic0) {
    int ti = 0, gi = 0;
    while (ti < NT && c->t[ti].used) ti++;
    while (gi < NL && c->g[gi].used) gi++;
    stx_t *t = &c->t[ti];
    memset(t, 0, sizeof(*t));
    t->used = 1; memset(t->hash, txb, 32); memset(t->from, tx_from, 20);
    memset(t->to, USDT_B, 20); t->has_to = 1; t->status = status;
    t->bn = (uint64_t)blk; memcpy(t->bh, c->b[blk].hash, 32);
    t->input_len = 68;                                  /* transfer(address,uint256) */
    t->head[0] = 0xa9; t->head[1] = 0x05; t->head[2] = 0x9c; t->head[3] = 0xbb;
    slog_t *g = &c->g[gi];
    memset(g, 0, sizeof(*g));
    g->used = 1; g->block = (uint64_t)blk;
    memset(g->l.address, token, 20);
    g->l.n_topics = 3;
    memcpy(g->l.topics[0], topic0, 32);
    memset(g->l.topics[1] + 12, log_from, 20);
    memset(g->l.topics[2] + 12, rcpt, 20);
    g->l.data_len = 32; g->l.data[31] = value;
    g->l.log_index = li;
    memset(g->l.tx, txb, 32);
    g->l.block_number = (uint64_t)blk;
    memcpy(g->l.block_hash, c->b[blk].hash, 32);
}

static void ch_pay(chain_t *c, uint8_t txb, uint32_t li, int blk, uint8_t from,
                   uint8_t value) {
    ch_pay_full(c, txb, li, blk, from, from, USDT_B, FOUND_B, value, 1, TOPIC0);
}

static int sp_chain_id_impl(void *ctx, uint64_t *out, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all) return AMM_ETH_ERR;
    *out = s->chain_id; return AMM_ETH_OK;
}
static int sp_block_number_impl(void *ctx, uint64_t *out, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all) return AMM_ETH_ERR;
    *out = s->tip_override ? s->tip_override : s->ch->tip; return AMM_ETH_OK;
}
static int sp_get_block_impl(void *ctx, uint64_t n, amm_eth_block_t *o, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_blocks) return AMM_ETH_ERR;
    if (n >= NB || n > s->ch->tip || !s->ch->b[n].exists) return AMM_ETH_NOT_FOUND;
    o->number = n; memcpy(o->hash, s->ch->b[n].hash, 32);
    memcpy(o->parent, s->ch->b[n].parent, 32); o->timestamp = s->ch->b[n].ts;
    return AMM_ETH_OK;
}
/* eth_getLogs by BLOCK HASH (filter.yaml:40-59, geth filter.go:83-97): a
 * provider answers about the block of that hash if it holds it, else it is an
 * error (an unknown block). It holds the block when its own chain has that hash
 * at the height, or when the fixture says it also holds it (also_hash). */
static int sp_get_logs_impl(void *ctx, uint64_t blk, const uint8_t *bhash, const uint8_t *contract,
                            const uint8_t *topic0, const uint8_t *to,
                            amm_eth_log_t *out, int cap, int *n, uint64_t d) {
    (void)d; (void)contract; (void)topic0; (void)to; sp_t *s = ctx; s->calls++;
    if (blk < 64) s->asked[blk]++;
    if (s->fail_all || s->fail_logs) return AMM_ETH_ERR;
    int holds = blk < NB && s->ch->b[blk].exists && !memcmp(s->ch->b[blk].hash, bhash, 32);
    if (!holds && s->has_also && blk == s->also_blk) {
        uint8_t ah[32];
        memset(ah, s->also_byte, 32);
        holds = !memcmp(ah, bhash, 32);
    }
    if (!holds) return AMM_ETH_ERR;                    /* unknown block */
    int k = 0;
    /* the stub does NOT filter: the watcher must not trust a provider's filter */
    for (int i = 0; i < NL; i++)
        if (s->ch->g[i].used && s->ch->g[i].block == blk && k < cap)
            out[k++] = s->ch->g[i].l;
    *n = k;
    return AMM_ETH_OK;
}
static stx_t *find_tx(chain_t *c, const uint8_t *h) {
    for (int i = 0; i < NT; i++)
        if (c->t[i].used && !memcmp(c->t[i].hash, h, 32)) return &c->t[i];
    return NULL;
}
static int sp_get_tx_impl(void *ctx, const uint8_t *h, amm_eth_tx_t *o, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_tx) return AMM_ETH_ERR;
    stx_t *t = find_tx(s->ch, h);
    if (!t) return AMM_ETH_NOT_FOUND;
    memcpy(o->from, t->from, 20); memcpy(o->to, t->to, 20); o->has_to = t->has_to;
    o->input_len = t->input_len; memcpy(o->input_head, t->head, 4);
    return AMM_ETH_OK;
}
static int sp_get_receipt_impl(void *ctx, const uint8_t *h, amm_eth_receipt_t *o, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_receipts) return AMM_ETH_ERR;
    stx_t *t = find_tx(s->ch, h);
    if (!t) return AMM_ETH_NOT_FOUND;
    o->status = t->status; o->block_number = t->bn; memcpy(o->block_hash, t->bh, 32);
    return AMM_ETH_OK;
}

/* The seam functions the providers expose: each runs the plain stub body
 * above between the optional gate (tests/amm_test_gate.h), the optional hold
 * (W34, W34b) and the per-method call counter. All of this is per stub and is
 * touched only by the thread that calls the stub (one provider's calls are
 * sequential), plus the test thread between steps. With no gate and no hold the
 * wrappers do nothing but count: no existing assertion changes. */
enum { GM_CHAIN, GM_TIP, GM_BLOCK, GM_LOGS, GM_TX, GM_RECEIPT, GM_N };
static const char *const GM_NAME[GM_N] = { "chain_id", "block_number", "get_block", "get_logs", "get_tx", "get_receipt" };

/* wait (bounded) until the counter says the other providers' units are done */
static void sp_hold(sp_t *s, int gm) {
    if (s->hold_method != gm || !s->hold_ctr) return;
    s->hold_k++;
    (void)amm_ctr_wait_ge(s->hold_ctr, s->hold_need * s->hold_k);
}

/* after the call: set this provider's "unit done" flag, count a held return */
static void sp_after(sp_t *s, int gm) {
    if (s->unit_method == gm && s->unit_ctr) amm_ctr_inc(s->unit_ctr);
    if (s->hold_method == gm && s->hold_ctr) atomic_fetch_add(&s->hold_returned, 1);
}

#define SP_WRAP(GM, CALL)                                                    \
    sp_t *s = ctx;                                                           \
    int t = amm_gate_enter(s->gate[GM], s->idx);                             \
    sp_hold(s, GM);                                                          \
    s->mcalls[GM]++;                                                         \
    int rc = (CALL);                                                         \
    sp_after(s, GM);                                                         \
    amm_gate_leave(s->gate[GM], s->idx, t);                                  \
    return rc;

static int sp_chain_id(void *ctx, uint64_t *out, uint64_t d) {
    SP_WRAP(GM_CHAIN, sp_chain_id_impl(ctx, out, d))
}
static int sp_block_number(void *ctx, uint64_t *out, uint64_t d) {
    SP_WRAP(GM_TIP, sp_block_number_impl(ctx, out, d))
}
static int sp_get_block(void *ctx, uint64_t n, amm_eth_block_t *o, uint64_t d) {
    SP_WRAP(GM_BLOCK, sp_get_block_impl(ctx, n, o, d))
}
static int sp_get_logs(void *ctx, uint64_t blk, const uint8_t *bhash, const uint8_t *contract,
                       const uint8_t *topic0, const uint8_t *to,
                       amm_eth_log_t *out, int cap, int *n, uint64_t d) {
    SP_WRAP(GM_LOGS, sp_get_logs_impl(ctx, blk, bhash, contract, topic0, to, out, cap, n, d))
}
static int sp_get_tx(void *ctx, const uint8_t *h, amm_eth_tx_t *o, uint64_t d) {
    SP_WRAP(GM_TX, sp_get_tx_impl(ctx, h, o, d))
}
static int sp_get_receipt(void *ctx, const uint8_t *h, amm_eth_receipt_t *o, uint64_t d) {
    SP_WRAP(GM_RECEIPT, sp_get_receipt_impl(ctx, h, o, d))
}

/* ── the fixture ──────────────────────────────────────────────────────── */

static char g_dir[64], g_path[128];
static amm_journal_t *g_j;
static chain_t g_chain;                 /* the shared chain                  */
static chain_t g_alt[3];                /* own chains for disagreement tests */
static sp_t g_sp[3];
static amm_eth_provider_t g_prov[3];
static amm_eth_watch_t *g_w;

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

static void provider_table(const int order[3]) {
    for (int i = 0; i < 3; i++) {
        int k = order[i];
        g_prov[i] = (amm_eth_provider_t){ .ctx = &g_sp[k], .name = "stub",
            .chain_id = sp_chain_id, .block_number = sp_block_number,
            .get_block = sp_get_block, .get_logs = sp_get_logs,
            .get_tx = sp_get_tx, .get_receipt = sp_get_receipt };
    }
}

static amm_eth_watch_cfg_t base_cfg(void) {
    amm_eth_watch_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.providers = g_prov; c.n_providers = 3; c.quorum = 2;
    memset(c.usdt, USDT_B, 20); memset(c.foundation, FOUND_B, 20);
    /* counts 3 / 4 / 5: every stub payment of the older tests carries a value
     * of at most 255 raw units, so they all wait count 1 = 3 (unchanged);
     * the small top count keeps the window 20 valid. W24 / W25 use the
     * plan's 3 / 5 / 33 through prod_counts(). */
    c.conf_bound_usdt[0] = 100000000ULL; c.conf_bound_usdt[1] = 1000000000ULL;
    c.conf_count[0] = 3; c.conf_count[1] = 4; c.conf_count[2] = 5;
    c.window_blocks = 20; c.start_height = 1;
    c.max_scan_blocks = 100; c.journal = g_j;
    c.chain_id = 1;                      /* setting eth_chain_id (givens item 77) */
    return c;
}

/* The plan's counts (givens item 60): 3 up to 100 USDT, 5 up to 1,000 USDT,
 * 33 above. */
static void prod_counts(amm_eth_watch_cfg_t *c) {
    c->conf_count[0] = 3; c->conf_count[1] = 5; c->conf_count[2] = 33;
}

/* Overwrite the logged value of the payment of transaction `txb` in chain
 * `c`: `raw` in the low 8 bytes, big-endian; `high` (non-zero) also sets a
 * byte above 64 bits (an amount that does not fit a u64). */
static void ch_set_value(chain_t *c, uint8_t txb, uint64_t raw, uint8_t high) {
    for (int i = 0; i < NL; i++) {
        if (!c->g[i].used || c->g[i].l.tx[0] != txb) continue;
        memset(c->g[i].l.data, 0, 32);
        for (int k = 0; k < 8; k++)
            c->g[i].l.data[31 - k] = (uint8_t)(raw >> (8 * k));
        c->g[i].l.data[0] = high;
        c->g[i].l.data_len = 32;
    }
}

static void new_watch(const amm_eth_watch_cfg_t *c) {
    if (g_w) amm_eth_watch_free(g_w);
    g_w = amm_eth_watch_new(c);
    if (!g_w) { printf("FATAL watch_new\n"); exit(2); }
}

/* A fresh world: journal, three providers on the shared chain, a watcher. */
static void fresh(uint64_t window) {
    if (g_w) { amm_eth_watch_free(g_w); g_w = NULL; }
    if (g_j) { amm_journal_close(g_j); g_j = NULL; }
    unlink(g_path);
    char p[160];
    snprintf(p, sizeof(p), "%s-wal", g_path); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", g_path); unlink(p);
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL open\n"); exit(2); }
    for (int i = 0; i < 3; i++) {
        memset(&g_sp[i], 0, sizeof(g_sp[i]));
        g_sp[i].ch = &g_chain; g_sp[i].chain_id = 1;
        g_sp[i].idx = i; g_sp[i].hold_method = -1; g_sp[i].unit_method = -1;
    }
    memset(&g_chain, 0, sizeof(g_chain));
    static const int id[3] = {0, 1, 2};
    provider_table(id);
    amm_eth_watch_cfg_t c = base_cfg();
    c.window_blocks = window;
    new_watch(&c);
}

static void reopen_world(uint64_t window) {
    if (g_w) { amm_eth_watch_free(g_w); g_w = NULL; }
    amm_journal_close(g_j);
    g_j = NULL;
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL reopen\n"); exit(2); }
    amm_eth_watch_cfg_t c = base_cfg();
    c.window_blocks = window;
    new_watch(&c);
}

static int step(amm_eth_step_t *o) {
    amm_eth_step_t local;
    return amm_eth_watch_step(g_w, 0, o ? o : &local);
}

static int step_n(int n, amm_eth_step_t *last) {
    int rc = AMM_W_OK;
    for (int i = 0; i < n; i++) rc = step(last);
    return rc;
}

static int count_state(const char *st) {
    amm_rec_t *r = calloc(256, sizeof(*r));
    int n = 0, c = 0;
    if (amm_journal_rec_list(g_j, 0, NULL, r, 256, &n) != 0) { free(r); return -1; }
    for (int i = 0; i < n; i++) c += !strcmp(r[i].state, st);
    free(r);
    return c;
}

static int rec_state(uint8_t txb, uint32_t li, char *out) {
    uint8_t tx[32]; memset(tx, txb, 32);
    amm_rec_t r;
    int g = amm_journal_rec_get(g_j, tx, li, &r);
    if (g != 0) return g;                    /* 1 = none, -1 = fault        */
    strcpy(out, r.state);
    return 0;
}

static int rec_load(uint8_t txb, uint32_t li, amm_rec_t *r) {
    uint8_t tx[32]; memset(tx, txb, 32);
    return amm_journal_rec_get(g_j, tx, li, r);
}

static int total_records(void) {
    amm_rec_t *r = calloc(256, sizeof(*r));
    int n = 0;
    if (amm_journal_rec_list(g_j, 0, NULL, r, 256, &n) != 0) n = -1;
    free(r);
    return n;
}

static uint64_t cursor(const char *name) {
    uint64_t v = 0;
    return amm_journal_cursor_get(g_j, name, &v) == 0 ? v : (uint64_t)-1;
}

/* A swap whose incoming id is the eth key of (txb, li) driven to `target`. */
static int make_swap_as(char sender_c, uint8_t txb, const char *target, amm_swap_t *s) {
    static uint64_t ctr = 1;
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    char sender[41], dest[129];
    memset(sender, sender_c, 40); sender[40] = '\0';
    memset(dest, 'e', 128); dest[128] = '\0';
    a.dir = AMM_USDT_TO_NODUS; a.sender = sender; a.dest = dest;
    a.amount = 5; a.minimum = 1; a.value_usdt = 5; a.approved_at = 1; a.expiry = 100;
    a.approved_tip = 1;
    a.incoming_id = ""; a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    a.req_no[31] = (uint8_t)ctr; a.req_no[30] = (uint8_t)(ctr >> 8);
    for (int i = 0; i < 16; i++) a.rand16[i] = (uint8_t)(ctr * 7 + i);
    ctr++;
    if (amm_journal_approve(g_j, &a, s) != AMM_J_OK) return 0;
    uint8_t tx[32]; memset(tx, txb, 32);
    char key[AMM_TID_MAX];
    amm_journal_eth_key(tx, key, sizeof(key));        /* the transaction hash alone */
    if (!strcmp(target, "approved")) return 1;
    if (amm_journal_swap_seen(g_j, s->seq, key, NULL, 500000000ULL, 0, NULL) != 0) return 0;   /* seen: takes room */
    if (!strcmp(target, "paid_waiting_depth")) return 1;
    if (amm_journal_swap_transition(g_j, s->seq, "counted", NULL, NULL, NULL) != 0) return 0;
    if (!strcmp(target, "counted")) return 1;
    if (amm_journal_swap_transition(g_j, s->seq, "payout_pending", NULL, NULL, NULL) != 0) return 0;
    if (!strcmp(target, "payout_pending")) return 1;
    return amm_journal_swap_transition(g_j, s->seq, "paid", NULL, NULL, NULL) == 0;
}

/* The common case: sender 0x11.. (hex '1'). `li` is unused: the swap's
 * incoming id is the transaction hash. */
static int make_swap(uint8_t txb, uint32_t li, const char *target, amm_swap_t *s) {
    (void)li;
    return make_swap_as('1', txb, target, s);
}

static int swap_is(const amm_swap_t *s, const char *st) {
    amm_swap_t g;
    return amm_journal_swap_get(g_j, s->id, &g) == 0 && !strcmp(g.state, st);
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void w1_quorum(void) {
    printf("W1 quorum and candidates\n");
    /* one provider failing its logs: the other two reach Q = 2 */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    g_sp[2].fail_logs = 1;
    amm_eth_step_t o;
    CHECK(step(&o) == AMM_W_OK && o.usable == 3, "step ok, three usable providers");
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "two of three agree: counted (deep at depth 3)");

    /* only ONE provider lists it, the others answer without: dropped */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    CHECK(step(&o) == AMM_W_OK, "step ok");
    CHECK(total_records() == 0 || count_state("seen") + count_state("deep") == 0,
          "a log listed by one provider alone is never counted");
    CHECK(count_state("candidate") == 0, "  and it is dropped once two providers answer without it");

    /* unresolved candidate: one lists it, one fails, one answers without */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[1].fail_logs = 1;
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "candidate"),
          "one lists, one fails, one without: a CANDIDATE is retained");
    CHECK(count_state("seen") + count_state("deep") == 0, "  never counted below the quorum");
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "candidate"), "  still retained the next step");
    /* the failing provider recovers and lists it: promoted */
    ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 5);
    g_sp[1].fail_logs = 0;
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "the quorum forms: promoted and counted");
}

static void w2_disagreement(void) {
    printf("W2 disagreement\n");
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);
    ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 6);
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[2].fail_logs = 1;
    amm_eth_step_t o;
    step(&o);
    CHECK(count_state("seen") + count_state("deep") == 0, "values 5 and 6: nothing counted");
    CHECK(count_state("candidate") == 1, "  one candidate retained");
    ch_pay(&g_alt[2], 0x31, 0, 10, 0x11, 5);
    g_sp[2].fail_logs = 0;
    step(&o);
    amm_rec_t r;
    CHECK(rec_load(0x31, 0, &r) == 0 && !strcmp(r.state, "deep") && r.value[31] == 5,
          "a later agreement counts the agreed value 5");
}

static void w3_unknown(void) {
    printf("W3 a failed read is unknown, never zero\n");
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    g_sp[0].fail_logs = 1; g_sp[1].fail_logs = 1;       /* only one answers   */
    amm_eth_step_t o;
    CHECK(step(&o) == AMM_W_UNKNOWN && o.unknown > 0, "logs: fewer than Q answer: unknown");
    CHECK(total_records() == 0, "  no record");
    uint64_t nx = cursor("eth_scan");
    amm_blk_t b;
    CHECK(amm_journal_block_get(g_j, 1, &b) == 1, "  no block written for the unread block");
    CHECK(nx == (uint64_t)-1 || nx == 1, "  the cursor did not move past it");
    g_sp[0].fail_logs = 0;
    /* blocks 1..9 hold no payments; the failure was at block 1 */
    CHECK(step(&o) == AMM_W_OK, "providers recover: ok");
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "the payment was not skipped and counts");

    /* receipts failing for two providers: the record is not decided */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    g_sp[0].fail_receipts = 1; g_sp[1].fail_receipts = 1;
    CHECK(step(&o) == AMM_W_UNKNOWN, "receipts: fewer than Q answer: unknown");
    CHECK(total_records() == 0, "  no record stored on a guess");
    CHECK(cursor("eth_scan") == 10, "  the cursor waits at the block (10)");
    g_sp[0].fail_receipts = 0; g_sp[1].fail_receipts = 0;
    CHECK(step(&o) == AMM_W_OK && rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"),
          "after recovery the block is read again and counts");

    /* blocks failing */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_sp[0].fail_blocks = 1; g_sp[1].fail_blocks = 1;
    CHECK(step(&o) == AMM_W_UNKNOWN && o.blocks == 0, "headers: fewer than Q answer: no block written");
}

static void w4_chain_id(void) {
    printf("W4 chain id\n");
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[2], 0x41, 0, 10, 0x11, 5);            /* only the bad provider */
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[2].chain_id = 5;
    amm_eth_step_t o;
    CHECK(step(&o) == AMM_W_OK && o.usable == 2, "a provider on chain id 5 is not used");
    CHECK(total_records() == 0, "  its payment is never seen");
    /* two providers off chain 1 with Q = 2 and three providers: one usable */
    g_sp[1].chain_id = 5;
    uint64_t before = cursor("eth_scan");
    CHECK(step(&o) == AMM_W_UNKNOWN && o.usable == 1, "fewer usable providers than Q: unknown");
    CHECK(cursor("eth_scan") == before, "  nothing written");
    g_sp[1].chain_id = 1; g_sp[2].fail_all = 1;
    CHECK(step(&o) == AMM_W_OK && o.usable == 2, "a provider that does not answer chain id is not used");

    /* the chain id is the SETTING (givens item 77: Sepolia 11155111): a watcher
     * configured for it uses the providers that report it and refuses those
     * that report mainnet. Fails without the setting wired in: the constant 1
     * would leave all three Sepolia providers unusable (usable == 0). */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    amm_eth_watch_cfg_t sc = base_cfg();
    sc.chain_id = 11155111ULL;
    new_watch(&sc);
    for (int i = 0; i < 3; i++) g_sp[i].chain_id = 11155111ULL;
    CHECK(step(&o) == AMM_W_OK && o.usable == 3, "chain id setting 11155111: three Sepolia providers are used");
    g_sp[2].chain_id = 1;
    CHECK(step(&o) == AMM_W_OK && o.usable == 2, "a provider on mainnet is not used by a Sepolia watcher");
    sc.chain_id = 0;
    CHECK(amm_eth_watch_new(&sc) == NULL, "chain id 0 is refused");
}

static void w5_depth(void) {
    printf("W5 depth and the quorum tip\n");
    fresh(20);
    ch_build(&g_chain, 1, 12, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    amm_eth_step_t o;
    char st[16];
    step(&o);
    CHECK(o.tip == 12 && rec_state(0x31, 0, st) == 0 && !strcmp(st, "seen"),
          "tip 12: depth 2: seen, not deep");
    amm_rec_t r;
    int reached = 99;
    CHECK(rec_load(0x31, 0, &r) == 0 &&
          amm_eth_watch_depth_reached(g_w, &r, 2, 0, &reached) == 0 && reached == 1,
          "depth 2 is reached by the joint vote (all three providers: receipt and tip 12)");
    CHECK(amm_eth_watch_depth_reached(g_w, &r, 3, 0, &reached) == 0 && reached == 0,
          "depth 3 is not reached");
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") && o.deep == 1,
          "tip 13: depth 3: deep");
    /* the quorum tip: the Q-th largest reported value */
    fresh(20);
    ch_build(&g_chain, 1, 12, 0, 0);
    g_sp[0].tip_override = 40;                          /* one liar           */
    step(&o);
    CHECK(o.tip == 12, "one provider reporting tip 40 cannot move the quorum tip (2nd largest of 40, 12, 12)");
    g_sp[1].tip_override = 40;
    step(&o);
    CHECK(o.tip == 40, "two providers at 40: the quorum tip is 40 (and the others are asked for blocks they lack)");
}

static void w6_ignored(void) {
    printf("W6 payments that are ignored\n");
    fresh(20);
    ch_build(&g_chain, 1, 14, 0, 0);
    /* transferFrom: the log's from (0x22) is not the transaction's sender */
    ch_pay_full(&g_chain, 0x51, 0, 5, 0x22, 0x11, USDT_B, FOUND_B, 5, 1, TOPIC0);
    /* failed receipt */
    ch_pay_full(&g_chain, 0x52, 0, 6, 0x11, 0x11, USDT_B, FOUND_B, 5, 0, TOPIC0);
    /* another token contract */
    ch_pay_full(&g_chain, 0x53, 0, 7, 0x11, 0x11, OTHER_TOKEN_B, FOUND_B, 5, 1, TOPIC0);
    /* another recipient */
    ch_pay_full(&g_chain, 0x54, 0, 8, 0x11, 0x11, USDT_B, OTHER_RCPT_B, 5, 1, TOPIC0);
    /* zero amount */
    ch_pay_full(&g_chain, 0x55, 0, 9, 0x11, 0x11, USDT_B, FOUND_B, 0, 1, TOPIC0);
    /* wrong topic */
    { uint8_t bad[32]; memcpy(bad, TOPIC0, 32); bad[0] ^= 1;
      ch_pay_full(&g_chain, 0x56, 0, 10, 0x11, 0x11, USDT_B, FOUND_B, 5, 1, bad); }
    /* the control: a plain direct transfer IS counted */
    ch_pay(&g_chain, 0x57, 0, 11, 0x11, 5);
    /* a self-authorised transferFrom: the sender is also the log's `from`,
     * the call data starts with transferFrom (23b872dd), not transfer */
    ch_pay(&g_chain, 0x59, 0, 12, 0x11, 5);
    { uint8_t h[32]; memset(h, 0x59, 32);
      stx_t *t = find_tx(&g_chain, h);
      t->head[0] = 0x23; t->head[1] = 0xb8; t->head[2] = 0x72; t->head[3] = 0xdd; }
    /* no call data at all (a plain call to the contract) */
    ch_pay(&g_chain, 0x5a, 0, 13, 0x11, 5);
    { uint8_t h[32]; memset(h, 0x5a, 32);
      stx_t *t = find_tx(&g_chain, h);
      t->input_len = 0; memset(t->head, 0, 4); }
    amm_eth_step_t o;
    CHECK(step(&o) == AMM_W_OK, "step ok");
    CHECK(total_records() == 1, "exactly one record: the control payment");
    char st[16];
    CHECK(rec_state(0x57, 0, st) == 0 && !strcmp(st, "deep"), "  the direct transfer counts");
    CHECK(rec_state(0x51, 0, st) == 1, "  transferFrom (log from != tx sender) ignored");
    CHECK(rec_state(0x52, 0, st) == 1, "  failed receipt ignored");
    CHECK(rec_state(0x53, 0, st) == 1, "  other token ignored");
    CHECK(rec_state(0x54, 0, st) == 1, "  other recipient ignored");
    CHECK(rec_state(0x55, 0, st) == 1, "  zero amount ignored");
    CHECK(rec_state(0x56, 0, st) == 1, "  wrong topic ignored");
    CHECK(rec_state(0x59, 0, st) == 1,
          "  self-authorised transferFrom (log from == tx sender, selector 23b872dd) ignored");
    CHECK(rec_state(0x5a, 0, st) == 1, "  a call without call data ignored");
    /* a transaction to another contract that emitted a USDT-looking log */
    fresh(20);
    ch_build(&g_chain, 1, 14, 0, 0);
    ch_pay(&g_chain, 0x58, 0, 5, 0x11, 5);
    memset(g_chain.t[0].to, 0xCC, 20);                  /* the call target is a router */
    step(&o);
    CHECK(total_records() == 0, "a log of a transaction whose target is not the USDT contract is ignored");
}

static void w7_match(void) {
    printf("W7 matching\n");
    amm_rec_t r;
    memset(&r, 0, sizeof(r));
    memset(r.from, 0x11, 20); r.value[31] = 5; r.block_ts = 96; r.block_number = 8;
    uint8_t sender[20], other[20], amount[32], amount6[32];
    memset(sender, 0x11, 20); memset(other, 0x22, 20);
    memset(amount, 0, 32); amount[31] = 5;
    memset(amount6, 0, 32); amount6[31] = 6;
    CHECK(amm_eth_watch_match(&r, sender, amount, 7, 100) == AMM_M_MATCH, "sender + amount + block above the approval tip + block time <= expiry: MATCH");
    CHECK(amm_eth_watch_match(&r, sender, amount, 7, 96) == AMM_M_MATCH, "block time == expiry: MATCH");
    CHECK(amm_eth_watch_match(&r, sender, amount6, 7, 100) == AMM_M_HELD_VALUE, "another logged value: held");
    CHECK(amm_eth_watch_match(&r, other, amount, 7, 100) == AMM_M_NONE, "another sender: none");
    CHECK(amm_eth_watch_match(&r, sender, amount, 7, 95) == AMM_M_HELD_EXPIRED, "block time after the expiry: held");
    /* review finding (a): approval first, then payment, bound by chain HEIGHT
     * (the tip read at approval), never by the wall clock; the payment is in block 8 */
    CHECK(amm_eth_watch_match(&r, sender, amount, 8, 100) == AMM_M_HELD_EARLY,
          "block 8, approval tip 8: the same block is not above it: held, it matches no approval");
    CHECK(amm_eth_watch_match(&r, sender, amount, 7, 100) == AMM_M_MATCH,
          "block 8, approval tip 7: one above: counted");
    CHECK(amm_eth_watch_match(&r, sender, amount, 9, 100) == AMM_M_HELD_EARLY,
          "approval tip 9 above the block: held");
    CHECK(amm_eth_watch_match(&r, sender, amount6, 8, 100) == AMM_M_HELD_VALUE &&
          amm_eth_watch_match(&r, other, amount, 8, 100) == AMM_M_NONE,
          "sender and value are judged before the height: HELD_VALUE and NONE keep their meaning");
    /* a payment first read after the expiry time still follows its approval
     * by BLOCK time: the chain is read late (start at block 12), the payment
     * sits in block 8 (ts 96) and the approval expires at 100 */
    fresh(20);
    ch_build(&g_chain, 1, 14, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 8, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    amm_rec_t got;
    CHECK(rec_load(0x31, 0, &got) == 0 && got.block_ts == 96, "record carries its block time");
    CHECK(amm_eth_watch_match(&got, sender, amount, 7, 100) == AMM_M_MATCH,
          "read after the expiry time (bot time 10^9, chain at 168) but in-window by block time: MATCH");
}

static void w8_reorg(void) {
    printf("W8 reorganisation\n");
    /* the transaction moves to another block (13) in the new fork (from 12) */
    fresh(20);
    ch_build(&g_chain, 1, 15, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    ch_pay(&g_chain, 0x32, 0, 13, 0x11, 7);
    amm_eth_step_t o;
    step(&o);
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") &&
          rec_state(0x32, 0, st) == 0 && !strcmp(st, "seen"), "setup: deep at block 10, seen at 13");
    ch_build(&g_chain, 1, 16, 12, 1);                    /* fork at 12         */
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);              /* below the fork: same */
    ch_pay(&g_chain, 0x32, 1, 14, 0x11, 7);              /* mined again in 14  */
    CHECK(step(&o) == AMM_W_OK && o.reorgs == 1, "the parent-hash mismatch is found and written");
    amm_blk_t b;
    CHECK(amm_journal_block_get(g_j, 12, &b) == 0 && b.hash[0] == hb(12, 1), "block 12 holds the new fork's hash");
    CHECK(amm_journal_block_get(g_j, 11, &b) == 0 && b.hash[0] == hb(11, 0), "block 11 (the common ancestor) unchanged");
    amm_rec_t r;
    CHECK(rec_load(0x32, 1, &r) == 0 && r.block_number == 14 && r.block_hash[0] == hb(14, 1) &&
          !strcmp(r.state, "seen") && r.value[31] == 7,
          "the moved transaction: the record follows it to block 14 with the quorum's log index 1, seen again");
    CHECK(rec_state(0x32, 0, st) == 0 && !strcmp(st, "dropped") && total_records() == 2,
          "the old row (log 0) is dropped: exactly one live record for the transaction");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "a record below the fork is untouched");
    CHECK(cursor("eth_scan") == 17, "the rescan caught up to the tip (cursor 17)");

    /* a SECOND reorganisation brings the transaction back as log 0 (block 15):
     * the dropped row (log 0) is revived only after the live row (log 1) was
     * dropped, so there is never more than one live record per hash */
    ch_build(&g_chain, 1, 17, 12, 2);                    /* tip 17: block 15 at depth 2: seen */
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    ch_pay(&g_chain, 0x32, 0, 15, 0x11, 7);
    CHECK(step(&o) == AMM_W_OK && o.reorgs == 1, "second reorganisation");
    CHECK(rec_load(0x32, 0, &r) == 0 && !strcmp(r.state, "seen") && r.block_number == 15 &&
          rec_state(0x32, 1, st) == 0 && !strcmp(st, "dropped") && total_records() == 2,
          "revived log 0 is the only live record of the transaction (log 1 dropped)");
}

static void w9_gone_unpaid(void) {
    printf("W9 a waiting payment whose transaction disappears\n");
    fresh(20);
    ch_build(&g_chain, 1, 14, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 13, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    char st[16];
    amm_swap_t s;
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "seen") &&
          make_swap(0x31, 0, "paid_waiting_depth", &s), "setup: a swap waits for the depth of its payment");
    ch_build(&g_chain, 1, 15, 12, 1);                    /* the transaction is gone */
    CHECK(step(&o) == AMM_W_OK && o.reorgs == 1 && o.dropped == 1, "reorganisation, one record dropped");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "dropped"), "record dropped");
    CHECK(swap_is(&s, "approved"), "the swap is unpaid again (approved)");
    int p = 1;
    CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 0, "no reversal pause for an unpaid payment");
}

static void w10_reversal(void) {
    printf("W10 reversal of counted and paid payments\n");
    static const char *targets[] = {"counted", "payout_pending", "paid"};
    for (size_t t = 0; t < 3; t++) {
        fresh(20);
        ch_build(&g_chain, 1, 15, 0, 0);
        ch_pay(&g_chain, 0x31, 0, 11, 0x11, 5);
        amm_eth_step_t o;
        step(&o);
        char st[16];
        amm_swap_t s;
        char msg[96];
        snprintf(msg, sizeof(msg), "setup: %s swap, record deep", targets[t]);
        CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") &&
              make_swap(0x31, 0, targets[t], &s), msg);
        ch_build(&g_chain, 1, 16, 11, 1);                /* fork at 11: the block holding the tx changes, tx gone */
        snprintf(msg, sizeof(msg), "%s: reversal detected through the stub chain", targets[t]);
        CHECK(step(&o) == AMM_W_OK && o.reorgs == 1 && o.reversed == 1, msg);
        CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "reversed"), "  record reversed");
        CHECK(swap_is(&s, "reversed"), "  swap reversed");
        int p = 0;
        CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 1, "  reversal pause set");
        reopen_world(20);
        p = 0;
        CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 1, "  the pause survives a restart");
        char sender[41], dest[129];
        memset(sender, '2', 40); sender[40] = '\0'; memset(dest, 'e', 128); dest[128] = '\0';
        amm_approve_t a;
        memset(&a, 0, sizeof(a));
        a.dir = AMM_USDT_TO_NODUS; a.sender = sender; a.dest = dest; a.amount = 1;
        a.value_usdt = 1; a.incoming_id = ""; a.swap_max = 100; a.inflight_max = 1000;
        a.approved_tip = 1;
        a.req_no[0] = 1; a.rand16[0] = 1;
        amm_swap_t n;
        CHECK(amm_journal_approve(g_j, &a, &n) == AMM_J_PAUSED, "  new approvals refused (settings flag off)");
    }
}

static int g_arm = 0;
static int fail_once(void) { return g_arm > 0 ? (g_arm--, 1) : 0; }

static void w11_restart(void) {
    printf("W11 stop between detection and the journal write\n");
    fresh(20);
    ch_build(&g_chain, 1, 15, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 11, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    amm_swap_t s;
    CHECK(make_swap(0x31, 0, "counted", &s), "setup: counted swap");
    ch_build(&g_chain, 1, 16, 11, 1);                    /* fork at 11, tx gone */
    uint64_t cur_before = cursor("eth_scan");
    g_arm = 1;
    amm_journal_test_precommit_hook(fail_once);
    CHECK(step(&o) == AMM_W_ERR, "the commit of the reorganisation fails: the step reports an error");
    amm_journal_test_precommit_hook(NULL);
    reopen_world(20);                                    /* the restart        */
    char st[16];
    int p = 1;
    CHECK(swap_is(&s, "counted") && rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") &&
          amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 0 &&
          cursor("eth_scan") == cur_before, "after the restart: swap, record, pause and cursor exactly as before");
    CHECK(step(&o) == AMM_W_OK && o.reversed == 1, "the same mismatch is found again and written");
    CHECK(swap_is(&s, "reversed") && amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 1,
          "swap reversed, pause set");
}

static void w12_window_limit(void) {
    printf("W12 a reversal deeper than the window is not detected\n");
    fresh(5);
    ch_build(&g_chain, 1, 40, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    amm_eth_step_t o;
    step_n(2, &o);
    amm_swap_t s;
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") && make_swap(0x31, 0, "counted", &s),
          "setup: a counted payment at block 10, tip 40, window 5");
    ch_build(&g_chain, 1, 41, 9, 1);                     /* the chain changes from 9 on; the tx is gone */
    step_n(4, &o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "the record below the window stays deep");
    CHECK(swap_is(&s, "counted"), "its swap stays counted (the stated detection limit)");
    int p = 1;
    CHECK(amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 0, "no pause");
}

static void w13_window_observation(void) {
    printf("W13 window observation\n");
    uint8_t sender[20], amount[32];
    memset(sender, 0x11, 20); memset(amount, 0, 32); amount[31] = 5;
    /* expiry 100: blocks have ts = h * 12; the first block after the expiry is 9 (108) */
    fresh(20);
    ch_build(&g_chain, 1, 11, 0, 0);
    amm_eth_step_t o;
    step(&o);
    CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 0,
          "tip 11: block 9 (first after the expiry) is at depth 2: not observed");
    ch_build(&g_chain, 1, 12, 0, 0);
    step(&o);
    CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 1,
          "tip 12: block 9 at depth 3, cursor past it: observed");
    CHECK(amm_eth_watch_window_observed(g_w, 1, 12 * 12, sender, amount) == 0,
          "an expiry later than every scanned block: not observed");
    /* reads failing: the cursor does not move, so a later window is not observed */
    fresh(20);
    ch_build(&g_chain, 1, 12, 0, 0);
    g_sp[0].fail_blocks = 1; g_sp[1].fail_blocks = 1;
    step(&o);
    CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 0,
          "headers unreadable (no cursor): not observed, the clock does not release room");
    g_sp[0].fail_blocks = 0; g_sp[1].fail_blocks = 0;
    /* a retained candidate for this sender and amount blocks it */
    fresh(20);
    ch_build(&g_chain, 1, 14, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 8, 0x11, 5);
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[1].fail_logs = 1;                               /* one lists, one fails, one without */
    step(&o);
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "candidate"), "setup: a candidate for sender 0x11 amount 5");
    CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 0,
          "a below-quorum candidate for this approval is unresolved: not observed");
    uint8_t amount7[32];
    memset(amount7, 0, 32); amount7[31] = 7;
    CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount7) == 1,
          "another amount is not affected");
    g_sp[1].fail_logs = 0;                               /* it answers without: dropped */
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "dropped") &&
          amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 1,
          "the candidate resolves (dropped): observed");
}

static void w14_order(void) {
    printf("W14 provider order does not matter\n");
    amm_rec_t first[8];
    int n1 = 0;
    static const int orders[2][3] = {{0, 1, 2}, {2, 0, 1}};
    for (int k = 0; k < 2; k++) {
        fresh(20);
        ch_build(&g_chain, 1, 14, 0, 0);
        g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
        ch_pay(&g_alt[0], 0x31, 0, 8, 0x11, 5);
        ch_pay(&g_alt[1], 0x31, 0, 8, 0x11, 5);
        ch_pay(&g_alt[2], 0x32, 0, 9, 0x12, 6);          /* a lone log          */
        ch_pay(&g_alt[0], 0x33, 0, 10, 0x13, 7);
        ch_pay(&g_alt[2], 0x33, 0, 10, 0x13, 7);
        for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
        provider_table(orders[k]);
        amm_eth_watch_cfg_t c = base_cfg();
        new_watch(&c);
        step_n(2, NULL);
        amm_rec_t cur[8];
        int n = 0;
        amm_journal_rec_list(g_j, 0, NULL, cur, 8, &n);
        if (k == 0) { memcpy(first, cur, sizeof(cur)); n1 = n; }
        else CHECK(n == n1 && !memcmp(first, cur, sizeof(amm_rec_t) * (size_t)n),
                   "the same records, states and order after a permutation of the providers");
    }
    CHECK(n1 == 2, "two counted records (the lone log is dropped)");
}

static void w15_restart(void) {
    printf("W15 restart from the stored cursor\n");
    fresh(20);
    ch_build(&g_chain, 1, 12, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    CHECK(o.blocks == 12, "first run scans blocks 1..12");
    reopen_world(20);
    int calls_before = g_sp[0].calls;
    CHECK(step(&o) == AMM_W_OK && o.blocks == 0, "after a restart nothing is scanned again");
    (void)calls_before;
    ch_build(&g_chain, 1, 14, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    CHECK(step(&o) == AMM_W_OK && o.blocks == 2 && o.deep == 1, "new blocks 13, 14 are scanned; the record becomes deep");
    CHECK(count_state("deep") == 1 && total_records() == 1, "one record, no duplicates");
}

static void w16_config(void) {
    printf("W16 configuration\n");
    fresh(20);
    amm_eth_watch_cfg_t c = base_cfg();
    amm_eth_watch_t *w;
    CHECK((w = amm_eth_watch_new(&c)) != NULL, "a valid configuration builds");
    amm_eth_watch_free(w);
    c = base_cfg(); c.quorum = 0;
    CHECK(amm_eth_watch_new(&c) == NULL, "quorum 0 refused");
    c = base_cfg(); c.quorum = 4;
    CHECK(amm_eth_watch_new(&c) == NULL, "quorum above the provider count refused");
    c = base_cfg(); c.window_blocks = 2;
    CHECK(amm_eth_watch_new(&c) == NULL, "window below the confirmations refused");
    c = base_cfg(); c.window_blocks = 4;
    CHECK(amm_eth_watch_new(&c) == NULL, "window 4 below the largest count 5 refused");
    c = base_cfg(); c.window_blocks = 5;
    CHECK((w = amm_eth_watch_new(&c)) != NULL, "window == the largest count 5 accepted");
    amm_eth_watch_free(w);
    c = base_cfg(); prod_counts(&c); c.window_blocks = 32;
    CHECK(amm_eth_watch_new(&c) == NULL, "window 32 below the largest count 33 refused");
    c = base_cfg(); prod_counts(&c); c.window_blocks = 33;
    CHECK((w = amm_eth_watch_new(&c)) != NULL, "window 33 == the largest count 33 accepted");
    amm_eth_watch_free(w);
    c = base_cfg(); c.conf_count[0] = 0;
    CHECK(amm_eth_watch_new(&c) == NULL, "zero count 1 refused");
    c = base_cfg(); c.conf_count[0] = 4; c.conf_count[1] = 3;
    CHECK(amm_eth_watch_new(&c) == NULL, "count 2 below count 1 refused");
    c = base_cfg(); c.conf_count[1] = 6;
    CHECK(amm_eth_watch_new(&c) == NULL, "count 2 above count 3 refused");
    c = base_cfg(); c.conf_count[0] = c.conf_count[1] = c.conf_count[2] = 4;
    CHECK((w = amm_eth_watch_new(&c)) != NULL, "equal counts accepted (not decreasing)");
    amm_eth_watch_free(w);
    c = base_cfg(); c.conf_bound_usdt[1] = c.conf_bound_usdt[0];
    CHECK(amm_eth_watch_new(&c) == NULL, "equal bounds refused");
    c = base_cfg(); c.conf_bound_usdt[0] = 2000000000ULL;
    CHECK(amm_eth_watch_new(&c) == NULL, "descending bounds refused");
    c = base_cfg(); c.max_scan_blocks = 0;
    CHECK(amm_eth_watch_new(&c) == NULL, "zero scan bound refused");
    c = base_cfg(); c.n_providers = 0;
    CHECK(amm_eth_watch_new(&c) == NULL, "no providers refused");
    c = base_cfg(); c.journal = NULL;
    CHECK(amm_eth_watch_new(&c) == NULL, "no journal refused");
    amm_eth_provider_t bad[3];
    memcpy(bad, g_prov, sizeof(bad));
    bad[1].get_receipt = NULL;
    c = base_cfg(); c.providers = bad;
    CHECK(amm_eth_watch_new(&c) == NULL, "a provider without a function refused");
}

/* W17: the SAME Q providers must report the payment's block hash and a deep
 * enough tip (plan line 252). */
static void w17_depth_votes(void) {
    printf("W17 depth votes: receipt voters and tip voters must be the same providers\n");
    fresh(20);
    ch_build(&g_chain, 1, 14, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);             /* A and B hold the payment   */
    ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 5);
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[0].tip_override = 11;                           /* A: tip 11 (depth 1)        */
    amm_eth_step_t o;                                    /* B and C report tip 14      */
    char st[16];
    CHECK(step(&o) == AMM_W_OK && o.tip == 14, "the quorum tip is 14 (B and C report it)");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "seen") && o.deep == 0,
          "Q = 2: A and B give the receipt, B and C a high tip: only B does both: NOT deep");
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "seen"), "  and it stays seen on the next step");
    g_sp[0].tip_override = 0;                            /* A now reports tip 14       */
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") && o.deep == 1,
          "A and B give both the receipt and the deep tip: deep");
}

/* W18: a false below-quorum record must not suppress a genuine quorum record
 * of the same transaction (and the record is not lost when the cursor moves). */
static void w18_false_candidate(void) {
    printf("W18 a false candidate does not hide the genuine record\n");
    char st[16];
    amm_eth_step_t o;
    /* same block: the fake log has the smaller log index */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 1, 10, 0x11, 5);             /* genuine: log 1, A and B    */
    ch_pay(&g_alt[1], 0x31, 1, 10, 0x11, 5);
    ch_pay(&g_alt[2], 0x31, 0, 10, 0x11, 5);             /* fake: log 0, C alone       */
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    step(&o);
    CHECK(rec_state(0x31, 1, st) == 0 && !strcmp(st, "deep"),
          "the quorum record (log 1) is stored although a candidate with log 0 sorts first");
    CHECK(rec_state(0x31, 0, st) == 1 && total_records() == 1, "  the fake log 0 is not stored beside it");
    step(&o);
    CHECK(rec_state(0x31, 1, st) == 0 && !strcmp(st, "deep") && total_records() == 1,
          "  and it stays after the cursor has advanced and the next step ran");

    /* the candidate came first, the genuine record later */
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);             /* fake log 0 on A            */
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[1].fail_logs = 1;
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "candidate"), "setup: the fake log is a retained candidate");
    ch_pay(&g_alt[0], 0x31, 1, 10, 0x11, 5);             /* the genuine log appears    */
    ch_pay(&g_alt[1], 0x31, 1, 10, 0x11, 5);
    g_sp[1].fail_logs = 0;
    step(&o);
    CHECK(rec_state(0x31, 1, st) == 0 && !strcmp(st, "deep") &&
          rec_state(0x31, 0, st) == 0 && !strcmp(st, "dropped") && total_records() == 1,
          "the quorum record displaces the candidate: one live record, the genuine one");
}

/* W20: a moved transaction takes the quorum's actual logged value. */
static void w20_moved_value(void) {
    printf("W20 a moved transaction takes the quorum's logged value\n");
    static const char *targets[] = {"paid_waiting_depth", "counted"};
    uint8_t sender[20], amount5[32];
    memset(sender, 0x11, 20); memset(amount5, 0, 32); amount5[31] = 5;
    for (size_t t = 0; t < 2; t++) {
        fresh(20);
        ch_build(&g_chain, 1, 15, 0, 0);
        ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
        amm_eth_step_t o;
        step(&o);
        amm_swap_t s;
        char msg[120];
        snprintf(msg, sizeof(msg), "setup: %s swap on a deep payment of 5", targets[t]);
        char st[16];
        CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") &&
              make_swap(0x31, 0, targets[t], &s), msg);
        ch_build(&g_chain, 1, 16, 10, 1);                /* fork at 10                 */
        ch_pay(&g_chain, 0x31, 0, 12, 0x11, 6);          /* mined again with value 6   */
        CHECK(step(&o) == AMM_W_OK && o.reorgs == 1, "reorganisation");
        if (t == 0) {
            amm_rec_t r;
            CHECK(rec_load(0x31, 0, &r) == 0 && r.value[31] == 6 && r.block_number == 12,
                  "the record carries the new block's logged value 6, not the old 5");
            CHECK(amm_eth_watch_match(&r, sender, amount5, 1, 1000) == AMM_M_HELD_VALUE,
                  "against the approved amount 5 it is a mismatched value: held");
            CHECK(swap_is(&s, "approved"), "the swap that waited for a payment of 5 is unpaid again");
        } else {
            int p = 0;
            CHECK(swap_is(&s, "reversed") && amm_journal_reversal_pause_get(g_j, &p) == 0 && p == 1,
                  "a counted payment of 5 that is now a payment of 6: reversal and pause");
        }
    }
}

/* W21: the permanent marker is the transaction hash. */
static void w21_marker_by_hash(void) {
    printf("W21 a reversed transaction re-mined under another log index is not counted again\n");
    fresh(20);
    ch_build(&g_chain, 1, 15, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 11, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    amm_swap_t s1, s2;
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") &&
          make_swap_as('1', 0x31, "counted", &s1) && make_swap_as('2', 0x31, "approved", &s2),
          "setup: swap 1 counted on the payment, swap 2 approved");
    char key[AMM_TID_MAX];
    uint8_t tx[32]; memset(tx, 0x31, 32);
    amm_journal_eth_key(tx, key, sizeof(key));
    CHECK(amm_journal_marker_exists(g_j, key) == 0, "the marker eth:<tx hash> exists");
    ch_build(&g_chain, 1, 16, 11, 1);                    /* the transaction is gone    */
    CHECK(step(&o) == AMM_W_OK && o.reversed == 1 && swap_is(&s1, "reversed"), "reversal detected");
    ch_build(&g_chain, 1, 17, 12, 2);                    /* mined again, log index 1   */
    ch_pay(&g_chain, 0x31, 1, 13, 0x11, 5);
    CHECK(step(&o) == AMM_W_OK, "second reorganisation");
    CHECK(rec_state(0x31, 1, st) == 0 && (!strcmp(st, "seen") || !strcmp(st, "deep")),
          "the new log (index 1) is a live record (the old log 0 is reversed)");
    /* swap 2's marker comes from the NEW record itself (log index 1), not
     * from the string computed before the re-mine */
    amm_rec_t nr;
    char key2[AMM_TID_MAX];
    CHECK(rec_load(0x31, 1, &nr) == 0, "the re-mined record is read back");
    amm_journal_eth_key(nr.tx, key2, sizeof(key2));
    CHECK(nr.log_index == 1 && !strcmp(key2, key),
          "its key, derived from the new record (log 1), is the same eth:<tx hash>");
    /* review finding (b): swap 1 (reversed) still carries the id, so swap 2 is
     * refused already when it tries to wait on the same payment; the
     * permanent marker (the transaction hash, not hash + log index) stays the
     * second line of defence at `counted` */
    CHECK(amm_journal_swap_seen(g_j, s2.seq, key2, NULL, 500000000ULL, 0, NULL) == AMM_J_DUP_TRANSFER,
          "swap 2 naming the re-mined payment is refused: swap 1 already carries eth:<tx hash>");
    CHECK(swap_is(&s2, "approved"), "  swap 2 is unchanged (not paid)");
    CHECK(amm_journal_marker_exists(g_j, key2) == 0, "  the permanent marker still holds the transaction hash");
}

/* W22: a candidate holds an approval's window only when its block time is
 * within the validity (plan lines 314, 319). */
static void w22_candidate_time(void) {
    printf("W22 candidate matching by block time\n");
    uint8_t sender[20], amount[32];
    memset(sender, 0x11, 20); memset(amount, 0, 32); amount[31] = 5;
    fresh(20);
    ch_build(&g_chain, 1, 16, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 11, 0x11, 5);             /* candidate, block 11, ts 132 */
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[1].fail_logs = 1;
    amm_eth_step_t o;
    step(&o);
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "candidate"), "setup: a candidate with block time 132");
    CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 1,
          "expiry 100: the candidate (132) lies after the validity: the window is observed");
    CHECK(amm_eth_watch_window_observed(g_w, 1, 132, sender, amount) == 0,
          "expiry 132: the candidate (132) is within the validity: not observed");
    /* review finding (a), the candidate check, by chain HEIGHT: a candidate in
     * a block at or below the tip read at approval is not a payment for that
     * approval and holds nothing (the candidate is in block 11; block 13, ts
     * 156, is the first scanned block after expiry 150) */
    CHECK(amm_eth_watch_window_observed(g_w, 10, 150, sender, amount) == 0,
          "approval tip 10, expiry 150: the candidate (block 11) is one above: not observed");
    CHECK(amm_eth_watch_window_observed(g_w, 11, 150, sender, amount) == 1,
          "approval tip 11: the candidate is in the tip block, not above it: observed");
    CHECK(amm_eth_watch_window_observed(g_w, 12, 150, sender, amount) == 1,
          "approval tip 12: the candidate lies before the approval: observed");
}

/* W23: the liquidity depth helper uses the joint vote, not the global tip. */
static void w23_liquidity_depth(void) {
    printf("W23 depth helper: the same providers give the receipt and the deep tip\n");
    fresh(400);
    ch_build(&g_chain, 1, 14, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);             /* receipt voters: A and B    */
    ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 5);
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[0].tip_override = 13;                           /* tips: A 13, B 310, C 310   */
    g_sp[1].tip_override = 310;
    g_sp[2].tip_override = 310;
    amm_eth_step_t o;
    step(&o);
    amm_rec_t r;
    CHECK(rec_load(0x31, 0, &r) == 0, "the payment at block 10 is recorded");
    CHECK(amm_journal_cursor_get(g_j, "eth_tip", &o.tip) == 0 && o.tip == 310,
          "the stored global quorum tip is 310 (so tip - block would read 300)");
    int reached = 99;
    CHECK(amm_eth_watch_depth_reached(g_w, &r, 3, 0, &reached) == 0 && reached == 1,
          "depth 3 IS reached: A (tip 13) and B (tip 310) both hold the receipt");
    reached = 99;
    CHECK(amm_eth_watch_depth_reached(g_w, &r, 300, 0, &reached) == 0 && reached == 0,
          "depth 300 is NOT reached: only B supplies both the receipt and a tip 300 above it");
    g_sp[0].tip_override = 310;                          /* A catches up               */
    CHECK(amm_eth_watch_depth_reached(g_w, &r, 300, 0, &reached) == 0 && reached == 1,
          "depth 300 is reached once A and B both report tip 310");
    /* unknown, not a verdict: fewer than Q usable providers */
    g_sp[1].fail_all = 1; g_sp[2].fail_all = 1;
    reached = 99;
    CHECK(amm_eth_watch_depth_reached(g_w, &r, 3, 0, &reached) == 1 && reached == 99,
          "fewer than Q usable providers: unknown, the answer is untouched");
}

/* A watcher with the plan's counts 3 / 5 / 33 and window 40 on a fresh world. */
static void fresh_prod(void) {
    fresh(40);
    amm_eth_watch_cfg_t c = base_cfg();
    prod_counts(&c);
    c.window_blocks = 40;
    new_watch(&c);
}

/* One depth case: a payment of `raw` (+ `high` byte) in block 10 is `seen`
 * at tip 10 + need - 1 and `deep` at tip 10 + need. */
static void depth_case(const char *name, uint64_t raw, uint8_t high, int need) {
    char msg[160], st[16];
    amm_eth_step_t o;
    fresh_prod();
    ch_build(&g_chain, 1, 10 + need - 1, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    ch_set_value(&g_chain, 0x31, raw, high);
    step(&o);
    snprintf(msg, sizeof(msg), "%s: depth %d (tip %d): seen, not deep", name, need - 1, 10 + need - 1);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "seen") && o.deep == 0, msg);
    ch_build(&g_chain, 1, 10 + need, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    ch_set_value(&g_chain, 0x31, raw, high);
    step(&o);
    snprintf(msg, sizeof(msg), "%s: depth %d (tip %d): deep", name, need, 10 + need);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") && o.deep == 1, msg);
}

static void w24_depth_by_amount(void) {
    printf("W24 depth by the payment's USDT amount (givens item 60; 6 decimals)\n");
    /* the pure rule, with every bound edge */
    fresh_prod();
    struct { uint64_t raw; uint8_t high; uint64_t want; const char *what; } t[] = {
        {1,          0, 3,  "1 raw unit"},
        {99999999,   0, 3,  "99.999999 USDT"},
        {100000000,  0, 3,  "exactly 100 USDT (bound included)"},
        {100000001,  0, 5,  "100.000001 USDT"},
        {999999999,  0, 5,  "999.999999 USDT"},
        {1000000000, 0, 5,  "exactly 1,000 USDT (bound included)"},
        {1000000001, 0, 33, "1,000.000001 USDT"},
        {1000000000000ULL, 0, 33, "1,000,000 USDT (no upper bound)"},
        {UINT64_MAX, 0, 33, "the largest 64-bit amount"},
        {5,          1, 33, "an amount above 64 bits is above every bound"},
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        uint8_t v[32];
        memset(v, 0, 32);
        for (int k = 0; k < 8; k++) v[31 - k] = (uint8_t)(t[i].raw >> (8 * k));
        v[0] = t[i].high;
        char msg[120];
        snprintf(msg, sizeof(msg), "count for %s is %llu", t[i].what,
                 (unsigned long long)t[i].want);
        CHECK(amm_eth_watch_confirmations(g_w, v) == t[i].want, msg);
    }
    /* the watcher honours it: seen one block short, deep at the count */
    depth_case("100 USDT", 100000000ULL, 0, 3);
    depth_case("100.000001 USDT", 100000001ULL, 0, 5);
    depth_case("1,000 USDT", 1000000000ULL, 0, 5);
    depth_case("1,000.000001 USDT", 1000000001ULL, 0, 33);
    depth_case("above 64 bits", 5, 1, 33);
}

static void w25_window_by_value(void) {
    printf("W25 window rule uses the count of the approval's value (givens item 60)\n");
    uint8_t sender[20];
    memset(sender, 0x11, 20);
    /* expiry 100: ts = h * 12, so block 9 (108) is the first after it */
    /* hi = 1 sets bit 64 (byte 23), so the value no longer fits 64 bits */
    static const struct { uint64_t raw; int hi; int need; const char *what; } t[] = {
        {100000000ULL,  0, 3,  "value 100 USDT (count 3)"},
        {100000001ULL,  0, 5,  "value 100.000001 USDT (count 5)"},
        {1000000000ULL, 0, 5,  "value 1,000 USDT (count 5)"},
        {1000000001ULL, 0, 33, "value 1,000.000001 USDT (count 33)"},
        {5ULL,          1, 33, "value above 64 bits (count 33)"},
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        uint8_t amount[32];
        memset(amount, 0, 32);
        for (int k = 0; k < 8; k++) amount[31 - k] = (uint8_t)(t[i].raw >> (8 * k));
        if (t[i].hi) amount[23] = 1;
        char msg[160];
        amm_eth_step_t o;
        fresh_prod();
        ch_build(&g_chain, 1, 9 + t[i].need - 1, 0, 0);
        step(&o);
        snprintf(msg, sizeof(msg), "%s: block 9 at depth %d: not observed", t[i].what, t[i].need - 1);
        CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 0, msg);
        ch_build(&g_chain, 1, 9 + t[i].need, 0, 0);
        step(&o);
        snprintf(msg, sizeof(msg), "%s: block 9 at depth %d: observed", t[i].what, t[i].need);
        CHECK(amm_eth_watch_window_observed(g_w, 1, 100, sender, amount) == 1, msg);
    }
}

/* W26  the evidence set of the block logs is the parent's: every usable provider
 * is asked, whatever its header read returned (the first version of this test
 * asserted a saving, no get_logs for a provider without the quorum header, which
 * changed verdicts against bf5a4bcb4 and was removed in two steps, 2026-11-12:
 * Sol recheck 2 for failed header reads, the code red team N2 for different
 * headers).
 * PROVES: with three providers and quorum 2, (a) a provider that has NO header
 * at height 10 and (b) a provider that returns a DIFFERENT header at heights
 * 10..13 ARE asked get_logs for those heights (counted per block in the stub),
 * the two agreeing providers are asked, the control block 9 asks all three, and
 * the payment at block 10 still counts (logs of another block hash are rejected
 * by log_ok, as at the parent).
 * FLAGS: default build. LEAVES BEHIND: the usual /tmp journal of this file.
 * HOW IT CAN FALSELY PASS: the counter is the stub's own get_logs entry, so a
 * watcher that fetched the logs through another call (get_tx, get_receipt)
 * would not be seen; the heights checked are the ones where the stub's headers
 * differ, so it proves nothing about a provider that disagrees only on a later
 * header. The assertions require POSITIVE get_logs counters for the provider
 * without the quorum header (variant a at block 10, variant b at blocks 10 to
 * 13), for the two agreeing providers at block 10 and for all three at block
 * 9: the test fails if any of them is not asked (a skipping watcher). */
static void w26_logs_asked_of_every_usable_provider(void) {
    printf("W26 get_logs is asked of every usable provider, whatever its header read returned\n");
    for (int variant = 0; variant < 2; variant++) {
        fresh(20);
        ch_build(&g_chain, 1, 13, 0, 0);
        g_alt[0] = g_chain; g_alt[1] = g_chain;
        if (variant == 0) {                              /* no header at 10 */
            g_alt[2] = g_chain;
            g_alt[2].b[10].exists = 0;
        } else {                                         /* another header from 10 */
            ch_build(&g_alt[2], 1, 13, 10, 1);
        }
        ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);
        ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 5);
        for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
        amm_eth_step_t o;
        step_n(3, &o);
        const int last = variant == 0 ? 10 : 13;
        int asked_bad = 0;
        for (int h = 10; h <= last; h++) asked_bad += g_sp[2].asked[h];
        if (variant == 0)
            CHECK(asked_bad > 0, "no header at 10: that provider IS asked for block 10 (the parent's evidence)");
        else {
            int all = 1;
            for (int h = 10; h <= 13; h++) all &= g_sp[2].asked[h] > 0;
            CHECK(all, "another header at 10..13: that provider IS asked for each of those blocks (the parent's evidence)");
        }
        CHECK(g_sp[0].asked[10] > 0 && g_sp[1].asked[10] > 0, "  the two agreeing providers are asked for block 10");
        CHECK(g_sp[0].asked[9] > 0 && g_sp[1].asked[9] > 0 && g_sp[2].asked[9] > 0,
              "  control: all three providers are asked for block 9, where all agree");
        char st[16];
        CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"),
              "  the payment counts (state deep) through the quorum of two");
    }
}

/* W27  a provider whose header read FAILED at h is still asked for the logs of
 * h: every usable provider except one with a different header is asked, in
 * provider index order, as at the parent (Sol's case, 2026-11-12).
 * PROVES: (a) A and B hold the header, B's get_logs fails, C's header read
 * fails but its logs are those of the quorum block: C IS asked, two providers
 * answer and the payment counts (the parent's behaviour); (b) CHANGED 2026-11-12
 * (Sol recheck 2): C's header read fails but A and B answer: C is STILL asked
 * (no early stop; the parent's evidence set) and the payment counts.
 * HOW IT CAN FALSELY PASS: C's failure is a stub switch for every height
 * (fail_blocks), so it does not prove a per-height mix; the counter is the
 * stub's get_logs entry. On the unfixed b25d56738 watcher (a) fails: C is never
 * asked, one answer, the block is unknown. */
static void w27_failed_header_provider_is_fallback(void) {
    printf("W27 a provider whose header read failed is the fallback for the logs\n");
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    g_sp[1].fail_logs = 1;
    g_sp[2].fail_blocks = 1;
    amm_eth_step_t o;
    step_n(3, &o);
    char st[16];
    CHECK(g_sp[2].asked[10] > 0, "(a) C, whose header read failed, is asked once B's logs fail");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"),
          "(a) the payment counts through A and C (the parent's behaviour)");

    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    g_sp[2].fail_blocks = 1;
    step_n(3, &o);
    int c_asked = 0;
    for (int h = 1; h <= 13; h++) c_asked += g_sp[2].asked[h];
    CHECK(c_asked > 0, "(b) A and B answer: C, whose header read failed, is still asked (no early stop)");
    CHECK(g_sp[0].asked[10] > 0 && g_sp[1].asked[10] > 0, "(b) A and B are asked");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "(b) the payment counts");
}

/* W28  disagreement among the quorum-header providers asks the failed-header
 * provider too (Sol's scenario, 2026-11-12), as the parent's full set did.
 * PROVES: quorum 2; A and B return the quorum header at height 10, C's header
 * read fails; A and C list the same valid payment, B lists nothing. In ONE step
 * the payment is stored as counted (state seen or deep, never candidate): C was
 * asked (every usable provider without another header is asked, in index order).
 * HOW IT CAN FALSELY PASS: C's header failure is the stub switch fail_blocks for
 * every height; the check is on the record state after one step, so a later
 * step that happens to reach C would not hide it (a single step is run). On
 * e40c11e66 the first pass counts two answers and stops, the payment stays a
 * candidate, and the check fails. */
static void w28_disagreement_asks_failed_header_provider(void) {
    printf("W28 a disagreement among the quorum-header providers asks the failed-header provider\n");
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);          /* A lists the payment   */
    ch_pay(&g_alt[2], 0x31, 0, 10, 0x11, 5);          /* C lists the same one  */
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];   /* B (index 1): empty */
    g_sp[2].fail_blocks = 1;                          /* C's header read fails */
    amm_eth_step_t o;
    step(&o);
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && (!strcmp(st, "seen") || !strcmp(st, "deep")),
          "the payment is counted in that step (A and C agree), not left a candidate");
    CHECK(g_sp[2].asked[10] > 0, "C was asked for block 10 because A and B disagreed");
}

/* W29  no early stop: a provider whose header read failed is asked even when
 * the quorum-header providers all answered identically (Sol recheck 2,
 * 2026-11-12: skipping it changed verdicts against the parent's evidence set).
 * PROVES: quorum 2; A and B return the quorum header and EMPTY lists, C's header
 * read fails but C lists a payment in block 10: C is asked, and its below-quorum
 * listing is created as a candidate and dropped again in the same step (A and B
 * answered without it), never counted, exactly as at the parent; with C skipped
 * the payment is not recorded at all, and for a moved transaction the same skip
 * turns find_tx_record's "unknown" into "gone". The asserted facts: C's
 * get_logs counter for block 10, no seen/deep record, no candidate left.
 * HOW IT CAN FALSELY PASS: this is the eval_block form of Sol's counterexample
 * (a provider-only log), not the moved-transaction form through find_tx_record,
 * which needs a reorganisation fixture; both depend on the same gather_logs rule.
 * On f5a5f74b8 the first pass is unanimous (two empty lists), C is skipped, no
 * candidate is stored and the checks fail. */
static void w29_no_early_stop(void) {
    printf("W29 no early stop: the failed-header provider is asked when A and B agree on empty\n");
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
    ch_pay(&g_alt[2], 0x31, 0, 10, 0x11, 5);          /* only C lists the payment */
    for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
    g_sp[2].fail_blocks = 1;                          /* C's header read fails    */
    amm_eth_step_t o;
    step(&o);
    CHECK(g_sp[2].asked[10] > 0, "C is asked for block 10 although A and B answered");
    /* the parent's verdict (bf5a4bcb4): C's listing is below the quorum, so it
     * is stored as a candidate and, in the same step, rescan_candidates finds
     * two providers (A, B) answering without it and drops it (the existing W1
     * checks at the top of this file: a log listed by one provider alone is
     * never counted and is dropped once two providers answer without it) */
    CHECK(count_state("seen") + count_state("deep") == 0,
          "C's listing alone is never counted (the parent's verdict)");
    CHECK(count_state("candidate") == 0,
          "and no candidate is left: two providers answered without it, it is dropped in the same step");
}

/* W30  the moved-transaction form of Sol's counterexample through
 * find_tx_record (Sol recheck 2, 2026-11-12).
 * PROVES: a deep payment (tx 0x31, block 10, value 5) is seen again after a
 * reorganisation from block 10: in the new chain the transaction is mined in
 * block 12. A and B hold the new quorum header and their RECEIPTS put the
 * transaction in block 12, but their eth_getLogs for block 12 list nothing for
 * it; C's header read fails, C's receipt agrees and its eth_getLogs lists the
 * transaction with the quorum block's hash. The record must NOT be declared gone
 * in that step: it stays deep and nothing is dropped (the parent asked C, saw a
 * below-quorum listing and returned "unknown"; with C skipped find_tx_record
 * answers "gone" and the disappearance is applied: record dropped).
 * HOW IT CAN FALSELY PASS: the "receipt in 12 but no log in 12" fixture is a
 * provider inconsistency built by hand (the stub keeps receipts and logs
 * apart); any other reason the step leaves the record deep (for instance an
 * unrelated unknown) would also pass the state check, which is why the
 * dropped counter and C's get_logs counter for block 12 are checked too. On
 * f5a5f74b8 C is skipped for the block, the record is dropped and both fail. */
static void w30_moved_transaction_not_gone(void) {
    printf("W30 a moved transaction listed only by the failed-header provider is not declared gone\n");
    fresh(20);
    ch_build(&g_chain, 1, 15, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "setup: a deep payment of 5 at block 10");
    for (int i = 0; i < 3; i++) {
        ch_build(&g_alt[i], 1, 16, 10, 1);             /* fork at 10                    */
        ch_pay(&g_alt[i], 0x31, 0, 12, 0x11, 5);       /* mined again in block 12       */
        g_sp[i].ch = &g_alt[i];
    }
    for (int k = 0; k < NL; k++)                       /* A and B list no log for it    */
        for (int i = 0; i < 2; i++)
            if (g_alt[i].g[k].used && g_alt[i].g[k].l.tx[0] == 0x31) g_alt[i].g[k].used = 0;
    g_sp[2].fail_blocks = 1;                           /* C's header read fails         */
    memset(g_sp[2].asked, 0, sizeof(g_sp[2].asked));
    step(&o);
    CHECK(o.dropped == 0, "nothing is dropped in that step");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"),
          "the record is not declared gone: it stays deep");
    CHECK(g_sp[2].asked[12] > 0, "C was asked for the logs of block 12");
}

/* W31  the code red team's N2 (2026-11-12): a provider that returned a
 * DIFFERENT header at the moved transaction's new block still counts as
 * evidence through its logs.
 * PROVES: as W30, but C's header at block 12 is a DIFFERENT header (not a failed
 * read) while its eth_getLogs lists the transaction stamped with the QUORUM
 * block's hash. A and B list nothing for the transaction. The record is not
 * declared gone: it stays deep, nothing is dropped, and C was asked for block 12
 * (the parent counted C's listing: find_tx_record "unknown"; excluding C turns
 * it into "gone").
 * HOW IT CAN FALSELY PASS: the log stamped with the quorum hash from a provider
 * that disagrees about the header is a hand-built inconsistency, and the
 * receipt fixture is the one of W30; another reason for the record to stay deep
 * is excluded by the dropped counter and C's get_logs counter for block 12.
 * With C excluded (cae470fb7) the record is dropped and the checks fail. */
static void w31_different_header_provider_listing(void) {
    printf("W31 a moved transaction listed only by a different-header provider is not declared gone\n");
    fresh(20);
    ch_build(&g_chain, 1, 15, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    amm_eth_step_t o;
    step(&o);
    char st[16];
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), "setup: a deep payment of 5 at block 10");
    for (int i = 0; i < 2; i++) {                      /* A and B: the quorum chain */
        ch_build(&g_alt[i], 1, 16, 10, 1);
        ch_pay(&g_alt[i], 0x31, 0, 12, 0x11, 5);
        for (int k = 0; k < NL; k++)
            if (g_alt[i].g[k].used && g_alt[i].g[k].l.tx[0] == 0x31) g_alt[i].g[k].used = 0;
        g_sp[i].ch = &g_alt[i];
    }
    ch_build(&g_alt[2], 1, 16, 10, 2);                 /* C: another header from 10 */
    ch_pay(&g_alt[2], 0x31, 0, 12, 0x11, 5);
    for (int k = 0; k < NL; k++)                       /* C's log carries the QUORUM hash */
        if (g_alt[2].g[k].used && g_alt[2].g[k].l.tx[0] == 0x31)
            memset(g_alt[2].g[k].l.block_hash, hb(12, 1), 32);
    g_sp[2].ch = &g_alt[2];
    /* by block hash a provider answers about the block it HOLDS: C's own header
     * at 12 is another one, so the fixture says it also holds the quorum block */
    g_sp[2].has_also = 1; g_sp[2].also_blk = 12; g_sp[2].also_byte = hb(12, 1);
    memset(g_sp[2].asked, 0, sizeof(g_sp[2].asked));
    step(&o);
    CHECK(o.dropped == 0, "nothing is dropped in that step");
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"),
          "the record is not declared gone: it stays deep");
    CHECK(g_sp[2].asked[12] > 0, "C, with another header at block 12, was asked for its logs");
}

/* W32  the block-hash read: an answer is about exactly the accepted block
 * (the defect: get_logs asked by block NUMBER, so a provider holding another
 * block at that height answered an empty list about that other block; log_ok
 * dropped nothing, but answered counted it and its empty list was an "absent"
 * vote that dropped a candidate or declared a moved payment gone).
 * Across EventManager (EventUtils.ts:157-171) removes an event only on a report
 * bound to that event's blockHash; filter.yaml:40-59 "Filter by block hash" and
 * geth filter.go:83-97 (an unknown hash is an error) give the same binding here.
 * PROVES, each for a control run (C also holds the quorum block and answers an
 * empty list: the old verdict) and the defect run (C holds another block at the
 * height: its answer to the quorum hash is an ERROR, not an empty list):
 *  (1) candidate drop (eval_block): a candidate is retained (W2 setup); then A
 *      holds the quorum block and lists nothing, B fails the log read, C is on
 *      another block. Defect run: answered = 1 < Q, the block is unknown: the
 *      candidate is still there, nothing is dropped, o.unknown > 0. Control run:
 *      answered = 2 (A, C both without it): the candidate is dropped (this shows
 *      the fixture reaches the drop).
 *  (2) moved record (find_tx_record): W30's fixture with B failing its logs and
 *      C on another block with no transaction. Defect run: answered = 1 < Q,
 *      unknown: the record stays deep, o.dropped == 0. Control run: A and C
 *      answer empty, find_tx_record says gone and the record is no longer deep.
 * HOW IT CAN FALSELY PASS: the control runs are what tells the defect runs
 * apart from a fixture that never reaches the verdict; the stub's hash rule
 * (holds = its own header at the height has that hash, or also_hash) is the
 * test's model of a provider, not a provider. On 32425b38e the new get_logs
 * signature does not exist, so the file does not compile there; against the
 * by-number behaviour the defect runs fail at: (1) "the candidate is kept"
 * (count_state("candidate") == 1 sees 0) and (2) "the record stays deep". */
static void w32_block_hash_answer(void) {
    printf("W32 an answer about another block is an error, not an absent vote\n");
    amm_eth_step_t o;
    char st[16];
    for (int control = 0; control < 2; control++) {
        const char *run = control ? "control (C holds the quorum block)" : "defect run (C holds another block)";
        char msg[160];
        /* (1) candidate drop */
        fresh(20);
        ch_build(&g_chain, 1, 13, 0, 0);
        g_alt[0] = g_chain; g_alt[1] = g_chain; g_alt[2] = g_chain;
        ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);
        ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 6);
        for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
        g_sp[2].fail_logs = 1;
        step(&o);
        snprintf(msg, sizeof(msg), "(1) %s: setup, one candidate is retained", run);
        CHECK(count_state("candidate") == 1, msg);
        for (int k = 0; k < NL; k++)                   /* A and B no longer list it */
            for (int i = 0; i < 2; i++)
                if (g_alt[i].g[k].used && g_alt[i].g[k].l.tx[0] == 0x31) g_alt[i].g[k].used = 0;
        g_sp[2].fail_logs = 0;
        g_sp[1].fail_logs = 1;                         /* B fails the log read      */
        ch_build(&g_alt[2], 1, 13, 10, 2);             /* C: another block from 10  */
        if (control) { g_sp[2].has_also = 1; g_sp[2].also_blk = 10; g_sp[2].also_byte = hb(10, 0); }
        step(&o);
        if (control) {
            snprintf(msg, sizeof(msg), "(1) %s: A and C answer without it, the candidate is dropped", run);
            CHECK(count_state("candidate") == 0, msg);
        } else {
            snprintf(msg, sizeof(msg), "(1) %s: the candidate is kept (answered 1 < Q)", run);
            CHECK(count_state("candidate") == 1, msg);
            CHECK(o.dropped == 0 && o.unknown > 0, "(1)   nothing dropped, the step reports unknown");
        }

        /* (2) moved record */
        fresh(20);
        ch_build(&g_chain, 1, 15, 0, 0);
        ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
        step(&o);
        snprintf(msg, sizeof(msg), "(2) %s: setup, a deep payment at block 10", run);
        CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep"), msg);
        for (int i = 0; i < 2; i++) {                  /* A and B: the quorum chain */
            ch_build(&g_alt[i], 1, 16, 10, 1);
            ch_pay(&g_alt[i], 0x31, 0, 12, 0x11, 5);
            for (int k = 0; k < NL; k++)
                if (g_alt[i].g[k].used && g_alt[i].g[k].l.tx[0] == 0x31) g_alt[i].g[k].used = 0;
            g_sp[i].ch = &g_alt[i];
        }
        ch_build(&g_alt[2], 1, 16, 10, 2);             /* C: another block, no tx   */
        g_sp[2].ch = &g_alt[2];
        g_sp[1].fail_logs = 1;                         /* B fails the log read      */
        if (control) { g_sp[2].has_also = 1; g_sp[2].also_blk = 12; g_sp[2].also_byte = hb(12, 1); }
        step(&o);
        if (control) {
            snprintf(msg, sizeof(msg), "(2) %s: A and C answer empty, the record is declared gone (not deep)", run);
            CHECK(rec_state(0x31, 0, st) == 0 && strcmp(st, "deep") != 0, msg);
        } else {
            snprintf(msg, sizeof(msg), "(2) %s: the record stays deep (answered 1 < Q, unknown)", run);
            CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "deep") && o.dropped == 0, msg);
        }
    }
}

/* ═══ W33-W35: the providers of a group are asked at the same time (plan
 *     docs/plans/approved/2026-11-12-bot-round-latency.md 6.2.2, 7.0, 7.1.2) ═══
 *
 * PROVES
 *   W33 arrival order changes nothing. Three scenarios (the shapes of W1: a
 *       quorum record, a below-quorum candidate that is later resolved and a log
 *       listed by one provider only; W8: a reorganisation and a moved record;
 *       W17: the joint depth vote) run once with no gate and once for each method
 *       with a counting gate in REVERSE mode (tests/amm_test_gate.h: k = 3; the
 *       three providers' calls of a group are in flight at the same time and
 *       return in descending provider index). Equal in every pair: the journal's
 *       record rows (all states), the stored block rows, the cursor, each step's
 *       result and counters, and the watcher's AMM_WATCH log lines in order
 *       (read from a log file in the test's own mkdtemp directory, timestamps
 *       stripped). timed_out == 0 in every gated run (all three providers were in
 *       flight at once) and the gate saw one generation per group.
 *       SCOPING (7.0): a method is gated in a scenario only when the ungated run
 *       shows every provider called it equally often (once per usable provider
 *       per group); such a pair is otherwise skipped and the test asserts that
 *       every method was gated in at least one scenario.
 *   W34 a provider that answers last with an error: provider 2's get_logs waits
 *       until providers 0 and 1 have returned theirs, then fails; the step's
 *       results, rows and log lines equal those of the run where provider 2 fails
 *       at once; provider 2's held calls have all returned when the step returns.
 *   W34b the unit is the bound: in verify_record, provider 2's get_tx returns at
 *       once and its get_receipt waits until providers 0 and 1 have finished their
 *       units; the step returns only after that second request (a serial run
 *       passes this too; what it rules out is a join that waits for each unit's
 *       first request only).
 *   W35 every usable provider is still asked: the per-stub call counts and the
 *       asked[] sets of W33's gated runs equal those of the ungated runs.
 * FLAGS: none. ENVIRONMENT: none. LEAVES BEHIND: nothing (mkdtemp directories
 *   under /tmp, removed).
 * HOW THEY CAN FALSELY PASS: a pair excluded by the scoping rule is not gated (the
 *   at-least-one assertion shows a method that no scenario gated); W34/W34b pass
 *   on a serial implementation by construction; the log-line comparison proves the
 *   lines are equal for these scenarios, not for every possible one; the gate
 *   widens the interleavings that occur, it does not enumerate them. */
static amm_gate_t g_wg;
static amm_ctr_t  g_wc;
static int        g_wg_ready;

static void wg_ready(void) {
    if (g_wg_ready) return;
    amm_gate_init(&g_wg);
    amm_ctr_init(&g_wc);
    g_wg_ready = 1;
}

/* set when a signature did not fit its buffer: a truncated signature must FAIL
 * the test (checked after every compared pair), never pass it */
static int g_sig_overflow;

static void sig_add(char *sig, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void sig_add(char *sig, size_t cap, const char *fmt, ...) {
    size_t n = strlen(sig);
    if (n >= cap - 1) { g_sig_overflow = 1; return; }
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(sig + n, cap - n, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= cap - n) g_sig_overflow = 1;
}

static void sig_hex(char *sig, size_t cap, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) sig_add(sig, cap, "%02x", b[i]);
}

static char g_cdir[64];

/* open a log file in a fresh mkdtemp directory */
static void cap_begin(void) {
    snprintf(g_cdir, sizeof(g_cdir), "/tmp/amm_watch_logXXXXXX");
    if (!mkdtemp(g_cdir)) { printf("FATAL mkdtemp\n"); exit(2); }
    if (nodus_log_file_open(g_cdir, 1 << 20, 1) != 0) { printf("FATAL log file\n"); exit(2); }
}

/* close it and append every AMM_WATCH line, its timestamp stripped */
static void cap_end(char *sig, size_t cap) {
    nodus_log_file_close();
    char path[128];
    snprintf(path, sizeof(path), "%s/nodus-amm.log", g_cdir);
    FILE *f = fopen(path, "r");
    char line[1100];
    while (f && fgets(line, sizeof(line), f)) {
        if (!strstr(line, "AMM_WATCH:")) continue;
        const char *q = strstr(line, "Z [");
        sig_add(sig, cap, "L:%s", q ? q + 2 : line);
    }
    if (f) fclose(f);
    unlink(path);
    rmdir(g_cdir);
}

/* the journal's rows, the stored blocks and the cursor, as text */
static void state_sig(char *sig, size_t cap) {
    static const char *const states[] = { "candidate", "seen", "deep", "held", "dropped", "reversed" };
    amm_rec_t *r = calloc(256, sizeof(*r));
    for (size_t k = 0; k < sizeof(states) / sizeof(states[0]); k++) {
        int n = 0;
        if (amm_journal_rec_list(g_j, 0, states[k], r, 256, &n) != 0) { sig_add(sig, cap, "R:%s:fault\n", states[k]); continue; }
        /* every field of amm_rec_t, field by field (no struct memcmp: padding never enters) */
        for (int i = 0; i < n; i++) {
            sig_add(sig, cap, "R:%s tx=", r[i].state);
            sig_hex(sig, cap, r[i].tx, 32);
            sig_add(sig, cap, " li=%u blk=%llu bh=", r[i].log_index, (unsigned long long)r[i].block_number);
            sig_hex(sig, cap, r[i].block_hash, 32);
            sig_add(sig, cap, " ts=%llu from=", (unsigned long long)r[i].block_ts);
            sig_hex(sig, cap, r[i].from, 20);
            sig_add(sig, cap, " to=");
            sig_hex(sig, cap, r[i].to, 20);
            sig_add(sig, cap, " v=");
            sig_hex(sig, cap, r[i].value, 32);
            sig_add(sig, cap, "\n");
        }
    }
    free(r);
    for (uint64_t h = 1; h <= 20; h++) {
        amm_blk_t b;
        if (amm_journal_block_get(g_j, h, &b) != 0) continue;
        sig_add(sig, cap, "B:%llu hash=", (unsigned long long)b.height);
        sig_hex(sig, cap, b.hash, 32);
        sig_add(sig, cap, " parent=");
        sig_hex(sig, cap, b.parent, 32);
        sig_add(sig, cap, " ts=%llu\n", (unsigned long long)b.ts);
    }
    sig_add(sig, cap, "C:%llu\n", (unsigned long long)cursor("eth_scan"));
}

static void step_sig(char *sig, size_t cap, int rc, const amm_eth_step_t *o) {
    sig_add(sig, cap, "S:%d u%d t%llu b%d r%d n%d d%d x%d v%d k%d\n", rc, o->usable, (unsigned long long)o->tip,
            o->blocks, o->reorgs, o->new_records, o->deep, o->dropped, o->reversed, o->unknown);
}

typedef struct {
    char sig[65536];                  /* full-field rows and blocks, hex; sig_add flags an overflow */
    char asked[2048];
    int  mcalls[GM_N][3];
    int  timed_out, gens;
} w33_out_t;

static w33_out_t g_w33_ref, g_w33_gat;

static void w33_step(char *sig, size_t cap) {
    amm_eth_step_t o;
    int rc = step(&o);
    step_sig(sig, cap, rc, &o);
}

/* One run of scenario `scen` (0: W1 shape, 1: W8 shape, 2: W17 shape); gm < 0: no
 * gate, else every provider's gm method goes through the reverse gate (k = 3). */
static void w33_run(int scen, int gm, w33_out_t *out) {
    memset(out, 0, sizeof(*out));
    fresh(20);
    if (scen == 0) {
        ch_build(&g_chain, 1, 13, 0, 0);
        for (int i = 0; i < 3; i++) g_alt[i] = g_chain;
        for (int i = 0; i < 3; i++) ch_pay(&g_alt[i], 0x31, 0, 10, 0x11, 5);     /* the quorum record */
        ch_pay(&g_alt[0], 0x32, 0, 11, 0x11, 6);          /* listed by one provider only */
        for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
        g_sp[1].fail_logs = 1;
    } else if (scen == 1) {
        ch_build(&g_chain, 1, 15, 0, 0);
        ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
        ch_pay(&g_chain, 0x32, 0, 13, 0x11, 7);
    } else {
        ch_build(&g_chain, 1, 14, 0, 0);
        for (int i = 0; i < 3; i++) g_alt[i] = g_chain;
        ch_pay(&g_alt[0], 0x31, 0, 10, 0x11, 5);
        ch_pay(&g_alt[1], 0x31, 0, 10, 0x11, 5);
        for (int i = 0; i < 3; i++) g_sp[i].ch = &g_alt[i];
        g_sp[0].tip_override = 11;
    }
    if (gm >= 0) {
        amm_gate_arm(&g_wg, 3, 1);
        for (int i = 0; i < 3; i++) g_sp[i].gate[gm] = &g_wg;
    }
    cap_begin();
    if (scen == 0) {
        w33_step(out->sig, sizeof(out->sig));
        w33_step(out->sig, sizeof(out->sig));            /* the candidate is retained */
        g_sp[1].fail_logs = 0;
        w33_step(out->sig, sizeof(out->sig));            /* the quorum forms: dropped */
    } else if (scen == 1) {
        w33_step(out->sig, sizeof(out->sig));
        ch_build(&g_chain, 1, 16, 12, 1);                /* fork at 12 */
        ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
        ch_pay(&g_chain, 0x32, 1, 14, 0x11, 7);
        w33_step(out->sig, sizeof(out->sig));
        ch_build(&g_chain, 1, 17, 12, 2);                /* a second reorganisation */
        ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
        ch_pay(&g_chain, 0x32, 0, 15, 0x11, 7);
        w33_step(out->sig, sizeof(out->sig));
    } else {
        w33_step(out->sig, sizeof(out->sig));
        w33_step(out->sig, sizeof(out->sig));
        g_sp[0].tip_override = 0;
        w33_step(out->sig, sizeof(out->sig));
    }
    state_sig(out->sig, sizeof(out->sig));
    cap_end(out->sig, sizeof(out->sig));
    if (gm >= 0) {
        amm_gate_disarm(&g_wg);
        out->timed_out = amm_gate_timed_out(&g_wg);
        out->gens = amm_gate_gens(&g_wg);
    }
    for (int i = 0; i < 3; i++) {
        for (int m = 0; m < GM_N; m++) out->mcalls[m][i] = g_sp[i].mcalls[m];
        sig_add(out->asked, sizeof(out->asked), "P%d calls%d:", i, g_sp[i].calls);
        for (int h = 0; h < 64; h++)
            if (g_sp[i].asked[h]) sig_add(out->asked, sizeof(out->asked), " %d=%d", h, g_sp[i].asked[h]);
        sig_add(out->asked, sizeof(out->asked), "\n");
    }
}

static void w33_arrival_order(void) {
    printf("W33 the providers of a group in flight at once, returning in reverse order: nothing changes\n");
    wg_ready();
    int gated_runs[GM_N] = { 0 };
    for (int scen = 0; scen < 3; scen++) {
        w33_run(scen, -1, &g_w33_ref);
        for (int gm = 0; gm < GM_N; gm++) {
            const int *mc = g_w33_ref.mcalls[gm];
            if (mc[0] == 0 || mc[0] != mc[1] || mc[0] != mc[2]) continue;      /* the scoping rule of 7.0 */
            w33_run(scen, gm, &g_w33_gat);
            gated_runs[gm]++;
            char m[160];
            snprintf(m, sizeof(m), "scenario %d, %s gated: all three providers in flight at once (no timeout)", scen, GM_NAME[gm]);
            CHECK(g_w33_gat.timed_out == 0, m);
            snprintf(m, sizeof(m), "scenario %d, %s gated: one gate generation per group (%d)", scen, GM_NAME[gm], mc[0]);
            CHECK(g_w33_gat.gens == mc[0], m);
            snprintf(m, sizeof(m), "scenario %d, %s gated: rows, blocks, cursor, step counters and log lines equal the ungated run",
                     scen, GM_NAME[gm]);
            CHECK(strcmp(g_w33_gat.sig, g_w33_ref.sig) == 0 && !g_sig_overflow, m);
            snprintf(m, sizeof(m), "W35 scenario %d, %s gated: every provider asked as before (calls and asked[] equal)", scen, GM_NAME[gm]);
            CHECK(strcmp(g_w33_gat.asked, g_w33_ref.asked) == 0, m);
        }
    }
    for (int gm = 0; gm < GM_N; gm++) {
        char m[96];
        snprintf(m, sizeof(m), "%s was gated in at least one scenario", GM_NAME[gm]);
        CHECK(gated_runs[gm] > 0, m);
    }
}

typedef struct { char sig[65536]; int returned, calls2; } w34_out_t;
static w34_out_t g_w34_a, g_w34_b;

/* hold = 0: the reference; 1: provider 2's hold_method waits for providers 0 and 1 */
static void w34_run(int variant, int hold, w34_out_t *out) {
    memset(out, 0, sizeof(*out));
    fresh(20);
    ch_build(&g_chain, 1, 13, 0, 0);
    ch_pay(&g_chain, 0x31, 0, 10, 0x11, 5);
    int gm = variant == 0 ? GM_LOGS : GM_RECEIPT;
    if (variant == 0) g_sp[2].fail_logs = 1;                       /* W34: the last provider fails */
    amm_ctr_reset(&g_wc);
    if (hold) {
        g_sp[2].hold_method = gm; g_sp[2].hold_need = 2; g_sp[2].hold_ctr = &g_wc;
        for (int i = 0; i < 2; i++) { g_sp[i].unit_method = gm; g_sp[i].unit_ctr = &g_wc; }
    }
    cap_begin();
    w33_step(out->sig, sizeof(out->sig));
    if (variant == 0) w33_step(out->sig, sizeof(out->sig));
    state_sig(out->sig, sizeof(out->sig));
    cap_end(out->sig, sizeof(out->sig));
    out->returned = atomic_load(&g_sp[2].hold_returned);
    out->calls2 = g_sp[2].mcalls[gm];
}

static void w34_late_provider(void) {
    printf("W34 a provider that answers last: the group waits for it, nothing changes\n");
    wg_ready();
    w34_run(0, 0, &g_w34_a);
    w34_run(0, 1, &g_w34_b);
    CHECK(g_w34_a.calls2 > 0 && strstr(g_w34_a.sig, "S:") != NULL, "setup: the logs are read from provider 2 (it fails at once)");
    CHECK(amm_ctr_timed_out(&g_wc) == 0, "provider 2's get_logs waited for providers 0 and 1 (no timeout)");
    CHECK(strcmp(g_w34_b.sig, g_w34_a.sig) == 0 && !g_sig_overflow,
          "the steps' results, the rows and the log lines equal the run where provider 2 fails at once");
    CHECK(g_w34_b.returned == g_w34_b.calls2 && g_w34_b.calls2 > 0,
          "every held get_logs of provider 2 had returned when the step returned (the join waited)");
    printf("W34b the unit is the bound: provider 2's second request is waited for\n");
    w34_run(1, 0, &g_w34_a);
    w34_run(1, 1, &g_w34_b);
    CHECK(g_w34_a.calls2 > 0, "setup: provider 2's get_receipt is called by verify_record");
    CHECK(amm_ctr_timed_out(&g_wc) == 0, "provider 2's get_receipt waited for providers 0 and 1 to finish their units (no timeout)");
    CHECK(strcmp(g_w34_b.sig, g_w34_a.sig) == 0 && !g_sig_overflow, "the step's result, rows and log lines equal the ungated run");
    CHECK(g_w34_b.returned == g_w34_b.calls2 && g_w34_b.calls2 > 0,
          "the step returned only after provider 2's get_receipt returned (its flag is set)");
}

int main(void) {
    printf("test_amm_eth_watch\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/amm_watch_testXXXXXX");
    if (!mkdtemp(g_dir)) { printf("FATAL mkdtemp\n"); return 2; }
    snprintf(g_path, sizeof(g_path), "%s/journal.db", g_dir);

    w1_quorum();
    w2_disagreement();
    w3_unknown();
    w4_chain_id();
    w5_depth();
    w6_ignored();
    w7_match();
    w8_reorg();
    w9_gone_unpaid();
    w10_reversal();
    w11_restart();
    w12_window_limit();
    w13_window_observation();
    w14_order();
    w15_restart();
    w16_config();
    w17_depth_votes();
    w18_false_candidate();
    w20_moved_value();
    w21_marker_by_hash();
    w22_candidate_time();
    w23_liquidity_depth();
    w24_depth_by_amount();
    w25_window_by_value();
    w26_logs_asked_of_every_usable_provider();
    w27_failed_header_provider_is_fallback();
    w28_disagreement_asks_failed_header_provider();
    w29_no_early_stop();
    w30_moved_transaction_not_gone();
    w31_different_header_provider_listing();
    w32_block_hash_answer();
    w33_arrival_order();
    w34_late_provider();

    if (g_w) amm_eth_watch_free(g_w);
    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
