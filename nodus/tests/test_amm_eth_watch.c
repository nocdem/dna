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
 *   W7  matching (pure): sender + exact logged value + block time within the
 *       expiry = MATCH; another value = held (mismatched value); another
 *       sender = none; block time after the expiry = held; a payment first
 *       read after the expiry time but within it by block time still MATCHes;
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
 *       swap naming it cannot be counted (DUP_TRANSFER);
 *   W22 a candidate holds an approval's window only when its block time is
 *       within the validity: block time 132 blocks expiry 132, not expiry 100;
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
 *       refused (NULL).
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_eth_watch.h"

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

static int sp_chain_id(void *ctx, uint64_t *out, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all) return AMM_ETH_ERR;
    *out = s->chain_id; return AMM_ETH_OK;
}
static int sp_block_number(void *ctx, uint64_t *out, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all) return AMM_ETH_ERR;
    *out = s->tip_override ? s->tip_override : s->ch->tip; return AMM_ETH_OK;
}
static int sp_get_block(void *ctx, uint64_t n, amm_eth_block_t *o, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_blocks) return AMM_ETH_ERR;
    if (n >= NB || n > s->ch->tip || !s->ch->b[n].exists) return AMM_ETH_NOT_FOUND;
    o->number = n; memcpy(o->hash, s->ch->b[n].hash, 32);
    memcpy(o->parent, s->ch->b[n].parent, 32); o->timestamp = s->ch->b[n].ts;
    return AMM_ETH_OK;
}
static int sp_get_logs(void *ctx, uint64_t blk, const uint8_t *contract,
                       const uint8_t *topic0, const uint8_t *to,
                       amm_eth_log_t *out, int cap, int *n, uint64_t d) {
    (void)d; (void)contract; (void)topic0; (void)to; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_logs) return AMM_ETH_ERR;
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
static int sp_get_tx(void *ctx, const uint8_t *h, amm_eth_tx_t *o, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_tx) return AMM_ETH_ERR;
    stx_t *t = find_tx(s->ch, h);
    if (!t) return AMM_ETH_NOT_FOUND;
    memcpy(o->from, t->from, 20); memcpy(o->to, t->to, 20); o->has_to = t->has_to;
    o->input_len = t->input_len; memcpy(o->input_head, t->head, 4);
    return AMM_ETH_OK;
}
static int sp_get_receipt(void *ctx, const uint8_t *h, amm_eth_receipt_t *o, uint64_t d) {
    (void)d; sp_t *s = ctx; s->calls++;
    if (s->fail_all || s->fail_receipts) return AMM_ETH_ERR;
    stx_t *t = find_tx(s->ch, h);
    if (!t) return AMM_ETH_NOT_FOUND;
    o->status = t->status; o->block_number = t->bn; memcpy(o->block_hash, t->bh, 32);
    return AMM_ETH_OK;
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
    c.confirmations = 3; c.window_blocks = 20; c.start_height = 1;
    c.max_scan_blocks = 100; c.journal = g_j;
    return c;
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
    a.incoming_id = ""; a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    a.req_no[31] = (uint8_t)ctr; a.req_no[30] = (uint8_t)(ctr >> 8);
    for (int i = 0; i < 16; i++) a.rand16[i] = (uint8_t)(ctr * 7 + i);
    ctr++;
    if (amm_journal_approve(g_j, &a, s) != AMM_J_OK) return 0;
    uint8_t tx[32]; memset(tx, txb, 32);
    char key[AMM_TID_MAX];
    amm_journal_eth_key(tx, key, sizeof(key));        /* the transaction hash alone */
    if (!strcmp(target, "approved")) return 1;
    if (amm_journal_swap_transition(g_j, s->seq, "paid_waiting_depth", key, NULL, NULL) != 0) return 0;
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
    memset(r.from, 0x11, 20); r.value[31] = 5; r.block_ts = 96;
    uint8_t sender[20], other[20], amount[32], amount6[32];
    memset(sender, 0x11, 20); memset(other, 0x22, 20);
    memset(amount, 0, 32); amount[31] = 5;
    memset(amount6, 0, 32); amount6[31] = 6;
    CHECK(amm_eth_watch_match(&r, sender, amount, 100) == AMM_M_MATCH, "sender + amount + block time within expiry: MATCH");
    CHECK(amm_eth_watch_match(&r, sender, amount, 96) == AMM_M_MATCH, "block time == expiry: MATCH");
    CHECK(amm_eth_watch_match(&r, sender, amount6, 100) == AMM_M_HELD_VALUE, "another logged value: held");
    CHECK(amm_eth_watch_match(&r, other, amount, 100) == AMM_M_NONE, "another sender: none");
    CHECK(amm_eth_watch_match(&r, sender, amount, 95) == AMM_M_HELD_EXPIRED, "block time after the expiry: held");
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
    CHECK(amm_eth_watch_match(&got, sender, amount, 100) == AMM_M_MATCH,
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
    CHECK(amm_eth_watch_window_observed(g_w, 100, sender, amount) == 0,
          "tip 11: block 9 (first after the expiry) is at depth 2: not observed");
    ch_build(&g_chain, 1, 12, 0, 0);
    step(&o);
    CHECK(amm_eth_watch_window_observed(g_w, 100, sender, amount) == 1,
          "tip 12: block 9 at depth 3, cursor past it: observed");
    CHECK(amm_eth_watch_window_observed(g_w, 12 * 12, sender, amount) == 0,
          "an expiry later than every scanned block: not observed");
    /* reads failing: the cursor does not move, so a later window is not observed */
    fresh(20);
    ch_build(&g_chain, 1, 12, 0, 0);
    g_sp[0].fail_blocks = 1; g_sp[1].fail_blocks = 1;
    step(&o);
    CHECK(amm_eth_watch_window_observed(g_w, 100, sender, amount) == 0,
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
    CHECK(amm_eth_watch_window_observed(g_w, 100, sender, amount) == 0,
          "a below-quorum candidate for this approval is unresolved: not observed");
    uint8_t amount7[32];
    memset(amount7, 0, 32); amount7[31] = 7;
    CHECK(amm_eth_watch_window_observed(g_w, 100, sender, amount7) == 1,
          "another amount is not affected");
    g_sp[1].fail_logs = 0;                               /* it answers without: dropped */
    step(&o);
    CHECK(rec_state(0x31, 0, st) == 0 && !strcmp(st, "dropped") &&
          amm_eth_watch_window_observed(g_w, 100, sender, amount) == 1,
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
    c = base_cfg(); c.confirmations = 0;
    CHECK(amm_eth_watch_new(&c) == NULL, "zero confirmations refused");
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
            CHECK(amm_eth_watch_match(&r, sender, amount5, 1000) == AMM_M_HELD_VALUE,
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
    CHECK(amm_journal_swap_transition(g_j, s2.seq, "paid_waiting_depth", key2, NULL, NULL) == 0,
          "swap 2 names the re-mined payment by the new record's key");
    CHECK(amm_journal_swap_transition(g_j, s2.seq, "counted", NULL, NULL, NULL) == AMM_J_DUP_TRANSFER,
          "counting it again is refused: the marker is the transaction hash, not hash + log index");
    CHECK(swap_is(&s2, "paid_waiting_depth"), "  swap 2 is not paid");
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
    CHECK(amm_eth_watch_window_observed(g_w, 100, sender, amount) == 1,
          "expiry 100: the candidate (132) lies after the validity: the window is observed");
    CHECK(amm_eth_watch_window_observed(g_w, 132, sender, amount) == 0,
          "expiry 132: the candidate (132) is within the validity: not observed");
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

    if (g_w) amm_eth_watch_free(g_w);
    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
