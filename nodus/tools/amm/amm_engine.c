/**
 * @file amm_engine.c
 * @brief nodus-amm engine (see amm_engine.h).
 */
#include "amm_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amm_eth_tx.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_ENG"

struct amm_engine {
    amm_engine_cfg_t c;
    amm_cfg_t cfg;
    int page;                  /* rows per page of every list the step walks */
    int64_t nodus_after;       /* NODUS payouts: the last swap deferred in the
                                * previous round (0 = start from the oldest);
                                * in memory, a restart starts from 0          */
    /* the bounded walks (cfg.round_rows_max rows per list per round) resume
     * after the last row examined; 0 = start from the oldest. In memory: a
     * restart begins at the oldest row, which keeps the guarantee that every
     * row is examined after a bounded number of rounds. */
    int64_t release_after;     /* release(): approved swaps                  */
    int blk;                   /* decisions(): the shared wait causes found in THIS
                                * round (B_* below); reset at the start of every round */
    int wait_shared;           /* set by decide_one / act_withdraw when a row waited
                                * for a shared cause (B_*), 0 = a row-specific wait */
    int64_t adds_after[3];     /* liquidity_adds(): signed, approved, signed
                                * with no deposit matched                    */
    /* the question path's shared reads (givens item 98) */
    struct { int valid; uint64_t at_ms; uint64_t v; } rc_usdt, rc_nodus, rc_ethfee;
    /* the log: the last wait written per swap, so a wait is written once when
     * it starts or changes (in memory; a restart writes each wait again) */
    struct { int64_t seq; char why[96]; } waits[16];
    int n_waits, waits_next;
};

#include <time.h>

static uint64_t mono_now_ms(const amm_engine_t *e) {
    if (e->c.mono_ms) return e->c.mono_ms(e->c.mono_ctx);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

amm_engine_t *amm_engine_new(const amm_engine_cfg_t *c) {
    if (!c || !c->cfg || !c->journal || !c->eth_watch || !c->eth_pay ||
        !c->nodus_watch || !c->nodus_pay || !c->providers ||
        c->n_providers < 1 || c->n_providers > AMM_ETH_MAX_PROVIDERS ||
        c->quorum < 1 || c->quorum > c->n_providers || !c->price.fee_usdt ||
        !c->now_unix || !c->rand_fn || !c->node.ruleset_info || !c->node.balance ||
        c->page < 0 || c->page > AMM_ENGINE_PAGE_MAX)
        return NULL;
    for (int i = 0; i < c->n_providers; i++) {
        const amm_eth_provider_t *p = &c->providers[i];
        if (!p->estimate_gas || !p->gas_price || !p->erc20_balance) return NULL;
    }
    amm_engine_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->c = *c;
    e->cfg = *c->cfg;
    e->c.cfg = &e->cfg;
    e->page = c->page > 0 ? c->page : AMM_ENGINE_PAGE;
    return e;
}

void amm_engine_free(amm_engine_t *e) { free(e); }

/* ── small helpers ────────────────────────────────────────────────────── */

static void hex_to(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = H[b[i] >> 4]; out[2 * i + 1] = H[b[i] & 15]; }
    out[2 * n] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int from_hex(const char *s, uint8_t *out, size_t n) {
    if (strlen(s) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int a = hexval(s[2 * i]), b = hexval(s[2 * i + 1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return 0;
}

static void be32_of_u64(uint64_t v, uint8_t out[32]) {
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

/* A 32-byte big-endian value as a u64: 0 / -1 when it does not fit. */
static int be32_to_u64(const uint8_t b[32], uint64_t *out) {
    for (int i = 0; i < 24; i++)
        if (b[i]) return -1;
    uint64_t v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | b[i];
    *out = v;
    return 0;
}

static int desc(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? 1 : (x > y ? -1 : 0);
}

/* The Q-th largest of the answers (at least Q providers report that value or
 * more), as amm_eth_pay does. -1 when fewer than Q answered. */
static int kth_largest(uint64_t *v, int n, int q, uint64_t *out) {
    if (n < q) return -1;
    qsort(v, (size_t)n, sizeof(uint64_t), desc);
    *out = v[q - 1];
    return 0;
}

static uint64_t u256_to_u64_sat(const uint8_t b[32]) {
    for (int i = 0; i < 24; i++)
        if (b[i]) return UINT64_MAX;
    uint64_t v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | b[i];
    return v;
}

/* ── reads through the seams (a failed read is UNKNOWN, never zero) ───── */

static int read_eth_tip(amm_engine_t *e, uint64_t *tip) {
    uint64_t t = 0;
    if (amm_eth_watch_tip(e->c.eth_watch, &t) != 0 || t == 0) return -1;
    *tip = t;
    return 0;
}

static int read_nodus_tip(amm_engine_t *e, uint64_t dl, uint64_t *tip) {
    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (e->c.node.ruleset_info(e->c.node.ctx, &ri, dl) != AMM_NODE_OK || ri.tip == 0)
        return -1;
    *tip = ri.tip;
    return 0;
}

/* The bot's USDT: the SMALLEST answer of at least Q providers (a balance is
 * never taken higher than a provider says, amm_eth_pay.h). */
static int read_usdt_balance(amm_engine_t *e, uint64_t dl, uint64_t *bal) {
    uint8_t foundation[20];
    amm_eth_pay_self(e->c.eth_pay, foundation);
    uint64_t lo = UINT64_MAX;
    int ok = 0;
    for (int i = 0; i < e->c.n_providers; i++) {
        const amm_eth_provider_t *p = &e->c.providers[i];
        uint8_t w[32];
        if (p->erc20_balance(p->ctx, e->cfg.usdt_contract, foundation, w, dl) != AMM_ETH_OK)
            continue;
        uint64_t v = u256_to_u64_sat(w);
        if (v < lo) lo = v;
        ok++;
    }
    if (ok < e->c.quorum) return -1;
    *bal = lo;
    return 0;
}

static int read_nodus_balance(amm_engine_t *e, uint64_t dl, uint64_t *bal) {
    uint8_t native[64];
    memset(native, 0, sizeof(native));
    uint64_t tip = 0, total = 0;
    if (e->c.node.balance(e->c.node.ctx, amm_nodus_pay_self(e->c.nodus_pay), native,
                          &tip, &total, dl) != AMM_NODE_OK)
        return -1;
    *bal = total;
    return 0;
}

/* The estimated Ethereum fee of one USDT payout, in USDT raw (plan section
 * 10; givens item 82, shown apart): the gas of a transfer(self, 1) estimated
 * by the providers (Q-th largest, bumped 25% rounded up as the payer does),
 * the gas price likewise, converted with the price seam. Unknown -> -1. */
static int estimate_eth_fee(amm_engine_t *e, uint64_t dl, uint64_t *fee) {
    uint8_t self[20], data[AMM_TX_TRANSFER_DATA_LEN];
    amm_eth_pay_self(e->c.eth_pay, self);
    amm_tx_transfer_calldata(self, 1, data);
    uint64_t gas[AMM_ETH_MAX_PROVIDERS], px[AMM_ETH_MAX_PROVIDERS];
    int ng = 0, np = 0;
    for (int i = 0; i < e->c.n_providers; i++) {
        const amm_eth_provider_t *p = &e->c.providers[i];
        uint64_t g = 0, pr = 0;
        if (p->estimate_gas(p->ctx, self, e->cfg.usdt_contract, data, sizeof(data), &g, dl) == AMM_ETH_OK)
            gas[ng++] = g;
        if (p->gas_price(p->ctx, &pr, dl) == AMM_ETH_OK) px[np++] = pr;
    }
    uint64_t g = 0, pr = 0;
    if (kth_largest(gas, ng, e->c.quorum, &g) != 0 ||
        kth_largest(px, np, e->c.quorum, &pr) != 0 || g == 0) return -1;
    if (g > (UINT64_MAX - 99) / 125) return -1;
    g = (g * 125 + 99) / 100;
    return e->c.price.fee_usdt(e->c.price.ctx, g, pr, fee, dl) == AMM_ETH_OK ? 0 : -1;
}

/* The NODUS the bot's payout of `gross` would cost in Nodus fee (the planner's
 * quote), in NODUS raw. Unknown -> -1. */
static int estimate_nodus_fee(amm_engine_t *e, uint64_t gross, uint64_t dl, uint64_t *fee) {
    amm_np_quote_t q;
    memset(&q, 0, sizeof(q));
    if (amm_nodus_pay_quote(e->c.nodus_pay, gross, dl, &q) != AMM_NP_OK) return -1;
    *fee = q.fee;
    return 0;
}

/* Shared reads of the QUESTION path (givens item 98): the bot's USDT balance,
 * the Ethereum fee estimate (gas estimate and gas price of every provider) and
 * the bot's Nodus balance are reused by the next question for
 * `quote_read_fresh_ms` of the monotonic clock instead of being read for every
 * question. Only this path: the decision and the payouts read through
 * amm_eth_pay_prepare / amm_nodus_pay_prepare and never through these, so nothing
 * a payment receives is computed from a reused read. A failed read is not
 * stored. */
#define CACHED_READ(NAME, FIELD, CALL)                                          \
    static int NAME(amm_engine_t *e, uint64_t dl, uint64_t *out) {              \
        const uint64_t now = mono_now_ms(e);                                    \
        if (e->FIELD.valid && now >= e->FIELD.at_ms &&                          \
            now - e->FIELD.at_ms < e->cfg.quote_read_fresh_ms) {                \
            *out = e->FIELD.v;                                                  \
            return 0;                                                           \
        }                                                                       \
        uint64_t v = 0;                                                         \
        if (CALL(e, dl, &v) != 0) return -1;                                    \
        e->FIELD.valid = 1; e->FIELD.at_ms = now; e->FIELD.v = v;               \
        *out = v;                                                               \
        return 0;                                                               \
    }
CACHED_READ(q_usdt_balance, rc_usdt, read_usdt_balance)
CACHED_READ(q_nodus_balance, rc_nodus, read_nodus_balance)
CACHED_READ(q_eth_fee, rc_ethfee, estimate_eth_fee)

static int swaps_paused_now(amm_engine_t *e, int *paused);

/* the open-question limit (givens item 98) before any read; the journal repeats
 * it inside the insert. @return 0 below the limit / 1 at it / -1. */
static int questions_at_limit(amm_engine_t *e) {
    int64_t open = 0;
    if (amm_journal_open_questions(e->c.journal, &open) != 0) return -1;
    return (uint64_t)open >= e->cfg.quote_open_max ? 1 : 0;
}

/* ── 1. the price question ───────────────────────────────────────────── */

int amm_engine_quote(amm_engine_t *e, amm_dir_t dir, uint64_t amount,
                     uint64_t deadline_ms, amm_quote_answer_t *out) {
    if (!e || !out) return AMM_Q_ERR;
    if ((dir != AMM_USDT_TO_NODUS && dir != AMM_NODUS_TO_USDT) || amount == 0 ||
        amount > (uint64_t)INT64_MAX)
        return AMM_Q_BAD;

    /* the refusals that need no read come first (the journal repeats them
     * inside the approval transaction) */
    {
        int paused = 0, unknown = 0;
        if (swaps_paused_now(e, &paused) != 0 ||
            amm_journal_state_count(e->c.journal, AMM_S_UNKNOWN, &unknown) != 0)
            return AMM_Q_ERR;
        if (paused) return AMM_Q_PAUSED;
        if (unknown > 0) return AMM_Q_STOPPED;
        /* givens item 98: at the limit of open unpaid questions nothing is read */
        int lim = questions_at_limit(e);
        if (lim < 0) return AMM_Q_ERR;
        if (lim == 1) return AMM_Q_BUSY;
    }

    amm_pool_t pool;
    int g = amm_journal_pool_get(e->c.journal, &pool);
    if (g < 0) return AMM_Q_ERR;
    if (g == 1) return AMM_Q_UNAVAILABLE;           /* no ledger, no price  */

    evm_u256 x, o;
    evm_u256_from_u64(&x, amount);
    int qr = amm_pool_quote(&pool, dir, &x, &o);
    if (qr == AMM_E_DEPTH) return AMM_Q_NO_LIQUIDITY;
    if (qr != AMM_OK) return AMM_Q_UNAVAILABLE;
    uint64_t number = 0;
    if (amm_to_u64(&number, &o) != AMM_OK) return AMM_Q_NO_LIQUIDITY;
    if (number == 0) return AMM_Q_NO_LIQUIDITY;

    /* the value v on the USDT side in both directions (givens items 19, 38) */
    const uint64_t v = (dir == AMM_USDT_TO_NODUS) ? amount : number;
    if (v < e->cfg.swap_min_usdt) return AMM_Q_BELOW_MIN;
    if (v > e->cfg.swap_max_usdt) return AMM_Q_ABOVE_MAX;

    /* The in-flight room (plan section 13, givens item 94): the question holds
     * nothing; it is refused when the payments already SEEN leave no room for
     * this swap. The journal repeats the check inside the approval
     * transaction. */
    {
        uint64_t sum = 0;
        if (amm_journal_inflight_sum(e->c.journal, e->cfg.held_keeps_room, &sum) != 0)
            return AMM_Q_ERR;
        int ar = amm_inflight_admit(v, sum, e->cfg.swap_max_usdt, e->cfg.inflight_max_usdt);
        if (ar == AMM_E_SWAP_LIMIT) return AMM_Q_ABOVE_MAX;
        if (ar == AMM_E_INFLIGHT) return AMM_Q_INFLIGHT;
        if (ar != AMM_OK) return AMM_Q_ERR;
    }

    /* The payout must be within what the bot's key holds, less what it
     * already owes to swaps whose payment is SEEN (givens items 40, 94; plan
     * section 12): an ESTIMATE with the indicative numbers; the binding check
     * is the decision's. */
    uint64_t held = 0, owed = 0;
    if (dir == AMM_USDT_TO_NODUS) {
        if (q_nodus_balance(e, deadline_ms, &held) != 0) return AMM_Q_UNAVAILABLE;
    } else {
        if (q_usdt_balance(e, deadline_ms, &held) != 0) return AMM_Q_UNAVAILABLE;
    }
    if (amm_journal_owed_sum(e->c.journal, dir == AMM_NODUS_TO_USDT, &owed) != 0)
        return AMM_Q_UNAVAILABLE;
    if (owed > UINT64_MAX - number || held < owed + number) return AMM_Q_CANNOT_PAY;

    uint64_t est = 0;
    if (dir == AMM_USDT_TO_NODUS) {
        if (estimate_nodus_fee(e, number, deadline_ms, &est) != 0) return AMM_Q_UNAVAILABLE;
    } else {
        if (q_eth_fee(e, deadline_ms, &est) != 0) return AMM_Q_UNAVAILABLE;
    }

    uint64_t tip = 0;
    if (dir == AMM_USDT_TO_NODUS) {
        if (read_eth_tip(e, &tip) != 0) return AMM_Q_UNAVAILABLE;
    } else {
        if (read_nodus_tip(e, deadline_ms, &tip) != 0) return AMM_Q_UNAVAILABLE;
    }

    const uint64_t now = e->c.now_unix(e->c.now_ctx);
    amm_quote_t q;
    memset(&q, 0, sizeof(q));
    q.dir = dir;
    q.amount = amount;
    q.quote_out = number;
    q.est_fee = est;
    q.value_usdt = v;
    q.approved_at = now;
    q.expiry = now + e->cfg.approval_valid_seconds;
    q.approved_tip = tip;
    q.swap_max = e->cfg.swap_max_usdt;
    q.inflight_max = e->cfg.inflight_max_usdt;
    q.swaps_paused_cfg = e->cfg.swaps_paused;
    q.held_keeps_room = e->cfg.held_keeps_room;
    q.open_max = e->cfg.quote_open_max;

    /* the number is drawn at random and is unique among the bot's approvals:
     * a collision is redrawn (the journal refuses it, writing nothing) */
    amm_swap_t sw;
    for (int attempt = 0; attempt < 16; attempt++) {
        uint8_t r[20];
        if (e->c.rand_fn(e->c.rand_ctx, r, sizeof(r)) != 0) return AMM_Q_UNAVAILABLE;
        uint32_t n = ((uint32_t)r[0] << 24) | ((uint32_t)r[1] << 16) |
                     ((uint32_t)r[2] << 8) | r[3];
        if (n == 0) continue;
        q.bot_req = n;
        memcpy(q.rand16, r + 4, 16);
        int jr = amm_journal_quote_approve(e->c.journal, &q, &sw);
        if (jr == AMM_J_NUMBER_TAKEN) continue;
        if (jr == AMM_J_PAUSED) return AMM_Q_PAUSED;
        if (jr == AMM_J_STOPPED) return AMM_Q_STOPPED;
        if (jr == AMM_J_SWAP_LIMIT) return AMM_Q_ABOVE_MAX;
        if (jr == AMM_J_INFLIGHT) return AMM_Q_INFLIGHT;
        if (jr == AMM_J_BUSY) return AMM_Q_BUSY;
        if (jr != AMM_J_OK) return AMM_Q_ERR;

        memset(out, 0, sizeof(*out));
        out->dir = dir;
        out->amount = amount;
        out->number = number;
        out->est_fee = est;
        out->request_number = n;
        out->valid_until = q.expiry;
        if (dir == AMM_USDT_TO_NODUS) {            /* pay USDT to the Foundation's Ethereum address */
            out->pay_to[0] = '0'; out->pay_to[1] = 'x';
            hex_to(e->cfg.foundation_eth, 20, out->pay_to + 2);
        } else {
            memcpy(out->pay_to, e->cfg.foundation_nodus, AMM_ADDR_NODUS + 1);
        }
        return AMM_Q_OK;
    }
    return AMM_Q_UNAVAILABLE;
}

/* ── 2. the signed request ───────────────────────────────────────────── */

static int accept_common(amm_engine_t *e, amm_accept_t *a, uint64_t request_number,
                         amm_swap_t *swap_out) {
    if (request_number == 0 || request_number > UINT32_MAX) return AMM_ACC_NO_NUMBER;
    a->bot_req = (uint32_t)request_number;
    amm_swap_t cur;
    int g = amm_journal_swap_by_botreq(e->c.journal, a->bot_req, &cur);
    if (g < 0) return AMM_ACC_ERR;
    if (g == 1) {
        /* the row of an unused expired question may have been deleted: its
         * number stays marked, and the request is answered as for an expired one */
        int u = amm_journal_bot_req_used(e->c.journal, 0, a->bot_req);
        if (u < 0) return AMM_ACC_ERR;
        return u == 0 ? AMM_ACC_EXPIRED : AMM_ACC_NO_NUMBER;
    }
    if (e->c.now_unix(e->c.now_ctx) > cur.expiry) return AMM_ACC_EXPIRED;
    amm_swap_t out;
    memset(&out, 0, sizeof(out));
    int r = amm_journal_accept_request(e->c.journal, a, &out);
    switch (r) {
    case AMM_J_OK:          if (swap_out) *swap_out = out; return AMM_ACC_RECEIVED;
    case AMM_J_OPEN_DUP:    if (swap_out) *swap_out = out; return AMM_ACC_OPEN;
    case AMM_J_NO_APPROVAL: return AMM_ACC_NO_NUMBER;
    case AMM_J_AMOUNT:      return AMM_ACC_AMOUNT;
    case AMM_J_REQ_REUSED:  return AMM_ACC_REUSED;
    case AMM_J_ILLEGAL:     return AMM_ACC_USED;
    default:                return AMM_ACC_ERR;
    }
}

int amm_engine_accept_usdt(amm_engine_t *e, const amm_req_usdt_t *r, amm_swap_t *swap_out) {
    if (!e || !r) return AMM_ACC_ERR;
    amm_accept_t a;
    memset(&a, 0, sizeof(a));
    a.dir = AMM_USDT_TO_NODUS;
    a.sender = r->sender;
    a.dest = r->destination;
    a.amount = r->amount;
    a.minimum = r->minimum;
    a.incoming_id = "";                 /* the Ethereum payment names itself */
    memcpy(a.req_no, r->req_no, 32);
    return accept_common(e, &a, r->request_number, swap_out);
}

int amm_engine_accept_nodus(amm_engine_t *e, const amm_req_nodus_to_usdt_t *r,
                            amm_swap_t *swap_out) {
    if (!e || !r) return AMM_ACC_ERR;
    char incoming[AMM_TID_MAX];
    snprintf(incoming, sizeof(incoming), "nodus:%s", r->transfer_id);
    amm_accept_t a;
    memset(&a, 0, sizeof(a));
    a.dir = AMM_NODUS_TO_USDT;
    a.sender = r->sender;
    a.dest = r->destination;
    a.amount = r->amount;
    a.minimum = r->minimum;
    a.incoming_id = incoming;
    memcpy(a.req_no, r->req_no, 32);
    return accept_common(e, &a, r->request_number, swap_out);
}

/* ── 2b. the liquidity add ───────────────────────────────────────────── */

int amm_engine_add_question(amm_engine_t *e, amm_side_t side, uint64_t amount,
                            uint64_t deadline_ms, amm_add_answer_t *out) {
    if (!e || !out) return AMM_AQ_ERR;
    if ((side != AMM_SIDE_USDT && side != AMM_SIDE_NODUS) || amount == 0 ||
        amount > (uint64_t)INT64_MAX)
        return AMM_AQ_BAD;
    if (e->cfg.liquidity_paused) return AMM_AQ_PAUSED;
    {
        int unknown = 0;
        if (amm_journal_state_count(e->c.journal, AMM_S_UNKNOWN, &unknown) != 0)
            return AMM_AQ_ERR;
        if (unknown > 0) return AMM_AQ_STOPPED;
        int lim = questions_at_limit(e);            /* givens item 98: before any read */
        if (lim < 0) return AMM_AQ_ERR;
        if (lim == 1) return AMM_AQ_BUSY;
    }

    /* the pool's ratio (givens item 35); an empty pool has none: the start
     * ratio of the settings (plan section 14, PLAN READING of items 20, 35, 91) */
    amm_pool_t pool;
    int g = amm_journal_pool_get(e->c.journal, &pool);
    if (g < 0) return AMM_AQ_ERR;
    evm_u256 dn, du;
    if (g == 0 && !evm_u256_is_zero(&pool.depth_n) && !evm_u256_is_zero(&pool.depth_u)) {
        dn = pool.depth_n;
        du = pool.depth_u;
    } else {
        evm_u256_from_u64(&dn, e->cfg.pool_start_nodus);
        evm_u256_from_u64(&du, e->cfg.pool_start_usdt);
    }
    /* the other side = the typed amount x the other side's depth / the typed
     * side's depth, truncated (6.4.6, PROPOSED: no reference line computes it) */
    evm_u256 a, prod, quot;
    evm_u256_from_u64(&a, amount);
    uint64_t usdt = 0, nodus = 0, other = 0;
    if (side == AMM_SIDE_USDT) {
        if (amm_mul(&prod, &a, &dn) != AMM_OK || amm_div(&quot, &prod, &du) != AMM_OK ||
            amm_to_u64(&other, &quot) != AMM_OK) return AMM_AQ_BAD;
        usdt = amount; nodus = other;
    } else {
        if (amm_mul(&prod, &a, &du) != AMM_OK || amm_div(&quot, &prod, &dn) != AMM_OK ||
            amm_to_u64(&other, &quot) != AMM_OK) return AMM_AQ_BAD;
        nodus = amount; usdt = other;
    }
    if (usdt == 0 || nodus == 0 || usdt > (uint64_t)INT64_MAX || nodus > (uint64_t)INT64_MAX)
        return AMM_AQ_BAD;
    /* givens item 96: refused below the minimum, nothing written */
    if (nodus < e->cfg.liquidity_min_nodus) return AMM_AQ_BELOW_MIN;

    uint64_t eth_tip = 0, nodus_tip = 0;
    if (read_eth_tip(e, &eth_tip) != 0 || read_nodus_tip(e, deadline_ms, &nodus_tip) != 0)
        return AMM_AQ_UNAVAILABLE;

    const uint64_t now = e->c.now_unix(e->c.now_ctx);
    amm_add_q_t q;
    memset(&q, 0, sizeof(q));
    q.usdt_amount = usdt;
    q.nodus_amount = nodus;
    q.approved_at = now;
    q.expiry = now + e->cfg.approval_valid_seconds;
    q.eth_tip = eth_tip;
    q.nodus_tip = nodus_tip;
    q.nodus_min = e->cfg.liquidity_min_nodus;
    q.liquidity_paused_cfg = e->cfg.liquidity_paused;
    q.open_max = e->cfg.quote_open_max;

    amm_add_t row;
    for (int attempt = 0; attempt < 16; attempt++) {
        uint8_t r[4];
        if (e->c.rand_fn(e->c.rand_ctx, r, sizeof(r)) != 0) return AMM_AQ_UNAVAILABLE;
        uint32_t n = ((uint32_t)r[0] << 24) | ((uint32_t)r[1] << 16) |
                     ((uint32_t)r[2] << 8) | r[3];
        if (n == 0) continue;
        q.bot_req = n;
        int jr = amm_journal_add_approve(e->c.journal, &q, &row);
        if (jr == AMM_J_NUMBER_TAKEN) continue;
        if (jr == AMM_J_PAUSED) return AMM_AQ_PAUSED;
        if (jr == AMM_J_STOPPED) return AMM_AQ_STOPPED;
        if (jr == AMM_J_BELOW_MIN) return AMM_AQ_BELOW_MIN;
        if (jr == AMM_J_BUSY) return AMM_AQ_BUSY;
        if (jr != AMM_J_OK) return AMM_AQ_ERR;
        memset(out, 0, sizeof(*out));
        out->usdt_amount = usdt;
        out->nodus_amount = nodus;
        out->request_number = n;
        out->valid_until = q.expiry;
        out->pay_eth[0] = '0'; out->pay_eth[1] = 'x';
        hex_to(e->cfg.foundation_eth, 20, out->pay_eth + 2);
        memcpy(out->pay_nodus, e->cfg.foundation_nodus, AMM_ADDR_NODUS + 1);
        return AMM_AQ_OK;
    }
    return AMM_AQ_UNAVAILABLE;
}

int amm_engine_accept_add(amm_engine_t *e, const amm_req_liq_add_t *r, uint32_t *open_req) {
    if (!e || !r) return AMM_ACC_ERR;
    if (r->request_number == 0 || r->request_number > UINT32_MAX) return AMM_ACC_NO_NUMBER;
    amm_add_t cur;
    int g = amm_journal_add_by_botreq(e->c.journal, (uint32_t)r->request_number, &cur);
    if (g < 0) return AMM_ACC_ERR;
    if (g == 1) {                                  /* as in accept_common */
        int u = amm_journal_bot_req_used(e->c.journal, 1, (uint32_t)r->request_number);
        if (u < 0) return AMM_ACC_ERR;
        return u == 0 ? AMM_ACC_EXPIRED : AMM_ACC_NO_NUMBER;
    }
    if (e->c.now_unix(e->c.now_ctx) > cur.expiry) return AMM_ACC_EXPIRED;
    char tid[AMM_TID_MAX];
    snprintf(tid, sizeof(tid), "nodus:%s", r->transfer_id);
    amm_add_accept_t a;
    memset(&a, 0, sizeof(a));
    a.bot_req = (uint32_t)r->request_number;
    a.eth_addr = r->ethereum_address;
    a.nodus_addr = r->nodus_address;
    a.usdt_amount = r->usdt_amount;
    a.nodus_amount = r->nodus_amount;
    a.transfer_id = tid;
    memcpy(a.eth_req_no, r->req_no, 32);
    memcpy(a.nodus_req_no, r->req_no, 32);
    int jr = amm_journal_add_accept(e->c.journal, &a, NULL, open_req);
    switch (jr) {
    case AMM_J_OK:           return AMM_ACC_RECEIVED;
    case AMM_J_OPEN_DUP:     return AMM_ACC_OPEN;
    case AMM_J_NO_APPROVAL:  return AMM_ACC_NO_NUMBER;
    case AMM_J_AMOUNT:       return AMM_ACC_AMOUNT;
    case AMM_J_REQ_REUSED:   return AMM_ACC_REUSED;
    case AMM_J_ILLEGAL:      return AMM_ACC_USED;
    case AMM_J_DUP_TRANSFER: return AMM_ACC_DUP_TRANSFER;
    default:                 return AMM_ACC_ERR;
    }
}

/* ── 2c. the liquidity withdraw ──────────────────────────────────────── */

int amm_engine_accept_withdraw(amm_engine_t *e, const amm_req_liq_withdraw_t *r) {
    if (!e || !r) return AMM_ACC_ERR;
    /* the refusals that need no read first (the journal repeats all of them
     * inside the accept transaction) */
    if (e->cfg.liquidity_paused) return AMM_ACC_PAUSED;
    int mk = amm_journal_req_marker_exists(e->c.journal, r->nodus_address, r->req_no);
    if (mk < 0) return AMM_ACC_ERR;
    if (mk == 0) return AMM_ACC_REUSED;
    evm_u256 units;
    int pg = amm_journal_position_get(e->c.journal, r->ethereum_address, r->nodus_address, &units);
    if (pg < 0) return AMM_ACC_ERR;
    if (pg == 1 || evm_u256_is_zero(&units)) return AMM_ACC_NO_POSITION;
    /* the wait is counted from the Ethereum tip of this moment (plan section 14:
     * "300 Ethereum blocks after the request is accepted") */
    uint64_t tip = 0;
    if (read_eth_tip(e, &tip) != 0) return AMM_ACC_UNAVAILABLE;
    amm_wd_accept_t a;
    memset(&a, 0, sizeof(a));
    a.eth_addr = r->ethereum_address;
    a.nodus_addr = r->nodus_address;
    a.bp = r->basis_points;
    memcpy(a.req_no, r->req_no, 32);
    a.eth_tip = tip;
    a.liquidity_paused_cfg = e->cfg.liquidity_paused;
    int jr = amm_journal_withdraw_accept(e->c.journal, &a, NULL);
    switch (jr) {
    case AMM_J_OK:          return AMM_ACC_RECEIVED;
    case AMM_J_PAUSED:      return AMM_ACC_PAUSED;
    case AMM_J_REQ_REUSED:  return AMM_ACC_REUSED;
    case AMM_J_NO_POSITION: return AMM_ACC_NO_POSITION;
    default:                return AMM_ACC_ERR;
    }
}

/* ── 3. the worker ───────────────────────────────────────────────────── */

static int swaps_paused_now(amm_engine_t *e, int *paused) {
    int flag = 0;
    if (amm_journal_reversal_pause_get(e->c.journal, &flag) != 0) return -1;
    *paused = e->cfg.swaps_paused || flag;
    return 0;
}

/* b / i. the line for room: the earliest waiting payment first (plan section
 * 13). */
static int room_line(amm_engine_t *e, amm_engine_step_t *o) {
    int granted = 0;
    if (amm_journal_room_grant(e->c.journal, e->cfg.inflight_max_usdt,
                               e->cfg.held_keeps_room, &granted) != 0) return -1;
    o->room_granted += granted;
    return 0;
}

/* A swap's wait, written to the log when it starts or changes. */
static void wait_log(amm_engine_t *e, const amm_swap_t *s, const char *why) {
    int k = -1;
    for (int i = 0; i < e->n_waits; i++) if (e->waits[i].seq == s->seq) k = i;
    if (k >= 0 && !strcmp(e->waits[k].why, why)) return;
    if (k < 0) {
        if (e->n_waits < (int)(sizeof(e->waits) / sizeof(e->waits[0]))) k = e->n_waits++;
        else { k = e->waits_next; e->waits_next = (k + 1) % e->n_waits; }
        e->waits[k].seq = s->seq;
    }
    snprintf(e->waits[k].why, sizeof(e->waits[k].why), "%s", why);
    QGP_LOG_INFO(LOG_TAG, "swap %s waits: %s", s->id, why);
}

/* The count of a swap that holds room and whose payment is deep. NO_ROOM is a
 * waiting payment, not a fault. */
static int count_swap(amm_engine_t *e, const amm_swap_t *s, amm_engine_step_t *o) {
    int tr = amm_journal_swap_transition(e->c.journal, s->seq, AMM_S_COUNTED, NULL, NULL, NULL);
    if (tr == AMM_J_OK) {
        o->counted++;
        QGP_LOG_INFO(LOG_TAG, "swap %s counted", s->id);
        return 0;
    }
    if (tr == AMM_J_NO_ROOM) {
        o->waiting++;
        wait_log(e, s, "its payment is deep, no room to count it");
        return 0;
    }
    if (tr == AMM_J_DUP_TRANSFER) return 0;
    QGP_LOG_ERROR(LOG_TAG, "counting refused (%d)", tr);
    return tr == -1 ? -1 : 0;
}

/* c. Ethereum records -> signed USDT -> NODUS approvals and liquidity adds.
 * The engine reads EVERY unconsumed record (no block window), one page at a
 * time by the list's own key order: a payment the watcher stored but the engine
 * had not matched yet is still read after any downtime (plan section 13: a
 * payment within the validity found later follows its approval). A consumed
 * record (its swap is counted or later, or an add took it) is not read again. */
static int eth_records(amm_engine_t *e, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_rec_t *recs = malloc(sizeof(*recs) * (size_t)pg);
    if (!recs) return -1;
    int rc = 0;
    static const char *RS[] = {AMM_R_SEEN, AMM_R_DEEP};
    int stop = 0;
    for (int rs = 0; rs < 2 && rc == 0 && !stop; rs++) {
        amm_rec_t after_rec;
        int have_after = 0;
        for (;;) {
            int nr = 0;
            if (amm_journal_rec_list_unconsumed(e->c.journal, RS[rs],
                                                have_after ? &after_rec : NULL,
                                                recs, pg, &nr) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Ethereum records not readable this step");
                stop = 1;                /* nothing is lost: read again next step */
                break;
            }
            for (int i = 0; i < nr && rc == 0; i++) {
                const amm_rec_t *r = &recs[i];
                const int deep = rs == 1;
                char key[AMM_TID_MAX];
                amm_journal_eth_key(r->tx, key, sizeof(key));
                amm_swap_t carrier;
                int cg = amm_journal_swap_by_incoming(e->c.journal, key, &carrier);
                if (cg < 0) { rc = -1; break; }
                if (cg == 0) {
                    if (deep && !strcmp(carrier.state, AMM_S_PAID_WAITING)) {
                        /* the validity is checked again at counting: a
                         * reorganisation may have moved the payment (the watcher
                         * keeps the link) to a block outside the approval's
                         * window; such a payment matches no approval: the swap is
                         * unpaid again and the record is held (givens item 32) */
                        uint8_t csender[20], camt[32];
                        if (from_hex(carrier.sender, csender, 20) != 0) continue;
                        be32_of_u64(carrier.amount, camt);
                        if (amm_eth_watch_match(r, csender, camt, carrier.approved_tip,
                                                carrier.expiry) != AMM_M_MATCH) {
                            int ur = amm_journal_payment_unmatched(e->c.journal, r->tx, r->log_index);
                            if (ur == AMM_J_OK) o->held_records++;
                            else if (ur != AMM_J_ILLEGAL) rc = -1;
                            continue;
                        }
                        if (carrier.room && count_swap(e, &carrier, o) != 0) rc = -1;
                    }
                    continue;
                }
                /* no swap carries it: does a signed approval or a liquidity add
                 * match? (keyed lookups: at most one signed open approval
                 * exists per sender and amount, givens item 57) */
                int taken = 0;
                uint64_t amount = 0;
                if (be32_to_u64(r->value, &amount) == 0 && amount <= (uint64_t)INT64_MAX) {
                    char from_h[41];
                    hex_to(r->from, 20, from_h);
                    amm_swap_t ap;
                    int fg = amm_journal_swap_find_open_usdt(e->c.journal, from_h, amount, &ap);
                    if (fg < 0) { rc = -1; break; }
                    if (fg == 0 &&
                        amm_eth_watch_match(r, r->from, r->value, ap.approved_tip,
                                            ap.expiry) == AMM_M_MATCH) {
                        /* SEEN: ONE transaction -- the incoming id, the next
                         * seen number, room or a place in the line */
                        int took = 0;
                        int sr = amm_journal_swap_seen(e->c.journal, ap.seq, key, NULL,
                                                       e->cfg.inflight_max_usdt,
                                                       e->cfg.held_keeps_room, &took);
                        if (sr == AMM_J_OK) {
                            o->matched++;
                            taken = 1;
                            QGP_LOG_INFO(LOG_TAG, "swap %s: its payment is seen in block %llu (%s%s)",
                                         ap.id, (unsigned long long)r->block_number,
                                         deep ? "deep" : "not deep yet",
                                         took ? "" : ", no room: it waits in the line");
                            if (!took) o->waiting++;
                            else if (deep) {
                                amm_swap_t now_s;
                                if (amm_journal_swap_by_seq(e->c.journal, ap.seq, &now_s) != 0 ||
                                    count_swap(e, &now_s, o) != 0) { rc = -1; break; }
                            }
                        } else if (sr == -1) {
                            rc = -1;
                            break;
                        } else if (sr != AMM_J_DUP_TRANSFER && sr != AMM_J_ILLEGAL) {
                            QGP_LOG_ERROR(LOG_TAG, "recording a seen payment refused (%d)", sr);
                        }
                    }
                    if (!taken) {
                        amm_add_t ad;
                        int ag = amm_journal_add_find_eth(e->c.journal, from_h, amount, &ad);
                        if (ag < 0) { rc = -1; break; }
                        if (ag == 0 &&
                            amm_eth_watch_match(r, r->from, r->value, ad.eth_tip,
                                                ad.expiry) == AMM_M_MATCH) {
                            int lr = amm_journal_add_link_eth(e->c.journal, ad.seq, key,
                                                              r->log_index);
                            if (lr == AMM_J_OK) { taken = 1; o->adds_linked++; }
                            else if (lr == -1) { rc = -1; break; }
                        }
                    }
                }
                if (!taken && deep) {
                    /* a payment that matches no approval is held (plan section 7) */
                    amm_rec_t h = *r;
                    snprintf(h.state, sizeof(h.state), "%s", AMM_R_HELD);
                    if (amm_journal_rec_put(e->c.journal, &h) == AMM_J_OK) o->held_records++;
                }
            }
            if (rc != 0 || stop || nr < pg) break;
            after_rec = recs[nr - 1];
            have_after = 1;
        }
    }
    free(recs);
    return rc;
}

/* d. a waiting NODUS payment that now holds room is counted: a committed block
 * needs no extra depth (plan section 11). */
static int nodus_waiting(amm_engine_t *e, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *l = malloc(sizeof(*l) * (size_t)pg);
    if (!l) return -1;
    int rc = 0;
    int64_t after = 0;
    for (;;) {
        int n = 0;
        if (amm_journal_swap_page(e->c.journal, AMM_S_PAID_WAITING, 1, after, l, pg, &n) != 0) {
            rc = -1;
            break;
        }
        for (int i = 0; i < n && rc == 0; i++) {
            after = l[i].seen_seq;
            if (l[i].dir == AMM_NODUS_TO_USDT && l[i].room && count_swap(e, &l[i], o) != 0)
                rc = -1;
        }
        if (rc != 0 || n < pg) break;
    }
    free(l);
    return rc;
}

/* e. liquidity adds (plan section 14). One page of signed adds at a time. */
static int liquidity_adds(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_add_t *l = malloc(sizeof(*l) * (size_t)pg);
    if (!l) return -1;
    int rc = 0;
    static const char *ST[] = {AMM_L_SIGNED, AMM_L_APPROVED};
    for (int sti = 0; sti < 2 && rc == 0; sti++) {
        /* each walk examines at most `round_rows_max` rows per round and resumes
         * after the last one (givens item 98) */
        int64_t after = e->adds_after[sti];
        uint64_t examined = 0;
        for (;;) {
            int n = 0;
            const uint64_t room_left = e->cfg.round_rows_max - examined;
            if (room_left == 0) break;
            const int lim = room_left < (uint64_t)pg ? (int)room_left : pg;
            if (amm_journal_add_page(e->c.journal, ST[sti], after, l, lim, &n) != 0) { rc = -1; break; }
            for (int i = 0; i < n && rc == 0; i++) {
                amm_add_t a = l[i];
                after = a.seq;
                examined++;
                if (sti == 0) {
                    /* the NODUS deposit: matched by its transfer id in the
                     * recorded history rows (wire id), peer, exact amount, block
                     * time within the validity and a block above the tip read at
                     * the question */
                    if (a.nodus_height == 0) {
                        uint8_t wire[64];
                        if (from_hex(a.transfer_id + 6, wire, 64) == 0) {
                            amm_nrow_t nr;
                            int ng = amm_journal_nrow_by_wire(e->c.journal, wire, &nr);
                            if (ng < 0) { rc = -1; break; }
                            if (ng == 0 && !strcmp(nr.peer, a.nodus_addr) &&
                                nr.amount == a.nodus_amount && nr.ts <= a.expiry &&
                                nr.height > a.nodus_tip) {
                                int lr = amm_journal_add_link_nodus(e->c.journal, a.seq, nr.height);
                                if (lr == AMM_J_OK) { a.nodus_height = nr.height; o->adds_linked++; }
                                else if (lr == -1) { rc = -1; break; }
                            }
                        }
                    }
                    /* an add with both deposits matched is committed in the
                     * shared seen order with the swaps' decisions (decisions()) */
                } else {
                    /* an approved add that was never signed: expired once the
                     * payment window of both chains is fully observed (the same
                     * window rule as an unsigned approval, plan section 13) */
                    uint8_t amt[32];
                    be32_of_u64(a.usdt_amount, amt);
                    int we = amm_eth_watch_window_observed_unsigned(e->c.eth_watch, a.expiry, amt);
                    int wn = amm_nodus_watch_window_observed(e->c.nodus_watch, a.expiry);
                    if (we == 1 && wn == 1) {
                        int xr = amm_journal_add_expire(e->c.journal, a.seq);
                        if (xr == AMM_J_OK) o->adds_expired++;
                        else if (xr != AMM_J_ILLEGAL) rc = -1;
                    }
                }
            }
            if (rc != 0) break;
            if (n < lim) { after = 0; break; }        /* the end of the rows: start again next round */
        }
        if (rc == 0) e->adds_after[sti] = after;
        o->adds_examined += (int)examined;
    }
    /* a signed add with no deposit matched whose windows are fully observed */
    {
        int64_t after = e->adds_after[2];
        uint64_t examined = 0;
        for (;;) {
            int n = 0;
            const uint64_t room_left = e->cfg.round_rows_max - examined;
            if (rc == 0 && room_left == 0) break;
            const int lim = room_left < (uint64_t)pg ? (int)room_left : pg;
            if (rc != 0 || amm_journal_add_page(e->c.journal, AMM_L_SIGNED, after, l, lim, &n) != 0) {
                if (rc == 0) rc = -1;
                break;
            }
            for (int i = 0; i < n && rc == 0; i++) {
                const amm_add_t *a = &l[i];
                after = a->seq;
                examined++;
                if (*a->eth_tx || a->nodus_height != 0) continue;
                uint8_t sender[20], amt[32];
                if (from_hex(a->eth_addr, sender, 20) != 0) continue;
                be32_of_u64(a->usdt_amount, amt);
                int we = amm_eth_watch_window_observed(e->c.eth_watch, a->eth_tip, a->expiry,
                                                       sender, amt);
                int wn = amm_nodus_watch_window_observed(e->c.nodus_watch, a->expiry);
                if (we == 1 && wn == 1) {
                    int xr = amm_journal_add_expire(e->c.journal, a->seq);
                    if (xr == AMM_J_OK) o->adds_expired++;
                    else if (xr != AMM_J_ILLEGAL) rc = -1;
                }
            }
            if (rc != 0) break;
            if (n < lim) { after = 0; break; }
        }
        if (rc == 0) e->adds_after[2] = after;
        o->adds_examined += (int)examined;
    }
    free(l);
    return rc;
}

/* f. THE DECISION of one counted swap (plan section 12). Returns 0 (done or
 * not decidable now) / -1 (a journal fault). */
static int decide_refund(amm_engine_t *e, const amm_swap_t *s, const char *why,
                         amm_engine_step_t *o) {
    amm_decision_t d;
    memset(&d, 0, sizeof(d));
    d.seq = s->seq;
    d.refund = 1;
    d.message = why;
    int jr = amm_journal_swap_decide(e->c.journal, &d);
    if (jr == AMM_J_OK) {
        o->to_refund++;
        QGP_LOG_INFO(LOG_TAG, "swap %s decided: refund (%s)", s->id, why);
        return 0;
    }
    if (jr == -1) return -1;
    QGP_LOG_ERROR(LOG_TAG, "swap %s: the refund decision was refused (%d)", s->id, jr);
    return 0;
}

/* SHARED WAIT CAUSES (the contract of the bounded decision merge, plan line 577,
 * givens item 98): a cause that makes a whole class of rows wait in one round is
 * detected ONCE by the first row that meets it; that row does not use the round's
 * bound and the class is skipped for the rest of the round (decisions()).
 *   B_PAUSED      payouts_paused: every swap decision and every withdrawal waits;
 *   B_NODUS_LIVE  a NODUS payout is signed or submitted (one payout in flight):
 *                 every USDT -> NODUS payout decision and every withdrawal waits;
 *   B_ETH         the Ethereum side is unreadable (providers, gas, price, balance):
 *                 every NODUS -> USDT payout decision and every withdrawal waits;
 *   B_NODUS_NODE  the Nodus node is unreadable or the rule set is not carried:
 *                 every USDT -> NODUS payout decision and every withdrawal waits.
 * The split of the payers' codes (amm_eth_pay.h:179-206, amm_nodus_pay.h:142-165):
 *   AMM_EP_PAUSED / AMM_NP_PAUSED              shared (B_PAUSED);
 *   AMM_NP_UNSUPPORTED                         shared (B_NODUS_NODE);
 *   AMM_EP_UNKNOWN / AMM_NP_UNKNOWN            shared only when the engine's own
 *       probe of the same seams fails (eth_class_down / nodus_class_down), else the
 *       row's own (a gas estimate that fails for THIS recipient, a build that fails);
 *   AMM_EP_FUNDS / AMM_NP_FUNDS                row-specific (the amount does not fit);
 *   every other code, a refused or empty transaction, an arithmetic that cannot be
 *   computed                                   row-specific. */
enum { B_PAUSED = 1, B_NODUS_LIVE = 2, B_ETH = 4, B_NODUS_NODE = 8 };

static int eth_class_down(amm_engine_t *e, uint64_t dl) {
    uint64_t f = 0, b = 0;
    return estimate_eth_fee(e, dl, &f) != 0 || read_usdt_balance(e, dl, &b) != 0;
}

static int nodus_class_down(amm_engine_t *e, uint64_t dl) {
    uint64_t t = 0;
    return read_nodus_tip(e, dl, &t) != 0;
}

/* the shared cause of a payer's failure code, or 0 for a row's own wait */
static int ep_shared(amm_engine_t *e, int pr, uint64_t dl) {
    if (pr == AMM_EP_PAUSED) return B_PAUSED;
    if (pr == AMM_EP_UNKNOWN && eth_class_down(e, dl)) return B_ETH;
    return 0;
}

static int np_shared(amm_engine_t *e, int pr, uint64_t dl) {
    if (pr == AMM_NP_PAUSED) return B_PAUSED;
    if (pr == AMM_NP_UNSUPPORTED) return B_NODUS_NODE;
    if (pr == AMM_NP_UNKNOWN && nodus_class_down(e, dl)) return B_NODUS_NODE;
    return 0;
}

static int decide_one(amm_engine_t *e, const amm_swap_t *s, int paused, uint64_t dl,
                      amm_engine_step_t *o) {
    /* payouts_paused: nothing is signed and no swap is decided of any kind, the
     * trading-halt refund included (plan section 16): the swap waits counted
     * with its room */
    if (e->cfg.payouts_paused) {
        wait_log(e, s, "payouts are paused (setting payouts_paused)");
        e->wait_shared = B_PAUSED;
        o->undecided++;
        return 0;
    }
    if (paused) return decide_refund(e, s, "trading halted", o);

    amm_pool_t pool;
    int g = amm_journal_pool_get(e->c.journal, &pool);
    if (g < 0) return -1;
    if (g == 1) return decide_refund(e, s, "no ledger: the pool gives nothing", o);

    /* the output from the depths of THIS moment (givens items 93, 94) */
    evm_u256 x, out;
    evm_u256_from_u64(&x, s->amount);
    int qr = amm_pool_quote(&pool, s->dir, &x, &out);
    if (qr == AMM_E_DEPTH || qr == AMM_E_ZERO_DIV || qr == AMM_E_RANGE)
        return decide_refund(e, s, "an empty side or the depth reached: the pool gives nothing", o);
    uint64_t output = 0;
    if (qr != AMM_OK || amm_to_u64(&output, &out) != AMM_OK) {
        QGP_LOG_ERROR(LOG_TAG, "swap %s: the output cannot be computed (%d): not decided", s->id, qr);
        o->undecided++;
        return 0;
    }
    if (output == 0) return decide_refund(e, s, "zero output", o);
    amm_pool_t after = pool;
    int ar = amm_pool_apply_swap(&after, s->dir, &x, &out);
    if (ar == AMM_E_DEPTH) return decide_refund(e, s, "the output reaches the output side's depth", o);
    if (ar != AMM_OK) {
        QGP_LOG_ERROR(LOG_TAG, "swap %s: the ledger update cannot be computed (%d): not decided",
                      s->id, ar);
        o->undecided++;
        return 0;
    }

    amm_decision_t d;
    memset(&d, 0, sizeof(d));
    d.seq = s->seq;
    d.out_amount = output;
    d.pool_before = &pool;
    d.pool_after = &after;

    if (s->dir == AMM_USDT_TO_NODUS) {
        /* ONE PAYOUT IN FLIGHT (plan section 7 step 7): wait only while another
         * NODUS payout is signed or submitted */
        int owed = amm_journal_nodus_payout_owed(e->c.journal);
        if (owed < 0) return -1;
        if (owed == 1) {
            wait_log(e, s, "another NODUS payout is signed or submitted and not settled yet");
            e->wait_shared = B_NODUS_LIVE;
            o->undecided++;
            return 0;
        }
        if (e->blk & B_NODUS_NODE) {
            wait_log(e, s, "the Nodus node did not answer earlier in this round");
            e->wait_shared = B_NODUS_NODE;
            o->undecided++;
            return 0;
        }
        amm_np_prepared_t pre;
        int pr = amm_nodus_pay_prepare(e->c.nodus_pay, s->dest, output, s->minimum, dl, &pre);
        if (pr == AMM_NP_ZERO || pr == AMM_NP_BELOW_MIN) {
            int r = decide_refund(e, s, pr == AMM_NP_ZERO
                                      ? "nothing is left after the Nodus fee"
                                      : "below the minimum after the Nodus fee", o);
            amm_np_prepared_free(&pre);
            return r;
        }
        if (pr != AMM_NP_OK) {
            QGP_LOG_WARN(LOG_TAG, "swap %s: not decided, the NODUS payout cannot be planned (%d: %s)",
                         s->id, pr, pre.msg);
            amm_np_prepared_free(&pre);
            e->wait_shared = np_shared(e, pr, dl);
            o->undecided++;
            return 0;
        }
        d.out_fee = pre.fee;
        d.out_paid = pre.net;
        d.nattempt = &pre.attempt;
        int jr = amm_journal_swap_decide(e->c.journal, &d);
        amm_np_prepared_free(&pre);
        if (jr == AMM_J_OK) {
            o->decided++;
            QGP_LOG_INFO(LOG_TAG, "swap %s decided: %llu NODUS units to pay, fee %llu",
                         s->id, (unsigned long long)d.out_paid, (unsigned long long)d.out_fee);
            return 0;
        }
        if (jr == -1) return -1;
        QGP_LOG_WARN(LOG_TAG, "swap %s: the decision wrote nothing (%d)", s->id, jr);
        o->undecided++;
        return 0;
    }

    if (e->blk & B_ETH) {                               /* found earlier this round */
        wait_log(e, s, "the Ethereum payer could not plan a payout earlier in this round");
        e->wait_shared = B_ETH;
        o->undecided++;
        return 0;
    }
    amm_ep_prepared_t pre;
    int pr = amm_eth_pay_prepare(e->c.eth_pay, s->dest, output, s->minimum, dl, &pre);
    if (pr == AMM_EP_ZERO || pr == AMM_EP_BELOW_MIN) {
        int r = decide_refund(e, s, pr == AMM_EP_ZERO
                                  ? "nothing is left after the Ethereum fee"
                                  : "below the minimum after the Ethereum fee", o);
        amm_ep_prepared_free(&pre);
        return r;
    }
    if (pr != AMM_EP_OK) {
        QGP_LOG_WARN(LOG_TAG, "swap %s: not decided, the USDT payout cannot be planned (%d: %s)",
                     s->id, pr, pre.msg);
        amm_ep_prepared_free(&pre);
        e->wait_shared = ep_shared(e, pr, dl);
        o->undecided++;
        return 0;
    }
    d.out_fee = pre.fee;
    d.out_paid = pre.net;
    d.eattempt = &pre.attempt;
    int jr = amm_journal_swap_decide(e->c.journal, &d);
    amm_ep_prepared_free(&pre);
    if (jr == AMM_J_OK) {
        o->decided++;
        QGP_LOG_INFO(LOG_TAG, "swap %s decided: %llu USDT units to pay, fee %llu",
                     s->id, (unsigned long long)d.out_paid, (unsigned long long)d.out_fee);
        return 0;
    }
    if (jr == -1) return -1;
    QGP_LOG_WARN(LOG_TAG, "swap %s: the decision wrote nothing (%d)", s->id, jr);
    o->undecided++;
    return 0;
}

/* f. the counted swaps, decided in the seen order, one page at a time; a swap
 * that cannot be decided in this round does not stop those behind it. */
/* An add whose both deposits are matched and both waits are over (300 Ethereum
 * blocks, 3 Nodus blocks). 1 ready / 0 not yet or unknown / -1 fault. */
static int add_ready(amm_engine_t *e, const amm_add_t *a, uint64_t dl) {
    uint8_t tx[32];
    amm_rec_t rec;
    if (from_hex(a->eth_tx + 4, tx, 32) != 0) return 0;
    int rg = amm_journal_rec_get(e->c.journal, tx, a->eth_log, &rec);
    if (rg < 0) return -1;
    if (rg == 1) return 0;
    int eth_ok = 0, nodus_ok = 0;
    if (amm_eth_watch_depth_reached(e->c.eth_watch, &rec, e->cfg.liquidity_wait_eth_blocks, dl,
                                    &eth_ok) != 0) return 0;
    if (amm_nodus_watch_depth_reached(e->c.nodus_watch, a->nodus_height, dl, &nodus_ok) != 0)
        return 0;
    return eth_ok && nodus_ok;
}

static int commit_add(amm_engine_t *e, int64_t seq, amm_engine_step_t *o) {
    evm_u256 units;
    int cr = amm_journal_add_commit(e->c.journal, seq, &units);
    if (cr == AMM_J_OK) { o->adds_committed++; return 0; }
    if (cr == -1) return -1;
    QGP_LOG_ERROR(LOG_TAG, "an add cannot be committed (%d)", cr);
    return 0;
}

/* f'. A DUE LIQUIDITY WITHDRAWAL ACTS (plan section 14; see amm_engine.h). Every
 * case is settled BEFORE any unit change; what the texts do not settle is not
 * decided.
 *   refuse whole   either side is nothing after its network fee: the NODUS side
 *                  after the Nodus fee, the USDT side (or a zero share) after the
 *                  Ethereum fee (manager_txout_current.go:987-989, :1035-1060,
 *                  plan line 576; givens Errata on item 90);
 *   wait           nothing written: payouts paused, another NODUS payout in
 *                  flight, a read or the planner failed, an amount that does not
 *                  fit 64 bits;
 *   act            ONE journal transaction (amm_journal_withdraw_act).
 * Returns 0 / -1 (a journal fault). */
static int refuse_withdraw(amm_engine_t *e, const amm_wd_t *w, const char *why,
                           amm_engine_step_t *o) {
    amm_wd_act_t a;
    memset(&a, 0, sizeof(a));
    a.seq = w->seq;
    a.refuse = 1;
    a.message = why;
    int jr = amm_journal_withdraw_act(e->c.journal, &a);
    if (jr == AMM_J_OK) {
        QGP_LOG_INFO(LOG_TAG, "withdrawal %lld refused whole: %s", (long long)w->seq, why);
        o->withdraws_refused++;
        return 0;
    }
    if (jr == -1) return -1;
    QGP_LOG_ERROR(LOG_TAG, "withdrawal %lld: the refusal was not written (%d)", (long long)w->seq, jr);
    o->withdraws_waiting++;
    return 0;
}

static int act_withdraw(amm_engine_t *e, const amm_wd_t *w, uint64_t dl, amm_engine_step_t *o) {
    if (e->cfg.payouts_paused) { e->wait_shared = B_PAUSED; o->withdraws_waiting++; return 0; }   /* nothing is signed */

    amm_pool_t pool;
    int g = amm_journal_pool_get(e->c.journal, &pool);
    if (g < 0) return -1;
    evm_u256 units;
    int ug = amm_journal_position_get(e->c.journal, w->eth_addr, w->nodus_addr, &units);
    if (ug < 0) return -1;
    /* no ledger, no position or none of it left (an earlier withdrawal took it):
     * no share on either side, the NODUS side is nothing */
    if (g == 1 || ug == 1 || evm_u256_is_zero(&units))
        return refuse_withdraw(e, w, "nothing is left of the position: the NODUS side is nothing", o);

    /* the shares from the ledger of THIS moment (plan section 14) */
    amm_withdraw_t sh;
    int cr = amm_withdraw_calc(&sh, &pool, &units, w->bp);
    if (cr == AMM_E_RANGE)
        return refuse_withdraw(e, w, "an empty pool side: the NODUS side is nothing", o);
    uint64_t n_gross = 0, u_gross = 0;
    if (cr != AMM_OK || amm_to_u64(&n_gross, &sh.out_n) != AMM_OK ||
        amm_to_u64(&u_gross, &sh.out_u) != AMM_OK) {
        QGP_LOG_ERROR(LOG_TAG, "withdrawal %lld: the shares cannot be computed (%d): not acted on",
                      (long long)w->seq, cr);
        o->withdraws_waiting++;
        return 0;
    }
    if (n_gross == 0)
        return refuse_withdraw(e, w, "the NODUS side is nothing after the Nodus fee", o);

    /* ONE PAYOUT IN FLIGHT: the NODUS first attempt is stored only while no other
     * NODUS payout is signed or submitted (as the decision of a USDT -> NODUS swap) */
    int owed = amm_journal_nodus_payout_owed(e->c.journal);
    if (owed < 0) return -1;
    if (owed == 1) { e->wait_shared = B_NODUS_LIVE; o->withdraws_waiting++; return 0; }
    amm_np_prepared_t npre;
    int pr = amm_nodus_pay_prepare(e->c.nodus_pay, w->nodus_addr, n_gross, 0, dl, &npre);
    if (pr == AMM_NP_ZERO) {
        amm_np_prepared_free(&npre);
        return refuse_withdraw(e, w, "the NODUS side is nothing after the Nodus fee", o);
    }
    if (pr != AMM_NP_OK) {
        QGP_LOG_WARN(LOG_TAG, "withdrawal %lld: not acted on, the NODUS payout cannot be planned (%d: %s)",
                     (long long)w->seq, pr, npre.msg);
        amm_np_prepared_free(&npre);
        e->wait_shared = np_shared(e, pr, dl);
        o->withdraws_waiting++;
        return 0;
    }

    /* the USDT side: a share of zero, or one that is not above the Ethereum fee,
     * refuses the WHOLE withdrawal like the NODUS side (THORChain returns "tx out
     * item has zero coin" for a withdrawal's outbound of ANY asset,
     * manager_txout_current.go:987-989, :1052-1058): nothing is changed or paid. */
    amm_ep_prepared_t epre;
    memset(&epre, 0, sizeof(epre));
    int er = u_gross == 0 ? AMM_EP_ZERO
                          : amm_eth_pay_prepare(e->c.eth_pay, w->eth_addr, u_gross, 0, dl, &epre);
    if (er == AMM_EP_ZERO) {
        amm_np_prepared_free(&npre);
        amm_ep_prepared_free(&epre);
        return refuse_withdraw(e, w, "the USDT side is nothing after the Ethereum fee", o);
    }
    if (er != AMM_EP_OK) {
        QGP_LOG_WARN(LOG_TAG, "withdrawal %lld: not acted on, the USDT payout cannot be planned (%d: %s)",
                     (long long)w->seq, er, epre.msg);
        amm_np_prepared_free(&npre);
        amm_ep_prepared_free(&epre);
        e->wait_shared = ep_shared(e, er, dl);
        o->withdraws_waiting++;
        return 0;
    }

    amm_wd_act_t a;
    memset(&a, 0, sizeof(a));
    a.seq = w->seq;
    a.pool_before = &pool;
    a.units_before = units;
    a.w = sh;
    a.n_gross = n_gross; a.n_fee = npre.fee; a.n_net = npre.net;
    a.u_gross = u_gross; a.u_fee = epre.fee; a.u_net = epre.net;
    a.nattempt = &npre.attempt;
    a.eattempt = &epre.attempt;
    int jr = amm_journal_withdraw_act(e->c.journal, &a);
    amm_np_prepared_free(&npre);
    amm_ep_prepared_free(&epre);
    if (jr == AMM_J_OK) {
        QGP_LOG_INFO(LOG_TAG, "withdrawal %lld acted on: NODUS %llu, USDT %llu", (long long)w->seq,
                     (unsigned long long)n_gross, (unsigned long long)u_gross);
        o->withdraws_done++;
        return 0;
    }
    if (jr == -1) return -1;
    QGP_LOG_WARN(LOG_TAG, "withdrawal %lld: the act wrote nothing (%d)", (long long)w->seq, jr);
    o->withdraws_waiting++;
    return 0;
}

/* One of the three streams of the shared seen order, read a page at a time:
 * the counted swaps (kind 0), the signed adds with both deposits linked (kind 1:
 * add_ready decides whether one commits now) and the due withdrawals (kind 2). */
typedef struct {
    int      kind;
    int64_t  after;                /* the last seen number fetched                */
    int      n, i;                 /* rows in the page, the next one to take      */
    int      last;                 /* the page was short: nothing follows it      */
    int      off;                  /* the stream is empty for this round          */
    uint64_t max_tip;              /* kind 2: due = acceptance tip at most this   */
    amm_swap_t *sl;
    amm_add_t  *al;
    amm_wd_t   *wl;
} dstream_t;

/* The seen number of the stream's next row, fetching the next page when the
 * current one is used up. @return 1 a row / 0 the stream has ended / -1 fault. */
static int dnext(amm_engine_t *e, dstream_t *s, int pg, int64_t *seen) {
    if (s->off) return 0;
    if (s->i >= s->n) {
        if (s->last) return 0;
        int n = 0, r = -1;
        if (s->kind == 0)
            r = amm_journal_swap_page(e->c.journal, AMM_S_COUNTED, 1, s->after, s->sl, pg, &n);
        else if (s->kind == 1)
            r = amm_journal_add_page_ready(e->c.journal, s->after, s->al, pg, &n);
        else
            r = amm_journal_withdraw_page_due(e->c.journal, s->max_tip, s->after, s->wl, pg, &n);
        if (r != 0) return -1;
        s->n = n; s->i = 0;
        if (n < pg) s->last = 1;
        if (n == 0) return 0;
        s->after = s->kind == 0 ? s->sl[n - 1].seen_seq
                 : s->kind == 1 ? s->al[n - 1].seen_seq : s->wl[n - 1].seen_seq;
    }
    *seen = s->kind == 0 ? s->sl[s->i].seen_seq
          : s->kind == 1 ? s->al[s->i].seen_seq : s->wl[s->i].seen_seq;
    return 1;
}

/* f. The counted swaps, the ready liquidity adds and the due liquidity
 * withdrawals, taken in ONE order: the shared seen sequence (plan section 13;
 * line 577: "a liquidity commit takes its place in the same order"). The three
 * streams are merged by seen number one row at a time, each read page by page,
 * so no backlog is held in memory. EVERY ROUND STARTS AT THE OLDEST ROW (no cursor:
 * a row that waited is looked at again before any row behind it), rows are taken
 * in ascending seen number, and AT MOST `round_rows_max` rows are EXAMINED per
 * round -- decided, refused, acted, committed, a not-yet-ready add, or waiting for
 * a reason of its own (funds short for this amount, an arithmetic that cannot be
 * computed, a transaction that wrote nothing) -- (givens item 98: the per-round
 * check work is bounded, the rest carried to the next round). The round stops at the
 * first row beyond the bound while a further candidate exists: nothing with a
 * higher seen number is touched, so a later operation never passes an earlier one;
 * with no further candidate the bound ends nothing.
 * A wait whose cause is SHARED by a whole class of rows (B_* above: payouts paused,
 * a live NODUS payout, the Ethereum or the Nodus side unreadable) is found once, by
 * the first row that meets it: that row does not use the bound and the class is
 * skipped for the rest of the round (a whole stream is switched off, not walked). A
 * swap decided in between changes a withdrawal's shares (they are computed when it
 * acts, from the ledger then). */
static int decisions(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *sl = malloc(sizeof(*sl) * (size_t)pg);
    amm_add_t *al = malloc(sizeof(*al) * (size_t)pg);
    amm_wd_t *wl = malloc(sizeof(*wl) * (size_t)pg);
    int rc = 0;
    if (!sl || !al || !wl) { free(sl); free(al); free(wl); return -1; }
    dstream_t st[3];
    memset(st, 0, sizeof(st));
    for (int k = 0; k < 3; k++) st[k].kind = k;        /* every round starts at the oldest row */
    e->blk = 0;
    st[0].sl = sl; st[1].al = al; st[2].wl = wl;
    /* the due withdrawals: the Ethereum tip is at least liquidity_wait_eth_blocks
     * above the tip read at acceptance (a tip that cannot be read: none is due) */
    uint64_t tip = 0;
    if (read_eth_tip(e, &tip) == 0 && tip >= e->cfg.liquidity_wait_eth_blocks)
        st[2].max_tip = tip - e->cfg.liquidity_wait_eth_blocks;
    else
        st[2].off = 1;
    int paused = 0;
    if (swaps_paused_now(e, &paused) != 0) rc = -1;

    uint64_t examined = 0;
    while (rc == 0) {
        /* a class blocked by a shared cause is off for the rest of the round: the
         * swaps when payouts are paused, the withdrawals for any shared cause
         * (they need both payers) */
        if (e->blk & B_PAUSED) st[0].off = 1;
        if (e->blk) st[2].off = 1;
        int pick = -1;
        int64_t best = 0;
        for (int k = 0; k < 3 && rc == 0; k++) {
            int64_t sn = 0;
            int r = dnext(e, &st[k], pg, &sn);
            if (r < 0) { rc = -1; break; }
            if (r == 1 && (pick < 0 || sn < best)) { pick = k; best = sn; }
        }
        if (rc != 0) break;
        if (pick < 0) break;                              /* no candidate left in any stream: the end */
        /* the bound is checked only once a further candidate exists, so reaching
         * it with nothing behind is the end of the round's work, not a stop */
        if (examined >= e->cfg.round_rows_max) break;
        dstream_t *s = &st[pick];
        e->wait_shared = 0;
        if (pick == 0) {
            rc = decide_one(e, &s->sl[s->i], paused, dl, o);
        } else if (pick == 1) {
            const amm_add_t *a = &s->al[s->i];
            int rd = add_ready(e, a, dl);
            if (rd < 0) rc = -1;
            else if (rd) rc = commit_add(e, a->seq, o);
        } else {
            amm_wd_t w;
            int g = amm_journal_withdraw_get(e->c.journal, s->wl[s->i].seq, &w);
            if (g < 0) rc = -1;
            else if (g == 0 && !strcmp(w.state, AMM_W_ACCEPTED)) rc = act_withdraw(e, &w, dl, o);
        }
        s->i++;
        /* a row that waited for a shared cause is not an examined row: it does not
         * use the bound, and the class is skipped from here on; every other row
         * (decided, refused, acted, committed, or waiting for its own reason) does */
        if (e->wait_shared) e->blk |= e->wait_shared;
        else examined++;
    }
    o->decisions_examined += (int)examined;
    free(wl);
    free(al);
    free(sl);
    return rc;
}

/* g. NODUS payouts through amm_nodus_pay: settlement and resubmission of the
 * stored envelopes; the REFUND of a NODUS -> USDT swap is signed here. A
 * decided payout always has its envelope (stored in the decision). */
static int nodus_payouts(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    /* A swap whose attempt is signed or submitted keeps priority (the single
     * live attempt). With none live, a swap whose expired attempt cannot be
     * replaced now (`waiting`: funds, an unreadable answer, the changed fee)
     * is DEFERRED for this round: `after` moves past it, so the next owed swap
     * in seq order is served (a refund is signed, another expired payout is
     * replaced) and the deferred one is not selected again before the next
     * round. The guard bounds the work per round, so the walk RESUMES in the
     * next round after the last deferred swap (`e->nodus_after`) and wraps to
     * the oldest owed swap when nothing is left beyond it: every owed swap is
     * reached within ceil(owed / 8) + 1 rounds, however many wait. */
    int64_t after = e->nodus_after;
    int wrapped = after == 0;
    for (int guard = 0; guard < 8; guard++) {
        amm_np_step_t st;
        memset(&st, 0, sizeof(st));
        int r = amm_nodus_pay_step_after(e->c.nodus_pay, dl, after, &st);
        if (r == AMM_NP_ERR) return -1;
        if (r != AMM_NP_NEED_SIGN) {
            if (st.waiting) {
                after = st.swap_seq;
                continue;
            }
            if (!st.worked) {
                /* no swap named: nothing is owed beyond `after`; start again
                 * from the oldest once per round */
                if (st.swap_seq == 0 && after > 0 && !wrapped) {
                    after = 0;
                    wrapped = 1;
                    continue;
                }
                break;
            }
            continue;
        }
        amm_swap_t head;
        int h = amm_journal_swap_head_payout_after(e->c.journal, after, &head);
        if (h < 0) return -1;
        if (h == 1) break;
        if (strcmp(head.state, AMM_S_REFUND_PENDING) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "swap %s is payout_pending with no stored envelope: not signed here",
                          head.id);
            break;
        }
        amm_np_step_t ss;
        memset(&ss, 0, sizeof(ss));
        int sr = amm_nodus_pay_sign(e->c.nodus_pay, head.seq, head.amount, dl, &ss);
        if (sr == AMM_NP_ERR) return -1;
        if (sr == AMM_NP_ZERO) {                 /* dropped: zero after the Nodus fee (items 89, 90) */
            o->dropped++;
            continue;
        }
        if (sr == AMM_NP_PAUSED || sr == AMM_NP_BUSY) break;   /* nothing can be signed now */
        if (sr != AMM_NP_OK) {
            /* funds, an unreadable answer, unsupported: this refund waits and is
             * deferred like a waiting replacement (`after` moves past it), so a younger
             * expired payout whose own reserved coins fund its replacement is reached;
             * the refund is tried again after the wrap in a later round */
            after = head.seq;
            continue;
        }
    }
    e->nodus_after = after;
    return 0;
}

/* h. USDT payouts through amm_eth_pay: settlement and broadcast of the stored
 * transactions; a USDT refund is signed here. */
static int usdt_payouts(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *l = malloc(sizeof(*l) * (size_t)pg);
    if (!l) return -1;
    int rc = 0;
    int64_t after = 0;
    for (;;) {
        int n = 0;
        if (amm_journal_swap_page_usdt_owed(e->c.journal, after, l, pg, &n) != 0) { rc = -1; break; }
        for (int i = 0; i < n && rc == 0; i++) {
            amm_swap_t *s = &l[i];
            after = s->seq;
            amm_eattempt_t at;
            memset(&at, 0, sizeof(at));
            int a = amm_journal_eth_attempt_latest(e->c.journal, s->seq, &at);
            if (a < 0) { rc = -1; break; }
            amm_ep_step_t st;
            memset(&st, 0, sizeof(st));
            if (a == 0) {
                amm_eattempt_free(&at);
                int r = amm_eth_pay_step(e->c.eth_pay, s->seq, dl, &st);
                if (r == AMM_EP_ERR) rc = -1;
                continue;
            }
            if (strcmp(s->state, AMM_S_REFUND_PENDING) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "swap %s is payout_pending with no stored transaction: not signed here",
                              s->id);
                continue;
            }
            /* a USDT refund that is nothing after its Ethereum fee is not
             * broadcast and not held (givens items 89, 90): the payer drops it */
            int sr = amm_eth_pay_sign(e->c.eth_pay, s->seq, s->amount, dl, &st);
            if (sr == AMM_EP_ERR) rc = -1;
            else if (sr == AMM_EP_ZERO) o->dropped++;
            else if (sr == AMM_EP_OK) {
                amm_ep_step_t s2;
                memset(&s2, 0, sizeof(s2));
                (void)amm_eth_pay_step(e->c.eth_pay, s->seq, dl, &s2);
            }
        }
        if (rc != 0 || n < pg) break;
    }
    free(l);
    return rc;
}

/* j. the Ethereum fee deducted from a paid USDT payout, booked to the
 * Foundation AS USDT (givens items 80, 92). The pool is not touched: its USDT
 * depth already fell by the full output at the decision. The paid rows without
 * a booking are read in PAGES (by seq), so no number of old rows can stop the
 * booking; a paid row that cannot be booked yet (its attempt is not confirmed,
 * or the fee is zero) is skipped, not retried inside the page. */
static int fee_booking(amm_engine_t *e, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *l = malloc(sizeof(*l) * (size_t)pg);
    if (!l) return -1;
    int rc = 0;
    int64_t after = 0;
    for (;;) {
        int n = 0;
        if (amm_journal_swap_list_unbooked_paid(e->c.journal, after, l, pg, &n) != 0) {
            rc = -1;
            break;
        }
        for (int i = 0; i < n && rc == 0; i++) {
            after = l[i].seq;
            amm_eattempt_t at;
            memset(&at, 0, sizeof(at));
            int a = amm_journal_eth_attempt_latest(e->c.journal, l[i].seq, &at);
            if (a < 0) { rc = -1; break; }
            if (a == 1) continue;
            const uint64_t fee = at.fee;
            const int confirmed = !strcmp(at.state, AMM_EA_CONFIRMED);
            amm_eattempt_free(&at);
            if (!confirmed || fee == 0) continue;
            int r = amm_journal_book_fee(e->c.journal, l[i].seq, fee);
            if (r == AMM_J_OK) o->fees_booked++;
            else if (r != AMM_J_ILLEGAL) rc = -1;
        }
        if (rc != 0 || n < pg) break;
    }
    free(l);
    return rc;
}

/* k. an approval whose payment window is FULLY OBSERVED becomes expired. Since
 * givens item 94 an unpaid approval holds no room, so this only decides when it
 * stops matching payments (plan section 13 window rule); the bot's clock
 * passing the expiry does not do it. Read in pages by seq; at most
 * `round_rows_max` rows are examined per round (givens item 98): the walk
 * resumes after the last row in the next round (`release_after`) and starts
 * again at the oldest row once it has reached the end, so every approved row is
 * examined within ceil(rows / round_rows_max) + 1 rounds. */
static int release(amm_engine_t *e, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *l = malloc(sizeof(*l) * (size_t)pg);
    if (!l) return -1;
    int rc = 0;
    int64_t after = e->release_after;
    uint64_t examined = 0;
    for (;;) {
        int n = 0;
        const uint64_t room_left = e->cfg.round_rows_max - examined;
        if (room_left == 0) break;                    /* the round's bound: resume next round */
        const int lim = room_left < (uint64_t)pg ? (int)room_left : pg;
        if (amm_journal_swap_page(e->c.journal, AMM_S_APPROVED, 0, after, l, lim, &n) != 0) {
            rc = -1;
            break;
        }
        for (int i = 0; i < n && rc == 0; i++) {
            const amm_swap_t *s = &l[i];
            after = s->seq;
            examined++;
            int done = 0;
            if (s->dir == AMM_USDT_TO_NODUS) {
                uint8_t sender[20], amt[32];
                be32_of_u64(s->amount, amt);
                int w;
                if (*s->sender) {
                    if (from_hex(s->sender, sender, 20) != 0) continue;
                    w = amm_eth_watch_window_observed(e->c.eth_watch, s->approved_tip, s->expiry, sender, amt);
                } else {
                    w = amm_eth_watch_window_observed_unsigned(e->c.eth_watch, s->expiry, amt);
                }
                if (w < 0) continue;
                done = w == 1;
            } else {
                int w = amm_nodus_watch_window_observed(e->c.nodus_watch, s->expiry);
                if (w < 0) continue;
                done = w == 1;
            }
            if (!done) continue;
            int r = amm_journal_swap_transition(e->c.journal, s->seq, AMM_S_EXPIRED, NULL, NULL, NULL);
            if (r == AMM_J_OK) o->expired++;
            else if (r != AMM_J_ILLEGAL) rc = -1;
        }
        if (rc != 0) break;
        if (n < lim) { after = 0; break; }            /* the end of the rows: start again next round */
    }
    if (rc == 0) e->release_after = after;
    o->rows_examined += (int)examined;
    free(l);
    return rc;
}

/* l. the unused expired questions are deleted, at most `round_rows_max` price
 * questions and as many liquidity add questions per round, in one transaction
 * (givens item 98). Their request numbers stay marked as used. */
static int purge_questions(amm_engine_t *e, amm_engine_step_t *o) {
    const int cap = e->cfg.round_rows_max > 100000 ? 100000 : (int)e->cfg.round_rows_max;
    int ns = 0, na = 0;
    if (amm_journal_purge_expired_questions(e->c.journal, cap, &ns, &na) != 0) return -1;
    o->questions_deleted += ns + na;
    return 0;
}

int amm_engine_step(amm_engine_t *e, uint64_t deadline_ms, amm_engine_step_t *out) {
    amm_engine_step_t local;
    amm_engine_step_t *o = out ? out : &local;
    memset(o, 0, sizeof(*o));
    if (!e) return -1;

    amm_eth_step_t es;
    amm_nodus_step_t ns;
    memset(&es, 0, sizeof(es));
    memset(&ns, 0, sizeof(ns));
    o->eth_rc = amm_eth_watch_step(e->c.eth_watch, deadline_ms, &es);
    o->nodus_rc = amm_nodus_watch_step(e->c.nodus_watch, deadline_ms, &ns);
    o->counted += ns.counted;
    o->waiting += ns.waiting;
    if (o->eth_rc == AMM_W_ERR || o->nodus_rc == AMM_NW_ERR) return -1;

    /* the questions that expired in an earlier round and were never used go
     * first, so a row that expires in this round is still seen as expired by
     * the end of it */
    if (purge_questions(e, o) != 0) return -1;
    if (room_line(e, o) != 0) return -1;
    if (eth_records(e, o) != 0) return -1;
    if (nodus_waiting(e, o) != 0) return -1;
    if (liquidity_adds(e, deadline_ms, o) != 0) return -1;
    if (decisions(e, deadline_ms, o) != 0) return -1;
    if (nodus_payouts(e, deadline_ms, o) != 0) return -1;
    if (usdt_payouts(e, deadline_ms, o) != 0) return -1;
    if (room_line(e, o) != 0) return -1;
    if (fee_booking(e, o) != 0) return -1;
    if (release(e, o) != 0) return -1;
    return 0;
}

/* ── status ──────────────────────────────────────────────────────────── */

int amm_engine_status(amm_engine_t *e, amm_engine_status_t *out) {
    if (!e || !out) return -1;
    memset(out, 0, sizeof(*out));
    int g = amm_journal_pool_get(e->c.journal, &out->pool);
    if (g < 0) return -1;
    out->have_pool = g == 0;
    int flag = 0, unknown = 0;
    if (amm_journal_reversal_pause_get(e->c.journal, &flag) != 0 ||
        amm_journal_state_count(e->c.journal, AMM_S_UNKNOWN, &unknown) != 0 ||
        amm_journal_inflight_sum(e->c.journal, e->cfg.held_keeps_room, &out->inflight_usdt) != 0)
        return -1;
    out->swaps_paused = e->cfg.swaps_paused || flag;
    out->liquidity_paused = e->cfg.liquidity_paused;
    out->payouts_paused = e->cfg.payouts_paused;
    out->stopped = unknown > 0;
    out->room_usdt = e->cfg.inflight_max_usdt > out->inflight_usdt
                         ? e->cfg.inflight_max_usdt - out->inflight_usdt : 0;
    return 0;
}
