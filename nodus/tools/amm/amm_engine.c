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
};

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

static int swaps_paused_now(amm_engine_t *e, int *paused);

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
        if (read_nodus_balance(e, deadline_ms, &held) != 0) return AMM_Q_UNAVAILABLE;
    } else {
        if (read_usdt_balance(e, deadline_ms, &held) != 0) return AMM_Q_UNAVAILABLE;
    }
    if (amm_journal_owed_sum(e->c.journal, dir == AMM_NODUS_TO_USDT, &owed) != 0)
        return AMM_Q_UNAVAILABLE;
    if (owed > UINT64_MAX - number || held < owed + number) return AMM_Q_CANNOT_PAY;

    uint64_t est = 0;
    if (dir == AMM_USDT_TO_NODUS) {
        if (estimate_nodus_fee(e, number, deadline_ms, &est) != 0) return AMM_Q_UNAVAILABLE;
    } else {
        if (estimate_eth_fee(e, deadline_ms, &est) != 0) return AMM_Q_UNAVAILABLE;
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
    if (g == 1) return AMM_ACC_NO_NUMBER;
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
    if (g == 1) return AMM_ACC_NO_NUMBER;
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

/* The count of a swap that holds room and whose payment is deep. NO_ROOM is a
 * waiting payment, not a fault. */
static int count_swap(amm_engine_t *e, const amm_swap_t *s, amm_engine_step_t *o) {
    int tr = amm_journal_swap_transition(e->c.journal, s->seq, AMM_S_COUNTED, NULL, NULL, NULL);
    if (tr == AMM_J_OK) { o->counted++; return 0; }
    if (tr == AMM_J_NO_ROOM) { o->waiting++; return 0; }
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
        int64_t after = 0;
        for (;;) {
            int n = 0;
            if (amm_journal_add_page(e->c.journal, ST[sti], after, l, pg, &n) != 0) { rc = -1; break; }
            for (int i = 0; i < n && rc == 0; i++) {
                amm_add_t a = l[i];
                after = a.seq;
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
            if (rc != 0 || n < pg) break;
        }
    }
    /* a signed add with no deposit matched whose windows are fully observed */
    {
        int64_t after = 0;
        for (;;) {
            int n = 0;
            if (rc != 0 || amm_journal_add_page(e->c.journal, AMM_L_SIGNED, after, l, pg, &n) != 0) {
                if (rc == 0) rc = -1;
                break;
            }
            for (int i = 0; i < n && rc == 0; i++) {
                const amm_add_t *a = &l[i];
                after = a->seq;
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
            if (rc != 0 || n < pg) break;
        }
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
    if (jr == AMM_J_OK) { o->to_refund++; return 0; }
    if (jr == -1) return -1;
    QGP_LOG_ERROR(LOG_TAG, "swap %s: the refund decision was refused (%d)", s->id, jr);
    return 0;
}

static int decide_one(amm_engine_t *e, const amm_swap_t *s, int paused, uint64_t dl,
                      amm_engine_step_t *o) {
    /* payouts_paused: nothing is signed and no swap is decided of any kind, the
     * trading-halt refund included (plan section 16): the swap waits counted
     * with its room */
    if (e->cfg.payouts_paused) { o->undecided++; return 0; }
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
        if (owed == 1) { o->undecided++; return 0; }
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
            o->undecided++;
            return 0;
        }
        d.out_fee = pre.fee;
        d.out_paid = pre.net;
        d.nattempt = &pre.attempt;
        int jr = amm_journal_swap_decide(e->c.journal, &d);
        amm_np_prepared_free(&pre);
        if (jr == AMM_J_OK) { o->decided++; return 0; }
        if (jr == -1) return -1;
        QGP_LOG_WARN(LOG_TAG, "swap %s: the decision wrote nothing (%d)", s->id, jr);
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
        o->undecided++;
        return 0;
    }
    d.out_fee = pre.fee;
    d.out_paid = pre.net;
    d.eattempt = &pre.attempt;
    int jr = amm_journal_swap_decide(e->c.journal, &d);
    amm_ep_prepared_free(&pre);
    if (jr == AMM_J_OK) { o->decided++; return 0; }
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

/* f. The counted swaps and the ready liquidity adds, taken in ONE order: the
 * shared seen sequence (plan section 13; line 575: "a liquidity commit takes its
 * place in the same order"). The ready adds are read first (page by page into a
 * growing list: no cap), then merged with the swaps' pages: an add commits before
 * the swap whose seen number is above its own. */
static int decisions(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *l = malloc(sizeof(*l) * (size_t)pg);
    amm_add_t *al = malloc(sizeof(*al) * (size_t)pg);
    int64_t *rq = NULL;                    /* ready adds: seq, seen_seq pairs */
    size_t rn = 0, rcap = 0, ri = 0;
    int rc = 0;
    if (!l || !al) { free(l); free(al); return -1; }
    {
        int64_t a_after = 0;
        for (;;) {
            int n = 0;
            if (amm_journal_add_page_ready(e->c.journal, a_after, al, pg, &n) != 0) { rc = -1; break; }
            for (int i = 0; i < n && rc == 0; i++) {
                a_after = al[i].seen_seq;
                int rd = add_ready(e, &al[i], dl);
                if (rd < 0) { rc = -1; break; }
                if (!rd) continue;
                if (rn + 2 > rcap) {
                    size_t nc = rcap ? rcap * 2 : 16;
                    int64_t *t = realloc(rq, nc * sizeof(*t));
                    if (!t) { rc = -1; break; }
                    rq = t; rcap = nc;
                }
                rq[rn++] = al[i].seq;
                rq[rn++] = al[i].seen_seq;
            }
            if (rc != 0 || n < pg) break;
        }
    }
    int paused = 0;
    if (rc == 0 && swaps_paused_now(e, &paused) != 0) rc = -1;
    int64_t after = 0;
    while (rc == 0) {
        int n = 0;
        if (amm_journal_swap_page(e->c.journal, AMM_S_COUNTED, 1, after, l, pg, &n) != 0) {
            rc = -1;
            break;
        }
        for (int i = 0; i < n && rc == 0; i++) {
            after = l[i].seen_seq;
            while (rc == 0 && ri < rn && rq[ri + 1] < l[i].seen_seq) {
                if (commit_add(e, rq[ri], o) != 0) rc = -1;
                ri += 2;
            }
            if (rc == 0 && decide_one(e, &l[i], paused, dl, o) != 0) rc = -1;
        }
        if (rc != 0 || n < pg) break;
    }
    while (rc == 0 && ri < rn) {           /* the adds behind every counted swap */
        if (commit_add(e, rq[ri], o) != 0) rc = -1;
        ri += 2;
    }
    free(rq);
    free(al);
    free(l);
    return rc;
}

/* g. NODUS payouts through amm_nodus_pay: settlement and resubmission of the
 * stored envelopes; the REFUND of a NODUS -> USDT swap is signed here. A
 * decided payout always has its envelope (stored in the decision). */
static int nodus_payouts(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    for (int guard = 0; guard < 8; guard++) {
        amm_np_step_t st;
        memset(&st, 0, sizeof(st));
        int r = amm_nodus_pay_step(e->c.nodus_pay, dl, &st);
        if (r == AMM_NP_ERR) return -1;
        if (r != AMM_NP_NEED_SIGN) {
            if (!st.worked) break;
            continue;
        }
        amm_swap_t head;
        int h = amm_journal_swap_head_payout(e->c.journal, &head);
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
        if (sr != AMM_NP_OK) break;        /* funds, unknown, paused, busy: the swap stays */
    }
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
 * passing the expiry does not do it. Read in pages by seq. */
static int release(amm_engine_t *e, amm_engine_step_t *o) {
    const int pg = e->page;
    amm_swap_t *l = malloc(sizeof(*l) * (size_t)pg);
    if (!l) return -1;
    int rc = 0;
    int64_t after = 0;
    for (;;) {
        int n = 0;
        if (amm_journal_swap_page(e->c.journal, AMM_S_APPROVED, 0, after, l, pg, &n) != 0) {
            rc = -1;
            break;
        }
        for (int i = 0; i < n && rc == 0; i++) {
            const amm_swap_t *s = &l[i];
            after = s->seq;
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
        if (rc != 0 || n < pg) break;
    }
    free(l);
    return rc;
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
