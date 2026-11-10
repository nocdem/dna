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

#define LIST_CAP 1024            /* swaps or records one step reads at a time  */

struct amm_engine {
    amm_engine_cfg_t c;
    amm_cfg_t cfg;
};

amm_engine_t *amm_engine_new(const amm_engine_cfg_t *c) {
    if (!c || !c->cfg || !c->journal || !c->eth_watch || !c->eth_pay ||
        !c->nodus_watch || !c->nodus_pay || !c->providers ||
        c->n_providers < 1 || c->n_providers > AMM_ETH_MAX_PROVIDERS ||
        c->quorum < 1 || c->quorum > c->n_providers || !c->price.fee_usdt ||
        !c->now_unix || !c->rand_fn || !c->node.ruleset_info || !c->node.balance)
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

/* The sum the bot still owes in the payout asset of a quote of direction `dir`
 * (USDT for NODUS -> USDT, NODUS for USDT -> NODUS), WHATEVER the direction of
 * the swap that owes it: the numbers of the approved, waiting, counted and
 * payout-pending swaps whose payout is in that asset, and the amounts of the
 * refund-pending swaps whose REFUND is in that asset (a refund returns the
 * input asset: USDT for a USDT -> NODUS swap, NODUS for a NODUS -> USDT one). */
static int reserved_output(amm_engine_t *e, amm_dir_t dir, uint64_t *sum) {
    static const char *ST[] = {AMM_S_APPROVED, AMM_S_PAID_WAITING, AMM_S_COUNTED,
                               AMM_S_PAYOUT_PENDING, AMM_S_REFUND_PENDING};
    const int want_usdt = dir == AMM_NODUS_TO_USDT;     /* the quote's payout asset */
    amm_swap_t *l = malloc(sizeof(*l) * LIST_CAP);
    if (!l) return -1;
    uint64_t s = 0;
    int rc = 0;
    for (size_t k = 0; k < sizeof(ST) / sizeof(ST[0]) && rc == 0; k++) {
        const int is_refund = !strcmp(ST[k], AMM_S_REFUND_PENDING);
        int n = 0;
        if (amm_journal_swap_list_state(e->c.journal, ST[k], l, LIST_CAP, &n) != 0) { rc = -1; break; }
        for (int i = 0; i < n; i++) {
            const int swap_in_usdt = l[i].dir == AMM_USDT_TO_NODUS;
            const int owes_usdt = is_refund ? swap_in_usdt : !swap_in_usdt;
            if (owes_usdt != want_usdt) continue;
            const uint64_t owed = is_refund ? l[i].amount : l[i].quote_out;
            if (s > UINT64_MAX - owed) { rc = -1; break; }
            s += owed;
        }
    }
    free(l);
    if (rc == 0) *sum = s;
    return rc;
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

    /* the payout must be within what the bot's key holds, less what it
     * already owes (givens item 40; plan section 12) */
    uint64_t held = 0, owed = 0;
    if (dir == AMM_USDT_TO_NODUS) {
        if (read_nodus_balance(e, deadline_ms, &held) != 0) return AMM_Q_UNAVAILABLE;
    } else {
        if (read_usdt_balance(e, deadline_ms, &held) != 0) return AMM_Q_UNAVAILABLE;
    }
    if (reserved_output(e, dir, &owed) != 0) return AMM_Q_UNAVAILABLE;
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

/* ── 3. the worker ───────────────────────────────────────────────────── */

static int swaps_paused_now(amm_engine_t *e, int *paused) {
    int flag = 0;
    if (amm_journal_reversal_pause_get(e->c.journal, &flag) != 0) return -1;
    *paused = e->cfg.swaps_paused || flag;
    return 0;
}

/* b. Ethereum records -> signed USDT -> NODUS approvals. The engine reads
 * EVERY unconsumed record (no block window): a payment the watcher stored but
 * the engine had not matched yet is still read after any downtime (plan
 * section 13: a payment within the validity found later follows its approval).
 * A consumed record (its swap is counted or later) is not read again. */
static int eth_records(amm_engine_t *e, amm_engine_step_t *o) {
    amm_rec_t *recs = malloc(sizeof(*recs) * LIST_CAP);
    amm_swap_t *ap = malloc(sizeof(*ap) * LIST_CAP);
    if (!recs || !ap) { free(recs); free(ap); return -1; }
    int rc = 0;
    static const char *RS[] = {AMM_R_SEEN, AMM_R_DEEP};
    int stop = 0;
    for (int rs = 0; rs < 2 && rc == 0 && !stop; rs++) {
      /* page through every unconsumed record of this state, LIST_CAP at a
       * time, by the list's own key order (Sol verify 10, claim 6) */
      amm_rec_t after_rec;
      int have_after = 0;
      for (;;) {
        int nr = 0;
        if (amm_journal_rec_list_unconsumed(e->c.journal, RS[rs],
                                            have_after ? &after_rec : NULL,
                                            recs, LIST_CAP, &nr) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Ethereum records not readable this step");
            rc = 0;                      /* nothing is lost: read again next step */
            stop = 1;
            break;
        }
        for (int i = 0; i < nr; i++) {
            const amm_rec_t *r = &recs[i];
            const int deep = rs == 1;
            char key[AMM_TID_MAX];
            amm_journal_eth_key(r->tx, key, sizeof(key));
            amm_swap_t carrier;
            int cg = amm_journal_swap_by_incoming(e->c.journal, key, &carrier);
            if (cg < 0) { rc = -1; break; }
            if (cg == 0) {
                if (deep && !strcmp(carrier.state, AMM_S_PAID_WAITING)) {
                    /* the validity is checked again at counting: a reorganisation
                     * may have moved the payment (the watcher keeps the link) to
                     * a block outside the approval's window; such a payment
                     * matches no approval: the swap is unpaid again and the
                     * record is held (givens item 32) */
                    uint8_t csender[20], camt[32];
                    if (from_hex(carrier.sender, csender, 20) != 0) continue;
                    be32_of_u64(carrier.amount, camt);
                    if (amm_eth_watch_match(r, csender, camt, carrier.approved_tip,
                                            carrier.expiry) != AMM_M_MATCH) {
                        int ur = amm_journal_payment_unmatched(e->c.journal, r->tx, r->log_index);
                        if (ur == AMM_J_OK) o->held_records++;
                        else if (ur != AMM_J_ILLEGAL) { rc = -1; break; }
                        continue;
                    }
                    int tr =amm_journal_swap_transition(e->c.journal, carrier.seq,
                                                         AMM_S_COUNTED, NULL, NULL, NULL);
                    if (tr == AMM_J_OK) o->counted++;
                    else if (tr != AMM_J_DUP_TRANSFER) QGP_LOG_ERROR(LOG_TAG, "counting refused (%d)", tr);
                }
                continue;
            }
            /* no swap carries it: does a signed approval match? */
            int na = 0;
            if (amm_journal_swap_list_state(e->c.journal, AMM_S_APPROVED, ap, LIST_CAP, &na) != 0) {
                rc = -1; break;
            }
            int taken = 0;
            for (int k = 0; k < na && !taken; k++) {
                if (ap[k].dir != AMM_USDT_TO_NODUS || !*ap[k].sender) continue;
                uint8_t sender[20], amt[32];
                if (from_hex(ap[k].sender, sender, 20) != 0) continue;
                be32_of_u64(ap[k].amount, amt);
                if (amm_eth_watch_match(r, sender, amt, ap[k].approved_tip, ap[k].expiry) != AMM_M_MATCH)
                    continue;
                int tr = amm_journal_swap_transition(e->c.journal, ap[k].seq,
                                                     AMM_S_PAID_WAITING, key, NULL, NULL);
                if (tr == AMM_J_DUP_TRANSFER) continue;
                if (tr != AMM_J_OK) { QGP_LOG_ERROR(LOG_TAG, "matching refused (%d)", tr); continue; }
                o->matched++;
                taken = 1;
                if (deep &&
                    amm_journal_swap_transition(e->c.journal, ap[k].seq, AMM_S_COUNTED,
                                                NULL, NULL, NULL) == AMM_J_OK)
                    o->counted++;
            }
            if (!taken && deep) {
                /* a payment that matches no approval is held (plan section 7) */
                amm_rec_t h = *r;
                snprintf(h.state, sizeof(h.state), "%s", AMM_R_HELD);
                if (amm_journal_rec_put(e->c.journal, &h) == AMM_J_OK) o->held_records++;
            }
        }
        if (rc != 0 || nr < LIST_CAP) break;
        after_rec = recs[nr - 1];
        have_after = 1;
      }
    }
    free(recs);
    free(ap);
    return rc;
}

/* c. counted swaps: the ledger update of the approval's number, or a refund */
static int counted_swaps(amm_engine_t *e, amm_engine_step_t *o) {
    amm_swap_t *l = malloc(sizeof(*l) * LIST_CAP);
    if (!l) return -1;
    int n = 0, rc = 0;
    if (amm_journal_swap_list_state(e->c.journal, AMM_S_COUNTED, l, LIST_CAP, &n) != 0) {
        free(l);
        return -1;
    }
    int paused = 0;
    if (swaps_paused_now(e, &paused) != 0) { free(l); return -1; }
    for (int i = 0; i < n && rc == 0; i++) {
        const amm_swap_t *s = &l[i];
        int refund = paused;
        amm_pool_t pool;
        if (!refund) {
            int g = amm_journal_pool_get(e->c.journal, &pool);
            if (g < 0) { rc = -1; break; }
            evm_u256 x, paid;
            evm_u256_from_u64(&x, s->amount);
            evm_u256_from_u64(&paid, s->quote_out);
            /* the approval's number is applied as given, not computed again */
            if (g == 1 || amm_pool_apply_swap(&pool, s->dir, &x, &paid) != AMM_OK) refund = 1;
        }
        int tr = refund
            ? amm_journal_swap_transition(e->c.journal, s->seq, AMM_S_REFUND_PENDING, NULL, NULL,
                                          paused ? "trading halted" : "the number cannot be applied")
            : amm_journal_swap_transition(e->c.journal, s->seq, AMM_S_PAYOUT_PENDING, NULL, &pool, NULL);
        if (tr == AMM_J_OK) { if (refund) o->to_refund++; else o->to_payout++; }
        else if (tr != AMM_J_ILLEGAL) rc = -1;
    }
    free(l);
    return rc;
}

/* d. NODUS payouts through amm_nodus_pay */
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
        const int is_refund = !strcmp(head.state, AMM_S_REFUND_PENDING);
        const uint64_t gross = is_refund ? head.amount : head.quote_out;
        amm_np_quote_t q;
        memset(&q, 0, sizeof(q));
        /* AMM_NP_ZERO is a known answer (q.fee is set, nothing is left after
         * it): the verdict below drops a refund or turns a payout into one */
        int qr = amm_nodus_pay_quote(e->c.nodus_pay, gross, dl, &q);
        if (qr != AMM_NP_OK && qr != AMM_NP_ZERO) break;   /* unknown: stays */
        amm_np_verdict_t v = amm_nodus_pay_judge(gross, q.fee, is_refund ? 0 : head.minimum, NULL);
        if (v != AMM_NP_PAY) {
            if (is_refund) {
                /* zero after the Nodus fee: not sent, not held (items 89, 90) */
                if (amm_journal_swap_transition(e->c.journal, head.seq, AMM_S_DROPPED, NULL, NULL,
                                                "zero after the Nodus fee") == AMM_J_OK)
                    o->dropped++;
            } else if (amm_journal_swap_transition(e->c.journal, head.seq, AMM_S_REFUND_PENDING,
                                                   NULL, NULL, "below the minimum after the Nodus fee") == AMM_J_OK) {
                o->to_refund++;            /* its ledger update is reversed in (f) */
            }
            continue;
        }
        amm_np_step_t ss;
        memset(&ss, 0, sizeof(ss));
        int sr = amm_nodus_pay_sign(e->c.nodus_pay, head.seq, gross, dl, &ss);
        if (sr == AMM_NP_ERR) return -1;
        if (sr != AMM_NP_OK) break;        /* funds, unknown, paused: the swap stays */
    }
    return 0;
}

/* e. USDT payouts through amm_eth_pay */
static int usdt_payouts(amm_engine_t *e, uint64_t dl, amm_engine_step_t *o) {
    amm_swap_t *l = malloc(sizeof(*l) * LIST_CAP);
    if (!l) return -1;
    int n = 0, rc = 0;
    if (amm_journal_swap_list_usdt_owed(e->c.journal, l, LIST_CAP, &n) != 0) { free(l); return -1; }
    for (int i = 0; i < n && rc == 0; i++) {
        amm_swap_t *s = &l[i];
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
        const int is_refund = !strcmp(s->state, AMM_S_REFUND_PENDING);
        const uint64_t gross = is_refund ? s->amount : s->quote_out;
        if (is_refund) {
            /* a USDT refund that is nothing after its Ethereum fee is not
             * broadcast and not held (givens items 89, 90) */
            uint64_t est = 0;
            if (estimate_eth_fee(e, dl, &est) != 0) continue;       /* unknown: stays */
            if (est >= gross) {
                if (amm_journal_swap_transition(e->c.journal, s->seq, AMM_S_DROPPED, NULL, NULL,
                                                "zero after the Ethereum fee") == AMM_J_OK)
                    o->dropped++;
                continue;
            }
        }
        int sr = amm_eth_pay_sign(e->c.eth_pay, s->seq, gross, dl, &st);
        if (sr == AMM_EP_ERR) rc = -1;
        /* ZERO / BELOW_MIN of a payout: the payer moved it to refund_pending; its
         * ledger update is reversed in (f) */
        if (sr == AMM_EP_OK) {
            amm_ep_step_t s2;
            memset(&s2, 0, sizeof(s2));
            (void)amm_eth_pay_step(e->c.eth_pay, s->seq, dl, &s2);
        }
    }
    free(l);
    return rc;
}

/* f. a refund whose ledger update is still in the reserves */
static int reversals(amm_engine_t *e, amm_engine_step_t *o) {
    amm_swap_t *l = malloc(sizeof(*l) * LIST_CAP);
    if (!l) return -1;
    int n = 0, rc = 0;
    if (amm_journal_swap_list_state(e->c.journal, AMM_S_REFUND_PENDING, l, LIST_CAP, &n) != 0) {
        free(l);
        return -1;
    }
    for (int i = 0; i < n && rc == 0; i++) {
        if (!l[i].ledger_applied) continue;
        amm_pool_t pool;
        int g = amm_journal_pool_get(e->c.journal, &pool);
        if (g < 0) { rc = -1; break; }
        evm_u256 x, paid;
        evm_u256_from_u64(&x, l[i].amount);
        evm_u256_from_u64(&paid, l[i].quote_out);
        if (g == 1 || amm_pool_unapply_swap(&pool, l[i].dir, &x, &paid) != AMM_OK) {
            QGP_LOG_ERROR(LOG_TAG, "a ledger update cannot be reversed (swap %lld)",
                          (long long)l[i].seq);
            continue;
        }
        int r = amm_journal_ledger_reverse(e->c.journal, l[i].seq, &pool);
        if (r == AMM_J_OK) o->reversed_ledger++;
        else if (r != AMM_J_ILLEGAL) rc = -1;
    }
    free(l);
    return rc;
}

/* g. the Ethereum fee deducted from a paid USDT payout, booked to the
 * Foundation AS USDT (givens items 80, 92). The pool is not touched: its USDT
 * depth already fell by the full gross payout at the ledger update. The paid
 * rows without a booking are read in PAGES (by seq), so no number of old rows
 * can stop the booking; a paid row that cannot be booked yet (its attempt is
 * not confirmed, or the fee is zero) is skipped, not retried inside the page. */
static int fee_booking(amm_engine_t *e, amm_engine_step_t *o) {
    amm_swap_t *l = malloc(sizeof(*l) * LIST_CAP);
    if (!l) return -1;
    int rc = 0;
    int64_t after = 0;
    for (;;) {
        int n = 0;
        if (amm_journal_swap_list_unbooked_paid(e->c.journal, after, l, LIST_CAP, &n) != 0) {
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
        if (rc != 0 || n < LIST_CAP) break;
    }
    free(l);
    return rc;
}

/* h. release of room: a window fully observed */
static int release(amm_engine_t *e, amm_engine_step_t *o) {
    amm_swap_t *l = malloc(sizeof(*l) * LIST_CAP);
    if (!l) return -1;
    int n = 0, rc = 0;
    if (amm_journal_swap_list_state(e->c.journal, AMM_S_APPROVED, l, LIST_CAP, &n) != 0) {
        free(l);
        return -1;
    }
    for (int i = 0; i < n && rc == 0; i++) {
        const amm_swap_t *s = &l[i];
        int done = 0;
        /* The window rule of plan section 13 for every approval, signed or not:
         * the bot's clock passing the expiry does not release room. An approval
         * with no signed request has no sender, so no payment can be matched to
         * it; its window is observed by the same cursor and depth conditions. */
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
    if (o->eth_rc == AMM_W_ERR || o->nodus_rc == AMM_NW_ERR) return -1;

    if (eth_records(e, o) != 0) return -1;
    if (counted_swaps(e, o) != 0) return -1;
    if (reversals(e, o) != 0) return -1;            /* restart recovery first */
    if (nodus_payouts(e, deadline_ms, o) != 0) return -1;
    if (usdt_payouts(e, deadline_ms, o) != 0) return -1;
    if (reversals(e, o) != 0) return -1;
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
