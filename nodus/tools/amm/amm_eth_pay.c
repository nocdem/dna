/**
 * @file amm_eth_pay.c
 * @brief nodus-amm USDT payout (see amm_eth_pay.h for the rules and their
 *        plan lines).
 */
#include "amm_eth_pay.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amm_eth_tx.h"
#include "amm_ledger.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_PAY"

struct amm_eth_pay {
    amm_eth_pay_cfg_t  cfg;
    amm_eth_provider_t prov[AMM_ETH_MAX_PROVIDERS];
    amm_signer_t      *signer;
    uint8_t            self[20];
    pthread_mutex_t    mu;        /* the one lock of nonce allocation (plan l.265) */
};

/* ── construction ─────────────────────────────────────────────────────── */

amm_eth_pay_t *amm_eth_pay_new(const amm_eth_pay_cfg_t *cfg) {
    if (!cfg || !cfg->providers || !cfg->journal || !cfg->sk ||
        cfg->n_providers < 1 || cfg->n_providers > AMM_ETH_MAX_PROVIDERS ||
        cfg->quorum < 1 || cfg->quorum > cfg->n_providers ||
        cfg->final_depth < 1 || cfg->final_depth > (uint64_t)INT64_MAX / 2 ||
        !cfg->price.fee_usdt || cfg->chain_id < 1)
        return NULL;
    for (int i = 0; i < cfg->n_providers; i++) {
        const amm_eth_provider_t *p = &cfg->providers[i];
        if (!p->chain_id || !p->block_number || !p->get_receipt || !p->get_balance ||
            !p->erc20_balance || !p->tx_count || !p->estimate_gas || !p->gas_price ||
            !p->max_priority_fee || !p->send_raw) return NULL;
    }
    amm_eth_pay_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->cfg = *cfg;
    for (int i = 0; i < cfg->n_providers; i++) p->prov[i] = cfg->providers[i];
    p->cfg.providers = p->prov;
    p->cfg.sk = NULL;                       /* the key lives in the signer only */
    p->cfg.blind = NULL;
    p->signer = amm_signer_new(cfg->sk, cfg->blind);
    if (!p->signer) { free(p); return NULL; }
    amm_signer_address(p->signer, p->self);
    pthread_mutex_init(&p->mu, NULL);
    return p;
}

void amm_eth_pay_free(amm_eth_pay_t *p) {
    if (!p) return;
    amm_signer_free(p->signer);
    pthread_mutex_destroy(&p->mu);
    free(p);
}

void amm_eth_pay_self(const amm_eth_pay_t *p, uint8_t out[20]) {
    memcpy(out, p->self, 20);
}

/* ── the pure verdict ─────────────────────────────────────────────────── */

amm_ep_verdict_t amm_eth_pay_judge(uint64_t gross, uint64_t fee, uint64_t minimum,
                                   uint64_t *net_out) {
    evm_u256 g, f, m, n;
    evm_u256_from_u64(&g, gross);
    evm_u256_from_u64(&f, fee);
    evm_u256_from_u64(&m, minimum);
    amm_payout_t v = amm_payout_after_fee(&g, &f, &m, &n);
    uint64_t nv = 0;
    if (amm_to_u64(&nv, &n) != AMM_OK) nv = 0;     /* net <= gross: cannot happen */
    if (net_out) *net_out = nv;
    if (nv == 0) return AMM_EP_NOTHING;
    return v == AMM_PAYOUT_PAY ? AMM_EP_PAY : AMM_EP_BELOW;
}

/* ── quorum reads over the usable providers ───────────────────────────── */

typedef struct {
    int      use[AMM_ETH_MAX_PROVIDERS];
    uint64_t dl;
} rd_t;

/* Providers used: the configured chain id only (setting eth_chain_id, givens
 * item 77). @return the number. */
static int qualify(amm_eth_pay_t *p, rd_t *rd) {
    int n = 0;
    for (int i = 0; i < p->cfg.n_providers; i++) {
        uint64_t id = 0;
        const amm_eth_provider_t *pr = &p->prov[i];
        rd->use[i] = (pr->chain_id(pr->ctx, &id, rd->dl) == AMM_ETH_OK &&
                      id == p->cfg.chain_id);
        n += rd->use[i];
    }
    return n;
}

typedef enum { R_TIP, R_COUNT_PENDING, R_COUNT_LATEST, R_GASPRICE, R_PRIO } rk_t;

static int cmp_desc(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) - (x > y);
}

/* The Q-th largest answer over the usable providers. @return 0 / 1 (fewer
 * than Q answered). */
static int qth(amm_eth_pay_t *p, const rd_t *rd, rk_t k, uint64_t *out) {
    uint64_t v[AMM_ETH_MAX_PROVIDERS];
    int n = 0;
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        const amm_eth_provider_t *pr = &p->prov[i];
        uint64_t x = 0;
        int rc;
        switch (k) {
        case R_TIP:           rc = pr->block_number(pr->ctx, &x, rd->dl); break;
        case R_COUNT_PENDING: rc = pr->tx_count(pr->ctx, p->self, 1, &x, rd->dl); break;
        case R_COUNT_LATEST:  rc = pr->tx_count(pr->ctx, p->self, 0, &x, rd->dl); break;
        case R_GASPRICE:      rc = pr->gas_price(pr->ctx, &x, rd->dl); break;
        default:              rc = pr->max_priority_fee(pr->ctx, &x, rd->dl); break;
        }
        if (rc == AMM_ETH_OK) v[n++] = x;
    }
    if (n < p->cfg.quorum) return 1;
    qsort(v, (size_t)n, sizeof(v[0]), cmp_desc);
    *out = v[p->cfg.quorum - 1];
    return 0;
}

/* A balance: the SMALLEST answer, needing Q answers. erc != 0: the USDT
 * balanceOf of the bot, else its ether. @return 0 / 1. */
static int min_balance(amm_eth_pay_t *p, const rd_t *rd, int erc, evm_u256 *out) {
    int n = 0;
    evm_u256 lo;
    memset(&lo, 0, sizeof(lo));
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        const amm_eth_provider_t *pr = &p->prov[i];
        uint8_t w[32];
        int rc = erc ? pr->erc20_balance(pr->ctx, p->cfg.usdt, p->self, w, rd->dl)
                     : pr->get_balance(pr->ctx, p->self, w, rd->dl);
        if (rc != AMM_ETH_OK) continue;
        evm_u256 v;
        evm_u256_from_be(&v, w);
        if (n == 0 || evm_u256_cmp(&v, &lo) < 0) lo = v;
        n++;
    }
    if (n < p->cfg.quorum) return 1;
    *out = lo;
    return 0;
}

/* The gas estimate of a call: the Q-th largest answer, as qth() takes every
 * other quorum read, so one provider alone can neither raise the estimate
 * (and the fee deducted from the user) nor lower it below what Q providers
 * report. An error object ("execution reverted") is an unanswered provider.
 * @return 0 / 1 (not enough answers: the payout stays unsent). */
static int max_estimate(amm_eth_pay_t *p, const rd_t *rd, const uint8_t *cd,
                        size_t cd_len, uint64_t *out) {
    uint64_t v[AMM_ETH_MAX_PROVIDERS];
    int n = 0;
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        const amm_eth_provider_t *pr = &p->prov[i];
        uint64_t g = 0;
        if (pr->estimate_gas(pr->ctx, p->self, p->cfg.usdt, cd, cd_len, &g,
                             rd->dl) != AMM_ETH_OK || g == 0) continue;
        v[n++] = g;
    }
    if (n < p->cfg.quorum) return 1;
    qsort(v, (size_t)n, sizeof(v[0]), cmp_desc);
    *out = v[p->cfg.quorum - 1];
    return 0;
}

typedef enum { RR_UNKNOWN, RR_FOUND, RR_NONE } rr_t;

/* The receipt of `hash`: at least Q usable providers return the IDENTICAL
 * receipt (status, block number, block hash, and the same logs), or at least
 * Q say there is none; anything else is unknown. DEPTH (plan line 252, the
 * package 1 rule of amm_eth_watch.c classify, F6): the SAME provider that
 * reports the receipt's block hash must also report a tip at least
 * `final_depth` above that block; `*deep` is 1 only when at least Q such
 * providers vote for the chosen receipt. A receipt with status 1 whose logs
 * differ between providers is a different receipt (no quorum). */
static rr_t read_receipt(amm_eth_pay_t *p, const rd_t *rd, const uint8_t hash[32],
                         amm_eth_receipt_t *out, int *deep) {
    amm_eth_receipt_t *grp = calloc(AMM_ETH_MAX_PROVIDERS, sizeof(*grp));
    amm_eth_receipt_t *r = calloc(1, sizeof(*r));
    int cnt[AMM_ETH_MAX_PROVIDERS], dv[AMM_ETH_MAX_PROVIDERS];
    int ng = 0, none = 0;
    rr_t res = RR_UNKNOWN;
    *deep = 0;
    if (!grp || !r) goto out;
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        const amm_eth_provider_t *pr = &p->prov[i];
        int rc = pr->get_receipt(pr->ctx, hash, r, rd->dl);
        if (rc == AMM_ETH_NOT_FOUND) { none++; continue; }
        if (rc != AMM_ETH_OK) continue;
        int g;
        for (g = 0; g < ng; g++)
            if (grp[g].status == r->status && grp[g].block_number == r->block_number &&
                !memcmp(grp[g].block_hash, r->block_hash, 32) &&
                grp[g].n_logs == r->n_logs && grp[g].logs_total == r->logs_total &&
                !memcmp(grp[g].logs, r->logs, sizeof(r->logs[0]) * (size_t)r->n_logs)) break;
        if (g == ng) { grp[ng] = *r; cnt[ng] = 0; dv[ng] = 0; ng++; }
        cnt[g]++;
        uint64_t tip = 0;
        if (pr->block_number(pr->ctx, &tip, rd->dl) == AMM_ETH_OK &&
            tip >= r->block_number && tip - r->block_number >= p->cfg.final_depth)
            dv[g]++;
    }
    int found = -1, reach = 0;
    for (int g = 0; g < ng; g++)
        if (cnt[g] >= p->cfg.quorum) { found = g; reach++; }
    if (reach == 1 && none < p->cfg.quorum) {
        *out = grp[found];
        *deep = dv[found] >= p->cfg.quorum;
        res = RR_FOUND;
    } else if (reach == 0 && none >= p->cfg.quorum) {
        res = RR_NONE;
    }
out:
    free(grp);
    free(r);
    return res;
}

/* USDT Transfer(address indexed from, address indexed to, uint256 value):
 * THORChain bifrost/pkg/chainclients/shared/evm/direct_erc20_transfer.go:18;
 * ERC-20 event, erc-20.md:157. */
static const uint8_t TRANSFER_TOPIC[32] = {
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68,
    0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef};

typedef enum { LG_MISSING, LG_MATCH, LG_DIFFERENT } lg_t;

/* The Transfer log of a payout (plan line 264: "receipt status and the
 * Transfer log"), checked the way amm_eth_watch.c checks an incoming log:
 * the emitter is the USDT contract, exactly three topics, topic0 the Transfer
 * topic, data 32 bytes. EXACTLY ONE such log must go from the bot to the
 * recipient (padded address words in topics 1 and 2); none, two or more, or
 * a receipt whose logs do not all fit the table, is LG_MISSING (the result
 * cannot be shown). Its value is `*logged`. LG_DIFFERENT: the logged value is
 * not `net` (TetherToken.sol:123-134: the recipient gets value - fee). */
static lg_t check_transfer_log(const amm_eth_pay_t *p, const amm_eth_receipt_t *r,
                               const uint8_t recipient[20], uint64_t net,
                               uint64_t *logged, int *fits, uint8_t val[32]) {
    int hits = 0, idx = -1;
    *fits = 1;
    if (r->logs_total > r->n_logs) return LG_MISSING;
    for (int i = 0; i < r->n_logs; i++) {
        const amm_eth_log_t *l = &r->logs[i];
        static const uint8_t zero12[12] = {0};
        if (memcmp(l->address, p->cfg.usdt, 20) != 0 || l->n_topics != 3 ||
            memcmp(l->topics[0], TRANSFER_TOPIC, 32) != 0 || l->data_len != 32) continue;
        if (memcmp(l->topics[1], zero12, 12) != 0 || memcmp(l->topics[1] + 12, p->self, 20) != 0 ||
            memcmp(l->topics[2], zero12, 12) != 0 || memcmp(l->topics[2] + 12, recipient, 20) != 0)
            continue;
        hits++;
        idx = i;
    }
    if (hits != 1) return LG_MISSING;
    const uint8_t *v = r->logs[idx].data;
    memcpy(val, v, 32);                    /* the full delivered value */
    for (int i = 0; i < 24; i++) if (v[i] != 0) { *fits = 0; break; }
    uint64_t x = 0;
    for (int i = 24; i < 32; i++) x = (x << 8) | v[i];
    *logged = x;
    return (*fits && x == net) ? LG_MATCH : LG_DIFFERENT;
}

/* ── small helpers ────────────────────────────────────────────────────── */

static void say(amm_ep_step_t *o, const char *m) {
    if (o) snprintf(o->msg, sizeof(o->msg), "%s", m);
}

static int unhex20(const char *s, uint8_t out[20]) {
    if (!s || strlen(s) != 40) return -1;
    for (int i = 0; i < 20; i++) {
        int v[2];
        for (int k = 0; k < 2; k++) {
            char c = s[2 * i + k];
            if (c >= '0' && c <= '9') v[k] = c - '0';
            else if (c >= 'a' && c <= 'f') v[k] = c - 'a' + 10;
            else return -1;
        }
        out[i] = (uint8_t)(v[0] * 16 + v[1]);
    }
    return 0;
}

/* The swap owes a USDT payout (the states of amm_journal_swap_list_usdt_owed). */
static int owes_usdt(const amm_swap_t *s) {
    return (s->dir == AMM_NODUS_TO_USDT && !strcmp(s->state, AMM_S_PAYOUT_PENDING)) ||
           (s->dir == AMM_USDT_TO_NODUS && !strcmp(s->state, AMM_S_REFUND_PENDING));
}

static int is_payout(const amm_swap_t *s) { return s->dir == AMM_NODUS_TO_USDT; }

/* Finish the attempt and move the swap in ONE journal transaction. */
static int finish_and_move(amm_eth_pay_t *p, const amm_swap_t *s, const char *att_state,
                           const char *swap_to, const char *msg) {
    amm_journal_t *j = p->cfg.journal;
    if (amm_journal_tx_begin(j) != 0) return -1;
    if (amm_journal_eth_attempt_finish(j, s->seq, att_state) != 0 ||
        (swap_to && amm_journal_swap_transition(j, s->seq, swap_to, NULL, NULL, msg) != 0)) {
        amm_journal_tx_rollback(j);
        return -1;
    }
    return amm_journal_tx_commit(j) == 0 ? 0 : -1;
}

/* ── sign ─────────────────────────────────────────────────────────────── */

static int sign_locked(amm_eth_pay_t *p, int64_t swap_seq, uint64_t gross,
                       uint64_t deadline_ms, amm_ep_step_t *out) {
    amm_journal_t *j = p->cfg.journal;
    amm_swap_t s;
    if (amm_journal_swap_by_seq(j, swap_seq, &s) != 0) { say(out, "no such swap"); return AMM_EP_ERR; }
    if (!owes_usdt(&s)) { say(out, "the swap owes no USDT payout"); return AMM_EP_ERR; }
    amm_eattempt_t prev;
    int pv = amm_journal_eth_attempt_latest(j, swap_seq, &prev);
    if (pv == 0) {
        amm_eattempt_free(&prev);
        say(out, "the swap already has a payout transaction");
        return AMM_EP_ERR;
    }
    if (pv < 0) return AMM_EP_ERR;
    if (p->cfg.payouts_paused) { say(out, "payouts paused"); return AMM_EP_PAUSED; }
    uint8_t recipient[20];
    if (unhex20(is_payout(&s) ? s.dest : s.sender, recipient) != 0) {
        say(out, "the swap holds no Ethereum address");
        return AMM_EP_ERR;
    }
    const uint64_t minimum = is_payout(&s) ? s.minimum : 0;

    rd_t rd = { .dl = deadline_ms };
    if (qualify(p, &rd) < p->cfg.quorum) { say(out, "providers below the quorum"); return AMM_EP_UNKNOWN; }

    /* the fee fields of the transaction (plan silent: reading in the header) */
    uint64_t max_fee = 0, prio = 0;
    if (qth(p, &rd, R_GASPRICE, &max_fee) != 0 || qth(p, &rd, R_PRIO, &prio) != 0 ||
        max_fee == 0 || max_fee > (uint64_t)INT64_MAX) {
        say(out, "the gas price is not readable");
        return AMM_EP_UNKNOWN;
    }
    if (prio > max_fee) prio = max_fee;

    /* gas first (plan line 267), net from it, until the estimated call data
     * is the call data that will be signed */
    uint64_t a = gross, gas = 0, fee = 0, net = 0;
    int fixed = 0;
    for (int it = 0; it < AMM_EP_ITER_MAX && !fixed; it++) {
        uint8_t cd[AMM_TX_TRANSFER_DATA_LEN];
        amm_tx_transfer_calldata(recipient, a, cd);
        if (max_estimate(p, &rd, cd, sizeof(cd), &gas) != 0) {
            say(out, "the gas estimate failed: payout left unsent");
            return AMM_EP_UNKNOWN;
        }
        /* the estimate is raised by 25%, rounded up: Boltz bumpGasLimit
         * (gasLimit * 125 + 99) / 100, lib/wallet/ethereum/EthereumUtils.ts:
         * 83-85 (applied in SequentialSigner.ts before signing). The plan gives
         * no margin; without one a payout can run out of gas (status 0). The
         * bumped limit is what is quoted to the price seam and signed. */
        if (gas > (UINT64_MAX - 99) / 125) {
            say(out, "the gas estimate is out of range");
            return AMM_EP_UNKNOWN;
        }
        gas = (gas * 125 + 99) / 100;
        if (gas > (uint64_t)INT64_MAX ||
            p->cfg.price.fee_usdt(p->cfg.price.ctx, gas, max_fee, &fee, deadline_ms) != AMM_ETH_OK) {
            say(out, "the ETH price is not readable: nothing signed");
            return AMM_EP_UNKNOWN;
        }
        amm_ep_verdict_t v = amm_eth_pay_judge(gross, fee, minimum, &net);
        if (v == AMM_EP_NOTHING) break;
        if (net == a) fixed = 1; else a = net;
    }
    if (out) { out->fee = fee; out->net = net; }

    /* nothing left, or a payout below its minimum: no attempt is signed */
    amm_ep_verdict_t v = amm_eth_pay_judge(gross, fee, minimum, &net);
    if (out) { out->fee = fee; out->net = net; }
    if (v == AMM_EP_NOTHING) {
        say(out, "nothing is left after the Ethereum fee: nothing signed");
        int mv = is_payout(&s)
            ? amm_journal_swap_transition(j, swap_seq, AMM_S_REFUND_PENDING, NULL, NULL,
                                          "zero USDT after the Ethereum fee: refund")
            : amm_journal_swap_transition(j, swap_seq, AMM_S_DROPPED, NULL, NULL,
                                          "Ethereum fee at or above the refund: dropped");
        if (mv != 0) return AMM_EP_ERR;
        if (out) out->worked = 1;
        return AMM_EP_ZERO;
    }
    if (!fixed) { say(out, "the gas estimate did not settle: payout left unsent"); return AMM_EP_UNKNOWN; }
    if (v == AMM_EP_BELOW) {
        say(out, "below the signed minimum after the Ethereum fee: nothing signed");
        if (amm_journal_swap_transition(j, swap_seq, AMM_S_REFUND_PENDING, NULL, NULL,
                                        "below the minimum after the Ethereum fee: refund") != 0)
            return AMM_EP_ERR;
        if (out) out->worked = 1;
        return AMM_EP_BELOW_MIN;
    }

    /* balance check before signing (plan line 266) */
    evm_u256 usdt_bal, eth_bal;
    if (min_balance(p, &rd, 1, &usdt_bal) != 0 || min_balance(p, &rd, 0, &eth_bal) != 0) {
        say(out, "a balance is not readable");
        return AMM_EP_UNKNOWN;
    }
    uint64_t pending = 0;
    if (amm_journal_eth_pending_usdt(j, &pending) != 0) return AMM_EP_ERR;
    evm_u256 pend, avail, need_usdt, g256, mf, need_eth;
    evm_u256_from_u64(&pend, pending);
    amm_sub_sat(&avail, &usdt_bal, &pend);
    evm_u256_from_u64(&need_usdt, net);
    evm_u256_from_u64(&g256, gas);
    evm_u256_from_u64(&mf, max_fee);
    evm_u256_mul(&need_eth, &g256, &mf);            /* 64 x 64 bit: no wrap     */
    if (evm_u256_cmp(&avail, &need_usdt) < 0 || evm_u256_cmp(&eth_bal, &need_eth) < 0) {
        say(out, "the bot's USDT or ether cannot cover the payout");
        return AMM_EP_FUNDS;
    }

    /* nonce under the one lock the caller holds (plan line 265) */
    uint64_t base = 0, jn = 0, nonce;
    if (qth(p, &rd, R_COUNT_PENDING, &base) != 0) {
        say(out, "the nonce is not readable");
        return AMM_EP_UNKNOWN;
    }
    int nr = amm_journal_eth_next_nonce(j, p->cfg.chain_id, &jn);
    if (nr < 0) return AMM_EP_ERR;
    if (nr == 1) jn = 0;
    nonce = base > jn ? base : jn;

    uint8_t cd[AMM_TX_TRANSFER_DATA_LEN];
    amm_tx_transfer_calldata(recipient, net, cd);
    amm_tx1559_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.chain_id = p->cfg.chain_id;
    tx.nonce = nonce;
    tx.max_priority_fee_per_gas = prio;
    tx.max_fee_per_gas = max_fee;
    tx.gas = gas;
    tx.has_to = 1;
    memcpy(tx.to, p->cfg.usdt, 20);
    tx.data = cd;
    tx.data_len = sizeof(cd);
    amm_eattempt_t at;
    memset(&at, 0, sizeof(at));
    if (amm_tx1559_sign(p->signer, &tx, &at.raw, &at.raw_len, at.hash) != 0) {
        say(out, "signing failed");
        return AMM_EP_ERR;
    }
    at.swap_seq = swap_seq;
    at.chain_id = p->cfg.chain_id;
    at.nonce = nonce;
    memcpy(at.recipient, recipient, 20);
    at.gross = gross; at.net = net; at.fee = fee;
    at.gas_limit = gas;
    at.max_fee_per_gas = max_fee;
    at.max_priority_fee_per_gas = prio;
    /* WRITE-AHEAD: stored here, broadcast only by amm_eth_pay_step */
    int jr = amm_journal_eth_attempt_sign(j, &at);
    amm_eattempt_free(&at);
    if (jr != AMM_J_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the signed payout was not stored (%d)", jr);
        say(out, "the signed payout was not stored");
        return AMM_EP_ERR;
    }
    if (out) { out->worked = 1; out->signed_ = 1; }
    return AMM_EP_OK;
}

int amm_eth_pay_sign(amm_eth_pay_t *p, int64_t swap_seq, uint64_t gross,
                     uint64_t deadline_ms, amm_ep_step_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); out->swap_seq = swap_seq; }
    if (!p || gross == 0 || gross > (uint64_t)INT64_MAX) return AMM_EP_ERR;
    pthread_mutex_lock(&p->mu);
    int rc = sign_locked(p, swap_seq, gross, deadline_ms, out);
    pthread_mutex_unlock(&p->mu);
    return rc;
}

/* ── step ─────────────────────────────────────────────────────────────── */

static int step_locked(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                       amm_ep_step_t *out) {
    amm_journal_t *j = p->cfg.journal;
    amm_swap_t s;
    if (amm_journal_swap_by_seq(j, swap_seq, &s) != 0) { say(out, "no such swap"); return AMM_EP_ERR; }
    if (!owes_usdt(&s)) { say(out, "the swap owes no USDT payout"); return AMM_EP_ERR; }
    amm_eattempt_t a;
    int g = amm_journal_eth_attempt_latest(j, swap_seq, &a);
    if (g < 0) return AMM_EP_ERR;
    if (g == 1) return AMM_EP_NEED_SIGN;
    int rc = AMM_EP_ERR;
    amm_eth_receipt_t *r = NULL;
    if (!strcmp(a.state, AMM_EA_FAILED)) { say(out, "the payout failed on chain"); rc = AMM_EP_FAILED; goto done; }
    if (strcmp(a.state, AMM_EA_SIGNED) && strcmp(a.state, AMM_EA_SUBMITTED)) {
        say(out, "the attempt is already final");
        rc = AMM_EP_ERR;
        goto done;
    }

    rd_t rd = { .dl = deadline_ms };
    if (qualify(p, &rd) < p->cfg.quorum) { say(out, "providers below the quorum"); rc = AMM_EP_UNKNOWN; goto done; }
    uint64_t tip = 0;
    if (qth(p, &rd, R_TIP, &tip) != 0) { say(out, "the tip is not readable"); rc = AMM_EP_UNKNOWN; goto done; }
    r = calloc(1, sizeof(*r));
    if (!r) { rc = AMM_EP_ERR; goto done; }
    int deep = 0;
    rr_t rr = read_receipt(p, &rd, a.hash, r, &deep);
    if (rr == RR_UNKNOWN) { say(out, "the receipt is not readable or the providers disagree"); rc = AMM_EP_UNKNOWN; goto done; }

    if (rr == RR_FOUND) {
        if (!deep) { rc = AMM_EP_OK; goto done; }              /* waiting for the final depth (joint vote) */
        if (r->status == 1) {
            /* status 1 AND the USDT Transfer log (plan line 264) */
            uint8_t rcpt[20];
            uint64_t logged = 0;
            int fits = 1;
            uint8_t val[32] = {0};
            if (unhex20(is_payout(&s) ? s.dest : s.sender, rcpt) != 0) { rc = AMM_EP_ERR; goto done; }
            lg_t lg = check_transfer_log(p, r, rcpt, a.net, &logged, &fits, val);
            if (lg == LG_MISSING) {
                if (finish_and_move(p, &s, AMM_EA_UNKNOWN, AMM_S_UNKNOWN,
                                    "receipt status 1 but no USDT Transfer log from the bot to the recipient") != 0) {
                    rc = AMM_EP_ERR;
                    goto done;
                }
                if (out) out->worked = 1;
                say(out, "no matching Transfer log: the attempt and the swap are unknown, the bot stops");
                rc = AMM_EP_NO_LOG;
                goto done;
            }
            if (lg == LG_DIFFERENT) {
                char m[AMM_MSG_MAX];
                if (fits)
                    snprintf(m, sizeof(m), "USDT delivered %llu differs from the %llu sent: held",
                             (unsigned long long)logged, (unsigned long long)a.net);
                else {
                    /* above 64 bits: the full 32-byte value, as hex */
                    char hx[65];
                    static const char *dg = "0123456789abcdef";
                    for (int i = 0; i < 32; i++) { hx[2 * i] = dg[val[i] >> 4]; hx[2 * i + 1] = dg[val[i] & 15]; }
                    hx[64] = '\0';
                    snprintf(m, sizeof(m), "USDT delivered 0x%s differs from the %llu sent: held",
                             hx, (unsigned long long)a.net);
                }
                /* the transfer happened: the attempt is confirmed, the swap is
                 * held for manual handling (what follows is DEFERRED, plan line 277) */
                if (finish_and_move(p, &s, AMM_EA_CONFIRMED, AMM_S_HELD, m) != 0) {
                    rc = AMM_EP_ERR;
                    goto done;
                }
                if (out) { out->worked = 1; snprintf(out->msg, sizeof(out->msg), "%s", m); }
                rc = AMM_EP_HELD;
                goto done;
            }
            if (finish_and_move(p, &s, AMM_EA_CONFIRMED,
                                is_payout(&s) ? AMM_S_PAID : AMM_S_REFUNDED, NULL) != 0) {
                rc = AMM_EP_ERR;
                goto done;
            }
            if (out) { out->worked = 1; out->confirmed = 1; }
            rc = AMM_EP_OK;
            goto done;
        }
        if (amm_journal_eth_attempt_finish(j, swap_seq, AMM_EA_FAILED) != 0) { rc = AMM_EP_ERR; goto done; }
        if (out) out->worked = 1;
        say(out, "the payout transaction failed (receipt status is not 1)");
        rc = AMM_EP_FAILED;
        goto done;
    }

    /* no receipt at the quorum: is its nonce used by another transaction? */
    uint64_t confirmed = 0;
    if (qth(p, &rd, R_COUNT_LATEST, &confirmed) != 0) { say(out, "the confirmed nonce is not readable"); rc = AMM_EP_UNKNOWN; goto done; }
    if (confirmed > a.nonce) {
        if (finish_and_move(p, &s, AMM_EA_ORPHANED, AMM_S_UNKNOWN,
                            "payout transaction orphaned: its nonce was used by another transaction") != 0) {
            rc = AMM_EP_ERR;
            goto done;
        }
        if (out) out->worked = 1;
        say(out, "orphaned: the swap is unknown and the bot stops");
        rc = AMM_EP_ORPHANED;
        goto done;
    }
    if (strcmp(a.state, AMM_EA_SIGNED) != 0) { rc = AMM_EP_OK; goto done; }   /* submitted: wait */
    if (p->cfg.payouts_paused) { say(out, "payouts paused"); rc = AMM_EP_PAUSED; goto done; }

    /* stored, never broadcast: send the SAME STORED BYTES to every usable provider */
    int accepted = 0;
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd.use[i]) continue;
        const amm_eth_provider_t *pr = &p->prov[i];
        uint8_t h[32];
        if (pr->send_raw(pr->ctx, a.raw, a.raw_len, h, deadline_ms) == AMM_ETH_OK &&
            !memcmp(h, a.hash, 32)) accepted++;
    }
    if (accepted == 0) { say(out, "no provider took the transaction"); rc = AMM_EP_UNKNOWN; goto done; }
    if (amm_journal_eth_attempt_submitted(j, swap_seq, tip) != 0) { rc = AMM_EP_ERR; goto done; }
    if (out) { out->worked = 1; out->submitted = 1; }
    rc = AMM_EP_OK;
done:
    free(r);
    amm_eattempt_free(&a);
    return rc;
}

int amm_eth_pay_step(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                     amm_ep_step_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); out->swap_seq = swap_seq; }
    if (!p) return AMM_EP_ERR;
    pthread_mutex_lock(&p->mu);
    int rc = step_locked(p, swap_seq, deadline_ms, out);
    pthread_mutex_unlock(&p->mu);
    return rc;
}
