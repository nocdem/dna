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

#include "amm_eth_fanout.h"
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
            !p->erc20_balance || !p->tx_count || !p->estimate_gas || !p->base_fee ||
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
/* The helpers below ask every usable provider at once (amm_eth_fanout): a work
 * unit runs one provider's call(s) on that provider's thread and writes only
 * slot i of its job; the examination is today's loop, run on the calling thread
 * after every unit has returned, in provider index order. A unit never takes
 * p->mu or touches the journal (the payer's callers hold p->mu). */
typedef struct {
    const amm_eth_pay_t *p;
    uint64_t             dl;
    int                  rc[AMM_ETH_MAX_PROVIDERS];
    uint64_t             id[AMM_ETH_MAX_PROVIDERS];
} pq_job_t;

static void pq_unit(void *arg, int i) {
    pq_job_t *j = arg;
    const amm_eth_provider_t *pr = &j->p->prov[i];
    j->id[i] = 0;
    j->rc[i] = pr->chain_id(pr->ctx, &j->id[i], j->dl);
}

static int qualify(amm_eth_pay_t *p, rd_t *rd) {
    int n = 0;
    pq_job_t job;
    job.p = p; job.dl = rd->dl;
    amm_fanout_run(p->cfg.n_providers, NULL, pq_unit, &job);        /* every configured provider */
    for (int i = 0; i < p->cfg.n_providers; i++) {
        rd->use[i] = (job.rc[i] == AMM_ETH_OK && job.id[i] == p->cfg.chain_id);
        n += rd->use[i];
    }
    return n;
}

typedef enum { R_TIP, R_COUNT_PENDING, R_COUNT_LATEST, R_BASEFEE, R_PRIO } rk_t;

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
        case R_BASEFEE:       rc = pr->base_fee(pr->ctx, &x, rd->dl); break;
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
typedef struct {
    const amm_eth_pay_t *p;
    uint64_t             dl;
    int                  erc;
    int                  rc[AMM_ETH_MAX_PROVIDERS];
    uint8_t              w[AMM_ETH_MAX_PROVIDERS][32];
} bal_job_t;

static void bal_unit(void *arg, int i) {
    bal_job_t *j = arg;
    const amm_eth_pay_t *p = j->p;
    const amm_eth_provider_t *pr = &p->prov[i];
    j->rc[i] = j->erc ? pr->erc20_balance(pr->ctx, p->cfg.usdt, p->self, j->w[i], j->dl)
                      : pr->get_balance(pr->ctx, p->self, j->w[i], j->dl);
}

static int min_balance(amm_eth_pay_t *p, const rd_t *rd, int erc, evm_u256 *out) {
    int n = 0;
    evm_u256 lo;
    memset(&lo, 0, sizeof(lo));
    bal_job_t job;
    job.p = p; job.dl = rd->dl; job.erc = erc;
    amm_fanout_run(p->cfg.n_providers, rd->use, bal_unit, &job);
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        if (job.rc[i] != AMM_ETH_OK) continue;
        evm_u256 v;
        evm_u256_from_be(&v, job.w[i]);
        if (n == 0 || evm_u256_cmp(&v, &lo) < 0) lo = v;
        n++;
    }
    if (n < p->cfg.quorum) return 1;
    *out = lo;
    return 0;
}

/* The gas estimate of a call: the Q-th largest answer, as qth() takes every
 * other quorum read. With Q >= 2 one provider can move the selected value only
 * within the other providers' answers (it can neither raise it above, nor
 * lower it below, what Q - 1 others report); with Q = 1 it sets the value
 * alone (evm-fee plan 2.4.2). An error object ("execution reverted") is an
 * unanswered provider.
 * @return 0 / 1 (not enough answers: the payout stays unsent). */
typedef struct {
    const amm_eth_pay_t *p;
    uint64_t             dl;
    const uint8_t       *cd;
    size_t               cd_len;
    int                  rc[AMM_ETH_MAX_PROVIDERS];
    uint64_t             g[AMM_ETH_MAX_PROVIDERS];
} est_job_t;

static void est_unit(void *arg, int i) {
    est_job_t *j = arg;
    const amm_eth_pay_t *p = j->p;
    const amm_eth_provider_t *pr = &p->prov[i];
    j->g[i] = 0;
    j->rc[i] = pr->estimate_gas(pr->ctx, p->self, p->cfg.usdt, j->cd, j->cd_len, &j->g[i], j->dl);
}

static int max_estimate(amm_eth_pay_t *p, const rd_t *rd, const uint8_t *cd,
                        size_t cd_len, uint64_t *out) {
    uint64_t v[AMM_ETH_MAX_PROVIDERS];
    int n = 0;
    est_job_t job;
    job.p = p; job.dl = rd->dl; job.cd = cd; job.cd_len = cd_len;
    amm_fanout_run(p->cfg.n_providers, rd->use, est_unit, &job);
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        if (job.rc[i] != AMM_ETH_OK || job.g[i] == 0) continue;
        v[n++] = job.g[i];
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
typedef struct {
    const amm_eth_pay_t *p;
    uint64_t             dl;
    const uint8_t       *hash;
    int                  rc_r[AMM_ETH_MAX_PROVIDERS], rc_tip[AMM_ETH_MAX_PROVIDERS];
    amm_eth_receipt_t    rcpt[AMM_ETH_MAX_PROVIDERS];
    uint64_t             tip[AMM_ETH_MAX_PROVIDERS];
} rcpt_job_t;

/* one unit: the receipt, then (only if one came) the SAME provider's latest
 * block, in today's per-provider order (the joint depth vote) */
static void rcpt_unit(void *arg, int i) {
    rcpt_job_t *j = arg;
    const amm_eth_provider_t *pr = &j->p->prov[i];
    j->rc_tip[i] = AMM_ETH_ERR;
    j->tip[i] = 0;
    j->rc_r[i] = pr->get_receipt(pr->ctx, j->hash, &j->rcpt[i], j->dl);
    if (j->rc_r[i] == AMM_ETH_OK)
        j->rc_tip[i] = pr->block_number(pr->ctx, &j->tip[i], j->dl);
}

static rr_t read_receipt(amm_eth_pay_t *p, const rd_t *rd, const uint8_t hash[32],
                         amm_eth_receipt_t *out, int *deep) {
    amm_eth_receipt_t *grp = calloc(AMM_ETH_MAX_PROVIDERS, sizeof(*grp));
    rcpt_job_t *job = calloc(1, sizeof(*job));
    int cnt[AMM_ETH_MAX_PROVIDERS], dv[AMM_ETH_MAX_PROVIDERS];
    int ng = 0, none = 0;
    rr_t res = RR_UNKNOWN;
    *deep = 0;
    if (!grp || !job) goto out;
    job->p = p; job->dl = rd->dl; job->hash = hash;
    amm_fanout_run(p->cfg.n_providers, rd->use, rcpt_unit, job);
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd->use[i]) continue;
        const amm_eth_receipt_t *r = &job->rcpt[i];
        int rc = job->rc_r[i];
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
        uint64_t tip = job->tip[i];
        if (job->rc_tip[i] == AMM_ETH_OK &&
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
    free(job);
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

/* A transaction hash as hex (out holds 65), for the log. */
static const char *hash_hex(const uint8_t h[32], char out[65]) {
    static const char *dg = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = dg[h[i] >> 4]; out[2 * i + 1] = dg[h[i] & 15]; }
    out[64] = '\0';
    return out;
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

/* Settle attempt `n` of the swap (every other attempt of its nonce becomes
 * voided) and move the swap in ONE journal transaction. */
static int finish_and_move(amm_eth_pay_t *p, const amm_swap_t *s, int n, const char *att_state,
                           const char *swap_to, const char *msg) {
    amm_journal_t *j = p->cfg.journal;
    if (amm_journal_tx_begin(j) != 0) return -1;
    if (amm_journal_eth_attempt_settle(j, s->seq, n, att_state) != 0 ||
        (swap_to && amm_journal_swap_transition(j, s->seq, swap_to, NULL, NULL, msg) != 0)) {
        amm_journal_tx_rollback(j);
        return -1;
    }
    return amm_journal_tx_commit(j) == 0 ? 0 : -1;
}

/* ── the fee formula (evm-fee plan 6.3), pure ─────────────────────────── */

int amm_eth_pay_max_fee(uint64_t base, uint64_t prio, uint64_t *max_fee) {
    if (!max_fee || prio > (uint64_t)INT64_MAX) return -1;          /* checked first: the
                                                                      * subtraction below is unsigned */
    if (base > ((uint64_t)INT64_MAX - prio) / 2) return -1;        /* result within INT64_MAX */
    const uint64_t m = 2 * base + prio;
    if (m == 0 || m < prio) return -1;
    *max_fee = m;
    return 0;
}

int amm_eth_pay_bump(uint64_t x, uint64_t *out) {
    const uint64_t step = x / 10 > 1 ? x / 10 : 1;                 /* floor(x * 110 / 100) = x + x / 10 */
    if (!out || x > (uint64_t)INT64_MAX || step > (uint64_t)INT64_MAX - x) return -1;
    *out = x + step;
    return 0;
}

int amm_eth_pay_replacement_fees(uint64_t base, uint64_t prio, uint64_t old_max_fee,
                                 uint64_t old_prio, uint64_t *max_fee, uint64_t *prio_out) {
    uint64_t bp, bm, pr, mf;
    if (!max_fee || !prio_out || amm_eth_pay_bump(old_prio, &bp) != 0 ||
        amm_eth_pay_bump(old_max_fee, &bm) != 0) return -1;
    pr = prio > bp ? prio : bp;
    if (amm_eth_pay_max_fee(base, pr, &mf) != 0 || mf < bm) return -1;
    *max_fee = mf;
    *prio_out = pr;
    return 0;
}

/* ── planning (evm-fee plan 6.5.2): read-only, no payer lock ──────────── */

/* The fee facts: the providers on the configured chain id, the base fee and
 * the tip at the quorum, the max fee from the formula. `why` (may be NULL) is
 * the reason of a failure. */
static int facts_read(amm_eth_pay_t *p, uint64_t deadline_ms, amm_ep_facts_t *f, const char **why) {
    rd_t rd = { .dl = deadline_ms };
    memset(f, 0, sizeof(*f));
    f->n_usable = qualify(p, &rd);
    memcpy(f->use, rd.use, sizeof(f->use));
    if (f->n_usable < p->cfg.quorum) {
        if (why) *why = "providers below the quorum";
        return AMM_EP_UNKNOWN;
    }
    if (qth(p, &rd, R_BASEFEE, &f->base) != 0 || qth(p, &rd, R_PRIO, &f->prio) != 0 ||
        amm_eth_pay_max_fee(f->base, f->prio, &f->max_fee) != 0) {
        if (why) *why = "the network fee is not readable";
        return AMM_EP_UNKNOWN;
    }
    return AMM_EP_OK;
}

int amm_eth_pay_fee_facts(amm_eth_pay_t *p, uint64_t deadline_ms, amm_ep_facts_t *out) {
    if (!p || !out) return AMM_EP_ERR;
    return facts_read(p, deadline_ms, out, NULL);
}

int amm_eth_pay_plan(amm_eth_pay_t *p, const amm_ep_facts_t *facts, const uint8_t recipient[20],
                     uint64_t gross, uint64_t minimum, uint64_t deadline_ms,
                     amm_ep_plan_t *out) {
    if (!p || !facts || !recipient || !out) return AMM_EP_ERR;
    memset(out, 0, sizeof(*out));
    if (gross == 0 || gross > (uint64_t)INT64_MAX || facts->max_fee == 0 ||
        facts->max_fee > (uint64_t)INT64_MAX) return AMM_EP_ERR;
    rd_t rd = { .dl = deadline_ms };
    memcpy(rd.use, facts->use, sizeof(rd.use));
    const uint64_t max_fee = facts->max_fee;

    /* gas first (plan line 267), net from it, until the estimated call data
     * is the call data that will be signed */
    uint64_t a = gross, gas = 0, fee = 0, net = 0;
    int fixed = 0;
    for (int it = 0; it < AMM_EP_ITER_MAX && !fixed; it++) {
        uint8_t cd[AMM_TX_TRANSFER_DATA_LEN];
        amm_tx_transfer_calldata(recipient, a, cd);
        if (max_estimate(p, &rd, cd, sizeof(cd), &gas) != 0) {
            snprintf(out->msg, sizeof(out->msg), "the gas estimate failed: payout left unsent");
            return AMM_EP_UNKNOWN;
        }
        /* the estimate is raised by 25%, rounded up: Boltz bumpGasLimit
         * (gasLimit * 125 + 99) / 100, lib/wallet/ethereum/EthereumUtils.ts:
         * 83-85 (applied in SequentialSigner.ts before signing). The plan gives
         * no margin; without one a payout can run out of gas (status 0). The
         * bumped limit is what is quoted to the price seam and signed. */
        if (gas > (UINT64_MAX - 99) / 125) {
            snprintf(out->msg, sizeof(out->msg), "the gas estimate is out of range");
            return AMM_EP_UNKNOWN;
        }
        gas = (gas * 125 + 99) / 100;
        if (gas > (uint64_t)INT64_MAX ||
            p->cfg.price.fee_usdt(p->cfg.price.ctx, gas, max_fee, &fee, deadline_ms) != AMM_ETH_OK) {
            snprintf(out->msg, sizeof(out->msg), "the ETH price is not readable: nothing signed");
            return AMM_EP_UNKNOWN;
        }
        amm_ep_verdict_t v = amm_eth_pay_judge(gross, fee, minimum, &net);
        if (v == AMM_EP_NOTHING) break;
        if (net == a) fixed = 1; else a = net;
    }

    /* nothing left, or a payout below its minimum */
    amm_ep_verdict_t v = amm_eth_pay_judge(gross, fee, minimum, &net);
    out->gas = gas; out->fee = fee; out->net = net; out->verdict = v;
    if (v == AMM_EP_NOTHING) {
        snprintf(out->msg, sizeof(out->msg), "nothing is left after the Ethereum fee: nothing signed");
        return AMM_EP_OK;
    }
    if (!fixed) {
        snprintf(out->msg, sizeof(out->msg), "the gas estimate did not settle: payout left unsent");
        return AMM_EP_UNKNOWN;
    }
    if (v == AMM_EP_BELOW)
        snprintf(out->msg, sizeof(out->msg), "below the signed minimum after the Ethereum fee: nothing signed");
    return AMM_EP_OK;
}

/* ── sign ─────────────────────────────────────────────────────────────── */

/* Plan, estimate, check the funds and SIGN a payout of `gross` USDT to
 * `recipient` WITHOUT touching the journal: `at` is filled (raw on the heap,
 * the caller stores it or frees it) when the result is AMM_EP_OK. The minimum
 * is compared with the amount after the Ethereum fee (0 = none). ZERO and
 * BELOW_MIN are only returned; moving a swap is the engine's (plan section 12,
 * revision 12: the decision is made once). `repl` (NULL for a first attempt or a
 * re-send) is the stuck head a REPLACEMENT replaces: it is signed with the
 * head's nonce, the fields of the formula raised to the pool's replacement
 * minimum (6.11.3), and the funds of its nonce are counted once, at the larger
 * of the two attempts (6.11.4, 6.13). `p->mu` is held by the caller. */
static int build_locked(amm_eth_pay_t *p, const uint8_t recipient[20], uint64_t gross,
                        uint64_t minimum, uint64_t deadline_ms, const amm_eattempt_t *repl,
                        amm_eattempt_t *at, amm_ep_step_t *out) {
    amm_journal_t *j = p->cfg.journal;
    memset(at, 0, sizeof(*at));
    if (p->cfg.payouts_paused) { say(out, "payouts paused"); return AMM_EP_PAUSED; }

    amm_ep_facts_t f;
    const char *why = NULL;
    if (facts_read(p, deadline_ms, &f, &why) != AMM_EP_OK) { say(out, why); return AMM_EP_UNKNOWN; }
    uint64_t max_fee = f.max_fee, prio = f.prio;
    if (repl) {
        uint64_t rmf = 0, rpr = 0;
        if (amm_eth_pay_replacement_fees(f.base, f.prio, repl->max_fee_per_gas,
                                         repl->max_priority_fee_per_gas, &rmf, &rpr) != 0) {
            say(out, "the replacement fee cannot be computed");
            return AMM_EP_UNKNOWN;
        }
        max_fee = rmf; prio = rpr;
        f.max_fee = rmf; f.prio = rpr;
    }

    amm_ep_plan_t pl;
    int pr = amm_eth_pay_plan(p, &f, recipient, gross, minimum, deadline_ms, &pl);
    if (out) { out->fee = pl.fee; out->net = pl.net; }
    if (pr != AMM_EP_OK) { say(out, pl.msg); return pr; }
    if (pl.verdict == AMM_EP_NOTHING) { say(out, pl.msg); return AMM_EP_ZERO; }
    if (pl.verdict == AMM_EP_BELOW) { say(out, pl.msg); return AMM_EP_BELOW_MIN; }
    const uint64_t gas = pl.gas, fee = pl.fee, net = pl.net;

    /* balance check before signing (plan line 266; evm-fee plan 6.13): the
     * USDT and the ether of the bot's own pending payouts are counted, once per
     * nonce */
    rd_t rd = { .dl = deadline_ms };
    memcpy(rd.use, f.use, sizeof(rd.use));
    evm_u256 usdt_bal, eth_bal;
    if (min_balance(p, &rd, 1, &usdt_bal) != 0 || min_balance(p, &rd, 0, &eth_bal) != 0) {
        say(out, "a balance is not readable");
        return AMM_EP_UNKNOWN;
    }
    uint64_t pending = 0;
    evm_u256 pend_e;
    if (amm_journal_eth_pending(j, p->cfg.chain_id, repl ? &repl->nonce : NULL,
                                &pending, &pend_e) != 0) return AMM_EP_ERR;
    evm_u256 pend, avail, need_usdt, g256, mf, need_eth, total_eth;
    evm_u256_from_u64(&pend, pending);
    amm_sub_sat(&avail, &usdt_bal, &pend);
    evm_u256_from_u64(&need_usdt, repl && repl->net > net ? repl->net : net);
    evm_u256_from_u64(&g256, gas);
    evm_u256_from_u64(&mf, max_fee);
    evm_u256_mul(&need_eth, &g256, &mf);            /* 64 x 64 bit: no wrap     */
    if (repl) {                                     /* its nonce at the larger of the two */
        evm_u256 og, om, old_eth;
        evm_u256_from_u64(&og, repl->gas_limit);
        evm_u256_from_u64(&om, repl->max_fee_per_gas);
        evm_u256_mul(&old_eth, &og, &om);
        if (evm_u256_cmp(&old_eth, &need_eth) > 0) need_eth = old_eth;
    }
    if (amm_add(&total_eth, &pend_e, &need_eth) != AMM_OK) return AMM_EP_ERR;
    if (evm_u256_cmp(&avail, &need_usdt) < 0 || evm_u256_cmp(&eth_bal, &total_eth) < 0) {
        say(out, "the bot's USDT or ether cannot cover the payout");
        return AMM_EP_FUNDS;
    }

    /* nonce under the one lock the caller holds (plan line 265); a
     * replacement keeps its head's nonce */
    uint64_t nonce;
    if (repl) {
        nonce = repl->nonce;
    } else {
        uint64_t base = 0, jn = 0;
        if (qth(p, &rd, R_COUNT_PENDING, &base) != 0) {
            say(out, "the nonce is not readable");
            return AMM_EP_UNKNOWN;
        }
        int nr = amm_journal_eth_next_nonce(j, p->cfg.chain_id, &jn);
        if (nr < 0) return AMM_EP_ERR;
        if (nr == 1) jn = 0;
        nonce = base > jn ? base : jn;
    }

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
    if (amm_tx1559_sign(p->signer, &tx, &at->raw, &at->raw_len, at->hash) != 0) {
        say(out, "signing failed");
        return AMM_EP_ERR;
    }
    at->chain_id = p->cfg.chain_id;
    at->nonce = nonce;
    memcpy(at->recipient, recipient, 20);
    at->gross = gross; at->net = net; at->fee = fee;
    at->gas_limit = gas;
    at->max_fee_per_gas = max_fee;
    at->max_priority_fee_per_gas = prio;
    return AMM_EP_OK;
}

/* Sign and STORE the USDT REFUND of a USDT -> NODUS swap in refund_pending. A
 * NODUS -> USDT payout's first transaction is stored by the decision
 * (amm_eth_pay_prepare, amm_journal_swap_decide), never here. */
static int sign_locked(amm_eth_pay_t *p, int64_t swap_seq, uint64_t gross,
                       uint64_t deadline_ms, amm_ep_step_t *out) {
    amm_journal_t *j = p->cfg.journal;
    amm_swap_t s;
    if (amm_journal_swap_by_seq(j, swap_seq, &s) != 0) { say(out, "no such swap"); return AMM_EP_ERR; }
    if (!owes_usdt(&s)) { say(out, "the swap owes no USDT payout"); return AMM_EP_ERR; }
    if (is_payout(&s)) { say(out, "a payout is signed in its decision, not here"); return AMM_EP_ERR; }
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
    if (unhex20(s.sender, recipient) != 0) {
        say(out, "the swap holds no Ethereum address");
        return AMM_EP_ERR;
    }
    amm_eattempt_t at;
    /* a refund whose Ethereum fee is at or above it is not sent (givens items
     * 89, 90): AMM_EP_ZERO, nothing signed and nothing moved here; the engine
     * puts its USDT in the pool and drops the swap (givens item 114 "4 a") */
    int rc = build_locked(p, recipient, gross, 0, deadline_ms, NULL, &at, out);
    if (rc != AMM_EP_OK) return rc;
    at.swap_seq = swap_seq;
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

void amm_ep_prepared_free(amm_ep_prepared_t *pre) {
    if (!pre) return;
    amm_eattempt_free(&pre->attempt);
    memset(pre, 0, sizeof(*pre));
}

int amm_eth_pay_prepare(amm_eth_pay_t *p, const char *recipient_hex, uint64_t gross,
                        uint64_t minimum, uint64_t deadline_ms,
                        amm_ep_prepared_t *out) {
    if (!p || !recipient_hex || !out) return AMM_EP_ERR;
    memset(out, 0, sizeof(*out));
    uint8_t recipient[20];
    if (unhex20(recipient_hex, recipient) != 0 || gross == 0 ||
        gross > (uint64_t)INT64_MAX) return AMM_EP_ERR;
    amm_ep_step_t st;
    memset(&st, 0, sizeof(st));
    pthread_mutex_lock(&p->mu);
    int rc = build_locked(p, recipient, gross, minimum, deadline_ms, NULL, &out->attempt, &st);
    pthread_mutex_unlock(&p->mu);
    out->fee = st.fee;
    out->net = st.net;
    snprintf(out->msg, sizeof(out->msg), "%s", st.msg);
    if (rc != AMM_EP_OK) amm_eattempt_free(&out->attempt);
    return rc;
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
    /* the HEAD of the swap's attempts and, while it waits, its GROUP: the head
     * and the attempts it replaced (same nonce; only one can be included) */
    amm_eattempt_t head;
    int g = amm_journal_eth_attempt_head(j, swap_seq, &head);
    if (g < 0) return AMM_EP_ERR;
    if (g == 1) return AMM_EP_NEED_SIGN;
    int rc = AMM_EP_ERR;
    amm_eth_receipt_t *r = NULL;
    amm_eattempt_t grp[AMM_EA_GROUP_MAX];
    int ng = 0;
    /* `a` is the attempt the rest of the step is about: the head, or the member
     * that landed (a shallow view: the heap bytes belong to `head` and `grp`) */
    amm_eattempt_t a = head;
    if (!strcmp(head.state, AMM_EA_FAILED)) { say(out, "the payout failed on chain"); rc = AMM_EP_FAILED; goto done; }
    if (strcmp(head.state, AMM_EA_SIGNED) && strcmp(head.state, AMM_EA_SUBMITTED)) {
        say(out, "the attempt is already final");
        rc = AMM_EP_ERR;
        goto done;
    }
    if (amm_journal_eth_attempt_group(j, swap_seq, grp, AMM_EA_GROUP_MAX, &ng) != 0 || ng < 1) {
        rc = AMM_EP_ERR;
        goto done;
    }

    rd_t rd = { .dl = deadline_ms };
    if (qualify(p, &rd) < p->cfg.quorum) { say(out, "providers below the quorum"); rc = AMM_EP_UNKNOWN; goto done; }
    uint64_t tip = 0;
    if (qth(p, &rd, R_TIP, &tip) != 0) { say(out, "the tip is not readable"); rc = AMM_EP_UNKNOWN; goto done; }
    r = calloc(1, sizeof(*r));
    amm_eth_receipt_t *tmp = calloc(1, sizeof(*tmp));
    if (!r || !tmp) { free(tmp); rc = AMM_EP_ERR; goto done; }
    /* every member's receipt (plan 6.11.5): one not readable at the quorum
     * changes nothing; one found is the attempt that landed */
    int deep = 0, nfound = 0, unreadable = 0;
    rr_t rr = RR_NONE;
    for (int i = 0; i < ng; i++) {
        int dp = 0;
        rr_t ri = read_receipt(p, &rd, grp[i].hash, tmp, &dp);
        if (ri == RR_UNKNOWN) { unreadable = 1; break; }
        if (ri == RR_FOUND) {
            nfound++;
            *r = *tmp;
            deep = dp;
            a = grp[i];
        }
    }
    free(tmp);
    if (unreadable) { say(out, "the receipt is not readable or the providers disagree"); rc = AMM_EP_UNKNOWN; goto done; }
    if (nfound > 1) {
        /* one nonce is included at most once: two receipts cannot both be true */
        QGP_LOG_ERROR(LOG_TAG, "swap %s: receipts for two attempts of one nonce: unknown", s.id);
        say(out, "two attempts of one nonce have receipts: unreadable");
        rc = AMM_EP_UNKNOWN;
        goto done;
    }
    if (nfound == 1) rr = RR_FOUND;

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
                if (finish_and_move(p, &s, a.n, AMM_EA_UNKNOWN, AMM_S_UNKNOWN,
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
                if (finish_and_move(p, &s, a.n, AMM_EA_CONFIRMED, AMM_S_HELD, m) != 0) {
                    rc = AMM_EP_ERR;
                    goto done;
                }
                if (out) { out->worked = 1; snprintf(out->msg, sizeof(out->msg), "%s", m); }
                rc = AMM_EP_HELD;
                goto done;
            }
            if (finish_and_move(p, &s, a.n, AMM_EA_CONFIRMED,
                                is_payout(&s) ? AMM_S_PAID : AMM_S_REFUNDED, NULL) != 0) {
                rc = AMM_EP_ERR;
                goto done;
            }
            char th[65];
            QGP_LOG_INFO(LOG_TAG, "swap %s: USDT %s 0x%s confirmed in block %llu (attempt %d, %llu units%s)",
                         s.id, is_payout(&s) ? "payout" : "refund", hash_hex(a.hash, th),
                         (unsigned long long)r->block_number, a.n, (unsigned long long)a.net,
                         ng > 1 ? ", an attempt of a replaced group: the others are voided" : "");
            if (out) { out->worked = 1; out->confirmed = 1; }
            rc = AMM_EP_OK;
            goto done;
        }
        if (amm_journal_eth_attempt_settle(j, swap_seq, a.n, AMM_EA_FAILED) != 0) { rc = AMM_EP_ERR; goto done; }
        if (out) out->worked = 1;
        {
            char th[65];
            QGP_LOG_WARN(LOG_TAG, "swap %s: USDT transaction 0x%s failed in block %llu (attempt %d, receipt status %d)",
                         s.id, hash_hex(a.hash, th), (unsigned long long)r->block_number, a.n, r->status);
        }
        say(out, "the payout transaction failed (receipt status is not 1)");
        rc = AMM_EP_FAILED;
        goto done;
    }

    /* no receipt at the quorum: is its nonce used by another transaction? */
    uint64_t confirmed = 0;
    if (qth(p, &rd, R_COUNT_LATEST, &confirmed) != 0) { say(out, "the confirmed nonce is not readable"); rc = AMM_EP_UNKNOWN; goto done; }
    if (confirmed > a.nonce) {
        if (finish_and_move(p, &s, a.n, AMM_EA_ORPHANED, AMM_S_UNKNOWN,
                            "payout transaction orphaned: its nonce was used by another transaction") != 0) {
            rc = AMM_EP_ERR;
            goto done;
        }
        if (out) out->worked = 1;
        {
            char th[65];
            QGP_LOG_WARN(LOG_TAG, "swap %s: USDT transaction 0x%s orphaned: nonce %llu used by another transaction",
                         s.id, hash_hex(a.hash, th), (unsigned long long)a.nonce);
        }
        say(out, "orphaned: the swap is unknown and the bot stops");
        rc = AMM_EP_ORPHANED;
        goto done;
    }
    /* no receipt, the nonce unused: a head whose max fee per gas the latest
     * block's base fee (Q-th largest) has passed cannot be included as it is
     * (a block refuses a max fee per gas below its base fee), and it holds this nonce and every
     * later payout's. Nothing is written; the engine calls amm_eth_pay_replace.
     * A base fee that cannot be read at the quorum replaces nothing now. */
    uint64_t base_now = 0;
    if (qth(p, &rd, R_BASEFEE, &base_now) == 0 && base_now > a.max_fee_per_gas) {
        char th[65];
        QGP_LOG_WARN(LOG_TAG, "swap %s: USDT transaction 0x%s (attempt %d, nonce %llu) cannot be included: "
                     "the base fee %llu is above its max fee per gas %llu",
                     s.id, hash_hex(a.hash, th), a.n, (unsigned long long)a.nonce,
                     (unsigned long long)base_now, (unsigned long long)a.max_fee_per_gas);
        say(out, "stuck: the base fee is above the max fee per gas of the payout transaction");
        rc = AMM_EP_STUCK;
        goto done;
    }
    const int signed_head = !strcmp(a.state, AMM_EA_SIGNED);
    /* a submitted head is sent again only once per new block (the latest block
     * above the tip of its last broadcast); a replaced attempt never */
    if (!signed_head && tip <= a.last_submit_tip) { rc = AMM_EP_OK; goto done; }
    if (p->cfg.payouts_paused) {
        if (signed_head) { say(out, "payouts paused"); rc = AMM_EP_PAUSED; }
        else rc = AMM_EP_OK;
        goto done;
    }

    /* the SAME STORED BYTES to every usable provider: a signed attempt that was
     * never broadcast (or a restart between store and broadcast), or a submitted
     * one again (a node that holds it answers "already known", a node that
     * dropped it takes it back) */
    int accepted = 0;
    for (int i = 0; i < p->cfg.n_providers; i++) {
        if (!rd.use[i]) continue;
        const amm_eth_provider_t *pr = &p->prov[i];
        uint8_t h[32];
        if (pr->send_raw(pr->ctx, a.raw, a.raw_len, h, deadline_ms) == AMM_ETH_OK &&
            !memcmp(h, a.hash, 32)) accepted++;
    }
    char th[65];
    hash_hex(a.hash, th);
    if (!signed_head) {
        /* stays submitted whatever the answers; recorded, so a new broadcast
         * waits for the next block */
        if (amm_journal_eth_attempt_broadcast_tip(j, swap_seq, tip) != 0) { rc = AMM_EP_ERR; goto done; }
        QGP_LOG_INFO(LOG_TAG, "swap %s: USDT transaction 0x%s (attempt %d, nonce %llu) sent again as the "
                     "same bytes: %d providers took it, latest block %llu", s.id, th, a.n,
                     (unsigned long long)a.nonce, accepted, (unsigned long long)tip);
        if (out) out->worked = 1;
        rc = AMM_EP_OK;
        goto done;
    }
    if (accepted == 0) {
        QGP_LOG_WARN(LOG_TAG, "swap %s: USDT transaction 0x%s: no provider took it", s.id, th);
        say(out, "no provider took the transaction");
        rc = AMM_EP_UNKNOWN;
        goto done;
    }
    if (amm_journal_eth_attempt_submitted(j, swap_seq, tip) != 0) { rc = AMM_EP_ERR; goto done; }
    QGP_LOG_INFO(LOG_TAG, "swap %s: USDT transaction 0x%s submitted (attempt %d, nonce %llu, max fee per gas %llu, "
                 "max priority fee per gas %llu, %d providers took it, latest block %llu)",
                 s.id, th, a.n, (unsigned long long)a.nonce, (unsigned long long)a.max_fee_per_gas,
                 (unsigned long long)a.max_priority_fee_per_gas, accepted, (unsigned long long)tip);
    if (out) { out->worked = 1; out->submitted = 1; }
    rc = AMM_EP_OK;
done:
    free(r);
    for (int i = 0; i < ng; i++) amm_eattempt_free(&grp[i]);
    amm_eattempt_free(&head);
    return rc;
}

/* ── re-send of a failed payout (evm-fee plan 6.9) ────────────────────── */

static int resend_locked(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                         amm_ep_step_t *out) {
    amm_journal_t *j = p->cfg.journal;
    amm_swap_t s;
    if (amm_journal_swap_by_seq(j, swap_seq, &s) != 0) { say(out, "no such swap"); return AMM_EP_ERR; }
    if (!owes_usdt(&s)) { say(out, "the swap owes no USDT payout"); return AMM_EP_ERR; }
    amm_eattempt_t head;
    int g = amm_journal_eth_attempt_head(j, swap_seq, &head);
    if (g < 0) return AMM_EP_ERR;
    if (g == 1) { say(out, "the swap has no payout transaction to re-send"); return AMM_EP_ERR; }
    /* only `failed` is re-sent: orphaned and unknown stop the bot, held stays held */
    if (strcmp(head.state, AMM_EA_FAILED) != 0) {
        amm_eattempt_free(&head);
        say(out, "the head attempt did not fail: not re-sent");
        return AMM_EP_ERR;
    }
    if (p->cfg.payouts_paused) { amm_eattempt_free(&head); say(out, "payouts paused"); return AMM_EP_PAUSED; }
    uint8_t recipient[20];
    memcpy(recipient, head.recipient, 20);
    const uint64_t gross = head.net;      /* what the failed attempt carried and did not deliver */
    const int failed_n = head.n;
    amm_eattempt_free(&head);
    amm_eattempt_t at;
    int rc = build_locked(p, recipient, gross, 0, deadline_ms, NULL, &at, out);
    if (rc != AMM_EP_OK) return rc;
    at.swap_seq = swap_seq;
    /* WRITE-AHEAD: stored here, broadcast only by amm_eth_pay_step */
    int jr = amm_journal_eth_attempt_sign(j, &at);
    if (jr != AMM_J_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the re-sent payout was not stored (%d)", jr);
        amm_eattempt_free(&at);
        say(out, "the re-sent payout was not stored");
        return AMM_EP_ERR;
    }
    char th[65];
    QGP_LOG_WARN(LOG_TAG, "swap %s: attempt %d failed; re-sent as attempt %d (nonce %llu, hash 0x%s, gross %llu, "
                 "fee %llu, net %llu)", s.id, failed_n, at.n, (unsigned long long)at.nonce,
                 hash_hex(at.hash, th), (unsigned long long)at.gross, (unsigned long long)at.fee,
                 (unsigned long long)at.net);
    amm_eattempt_free(&at);
    if (out) { out->worked = 1; out->signed_ = 1; }
    return AMM_EP_OK;
}

int amm_eth_pay_resend(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                       amm_ep_step_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); out->swap_seq = swap_seq; }
    if (!p) return AMM_EP_ERR;
    pthread_mutex_lock(&p->mu);
    int rc = resend_locked(p, swap_seq, deadline_ms, out);
    pthread_mutex_unlock(&p->mu);
    return rc;
}

/* ── replacement of a stuck payout (evm-fee plan 6.11) ────────────────── */

static int replace_locked(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                          amm_ep_step_t *out) {
    amm_journal_t *j = p->cfg.journal;
    amm_swap_t s;
    if (amm_journal_swap_by_seq(j, swap_seq, &s) != 0) { say(out, "no such swap"); return AMM_EP_ERR; }
    if (!owes_usdt(&s)) { say(out, "the swap owes no USDT payout"); return AMM_EP_ERR; }
    amm_eattempt_t head, grp[AMM_EA_GROUP_MAX];
    int ng = 0;
    int g = amm_journal_eth_attempt_head(j, swap_seq, &head);
    if (g < 0) return AMM_EP_ERR;
    if (g == 1) { say(out, "the swap has no payout transaction to replace"); return AMM_EP_ERR; }
    int rc = AMM_EP_ERR;
    if (strcmp(head.state, AMM_EA_SIGNED) && strcmp(head.state, AMM_EA_SUBMITTED)) {
        say(out, "the head attempt is not waiting: nothing to replace");
        goto done;
    }
    if (p->cfg.payouts_paused) { say(out, "payouts paused"); rc = AMM_EP_PAUSED; goto done; }
    if (amm_journal_eth_attempt_group(j, swap_seq, grp, AMM_EA_GROUP_MAX, &ng) != 0 || ng < 1) goto done;

    /* the trigger again, with fresh reads (the engine's call may come later in
     * the round): no receipt of any attempt of the nonce, the nonce unused, the
     * base fee above the head's max fee per gas */
    rd_t rd = { .dl = deadline_ms };
    if (qualify(p, &rd) < p->cfg.quorum) { say(out, "providers below the quorum"); rc = AMM_EP_UNKNOWN; goto done; }
    amm_eth_receipt_t *tmp = calloc(1, sizeof(*tmp));
    if (!tmp) goto done;
    int unreadable = 0, found = 0;
    for (int i = 0; i < ng && !unreadable && !found; i++) {
        int dp = 0;
        rr_t ri = read_receipt(p, &rd, grp[i].hash, tmp, &dp);
        if (ri == RR_UNKNOWN) unreadable = 1;
        else if (ri == RR_FOUND) found = 1;
    }
    free(tmp);
    if (unreadable) { say(out, "the receipt is not readable or the providers disagree"); rc = AMM_EP_UNKNOWN; goto done; }
    uint64_t confirmed = 0, base_now = 0;
    if (!found && qth(p, &rd, R_COUNT_LATEST, &confirmed) != 0) {
        say(out, "the confirmed nonce is not readable");
        rc = AMM_EP_UNKNOWN;
        goto done;
    }
    if (found || confirmed > head.nonce || qth(p, &rd, R_BASEFEE, &base_now) != 0 ||
        base_now <= head.max_fee_per_gas) {
        say(out, "the payout is no longer stuck: not replaced");
        rc = AMM_EP_OK;                                 /* nothing written, out->worked stays 0 */
        goto done;
    }

    uint8_t recipient[20];
    memcpy(recipient, head.recipient, 20);
    /* gross unchanged: the replaced attempt can never execute together with
     * its replacement, so only the ceiling of the one that lands is deducted
     * (the extra fee is fee_r - fee_head); minimum 0 */
    amm_eattempt_t at;
    rc = build_locked(p, recipient, head.gross, 0, deadline_ms, &head, &at, out);
    if (rc != AMM_EP_OK) goto done;                     /* ZERO: the old attempt stays */
    at.swap_seq = swap_seq;
    int jr = amm_journal_eth_attempt_replace(j, &at);
    if (jr != AMM_J_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the replacement payout was not stored (%d)", jr);
        amm_eattempt_free(&at);
        say(out, "the replacement payout was not stored");
        rc = AMM_EP_ERR;
        goto done;
    }
    {
        char th[65];
        QGP_LOG_WARN(LOG_TAG, "swap %s: attempt %d (nonce %llu) is stuck at base fee %llu; replaced by attempt %d "
                     "(hash 0x%s): max fee per gas %llu -> %llu, max priority fee per gas %llu -> %llu, "
                     "extra fee %lld", s.id, head.n, (unsigned long long)head.nonce,
                     (unsigned long long)base_now, at.n, hash_hex(at.hash, th),
                     (unsigned long long)head.max_fee_per_gas, (unsigned long long)at.max_fee_per_gas,
                     (unsigned long long)head.max_priority_fee_per_gas,
                     (unsigned long long)at.max_priority_fee_per_gas,
                     (long long)((int64_t)at.fee - (int64_t)head.fee));
    }
    amm_eattempt_free(&at);
    if (out) { out->worked = 1; out->signed_ = 1; }
    rc = AMM_EP_OK;
done:
    for (int i = 0; i < ng; i++) amm_eattempt_free(&grp[i]);
    amm_eattempt_free(&head);
    return rc;
}

int amm_eth_pay_replace(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                        amm_ep_step_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); out->swap_seq = swap_seq; }
    if (!p) return AMM_EP_ERR;
    pthread_mutex_lock(&p->mu);
    int rc = replace_locked(p, swap_seq, deadline_ms, out);
    pthread_mutex_unlock(&p->mu);
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
