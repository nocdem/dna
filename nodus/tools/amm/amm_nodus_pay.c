/**
 * @file amm_nodus_pay.c
 * @brief nodus-amm NODUS payout and refund (see amm_nodus_pay.h). The pattern
 *        is tools/faucet/faucet_core.c (do_plan_and_sign, do_settle), carried
 *        as the bot's own copy over the AMM journal; plan sections 11, 17.
 */
#include "amm_nodus_pay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"
#include "dnac/dnac.h"            /* DNAC_MIN_FEE_RAW */

#define LOG_TAG "AMM_NPAY"

#define FEE_PASSES 8              /* the planner's own bound (nodus_v2_spend.c) */

static const uint8_t NATIVE_TOKEN[64] = {0};

struct amm_nodus_pay {
    amm_nodus_pay_cfg_t cfg;
    amm_node_t          node;
    char                self_hex[129];
    /* Block-walk progress of the settlement scan, kept IN MEMORY across
     * steps so a walk cut by its time budget resumes at its last validated
     * page (faucet core.scan_prog). Keyed by (height, intent id); the single
     * worker thread only. An incomplete walk decides nothing. */
    struct {
        int      valid;
        uint64_t height;
        uint8_t  intent[64];
        uint32_t from;
        int      found;
    } prog;
};

/* ── construction ───────────────────────────────────────────────────── */

amm_nodus_pay_t *amm_nodus_pay_new(const amm_nodus_pay_cfg_t *cfg) {
    if (!cfg || !cfg->node || !cfg->journal || !cfg->pk || !cfg->sk || !cfg->rand)
        return NULL;
    const amm_node_t *n = cfg->node;
    if (!n->chain_id32 || !n->ruleset_info || !n->gas_price || !n->coins ||
        !n->scan_block || !n->submit) return NULL;
    if (cfg->expiry_ahead < 1 || cfg->expiry_ahead > NODUS_CMT_APP_MAX_EXPIRY_AHEAD ||
        cfg->resubmit_blocks == 0 || cfg->scan_blocks == 0) return NULL;
    amm_nodus_pay_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->cfg = *cfg;
    p->node = *cfg->node;
    p->cfg.node = &p->node;
    uint8_t raw[64];
    if (qgp_sha3_512(cfg->pk, 2592, raw) != 0) { free(p); return NULL; }
    qgp_fp_raw_to_hex(raw, p->self_hex);
    return p;
}

void amm_nodus_pay_free(amm_nodus_pay_t *p) { free(p); }

const char *amm_nodus_pay_self(const amm_nodus_pay_t *p) { return p ? p->self_hex : ""; }

amm_np_verdict_t amm_nodus_pay_judge(uint64_t gross, uint64_t fee,
                                     uint64_t minimum, uint64_t *net_out) {
    /* saturating subtraction (THORChain SafeSub, type_convert.go:64-71;
     * givens item 52): never a wrapped value */
    uint64_t net = gross > fee ? gross - fee : 0;
    if (net_out) *net_out = net;
    if (net == 0) return AMM_NP_NOTHING;
    return net < minimum ? AMM_NP_BELOW : AMM_NP_PAY;
}

/* ── planning ───────────────────────────────────────────────────────── */

typedef struct {
    nodus_v2_ruleset_id_t      rs;
    dna_meter_policy_t         policy;
    nodus_v2_coin_t            coins[AMM_COINS_MAX];   /* the spendable set   */
    nodus_v2_coin_t            work[AMM_COINS_MAX];    /* planner sorts here  */
    int                        n_coins;
    int                        truncated;
    uint64_t                   tip;
    uint64_t                   gas_price;
    nodus_v2_spend_plan_t      plan;
    uint64_t                   fee;
    uint64_t                   net;
    nodus_v2_spend_build_req_t breq;
    nodus_v2_spend_built_t     built;
} pctx_t;

static int nul_in(const uint8_t *nul, uint8_t (*set)[64], int n) {
    for (int i = 0; i < n; i++)
        if (!memcmp(nul, set[i], 64)) return 1;
    return 0;
}

/* Read what a plan needs: the chain guard, the tip, the gas price, the
 * rule-set, the bot's own spendable coins. @return AMM_NP_OK / UNKNOWN /
 * UNSUPPORTED (`msg` says which). */
static int prepare(amm_nodus_pay_t *p, pctx_t *b, uint64_t dl, char *msg,
                   size_t cap) {
    uint8_t got[32];
    if (p->node.chain_id32(p->node.ctx, got, dl) != AMM_NODE_OK ||
        memcmp(got, p->cfg.chain_id, 32) != 0) {
        snprintf(msg, cap, "the node's chain id is unreadable or is not the configured one");
        return AMM_NP_UNKNOWN;
    }
    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (p->node.ruleset_info(p->node.ctx, &ri, dl) != AMM_NODE_OK || ri.tip == 0) {
        snprintf(msg, cap, "dnac_ruleset_info is unreadable");
        return AMM_NP_UNKNOWN;
    }
    b->tip = ri.tip;
    /* The price must be REPORTED: a missing or malformed gas_price is not the
     * price 0 ("rule off"); a fee computed from a guess is never paid. A
     * present 0 is a valid price. */
    int gr = p->node.gas_price(p->node.ctx, &b->gas_price, dl);
    if (gr == AMM_NODE_UNREPORTED) {
        snprintf(msg, cap, "the node did not report a gas price");
        return AMM_NP_UNKNOWN;
    }
    if (gr != AMM_NODE_OK) {
        snprintf(msg, cap, "the gas price is unreadable");
        return AMM_NP_UNKNOWN;
    }
    /* the pinned rule-set generation whose tuples EQUAL the node's answer --
     * never by height (fail closed) */
    uint32_t gen = 0;
    for (uint32_t k = 1; k <= nodus_v2_pins_generation_count(); k++) {
        uint32_t sv = 0, cv = 0;
        uint8_t sh[64], ch[64];
        if (nodus_v2_pins_tuples(k, &sv, sh, &cv, ch) != NODUS_V2_SPEND_OK) continue;
        if (sv == ri.sys_version && cv == ri.core_version &&
            !memcmp(sh, ri.sys_hash, 64) && !memcmp(ch, ri.core_hash, 64)) {
            gen = k;
            break;
        }
    }
    if (gen == 0) {
        snprintf(msg, cap, "this build does not carry the node's rule-set generation");
        return AMM_NP_UNSUPPORTED;
    }
    if (gen == 1) {
        snprintf(msg, cap, "rule-set generation 1 is not supported");
        return AMM_NP_UNSUPPORTED;
    }
    if (nodus_v2_ruleset_from_pins_gen(gen, &b->rs, &b->policy) != NODUS_V2_SPEND_OK) {
        snprintf(msg, cap, "the pinned rule-set failed its digest check");
        return AMM_NP_UNSUPPORTED;
    }
    /* the bot's own native coins. INCOMPLETE = the node ignored the token
     * filter (the list holds other tokens): unusable. A listing that merely
     * filled the node's cap is OK + truncated: the node lists the LARGEST
     * coins first, so the plan runs over what it got. */
    amm_coin_list_t *nat = calloc(1, sizeof(*nat));
    if (!nat) { snprintf(msg, cap, "out of memory"); return AMM_NP_ERR; }
    int cr = p->node.coins(p->node.ctx, NATIVE_TOKEN, nat, dl);
    if (cr != AMM_NODE_OK) {
        snprintf(msg, cap, cr == AMM_NODE_INCOMPLETE ? "coin list incomplete"
                                                      : "the native coins are unreadable");
        free(nat);
        return AMM_NP_UNKNOWN;
    }
    b->truncated = nat->truncated;
    b->n_coins = 0;
    for (int i = 0; i < nat->n && b->n_coins < AMM_COINS_MAX; i++) {
        const amm_coin_t *k = &nat->c[i];
        if (k->amount == 0 || k->unlock_block > b->tip) continue;
        nodus_v2_coin_t *o = &b->coins[b->n_coins++];
        memcpy(o->nul, k->nul, 64);
        o->amount = k->amount;
        o->kind = 0;
        o->used = 0;
    }
    free(nat);
    return AMM_NP_OK;
}

static uint64_t fee_floor(void) {
    return DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
}

/* Plan ONE native spend over `coins` that debits exactly `gross`: the
 * recipient gets net = gross - fee (saturating) and the planner's fee is paid
 * on top, so net + fee == gross. The coins picked cover amount + fee ==
 * gross in every pass, so the shape (and the fee) settle at once; the loop
 * is bounded. The dust sweep and change absorption are OFF (coin joining is
 * DEFERRED, plan line 288). On OK b->plan, b->fee, b->net and b->work (the
 * array the plan indexes) are set. @return AMM_NP_OK / ZERO (net 0: b->fee
 * is the fee found, b->net 0) / FUNDS / UNKNOWN. */
static int plan_fixed(pctx_t *b, uint64_t gross, const nodus_v2_coin_t *coins,
                      int n, char *msg, size_t cap) {
    uint64_t fee = fee_floor();
    for (int pass = 0; pass < FEE_PASSES; pass++) {
        uint64_t net = gross > fee ? gross - fee : 0;
        b->fee = fee;
        b->net = net;
        if (net == 0) return AMM_NP_ZERO;
        memcpy(b->work, coins, (size_t)n * sizeof(*coins));
        nodus_v2_spend_plan_req_t preq;
        memset(&preq, 0, sizeof(preq));
        preq.rs            = &b->rs;
        preq.order         = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
        preq.is_native     = 1;
        preq.amount        = net;
        preq.fee           = fee;
        /* FIXED fee: the SDK then never raises the fee under a fixed amount
         * (which would demand amount + the higher fee from the coins and
         * refuse a coin that exactly equals gross); a fee below what the
         * shape needs is refused with the needed fee in `pe.required`
         * (nodus_v2_spend.c:915), and the fee is deducted from gross at THAT
         * fee (givens item 39) */
        preq.fee_fixed     = 1;
        preq.gas_price     = b->gas_price;
        preq.count         = 1;
        preq.no_dust_sweep = 1;
        nodus_v2_spend_plan_t *plans = NULL;
        long pcount = 0;
        uint64_t fee_out = 0;
        nodus_v2_spend_err_t pe;
        memset(&pe, 0, sizeof(pe));
        int prc = nodus_v2_spend_plan(&preq, b->work, n, &plans, &pcount, &fee_out, &pe);
        if (prc == NODUS_V2_SPEND_ERR_INSUFFICIENT || prc == NODUS_V2_SPEND_ERR_NO_COIN_ALL) {
            /* short funding on a listing that filled the node's cap may only
             * be "the coins we did not see": say so, never "funding short" */
            snprintf(msg, cap, b->truncated ? "coin list incomplete"
                                            : "the bot's coins cannot cover the payout");
            return AMM_NP_FUNDS;
        }
        if (prc == NODUS_V2_SPEND_ERR_MAX_INPUTS) {
            snprintf(msg, cap, "the payout would need more than 15 coins; the operator must consolidate");
            return AMM_NP_FUNDS;
        }
        if (prc == NODUS_V2_SPEND_ERR_FEE_BELOW_GAS) {
            if (pe.required <= fee) {        /* the SDK reports what it needs */
                snprintf(msg, cap, "the planner refused the fee without a higher fee needed");
                return AMM_NP_UNKNOWN;
            }
            fee = pe.required;               /* deduct THIS fee from gross: re-plan */
            continue;
        }
        if (prc != NODUS_V2_SPEND_OK || pcount != 1 || !plans || fee_out != fee) {
            free(plans);
            snprintf(msg, cap, "the planner refused the payout (rc %d)", prc);
            return AMM_NP_UNKNOWN;
        }
        b->plan = plans[0];
        free(plans);
        return AMM_NP_OK;
    }
    snprintf(msg, cap, "the fee did not settle");
    return AMM_NP_UNKNOWN;
}

int amm_nodus_pay_quote(amm_nodus_pay_t *p, uint64_t gross, uint64_t deadline_ms,
                        amm_np_quote_t *q) {
    if (!p || !q || gross == 0) return AMM_NP_ERR;
    memset(q, 0, sizeof(*q));
    q->gross = gross;
    pctx_t *b = calloc(1, sizeof(*b));
    if (!b) return AMM_NP_ERR;
    int rc = prepare(p, b, deadline_ms, q->msg, sizeof(q->msg));
    if (rc == AMM_NP_OK) {
        q->tip = b->tip;
        rc = plan_fixed(b, gross, b->coins, b->n_coins, q->msg, sizeof(q->msg));
        q->fee = b->fee;
        q->net = b->net;
        if (rc == AMM_NP_OK) q->n_in = b->plan.n_in;
        if (rc == AMM_NP_ZERO)
            snprintf(q->msg, sizeof(q->msg), "nothing is left after the Nodus fee");
    }
    free(b);
    return rc;
}

/* ── building and storing ───────────────────────────────────────────── */

/* The independent read-back of the BUILT bytes against the payout tuple fixed
 * before the build (faucet verify_built). 0 = matches. */
static int verify_built(const amm_nodus_pay_t *p, const pctx_t *b,
                        const char *dest, uint64_t gross, uint64_t expiry) {
    const nodus_v2_spend_decoded_t *d = &b->built.dec;
    if (d->fee != b->fee) return -1;
    if (d->expiry_height != expiry) return -2;
    if (d->n_recipient_out != 1) return -3;
    if (strcmp(d->out_owner[0], dest) != 0) return -4;
    if (memcmp(d->out_token[0], NATIVE_TOKEN, 64) != 0) return -5;
    if (d->out_amount[0] != b->net) return -6;
    if (d->out_amount[0] > UINT64_MAX - d->fee ||
        d->out_amount[0] + d->fee != gross) return -7;        /* net + fee == gross */
    for (int o = d->n_recipient_out; o < d->n_out; o++)
        if (strcmp(d->out_owner[o], p->self_hex) != 0) return -8;   /* change: ours */
    if (d->n_in != b->plan.n_in) return -9;
    uint8_t planned[AMM_MAX_INPUTS][64];
    for (int i = 0; i < b->plan.n_in && i < AMM_MAX_INPUTS; i++)
        memcpy(planned[i], b->work[b->plan.idx[i]].nul, 64);
    for (int i = 0; i < d->n_in; i++)
        if (!nul_in(d->in_nul[i], planned, b->plan.n_in)) return -10;
    return 0;
}

static void set_msg(amm_np_step_t *out, const char *m) {
    if (out) snprintf(out->msg, sizeof(out->msg), "%s", m);
}

/* Plan, build, sign and store for swap `seq`. `prior` (NULL = the first
 * attempt) is the EXPIRED attempt a replacement follows: it is planned over
 * the prior attempt's own coins first and must share at least one input with
 * it (faucet design 6.4: the original can then never also apply). */
static int sign_impl(amm_nodus_pay_t *p, int64_t seq, uint64_t gross,
                     const amm_attempt_t *prior, uint64_t dl, amm_np_step_t *out) {
    char msg[AMM_MSG_MAX];
    msg[0] = '\0';
    if (out) { memset(out, 0, sizeof(*out)); out->swap_seq = seq; }
    amm_journal_t *j = p->cfg.journal;
    if (gross == 0) return AMM_NP_ERR;

    amm_swap_t s;
    int g = amm_journal_swap_by_seq(j, seq, &s);
    if (g != 0) return AMM_NP_ERR;
    const int is_payout = (s.dir == AMM_USDT_TO_NODUS && !strcmp(s.state, AMM_S_PAYOUT_PENDING));
    const int is_refund = (s.dir == AMM_NODUS_TO_USDT && !strcmp(s.state, AMM_S_REFUND_PENDING));
    if (!is_payout && !is_refund) {
        QGP_LOG_ERROR(LOG_TAG, "swap %s owes no NODUS payout (state %s)", s.id, s.state);
        return AMM_NP_ERR;
    }
    /* the user's own native address (plan line 289): the payout goes to the
     * swap's destination, a refund back to the request's sender */
    const char *dest = is_payout ? s.dest : s.sender;
    const uint64_t minimum = is_payout ? s.minimum : 0;

    if (p->cfg.payouts_paused) {
        set_msg(out, "payouts are paused: nothing is signed or broadcast");
        return AMM_NP_PAUSED;
    }

    pctx_t *b = calloc(1, sizeof(*b));
    if (!b) return AMM_NP_ERR;
    int ret = AMM_NP_ERR;
    int rc = prepare(p, b, dl, msg, sizeof(msg));
    if (rc != AMM_NP_OK) { ret = rc; goto out; }

    /* plan: a replacement tries the expired attempt's own coins first */
    int planned = 0;
    if (prior) {
        nodus_v2_coin_t *rest = calloc((size_t)AMM_COINS_MAX, sizeof(*rest));
        if (!rest) goto out;
        int nr = 0;
        for (int i = 0; i < b->n_coins; i++)
            if (nul_in(b->coins[i].nul, (uint8_t (*)[64])prior->inputs, prior->n_in))
                rest[nr++] = b->coins[i];
        if (nr == 0) {
            free(rest);
            snprintf(msg, sizeof(msg), "the expired attempt's coins are no longer unspent; the operator must check");
            ret = AMM_NP_FUNDS;
            goto out;
        }
        rc = plan_fixed(b, gross, rest, nr, msg, sizeof(msg));
        free(rest);
        if (rc == AMM_NP_OK) planned = 1;
        else if (rc != AMM_NP_FUNDS) { ret = rc; goto zero_or_out; }
    }
    if (!planned) {
        rc = plan_fixed(b, gross, b->coins, b->n_coins, msg, sizeof(msg));
        if (rc != AMM_NP_OK) { ret = rc; goto zero_or_out; }
    }
    if (prior) {
        int shared = 0;
        for (int i = 0; i < b->plan.n_in; i++)
            if (nul_in(b->work[b->plan.idx[i]].nul, (uint8_t (*)[64])prior->inputs, prior->n_in))
                shared = 1;
        if (!shared) {
            snprintf(msg, sizeof(msg), "a replacement would share no input with the expired attempt");
            ret = AMM_NP_FUNDS;
            goto out;
        }
    }

    /* the minimum is compared AFTER the Nodus fee (givens item 51), before
     * anything is built or signed */
    if (amm_nodus_pay_judge(gross, b->fee, minimum, NULL) == AMM_NP_BELOW) {
        snprintf(msg, sizeof(msg), "after the Nodus fee %llu the amount %llu is below the minimum %llu",
                 (unsigned long long)b->fee, (unsigned long long)b->net,
                 (unsigned long long)minimum);
        ret = AMM_NP_BELOW_MIN;
        /* a payout whose amount fell below the signed minimum after a fee
         * rise takes the REFUND path (plan line 226: "Output after the Nodus
         * fee < minimum, or zero: refund"); the edge exists only while no
         * attempt of the swap is signed or submitted, which holds here (none,
         * or the latest expired). The ledger reversal is the engine's. */
        if (is_payout) {
            if (amm_journal_swap_transition(j, seq, AMM_S_REFUND_PENDING, NULL, NULL, msg) != 0) {
                ret = AMM_NP_ERR;
            } else if (out) {
                out->worked = 1;
            }
        }
        goto out;
    }

    {
        uint8_t to_raw[64];
        if (qgp_fp_hex_to_raw(dest, to_raw) != 0) goto out;
        const uint64_t expiry = b->tip + p->cfg.expiry_ahead;
        nodus_v2_spend_build_req_t *q = &b->breq;
        q->rs = &b->rs;
        q->chain32 = p->cfg.chain_id;
        q->tip = b->tip;
        q->expiry_height = expiry;
        q->pk = p->cfg.pk;
        q->sk = p->cfg.sk;
        q->to_fp = to_raw;
        q->token = NULL;                         /* native NODUS (plan line 289) */
        q->amount = b->net;
        q->native_amount = 0;
        q->fee = b->fee;
        q->gas_price = b->gas_price;
        q->coins = b->work;
        q->plan = &b->plan;
        q->rand = p->cfg.rand;
        q->rand_ctx = p->cfg.rand_ctx;
        nodus_v2_spend_err_t be;
        memset(&be, 0, sizeof(be));
        int brc = nodus_v2_spend_build(q, &b->built, &be);
        if (brc != NODUS_V2_SPEND_OK) {
            QGP_LOG_ERROR(LOG_TAG, "swap %s: build refused (rc %d)", s.id, brc);
            snprintf(msg, sizeof(msg), "the payout could not be built (rc %d); nothing was stored", brc);
            ret = AMM_NP_UNKNOWN;
            goto out;
        }
        int vr = verify_built(p, b, dest, gross, expiry);
        if (vr != 0) {
            QGP_LOG_ERROR(LOG_TAG, "swap %s: read-back refused the built payout (%d)", s.id, vr);
            snprintf(msg, sizeof(msg), "the built payout failed the read-back (%d); nothing was stored", vr);
            ret = AMM_NP_UNKNOWN;
            goto out;
        }
        amm_attempt_t a;
        memset(&a, 0, sizeof(a));
        a.swap_seq = seq;
        a.gross = gross; a.fee = b->fee; a.net = b->net;
        snprintf(a.dest, sizeof(a.dest), "%s", dest);
        a.env = b->built.env;                    /* borrowed, freed below */
        a.env_len = b->built.env_len;
        memcpy(a.wire_id, b->built.wire_id, 64);
        memcpy(a.intent_id, b->built.intent_id, 64);
        a.n_in = b->built.dec.n_in;
        for (int i = 0; i < a.n_in; i++) memcpy(a.inputs[i], b->built.dec.in_nul[i], 64);
        a.build_tip = b->tip;
        a.expiry = expiry;
        a.scan_next = b->tip + 1;
        /* WRITE-AHEAD (plan section 17): the signed bytes are in the journal
         * before anything is submitted; if this fails nothing is ever sent */
        int sr = amm_journal_attempt_sign(j, &a);
        if (sr != AMM_J_OK) {
            QGP_LOG_ERROR(LOG_TAG, "swap %s: the signed attempt was not recorded (%d) -- never submitted",
                          s.id, sr);
            snprintf(msg, sizeof(msg), "the signed attempt could not be recorded (%d); nothing was submitted", sr);
            ret = AMM_NP_ERR;
            goto out;
        }
        QGP_LOG_INFO(LOG_TAG, "swap %s signed (attempt %d, gross %llu, fee %llu, net %llu, expiry %llu)",
                     s.id, a.n, (unsigned long long)gross, (unsigned long long)b->fee,
                     (unsigned long long)b->net, (unsigned long long)expiry);
        if (out) { out->worked = 1; out->signed_ = 1; }
        msg[0] = '\0';
        ret = AMM_NP_OK;
        goto out;
    }

zero_or_out:
    if (ret == AMM_NP_ZERO) {
        snprintf(msg, sizeof(msg), "nothing is left after the Nodus fee %llu on %llu",
                 (unsigned long long)b->fee, (unsigned long long)gross);
        if (is_refund) {
            /* a refund that is zero after the fee is DROPPED (not sent, not
             * held), a replacement attempt included (givens items 89, 90) */
            if (amm_journal_swap_transition(j, seq, AMM_S_DROPPED, NULL, NULL, msg) != 0) {
                ret = AMM_NP_ERR;
            } else if (out) {
                out->worked = 1;
            }
        } else if (is_payout) {
            /* a payout that is zero after the fee takes the refund path
             * (plan line 226), as above */
            if (amm_journal_swap_transition(j, seq, AMM_S_REFUND_PENDING, NULL, NULL, msg) != 0) {
                ret = AMM_NP_ERR;
            } else if (out) {
                out->worked = 1;
            }
        }
    }
out:
    if (b) nodus_v2_spend_built_free(&b->built);
    free(b);
    set_msg(out, msg);
    return ret;
}

int amm_nodus_pay_sign(amm_nodus_pay_t *p, int64_t swap_seq, uint64_t gross,
                       uint64_t deadline_ms, amm_np_step_t *out) {
    if (!p) return AMM_NP_ERR;
    amm_attempt_t prev;
    int g = amm_journal_attempt_latest(p->cfg.journal, swap_seq, &prev);
    if (g < 0) return AMM_NP_ERR;
    if (g == 0) {                 /* an attempt exists: only the step replaces */
        amm_attempt_free(&prev);
        QGP_LOG_ERROR(LOG_TAG, "swap seq %lld already has an attempt", (long long)swap_seq);
        return AMM_NP_ERR;
    }
    return sign_impl(p, swap_seq, gross, NULL, deadline_ms, out);
}

/* ── settlement ─────────────────────────────────────────────────────── */

static int finish_confirmed(amm_nodus_pay_t *p, const amm_swap_t *head,
                            uint64_t height) {
    amm_journal_t *j = p->cfg.journal;
    char m[AMM_MSG_MAX];
    snprintf(m, sizeof(m), "%s in block %llu",
             !strcmp(head->state, AMM_S_PAYOUT_PENDING) ? "paid" : "refunded",
             (unsigned long long)height);
    /* the attempt and the swap move together or not at all */
    if (amm_journal_tx_begin(j) != 0) return -1;
    int ok = amm_journal_attempt_finish(j, head->seq, AMM_A_CONFIRMED) == 0 &&
             amm_journal_swap_transition(j, head->seq,
                 !strcmp(head->state, AMM_S_PAYOUT_PENDING) ? AMM_S_PAID : AMM_S_REFUNDED,
                 NULL, NULL, m) == 0;
    if (!ok) { amm_journal_tx_rollback(j); return -1; }
    return amm_journal_tx_commit(j) == 0 ? 0 : -1;
}

int amm_nodus_pay_step(amm_nodus_pay_t *p, uint64_t dl, amm_np_step_t *out) {
    amm_np_step_t local;
    amm_np_step_t *o = out ? out : &local;
    memset(o, 0, sizeof(*o));
    if (!p) return AMM_NP_ERR;
    amm_journal_t *j = p->cfg.journal;

    amm_swap_t head;
    int h = amm_journal_swap_head_payout(j, &head);
    if (h < 0) return AMM_NP_ERR;
    if (h == 1) return AMM_NP_OK;                  /* nothing is owed        */
    o->swap_seq = head.seq;

    amm_attempt_t a;
    int ar = amm_journal_attempt_latest(j, head.seq, &a);
    if (ar < 0) return AMM_NP_ERR;
    if (ar == 1) return AMM_NP_NEED_SIGN;          /* the engine signs first */

    int ret = AMM_NP_ERR;
    if (!strcmp(a.state, AMM_A_CONFIRMED)) {
        /* the attempt and the swap move together, so this cannot be reached
         * by this module: say so and stop */
        QGP_LOG_ERROR(LOG_TAG, "swap %s is still %s with a confirmed attempt", head.id, head.state);
        goto out;
    }
    if (!strcmp(a.state, AMM_A_EXPIRED)) {
        /* a replacement, built from the stored gross */
        ret = sign_impl(p, head.seq, a.gross, &a, dl, o);
        goto out;
    }

    /* signed or submitted: settle */
    uint8_t chain[32];
    if (p->node.chain_id32(p->node.ctx, chain, dl) != AMM_NODE_OK ||
        memcmp(chain, p->cfg.chain_id, 32) != 0) {
        p->prog.valid = 0;               /* a height of another chain is another block */
        set_msg(o, "the node's chain id is unreadable or is not the configured one");
        ret = AMM_NP_UNKNOWN;
        goto out;
    }
    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (p->node.ruleset_info(p->node.ctx, &ri, dl) != AMM_NODE_OK || ri.tip == 0) {
        ret = AMM_NP_UNKNOWN;
        goto out;
    }
    const uint64_t tip = ri.tip;
    const uint64_t last = tip < a.expiry ? tip : a.expiry;
    uint64_t next = a.scan_next;

    /* Only a COMPLETE block scan moves a state. What is not scanned yet is
     * picked up from the stored cursor at the next step. */
    for (uint32_t budget = p->cfg.scan_blocks; next <= last && budget > 0;
         budget--, next++) {
        if (!p->prog.valid || p->prog.height != next ||
            memcmp(p->prog.intent, a.intent_id, 64) != 0) {
            memset(&p->prog, 0, sizeof(p->prog));
            p->prog.valid = 1;
            p->prog.height = next;
            memcpy(p->prog.intent, a.intent_id, 64);
        }
        int sr = p->node.scan_block(p->node.ctx, next, a.intent_id, &p->prog.from,
                                    &p->prog.found, dl);
        const int found = p->prog.found;
        if (sr == AMM_NODE_OK || sr == AMM_NODE_NOT_HELD) p->prog.valid = 0;
        if (sr == AMM_NODE_OK) {
            if (found) {
                if (finish_confirmed(p, &head, next) != 0) goto out;
                QGP_LOG_INFO(LOG_TAG, "swap %s settled in block %llu", head.id,
                             (unsigned long long)next);
                o->worked = 1; o->confirmed = 1;
                ret = AMM_NP_OK;
                goto out;
            }
            if (amm_journal_attempt_scanned(j, head.seq, next + 1) != 0) goto out;
            o->worked = 1;
        } else if (sr == AMM_NODE_NOT_HELD) {
            /* the evidence is gone for good (a pruned block): the result
             * cannot be established -> unknown, which stops new approvals
             * until the operator resolves it (plan line 371) */
            char m[AMM_MSG_MAX];
            snprintf(m, sizeof(m), "block %llu is not held by the node; the payout result cannot be established",
                     (unsigned long long)next);
            QGP_LOG_ERROR(LOG_TAG, "swap %s: %s", head.id, m);
            if (amm_journal_swap_transition(j, head.seq, AMM_S_UNKNOWN, NULL, NULL, m) != 0) goto out;
            set_msg(o, m);
            o->worked = 1;
            ret = AMM_NP_OK;
            goto out;
        } else {
            /* an incomplete read changes no state (plan line 372) */
            QGP_LOG_WARN(LOG_TAG, "swap %s: block %llu could not be read completely",
                         head.id, (unsigned long long)next);
            set_msg(o, "a block could not be read completely; retried at the next step");
            ret = AMM_NP_UNKNOWN;
            goto out;
        }
    }

    if (next > a.expiry && tip > a.expiry) {
        /* every block up to the expiry was scanned and none held the intent:
         * the attempt can never apply; a replacement follows */
        if (amm_journal_attempt_finish(j, head.seq, AMM_A_EXPIRED) != 0) goto out;
        QGP_LOG_INFO(LOG_TAG, "swap %s attempt %d expired", head.id, a.n);
        o->worked = 1; o->expired = 1;
        ret = AMM_NP_OK;
        goto out;
    }

    /* Resubmit the SAME stored bytes (the chain's replay guard makes this
     * safe); the node's answer moves nothing. */
    if (!p->cfg.payouts_paused && tip < a.expiry &&
        (!strcmp(a.state, AMM_A_SIGNED) ||
         tip >= a.last_submit_tip + p->cfg.resubmit_blocks)) {
        char msg[128];
        msg[0] = '\0';
        int sub = p->node.submit(p->node.ctx, a.wire_id, a.env, a.env_len, msg,
                                 sizeof(msg), dl);
        if (sub == -1) {
            QGP_LOG_WARN(LOG_TAG, "swap %s: submit got no answer", head.id);
        } else {
            QGP_LOG_INFO(LOG_TAG, "swap %s submitted (node %s: %s)", head.id,
                         sub == 0 ? "accepted" : "refused", msg);
            if (amm_journal_attempt_submitted(j, head.seq, tip) != 0) goto out;
            o->worked = 1; o->submitted = 1;
        }
    }
    ret = AMM_NP_OK;
out:
    amm_attempt_free(&a);
    return ret;
}
