/**
 * @file faucet_core.c
 * @brief nodus-faucet core (see faucet_core.h). Spec: docs/plans/
 *        2026-10-22-testnet-faucet-design.md section 6 (rev 2).
 */
#include "faucet_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"
#include "dnac/dnac.h"            /* DNAC_MIN_FEE_RAW */
#include "nodus/nodus_v2_spend.h"

#define LOG_TAG "FAUCET"

#define FAUCET_BLOCKS_PER_STEP   64    /* scan bound per worker step        */
#define FAUCET_RESUBMIT_BLOCKS   3     /* resubmit the SAME bytes every 3   */
#define FAUCET_COIN_CAP          (2 * FAUCET_COINS_MAX)

static const uint8_t NATIVE_TOKEN[64] = {0};

/* ── small helpers ──────────────────────────────────────────────────── */

static uint64_t mono_ms(void) { return faucet_now_ms(); }

/* A node call's outcome is only usable while the request's deadline holds. */
static int past_deadline(uint64_t deadline_ms) {
    return deadline_ms != FAUCET_NODE_NO_DEADLINE && mono_ms() >= deadline_ms;
}

static int is_hex_lower(const char *s, size_t n) {
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return 0;
    }
    return 1;
}

static int name_ok(const char *s) {
    size_t n = strlen(s);
    if (n < 3 || n > 36) return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9')))
            return 0;
    return 1;
}

static void ans_set(faucet_answer_t *a, int http, const char *id,
                    const char *state, const char *kind, const char *msg) {
    memset(a, 0, sizeof(*a));
    a->http = http;
    snprintf(a->claim_id, sizeof(a->claim_id), "%s", id ? id : FAUCET_NO_CLAIM_ID);
    snprintf(a->state, sizeof(a->state), "%s", state);
    snprintf(a->kind, sizeof(a->kind), "%s", kind);
    snprintf(a->message, sizeof(a->message), "%s", msg ? msg : "");
}

static void ans_claim(faucet_answer_t *a, const faucet_claim_t *cl,
                      const char *override_msg) {
    ans_set(a, 200, cl->claim_id, cl->state, cl->kind,
            override_msg ? override_msg : cl->message);
}

/* ── init / chain guard ─────────────────────────────────────────────── */

int faucet_core_init(faucet_core_t *c, const faucet_cfg_t *cfg,
                     const faucet_node_t *node, faucet_journal_t *journal,
                     const uint8_t *pk, const uint8_t *sk,
                     nodus_v2_rand_fn rand, void *rand_ctx) {
    if (!c || !cfg || !node || !journal || !pk || !sk || !rand) return -1;
    memset(c, 0, sizeof(*c));
    c->cfg = cfg;
    c->node = node;
    c->journal = journal;
    c->pk = pk;
    c->sk = sk;
    c->rand = rand;
    c->rand_ctx = rand_ctx;
    if (pthread_mutex_init(&c->smu, NULL) != 0) return -1;
    uint8_t raw[64];
    if (qgp_sha3_512(pk, 2592, raw) != 0) return -1;
    qgp_fp_raw_to_hex(raw, c->self_hex);
    atomic_init(&c->chain_ok, 0);
    return 0;
}

int faucet_core_check_chain(faucet_core_t *c) {
    uint8_t got[32];
    int ok = 0;
    if (c->node->chain_id32(c->node->ctx, got, FAUCET_NODE_NO_DEADLINE) ==
            FAUCET_NODE_OK &&
        memcmp(got, c->cfg->chain_id, 32) == 0)
        ok = 1;
    else
        QGP_LOG_ERROR(LOG_TAG, "the node's chain id does not match the "
                      "configured one (or is unreadable) — the faucet stops");
    atomic_store(&c->chain_ok, ok);
    return ok;
}

/* ── decision (design 6.1) ──────────────────────────────────────────── */

int faucet_decide(const faucet_node_t *node, const char *address_hex,
                  uint64_t deadline_ms, faucet_verdict_t *out) {
    if (!node || !address_hex || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->kind = FD_UNREADABLE;
    if (!is_hex_lower(address_hex, 128)) return -1;

    for (int t = 0; t < FAUCET_DECIDE_TRIES; t++) {
        if (past_deadline(deadline_ms)) return 0;     /* out of time         */
        nodus_dnac_name_result_t nr;
        memset(&nr, 0, sizeof(nr));
        if (node->name_of(node->ctx, address_hex, &nr, deadline_ms) != FAUCET_NODE_OK)
            return 0;                         /* an error is never "no name" */
        uint64_t tip = 0, total = 0;
        if (node->balance(node->ctx, address_hex, NATIVE_TOKEN, &tip,
                          &total, deadline_ms) != FAUCET_NODE_OK)
            return 0;                         /* an error is never zero      */
        if (nr.committed_height == 0 || tip == 0 ||
            nr.committed_height != tip)
            continue;                         /* two heights: read again     */
        out->height = tip;
        if (nr.found) {
            nr.name[sizeof(nr.name) - 1] = '\0';
            if (!name_ok(nr.name)) return 0;  /* a malformed answer          */
            snprintf(out->name, sizeof(out->name), "%s", nr.name);
            out->kind = FD_FULL;
        } else if (total == 0) {
            out->kind = FD_START;
        } else {
            out->kind = FD_NOT_EMPTY;
        }
        return 0;
    }
    return 0;                                 /* never agreed: UNREADABLE    */
}

/* ── faucet funds / capacity ────────────────────────────────────────── */

static int read_self_funds(faucet_core_t *c, uint64_t *native, uint64_t *token,
                           uint64_t deadline_ms) {
    uint64_t t1 = 0, t2 = 0;
    if (c->node->balance(c->node->ctx, c->self_hex, NATIVE_TOKEN, &t1,
                         native, deadline_ms) != FAUCET_NODE_OK) return -1;
    if (c->node->balance(c->node->ctx, c->self_hex, c->cfg->token_id, &t2,
                         token, deadline_ms) != FAUCET_NODE_OK) return -1;
    return 0;
}

/* 1 = enough for one payout of `kind` at the fee ceiling, 0 not, -1 unread */
static int funded_for(faucet_core_t *c, int is_full, uint64_t deadline_ms) {
    uint64_t nat = 0, tok = 0;
    if (read_self_funds(c, &nat, &tok, deadline_ms) != 0) return -1;
    const faucet_cfg_t *g = c->cfg;
    uint64_t need = (is_full ? g->full_native : g->start_native) + g->fee_ceiling;
    if (nat < need) return 0;
    if (is_full && tok < g->full_token) return 0;
    return 1;
}

/* ── API ────────────────────────────────────────────────────────────── */

void faucet_api_claim(faucet_core_t *c, const char *address_hex,
                      uint64_t deadline_ms, faucet_answer_t *ans) {
    if (!address_hex || !is_hex_lower(address_hex, 128)) {
        ans_set(ans, 400, NULL, "refused", "none",
                "address must be 128 lowercase hex characters");
        return;
    }
    if (!atomic_load(&c->chain_ok)) {
        ans_set(ans, 503, NULL, "refused", "none",
                "the faucet is stopped: its node's chain is not the configured one");
        return;
    }
    if (past_deadline(deadline_ms)) {
        ans_set(ans, 503, NULL, "refused", "none",
                "the request ran out of time; try again shortly");
        return;
    }
    faucet_verdict_t v;
    if (faucet_decide(c->node, address_hex, deadline_ms, &v) != 0 ||
        v.kind == FD_UNREADABLE) {
        ans_set(ans, 503, NULL, "refused", "none",
                "the node gave no consistent answer; try again shortly");
        return;
    }

    faucet_claim_t latest;
    int lr = faucet_journal_claim_by_address(c->journal, address_hex, &latest);
    if (lr == FJ_BUSY) {
        ans_set(ans, 503, NULL, "refused", "none", "busy, try again");
        return;
    }
    if (lr < 0) {
        ans_set(ans, 503, NULL, "refused", "none", "the faucet journal is unavailable");
        return;
    }
    if (v.kind == FD_NOT_EMPTY) {
        if (lr == 0) ans_claim(ans, &latest, NULL);       /* an earlier claim */
        else ans_set(ans, 200, NULL, "refused", "none",
                     "this address already holds NODUS and owns no name");
        return;
    }
    const int is_full = (v.kind == FD_FULL);
    /* The same decision already journalled: answer it, do not decide twice. */
    if (lr == 0 && !strcmp(latest.kind, is_full ? "full" : "start") &&
        (!is_full || !strcmp(latest.name, v.name))) {
        ans_claim(ans, &latest, NULL);
        return;
    }
    int fr = funded_for(c, is_full, deadline_ms);
    if (fr < 0) {
        ans_set(ans, 503, NULL, "refused", "none",
                "the faucet balance could not be read; try again shortly");
        return;
    }
    if (fr == 0) {
        ans_set(ans, 200, NULL, "refused", "none",
                "the faucet is empty right now");
        return;
    }
    uint8_t rnd[16];
    if (c->rand(c->rand_ctx, rnd, sizeof(rnd)) != 0) {
        ans_set(ans, 503, NULL, "refused", "none", "no randomness available");
        return;
    }
    /* The node reads above may have used the whole request: a claim is not
     * created for a request that has already run out of time. */
    if (past_deadline(deadline_ms)) {
        ans_set(ans, 503, NULL, "refused", "none", "busy, try again");
        return;
    }
    faucet_claim_t cl;
    int rc = faucet_journal_claim_create(c->journal, is_full ? "full" : "start",
                                         address_hex, is_full ? v.name : NULL,
                                         c->cfg->queue_cap, rnd, &cl);
    switch (rc) {
    case FJ_CREATED:
        QGP_LOG_INFO(LOG_TAG, "claim %s created (%s)", cl.claim_id, cl.kind);
        ans_claim(ans, &cl, "queued");
        break;
    case FJ_EXISTS:
        ans_claim(ans, &cl, NULL);
        break;
    case FJ_QUEUE_FULL:
        ans_set(ans, 200, NULL, "refused", "none",
                "the faucet queue is full; try again later");
        break;
    case FJ_STORAGE_FULL:
        ans_set(ans, 503, NULL, "refused", "none",
                "the faucet's claim history is full; waiting for the operator");
        break;
    case FJ_STOPPED:
        ans_set(ans, 503, NULL, "refused", "none",
                "the faucet is stopped until the operator resolves an open claim");
        break;
    case FJ_BUSY:
        ans_set(ans, 503, NULL, "refused", "none", "busy, try again");
        break;
    default:
        ans_set(ans, 503, NULL, "refused", "none", "the faucet journal is unavailable");
        break;
    }
}

void faucet_api_get_claim(faucet_core_t *c, const char *claim_id,
                          faucet_answer_t *ans) {
    if (!claim_id || !is_hex_lower(claim_id, 32)) {
        ans_set(ans, 400, NULL, "refused", "none", "bad claim id");
        return;
    }
    if (!strcmp(claim_id, FAUCET_NO_CLAIM_ID)) {
        ans_set(ans, 200, NULL, "refused", "none", "no claim");
        return;
    }
    faucet_claim_t cl;
    int r = faucet_journal_claim_get(c->journal, claim_id, &cl);
    if (r == FJ_BUSY) ans_set(ans, 503, NULL, "refused", "none", "busy, try again");
    else if (r < 0) ans_set(ans, 503, NULL, "refused", "none", "the faucet journal is unavailable");
    else if (r == 1) ans_set(ans, 404, NULL, "refused", "none", "unknown claim");
    else ans_claim(ans, &cl, NULL);
}

int faucet_api_status(faucet_core_t *c, faucet_status_t *out) {
    memset(out, 0, sizeof(*out));
    faucet_jcounts_t cnt;
    int sf = faucet_journal_storage_full(c->journal);
    if (sf == FJ_BUSY) return FJ_BUSY;
    if (sf < 0) return -1;
    int cr = faucet_journal_counts(c->journal, &cnt);
    if (cr == FJ_BUSY) return FJ_BUSY;
    if (cr != 0) return -1;
    out->paused = cnt.paused > 0;

    /* The funds come from the cache the WORKER keeps: this thread never
     * waits on the node. A cache the worker has not refreshed lately (the
     * node is down, the worker is stuck) is not trusted. */
    uint64_t now = mono_ms();
    uint64_t status_native = 0, status_token = 0;
    int status_valid = 0;
    pthread_mutex_lock(&c->smu);
    if (c->status_valid && now - c->status_at_ms < FAUCET_STATUS_MAX_AGE_MS) {
        status_valid = 1;
        status_native = c->status_native;
        status_token = c->status_token;
    }
    pthread_mutex_unlock(&c->smu);
    const faucet_cfg_t *g = c->cfg;
    if (status_valid) {
        uint64_t f_nat = status_native / (g->full_native + g->fee_ceiling);
        uint64_t f_tok = status_token / g->full_token;
        out->full_left = f_nat < f_tok ? f_nat : f_tok;
        out->start_left = status_native / (g->start_native + g->fee_ceiling);
    }
    const char *msg = "ok";
    if (!atomic_load(&c->chain_ok))
        msg = "stopped: the node's chain is not the configured one";
    else if (cnt.unknown > 0)
        msg = "stopped: an open claim could not be settled; waiting for the operator";
    else if (sf == 1)
        msg = "stopped: the claim history is full";
    else if (!status_valid)
        msg = "the node could not be read";
    else if (cnt.paused > 0)
        msg = "payouts are paused (fee above the ceiling, or funding short)";
    out->open = atomic_load(&c->chain_ok) && cnt.unknown == 0 && sf == 0 &&
                status_valid;
    snprintf(out->message, sizeof(out->message), "%s", msg);
    return 0;
}

void faucet_core_refresh_status(faucet_core_t *c) {
    uint64_t now = mono_ms();
    pthread_mutex_lock(&c->smu);
    int fresh = c->status_valid && now - c->status_at_ms < FAUCET_STATUS_TTL_MS;
    pthread_mutex_unlock(&c->smu);
    if (fresh) return;
    uint64_t nat = 0, tok = 0;
    int ok = read_self_funds(c, &nat, &tok, FAUCET_NODE_NO_DEADLINE) == 0;
    pthread_mutex_lock(&c->smu);
    c->status_valid = ok;
    if (ok) {
        c->status_native = nat;
        c->status_token = tok;
        c->status_at_ms = mono_ms();
    }
    pthread_mutex_unlock(&c->smu);
}

/* ── worker: plan + sign ────────────────────────────────────────────── */

typedef struct {
    nodus_v2_ruleset_id_t    rs;
    dna_meter_policy_t       policy;
    nodus_v2_coin_t          coins[FAUCET_COIN_CAP];
    nodus_v2_coin_t          work[FAUCET_COIN_CAP];   /* planner sorts in place */
    int                      n_coins;
    nodus_v2_spend_build_req_t breq;
    nodus_v2_spend_built_t   built;
    uint8_t                  inputs[FJ_MAX_INPUTS][64];
    int                      n_inputs;
} build_ctx_t;

static void pause_claim(faucet_core_t *c, const faucet_claim_t *cl,
                        const char *msg) {
    if (!strcmp(cl->state, "paused") && !strcmp(cl->message, msg)) return;
    QGP_LOG_WARN(LOG_TAG, "claim %s paused: %s", cl->claim_id, msg);
    if (faucet_journal_set_state(c->journal, cl->seq, "paused", msg) != 0)
        QGP_LOG_ERROR(LOG_TAG, "claim %s: could not record the pause", cl->claim_id);
}

static const char *plan_refusal(int prc, int truncated, char *buf, size_t cap) {
    switch (prc) {
    case NODUS_V2_SPEND_ERR_INSUFFICIENT:
    case NODUS_V2_SPEND_ERR_NO_COIN_ALL:
        /* short funding on a listing that filled the node's cap may only be
         * "the coins we did not see": say so, never "funding short" */
        if (truncated) return "coin list incomplete";
        return "the faucet's funding is short; waiting for funding";
    case NODUS_V2_SPEND_ERR_MAX_INPUTS:
        return "the payout would need more than 15 coins; the operator must consolidate";
    default:
        snprintf(buf, cap, "the planner refused the payout (rc %d)", prc);
        return buf;
    }
}

static int nul_in(const uint8_t *nul, uint8_t (*set)[64], int n) {
    for (int i = 0; i < n; i++)
        if (!memcmp(nul, set[i], 64)) return 1;
    return 0;
}

/* Plan one spend over `coins` (copied into b->work, sorted by the planner).
 * On OK b->inputs/n_inputs hold the chosen nullifiers and *fee_out the fee.
 * @return the planner's rc. */
static int plan_over(faucet_core_t *c, build_ctx_t *b, int is_full,
                     const nodus_v2_coin_t *coins, int n, uint64_t gas_price,
                     nodus_v2_spend_plan_t *plan_out, uint64_t *fee_out) {
    memcpy(b->work, coins, (size_t)n * sizeof(*coins));
    const faucet_cfg_t *g = c->cfg;
    nodus_v2_spend_plan_req_t preq;
    memset(&preq, 0, sizeof(preq));
    preq.rs         = &b->rs;
    preq.order      = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
    preq.is_native  = is_full ? 0 : 1;
    preq.amount     = is_full ? g->full_token : g->start_native;
    preq.native_amount = is_full ? g->full_native : 0;
    preq.fee        = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                    ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    preq.fee_fixed  = 0;
    preq.gas_price  = gas_price;
    preq.count      = 1;
    nodus_v2_spend_plan_t *plans = NULL;
    long pcount = 0;
    nodus_v2_spend_err_t pe;
    memset(&pe, 0, sizeof(pe));
    int prc = nodus_v2_spend_plan(&preq, b->work, n, &plans, &pcount, fee_out, &pe);
    if (prc == NODUS_V2_SPEND_OK && pcount == 1 && plans) {
        *plan_out = plans[0];
        b->n_inputs = plans[0].n_in;
        for (int i = 0; i < plans[0].n_in; i++)
            memcpy(b->inputs[i], b->work[plans[0].idx[i]].nul, 64);
    } else if (prc == NODUS_V2_SPEND_OK) {
        prc = NODUS_V2_SPEND_ERR_ARG;
    }
    free(plans);
    return prc;
}

/* The independent read-back of the BUILT bytes against the payout tuple
 * fixed before the build (design 6.3). 0 = matches. */
static int verify_built(faucet_core_t *c, const build_ctx_t *b, int is_full,
                        const uint8_t to_raw[64], const char *address_hex,
                        uint64_t fee, uint64_t expiry) {
    const nodus_v2_spend_decoded_t *d = &b->built.dec;
    const faucet_cfg_t *g = c->cfg;
    if (d->fee != fee || d->fee > g->fee_ceiling) return -1;
    if (d->expiry_height != expiry) return -2;
    if (d->n_recipient_out != (is_full ? 2 : 1)) return -3;
    if (strcmp(d->out_owner[0], address_hex)) return -4;
    if (memcmp(d->out_token[0], NATIVE_TOKEN, 64)) return -5;
    if (d->out_amount[0] != (is_full ? g->full_native : g->start_native)) return -6;
    if (is_full) {
        if (strcmp(d->out_owner[1], address_hex)) return -7;
        if (memcmp(d->out_token[1], g->token_id, 64)) return -8;
        if (d->out_amount[1] != g->full_token) return -9;
    }
    for (int o = d->n_recipient_out; o < d->n_out; o++)
        if (strcmp(d->out_owner[o], c->self_hex)) return -10;
    if (d->n_in != b->n_inputs) return -11;
    for (int i = 0; i < d->n_in; i++)
        if (!nul_in(d->in_nul[i], (uint8_t (*)[64])b->inputs, b->n_inputs))
            return -12;
    (void)to_raw;
    return 0;
}

static int do_plan_and_sign(faucet_core_t *c, const faucet_claim_t *cl,
                            const faucet_attempt_t *prior) {
    const faucet_cfg_t *g = c->cfg;
    const int is_full = !strcmp(cl->kind, "full");

    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (c->node->ruleset_info(c->node->ctx, &ri, FAUCET_NODE_NO_DEADLINE) != FAUCET_NODE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "claim %s: dnac_ruleset_info unreadable", cl->claim_id);
        return -1;
    }
    const uint64_t tip = ri.tip;
    if (tip == 0) {
        QGP_LOG_ERROR(LOG_TAG, "the node reported tip 0 — refusing to build");
        return -1;
    }
    /* The price must be REPORTED: a missing or malformed gas_price is not
     * the price 0 ("rule off") — paying a fee computed from a guess is
     * never done; the claim waits. A present 0 is a valid price. */
    uint64_t gas_price = 0;
    int gr = c->node->gas_price(c->node->ctx, &gas_price, FAUCET_NODE_NO_DEADLINE);
    if (gr == FAUCET_NODE_UNREPORTED) {
        pause_claim(c, cl, "the node did not report a gas price; waiting");
        return 0;
    }
    if (gr != FAUCET_NODE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "claim %s: gas price unreadable", cl->claim_id);
        return -1;
    }

    build_ctx_t *b = calloc(1, sizeof(*b));
    faucet_coin_list_t *nat = calloc(1, sizeof(*nat));
    faucet_coin_list_t *tok = calloc(1, sizeof(*tok));
    uint8_t (*reserved)[64] = NULL;
    int ret = -1;
    if (!b || !nat || !tok) goto out;

    /* rule-set generation: the pinned one whose tuples EQUAL the node's
     * answer — never by height (fail closed). */
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
        pause_claim(c, cl, "this faucet build does not carry the node's rule-set generation");
        ret = 0;
        goto out;
    }
    if (gen == 1) {
        pause_claim(c, cl, "rule-set generation 1 is not supported by the faucet");
        ret = 0;
        goto out;
    }
    if (nodus_v2_ruleset_from_pins_gen(gen, &b->rs, &b->policy) != NODUS_V2_SPEND_OK) {
        pause_claim(c, cl, "the pinned rule-set failed its digest check");
        ret = 0;
        goto out;
    }

    /* coins of the faucet itself, per token */
    /* FAUCET_NODE_INCOMPLETE = the node ignored the token filter (the list
     * holds other tokens): unusable. A listing that merely filled the node's
     * cap is OK + truncated: the node lists the LARGEST coins first, so the
     * faucet plans over what it got (dust sent to it cannot stop it) and
     * calls the list incomplete only if those coins do not cover the payout
     * (below, at the planner's refusal). */
    int cr = c->node->coins(c->node->ctx, NATIVE_TOKEN, nat, FAUCET_NODE_NO_DEADLINE);
    if (cr == FAUCET_NODE_INCOMPLETE) {
        pause_claim(c, cl, "coin list incomplete");
        ret = 0;
        goto out;
    }
    if (cr != FAUCET_NODE_OK) { QGP_LOG_ERROR(LOG_TAG, "native coins unreadable"); goto out; }
    if (is_full) {
        cr = c->node->coins(c->node->ctx, g->token_id, tok, FAUCET_NODE_NO_DEADLINE);
        if (cr == FAUCET_NODE_INCOMPLETE) {
            pause_claim(c, cl, "coin list incomplete");
            ret = 0;
            goto out;
        }
        if (cr != FAUCET_NODE_OK) { QGP_LOG_ERROR(LOG_TAG, "token coins unreadable"); goto out; }
    }

    const int rcap = FJ_MAX_INPUTS * (g->queue_cap + 1);
    reserved = malloc((size_t)rcap * 64);
    if (!reserved) goto out;
    int nres = faucet_journal_reserved_other(c->journal, cl->seq, reserved, rcap);
    if (nres < 0) { QGP_LOG_ERROR(LOG_TAG, "reservations unreadable"); goto out; }

    /* the spendable coin set: positive, unlocked, not held by another claim */
    for (int pass = 0; pass < (is_full ? 2 : 1); pass++) {
        const faucet_coin_list_t *L = pass == 0 ? nat : tok;
        for (int i = 0; i < L->n; i++) {
            const faucet_coin_t *k = &L->c[i];
            if (k->amount == 0 || k->unlock_block > tip) continue;
            if (nul_in(k->nul, reserved, nres)) continue;
            if (b->n_coins >= FAUCET_COIN_CAP) break;
            nodus_v2_coin_t *o = &b->coins[b->n_coins++];
            memcpy(o->nul, k->nul, 64);
            o->amount = k->amount;
            o->kind = (uint8_t)pass;       /* 0 native, 1 the token */
            o->used = 0;
        }
    }

    /* plan: a replacement tries the expired attempt's own coins first and
     * must in the end share at least one input with it (design 6.4) */
    nodus_v2_spend_plan_t plan;
    uint64_t fee = 0;
    int prc = NODUS_V2_SPEND_ERR_INSUFFICIENT;
    int planned = 0;
    if (prior) {
        nodus_v2_coin_t *rest = calloc((size_t)FAUCET_COIN_CAP, sizeof(*rest));
        if (!rest) goto out;
        int nr = 0;
        for (int i = 0; i < b->n_coins; i++)
            if (nul_in(b->coins[i].nul, (uint8_t (*)[64])prior->inputs, prior->n_in))
                rest[nr++] = b->coins[i];
        if (nr == 0) {
            free(rest);
            pause_claim(c, cl, "the expired attempt's coins are no longer unspent; the operator must check");
            ret = 0;
            goto out;
        }
        prc = plan_over(c, b, is_full, rest, nr, gas_price, &plan, &fee);
        free(rest);
        if (prc == NODUS_V2_SPEND_OK) planned = 1;
        else if (prc != NODUS_V2_SPEND_ERR_INSUFFICIENT &&
                 prc != NODUS_V2_SPEND_ERR_NO_COIN_ALL) goto refused;
    }
    if (!planned) {
        prc = plan_over(c, b, is_full, b->coins, b->n_coins, gas_price, &plan, &fee);
        if (prc != NODUS_V2_SPEND_OK) goto refused;
    }
    if (prior) {
        int shared = 0;
        for (int i = 0; i < b->n_inputs; i++)
            if (nul_in(b->inputs[i], (uint8_t (*)[64])prior->inputs, prior->n_in))
                shared = 1;
        if (!shared) {
            pause_claim(c, cl, "a replacement would share no input with the expired attempt");
            ret = 0;
            goto out;
        }
    }
    /* the fee ceiling is judged BEFORE anything is built or signed */
    if (fee > g->fee_ceiling) {
        char m[FJ_MSG_MAX];
        snprintf(m, sizeof(m), "fee %llu raw is above the ceiling %llu raw; waiting for the operator",
                 (unsigned long long)fee, (unsigned long long)g->fee_ceiling);
        pause_claim(c, cl, m);
        ret = 0;
        goto out;
    }

    /* build + sign (the builder re-checks the tuple before AND after
     * signing); then our own independent read-back */
    uint8_t to_raw[64];
    if (qgp_fp_hex_to_raw(cl->address, to_raw) != 0) goto out;
    const uint64_t expiry = tip + g->expiry_ahead;
    uint8_t chain32[32];
    memcpy(chain32, g->chain_id, 32);
    nodus_v2_spend_build_req_t *q = &b->breq;
    q->rs = &b->rs;
    q->chain32 = chain32;
    q->tip = tip;
    q->expiry_height = expiry;
    q->pk = c->pk;
    q->sk = c->sk;
    q->to_fp = to_raw;
    q->token = is_full ? g->token_id : NULL;
    q->amount = is_full ? g->full_token : g->start_native;
    q->native_amount = is_full ? g->full_native : 0;
    q->fee = fee;
    q->gas_price = gas_price;
    q->coins = b->work;
    q->plan = &plan;
    q->rand = c->rand;
    q->rand_ctx = c->rand_ctx;
    nodus_v2_spend_err_t be;
    memset(&be, 0, sizeof(be));
    int brc = nodus_v2_spend_build(q, &b->built, &be);
    if (brc != NODUS_V2_SPEND_OK) {
        char m[FJ_MSG_MAX];
        QGP_LOG_ERROR(LOG_TAG, "claim %s: build refused (rc %d)", cl->claim_id, brc);
        snprintf(m, sizeof(m), "the payout could not be built (rc %d); nothing was submitted", brc);
        pause_claim(c, cl, m);
        ret = 0;
        goto out;
    }
    int vr = verify_built(c, b, is_full, to_raw, cl->address, fee, expiry);
    if (vr != 0) {
        char m[FJ_MSG_MAX];
        QGP_LOG_ERROR(LOG_TAG, "claim %s: read-back refused the built payout (%d)", cl->claim_id, vr);
        snprintf(m, sizeof(m), "the built payout failed the read-back (%d); nothing was submitted", vr);
        pause_claim(c, cl, m);
        ret = 0;
        goto out;
    }

    faucet_attempt_t a;
    memset(&a, 0, sizeof(a));
    a.env = b->built.env;                       /* borrowed, freed below */
    a.env_len = b->built.env_len;
    memcpy(a.wire_id, b->built.wire_id, 64);
    memcpy(a.intent_id, b->built.intent_id, 64);
    a.n_in = b->built.dec.n_in;
    for (int i = 0; i < a.n_in; i++) memcpy(a.inputs[i], b->built.dec.in_nul[i], 64);
    a.build_tip = tip;
    a.expiry = expiry;
    a.scan_next = tip + 1;
    int sr = faucet_journal_attempt_sign(c->journal, cl->seq, &a);
    if (sr == -3) {
        pause_claim(c, cl, "a coin is reserved by another claim; waiting");
        ret = 0;
    } else if (sr == -4) {
        /* the journal is at its storage ceiling: the replacement was NOT
         * recorded and is not submitted; the claim waits for the operator */
        pause_claim(c, cl, "the claim history is full; replacement signing is paused for the operator");
        ret = 0;
    } else if (sr != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim %s: signed attempt not recorded (%d) — never submitted",
                      cl->claim_id, sr);
        ret = -1;
    } else {
        QGP_LOG_INFO(LOG_TAG, "claim %s signed (attempt %d, fee %llu, expiry %llu)",
                     cl->claim_id, a.n, (unsigned long long)fee,
                     (unsigned long long)expiry);
        ret = 1;
    }
    goto out;
refused: {
        char buf[FJ_MSG_MAX];
        pause_claim(c, cl, plan_refusal(prc,
                                        nat->truncated || (is_full && tok->truncated),
                                        buf, sizeof(buf)));
        ret = 0;
    }
out:
    if (b) nodus_v2_spend_built_free(&b->built);
    free(b);
    free(nat);
    free(tok);
    free(reserved);
    return ret;
}

/* ── worker: submit + settle ────────────────────────────────────────── */

static int do_settle(faucet_core_t *c, const faucet_claim_t *cl) {
    faucet_attempt_t a;
    int ar = faucet_journal_attempt_latest(c->journal, cl->seq, &a);
    if (ar != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim %s (%s) has no readable attempt", cl->claim_id,
                      cl->state);
        return -1;
    }
    int ret = -1;
    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (c->node->ruleset_info(c->node->ctx, &ri, FAUCET_NODE_NO_DEADLINE) != FAUCET_NODE_OK) goto out;
    const uint64_t tip = ri.tip;
    int progressed = 0;
    uint64_t next = a.scan_next;
    uint64_t last = tip < a.expiry ? tip : a.expiry;
    const uint64_t step_start = mono_ms();

    /* Only a COMPLETE block scan moves a state (design 6.4). The step is
     * bounded by block count AND by elapsed time (a slow node must not keep
     * one step — and its claim — busy for minutes); what is not scanned yet
     * is picked up from the stored cursor on the next step. */
    for (int budget = FAUCET_BLOCKS_PER_STEP; next <= last && budget > 0;
         budget--, next++) {
        if (mono_ms() - step_start >= FAUCET_STEP_BUDGET_MS) break;
        /* one block walk has its own time budget inside the adapter and
         * releases the node session between pages; its validated progress
         * for THIS (height, intent) is resumed, never restarted */
        if (!c->scan_prog.valid || c->scan_prog.height != next ||
            memcmp(c->scan_prog.intent, a.intent_id, 64) != 0) {
            memset(&c->scan_prog, 0, sizeof(c->scan_prog));
            c->scan_prog.valid = 1;
            c->scan_prog.height = next;
            memcpy(c->scan_prog.intent, a.intent_id, 64);
        }
        int sr = c->node->scan_block(c->node->ctx, next, a.intent_id,
                                     &c->scan_prog.from, &c->scan_prog.found,
                                     FAUCET_NODE_NO_DEADLINE);
        const int found = c->scan_prog.found;
        if (sr == FAUCET_NODE_OK || sr == FAUCET_NODE_NOT_HELD)
            c->scan_prog.valid = 0;             /* done, or nothing to resume */
        if (sr == FAUCET_NODE_OK) {
            if (found) {
                char m[FJ_MSG_MAX];
                snprintf(m, sizeof(m), "paid in block %llu", (unsigned long long)next);
                if (faucet_journal_finish(c->journal, cl->seq, "confirmed", m) != 0) goto out;
                QGP_LOG_INFO(LOG_TAG, "claim %s confirmed in block %llu",
                             cl->claim_id, (unsigned long long)next);
                ret = 1;
                goto out;
            }
            if (faucet_journal_attempt_scanned(c->journal, cl->seq, next + 1) != 0) goto out;
            progressed = 1;
        } else if (sr == FAUCET_NODE_NOT_HELD) {
            if (!strcmp(cl->state, "unknown")) { ret = 0; goto out; }
            char m[FJ_MSG_MAX];
            snprintf(m, sizeof(m), "block %llu is not held by the node; settlement unknown, waiting for the operator",
                     (unsigned long long)next);
            QGP_LOG_ERROR(LOG_TAG, "claim %s: %s", cl->claim_id, m);
            if (faucet_journal_finish(c->journal, cl->seq, "unknown", m) != 0) goto out;
            ret = 1;
            goto out;
        } else {
            /* ANY incomplete required scan (timeout, a malformed or missing
             * page, an internal error — not only "not held") leaves the
             * settlement evidence unreadable: the claim becomes `unknown`,
             * which stops admission of new claims, and the cursor stays
             * BEFORE this block. `unknown` returns to `submitted` by itself
             * once a later step reads the evidence completely. */
            QGP_LOG_WARN(LOG_TAG, "claim %s: block %llu could not be read completely",
                         cl->claim_id, (unsigned long long)next);
            if (!strcmp(cl->state, "unknown")) { ret = progressed ? 1 : -1; goto out; }
            char m[FJ_MSG_MAX];
            snprintf(m, sizeof(m), "block %llu could not be read completely; settlement unknown until it is readable",
                     (unsigned long long)next);
            if (faucet_journal_finish(c->journal, cl->seq, "unknown", m) != 0) goto out;
            ret = 1;
            goto out;
        }
    }

    if (next > a.expiry && tip > a.expiry) {
        char m[FJ_MSG_MAX];
        snprintf(m, sizeof(m), "not applied by expiry height %llu; a replacement follows",
                 (unsigned long long)a.expiry);
        if (faucet_journal_finish(c->journal, cl->seq, "expired", m) != 0) goto out;
        QGP_LOG_INFO(LOG_TAG, "claim %s attempt %d expired", cl->claim_id, a.n);
        ret = 1;
        goto out;
    }
    if (!strcmp(cl->state, "unknown")) {
        /* the evidence is readable again and shows no terminal fact */
        if (faucet_journal_set_state(c->journal, cl->seq, "submitted", "") != 0) goto out;
        progressed = 1;
    }
    /* Resubmit the SAME stored bytes (the chain's replay guard makes this
     * safe); the node's answer moves nothing. */
    if (tip < a.expiry &&
        (!strcmp(cl->state, "signed") ||
         tip >= a.last_submit_tip + FAUCET_RESUBMIT_BLOCKS)) {
        char msg[128];
        msg[0] = '\0';
        int sub = c->node->submit(c->node->ctx, a.wire_id, a.env, a.env_len,
                                  msg, sizeof(msg), FAUCET_NODE_NO_DEADLINE);
        if (sub == -1) {
            QGP_LOG_WARN(LOG_TAG, "claim %s: submit got no answer", cl->claim_id);
        } else {
            QGP_LOG_INFO(LOG_TAG, "claim %s submitted (node %s: %s)", cl->claim_id,
                         sub == 0 ? "accepted" : "refused", msg);
            if (faucet_journal_attempt_submitted(c->journal, cl->seq, tip) != 0) goto out;
            progressed = 1;
        }
    }
    ret = progressed ? 1 : 0;
out:
    faucet_attempt_free(&a);
    return ret;
}

int faucet_worker_step(faucet_core_t *c) {
    /* every cycle: the chain guard, so the HTTP side stops at once when the
     * node's chain is not the configured one */
    if (!faucet_core_check_chain(c)) {
        c->scan_prog.valid = 0;     /* a height of another chain is another block */
        return 0;
    }
    faucet_core_refresh_status(c);      /* /status answers from this cache */
    faucet_claim_t cl;
    int hr = faucet_journal_head(c->journal, &cl);
    if (hr < 0) return -1;
    if (hr == 1) return 0;

    if (!strcmp(cl.state, "planned") || !strcmp(cl.state, "paused") ||
        !strcmp(cl.state, "expired")) {
        faucet_attempt_t prior;
        int pr = faucet_journal_attempt_latest(c->journal, cl.seq, &prior);
        if (pr < 0) return -1;
        /* a claim that already had an attempt can only be here because that
         * attempt expired: this round is a REPLACEMENT */
        int rc = do_plan_and_sign(c, &cl, pr == 0 ? &prior : NULL);
        if (pr == 0) faucet_attempt_free(&prior);
        return rc;
    }
    if (!strcmp(cl.state, "signed") || !strcmp(cl.state, "submitted") ||
        !strcmp(cl.state, "unknown"))
        return do_settle(c, &cl);
    QGP_LOG_ERROR(LOG_TAG, "claim %s in unexpected state %s", cl.claim_id, cl.state);
    return -1;
}
