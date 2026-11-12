/**
 * @file amm_eth_watch.c
 * @brief nodus-amm Ethereum observation (see amm_eth_watch.h for the rules
 *        and their plan lines).
 */
#include "amm_eth_watch.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_WATCH"

/* Plan section 2 "Pinned": the Transfer topic constant is THORChain
 * bifrost/pkg/chainclients/shared/evm/direct_erc20_transfer.go:18
 * ("0xddf252ad...b3ef"). */
static const uint8_t TRANSFER_TOPIC[32] = {
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68,
    0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef};

/* ERC-20 transfer(address,uint256) selector: THORChain
 * bifrost/pkg/chainclients/shared/evm/direct_erc20_transfer.go:20
 * (`erc20TransferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb}`), checked as in
 * shared/evm/utils.go:31-36 (HasERC20TransferSelector). */
static const uint8_t TRANSFER_SELECTOR[4] = {0xa9, 0x05, 0x9c, 0xbb};

/* Capacity of the buffer of ONE journal query (records returned by one
 * amm_journal_rec_list call: the candidates, the `seen` records, or the
 * records inside the reorganisation window). It is not a global limit on live
 * records: a query that would return more rows fails with an error (the list
 * is never cut) and the step reports AMM_W_ERR; other queries and later steps
 * are unaffected by the count of records outside their own query. */
#define REC_CAP 8192
/* one block: at most every provider's full log list as distinct groups */
#define PLAN_CAP (AMM_ETH_MAX_PROVIDERS * AMM_ETH_LOGS_MAX)

/* The log of a step: one line per condition that keeps the step from
 * progressing, written when it appears or changes, counted while it repeats,
 * and closed by a "resolved" line at the first step that no longer reports
 * it. */
enum { NOTE_PROV, NOTE_TIP, NOTE_SCAN, NOTE_CAND, NOTE_DEPTH, NOTE_N };
static const char *const NOTE_NAME[NOTE_N] = {
    "providers", "latest block", "block scan", "candidates", "payment depth"};

typedef struct {
    char     msg[2048];
    uint32_t rep;    /* later steps that reported the same line            */
    int      hit;    /* reported in the current step                       */
} note_t;

struct amm_eth_watch {
    amm_eth_watch_cfg_t  cfg;
    amm_eth_provider_t   prov[AMM_ETH_MAX_PROVIDERS];
    amm_eth_log_t       *logbuf;   /* n_providers * AMM_ETH_LOGS_MAX        */
    note_t               note[NOTE_N];
    char                 why[768]; /* the reason of the last unknown read   */
};

typedef struct {
    int      use[AMM_ETH_MAX_PROVIDERS];
    uint64_t deadline;
    char    *why;       /* amm_eth_watch_step only (w->why); NULL elsewhere */
    size_t   why_cap;
} step_t;

/* ── log text ─────────────────────────────────────────────────────────── */

static void note_set(amm_eth_watch_t *w, int k, int warn, const char *msg) {
    note_t *n = &w->note[k];
    n->hit = 1;
    if (n->msg[0] && !strcmp(n->msg, msg)) { n->rep++; return; }
    if (n->rep)
        QGP_LOG_INFO(LOG_TAG, "%s: the previous line repeated in %u more steps",
                     NOTE_NAME[k], n->rep);
    if (warn) QGP_LOG_WARN(LOG_TAG, "%s: %s", NOTE_NAME[k], msg);
    else QGP_LOG_INFO(LOG_TAG, "%s: %s", NOTE_NAME[k], msg);
    snprintf(n->msg, sizeof(n->msg), "%s", msg);
    n->rep = 0;
}

/* The end of a step: a condition it did not report is resolved. */
static void notes_close(amm_eth_watch_t *w) {
    for (int k = 0; k < NOTE_N; k++) {
        note_t *n = &w->note[k];
        if (!n->hit && n->msg[0]) {
            QGP_LOG_INFO(LOG_TAG, "%s: resolved (the last line repeated in %u more steps)",
                         NOTE_NAME[k], n->rep);
            n->msg[0] = '\0';
            n->rep = 0;
        }
        n->hit = 0;
    }
}

static void why_set(const step_t *st, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void why_set(const step_t *st, const char *fmt, ...) {
    if (!st->why || st->why_cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(st->why, st->why_cap, fmt, ap);
    va_end(ap);
}

/* A bounded text that is appended to (cut at its end, always terminated). */
typedef struct { char *b; size_t cap, len; } txt_t;

static void txt_add(txt_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void txt_add(txt_t *t, const char *fmt, ...) {
    if (!t || !t->b || t->len + 1 >= t->cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(t->b + t->len, t->cap - t->len, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    size_t room = t->cap - t->len - 1;
    t->len += (size_t)n < room ? (size_t)n : room;
}

/* `n` bytes as hex digits (out holds 2n + 1). */
static const char *hx(const uint8_t *b, int n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
    return out;
}

/* The low 64 bits of a 256-bit big-endian value (the USDT amounts). */
static unsigned long long low64(const uint8_t v[32]) {
    unsigned long long x = 0;
    for (int i = 24; i < 32; i++) x = (x << 8) | v[i];
    return x;
}

/* ── construction ─────────────────────────────────────────────────────── */

amm_eth_watch_t *amm_eth_watch_new(const amm_eth_watch_cfg_t *cfg) {
    if (!cfg || !cfg->providers || !cfg->journal ||
        cfg->n_providers < 1 || cfg->n_providers > AMM_ETH_MAX_PROVIDERS ||
        cfg->quorum < 1 || cfg->quorum > cfg->n_providers ||
        cfg->conf_bound_usdt[0] >= cfg->conf_bound_usdt[1] ||
        cfg->conf_count[0] < 1 || cfg->conf_count[0] > cfg->conf_count[1] ||
        cfg->conf_count[1] > cfg->conf_count[2] ||
        cfg->window_blocks < cfg->conf_count[2] ||   /* the largest count */
        cfg->window_blocks > (uint64_t)INT64_MAX / 2 ||
        cfg->max_scan_blocks < 1 || cfg->chain_id < 1)
        return NULL;
    for (int i = 0; i < cfg->n_providers; i++) {
        const amm_eth_provider_t *p = &cfg->providers[i];
        if (!p->chain_id || !p->block_number || !p->get_block || !p->get_logs ||
            !p->get_tx || !p->get_receipt) return NULL;
    }
    amm_eth_watch_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cfg = *cfg;
    for (int i = 0; i < cfg->n_providers; i++) w->prov[i] = cfg->providers[i];
    w->cfg.providers = w->prov;
    w->logbuf = calloc((size_t)cfg->n_providers * AMM_ETH_LOGS_MAX,
                       sizeof(amm_eth_log_t));
    if (!w->logbuf) { free(w); return NULL; }
    return w;
}

void amm_eth_watch_free(amm_eth_watch_t *w) {
    if (!w) return;
    free(w->logbuf);
    free(w);
}

/* 1 when the 256-bit big-endian `v` is <= `bound`. */
static int value_le(const uint8_t v[32], uint64_t bound) {
    for (int i = 0; i < 24; i++)
        if (v[i] != 0) return 0;
    uint64_t x = 0;
    for (int i = 24; i < 32; i++) x = (x << 8) | v[i];
    return x <= bound;
}

uint64_t amm_eth_watch_confirmations(const amm_eth_watch_t *w,
                                     const uint8_t value_be[32]) {
    if (value_le(value_be, w->cfg.conf_bound_usdt[0])) return w->cfg.conf_count[0];
    if (value_le(value_be, w->cfg.conf_bound_usdt[1])) return w->cfg.conf_count[1];
    return w->cfg.conf_count[2];
}

/* ── quorum primitives ────────────────────────────────────────────────── */

static int cmp_u64_desc(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) - (x > y);
}

/* Providers used this step: the configured chain id only (setting
 * eth_chain_id, givens item 77). @return the number used. */
static int qualify(amm_eth_watch_t *w, step_t *st) {
    int n = 0;
    char buf[256] = "";
    txt_t t = { buf, sizeof(buf), 0 };
    for (int i = 0; i < w->cfg.n_providers; i++) {
        uint64_t id = 0;
        const amm_eth_provider_t *p = &w->prov[i];
        int r = p->chain_id(p->ctx, &id, st->deadline);
        st->use[i] = (r == AMM_ETH_OK && id == w->cfg.chain_id);
        if (r != AMM_ETH_OK) txt_add(&t, " provider %d gave no chain id (%d);", i, r);
        else if (!st->use[i]) txt_add(&t, " provider %d is on chain %llu;", i, (unsigned long long)id);
        n += st->use[i];
    }
    if (t.len) why_set(st, "%d of %d providers usable:%s", n, w->cfg.n_providers, buf);
    return n;
}

/* The Q-th largest latest block over the usable providers. @return 0 /
 * 1 (fewer than Q reported). */
static int quorum_tip(amm_eth_watch_t *w, const step_t *st, uint64_t *out) {
    uint64_t tips[AMM_ETH_MAX_PROVIDERS];
    int n = 0;
    for (int i = 0; i < w->cfg.n_providers; i++) {
        uint64_t t = 0;
        if (!st->use[i]) continue;
        const amm_eth_provider_t *p = &w->prov[i];
        if (p->block_number(p->ctx, &t, st->deadline) == AMM_ETH_OK) tips[n++] = t;
    }
    if (n < w->cfg.quorum) {
        why_set(st, "%d usable providers reported their latest block, %d needed", n, w->cfg.quorum);
        return 1;
    }
    qsort(tips, (size_t)n, sizeof(tips[0]), cmp_u64_desc);
    *out = tips[w->cfg.quorum - 1];
    return 0;
}

static int blk_eq(const amm_eth_block_t *a, const amm_eth_block_t *b) {
    return a->number == b->number && a->timestamp == b->timestamp &&
           !memcmp(a->hash, b->hash, 32) && !memcmp(a->parent, b->parent, 32);
}

/* The header at height h that at least Q usable providers return identically,
 * when no other header also reaches Q. @return 0 / 1 (unknown). */
/* The answers behind a header without quorum, for the log. */
static void why_block(amm_eth_watch_t *w, const step_t *st, uint64_t h, const char *what,
                      const amm_eth_block_t *b, const int *bi, int n) {
    if (!st->why) return;
    char buf[512] = "";
    txt_t t = { buf, sizeof(buf), 0 };
    for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i]) continue;
        int k = -1;
        for (int j = 0; j < n; j++) if (bi[j] == i) k = j;
        char hh[9];
        if (k < 0) txt_add(&t, " provider %d: no header;", i);
        else txt_add(&t, " provider %d: %s at %llu;", i, hx(b[k].hash, 4, hh),
                     (unsigned long long)b[k].timestamp);
    }
    why_set(st, "block %llu: %s:%s", (unsigned long long)h, what, buf);
}

/* How a usable provider's header read at h compares with the quorum header
 * (`agree[i]`, 0 for an unusable provider and for all when the result is 1):
 * the logs of the block are asked of every usable provider in index order,
 * the AGREE_NO_HEADER ones included (their header read failed, so their logs
 * may still be those of the quorum block, log_ok checks the block hash); the
 * AGREE_OTHER ones (another header at h) are never asked. */
#define AGREE_QUORUM    1
#define AGREE_NO_HEADER 2
#define AGREE_OTHER     3
static int quorum_block(amm_eth_watch_t *w, const step_t *st, uint64_t h,
                        amm_eth_block_t *out, int agree[AMM_ETH_MAX_PROVIDERS]) {
    amm_eth_block_t b[AMM_ETH_MAX_PROVIDERS];
    int bi[AMM_ETH_MAX_PROVIDERS];
    int n = 0;
    memset(agree, 0, sizeof(int) * AMM_ETH_MAX_PROVIDERS);
    for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i]) continue;
        const amm_eth_provider_t *p = &w->prov[i];
        amm_eth_block_t t;
        if (p->get_block(p->ctx, h, &t, st->deadline) == AMM_ETH_OK &&
            t.number == h) { bi[n] = i; b[n++] = t; }
    }
    int found = -1;
    for (int i = 0; i < n; i++) {
        int c = 0;
        for (int k = 0; k < n; k++) c += blk_eq(&b[i], &b[k]);
        if (c >= w->cfg.quorum) {
            if (found < 0) found = i;
            else if (!blk_eq(&b[found], &b[i])) {               /* ambiguous  */
                why_block(w, st, h, "two different headers at the quorum", b, bi, n);
                return 1;
            }
        }
    }
    if (found < 0) {
        why_block(w, st, h, "no header at the quorum", b, bi, n);
        return 1;
    }
    *out = b[found];
    /* every usable provider is classified: it returned the quorum header, it
     * returned another one, or its header read failed */
    for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i]) continue;
        agree[i] = AGREE_NO_HEADER;
        for (int j = 0; j < n; j++)
            if (bi[j] == i) agree[i] = blk_eq(&b[j], &b[found]) ? AGREE_QUORUM : AGREE_OTHER;
    }
    return 0;
}

/* ── log groups ───────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  tx[32];
    uint32_t log_index;
    uint8_t  from[20];
    uint8_t  to[20];
    uint8_t  value[32];
    int      prov;
} ent_t;

static int ent_cmp(const void *pa, const void *pb) {
    const ent_t *a = pa, *b = pb;
    int c;
    if ((c = memcmp(a->tx, b->tx, 32))) return c;
    if (a->log_index != b->log_index) return a->log_index < b->log_index ? -1 : 1;
    if ((c = memcmp(a->from, b->from, 20))) return c;
    if ((c = memcmp(a->to, b->to, 20))) return c;
    if ((c = memcmp(a->value, b->value, 32))) return c;
    return (a->prov > b->prov) - (a->prov < b->prov);
}

static int ent_same_key(const ent_t *a, const ent_t *b) {
    return !memcmp(a->tx, b->tx, 32) && a->log_index == b->log_index &&
           !memcmp(a->from, b->from, 20) && !memcmp(a->to, b->to, 20) &&
           !memcmp(a->value, b->value, 32);
}

static int value_zero(const uint8_t v[32]) {
    for (int i = 0; i < 32; i++) if (v[i]) return 0;
    return 1;
}

/* A log is considered only when it passes every local check (amm_eth_watch.h
 * step 5). */
static int log_ok(const amm_eth_watch_t *w, const amm_eth_log_t *l,
                  const amm_eth_block_t *qb, ent_t *e) {
    if (memcmp(l->address, w->cfg.usdt, 20) != 0) return 0;
    if (l->n_topics != 3 || memcmp(l->topics[0], TRANSFER_TOPIC, 32) != 0) return 0;
    if (l->data_len != 32) return 0;
    if (l->block_number != qb->number || memcmp(l->block_hash, qb->hash, 32) != 0)
        return 0;
    /* the address of an indexed topic is its last 20 bytes (THORChain
     * BytesToAddress, direct_erc20_transfer.go:111-115) */
    if (memcmp(l->topics[2] + 12, w->cfg.foundation, 20) != 0) return 0;
    if (value_zero(l->data)) return 0;
    memcpy(e->tx, l->tx, 32);
    e->log_index = l->log_index;
    memcpy(e->from, l->topics[1] + 12, 20);
    memcpy(e->to, l->topics[2] + 12, 20);
    memcpy(e->value, l->data, 32);
    return 1;
}

/* ── record plans ─────────────────────────────────────────────────────── */

typedef struct {
    amm_rec_t *put;      int n_put;     /* state candidate or seen            */
    amm_rec_t *drop;     int n_drop;    /* candidates to drop                 */
} plan_t;

static int plan_alloc(plan_t *p) {
    memset(p, 0, sizeof(*p));
    p->put = calloc(PLAN_CAP, sizeof(amm_rec_t));
    p->drop = calloc(PLAN_CAP, sizeof(amm_rec_t));
    if (!p->put || !p->drop) { free(p->put); free(p->drop); memset(p, 0, sizeof(*p)); return -1; }
    return 0;
}

static void plan_free(plan_t *p) { free(p->put); free(p->drop); }

typedef enum { V_VALID, V_INVALID, V_UNKNOWN } verdict_t;

/* Per-provider verification of a quorum record (amm_eth_watch.h step 6). */
static verdict_t verify_record(amm_eth_watch_t *w, const step_t *st,
                               const amm_eth_block_t *qb, const ent_t *e) {
    int valid = 0, invalid = 0;
    for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i]) continue;
        const amm_eth_provider_t *p = &w->prov[i];
        amm_eth_tx_t tx;
        amm_eth_receipt_t rc;
        if (p->get_tx(p->ctx, e->tx, &tx, st->deadline) != AMM_ETH_OK) continue;
        if (p->get_receipt(p->ctx, e->tx, &rc, st->deadline) != AMM_ETH_OK) continue;
        if (rc.status == 1 && rc.block_number == qb->number &&
            !memcmp(rc.block_hash, qb->hash, 32) && tx.has_to &&
            !memcmp(tx.to, w->cfg.usdt, 20) && !memcmp(tx.from, e->from, 20) &&
            tx.input_len >= 4 && !memcmp(tx.input_head, TRANSFER_SELECTOR, 4))
            valid++;
        else
            invalid++;
    }
    if (valid >= w->cfg.quorum && invalid < w->cfg.quorum) return V_VALID;
    if (invalid >= w->cfg.quorum && valid < w->cfg.quorum) return V_INVALID;
    char th[65];
    why_set(st, "block %llu: payment %s: its transaction and receipt are valid at %d "
            "providers and not at %d, %d needed", (unsigned long long)qb->number,
            hx(e->tx, 32, th), valid, invalid, w->cfg.quorum);
    return V_UNKNOWN;
}

static void rec_from_ent(amm_rec_t *r, const ent_t *e, const amm_eth_block_t *qb,
                         const char *state) {
    memset(r, 0, sizeof(*r));
    memcpy(r->tx, e->tx, 32);
    r->log_index = e->log_index;
    r->block_number = qb->number;
    memcpy(r->block_hash, qb->hash, 32);
    r->block_ts = qb->timestamp;
    memcpy(r->from, e->from, 20);
    memcpy(r->to, e->to, 20);
    memcpy(r->value, e->value, 32);
    snprintf(r->state, sizeof(r->state), "%s", state);
}

/* Read the logs of accepted block `qb` from every usable provider and build
 * the plan: quorum records (verified) as seen, below-quorum groups as
 * candidates, and the existing candidates of this block that at least Q
 * providers now answer without as drops. @return 0 / 1 (unknown: nothing to
 * apply) / -1 (out of memory or plan overflow). */
/* The logs of block `qb` of every usable provider that answered, locally
 * checked (log_ok) and flattened. `ans[i]` marks the providers that answered.
 * @return the number of entries, -1 on memory failure (`*ents_out` heap, the
 * caller frees it). */
static int gather_logs(amm_eth_watch_t *w, const step_t *st,
                       const amm_eth_block_t *qb, const int *agree, ent_t **ents_out,
                       int ans[AMM_ETH_MAX_PROVIDERS], int *answered_out) {
    ent_t *ents = calloc((size_t)w->cfg.n_providers * AMM_ETH_LOGS_MAX, sizeof(ent_t));
    if (!ents) return -1;
    int n_ent = 0, answered = 0;
    int asked[AMM_ETH_MAX_PROVIDERS];
    memset(ans, 0, sizeof(int) * AMM_ETH_MAX_PROVIDERS);
    memset(asked, 0, sizeof(asked));
    /* The parent's single loop in provider index order, no early stop: every
     * usable provider is asked except those that returned ANOTHER header at this
     * height, so no verdict differs from the parent's because a provider able
     * to answer was skipped. */
    {
      for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i] || agree[i] == AGREE_OTHER) continue;
        asked[i] = 1;
        const amm_eth_provider_t *p = &w->prov[i];
        amm_eth_log_t *buf = w->logbuf + (size_t)i * AMM_ETH_LOGS_MAX;
        int n = 0;
        if (p->get_logs(p->ctx, qb->number, w->cfg.usdt, TRANSFER_TOPIC,
                        w->cfg.foundation, buf, AMM_ETH_LOGS_MAX, &n,
                        st->deadline) != AMM_ETH_OK ||
            n < 0 || n > AMM_ETH_LOGS_MAX) continue;
        ans[i] = 1;
        answered++;
        for (int k = 0; k < n; k++) {
            ent_t e;
            memset(&e, 0, sizeof(e));
            if (!log_ok(w, &buf[k], qb, &e)) continue;
            e.prov = i;
            ents[n_ent++] = e;
        }
      }
    }
    /* one line naming the providers not asked for this block's logs, and why
     * (instead of their errors) */
    char skipped[160] = "";
    txt_t t = { skipped, sizeof(skipped), 0 };
    for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i] || asked[i]) continue;
        txt_add(&t, " provider-%d (a different header at that height);", i + 1);
    }
    if (t.len)
        QGP_LOG_INFO(LOG_TAG, "block %llu: not asked for its logs:%s %d of the asked "
                     "providers answered", (unsigned long long)qb->number, skipped, answered);
    qsort(ents, (size_t)n_ent, sizeof(ents[0]), ent_cmp);
    *ents_out = ents;
    *answered_out = answered;
    return n_ent;
}

static int eval_block(amm_eth_watch_t *w, const step_t *st,
                      const amm_eth_block_t *qb, const int *agree, const amm_rec_t *cands,
                      int n_cands, plan_t *plan) {
    ent_t *ents = NULL;
    int ans[AMM_ETH_MAX_PROVIDERS], answered = 0;
    int n_ent = gather_logs(w, st, qb, agree, &ents, ans, &answered);
    if (n_ent < 0) return -1;
    int ret = 1;
    if (answered < w->cfg.quorum) {               /* unknown                  */
        why_set(st, "block %llu: %d usable providers listed its logs, %d needed",
                (unsigned long long)qb->number, answered, w->cfg.quorum);
        goto out;
    }
    /* groups of identical entries; distinct providers per group */
    for (int a = 0; a < n_ent;) {
        int b = a, distinct = 0, last_prov = -1;
        while (b < n_ent && ent_same_key(&ents[a], &ents[b])) {
            if (ents[b].prov != last_prov) { distinct++; last_prov = ents[b].prov; }
            b++;
        }
        if (distinct >= w->cfg.quorum) {
            verdict_t v = verify_record(w, st, qb, &ents[a]);
            if (v == V_UNKNOWN) goto out;
            if (v == V_VALID) {
                if (plan->n_put >= PLAN_CAP) { ret = -1; goto out; }
                rec_from_ent(&plan->put[plan->n_put++], &ents[a], qb, AMM_R_SEEN);
            }
        } else {
            if (plan->n_put >= PLAN_CAP) { ret = -1; goto out; }
            rec_from_ent(&plan->put[plan->n_put++], &ents[a], qb, AMM_R_CANDIDATE);
        }
        a = b;
    }
    /* existing candidates answered without by at least Q providers */
    for (int c = 0; c < n_cands; c++) {
        if (cands[c].block_number != qb->number) continue;
        int absent = 0;
        for (int i = 0; i < w->cfg.n_providers; i++) {
            if (!ans[i]) continue;
            int has = 0;
            for (int a = 0; a < n_ent; a++) {
                if (ents[a].prov == i && !memcmp(ents[a].tx, cands[c].tx, 32) &&
                    ents[a].log_index == cands[c].log_index &&
                    !memcmp(ents[a].from, cands[c].from, 20) &&
                    !memcmp(ents[a].value, cands[c].value, 32)) { has = 1; break; }
            }
            if (!has) absent++;
        }
        if (absent >= w->cfg.quorum) {
            if (plan->n_drop >= PLAN_CAP) { ret = -1; goto out; }
            plan->drop[plan->n_drop++] = cands[c];
        }
    }
    ret = 0;
out:
    free(ents);
    return ret;
}

typedef enum { F_FOUND, F_GONE, F_UNKNOWN } find_t;

/* The quorum log of transaction `tx` in accepted block `qb` (a transaction
 * that moved to another block after a reorganisation): its ACTUAL logged
 * sender, recipient, value and log index in that block, verified as in
 * eval_block. F_GONE: at least Q providers answered and the transaction has
 * no valid payment log there (or the quorum says it is not a valid direct
 * transfer); F_UNKNOWN: no decision. `*err` = 1 on memory failure. */
static find_t find_tx_record(amm_eth_watch_t *w, const step_t *st,
                             const amm_eth_block_t *qb, const int *agree,
                             const uint8_t tx[32], amm_rec_t *out, int *err) {
    ent_t *ents = NULL;
    int ans[AMM_ETH_MAX_PROVIDERS], answered = 0;
    *err = 0;
    int n_ent = gather_logs(w, st, qb, agree, &ents, ans, &answered);
    if (n_ent < 0) { *err = 1; return F_UNKNOWN; }
    find_t res = F_UNKNOWN;
    if (answered < w->cfg.quorum) goto out;
    int groups_at_q = 0, any_listing = 0, first = -1;
    for (int a = 0; a < n_ent;) {
        int b = a, distinct = 0, last_prov = -1;
        while (b < n_ent && ent_same_key(&ents[a], &ents[b])) {
            if (ents[b].prov != last_prov) { distinct++; last_prov = ents[b].prov; }
            b++;
        }
        if (!memcmp(ents[a].tx, tx, 32)) {
            any_listing = 1;
            if (distinct >= w->cfg.quorum) { groups_at_q++; if (first < 0) first = a; }
        }
        a = b;
    }
    if (groups_at_q > 1) goto out;                 /* ambiguous: unknown     */
    if (groups_at_q == 1) {
        verdict_t v = verify_record(w, st, qb, &ents[first]);
        if (v == V_VALID) {
            rec_from_ent(out, &ents[first], qb, AMM_R_SEEN);
            res = F_FOUND;
        } else if (v == V_INVALID) {
            res = F_GONE;
        }
        goto out;
    }
    /* no quorum log for the transaction: gone only when at least Q providers
     * answered and list nothing for it at all; a below-quorum listing leaves
     * the question open */
    if (!any_listing) {
        res = F_GONE;                              /* answered >= Q, none list */
    }
out:
    free(ents);
    return res;
}

/* Walk to `seen` through the legal record states. */
static int rec_set_seen(amm_journal_t *j, amm_rec_t *r, const char *cur_state) {
    if (!strcmp(cur_state, AMM_R_HELD)) {
        snprintf(r->state, sizeof(r->state), "%s", AMM_R_DEEP);
        if (amm_journal_rec_put(j, r) != AMM_J_OK) return -1;
    }
    snprintf(r->state, sizeof(r->state), "%s", AMM_R_SEEN);
    return amm_journal_rec_put(j, r) == AMM_J_OK ? 0 : -1;
}

/* Apply a plan inside a journal transaction. `new_seen` counts records that
 * became seen. @return 0 / -1. */
/* rec_put where a refusal (AMM_J_ILLEGAL: the one-live-record-per-transaction
 * rule or a record state that does not allow it) is a skip, not a fault.
 * @return 0 stored / 1 skipped / -1 fault. */
static int put_rec(amm_journal_t *j, const amm_rec_t *r) {
    int rc = amm_journal_rec_put(j, r);
    if (rc == AMM_J_OK) return 0;
    if (rc == AMM_J_ILLEGAL) return 1;
    return -1;
}

/* The payment of live record `cur` is, at the quorum, now in another block
 * and `nw` is its quorum record there (ACTUAL sender, recipient, value, log
 * index). Same sender and value: the record follows the transaction (in
 * place when the log index is unchanged; otherwise the old row is dropped and
 * a new row is stored -- the marker key is the transaction hash, so the swap
 * link survives). A changed value or sender: the payment as recorded is gone
 * (amm_journal_payment_gone: unpaid again, or a confirmed reversal of a
 * counted payment) and the new record, which matches no approval at the old
 * amount (plan lines 225, 251: a logged value other than the approved one is
 * held), is stored as seen. @return 0 / -1. */
static int rec_follow(amm_journal_t *j, const amm_rec_t *cur,
                      const amm_rec_t *nw, amm_eth_step_t *out) {
    int same_pay = !memcmp(cur->value, nw->value, 32) &&
                   !memcmp(cur->from, nw->from, 20) &&
                   !memcmp(cur->to, nw->to, 20);
    if (same_pay && cur->log_index == nw->log_index) {
        amm_rec_t r = *nw;
        return rec_set_seen(j, &r, cur->state);
    }
    if (same_pay) {
        amm_rec_t d = *cur;
        snprintf(d.state, sizeof(d.state), "%s", AMM_R_DROPPED);
        if (amm_journal_rec_put(j, &d) != AMM_J_OK) return -1;
    } else {
        amm_gone_t g;
        if (amm_journal_payment_gone(j, cur->tx, cur->log_index, &g) != AMM_J_OK)
            return -1;
        if (g == AMM_GONE_REVERSED) out->reversed++;
        else out->dropped++;
    }
    return put_rec(j, nw) < 0 ? -1 : 0;
}

/* A payment record stored seen (written inside the journal transaction; a
 * rolled-back transaction is written again by the next step). */
static void log_seen(const amm_rec_t *r) {
    char th[65], fh[41];
    QGP_LOG_INFO(LOG_TAG, "payment %s (log %u) of %llu USDT units from 0x%s seen in block %llu",
                 hx(r->tx, 32, th), r->log_index, low64(r->value), hx(r->from, 20, fh),
                 (unsigned long long)r->block_number);
}

static int apply_plan(amm_journal_t *j, const plan_t *plan, int *new_seen,
                      int *dropped, amm_eth_step_t *out) {
    /* quorum records first, then candidates: a below-quorum record of a
     * transaction must never keep a quorum record of the same transaction
     * out (the journal displaces candidates for a seen record, and refuses a
     * candidate beside a live record) */
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < plan->n_put; i++) {
            amm_rec_t r = plan->put[i], cur;
            int want_seen = !strcmp(r.state, AMM_R_SEEN);
            if (want_seen != (pass == 0)) continue;
            int g = amm_journal_rec_get(j, r.tx, r.log_index, &cur);
            if (g < 0) return -1;
            if (g == 1) {
                int pr = put_rec(j, &r);
                if (pr < 0) return -1;
                if (pr == 0 && want_seen) { (*new_seen)++; log_seen(&r); }
                continue;
            }
            if (!strcmp(cur.state, AMM_R_REVERSED)) continue;   /* terminal */
            if (!want_seen) {
                /* an existing candidate is refreshed, a dropped one revived
                 * (the journal enforces one live record per transaction) */
                if (!strcmp(cur.state, AMM_R_CANDIDATE) ||
                    !strcmp(cur.state, AMM_R_DROPPED)) {
                    if (put_rec(j, &r) < 0) return -1;
                }
                continue;
            }
            if (!strcmp(cur.state, AMM_R_SEEN) || !strcmp(cur.state, AMM_R_DEEP) ||
                !strcmp(cur.state, AMM_R_HELD)) {
                if (cur.block_number == r.block_number &&
                    !memcmp(cur.block_hash, r.block_hash, 32) &&
                    !memcmp(cur.value, r.value, 32)) continue;      /* kept */
                if (rec_follow(j, &cur, &r, out) != 0) return -1;   /* moved */
                continue;
            }
            /* candidate or dropped -> seen */
            int pr = put_rec(j, &r);
            if (pr < 0) return -1;
            if (pr == 0) { (*new_seen)++; log_seen(&r); }
        }
    }
    for (int i = 0; i < plan->n_drop; i++) {
        amm_rec_t r = plan->drop[i], cur;
        /* only a record that is STILL a candidate (a quorum reached by the
         * puts above promotes it first) */
        int g = amm_journal_rec_get(j, r.tx, r.log_index, &cur);
        if (g < 0) return -1;
        if (g == 1 || strcmp(cur.state, AMM_R_CANDIDATE) != 0) continue;
        r = cur;
        snprintf(r.state, sizeof(r.state), "%s", AMM_R_DROPPED);
        if (amm_journal_rec_put(j, &r) != AMM_J_OK) return -1;
        (*dropped)++;
    }
    return 0;
}

/* ── lookup of a recorded transaction (reorganisation, depth) ─────────── */

typedef enum { C_SAME, C_MOVED, C_GONE, C_UNKNOWN } cls_t;

/* Where a moved transaction is now: the quorum record in its new block. */
typedef struct { amm_rec_t nw; } moved_t;

/* Where is the transaction of `rec` now, at the quorum? Exactly one of: in
 * the same block, in another block, no receipt / failed receipt; anything
 * else is unknown. */
static cls_t classify(amm_eth_watch_t *w, const step_t *st, const amm_rec_t *rec,
                      moved_t *mv, int *deep_ok, uint64_t min_gap, txt_t *dt) {
    amm_eth_receipt_t rc[AMM_ETH_MAX_PROVIDERS];
    int kind[AMM_ETH_MAX_PROVIDERS];       /* 0 unknown 1 ok-status1 2 gone  */
    int pidx[AMM_ETH_MAX_PROVIDERS];       /* provider behind each answer    */
    int n = 0;
    if (deep_ok) *deep_ok = 0;
    for (int i = 0; i < w->cfg.n_providers; i++) {
        if (!st->use[i]) continue;
        const amm_eth_provider_t *p = &w->prov[i];
        amm_eth_receipt_t t;
        int r = p->get_receipt(p->ctx, rec->tx, &t, st->deadline);
        char bh[9];
        if (r == AMM_ETH_OK) {
            rc[n] = t;
            kind[n] = (t.status == 1) ? 1 : 2;
            pidx[n] = i;
            n++;
            txt_add(dt, " provider %d: receipt%s in %llu %s", i, t.status == 1 ? "" : " (failed)",
                    (unsigned long long)t.block_number, hx(t.block_hash, 4, bh));
        } else if (r == AMM_ETH_NOT_FOUND) {
            memset(&rc[n], 0, sizeof(rc[n]));
            kind[n] = 2;
            pidx[n] = i;
            n++;
            txt_add(dt, " provider %d: no receipt", i);
        } else {
            txt_add(dt, " provider %d: no answer (%d)", i, r);
        }
    }
    int same = 0, gone = 0;
    int mg[AMM_ETH_MAX_PROVIDERS], nmg = 0;     /* representatives of the
                                                 * moved groups at quorum   */
    for (int i = 0; i < n; i++) {
        if (kind[i] == 2) { gone++; continue; }
        if (!memcmp(rc[i].block_hash, rec->block_hash, 32) &&
            rc[i].block_number == rec->block_number) {
            same++;
            /* depth (plan line 252): the SAME provider that reports the
             * payment's block hash must also report a tip at least
             * `min_gap` (the payment's count) above it */
            if (deep_ok) {
                uint64_t tip = 0;
                const amm_eth_provider_t *p = &w->prov[pidx[i]];
                int tr = p->block_number(p->ctx, &tip, st->deadline);
                if (tr == AMM_ETH_OK && tip >= rec->block_number &&
                    tip - rec->block_number >= min_gap)
                    (*deep_ok)++;
                if (tr == AMM_ETH_OK)
                    txt_add(dt, "; provider %d latest block %llu", pidx[i], (unsigned long long)tip);
                else
                    txt_add(dt, "; provider %d gave no latest block (%d)", pidx[i], tr);
            }
            continue;
        }
        int c = 0;
        for (int k = 0; k < n; k++)
            c += kind[k] == 1 && rc[k].block_number == rc[i].block_number &&
                 !memcmp(rc[k].block_hash, rc[i].block_hash, 32);
        if (c < w->cfg.quorum) continue;
        int known = 0;
        for (int m = 0; m < nmg; m++)
            known |= rc[mg[m]].block_number == rc[i].block_number &&
                     !memcmp(rc[mg[m]].block_hash, rc[i].block_hash, 32);
        if (!known) mg[nmg++] = i;
    }
    int q = w->cfg.quorum;
    int hits = (same >= q) + (gone >= q) + nmg;
    txt_add(dt, "; same block %d, no or failed receipt %d, other blocks at the quorum %d",
            same, gone, nmg);
    if (hits != 1) return C_UNKNOWN;
    if (same >= q) return C_SAME;
    if (gone >= q) return C_GONE;
    /* moved: its new block must be at the quorum with the same hash */
    int moved_idx = mg[0];
    amm_eth_block_t nb;
    int nb_agree[AMM_ETH_MAX_PROVIDERS];
    if (quorum_block(w, st, rc[moved_idx].block_number, &nb, nb_agree) != 0 ||
        memcmp(nb.hash, rc[moved_idx].block_hash, 32) != 0) return C_UNKNOWN;
    /* the quorum's ACTUAL log of the transaction in its new block (sender,
     * recipient, logged value, log index): a receipt location alone would
     * keep the old value */
    int err = 0;
    find_t f = find_tx_record(w, st, &nb, nb_agree, rec->tx, &mv->nw, &err);
    if (f == F_FOUND) return C_MOVED;
    if (f == F_GONE) return C_GONE;
    return C_UNKNOWN;
}

typedef struct {
    amm_rec_t rec;
    cls_t     cls;
    moved_t   mv;
} dec_t;

/* Apply one lookup decision inside a journal transaction. @return 0 / -1. */
static int apply_decision(amm_journal_t *j, const dec_t *d, amm_eth_step_t *out) {
    if (d->cls == C_MOVED) return rec_follow(j, &d->rec, &d->mv.nw, out);
    if (d->cls == C_GONE) {
        amm_gone_t g;
        if (amm_journal_payment_gone(j, d->rec.tx, d->rec.log_index, &g) != AMM_J_OK)
            return -1;
        if (g == AMM_GONE_REVERSED) out->reversed++;
        else out->dropped++;
    }
    return 0;
}

static uint64_t floor_of(const amm_eth_watch_t *w, uint64_t tip) {
    return tip >= w->cfg.window_blocks ? tip - w->cfg.window_blocks : 0;
}

/* ── reorganisation ───────────────────────────────────────────────────── */

/* A parent-hash mismatch at height h (stored block h-1 differs from the
 * accepted block h's parent). @return AMM_W_OK (written) / AMM_W_UNKNOWN
 * (nothing written) / AMM_W_ERR. */
static int handle_reorg(amm_eth_watch_t *w, const step_t *st, uint64_t h,
                        uint64_t tip, amm_eth_step_t *out) {
    amm_journal_t *j = w->cfg.journal;
    uint64_t floor = floor_of(w, tip);
    uint64_t lowest = 0;
    int found = 0;
    for (uint64_t k = h - 1; ; k--) {
        amm_blk_t sb;
        int g = amm_journal_block_get(j, k, &sb);
        if (g < 0) return AMM_W_ERR;
        if (g == 1) break;                      /* no stored history below   */
        amm_eth_block_t fresh;
        int fresh_agree[AMM_ETH_MAX_PROVIDERS];
        if (quorum_block(w, st, k, &fresh, fresh_agree) != 0) return AMM_W_UNKNOWN;
        if (!memcmp(sb.hash, fresh.hash, 32)) break;    /* common ancestor   */
        lowest = k;
        found = 1;
        if (k == 0 || k <= floor) break;
    }
    if (!found) {                               /* providers inconsistent    */
        why_set(st, "block %llu: its parent differs from the stored block %llu, but no "
                "differing stored block was found below it", (unsigned long long)h,
                (unsigned long long)(h - 1));
        return AMM_W_UNKNOWN;
    }

    amm_rec_t *recs = calloc(REC_CAP, sizeof(amm_rec_t));
    dec_t *decs = calloc(REC_CAP, sizeof(dec_t));
    if (!recs || !decs) { free(recs); free(decs); return AMM_W_ERR; }
    int n = 0, nd = 0, rc = AMM_W_OK;
    if (amm_journal_rec_list(j, floor, NULL, recs, REC_CAP, &n) != 0) { rc = AMM_W_ERR; goto out; }
    for (int i = 0; i < n; i++) {
        if (!strcmp(recs[i].state, AMM_R_CANDIDATE)) continue;  /* rescanned  */
        dec_t *d = &decs[nd];
        d->rec = recs[i];
        d->cls = classify(w, st, &recs[i], &d->mv, NULL, 0, NULL);
        if (d->cls == C_UNKNOWN) {
            char th[65];
            why_set(st, "reorganisation below block %llu: where payment %s is now is unknown",
                    (unsigned long long)h, hx(recs[i].tx, 32, th));
            rc = AMM_W_UNKNOWN;
            goto out;
        }
        nd++;
    }
    /* one transaction: stored blocks above the ancestor removed, cursor back
     * to rescan them, every record decision */
    if (amm_journal_tx_begin(j) != 0) { rc = AMM_W_ERR; goto out; }
    int ok = amm_journal_blocks_delete_from(j, lowest) == 0 &&
             amm_journal_cursor_reset(j, "eth_scan", lowest) == 0;
    for (int i = 0; ok && i < nd; i++) ok = apply_decision(j, &decs[i], out) == 0;
    if (!ok) { amm_journal_tx_rollback(j); rc = AMM_W_ERR; goto out; }
    if (amm_journal_tx_commit(j) != 0) { rc = AMM_W_ERR; goto out; }
    out->reorgs++;
    QGP_LOG_WARN(LOG_TAG, "reorganisation: blocks from %llu replaced (found at block %llu), "
                 "%d payment records decided again", (unsigned long long)lowest,
                 (unsigned long long)h, nd);
out:
    free(recs);
    free(decs);
    return rc;
}

/* ── one block ────────────────────────────────────────────────────────── */

/* Scan block h. @return AMM_W_OK (block written, or a reorganisation written)
 * / AMM_W_UNKNOWN / AMM_W_ERR; *reorg = 1 when a reorganisation was written
 * (the cursor moved back, nothing else happened for h). */
static int scan_block(amm_eth_watch_t *w, const step_t *st, uint64_t h,
                      uint64_t tip, amm_eth_step_t *out, int *reorg) {
    amm_journal_t *j = w->cfg.journal;
    *reorg = 0;
    amm_eth_block_t qb;
    int qb_agree[AMM_ETH_MAX_PROVIDERS];
    if (quorum_block(w, st, h, &qb, qb_agree) != 0) return AMM_W_UNKNOWN;
    if (h > 0) {
        amm_blk_t prev;
        int g = amm_journal_block_get(j, h - 1, &prev);
        if (g < 0) return AMM_W_ERR;
        if (g == 0 && memcmp(prev.hash, qb.parent, 32) != 0) {
            int r = handle_reorg(w, st, h, tip, out);
            if (r == AMM_W_OK) *reorg = 1;
            return r;
        }
    }
    amm_rec_t *cands = calloc(REC_CAP, sizeof(amm_rec_t));
    if (!cands) return AMM_W_ERR;
    plan_t plan;
    int ncand = 0, rc = AMM_W_ERR;
    if (plan_alloc(&plan) != 0) { free(cands); return AMM_W_ERR; }
    {   /* the candidates already kept for this block (compacted in place) */
        int n = 0;
        if (amm_journal_rec_list(j, h, AMM_R_CANDIDATE, cands, REC_CAP, &n) != 0) goto out;
        for (int i = 0; i < n; i++)
            if (cands[i].block_number == h) cands[ncand++] = cands[i];
    }
    int e = eval_block(w, st, &qb, qb_agree, cands, ncand, &plan);
    if (e < 0) goto out;
    if (e == 1) { rc = AMM_W_UNKNOWN; goto out; }

    amm_blk_t sb;
    memset(&sb, 0, sizeof(sb));
    sb.height = qb.number;
    memcpy(sb.hash, qb.hash, 32);
    memcpy(sb.parent, qb.parent, 32);
    sb.ts = qb.timestamp;
    int new_seen = 0, dropped = 0;
    if (amm_journal_tx_begin(j) != 0) goto out;
    int ok = amm_journal_block_put(j, &sb) == 0 &&
             apply_plan(j, &plan, &new_seen, &dropped, out) == 0 &&
             amm_journal_cursor_put(j, "eth_scan", h + 1) == AMM_J_OK &&
             amm_journal_cursor_reset(j, "eth_tip", tip) == 0;
    if (!ok) { amm_journal_tx_rollback(j); goto out; }
    if (amm_journal_tx_commit(j) != 0) goto out;
    out->blocks++;
    out->new_records += new_seen;
    out->dropped += dropped;
    rc = AMM_W_OK;
out:
    plan_free(&plan);
    free(cands);
    return rc;
}

/* ── candidates, depth ────────────────────────────────────────────────── */

/* Evaluate the retained candidates again (amm_eth_watch.h step 8). */
static int rescan_candidates(amm_eth_watch_t *w, const step_t *st, uint64_t tip,
                             amm_eth_step_t *out) {
    amm_journal_t *j = w->cfg.journal;
    amm_rec_t *recs = calloc(REC_CAP, sizeof(amm_rec_t));
    if (!recs) return AMM_W_ERR;
    int nc = 0, rc = AMM_W_OK;
    char cbuf[2048] = "";
    txt_t ct = { cbuf, sizeof(cbuf), 0 };
    /* every retained candidate, whatever its age: a stale candidate would
     * keep a payment window unresolved for ever (amm_eth_watch_window_
     * observed), so each is evaluated again until promoted or dropped */
    if (amm_journal_rec_list(j, 0, AMM_R_CANDIDATE, recs, REC_CAP, &nc) != 0) {
        free(recs);
        return AMM_W_ERR;
    }
    for (int a = 0; a < nc;) {
        uint64_t blk = recs[a].block_number;
        int b = a;
        while (b < nc && recs[b].block_number == blk) b++;
        amm_eth_block_t qb;
        plan_t plan;
        if (plan_alloc(&plan) != 0) { rc = AMM_W_ERR; break; }
        int e = 1;
        if (st->why) st->why[0] = '\0';
        int blk_agree[AMM_ETH_MAX_PROVIDERS];
        if (quorum_block(w, st, blk, &qb, blk_agree) == 0) {
            if (memcmp(qb.hash, recs[a].block_hash, 32) != 0) {
                /* the block is no longer the accepted one: its candidates
                 * are stale */
                if (b - a > PLAN_CAP) e = -1;
                else {
                    for (int k = a; k < b; k++) plan.drop[plan.n_drop++] = recs[k];
                    e = 0;
                }
            } else {
                e = eval_block(w, st, &qb, blk_agree, &recs[a], b - a, &plan);
            }
        }
        if (e < 0) { plan_free(&plan); rc = AMM_W_ERR; break; }
        if (e == 1) {
            out->unknown++;
            if (rc == AMM_W_OK) rc = AMM_W_UNKNOWN;
            txt_add(&ct, "%s%d records of block %llu not evaluated: %s", ct.len ? " | " : "",
                    b - a, (unsigned long long)blk,
                    st->why && st->why[0] ? st->why : "no reason recorded");
        } else {
            int new_seen = 0, dropped = 0;
            if (amm_journal_tx_begin(j) != 0) { plan_free(&plan); rc = AMM_W_ERR; break; }
            int ok = apply_plan(j, &plan, &new_seen, &dropped, out) == 0 &&
                     amm_journal_cursor_reset(j, "eth_tip", tip) == 0;
            if (!ok) { amm_journal_tx_rollback(j); plan_free(&plan); rc = AMM_W_ERR; break; }
            if (amm_journal_tx_commit(j) != 0) { plan_free(&plan); rc = AMM_W_ERR; break; }
            out->new_records += new_seen;
            out->dropped += dropped;
        }
        plan_free(&plan);
        a = b;
    }
    free(recs);
    if (ct.len && st->why) note_set(w, NOTE_CAND, 1, cbuf);
    return rc;
}

/* seen -> deep for records at their count (by amount) below the tip, after a lookup
 * (amm_eth_watch.h step 9). */
static int mark_deep(amm_eth_watch_t *w, const step_t *st, uint64_t tip,
                     amm_eth_step_t *out) {
    amm_journal_t *j = w->cfg.journal;
    amm_rec_t *recs = calloc(REC_CAP, sizeof(amm_rec_t));
    if (!recs) return AMM_W_ERR;
    int n = 0, rc = AMM_W_OK;
    /* every `seen` record, whatever its age (a payment found by a late scan
     * may already lie below the window; the window bounds the detection of
     * a reversal, not the counting of a payment) */
    if (amm_journal_rec_list(j, 0, AMM_R_SEEN, recs, REC_CAP, &n) != 0) {
        free(recs);
        return AMM_W_ERR;
    }
    char lbuf[2048] = "";
    txt_t lt = { lbuf, sizeof(lbuf), 0 };
    int warn = 0;
    for (int i = 0; i < n; i++) {
        /* the count follows this payment's logged amount (givens item 60) */
        uint64_t need = amm_eth_watch_confirmations(w, recs[i].value);
        char th[65];
        hx(recs[i].tx, 32, th);
        if (tip < recs[i].block_number ||
            tip - recs[i].block_number < need) {
            txt_add(&lt, "%spayment %s in block %llu waits for %llu blocks, latest block at "
                    "the quorum %llu", lt.len ? " | " : "", th,
                    (unsigned long long)recs[i].block_number, (unsigned long long)need,
                    (unsigned long long)tip);
            continue;
        }
        dec_t d;
        d.rec = recs[i];
        int deep_votes = 0;
        char dbuf[768] = "";
        txt_t dt = { dbuf, sizeof(dbuf), 0 };
        d.cls = classify(w, st, &recs[i], &d.mv, &deep_votes, need, &dt);
        if (d.cls == C_UNKNOWN) {
            out->unknown++;
            if (rc == AMM_W_OK) rc = AMM_W_UNKNOWN;
            warn = 1;
            txt_add(&lt, "%spayment %s in block %llu (%llu blocks needed, latest block at the "
                    "quorum %llu): no answer at the quorum:%s", lt.len ? " | " : "", th,
                    (unsigned long long)recs[i].block_number, (unsigned long long)need,
                    (unsigned long long)tip, dbuf);
            continue;
        }
        /* plan line 252: at least Q providers must report the payment's block
         * hash AND a deep enough tip, the same providers; fewer: not deep
         * yet (no state change, not an unknown) */
        if (d.cls == C_SAME && deep_votes < w->cfg.quorum) {
            warn = 1;
            txt_add(&lt, "%spayment %s in block %llu (%llu blocks needed, latest block at the "
                    "quorum %llu): deep at %d providers, %d needed:%s", lt.len ? " | " : "", th,
                    (unsigned long long)recs[i].block_number, (unsigned long long)need,
                    (unsigned long long)tip, deep_votes, w->cfg.quorum, dbuf);
            continue;
        }
        if (amm_journal_tx_begin(j) != 0) { rc = AMM_W_ERR; break; }
        int ok;
        if (d.cls == C_SAME) {
            amm_rec_t r = recs[i];
            snprintf(r.state, sizeof(r.state), "%s", AMM_R_DEEP);
            ok = amm_journal_rec_put(j, &r) == AMM_J_OK;
            if (ok) out->deep++;
        } else {
            ok = apply_decision(j, &d, out) == 0;
        }
        if (!ok) { amm_journal_tx_rollback(j); rc = AMM_W_ERR; break; }
        if (amm_journal_tx_commit(j) != 0) { rc = AMM_W_ERR; break; }
        if (d.cls == C_SAME)
            QGP_LOG_INFO(LOG_TAG, "payment %s in block %llu is deep: %llu blocks needed, "
                         "latest block at the quorum %llu, deep at %d providers", th,
                         (unsigned long long)recs[i].block_number, (unsigned long long)need,
                         (unsigned long long)tip, deep_votes);
        else
            QGP_LOG_WARN(LOG_TAG, "payment %s in block %llu: %s", th,
                         (unsigned long long)recs[i].block_number,
                         d.cls == C_MOVED ? "moved to another block" : "gone (no or failed receipt)");
    }
    free(recs);
    if (lt.len && st->why) note_set(w, NOTE_DEPTH, warn, lbuf);
    return rc;
}

/* ── the step ─────────────────────────────────────────────────────────── */

static int step_run(amm_eth_watch_t *w, step_t *stp, amm_eth_step_t *out) {
    amm_journal_t *j = w->cfg.journal;
    step_t st = *stp;

    w->why[0] = '\0';
    out->usable = qualify(w, &st);
    if (w->why[0]) note_set(w, NOTE_PROV, 1, w->why);
    if (out->usable < w->cfg.quorum) { out->unknown++; return AMM_W_UNKNOWN; }
    uint64_t tip = 0;
    w->why[0] = '\0';
    if (quorum_tip(w, &st, &tip) != 0) {
        note_set(w, NOTE_TIP, 1, w->why);
        out->unknown++;
        return AMM_W_UNKNOWN;
    }
    out->tip = tip;

    uint64_t next = 0;
    int g = amm_journal_cursor_get(j, "eth_scan", &next);
    if (g < 0) return AMM_W_ERR;
    if (g == 1) next = w->cfg.start_height;

    int rc = AMM_W_OK;
    uint32_t scanned = 0;
    while (next <= tip && scanned < w->cfg.max_scan_blocks) {
        int reorg = 0;
        w->why[0] = '\0';
        int r = scan_block(w, &st, next, tip, out, &reorg);
        if (r == AMM_W_ERR) return AMM_W_ERR;
        if (r == AMM_W_UNKNOWN) {
            char m[1024];
            snprintf(m, sizeof(m), "block %llu not scanned (latest block at the quorum %llu): %s",
                     (unsigned long long)next, (unsigned long long)tip,
                     w->why[0] ? w->why : "no reason recorded");
            note_set(w, NOTE_SCAN, 1, m);
            out->unknown++;
            rc = AMM_W_UNKNOWN;
            break;
        }
        scanned++;
        if (reorg) {
            g = amm_journal_cursor_get(j, "eth_scan", &next);
            if (g != 0) return AMM_W_ERR;
        } else {
            next++;
        }
    }

    uint64_t floor = floor_of(w, tip);
    int r = rescan_candidates(w, &st, tip, out);
    if (r == AMM_W_ERR) return AMM_W_ERR;
    if (r == AMM_W_UNKNOWN) rc = AMM_W_UNKNOWN;
    r = mark_deep(w, &st, tip, out);
    if (r == AMM_W_ERR) return AMM_W_ERR;
    if (r == AMM_W_UNKNOWN) rc = AMM_W_UNKNOWN;

    if (amm_journal_blocks_prune_below(j, floor) != 0) return AMM_W_ERR;
    if (amm_journal_cursor_reset(j, "eth_tip", tip) != 0) return AMM_W_ERR;
    return rc;
}

int amm_eth_watch_step(amm_eth_watch_t *w, uint64_t deadline_ms,
                       amm_eth_step_t *out) {
    amm_eth_step_t local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    if (!w) return AMM_W_ERR;
    step_t st;
    memset(&st, 0, sizeof(st));
    st.deadline = deadline_ms;
    st.why = w->why;
    st.why_cap = sizeof(w->why);
    int rc = step_run(w, &st, out);
    notes_close(w);
    return rc;
}

/* ── queries ──────────────────────────────────────────────────────────── */

int amm_eth_watch_tip(amm_eth_watch_t *w, uint64_t *tip) {
    if (!w || !tip) return -1;
    return amm_journal_cursor_get(w->cfg.journal, "eth_tip", tip);
}

int amm_eth_watch_depth_reached(amm_eth_watch_t *w, const amm_rec_t *rec,
                                uint64_t min_depth, uint64_t deadline_ms,
                                int *reached) {
    if (!w || !rec || !reached) return -1;
    step_t st;
    memset(&st, 0, sizeof(st));
    st.deadline = deadline_ms;
    if (qualify(w, &st) < w->cfg.quorum) return 1;
    moved_t mv;
    int votes = 0;
    cls_t c = classify(w, &st, rec, &mv, &votes, min_depth, NULL);
    if (c == C_UNKNOWN) return 1;
    /* the same joint vote as the swap depth (plan line 252): a provider
     * counts only when it reports the record's block AND its own tip is at
     * least min_depth above it */
    *reached = (c == C_SAME && votes >= w->cfg.quorum);
    return 0;
}

amm_match_t amm_eth_watch_match(const amm_rec_t *rec, const uint8_t sender[20],
                                const uint8_t amount_be[32],
                                uint64_t approved_tip, uint64_t expiry_ts) {
    if (memcmp(rec->from, sender, 20) != 0) return AMM_M_NONE;
    if (memcmp(rec->value, amount_be, 32) != 0) return AMM_M_HELD_VALUE;
    if (rec->block_number <= approved_tip) return AMM_M_HELD_EARLY;
    if (rec->block_ts > expiry_ts) return AMM_M_HELD_EXPIRED;
    return AMM_M_MATCH;
}

/* The window rule; `sender` NULL = an approval with no signed request (no
 * sender: no candidate record can be "for that approval", only the cursor and
 * depth conditions apply). */
static int window_observed_impl(amm_eth_watch_t *w, uint64_t approved_tip,
                                uint64_t expiry_ts, const uint8_t *sender,
                                const uint8_t amount_be[32]) {
    amm_journal_t *j = w->cfg.journal;
    uint64_t tip = 0, next = 0;
    int a = amm_journal_cursor_get(j, "eth_tip", &tip);
    int b = amm_journal_cursor_get(j, "eth_scan", &next);
    if (a < 0 || b < 0) return -1;
    if (a == 1 || b == 1 || next == 0) return 0;
    /* the count of the approval's value v (plan section 13, givens item 60) */
    uint64_t need = amm_eth_watch_confirmations(w, amount_be);
    if (tip < need) return 0;
    uint64_t max_h = next - 1;
    if (tip - need < max_h) max_h = tip - need;
    uint64_t found = 0;
    int f = amm_journal_block_after_ts(j, expiry_ts, max_h, &found);
    if (f < 0) return -1;
    if (f == 1) return 0;
    if (!sender) return 1;
    /* only a candidate whose block time is within the approval's validity (or
     * unknown) is "for that approval" (plan lines 314, 319) */
    int c = amm_journal_rec_candidate_exists(j, sender, amount_be, approved_tip,
                                             expiry_ts);
    if (c < 0) return -1;
    return c == 0 ? 0 : 1;      /* a retained candidate: still unresolved   */
}

int amm_eth_watch_window_observed(amm_eth_watch_t *w, uint64_t approved_tip,
                                  uint64_t expiry_ts, const uint8_t sender[20],
                                  const uint8_t amount_be[32]) {
    if (!w || !sender || !amount_be) return -1;
    return window_observed_impl(w, approved_tip, expiry_ts, sender, amount_be);
}

int amm_eth_watch_window_observed_unsigned(amm_eth_watch_t *w, uint64_t expiry_ts,
                                           const uint8_t amount_be[32]) {
    if (!w || !amount_be) return -1;
    return window_observed_impl(w, 0, expiry_ts, NULL, amount_be);
}
