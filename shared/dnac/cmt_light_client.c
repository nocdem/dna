/**
 * @file shared/dnac/cmt_light_client.c
 * @brief cometbft @v0.38.26 light/client.go + light/trust_options.go — see
 *        cmt_light_client.h for the mapping, the deviations (D1-D19), the
 *        reproduced quirks (Q1-Q8) and the item-9 agreement rule (R1-R6).
 *
 * Every function names the reference lines it ports. Ownership: every
 * light block the client holds lives in a `cmt_light_block_buf_t` (above
 * one megabyte, never on the stack). One verification keeps the blocks it
 * fetches in a POOL that is freed when the public call returns; the trace
 * and the bisection cache are arrays of pointers into that pool (or to
 * the trusted / target block, which the caller of the step owns).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_light_client.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_block.h"

#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_LIGHT_CLIENT"

/* ══ the client ═══════════════════════════════════════════════════════ */

typedef struct {
    cmt_light_provider_t p;
    uint8_t              id[CMT_LIGHT_CLIENT_PEER_ID_MAX];
    size_t               id_len;
} peer_t;

/* client.go:133-162 — `type Client struct`. */
struct cmt_light_client {
    uint8_t                    chain_id[CMT_PB_CHAINID_MAX];   /* :134 */
    size_t                     chain_id_len;
    int64_t                    trusting_period;                /* :135 */
    cmt_light_client_options_t o;                              /* :136-140, :155-157 */
    peer_t                     primary;                        /* :145 */
    peer_t                    *witnesses;                      /* :147 */
    size_t                     n_witnesses;
    size_t                     witnesses_cap;   /* configured + 1 (:1086) */
    cmt_light_store_t          store;                          /* :150 */
    cmt_light_block_buf_t     *latest;          /* :152; NULL = nil */
};

/* ══ small helpers ════════════════════════════════════════════════════ */

static void err_clear(cmt_light_client_error_t *err)
{
    if (err != NULL) {
        memset(err, 0, sizeof(*err));
    }
}

static int reject(cmt_light_client_error_t *err, int code)
{
    if (err != NULL) {
        err_clear(err);
        err->code = code;
    }
    return CMT_REJECT;
}

/* A CMT_FAULT carries no error value (cmt_light_client_error_t's rule). */
static int fault(cmt_light_client_error_t *err)
{
    err_clear(err);
    return CMT_FAULT;
}

/* ErrVerificationFailed{From, To, Reason} (errors.go:49-64). */
static int verification_failed(cmt_light_client_error_t *err, int64_t from,
                               int64_t to, int reason,
                               const cmt_light_error_t *verr,
                               const cmt_light_provider_error_t *perr)
{
    if (err != NULL) {
        err_clear(err);
        err->code   = CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED;
        err->from   = from;
        err->to     = to;
        err->reason = reason;
        if (verr != NULL) {
            err->verify = *verr;
        }
        if (perr != NULL) {
            err->provider = *perr;
        }
    }
    return CMT_REJECT;
}

/* The block's height, through the embedded `*Header` — a Go nil
 * dereference when absent (D7). */
static int lb_height(const cmt_light_block_t *lb, int64_t *out)
{
    if (lb == NULL || lb->signed_header == NULL ||
        lb->signed_header->header == NULL) {
        return CMT_FAULT;
    }
    *out = lb->signed_header->header->height;
    return CMT_OK;
}

/* `LightBlock.Hash()` = `Header.Hash()` (types/light.go embeds the
 * SignedHeader, types/block.go:445-480). The reference's nil hash
 * (CMT_HASH_NIL, cmt_block.h:423-428) is length 0 here, so that
 * `bytes.Equal(nil, nil)` stays true and `bytes.Equal(nil, x)` false. */
static int header_hash(const cmt_header_t *h, uint8_t out[CMT_TMHASH_SIZE],
                       size_t *len)
{
    int rc;

    if (h == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_header_hash(h, out);
    if (rc == CMT_OK) {
        *len = CMT_TMHASH_SIZE;
        return CMT_OK;
    }
    if (rc == CMT_HASH_NIL) {
        *len = 0u;
        return CMT_OK;
    }
    return CMT_FAULT;
}

static int lb_hash(const cmt_light_block_t *lb, uint8_t out[CMT_TMHASH_SIZE],
                   size_t *len)
{
    if (lb == NULL || lb->signed_header == NULL) {
        return CMT_FAULT;
    }
    return header_hash(lb->signed_header->header, out, len);
}

static bool bytes_equal(const uint8_t *a, size_t alen,
                        const uint8_t *b, size_t blen)
{
    return alen == blen && (alen == 0u || memcmp(a, b, alen) == 0);
}

/* `bytes.Equal(a.Hash(), b.Hash())` for two light blocks. */
static int lb_hash_equal(const cmt_light_block_t *a,
                         const cmt_light_block_t *b, bool *eq)
{
    uint8_t ha[CMT_TMHASH_SIZE], hb[CMT_TMHASH_SIZE];
    size_t  la = 0u, lb = 0u;

    if (lb_hash(a, ha, &la) != CMT_OK || lb_hash(b, hb, &lb) != CMT_OK) {
        return CMT_FAULT;
    }
    *eq = bytes_equal(ha, la, hb, lb);
    return CMT_OK;
}

/* A deep copy of `src` into `dst`, re-aiming every pointer at `dst`'s own
 * storage (cmt_light_block.h:293-309). An absent member stays absent. */
static int buf_copy(cmt_light_block_buf_t *dst, const cmt_light_block_t *src)
{
    if (dst == NULL || src == NULL || src == &dst->lb ||
        cmt_light_block_buf_reset(dst) != CMT_OK) {
        return CMT_FAULT;
    }
    if (src->signed_header != NULL) {
        const cmt_signed_header_t *sh = src->signed_header;

        if (sh->header != NULL) {
            dst->header               = *sh->header;
            dst->signed_header.header = &dst->header;
        }
        if (sh->commit != NULL) {
            const cmt_commit_t *c = sh->commit;

            if (c->signatures_len > (size_t)CMT_VALSET_MAX ||
                (c->signatures_len > 0u && c->signatures == NULL)) {
                (void)cmt_light_block_buf_reset(dst);
                return CMT_FAULT;
            }
            dst->commit                = *c;
            dst->commit.signatures     = dst->sigs;
            dst->commit.signatures_cap = (size_t)CMT_VALSET_MAX;
            if (c->signatures_len > 0u) {
                memcpy(dst->sigs, c->signatures,
                       c->signatures_len * sizeof(dst->sigs[0]));
            }
            dst->signed_header.commit = &dst->commit;
        }
        dst->lb.signed_header = &dst->signed_header;
    }
    if (src->validator_set != NULL) {
        if (cmt_validator_set_copy(src->validator_set,
                                   &dst->validator_set) != CMT_OK) {
            (void)cmt_light_block_buf_reset(dst);
            return CMT_FAULT;
        }
        dst->lb.validator_set = &dst->validator_set;
    }
    return CMT_OK;
}

/* K25-3 — the full proposer-priority vector, in validator order, length
 * included (instead of ProposerPriorityHash, detector.go:211-216, whose
 * hash writes every varint at offset 0, types/validator_set.go:392-398). */
static bool priorities_equal(const cmt_validator_set_t *a,
                             const cmt_validator_set_t *b)
{
    size_t i;

    if (a == NULL || b == NULL) {
        return a == b;
    }
    if (a->validators_len != b->validators_len) {
        return false;
    }
    for (i = 0; i < a->validators_len; i++) {
        if (a->validators[i].proposer_priority !=
            b->validators[i].proposer_priority) {
            return false;
        }
    }
    return true;
}

/* ══ the per-operation pool, the trace and the cache ══════════════════ */

typedef struct {
    cmt_light_block_buf_t **b;
    size_t                  len;
    size_t                  cap;
} pool_t;

static cmt_light_block_buf_t *pool_new(pool_t *p)
{
    cmt_light_block_buf_t *b;

    if (p->len == p->cap) {
        size_t                  ncap = p->cap == 0u ? 8u : 2u * p->cap;
        cmt_light_block_buf_t **nb;

        if (ncap < p->cap) {
            return NULL;
        }
        nb = realloc(p->b, ncap * sizeof(*nb));
        if (nb == NULL) {
            return NULL;
        }
        p->b   = nb;
        p->cap = ncap;
    }
    b = cmt_light_block_buf_new();
    if (b == NULL) {
        return NULL;
    }
    p->b[p->len++] = b;
    return b;
}

static void pool_free(pool_t *p)
{
    size_t i;

    for (i = 0; i < p->len; i++) {
        cmt_light_block_buf_free(p->b[i]);
    }
    free(p->b);
    p->b   = NULL;
    p->len = 0u;
    p->cap = 0u;
}

/* An array of light-block pointers bounded by `limit` (the trace, D3, and
 * the bisection cache, D3). Not owning. */
typedef struct {
    const cmt_light_block_t **v;
    size_t                    len;
    size_t                    cap;
    uint64_t                  limit;
} lbvec_t;

/* @return CMT_OK; CMT_REJECT when the push would pass `limit`;
 *         CMT_FAULT on allocation failure. */
static int lbvec_push(lbvec_t *t, const cmt_light_block_t *lb)
{
    if ((uint64_t)t->len >= t->limit) {
        return CMT_REJECT;
    }
    if (t->len == t->cap) {
        size_t                    ncap = t->cap == 0u ? 8u : 2u * t->cap;
        const cmt_light_block_t **nv;

        if (ncap < t->cap) {
            return CMT_FAULT;
        }
        nv = realloc((void *)t->v, ncap * sizeof(*nv));
        if (nv == NULL) {
            return CMT_FAULT;
        }
        t->v   = nv;
        t->cap = ncap;
    }
    t->v[t->len++] = lb;
    return CMT_OK;
}

static void lbvec_free(lbvec_t *t)
{
    free((void *)t->v);
    t->v   = NULL;
    t->len = 0u;
    t->cap = 0u;
}

static int trace_push(lbvec_t *trace, const cmt_light_block_t *lb,
                      cmt_light_client_error_t *err)
{
    int rc = lbvec_push(trace, lb);

    if (rc == CMT_REJECT) {
        return reject(err, CMT_LIGHT_CLIENT_ERR_CAP_TRACE);       /* D3 */
    }
    return rc == CMT_OK ? CMT_OK : fault(err);
}

/* ══ providers ════════════════════════════════════════════════════════ */

/* Refuse an answer as the reference's provider would: BAD_LIGHT_BLOCK
 * with reason REJECT, the buffer emptied. */
static int bad_light_block(cmt_light_block_buf_t *out,
                           cmt_light_provider_error_t *perr)
{
    (void)cmt_light_block_buf_reset(out);
    perr->code   = CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK;
    perr->reason = CMT_REJECT;
    return CMT_REJECT;
}

/*
 * provider.go:9-29 — `LightBlock(ctx, height)`: the ONE entry point
 * through which every provider answer reaches the client. On a CMT_OK
 * answer the client itself enforces what the reference's provider
 * promises before it returns a block (D15, "provider contract moved into
 * the client"):
 *   1. every member is present (D16 — a nil one would be a Go panic in
 *      the verifier, and must not be reachable from a peer's answer);
 *   2. when `height != 0`, the header is at that height —
 *      light/provider/http/http.go:80-84 (`height != 0 && sh.Height !=
 *      height` → ErrBadLightBlock);
 *   3. `LightBlock.ValidateBasic(chainID)` — http.go:96-99 (→
 *      ErrBadLightBlock), which binds the set's hash to the header's
 *      ValidatorsHash (types/light.go:21-44); here with the client's chain
 *      id and block_protocol.
 * A failure is BAD_LIGHT_BLOCK (reason REJECT) with `out` reset, exactly
 * what a provider's own ErrBadLightBlock gets from every caller.
 */
static int provider_light_block(const cmt_light_client_t *c, const peer_t *pr,
                                int64_t height, cmt_light_block_buf_t *out,
                                cmt_light_provider_error_t *perr)
{
    int rc;

    perr->code   = CMT_LIGHT_PROVIDER_ERR_NONE;
    perr->reason = CMT_OK;
    if (pr->p.light_block == NULL) {
        return CMT_FAULT;
    }
    rc = pr->p.light_block(pr->p.ctx, height, out, perr);
    if (rc == CMT_FAULT) {
        perr->code   = CMT_LIGHT_PROVIDER_ERR_NONE;
        perr->reason = CMT_OK;
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        return CMT_REJECT;
    }
    if (out->lb.signed_header == NULL ||
        out->lb.signed_header->header == NULL ||
        out->lb.signed_header->commit == NULL ||
        out->lb.validator_set == NULL) {                         /* 1, D16 */
        return bad_light_block(out, perr);
    }
    if (height != 0 &&
        out->lb.signed_header->header->height != height) {      /* 2, http.go:80-84 */
        return bad_light_block(out, perr);
    }
    rc = cmt_light_block_validate_basic(&out->lb, c->chain_id,   /* 3, http.go:96-99 */
                                        c->chain_id_len,
                                        c->o.block_protocol);
    if (rc == CMT_FAULT) {
        (void)cmt_light_block_buf_reset(out);
        return CMT_FAULT;            /* this process could not decide (D6) */
    }
    if (rc != CMT_OK) {
        return bad_light_block(out, perr);
    }
    return CMT_OK;
}

/* The benign class: client.go:1003 / :1106 (ErrNoResponse,
 * ErrLightBlockNotFound, ErrHeightTooHigh). */
static bool provider_benign(int code)
{
    return code == CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE ||
           code == CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND ||
           code == CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH;
}

/* cometbft@v0.38.26 light/client.go:1018-1034 — removeWitnesses(): refuse
 * when no witness would remain (:1021-1023); otherwise sort the indexes
 * (:1027) and, from the highest down, overwrite each slot with the last
 * witness and shrink (:1028-1031, Q7). `idx` holds distinct indexes. */
static int remove_witnesses(cmt_light_client_t *c, size_t *idx, size_t k)
{
    size_t i, j;

    if (c->n_witnesses <= k) {
        return CMT_REJECT;                                       /* :1021-1023 */
    }
    for (i = 1; i < k; i++) {                                    /* :1027 */
        size_t v = idx[i];

        for (j = i; j > 0 && idx[j - 1] > v; j--) {
            idx[j] = idx[j - 1];
        }
        idx[j] = v;
    }
    for (i = k; i > 0; i--) {                                    /* :1028-1031 */
        c->witnesses[idx[i - 1]] = c->witnesses[c->n_witnesses - 1];
        c->n_witnesses--;
    }
    return CMT_OK;
}

/*
 * cometbft@v0.38.26 light/client.go:1036-1127 — findNewPrimary().
 *
 * D2: the witnesses are asked one at a time in INDEX order; the first
 * valid answer is taken, as the reference takes the first to ARRIVE
 * (:1075-1104). A witness after it is not asked (in Go its request is
 * cancelled, :1080). D6: a CMT_FAULT ends the call at once and changes
 * nothing.
 * On CMT_OK `out` is the new primary's block. On CMT_REJECT `err->code`
 * is NO_WITNESSES (:1050-1052, :1098-1100) or PROVIDER with the last
 * witness error (:1126).
 */
static int find_new_primary(cmt_light_client_t *c, int64_t height,
                            bool remove, cmt_light_block_buf_t *out,
                            cmt_light_client_error_t *err)
{
    cmt_light_provider_error_t perr, last = { CMT_LIGHT_PROVIDER_ERR_NONE,
                                              CMT_OK };
    size_t *to_remove;
    size_t  n_remove = 0u;
    size_t  i;
    int     rc;

    if (c->n_witnesses == 0u) {                                  /* :1050-1052 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);
    }
    to_remove = malloc(c->n_witnesses * sizeof(*to_remove));
    if (to_remove == NULL) {
        return fault(err);
    }

    for (i = 0; i < c->n_witnesses; i++) {
        rc = provider_light_block(c, &c->witnesses[i], height, out, &perr);
        if (rc == CMT_FAULT) {                                   /* D6 */
            free(to_remove);
            return fault(err);
        }
        if (rc == CMT_OK) {                                      /* :1079 */
            if (!remove) {                                       /* :1084-1087 */
                c->witnesses[c->n_witnesses++] = c->primary;
            }
            QGP_LOG_DEBUG(LOG_TAG, "found new primary: witness #%zu", i);
            c->primary = c->witnesses[i];                        /* :1089-1091 */
            to_remove[n_remove++] = i;                           /* :1093-1094 */
            rc = remove_witnesses(c, to_remove, n_remove);       /* :1096-1100 (Q6) */
            free(to_remove);
            if (rc != CMT_OK) {
                (void)cmt_light_block_buf_reset(out);
                return reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);
            }
            return CMT_OK;                                       /* :1103 */
        }
        last = perr;
        if (provider_benign(perr.code)) {                        /* :1105-1110 */
            QGP_LOG_DEBUG(LOG_TAG, "witness #%zu: benign error %d at %lld",
                          i, perr.code, (long long)height);
            continue;
        }
        QGP_LOG_ERROR(LOG_TAG, "witness #%zu: error %d at %lld, removing",
                      i, perr.code, (long long)height);          /* :1112-1117 */
        to_remove[n_remove++] = i;
    }

    if (remove_witnesses(c, to_remove, n_remove) != CMT_OK) {    /* :1121-1124 */
        QGP_LOG_ERROR(LOG_TAG, "failed to remove %zu witnesses", n_remove);
    }
    free(to_remove);
    (void)cmt_light_block_buf_reset(out);
    if (err != NULL) {
        err_clear(err);
        err->code     = CMT_LIGHT_CLIENT_ERR_PROVIDER;           /* :1126 */
        err->provider = last;
    }
    return CMT_REJECT;
}

/*
 * cometbft@v0.38.26 light/client.go:981-1016 — lightBlockFromPrimary():
 * success (:996-998); a benign error replaces the primary and keeps it as
 * a witness (:1003-1007); any other error drops it (:1009-1015).
 * `context.Canceled` / `DeadlineExceeded` (:1000-1001) have no
 * counterpart (cmt_light_provider.h). D6: CMT_FAULT is returned as is.
 */
static int light_block_from_primary(cmt_light_client_t *c, int64_t height,
                                    cmt_light_block_buf_t *out,
                                    cmt_light_client_error_t *err)
{
    cmt_light_provider_error_t perr;
    int                        rc;

    rc = provider_light_block(c, &c->primary, height, out, &perr);
    if (rc == CMT_OK) {
        return CMT_OK;
    }
    if (rc == CMT_FAULT) {
        return fault(err);
    }
    if (provider_benign(perr.code)) {
        QGP_LOG_INFO(LOG_TAG, "primary: error %d at %lld, replacing",
                     perr.code, (long long)height);
        return find_new_primary(c, height, false, out, err);
    }
    QGP_LOG_INFO(LOG_TAG, "primary: error %d at %lld, removing",
                 perr.code, (long long)height);
    return find_new_primary(c, height, true, out, err);
}

/* ══ the detector hook (Kurultay #25 item 2; D5) ══════════════════════ */

/*
 * The ONE place where the reference calls detectDivergence
 * (client.go:691-696, :815-822). Package 3 replaces the body below with
 * the port of light/detector.go:28-118.
 *
 * Its first check is detector.go:29-31 ("nil or single block primary
 * trace"), which the reference reaches with a nil trace through Q2.
 * After it: FAIL CLOSED. The verified block is not saved, the caller gets
 * CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED with the trace's length
 * and end heights. This function must never return CMT_OK until the
 * detector is ported.
 */
static int detect_divergence(cmt_light_client_t *c, const lbvec_t *trace,
                             cmt_time_t now, cmt_light_client_error_t *err)
{
    int64_t from = 0, to = 0;

    (void)c;
    (void)now;
    if (trace->len < 2u) {                                       /* detector.go:29-31 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_SHORT_TRACE);
    }
    if (lb_height(trace->v[0], &from) != CMT_OK ||
        lb_height(trace->v[trace->len - 1u], &to) != CMT_OK) {
        return fault(err);
    }
    QGP_LOG_WARN(LOG_TAG, "detector not ported: verified %lld -> %lld "
                 "(%zu blocks) is NOT trusted", (long long)from,
                 (long long)to, trace->len);
    if (err != NULL) {
        err_clear(err);
        err->code       = CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED;
        err->trace_len  = trace->len;
        err->trace_from = from;
        err->trace_to   = to;
    }
    return CMT_REJECT;
}

/* ══ store use ════════════════════════════════════════════════════════ */

/* A store call's CMT_REJECT (cmt_light_store.h: an unreadable row). */
static int store_rc(int rc, cmt_light_client_error_t *err)
{
    if (rc == CMT_OK) {
        return CMT_OK;
    }
    if (rc == CMT_REJECT) {
        return reject(err, CMT_LIGHT_CLIENT_ERR_STORE);
    }
    return fault(err);
}

/* cometbft@v0.38.26 light/client.go:266-283 — restoreTrustedLightBlock(). */
static int restore_trusted_light_block(cmt_light_client_t *c,
                                       cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *b;
    int64_t                last = -1;
    bool                   found = false;
    int                    rc;

    rc = c->store.last_light_block_height(c->store.ctx, &last);  /* :268-271 */
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }
    if (last <= 0) {                                             /* :273 */
        return CMT_OK;
    }
    b = cmt_light_block_buf_new();
    if (b == NULL) {
        return fault(err);
    }
    rc = c->store.light_block(c->store.ctx, last, b, &found);    /* :274-277 */
    if (rc != CMT_OK || !found) {
        cmt_light_block_buf_free(b);
        return rc != CMT_OK ? store_rc(rc, err)
                            : reject(err, CMT_LIGHT_CLIENT_ERR_NOT_FOUND);
    }
    cmt_light_block_buf_free(c->latest);
    c->latest = b;                                               /* :278 */
    QGP_LOG_INFO(LOG_TAG, "restored trusted light block %lld",
                 (long long)last);                               /* :279 */
    return CMT_OK;
}

/* cometbft@v0.38.26 light/client.go:910-928 — updateTrustedLightBlock():
 * save (:913-915); prune to `pruning_size` when it is not 0 (:917-921);
 * keep the higher block as the latest (:923-925). */
static int update_trusted_light_block(cmt_light_client_t *c,
                                      const cmt_light_block_t *l,
                                      cmt_light_client_error_t *err)
{
    int64_t h = 0, lh = 0;
    int     rc;

    if (lb_height(l, &h) != CMT_OK) {
        return fault(err);
    }
    rc = c->store.save_light_block(c->store.ctx, l);             /* :913-915 */
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }
    if (c->o.pruning_size > 0u) {                                /* :917-921 */
        rc = c->store.prune(c->store.ctx, c->o.pruning_size);
        if (rc != CMT_OK) {
            return store_rc(rc, err);
        }
    }
    if (c->latest != NULL && lb_height(&c->latest->lb, &lh) != CMT_OK) {
        return fault(err);
    }
    if (c->latest == NULL || h > lh) {                           /* :923-925 */
        /* Copy into a NEW buffer and swap only on success: a failed copy
         * (allocation) leaves `c->latest` as it was — the block is saved,
         * the next restore or a higher save picks it up — and the call is
         * CMT_FAULT. */
        cmt_light_block_buf_t *nb = cmt_light_block_buf_new();

        if (nb == NULL || buf_copy(nb, l) != CMT_OK) {
            cmt_light_block_buf_free(nb);
            return fault(err);
        }
        cmt_light_block_buf_free(c->latest);
        c->latest = nb;
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 light/client.go:871-877 — Cleanup(). */
int cmt_light_client_cleanup(cmt_light_client_t *c)
{
    if (c == NULL || c->store.prune == NULL) {
        return CMT_FAULT;
    }
    QGP_LOG_INFO(LOG_TAG, "removing all the data");             /* :874 */
    cmt_light_block_buf_free(c->latest);                         /* :875 */
    c->latest = NULL;
    return c->store.prune(c->store.ctx, 0u);                     /* :876 */
}

/*
 * cometbft@v0.38.26 light/client.go:879-908 — cleanupAfter(height):
 * "deletes all headers & validator sets after +height+" — walking
 * LightBlockBefore from the LATEST trusted height down (:882-899), which
 * never deletes the latest block itself (Q3); then re-reads the latest
 * (:901-905). D8: a delete that does not return CMT_OK ends the walk.
 * The walk is bounded: each step reads a strictly lower stored height
 * (LightBlockBefore, cmt_light_store.h), so it takes at most as many
 * steps as the store holds rows — counted here against Size() + 1.
 */
static int cleanup_after(cmt_light_client_t *c, int64_t height,
                         cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *b;
    int64_t                prev = 0, h = 0;
    uint64_t               size = 0u, steps = 0u;
    bool                   found = false;
    int                    rc;

    if (c->latest == NULL || lb_height(&c->latest->lb, &prev) != CMT_OK) {
        return fault(err);                                       /* :882 */
    }
    rc = c->store.size(c->store.ctx, &size);
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }
    b = cmt_light_block_buf_new();
    if (b == NULL) {
        return fault(err);
    }
    for (;;) {                                                   /* :884 */
        if (steps++ > size) {
            /* More steps than rows: the store broke its own order. */
            cmt_light_block_buf_free(b);
            return fault(err);
        }
        rc = c->store.light_block_before(c->store.ctx, prev, b, &found);
        if (rc != CMT_OK) {                                      /* :888-890 */
            cmt_light_block_buf_free(b);
            return store_rc(rc, err);
        }
        if (!found) {                                            /* :886 */
            break;
        }
        if (lb_height(&b->lb, &h) != CMT_OK) {
            cmt_light_block_buf_free(b);
            return fault(err);
        }
        if (h <= height) {                                       /* :886-887 */
            break;
        }
        rc = c->store.delete_light_block(c->store.ctx, h);       /* :892-896, D8 */
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "can't remove trusted block %lld",
                          (long long)h);
            cmt_light_block_buf_free(b);
            return store_rc(rc, err);
        }
        prev = h;                                                /* :898 */
    }
    cmt_light_block_buf_free(b);

    cmt_light_block_buf_free(c->latest);                         /* :901 */
    c->latest = NULL;
    return restore_trusted_light_block(c, err);                  /* :902-905 */
}

/* ══ verification ═════════════════════════════════════════════════════ */

/*
 * cometbft@v0.38.26 light/client.go:612-697 — verifySequential().
 * D3: the trace is gap + 1 blocks, refused up front when that passes
 * `max_trace_len`; the loop's iterations (retries included) count against
 * `max_verify_steps`.
 */
static int verify_sequential(cmt_light_client_t *c,
                             const cmt_light_block_t *trusted,
                             const cmt_light_block_t *new_lb,
                             cmt_time_t now, cmt_light_client_error_t *err)
{
    pool_t                      pool  = { NULL, 0u, 0u };
    lbvec_t                     trace = { NULL, 0u, 0u, 0u };
    const cmt_light_block_t    *verified = trusted;              /* :620 */
    const cmt_light_block_t    *interim;
    cmt_light_block_buf_t      *b;
    cmt_light_error_t           verr;
    int64_t                     trusted_h = 0, new_h = 0, verified_h = 0;
    int64_t                     interim_h = 0, height;
    uint64_t                    steps = 0u;
    bool                        eq = false;
    int                         rc;

    if (lb_height(trusted, &trusted_h) != CMT_OK ||
        lb_height(new_lb, &new_h) != CMT_OK) {
        return fault(err);
    }
    trace.limit = c->o.max_trace_len;
    if (new_h > trusted_h &&
        (uint64_t)(new_h - trusted_h) >= c->o.max_trace_len) {   /* D3 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_CAP_TRACE);
    }
    rc = trace_push(&trace, trusted, err);                       /* :623 */
    if (rc != CMT_OK) {
        goto out;
    }
    verified_h = trusted_h;

    for (height = trusted_h + 1; height <= new_h; height++) {    /* :626 */
        if (++steps > c->o.max_verify_steps) {                   /* D3 */
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS);
            goto out;
        }
        /* 1) Fetch interim light block if needed (:627-635). */
        if (height == new_h) {
            interim = new_lb;
        } else {
            cmt_light_client_error_t e;

            b = pool_new(&pool);
            if (b == NULL) {
                rc = fault(err);
                goto out;
            }
            rc = light_block_from_primary(c, height, b, &e);
            if (rc == CMT_FAULT) {
                rc = fault(err);
                goto out;
            }
            if (rc != CMT_OK) {                                  /* :632-634 */
                rc = verification_failed(err, verified_h, height,
                        e.code == CMT_LIGHT_CLIENT_ERR_NO_WITNESSES
                            ? CMT_LIGHT_CLIENT_REASON_NO_WITNESSES
                            : CMT_LIGHT_CLIENT_REASON_PROVIDER,
                        NULL, &e.provider);
                goto out;
            }
            interim = &b->lb;
        }
        if (lb_height(interim, &interim_h) != CMT_OK) {
            rc = fault(err);
            goto out;
        }

        /* 2) Verify them (:637-682). */
        rc = cmt_light_verify_adjacent(verified->signed_header,
                                       interim->signed_header,
                                       interim->validator_set,
                                       c->trusting_period, now,
                                       c->o.max_clock_drift,
                                       c->o.block_protocol, &verr);
        if (rc == CMT_FAULT) {
            rc = fault(err);
            goto out;
        }
        if (rc != CMT_OK) {
            cmt_light_client_error_t orig;

            (void)verification_failed(&orig, verified_h, interim_h,  /* :647 */
                                      CMT_LIGHT_CLIENT_REASON_VERIFIER,
                                      &verr, NULL);
            if (verr.code == CMT_LIGHT_ERR_INVALID_HEADER) {     /* :650 */
                cmt_light_client_error_t e;

                if (orig.to == new_h) {                          /* :651-655 */
                    QGP_LOG_DEBUG(LOG_TAG, "target header is invalid");
                    rc = CMT_REJECT;
                    goto fail_orig;
                }
                QGP_LOG_ERROR(LOG_TAG, "primary sent invalid header -> "
                              "replacing");                      /* :659 */
                b = pool_new(&pool);
                if (b == NULL) {
                    rc = fault(err);
                    goto out;
                }
                rc = find_new_primary(c, new_h, true, b, &e);    /* :661-665 */
                if (rc == CMT_FAULT) {
                    rc = fault(err);
                    goto out;
                }
                if (rc != CMT_OK) {
                    rc = CMT_REJECT;
                    goto fail_orig;
                }
                if (lb_hash_equal(&b->lb, new_lb, &eq) != CMT_OK) {
                    rc = fault(err);
                    goto out;
                }
                if (!eq) {                                       /* :667-673 */
                    QGP_LOG_ERROR(LOG_TAG, "replacement provider has a "
                                  "different light block");
                    rc = CMT_REJECT;
                    goto fail_orig;
                }
                height--;                                        /* :675-678 */
                continue;
            }
            rc = CMT_REJECT;                                     /* :679-680 */
        fail_orig:
            if (err != NULL) {
                *err = orig;
            }
            goto out;
        }

        /* 3) Update verifiedBlock; 4) add it to the trace (:684-688). */
        verified   = interim;
        verified_h = interim_h;
        rc = trace_push(&trace, verified, err);
        if (rc != CMT_OK) {
            goto out;
        }
    }

    /* :691-696 — the detector hook (D5). */
    rc = detect_divergence(c, &trace, now, err);
out:
    lbvec_free(&trace);
    pool_free(&pool);
    return rc;
}

/* Go's `verifiedBlock.Height + (h - verifiedBlock.Height) *
 * verifySkippingNumerator / verifySkippingDenominator` (:749-750) in
 * int64 arithmetic that WRAPS as Go's does, without C's signed-overflow
 * undefined behaviour; then truncating division, as in Go. */
static int64_t skipping_pivot(int64_t verified_h, int64_t h)
{
    uint64_t diff = (uint64_t)h - (uint64_t)verified_h;
    uint64_t prod = diff * (uint64_t)CMT_LIGHT_CLIENT_VERIFY_SKIPPING_NUMERATOR;
    int64_t  sprod;

    memcpy(&sprod, &prod, sizeof(sprod));
    return (int64_t)((uint64_t)verified_h +
                     (uint64_t)(sprod /
                                CMT_LIGHT_CLIENT_VERIFY_SKIPPING_DENOMINATOR));
}

/*
 * cometbft@v0.38.26 light/client.go:699-773 — verifySkipping(): bisect
 * between `trusted` and `new_lb`, fetching pivots from `source`. On CMT_OK
 * `trace` is the verified trace. Pivots land in `pool`. `steps` counts
 * Verify calls across the re-runs of verifySkippingAgainstPrimary.
 */
static int verify_skipping(cmt_light_client_t *c, const peer_t *source,
                           const cmt_light_block_t *trusted,
                           const cmt_light_block_t *new_lb, cmt_time_t now,
                           lbvec_t *trace, pool_t *pool, uint64_t *steps,
                           cmt_light_client_error_t *err)
{
    lbvec_t                  cache = { NULL, 0u, 0u, 0u };   /* :714 */
    const cmt_light_block_t *verified = trusted;             /* :717 */
    const cmt_light_block_t *target;
    cmt_light_error_t        verr;
    size_t                   depth = 0u;                     /* :715 */
    int64_t                  verified_h = 0, target_h = 0;
    int                      rc;

    cache.limit = c->o.max_skipping_cache;
    if (lb_height(trusted, &verified_h) != CMT_OK) {
        return fault(err);
    }
    rc = lbvec_push(&cache, new_lb);
    if (rc != CMT_OK) {
        rc = rc == CMT_REJECT
             ? reject(err, CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE)
             : fault(err);
        goto out;
    }
    rc = trace_push(trace, trusted, err);                    /* :718 */
    if (rc != CMT_OK) {
        goto out;
    }

    for (;;) {                                               /* :721 */
        if (++*steps > c->o.max_verify_steps) {              /* D3 */
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS);
            goto out;
        }
        target = cache.v[depth];
        if (lb_height(target, &target_h) != CMT_OK) {
            rc = fault(err);
            goto out;
        }
        rc = cmt_light_verify(verified->signed_header,       /* :728-729 */
                              verified->validator_set,
                              target->signed_header,
                              target->validator_set,
                              c->trusting_period, now,
                              c->o.max_clock_drift, c->o.trust_level,
                              c->o.block_protocol, &verr);
        if (rc == CMT_FAULT) {
            rc = fault(err);
            goto out;
        }
        if (rc == CMT_OK) {                                  /* :731 */
            if (depth == 0u) {                               /* :732-736 */
                rc = trace_push(trace, new_lb, err);
                goto out;
            }
            verified   = target;                             /* :738 */
            verified_h = target_h;
            cache.len  = depth;                              /* :740 */
            depth      = 0u;                                 /* :742 */
            rc = trace_push(trace, verified, err);           /* :744 */
            if (rc != CMT_OK) {
                goto out;
            }
            continue;
        }
        if (verr.code == CMT_LIGHT_ERR_NEW_VAL_SET_CANT_BE_TRUSTED) { /* :746 */
            if (depth == cache.len - 1u) {                   /* :748 */
                cmt_light_provider_error_t perr;
                cmt_light_block_buf_t     *b;
                int64_t                    pivot =
                    skipping_pivot(verified_h, target_h);    /* :749-750 */

                b = pool_new(pool);
                if (b == NULL) {
                    rc = fault(err);
                    goto out;
                }
                rc = provider_light_block(c, source, pivot, b, &perr); /* :751 */
                if (rc == CMT_FAULT) {
                    rc = fault(err);
                    goto out;
                }
                if (rc != CMT_OK) {
                    if (provider_benign(perr.code)) {        /* :756-758 (Q2) */
                        if (err != NULL) {
                            err_clear(err);
                            err->code   = CMT_LIGHT_CLIENT_ERR_VERIFIER;
                            err->verify = verr;
                        }
                        rc = CMT_REJECT;
                        goto out;
                    }
                    rc = verification_failed(err, verified_h, pivot, /* :760-763 */
                                             CMT_LIGHT_CLIENT_REASON_PROVIDER,
                                             NULL, &perr);
                    goto out;
                }
                /* :754 AND :765 — the pivot is appended TWICE (Q1). */
                rc = lbvec_push(&cache, &b->lb);
                if (rc == CMT_OK) {
                    rc = lbvec_push(&cache, &b->lb);
                }
                if (rc != CMT_OK) {
                    rc = rc == CMT_REJECT
                         ? reject(err, CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE)
                         : fault(err);
                    goto out;
                }
            }
            depth++;                                         /* :767 */
            continue;
        }
        rc = verification_failed(err, verified_h, target_h,  /* :769-770 */
                                 CMT_LIGHT_CLIENT_REASON_VERIFIER, &verr,
                                 NULL);
        goto out;
    }
out:
    lbvec_free(&cache);
    return rc;
}

/*
 * cometbft@v0.38.26 light/client.go:775-828 — verifySkippingAgainstPrimary().
 * The re-run after a replacement (:813) is the loop here (D4); every
 * re-run's Verify calls count against `max_verify_steps`.
 */
static int verify_skipping_against_primary(cmt_light_client_t *c,
                                           const cmt_light_block_t *trusted,
                                           const cmt_light_block_t *new_lb,
                                           cmt_time_t now,
                                           cmt_light_client_error_t *err)
{
    pool_t                   pool   = { NULL, 0u, 0u };
    lbvec_t                  trace  = { NULL, 0u, 0u, 0u };
    const cmt_light_block_t *target = new_lb;
    cmt_light_client_error_t e;
    uint64_t                 steps  = 0u;
    int64_t                  target_h = 0;
    bool                     eq = false;
    int                      rc;

    trace.limit = c->o.max_trace_len;
    for (;;) {
        trace.len = 0u;
        if (lb_height(target, &target_h) != CMT_OK) {
            rc = fault(err);
            goto out;
        }
        rc = verify_skipping(c, &c->primary, trusted, target, now, /* :783 */
                             &trace, &pool, &steps, &e);
        if (rc == CMT_FAULT) {
            rc = fault(err);
            goto out;
        }
        if (rc == CMT_OK) {                                  /* :814-822 */
            rc = detect_divergence(c, &trace, now, err);
            goto out;
        }
        /* :785 `errors.Unwrap(err).(type)`. */
        if (e.code == CMT_LIGHT_CLIENT_ERR_VERIFIER) {
            /* A bare ErrNewValSetCantBeTrusted has no Unwrap: nil →
             * `case nil` with a nil trace (Q2). */
            trace.len = 0u;
            rc = detect_divergence(c, &trace, now, err);
            goto out;
        }
        if (e.code == CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED &&
            e.reason == CMT_LIGHT_CLIENT_REASON_VERIFIER &&
            e.verify.code == CMT_LIGHT_ERR_INVALID_HEADER) {     /* :786 */
            cmt_light_client_error_t e2;
            cmt_light_block_buf_t   *b;

            if (e.to == target_h) {                          /* :788-792 */
                QGP_LOG_DEBUG(LOG_TAG, "target header is invalid");
                break;
            }
            QGP_LOG_ERROR(LOG_TAG, "primary sent invalid header -> "
                          "replacing");                      /* :796 */
            b = pool_new(&pool);
            if (b == NULL) {
                rc = fault(err);
                goto out;
            }
            rc = find_new_primary(c, target_h, true, b, &e2); /* :798-802 */
            if (rc == CMT_FAULT) {
                rc = fault(err);
                goto out;
            }
            if (rc != CMT_OK) {
                break;
            }
            if (lb_hash_equal(&b->lb, target, &eq) != CMT_OK) {
                rc = fault(err);
                goto out;
            }
            if (!eq) {                                       /* :804-810 */
                QGP_LOG_ERROR(LOG_TAG, "replacement provider has a "
                              "different light block");
                break;
            }
            target = &b->lb;                                 /* :812-813 */
            continue;
        }
        break;                                               /* :823-824 */
    }
    /* Return the original error (:791, :801, :809, :824). */
    rc = CMT_REJECT;
    if (err != NULL) {
        *err = e;
    }
out:
    lbvec_free(&trace);
    pool_free(&pool);
    return rc;
}

/* client.go:566-573 — the verifyFunc of the configured mode. */
static int verify_func(cmt_light_client_t *c,
                       const cmt_light_block_t *trusted,
                       const cmt_light_block_t *new_lb, cmt_time_t now,
                       cmt_light_client_error_t *err)
{
    if (c->o.verification_mode == CMT_LIGHT_CLIENT_MODE_SEQUENTIAL) {
        return verify_sequential(c, trusted, new_lb, now, err);
    }
    return verify_skipping_against_primary(c, trusted, new_lb, now, err);
}

/*
 * cometbft@v0.38.26 light/client.go:930-979 — backwards(): walk down from
 * `trusted_header`, one parent at a time, to `new_header`'s height. The
 * re-run after a replacement (:973) is the loop here (D4); every fetch
 * counts against `max_backwards_steps` (D3). Two buffers alternate for
 * the walk and two for the target, so memory does not grow with the gap.
 * D9 (SECURITY): the header the walk reaches must BE the target.
 */
static int backwards(cmt_light_client_t *c, const cmt_header_t *trusted_header,
                     const cmt_header_t *new_header,
                     cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *walk[2] = { NULL, NULL };
    cmt_light_block_buf_t *tgt[2]  = { NULL, NULL };
    const cmt_header_t    *verified = trusted_header;        /* :939 */
    const cmt_header_t    *target   = new_header;
    const cmt_header_t    *interim;
    cmt_light_error_t      verr;
    uint8_t                ha[CMT_TMHASH_SIZE], hb[CMT_TMHASH_SIZE];
    size_t                 la = 0u, lb = 0u;
    size_t                 wnext = 0u, tnext = 0u;
    uint64_t               steps = 0u;
    int                    rc;

    if (verified == NULL || target == NULL) {
        return fault(err);
    }
    walk[0] = cmt_light_block_buf_new();
    walk[1] = cmt_light_block_buf_new();
    tgt[0]  = cmt_light_block_buf_new();
    tgt[1]  = cmt_light_block_buf_new();
    if (walk[0] == NULL || walk[1] == NULL || tgt[0] == NULL ||
        tgt[1] == NULL) {
        rc = fault(err);
        goto out;
    }

    while (verified->height > target->height) {              /* :943 */
        cmt_light_block_buf_t   *b = walk[wnext];
        cmt_light_client_error_t e;

        if (++steps > c->o.max_backwards_steps) {            /* D3 */
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_CAP_BACKWARDS_STEPS);
            goto out;
        }
        rc = light_block_from_primary(c, verified->height - 1, b, &e); /* :944-947 */
        if (rc != CMT_OK) {
            if (rc == CMT_FAULT) {
                rc = fault(err);
            } else if (err != NULL) {
                *err = e;            /* fmt.Errorf("…: %w", err) — the wrapped error */
            }
            goto out;
        }
        interim = b->lb.signed_header->header;               /* :948 */
        rc = cmt_light_verify_backwards(interim, verified,   /* :954 */
                                        c->o.block_protocol, &verr);
        if (rc == CMT_FAULT) {
            rc = fault(err);
            goto out;
        }
        if (rc != CMT_OK) {
            cmt_light_block_buf_t   *r = tgt[tnext];
            cmt_light_client_error_t e2;

            QGP_LOG_ERROR(LOG_TAG, "backwards verification failed, "
                          "replacing primary...");           /* :956 */
            rc = find_new_primary(c, target->height, true, r, &e2); /* :959-963 */
            if (rc == CMT_FAULT) {
                rc = fault(err);
                goto out;
            }
            if (rc == CMT_OK) {
                if (header_hash(r->lb.signed_header->header, ha, &la) != CMT_OK ||
                    header_hash(target, hb, &lb) != CMT_OK) {
                    rc = fault(err);
                    goto out;
                }
                if (bytes_equal(ha, la, hb, lb)) {           /* :966-970 */
                    target = r->lb.signed_header->header;    /* :973 */
                    tnext ^= 1u;
                    continue;
                }
                QGP_LOG_DEBUG(LOG_TAG, "replaced primary but new primary "
                              "has a different block");
            }
            if (err != NULL) {                               /* :962, :969 */
                err_clear(err);
                err->code   = CMT_LIGHT_CLIENT_ERR_VERIFIER;
                err->verify = verr;
            }
            rc = CMT_REJECT;
            goto out;
        }
        verified = interim;                                  /* :975 */
        wnext ^= 1u;
    }

    /* ⚠ WARNING — D9: the reference stops here (:978) without checking
     * that the header reached IS the target the primary sent first; a
     * primary answering the same height twice differently would get its
     * first answer stored unverified. Refused here. */
    if (header_hash(verified, ha, &la) != CMT_OK ||
        header_hash(target, hb, &lb) != CMT_OK) {
        rc = fault(err);
        goto out;
    }
    if (!bytes_equal(ha, la, hb, lb)) {
        QGP_LOG_ERROR(LOG_TAG, "backwards: the header reached at %lld is "
                      "not the target", (long long)verified->height);
        rc = verification_failed(err, trusted_header->height, target->height,
                                 CMT_LIGHT_CLIENT_REASON_TARGET_MISMATCH,
                                 NULL, NULL);
        goto out;
    }
    rc = CMT_OK;
out:
    cmt_light_block_buf_free(walk[0]);
    cmt_light_block_buf_free(walk[1]);
    cmt_light_block_buf_free(tgt[0]);
    cmt_light_block_buf_free(tgt[1]);
    return rc;
}

/*
 * cometbft@v0.38.26 light/client.go:558-610 — verifyLightBlock(): choose
 * forwards (:582-583), backwards (:586-592) or between (:595-601), and on
 * success save (:608-609). D7: no trusted block is CMT_FAULT.
 */
static int verify_light_block(cmt_light_client_t *c,
                              const cmt_light_block_t *new_lb,
                              cmt_time_t now, cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *b = NULL;
    int64_t                first = -1, new_h = 0, latest_h = 0;
    bool                   found = false;
    int                    rc;

    if (c->latest == NULL || lb_height(&c->latest->lb, &latest_h) != CMT_OK ||
        lb_height(new_lb, &new_h) != CMT_OK) {
        return fault(err);
    }
    QGP_LOG_INFO(LOG_TAG, "VerifyHeader %lld", (long long)new_h); /* :559 */

    rc = c->store.first_light_block_height(c->store.ctx, &first); /* :575-578 */
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }

    if (new_h >= latest_h) {                                 /* :582-583 */
        rc = verify_func(c, &c->latest->lb, new_lb, now, err);
    } else {
        b = cmt_light_block_buf_new();
        if (b == NULL) {
            return fault(err);
        }
        if (new_h < first) {                                 /* :586-592 */
            rc = c->store.light_block(c->store.ctx, first, b, &found);
            if (rc == CMT_OK && !found) {
                rc = reject(err, CMT_LIGHT_CLIENT_ERR_NOT_FOUND);
            } else if (rc != CMT_OK) {
                rc = store_rc(rc, err);
            } else if (b->lb.signed_header == NULL) {
                rc = fault(err);     /* a stored row always has one (D7 of the store) */
            } else {
                rc = backwards(c, b->lb.signed_header->header,
                               new_lb->signed_header->header, err);
            }
        } else {                                             /* :595-601 */
            rc = c->store.light_block_before(c->store.ctx, new_h, b, &found);
            if (rc == CMT_OK && !found) {
                rc = reject(err, CMT_LIGHT_CLIENT_ERR_NOT_FOUND);
            } else if (rc != CMT_OK) {
                rc = store_rc(rc, err);
            } else {
                rc = verify_func(c, &b->lb, new_lb, now, err);
            }
        }
    }
    cmt_light_block_buf_free(b);
    if (rc != CMT_OK) {                                      /* :603-606 */
        QGP_LOG_ERROR(LOG_TAG, "can't verify %lld", (long long)new_h);
        return rc;
    }
    return update_trusted_light_block(c, new_lb, err);       /* :609 */
}

/* ══ init ═════════════════════════════════════════════════════════════ */

/*
 * Kurultay #25 item 9 — the explicit agreement check that REPLACES
 * compareFirstLightBlockWithWitnesses (client.go:1129-1190; D1). The
 * rules R1-R6 are written out in cmt_light_client.h; each is marked at
 * its line below.
 */
static int init_agreement(cmt_light_client_t *c, const cmt_light_block_t *l,
                          cmt_light_client_error_t *err)
{
    const peer_t              **agreed = NULL;
    size_t                     *to_remove = NULL;
    size_t                      n_agreed = 0u, n_remove = 0u, i, k;
    cmt_light_block_buf_t      *b = NULL;
    cmt_light_provider_error_t  perr;
    int64_t                     height = 0;
    bool                        eq = false;
    int                         rc;

    if (c->n_witnesses == 0u) {                              /* :1138-1140 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);
    }
    if (lb_height(l, &height) != CMT_OK) {
        return fault(err);
    }
    agreed    = malloc((c->n_witnesses + 1u) * sizeof(*agreed));
    to_remove = malloc(c->n_witnesses * sizeof(*to_remove));
    b         = cmt_light_block_buf_new();
    if (agreed == NULL || to_remove == NULL || b == NULL) {
        rc = fault(err);
        goto out;
    }
    agreed[n_agreed++] = &c->primary;          /* R2, R6: the primary counts */

    for (i = 0; i < c->n_witnesses; i++) {     /* R1: the cohort, index order */
        const peer_t *w = &c->witnesses[i];
        bool          dup = false;

        rc = provider_light_block(c, w, height, b, &perr); /* R1: the same height */
        if (rc == CMT_FAULT) {
            rc = fault(err);
            goto out;
        }
        if (rc != CMT_OK) {
            if (provider_benign(perr.code)) {                /* R4 */
                QGP_LOG_INFO(LOG_TAG, "init: witness #%zu did not answer "
                             "(%d) — not counted", i, perr.code);
                continue;
            }
            QGP_LOG_INFO(LOG_TAG, "init: witness #%zu sent an invalid "
                         "light block, removing", i);        /* R4, :1161-1166 */
            to_remove[n_remove++] = i;
            continue;
        }
        if (lb_hash_equal(&b->lb, l, &eq) != CMT_OK) {
            rc = fault(err);
            goto out;
        }
        if (!eq) {                                           /* R5, :1156-1160 */
            QGP_LOG_ERROR(LOG_TAG, "init: witness #%zu reports a "
                          "conflicting header", i);
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS);
            if (err != NULL) {
                err->witness_index = i;
            }
            goto out;
        }
        if (!priorities_equal(l->validator_set, b->lb.validator_set)) {
            QGP_LOG_ERROR(LOG_TAG, "init: witness #%zu reports conflicting "
                          "proposer priorities", i);         /* R5, R3, :1167-1171 */
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE);
            if (err != NULL) {
                err->witness_index = i;
            }
            goto out;
        }
        for (k = 0; k < n_agreed; k++) {                     /* R2: dedup */
            if (bytes_equal(agreed[k]->id, agreed[k]->id_len,
                            w->id, w->id_len)) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            agreed[n_agreed++] = w;
        }
    }

    if (remove_witnesses(c, to_remove, n_remove) != CMT_OK) {   /* :1184-1187 */
        QGP_LOG_ERROR(LOG_TAG, "failed to remove %zu witnesses", n_remove);
    }
    if (n_agreed < c->o.min_init_agreement) {                /* R6 */
        QGP_LOG_ERROR(LOG_TAG, "init: %zu distinct providers agree, %zu "
                      "required", n_agreed, c->o.min_init_agreement);
        rc = reject(err, CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT);
        if (err != NULL) {
            err->agreeing = n_agreed;
        }
        goto out;
    }
    rc = CMT_OK;
out:
    free(agreed);
    free(to_remove);
    cmt_light_block_buf_free(b);
    return rc;
}

/* cometbft@v0.38.26 light/client.go:360-393 — initializeWithTrustOptions(). */
static int initialize_with_trust_options(cmt_light_client_t *c,
                                         const cmt_light_trust_options_t *t,
                                         cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *b;
    const cmt_light_block_t *l;
    cmt_vs_error_t         vserr;
    uint8_t                h[CMT_TMHASH_SIZE];
    size_t                 hlen = 0u;
    int                    rc;

    b = cmt_light_block_buf_new();
    if (b == NULL) {
        return fault(err);
    }
    l = &b->lb;
    /* 1) Fetch and verify the light block (:363-367). */
    rc = light_block_from_primary(c, t->height, b, err);
    if (rc != CMT_OK) {
        goto out;
    }
    /* :369-374 — ValidateBasic; no time check here (the reference's
     * NOTE: "h.Time is not being checked against time.Now()"). */
    rc = cmt_light_block_validate_basic(l, c->chain_id, c->chain_id_len,
                                        c->o.block_protocol);
    if (rc != CMT_OK) {
        rc = rc == CMT_REJECT
             ? reject(err, CMT_LIGHT_CLIENT_ERR_INVALID_LIGHT_BLOCK)
             : fault(err);
        goto out;
    }
    if (lb_hash(l, h, &hlen) != CMT_OK) {
        rc = fault(err);
        goto out;
    }
    if (!bytes_equal(t->hash, t->hash_len, h, hlen)) {       /* :376-378 */
        rc = reject(err, CMT_LIGHT_CLIENT_ERR_HASH_MISMATCH);
        goto out;
    }
    /* 2) Ensure that +2/3 of validators signed correctly (:380-384). */
    memset(&vserr, 0, sizeof(vserr));
    rc = cmt_validator_set_verify_commit_light(l->validator_set, c->chain_id,
                                               c->chain_id_len,
                                               &l->signed_header->commit->block_id,
                                               l->signed_header->header->height,
                                               l->signed_header->commit,
                                               &vserr);
    if (rc != CMT_OK) {
        if (rc == CMT_REJECT) {
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_INVALID_COMMIT);
            if (err != NULL) {
                err->verify.reason = vserr;
            }
        } else {
            rc = fault(err);
        }
        goto out;
    }
    /* 3) Cross-verify with witnesses (:386-389) — item 9, D1. */
    rc = init_agreement(c, l, err);
    if (rc != CMT_OK) {
        goto out;
    }
    /* 4) Persist and continue (:391-392). */
    rc = update_trusted_light_block(c, l, err);
out:
    cmt_light_block_buf_free(b);
    return rc;
}

/* cometbft@v0.38.26 light/client.go:285-358 — checkTrustedHeaderUsingOptions(). */
static int check_trusted_header_using_options(cmt_light_client_t *c,
                                              const cmt_light_trust_options_t *t,
                                              cmt_light_client_error_t *err)
{
    uint8_t ph[CMT_TMHASH_SIZE], lh[CMT_TMHASH_SIZE];
    size_t  plen = 0u, llen = 0u;
    int64_t latest_h = 0;
    int     rc;

    if (c->latest == NULL || lb_height(&c->latest->lb, &latest_h) != CMT_OK) {
        return fault(err);
    }
    if (t->height > latest_h) {                              /* :306-311 */
        cmt_light_block_buf_t *b = cmt_light_block_buf_new();

        if (b == NULL) {
            return fault(err);
        }
        rc = light_block_from_primary(c, latest_h, b, err);
        if (rc == CMT_OK && lb_hash(&b->lb, ph, &plen) != CMT_OK) {
            rc = fault(err);
        }
        cmt_light_block_buf_free(b);
        if (rc != CMT_OK) {
            return rc;
        }
    } else if (t->height == latest_h) {                      /* :312-313 */
        if (t->hash_len > sizeof(ph)) {
            return fault(err);                /* ValidateBasic passed: cannot */
        }
        memcpy(ph, t->hash, t->hash_len);
        plen = t->hash_len;
    } else {                                                 /* :314-337 */
        QGP_LOG_INFO(LOG_TAG, "client initialized with old header %lld "
                     "(trusted %lld)", (long long)t->height,
                     (long long)latest_h);
        if (c->o.confirm == NULL ||
            c->o.confirm(c->o.confirm_ctx, CMT_LIGHT_CLIENT_ACTION_ROLLBACK,
                         t->height, latest_h)) {             /* :324 */
            rc = cleanup_after(c, t->height, err);           /* :325-329 */
            if (rc != CMT_OK) {
                return rc;
            }
            QGP_LOG_INFO(LOG_TAG, "rolled back to older header %lld",
                         (long long)t->height);
        } else {
            return CMT_OK;                                   /* :333-335 */
        }
        if (t->hash_len > sizeof(ph)) {
            return fault(err);
        }
        memcpy(ph, t->hash, t->hash_len);                    /* :337 */
        plen = t->hash_len;
    }

    if (c->latest == NULL || lb_hash(&c->latest->lb, lh, &llen) != CMT_OK ||
        lb_height(&c->latest->lb, &latest_h) != CMT_OK) {
        return fault(err);                                   /* D7 */
    }
    if (!bytes_equal(ph, plen, lh, llen)) {                  /* :340-355 */
        QGP_LOG_INFO(LOG_TAG, "previously trusted header's hash does not "
                     "match the primary's");
        if (c->o.confirm == NULL ||
            c->o.confirm(c->o.confirm_ctx,
                         CMT_LIGHT_CLIENT_ACTION_CLEANUP_ALL, latest_h, 0)) {
            rc = cmt_light_client_cleanup(c);                /* :348-351 */
            return rc == CMT_OK ? CMT_OK : store_rc(rc, err);
        }
        return reject(err, CMT_LIGHT_CLIENT_ERR_REFUSED_CLEANUP); /* :353 */
    }
    return CMT_OK;
}

/* ══ public API ═══════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 light/trust_options.go:38-53 — ValidateBasic(). */
int cmt_light_trust_options_validate_basic(const cmt_light_trust_options_t *o)
{
    if (o == NULL) {
        return CMT_FAULT;
    }
    if (o->period <= 0) {                                    /* :40-42 */
        return CMT_REJECT;
    }
    if (o->height <= 0) {                                    /* :43-45 */
        return CMT_REJECT;
    }
    if (o->hash_len != (size_t)CMT_TMHASH_SIZE) {            /* :46-52 */
        return CMT_REJECT;
    }
    if (o->hash == NULL) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* client.go:220-235 — the defaults of NewClientFromTrustedStore. */
void cmt_light_client_options_default(cmt_light_client_options_t *o)
{
    if (o == NULL) {
        return;
    }
    memset(o, 0, sizeof(*o));
    o->verification_mode  = CMT_LIGHT_CLIENT_MODE_SKIPPING;      /* :223 */
    o->trust_level        = CMT_LIGHT_DEFAULT_TRUST_LEVEL;       /* :224 */
    o->max_retry_attempts = CMT_LIGHT_CLIENT_DEFAULT_MAX_RETRY_ATTEMPTS; /* :225 */
    o->max_clock_drift    = CMT_LIGHT_CLIENT_DEFAULT_MAX_CLOCK_DRIFT;    /* :226 */
    o->max_block_lag      = CMT_LIGHT_CLIENT_DEFAULT_MAX_BLOCK_LAG;      /* :227 */
    o->pruning_size       = CMT_LIGHT_CLIENT_DEFAULT_PRUNING_SIZE;       /* :231 */
    o->confirm            = NULL;                                /* :232 */
    o->confirm_ctx        = NULL;
    o->block_protocol     = CMT_BLOCK_PROTOCOL;
    o->min_init_agreement = CMT_LIGHT_CLIENT_MIN_INIT_AGREEMENT;
}

static bool peer_rows_ok(const cmt_light_client_peer_t *p)
{
    return p->provider.chain_id != NULL && p->provider.light_block != NULL &&
           p->provider.report_evidence != NULL;
}

static bool peer_id_ok(const cmt_light_client_peer_t *p)
{
    return p->id != NULL && p->id_len > 0u &&
           p->id_len <= (size_t)CMT_LIGHT_CLIENT_PEER_ID_MAX;
}

static void peer_set(peer_t *dst, const cmt_light_client_peer_t *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->p      = src->provider;
    memcpy(dst->id, src->id, src->id_len);
    dst->id_len = src->id_len;
}

/* cometbft@v0.38.26 light/client.go:209-264 — NewClientFromTrustedStore(). */
int cmt_light_client_new_from_trusted_store(
        const uint8_t *chain_id, size_t chain_id_len,
        int64_t trusting_period,
        const cmt_light_client_peer_t *primary,
        const cmt_light_client_peer_t *witnesses, size_t n_witnesses,
        const cmt_light_store_t *store,
        const cmt_light_client_options_t *opts,
        cmt_light_client_t **out,
        cmt_light_client_error_t *err)
{
    const cmt_light_client_options_t *o = opts;
    cmt_light_client_t               *c;
    size_t                            i;
    int                               rc;

    err_clear(err);
    if (out == NULL) {
        return CMT_FAULT;
    }
    *out = NULL;
    if ((chain_id == NULL && chain_id_len > 0u) || primary == NULL ||
        (witnesses == NULL && n_witnesses > 0u) || store == NULL ||
        opts == NULL) {
        return CMT_FAULT;
    }
    if (store->save_light_block == NULL ||
        store->delete_light_block == NULL || store->light_block == NULL ||
        store->last_light_block_height == NULL ||
        store->first_light_block_height == NULL ||
        store->light_block_before == NULL || store->prune == NULL ||
        store->size == NULL || !peer_rows_ok(primary)) {
        return CMT_FAULT;
    }
    for (i = 0; i < n_witnesses; i++) {
        if (!peer_rows_ok(&witnesses[i])) {
            return CMT_FAULT;
        }
    }

    /* The options (:237-239) and their domains (D3, item 9). */
    if (chain_id_len > (size_t)CMT_PB_CHAINID_MAX ||
        (o->verification_mode != CMT_LIGHT_CLIENT_MODE_SEQUENTIAL &&
         o->verification_mode != CMT_LIGHT_CLIENT_MODE_SKIPPING) ||
        o->max_trace_len == 0u || o->max_verify_steps == 0u ||
        o->max_skipping_cache == 0u || o->max_backwards_steps == 0u ||
        o->min_init_agreement < (size_t)CMT_LIGHT_CLIENT_MIN_INIT_AGREEMENT ||
        !peer_id_ok(primary)) {
        return reject(err, CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS);
    }
    for (i = 0; i < n_witnesses; i++) {
        if (!peer_id_ok(&witnesses[i])) {
            return reject(err, CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS);
        }
    }

    if (n_witnesses == 0u) {                                 /* :241-244 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);
    }
    for (i = 0; i < n_witnesses; i++) {                      /* :246-252 (Q4) */
        const uint8_t *wc = NULL;
        size_t         wl = 0u;

        rc = witnesses[i].provider.chain_id(witnesses[i].provider.ctx,
                                            &wc, &wl);
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        if (!bytes_equal(wc, wl, chain_id, chain_id_len)) {
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_WITNESS_WRONG_CHAIN);
            if (err != NULL) {
                err->witness_index = i;
            }
            return rc;
        }
    }
    if (cmt_light_validate_trust_level(o->trust_level) != CMT_OK) { /* :254-257 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_LEVEL);
    }

    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return CMT_FAULT;
    }
    c->witnesses_cap = n_witnesses + 1u;                     /* :1086 */
    c->witnesses     = calloc(c->witnesses_cap, sizeof(*c->witnesses));
    if (c->witnesses == NULL) {
        free(c);
        return CMT_FAULT;
    }
    if (chain_id_len > 0u) {
        memcpy(c->chain_id, chain_id, chain_id_len);         /* :221 */
    }
    c->chain_id_len    = chain_id_len;
    c->trusting_period = trusting_period;                    /* :222 */
    c->o               = *o;
    peer_set(&c->primary, primary);                          /* :228 */
    for (i = 0; i < n_witnesses; i++) {                      /* :229 */
        peer_set(&c->witnesses[i], &witnesses[i]);
    }
    c->n_witnesses = n_witnesses;
    c->store       = *store;                                 /* :230 */

    rc = restore_trusted_light_block(c, err);                /* :259-261 */
    if (rc != CMT_OK) {
        cmt_light_client_free(c);
        return rc;
    }
    *out = c;
    return CMT_OK;
}

/* cometbft@v0.38.26 light/client.go:164-207 — NewClient(). */
int cmt_light_client_new(const uint8_t *chain_id, size_t chain_id_len,
                         const cmt_light_trust_options_t *trust,
                         const cmt_light_client_peer_t *primary,
                         const cmt_light_client_peer_t *witnesses,
                         size_t n_witnesses,
                         const cmt_light_store_t *store,
                         const cmt_light_client_options_t *opts,
                         cmt_light_client_t **out,
                         cmt_light_client_error_t *err)
{
    cmt_light_client_t *c = NULL;
    int64_t             latest_h = 0;
    int                 rc;

    err_clear(err);
    if (out == NULL || trust == NULL) {
        return CMT_FAULT;
    }
    *out = NULL;
    rc = cmt_light_trust_options_validate_basic(trust);      /* :183-185 */
    if (rc != CMT_OK) {
        return rc == CMT_REJECT
               ? reject(err, CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_OPTIONS)
               : CMT_FAULT;
    }
    rc = cmt_light_client_new_from_trusted_store(chain_id, chain_id_len, /* :187-190 */
                                                 trust->period, primary,
                                                 witnesses, n_witnesses,
                                                 store, opts, &c, err);
    if (rc != CMT_OK) {
        return rc;
    }
    if (c->latest != NULL) {                                 /* :192-197 */
        QGP_LOG_INFO(LOG_TAG, "checking trusted light block using options");
        rc = check_trusted_header_using_options(c, trust, err);
        if (rc != CMT_OK) {
            cmt_light_client_free(c);
            return rc;
        }
    }
    if (c->latest != NULL && lb_height(&c->latest->lb, &latest_h) != CMT_OK) {
        cmt_light_client_free(c);
        return fault(err);
    }
    if (c->latest == NULL || latest_h < trust->height) {     /* :199-204 */
        QGP_LOG_INFO(LOG_TAG, "downloading trusted light block using options");
        rc = initialize_with_trust_options(c, trust, err);
        if (rc != CMT_OK) {
            cmt_light_client_free(c);
            return rc;
        }
    }
    *out = c;
    return CMT_OK;
}

void cmt_light_client_free(cmt_light_client_t *c)
{
    if (c == NULL) {
        return;
    }
    cmt_light_block_buf_free(c->latest);
    free(c->witnesses);
    free(c);
}

/* cometbft@v0.38.26 light/client.go:412-431 — compareWithLatestHeight(). */
static int compare_with_latest_height(cmt_light_client_t *c, int64_t height,
                                      int64_t *out,
                                      cmt_light_client_error_t *err)
{
    int64_t latest = -1;
    int     rc;

    rc = c->store.last_light_block_height(c->store.ctx, &latest); /* :413-416 */
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }
    if (latest == -1) {                                      /* :417-419 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_NO_HEADERS);
    }
    if (height > latest) {                                   /* :422-423 (Q8) */
        return reject(err, CMT_LIGHT_CLIENT_ERR_UNVERIFIED_HEIGHT);
    }
    if (height == 0) {                                       /* :424-425 */
        *out = latest;
        return CMT_OK;
    }
    if (height < 0) {                                        /* :426-427 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_BAD_HEIGHT);
    }
    *out = height;                                           /* :430 */
    return CMT_OK;
}

/* cometbft@v0.38.26 light/client.go:395-410 — TrustedLightBlock(). */
int cmt_light_client_trusted_light_block(cmt_light_client_t *c,
                                         int64_t height,
                                         cmt_light_block_buf_t *out,
                                         cmt_light_client_error_t *err)
{
    bool found = false;
    int  rc;

    err_clear(err);
    if (c == NULL || out == NULL) {
        return CMT_FAULT;
    }
    (void)cmt_light_block_buf_reset(out);
    rc = compare_with_latest_height(c, height, &height, err); /* :405-408 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = c->store.light_block(c->store.ctx, height, out, &found); /* :409 */
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }
    if (!found) {
        return reject(err, CMT_LIGHT_CLIENT_ERR_NOT_FOUND);
    }
    return CMT_OK;
}

/* client.go:830-836 — LastTrustedHeight(). */
int cmt_light_client_last_trusted_height(cmt_light_client_t *c, int64_t *out)
{
    if (c == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return c->store.last_light_block_height(c->store.ctx, out);
}

/* client.go:838-844 — FirstTrustedHeight(). */
int cmt_light_client_first_trusted_height(cmt_light_client_t *c, int64_t *out)
{
    if (c == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return c->store.first_light_block_height(c->store.ctx, out);
}

/* cometbft@v0.38.26 light/client.go:433-462 — Update(now). */
int cmt_light_client_update(cmt_light_client_t *c, cmt_time_t now,
                            cmt_light_block_buf_t *out, bool *advanced,
                            cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *b;
    int64_t                last = -1, h = 0;
    int                    rc;

    err_clear(err);
    if (c == NULL || out == NULL || advanced == NULL) {
        return CMT_FAULT;
    }
    *advanced = false;
    (void)cmt_light_block_buf_reset(out);
    rc = c->store.last_light_block_height(c->store.ctx, &last); /* :437-440 */
    if (rc != CMT_OK) {
        return store_rc(rc, err);
    }
    if (last == -1) {                                        /* :442-445 */
        return CMT_OK;
    }
    b = cmt_light_block_buf_new();
    if (b == NULL) {
        return CMT_FAULT;
    }
    rc = light_block_from_primary(c, 0, b, err);             /* :447-450 */
    if (rc == CMT_OK && lb_height(&b->lb, &h) != CMT_OK) {
        rc = fault(err);
    }
    if (rc == CMT_OK && h > last) {                          /* :452-459 */
        rc = verify_light_block(c, &b->lb, now, err);
        if (rc == CMT_OK) {
            rc = buf_copy(out, &b->lb) == CMT_OK ? CMT_OK : fault(err);
            if (rc == CMT_OK) {
                QGP_LOG_INFO(LOG_TAG, "advanced to new state %lld",
                             (long long)h);
                *advanced = true;
            }
        }
    }
    cmt_light_block_buf_free(b);
    return rc;                                               /* :461 */
}

/* cometbft@v0.38.26 light/client.go:464-494 — VerifyLightBlockAtHeight(). */
int cmt_light_client_verify_light_block_at_height(cmt_light_client_t *c,
                                                  int64_t height,
                                                  cmt_time_t now,
                                                  cmt_light_block_buf_t *out,
                                                  cmt_light_client_error_t *err)
{
    cmt_light_block_buf_t *b;
    int                    rc;

    err_clear(err);
    if (c == NULL || out == NULL) {
        return CMT_FAULT;
    }
    (void)cmt_light_block_buf_reset(out);
    if (height <= 0) {                                       /* :475-477 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_BAD_HEIGHT);
    }
    rc = cmt_light_client_trusted_light_block(c, height, out, NULL); /* :479-485 */
    if (rc == CMT_OK) {
        QGP_LOG_INFO(LOG_TAG, "header %lld has already been verified",
                     (long long)height);
        return CMT_OK;
    }
    if (rc == CMT_FAULT) {                                   /* D11 */
        return CMT_FAULT;
    }
    b = cmt_light_block_buf_new();
    if (b == NULL) {
        return CMT_FAULT;
    }
    rc = light_block_from_primary(c, height, b, err);        /* :487-491 */
    if (rc == CMT_OK) {
        rc = verify_light_block(c, &b->lb, now, err);        /* :493 */
    }
    if (rc == CMT_OK && buf_copy(out, &b->lb) != CMT_OK) {   /* D10 */
        rc = fault(err);
    }
    cmt_light_block_buf_free(b);
    return rc;
}

size_t cmt_light_client_witness_count(const cmt_light_client_t *c)
{
    return c == NULL ? 0u : c->n_witnesses;
}

int cmt_light_client_primary_id(const cmt_light_client_t *c,
                                const uint8_t **id, size_t *id_len)
{
    if (c == NULL || id == NULL || id_len == NULL) {
        return CMT_FAULT;
    }
    *id     = c->primary.id;
    *id_len = c->primary.id_len;
    return CMT_OK;
}

int cmt_light_client_witness_id(const cmt_light_client_t *c, size_t i,
                                const uint8_t **id, size_t *id_len)
{
    if (c == NULL || id == NULL || id_len == NULL) {
        return CMT_FAULT;
    }
    if (i >= c->n_witnesses) {
        return CMT_REJECT;
    }
    *id     = c->witnesses[i].id;
    *id_len = c->witnesses[i].id_len;
    return CMT_OK;
}
