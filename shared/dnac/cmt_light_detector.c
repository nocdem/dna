/**
 * @file shared/dnac/cmt_light_detector.c
 * @brief cometbft @v0.38.26 light/detector.go — see cmt_light_detector.h
 *        for the mapping, the deviations (DD1-DD10) and the reproduced
 *        quirks (Q-D1 .. Q-D6).
 *
 * Every function names the reference lines it ports. Ownership: the
 * primary's trace belongs to the caller; one comparison buffer serves
 * every witness in turn; each conflicting witness gets its own pool for
 * the two examines, freed before the next witness; an attack's record
 * holds deep copies and is handed to the client (`c->attack`).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define CMT_LIGHT_CLIENT_INTERNAL
#include "dnac/cmt_light_detector.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_block.h"

#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_LIGHT_DETECTOR"

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

static int fault(cmt_light_client_error_t *err)
{
    err_clear(err);
    return CMT_FAULT;
}

/* The client's D3 caps (DD5). */
static bool is_cap(int code)
{
    return code == CMT_LIGHT_CLIENT_ERR_CAP_TRACE ||
           code == CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS ||
           code == CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE ||
           code == CMT_LIGHT_CLIENT_ERR_CAP_BACKWARDS_STEPS;
}

static bool hdr_bytes_equal(const uint8_t *a, size_t alen,
                            const uint8_t *b, size_t blen)
{
    return alen == blen && (alen == 0u || memcmp(a, b, alen) == 0);
}

/* The header of a light block — a Go nil dereference when absent (DD6). */
static const cmt_header_t *lb_header(const cmt_light_block_t *lb)
{
    if (lb == NULL || lb->signed_header == NULL) {
        return NULL;
    }
    return lb->signed_header->header;
}

/* ══ K25-3 (DD1) ══════════════════════════════════════════════════════ */

/* K25-3 — the full proposer-priority vector, in validator order, length
 * included (instead of ProposerPriorityHash, detector.go:211-216, whose
 * hash writes every varint at offset 0, types/validator_set.go:392-398).
 * Moved here from cmt_light_client.c (package 2), body unchanged; the
 * client's init agreement rule (item 9 R3) calls this one. */
bool cmt_light_priorities_equal(const cmt_validator_set_t *a,
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

/* ══ the local record (DD3) ═══════════════════════════════════════════ */

/* cometbft@v0.38.26 types/evidence.go:304-310 — ConflictingHeaderIsInvalid. */
bool cmt_light_conflicting_header_is_invalid(const cmt_header_t *t,
                                             const cmt_header_t *c)
{
    if (t == NULL || c == NULL) {
        return false;
    }
    return !hdr_bytes_equal(t->validators_hash, t->validators_hash_len,
                            c->validators_hash, c->validators_hash_len) ||
           !hdr_bytes_equal(t->next_validators_hash, t->next_validators_hash_len,
                            c->next_validators_hash, c->next_validators_hash_len) ||
           !hdr_bytes_equal(t->consensus_hash, t->consensus_hash_len,
                            c->consensus_hash, c->consensus_hash_len) ||
           !hdr_bytes_equal(t->app_hash, t->app_hash_len,
                            c->app_hash, c->app_hash_len) ||
           !hdr_bytes_equal(t->last_results_hash, t->last_results_hash_len,
                            c->last_results_hash, c->last_results_hash_len);
}

void cmt_light_attack_evidence_release(cmt_light_attack_evidence_t *ev)
{
    if (ev == NULL) {
        return;
    }
    cmt_light_block_buf_free(ev->conflicting_block);
    free(ev->byzantine_validators);
    memset(ev, 0, sizeof(*ev));
}

void cmt_light_attack_record_free(cmt_light_attack_record_t *r)
{
    if (r == NULL) {
        return;
    }
    cmt_light_attack_evidence_release(&r->against_primary);
    cmt_light_attack_evidence_release(&r->against_witness);
    free(r);
}

/* Append a copy of `v` to `list` (capacity CMT_VALSET_MAX). */
static int byz_push(cmt_validator_t *list, size_t *n, const cmt_validator_t *v)
{
    if (*n >= (size_t)CMT_VALSET_MAX) {
        return CMT_FAULT;
    }
    if (cmt_validator_copy(v, &list[*n]) != CMT_OK) {
        return CMT_FAULT;
    }
    (*n)++;
    return CMT_OK;
}

/*
 * cometbft@v0.38.26 types/evidence.go:252-298 — GetByzantineValidators(
 * commonVals, trusted). `list` has CMT_VALSET_MAX slots; on CMT_OK it holds
 * `*n` validators in ValidatorsByVotingPower order, `*kind` names the
 * branch taken and `*n_unknown` counts the equivocation-branch signers
 * that are not in the conflicting set (DD6).
 */
static int get_byzantine_validators(const cmt_light_block_t *conflicting,
                                    const cmt_validator_set_t *common_vals,
                                    const cmt_signed_header_t *trusted,
                                    cmt_validator_t *list, size_t *n,
                                    int *kind, size_t *n_unknown)
{
    const cmt_commit_t *cc = conflicting->signed_header->commit;
    const cmt_commit_t *tc = trusted->commit;
    cmt_validator_t   **ptrs;
    cmt_validator_t    *sorted;
    size_t              i;
    int                 rc;

    *n         = 0u;
    *n_unknown = 0u;
    if (cc == NULL || tc == NULL || trusted->header == NULL ||
        cc->signatures_len > (size_t)CMT_VALSET_MAX ||
        (cc->signatures_len > 0u && cc->signatures == NULL)) {
        return CMT_FAULT;
    }
    if (cmt_light_conflicting_header_is_invalid(trusted->header,      /* :257 */
                                                conflicting->signed_header->header)) {
        *kind = CMT_LIGHT_ATTACK_LUNATIC;
        for (i = 0; i < cc->signatures_len; i++) {                    /* :258 */
            const cmt_commit_sig_t *s = &cc->signatures[i];
            cmt_validator_t         val;
            int32_t                 idx = -1;

            if (s->block_id_flag != (int32_t)CMT_BLOCK_ID_FLAG_COMMIT) { /* :259-261 */
                continue;
            }
            if (cmt_validator_set_get_by_address(common_vals,         /* :263 */
                                                 s->validator_address,
                                                 s->validator_address_len,
                                                 &idx, &val) != CMT_OK) {
                return CMT_FAULT;
            }
            if (idx < 0) {                                            /* :264-267 */
                continue;
            }
            if (byz_push(list, n, &val) != CMT_OK) {                  /* :268 */
                return CMT_FAULT;
            }
        }
    } else if (tc->round == cc->round) {                              /* :272 */
        *kind = CMT_LIGHT_ATTACK_EQUIVOCATION;
        if (conflicting->validator_set == NULL) {
            return CMT_FAULT;
        }
        for (i = 0; i < cc->signatures_len; i++) {                    /* :277 */
            const cmt_commit_sig_t *a = &cc->signatures[i];
            cmt_validator_t         val;
            int32_t                 idx = -1;

            if (a->block_id_flag != (int32_t)CMT_BLOCK_ID_FLAG_COMMIT) { /* :279-281 */
                continue;
            }
            if (i >= tc->signatures_len || tc->signatures == NULL) {
                return CMT_FAULT;              /* :283 index panic (DD6) */
            }
            if (tc->signatures[i].block_id_flag !=                    /* :283-286 */
                (int32_t)CMT_BLOCK_ID_FLAG_COMMIT) {
                continue;
            }
            if (cmt_validator_set_get_by_address(conflicting->validator_set, /* :288 */
                                                 a->validator_address,
                                                 a->validator_address_len,
                                                 &idx, &val) != CMT_OK) {
                return CMT_FAULT;
            }
            if (idx < 0) {
                /* :289 — Go appends a nil and the sort at :291 panics.
                 * Reachable: a signature past the commit check's 2/3
                 * early stop (types/validation.go:289-291, :401-403) is
                 * never checked, so its address may name nobody. Skipped
                 * and counted (DD6, BUGS Z-42). */
                (*n_unknown)++;
                continue;
            }
            if (byz_push(list, n, &val) != CMT_OK) {                  /* :289 */
                return CMT_FAULT;
            }
        }
    } else {
        *kind = CMT_LIGHT_ATTACK_AMNESIA;                             /* :294-297 */
        return CMT_OK;
    }
    if (*n < 2u) {
        return CMT_OK;
    }
    /* :270 / :291 — sort.Sort(ValidatorsByVotingPower(validators)), over
     * pointers, then written back in that order. */
    ptrs   = malloc(*n * sizeof(*ptrs));
    sorted = malloc(*n * sizeof(*sorted));
    if (ptrs == NULL || sorted == NULL) {
        free(ptrs);
        free(sorted);
        return CMT_FAULT;
    }
    for (i = 0; i < *n; i++) {
        ptrs[i] = &list[i];
    }
    cmt_validators_sort_by_voting_power(ptrs, *n);
    rc = CMT_OK;
    for (i = 0; i < *n && rc == CMT_OK; i++) {
        rc = cmt_validator_copy(ptrs[i], &sorted[i]);
    }
    for (i = 0; i < *n && rc == CMT_OK; i++) {
        rc = cmt_validator_copy(&sorted[i], &list[i]);
    }
    free(ptrs);
    free(sorted);
    return rc == CMT_OK ? CMT_OK : CMT_FAULT;
}

/* cometbft@v0.38.26 light/detector.go:423-439 — newLightClientAttackEvidence
 * (DD3: a local record). */
int cmt_light_attack_evidence_build(const cmt_light_block_t *conflicted,
                                    const cmt_light_block_t *trusted,
                                    const cmt_light_block_t *common,
                                    cmt_light_attack_evidence_t *out)
{
    const cmt_light_block_t *src;
    cmt_validator_t         *list = NULL;
    size_t                   n = 0u, n_unknown = 0u;
    int                      kind = 0;
    int64_t                  total = 0;

    if (out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    if (lb_header(conflicted) == NULL || lb_header(trusted) == NULL ||
        lb_header(common) == NULL || trusted->signed_header->commit == NULL ||
        conflicted->signed_header->commit == NULL ||
        trusted->validator_set == NULL || common->validator_set == NULL) {
        return CMT_FAULT;
    }

    out->conflicting_block = cmt_light_block_buf_new();          /* :424 */
    list = malloc((size_t)CMT_VALSET_MAX * sizeof(*list));
    if (out->conflicting_block == NULL || list == NULL ||
        cmt_light_client_buf_copy(out->conflicting_block, conflicted) != CMT_OK) {
        free(list);
        cmt_light_attack_evidence_release(out);
        return CMT_FAULT;
    }
    /* :428 — ev.ConflictingHeaderIsInvalid(trusted.Header). */
    src = cmt_light_conflicting_header_is_invalid(lb_header(trusted),
                                                  lb_header(conflicted))
          ? common                                               /* :429-431 */
          : trusted;                                             /* :433-435 */
    out->common_height = lb_header(src)->height;
    out->timestamp     = lb_header(src)->time;
    if (cmt_validator_set_total_voting_power(src->validator_set, &total) != CMT_OK) {
        free(list);
        cmt_light_attack_evidence_release(out);
        return CMT_FAULT;                 /* the reference panics (:344-345) */
    }
    out->total_voting_power = total;

    /* :437 — ev.GetByzantineValidators(common.ValidatorSet, trusted.SignedHeader). */
    if (get_byzantine_validators(conflicted, common->validator_set,
                                 trusted->signed_header, list, &n,
                                 &kind, &n_unknown) != CMT_OK) {
        free(list);
        cmt_light_attack_evidence_release(out);
        return CMT_FAULT;
    }
    out->attack            = kind;
    out->n_unknown_signers = n_unknown;
    if (n == 0u) {
        free(list);
        list = NULL;
    }
    out->byzantine_validators = list;
    out->n_byzantine          = n;
    return CMT_OK;
}

/* ══ DD9 — the durable form of a record ═══════════════════════════════ */

/* A growing byte buffer; `fail` sticks after the first failure. */
typedef struct {
    uint8_t *b;
    size_t   len;
    size_t   cap;
    bool     fail;
} wbuf_t;

static void w_bytes(wbuf_t *w, const uint8_t *p, size_t n)
{
    if (w->fail || n == 0u) {
        return;
    }
    if (n > SIZE_MAX - w->len) {
        w->fail = true;
        return;
    }
    if (w->len + n > w->cap) {
        size_t   cap = w->cap == 0u ? 4096u : w->cap;
        uint8_t *nb;

        while (cap < w->len + n) {
            if (cap > SIZE_MAX / 2u) {
                cap = w->len + n;
                break;
            }
            cap *= 2u;
        }
        nb = realloc(w->b, cap);
        if (nb == NULL) {
            w->fail = true;
            return;
        }
        w->b   = nb;
        w->cap = cap;
    }
    memcpy(w->b + w->len, p, n);
    w->len += n;
}

static void w_u64(wbuf_t *w, uint64_t v)
{
    uint8_t b[8];
    int     i;

    for (i = 7; i >= 0; i--) {
        b[i] = (uint8_t)(v & 0xFFu);
        v >>= 8;
    }
    w_bytes(w, b, sizeof(b));
}

static void w_u32(wbuf_t *w, uint32_t v)
{
    uint8_t b[4];

    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
    w_bytes(w, b, sizeof(b));
}

static void w_u8(wbuf_t *w, uint8_t v)
{
    w_bytes(w, &v, 1u);
}

/* A length that must fit its length field, else the encode faults. */
static void w_len8(wbuf_t *w, size_t n)
{
    if (n > 0xFFu) {
        w->fail = true;
        return;
    }
    w_u8(w, (uint8_t)n);
}

static void w_len32(wbuf_t *w, size_t n)
{
    if (n > 0xFFFFFFFFu) {
        w->fail = true;
        return;
    }
    w_u32(w, (uint32_t)n);
}

static void w_time(wbuf_t *w, cmt_time_t t)
{
    w_u64(w, (uint64_t)t.seconds);
    w_u32(w, (uint32_t)t.nanos);
}

/* EVIDENCE (cmt_light_detector.h, DD9). */
static int w_evidence(wbuf_t *w, const cmt_light_attack_evidence_t *ev)
{
    uint8_t *bz = NULL;
    size_t   bz_len = 0u, i;
    int      rc;

    if (ev->conflicting_block == NULL ||
        (ev->n_byzantine > 0u && ev->byzantine_validators == NULL)) {
        return CMT_FAULT;
    }
    rc = cmt_light_block_encode(&ev->conflicting_block->lb, &bz, &bz_len);
    if (rc != CMT_OK) {
        return rc;
    }
    w_len32(w, bz_len);
    w_bytes(w, bz, bz_len);
    free(bz);
    w_u64(w, (uint64_t)ev->common_height);
    w_u64(w, (uint64_t)ev->total_voting_power);
    w_time(w, ev->timestamp);
    w_u32(w, (uint32_t)ev->attack);
    w_len32(w, ev->n_unknown_signers);
    w_len32(w, ev->n_byzantine);
    for (i = 0; i < ev->n_byzantine; i++) {
        const cmt_validator_t *v = &ev->byzantine_validators[i];

        if (v->address_len > sizeof(v->address)) {
            return CMT_FAULT;
        }
        w_len8(w, v->address_len);
        w_bytes(w, v->address, v->address_len);
        w_u8(w, v->pub_key.present ? 1u : 0u);
        if (v->pub_key.present) {
            w_bytes(w, v->pub_key.key, sizeof(v->pub_key.key));
        }
        w_u64(w, (uint64_t)v->voting_power);
        w_u64(w, (uint64_t)v->proposer_priority);
    }
    return CMT_OK;
}

int cmt_light_attack_record_encode(const cmt_light_attack_record_t *r,
                                   uint8_t **out, size_t *out_len)
{
    wbuf_t  w = { NULL, 0u, 0u, false };
    uint8_t flags = 0u;
    int     rc = CMT_OK;

    if (out != NULL) {
        *out = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (r == NULL || out == NULL || out_len == NULL ||
        r->primary_id_len > sizeof(r->primary_id) ||
        r->witness_id_len > sizeof(r->witness_id) || r->missing > 0xFFu) {
        return CMT_FAULT;
    }
    if (r->has_against_witness) {
        flags |= 1u;
    }
    if (r->commit_rounds_differ) {
        flags |= 2u;
    }
    w_u8(&w, 1u);                                   /* version */
    w_time(&w, r->now);
    w_u64(&w, (uint64_t)r->witness_index);
    w_len8(&w, r->primary_id_len);
    w_bytes(&w, r->primary_id, r->primary_id_len);
    w_len8(&w, r->witness_id_len);
    w_bytes(&w, r->witness_id, r->witness_id_len);
    w_u8(&w, flags);
    w_u8(&w, (uint8_t)r->missing);
    if ((r->missing & CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY) == 0u) {
        rc = w_evidence(&w, &r->against_primary);
    }
    if (rc == CMT_OK && r->has_against_witness) {
        rc = w_evidence(&w, &r->against_witness);
    }
    if (rc == CMT_OK && w.fail) {
        rc = CMT_FAULT;
    }
    if (rc != CMT_OK) {
        free(w.b);
        return rc;
    }
    *out     = w.b;
    *out_len = w.len;
    return CMT_OK;
}

/* ══ detector.go — the witness comparison ═════════════════════════════ */

/* The result classes compareNewLightBlockWithWitness sends on `errc`
 * (detector.go:112-120) and detectDivergence switches on (:59-94). */
enum {
    CMP_MATCH = 1,  /* nil                                  :219         */
    CMP_CONFLICT,   /* ErrConflictingHeaders, the block in `buf`
                       :160, :185, :207                                  */
    CMP_BAD,        /* errBadWitness                        :174, :202   */
    CMP_DIVERGE,    /* ErrProposerPrioritiesDiverge         :214         */
    CMP_BENIGN,     /* default (ErrNoResponse, …)           :135, :147, :196 */
    CMP_SLEEP       /* reached :164-168 (DD2)                            */
};

/*
 * cometbft@v0.38.26 light/detector.go:394-419 — getTargetBlockOrLatest():
 * the witness's latest block (:399-402); the same height → the target
 * (:404-408); higher → the block at `height` (:410-416); lower → the
 * latest (:418). At most two fetches.
 */
static int get_target_block_or_latest(const cmt_light_client_t *c,
                                      const cmt_light_peer_t *w,
                                      int64_t height,
                                      cmt_light_block_buf_t *buf,
                                      bool *is_target,
                                      cmt_light_provider_error_t *perr)
{
    int64_t lh = 0;
    int     rc;

    *is_target = false;
    rc = cmt_light_client_fetch(c, w, 0, buf, perr);              /* :399-402 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (cmt_light_client_lb_height(&buf->lb, &lh) != CMT_OK) {
        return CMT_FAULT;
    }
    if (lh == height) {                                          /* :404-408 */
        *is_target = true;
        return CMT_OK;
    }
    if (lh > height) {                                           /* :410-416 */
        *is_target = true;
        return cmt_light_client_fetch(c, w, height, buf, perr);
    }
    return CMT_OK;                                               /* :418 */
}

/* detector.go:206-219 — the hash, then the priorities (K25-3, DD1). */
static int compare_blocks(const cmt_light_block_t *l,
                          const cmt_light_block_t *got, int *result)
{
    bool eq = false;

    if (cmt_light_client_lb_hash_equal(l, got, &eq) != CMT_OK) {
        return CMT_FAULT;
    }
    if (!eq) {                                                   /* :206-209 */
        *result = CMP_CONFLICT;
        return CMT_OK;
    }
    if (!cmt_light_priorities_equal(l->validator_set,            /* :211-216 */
                                    got->validator_set)) {
        *result = CMP_DIVERGE;
        return CMT_OK;
    }
    *result = CMP_MATCH;                                         /* :218-219 */
    return CMT_OK;
}

/* `!lightBlock.Time.Before(h.Time)` (:159, :184). */
static int not_before(const cmt_light_block_t *got,
                      const cmt_light_block_t *l, bool *out)
{
    const cmt_header_t *a = lb_header(got), *b = lb_header(l);

    if (a == NULL || b == NULL) {
        return CMT_FAULT;
    }
    *out = !cmt_time_before(a->time, b->time);
    return CMT_OK;
}

/*
 * cometbft@v0.38.26 light/detector.go:121-220 — compareNewLightBlockWithWitness
 * up to the sleep. `waited` (DD2): a recorded wait for this target has
 * elapsed, so a witness that answers ErrHeightTooHigh is handed to the
 * post-sleep ask (`after_sleep`) — its pre-sleep steps ran in the earlier
 * call. On CMT_OK `*result` is a CMP_* class; for CMP_CONFLICT the
 * witness's block is in `buf`.
 */
static int compare_with_witness(const cmt_light_client_t *c,
                                const cmt_light_block_t *l,
                                const cmt_light_peer_t *w, bool waited,
                                cmt_light_block_buf_t *buf, int *result)
{
    cmt_light_provider_error_t perr;
    const cmt_header_t        *h = lb_header(l);
    bool                       is_target = false, nb = false;
    int                        rc;

    if (h == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_light_client_fetch(c, w, h->height, buf, &perr);     /* :126 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc == CMT_OK) {                                          /* :129-130 */
        return compare_blocks(l, &buf->lb, result);
    }
    if (perr.code == CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE ||       /* :134-136 */
        perr.code == CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND) {
        *result = CMP_BENIGN;
        return CMT_OK;
    }
    if (perr.code != CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH) {   /* :199-203 */
        *result = CMP_BAD;
        return CMT_OK;
    }
    /* :142 — ErrHeightTooHigh. */
    if (waited) {
        *result = CMP_SLEEP;            /* DD2: straight to the post-sleep ask */
        return CMT_OK;
    }
    rc = get_target_block_or_latest(c, w, h->height, buf,        /* :145 */
                                    &is_target, &perr);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {                 /* :146-149 — raw → `default` (Q-D1) */
        *result = CMP_BENIGN;
        return CMT_OK;
    }
    if (is_target) {                                             /* :153-155 */
        return compare_blocks(l, &buf->lb, result);
    }
    if (not_before(&buf->lb, l, &nb) != CMT_OK) {
        return CMT_FAULT;
    }
    if (nb) {                                                    /* :159-162 */
        *result = CMP_CONFLICT;
        return CMT_OK;
    }
    *result = CMP_SLEEP;                                         /* :164-168 */
    return CMT_OK;
}

/* cometbft@v0.38.26 light/detector.go:169-197 — after the sleep: ask again;
 * an error is errBadWitness (:170-176, Q-D1); still behind and earlier in
 * time → ErrNoResponse (:196, benign). */
static int after_sleep(const cmt_light_client_t *c, const cmt_light_block_t *l,
                       const cmt_light_peer_t *w, cmt_light_block_buf_t *buf,
                       int *result)
{
    cmt_light_provider_error_t perr;
    const cmt_header_t        *h = lb_header(l);
    bool                       is_target = false, nb = false;
    int                        rc;

    if (h == NULL) {
        return CMT_FAULT;
    }
    rc = get_target_block_or_latest(c, w, h->height, buf,        /* :169 */
                                    &is_target, &perr);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {                                          /* :170-177 */
        *result = CMP_BAD;
        return CMT_OK;
    }
    if (is_target) {                                             /* :178-180 */
        return compare_blocks(l, &buf->lb, result);
    }
    if (not_before(&buf->lb, l, &nb) != CMT_OK) {
        return CMT_FAULT;
    }
    if (nb) {                                                    /* :184-187 */
        *result = CMP_CONFLICT;
        return CMT_OK;
    }
    *result = CMP_BENIGN;                                        /* :196 */
    return CMT_OK;
}

/* ══ detector.go:291-389 — examine ════════════════════════════════════ */

/*
 * cometbft@v0.38.26 light/detector.go:305-389 —
 * examineConflictingHeaderAgainstTrace(trace, targetBlock, source, now).
 * On CMT_OK `out_trace` is the source's verified trace and `*divergent`
 * the trace block where the two part. Fetched blocks go to `pool`; every
 * verifySkipping of one examine shares one step counter (DD5). On
 * CMT_REJECT `err` carries the verifySkipping error, or no code for the
 * examine's own refusals (each logged).
 */
static int examine_trace(cmt_light_client_t *c, const cmt_light_trace_t *trace,
                         const cmt_light_block_t *target,
                         const cmt_light_peer_t *source, cmt_time_t now,
                         cmt_light_pool_t *pool, cmt_light_trace_t *out_trace,
                         const cmt_light_block_t **divergent,
                         cmt_light_client_error_t *err)
{
    const cmt_light_block_t *prev = NULL;   /* previouslyVerifiedBlock */
    const cmt_light_block_t *sb;            /* sourceBlock             */
    const cmt_header_t      *th, *tb_h;
    uint64_t                 steps = 0u;
    size_t                   idx;
    bool                     eq = false;
    int                      rc;

    err_clear(err);
    *divergent     = NULL;
    out_trace->len = 0u;
    th = lb_header(target);
    if (trace->len == 0u || th == NULL || lb_header(trace->v[0]) == NULL) {
        return CMT_FAULT;                                /* CONTRACT 1 (:301) */
    }
    if (th->height < lb_header(trace->v[0])->height) {           /* :318-321 */
        QGP_LOG_INFO(LOG_TAG, "target block %lld is below the trusted "
                     "height %lld", (long long)th->height,
                     (long long)lb_header(trace->v[0])->height);
        return CMT_REJECT;
    }

    for (idx = 0; idx < trace->len; idx++) {                     /* :323 */
        const cmt_light_block_t *tb = trace->v[idx];

        tb_h = lb_header(tb);
        if (tb_h == NULL) {
            return CMT_FAULT;
        }
        if (tb_h->height > th->height) {                         /* :326 */
            const cmt_header_t *ph = lb_header(prev);

            if (cmt_time_after(tb_h->time, th->time)) {          /* :331-334 */
                QGP_LOG_INFO(LOG_TAG, "sanity check failed: trace block "
                             "%lld is later than the target",
                             (long long)tb_h->height);
                return CMT_REJECT;
            }
            if (ph == NULL) {
                return CMT_FAULT;                         /* :338 nil (DD6) */
            }
            if (ph->height != th->height) {                      /* :338-343 */
                out_trace->len = 0u;
                rc = cmt_light_client_verify_skipping(c, source, prev, target,
                                                      now, out_trace, pool,
                                                      &steps, err);
                if (rc != CMT_OK) {
                    return rc;
                }
            }
            *divergent = tb;                                     /* :344 */
            return CMT_OK;
        }

        if (tb_h->height == th->height) {                        /* :348-349 */
            sb = target;
        } else {                                                 /* :350-355 */
            cmt_light_provider_error_t perr;
            cmt_light_block_buf_t     *b = cmt_light_client_pool_new(pool);

            if (b == NULL) {
                return CMT_FAULT;
            }
            rc = cmt_light_client_fetch(c, source, tb_h->height, b, &perr);
            if (rc == CMT_FAULT) {
                return CMT_FAULT;
            }
            if (rc != CMT_OK) {
                QGP_LOG_INFO(LOG_TAG, "failed to examine trace at %lld: "
                             "provider error %d", (long long)tb_h->height,
                             perr.code);
                return CMT_REJECT;
            }
            sb = &b->lb;
        }

        if (cmt_light_client_lb_hash_equal(sb, tb, &eq) != CMT_OK) {
            return CMT_FAULT;
        }
        if (idx == 0u) {                                         /* :359-366 */
            if (!eq) {
                QGP_LOG_INFO(LOG_TAG, "trusted block is different to the "
                             "source's first block");
                return CMT_REJECT;
            }
            prev = sb;
            continue;
        }

        out_trace->len = 0u;                                     /* :370-373 */
        rc = cmt_light_client_verify_skipping(c, source, prev, sb, now,
                                              out_trace, pool, &steps, err);
        if (rc != CMT_OK) {
            return rc;
        }
        if (!eq) {                                               /* :375-378 */
            *divergent = tb;
            return CMT_OK;
        }
        prev = sb;                                               /* :381 */
    }
    QGP_LOG_INFO(LOG_TAG, "sanity check failed: no divergence between the "
                 "original trace and the provider's new trace"); /* :387 */
    return CMT_REJECT;
}

/* ══ detector.go:230-289 — handleConflictingHeaders ═══════════════════ */

static void copy_id(uint8_t *dst, size_t *dst_len, const cmt_light_peer_t *p)
{
    memcpy(dst, p->id, p->id_len);
    *dst_len = p->id_len;
}

/*
 * cometbft@v0.38.26 light/detector.go:232-289 — handleConflictingHeaders().
 * @return CMT_OK when the witness's header did not verify (:247-250 —
 *         "return nil": the caller removes the witness, :74-75);
 *         CMT_REJECT with LIGHT_CLIENT_ATTACK (:278, :288; the record in
 *         `c->attack`, kept whatever its evidence build did — DD10) or
 *         with a cap's code (DD5); CMT_FAULT before the attack is
 *         established, or when the record cannot be allocated (DD10).
 */
static int handle_conflicting_headers(cmt_light_client_t *c,
                                      const cmt_light_trace_t *primary_trace,
                                      const cmt_light_block_t *challenging,
                                      size_t witness_index, cmt_time_t now,
                                      cmt_light_client_error_t *err)
{
    const cmt_light_peer_t    *supporting = &c->witnesses[witness_index]; /* :239 */
    cmt_light_pool_t           pool   = { NULL, 0u, 0u };
    cmt_light_trace_t          wtrace = { NULL, 0u, 0u, 0u };
    cmt_light_trace_t          ptrace = { NULL, 0u, 0u, 0u };
    const cmt_light_block_t   *primary_block = NULL, *witness_block = NULL;
    const cmt_header_t        *pbh, *tbh;
    cmt_light_attack_record_t *rec = NULL;
    cmt_light_client_error_t   e;
    bool                       trace_ok;
    int                        rc;

    wtrace.limit = c->o.max_trace_len;
    ptrace.limit = c->o.max_trace_len;

    rc = examine_trace(c, primary_trace, challenging, supporting, now, /* :240-246 */
                       &pool, &wtrace, &primary_block, &e);
    if (rc == CMT_FAULT) {
        rc = fault(err);
        goto out;
    }
    if (rc != CMT_OK) {
        if (is_cap(e.code)) {                                    /* DD5 */
            if (err != NULL) {
                *err = e;
            }
            rc = CMT_REJECT;
            goto out;
        }
        QGP_LOG_INFO(LOG_TAG, "error validating witness #%zu's divergent "
                     "header", witness_index);                   /* :247-250 */
        rc = CMT_OK;
        goto out;
    }
    /* The witness's conflicting header verified (:240-250 passed): the
     * attack is ESTABLISHED. From here every path keeps the record and
     * returns LIGHT_CLIENT_ATTACK (DD10); only the record's own
     * allocation failing is CMT_FAULT, and the client is locked anyway. */
    rec = calloc(1, sizeof(*rec));
    if (rec == NULL) {
        c->locked = true;                                        /* DD9 */
        QGP_LOG_ERROR(LOG_TAG, "ATTEMPTED ATTACK DETECTED: witness #%zu — "
                      "the record could not be allocated; locked in memory "
                      "only", witness_index);
        rc = fault(err);
        goto out;
    }
    rec->now           = now;
    rec->witness_index = witness_index;
    copy_id(rec->primary_id, &rec->primary_id_len, &c->primary);
    copy_id(rec->witness_id, &rec->witness_id_len, supporting);

    /* :254 — the witness trace's last block, and both commits (read at
     * :260). An empty trace or a nil member is the Go index / nil panic
     * (DD6); here it only means the evidence cannot be built (DD10). */
    pbh = lb_header(primary_block);
    tbh = wtrace.len > 0u ? lb_header(wtrace.v[wtrace.len - 1u]) : NULL;
    trace_ok = pbh != NULL && tbh != NULL &&
               primary_block->signed_header->commit != NULL &&
               wtrace.v[wtrace.len - 1u]->signed_header->commit != NULL;

    /* :252-255 — the witness as the source of truth: evidence against the
     * primary, from the witness trace's common and trusted blocks. */
    if (!trace_ok) {
        rec->missing |= CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY;
        QGP_LOG_ERROR(LOG_TAG, "witness #%zu: the examined trace is "
                      "malformed — evidence against the primary NOT built "
                      "(DD10)", witness_index);
    } else if (cmt_light_attack_evidence_build(primary_block,
                                               wtrace.v[wtrace.len - 1u],
                                               wtrace.v[0],
                                               &rec->against_primary) != CMT_OK) {
        rec->missing |= CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY;
        QGP_LOG_ERROR(LOG_TAG, "witness #%zu: evidence against the primary "
                      "could not be built (DD10)", witness_index);
    }
    QGP_LOG_ERROR(LOG_TAG, "ATTEMPTED ATTACK DETECTED: witness #%zu holds a "
                  "verified header conflicting with the primary's at %lld "
                  "(common height %lld) — recorded locally, NOT sent",
                  witness_index, pbh != NULL ? (long long)pbh->height : -1LL,
                  (rec->missing & CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY) != 0u
                      ? -1LL
                      : (long long)rec->against_primary.common_height); /* :256-258, DD4 */

    if (!trace_ok) {
        /* No primary block to examine from: the second examine cannot
         * run, and that is not Q-D4. */
        rec->missing |= CMT_LIGHT_ATTACK_MISSING_AGAINST_WITNESS;
        goto keep;
    }
    if (primary_block->signed_header->commit->round !=           /* :260-264 */
        wtrace.v[wtrace.len - 1u]->signed_header->commit->round) {
        rec->commit_rounds_differ = true;
        QGP_LOG_INFO(LOG_TAG, "the conflicting commits are in different "
                     "rounds (an attempted amnesia attack)");
    }

    /* :266-275 — reversed: the primary as the source of truth. */
    rc = examine_trace(c, &wtrace, primary_block, &c->primary, now,
                       &pool, &ptrace, &witness_block, &e);
    if (rc == CMT_FAULT) {
        rec->missing |= CMT_LIGHT_ATTACK_MISSING_AGAINST_WITNESS;
        QGP_LOG_ERROR(LOG_TAG, "witness #%zu: the reverse examine faulted — "
                      "evidence against the witness NOT built, the attack "
                      "stands (DD10)", witness_index);
    } else if (rc == CMT_OK) {
        if (ptrace.len == 0u || witness_block == NULL) {         /* :282 (DD6) */
            rec->missing |= CMT_LIGHT_ATTACK_MISSING_AGAINST_WITNESS;
            QGP_LOG_ERROR(LOG_TAG, "witness #%zu: the primary's trace is "
                          "empty — evidence against the witness NOT built "
                          "(DD10)", witness_index);
        } else if (cmt_light_attack_evidence_build(witness_block, /* :281-283 */
                                                   ptrace.v[ptrace.len - 1u],
                                                   ptrace.v[0],
                                                   &rec->against_witness)
                   != CMT_OK) {
            rec->missing |= CMT_LIGHT_ATTACK_MISSING_AGAINST_WITNESS;
            QGP_LOG_ERROR(LOG_TAG, "witness #%zu: evidence against the "
                          "witness could not be built (DD10)", witness_index);
        } else {
            rec->has_against_witness = true;
            QGP_LOG_ERROR(LOG_TAG, "the primary's trace also verifies: "
                          "evidence against witness #%zu recorded locally, "
                          "NOT sent", witness_index);           /* :284-286, DD4 */
        }
    } else {
        QGP_LOG_INFO(LOG_TAG, "error validating the primary's divergent "
                     "header — the attack stands (Q-D4)");      /* :276-279 */
    }

keep:

    cmt_light_attack_record_free(c->attack);
    c->attack = rec;
    rec = NULL;
    rc = reject(err, CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK);  /* :278, :288 */
    if (err != NULL) {
        err->witness_index = witness_index;
    }
out:
    cmt_light_attack_record_free(rec);
    cmt_light_client_trace_free(&wtrace);
    cmt_light_client_trace_free(&ptrace);
    cmt_light_client_pool_free(&pool);
    return rc;
}

/* ══ detector.go:18-110 — detectDivergence ════════════════════════════ */

/* DD2 — the wait the reference sleeps, 2*maxClockDrift + maxBlockLag
 * (:168), in saturating int64 nanoseconds. */
static int64_t wait_ns(const cmt_light_client_t *c)
{
    return cmt_vs_safe_add_clip(cmt_vs_safe_add_clip(c->o.max_clock_drift,
                                                     c->o.max_clock_drift),
                                c->o.max_block_lag);
}

/* DD2 — forget the recorded wait and free its stored target. */
void cmt_light_detector_wait_clear(cmt_light_client_t *c)
{
    if (c == NULL) {
        return;
    }
    cmt_light_block_buf_free(c->wait.target);
    memset(&c->wait, 0, sizeof(c->wait));
}

/* DD2 — a wait is recorded and the caller's `now` is at or past
 * since + 2*drift + lag (Update's pinned target, cmt_light_client.h D21). */
bool cmt_light_detector_wait_elapsed(const cmt_light_client_t *c,
                                     cmt_time_t now)
{
    return c != NULL && c->wait.pending &&
           !cmt_time_before(now, cmt_time_add_ns(c->wait.since, wait_ns(c)));
}

/* DD2 — the recorded wait is for this target (height AND hash). */
static bool wait_is_for(const cmt_light_client_t *c, int64_t height,
                        const uint8_t *hash, size_t hash_len)
{
    return c->wait.pending && c->wait.height == height &&
           hdr_bytes_equal(c->wait.hash, c->wait.hash_len, hash, hash_len);
}

/*
 * cometbft@v0.38.26 light/detector.go:28-110 — detectDivergence().
 */
int cmt_light_detect_divergence(cmt_light_client_t *c,
                                const cmt_light_trace_t *trace,
                                cmt_time_t now,
                                cmt_light_client_error_t *err)
{
    const cmt_light_block_t *last;
    cmt_light_block_buf_t   *buf = NULL;
    size_t                  *to_remove = NULL, *deferred = NULL;
    size_t                   n_remove = 0u, n_deferred = 0u, i, n;
    uint8_t                  hash[CMT_TMHASH_SIZE];
    size_t                   hash_len = 0u;
    int64_t                  height = 0;
    bool                     matched = false, behind = false, waited = false;
    int                      rc, result = 0;

    err_clear(err);
    if (c == NULL || trace == NULL) {
        return CMT_FAULT;
    }
    if (trace->len < 2u) {                                       /* :29-31 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_SHORT_TRACE);
    }
    last = trace->v[trace->len - 1u];                            /* :34-35 */
    if (cmt_light_client_lb_height(last, &height) != CMT_OK ||
        cmt_light_client_lb_hash(last, hash, &hash_len) != CMT_OK) {
        return fault(err);
    }
    QGP_LOG_DEBUG(LOG_TAG, "running detector against trace: height %lld, "
                  "length %zu", (long long)height, trace->len);  /* :38-39 */

    if (c->n_witnesses == 0u) {                                  /* :44-46 */
        return reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);
    }
    /* DD2 — the post-sleep pass: a wait was recorded for this target and
     * the caller's `now` is past it. */
    if (wait_is_for(c, height, hash, hash_len) &&
        !cmt_time_before(now, cmt_time_add_ns(c->wait.since, wait_ns(c)))) {
        waited = true;
    }

    n         = c->n_witnesses;
    buf       = cmt_light_block_buf_new();
    to_remove = malloc(n * sizeof(*to_remove));
    deferred  = malloc(n * sizeof(*deferred));
    if (buf == NULL || to_remove == NULL || deferred == NULL) {
        rc = fault(err);
        goto out;
    }

    /* :48-57 — one comparison per witness, in INDEX order (DD7); then, in
     * the post-sleep pass, the post-sleep asks, after every other result
     * (DD2). At most 2 × n iterations. The witness list does not change
     * before :98, so the indexes stay valid. */
    for (i = 0; i < n + n_deferred; i++) {
        size_t wi = i < n ? i : deferred[i - n];

        if (i < n) {
            rc = compare_with_witness(c, last, &c->witnesses[wi], waited,
                                      buf, &result);
        } else {
            rc = after_sleep(c, last, &c->witnesses[wi], buf, &result);
        }
        if (rc != CMT_OK) {
            rc = fault(err);
            goto out;
        }

        switch (result) {                                        /* :59 */
        case CMP_MATCH:                                          /* :60-61 */
            matched = true;
            QGP_LOG_DEBUG(LOG_TAG, "witness #%zu: matching header", wi);
            break;
        case CMP_CONFLICT:                                       /* :62-75 */
            rc = handle_conflicting_headers(c, trace, &buf->lb, wi, now, err);
            if (rc != CMT_OK) {
                goto out;              /* the attack, a cap, or a fault */
            }
            to_remove[n_remove++] = wi;
            break;
        case CMP_BAD:                                            /* :77-82 */
            QGP_LOG_INFO(LOG_TAG, "witness #%zu returned an error during "
                         "header comparison, removing", wi);
            to_remove[n_remove++] = wi;
            break;
        case CMP_DIVERGE:                                        /* :83-86 (Q-D2) */
            QGP_LOG_INFO(LOG_TAG, "witness #%zu reported a validator set "
                         "with different proposer priorities", wi);
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE);
            if (err != NULL) {
                err->witness_index = wi;
            }
            goto out;
        case CMP_SLEEP:                                          /* :164-168 (DD2) */
            if (waited && i < n) {     /* after_sleep never returns SLEEP */
                deferred[n_deferred++] = wi;
            } else {
                behind = true;
                QGP_LOG_INFO(LOG_TAG, "witness #%zu is behind the primary "
                             "at %lld — re-check after the wait", wi,
                             (long long)height);
            }
            break;
        default:                                                 /* :87-94 */
            QGP_LOG_INFO(LOG_TAG, "witness #%zu: no comparable block "
                         "(benign)", wi);
            break;
        }
    }

    if (behind) {                                                /* DD2 */
        /* :98-100 — the witnesses already marked bad in this pass go now,
         * as the reference removes them once its sleeping comparison has
         * returned. The behind witness is never marked, so the Q-D3
         * refusal cannot fire here; it is kept, as NO_WITNESSES. */
        if (cmt_light_client_remove_witnesses(c, to_remove, n_remove) != CMT_OK) {
            rc = reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);
            goto out;
        }
        if (!wait_is_for(c, height, hash, hash_len) || c->wait.target == NULL) {
            /* Record THIS target and a deep copy of its block (D21): the
             * block judged after the wait is this one, never re-fetched. */
            cmt_light_block_buf_t *t = cmt_light_block_buf_new();

            if (t == NULL || cmt_light_client_buf_copy(t, last) != CMT_OK) {
                cmt_light_block_buf_free(t);
                rc = fault(err);
                goto out;
            }
            cmt_light_detector_wait_clear(c);       /* the old one, if any */
            c->wait.pending  = true;
            c->wait.height   = height;
            memcpy(c->wait.hash, hash, hash_len);
            c->wait.hash_len = hash_len;
            c->wait.since    = now;
            c->wait.target   = t;
        }
        rc = reject(err, CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND);
        goto out_keep_wait;
    }

    if (cmt_light_client_remove_witnesses(c, to_remove, n_remove) != CMT_OK) {
        rc = reject(err, CMT_LIGHT_CLIENT_ERR_NO_WITNESSES);     /* :98-100 (Q-D3) */
        goto out;
    }
    if (matched) {                                               /* :102-106 */
        rc = CMT_OK;
        goto out;
    }
    rc = reject(err, CMT_LIGHT_CLIENT_ERR_FAILED_HEADER_CROSS_REFERENCING); /* :108-109 */
out:
    /* Every outcome but WITNESS_BEHIND ends this detection: the recorded
     * wait, if any, is spent. */
    cmt_light_detector_wait_clear(c);
out_keep_wait:
    cmt_light_block_buf_free(buf);
    free(to_remove);
    free(deferred);
    return rc;
}
