/**
 * @file shared/dnac/res_meter.c
 * @brief Ledger V2 — deterministic resource metering + reservation.
 *
 * INACTIVE: no live consensus path calls anything here. Authority model,
 * locked formula, lifecycle machine and purity properties: res_meter.h.
 *
 * Every mutation of a meter or a budget in this file is ATOMIC: all new
 * values are computed into local temporaries through the checked helpers
 * first, and only a fully successful computation is committed. A failed
 * call leaves both structures byte-identical to entry.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "res_meter.h"

#include "crypto/hash/qgp_sha3.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── Checked u64 arithmetic ─────────────────────────────────────────── */

int dna_ck_add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (!out) return -1;
    *out = 0;
    if (b > UINT64_MAX - a) return -1;
    *out = a + b;
    return 0;
}

int dna_ck_mul_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (!out) return -1;
    *out = 0;
    if (a != 0 && b > UINT64_MAX / a) return -1;
    *out = a * b;
    return 0;
}

int dna_ck_sub_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (!out) return -1;
    *out = 0;
    if (b > a) return -1;
    *out = a - b;
    return 0;
}

/* ── Policy ─────────────────────────────────────────────────────────── */

/* 16-byte zero-padded ASCII tags (the env_wire.h tag discipline).
 * SEAL = the local integrity checksum; ID = the consensus identity a
 * ruleset descriptor commits (res_meter.h dna_meter_policy_digest).
 * Distinct tags so the two values can never be confused for each other
 * even though they serialize the same canonical fields. */
static const uint8_t METER_POLICY_TAG[16]    = "DNA.METPOL.v1";
static const uint8_t METER_POLICY_ID_TAG[16] = "DNA.METPOLID.v1";

/* Seal preimage: tag(16) + version(4) + 7 scalar weights (56)
 * + 256 op weights (2048) + 4 mask words (32) = 2156 bytes. */
#define METER_SEAL_PREIMAGE_LEN \
    (16u + 4u + 7u * 8u + (unsigned)DNA_METER_OP_SPACE * 8u + \
     (unsigned)DNA_METER_OP_MASK_WORDS * 8u)
_Static_assert(METER_SEAL_PREIMAGE_LEN == 2156u,
               "policy seal preimage layout drifted");

static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static void put_u64be(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}

/** Canonical field serialization under `tag` + SHA3-512 into out[64].
 *  The seal field is never part of the preimage. @return 0 / -1. */
static int policy_hash_tagged(const dna_meter_policy_t *p,
                              const uint8_t tag[16], uint8_t out[64]) {
    uint8_t pre[METER_SEAL_PREIMAGE_LEN];
    size_t off = 0;
    memcpy(pre + off, tag, 16); off += 16;
    put_u32be(pre + off, p->policy_version);  off += 4;
    put_u64be(pre + off, p->w_base);          off += 8;
    put_u64be(pre + off, p->w_callbyte);      off += 8;
    put_u64be(pre + off, p->w_authbyte);      off += 8;
    put_u64be(pre + off, p->w_effect);        off += 8;
    put_u64be(pre + off, p->w_effectbyte);    off += 8;
    put_u64be(pre + off, p->w_read);          off += 8;
    put_u64be(pre + off, p->w_write);         off += 8;
    for (size_t i = 0; i < DNA_METER_OP_SPACE; i++) {
        put_u64be(pre + off, p->w_op[i]); off += 8;
    }
    for (size_t i = 0; i < DNA_METER_OP_MASK_WORDS; i++) {
        put_u64be(pre + off, p->op_present[i]); off += 8;
    }
    if (off != METER_SEAL_PREIMAGE_LEN) return -1;   /* arithmetic identity */
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int dna_meter_op_set(dna_meter_policy_t *p, uint32_t runtime_op, uint64_t w) {
    if (!p || runtime_op >= DNA_METER_OP_SPACE) return -1;
    p->w_op[runtime_op] = w;
    p->op_present[runtime_op / 64] |= (uint64_t)1 << (runtime_op % 64);
    return 0;
}

int dna_meter_policy_seal(dna_meter_policy_t *p) {
    if (!p || p->policy_version != DNA_METER_POLICY_VERSION) return -1;
    return policy_hash_tagged(p, METER_POLICY_TAG, p->seal);
}

int dna_meter_policy_check(const dna_meter_policy_t *p) {
    uint8_t d[64];
    if (!p || p->policy_version != DNA_METER_POLICY_VERSION) return -1;
    if (policy_hash_tagged(p, METER_POLICY_TAG, d) != 0) return -1;
    return memcmp(d, p->seal, 64) == 0 ? 0 : -1;
}

int dna_meter_policy_digest(const dna_meter_policy_t *p, uint8_t out[64]) {
    if (!p || !out || p->policy_version != DNA_METER_POLICY_VERSION)
        return -1;
    return policy_hash_tagged(p, METER_POLICY_ID_TAG, out);
}

int dna_meter_op_weight(const dna_meter_policy_t *p, uint32_t runtime_op,
                        uint64_t *w_out) {
    if (!w_out) return -1;
    *w_out = 0;
    if (!p || runtime_op >= DNA_METER_OP_SPACE) return -1;
    if (((p->op_present[runtime_op / 64] >> (runtime_op % 64)) & 1u) == 0)
        return -1;
    *w_out = p->w_op[runtime_op];
    return 0;
}

/* ── Budget ─────────────────────────────────────────────────────────── */

int dna_meter_budget_check(const dna_meter_budget_t *b) {
    if (!b || b->n_domains > DNA_METER_MAX_DOMAINS) return -1;
    for (uint16_t i = 1; i < b->n_domains; i++)
        if (b->dom[i - 1].domain_id >= b->dom[i].domain_id) return -1;
    return 0;
}

/** Index of domain_id in the (strictly ascending) budget table, or -1. */
static int budget_dom_index(const dna_meter_budget_t *b, uint32_t domain_id) {
    for (uint16_t i = 0; i < b->n_domains; i++)
        if (b->dom[i].domain_id == domain_id) return (int)i;
    return -1;
}

/* ── Plan build (PURE) ──────────────────────────────────────────────── */

dna_meter_status_t dna_meter_plan_build(const dna_meter_policy_t *pol,
                                        const dna_env_view_t *view,
                                        dna_meter_plan_t *out) {
    if (!out) return DNA_METER_ERR_ARG;
    memset(out, 0, sizeof(*out));

    if (!pol || !view) return DNA_METER_ERR_ARG;
    /* A zeroed view is the codec's rejected-decode marker; a leg count
     * outside the wire bounds cannot come from a strict decode. */
    if (!view->buf || view->leg_count == 0 ||
        view->leg_count > DNA_ENV_MAX_LEGS)
        goto fail_arg;

    if (dna_meter_policy_check(pol) != 0) {
        memset(out, 0, sizeof(*out));
        return DNA_METER_ERR_POLICY;
    }

    out->total_ceiling = view->res_max_total_units;
    out->base_units    = pol->w_base;
    out->w_effect      = pol->w_effect;
    out->w_effectbyte  = pol->w_effectbyte;
    out->w_read        = pol->w_read;
    out->w_write       = pol->w_write;
    out->n_legs        = view->leg_count;

    uint64_t total = pol->w_base;      /* static_units(envelope) so far  */

    for (uint16_t i = 0; i < view->leg_count; i++) {
        const dna_env_leg_hdr_t *lh = &view->leg[i];
        dna_meter_leg_plan_t *lp = &out->leg[i];

        /* STRICTLY ascending domains — defence in depth: the strict
         * decoder already enforces this (env_wire.c:316-317), but a
         * hand-built view that violated it would alias two legs onto
         * ONE budget entry (the reserve/finalize/abort commit loops are
         * last-write-wins per domain), silently under-debiting the
         * block budget. The metering boundary therefore restates the
         * invariant rather than inheriting it. */
        if (i > 0 && view->leg[i - 1].domain_id >= lh->domain_id)
            goto fail_arg;

        /* Declared effect ceilings must fit the effect codec's versioned
         * caps — a declaration the codec could never encode is rejected
         * here, not discovered at charge time. */
        if (lh->res_max_effects > DNA_EFFECT_MAX_COUNT ||
            lh->res_max_effect_bytes > DNA_EFFECT_MAX_TOTAL_LEN)
            goto fail_decl;

        uint64_t w_op;
        if (dna_meter_op_weight(pol, lh->runtime_op, &w_op) != 0)
            goto fail_op;

        /* static_units(leg), every product and sum checked */
        uint64_t t_call, t_auth, t_eff, t_effb, s;
        if (dna_ck_mul_u64(pol->w_callbyte, lh->call_len, &t_call) != 0 ||
            dna_ck_mul_u64(pol->w_authbyte, lh->auth_len, &t_auth) != 0 ||
            dna_ck_mul_u64(pol->w_effect, lh->res_max_effects, &t_eff) != 0 ||
            dna_ck_mul_u64(pol->w_effectbyte, lh->res_max_effect_bytes,
                           &t_effb) != 0)
            goto fail_overflow;
        if (dna_ck_add_u64(w_op, t_call, &s) != 0 ||
            dna_ck_add_u64(s, t_auth, &s) != 0 ||
            dna_ck_add_u64(s, t_eff, &s) != 0 ||
            dna_ck_add_u64(s, t_effb, &s) != 0)
            goto fail_overflow;

        /* fixed_units (activate-time charge) is a strict sub-sum of the
         * terms above, so it cannot overflow once s did not — computed
         * checked anyway: this file has ONE arithmetic discipline. */
        uint64_t f;
        if (dna_ck_add_u64(w_op, t_call, &f) != 0 ||
            dna_ck_add_u64(f, t_auth, &f) != 0)
            goto fail_overflow;

        lp->domain_id            = lh->domain_id;
        lp->runtime_op           = lh->runtime_op;
        lp->static_units         = s;
        lp->fixed_units          = f;
        lp->res_max_effects      = lh->res_max_effects;
        lp->res_max_effect_bytes = lh->res_max_effect_bytes;

        if (dna_ck_add_u64(total, s, &total) != 0)
            goto fail_overflow;
    }

    out->static_total = total;

    /* The signed ceiling bounds the whole static reservation. */
    if (total > out->total_ceiling) {
        memset(out, 0, sizeof(*out));
        return DNA_METER_ERR_CEILING;
    }
    return DNA_METER_OK;

fail_arg:      memset(out, 0, sizeof(*out)); return DNA_METER_ERR_ARG;
fail_decl:     memset(out, 0, sizeof(*out)); return DNA_METER_ERR_DECL;
fail_op:       memset(out, 0, sizeof(*out)); return DNA_METER_ERR_OP_WEIGHT;
fail_overflow: memset(out, 0, sizeof(*out)); return DNA_METER_ERR_OVERFLOW;
}

/* ── Meter lifecycle ────────────────────────────────────────────────── */

dna_meter_status_t dna_meter_reserve(dna_meter_t *m,
                                     const dna_meter_policy_t *pol,
                                     const dna_env_view_t *view,
                                     dna_meter_budget_t *bud) {
    if (!m) return DNA_METER_ERR_ARG;
    if (m->state != DNA_METER_ST_ZERO) return DNA_METER_ERR_STATE;
    /* From here every reject re-zeroes the meter (it was ZERO-state, so
     * zeroing publishes nothing new) and leaves the budget untouched. */
    if (!pol || !view || !bud) {
        memset(m, 0, sizeof(*m));
        return DNA_METER_ERR_ARG;
    }

    dna_meter_status_t st = dna_meter_plan_build(pol, view, &m->plan);
    if (st != DNA_METER_OK) {
        memset(m, 0, sizeof(*m));
        return st;
    }

    if (dna_meter_budget_check(bud) != 0) {
        memset(m, 0, sizeof(*m));
        return DNA_METER_ERR_DOMAIN;
    }

    /* Fit checks + new values, ALL in temporaries. */
    uint64_t new_global;
    if (dna_ck_sub_u64(bud->global_remaining, m->plan.total_ceiling,
                       &new_global) != 0) {
        memset(m, 0, sizeof(*m));
        return DNA_METER_ERR_GLOBAL_BUDGET;
    }

    int      dom_idx[DNA_ENV_MAX_LEGS];
    uint64_t dom_new[DNA_ENV_MAX_LEGS];
    for (uint16_t i = 0; i < m->plan.n_legs; i++) {
        int di = budget_dom_index(bud, m->plan.leg[i].domain_id);
        if (di < 0) {
            memset(m, 0, sizeof(*m));
            return DNA_METER_ERR_DOMAIN;
        }
        if (dna_ck_sub_u64(bud->dom[di].remaining_units,
                           m->plan.leg[i].static_units, &dom_new[i]) != 0) {
            memset(m, 0, sizeof(*m));
            return DNA_METER_ERR_DOMAIN_BUDGET;
        }
        dom_idx[i] = di;
    }

    /* Commit. */
    bud->global_remaining = new_global;
    for (uint16_t i = 0; i < m->plan.n_legs; i++)
        bud->dom[dom_idx[i]].remaining_units = dom_new[i];

    m->budget     = bud;
    m->g_reserved = m->plan.total_ceiling;
    m->g_consumed = 0;
    m->g_released = 0;
    memset(m->dom_dyn, 0, sizeof(m->dom_dyn));
    memset(m->dom_consumed, 0, sizeof(m->dom_consumed));
    memset(m->dom_released, 0, sizeof(m->dom_released));
    memset(m->effects_charged, 0, sizeof(m->effects_charged));
    m->state = DNA_METER_ST_RESERVED;
    return DNA_METER_OK;
}

/** Leg index for domain_id in the plan, or -1. One leg per domain by
 *  envelope construction (legs strictly ascending by domain_id). */
static int plan_leg_index(const dna_meter_plan_t *p, uint32_t domain_id) {
    for (uint16_t i = 0; i < p->n_legs; i++)
        if (p->leg[i].domain_id == domain_id) return (int)i;
    return -1;
}

/**
 * Charge `amount` units to leg `li`, atomically, per the honest
 * deterministic rule: consume static headroom first, claim the excess
 * from the domain's remaining block budget, bound the total by the
 * global ceiling. Nothing commits before every checked step succeeded.
 */
static dna_meter_status_t meter_charge(dna_meter_t *m, int li,
                                       uint64_t amount) {
    /* global: consumed never crosses the reserved ceiling */
    uint64_t new_gc;
    if (dna_ck_add_u64(m->g_consumed, amount, &new_gc) != 0)
        return DNA_METER_ERR_OVERFLOW;
    if (new_gc > m->g_reserved)
        return DNA_METER_ERR_CEILING;

    /* domain: available = static + dyn - consumed */
    uint64_t avail, new_dc, new_dyn = m->dom_dyn[li];
    uint64_t new_bud = 0;
    int need_budget_write = 0;
    if (dna_ck_add_u64(m->plan.leg[li].static_units, m->dom_dyn[li],
                       &avail) != 0 ||
        dna_ck_sub_u64(avail, m->dom_consumed[li], &avail) != 0)
        return DNA_METER_ERR_FAULT;      /* consumed > static+dyn: broken */
    if (dna_ck_add_u64(m->dom_consumed[li], amount, &new_dc) != 0)
        return DNA_METER_ERR_OVERFLOW;
    if (amount > avail) {
        uint64_t need = amount - avail;  /* > 0; no wrap: amount > avail */
        int di = budget_dom_index(m->budget, m->plan.leg[li].domain_id);
        if (di < 0) return DNA_METER_ERR_FAULT;  /* was present at reserve */
        if (dna_ck_sub_u64(m->budget->dom[di].remaining_units, need,
                           &new_bud) != 0)
            return DNA_METER_ERR_DOMAIN_BUDGET;
        if (dna_ck_add_u64(m->dom_dyn[li], need, &new_dyn) != 0)
            return DNA_METER_ERR_OVERFLOW;
        need_budget_write = di + 1;      /* remember di, 0 = none */
    }

    /* Commit. */
    m->g_consumed = new_gc;
    m->dom_consumed[li] = new_dc;
    if (need_budget_write) {
        m->budget->dom[need_budget_write - 1].remaining_units = new_bud;
        m->dom_dyn[li] = new_dyn;
    }
    return DNA_METER_OK;
}

dna_meter_status_t dna_meter_activate(dna_meter_t *m) {
    if (!m) return DNA_METER_ERR_ARG;
    if (m->state != DNA_METER_ST_RESERVED) return DNA_METER_ERR_STATE;
    if (!m->budget) return DNA_METER_ERR_FAULT;

    /* ALL fixed-work charges are computed into temporaries; nothing
     * commits until every checked step has succeeded, so a FAULT leaves
     * the meter RESERVED (abort stays available — no reservation is
     * ever stranded) and touches neither meter nor budget. w_base is
     * envelope-level fixed work with no authoring domain: GLOBAL only.
     * fixed_units is a strict sub-sum of static_units, and
     * base + Σ fixed <= static_total <= ceiling was proven at plan
     * build, so every failure below is an accounting FAULT of this
     * node, never a budget verdict. The budget is not consulted at all:
     * activation never needs a dynamic claim. */
    uint64_t new_gc;
    if (dna_ck_add_u64(m->g_consumed, m->plan.base_units, &new_gc) != 0)
        return DNA_METER_ERR_FAULT;
    uint64_t dom_new[DNA_ENV_MAX_LEGS];
    for (uint16_t i = 0; i < m->plan.n_legs; i++) {
        if (dna_ck_add_u64(new_gc, m->plan.leg[i].fixed_units,
                           &new_gc) != 0)
            return DNA_METER_ERR_FAULT;
        if (dna_ck_add_u64(m->dom_consumed[i], m->plan.leg[i].fixed_units,
                           &dom_new[i]) != 0 ||
            dom_new[i] > m->plan.leg[i].static_units)
            return DNA_METER_ERR_FAULT;
    }
    if (new_gc > m->g_reserved) return DNA_METER_ERR_FAULT;

    /* Commit. */
    m->g_consumed = new_gc;
    for (uint16_t i = 0; i < m->plan.n_legs; i++)
        m->dom_consumed[i] = dom_new[i];
    m->state = DNA_METER_ST_ACTIVE;
    return DNA_METER_OK;
}

dna_meter_status_t dna_meter_charge_effects(dna_meter_t *m,
                                            uint32_t domain_id,
                                            const dna_effect_view_t *v) {
    if (!m) return DNA_METER_ERR_ARG;
    if (m->state != DNA_METER_ST_ACTIVE) return DNA_METER_ERR_STATE;
    if (!m->budget) return DNA_METER_ERR_FAULT;

    /* The view must be a strictly-decoded, non-rejected result. buf ==
     * NULL is the codec's rejected marker (effect_wire.h:273-276); the
     * bounds re-checked here are defence in depth against a hand-built
     * view — a decode-produced view satisfies them by construction. */
    if (!v || !v->buf ||
        v->result_version != DNA_EFFECT_RESULT_VERSION ||
        v->effect_count > DNA_EFFECT_MAX_COUNT ||
        v->res_len > DNA_EFFECT_MAX_TOTAL_LEN)
        return DNA_METER_ERR_ARG;

    /* res_len must be the EXACT canonical encoded length — head +
     * records + every declared key/value byte. The decoder pins this by
     * construction (effect_wire.c exact-length walk); a hand-built view
     * that disagrees in EITHER direction (inflated -> over-charge,
     * deflated -> under-charge) cannot be charged at all. The sum is
     * bounded: 23 + 64*84 + 64*(65535 + 2^32) < 2^39, no wrap. */
    {
        uint64_t want = (uint64_t)DNA_EFFECT_FIXED_HEAD +
                        (uint64_t)v->effect_count * DNA_EFFECT_RECORD_LEN;
        for (uint16_t i = 0; i < v->effect_count; i++)
            want += (uint64_t)v->eff[i].key_len +
                    (uint64_t)v->eff[i].value_len;
        if ((uint64_t)v->res_len != want)
            return DNA_METER_ERR_ARG;
    }

    int li = plan_leg_index(&m->plan, domain_id);
    if (li < 0) return DNA_METER_ERR_DOMAIN;
    if (m->effects_charged[li]) return DNA_METER_ERR_STATE;

    /* ACTUAL vs DECLARED: the leg's signed ceilings gate the charge. */
    if (v->effect_count > m->plan.leg[li].res_max_effects ||
        v->res_len > (size_t)m->plan.leg[li].res_max_effect_bytes)
        return DNA_METER_ERR_LIMIT;

    /* w_effect * actual count + w_effectbyte * actual canonical bytes */
    uint64_t t_cnt, t_len, amount;
    if (dna_ck_mul_u64(m->plan.w_effect, v->effect_count, &t_cnt) != 0 ||
        dna_ck_mul_u64(m->plan.w_effectbyte, (uint64_t)v->res_len,
                       &t_len) != 0 ||
        dna_ck_add_u64(t_cnt, t_len, &amount) != 0)
        return DNA_METER_ERR_OVERFLOW;

    dna_meter_status_t st = meter_charge(m, li, amount);
    if (st != DNA_METER_OK) return st;
    m->effects_charged[li] = 1;
    return DNA_METER_OK;
}

static dna_meter_status_t charge_rw(dna_meter_t *m, uint32_t domain_id,
                                    uint64_t w) {
    if (!m) return DNA_METER_ERR_ARG;
    if (m->state != DNA_METER_ST_ACTIVE) return DNA_METER_ERR_STATE;
    if (!m->budget) return DNA_METER_ERR_FAULT;
    int li = plan_leg_index(&m->plan, domain_id);
    if (li < 0) return DNA_METER_ERR_DOMAIN;
    return meter_charge(m, li, w);
}

dna_meter_status_t dna_meter_charge_read(dna_meter_t *m, uint32_t domain_id) {
    return charge_rw(m, domain_id, m ? m->plan.w_read : 0);
}

dna_meter_status_t dna_meter_charge_write(dna_meter_t *m, uint32_t domain_id) {
    return charge_rw(m, domain_id, m ? m->plan.w_write : 0);
}

dna_meter_status_t dna_meter_finalize(dna_meter_t *m) {
    if (!m) return DNA_METER_ERR_ARG;
    if (m->state != DNA_METER_ST_ACTIVE) return DNA_METER_ERR_STATE;
    if (!m->budget) return DNA_METER_ERR_FAULT;

    /* ALL releases in temporaries first — a fault commits nothing. */
    uint64_t g_rel, new_global;
    if (dna_ck_sub_u64(m->g_reserved, m->g_consumed, &g_rel) != 0 ||
        dna_ck_add_u64(m->budget->global_remaining, g_rel,
                       &new_global) != 0)
        return DNA_METER_ERR_FAULT;

    int      dom_idx[DNA_ENV_MAX_LEGS];
    uint64_t dom_rel[DNA_ENV_MAX_LEGS];
    uint64_t dom_new[DNA_ENV_MAX_LEGS];
    for (uint16_t i = 0; i < m->plan.n_legs; i++) {
        int di = budget_dom_index(m->budget, m->plan.leg[i].domain_id);
        if (di < 0) return DNA_METER_ERR_FAULT;
        uint64_t taken;
        if (dna_ck_add_u64(m->plan.leg[i].static_units, m->dom_dyn[i],
                           &taken) != 0 ||
            dna_ck_sub_u64(taken, m->dom_consumed[i], &dom_rel[i]) != 0 ||
            dna_ck_add_u64(m->budget->dom[di].remaining_units, dom_rel[i],
                           &dom_new[i]) != 0)
            return DNA_METER_ERR_FAULT;
        dom_idx[i] = di;
    }

    /* Commit. */
    m->budget->global_remaining = new_global;
    m->g_released = g_rel;
    for (uint16_t i = 0; i < m->plan.n_legs; i++) {
        m->budget->dom[dom_idx[i]].remaining_units = dom_new[i];
        m->dom_released[i] = dom_rel[i];
    }
    m->state = DNA_METER_ST_FINALIZED;
    return DNA_METER_OK;
}

dna_meter_status_t dna_meter_abort(dna_meter_t *m) {
    if (!m) return DNA_METER_ERR_ARG;
    if (m->state != DNA_METER_ST_RESERVED &&
        m->state != DNA_METER_ST_ACTIVE)
        return DNA_METER_ERR_STATE;
    if (!m->budget) return DNA_METER_ERR_FAULT;

    /* Restore EVERYTHING taken: the ceiling globally, static + dynamic
     * claims per domain. Restoring more than was taken cannot be
     * expressed here (the amounts ARE what reserve/charge recorded);
     * an overflow of the budget on restore means the budget was mutated
     * behind the meter's back — a FAULT, and nothing commits. */
    uint64_t new_global;
    if (dna_ck_add_u64(m->budget->global_remaining, m->g_reserved,
                       &new_global) != 0)
        return DNA_METER_ERR_FAULT;

    int      dom_idx[DNA_ENV_MAX_LEGS];
    uint64_t dom_new[DNA_ENV_MAX_LEGS];
    for (uint16_t i = 0; i < m->plan.n_legs; i++) {
        int di = budget_dom_index(m->budget, m->plan.leg[i].domain_id);
        if (di < 0) return DNA_METER_ERR_FAULT;
        uint64_t taken;
        if (dna_ck_add_u64(m->plan.leg[i].static_units, m->dom_dyn[i],
                           &taken) != 0 ||
            dna_ck_add_u64(m->budget->dom[di].remaining_units, taken,
                           &dom_new[i]) != 0)
            return DNA_METER_ERR_FAULT;
        dom_idx[i] = di;
    }

    /* Commit. */
    m->budget->global_remaining = new_global;
    for (uint16_t i = 0; i < m->plan.n_legs; i++)
        m->budget->dom[dom_idx[i]].remaining_units = dom_new[i];
    m->state = DNA_METER_ST_ABORTED;
    return DNA_METER_OK;
}
