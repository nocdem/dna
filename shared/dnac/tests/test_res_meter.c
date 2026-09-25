/**
 * @file shared/dnac/tests/test_res_meter.c
 * @brief Ledger V2 — tests for the deterministic resource metering +
 *        reservation boundary (shared/dnac/res_meter.{h,c}).
 *
 * What is pinned here, in increasing order of importance:
 *
 *   1. CHECKED ARITHMETIC — every add/mul/sub boundary at UINT64_MAX,
 *      zero operands, long-accumulation overflow, and output zeroing on
 *      every failure. No wrap, no saturation, no clamp survives.
 *   2. THE LOCKED FORMULA — static_units(leg) and static_units(envelope)
 *      exactly, from both sides of every bound (exact ceiling fit vs one
 *      unit over, exact budget fit vs one unit short), with weights and
 *      budgets ABOVE 2^32 so a u64 truncated anywhere breaks a pinned
 *      value.
 *   3. AUTHORITY — the policy snapshot is the only price source: the
 *      seal KAT is pinned from an independent python oracle
 *      (res_meter_oracle.py), a post-seal mutation is detected, an
 *      absent op weight rejects (a zero weight does not), and envelope
 *      ceilings can bound but never reprice.
 *   4. LIFECYCLE + BUDGET ISOLATION — the state machine rejects every
 *      invalid transition without mutating anything; a failed charge
 *      leaves meter AND budget byte-identical; no domain can consume
 *      another's budget; conservation holds on finalize AND abort.
 *   5. EFFECT CHARGING — actual (count, canonical encoded length) from a
 *      strictly-decoded view, gated by the DECLARED per-leg ceilings;
 *      a malformed or zeroed view cannot be charged.
 *
 * Property batteries use a PINNED xorshift64* seed and an INDEPENDENT
 * hi/lo-u64 wide-arithmetic model (no __int128, no shared helpers).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/res_meter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int g_checks = 0;

#define CHECK(cond) do {                                                 \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
    } else {                                                             \
        g_checks++;                                                      \
    }                                                                    \
} while (0)

#define MUST_ALLOC(p) do {                                               \
    if (!(p)) {                                                          \
        fprintf(stderr, "FATAL %s:%d: allocation failed\n",              \
                __FILE__, __LINE__);                                     \
        exit(2);                                                         \
    }                                                                    \
} while (0)

/* ══════════════════════════════════════════════════════════════════════
 * Fixtures
 * ════════════════════════════════════════════════════════════════════ */

/* ORACLE: python3 res_meter_oracle.py (independent hashlib.sha3_512). */
static const char K_SEAL_HEX[] =
    "92c9cb0ee923a85fce08df55594c131374bd993bb46bd739f5a5219e39545cb4"
    "61b5e10191482cb55b4171c2eb37c06b797848b1d2902eecb450423b7c037040";
/* The CONSENSUS identity digest of the same fixture policy
 * ("DNA.METPOLID.v1", execution season — the value a RulesetDescriptor
 * commits). Distinct tag ⇒ distinct value from the seal. */
static const char K_IDENT_HEX[] =
    "159d3ad24c5c45c50bb71a8cdc0594ab18eb12c69df132439fb1fa51f4ddb196"
    "425753a84c8d5d969f5379bc11f7db4e3acdd8dd28d08bb8e8fcf1078a3b360a";

/* THE fixture policy — mirrored in res_meter_oracle.py. w_op[255] is
 * deliberately above 2^32: a truncation anywhere in the policy path
 * breaks the seal KAT and the op-255 pricing tests. */
static void fixture_policy(dna_meter_policy_t *p) {
    memset(p, 0, sizeof(*p));
    p->policy_version = DNA_METER_POLICY_VERSION;
    p->w_base       = 7;
    p->w_callbyte   = 1;
    p->w_authbyte   = 2;
    p->w_effect     = 100;
    p->w_effectbyte = 3;
    p->w_read       = 5;
    p->w_write      = 11;
    /* policy v2 (capacity season): a distinctive fixture bound so the
     * KAT covers the appended field with a value no other field holds */
    p->max_block_env_bytes = 123456789;
    CHECK(dna_meter_op_set(p, 0, 50) == 0);
    CHECK(dna_meter_op_set(p, 1, 60) == 0);
    CHECK(dna_meter_op_set(p, 255, (uint64_t)1 << 63) == 0);
    CHECK(dna_meter_policy_seal(p) == 0);
}

typedef struct {
    uint32_t dom, op;
    uint32_t call_len, auth_len, maxeff, maxeffb;
} leg_spec_t;

static uint8_t g_blob[70000];   /* zeroed call/auth source data */

/** Encode + strictly decode an envelope from leg specs. Returns the
 *  malloc'd buffer the view borrows; caller frees AFTER using the view. */
static uint8_t *build_env(const leg_spec_t *ls, uint16_t n, uint64_t ceiling,
                          dna_env_view_t *view) {
    dna_env_leg_in_t legs[DNA_ENV_MAX_LEGS];
    memset(legs, 0, sizeof(legs));
    for (uint16_t i = 0; i < n; i++) {
        legs[i].hdr.domain_id            = ls[i].dom;
        legs[i].hdr.runtime_op           = ls[i].op;
        legs[i].hdr.ruleset_version      = 1;
        legs[i].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
        legs[i].hdr.auth_kind            = 1;
        legs[i].hdr.call_len             = ls[i].call_len;
        legs[i].hdr.auth_len             = ls[i].auth_len;
        legs[i].hdr.res_max_effects      = ls[i].maxeff;
        legs[i].hdr.res_max_effect_bytes = ls[i].maxeffb;
        legs[i].call_data = g_blob;
        legs[i].auth_data = g_blob;
    }
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = 0;
    in.fee_amount          = 1;
    in.res_max_total_units = ceiling;
    in.leg_count           = n;
    in.legs                = legs;

    size_t need = 0, written = 0;
    CHECK(dna_env_encoded_size(legs, n, &need) == 0);
    uint8_t *buf = malloc(need ? need : 1);
    MUST_ALLOC(buf);
    CHECK(dna_env_encode(&in, buf, need, &written) == 0 && written == need);
    CHECK(dna_env_decode(buf, written, view) == 0);
    return buf;
}

static void bud_init(dna_meter_budget_t *b, uint64_t global) {
    memset(b, 0, sizeof(*b));
    b->global_remaining = global;
}

static void bud_add(dna_meter_budget_t *b, uint32_t dom, uint64_t units) {
    b->dom[b->n_domains].domain_id       = dom;
    b->dom[b->n_domains].remaining_units = units;
    b->n_domains++;
}

/** Encode + strictly decode a canonical effect result with n simple
 *  records (CREATE/ABSENT, ascending 1-byte keys, val_len value bytes
 *  each). Returns the malloc'd buffer the view borrows. */
static uint8_t *build_effects(uint16_t n, uint32_t val_len,
                              dna_effect_view_t *view) {
    dna_effect_in_t eff[DNA_EFFECT_MAX_COUNT];
    static uint8_t keys[DNA_EFFECT_MAX_COUNT];
    memset(eff, 0, sizeof(eff));
    for (uint16_t i = 0; i < n; i++) {
        keys[i] = (uint8_t)i;                    /* strictly ascending  */
        eff[i].hdr.op_id       = 1;
        eff[i].hdr.effect_kind = DNA_EFFECT_CREATE;
        eff[i].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
        eff[i].hdr.key_len     = 1;
        eff[i].hdr.value_len   = val_len;
        eff[i].key   = &keys[i];
        eff[i].value = val_len ? g_blob : NULL;
    }
    size_t need = 0, written = 0;
    CHECK(dna_effect_result_encoded_size(n ? eff : NULL, n, &need) == 0);
    uint8_t *buf = malloc(need ? need : 1);
    MUST_ALLOC(buf);
    CHECK(dna_effect_result_encode(n ? eff : NULL, n, buf, need,
                                   &written) == 0 && written == need);
    CHECK(dna_effect_result_decode(buf, written, view) == 0);
    return buf;
}

/* ══════════════════════════════════════════════════════════════════════
 * A. Checked arithmetic
 * ════════════════════════════════════════════════════════════════════ */
static void test_checked_arithmetic(void) {
    uint64_t r;

    /* add: success incl. the exact boundary */
    CHECK(dna_ck_add_u64(0, 0, &r) == 0 && r == 0);
    CHECK(dna_ck_add_u64(1, 2, &r) == 0 && r == 3);
    CHECK(dna_ck_add_u64(UINT64_MAX, 0, &r) == 0 && r == UINT64_MAX);
    CHECK(dna_ck_add_u64(UINT64_MAX - 5, 5, &r) == 0 && r == UINT64_MAX);
    /* add: overflow, output zeroed */
    r = 0xDEAD;
    CHECK(dna_ck_add_u64(UINT64_MAX, 1, &r) == -1 && r == 0);
    r = 0xDEAD;
    CHECK(dna_ck_add_u64(UINT64_MAX - 4, 5, &r) == -1 && r == 0);
    CHECK(dna_ck_add_u64(1, 2, NULL) == -1);

    /* mul: success incl. boundary and zero operands */
    CHECK(dna_ck_mul_u64(0, UINT64_MAX, &r) == 0 && r == 0);
    CHECK(dna_ck_mul_u64(UINT64_MAX, 0, &r) == 0 && r == 0);
    CHECK(dna_ck_mul_u64(1, UINT64_MAX, &r) == 0 && r == UINT64_MAX);
    CHECK(dna_ck_mul_u64(UINT64_MAX / 3, 3, &r) == 0 &&
          r == (UINT64_MAX / 3) * 3);
    /* mul: overflow, output zeroed */
    r = 0xDEAD;
    CHECK(dna_ck_mul_u64(UINT64_MAX / 3 + 1, 3, &r) == -1 && r == 0);
    r = 0xDEAD;
    CHECK(dna_ck_mul_u64((uint64_t)1 << 32, (uint64_t)1 << 32, &r) == -1 &&
          r == 0);
    CHECK(dna_ck_mul_u64(2, 2, NULL) == -1);

    /* sub: success and underflow */
    CHECK(dna_ck_sub_u64(5, 5, &r) == 0 && r == 0);
    CHECK(dna_ck_sub_u64(UINT64_MAX, 0, &r) == 0 && r == UINT64_MAX);
    r = 0xDEAD;
    CHECK(dna_ck_sub_u64(0, 1, &r) == -1 && r == 0);
    r = 0xDEAD;
    CHECK(dna_ck_sub_u64(7, 8, &r) == -1 && r == 0);
    CHECK(dna_ck_sub_u64(9, 1, NULL) == -1);

    /* long accumulation: 4 * 2^62 fits once, overflows on the 5th */
    uint64_t acc = 0;
    int rc = 0;
    for (int i = 0; i < 5; i++)
        if (dna_ck_add_u64(acc, (uint64_t)1 << 62, &acc) != 0) { rc = -1; break; }
    CHECK(rc == -1 && acc == 0);
}

/* ══════════════════════════════════════════════════════════════════════
 * B. Policy seal / check / weight authority
 * ════════════════════════════════════════════════════════════════════ */
static void test_policy(void) {
    dna_meter_policy_t *p = malloc(sizeof(*p));
    MUST_ALLOC(p);
    fixture_policy(p);

    /* the pinned KAT — independent oracle */
    char hex[129];
    for (int i = 0; i < 64; i++)
        snprintf(hex + 2 * i, 3, "%02x", p->seal[i]);
    CHECK(strcmp(hex, K_SEAL_HEX) == 0);
    CHECK(dna_meter_policy_check(p) == 0);

    /* the IDENTITY digest (execution season): oracle-pinned, distinct
     * from the seal, and INDEPENDENT of the seal field — it identifies
     * the weights, not the in-memory checksum state */
    {
        uint8_t id[64], id2[64];
        CHECK(dna_meter_policy_digest(p, id) == 0);
        for (int i = 0; i < 64; i++)
            snprintf(hex + 2 * i, 3, "%02x", id[i]);
        CHECK(strcmp(hex, K_IDENT_HEX) == 0);
        CHECK(memcmp(id, p->seal, 64) != 0);   /* different tags        */
        uint8_t seal_save[64];
        memcpy(seal_save, p->seal, 64);
        memset(p->seal, 0xEE, 64);             /* scribble the seal     */
        CHECK(dna_meter_policy_digest(p, id2) == 0);
        CHECK(memcmp(id, id2, 64) == 0);       /* identity unmoved      */
        memcpy(p->seal, seal_save, 64);
        /* any weight difference moves the identity */
        p->w_read++;
        CHECK(dna_meter_policy_digest(p, id2) == 0);
        CHECK(memcmp(id, id2, 64) != 0);
        p->w_read--;
        /* rejects */
        CHECK(dna_meter_policy_digest(NULL, id) == -1);
        CHECK(dna_meter_policy_digest(p, NULL) == -1);
        p->policy_version = 9;
        CHECK(dna_meter_policy_digest(p, id) == -1);
        p->policy_version = DNA_METER_POLICY_VERSION;
    }

    /* post-seal mutation of ANY priced field is detected */
    p->w_effect++;
    CHECK(dna_meter_policy_check(p) != 0);
    p->w_effect--;
    CHECK(dna_meter_policy_check(p) == 0);
    p->w_op[17] = 1;                       /* weight w/o presence bit    */
    CHECK(dna_meter_policy_check(p) != 0);
    p->w_op[17] = 0;
    p->op_present[0] ^= ((uint64_t)1 << 9);
    CHECK(dna_meter_policy_check(p) != 0);
    p->op_present[0] ^= ((uint64_t)1 << 9);
    CHECK(dna_meter_policy_check(p) == 0);

    /* version discipline: the RETIRED v1 and an unknown future version
     * both reject (capacity season: only v2 seals/checks/digests) */
    p->policy_version = 1;
    CHECK(dna_meter_policy_seal(p) == -1);
    CHECK(dna_meter_policy_check(p) == -1);
    p->policy_version = 3;
    CHECK(dna_meter_policy_seal(p) == -1);
    CHECK(dna_meter_policy_check(p) == -1);
    p->policy_version = DNA_METER_POLICY_VERSION;
    CHECK(dna_meter_policy_seal(p) == 0);

    /* v2 shape discipline: max_block_env_bytes == 0 is NOT a policy —
     * an unbounded block must fail closed at the source (seal, check
     * AND digest all reject it) */
    {
        uint64_t save_mb = p->max_block_env_bytes;
        uint8_t d0[64];
        p->max_block_env_bytes = 0;
        CHECK(dna_meter_policy_seal(p) == -1);
        CHECK(dna_meter_policy_check(p) == -1);
        CHECK(dna_meter_policy_digest(p, d0) == -1);
        p->max_block_env_bytes = save_mb;
        CHECK(dna_meter_policy_seal(p) == 0);
        CHECK(dna_meter_policy_check(p) == 0);
        /* and the bound is part of the identity: moving it moves the
         * digest */
        uint8_t d1[64], d2[64];
        CHECK(dna_meter_policy_digest(p, d1) == 0);
        p->max_block_env_bytes = save_mb + 1;
        CHECK(dna_meter_policy_seal(p) == 0);
        CHECK(dna_meter_policy_digest(p, d2) == 0);
        CHECK(memcmp(d1, d2, 64) != 0);
        p->max_block_env_bytes = save_mb;
        CHECK(dna_meter_policy_seal(p) == 0);
    }

    /* weight authority: present-with-zero prices; absent rejects */
    uint64_t w = 0xDEAD;
    CHECK(dna_meter_op_weight(p, 0, &w) == 0 && w == 50);
    CHECK(dna_meter_op_weight(p, 255, &w) == 0 && w == ((uint64_t)1 << 63));
    w = 0xDEAD;
    CHECK(dna_meter_op_weight(p, 2, &w) == -1 && w == 0);   /* absent   */
    CHECK(dna_meter_op_weight(p, 256, &w) == -1);           /* range    */
    CHECK(dna_meter_op_weight(p, UINT32_MAX, &w) == -1);
    CHECK(dna_meter_op_weight(NULL, 0, &w) == -1);
    CHECK(dna_meter_op_weight(p, 0, NULL) == -1);
    CHECK(dna_meter_op_set(p, 3, 9) == 0);   /* set works pre-seal…     */
    CHECK(dna_meter_policy_check(p) != 0);   /* …and unseals the policy */
    CHECK(dna_meter_op_set(NULL, 3, 9) == -1);
    CHECK(dna_meter_op_set(p, 256, 9) == -1);

    /* a zero-weight PRESENT op is a legal price */
    fixture_policy(p);
    CHECK(dna_meter_op_set(p, 7, 0) == 0);
    CHECK(dna_meter_policy_seal(p) == 0);
    CHECK(dna_meter_op_weight(p, 7, &w) == 0 && w == 0);

    free(p);
}

/* ══════════════════════════════════════════════════════════════════════
 * C. Reservation calculation (pure plan build)
 * ════════════════════════════════════════════════════════════════════ */
static void test_plan_build(void) {
    dna_meter_policy_t *pol = malloc(sizeof(*pol));
    MUST_ALLOC(pol);
    fixture_policy(pol);

    dna_meter_plan_t plan;
    dna_env_view_t view;
    static const dna_meter_plan_t zero_plan;   /* all-zero reference    */

    /* one leg, exact formula field-by-field:
     * op 0 (w 50), call 10 (w 1), auth 4 (w 2), maxeff 2 (w 100),
     * maxeffb 200 (w 3): static = 50+10+8+200+600 = 868; total 875. */
    {
        leg_spec_t ls = { 5, 0, 10, 4, 2, 200 };
        uint8_t *buf = build_env(&ls, 1, 1000, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK);
        CHECK(plan.total_ceiling == 1000);
        CHECK(plan.base_units == 7);
        CHECK(plan.static_total == 875);
        CHECK(plan.n_legs == 1);
        CHECK(plan.leg[0].domain_id == 5);
        CHECK(plan.leg[0].runtime_op == 0);
        CHECK(plan.leg[0].static_units == 868);
        CHECK(plan.leg[0].fixed_units == 68);          /* 50+10+8       */
        CHECK(plan.leg[0].res_max_effects == 2);
        CHECK(plan.leg[0].res_max_effect_bytes == 200);
        CHECK(plan.w_effect == 100 && plan.w_effectbyte == 3);
        CHECK(plan.w_read == 5 && plan.w_write == 11);

        /* exact ceiling fit passes; one unit below rejects and zeroes */
        leg_spec_t ls2 = { 5, 0, 10, 4, 2, 200 };
        free(buf);
        buf = build_env(&ls2, 1, 875, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK);
        CHECK(plan.static_total == 875 && plan.total_ceiling == 875);
        free(buf);
        buf = build_env(&ls2, 1, 874, &view);
        memset(&plan, 0xAA, sizeof(plan));
        CHECK(dna_meter_plan_build(pol, &view, &plan) ==
              DNA_METER_ERR_CEILING);
        CHECK(memcmp(&plan, &zero_plan, sizeof(plan)) == 0);
        free(buf);
    }

    /* multi-domain envelope (3 legs), including the >2^32 op weight */
    {
        leg_spec_t ls[3] = {
            { 2, 1,  0, 0, 0, 0 },     /* static = 60                  */
            { 7, 0,  3, 1, 1, 10 },    /* 50+3+2+100+30 = 185          */
            { 9, 255, 0, 0, 0, 0 }     /* 2^63                         */
        };
        uint64_t want = 7 + 60 + 185 + ((uint64_t)1 << 63);
        uint8_t *buf = build_env(ls, 3, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK);
        CHECK(plan.n_legs == 3);
        CHECK(plan.leg[0].static_units == 60);
        CHECK(plan.leg[1].static_units == 185);
        CHECK(plan.leg[2].static_units == ((uint64_t)1 << 63));
        CHECK(plan.static_total == want);
        free(buf);
    }

    /* maximum-leg envelope: 64 legs, ascending domains, op 1 each */
    {
        leg_spec_t ls[DNA_ENV_MAX_LEGS];
        for (uint32_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
            leg_spec_t s = { i + 1, 1, 0, 0, 0, 0 };
            ls[i] = s;
        }
        uint8_t *buf = build_env(ls, DNA_ENV_MAX_LEGS, 100000, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK);
        CHECK(plan.n_legs == DNA_ENV_MAX_LEGS);
        CHECK(plan.static_total == 7 + 64u * 60u);
        free(buf);
    }

    /* zero-weight policy: everything prices to w_base = 0 */
    {
        dna_meter_policy_t *z = malloc(sizeof(*z));
        MUST_ALLOC(z);
        memset(z, 0, sizeof(*z));
        z->policy_version = DNA_METER_POLICY_VERSION;
        z->max_block_env_bytes = 1;      /* v2 shape: nonzero required   */
        CHECK(dna_meter_op_set(z, 4, 0) == 0);
        CHECK(dna_meter_policy_seal(z) == 0);
        leg_spec_t ls = { 3, 4, 100, 100, 64, 65536 };
        uint8_t *buf = build_env(&ls, 1, 0, &view);   /* ceiling 0 fits */
        CHECK(dna_meter_plan_build(z, &view, &plan) == DNA_METER_OK);
        CHECK(plan.static_total == 0 && plan.total_ceiling == 0);
        free(buf);
        free(z);
    }

    /* unknown operation weight (op 2 has no presence bit) */
    {
        leg_spec_t ls = { 5, 2, 0, 0, 0, 0 };
        uint8_t *buf = build_env(&ls, 1, 1000, &view);
        memset(&plan, 0xAA, sizeof(plan));
        CHECK(dna_meter_plan_build(pol, &view, &plan) ==
              DNA_METER_ERR_OP_WEIGHT);
        CHECK(memcmp(&plan, &zero_plan, sizeof(plan)) == 0);
        free(buf);
    }

    /* declared effect count / bytes: at cap OK, one over rejects */
    {
        leg_spec_t at = { 5, 0, 0, 0, DNA_EFFECT_MAX_COUNT,
                          DNA_EFFECT_MAX_TOTAL_LEN };
        uint8_t *buf = build_env(&at, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK);
        free(buf);
        leg_spec_t over_c = { 5, 0, 0, 0, DNA_EFFECT_MAX_COUNT + 1, 0 };
        buf = build_env(&over_c, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_ERR_DECL);
        free(buf);
        leg_spec_t over_b = { 5, 0, 0, 0, 0, DNA_EFFECT_MAX_TOTAL_LEN + 1 };
        buf = build_env(&over_b, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_ERR_DECL);
        free(buf);
    }

    /* overflow in EVERY multiplication term, and in both sums */
    {
        dna_meter_policy_t *h = malloc(sizeof(*h));
        MUST_ALLOC(h);

        /* w_callbyte * call_len */
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_callbyte = UINT64_MAX / 2;
        CHECK(dna_meter_op_set(h, 0, 0) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l1 = { 5, 0, 3, 0, 0, 0 };
        uint8_t *buf = build_env(&l1, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(h, &view, &plan) ==
              DNA_METER_ERR_OVERFLOW);
        free(buf);

        /* w_authbyte * auth_len */
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_authbyte = UINT64_MAX / 2;
        CHECK(dna_meter_op_set(h, 0, 0) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l2 = { 5, 0, 0, 3, 0, 0 };
        buf = build_env(&l2, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(h, &view, &plan) ==
              DNA_METER_ERR_OVERFLOW);
        free(buf);

        /* w_effect * res_max_effects */
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_effect = UINT64_MAX / 2;
        CHECK(dna_meter_op_set(h, 0, 0) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l3 = { 5, 0, 0, 0, 3, 0 };
        buf = build_env(&l3, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(h, &view, &plan) ==
              DNA_METER_ERR_OVERFLOW);
        free(buf);

        /* w_effectbyte * res_max_effect_bytes */
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_effectbyte = UINT64_MAX / 2;
        CHECK(dna_meter_op_set(h, 0, 0) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l4 = { 5, 0, 0, 0, 0, 3 };
        buf = build_env(&l4, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(h, &view, &plan) ==
              DNA_METER_ERR_OVERFLOW);
        free(buf);

        /* per-leg sum: w_op = UINT64_MAX plus a nonzero call term */
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_callbyte = 1;
        CHECK(dna_meter_op_set(h, 0, UINT64_MAX) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l5 = { 5, 0, 1, 0, 0, 0 };
        buf = build_env(&l5, 1, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(h, &view, &plan) ==
              DNA_METER_ERR_OVERFLOW);
        free(buf);

        /* envelope sum: two 2^63 legs + w_base */
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_base = 1;
        CHECK(dna_meter_op_set(h, 0, (uint64_t)1 << 63) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l6[2] = { { 5, 0, 0, 0, 0, 0 }, { 6, 0, 0, 0, 0, 0 } };
        buf = build_env(l6, 2, UINT64_MAX, &view);
        CHECK(dna_meter_plan_build(h, &view, &plan) ==
              DNA_METER_ERR_OVERFLOW);
        free(buf);
        free(h);
    }

    /* invalid policy (unsealed / mutated) rejects the build */
    {
        leg_spec_t ls = { 5, 0, 0, 0, 0, 0 };
        uint8_t *buf = build_env(&ls, 1, 1000, &view);
        dna_meter_policy_t *bad = malloc(sizeof(*bad));
        MUST_ALLOC(bad);
        fixture_policy(bad);
        bad->w_base = 8;                        /* post-seal mutation    */
        CHECK(dna_meter_plan_build(bad, &view, &plan) ==
              DNA_METER_ERR_POLICY);
        free(bad);

        /* NULL / zeroed-view arguments */
        CHECK(dna_meter_plan_build(pol, &view, NULL) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_plan_build(NULL, &view, &plan) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_plan_build(pol, NULL, &plan) == DNA_METER_ERR_ARG);
        dna_env_view_t zv;
        memset(&zv, 0, sizeof(zv));             /* rejected-decode marker */
        CHECK(dna_meter_plan_build(pol, &zv, &plan) == DNA_METER_ERR_ARG);
        free(buf);
    }

    free(pol);
}

/* ══════════════════════════════════════════════════════════════════════
 * D. Budget structural check
 * ════════════════════════════════════════════════════════════════════ */
static void test_budget_check(void) {
    dna_meter_budget_t b;
    bud_init(&b, 100);
    CHECK(dna_meter_budget_check(&b) == 0);       /* empty table is legal */
    bud_add(&b, 2, 10);
    bud_add(&b, 5, 10);
    bud_add(&b, 9, 10);
    CHECK(dna_meter_budget_check(&b) == 0);
    b.dom[1].domain_id = 2;                       /* duplicate            */
    CHECK(dna_meter_budget_check(&b) == -1);
    b.dom[1].domain_id = 1;                       /* descending           */
    CHECK(dna_meter_budget_check(&b) == -1);
    b.dom[1].domain_id = 5;
    CHECK(dna_meter_budget_check(&b) == 0);
    b.n_domains = DNA_METER_MAX_DOMAINS + 1;
    CHECK(dna_meter_budget_check(&b) == -1);
    CHECK(dna_meter_budget_check(NULL) == -1);
}

/* ══════════════════════════════════════════════════════════════════════
 * E. Meter lifecycle + budget accounting
 * ════════════════════════════════════════════════════════════════════ */
static void test_meter_lifecycle(void) {
    dna_meter_policy_t *pol = malloc(sizeof(*pol));
    MUST_ALLOC(pol);
    fixture_policy(pol);

    dna_env_view_t view;
    dna_meter_t m;
    dna_meter_budget_t bud, snap;

    /* ── the happy path, every number pinned ──────────────────────────
     * leg: dom 5, op 0, call 10, auth 4, maxeff 2, maxeffb 200
     * static 868, fixed 68, total 875, ceiling 1000. */
    leg_spec_t ls = { 5, 0, 10, 4, 2, 200 };
    uint8_t *env = build_env(&ls, 1, 1000, &view);

    bud_init(&bud, 2000);
    bud_add(&bud, 5, 900);
    bud_add(&bud, 9, 400);           /* untouched bystander domain      */

    memset(&m, 0, sizeof(m));
    CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
    CHECK(m.state == DNA_METER_ST_RESERVED);
    CHECK(m.g_reserved == 1000 && m.g_consumed == 0);
    CHECK(bud.global_remaining == 1000);          /* 2000 - ceiling      */
    CHECK(bud.dom[0].remaining_units == 32);      /* 900 - 868           */
    CHECK(bud.dom[1].remaining_units == 400);     /* bystander untouched */

    /* reserve twice rejects — and "ERR_STATE leaves a live meter
     * untouched": a re-zero here would strand the reservation the
     * budget already recorded (res_meter.h reject-output contract) */
    {
        dna_meter_t before;
        memcpy(&before, &m, sizeof(m));
        dna_meter_budget_t bud_before = bud;
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) ==
              DNA_METER_ERR_STATE);
        CHECK(memcmp(&before, &m, sizeof(m)) == 0);
        CHECK(memcmp(&bud_before, &bud, sizeof(bud)) == 0);
        CHECK(m.state == DNA_METER_ST_RESERVED);   /* still RESERVED    */
    }

    /* activate: base 7 (global only) + fixed 68 (domain 5) */
    CHECK(dna_meter_activate(&m) == DNA_METER_OK);
    CHECK(m.state == DNA_METER_ST_ACTIVE);
    CHECK(m.g_consumed == 75);
    CHECK(m.dom_consumed[0] == 68);
    CHECK(dna_meter_activate(&m) == DNA_METER_ERR_STATE);

    /* one read + one write */
    CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_OK);
    CHECK(dna_meter_charge_write(&m, 5) == DNA_METER_OK);
    CHECK(m.g_consumed == 91 && m.dom_consumed[0] == 84);
    CHECK(m.dom_dyn[0] == 0);                     /* still inside static */

    /* effects: 1 CREATE, key 1B, value 5B -> res_len 23+84+1+5 = 113;
     * amount = 100*1 + 3*113 = 439 */
    dna_effect_view_t ev;
    uint8_t *effbuf = build_effects(1, 5, &ev);
    CHECK(ev.res_len == 113);
    CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_OK);
    CHECK(m.g_consumed == 530 && m.dom_consumed[0] == 523);
    /* a second effect charge on the same leg rejects */
    CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_ERR_STATE);

    /* charges to a domain with no leg reject */
    CHECK(dna_meter_charge_read(&m, 9) == DNA_METER_ERR_DOMAIN);
    CHECK(dna_meter_charge_effects(&m, 9, &ev) == DNA_METER_ERR_DOMAIN);

    /* finalize: global release 1000-530 = 470 -> budget 1470 = 2000-530;
     * domain release 868-523 = 345 -> 32+345 = 377 = 900-523. */
    CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
    CHECK(m.state == DNA_METER_ST_FINALIZED);
    CHECK(m.g_released == 470);
    CHECK(m.dom_released[0] == 345);
    CHECK(bud.global_remaining == 1470);
    CHECK(bud.dom[0].remaining_units == 377);
    CHECK(bud.dom[1].remaining_units == 400);
    /* conservation: reserved == consumed + released, both scopes */
    CHECK(m.g_reserved == m.g_consumed + m.g_released);
    CHECK(m.plan.leg[0].static_units + m.dom_dyn[0] ==
          m.dom_consumed[0] + m.dom_released[0]);

    /* terminal-state discipline: no double release / refund / charge */
    CHECK(dna_meter_finalize(&m) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_abort(&m) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_STATE);
    CHECK(bud.global_remaining == 1470);          /* nothing moved       */
    CHECK(bud.dom[0].remaining_units == 377);
    free(effbuf);

    /* ── reserve -> abort restores byte-identically ─────────────────── */
    bud_init(&bud, 2000);
    bud_add(&bud, 5, 900);
    snap = bud;
    memset(&m, 0, sizeof(m));
    CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
    CHECK(bud.global_remaining == 1000);
    CHECK(dna_meter_abort(&m) == DNA_METER_OK);
    CHECK(m.state == DNA_METER_ST_ABORTED);
    CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);
    CHECK(dna_meter_abort(&m) == DNA_METER_ERR_STATE);   /* abort twice  */
    CHECK(dna_meter_finalize(&m) == DNA_METER_ERR_STATE);
    CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);

    /* ── charge before reserve / activate before reserve ────────────── */
    memset(&m, 0, sizeof(m));
    CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_activate(&m) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_finalize(&m) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_abort(&m) == DNA_METER_ERR_STATE);
    /* charge in RESERVED (before activate) rejects too */
    bud_init(&bud, 2000);
    bud_add(&bud, 5, 900);
    CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
    CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_finalize(&m) == DNA_METER_ERR_STATE);
    CHECK(dna_meter_abort(&m) == DNA_METER_OK);
    free(env);

    /* ── budget fit boundaries, both sides ──────────────────────────── */
    {
        /* global: ceiling 875 == static_total; budget exactly 875 */
        leg_spec_t l = { 5, 0, 10, 4, 2, 200 };
        env = build_env(&l, 1, 875, &view);
        bud_init(&bud, 875);
        bud_add(&bud, 5, 868);                    /* exact static fit    */
        snap = bud;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(bud.global_remaining == 0 && bud.dom[0].remaining_units == 0);
        CHECK(dna_meter_abort(&m) == DNA_METER_OK);
        CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);

        /* global one unit short */
        bud_init(&bud, 874);
        bud_add(&bud, 5, 868);
        snap = bud;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) ==
              DNA_METER_ERR_GLOBAL_BUDGET);
        CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);
        CHECK(m.state == DNA_METER_ST_ZERO);      /* meter re-zeroed     */

        /* domain one unit short */
        bud_init(&bud, 100000);
        bud_add(&bud, 5, 867);
        snap = bud;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) ==
              DNA_METER_ERR_DOMAIN_BUDGET);
        CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);

        /* missing domain-budget entry */
        bud_init(&bud, 100000);
        bud_add(&bud, 4, 100000);
        snap = bud;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) ==
              DNA_METER_ERR_DOMAIN);
        CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);

        /* duplicate domain-budget entry (ambiguous authority) */
        bud_init(&bud, 100000);
        bud_add(&bud, 5, 100000);
        bud.dom[1].domain_id = 5;                 /* forced duplicate    */
        bud.dom[1].remaining_units = 1;
        bud.n_domains = 2;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) ==
              DNA_METER_ERR_DOMAIN);
        free(env);
    }

    /* ── dynamic claims, exhaustion, isolation, abort-with-dyn ──────── */
    {
        /* leg: dom 5, op 1 (w 60), nothing else declared: static 60,
         * fixed 60, total 67; ceiling 1000. Domain budget 70: after
         * reserve 10 remain for dynamic claims. */
        leg_spec_t l2[2] = { { 5, 1, 0, 0, 0, 0 }, { 9, 1, 0, 0, 0, 0 } };
        env = build_env(l2, 2, 1000, &view);
        bud_init(&bud, 5000);
        bud_add(&bud, 5, 70);
        bud_add(&bud, 9, 1000);
        snap = bud;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(bud.dom[0].remaining_units == 10);
        CHECK(bud.dom[1].remaining_units == 940);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(m.dom_consumed[0] == 60);           /* static exhausted    */

        /* first read: dyn claim 5 from domain budget */
        CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_OK);
        CHECK(m.dom_dyn[0] == 5 && bud.dom[0].remaining_units == 5);
        /* second read: dyn claim 5 more — domain budget now 0 */
        CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_OK);
        CHECK(m.dom_dyn[0] == 10 && bud.dom[0].remaining_units == 0);
        /* third read: the domain budget is exhausted — typed reject,
         * meter AND budget unchanged */
        dna_meter_t msnap = m;
        dna_meter_budget_t bsnap = bud;
        CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_DOMAIN_BUDGET);
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);

        /* ISOLATION: domain 9 still has 940 — domain 5 cannot reach it,
         * and charging domain 9 claims from DOMAIN 9's budget only
         * (leg 9's fixed work equals its static reservation, so the
         * read is a dynamic claim on 9) */
        CHECK(dna_meter_charge_read(&m, 9) == DNA_METER_OK);
        CHECK(bud.dom[0].remaining_units == 0);   /* dom 5 untouched     */
        CHECK(m.dom_dyn[1] == 5);
        CHECK(bud.dom[1].remaining_units == 935);

        /* abort restores EVERYTHING incl. dynamic claims */
        CHECK(dna_meter_abort(&m) == DNA_METER_OK);
        CHECK(memcmp(&bud, &snap, sizeof(bud)) == 0);
        free(env);
    }

    /* ── the global ceiling binds even when domain budgets have room ── */
    {
        /* ceiling == static_total (67); after activate the whole
         * ceiling is consumed (no effect declarations): the next charge
         * of any size crosses it by at least one -> ERR_CEILING. */
        leg_spec_t l = { 5, 1, 0, 0, 0, 0 };
        env = build_env(&l, 1, 67, &view);
        bud_init(&bud, 1000);
        bud_add(&bud, 5, 1000);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(m.g_consumed == 67);                /* actual == ceiling   */
        dna_meter_t msnap = m;
        dna_meter_budget_t bsnap = bud;
        CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_CEILING);
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
        /* actual == ceiling finalizes cleanly with zero global release */
        CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
        CHECK(m.g_released == 0);
        CHECK(bud.global_remaining == 1000 - 67);
        free(env);
    }

    /* ── >2^32 weights and budgets: truncation tripwire ─────────────── */
    {
        /* op 255 weight is 2^63; budget values near 2^63. */
        leg_spec_t l = { 5, 255, 0, 0, 0, 0 };
        uint64_t stat = (uint64_t)1 << 63;
        uint64_t ceil_ = stat + 7;                /* + w_base            */
        env = build_env(&l, 1, ceil_, &view);
        bud_init(&bud, ceil_ + 12345);
        bud_add(&bud, 5, stat + 99);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(bud.global_remaining == 12345);
        CHECK(bud.dom[0].remaining_units == 99);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(m.g_consumed == stat + 7);
        CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
        CHECK(bud.global_remaining == 12345);     /* release 0           */
        CHECK(bud.dom[0].remaining_units == 99);
        free(env);
    }

    free(pol);
}

/* ══════════════════════════════════════════════════════════════════════
 * F. Effect charging
 * ════════════════════════════════════════════════════════════════════ */
static void test_effect_charging(void) {
    dna_meter_policy_t *pol = malloc(sizeof(*pol));
    MUST_ALLOC(pol);
    fixture_policy(pol);

    dna_env_view_t view;
    dna_meter_t m;
    dna_meter_budget_t bud;
    dna_effect_view_t ev;
    uint8_t *effbuf;

    /* generous leg: op 0, maxeff 64, maxeffb 65536:
     * static = 50 + 100*64 + 3*65536 = 203058; total 203065 */
    leg_spec_t ls = { 5, 0, 0, 0, 64, 65536 };
    uint8_t *env = build_env(&ls, 1, 1000000, &view);

#define FRESH_METER() do {                                               \
    bud_init(&bud, 5000000);                                             \
    bud_add(&bud, 5, 1000000);                                           \
    memset(&m, 0, sizeof(m));                                            \
    CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);      \
    CHECK(dna_meter_activate(&m) == DNA_METER_OK);                       \
} while (0)

    /* empty result: count 0, res_len 23 -> amount = 3*23 = 69 */
    FRESH_METER();
    effbuf = build_effects(0, 0, &ev);
    CHECK(ev.effect_count == 0 && ev.res_len == DNA_EFFECT_FIXED_HEAD);
    uint64_t before = m.g_consumed;
    CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_OK);
    CHECK(m.g_consumed == before + 69);
    free(effbuf);

    /* one CREATE (key 1, value 5): res_len 113 -> 100 + 339 = 439 */
    FRESH_METER();
    effbuf = build_effects(1, 5, &ev);
    before = m.g_consumed;
    CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_OK);
    CHECK(m.g_consumed == before + 100 + 3 * 113);
    free(effbuf);

    /* multiple effects: 3 records, value 10 each:
     * res_len = 23 + 3*84 + 3*1 + 3*10 = 308 -> 300 + 924 = 1224 */
    FRESH_METER();
    effbuf = build_effects(3, 10, &ev);
    CHECK(ev.effect_count == 3 && ev.res_len == 308);
    before = m.g_consumed;
    CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_OK);
    CHECK(m.g_consumed == before + 100 * 3 + 3 * 308);
    free(effbuf);

    /* declared count exceeded: leg declares 1, result carries 2 */
    {
        leg_spec_t tight = { 5, 0, 0, 0, 1, 65536 };
        uint8_t *env2 = build_env(&tight, 1, 1000000, &view);
        FRESH_METER();
        effbuf = build_effects(2, 0, &ev);
        dna_meter_t msnap = m;
        CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_ERR_LIMIT);
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        free(effbuf);
        free(env2);
    }

    /* declared bytes exceeded by ONE: leg declares res_len-1 */
    {
        effbuf = build_effects(1, 5, &ev);        /* res_len 113         */
        leg_spec_t tight = { 5, 0, 0, 0, 64, 112 };
        uint8_t *env2 = build_env(&tight, 1, 1000000, &view);
        FRESH_METER();
        CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_ERR_LIMIT);
        /* and at exactly the declared bytes it passes */
        leg_spec_t exact = { 5, 0, 0, 0, 64, 113 };
        uint8_t *env3 = build_env(&exact, 1, 1000000, &view);
        bud_init(&bud, 5000000);
        bud_add(&bud, 5, 1000000);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_OK);
        free(env3);
        free(env2);
        free(effbuf);
    }

    /* the actual EFFECT charge landing exactly on, then crossing, the
     * global ceiling. Leg {op 0, maxeff 1, maxeffb 113}: static =
     * 50+100+339 = 489, static_total 496. With ceiling 496 the 439
     * effect charge after activate (57) lands EXACTLY on the ceiling.
     * Effects ALONE cannot cross when ceiling == static_total (the
     * static reservation covers every declared effect byte), but ANY
     * prior dynamic charge makes the crossing constructible: with
     * ceiling 500, activate (57) + one read (5) + 439 = 501 crosses by
     * EXACTLY ONE and the effect charge itself returns ERR_CEILING,
     * mutating nothing. */
    {
        effbuf = build_effects(1, 5, &ev);        /* res_len 113         */
        leg_spec_t small = { 5, 0, 0, 0, 1, 113 };
        uint8_t *env2 = build_env(&small, 1, 496, &view);

        /* exact fit on the ceiling */
        bud_init(&bud, 5000000);
        bud_add(&bud, 5, 1000000);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(m.g_consumed == 57);
        CHECK(dna_meter_charge_effects(&m, 5, &ev) == DNA_METER_OK);
        CHECK(m.g_consumed == 496);               /* exactly the ceiling */
        free(env2);

        /* crossing by exactly one via the effect charge itself */
        uint8_t *env3 = build_env(&small, 1, 500, &view);
        bud_init(&bud, 5000000);
        bud_add(&bud, 5, 1000000);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_OK);
        CHECK(m.g_consumed == 62);                /* 62 + 439 = 501      */
        dna_meter_t msnap = m;
        dna_meter_budget_t bsnap = bud;
        CHECK(dna_meter_charge_effects(&m, 5, &ev) ==
              DNA_METER_ERR_CEILING);
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
        free(env3);
        free(effbuf);
    }

    /* malformed / zeroed views cannot be charged. The env is REBUILT
     * here so `view` borrows a LIVE buffer (the earlier blocks freed
     * theirs). */
    {
        leg_spec_t gen = { 5, 0, 0, 0, 64, 65536 };
        uint8_t *env4 = build_env(&gen, 1, 1000000, &view);
        FRESH_METER();
        dna_meter_t msnap = m;
        dna_effect_view_t bad;
        memset(&bad, 0, sizeof(bad));             /* rejected marker     */
        CHECK(dna_meter_charge_effects(&m, 5, &bad) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_charge_effects(&m, 5, NULL) == DNA_METER_ERR_ARG);
        /* hand-built inconsistency: count says 2, res_len says head */
        memset(&bad, 0, sizeof(bad));
        bad.result_version = DNA_EFFECT_RESULT_VERSION;
        bad.effect_count = 2;
        bad.buf = g_blob;
        bad.res_len = DNA_EFFECT_FIXED_HEAD;
        CHECK(dna_meter_charge_effects(&m, 5, &bad) == DNA_METER_ERR_ARG);
        /* wrong result version */
        memset(&bad, 0, sizeof(bad));
        bad.result_version = 2;
        bad.buf = g_blob;
        bad.res_len = DNA_EFFECT_FIXED_HEAD;
        CHECK(dna_meter_charge_effects(&m, 5, &bad) == DNA_METER_ERR_ARG);
        /* over-cap res_len */
        memset(&bad, 0, sizeof(bad));
        bad.result_version = DNA_EFFECT_RESULT_VERSION;
        bad.buf = g_blob;
        bad.res_len = DNA_EFFECT_MAX_TOTAL_LEN + 1;
        CHECK(dna_meter_charge_effects(&m, 5, &bad) == DNA_METER_ERR_ARG);
        /* structurally plausible but res_len != the EXACT canonical
         * length implied by the carried key/value lengths: an inflated
         * hand-built res_len (would over-charge) and a deflated one
         * (would under-charge) both reject */
        {
            dna_effect_view_t good, forged;
            uint8_t *eb = build_effects(1, 5, &good);  /* res_len 113   */
            forged = good;
            forged.res_len = 114;                      /* inflated      */
            CHECK(dna_meter_charge_effects(&m, 5, &forged) ==
                  DNA_METER_ERR_ARG);
            forged = good;
            forged.res_len = 112;                      /* deflated      */
            CHECK(dna_meter_charge_effects(&m, 5, &forged) ==
                  DNA_METER_ERR_ARG);
            free(eb);
        }
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        free(env4);
    }

#undef FRESH_METER
    free(env);
    free(pol);
}

/* ══════════════════════════════════════════════════════════════════════
 * G. Seeded properties — independent wide-arithmetic model
 * ════════════════════════════════════════════════════════════════════ */

/* xorshift64* with a PINNED literal seed — deterministic run to run. */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) {
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    return g_rng * 0x2545F4914F6CDD1DULL;
}

/* Independent 128-bit model: hi/lo u64 pairs, 32-bit-split multiply.
 * Shares NO code with dna_ck_* (which never widens at all). */
typedef struct { uint64_t hi, lo; } tu128;

static tu128 tu_mul(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xFFFFFFFFu, a1 = a >> 32;
    uint64_t b0 = b & 0xFFFFFFFFu, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    tu128 r;
    r.lo = (p00 & 0xFFFFFFFFu) | (mid << 32);
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return r;
}

static tu128 tu_add(tu128 x, tu128 y) {
    tu128 r;
    r.lo = x.lo + y.lo;
    r.hi = x.hi + y.hi + (r.lo < x.lo ? 1 : 0);
    return r;
}

static void test_property_formula(void) {
    /* interesting weight values, incl. >2^32 and overflow-prone */
    static const uint64_t WSET[] = {
        0, 1, 3, 100, (uint64_t)1 << 31, ((uint64_t)1 << 32) + 7,
        (uint64_t)1 << 62, UINT64_MAX / 3
    };
#define WPICK() (WSET[rnd() % (sizeof(WSET) / sizeof(WSET[0]))])

    for (int iter = 0; iter < 200; iter++) {
        dna_meter_policy_t *pol = malloc(sizeof(*pol));
        MUST_ALLOC(pol);
        memset(pol, 0, sizeof(*pol));
        pol->policy_version = DNA_METER_POLICY_VERSION;
        pol->w_base       = WPICK();
        pol->w_callbyte   = WPICK();
        pol->w_authbyte   = WPICK();
        pol->w_effect     = WPICK();
        pol->w_effectbyte = WPICK();
        pol->w_read       = WPICK();
        pol->w_write      = WPICK();
        pol->max_block_env_bytes = 1;    /* v2 shape: nonzero required  */
        uint64_t wop[3];
        for (int i = 0; i < 3; i++) {
            wop[i] = WPICK();
            CHECK(dna_meter_op_set(pol, (uint32_t)i, wop[i]) == 0);
        }
        CHECK(dna_meter_policy_seal(pol) == 0);

        uint16_t n = (uint16_t)(1 + rnd() % 4);
        leg_spec_t ls[4];
        uint32_t dom = 1;
        for (uint16_t i = 0; i < n; i++) {
            dom += (uint32_t)(1 + rnd() % 5);
            ls[i].dom      = dom;
            ls[i].op       = (uint32_t)(rnd() % 3);
            ls[i].call_len = (uint32_t)(rnd() % 40);
            ls[i].auth_len = (uint32_t)(rnd() % 40);
            ls[i].maxeff   = (uint32_t)(rnd() % (DNA_EFFECT_MAX_COUNT + 1));
            ls[i].maxeffb  = (uint32_t)(rnd() % (DNA_EFFECT_MAX_TOTAL_LEN + 1));
        }
        uint64_t ceiling = rnd();               /* full-range ceiling    */

        /* the MODEL: 128-bit exact static total */
        tu128 tot = tu_mul(pol->w_base, 1);
        int model_overflow = 0;
        uint64_t model_leg[4] = { 0, 0, 0, 0 };
        for (uint16_t i = 0; i < n; i++) {
            tu128 s = tu_mul(wop[ls[i].op], 1);
            s = tu_add(s, tu_mul(pol->w_callbyte, ls[i].call_len));
            s = tu_add(s, tu_mul(pol->w_authbyte, ls[i].auth_len));
            s = tu_add(s, tu_mul(pol->w_effect, ls[i].maxeff));
            s = tu_add(s, tu_mul(pol->w_effectbyte, ls[i].maxeffb));
            if (s.hi != 0) model_overflow = 1;
            model_leg[i] = s.lo;
            tot = tu_add(tot, s);
        }
        if (tot.hi != 0) model_overflow = 1;

        dna_env_view_t view;
        dna_meter_plan_t plan;
        uint8_t *buf = build_env(ls, n, ceiling, &view);
        dna_meter_status_t st = dna_meter_plan_build(pol, &view, &plan);

        if (model_overflow) {
            CHECK(st == DNA_METER_ERR_OVERFLOW);
        } else if (tot.lo > ceiling) {
            CHECK(st == DNA_METER_ERR_CEILING);
        } else {
            CHECK(st == DNA_METER_OK);
            if (st == DNA_METER_OK) {
                CHECK(plan.static_total == tot.lo);
                for (uint16_t i = 0; i < n; i++)
                    CHECK(plan.leg[i].static_units == model_leg[i]);
            }
        }
        free(buf);
        free(pol);
    }
#undef WPICK
}

static void test_property_conservation(void) {
    dna_meter_policy_t *pol = malloc(sizeof(*pol));
    MUST_ALLOC(pol);
    fixture_policy(pol);

    for (int iter = 0; iter < 100; iter++) {
        leg_spec_t ls[2];
        uint16_t n = (uint16_t)(1 + rnd() % 2);
        for (uint16_t i = 0; i < n; i++) {
            ls[i].dom      = i == 0 ? 3 : 8;
            ls[i].op       = (uint32_t)(rnd() % 2);
            ls[i].call_len = (uint32_t)(rnd() % 20);
            ls[i].auth_len = (uint32_t)(rnd() % 20);
            ls[i].maxeff   = (uint32_t)(rnd() % 4);
            ls[i].maxeffb  = (uint32_t)(rnd() % 400);
        }
        uint64_t ceiling = 2000 + rnd() % 2000;
        dna_env_view_t view;
        uint8_t *buf = build_env(ls, n, ceiling, &view);

        dna_meter_budget_t bud, initial;
        bud_init(&bud, 1000 + rnd() % 5000);
        bud_add(&bud, 3, 500 + rnd() % 2000);
        bud_add(&bud, 8, 500 + rnd() % 2000);
        initial = bud;

        dna_meter_t m;
        memset(&m, 0, sizeof(m));
        dna_meter_status_t st = dna_meter_reserve(&m, pol, &view, &bud);
        if (st != DNA_METER_OK) {
            /* a failed reserve moves nothing */
            CHECK(memcmp(&bud, &initial, sizeof(bud)) == 0);
            free(buf);
            continue;
        }
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);

        /* random charge sequence; rejected charges must move nothing */
        int steps = (int)(rnd() % 10);
        for (int s = 0; s < steps; s++) {
            uint32_t d = (rnd() & 1) ? 3u : 8u;
            dna_meter_t msnap = m;
            dna_meter_budget_t bsnap = bud;
            dna_meter_status_t cs = (rnd() & 1)
                ? dna_meter_charge_read(&m, d)
                : dna_meter_charge_write(&m, d);
            if (cs != DNA_METER_OK) {
                CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
                CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
            }
        }

        if (rnd() & 1) {
            /* FINALIZE: budget loses exactly what was consumed */
            uint64_t dc[2] = { m.dom_consumed[0], m.dom_consumed[1] };
            uint64_t gc = m.g_consumed;
            CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
            CHECK(m.g_reserved == m.g_consumed + m.g_released);
            CHECK(bud.global_remaining == initial.global_remaining - gc);
            for (uint16_t i = 0; i < n; i++) {
                CHECK(m.plan.leg[i].static_units + m.dom_dyn[i] ==
                      m.dom_consumed[i] + m.dom_released[i]);
                CHECK(bud.dom[i == 0 ? 0 : 1].remaining_units ==
                      initial.dom[i == 0 ? 0 : 1].remaining_units - dc[i]);
            }
        } else {
            /* ABORT: the budget returns byte-identically */
            CHECK(dna_meter_abort(&m) == DNA_METER_OK);
            CHECK(memcmp(&bud, &initial, sizeof(bud)) == 0);
        }
        free(buf);
    }
    free(pol);
}

static void test_property_state_machine(void) {
    dna_meter_policy_t *pol = malloc(sizeof(*pol));
    MUST_ALLOC(pol);
    fixture_policy(pol);

    leg_spec_t ls = { 5, 0, 4, 4, 1, 120 };
    dna_env_view_t view;
    uint8_t *buf = build_env(&ls, 1, 10000, &view);
    dna_effect_view_t ev;
    uint8_t *effbuf = build_effects(1, 5, &ev);

    /* From EVERY reachable state — ZERO(0), RESERVED(1), ACTIVE(2),
     * FINALIZED(3), ABORTED(4) — every ILLEGAL call is ERR_STATE and
     * mutates neither meter nor budget. */
    for (int target = 0; target < 5; target++) {
        dna_meter_budget_t bud;
        bud_init(&bud, 100000);
        bud_add(&bud, 5, 50000);
        dna_meter_t m;
        memset(&m, 0, sizeof(m));

        /* drive to the target state */
        if (target >= 1)
            CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        if (target >= 2)
            CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        if (target == 3)
            CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
        if (target == 4)
            CHECK(dna_meter_abort(&m) == DNA_METER_OK);

        dna_meter_t msnap = m;
        dna_meter_budget_t bsnap = bud;

        /* the calls illegal in this state */
        if (target != 0)
            CHECK(dna_meter_reserve(&m, pol, &view, &bud) ==
                  DNA_METER_ERR_STATE);
        if (target != 1)
            CHECK(dna_meter_activate(&m) == DNA_METER_ERR_STATE);
        if (target != 2) {
            CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_STATE);
            CHECK(dna_meter_charge_write(&m, 5) == DNA_METER_ERR_STATE);
            CHECK(dna_meter_charge_effects(&m, 5, &ev) ==
                  DNA_METER_ERR_STATE);
            CHECK(dna_meter_finalize(&m) == DNA_METER_ERR_STATE);
        }
        if (target != 1 && target != 2)
            CHECK(dna_meter_abort(&m) == DNA_METER_ERR_STATE);

        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
    }

    free(effbuf);
    free(buf);
    free(pol);
}

/* ══════════════════════════════════════════════════════════════════════
 * H. Review-round hardenings (FLEET 043 O6 findings)
 * ════════════════════════════════════════════════════════════════════ */
static void test_review_hardenings(void) {
    dna_meter_policy_t *pol = malloc(sizeof(*pol));
    MUST_ALLOC(pol);
    fixture_policy(pol);

    dna_env_view_t view;
    dna_meter_plan_t plan;
    dna_meter_t m;
    dna_meter_budget_t bud;
    static const dna_meter_plan_t zero_plan;

    /* ── duplicate / non-ascending domains in a HAND-BUILT view reject
     * at plan build (the decoder can never produce one; without this
     * guard the reserve commit loops would alias two legs onto one
     * budget entry and under-debit it) ──────────────────────────────── */
    {
        leg_spec_t ls[2] = { { 5, 0, 0, 0, 0, 0 }, { 9, 0, 0, 0, 0, 0 } };
        uint8_t *buf = build_env(ls, 2, 1000, &view);
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK);
        view.leg[1].domain_id = 5;                /* forged duplicate    */
        memset(&plan, 0xAA, sizeof(plan));
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_ERR_ARG);
        CHECK(memcmp(&plan, &zero_plan, sizeof(plan)) == 0);
        view.leg[1].domain_id = 3;                /* forged descending   */
        CHECK(dna_meter_plan_build(pol, &view, &plan) == DNA_METER_ERR_ARG);
        /* and reserve (which builds the plan) rejects identically,
         * moving nothing */
        bud_init(&bud, 100000);
        bud_add(&bud, 3, 1000);
        bud_add(&bud, 5, 1000);
        dna_meter_budget_t bsnap = bud;
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_ERR_ARG);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
        free(buf);
    }

    /* ── the FULL 64-leg / 64-domain-budget lifecycle: reserve →
     * activate → finalize with every array slot live. Per leg (op 1):
     * static = fixed = 60; static_total = 7 + 64*60 = 3847 ──────────── */
    {
        leg_spec_t ls[DNA_ENV_MAX_LEGS];
        for (uint32_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
            leg_spec_t s = { i + 1, 1, 0, 0, 0, 0 };
            ls[i] = s;
        }
        uint8_t *buf = build_env(ls, DNA_ENV_MAX_LEGS, 4000, &view);
        bud_init(&bud, 5000);
        for (uint32_t i = 0; i < DNA_ENV_MAX_LEGS; i++)
            bud_add(&bud, i + 1, 100);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(bud.global_remaining == 1000);      /* 5000 - 4000         */
        for (uint16_t i = 0; i < DNA_METER_MAX_DOMAINS; i++)
            CHECK(bud.dom[i].remaining_units == 40);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(m.g_consumed == 3847);
        CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
        CHECK(m.g_released == 153);               /* 4000 - 3847         */
        CHECK(bud.global_remaining == 1153);      /* 5000 - 3847         */
        for (uint16_t i = 0; i < DNA_METER_MAX_DOMAINS; i++) {
            CHECK(bud.dom[i].remaining_units == 40);   /* release 0      */
            CHECK(m.dom_consumed[i] == 60 && m.dom_released[i] == 0);
        }
        free(buf);
    }

    /* ── charge-time ERR_OVERFLOW: a pinned w_read of UINT64_MAX makes
     * g_consumed + amount unrepresentable; the charge rejects and
     * mutates nothing ────────────────────────────────────────────────── */
    {
        dna_meter_policy_t *h = malloc(sizeof(*h));
        MUST_ALLOC(h);
        memset(h, 0, sizeof(*h));
        h->policy_version = DNA_METER_POLICY_VERSION;
        h->max_block_env_bytes = 1;      /* v2 shape: nonzero required  */
        h->w_base = 1;
        h->w_read = UINT64_MAX;
        CHECK(dna_meter_op_set(h, 0, 0) == 0);
        CHECK(dna_meter_policy_seal(h) == 0);
        leg_spec_t l = { 5, 0, 0, 0, 0, 0 };
        uint8_t *buf = build_env(&l, 1, UINT64_MAX, &view);
        bud_init(&bud, UINT64_MAX);
        bud_add(&bud, 5, 1000);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, h, &view, &bud) == DNA_METER_OK);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        CHECK(m.g_consumed == 1);
        dna_meter_t msnap = m;
        dna_meter_budget_t bsnap = bud;
        CHECK(dna_meter_charge_read(&m, 5) == DNA_METER_ERR_OVERFLOW);
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
        free(buf);
        free(h);
    }

    /* ── ERR_FAULT: the budget mutated behind the meter's back (the
     * documented borrowing-rule violation) — finalize faults and
     * commits NOTHING; restoring the entry makes it succeed ─────────── */
    {
        leg_spec_t l = { 5, 0, 0, 0, 0, 0 };      /* static 50, total 57 */
        uint8_t *buf = build_env(&l, 1, 100, &view);
        bud_init(&bud, 1000);
        bud_add(&bud, 5, 500);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(&m, pol, &view, &bud) == DNA_METER_OK);
        CHECK(dna_meter_activate(&m) == DNA_METER_OK);
        bud.dom[0].domain_id = 77;                /* structural mutation */
        dna_meter_t msnap = m;
        dna_meter_budget_t bsnap = bud;
        CHECK(dna_meter_finalize(&m) == DNA_METER_ERR_FAULT);
        CHECK(memcmp(&m, &msnap, sizeof(m)) == 0);
        CHECK(memcmp(&bud, &bsnap, sizeof(bud)) == 0);
        CHECK(dna_meter_abort(&m) == DNA_METER_ERR_FAULT);   /* same     */
        bud.dom[0].domain_id = 5;                 /* repair the entry    */
        CHECK(dna_meter_finalize(&m) == DNA_METER_OK);
        free(buf);
    }

    /* ── NULL-argument entries ───────────────────────────────────────── */
    {
        leg_spec_t l = { 5, 0, 0, 0, 0, 0 };
        uint8_t *buf = build_env(&l, 1, 100, &view);
        bud_init(&bud, 1000);
        bud_add(&bud, 5, 500);
        memset(&m, 0, sizeof(m));
        CHECK(dna_meter_reserve(NULL, pol, &view, &bud) ==
              DNA_METER_ERR_ARG);
        CHECK(dna_meter_reserve(&m, NULL, &view, &bud) ==
              DNA_METER_ERR_ARG);
        CHECK(dna_meter_reserve(&m, pol, NULL, &bud) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_reserve(&m, pol, &view, NULL) ==
              DNA_METER_ERR_ARG);
        CHECK(dna_meter_activate(NULL) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_finalize(NULL) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_abort(NULL) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_charge_read(NULL, 5) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_charge_write(NULL, 5) == DNA_METER_ERR_ARG);
        CHECK(dna_meter_charge_effects(NULL, 5, NULL) == DNA_METER_ERR_ARG);
        CHECK(m.state == DNA_METER_ST_ZERO);      /* nothing happened    */
        free(buf);
    }

    free(pol);
}

/* ══════════════════════════════════════════════════════════════════════ */
int main(void) {
    printf("sizeof(dna_meter_policy_t) = %zu\n", sizeof(dna_meter_policy_t));
    printf("sizeof(dna_meter_plan_t)   = %zu\n", sizeof(dna_meter_plan_t));
    printf("sizeof(dna_meter_t)        = %zu\n", sizeof(dna_meter_t));

    test_checked_arithmetic();
    test_policy();
    test_plan_build();
    test_budget_check();
    test_meter_lifecycle();
    test_effect_charging();
    test_property_formula();
    test_property_conservation();
    test_property_state_machine();
    test_review_hardenings();

    printf("test_res_meter: %d checks, %d failures\n", g_checks, failures);
    return failures == 0 ? 0 : 1;
}
