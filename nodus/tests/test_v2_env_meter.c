/**
 * Nodus — Ledger V2: the METERED envelope seam entry
 * (nodus_witness_v2_env_preflight_reserve_batch), where a preflighted
 * batch acquires its deterministic reservation plans.
 *
 * The properties pinned here, in increasing order of importance:
 *
 *   1. BASE-CONTRACT EQUIVALENCE — the metered entry changes NOTHING
 *      about the base preflight: identical derived tx_ids (recomputed
 *      through the shared dna_env_preflight with the DERIVED chain id),
 *      identical rejection statuses for base-level failures, batch dedup
 *      still over derived ids only.
 *   2. SEQUENTIAL DETERMINISTIC RESERVATION — envelope i+1 is judged
 *      against the budget AFTER envelope i's reservation; every debit is
 *      a pinned number.
 *   3. ATOMIC FAILURE — ANY failure (base preflight, policy, budget)
 *      zeroes BOTH caller arrays completely AND restores the budget
 *      byte-identically. A failed batch publishes nothing and reserves
 *      nothing.
 *   4. POLICY AUTHORITY — the policy snapshot is the only price source:
 *      an unsealed/mutated policy rejects the whole batch, and raising an
 *      envelope's ceiling changes its reservation BOUND, never its
 *      computed static price.
 *
 * @file test_v2_env_meter.c
 */

#define _DEFAULT_SOURCE 1

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_env.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/env_wire.h"
#include "dnac/res_meter.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── fs + fixture (test_v2_env_preflight.c pattern) ─────────────────── */
static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;              /* HEAP: nodus_witness_t is multi-MB */
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_env_meter_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x33, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    nodus_chain_config_db_migrate(fx->w);
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static void mk_gen_id(uint8_t out[64], uint8_t base) {
    for (int i = 0; i < 64; i++) out[i] = (uint8_t)(base + i);
}

/** A 1-leg envelope on domain 1: runtime_op 1, call_len 8, auth_len 0,
 *  res_max_effects 2, res_max_effect_bytes 64, chosen ceiling.
 *  With the fixture policy below its static price is
 *  w_op(3) + 8*w_callbyte(1) + 2*w_effect(4) + 64*w_effectbyte(1) = 83,
 *  and static_total = w_base(2) + 83 = 85. */
static uint8_t *mk_env(const uint8_t *call, uint32_t call_len,
                       uint64_t ceiling, uint64_t expiry, size_t *len_out) {
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = 1;
    leg.hdr.runtime_op           = 1;
    leg.hdr.ruleset_version      = 1;
    leg.hdr.access_mode          = (uint8_t)DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = 1;
    leg.hdr.call_len             = call_len;
    leg.hdr.auth_len             = 0;
    leg.hdr.res_max_effects      = 2;
    leg.hdr.res_max_effect_bytes = 64;
    leg.call_data                = call;
    leg.auth_data                = NULL;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = expiry;
    in.fee_amount          = 10;
    in.res_max_total_units = ceiling;
    in.leg_count           = 1;
    in.legs                = &leg;

    size_t need = 0;
    if (dna_env_encoded_size(&leg, 1, &need) != 0) return NULL;
    uint8_t *buf = malloc(need);
    if (!buf) return NULL;
    if (dna_env_encode(&in, buf, need, len_out) != 0) { free(buf); return NULL; }
    return buf;
}

static void mk_rulesets(dna_env_leg_ctx_t *tab, uint8_t hash_fill) {
    memset(tab, 0, sizeof(*tab));
    tab->domain_id       = 1;
    tab->ruleset_version = 1;
    memset(tab->ruleset_hash, hash_fill, DNA_ENV_RULESET_HASH_LEN);
}

/** The fixture policy: w_base 2, w_callbyte 1, w_authbyte 1, w_effect 4,
 *  w_effectbyte 1, w_read 5, w_write 9; op 1 present with weight 3. */
static void mk_policy(dna_meter_policy_t *p) {
    memset(p, 0, sizeof(*p));
    p->policy_version = DNA_METER_POLICY_VERSION;
    p->w_base       = 2;
    p->w_callbyte   = 1;
    p->w_authbyte   = 1;
    p->w_effect     = 4;
    p->w_effectbyte = 1;
    p->w_read       = 5;
    p->w_write      = 9;
    (void)dna_meter_op_set(p, 1, 3);
}

static int all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

int main(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();
    CHECK(nodus_witness_db_migrate_v2s7(fx.w) == 0, "migrate"); OK();

    uint8_t gen_id[64], vset[64];
    mk_gen_id(gen_id, 0x40);
    memset(vset, 0x77, sizeof(vset));
    CHECK(nodus_witness_v2_genesis(fx.w, gen_id, vset, 0) == 0, "genesis");
    OK();

    dna_env_leg_ctx_t tab;
    mk_rulesets(&tab, 0xB7);

    dna_meter_policy_t *pol = calloc(1, sizeof(*pol));
    CHECK(pol != NULL, "policy alloc"); OK();
    mk_policy(pol);
    CHECK(dna_meter_policy_seal(pol) == 0, "seal"); OK();

    /* three envelopes, static price 83 each, ceilings 100/100/200 */
    static const uint8_t c0[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    static const uint8_t c1[8] = { 0, 1, 2, 3, 4, 5, 6, 8 };
    static const uint8_t c2[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    size_t l0 = 0, l1 = 0, l2 = 0;
    uint8_t *e0 = mk_env(c0, 8, 100, 0, &l0);
    uint8_t *e1 = mk_env(c1, 8, 100, 0, &l1);
    uint8_t *e2 = mk_env(c2, 8, 200, 0, &l2);
    CHECK(e0 && e1 && e2, "envelope encode"); OK();

    nodus_v2_envelope_t envs[NODUS_V2_ENV_BATCH_MAX];
    memset(envs, 0, sizeof(envs));
    envs[0].env_bytes = e0; envs[0].env_len = l0;
    envs[1].env_bytes = e1; envs[1].env_len = l1;
    envs[2].env_bytes = e2; envs[2].env_len = l2;

    /* HEAP: preflight entries are ~11 KB, meters ~3.5 KB */
    dna_env_preflight_t *out = calloc(NODUS_V2_ENV_BATCH_MAX, sizeof(*out));
    dna_meter_t *meters = calloc(NODUS_V2_ENV_BATCH_MAX, sizeof(*meters));
    CHECK(out && meters, "array alloc"); OK();

    dna_meter_budget_t bud, entry_bud;
    memset(&bud, 0, sizeof(bud));
    bud.global_remaining = 1000;
    bud.n_domains = 1;
    bud.dom[0].domain_id = 1;
    bud.dom[0].remaining_units = 300;
    entry_bud = bud;

    size_t fail_idx = 999;
    dna_env_preflight_status_t pf_st = DNA_ENV_PF_ERR_HASH;
    dna_meter_status_t ms = DNA_METER_ERR_FAULT;

    /* ── 1+2. HAPPY METERED BATCH: pinned sequential debits ─────────── */
    CHECK(nodus_witness_v2_env_preflight_reserve_batch(
              fx.w, 1, &tab, 1, pol, &bud, envs, 3, out, meters,
              &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_OK,
          "happy metered batch"); OK();
    CHECK(fail_idx == 0 && pf_st == DNA_ENV_PF_OK && ms == DNA_METER_OK,
          "optional outs not cleared"); OK();
    /* global: 1000 - (100+100+200) = 600; domain 1: 300 - 3*83 = 51 */
    CHECK(bud.global_remaining == 600, "global debit"); OK();
    CHECK(bud.dom[0].remaining_units == 51, "domain debit"); OK();
    for (int i = 0; i < 3; i++) {
        CHECK(meters[i].state == DNA_METER_ST_RESERVED, "meter state"); OK();
        CHECK(meters[i].budget == &bud, "meter budget binding"); OK();
        CHECK(meters[i].plan.static_total == 85, "static price"); OK();
        CHECK(meters[i].plan.leg[0].static_units == 83, "leg price"); OK();
    }
    /* POLICY AUTHORITY: e2's doubled ceiling changed its BOUND only */
    CHECK(meters[0].plan.total_ceiling == 100 &&
          meters[2].plan.total_ceiling == 200, "ceiling copied"); OK();
    CHECK(meters[0].plan.static_total == meters[2].plan.static_total,
          "a ceiling change repriced the envelope"); OK();

    /* BASE-CONTRACT EQUIVALENCE: derived ids match the shared preflight
     * under the DERIVED chain id (and the batch produced 3 distinct). */
    {
        uint8_t derived[DNA_CHAIN_ID_LEN];
        CHECK(nodus_witness_v2_chain_id(fx.w, derived) == 0, "chain id");
        OK();
        dna_env_preflight_t *ref = calloc(1, sizeof(*ref));
        CHECK(ref != NULL, "ref alloc");
        const uint8_t *bufs[3] = { e0, e1, e2 };
        const size_t lens[3] = { l0, l1, l2 };
        for (int i = 0; i < 3; i++) {
            CHECK(dna_env_preflight(bufs[i], lens[i], derived, 1, &tab, 1,
                                    ref) == DNA_ENV_PF_OK, "ref preflight");
            CHECK(memcmp(ref->tx_id, out[i].tx_id, 64) == 0,
                  "metered seam tx_id != shared recomputation"); OK();
        }
        CHECK(memcmp(out[0].tx_id, out[1].tx_id, 64) != 0, "dup id"); OK();
        free(ref);
    }

    /* ── 3a. DOMAIN BUDGET FAILURE mid-batch: atomic restore ────────── */
    memset(&bud, 0, sizeof(bud));
    bud.global_remaining = 1000;
    bud.n_domains = 1;
    bud.dom[0].domain_id = 1;
    bud.dom[0].remaining_units = 2 * 83 + 82;      /* 3rd is 1 short     */
    entry_bud = bud;
    memset(out, 0xAA, NODUS_V2_ENV_BATCH_MAX * sizeof(*out));
    memset(meters, 0xAA, NODUS_V2_ENV_BATCH_MAX * sizeof(*meters));
    fail_idx = 999; ms = DNA_METER_OK;
    CHECK(nodus_witness_v2_env_preflight_reserve_batch(
              fx.w, 1, &tab, 1, pol, &bud, envs, 3, out, meters,
              &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_METER,
          "domain-budget failure"); OK();
    CHECK(fail_idx == 2, "failing envelope index"); OK();
    CHECK(ms == DNA_METER_ERR_DOMAIN_BUDGET, "meter status"); OK();
    CHECK(all_zero((const uint8_t *)out, 3 * sizeof(*out)),
          "out not fully zeroed"); OK();
    CHECK(all_zero((const uint8_t *)meters, 3 * sizeof(*meters)),
          "meters not fully zeroed"); OK();
    CHECK(memcmp(&bud, &entry_bud, sizeof(bud)) == 0,
          "budget not restored"); OK();

    /* ── 3b. GLOBAL BUDGET FAILURE at the first envelope ────────────── */
    memset(&bud, 0, sizeof(bud));
    bud.global_remaining = 99;                     /* < ceiling 100      */
    bud.n_domains = 1;
    bud.dom[0].domain_id = 1;
    bud.dom[0].remaining_units = 1000;
    entry_bud = bud;
    fail_idx = 999; ms = DNA_METER_OK;
    CHECK(nodus_witness_v2_env_preflight_reserve_batch(
              fx.w, 1, &tab, 1, pol, &bud, envs, 3, out, meters,
              &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_METER,
          "global-budget failure"); OK();
    CHECK(fail_idx == 0 && ms == DNA_METER_ERR_GLOBAL_BUDGET,
          "global status"); OK();
    CHECK(memcmp(&bud, &entry_bud, sizeof(bud)) == 0, "budget moved"); OK();

    /* ── 3c. MISSING DOMAIN BUDGET ENTRY ────────────────────────────── */
    memset(&bud, 0, sizeof(bud));
    bud.global_remaining = 1000;
    bud.n_domains = 1;
    bud.dom[0].domain_id = 2;                      /* not domain 1       */
    bud.dom[0].remaining_units = 1000;
    entry_bud = bud;
    ms = DNA_METER_OK;
    CHECK(nodus_witness_v2_env_preflight_reserve_batch(
              fx.w, 1, &tab, 1, pol, &bud, envs, 3, out, meters,
              &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_METER,
          "missing domain entry"); OK();
    CHECK(ms == DNA_METER_ERR_DOMAIN, "missing-domain status"); OK();
    CHECK(memcmp(&bud, &entry_bud, sizeof(bud)) == 0, "budget moved"); OK();

    /* ── 4. POLICY AUTHORITY: a post-seal mutation rejects the batch ── */
    memset(&bud, 0, sizeof(bud));
    bud.global_remaining = 1000;
    bud.n_domains = 1;
    bud.dom[0].domain_id = 1;
    bud.dom[0].remaining_units = 300;
    entry_bud = bud;
    pol->w_effect = 40;                            /* mutate AFTER seal  */
    memset(out, 0xAA, NODUS_V2_ENV_BATCH_MAX * sizeof(*out));
    memset(meters, 0xAA, NODUS_V2_ENV_BATCH_MAX * sizeof(*meters));
    ms = DNA_METER_OK;
    CHECK(nodus_witness_v2_env_preflight_reserve_batch(
              fx.w, 1, &tab, 1, pol, &bud, envs, 3, out, meters,
              &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_METER,
          "mutated policy accepted"); OK();
    CHECK(ms == DNA_METER_ERR_POLICY, "policy status"); OK();
    CHECK(all_zero((const uint8_t *)out, 3 * sizeof(*out)) &&
          all_zero((const uint8_t *)meters, 3 * sizeof(*meters)),
          "arrays not zeroed on policy reject"); OK();
    CHECK(memcmp(&bud, &entry_bud, sizeof(bud)) == 0, "budget moved"); OK();
    mk_policy(pol);
    CHECK(dna_meter_policy_seal(pol) == 0, "reseal"); OK();

    /* ── 5. BASE-PREFLIGHT FAILURE PROPAGATES VERBATIM ──────────────── */
    {
        size_t lx = 0;
        uint8_t *ex = mk_env(c0, 8, 100, /*expiry=*/1, &lx);  /* H=2 -> expired */
        CHECK(ex != NULL, "expired env"); OK();
        nodus_v2_envelope_t one;
        one.env_bytes = ex; one.env_len = lx;
        memset(out, 0xAA, sizeof(*out));
        memset(meters, 0xAA, sizeof(*meters));
        ms = DNA_METER_ERR_FAULT;
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 2, &tab, 1, pol, &bud, &one, 1, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_PREFLIGHT,
              "expired envelope status"); OK();
        CHECK(pf_st == DNA_ENV_PF_ERR_EXPIRED, "pf status"); OK();
        CHECK(ms == DNA_METER_OK, "meter status not OK on base fail"); OK();
        CHECK(all_zero((const uint8_t *)out, sizeof(*out)) &&
              all_zero((const uint8_t *)meters, sizeof(*meters)),
              "arrays not zeroed on base fail"); OK();
        free(ex);

        /* duplicate envelope bytes -> ERR_DUP propagates */
        nodus_v2_envelope_t two[2];
        two[0].env_bytes = e0; two[0].env_len = l0;
        two[1].env_bytes = e0; two[1].env_len = l0;
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, &bud, two, 2, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_DUP,
              "duplicate status"); OK();
        CHECK(fail_idx == 1, "dup second member"); OK();
    }

    /* ── 6. STEP-1 GATES touch neither caller buffer ────────────────── */
    {
        memset(out, 0xAA, sizeof(*out));
        memset(meters, 0xAA, sizeof(*meters));
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, &bud, envs, 3, NULL, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_ARG,
              "NULL out"); OK();
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, &bud, envs, 3, out, NULL,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_ARG,
              "NULL meters"); OK();
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, &bud, envs,
                  NODUS_V2_ENV_BATCH_MAX + 1, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_ARG,
              "oversize batch"); OK();
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, &bud, envs, 0, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_ARG,
              "zero batch"); OK();
        /* the 0xAA sentinel survived the gate rejects */
        CHECK(((const uint8_t *)out)[0] == 0xAA &&
              ((const uint8_t *)meters)[0] == 0xAA,
              "gate reject wrote a caller buffer"); OK();
        /* NULL policy / budget: after the gates, arrays ARE zeroed */
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, NULL, &bud, envs, 3, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_ARG,
              "NULL policy"); OK();
        CHECK(all_zero((const uint8_t *)out, 3 * sizeof(*out)) &&
              all_zero((const uint8_t *)meters, 3 * sizeof(*meters)),
              "arrays not zeroed on NULL policy"); OK();
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, NULL, envs, 3, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_ARG,
              "NULL budget"); OK();
    }

    /* ── 7. A RESERVED meter from the seam drives the full lifecycle ── */
    {
        memset(&bud, 0, sizeof(bud));
        bud.global_remaining = 1000;
        bud.n_domains = 1;
        bud.dom[0].domain_id = 1;
        bud.dom[0].remaining_units = 300;
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &tab, 1, pol, &bud, envs, 1, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_OK,
              "single batch"); OK();
        CHECK(dna_meter_activate(&meters[0]) == DNA_METER_OK, "activate");
        OK();
        /* fixed work: base 2 (global) + op 3 + call 8 = g_consumed 13 */
        CHECK(meters[0].g_consumed == 13, "fixed charge"); OK();
        CHECK(dna_meter_charge_read(&meters[0], 1) == DNA_METER_OK, "read");
        OK();
        CHECK(dna_meter_finalize(&meters[0]) == DNA_METER_OK, "finalize");
        OK();
        /* g_consumed 18 total (13 fixed + 5 read): global budget
         * 1000 - 18 = 982. Leg consumed = 11 fixed + 5 read = 16:
         * domain budget 300 - 16 = 284. */
        CHECK(bud.global_remaining == 982, "global conservation"); OK();
        CHECK(bud.dom[0].remaining_units == 284, "domain conservation");
        OK();
    }

    /* ── 7b. REMAINING BASE-LEVEL REJECTS PROPAGATE THROUGH THE
     * METERED ENTRY: a non-ascending ruleset table and a context table
     * missing the envelope's domain ─────────────────────────────────── */
    {
        dna_env_leg_ctx_t two[2];
        mk_rulesets(&two[0], 0xB7);
        mk_rulesets(&two[1], 0xB7);
        two[0].domain_id = 2;                     /* 2 then 1: descending */
        two[1].domain_id = 1;
        memset(out, 0xAA, sizeof(*out));
        memset(meters, 0xAA, sizeof(*meters));
        ms = DNA_METER_ERR_FAULT;
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, two, 2, pol, &bud, envs, 1, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_RULESETS,
              "unsorted rulesets status"); OK();
        CHECK(ms == DNA_METER_OK, "meter status on RULESETS fail"); OK();
        CHECK(all_zero((const uint8_t *)out, sizeof(*out)) &&
              all_zero((const uint8_t *)meters, sizeof(*meters)),
              "arrays not zeroed on RULESETS fail"); OK();

        dna_env_leg_ctx_t other;
        mk_rulesets(&other, 0xB7);
        other.domain_id = 2;                      /* envelope is domain 1 */
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx.w, 1, &other, 1, pol, &bud, envs, 1, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_CTX_MISSING,
              "missing ctx status"); OK();
        CHECK(pf_st == DNA_ENV_PF_OK && ms == DNA_METER_OK,
              "optional outs on CTX_MISSING"); OK();
    }

    /* ── 8. NO COMMITTED GENESIS -> ERR_CHAIN propagates ────────────── */
    {
        fixture_t fx2;
        CHECK(fx_open(&fx2) == 0, "fixture 2"); OK();
        CHECK(nodus_witness_db_migrate_v2s7(fx2.w) == 0, "migrate 2"); OK();
        memset(out, 0xAA, sizeof(*out));
        memset(meters, 0xAA, sizeof(*meters));
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(
                  fx2.w, 1, &tab, 1, pol, &bud, envs, 1, out, meters,
                  &fail_idx, &pf_st, &ms) == NODUS_V2_ENV_ERR_CHAIN,
              "no-genesis status"); OK();
        CHECK(all_zero((const uint8_t *)out, sizeof(*out)) &&
              all_zero((const uint8_t *)meters, sizeof(*meters)),
              "arrays not zeroed on ERR_CHAIN"); OK();
        fx_close(&fx2);
    }

    free(out);
    free(meters);
    free(pol);
    free(e0); free(e1); free(e2);
    fx_close(&fx);
    printf("test_v2_env_meter: %d checks OK\n", g_checks);
    return 0;
}
