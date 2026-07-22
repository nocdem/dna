/**
 * @file test_conf_nullifier_air.c
 * @brief Dual-mode C4 — nullifier-PRF construction gate (is_zk=0).
 *
 * (accept) honest ⇒ 0 violations, nf deterministic;
 * soundness properties: same note+nk ⇒ same nf (double-spend detectable);
 *   different nk ⇒ different nf; different (cm,pos) ⇒ different ρ ⇒ different nf
 *   (Faerie-Gold ρ-uniqueness);
 * (reject) wrong ρ-input pin, DOMSEP confusion, capacity break, nf not single-
 *   source, wrong public nf ⇒ ≥1 violation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_nullifier_air.h"
#include "../note_commit.h"
#include "../shielded_domsep.h"

static int fails = 0;

static void expect_reject(const char *name, const uint64_t *trace,
                          const uint64_t cm[4], uint64_t pos, const uint64_t nf[4]) {
    int v = conf_nullifier_air_eval(trace, cm, pos, nf);
    if (v >= 1) printf("  [reject] %-42s caught (%d viol) — OK\n", name, v);
    else { printf("  [reject] %-42s NOT caught — FAIL\n", name); fails++; }
}

int main(void) {
    uint64_t cm[4];
    { uint64_t a[4] = {11, 22, 33, 44}, r[2] = {7, 8}; note_commit(500, a, r, cm); }
    const uint64_t pos = 12345;
    /* F3: nk is 4 lanes, all distinct nonzero (per-lane bugs can't hide). */
    const uint64_t nk[CONF_NF_NK_LANES] = {0xA11CE, 0xA11CF, 0xA11D0, 0xA11D1};

    uint64_t trace[CONF_NF_WIDTH];
    uint64_t nf[4];
    if (!conf_nullifier_air_generate(cm, pos, nk, trace, nf)) {
        printf("FAIL: honest generate failed\n"); return 1;
    }

    printf("============================================================\n");
    printf("C4 nullifier AIR — ρ=CRH(cm,pos), nf=PRF(nk[4],ρ), WIDTH=%d\n",
           CONF_NF_WIDTH);
    printf("============================================================\n");

    int v = conf_nullifier_air_eval(trace, cm, pos, nf);
    if (v == 0) printf("  [accept] honest nullifier witness               0 viol — OK\n");
    else { printf("  [accept] honest nullifier witness               %d viol — FAIL\n", v); fails++; }

    /* Soundness: same note + same nk ⇒ SAME nf (double-spend detectable). */
    {
        uint64_t t2[CONF_NF_WIDTH], nf2[4];
        conf_nullifier_air_generate(cm, pos, nk, t2, nf2);
        int ok = memcmp(nf, nf2, sizeof nf) == 0;
        printf("  [accept] same note+nk ⇒ same nf (double-spend)  %s\n", ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }
    /* Different nk ⇒ different nf (unlinkability / key-binding) — checked on
     * EVERY lane independently (F3: flipping any single lane must change nf). */
    {
        int diff_all = 1;
        for (unsigned lane = 0; lane < CONF_NF_NK_LANES; lane++) {
            uint64_t nk2[CONF_NF_NK_LANES];
            memcpy(nk2, nk, sizeof nk2);
            nk2[lane] ^= 1u;
            uint64_t t2[CONF_NF_WIDTH], nf2[4];
            conf_nullifier_air_generate(cm, pos, nk2, t2, nf2);
            if (memcmp(nf, nf2, sizeof nf) == 0) diff_all = 0;
        }
        printf("  [accept] different nk ⇒ different nf (per-lane)  %s\n",
               diff_all ? "OK" : "FAIL");
        if (!diff_all) fails++;
    }
    /* F3 lane-order pinned: swapping two nk lanes changes nf (order-sensitive
     * §3b packing — an order-insensitive PRF would collapse the keyspace). */
    {
        uint64_t nk_sw[CONF_NF_NK_LANES] = {nk[1], nk[0], nk[2], nk[3]};
        uint64_t t2[CONF_NF_WIDTH], nf2[4];
        conf_nullifier_air_generate(cm, pos, nk_sw, t2, nf2);
        int diff = memcmp(nf, nf2, sizeof nf) != 0;
        printf("  [accept] nk lane-swap ⇒ different nf (F3 order)  %s\n",
               diff ? "OK" : "FAIL");
        if (!diff) fails++;
    }
    /* Faerie-Gold: different pos (same cm,nk) ⇒ different ρ ⇒ different nf. */
    {
        uint64_t t2[CONF_NF_WIDTH], nf2[4];
        conf_nullifier_air_generate(cm, pos + 1, nk, t2, nf2);
        int diff = memcmp(nf, nf2, sizeof nf) != 0;
        printf("  [accept] different pos ⇒ different nf (Faerie)   %s\n", diff ? "OK" : "FAIL");
        if (!diff) fails++;
    }
    /* Different cm (same pos,nk) ⇒ different nf (cm-binding). */
    {
        uint64_t cm2[4]; memcpy(cm2, cm, sizeof cm2); cm2[0] += 1;
        uint64_t t2[CONF_NF_WIDTH], nf2[4];
        conf_nullifier_air_generate(cm2, pos, nk, t2, nf2);
        int diff = memcmp(nf, nf2, sizeof nf) != 0;
        printf("  [accept] different cm ⇒ different nf (cm-bind)   %s\n", diff ? "OK" : "FAIL");
        if (!diff) fails++;
    }

    /* DOMSEP_RHO ≠ DOMSEP_NF (G5). */
    printf("  [accept] DOMSEP_RHO != DOMSEP_NF (G5)            %s\n",
           (DNAC_DOMSEP_RHO != DNAC_DOMSEP_NF) ? "OK" : "FAIL");
    if (DNAC_DOMSEP_RHO == DNAC_DOMSEP_NF) fails++;

    /* REJECT: ρ-input not bound to the public cm (G2). */
    {
        uint64_t bad_cm[4]; memcpy(bad_cm, cm, sizeof bad_cm); bad_cm[2] += 1;
        expect_reject("ρ-input cm-pin (G2)", trace, bad_cm, pos, nf);
    }
    /* REJECT: ρ-input not bound to the public pos (G2). */
    expect_reject("ρ-input pos-pin (G2)", trace, cm, pos + 1, nf);

    /* REJECT: wrong DOMSEP_RHO pad cell (RHO2.in[1]). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_RHO2_OFF + p2air_input_off(1)] += 1;
        expect_reject("wrong DOMSEP_RHO (RHO2.in[1])", bad, cm, pos, nf);
    }
    /* REJECT: DOMSEP confusion — set DOMSEP_NF cell to DOMSEP_RHO (F3: the
     * DOMSEP moved to NF3.in[0]). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF3_OFF + p2air_input_off(0)] = DNAC_DOMSEP_RHO;
        expect_reject("DOMSEP confusion (NF uses RHO tag)", bad, cm, pos, nf);
    }
    /* REJECT: break ρ capacity carry (RHO2.in[5] != RHO1.out[5]). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_RHO2_OFF + p2air_input_off(5)] += 1;
        expect_reject("ρ capacity-carry break (G1)", bad, cm, pos, nf);
    }
    /* REJECT: nf not single-source (public NF column != NF3.out). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF_OFF + 0] += 1;
        uint64_t bad_nf[4]; memcpy(bad_nf, nf, sizeof bad_nf); bad_nf[0] += 1;
        expect_reject("nf != NF3.out (G4 single-source)", bad, cm, pos, bad_nf);
    }
    /* REJECT: wrong public nf (verifier-supplied nf != derived). */
    {
        uint64_t wrong_nf[4]; memcpy(wrong_nf, nf, sizeof wrong_nf); wrong_nf[3] += 1;
        expect_reject("wrong public nf", trace, cm, pos, wrong_nf);
    }
    /* REJECT: forge nk in NF1 without changing nf (per-lane cell binding) —
     * every lane pin checked independently (F3). */
    for (unsigned lane = 0; lane < CONF_NF_NK_LANES; lane++) {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF1_OFF + p2air_input_off(lane)] += 1; /* != trace nk cell */
        char name[64];
        snprintf(name, sizeof name, "nk-pin NF1.in[%u] != nk cell (F3)", lane);
        expect_reject(name, bad, cm, pos, nf);
    }
    /* REJECT (F3): break the NEW NF3 capacity carry (NF3.in[5] != NF2.out[5]). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF3_OFF + p2air_input_off(5)] += 1;
        expect_reject("NF3 capacity-carry break (F3)", bad, cm, pos, nf);
    }
    /* REJECT (F3): tamper a NK trace cell lane (cell != NF1 input; both halves
     * of the per-lane split must fire). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NK_OFF + 3] += 1;
        expect_reject("NK cell lane 3 tamper (F3)", bad, cm, pos, nf);
    }

    /* REJECT (MF-1): ρ-input cm-cell divergence — RHO1.in[0] != the CM trace cell.
     * At S4 the CM cell is C1's cm_carry; this pin forces ρ over the spent note. */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_RHO1_OFF + p2air_input_off(0)] += 1; /* != trace CM cell */
        expect_reject("ρ-input RHO1.in[0] != CM cell (MF-1)", bad, cm, pos, nf);
    }
    /* REJECT (MF-1): ρ-input pos-cell divergence — RHO2.in[0] != the POS trace cell. */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_RHO2_OFF + p2air_input_off(0)] += 1; /* != trace POS cell */
        expect_reject("ρ-input RHO2.in[0] != POS cell (MF-1)", bad, cm, pos, nf);
    }
    /* REJECT (MF-1): CM trace cell != public cm (the other half of the split). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_CM_OFF + 0] += 1; /* cell diverges from both public cm and RHO1.in */
        expect_reject("CM cell != public cm (MF-1)", bad, cm, pos, nf);
    }

    printf("------------------------------------------------------------\n");
    if (fails) { printf("C4 nullifier: %d FAIL\n", fails); return 1; }
    printf("C4 nullifier: honest accepted + soundness (Faerie-Gold, per-lane "
           "key-binding, F3 4-lane nk) + attacks rejected (incl. MF-1 cell-binding)"
           " — PASS\n");
    return 0;
}
