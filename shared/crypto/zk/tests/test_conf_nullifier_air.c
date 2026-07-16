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
    const uint64_t nk = 0xA11CE;

    uint64_t trace[CONF_NF_WIDTH];
    uint64_t nf[4];
    if (!conf_nullifier_air_generate(cm, pos, nk, trace, nf)) {
        printf("FAIL: honest generate failed\n"); return 1;
    }

    printf("============================================================\n");
    printf("C4 nullifier AIR — ρ=CRH(cm,pos), nf=PRF(nk,ρ), WIDTH=%d\n",
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
    /* Different nk ⇒ different nf (unlinkability / key-binding). */
    {
        uint64_t t2[CONF_NF_WIDTH], nf2[4];
        conf_nullifier_air_generate(cm, pos, nk ^ 1u, t2, nf2);
        int diff = memcmp(nf, nf2, sizeof nf) != 0;
        printf("  [accept] different nk ⇒ different nf             %s\n", diff ? "OK" : "FAIL");
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
    /* REJECT: DOMSEP confusion — set DOMSEP_NF cell to DOMSEP_RHO. */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF2_OFF + p2air_input_off(1)] = DNAC_DOMSEP_RHO;
        expect_reject("DOMSEP confusion (NF uses RHO tag)", bad, cm, pos, nf);
    }
    /* REJECT: break ρ capacity carry (RHO2.in[5] != RHO1.out[5]). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_RHO2_OFF + p2air_input_off(5)] += 1;
        expect_reject("ρ capacity-carry break (G1)", bad, cm, pos, nf);
    }
    /* REJECT: nf not single-source (public NF column != NF2.out). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF_OFF + 0] += 1;
        uint64_t bad_nf[4]; memcpy(bad_nf, nf, sizeof bad_nf); bad_nf[0] += 1;
        expect_reject("nf != NF2.out (G4 single-source)", bad, cm, pos, bad_nf);
    }
    /* REJECT: wrong public nf (verifier-supplied nf != derived). */
    {
        uint64_t wrong_nf[4]; memcpy(wrong_nf, nf, sizeof wrong_nf); wrong_nf[3] += 1;
        expect_reject("wrong public nf", trace, cm, pos, wrong_nf);
    }
    /* REJECT: forge nk in NF1 without changing nf (nk one-cell binding). */
    {
        uint64_t bad[CONF_NF_WIDTH]; memcpy(bad, trace, sizeof bad);
        bad[CONF_NF_NF1_OFF + p2air_input_off(0)] += 1; /* != trace nk cell */
        expect_reject("nk-pin NF1.in[0] != nk cell", bad, cm, pos, nf);
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
    printf("C4 nullifier: honest accepted + soundness (Faerie-Gold, key-binding) + "
           "12 attacks rejected (incl. MF-1 cell-binding) — PASS\n");
    return 0;
}
