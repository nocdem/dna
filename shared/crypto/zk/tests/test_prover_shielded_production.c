/**
 * @file test_prover_shielded_production.c
 * @brief Phase-P gate — production aggregate prover at the PINNED shielded FRI
 *        params, verified through the pinned consensus wire entry.
 *
 * Closes the S6-roadmap P1 gate ("a real 100-query proof reaches DNAC_FRI_OK
 * on the pinned dnac_fri_verify_wire_shielded path"):
 *
 *   T1  height pin: dnac_agg_prover_prove_production REJECTS log_height != 10
 *       (the C1 fixed H=1024 pin; a smaller trace would be rejected by the
 *       verifier's committed-height==11 guard, so the entry fails close).
 *   T2  production prove: 1-input action (IN 100 = OUT 70 + FEE 30, D=4) at
 *       h=1024, OS-entropy draws AND leaf salts (genuinely salted, M3b),
 *       pinned params (num_queries=100, log_final_poly_len=0, query_pow=16
 *       -> 216-bit conjectured soundness). Internally self-verified (FRI with
 *       the 16-bit PoW witness checks + N-chunk constraint check).
 *   T3  pinned wire gate: serialize (wire v2, salted) and verify the BYTES via
 *       dnac_fri_verify_wire_shielded -> CODEC_OK + DNAC_FRI_OK. Exercises
 *       params-equality, pinned-param substitution, committed-height==11 and
 *       the query-PoW check on the decode path.
 *   T4  param pin bites: a TEST-params proof (dnac_agg_prover_prove, 2-query)
 *       FAILS the same wire gate with SHIELDED_PARAM_MISMATCH.
 *
 * NO-FLAKY: every assertion is on a status code, never on an entropy-dependent
 * value — the outcome is identical for every OS-entropy stream (same pattern
 * as the conf prover's production T7).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_action_air.h"
#include "note_commit.h"
#include "shielded_fri_params.h"
#include "stark_prover_agg.h"
#include "zk_entropy.h"

/* The 1-input action instance (== dump_conf_action_agg_air_zk note set): the
 * witness data is height-independent; only the padding grows to H=1024. */
static void build_notes(uint64_t value[3], uint8_t roles[3], uint64_t pos[3],
                        uint64_t nk[12], uint64_t ak[12], uint64_t addr[12],
                        uint64_t rcm[6], uint64_t memb_siblings[48]) {
    const uint64_t v[3] = {100, 70, 30};
    const uint8_t r[3] = {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT,
                          CONF_ACTION_ROLE_FEE};
    const uint64_t p[3] = {5, 0, 0};
    /* F3: nk/ak are 4 Goldilocks lanes PER NOTE ([blk*4+lane], instance doc
     * stark_prover_agg.h:72-73; generate reads nk[i*4+j] for EVERY note,
     * conf_action_air.c:131-135). The pre-F3 [3] scalar arrays here were a
     * 9-element stack OOB read — fixed to the full 3x4 lane layout. */
    const uint64_t k[12] = {0x22221111ULL, 0x22222222ULL, 0x22223333ULL,
                            0x22224444ULL, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint64_t a[12] = {0x11111111ULL, 0x11112222ULL, 0x11113333ULL,
                            0x11114444ULL, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint64_t ad[12] = {0, 0, 0, 0, 0xAA01, 0xAA02, 0xAA03, 0xAA04,
                             0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4};
    const uint64_t rc[6] = {0x11, 0x12, 0x21, 0x22, 0x31, 0x32};
    const uint64_t sib[48] = {
        0x1001, 0x1002, 0x1003, 0x1004, 0x2001, 0x2002, 0x2003, 0x2004,
        0x3001, 0x3002, 0x3003, 0x3004, 0x4001, 0x4002, 0x4003, 0x4004,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(value, v, sizeof v);
    memcpy(roles, r, sizeof r);
    memcpy(pos, p, sizeof p);
    memcpy(nk, k, sizeof k);
    memcpy(ak, a, sizeof a);
    memcpy(addr, ad, sizeof ad);
    memcpy(rcm, rc, sizeof rc);
    memcpy(memb_siblings, sib, 48 * sizeof(uint64_t));
}

int main(void) {
    printf("============================================================\n");
    printf("Phase-P — PRODUCTION shielded prover gate (pinned FRI params)\n");
    printf("  num_queries=%zu log_final_poly_len=%zu query_pow=%zu"
           " (%zu-bit conjectured)\n",
           (size_t)DNAC_SHIELDED_FRI_NUM_QUERIES,
           (size_t)DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN,
           (size_t)DNAC_SHIELDED_FRI_QUERY_POW_BITS,
           (size_t)DNAC_SHIELDED_FRI_SOUNDNESS_BITS);
    printf("============================================================\n");

    int fails = 0;

    uint64_t value[3], pos[3], nk[12], ak[12], addr[12], rcm[6],
        memb_siblings[48];
    uint8_t roles[3];
    build_notes(value, roles, pos, nk, ak, addr, rcm, memb_siblings);
    static const uint64_t kat_txbind[4] = {
        0x1111111111111111ULL, 0x2222222222222222ULL,
        0x3333333333333333ULL, 0x4444444444444444ULL};

    dnac_agg_prover_instance_t inst;
    memset(&inst, 0, sizeof inst);
    inst.value = value;
    inst.addr = addr;
    inst.rcm = rcm;
    inst.roles = roles;
    inst.pos = pos;
    inst.nk = nk;
    inst.ak = ak;
    inst.num_notes = 3;
    inst.memb_siblings = memb_siblings;
    inst.tx_binding = kat_txbind;

    /* ── T1: height pin — anything but the C1 fixed H=1024 fails close. ── */
    {
        dnac_agg_prover_proof_t *pf = NULL;
        inst.log_height = 7; /* h=128: verifier would reject committed 8 != 11 */
        dnac_prover_status_t st = dnac_agg_prover_prove_production(&inst, &pf);
        int ok = (st == DNAC_PROVER_ERR_PARAM) && (pf == NULL);
        printf("  T1 production entry REJECTS log_height!=%zu          %s\n",
               (size_t)DNAC_SHIELDED_BASE_LOG_HEIGHT, ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* ── T2: production prove at h=1024, OS entropy, pinned params. ── */
    dnac_agg_prover_proof_t *pf = NULL;
    {
        inst.log_height = (unsigned)DNAC_SHIELDED_BASE_LOG_HEIGHT;
        dnac_prover_status_t st = dnac_agg_prover_prove_production(&inst, &pf);
        int ok = (st == DNAC_PROVER_OK) && (pf != NULL);
        printf("  T2 production prove (h=1024, salted, self-verified)   %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) {
            printf("     status=%d\n", (int)st);
            return 1; /* nothing else to check without a proof */
        }
    }

    /* ── T3: the pinned consensus wire gate — the roadmap P1 milestone. ── */
    {
        dnac_fri_status_t fs = (dnac_fri_status_t)-1;
        dnac_fri_codec_status_t cs =
            dnac_agg_prover_wire_selfcheck_shielded(pf, &fs);
        int ok = (cs == DNAC_FRI_CODEC_OK) && (fs == DNAC_FRI_OK);
        printf("  T3 dnac_fri_verify_wire_shielded on the WIRE bytes    %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) {
            printf("     codec=%d fri=%d\n", (int)cs, (int)fs);
            fails++;
        }
    }

    /* ── T4: param pin bites — a TEST-params (2-query) proof is REJECTED by
     * the same wire gate with SHIELDED_PARAM_MISMATCH. h=128 keeps it fast;
     * the params check fires before the height check (fri_proof_codec.c). ── */
    {
        const unsigned lh = 7;
        const size_t h = (size_t)1 << lh;
        const size_t nd = DNAC_AGG_PROVER_TOTAL_DRAWS(h);
        uint64_t *draws = (uint64_t *)malloc(nd * sizeof(uint64_t));
        int ok = 0;
        if (draws && dnac_zk_fill_draws(draws, nd) == 0) {
            dnac_agg_prover_instance_t ti = inst;
            ti.log_height = lh;
            ti.draws = draws;
            ti.num_draws = nd;
            ti.salt_draws = NULL;
            ti.num_salt_draws = 0;
            dnac_agg_prover_proof_t *tp = NULL;
            if (dnac_agg_prover_prove(&ti, &tp) == DNAC_PROVER_OK) {
                dnac_fri_status_t fs = (dnac_fri_status_t)-1;
                dnac_fri_codec_status_t cs =
                    dnac_agg_prover_wire_selfcheck_shielded(tp, &fs);
                ok = (cs == DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH) &&
                     (fs != DNAC_FRI_OK);
                if (!ok)
                    printf("     codec=%d fri=%d (want codec=%d, fri!=OK)\n",
                           (int)cs, (int)fs,
                           (int)DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH);
                dnac_agg_prover_proof_free(tp);
            }
        }
        free(draws);
        printf("  T4 TEST-params proof REJECTED (param pin bites)       %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    dnac_agg_prover_proof_free(pf);

    printf("------------------------------------------------------------\n");
    if (fails == 0) {
        printf("PHASE-P PRODUCTION GATE: GREEN — pinned-param salted proof\n");
        printf("  accepted on the consensus wire path; wrong height and wrong\n");
        printf("  params both fail close.\n");
        printf("============================================================\n");
        return 0;
    }
    printf("PHASE-P PRODUCTION GATE: RED (%d failures)\n", fails);
    return 1;
}
