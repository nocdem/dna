/**
 * @file test_shielded_verify.c
 * @brief Phase-C C2.1 gate — dnac_shielded_verify_statement KATs.
 *
 * The consensus shielded verify (wire-recomputed publics + fresh-primed
 * transcript + SAMPLED zeta + pinned FRI **AND** N-chunk constraint check)
 * must ACCEPT a real production proof and REJECT every statement/proof tamper
 * in the C2 design v2 §4.2 list, each on its DISTINCT fail-close code:
 *
 *   T-A   ACCEPT: real production proof (h=1024, 100-query, salted) whose
 *         wire fields equal its publics and whose tx_binding =
 *         conf_txbind_map(sighash_v4).                      -> OK
 *   T-R1  tampered public (nf lane, txbind re-mapped)       -> OPENING_POINT
 *   T-R2  tampered proof byte (last blob byte)              -> any non-OK
 *   T-R3  wrong tx_binding                                  -> TXBIND
 *   T-R4  count forgery num_input (1 -> 2, txbind re-mapped)-> OPENING_POINT
 *   T-R5  count forgery num_output (1 -> 0, txbind re-mapped)-> OPENING_POINT
 *   T-R6  wrong params (TEST 2-query proof @ h=1024)        -> FRI (param pin)
 *   T-R7  wrong height (re-encoded, domains 11 -> 10)       -> HEIGHT
 *   T-R8  wire-zeta (re-encoded, trace opening point +1)    -> OPENING_POINT
 *   T-R9  FRI-passes-but-constraint-fails (forged publics:
 *         honest FS over fee+1, quotient from true publics) -> CONSTRAINTS
 *         ** the CRIT-1 isolating vector: FRI alone accepts this proof **
 *   T-R10 sf->fee != committed_fee                          -> FEE
 *   T-R11 oversize blob length                              -> OVERSIZE
 *   T-R12 non-canonical lane (>= p)                         -> NONCANONICAL
 *   T-R13 non-zero unused nf slot                           -> SLOT_NONZERO
 *   T-R14 count out of range (0 and MAX+1)                  -> COUNT
 *
 * NO-FLAKY: every assertion is a status-code equality; T-R2 (arbitrary byte
 * flip) asserts only non-OK because the flipped byte's field depends on the
 * entropy-dependent proof layout — any rejecting code is the correct
 * fail-close there.
 *
 * Publics discovery: the wire fields must EQUAL the proof publics, and
 * tx_binding feeds BACK into the prove — so the test first proves once at
 * TEST params (publics are trace-derived, param/draw-independent), reads the
 * publics, derives sighash_v4/tx_binding for the real wire fields, then runs
 * the production prove with that binding. The pass-1 proof doubles as the
 * T-R6 wrong-params vector.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_action_air.h"
#include "conf_txbind.h"
#include "field_goldilocks.h"
#include "fri_proof_codec.h"
#include "shielded_fri_params.h"
#include "shielded_verify.h"
#include "stark_prover_agg.h"
#include "zk_entropy.h"

static int g_fails = 0;

static void check(const char *name, int ok, int got) {
    printf("  %-52s %s", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        printf(" (got %d)", got);
        g_fails++;
    }
    printf("\n");
}

/* Same 1-input action as the Phase-P production gate (IN 100 = OUT 70 + FEE
 * 30, D=4), F3 lane layout: nk/ak are 4 lanes per note. */
static void build_notes(uint64_t value[3], uint8_t roles[3], uint64_t pos[3],
                        uint64_t nk[12], uint64_t ak[12], uint64_t addr[12],
                        uint64_t rcm[6], uint64_t memb_siblings[48]) {
    const uint64_t v[3] = {100, 70, 30};
    const uint8_t r[3] = {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT,
                          CONF_ACTION_ROLE_FEE};
    const uint64_t p[3] = {5, 0, 0};
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

/* Fill the wire struct's statement fields from the 43 proof publics
 * (CONF_AGGZK_PUB_* layout) — the honest wire == publics identity (D4.2/D6). */
static void sf_from_publics(const gold_fp_t *pub, dnac_tx_shielded_fields_t *sf) {
    memset(sf, 0, sizeof(*sf));
    for (unsigned j = 0; j < 4; j++)
        sf->anchor[j] = gold_fp_to_u64(pub[CONF_AGGZK_PUB_ANCHOR + j]);
    sf->num_input = (uint8_t)gold_fp_to_u64(pub[CONF_AGGZK_PUB_NUMIN]);
    for (unsigned s = 0; s < 4; s++)
        for (unsigned j = 0; j < 4; j++)
            sf->nf_set[s][j] =
                gold_fp_to_u64(pub[CONF_AGGZK_PUB_NFSLOT + s * 4 + j]);
    sf->num_output = (uint8_t)gold_fp_to_u64(pub[CONF_AGGZK_PUB_NUMOUT]);
    for (unsigned s = 0; s < 4; s++)
        for (unsigned j = 0; j < 4; j++)
            sf->output_commit[s][j] =
                gold_fp_to_u64(pub[CONF_AGGZK_PUB_OCOMMIT + s * 4 + j]);
    sf->fee = gold_fp_to_u64(pub[CONF_AGGZK_PUB_FEE]);
}

/* tx_binding = conf_txbind_map(sighash_v4(sf, chain_id)) — the same linked
 * libdna sighash + zk map the verifier uses (single source, G-DET-2). */
static int bind_sf(dnac_tx_shielded_fields_t *sf, const uint8_t chain_id[32]) {
    uint8_t sighash[CONF_TXBIND_SIGHASH_LEN];
    uint64_t lanes[CONF_TXBIND_LANES];
    if (dnac_tx_shielded_sighash(sf, chain_id, sighash) != 0) return 0;
    if (!conf_txbind_map(sighash, lanes)) return 0;
    for (unsigned j = 0; j < 4; j++) sf->tx_binding[j] = lanes[j];
    return 1;
}

int main(void) {
    printf("============================================================\n");
    printf("C2.1 — consensus shielded verify (wire-recomputed statement)\n");
    printf("============================================================\n");

    uint64_t value[3], pos[3], nk[12], ak[12], addr[12], rcm[6],
        memb_siblings[48];
    uint8_t roles[3];
    build_notes(value, roles, pos, nk, ak, addr, rcm, memb_siblings);

    uint8_t chain_id[32];
    for (unsigned i = 0; i < 32; i++) chain_id[i] = (uint8_t)(0xC0 + i);

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
    inst.log_height = (unsigned)DNAC_SHIELDED_BASE_LOG_HEIGHT;

    /* ── Pass 1: TEST-params prove @ h=1024 — publics discovery + the T-R6
     * wrong-params wire vector (committed height matches the pin, so the
     * param check is the ONLY thing that fires). ── */
    uint8_t *tp_buf = NULL;
    size_t tp_len = 0;
    dnac_tx_shielded_fields_t sf; /* the honest statement (pass-1 publics) */
    {
        const size_t h = (size_t)1 << inst.log_height;
        const size_t nd = DNAC_AGG_PROVER_TOTAL_DRAWS(h);
        uint64_t *draws = (uint64_t *)malloc(nd * sizeof(uint64_t));
        if (!draws || dnac_zk_fill_draws(draws, nd) != 0) {
            printf("  entropy/alloc FAILED\n");
            return 1;
        }
        dnac_agg_prover_instance_t ti = inst;
        ti.draws = draws;
        ti.num_draws = nd;
        static const uint64_t dummy_bind[4] = {0, 0, 0, 0};
        ti.tx_binding = dummy_bind; /* pass 1 only discovers the publics */
        dnac_agg_prover_proof_t *tp = NULL;
        if (dnac_agg_prover_prove(&ti, &tp) != DNAC_PROVER_OK) {
            printf("  pass-1 TEST prove FAILED\n");
            free(draws);
            return 1;
        }
        size_t np = 0;
        const gold_fp_t *pub = dnac_agg_prover_proof_publics(tp, &np);
        if (np != (size_t)CONF_AGGZK_NUM_PUBLICS) {
            printf("  pass-1 publics len %zu != 43\n", np);
            free(draws);
            return 1;
        }
        sf_from_publics(pub, &sf);
        if (!bind_sf(&sf, chain_id)) {
            printf("  pass-1 bind FAILED\n");
            free(draws);
            return 1;
        }
        /* Re-prove pass 1 WITH the real binding so its wire vector is a
         * statement-consistent wrong-PARAMS-only proof (T-R6). */
        dnac_agg_prover_proof_free(tp);
        tp = NULL;
        ti.tx_binding = sf.tx_binding;
        if (dnac_agg_prover_prove(&ti, &tp) != DNAC_PROVER_OK ||
            dnac_agg_prover_proof_wire_encode_testonly(tp, &tp_buf, &tp_len) !=
                DNAC_FRI_CODEC_OK) {
            printf("  pass-1 re-prove/encode FAILED\n");
            free(draws);
            return 1;
        }
        dnac_agg_prover_proof_free(tp);
        free(draws);
    }

    /* ── Pass 2: PRODUCTION prove with the real tx_binding (T-A base). ── */
    uint8_t *buf = NULL;
    size_t len = 0;
    gold_fp_t prod_publics[CONF_AGGZK_NUM_PUBLICS];
    {
        dnac_agg_prover_instance_t pi = inst;
        pi.tx_binding = sf.tx_binding;
        dnac_agg_prover_proof_t *pf = NULL;
        if (dnac_agg_prover_prove_production(&pi, &pf) != DNAC_PROVER_OK) {
            printf("  production prove FAILED\n");
            return 1;
        }
        size_t np = 0;
        const gold_fp_t *pub = dnac_agg_prover_proof_publics(pf, &np);
        memcpy(prod_publics, pub, np * sizeof(gold_fp_t));
        /* Cross-check: production publics == pass-1 publics (trace-derived,
         * param/draw-independent) — guards the two-pass construction. */
        dnac_tx_shielded_fields_t sf2;
        sf_from_publics(pub, &sf2);
        if (memcmp(sf2.anchor, sf.anchor, sizeof sf.anchor) != 0 ||
            memcmp(sf2.nf_set, sf.nf_set, sizeof sf.nf_set) != 0 ||
            memcmp(sf2.output_commit, sf.output_commit,
                   sizeof sf.output_commit) != 0 ||
            sf2.num_input != sf.num_input || sf2.num_output != sf.num_output ||
            sf2.fee != sf.fee) {
            printf("  production/pass-1 publics DIVERGED\n");
            return 1;
        }
        if (dnac_agg_prover_proof_wire_encode_testonly(pf, &buf, &len) !=
            DNAC_FRI_CODEC_OK) {
            printf("  production wire encode FAILED\n");
            return 1;
        }
        dnac_agg_prover_proof_free(pf);
    }
    sf.fri_proof = buf;
    sf.fri_proof_len = (uint32_t)len;
    const uint64_t committed_fee = sf.fee;

    /* ── T-A: the real production proof is ACCEPTED. ── */
    {
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&sf, chain_id, committed_fee);
        check("T-A   production proof ACCEPT", st == DNAC_SHIELDED_VERIFY_OK,
              (int)st);
    }

    /* ── T-R1: tampered public (nf lane +1, binding re-mapped so the txbind
     * gate passes and the FS divergence is what fires). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.nf_set[0][0] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(t.nf_set[0][0]),
                                       gold_fp_one()));
        if (!bind_sf(&t, chain_id)) { g_fails++; }
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R1  tampered nf public -> OPENING_POINT",
              st == DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT, (int)st);
    }

    /* ── T-R2: tampered proof byte (fail-close, any rejecting code). ── */
    {
        uint8_t *b2 = (uint8_t *)malloc(len);
        memcpy(b2, buf, len);
        b2[len - 1] ^= 0x01;
        dnac_tx_shielded_fields_t t = sf;
        t.fri_proof = b2;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R2  tampered proof byte -> reject",
              st != DNAC_SHIELDED_VERIFY_OK, (int)st);
        free(b2);
    }

    /* ── T-R3: wrong tx_binding. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.tx_binding[0] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(t.tx_binding[0]),
                                       gold_fp_one()));
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R3  wrong tx_binding -> TXBIND",
              st == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)st);
    }

    /* ── T-R4: count forgery — wire num_input=2 vs proven 1 (G-SEC-2: the
     * count SCALAR is bound, not just slot values). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_input = 2; /* slot 1 stays zero — canonical encoding holds */
        if (!bind_sf(&t, chain_id)) { g_fails++; }
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R4  count forgery num_input -> OPENING_POINT",
              st == DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT, (int)st);
    }

    /* ── T-R5: count forgery — wire num_output=0 vs proven 1. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_output = 0;
        memset(t.output_commit, 0, sizeof t.output_commit);
        if (!bind_sf(&t, chain_id)) { g_fails++; }
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R5  count forgery num_output -> OPENING_POINT",
              st == DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT, (int)st);
    }

    /* ── T-R6: wrong params — the TEST 2-query proof at the pinned height;
     * everything matches except the param set (G-SEC-4 pin bites). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.fri_proof = tp_buf;
        t.fri_proof_len = (uint32_t)tp_len;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R6  TEST-params proof -> FRI (param pin)",
              st == DNAC_SHIELDED_VERIFY_ERR_FRI, (int)st);
    }

    /* ── T-R7/T-R8: re-encoded wire tampers — decode the honest package, copy
     * the commitment metadata, patch, re-encode. ── */
    {
        dnac_fri_wire_package_t *pkg = NULL;
        if (dnac_fri_proof_decode(buf, len, &pkg) != DNAC_FRI_CODEC_OK) {
            printf("  T-R7/8 decode FAILED\n");
            g_fails += 2;
        } else {
            size_t n = 0;
            const dnac_fri_commitment_with_opening_points_t *coms =
                dnac_fri_wire_commitments(pkg, &n);
            /* mutable copies of the 3 coms + their matrix arrays */
            dnac_fri_commitment_with_opening_points_t c2[3];
            dnac_fri_matrix_openings_t m0[1], m1[1], m2[8];
            memcpy(c2, coms, sizeof c2);
            memcpy(m0, coms[0].matrices, sizeof m0);
            memcpy(m1, coms[1].matrices, sizeof m1);
            memcpy(m2, coms[2].matrices, sizeof m2);
            c2[0].matrices = m0;
            c2[1].matrices = m1;
            c2[2].matrices = m2;

            /* T-R7: every committed domain 11 -> 10 (height pin, G-SEC-4). */
            m0[0].domain.log_size = 10;
            m1[0].domain.log_size = 10;
            for (unsigned k = 0; k < 8; k++) m2[k].domain.log_size = 10;
            uint8_t *b7 = NULL;
            size_t l7 = 0;
            if (dnac_fri_proof_encode(dnac_fri_wire_params(pkg),
                                      dnac_fri_wire_proof(pkg), c2, 3, &b7,
                                      &l7) == DNAC_FRI_CODEC_OK) {
                dnac_tx_shielded_fields_t t = sf;
                t.fri_proof = b7;
                t.fri_proof_len = (uint32_t)l7;
                dnac_shielded_verify_status_t st =
                    dnac_shielded_verify_statement(&t, chain_id, committed_fee);
                check("T-R7  wire height 11->10 -> HEIGHT",
                      st == DNAC_SHIELDED_VERIFY_ERR_HEIGHT, (int)st);
                free(b7);
            } else {
                printf("  T-R7 re-encode FAILED\n");
                g_fails++;
            }

            /* T-R8: restore heights; move the trace opening coordinate off the
             * derived zeta (H2: a wire-chosen opening point is never trusted). */
            m0[0].domain.log_size = 11;
            m1[0].domain.log_size = 11;
            for (unsigned k = 0; k < 8; k++) m2[k].domain.log_size = 11;
            dnac_fri_opening_point_t tpts[2];
            memcpy(tpts, m1[0].points, sizeof tpts);
            tpts[0].point.a = gold_fp_add(tpts[0].point.a, gold_fp_one());
            m1[0].points = tpts;
            uint8_t *b8 = NULL;
            size_t l8 = 0;
            if (dnac_fri_proof_encode(dnac_fri_wire_params(pkg),
                                      dnac_fri_wire_proof(pkg), c2, 3, &b8,
                                      &l8) == DNAC_FRI_CODEC_OK) {
                dnac_tx_shielded_fields_t t = sf;
                t.fri_proof = b8;
                t.fri_proof_len = (uint32_t)l8;
                dnac_shielded_verify_status_t st =
                    dnac_shielded_verify_statement(&t, chain_id, committed_fee);
                check("T-R8  wire-zeta opening point -> OPENING_POINT",
                      st == DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT, (int)st);
                free(b8);
            } else {
                printf("  T-R8 re-encode FAILED\n");
                g_fails++;
            }
            dnac_fri_wire_free(pkg);
        }
    }

    /* ── T-R9: the CRIT-1 isolating vector — an honest-FS proof over FORGED
     * publics (fee+1, binding re-mapped) whose quotient came from the TRUE
     * trace publics. FRI ACCEPTS it; only the N-chunk constraint check can
     * reject. This KAT is what proves the verify chain actually RUNS the
     * constraint check (no tamper KAT above can isolate its absence). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.fee = sf.fee + 1;
        if (!bind_sf(&t, chain_id)) { g_fails++; }
        uint64_t forged[CONF_AGGZK_NUM_PUBLICS];
        for (size_t i = 0; i < (size_t)CONF_AGGZK_NUM_PUBLICS; i++)
            forged[i] = gold_fp_to_u64(prod_publics[i]);
        forged[CONF_AGGZK_PUB_FEE] = t.fee;
        for (unsigned j = 0; j < 4; j++)
            forged[CONF_AGGZK_PUB_TXBIND + j] = t.tx_binding[j];
        dnac_agg_prover_instance_t fi = inst;
        fi.tx_binding = sf.tx_binding; /* TRUE binding: the trace/quotient are
                                        * built from the TRUE publics */
        dnac_agg_prover_proof_t *fp = NULL;
        uint8_t *fb = NULL;
        size_t fl = 0;
        if (dnac_agg_prover_prove_production_forged_publics_testonly(
                &fi, forged, &fp) != DNAC_PROVER_OK ||
            dnac_agg_prover_proof_wire_encode_testonly(fp, &fb, &fl) !=
                DNAC_FRI_CODEC_OK) {
            printf("  T-R9 forge prove/encode FAILED\n");
            g_fails++;
        } else {
            t.fri_proof = fb;
            t.fri_proof_len = (uint32_t)fl;
            dnac_shielded_verify_status_t st = dnac_shielded_verify_statement(
                &t, chain_id, /*committed_fee=*/t.fee);
            check("T-R9  FRI-passes-constraint-fails -> CONSTRAINTS",
                  st == DNAC_SHIELDED_VERIFY_ERR_CONSTRAINTS, (int)st);
            free(fb);
        }
        if (fp) dnac_agg_prover_proof_free(fp);
    }

    /* ── T-R10: fee != committed_fee (D7.2 single fee authority). ── */
    {
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&sf, chain_id, committed_fee + 1);
        check("T-R10 fee != committed_fee -> FEE",
              st == DNAC_SHIELDED_VERIFY_ERR_FEE, (int)st);
    }

    /* ── T-R11: oversize blob length (fail-close, no read past cap). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.fri_proof_len = (uint32_t)DNAC_FRI_WIRE_MAX_TOTAL_LEN + 1u;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R11 oversize blob -> OVERSIZE",
              st == DNAC_SHIELDED_VERIFY_ERR_OVERSIZE, (int)st);
    }

    /* ── T-R12: non-canonical lane (>= p). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.nf_set[0][0] = GOLDILOCKS_P;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R12 lane >= p -> NONCANONICAL",
              st == DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL, (int)st);
    }

    /* ── T-R13: non-zero unused nf slot (DET-S5-3 canonical encoding). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.nf_set[3][0] = 1;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        check("T-R13 unused nf slot != 0 -> SLOT_NONZERO",
              st == DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO, (int)st);
    }

    /* ── T-R14: counts out of range. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_input = 0;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        int ok = (st == DNAC_SHIELDED_VERIFY_ERR_COUNT);
        t = sf;
        t.num_input = DNAC_SHIELDED_MAX_INPUTS + 1;
        st = dnac_shielded_verify_statement(&t, chain_id, committed_fee);
        ok = ok && (st == DNAC_SHIELDED_VERIFY_ERR_COUNT);
        check("T-R14 count out of range -> COUNT", ok, (int)st);
    }

    free(tp_buf);
    free(buf);

    printf("------------------------------------------------------------\n");
    if (g_fails == 0) {
        printf("C2.1 SHIELDED VERIFY GATE: GREEN — accept + 13 fail-close\n");
        printf("  rejects incl. the CRIT-1 constraint-check isolator.\n");
        printf("============================================================\n");
        return 0;
    }
    printf("C2.1 SHIELDED VERIFY GATE: RED (%d failures)\n", g_fails);
    return 1;
}
