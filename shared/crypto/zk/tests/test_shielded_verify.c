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
 *         conf_txbind_map(sighash_v5).                      -> OK
 *
 * LEDGER-V2 S8 Gate 2 (2026-08-06): the entry takes a
 * dnac_shielded_verify_ctx_t instead of a bare chain_id (sighash_v5 binds the
 * whole ExecutionContext), the statement is 45 publics with the two transparent
 * legs, num_input == 0 is LEGAL, and three new fail-close classes exist —
 * STATEMENT_VERSION (15), BOUNDARY (16), ANCHOR (17). The S8 adversarial matrix
 * is the T-S* block at the end.
 * d4.c-3 (2026-07-26): shielded_verify.c re-based onto DZKF v4 + dnac_batch_verify.
 * The v4 wire carries NO opening points (the verifier samples zeta), so the v3
 * OPENING_POINT class is structurally closed: T-R1/R4/R5 (tampered publics/counts)
 * now reject via Fiat-Shamir divergence inside dnac_batch_verify -> FRI; T-R7/R8
 * are RETIRED (no wire height/opening-point field to tamper; degree_bits is a
 * compile-time pin, so a wrong-height proof simply fails FRI).
 *
 *   T-R1  tampered public (nf lane, txbind re-mapped)       -> FRI (FS-divergence)
 *   T-R2  tampered proof byte (last blob byte)              -> any non-OK
 *   T-R3  wrong tx_binding                                  -> TXBIND
 *   T-R4  count forgery num_input (1 -> 2, txbind re-mapped)-> FRI (FS-divergence)
 *   T-R5  count forgery num_output (1 -> 0, txbind re-mapped)-> FRI (FS-divergence)
 *   T-R6  wrong params (TEST 2-query proof @ h=1024)        -> FRI (param pin)
 *   T-R7  RETIRED (v4 has no wire height field; degree_bits pinned)
 *   T-R8  RETIRED (v4 carries no opening points -> not constructible)
 *   T-R9  FRI-passes-but-constraint-fails (forged publics:
 *         honest FS over fee+1, quotient from true publics) -> CONSTRAINTS
 *         ** the CRIT-1 isolating vector: FRI alone accepts this proof **
 *   T-R10 sf->fee != committed_fee                          -> FEE
 *   T-R11 oversize blob length                              -> OVERSIZE
 *   T-R12 non-canonical lane (>= p)                         -> NONCANONICAL
 *   T-R13 non-zero unused nf slot                           -> SLOT_NONZERO
 *   T-R14 count out of range (num_input MAX+1, num_output MAX+1) -> COUNT
 *         ⚠ S8: num_input == 0 is NO LONGER a COUNT reject — it is the legal
 *         SHIELD shape. Its rules moved to T-S1 / T-S2.
 *   T-S1  num_input == 0 with a non-zero nf slot            -> SLOT_NONZERO
 *   T-S2  num_input == 0 with a non-zero anchor             -> ANCHOR (17)
 *   T-S3  boundary 2^63-1 passes the range gate (rejects later, on FS
 *         divergence); boundary 2^63 on either leg          -> BOUNDARY (16)
 *   T-S4  Goldilocks-adjacent boundaries (p-1, p, 2^64-1)   -> BOUNDARY (16)
 *   T-S5  statement_version != 1, and vctx == NULL          -> STATEMENT_VERSION
 *
 * NO-FLAKY: every assertion is a status-code equality; T-R2 (arbitrary byte
 * flip) asserts only non-OK because the flipped byte's field depends on the
 * entropy-dependent proof layout — any rejecting code is the correct
 * fail-close there.
 *
 * Publics discovery: the wire fields must EQUAL the proof publics, and
 * tx_binding feeds BACK into the prove — so the test first proves once at
 * TEST params (publics are trace-derived, param/draw-independent), reads the
 * publics, derives sighash_v5/tx_binding for the real wire fields, then runs
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

#include "conf_action_agg_air.h" /* CONF_AGG_TREE_DEPTH (D = 24 since S8)      */
#include "conf_action_air.h"
#include "conf_txbind.h"
#include "dnac/tx_wire.h" /* dna_exec_context_t + dnac_sighash_v5 (SHARED codec) */
#include "field_goldilocks.h"
#include "fri_proof_codec.h"
#include "shielded_fri_params.h"
#include "shielded_verify.h"
#include "stark_prover_agg.h"
#include "zk_entropy.h"

static int g_fails = 0;

/* S8 Gate 2: sibling stride is D levels x 4 lanes, sized by the MACRO. */
#define SV_SIB_STRIDE ((size_t)CONF_AGG_TREE_DEPTH * 4)
#define SV_SIB_LEN    (3 * SV_SIB_STRIDE)
/* The S8 statement's two transparent legs. This action is value-CONSERVING
 * (IN 100 = OUT 70 + OUT 30), so both legs are 0 — the historical BAL == 0. */
#define SV_BOUNDARY_IN  0u
#define SV_BOUNDARY_OUT 0u
/* Non-zero so the field is genuinely carried through the sighash_v5 preimage
 * (it is bound but is NOT a proof public). */
#define SV_EXPIRY_HEIGHT 123456u

static void check(const char *name, int ok, int got) {
    printf("  %-52s %s", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        printf(" (got %d)", got);
        g_fails++;
    }
    printf("\n");
}

/* Same 1-input action as the Phase-P production gate (IN 100 = OUT 70 + OUT 30,
 * D = CONF_AGG_TREE_DEPTH), F3 lane layout: nk/ak are 4 lanes per note.
 * ⚠ S8 Gate 2: note 2 WAS a CONF_ACTION_ROLE_FEE block. IS_FEE is pinned ZERO
 * and generate rejects a FEE-role note, so it is now a second OUTPUT of the
 * SAME value (the set stays conserving) and the fee reaches the statement as
 * the independent public inst.fee (set in main). num_output is therefore 2. */
static void build_notes(uint64_t value[3], uint8_t roles[3], uint64_t pos[3],
                        uint64_t nk[12], uint64_t ak[12], uint64_t addr[12],
                        uint64_t rcm[6], uint64_t *memb_siblings) {
    const uint64_t v[3] = {100, 70, 30};
    const uint8_t r[3] = {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT,
                          CONF_ACTION_ROLE_OUTPUT};
    const uint64_t p[3] = {5, 0, 0};
    const uint64_t k[12] = {0x22221111ULL, 0x22222222ULL, 0x22223333ULL,
                            0x22224444ULL, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint64_t a[12] = {0x11111111ULL, 0x11112222ULL, 0x11113333ULL,
                            0x11114444ULL, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint64_t ad[12] = {0, 0, 0, 0, 0xAA01, 0xAA02, 0xAA03, 0xAA04,
                             0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4};
    const uint64_t rc[6] = {0x11, 0x12, 0x21, 0x22, 0x31, 0x32};
    memcpy(value, v, sizeof v);
    memcpy(roles, r, sizeof r);
    memcpy(pos, p, sizeof p);
    memcpy(nk, k, sizeof k);
    memcpy(ak, a, sizeof a);
    memcpy(addr, ad, sizeof ad);
    memcpy(rcm, rc, sizeof rc);
    /* Block 0 (the only INPUT) walks D levels. The pre-S8 fixture spelled out
     * 4 literal levels {0x(L+1)001..0x(L+1)004}; the SAME rule now fills all D,
     * so levels 0-3 stay byte-identical. Blocks 1/2 are OUTPUTs — their sibling
     * slots are never read, so they stay zero. */
    memset(memb_siblings, 0, SV_SIB_LEN * sizeof(uint64_t));
    for (unsigned L = 0; L < (unsigned)CONF_AGG_TREE_DEPTH; L++)
        for (unsigned j = 0; j < 4; j++)
            memb_siblings[(size_t)L * 4 + j] =
                (uint64_t)0x1000 * (L + 1) + 0x0001 + (uint64_t)j;
}

/* Fill the wire struct's statement fields from the 45 proof publics
 * (CONF_AGGZK_PUB_* layout) — the honest wire == publics identity (D4.2/D6).
 * S8 Gate 2 adds the two transparent legs (which ARE publics) and
 * expiry_height (which is NOT — it is sighash_v5-bound only, so the test
 * supplies it). */
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
    sf->boundary_in = gold_fp_to_u64(pub[CONF_AGGZK_PUB_BIN]);
    sf->boundary_out = gold_fp_to_u64(pub[CONF_AGGZK_PUB_BOUT]);
    sf->expiry_height = SV_EXPIRY_HEIGHT;
}

/* tx_binding = conf_txbind_map(sighash_v5(ctx, sect_version, ruleset_hash, st,
 * tagged-empty tleg/ct)) — the SAME shared codec (shared/dnac/tx_wire.c) and zk
 * map the verifier uses, assembled exactly as shielded_verify.c:222-270 does
 * (wire_version and sect_version PINNED, tx_binding excluded from its own
 * preimage). Single source, G-DET-2 — never a re-implementation. */
static int bind_sf(dnac_tx_shielded_fields_t *sf,
                   const dnac_shielded_verify_ctx_t *vctx) {
    dna_exec_context_t ectx;
    if (dna_exec_context_init(&ectx, vctx->chain_id, vctx->domain_id,
                              vctx->pool_id, vctx->tx_type,
                              (uint8_t)DNAC_TXW3_WIRE_VERSION,
                              vctx->ruleset_version,
                              vctx->statement_version) != 0)
        return 0;

    dnac_txw3_shielded_t st;
    memset(&st, 0, sizeof st);
    st.sect_version = (uint8_t)DNAC_TXW3_SECT_VERSION;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
        st.anchor[j] = sf->anchor[j];
    st.num_input = sf->num_input;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
            st.nf_set[s][j] = sf->nf_set[s][j];
    st.num_output = sf->num_output;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
            st.output_commit[s][j] = sf->output_commit[s][j];
    st.fee = sf->fee;
    st.boundary_in = sf->boundary_in;
    st.boundary_out = sf->boundary_out;
    st.expiry_height = sf->expiry_height;
    st.fri_len = sf->fri_proof_len;

    uint8_t tleg[DNAC_TXW_HASH_LEN], ctc[DNAC_TXW_HASH_LEN];
    if (dnac_tleg_commit_empty(tleg) != 0 || dnac_ct_commit_empty(ctc) != 0)
        return 0;

    uint8_t sighash[CONF_TXBIND_SIGHASH_LEN];
    uint64_t lanes[CONF_TXBIND_LANES];
    if (dnac_sighash_v5(&ectx, (uint8_t)DNAC_TXW3_SECT_VERSION,
                        vctx->ruleset_hash, &st, tleg, ctc, sighash) != 0)
        return 0;
    if (!conf_txbind_map(sighash, lanes)) return 0;
    for (unsigned j = 0; j < 4; j++) sf->tx_binding[j] = lanes[j];
    return 1;
}

int main(void) {
    printf("============================================================\n");
    printf("C2.1 — consensus shielded verify (wire-recomputed statement)\n");
    printf("============================================================\n");

    uint64_t value[3], pos[3], nk[12], ak[12], addr[12], rcm[6],
        memb_siblings[SV_SIB_LEN];
    uint8_t roles[3];
    build_notes(value, roles, pos, nk, ak, addr, rcm, memb_siblings);

    /* S8 Gate 2: the consensus-authoritative binding context. Every field is
     * caller-supplied from execution state; wire_version and sect_version are
     * PINNED inside the entry and are deliberately absent here. */
    dnac_shielded_verify_ctx_t vctx;
    memset(&vctx, 0, sizeof vctx);
    for (unsigned i = 0; i < 32; i++) vctx.chain_id[i] = (uint8_t)(0xC0 + i);
    vctx.domain_id = DNA_DOMAIN_CORE;
    vctx.pool_id = DNAC_SHIELDED_POOL_V1;
    vctx.tx_type = (uint8_t)DNAC_TXW_TYPE_SHIELDED; /* 11 */
    vctx.ruleset_version = 1u;
    vctx.statement_version = DNAC_SHIELDED_STATEMENT_VERSION;
    for (unsigned i = 0; i < 64; i++) vctx.ruleset_hash[i] = (uint8_t)(0x5A + i);
    /* S9 CORRECTION PASS: the transparent-leg commitment is now CALLER-supplied
     * (dnac_shielded_verify_ctx_t.tleg_commit). Every fixture in this file is a
     * type-11 statement, which carries no transparent leg, so the canonical
     * TAGGED-EMPTY digest is the right value — byte-identical to what the entry
     * used to compute for itself, hence every KAT below is unchanged. */
    if (dnac_tleg_commit_empty(vctx.tleg_commit) != 0) {
        fprintf(stderr, "tleg_commit_empty failed\n");
        return 1;
    }

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
    /* S8 Gate 2: conserving note set ⇒ both transparent legs 0; the fee is now
     * an independent public (stark_prover_agg.h:102-114) carrying the value the
     * retired FEE-role note used to hold. */
    inst.boundary_in = SV_BOUNDARY_IN;
    inst.boundary_out = SV_BOUNDARY_OUT;
    inst.fee = 30;
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
            printf("  pass-1 publics len %zu != %d\n", np,
                   (int)CONF_AGGZK_NUM_PUBLICS);
            free(draws);
            return 1;
        }
        sf_from_publics(pub, &sf);
        if (!bind_sf(&sf, &vctx)) {
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
            sf2.fee != sf.fee || sf2.boundary_in != sf.boundary_in ||
            sf2.boundary_out != sf.boundary_out) {
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
            dnac_shielded_verify_statement(&sf, &vctx, committed_fee);
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
        if (!bind_sf(&t, &vctx)) { g_fails++; }
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        /* v4: no wire opening point — the recomputed (tampered) publics feed
         * the priming, so ζ/α diverge and the FRI verify rejects (FS-divergence,
         * the v3 OPENING_POINT class closes structurally). */
        check("T-R1  tampered nf public -> FRI (FS-divergence)",
              st == DNAC_SHIELDED_VERIFY_ERR_FRI, (int)st);
    }

    /* ── T-R2: tampered proof byte (fail-close, any rejecting code). ── */
    {
        uint8_t *b2 = (uint8_t *)malloc(len);
        memcpy(b2, buf, len);
        b2[len - 1] ^= 0x01;
        dnac_tx_shielded_fields_t t = sf;
        t.fri_proof = b2;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
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
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R3  wrong tx_binding -> TXBIND",
              st == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)st);
    }

    /* ── T-R4: count forgery — wire num_input=2 vs proven 1 (G-SEC-2: the
     * count SCALAR is bound, not just slot values). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_input = 2; /* slot 1 stays zero — canonical encoding holds */
        if (!bind_sf(&t, &vctx)) { g_fails++; }
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R4  count forgery num_input -> FRI (FS-divergence)",
              st == DNAC_SHIELDED_VERIFY_ERR_FRI, (int)st);
    }

    /* ── T-R5: count forgery — wire num_output=0 vs proven 1. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_output = 0;
        memset(t.output_commit, 0, sizeof t.output_commit);
        if (!bind_sf(&t, &vctx)) { g_fails++; }
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R5  count forgery num_output -> FRI (FS-divergence)",
              st == DNAC_SHIELDED_VERIFY_ERR_FRI, (int)st);
    }

    /* ── T-R6: wrong params — the TEST 2-query proof at the pinned height;
     * everything matches except the param set (G-SEC-4 pin bites). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.fri_proof = tp_buf;
        t.fri_proof_len = (uint32_t)tp_len;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R6  TEST-params proof -> FRI (param pin)",
              st == DNAC_SHIELDED_VERIFY_ERR_FRI, (int)st);
    }

    /* ── T-R7 / T-R8 RETIRED (d4.c-3, DZKF v4 structural closure). The v3 wire
     * carried per-matrix opening COORDINATES and committed domain LOG_SIZEs that
     * an attacker could patch; the v4 batched wire carries NEITHER — the verifier
     * SAMPLES ζ itself (so a wire-chosen opening point cannot exist: the v3
     * OPENING_POINT / T-R8 class is closed by construction) and PINS degree_bits
     * = 11 (so there is no wire height field to move 11->10: a proof made at any
     * other height fails the FRI verify, exercised transitively — the v3 HEIGHT /
     * T-R7 class collapses into the FS/FRI path). Both attack surfaces are gone,
     * not merely untested; ERR_OPENING_POINT and ERR_HEIGHT are now unreachable
     * by construction. ── */

    /* ── T-R9: the CRIT-1 isolating vector — an honest-FS proof over FORGED
     * publics (boundary_out+1, binding re-mapped) whose quotient came from the
     * TRUE trace publics. FRI ACCEPTS it; only the N-chunk constraint check can
     * reject. This KAT is what proves the verify chain actually RUNS the
     * constraint check (no tamper KAT above can isolate its absence).
     *
     * S8 Gate-2 RE-BASE (was fee+1): the fee is NO LONGER an AIR-constrained
     * public — IS_FEE is pinned zero, so the fee left the balance accumulator
     * and the terminal entirely and is bound ONLY at the non-AIR layers
     * (header/section mirror equality, sighash_v5 -> tx_binding, and the
     * verifier's own recomputation). Forging it therefore no longer reaches a
     * constraint violation and this KAT silently stopped testing what it
     * claims. `boundary_out` IS constrained — the terminal is
     * BAL == boundary_out - boundary_in — so +1 breaks exactly that identity
     * while every earlier gate still passes: the value stays < 2^63 (range OK),
     * num_input is non-zero here (the anchor rule is not engaged), the fee is
     * untouched so the D7.2 mirror still holds, and the binding is re-mapped so
     * ERR_TXBIND cannot fire first. Fee tampering is covered at its correct
     * owning layer by T-R10 (fee != committed_fee -> ERR_FEE); the sighash_v5 /
     * tx_binding leg is covered by T-R1/T-R4/T-R5. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.boundary_out = sf.boundary_out + 1; /* fixture legs are 0 => 1 < 2^63 */
        if (!bind_sf(&t, &vctx)) { g_fails++; }
        uint64_t forged[CONF_AGGZK_NUM_PUBLICS];
        for (size_t i = 0; i < (size_t)CONF_AGGZK_NUM_PUBLICS; i++)
            forged[i] = gold_fp_to_u64(prod_publics[i]);
        forged[CONF_AGGZK_PUB_BOUT] = t.boundary_out;
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
                &t, &vctx, /*committed_fee=*/t.fee);
            /* The assertion names the EXACT stage: not "non-zero", and not any
             * earlier class — ERR_BOUNDARY/TXBIND/FEE here would mean the
             * forgery was caught before the constraint check and the CRIT-1
             * property went untested. */
            check("T-R9  FRI-passes-constraint-fails -> CONSTRAINTS",
                  st == DNAC_SHIELDED_VERIFY_ERR_CONSTRAINTS, (int)st);
            free(fb);
        }
        if (fp) dnac_agg_prover_proof_free(fp);
    }

    /* ── T-R10: fee != committed_fee (D7.2 single fee authority). ── */
    {
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&sf, &vctx, committed_fee + 1);
        check("T-R10 fee != committed_fee -> FEE",
              st == DNAC_SHIELDED_VERIFY_ERR_FEE, (int)st);
    }

    /* ── T-R11: oversize blob length (fail-close, no read past cap). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.fri_proof_len = (uint32_t)DNAC_FRI_WIRE_MAX_TOTAL_LEN + 1u;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R11 oversize blob -> OVERSIZE",
              st == DNAC_SHIELDED_VERIFY_ERR_OVERSIZE, (int)st);
    }

    /* ── T-R12: non-canonical lane (>= p). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.nf_set[0][0] = GOLDILOCKS_P;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R12 lane >= p -> NONCANONICAL",
              st == DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL, (int)st);
    }

    /* ── T-R13: non-zero unused nf slot (DET-S5-3 canonical encoding). ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.nf_set[3][0] = 1;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-R13 unused nf slot != 0 -> SLOT_NONZERO",
              st == DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO, (int)st);
    }

    /* ── T-R14: counts out of range.
     * ⚠ S8 Gate 2 CHANGED THIS CASE. `num_input == 0` used to be asserted as
     * ERR_COUNT (3); it is now the LEGAL SHIELD shape (shielded_verify.c:162-169),
     * so that leg was REMOVED from here and its real rules are asserted in
     * T-S1/T-S2. What stays is the upper bound on BOTH counts —
     * DNAC_SHIELDED_MAX_INPUTS + 1 == 5 is exactly the matrix's "num_input == 5"
     * item. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_input = DNAC_SHIELDED_MAX_INPUTS + 1; /* 5 */
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        int ok = (st == DNAC_SHIELDED_VERIFY_ERR_COUNT);
        t = sf;
        t.num_output = DNAC_SHIELDED_MAX_OUTPUTS + 1; /* 5 */
        st = dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        ok = ok && (st == DNAC_SHIELDED_VERIFY_ERR_COUNT);
        check("T-R14 num_input/num_output == MAX+1 -> COUNT", ok, (int)st);
    }

    /* ══════════════════════════════════════════════════════════════════════
     * LEDGER-V2 S8 Gate 2 adversarial matrix. Every case asserts the EXACT
     * status so a future regression cannot pass for the wrong reason.
     * ════════════════════════════════════════════════════════════════════ */

    /* ── T-S1 (matrix 4): num_input == 0 with a NON-ZERO nullifier slot. A
     * zero-input statement spends nothing, so EVERY nf slot is "unused" and
     * must be zero (DET-S5-3 canonical encoding, shielded_verify.c:170-176).
     * The honest sf carries a real nf in slot 0, so simply declaring
     * num_input = 0 over it is exactly the attack. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_input = 0;
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-S1  num_input==0 + non-zero nf slot -> SLOT_NONZERO",
              st == DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO, (int)st);
    }

    /* ── T-S2 (matrix 5): num_input == 0 with a NON-ZERO anchor. With the nf
     * slots cleared the SLOT_NONZERO gate no longer fires, so the zero-input
     * anchor rule is the one under test (shielded_verify.c:194-197): a
     * statement that proves NO membership must publish the all-zero anchor. ── */
    {
        dnac_tx_shielded_fields_t t = sf;
        t.num_input = 0;
        memset(t.nf_set, 0, sizeof t.nf_set);
        dnac_shielded_verify_status_t st =
            dnac_shielded_verify_statement(&t, &vctx, committed_fee);
        check("T-S2  num_input==0 + non-zero anchor -> ANCHOR",
              st == DNAC_SHIELDED_VERIFY_ERR_ANCHOR, (int)st);
    }

    /* ── T-S3 (matrix 7): the frozen B2 range on both transparent legs.
     *   2^63 - 1 is INSIDE the range: the gate must NOT fire, so the statement
     *   travels on into the proof check. Re-bound (so TXBIND passes), the
     *   changed public diverges Fiat-Shamir and the FRI verify rejects — the
     *   same mechanism T-R1/T-R4/T-R5 assert. Asserting ERR_FRI (not merely
     *   "non-OK") is what proves the value reached the publics.
     *   2^63 exactly is OUTSIDE: ERR_BOUNDARY, on either leg. ── */
    {
        const uint64_t lim = (uint64_t)1 << 63;
        int ok = 1;
        {   /* in-range, both legs */
            dnac_tx_shielded_fields_t t = sf;
            t.boundary_in = lim - 1;
            if (!bind_sf(&t, &vctx)) { g_fails++; }
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, committed_fee) ==
                           DNAC_SHIELDED_VERIFY_ERR_FRI;
            t = sf;
            t.boundary_out = lim - 1;
            if (!bind_sf(&t, &vctx)) { g_fails++; }
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, committed_fee) ==
                           DNAC_SHIELDED_VERIFY_ERR_FRI;
        }
        {   /* at the limit — the gate fires BEFORE any binding work, so these
             * keep the honest (now stale) tx_binding on purpose. */
            dnac_tx_shielded_fields_t t = sf;
            t.boundary_in = lim;
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, committed_fee) ==
                           DNAC_SHIELDED_VERIFY_ERR_BOUNDARY;
            t = sf;
            t.boundary_out = lim;
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, committed_fee) ==
                           DNAC_SHIELDED_VERIFY_ERR_BOUNDARY;
        }
        check("T-S3  boundary 2^63-1 in range / 2^63 -> BOUNDARY", ok, -1);
    }

    /* ── T-S4 (matrix 8): Goldilocks-adjacent boundary values. p-1, p and
     * 2^64-1 are all >= 2^63, so all six placements are ERR_BOUNDARY — the
     * range gate subsumes the canonicality question for these two fields
     * (shielded_verify.c:75-79). ── */
    {
        const uint64_t adj[3] = {GOLDILOCKS_P - 1, GOLDILOCKS_P, UINT64_MAX};
        int ok = 1;
        for (unsigned i = 0; i < 3; i++) {
            dnac_tx_shielded_fields_t t = sf;
            t.boundary_in = adj[i];
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, committed_fee) ==
                           DNAC_SHIELDED_VERIFY_ERR_BOUNDARY;
            t = sf;
            t.boundary_out = adj[i];
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, committed_fee) ==
                           DNAC_SHIELDED_VERIFY_ERR_BOUNDARY;
        }
        check("T-S4  boundary p-1 / p / 2^64-1 -> BOUNDARY (6/6)", ok, -1);
    }

    /* ── T-S5 (matrix 10): the statement-version pin. The 45-public layout, the
     * D=24 depth and the sighash_v5 preimage are frozen TOGETHER under version
     * 1, so a foreign version must be rejected outright rather than measured
     * against this shape — and a MISSING context is the same failure class,
     * since without it there is no declared version at all
     * (shielded_verify.c:151-160). Note the honest proof is otherwise intact:
     * only the declared version moves. ── */
    {
        int ok = 1;
        dnac_shielded_verify_ctx_t bad = vctx;
        bad.statement_version = DNAC_SHIELDED_STATEMENT_VERSION + 1u;
        ok = ok && dnac_shielded_verify_statement(&sf, &bad, committed_fee) ==
                       DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION;
        bad.statement_version = 0u; /* 0 == "no ZK statement" */
        ok = ok && dnac_shielded_verify_statement(&sf, &bad, committed_fee) ==
                       DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION;
        ok = ok && dnac_shielded_verify_statement(&sf, NULL, committed_fee) ==
                       DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION;
        check("T-S5  statement_version != 1 / NULL vctx -> VERSION", ok, -1);
    }

    free(tp_buf);
    free(buf);

    printf("------------------------------------------------------------\n");
    if (g_fails == 0) {
        printf("C2.1 SHIELDED VERIFY GATE: GREEN — accept + 12 fail-close\n");
        printf("  rejects incl. the CRIT-1 constraint-check isolator (T-R9);\n");
        printf("  T-R7/R8 retired — v4 has no wire height/opening-point field;\n");
        printf("  + the S8 Gate 2 matrix (T-S1..T-S5: zero-input slot/anchor,\n");
        printf("  boundary range, Goldilocks-adjacent legs, version pin).\n");
        printf("============================================================\n");
        return 0;
    }
    printf("C2.1 SHIELDED VERIFY GATE: RED (%d failures)\n", g_fails);
    return 1;
}
