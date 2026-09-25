/**
 * @file test_native_verify_v3_proofs.c
 * @brief Ledger V2 S9 CORRECTION PASS — the REAL-PROOF gate for the native
 *        stateless V3 verifier: types 11, 12 and 13 must reach internal VALID.
 *
 * This is the test the correction pass exists for. Before it, types 12/13 could
 * not be proof-verified at all: dnac_shielded_verify_statement derived the
 * transparent-leg commitment itself (always the TAGGED-EMPTY form), so a
 * populated leg mis-bound by construction and the native entry returned a
 * deferral status. The commitment is now caller-supplied
 * (dnac_shielded_verify_ctx_t.tleg_commit), so all three types run the SAME
 * aggregate verifier and an honest transaction of ANY of them reaches
 * DNAC_SHIELDED_VERIFY_OK.
 *
 * ⚠ ── WHERE THE ACCEPTS ARE PROVEN, AND WHY NOT END-TO-END ────────────────
 * A production aggregate proof at the pinned consensus parameters measures
 * ~2.36 MB (2,474,998 B — printed by section C below). A Wire V3 body is
 * capped at DNAC_TXW3_MAX_BODY_LEN = 65,426 B (tx_wire.h §2, mirroring
 * NODUS_T3_MAX_TX_SIZE = 65,536). A type-11 body would therefore need
 * 359 + 2,474,998 = 2,475,357 B — 37.8x the cap. **No production shielded
 * transaction can be framed as a V3 transaction today.**
 *
 * That is a PRE-EXISTING carrier constraint, not something this pass
 * introduced or may fix: raising the cap is a consensus-relevant wire change
 * owned by the activation season. So the accepts are proven where they can be
 * proven honestly — at dnac_shielded_verify_statement, the entry the
 * correction actually changed, driven with REAL runtime proofs and the REAL
 * per-type transparent-leg commitment (section A). That is precisely the call
 * that was impossible before: a populated leg mis-bound by construction.
 * Section C pins the carrier gap itself with an assertion, so the number is a
 * test result rather than prose. The native entry's full stateless path
 * (~80 negatives + the timestamp rule) is covered by test_native_verify_v3.
 *
 * ── Why this binary is zk-ONLY ────────────────────────────────────────────
 * Every case here PROVES at runtime (dnac_agg_prover_prove_production). The
 * prover is not part of libnodus (nodus/CMakeLists.txt compiles the verify side
 * only), so a proof-generating gate cannot live in the dual-build
 * test_native_verify_v3. That binary keeps the stateless matrix (stub blobs,
 * ~80 negatives) and runs in BOTH builds; this one adds the accepts.
 * NO tracked vector is read or written — every proof is generated in-process.
 *
 * ── Honest scope note ─────────────────────────────────────────────────────
 * The type-12 spend-authority callback here is a STUB that accepts. That is
 * deliberate and is not what this file claims to test: the signature mechanism
 * (verified over the 64-byte sighash_v5, rejection propagates, a NULL verifier
 * is ERR_SIG never a skip, binding is checked BEFORE signatures) is pinned by
 * the J-family in test_native_verify_v3.c. Here the callback must simply not
 * stand between the transaction and the PROOF step.
 *
 * ── The four accepting shapes (conservation: Σin + b_in = Σout + b_out) ────
 *   T11   TRANSFER  1 in(100) → 1 out(70),  b_in 0,   b_out 30 == fee
 *   T12   SHIELD    0 in      → 1 out(100), b_in 100, b_out 0   (fee transparent)
 *   T13a  UNSHIELD  1 in(100) → 0 out,      b_in 0,   b_out 100 == 70 + fee
 *   T13b  UNSHIELD  1 in(100) → 1 out(40),  b_in 0,   b_out 60  == 30 + fee
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_action_agg_air.h"
#include "conf_action_agg_fold.h"
#include "conf_txbind.h"
#include "dnac/tx_wire.h"
#include "field_goldilocks.h"
#include "native_verify_v3.h"
#include "shielded_fri_params.h"
#include "shielded_verify.h"
#include "stark_prover_agg.h"

#define NV3P_FEE          30u
#define NV3P_EXPIRY       123456u
#define NV3P_DOMAIN       DNA_DOMAIN_CORE
#define NV3P_POOL         DNAC_SHIELDED_POOL_V1
#define NV3P_RULESET_VER  1u
#define NV3P_SIB_LEN      ((size_t)4 * CONF_AGG_TREE_DEPTH * 4)

static int g_fails = 0;

static void check(const char *name, int ok, int got) {
    printf("  %-56s %s", name, ok ? "PASS" : "FAIL");
    if (!ok) { printf(" (got %d)", got); g_fails++; }
    printf("\n");
}

/* The type-12 authority callback — see the honest scope note above. Its
 * signature is the exact shape of qgp_dsa87_verify so production wiring needs
 * no adapter. */
static int stub_sig_ok(const uint8_t *sig, size_t sig_len, const uint8_t *msg,
                       size_t msg_len, const uint8_t *pk) {
    (void)sig; (void)sig_len; (void)msg; (void)msg_len; (void)pk;
    return 0;
}

/* One accepting scenario, fully described. */
typedef struct {
    const char *name;
    uint8_t     tx_type;
    unsigned    num_notes;
    uint64_t    value[4];
    uint8_t     roles[4];
    uint64_t    boundary_in;
    uint64_t    boundary_out;
    uint8_t     num_tin;        /* transparent leg shape (12/13) */
    uint8_t     num_tout;
    uint8_t     num_signers;
    uint64_t    tout_amount;    /* type 13: the recipient amount */
} nv3p_case_t;

/* Fill the wire statement from the 45 proof publics — the honest
 * wire == publics identity. */
static void st_from_publics(const gold_fp_t *pub, dnac_txw3_shielded_t *st,
                            uint64_t fee, uint64_t b_in, uint64_t b_out) {
    memset(st, 0, sizeof(*st));
    st->sect_version = (uint8_t)DNAC_TXW3_SECT_VERSION;
    for (unsigned j = 0; j < 4; j++)
        st->anchor[j] = gold_fp_to_u64(pub[CONF_AGGZK_PUB_ANCHOR + j]);
    st->num_input = (uint8_t)gold_fp_to_u64(pub[CONF_AGGZK_PUB_NUMIN]);
    for (unsigned s = 0; s < 4; s++)
        for (unsigned j = 0; j < 4; j++)
            st->nf_set[s][j] =
                gold_fp_to_u64(pub[CONF_AGGZK_PUB_NFSLOT + s * 4 + j]);
    st->num_output = (uint8_t)gold_fp_to_u64(pub[CONF_AGGZK_PUB_NUMOUT]);
    for (unsigned s = 0; s < 4; s++)
        for (unsigned j = 0; j < 4; j++)
            st->output_commit[s][j] =
                gold_fp_to_u64(pub[CONF_AGGZK_PUB_OCOMMIT + s * 4 + j]);
    st->fee           = fee;
    st->boundary_in   = b_in;
    st->boundary_out  = b_out;
    st->expiry_height = NV3P_EXPIRY;
}

static void build_leg(dnac_txw3_tleg_t *leg, const nv3p_case_t *c) {
    memset(leg, 0, sizeof(*leg));
    leg->tleg_version = (uint8_t)DNAC_TXW3_TLEG_VERSION;
    leg->num_tin      = c->num_tin;
    for (unsigned i = 0; i < c->num_tin; i++)
        memset(leg->tin_nullifier[i], (int)(0x40 + i),
               DNAC_TXW_NULLIFIER_LEN);   /* strictly ascending by construction */
    leg->num_tout = c->num_tout;
    for (unsigned i = 0; i < c->num_tout; i++) {
        memset(leg->tout[i].fp, (int)(0x70 + i), DNAC_TXW_FP_LEN);
        leg->tout[i].amount = c->tout_amount;
        memset(leg->tout[i].nullifier_seed, (int)(0x90 + i), DNAC_TXW_SEED_LEN);
    }
    leg->num_signers = c->num_signers;
    for (unsigned i = 0; i < c->num_signers; i++) {
        memset(leg->signer[i].pubkey, (int)(0xB0 + i), DNAC_TXW_PK_LEN);
        memset(leg->signer[i].signature, (int)(0xC0 + i), DNAC_TXW_SIG_LEN);
    }
}

static void build_ctx(dnac_v3_native_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    for (unsigned i = 0; i < 32; i++) ctx->chain_id[i] = (uint8_t)(0xC0 + i);
    ctx->domain_id         = NV3P_DOMAIN;
    ctx->pool_id           = NV3P_POOL;
    ctx->ruleset_version   = NV3P_RULESET_VER;
    ctx->statement_version = DNAC_SHIELDED_STATEMENT_VERSION;
    for (unsigned i = 0; i < 64; i++) ctx->ruleset_hash[i] = (uint8_t)(0x5A + i);
    ctx->sig_verify = stub_sig_ok;
}

/* Encode header + [leg] + section + blob into one canonical V3 transaction. */
static int assemble(const dnac_v3_native_ctx_t *ctx, uint8_t tx_type,
                    const dnac_txw3_shielded_t *st, const dnac_txw3_tleg_t *leg,
                    int with_leg, const uint8_t *fri, uint32_t fri_len,
                    uint8_t **tx_out, size_t *tx_len_out) {
    static uint8_t body[DNAC_TXW3_MAX_BODY_LEN];
    size_t off = 0;
    if (with_leg) {
        size_t w = 0;
        if (dnac_txw3_tleg_encode(leg, body, sizeof body, &w) != 0) return -1;
        off = w;
    }
    size_t sw = 0;
    if (dnac_txw3_shielded_encode(st, fri, fri_len, body + off,
                                  sizeof body - off, &sw) != 0)
        return -1;
    off += sw;

    dnac_txw3_header_t hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.wire_version      = (uint8_t)DNAC_TXW3_WIRE_VERSION;
    hdr.tx_type           = tx_type;
    hdr.domain_id         = ctx->domain_id;
    hdr.pool_id           = ctx->pool_id;
    hdr.ruleset_version   = ctx->ruleset_version;
    hdr.statement_version = ctx->statement_version;
    hdr.expiry_height     = NV3P_EXPIRY;
    hdr.committed_fee     = NV3P_FEE;
    hdr.timestamp         = 0;          /* pinned for 11/12/13 (OBL-S9-TS-BIND) */

    size_t need = 0;
    if (dnac_txw3_encoded_size((uint32_t)off, &need) != 0) return -1;
    uint8_t *tx = (uint8_t *)malloc(need);
    if (!tx) return -1;
    size_t written = 0;
    if (dnac_txw3_encode(&hdr, body, (uint32_t)off, tx, need, &written) != 0) {
        free(tx);
        return -1;
    }
    *tx_out = tx;
    *tx_len_out = written;
    return 0;
}

/* Prove the case and assemble its transaction. Two passes, exactly as the
 * production gate does: pass 1 yields the publics (so the statement's
 * nullifiers/commitments/anchor are the PROVER's, not invented), the statement
 * then fixes sighash_v5 -> tx_binding, and pass 2 proves against that binding. */
static int build_case(const nv3p_case_t *c, const dnac_v3_native_ctx_t *ctx,
                      dnac_txw3_shielded_t *st_out, dnac_txw3_tleg_t *leg_out,
                      uint8_t tleg_out[DNAC_TXW_HASH_LEN],
                      uint8_t **fri_out, size_t *fri_len_out,
                      uint8_t **tx_out, size_t *tx_len_out) {
    static uint64_t addr[16], rcm[8], nk[16], ak[16], pos[4];
    static uint64_t sib[NV3P_SIB_LEN];
    memset(addr, 0, sizeof addr); memset(rcm, 0, sizeof rcm);
    memset(nk, 0, sizeof nk);     memset(ak, 0, sizeof ak);
    memset(pos, 0, sizeof pos);   memset(sib, 0, sizeof sib);
    for (unsigned b = 0; b < c->num_notes; b++) {
        for (unsigned j = 0; j < 4; j++) {
            addr[b * 4 + j] = 0xAA01 + b * 0x10 + j;
            nk[b * 4 + j]   = 0x22221111ULL + b * 0x1000 + j;
            ak[b * 4 + j]   = 0x11111111ULL + b * 0x1000 + j;
        }
        rcm[b * 2 + 0] = 0x11 + b * 0x10;
        rcm[b * 2 + 1] = 0x12 + b * 0x10;
        if (c->roles[b] == CONF_ACTION_ROLE_INPUT) {
            pos[b] = 5;
            for (unsigned L = 0; L < (unsigned)CONF_AGG_TREE_DEPTH; L++)
                for (unsigned j = 0; j < 4; j++)
                    sib[(size_t)b * CONF_AGG_TREE_DEPTH * 4 + L * 4 + j] =
                        (uint64_t)0x1000 * (L + 1) + 0x0001 + j;
        }
    }

    dnac_agg_prover_instance_t inst;
    memset(&inst, 0, sizeof inst);
    inst.value = c->value;   inst.addr = addr;  inst.rcm = rcm;
    inst.roles = c->roles;   inst.pos = pos;    inst.nk = nk;   inst.ak = ak;
    inst.num_notes = c->num_notes;
    inst.memb_siblings = sib;
    inst.boundary_in  = c->boundary_in;
    inst.boundary_out = c->boundary_out;
    inst.fee = NV3P_FEE;
    inst.log_height = (unsigned)DNAC_SHIELDED_BASE_LOG_HEIGHT;

    /* Pass 1 — publics only. */
    uint64_t zero_bind[4] = {0, 0, 0, 0};
    dnac_agg_prover_proof_t *p1 = NULL;
    {
        dnac_agg_prover_instance_t i1 = inst;
        i1.tx_binding = zero_bind;
        dnac_prover_status_t ps = dnac_agg_prover_prove_production(&i1, &p1);
        if (ps != DNAC_PROVER_OK) {
            fprintf(stderr, "    [build] pass-1 prove failed: status %d\n",
                    (int)ps);
            return -1;
        }
    }
    size_t np = 0;
    const gold_fp_t *pub = dnac_agg_prover_proof_publics(p1, &np);
    if (!pub || np != CONF_AGGZK_NUM_PUBLICS) {
        fprintf(stderr, "    [build] publics: ptr=%p np=%zu want=%d\n",
                (const void *)pub, np, (int)CONF_AGGZK_NUM_PUBLICS);
        dnac_agg_prover_proof_free(p1);
        return -1;
    }
    st_from_publics(pub, st_out, NV3P_FEE, c->boundary_in, c->boundary_out);
    dnac_agg_prover_proof_free(p1);

    /* The leg and its commitment — tagged-empty for 11, real for 12/13. */
    build_leg(leg_out, c);
    const int has_leg = (c->tx_type != DNAC_TX_SHIELDED);
    uint8_t tleg[DNAC_TXW_HASH_LEN], ctc[DNAC_TXW_HASH_LEN];
    if ((has_leg ? dnac_tleg_commit(leg_out, tleg)
                 : dnac_tleg_commit_empty(tleg)) != 0 ||
        dnac_ct_commit_empty(ctc) != 0) {
        fprintf(stderr, "    [build] leg/ct commit failed (has_leg=%d)\n",
                has_leg);
        return -1;
    }

    dna_exec_context_t ectx;
    if (dna_exec_context_init(&ectx, ctx->chain_id, ctx->domain_id,
                              ctx->pool_id, c->tx_type,
                              (uint8_t)DNAC_TXW3_WIRE_VERSION,
                              ctx->ruleset_version,
                              ctx->statement_version) != 0)
        return -1;
    uint8_t sighash[DNAC_TXW_HASH_LEN];
    uint64_t bind[4];
    if (dnac_sighash_v5(&ectx, (uint8_t)DNAC_TXW3_SECT_VERSION,
                        ctx->ruleset_hash, st_out, tleg, ctc, sighash) != 0) {
        fprintf(stderr, "    [build] sighash_v5 failed (nin=%u nout=%u "
                        "b_in=%llu b_out=%llu)\n",
                st_out->num_input, st_out->num_output,
                (unsigned long long)st_out->boundary_in,
                (unsigned long long)st_out->boundary_out);
        return -1;
    }
    if (!conf_txbind_map(sighash, bind)) {
        fprintf(stderr, "    [build] txbind_map failed\n");
        return -1;
    }
    for (unsigned j = 0; j < 4; j++) st_out->tx_binding[j] = bind[j];

    /* Pass 2 — prove against the real binding, then encode the blob. */
    uint8_t *buf = NULL;
    size_t len = 0;
    {
        dnac_agg_prover_instance_t i2 = inst;
        i2.tx_binding = bind;
        dnac_agg_prover_proof_t *p2 = NULL;
        if (dnac_agg_prover_prove_production(&i2, &p2) != DNAC_PROVER_OK)
            return -1;
        if (dnac_agg_prover_proof_wire_encode_testonly(p2, &buf, &len) !=
            DNAC_FRI_CODEC_OK) {
            dnac_agg_prover_proof_free(p2);
            return -1;
        }
        dnac_agg_prover_proof_free(p2);
    }
    st_out->fri_len = (uint32_t)len;
    *fri_out = buf;
    *fri_len_out = len;

    /* The V3 framing is ATTEMPTED, not required: a production proof exceeds the
     * body cap (see the header note + section C), so *tx_out stays NULL and the
     * accepts run at the statement entry. Reported, never silently ignored. */
    *tx_out = NULL;
    *tx_len_out = 0;
    (void)assemble(ctx, c->tx_type, st_out, leg_out, has_leg, buf,
                   (uint32_t)len, tx_out, tx_len_out);
    /* Hand the caller the commitment it must give the statement entry. */
    memcpy(tleg_out, tleg, DNAC_TXW_HASH_LEN);
    return 0;
}


/* Build the wire shielded-fields view the statement entry consumes. */
static void sf_from_st(const dnac_txw3_shielded_t *st, const uint8_t *fri,
                       size_t fri_len, dnac_tx_shielded_fields_t *sf) {
    memset(sf, 0, sizeof(*sf));
    for (unsigned j = 0; j < 4; j++) sf->anchor[j] = st->anchor[j];
    sf->num_input = st->num_input;
    for (unsigned s = 0; s < 4; s++)
        for (unsigned j = 0; j < 4; j++) sf->nf_set[s][j] = st->nf_set[s][j];
    sf->num_output = st->num_output;
    for (unsigned s = 0; s < 4; s++)
        for (unsigned j = 0; j < 4; j++)
            sf->output_commit[s][j] = st->output_commit[s][j];
    sf->fee = st->fee;
    for (unsigned j = 0; j < 4; j++) sf->tx_binding[j] = st->tx_binding[j];
    sf->boundary_in   = st->boundary_in;
    sf->boundary_out  = st->boundary_out;
    sf->expiry_height = st->expiry_height;
    sf->fri_proof     = (uint8_t *)(uintptr_t)fri;
    sf->fri_proof_len = (uint32_t)fri_len;
}

static void vctx_from_native(const dnac_v3_native_ctx_t *n, uint8_t tx_type,
                             const uint8_t tleg[DNAC_TXW_HASH_LEN],
                             dnac_shielded_verify_ctx_t *v) {
    memset(v, 0, sizeof(*v));
    memcpy(v->chain_id, n->chain_id, sizeof v->chain_id);
    v->domain_id         = n->domain_id;
    v->pool_id           = n->pool_id;
    v->tx_type           = tx_type;
    v->ruleset_version   = n->ruleset_version;
    v->statement_version = n->statement_version;
    memcpy(v->ruleset_hash, n->ruleset_hash, sizeof v->ruleset_hash);
    memcpy(v->tleg_commit, tleg, DNAC_TXW_HASH_LEN);
}

int main(void) {
    printf("============================================================\n");
    printf("S9 CORRECTION — REAL-PROOF accepts for types 11 / 12 / 13\n");
    printf("  the transparent-leg commitment is CALLER-SUPPLIED, so a\n");
    printf("  populated leg now binds instead of mis-binding\n");
    printf("============================================================\n");

    const nv3p_case_t cases[4] = {
        { "A-11  TRANSFER 1-in/1-out", DNAC_TX_SHIELDED, 2,
          {100, 70, 0, 0},
          {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT, 0, 0},
          0, NV3P_FEE, 0, 0, 0, 0 },
        { "A-12  SHIELD 0-in/1-out", DNAC_TX_SHIELD, 1,
          {100, 0, 0, 0}, {CONF_ACTION_ROLE_OUTPUT, 0, 0, 0},
          100, 0, 1, 0, 1, 0 },
        { "A-13a UNSHIELD 1-in/0-change", DNAC_TX_UNSHIELD, 1,
          {100, 0, 0, 0}, {CONF_ACTION_ROLE_INPUT, 0, 0, 0},
          0, 100, 0, 1, 0, 70 },
        { "A-13b UNSHIELD 1-in/1-change", DNAC_TX_UNSHIELD, 2,
          {100, 40, 0, 0},
          {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT, 0, 0},
          0, 60, 0, 1, 0, 30 },
    };

    dnac_v3_native_ctx_t nctx;
    build_ctx(&nctx);

    /* A-12's material is kept for the substitution negatives. */
    dnac_txw3_shielded_t keep_st;
    dnac_txw3_tleg_t     keep_leg;
    uint8_t              keep_tleg[DNAC_TXW_HASH_LEN];
    uint8_t             *keep_fri = NULL;
    size_t               keep_fri_len = 0;
    int                  have_keep = 0;

    printf("\n-- A. honest transactions reach internal VALID (real proofs) --\n");
    for (unsigned i = 0; i < 4; i++) {
        dnac_txw3_shielded_t st;
        dnac_txw3_tleg_t     leg;
        uint8_t              tleg[DNAC_TXW_HASH_LEN];
        uint8_t             *fri = NULL, *tx = NULL;
        size_t               fri_len = 0, tx_len = 0;
        char                 label[96];

        if (build_case(&cases[i], &nctx, &st, &leg, tleg, &fri, &fri_len,
                       &tx, &tx_len) != 0) {
            snprintf(label, sizeof label, "%s -> internal VALID", cases[i].name);
            check(label, 0, -1);
            free(fri); free(tx);
            continue;
        }

        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        sf_from_st(&st, fri, fri_len, &sf);
        vctx_from_native(&nctx, cases[i].tx_type, tleg, &vctx);

        dnac_shielded_verify_status_t s =
            dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
        snprintf(label, sizeof label, "%s -> internal VALID", cases[i].name);
        check(label, s == DNAC_SHIELDED_VERIFY_OK, (int)s);

        if (cases[i].tx_type == DNAC_TX_SHIELD && !have_keep) {
            keep_st = st; keep_leg = leg;
            memcpy(keep_tleg, tleg, sizeof keep_tleg);
            keep_fri = fri; keep_fri_len = fri_len;
            have_keep = 1;
            free(tx);
            continue;
        }
        free(fri); free(tx);
    }

    if (!have_keep) {
        printf("  SHIELD fixture unavailable — negatives skipped\n");
        g_fails++;
        return 1;
    }

    printf("\n-- B. the accepts are not vacuous --\n");
    {
        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        uint8_t *bad = (uint8_t *)malloc(keep_fri_len);
        memcpy(bad, keep_fri, keep_fri_len);
        bad[keep_fri_len - 1] ^= 0x01;
        sf_from_st(&keep_st, bad, keep_fri_len, &sf);
        vctx_from_native(&nctx, DNAC_TX_SHIELD, keep_tleg, &vctx);
        dnac_shielded_verify_status_t s =
            dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
        check("B-1   proof-byte tamper rejects", s != DNAC_SHIELDED_VERIFY_OK,
              (int)s);
        free(bad);
    }
    {
        /* Transparent-leg substitution under an UNCHANGED proof: the leg digest
         * moves, so sighash_v5 moves, so the wire tx_binding no longer matches.
         * THIS is the check the old deferral could not perform at all. */
        dnac_txw3_tleg_t sub = keep_leg;
        sub.tin_nullifier[0][0] ^= 0xFF;
        uint8_t sub_tleg[DNAC_TXW_HASH_LEN];
        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        if (dnac_tleg_commit(&sub, sub_tleg) != 0) {
            check("B-2   transparent-leg substitution -> ERR_TXBIND", 0, -1);
        } else {
            sf_from_st(&keep_st, keep_fri, keep_fri_len, &sf);
            vctx_from_native(&nctx, DNAC_TX_SHIELD, sub_tleg, &vctx);
            dnac_shielded_verify_status_t s =
                dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
            check("B-2   transparent-leg substitution -> ERR_TXBIND",
                  s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
        }
    }
    {
        /* Boundary substitution: b_in moved on the wire, proof untouched. */
        dnac_txw3_shielded_t sub = keep_st;
        sub.boundary_in += 1;
        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        sf_from_st(&sub, keep_fri, keep_fri_len, &sf);
        vctx_from_native(&nctx, DNAC_TX_SHIELD, keep_tleg, &vctx);
        dnac_shielded_verify_status_t s =
            dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
        check("B-3   boundary substitution rejects", s != DNAC_SHIELDED_VERIFY_OK,
              (int)s);
    }
    {
        /* A type-11 context accepts ONLY the tagged-empty leg: hand the SHIELD
         * statement the EMPTY commitment and it must fail to bind. This is the
         * mirror image of B-2 and pins that the value is load-bearing in both
         * directions. */
        uint8_t empty_tleg[DNAC_TXW_HASH_LEN];
        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        if (dnac_tleg_commit_empty(empty_tleg) != 0) {
            check("B-4   tagged-empty leg on a populated statement -> TXBIND",
                  0, -1);
        } else {
            sf_from_st(&keep_st, keep_fri, keep_fri_len, &sf);
            vctx_from_native(&nctx, DNAC_TX_SHIELD, empty_tleg, &vctx);
            dnac_shielded_verify_status_t s =
                dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
            check("B-4   tagged-empty leg on a populated statement -> TXBIND",
                  s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
        }
    }
    {
        /* A zeroed tleg_commit — the "caller forgot" shape — must fail closed,
         * never default to empty. */
        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        uint8_t zero_tleg[DNAC_TXW_HASH_LEN];
        memset(zero_tleg, 0, sizeof zero_tleg);
        sf_from_st(&keep_st, keep_fri, keep_fri_len, &sf);
        vctx_from_native(&nctx, DNAC_TX_SHIELD, zero_tleg, &vctx);
        dnac_shielded_verify_status_t s =
            dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
        check("B-5   all-zero tleg_commit fails closed (no default)",
              s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
    }
    {
        /* The untouched fixture still verifies — proves B-1..B-5 moved
         * something real and left nothing damaged. */
        dnac_tx_shielded_fields_t  sf;
        dnac_shielded_verify_ctx_t vctx;
        sf_from_st(&keep_st, keep_fri, keep_fri_len, &sf);
        vctx_from_native(&nctx, DNAC_TX_SHIELD, keep_tleg, &vctx);
        dnac_shielded_verify_status_t s =
            dnac_shielded_verify_statement(&sf, &vctx, NV3P_FEE);
        check("B-6   untouched fixture still VALID", s == DNAC_SHIELDED_VERIFY_OK,
              (int)s);
    }

    printf("\n-- C. the V3 carrier cannot frame a production proof --\n");
    {
        /* Measured, not asserted from a document. A type-11 body would be
         * 359 + fri_len; the cap is DNAC_TXW3_MAX_BODY_LEN. */
        const size_t need_body = (size_t)DNAC_TXW3_SHIELDED_FIXED + keep_fri_len;
        size_t sz = 0;
        const int over = (need_body > (size_t)DNAC_TXW3_MAX_BODY_LEN);
        printf("  production proof        : %zu B\n", keep_fri_len);
        printf("  body needed (section+proof): %zu B\n", need_body);
        printf("  DNAC_TXW3_MAX_BODY_LEN  : %u B\n",
               (unsigned)DNAC_TXW3_MAX_BODY_LEN);
        printf("  overflow factor         : %.1fx\n",
               (double)need_body / (double)DNAC_TXW3_MAX_BODY_LEN);
        check("C-1   a production proof EXCEEDS the V3 body cap", over,
              (int)over);
        check("C-2   dnac_txw3_encoded_size refuses that body",
              dnac_txw3_encoded_size((uint32_t)need_body, &sz) != 0, 0);
    }

    free(keep_fri);

    printf("------------------------------------------------------------\n");
    if (g_fails == 0)
        printf("S9 REAL-PROOF GATE: GREEN — 11/12/13 all reach internal VALID\n"
               "  (at the statement entry; the V3 carrier cap is pinned in C)\n");
    else
        printf("S9 REAL-PROOF GATE: RED — %d failure(s)\n", g_fails);
    printf("============================================================\n");
    return g_fails ? 1 : 0;
}
