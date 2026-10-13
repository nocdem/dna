/**
 * @file nodus/tests/test_hf6_payer.c
 * @brief HF-6 — the payer binding of the CORE SYSFUND funding leg under
 *        generation 4 (CORE v9): a kind-3 payer must be the vault the
 *        SYSTEM leg's signed owner field names.
 *
 * Governing record: docs/plans/2026-10-03-hf5-validator-owner-stake-
 * design.md §2 "ÖDEYİCİ BAĞLAMA — han kararı 2026-10-13" (red-team round 3,
 * operator "Yap"): "SYSFUND bacağı kind-3 ise msig_addr == SYSTEM bacağının
 * imzalı sahibi (STAKE / STORAGE_REGISTER / UNSTAKE / VALIDATOR_UPDATE /
 * STORAGE_EXIT: çağrının owner_fp'si; DELEGATE / UNDELEGATE: delegator_fp)
 * — yoksa -1 … Kind-1 fonlama … ve kind-1 üçüncü-taraf fonlama değişmez;
 * çok imzalı ÜÇÜNCÜ-taraf fonlama … kapanır. CORE ruleset_version 8 → 9".
 * The rule under test is nodus_witness_rt_native.c rtn_sysfund_payer_bound,
 * called from rtn_sysfund_exec under rtn_gen_roles(generation).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  Hook level, the generation-4 CORE runtime (nodus_rt_core_exec on
 *  NODUS_RT_GEN_STORAGE), a decoded 2-leg {SYSTEM op, CORE SYSFUND}
 *  envelope, a FABRICATED engine verdict for the CORE leg and fabricated
 *  funding reads (every input a native UTXO row owned by the payer, then
 *  the pool row). For EACH of the seven generation-4 owner operations —
 *  STAKE (7301 B, owner_fp at 0), DELEGATE / UNDELEGATE (136 B,
 *  delegator_fp at 0), UNSTAKE (128 B, owner_fp at 64), VALIDATOR_UPDATE
 *  (130 B, owner_fp at 64), STORAGE_REGISTER (7299 B, owner_fp at 0),
 *  STORAGE_EXIT (128 B, owner_fp at 64) — with the inputs balancing
 *  (Σin == fee + lock, no change):
 *   P1 kind-3 CORE leg, ONE satisfied descriptor whose address == the
 *      call's signed owner, coins owned by that address → APPLIES (0);
 *   P2 the same with the descriptor (and the coins) of ANOTHER vault →
 *      REFUSED (-1) — the multisig third-party payer is closed;
 *   P3 kind-1 CORE leg, one signer that is NOT the owner, coins owned by
 *      that signer → APPLIES (0) — kind-1 third-party funding unchanged.
 *  Then, on DELEGATE:
 *   P4 two satisfied descriptors [the owner, another vault], one input
 *      owned by each (both used) → REFUSED (-1): every carried descriptor
 *      must be the owner, not only msig_addr[0];
 *   P5 the same with the order of the vaults' bytes swapped so the
 *      OTHER vault is msig_addr[0] and the owner msig_addr[1] → REFUSED.
 *  Generation 3 (the EVM generation's CORE runtime, the legacy call
 *  layouts — no owner field):
 *   P6 a legacy DELEGATE (5192 B) and a legacy UNSTAKE (2592 B) funded by
 *      a kind-3 vault that is NOT SHA3-512(the call's pubkey) → APPLY (0):
 *      the rule does not exist below generation 4.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generations 3 and 4 are compiled only
 * with the EVM runtime; the CMake target is registered only then).
 * Environment: none. No database, no network, no files.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The verdicts are FABRICATED (no signature is verified) and so are the
 *    reads: it proves the CORE hook's decision over given engine facts,
 *    not the auth hook nor the engine's read execution.
 *  - The SYSTEM call bytes are framed but otherwise arbitrary (no consent,
 *    no row): only the CORE leg is executed. The SYSTEM leg's own owner
 *    rule (rtn_sys_owner_auth) is test_hf6_calls / test_hf6_msig_owner's.
 *  - A P1 success also needs the conservation and fee rules to pass; a
 *    regression there would show as a P1 / P3 / P6 failure, not as a
 *    wrong P2 pass.
 *  - Written and compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_types.h"
#include "client/nodus_v2_stake.h"

#include "dnac/dnac.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define FEE      ((uint64_t)DNAC_MIN_FEE_RAW)
#define H_EXEC   9u
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define AUTH1    (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define LOCK_AMT 5000000000ULL    /* bond / delegation amount             */

/* restated from nodus_witness_rt_native.c (static there) — the values
 * test_hf6_msig_owner.c restates */
#define UTXO_REC_LEN  284u
#define UTXO_AMT_OFF  128u
#define UTXO_UNL_OFF  276u

_Static_assert(FEE >= (uint64_t)NODUS_W_BASE_TX_FEE,
               "the fee must clear both shipped floors");

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

/* three distinct 64-byte identities, ascending by their first byte:
 * OWN (the call's signed owner), VB (another vault), PAY (a single key) */
static uint8_t g_own[64], g_vb[64], g_pay[64];

static const nodus_domain_runtime_t *g_c4, *g_c3;

/* ══ the envelope ═════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  sys[NODUS_V2_STAKE2_CALL_LEN];
    uint32_t sys_len;
    uint8_t  fund[2 + 2 * 64];
    uint32_t fund_len;
    uint8_t  auth[2][AUTH1];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} env_t;

/* the generation-4 SYSTEM call of `op` naming `owner` as its signed owner
 * (and moving LOCK_AMT where the op locks or releases) */
static uint32_t call_v2(uint8_t *d, uint32_t op, const uint8_t owner[64]) {
    switch (op) {
    case DNA_SYSRULE_STAKE:              /* owner ‖ pk ‖ sig ‖ exp ‖ comm ‖
                                          * bond                         */
        memset(d, 0x5A, NODUS_V2_STAKE2_CALL_LEN);
        memcpy(d, owner, 64);
        d[NODUS_V2_STAKE2_CALL_LEN - 10] = 0;        /* commission 0     */
        d[NODUS_V2_STAKE2_CALL_LEN - 9]  = 0;
        put64(d + NODUS_V2_STAKE2_CALL_LEN - 8, LOCK_AMT);
        return NODUS_V2_STAKE2_CALL_LEN;
    case DNA_SYSRULE_DELEGATE:
    case DNA_SYSRULE_UNDELEGATE:         /* delegator ‖ validator ‖ amount */
        memcpy(d, owner, 64);
        memset(d + 64, 0x6B, 64);
        put64(d + 128, LOCK_AMT);
        return NODUS_V2_DELEG2_CALL_LEN;
    case DNA_SYSRULE_UNSTAKE:            /* validator ‖ owner            */
        memset(d, 0x6B, 64);
        memcpy(d + 64, owner, 64);
        return NODUS_V2_UNSTAKE2_CALL_LEN;
    case DNA_SYSRULE_VALIDATOR_UPDATE:   /* validator ‖ owner ‖ comm     */
        memset(d, 0x6B, 64);
        memcpy(d + 64, owner, 64);
        d[128] = 0;
        d[129] = 100;
        return NODUS_V2_VUPD2_CALL_LEN;
    case DNA_SYSRULE_STORAGE_REGISTER:   /* owner ‖ pk ‖ sig ‖ exp ‖ bond  */
        memset(d, 0x5A, NODUS_V2_STREG_CALL_LEN);
        memcpy(d, owner, 64);
        put64(d + NODUS_V2_STREG_CALL_LEN - 8, LOCK_AMT);
        return NODUS_V2_STREG_CALL_LEN;
    case DNA_SYSRULE_STORAGE_EXIT:       /* node ‖ owner                 */
        memset(d, 0x7C, 64);
        memcpy(d + 64, owner, 64);
        return NODUS_V2_STEXIT_CALL_LEN;
    default:
        return 0;
    }
}

/* does the op lock LOCK_AMT on its funding leg? */
static int op_locks(uint32_t op) {
    return op == DNA_SYSRULE_STAKE || op == DNA_SYSRULE_DELEGATE ||
           op == DNA_SYSRULE_STORAGE_REGISTER;
}

/* leg 0 SYSTEM `op` (call already in e->sys), leg 1 CORE SYSFUND with
 * `n_in` inputs (strictly ascending nullifiers) and no change, CORE auth
 * kind `core_kind`; auth bytes zero (the exec reads the verdict only) */
static int env_build(env_t *e, uint32_t op, int n_in, uint8_t core_kind,
                     uint32_t sys_version, uint32_t core_version) {
    size_t off = 0;
    e->fund[off++] = (uint8_t)n_in;
    for (int i = 0; i < n_in; i++) {
        memset(e->fund + off, 0xA1 + i, 64);
        off += 64;
    }
    e->fund[off++] = 0;
    e->fund_len = (uint32_t)off;
    memset(e->auth, 0, sizeof(e->auth));
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = e->sys_len;
    legs[0].hdr.auth_len = AUTH1;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = e->sys;
    legs[0].auth_data = e->auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = core_kind;
    legs[1].hdr.call_len = e->fund_len;
    legs[1].hdr.auth_len = AUTH1;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = e->fund;
    legs[1].auth_data = e->auth[1];
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0)
        return -1;
    return dna_env_decode(e->bytes, e->len, &e->view);
}

/* ══ the engine facts ═════════════════════════════════════════════════ */

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static nodus_rt_read_res_t     g_reads[NODUS_RT_MAX_READS];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];

static void ctx_reset(void) {
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_chain, 0x42, sizeof(g_chain));
    memset(g_intent, 0x5D, sizeof(g_intent));
    memset(g_dig, 0x3C, sizeof(g_dig));
    g_ctx.chain_id = g_chain;
    g_ctx.global_height = H_EXEC;
    g_ctx.epoch = H_EXEC / E_LEN;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
}

/* kind 1: one verified signer `fp` */
static void av_k1(const uint8_t fp[64]) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], fp, 64);
}

/* kind 3: two verified signers (neither is an input owner here),
 * `nd` satisfied descriptors with addresses a0 (and a1) */
static void av_k3(const uint8_t a0[64], const uint8_t *a1) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 2;
    memset(g_av.signer_fp[0], 0xE1, 64);
    memset(g_av.signer_fp[1], 0xE2, 64);
    g_av.n_msig = a1 ? 2 : 1;
    memcpy(g_av.msig_addr[0], a0, 64);
    g_av.msig_satisfied[0] = 1;
    g_av.msig_signers_in_desc = 1u;
    if (a1) {
        memcpy(g_av.msig_addr[1], a1, 64);
        g_av.msig_satisfied[1] = 1;
        g_av.msig_signers_in_desc |= 2u;
    }
}

/* the funding reads: input i a native UTXO row owned by owner_i holding
 * amount_i, then the pool row; @return the read count */
static uint16_t reads_set(int n_in, const uint8_t *const owners[],
                          const uint64_t amounts[]) {
    memset(g_reads, 0, sizeof(g_reads));
    for (int i = 0; i < n_in; i++) {
        char h[129];
        hex_of(owners[i], h);
        g_reads[i].present = 1;
        g_reads[i].value_len = UTXO_REC_LEN;
        memcpy(g_reads[i].value, h, 128);
        put64(g_reads[i].value + UTXO_AMT_OFF, amounts[i]);
        put64(g_reads[i].value + UTXO_UNL_OFF, 0);
    }
    g_reads[n_in].present = 1;
    g_reads[n_in].value_len = 8;
    put64(g_reads[n_in].value, 1000u);
    return (uint16_t)(n_in + 1);
}

static int core_exec(const nodus_domain_runtime_t *rt, const env_t *e,
                     uint16_t n_reads) {
    size_t rl = 0;
    return nodus_rt_core_exec(rt, &e->view, 1, &g_ctx, g_reads, n_reads,
                              g_res, sizeof(g_res), &rl);
}

/* ══ P1-P3 per op, P4-P5 on DELEGATE (generation 4) ══════════════════ */

static int t_gen4(void) {
    static const uint32_t ops[7] = {
        DNA_SYSRULE_STAKE, DNA_SYSRULE_DELEGATE, DNA_SYSRULE_UNSTAKE,
        DNA_SYSRULE_UNDELEGATE, DNA_SYSRULE_VALIDATOR_UPDATE,
        DNA_SYSRULE_STORAGE_REGISTER, DNA_SYSRULE_STORAGE_EXIT
    };
    env_t *e = calloc(1, sizeof(*e));
    CHECK(e != NULL, "alloc");
    const uint32_t sv = 10, cv = g_c4->ruleset_version;
    CHECK(cv == 9, "the generation-4 CORE is v9 (the payer binding)");
    for (int k = 0; k < 7; k++) {
        const uint32_t op = ops[k];
        const uint64_t in_amt = FEE + (op_locks(op) ? LOCK_AMT : 0);
        char what[96];
        e->sys_len = call_v2(e->sys, op, g_own);
        CHECK(e->sys_len > 0, "call framed");

        /* P1 — kind 3, the owner's vault pays */
        CHECK(env_build(e, op, 1, NODUS_RT_AUTHKIND_DSA87_MSIG_V1, sv,
                        cv) == 0, "P1 envelope");
        ctx_reset();
        av_k3(g_own, NULL);
        {
            const uint8_t *ow[1] = { g_own };
            const uint64_t am[1] = { in_amt };
            snprintf(what, sizeof(what), "P1 op %u: kind-3 payer == the "
                     "signed owner APPLIES", (unsigned)op);
            CHECK(core_exec(g_c4, e, reads_set(1, ow, am)) == 0, what);
        }

        /* P2 — kind 3, another vault pays */
        ctx_reset();
        av_k3(g_vb, NULL);
        {
            const uint8_t *ow[1] = { g_vb };
            const uint64_t am[1] = { in_amt };
            snprintf(what, sizeof(what), "P2 op %u: kind-3 payer != the "
                     "signed owner REFUSED", (unsigned)op);
            CHECK(core_exec(g_c4, e, reads_set(1, ow, am)) == -1, what);
        }

        /* P3 — kind 1, a third-party key pays (unchanged) */
        CHECK(env_build(e, op, 1, NODUS_RT_AUTHKIND_DSA87_MULTI_V1, sv,
                        cv) == 0, "P3 envelope");
        ctx_reset();
        av_k1(g_pay);
        {
            const uint8_t *ow[1] = { g_pay };
            const uint64_t am[1] = { in_amt };
            snprintf(what, sizeof(what), "P3 op %u: kind-1 third-party "
                     "payer APPLIES (unchanged)", (unsigned)op);
            CHECK(core_exec(g_c4, e, reads_set(1, ow, am)) == 0, what);
        }
    }

    /* P4 / P5 — two descriptors on DELEGATE, one input each */
    e->sys_len = call_v2(e->sys, DNA_SYSRULE_DELEGATE, g_own);
    CHECK(env_build(e, DNA_SYSRULE_DELEGATE, 2,
                    NODUS_RT_AUTHKIND_DSA87_MSIG_V1, sv, cv) == 0,
          "P4 envelope");
    {
        const uint8_t *ow[2] = { g_own, g_vb };
        const uint64_t am[2] = { FEE, LOCK_AMT };
        ctx_reset();
        av_k3(g_own, g_vb);                 /* ascending: own < vb       */
        CHECK(core_exec(g_c4, e, reads_set(2, ow, am)) == -1,
              "P4: [owner, another vault] — the second descriptor pays "
              "too: REFUSED");
    }
    {
        /* the owner is the LARGER address this time: msig_addr[0] is the
         * other vault, msig_addr[1] the owner */
        uint8_t own_hi[64];
        memset(own_hi, 0x44, sizeof(own_hi));
        e->sys_len = call_v2(e->sys, DNA_SYSRULE_DELEGATE, own_hi);
        CHECK(env_build(e, DNA_SYSRULE_DELEGATE, 2,
                        NODUS_RT_AUTHKIND_DSA87_MSIG_V1, sv, cv) == 0,
              "P5 envelope");
        const uint8_t *ow[2] = { g_vb, own_hi };
        const uint64_t am[2] = { FEE, LOCK_AMT };
        ctx_reset();
        av_k3(g_vb, own_hi);                /* ascending: vb < own_hi    */
        CHECK(core_exec(g_c4, e, reads_set(2, ow, am)) == -1,
              "P5: [another vault, owner] — REFUSED");
    }
    free(e);
    return 0;
}

/* ══ P6 — generation 3: no rule ═══════════════════════════════════════ */

static int t_gen3(void) {
    env_t *e = calloc(1, sizeof(*e));
    CHECK(e != NULL, "alloc");
    const uint32_t sv = 8, cv = g_c3->ruleset_version;
    CHECK(cv == 6, "the generation-3 CORE is v6 (unchanged)");
    /* legacy DELEGATE: delegator_pk ‖ validator_pk ‖ amount */
    memset(e->sys, 0x31, PK_LEN);
    memset(e->sys + PK_LEN, 0x32, PK_LEN);
    put64(e->sys + 2 * PK_LEN, LOCK_AMT);
    e->sys_len = NODUS_V2_DELEG_CALL_LEN;
    CHECK(env_build(e, DNA_SYSRULE_DELEGATE, 1,
                    NODUS_RT_AUTHKIND_DSA87_MSIG_V1, sv, cv) == 0,
          "P6 DELEGATE envelope");
    {
        const uint8_t *ow[1] = { g_vb };
        const uint64_t am[1] = { FEE + LOCK_AMT };
        ctx_reset();
        av_k3(g_vb, NULL);
        CHECK(core_exec(g_c3, e, reads_set(1, ow, am)) == 0,
              "P6: generation-3 legacy DELEGATE funded by an unrelated "
              "kind-3 vault APPLIES (no rule below generation 4)");
    }
    /* legacy UNSTAKE: validator_pk */
    memset(e->sys, 0x33, PK_LEN);
    e->sys_len = NODUS_V2_UNSTAKE_CALL_LEN;
    CHECK(env_build(e, DNA_SYSRULE_UNSTAKE, 1,
                    NODUS_RT_AUTHKIND_DSA87_MSIG_V1, sv, cv) == 0,
          "P6 UNSTAKE envelope");
    {
        const uint8_t *ow[1] = { g_vb };
        const uint64_t am[1] = { FEE };
        ctx_reset();
        av_k3(g_vb, NULL);
        CHECK(core_exec(g_c3, e, reads_set(1, ow, am)) == 0,
              "P6: generation-3 legacy UNSTAKE funded by an unrelated "
              "kind-3 vault APPLIES");
    }
    free(e);
    return 0;
}

int main(void) {
    memset(g_own, 0x11, sizeof(g_own));
    memset(g_vb, 0x22, sizeof(g_vb));
    memset(g_pay, 0x33, sizeof(g_pay));
    g_c4 = nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                        DNA_DOMAIN_CORE);
    g_c3 = nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_CORE);
    if (!g_c4 || !g_c3) {
        fprintf(stderr, "generations 3 / 4 not compiled (NODUS_EVM_ENABLED "
                "missing)\n");
        return 1;
    }
    if (t_gen4() != 0) return 1;
    if (t_gen3() != 0) return 1;
    printf("test_hf6_payer: %d checks passed\n", g_checks);
    return 0;
}
