/**
 * @file nodus/tests/test_storage_cli.c
 * @brief Storage reward v1, package B2b-CLI — the shared builder's
 *        STORAGE_REGISTER (op 7) / STORAGE_EXIT (op 8) envelopes fed to the
 *        chain's own hooks, the builder's refusals, the decoder's
 *        refusals, and the dnac_storage_status reply decoder's strict
 *        rules.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (registration, 1M bond, node-key authority STAY);
 * docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md
 * ("İşlem kurucu": the CLI and the wallet build with ONE C builder,
 * nodus/src/client/nodus_v2_stake.c). Call bytes:
 * docs/plans/2026-10-04-storage-reward-bytes.md item 5.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  C1 REGISTER built by nodus_v2_stake_build (GEN_STORAGE tuples from the
 *     compiled table, a fixed key, gas price 0):
 *       - the read-back carries op 7, the key, bond DNAC_STORAGE_STAKE_MIN
 *         and payee = SHA3-512(pk);
 *       - the SYSTEM call bytes equal an independent restatement of bytes
 *         doc item 5 (node_pk ‖ bond u64 BE ‖ payee_fp, 2664 bytes);
 *       - the GEN_STORAGE SYSTEM read plan asks [row op 8 key node_fp,
 *         live count op 9 selector 1]; the generation-2 SYSTEM refuses;
 *       - the GEN_STORAGE SYSTEM exec, given the node as the single
 *         verified signer, an absent row and a live count of 0, emits ONE
 *         CREATE / ABSENT whose record is node_pk ‖ payee ‖ bond ‖ ACTIVE ‖
 *         h ‖ 0 ‖ 0; another signer is refused;
 *       - the GEN_STORAGE CORE read plan of the funding leg is the inputs
 *         + the pool; the generation-2 CORE refuses the pairing;
 *       - the GEN_STORAGE CORE exec of the funding leg over fabricated
 *         input rows owned by the node succeeds: Σin == change + fee +
 *         bond (rtn_sys_call_flow lock = bond); one raw unit more on the
 *         input breaks the equation and is refused.
 *     False if the call layout, the op id, the leg shape, the payee rule,
 *     the funding arithmetic or the signer binding were wrong.
 *  C2 EXIT built by the builder: op 8, call = the node key (2592 bytes),
 *     the read plan [row]; the exec from an ACTIVE row emits ONE SET /
 *     EXISTS_VHASH to EXITING with exit_height h; the funding leg is
 *     fee-only (Σin == change + fee; +1 refused); decoded amount 0.
 *  C3 Builder refusals: bond one under / one over (ERR_STORAGE_BOND), a
 *     foreign payee (ERR_PAYEE), no payee (ERR_ARG), STORAGE_REPORT (op 9)
 *     and VALIDATOR_UPDATE (op 5) (ERR_OP), funding below bond + fee
 *     (ERR_INSUFFICIENT).
 *  C4 nodus_v2_stake_decode refuses a REGISTER whose payee byte was
 *     flipped (the pre-HF-5 payee rule) and accepts the untouched bytes.
 *  C5 nodus_dnac_storage_status_decode: a found member with segments, a
 *     not-found node with no set, a full 64-entry list for ns = 100 are
 *     accepted with every field (K9: "gu" grace_until read back, a full
 *     u64 accepted); refused: a missing required key, a duplicate key, a
 *     found row missing a row key ("payee", "gu"), a duplicate "gu", row
 *     keys on a not-found
 *     reply, st 0 / 4, rh 0, fs above u32, sc 257, an uppercase payee,
 *     es > ch, set false with sc 1, set false with mem true, mem true with
 *     found false, ns > 0 without membership, a list shorter than
 *     min(ns, 64), 65 entries, a descending list, a 0 segment, "found" as
 *     an integer.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. No
 * database, no network, no files.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Hook level only: the verdict, the registry rows, the live count, the
 *    input UTXO rows and the pool are FABRICATED engine facts. It proves
 *    the builder's bytes against the exec's rule decisions, NOT admission
 *    (descriptor ownership, meter policy, the 400 000-unit ceiling's
 *    sufficiency), signature verification or a block applied end to end.
 *    The engine path of registrations is test_storage_reg section B (its
 *    envelopes are hand-built there, not by this builder).
 *  - The SYSTEM call restatement is written by the same author as the
 *    builder change (self-consistency with bytes doc item 5 and the exec's
 *    parser, not an independent oracle).
 *  - C5 covers the decoder only; the witness handler
 *    (handle_dnac_storage_status) is not driven here — no fixture chain
 *    with a frozen storage set is built.
 *  - Written and compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_stake.h"
#include "protocol/nodus_cbor.h"

#include "dnac/dnac.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdbool.h>
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

#define BOND     ((uint64_t)DNAC_STORAGE_STAKE_MIN)
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define H_EXEC   9u               /* the fabricated executing height      */
#define TIP      8u

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_STOR        8u
#define OP_STORCNT     9u
#define OP_UTXO        1u
#define OP_SUPPLY      3u
#define SEL_POOL       3u
#define STOR_REC_LEN   2693u   /* + fail_streak u32, + grace_until u64 (K9) */
#define STOR_PAYEE_OFF 2592u
#define STOR_BOND_OFF  2656u
#define STOR_STAT_OFF  2664u
#define STOR_REGH_OFF  2665u
#define STOR_EXITH_OFF 2673u
#define UTXO_REC_LEN   284u
#define UTXO_AMT_OFF   128u
#define UTXO_TOK_OFF   136u
#define UTXO_UNL_OFF   276u

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

/* ══ keys, ruleset, coins ════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];
    char    hex[129];
} sc_key_t;

enum { KN, KO, N_KEYS };          /* the node, another key              */
static sc_key_t g_k[N_KEYS];

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x3C + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

static nodus_v2_stake_ruleset_t g_rs;
static uint8_t g_chain32[DNA_CHAIN_ID_LEN];

static int rs_storage(void) {
    const nodus_domain_runtime_t *s =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    if (!s || !c) return -1;
    memset(&g_rs, 0, sizeof(g_rs));
    g_rs.sys_ruleset_version  = s->ruleset_version;
    memcpy(g_rs.sys_ruleset_hash, s->ruleset_hash, 64);
    g_rs.core_ruleset_version = c->ruleset_version;
    memcpy(g_rs.core_ruleset_hash, c->ruleset_hash, 64);
    memset(g_chain32, 0x5C, sizeof(g_chain32));
    return 0;
}

/* one native, unlocked coin of the node */
static nodus_v2_stake_coin_t g_coin;

static void coin_set(uint64_t amount) {
    memset(&g_coin, 0, sizeof(g_coin));
    memset(g_coin.nul, 0x42, 64);
    g_coin.amount = amount;
}

static void req_base(nodus_v2_stake_req_t *r, nodus_v2_stake_op_t op) {
    memset(r, 0, sizeof(*r));
    r->rs = &g_rs;
    r->op = op;
    r->chain32 = g_chain32;
    r->tip = TIP;
    r->expiry_height = TIP + 50u;
    r->pk = g_k[KN].pk;
    r->sk = g_k[KN].sk;
    r->amount = op == NODUS_V2_STAKE_OP_STORAGE_REGISTER ? BOND : 0;
    r->dest_fp = op == NODUS_V2_STAKE_OP_STORAGE_REGISTER ? g_k[KN].fp : NULL;
    r->gas_price = 0;
    r->coins = &g_coin;
    r->n_coins = 1;
}

/* ══ fabricated engine facts (the test_storage_reg hk_ctx pattern) ═══ */

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_intent[64], g_dig[64];
static nodus_rt_read_res_t g_reads[NODUS_RT_MAX_READS];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

static void ctx_set(int signer) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], g_k[signer].fp, 64);
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_intent, 0x6E, sizeof(g_intent));
    memset(g_dig, 0x2D, sizeof(g_dig));
    g_ctx.chain_id = g_chain32;
    g_ctx.global_height = H_EXEC;
    g_ctx.epoch = H_EXEC / (uint64_t)DNAC_EPOCH_LENGTH;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
}

/* the funding leg's mediated reads: one fabricated UTXO row per input
 * (owner = the node's hex fp, native, unlocked) holding `amount_each`
 * (the input amount of THIS test's single coin), then the pool */
static uint16_t fund_reads(const dna_env_view_t *v, uint64_t amount) {
    const uint8_t *c = v->buf + v->call_off[1];
    const uint8_t n_in = c[0];
    memset(g_reads, 0, sizeof(g_reads));
    for (uint8_t i = 0; i < n_in; i++) {
        g_reads[i].present = 1;
        g_reads[i].value_len = UTXO_REC_LEN;
        memcpy(g_reads[i].value, g_k[KN].hex, 128);
        put64(g_reads[i].value + UTXO_AMT_OFF, amount);
        put64(g_reads[i].value + UTXO_UNL_OFF, 0);
    }
    g_reads[n_in].present = 1;
    g_reads[n_in].value_len = 8;
    put64(g_reads[n_in].value, 1000u);
    return (uint16_t)(n_in + 1u);
}

static int sys_exec(const nodus_domain_runtime_t *rt,
                    const dna_env_view_t *v, uint16_t n_reads,
                    dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, v, 0, &g_ctx, g_reads, n_reads,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int core_exec(const nodus_domain_runtime_t *rt,
                     const dna_env_view_t *v, uint16_t n_reads) {
    size_t rl = 0;
    return nodus_rt_core_exec(rt, v, 1, &g_ctx, g_reads, n_reads,
                              g_res, sizeof(g_res), &rl);
}

/* ══ C1 / C2 — builder envelopes through the hooks ═══════════════════ */

static int t_register(void) {
    const nodus_domain_runtime_t *s2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s2 && s3 && c2 && c3, "compiled generations 2 and GEN_STORAGE");

    const uint64_t coin = BOND + 7000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "REGISTER builds");
    CHECK(b.dec.op == DNA_SYSRULE_STORAGE_REGISTER && b.dec.amount == BOND &&
          memcmp(b.dec.identity_pk, g_k[KN].pk, PK_LEN) == 0 &&
          memcmp(b.dec.dest_fp, g_k[KN].fp, 64) == 0 &&
          b.n_in == 1 && b.change == coin - BOND - b.fee,
          "read-back: op 7, node key, bond, payee = own fp, change");

    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "view alloc");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0 && v->leg_count == 2,
          "two legs decode");
    CHECK(v->leg[0].domain_id == DNA_DOMAIN_SYSTEM &&
          v->leg[0].runtime_op == DNA_SYSRULE_STORAGE_REGISTER &&
          v->leg[1].domain_id == DNA_DOMAIN_CORE &&
          v->leg[1].runtime_op == DNA_CORERULE_SYSFUND,
          "leg 0 SYSTEM op 7, leg 1 CORE SYSFUND");
    {   /* bytes doc item 5, restated */
        static uint8_t want[PK_LEN + 8 + 64];
        memcpy(want, g_k[KN].pk, PK_LEN);
        put64(want + PK_LEN, BOND);
        memcpy(want + PK_LEN + 8, g_k[KN].fp, 64);
        CHECK(v->leg[0].call_len == sizeof(want) && sizeof(want) == 2664u &&
              memcmp(v->buf + v->call_off[0], want, sizeof(want)) == 0,
              "call = node_pk ‖ bond u64 BE ‖ payee_fp (2664 bytes)");
    }

    ctx_set(KN);
    /* read plans */
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        CHECK(nodus_rt_system_read_plan(s3, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 2 && rq[0].op_id == OP_STOR && rq[0].key_len == 64 &&
              memcmp(rq[0].key, g_k[KN].fp, 64) == 0 &&
              rq[1].op_id == OP_STORCNT && rq[1].key_len == 1 &&
              rq[1].key[0] == 1, "SYSTEM plan: row by node_fp + live count");
        CHECK(nodus_rt_system_read_plan(s2, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == -1,
              "generation 2 plans nothing for op 7");
        CHECK(nodus_rt_core_read_plan(c3, v, 1, &g_ctx, rq,
                                      NODUS_RT_MAX_READS, &n) == 0 &&
              n == 2 && rq[0].op_id == OP_UTXO &&
              memcmp(rq[0].key, g_coin.nul, 64) == 0 &&
              rq[1].op_id == OP_SUPPLY && rq[1].key[0] == SEL_POOL,
              "CORE plan: the input + the pool");
        CHECK(nodus_rt_core_read_plan(c2, v, 1, &g_ctx, rq,
                                      NODUS_RT_MAX_READS, &n) == -1,
              "generation-2 CORE refuses the storage pairing");
    }
    /* SYSTEM exec: absent row, live count 0 */
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[1].present = 1;
        g_reads[1].value_len = 8;
        put64(g_reads[1].value, 0);
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(s3, v, 2, &ev) == 0, "REGISTER exec applies");
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].value_len == STOR_REC_LEN &&
              memcmp(ev.buf + ev.key_off[0], g_k[KN].fp, 64) == 0,
              "one CREATE / ABSENT keyed node_fp");
        static uint8_t rec[STOR_REC_LEN];
        memset(rec, 0, sizeof(rec));
        memcpy(rec, g_k[KN].pk, PK_LEN);
        memcpy(rec + STOR_PAYEE_OFF, g_k[KN].fp, 64);
        put64(rec + STOR_BOND_OFF, BOND);
        rec[STOR_STAT_OFF] = DNA_V2_STORAGE_ACTIVE;
        put64(rec + STOR_REGH_OFF, H_EXEC);
        CHECK(memcmp(ev.buf + ev.val_off[0], rec, STOR_REC_LEN) == 0,
              "record = pk ‖ payee ‖ bond ‖ ACTIVE ‖ h ‖ 0 ‖ 0");
        ctx_set(KO);
        CHECK(sys_exec(s3, v, 2, NULL) == -1,
              "a signer other than the node is refused");
        ctx_set(KN);
    }
    /* CORE exec: Σin == change + fee + bond */
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(c3, v, nr) == 0,
              "funding leg balances with lock = bond");
        nr = fund_reads(v, coin + 1u);
        CHECK(core_exec(c3, v, nr) == -1,
              "one raw unit more on the input breaks the equation");
    }
    free(v);
    nodus_v2_stake_built_free(&b);
    return 0;
}

static int t_exit(void) {
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s3 && c3, "GEN_STORAGE runtimes");

    const uint64_t coin = 9000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_EXIT);
    r.amount = 12345;                    /* must be ignored               */
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "EXIT builds");
    CHECK(b.dec.op == DNA_SYSRULE_STORAGE_EXIT && b.dec.amount == 0 &&
          memcmp(b.dec.identity_pk, g_k[KN].pk, PK_LEN) == 0 &&
          b.change == coin - b.fee, "read-back: op 8, no amount, fee only");

    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "view alloc");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0 && v->leg_count == 2 &&
          v->leg[0].runtime_op == DNA_SYSRULE_STORAGE_EXIT &&
          v->leg[0].call_len == PK_LEN &&
          memcmp(v->buf + v->call_off[0], g_k[KN].pk, PK_LEN) == 0,
          "call = the node key (2592 bytes)");

    ctx_set(KN);
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        CHECK(nodus_rt_system_read_plan(s3, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 1 && rq[0].op_id == OP_STOR &&
              memcmp(rq[0].key, g_k[KN].fp, 64) == 0,
              "EXIT plans the row");
    }
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;
        g_reads[0].value_len = STOR_REC_LEN;
        uint8_t *rec = g_reads[0].value;
        memcpy(rec, g_k[KN].pk, PK_LEN);
        memcpy(rec + STOR_PAYEE_OFF, g_k[KN].fp, 64);
        put64(rec + STOR_BOND_OFF, BOND);
        rec[STOR_STAT_OFF] = DNA_V2_STORAGE_ACTIVE;
        put64(rec + STOR_REGH_OFF, 2);
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(s3, v, 1, &ev) == 0, "EXIT from ACTIVE applies");
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_SET &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH,
              "one SET / EXISTS_VHASH");
        const uint8_t *nv = ev.buf + ev.val_off[0];
        CHECK(nv[STOR_STAT_OFF] == DNA_V2_STORAGE_EXITING &&
              get64(nv + STOR_EXITH_OFF) == H_EXEC &&
              get64(nv + STOR_BOND_OFF) == BOND,
              "EXITING, exit_height h, the bond stays on the row");
    }
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(c3, v, nr) == 0, "fee-only funding balances");
        nr = fund_reads(v, coin + 1u);
        CHECK(core_exec(c3, v, nr) == -1, "an excess input is refused");
    }
    free(v);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* ══ C3 / C4 — refusals ══════════════════════════════════════════════ */

static int t_refusals(void) {
    nodus_v2_stake_req_t r;
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    coin_set(BOND + 7000000000ULL);

    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER);
    r.amount = BOND - 1u;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_STORAGE_BOND,
          "bond one under refused");
    r.amount = BOND + 1u;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_STORAGE_BOND,
          "bond one over refused");
    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER);
    r.dest_fp = g_k[KO].fp;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_PAYEE,
          "a foreign payee refused (until HF-5)");
    r.dest_fp = NULL;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "no payee refused");
    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER);
    r.op = (nodus_v2_stake_op_t)DNA_SYSRULE_STORAGE_REPORT;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_OP,
          "STORAGE_REPORT is not built here");
    r.op = (nodus_v2_stake_op_t)DNA_SYSRULE_VALIDATOR_UPDATE;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_OP,
          "VALIDATOR_UPDATE is not built here");
    coin_set(BOND);                      /* bond, but not bond + fee      */
    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_INSUFFICIENT
          && e.need > BOND, "funding below bond + fee refused");

    /* C4: the decoder's payee rule */
    coin_set(BOND + 7000000000ULL);
    req_base(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "REGISTER builds");
    nodus_v2_stake_decoded_t *d = calloc(1, sizeof(*d));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    uint8_t *copy = malloc(b.env_len);
    CHECK(d && v && copy, "alloc");
    CHECK(nodus_v2_stake_decode(b.env, b.env_len, d) == NODUS_V2_SPEND_OK &&
          d->op == DNA_SYSRULE_STORAGE_REGISTER, "untouched bytes decode");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0, "view");
    memcpy(copy, b.env, b.env_len);
    copy[v->call_off[0] + PK_LEN + 8] ^= 0x01;   /* first payee byte */
    CHECK(nodus_v2_stake_decode(copy, b.env_len, d) ==
          NODUS_V2_SPEND_ERR_DECODE, "a payee != SHA3-512(node_pk) refused");
    free(copy);
    free(v);
    free(d);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* ══ C5 — the status reply decoder ═══════════════════════════════════ */

typedef struct {
    uint64_t ch, es, st, bond, fs, gu, rh, xh, sc, ns;
    int found, set, mem;
    const char *payee;
    size_t nsegs;
    uint64_t segs[70];
    const char *omit;            /* a key not emitted                    */
    const char *dup;             /* a key emitted twice                  */
    int row;                     /* -1 follow found, 0 none, 1 all       */
    int found_uint;              /* "found" encoded as an integer        */
} sr_t;

static char g_payee[129];

static void sr_member(sr_t *s) {
    memset(s, 0, sizeof(*s));
    s->ch = 1500; s->es = 1440; s->found = 1;
    s->st = DNA_V2_STORAGE_ACTIVE; s->bond = BOND; s->fs = 1; s->rh = 20;
    s->gu = 2160;
    s->xh = 0; s->payee = g_payee; s->set = 1; s->sc = 5; s->mem = 1;
    s->ns = 2; s->nsegs = 2; s->segs[0] = 3; s->segs[1] = 7;
    s->row = -1;
}

static void sr_absent(sr_t *s) {
    memset(s, 0, sizeof(*s));
    s->ch = 700; s->es = 0; s->found = 0; s->payee = g_payee; s->row = -1;
}

/* emit (or, with enc == NULL, count) the "r" map's entries */
static size_t sr_emit(const sr_t *s, cbor_encoder_t *enc) {
    size_t n = 0;
    const int row = s->row < 0 ? s->found : s->row;
    for (int pass = 0; pass < 2; pass++) {
        const int dup = pass == 1;
#define SR_U(name, val) \
        if ((!dup && (!s->omit || strcmp(s->omit, name))) || \
            (dup && s->dup && !strcmp(s->dup, name))) { \
            n++; \
            if (enc) { cbor_encode_cstr(enc, name); \
                       cbor_encode_uint(enc, (val)); } }
#define SR_B(name, val) \
        if ((!dup && (!s->omit || strcmp(s->omit, name))) || \
            (dup && s->dup && !strcmp(s->dup, name))) { \
            n++; \
            if (enc) { cbor_encode_cstr(enc, name); \
                       cbor_encode_bool(enc, (val) != 0); } }
        SR_U("ch", s->ch)
        SR_U("es", s->es)
        if ((!dup && (!s->omit || strcmp(s->omit, "found"))) ||
            (dup && s->dup && !strcmp(s->dup, "found"))) {
            n++;
            if (enc) {
                cbor_encode_cstr(enc, "found");
                if (s->found_uint) cbor_encode_uint(enc, (uint64_t)s->found);
                else cbor_encode_bool(enc, s->found != 0);
            }
        }
        if (row) {
            SR_U("st", s->st)
            SR_U("bond", s->bond)
            SR_U("fs", s->fs)
            SR_U("gu", s->gu)
            SR_U("rh", s->rh)
            SR_U("xh", s->xh)
            if ((!dup && (!s->omit || strcmp(s->omit, "payee"))) ||
                (dup && s->dup && !strcmp(s->dup, "payee"))) {
                n++;
                if (enc) {
                    cbor_encode_cstr(enc, "payee");
                    cbor_encode_cstr(enc, s->payee);
                }
            }
        }
        SR_B("set", s->set)
        SR_U("sc", s->sc)
        SR_B("mem", s->mem)
        SR_U("ns", s->ns)
        if ((!dup && (!s->omit || strcmp(s->omit, "segs"))) ||
            (dup && s->dup && !strcmp(s->dup, "segs"))) {
            n++;
            if (enc) {
                cbor_encode_cstr(enc, "segs");
                cbor_encode_array(enc, s->nsegs);
                for (size_t i = 0; i < s->nsegs; i++)
                    cbor_encode_uint(enc, s->segs[i]);
            }
        }
#undef SR_U
#undef SR_B
    }
    return n;
}

static int sr_decode(const sr_t *s, nodus_dnac_storage_status_t *out) {
    static uint8_t buf[4096];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, "dnac_storage_status");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, sr_emit(s, NULL));
    (void)sr_emit(s, &enc);
    size_t len = cbor_encoder_len(&enc);
    if (len == 0) return -9;
    return nodus_dnac_storage_status_decode(buf, len, out);
}

static int t_status_decoder(void) {
    sr_t s;
    nodus_dnac_storage_status_t o;
    hex_of(g_k[KN].fp, g_payee);

    /* accepted */
    sr_member(&s);
    CHECK(sr_decode(&s, &o) == 0, "a found member decodes");
    CHECK(o.committed_height == 1500 && o.epoch_start == 1440 && o.found &&
          o.status == DNA_V2_STORAGE_ACTIVE && o.bond == BOND &&
          o.fail_streak == 1 && o.grace_until == 2160 &&
          o.registered_height == 20 &&
          o.exit_height == 0 && strcmp(o.payee, g_payee) == 0 &&
          o.set_exists && o.set_count == 5 && o.member &&
          o.n_segments == 2 && o.n_listed == 2 && o.segments[0] == 3 &&
          o.segments[1] == 7, "every field read back");
    sr_absent(&s);
    CHECK(sr_decode(&s, &o) == 0 && !o.found && !o.set_exists && !o.member &&
          o.n_listed == 0, "a not-found node with no set decodes");
    sr_member(&s);
    s.ns = 100; s.nsegs = NODUS_DNAC_STORAGE_SEG_MAX;
    for (size_t i = 0; i < s.nsegs; i++) s.segs[i] = 10 + i;
    CHECK(sr_decode(&s, &o) == 0 && o.n_segments == 100 &&
          o.n_listed == NODUS_DNAC_STORAGE_SEG_MAX,
          "a full list for ns > SEG_MAX decodes");

    /* refused */
    static const char *const REQ[] = { "ch", "es", "found", "set", "sc",
                                       "mem", "ns", "segs" };
    for (size_t i = 0; i < sizeof(REQ) / sizeof(REQ[0]); i++) {
        sr_member(&s);
        s.omit = REQ[i];
        CHECK(sr_decode(&s, &o) == -1, "a missing required key refused");
    }
    sr_member(&s); s.dup = "ch";
    CHECK(sr_decode(&s, &o) == -1, "a duplicate key refused");
    sr_member(&s); s.omit = "payee";
    CHECK(sr_decode(&s, &o) == -1, "a found row missing a key refused");
    sr_member(&s); s.omit = "gu";
    CHECK(sr_decode(&s, &o) == -1, "a found row without grace_until "
          "refused");
    sr_member(&s); s.dup = "gu";
    CHECK(sr_decode(&s, &o) == -1, "a duplicate grace_until refused");
    sr_member(&s); s.gu = UINT64_MAX;
    CHECK(sr_decode(&s, &o) == 0 && o.grace_until == UINT64_MAX,
          "grace_until is a full u64 on the wire");
    sr_absent(&s); s.row = 1;
    CHECK(sr_decode(&s, &o) == -1, "row keys on a not-found reply refused");
    sr_member(&s); s.st = 0;
    CHECK(sr_decode(&s, &o) == -1, "status 0 refused");
    sr_member(&s); s.st = 4;
    CHECK(sr_decode(&s, &o) == -1, "status 4 refused");
    sr_member(&s); s.rh = 0;
    CHECK(sr_decode(&s, &o) == -1, "registered_height 0 refused");
    sr_member(&s); s.fs = (uint64_t)UINT32_MAX + 1u;
    CHECK(sr_decode(&s, &o) == -1, "fail_streak above u32 refused");
    sr_member(&s); s.sc = NODUS_DNAC_STORAGE_SET_MAX + 1u;
    CHECK(sr_decode(&s, &o) == -1, "sc 257 refused");
    {
        static char upper[129];
        memcpy(upper, g_payee, sizeof(upper));
        for (int i = 0; i < 128; i++)
            if (upper[i] >= 'a' && upper[i] <= 'f') { upper[i] -= 32; break; }
        sr_member(&s); s.payee = upper;
        CHECK(sr_decode(&s, &o) == -1, "an uppercase payee refused");
    }
    sr_member(&s); s.es = s.ch + 1u;
    CHECK(sr_decode(&s, &o) == -1, "es above ch refused");
    sr_absent(&s); s.sc = 1;
    CHECK(sr_decode(&s, &o) == -1, "no set but a member count refused");
    sr_member(&s); s.set = 0; s.sc = 0;
    CHECK(sr_decode(&s, &o) == -1, "no set but a member refused");
    sr_absent(&s); s.es = 0; s.set = 1; s.mem = 1;
    CHECK(sr_decode(&s, &o) == -1, "a member without a registry row refused");
    sr_member(&s); s.mem = 0;
    CHECK(sr_decode(&s, &o) == -1, "segments without membership refused");
    sr_member(&s); s.ns = 3;
    CHECK(sr_decode(&s, &o) == -1, "a list shorter than min(ns, 64) refused");
    sr_member(&s);
    s.ns = 100; s.nsegs = NODUS_DNAC_STORAGE_SEG_MAX + 1u;
    for (size_t i = 0; i < s.nsegs; i++) s.segs[i] = 10 + i;
    CHECK(sr_decode(&s, &o) == -1, "65 listed segments refused");
    sr_member(&s); s.segs[0] = 7; s.segs[1] = 3;
    CHECK(sr_decode(&s, &o) == -1, "a descending list refused");
    sr_member(&s); s.segs[0] = 0;
    CHECK(sr_decode(&s, &o) == -1, "segment 0 refused");
    sr_member(&s); s.found_uint = 1;
    CHECK(sr_decode(&s, &o) == -1, "\"found\" as an integer refused");
    return 0;
}

int main(void) {
    if (keys_make() != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    if (rs_storage() != 0) {
        fprintf(stderr, "GEN_STORAGE runtimes missing from the table\n");
        return 1;
    }
    if (t_register() != 0) return 1;
    if (t_exit() != 0) return 1;
    if (t_refusals() != 0) return 1;
    if (t_status_decoder() != 0) return 1;
    printf("test_storage_cli: %d checks passed\n", g_checks);
    return 0;
}
