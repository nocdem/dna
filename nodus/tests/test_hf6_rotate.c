/**
 * @file nodus/tests/test_hf6_rotate.c
 * @brief HF-6 D1 — NO key rotation; the consensus-key index is PERMANENT.
 *
 * Khan decision docs/plans/decisions/2026-10-13-kurultay-18-summary.md
 * items 1 and 4 (Option D; design docs/plans/2026-10-03-hf5-validator-
 * owner-stake-design.md §3 box "KALDIRILDI — han kararı 2026-10-13"):
 * ROTATE_CONSENSUS_KEY (SYSTEM op 10, consent op 2) is removed from
 * generation 4; a consensus key that ever appeared in a validators row
 * (any status, UNSTAKED included) can never be STAKEd again; an operator
 * who wants a new key UNSTAKEs and STAKEs a new validator under a fresh
 * key. v2_consensus_keys is a permanent, append-only index — one role-1
 * row per validators row, never released — and the §6.3 pending fields
 * are always zero. (Until 2026-10-13 this file tested the ROTATE exec,
 * the rotation pass of the freeze, the swap and the sweep; all of that
 * was deleted with the feature.)
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. TABLE (no database):
 *   A1 DNA_SYSRULE_ROTATE_CONSENSUS_KEY keeps the reserved id 10; NO
 *      generation's SYSTEM or CORE descriptor owns op 10 (the list
 *      rt_owns_runtime_op walks, restated as the same ascending scan) and
 *      no SYSTEM meter policy prices it; the generation-4 SYSTEM (still v9)
 *      owns exactly {1..9}.
 *   A2 the compiled table passes its selfcheck and the param-18 vote value
 *      D4 re-derives through nodus_runtime_gen4_vote_digest.
 *      ⚠ EXPECTED RED until the next package (D2): the pinned SYSTEM hash,
 *      policy digest, nodus_ruleset_pins.h and DNAC_CFG_RULESET_GEN_ROLES_D
 *      still carry the {1..10} values (decision item 3: SYSTEM 9 -> 10,
 *      CORE 7 -> 8 and an oracle re-pin). Every engine case below opens a
 *      chain through the same selfcheck, so they are red with it.
 *  H. HOOKS (fabricated engine facts, a real committed-row shape):
 *   H1 for a NULL runtime and generations 1..4 the SYSTEM read plan and
 *      exec of a 2-leg {SYSTEM op 10, CORE SYSFUND} envelope return -1 —
 *      a VERDICT, never -2 — at generation 4 also with a kind-1 verdict of
 *      the row's owner and the committed row as the read;
 *   H2 the CORE SYSFUND plan and exec refuse to pair with an op-10
 *      sibling (-1) under generations 3 and 4;
 *   H3 the read-only describer refuses an op-10 leg (-1: no applied leg
 *      can carry it).
 *  B. ENGINE (twin seeded chains, EVM-enabled build: V0..V6 ACTIVE 10M
 *     since 1 and VU an UNSTAKED pre-HF-6 row (self 0) — every block from
 *     2 carrying the seven COMMIT votes; param 9 at 2, param 14 at 3,
 *     param 18 — the generation-4 vote (D4) — at 4, so the edge runs in
 *     block 3):
 *   B1 block 3 (generation 3): an op-10 envelope is refused at ADMISSION;
 *      its funding coin stays unspent.
 *   B2 after the edge: EIGHT role-1 reservations — the seven bonded rows
 *      AND the UNSTAKED VU (the edge seeds every status) — VU's
 *      key naming VU's migrated validator_id; the self-check core
 *      (nodus_witness_v2_keyres_diff) finds 0 differences.
 *   B3 block 4 (generation 4): an op-10 envelope is refused at ADMISSION
 *      with the ledger tables byte-identical and the coin unspent.
 *   B4 block 5: a STAKE of V_A (owner KO, key KC1) applies; block 6: its
 *      UNSTAKE applies (RETIRING).
 *   B5 block 7: a STAKE under VU's key (the pre-HF-6 retired key, its own
 *      consent) is REFUSED at exec with the ledger byte-identical.
 *   B6 boundary E: V_A graduates (UNSTAKED) and its reservation is KEPT
 *      (nine rows); the self-check at every boundary finds 0 differences.
 *   B7 block E + 1: a STAKE re-using KC1 (V_A's — graduated — key, its own
 *      consent) is REFUSED with the ledger byte-identical and the coin
 *      unspent: "UNSTAKE + new STAKE under the SAME key" does not exist.
 *   B8 block E + 2: a STAKE under a FRESH key KC2 applies (the only way to
 *      a new key: a new validator); ten rows; 0 differences.
 *   K. THE SELF-CHECK CORE on that state (twin A, each probe inside a
 *      ROLLED-BACK transaction): a missing row, an extra row, a row naming
 *      another validator, a role-2 row on a derived key, a TEXT
 *      consensus_pk_hash and a TEXT validator_id (malformed — the storage
 *      class is checked) are each EXACTLY one difference; a non-zero
 *      pending field makes the core refuse to compare (rc -1 — the strict
 *      row reader refuses the row). Rolled back: A is byte-identical to B.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). B assumes
 * DNAC_EPOCH_LENGTH >= 12 (checked; true for the production 720 and the
 * harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_hf6_rotate_* directories, removed at the end (left behind
 * when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - A1 restates rt_owns_runtime_op's scan (the engine's is static); B1 and
 *    B3 are what drive the real admission gate.
 *  - Section H fabricates the verdicts and the read results: it proves the
 *    hooks' refusals, not the engine's reads.
 *  - B's genesis UTXOs, the UNSTAKED VU row and the reward pool are SEEDED
 *    (V2X_SEED_NOT_REAL_UTXOS / _STATUSES): a pre-HF-6 retired row is
 *    planted, not produced by a legacy UNSTAKE + graduation.
 *  - B7's refusal is asserted as NODUS_V2_TX_ERR_EXEC with the ledger
 *    untouched; that it is the RESERVATION (and not the call) is pinned by
 *    B8, the same call shape under a fresh key, which applies.
 *  - K corrupts the table / a roles row by direct SQL inside a rolled-back
 *    transaction and calls the core there: it proves the comparison, not
 *    that any writer could produce that state. The boundary's log-only
 *    wrapper calling the same core is read from the source
 *    (nodus_witness_v2_epoch.c step 7), not observed — no log is captured.
 *  - B stops at E + 2: one boundary is crossed (the graduation); a row
 *    STAKEd at generation 4 is never seated here (Rule R tenure).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_native.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/cmt_pb.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/res_meter.h"
#include "dnac/valbind_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define FEE       ((uint64_t)DNAC_MIN_FEE_RAW)
#define TEN_M     ((uint64_t)DNAC_SELF_STAKE_AMOUNT)
#define SMIN      ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define RPOOL     10000000000000000ULL               /* 10^16 raw         */
#define PK_LEN    ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN   ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define AUTH1     (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define OP10_LEN  7291u     /* the removed ROTATE call's length: any bytes
                             * of it are refused before they are parsed  */
#define STK_LEN   7301u     /* design §2 (K7): 64+2592+4627+8+2+8        */
#define UNS_LEN   64u       /* the generation-4 UNSTAKE: validator_id    */

/* restated from nodus_witness_rt_native.c (static there) */
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_CPK_OFF    128u
#define V2_KEFF_OFF   (128u + 2u * 2592u)             /* 5312 */
#define V2_SELF_OFF   (V2_KEFF_OFF + 8u)
#define V2_COMM_OFF   (V2_SELF_OFF + 24u)
#define V2_STAT_OFF   (V2_COMM_OFF + 12u)
#define V2_SINCE_OFF  (V2_STAT_OFF + 1u)

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* V0..V6 the genesis committee; VU an UNSTAKED pre-HF-6 row; KO the
 * single-key owner / funder; KC1 / KC2 consensus keys of STAKEd
 * validators; KN the key an op-10 call would have named */
enum { V0, V1, V2, V3, V4, V5, V6, VU, KO, KC1, KC2, KN, N_KEYS };
#define N_VAL 7
static sk_key_t g_k[N_KEYS];
static uint8_t  g_vaddr[N_VAL][32];
static int32_t  g_vflag[N_VAL];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x31 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    for (int i = 0; i < N_VAL; i++) {
        if (nodus_chain_config_derive_witness_id(g_k[i].pk, g_vaddr[i]) != 0)
            return -1;
        g_vflag[i] = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    return 0;
}

/* SYSFUND call: in_count ‖ nullifier ‖ out_count 0 */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64]) {
    dst[0] = 1;
    memcpy(dst + 1, nul, 64);
    dst[65] = 0;
    return 66u;
}

/* ══ A. the table ════════════════════════════════════════════════════ */

/* the rt_owns_runtime_op scan (nodus_witness_v2_apply.c — static there) */
static int owns(const nodus_domain_runtime_t *rt, uint32_t op) {
    const dna_ruleset_desc_t *d = &rt->descriptor;
    for (size_t i = 0; i < d->rule_count; i++) {
        if (d->rule_ids[i] == op) return 1;
        if (d->rule_ids[i] > op) break;
    }
    return 0;
}

static int t_table(void) {
    const uint32_t OP = DNA_SYSRULE_ROTATE_CONSENSUS_KEY;
    CHECK(OP == 10u, "the retired ROTATE id stays reserved as 10");

    for (uint32_t g = 1; g <= NODUS_RT_GEN_STORAGE; g++) {
        const nodus_domain_runtime_t *s =
            nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c =
            nodus_runtime_for_generation(g, DNA_DOMAIN_CORE);
        CHECK(s && c, "generations 1..4 compiled");
        CHECK(owns(c, OP) == 0, "no CORE descriptor owns op 10");
        CHECK(owns(s, OP) == 0, "no SYSTEM descriptor owns op 10");
        uint64_t w = 0;
        CHECK(!(s->meter_policy &&
                dna_meter_op_weight(s->meter_policy, OP, &w) == 0),
              "no SYSTEM policy prices op 10");
    }
    {
        const nodus_domain_runtime_t *s4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_SYSTEM);
        CHECK(s4->ruleset_version == 9,
              "the generation-4 SYSTEM version is still 9 (the bump is "
              "the next package's)");
        CHECK(s4->descriptor.rule_count == 9, "SYSTEM v9 rules {1..9}");
        for (uint32_t i = 0; i < 9; i++)
            CHECK(s4->descriptor.rule_ids[i] == i + 1u, "ascending 1..9");
    }
    /* A2 — ⚠ RED until the next package re-pins (header) */
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "the compiled table passes its selfcheck (every pin re-derives)");
    {
        uint64_t d = 0;
        CHECK(nodus_runtime_gen4_vote_digest(&d) == 0 &&
              d == (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D,
              "the generation-4 vote D4 re-derives from the pinned hashes");
    }
    return 0;
}

/* ══ H. hook level ═══════════════════════════════════════════════════ */

typedef struct {
    uint8_t  fund[66];
    uint8_t  auth[2][AUTH1];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

/* {SYSTEM op 10 (`call`), CORE SYSFUND} — kind 1 on both legs */
static int hk_build(hk_env_t *e, const uint8_t *call, uint32_t call_len) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = DNA_SYSRULE_ROTATE_CONSENSUS_KEY;
    legs[0].hdr.ruleset_version = 9;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH1;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = e->auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = 7;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
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

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];

static void ctx_reset(uint64_t height) {
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_chain, 0x4C, sizeof(g_chain));
    memset(g_intent, 0x5D, sizeof(g_intent));
    memset(g_dig, 0x3C, sizeof(g_dig));
    g_ctx.chain_id = g_chain;
    g_ctx.global_height = height;
    g_ctx.epoch = height / E_LEN;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
    g_ctx.stake_min = SMIN;
}

static void av_k1(int key) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], g_k[key].fp, 64);
}

static nodus_rt_read_res_t g_reads[4];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* the observed §6.3 record (op 13 value) of validator `vid`: owner KO,
 * current key V0, ACTIVE, the pending fields zero; self STAKE_MIN,
 * commission 500, active since 1 */
static void row_make(uint8_t rec[V2_REC_LEN], const uint8_t vid[64]) {
    memset(rec, 0, V2_REC_LEN);
    memcpy(rec, vid, 64);
    memcpy(rec + V2_OWNER_OFF, g_k[KO].fp, 64);
    memcpy(rec + V2_CPK_OFF, g_k[V0].pk, PK_LEN);
    put64(rec + V2_SELF_OFF, SMIN);
    rec[V2_COMM_OFF] = 0x01;
    rec[V2_COMM_OFF + 1] = 0xF4;                       /* 500 bps         */
    rec[V2_STAT_OFF] = (uint8_t)DNAC_VALIDATOR_ACTIVE;
    put64(rec + V2_SINCE_OFF, 1);
}

static int t_hooks(void) {
    static hk_env_t e;
    static uint8_t call[OP10_LEN];
    static uint8_t row[V2_REC_LEN];
    uint8_t vid[64];
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    const uint64_t H = 9;

    /* the removed ROTATE layout (validator_id ‖ new_pk ‖ consent_sig ‖
     * expiry), filled with a plausible validator_id and key: nothing of
     * it is parsed any more */
    memset(vid, 0x2A, sizeof(vid));
    memset(call, 0x5A, sizeof(call));
    memcpy(call, vid, 64);
    memcpy(call + 64, g_k[KN].pk, PK_LEN);
    put64(call + 64 + PK_LEN + SIG_LEN, H + 100);
    CHECK(hk_build(&e, call, OP10_LEN) == 0, "an op-10 envelope");
    row_make(row, vid);
    ctx_reset(H);

    /* ── H1. SYSTEM: NULL and generations 1..4 refuse op 10 (-1) ────── */
    for (uint32_t g = 0; g <= NODUS_RT_GEN_STORAGE; g++) {
        const nodus_domain_runtime_t *s =
            g ? nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM) : NULL;
        CHECK(g == 0 || s != NULL, "the SYSTEM runtime");
        uint16_t n = 0;
        size_t rl = 0;
        av_k1(KO);                                  /* the row's owner    */
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;                     /* the committed row  */
        g_reads[0].value_len = V2_REC_LEN;
        memcpy(g_reads[0].value, row, V2_REC_LEN);
        CHECK(nodus_rt_system_read_plan(s, &e.view, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == -1,
              "op 10's read plan refuses (-1), every generation");
        CHECK(nodus_rt_system_exec(s, &e.view, 0, &g_ctx, g_reads, 2, g_res,
                                   sizeof(g_res), &rl) == -1,
              "op 10's exec refuses (-1), every generation — the owner "
              "signing, the row present");
    }

    /* ── H2. CORE SYSFUND does not pair with an op-10 sibling ───────── */
    for (uint32_t g = NODUS_RT_GEN_EVM; g <= NODUS_RT_GEN_STORAGE; g++) {
        const nodus_domain_runtime_t *c =
            nodus_runtime_for_generation(g, DNA_DOMAIN_CORE);
        CHECK(c != NULL, "the CORE runtime");
        uint16_t n = 0;
        size_t rl = 0;
        CHECK(nodus_rt_core_read_plan(c, &e.view, 1, &g_ctx, rq,
                                      NODUS_RT_MAX_READS, &n) == -1,
              "the SYSFUND plan refuses an op-10 sibling (-1)");
        memset(g_reads, 0, sizeof(g_reads));
        CHECK(nodus_rt_core_exec(c, &e.view, 1, &g_ctx, g_reads, 0, g_res,
                                 sizeof(g_res), &rl) == -1,
              "the SYSFUND exec refuses an op-10 sibling (-1)");
    }

    /* ── H3. the describer ─────────────────────────────────────────── */
    {
        nodus_rt_leg_desc_t d;
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == -1,
              "an op-10 leg is not described (no applied leg carries it)");
    }
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

/* every coin is KO's: S* fund a STAKE (bond STAKE_MIN + FEE), R* an
 * admission probe or the UNSTAKE (exactly FEE — neither locks anything) */
enum { S1, S2, S3, S4, R1, R2, R3, N_COINS };
static uint8_t  g_nul[N_COINS][64];
static uint64_t g_amt[N_COINS];

#define H9   2u
#define HE   3u
#define H14  4u       /* param 18: the gen-4 edge runs in block H14 − 1 */

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[KO].hex, 128);
    memset(pre + 128, 0x61 + c, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coin(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_bind_text(st, 2, g_k[KO].hex, 128, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_bind_int64(st, 3, (sqlite3_int64)g_amt[c]) == SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_bind_int64(st, 1, (sqlite3_int64)param) == SQLITE_OK &&
        sqlite3_bind_int64(st, 2, (sqlite3_int64)value) == SQLITE_OK &&
        sqlite3_bind_int64(st, 3, (sqlite3_int64)effective) == SQLITE_OK &&
        sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce) == SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* a pre-HF-6 validators row of key `k`: `status`, bond `self` */
static int seed_val(nodus_witness_t *w, int k, uint8_t status,
                    uint64_t self) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PK_LEN);
    v.self_stake = self;
    v.commission_bps = 500;
    v.status = status;
    v.active_since_block = 1;
    memcpy(v.unstake_destination_fp, g_k[k].hex, 129);
    return nodus_validator_insert(w, &v);
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));          /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_rotate_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x6E, sizeof(fx->chain16));
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
               H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, H14, 13) != 0)
        return -1;
    uint64_t total = 0;
    for (int i = 0; i < N_VAL; i++) {
        if (seed_val(w, i, (uint8_t)DNAC_VALIDATOR_ACTIVE, TEN_M) != 0)
            return -1;
        total += TEN_M;
    }
    /* not a real genesis: a pre-HF-6 RETIRED (graduated) row — UNSTAKED,
     * its bond already released (self 0) */
    if (seed_val(w, VU, (uint8_t)DNAC_VALIDATOR_UNSTAKED, 0) != 0) return -1;
    for (int c = 0; c < N_COINS; c++) {
        if (seed_coin(w, c) != 0) return -1;
        total += g_amt[c];
    }
    {
        /* not a real genesis: a non-zero reward pool (the test_v2_econ
         * device) and spendable coins; supply = bonds + coins + pool */
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, %llu)",
                 (unsigned long long)(total + RPOOL),
                 (unsigned long long)(total + RPOOL),
                 (unsigned long long)RPOOL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS | V2X_SEED_NOT_REAL_STATUSES);
    return v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, NULL);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
    if (h > 1) {
        b->cmt.votes_address = (const uint8_t (*)[32])g_vaddr;
        b->cmt.votes_block_id_flag = g_vflag;
        b->cmt.votes_len = N_VAL;
    }
}

/* the self-check core (nodus_witness_v2_keyres_diff): the number of
 * differences, or -1 when it did not compare (rc != 0) */
static long kr_diff(nodus_witness_t *w) {
    size_t n = 0;
    if (nodus_witness_v2_keyres_diff(w, &n) != 0) return -1;
    return (long)n;
}

/* every generation-4 boundary apply_both commits: the self-check compares
 * (rc 0) and finds no difference; below generation 4 it must answer "not
 * applicable" (rc 1). 0 / -1. */
static int g_kr_runs = 0;      /* boundaries the self-check compared at */
static int kr_boundary(nodus_witness_t *w, uint64_t h) {
    size_t n = 0;
    int rc = nodus_witness_v2_keyres_diff(w, &n);
    if (rc == 1) return 0;
    if (rc != 0 || n != 0) {
        fprintf(stderr, "boundary %llu: key-reservation self-check rc %d, "
                "%zu difference(s)\n", (unsigned long long)h, rc, n);
        return -1;
    }
    g_kr_runs++;
    return 0;
}

/* one block on both twins (0 or 1 envelope); the item codes agree and the
 * committed global roots agree; at an epoch boundary the self-check finds
 * no difference on either twin. *code = the item's code. 0 / -1. */
static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const uint8_t *env, size_t len, uint32_t *code) {
    nodus_v2_envelope_t v[1] = { { env, len } };
    nodus_v2_tx_result_t ra[1], rb[1];
    nodus_v2_block_t ba, bb;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, env ? v : NULL, env ? 1 : 0);
    mk_block(&bb, h, env ? v : NULL, env ? 1 : 0);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 1;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 1;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0) {
        fprintf(stderr, "block %llu: %s | %s\n", (unsigned long long)h,
                ba.out_reason, bb.out_reason);
        return -1;
    }
    if (env && ra[0].code != rb[0].code) return -1;
    if (code) *code = env ? ra[0].code : 0;
    uint8_t ca[64], cb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        memcmp(ca, cb, 64) != 0) {
        fprintf(stderr, "block %llu: twin global roots differ\n",
                (unsigned long long)h);
        return -1;
    }
    if ((h % E_LEN) == 0 &&
        (kr_boundary(a->w, h) != 0 || kr_boundary(b->w, h) != 0))
        return -1;
    return 0;
}

static int run_to(fixture_t *a, fixture_t *b, uint64_t *h, uint64_t last) {
    while (*h < last) {
        if (apply_both(a, b, *h + 1, NULL, 0, NULL) != 0) return -1;
        (*h)++;
    }
    return 0;
}

/* A 2-leg {SYSTEM `op`, CORE SYSFUND} envelope against the registry's
 * CURRENT manifests, REALLY signed (two passes): the SYSTEM leg kind 1 by
 * KO, the CORE SYSFUND leg kind 1 by KO spending coin `c` entirely.
 * *intent_out (may be NULL) = the engine-derived intent_id.
 * @return 0 / -1. */
static int rec_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                   const uint8_t *call, uint32_t call_len, int c,
                   uint8_t **out, size_t *out_len, uint8_t *intent_out) {
    static uint8_t fund[66];
    static uint8_t sys_auth[AUTH1];
    static uint8_t core_auth[AUTH1];
    dna_domain_manifest_t sys, core;
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0
        || nodus_witness_v2_chain_id(w, chain32) != 0)
        return -1;
    uint32_t fl = fund_call(fund, g_nul[c]);
    memset(sys_auth, 0, sizeof(sys_auth));
    memset(core_auth, 0, sizeof(core_auth));

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH1;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = sys_auth;
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH1;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = core_auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys.ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core.ruleset_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        size_t sl = 0;
        sys_auth[0] = 1;
        memcpy(sys_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(sys_auth + 1 + PK_LEN, &sl, pf->auth_digest[0],
                           64, g_k[KO].sk) != 0)
            break;
        core_auth[0] = 1;
        memcpy(core_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(core_auth + 1 + PK_LEN, &sl, pf->auth_digest[1],
                           64, g_k[KO].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (intent_out) memcpy(intent_out, pf->intent_id, 64);
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* the generation-4 STAKE call (owner KO, key `ckey`, bond STAKE_MIN,
 * commission 300) with its op-1 consent signed by `ckey` — test_hf6_stake's
 * layout. @return STK_LEN / 0. */
static uint32_t stake2_call(uint8_t *dst, const uint8_t chain32[32],
                            int ckey, uint64_t expiry) {
    static const uint8_t zero_subj[64] = { 0 };
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    if (dna_valbind_consent_msg(msg, chain32, DNA_VALBIND_OP_STAKE,
                                zero_subj, g_k[KO].fp, g_k[ckey].pk,
                                expiry) != 0)
        return 0;
    size_t sl = 0;
    if (dna_valbind_consent_sign(dst + 64 + PK_LEN, &sl, msg,
                                 g_k[ckey].sk) != 0 || sl != SIG_LEN)
        return 0;
    memcpy(dst, g_k[KO].fp, 64);
    memcpy(dst + 64, g_k[ckey].pk, PK_LEN);
    size_t off = 64 + PK_LEN + SIG_LEN;
    put64(dst + off, expiry);         off += 8;
    dst[off++] = 0x01;
    dst[off++] = 0x2C;                                 /* 300 bps         */
    put64(dst + off, SMIN);           off += 8;
    return off == STK_LEN ? STK_LEN : 0;
}

/* the independent §6.2 recomputation: SHA3-512("NDS.VALID.v1" + 4 × 0x00
 * ‖ chain32 ‖ intent_id) */
static int vid_expect(const uint8_t chain32[32], const uint8_t intent[64],
                      uint8_t out[64]) {
    uint8_t pre[16 + 32 + 64];
    memset(pre, 0, 16);
    memcpy(pre, "NDS.VALID.v1", 12);
    memcpy(pre + 16, chain32, 32);
    memcpy(pre + 48, intent, 64);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* SHA3-512 over the ledger tables' rows in key order — the state a
 * refused item must leave untouched */
static int ledger_digest(nodus_witness_t *w, uint8_t out[64]) {
    static const char *const q[] = {
        "SELECT * FROM validators ORDER BY pubkey_hash",
        "SELECT * FROM v2_validator_roles ORDER BY validator_id",
        "SELECT * FROM v2_consensus_keys ORDER BY consensus_pk_hash",
        "SELECT * FROM delegations ORDER BY delegator_hash, validator_hash",
        "SELECT * FROM utxo_set ORDER BY nullifier",
        "SELECT * FROM supply_tracking ORDER BY id",
        "SELECT * FROM validator_stats ORDER BY key",
    };
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    int ok = 0;
    for (size_t i = 0; i < sizeof(q) / sizeof(q[0]) && ok == 0; i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, q[i], -1, &st, NULL) != SQLITE_OK) {
            ok = -1;
            break;
        }
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && ok == 0) {
            int nc = sqlite3_column_count(st);
            for (int c = 0; c < nc && ok == 0; c++) {
                int t = sqlite3_column_type(st, c);
                const void *p = NULL;
                int n = 0;
                sqlite3_int64 iv = 0;
                if (t == SQLITE_INTEGER) {
                    iv = sqlite3_column_int64(st, c);
                    p = &iv;
                    n = (int)sizeof(iv);
                } else if (t != SQLITE_NULL) {
                    p = sqlite3_column_blob(st, c);
                    n = sqlite3_column_bytes(st, c);
                }
                size_t need = len + 1 + 4 + (size_t)n;
                if (need > cap) {
                    size_t nc2 = cap;
                    while (nc2 < need) nc2 *= 2;
                    uint8_t *g = realloc(buf, nc2);
                    if (!g) { ok = -1; break; }
                    buf = g;
                    cap = nc2;
                }
                buf[len++] = (uint8_t)t;
                buf[len++] = (uint8_t)(n >> 24);
                buf[len++] = (uint8_t)(n >> 16);
                buf[len++] = (uint8_t)(n >> 8);
                buf[len++] = (uint8_t)n;
                if (n > 0 && p) memcpy(buf + len, p, (size_t)n);
                len += (size_t)n;
            }
        }
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) ok = -1;
        sqlite3_finalize(st);
    }
    if (ok == 0 && qgp_sha3_512(buf, len, out) != 0) ok = -1;
    free(buf);
    return ok;
}

/* the first column of `sql` (blob ?1 = `b1`/`l1` when b1) as a u64 */
static int q_u64(nodus_witness_t *w, const char *sql, const uint8_t *b1,
                 int l1, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (b1 && sqlite3_bind_blob(st, 1, b1, l1, SQLITE_TRANSIENT) !=
                  SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* rows of utxo_set holding coin `c`: 1 unspent / 0 spent / -1 error */
static int coin_count(nodus_witness_t *w, int c) {
    uint64_t n = 0;
    if (q_u64(w, "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?1",
              g_nul[c], 64, &n) != 0)
        return -1;
    return (int)n;
}

/* the reservation of `pk`: 0 found (vid, role) / 1 absent / -1 */
static int key_of(nodus_witness_t *w, const uint8_t *pk, uint8_t vid[64],
                  uint8_t *role) {
    uint8_t kh[64];
    if (qgp_sha3_512(pk, PK_LEN, kh) != 0) return -1;
    return nodus_validator_v2_key_get(w, kh, vid, role);
}

/* one SYSTEM-`op` block expected REFUSED with item code `want`, the ledger
 * tables untouched and the funding coin unspent */
static int env_refused(fixture_t *A, fixture_t *B, uint64_t h, uint32_t op,
                       const uint8_t *call, uint32_t len, int coin,
                       uint32_t want) {
    uint8_t *e = NULL, d0[64], d1[64];
    size_t l = 0;
    uint32_t code = 0;
    if (rec_env(A->w, h, op, call, len, coin, &e, &l, NULL) != 0)
        return -1;
    int ok = ledger_digest(A->w, d0) == 0 &&
             apply_both(A, B, h, e, l, &code) == 0 && code == want &&
             ledger_digest(A->w, d1) == 0 && memcmp(d0, d1, 64) == 0 &&
             coin_count(A->w, coin) == 1;
    if (!ok)
        fprintf(stderr, "block %llu: item code %u (want %u)\n",
                (unsigned long long)h, code, want);
    free(e);
    return ok ? 0 : -1;
}

/* one envelope block on both twins, expected APPLIED: 0 / -1 */
static int env_ok(fixture_t *A, fixture_t *B, uint64_t h, uint32_t op,
                  const uint8_t *call, uint32_t len, int coin,
                  uint8_t *intent) {
    uint8_t *e = NULL;
    size_t l = 0;
    uint32_t code = 0;
    if (rec_env(A->w, h, op, call, len, coin, &e, &l, intent) != 0)
        return -1;
    int ok = apply_both(A, B, h, e, l, &code) == 0 &&
             code == NODUS_V2_TX_OK;
    free(e);
    return ok ? 0 : -1;
}

/* `sql` (blob ?1 = b1/l1, blob ?2 = b2/l2 when given) inside a fresh
 * transaction on `w`, then the self-check core, then ROLLBACK. *n_out =
 * kr_diff (or -1 when it did not compare). 0 / -1 (setup). */
static int kr_probe(nodus_witness_t *w, const char *sql,
                    const uint8_t *b1, int l1, const uint8_t *b2, int l2,
                    long *n_out) {
    *n_out = -2;
    if (sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) !=
            SQLITE_OK)
        return -1;
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) == SQLITE_OK &&
             (!b1 || sqlite3_bind_blob(st, 1, b1, l1, SQLITE_TRANSIENT) ==
                         SQLITE_OK) &&
             (!b2 || sqlite3_bind_blob(st, 2, b2, l2, SQLITE_TRANSIENT) ==
                         SQLITE_OK) &&
             sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) == 1;
    if (st) sqlite3_finalize(st);
    if (ok) *n_out = kr_diff(w);
    if (sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    return ok ? 0 : -1;
}

static int t_engine(void) {
    fixture_t A, B;
    static uint8_t call[STK_LEN];
    uint8_t intent[64], chain32[DNA_CHAIN_ID_LEN];
    uint8_t vid_a[64], vid_c[64], vid_u[64], got[64], role = 0;
    uint64_t h = 0, x = 0;
    const int kr0 = g_kr_runs;

    CHECK(E_LEN >= 12, "no epoch boundary among heights 1..11");
    for (int c = 0; c < N_COINS; c++) g_amt[c] = FEE;
    g_amt[S1] = SMIN + FEE;
    g_amt[S2] = SMIN + FEE;
    g_amt[S3] = SMIN + FEE;
    g_amt[S4] = SMIN + FEE;
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");
    CHECK(dna_validator_id_migrated(vid_u, chain32, g_k[VU].pk) == 0,
          "VU's migrated validator_id");

    /* the removed ROTATE layout, naming V0's migrated id and KN: refused
     * at admission before a byte of it is read */
    {
        static uint8_t op10[OP10_LEN];
        uint8_t vid0[64];
        CHECK(dna_validator_id_migrated(vid0, chain32, g_k[V0].pk) == 0,
              "V0's migrated validator_id");
        memset(op10, 0x5A, sizeof(op10));
        memcpy(op10, vid0, 64);
        memcpy(op10 + 64, g_k[KN].pk, PK_LEN);
        put64(op10 + 64 + PK_LEN + SIG_LEN, HE + 100);

        /* ── B1. block 3 (generation 3): refused at ADMISSION ──────── */
        CHECK(run_to(&A, &B, &h, HE - 1) == 0, "blocks 1..2");
        uint8_t *e = NULL;
        size_t l = 0;
        uint32_t code = 0;
        CHECK(rec_env(A.w, HE, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, op10,
                      OP10_LEN, R1, &e, &l, NULL) == 0,
              "an op-10 envelope at block 3");
        CHECK(apply_both(&A, &B, HE, e, l, &code) == 0 &&
              code == NODUS_V2_TX_ERR_ADMISSION,
              "generation 3: op 10 is refused at admission (unowned)");
        free(e);
        h = HE;
        /* block 3 also runs the generation-4 edge (the migration rewrites
         * the validator tables): the refused envelope's coin is what must
         * survive */
        CHECK(coin_count(A.w, R1) == 1,
              "the refused envelope's funding coin is unspent");

        /* ── B2. the edge reserved EVERY row's key, UNSTAKED included ─ */
        CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_consensus_keys", NULL, 0,
                    &x) == 0 && x == N_VAL + 1,
              "eight reservations: the seven bonded rows AND the UNSTAKED "
              "VU (khan decision item 4: the edge seeds every status)");
        CHECK(key_of(A.w, g_k[VU].pk, got, &role) == 0 &&
              memcmp(got, vid_u, 64) == 0 && role == NODUS_V2_KEY_ROLE_ACTIVE,
              "VU's key reserved to its migrated validator_id, role 1");
        CHECK(kr_diff(A.w) == 0 && kr_diff(B.w) == 0,
              "the self-check core: 0 differences after the edge");

        /* ── B3. block 4 (generation 4): op 10 refused at ADMISSION ─── */
        memcpy(op10 + 0, vid0, 64);
        put64(op10 + 64 + PK_LEN + SIG_LEN, H14 + 100);
        CHECK(env_refused(&A, &B, H14, DNA_SYSRULE_ROTATE_CONSENSUS_KEY,
                          op10, OP10_LEN, R2, NODUS_V2_TX_ERR_ADMISSION)
                  == 0,
              "generation 4: op 10 is refused at admission (owned by no "
              "descriptor), the ledger tables byte-identical, the coin "
              "unspent");
        h = H14;
    }

    /* ── B4. block 5: STAKE V_A (KC1); block 6: its UNSTAKE ────────── */
    CHECK(stake2_call(call, chain32, KC1, 5 + 100) == STK_LEN, "STAKE call");
    CHECK(env_ok(&A, &B, 5, DNA_SYSRULE_STAKE, call, STK_LEN, S1, intent)
              == 0, "block 5: the STAKE of V_A applies");
    CHECK(vid_expect(chain32, intent, vid_a) == 0, "V_A's validator_id");
    h = 5;
    memcpy(call, vid_a, 64);
    CHECK(env_ok(&A, &B, 6, DNA_SYSRULE_UNSTAKE, call, UNS_LEN, R3, NULL)
              == 0, "block 6: V_A's UNSTAKE applies");
    h = 6;
    CHECK(q_u64(A.w, "SELECT status FROM validators WHERE pubkey_hash = ?1",
                vid_a, 64, &x) == 0 && x == DNAC_VALIDATOR_RETIRING,
          "V_A RETIRING");

    /* ── B5. block 7: VU's (pre-HF-6 retired) key cannot be STAKEd ─── */
    CHECK(stake2_call(call, chain32, VU, 7 + 100) == STK_LEN, "STAKE call");
    CHECK(env_refused(&A, &B, 7, DNA_SYSRULE_STAKE, call, STK_LEN, S4,
                      NODUS_V2_TX_ERR_EXEC) == 0,
          "block 7: a STAKE under VU's key (UNSTAKED before the edge) is "
          "REFUSED, the ledger byte-identical");
    h = 7;

    /* ── B6. boundary E: V_A graduates, its reservation is KEPT ────── */
    CHECK(run_to(&A, &B, &h, E_LEN) == 0, "to the boundary E");
    CHECK(q_u64(A.w, "SELECT status FROM validators WHERE pubkey_hash = ?1",
                vid_a, 64, &x) == 0 && x == DNAC_VALIDATOR_UNSTAKED,
          "V_A graduated at E (UNSTAKED)");
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 0 &&
          memcmp(got, vid_a, 64) == 0 && role == NODUS_V2_KEY_ROLE_ACTIVE,
          "KC1's reservation KEPT after the graduation (permanent)");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_consensus_keys", NULL, 0,
                &x) == 0 && x == N_VAL + 2,
          "nine reservations: one per validators row");
    CHECK(g_kr_runs >= kr0 + 2,
          "the boundary self-check compared on both twins at E");

    /* ── B7. E + 1: KC1 (graduated) cannot be STAKEd again ──────────── */
    CHECK(stake2_call(call, chain32, KC1, E_LEN + 50) == STK_LEN,
          "STAKE call");
    CHECK(env_refused(&A, &B, E_LEN + 1, DNA_SYSRULE_STAKE, call, STK_LEN,
                      S3, NODUS_V2_TX_ERR_EXEC) == 0,
          "E + 1: a STAKE re-using the graduated V_A's key is REFUSED, the "
          "ledger byte-identical, the coin unspent");
    h = E_LEN + 1;
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM validators WHERE pubkey = ?1",
                g_k[KC1].pk, (int)PK_LEN, &x) == 0 && x == 1,
          "one row holds KC1: the UNSTAKED V_A");

    /* ── B8. E + 2: a FRESH key — a new validator — applies ─────────── */
    CHECK(stake2_call(call, chain32, KC2, E_LEN + 50) == STK_LEN,
          "STAKE call");
    CHECK(env_ok(&A, &B, E_LEN + 2, DNA_SYSRULE_STAKE, call, STK_LEN, S2,
                 intent) == 0,
          "E + 2: a STAKE under a fresh key applies (a new validator)");
    h = E_LEN + 2;
    CHECK(vid_expect(chain32, intent, vid_c) == 0 &&
          memcmp(vid_c, vid_a, 64) != 0, "a NEW validator_id");
    CHECK(key_of(A.w, g_k[KC2].pk, got, &role) == 0 &&
          memcmp(got, vid_c, 64) == 0 && role == NODUS_V2_KEY_ROLE_ACTIVE,
          "KC2 reserved to the new validator");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_consensus_keys", NULL, 0,
                &x) == 0 && x == N_VAL + 3,
          "ten reservations: one per validators row");
    CHECK(kr_diff(A.w) == 0 && kr_diff(B.w) == 0,
          "the self-check core: 0 differences");

    /* ── K. the self-check core on single-row corruptions (A, rolled
     *       back each time) ────────────────────────────────────────── */
    {
        uint8_t kh1[64], khc[64], khn[64];
        long n = -2;
        static const char text64[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        CHECK(qgp_sha3_512(g_k[KC1].pk, PK_LEN, kh1) == 0 &&
              qgp_sha3_512(g_k[KC2].pk, PK_LEN, khc) == 0 &&
              qgp_sha3_512(g_k[KN].pk, PK_LEN, khn) == 0, "key hashes");

        CHECK(kr_probe(A.w, "DELETE FROM v2_consensus_keys WHERE "
                       "consensus_pk_hash = ?1", kh1, 64, NULL, 0, &n) == 0
              && n == 1,
              "K: the graduated V_A's reservation deleted -> 1 (missing)");
        CHECK(kr_probe(A.w, "INSERT INTO v2_consensus_keys (consensus_pk_hash,"
                       " validator_id, role) VALUES (?1, ?2, 1)", khn, 64,
                       vid_a, 64, &n) == 0 && n == 1,
              "K: a reservation no validators row derives -> 1 (extra)");
        CHECK(kr_probe(A.w, "UPDATE v2_consensus_keys SET validator_id = ?2 "
                       "WHERE consensus_pk_hash = ?1", khc, 64, vid_a, 64,
                       &n) == 0 && n == 1,
              "K: KC2's row naming another validator -> 1");
        CHECK(kr_probe(A.w, "UPDATE v2_consensus_keys SET role = 2 WHERE "
                       "consensus_pk_hash = ?1", khc, 64, NULL, 0, &n) == 0
              && n == 1,
              "K: a role-2 row on a derived key -> 1 (role 1 only)");
        {
            char sql[256];
            snprintf(sql, sizeof(sql), "INSERT INTO v2_consensus_keys "
                     "(consensus_pk_hash, validator_id, role) VALUES "
                     "('%s', ?1, 1)", text64);
            CHECK(kr_probe(A.w, sql, vid_a, 64, NULL, 0, &n) == 0 && n == 1,
                  "K: a 64-character TEXT consensus_pk_hash -> 1 "
                  "(malformed: the storage class is checked)");
            snprintf(sql, sizeof(sql), "INSERT INTO v2_consensus_keys "
                     "(consensus_pk_hash, validator_id, role) VALUES "
                     "(?1, '%s', 1)", text64);
            CHECK(kr_probe(A.w, sql, khn, 64, NULL, 0, &n) == 0 && n == 1,
                  "K: a 64-character TEXT validator_id -> 1 (malformed)");
        }
        CHECK(kr_probe(A.w, "UPDATE v2_validator_roles SET "
                       "consensus_key_effective_epoch = 1 WHERE "
                       "validator_id = ?1", vid_c, 64, NULL, 0, &n) == 0 &&
              n == -1,
              "K: a non-zero pending field -> the core does not compare "
              "(the strict reader refuses the row)");
        CHECK(kr_diff(A.w) == 0, "rolled back: 0 differences");
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0,
              "the probes rolled back: A is byte-identical to B");
    }

    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    CHECK(keys_make() == 0, "keys");
    if (t_table() != 0) return 1;
    if (t_hooks() != 0) return 1;
    if (t_engine() != 0) return 1;
    printf("test_hf6_rotate: %d checks passed (self-check compared at %d "
           "boundaries)\n", g_checks, g_kr_runs);
    return 0;
}
