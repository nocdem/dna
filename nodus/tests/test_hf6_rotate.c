/**
 * @file nodus/tests/test_hf6_rotate.c
 * @brief HF-6 slice 6 — ROTATE_CONSENSUS_KEY (runtime_op 10): owned and
 *        priced by generation 4 only (sub-slice 6a).
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §2 (ROTATE = runtime_op 10, call validator_id[64] ‖ new_pk[2592] ‖
 * consent_sig[4627] ‖ consent_expiry u64 = 7291 B; the generation-4
 * SYSTEM descriptor {1..10}; "SYSTEM meter politikası 10'u fiyatlar"), §3
 * (khan decision A6: the descriptor versions stay SYSTEM 9 / CORE 7, the
 * hashes are re-pinned), §8; decision 2026-10-08-kurultay-14-hf6-
 * summary.md K7; plan tasks/hf6-slice6-plan.md §2 "6a".
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. TABLE (no database):
 *   A1 DNA_SYSRULE_ROTATE_CONSENSUS_KEY == 10; the generation-4 SYSTEM
 *      descriptor (still v9) owns op 10 and no earlier generation's
 *      SYSTEM or CORE descriptor does — the list rt_owns_runtime_op
 *      (nodus_witness_v2_apply.c, static) walks, restated here as the
 *      same ascending scan.
 *   A2 the generation-4 SYSTEM policy prices op 10 at weight 1; the EVM
 *      generation's does not; the compiled table passes its selfcheck
 *      (every pin and DNAC_CFG_RULESET_GEN_STORAGE_D re-derive — the
 *      oracle literals of shared/dnac/tests/storage_oracle.py).
 *   A3 the SYSTEM read plan and exec of generations 1..3 refuse op 10
 *      (-1, never -2), and so do generation 4's while op 10 is not yet
 *      executable (sub-slice 6a: the un-migrated-op default).
 *  B. ENGINE (twin seeded chains, EVM-enabled build — the test_hf6_stake
 *     fixture: V0..V6 ACTIVE 10M since 1; param 9 at 2, param 14 at 3,
 *     param 16 — the generation-4 dev trigger — at 4, so the edge runs in
 *     block 3):
 *   B1 block 3 (generation 3): a 2-leg {SYSTEM op 10, CORE SYSFUND}
 *      envelope is refused at ADMISSION (the live gate is
 *      rt_owns_runtime_op in env_admit_legs — admission inspects the
 *      runtime_op against the committed descriptor; rt_admit_common
 *      judges (tx_type, pool) only and is reached solely through
 *      nodus_witness_domreg_admit_v2, which has no production caller —
 *      so no SYS_TYPES change is involved); its funding coin stays
 *      unspent (block 3 also runs the edge, so the ledger itself moves).
 *   B2 block 4 (generation 4): the SAME envelope shape passes admission
 *      and reservation (op 10 is owned and priced) and is refused at
 *      EXEC (sub-slice 6a: not yet executable); the ledger tables are
 *      byte-identical across block 4 and the twins' databases agree.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). Environment:
 * none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_hf6_rotate_* directories, removed at the end (left behind
 * when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - A1 restates rt_owns_runtime_op's scan (the engine's is static); B
 *    is what drives the real gate.
 *  - The pinned hashes are oracle literals: selfcheck proves this build's
 *    encoder agrees with them, not that the oracle's inputs are the
 *    design's (the oracle names its sources in its docstring).
 *  - B2's call bytes are a well-formed 7291-byte frame with a zero
 *    signature: sub-slice 6a refuses op 10 before reading any of them.
 *  - B's genesis UTXOs are SEEDED (V2X_SEED_NOT_REAL_UTXOS); the reward
 *    pool is non-zero by hand (the test_v2_econ device).
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
#define RPOOL     10000000000000000ULL               /* 10^16 raw         */
#define PK_LEN    ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN   ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define AUTH1     (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define ROT_LEN   7291u           /* design §2 (K7): 64+2592+4627+8      */

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* V0..V6 the genesis committee, KO a single-key owner / funder, KC1 a
 * consensus key */
enum { V0, V1, V2, V3, V4, V5, V6, KO, KC1, N_KEYS };
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
    CHECK(OP == 10u, "ROTATE_CONSENSUS_KEY is runtime_op 10 (design §2)");
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "the compiled table passes its selfcheck (the oracle pins and "
          "the generation-4 vote literal re-derive)");

    for (uint32_t g = 1; g <= NODUS_RT_GEN_STORAGE; g++) {
        const nodus_domain_runtime_t *s =
            nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c =
            nodus_runtime_for_generation(g, DNA_DOMAIN_CORE);
        CHECK(s && c, "generations 1..4 compiled");
        CHECK(owns(c, OP) == 0, "no CORE descriptor owns op 10");
        CHECK(owns(s, OP) == (g == NODUS_RT_GEN_STORAGE),
              "only the generation-4 SYSTEM descriptor owns op 10");
        uint64_t w = 0;
        int priced = s->meter_policy &&
                     dna_meter_op_weight(s->meter_policy, OP, &w) == 0;
        CHECK(priced == (g == NODUS_RT_GEN_STORAGE),
              "only the generation-4 SYSTEM policy prices op 10");
        if (priced) CHECK(w == 1u, "at weight 1");
    }
    {
        const nodus_domain_runtime_t *s4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_CORE);
        CHECK(s4->ruleset_version == 9 && c4->ruleset_version == 7,
              "the generation-4 versions stay SYSTEM 9 / CORE 7 (A6)");
        CHECK(s4->descriptor.rule_count == 10 &&
              s4->descriptor.rule_ids[9] == OP,
              "SYSTEM v9 rules {1..10}");
        uint64_t d = 0;
        CHECK(dna_ruleset_gen_digest(NODUS_RT_GEN_STORAGE,
                                     s4->ruleset_hash, c4->ruleset_hash,
                                     DNAC_RULESET_SWITCH_SPEC_VERSION,
                                     &d) == 0 &&
              d == (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D,
              "the dev vote literal re-derives from the re-pinned hashes");
    }

    /* A3: every SYSTEM hook refuses op 10 with no executable rule */
    {
        static uint8_t call[ROT_LEN], fund[66], auth[2][AUTH1];
        static uint8_t bytes[16384];
        uint8_t nul[64];
        memset(call, 0x5A, sizeof(call));
        memset(nul, 0xA5, sizeof(nul));
        uint32_t fl = fund_call(fund, nul);
        memset(auth, 0, sizeof(auth));
        dna_env_leg_in_t legs[2];
        memset(legs, 0, sizeof(legs));
        legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
        legs[0].hdr.runtime_op = OP;
        legs[0].hdr.ruleset_version = 9;
        legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        legs[0].hdr.call_len = ROT_LEN;
        legs[0].hdr.auth_len = AUTH1;
        legs[0].hdr.res_max_effects = 8;
        legs[0].hdr.res_max_effect_bytes = 16384;
        legs[0].call_data = call;
        legs[0].auth_data = auth[0];
        legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
        legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
        legs[1].hdr.ruleset_version = 7;
        legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        legs[1].hdr.call_len = fl;
        legs[1].hdr.auth_len = AUTH1;
        legs[1].hdr.res_max_effects = 40;
        legs[1].hdr.res_max_effect_bytes = 16384;
        legs[1].call_data = fund;
        legs[1].auth_data = auth[1];
        dna_env_in_t in;
        memset(&in, 0, sizeof(in));
        in.fee_amount = FEE;
        in.res_max_total_units = 400000;
        in.leg_count = 2;
        in.legs = legs;
        size_t len = 0;
        dna_env_view_t v;
        CHECK(dna_env_encode(&in, bytes, sizeof(bytes), &len) == 0 &&
              dna_env_decode(bytes, len, &v) == 0, "an op-10 envelope");

        static uint8_t chain[DNA_CHAIN_ID_LEN], intent[64];
        static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
        nodus_rt_auth_verdict_t av;
        memset(&av, 0, sizeof(av));
        av.n_signers = 1;
        nodus_rt_exec_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.chain_id = chain;
        ctx.intent_id = intent;
        ctx.global_height = 10;
        ctx.auth = &av;
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        for (uint32_t g = 0; g <= NODUS_RT_GEN_STORAGE; g++) {
            const nodus_domain_runtime_t *s =
                g ? nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM)
                  : NULL;
            uint16_t n = 0;
            size_t rl = 0;
            CHECK(nodus_rt_system_read_plan(s, &v, 0, &ctx, rq,
                                            NODUS_RT_MAX_READS, &n) == -1,
                  "op 10's read plan refuses (-1) in every generation "
                  "(6a: not yet executable)");
            CHECK(nodus_rt_system_exec(s, &v, 0, &ctx, NULL, 0, res,
                                       sizeof(res), &rl) == -1,
                  "op 10's exec refuses (-1) in every generation");
        }
    }
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

/* coins of exactly FEE (a ROTATE locks nothing — khan decision A4) */
enum { R1, R2, N_COINS };
static uint8_t g_nul[N_COINS][64];

#define H9   2u
#define HE   3u
#define H14  4u       /* param 16: the gen-4 edge runs in block H14 − 1 */

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[KO].hex, 128);
    memset(pre + 128, 0x61 + c, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coin(nodus_witness_t *w, int c, uint64_t amount) {
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
        sqlite3_bind_int64(st, 3, (sqlite3_int64)amount) == SQLITE_OK)
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

static int seed_val(nodus_witness_t *w, int k) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PK_LEN);
    v.self_stake = TEN_M;
    v.commission_bps = 500;
    v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
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
        cc_row(w, DNAC_CFG_RULESET_GEN_STORAGE,
               (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D, H14, 13) != 0)
        return -1;
    uint64_t total = 0;
    for (int i = 0; i < N_VAL; i++) {
        if (seed_val(w, i) != 0) return -1;
        total += TEN_M;
    }
    for (int c = 0; c < N_COINS; c++) {
        if (seed_coin(w, c, FEE) != 0) return -1;
        total += FEE;
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
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
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

/* one block on both twins (0 or 1 envelope); the item codes agree and the
 * committed global roots agree. *code = the item's code. 0 / -1. */
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
 * `sys_signer`, the CORE SYSFUND leg kind 1 by KO spending coin `c`
 * entirely (exactly FEE). @return 0 / -1. */
static int rec_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                   const uint8_t *call, uint32_t call_len, int c,
                   int sys_signer, uint8_t **out, size_t *out_len) {
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
        memcpy(sys_auth + 1, g_k[sys_signer].pk, PK_LEN);
        if (qgp_dsa87_sign(sys_auth + 1 + PK_LEN, &sl, pf->auth_digest[0],
                           64, g_k[sys_signer].sk) != 0)
            break;
        core_auth[0] = 1;
        memcpy(core_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(core_auth + 1 + PK_LEN, &sl, pf->auth_digest[1],
                           64, g_k[KO].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* SHA3-512 over the ledger tables' rows in key order — the state a
 * refused leg must leave untouched */
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

/* rows of utxo_set holding coin `c`: 1 unspent / 0 spent / -1 error */
static int coin_count(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    int out = -1;
    if (sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

static int t_engine(void) {
    fixture_t A, B;
    static uint8_t call[ROT_LEN];
    uint8_t *e = NULL, d0[64], d1[64], vid0[64], chain32[DNA_CHAIN_ID_LEN];
    size_t l = 0;
    uint64_t h = 0;
    uint32_t code = 0;

    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..7");
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");
    CHECK(dna_validator_id_migrated(vid0, chain32, g_k[V0].pk) == 0,
          "V0's migrated validator_id");

    /* a well-formed 7291-byte frame naming V0, new key KC1 */
    memset(call, 0, sizeof(call));
    memcpy(call, vid0, 64);
    memcpy(call + 64, g_k[KC1].pk, PK_LEN);

    /* ── B1. block 3 (generation 3): refused at ADMISSION ──────────── */
    CHECK(run_to(&A, &B, &h, HE - 1) == 0, "blocks 1..2");
    CHECK(rec_env(A.w, HE, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                  R1, KO, &e, &l) == 0, "an op-10 envelope at block 3");
    CHECK(apply_both(&A, &B, HE, e, l, &code) == 0 &&
          code == NODUS_V2_TX_ERR_ADMISSION,
          "generation 3: op 10 is refused at admission (unowned)");
    free(e); e = NULL;
    h = HE;
    /* block 3 also runs the generation-4 edge (the migration rewrites
     * the validator tables), so no whole-ledger comparison here: the
     * refused envelope's funding coin is what must survive */
    CHECK(coin_count(A.w, R1) == 1,
          "the refused envelope's funding coin is unspent");

    /* ── B2. block 4 (generation 4): admitted, priced, refused at exec */
    CHECK(rec_env(A.w, H14, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                  R2, KO, &e, &l) == 0, "an op-10 envelope at block 4");
    CHECK(ledger_digest(A.w, d0) == 0, "ledger before");
    CHECK(apply_both(&A, &B, H14, e, l, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC,
          "generation 4: op 10 passes admission and reservation and is "
          "refused at exec (6a: not yet executable)");
    free(e); e = NULL;
    h = H14;
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "the ledger tables are byte-identical across block 4");
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
    }
    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "table_op10_owned",      t_table },
        { "engine_op10_admission", t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0) {
        fprintf(stderr, "test_hf6_rotate: key setup failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_rotate: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
