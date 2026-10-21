/**
 * @file nodus/tests/test_hf8_msig_name.c
 * @brief HF-8 rev 3 — a NAME_REGISTER authorised by a multisig vault,
 *        through the ENGINE: before and after the param-17 activation
 *        height, the CheckTx dry run (a verdict or an admission, never a
 *        node fault), the stored owner, one name per vault, vault-only
 *        funding.
 *
 * Governing records: docs/plans/decisions/2026-10-21-hf8-activation.md,
 * amendment 2026-10-21 (operator "ekle." — a NAME_REGISTER may be
 * authorised by a satisfied multisig from H, owner = the vault address;
 * operator "Yalnız kasanın parası" — a kind-3 registration is refused
 * unless EVERY input is the vault's); design docs/plans/2026-10-07-
 * delegate-name-required-design.md rev 3 item 3; Kurultay #33 (docs/plans/
 * kurultay/2026-10-21-33-hf8-stake-msig/fable-r1.md fix 2, astra-r1.md fix
 * 1: the CheckTx owner-key helper nodus_rt_core_name_owner_key must derive
 * kind 3 too, or every well-formed multisig registration FAULTs CheckTx).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 * Twin fixtures A and B (same seed, same genesis), production runtimes,
 * HF-2 on from 1, param 9 (D2) effective at 4 (generation 2 from block 4),
 * a committed param-17 (DELEGATE_NAME_REQUIRED) row = 1 effective at H =
 * 6, written into chain_config_history before genesis. A 2-of-3 vault V
 * (members K1 K2 K3, address SHA3-512(descriptor)) owns four seeded coins;
 * member K1 owns one. Every envelope is REALLY signed by K1 and K2 over the
 * engine-derived leg digest (auth_kind 3: count 2 ‖ 2 × (pk ‖ sig) ‖
 * dcount 1 ‖ dlen ‖ descriptor). Every block is applied to BOTH twins with
 * the same bytes; after each block the two committed global roots agree
 * and each equals a fresh recomputation.
 *   tip 4 (dry run at 5, flag 0): V's "vault" registration — rc -1 with
 *     code EXEC (a verdict), never -2;
 *   block 5 (flag 0): the same envelope is NOT applied; v2_names empty;
 *   tip 5 (dry run at 6 = H, flag 1): rc 0, code OK, the conflict rows
 *     carry NAME("vault") and the synthetic OWNER (CORE, op 6, V's
 *     address) — the CheckTx owner key derives the vault, no FAULT; a
 *     registration funded by a vault coin AND K1's coin: rc -1, EXEC;
 *   block 6 (= H): V registers "vault": OK; the v2_names row is (vault,
 *     V's address, 6); the input is spent; the change coin is V's;
 *   block 7: V's second registration ("vaultb") is refused (one name per
 *     ID; its dry run too), and the mixed-funding "mixed" registration is
 *     refused (over-determined here: V is named by then — the dry run at
 *     tip 5, before V held a name, is the case that isolates the
 *     vault-only funding rule); v2_names still holds exactly one row.
 *   block 8: a second vault W (2-of-2 {K1, K2}, one seeded coin) registers
 *     "wvlib" through the SHARED LIBRARY the CLI runs —
 *     nodus_v2_name_msig_build, nodus_v2_name_msig_review by member K2,
 *     two real signatures, nodus_v2_msig_combine_op(NAME_REGISTER): the dry
 *     run admits it (the library's units, fee and auth blob are what the
 *     engine accepts) with W's OWNER row, block 8 applies it, v2_names
 *     holds (wvlib, W, 8), W's coin is spent.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build; DNAC_EPOCH_LENGTH must be
 * > 8 (no epoch boundary among heights 1..8 — checked; true for the
 * production 720 and the harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf8_msig_name_* directory per fixture, removed at the end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The genesis is SEEDED with spendable UTXOs (V2X_SEED_NOT_REAL_UTXOS)
 *    and the param-17 row is written straight into chain_config_history
 *    (not voted): the vote's own rules (scalar 1, ERGONOMIC grace, the
 *    generation-2 stateful rule) are test_hf4_params.c's.
 *  - It runs at GENERATION 2 (the NAME_REGISTER owner rule is generation-
 *    2 code, rtn_name_owner); the live chain's generation 5 is the stagef
 *    scenario test_cmt_hf8_gen5.sh's. The STAKE rule (generation 4 only)
 *    is not driven here (test_hf6_stake.c A8 at hook level, the stagef
 *    scenario end to end).
 *  - "Twin" is two fixtures in one process built from the same seed — the
 *    engine's answer as a function of (state, block bytes), not a
 *    7-machine run.
 *  - CheckTx itself (nodus_witness_cmt_app.c app_check_envelope) is not
 *    called, only its dry-run seam; that the seam's -2 maps to CMT_FAULT
 *    there is read, not driven.
 *  - A refused registration leaves its coin (the engine does not yet
 *    charge a failed item); every case uses its own coins.
 *  - Written and compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_name.h"      /* the vault builder / read-back   */
#include "client/nodus_v2_msig.h"      /* combine_op, desc_from_keys      */

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/msig_wire.h"
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

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define D2      ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)
#define FEE     ((uint64_t)DNAC_MIN_FEE_RAW)
#define P5      ((uint64_t)DNAC_NAME_PRICE_5P_DEFAULT)   /* "vault" = 5 B */
#define P6      ((uint64_t)DNAC_NAME_PRICE_6P_DEFAULT)   /* "vaultb"      */
#define CHG     700000000ULL
#define OUT_LEN 232u              /* NODUS_V2_SPEND_OUT_LEN              */
#define PK_LEN  ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define SGN_LEN ((size_t)NODUS_RT_AUTH_SIGNER_LEN)
#define OP_NAME     5u            /* nodus_witness_rt_native.c, static   */
#define OP_NAMEOWN  6u
#define H9      4u                /* generation 2 from block 4           */
#define H17     6u                /* param 17 effective = H              */

/* ══ keys and the vault ══════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];
    char    hex[129];
} mk_key_t;

enum { K1, K2, K3, N_KEYS };
static mk_key_t g_k[N_KEYS];
static uint8_t  g_desc[DNA_MSIG_MAX_DESC_LEN];
static size_t   g_desc_len;
static uint8_t  g_vault[64];
static char     g_vault_hex[129];
/* W = 2-of-2 {K1, K2}: the vault whose registration the SHARED LIBRARY
 * builds (nodus_v2_name_msig_build / _review, nodus_v2_msig_combine_op) */
static uint8_t  g_wdesc[DNA_MSIG_MAX_DESC_LEN];
static size_t   g_wdesc_len;
static uint8_t  g_wvault[64];
static char     g_wvault_hex[129];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int pk_cmp(const void *a, const void *b) {
    return memcmp(a, b, PK_LEN);
}

static int keys_make(void) {
    static uint8_t keys[3 * QGP_DSA87_PUBLICKEYBYTES];
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x71 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
        memcpy(keys + (size_t)i * PK_LEN, g_k[i].pk, PK_LEN);
    }
    qsort(keys, 3, PK_LEN, pk_cmp);                /* canonical order    */
    if (dna_msig_desc_encode(2, 3, keys, g_desc, sizeof(g_desc),
                             &g_desc_len) != 0)
        return -1;
    if (dna_msig_address(g_desc, g_desc_len, g_vault) != 0) return -1;
    hex_of(g_vault, g_vault_hex);
    {
        uint8_t two[2 * QGP_DSA87_PUBLICKEYBYTES];
        memcpy(two, g_k[K1].pk, PK_LEN);
        memcpy(two + PK_LEN, g_k[K2].pk, PK_LEN);
        if (nodus_v2_msig_desc_from_keys(2, 2, two, g_wdesc, sizeof(g_wdesc),
                                         &g_wdesc_len, g_wvault)
            != NODUS_V2_SPEND_OK)
            return -1;
        hex_of(g_wvault, g_wvault_hex);
    }
    return 0;
}

/* ══ the fixture ═════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

/* coins: owner (0 = the vault V, 1 = member K1, 2 = the vault W), seed
 * byte, amount */
typedef struct { int member; uint8_t seed; uint64_t amount; } coin_def_t;
enum { VC_EARLY, VC_REG, VC_SECOND, VC_MIXED, MC_MIXED, WC_LIB, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [VC_EARLY]  = { 0, 0xA1, P5 + FEE + CHG }, /* "vault" at 5 (flag 0)  */
    [VC_REG]    = { 0, 0xA2, P5 + FEE + CHG }, /* "vault" at 6 (= H)     */
    [VC_SECOND] = { 0, 0xA3, P6 + FEE },       /* "vaultb" at 7 (2nd)    */
    [VC_MIXED]  = { 0, 0xA4, P5 },             /* "mixed": vault part    */
    [MC_MIXED]  = { 1, 0xB1, FEE },            /* "mixed": K1's part     */
    [WC_LIB]    = { 2, 0xC1, P5 + FEE + CHG }, /* W "wvlib" at 8 (lib)   */
};
static uint8_t g_nul[N_COINS][64];

static const char *coin_owner_hex(int c) {
    return COINS[c].member == 1 ? g_k[K1].hex
         : COINS[c].member == 2 ? g_wvault_hex : g_vault_hex;
}

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, coin_owner_hex(c), 128);
    memset(pre + 128, COINS[c].seed, 32);
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
    sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, coin_owner_hex(c), 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)COINS[c].amount);
    int rc = sqlite3_step(st);
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
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static void rmrf_dir(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

/* HF-2 on from 1, D2 at H9, param 17 = 1 at H17, the coins — all BEFORE
 * the engine genesis (test_hf4_names_engine.c fx_open). */
static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf8_msig_name_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x38, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0)
        return -1;
    if (cc_row(fx->w, DNAC_CFG_RULESET_GEN2, D2, H9, 12) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_DELEGATE_NAME_REQUIRED,
               DNAC_CFG_DELEGATE_NAME_REQUIRED_ON, H17, 13) != 0)
        return -1;
    for (int c = 0; c < N_COINS; c++)
        if (seed_coin(fx->w, c) != 0) return -1;
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    rmrf_dir(fx->dir);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* The kind-3 auth blob: K1 + K2 (ascending pk) sign `digest` (zero slots
 * when NULL — pass 1), one descriptor. @return its length / 0. */
static size_t k3_blob(uint8_t *dst, size_t cap, const uint8_t *digest) {
    const int ord0 = memcmp(g_k[K1].pk, g_k[K2].pk, PK_LEN) < 0 ? K1 : K2;
    const int ord1 = ord0 == K1 ? K2 : K1;
    const int ord[2] = { ord0, ord1 };
    const size_t need = 1 + 2 * SGN_LEN + 1 + 2 + g_desc_len;
    if (need > cap) return 0;
    size_t off = 0;
    dst[off++] = 2;
    for (int i = 0; i < 2; i++) {
        memcpy(dst + off, g_k[ord[i]].pk, PK_LEN);
        memset(dst + off + PK_LEN, 0, SIG_LEN);
        if (digest) {
            size_t sl = 0;
            if (qgp_dsa87_sign(dst + off + PK_LEN, &sl, digest, 64,
                               g_k[ord[i]].sk) != 0 || sl != SIG_LEN)
                return 0;
        }
        off += SGN_LEN;
    }
    dst[off++] = 1;
    dst[off++] = (uint8_t)(g_desc_len >> 8);
    dst[off++] = (uint8_t)g_desc_len;
    memcpy(dst + off, g_desc, g_desc_len);
    off += g_desc_len;
    return off == need ? off : 0;
}

/* One kind-3 registration of `name` at `price` spending coins `cs[0..n)`
 * (ascending by nullifier on the wire), change `change` back to the
 * vault, built against the registry's CURRENT CORE manifest and REALLY
 * signed by K1 + K2 over the engine-derived leg digest at `height`
 * (test_hf4_names_engine.c reg_env's two-pass). @return 0 / -1. */
static int reg_env(nodus_witness_t *w, uint64_t height, const char *name,
                   uint64_t price, const int *cs, int n, uint64_t change,
                   uint8_t **out, size_t *out_len) {
    static uint8_t call[1 + 36 + 8 + 1 + 2 * 64 + 1 + OUT_LEN];
    static uint8_t auth[1 + 2 * NODUS_RT_AUTH_SIGNER_LEN + 3 +
                        DNA_MSIG_MAX_DESC_LEN];
    const size_t nl = strlen(name);
    const uint32_t n_out = change > 0 ? 1u : 0u;
    dna_domain_manifest_t core;
    const nodus_domain_runtime_t *sys = NULL;

    *out = NULL;
    if (nl < 3 || nl > 36 || n < 1 || n > 2) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    sys = nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    if (!sys || !sys->meter_policy) return -1;

    uint8_t nul[2][64];
    for (int i = 0; i < n; i++) memcpy(nul[i], g_nul[cs[i]], 64);
    if (n == 2 && memcmp(nul[0], nul[1], 64) > 0) {
        uint8_t t[64];
        memcpy(t, nul[0], 64);
        memcpy(nul[0], nul[1], 64);
        memcpy(nul[1], t, 64);
    }
    size_t off = 0;
    call[off++] = (uint8_t)nl;
    memcpy(call + off, name, nl);       off += nl;
    put64(call + off, price);           off += 8;
    call[off++] = (uint8_t)n;
    for (int i = 0; i < n; i++) {
        memcpy(call + off, nul[i], 64);
        off += 64;
    }
    call[off++] = (uint8_t)n_out;
    if (n_out) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + cs[0]), sizeof(seed));
        nodus_v2_xfer_out_put(call + off, g_vault_hex, change, NULL, seed);
        off += OUT_LEN;
    }

    const size_t alen = k3_blob(auth, sizeof(auth), NULL);
    if (alen == 0) return -1;

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id       = DNA_DOMAIN_CORE;
    leg.hdr.runtime_op      = DNA_CORERULE_NAME_REGISTER;
    leg.hdr.ruleset_version = core.ruleset_version;
    leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
    leg.hdr.call_len        = (uint32_t)off;
    leg.hdr.auth_len        = (uint32_t)alen;
    /* the exact result size (test_hf4_names_engine.c reg_env's
     * restatement, with n inputs) */
    leg.hdr.res_max_effects = (uint32_t)n + n_out + 2u;
    leg.hdr.res_max_effect_bytes =
        (uint32_t)DNA_EFFECT_FIXED_HEAD +
        (uint32_t)DNA_EFFECT_RECORD_LEN * leg.hdr.res_max_effects +
        n_out * (64u + 284u) + ((uint32_t)nl + 72u) + (1u + 8u) +
        (uint32_t)n * 64u;
    leg.call_data = call;
    leg.auth_data = auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.leg_count  = 1;
    in.legs       = &leg;
    uint64_t units = 0;
    if (nodus_v2_spend_ceiling(&in, sys->meter_policy, (uint32_t)n + 3u,
                               &units) != 0)
        return -1;
    in.res_max_total_units = units;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = core.ruleset_version;
    memcpy(lctx.ruleset_hash, core.ruleset_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(&leg, 1, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, &lctx, 1, pf)
            != DNA_ENV_PF_OK)
            break;
        if (k3_blob(auth, sizeof(auth), pf->auth_digest[0]) != alen) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* ── observations ───────────────────────────────────────────────────── */

static int count_q(nodus_witness_t *w, const char *sql, sqlite3_int64 *n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int coin_live(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "nullifier = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int vault_coin_of(nodus_witness_t *w, uint64_t amount) {
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "owner = ?1 AND amount = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, g_vault_hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)amount);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* the v2_names row of `name`: 1 found / 0 absent / -1 error */
static int name_row(nodus_witness_t *w, const char *name, uint8_t owner[64],
                    uint64_t *h) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT owner, registered_height FROM "
                           "v2_names WHERE name = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, name, (int)strlen(name), SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(owner, sqlite3_column_blob(st, 0), 64);
        *h = (uint64_t)sqlite3_column_int64(st, 1);
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

static int roots_agree(fixture_t *a, fixture_t *b) {
    uint8_t ca[64], cb[64], fa[64], fb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        nodus_witness_global_root_v2(a->w, fa, NULL, NULL, NULL) != 0 ||
        nodus_witness_global_root_v2(b->w, fb, NULL, NULL, NULL) != 0)
        return -1;
    if (memcmp(ca, fa, 64) != 0 || memcmp(cb, fb, 64) != 0) return -1;
    return memcmp(ca, cb, 64) == 0 ? 0 : -1;
}

static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const nodus_v2_envelope_t *envs, size_t n,
                      uint32_t *codes) {
    nodus_v2_tx_result_t ra[4], rb[4];
    nodus_v2_block_t ba, bb;
    if (n > 4) return -1;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, envs, n);
    mk_block(&bb, h, envs, n);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 4;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 4;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (ra[i].code != rb[i].code) return -1;
        if (codes) codes[i] = ra[i].code;
    }
    return roots_agree(a, b);
}

/* the CheckTx dry-run seam; *code_out = the class (out->code) */
static int dry(nodus_witness_t *w, const uint8_t *env, size_t len,
               uint32_t *code_out, int *name_rows, int *owner_rows,
               const char *name) {
    char reason[256];
    reason[0] = '\0';
    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    if (!d) return -99;
    int rc = nodus_witness_v2_env_dry_run(w, env, len, NULL, d, reason,
                                          sizeof(reason));
    if (code_out) *code_out = d->code;
    int nr = 0, orow = 0;
    for (size_t i = 0; i < d->n_rows; i++) {
        if (d->rows[i].domain_id != DNA_DOMAIN_CORE) continue;
        if (name && d->rows[i].op_id == OP_NAME &&
            d->rows[i].key_len == strlen(name) &&
            memcmp(d->rows[i].key, name, strlen(name)) == 0)
            nr++;
        if (d->rows[i].op_id == OP_NAMEOWN && d->rows[i].key_len == 64 &&
            memcmp(d->rows[i].key, g_vault, 64) == 0)
            orow++;
    }
    if (name_rows) *name_rows = nr;
    if (owner_rows) *owner_rows = orow;
    nodus_witness_v2_env_dry_run_free(d);
    free(d);
    return rc;
}

static int lib_rand(void *ctx, uint8_t *buf, size_t len) {
    uint8_t *next = ctx;
    for (size_t i = 0; i < len; i++) buf[i] = (*next)++;
    return 0;
}

/* Block 8 (tip 7): W's "wvlib" from its one coin, through the shared
 * library end to end; the dry run admits it with W's owner row, block 8
 * applies it on both twins, v2_names stores W. @return 0 / 1. */
static int lib_vault_register(fixture_t *A, fixture_t *B) {
    dna_domain_manifest_t core;
    CHECK(nodus_witness_domreg_get(A->w, DNA_DOMAIN_CORE, NULL, &core, NULL)
              == 0, "the CORE manifest in force");
    const nodus_domain_runtime_t *sys =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    CHECK(sys && sys->meter_policy, "the generation-2 SYSTEM policy");
    nodus_v2_ruleset_id_t rs;
    memset(&rs, 0, sizeof(rs));
    rs.core_ruleset_version = core.ruleset_version;
    memcpy(rs.core_ruleset_hash, core.ruleset_hash, 64);
    rs.meter_policy = sys->meter_policy;

    nodus_v2_coin_t coin;
    memset(&coin, 0, sizeof(coin));
    memcpy(coin.nul, g_nul[WC_LIB], 64);
    coin.amount = COINS[WC_LIB].amount;
    uint8_t seed_next = 0x90;
    nodus_v2_name_msig_req_t req;
    memset(&req, 0, sizeof(req));
    req.rs            = &rs;
    req.chain32       = A->w->v2_chain32;
    req.tip           = 7;
    req.expiry_height = 7 + NODUS_V2_MSIG_EXPIRY_AHEAD;
    req.desc          = g_wdesc;
    req.desc_len      = g_wdesc_len;
    req.name          = "wvlib";
    req.price         = P5;
    req.coins         = &coin;
    req.n_coins       = 1;
    req.rand          = lib_rand;
    req.rand_ctx      = &seed_next;
    nodus_v2_name_msig_built_t *b = calloc(1, sizeof(*b));
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    nodus_v2_name_msig_review_t *rv = calloc(1, sizeof(*rv));
    CHECK(b && pf && rv, "alloc");
    nodus_v2_name_err_t err;
    CHECK(nodus_v2_name_msig_build(&req, b, &err) == NODUS_V2_SPEND_OK &&
          memcmp(b->addr, g_wvault, 64) == 0 && b->signers == 2,
          "the library builds W's unsigned registration");

    nodus_v2_msig_export_t x;
    memset(&x, 0, sizeof(x));
    memcpy(x.chain32, A->w->v2_chain32, DNA_CHAIN_ID_LEN);
    x.tip = 7;
    x.signers = b->signers;
    memcpy(x.digest, b->digest, 64);
    x.env = b->env;
    x.env_len = b->env_len;
    CHECK(nodus_v2_name_msig_review(&x, rs.core_ruleset_version,
                                    rs.core_ruleset_hash, g_k[K2].pk, pf, rv)
              == NODUS_V2_SPEND_OK &&
          memcmp(rv->addr, g_wvault, 64) == 0 &&
          strcmp(rv->name, "wvlib") == 0 && rv->n_out == 1,
          "a member's read-back: W, the name, W's change");

    static uint8_t pks[2][QGP_DSA87_PUBLICKEYBYTES];
    static uint8_t sigs[2][QGP_DSA87_SIGNATURE_BYTES];
    uint8_t dg[2][64];
    const int who[2] = { K1, K2 };
    for (int i = 0; i < 2; i++) {
        size_t sl = 0;
        memcpy(pks[i], g_k[who[i]].pk, PK_LEN);
        memcpy(dg[i], x.digest, 64);
        CHECK(qgp_dsa87_sign(sigs[i], &sl, x.digest, 64, g_k[who[i]].sk)
                  == 0 && sl == SIG_LEN, "member signature");
    }
    int bad = -2;
    CHECK(nodus_v2_msig_combine_op(&x, DNA_CORERULE_NAME_REGISTER,
                                   rs.core_ruleset_version,
                                   rs.core_ruleset_hash,
                                   (const uint8_t (*)[64])dg,
                                   (const uint8_t (*)[NODUS_V2_MSIG_PK_LEN])pks,
                                   (const uint8_t (*)[NODUS_V2_MSIG_SIG_LEN])
                                       sigs,
                                   2, pf, &bad) == NODUS_V2_SPEND_OK,
          "combine_op assembles the two signatures");

    uint32_t code = 0;
    int orow_w = 0;
    {
        char reason[256];
        reason[0] = '\0';
        nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
        CHECK(d != NULL, "alloc");
        int rc = nodus_witness_v2_env_dry_run(A->w, x.env, x.env_len, NULL, d,
                                              reason, sizeof(reason));
        if (rc != 0 && reason[0])
            fprintf(stderr, "  (dry run rc %d: %s)\n", rc, reason);
        code = d->code;
        for (size_t i = 0; i < d->n_rows; i++)
            if (d->rows[i].domain_id == DNA_DOMAIN_CORE &&
                d->rows[i].op_id == OP_NAMEOWN && d->rows[i].key_len == 64 &&
                memcmp(d->rows[i].key, g_wvault, 64) == 0)
                orow_w++;
        nodus_witness_v2_env_dry_run_free(d);
        free(d);
        CHECK(rc == 0 && code == NODUS_V2_TX_OK,
              "the library-built envelope is admitted (units, fee, auth)");
        CHECK(orow_w == 1, "its OWNER conflict row is W's address");
    }
    {
        nodus_v2_envelope_t env[1] = { { x.env, x.env_len } };
        uint32_t codes[1];
        CHECK(apply_both(A, B, 8, env, 1, codes) == 0, "block 8");
        CHECK(codes[0] == NODUS_V2_TX_OK, "W's registration applies");
    }
    uint8_t own[64];
    uint64_t rh = 0;
    CHECK(name_row(A->w, "wvlib", own, &rh) == 1 &&
          memcmp(own, g_wvault, 64) == 0 && rh == 8,
          "v2_names (wvlib, W, 8)");
    CHECK(coin_live(A->w, g_nul[WC_LIB]) == 0, "W's coin is spent");
    nodus_v2_name_msig_built_free(b);    /* x.env aliases b->env */
    free(b);
    free(rv);
    free(pf);
    return 0;
}

static int t_engine(void) {
    fixture_t A, B;
    uint32_t codes[2], code = 0;
    uint8_t *e1 = NULL, *e2 = NULL;
    size_t l1 = 0, l2 = 0;
    uint8_t own[64];
    uint64_t rh = 0;
    sqlite3_int64 n = -1;
    int nr = 0, orow = 0;

    CHECK(E_LEN > 8, "no epoch boundary among heights 1..8");
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin ids");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (HF-2 on, D2 at 4, param 17 at 6, coins)");
    CHECK(roots_agree(&A, &B) == 0, "the twins start identical");
    for (uint64_t h = 1; h <= 4; h++)
        CHECK(apply_both(&A, &B, h, NULL, 0, NULL) == 0, "idle block");

    /* tip 4: the dry run at 5 (flag 0) — a verdict, never a fault */
    {
        const int cs[1] = { VC_EARLY };
        CHECK(reg_env(A.w, 5, "vault", P5, cs, 1, CHG, &e1, &l1) == 0,
              "V's registration built for 5");
    }
    {
        int rc = dry(A.w, e1, l1, &code, NULL, NULL, NULL);
        CHECK(rc != -2, "flag 0: the dry run is not a node fault");
        CHECK(rc == -1 && code == NODUS_V2_TX_ERR_EXEC,
              "flag 0: refused in EXEC (a multisig name before H)");
    }
    {
        nodus_v2_envelope_t env[1] = { { e1, l1 } };
        CHECK(apply_both(&A, &B, 5, env, 1, codes) == 0, "block 5");
        CHECK(codes[0] != NODUS_V2_TX_OK, "flag 0: not applied");
        CHECK(count_q(A.w, "SELECT COUNT(*) FROM v2_names", &n) == 0 &&
              n == 0, "v2_names still empty");
        CHECK(coin_live(A.w, g_nul[VC_EARLY]) == 1, "its coin is kept");
    }
    free(e1); e1 = NULL;

    /* tip 5: the dry run at 6 = H (flag 1) — admitted, vault owner key */
    {
        const int cs[1] = { VC_REG };
        CHECK(reg_env(A.w, H17, "vault", P5, cs, 1, CHG, &e1, &l1) == 0,
              "V's registration built for 6");
    }
    {
        int rc = dry(A.w, e1, l1, &code, &nr, &orow, "vault");
        CHECK(rc != -2, "flag 1: the dry run is not a node fault (the "
              "CheckTx owner key derives the vault)");
        CHECK(rc == 0 && code == NODUS_V2_TX_OK, "flag 1: admitted");
        CHECK(nr == 1, "the NAME(\"vault\") conflict row");
        CHECK(orow == 1, "the synthetic OWNER row (CORE, op 6, the vault "
              "address)");
    }
    {
        const int cs[2] = { VC_MIXED, MC_MIXED };
        CHECK(reg_env(A.w, H17, "mixed", P5, cs, 2, 0, &e2, &l2) == 0,
              "a vault coin + K1's coin");
        int rc = dry(A.w, e2, l2, &code, NULL, NULL, NULL);
        CHECK(rc != -2, "mixed funding: not a node fault");
        CHECK(rc == -1 && code == NODUS_V2_TX_ERR_EXEC,
              "mixed funding: refused in EXEC (vault-only funding)");
    }

    /* block 6 = H: V registers "vault" */
    {
        nodus_v2_envelope_t env[1] = { { e1, l1 } };
        CHECK(apply_both(&A, &B, H17, env, 1, codes) == 0,
              "block 6 on both; roots agree");
        CHECK(codes[0] == NODUS_V2_TX_OK, "the vault registration applies");
    }
    free(e1); e1 = NULL;
    CHECK(name_row(A.w, "vault", own, &rh) == 1 &&
          memcmp(own, g_vault, 64) == 0 && rh == H17,
          "v2_names (vault, the vault address, 6)");
    CHECK(name_row(B.w, "vault", own, &rh) == 1 &&
          memcmp(own, g_vault, 64) == 0, "and on the twin");
    CHECK(memcmp(own, g_k[K1].fp, 64) != 0 &&
          memcmp(own, g_k[K2].fp, 64) != 0, "never a co-signer");
    CHECK(coin_live(A.w, g_nul[VC_REG]) == 0, "the vault coin is spent");
    CHECK(vault_coin_of(A.w, CHG) == 1, "the change is the vault's");

    /* block 7: a second name by V, and the mixed-funding one */
    {
        const int cs[1] = { VC_SECOND };
        CHECK(reg_env(A.w, 7, "vaultb", P6, cs, 1, 0, &e1, &l1) == 0,
              "V's second registration");
    }
    free(e2); e2 = NULL;
    {
        const int cs[2] = { VC_MIXED, MC_MIXED };
        CHECK(reg_env(A.w, 7, "mixed", P5, cs, 2, 0, &e2, &l2) == 0,
              "the mixed registration for 7");
    }
    {
        int rc = dry(A.w, e1, l1, &code, NULL, NULL, NULL);
        CHECK(rc == -1 && code == NODUS_V2_TX_ERR_EXEC,
              "dry run: one name per vault (a verdict)");
    }
    {
        nodus_v2_envelope_t env[2] = { { e1, l1 }, { e2, l2 } };
        CHECK(apply_both(&A, &B, 7, env, 2, codes) == 0, "block 7");
        CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC,
              "V's second name: refused (one name per ID)");
        CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
              "mixed funding: refused");
        CHECK(count_q(A.w, "SELECT COUNT(*) FROM v2_names", &n) == 0 &&
              n == 1, "v2_names holds exactly one row");
        CHECK(coin_live(A.w, g_nul[MC_MIXED]) == 1 &&
              coin_live(A.w, g_nul[VC_MIXED]) == 1,
              "the mixed item's coins are kept");
    }
    free(e1); e1 = NULL;
    free(e2); e2 = NULL;

    /* block 8: vault W's registration built by the SHARED LIBRARY (what
     * nodus-cli `name register --msig` / `msig sign` / `msig combine`
     * run), read back by a member, signed by K1 + K2, combined */
    CHECK(lib_vault_register(&A, &B) == 0,
          "the library-built vault registration lands");
    CHECK(roots_agree(&A, &B) == 0, "the twins end identical");

    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    if (keys_make() != 0) {
        fprintf(stderr, "test_hf8_msig_name: key / vault setup failed\n");
        return 1;
    }
    int rc = t_engine();
    fprintf(stderr, "%-24s %s\n", "msig_name_engine", rc == 0 ? "ok" : "FAIL");
    fprintf(stderr, "test_hf8_msig_name: %d/1 cases passed, %d checks\n",
            rc == 0 ? 1 : 0, g_checks);
    return rc == 0 ? 0 : 1;
}
