/**
 * @file nodus/tests/test_hf4_names_engine.c
 * @brief HF-4 part A2 — NAME_REGISTER through the ENGINE: the v2_names
 *        per-open DDL check, and registrations applied end to end on a
 *        generation-2 chain (state, pool, name_root, twin determinism,
 *        refusals, the CheckTx owner key, the address index row).
 *
 * Design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.7, §2;
 * decision docs/plans/decisions/2026-10-02-onchain-names.md items 2-6,
 * 10, 11, 16; fee destination docs/plans/decisions/2026-09-22-nodus-
 * tokenomics-v3-operator.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. DDL check (nodus_witness.c witness_v2_names_ddl_check, reached by
 *     nodus_witness_create_chain_db's production open path): a fresh
 *     chain DB opens and carries v2_names; a v2_names of the same name
 *     but another shape (no CHECKs, no UNIQUE) makes the open REFUSE (-1,
 *     no handle); a DROPPED v2_names is re-created by the base schema and
 *     the open succeeds (control: the check refuses a wrong shape, not
 *     every reopen).
 *  B. ENGINE, twin fixtures A and B (same seed, same genesis — the "every
 *     node" stand-in), production runtimes, HF-2 on from 1, param 9 (D2)
 *     effective H = 4 committed at genesis, eight coins seeded for three
 *     keys. Every block below is applied to BOTH with the SAME envelope
 *     bytes, and after each block the two committed global roots are
 *     equal AND each equals a fresh recomputation.
 *       block 2 (generation 1): a registration built against the
 *         generation-1 CORE manifest is NOT applied; v2_names stays empty
 *         (and the CheckTx dry run refuses it too).
 *       block 3 (= H-1): the switch (test_hf4_switch's subject) — idle.
 *       before block 4: the CheckTx dry run of key 1's "punk" admits it
 *         (rc 0, code OK) and reports the NAME CREATE key and the
 *         synthetic OWNER key (CORE, op 6, fp1); a second registration by
 *         key 1 ("bios") reports the SAME owner key — the key the mempool
 *         conflicts on (one registration per owner per node).
 *       block 4 (= H): key 1 registers "punk": code OK; the v2_names row
 *         is (punk, fp1, 4) with BLOB/BLOB/INTEGER storage; the input is
 *         gone; the change coin exists; the reward pool rose by EXACTLY
 *         fee + price (no burn). On fixture A only the address index is ON
 *         for this block: one "name" row on fp1 with amount = the price —
 *         and A's global root still equals B's (the index is out of every
 *         root).
 *       after block 4: the dry run of key 2's "punk" is refused (EXEC).
 *       block 5: key 2 "punk" (taken) and key 1 "bios" (key 1 already
 *         holds a name) are both refused in EXEC; v2_names unchanged.
 *       block 6: key 2 "bios" applies; key 3 "bios" in the SAME block,
 *         after it, is refused (first wins — the read sees the earlier
 *         item's CREATE).
 *     Finally the names leg is bound into the CORE root: changing one
 *     registered_height or deleting the rows (inside a rolled-back
 *     transaction) moves nodus_witness_core_root_v2, and the rollback
 *     restores it.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build; DNAC_EPOCH_LENGTH must be
 * > 8 (no epoch boundary among heights 1..6 — checked; true for the
 * production 720 and the harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf4_names_engine_* directory per fixture, removed at the
 * end (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The genesis is SEEDED with spendable UTXOs (V2X_SEED_NOT_REAL_UTXOS),
 *    a state the real derivation never writes.
 *  - "Twin" is two fixtures in one process built from the same seed; it
 *    proves the engine's answer is a function of (state, block bytes), not
 *    a 7-machine run. The Genesis Protocol harness is the latter.
 *  - Refusals are asserted by item code and by the v2_names / root
 *    observations, NOT by a whole-database digest (v2x_db_digest /
 *    v2x_ledger_digest — which order a WITHOUT ROWID table such as
 *    v2_names by its primary key, v2x_digest_select_sql). No FAULT case
 *    is driven here.
 *  - The generation-1 attempt at block 2 asserts only "not applied"
 *    (whatever refusal class the gen-1 lane picks); the distinct CheckTx
 *    "generation not in force" code (nodus_witness_cmt_app.c) is NOT
 *    driven — CheckTx itself is not called here, only its dry-run seam.
 *  - A refused registration leaves its coin today (the engine does not
 *    yet charge a failed item — decision 2026-09-25-failed-tx-pays-fee.md
 *    is approved, not implemented); every case below uses its own coin,
 *    so none depends on that.
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
#include "witness/nodus_witness_addr_index.h"
#include "server/nodus_server.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
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
#define P4      ((uint64_t)DNAC_NAME_PRICE_4P_DEFAULT)
#define CHG     700000000ULL
#define OUT_LEN 232u              /* NODUS_V2_SPEND_OUT_LEN              */
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define OP_NAME     5u            /* nodus_witness_rt_native.c, static   */
#define OP_NAMEOWN  6u

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk) — the verdict signer fp */
    char    hex[129];
} nm_key_t;

static nm_key_t g_k[3];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < 3; i++) {
        uint8_t seed[32];
        memset(seed, 0x61 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, QGP_DSA87_PUBLICKEYBYTES, g_k[i].fp)
            != 0)
            return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* ══ A. the per-open DDL check ═══════════════════════════════════════ */

static void rmrf_dir(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int raw_exec(const char *path, const char *sql) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK)
        rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (db) sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

static int t_ddl_check(void) {
    char dir[96], path[256];
    uint8_t cid[16];
    memset(cid, 0xD5, sizeof(cid));
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "alloc");
    snprintf(dir, sizeof(dir), "/tmp/test_hf4_names_engine_ddl_XXXXXX");
    CHECK(mkdtemp(dir) != NULL, "mkdtemp");
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    {
        char hex[33];
        for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", cid[i]);
        snprintf(path, sizeof(path), "%s/witness_%s.db", dir, hex);
    }

    CHECK(nodus_witness_create_chain_db(w, cid) == 0 && w->db,
          "a fresh chain DB opens");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM sqlite_master "
                                 "WHERE type='table' AND name='v2_names'",
                                 -1, &st, NULL) == SQLITE_OK, "prepare");
        int ok = sqlite3_step(st) == SQLITE_ROW &&
                 sqlite3_column_int(st, 0) == 1;
        sqlite3_finalize(st);
        CHECK(ok, "the base schema created v2_names");
    }
    sqlite3_close(w->db);
    w->db = NULL;

    /* the same name, another shape */
    CHECK(raw_exec(path, "DROP TABLE v2_names; CREATE TABLE v2_names("
                   "name BLOB NOT NULL PRIMARY KEY, owner BLOB NOT NULL, "
                   "registered_height INTEGER NOT NULL) WITHOUT ROWID")
              == 0, "tamper the table");
    CHECK(nodus_witness_create_chain_db(w, cid) == -1 && w->db == NULL,
          "a v2_names of another shape refuses the open");

    /* dropped: the base schema re-creates it, the open succeeds */
    CHECK(raw_exec(path, "DROP TABLE v2_names") == 0, "drop the table");
    CHECK(nodus_witness_create_chain_db(w, cid) == 0 && w->db,
          "an absent v2_names is re-created (control)");
    sqlite3_close(w->db);
    free(w);
    rmrf_dir(dir);
    return 0;
}

/* ══ B. the engine fixture ═══════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

/* The seeded coins: (key, seed byte, amount). Nullifier = SHA3-512(
 * owner_hex128 ‖ seed32) — the output-identity derivation. */
typedef struct { int key; uint8_t seed; uint64_t amount; } coin_def_t;
enum { C1A, C1B, C1C, C2A, C2B, C3A, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [C1A] = { 0, 0xC1, P4 + FEE + CHG },   /* key 1 "punk" at 4        */
    [C1B] = { 0, 0xC2, P4 + FEE },         /* key 1 "bios" at 5 (owns) */
    [C1C] = { 0, 0xC3, P4 + FEE },         /* key 1 "gena" at 2 (gen 1)*/
    [C2A] = { 1, 0xD1, P4 + FEE },         /* key 2 "punk" at 5 (taken)*/
    [C2B] = { 1, 0xD2, P4 + FEE },         /* key 2 "bios" at 6        */
    [C3A] = { 2, 0xE1, P4 + FEE },         /* key 3 "bios" at 6 (2nd)  */
};
static uint8_t g_nul[N_COINS][64];

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[COINS[c].key].hex, 128);
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
    sqlite3_bind_text(st, 2, g_k[COINS[c].key].hex, 128, SQLITE_TRANSIENT);
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

/* HF-2 on from 1, param 9 (D2) effective `h9`, the coins — all BEFORE
 * the engine genesis (test_hf4_switch.c fx_open + test_v2_spend_build.c
 * chain_open). */
static int fx_open(fixture_t *fx, const char *tag, uint64_t h9) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf4_names_engine_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x35, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0)
        return -1;
    if (cc_row(fx->w, DNAC_CFG_RULESET_GEN2, D2, h9, 12) != 0) return -1;
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

/* One single-input registration of `name` by key `k` spending coin `c`
 * (change CHG back to the key when the coin carries it), built against
 * the registry's CURRENT CORE manifest and REALLY signed by the key over
 * the engine-derived leg digest at `height` (the cc_env_build two-pass of
 * test_hf4_switch.c; the units from nodus_v2_spend_ceiling, as nodus-cli
 * `name register` sizes them). @return 0 / -1. */
static int reg_env(nodus_witness_t *w, uint64_t height, int k, int c,
                   const char *name, uint8_t **out, size_t *out_len) {
    static uint8_t call[1 + 36 + 8 + 1 + 64 + 1 + OUT_LEN];
    static uint8_t auth[AUTH_LEN];
    const size_t nl = strlen(name);
    const uint64_t change = COINS[c].amount - FEE - P4;
    const uint32_t n_out = change > 0 ? 1u : 0u;
    dna_domain_manifest_t core;
    const nodus_domain_runtime_t *sys = NULL;

    *out = NULL;
    if (nl < 3 || nl > 36) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    /* the units are priced under the GENERATION-2 SYSTEM policy ALWAYS —
     * a client builds a registration against the generation-2 pins; the
     * generation-1 policy has no op-8 weight, so a block-2 envelope could
     * not even be sized under it, and the generation-1 refusal must
     * happen inside the chain, which is what block 2 tests */
    sys = nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    if (!sys || !sys->meter_policy)
        return -1;

    size_t off = 0;
    call[off++] = (uint8_t)nl;
    memcpy(call + off, name, nl);       off += nl;
    put64(call + off, P4);              off += 8;
    call[off++] = 1;
    memcpy(call + off, g_nul[c], 64);   off += 64;
    call[off++] = (uint8_t)n_out;
    if (n_out) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + c), sizeof(seed));
        nodus_v2_xfer_out_put(call + off, g_k[k].hex, change, NULL, seed);
        off += OUT_LEN;
    }

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id       = DNA_DOMAIN_CORE;
    leg.hdr.runtime_op      = DNA_CORERULE_NAME_REGISTER;
    leg.hdr.ruleset_version = core.ruleset_version;
    leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len        = (uint32_t)off;
    leg.hdr.auth_len        = AUTH_LEN;
    /* the exact result size: n_in + n_out + 2 effects (restated from the
     * effect codec, independently of nodus-cli t8_name_effect_decl) */
    leg.hdr.res_max_effects = 1u + n_out + 2u;
    leg.hdr.res_max_effect_bytes =
        (uint32_t)DNA_EFFECT_FIXED_HEAD +
        (uint32_t)DNA_EFFECT_RECORD_LEN * leg.hdr.res_max_effects +
        n_out * (64u + 284u) + ((uint32_t)nl + 72u) + (1u + 8u) + 64u;
    leg.call_data = call;
    memset(auth, 0, sizeof(auth));
    leg.auth_data = auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.leg_count  = 1;
    in.legs       = &leg;
    uint64_t units = 0;
    if (nodus_v2_spend_ceiling(&in, sys->meter_policy, 1u + 3u, &units) != 0)
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
        auth[0] = 1;
        memcpy(auth + 1, g_k[k].pk, QGP_DSA87_PUBLICKEYBYTES);
        size_t sl = 0;
        if (qgp_dsa87_sign(auth + 1 + QGP_DSA87_PUBLICKEYBYTES, &sl,
                           pf->auth_digest[0], 64, g_k[k].sk) != 0)
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

/* ── observations ───────────────────────────────────────────────────── */

static int count_q(nodus_witness_t *w, const char *sql, sqlite3_int64 *n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int pool_of(nodus_witness_t *w, uint64_t *out) {
    sqlite3_int64 v = -1;
    if (count_q(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
                &v) != 0 || v < 0)
        return -1;
    *out = (uint64_t)v;
    return 0;
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

static int change_live(nodus_witness_t *w, int k, uint64_t amount) {
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "owner = ?1 AND amount = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, g_k[k].hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)amount);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* the v2_names row of `name`: 1 found (owner, height, storage types
 * blob/blob/integer), 0 absent, -1 error / wrong storage */
static int name_row(nodus_witness_t *w, const char *name, uint8_t owner[64],
                    uint64_t *h) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT owner, registered_height, "
                           "typeof(name), typeof(owner), "
                           "typeof(registered_height) FROM v2_names WHERE "
                           "name = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, name, (int)strlen(name), SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64 &&
               strcmp((const char *)sqlite3_column_text(st, 2), "blob") == 0 &&
               strcmp((const char *)sqlite3_column_text(st, 3), "blob") == 0 &&
               strcmp((const char *)sqlite3_column_text(st, 4),
                      "integer") == 0) {
        memcpy(owner, sqlite3_column_blob(st, 0), 64);
        *h = (uint64_t)sqlite3_column_int64(st, 1);
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* committed == fresh on both, and A == B */
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

/* apply the same block to both fixtures; codes out (from A; B must
 * agree) */
static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const nodus_v2_envelope_t *envs, size_t n,
                      uint32_t *codes) {
    /* each block its OWN results array — the fixture's default (v2x_res)
     * is one process-global array, which would make the A/B comparison
     * below compare an array with itself */
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

/* the CheckTx dry-run seam over one envelope */
static int dry(nodus_witness_t *w, const uint8_t *env, size_t len,
               nodus_v2_env_dry_run_t *d) {
    char reason[256];
    reason[0] = '\0';
    memset(d, 0, sizeof(*d));
    return nodus_witness_v2_env_dry_run(w, env, len, NULL, d, reason,
                                        sizeof(reason));
}

static int dry_has_row(const nodus_v2_env_dry_run_t *d, uint32_t op,
                       const uint8_t *key, uint16_t key_len) {
    int n = 0;
    for (size_t i = 0; i < d->n_rows; i++)
        if (d->rows[i].domain_id == DNA_DOMAIN_CORE &&
            d->rows[i].op_id == op && d->rows[i].key_len == key_len &&
            memcmp(d->rows[i].key, key, key_len) == 0)
            n++;
    return n;
}

static int t_engine(void) {
    fixture_t A, B;
    const uint64_t H = 4;
    uint32_t codes[2];
    uint8_t *e1 = NULL, *e2 = NULL;
    size_t l1 = 0, l2 = 0;
    uint8_t own[64];
    uint64_t rh = 0, pool0 = 0, pool1 = 0;
    sqlite3_int64 n = -1;

    CHECK(E_LEN > 8, "no epoch boundary among heights 1..6");
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin ids");
    CHECK(fx_open(&A, "a", H) == 0 && fx_open(&B, "b", H) == 0,
          "twin seeded chains (HF-2 on, vote at 4, coins)");
    CHECK(roots_agree(&A, &B) == 0, "the twins start identical");

    /* block 1 idle */
    CHECK(apply_both(&A, &B, 1, NULL, 0, NULL) == 0, "block 1");

    /* block 2 — generation 1: a registration is not applied */
    CHECK(reg_env(A.w, 2, 0, C1C, "gena", &e1, &l1) == 0,
          "a registration against the generation-1 manifest");
    {
        nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
        CHECK(d != NULL, "alloc");
        int rc = dry(A.w, e1, l1, d);
        nodus_witness_v2_env_dry_run_free(d);
        free(d);
        CHECK(rc == -1, "the dry run refuses it under generation 1");
    }
    {
        nodus_v2_envelope_t env[1] = { { e1, l1 } };
        CHECK(apply_both(&A, &B, 2, env, 1, codes) == 0, "block 2");
        CHECK(codes[0] != NODUS_V2_TX_OK, "not applied under generation 1");
        CHECK(count_q(A.w, "SELECT COUNT(*) FROM v2_names", &n) == 0 &&
              n == 0, "v2_names still empty");
    }
    free(e1); e1 = NULL;

    /* block 3 = H-1, the switch */
    CHECK(apply_both(&A, &B, 3, NULL, 0, NULL) == 0, "block 3 (the switch)");

    /* the dry run before block 4: admitted, NAME + OWNER keys */
    CHECK(reg_env(A.w, H, 0, C1A, "punk", &e1, &l1) == 0, "punk by key 1");
    CHECK(reg_env(A.w, H, 0, C1B, "bios", &e2, &l2) == 0, "bios by key 1");
    {
        nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
        nodus_v2_env_dry_run_t *d2 = calloc(1, sizeof(*d2));
        CHECK(d && d2, "alloc");
        int rc = dry(A.w, e1, l1, d);
        int rc2 = dry(A.w, e2, l2, d2);
        int ok = rc == 0 && d->code == NODUS_V2_TX_OK &&
                 dry_has_row(d, OP_NAME, (const uint8_t *)"punk", 4) == 1 &&
                 dry_has_row(d, OP_NAMEOWN, g_k[0].fp, 64) == 1;
        int same = rc2 == 0 &&
                   dry_has_row(d2, OP_NAMEOWN, g_k[0].fp, 64) == 1;
        nodus_witness_v2_env_dry_run_free(d);
        nodus_witness_v2_env_dry_run_free(d2);
        free(d);
        free(d2);
        CHECK(ok, "admitted; the NAME CREATE key and the synthetic OWNER "
              "key (CORE, op 6, fp1) reported");
        CHECK(same, "a second registration by the same key reports the "
              "SAME owner key — the mempool conflict key");
    }
    free(e2); e2 = NULL;

    /* block 4 = H: key 1 registers "punk"; the address index on A only */
    CHECK(pool_of(A.w, &pool0) == 0, "pool before");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    CHECK(srv != NULL, "alloc");
    srv->config.addr_history_index = true;
    nodus_witness_host_t host;
    nodus_server_witness_host(srv, &host);
    A.w->host = &host;
    CHECK(nodus_witness_addr_index_migrate(A.w) == 0, "index tables");
    {
        nodus_v2_envelope_t env[1] = { { e1, l1 } };
        int rc = apply_both(&A, &B, H, env, 1, codes);
        A.w->host = NULL;
        CHECK(rc == 0, "block 4 on both; roots agree (index out of roots)");
        CHECK(codes[0] == NODUS_V2_TX_OK, "the registration applies");
    }
    free(srv);
    free(e1); e1 = NULL;
    CHECK(name_row(A.w, "punk", own, &rh) == 1 &&
          memcmp(own, g_k[0].fp, 64) == 0 && rh == H,
          "v2_names (punk, fp1, 4) — BLOB / BLOB / INTEGER");
    CHECK(name_row(B.w, "punk", own, &rh) == 1 &&
          memcmp(own, g_k[0].fp, 64) == 0 && rh == H, "and on the twin");
    CHECK(coin_live(A.w, g_nul[C1A]) == 0, "the input is spent");
    CHECK(change_live(A.w, 0, CHG) == 1, "the change coin exists");
    CHECK(pool_of(A.w, &pool1) == 0 && pool1 == pool0 + FEE + P4,
          "the reward pool rose by EXACTLY fee + price");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db, "SELECT owner, amount FROM "
                                 "addr_history WHERE h = 4 AND kind = 'name'",
                                 -1, &st, NULL) == SQLITE_OK, "prepare");
        int rows = 0, good = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            rows++;
            if (sqlite3_column_bytes(st, 0) == 64 &&
                memcmp(sqlite3_column_blob(st, 0), g_k[0].fp, 64) == 0 &&
                (uint64_t)sqlite3_column_int64(st, 1) == P4)
                good++;
        }
        sqlite3_finalize(st);
        CHECK(rows == 1 && good == 1,
              "one address-index 'name' row on fp1, amount = the price");
    }

    /* after block 4: key 2's "punk" is refused by the dry run */
    CHECK(reg_env(A.w, 5, 1, C2A, "punk", &e1, &l1) == 0, "punk by key 2");
    {
        nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
        CHECK(d != NULL, "alloc");
        int rc = dry(A.w, e1, l1, d);
        uint32_t code = d->code;
        nodus_witness_v2_env_dry_run_free(d);
        free(d);
        CHECK(rc == -1 && code == NODUS_V2_TX_ERR_EXEC,
              "a taken name: refused in EXEC (a verdict, not a fault)");
    }

    /* block 5: taken name + an owner who already holds one */
    CHECK(reg_env(A.w, 5, 0, C1B, "bios", &e2, &l2) == 0, "bios by key 1");
    {
        nodus_v2_envelope_t env[2] = { { e1, l1 }, { e2, l2 } };
        CHECK(apply_both(&A, &B, 5, env, 2, codes) == 0, "block 5");
        CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC, "key 2 'punk': taken");
        CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC, "key 1 'bios': one per ID");
        CHECK(count_q(A.w, "SELECT COUNT(*) FROM v2_names", &n) == 0 &&
              n == 1, "v2_names unchanged");
        CHECK(name_row(A.w, "punk", own, &rh) == 1 &&
              memcmp(own, g_k[0].fp, 64) == 0 && rh == H,
              "punk still key 1's, height 4");
    }
    free(e1); e1 = NULL;
    free(e2); e2 = NULL;

    /* block 6: key 2 "bios" applies; key 3 "bios" after it is refused */
    CHECK(reg_env(A.w, 6, 1, C2B, "bios", &e1, &l1) == 0, "bios by key 2");
    CHECK(reg_env(A.w, 6, 2, C3A, "bios", &e2, &l2) == 0, "bios by key 3");
    {
        nodus_v2_envelope_t env[2] = { { e1, l1 }, { e2, l2 } };
        CHECK(apply_both(&A, &B, 6, env, 2, codes) == 0, "block 6");
        CHECK(codes[0] == NODUS_V2_TX_OK, "the first 'bios' applies");
        CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
              "the second 'bios' of the same block: first wins");
        CHECK(name_row(A.w, "bios", own, &rh) == 1 &&
              memcmp(own, g_k[1].fp, 64) == 0 && rh == 6,
              "bios = (fp2, 6)");
        CHECK(coin_live(A.w, g_nul[C2B]) == 0, "the applied item's input "
              "is spent");
    }
    free(e1); e1 = NULL;
    free(e2); e2 = NULL;

    /* the names leg is IN the CORE root */
    {
        uint8_t r0[64], r1[64], r2[64], r3[64];
        CHECK(nodus_witness_core_root_v2(A.w, r0) == 0, "core root");
        CHECK(sqlite3_exec(A.w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                  == SQLITE_OK, "begin");
        CHECK(sqlite3_exec(A.w->db, "UPDATE v2_names SET registered_height "
                           "= registered_height + 1 WHERE name = "
                           "x'70756e6b'", NULL, NULL, NULL) == SQLITE_OK,
              "bump punk's height");
        CHECK(nodus_witness_core_root_v2(A.w, r1) == 0 &&
              memcmp(r0, r1, 64) != 0, "a leaf field moves the CORE root");
        CHECK(sqlite3_exec(A.w->db, "DELETE FROM v2_names", NULL, NULL, NULL)
                  == SQLITE_OK, "empty the table");
        CHECK(nodus_witness_core_root_v2(A.w, r2) == 0 &&
              memcmp(r0, r2, 64) != 0 && memcmp(r1, r2, 64) != 0,
              "no rows: another root again");
        CHECK(sqlite3_exec(A.w->db, "ROLLBACK", NULL, NULL, NULL)
                  == SQLITE_OK, "rollback");
        CHECK(nodus_witness_core_root_v2(A.w, r3) == 0 &&
              memcmp(r0, r3, 64) == 0, "the rollback restores it");
    }
    CHECK(roots_agree(&A, &B) == 0, "the twins end identical");

    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "v2_names_ddl_check",      t_ddl_check },
        { "register_end_to_end",     t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0) {
        fprintf(stderr, "test_hf4_names_engine: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf4_names_engine: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
