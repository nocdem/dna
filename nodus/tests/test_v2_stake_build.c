/**
 * @file nodus/tests/test_v2_stake_build.c
 * @brief The shared staking envelope builder (nodus/src/client/
 *        nodus_v2_stake.c — STAKE, DELEGATE, UNDELEGATE) against the
 *        production engine.
 *
 * Governing records: docs/plans/decisions/2026-09-25-web-wallet-nodus-send-
 * transport.md ("İşlem kurucu" — the wallet builds with the SAME C code as
 * nodus-cli) and docs/plans/decisions/2026-09-28-treasury-pools-and-exact-
 * self-stake.md (the bond is EXACTLY DNAC_SELF_STAKE_AMOUNT).
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 *  K1  A STAKE, a DELEGATE (to a seeded validator) and — after that DELEGATE
 *      is applied in a block — an UNDELEGATE of the whole delegation, each
 *      built by the library with the compiled-table ruleset and a fixed key,
 *      are ADMITTED by the engine's CheckTx seam
 *      (nodus_witness_v2_env_dry_run) on a seeded version-3 chain running
 *      the PRODUCTION runtime table (rc 0, code OK), and the engine derives
 *      the builder's wire_id and intent_id. False if a leg header, a call
 *      layout, the funding arithmetic (UNDELEGATE: fee only), the ruleset
 *      binding or the signature were wrong.
 *  K2  The fields read back from the built bytes equal the request (the
 *      library's decoded struct): op, identity key, validator key / bond /
 *      commission / destination, amount, inputs, change, fee, expiry.
 *  K3  nodus-cli equivalence. `v2-envelope stake|delegate` has no builder
 *      of its own any more: it calls nodus_v2_stake_build with the
 *      compiled-table ruleset. A literal byte comparison of two envelopes
 *      is impossible because qgp_dsa87_sign is HEDGED (see
 *      test_v2_spend_build.c S4); instead:
 *        (a) both call blobs equal an independent restatement, in this
 *            file, of the pre-move cmd_v2_stake algorithm: coins filtered
 *            (zero / non-native / locked skipped), ascending by nullifier,
 *            taken until they cover lock + fee; SYSTEM call = pk ‖
 *            commission ‖ bond ‖ dest (STAKE) or pk ‖ validator ‖ amount
 *            (DELEGATE); SYSFUND call = in_count ‖ nullifiers ‖ out_count ‖
 *            one change record seeded SHA3-512(nullifiers)[0..31];
 *        (b) the leg headers (8 / 16384 and 40 / 16384 effects, kind-1, one
 *            signer), units (400 000), fee (the floor at gas price 0) and
 *            expiry (tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD − 10) equal the
 *            pre-move constants;
 *        (c) two builds from identical inputs have the same length, the same
 *            intent_id and are byte-identical outside the two auth blobs.
 *  K4  The gas-price fee: at gas price 5 the fee is 400 000 × 5 (above the
 *      floor) and the engine admits the overpaying envelope.
 *  K5  Refusals: a bond other than the self-bond, a commission above the
 *      maximum, a DELEGATE amount of 0 or above the supply, an op that is
 *      not STAKE / DELEGATE / UNDELEGATE, a 0 tip, and funding that cannot
 *      cover (no coin; only a locked coin; only a non-native coin).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (blocks at heights 1 and 2;
 * it assumes neither is an epoch boundary — true for every
 * DNAC_EPOCH_LENGTH > 2). Environment: none. SQLite >= 3.35.0 (the seeded
 * genesis fixture).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_v2_stake_build_XXXXXX directory, removed at the end; a
 * CHECK failure leaves it behind (this tree's fixture convention).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The genesis is SEEDED (v2_genesis_fixture.h TIER B) with spendable
 *     genesis UTXOs (V2X_SEED_NOT_REAL_UTXOS), one of them larger than the
 *     self-bond — a state the real derivation never writes.
 *  2. The dry run is CheckTx's per-item seam; the node's separate
 *     `expiry > tip + 100` gate is not called here — the library's own
 *     expiry refusal is tested instead (K5).
 *  3. The chain's gas price is 0 (the seeded document): K4 proves the
 *     builder's arithmetic and that an overpaying fee is admitted, not that
 *     the engine would demand exactly that fee.
 *  4. K3 is NOT a byte comparison with a running nodus-cli (that needs a
 *     node over the network); the restatement in this file is what replaces
 *     it, and it was written by the same author as the library.
 *  5. The STAKE and the UNDELEGATE are only dry-run (never applied); only
 *     the DELEGATE is applied in a block, so the UNDELEGATE has a row.
 *  6. Written, compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"    /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_produce.h"   /* v2_tip_height             */
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_stake.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"

#include "v2_genesis_fixture.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

#define KB_FLOOR   (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                        ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE)
#define KB_EXPIRY_AHEAD ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
#define KB_N_COINS 4
/* coin amounts: one covers the self-bond, one a minimum delegation, two
 * small ones cover a fee */
static const uint64_t KB_AMT[KB_N_COINS] = {
    DNAC_SELF_STAKE_AMOUNT + 10000000ULL,
    2ULL * DNAC_MIN_DELEGATION,
    5000000ULL,
    5000000ULL
};
#define KB_COMMISSION 1200u

/* ══ fixed keys ══════════════════════════════════════════════════════ */

static uint8_t g_pk[2592], g_sk[4896];
static char    g_fp[QGP_FP_HEX_BUFFER];
static uint8_t g_fp_raw[64];

static int keys_init(void) {
    uint8_t seed[32];
    memset(seed, 0x5E, sizeof(seed));
    if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) return -1;
    if (qgp_sha3_512(g_pk, sizeof(g_pk), g_fp_raw) != 0) return -1;
    qgp_fp_raw_to_hex(g_fp_raw, g_fp);
    return 0;
}

/* ══ the chain ═══════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          file16[16];
    uint8_t          chain32[32];
    uint64_t         tip;
    uint8_t          nul[KB_N_COINS][64];
    uint8_t          validator_pk[2592];   /* a seeded, bonded validator */
} kb_chain_t;

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

/* One CORE utxo owned by the key; nullifier = SHA3-512(owner128 ‖ seed32)
 * (test_v2_spend_build.c seed_coin). */
static int seed_coin(kb_chain_t *c, uint64_t amount, uint8_t seed_byte,
                     uint8_t nul_out[64]) {
    uint8_t seed[32], pre[160];
    memset(seed, seed_byte, sizeof(seed));
    memcpy(pre, g_fp, 128);
    memcpy(pre + 128, seed, 32);
    if (qgp_sha3_512(pre, sizeof(pre), nul_out) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul_out, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_fp, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* the lowest-pubkey seeded validator (the document's own committee) */
static int first_validator(kb_chain_t *c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->w->db,
            "SELECT pubkey FROM validators ORDER BY pubkey LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == (int)sizeof(c->validator_pk)) {
        memcpy(c->validator_pk, sqlite3_column_blob(st, 0),
               sizeof(c->validator_pk));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int chain_open(kb_chain_t *c) {
    memset(c, 0, sizeof(*c));
    c->w = calloc(1, sizeof(*c->w));
    if (!c->w) return -1;
    c->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(c->dir, sizeof(c->dir), "/tmp/test_v2_stake_build_XXXXXX");
    if (!mkdtemp(c->dir)) return -1;
    snprintf(c->w->data_path, sizeof(c->w->data_path), "%s", c->dir);
    memset(c->file16, 0x6B, sizeof(c->file16));
    if (v2x_seed_prepare(c->w, c->file16, 0) != 0) return -1;
    for (int i = 0; i < KB_N_COINS; i++)
        if (seed_coin(c, KB_AMT[i], (uint8_t)(0xB1 + i), c->nul[i]) != 0)
            return -1;
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(c->w, c->file16, 0, NULL, 0, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(c->w, c->chain32) != 0) return -1;
    if (first_validator(c) != 0) return -1;

    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = 1;
    b.epoch = nodus_v2_epoch_for_height(1);
    if (v2x_cmt_apply_ok(c->w, &b) != 0) return -1;
    return nodus_witness_v2_tip_height(c->w, &c->tip) == 0 && c->tip == 1
               ? 0 : -1;
}

static void chain_close(kb_chain_t *c) {
    if (c->w) {
        if (c->w->db) sqlite3_close(c->w->db);
        free(c->w);
        c->w = NULL;
    }
    if (c->dir[0]) rmrf(c->dir);
}

static int dry(nodus_witness_t *w, const uint8_t *env, size_t len,
               uint32_t *code, uint8_t wire_id[64], uint8_t intent_id[64]) {
    char reason[256];
    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    if (!d) return -100;
    reason[0] = '\0';
    int rc = nodus_witness_v2_env_dry_run(w, env, len, NULL, d, reason,
                                          sizeof(reason));
    *code = d->code;
    memcpy(wire_id, d->wire_id, 64);
    memcpy(intent_id, d->intent_id, 64);
    if (rc != 0 && reason[0])
        fprintf(stderr, "  (dry run rc %d: %s)\n", rc, reason);
    nodus_witness_v2_env_dry_run_free(d);
    free(d);
    return rc;
}

/* ══ helpers ═════════════════════════════════════════════════════════ */

static void table_ruleset(nodus_v2_stake_ruleset_t *rs) {
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    memset(rs, 0, sizeof(*rs));
    for (size_t i = 0; i < n; i++) {
        if (t[i].domain_id == DNA_DOMAIN_CORE) {
            rs->core_ruleset_version = t[i].ruleset_version;
            memcpy(rs->core_ruleset_hash, t[i].ruleset_hash, 64);
        } else if (t[i].domain_id == DNA_DOMAIN_SYSTEM) {
            rs->sys_ruleset_version = t[i].ruleset_version;
            memcpy(rs->sys_ruleset_hash, t[i].ruleset_hash, 64);
        }
    }
}

static int coins_of(const kb_chain_t *c, nodus_v2_stake_coin_t *coins) {
    memset(coins, 0, KB_N_COINS * sizeof(coins[0]));
    for (int i = 0; i < KB_N_COINS; i++) {
        memcpy(coins[i].nul, c->nul[i], 64);
        coins[i].amount = KB_AMT[i];
    }
    return KB_N_COINS;
}

static void base_req(nodus_v2_stake_req_t *r,
                     const nodus_v2_stake_ruleset_t *rs, const kb_chain_t *c,
                     nodus_v2_stake_op_t op, uint64_t amount,
                     const nodus_v2_stake_coin_t *coins, int n_coins) {
    memset(r, 0, sizeof(*r));
    r->rs             = rs;
    r->op             = op;
    r->chain32        = c->chain32;
    r->tip            = c->tip;
    r->expiry_height  = c->tip + KB_EXPIRY_AHEAD;
    r->pk             = g_pk;
    r->sk             = g_sk;
    r->amount         = amount;
    r->commission_bps = KB_COMMISSION;
    r->dest_fp        = g_fp_raw;
    r->validator_pk   = op == NODUS_V2_STAKE_OP_STAKE ? NULL : c->validator_pk;
    r->coins          = coins;
    r->n_coins        = n_coins;
}

/* ── the pre-move cmd_v2_stake algorithm, restated ─────────────────── */

typedef struct {
    uint8_t  nulls[NODUS_V2_SPEND_MAX_IN][64];
    int      n_in;
    uint64_t sum_in, change;
} kb_sel_t;

static int nul_cmp(const void *a, const void *b) { return memcmp(a, b, 64); }

/* eligible (amount > 0, native, unlock <= tip) nullifiers ascending, taken
 * until they cover `need` (at most 15) */
static int restate_select(const nodus_v2_stake_coin_t *coins, int n,
                          uint64_t tip, uint64_t need, kb_sel_t *s) {
    static const uint8_t zero64[64] = {0};
    typedef struct { uint8_t nul[64]; uint64_t amt; } row_t;
    row_t rows[16];
    int m = 0;
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < n && m < 16; i++) {
        if (coins[i].amount == 0 ||
            memcmp(coins[i].token, zero64, 64) != 0 ||
            coins[i].unlock_block > tip) continue;
        memcpy(rows[m].nul, coins[i].nul, 64);
        rows[m].amt = coins[i].amount;
        m++;
    }
    qsort(rows, (size_t)m, sizeof(rows[0]), nul_cmp);
    for (int i = 0; i < m && s->sum_in < need && s->n_in < 15; i++) {
        memcpy(s->nulls[s->n_in++], rows[i].nul, 64);
        s->sum_in += rows[i].amt;
    }
    if (s->sum_in < need) return -1;
    s->change = s->sum_in - need;
    return 0;
}

/* the SYSFUND call the pre-move CLI wrote for this selection */
static size_t restate_fund_call(const kb_sel_t *s, uint8_t *out) {
    size_t off = 0;
    out[off++] = (uint8_t)s->n_in;
    for (int i = 0; i < s->n_in; i++) { memcpy(out + off, s->nulls[i], 64); off += 64; }
    out[off++] = s->change > 0 ? 1 : 0;
    if (s->change > 0) {
        uint8_t seed_full[64];
        if (qgp_sha3_512((const uint8_t *)s->nulls, (size_t)s->n_in * 64,
                         seed_full) != 0) return 0;
        memcpy(out + off, g_fp, 128);
        for (int i = 0; i < 8; i++)
            out[off + 128 + i] = (uint8_t)(s->change >> (56 - 8 * i));
        memset(out + off + 136, 0, 64);
        memcpy(out + off + 200, seed_full, 32);
        off += 232;
    }
    return off;
}

/* the SYSTEM call the pre-move CLI wrote */
static size_t restate_sys_call(nodus_v2_stake_op_t op, uint64_t amount,
                               const uint8_t *validator_pk, uint8_t *out) {
    memcpy(out, g_pk, 2592);
    if (op == NODUS_V2_STAKE_OP_STAKE) {
        out[2592] = (uint8_t)(KB_COMMISSION >> 8);
        out[2593] = (uint8_t)KB_COMMISSION;
        for (int i = 0; i < 8; i++) out[2594 + i] = (uint8_t)(amount >> (56 - 8 * i));
        memcpy(out + 2602, g_fp_raw, 64);
        return 2666;
    }
    memcpy(out + 2592, validator_pk, 2592);
    for (int i = 0; i < 8; i++)
        out[2 * 2592 + i] = (uint8_t)(amount >> (56 - 8 * i));
    return 5192;
}

/* K2 + K3(a)(b) on one built envelope */
static int check_layout(const nodus_v2_stake_built_t *b,
                        const nodus_v2_stake_req_t *r,
                        const nodus_v2_stake_ruleset_t *rs,
                        uint64_t want_fee) {
    const uint64_t lock = r->op == NODUS_V2_STAKE_OP_UNDELEGATE ? 0 : r->amount;
    kb_sel_t s;
    CHECK(restate_select(r->coins, r->n_coins, r->tip, lock + want_fee, &s) == 0,
          "restated selection covers lock + fee");

    /* K2 — the library's decoded struct */
    const nodus_v2_stake_decoded_t *d = &b->dec;
    CHECK(d->op == (uint32_t)r->op, "read-back op");
    CHECK(memcmp(d->identity_pk, g_pk, 2592) == 0, "read-back identity key");
    CHECK(d->amount == r->amount, "read-back amount / bond");
    CHECK(d->fee == want_fee && b->fee == want_fee, "read-back fee");
    CHECK(d->units == NODUS_V2_STAKE_UNITS, "read-back units = 400000");
    CHECK(d->expiry_height == r->tip + KB_EXPIRY_AHEAD, "read-back expiry");
    CHECK(d->sys_ruleset_version == rs->sys_ruleset_version &&
          d->core_ruleset_version == rs->core_ruleset_version,
          "read-back ruleset versions");
    CHECK(d->n_in == s.n_in && b->n_in == s.n_in &&
          memcmp(d->in_nul, s.nulls, (size_t)s.n_in * 64) == 0,
          "read-back inputs = the restated selection");
    CHECK(b->sum_in == s.sum_in && b->change == s.change, "sum and change");
    CHECK(d->n_out == (s.change > 0 ? 1 : 0), "read-back change count");
    if (s.change > 0)
        CHECK(memcmp(d->change_owner, g_fp, 128) == 0 &&
              d->change_amount == s.change, "read-back change record");
    if (r->op == NODUS_V2_STAKE_OP_STAKE)
        CHECK(d->commission_bps == KB_COMMISSION &&
              memcmp(d->dest_fp, g_fp_raw, 64) == 0,
              "read-back commission + destination");
    else
        CHECK(memcmp(d->validator_pk, r->validator_pk, 2592) == 0,
              "read-back validator key");

    /* K3(a)(b) — an INDEPENDENT parse against the restated CLI */
    dna_env_view_t *v = calloc(1, sizeof(*v));
    uint8_t *want_s = calloc(1, 5192);
    uint8_t *want_f = calloc(1, 2 + 15 * 64 + 232);
    CHECK(v && want_s && want_f, "alloc");
    CHECK(dna_env_decode(b->env, b->env_len, v) == 0 && v->leg_count == 2,
          "two legs");
    CHECK(v->leg[0].domain_id == DNA_DOMAIN_SYSTEM &&
          v->leg[0].runtime_op == (uint32_t)r->op &&
          v->leg[0].ruleset_version == rs->sys_ruleset_version &&
          v->leg[0].res_max_effects == 8 &&
          v->leg[0].res_max_effect_bytes == 16384,
          "leg0 = SYSTEM record, 8 / 16384");
    CHECK(v->leg[1].domain_id == DNA_DOMAIN_CORE &&
          v->leg[1].runtime_op == DNA_CORERULE_SYSFUND &&
          v->leg[1].ruleset_version == rs->core_ruleset_version &&
          v->leg[1].res_max_effects == 40 &&
          v->leg[1].res_max_effect_bytes == 16384,
          "leg1 = CORE SYSFUND, 40 / 16384");
    for (int L = 0; L < 2; L++)
        CHECK(v->leg[L].access_mode == DNA_ENV_ACCESS_INVOKE &&
              v->leg[L].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
              v->leg[L].auth_len == 1u + NODUS_RT_AUTH_SIGNER_LEN,
              "INVOKE, kind-1, one signer");
    CHECK(v->res_max_total_units == 400000u && v->fee_amount == want_fee &&
          v->expiry_height == r->tip + KB_EXPIRY_AHEAD,
          "units / fee / expiry = the pre-move constants");
    size_t sl = restate_sys_call(r->op, r->amount, r->validator_pk, want_s);
    CHECK(v->leg[0].call_len == sl &&
          memcmp(v->buf + v->call_off[0], want_s, sl) == 0,
          "SYSTEM call = the restated nodus-cli layout");
    size_t fl = restate_fund_call(&s, want_f);
    CHECK(fl != 0 && v->leg[1].call_len == fl &&
          memcmp(v->buf + v->call_off[1], want_f, fl) == 0,
          "SYSFUND call = the restated nodus-cli layout");
    free(want_f);
    free(want_s);
    free(v);
    return 0;
}

/* K3(c) — two builds: same length, same intent, identical outside both
 * auth blobs */
static int check_twin(const nodus_v2_stake_req_t *r,
                      const nodus_v2_stake_built_t *b1) {
    nodus_v2_stake_built_t b2;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(r, &b2, &e) == NODUS_V2_SPEND_OK, "twin build");
    CHECK(b2.env_len == b1->env_len, "twin: same length");
    CHECK(memcmp(b2.intent_id, b1->intent_id, 64) == 0, "twin: same intent_id");
    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "alloc");
    CHECK(dna_env_decode(b1->env, b1->env_len, v) == 0, "decode");
    const size_t a0 = v->auth_off[0], a1 = v->auth_off[1];
    const size_t al = 1u + NODUS_RT_AUTH_SIGNER_LEN;
    CHECK(a0 + al <= a1 && a1 + al <= b1->env_len, "auth blobs ordered");
    CHECK(memcmp(b1->env, b2.env, a0) == 0 &&
          memcmp(b1->env + a0 + al, b2.env + a0 + al, a1 - (a0 + al)) == 0 &&
          memcmp(b1->env + a1 + al, b2.env + a1 + al,
                 b1->env_len - (a1 + al)) == 0,
          "twin: byte-identical outside the two auth blobs");
    free(v);
    nodus_v2_stake_built_free(&b2);
    return 0;
}

/* ══ K1–K3 ═══════════════════════════════════════════════════════════ */

static int t_stake(kb_chain_t *c) {
    nodus_v2_stake_ruleset_t rs;
    table_ruleset(&rs);
    nodus_v2_stake_coin_t coins[KB_N_COINS];
    int n = coins_of(c, coins);
    nodus_v2_stake_req_t r;
    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_STAKE, DNAC_SELF_STAKE_AMOUNT,
             coins, n);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK, "build STAKE");
    uint32_t code = 99;
    uint8_t wid[64], iid[64];
    CHECK(dry(c->w, b.env, b.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK, "the engine admits the STAKE");
    CHECK(memcmp(wid, b.wire_id, 64) == 0 && memcmp(iid, b.intent_id, 64) == 0,
          "STAKE: the engine derives the builder's ids");
    if (check_layout(&b, &r, &rs, KB_FLOOR) != 0) return 1;
    if (check_twin(&r, &b) != 0) return 1;
    nodus_v2_stake_built_free(&b);
    return 0;
}

static int t_delegate_then_undelegate(kb_chain_t *c) {
    nodus_v2_stake_ruleset_t rs;
    table_ruleset(&rs);
    nodus_v2_stake_coin_t coins[KB_N_COINS + 1];
    int n = coins_of(c, coins);
    nodus_v2_stake_req_t r;
    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_DELEGATE, DNAC_MIN_DELEGATION,
             coins, n);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "build DELEGATE");
    uint32_t code = 99;
    uint8_t wid[64], iid[64];
    CHECK(dry(c->w, b.env, b.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK, "the engine admits the DELEGATE");
    CHECK(memcmp(wid, b.wire_id, 64) == 0 && memcmp(iid, b.intent_id, 64) == 0,
          "DELEGATE: the engine derives the builder's ids");
    if (check_layout(&b, &r, &rs, KB_FLOOR) != 0) return 1;
    if (check_twin(&r, &b) != 0) return 1;

    /* K4 — the gas-price fee on the same request */
    {
        nodus_v2_stake_req_t rg = r;
        rg.gas_price = 5;
        nodus_v2_stake_built_t bg;
        CHECK(nodus_v2_stake_build(&rg, &bg, &e) == NODUS_V2_SPEND_OK,
              "build at gas price 5");
        CHECK(400000ull * 5ull > KB_FLOOR, "the gas fee is above the floor");
        CHECK(bg.fee == 400000ull * 5ull && bg.dec.fee == bg.fee,
              "fee = units x gas price");
        CHECK(dry(c->w, bg.env, bg.env_len, &code, wid, iid) == 0 &&
              code == NODUS_V2_TX_OK, "the engine admits the gas-priced fee");
        nodus_v2_stake_built_free(&bg);
    }

    /* apply the DELEGATE at height 2, so a delegation row exists */
    {
        nodus_v2_envelope_t ve = { b.env, b.env_len };
        nodus_v2_block_t blk;
        memset(&blk, 0, sizeof(blk));
        blk.global_height = 2;
        blk.epoch = nodus_v2_epoch_for_height(2);
        blk.envs = &ve;
        blk.n_envs = 1;
        CHECK(v2x_cmt_apply_ok(c->w, &blk) == 0,
              "the DELEGATE applies in block 2");
        CHECK(nodus_witness_v2_tip_height(c->w, &c->tip) == 0 && c->tip == 2,
              "tip 2");
    }

    /* the coins still unspent + the DELEGATE's change coin */
    nodus_v2_stake_coin_t left[KB_N_COINS + 1];
    int m = 0;
    for (int i = 0; i < n; i++) {
        int used = 0;
        for (int j = 0; j < b.dec.n_in; j++)
            if (memcmp(coins[i].nul, b.dec.in_nul[j], 64) == 0) used = 1;
        if (!used) left[m++] = coins[i];
    }
    if (b.dec.n_out == 1) {
        memset(&left[m], 0, sizeof(left[m]));
        memcpy(left[m].nul, b.dec.change_id, 64);
        left[m].amount = b.dec.change_amount;
        m++;
    }
    CHECK(m >= 1, "a coin is left to pay the UNDELEGATE fee");

    /* UNDELEGATE the whole delegation: the funding pays the fee only */
    nodus_v2_stake_req_t ru;
    base_req(&ru, &rs, c, NODUS_V2_STAKE_OP_UNDELEGATE, DNAC_MIN_DELEGATION,
             left, m);
    nodus_v2_stake_built_t bu;
    CHECK(nodus_v2_stake_build(&ru, &bu, &e) == NODUS_V2_SPEND_OK,
          "build UNDELEGATE");
    CHECK(bu.sum_in == bu.change + KB_FLOOR,
          "UNDELEGATE funding: inputs = change + fee (lock 0)");
    CHECK(dry(c->w, bu.env, bu.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK, "the engine admits the UNDELEGATE");
    CHECK(memcmp(wid, bu.wire_id, 64) == 0 &&
          memcmp(iid, bu.intent_id, 64) == 0,
          "UNDELEGATE: the engine derives the builder's ids");
    if (check_layout(&bu, &ru, &rs, KB_FLOOR) != 0) return 1;
    if (check_twin(&ru, &bu) != 0) return 1;

    nodus_v2_stake_built_free(&bu);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* ══ K5 ══════════════════════════════════════════════════════════════ */

static int t_refusals(kb_chain_t *c) {
    nodus_v2_stake_ruleset_t rs;
    table_ruleset(&rs);
    nodus_v2_stake_coin_t coins[KB_N_COINS];
    int n = coins_of(c, coins);
    nodus_v2_stake_req_t r;
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;

    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_STAKE, DNAC_SELF_STAKE_AMOUNT - 1,
             coins, n);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_BOND,
          "a bond other than the self-bond is refused");

    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_STAKE, DNAC_SELF_STAKE_AMOUNT,
             coins, n);
    r.commission_bps = DNAC_COMMISSION_BPS_MAX + 1;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_COMMISSION,
          "a commission above the maximum is refused");

    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_DELEGATE, 0, coins, n);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_AMOUNT,
          "a DELEGATE amount of 0 is refused");
    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_UNDELEGATE,
             DNAC_DEFAULT_TOTAL_SUPPLY + 1, coins, n);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_AMOUNT,
          "an amount above the supply is refused");

    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_DELEGATE, DNAC_MIN_DELEGATION,
             coins, n);
    r.op = (nodus_v2_stake_op_t)3;               /* UNSTAKE — not built here */
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_OP,
          "an op other than STAKE / DELEGATE / UNDELEGATE is refused");

    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_DELEGATE, DNAC_MIN_DELEGATION,
             coins, n);
    r.tip = 0;
    r.expiry_height = KB_EXPIRY_AHEAD;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_EXPIRY,
          "a 0 tip is refused");

    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_DELEGATE, DNAC_MIN_DELEGATION,
             coins, 0);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_INSUFFICIENT,
          "no coin: insufficient");

    nodus_v2_stake_coin_t one = coins[0];
    one.unlock_block = c->tip + 1;               /* still locked at the tip */
    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_UNDELEGATE, DNAC_MIN_DELEGATION,
             &one, 1);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_INSUFFICIENT,
          "a locked coin is not selected");

    one = coins[0];
    one.token[0] = 0x01;                          /* a non-native token */
    base_req(&r, &rs, c, NODUS_V2_STAKE_OP_UNDELEGATE, DNAC_MIN_DELEGATION,
             &one, 1);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_INSUFFICIENT,
          "a non-native coin is not selected");
    return 0;
}

int main(void) {
    printf("=== shared staking envelope builder (STAKE / DELEGATE / "
           "UNDELEGATE) ===\n");
    if (keys_init() != 0) {
        fprintf(stderr, "key setup failed\n");
        return 1;
    }
    kb_chain_t c;
    if (chain_open(&c) != 0) {
        fprintf(stderr, "seeded chain setup failed\n");
        chain_close(&c);
        return 1;
    }
    int fails = 0;
    fails += t_refusals(&c);
    fails += t_stake(&c);
    fails += t_delegate_then_undelegate(&c);
    chain_close(&c);

    printf("=== %s: %d checks, %d failed section(s) ===\n",
           fails ? "FAIL" : "PASS", g_checks, fails);
    return fails ? 1 : 0;
}
