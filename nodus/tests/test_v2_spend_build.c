/**
 * @file nodus/tests/test_v2_spend_build.c
 * @brief Web wallet package (c2) — the shared CORE SPEND builder
 *        (nodus/src/client/nodus_v2_spend.c) against the production engine.
 *
 * Governing records: docs/plans/2026-09-25-web-wallet-nodus-send-design.md
 * §0a.3 (c2) + §1.3, and docs/plans/decisions/2026-09-25-web-wallet-nodus-
 * send-transport.md ("İşlem kurucu" — the browser builds its SPEND with the
 * SAME C code as nodus-cli; addendum 2026-09-29 "Yol 2" — the ruleset
 * identity from the generated nodus_ruleset_pins.h).
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 *  S1  The pins-derived ruleset identity (nodus_v2_ruleset_from_pins — what
 *      the browser module uses) equals the node's compiled table (what
 *      nodus-cli uses): CORE ruleset_version, ruleset_hash, and the SYSTEM
 *      meter policy's dna_meter_policy_digest. False if the pins header
 *      drifted from the table or the rebuild recipe were wrong.
 *  S2  An envelope built by the library with the PINS ruleset, a fixed key
 *      (qgp_dsa87_keypair_derand) and a fixed randomness stream is ADMITTED
 *      by the engine's own CheckTx seam (nodus_witness_v2_env_dry_run, the
 *      call nodus_witness_cmt_app.c app_check_envelope makes) on a seeded
 *      version-3 chain running the PRODUCTION runtime table: rc 0, code OK,
 *      and the engine derives the same wire_id and intent_id the builder
 *      reported. False if any header field, the call layout, the units
 *      ceiling, the fee rule, the signature or the ruleset binding were
 *      wrong.
 *  S3  The fields read back from the built bytes equal the request:
 *      recipient, amount, fee, change (owner + amount), expiry, inputs
 *      (the plan's nullifiers, strictly ascending), native token — checked
 *      both on the library's decoded struct AND on an independent parse of
 *      the call bytes here.
 *  S4  nodus-cli equivalence. nodus-cli `v2-envelope spend` has no builder
 *      of its own any more: it calls nodus_v2_spend_plan +
 *      nodus_v2_spend_build with the compiled-table ruleset (S1 proves it
 *      equal to the pins one) and nodus_random as the seed source. A literal
 *      byte comparison of two envelopes is impossible for a different
 *      reason than the seeds: qgp_dsa87_sign is HEDGED
 *      (shared/crypto/sign/dsa/config.h DILITHIUM_RANDOMIZED_SIGNING,
 *      dsa/sign.c randombytes), so the 4627 signature bytes, and with them
 *      wire_id, differ between ANY two builds. What is proved instead:
 *        (a) two builds from identical inputs and an identical seed stream
 *            have the same length, the same intent_id and are byte-identical
 *            everywhere except the auth blob;
 *        (b) the call bytes equal an independent restatement, in this file,
 *            of the pre-move nodus-cli algorithm (in_count ‖ ascending
 *            nullifiers ‖ out_count ‖ recipient record ‖ change record, the
 *            seeds drawn in output order from the stream), and the leg
 *            header / fee / expiry / units equal the pre-move formulas;
 *        (c) a table-ruleset build and a pins-ruleset build of the same
 *            request (same seed stream) have the same intent_id.
 *  S5  The gas-price fixed point: at gas price 200 the plan raises the fee
 *      to units(shape) × 200 (above the 10^6 floor), the built envelope's
 *      own units × 200 fit that fee, and the engine admits it.
 *  S6  Refusals: tip 0, expiry past tip + 100, expiry at tip, an unknown
 *      selection order, and an amount the coins cannot cover.
 *      S2-S6 run with req.no_dust_sweep = 1: they pin the pre-2026-10-07
 *      1-in/2-out shape (the default would also sweep coins B and C).
 *  S7  The dust sweep (operator 2026-10-07, nodus/BUGS.md), plan-level on
 *      synthetic coins: (a) after the covering pick, dust above the
 *      marginal fee is added smallest first, equal amounts by nullifier
 *      ascending, up to 15 inputs; change = in − amount − fee exactly and
 *      the fee is priced on the swept shape; (b) a coin at exactly the
 *      marginal fee (units(n+1)−units(n))×gas price is NOT added, one raw
 *      above is; at gas price 0 any coin above 0 is; (c) count 2 plans are
 *      the flag-off plans (no sweep); (d) --amount all sweeps into the one
 *      output; (e) no_dust_sweep = 1 gives the old shape, the default the
 *      swept one; (f) four permutations of one listing give the identical
 *      plan. Engine: a swept 3-input envelope of the seeded coins is
 *      admitted by CheckTx.
 *  S8  The change absorption: a native change at or below the threshold
 *      (the floor at gas price 0; the marginal per-input fee otherwise)
 *      becomes fee — no change output, fee = in − amount — and one raw
 *      above stays a change output; never under fee_fixed or the flag.
 *      Engine: the absorbed 1-output envelope of seeded coin D is admitted.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (one empty block at height 1;
 * it assumes height 1 is not an epoch boundary — true for every
 * DNAC_EPOCH_LENGTH > 1). Environment: none. SQLite >= 3.35.0 (the seeded
 * genesis fixture).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_v2_spend_build_XXXXXX directory, removed at the end; a
 * CHECK failure leaves it behind (this tree's fixture convention).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The genesis is SEEDED (v2_genesis_fixture.h TIER B) with spendable
 *     genesis UTXOs (V2X_SEED_NOT_REAL_UTXOS) — a state the real
 *     derivation never writes; the dry run judges the envelope against it.
 *  2. The dry run is CheckTx's per-item seam; the node's separate
 *     `expiry > tip + 100` gate (app_check_envelope) is not called here —
 *     the library's own expiry window refusal is tested instead (S6).
 *  3. The chain's gas price is 0 (the seeded document), so S5 proves the
 *     builder's arithmetic and that an overpaying fee is admitted, not that
 *     the engine would demand exactly that fee.
 *  4. S4 is NOT a byte comparison with a running nodus-cli (that needs a
 *     node over the network); see S4 above for what replaces it.
 *  4b. S2 proves the PRODUCTION CORE exec and the per-item CheckTx stages
 *     accept the envelope against the seeded committee (the document's
 *     synthetic validators); it says nothing about mempool gossip or
 *     PrepareProposal's unit reservation — no block carrying the envelope
 *     is applied here.
 *  4c. S7 (a)/(b)/(d)/(f) and S8 at gas price 1 are PLAN-level only (no
 *     build, no engine); the marginal fees they compare against are derived
 *     from nodus_v2_spend_units_for_shape — the same function the planner
 *     prices with, so a wrong units function would not be caught here (S5
 *     and S2 pin units against the metering module). The S8 gas-price-1
 *     case assumes every shape prices under the floor at price 1 and CHECKs
 *     that assumption rather than skipping.
 *  5. Written, compiled, NOT RUN by its author (the BUILDER rule).
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

#define SB_FLOOR  (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                       ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE)
#define SB_COIN_A 5000000ULL
#define SB_COIN_B 3000000ULL
#define SB_COIN_C 2000000ULL
#define SB_AMOUNT 1234567ULL
/* coin D: SB_AMOUNT + the floor fee + a change of SB_D_CHANGE, which is
 * NOT above the floor — at gas price 0 the default plan folds it into the
 * fee (S8) */
#define SB_D_CHANGE 400000ULL
#define SB_COIN_D (SB_AMOUNT + SB_FLOOR + SB_D_CHANGE)

/* ══ fixed key + fixed randomness ════════════════════════════════════ */

static uint8_t g_pk[2592], g_sk[4896];
static char    g_sender_fp[QGP_FP_HEX_BUFFER];
static uint8_t g_to_raw[64];
static char    g_to_fp[QGP_FP_HEX_BUFFER];

static int keys_init(void) {
    uint8_t seed[32], rpk[2592], rsk[4896], raw[64];
    memset(seed, 0x5E, sizeof(seed));
    if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) return -1;
    if (qgp_sha3_512(g_pk, sizeof(g_pk), raw) != 0) return -1;
    qgp_fp_raw_to_hex(raw, g_sender_fp);
    memset(seed, 0x7A, sizeof(seed));
    if (qgp_dsa87_keypair_derand(rpk, rsk, seed) != 0) return -1;
    if (qgp_sha3_512(rpk, sizeof(rpk), g_to_raw) != 0) return -1;
    qgp_fp_raw_to_hex(g_to_raw, g_to_fp);
    return 0;
}

/* A deterministic byte stream: block i = SHA3-512(seed32 ‖ i as u64 BE),
 * concatenated. Two streams with the same seed yield the same bytes. */
typedef struct {
    uint8_t  seed[32];
    uint64_t block;
    uint8_t  buf[64];
    size_t   have;
} sb_stream_t;

static void stream_init(sb_stream_t *s, uint8_t fill) {
    memset(s, 0, sizeof(*s));
    memset(s->seed, fill, sizeof(s->seed));
}

static int stream_rand(void *ctx, uint8_t *out, size_t len) {
    sb_stream_t *s = (sb_stream_t *)ctx;
    while (len > 0) {
        if (s->have == 0) {
            uint8_t pre[40];
            memcpy(pre, s->seed, 32);
            for (int i = 0; i < 8; i++)
                pre[32 + i] = (uint8_t)(s->block >> (56 - 8 * i));
            if (qgp_sha3_512(pre, sizeof(pre), s->buf) != 0) return -1;
            s->block++;
            s->have = 64;
        }
        size_t take = len < s->have ? len : s->have;
        memcpy(out, s->buf + (64 - s->have), take);
        s->have -= take;
        out += take;
        len -= take;
    }
    return 0;
}

/* ══ the chain ═══════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          file16[16];
    uint8_t          chain32[32];
    uint64_t         tip;
    uint8_t          nul[4][64];      /* the seeded coins: A, B, C, D    */
} sb_chain_t;

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

/* One CORE utxo owned by the sender; nullifier = SHA3-512(owner128 ‖
 * seed32) — the SOURCE output-identity derivation (test_v2_native.c
 * seed_utxo_owner's shape). */
static int seed_coin(sb_chain_t *c, uint64_t amount, uint8_t seed_byte,
                     uint8_t nul_out[64]) {
    uint8_t seed[32], pre[160];
    memset(seed, seed_byte, sizeof(seed));
    memcpy(pre, g_sender_fp, 128);
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
    sqlite3_bind_text(st, 2, g_sender_fp, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* seeded version-3 genesis over the PRODUCTION table + three coins of the
 * sender, then ONE empty block so the committed tip is 1 (the builder
 * refuses a 0 tip). 0 / -1. */
static int chain_open(sb_chain_t *c) {
    memset(c, 0, sizeof(*c));
    c->w = calloc(1, sizeof(*c->w));
    if (!c->w) return -1;
    c->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(c->dir, sizeof(c->dir), "/tmp/test_v2_spend_build_XXXXXX");
    if (!mkdtemp(c->dir)) return -1;
    snprintf(c->w->data_path, sizeof(c->w->data_path), "%s", c->dir);
    memset(c->file16, 0x5B, sizeof(c->file16));
    if (v2x_seed_prepare(c->w, c->file16, 0) != 0) return -1;
    if (seed_coin(c, SB_COIN_A, 0xA1, c->nul[0]) != 0 ||
        seed_coin(c, SB_COIN_B, 0xA2, c->nul[1]) != 0 ||
        seed_coin(c, SB_COIN_C, 0xA3, c->nul[2]) != 0 ||
        seed_coin(c, SB_COIN_D, 0xA4, c->nul[3]) != 0)
        return -1;
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(c->w, c->file16, 0, NULL, 0, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(c->w, c->chain32) != 0) return -1;

    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = 1;
    b.epoch = nodus_v2_epoch_for_height(1);
    if (v2x_cmt_apply_ok(c->w, &b) != 0) return -1;
    return nodus_witness_v2_tip_height(c->w, &c->tip) == 0 && c->tip == 1
               ? 0 : -1;
}

static void chain_close(sb_chain_t *c) {
    if (c->w) {
        if (c->w->db) sqlite3_close(c->w->db);
        free(c->w);
        c->w = NULL;
    }
    if (c->dir[0]) rmrf(c->dir);
}

/* The engine's CheckTx seam on one envelope. rc; *code, ids out. */
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

/* The chain's view of the sender's coins, as nodus-cli builds it from a
 * dnac_utxo listing (all native, all unlocked here). */
static int coins_of(const sb_chain_t *c, nodus_v2_coin_t coins[3]) {
    static const uint64_t amt[3] = { SB_COIN_A, SB_COIN_B, SB_COIN_C };
    memset(coins, 0, 3 * sizeof(coins[0]));
    for (int i = 0; i < 3; i++) {
        memcpy(coins[i].nul, c->nul[i], 64);
        coins[i].amount = amt[i];
        coins[i].kind   = 0;
    }
    return 3;
}

static void table_ruleset(nodus_v2_ruleset_id_t *rs) {
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    memset(rs, 0, sizeof(*rs));
    for (size_t i = 0; i < n; i++) {
        if (t[i].domain_id == DNA_DOMAIN_CORE) {
            rs->core_ruleset_version = t[i].ruleset_version;
            memcpy(rs->core_ruleset_hash, t[i].ruleset_hash, 64);
        } else if (t[i].domain_id == DNA_DOMAIN_SYSTEM) {
            rs->meter_policy = t[i].meter_policy;
        }
    }
}

/* plan ONE native spend of `amount` at `gas_price`; `no_sweep` = 1 turns
 * the dust sweep and the change absorption off (the pre-2026-10-07 shape);
 * 0 / rc */
static int plan_one(const nodus_v2_ruleset_id_t *rs, nodus_v2_coin_t *coins,
                    int n, uint64_t amount, uint64_t gas_price, int no_sweep,
                    nodus_v2_spend_plan_t **plans, uint64_t *fee) {
    nodus_v2_spend_plan_req_t q;
    memset(&q, 0, sizeof(q));
    q.rs            = rs;
    q.order         = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
    q.is_native     = 1;
    q.amount        = amount;
    q.fee           = SB_FLOOR;
    q.gas_price     = gas_price;
    q.count         = 1;
    q.no_dust_sweep = no_sweep;
    long cnt = 0;
    nodus_v2_spend_err_t e;
    return nodus_v2_spend_plan(&q, coins, n, plans, &cnt, fee, &e);
}

static void build_req(nodus_v2_spend_build_req_t *r,
                      const nodus_v2_ruleset_id_t *rs, const sb_chain_t *c,
                      const nodus_v2_coin_t *coins,
                      const nodus_v2_spend_plan_t *p, uint64_t fee,
                      uint64_t gas_price, sb_stream_t *s) {
    memset(r, 0, sizeof(*r));
    r->rs            = rs;
    r->chain32       = c->chain32;
    r->tip           = c->tip;
    r->expiry_height = c->tip + 90;      /* nodus-cli CLI_ENV_EXPIRY_AHEAD */
    r->pk            = g_pk;
    r->sk            = g_sk;
    r->to_fp         = g_to_raw;
    r->token         = NULL;
    r->amount        = SB_AMOUNT;
    r->fee           = fee;
    r->gas_price     = gas_price;
    r->coins         = coins;
    r->plan          = p;
    r->rand          = stream_rand;
    r->rand_ctx      = s;
}

/* ══ S1 ══════════════════════════════════════════════════════════════ */

static int t_pins_equal_table(void) {
    nodus_v2_ruleset_id_t pins, tab;
    dna_meter_policy_t *store = calloc(1, sizeof(*store));
    CHECK(store != NULL, "alloc");
    CHECK(nodus_v2_ruleset_from_pins(&pins, store) == NODUS_V2_SPEND_OK,
          "the pins policy rebuilds to its pinned digest");
    table_ruleset(&tab);
    CHECK(tab.meter_policy != NULL, "the table carries a SYSTEM policy");
    CHECK(pins.core_ruleset_version == tab.core_ruleset_version,
          "pins CORE ruleset_version == table");
    CHECK(memcmp(pins.core_ruleset_hash, tab.core_ruleset_hash, 64) == 0,
          "pins CORE ruleset_hash == table");
    uint8_t d1[64], d2[64];
    CHECK(dna_meter_policy_digest(pins.meter_policy, d1) == 0 &&
          dna_meter_policy_digest(tab.meter_policy, d2) == 0 &&
          memcmp(d1, d2, 64) == 0,
          "pins SYSTEM meter policy digest == table");
    free(store);
    return 0;
}

/* ══ S2 + S3 + S4 ════════════════════════════════════════════════════ */

static int t_build_admitted_and_read_back(sb_chain_t *c) {
    dna_meter_policy_t *store = calloc(1, sizeof(*store));
    CHECK(store != NULL, "alloc");
    nodus_v2_ruleset_id_t rs, tab;
    CHECK(nodus_v2_ruleset_from_pins(&rs, store) == 0, "pins ruleset");
    table_ruleset(&tab);

    nodus_v2_coin_t coins[3];
    int n = coins_of(c, coins);
    nodus_v2_spend_plan_t *plans = NULL;
    uint64_t fee = 0;
    /* no_sweep = 1: S2-S4 pin the PRE-2026-10-07 1-in/2-out layout (the
     * restated nodus-cli call bytes below). With the default sweep the
     * plan would also take B and C (S7 covers that shape). */
    CHECK(plan_one(&rs, coins, n, SB_AMOUNT, 0, 1, &plans, &fee) == 0,
          "plan one native spend");
    /* largest first: coin A (5 000 000) alone covers amount + fee */
    CHECK(fee == SB_FLOOR, "gas price 0: the fee is the floor");
    CHECK(plans[0].n_in == 1 && coins[plans[0].idx[0]].amount == SB_COIN_A,
          "largest-first picks coin A alone");
    const uint64_t change = SB_COIN_A - SB_AMOUNT - fee;
    CHECK(plans[0].native_change == change, "the plan's change");

    sb_stream_t s1;
    stream_init(&s1, 0x11);
    nodus_v2_spend_build_req_t r;
    build_req(&r, &rs, c, coins, &plans[0], fee, 0, &s1);
    nodus_v2_spend_built_t b1;
    nodus_v2_spend_err_t e;
    CHECK(nodus_v2_spend_build(&r, &b1, &e) == NODUS_V2_SPEND_OK,
          "build with the PINS ruleset");

    /* S2 — the engine's CheckTx seam admits it */
    uint32_t code = 99;
    uint8_t wid[64], iid[64];
    CHECK(dry(c->w, b1.env, b1.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK,
          "nodus_witness_v2_env_dry_run admits the envelope (code OK)");
    CHECK(memcmp(wid, b1.wire_id, 64) == 0,
          "the engine derives the builder's wire_id");
    CHECK(memcmp(iid, b1.intent_id, 64) == 0,
          "the engine derives the builder's intent_id");

    /* S3 — read-back == request (the library's decoded struct) */
    const nodus_v2_spend_decoded_t *d = &b1.dec;
    CHECK(d->n_in == 1 && memcmp(d->in_nul[0], c->nul[0], 64) == 0,
          "input = coin A's nullifier");
    CHECK(d->n_out == 2, "recipient + native change");
    CHECK(memcmp(d->out_owner[0], g_to_fp, 128) == 0,
          "out[0] owner = the recipient fingerprint");
    CHECK(d->out_amount[0] == SB_AMOUNT, "out[0] amount = the amount");
    CHECK(memcmp(d->out_owner[1], g_sender_fp, 128) == 0,
          "out[1] owner = the sender (change)");
    CHECK(d->out_amount[1] == change, "out[1] amount = the change");
    static const uint8_t zero64[64] = {0};
    CHECK(memcmp(d->out_token[0], zero64, 64) == 0 &&
          memcmp(d->out_token[1], zero64, 64) == 0, "native outputs");
    CHECK(d->fee == fee, "fee");
    CHECK(d->expiry_height == c->tip + 90, "expiry = tip + 90");
    CHECK(d->ruleset_version == tab.core_ruleset_version,
          "leg ruleset_version = the table's CORE version");

    /* S3/S4(b) — an INDEPENDENT parse + restatement of the pre-move
     * nodus-cli layout, the seeds re-drawn from a fresh identical stream
     * in output order */
    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "alloc");
    CHECK(dna_env_decode(b1.env, b1.env_len, v) == 0 && v->leg_count == 1,
          "one leg");
    CHECK(v->leg[0].domain_id == DNA_DOMAIN_CORE &&
          v->leg[0].runtime_op == DNA_CORERULE_SPEND &&
          v->leg[0].access_mode == DNA_ENV_ACCESS_INVOKE &&
          v->leg[0].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
          v->leg[0].auth_len == 1u + NODUS_RT_AUTH_SIGNER_LEN,
          "leg header = CORE SPEND, INVOKE, kind-1, one signer");
    /* effects = n_in + n_out + 1; bytes = 116 + 148·n_in + 432·n_out */
    CHECK(v->leg[0].res_max_effects == 1u + 2u + 1u &&
          v->leg[0].res_max_effect_bytes == 116u + 148u * 1u + 432u * 2u,
          "effect declaration = the pre-move formula");
    {
        uint8_t exp_call[2 + 64 + 2 * 232];
        sb_stream_t s;
        stream_init(&s, 0x11);
        uint8_t seed0[32], seed1[32];
        CHECK(stream_rand(&s, seed0, 32) == 0 &&
              stream_rand(&s, seed1, 32) == 0, "re-draw the seeds");
        size_t off = 0;
        exp_call[off++] = 1;
        memcpy(exp_call + off, c->nul[0], 64); off += 64;
        exp_call[off++] = 2;
        nodus_v2_xfer_out_put(exp_call + off, g_to_fp, SB_AMOUNT, NULL, seed0);
        off += 232;
        nodus_v2_xfer_out_put(exp_call + off, g_sender_fp, change, NULL, seed1);
        off += 232;
        /* the record layout itself, restated without the writer: the
         * recipient record starts after in_count (1) + one nullifier (64)
         * + out_count (1) = byte 66 */
        CHECK(memcmp(exp_call + 66, g_to_fp, 128) == 0 &&
              exp_call[66 + 128 + 7] == (uint8_t)(SB_AMOUNT & 0xff) &&
              memcmp(exp_call + 66 + 136, zero64, 64) == 0 &&
              memcmp(exp_call + 66 + 200, seed0, 32) == 0,
              "record = owner hex ‖ amount BE ‖ token ‖ seed");
        CHECK(v->leg[0].call_len == off &&
              memcmp(v->buf + v->call_off[0], exp_call, off) == 0,
              "call bytes = the restated nodus-cli layout");
    }
    {
        /* units = the metering module's ceiling of this very envelope */
        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr = v->leg[0];
        leg.call_data = v->buf + v->call_off[0];
        leg.auth_data = v->buf + v->auth_off[0];
        dna_env_in_t in;
        memset(&in, 0, sizeof(in));
        in.expiry_height = v->expiry_height;
        in.fee_amount    = v->fee_amount;
        in.leg_count     = 1;
        in.legs          = &leg;
        uint64_t units = 0;
        CHECK(nodus_v2_spend_ceiling(&in, tab.meter_policy, 2u, &units) == 0 &&
              units == v->res_max_total_units,
              "res_max_total_units = static_units + (in + 1) reads");
    }

    /* S4(a) — a twin build: same length, same intent_id, identical bytes
     * outside the (hedged) signature blob */
    sb_stream_t s2;
    stream_init(&s2, 0x11);
    build_req(&r, &rs, c, coins, &plans[0], fee, 0, &s2);
    nodus_v2_spend_built_t b2;
    CHECK(nodus_v2_spend_build(&r, &b2, &e) == 0, "twin build");
    CHECK(b2.env_len == b1.env_len, "twin: same length");
    CHECK(memcmp(b2.intent_id, b1.intent_id, 64) == 0, "twin: same intent_id");
    {
        const size_t a0 = v->auth_off[0], al = v->leg[0].auth_len;
        CHECK(memcmp(b1.env, b2.env, a0) == 0 &&
              memcmp(b1.env + a0 + al, b2.env + a0 + al,
                     b1.env_len - a0 - al) == 0,
              "twin: byte-identical outside the auth blob");
        /* the auth blob's public key half is identical too */
        CHECK(b1.env[a0] == 1 && b2.env[a0] == 1 &&
              memcmp(b1.env + a0 + 1, g_pk, 2592) == 0 &&
              memcmp(b2.env + a0 + 1, g_pk, 2592) == 0,
              "twin: count 1 ‖ the sender pk");
    }

    /* S4(c) — the TABLE ruleset (nodus-cli's source) gives the same
     * intent as the PINS ruleset (the browser's) */
    sb_stream_t s3;
    stream_init(&s3, 0x11);
    build_req(&r, &tab, c, coins, &plans[0], fee, 0, &s3);
    nodus_v2_spend_built_t b3;
    CHECK(nodus_v2_spend_build(&r, &b3, &e) == 0, "table-ruleset build");
    CHECK(memcmp(b3.intent_id, b1.intent_id, 64) == 0,
          "table ruleset intent_id == pins ruleset intent_id");

    free(v);
    nodus_v2_spend_built_free(&b1);
    nodus_v2_spend_built_free(&b2);
    nodus_v2_spend_built_free(&b3);
    free(plans);
    free(store);
    return 0;
}

/* ══ S5 ══════════════════════════════════════════════════════════════ */

static int t_gas_price(sb_chain_t *c) {
    const uint64_t gp = 200;
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    nodus_v2_coin_t coins[3];
    int n = coins_of(c, coins);
    nodus_v2_spend_plan_t *plans = NULL;
    uint64_t fee = 0;
    /* no_sweep = 1: S5 pins the fixed point on the 1-in/2-out shape; the
     * default sweep would add B and C and price a 3-in shape (S7 (a)
     * prices a swept shape). */
    CHECK(plan_one(&tab, coins, n, SB_AMOUNT, gp, 1, &plans, &fee) == 0,
          "plan at gas price 200");
    uint64_t u = 0;
    CHECK(nodus_v2_spend_units_for_shape(tab.core_ruleset_version,
                                         tab.meter_policy,
                                         1u + NODUS_RT_AUTH_SIGNER_LEN,
                                         plans[0].n_in, 2, &u) == 0,
          "units of the planned 1-in/2-out shape");
    CHECK(u * gp > SB_FLOOR, "the gas fee is above the floor here");
    CHECK(fee == u * gp, "the fee settled at units x gas price");

    sb_stream_t s;
    stream_init(&s, 0x22);
    nodus_v2_spend_build_req_t r;
    build_req(&r, &tab, c, coins, &plans[0], fee, gp, &s);
    nodus_v2_spend_built_t b;
    nodus_v2_spend_err_t e;
    CHECK(nodus_v2_spend_build(&r, &b, &e) == 0, "build at gas price 200");
    CHECK(b.dec.fee == fee && b.dec.units * gp <= fee,
          "the built units x price fit the fee");
    CHECK(b.dec.out_amount[1] == SB_COIN_A - SB_AMOUNT - fee,
          "change = coin - amount - gas fee");
    uint32_t code = 99;
    uint8_t wid[64], iid[64];
    CHECK(dry(c->w, b.env, b.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK, "the engine admits the gas-priced spend");
    nodus_v2_spend_built_free(&b);
    free(plans);
    return 0;
}

/* ══ S6 ══════════════════════════════════════════════════════════════ */

static int t_refusals(sb_chain_t *c) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    nodus_v2_coin_t coins[3];
    int n = coins_of(c, coins);
    nodus_v2_spend_plan_t *plans = NULL;
    uint64_t fee = 0;
    /* no_sweep = 1: the refusals below do not depend on the shape; the
     * flag keeps this plan the one S2 built */
    CHECK(plan_one(&tab, coins, n, SB_AMOUNT, 0, 1, &plans, &fee) == 0,
          "plan");

    sb_stream_t s;
    nodus_v2_spend_build_req_t r;
    nodus_v2_spend_built_t b;
    nodus_v2_spend_err_t e;

    stream_init(&s, 0x33);
    build_req(&r, &tab, c, coins, &plans[0], fee, 0, &s);
    r.tip = 0;
    r.expiry_height = 90;
    CHECK(nodus_v2_spend_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_EXPIRY,
          "tip 0 is refused");

    build_req(&r, &tab, c, coins, &plans[0], fee, 0, &s);
    r.expiry_height = c->tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD + 1;
    CHECK(nodus_v2_spend_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_EXPIRY,
          "expiry past tip + 100 is refused");

    build_req(&r, &tab, c, coins, &plans[0], fee, 0, &s);
    r.expiry_height = c->tip;
    CHECK(nodus_v2_spend_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_EXPIRY,
          "expiry at the tip is refused");

    CHECK(nodus_v2_spend_sort_coins(coins, n, (nodus_v2_spend_order_t)1) ==
              NODUS_V2_SPEND_ERR_ARG,
          "an unknown selection order is refused");

    nodus_v2_spend_plan_t *p2 = NULL;
    uint64_t f2 = 0;
    /* sweep ON (the default): an uncovered need is refused before any
     * sweep runs */
    CHECK(plan_one(&tab, coins, n, SB_COIN_A + SB_COIN_B + SB_COIN_C, 0, 0,
                   &p2, &f2) == NODUS_V2_SPEND_ERR_INSUFFICIENT && !p2,
          "an amount the coins cannot cover (plus the fee) is refused");
    free(plans);
    return 0;
}

/* ══ S7 + S8 — the dust sweep and the change absorption ══════════════ */

#define SB_GP     200ULL
#define SB_BIG    1000000000ULL
#define SB_AMT10  10000000ULL
#define SB_ALEN   (1u + NODUS_RT_AUTH_SIGNER_LEN)

/* a synthetic native coin (plan-only sections): nullifier = 64 × `b` */
static void syn_coin(nodus_v2_coin_t *c, uint64_t amount, uint8_t b) {
    memset(c, 0, sizeof(*c));
    memset(c->nul, b, 64);
    c->amount = amount;
    c->kind   = 0;
}

static int units_of(const nodus_v2_ruleset_id_t *rs, int n_in, int n_out,
                    uint64_t *u) {
    return nodus_v2_spend_units_for_shape(rs->core_ruleset_version,
                                          rs->meter_policy, SB_ALEN, n_in,
                                          n_out, u);
}

static uint64_t u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }

/* The largest marginal fee any sweep step can face at gas price `gp`: one
 * more input on every shape, and one more input that also creates the
 * change output. Restated here from units_of, not from the planner.
 * 0 / -1 */
static int max_marginal(const nodus_v2_ruleset_id_t *rs, uint64_t gp,
                        uint64_t *out) {
    uint64_t m = 0;
    for (int n = 1; n < (int)NODUS_V2_SPEND_MAX_IN; n++)
        for (int o = 1; o <= (int)NODUS_V2_SPEND_MAX_OUTS; o++) {
            uint64_t a = 0, b = 0;
            if (units_of(rs, n, o, &a) != 0 || units_of(rs, n + 1, o, &b) != 0)
                return -1;
            if (b > a && (b - a) * gp > m) m = (b - a) * gp;
            if (o < (int)NODUS_V2_SPEND_MAX_OUTS) {
                if (units_of(rs, n + 1, o + 1, &b) != 0) return -1;
                if (b > a && (b - a) * gp > m) m = (b - a) * gp;
            }
        }
    *out = m;
    return 0;
}

/* the general request; *plans heap (caller frees). 0 / rc */
static int plan_q(const nodus_v2_ruleset_id_t *rs, nodus_v2_coin_t *coins,
                  int n, uint64_t amount, int amount_all, long count,
                  uint64_t gp, int no_sweep, int fee_fixed,
                  nodus_v2_spend_plan_t **plans, long *cnt, uint64_t *fee) {
    nodus_v2_spend_plan_req_t q;
    memset(&q, 0, sizeof(q));
    q.rs            = rs;
    q.order         = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
    q.is_native     = 1;
    q.amount        = amount;
    q.amount_all    = amount_all;
    q.fee           = SB_FLOOR;
    q.fee_fixed     = fee_fixed;
    q.gas_price     = gp;
    q.count         = count;
    q.no_dust_sweep = no_sweep;
    nodus_v2_spend_err_t e;
    *plans = NULL;
    return nodus_v2_spend_plan(&q, coins, n, plans, cnt, fee, &e);
}

/* (a)/(f) fixture: one big coin + 17 dust coins worth more than any
 * marginal fee at SB_GP. Amounts come in equal PAIRS, and inside a pair the
 * later coin has the SMALLER nullifier byte, so the listing order is not
 * the sweep order. Returns the coin count (18). */
#define SB_N_DUST 17
static int dust_fixture(nodus_v2_coin_t *coins, uint64_t d_base) {
    syn_coin(&coins[0], SB_BIG, 0xF0);
    for (int i = 0; i < SB_N_DUST; i++)
        syn_coin(&coins[1 + i], d_base + (uint64_t)(i / 2),
                 (uint8_t)(0x80 - i));
    return 1 + SB_N_DUST;
}

/* (a) the sweep: smallest first (ties by nullifier ascending) up to the
 * 15-input cap, the change exact, the fee re-priced for the 15-in shape */
static int t_sweep_cap(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    uint64_t maxm = 0;
    CHECK(max_marginal(&tab, SB_GP, &maxm) == 0 && maxm > 0,
          "the marginal fees at gas price 200");
    nodus_v2_coin_t coins[1 + SB_N_DUST];
    const int n = dust_fixture(coins, maxm + 1);

    /* the expected sweep order, restated: (amount asc, nullifier asc) */
    uint64_t ea[SB_N_DUST];
    uint8_t  eb[SB_N_DUST];
    for (int i = 0; i < SB_N_DUST; i++) {
        ea[i] = coins[1 + i].amount;
        eb[i] = coins[1 + i].nul[0];
    }
    for (int i = 1; i < SB_N_DUST; i++)
        for (int j = i; j > 0 && (ea[j - 1] > ea[j] ||
                                  (ea[j - 1] == ea[j] && eb[j - 1] > eb[j]));
             j--) {
            uint64_t ta = ea[j]; ea[j] = ea[j - 1]; ea[j - 1] = ta;
            uint8_t tb = eb[j]; eb[j] = eb[j - 1]; eb[j - 1] = tb;
        }

    nodus_v2_spend_plan_t *plans = NULL;
    long cnt = 0;
    uint64_t fee = 0;
    CHECK(plan_q(&tab, coins, n, SB_AMT10, 0, 1, SB_GP, 0, 0, &plans, &cnt,
                 &fee) == NODUS_V2_SPEND_OK && cnt == 1,
          "(a) plan one native spend with dust");
    const nodus_v2_spend_plan_t *p = &plans[0];
    CHECK(p->n_in == (int)NODUS_V2_SPEND_MAX_IN,
          "(a) the sweep stops at the 15-input cap");
    CHECK(coins[p->idx[0]].amount == SB_BIG,
          "(a) the covering pick is the big coin alone");
    uint64_t in = SB_BIG;
    for (int j = 1; j < p->n_in; j++) {
        CHECK(coins[p->idx[j]].amount == ea[j - 1] &&
              coins[p->idx[j]].nul[0] == eb[j - 1],
              "(a) dust swept smallest first, ties by nullifier ascending");
        in += ea[j - 1];
    }
    uint64_t u15 = 0;
    CHECK(units_of(&tab, (int)NODUS_V2_SPEND_MAX_IN, 2, &u15) == 0,
          "(a) units of the 15-in/2-out shape");
    CHECK(fee == u64_max(SB_FLOOR, u15 * SB_GP),
          "(a) the fee is priced on the SWEPT shape");
    CHECK(p->native_in == in, "(a) native_in = big + the swept dust");
    CHECK(p->native_change > 0 &&
          p->native_change == in - SB_AMT10 - fee,
          "(a) change = in - amount - fee exactly");
    free(plans);
    return 0;
}

/* (b) a coin at exactly the marginal fee is NOT swept; one raw above is */
static int t_sweep_threshold(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    uint64_t u12 = 0, u22 = 0;
    CHECK(units_of(&tab, 1, 2, &u12) == 0 && units_of(&tab, 2, 2, &u22) == 0 &&
          u22 > u12, "(b) units of 1-in/2-out and 2-in/2-out");
    const uint64_t m = (u22 - u12) * SB_GP;

    nodus_v2_coin_t coins[2];
    nodus_v2_spend_plan_t *plans = NULL;
    long cnt = 0;
    uint64_t fee = 0;

    syn_coin(&coins[0], SB_BIG, 0xF0);
    syn_coin(&coins[1], m, 0x11);
    CHECK(plan_q(&tab, coins, 2, SB_AMT10, 0, 1, SB_GP, 0, 0, &plans, &cnt,
                 &fee) == 0 && plans[0].n_in == 1,
          "(b) a coin worth exactly the marginal fee is not swept");
    CHECK(plans[0].native_change == SB_BIG - SB_AMT10 - fee,
          "(b) change of the big coin alone");
    free(plans);

    syn_coin(&coins[0], SB_BIG, 0xF0);
    syn_coin(&coins[1], m + 1, 0x11);
    CHECK(plan_q(&tab, coins, 2, SB_AMT10, 0, 1, SB_GP, 0, 0, &plans, &cnt,
                 &fee) == 0 && plans[0].n_in == 2,
          "(b) a coin one raw above the marginal fee is swept");
    CHECK(plans[0].native_change == SB_BIG + m + 1 - SB_AMT10 - fee,
          "(b) its value joins the change");
    free(plans);

    /* gas price 0: the marginal fee is 0, a 1-raw coin is swept */
    syn_coin(&coins[0], SB_BIG, 0xF0);
    syn_coin(&coins[1], 1, 0x11);
    CHECK(plan_q(&tab, coins, 2, SB_AMT10, 0, 1, 0, 0, 0, &plans, &cnt,
                 &fee) == 0 && plans[0].n_in == 2 && fee == SB_FLOOR,
          "(b) gas price 0: any coin above 0 is swept");
    free(plans);
    return 0;
}

/* (c) count > 1: no sweep — each spend keeps its covering input only */
static int t_sweep_count2(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    nodus_v2_coin_t c1[5], c2[5];
    syn_coin(&c1[0], SB_BIG, 0xF1);
    syn_coin(&c1[1], SB_BIG - 1, 0xF2);
    syn_coin(&c1[2], 5000000, 0x21);
    syn_coin(&c1[3], 4000000, 0x22);
    syn_coin(&c1[4], 3000000, 0x23);
    memcpy(c2, c1, sizeof(c1));

    nodus_v2_spend_plan_t *pa = NULL, *pb = NULL;
    long na = 0, nb = 0;
    uint64_t fa = 0, fb = 0;
    CHECK(plan_q(&tab, c1, 5, SB_AMT10, 0, 2, 0, 0, 0, &pa, &na, &fa) == 0 &&
          na == 2, "(c) plan two spends, sweep flag left ON");
    CHECK(plan_q(&tab, c2, 5, SB_AMT10, 0, 2, 0, 1, 0, &pb, &nb, &fb) == 0 &&
          nb == 2, "(c) plan two spends, sweep flag OFF");
    CHECK(pa[0].n_in == 1 && c1[pa[0].idx[0]].amount == SB_BIG &&
          pa[1].n_in == 1 && c1[pa[1].idx[0]].amount == SB_BIG - 1,
          "(c) count 2: each spend has its one covering coin, no dust");
    CHECK(fa == fb && fa == SB_FLOOR &&
          pa[0].native_change == pb[0].native_change &&
          pa[1].native_change == pb[1].native_change &&
          pb[0].n_in == 1 && pb[1].n_in == 1,
          "(c) count 2 plans are the flag-off plans");
    free(pa);
    free(pb);
    return 0;
}

/* (d) amount_all: dust is swept into the single output */
static int t_sweep_amount_all(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    uint64_t maxm = 0;
    CHECK(max_marginal(&tab, SB_GP, &maxm) == 0, "(d) marginal fees");
    nodus_v2_coin_t coins[4];
    syn_coin(&coins[0], SB_BIG, 0xF0);
    syn_coin(&coins[1], maxm + 1, 0x31);
    syn_coin(&coins[2], maxm + 2, 0x32);
    syn_coin(&coins[3], maxm + 3, 0x33);
    nodus_v2_spend_plan_t *plans = NULL;
    long cnt = 0;
    uint64_t fee = 0;
    CHECK(plan_q(&tab, coins, 4, 0, 1, 1, SB_GP, 0, 0, &plans, &cnt,
                 &fee) == 0 && cnt == 1, "(d) plan --amount all");
    const nodus_v2_spend_plan_t *p = &plans[0];
    uint64_t u41 = 0;
    CHECK(units_of(&tab, 4, 1, &u41) == 0, "(d) units of 4-in/1-out");
    CHECK(p->n_in == 4 && coins[p->idx[0]].amount == SB_BIG,
          "(d) the big coin + every dust coin");
    CHECK(p->native_in == SB_BIG + 3 * maxm + 6 && p->native_change == 0,
          "(d) all value goes to the single output, no change");
    CHECK(fee == u64_max(SB_FLOOR, u41 * SB_GP) && p->native_in > fee,
          "(d) the fee is priced on the 4-in/1-out shape; output > 0");
    free(plans);
    return 0;
}

/* (e) the disable flag gives the pre-2026-10-07 shape; the default sweeps */
static int t_sweep_flag(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    nodus_v2_coin_t coins[3];
    nodus_v2_spend_plan_t *plans = NULL;
    uint64_t fee = 0;

    syn_coin(&coins[0], SB_COIN_A, 0x0A);
    syn_coin(&coins[1], SB_COIN_B, 0x0B);
    syn_coin(&coins[2], SB_COIN_C, 0x0C);
    CHECK(plan_one(&tab, coins, 3, SB_AMOUNT, 0, 1, &plans, &fee) == 0 &&
          plans[0].n_in == 1 && coins[plans[0].idx[0]].amount == SB_COIN_A &&
          plans[0].native_change == SB_COIN_A - SB_AMOUNT - SB_FLOOR &&
          fee == SB_FLOOR,
          "(e) no_dust_sweep = 1: coin A alone, the old change");
    free(plans);

    syn_coin(&coins[0], SB_COIN_A, 0x0A);
    syn_coin(&coins[1], SB_COIN_B, 0x0B);
    syn_coin(&coins[2], SB_COIN_C, 0x0C);
    CHECK(plan_one(&tab, coins, 3, SB_AMOUNT, 0, 0, &plans, &fee) == 0 &&
          plans[0].n_in == 3 &&
          coins[plans[0].idx[0]].amount == SB_COIN_A &&
          coins[plans[0].idx[1]].amount == SB_COIN_C &&
          coins[plans[0].idx[2]].amount == SB_COIN_B &&
          plans[0].native_change ==
              SB_COIN_A + SB_COIN_B + SB_COIN_C - SB_AMOUNT - SB_FLOOR &&
          fee == SB_FLOOR,
          "(e) default: A covers, then C, then B (smallest first)");
    free(plans);
    return 0;
}

/* (f) determinism: any listing order of the same coins → the same plan */
static int t_sweep_determinism(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    uint64_t maxm = 0;
    CHECK(max_marginal(&tab, SB_GP, &maxm) == 0, "(f) marginal fees");
    nodus_v2_coin_t base[1 + SB_N_DUST];
    const int n = dust_fixture(base, maxm + 1);

    uint8_t  ref_nul[NODUS_V2_SPEND_MAX_IN];
    int      ref_n = 0;
    uint64_t ref_fee = 0, ref_in = 0, ref_ch = 0;
    for (int perm = 0; perm < 4; perm++) {
        nodus_v2_coin_t coins[1 + SB_N_DUST];
        for (int i = 0; i < n; i++) {
            int src;
            switch (perm) {
            case 0:  src = i; break;                       /* as listed   */
            case 1:  src = n - 1 - i; break;               /* reversed    */
            case 2:  src = (i + 7) % n; break;             /* rotated     */
            default: src = i < (n + 1) / 2 ? 2 * i         /* evens, odds */
                                           : 2 * (i - (n + 1) / 2) + 1;
            }
            coins[i] = base[src];
        }
        nodus_v2_spend_plan_t *plans = NULL;
        long cnt = 0;
        uint64_t fee = 0;
        CHECK(plan_q(&tab, coins, n, SB_AMT10, 0, 1, SB_GP, 0, 0, &plans,
                     &cnt, &fee) == 0, "(f) plan a permuted listing");
        const nodus_v2_spend_plan_t *p = &plans[0];
        int same = 1;
        if (perm == 0) {
            ref_n = p->n_in;
            for (int j = 0; j < p->n_in; j++)
                ref_nul[j] = coins[p->idx[j]].nul[0];
            ref_fee = fee;
            ref_in  = p->native_in;
            ref_ch  = p->native_change;
        } else {
            same = p->n_in == ref_n && fee == ref_fee &&
                   p->native_in == ref_in && p->native_change == ref_ch;
            for (int j = 0; same && j < p->n_in; j++)
                if (coins[p->idx[j]].nul[0] != ref_nul[j]) same = 0;
        }
        free(plans);
        CHECK(same, "(f) a permuted listing gives the identical plan");
    }
    CHECK(ref_n == (int)NODUS_V2_SPEND_MAX_IN,
          "(f) the reference plan is the swept 15-input plan");
    return 0;
}

/* (g) the change absorption: a change not above the threshold becomes fee;
 * one raw above stays a change output; never under fee_fixed or the flag */
static int t_absorb(void) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    nodus_v2_coin_t coin;
    nodus_v2_spend_plan_t *plans = NULL;
    long cnt = 0;
    uint64_t fee = 0;

    /* gas price 0: the threshold is the floor */
    syn_coin(&coin, SB_AMOUNT + SB_FLOOR + SB_D_CHANGE, 0x44);
    CHECK(plan_one(&tab, &coin, 1, SB_AMOUNT, 0, 0, &plans, &fee) == 0 &&
          plans[0].n_in == 1 && plans[0].native_change == 0 &&
          fee == SB_FLOOR + SB_D_CHANGE &&
          fee == plans[0].native_in - SB_AMOUNT,
          "(g) gp 0: a change below the floor is absorbed into the fee");
    free(plans);

    syn_coin(&coin, SB_AMOUNT + 2 * SB_FLOOR, 0x44);
    CHECK(plan_one(&tab, &coin, 1, SB_AMOUNT, 0, 0, &plans, &fee) == 0 &&
          plans[0].native_change == 0 && fee == 2 * SB_FLOOR,
          "(g) gp 0: a change of exactly the floor is absorbed");
    free(plans);

    syn_coin(&coin, SB_AMOUNT + 2 * SB_FLOOR + 1, 0x44);
    CHECK(plan_one(&tab, &coin, 1, SB_AMOUNT, 0, 0, &plans, &fee) == 0 &&
          plans[0].native_change == SB_FLOOR + 1 && fee == SB_FLOOR,
          "(g) gp 0: a change one raw above the floor is kept");
    free(plans);

    /* gas price 1: every shape prices under the floor (checked), so the
     * fee stays the floor and the threshold is the marginal per-input fee
     * of the 1-in/2-out shape */
    uint64_t u12 = 0, u22 = 0, u_top = 0;
    CHECK(units_of(&tab, 1, 2, &u12) == 0 && units_of(&tab, 2, 2, &u22) == 0 &&
          units_of(&tab, (int)NODUS_V2_SPEND_MAX_IN,
                   (int)NODUS_V2_SPEND_MAX_OUTS, &u_top) == 0 &&
          u22 > u12 && u_top < SB_FLOOR,
          "(g) gp 1: units below the floor, a positive marginal");
    const uint64_t thr = u22 - u12;
    syn_coin(&coin, SB_AMOUNT + SB_FLOOR + thr, 0x44);
    CHECK(plan_q(&tab, &coin, 1, SB_AMOUNT, 0, 1, 1, 0, 0, &plans, &cnt,
                 &fee) == 0 && plans[0].native_change == 0 &&
          fee == SB_FLOOR + thr,
          "(g) gp 1: a change of exactly the marginal fee is absorbed");
    free(plans);
    syn_coin(&coin, SB_AMOUNT + SB_FLOOR + thr + 1, 0x44);
    CHECK(plan_q(&tab, &coin, 1, SB_AMOUNT, 0, 1, 1, 0, 0, &plans, &cnt,
                 &fee) == 0 && plans[0].native_change == thr + 1 &&
          fee == SB_FLOOR,
          "(g) gp 1: a change one raw above the marginal fee is kept");
    free(plans);

    /* a fixed fee is never changed; the flag keeps the old shape */
    syn_coin(&coin, SB_AMOUNT + SB_FLOOR + SB_D_CHANGE, 0x44);
    CHECK(plan_q(&tab, &coin, 1, SB_AMOUNT, 0, 1, 0, 0, 1, &plans, &cnt,
                 &fee) == 0 && plans[0].native_change == SB_D_CHANGE &&
          fee == SB_FLOOR,
          "(g) fee_fixed: the change is kept, the fee unchanged");
    free(plans);
    syn_coin(&coin, SB_AMOUNT + SB_FLOOR + SB_D_CHANGE, 0x44);
    CHECK(plan_one(&tab, &coin, 1, SB_AMOUNT, 0, 1, &plans, &fee) == 0 &&
          plans[0].native_change == SB_D_CHANGE && fee == SB_FLOOR,
          "(g) no_dust_sweep = 1: the change is kept");
    free(plans);
    return 0;
}

/* S7/S8 against the engine: a swept 3-in envelope and an absorbed 1-out
 * envelope, both built from the seeded coins, are admitted by CheckTx */
static int t_dust_admitted(sb_chain_t *c) {
    nodus_v2_ruleset_id_t tab;
    table_ruleset(&tab);
    nodus_v2_spend_plan_t *plans = NULL;
    uint64_t fee = 0;
    nodus_v2_spend_build_req_t r;
    nodus_v2_spend_built_t b;
    nodus_v2_spend_err_t e;
    sb_stream_t s;
    uint32_t code = 99;
    uint8_t wid[64], iid[64];

    /* swept: A covers, C and B are swept (gas price 0) */
    nodus_v2_coin_t coins[3];
    int n = coins_of(c, coins);
    CHECK(plan_one(&tab, coins, n, SB_AMOUNT, 0, 0, &plans, &fee) == 0 &&
          plans[0].n_in == 3 && fee == SB_FLOOR, "S7 plan the swept spend");
    stream_init(&s, 0x44);
    build_req(&r, &tab, c, coins, &plans[0], fee, 0, &s);
    CHECK(nodus_v2_spend_build(&r, &b, &e) == 0, "S7 build the swept spend");
    CHECK(b.dec.n_in == 3 && b.dec.n_out == 2 && b.dec.fee == SB_FLOOR &&
          b.dec.out_amount[0] == SB_AMOUNT &&
          b.dec.out_amount[1] ==
              SB_COIN_A + SB_COIN_B + SB_COIN_C - SB_AMOUNT - SB_FLOOR,
          "S7 read-back: 3 inputs, recipient + the swept change");
    CHECK(dry(c->w, b.env, b.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK, "S7 the engine admits the swept spend");
    nodus_v2_spend_built_free(&b);
    free(plans);

    /* absorbed: coin D alone, its change folds into the fee */
    nodus_v2_coin_t d;
    memset(&d, 0, sizeof(d));
    memcpy(d.nul, c->nul[3], 64);
    d.amount = SB_COIN_D;
    d.kind   = 0;
    CHECK(plan_one(&tab, &d, 1, SB_AMOUNT, 0, 0, &plans, &fee) == 0 &&
          plans[0].native_change == 0 && fee == SB_FLOOR + SB_D_CHANGE,
          "S8 plan the absorbed spend");
    stream_init(&s, 0x55);
    build_req(&r, &tab, c, &d, &plans[0], fee, 0, &s);
    CHECK(nodus_v2_spend_build(&r, &b, &e) == 0, "S8 build the absorbed spend");
    CHECK(b.dec.n_in == 1 && b.dec.n_out == 1 &&
          b.dec.out_amount[0] == SB_AMOUNT &&
          b.dec.fee == SB_FLOOR + SB_D_CHANGE &&
          b.dec.fee + b.dec.out_amount[0] == SB_COIN_D,
          "S8 read-back: one output, in = amount + fee exactly");
    CHECK(dry(c->w, b.env, b.env_len, &code, wid, iid) == 0 &&
          code == NODUS_V2_TX_OK, "S8 the engine admits the absorbed spend");
    nodus_v2_spend_built_free(&b);
    free(plans);
    return 0;
}

int main(void) {
    printf("=== shared CORE SPEND builder (web wallet package c2) ===\n");
    if (keys_init() != 0) {
        fprintf(stderr, "key setup failed\n");
        return 1;
    }
    int fails = 0;
    fails += t_pins_equal_table();

    sb_chain_t c;
    if (chain_open(&c) != 0) {
        fprintf(stderr, "seeded chain setup failed\n");
        chain_close(&c);
        return 1;
    }
    fails += t_build_admitted_and_read_back(&c);
    fails += t_gas_price(&c);
    fails += t_refusals(&c);
    fails += t_sweep_cap();
    fails += t_sweep_threshold();
    fails += t_sweep_count2();
    fails += t_sweep_amount_all();
    fails += t_sweep_flag();
    fails += t_sweep_determinism();
    fails += t_absorb();
    fails += t_dust_admitted(&c);
    chain_close(&c);

    printf("=== %s: %d checks, %d failed section(s) ===\n",
           fails ? "FAIL" : "PASS", g_checks, fails);
    return fails ? 1 : 0;
}
