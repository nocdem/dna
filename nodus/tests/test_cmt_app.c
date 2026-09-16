/**
 * @file nodus/tests/test_cmt_app.c
 * @brief The Comet APPLICATION over the Ledger V2 engine
 *        (nodus_witness_cmt_app.{h,c}), the engine's COMETBFT APPLY LANE
 *        (`nodus_v2_block_t.cmt`, nodus_witness_v2_apply.c) and the
 *        host's ledger-transaction bracket
 *        (nodus_witness_cmt_host.c `apply_block`).
 *
 * ── WHAT EACH CASE PROVES ──────────────────────────────────────────────
 * Named per case. Every case drives the REAL function under test over a
 * REAL temporary SQLite database with REAL ML-DSA-87 keys; there is no
 * stand-in for anything this file is about.
 *
 * ── TWO FIXTURES, AND WHY ──────────────────────────────────────────────
 * `gfx_*` is a REAL VERSION-3 chain, derived by
 * `nodus_witness_v2_gen_derive_v3` exactly as test_v2_gen.c §10 derives
 * one and opened by hand (the production open path refuses a version-3
 * chain until W3 — nodus_witness_v2_gen.h's note on
 * `..._stored_chain_id`). The apply-lane, InitChain, Commit and bracket
 * cases run there.
 *
 * `fx_*` is a version-2 SUCCESSOR chain climbed to S14. It survives for
 * exactly TWO things the version-3 chain cannot prove, each named at its
 * case: `t_chain_id_row_branch_unchanged` (a chain that HAS a height-0
 * block row still derives its identity from that row — the branch of
 * `nodus_witness_v2_chain_id` the version-3 fallback must not disturb)
 * and the S12 half of `t_apply_entry_preconditions` (a chain below S14).
 * Every other case, the seam-backed rows included, now runs on the
 * version-3 chain: `nodus_witness_v2_chain_id` answers from the stored
 * genesis document when there is no block row
 * (nodus_witness_v2_claims.c:186-224), so the batch preflight, claim
 * admission and the capacity seam all work there.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build (no QGP_FAULT_INJECT — the
 * post-commit window is the RUNTIME field
 * `nodus_cmt_blockexec_t.test_fail_after_commit`). Environment: none.
 * SQLite >= 3.35.0, which the S14 rung enforces itself.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * One `/tmp/test_cmt_app_*` directory per fixture, removed at close. A
 * case that aborts through CHECK leaves its directory behind.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. `t_claim_items` proves ONE claim applies and ONE is refused. It
 *     does not cover the other claim refusal classes, and its "refused"
 *     claim fails at the MANIFEST lookup — the earliest of the six
 *     stages `claim_prescan_one`/`claim_execute_one` run.
 *  2. VALIDATOR UPDATES are not covered: `finalize_block` returns none
 *     by construction (R3-T), so `t_finalize_block` asserting an empty
 *     update list proves the GAP, not a capability.
 *  3. `t_prepare_fee_order` compares the returned DESCRIPTORS by
 *     pointer, which is exactly what the row promises (it borrows the
 *     request's byte views). If the row ever copied the bytes instead,
 *     the case would fail for the wrong reason and must be re-expressed
 *     as a byte comparison.
 *  3b. FOUR VACUITIES THE VERIFIER FOUND, and what closes each:
 *     the InitChain app_hash leg was tautological (`gfx_doc` fills the
 *     config from the same helper InitChain reads) — closed by reading
 *     the STORED "genesisDoc" bytes back and decoding them; the
 *     PrepareProposal drop loop was never driven (undecodable bytes are
 *     dropped before the seam is called) — closed with a decodable
 *     DUPLICATE; no second Comet block was ever applied, so
 *     `prev_block_id` was only ever the all-zero case — closed in
 *     `t_finalize_block`; and no refusal ever carried applied work away
 *     — closed by `t_per_item_rollback_after_work` (F37). Crash window
 *     (b) asserted only that `stateKey` existed; it now reads the saved
 *     State back and asserts its height.
 *  4. The per-item failure case uses bytes that carry the envelope
 *     family marker but do not decode. It proves the DECODE class and
 *     the isolation around it; the other seven `nodus_v2_tx_code_t`
 *     classes are not individually driven.
 *  5. The twin-fixture root comparison derives a SECOND chain from the
 *     same config. Two derivations of one config are byte-identical by
 *     `derive_v3`'s own contract, so the comparison is meaningful only
 *     because that contract holds — it is not re-proven here.
 *  6. THE PER-REQUEST TRANSACTION BOUND. `finalize_block` refuses a
 *     block carrying more than `NODUS_CMT_APP_MAX_TXS` items, and that
 *     bound is `NODUS_W_MAX_BLOCK_TXS` (10) — the LEDGER SEAM's cap,
 *     which D-4 rev 3 (2) retires for the Comet lane and W3 raises
 *     (register row R3-C1a-4). Until then a DECIDED block above it
 *     STOPS THE NODE. `t_finalize_block_bound` proves the refusal is
 *     real and fabricates nothing; it does NOT prove the bound is the
 *     right number, and nothing here exercises a block larger than it.
 *  7. Nothing here was RUN by its author: this package could not build
 *     or run tests. Every expectation is an expectation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_emission.h"      /* DNAC_DECIMAL_UNIT   */
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_cmt_app.h"
#include "server/nodus_server.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/vset_wire.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"               /* the LastCommit's precommits  */
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_part_set.h"           /* a COMPLETE BlockID's header  */
#include "dnac/cmt_results.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_pb_store.h"

#include "dnac/manifest_wire.h"          /* dna_claim_t, the dist helpers */
#include "dnac/block_v2.h"               /* dna_bh2_derive_chain_id       */

#include "../tests/v2_genesis_fixture.h"
#include "../tests/v2_exec_fixture.h"    /* the SCRIPTED runtime table:
                                          * envelopes with a free
                                          * fee_amount and no committee */

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

/* ══ FIXTURE LIFETIME — the convention, and its limit ════════════════
 *
 * `CHECK` returns from the case the instant it fails, so a FAILING case
 * does not reach its teardown and leaks its fixture. That is the
 * established convention of this tree's harness — test_cmt_host.c:164-171
 * has the identical macro and its 27 cases free at the end the same way
 * — and it means the suite is ASan-clean on a GREEN run, not on a red
 * one.
 *
 * A round-8 attempt to sweep leaked fixtures from `main` was WITHDRAWN as
 * unsound: every fixture here is a STACK local, so a registry of their
 * addresses dereferences dead frames after the case returns. It read a
 * recycled frame and freed a SQLite-owned pointer. Making the sweep
 * correct means heap-owning the fixtures, which is a change to every
 * case; it is not made unasked.
 */

/* ══ deterministic REAL keys — test_v2_produce.c:83-102's shape ══════ */

#define N_KEYS ((int)DNAC_COMMITTEE_SIZE)
#define TREASURY_RAW 93000000000000000ULL   /* test_v2_gen.c:66          */
#define GEN_TIME_MS  1767225600000ULL       /* test_v2_gen.c:1299        */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_KEYS];

static int make_keys(void)
{
    int i;

    for (i = 0; i < N_KEYS; i++) {
        uint8_t seed[32], full[64];

        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0) {
            return -1;
        }
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0) {
            return -1;
        }
        memcpy(g_ks[i].voter, full, 32);
    }
    return 0;
}

static void rmrf(const char *path)
{
    char cmd[300];

    if (!path || !path[0]) {
        return;               /* a fixture that failed before mkdtemp */
    }
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int   rc  = sqlite3_exec(db, sql, NULL, NULL, &err);

    if (err) {
        sqlite3_free(err);
    }
    return rc == SQLITE_OK ? 0 : -1;
}

static int64_t q1(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t       v  = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    if (sqlite3_step(st) == SQLITE_ROW) {
        v = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

/* test_v2_gen.c:94-103 */
static void hex_lower_fp(const uint8_t *src, size_t src_len, uint8_t *out129)
{
    static const char hexd[] = "0123456789abcdef";
    uint8_t d[64];
    int i;

    qgp_sha3_512(src, src_len, d);
    for (i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[d[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[d[i] & 0x0F];
    }
    out129[128] = 0;
}

/* ══ FIXTURE A — a REAL version-3 chain ══════════════════════════════ */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b)
{
    if (b) {
        free(b->cfg);
        free(b->allocs);
        memset(b, 0, sizeof(*b));
    }
}

/**
 * test_v2_gen.c:202-262 + :1345-1355, with ONE difference: the
 * validators carry the REAL ML-DSA-87 public keys of `g_ks`, not
 * synthetic bytes. That is what lets this file build a chain_config
 * envelope whose committee approvals actually verify — the committee is
 * derived from these same validator rows.
 */
static int cfg_make_v3_real(cfgbox_t *b)
{
    nodus_v2_gen_config_t *c;
    uint16_t k;

    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));      /* ~240 KB: never stack */
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) {
        cfg_free(b);
        return -1;
    }
    c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 1ULL;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = (uint16_t)N_KEYS;
    for (k = 0; k < (uint16_t)N_KEYS; k++) {
        nodus_v2_gen_validator_t *v = &c->validators[k];
        size_t bb;

        memcpy(v->pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE);
        for (bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    /* The claim pipeline binds SHA3-512(claimant pubkey) to this field
     * byte-for-byte (nodus_witness_v2_claims.c:510-517), so binding it
     * to a key THIS FILE HOLDS is what makes a valid claim buildable
     * here. ONE allocation means the distribution tree has one leaf and
     * a proof carries no siblings. */
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    c->genesis_time_ms = GEN_TIME_MS;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        cfg_free(b);
        return -1;
    }
    return 0;
}

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
} gfx_t;

/**
 * Derive a version-3 chain and OPEN IT BY HAND.
 *
 * `nodus_witness_create_chain_db` cannot be used: it derives the chain's
 * role, finds the pure-V2 manifest tag and then calls the height-0
 * chain_id, which a version-3 chain cannot answer — the refusal
 * nodus_witness_v2_gen.h records as a W3 item. So the handle is built
 * field by field, and EVERY field set here is one the app/apply path
 * reads:
 *   db                            every statement
 *   data_path                     nothing in this path, set for parity
 *   v2_successor                  the app's bind gate and the verify divert
 *   v2_chain32                    the successor identity cache
 *   v2_ingress_armed              the verify divert's arm gate
 *   my_id / server->identity      the produce seam's signer identity
 *   cached_committee_epoch_start  the committee cache's "cold" marker
 */
static int gfx_open(gfx_t *g, const char *tag)
{
    char path[600];
    int  i;

    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real(&g->box) != 0) {
        return -1;
    }
    if (nodus_witness_v2_gen_v3_validate(g->box.cfg) != 0) {
        return -1;
    }
    snprintf(g->dir, sizeof(g->dir), "/tmp/test_cmt_app_%s_XXXXXX", tag);
    if (!mkdtemp(g->dir)) {
        return -1;
    }
    if (nodus_witness_v2_gen_derive_v3(g->dir, g->box.cfg, g->chain32) != 0) {
        return -1;
    }
    /* "the database is named witness_<chain_id[0..15] hex>.db — a file
     * SELECTION convention, never the identity" (gen.h) */
    {
        char hex[33];

        for (i = 0; i < 16; i++) {
            snprintf(hex + 2 * i, 3, "%02x", g->chain32[i]);
        }
        hex[32] = '\0';
        snprintf(path, sizeof(path), "%s/witness_%s.db", g->dir, hex);
    }
    g->w   = calloc(1, sizeof(*g->w));           /* multi-MB: never stack */
    g->srv = calloc(1, sizeof(*g->srv));
    if (!g->w || !g->srv) {
        return -1;
    }
    if (sqlite3_open_v2(path, &g->w->db, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        return -1;
    }
    snprintf(g->w->data_path, sizeof(g->w->data_path), "%s", g->dir);
    g->w->cached_committee_epoch_start = UINT64_MAX;
    g->w->v2_successor     = true;
    g->w->v2_ingress_armed = true;
    memcpy(g->w->v2_chain32, g->chain32, 32);
    memcpy(g->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(g->srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(g->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    g->w->server = g->srv;
    memcpy(g->w->my_id, g_ks[0].voter, 32);
    return 0;
}

static void gfx_close(gfx_t *g)
{
    if (g->w) {
        if (g->w->db) {
            sqlite3_close(g->w->db);
        }
        free(g->w);
        g->w = NULL;
    }
    free(g->srv);
    g->srv = NULL;
    cfg_free(&g->box);
    rmrf(g->dir);
}

/* ══ FIXTURE B — a version-2 successor chain at S14 ══════════════════
 * The seam-backed rows need the height-0 block row (see the header). */

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;
    char             dir[128];
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];
    uint8_t          genesis_id[64];
} fixture_t;

static int seed_validators(fixture_t *fx)
{
    int i, b;

    for (i = 0; i < N_KEYS; i++) {
        dnac_validator_record_t v;
        uint8_t fpr[64];

        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_ks[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake         = 0;
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        if (qgp_sha3_512(g_ks[i].pk, DNAC_PUBKEY_SIZE, fpr) != 0) {
            return -1;
        }
        {
            static const char hexd[] = "0123456789abcdef";

            for (b = 0; b < 64; b++) {
                v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
                v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
            }
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(fx->w, &v) != 0) {
            return -1;
        }
    }
    return 0;
}

/* test_v2_produce.c:149-192, then the S14 rung. ORDER IS LOAD-BEARING:
 * the V2 genesis runs at S9 (the engine's genesis gate accepts S9-S12)
 * and the S9 rung REFUSES a populated v2_blocks, so the climb to S14
 * comes after. */
static int fx_open(fixture_t *fx, const char *tag)
{
    uint8_t cid16[16];
    uint8_t vset[64];

    memset(fx, 0, sizeof(*fx));
    fx->w   = calloc(1, sizeof(*fx->w));
    fx->srv = calloc(1, sizeof(*fx->srv));
    if (!fx->w || !fx->srv) {
        return -1;
    }
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_cmt_app_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) {
        return -1;
    }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(cid16, 0x5D, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0 ||
        nodus_chain_config_db_migrate(fx->w) != 0 ||
        nodus_witness_db_migrate_v2s9(fx->w) != 0) {
        return -1;
    }
    if (run_sql(fx->w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
            " total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 0, 0, 0, 0, zeroblob(64), 0)") != 0) {
        return -1;
    }
    if (seed_validators(fx) != 0 ||
        nodus_witness_vset_commit_genesis(fx->w, 1) != 0) {
        return -1;
    }
    memset(vset, 0x77, sizeof(vset));
    if (v2x_genesis_min(fx->w, vset, fx->genesis_id, NULL) != 0 ||
        nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) {
        return -1;
    }
    memcpy(fx->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(fx->srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(fx->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    fx->w->server = fx->srv;
    memcpy(fx->w->my_id, g_ks[0].voter, 32);
    fx->w->v2_successor = true;
    memcpy(fx->w->v2_chain32, fx->chain_id, 32);
    fx->w->v2_ingress_armed = true;
    if (nodus_witness_db_migrate_v2s14(fx->w) != 0) {
        return -1;
    }
    return 0;
}

static void fx_close(fixture_t *fx)
{
    if (fx->w) {
        if (fx->w->db) {
            sqlite3_close(fx->w->db);
        }
        free(fx->w);
        fx->w = NULL;
    }
    free(fx->srv);
    fx->srv = NULL;
    rmrf(fx->dir);
}

/* ══ a REAL chain_config envelope — test_v2_produce.c:256-410 ════════
 * Copied (that file's copy is static and its fixture type differs); the
 * logic is that function's, retyped over a `nodus_witness_t *`. */

#define CC_CALL_LEN 41u
#define CC_UNITS    200000u

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
} test_env_t;

static int build_cc_env(nodus_witness_t *w, const uint8_t chain32[32],
                        uint64_t nonce, test_env_t *out)
{
    dna_domain_manifest_t     sys_man;
    nodus_committee_member_t *cm = NULL;
    dna_env_preflight_t      *pf = NULL;
    uint8_t                  *fps = NULL, *auth = NULL, *env_bytes = NULL;
    uint8_t                  *call = NULL;
    uint64_t                  tip = 0;
    int                       cmn = 0, rc = -1, bad = 0;

    memset(out, 0, sizeof(*out));
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys_man,
                                 NULL) != 0) {
        return -1;
    }
    /* A version-3 chain has no block rows at all, so the tip read
     * answers 0 and the candidate height is 1 — which is the first
     * Comet block's height. */
    if (nodus_witness_v2_tip_height(w, &tip) != 0) {
        return -1;
    }
    if (nodus_committee_get_for_block_alloc(w, tip, &cm, &cmn) != 0 ||
        cmn < 1) {
        return -1;
    }
    fps  = malloc((size_t)cmn * 64);
    pf   = calloc(1, sizeof(*pf));
    call = calloc(1, CC_CALL_LEN);
    do {
        uint8_t  set_hash[64];
        uint64_t appr_epoch, nv = 7, eff, vb, sa = 1;
        uint32_t quorum, emitted = 0;
        size_t   auth_len, env_len = 0, used = 0, sl = 0;
        dna_env_leg_in_t  leg;
        dna_env_in_t      env_in;
        dna_env_leg_ctx_t lctx;
        uint8_t          *p;
        int i, s;

        if (!fps || !pf || !call) {
            break;
        }
        for (i = 0; i < cmn; i++) {
            if (qgp_sha3_512(cm[i].pubkey, DNAC_PUBKEY_SIZE,
                             fps + (size_t)i * 64) != 0) {
                bad = 1;
                break;
            }
        }
        if (bad ||
            nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                        (uint32_t)cmn, set_hash) != 0) {
            break;
        }
        appr_epoch = nodus_v2_epoch_for_height(tip);
        quorum     = dna_bft_quorum((uint32_t)cmn);
        eff = tip + 100000;
        vb  = eff + 100000;
        call[0] = 4;                        /* DNAC_CFG_TARGET_ACTIVE_COUNT */
        for (i = 0; i < 8; i++) call[1 + i]  = (uint8_t)(nv    >> (56 - 8 * i));
        for (i = 0; i < 8; i++) call[9 + i]  = (uint8_t)(eff   >> (56 - 8 * i));
        for (i = 0; i < 8; i++) call[17 + i] = (uint8_t)(nonce >> (56 - 8 * i));
        for (i = 0; i < 8; i++) call[25 + i] = (uint8_t)(sa    >> (56 - 8 * i));
        for (i = 0; i < 8; i++) call[33 + i] = (uint8_t)(vb    >> (56 - 8 * i));

        auth_len = 1 + NODUS_RT_AUTH_SIGNER_LEN + 2 +
                   (size_t)quorum * NODUS_RT_AUTH_APPROVAL_LEN;
        auth = calloc(1, auth_len);
        if (!auth) {
            break;
        }
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
        leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
        leg.hdr.ruleset_version      = sys_man.ruleset_version;
        leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_CC_V1;
        leg.hdr.call_len             = CC_CALL_LEN;
        leg.hdr.auth_len             = (uint32_t)auth_len;
        leg.hdr.res_max_effects      = 4;
        leg.hdr.res_max_effect_bytes = 4096;
        leg.call_data                = call;
        leg.auth_data                = auth;

        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height       = 0;
        env_in.fee_amount          = 0;   /* a CHAIN_CONFIG leg requires 0 */
        env_in.res_max_total_units = CC_UNITS;
        env_in.leg_count           = 1;
        env_in.legs                = &leg;

        if (dna_env_encoded_size(&leg, 1, &env_len) != 0) {
            break;
        }
        env_bytes = malloc(env_len);
        if (!env_bytes) {
            break;
        }
        lctx.domain_id       = DNA_DOMAIN_SYSTEM;
        lctx.ruleset_version = sys_man.ruleset_version;
        memcpy(lctx.ruleset_hash, sys_man.ruleset_hash, 64);

        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len ||
            dna_env_preflight(env_bytes, env_len, chain32, tip + 1, &lctx,
                              1, pf) != DNA_ENV_PF_OK) {
            break;
        }
        p = auth;
        p[0] = 1;
        memcpy(p + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
        if (qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl, pf->auth_digest[0],
                           64, g_ks[0].sk) != 0) {
            break;
        }
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)(quorum >> 8);
        p[1] = (uint8_t)quorum;
        p += 2;
        for (s = 0; s < cmn && emitted < quorum; s++) {
            int     ki = -1;
            uint8_t adg[64];
            int     k;

            for (k = 0; k < N_KEYS; k++) {
                if (memcmp(cm[s].pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE) == 0) {
                    ki = k;
                    break;
                }
            }
            if (ki < 0 ||
                nodus_rt_cc_approval_digest(pf->auth_digest[0], set_hash,
                                            appr_epoch, (uint16_t)s,
                                            adg) != 0) {
                bad = 1;
                break;
            }
            p[0] = (uint8_t)((uint16_t)s >> 8);
            p[1] = (uint8_t)s;
            sl = 0;
            if (qgp_dsa87_sign(p + 2, &sl, adg, 64, g_ks[ki].sk) != 0) {
                bad = 1;
                break;
            }
            p += NODUS_RT_AUTH_APPROVAL_LEN;
            emitted++;
        }
        if (bad || emitted != quorum) {
            break;
        }
        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len ||
            dna_env_preflight(env_bytes, env_len, chain32, tip + 1, &lctx,
                              1, pf) != DNA_ENV_PF_OK) {
            break;
        }
        out->bytes = env_bytes;
        out->len   = env_len;
        memcpy(out->wire_id, pf->wire_id, 64);
        memcpy(out->intent_id, pf->intent_id, 64);
        env_bytes = NULL;
        rc = 0;
    } while (0);

    free(env_bytes);
    free(call);
    free(auth);
    free(pf);
    free(fps);
    free(cm);
    return rc;
}

/* Bytes that classify as an ENVELOPE (the family marker is present) and
 * do not decode — the DECODE class of nodus_v2_tx_code_t. */
static const uint8_t POISON[20] = {
    'D','N','A','.','E','N','V','W','I','R','E','.','v','1', 0, 0,
    0xFF, 0xFF, 0xFF, 0xFF
};

/* ══ the blockexec over a fixture, with the REAL application ═════════ */

static int t_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
    return CMT_OK;
}

/* Defined below; `exec_init` needs the COMPLETED document too, so that
 * the cometbft State it makes carries the same AppHash the derivation
 * stored rather than the config's zeros. */
static int gfx_doc(gfx_t *g, cmt_genesis_doc_t *doc,
                   cmt_genesis_validator_t *gvals);

typedef struct {
    nodus_cmt_store_t      *store;
    nodus_cmt_blockexec_t  *be;
    nodus_cmt_app_ledger_t *ledger;
    nodus_cmt_app_t         app_if;
    nodus_cmt_mempool_if_t  mp_if;
    nodus_cmt_evpool_if_t   ev_if;
    cmt_state_storage_t    *stor;
    cmt_state_t            *state;
    cmt_valset_scratch_t   *vscratch;
    cmt_state_block_scratch_t *bscratch;
    cmt_genesis_doc_t       doc;
    cmt_genesis_validator_t gvals[DNAC_COMMITTEE_SIZE];
    cmt_block_t            *blk;
    cmt_pb_bytes_t          txs[NODUS_CMT_APP_MAX_TXS];
    /* ⚠ THE BLOCK BORROWS ITS LastCommit BY POINTER
     * (`cmt_block_t.last_commit`, cmt_block.h:783 — "a POINTER, as the
     * reference's is"; `cmt_state_make_block` stores what it is given,
     * cmt_state.h:367-375). So the commit and its signature array MUST
     * outlive the block. They live here, with the block, and NOT on
     * `exec_make_block`'s frame — which is exactly the bug that made
     * block 2 read a commit size of 94090696762656 out of a dead
     * stack. */
    cmt_commit_t            last_commit;
    /* CMT_VALSET_MAX is 128 and a `cmt_commit_sig_t` carries a
     * 4 627-byte ML-DSA-87 signature, so this array is ~600 KB — heap,
     * never the frame `exec_t` lives on (the repo's own rule). */
    cmt_commit_sig_t       *last_sigs;
    uint8_t                 chain_id[32];   /* the vote sign bytes' */
    /* the block's PART SET, which is where a complete BlockID's
     * PartSetHeader comes from — heap, one 64 KiB part per slot */
    uint8_t                *part_scratch;
    size_t                  part_scratch_cap;
    cmt_part_t             *parts;
    size_t                  parts_cap;
} exec_t;

#define APP_PARTS_CAP 8u

static void exec_free(exec_t *x)
{
    if (x->be) {
        nodus_cmt_blockexec_release(x->be);
        free(x->be);
    }
    if (x->store) {
        nodus_cmt_store_release(x->store);
        free(x->store);
    }
    free(x->ledger);
    free(x->stor);
    free(x->state);
    free(x->vscratch);
    free(x->bscratch);
    free(x->blk);
    free(x->last_sigs);
    free(x->parts);
    free(x->part_scratch);
    memset(x, 0, sizeof(*x));
}

/**
 * The store, the REAL application table, the block executor and a
 * cometbft State made from the chain's OWN genesis document — the same
 * shape test_cmt_host.c:800-830 builds, over a real ledger.
 */
static int exec_init(exec_t *x, gfx_t *g)
{
    nodus_cmt_host_limits_t lim;

    memset(x, 0, sizeof(*x));
    x->store    = calloc(1, sizeof(*x->store));
    x->be       = calloc(1, sizeof(*x->be));
    x->ledger   = calloc(1, sizeof(*x->ledger));   /* ~85 KB            */
    x->stor     = calloc(1, sizeof(*x->stor));
    x->state    = calloc(1, sizeof(*x->state));
    x->vscratch = calloc(1, sizeof(*x->vscratch));
    x->bscratch = calloc(1, sizeof(*x->bscratch));
    x->blk      = calloc(1, sizeof(*x->blk));
    x->last_sigs = calloc(CMT_VALSET_MAX, sizeof(*x->last_sigs));
    x->parts_cap        = APP_PARTS_CAP;
    x->parts            = calloc(APP_PARTS_CAP, sizeof(*x->parts));
    x->part_scratch_cap = (size_t)APP_PARTS_CAP * CMT_BLOCK_PART_SIZE_BYTES;
    x->part_scratch     = malloc(x->part_scratch_cap);
    if (!x->store || !x->be || !x->ledger || !x->stor || !x->state ||
        !x->vscratch || !x->bscratch || !x->blk || !x->last_sigs ||
        !x->parts || !x->part_scratch) {
        return -1;
    }
    if (nodus_cmt_store_init(x->store, g->w->db, false) != CMT_OK) {
        return -1;
    }
    memcpy(x->chain_id, g->chain32, 32);   /* what a vote is signed over */
    /* the PORT's own genesis document, projected from the very config
     * this chain was derived from, with the app_hash the derivation
     * completed it with (gfx_doc) */
    if (gfx_doc(g, &x->doc, x->gvals) != 0) {
        return -1;
    }
    if (nodus_cmt_app_ledger_init(x->ledger, g->w, &x->doc) != CMT_OK ||
        nodus_cmt_app_ledger_build(&x->app_if, x->ledger) != CMT_OK) {
        return -1;
    }
    x->mp_if = nodus_cmt_nop_mempool;
    x->ev_if = nodus_cmt_empty_evpool;
    memset(&lim, 0, sizeof(lim));
    lim.max_txs      = NODUS_CMT_APP_MAX_TXS;
    lim.tx_arena_cap = 2u * 1024u * 1024u;
    lim.max_evidence = 4;
    if (nodus_cmt_blockexec_init(x->be, x->store, &x->app_if, &x->mp_if,
                                 &x->ev_if, NULL, NULL, t_now, NULL, NULL,
                                 NULL, &lim) != CMT_OK) {
        return -1;
    }
    if (cmt_state_init(x->state, x->stor) != CMT_OK ||
        cmt_state_make_genesis(&x->doc, NULL, NULL, x->vscratch, x->state)
            != CMT_OK) {
        return -1;
    }
    return nodus_cmt_ss_save(x->store, x->state) == CMT_OK ? 0 : -1;
}

/**
 * THE BLOCK'S REAL BlockID — hash AND part-set header.
 *
 * `block_id_of`, test_cmt_host.c:3896-3910. A BlockID carrying only a
 * hash is NEITHER complete nor zero, and that is not a nuance: the
 * reference's `BlockID.IsComplete()` requires a tmhash-sized hash, a
 * PartSetHeader with `Total > 0` AND a tmhash-sized part-set hash
 * (types/block.go:1504-1508), and `Vote.CommitSig()` PANICS on anything
 * in between — "expected BlockID to be either empty or complete"
 * (types/vote.go:112-114). The port turns that panic into the CMT_REJECT
 * `cmt_vote_commit_sig` returns, which is what refused every precommit
 * in round 7.
 */
static int exec_block_id(exec_t *x, cmt_block_t *b, cmt_block_id_t *out)
{
    cmt_part_set_t ps;

    memset(out, 0, sizeof(*out));
    if (cmt_block_hash(b, out->hash) != CMT_OK) {
        return -1;
    }
    out->hash_len = CMT_TMHASH_SIZE;
    if (cmt_block_make_part_set(b, CMT_BLOCK_PART_SIZE_BYTES,
                                x->part_scratch, x->part_scratch_cap,
                                x->parts, x->parts_cap, &ps) != CMT_OK) {
        return -1;
    }
    return cmt_part_set_header(&ps, &out->part_set_header) == CMT_OK ? 0 : -1;
}

/** The completeness the reference demands (block.go:1504-1508), asserted
 *  where a failure is still nameable. */
static bool block_id_is_complete(const cmt_block_id_t *bid)
{
    return bid->hash_len == CMT_TMHASH_SIZE &&
           bid->part_set_header.total > 0 &&
           bid->part_set_header.hash_len == CMT_TMHASH_SIZE;
}

/* The ONE signer the fixture's validators use: an ML-DSA-87 signature
 * over the canonical vote sign bytes, the shape test_cmt_host.c:919-935
 * uses. `ctx` is the `keyset_t` whose address the vote carries. */
static int app_sign_vote(void *ctx, const uint8_t *chain_id,
                         size_t chain_id_len, cmt_pb_vote_t *v)
{
    const keyset_t *k = (const keyset_t *)ctx;
    uint8_t         sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t          sb_len = 0, sig_len = 0;

    if (cmt_vote_sign_bytes(chain_id, chain_id_len, v, sb, sizeof(sb),
                            &sb_len) != CMT_OK) {
        return CMT_FAULT;
    }
    if (qgp_dsa87_sign(v->signature, &sig_len, sb, sb_len, k->sk) != 0) {
        return CMT_FAULT;
    }
    v->signature_len = sig_len;
    return CMT_OK;
}

/**
 * A REAL LastCommit for `height` over `bid` — one precommit per
 * validator of the set the STATE STORE holds at `height`, each signed by
 * the key whose address it carries.
 *
 * `nodus_cmt_build_last_commit_info` requires exactly one signature slot
 * per validator and panics otherwise (host.c:502-508, the port of
 * state/execution.go:458-469), so a block above the initial height
 * cannot be applied without this. The apply path reads only the SIZE and
 * each slot's `block_id_flag` — it does not verify these signatures,
 * because `ApplyVerifiedBlock` is by definition past verification — but
 * the commit is built REAL anyway, so the fixture never asserts a shape
 * consensus could not produce.
 *
 * The signature array lives in `exec_t`, not here: the commit is
 * borrowed by pointer.
 */
static int exec_make_last_commit(exec_t *x, int64_t height,
                                 const cmt_block_id_t *bid)
{
    cmt_validator_set_t  vals;
    cmt_validator_t     *storage = NULL;
    cmt_vote_t          *vote = NULL;
    cmt_time_t           ts;
    size_t               i;
    int                  rc = -1;

    storage = calloc(CMT_VALSET_MAX, sizeof(*storage));
    vote    = calloc(1, sizeof(*vote));
    if (!storage || !vote) {
        goto done;
    }
    /* A named failure instead of a silent -1 from the conversion below:
     * an incomplete BlockID is exactly what round 7 fed this helper. */
    if (!block_id_is_complete(bid)) {
        fprintf(stderr, "exec_make_last_commit: the BlockID is incomplete "
                "(hash_len %zu, part total %u, part hash_len %zu) — "
                "cmt_vote_commit_sig refuses anything that is neither "
                "complete nor zero (vote.go:112-114)\n",
                bid->hash_len, (unsigned)bid->part_set_header.total,
                bid->part_set_header.hash_len);
        goto done;
    }
    /* A REAL instant, not zero: above the initial height
     * `cmt_state_make_block` derives the new block's time from this
     * commit with `cmt_state_median_time` (cmt_state.c:255-268, the port
     * of BFT-time), so the stamps carried here become block 2's
     * timestamp. The chain's own last block time is the honest choice
     * and is always a valid instant. */
    ts = x->state->last_block_time;
    if (cmt_validator_set_init(&vals, storage, CMT_VALSET_MAX) != CMT_OK ||
        nodus_cmt_ss_load_validators(x->store, height, &vals) != CMT_OK) {
        goto done;
    }
    if (vals.validators_len > CMT_VALSET_MAX) {
        goto done;
    }
    for (i = 0; i < vals.validators_len; i++) {
        const keyset_t *k = NULL;
        int             j;

        /* the validator's address IS SHA3-512(pubkey)[0..31]
         * (`cmt_address_hash`), which is what `keyset_t.voter` holds */
        for (j = 0; j < N_KEYS; j++) {
            if (memcmp(g_ks[j].voter, vals.validators[i].address, 32) == 0) {
                k = &g_ks[j];
                break;
            }
        }
        if (!k) {
            goto done;
        }
        memset(vote, 0, sizeof(*vote));
        memcpy(vote->validator_address, k->voter, 32);
        vote->validator_address_len = 32;
        vote->validator_index = (int32_t)i;
        vote->height          = height;
        vote->round           = 0;
        vote->type            = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
        vote->block_id        = *bid;
        vote->timestamp       = ts;
        {
            bool recoverable = false;

            if (cmt_sign_and_check_vote(vote, app_sign_vote, (void *)k,
                                        x->chain_id, 32,
                                        /*extensions_enabled=*/false,
                                        &recoverable) != CMT_OK) {
                goto done;
            }
        }
        /* a complete BlockID gives a COMMIT entry (vote.go:101-123) */
        if (cmt_vote_commit_sig(vote, &x->last_sigs[i]) != CMT_OK) {
            goto done;
        }
    }
    memset(&x->last_commit, 0, sizeof(x->last_commit));
    x->last_commit.height         = height;
    x->last_commit.round          = 0;
    x->last_commit.block_id       = *bid;
    x->last_commit.signatures     = x->last_sigs;
    x->last_commit.signatures_cap = CMT_VALSET_MAX;
    x->last_commit.signatures_len = vals.validators_len;
    rc = 0;
done:
    free(vote);
    free(storage);
    return rc;
}

/**
 * MakeBlock at `height` over `n` transaction descriptors.
 *
 * `last_commit` is ZEROED into the fixture's own storage for the initial
 * height (the reference's empty-but-not-nil commit, which
 * `BuildLastCommitInfo` returns before ever reading —
 * state/execution.go:451-455) and must already have been built by
 * `exec_make_last_commit` for any height above it.
 */
static int exec_make_block(exec_t *x, int64_t height, size_t n)
{
    cmt_data_t data;

    memset(&data, 0, sizeof(data));
    data.txs     = x->txs;
    data.txs_cap = NODUS_CMT_APP_MAX_TXS;
    data.txs_len = n;
    if (height == x->state->initial_height) {
        memset(&x->last_commit, 0, sizeof(x->last_commit));
        x->last_commit.signatures     = x->last_sigs;
        x->last_commit.signatures_cap = CMT_VALSET_MAX;
        x->last_commit.signatures_len = 0;
    }
    memset(x->blk, 0, sizeof(*x->blk));
    return cmt_state_make_block(x->state, height, &data, &x->last_commit,
                                NULL,
                                x->state->validators.proposer.address,
                                x->state->validators.proposer.address_len,
                                x->bscratch, x->blk)
               == CMT_OK ? 0 : -1;
}

/* Scratch store for the stored-document read in t_init_chain_match; a
 * file-scope object so the case does not put a multi-KB store on its
 * frame. */
static nodus_cmt_store_t g_doc_store;

/* ══ CASES — InitChain ═══════════════════════════════════════════════ */

/**
 * Project the chain's config onto the PORT's genesis document, WITH the
 * app_hash the derivation completed it with.
 *
 * `app_hash` and `chain_id` are OUTPUTS of the derivation, not inputs:
 * an operator's config carries zeros and
 * `nodus_witness_v2_gen_v3_validate` does not constrain them
 * (nodus_witness_v2_gen.h:637-639). `derive_v3` writes the completed
 * document into `cmt_state` under "genesisDoc" but does not write back
 * into the caller's config, so a document projected straight from
 * `box.cfg` carries a ZERO app_hash — which is precisely what made the
 * round-3 InitChain cases fail. Filling it from the ledger's committed
 * root reproduces what the derivation stored, and keeps the comparison
 * meaningful: the mismatch cases below still flip a byte.
 */
static int gfx_doc(gfx_t *g, cmt_genesis_doc_t *doc,
                   cmt_genesis_validator_t *gvals)
{
    if (nodus_witness_v2_committed_global_root(g->w, g->box.cfg->app_hash)
        != 0) {
        return -1;
    }
    return nodus_witness_v2_gen_to_cmt_doc(g->box.cfg, doc, gvals,
                                           DNAC_COMMITTEE_SIZE);
}

static int init_chain_inputs(gfx_t *g, cmt_genesis_doc_t *doc,
                             nodus_abci_request_init_chain_t *req,
                             cmt_pb_validator_update_t *vals,
                             cmt_genesis_validator_t *gvals, size_t *out_n)
{
    size_t i;

    if (gfx_doc(g, doc, gvals) != 0) {
        return -1;
    }
    for (i = 0; i < doc->validators_len; i++) {
        memset(&vals[i], 0, sizeof(vals[i]));
        vals[i].pub_key = doc->validators[i].pub_key;
        vals[i].power   = doc->validators[i].power;
    }
    *out_n = doc->validators_len;
    memset(req, 0, sizeof(*req));
    memcpy(req->chain_id, g->chain32, 32);
    req->chain_id_len   = 32;
    req->initial_height = doc->initial_height;
    req->validators     = vals;
    req->validators_len = *out_n;
    return 0;
}

/** A matching genesis is accepted, returns the ledger's committed global
 *  root as app_hash and asks for NO validator and NO parameter update
 *  (D-23 rev 5 (7)). The document's power is in WHOLE units. */
static int t_init_chain_match(void)
{
    gfx_t                            g;
    cmt_genesis_doc_t                doc;
    nodus_abci_request_init_chain_t  req;
    nodus_abci_response_init_chain_t resp;
    nodus_cmt_app_ledger_t          *app;
    cmt_pb_validator_update_t        vals[DNAC_COMMITTEE_SIZE];
    cmt_genesis_validator_t          gvals[DNAC_COMMITTEE_SIZE];
    uint8_t                          root[64];
    size_t                           n = 0;

    CHECK(gfx_open(&g, "init_ok") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");

    /* THE PROPERTY InitChain EXISTS FOR, asserted against the STORED
     * document rather than a projection of our own config.
     *
     * `gfx_doc` fills the config's app_hash from the same helper
     * InitChain compares against, so the app_hash leg of the cases below
     * is a tautology on its own. This block closes it: the bytes the
     * DERIVATION wrote under "genesisDoc" are read back, decoded
     * strictly, and their app_hash is compared against the ledger's
     * committed global root. If those two ever disagree, a real node
     * would refuse its own genesis at startup. */
    {
        nodus_v2_gen_config_t *stored = calloc(1, sizeof(*stored));
        nodus_v2_gen_alloc_t  *sallocs = NULL;
        const uint8_t         *bytes = NULL;
        size_t                 len = 0;
        uint8_t                root[64];

        CHECK(stored != NULL, "alloc");
        CHECK(nodus_cmt_store_init(&g_doc_store, g.w->db, false) == CMT_OK,
              "the store over the derived chain");
        CHECK(nodus_cmt_store_get(&g_doc_store, /*state_table=*/true,
                                  "genesisDoc", &bytes, &len) == CMT_OK &&
              len > 0,
              "the derivation stored a genesis document");
        CHECK(nodus_witness_v2_gen_v3_decode(bytes, len, stored, &sallocs)
                  == 0,
              "and it decodes strictly as a version-3 document");
        CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0, "root");
        CHECK(memcmp(stored->app_hash, root, 64) == 0,
              "the STORED document's app_hash IS the ledger's committed "
              "global root");
        CHECK(memcmp(stored->chain_id, g.chain32, 32) == 0,
              "and its chain id is the derived one");
        free(sallocs);
        free(stored);
        nodus_cmt_store_release(&g_doc_store);
    }

    CHECK(init_chain_inputs(&g, &doc, &req, vals, gvals, &n) == 0, "inputs");
    CHECK(n == (size_t)DNAC_COMMITTEE_SIZE, "seven validators");
    CHECK(vals[0].power == (int64_t)(DNAC_SELF_STAKE_AMOUNT /
                                     DNAC_DECIMAL_UNIT),
          "the document's power is the stake in WHOLE units");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_OK,
          "a matching genesis is accepted");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0, "root");
    CHECK(resp.app_hash_len == 64 && memcmp(resp.app_hash, root, 64) == 0,
          "app_hash is the ledger's committed global root");
    CHECK(resp.validators_len == 0 && resp.validators == NULL,
          "no validator update");
    CHECK(resp.has_consensus_params == false, "no consensus-param update");
    free(app);
    gfx_close(&g);
    return 0;
}

/** Each comparison refuses on its own, as CMT_FAULT. */
static int t_init_chain_mismatches(void)
{
    gfx_t                            g;
    cmt_genesis_doc_t                doc;
    nodus_abci_request_init_chain_t  req;
    nodus_abci_response_init_chain_t resp;
    nodus_cmt_app_ledger_t          *app;
    cmt_pb_validator_update_t        vals[DNAC_COMMITTEE_SIZE];
    cmt_genesis_validator_t          gvals[DNAC_COMMITTEE_SIZE];
    size_t                           n = 0;

    CHECK(gfx_open(&g, "init_bad") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(init_chain_inputs(&g, &doc, &req, vals, gvals, &n) == 0, "inputs");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_OK, "baseline");

    doc.app_hash[0] ^= 0xFF;
    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_FAULT,
          "a wrong app_hash is refused");
    doc.app_hash[0] ^= 0xFF;

    req.chain_id[0] ^= 0xFF;
    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_FAULT,
          "a wrong chain id is refused");
    req.chain_id[0] ^= 0xFF;

    vals[0].power += 1;
    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_FAULT,
          "a wrong validator power is refused");
    vals[0].power -= 1;

    req.validators_len = n - 1;
    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_FAULT,
          "a short validator set is refused");
    req.validators_len = n;

    CHECK(nodus_cmt_app_init_chain(app, &req, &resp) == CMT_OK,
          "the restored inputs still match");
    free(app);
    gfx_close(&g);
    return 0;
}

/* ══ CASES — FinalizeBlock through the REAL host ═════════════════════ */

/** One 64-byte column of the `v2_blocks` row at `height`. 0 / -1. */
static int row_blob(nodus_witness_t *w, const char *col, uint64_t height,
                    uint8_t out[64])
{
    char          sql[128];
    sqlite3_stmt *st = NULL;
    int           ok = 0;

    snprintf(sql, sizeof(sql),
             "SELECT %s FROM v2_blocks WHERE global_height = ?1", col);
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/** Does `cmt_state` hold a row under this key? */
static int has_state_key(sqlite3 *db, const char *key)
{
    sqlite3_stmt *st = NULL;
    int           n  = 0;

    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM cmt_state WHERE key = ?1",
                           -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        n = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return n;
}

/**
 * ONE decided block, applied through the REAL
 * `nodus_cmt_host_apply_verified_block`: the bracket opens the
 * transaction, `FinalizeBlock` drives the ledger's Comet lane, the
 * response row joins the same transaction, and `Commit` closes it.
 *
 * Proves the Comet row shape of D-17 rev 7 (6): `block_id` is the hash
 * consensus passed in, `prev_block_id` is 64 zero bytes at the first
 * block, `vset_hash` is the request's NextValidatorsHash (R3-C1a-10 —
 * the only validator hash RequestFinalizeBlock carries), `global_root` is
 * what `app_hash` returned, and no `header`/`qc`/`commit_cert` column
 * exists to write.
 */
static int t_finalize_block(void)
{
    gfx_t      g;
    exec_t     x;
    test_env_t env;
    cmt_block_id_t bid;
    uint8_t    hash[CMT_TMHASH_SIZE];
    sqlite3_stmt *st = NULL;
    int        ok = 0;

    CHECK(gfx_open(&g, "fin") == 0, "version-3 fixture");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 0,
          "a version-3 chain starts with NO block rows");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");
    CHECK(build_cc_env(g.w, g.chain32, 0x5001, &env) == 0,
          "a real chain_config envelope");

    x.txs[0].data = env.bytes;
    x.txs[0].len  = env.len;
    CHECK(exec_make_block(&x, 1, 1) == 0, "block 1");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "the block's COMPLETE BlockID (hash + part-set header)");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);

    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK,
          "the decided block applies");
    CHECK(sqlite3_get_autocommit(g.w->db) != 0,
          "Commit closed the bracket's transaction");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1,
          "the ledger committed exactly one block row");

    CHECK(sqlite3_prepare_v2(g.w->db,
            "SELECT block_id, prev_block_id, vset_hash, global_root, "
            "tx_count FROM v2_blocks WHERE global_height = 1",
            -1, &st, NULL) == SQLITE_OK, "prepare");
    if (sqlite3_step(st) == SQLITE_ROW) {
        static const uint8_t ZERO64[64] = { 0 };

        ok = (sqlite3_column_bytes(st, 0) == 64 &&
              memcmp(sqlite3_column_blob(st, 0), hash, 64) == 0 &&
              sqlite3_column_bytes(st, 1) == 64 &&
              memcmp(sqlite3_column_blob(st, 1), ZERO64, 64) == 0 &&
              sqlite3_column_bytes(st, 2) == 64 &&
              memcmp(sqlite3_column_blob(st, 2),
                     x.blk->header.next_validators_hash, 64) == 0 &&
              sqlite3_column_int64(st, 4) == 1);
    }
    sqlite3_finalize(st);
    CHECK(ok,
          "block_id is the hash consensus gave FinalizeBlock, "
          "prev_block_id is 64 zero bytes at the first block, vset_hash "
          "vset_hash is the request's NextValidatorsHash (R3-C1a-10)");

    /* the state store carries the response the reference stores */
    CHECK(has_state_key(g.w->db, "abciResponsesKey:1") == 1,
          "the FinalizeBlock response is stored under the reference's key");
    CHECK(has_state_key(g.w->db, "stateKey") == 1,
          "store.Save(state) ran after the COMMIT");

    /* ── A SECOND BLOCK: the chain actually LINKS ────────────────────
     * One block never exercises `prev_block_id` as anything but the
     * all-zero first-block case, nor the height-continuity path, nor the
     * duplicate-id probe. Height 2 does all three. */
    {
        test_env_t env2;
        uint8_t    prev[64];

        CHECK(build_cc_env(g.w, g.chain32, 0x5002, &env2) == 0,
              "a second envelope");
        /* Block 2 needs a REAL LastCommit for block 1: the host requires
         * one signature slot per validator of the set at height 1 and
         * FAULTs otherwise (host.c:502-508 = execution.go:458-469).
         * `bid` still carries block 1's BlockID. */
        CHECK(exec_make_last_commit(&x, 1, &bid) == 0,
              "a precommit from every validator for block 1");
        CHECK(x.last_commit.signatures_len == (size_t)DNAC_COMMITTEE_SIZE,
              "one signature slot per validator");
        x.txs[0].data = env2.bytes;
        x.txs[0].len  = env2.len;
        CHECK(exec_make_block(&x, 2, 1) == 0, "block 2");
        CHECK(exec_block_id(&x, x.blk, &bid) == 0 &&
              block_id_is_complete(&bid), "block 2's COMPLETE BlockID");
        CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
                  == CMT_OK, "block 2 applies");
        CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 2,
              "two committed block rows");
        CHECK(row_blob(g.w, "prev_block_id", 2, prev) == 0, "prev of block 2");
        CHECK(memcmp(prev, hash, 64) == 0,
              "block 2's prev_block_id IS block 1's block_id");
        CHECK(has_state_key(g.w->db, "abciResponsesKey:2") == 1,
              "and its response is stored under its own key");

        free(env2.bytes);
    }

    /* ── THE DUPLICATE-BlockID PROBE, driven DIRECTLY ────────────────
     *
     * It cannot be reached through the host, and that is a property of
     * the design rather than a gap here. `build_finalize_request` takes
     * the hash from the BLOCK — `block_hash_of(block)`, the port of
     * `Hash: block.Hash()` (state/execution.go:225) — while the
     * `block_id` ARGUMENT only ever reaches `updateState`'s LastBlockID.
     * So overwriting that argument's hash changes nothing the engine
     * sees: the round-8 version of this case did exactly that and block
     * 3 applied cleanly under its own hash. Under cometbft the shape is
     * unreachable in principle too, because the header hash commits the
     * height — two heights cannot share an id.
     *
     * The probe therefore guards a DIRECT caller of the engine, and that
     * is who drives it here: the same database after blocks 1 and 2, a
     * transaction the CALLER owns (the Comet lane opens none), and a
     * block at height 3 carrying block 1's hash. The wrapper maps the
     * probe's verdict to INTERNAL_FAULT, because a decided block is
     * never refused (apply.h's REFUSAL rule). */
    {
        nodus_v2_block_t     *dup = calloc(1, sizeof(*dup));
        nodus_v2_tx_result_t  res[2];
        test_env_t            env3;
        nodus_v2_envelope_t   one;

        CHECK(dup != NULL, "alloc");
        CHECK(build_cc_env(g.w, g.chain32, 0x5003, &env3) == 0,
              "an envelope for the probe block");
        one.env_bytes = env3.bytes;
        one.env_len   = env3.len;
        dup->global_height = 3;
        dup->epoch         = nodus_v2_epoch_for_height(3);
        dup->envs          = &one;
        dup->n_envs        = 1;
        dup->cmt.on        = true;
        memcpy(dup->cmt.block_hash, hash, 64);      /* block 1's id AGAIN */
        dup->cmt.results     = res;
        dup->cmt.results_cap = 2;

        CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0,
              "the transaction the Comet entry requires");
        CHECK(nodus_witness_v2_apply_block(g.w, dup)
                  == NODUS_V2_INTERNAL_FAULT,
              "a block_id already committed at another height is refused");
        CHECK(run_sql(g.w->db, "ROLLBACK") == 0, "roll it back");
        CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 2,
              "and nothing was committed for it");
        free(env3.bytes);
        free(dup);
    }

    free(env.bytes);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * PER-ITEM ISOLATION. A block carrying [valid, undecodable] commits:
 * the valid item is applied, the bad one gets a nonzero code, its rows
 * are gone with its SAVEPOINT — and the block's committed global root
 * equals the root of the SAME chain given only the valid item.
 *
 * The twin fixture is what makes the last assertion real: a root that
 * merely "looked right" could still have carried the refused item.
 */
static int t_per_item_failure(void)
{
    gfx_t      g, twin;
    exec_t     x, tx;
    test_env_t env;
    cmt_block_id_t bid;
    uint8_t    hash[CMT_TMHASH_SIZE];
    uint8_t    root_mixed[64], root_clean[64];
    int        rc;

    CHECK(gfx_open(&g, "item") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec");
    CHECK(build_cc_env(g.w, g.chain32, 0x6001, &env) == 0, "envelope");

    x.txs[0].data = env.bytes;    x.txs[0].len = env.len;
    x.txs[1].data = POISON;       x.txs[1].len = sizeof(POISON);
    CHECK(exec_make_block(&x, 1, 2) == 0, "block 1 with two items");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);

    rc = nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state);
    CHECK(rc == CMT_OK, "a bad ITEM does not fail the block");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1, "committed");
    CHECK(q1(g.w->db, "SELECT tx_count FROM v2_blocks "
                      "WHERE global_height = 1") == 1,
          "only the APPLIED item is counted in the block row");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_tx_index") == 1,
          "the refused item wrote no wire index row");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_intent_index") == 1,
          "and no intent index row");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root_mixed) == 0,
          "the root the mixed block COMMITTED");

    /* THE TWIN: the same chain, the SAME BYTES, without the poison.
     *
     * The envelope is REUSED rather than rebuilt, and that is not a
     * shortcut — two builds CANNOT be byte-identical. ML-DSA-87 signing
     * in this tree is randomized, so signing one message twice gives two
     * different signatures, and every approval in a chain_config
     * envelope is a fresh signature. The bytes are valid on the twin
     * because the two derivations produce the SAME CHAIN ID (same
     * config → same document hash), and the chain id is what the
     * envelope's commitments bind.
     *
     * What this proves is the intent season's property: the committed
     * roots bind the DERIVED identities, not the authorization witness,
     * so two chains that applied the same intent agree — here, both the
     * global root and `tx_root`. */
    CHECK(gfx_open(&twin, "twin") == 0, "twin fixture");
    CHECK(memcmp(twin.chain32, g.chain32, 32) == 0,
          "the two derivations produce the same chain id");
    CHECK(exec_init(&tx, &twin) == 0, "twin blockexec");
    tx.txs[0].data = env.bytes;  tx.txs[0].len = env.len;
    CHECK(exec_make_block(&tx, 1, 1) == 0, "twin block 1");
    CHECK(exec_block_id(&tx, tx.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);
    CHECK(nodus_cmt_host_apply_verified_block(tx.be, &bid, tx.blk, tx.state)
              == CMT_OK, "the twin block applies");
    CHECK(nodus_witness_v2_committed_global_root(twin.w, root_clean) == 0,
          "twin root");
    CHECK(memcmp(root_mixed, root_clean, 64) == 0,
          "the refused item left NO trace in the committed state");
    {
        uint8_t txr_mixed[64], txr_clean[64];

        CHECK(row_blob(g.w, "tx_root", 1, txr_mixed) == 0 &&
              row_blob(twin.w, "tx_root", 1, txr_clean) == 0, "tx_roots");
        CHECK(memcmp(txr_mixed, txr_clean, 64) == 0,
              "and tx_root commits the same ONE wire id on both chains");
    }

    exec_free(&tx);
    gfx_close(&twin);
    free(env.bytes);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/** The Comet apply entry refuses outside a transaction, and at S12. */
static int t_apply_entry_preconditions(void)
{
    gfx_t             g;
    fixture_t         fx;
    nodus_v2_block_t *blk;
    nodus_v2_tx_result_t results[4];

    CHECK(gfx_open(&g, "pre") == 0, "version-3 fixture");
    blk = calloc(1, sizeof(*blk));
    CHECK(blk != NULL, "alloc");
    blk->global_height = 1;
    blk->epoch = nodus_v2_epoch_for_height(1);
    blk->cmt.on = true;
    blk->cmt.results = results;
    blk->cmt.results_cap = 4;
    CHECK(sqlite3_get_autocommit(g.w->db) != 0, "no transaction is open");
    CHECK(nodus_witness_v2_apply_block(g.w, blk) == NODUS_V2_INTERNAL_FAULT,
          "the Comet entry refuses outside the host's transaction");
    CHECK(strstr(blk->out_reason, "outside the host's transaction") != NULL,
          "and says so");
    gfx_close(&g);

    /* the same entry at S12 — the version-2 fixture BEFORE its S14 rung
     * would be ideal, but fx_open climbs it; a chain at S12 is built by
     * asking the schema module directly. */
    CHECK(fx_open(&fx, "pre_s12") == 0, "version-2 fixture at S14");
    CHECK(run_sql(fx.w->db, "PRAGMA user_version = 12") == 0,
          "pretend this node is still at S12");
    CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "a host transaction");
    memset(blk, 0, sizeof(*blk));
    blk->global_height = 1;
    blk->epoch = nodus_v2_epoch_for_height(1);
    blk->cmt.on = true;
    blk->cmt.results = results;
    blk->cmt.results_cap = 4;
    CHECK(nodus_witness_v2_apply_block(fx.w, blk) == NODUS_V2_INTERNAL_FAULT,
          "the Comet entry refuses at S12");
    CHECK(strstr(blk->out_reason, "schema version") != NULL, "and says so");
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "clean up");
    free(blk);
    fx_close(&fx);
    return 0;
}

/**
 * CRASH WINDOW (a): a fault BEFORE the COMMIT, raised AFTER an item has
 * already applied. The host rolls its transaction back and the database
 * is byte-identical — no block row, no `abciResponsesKey` row, and,
 * crucially, no trace of the item that DID apply.
 *
 * The fault point is the engine's own `V2AP_FAIL_AFTER_TX_INDEX`
 * (nodus_witness_v2_apply.h) — it fires after phase 12 has written the
 * applied item's index rows and BEFORE phase 13 inserts the block row,
 * so the assertion below proves the rollback of APPLIED WORK rather
 * than an early refusal that never touched anything. The application
 * carries it into the block through its test-only `test_fail_at` field,
 * which is the only way a test can reach a point inside the apply: the
 * block struct is built inside `finalize_block`.
 */
static int t_crash_window_before_commit(void)
{
    gfx_t      g;
    exec_t     x;
    test_env_t env;
    uint8_t    before[64], after[64];
    cmt_block_id_t bid;
    uint8_t    hash[CMT_TMHASH_SIZE];
    int        rc;

    CHECK(gfx_open(&g, "crash_a") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec");
    CHECK(build_cc_env(g.w, g.chain32, 0x8001, &env) == 0, "envelope");
    CHECK(v2x_db_digest(g.w, before) == 0, "digest before");

    x.txs[0].data = env.bytes;
    x.txs[0].len  = env.len;
    CHECK(exec_make_block(&x, 1, 1) == 0, "block 1 with ONE valid item");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);

    /* the item applies, its index rows are written, and THEN the engine
     * is interrupted */
    x.ledger->test_fail_at = V2AP_FAIL_AFTER_TX_INDEX;

    rc = nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state);
    CHECK(rc == CMT_FAULT, "the node stops rather than half-applying");
    CHECK(sqlite3_get_autocommit(g.w->db) != 0,
          "the host rolled its transaction back");
    CHECK(v2x_db_digest(g.w, after) == 0, "digest after");
    CHECK(memcmp(before, after, 64) == 0,
          "and the database is byte-identical — the APPLIED item's rows "
          "went with the rollback");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 0, "no block row");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_tx_index") == 0,
          "and no index row for the item that had applied");
    CHECK(has_state_key(g.w->db, "abciResponsesKey:1") == 0,
          "and no stored response");

    free(env.bytes);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * The application's per-request transaction BOUND (register row
 * R3-C1a-4). A decided block above it stops the node — the bound is the
 * ledger seam's `NODUS_W_MAX_BLOCK_TXS`, which D-4 rev 3 (2) retires for
 * the Comet lane and W3 raises. Until then this is a real refusal and
 * the node must not pretend otherwise.
 *
 * The request is built WITHOUT writing past `exec_t.txs` — the round-3
 * version of this case set `data.txs_len` one past the array and smashed
 * the stack, which is what produced the SIGSEGV in
 * `sqlite3_get_autocommit`: the handle it read had been overwritten, not
 * closed.
 */
static int t_finalize_block_bound(void)
{
    gfx_t                                g;
    cmt_genesis_doc_t                    doc;
    cmt_genesis_validator_t              gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t              *app;
    nodus_abci_request_finalize_block_t  req;
    nodus_abci_response_finalize_block_t resp;
    cmt_pb_bytes_t                       txs[NODUS_CMT_APP_MAX_TXS + 1];
    size_t                               i;

    CHECK(gfx_open(&g, "bound") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");

    for (i = 0; i < (size_t)NODUS_CMT_APP_MAX_TXS + 1; i++) {
        txs[i].data = POISON;
        txs[i].len  = sizeof(POISON);
    }
    memset(&req, 0, sizeof(req));
    req.txs     = txs;
    req.txs_len = (size_t)NODUS_CMT_APP_MAX_TXS + 1;
    req.height  = 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_finalize_block(app, &req, &resp) == CMT_FAULT,
          "a decided block above the bound stops the node");
    CHECK(resp.tx_results_len == 0 && resp.app_hash_len == 0,
          "and it fabricates no results and no app_hash");
    CHECK(sqlite3_get_autocommit(g.w->db) != 0,
          "it opened no transaction of its own");

    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * CRASH WINDOW (b): the post-commit hook. The ledger row AND the
 * response row are durable, `stateKey` is not — the three heights the
 * Handshaker's replay.go:437-453 branch expects.
 */
static int t_crash_window_after_commit(void)
{
    gfx_t      g;
    exec_t     x;
    test_env_t env;
    cmt_block_id_t bid;
    uint8_t    hash[CMT_TMHASH_SIZE];
    int        rc;

    CHECK(gfx_open(&g, "crash_b") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec");
    CHECK(build_cc_env(g.w, g.chain32, 0x7001, &env) == 0, "envelope");
    CHECK(has_state_key(g.w->db, "stateKey") == 1,
          "the fixture saved a State at height 0");

    x.txs[0].data = env.bytes;
    x.txs[0].len  = env.len;
    CHECK(exec_make_block(&x, 1, 1) == 0, "block 1");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);

    x.be->test_fail_after_commit = true;
    rc = nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state);
    CHECK(rc == CMT_FAULT, "the node stops in the window");
    CHECK(sqlite3_get_autocommit(g.w->db) != 0, "the COMMIT had run");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1,
          "the ledger block IS durable");
    CHECK(has_state_key(g.w->db, "abciResponsesKey:1") == 1,
          "and so is the stored FinalizeBlock response");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks "
                      "WHERE global_height = 1") == 1,
          "the ledger tip is height 1");
    /* stateKey must still name the PREVIOUS height — that IS the
     * Handshaker's "we ran Commit, but didn't save the state" branch,
     * and asserting merely that the row EXISTS would pass even if
     * store.Save had run. The saved State's LastBlockHeight is read
     * back and must be 0 (the fixture saved it before block 1), while
     * the ledger tip is 1. Healing it is the Handshaker's job and that
     * is package C1c's. */
    {
        cmt_state_storage_t *stor = calloc(1, sizeof(*stor));
        cmt_state_t         *st = calloc(1, sizeof(*st));

        CHECK(stor && st, "alloc");
        CHECK(cmt_state_init(st, stor) == CMT_OK, "state storage");
        CHECK(nodus_cmt_ss_load(x.store, st) == CMT_OK,
              "the saved State loads");
        CHECK(st->last_block_height == 0,
              "stateKey still names height 0 — Commit ran, store.Save did "
              "not");
        free(st);
        free(stor);
    }
    CHECK(q1(g.w->db, "SELECT MAX(global_height) FROM v2_blocks") == 1,
          "while the LEDGER tip is height 1 — the two heights the "
          "Handshaker's replay.go:437-453 branch expects");

    free(env.bytes);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/** Commit outside the host's transaction is a node-local fault; inside
 *  one it is the COMMIT (D-23 rev 5 (5)). */
static int t_commit(void)
{
    gfx_t                        g;
    cmt_genesis_doc_t            doc;
    nodus_cmt_app_ledger_t      *app;
    nodus_abci_response_commit_t resp;
    cmt_genesis_validator_t      gvals[DNAC_COMMITTEE_SIZE];

    CHECK(gfx_open(&g, "commit") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");

    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_commit(app, &resp) == CMT_FAULT,
          "Commit outside a transaction is a node-local fault");

    CHECK(run_sql(g.w->db, "CREATE TABLE t_marker (v INTEGER)") == 0, "ddl");
    CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0, "the host's BEGIN");
    CHECK(run_sql(g.w->db, "INSERT INTO t_marker (v) VALUES (7)") == 0,
          "a write that joins the transaction");
    memset(&resp, 0xEE, sizeof(resp));
    CHECK(nodus_cmt_app_commit(app, &resp) == CMT_OK, "Commit closes it");
    CHECK(sqlite3_get_autocommit(g.w->db) != 0, "the connection is free");
    CHECK(resp.retain_height == 0, "retain_height 0: no pruning in W2");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM t_marker") == 1,
          "the joined write is durable");
    CHECK(nodus_cmt_app_commit(app, &resp) == CMT_FAULT,
          "a second Commit has no transaction to close");
    free(app);
    gfx_close(&g);
    return 0;
}

/* ══ CASES — the seam-backed rows, on the version-2 fixture ══════════ */

static int t_check_tx(void)
{
    gfx_t                       g;
    cmt_genesis_doc_t           doc;
    nodus_cmt_app_ledger_t     *app;
    cmt_mem_app_t               mem;
    cmt_mem_request_check_tx_t  req;
    cmt_mem_response_check_tx_t res;
    test_env_t                  env;
    cmt_genesis_validator_t     gvals[DNAC_COMMITTEE_SIZE];

    /* On the VERSION-3 chain: the seam reaches
     * `nodus_witness_v2_chain_id`, which now answers from the stored
     * genesis document when there is no height-0 block row. */
    CHECK(gfx_open(&g, "checktx") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(nodus_cmt_app_ledger_build_mempool(&mem, app) == CMT_OK, "table");
    CHECK(mem.check_tx && mem.error && mem.flush, "every row is filled");
    CHECK(build_cc_env(g.w, g.chain32, 0x1001, &env) == 0, "envelope");

    memset(&req, 0, sizeof(req));
    req.tx = env.bytes;
    req.tx_len = env.len;
    req.type = CMT_MEM_CHECK_TX_TYPE_NEW;
    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "the request is served");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "a valid envelope is admitted");
    CHECK(res.gas_wanted == 0, "gas_wanted is 0 while MaxGas is -1");

    /* The last byte of the envelope is the last byte of the last
     * committee approval's ML-DSA-87 signature, and the envelope carries
     * EXACTLY `dna_bft_quorum(7)` = 5 approvals (build_cc_env emits
     * `quorum` and fails otherwise), so breaking one leaves four — below
     * quorum. Nothing in the ADMISSION lane looked at it before this
     * round: the preflight decides nothing about authorization
     * (env_preflight.h:57-63) and the `wire_id` comparison is a
     * tautology because check_tx derives the id from the bytes it is
     * checking. It is `nodus_witness_v2_env_authorize` that refuses it. */
    env.bytes[env.len - 1] ^= 0xFF;
    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "served");
    CHECK(res.code != CMT_MEM_CODE_TYPE_OK,
          "a corrupted APPROVAL SIGNATURE is refused at admission");
    env.bytes[env.len - 1] ^= 0xFF;

    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "served");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK,
          "and the restored bytes are admitted again");

    req.tx = POISON;
    req.tx_len = sizeof(POISON);
    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "served");
    CHECK(res.code != CMT_MEM_CODE_TYPE_OK, "undecodable bytes are refused");

    free(env.bytes);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * The OTHER branch of the same function: a chain that HAS a height-0
 * block row still derives its identity from that row, byte-for-byte as
 * before the version-3 fallback was added
 * (nodus_witness_v2_claims.c:186-224). This is the one case that must
 * run on the version-2 fixture — the version-3 chain has no such row,
 * so it cannot exercise this path at all.
 */
static int t_chain_id_row_branch_unchanged(void)
{
    fixture_t fx;
    uint8_t   from_row[DNA_CHAIN_ID_LEN];
    uint8_t   derived[DNA_CHAIN_ID_LEN];

    CHECK(fx_open(&fx, "chainid") == 0, "version-2 fixture");
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_blocks "
                       "WHERE global_height = 0") == 1,
          "this chain HAS a height-0 block row");
    CHECK(nodus_witness_v2_chain_id(fx.w, from_row) == 0, "it answers");
    CHECK(dna_bh2_derive_chain_id(fx.genesis_id, derived) == 0, "derive");
    CHECK(memcmp(from_row, derived, DNA_CHAIN_ID_LEN) == 0,
          "and the answer is still the genesis block id's derivation, "
          "not the stored document's");
    fx_close(&fx);
    return 0;
}

static int t_prepare_proposal(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    nodus_cmt_app_ledger_t                 *app;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    cmt_pb_bytes_t                          txs[3];
    test_env_t                              env;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];

    CHECK(gfx_open(&g, "prepare") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(build_cc_env(g.w, g.chain32, 0x2002, &env) == 0, "envelope");

    txs[0].data = POISON;      txs[0].len = sizeof(POISON);
    txs[1].data = env.bytes;   txs[1].len = env.len;
    txs[2].data = POISON;      txs[2].len = sizeof(POISON);
    memset(&req, 0, sizeof(req));
    req.txs = txs;
    req.txs_len = 3;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == 1, "the chain_config transaction rides alone");
    CHECK(resp.txs[0].len == env.len &&
          memcmp(resp.txs[0].data, env.bytes, env.len) == 0,
          "and it is the chain_config transaction that survives");

    txs[0].data = POISON; txs[0].len = sizeof(POISON);
    req.txs_len = 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK, "answers");
    CHECK(resp.txs_len == 0,
          "an entry the engine would refuse is dropped, not proposed");

    /* THE SEAM'S DROP LOOP, actually driven.
     *
     * The POISON case above never reaches it: undecodable bytes are
     * dropped while the candidates are being classified, so the seam is
     * called with an empty set. Here BOTH entries decode and both are
     * individually valid — they are the SAME envelope twice — so the
     * seam is what refuses, naming the SECOND as the duplicate
     * (ERR_DUP / ERR_DUP_INTENT, nodus_witness_v2_env.h). The loop must
     * drop that one and re-run, leaving the envelope proposed ONCE and
     * still in its request position. */
    txs[0].data = env.bytes; txs[0].len = env.len;
    txs[1].data = env.bytes; txs[1].len = env.len;
    req.txs_len = 2;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == 1,
          "the seam named the duplicate and the drop loop removed it");
    CHECK(resp.txs[0].data == env.bytes && resp.txs[0].len == env.len,
          "and the surviving copy is the envelope itself");

    txs[0].data = env.bytes; txs[0].len = env.len;
    req.txs_len = 1;
    req.max_tx_bytes = 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK, "answers");
    CHECK(resp.txs_len == 0, "a transaction over the byte budget is dropped");

    req.txs_len = (size_t)NODUS_CMT_APP_MAX_TXS + 1;
    req.max_tx_bytes = 22020096;
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_FAULT,
          "a request above the bound faults");

    free(env.bytes);
    free(app);
    gfx_close(&g);
    return 0;
}

static int t_process_proposal(void)
{
    gfx_t                                  g;
    cmt_genesis_doc_t                      doc;
    nodus_cmt_app_ledger_t                *app;
    nodus_abci_request_process_proposal_t  req;
    nodus_abci_response_process_proposal_t resp;
    cmt_pb_bytes_t                         txs[2];
    test_env_t                             env;
    cmt_genesis_validator_t                gvals[DNAC_COMMITTEE_SIZE];

    CHECK(gfx_open(&g, "process") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(build_cc_env(g.w, g.chain32, 0x3003, &env) == 0, "envelope");

    txs[0].data = env.bytes; txs[0].len = env.len;
    memset(&req, 0, sizeof(req));
    req.txs = txs;
    req.txs_len = 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_process_proposal(app, &req, &resp) == CMT_OK, "answers");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "a proposal the engine would apply is accepted");

    txs[0].data = POISON; txs[0].len = sizeof(POISON);
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_process_proposal(app, &req, &resp) == CMT_OK, "answers");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "a proposal the engine would refuse is rejected");

    req.txs_len = 0;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_process_proposal(app, &req, &resp) == CMT_OK, "answers");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "an empty proposal is accepted");

    req.txs_len = (size_t)NODUS_CMT_APP_MAX_TXS + 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_process_proposal(app, &req, &resp) == CMT_OK,
          "an over-bound proposal does NOT stop the node");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "it is rejected instead");

    free(env.bytes);
    free(app);
    gfx_close(&g);
    return 0;
}

/** The vote-extension pair is the reference's BaseApplication default. */
static int t_vote_extensions(void)
{
    fixture_t                                   fx;
    cmt_genesis_doc_t                           doc;
    nodus_cmt_app_ledger_t                     *app;
    nodus_abci_request_extend_vote_t            evreq;
    nodus_abci_response_extend_vote_t           evresp;
    nodus_abci_request_verify_vote_extension_t  vreq;
    nodus_abci_response_verify_vote_extension_t vresp;

    CHECK(fx_open(&fx, "voteext") == 0, "version-2 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    memset(&doc, 0, sizeof(doc));
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &doc) == CMT_OK, "bind");
    memset(&evreq, 0, sizeof(evreq));
    memset(&evresp, 0xAA, sizeof(evresp));
    CHECK(nodus_cmt_app_extend_vote(app, &evreq, &evresp) == CMT_OK, "extend");
    CHECK(evresp.vote_extension.len == 0, "the extension is empty");
    memset(&vreq, 0, sizeof(vreq));
    memset(&vresp, 0, sizeof(vresp));
    CHECK(nodus_cmt_app_verify_vote_extension(app, &vreq, &vresp) == CMT_OK,
          "verify");
    CHECK(vresp.status == NODUS_ABCI_VERIFY_STATUS_ACCEPT, "ACCEPT");
    free(app);
    fx_close(&fx);
    return 0;
}

/**
 * A CLAIM IS AN ITEM. One valid claim against the chain's own genesis
 * distribution applies inside its own SAVEPOINT and the block commits;
 * a second claim whose manifest is not committed here is refused with
 * code CLAIM (8), rolled back, and the block STILL commits.
 *
 * The genesis carries exactly one allocation, bound to `g_ks[0]`'s
 * public key (cfg_make_v3_real), so the distribution tree has one leaf
 * and the claim's inclusion proof carries no siblings.
 */
static int t_claim_items(void)
{
    gfx_t       g;
    exec_t      x;
    dna_claim_t *good, *bad;
    uint8_t     mh[64], leaf_hash[64];
    uint8_t     cbytes[DNA_CLAIM_MAX_WIRE], bbytes[DNA_CLAIM_MAX_WIRE];
    size_t      clen = 0, blen = 0;
    cmt_block_id_t bid;
    uint8_t     hash[CMT_TMHASH_SIZE];
    int         rc;

    CHECK(gfx_open(&g, "claim") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec");
    good = calloc(1, sizeof(*good));      /* ~5 KB each: never on the stack */
    bad  = calloc(1, sizeof(*bad));
    CHECK(good && bad, "alloc");

    /* the committed genesis manifest — seq 0, the one C1b's genesis
     * commits (nodus_witness_v2_claims.h:137-140) */
    {
        dna_gman_t m;

        CHECK(nodus_witness_v2_manifest_load(g.w, 0, &m) == 0,
              "the genesis manifest is committed at seq 0");
        CHECK(dna_gman_hash(&m, mh) == 0, "its hash");
        CHECK(m.dist_present == 1, "it carries a distribution section");
    }

    /* the ONE leaf, exactly as the engine derives it */
    {
        dna_dist_leaf_t leaf;

        memset(&leaf, 0, sizeof(leaf));
        leaf.leaf_version = DNA_DIST_VERSION;
        /* the config's source_id is a FIXED 64 bytes
         * (NODUS_V2_GEN_SRCID_LEN, nodus_witness_v2_gen.h:246); the
         * leaf's is length-prefixed up to 128
         * (DNA_DIST_SRCID_MAX, manifest_wire.h:279) */
        leaf.source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
        memcpy(leaf.source_id, g.box.allocs[0].source_id,
               NODUS_V2_GEN_SRCID_LEN);
        leaf.source_amount = g.box.allocs[0].amount;
        memcpy(leaf.dest_binding, g.box.allocs[0].dest_binding, 64);
        CHECK(dna_dist_leaf_hash(&leaf, leaf_hash) == 0, "leaf hash");

        good->claim_version = DNA_CLAIM_VERSION;
        memcpy(good->chain_id, g.chain32, DNA_CHAIN_ID_LEN);
        memcpy(good->manifest_hash, mh, 64);
        good->leaf_index    = 0;
        good->source_id_len = leaf.source_id_len;
        memcpy(good->source_id, leaf.source_id, leaf.source_id_len);
        good->source_amount = leaf.source_amount;
        memcpy(good->dest_binding, leaf.dest_binding, 64);
        good->n_siblings = 0;             /* a one-leaf tree */
        good->auth_mode  = DNA_CLAIMAUTH_DNA_NATIVE;
        memcpy(good->pubkey, g_ks[0].pk, QGP_DSA87_PUBLICKEYBYTES);
    }
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t  pre_len = 0, siglen = 0;

        CHECK(dna_claim_preimage(good, pre, &pre_len) == 0, "preimage");
        CHECK(qgp_dsa87_sign(good->signature, &siglen, pre, pre_len,
                             g_ks[0].sk) == 0 &&
              siglen == DNA_CLAIM_SIG_LEN, "the claimant signs it");
    }
    CHECK(dna_claim_encode(good, cbytes, sizeof(cbytes), &clen) == 0,
          "the claim encodes");

    /* the same claim against a manifest this chain never committed */
    memcpy(bad, good, sizeof(*bad));
    bad->manifest_hash[0] ^= 0xFF;
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t  pre_len = 0, siglen = 0;

        CHECK(dna_claim_preimage(bad, pre, &pre_len) == 0, "preimage");
        CHECK(qgp_dsa87_sign(bad->signature, &siglen, pre, pre_len,
                             g_ks[0].sk) == 0, "signed");
    }
    CHECK(dna_claim_encode(bad, bbytes, sizeof(bbytes), &blen) == 0,
          "it encodes too — it is REFUSED for its manifest, not its shape");

    x.txs[0].data = cbytes; x.txs[0].len = clen;
    x.txs[1].data = bbytes; x.txs[1].len = blen;
    CHECK(exec_make_block(&x, 1, 2) == 0, "block 1 with two claims");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);

    rc = nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state);
    CHECK(rc == CMT_OK, "a refused CLAIM does not fail the block");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1, "committed");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_claims_spent") == 1,
          "exactly ONE claim was spent — the refused one left no row");

    free(bad);
    free(good);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * A PER-ITEM REFUSAL THAT CARRIES WORK AWAY.
 *
 * The other refusal cases refuse an item BEFORE it mutates anything — a
 * decode failure, a manifest miss — so they prove the code and the
 * result shape but not the rollback. This one interrupts an item that
 * has ALREADY APPLIED AN EFFECT: the engine's own `V2AP_FAIL_AFTER_
 * EFFECT_APPLY` (F37, apply.h:390) stops the effect list after the
 * effect named by `fail_effect_index` of the item named by
 * `fail_env_index`, and the `ERR_INJECTED` it produces rides the
 * ordinary deterministic-verdict abort (apply.c:1418-1451) — so the
 * rollback proven here is the one every real rejection takes.
 *
 * Block [A, B], both valid, F37 on A: A must be coded EXEC (7) with its
 * mutations gone, B must apply, and the committed state must equal a
 * twin chain given [B] ALONE. The last assertion is the one that
 * matters — it says A's applied effect left NO residue, not merely that
 * A was reported as failed.
 */
static int t_per_item_rollback_after_work(void)
{
    gfx_t      g, twin;
    exec_t     x, tx;
    test_env_t ea, eb;
    cmt_block_id_t bid;
    uint8_t    hash[CMT_TMHASH_SIZE];
    uint8_t    root_mixed[64], root_clean[64];
    uint8_t    txr_mixed[64], txr_clean[64];

    CHECK(gfx_open(&g, "f37") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec");
    CHECK(build_cc_env(g.w, g.chain32, 0x9001, &ea) == 0, "envelope A");
    CHECK(build_cc_env(g.w, g.chain32, 0x9002, &eb) == 0, "envelope B");

    x.txs[0].data = ea.bytes; x.txs[0].len = ea.len;
    x.txs[1].data = eb.bytes; x.txs[1].len = eb.len;
    CHECK(exec_make_block(&x, 1, 2) == 0, "block 1 with two valid items");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);

    /* interrupt A after its FIRST effect has been applied */
    x.ledger->test_fail_at           = V2AP_FAIL_AFTER_EFFECT_APPLY;
    x.ledger->test_fail_env_index    = 0;
    x.ledger->test_fail_effect_index = 0;

    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK, "an interrupted ITEM does not fail the block");
    CHECK(x.ledger->fb_results[0].code == NODUS_V2_TX_ERR_EXEC,
          "item A is coded EXEC (7)");
    CHECK(x.ledger->fb_results[1].code == NODUS_V2_TX_OK, "item B applied");
    CHECK(x.ledger->fb_results[1].gas_wanted > 0,
          "and B still reserved from the budget A's abort restored");
    CHECK(q1(g.w->db, "SELECT tx_count FROM v2_blocks "
                      "WHERE global_height = 1") == 1,
          "the block row counts ONE applied item");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root_mixed) == 0,
          "the committed root");
    CHECK(row_blob(g.w, "tx_root", 1, txr_mixed) == 0, "tx_root");

    /* the twin: the SAME B bytes alone (rebuilding would re-sign, and
     * ML-DSA-87 signing is randomized — see t_per_item_failure) */
    CHECK(gfx_open(&twin, "f37twin") == 0, "twin fixture");
    CHECK(memcmp(twin.chain32, g.chain32, 32) == 0, "same chain id");
    CHECK(exec_init(&tx, &twin) == 0, "twin blockexec");
    tx.txs[0].data = eb.bytes; tx.txs[0].len = eb.len;
    CHECK(exec_make_block(&tx, 1, 1) == 0, "twin block 1");
    CHECK(exec_block_id(&tx, tx.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    memcpy(hash, bid.hash, CMT_TMHASH_SIZE);
    CHECK(nodus_cmt_host_apply_verified_block(tx.be, &bid, tx.blk, tx.state)
              == CMT_OK, "the twin block applies");
    CHECK(nodus_witness_v2_committed_global_root(twin.w, root_clean) == 0,
          "twin root");
    CHECK(row_blob(twin.w, "tx_root", 1, txr_clean) == 0, "twin tx_root");

    CHECK(memcmp(root_mixed, root_clean, 64) == 0,
          "the interrupted item's APPLIED EFFECT left no residue in the "
          "committed state");
    CHECK(memcmp(txr_mixed, txr_clean, 64) == 0,
          "and tx_root commits B alone on both chains");

    free(eb.bytes);
    free(ea.bytes);
    exec_free(&tx);
    gfx_close(&twin);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * PrepareProposal's FEE-DESCENDING order, with a STABLE tie.
 *
 * Drivable because `v2_exec_fixture.h`'s `v2x_table_init` installs a
 * SCRIPTED runtime table into `w->v2_runtime_table` (v2_exec_fixture.h:
 * 511-529) — the very override `nodus_witness_v2_runtime_for` consults
 * — whose `auth` hook is a pseudo-signer, so an envelope needs no
 * committee approval and may carry ANY `fee_amount`
 * (`v2x_env_build_ex`, :569-598). The chain_config envelope the other
 * cases use cannot: a SYSTEM CHAIN_CONFIG leg requires fee 0
 * (nodus_witness_rt_native.c:275) and rides alone.
 */
static int t_prepare_fee_order(void)
{
    gfx_t                                  g;
    cmt_genesis_doc_t                      doc;
    nodus_cmt_app_ledger_t                *app;
    nodus_abci_request_prepare_proposal_t  req;
    nodus_abci_response_prepare_proposal_t resp;
    cmt_genesis_validator_t                gvals[DNAC_COMMITTEE_SIZE];
    cmt_pb_bytes_t                         txs[3];
    v2x_env_t                             *e_lo, *e_mid, *e_hi;
    uint8_t                                script[64];
    uint32_t                               slen;
    v2x_leg_t                              leg;

    CHECK(gfx_open(&g, "feeord") == 0, "version-3 fixture");
    CHECK(v2x_table_init(g.w) == 0, "the scripted runtime table");
    app = calloc(1, sizeof(*app));
    e_lo = calloc(1, sizeof(*e_lo));
    e_mid = calloc(1, sizeof(*e_mid));
    e_hi = calloc(1, sizeof(*e_hi));
    CHECK(app && e_lo && e_mid && e_hi, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");

    /* a no-read, no-effect script: the ordering is what is under test,
     * not what the runtime does */
    slen = v2x_script_build(script, sizeof(script), NULL, 0, NULL, 0);
    CHECK(slen > 0, "script");
    memset(&leg, 0, sizeof(leg));
    leg.domain_id        = DNA_DOMAIN_CORE;
    leg.runtime_op       = 1;
    leg.call             = script;
    leg.call_len         = slen;
    leg.max_effects      = 1;
    leg.max_effect_bytes = 64;
    CHECK(v2x_env_build_ex(e_hi,  200000, 0, 9, &leg, 1) == 0, "fee 9 (a)");
    leg.runtime_op = 2;                  /* a DIFFERENT derived identity */
    CHECK(v2x_env_build_ex(e_mid, 200000, 0, 9, &leg, 1) == 0, "fee 9 (b)");
    leg.runtime_op = 3;
    CHECK(v2x_env_build_ex(e_lo,  200000, 0, 5, &leg, 1) == 0, "fee 5");

    /* request order: [fee 9 (a), fee 5, fee 9 (b)] */
    txs[0].data = e_hi->bytes;  txs[0].len = e_hi->len;
    txs[1].data = e_lo->bytes;  txs[1].len = e_lo->len;
    txs[2].data = e_mid->bytes; txs[2].len = e_mid->len;
    memset(&req, 0, sizeof(req));
    req.txs = txs;
    req.txs_len = 3;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == 3, "all three survive the seam");
    CHECK(resp.txs[0].data == e_hi->bytes,
          "fee 9 (a) is first — fee DESCENDING");
    CHECK(resp.txs[1].data == e_mid->bytes,
          "fee 9 (b) is second: a TIE keeps the request's order");
    CHECK(resp.txs[2].data == e_lo->bytes, "fee 5 is last");

    free(e_hi);
    free(e_mid);
    free(e_lo);
    free(app);
    gfx_close(&g);
    return 0;
}

/** Binding a LEGACY chain is refused. */
static int t_bind_refuses_legacy(void)
{
    fixture_t               fx;
    cmt_genesis_doc_t       doc;
    nodus_cmt_app_ledger_t *app;

    CHECK(fx_open(&fx, "bind") == 0, "version-2 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    memset(&doc, 0, sizeof(doc));
    fx.w->v2_successor = false;
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &doc) == CMT_FAULT,
          "a legacy chain must be refused");
    fx.w->v2_successor = true;
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &doc) == CMT_OK,
          "a successor chain binds");
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, NULL) == CMT_FAULT,
          "the genesis document is mandatory");
    free(app);
    fx_close(&fx);
    return 0;
}

/* ══ main ════════════════════════════════════════════════════════════ */

int main(void)
{
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "bind_refuses_legacy",        t_bind_refuses_legacy },
        { "init_chain_match",           t_init_chain_match },
        { "init_chain_mismatches",      t_init_chain_mismatches },
        { "finalize_block",             t_finalize_block },
        { "per_item_failure",           t_per_item_failure },
        { "per_item_rollback_after_work", t_per_item_rollback_after_work },
        { "apply_entry_preconditions",  t_apply_entry_preconditions },
        { "crash_window_before_commit", t_crash_window_before_commit },
        { "crash_window_after_commit",  t_crash_window_after_commit },
        { "finalize_block_bound",       t_finalize_block_bound },
        { "commit",                     t_commit },
        { "claim_items",                t_claim_items },
        { "check_tx",                   t_check_tx },
        { "chain_id_row_branch",        t_chain_id_row_branch_unchanged },
        { "prepare_proposal",           t_prepare_proposal },
        { "prepare_fee_order",          t_prepare_fee_order },
        { "process_proposal",           t_process_proposal },
        { "vote_extensions",            t_vote_extensions },
    };
    size_t i, failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_cmt_app: key generation failed\n");
        return 1;
    }
    for (i = 0; i < ncases; i++) {
        int rc = cases[i].fn();

        /* No sweep here — see "FIXTURE LIFETIME" at the top. A case owns
         * its fixtures and frees them on the path that succeeds. */
        fprintf(stderr, "%-30s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) {
            failed++;
        }
    }
    fprintf(stderr, "test_cmt_app: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
