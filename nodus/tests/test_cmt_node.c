/**
 * @file nodus/tests/test_cmt_node.c
 * @brief THE STARTUP TABLE (nodus_witness_cmt_node.{h,c}): cometbft's
 *        node construction and start over a REAL version-3 chain — the
 *        genesis document loader (node/setup.go:556-611), the Handshaker
 *        with its full height case analysis and both crash windows
 *        (consensus/replay.go:201-565), the mock application
 *        (consensus/replay_stubs.go:60-79) and OnStart
 *        (consensus/state.go:318-405).
 *
 * ── WHAT EACH CASE PROVES ──────────────────────────────────────────────
 * Named per case, with the reference line it is taken from. Every case
 * drives the REAL function under test over a REAL temporary SQLite
 * database derived by `nodus_witness_v2_gen_derive_v3`, with REAL
 * ML-DSA-87 keys and a REAL last-sign-state file. The only stand-ins are
 * named in "HOW IT CAN LIE".
 *
 * Ported from consensus/replay_test.go where the scenario is drivable
 * (every name below was read in that file at the line given; the ones
 * that carry no replay_test.go name have none — they are ported from
 * replay.go's own branches, which that file never drives directly):
 *   TestHandshakeReplayNone (replay_test.go:599, nBlocks == numBlocks)
 *       → t_progress_all_synced (replay.go:413-416)
 *   TestHandshakeReplayAll (replay_test.go:563, nBlocks == 0, the app
 *       applied nothing while the store holds every block)
 *       → t_replay_blocks_app_behind (replay.go:409-411)
 *   no named test — replay.go:428-436, the real application
 *       → t_crash_before_commit
 *   no named test — replay.go:437-453, the mock application built by
 *       `newMockProxyApp` (replay_stubs.go:60)
 *       → t_crash_after_commit
 * NOT ported, with the reason:
 *   · `TestHandshakeReplaySome` (replay_test.go:575, nBlocks == 2) and
 *     `TestHandshakeReplayOne` (:587, nBlocks == numBlocks-1): the same
 *     branch as ReplayAll, differing only in the trip count of
 *     `replayBlocks`' loop, which `t_replay_blocks_app_behind` already
 *     runs twice;
 *   · every case that drives the WAL half of the handshake
 *     (`testHandshakeReplay`, replay_test.go:627, over the file made by
 *     `tempWALWithData` at :610 and installed at :650-653; and
 *     `TestWALCrash` at :133): the WAL catch-up is inside `cmt_cs_start`,
 *     R2's, and its own suite is test_cmt_cs;
 *   · `TestHandshakePanicsIfAppReturnsWrongAppHash` (replay_test.go:917):
 *     the two assert functions are FAULTs here, and reaching one needs a
 *     ledger whose committed root disagrees with a block it produced —
 *     this fixture cannot build that state without corrupting the ledger
 *     by hand, which would prove the corruption, not the assert;
 *   · `TestHandshakeUpdatesValidators` (replay_test.go:1237): InitChain
 *     returns NO validator updates on this chain by construction (R3-T),
 *     so the branch at replay.go:351-357 has no producer;
 *   · the block-height edge case at replay.go:393-395 (state > store):
 *     the port's `apply_verified_block` advances the ledger and the state
 *     inside ONE transaction, so app == state on every path this fixture
 *     can build, and `store < app` and `store < state` are then the SAME
 *     predicate — the earlier case in the reference's ordered switch,
 *     :389-391 (store < app, ErrAppBlockHeightTooHigh), always wins.
 *     `t_edge_state_ahead_of_store` therefore drives :389-391; :393-395
 *     is unreachable with this fixture (verifier finding, W2).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none.
 * SQLite >= 3.35.0, which the S14 rung enforces itself.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * One `/tmp/test_cmt_node_*` directory per fixture, removed at close,
 * each holding the chain database and a `priv_validator_state.json`. A
 * case that aborts through CHECK leaves its directory behind.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THE COMMITS ARE NOT VERIFIABLE. Blocks above the initial height
 *     need a LastCommit for `cmt_state_make_block`'s MedianTime
 *     (cmt_state.c:246-251), and `mk_commit` builds one carrying the real
 *     validator addresses and timestamps but a FILLER signature. Nothing
 *     on the paths these cases drive verifies a commit — `ExecCommitBlock`
 *     and `apply_verified_block` do not, and the only case that replays
 *     through `ApplyBlock` (which does validate) runs at the INITIAL
 *     height, where the reference requires the commit to be EMPTY
 *     (validation.go:86-97). If a later change made any of these paths
 *     verify, these cases would fail for the right reason but the
 *     fixture would need real signatures.
 *  2. `t_replay_blocks_app_behind` copies one chain's consensus stores
 *     onto a SECOND derivation of the SAME config. It is meaningful only
 *     because two derivations of one config are byte-identical by
 *     `derive_v3`'s own contract; the case ASSERTS the two chain ids are
 *     equal but does not re-prove the contract.
 *  3. THE SIGNER IS THE TEST'S. `raw_sign` is this file's ML-DSA-87
 *     callback over `g_ks[0]`; R3-C2 binds the production one. A green
 *     here says nothing about the production signing path.
 *  4. `t_start_and_release` observes the WAL only as ROW COUNTS and the
 *     transaction state only through `sqlite3_get_autocommit`. It proves
 *     the WAL was seeded and that no transaction was open around the
 *     call; it does NOT prove the fsync the WAL's durability rests on,
 *     which is not observable from inside the process.
 *  4b. `t_genesis_doc_loader`'s case (f) — the tampered STORED row beside
 *     a valid provider — would LIE if the flipped byte landed outside the
 *     encoded document: a trailing byte the decoder never reads would
 *     leave the row acceptable, the node would start, and the case would
 *     then be asserting a refusal that never happened. It flips byte 100,
 *     which is inside the version-2 body, and asserts before the run that
 *     the stored row's length still equals the original's, so the flip is
 *     an EDIT and not an append. It does not prove WHICH of the four
 *     checks refused it — `t_v2_gen`'s own cases do that.
 *  5. NO REACTOR, NO TICK. `cmt_cs_start` is reached and returns, but
 *     nothing steps the state machine afterwards (that is W3). A green
 *     proves the node STARTS, not that it makes progress.
 *  6. Nothing here was RUN by its author: this package could not build
 *     or run tests. Every expectation is an expectation. What IS known
 *     from the ORCHESTRATOR's runs: round 2's reached case 2 and stopped
 *     on a FIXTURE defect (a genesis document projected from the
 *     caller's config, so its chain id was 32 zero bytes — see
 *     `bx_doc`); round 3's ran cases 1-8 GREEN and stopped inside case
 *     9 on a real defect in the node (no `LoadOrGenFilePV`, so a first
 *     boot died on the missing state file). Named by FUNCTION, because
 *     the banner numbers and the registration order do not agree:
 *     `t_start_and_release`, `t_privval_load_or_gen`,
 *     `t_init_invariants` and `t_mock_app_rows` have never been executed
 *     by anyone, and neither has `nodus_cmt_node_init` past step 4 —
 *     everything above drove the Handshaker through `run_handshake`'s
 *     shim, never the node's own build. Case 2's refusal leg was also
 *     VACUOUS before round 2: it asserted a FAULT that the chain-id
 *     check produced, not the app_hash check it names.
 *  7. `t_start_and_release` proves the GENERATE branch of
 *     `LoadOrGenFilePV` (file.go:242-243) only because the fixture does
 *     NOT pre-create the last-sign state file — `gfx_open` builds the
 *     path and nothing else. It asserts the file's ABSENCE before the
 *     init and its presence after, so the branch cannot be faked by a
 *     file somebody else left behind; if that first assertion is ever
 *     "fixed" by creating the file, the case silently becomes a test of
 *     the LOAD branch, which is `t_privval_load_or_gen`'s job.
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
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"         /* round 2: build_cc_env */
#include "witness/nodus_witness_runtime.h"        /* round 2: build_cc_env */
#include "witness/nodus_witness_emission.h"      /* DNAC_DECIMAL_UNIT   */
#include "witness/nodus_witness_cmt_app.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_cmt_node.h"
#include "witness/nodus_witness_cmt_store.h"
#include "server/nodus_server.h"

#include "dnac/dnac.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_mem.h"           /* round 2: cmt_mem_check_tx driving */
#include "dnac/ledger_ids.h"        /* round 2: dna_bft_quorum           */
#include "dnac/env_wire.h"          /* round 2: build_cc_env             */
#include "dnac/env_preflight.h"     /* round 2: build_cc_env             */
#include "dnac/cmt_tmhash.h"

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

/* ══ deterministic REAL keys — test_cmt_app.c:150-180 ════════════════ */

#define N_KEYS ((int)DNAC_COMMITTEE_SIZE)
#define TREASURY_RAW 93000000000000000ULL   /* test_cmt_app.c:155        */
#define GEN_TIME_MS  1767225600000ULL       /* test_cmt_app.c:156        */

/* ORCHESTRATOR delta 1, item B — a small, TEST-LOCAL executor bound, now
 * that NODUS_CMT_APP_MAX_TXS is retired. Every fixture in this file
 * carries at most a handful of transactions per block (most carry none
 * at all), so a small capacity keeps the per-slot payload arenas modest
 * — it says nothing about, and does not need to match, the byte-derived
 * bounds the application itself computes at nodus_cmt_app_ledger_init
 * (see that function's own comment, nodus_witness_cmt_app.c). */
#define TEST_NODE_MAX_TXS ((size_t)16)

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

/* The clock, frozen, AFTER the genesis instant so that a block above the
 * initial height is stamped later than it. */
static cmt_time_t g_now = { (int64_t)(GEN_TIME_MS / 1000ULL) + 10, 0 };

static int t_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    if (!out) {
        return CMT_FAULT;
    }
    *out = g_now;
    return CMT_OK;
}

/** `pv.Key.PrivKey.Sign` — the test's signer (R3-C2 binds production's). */
static int t_raw_sign(void *ctx, const uint8_t *sign_bytes, size_t len,
                      uint8_t sig_out[CMT_MAX_SIGNATURE_SIZE], size_t *sig_len)
{
    (void)ctx;
    if (!sign_bytes || !sig_out || !sig_len) {
        return CMT_FAULT;
    }
    if (qgp_dsa87_sign(sig_out, sig_len, sign_bytes, len, g_ks[0].sk) != 0) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

static void rmrf(const char *path)
{
    char cmd[300];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int   rc  = sqlite3_exec(db, sql, NULL, NULL, &err);

    if (err) {
        fprintf(stderr, "  sql: %s\n", err);
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

/* test_cmt_app.c:211-224 */
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

/* ══ FIXTURE — a REAL version-3 chain (test_cmt_app.c:226-403) ═══════ */

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

/** test_cmt_app.c:242-309 `cfg_make_v3_real`, retyped here (that copy is
 *  static in its own file). */
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
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED,
                                        * the only legal value is 0 */
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
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve;
     * this fixture's allocation spends the whole supply and it is not a
     * reward test — no pool reserved. */
    c->reward_pool_initial = 0;
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
    char             dbpath[600];
    char             pvpath[200];
    uint8_t          chain32[32];
} gfx_t;

/**
 * test_cmt_app.c:318-403 `gfx_open`: derive a version-3 chain and OPEN IT
 * BY HAND, because `nodus_witness_create_chain_db` refuses a version-3
 * chain until W3 (nodus_witness_v2_gen.h's note on
 * `..._stored_chain_id`). Every field set here is one the startup table
 * or the application reads; the last-sign-state path is this file's
 * addition.
 */
static int gfx_open(gfx_t *g, const char *tag)
{
    int i;

    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real(&g->box) != 0) {
        return -1;
    }
    if (nodus_witness_v2_gen_v3_validate(g->box.cfg) != 0) {
        return -1;
    }
    snprintf(g->dir, sizeof(g->dir), "/tmp/test_cmt_node_%s_XXXXXX", tag);
    if (!mkdtemp(g->dir)) {
        return -1;
    }
    if (nodus_witness_v2_gen_derive_v3(g->dir, g->box.cfg, g->chain32) != 0) {
        return -1;
    }
    {
        char hex[33];

        for (i = 0; i < 16; i++) {
            snprintf(hex + 2 * i, 3, "%02x", g->chain32[i]);
        }
        hex[32] = '\0';
        snprintf(g->dbpath, sizeof(g->dbpath), "%s/witness_%s.db", g->dir, hex);
    }
    snprintf(g->pvpath, sizeof(g->pvpath), "%s/priv_validator_state.json",
             g->dir);
    g->w   = calloc(1, sizeof(*g->w));           /* multi-MB: never stack */
    g->srv = calloc(1, sizeof(*g->srv));
    if (!g->w || !g->srv) {
        return -1;
    }
    if (sqlite3_open_v2(g->dbpath, &g->w->db, SQLITE_OPEN_READWRITE, NULL)
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

/** Close the SQLite handle but keep the directory — used where a second
 *  chain ATTACHes this one's file. */
static void gfx_close_db(gfx_t *g)
{
    if (g->w && g->w->db) {
        sqlite3_close(g->w->db);
        g->w->db = NULL;
    }
}

static void gfx_close(gfx_t *g)
{
    gfx_close_db(g);
    free(g->w);
    g->w = NULL;
    free(g->srv);
    g->srv = NULL;
    cfg_free(&g->box);
    rmrf(g->dir);
}

static void opts_default(gfx_t *g, nodus_cmt_node_opts_t *o)
{
    memset(o, 0, sizeof(*o));
    o->privval_state_path = g->pvpath;
    o->now                = t_now;
    o->raw_sign           = t_raw_sign;
    /* A small arena: this fixture's blocks carry no transactions, and
     * the default (`Block.MaxBytes` = 22 020 096) would have three block
     * slots plus three executor arenas allocate hundreds of megabytes
     * per case. Named here because the header says the default is the
     * only value a PRODUCTION caller may use. */
    o->limits.max_txs      = TEST_NODE_MAX_TXS;
    o->limits.tx_arena_cap = 2u * 1024u * 1024u;
    o->limits.max_evidence = 4;
}

/* ══ a REAL chain_config envelope — test_cmt_app.c:874-1036's shape
 * ═══════════════════════════════════════════════════════════════════
 * round 2 (test_cmt_node.c drive): "retyped here" over this file's own
 * `gfx_t`/`g_ks`, the SAME convention `cfg_make_v3_real` above already
 * follows for this file (its own comment cites test_cmt_app.c:242-309).
 * Needed ONLY to drive a transaction CheckTx genuinely ACCEPTS —
 * `mem_res_cb_first_time`'s `notifyTxsAvailable` (clist_mempool.go:453)
 * fires only on `res->code == CMT_MEM_CODE_TYPE_OK`, so the txsAvailable
 * drive below cannot use a stub. */

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
        /* CHECKTX-P1 round 2b: the effective height is DISTINCT per
         * nonce. A CHAIN_CONFIG leg CREATEs its history row under key
         * param ‖ effective with PRE_ABSENT (nodus_witness_rt_native.c
         * :4137-4138, :4152-4154), and CheckTx's pending conflict set
         * keys every PRE_ABSENT row — so two envelopes with one
         * (param, effective) are ONE row and the second is refused. The
         * nonce offset keeps the three envelopes of t_txs_available_fires
         * three distinct, independently admissible proposals. No upper
         * horizon rule applies (nodus_chain_config_scalar_rules). */
        eff = tip + 100000 + (nonce & 0xFFFFu);
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
        /* CHECKTX-P1 round 2: CheckTx refuses expiry 0 and anything past
         * tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD (nodus_types.h; decision
         * 2026-09-25-mempool-policy.md 1) — the full window. */
        env_in.expiry_height       = tip +
                                     (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD;
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

/* ══ cmt_state row helpers ═══════════════════════════════════════════ */

static int state_key_count(sqlite3 *db, const char *key)
{
    sqlite3_stmt *st = NULL;
    int           n  = -1;

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

/** The row's bytes into a malloc'd buffer. NULL when absent. */
static uint8_t *state_key_read(sqlite3 *db, const char *key, size_t *out_len)
{
    sqlite3_stmt *st = NULL;
    uint8_t      *out = NULL;

    *out_len = 0;
    if (sqlite3_prepare_v2(db, "SELECT value FROM cmt_state WHERE key = ?1",
                           -1, &st, NULL) != SQLITE_OK) {
        return NULL;
    }
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);

        if (n > 0) {
            out = (uint8_t *)malloc((size_t)n);
            if (out) {
                memcpy(out, sqlite3_column_blob(st, 0), (size_t)n);
                *out_len = (size_t)n;
            }
        }
    }
    sqlite3_finalize(st);
    return out;
}

static int state_key_write(sqlite3 *db, const char *key, const uint8_t *v,
                           size_t len)
{
    sqlite3_stmt *st = NULL;
    int           ok;

    if (sqlite3_prepare_v2(db,
            "INSERT INTO cmt_state (key, value) VALUES (?1, ?2) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, v, (int)len, SQLITE_TRANSIENT);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int state_key_delete(sqlite3 *db, const char *key)
{
    sqlite3_stmt *st = NULL;
    int           ok;

    if (sqlite3_prepare_v2(db, "DELETE FROM cmt_state WHERE key = ?1", -1, &st,
                           NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, (int)strlen(key), SQLITE_TRANSIENT);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/**
 * test_cmt_host.c:547-633 `db_digest`, with ONE change: the four CONSENSUS
 * tables are excluded, so the digest covers the LEDGER only.
 *
 * `t_crash_after_commit` is the reason it exists: that case must show the
 * ledger untouched while `cmt_state` legitimately changes (the replay
 * saves the state and re-saves the response). A whole-database digest
 * could not say that. Excluding four names rather than listing the
 * ledger's tables means a table added to the ledger later is covered
 * automatically.
 */
static bool is_consensus_table(const char *name)
{
    return strcmp(name, "cmt_state") == 0 ||
           strcmp(name, "cmt_blockstore") == 0 ||
           strcmp(name, "cmt_wal") == 0 ||
           strcmp(name, "cmt_wal_sync") == 0;
}

static int ledger_digest(sqlite3 *db, uint8_t out[64])
{
    sqlite3_stmt *ts = NULL;
    uint8_t      *buf = NULL;
    size_t        len = 0, cap = 0;
    int           rc, ret = -1;

#define DD_PUT(p, n) do {                                                  \
        if (len + (n) > cap) {                                             \
            size_t nc = cap ? cap * 2 : 4096;                              \
            uint8_t *nb;                                                   \
            while (nc < len + (n)) nc *= 2;                                \
            nb = (uint8_t *)realloc(buf, nc);                              \
            if (!nb) goto done;                                            \
            buf = nb; cap = nc;                                            \
        }                                                                  \
        memcpy(buf + len, (p), (n)); len += (n);                           \
    } while (0)

    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name NOT LIKE 'sqlite_%' ORDER BY 1", -1, &ts, NULL)
        != SQLITE_OK) {
        return -1;
    }
    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char   *name = (const char *)sqlite3_column_text(ts, 0);
        char          sql[256];
        sqlite3_stmt *rs = NULL;
        int           rrc;

        if (!name) {
            goto done;
        }
        if (is_consensus_table(name)) {
            continue;
        }
        DD_PUT(name, strlen(name) + 1);
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid", name);
        if (sqlite3_prepare_v2(db, sql, -1, &rs, NULL) != SQLITE_OK) {
            goto done;
        }
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs), c;

            for (c = 0; c < nc; c++) {
                uint8_t     t = (uint8_t)sqlite3_column_type(rs, c);
                const void *b;
                int         bl;
                uint32_t    bl32;

                DD_PUT(&t, 1);
                if (t == SQLITE_NULL) {
                    continue;
                }
                b  = sqlite3_column_blob(rs, c);
                bl = sqlite3_column_bytes(rs, c);
                bl32 = (uint32_t)bl;
                DD_PUT(&bl32, 4);
                if (bl > 0 && b) {
                    DD_PUT(b, (size_t)bl);
                }
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) {
            goto done;
        }
    }
    if (rc != SQLITE_DONE) {
        goto done;
    }
    ret = qgp_sha3_512(buf, len, out) == 0 ? 0 : -1;
done:
    sqlite3_finalize(ts);
    free(buf);
#undef DD_PUT
    return ret;
}

/* ══ the block-producing fixture ═════════════════════════════════════ */

#define BX_PARTS_CAP   64u
#define BX_SCRATCH_CAP (2u * 1024u * 1024u)

typedef struct {
    nodus_cmt_store_t         *store;
    nodus_cmt_app_ledger_t    *ledger;
    nodus_cmt_app_t            app_if;
    nodus_cmt_mempool_if_t     mp_if;
    nodus_cmt_evpool_if_t      ev_if;
    nodus_cmt_blockexec_t     *be;
    cmt_genesis_doc_t          doc;
    cmt_genesis_validator_t   *gvals;   /* heap: 128 × a 2592-byte key */
    cmt_state_storage_t       *stor;
    cmt_state_t               *state;
    cmt_valset_scratch_t      *vscratch;
    cmt_state_block_scratch_t *bscratch;
    cmt_block_t               *blk;
    cmt_part_t                *parts;
    uint8_t                   *part_scratch;
    uint8_t                   *size_scratch;
    cmt_pb_bytes_t             txs[1];     /* a non-NULL, EMPTY tx list */
    cmt_commit_sig_t          *sigs;       /* the commit we build       */
    cmt_extended_commit_sig_t *ecs;        /* the seen commit we store  */
    cmt_commit_sig_t          *tocommit;   /* ToCommit()'s storage      */
} bx_t;

static void bx_free(bx_t *x)
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
    free(x->gvals);
    free(x->stor);
    free(x->state);
    free(x->vscratch);
    free(x->bscratch);
    free(x->blk);
    free(x->parts);
    free(x->part_scratch);
    free(x->size_scratch);
    free(x->sigs);
    free(x->ecs);
    free(x->tocommit);
    memset(x, 0, sizeof(*x));
}

/**
 * The fixture's document is built EXACTLY as `nodus_cmt_node_init` builds
 * its own: the STORED "genesisDoc" row, read back through this package's
 * canonical-strict loader (nodus_witness_cmt_node.c:1272, setup.go:561),
 * then projected with `nodus_witness_v2_gen_to_cmt_doc` (node.c:1499,
 * setup.go:568).
 *
 * ⚠ IT MUST NOT PROJECT `g->box.cfg`, which is what this fixture did
 * until round 2 and what the run caught. `chain_id` and `app_hash` are
 * OUTPUTS of the derivation — gen.h:749-751 says `app_hash` is the root
 * the apply returns and `chain_id` is the hash of the completed document
 * — and the derivation CANNOT write either back into the caller's
 * config, because it takes it as `const nodus_v2_gen_config_t *`
 * (gen.h:775-777); the id comes back through the separate `out_chain32`
 * argument, which is why `gfx_open` keeps `g->chain32`. A document
 * projected from that config therefore carries 32 ZERO bytes where the
 * chain id belongs, every handshake built on it sends an InitChain the
 * application refuses at its chain-id check (cmt_app.c:309-315), and the
 * second case died there.
 *
 * Building it from the stored row removes the whole class: the document
 * the fixture hands the Handshaker is now byte-for-byte the one the node
 * would load, so `chain_id`, `app_hash`, the validator rows and the
 * consensus parameters are the committed ones rather than a projection
 * that happens to agree in some fields.
 *
 * `to_cmt_doc` copies every scalar and writes the validators into
 * `gvals`, aliasing nothing in `cfg` (gen.c:2541-2564), so the config and
 * its allocation list are freed here; only `gvals` must outlive `doc`.
 * The one struct assignment among those copies —
 * `out->consensus_params = cfg->consensus_params` at gen.c:2547 — is a
 * value copy all the way down: every member of `cmt_consensus_params_t`
 * is a scalar or a fixed array, `pub_key_types` included
 * (cmt_params.h:109-157). This is the first place in the tree where the
 * config dies before the document does, so that had to be true.
 */
static int bx_doc(gfx_t *g, cmt_genesis_doc_t *doc,
                  cmt_genesis_validator_t *gvals)
{
    nodus_v2_gen_config_t *cfg;          /* ~240 KB: never a stack object */
    nodus_v2_gen_alloc_t  *allocs = NULL;
    int                    rc;

    cfg = (nodus_v2_gen_config_t *)calloc(1, sizeof(*cfg));
    if (!cfg) {
        return -1;
    }
    rc = nodus_witness_v2_gen_stored_doc(g->w, cfg, &allocs);
    if (rc == 0) {
        rc = nodus_witness_v2_gen_to_cmt_doc(cfg, doc, gvals,
                                             NODUS_V2_GEN_MAX_VALIDATORS);
    }
    free(allocs);      /* the caller frees it on success and failure alike */
    free(cfg);
    return rc;
}

/**
 * test_cmt_app.c:767-814 `exec_init`, plus the block-store storage this
 * file needs (the app fixture never saves a block).
 *
 * @param save_state true makes the genesis state and SAVES it — the
 *        `LoadFromDBOrGenesisDoc` half (setup.go:581), performed here so
 *        a case can advance a chain WITHOUT running the startup table,
 *        which is the thing under test. false LOADS whatever is already
 *        stored, which is what a case that planted a state needs.
 */
static int bx_init_ex(bx_t *x, gfx_t *g, bool save_state)
{
    nodus_cmt_host_limits_t lim;

    memset(x, 0, sizeof(*x));
    x->store        = calloc(1, sizeof(*x->store));
    x->be           = calloc(1, sizeof(*x->be));
    x->ledger       = calloc(1, sizeof(*x->ledger));   /* ~85 KB         */
    x->gvals        = calloc(NODUS_V2_GEN_MAX_VALIDATORS,
                             sizeof(cmt_genesis_validator_t));
    x->stor         = calloc(1, sizeof(*x->stor));
    x->state        = calloc(1, sizeof(*x->state));
    x->vscratch     = calloc(1, sizeof(*x->vscratch));
    x->bscratch     = calloc(1, sizeof(*x->bscratch));
    x->blk          = calloc(1, sizeof(*x->blk));
    x->parts        = calloc(BX_PARTS_CAP, sizeof(cmt_part_t));
    x->part_scratch = malloc(BX_SCRATCH_CAP);
    x->size_scratch = malloc(BX_SCRATCH_CAP);
    x->sigs         = calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    x->ecs          = calloc(CMT_VALSET_MAX, sizeof(cmt_extended_commit_sig_t));
    x->tocommit     = calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    if (!x->store || !x->be || !x->ledger || !x->gvals || !x->stor ||
        !x->state || !x->vscratch || !x->bscratch || !x->blk || !x->parts ||
        !x->part_scratch || !x->size_scratch || !x->sigs || !x->ecs ||
        !x->tocommit) {
        return -1;
    }
    if (nodus_cmt_store_init(x->store, g->w->db, false) != CMT_OK) {
        return -1;
    }
    if (bx_doc(g, &x->doc, x->gvals) != 0) {
        return -1;
    }
    if (nodus_cmt_app_ledger_init(x->ledger, g->w, &x->doc) != CMT_OK ||
        nodus_cmt_app_ledger_build(&x->app_if, x->ledger) != CMT_OK) {
        return -1;
    }
    x->mp_if = nodus_cmt_nop_mempool;
    x->ev_if = nodus_cmt_empty_evpool;
    memset(&lim, 0, sizeof(lim));
    lim.max_txs      = TEST_NODE_MAX_TXS;
    lim.tx_arena_cap = BX_SCRATCH_CAP;
    lim.max_evidence = 4;
    if (nodus_cmt_blockexec_init(x->be, x->store, &x->app_if, &x->mp_if,
                                 &x->ev_if, NULL, NULL, t_now, NULL, NULL,
                                 NULL, &lim) != CMT_OK) {
        return -1;
    }
    if (cmt_state_init(x->state, x->stor) != CMT_OK) {
        return -1;
    }
    if (!save_state) {
        return nodus_cmt_ss_load(x->store, x->state) == CMT_OK ? 0 : -1;
    }
    if (cmt_state_make_genesis(&x->doc, NULL, NULL, x->vscratch, x->state)
        != CMT_OK) {
        return -1;
    }
    /* ⚠ LOAD-BEARING, and easy to leave out: `MakeGenesisState` leaves
     * LastResultsHash EMPTY (cmt_state.c:459-460), but the startup table
     * sets it to H("") at replay.go:367-368 before it saves. A block
     * this fixture builds from a state WITHOUT that value carries an
     * empty `LastResultsHash` in its header, and `validateBlock`
     * (validation.go:66-71) then refuses it against the state the
     * handshake produced — which is exactly the path
     * `t_crash_before_commit` drives. The fixture therefore completes
     * the state the same way the startup table does. */
    if (cmt_merkle_empty_hash(x->state->last_results_hash) != CMT_OK) {
        return -1;
    }
    x->state->last_results_hash_len = CMT_TMHASH_SIZE;
    return nodus_cmt_ss_save(x->store, x->state) == CMT_OK ? 0 : -1;
}

static int bx_init(bx_t *x, gfx_t *g)
{
    return bx_init_ex(x, g, true);
}

/**
 * A LastCommit for height `h-1` carrying the REAL validator addresses of
 * `state->last_validators` and a timestamp, so that
 * `cmt_state_make_block`'s MedianTime (cmt_state.c:250) has something to
 * weigh. The signatures are FILLER — see "HOW IT CAN LIE" item 1.
 */
static void mk_commit(const cmt_state_t *state, int64_t h,
                      const cmt_block_id_t *bid, cmt_time_t ts,
                      cmt_commit_sig_t *sigs, cmt_commit_t *out)
{
    size_t i;

    memset(out, 0, sizeof(*out));
    for (i = 0; i < state->last_validators.validators_len; i++) {
        memset(&sigs[i], 0, sizeof(sigs[i]));
        sigs[i].block_id_flag = CMT_PB_BLOCK_ID_FLAG_COMMIT;
        memcpy(sigs[i].validator_address,
               state->last_validators.validators[i].address,
               state->last_validators.validators[i].address_len);
        sigs[i].validator_address_len =
            state->last_validators.validators[i].address_len;
        sigs[i].timestamp = ts;
        memset(sigs[i].signature, (int)(0x30 + i), 64);
        sigs[i].signature_len = 64;
    }
    out->height              = h - 1;
    out->round               = 0;
    out->block_id            = *bid;
    out->signatures          = sigs;
    out->signatures_cap      = CMT_VALSET_MAX;
    out->signatures_len      = state->last_validators.validators_len;
}

/* test_cmt_host.c:3896-3914 `block_id_of`. */
static int bx_block_id(bx_t *x, cmt_block_t *b, cmt_block_id_t *out)
{
    cmt_part_set_t ps;

    memset(out, 0, sizeof(*out));
    if (cmt_block_hash(b, out->hash) != CMT_OK) {
        return -1;
    }
    out->hash_len = 64;
    if (cmt_block_make_part_set(b, CMT_BLOCK_PART_SIZE_BYTES, x->part_scratch,
                                BX_SCRATCH_CAP, x->parts, BX_PARTS_CAP, &ps)
            != CMT_OK ||
        cmt_part_set_header(&ps, &out->part_set_header) != CMT_OK) {
        return -1;
    }
    return 0;
}

/* test_cmt_host.c:1067-1094 `make_test_ext_commit`, reduced to what
 * `SaveBlockWithExtendedCommit` checks: only the HEIGHT is compared
 * against the block (nodus_witness_cmt_store.c `save_block_to_batch`). */
static void mk_seen_ext_commit(int64_t h, cmt_time_t ts,
                               const cmt_block_id_t *bid,
                               cmt_extended_commit_sig_t *sigs,
                               cmt_extended_commit_t *out)
{
    memset(out, 0, sizeof(*out));
    memset(&sigs[0], 0, sizeof(sigs[0]));
    sigs[0].commit_sig.block_id_flag = CMT_PB_BLOCK_ID_FLAG_COMMIT;
    memset(sigs[0].commit_sig.validator_address, 0x71, 32);
    sigs[0].commit_sig.validator_address_len = 32;
    sigs[0].commit_sig.timestamp = ts;
    memset(sigs[0].commit_sig.signature, 0x72, 64);
    sigs[0].commit_sig.signature_len = 64;
    memcpy(sigs[0].extension_signature, "ExtensionSignature", 18);
    sigs[0].extension_signature_len = 18;
    out->height                  = h;
    out->block_id                = *bid;
    out->extended_signatures     = sigs;
    out->extended_signatures_cap = CMT_VALSET_MAX;
    out->extended_signatures_len = 1;
}

/**
 * Advance the chain by one block at `h`, in the reference's own order:
 * `blockStore.SaveBlock…` (state.go:1735-1737) and then
 * `blockExec.ApplyVerifiedBlock` (:1790) — the two separate steps D-4
 * rev 3 (5) names, each its own transaction, which is what makes the
 * Handshaker's crash windows reachable.
 *
 * @param save_block  false leaves the block OUT of the block store.
 * @param apply       false leaves the ledger and the state where they are.
 */
static int bx_advance(bx_t *x, int64_t h, bool save_block, bool apply)
{
    cmt_data_t     data;
    cmt_commit_t   last_commit;
    cmt_block_id_t bid;
    cmt_part_set_t ps;
    cmt_extended_commit_t ec;
    cmt_time_t     ts = g_now;
    cmt_validator_t proposer;

    memset(&data, 0, sizeof(data));
    memset(&last_commit, 0, sizeof(last_commit));
    /* An EMPTY transaction list over a NON-NULL array, the shape
     * test_cmt_app.c:817-826 uses: these blocks carry no transactions
     * (the startup table is what is under test, not the apply lane). */
    data.txs     = x->txs;
    data.txs_cap = 1;
    data.txs_len = 0;
    ts.seconds += h;

    if (h > x->state->initial_height) {
        /* MedianTime needs a commit over the PREVIOUS block. */
        mk_commit(x->state, h, &x->state->last_block_id, ts, x->sigs,
                  &last_commit);
    }
    if (cmt_validator_set_get_proposer(&x->state->validators, &proposer)
        != CMT_OK) {
        return -1;
    }
    if (cmt_state_make_block(x->state, h, &data, &last_commit, NULL,
                             proposer.address, proposer.address_len,
                             x->bscratch, x->blk) != CMT_OK) {
        return -1;
    }
    if (bx_block_id(x, x->blk, &bid) != 0) {
        return -1;
    }
    if (save_block) {
        if (cmt_block_make_part_set(x->blk, CMT_BLOCK_PART_SIZE_BYTES,
                                    x->part_scratch, BX_SCRATCH_CAP, x->parts,
                                    BX_PARTS_CAP, &ps) != CMT_OK) {
            return -1;
        }
        mk_seen_ext_commit(h, ts, &bid, x->ecs, &ec);
        if (nodus_cmt_bs_save_block_with_extended_commit(
                x->store, x->blk, &ps, &ec, x->tocommit, CMT_VALSET_MAX,
                x->size_scratch, BX_SCRATCH_CAP) != CMT_OK) {
            return -1;
        }
    }
    if (apply) {
        if (nodus_cmt_host_apply_verified_block(x->be, &bid, x->blk, x->state)
            != CMT_OK) {
            return -1;
        }
    }
    return 0;
}

/* ══ the counting application shim ═══════════════════════════════════ */

/**
 * The REAL application table with `init_chain` wrapped in a counter —
 * the reference's own `TestHandshakeReplay*` drives the Handshaker with
 * its own proxyApp for exactly this reason (replay_test.go). No
 * production code carries a test hook.
 */
typedef struct {
    nodus_cmt_app_ledger_t *real;
    int                     init_chain_calls;
    int                     finalize_calls;
} shim_t;

static shim_t g_shim;

static int shim_init_chain(void *ctx,
                           const nodus_abci_request_init_chain_t *req,
                           nodus_abci_response_init_chain_t *resp)
{
    shim_t *s = (shim_t *)ctx;

    s->init_chain_calls++;
    return nodus_cmt_app_init_chain(s->real, req, resp);
}

static int shim_finalize_block(void *ctx,
                               const nodus_abci_request_finalize_block_t *req,
                               nodus_abci_response_finalize_block_t *resp)
{
    shim_t *s = (shim_t *)ctx;

    s->finalize_calls++;
    return nodus_cmt_app_finalize_block(s->real, req, resp);
}

static int shim_commit(void *ctx, nodus_abci_response_commit_t *resp)
{
    return nodus_cmt_app_commit(((shim_t *)ctx)->real, resp);
}

static int shim_prepare(void *ctx,
                        const nodus_abci_request_prepare_proposal_t *req,
                        nodus_abci_response_prepare_proposal_t *resp)
{
    return nodus_cmt_app_prepare_proposal(((shim_t *)ctx)->real, req, resp);
}

static int shim_process(void *ctx,
                        const nodus_abci_request_process_proposal_t *req,
                        nodus_abci_response_process_proposal_t *resp)
{
    return nodus_cmt_app_process_proposal(((shim_t *)ctx)->real, req, resp);
}

static int shim_extend(void *ctx, const nodus_abci_request_extend_vote_t *req,
                       nodus_abci_response_extend_vote_t *resp)
{
    return nodus_cmt_app_extend_vote(((shim_t *)ctx)->real, req, resp);
}

static int shim_verify(void *ctx,
                       const nodus_abci_request_verify_vote_extension_t *req,
                       nodus_abci_response_verify_vote_extension_t *resp)
{
    return nodus_cmt_app_verify_vote_extension(((shim_t *)ctx)->real, req,
                                               resp);
}

static void shim_table(nodus_cmt_app_t *t, nodus_cmt_app_ledger_t *real)
{
    memset(&g_shim, 0, sizeof(g_shim));
    g_shim.real = real;
    memset(t, 0, sizeof(*t));
    t->ctx                   = &g_shim;
    t->init_chain            = shim_init_chain;
    t->prepare_proposal      = shim_prepare;
    t->process_proposal      = shim_process;
    t->extend_vote           = shim_extend;
    t->verify_vote_extension = shim_verify;
    t->finalize_block        = shim_finalize_block;
    t->commit                = shim_commit;
}

/** Run one handshake over `x`'s store and application, from a state
 *  loaded the way `nodus_cmt_node_init` loads it. */
static int run_handshake(gfx_t *g, bx_t *x, int *out_nblocks)
{
    nodus_cmt_handshaker_t *h;
    nodus_cmt_app_t         shim;
    nodus_cmt_host_limits_t lim;
    int                     rc;

    memset(&lim, 0, sizeof(lim));
    lim.max_txs      = TEST_NODE_MAX_TXS;
    lim.tx_arena_cap = BX_SCRATCH_CAP;
    lim.max_evidence = 4;
    shim_table(&shim, x->ledger);
    h = (nodus_cmt_handshaker_t *)calloc(1, sizeof(*h));
    if (!h) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_handshaker_init(h, x->store, x->state, &x->doc, g->w,
                                   t_now, NULL, &lim);
    if (rc == CMT_OK) {
        rc = nodus_cmt_handshaker_handshake(h, &shim);
        if (out_nblocks) {
            *out_nblocks = h->nblocks;
        }
    }
    nodus_cmt_handshaker_release(h);
    free(h);
    return rc;
}

/* ══ CASE 1 — Info over the ledger ═══════════════════════════════════ */

/** replay.go:250-259's source: a chain that has committed only its
 *  genesis answers height 0 and the genesis composition's root. */
static int t_app_info(void)
{
    gfx_t                g;
    nodus_cmt_app_info_t info;
    uint8_t              root[64];

    CHECK(gfx_open(&g, "info") == 0, "version-3 fixture");
    CHECK(nodus_cmt_node_app_info(g.w, &info) == CMT_OK, "Info answers");
    CHECK(info.last_block_height == 0,
          "a chain with no Comet block row is at height 0 (replay.go:320's "
          "InitChain branch)");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0, "root");
    CHECK(info.last_block_app_hash_len == 64 &&
          memcmp(info.last_block_app_hash, root, 64) == 0,
          "last_block_app_hash is the ledger's committed global root");
    CHECK(info.app_version == 0, "app_version 0 (D-4 rev 3 (2))");
    CHECK(info.version != NULL && info.version[0] != '\0',
          "version is the build's CMT_SOFTWARE_VERSION");
    gfx_close(&g);
    return 0;
}

/* ══ CASE 2 — a fresh start ══════════════════════════════════════════ */

/**
 * replay.go:320-373. On a chain that has committed only its genesis:
 * InitChain is called EXACTLY ONCE, `stateKey` lands with
 * LastBlockHeight 0, AppHash == the document's, and LastResultsHash ==
 * H("") (:367-368).
 */
static int t_fresh_start_handshake(void)
{
    gfx_t   g;
    bx_t    x;
    uint8_t empty[CMT_TMHASH_SIZE];
    int     nb = -1;

    CHECK(gfx_open(&g, "fresh") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    /* The fixture's own precondition, asserted where a failure names
     * itself: the document must be the chain's. A document projected from
     * the caller's config carries a ZERO chain id (see `bx_doc`), and the
     * only symptom downstream is InitChain being refused. */
    CHECK(x.doc.chain_id_len == 32 &&
          memcmp(x.doc.chain_id, g.chain32, 32) == 0,
          "the fixture's document carries THIS chain's id, not zeros");
    {
        uint8_t root[64];

        /* The old fixture made InitChain's check (2) tautological by
         * copying the ledger's root INTO the document. Now the document
         * carries what the DERIVATION stored, so the equality is a real
         * claim about `derive_v3` — asserted here so a break names
         * itself instead of surfacing as a failed handshake. */
        CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0,
              "the ledger's committed global root");
        CHECK(x.doc.app_hash_len == 64 &&
              memcmp(x.doc.app_hash, root, 64) == 0,
              "and the stored document's app_hash IS that root");
    }
    CHECK(run_handshake(&g, &x, &nb) == CMT_OK, "the handshake succeeds");
    CHECK(g_shim.init_chain_calls == 1,
          "InitChain was called exactly once (replay.go:336)");
    CHECK(nb == 0, "no block was replayed");
    CHECK(state_key_count(g.w->db, "stateKey") == 1, "stateKey was saved");
    {
        cmt_state_t         *st  = calloc(1, sizeof(*st));
        cmt_state_storage_t *sto = calloc(1, sizeof(*sto));

        CHECK(st && sto, "alloc");
        CHECK(cmt_state_init(st, sto) == CMT_OK, "state init");
        CHECK(nodus_cmt_ss_load(x.store, st) == CMT_OK, "the state loads");
        CHECK(st->last_block_height == 0, "LastBlockHeight 0");
        CHECK(st->app_hash_len == 64 &&
              memcmp(st->app_hash, x.doc.app_hash, 64) == 0,
              "AppHash is the document's — the application returned the "
              "ledger's committed global root and it is the same value");
        CHECK(cmt_merkle_empty_hash(empty) == CMT_OK, "H(\"\")");
        CHECK(st->last_results_hash_len == CMT_TMHASH_SIZE &&
              memcmp(st->last_results_hash, empty, CMT_TMHASH_SIZE) == 0,
              "LastResultsHash is H(\"\") (replay.go:367, RFC-6962)");
        free(st);
        free(sto);
    }
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * A document whose app_hash does not match the ledger's committed root is
 * refused by InitChain (D-23 rev 5 (7)) and NOTHING is written: the
 * handshake fails before replay.go:369's Save.
 */
static int t_fresh_start_mismatch(void)
{
    gfx_t g;
    bx_t  x;

    CHECK(gfx_open(&g, "mismatch") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    /* bx_init saved a state already (it is the fixture's own
     * LoadFromDBOrGenesisDoc half); drop it so "nothing written" is
     * observable. */
    CHECK(state_key_delete(g.w->db, "stateKey") == 0, "clear stateKey");
    /* The ONLY thing wrong with this document must be its app_hash: the
     * application checks the chain id FIRST (nodus_witness_cmt_app.c:309)
     * and a zero id would refuse it there, which would make this case
     * assert a refusal it did not cause. */
    CHECK(x.doc.chain_id_len == 32 &&
          memcmp(x.doc.chain_id, g.chain32, 32) == 0,
          "the chain id is the committed one, so check (1) passes");
    x.doc.app_hash[0] ^= 0xFF;
    CHECK(run_handshake(&g, &x, NULL) == CMT_FAULT,
          "a document whose app_hash is not the ledger's root is refused");
    CHECK(g_shim.init_chain_calls == 1, "InitChain was reached and refused");
    CHECK(state_key_count(g.w->db, "stateKey") == 0,
          "no state was saved by the refused handshake");
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 3 — a restart with no blocks ═══════════════════════════════ */

/**
 * ⚠ WHAT THIS PINS DOWN, AND WHY IT IS NOT "InitChain is not called
 * again": replay.go:320 branches on `appBlockHeight == 0` and NOTHING
 * else. A chain that has produced no block still answers 0 from Info, so
 * a restart RE-RUNS InitChain — which is the whole point of D-23
 * rev 5 (7)'s "InitChain verifies the committed genesis state", and of
 * D-18 rev 5's register row "a restart verifies through InitChain".
 * The branch that skips InitChain is `appBlockHeight > 0`, and
 * `t_progress_all_synced` below is where that is proven.
 */
static int t_restart_no_blocks(void)
{
    gfx_t    g;
    bx_t     x;
    size_t   blen = 0, alen = 0;
    uint8_t *b, *a;
    int      same;

    CHECK(gfx_open(&g, "restart") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    CHECK(run_handshake(&g, &x, NULL) == CMT_OK, "first start");
    CHECK(g_shim.init_chain_calls == 1, "InitChain once");
    /* The marshalled State carries three validator sets of ML-DSA-87
     * public keys (2592 B each), so it is tens of kilobytes: the two
     * copies are compared where `state_key_read` allocated them, never
     * through a fixed-size buffer. */
    b = state_key_read(g.w->db, "stateKey", &blen);
    CHECK(b && blen > 0, "stateKey after the first start");

    CHECK(run_handshake(&g, &x, NULL) == CMT_OK, "second start");
    CHECK(g_shim.init_chain_calls == 1,
          "InitChain runs AGAIN on the restart — it is the genesis CHECK "
          "(replay.go:320 branches on appBlockHeight alone)");
    a = state_key_read(g.w->db, "stateKey", &alen);
    CHECK(a && alen == blen, "the state row is the same length");
    same = (memcmp(a, b, blen) == 0);
    free(a);
    free(b);
    CHECK(same, "and byte-identical: the re-run changed nothing");
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 4 — normal progress, then the all-synced branch ════════════ */

/**
 * replay_test.go TestHandshakeReplayNone / replay.go:413-416. Two blocks
 * saved AND applied: store == state == app == 2, so the handshake
 * asserts and returns without replaying and without InitChain.
 */
static int t_progress_all_synced(void)
{
    gfx_t                g;
    bx_t                 x;
    nodus_cmt_app_info_t info;
    int                  nb = -1;

    CHECK(gfx_open(&g, "synced") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    CHECK(bx_advance(&x, 1, true, true) == 0, "block 1 saved and applied");
    CHECK(bx_advance(&x, 2, true, true) == 0, "block 2 saved and applied");
    CHECK(nodus_cmt_bs_height(x.store) == 2, "store height 2");
    CHECK(x.state->last_block_height == 2, "state height 2");
    CHECK(nodus_cmt_node_app_info(g.w, &info) == CMT_OK &&
          info.last_block_height == 2, "Info answers height 2");

    CHECK(run_handshake(&g, &x, &nb) == CMT_OK, "the handshake succeeds");
    CHECK(g_shim.init_chain_calls == 0,
          "InitChain is NOT called once the ledger is past height 0 "
          "(replay.go:320)");
    CHECK(nb == 0, "nothing was replayed (replay.go:413-416)");
    CHECK(g_shim.finalize_calls == 0, "and no block was finalized again");
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 5 — crash window (a): the block saved, the apply rolled back ═ */

/**
 * replay.go:428-436, "We haven't run Commit (both the state and app are
 * one block behind), so replayBlock with the real app."
 *
 * The window is produced by C1a's runtime fault point
 * `nodus_cmt_app_ledger_t.test_fail_at`, which fails the apply INSIDE
 * the host's transaction, so the bracket rolls it back: the block is in
 * the block store, the ledger and the state are not advanced.
 */
static int t_crash_before_commit(void)
{
    gfx_t   g;
    bx_t    x;
    int     nb = -1;

    CHECK(gfx_open(&g, "crash_pre") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    /* The block is SAVED, then the apply is failed INSIDE the host's
     * transaction by C1a's runtime fault point, so the bracket rolls it
     * back: store 1, ledger 0, state 0.
     *
     * `V2AP_FAIL_BEFORE_COMMIT` is chosen because it sits on the SHARED
     * tail of the engine, ahead of the Comet lane's early return
     * (nodus_witness_v2_apply.c:4855 precedes the `blk->cmt.on` return at
     * :4864) — so it fires on a block with no transactions, which is
     * what this fixture builds. */
    x.ledger->test_fail_at = V2AP_FAIL_BEFORE_COMMIT;
    CHECK(bx_advance(&x, 1, true, true) != 0,
          "the apply fails before the host's COMMIT");
    x.ledger->test_fail_at = V2AP_FAIL_NONE;
    CHECK(sqlite3_get_autocommit(g.w->db) == 1,
          "and the host rolled the transaction back");
    CHECK(nodus_cmt_bs_height(x.store) == 1, "store height 1");
    CHECK(x.state->last_block_height == 0, "state height 0");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 0,
          "the ledger has no block row");

    CHECK(run_handshake(&g, &x, &nb) == CMT_OK,
          "the handshake heals the window");
    CHECK(nb == 1, "exactly one block was replayed (replay.go:434)");
    CHECK(g_shim.finalize_calls == 1,
          "through the REAL application, once");
    CHECK(g_shim.init_chain_calls == 1,
          "InitChain also ran, because the app was still at height 0 "
          "(replay.go:320)");
    CHECK(nodus_cmt_bs_height(x.store) == 1, "store still 1");
    {
        cmt_state_t         *st  = calloc(1, sizeof(*st));
        cmt_state_storage_t *sto = calloc(1, sizeof(*sto));
        uint64_t             h   = 0;

        CHECK(st && sto && cmt_state_init(st, sto) == CMT_OK, "state init");
        CHECK(nodus_cmt_ss_load(x.store, st) == CMT_OK, "the state loads");
        CHECK(st->last_block_height == 1, "state advanced to 1");
        CHECK(nodus_witness_v2_tip_height(g.w, &h) == 0 && h == 1,
              "and so did the ledger");
        CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1,
              "the ledger's block row exists");
        {
            uint8_t root[64];

            CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0,
                  "root");
            CHECK(st->app_hash_len == 64 && memcmp(st->app_hash, root, 64) == 0,
                  "the saved state's AppHash is the ledger's committed root");
        }
        free(st);
        free(sto);
    }
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 6 — crash window (b): after COMMIT, before store.Save ══════ */

/**
 * replay.go:437-453, "We ran Commit, but didn't save the state, so
 * replayBlock with mock app."
 *
 * The window is produced by W1's runtime fault point
 * `nodus_cmt_blockexec_t.test_fail_after_commit`, which fails
 * `applyBlock` in the ONE step between `Commit` returning (the ledger
 * transaction is committed) and `store.Save(state)`.
 *
 * What it must prove is not only that the node starts: it is that the
 * LEDGER IS NOT COMMITTED TWICE. The ledger tables are digested before
 * and after the replay and must be identical.
 */
static int t_crash_after_commit(void)
{
    gfx_t   g;
    bx_t    x;
    uint8_t before[64], after[64];
    int     nb = -1;

    CHECK(gfx_open(&g, "crash_post") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    x.be->test_fail_after_commit = true;
    CHECK(bx_advance(&x, 1, true, true) != 0,
          "the apply fails in the post-commit window");
    x.be->test_fail_after_commit = false;

    CHECK(nodus_cmt_bs_height(x.store) == 1, "store height 1");
    {
        uint64_t h = 0;

        CHECK(nodus_witness_v2_tip_height(g.w, &h) == 0 && h == 1,
              "the LEDGER is at 1 — its transaction committed");
    }
    {
        cmt_state_t         *st  = calloc(1, sizeof(*st));
        cmt_state_storage_t *sto = calloc(1, sizeof(*sto));

        CHECK(st && sto && cmt_state_init(st, sto) == CMT_OK, "state init");
        CHECK(nodus_cmt_ss_load(x.store, st) == CMT_OK, "the state loads");
        CHECK(st->last_block_height == 0,
              "but the STATE is still at 0 — store.Save never ran");
        free(st);
        free(sto);
    }
    CHECK(state_key_count(g.w->db, "lastABCIResponseKey") == 1,
          "the FinalizeBlock response was saved inside the same "
          "transaction (execution.go:259)");
    CHECK(ledger_digest(g.w->db, before) == 0, "ledger digest before");

    /* The fixture's in-memory state is the pre-apply one, which is
     * exactly what a restart would load. */
    CHECK(run_handshake(&g, &x, &nb) == CMT_OK,
          "the handshake heals the window");
    CHECK(nb == 1, "one block replayed (replay.go:452)");
    CHECK(g_shim.init_chain_calls == 0,
          "InitChain was not called — the ledger is past height 0");
    CHECK(g_shim.finalize_calls == 0,
          "the REAL application was NOT asked to finalize it again — the "
          "MOCK application served the stored response");
    CHECK(ledger_digest(g.w->db, after) == 0, "ledger digest after");
    CHECK(memcmp(before, after, 64) == 0,
          "and the ledger tables are byte-identical: no second COMMIT of "
          "the block's effects");
    {
        cmt_state_t         *st  = calloc(1, sizeof(*st));
        cmt_state_storage_t *sto = calloc(1, sizeof(*sto));

        CHECK(st && sto && cmt_state_init(st, sto) == CMT_OK, "state init");
        CHECK(nodus_cmt_ss_load(x.store, st) == CMT_OK, "the state loads");
        CHECK(st->last_block_height == 1, "the state caught up to 1");
        free(st);
        free(sto);
    }
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 7 — replayBlocks: the app behind by two ════════════════════ */

/**
 * replay.go:409-411 and :462-522 (`replayBlocks`, mutateState false):
 * store == state, app behind.
 *
 * ── HOW THE STATE IS CONSTRUCTED, since one chain cannot reach it ─────
 * The port applies the ledger and saves the state in ONE transaction, so
 * app == state on every path a single chain can take. The window is
 * built with TWO chains derived from the SAME config: chain A is
 * advanced two blocks, and A's consensus stores (`cmt_blockstore` and
 * `cmt_state`, which is where the block store, the state and the genesis
 * document all live) are copied wholesale onto chain B, whose LEDGER is
 * untouched at height 0.
 *
 * Two derivations of one config are byte-identical by `derive_v3`'s own
 * contract; the case asserts the two chain ids are equal, which is the
 * observable part of that, and relies on the rest (item 2 of "HOW IT CAN
 * LIE").
 *
 * What it proves beyond the branch: replaying A's blocks on B reproduces
 * A's committed global root. That is two nodes, the same blocks, the
 * same state — the determinism claim the whole lane rests on.
 */
static int t_replay_blocks_app_behind(void)
{
    gfx_t   ga, gb;
    bx_t    xa, xb;
    uint8_t root_a[64], root_b[64];
    char    sql[900];
    int     nb = -1;

    CHECK(gfx_open(&ga, "rb_a") == 0, "chain A");
    CHECK(bx_init(&xa, &ga) == 0, "A's block fixture");
    CHECK(bx_advance(&xa, 1, true, true) == 0, "A block 1");
    CHECK(bx_advance(&xa, 2, true, true) == 0, "A block 2");
    CHECK(nodus_witness_v2_committed_global_root(ga.w, root_a) == 0,
          "A's committed root at height 2");
    bx_free(&xa);
    gfx_close_db(&ga);          /* the file is read by B's ATTACH */

    CHECK(gfx_open(&gb, "rb_b") == 0, "chain B");
    CHECK(memcmp(ga.chain32, gb.chain32, 32) == 0,
          "two derivations of one config are the same chain");
    snprintf(sql, sizeof(sql),
             "ATTACH DATABASE '%s' AS src;"
             "DELETE FROM cmt_blockstore;"
             "INSERT INTO cmt_blockstore SELECT * FROM src.cmt_blockstore;"
             "DELETE FROM cmt_state;"
             "INSERT INTO cmt_state SELECT * FROM src.cmt_state;"
             "DETACH DATABASE src;", ga.dbpath);
    CHECK(run_sql(gb.w->db, sql) == 0, "A's consensus stores copied onto B");

    /* The copy comes FIRST: `bx_init_ex`'s store handle caches the block
     * store's base and height at open, and its `save_state` half would
     * overwrite the state the copy just planted. */
    CHECK(bx_init_ex(&xb, &gb, /*save_state=*/false) == 0,
          "B's block fixture over the copied stores");
    CHECK(xb.state->last_block_height == 2, "B's state says 2");
    CHECK(nodus_cmt_bs_height(xb.store) == 2, "B's block store says 2");
    {
        uint64_t h = 1;

        CHECK(nodus_witness_v2_tip_height(gb.w, &h) == 0 && h == 0,
              "but B's LEDGER is still at 0");
    }

    CHECK(run_handshake(&gb, &xb, &nb) == CMT_OK, "the handshake replays");
    CHECK(g_shim.init_chain_calls == 1,
          "InitChain ran first (the app was at 0, replay.go:320)");
    CHECK(nb == 2, "both blocks were replayed (replay.go:489-509)");
    CHECK(g_shim.finalize_calls == 2, "each through ExecCommitBlock once");
    {
        uint64_t h = 0;

        CHECK(nodus_witness_v2_tip_height(gb.w, &h) == 0 && h == 2,
              "B's ledger caught up to 2");
    }
    CHECK(nodus_witness_v2_committed_global_root(gb.w, root_b) == 0,
          "B's committed root");
    CHECK(memcmp(root_a, root_b, 64) == 0,
          "and it EQUALS A's: the same blocks produce the same ledger state "
          "on a second node");
    bx_free(&xb);
    gfx_close(&gb);
    gfx_close(&ga);
    return 0;
}

/* ══ CASE 8 — an edge case of replay.go:376-400 ══════════════════════ */

/**
 * replay.go:389-391, `ErrAppBlockHeightTooHigh` ("the app should never
 * be ahead of the store") — CMT_FAULT here (umbrella rev 6). Built by
 * applying two blocks but saving only the first: store 1, state 2,
 * app 2.
 *
 * WHICH BRANCH THIS REACHES, stated because an earlier cut of this case
 * named the wrong one: the reference's switch (replay.go:376-400) is
 * ordered, and `store < app` (:389) is tested BEFORE `store < state`
 * (:393). The port advances the ledger and the state in one transaction,
 * so app == state on every path this fixture can build, the two
 * predicates coincide, and :389-391 always wins. The :393-395 panic
 * (`StateBlockHeight > StoreBlockHeight`) is NOT constructible with this
 * fixture — stated in the file header.
 */
static int t_edge_state_ahead_of_store(void)
{
    gfx_t g;
    bx_t  x;

    CHECK(gfx_open(&g, "edge") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    CHECK(bx_advance(&x, 1, true, true) == 0, "block 1 saved and applied");
    CHECK(bx_advance(&x, 2, false, true) == 0, "block 2 applied, NOT saved");
    CHECK(nodus_cmt_bs_height(x.store) == 1, "store height 1");
    CHECK(x.state->last_block_height == 2, "state height 2");
    CHECK(run_handshake(&g, &x, NULL) == CMT_FAULT,
          "an app ahead of the store stops the node (replay.go:389-391, "
          "the branch that wins because app == state here)");
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 9 — the genesis document loader ════════════════════════════ */

/**
 * node/setup.go:556-587 and :589-603, with D-18 rev 5 (3): an absent row
 * with no provider refuses; provider bytes are accepted and stored; a
 * tampered document — provided or stored — is refused by the four checks;
 * and a PRESENT row is authority whether or not it is readable, so the
 * provider can neither be consulted nor overwrite it (:597-601).
 *
 * The three-way table of `loadGenesisDoc` is driven here as (a)/(c) the
 * absent row, (d) the present readable row, (e)/(f) the present
 * unreadable one. The db-error leg (:591-593) is NOT driven: forcing
 * `nodus_cmt_store_get` to fail needs a broken connection, and breaking
 * it would prove the breakage rather than the branch.
 */
static int t_genesis_doc_loader(void)
{
    gfx_t                 g;
    nodus_cmt_node_opts_t o;
    nodus_cmt_node_t     *n;
    uint8_t              *doc;
    size_t                dlen = 0;

    CHECK(gfx_open(&g, "gendoc") == 0, "version-3 fixture");
    n = (nodus_cmt_node_t *)calloc(1, sizeof(*n));
    CHECK(n != NULL, "alloc");

    doc = state_key_read(g.w->db, NODUS_V2_GEN_GENESIS_DOC_KEY, &dlen);
    CHECK(doc && dlen > 0, "the derivation stored a genesis document");

    /* (a) no row, no provider → refuse. */
    CHECK(state_key_delete(g.w->db, NODUS_V2_GEN_GENESIS_DOC_KEY) == 0,
          "drop the row");
    opts_default(&g, &o);
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
          "no stored document and no provider is a refusal (setup.go:563)");
    CHECK(state_key_count(g.w->db, NODUS_V2_GEN_GENESIS_DOC_KEY) == 0,
          "and nothing was written");

    /* (b) a TAMPERED provider → refuse, and still nothing written. */
    opts_default(&g, &o);
    doc[dlen / 2] ^= 0xFF;
    o.genesis_doc_bytes = doc;
    o.genesis_doc_len   = dlen;
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
          "a tampered document fails the four checks");
    CHECK(state_key_count(g.w->db, NODUS_V2_GEN_GENESIS_DOC_KEY) == 0,
          "and the refusal left NO row behind (the write is rolled back)");
    doc[dlen / 2] ^= 0xFF;

    /* (c) the real bytes → accepted, stored, and the node builds. */
    opts_default(&g, &o);
    o.genesis_doc_bytes = doc;
    o.genesis_doc_len   = dlen;
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_OK,
          "the document the derivation wrote is accepted from a provider");
    CHECK(state_key_count(g.w->db, NODUS_V2_GEN_GENESIS_DOC_KEY) == 1,
          "and stored under the reference's key (setup.go:551)");
    nodus_cmt_node_release(n);

    /* (d) with the row present the provider is never consulted: a
     * GARBAGE provider beside a good row still starts (setup.go:561). */
    opts_default(&g, &o);
    {
        uint8_t junk[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

        o.genesis_doc_bytes = junk;
        o.genesis_doc_len   = sizeof(junk);
        CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_OK,
              "a stored row is authority; the provider is not called");
        nodus_cmt_node_release(n);
    }

    /* (e) a TAMPERED STORED row is refused. */
    {
        uint8_t *bad = (uint8_t *)malloc(dlen);

        CHECK(bad != NULL, "alloc");
        memcpy(bad, doc, dlen);
        bad[dlen / 3] ^= 0x01;
        CHECK(state_key_write(g.w->db, NODUS_V2_GEN_GENESIS_DOC_KEY, bad, dlen)
              == 0, "store a tampered document");
        free(bad);
    }
    opts_default(&g, &o);
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
          "a one-byte edit of the stored document stops the node");

    /* (f) THE ROW WINS OVER THE PROVIDER EVEN WHEN THE ROW IS THE BROKEN
     * ONE — setup.go:597-601 panics on a present-but-unreadable document
     * and never reaches the provider call at :563. Without the row probe
     * this port could not tell "absent" from "refused" (both are -1 from
     * `..._stored_doc`), would take the provider branch, and would
     * OVERWRITE a chain's genesis document with a start-up argument.
     * The row is written and read back through the STORE's own rows, the
     * ones the node itself uses. */
    {
        nodus_cmt_store_t *s;          /* prepared statements: heap, not stack */
        uint8_t           *bad;
        const uint8_t     *back = NULL;
        size_t             blen = 0;
        int                unchanged;

        s   = (nodus_cmt_store_t *)calloc(1, sizeof(*s));
        bad = (uint8_t *)malloc(dlen);
        CHECK(s && bad, "alloc");
        CHECK(dlen > 100, "the document is long enough for the flip to land "
              "INSIDE it, not past its end");
        memcpy(bad, doc, dlen);
        bad[100] ^= 0x01;              /* inside the version-2 body */
        CHECK(nodus_cmt_store_init(s, g.w->db, false) == CMT_OK,
              "a store on this chain's open connection");
        CHECK(nodus_cmt_store_set(s, /*state_table=*/true,
                                  NODUS_V2_GEN_GENESIS_DOC_KEY, bad, dlen)
              == CMT_OK, "store the tampered document");
        CHECK(nodus_cmt_store_get(s, /*state_table=*/true,
                                  NODUS_V2_GEN_GENESIS_DOC_KEY, &back, &blen)
              == CMT_OK && blen == dlen,
              "and the stored row is the SAME LENGTH as the original — the "
              "flipped byte is inside the encoded document");

        opts_default(&g, &o);
        o.genesis_doc_bytes = doc;     /* the CORRECT canonical document */
        o.genesis_doc_len   = dlen;
        CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
              "a stored row the four checks refuse stops the node even when "
              "a VALID document is supplied (setup.go:597-601)");

        CHECK(nodus_cmt_store_get(s, /*state_table=*/true,
                                  NODUS_V2_GEN_GENESIS_DOC_KEY, &back, &blen)
              == CMT_OK, "read the row back");
        unchanged = (blen == dlen && back != NULL &&
                     memcmp(back, bad, dlen) == 0);
        nodus_cmt_store_release(s);
        free(s);
        free(bad);
        CHECK(unchanged,
              "and the row is still the TAMPERED bytes: the provider's "
              "document was NEVER written (setup.go:563 is unreachable "
              "while a row exists)");
    }
    free(doc);
    free(n);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 10 — init, start, release ══════════════════════════════════ */

/**
 * consensus/state.go:318-405 through `nodus_cmt_node_start`: the WAL is
 * opened OUTSIDE any transaction and seeded with EndHeight{0}
 * (wal.go:124-131).
 *
 * ORCHESTRATOR delta 1, item 2 / E — `cmt_cs_start` is DELIBERATELY NOT
 * reached here any more (this comment used to claim it was): D-23 rev 7
 * item 17 moves that call to `cmt_conr_start`, which the WITNESS builds
 * and owns (nodus_witness.c's witness_cmt_live_init/witness_cmt_tick),
 * not this module. The observable proof that `nodus_cmt_node_start`
 * stops short of it: `scheduleRound0` (state.go:402, inside
 * `cmt_cs_start`) arms the propose-timeout timer, so if `cmt_cs_start`
 * had run, `nodus_cmt_host_next_deadline` would report one armed. It
 * must not, here — see the assertion right after the start call below.
 * `n->cs_started` — the field the WITNESS sets externally once
 * `cmt_conr_start` actually reaches `cmt_cs_start` — must also stay
 * false, for the same reason.
 *
 * Then everything releases — ASan is what proves that, and the
 * ORCHESTRATOR runs it.
 *
 * ORCHESTRATOR delta 7, item A — the OBSERABLE proof of the nilWAL
 * binding fix, not the log text: `cmt_cs_init` (inside
 * `nodus_cmt_node_init`, called above) writes a round-state row through
 * the SAME host `wal_write` row `nodus_cmt_node_start` seeds
 * EndHeight{0} through later. Before this fix, `nodus_cmt_blockexec_init`
 * bound `ctx->wal` to `&n->wal` — a non-NULL but UNOPENED wal object —
 * so that write reached `nodus_cmt_wal_write` on an unopened WAL and
 * FAILED (logging an error on every single init); the row still never
 * landed (an unopened connection cannot write), so the row-count
 * assertions above were already green even under the bug — only the
 * host row's own RETURN CODE distinguishes fixed from broken. Calling
 * `n->host.wal_write` DIRECTLY (the exact row `cmt_cs_init` itself
 * calls, isolated from its own internals) proves both halves: CMT_OK
 * with zero landed rows before start (the nilWAL-mirroring no-op), and
 * a REAL row landing after start once the WAL is genuinely open and
 * bound.
 */
static int t_start_and_release(void)
{
    gfx_t                 g;
    nodus_cmt_node_opts_t o;
    nodus_cmt_node_t     *n;

    CHECK(gfx_open(&g, "start") == 0, "version-3 fixture");
    n = (nodus_cmt_node_t *)calloc(1, sizeof(*n));
    CHECK(n != NULL, "alloc");
    opts_default(&g, &o);
    /* ⚠ THE FIXTURE MUST NOT PRE-CREATE IT. This is the GEN branch of
     * `LoadOrGenFilePV` (file.go:242-243): a node's FIRST start has no
     * last-sign state file and must make one. If this assertion ever
     * fails because something created the file earlier, the case below
     * stops proving the branch — see "HOW IT CAN LIE" item 7. */
    CHECK(access(g.pvpath, F_OK) != 0,
          "a fresh chain directory has NO last-sign state file");

    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_OK, "the node builds");
    /* tokenomics-v3 P1 (D-5) — the REGISTRATION half of the TxsAvailable
     * wiring, observable without driving a CheckTx: before this package
     * `cmt_mem_enable_txs_available` was called with a NULL callback and
     * a NULL ctx (nodus_witness_cmt_node.c, "a channel nobody reads; the
     * flag still flips") — both fields stayed NULL after init. This
     * fixture's own settings make `cmt_config_wait_for_txs` true
     * (CreateEmptyBlocksInterval > 0), so the registration call always
     * runs. Pins ONLY that a real callback and the node itself as its
     * ctx got bound; it does NOT prove the callback FIRES on the first
     * accepted tx (that needs a CheckTx drive this fixture does not do —
     * reported as a gap, not invented here). RED before D-5:
     * `n->mem->txs_available_fn == NULL`. */
    CHECK(n->mem != NULL, "mempool exists");
    CHECK(n->mem->txs_available_fn != NULL,
          "D-5: TxsAvailable is bound to a REAL callback, not NULL");
    CHECK(n->mem->txs_available_ctx == (void *)n,
          "D-5: the callback's ctx is the node itself");
    /* PACKAGE C2e, register R3-A-5: node_slots_alloc's part-set payload
     * store, one per block slot, sized parts_cap[k] *
     * CMT_BLOCK_PART_SIZE_BYTES — the same arithmetic node_slots_alloc's
     * own comment states. ASan (a leak or a double-free in
     * nodus_cmt_node_release, which this test reaches below) is what
     * actually proves the free side; this proves the alloc side landed
     * with the right size and every slot got one. */
    {
        int k;

        CHECK(n->slots != NULL, "slots exist");
        for (k = 0; k < CMT_CS_BLOCK_SLOTS; k++) {
            CHECK(n->slots->part_bytes[k] != NULL,
                  "every block slot has a part_bytes store");
            CHECK(n->slots->part_bytes_cap[k] ==
                      n->slots->parts_cap[k] * (size_t)CMT_BLOCK_PART_SIZE_BYTES,
                  "part_bytes_cap is parts_cap * CMT_BLOCK_PART_SIZE_BYTES");
        }
    }
    {
        nodus_cmt_privval_t scratch;
        cmt_lss_t           back;

        /* file.go:243 `pv.Save()` — the file exists after the first
         * start, and it holds the EMPTY state `NewFilePV` builds
         * (file.go:171-174: `Step: stepNone`, nothing else). Read back
         * through the port's own loader, not by parsing JSON here. */
        CHECK(access(g.pvpath, F_OK) == 0,
              "the first start GENERATED the last-sign state file");
        memset(&back, 0, sizeof(back));
        CHECK(nodus_cmt_privval_open(&scratch, g.pvpath, t_now, NULL,
                                     /*load_state=*/true, &back) == CMT_OK,
              "and it decodes through LoadFilePV");
        CHECK(back.height == 0, "height 0");
        CHECK(back.round == 0, "round 0");
        CHECK(back.step == CMT_STEP_NONE, "step stepNone (file.go:172)");
        CHECK(!back.has_signature && !back.has_sign_bytes,
              "and it carries neither a signature nor sign bytes");
        nodus_cmt_privval_close(&scratch);
    }
    CHECK(n->handshake_nblocks == 0, "a fresh chain replays nothing");
    CHECK(state_key_count(g.w->db, "stateKey") == 1,
          "the handshake saved the genesis state");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM cmt_wal") == 0,
          "no WAL row before start");
    CHECK(sqlite3_get_autocommit(g.w->db) == 1,
          "no transaction is open across the start boundary "
          "(nodus_witness_cmt_wal.h's §B.4 caller contract)");

    /* ORCHESTRATOR delta 7, item A — the DIRECT proof: the exact host
     * row `cmt_cs_init` itself calls, isolated from its own internals.
     * `nodus_cmt_blockexec_init` bound `ctx->wal = NULL` in
     * `nodus_cmt_node_init` above (the port's own nilWAL,
     * nodus_witness_cmt_host.c's `host_wal_write`), so a write reaching
     * it BEFORE start returns CMT_OK and lands nowhere — RED before this
     * fix: `ctx->wal` was `&n->wal` (non-NULL, unopened), so this exact
     * call would have returned CMT_FAULT (nodus_cmt_wal_write failing
     * against an unopened WAL) instead of CMT_OK. */
    {
        cmt_wal_message_t msg;

        memset(&msg, 0, sizeof(msg));
        msg.kind = CMT_PB_WAL_EVENT_DATA_ROUND_STATE;
        msg.u.event_data_round_state.height = 1;
        CHECK(n->host.wal_write(n->be, &msg) == CMT_OK,
              "a WAL write reaching the host before start is the "
              "nilWAL's silent no-op (CMT_OK), not a fault");
        CHECK(q1(g.w->db, "SELECT COUNT(*) FROM cmt_wal") == 0,
              "and it still landed NOWHERE — the row count is unchanged");
    }

    CHECK(nodus_cmt_node_start(n) == CMT_OK, "the node starts");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM cmt_wal") == 1,
          "start wrote EndHeight(0) exactly once (wal.go:124-131)");
    CHECK(sqlite3_get_autocommit(g.w->db) == 1,
          "and left no transaction open");

    /* ORCHESTRATOR delta 7, item A — the SAME row, called the SAME way,
     * now reaches the REAL bound-and-open WAL: a genuine second row
     * lands. RED if `nodus_cmt_node_start` failed to bind the real WAL
     * via `nodus_cmt_blockexec_set_wal` (the write would either fault
     * again, or — if some future change silently restored a permanent
     * no-op — return CMT_OK while the row count stayed at 1). */
    {
        cmt_wal_message_t msg;

        memset(&msg, 0, sizeof(msg));
        msg.kind = CMT_PB_WAL_EVENT_DATA_ROUND_STATE;
        msg.u.event_data_round_state.height = 2;
        CHECK(n->host.wal_write(n->be, &msg) == CMT_OK,
              "a WAL write after start succeeds against the REAL, open "
              "WAL");
        CHECK(q1(g.w->db, "SELECT COUNT(*) FROM cmt_wal") == 2,
              "and a genuine second row lands — the WAL is truly bound "
              "now, not still silently discarding writes");
    }
    /* ORCHESTRATOR delta 1, item 2 / E — the state machine is NOT
     * running after nodus_cmt_node_start: no armed propose timer (the
     * scheduleRound0 side effect only cmt_cs_start produces), and
     * n->cs_started stays the false the struct was calloc'd with (this
     * module never sets it any more — see nodus_witness_cmt_node.h's
     * comment on that field). Would go RED if cmt_cs_start were ever
     * called from here again. */
    {
        int64_t dl = 0;
        CHECK(!nodus_cmt_host_next_deadline(n->be, &dl),
              "no propose timer armed — cmt_cs_start did not run");
        CHECK(!n->cs_started, "cs_started stays false: only the caller "
              "that reaches cmt_cs_start through cmt_conr_start may set "
              "it");
    }
    CHECK(nodus_cmt_node_start(n) == CMT_FAULT, "a second start is refused");

    nodus_cmt_node_release(n);
    free(n);
    /* The file the privval half wrote is this node's, and it survives
     * the release — a restart must find it. */
    CHECK(access(g.pvpath, F_OK) == 0,
          "the last-sign-state file is on disk after release");
    gfx_close(&g);
    return 0;
}

/**
 * tokenomics-v3 P1 (D-5), round 2 — the DRIVE half of the TxsAvailable
 * wiring `t_start_and_release` above only REGISTERS. A transaction
 * CheckTx genuinely ACCEPTS fires the callback and sets
 * `n->cs->txs_available`; a SECOND accepted transaction at the SAME
 * height does NOT fire it again (`notified_txs_available`'s own latch,
 * clist_mempool.go:510-521 / cmt_mem.c:1223-1229); the mempool's own
 * `Update` (the per-height reset, clist_mempool.go:592-593 /
 * cmt_mem.c:1706) clears that latch, so the NEXT accepted transaction at
 * the next height fires it once more — "once per height".
 *
 * `cmt_mem_check_tx` is driven DIRECTLY on `n->mem`, not through a
 * FinalizeBlock request — CheckTx and FinalizeBlock are different ABCI
 * connections (AppConnMempool vs AppConnConsensus,
 * nodus_witness_cmt_app.h's own file header) and this property belongs
 * to the mempool connection alone.
 */
static int t_txs_available_fires(void)
{
    gfx_t                       g;
    nodus_cmt_node_opts_t       o;
    nodus_cmt_node_t           *n;
    test_env_t                  env1, env2, env3;
    cmt_mem_tx_info_t           info;
    cmt_mem_response_check_tx_t res;
    cmt_mem_error_t             err;

    CHECK(gfx_open(&g, "txsavail") == 0, "version-3 fixture");
    n = (nodus_cmt_node_t *)calloc(1, sizeof(*n));
    CHECK(n != NULL, "alloc");
    opts_default(&g, &o);
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_OK, "the node builds");
    CHECK(n->cs != NULL, "consensus state exists after init");
    CHECK(!n->cs->txs_available,
          "FIXTURE GUARD: not set before any transaction");

    memset(&info, 0, sizeof(info));

    /* ── first accepted transaction: FIRES it ──────────────────────── */
    CHECK(build_cc_env(g.w, g.chain32, 0x9001, &env1) == 0, "envelope 1");
    memset(&res, 0, sizeof(res));
    memset(&err, 0, sizeof(err));
    CHECK(cmt_mem_check_tx(n->mem, env1.bytes, env1.len, &info, &res, &err)
              == CMT_OK, "checked");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "a valid envelope is admitted");
    CHECK(n->cs->txs_available,
          "D-5: the FIRST accepted transaction fires the callback and "
          "sets cs->txs_available");

    /* the flag is CONSUMED by the real consensus event loop
     * (`cmt_cs_handle_txs_available`'s own reset, cmt_cs.c:1616) — this
     * test clears it by hand to observe what happens NEXT, the same
     * substitution that handler performs. */
    n->cs->txs_available = false;

    /* ── a SECOND accepted transaction at the SAME height: does NOT fire
     * it again. */
    CHECK(build_cc_env(g.w, g.chain32, 0x9002, &env2) == 0, "envelope 2");
    memset(&res, 0, sizeof(res));
    memset(&err, 0, sizeof(err));
    CHECK(cmt_mem_check_tx(n->mem, env2.bytes, env2.len, &info, &res, &err)
              == CMT_OK, "checked");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "also admitted");
    CHECK(!n->cs->txs_available,
          "D-5: a SECOND accepted transaction at the same height does "
          "NOT fire the callback again — notified_txs_available already "
          "latched");

    /* ── Update commits BOTH pending transactions, emptying the pool, so
     * its own tail re-notify ("notify when transactions remain",
     * clist_mempool.go:634-636) does NOT fire — isolating what this
     * case is actually about: a NEW transaction at the NEXT height gets
     * a FRESH chance to fire, because Update cleared the latch, not
     * because the pool happened to be non-empty. */
    {
        cmt_pb_bytes_t          committed[2];
        cmt_pb_exec_tx_result_t results[2];

        committed[0].data = env1.bytes; committed[0].len = env1.len;
        committed[1].data = env2.bytes; committed[1].len = env2.len;
        memset(results, 0, sizeof(results));
        CHECK(cmt_mem_update(n->mem, 1, committed, 2, results, 2,
                             NULL, NULL) == CMT_OK, "Update commits both");
    }
    CHECK(!n->cs->txs_available,
          "FIXTURE GUARD: Update left the flag clear — the pool is now "
          "empty, so its own tail re-notify did not fire either");

    CHECK(build_cc_env(g.w, g.chain32, 0x9003, &env3) == 0, "envelope 3");
    memset(&res, 0, sizeof(res));
    memset(&err, 0, sizeof(err));
    CHECK(cmt_mem_check_tx(n->mem, env3.bytes, env3.len, &info, &res, &err)
              == CMT_OK, "checked");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "admitted at the new height");
    CHECK(n->cs->txs_available,
          "D-5: after Update resets the latch, the NEXT accepted "
          "transaction fires the callback again — once per height");

    free(env1.bytes);
    free(env2.bytes);
    free(env3.bytes);
    nodus_cmt_node_release(n);
    free(n);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 10b — LoadOrGenFilePV's LOAD branch ════════════════════════ */

/**
 * privval/file.go:237-245, the other half of what `t_start_and_release`
 * drives. That case proves the GEN branch (:242-243) on a first start;
 * this one proves the LOAD branch (:239-240): when the state file
 * EXISTS the node carries what it says, which is the entire point of
 * the file — a restart must not sign again at a height it already
 * signed at.
 *
 * DEVIATION R3-C1c-5 is what makes the branch selectable here: the
 * reference takes the existence test on the KEY file (:239) and this
 * port has no key file, so it takes it on the STATE file.
 *
 * The previous run's file is written with the PORT'S OWN writer
 * (`nodus_cmt_privval_save_lss`, the shape test_cmt_host.c:1893-1903
 * uses), never by hand-rolled JSON here: a fixture that wrote the file
 * itself would be testing this file's idea of the format.
 */
static int t_privval_load_or_gen(void)
{
    gfx_t                 g;
    nodus_cmt_node_opts_t o;
    nodus_cmt_node_t     *n;
    nodus_cmt_privval_t   scratch;
    cmt_lss_t             seed;

    CHECK(gfx_open(&g, "pvload") == 0, "version-3 fixture");
    n = (nodus_cmt_node_t *)calloc(1, sizeof(*n));
    CHECK(n != NULL, "alloc");

    CHECK(access(g.pvpath, F_OK) != 0, "no state file yet");
    CHECK(nodus_cmt_privval_open(&scratch, g.pvpath, t_now, NULL,
                                 /*load_state=*/false, &seed) == CMT_OK,
          "a writer bound to the path");
    memset(&seed, 0, sizeof(seed));
    seed.height = 1;
    seed.round  = 0;
    seed.step   = CMT_STEP_PRECOMMIT;                     /* file.go:29 */
    CHECK(nodus_cmt_privval_save_lss(&scratch, &seed) == CMT_OK,
          "a last-sign state from a previous run is on disk");
    nodus_cmt_privval_close(&scratch);
    CHECK(access(g.pvpath, F_OK) == 0, "the file exists before init");

    opts_default(&g, &o);
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_OK, "the node builds");
    CHECK(n->pv != NULL, "the node has a private validator");
    CHECK(n->pv->last_sign_state.height == 1,
          "the node LOADED the existing state instead of generating one "
          "over it (file.go:239-240)");
    CHECK(n->pv->last_sign_state.round == 0, "round 0");
    CHECK(n->pv->last_sign_state.step == CMT_STEP_PRECOMMIT,
          "at the step the previous run reached — this is what stops a "
          "double sign across a restart");
    nodus_cmt_node_release(n);
    free(n);
    gfx_close(&g);
    return 0;
}

/**
 * The two invariants `nodus_cmt_node_init` enforces (both found by C1a).
 * The transaction bound is drivable from the options; the two-connection
 * one is not, because `opts` gives no way to hand the application a
 * different handle — stated rather than faked.
 */
static int t_init_invariants(void)
{
    gfx_t                 g;
    nodus_cmt_node_opts_t o;
    nodus_cmt_node_t     *n;

    CHECK(gfx_open(&g, "inv") == 0, "version-3 fixture");
    n = (nodus_cmt_node_t *)calloc(1, sizeof(*n));
    CHECK(n != NULL, "alloc");

    opts_default(&g, &o);
    /* ORCHESTRATOR delta 1, item B/7 — the application's own bound is
     * now the byte-derived env_bound (hundreds of thousands at this
     * fixture's genesis Block.MaxBytes), not the retired
     * NODUS_CMT_APP_MAX_TXS (10). A value comfortably above ANY
     * plausible byte-derived bound — one million, far past what
     * Block.MaxBytes / a 73-byte minimal envelope could ever yield —
     * proves the SAME invariant without this test needing to know the
     * fixture's exact derived figure. */
    o.limits.max_txs = (size_t)1000000;
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
          "an executor sized above the application's own bound is refused");

    opts_default(&g, &o);
    o.privval_state_path = NULL;
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
          "a node with no last-sign-state path is refused");

    opts_default(&g, &o);
    o.now = NULL;
    CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
          "a node with no clock callback is refused — no time is invented");

    /* node.go:343-345 `can't get pubkey` returns an error: a node with no
     * identity does not come up. Without this the private validator would
     * carry an all-zero key and an address matching no member of the set,
     * and the node would start believing it is not a validator. */
    opts_default(&g, &o);
    {
        nodus_server_t *saved = g.w->server;

        g.w->server = NULL;
        CHECK(nodus_cmt_node_init(n, g.w, &o) == CMT_FAULT,
              "a node with no identity is refused (node.go:343-345)");
        g.w->server = saved;
    }

    free(n);
    gfx_close(&g);
    return 0;
}

/* ══ CASE 11 — the mock application's rows ═══════════════════════════ */

/**
 * replay_stubs.go:60-79 driven directly: `FinalizeBlock` returns the
 * STORED response whatever the request says, and `Commit` closes the
 * host's transaction rather than returning BaseApplication's empty
 * answer (D-23 rev 5 (5)).
 */
static int t_mock_app_rows(void)
{
    gfx_t                 g;
    bx_t                  x;
    nodus_cmt_mock_app_t *m;
    nodus_cmt_app_t       tbl;
    nodus_abci_request_finalize_block_t  req;
    nodus_abci_response_finalize_block_t resp;
    nodus_abci_response_commit_t         cres;
    uint8_t                              root[64];

    CHECK(gfx_open(&g, "mock") == 0, "version-3 fixture");
    CHECK(bx_init(&x, &g) == 0, "block fixture");
    CHECK(bx_advance(&x, 1, true, true) == 0, "block 1 saved and applied");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0, "root");

    m = (nodus_cmt_mock_app_t *)calloc(1, sizeof(*m));
    CHECK(m != NULL, "alloc");
    CHECK(nodus_cmt_mock_app_open(m, x.store, g.w->db, 1, NULL, 0,
                                  TEST_NODE_MAX_TXS) == CMT_OK,
          "the stored FinalizeBlock response at height 1 loads "
          "(replay.go:439)");
    CHECK(m->resp.app_hash_len == 64 &&
          memcmp(m->resp.app_hash, root, 64) == 0,
          "and it carries the app hash the real application returned");
    CHECK(nodus_cmt_mock_app_build(&tbl, m) == CMT_OK, "the table builds");

    memset(&req, 0, sizeof(req));
    req.height = 99;                     /* the mock ignores the request */
    memset(&resp, 0, sizeof(resp));
    CHECK(tbl.finalize_block(tbl.ctx, &req, &resp) == CMT_OK,
          "FinalizeBlock answers");
    CHECK(resp.app_hash_len == 64 && memcmp(resp.app_hash, root, 64) == 0,
          "with the STORED response, whatever the request said "
          "(replay_stubs.go:77-79)");

    /* Commit outside a transaction is the invariant it must refuse. */
    memset(&cres, 0, sizeof(cres));
    CHECK(sqlite3_get_autocommit(g.w->db) == 1, "no transaction is open");
    CHECK(tbl.commit(tbl.ctx, &cres) == CMT_FAULT,
          "Commit with no open transaction is a node-local fault — the mock "
          "COMMITS the host's bracket and cannot invent one");
    CHECK(m->commit_calls == 0, "and it did not count a commit");

    /* Inside one, it commits. */
    CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0, "open a transaction");
    CHECK(tbl.commit(tbl.ctx, &cres) == CMT_OK, "Commit closes it");
    CHECK(sqlite3_get_autocommit(g.w->db) == 1, "the transaction is closed");
    CHECK(m->commit_calls == 1, "and it counted");
    CHECK(cres.retain_height == 0, "retain_height 0 — no pruning on replay");

    nodus_cmt_mock_app_close(m);
    free(m);
    bx_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    struct { const char *name; int (*fn)(void); } cases[] = {
        { "app_info",                 t_app_info                 },
        { "fresh_start_handshake",    t_fresh_start_handshake    },
        { "fresh_start_mismatch",     t_fresh_start_mismatch     },
        { "restart_no_blocks",        t_restart_no_blocks        },
        { "progress_all_synced",      t_progress_all_synced      },
        { "crash_before_commit",      t_crash_before_commit      },
        { "crash_after_commit",       t_crash_after_commit       },
        { "replay_blocks_app_behind", t_replay_blocks_app_behind },
        { "edge_state_ahead",         t_edge_state_ahead_of_store},
        { "genesis_doc_loader",       t_genesis_doc_loader       },
        { "start_and_release",        t_start_and_release        },
        { "txs_available_fires",      t_txs_available_fires      },
        { "privval_load_or_gen",      t_privval_load_or_gen      },
        { "init_invariants",          t_init_invariants          },
        { "mock_app_rows",            t_mock_app_rows            },
    };
    size_t i;

    if (make_keys() != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        printf("== %s\n", cases[i].name);
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAILED: %s\n", cases[i].name);
            return 1;
        }
    }
    printf("test_cmt_node: %d checks passed\n", g_checks);
    return 0;
}
