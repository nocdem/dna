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
 *  2. VALIDATOR UPDATES ARE COVERED (round 2, §A; round 4, R4-2):
 *     `t_val_updates_non_boundary` / `_missing_snapshot` still drive the
 *     REAL `nodus_cmt_app_finalize_block` directly (the
 *     `t_finalize_block_bound` pattern, no host, no signing).
 *     `_quiet_boundary` / `_boundary_diff` drive the REAL HOST pipeline
 *     instead (`vu_host_drive_to`, the `t_d4_empty_blocks_root_stable`
 *     pattern) — round 3 measured that the finalize-block-only pipeline
 *     never writes a Comet BlockMeta, so the committee's tiebreak seed
 *     cannot resolve above height 1 and a boundary above 1 FAULTs there.
 *     `t_finalize_block` itself still asserts nothing about validator
 *     updates — that assertion moved to the four cases above.
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
 *     block carrying more than `env_bound` items — the byte-derived
 *     count (MaxDataBytes / an envelope's framing minimum,
 *     nodus_cmt_app_ledger_init), in the hundreds of thousands at this
 *     fixture's genesis document. The retired `NODUS_CMT_APP_MAX_TXS`
 *     (= `NODUS_W_MAX_BLOCK_TXS`, 10 — the legacy ledger seam's cap)
 *     does not exist in the Comet lane any more (D-4 rev 3 (2); register
 *     row R3-C1a-4, CLOSED delta 1). A DECIDED block above `env_bound`
 *     STOPS THE NODE. `t_finalize_block_bound` proves the refusal is
 *     real and fabricates nothing; it does NOT prove the bound is the
 *     right number, and nothing here exercises a block larger than it.
 *  7. Nothing here was RUN by its author: this package could not build
 *     or run tests. Every expectation is an expectation.
 *  8. ORCHESTRATOR delta 4, item A — `t_finalize_block_empty` proves an
 *     EMPTY decided block (D-4 rev 3's 60 s `create_empty_blocks_
 *     interval`) applies through the real pipeline. It was RED before
 *     its own fix: `blk->cmt.results` was NULL whenever `req->txs_len
 *     == 0` (delta 2's per-request branch left every array NULL), and
 *     the engine's own precondition refuses a NULL results array before
 *     it ever checks the count — independently proven RED by
 *     test_cmt_node.c's `progress_all_synced` case (test_cmt_node.c:
 *     1308), which drives a real node through a real empty height.
 *  9. ORCHESTRATOR delta 11 (R3-W3-C2a-19) / R3 W4 package C —
 *     `t_prepare_proposal_item_cap` proves the CLAIM class cap
 *     (`min(claim_bound, NODUS_V2_APPLY_MAX_CLAIMS)`) keeps 40 GENUINELY
 *     admissible claims (`gfx_open_n`/`build_claim_n`, a real 40-leaf
 *     genesis distribution — not 40 copies of one claim, which the
 *     seam's own in-batch nullifier dedup would have trimmed on its own
 *     and made RED silently equal GREEN) and that FinalizeBlock applies
 *     the resulting 40-claim block for real; `t_process_proposal_item_
 *     cap` proves ProcessProposal's own envelope-class refusal at
 *     `NODUS_V2_ENV_BATCH_MAX` + 1 (11) over independently admissible
 *     AND executable envelopes.
 *     ⚠ CORRECTED CLAIM (this row was wrong through W3): "one envelope
 *     may carry many legs on one domain, unbounded by any item cap" is
 *     NOT a real gap. `dna_env_decode` (shared/dnac/env_wire.c:364-365)
 *     and `dna_env_encode` (:276) both refuse a leg list that is not
 *     STRICTLY ascending by `domain_id`, so a domain_id CANNOT repeat
 *     across one envelope's legs — the per-domain `d->n_tx` bound
 *     (apply.c's admission block) is therefore a PROVEN-UNREACHABLE
 *     FAULT in the engine, never a live risk this test suite needs to
 *     cover.
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

/* ══ deterministic REAL keys — test_v2_produce.c:83-102's shape ══════
 * test_v2_produce.c is deleted with the closed consensus lane (R3 W4);
 * this shape is kept here and this behaviour is now proven only in
 * this file and test_cmt_live.c. */

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
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED */
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
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve;
     * this fixture's allocations spend the whole supply and it is not a
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

/**
 * ORCHESTRATOR delta 11 (R3-W3-C2a-19) — `cfg_make_v3_real`'s own logic,
 * parameterized to `n` allocations instead of hardcoding one. Needed to
 * build MORE than one genuinely, independently claimable distribution
 * leaf: `nodus_witness_v2_claim_admit` (the seam PrepareProposal and
 * ProcessProposal both run their claim candidates through) checks each
 * claim against a REAL committed manifest leaf, so proving the new
 * item-count cap against 40 (or 16, or 17) ADMISSIBLE claims — not 40
 * copies of the same one, which the seam's in-batch nullifier dedup
 * would reject as duplicates past the first — needs a distribution tree
 * with that many leaves.
 *
 * Every leaf's `dest_binding` stays the SAME g_ks[0] binding
 * `cfg_make_v3_real` uses (nodus_witness_v2_claims.c:510-517 binds
 * SHA3-512(claimant pubkey) to this field), so every leaf this builds is
 * claimable by the ONE claimant this file holds signing keys for;
 * distinctness across leaves comes from `source_id` alone (byte 0 fixed
 * at 0x30 as `cfg_make_v3_real`'s does, bytes 1-2 the big-endian index),
 * which is enough: gen.c's own leaf order is ascending `source_id`
 * (nodus_witness_v2_gen.c ~:781-788, `qsort` + `gen_leaf_qcmp`), and
 * these source_ids are already in that order by construction, so no
 * re-sort is needed to know leaf `i` here IS leaf `i` in the committed
 * tree. `TREASURY_RAW` is split `n` ways, remainder folded into the
 * LAST leaf, so Σ allocations == TREASURY_RAW exactly for any `n` (Rule
 * P.2, nodus_witness_v2_gen.c's own supply-sum check) — `TREASURY_RAW`
 * (93 000 000 000 000 000) divided by any `n` this file uses is always
 * >= 1, the one thing an allocation amount must be.
 *
 * `cfg_make_v3_real` itself is left completely UNCHANGED: `t_claim_items`
 * depends on its one-leaf, no-siblings shape (`good->n_siblings = 0`)
 * and must stay on it, not on this.
 *
 * tokenomics-v3 P2 (P2-4): the round-2 (R2-3) `inflation_start`
 * parameter is REMOVED — the genesis inflation start is retired and its
 * only legal value is 0, so there is nothing left to vary (the per-block
 * mint it switched off is deleted).
 */
static int cfg_make_v3_real_n(cfgbox_t *b, uint32_t n)
{
    nodus_v2_gen_config_t *c;
    uint16_t k;
    uint32_t i;
    uint64_t share, rem;

    memset(b, 0, sizeof(*b));
    if (n < 1) {
        return -1;
    }
    b->cfg    = calloc(1, sizeof(*b->cfg));      /* ~240 KB: never stack */
    b->allocs = calloc(n, sizeof(*b->allocs));
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
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED */
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

    share = TREASURY_RAW / n;
    rem   = TREASURY_RAW % n;
    for (i = 0; i < n; i++) {
        memset(b->allocs[i].source_id, 0, sizeof(b->allocs[i].source_id));
        b->allocs[i].source_id[0] = 0x30;
        b->allocs[i].source_id[1] = (uint8_t)(i >> 8);
        b->allocs[i].source_id[2] = (uint8_t)i;
        qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[i].dest_binding);
        b->allocs[i].amount = share + ((i == n - 1) ? rem : 0);
    }
    c->n_allocs = n;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve;
     * this fixture's allocations spend the whole supply and it is not a
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
    uint8_t          chain32[32];
} gfx_t;

/**
 * Derive a version-3 chain and OPEN IT BY HAND.
 *
 * The handle is built field by field rather than through
 * `nodus_witness_create_chain_db`. (The reason first recorded here — that
 * the production open could not recognise a version-3 chain — stopped
 * being true in R3 W3: the post-open gate now reads the stored document,
 * and v2_genesis_fixture.h's v2x_chain_open reopens through it.) This
 * fixture keeps its by-hand open; EVERY field set here is one the
 * app/apply path reads:
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

/**
 * ORCHESTRATOR delta 11 (R3-W3-C2a-19) — `gfx_open`'s own body, with ONE
 * substitution: `cfg_make_v3_real_n(&g->box, n_allocs)`
 * in place of `cfg_make_v3_real(&g->box)`, so the derived chain's genesis
 * commits an `n_allocs`-leaf distribution tree instead of one. `gfx_open`
 * itself is untouched.
 *
 * tokenomics-v3 P2 (P2-4): the round-2 (R2-3) `inflation_start`
 * parameter is REMOVED with the per-block mint it existed to switch off
 * (its only legal value is 0 now); every fixture chain is quiet.
 */
static int gfx_open_n(gfx_t *g, const char *tag, uint32_t n_allocs)
{
    char path[600];
    int  i;

    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real_n(&g->box, n_allocs) != 0) {
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

/**
 * ORCHESTRATOR delta 11 (R3-W3-C2a-19) — build a REAL, independently
 * admissible claim against leaf `index` of an `n`-leaf distribution
 * tree derived by `cfg_make_v3_real_n`/`gfx_open_n` into `g`. Ports
 * `t_claim_items`'s single-leaf construction (below, near its own use)
 * to the general N-leaf case: it recomputes every leaf's hash from
 * `g->box.allocs[]` (already in the ascending `source_id` order gen.c's
 * own leaf sort produces — `cfg_make_v3_real_n`'s `source_id` bytes 1-2
 * already run 0..n-1 in that order, so no re-sort is needed here) and
 * calls `dna_dist_proof_build` (manifest_wire.h:420-428, "test/fixture
 * helper — consensus only VERIFIES") for the one inclusion proof leaf
 * `index` needs. Defined here, beside the two fixture openers it needs
 * (`gfx_t`/`g->box`), so every case below can call it.
 *
 * Every leaf shares the SAME `dest_binding` (`cfg_make_v3_real_n` binds
 * every leaf to `g_ks[0]`'s public key, exactly as `cfg_make_v3_real`
 * binds its one leaf), so every claim this builds is claimable by the
 * ONE claimant this file holds signing keys for; distinctness across
 * indices comes from the LEAF ITSELF (`source_id`, hence `leaf_hash`,
 * hence — manifest_wire.h:493-497 — the nullifier), never from the
 * claimant, so N claims over N distinct leaves carry N distinct
 * nullifiers and none collides in the seam's in-batch dedup.
 *
 * `out`/`out_cap`/`out_len` follow `dna_claim_encode`'s own contract
 * (`cbytes`/`sizeof(cbytes)`/`&clen` in `t_claim_items`).
 * @return 0 with `*out_len` set / -1 on any failure.
 */
static int build_claim_n(gfx_t *g, uint32_t n, uint32_t index,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    dna_gman_t       m;
    uint8_t          mh[64];
    dna_dist_leaf_t *leaves = NULL;
    uint8_t        (*lh)[DNA_V2_ROOT_LEN] = NULL;
    dna_claim_t     *c = NULL;
    uint32_t         i;
    int              rc = -1;

    if (!g || index >= n) {
        return -1;
    }
    if (nodus_witness_v2_manifest_load(g->w, 0, &m) != 0) {
        return -1;
    }
    if (dna_gman_hash(&m, mh) != 0) {
        return -1;
    }
    /* Heap: `n` can be in the tens, and `dna_claim_t` alone is ~5 KB
     * (t_claim_items's own comment) — never on the stack. */
    leaves = (dna_dist_leaf_t *)calloc(n, sizeof(*leaves));
    lh     = calloc(n, sizeof(*lh));
    c      = (dna_claim_t *)calloc(1, sizeof(*c));
    if (!leaves || !lh || !c) {
        goto done;
    }
    for (i = 0; i < n; i++) {
        leaves[i].leaf_version  = DNA_DIST_VERSION;
        leaves[i].source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
        memcpy(leaves[i].source_id, g->box.allocs[i].source_id,
               NODUS_V2_GEN_SRCID_LEN);
        leaves[i].source_amount = g->box.allocs[i].amount;
        memcpy(leaves[i].dest_binding, g->box.allocs[i].dest_binding, 64);
        if (dna_dist_leaf_hash(&leaves[i], lh[i]) != 0) {
            goto done;
        }
    }

    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, g->chain32, DNA_CHAIN_ID_LEN);
    memcpy(c->manifest_hash, mh, 64);
    c->leaf_index    = index;
    c->source_id_len = leaves[index].source_id_len;
    memcpy(c->source_id, leaves[index].source_id, leaves[index].source_id_len);
    c->source_amount = leaves[index].source_amount;
    memcpy(c->dest_binding, leaves[index].dest_binding, 64);
    if (dna_dist_proof_build(lh, n, index, c->siblings, &c->n_siblings) != 0) {
        goto done;
    }
    c->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, g_ks[0].pk, QGP_DSA87_PUBLICKEYBYTES);
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t  pre_len = 0, siglen = 0;

        if (dna_claim_preimage(c, pre, &pre_len) != 0) {
            goto done;
        }
        if (qgp_dsa87_sign(c->signature, &siglen, pre, pre_len,
                           g_ks[0].sk) != 0 || siglen != DNA_CLAIM_SIG_LEN) {
            goto done;
        }
    }
    if (dna_claim_encode(c, out, out_cap, out_len) != 0) {
        goto done;
    }
    rc = 0;

done:
    free(leaves);
    free(lh);
    free(c);
    return rc;
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
 * tokenomics-v3 P4: used by ONE case only, t_chain_id_row_branch_
 * unchanged, whose subject is the height-0-row branch of
 * nodus_witness_v2_chain_id (nodus_witness_v2_claims.c) — a branch of the
 * deleted version-2 genesis that stays in the tree until claims.c is in
 * a package's whitelist (OBLIGATION atlas-dec-71525f3b names it). Every
 * other case that borrowed this fixture now runs on gfx_open. */

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

/* test_v2_produce.c:149-192's shape (that file is deleted with the
 * closed consensus lane, R3 W4), then the S14 rung. ORDER IS
 * LOAD-BEARING: the V2 genesis runs at S9 (the engine's genesis gate
 * accepts S9-S12) and the S9 rung REFUSES a populated v2_blocks, so the
 * climb to S14 comes after. */
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
    /* tokenomics-v3 P2: the cometbft lane's schema gate moved S15 -> S16
     * (nodus_witness_v2_apply.c); the fixture climbs to the live rung. */
    if (nodus_witness_db_migrate_v2s16(fx->w) != 0) {
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

/* ══ a REAL chain_config envelope — test_v2_produce.c:256-410's shape
 * ═══════════════════════════════════════════════════════════════════
 * Copied (that file's copy is static and its fixture type differs); the
 * logic is that function's, retyped over a `nodus_witness_t *`.
 * test_v2_produce.c is deleted with the closed consensus lane (R3 W4);
 * this behaviour is now proven only here and in test_cmt_live.c. */

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

/* ORCHESTRATOR delta 1, item B — the FIXTURE's own transaction-descriptor
 * capacity (exec_t.txs, exec_make_block's data.txs_cap, exec_init's
 * executor `lim.max_txs`), now that NODUS_CMT_APP_MAX_TXS is retired.
 * This is a TEST-LOCAL bound, unrelated to the application's own
 * prep_bound / env_bound (both in the hundreds to hundreds-of-thousands
 * now): every case in this file builds at most a handful of test blocks,
 * so a small, cheap, stack-safe capacity is exactly right here — it says
 * nothing about, and does not need to match, the production bounds the
 * application itself derives at nodus_cmt_app_ledger_init. R3 W4 package
 * C bumped this 32 -> 48: `t_prepare_proposal_item_cap` now drives a
 * real 40-claim decided block through this same `exec_t`, and 40 no
 * longer fits the old 32-entry capacity (it used to only exercise
 * PrepareProposal's response, never `exec_make_block`). Still sized to
 * comfortably exceed every fixture in this file, never to a production
 * bound. */
#define TEST_APP_TXS_CAP 48u

/* ORCHESTRATOR delta 1, item B — the byte-bound test's own "eleven small
 * transactions" figure (t_byte_bound_prepare_and_process), the exact
 * count D-23 rev 7 (24)'s test instruction names. UNCHANGED by delta 4's
 * redesign of that case — only the envelopes' PRICING shape changed. */
#define TEST_APP_SMALL_N 11u

/* ORCHESTRATOR delta 4, item B — the reservation CEILING every byte-bound
 * envelope declares (`res_max_total_units`, env_wire.h:52). Chosen large
 * enough to clear the envelope's own actual `static_units` (verified IN
 * THE TEST against the real committed policy, not assumed here) with
 * generous margin, and small enough that reserving it TEST_APP_SMALL_N+1
 * times over — the worst case if every envelope's FULL ceiling were ever
 * taken from the global budget at once — still leaves the global unit
 * budget (NODUS_V2_GLOBAL_UNIT_BUDGET, nodus_witness_v2_apply.h) mostly
 * unspent. See t_byte_bound_prepare_and_process's own doc comment for
 * the arithmetic this constant is checked against. */
#define TEST_APP_ENV_CEILING 10000ull

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
    cmt_pb_bytes_t          txs[TEST_APP_TXS_CAP];
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

/* R3 W4 package C bumped this 8 -> 16 (512 KiB -> 1 MiB of 64 KiB
 * `CMT_BLOCK_PART_SIZE_BYTES` parts): `t_prepare_proposal_item_cap`'s
 * 40-claim block encodes to roughly 40 x ~7.8 KB (DNA_CLAIM_FIXED_LEN
 * plus a handful of merkle-proof siblings for a 40-leaf tree) =~ 310 KiB
 * of tx bytes alone, which would have been tight against the old 512 KiB
 * ceiling once header/proto framing is added. Still a TEST-LOCAL bound
 * (see TEST_APP_TXS_CAP above), not a production figure. */
#define APP_PARTS_CAP 16u

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
    /* ORCHESTRATOR delta 1, item B — the ledger context now owns heap
     * arrays of its own (nodus_cmt_app_ledger_init); release them before
     * freeing the context struct. NULL-safe. */
    nodus_cmt_app_ledger_release(x->ledger);
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
    /* delta 2, item A: nodus_cmt_app_ledger_t dropped every fixed-size
     * worst-case scratch array (fb_class/fb_of/fb_env/fb_claim/
     * fb_results) in favour of per-request heap allocation — this
     * struct is now a handful of pointers, size_t bounds and three
     * TEST-ONLY fault fields, well under 200 bytes, not the ~85 KB the
     * delta-1 fixed arrays made it. */
    x->ledger   = calloc(1, sizeof(*x->ledger));
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
    lim.max_txs      = TEST_APP_TXS_CAP;
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
    data.txs_cap = TEST_APP_TXS_CAP;
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
    /* ORCHESTRATOR (P1 round 5, MEASURED with gdb on a -g build): the
     * `chain_id` is the derivation's OTHER output (nodus_witness_v2_gen.h
     * :575-588, :648) and was never written back into `box.cfg` either,
     * so every document this helper projected — and therefore every
     * block header `cmt_state_make_block` built from it — carried an
     * ALL-ZERO chain id, while the node's own identity
     * (`w->v2_chain32`, set from the same `g->chain32` in gfx_open_n)
     * is the real one. Nothing noticed until a case crossed an epoch
     * boundary: the version-3 committee tiebreak seed
     * (`v2_seed_block_id`, nodus_witness_committee.c:218-220) compares
     * the stored BlockMeta's header chain id against `w->v2_chain32` and
     * correctly refused it as WRONG CHAIN at height 719. Filled here from
     * the derivation's own output, exactly like `app_hash` above. */
    memcpy(g->box.cfg->chain_id, g->chain32, NODUS_V2_GEN_CHAIN_ID_LEN);
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
    nodus_cmt_app_ledger_release(app);
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
    nodus_cmt_app_ledger_release(app);
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

    /* the same entry at S12. tokenomics-v3 P4: the chain is a real
     * version-3 chain (gfx_open) whose schema version is then rewritten
     * to 12, so the version is the only thing wrong with it — the
     * version-2 fixture this used to borrow is not needed for that. */
    CHECK(gfx_open(&g, "pre_s12") == 0, "version-3 fixture");
    CHECK(run_sql(g.w->db, "PRAGMA user_version = 12") == 0,
          "pretend this node is still at S12");
    CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0, "a host transaction");
    memset(blk, 0, sizeof(*blk));
    blk->global_height = 1;
    blk->epoch = nodus_v2_epoch_for_height(1);
    blk->cmt.on = true;
    blk->cmt.results = results;
    blk->cmt.results_cap = 4;
    CHECK(nodus_witness_v2_apply_block(g.w, blk) == NODUS_V2_INTERNAL_FAULT,
          "the Comet entry refuses at S12");
    CHECK(strstr(blk->out_reason, "schema version") != NULL, "and says so");
    CHECK(run_sql(g.w->db, "ROLLBACK") == 0, "clean up");
    free(blk);
    gfx_close(&g);
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
 * ORCHESTRATOR delta 1, item B (R3-C1a-4, CLOSED) — the application's
 * per-request transaction bound is now `env_bound`, the byte-derived
 * count (MaxDataBytes / an envelope's framing minimum), not the retired
 * `NODUS_CMT_APP_MAX_TXS` (= the ledger seam's old NODUS_W_MAX_BLOCK_TXS,
 * 10). `env_bound` at this fixture's genesis document is in the hundreds
 * of thousands (see nodus_cmt_app_ledger_init's own QGP_LOG_INFO line),
 * so this case does NOT allocate an `env_bound + 1`-sized array — the
 * bound check (`req->txs_len > ctx->env_bound`) is the FIRST thing
 * `finalize_block` reads, before it ever dereferences `req->txs[i]`, so
 * `req.txs_len` alone carries the test and `req.txs` can point at a
 * single dummy descriptor never actually read. (The round-3 version of
 * this case built a real N+1-sized stack array at N=10 and smashed the
 * stack when N grew — the exact class of bug this rewrite avoids by
 * construction, not by being careful.)
 */
static int t_finalize_block_bound(void)
{
    gfx_t                                g;
    cmt_genesis_doc_t                    doc;
    cmt_genesis_validator_t              gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t              *app;
    nodus_abci_request_finalize_block_t  req;
    nodus_abci_response_finalize_block_t resp;
    cmt_pb_bytes_t                       dummy_tx;

    CHECK(gfx_open(&g, "bound") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(app->env_bound > 0, "the byte-bound seam derived a positive "
          "env_bound");

    dummy_tx.data = POISON;
    dummy_tx.len  = sizeof(POISON);
    memset(&req, 0, sizeof(req));
    req.txs     = &dummy_tx;      /* never dereferenced — see above */
    req.txs_len = app->env_bound + 1;
    req.height  = 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_finalize_block(app, &req, &resp) == CMT_FAULT,
          "a decided block above env_bound stops the node");
    CHECK(resp.tx_results_len == 0 && resp.app_hash_len == 0,
          "and it fabricates no results and no app_hash");
    CHECK(sqlite3_get_autocommit(g.w->db) != 0,
          "it opened no transaction of its own");

    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * round 2, §A UNBLOCKED — tokenomics-v3 P1 (D-1, G1): the epoch-boundary
 * ValidatorUpdates diff (nodus_cmt_app_finalize_block's own comment;
 * ctx->val_updates, nodus_witness_cmt_app.h).
 * ═══════════════════════════════════════════════════════════════════════ */

#define VU_EPOCH ((uint64_t)DNAC_EPOCH_LENGTH)

/* Deterministic, per-height, DISTINCT block hash — the SAME byte-pattern
 * shape test_v2_epoch.c's own `mk_block_id` uses (not shared across test
 * binaries), needed only so no two heights this file drives through the
 * DIRECT `nodus_cmt_app_finalize_block` path below ever collide with the
 * engine's own already-committed-elsewhere refusal (`t_finalize_block`'s
 * duplicate-BlockID probe, above, proves that refusal is real). */
static void vu_block_hash(uint8_t out[64], uint64_t h)
{
    int i;

    for (i = 0; i < 8; i++) {
        out[i] = (uint8_t)(h >> (56 - 8 * i));
    }
    for (i = 8; i < 64; i++) {
        out[i] = (uint8_t)((h * 7u + (uint64_t)i * 3u + 1u) & 0xFF);
    }
}

/**
 * Drive height `h` through the REAL `nodus_cmt_app_finalize_block`,
 * bypassing the exec_t/cmt_state/blockexec pipeline entirely — the SAME
 * minimal pattern `t_finalize_block_bound` above already establishes (a
 * hand-built request straight into the application, no host, no
 * signing: the apply path "reads only the SIZE and each slot's
 * block_id_flag — it does not verify these signatures", D-2's own
 * comment on `exec_make_last_commit`), extended with a FULL-COMMITTEE
 * COMMIT vote for every height above the initial one (R2-2's own
 * discipline: Rule N must stay a no-op while these cases drive across an
 * epoch boundary, or the whole genesis committee AUTO_RETIREs before any
 * of this file's controlled mutations produce a diff to observe).
 * `finalize_block` itself opens no transaction
 * (nodus_witness_cmt_app.h: "the application never issues BEGIN") — this
 * helper opens and closes the ONE transaction the HOST normally brackets
 * it in, exactly as `t_finalize_block`'s duplicate-BlockID probe does
 * for a direct engine call.
 *
 * @return CMT_OK or CMT_FAULT (the application's own verdict); `resp` is
 *         always fully populated by `nodus_cmt_app_finalize_block` itself
 *         (memset first).
 */
static int vu_drive(nodus_witness_t *w, nodus_cmt_app_ledger_t *app,
                    uint64_t h, nodus_abci_response_finalize_block_t *resp)
{
    nodus_abci_request_finalize_block_t req;
    nodus_abci_vote_info_t votes[N_KEYS];
    int i, rc;

    memset(&req, 0, sizeof(req));
    memset(votes, 0, sizeof(votes));
    for (i = 0; i < N_KEYS; i++) {
        memcpy(votes[i].validator.address, g_ks[i].voter, 32);
        votes[i].validator.address_len = 32;
        votes[i].block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    if (h > 1) {
        /* h == 1 is the initial height (execution.go:451-455) — the
         * legal empty case (D-2's own comment); every height above it
         * carries a real commit for h-1. */
        req.decided_last_commit.votes     = votes;
        req.decided_last_commit.votes_len = (size_t)N_KEYS;
    }
    req.height = (int64_t)h;
    vu_block_hash(req.hash, h);
    req.hash_len = 64;

    memset(resp, 0, sizeof(*resp));
    if (run_sql(w->db, "BEGIN IMMEDIATE") != 0) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_app_finalize_block(app, &req, resp);
    if (rc != CMT_OK) {
        (void)run_sql(w->db, "ROLLBACK");
        return rc;
    }
    if (run_sql(w->db, "COMMIT") != 0) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* Drive every height in (from, to] with `vu_drive`, discarding each
 * response — the run-up blocks exist only to reach a target height with
 * full attendance behind them. */
static int vu_drive_to(nodus_witness_t *w, nodus_cmt_app_ledger_t *app,
                       uint64_t from, uint64_t to)
{
    uint64_t h;

    for (h = from + 1; h <= to; h++) {
        nodus_abci_response_finalize_block_t resp;

        if (vu_drive(w, app, h, &resp) != CMT_OK) {
            fprintf(stderr, "vu_drive_to: height %" PRIu64 " FAULTed\n", h);
            return -1;
        }
    }
    return 0;
}

/* §A round 4 (R4-2): drive heights (from, to] through the REAL host
 * pipeline `t_d4_empty_blocks_root_stable` already establishes —
 * `exec_make_block` / `exec_make_last_commit` / `exec_block_id` /
 * `nodus_cmt_host_apply_verified_block` — every block carrying ZERO
 * transactions (these §A cases are about the validator-updates response,
 * not envelopes). MEASURED (round 3): the OLDER `vu_drive`/`vu_drive_to`
 * pipeline calls `nodus_cmt_app_finalize_block` directly and never writes
 * a Comet BlockMeta, so the committee's tiebreak seed
 * (`v2_seed_block_id`, nodus_witness_committee.c:178-227) cannot resolve
 * above height 1 and any boundary above 1 FAULTs.
 *
 * ⚠ ORCHESTRATOR correction (round 4, MEASURED): applying a block does
 * NOT save it. An earlier version of this comment claimed this pipeline
 * "writes the BlockMeta itself, through `nodus_cmt_bs_save_block`
 * (nodus_witness_cmt_host.c)" — it does not, and the boundary still
 * FAULTed with `V2 seed row at 719 missing or unusable` after the move.
 * `nodus_cmt_bs_save_block`'s only production call site is the HOST
 * TABLE row `nodus_witness_cmt_host.c:1965` serves, which the CONSENSUS
 * layer (`cmt_cs`'s finalizeCommit) calls — never the block executor.
 * So this helper stands in for that layer too: after each apply it saves
 * the block with its part set and a seen commit, exactly the recipe the
 * two other fixtures that need a real BlockMeta already use
 * (`test_v2_preflight.c:732`, `test_v2_committee_seed.c:532`, both of
 * whose comments name themselves "the only caller"). The part set is
 * built here rather than through `exec_block_id`, which discards its own.
 *
 * `*bid` is the caller's scratch BlockID: zeroed by the caller before the
 * first call, and left holding `to`'s BlockID on return.
 */
static int vu_host_drive_to(exec_t *x, cmt_block_id_t *bid, int64_t from,
                            int64_t to)
{
    /* The block store marshals the block, its parts, the meta and the
     * commits into this scratch; it must NOT be `x->part_scratch`, which
     * the part set below still points into. Every block here carries zero
     * transactions, so 1 MiB is far more than `cmt_block_size`'s need. */
    const size_t save_cap = 1u << 20;
    uint8_t     *save_scratch = (uint8_t *)malloc(save_cap);
    int64_t      h;
    int          rc = -1;

    if (!save_scratch) {
        return -1;
    }
    for (h = from + 1; h <= to; h++) {
        cmt_part_set_t ps;
        cmt_commit_t   seen_commit;

        if (h > 1) {
            if (exec_make_last_commit(x, h - 1, bid) != 0) {
                fprintf(stderr, "vu_host_drive_to: last_commit for %"
                        PRId64 " failed\n", h - 1);
                goto done;
            }
        }
        if (exec_make_block(x, h, 0) != 0) {
            fprintf(stderr, "vu_host_drive_to: make_block %" PRId64
                    " failed\n", h);
            goto done;
        }
        /* `exec_block_id`'s body, with the part set KEPT — the block
         * store needs it and that helper throws its own away. */
        memset(bid, 0, sizeof(*bid));
        if (cmt_block_hash(x->blk, bid->hash) != CMT_OK) {
            fprintf(stderr, "vu_host_drive_to: block_hash %" PRId64
                    " failed\n", h);
            goto done;
        }
        bid->hash_len = CMT_TMHASH_SIZE;
        if (cmt_block_make_part_set(x->blk, CMT_BLOCK_PART_SIZE_BYTES,
                                    x->part_scratch, x->part_scratch_cap,
                                    x->parts, x->parts_cap, &ps) != CMT_OK ||
            cmt_part_set_header(&ps, &bid->part_set_header) != CMT_OK ||
            !block_id_is_complete(bid)) {
            fprintf(stderr, "vu_host_drive_to: block_id %" PRId64
                    " incomplete\n", h);
            goto done;
        }
        if (nodus_cmt_host_apply_verified_block(x->be, bid, x->blk, x->state)
                != CMT_OK) {
            fprintf(stderr, "vu_host_drive_to: apply %" PRId64
                    " FAULTed\n", h);
            goto done;
        }
        /* The half the executor does NOT do (see this function's own
         * comment): without it there is no BlockMeta and the committee
         * tiebreak seed cannot resolve at the boundary's lookback. */
        memset(&seen_commit, 0, sizeof(seen_commit));
        seen_commit.height   = h;
        seen_commit.round    = 0;
        seen_commit.block_id = *bid;
        if (nodus_cmt_bs_save_block(x->store, x->blk, &ps, &seen_commit,
                                    save_scratch, save_cap) != CMT_OK) {
            fprintf(stderr, "vu_host_drive_to: save_block %" PRId64
                    " failed\n", h);
            goto done;
        }
    }
    rc = 0;
done:
    free(save_scratch);
    return rc;
}

/* Load the FinalizeBlock response the boundary block itself stored
 * (`nodus_cmt_ss_save_finalize_block_response`, nodus_witness_cmt_host.c
 * apply_block :259) — the ONLY way to read `resp->validator_updates` back
 * out of the REAL host pipeline, which frees its own `resp` internally
 * (nodus_witness_cmt_host.c apply_block :1646). `vu_pool`/`vu_cap` size
 * the validator_updates pool; a validator update's pubkey is a FIXED
 * 2592-byte array on the struct itself (cmt_pb.h's cmt_pb_public_key_t),
 * so `arena` only needs to be non-NULL — these §A cases never encode a
 * tx_result or an event (every driven block carries zero transactions).
 */
static int vu_host_load_updates(exec_t *x, int64_t height,
                                cmt_pb_response_finalize_block_t *out,
                                cmt_pb_validator_update_t *vu_pool,
                                size_t vu_cap, cmt_pb_arena_t *arena)
{
    cmt_pb_rfb_storage_t rst;

    memset(&rst, 0, sizeof(rst));
    rst.validator_updates     = vu_pool;
    rst.validator_updates_cap = vu_cap;
    rst.arena                 = arena;
    memset(out, 0, sizeof(*out));
    return nodus_cmt_ss_load_finalize_block_response(x->store, height, &rst,
                                                      out);
}

/**
 * §A — a non-boundary height returns NULL/0: the legal "leave the set"
 * response (replay.go:346-360). Cheapest possible drive: height 1 alone.
 */
static int t_val_updates_non_boundary(void)
{
    gfx_t                                 g;
    cmt_genesis_doc_t                     doc;
    cmt_genesis_validator_t               gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                *app;
    nodus_abci_response_finalize_block_t   resp;

    /* (round 2 hardening used an inflation-OFF genesis here;
     * tokenomics-v3 P2 deleted the mint, so every fixture is quiet.) */
    CHECK(gfx_open_n(&g, "vu_nonb", 1) == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");

    CHECK(vu_drive(g.w, app, 1, &resp) == CMT_OK, "height 1 applies");
    CHECK(resp.validator_updates == NULL && resp.validator_updates_len == 0,
          "§A: a non-boundary height returns NULL/0");

    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * §A — the FIRST boundary (height E) is unavoidably QUIET: both
 * snapshot(0) and snapshot(E) are written by
 * `nodus_witness_vset_commit_genesis` in the SAME transaction, from the
 * SAME unmutated `validators` table (nodus_witness_vset.c) — so a
 * freshly-derived chain's first boundary always compares a set against
 * itself. Proves the quiet case without needing any mutation: unchanged
 * members are not re-announced.
 *
 * round 4 (R4-2, MEASURED): this case used to drive `vu_drive`/
 * `vu_drive_to` (a direct call into `nodus_cmt_app_finalize_block`).
 * Round 3 measured that pipeline never writes a Comet BlockMeta, so the
 * committee's tiebreak seed (`v2_seed_block_id`,
 * nodus_witness_committee.c:178-227 — needs BOTH the `v2_blocks` row AND
 * a BlockMeta at the lookback height) cannot resolve above height 1 and
 * this case FAULTed at the boundary. It now drives `vu_host_drive_to`
 * (the REAL host pipeline `t_d4_empty_blocks_root_stable` establishes —
 * see that helper's own comment), which writes the BlockMeta itself.
 */
static int t_val_updates_quiet_boundary(void)
{
    gfx_t                             g;
    exec_t                            x;
    cmt_block_id_t                    bid;
    cmt_pb_response_finalize_block_t  got;
    cmt_pb_validator_update_t         vu_pool[8];
    cmt_pb_arena_t                    arena;
    uint8_t                           arena_buf[1024];

    CHECK(gfx_open_n(&g, "vu_quiet", 1) == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    memset(&bid, 0, sizeof(bid));
    CHECK(vu_host_drive_to(&x, &bid, 0, (int64_t)VU_EPOCH) == 0,
          "drive height 1..E through the REAL host pipeline; the first "
          "boundary applies");

    arena.buf = arena_buf;
    arena.cap = sizeof(arena_buf);
    arena.used = 0;
    CHECK(vu_host_load_updates(&x, (int64_t)VU_EPOCH, &got, vu_pool, 8,
                               &arena) == CMT_OK,
          "load the boundary's stored FinalizeBlock response");
    CHECK(got.validator_updates_len == 0,
          "§A: a quiet boundary returns validator_updates_len 0");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * §A — either snapshot ABSENT or UNREADABLE is CMT_FAULT, never an
 * empty list. Deletes the OLD snapshot (epoch_start 0) after driving to
 * E-1. MEASURED, not assumed: `nodus_witness_vset_apply_boundary_flips`
 * (the engine's OWN boundary step that also touches snapshots) reads
 * snapshot(boundary_height) = snapshot(E), NOT snapshot(0)
 * (nodus_witness_vset.c) — and treats an ABSENT one as a graceful
 * pre-S3 skip, not a fault — so deleting snapshot(0) does not disturb
 * the engine's own internal boundary processing at all; the ONLY reader
 * of snapshot(0) at this boundary is this package's OWN §A diff
 * (`nodus_witness_v2_epoch_authority_for_epoch(w, H-E, ...)`), which is
 * exactly the path this case isolates.
 */
static int t_val_updates_missing_snapshot(void)
{
    gfx_t                                 g;
    cmt_genesis_doc_t                     doc;
    cmt_genesis_validator_t               gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                *app;
    nodus_abci_response_finalize_block_t   resp;

    CHECK(gfx_open_n(&g, "vu_missing", 1) == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");

    CHECK(vu_drive_to(g.w, app, 0, VU_EPOCH - 1) == 0, "drive to E-1");
    CHECK(run_sql(g.w->db,
              "DELETE FROM validator_set_snapshots WHERE epoch_start = 0")
              == 0, "remove the OLD snapshot the boundary's diff needs");

    CHECK(vu_drive(g.w, app, VU_EPOCH, &resp) == CMT_FAULT,
          "§A: a missing snapshot is CMT_FAULT, never an empty list");

    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * §A — twin-condition boundary diff: the mutated snapshot(E), diffed at
 * the FIRST boundary (E) against the unmutated, genesis-seeded
 * snapshot(0), with all THREE update kinds produced in a single pass: an
 * added member, a power change on an existing member, and a removed
 * member.
 *
 * round 4 (R4-2, MEASURED, replaces rounds 2/3's approach): this case
 * used to drive to the SECOND boundary (2E), mutating the `validators`
 * table between E-1 and E so the ENGINE's own
 * `nodus_witness_vset_commit_next(E)` would build a different snapshot(2E)
 * live. Two problems, both measured: (a) `vu_drive`'s finalize-block-only
 * pipeline cannot resolve the committee's tiebreak seed above height 1
 * (no BlockMeta — see `t_val_updates_quiet_boundary`'s own comment), and
 * (b) funding the added/doubled self_stake out of the genesis treasury
 * leaf so the supply invariant would still balance.
 *
 * §A's OWN diff (nodus_witness_cmt_app.c ~1504-1674) reads ONLY the two
 * COMMITTED SNAPSHOTS — `nodus_witness_v2_epoch_authority_for_epoch(w, H)`
 * and `(w, H-E)` — and never reads the `validators` table at all (that
 * resolver's own header, nodus_witness_v2_epoch.h:601-609: "nothing here
 * reads the `validators` table, at any height, ever"). So the same three
 * update kinds are produced with only ONE boundary (E, not 2E) by
 * mutating the COMMITTED snapshot(E) row directly — no `validators` row,
 * no funding, and `vu_host_drive_to` resolves the committee tiebreak seed
 * the same way `t_val_updates_quiet_boundary` now does.
 *
 * The mutated snapshot is built by loading the GENUINE, genesis-seeded
 * snapshot(E) — identical to snapshot(0), the quiet case's own proof —
 * copying every entry EXCEPT g_ks[2] (the removal), doubling g_ks[1]'s
 * `total_stake` (the power change — still a whole multiple of
 * DNAC_DECIMAL_UNIT, DNAC_SELF_STAKE_AMOUNT already is one), and
 * appending an 8th, freshly-generated ML-DSA-87 entry (the addition) —
 * then re-encoding and overwriting the `validator_set_snapshots` row for
 * epoch_start E directly (test-only — `nodus_witness_vset_insert` would
 * CONFLICT, -2, on a differing hash for an existing row, by design: that
 * is the cross-node identity check this fixture deliberately bypasses,
 * the same class of direct-row mutation `test_v2_epoch.c`'s own
 * `seed_validator` uses on `validators`).
 *
 * The boundary's OTHER consumers of this same snapshot do not fault:
 * `nodus_witness_vset_apply_boundary_flips(E)` (nodus_witness_vset.c)
 * runs as part of this SAME block's own processing and DOES consume the
 * mutated snapshot(E) — its pass 2 (`UPDATE validators SET status=ACTIVE
 * WHERE pubkey=? AND status=ELIGIBLE`) simply updates ZERO rows for the
 * added member's pubkey (no `validators` row exists to match, never a
 * fault); g_ks[2] (dropped from the mutated snapshot) is left ELIGIBLE
 * rather than re-flipped to ACTIVE — a real but harmless side effect,
 * since this case never drives past E or asserts anything about the
 * `validators` table. `nodus_witness_vset_commit_next(E)` then builds
 * snapshot(2E) from the POST-flip `validators` table, which our
 * snapshot(E) mutation never touched, and succeeds normally.
 *
 * §A's OWN algorithm guarantees every addition/power-change entry
 * PRECEDES every removal in the response (snap_new order, then snap_old
 * order) — this case asserts that ordering invariant directly (no
 * addition/change ever seen after the first removal) rather than
 * replicating `nodus_validator_top_n`'s own `ORDER BY`, which would make
 * the test as complex as the code it is checking.
 *
 * HOW THIS CAN LIE: combining the three into one mutated snapshot (rather
 * than three separate single-mutation drives) is a deliberate cost trade
 * — it does not prove the three kinds are independent of each other, only
 * that they compose correctly when they occur together in the same
 * boundary.
 */
static int t_val_updates_boundary_diff(void)
{
    gfx_t                              g;
    exec_t                             x;
    cmt_block_id_t                     bid;
    cmt_pb_response_finalize_block_t   got;
    cmt_pb_validator_update_t          vu_pool[16];
    cmt_pb_arena_t                     arena;
    uint8_t                            arena_buf[8192];
    dna_vset_snapshot_t                *old_snap = NULL;
    dna_vset_snapshot_t                *mutated = NULL;
    uint8_t                             extra_pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t                             extra_sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t                             extra_seed[32];
    uint8_t                             extra_digest[64];
    uint8_t                            *blob = NULL;
    size_t                              enc_len = 0, written = 0, mi = 0, oi;
    sqlite3_stmt                       *st = NULL;
    size_t                              i;
    int                                 found_added = 0, found_changed = 0,
                                         found_removed = 0;
    int                                 saw_g1 = 0, saw_g2 = 0;
    uint64_t expect_changed_power =
        2ULL * DNAC_SELF_STAKE_AMOUNT / DNAC_DECIMAL_UNIT;
    uint64_t expect_added_power = DNAC_SELF_STAKE_AMOUNT / DNAC_DECIMAL_UNIT;

    CHECK(gfx_open_n(&g, "vu_diff", 1) == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    CHECK(nodus_witness_vset_get(g.w, VU_EPOCH, &old_snap, NULL) == 0,
          "load the genesis-seeded snapshot(E)");
    CHECK(old_snap->active_count == (uint16_t)N_KEYS,
          "FIXTURE GUARD: genesis seeded snapshot(E) with all N_KEYS "
          "members");

    mutated = dna_vset_alloc((uint16_t)N_KEYS);
    CHECK(mutated != NULL, "alloc the mutated snapshot");
    mutated->epoch = VU_EPOCH;
    /* selection_ruleset + the all-zero sortition_seed dna_vset_alloc sets
     * are exactly what TOPN_V1 requires (vset_wire.h). */

    for (oi = 0; oi < old_snap->active_count; oi++) {
        const dna_vset_entry_t *oe = &old_snap->entries[oi];

        if (memcmp(oe->pubkey, g_ks[2].pk, DNAC_PUBKEY_SIZE) == 0) {
            saw_g2 = 1;
            continue;                          /* removal */
        }
        CHECK(mi < mutated->active_count, "room for the kept entry");
        mutated->entries[mi] = *oe;
        if (memcmp(oe->pubkey, g_ks[1].pk, DNAC_PUBKEY_SIZE) == 0) {
            mutated->entries[mi].total_stake *= 2;    /* power change */
            saw_g1 = 1;
        }
        mi++;
    }
    CHECK(saw_g1 && saw_g2,
          "FIXTURE GUARD: g_ks[1] and g_ks[2] were both present in the "
          "genesis-seeded snapshot(E) before this case mutated it");
    CHECK(mi == (size_t)mutated->active_count - 1,
          "N_KEYS - 1 members copied verbatim (or doubled)");

    /* addition: a freshly-generated 8th key, appended last */
    memset(extra_seed, 0x50, sizeof(extra_seed));
    CHECK(qgp_dsa87_keypair_derand(extra_pk, extra_sk, extra_seed) == 0,
          "the 8th keypair");
    CHECK(qgp_sha3_512(extra_pk, DNAC_PUBKEY_SIZE, extra_digest) == 0,
          "the 8th voter_id");
    memcpy(mutated->entries[mi].voter_id, extra_digest, 32);
    memcpy(mutated->entries[mi].pubkey, extra_pk, DNAC_PUBKEY_SIZE);
    mutated->entries[mi].total_stake = DNAC_SELF_STAKE_AMOUNT;
    mutated->entries[mi].self_bond   = DNAC_SELF_STAKE_AMOUNT;
    mutated->entries[mi].commission_bps = 100;
    mi++;
    CHECK(mi == (size_t)mutated->active_count, "N_KEYS entries total");

    /* ORCHESTRATOR (round 5, MEASURED): the overwrite below must happen
     * AFTER heights 1..E-1 are committed, not before height 1.
     * `validator_set_snapshots` is a leg of `system_state_root`, and the
     * SYSTEM domain head committed at genesis still carries the ORIGINAL
     * snapshot's root. Overwritten before height 1, the first block —
     * which does not touch SYSTEM — trips the engine's untouched-domain
     * guard ("domain 0 was not declared touched yet its root moved",
     * `nodus_witness_v2_apply.c` phase 8) and the case never reaches its
     * boundary. The boundary block at E DOES declare SYSTEM touched, so
     * a mutation landed just before it is recorded as that block's new
     * SYSTEM root instead of being refused. */
    memset(&bid, 0, sizeof(bid));
    CHECK(vu_host_drive_to(&x, &bid, 0, (int64_t)VU_EPOCH - 1) == 0,
          "drive height 1..E-1 through the REAL host pipeline, before "
          "the snapshot(E) overwrite");

    enc_len = dna_vset_encoded_len(mutated);
    CHECK(enc_len > 0, "the mutated snapshot encodes");
    blob = (uint8_t *)malloc(enc_len);
    CHECK(blob != NULL, "alloc");
    CHECK(dna_vset_encode(mutated, blob, enc_len, &written) == 0 &&
          written == enc_len, "encode the mutated snapshot");
    {
        uint8_t hash[DNA_VSET_HASH_LEN];

        CHECK(dna_vset_hash(mutated, hash) == 0,
              "hash the mutated snapshot");
        /* test-only direct overwrite: nodus_witness_vset_insert CONFLICTs
         * (-2) on a differing hash for an existing row, by design (the
         * cross-node identity check this fixture deliberately bypasses —
         * see this case's own doc comment). */
        CHECK(sqlite3_prepare_v2(g.w->db,
                "UPDATE validator_set_snapshots SET active_count = ?1, "
                "snapshot_hash = ?2, snapshot_blob = ?3 "
                "WHERE epoch_start = ?4", -1, &st, NULL) == SQLITE_OK,
              "prep");
        sqlite3_bind_int(st, 1, (int)mutated->active_count);
        sqlite3_bind_blob(st, 2, hash, DNA_VSET_HASH_LEN, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, blob, (int)enc_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)VU_EPOCH);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "overwrite snapshot(E)");
        CHECK(sqlite3_changes(g.w->db) == 1, "exactly one row updated");
        sqlite3_finalize(st);
        st = NULL;
    }
    free(blob);
    blob = NULL;
    dna_vset_free(&mutated);
    dna_vset_free(&old_snap);

    CHECK(vu_host_drive_to(&x, &bid, (int64_t)VU_EPOCH - 1,
                           (int64_t)VU_EPOCH) == 0,
          "apply the boundary block E; it diffs snapshot(E) [mutated] "
          "against snapshot(0) [genesis]");

    arena.buf = arena_buf;
    arena.cap = sizeof(arena_buf);
    arena.used = 0;
    CHECK(vu_host_load_updates(&x, (int64_t)VU_EPOCH, &got, vu_pool, 16,
                               &arena) == CMT_OK,
          "load the boundary's stored FinalizeBlock response");
    CHECK(got.validator_updates_len == 3,
          "§A: exactly one added + one power-changed + one removed");

    for (i = 0; i < got.validator_updates_len; i++) {
        const cmt_pb_validator_update_t *u = &got.validator_updates[i];

        CHECK(u->pub_key.present, "every update carries a key");
        if (u->power == 0) {
            CHECK(memcmp(u->pub_key.key, g_ks[2].pk, DNAC_PUBKEY_SIZE) == 0,
                  "§A: the ONLY power-0 entry is the removed member");
            found_removed = 1;
        } else if (memcmp(u->pub_key.key, g_ks[1].pk,
                          DNAC_PUBKEY_SIZE) == 0) {
            CHECK(!found_removed,
                  "§A: additions/power-changes precede removals");
            CHECK((uint64_t)u->power == expect_changed_power,
                  "§A: the power-changed entry carries the NEW power");
            found_changed = 1;
        } else if (memcmp(u->pub_key.key, extra_pk,
                          DNAC_PUBKEY_SIZE) == 0) {
            CHECK(!found_removed,
                  "§A: additions/power-changes precede removals");
            CHECK((uint64_t)u->power == expect_added_power,
                  "§A: the added entry carries its own power");
            found_added = 1;
        } else {
            CHECK(0, "§A: an update for a pubkey this case did not touch");
        }
    }
    CHECK(found_added && found_changed && found_removed,
          "§A: all three expected updates were present");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * ORCHESTRATOR delta 4, item A (D-4 rev 3's `create_empty_blocks_interval`,
 * 60 s) — AN EMPTY DECIDED BLOCK.
 *
 * RED against the code before this fix, proven independently:
 * test_cmt_node.c's `progress_all_synced` case (test_cmt_node.c:1308,
 * "block 1 saved and applied") drove a real node through a real height
 * with zero transactions and failed with the ENGINE's own precondition —
 * `[ERR/CMT-APP] FinalizeBlock: the ledger could not apply the decided
 * block at height 1 (rc -2): FAULT: cometbft lane: the caller's result
 * array holds 0 of the 0 items this block carries`. Root cause: delta 2's
 * `req->txs_len == 0` branch (nodus_witness_cmt_app.c) left EVERY
 * per-request array NULL, including `results_arr` — so `blk->cmt.results`
 * (nodus_witness_cmt_app.c:1165, formerly :1141) was NULL, and the
 * engine's own precondition (nodus_witness_v2_apply.c:2185-2191) refuses
 * `blk->cmt.results == NULL` BEFORE it ever looks at the count. Under
 * D-4 rev 3 a quiet chain produces an empty block every 60 s, so this was
 * not a corner case — it was the FIRST block a quiet chain would ever
 * apply, stopping the node at once. Fixed by allocating `results_arr`
 * unconditionally (`calloc(req->txs_len ? req->txs_len : 1, …)` — never a
 * bare `calloc(0, …)`, whose result is implementation-defined and this
 * tree builds for Windows/Android too) while `results_cap` stays the
 * TRUE `req->txs_len` (0 here), so the engine's count-based logic is
 * unaffected and only the NULL-avoidance slot exists.
 *
 * Proves: a decided block with ZERO transactions, through the REAL
 * pipeline (`exec_make_block` with 0 txs, `exec_block_id`,
 * `nodus_cmt_host_apply_verified_block`), commits a `v2_blocks` row at
 * height 1 with `tx_count == 0` and a stored `global_root` equal to the
 * committed global root (`app_hash`, D-23 rev 4 (3)); and that a SECOND
 * empty block at height 2 — the ordinary 60 s cadence, not a one-off —
 * also applies, with its own stored `abciResponsesKey:2` row.
 */
static int t_finalize_block_empty(void)
{
    gfx_t          g;
    exec_t         x;
    cmt_block_id_t bid;
    uint8_t        root[64], stored_root[64];

    CHECK(gfx_open(&g, "empty") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    /* ── height 1: the FIRST block a quiet chain ever applies ────────── */
    CHECK(exec_make_block(&x, 1, 0) == 0, "block 1 with ZERO transactions");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID even for an empty block");

    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK, "an EMPTY decided block applies (was CMT_FAULT "
          "before this fix)");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1,
          "one block row committed");
    CHECK(q1(g.w->db, "SELECT tx_count FROM v2_blocks "
             "WHERE global_height = 1") == 0,
          "tx_count is 0 for the empty block");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0,
          "the committed global root");
    CHECK(row_blob(g.w, "global_root", 1, stored_root) == 0,
          "the stored row's global_root");
    CHECK(memcmp(root, stored_root, 64) == 0,
          "app_hash equals the committed global root — an empty block "
          "still commits a real state root");
    CHECK(has_state_key(g.w->db, "abciResponsesKey:1") == 1,
          "the (empty) FinalizeBlock response is stored for height 1 — "
          "an empty repeated field marshals fine (cmt_pb_store.c's "
          "response_finalize_block_wr only rejects tx_results_len != 0 "
          "paired with a NULL pointer)");

    /* ── height 2: the ORDINARY 60 s cadence, not a one-off ──────────── */
    CHECK(exec_make_last_commit(&x, 1, &bid) == 0,
          "a precommit from every validator for block 1");
    CHECK(exec_make_block(&x, 2, 0) == 0, "block 2 with ZERO transactions");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "block 2's COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK, "a SECOND empty decided block applies");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 2,
          "two block rows committed");
    CHECK(has_state_key(g.w->db, "abciResponsesKey:2") == 1,
          "the second empty block's response is stored too");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * tokenomics-v3 P1 (D-4) — THE PROPERTY test_pf_ready_after_first_block
 * (test_v2_preflight.c) can no longer discriminate on its own: TWO
 * structurally-identical EMPTY, non-boundary blocks commit the SAME
 * global_root, even when the second block's decided_last_commit carries
 * a FULL-COMMITTEE COMMIT vote for the first.
 *
 * RED on the code this package replaces: the O15C proposer-credit writer
 * ran on EVERY block (crediting the committed header proposer into the
 * validator merkle leaf), so `system_state_root` — and therefore
 * `global_root`/`app_hash` — moved at every height regardless of whether
 * the block carried any transaction. This exact equality would have
 * FAILED against that code: root1 (no attendance writer has run yet)
 * would differ from root2 (one proposer credit landed in the validator
 * leaf).
 *
 * GREEN on this package: `v2_attendance` is out-of-root (D-4) — a credit
 * lands in that table (proven below, so the equality is not vacuously
 * true because "nothing happened") but does not touch any leg of
 * `system_state_root` until the epoch boundary's digest leg commits a
 * SUMMARY of the whole ended epoch.
 */
static int t_d4_empty_blocks_root_stable(void)
{
    gfx_t          g;
    exec_t         x;
    cmt_block_id_t bid1, bid2;
    uint8_t        root1[64], root2[64];

    /* round 2 (R2-3, MEASURED) needed an inflation-OFF genesis here: the
     * O15J per-block mint moved `epoch_state.epoch_pool_accum` (a SYSTEM
     * leg) on every block, making this case's D-4 equality unsatisfiable
     * for a reason unrelated to attendance. tokenomics-v3 P2 deleted the
     * mint, so the case is unconditional now — any fixture is quiet. */
    CHECK(gfx_open_n(&g, "d4stable", 1) == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    CHECK(exec_make_block(&x, 1, 0) == 0, "block 1 with ZERO transactions");
    CHECK(exec_block_id(&x, x.blk, &bid1) == 0 &&
          block_id_is_complete(&bid1), "block 1's COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid1, x.blk, x.state)
              == CMT_OK, "block 1 applies");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root1) == 0,
          "root after block 1");

    /* block 2's decided_last_commit: EVERY validator voted COMMIT for
     * block 1 — the busiest honest case this lane can carry, chosen
     * deliberately over the quietest (an all-ABSENT commit would prove
     * nothing about whether a REAL credit fails to move the root). */
    CHECK(exec_make_last_commit(&x, 1, &bid1) == 0,
          "a precommit from every validator for block 1");
    CHECK(exec_make_block(&x, 2, 0) == 0, "block 2 with ZERO transactions");
    CHECK(exec_block_id(&x, x.blk, &bid2) == 0 &&
          block_id_is_complete(&bid2), "block 2's COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid2, x.blk, x.state)
              == CMT_OK, "block 2 applies");
    CHECK(nodus_witness_v2_committed_global_root(g.w, root2) == 0,
          "root after block 2");

    CHECK(memcmp(root1, root2, 64) == 0,
          "D-4: two structurally-identical empty blocks commit the SAME "
          "global_root, even though block 2's decided_last_commit "
          "carries a full-committee COMMIT vote crediting block 1");

    /* the credit DID land — proves the equality above is "out of root",
     * never "the writer did not run" (a vacuous pass). */
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_attendance WHERE "
                      "signed_count > 0") > 0,
          "v2_attendance recorded the credit even though the root did "
          "not move");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * tokenomics-v3 P1 (D-2, Q1) — attendance rows from a decided_last_commit
 * MIXING all three block_id_flag values: only COMMIT credits
 * `v2_attendance`; NIL and ABSENT do not, even though every slot here
 * carries a REAL, validly-signed vote (the apply path does not verify
 * signatures — `ApplyVerifiedBlock` is by definition past verification —
 * so this proves the FLAG is what gates the credit, not the presence or
 * validity of a signature).
 *
 * `exec_make_last_commit` signs every slot as a COMMIT (a complete
 * BlockID yields a COMMIT entry — vote.go:101-123, the doc comment on
 * that helper). This case then OVERWRITES two slots' `block_id_flag` to
 * NIL and ABSENT post-hoc: the apply path "reads only the SIZE and each
 * slot's block_id_flag — it does not verify these signatures" (the same
 * helper's own doc comment), so tampering the flag after a real signature
 * was produced is exactly the shape the reference itself would apply
 * (a NIL or ABSENT `CommitSig` never carries a meaningful signature to
 * begin with — vote.go's own construction).
 */
static int t_attendance_mixed_flags(void)
{
    gfx_t          g;
    exec_t         x;
    cmt_block_id_t bid1, bid2;

    CHECK(gfx_open(&g, "mixedflags") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    CHECK(exec_make_block(&x, 1, 0) == 0, "block 1 with ZERO transactions");
    CHECK(exec_block_id(&x, x.blk, &bid1) == 0 &&
          block_id_is_complete(&bid1), "block 1's COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid1, x.blk, x.state)
              == CMT_OK, "block 1 applies");

    CHECK(exec_make_last_commit(&x, 1, &bid1) == 0,
          "a real precommit from every validator for block 1");
    CHECK(x.last_commit.signatures_len >= 3,
          "FIXTURE GUARD: at least three validators to mix flags over");
    /* slot 0 stays COMMIT; slot 1 -> NIL; slot 2 -> ABSENT. */
    x.last_sigs[1].block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_NIL;
    x.last_sigs[2].block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT;
    uint8_t commit_addr[32], nil_addr[32], absent_addr[32];
    memcpy(commit_addr, x.last_sigs[0].validator_address, 32);
    memcpy(nil_addr,    x.last_sigs[1].validator_address, 32);
    memcpy(absent_addr, x.last_sigs[2].validator_address, 32);

    CHECK(exec_make_block(&x, 2, 0) == 0, "block 2 with ZERO transactions");
    CHECK(exec_block_id(&x, x.blk, &bid2) == 0 &&
          block_id_is_complete(&bid2), "block 2's COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid2, x.blk, x.state)
              == CMT_OK, "block 2 applies with the mixed-flag commit");

    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(g.w->db,
                "SELECT signed_count, last_signed_height FROM v2_attendance "
                "WHERE voter_id = ?1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, commit_addr, 32, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW, "COMMIT slot has a row");
        CHECK(sqlite3_column_int64(st, 0) == 1 &&
              sqlite3_column_int64(st, 1) == 1,
              "COMMIT credits signed_count=1, last_signed_height=1 "
              "(block 2 carries the commit FOR height 1)");
        sqlite3_finalize(st);
    }
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(g.w->db,
                "SELECT 1 FROM v2_attendance WHERE voter_id = ?1", -1,
                &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, nil_addr, 32, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE,
              "Q1: NIL does not credit — no row at all");
        sqlite3_finalize(st);
    }
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(g.w->db,
                "SELECT 1 FROM v2_attendance WHERE voter_id = ?1", -1,
                &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, absent_addr, 32, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE,
              "Q1: ABSENT does not credit — no row at all");
        sqlite3_finalize(st);
    }
    /* round 2 (R2-4): the LITERAL 1 this assertion used to compare
     * against was wrong — the fixture seats DNAC_COMMITTEE_SIZE
     * validators (exec_make_last_commit builds one COMMIT vote per
     * member of the height-1 validator set) and this case only
     * overwrites TWO of them (slot 1 -> NIL, slot 2 -> ABSENT), so
     * every OTHER slot (0 and 3..6) is still COMMIT and credits its own
     * row. The three assertions immediately above already PROVE the Q1
     * property (COMMIT credits; NIL has no row; ABSENT has no row) —
     * this final count is a sanity check on the WHOLE table, derived
     * from the real signature list rather than a hardcoded literal, so
     * it stays correct at any committee size. The discriminating part
     * of this case is the two ABSENT rows (no row for nil_addr,
     * absent_addr), not this count. */
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_attendance") ==
          (int64_t)(x.last_commit.signatures_len - 2),
          "every slot except the two flipped to NIL/ABSENT credited "
          "exactly one row");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * ORCHESTRATOR delta 1+2+4, item B — the byte-bound capacity seam's
 * actual job: PrepareProposal bounds by BYTES (`req->max_tx_bytes`),
 * never by count, and a batch that does not fit is trimmed from the
 * TAIL, not refused outright (prepare_proposal's own "drop from the
 * TAIL" byte loop).
 *
 * DELTA 4 REDESIGN — root cause of the delta-2/3 version's failure
 * ("all eleven are kept" failed BEFORE the apply step even ran): its
 * twelve envelopes used `leg.runtime_op = i + 1` (1..12) for
 * distinctness, but the committed SYSTEM meter policy
 * (nodus_witness_runtime.c's `sys_policy_build`) prices ONLY runtime_op
 * 1..7 (CORE's own owned rule range, O11: "the rule list GREW to
 * {1..7}") — ops 8..12 carry NO authoritative weight and fail
 * `DNA_METER_ERR_OP_WEIGHT` (status 3) at `dna_meter_plan_build`. Worse,
 * every envelope's declared reservation CEILING (200 000,
 * `res_max_total_units`) is reserved WHOLE from the GLOBAL unit budget
 * (`NODUS_V2_GLOBAL_UNIT_BUDGET`, 1 000 000 at the time; 2 097 152 since
 * block capacity trial B, operator 2026-09-24, where the same shape
 * would exhaust it at the ELEVENTH — floor(2 097 152 / 200 000) = 10) at
 * RESERVE time — five such envelopes exhausted it EXACTLY (5 x 200 000
 * = 1 000 000), so the SIXTH
 * (batch index 5) failed `DNA_METER_ERR_GLOBAL_BUDGET` (status 7) before
 * ever reaching PrepareProposal's own byte-budget logic; the retry loop
 * dropped it and re-hit GLOBAL_BUDGET once more at the new index 5 (2x
 * status 7 in the log), then OP_WEIGHT for ops 8/9/10/11 in turn (4x
 * status 3) — kept 5, not 11. The test's PREMISE was wrong, not the
 * application.
 *
 * FIXED (delta 4): `runtime_op` is FIXED at 1 for every envelope (owned,
 * priced, weight 1). `TEST_APP_ENV_CEILING` (10 000) is verified IN THIS
 * TEST, not guessed: it runs the SAME `dna_meter_plan_build` the engine
 * itself runs, and checks the built plan's `static_total` fits
 * comfortably under it, and that reserving EVERY envelope's full ceiling
 * TWICE OVER still leaves the global unit budget mostly unspent.
 * `TEST_APP_SMALL_N` (11) is UNCHANGED — only the envelopes' pricing
 * shape needed to change.
 *
 * DELTA 5 CORRECTION — delta 4's own distinctness mechanism (a mediated
 * READ over a distinct 64-byte key, none of which existed) reached the
 * apply step but the decided block's `tx_count` was not 11: admission
 * (PrepareProposal / ProcessProposal, neither of which EXECUTES
 * anything) accepted every envelope, but FinalizeBlock actually RUNS
 * them, and delta 4's script carried a COMPLETELY EMPTY effect-result
 * tail (`v2x_script_build(..., NULL, 0, NULL, 0)`, 0 bytes) for every
 * envelope. `dna_effect_result_decode` REJECTS a 0-byte result as
 * truncated (effect_wire.c: `src_len < DNA_EFFECT_FIXED_HEAD` fails
 * before the count is ever read — "0 is a valid empty result" means the
 * COUNT field may be 0, inside a full `DNA_EFFECT_FIXED_HEAD`-byte
 * header, never that 0 TOTAL BYTES is valid) — every envelope's leg was
 * therefore refused at EXECUTION with a nonzero `nodus_v2_tx_code_t`,
 * on BOTH delta 4's design and the pre-delta-4 one (neither ever built
 * a real result encoding; the earlier version never reached the apply
 * step to expose it). ADMISSION DOES NOT EXECUTE — an item can pass
 * PrepareProposal/ProcessProposal cleanly and still be refused at
 * FinalizeBlock — which is why this case now asserts every applied
 * item's own code, not only the block's `tx_count`.
 *
 * FIXED (delta 5): every envelope's script now carries a REAL, VALID,
 * DECODABLE empty-effect-result (`v2x_effres(dst, cap, NULL, 0,
 * &len)` — `effect_wire.c`'s own documented "n == 0 with a NULL array is
 * ACCEPTED" rule — a `DNA_EFFECT_FIXED_HEAD`-byte header encoding ZERO
 * effects), byte-IDENTICAL across every envelope; distinctness instead
 * comes from `leg.max_effect_bytes` (`res_max_effect_bytes`, a per-leg
 * WIRE HEADER field, encoded distinctly per envelope), which the
 * scripted runtime never reads or acts on — it is consulted only as a
 * DECLARED CEILING at reservation (`dna_meter_plan_build`) and at the
 * effect-charge gate (`dna_meter_charge_effects`), both of which compare
 * the ACTUAL effect byte count (0, always) against it, so varying it
 * changes nothing about execution. Zero effects means the adapter is
 * never called at all — no precondition, no mutation, nothing that could
 * itself be refused.
 *
 * Proves, in order: (1) N envelopes fit a byte budget sized exactly for
 * them — ALL kept; (2) the SAME budget, one further individually-
 * ADMISSIBLE envelope appended — trimmed from the tail; (3) the SAME
 * N+1, with the byte budget LIFTED to fit all of them — ALL N+1 kept,
 * which is the direct proof that (2)'s trim was BYTES ALONE: nothing
 * else changes between (2) and (3) except the byte ceiling, and the
 * outcome flips completely; (4) ProcessProposal on the full N+1 batch
 * ACCEPTS outright — confirmed directly by calling the SAME seam
 * (`nodus_witness_v2_produce_batch_check_capped`) and reading
 * `result.kind == NODUS_V2_BATCH_FAIL_NONE`, the direct "not METER, not
 * BYTES either" evidence for a batch this size; (5) the FIRST N, from
 * PrepareProposal's own kept response, actually APPLY: every applied
 * item's `x.ledger->fb_pb[i].det.code` is individually asserted
 * `NODUS_V2_TX_OK` — naming the refused item's index and code on
 * failure rather than a bare count mismatch — and only then is
 * `tx_count == N` checked, since a matching count with a wrong code
 * inside it would prove nothing.
 *
 * DEVIATION from the dispatch's literal wording — reported, not
 * silently substituted: "assert the seam's refusal KIND for the (N+1)th
 * is the BLOCK_BYTES kind" cannot be built at this envelope count/size.
 * `NODUS_V2_BATCH_FAIL_CAPACITY_BYTES` is real (nodus_witness_v2_env.h)
 * but is checked against the policy's ABSOLUTE `max_block_env_bytes`
 * (2 x `DNA_ENV_MAX_TOTAL_LEN` = 2 MiB, `sys_policy_build`) — a batch of
 * a dozen envelopes at a few hundred bytes each cannot approach it;
 * doing so honestly would need many thousands of envelopes, an
 * unrelated scale from this per-request case (`ProcessProposal` has no
 * `max_tx_bytes` input of its own — state/execution.go:162-188 — so
 * ITS byte ceiling is this fixed policy constant, never the test's
 * chosen `max_tx_bytes`). Steps (2)/(3) above prove the BYTES-ALONE
 * claim the dispatch actually wants, over the mechanism that is really
 * reachable — PrepareProposal's own `req->max_tx_bytes` — rather than
 * over the seam's unreachable-at-this-scale absolute ceiling.
 */
static int t_byte_bound_prepare_and_process(void)
{
    gfx_t                                  g;
    exec_t                                 x;
    nodus_abci_request_prepare_proposal_t  preq;
    nodus_abci_response_prepare_proposal_t presp;
    nodus_abci_request_process_proposal_t  procreq;
    nodus_abci_response_process_proposal_t procresp;
    cmt_pb_bytes_t                         small_txs[TEST_APP_SMALL_N];
    v2x_env_t                             *envs[TEST_APP_SMALL_N + 1];
    uint8_t                                effres[DNA_EFFECT_FIXED_HEAD];
    size_t                                 effres_len = 0;
    uint8_t                                script[512];  /* one CREATE */
    uint32_t                               slen;
    v2x_leg_t                              leg;
    int64_t                                budget_for_eleven;
    int64_t                                budget_for_twelve;
    size_t                                 i;
    int                                    ok = 1;

    CHECK(gfx_open(&g, "bytebound") == 0, "version-3 fixture");
    CHECK(v2x_table_init(g.w) == 0, "the scripted runtime table");
    CHECK(exec_init(&x, &g) == 0, "app+host+state fixture (builds and "
          "binds the completed genesis document internally)");

    /* Twelve REAL, individually-admissible AND individually-EXECUTABLE
     * envelopes, all sharing the SAME priced `runtime_op` (1) and the
     * SAME real, valid, DECODABLE empty-effect-result script (delta 5:
     * a 0-byte tail is truncated, not empty — effect_wire.c rejects it
     * before the count is even read). Distinctness comes from
     * `leg.max_effect_bytes` alone — a per-leg WIRE HEADER field the
     * scripted runtime never reads, consulted only as a declared
     * ceiling the actual (zero) effect bytes trivially stay under — so
     * every envelope's WIRE BYTES differ (hence distinct commitments)
     * while every envelope EXECUTES identically: zero effects, no
     * adapter call, nothing to refuse. This case is about the
     * BYTE-BUDGET path specifically, so every candidate must be
     * genuinely admissible AND executable — a garbage byte string, or
     * one that decodes to nothing at execution, would be refused
     * before the byte-budget logic (or the apply step) is ever
     * meaningfully exercised. */
    /* tokenomics-v3 P2 (ORCHESTRATOR, 2026-09-24): every envelope now
     * CREATEs ONE zero-amount utxo_set row (fixture op V2X_OP_UTXO, a
     * distinct key per envelope). Before P2 these envelopes executed to
     * ZERO effects and the block still applied only because the per-block
     * MINT moved the CORE root every height; with the mint deleted, a
     * CORE-declared block whose CORE root does not move is correctly a
     * "declared no-op" (the engine's phase-9 rule). A zero amount keeps
     * the supply equation untouched while the new row moves the root —
     * which is what every real CORE op does. `effres` (the old zero-effect
     * result) is kept only for the header-size sanity check below. */
    CHECK(v2x_effres(effres, sizeof(effres), NULL, 0, &effres_len) == 0 &&
          effres_len == DNA_EFFECT_FIXED_HEAD,
          "a real, valid, header-only ZERO-effect result encodes — "
          "\"n == 0 with a NULL array is ACCEPTED\" (effect_wire.c)");
    memset(&leg, 0, sizeof(leg));
    leg.domain_id   = DNA_DOMAIN_CORE;
    leg.runtime_op  = 1;                   /* owned + priced, weight 1  */
    leg.max_effects = 4;                   /* ceiling; actual count 1   */
    for (i = 0; i < TEST_APP_SMALL_N + 1; i++) {
        uint8_t ukey[64] = { 0 };
        uint8_t uval[8]  = { 0 };          /* amount 0: supply unchanged */
        uint8_t ures[512];
        size_t  ulen = 0;
        ukey[0]  = 0xB7;
        ukey[63] = (uint8_t)(0x40 + i);    /* distinct row per envelope  */
        envs[i] = calloc(1, sizeof(*envs[i]));
        if (!envs[i]) { ok = 0; break; }
        if (v2x_eff1(ures, sizeof(ures), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                     DNA_EFFECT_PRE_ABSENT, ukey, 64, uval, 8,
                     &ulen) != 0) { ok = 0; break; }
        slen = v2x_script_build(script, sizeof(script), NULL, 0, ures,
                                ulen);
        if (slen == 0) { ok = 0; break; }
        leg.call        = script;
        leg.call_len    = slen;
        leg.max_effect_bytes = (uint32_t)(2048 + i);  /* varies too     */
        if (v2x_env_build_ex(envs[i], TEST_APP_ENV_CEILING, 0, 1, &leg, 1)
                != 0) {
            ok = 0;
            break;
        }
    }
    CHECK(ok, "twelve distinct, individually-executable envelopes");

    /* ── the ceiling is VERIFIED against the real policy, not assumed ──
     * the exact plan the engine itself would build for the LARGEST leg
     * (the twelfth envelope, index N: the largest `max_effect_bytes`,
     * hence the largest `static_units`). */
    {
        const nodus_domain_runtime_t *bt;
        size_t                        nbt = 0;
        dna_env_view_t                view;
        dna_meter_plan_t              plan;

        bt = nodus_runtime_builtin_table(&nbt);
        CHECK(bt != NULL && nbt == 2 && bt[0].meter_policy != NULL,
              "the committed SYSTEM meter policy is available");
        memset(&view, 0, sizeof(view));
        CHECK(dna_env_decode(envs[TEST_APP_SMALL_N]->bytes,
                             envs[TEST_APP_SMALL_N]->len, &view) == 0,
              "the largest (twelfth) envelope decodes");
        memset(&plan, 0, sizeof(plan));
        CHECK(dna_meter_plan_build(bt[0].meter_policy, &view, &plan)
                  == DNA_METER_OK, "the plan the engine itself would build");
        CHECK(plan.static_total <= TEST_APP_ENV_CEILING,
              "the chosen ceiling covers this envelope's actual static "
              "cost, verified from the real policy rather than assumed");
        CHECK((uint64_t)(TEST_APP_SMALL_N + 1) * TEST_APP_ENV_CEILING * 2 <=
                  NODUS_V2_GLOBAL_UNIT_BUDGET,
              "even reserving EVERY envelope's full declared ceiling at "
              "once, twice over, stays under the global unit budget — "
              "this batch can never be meter-limited at this scale");
    }

    budget_for_eleven = 0;
    for (i = 0; i < TEST_APP_SMALL_N; i++) {
        small_txs[i].data = envs[i]->bytes;
        small_txs[i].len  = envs[i]->len;
        budget_for_eleven +=
            nodus_cmt_compute_proto_size_for_tx(small_txs[i].len);
    }
    budget_for_twelve = budget_for_eleven +
        nodus_cmt_compute_proto_size_for_tx(envs[TEST_APP_SMALL_N]->len);

    /* ── (1) PrepareProposal: a budget that fits exactly the eleven ──── */
    memset(&preq, 0, sizeof(preq));
    preq.txs         = small_txs;
    preq.txs_len     = TEST_APP_SMALL_N;
    preq.max_tx_bytes = budget_for_eleven;
    memset(&presp, 0, sizeof(presp));
    CHECK(nodus_cmt_app_prepare_proposal(x.ledger, &preq, &presp) == CMT_OK,
          "prepare_proposal accepts a byte-exact batch");
    CHECK(presp.txs_len == TEST_APP_SMALL_N,
          "all eleven are kept — the budget fits them exactly, and every "
          "envelope reserves/prices identically (fixed, priced "
          "runtime_op, a verified ceiling), so this proves the BYTE "
          "path cleanly, not the count path (t_finalize_block_bound) or "
          "an accidental meter rejection (delta 4's own root cause)");

    /* ── (2)/(3) the same eleven plus one admissible twelfth: trimmed at
     * the eleven-budget, kept whole once the budget is LIFTED to fit it —
     * the direct proof that (2)'s trim is BYTES ALONE. ────────────────── */
    {
        cmt_pb_bytes_t twelve[TEST_APP_SMALL_N + 1];
        memcpy(twelve, small_txs, sizeof(small_txs));
        twelve[TEST_APP_SMALL_N].data = envs[TEST_APP_SMALL_N]->bytes;
        twelve[TEST_APP_SMALL_N].len  = envs[TEST_APP_SMALL_N]->len;

        memset(&preq, 0, sizeof(preq));
        preq.txs          = twelve;
        preq.txs_len      = TEST_APP_SMALL_N + 1;
        preq.max_tx_bytes = budget_for_eleven;  /* no room for the 12th */
        memset(&presp, 0, sizeof(presp));
        CHECK(nodus_cmt_app_prepare_proposal(x.ledger, &preq, &presp)
                  == CMT_OK, "prepare_proposal still returns cleanly");
        CHECK(presp.txs_len == TEST_APP_SMALL_N,
              "the twelfth candidate was trimmed from the tail, not the "
              "eleven that fit");

        memset(&preq, 0, sizeof(preq));
        preq.txs          = twelve;
        preq.txs_len      = TEST_APP_SMALL_N + 1;
        preq.max_tx_bytes = budget_for_twelve;  /* room for all twelve  */
        memset(&presp, 0, sizeof(presp));
        CHECK(nodus_cmt_app_prepare_proposal(x.ledger, &preq, &presp)
                  == CMT_OK, "prepare_proposal returns cleanly with the "
              "budget lifted");
        CHECK(presp.txs_len == TEST_APP_SMALL_N + 1,
              "ALL TWELVE are now kept — the ONLY thing that changed "
              "since the trim above is the byte budget, so the trim "
              "was BYTES ALONE, not a meter or admission rejection");

        /* ── (4) ProcessProposal: a PEER proposes the FULL twelve. Every
         * envelope prices/reserves identically and the batch is nowhere
         * near the seam's own absolute max_block_env_bytes ceiling
         * (2 MiB; ProcessProposal has no max_tx_bytes input of its own —
         * state/execution.go:162-188), so the whole batch ACCEPTS. */
        memset(&procreq, 0, sizeof(procreq));
        procreq.txs     = twelve;
        procreq.txs_len = TEST_APP_SMALL_N + 1;
        memset(&procresp, 0, sizeof(procresp));
        CHECK(nodus_cmt_app_process_proposal(x.ledger, &procreq, &procresp)
                  == CMT_OK, "process_proposal returns cleanly");
        CHECK(procresp.status == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
              "process_proposal ACCEPTS the full twelve outright — a "
              "batch this small cannot reach the seam's own absolute "
              "byte ceiling, and every envelope prices identically, so "
              "nothing in it can be refused");

        /* direct seam evidence: the SAME call ACCEPT was derived from,
         * with the classified kind read straight off the result — "not
         * METER" stated as the struct the seam itself fills, not
         * inferred from the ABCI verdict alone. */
        {
            nodus_witness_batch_item_t   view[TEST_APP_SMALL_N + 1];
            nodus_v2_batch_check_result_t result;
            int                            fail_index = 0;

            for (i = 0; i < TEST_APP_SMALL_N + 1; i++) {
                view[i].tx_type = nodus_witness_v2_classify_entry(
                    twelve[i].data, (uint32_t)twelve[i].len);
                view[i].tx_data = twelve[i].data;
                view[i].tx_len  = twelve[i].len;
            }
            memset(&result, 0, sizeof(result));
            CHECK(nodus_witness_v2_produce_batch_check_capped(
                      g.w, view, (int)(TEST_APP_SMALL_N + 1),
                      (int)(TEST_APP_SMALL_N + 1), &fail_index, &result)
                      == 0, "the seam itself accepts the full twelve");
            CHECK(result.kind == NODUS_V2_BATCH_FAIL_NONE,
                  "and its classified kind is NONE — direct evidence "
                  "this is not a meter rejection of any kind");
        }
    }

    /* ── ORCHESTRATOR delta 2, item B — the decided block actually
     * APPLIES, proving the doc comment's own claim rather than stopping
     * at PrepareProposal's response. Drives PrepareProposal's OWN eleven
     * kept transactions through the REAL host pipeline
     * (exec_make_block + exec_block_id +
     * nodus_cmt_host_apply_verified_block), the same shape t_finalize_
     * block uses above. Run LAST, after both PrepareProposal/
     * ProcessProposal calls above: the seam they call reads committed
     * state and writes nothing (nodus_witness_cmt_app.h's own DETERMINISM
     * guarantee), so applying these eleven here cannot perturb the
     * byte-budget assertions already checked against the SAME envelopes.
     * `presp` at this point is (2)/(3)'s LAST response (the lifted-
     * budget, twelve-kept one) — re-run PrepareProposal ONE more time at
     * the eleven-only budget so `presp` holds exactly the eleven this
     * step means to apply.
     *
     * `x.ledger` is the ONE context `exec_init` built for this whole
     * function — nothing in this test (or in prepare_proposal /
     * process_proposal) ever writes `test_fail_at` /
     * `test_fail_env_index` / `test_fail_effect_index`, so the block
     * `finalize_block` constructs carries V2AP_FAIL_NONE (the calloc +
     * memset inside nodus_cmt_app_ledger_init) and injects nothing. */
    memset(&preq, 0, sizeof(preq));
    preq.txs         = small_txs;
    preq.txs_len     = TEST_APP_SMALL_N;
    preq.max_tx_bytes = budget_for_eleven;
    memset(&presp, 0, sizeof(presp));
    CHECK(nodus_cmt_app_prepare_proposal(x.ledger, &preq, &presp) == CMT_OK,
          "prepare_proposal re-run for the apply step, eleven only");
    CHECK(presp.txs_len == TEST_APP_SMALL_N, "still all eleven");
    for (i = 0; i < presp.txs_len; i++) {
        x.txs[i] = presp.txs[i];
    }
    CHECK(exec_make_block(&x, 1, presp.txs_len) == 0,
          "block 1 built from PrepareProposal's own eleven-tx response");
    {
        cmt_block_id_t bid11;

        CHECK(exec_block_id(&x, x.blk, &bid11) == 0 &&
              block_id_is_complete(&bid11), "a COMPLETE BlockID");
        CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid11, x.blk,
                                                  x.state) == CMT_OK,
              "the decided block APPLIES — no sticky fault injection "
              "survives from any earlier case into this fresh context");
    }
    /* ORCHESTRATOR delta 5 — ADMISSION DOES NOT EXECUTE: PrepareProposal
     * and ProcessProposal both accepted every one of these eleven, but
     * neither one RUNS them — only FinalizeBlock does, and a decided
     * block is never refused as a WHOLE, so an item the engine refuses
     * per item is simply left OUT of `tx_count` with a nonzero
     * `nodus_v2_tx_code_t` in its own result. Naming the offending
     * item's index and code here is what turned delta 4's bare "tx_count
     * is not 11" into the actual, fixable diagnosis (a truncated,
     * undecodable empty effect-result, effect_wire.c) — asserted
     * PER ITEM so any regression here names its offender the same way,
     * rather than a bare count mismatch a reader has to re-derive. */
    for (i = 0; i < presp.txs_len; i++) {
        char msg[96];

        snprintf(msg, sizeof(msg),
                 "item %zu applied with code %u, expected "
                 "NODUS_V2_TX_OK (0)",
                 i, (unsigned)x.ledger->fb_pb[i].det.code);
        CHECK(x.ledger->fb_pb[i].det.code == (uint32_t)NODUS_V2_TX_OK, msg);
    }
    CHECK(q1(g.w->db, "SELECT tx_count FROM v2_blocks "
             "WHERE global_height = 1") == (int)TEST_APP_SMALL_N,
          "and the Comet row records all eleven kept transactions — a "
          "matching count with a wrong code inside it would have proven "
          "nothing, which is why every item's code was checked above "
          "first");

    for (i = 0; i < TEST_APP_SMALL_N + 1; i++) {
        free(envs[i]);
    }
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * ORCHESTRATOR delta 4, item E — ProcessProposal's count-malformed guard
 * is `env_bound`, NOT `prep_bound`. delta 1 narrowed this to `prep_bound`
 * because the arrays it guarded (prep_class/prep_order/seam_entry/
 * seam_ptr) were shared, ctx-owned, fixed-size, sized to `prep_bound` for
 * memory reasons; delta 2 made every array here per-request and local
 * (nodus_witness_cmt_app.h's own struct comment), so there is no fixed
 * array left for a `prep_bound` narrowing to protect — the guard IS
 * `req->txs_len > ctx->env_bound` (nodus_cmt_app_process_proposal, the
 * byte-derived physical ceiling), and a count strictly BETWEEN
 * `prep_bound` and `env_bound` (5 001..293 525) is NOT malformed on
 * ProcessProposal any more: it is merely a proposal PrepareProposal
 * itself could never have produced (that is `prep_bound`'s OWN guard,
 * inside `nodus_cmt_app_prepare_proposal`), which is a different check
 * at a different row. This case's `req.txs_len` must exceed `env_bound`
 * itself to reach the ACTUAL guard — `prep_bound + 1` passes it silently
 * and falls through into the per-item loop, reading `req->txs[i]` for
 * `i` up to that count: over a single-element `dummy_tx`, an
 * ASan-caught stack-buffer-overflow (delta 4 ADDENDUM item E), not the
 * "never dereferenced" the previous version of this comment claimed.
 */
static int t_process_proposal_malformed_count(void)
{
    gfx_t                                  g;
    exec_t                                 x;
    nodus_abci_request_process_proposal_t  req;
    nodus_abci_response_process_proposal_t resp;
    cmt_pb_bytes_t                         dummy_tx;

    CHECK(gfx_open(&g, "malformed") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "app+host+state fixture (builds and "
          "binds the completed genesis document internally)");
    CHECK(x.ledger->env_bound > 0, "the byte-bound seam derived a "
          "positive env_bound");

    dummy_tx.data = POISON;
    dummy_tx.len  = sizeof(POISON);
    memset(&req, 0, sizeof(req));
    /* txs_len alone carries this case: the guard
     * (req->txs_len > ctx->env_bound) is the FIRST thing
     * process_proposal reads, and it REJECTS before req->txs is ever
     * dereferenced — so a single-element dummy_tx is safe ONLY because
     * env_bound, not prep_bound, is what is exceeded here. */
    req.txs     = &dummy_tx;
    req.txs_len = x.ledger->env_bound + 1;
    memset(&resp, 0, sizeof(resp));
    resp.status = (nodus_abci_proposal_status_t)(-1);   /* poison */
    CHECK(nodus_cmt_app_process_proposal(x.ledger, &req, &resp) == CMT_OK,
          "process_proposal returns a verdict, not a fault, for a "
          "malformed-count proposal");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "and the verdict is REJECT");

    exec_free(&x);
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
    nodus_cmt_app_ledger_release(app);
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

    nodus_cmt_app_ledger_release(app);
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

    /* ORCHESTRATOR delta 1, item B — the bound is now app->prep_bound
     * (the mempool's own configured size), not the retired
     * NODUS_CMT_APP_MAX_TXS. `req.txs` stays the 2-element local array:
     * the guard reads only `req.txs_len` before ever touching
     * `req.txs[i]`. */
    req.txs_len = app->prep_bound + 1;
    req.max_tx_bytes = 22020096;
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_FAULT,
          "a request above the bound faults");

    nodus_cmt_app_ledger_release(app);

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

    /* ORCHESTRATOR delta 4, item E — ProcessProposal's guard is
     * `env_bound`, NOT `prep_bound` (delta 2 dropped the `prep_bound`
     * narrowing here — see t_process_proposal_malformed_count's own note
     * for why). `app->prep_bound + 1` (5 001) is SMALLER than
     * `env_bound` (in the hundreds of thousands), so it silently PASSES
     * the real guard and falls into the per-item loop, reading
     * `req.txs[i]` for `i` up to 5 000 over this case's 2-element `txs`
     * array — an ASan-caught stack-buffer-overflow the -O2 ctest missed
     * by stack luck. `env_bound + 1` is what actually exceeds the guard
     * that exists, so the REJECT is decided before `req.txs` is ever
     * read. */
    req.txs_len = app->env_bound + 1;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_process_proposal(app, &req, &resp) == CMT_OK,
          "an over-bound proposal does NOT stop the node");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "it is rejected instead");

    nodus_cmt_app_ledger_release(app);
    free(env.bytes);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * R3 W4 package C — THE LIVE DEFECT'S ACTUAL FIX, proven end to end:
 * PrepareProposal packs ALL 40 admissible claims (no longer trimmed to
 * the old flat 16), ProcessProposal accepts the resulting proposal, and
 * FinalizeBlock APPLIES the decided 40-claim block for real.
 *
 * `/tmp/stagef-20260917T034259Z` (`test_v2_epoch_boundary.sh`, E=15): 40
 * claims pumped at once, the proposer packed all 40 into block 7 (no
 * item-count cap existed anywhere upstream), the block was DECIDED, and
 * every node's FinalizeBlock FAULTED — `nodus_witness_v2_apply.c`'s
 * `claim_nuls[MAX_OPS][64]` (a 16-slot STACK array) could not hold 40 —
 * stopping consensus participation on all seven. R3-W3-C2a-19 (delta 11)
 * then trimmed the proposal to 16 to make the array bound unreachable;
 * THIS package instead moved the array to the heap, sized to the BLOCK's
 * own claim count, and re-derived the item bounds so 40 (and up to
 * NODUS_V2_APPLY_MAX_CLAIMS, 14 162) fit for real — the harness's own
 * scenario becomes reachable in full again, cited at every anchor below.
 *
 * 40 GENUINELY, INDEPENDENTLY ADMISSIBLE claims (not 40 copies of one):
 * the engine's own seam (`nodus_witness_v2_produce_batch_check_capped`,
 * called from `app_seam_check` below `nodus_cmt_app_prepare_proposal`'s
 * caps) runs each surviving candidate through
 * `nodus_witness_v2_claim_admit` and rejects an in-batch duplicate
 * nullifier — so if fewer than 40 were independently admissible, the
 * seam's own drop-and-retry loop would trim toward the admissible core
 * regardless of any item-count cap, and RED-today would silently equal
 * GREEN-after instead of proving the fix. All 40 here are real, distinct
 * leaves of a 40-leaf genesis distribution (`gfx_open_n`), each
 * independently claimable by `g_ks[0]`.
 *
 * RED-BEFORE-THIS-PACKAGE, STATED HONESTLY, THREE WAYS:
 *   1. `resp.txs_len == N` (40): RED at R3-W3-C2a-19 (it read 16 — the
 *      flat mixed cap trimmed every claims-only proposal to it).
 *   2. `nodus_cmt_app_process_proposal(...) == ACCEPT` on the 40-item
 *      proposal: RED before this package for the SAME reason bullet 1 is
 *      — a 40-item proposal never existed for it to accept.
 *   3. `nodus_cmt_host_apply_verified_block(...) == CMT_OK`, every item
 *      coded OK, `v2_blocks.tx_count == 40`: RED on e72d8cb5 — FAULT at
 *      `claim_nuls[i]` past the old 16-slot array (exactly the harness's
 *      own height-7 stall), never reached with the 16-item trim in place
 *      either (there was nothing left to apply beyond item 16).
 */
static int t_prepare_proposal_item_cap(void)
{
    gfx_t                                    g;
    exec_t                                   x;
    nodus_abci_request_prepare_proposal_t    preq;
    nodus_abci_response_prepare_proposal_t   presp;
    nodus_abci_request_process_proposal_t    procreq;
    nodus_abci_response_process_proposal_t   procresp;
    cmt_block_id_t                           bid;
    cmt_pb_bytes_t                           *txs = NULL;
    uint8_t                                (*claim_bytes)[DNA_CLAIM_MAX_WIRE] = NULL;
    size_t                                   *claim_len = NULL;
    const uint32_t                            N = 40;
    uint32_t                                  i;

    CHECK(gfx_open_n(&g, "prep_cap", N) == 0,
          "40-leaf version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "app+host+state fixture (builds and "
          "binds the completed genesis document internally)");
    /* Heap: 40 x DNA_CLAIM_MAX_WIRE (each claim carries up to
     * DNA_DIST_PROOF_MAX == 64 siblings, ~4 KB alone) is far too large
     * for a stack frame — feedback_heap_alloc_test_fixture. */
    txs         = (cmt_pb_bytes_t *)calloc(N, sizeof(*txs));
    claim_bytes = calloc(N, sizeof(*claim_bytes));
    claim_len   = (size_t *)calloc(N, sizeof(*claim_len));
    CHECK(txs && claim_bytes && claim_len, "alloc");

    for (i = 0; i < N; i++) {
        CHECK(build_claim_n(&g, N, i, claim_bytes[i], DNA_CLAIM_MAX_WIRE,
                            &claim_len[i]) == 0,
              "a real claim over its own genesis leaf");
        txs[i].data = claim_bytes[i];
        txs[i].len  = claim_len[i];
    }

    /* ── (1) PrepareProposal packs ALL 40 ─────────────────────────────*/
    memset(&preq, 0, sizeof(preq));
    preq.txs          = txs;
    preq.txs_len      = N;
    preq.max_tx_bytes = 22020096;
    memset(&presp, 0, sizeof(presp));
    CHECK(nodus_cmt_app_prepare_proposal(x.ledger, &preq, &presp) == CMT_OK,
          "prepare answers");
    CHECK(presp.txs_len == N,
          "R3 W4 package C: the per-class claim cap (min(claim_bound, "
          "NODUS_V2_APPLY_MAX_CLAIMS) = 14 162 at this fixture's genesis "
          "document) keeps all 40 admissible claims — RED at "
          "R3-W3-C2a-19's flat mixed cap, which read 16");
    for (i = 0; i < N; i++) {
        CHECK(presp.txs[i].data == txs[i].data &&
              presp.txs[i].len == txs[i].len,
              "the KEPT 40 are the FIRST 40 in request order — fee-"
              "descending is a stable sort and every claim's key is 0, so "
              "arrival order survives, and the byte budget never trims "
              "40 tiny claims");
    }

    /* ── (2) ProcessProposal ACCEPTS the 40-item proposal ─────────────*/
    memset(&procreq, 0, sizeof(procreq));
    procreq.txs     = presp.txs;
    procreq.txs_len = presp.txs_len;
    memset(&procresp, 0, sizeof(procresp));
    CHECK(nodus_cmt_app_process_proposal(x.ledger, &procreq, &procresp)
              == CMT_OK, "process_proposal returns a verdict, not a fault");
    CHECK(procresp.status == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "40 claims are within both the per-class claim cap and the "
          "mixed item cap — accepted, never refused for mere COUNT");

    /* ── (3) FinalizeBlock APPLIES the decided 40-claim block ─────────*/
    for (i = 0; i < presp.txs_len; i++) {
        x.txs[i] = presp.txs[i];
    }
    CHECK(exec_make_block(&x, 1, presp.txs_len) == 0,
          "block 1 built from PrepareProposal's own 40-claim response");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK,
          "the decided 40-claim block APPLIES — RED on e72d8cb5: the "
          "engine's claim_nuls[MAX_OPS][64] STACK array (MAX_OPS was 16) "
          "could not hold a 40th claim, exactly the harness's height-7 "
          "stall (/tmp/stagef-20260917T034259Z); claim_nuls is heap now, "
          "sized to the block's own n_claims (nodus_witness_v2_apply.c)");
    for (i = 0; i < presp.txs_len; i++) {
        char msg[96];

        snprintf(msg, sizeof(msg),
                 "claim %u applied with code %u, expected NODUS_V2_TX_OK "
                 "(0)", i, (unsigned)x.ledger->fb_pb[i].det.code);
        CHECK(x.ledger->fb_pb[i].det.code == (uint32_t)NODUS_V2_TX_OK, msg);
    }
    /* NOT `v2_blocks.tx_count`: that column counts `tx_root`'s members,
     * and claims are bound into a block's identity TRANSITIVELY ONLY
     * (through `claims_root`, a leg of the target domain's state root) —
     * they are not transactions and never enter `tx_root` (apply.h,
     * "HOW THE THREE CONTENT CHANNELS REACH THE BLOCK IDENTITY"). The
     * ledger-level proof that all 40 applied is the spent-claim table
     * itself, exactly as `t_claim_items` above checks it. */
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_claims_spent") == (int)N,
          "all 40 claims were spent — the ledger's own record of what "
          "applied, independent of tx_root/tx_count");

    free(claim_len);
    free(claim_bytes);
    free(txs);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * R3 W4-C delta 2 (operator "kaldır" 2026-09-18) — ProcessProposal's
 * ENVELOPE class-cap REFUSAL, re-anchored to the new DERIVED ceiling.
 *
 * `NODUS_V2_ENV_BATCH_MAX` is no longer 10 (delta 1's chain-config-
 * derived value) — it is now a per-block MEMORY ceiling in the low
 * thousands (nodus_witness_v2_apply.h, delta 2), because the operator
 * retired the governance parameter it used to derive from. Building
 * `NODUS_V2_ENV_BATCH_MAX + 1` GENUINELY ADMISSIBLE, EXECUTABLE
 * envelopes (delta 1's approach, practical at 11) is NOT practical at
 * this scale — so this case proves the REFUSAL genuinely, at the REAL
 * bound, a different way: `nodus_witness_v2_classify_entry`
 * (nodus_witness_v2_produce.c:75-80) classifies an entry as an
 * ENVELOPE from a 16-byte WIRE-FAMILY-MARKER PREFIX ALONE ("DNA.
 * ENVWIRE.v1\0\0") — no seam, no decode, no admission, no signature —
 * and ProcessProposal's per-class COUNT check runs on exactly that
 * classification, BEFORE the per-item seam is ever reached (this
 * function's own early-return shape, matching the pre-existing mixed-
 * cap check's "checked FIRST and alone: nothing read from req->txs
 * beyond the classify pass" contract). A buffer that is JUST the
 * marker therefore classifies identically to a real envelope for THIS
 * check, without needing to be individually admissible — proven below
 * before relying on it.
 *
 * NOT PROVEN HERE, STATED HONESTLY: "exactly AT the bound is accepted"
 * (delta 1's second assertion) is NOT re-tested at the new, much larger
 * scale — that would need `NODUS_V2_ENV_BATCH_MAX` (thousands) of
 * GENUINELY ADMISSIBLE envelopes to reach ACCEPT for real (a marker-
 * only buffer fails real decode at the per-item seam, which DOES run
 * once the count is within bound), which is exactly the construction
 * this case's own header says is impractical. The ACCEPT side of "a
 * count within the new, larger bound is still accepted" is covered at
 * small scale by `t_byte_bound_prepare_and_process` above (11 real
 * envelopes, ACCEPT) — RED under delta 1's 10-item cap, GREEN here,
 * per the ORCHESTRATOR's own note on landing this delta. The `>` vs
 * `>=` boundary EXACTNESS at the new scale is therefore an open gap,
 * named rather than silently dropped.
 *
 * RED-BEFORE-THIS-PACKAGE, STATED HONESTLY: before it, ProcessProposal
 * had no per-CLASS ceiling at all — only the byte-derived `env_bound`
 * (in the hundreds of thousands) and the flat mixed item cap, neither
 * of which `NODUS_V2_ENV_BATCH_MAX + 1` marker-only buffers would have
 * approached — so the request would have reached the per-item seam,
 * which decodes each entry for real and REJECTS every one of them for
 * being too short to be a real envelope (a DIFFERENT reason than the
 * one this case exists to prove) rather than the per-class COUNT this
 * case targets. That distinction is exactly why the classification
 * self-check below (proving these buffers count AS envelopes without
 * needing to decode as one) matters.
 */
static int t_process_proposal_item_cap(void)
{
    gfx_t                                    g;
    cmt_genesis_doc_t                        doc;
    nodus_cmt_app_ledger_t                  *app;
    nodus_abci_request_process_proposal_t    req;
    nodus_abci_response_process_proposal_t   resp;
    cmt_genesis_validator_t                   gvals[DNAC_COMMITTEE_SIZE];
    cmt_pb_bytes_t                            *txs = NULL;
    uint8_t                                  (*bufs)[16] = NULL;
    const size_t                               N =
        (size_t)NODUS_V2_ENV_BATCH_MAX + 1;
    size_t                                     i;

    CHECK(gfx_open(&g, "proc_cap") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");

    txs  = (cmt_pb_bytes_t *)calloc(N, sizeof(*txs));
    bufs = calloc(N, sizeof(*bufs));
    CHECK(txs && bufs, "alloc");
    for (i = 0; i < N; i++) {
        memcpy(bufs[i], "DNA.ENVWIRE.v1", 14);
        bufs[i][14] = 0;
        bufs[i][15] = 0;
        txs[i].data = bufs[i];
        txs[i].len  = sizeof(*bufs);
    }
    CHECK(nodus_witness_v2_classify_entry(bufs[0], 16) ==
              NODUS_W_TX_V2_ENVELOPE,
          "the marker-only buffer must classify as an envelope, or this "
          "case proves nothing about the envelope class cap");

    memset(&req, 0, sizeof(req));
    req.txs     = txs;
    req.txs_len = N;                 /* NODUS_V2_ENV_BATCH_MAX + 1     */
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_process_proposal(app, &req, &resp) == CMT_OK,
          "process_proposal returns a verdict, not a fault");
    CHECK(resp.status == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "R3 W4-C delta 2: NODUS_V2_ENV_BATCH_MAX + 1 envelope-"
          "classified entries must be refused BEFORE any per-item work "
          "(RED before this delta's classify-count check existed: these "
          "would have reached the per-item seam and been rejected for "
          "malformed bytes instead — the WRONG reason)");

    nodus_cmt_app_ledger_release(app);
    free(bufs);
    free(txs);
    free(app);
    gfx_close(&g);
    return 0;
}

/** The vote-extension pair is the reference's BaseApplication default. */
static int t_vote_extensions(void)
{
    gfx_t                                       fx;
    cmt_genesis_doc_t                           doc;
    nodus_cmt_app_ledger_t                     *app;
    nodus_abci_request_extend_vote_t            evreq;
    nodus_abci_response_extend_vote_t           evresp;
    nodus_abci_request_verify_vote_extension_t  vreq;
    nodus_abci_response_verify_vote_extension_t vresp;

    /* tokenomics-v3 P4: a real version-3 chain (the version-2 fixture
     * this case borrowed carried nothing it reads). */
    CHECK(gfx_open(&fx, "voteext") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    memset(&doc, 0, sizeof(doc));
    /* ORCHESTRATOR delta 1, item B — nodus_cmt_app_ledger_init now
     * derives the byte-bound seam's arrays from
     * doc.consensus_params.block.max_bytes, so a FULLY zeroed document
     * (this case's original doc — extend_vote/verify_vote_extension
     * need nothing from it) no longer binds. A minimal, valid
     * Block.MaxBytes (D-4 rev 3's own value) is enough; this case is
     * about the vote-extension defaults, not the genesis document. */
    doc.has_consensus_params = true;
    doc.consensus_params.block.max_bytes = 22020096;
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
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&fx);
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

/* TV3-P0 item 2 regression — ported from the ORCHESTRATOR's impact-review
 * scratch scenario (scratchpad/claimfault/scratch_case.inc, 2026-09-22/23).
 * Denies the ONE sqlite write `nodus_witness_v2_claim_spend_insert` makes
 * (the shape of a local SQLITE_IOERR/FULL) — a NODE-LOCAL fault inside one
 * claim item on the cometbft lane. */
static int authz_deny_v2_claims_spent_insert(void *ud, int action,
                                             const char *a1, const char *a2,
                                             const char *a3, const char *a4)
{
    (void)ud; (void)a2; (void)a3; (void)a4;
    if (action == SQLITE_INSERT && a1 && strcmp(a1, "v2_claims_spent") == 0) {
        return SQLITE_DENY;
    }
    return SQLITE_OK;
}

/**
 * A NODE-LOCAL STORAGE FAULT INSIDE ONE CLAIM ITEM IS A BLOCK FAULT, NOT
 * AN ITEM CODE.
 *
 * Before TV3-P0, `nodus_witness_v2_claim_spend_insert`'s INSERT failing
 * for a NODE-LOCAL reason was indistinguishable from a deterministic
 * claim refusal: the helper returned a bare -1 for both,
 * `claim_execute_one` propagated -1, and the cometbft-lane claim loop
 * folded ANY nonzero into item code CLAIM (8) with a savepoint rollback
 * — the block still COMMITTED, with a LastResultsHash that depended on
 * a fault only THIS node hit (a node-local condition becoming consensus
 * data). The helper now returns -2 for exactly this class, the loop
 * takes `goto fail_fault` instead of the item-refusal path, and
 * `nodus_cmt_app_finalize_block`'s existing `rc != 0 -> CMT_FAULT`
 * mapping (nodus_witness_cmt_app.c:1341-1369, read-only for this
 * package) turns it into CMT_FAULT — this node stops rather than
 * voting on state a peer without the fault would not share.
 *
 * The genesis carries exactly one allocation, bound to `g_ks[0]`'s
 * public key (cfg_make_v3_real) — the same single-leaf claim shape
 * `t_claim_items` builds; the config derivation is deterministic, so two
 * independent `gfx_open` fixtures agree on the same chain and the same
 * claim bytes apply cleanly to both.
 */
static int t_claim_local_fault_is_block_fault(void)
{
    gfx_t          gm, gc;
    exec_t         xm, xc;
    dna_claim_t   *claim;
    uint8_t        mh[64], leaf_hash[64];
    uint8_t        cbytes[DNA_CLAIM_MAX_WIRE];
    size_t         clen = 0;
    cmt_block_id_t bid_m, bid_c;
    int            rc;

    CHECK(gfx_open(&gm, "claimfaultm") == 0, "faulted fixture");
    CHECK(gfx_open(&gc, "claimfaultc") == 0, "clean fixture");
    CHECK(memcmp(gm.chain32, gc.chain32, 32) == 0,
          "the config derivation is deterministic — same chain both sides");
    CHECK(exec_init(&xm, &gm) == 0, "faulted blockexec");
    CHECK(exec_init(&xc, &gc) == 0, "clean blockexec");

    claim = calloc(1, sizeof(*claim));    /* ~5 KB: never on the stack */
    CHECK(claim, "alloc");
    {
        dna_gman_t      m;
        dna_dist_leaf_t leaf;

        CHECK(nodus_witness_v2_manifest_load(gm.w, 0, &m) == 0,
              "the genesis manifest is committed at seq 0");
        CHECK(dna_gman_hash(&m, mh) == 0, "its hash");
        CHECK(m.dist_present == 1, "it carries a distribution section");

        memset(&leaf, 0, sizeof(leaf));
        leaf.leaf_version  = DNA_DIST_VERSION;
        leaf.source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
        memcpy(leaf.source_id, gm.box.allocs[0].source_id,
               NODUS_V2_GEN_SRCID_LEN);
        leaf.source_amount = gm.box.allocs[0].amount;
        memcpy(leaf.dest_binding, gm.box.allocs[0].dest_binding, 64);
        CHECK(dna_dist_leaf_hash(&leaf, leaf_hash) == 0, "leaf hash");

        claim->claim_version = DNA_CLAIM_VERSION;
        memcpy(claim->chain_id, gm.chain32, DNA_CHAIN_ID_LEN);
        memcpy(claim->manifest_hash, mh, 64);
        claim->leaf_index    = 0;
        claim->source_id_len = leaf.source_id_len;
        memcpy(claim->source_id, leaf.source_id, leaf.source_id_len);
        claim->source_amount = leaf.source_amount;
        memcpy(claim->dest_binding, leaf.dest_binding, 64);
        claim->n_siblings = 0;             /* a one-leaf tree */
        claim->auth_mode  = DNA_CLAIMAUTH_DNA_NATIVE;
        memcpy(claim->pubkey, g_ks[0].pk, QGP_DSA87_PUBLICKEYBYTES);
    }
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t  pre_len = 0, siglen = 0;

        CHECK(dna_claim_preimage(claim, pre, &pre_len) == 0, "preimage");
        CHECK(qgp_dsa87_sign(claim->signature, &siglen, pre, pre_len,
                             g_ks[0].sk) == 0 &&
              siglen == DNA_CLAIM_SIG_LEN, "the claimant signs it");
    }
    CHECK(dna_claim_encode(claim, cbytes, sizeof(cbytes), &clen) == 0,
          "the claim encodes");

    /* ── the FAULTED node: this transaction's v2_claims_spent INSERT is
     * denied by the authorizer — the shape of a local SQLITE_IOERR/FULL
     * at prepare time. ─────────────────────────────────────────────── */
    xm.txs[0].data = cbytes; xm.txs[0].len = clen;
    CHECK(exec_make_block(&xm, 1, 1) == 0, "faulted node: block 1 = [claim]");
    CHECK(exec_block_id(&xm, xm.blk, &bid_m) == 0 &&
          block_id_is_complete(&bid_m), "a COMPLETE BlockID");

    CHECK(sqlite3_set_authorizer(gm.w->db,
                                 authz_deny_v2_claims_spent_insert,
                                 NULL) == SQLITE_OK, "authorizer installed");
    rc = nodus_cmt_host_apply_verified_block(xm.be, &bid_m, xm.blk, xm.state);
    sqlite3_set_authorizer(gm.w->db, NULL, NULL);
    CHECK(rc == CMT_FAULT,
          "a node-local spent-claim-insert fault stops the node "
          "(CMT_FAULT), never a CMT_OK block with item code CLAIM");
    CHECK(q1(gm.w->db, "SELECT COUNT(*) FROM v2_blocks") == 0,
          "the whole transaction rolled back — nothing committed at "
          "height 1 on the faulted node");
    CHECK(q1(gm.w->db, "SELECT COUNT(*) FROM v2_claims_spent") == 0,
          "no spent row either");
    /* THE POST-CONDITION THAT ACTUALLY OBSERVES THE ROLLBACK (ORCHESTRATOR
     * delta, verifier N9): the v2_blocks row is written AFTER the claim
     * loop and the denied INSERT is the spent row itself, so neither of
     * the two checks above observes any undo at all. What does:
     * `nodus_rt_core_claim_apply` inserts the claim's OUTPUT into utxo_set
     * BEFORE `_claim_spend_insert` runs (nodus_witness_v2_claims.c,
     * EXECUTE stage a precedes stage b), so that row genuinely existed
     * mid-transaction and its absence here is the undo made visible. A
     * version-3 genesis holds no spendable UTXO
     * (nodus_witness_v2_gen.c post-condition), so the expected count is
     * exactly 0.
     *
     * HONEST LABEL (second verifier, D5): this does NOT tell the host's
     * whole-transaction ROLLBACK apart from the item-savepoint unwind the
     * fault exit also performs — ROLLBACK TO SAVEPOINT would remove the
     * same row — so it proves "the output is undone on a FAULT", not
     * which of the two mechanisms undid it. The savepoint unwind at the
     * fault exits is a convention alignment with the envelope lane, not
     * an observable here. */
    CHECK(q1(gm.w->db, "SELECT COUNT(*) FROM utxo_set") == 0,
          "the claim OUTPUT written before the denied insert is undone "
          "on the faulted node");

    /* ── the CLEAN twin applies the SAME bytes with code 0 ──────────── */
    xc.txs[0].data = cbytes; xc.txs[0].len = clen;
    CHECK(exec_make_block(&xc, 1, 1) == 0, "clean node: block 1 = [claim]");
    CHECK(exec_block_id(&xc, xc.blk, &bid_c) == 0 &&
          block_id_is_complete(&bid_c), "a COMPLETE BlockID");
    CHECK(memcmp(bid_c.hash, bid_m.hash, CMT_TMHASH_SIZE) == 0,
          "block 1 is the SAME block on both nodes");
    CHECK(nodus_cmt_host_apply_verified_block(xc.be, &bid_c, xc.blk, xc.state)
              == CMT_OK, "the clean twin applies block 1");
    CHECK(xc.ledger->fb_pb[0].det.code == (uint32_t)NODUS_V2_TX_OK,
          "the clean twin's claim applied with code 0");
    CHECK(q1(gc.w->db, "SELECT COUNT(*) FROM v2_claims_spent") == 1,
          "the clean twin's spent row exists");
    CHECK(q1(gc.w->db, "SELECT COUNT(*) FROM utxo_set") == 1,
          "and its claim OUTPUT exists — the control for the faulted "
          "node's zero above");

    free(claim);
    exec_free(&xc); gfx_close(&gc);
    exec_free(&xm); gfx_close(&gm);
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
    /* ORCHESTRATOR delta 3, item A — `fb_results` (the engine's raw
     * per-item nodus_v2_tx_result_t array) is delta 2's LOCAL
     * `results_arr` inside `nodus_cmt_app_finalize_block`, freed via
     * goto-cleanup before the call returns; it no longer survives on the
     * ledger context. The SAME values this case needs (the mapped code
     * and gas_wanted `finalize_block` itself computed from that array,
     * `r->det.code = e->code; r->det.gas_wanted = (int64_t)e->gas_wanted;`)
     * are what the ABCI response buffer `ctx->fb_pb` retains — the ONE
     * array the ABCI ownership rule keeps ctx-owned across calls, valid
     * until the NEXT `finalize_block` (proxy/app_conn.go's rule; see
     * nodus_witness_cmt_app.h's struct comment). Reading `x.ledger->
     * fb_pb[i].det.*` here proves the identical assertion — the mapped
     * per-item result FinalizeBlock actually returned — through the
     * surface that now legitimately carries it. */
    CHECK(x.ledger->fb_pb[0].det.code == (uint32_t)NODUS_V2_TX_ERR_EXEC,
          "item A is coded EXEC (7)");
    CHECK(x.ledger->fb_pb[1].det.code == (uint32_t)NODUS_V2_TX_OK,
          "item B applied");
    CHECK(x.ledger->fb_pb[1].det.gas_wanted > 0,
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
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/** Binding a LEGACY chain is refused. */
static int t_bind_refuses_legacy(void)
{
    gfx_t                   fx;
    cmt_genesis_doc_t       doc;
    nodus_cmt_app_ledger_t *app;

    /* tokenomics-v3 P4: a real version-3 chain; the case flips
     * v2_successor itself, which is its subject. */
    CHECK(gfx_open(&fx, "bind") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    memset(&doc, 0, sizeof(doc));
    /* ORCHESTRATOR delta 1, item B — a valid Block.MaxBytes so the
     * v2_successor==true leg below reaches ITS verdict (CMT_OK) rather
     * than the byte-bound seam's own precondition (this case is about
     * v2_successor gating and the mandatory-doc check, not the genesis
     * document's content). */
    doc.has_consensus_params = true;
    doc.consensus_params.block.max_bytes = 22020096;
    fx.w->v2_successor = false;
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &doc) == CMT_FAULT,
          "a legacy chain must be refused");
    fx.w->v2_successor = true;
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &doc) == CMT_OK,
          "a successor chain binds");
    nodus_cmt_app_ledger_release(app);
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, NULL) == CMT_FAULT,
          "the genesis document is mandatory");
    free(app);
    gfx_close(&fx);
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
        { "val_updates_non_boundary",   t_val_updates_non_boundary },
        { "val_updates_quiet_boundary", t_val_updates_quiet_boundary },
        { "val_updates_missing_snapshot", t_val_updates_missing_snapshot },
        { "val_updates_boundary_diff",  t_val_updates_boundary_diff },
        { "finalize_block_empty",       t_finalize_block_empty },
        { "d4_empty_blocks_root_stable", t_d4_empty_blocks_root_stable },
        { "attendance_mixed_flags",     t_attendance_mixed_flags },
        { "commit",                     t_commit },
        { "claim_items",                t_claim_items },
        { "claim_local_fault_is_block_fault", t_claim_local_fault_is_block_fault },
        { "check_tx",                   t_check_tx },
        { "chain_id_row_branch",        t_chain_id_row_branch_unchanged },
        { "prepare_proposal",           t_prepare_proposal },
        { "prepare_fee_order",          t_prepare_fee_order },
        { "process_proposal",           t_process_proposal },
        { "vote_extensions",            t_vote_extensions },
        /* ORCHESTRATOR delta 1, item B (D-23 rev 7 (24)) */
        { "byte_bound_prepare_and_process", t_byte_bound_prepare_and_process },
        { "process_proposal_malformed_count",
          t_process_proposal_malformed_count },
        /* ORCHESTRATOR delta 11 (R3-W3-C2a-19) */
        { "prepare_proposal_item_cap",  t_prepare_proposal_item_cap },
        { "process_proposal_item_cap",  t_process_proposal_item_cap },
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
