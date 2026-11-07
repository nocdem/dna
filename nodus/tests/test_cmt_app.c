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
 * ── ONE FIXTURE ────────────────────────────────────────────────────────
 * `gfx_*` is a REAL VERSION-3 chain, derived by
 * `nodus_witness_v2_gen_derive_v3` exactly as test_v2_gen.c §10 derives
 * one and opened by hand (the production open path refuses a version-3
 * chain until W3 — nodus_witness_v2_gen.h's note on
 * `..._stored_chain_id`). Every case runs there, the seam-backed rows
 * included: `nodus_witness_v2_chain_id` answers from the stored genesis
 * document (nodus_witness_v2_claims.c), so the batch preflight, claim
 * admission and the capacity seam all work there.
 * tokenomics-v3 P4 deleted the second fixture (`fx_*`, a version-2
 * successor built through the deleted legacy genesis) together with its
 * last case, `t_chain_id_row_branch_unchanged`: that case pinned the
 * height-0-block-row branch of `nodus_witness_v2_chain_id`, and that
 * branch is deleted — nothing writes a height-0 v2_blocks row any more.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build (no QGP_FAULT_INJECT — the
 * post-commit window is the RUNTIME field
 * `nodus_cmt_blockexec_t.test_fail_after_commit`), except the one HF-9 WP5
 * case `hyb_shadow_fault_host`, built only with -DQGP_FAULT_INJECT=ON (the
 * shadow job's injection point; absent otherwise = missing coverage).
 * Environment: none.
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
 * 10. 2026-09-25 devnet halt — `t_prepare_env_byte_bound`,
 *     `t_prepare_units_truncate`, `t_prepare_entry_invalid_only`. The
 *     seam-run counter is `sqlite3_trace_v2` counting ONE SQL text (the
 *     successor-tip read the seam issues once per run); if a later
 *     change routes another tip read through PrepareProposal the counts
 *     rise and the cases FAIL — they cannot pass silently. The byte case
 *     proves the BYTE bound only because its premise CHECK (the kept
 *     prefix also fits the global AND the CORE unit budget) is asserted
 *     from the real block context: a policy repin that makes units bind
 *     first fails the premise, not the fix. Requirements: none beyond a
 *     default build; ~3 MiB of heap for the 48 fixture envelopes.
 * 11. CHECKTX-P1 — the `t_check_tx_*` and `t_prepare_cc_refused_*` /
 *     `_refill_after_drop` / `_claims_past_env_window` cases. They use no
 *     FUNCTION the package adds (round 2's one constant,
 *     NODUS_CMT_APP_MAX_EXPIRY_AHEAD, has an #ifndef fallback at the top
 *     of this file), so this file builds against 84f331f3 and the
 *     round-1 tree and each case can be run RED there (each case's
 *     comment says what fails, and on which tree).
 *     The light recheck's ONLY observable is the auth-hook COUNTER
 *     (`ckt_counting_table`: the runtime table's hooks wrapped, verdicts
 *     the original hook's); if a later change verifies through another
 *     path the counts move and the case fails loudly. The "block" in
 *     `t_check_tx_recheck_light` is a direct row DELETE inside a
 *     host-style BEGIN plus the application's own Commit row — it
 *     proves the Commit → recheck contract of this row, not the host's
 *     ordering (read in nodus_witness_cmt_host.c `blockexec_commit`, not
 *     driven here). The scripted CORE spend is the fixture adapter's
 *     DELETE, not the native SPEND; the dry run's DELETE-row keys are
 *     runtime-generic, so the native path shares the mechanism but is
 *     not itself exercised here. Requirements: none beyond a default
 *     build; ~3 MiB of heap for each 48-envelope case.
 *     ROUND 2 (`t_check_tx_expiry`, `_row_keys`, `t_prepare_hog_skipped`,
 *     `_fee_per_unit`): every fixture chain has tip 0, so CKT_EXPIRY
 *     (= 100) is the full lifetime window; the expiry case advances the
 *     tip with ONE real empty block through the host. The pack's
 *     per-domain quota path is NOT driven (every genesis manifest has
 *     quota 0 — nodus_witness_domreg.c:312). The round-2 hash set has no
 *     dedicated case: its behaviour is pinned by every conflict case, its
 *     O(1) insert and its all-or-none allocation are not observable here.
 * 12. HF-3 — `t_hf3_bounds_and_fee` (design docs/plans/2026-10-01-hf3-
 *     comet-block-bounds-design.md rev 3): chain_config param 8 at the
 *     candidate height, Prepare/Process at H-1 vs H over N envelopes with
 *     N derived from the measured env_len (byte sum > 2 MiB AND count >
 *     255, asserted from what Prepare kept), the proposal fee check
 *     (price 0 off, underpaid REJECT / dropped, all-SYSTEM exempt, no
 *     check below H), rule 5 (INT64_MAX accepted, INT64_MAX + 1
 *     REJECTed), rule 4 (a non-zero units quota still refuses) and an
 *     unreadable price = FAULT. Rows are direct SQL writes — honest only
 *     because no block is applied afterwards (see the case's own note).
 *     Since HF-3 PrepareProposal reads the tip once itself; the
 *     seam-run counter above subtracts that read (SEAM_RUNS()).
 *     Requirements: none beyond a default build; ~17 MiB of heap for the
 *     ~257 fixture envelopes. Leaves nothing behind (its own tmp dir).
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
#include "dnac/valbind_wire.h"           /* HF-9 WP4: STORAGE_REGISTER consent */
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

#ifdef NODUS_EVM_ENABLED
#include "witness/nodus_witness_v2_trie.h"      /* HF-9 T-15: leg roots   */
#include "witness/nodus_witness_v2_shadow.h"    /* HF-9 T-15 (iv): shadow */
#include "witness/nodus_witness_v2_storage.h"   /* HF-9 T-9: work counters */
#include "witness/nodus_witness_v2_epoch.h"     /* snapshot(H): report seats */
#include "dnac/ledger_roots_v2.h"               /* storage exit id / nullifier */
#include "witness/nodus_witness_cmt_node.h"     /* the Handshaker         */
#endif
#include "../tests/v2_genesis_fixture.h"
#include "../tests/v2_exec_fixture.h"    /* the SCRIPTED runtime table:
                                          * envelopes with a free
                                          * fee_amount and no committee */

/* CHECKTX-P1 round 2 — the mempool lifetime constant (nodus_types.h).
 * Guarded so this file still BUILDS against a tree that predates it and
 * each new case can be run RED there. */
#ifndef NODUS_CMT_APP_MAX_EXPIRY_AHEAD
#define NODUS_CMT_APP_MAX_EXPIRY_AHEAD 100u
#endif

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
 * this shape is kept here (test_cmt_live.c and test_cc_appr.c keep their
 * own copies of the same deterministic-key idiom). */

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
        /* general multisig ONAY 2: a genesis row's destination pubkey is
         * ALL ZERO (the fp above is only a shape-valid address) */
        memset(v->unstake_destination_pubkey, 0, DNAC_PUBKEY_SIZE);
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
    /* W-C: the builder's default genesis gas price (121) switches the
     * fee rule ON from block 1; this file's CORE envelopes pay 0..9 raw
     * to isolate OTHER rules (fee ordering, capacity, conflicts), so the
     * chain opts out explicitly — a committed price-0 row. The gas rule
     * itself is test_v2_gas_price.c's. */
    c->gas_price_raw_per_unit = 0;
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
        /* general multisig ONAY 2: a genesis row's destination pubkey is
         * ALL ZERO (the fp above is only a shape-valid address) */
        memset(v->unstake_destination_pubkey, 0, DNAC_PUBKEY_SIZE);
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
    /* W-C: the builder's default genesis gas price (121) switches the
     * fee rule ON from block 1; this file's CORE envelopes pay 0..9 raw
     * to isolate OTHER rules (fee ordering, capacity, conflicts), so the
     * chain opts out explicitly — a committed price-0 row. The gas rule
     * itself is test_v2_gas_price.c's. */
    c->gas_price_raw_per_unit = 0;
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
    nodus_witness_host_t host;              /* w->host, filled from srv */
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
    nodus_server_witness_host(g->srv, &g->host);
    g->w->host = &g->host;
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
    nodus_server_witness_host(g->srv, &g->host);
    g->w->host = &g->host;
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

/* ══ a REAL chain_config envelope — test_v2_produce.c:256-410's shape
 * ═══════════════════════════════════════════════════════════════════
 * Copied (that file's copy is static and its fixture type differs); the
 * logic is that function's, retyped over a `nodus_witness_t *`.
 * test_v2_produce.c is deleted with the closed consensus lane (R3 W4);
 * this behaviour (a real CHAIN_CONFIG envelope through the chain) is now
 * proven only here — test_cmt_live.c never built one (neither its first
 * version nor its P2P-PORT F5 port); test_cc_appr.c builds the pre-auth
 * form of the same envelope for the approval responder. */

#define CC_CALL_LEN 41u
#define CC_UNITS    200000u

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
} test_env_t;

/* CHECKTX-P1: `units` is the envelope's declared `res_max_total_units`
 * (build_cc_env passes CC_UNITS); 0 builds the red-team F1 poison — a
 * fully authorized chain_config whose reservation can never succeed. */
static int build_cc_env_units(nodus_witness_t *w, const uint8_t chain32[32],
                              uint64_t nonce, uint64_t units,
                              test_env_t *out)
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
        /* CHECKTX-P1 round 2: CheckTx refuses expiry 0 and anything past
         * tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD (decision 2026-09-25-
         * mempool-policy.md 1); the fixture uses the full window. Block
         * validity is unchanged, so the FinalizeBlock cases that apply
         * this envelope at a height <= tip + 100 are unaffected. */
        env_in.expiry_height       = tip +
                                     (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD;
        env_in.fee_amount          = 0;   /* a CHAIN_CONFIG leg requires 0 */
        env_in.res_max_total_units = units;
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

static int build_cc_env(nodus_witness_t *w, const uint8_t chain32[32],
                        uint64_t nonce, test_env_t *out)
{
    return build_cc_env_units(w, chain32, nonce, CC_UNITS, out);
}

/* Bytes that classify as an ENVELOPE (the family marker is present) and
 * do not decode — the DECODE class of nodus_v2_tx_code_t. */
static const uint8_t POISON[20] = {
    'N','D','S','.','E','N','V','W','I','R','E','.','v','1', 0, 0,
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

/* The executor's REQUIRED wait clock (decision 2026-09-30-monotonic-
 * waits.md). Nothing here arms the timer; a fixed value on its own base. */
static int t_mono(void *ctx, int64_t *out_ns)
{
    (void)ctx;
    *out_ns = 7LL * 1000000000LL;
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
    /* HF-9 WP4 (hybrid T-15): nanoseconds ADDED to the last block time in
     * every LastCommit vote stamp. 0 (every other case: unchanged) stamps
     * the votes with the last block time itself, so block h+1's median
     * time equals block h's; the ported validation requires block time >
     * last block time (nodus_witness_cmt_host.c:1163-1169, the port of
     * state/validation.go:132) and the replay path runs it. The hybrid
     * nodes set 1, so the median of equal stamps (cmt_state.c:255-268, the
     * port of MedianTime, state.go:250) is strictly greater than the last
     * block time; the block header time IS that median (validation.go:139). */
    int64_t                 vote_ts_step_ns;
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
                                 &x->ev_if, NULL, NULL, t_now, NULL, t_mono,
                                 NULL, NULL, NULL, &lim) != CMT_OK) {
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
    if (x->vote_ts_step_ns > 0) {
        int64_t nn = (int64_t)ts.nanos + x->vote_ts_step_ns;

        ts.seconds += nn / 1000000000;
        ts.nanos    = (int32_t)(nn % 1000000000);
    }
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

/** The Comet apply entry refuses outside a transaction, at S12, and a
 *  block that does not set `cmt.on` (the deleted legacy lane). */
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
    gfx_close(&g);

    /* tokenomics-v3 P4: a block WITHOUT `cmt.on` asks for the deleted
     * legacy lane. The entry refuses it as a node FAULT, judges nothing
     * and writes nothing — on an otherwise perfectly applicable block
     * (a real version-3 chain at S16, inside a host transaction, the
     * result array sized), so the missing flag is the ONLY thing wrong.
     * RED ON THE PRE-P4 TREE (the reason assertion): the legacy lane's
     * own S9-S12 schema gate refused this S16 chain first, with a
     * schema reason — a refusal incidental to the missing flag, which
     * nothing named. */
    {
        uint8_t d0[64], d1[64];

        CHECK(gfx_open(&g, "pre_nocmt") == 0, "version-3 fixture");
        CHECK(v2x_db_digest(g.w, d0) == 0, "digest before");
        CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0,
              "a host transaction");
        memset(blk, 0, sizeof(*blk));
        blk->global_height = 1;
        blk->epoch = nodus_v2_epoch_for_height(1);
        blk->cmt.results = results;
        blk->cmt.results_cap = 4;        /* everything but `cmt.on`      */
        CHECK(nodus_witness_v2_apply_block(g.w, blk) ==
                  NODUS_V2_INTERNAL_FAULT,
              "a block without cmt.on is refused as a node FAULT");
        CHECK(strstr(blk->out_reason, "legacy (non-cometbft) block lane "
                                      "is deleted") != NULL,
              "and says why");
        CHECK(run_sql(g.w->db, "ROLLBACK") == 0, "clean up");
        CHECK(v2x_db_digest(g.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "nothing was written");
        gfx_close(&g);
    }
    free(blk);
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

/* Overwrite the stored snapshot row of s->epoch with `s` (any ruleset,
 * encoded and hashed by the `_ex` family) — the test-only bypass
 * `t_val_updates_boundary_diff` documents. */
static int vu_snap_overwrite(nodus_witness_t *w, const dna_vset_snapshot_t *s)
{
    size_t         need = dna_vset_encoded_len_ex(s, DNA_VSET_RULESET_TOPN_V2);
    uint8_t       *b;
    uint8_t        h[DNA_VSET_HASH_LEN];
    sqlite3_stmt  *st = NULL;
    int            ok = -1;

    if (need == 0) {
        return -1;
    }
    b = (uint8_t *)malloc(need);
    if (!b) {
        return -1;
    }
    if (dna_vset_encode_ex(s, DNA_VSET_RULESET_TOPN_V2, b, need, NULL) == 0 &&
        dna_vset_hash_bytes_ex(b, need, DNA_VSET_RULESET_TOPN_V2, h) == 0 &&
        sqlite3_prepare_v2(w->db,
            "UPDATE validator_set_snapshots SET active_count = ?1, "
            "snapshot_hash = ?2, snapshot_blob = ?3 WHERE epoch_start = ?4",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, (int)s->active_count);
        sqlite3_bind_blob(st, 2, h, DNA_VSET_HASH_LEN, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, b, (int)need, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)s->epoch);
        if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) == 1) {
            ok = 0;
        }
    }
    if (st) {
        sqlite3_finalize(st);
    }
    free(b);
    return ok;
}

/**
 * HF-6 slice 5c — the §A diff with a RULESET-2 snapshot on the OLD side
 * (design rev 6 §5 "sınır güncelleme farkı … yeni VE eski güç"; plan
 * tasks/hf6-slice5-plan.md §1 "Comet's update across the switch").
 *
 * WHAT IT PROVES: at boundary E the diff reads snapshot(0)'s powers
 * through `nodus_witness_vset_powers` BY ITS OWN RULESET — counted
 * (capped) for a ruleset-2 snapshot — and still matches entries by
 * pubkey. snapshot(0) is rewritten (after heights 1..E-1, which it
 * governs, are committed) as a ruleset-2 set [60M, 10M × 6] whole coins
 * (g_ks[1] at 60M), whose counted vector at the compiled 3000 bps is
 * [25714285, 10M × 6] (design §5: k = 0 S = 120M c = 36M < 60M; k = 1
 * S = 60M c = ⌊3000·60M / 7000⌋ = 25714285 ≥ 10M, stop). snapshot(E)
 * stays ruleset 1 with g_ks[1] at exactly 25714285 coins and g_ks[2]
 * doubled to 20M. Counted on the old side ⇒ ONE update (g_ks[2], power
 * 20M); raw on the old side would be TWO (g_ks[1] 60M → 25714285 too).
 *
 * WHAT IT CANNOT PROVE (stated, not faked): a RULESET-2 snapshot on the
 * NEW side. The new side of the diff at H is snapshot(H), which governs
 * block H itself, and the engine's per-block phase 0a hashes the governing
 * snapshot with the ruleset-1-only `dna_vset_hash`
 * (nodus_witness_v2_apply.c, outside slice 5c's files) — a v2 snapshot(H)
 * faults block H before FinalizeBlock reaches the diff. That consumer is
 * slice 5d's (with the phase-0a codec switch).
 *
 * REQUIRES: a default build; nothing in the environment. The rewrite
 * happens at E-1 for the same reason `t_val_updates_boundary_diff` gives
 * (the untouched-domain guard). The other readers of snapshot(0) at block
 * E: Rule N's duty set (pubkey / voter_id — unchanged here) and the
 * reward distribution, which returns before reading any snapshot because
 * this fixture's reward pool is 0 (reward_pool_initial 0, empty blocks).
 *
 * LEAVES BEHIND: its `/tmp/test_cmt_app_vu_v2old_*` directory, removed at
 * close (left when a CHECK aborts).
 *
 * HOW IT CAN LIE: the snapshots are hand-written rows, not ones a builder
 * produced; the ids are arbitrary distinct bytes (they only tie-break the
 * cap, and no tie exists here).
 */
static int t_val_updates_v2_old_side(void)
{
    gfx_t                              g;
    exec_t                             x;
    cmt_block_id_t                     bid;
    cmt_pb_response_finalize_block_t   got;
    cmt_pb_validator_update_t          vu_pool[16];
    cmt_pb_arena_t                     arena;
    uint8_t                            arena_buf[8192];
    dna_vset_snapshot_t               *s0 = NULL, *sE = NULL;
    uint64_t                           pw[DNA_MAX_ACTIVE_VALIDATORS];
    const uint64_t                     U = DNAC_DECIMAL_UNIT;
    const uint64_t                     counted_big = 25714285ULL;
    int                                i, j1 = -1, j2 = -1;

    CHECK(DNAC_HF6_POWER_CAP_BPS_DEFAULT == 3000u,
          "the expected vector is derived at 3000 bps");
    CHECK(DNAC_SELF_STAKE_AMOUNT == 10000000ULL * U,
          "FIXTURE GUARD: genesis members hold 10M whole coins");
    CHECK(gfx_open_n(&g, "vu_v2old", 1) == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    memset(&bid, 0, sizeof(bid));
    CHECK(vu_host_drive_to(&x, &bid, 0, (int64_t)VU_EPOCH - 1) == 0,
          "drive height 1..E-1 (snapshot(0) governs them, unmodified)");

    /* the OLD side: snapshot(0) as ruleset 2, g_ks[1] at 60M */
    CHECK(nodus_witness_vset_get(g.w, 0, &s0, NULL) == 0 &&
          s0->active_count == (uint16_t)N_KEYS &&
          s0->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
          "the genesis-seeded snapshot(0)");
    s0->selection_ruleset = DNA_VSET_RULESET_TOPN_V2;
    for (i = 0; i < (int)s0->active_count; i++) {
        dna_vset_entry_t *e = &s0->entries[i];

        memset(e->validator_id, 0x40 + i, DNA_VSET_VALIDATOR_ID_LEN);
        memset(e->owner_fp, 0x80 + i, DNA_VSET_OWNER_FP_LEN);
        CHECK(e->total_stake == DNAC_SELF_STAKE_AMOUNT,
              "FIXTURE GUARD: 10M each in snapshot(0)");
        if (memcmp(e->pubkey, g_ks[1].pk, DNAC_PUBKEY_SIZE) == 0) {
            e->total_stake = 60000000ULL * U;
            j1 = i;
        }
        if (memcmp(e->pubkey, g_ks[2].pk, DNAC_PUBKEY_SIZE) == 0) {
            j2 = i;
        }
    }
    CHECK(j1 >= 0 && j2 >= 0, "FIXTURE GUARD: g_ks[1], g_ks[2] seated");
    CHECK(nodus_witness_vset_powers(g.w, s0, pw) == 0,
          "the helper over the v2 old side");
    for (i = 0; i < (int)s0->active_count; i++) {
        CHECK(pw[i] == (i == j1 ? counted_big : 10000000ULL),
              "old side counted [25714285, 10M x 6]");
    }
    CHECK(vu_snap_overwrite(g.w, s0) == 0, "rewrite snapshot(0) as ruleset 2");

    /* the NEW side: snapshot(E) stays ruleset 1 */
    CHECK(nodus_witness_vset_get(g.w, VU_EPOCH, &sE, NULL) == 0 &&
          sE->active_count == (uint16_t)N_KEYS &&
          sE->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
          "the genesis-seeded snapshot(E)");
    for (i = 0; i < (int)sE->active_count; i++) {
        dna_vset_entry_t *e = &sE->entries[i];

        if (memcmp(e->pubkey, g_ks[1].pk, DNAC_PUBKEY_SIZE) == 0) {
            e->total_stake = counted_big * U;   /* == its old counted power */
        }
        if (memcmp(e->pubkey, g_ks[2].pk, DNAC_PUBKEY_SIZE) == 0) {
            e->total_stake *= 2;                /* 20M: a real change      */
        }
    }
    CHECK(vu_snap_overwrite(g.w, sE) == 0, "rewrite snapshot(E), ruleset 1");
    {
        dna_vset_snapshot_t *back = NULL;

        CHECK(nodus_witness_vset_get(g.w, 0, &back, NULL) == 0 &&
              back->selection_ruleset == DNA_VSET_RULESET_TOPN_V2,
              "the stored ruleset-2 snapshot(0) reads back (5c store)");
        dna_vset_free(&back);
    }
    dna_vset_free(&s0);
    dna_vset_free(&sE);

    CHECK(vu_host_drive_to(&x, &bid, (int64_t)VU_EPOCH - 1,
                           (int64_t)VU_EPOCH) == 0,
          "apply the boundary block E (governed by the ruleset-1 snapshot(E))");

    arena.buf = arena_buf;
    arena.cap = sizeof(arena_buf);
    arena.used = 0;
    CHECK(vu_host_load_updates(&x, (int64_t)VU_EPOCH, &got, vu_pool, 16,
                               &arena) == CMT_OK,
          "load the boundary's stored FinalizeBlock response");
    CHECK(got.validator_updates_len == 1,
          "exactly ONE update: the old side was read COUNTED (raw would "
          "also re-announce g_ks[1])");
    CHECK(got.validator_updates[0].pub_key.present &&
          memcmp(got.validator_updates[0].pub_key.key, g_ks[2].pk,
                 DNAC_PUBKEY_SIZE) == 0 &&
          (uint64_t)got.validator_updates[0].power == 20000000ULL,
          "the update is g_ks[2] at its new raw power 20M, matched by pubkey");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * HF-6 slice 6d — what Comet is told at boundary U when a rotation was
 * accepted (design 2026-10-03-hf5-validator-owner-stake rev 6 §3
 * "Kabul edilen rotasyon S(U)'ya YENİ anahtarla girer. Comet: FinalizeBlock
 * U ilan eder"; plan tasks/hf6-slice6-plan.md §1.3, consumer #1).
 *
 * WHAT IT PROVES: a snapshot(U) that differs from snapshot(U−E) only in
 * ONE entry's consensus key (same stake, voter_id re-derived) — the shape
 * the 6d freeze stores for an accepted rotation — is announced by the §A
 * diff as EXACTLY two updates: the new key at the entry's power, then the
 * old key at power 0 (additions before removals); cometbft's
 * update_with_change_set accepts it (the boundary block commits), and the
 * validator set Comet saved for height U+2 holds the new address at that
 * power and no longer the old one, with the set size unchanged. No port
 * change: cometbft has no "key change", a rotation IS remove + add.
 *
 * ⚠ HF-6 D1 (khan decision docs/plans/decisions/2026-10-13-kurultay-18-
 * summary.md item 1): ROTATE and the 6d builder were removed, so no
 * committed chain produces this snapshot pair any more — the case is kept
 * as a test of the generic §A diff (a key change, however it arises, is
 * remove + add).
 *
 * WHAT IT CANNOT PROVE (stated, not faked): that any builder produces
 * this snapshot — this host fixture is not at key generation 4;
 * the new address's proposer priority — cometbft sets −1.125·P on entry
 * (cmt_validator_set.c compute_new_priorities) and the saved value is
 * after the rescale/centre and one increment of the update, so pinning it
 * would restate the port's own arithmetic (its unit tests cover it); and
 * any height past E — exec_make_last_commit signs only with g_ks keys, and
 * from E+2 the set holds a key this fixture did not generate as a member.
 *
 * REQUIRES: a default build; nothing in the environment. The rewrite
 * happens at E-1 (the untouched-domain guard — see
 * `t_val_updates_boundary_diff`).
 *
 * LEAVES BEHIND: its `/tmp/test_cmt_app_vu_rot_*` directory, removed at
 * close (left when a CHECK aborts).
 *
 * HOW IT CAN LIE: the snapshot is a hand-written ruleset-1 row; the other
 * readers of snapshot(E) at block E (the flips by pubkey: the replaced
 * member's row simply stays ELIGIBLE; the reward distribution returns
 * early on this fixture's empty pool) are not what is asserted.
 */
static int t_val_updates_rotation(void)
{
    gfx_t                              g;
    exec_t                             x;
    cmt_block_id_t                     bid;
    cmt_pb_response_finalize_block_t   got;
    cmt_pb_validator_update_t          vu_pool[16];
    cmt_pb_arena_t                     arena;
    uint8_t                            arena_buf[8192];
    dna_vset_snapshot_t               *s = NULL;
    uint8_t                            new_pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t                            new_sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t                            seed[32];
    uint8_t                            new_voter[32];
    cmt_validator_t                   *storage = NULL;
    cmt_validator_set_t                vals;
    int64_t                            power = -1;
    size_t                             i;
    int                                j = -1, saw_new = 0, saw_old = 0;

    CHECK(gfx_open_n(&g, "vu_rot", 1) == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    memset(&bid, 0, sizeof(bid));
    CHECK(vu_host_drive_to(&x, &bid, 0, (int64_t)VU_EPOCH - 1) == 0,
          "drive height 1..E-1 (snapshot(0) governs them, unmodified)");

    /* snapshot(E) = snapshot(0)'s members with g_ks[3]'s key rotated */
    memset(seed, 0x6D, sizeof(seed));
    CHECK(qgp_dsa87_keypair_derand(new_pk, new_sk, seed) == 0,
          "the rotation target key");
    CHECK(nodus_chain_config_derive_witness_id(new_pk, new_voter) == 0,
          "its voter_id (= Comet address)");
    CHECK(nodus_witness_vset_get(g.w, VU_EPOCH, &s, NULL) == 0 &&
          s->active_count == (uint16_t)N_KEYS &&
          s->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
          "the genesis-seeded snapshot(E)");
    for (i = 0; i < s->active_count; i++) {
        if (memcmp(s->entries[i].pubkey, g_ks[3].pk, DNAC_PUBKEY_SIZE) == 0)
            j = (int)i;
    }
    CHECK(j >= 0, "FIXTURE GUARD: g_ks[3] seated in snapshot(E)");
    memcpy(s->entries[j].pubkey, new_pk, DNAC_PUBKEY_SIZE);
    memcpy(s->entries[j].voter_id, new_voter, 32);
    power = (int64_t)(s->entries[j].total_stake / DNAC_DECIMAL_UNIT);
    CHECK(power > 0, "the rotated entry keeps its stake");
    CHECK(vu_snap_overwrite(g.w, s) == 0,
          "rewrite snapshot(E): one entry under a new key");
    dna_vset_free(&s);

    CHECK(vu_host_drive_to(&x, &bid, (int64_t)VU_EPOCH - 1,
                           (int64_t)VU_EPOCH) == 0,
          "apply the boundary block E: cometbft accepts the change set");

    arena.buf = arena_buf;
    arena.cap = sizeof(arena_buf);
    arena.used = 0;
    CHECK(vu_host_load_updates(&x, (int64_t)VU_EPOCH, &got, vu_pool, 16,
                               &arena) == CMT_OK,
          "load the boundary's stored FinalizeBlock response");
    CHECK(got.validator_updates_len == 2,
          "a rotation is EXACTLY two updates");
    CHECK(got.validator_updates[0].pub_key.present &&
          memcmp(got.validator_updates[0].pub_key.key, new_pk,
                 DNAC_PUBKEY_SIZE) == 0 &&
          got.validator_updates[0].power == power,
          "first the new key, at the entry's power");
    CHECK(got.validator_updates[1].pub_key.present &&
          memcmp(got.validator_updates[1].pub_key.key, g_ks[3].pk,
                 DNAC_PUBKEY_SIZE) == 0 &&
          got.validator_updates[1].power == 0,
          "then the old key, removed (power 0)");

    storage = calloc(CMT_VALSET_MAX, sizeof(*storage));
    CHECK(storage != NULL, "alloc");
    CHECK(cmt_validator_set_init(&vals, storage, CMT_VALSET_MAX) == CMT_OK &&
          nodus_cmt_ss_load_validators(x.store, (int64_t)VU_EPOCH + 2,
                                       &vals) == CMT_OK,
          "the validator set cometbft saved for height E+2");
    CHECK(vals.validators_len == (size_t)N_KEYS, "the set size is unchanged");
    for (i = 0; i < vals.validators_len; i++) {
        if (memcmp(vals.validators[i].address, new_voter, 32) == 0) {
            saw_new = 1;
            CHECK(vals.validators[i].voting_power == power,
                  "the new address carries the entry's power");
        }
        if (memcmp(vals.validators[i].address, g_ks[3].voter, 32) == 0)
            saw_old = 1;
    }
    CHECK(saw_new && !saw_old,
          "from E+2 cometbft's set holds the new address, not the old one");
    free(storage);

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
     * `nodus_witness_v2_chain_id`, which answers from the stored
     * genesis document (the chain's only identity since tokenomics-v3
     * P4 deleted the height-0 block-row branch). */
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

    /* The last byte of the envelope is the last byte of the last
     * committee approval's ML-DSA-87 signature, and the envelope carries
     * EXACTLY `dna_bft_quorum(7)` = 5 approvals (build_cc_env emits
     * `quorum` and fails otherwise), so breaking one leaves four — below
     * quorum. Nothing in the ADMISSION lane looks at it: the preflight
     * decides nothing about authorization (env_preflight.h:57-63) and the
     * `wire_id` comparison is a tautology because check_tx derives the id
     * from the bytes it is checking. It is the authorization stage of the
     * per-item dry run (`nodus_witness_v2_env_dry_run` →
     * `env_authorize_legs`, CHECKTX-P1) that refuses it.
     *
     * CHECKTX-P1 round 3 (verifier UNCOVERED 1): the corrupted copy goes
     * FIRST, on an EMPTY pending set. Checked after the valid copy, its
     * refusal came from the pending intent key (same intent_id — the
     * approvals are authorization evidence, outside the intent) and said
     * nothing about the signature. Here nothing is pending, so the
     * conflict set cannot be the refuser; the dry run's own item code
     * pins the stage to AUTH. */
    env.bytes[env.len - 1] ^= 0xFF;
    CHECK(app->pend_n == 0, "PREMISE: nothing is pending — the conflict "
          "set cannot be what refuses the corrupted copy");
    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "served");
    CHECK(res.code != CMT_MEM_CODE_TYPE_OK,
          "a corrupted APPROVAL SIGNATURE is refused at admission");
    CHECK(app->pend_n == 0, "and the refusal claimed no pending key");
    {
        nodus_v2_env_dry_run_t *dry = calloc(1, sizeof(*dry));
        char                    why[256];
        int                     drc;

        CHECK(dry != NULL, "alloc");
        drc = nodus_witness_v2_env_dry_run(g.w, env.bytes, env.len, NULL, dry,
                                           why, sizeof(why));
        CHECK(drc == -1 && dry->code == (uint32_t)NODUS_V2_TX_ERR_AUTH,
              "the stage that refuses it is AUTHORIZATION");
        nodus_witness_v2_env_dry_run_free(dry);
        free(dry);
    }
    env.bytes[env.len - 1] ^= 0xFF;

    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "the request is served");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK,
          "the restored (valid) envelope is admitted");
    CHECK(res.gas_wanted == 0, "gas_wanted is 0 while MaxGas is -1");

    memset(&res, 0, sizeof(res));
    CHECK(mem.check_tx(mem.ctx, &req, &res) == CMT_OK, "served");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK,
          "and the same bytes checked again are admitted again (the key's "
          "owner is the entry itself)");

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

    /* The SAME chain_config envelope twice, proposed ONCE.
     *
     * CHECKTX-P1: this no longer drives the seam's drop loop — each
     * chain_config candidate is now probed ALONE by the seam and the
     * first one it accepts rides alone, so the duplicate is simply the
     * second candidate that is never tried. The duplicate-drop path of
     * the drop loop (ERR_DUP at slot 1, excluded, repacked) is driven by
     * `t_prepare_cc_refused_packs_rest` case (c), over two byte-identical
     * ordinary envelopes. */
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
 * ENVELOPE from a 16-byte WIRE-FAMILY-MARKER PREFIX ALONE ("NDS.
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
        memcpy(bufs[i], "NDS.ENVWIRE.v1", 14);
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

/* ══ PrepareProposal vs the ledger's own capacity (2026-09-25 halt) ══
 *
 * The live devnet halted at height 135: ~827 envelopes (~6 MB) reached
 * the capacity seam, the seam refused the batch on the SYSTEM policy's
 * absolute envelope-byte bound (`max_block_env_bytes`, 2 MiB) with its
 * by-design fail index 0, and PrepareProposal's drop loop read that 0 as
 * an offender: it dropped the HIGHEST-fee envelope and re-ran the whole
 * seam, one envelope per pass. The three cases below pin the repaired
 * behaviour; the first two also COUNT the seam runs.
 *
 * THE COUNTER is an existing SQLite hook, not a production change:
 * `sqlite3_trace_v2(SQLITE_TRACE_STMT)` on the fixture's own handle,
 * counting statements whose SQL is the successor-tip read
 * "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks". On the
 * PrepareProposal path that statement is issued ONLY by
 * `nodus_witness_v2_tip_height` (nodus_witness_v2_produce.c), which the
 * seam calls exactly once per run with a non-empty batch
 * (produce_batch_check_impl's candidate-height read). The other two
 * sites carrying the same SQL text are the apply engine (never reached
 * by PrepareProposal) and `nodus_witness_block_height_checked`
 * (nodus_witness_db.c — callers in verify.c/peer.c/handlers.c only,
 * none on this path). PrepareProposal's own envelope-byte read goes
 * through `nodus_witness_v2_block_ctx_build`, which does not read the
 * tip itself — but since HF-3 (design 2026-10-01-hf3-comet-block-bounds-
 * design.md D1 (b)) PrepareProposal reads the tip ONCE, through the same
 * `nodus_witness_v2_tip_height`, to build that context at its own
 * candidate height; it does so exactly when at least one envelope is a
 * candidate, which every counted case below has. So the count is the
 * number of seam runs PLUS that one read — SEAM_RUNS() subtracts it.
 * HOW IT CAN LIE: if a later change routes another tip read through this
 * path, the counts below rise and the case fails loudly — it cannot pass
 * silently.
 *
 * The counter is a file-scope static because a failing CHECK returns
 * before the trace is cleared, and the hook must never point at a dead
 * stack frame. */
static int g_seam_runs = 0;
#define PREP_OWN_TIP_READS 1      /* HF-3 D1 (b): Prepare's own tip read */
#define SEAM_RUNS() (g_seam_runs - PREP_OWN_TIP_READS)

static int seam_run_trace(unsigned mask, void *ctx, void *p, void *x)
{
    const char *sql;

    (void)ctx;
    (void)x;
    if (mask != SQLITE_TRACE_STMT || !p) {
        return 0;
    }
    sql = sqlite3_sql((sqlite3_stmt *)p);
    if (sql &&
        strcmp(sql, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks")
            == 0) {
        g_seam_runs++;
    }
    return 0;
}

/**
 * One CORE envelope over the scripted runtime (runtime_op `op`), with
 * `call` as its call data and `fee` as its fee. `ceiling == 0` means
 * "declare EXACTLY the static cost the engine's own plan computes"
 * (build once with a generous ceiling, decode, `dna_meter_plan_build`
 * against the SAME policy the seam uses, rebuild with that figure — the
 * t_byte_bound_prepare_and_process pattern); any other value is
 * declared verbatim. Admission never EXECUTES (it preflights and
 * reserves only — nodus_witness_v2_produce.c), so the call bytes need
 * not be a runnable script; they only have to hash, and a differing
 * byte gives a differing call commitment, hence a distinct intent.
 * `*static_out` (may be NULL) receives the plan's static total.
 * @return 0 / -1.
 */
static int cap_env_build(v2x_env_t *e, const dna_meter_policy_t *pol,
                         const uint8_t *call, uint32_t call_len,
                         uint32_t op, uint64_t fee, uint64_t ceiling,
                         uint64_t *static_out)
{
    v2x_leg_t        leg;
    dna_env_view_t   view;
    dna_meter_plan_t plan;

    memset(&leg, 0, sizeof(leg));
    leg.domain_id        = DNA_DOMAIN_CORE;
    leg.runtime_op       = op;
    leg.call             = call;
    leg.call_len         = call_len;
    leg.max_effects      = 0;
    leg.max_effect_bytes = 0;
    if (v2x_env_build_ex(e, 1000000000ull, 0, fee, &leg, 1) != 0) {
        return -1;
    }
    memset(&view, 0, sizeof(view));
    memset(&plan, 0, sizeof(plan));
    if (dna_env_decode(e->bytes, e->len, &view) != 0) {
        return -1;
    }
    if (dna_meter_plan_build(pol, &view, &plan) == DNA_METER_OK) {
        if (static_out) {
            *static_out = plan.static_total;
        }
        if (ceiling == 0) {
            ceiling = plan.static_total;
        }
    } else if (ceiling == 0) {
        return -1;              /* an unpriceable op has no exact ceiling */
    }
    return v2x_env_build_ex(e, ceiling, 0, fee, &leg, 1);
}

/** The block-start context exactly as the seam builds it: at the
 *  candidate height, committed tip + 1 (HF-3 D1 (c) — the height the
 *  context's HF-3 switch is read at). 0 / -1. */
static int cap_ctx_build(nodus_witness_t *w, nodus_witness_v2_block_ctx_t *b)
{
    uint64_t tip = 0;

    if (nodus_witness_v2_tip_height(w, &tip) != 0) {
        return -1;
    }
    return nodus_witness_v2_block_ctx_build(w, tip + 1u, b) == 0 ? 0 : -1;
}

/** Bind an application to `g`, with the scripted runtime table and the
 *  block-start context the seam itself builds (`*bctx_out`, heap — its
 *  `policy` is the SYSTEM runtime's sealed meter policy). */
static int cap_fixture(gfx_t *g, const char *tag, cmt_genesis_doc_t *doc,
                       cmt_genesis_validator_t *gvals,
                       nodus_cmt_app_ledger_t **app_out,
                       nodus_witness_v2_block_ctx_t **bctx_out)
{
    *app_out  = NULL;
    *bctx_out = NULL;
    if (gfx_open(g, tag) != 0 || v2x_table_init(g->w) != 0) {
        return -1;
    }
    *app_out  = calloc(1, sizeof(**app_out));
    *bctx_out = calloc(1, sizeof(**bctx_out));
    if (!*app_out || !*bctx_out) {
        return -1;
    }
    if (gfx_doc(g, doc, gvals) != 0 ||
        nodus_cmt_app_ledger_init(*app_out, g->w, doc) != CMT_OK) {
        return -1;
    }
    /* HF-3: the context at the seam's own candidate height, tip + 1 */
    if (cap_ctx_build(g->w, *bctx_out) != 0 || !(*bctx_out)->policy) {
        return -1;
    }
    return 0;
}

/** The CORE domain's per-block unit remainder in a fresh context. */
static uint64_t cap_core_units(const nodus_witness_v2_block_ctx_t *bctx)
{
    size_t d;

    for (d = 0; d < bctx->budget.n_domains; d++) {
        if (bctx->budget.dom[d].domain_id == DNA_DOMAIN_CORE) {
            return bctx->budget.dom[d].remaining_units;
        }
    }
    return 0;
}

/* 48 envelopes of ~60 KB: ~2.9 MB of envelope bytes against the 2 MiB
 * bound — well over it, and each one still inside the fixture's 64 KiB
 * envelope buffer (V2X_ENV_BUF_LEN). */
#define CAP_BYTES_N        48u
#define CAP_BYTES_CALL_LEN 60000u

/**
 * (1) THE HALT, pinned. A request whose envelopes total well over the
 * policy's `max_block_env_bytes` is answered CMT_OK with the
 * fee-descending PREFIX that fits the bound — the HIGHEST fees — in ONE
 * seam run.
 *
 * Every envelope declares EXACTLY its static cost as its reservation
 * ceiling, so per envelope units = bytes - 71 (1 base + 1 op + call +
 * 1 auth, against 43 + 30 + call + 1 wire bytes): whatever fits the
 * byte bound also fits the unit budget, which the case asserts from the
 * real context before relying on it — so the only bound this request
 * can meet is the BYTE bound, and the case proves the trim, not the
 * unit truncation.
 *
 * RED on the unfixed code (reasoned from nodus_witness_cmt_app.c as it
 * was at 4189b97b, :812-944): the only byte trim was `max_tx_bytes`
 * (22 MB here, so all 48 reached the seam); the seam refused with
 * CAPACITY_BYTES at index 0; the loop dropped slot 0 — the HIGHEST fee —
 * and re-ran, until only the k LOWEST fees remained (every envelope is
 * the same 60 074 bytes, so k = floor(2 097 152 / 60 074) = 34 either
 * way). The response then starts with the 34th-lowest fee, not the top
 * one, so the first identity check fails; and the seam ran
 * 48 - 34 + 1 = 15 times, which fails the run-count check too.
 */
static int t_prepare_env_byte_bound(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                         *txs = NULL;
    uint8_t                                *call = NULL;
    uint64_t                                bound, sum, all, ceil_max = 0;
    size_t                                  i, k_fit;

    CHECK(cap_fixture(&g, "envbytes", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    bound = bctx->policy->max_block_env_bytes;
    CHECK(bound > 0, "the SYSTEM policy carries an envelope-byte bound");

    envs = calloc(CAP_BYTES_N, sizeof(*envs));     /* ~3 MiB: heap      */
    txs  = calloc(CAP_BYTES_N, sizeof(*txs));
    call = calloc(1, CAP_BYTES_CALL_LEN);
    CHECK(envs && txs && call, "alloc");

    /* request order = ASCENDING fee (fee 1000 + i), so the fee sort has
     * to reverse it: the highest fee is the LAST request entry. */
    for (i = 0; i < CAP_BYTES_N; i++) {
        uint64_t st = 0;

        memset(call, 0x5A, CAP_BYTES_CALL_LEN);
        call[0] = (uint8_t)i;                      /* distinct intent   */
        call[1] = 0xC7;
        CHECK(cap_env_build(&envs[i], bctx->policy, call,
                            CAP_BYTES_CALL_LEN, 1, 1000u + i, 0, &st) == 0,
              "a ~60 KB CORE envelope with an exact ceiling");
        if (st > ceil_max) {
            ceil_max = st;
        }
        txs[i].data = envs[i].bytes;
        txs[i].len  = envs[i].len;
    }

    /* the expected answer, from the bound itself: the longest
     * fee-descending prefix whose envelope bytes stay <= bound */
    sum = 0;
    all = 0;
    k_fit = 0;
    for (i = 0; i < CAP_BYTES_N; i++) {
        size_t j = CAP_BYTES_N - 1 - i;            /* fee-descending    */

        all += envs[j].len;
        if (k_fit == i && sum + envs[j].len <= bound) {
            sum += envs[j].len;
            k_fit++;
        }
    }
    CHECK(all > bound, "PREMISE: the request's envelope bytes exceed the "
          "ledger's per-block bound");
    CHECK(k_fit >= 2 && k_fit < CAP_BYTES_N, "PREMISE: a strict, "
          "non-trivial prefix fits");
    CHECK((uint64_t)k_fit * ceil_max <= bctx->budget.global_remaining &&
          (uint64_t)k_fit * ceil_max <= cap_core_units(bctx),
          "PREMISE: the byte-fitting prefix also fits the global AND the "
          "CORE unit budget — the byte bound is the only one in play");

    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = CAP_BYTES_N;
    req.max_tx_bytes = 22020096;                   /* not the binding one */
    memset(&resp, 0, sizeof(resp));
    g_seam_runs = 0;
    CHECK(sqlite3_trace_v2(g.w->db, SQLITE_TRACE_STMT, seam_run_trace,
                           NULL) == SQLITE_OK, "install the run counter");
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers CMT_OK over a mempool above the byte bound");
    sqlite3_trace_v2(g.w->db, 0, NULL, NULL);

    CHECK(resp.txs_len == k_fit,
          "exactly the fee-descending prefix that fits the bound is kept");
    sum = 0;
    for (i = 0; i < resp.txs_len; i++) {
        CHECK(resp.txs[i].data == envs[CAP_BYTES_N - 1 - i].bytes,
              "slot i holds the i-th HIGHEST fee — the top fees survive, "
              "they are not the ones thrown away");
        sum += resp.txs[i].len;
    }
    CHECK(sum <= bound, "the proposal's envelope bytes are within the bound");
    CHECK(SEAM_RUNS() == 1,
          "ONE seam run: the byte trim happened before the seam, so the "
          "seam accepted the first batch it saw (the unfixed loop ran it "
          "once per dropped envelope)");

    free(call);
    free(txs);
    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/* (2)'s shape: twelve small envelopes each declaring 300 000 units, so
 * floor(NODUS_V2_GLOBAL_UNIT_BUDGET / 300 000) of them reserve and the
 * next one is a CAPACITY_UNITS refusal at that slot; plus one POISON
 * envelope declaring more units than the whole block budget. */
#define CAP_UNITS_N       12u
#define CAP_UNITS_CEILING 300000ull
#define CAP_UNITS_POISON  3000000ull

/**
 * (2) The UNIT budget, applied by the pack. The poison (fee 100 over
 * 3 000 000 units — the higher fee per unit, so it sorts first) alone
 * exceeds the whole unit budget; the twelve (fee 7 over 300 000, a tie —
 * request order kept) fit floor(budget / 300 000) = 6 times. The kept
 * set is those six, in request order, without the poison.
 *
 * History: 0.19.77 took three seam runs here (poison dropped at slot 0,
 * one truncation, clean; the unfixed loop before it took eight).
 * CHECKTX-P1 round 2 moved the reservation INTO the pack (the seam's own
 * `dna_meter_reserve`, skipping what does not fit), so the seam runs
 * ONCE — which is what this case now pins (RED on round 1: 3 runs).
 */
static int t_prepare_units_truncate(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                          txs[CAP_UNITS_N + 1];
    uint8_t                                 call[64];
    uint64_t                                fit, st = 0;
    size_t                                  i;

    CHECK(cap_fixture(&g, "unitstrunc", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    envs = calloc(CAP_UNITS_N + 1, sizeof(*envs));
    CHECK(envs != NULL, "alloc");

    for (i = 0; i < CAP_UNITS_N; i++) {
        memset(call, 0x33, sizeof(call));
        call[0] = (uint8_t)i;
        CHECK(cap_env_build(&envs[i], bctx->policy, call, sizeof(call), 1,
                            7, CAP_UNITS_CEILING, &st) == 0,
              "a small envelope declaring 300 000 units");
        CHECK(st <= CAP_UNITS_CEILING, "its static cost is under that");
        txs[i].data = envs[i].bytes;
        txs[i].len  = envs[i].len;
    }
    memset(call, 0x44, sizeof(call));
    CHECK(cap_env_build(&envs[CAP_UNITS_N], bctx->policy, call, sizeof(call),
                        1, 100, CAP_UNITS_POISON, NULL) == 0,
          "the poison envelope");
    txs[CAP_UNITS_N].data = envs[CAP_UNITS_N].bytes;   /* LAST in the   */
    txs[CAP_UNITS_N].len  = envs[CAP_UNITS_N].len;     /* request order */

    fit = bctx->budget.global_remaining / CAP_UNITS_CEILING;
    CHECK(CAP_UNITS_POISON > bctx->budget.global_remaining,
          "PREMISE: the poison alone exceeds the whole unit budget");
    CHECK(fit >= 1 && fit < CAP_UNITS_N, "PREMISE: the twelve do not all "
          "fit the unit budget, some do");
    CHECK(fit * st <= cap_core_units(bctx), "PREMISE: the CORE domain "
          "quota is not the binding one");

    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = CAP_UNITS_N + 1;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    g_seam_runs = 0;
    CHECK(sqlite3_trace_v2(g.w->db, SQLITE_TRACE_STMT, seam_run_trace,
                           NULL) == SQLITE_OK, "install the run counter");
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    sqlite3_trace_v2(g.w->db, 0, NULL, NULL);

    CHECK(resp.txs_len == fit, "truncated to the prefix the unit budget "
          "fits");
    for (i = 0; i < resp.txs_len; i++) {
        CHECK(resp.txs[i].data == envs[i].bytes,
              "the prefix, in request order (a fee tie), without the "
              "poison");
    }
    CHECK(SEAM_RUNS() == 1, "ONE seam run: the pack reserved the units "
          "itself (CHECKTX-P1 round 2), skipping the poison and every "
          "envelope the budget no longer had room for");

    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * (3) ENTRY_INVALID still drops ONLY the offender. The middle-fee
 * envelope names runtime_op 8, which the committed SYSTEM policy does
 * not price (ops 1..7 only, nodus_witness_runtime.c `sys_policy_build`):
 * its plan is refused (meter status OP_WEIGHT) — a property of its
 * bytes, not of a full block. The other two survive, in fee order.
 * Since CHECKTX-P1 round 2 the PACK makes that refusal itself (its
 * `dna_meter_reserve` is the seam's), so the offender never reaches the
 * seam: ONE run (round 1 and 0.19.77: two — the seam's ENTRY_INVALID,
 * then clean). The seam's own ENTRY_INVALID → exclude → repack path is
 * pinned by `t_prepare_cc_refused_packs_rest` (c), a duplicate.
 */
static int t_prepare_entry_invalid_only(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                          txs[3];
    uint8_t                                 call[64];

    CHECK(cap_fixture(&g, "entryinv", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    envs = calloc(3, sizeof(*envs));
    CHECK(envs != NULL, "alloc");

    memset(call, 0x11, sizeof(call));
    CHECK(cap_env_build(&envs[0], bctx->policy, call, sizeof(call), 1, 9, 0,
                        NULL) == 0, "fee 9, priced op");
    memset(call, 0x22, sizeof(call));
    CHECK(cap_env_build(&envs[1], bctx->policy, call, sizeof(call), 8, 7,
                        200000, NULL) == 0, "fee 7, UNPRICED op 8");
    memset(call, 0x33, sizeof(call));
    CHECK(cap_env_build(&envs[2], bctx->policy, call, sizeof(call), 1, 5, 0,
                        NULL) == 0, "fee 5, priced op");
    /* request order [fee 5, fee 7 (invalid), fee 9] */
    txs[0].data = envs[2].bytes; txs[0].len = envs[2].len;
    txs[1].data = envs[1].bytes; txs[1].len = envs[1].len;
    txs[2].data = envs[0].bytes; txs[2].len = envs[0].len;

    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = 3;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    g_seam_runs = 0;
    CHECK(sqlite3_trace_v2(g.w->db, SQLITE_TRACE_STMT, seam_run_trace,
                           NULL) == SQLITE_OK, "install the run counter");
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    sqlite3_trace_v2(g.w->db, 0, NULL, NULL);

    CHECK(resp.txs_len == 2, "only the offender is dropped");
    CHECK(resp.txs[0].data == envs[0].bytes, "fee 9 first");
    CHECK(resp.txs[1].data == envs[2].bytes,
          "fee 5 second — the entry AFTER the offender was not truncated "
          "away with it");
    CHECK(SEAM_RUNS() == 1, "ONE seam run: the pack excluded the "
          "unpriceable envelope itself");

    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/* ══ CHECKTX-P1 — CheckTx parity with the apply lane, the pending
 * conflict set, the light recheck, and PrepareProposal's F1/F2/F6 ═══
 *
 * Every case below drives the REAL row (`nodus_cmt_app_check_tx` /
 * `nodus_cmt_app_prepare_proposal`) and uses NO symbol this package adds,
 * so the file builds against 84f331f3 too and each case can be run RED
 * there. What each is RED on is stated in its own comment. The scripted
 * cases use v2_exec_fixture.h's runtime table, whose CORE leg "spends" by
 * DELETEing a `utxo_set` row (V2X_OP_UTXDEL, PRE_EXISTS — the generic
 * shape of every input spend). */

/** CheckTx over one request of `type`; `*code` receives the answer's
 *  code (0 admitted). @return 0 served / -1 the row did not answer OK. */
static int ckt_check_log(nodus_cmt_app_ledger_t *app, const uint8_t *bytes,
                         size_t len, cmt_mem_check_tx_type_t type,
                         uint32_t *code, char log[CMT_MEM_CHECK_TX_LOG_MAX])
{
    cmt_mem_request_check_tx_t  req;
    cmt_mem_response_check_tx_t res;

    memset(&req, 0, sizeof(req));
    memset(&res, 0, sizeof(res));
    req.tx     = bytes;
    req.tx_len = len;
    req.type   = type;
    if (nodus_cmt_app_check_tx(app, &req, &res) != CMT_OK) {
        return -1;
    }
    *code = res.code;
    if (log) {
        memcpy(log, res.log, CMT_MEM_CHECK_TX_LOG_MAX);
    }
    return 0;
}

static int ckt_check(nodus_cmt_app_ledger_t *app, const uint8_t *bytes,
                     size_t len, cmt_mem_check_tx_type_t type,
                     uint32_t *code)
{
    return ckt_check_log(app, bytes, len, type, code, NULL);
}

/** One committed CORE `utxo_set` row keyed by 64 bytes of `tag` — the
 *  row the scripted adapter's probe reads (nullifier + domain_id,
 *  v2_exec_fixture.h `v2x_utxo_row`). AMOUNT 0 (round 2b): the CORE
 *  conservation invariant sums utxo_set amounts against the supply
 *  counters (nodus_witness_v2_claims.c `nodus_rt_core_invariant`), so a
 *  planted nonzero row makes committed state non-conserving and the
 *  apply engine's PRE-APPLY supply gate refuses the next block
 *  (nodus_witness_v2_apply.c, phase 2). A zero-amount row adds nothing
 *  to that sum — the same device t_byte_bound_prepare_and_process uses
 *  for its CREATEd rows — and the probe only needs the row to EXIST.
 *  @return 0 / -1. */
static int ckt_row_insert(nodus_witness_t *w, uint8_t tag)
{
    sqlite3_stmt *st = NULL;
    uint8_t       key[64], txh[64];
    int           rc;

    memset(key, tag, sizeof(key));
    memset(txh, tag, sizeof(txh));
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, unlock_block, "
            "domain_id) VALUES (?1, 'fp', 0, zeroblob(64), ?2, 0, 1, 0, 0, "
            "?3)", -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, txh, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)DNA_DOMAIN_CORE);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/** Does the CORE row keyed by 64 bytes of `tag` exist? @return 1/0/-1. */
static int ckt_row_exists(nodus_witness_t *w, uint8_t tag)
{
    sqlite3_stmt *st = NULL;
    uint8_t       key[64];
    int           rc;

    memset(key, tag, sizeof(key));
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM utxo_set WHERE nullifier = ?1 AND domain_id = ?2",
            -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)DNA_DOMAIN_CORE);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 1 : (rc == SQLITE_DONE ? 0 : -1);
}

/** Delete row `tag` (a block spending it). @return rows deleted / -1. */
static int ckt_row_delete(nodus_witness_t *w, uint8_t tag)
{
    sqlite3_stmt *st = NULL;
    uint8_t       key[64];
    int           rc;

    memset(key, tag, sizeof(key));
    if (sqlite3_prepare_v2(w->db,
            "DELETE FROM utxo_set WHERE nullifier = ?1 AND domain_id = ?2",
            -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)DNA_DOMAIN_CORE);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? sqlite3_changes(w->db) : -1;
}

/* Every fixture chain here has NO block row, so its tip is 0 and the
 * mempool lifetime rule (nodus_types.h NODUS_CMT_APP_MAX_EXPIRY_AHEAD,
 * round 2) admits an expiry in [1, 100]: the full window. */
#define CKT_EXPIRY ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD)

/** A scripted CORE envelope: one leg (runtime_op 1, owned and priced)
 *  whose result is exactly `effs` (canonical order — the caller's job).
 *  @return 0 / -1. */
static int ckt_effs_env(v2x_env_t *e, const dna_effect_in_t *effs,
                        uint16_t n_effs, uint64_t fee, uint64_t ceiling,
                        uint64_t expiry)
{
    uint8_t   res[1024], script[1200];
    size_t    rl = 0;
    uint32_t  sl;
    v2x_leg_t leg;

    if (v2x_effres(res, sizeof(res), effs, n_effs, &rl) != 0) {
        return -1;
    }
    sl = v2x_script_build(script, sizeof(script), NULL, 0, res, rl);
    if (sl == 0) {
        return -1;
    }
    memset(&leg, 0, sizeof(leg));
    leg.domain_id        = DNA_DOMAIN_CORE;
    leg.runtime_op       = 1;
    leg.call             = script;
    leg.call_len         = sl;
    leg.max_effects      = 4;
    leg.max_effect_bytes = 2048;
    return v2x_env_build_ex(e, ceiling, expiry, fee, &leg, 1);
}

/** A scripted CORE "spend" with an explicit expiry: its result DELETEs
 *  row `tag` with PRE_EXISTS. `fee` makes distinct intents over the same
 *  row; `ceiling` is the declared unit ceiling. @return 0 / -1. */
static int ckt_spend_env_x(v2x_env_t *e, uint8_t tag, uint64_t fee,
                           uint64_t ceiling, uint64_t expiry)
{
    uint8_t         key[64];
    dna_effect_in_t eff;

    memset(key, tag, sizeof(key));
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id       = V2X_OP_UTXDEL;
    eff.hdr.effect_kind = DNA_EFFECT_DELETE;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
    eff.hdr.key_len     = 64;
    eff.key             = key;
    return ckt_effs_env(e, &eff, 1, fee, ceiling, expiry);
}

/** ckt_spend_env_x at the full lifetime window (CKT_EXPIRY). */
static int ckt_spend_env(v2x_env_t *e, uint8_t tag, uint64_t fee,
                         uint64_t ceiling)
{
    return ckt_spend_env_x(e, tag, fee, ceiling, CKT_EXPIRY);
}

/** wire_id and intent_id of one envelope at the candidate height, from
 *  the committed context table (`bctx`). @return 0 / -1. */
static int ckt_ids(const gfx_t *g, const nodus_witness_v2_block_ctx_t *bctx,
                   const uint8_t *bytes, size_t len,
                   uint8_t wire[64], uint8_t intent[64])
{
    dna_env_view_t       view;
    dna_env_leg_ctx_t    lctx[DNA_ENV_MAX_LEGS];
    dna_env_preflight_t *pf;
    uint16_t             l;
    size_t               k;
    int                  rc = -1;

    memset(&view, 0, sizeof(view));
    if (dna_env_decode(bytes, len, &view) != 0) {
        return -1;
    }
    for (l = 0; l < view.leg_count; l++) {
        for (k = 0; k < bctx->n_rulesets; k++) {
            if (bctx->rulesets[k].domain_id == view.leg[l].domain_id) {
                lctx[l] = bctx->rulesets[k];
                break;
            }
        }
        if (k == bctx->n_rulesets) {
            return -1;
        }
    }
    pf = calloc(1, sizeof(*pf));
    if (!pf) {
        return -1;
    }
    if (dna_env_preflight(bytes, len, g->chain32, 1, lctx, view.leg_count,
                          pf) == DNA_ENV_PF_OK) {
        memcpy(wire, pf->wire_id, 64);
        memcpy(intent, pf->intent_id, 64);
        rc = 0;
    }
    free(pf);
    return rc;
}

/* ── the auth-hook COUNTER: the light recheck's only observable ───────
 * The runtime table's `auth` hooks are wrapped so every verification the
 * engine asks for is counted and then answered by the ORIGINAL hook —
 * nothing about the verdict changes. File-scope for the same reason as
 * g_seam_runs: the table outlives the case. */
static int              g_ckt_auth_calls = 0;
static nodus_rt_auth_fn g_ckt_auth_orig[2];
static nodus_domain_runtime_t g_ckt_table[2];

static int ckt_auth0(const nodus_domain_runtime_t *rt,
                     const dna_env_view_t *env, uint16_t leg,
                     const nodus_rt_exec_ctx_t *ctx,
                     nodus_rt_auth_verdict_t *out)
{
    g_ckt_auth_calls++;
    return g_ckt_auth_orig[0](rt, env, leg, ctx, out);
}

static int ckt_auth1(const nodus_domain_runtime_t *rt,
                     const dna_env_view_t *env, uint16_t leg,
                     const nodus_rt_exec_ctx_t *ctx,
                     nodus_rt_auth_verdict_t *out)
{
    g_ckt_auth_calls++;
    return g_ckt_auth_orig[1](rt, env, leg, ctx, out);
}

/** Install a counting copy of `src` (the scripted table or the builtin
 *  one) as the handle's runtime-table override. @return 0 / -1. */
static int ckt_counting_table(nodus_witness_t *w,
                              const nodus_domain_runtime_t *src, size_t n)
{
    if (!src || n != 2) {
        return -1;
    }
    memcpy(g_ckt_table, src, sizeof(g_ckt_table));
    g_ckt_auth_orig[0] = g_ckt_table[0].auth;
    g_ckt_auth_orig[1] = g_ckt_table[1].auth;
    if (!g_ckt_auth_orig[0] || !g_ckt_auth_orig[1]) {
        return -1;
    }
    g_ckt_table[0].auth = ckt_auth0;
    g_ckt_table[1].auth = ckt_auth1;
    w->v2_runtime_table   = g_ckt_table;
    w->v2_runtime_table_n = 2;
    g_ckt_auth_calls = 0;
    return 0;
}

/**
 * CheckTx runs the item's own stages (red-team F1 class, CheckTx side):
 * an envelope whose declared unit ceiling is BELOW its static cost, one
 * whose ceiling EXCEEDS the whole block budget, and one that spends a row
 * that does not exist are all REFUSED; the same spend over an existing
 * row, correctly declared, is ADMITTED (so the refusals are not blanket).
 *
 * RED on 84f331f3: CheckTx ran only the admission lane (decode, ruleset,
 * preflight, wire_id, committed intent) and the scripted auth stub —
 * no reservation, no execution — so all three were admitted.
 */
static int t_check_tx_dry_run(void)
{
    gfx_t                         g;
    cmt_genesis_doc_t             doc;
    cmt_genesis_validator_t       gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t       *app = NULL;
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    v2x_env_t                    *e = NULL;
    uint32_t                      code = 0;

    CHECK(cap_fixture(&g, "ckt_dry", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    e = calloc(4, sizeof(*e));
    CHECK(e != NULL, "alloc");
    CHECK(ckt_row_insert(g.w, 0xA1) == 0 && ckt_row_insert(g.w, 0xA2) == 0,
          "two committed CORE rows");
    CHECK(CAP_UNITS_POISON > bctx->budget.global_remaining,
          "PREMISE: the over-budget ceiling exceeds the whole unit budget");

    CHECK(ckt_spend_env(&e[0], 0xA1, 3, TEST_APP_ENV_CEILING) == 0,
          "a correctly declared spend of an existing row");
    CHECK(ckt_spend_env(&e[1], 0xA2, 3, 1) == 0,
          "a spend declaring 1 unit — below its own static cost");
    CHECK(ckt_spend_env(&e[2], 0xA2, 4, CAP_UNITS_POISON) == 0,
          "a spend declaring more units than the whole block budget");
    CHECK(ckt_spend_env(&e[3], 0xA3, 3, TEST_APP_ENV_CEILING) == 0,
          "a spend of a row that was never committed");

    CHECK(ckt_check(app, e[0].bytes, e[0].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the correct spend is admitted");
    CHECK(ckt_check(app, e[1].bytes, e[1].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "a ceiling below the static cost is refused at CheckTx");
    CHECK(ckt_check(app, e[2].bytes, e[2].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "a ceiling above the block budget is refused at CheckTx");
    CHECK(ckt_check(app, e[3].bytes, e[3].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "a spend of an absent row is refused at CheckTx (execution)");

    free(e);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * The red-team F1 poison at CheckTx, on the REAL runtime: a fully
 * authorized SYSTEM CHAIN_CONFIG envelope (real committee approvals)
 * declaring `res_max_total_units` 0 is REFUSED; the same envelope with
 * its real ceiling is admitted.
 *
 * RED on 84f331f3: the poison passed the admission lane and the
 * signature check (both are about the bytes and the committee, not the
 * ceiling) and was admitted — the seam refused it later, every block.
 */
static int t_check_tx_cc_poison(void)
{
    gfx_t                   g;
    cmt_genesis_doc_t       doc;
    cmt_genesis_validator_t gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t *app;
    test_env_t              good, poison;
    uint32_t                code = 0;

    CHECK(gfx_open(&g, "ckt_ccpoison") == 0, "version-3 fixture");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(build_cc_env(g.w, g.chain32, 0xC001, &good) == 0, "a real "
          "chain_config envelope");
    CHECK(build_cc_env_units(g.w, g.chain32, 0xC002, 0, &poison) == 0,
          "the same shape declaring 0 units");

    CHECK(ckt_check(app, poison.bytes, poison.len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "the 0-unit chain_config is refused at CheckTx");
    CHECK(ckt_check(app, good.bytes, good.len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the correctly declared one is admitted");

    free(good.bytes);
    free(poison.bytes);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * The PENDING CONFLICT SET: two envelopes spending the SAME row (two
 * intents — different fees) — the second is REFUSED; two envelopes that
 * are ONE intent under two wire ids (only the authorization byte
 * differs — PREMISE-checked below) — the second is REFUSED; the very
 * same bytes re-checked are still ADMITTED (the key's owner is the entry
 * itself — the mempool's own "already there" path, cmt_mem.c
 * mem_res_cb_first_time).
 *
 * RED on 84f331f3: no pending set existed — both double spends were
 * admitted (the 2026-09-25 live observation), and the DUP_INTENT variant
 * too (the scripted auth stub accepts any non-empty authorization).
 */
static int t_check_tx_conflicts(void)
{
    gfx_t                         g;
    cmt_genesis_doc_t             doc;
    cmt_genesis_validator_t       gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t       *app = NULL;
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    v2x_env_t                    *e = NULL;
    uint8_t                       w0[64], i0[64], w1[64], i1[64];
    uint32_t                      code = 0;

    CHECK(cap_fixture(&g, "ckt_conf", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    e = calloc(4, sizeof(*e));
    CHECK(e != NULL, "alloc");
    CHECK(ckt_row_insert(g.w, 0xB1) == 0 && ckt_row_insert(g.w, 0xB2) == 0,
          "two committed CORE rows");

    /* the double spend */
    CHECK(ckt_spend_env(&e[0], 0xB1, 3, TEST_APP_ENV_CEILING) == 0 &&
          ckt_spend_env(&e[1], 0xB1, 4, TEST_APP_ENV_CEILING) == 0,
          "two spends of ONE row, different intents");
    CHECK(ckt_check(app, e[0].bytes, e[0].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the first spend is admitted");
    CHECK(ckt_check(app, e[1].bytes, e[1].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "the second spend of the same row is refused");
    CHECK(ckt_check(app, e[0].bytes, e[0].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the SAME bytes checked again are not a conflict with themselves");

    /* one intent, two wire ids */
    CHECK(ckt_spend_env(&e[2], 0xB2, 5, TEST_APP_ENV_CEILING) == 0,
          "a spend of the second row");
    memcpy(&e[3], &e[2], sizeof(e[3]));
    e[3].bytes[e[3].len - 1] ^= 0x01;    /* the 1-byte auth stub, last */
    CHECK(ckt_ids(&g, bctx, e[2].bytes, e[2].len, w0, i0) == 0 &&
          ckt_ids(&g, bctx, e[3].bytes, e[3].len, w1, i1) == 0,
          "both preflight");
    CHECK(memcmp(i0, i1, 64) == 0 && memcmp(w0, w1, 64) != 0,
          "PREMISE: ONE intent under TWO wire ids");
    CHECK(ckt_check(app, e[2].bytes, e[2].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the first realization is admitted");
    CHECK(ckt_check(app, e[3].bytes, e[3].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "a second realization of the same intent is refused");

    free(e);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * K signature-variants of ONE claim (ML-DSA-87 signing is randomized —
 * shared/crypto/sign/dsa/config.h:6 — so two signings give two byte
 * strings, PREMISE-checked): distinct entry ids, ONE nullifier. The
 * first is admitted, the second REFUSED; a claim on another leaf is
 * admitted.
 *
 * RED on 84f331f3: both variants were admitted (red-team F5).
 */
static int t_check_tx_claim_variants(void)
{
    gfx_t                   g;
    cmt_genesis_doc_t       doc;
    cmt_genesis_validator_t gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t *app;
    uint8_t                *c1 = NULL, *c2 = NULL, *c3 = NULL;
    size_t                  l1 = 0, l2 = 0, l3 = 0;
    uint32_t                code = 0;

    CHECK(gfx_open_n(&g, "ckt_claimvar", 2) == 0,
          "version-3 fixture, two distribution leaves");
    app = calloc(1, sizeof(*app));
    c1 = malloc(DNA_CLAIM_MAX_WIRE);
    c2 = malloc(DNA_CLAIM_MAX_WIRE);
    c3 = malloc(DNA_CLAIM_MAX_WIRE);
    CHECK(app && c1 && c2 && c3, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(build_claim_n(&g, 2, 0, c1, DNA_CLAIM_MAX_WIRE, &l1) == 0 &&
          build_claim_n(&g, 2, 0, c2, DNA_CLAIM_MAX_WIRE, &l2) == 0 &&
          build_claim_n(&g, 2, 1, c3, DNA_CLAIM_MAX_WIRE, &l3) == 0,
          "two signings of leaf 0, one of leaf 1");
    CHECK(l1 != l2 || memcmp(c1, c2, l1) != 0,
          "PREMISE: the two signings of leaf 0 are different bytes");

    CHECK(ckt_check(app, c1, l1, CMT_MEM_CHECK_TX_TYPE_NEW, &code) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK, "the first claim is admitted");
    CHECK(ckt_check(app, c2, l2, CMT_MEM_CHECK_TX_TYPE_NEW, &code) == 0 &&
          code != CMT_MEM_CODE_TYPE_OK,
          "a signature-variant of the SAME claim is refused");
    CHECK(ckt_check(app, c3, l3, CMT_MEM_CHECK_TX_TYPE_NEW, &code) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK, "a claim on another leaf is "
          "admitted");

    free(c1);
    free(c2);
    free(c3);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * COMMIT + RECHECK, and the LIGHT recheck (auth_kind 1). Two spends of
 * two rows are admitted (two auth verifications). A "block" then spends
 * row A (committed through the application's own Commit row, inside a
 * host-style transaction). RECHECK of the spend of A is REFUSED — and
 * its auth was NOT re-verified (the cache answered); RECHECK of the
 * spend of B is ADMITTED, again without a re-verification. The pending
 * set was rebuilt by that recheck: a NEW spend of B is refused.
 *
 * RED on 84f331f3: CheckTx ignored the request type and never executed,
 * so the stale spend of A was re-admitted, and every recheck re-ran the
 * auth hook.
 */
static int t_check_tx_recheck_light(void)
{
    gfx_t                         g;
    cmt_genesis_doc_t             doc;
    cmt_genesis_validator_t       gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t       *app = NULL;
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    nodus_abci_response_commit_t  cres;
    v2x_env_t                    *e = NULL;
    uint32_t                      code = 0;

    CHECK(cap_fixture(&g, "ckt_recheck", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    CHECK(ckt_counting_table(g.w, g_v2x_table, 2) == 0,
          "the scripted table, auth hooks counted");
    e = calloc(3, sizeof(*e));
    CHECK(e != NULL, "alloc");
    CHECK(ckt_row_insert(g.w, 0xC1) == 0 && ckt_row_insert(g.w, 0xC2) == 0,
          "two committed CORE rows");
    CHECK(ckt_spend_env(&e[0], 0xC1, 3, TEST_APP_ENV_CEILING) == 0 &&
          ckt_spend_env(&e[1], 0xC2, 3, TEST_APP_ENV_CEILING) == 0 &&
          ckt_spend_env(&e[2], 0xC2, 7, TEST_APP_ENV_CEILING) == 0,
          "spend A, spend B, and a second spend of B");

    CHECK(ckt_check(app, e[0].bytes, e[0].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK &&
          ckt_check(app, e[1].bytes, e[1].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "both spends admitted");
    CHECK(g_ckt_auth_calls == 2, "two NEW admissions verified two legs");

    /* the block: row A spent, then the application's Commit */
    CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0, "the host's BEGIN");
    CHECK(ckt_row_delete(g.w, 0xC1) == 1, "row A spent (exactly one row)");
    memset(&cres, 0, sizeof(cres));
    CHECK(nodus_cmt_app_commit(app, &cres) == CMT_OK, "Commit");

    /* the recheck, in mempool FIFO order */
    CHECK(ckt_check(app, e[0].bytes, e[0].len,
                    CMT_MEM_CHECK_TX_TYPE_RECHECK, &code) == 0 &&
          code != CMT_MEM_CODE_TYPE_OK,
          "the spend of the spent row is dropped at recheck");
    CHECK(ckt_check(app, e[1].bytes, e[1].len,
                    CMT_MEM_CHECK_TX_TYPE_RECHECK, &code) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK,
          "the spend of the live row survives the recheck");
    CHECK(g_ckt_auth_calls == 2, "the recheck re-verified NO kind-1 "
          "signature (the cache answered for the same wire ids)");
    CHECK(ckt_check(app, e[2].bytes, e[2].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "the rebuilt pending set refuses a second spend of B");

    free(e);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * auth_kind 2 is NEVER taken from the cache: a real chain_config
 * (committee approvals) admitted NEW and then RECHECKed runs the auth
 * hook BOTH times, on the builtin runtime (auth hooks counted, verdicts
 * the real hook's). A regression pin, not a RED case: 84f331f3 also
 * verified it every time.
 */
static int t_check_tx_recheck_kind2(void)
{
    gfx_t                          g;
    cmt_genesis_doc_t              doc;
    cmt_genesis_validator_t        gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t        *app;
    const nodus_domain_runtime_t  *bt;
    size_t                         nbt = 0;
    test_env_t                     env;
    uint32_t                       code = 0;

    CHECK(gfx_open(&g, "ckt_kind2") == 0, "version-3 fixture");
    bt = nodus_runtime_builtin_table(&nbt);
    CHECK(ckt_counting_table(g.w, bt, nbt) == 0,
          "the builtin table, auth hooks counted");
    app = calloc(1, sizeof(*app));
    CHECK(app != NULL, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(build_cc_env(g.w, g.chain32, 0xC201, &env) == 0, "a real "
          "chain_config envelope");

    CHECK(ckt_check(app, env.bytes, env.len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK, "admitted");
    CHECK(g_ckt_auth_calls == 1, "one kind-2 leg verified at admission");
    CHECK(ckt_check(app, env.bytes, env.len, CMT_MEM_CHECK_TX_TYPE_RECHECK,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "still admitted at recheck");
    CHECK(g_ckt_auth_calls == 2, "the kind-2 leg was verified AGAIN");

    free(env.bytes);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/* ── general multisig (decision 2026-09-29-general-multisig.md, design
 * F1.3): the CheckTx recheck cache covers auth_kind 3 ─────────────────
 * The scripted CORE auth stub (v2x_auth) never fills multisig facts, and
 * the engine only reuses a kind-3 verdict that carries 1..7 of them
 * (nodus_witness_v2_apply.c env_authorize_legs) — so this case answers a
 * kind-3 leg with the stub's verdict PLUS one satisfied descriptor
 * address, exactly the shape the real hook produces (rt_native.c
 * rtn_auth_msig). It is counted like the other two hooks. */
static int ckt_auth_msig1(const nodus_domain_runtime_t *rt,
                          const dna_env_view_t *env, uint16_t leg,
                          const nodus_rt_exec_ctx_t *ctx,
                          nodus_rt_auth_verdict_t *out)
{
    int rc;

    g_ckt_auth_calls++;
    rc = g_ckt_auth_orig[1](rt, env, leg, ctx, out);
    if (rc == 0 &&
        env->leg[leg].auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1) {
        out->n_msig = 1;
        out->msig_satisfied[0] = 1;
        memset(out->msig_addr[0], 0x3C, 64);
    }
    return rc;
}

/** ckt_spend_env's scripted CORE spend, carried under auth_kind 3 (a
 *  1-byte stub auth blob — the scripted hook reads no structure).
 *  @return 0 / -1. */
static int ckt_spend_env_kind3(v2x_env_t *e, uint8_t tag, uint64_t fee)
{
    static const uint8_t auth_stub[1] = { 0xAB };
    uint8_t          key[64], res[1024], script[1200];
    size_t           rl = 0;
    uint32_t         sl;
    dna_effect_in_t  eff;
    dna_env_leg_in_t in;
    dna_env_in_t     env;

    memset(key, tag, sizeof(key));
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id       = V2X_OP_UTXDEL;
    eff.hdr.effect_kind = DNA_EFFECT_DELETE;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
    eff.hdr.key_len     = 64;
    eff.key             = key;
    if (v2x_effres(res, sizeof(res), &eff, 1, &rl) != 0) {
        return -1;
    }
    sl = v2x_script_build(script, sizeof(script), NULL, 0, res, rl);
    if (sl == 0) {
        return -1;
    }
    memset(&in, 0, sizeof(in));
    in.hdr.domain_id            = DNA_DOMAIN_CORE;
    in.hdr.runtime_op           = 1;
    in.hdr.ruleset_version      = v2x_ruleset_version_for(DNA_DOMAIN_CORE);
    in.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    in.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
    in.hdr.call_len             = sl;
    in.hdr.auth_len             = 1;
    in.hdr.res_max_effects      = 4;
    in.hdr.res_max_effect_bytes = 2048;
    in.call_data                = script;
    in.auth_data                = auth_stub;
    memset(&env, 0, sizeof(env));
    env.expiry_height       = CKT_EXPIRY;
    env.fee_amount          = fee;
    env.res_max_total_units = TEST_APP_ENV_CEILING;
    env.leg_count           = 1;
    env.legs                = &in;
    return dna_env_encode(&env, e->bytes, sizeof(e->bytes), &e->len);
}

/**
 * The LIGHT recheck covers auth_kind 3 (general multisig, F1.3): a
 * kind-3 spend admitted NEW is verified once; after a Commit that spends
 * an unrelated row, its RECHECK is admitted WITHOUT a re-verification —
 * the cache (keyed by the wire_id, which commits the auth bytes) answered
 * with the kind-3 verdict, descriptor facts included. A second kind-3
 * spend of the row the block consumed is dropped at recheck, also from
 * the cache. Control: the first NEW admission DID verify (the counter
 * moved), so the zero-delta at recheck is the cache, not a skipped hook.
 *
 * HOW IT CAN LIE: the auth hook is SCRIPTED (ckt_auth_msig1 fills the
 * facts the real hook would); this proves the cache store/reuse path for
 * kind 3, not signature or descriptor verification (test_v2_native.c
 * §multisig drives the real hook).
 */
static int t_check_tx_recheck_kind3(void)
{
    gfx_t                         g;
    cmt_genesis_doc_t             doc;
    cmt_genesis_validator_t       gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t       *app = NULL;
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    nodus_abci_response_commit_t  cres;
    v2x_env_t                    *e = NULL;
    uint32_t                      code = 0;

    CHECK(cap_fixture(&g, "ckt_recheck_k3", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    CHECK(ckt_counting_table(g.w, g_v2x_table, 2) == 0,
          "the scripted table, auth hooks counted");
    CHECK((g_ckt_table[1].allowed_auth_kinds &
           NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1)) != 0,
          "PREMISE: CORE's (builtin-copied) allowlist admits kind 3");
    g_ckt_table[1].auth = ckt_auth_msig1;
    e = calloc(2, sizeof(*e));
    CHECK(e != NULL, "alloc");
    CHECK(ckt_row_insert(g.w, 0xD1) == 0 && ckt_row_insert(g.w, 0xD2) == 0,
          "two committed CORE rows");
    CHECK(ckt_spend_env_kind3(&e[0], 0xD1, 3) == 0 &&
          ckt_spend_env_kind3(&e[1], 0xD2, 3) == 0,
          "two kind-3 spends");

    CHECK(ckt_check(app, e[0].bytes, e[0].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK &&
          ckt_check(app, e[1].bytes, e[1].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "both kind-3 spends admitted");
    CHECK(g_ckt_auth_calls == 2, "two NEW admissions verified two legs");

    CHECK(run_sql(g.w->db, "BEGIN IMMEDIATE") == 0, "the host's BEGIN");
    CHECK(ckt_row_delete(g.w, 0xD1) == 1, "row D1 spent (exactly one row)");
    memset(&cres, 0, sizeof(cres));
    CHECK(nodus_cmt_app_commit(app, &cres) == CMT_OK, "Commit");

    CHECK(ckt_check(app, e[0].bytes, e[0].len,
                    CMT_MEM_CHECK_TX_TYPE_RECHECK, &code) == 0 &&
          code != CMT_MEM_CODE_TYPE_OK,
          "the kind-3 spend of the spent row is dropped at recheck");
    CHECK(ckt_check(app, e[1].bytes, e[1].len,
                    CMT_MEM_CHECK_TX_TYPE_RECHECK, &code) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK,
          "the kind-3 spend of the live row survives the recheck");
    CHECK(g_ckt_auth_calls == 2, "the recheck re-verified NO kind-3 leg "
          "(the cache answered for the same wire ids)");

    free(e);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * PrepareProposal, red-team F1: a chain_config candidate the seam refuses
 * ALONE (0 declared units) no longer rides alone. (a) With two ordinary
 * envelopes beside it, both are proposed, fee-descending. (b) With a
 * VALID chain_config behind it (fee tie, request order), the valid one
 * rides alone. (c) Coverage the chain_config change moved here: the drop
 * loop's DUPLICATE path (ERR_DUP → excluded → repacked, two seam runs) —
 * not a RED leg, 84f331f3 handled it the same way.
 *
 * RED on 84f331f3: the fee-first chain_config rode alone unconditionally,
 * the seam refused it, and the proposal was EMPTY in both cases.
 */
static int t_prepare_cc_refused_packs_rest(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    test_env_t                              poison, good;
    cmt_pb_bytes_t                          txs[3];
    uint8_t                                 call[64];

    CHECK(cap_fixture(&g, "ckt_ccprep", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    envs = calloc(2, sizeof(*envs));
    CHECK(envs != NULL, "alloc");
    CHECK(build_cc_env_units(g.w, g.chain32, 0xC301, 0, &poison) == 0,
          "a chain_config declaring 0 units");
    CHECK(build_cc_env(g.w, g.chain32, 0xC302, &good) == 0,
          "a correctly declared chain_config");
    memset(call, 0x61, sizeof(call));
    CHECK(cap_env_build(&envs[0], bctx->policy, call, sizeof(call), 1, 9, 0,
                        NULL) == 0, "fee 9");
    memset(call, 0x62, sizeof(call));
    CHECK(cap_env_build(&envs[1], bctx->policy, call, sizeof(call), 1, 5, 0,
                        NULL) == 0, "fee 5");

    /* (a) [fee 5, poison chain_config, fee 9] */
    txs[0].data = envs[1].bytes; txs[0].len = envs[1].len;
    txs[1].data = poison.bytes;  txs[1].len = poison.len;
    txs[2].data = envs[0].bytes; txs[2].len = envs[0].len;
    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = 3;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == 2, "the refused chain_config is left out and the "
          "other two are packed");
    CHECK(resp.txs[0].data == envs[0].bytes &&
          resp.txs[1].data == envs[1].bytes, "fee-descending");

    /* (b) [poison chain_config, valid chain_config] */
    txs[0].data = poison.bytes; txs[0].len = poison.len;
    txs[1].data = good.bytes;   txs[1].len = good.len;
    req.txs_len = 2;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == 1 && resp.txs[0].data == good.bytes,
          "the valid chain_config rides alone");

    /* (c) the drop loop's DUPLICATE path: the same ordinary envelope
     * twice. The seam names the SECOND as ERR_DUP (nodus_witness_v2_env.c,
     * the wire-level duplicate scan); it is excluded and the batch
     * repacked — one kept, two seam runs. */
    txs[0].data = envs[0].bytes; txs[0].len = envs[0].len;
    txs[1].data = envs[0].bytes; txs[1].len = envs[0].len;
    req.txs_len = 2;
    memset(&resp, 0, sizeof(resp));
    g_seam_runs = 0;
    CHECK(sqlite3_trace_v2(g.w->db, SQLITE_TRACE_STMT, seam_run_trace,
                           NULL) == SQLITE_OK, "install the run counter");
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    sqlite3_trace_v2(g.w->db, 0, NULL, NULL);
    CHECK(resp.txs_len == 1 && resp.txs[0].data == envs[0].bytes &&
          resp.txs[0].len == envs[0].len, "the duplicate is dropped, the "
          "envelope proposed once");
    CHECK(SEAM_RUNS() == 2, "two seam runs: the duplicate refusal, then "
          "clean");

    free(poison.bytes);
    free(good.bytes);
    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * PrepareProposal, red-team F2: the room an unfit candidate would take
 * is FILLED. 48 equal ~60 KB envelopes against the 2 MiB envelope-byte
 * bound (the t_prepare_env_byte_bound shape, k_fit of them fit); the
 * top-ranked one (highest fee per unit: fee 1047 over a 60 000-unit
 * ceiling) names the unpriced runtime_op 8. The answer is the k_fit
 * highest-ranked VALID envelopes — the next one moved into the room.
 *
 * RED on 84f331f3: the byte pre-trim kept the k_fit highest fees
 * INCLUDING the invalid one, the seam dropped it and nothing refilled
 * the room: k_fit - 1 envelopes. RED on round 1 (0.19.78 first cut):
 * the seam refused it and the repack refilled — right answer, TWO seam
 * runs; round 2's pack refuses the unpriceable plan itself (the seam's
 * own `dna_meter_reserve`), so ONE run.
 */
static int t_prepare_refill_after_drop(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                         *txs = NULL;
    uint8_t                                *call = NULL;
    uint64_t                                bound, sum, ceil_max = 0;
    size_t                                  i, k_fit;
    const size_t                            bad = CAP_BYTES_N - 1;

    CHECK(cap_fixture(&g, "ckt_refill", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    bound = bctx->policy->max_block_env_bytes;
    envs = calloc(CAP_BYTES_N, sizeof(*envs));     /* ~3 MiB: heap      */
    txs  = calloc(CAP_BYTES_N, sizeof(*txs));
    call = calloc(1, CAP_BYTES_CALL_LEN);
    CHECK(envs && txs && call, "alloc");

    for (i = 0; i < CAP_BYTES_N; i++) {
        uint64_t st = 0;

        memset(call, 0x5B, CAP_BYTES_CALL_LEN);
        call[0] = (uint8_t)i;
        call[1] = 0xD3;
        if (i == bad) {
            CHECK(cap_env_build(&envs[i], bctx->policy, call,
                                CAP_BYTES_CALL_LEN, 8, 1000u + i, 60000,
                                NULL) == 0,
                  "the top-ranked candidate names the UNPRICED op 8");
        } else {
            CHECK(cap_env_build(&envs[i], bctx->policy, call,
                                CAP_BYTES_CALL_LEN, 1, 1000u + i, 0,
                                &st) == 0, "a ~60 KB priced envelope");
            if (st > ceil_max) {
                ceil_max = st;
            }
        }
        txs[i].data = envs[i].bytes;
        txs[i].len  = envs[i].len;
    }
    CHECK(envs[bad].len == envs[0].len, "PREMISE: every envelope is the "
          "same length");
    CHECK((uint64_t)(1000u + bad) * ceil_max >
              (uint64_t)(1000u + bad - 1) * 60000u,
          "PREMISE: the unpriced one ranks FIRST by fee per unit as well as "
          "by fee");
    k_fit = (size_t)(bound / envs[0].len);
    CHECK(k_fit >= 2 && k_fit + 1 < CAP_BYTES_N, "PREMISE: a strict, "
          "non-trivial prefix fits, with valid candidates beyond it");
    CHECK((uint64_t)k_fit * ceil_max <= bctx->budget.global_remaining &&
          (uint64_t)k_fit * ceil_max <= cap_core_units(bctx),
          "PREMISE: the unit budgets are not the binding bound");

    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = CAP_BYTES_N;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    g_seam_runs = 0;
    CHECK(sqlite3_trace_v2(g.w->db, SQLITE_TRACE_STMT, seam_run_trace,
                           NULL) == SQLITE_OK, "install the run counter");
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    sqlite3_trace_v2(g.w->db, 0, NULL, NULL);

    CHECK(resp.txs_len == k_fit, "the byte window is FULL again after the "
          "offender was dropped");
    sum = 0;
    for (i = 0; i < resp.txs_len; i++) {
        CHECK(resp.txs[i].data == envs[bad - 1 - i].bytes,
              "the k_fit highest-fee VALID envelopes, fee-descending");
        sum += resp.txs[i].len;
    }
    CHECK(sum <= bound, "within the envelope-byte bound");
    CHECK(SEAM_RUNS() == 1, "ONE seam run: the pack excluded the "
          "unpriceable top candidate and filled its room");

    free(call);
    free(txs);
    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * PrepareProposal, red-team F6: CLAIMS are not cut by the ENVELOPE-byte
 * window. 48 ~60 KB envelopes (more than the window holds) and one
 * genuinely admissible claim behind them (a claim's ordering key is 0,
 * so it sorts after every paying envelope). The answer is the k_fit
 * highest-fee envelopes AND the claim.
 *
 * RED on 84f331f3: the pre-trim STOPPED at the first envelope over the
 * window, which cut the claim behind it — k_fit envelopes, no claim.
 */
static int t_prepare_claims_past_env_window(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                         *txs = NULL;
    uint8_t                                *call = NULL, *claim = NULL;
    size_t                                  clen = 0, i, k_fit;
    uint64_t                                bound, ceil_max = 0;

    CHECK(gfx_open_n(&g, "ckt_claimwin", 2) == 0,
          "version-3 fixture, two distribution leaves");
    CHECK(v2x_table_init(g.w) == 0, "the scripted runtime table");
    app  = calloc(1, sizeof(*app));
    bctx = calloc(1, sizeof(*bctx));
    envs = calloc(CAP_BYTES_N, sizeof(*envs));
    txs  = calloc(CAP_BYTES_N + 1, sizeof(*txs));
    call = calloc(1, CAP_BYTES_CALL_LEN);
    claim = malloc(DNA_CLAIM_MAX_WIRE);
    CHECK(app && bctx && envs && txs && call && claim, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(cap_ctx_build(g.w, bctx) == 0 && bctx->policy,
          "the block context");
    bound = bctx->policy->max_block_env_bytes;

    for (i = 0; i < CAP_BYTES_N; i++) {
        uint64_t st = 0;

        memset(call, 0x5C, CAP_BYTES_CALL_LEN);
        call[0] = (uint8_t)i;
        call[1] = 0xE4;
        CHECK(cap_env_build(&envs[i], bctx->policy, call,
                            CAP_BYTES_CALL_LEN, 1, 1000u + i, 0, &st) == 0,
              "a ~60 KB priced envelope");
        if (st > ceil_max) {
            ceil_max = st;
        }
        txs[i].data = envs[i].bytes;
        txs[i].len  = envs[i].len;
    }
    CHECK(build_claim_n(&g, 2, 0, claim, DNA_CLAIM_MAX_WIRE, &clen) == 0,
          "an admissible claim");
    txs[CAP_BYTES_N].data = claim;
    txs[CAP_BYTES_N].len  = clen;
    k_fit = (size_t)(bound / envs[0].len);
    CHECK(k_fit >= 2 && k_fit < CAP_BYTES_N, "PREMISE: the envelopes "
          "overflow the window");
    CHECK((uint64_t)k_fit * ceil_max <= bctx->budget.global_remaining &&
          (uint64_t)k_fit * ceil_max <= cap_core_units(bctx),
          "PREMISE: the unit budgets are not the binding bound");

    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = CAP_BYTES_N + 1;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == k_fit + 1, "the k_fit envelopes AND the claim");
    for (i = 0; i < k_fit; i++) {
        CHECK(resp.txs[i].data == envs[CAP_BYTES_N - 1 - i].bytes,
              "the highest-fee envelopes, fee-descending");
    }
    CHECK(resp.txs[k_fit].data == claim, "the claim is proposed, after "
          "them");

    free(claim);
    free(call);
    free(txs);
    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/* ══ CHECKTX-P1 ROUND 2 — lifetime, row-identity keys, the unit-aware
 * pack, fee per unit ════════════════════════════════════════════════
 * Each case names the round-2 fix it targets and why it fails on the
 * round-1 tree. */

/**
 * [fix 4 — lifetime] The mempool lifetime rule (decision
 * 2026-09-25-mempool-policy.md 1; nodus_types.h
 * NODUS_CMT_APP_MAX_EXPIRY_AHEAD). Block 1 — a real block through the
 * host — CREATEs the two CORE rows the spends below need (amount 0, so
 * the supply equation is untouched; CREATEd by an applied item, so the
 * CORE root moves as a DECLARED touch — planting rows by SQL instead
 * trips the engine's untouched-domain guard, apply.c phase 8, and a
 * nonzero planted row its pre-apply supply gate, phase 2 — round 2b).
 * At tip 1: expiry 0 and tip + 101 are REFUSED, tip + 100 and tip + 1
 * ADMITTED. After a real EMPTY block 2 — the host's Commit clears the
 * pending set, the rows are untouched, ONLY the tip moved — the RECHECK
 * drops the tip + 1 = 2 envelope (expired at candidate height 3,
 * env_preflight.c step 3) and keeps the tip + 100 one.
 *
 * RED on round 1: expiry 0 and tip + 101 were admitted.
 */
static int t_check_tx_expiry(void)
{
    gfx_t           g;
    exec_t          x;
    cmt_block_id_t  bid;
    v2x_env_t      *e = NULL;
    dna_effect_in_t mk[2];
    uint8_t         k1[64], k2[64], zero8[8];
    uint64_t        tip;
    uint32_t        code = 0;
    char            log[CMT_MEM_CHECK_TX_LOG_MAX];

    CHECK(gfx_open(&g, "ckt_expiry") == 0, "version-3 fixture");
    CHECK(v2x_table_init(g.w) == 0, "the scripted runtime table");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");
    e = calloc(5, sizeof(*e));
    CHECK(e != NULL, "alloc");

    /* ── block 1: CREATE rows 0xE1 and 0xE2 (amount 0) ─────────────── */
    memset(k1, 0xE1, sizeof(k1));
    memset(k2, 0xE2, sizeof(k2));
    memset(zero8, 0, sizeof(zero8));
    memset(mk, 0, sizeof(mk));
    mk[0].hdr.op_id       = V2X_OP_UTXO;
    mk[0].hdr.effect_kind = DNA_EFFECT_CREATE;
    mk[0].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
    mk[0].hdr.key_len     = 64;
    mk[0].hdr.value_len   = 8;
    mk[0].key             = k1;              /* key order: 0xE1.. first  */
    mk[0].value           = zero8;
    mk[1]                 = mk[0];
    mk[1].key             = k2;
    CHECK(ckt_effs_env(&e[4], mk, 2, 1, TEST_APP_ENV_CEILING,
                       CKT_EXPIRY) == 0, "the row-creating envelope");
    x.txs[0].data = e[4].bytes;
    x.txs[0].len  = e[4].len;
    CHECK(exec_make_block(&x, 1, 1) == 0, "block 1");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "a COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK, "block 1 applies");
    CHECK(x.ledger->fb_pb[0].det.code == (uint32_t)NODUS_V2_TX_OK,
          "PREMISE: the row-creating item APPLIED");
    CHECK(ckt_row_exists(g.w, 0xE1) == 1 && ckt_row_exists(g.w, 0xE2) == 1,
          "PREMISE: both rows exist, committed by block 1");
    tip = 1;
    CHECK(q1(g.w->db, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks")
              == (int64_t)tip, "PREMISE: the tip is 1");

    /* ── at tip 1 ───────────────────────────────────────────────────── */
    CHECK(ckt_spend_env_x(&e[0], 0xE1, 3, TEST_APP_ENV_CEILING, 0) == 0 &&
          ckt_spend_env_x(&e[1], 0xE1, 4, TEST_APP_ENV_CEILING,
                          tip + CKT_EXPIRY + 1) == 0 &&
          ckt_spend_env_x(&e[2], 0xE1, 5, TEST_APP_ENV_CEILING,
                          tip + CKT_EXPIRY) == 0 &&
          ckt_spend_env_x(&e[3], 0xE2, 5, TEST_APP_ENV_CEILING,
                          tip + 1) == 0,
          "expiry 0, tip+101, tip+100, and tip+1");
    CHECK(ckt_check(x.ledger, e[0].bytes, e[0].len,
                    CMT_MEM_CHECK_TX_TYPE_NEW, &code) == 0 &&
          code != CMT_MEM_CODE_TYPE_OK, "expiry 0 (\"never\") is refused");
    CHECK(ckt_check_log(x.ledger, e[1].bytes, e[1].len,
                        CMT_MEM_CHECK_TX_TYPE_NEW, &code, log) == 0 &&
          code != CMT_MEM_CODE_TYPE_OK, "expiry tip + 101 is refused");
    CHECK(log[CMT_MEM_CHECK_TX_LOG_MAX - 1] == '\0' && log[0] != '\0' &&
          strstr(log, "expiry_height") != NULL,
          "the refusal carries its reason in ResponseCheckTx.log");
    CHECK(ckt_check_log(x.ledger, e[2].bytes, e[2].len,
                        CMT_MEM_CHECK_TX_TYPE_NEW, &code, log) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK, "expiry tip + 100 is admitted");
    CHECK(log[0] == '\0', "an admitted entry carries no log text");
    CHECK(ckt_check(x.ledger, e[3].bytes, e[3].len,
                    CMT_MEM_CHECK_TX_TYPE_NEW, &code) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK, "expiry tip + 1 is admitted");

    /* ── block 2, EMPTY: only the tip moves; the host's Commit runs ─── */
    CHECK(exec_make_last_commit(&x, 1, &bid) == 0,
          "a precommit from every validator for block 1");
    CHECK(exec_make_block(&x, 2, 0) == 0, "block 2, empty");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "block 2's COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK, "block 2 applies");
    CHECK(q1(g.w->db, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks")
              == 2, "PREMISE: the tip is 2");
    CHECK(ckt_row_exists(g.w, 0xE2) == 1, "PREMISE: the row the tip + 1 "
          "envelope spends is still live — its refusal below is the "
          "expiry, not the state");

    CHECK(ckt_check(x.ledger, e[2].bytes, e[2].len,
                    CMT_MEM_CHECK_TX_TYPE_RECHECK, &code) == 0 &&
          code == CMT_MEM_CODE_TYPE_OK,
          "the tip + 100 envelope survives the recheck");
    CHECK(ckt_check(x.ledger, e[3].bytes, e[3].len,
                    CMT_MEM_CHECK_TX_TYPE_RECHECK, &code) == 0 &&
          code != CMT_MEM_CODE_TYPE_OK,
          "the tip + 1 envelope is dropped at recheck once expired");

    free(e);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/**
 * [fix 5 — row-identity keys; round 3 — VHASH SETs are NOT keys]
 * (a) Two envelopes CREATEing the SAME new row (PRE_ABSENT — a
 * TOKEN_CREATE with one token_id, a STAKE for one validator): the second
 * is REFUSED. (b) Two envelopes SETting the SAME existing row bound to
 * its value hash (PRE_EXISTS_VHASH — the shape of two DELEGATEs to one
 * validator row): BOTH are admitted, because in a block the second
 * re-reads the row after the first wrote it and derives its expected
 * hash from that read (nodus_witness_v2_apply.c exec_one_env;
 * nodus_witness_rt_native.c rtn_row_set_eff) — both apply. (c) Two
 * ordinary INDEPENDENT spends that both update the SAME shared counter
 * under PRE_EXISTS_VERSION: BOTH are admitted.
 *
 * HOW IT CAN LIE: the effects here are the scripted runtime's STATIC
 * bytes, not a native DELEGATE's; (b) pins the keying RULE (a VHASH SET
 * is not a key), not the native runtime's re-derivation. A native
 * two-delegator DELEGATE case was judged impractical in this file: it
 * needs two differently-owned funded coins (this fixture's genesis
 * distribution binds every leaf to g_ks[0]) plus a SYSFUND leg each.
 *
 * RED on round 1: (a) — only DELETE rows were keyed. RED on round 2:
 * (b) — round 2 keyed VHASH SETs and refused the second. (c) passes on
 * every round (the pin that counters are never keys).
 */
static int t_check_tx_row_keys(void)
{
    gfx_t                         g;
    cmt_genesis_doc_t             doc;
    cmt_genesis_validator_t       gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t       *app = NULL;
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    v2x_env_t                    *e = NULL;
    dna_effect_in_t               eff[2];
    uint8_t                       newk[64], rowk[64], dk1[64], dk2[64];
    uint8_t                       val0[8], val6[8], oldv[8], pool_key[1];
    uint8_t                       pool_new[8];
    int64_t                       pool;
    uint32_t                      code = 0;
    int                           i;

    CHECK(cap_fixture(&g, "ckt_rowkeys", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    e = calloc(6, sizeof(*e));
    CHECK(e != NULL, "alloc");
    CHECK(ckt_row_insert(g.w, 0xD1) == 0 && ckt_row_insert(g.w, 0xD2) == 0 &&
          ckt_row_insert(g.w, 0xD3) == 0, "three committed CORE rows");

    /* (a) CREATE with PRE_ABSENT, one new key, two intents */
    memset(newk, 0xDA, sizeof(newk));
    memset(val0, 0, sizeof(val0));
    memset(eff, 0, sizeof(eff));
    eff[0].hdr.op_id       = V2X_OP_UTXO;
    eff[0].hdr.effect_kind = DNA_EFFECT_CREATE;
    eff[0].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
    eff[0].hdr.key_len     = 64;
    eff[0].hdr.value_len   = 8;
    eff[0].key             = newk;
    eff[0].value           = val0;
    CHECK(ckt_effs_env(&e[0], eff, 1, 3, TEST_APP_ENV_CEILING,
                       CKT_EXPIRY) == 0 &&
          ckt_effs_env(&e[1], eff, 1, 4, TEST_APP_ENV_CEILING,
                       CKT_EXPIRY) == 0, "two CREATEs of one new row");
    CHECK(ckt_check(app, e[0].bytes, e[0].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the first CREATE is admitted");
    CHECK(ckt_check(app, e[1].bytes, e[1].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code != CMT_MEM_CODE_TYPE_OK,
          "a second CREATE of the same row (PRE_ABSENT) is refused");

    /* (b) SET with PRE_EXISTS_VHASH on the existing row 0xD1 (amount 0 —
     * ckt_row_insert; the fixture adapter's value hash is over the 8-byte
     * BE amount, v2_exec_fixture.h v2x_core_probe). The SET is only ever
     * dry-run here, never applied. */
    memset(rowk, 0xD1, sizeof(rowk));
    memset(oldv, 0, sizeof(oldv));
    memset(val6, 0, sizeof(val6));
    val6[7] = 6;
    memset(eff, 0, sizeof(eff));
    eff[0].hdr.op_id       = V2X_OP_UTXO;
    eff[0].hdr.effect_kind = DNA_EFFECT_SET;
    eff[0].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VHASH;
    eff[0].hdr.key_len     = 64;
    eff[0].hdr.value_len   = 8;
    eff[0].key             = rowk;
    eff[0].value           = val6;
    CHECK(dna_effect_value_hash(oldv, 8, eff[0].hdr.expected_vhash) == 0,
          "the row's current value hash");
    CHECK(ckt_effs_env(&e[2], eff, 1, 3, TEST_APP_ENV_CEILING,
                       CKT_EXPIRY) == 0 &&
          ckt_effs_env(&e[3], eff, 1, 4, TEST_APP_ENV_CEILING,
                       CKT_EXPIRY) == 0, "two VHASH-bound SETs of one row");
    CHECK(ckt_check(app, e[2].bytes, e[2].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the first SET is admitted");
    CHECK(ckt_check(app, e[3].bytes, e[3].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "a second VHASH-bound SET of the same row is ALSO admitted — in a "
          "block each item re-reads the row after the earlier item's write "
          "and hashes THAT (round 3: not a conflict key)");

    /* (c) two independent spends, each also crediting the reward-pool
     * counter under PRE_EXISTS_VERSION (the native supply pattern) */
    pool = q1(g.w->db, "SELECT reward_pool FROM supply_tracking WHERE id=1");
    CHECK(pool >= 0, "PREMISE: the supply counter row exists");
    pool_key[0] = 3;                                  /* reward_pool   */
    for (i = 0; i < 8; i++) {
        pool_new[i] = (uint8_t)(((uint64_t)pool + 1u) >> (56 - 8 * i));
    }
    memset(dk1, 0xD2, sizeof(dk1));
    memset(dk2, 0xD3, sizeof(dk2));
    for (i = 0; i < 2; i++) {
        /* CANONICAL ORDER (shared/dnac/effect_wire.c eff_order_cmp):
         * effect_kind FIRST, then op_id, then key — so the SET (kind 2)
         * precedes the DELETE (kind 3) even though its op id (3) is the
         * larger one. Round 2 had them the other way round and the
         * encoder refused the result. */
        memset(eff, 0, sizeof(eff));
        eff[0].hdr.op_id            = V2X_OP_SUPPLY;
        eff[0].hdr.effect_kind      = DNA_EFFECT_SET;
        eff[0].hdr.precond_tag      = DNA_EFFECT_PRE_EXISTS_VERSION;
        eff[0].hdr.expected_version = (uint64_t)pool;
        eff[0].hdr.key_len          = 1;
        eff[0].hdr.value_len        = 8;
        eff[0].key                  = pool_key;
        eff[0].value                = pool_new;
        eff[1].hdr.op_id       = V2X_OP_UTXDEL;
        eff[1].hdr.effect_kind = DNA_EFFECT_DELETE;
        eff[1].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
        eff[1].hdr.key_len     = 64;
        eff[1].key             = i == 0 ? dk1 : dk2;
        CHECK(ckt_effs_env(&e[4 + i], eff, 2, 3, TEST_APP_ENV_CEILING,
                           CKT_EXPIRY) == 0,
              "a spend of its own row that also sets the shared counter");
    }
    CHECK(ckt_check(app, e[4].bytes, e[4].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the first independent spend is admitted");
    CHECK(ckt_check(app, e[5].bytes, e[5].len, CMT_MEM_CHECK_TX_TYPE_NEW,
                    &code) == 0 && code == CMT_MEM_CODE_TYPE_OK,
          "the second is admitted too — the EXISTS_VERSION counter row is "
          "not a conflict key");

    free(e);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * [fixes 1 + 2 — the hog] Ranked by fee per unit: a small top envelope,
 * then a HOG declaring the WHOLE unit budget (fee high enough to rank
 * second both by flat fee and by fee per unit — PREMISE-checked), then
 * four small envelopes and one claim. The UNIT budget binds: after the
 * top envelope the hog no longer fits, so the pack SKIPS it and packs
 * the four small envelopes and the claim behind it, in ONE seam run.
 *
 * RED on round 1 (and 0.19.77): the pack had no unit budget; the seam
 * refused the hog at slot 1 as CAPACITY_UNITS and the loop TRUNCATED the
 * proposal to [top] — the four fitting envelopes and the claim were
 * thrown away (red-team HIGH, and the claims MEDIUM).
 */
static int t_prepare_hog_skipped(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                          txs[7];
    uint8_t                                 call[64], *claim = NULL;
    size_t                                  clen = 0, i;
    uint64_t                                st_top = 0, st_small = 0, budget;

    CHECK(gfx_open_n(&g, "ckt_hog", 2) == 0,
          "version-3 fixture, two distribution leaves");
    CHECK(v2x_table_init(g.w) == 0, "the scripted runtime table");
    app   = calloc(1, sizeof(*app));
    bctx  = calloc(1, sizeof(*bctx));
    envs  = calloc(6, sizeof(*envs));
    claim = malloc(DNA_CLAIM_MAX_WIRE);
    CHECK(app && bctx && envs && claim, "alloc");
    CHECK(gfx_doc(&g, &doc, gvals) == 0, "the completed genesis document");
    CHECK(nodus_cmt_app_ledger_init(app, g.w, &doc) == CMT_OK, "bind");
    CHECK(cap_ctx_build(g.w, bctx) == 0 && bctx->policy,
          "the block context");
    budget = bctx->budget.global_remaining;

    memset(call, 0x71, sizeof(call));
    CHECK(cap_env_build(&envs[0], bctx->policy, call, sizeof(call), 1,
                        1000000000000ull, 0, &st_top) == 0, "the top one");
    memset(call, 0x72, sizeof(call));
    CHECK(cap_env_build(&envs[1], bctx->policy, call, sizeof(call), 1,
                        1000000000ull, budget, NULL) == 0,
          "the HOG: the whole unit budget declared");
    for (i = 2; i < 6; i++) {
        memset(call, (int)(0x80 + i), sizeof(call));
        CHECK(cap_env_build(&envs[i], bctx->policy, call, sizeof(call), 1,
                            5, 0, &st_small) == 0, "a small one");
    }
    CHECK(build_claim_n(&g, 2, 0, claim, DNA_CLAIM_MAX_WIRE, &clen) == 0,
          "an admissible claim");
    CHECK(1000000000000ull * budget > 1000000000ull * st_top &&
          1000000000ull * st_small > 5u * budget,
          "PREMISE: top > hog > small by fee per unit (and by flat fee)");
    CHECK(st_top + 4u * st_small <= budget && st_top > 0,
          "PREMISE: everything but the hog fits the unit budget, and the "
          "hog (the whole budget) no longer fits once the top one "
          "reserved its nonzero static cost");

    /* request order: small×4, hog, claim, top */
    for (i = 0; i < 4; i++) {
        txs[i].data = envs[2 + i].bytes;
        txs[i].len  = envs[2 + i].len;
    }
    txs[4].data = envs[1].bytes; txs[4].len = envs[1].len;
    txs[5].data = claim;         txs[5].len = clen;
    txs[6].data = envs[0].bytes; txs[6].len = envs[0].len;

    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = 7;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    g_seam_runs = 0;
    CHECK(sqlite3_trace_v2(g.w->db, SQLITE_TRACE_STMT, seam_run_trace,
                           NULL) == SQLITE_OK, "install the run counter");
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    sqlite3_trace_v2(g.w->db, 0, NULL, NULL);

    CHECK(resp.txs_len == 6, "top + four small + the claim — the hog is "
          "skipped, nothing behind it is lost");
    CHECK(resp.txs[0].data == envs[0].bytes, "the top one first");
    for (i = 0; i < 4; i++) {
        CHECK(resp.txs[1 + i].data == envs[2 + i].bytes,
              "the four small ones, request order (a tie)");
    }
    CHECK(resp.txs[5].data == claim, "the claim lands too");
    CHECK(SEAM_RUNS() == 1, "ONE seam run: the pack applied the unit "
          "budget itself");

    free(claim);
    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/**
 * [fix 3 — fee per unit] Three envelopes: A pays 100 over 10 000 units
 * (0.01 per unit), B pays 50 over 1 000 (0.05), and a hog pays 1 000 —
 * the highest FLAT fee — over the whole unit budget (~0.0005). Ranked by
 * fee per unit the answer is [B, A]; the hog ranks last and no longer
 * fits.
 *
 * RED on round 1: flat-fee order put the hog first; it reserved the whole
 * budget and the loop truncated the proposal to [hog].
 */
static int t_prepare_fee_per_unit(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_request_prepare_proposal_t   req;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    cmt_pb_bytes_t                          txs[3];
    uint8_t                                 call[64];
    uint64_t                                st_a = 0, st_b = 0;

    CHECK(cap_fixture(&g, "ckt_perunit", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    envs = calloc(3, sizeof(*envs));
    CHECK(envs != NULL, "alloc");
    memset(call, 0x91, sizeof(call));
    CHECK(cap_env_build(&envs[0], bctx->policy, call, sizeof(call), 1, 100,
                        10000, &st_a) == 0, "A: 100 over 10 000");
    memset(call, 0x92, sizeof(call));
    CHECK(cap_env_build(&envs[1], bctx->policy, call, sizeof(call), 1, 50,
                        1000, &st_b) == 0, "B: 50 over 1 000");
    memset(call, 0x93, sizeof(call));
    CHECK(cap_env_build(&envs[2], bctx->policy, call, sizeof(call), 1, 1000,
                        bctx->budget.global_remaining, NULL) == 0,
          "the hog: 1 000 over the whole budget");
    CHECK(st_a <= 10000 && st_b <= 1000, "PREMISE: both ceilings cover "
          "their static cost");

    /* request order: A, hog, B */
    txs[0].data = envs[0].bytes; txs[0].len = envs[0].len;
    txs[1].data = envs[2].bytes; txs[1].len = envs[2].len;
    txs[2].data = envs[1].bytes; txs[2].len = envs[1].len;
    memset(&req, 0, sizeof(req));
    req.txs          = txs;
    req.txs_len      = 3;
    req.max_tx_bytes = 22020096;
    memset(&resp, 0, sizeof(resp));
    CHECK(nodus_cmt_app_prepare_proposal(app, &req, &resp) == CMT_OK,
          "prepare answers");
    CHECK(resp.txs_len == 2, "the hog is not proposed");
    CHECK(resp.txs[0].data == envs[1].bytes &&
          resp.txs[1].data == envs[0].bytes,
          "B (0.05 per unit) before A (0.01 per unit)");

    free(envs);
    free(bctx);
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

/* ══ HF-3 — Comet-only block bounds + the proposal fee check ═══════════
 * Design docs/plans/2026-10-01-hf3-comet-block-bounds-design.md rev 3;
 * decision docs/plans/decisions/2026-10-01-hf3-comet-only-block-bounds.md
 * (answers 6, 9, 10). Chain-config param 8 HF3_ACTIVE, read ONCE per
 * block-start context at the candidate height (tip + 1).
 *
 * WHY DIRECT SQL ROWS ARE HONEST HERE: these cases run PrepareProposal and
 * ProcessProposal only — the seam preflights and reserves, it never
 * applies — so no block is applied after a row is written and the
 * engine's untouched-domain guard (which a post-genesis chain_config
 * write would trip) never runs. The FinalizeBlock half (the engine at H,
 * "zero code-9 items at H", twin roots) is test_v2_apply.c's
 * test_hf3_engine, whose rows are written BEFORE genesis.
 *
 * The chain has no block rows, so the candidate height is 1 throughout:
 * "H-1" is a param-8 row effective at 2, "H" the same row moved to 1. */

static int hf3_sql(nodus_witness_t *w, const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "hf3 sql failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    w->chain_config_cache_warm = false;        /* cache = DB, re-read   */
    return 0;
}

static int hf3_cc_insert(nodus_witness_t *w, uint8_t param, uint64_t value,
                         uint64_t eff)
{
    char sql[320];

    snprintf(sql, sizeof(sql),
             "INSERT INTO chain_config_history (param_id, new_value, "
             "effective_block, commit_block, tx_hash, proposal_nonce, "
             "created_at_unix) VALUES (%u, %llu, %llu, 0, zeroblob(64), "
             "%u, 0)", (unsigned)param, (unsigned long long)value,
             (unsigned long long)eff, 9000u + (unsigned)param);
    return hf3_sql(w, sql);
}

/** One ProcessProposal over `n` envelopes; the status, or -1 on a
 *  non-CMT_OK return (the answer a FAULT gives). */
static int hf3_process(nodus_cmt_app_ledger_t *app, cmt_pb_bytes_t *txs,
                       size_t n)
{
    nodus_abci_request_process_proposal_t  req;
    nodus_abci_response_process_proposal_t resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.txs     = txs;
    req.txs_len = n;
    if (nodus_cmt_app_process_proposal(app, &req, &resp) != CMT_OK) {
        return -1;
    }
    return (int)resp.status;
}

/** One PrepareProposal over `n` envelopes; the kept count (resp.txs is
 *  the app's buffer, valid until the next call), or -1 on a FAULT. */
static long hf3_prepare(nodus_cmt_app_ledger_t *app, cmt_pb_bytes_t *txs,
                        size_t n, nodus_abci_response_prepare_proposal_t *resp)
{
    nodus_abci_request_prepare_proposal_t req;

    memset(&req, 0, sizeof(req));
    memset(resp, 0, sizeof(*resp));
    req.txs          = txs;
    req.txs_len      = n;
    req.max_tx_bytes = 22020096;           /* Block.MaxBytes, not binding */
    if (nodus_cmt_app_prepare_proposal(app, &req, resp) != CMT_OK) {
        return -1;
    }
    return (long)resp->txs_len;
}

/**
 * (1) THE LIFT (test plan R4-1 / round 2 G3), RED before HF-3: N CORE
 * envelopes with N DERIVED from the fixture's own encoded env_len —
 * N = max(256, floor(2 097 152 / env_len) + 2), never a hardcoded count —
 * so the request is above BOTH the 2 MiB envelope-byte bound and 255
 * envelopes. Asserted from the MEASURED bytes of what Prepare kept.
 *   no row            Prepare caps (< N kept, <= 2 MiB), Process REJECT;
 *   row at 2 (H-1)    the same — a committed-but-future row changes
 *                     nothing (D3/D4);
 *   row at 1 (H)      Prepare keeps all N (byte sum > 2 097 152 AND
 *                     count > 255), Process ACCEPTs the same N.
 * (2) THE PROPOSAL FEE CHECK (operator answer 6, §0.2), at H:
 *   price 0           an underpaid envelope is not checked (rule off);
 *   price 1           Process REJECTs a block carrying it, ACCEPTs the
 *                     block without it; Prepare drops exactly it (the
 *                     drop loop's ENTRY_INVALID exclusion); an all-SYSTEM
 *                     chain_config (fee 0) stays exempt;
 *   row back at 2     (H-1, price 1) the same underpaid block is
 *                     ACCEPTed — pre-H identity, no fee check in the seam.
 * (3) RULE 5 (answer 10) at H: a ceiling of INT64_MAX is accepted (the
 *     flagged budget does not refuse it), INT64_MAX + 1 is REJECTed —
 *     both with a fee that pays it, so only rule 5 can refuse.
 * (3b) RULE 6b (answer 12) at H: a block carrying an envelope already in
 *     the committed intent index is REJECTed by Process and the drop loop
 *     excludes exactly it; at H-1 the same block is ACCEPTed.
 * (4) RULE 4 (answer 9, decided A) at H: a NON-zero CORE quota_verify_cost
 *     still refuses the block at Process (the seam's all-or-nothing
 *     reservation), exactly as below H.
 * (5) An unreadable price at H is a FAULT (CMT_FAULT), never a verdict.
 * HOW IT CAN LIE: (1) relies on cap_env_build giving every envelope the
 * same length; the premise checks below re-measure every one. (5) uses a
 * VIEW that raises only when the param-5 row is EVALUATED; the param-8
 * read never evaluates it (WHERE param_id = 8), which the ACCEPT just
 * before the poison proves on the same view shape.
 */
#define HF3_CALL_LEN 8126u                 /* ~8.2 KB envelopes          */
static int t_hf3_bounds_and_fee(void)
{
    gfx_t                                   g;
    cmt_genesis_doc_t                       doc;
    cmt_genesis_validator_t                 gvals[DNAC_COMMITTEE_SIZE];
    nodus_cmt_app_ledger_t                 *app = NULL;
    nodus_witness_v2_block_ctx_t           *bctx = NULL;
    nodus_abci_response_prepare_proposal_t  resp;
    v2x_env_t                              *envs = NULL;
    v2x_env_t                              *small = NULL;
    cmt_pb_bytes_t                         *txs = NULL;
    cmt_pb_bytes_t                          ftx[4];
    uint8_t                                *call = NULL;
    test_env_t                              cc;
    size_t                                  i, n, len0;
    uint64_t                                sum, st = 0;
    long                                    kept;
    const uint64_t                          floor_fee = 1000000ull;

    memset(&cc, 0, sizeof(cc));
    CHECK(cap_fixture(&g, "hf3", &doc, gvals, &app, &bctx) == 0,
          "version-3 fixture, scripted runtime, bound app, block context");
    CHECK(bctx->hf3_active == 0, "no param-8 row: HF-3 is OFF");
    CHECK(bctx->budget.global_unbounded == 0, "OFF: the global budget is "
          "a bound");

    /* ── the N envelopes, N from the measured length ───────────────── */
    call = calloc(1, HF3_CALL_LEN);
    CHECK(call != NULL, "alloc");
    memset(call, 0x3C, HF3_CALL_LEN);
    {
        v2x_env_t *probe = calloc(1, sizeof(*probe));

        CHECK(probe != NULL, "alloc");
        CHECK(cap_env_build(probe, bctx->policy, call, HF3_CALL_LEN, 1, 1000,
                            0, NULL) == 0, "the probe envelope");
        len0 = probe->len;
        free(probe);
    }
    n = 2097152u / len0 + 2u;
    if (n < 256u) {
        n = 256u;
    }
    CHECK(n <= app->prep_bound && n <= NODUS_V2_ENV_BATCH_MAX,
          "PREMISE: N fits the mempool and the engine's batch bound");
    envs = calloc(n, sizeof(*envs));          /* n x 64 KiB: heap        */
    txs  = calloc(n, sizeof(*txs));
    CHECK(envs && txs, "alloc");
    sum = 0;
    for (i = 0; i < n; i++) {
        call[0] = (uint8_t)(i >> 8);              /* distinct intent     */
        call[1] = (uint8_t)i;
        CHECK(cap_env_build(&envs[i], bctx->policy, call, HF3_CALL_LEN, 1,
                            1000u + i, 0, NULL) == 0,
              "a ~8 KB CORE envelope with an exact ceiling");
        CHECK(envs[i].len == len0, "PREMISE: every envelope has the "
              "measured length");
        txs[i].data = envs[i].bytes;
        txs[i].len  = envs[i].len;
        sum += envs[i].len;
    }
    CHECK(sum > 2097152u && n > 255u, "PREMISE: the request is above the "
          "2 MiB envelope-byte bound AND above 255 envelopes");

    /* ── OFF, no row ───────────────────────────────────────────────── */
    kept = hf3_prepare(app, txs, n, &resp);
    CHECK(kept >= 1 && (size_t)kept < n, "OFF: Prepare caps the proposal");
    sum = 0;
    for (i = 0; i < (size_t)kept; i++) {
        sum += resp.txs[i].len;
    }
    CHECK(sum <= 2097152u, "OFF: the kept bytes stay within 2 MiB");
    CHECK(hf3_process(app, txs, n) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "OFF: Process REJECTs the over-bound block");

    /* ── H-1: the row is committed but effective at 2 ──────────────── */
    CHECK(hf3_cc_insert(g.w, (uint8_t)DNAC_CFG_HF3_ACTIVE,
                        DNAC_CFG_HF3_ACTIVE_ON, 2) == 0, "param-8 row @2");
    CHECK(cap_ctx_build(g.w, bctx) == 0 && bctx->hf3_active == 0,
          "H-1: the context still reads OFF");
    kept = hf3_prepare(app, txs, n, &resp);
    CHECK(kept >= 1 && (size_t)kept < n, "H-1: Prepare still caps");
    CHECK(hf3_process(app, txs, n) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "H-1: Process still REJECTs");

    /* ── H: the same row, effective at the candidate height ────────── */
    CHECK(hf3_sql(g.w, "UPDATE chain_config_history SET effective_block "
                       "= 1 WHERE param_id = 8") == 0, "row -> @1");
    CHECK(cap_ctx_build(g.w, bctx) == 0 && bctx->hf3_active == 1 &&
          bctx->budget.global_unbounded == 1,
          "H: the context reads ON and flags the global budget");
    for (i = 0; i < bctx->budget.n_domains; i++) {
        CHECK(bctx->budget.dom[i].unbounded == 1, "H: every quota-0 "
              "domain slot is flagged (genesis quotas are 0)");
    }
    kept = hf3_prepare(app, txs, n, &resp);
    CHECK(kept >= 0 && (size_t)kept == n, "H: Prepare keeps ALL N");
    sum = 0;
    for (i = 0; i < (size_t)kept; i++) {
        sum += resp.txs[i].len;
    }
    CHECK(sum > 2097152u && kept > 255,
          "H: the kept proposal is above 2 MiB AND above 255 envelopes "
          "(measured)");
    CHECK(hf3_process(app, txs, n) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "H: Process ACCEPTs the same N");

    /* ── (2) the proposal fee check ────────────────────────────────── */
    small = calloc(5, sizeof(*small));
    CHECK(small != NULL, "alloc");
    for (i = 0; i < 3; i++) {
        uint8_t c[200];

        memset(c, (int)(0x90 + i), sizeof(c));
        CHECK(cap_env_build(&small[i], bctx->policy, c, sizeof(c), 1,
                            i < 2 ? 0 : 1000, 0, &st) == 0, "small env");
        if (i < 2) {
            /* paid at price 1: units x 1 + the flat floor */
            CHECK(cap_env_build(&small[i], bctx->policy, c, sizeof(c), 1,
                                st + floor_fee, 0, NULL) == 0, "paid env");
        }
    }
    ftx[0].data = small[0].bytes; ftx[0].len = small[0].len;   /* paid  */
    ftx[1].data = small[1].bytes; ftx[1].len = small[1].len;   /* paid  */
    ftx[2].data = small[2].bytes; ftx[2].len = small[2].len;   /* under */

    CHECK(hf3_process(app, ftx, 3) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "H, price 0: no fee check — the rule is off");

    CHECK(hf3_cc_insert(g.w, (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, 1,
                        1) == 0, "price 1 @1");
    CHECK(hf3_process(app, ftx, 3) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "H, price 1: Process REJECTs a block carrying an underpaid "
          "envelope");
    CHECK(hf3_process(app, ftx, 2) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "H, price 1: the same block without it is ACCEPTed");
    kept = hf3_prepare(app, ftx, 3, &resp);
    CHECK(kept == 2, "H, price 1: Prepare drops exactly one envelope");
    for (i = 0; i < 2; i++) {
        CHECK(resp.txs[i].data != small[2].bytes,
              "H, price 1: the dropped one is the underpaid one");
    }
    CHECK(build_cc_env(g.w, g.chain32, 0x3F03, &cc) == 0,
          "an all-SYSTEM chain_config envelope (fee 0)");
    ftx[3].data = cc.bytes; ftx[3].len = cc.len;
    CHECK(hf3_process(app, &ftx[3], 1) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "H, price 1: an all-SYSTEM envelope stays exempt");

    /* pre-H identity: the row back at 2, price 1 still active */
    CHECK(hf3_sql(g.w, "UPDATE chain_config_history SET effective_block "
                       "= 2 WHERE param_id = 8") == 0, "row -> @2");
    CHECK(hf3_process(app, ftx, 3) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "H-1, price 1: the underpaid block is ACCEPTed — the seam runs "
          "no fee check below H");
    kept = hf3_prepare(app, ftx, 3, &resp);
    CHECK(kept == 3, "H-1, price 1: Prepare keeps all three");

    /* ── (3) rule 5 at H, OFF for contrast ─────────────────────────── */
    {
        uint8_t c[200];

        memset(c, 0xA7, sizeof(c));
        CHECK(cap_env_build(&small[3], bctx->policy, c, sizeof(c), 1,
                            UINT64_MAX, (uint64_t)INT64_MAX, NULL) == 0,
              "a ceiling of exactly INT64_MAX, fee UINT64_MAX");
        memset(c, 0xA8, sizeof(c));
        CHECK(cap_env_build(&small[4], bctx->policy, c, sizeof(c), 1,
                            UINT64_MAX, (uint64_t)INT64_MAX + 1u, NULL) == 0,
              "a ceiling of INT64_MAX + 1, fee UINT64_MAX");
    }
    ftx[0].data = small[3].bytes; ftx[0].len = small[3].len;
    ftx[1].data = small[4].bytes; ftx[1].len = small[4].len;
    CHECK(hf3_process(app, &ftx[0], 1) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "H-1: an INT64_MAX ceiling exceeds the bounded unit budget");
    CHECK(hf3_sql(g.w, "UPDATE chain_config_history SET effective_block "
                       "= 1 WHERE param_id = 8") == 0, "row -> @1");
    CHECK(hf3_process(app, &ftx[0], 1) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "H: a ceiling of INT64_MAX is accepted (the flagged budget does "
          "not bound it, rule 5 admits it)");
    CHECK(hf3_process(app, &ftx[1], 1) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
          "H: a ceiling of INT64_MAX + 1 is REJECTed by rule 5");

    /* ── (3b) rule 6b (decision answer 12): committed replay at H ──────
     * small[0] (fee paid at price 1, exact ceiling, expiry 0 = never) is
     * marked COMMITTED by writing its derived intent_id / wire_id into
     * v2_intent_index — the row cmt_item_index writes for an applied
     * item. Honest only because no block is applied afterwards (the
     * case's note above). At H Process REJECTs a block carrying it and
     * ACCEPTs the same block without it (so the refusal is the replay —
     * the fee, rule 5 and the unbounded budget all pass small[0]); Prepare
     * drops exactly it; at H-1 the same block is ACCEPTed (no seam replay
     * check below H). RED without the seam's replay check: the first
     * REJECT is an ACCEPT. */
    {
        nodus_v2_envelope_t  e0;
        dna_env_preflight_t *pf0 = calloc(1, sizeof(*pf0));
        sqlite3_stmt        *stmt = NULL;

        CHECK(pf0 != NULL, "alloc");
        CHECK(cap_ctx_build(g.w, bctx) == 0, "H: context");
        e0.env_bytes = small[0].bytes;
        e0.env_len   = small[0].len;
        CHECK(nodus_witness_v2_env_preflight_batch(g.w, 1, bctx->rulesets,
                                                   bctx->n_rulesets, &e0, 1,
                                                   pf0, NULL, NULL)
                  == NODUS_V2_ENV_OK, "small[0]'s derived identities");
        CHECK(sqlite3_prepare_v2(g.w->db, "INSERT INTO v2_intent_index "
                                 "(intent_id, tx_id, global_height, "
                                 "global_index) VALUES (?1, ?2, 0, 0)", -1,
                                 &stmt, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(stmt, 1, pf0->intent_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, pf0->wire_id, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(stmt) == SQLITE_DONE, "mark small[0] committed");
        sqlite3_finalize(stmt);
        free(pf0);

        ftx[0].data = small[1].bytes; ftx[0].len = small[1].len;   /* fresh */
        ftx[1].data = small[0].bytes; ftx[1].len = small[0].len;   /* replay */
        CHECK(hf3_process(app, ftx, 2) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
              "H: Process REJECTs a block carrying an already-committed "
              "envelope");
        CHECK(hf3_process(app, ftx, 1) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
              "H: the same block without it is ACCEPTed");
        kept = hf3_prepare(app, ftx, 2, &resp);
        CHECK(kept == 1 && resp.txs[0].data == small[1].bytes,
              "H: Prepare's drop loop excludes exactly the replay");
        CHECK(hf3_sql(g.w, "UPDATE chain_config_history SET effective_block "
                           "= 2 WHERE param_id = 8") == 0, "row -> @2");
        CHECK(hf3_process(app, ftx, 2) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
              "H-1: the same block is ACCEPTed — no seam replay check below "
              "H (the item loop would refuse the item code 3, "
              "test_v2_apply test_hf3_engine)");
        CHECK(hf3_sql(g.w, "UPDATE chain_config_history SET effective_block "
                           "= 1 WHERE param_id = 8") == 0, "row -> @1");
    }

    /* ── (4) rule 4: a non-zero CORE units quota stays a block bound ─ */
    {
        dna_domain_manifest_t man, qman;
        dna_domreg_record_t   rec;
        uint8_t               enc[DNA_DOMMAN_MAX_ENC_LEN], mh[64];
        uint8_t               recb[DNA_DOMREG_REC_ENC_LEN];
        size_t                el = 0;
        sqlite3_stmt         *stmt = NULL;

        CHECK(nodus_witness_domreg_get(g.w, DNA_DOMAIN_CORE, &rec, &man,
                                       NULL) == 0, "the CORE manifest");
        qman = man;
        qman.quota_verify_cost = 5;     /* covers no real leg's reservation */
        CHECK(dna_domman_encode(&qman, enc, sizeof(enc), &el) == 0 &&
              dna_domman_hash(&qman, mh) == 0, "the quota manifest");
        memcpy(rec.current_manifest_hash, mh, 64);
        CHECK(dna_domreg_record_encode(&rec, recb) == 0, "the record");
        CHECK(sqlite3_prepare_v2(g.w->db, "UPDATE domain_registry SET "
                                 "record=?1, current_manifest=?2 WHERE "
                                 "domain_id=?3", -1, &stmt, NULL)
                  == SQLITE_OK, "prep");
        sqlite3_bind_blob(stmt, 1, recb, sizeof(recb), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, enc, (int)el, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)DNA_DOMAIN_CORE);
        CHECK(sqlite3_step(stmt) == SQLITE_DONE, "write the quota manifest");
        sqlite3_finalize(stmt);

        CHECK(cap_ctx_build(g.w, bctx) == 0 && bctx->hf3_active == 1,
              "H: context");
        for (i = 0; i < bctx->budget.n_domains; i++) {
            if (bctx->budget.dom[i].domain_id == DNA_DOMAIN_CORE) {
                CHECK(bctx->budget.dom[i].unbounded == 0 &&
                      bctx->budget.dom[i].remaining_units == 5,
                      "H: a non-zero quota keeps its real budget");
            }
        }
        /* small[1], not small[0]: (3b) marked small[0] committed, and a
         * replay refusal would mask the quota's */
        ftx[0].data = small[1].bytes; ftx[0].len = small[1].len;
        CHECK(hf3_process(app, ftx, 1) == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
              "H: the non-zero units quota still refuses the block at "
              "Process (rule 4, decided A)");
    }

    /* ── (5) an unreadable price at H is a FAULT ───────────────────── */
    CHECK(hf3_sql(g.w, "DELETE FROM chain_config_history WHERE "
                       "param_id = 5 AND effective_block = 1") == 0 &&
          hf3_sql(g.w, "ALTER TABLE chain_config_history RENAME TO "
                       "cch_raw") == 0 &&
          hf3_sql(g.w, "ALTER TABLE cch_raw ADD COLUMN bad INTEGER NOT "
                       "NULL DEFAULT 0") == 0 &&
          hf3_sql(g.w, "CREATE VIEW chain_config_history AS SELECT "
                       "param_id, CASE WHEN bad = 1 THEN "
                       "abs(-9223372036854775808) ELSE new_value END AS "
                       "new_value, effective_block, commit_block, tx_hash, "
                       "proposal_nonce, created_at_unix FROM cch_raw") == 0,
          "the chain_config view");
    CHECK(hf3_process(app, &ftx[3], 1) == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
          "the view answers every read while no row is poisoned (the "
          "non-vacuity leg)");
    CHECK(hf3_sql(g.w, "INSERT INTO cch_raw (param_id, new_value, "
                       "effective_block, commit_block, tx_hash, "
                       "proposal_nonce, created_at_unix, bad) VALUES "
                       "(5, 1, 1, 0, zeroblob(64), 9905, 0, 1)") == 0,
          "a param-5 row that raises when evaluated");
    CHECK(hf3_process(app, &ftx[3], 1) == -1,
          "H: an unreadable gas price is a node FAULT, never a verdict");

    free(cc.bytes);
    free(small);
    free(call);
    free(txs);
    free(envs);
    free(bctx);
    nodus_cmt_app_ledger_release(app);
    free(app);
    gfx_close(&g);
    return 0;
}

/* ══ main ════════════════════════════════════════════════════════════ */

/* ══ HF-9 WP4 — the HYBRID generation-6 blockexec probe ═════════════════
 *
 * What it is: a PROBE that only BUILDS the fixture plan :455 (T-15) needs
 * and asserts each prerequisite on its own labelled CHECK, so a run shows
 * exactly which step of the route breaks. No T-15 case yet.
 *
 * The route: the chain is seeded the way test_hf9_edge.c:340-371 seeds it
 * (v2x_seed_prepare, the chain_config ladder rows BEFORE v2x_seed_genesis
 * - rows written after the production genesis would move SYSTEM's
 * chain_config_root and trip the untouched-domain guard), but with the
 * committee's REAL g_ks public keys, installed through the config hook of
 * v2_genesis_fixture.h (g_v2x_cfg_hook), so the REAL blockexec of
 * exec_init can sign and apply blocks over it. The cometbft document is
 * projected from the very config the ledger was seeded from (gfx_doc), and
 * exec_init builds and saves the cometbft State itself.
 *
 * Proves, step by step: P1 the hook gives the committee the g_ks keys;
 * P2 the database and the ladder rows exist before the genesis; P3 the
 * seeded genesis (a version-3 chain with the g_ks committee in
 * `validators`); P4 the node identity and the committed root; P5 exec_init
 * (store, real application, blockexec, State saved: stateKey); P6 the
 * ladder rows survived the genesis; P7 a block 1 made over the real State
 * with a COMPLETE BlockID; P8 the block applies through
 * nodus_cmt_host_apply_verified_block and the ledger holds block 1.
 *
 * Flags: none beyond the file's (NODUS_EVM_ENABLED for the generation
 * constants). Leaves: a /tmp/test_cmt_app_hyb_XXXXXX directory (removed by
 * gfx_close). Can falsely pass: a probe passing means the route holds for
 * ONE empty block at height 1, not that generation 6 is reached - the
 * ladder heights (3..14) are not crossed here; the T-15 cases will.
 */
static void hyb_cfg_hook(nodus_v2_gen_config_t *c)
{
    for (uint16_t i = 0; i < c->n_validators && i < (uint16_t)N_KEYS; i++) {
        memcpy(c->validators[i].pubkey, g_ks[i].pk, DNAC_PUBKEY_SIZE);
    }
}

static int hyb_cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                      uint64_t effective, uint64_t nonce)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int t_hybrid_probe(void)
{
    gfx_t          g;
    exec_t         x;
    cmt_block_id_t bid;
    v2x_cfgbox_t   hb;
    uint8_t        file16[16];
    uint8_t        root[64];

    memset(&g, 0, sizeof(g));
    memset(&hb, 0, sizeof(hb));
    snprintf(g.dir, sizeof(g.dir), "/tmp/test_cmt_app_hyb_XXXXXX");
    CHECK(mkdtemp(g.dir) != NULL, "P0 a temp directory");

    /* P1 — the config hook: the committee is the g_ks keys */
    g_v2x_cfg_hook = hyb_cfg_hook;
    CHECK(v2x_cfg_make(&hb, 0) == 0, "P1a the v2x config builds");
    CHECK(hb.cfg->n_validators == (uint16_t)N_KEYS &&
          memcmp(hb.cfg->validators[0].pubkey, g_ks[0].pk,
                 DNAC_PUBKEY_SIZE) == 0 &&
          memcmp(hb.cfg->validators[N_KEYS - 1].pubkey, g_ks[N_KEYS - 1].pk,
                 DNAC_PUBKEY_SIZE) == 0,
          "P1b the hook gave the committee the real g_ks public keys");
    g.box.cfg    = hb.cfg;        /* ownership moves to g.box (gfx_close) */
    g.box.allocs = hb.allocs;

    /* P2 — database + the ladder rows BEFORE the genesis (edge test) */
    g.w = calloc(1, sizeof(*g.w));
    g.srv = calloc(1, sizeof(*g.srv));
    CHECK(g.w && g.srv, "P2a heap");
    snprintf(g.w->data_path, sizeof(g.w->data_path), "%s", g.dir);
    memset(file16, 0x5A, sizeof(file16));
    CHECK(v2x_seed_prepare(g.w, file16, 0) == 0,
          "P2b v2x_seed_prepare (an S20 version-3 database)");
    CHECK(hyb_cc_row(g.w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
              == 0 &&
          hyb_cc_row(g.w, DNAC_CFG_RULESET_GEN2,
                     (uint64_t)DNAC_CFG_RULESET_GEN2_D2, 3, 12) == 0 &&
          hyb_cc_row(g.w, DNAC_CFG_EVM_ACTIVE,
                     (uint64_t)DNAC_CFG_EVM_ACTIVE_D, 5, 14) == 0 &&
          hyb_cc_row(g.w, DNAC_CFG_RULESET_GEN_ROLES,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, 8, 13) == 0 &&
          hyb_cc_row(g.w, DNAC_CFG_RULESET_GEN_ROOTS,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 11, 15) == 0 &&
          hyb_cc_row(g.w, DNAC_CFG_RULESET_GEN_TRIE,
                     (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, 14, 16) == 0,
          "P2c the generation ladder rows (params 9/14/18/22/24) before "
          "the genesis");

    /* P3 — the seeded genesis over the same config */
    CHECK(v2x_seed_genesis(g.w, file16, 0, NULL, 0, g.chain32) == 0,
          "P3a v2x_seed_genesis (the engine genesis over the g_ks config)");
    g_v2x_cfg_hook = NULL;
    CHECK(g.w->v2_successor, "P3b the chain is a version-3 chain");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM validators") == N_KEYS,
          "P3c the committee rows are the config's validators");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 0,
          "P3d no block row yet");

    /* P4 — the node identity the fixture gives every gfx chain, and the
     * committed root the document's app_hash is made from */
    g.w->cached_committee_epoch_start = UINT64_MAX;
    g.w->v2_ingress_armed = true;
    memcpy(g.w->v2_chain32, g.chain32, 32);
    memcpy(g.srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(g.srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(g.srv->identity.node_id.bytes, g_ks[0].voter, 32);
    nodus_server_witness_host(g.srv, &g.host);
    g.w->host = &g.host;
    memcpy(g.w->my_id, g_ks[0].voter, 32);
    CHECK(nodus_witness_v2_committed_global_root(g.w, root) == 0,
          "P4 the committed global root reads");

    /* P5 — the real blockexec + application, State saved */
    CHECK(exec_init(&x, &g) == 0,
          "P5a exec_init: store, real application, blockexec, State made "
          "from the projected genesis document");
    CHECK(has_state_key(g.w->db, "stateKey") == 1,
          "P5b the cometbft State at height 0 is saved (stateKey)");

    /* P6 — the ladder rows survived the genesis */
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM chain_config_history WHERE "
                      "param_id = 24") == 1 &&
          q1(g.w->db, "SELECT effective_block FROM chain_config_history "
                      "WHERE param_id = 24") == 14,
          "P6 the param-24 ladder row is still there");

    /* P7 / P8 — one empty block through the real blockexec */
    CHECK(exec_make_block(&x, 1, 0) == 0, "P7a block 1 over the real State");
    CHECK(exec_block_id(&x, x.blk, &bid) == 0 && block_id_is_complete(&bid),
          "P7b a COMPLETE BlockID");
    CHECK(nodus_cmt_host_apply_verified_block(x.be, &bid, x.blk, x.state)
              == CMT_OK,
          "P8a the block applies through the real blockexec");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1,
          "P8b the ledger holds block 1");

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ HF-9 WP4 — T-15: recovery after commit, before the consensus-state
 *    save, on the HYBRID generation-6 chain (plan :455) ══════════════════
 *
 * Proves, for a stop at (i) the edge block A-1 = 13, (ii) an ordinary
 * generation-6 block (15) and (iii) the first generation-6 boundary B1 (the
 * block DNAC_EPOCH_LENGTH; no storage member exists on this chain, so the
 * boundary has NO storage event - the "with an event" variant needs a
 * registered node and is not built here, T-5 registry writer):
 *   S1  nodus_cmt_blockexec_t.test_fail_after_commit stops
 *       nodus_cmt_host_apply_verified_block with CMT_FAULT AFTER the ledger
 *       COMMIT and BEFORE store.Save(state) (nodus_witness_cmt_host.c:1764)
 *       - the false-pass guard: the stop is at the intended height (the
 *       ledger tip = the stop height), the COMMIT ran (autocommit on), the
 *       saved State still names height-1 and the block store holds it;
 *   S2  the stopped node's ledger digest equals a twin node that applied
 *       the same block without stopping (the block IS committed);
 *   S3  the handshake (replay.go:437-453) replays ONE block; the ledger
 *       digest is unchanged by it (not applied twice) - the digest covers
 *       v2_trie_roots, v2_trie_nodes, the six section-8.4 tables, the
 *       supply totals, v2_blocks and the domain heads;
 *   S4  the State caught up; every leg root (v2_trie_roots) equals the
 *       incremental AND the full rebuild of the rows;
 *   S5  the NEXT block applies on both nodes and their ledger digests and
 *       committed roots are equal (the replayed node = a node that never
 *       stopped).
 * Block counts: 13, 15 and DNAC_EPOCH_LENGTH (720 at production, 15 at the
 * short-epoch build) real signed blocks per node, two nodes per case; the
 * run time is main's to measure. Flags: NODUS_EVM_ENABLED only (the tries).
 * Leaves: two /tmp/test_cmt_app_hyb_XXXXXX directories per case (removed).
 * Can falsely pass: the digest hashes the listed tables, not the whole
 * database; the committee tiebreak seed, mempool and consensus tables are
 * not compared. The block-store save precedes the apply here (consensus
 * order), unlike vu_host_drive_to which saves after.
 */
#ifdef NODUS_EVM_ENABLED
typedef struct {
    gfx_t          g;
    exec_t         x;
    cmt_block_id_t bid;
    size_t         ntx;     /* transactions x.txs[0..ntx) of the NEXT block
                             * made by hyb_pair_step (reset to 0 after) */
} hyb_t;

/* HF-9 WP4 (funding probe, step a): the coins a funded hybrid chain gets
 * BEFORE the genesis, as test_storage_b2.c fx_open :1540-1590 plants them
 * (utxo_set rows, owner = the key's SHA3-512 fingerprint in lower-case hex,
 * native token, domain 1). Nothing else is planted: v2x_seed_rows
 * (v2_genesis_fixture.h ~700-840) itself seeds the committee (the hook's
 * g_ks keys), the supply_tracking row ("absent: created with
 * genesis_supply = UTXOs + bonds + delegated") and the nine v2_treasury
 * rows, so the coins join the supply by construction. */
#define HYB_COIN_BOND  (1000000ULL * 100000000ULL)   /* DNAC_HF6_STORAGE_
                                                      * BOND_DEFAULT      */
#define HYB_N_COINS    2

static void hyb_coin_nul(int c, uint8_t out[64])
{
    uint8_t pre[16] = "hf9-wp4-hyb-coin";

    pre[15] = (uint8_t)c;
    qgp_sha3_512(pre, sizeof(pre), out);
}

/* Coin 2 exists only on a chain opened with funded == 2: the FEE-only coin
 * of key 1's STORAGE_EXIT envelope (test_storage_b2.c COINS CBX = FEE, owner
 * = the exiting node's key); coins 0 and 1 belong to keys 0 and 1. */
#define HYB_EXIT_COIN  2
/* Coin 3 exists only on a chain opened with funded == 3: the registration
 * coin of key 2, a SECOND storage node that arrives after the first
 * publication (the K9a grace case of hybrid_storage_writers_probe). */
#define HYB_ARRIVAL_COIN  3

static int hyb_coin_key(int c)
{
    return c == HYB_EXIT_COIN ? 1 : c == HYB_ARRIVAL_COIN ? 2 : c;
}

/* BOND + FEE exactly, as test_storage_b2.c COINS: the SYSFUND leg consumes
 * the whole coin - the bond is locked, the rest is the envelope fee. The
 * exit coin is the fee alone (the exit's SYSFUND leg locks / releases
 * nothing: nodus_witness_rt_native.c rtn_storage_exit_exec ":6470"). */
static uint64_t hyb_coin_amount(int c)
{
    return c == HYB_EXIT_COIN ? (uint64_t)DNAC_MIN_FEE_RAW
                              : HYB_COIN_BOND + (uint64_t)DNAC_MIN_FEE_RAW;
}

static int hyb_coin_owner_hex(int key, char hex[129])
{
    uint8_t fp[64];

    if (qgp_sha3_512(g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0)
        return -1;
    for (int i = 0; i < 64; i++)
        snprintf(hex + 2 * i, 3, "%02x", fp[i]);
    return 0;
}

static int hyb_seed_coin(nodus_witness_t *w, int c)
{
    sqlite3_stmt *st = NULL;
    uint8_t       nul[64];
    char          hex[129];
    int           rc;

    hyb_coin_nul(c, nul);
    if (hyb_coin_owner_hex(hyb_coin_key(c), hex) != 0) return -1;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)hyb_coin_amount(c));
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* History for the growth probe (T-9): `g_hyb_filler` extra ordinary UTXOs
 * planted BEFORE the genesis next to the coins, read once by the next
 * hyb_open (which resets it to 0). Each is a state production can produce -
 * a one-unit UTXO with its own nullifier and owner - and joins the supply
 * by construction exactly like the coins (v2x seeds genesis_supply = UTXOs
 * + stakes + delegated); no supply, per-open or schema check is bypassed.
 * Nullifier and owner are deterministic SHA3-512 of a counter. */
static unsigned g_hyb_filler;
/* RELEASED registry nodes planted the same way (see hyb_plant_released) */
static unsigned g_hyb_released;
static int hyb_plant_released(nodus_witness_t *w, unsigned n);

static int hyb_seed_filler(nodus_witness_t *w, unsigned n)
{
    sqlite3_stmt *st = NULL;
    int           rc = SQLITE_DONE;

    if (sqlite3_exec(w->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) return -1;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, 1, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    for (unsigned i = 0; i < n && rc == SQLITE_DONE; i++) {
        uint8_t pre[24], nul[64], fp[64];
        char    hex[129];

        memcpy(pre, "hf9-wp4-hyb-fill", 16);
        for (int b = 0; b < 8; b++) pre[16 + b] = (uint8_t)((uint64_t)i >> (8 * (7 - b)));
        if (qgp_sha3_512(pre, sizeof(pre), nul) != 0) { rc = SQLITE_ERROR; break; }
        memcpy(pre, "hf9-wp4-hyb-fown", 16);
        if (qgp_sha3_512(pre, sizeof(pre), fp) != 0) { rc = SQLITE_ERROR; break; }
        for (int b = 0; b < 64; b++) snprintf(hex + 2 * b, 3, "%02x", fp[b]);
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, hex, 128, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return sqlite3_exec(w->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* funded: 0 unfunded; 1 coins 0 and 1; 2 also the exit coin (HYB_EXIT_COIN);
 * 3 also the arrival coin (HYB_ARRIVAL_COIN) */
static int hyb_open(hyb_t *h, int funded)
{
    v2x_cfgbox_t hb;
    uint8_t      file16[16];

    memset(h, 0, sizeof(*h));
    memset(&hb, 0, sizeof(hb));
    snprintf(h->g.dir, sizeof(h->g.dir), "/tmp/test_cmt_app_hyb_XXXXXX");
    CHECK(mkdtemp(h->g.dir) != NULL, "hyb: a temp directory");
    g_v2x_cfg_hook = hyb_cfg_hook;
    CHECK(v2x_cfg_make(&hb, 0) == 0, "hyb: the config builds");
    h->g.box.cfg    = hb.cfg;
    h->g.box.allocs = hb.allocs;
    h->g.w   = calloc(1, sizeof(*h->g.w));
    h->g.srv = calloc(1, sizeof(*h->g.srv));
    CHECK(h->g.w && h->g.srv, "hyb: heap");
    snprintf(h->g.w->data_path, sizeof(h->g.w->data_path), "%s", h->g.dir);
    memset(file16, 0x5A, sizeof(file16));
    CHECK(v2x_seed_prepare(h->g.w, file16, 0) == 0, "hyb: seed_prepare");
    CHECK(hyb_cc_row(h->g.w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1,
                     11) == 0 &&
          hyb_cc_row(h->g.w, DNAC_CFG_RULESET_GEN2,
                     (uint64_t)DNAC_CFG_RULESET_GEN2_D2, 3, 12) == 0 &&
          hyb_cc_row(h->g.w, DNAC_CFG_EVM_ACTIVE,
                     (uint64_t)DNAC_CFG_EVM_ACTIVE_D, 5, 14) == 0 &&
          hyb_cc_row(h->g.w, DNAC_CFG_RULESET_GEN_ROLES,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, 8, 13) == 0 &&
          hyb_cc_row(h->g.w, DNAC_CFG_RULESET_GEN_ROOTS,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 11, 15) == 0 &&
          hyb_cc_row(h->g.w, DNAC_CFG_RULESET_GEN_TRIE,
                     (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, 14, 16) == 0,
          "hyb: the ladder rows before the genesis");
    if (funded) {
        for (int c = 0; c < HYB_N_COINS; c++)
            CHECK(hyb_seed_coin(h->g.w, c) == 0, "hyb: a coin before the "
                  "genesis");
        if (funded == 2)
            CHECK(hyb_seed_coin(h->g.w, HYB_EXIT_COIN) == 0,
                  "hyb: the exit coin before the genesis");
        if (funded == 3)
            CHECK(hyb_seed_coin(h->g.w, HYB_ARRIVAL_COIN) == 0,
                  "hyb: the arrival coin before the genesis");
        CHECK(hyb_seed_filler(h->g.w, g_hyb_filler) == 0,
              "hyb: the history UTXOs before the genesis");
        CHECK(hyb_plant_released(h->g.w, g_hyb_released) == 0,
              "hyb: the released registry history before the genesis");
        v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);   /* one-shot */
    }
    CHECK(funded || (g_hyb_filler == 0 && g_hyb_released == 0),
          "hyb: history rows need a funded chain");
    g_hyb_filler = 0;
    g_hyb_released = 0;
    CHECK(v2x_seed_genesis(h->g.w, file16, 0, NULL, 0, h->g.chain32) == 0,
          "hyb: the seeded genesis");
    g_v2x_cfg_hook = NULL;
    h->g.w->cached_committee_epoch_start = UINT64_MAX;
    h->g.w->v2_ingress_armed = true;
    memcpy(h->g.w->v2_chain32, h->g.chain32, 32);
    memcpy(h->g.srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(h->g.srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(h->g.srv->identity.node_id.bytes, g_ks[0].voter, 32);
    nodus_server_witness_host(h->g.srv, &h->g.host);
    h->g.w->host = &h->g.host;
    memcpy(h->g.w->my_id, g_ks[0].voter, 32);
    CHECK(exec_init(&h->x, &h->g) == 0, "hyb: exec_init");
    h->x.vote_ts_step_ns = 1;   /* strictly increasing block times */
    return 0;
}

static void hyb_close(hyb_t *h)
{
    exec_free(&h->x);
    gfx_close(&h->g);
}

/* ROUND 19 - the hybrid cases at the short-epoch setting (E = 15) as well as at production
 * constants (E = 720). Several of them put "the boundary" at DNAC_EPOCH_LENGTH only because that
 * is the FIRST boundary at production; they now take it from the fixture:
 *   HYB_A_GEN6 = 14  the generation-6 activation of hyb_open's ladder: its last row is
 *                    hyb_cc_row(w, DNAC_CFG_RULESET_GEN_TRIE, D, 14, 16), i.e. effective_block = 14
 *                    (the param-24 row's effective height A; nonce 16) - read back by
 *                    t_hybrid_probe P6 ("effective_block ... == 14") and the edge is the end of
 *                    block A - 1 = 13 (test_hf9_edge.c HA);
 *   HYB_REG_BLK  = 16 the block of the first registration (hyb_register_step(.., 16, ..)).
 * hyb_boundary_above(h) is the first epoch boundary above h: DNAC_EPOCH_LENGTH (720) for both at
 * production, 15 above 14 and 30 above 16 at E = 15. */
#define HYB_A_GEN6  14u
#define HYB_REG_BLK 16u
static uint64_t hyb_boundary_above(uint64_t h)
{
    const uint64_t e = (uint64_t)DNAC_EPOCH_LENGTH;

    return (h / e + 1u) * e;
}

/* digest of the tables the replay must leave byte-identical */
static int hyb_digest(sqlite3 *db, uint8_t out[64])
{
    static const char *const tabs[] = {
        "v2_trie_roots", "v2_trie_nodes", "v2_storage_assign",
        "v2_storage_assign_basis", "v2_storage_assign_state",
        "v2_storage_held", "v2_storage_member_epoch",
        "v2_storage_xfer_diff", "v2_supply_totals", "v2_bond_total",
        "v2_blocks", "v2_domain_heads"
    };
    size_t   cap = 1u << 16, n = 0;
    uint8_t *buf = malloc(cap);
    int      bad = buf == NULL;

    for (size_t t = 0; t < sizeof(tabs) / sizeof(tabs[0]) && !bad; t++) {
        sqlite3_stmt *st = NULL;
        char          sql[400];
        int           cols, rc = SQLITE_DONE;

        snprintf(sql, sizeof(sql), "SELECT * FROM %s LIMIT 0", tabs[t]);
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
            /* Sol re-verify row 7: the ONLY table allowed to be absent is
             * the one-use v2_storage_xfer_diff (dropped at the first
             * generation-6 boundary), and only when sqlite_master really
             * has no such table; any other failure fails the digest */
            sqlite3_stmt *ms = NULL;
            int           absent = 0;

            if (strcmp(tabs[t], "v2_storage_xfer_diff") == 0 &&
                sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM sqlite_master "
                                   "WHERE type = 'table' AND name = "
                                   "'v2_storage_xfer_diff'", -1, &ms, NULL)
                    == SQLITE_OK) {
                absent = sqlite3_step(ms) == SQLITE_ROW &&
                         sqlite3_column_int(ms, 0) == 0;
                sqlite3_finalize(ms);
            }
            if (!absent) bad = 1;
            continue;
        }
        cols = sqlite3_column_count(st);
        sqlite3_finalize(st);
        {
            size_t off = (size_t)snprintf(sql, sizeof(sql),
                                          "SELECT * FROM %s ORDER BY ",
                                          tabs[t]);
            for (int c = 1; c <= cols && off < sizeof(sql) - 8; c++) {
                off += (size_t)snprintf(sql + off, sizeof(sql) - off,
                                        c > 1 ? ",%d" : "%d", c);
            }
        }
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
            bad = 1;
            break;
        }
        if (n + strlen(tabs[t]) + 2 > cap) { cap *= 2; buf = realloc(buf, cap); }
        memcpy(buf + n, tabs[t], strlen(tabs[t]) + 1);
        n += strlen(tabs[t]) + 1;
        while (!bad && (rc = sqlite3_step(st)) == SQLITE_ROW) {
            for (int c = 0; c < cols && !bad; c++) {
                int ty = sqlite3_column_type(st, c);
                int len = ty == SQLITE_NULL ? 0 : sqlite3_column_bytes(st, c);
                const void *p = ty == SQLITE_BLOB ? sqlite3_column_blob(st, c)
                    : ty == SQLITE_NULL ? NULL
                    : (const void *)sqlite3_column_text(st, c);
                while (n + 5 + (size_t)len > cap) {
                    cap *= 2;
                    buf = realloc(buf, cap);
                    if (!buf) { bad = 1; break; }
                }
                if (bad) break;
                buf[n++] = (uint8_t)ty;
                for (int i = 0; i < 4; i++) buf[n++] = (uint8_t)(len >> (8 * i));
                if (p && len > 0) { memcpy(buf + n, p, (size_t)len); n += (size_t)len; }
            }
            if (!bad) buf[n++] = 0xFF;
        }
        sqlite3_finalize(st);
        if (!bad && rc != SQLITE_DONE) bad = 1;   /* a truncated scan */
    }
    if (bad) { free(buf); return -1; }
    {
        int r = qgp_sha3_512(buf, n, out) == 0 ? 0 : -1;
        free(buf);
        return r;
    }
}

/* one block at `height` the CONSENSUS way: last commit, block, BlockID with
 * its part set, SAVE to the block store, then APPLY. @return the apply's rc
 * (CMT_OK / CMT_FAULT), or -2 on a setup failure */
/* ONE block at `height`, made ONCE (by node A: last commit, block, BlockID,
 * part set - ML-DSA signing is randomized, so two nodes that each built
 * their own block would build different bytes) and applied to BOTH nodes
 * the consensus way (save to the block store, then apply): node B first,
 * then node A, which stops after its COMMIT when `a_stop` is set.
 * @return A's apply rc (CMT_OK / CMT_FAULT), -2 on a setup failure, -3
 * when node B's save or apply failed. */
static int hyb_pair_step(hyb_t *A, hyb_t *B, int64_t height, int a_stop)
{
    exec_t        *x = &A->x;
    const size_t   save_cap = 1u << 20;
    uint8_t       *save_scratch = malloc(save_cap);
    cmt_part_set_t ps;
    cmt_commit_t   seen;
    int            rc = -2;

    if (!save_scratch) return -2;
    if (height > 1 && exec_make_last_commit(x, height - 1, &A->bid) != 0)
        goto done;
    {
        const size_t ntx = A->ntx;

        A->ntx = 0;
        if (exec_make_block(x, height, ntx) != 0) goto done;
    }
    memset(&A->bid, 0, sizeof(A->bid));
    if (cmt_block_hash(x->blk, A->bid.hash) != CMT_OK) goto done;
    A->bid.hash_len = CMT_TMHASH_SIZE;
    if (cmt_block_make_part_set(x->blk, CMT_BLOCK_PART_SIZE_BYTES,
                                x->part_scratch, x->part_scratch_cap,
                                x->parts, x->parts_cap, &ps) != CMT_OK ||
        cmt_part_set_header(&ps, &A->bid.part_set_header) != CMT_OK ||
        !block_id_is_complete(&A->bid))
        goto done;
    memset(&seen, 0, sizeof(seen));
    seen.height   = height;
    seen.round    = 0;
    seen.block_id = A->bid;
    if (B) {
        if (nodus_cmt_bs_save_block(B->x.store, x->blk, &ps, &seen,
                                    save_scratch, save_cap) != CMT_OK ||
            nodus_cmt_host_apply_verified_block(B->x.be, &A->bid, x->blk,
                                                B->x.state) != CMT_OK) {
            rc = -3;
            goto done;
        }
    }
    if (nodus_cmt_bs_save_block(x->store, x->blk, &ps, &seen, save_scratch,
                                save_cap) != CMT_OK)
        goto done;
    x->be->test_fail_after_commit = a_stop ? true : false;
    rc = nodus_cmt_host_apply_verified_block(x->be, &A->bid, x->blk, x->state);
    x->be->test_fail_after_commit = false;
done:
    free(save_scratch);
    return rc;
}

/* blocks from+1 .. to on both nodes, no stop */
static int hyb_pair_to(hyb_t *A, hyb_t *B, int64_t from, int64_t to)
{
    for (int64_t h = from + 1; h <= to; h++) {
        if (hyb_pair_step(A, B, h, 0) != CMT_OK) {
            fprintf(stderr, "hyb_pair_to: height %" PRId64 " failed\n", h);
            return -1;
        }
    }
    return 0;
}

static int hyb_handshake(hyb_t *h, int *nblocks)
{
    nodus_cmt_handshaker_t *hs = calloc(1, sizeof(*hs));
    nodus_cmt_host_limits_t lim;
    int                     rc;

    if (!hs) return CMT_FAULT;
    memset(&lim, 0, sizeof(lim));
    lim.max_txs      = TEST_APP_TXS_CAP;
    lim.tx_arena_cap = 2u * 1024u * 1024u;
    lim.max_evidence = 4;
    rc = nodus_cmt_handshaker_init(hs, h->x.store, h->x.state, &h->x.doc,
                                   h->g.w, t_now, NULL, t_mono, NULL, &lim);
    if (rc == CMT_OK) {
        rc = nodus_cmt_handshaker_handshake(hs, &h->x.app_if);
        if (nblocks) *nblocks = hs->nblocks;
    }
    nodus_cmt_handshaker_release(hs);
    free(hs);
    return rc;
}

/* every leg root: stored == incremental == full rebuild of the rows */
static int hyb_legs_ok(nodus_witness_t *w)
{
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++) {
        uint8_t inc[64], full[64], stored[64];

        if (nodus_witness_v2_trie_build_leg(w, leg, inc, full) != 0 ||
            nodus_witness_v2_trie_leg_root(w, leg, stored) != 0 ||
            memcmp(inc, full, 64) != 0 || memcmp(inc, stored, 64) != 0)
            return -1;
    }
    return 0;
}

static int hyb_register_step(hyb_t *A, hyb_t *B, int64_t height, int key,
                             uint8_t **env);

/* `reg` != 0: the chain is FUNDED and node key 1 registers as a storage
 * node in block `reg` (generation 6) on both nodes before the stop, so the
 * boundary of the stop block is a storage EVENT (an arrival against the
 * empty basis; plan :455 "with and without a storage event"). `reg` is a
 * block number >= HYB_A_GEN6 (generation 6 is in force from block 14), 0 =
 * no registration. */
static int hyb_case(int64_t stop_h, const char *what, int64_t reg)
{
    hyb_t  *A = calloc(1, sizeof(*A)), *Bn = calloc(1, sizeof(*Bn));
    uint8_t d0a[64], d0b[64], d1a[64], d1b[64], d2a[64], d3a[64], d3b[64];
    uint8_t ra[64], rb[64];
    uint8_t *renv = NULL;
    int     nb = -1, rc;

    CHECK(A && Bn, "alloc");
    CHECK(hyb_open(A, reg != 0) == 0, "S0 node A (stops) opens");
    CHECK(hyb_open(Bn, reg != 0) == 0, "S0 node B (never stops) opens");
    /* every block is made ONCE (by A) and applied to both nodes: the same
     * bytes (signing is randomized, two builders would differ) */
    if (reg) {
        CHECK(reg >= (int64_t)HYB_A_GEN6,
              "the registration block is a generation-6 block");
        CHECK(stop_h > reg, "the stop lies after the registration block");
        CHECK(hyb_pair_to(A, Bn, 0, reg - 1) == 0,
              "S0 both nodes reach the block before the registration, same "
              "blocks");
        CHECK(hyb_register_step(A, Bn, reg, 1, &renv) == CMT_OK,
              "S0 the STORAGE_REGISTER block applies on both nodes");
        CHECK(q1(A->g.w->db, "SELECT COUNT(*) FROM v2_storage_nodes WHERE "
                             "status = 1") == 1 &&
              q1(Bn->g.w->db, "SELECT COUNT(*) FROM v2_storage_nodes WHERE "
                              "status = 1") == 1,
              "S0 the registry row is ACTIVE on both nodes");
        CHECK(hyb_pair_to(A, Bn, reg, stop_h - 1) == 0,
              "S0 both nodes reach the block before the stop");
    } else {
        CHECK(hyb_pair_to(A, Bn, 0, stop_h - 1) == 0,
              "S0 both nodes reach the block before the stop, on the same "
              "blocks");
    }
    CHECK(hyb_digest(A->g.w->db, d0a) == 0 &&
          hyb_digest(Bn->g.w->db, d0b) == 0 && memcmp(d0a, d0b, 64) == 0,
          "S0 the twins are byte-identical before the stop block");

    /* S1 — the stop */
    rc = hyb_pair_step(A, Bn, stop_h, 1);   /* B applies it, A stops */
    CHECK(rc != -3, "S1 node B applied the stop block");
    CHECK(rc == CMT_FAULT,
          "S1a the apply stops with CMT_FAULT in the post-commit window");
    CHECK(sqlite3_get_autocommit(A->g.w->db) != 0,
          "S1b the COMMIT had run");
    CHECK(q1(A->g.w->db, "SELECT MAX(global_height) FROM v2_blocks") ==
              stop_h,
          "S1c the ledger tip is the intended stop height");
    CHECK(nodus_cmt_bs_height(A->x.store) == stop_h,
          "S1d the block store holds the stopped block");
    {
        cmt_state_storage_t *stor = calloc(1, sizeof(*stor));
        cmt_state_t         *st = calloc(1, sizeof(*st));

        CHECK(stor && st && cmt_state_init(st, stor) == CMT_OK &&
              nodus_cmt_ss_load(A->x.store, st) == CMT_OK,
              "S1e the saved State loads");
        CHECK(st->last_block_height == stop_h - 1,
              "S1f the saved State still names the previous height");
        free(st);
        free(stor);
    }
    CHECK(hyb_digest(A->g.w->db, d1a) == 0, "S1g digest of A after the stop");

    /* S2 — the twin applied the SAME block without stopping */
    CHECK(q1(Bn->g.w->db, "SELECT MAX(global_height) FROM v2_blocks") ==
              stop_h && sqlite3_get_autocommit(Bn->g.w->db) != 0,
          "S2a node B committed the stop height normally");
    CHECK(hyb_digest(Bn->g.w->db, d1b) == 0 && memcmp(d1a, d1b, 64) == 0,
          "S2b the stopped node's ledger = the node that never stopped");

    /* S3 — the replay */
    CHECK(hyb_handshake(A, &nb) == CMT_OK, "S3a the handshake heals");
    CHECK(nb == 1, "S3b exactly one block replayed");
    CHECK(hyb_digest(A->g.w->db, d2a) == 0 && memcmp(d1a, d2a, 64) == 0,
          "S3c the ledger tables are byte-identical after the replay "
          "(v2_trie_roots, v2_trie_nodes, the assignment tables, the supply "
          "totals): not applied twice");
    {
        cmt_state_storage_t *stor = calloc(1, sizeof(*stor));
        cmt_state_t         *st = calloc(1, sizeof(*st));

        CHECK(stor && st && cmt_state_init(st, stor) == CMT_OK &&
              nodus_cmt_ss_load(A->x.store, st) == CMT_OK &&
              st->last_block_height == stop_h,
              "S3d the State caught up to the stop height");
        free(st);
        free(stor);
    }
    /* S4 — roots against the full rebuild */
    CHECK(q1(A->g.w->db, "SELECT capture FROM v2_trie_state") == 1,
          "S4a the dirty capture is on");
    CHECK(hyb_legs_ok(A->g.w) == 0,
          "S4b every leg root equals the incremental and the full rebuild");

    /* S5 — the next block */
    CHECK(nodus_cmt_ss_load(A->x.store, A->x.state) == CMT_OK,
          "S5a the executor's State is the caught-up one");
    CHECK(hyb_pair_to(A, Bn, stop_h, stop_h + 1) == 0,
          "S5b the next block, made once, applies on the replayed node A "
          "and on node B");
    CHECK(hyb_digest(A->g.w->db, d3a) == 0 &&
          hyb_digest(Bn->g.w->db, d3b) == 0 && memcmp(d3a, d3b, 64) == 0,
          "S5d the next block: the replayed node's tables = the node that "
          "never stopped");
    CHECK(nodus_witness_v2_committed_global_root(A->g.w, ra) == 0 &&
          nodus_witness_v2_committed_global_root(Bn->g.w, rb) == 0 &&
          memcmp(ra, rb, 64) == 0, "S5e and so is the committed global root");
    (void)what;
    free(renv);
    hyb_close(Bn);
    hyb_close(A);
    free(Bn);
    free(A);
    return 0;
}

static int t_hyb_crash_edge(void)
{
    return hyb_case(13, "the edge block A-1", 0);
}

static int t_hyb_crash_ordinary(void)
{
    /* block 15 at production; at E = 15 block 15 IS the first boundary, so the ORDINARY block is 16
     * (round 19: the case was labelled "ordinary" but ran the boundary there) */
    const int64_t h = (15 % DNAC_EPOCH_LENGTH == 0) ? 16 : 15;

    return hyb_case(h, "an ordinary generation-6 block", 0);
}

/* The first generation-6 boundary B1 of hyb_open's ladder: the first boundary above the
 * generation-6 activation HYB_A_GEN6 (720 at production, 15 at E = 15). Round 19: the guard
 * E > 16 is replaced by this derivation; at E = 720 the stop height is E, as before. */
static int t_hyb_crash_boundary(void)
{
    return hyb_case((int64_t)hyb_boundary_above(HYB_A_GEN6),
                    "the first generation-6 boundary B1, no storage event",
                    0);
}

/* (iii) WITH a storage event: a registered node makes B1 an event, and the stop is B1 itself, the
 * first generation-6 boundary hyb_boundary_above(HYB_A_GEN6): 720 at production, 15 at E = 15
 * (round 20: round 19 stopped at the SECOND boundary, 30, at E = 15). The registration block
 * must lie in (A, B1): HYB_REG_BLK = 16 when E > 16 (as before); at E = 15 B1 = 15 = A + 1, so the
 * registration is block A = 14, the first generation-6 block (the registry is generation 6 from
 * the end of block A - 1 = 13; the STORAGE_REGISTER rule, rtn_storage_register_exec
 * nodus_witness_rt_native.c:6313, tests no height other than the bond and the consent expiry at
 * h, and hyb_register_env builds both at the block's own height). hyb_case CHECKs reg >= A and
 * stop > reg. */
static int t_hyb_crash_boundary_event(void)
{
    const int64_t b1  = (int64_t)hyb_boundary_above(HYB_A_GEN6);
    const int64_t reg = ((int64_t)HYB_REG_BLK < b1) ? (int64_t)HYB_REG_BLK
                                                    : (int64_t)HYB_A_GEN6;

    return hyb_case(b1, "B1 with a storage event (one registered node)", reg);
}

/* ══ HF-9 WP7 round 17 - the TEMPORARY boundary leg-root log line ═════════
 *
 * Operator decision 2026-11-06 (docs/plans/decisions/2026-11-06-hf9-boundary-
 * leg-root-log.md): at each epoch boundary under generation 6 the node writes
 *   HF9-BOUNDARY-ROOTS h=<H> global=<128 hex> leg1=<128 hex> ... leg8=<...>
 * to its log (nodus_cmt_app_commit, after the COMMIT). The line is TEMPORARY;
 * its removal is the operator's word, and this test goes with it.
 *
 * Proves, on the hybrid chain of hyb_open (generation 6 in force from block 13):
 *   L1  the Commit of the ordinary generation-6 block E - 1 writes NO line;
 *   L2  the Commit of the boundary block E (the first generation-6 boundary
 *       B1; no storage event) writes EXACTLY ONE line, with h = E, a global
 *       root equal to nodus_witness_v2_committed_global_root and the eight
 *       leg roots equal to the v2_trie_roots rows read by SQL;
 *   L3  nodus_cmt_app_boundary_root_line, called directly, returns that same
 *       text at E, and returns 0 (no line) at the non-boundary heights E - 1
 *       and E + 1 and at height 0;
 *   L4  the Commit of block E + 1 writes no line;
 *   L5  a boundary height under a generation BELOW 6 yields no line: a fresh
 *       chain at its genesis (the SYSTEM runtime resolves and is below
 *       NODUS_RT_GEN_TRIE - read, so the 0 is the generation rule and not an
 *       unresolved runtime) answers 0 at height E.
 * CAPTURE: the line is read from what the Commit really writes. The nodus
 * standalone build links nodus_log_shim.c, whose qgp_log_ring_add prints
 * every QGP_LOG_* line to stderr (there is no ring buffer in that build; the
 * real qgp_log.c ring truncates a message at QGP_LOG_MSG_MAX_LEN = 256 bytes,
 * shared/crypto/utils/qgp_log.c:231, and its file writer at 1024, :677 - both
 * shorter than the ~1250-byte line), so stderr is redirected into a temp file
 * around one block step (dup2) and scanned. L3 is the formatting function
 * itself, visible through nodus_witness_cmt_app.h.
 * Compile flags: NODUS_EVM_ENABLED (the tries). Round 19: the boundary block is
 * the first epoch boundary above the ladder's generation-6 activation
 * (hyb_boundary_above(HYB_A_GEN6)): 720 at production constants and 15 at the
 * short-epoch setting (-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
 * -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
 * -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15), so L1-L5 run at both; the
 * stepped blocks are B - 2 (setup), B - 1 (14 at E = 15: the first
 * generation-6 block, ordinary), B and B + 1. At production it runs 721 real
 * blocks; the harness scenario test_cmt_hf9.sh (check_boundary_leg_log, 7 logs
 * per boundary) is the node-level comparison. Environment: none. ONE-LINE PROPERTY (the node holds
 * flockfile(stderr) across the log call): no deterministic unit test exists -
 * the interleaving needs a second thread logging at the exact moment, so a test
 * would pass or fail by scheduling; the lock is argued in the comment at the log
 * site in nodus_cmt_app_commit and observed by the harness comparison. Leaves: one
 * /tmp/test_cmt_app_hyb_XXXXXX directory per chain (removed) and a tmpfile.
 * Can falsely pass: a log sink other than the shim (the real qgp_log.c with
 * file logging on) is not exercised, so L2 proves the standalone node's
 * stderr line, not a truncated one; the line is node-local text, never a
 * consensus byte; the below-generation-6 case is shown at a genesis chain,
 * not at a boundary block of a generation-5 chain.
 */
static char *blr_capture_block(hyb_t *A, int64_t height)
{
    FILE  *f;
    char  *buf = NULL;
    long   n;
    int    saved, rc;

    fflush(stderr);
    f = tmpfile();
    saved = dup(2);
    if (!f || saved < 0) { if (f) fclose(f); return NULL; }
    dup2(fileno(f), 2);
    rc = hyb_pair_step(A, NULL, height, 0);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    fflush(f);
    n = ftell(f);
    if (rc == CMT_OK && n >= 0) {
        buf = calloc((size_t)n + 1, 1);
        if (buf) {
            rewind(f);
            if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); buf = NULL; }
        }
    }
    fclose(f);
    return buf;
}

static int blr_count(const char *buf, const char *needle)
{
    int c = 0;

    for (const char *p = buf; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        c++;
    return c;
}

static int blr_leg_hex(sqlite3 *db, int leg, char out[129])
{
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (sqlite3_prepare_v2(db, "SELECT lower(hex(root)) FROM v2_trie_roots "
                               "WHERE leg = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, leg);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 128) {
        memcpy(out, sqlite3_column_text(st, 0), 128);
        out[128] = '\0';
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int t_hyb_boundary_leg_root_log(void)
{
    /* the boundary block: the first epoch boundary above the ladder's generation-6 activation
     * (HYB_A_GEN6): 720 at production, 15 at E = 15 (round 19; named E below as before) */
    const int64_t E = (int64_t)hyb_boundary_above(HYB_A_GEN6);
    hyb_t   *A = calloc(1, sizeof(*A)), *C = calloc(1, sizeof(*C));
    char    *cap_before, *cap_b, *cap_after, *at;
    char     line[NODUS_CMT_BOUNDARY_ROOT_LINE_MAX], expect[NODUS_CMT_BOUNDARY_ROOT_LINE_MAX];
    char     hx[129], gx[129];
    uint8_t  gr[64];
    size_t   n;
    const nodus_domain_runtime_t *rt = NULL;

    CHECK(A && C, "alloc");
    CHECK(E > (int64_t)HYB_A_GEN6,
          "the boundary lies above the ladder's generation-6 activation");
    CHECK(hyb_open(A, 0) == 0, "L0 node opens");
    CHECK(hyb_pair_to(A, NULL, 0, E - 2) == 0, "L0 blocks 1 .. E - 2");

    cap_before = blr_capture_block(A, E - 1);
    CHECK(cap_before != NULL, "L1 block E - 1 applies");
    CHECK(blr_count(cap_before, "HF9-BOUNDARY-ROOTS") == 0,
          "L1 an ordinary generation-6 block writes NO boundary line");
    free(cap_before);

    cap_b = blr_capture_block(A, E);
    CHECK(cap_b != NULL, "L2 the boundary block E applies");
    CHECK(blr_count(cap_b, "HF9-BOUNDARY-ROOTS") == 1,
          "L2 the generation-6 boundary Commit writes EXACTLY ONE line");
    at = strstr(cap_b, "HF9-BOUNDARY-ROOTS");
    CHECK(at != NULL, "L2 the line is there");
    n = strcspn(at, "\n");
    CHECK(n < sizeof(line), "L2 the line fits its bound");
    memcpy(line, at, n);
    line[n] = '\0';
    free(cap_b);

    CHECK(nodus_witness_v2_committed_global_root(A->g.w, gr) == 0, "L2 the committed global root reads");
    {
        static const char hexd[] = "0123456789abcdef";
        for (int i = 0; i < 64; i++) { gx[2 * i] = hexd[gr[i] >> 4]; gx[2 * i + 1] = hexd[gr[i] & 15]; }
        gx[128] = '\0';
    }
    n = (size_t)snprintf(expect, sizeof(expect), "HF9-BOUNDARY-ROOTS h=%" PRId64 " global=%s", E, gx);
    for (int l = 1; l <= 8; l++) {
        CHECK(blr_leg_hex(A->g.w->db, l, hx) == 0, "L2 the v2_trie_roots row reads");
        n += (size_t)snprintf(expect + n, sizeof(expect) - n, " leg%d=%s", l, hx);
    }
    CHECK(strcmp(line, expect) == 0,
          "L2 the line = h, the committed global root and the eight v2_trie_roots rows, full 128 hex each");

    CHECK(nodus_cmt_app_boundary_root_line(A->g.w, (uint64_t)E, line, sizeof(line)) == 1 &&
          strcmp(line, expect) == 0, "L3 the function returns the same text at E");
    CHECK(nodus_cmt_app_boundary_root_line(A->g.w, (uint64_t)E - 1, line, sizeof(line)) == 0 &&
          nodus_cmt_app_boundary_root_line(A->g.w, (uint64_t)E + 1, line, sizeof(line)) == 0 &&
          nodus_cmt_app_boundary_root_line(A->g.w, 0, line, sizeof(line)) == 0,
          "L3 no line at a non-boundary height or at 0");

    cap_after = blr_capture_block(A, E + 1);
    CHECK(cap_after != NULL, "L4 block E + 1 applies");
    CHECK(blr_count(cap_after, "HF9-BOUNDARY-ROOTS") == 0, "L4 the block after the boundary writes no line");
    free(cap_after);
    hyb_close(A);
    free(A);

    CHECK(hyb_open(C, 0) == 0, "L5 a fresh chain at its genesis opens");
    CHECK(nodus_witness_v2_runtime_for(C->g.w, DNA_DOMAIN_SYSTEM, 0, &rt) == 0 && rt &&
          rt->generation < NODUS_RT_GEN_TRIE,
          "L5 the SYSTEM runtime resolves and is below generation 6");
    CHECK(nodus_cmt_app_boundary_root_line(C->g.w, (uint64_t)E, line, sizeof(line)) == 0,
          "L5 a boundary height under a generation below 6 yields no line");
    hyb_close(C);
    free(C);
    return 0;
}

/* ══ HF-9 WP5 - T-15 (iv): a block during the SHADOW RUN (plan :455; the
 *    shadow run is plan §11, capture = 0, shadow running) ═════════════════
 *
 * Proves, on the hybrid chain (the ladder of hyb_open: generation 5 is
 * committed from block 10, the edge is block 13), node A with hf9_shadow on
 * and the shadow hook bound on ITS executor (the node binds it the same way,
 * nodus_witness_cmt_node.c), twin node B without a shadow:
 *   P1  the hook is reached through the real host path: after blocks 1..10
 *       the shadow is seeded (status running, one log row at 10); capture
 *       is 0 (the shadow never switches it);
 *   P2  stop at block 11 with test_fail_after_commit (the fault point
 *       between COMMIT and store.Save): the stop is at the intended height
 *       (ledger tip 11, COMMIT ran, State names 10), the HOOK DID NOT RUN
 *       (no log row at 11), and A's ledger tables equal B's (digest of
 *       hyb_digest);
 *   P3  the handshake replays ONE block; the ledger digest (v2_trie_roots,
 *       v2_trie_nodes, the assignment tables, the supply totals, blocks,
 *       heads) is byte-identical before and after the replay - not applied
 *       twice - and the replay called no hook: shadow roots, row copy and
 *       log are untouched;
 *   P4  the next block (12) applies on both nodes; A's hook runs: ONE new
 *       log row at 12 and NONE at 11 (the next pass covered the missed
 *       height in one step); every shadow leg root equals the full rebuild
 *       of the rows; A's ledger digest and committed global root equal B's
 *       (a node that never stopped); capture is still 0.
 * Flags: NODUS_EVM_ENABLED only. Leaves: two /tmp/test_cmt_app_hyb_XXXXXX
 * directories (removed). Can falsely pass: the blocks carry no row change
 * (idle blocks), so the catch-up is proven here as "the pass after the
 * replay runs, covers both heights and equals the rebuild", while a pass
 * that applies changes is test_hf9_shadow.c A / F; the hook's wiring on the
 * node's executor (not the test's) is test_cmt_node.c.
 */
/* The full rebuild writes nodes to the CONSENSUS v2_trie_nodes (the build is
 * the edge's), which must stay empty on a pre-edge chain: it runs inside a
 * transaction that is rolled back, and the caller digests the ledger around
 * the call. */
static int hyb_shadow_roots_equal_rebuild(nodus_witness_t *w)
{
    int ret = 0;

    if (sqlite3_exec(w->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) return -1;
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS && ret == 0; leg++) {
        uint8_t sh[64], inc[64], full[64];

        if (nodus_witness_v2_trie_shadow_leg_root(w, leg, sh) != 0 ||
            nodus_witness_v2_trie_build_leg(w, leg, inc, full) != 0 ||
            memcmp(sh, full, 64) != 0 || memcmp(inc, full, 64) != 0)
            ret = -1;
    }
    if (sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
        ret = -1;
    return ret;
}

/* The log row of `height` against the expected values, all 64 bytes of each
 * (Sol re-verify row 14): the eight legs and CORE v4' / STOR v3' / SYS v7'
 * as the CONSENSUS code computes them after a simulated activation of the
 * same rows (build_all + the consensus compositions in a rolled-back
 * transaction), and GLOBAL v2' composed here from the committed
 * v2_domain_heads (SYSTEM / CORE roots replaced), the committed
 * last_upd_hash column and the committed replay root through the shared
 * dnac primitives (plan §6 :217, §11 :424) - not by the code under test.
 * 0 = all equal. */
static int hyb_log_matches(nodus_witness_t *w, uint64_t height)
{
    nodus_v2_shadow_log_t row;
    uint8_t core[64], stor[64], sys[64], stored[NODUS_V2_TRIE_LEGS][64];
    dna_v2_domain_head_t heads[8];
    uint8_t luh[8][64], domains[64], replay[64], glob[64];
    size_t n = 0;
    sqlite3_stmt *st = NULL;
    int rc, ok;

    if (nodus_witness_v2_shadow_log_read(w, height, &row) != 1) return 1;
    if (sqlite3_exec(w->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) return 2;
    ok = nodus_witness_v2_trie_build_all(w) == 0 &&
         nodus_witness_core_root_v4(w, core) == 0 &&
         nodus_witness_storage_root_v3(w, stor) == 0 &&
         nodus_witness_system_root_v7(w, sys) == 0;
    for (int leg = 1; ok && leg <= NODUS_V2_TRIE_LEGS; leg++)
        ok = nodus_witness_v2_trie_leg_root(w, leg, stored[leg - 1]) == 0;
    if (sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) return 3;
    if (!ok) return 4;
    for (int leg = 0; leg < NODUS_V2_TRIE_LEGS; leg++)
        if (memcmp(row.leg[leg], stored[leg], 64) != 0) return 10 + leg;
    if (memcmp(row.core, core, 64) != 0) return 20;
    if (memcmp(row.stor, stor, 64) != 0) return 21;
    if (memcmp(row.sys, sys, 64) != 0) return 22;

    if (sqlite3_prepare_v2(w->db, "SELECT head, last_upd_hash, "
            "typeof(last_upd_hash) FROM v2_domain_heads ORDER BY domain_id "
            "ASC", -1, &st, NULL) != SQLITE_OK) return 30;
    ok = 1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const uint8_t *b = sqlite3_column_blob(st, 0);
        const char *ty = (const char *)sqlite3_column_text(st, 2);
        dna_v2_domain_head_t *h = &heads[n < 8 ? n : 0];

        if (n >= 8 || !b ||
            sqlite3_column_bytes(st, 0) != DNA_V2_DOMHEAD_ENC_LEN ||
            !ty || strcmp(ty, "blob") != 0 ||
            sqlite3_column_bytes(st, 1) != 64) { ok = 0; break; }
        memset(h, 0, sizeof(*h));
        h->domain_id = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                       ((uint32_t)b[2] << 8) | b[3];
        memcpy(h->domain_state_root, b + 4, 64);
        for (int i = 0; i < 8; i++)
            h->domain_height = (h->domain_height << 8) | b[68 + i];
        for (int i = 0; i < 8; i++)
            h->last_updated_global_height =
                (h->last_updated_global_height << 8) | b[76 + i];
        h->ruleset_version = ((uint32_t)b[84] << 24) | ((uint32_t)b[85] << 16) |
                             ((uint32_t)b[86] << 8) | b[87];
        h->status = b[88];
        if (h->domain_id == DNA_DOMAIN_SYSTEM)
            memcpy(h->domain_state_root, sys, 64);
        else if (h->domain_id == DNA_DOMAIN_CORE)
            memcpy(h->domain_state_root, core, 64);
        memcpy(luh[n], sqlite3_column_blob(st, 1), 64);
        n++;
    }
    if (rc != SQLITE_DONE) ok = 0;
    sqlite3_finalize(st);
    if (!ok || n == 0) return 31;
    if (dna_v2_domains_root_v2(heads, (const uint8_t (*)[64])luh, n, domains)
            != 0 ||
        nodus_witness_replay_root(w, replay) != 0 ||
        dna_v2_global_root_v2(domains, replay, glob) != 0) return 32;
    return memcmp(row.glob, glob, 64) == 0 ? 0 : 33;
}

/* The row copy v2_trie_shadow_rows against the CURRENT rows (plan :424): for
 * every leg each row the build's own scan selects (canonical key, 64-byte
 * leaf hash) is in the copy with the same value and the copy holds no other
 * row of the leg. The expected side is the scan, never the copy. 0 = equal */
typedef struct {
    sqlite3_stmt *q;
    int           leg;
    long          n, bad;
} hyb_copy_t;

static int hyb_copy_row(void *vctx, const uint8_t *key, size_t key_len,
                        const uint8_t val[64])
{
    hyb_copy_t *c = (hyb_copy_t *)vctx;

    c->n++;
    if (sqlite3_reset(c->q) != SQLITE_OK ||
        sqlite3_clear_bindings(c->q) != SQLITE_OK ||
        sqlite3_bind_int(c->q, 1, c->leg) != SQLITE_OK ||
        sqlite3_bind_blob(c->q, 2, key, (int)key_len, SQLITE_STATIC)
            != SQLITE_OK) {
        c->bad++;
        return 0;
    }
    if (sqlite3_step(c->q) != SQLITE_ROW ||
        sqlite3_column_bytes(c->q, 0) != 64 ||
        memcmp(sqlite3_column_blob(c->q, 0), val, 64) != 0)
        c->bad++;
    return 0;
}

static int hyb_shadow_rows_match(nodus_witness_t *w)
{
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++) {
        hyb_copy_t c;
        char       sql[96];
        int        rc;

        memset(&c, 0, sizeof(c));
        c.leg = leg;
        if (sqlite3_prepare_v2(w->db, "SELECT value FROM "
                "v2_trie_shadow_rows WHERE leg = ?1 AND key = ?2", -1, &c.q,
                NULL) != SQLITE_OK) return -1;
        rc = nodus_witness_v2_trie_scan_leg(w, leg, hyb_copy_row, &c);
        sqlite3_finalize(c.q);
        if (rc != 0 || c.bad != 0) return leg;
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_trie_shadow_rows WHERE leg = %d", leg);
        if (q1(w->db, sql) != c.n) return 100 + leg;
    }
    return 0;
}

static int t_hyb_crash_shadow(void)
{
    hyb_t  *A = calloc(1, sizeof(*A)), *Bn = calloc(1, sizeof(*Bn));
    uint8_t d1a[64], d1b[64], d2a[64], d3a[64], d3b[64], ra[64], rb[64];
    uint8_t sh0[NODUS_V2_TRIE_LEGS][64], sh1[NODUS_V2_TRIE_LEGS][64];
    sqlite3_int64 rows0;
    nodus_v2_shadow_log_t row;
    int     nb = -1, rc;
    const int64_t stop_h = 11;

    CHECK(A && Bn, "alloc");
    CHECK(hyb_open(A, 0) == 0, "P0 node A (shadow, stops) opens");
    CHECK(hyb_open(Bn, 0) == 0, "P0 node B (no shadow, never stops) opens");
    A->g.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    CHECK(nodus_cmt_blockexec_set_block_saved_hook(
              A->x.be, nodus_witness_v2_shadow_after_commit, A->g.w)
              == CMT_OK, "P0 the hook is bound on A's executor");

    /* P1 - through the real host path */
    CHECK(hyb_pair_to(A, Bn, 0, 10) == 0, "P1 blocks 1..10 on both nodes");
    {
        int st = -2;

        CHECK(nodus_witness_v2_shadow_status(A->g.w, &st) == 0 &&
              st == NODUS_V2_SHADOW_RUNNING,
              "P1 the hook seeded the shadow: status running");
    }
    CHECK(nodus_witness_v2_shadow_log_read(A->g.w, 10, &row) == 1 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1,
          "P1 one log row, at the first generation-5 height (10)");
    CHECK(q1(A->g.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "P1 capture is 0 during the shadow run");
    CHECK(q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_dirty") == 0,
          "P1 nothing shadow-related in the block transaction: no dirty key");

    /* P2 - the stop between COMMIT and the state save */
    rc = hyb_pair_step(A, Bn, stop_h, 1);   /* B applies it, A stops */
    CHECK(rc != -3, "P2 node B applied the stop block");
    CHECK(rc == CMT_FAULT,
          "P2a the apply stops with CMT_FAULT in the post-commit window");
    CHECK(sqlite3_get_autocommit(A->g.w->db) != 0, "P2b the COMMIT had run");
    CHECK(q1(A->g.w->db, "SELECT MAX(global_height) FROM v2_blocks") ==
              stop_h, "P2c the ledger tip is the intended stop height");
    CHECK(nodus_witness_v2_shadow_log_read(A->g.w, (uint64_t)stop_h, &row)
              == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1,
          "P2d the hook did NOT run at the stop (no log row at 11)");
    CHECK(hyb_digest(A->g.w->db, d1a) == 0 &&
          hyb_digest(Bn->g.w->db, d1b) == 0 && memcmp(d1a, d1b, 64) == 0,
          "P2e the stopped node's ledger = the node that never stopped");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_shadow_leg_root(A->g.w, leg,
                                                    sh0[leg - 1]) == 0,
              "P2f shadow roots before the replay");
    rows0 = q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_rows");

    /* P3 - the replay */
    CHECK(hyb_handshake(A, &nb) == CMT_OK && nb == 1,
          "P3a the handshake replays exactly one block");
    CHECK(hyb_digest(A->g.w->db, d2a) == 0 && memcmp(d1a, d2a, 64) == 0,
          "P3b the ledger tables are byte-identical after the replay: not "
          "applied twice");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_shadow_leg_root(A->g.w, leg,
                                                    sh1[leg - 1]) == 0,
              "P3c shadow roots after the replay");
    CHECK(memcmp(sh0, sh1, sizeof(sh0)) == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_rows") == rows0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1,
          "P3d the replay called no hook: shadow roots, row copy and log "
          "untouched");

    /* P4 - the next block; the pass catches up */
    CHECK(nodus_cmt_ss_load(A->x.store, A->x.state) == CMT_OK,
          "P4a the executor's State is the caught-up one");
    CHECK(hyb_pair_to(A, Bn, stop_h, stop_h + 1) == 0,
          "P4b the next block, made once, applies on both nodes");
    CHECK(nodus_witness_v2_shadow_log_read(A->g.w, (uint64_t)stop_h + 1, &row)
              == 1 &&
          nodus_witness_v2_shadow_log_read(A->g.w, (uint64_t)stop_h, &row)
              == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 2,
          "P4c ONE new log row, at 12, none at 11: the pass covered the "
          "missed height in one step");
    CHECK(hyb_digest(A->g.w->db, d3a) == 0, "P4d0 digest before the rebuild");
    CHECK(hyb_shadow_roots_equal_rebuild(A->g.w) == 0,
          "P4d every shadow leg root equals the full rebuild of the rows");
    CHECK(hyb_digest(A->g.w->db, d2a) == 0 && memcmp(d2a, d3a, 64) == 0,
          "P4d1 the rolled-back rebuild left the ledger tables untouched "
          "(v2_trie_nodes stays empty before the edge)");
    CHECK(hyb_digest(Bn->g.w->db, d3b) == 0 && memcmp(d3a, d3b, 64) == 0,
          "P4e the replayed node's ledger tables = the node that never "
          "stopped");
    CHECK(nodus_witness_v2_committed_global_root(A->g.w, ra) == 0 &&
          nodus_witness_v2_committed_global_root(Bn->g.w, rb) == 0 &&
          memcmp(ra, rb, 64) == 0, "P4f and so is the committed global root");
    CHECK(q1(A->g.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "P4g capture is still 0");
    hyb_close(Bn);
    hyb_close(A);
    free(Bn);
    free(A);
    return 0;
}

#ifdef QGP_FAULT_INJECT
/* HF-9 WP5, plan T-10 "injected shadow fault -> block still commits, node
 * keeps running", THROUGH THE HOST: the shadow log write (injection point 3,
 * which fires on every pass, idle blocks included) is armed before block 11
 * of the hybrid chain on node A (hook bound, hf9_shadow on); the host's
 * apply returns CMT_OK, the ledger tip advances, the saved State names 11,
 * the shadow status is FAULTED, A's ledger tables equal the twin B's, and
 * the next block applies on both and still equals. Flags:
 * -DQGP_FAULT_INJECT=ON (absent otherwise = missing coverage). Leaves: two
 * /tmp/test_cmt_app_hyb_XXXXXX directories (removed). Can falsely pass: if
 * the injection point is never reached - asserted through the hit count. */
static int t_hyb_shadow_fault_host(void)
{
    hyb_t  *A = calloc(1, sizeof(*A)), *Bn = calloc(1, sizeof(*Bn));
    uint8_t da[64], db_[64];
    int     hits0, st = -2, rc;

    CHECK(A && Bn, "alloc");
    CHECK(hyb_open(A, 0) == 0 && hyb_open(Bn, 0) == 0, "Q0 both nodes open");
    A->g.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    CHECK(nodus_cmt_blockexec_set_block_saved_hook(
              A->x.be, nodus_witness_v2_shadow_after_commit, A->g.w)
              == CMT_OK, "Q0 the hook is bound on A's executor");
    CHECK(hyb_pair_to(A, Bn, 0, 10) == 0, "Q1 blocks 1..10 (seeded at 10)");
    CHECK(nodus_witness_v2_shadow_status(A->g.w, &st) == 0 &&
          st == NODUS_V2_SHADOW_RUNNING, "Q1 the shadow runs");

    hits0 = nodus_witness_v2_shadow_test_hits();
    CHECK(nodus_witness_v2_shadow_test_fault(3) == 0, "Q2 arm the log write");
    rc = hyb_pair_step(A, Bn, 11, 0);
    CHECK(rc == CMT_OK, "Q2a the host's apply of block 11 is CMT_OK although "
          "the shadow faulted");
    CHECK(nodus_witness_v2_shadow_test_hits() == hits0 + 1,
          "Q2b the injection point was reached (false-pass guard)");
    CHECK(q1(A->g.w->db, "SELECT MAX(global_height) FROM v2_blocks") == 11 &&
          sqlite3_get_autocommit(A->g.w->db) != 0,
          "Q2c the block is committed and no transaction is left open");
    {
        cmt_state_storage_t *stor = calloc(1, sizeof(*stor));
        cmt_state_t         *cs = calloc(1, sizeof(*cs));

        CHECK(stor && cs && cmt_state_init(cs, stor) == CMT_OK &&
              nodus_cmt_ss_load(A->x.store, cs) == CMT_OK &&
              cs->last_block_height == 11,
              "Q2d the consensus state was saved at 11");
        free(cs);
        free(stor);
    }
    CHECK(nodus_witness_v2_shadow_status(A->g.w, &st) == 0 &&
          st == NODUS_V2_SHADOW_FAULTED, "Q2e the shadow status is FAULTED");
    CHECK(hyb_digest(A->g.w->db, da) == 0 && hyb_digest(Bn->g.w->db, db_) == 0 &&
          memcmp(da, db_, 64) == 0,
          "Q2f the faulted node's ledger = the node without a shadow");
    CHECK(hyb_pair_to(A, Bn, 11, 12) == 0,
          "Q3 the node keeps running: block 12 applies on both");
    CHECK(hyb_digest(A->g.w->db, da) == 0 && hyb_digest(Bn->g.w->db, db_) == 0 &&
          memcmp(da, db_, 64) == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1,
          "Q3a ... equal again, and the faulted shadow logged nothing more");
    hyb_close(Bn);
    hyb_close(A);
    free(Bn);
    free(A);
    return 0;
}
#endif
/* ── the STORAGE_REGISTER envelope (step b), ported from test_storage_b2.c
 *    streg_call :1719-1745 and st_env :1747-1830: a 2-leg envelope, SYSTEM
 *    STORAGE_REGISTER (owner_fp ‖ node_pk ‖ consent_sig ‖ expiry ‖ bond,
 *    7299 B, the node is its own owner) + CORE SYSFUND over the coin (66
 *    B: in_count 1 ‖ nullifier ‖ out_count 0), both legs signed by the
 *    node's key (= the coin's owner). Built against the chain's CURRENT
 *    SYSTEM / CORE manifests (generation 6 after the edge). ─────────────── */
#define HYB_STREG_LEN  7299u
#define HYB_AUTH_LEN   (1u + NODUS_RT_AUTH_SIGNER_LEN)

static void hyb_put64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

static uint32_t hyb_streg_call(nodus_witness_t *w, uint8_t *dst, int key,
                               uint64_t height)
{
    static const uint8_t zero64[64] = { 0 };
    uint8_t  msg[DNA_VALBIND_MSG_LEN], fp[64];
    const uint64_t cexp = height + 10u;
    size_t   sl = 0, off = 0;

    if (qgp_sha3_512(g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0 ||
        dna_valbind_consent_msg(msg, w->v2_chain32,
                                DNA_VALBIND_OP_STORAGE_REGISTER, zero64, fp,
                                g_ks[key].pk, cexp) != 0)
        return 0;
    memcpy(dst, fp, 64);                                  off += 64;
    memcpy(dst + off, g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES);
    off += QGP_DSA87_PUBLICKEYBYTES;
    if (dna_valbind_consent_sign(dst + off, &sl, msg, g_ks[key].sk) != 0 ||
        sl != (size_t)DNA_VALBIND_SIG_LEN)
        return 0;
    off += DNA_VALBIND_SIG_LEN;
    hyb_put64(dst + off, cexp);                           off += 8;
    hyb_put64(dst + off, HYB_COIN_BOND);                  off += 8;
    return off == HYB_STREG_LEN ? HYB_STREG_LEN : 0;
}

/* A 2-leg storage envelope: SYSTEM `op` with the call `call` (call_len
 * bytes) + CORE SYSFUND over coin `coin`, both legs signed by node key
 * `key` (the node is its own owner and the coin's owner; test_storage_b2.c
 * st_env :1747). @return 0 and a heap envelope in *out (free()), or -1 */
static int hyb_storage_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                           const uint8_t *call, uint32_t call_len, int coin,
                           int key, uint8_t **out, size_t *out_len)
{
    static uint8_t fund[66];
    static uint8_t auth[2][HYB_AUTH_LEN];
    dna_domain_manifest_t sys, core;
    dna_env_leg_in_t      legs[2];
    dna_env_in_t          in;
    dna_env_leg_ctx_t     lctx[2];
    uint8_t               nul[64];
    size_t                len = 0, used = 0;
    uint8_t              *bytes = NULL;
    dna_env_preflight_t  *pf = NULL;
    int                   ok = -1;

    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL) != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    hyb_coin_nul(coin, nul);
    fund[0] = 1;
    memcpy(fund + 1, nul, 64);
    fund[65] = 0;
    memset(legs, 0, sizeof(legs));
    memset(auth, 0, sizeof(auth));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = HYB_AUTH_LEN;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = 66;
    legs[1].hdr.auth_len = HYB_AUTH_LEN;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = auth[1];
    memset(&in, 0, sizeof(in));
    in.fee_amount = (uint64_t)DNAC_MIN_FEE_RAW;
    /* inside the D2 window [height, height + 720] of the carrying block
     * (phase 0d refuses 0); same choice as 4320043cd and test_hf7_edge.c
     * :667 ("expiry A + 5") */
    in.expiry_height = height + 5u;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys.ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core.ruleset_hash, 64);

    if (dna_env_encoded_size(legs, 2, &len) != 0) return -1;
    bytes = malloc(len);
    pf = calloc(1, sizeof(*pf));
    do {
        int bad = 0;

        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        for (int L = 0; L < 2 && !bad; L++) {
            size_t sl = 0;

            auth[L][0] = 1;
            memcpy(auth[L] + 1, g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES);
            if (qgp_dsa87_sign(auth[L] + 1 + QGP_DSA87_PUBLICKEYBYTES, &sl,
                               pf->auth_digest[L], 64, g_ks[key].sk) != 0)
                bad = 1;
        }
        if (bad) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* @return 0 and a heap envelope in *out (free()), or -1: key `key`'s
 * STORAGE_REGISTER (coin = the key's own coin) */
static int hyb_register_env(nodus_witness_t *w, uint64_t height, int key,
                            uint8_t **out, size_t *out_len)
{
    static uint8_t call[HYB_STREG_LEN];

    *out = NULL;
    if (hyb_streg_call(w, call, key, height) != HYB_STREG_LEN) return -1;
    /* key 2's coin is the arrival coin (coin 2 is the exit coin of key 1) */
    return hyb_storage_env(w, height, DNA_SYSRULE_STORAGE_REGISTER, call,
                           HYB_STREG_LEN,
                           key == 2 ? HYB_ARRIVAL_COIN : key, key, out,
                           out_len);
}

/* @return 0 and a heap envelope in *out (free()), or -1: key `key`'s
 * STORAGE_EXIT, call node_fp ‖ owner_fp (128 B; the node is its own owner,
 * test_storage_b2.c :3029-3033), funded by the exit coin */
static int hyb_exit_env(nodus_witness_t *w, uint64_t height, int key,
                        uint8_t **out, size_t *out_len)
{
    uint8_t xcall[128];

    *out = NULL;
    if (qgp_sha3_512(g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES, xcall) != 0)
        return -1;
    memcpy(xcall + 64, xcall, 64);
    return hyb_storage_env(w, height, DNA_SYSRULE_STORAGE_EXIT, xcall, 128u,
                           HYB_EXIT_COIN, key, out, out_len);
}

/* Put the envelope `env` (elen bytes) into the NEXT block of the pair at
 * `height` and apply it (to B too when given). @return the apply rc */
static int hyb_tx_step(hyb_t *A, hyb_t *B, int64_t height, uint8_t *env,
                       size_t elen)
{
    A->x.txs[0].data = env;
    A->x.txs[0].len  = elen;
    A->ntx = 1;
    return hyb_pair_step(A, B, height, 0);
}

/* Put one registration for node key `key` into the NEXT block of the pair
 * at `height` and apply it (to B too when given). @return the apply rc
 * (CMT_OK) or -1 on a build failure. The envelope buffer is leaked into
 * `*env` for the caller to free after the step. */
static int hyb_register_step(hyb_t *A, hyb_t *B, int64_t height, int key,
                             uint8_t **env)
{
    size_t elen = 0;

    if (hyb_register_env(A->g.w, (uint64_t)height, key, env, &elen) != 0)
        return -1;
    return hyb_tx_step(A, B, height, *env, elen);
}

/* the same for key `key`'s STORAGE_EXIT */
static int hyb_exit_step(hyb_t *A, hyb_t *B, int64_t height, int key,
                         uint8_t **env)
{
    size_t elen = 0;

    if (hyb_exit_env(A->g.w, (uint64_t)height, key, env, &elen) != 0)
        return -1;
    return hyb_tx_step(A, B, height, *env, elen);
}

/* ══ HF-9 WP5 - T-15 (iv) WITH A COMMITTED ROW CHANGE (Sol verify row 12) ═
 *
 * The same stop as t_hyb_crash_shadow, but the stop block CARRIES a signed
 * STORAGE_REGISTER (op 7, a generation-4 op, valid under generation 5) on
 * the funded hybrid: the block that commits and then stops moves the
 * registry leg (leg 5), so the missed height has a real change in the
 * migrated rows.
 *   S1  after blocks 1..10 the shadow is seeded (log row at 10), the hook is
 *       bound on node A only, capture 0;
 *   S2  block 11 carries the registration; A stops after the COMMIT
 *       (test_fail_after_commit): the registry row exists on A and on B (the
 *       change IS committed), the hook did not run (no log row at 11), the
 *       shadow's registry root is STALE - it differs from the full rebuild
 *       of the rows (the control the missing change would otherwise hide);
 *   S3  the handshake replays one block; the ledger digest is unchanged and
 *       the shadow roots are still the stale ones;
 *   S4  block 12 (idle) applies on both nodes; A's pass catches up from the
 *       committed rows: ONE new log row at 12, none at 11; the registry
 *       shadow root MOVED and every leg equals the full rebuild; A's ledger
 *       and committed global root equal the node that never stopped.
 * Flags: NODUS_EVM_ENABLED. Leaves two /tmp/test_cmt_app_hyb_XXXXXX
 * directories (removed). Can falsely pass: if the registration is refused
 * under generation 5 the stop block carries no change - S2's registry-count
 * check and the stale-root control fail then (the case cannot pass without
 * a committed change). The hook is bound by the test (the node's own
 * binding is test_cmt_node.c t_block_saved_hook_bound). */
static int t_hyb_crash_shadow_rows(void)
{
    hyb_t   *A = calloc(1, sizeof(*A)), *Bn = calloc(1, sizeof(*Bn));
    uint8_t *env = NULL;
    size_t   elen = 0;
    uint8_t  d1a[64], d1b[64], d2a[64], d3a[64], d3b[64], ra[64], rb[64];
    uint8_t  seed5[64], stale5[64], now5[64], inc[64], full[64];
    nodus_v2_shadow_log_t row;
    int      nb = -1, rc;

    CHECK(A && Bn, "alloc");
    CHECK(hyb_open(A, 1) == 0 && hyb_open(Bn, 1) == 0,
          "S0 both funded nodes open");
    A->g.w->config.hf9_shadow = NODUS_HF9_SHADOW_ON;
    CHECK(nodus_cmt_blockexec_set_block_saved_hook(
              A->x.be, nodus_witness_v2_shadow_after_commit, A->g.w)
              == CMT_OK, "S0 the hook is bound on A's executor");
    CHECK(hyb_pair_to(A, Bn, 0, 10) == 0, "S1 blocks 1..10");
    CHECK(nodus_witness_v2_shadow_log_read(A->g.w, 10, &row) == 1 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1 &&
          q1(A->g.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "S1 seeded at 10, capture 0");
    CHECK(nodus_witness_v2_trie_shadow_leg_root(A->g.w, 5, seed5) == 0,
          "S1 the seeded registry root");

    /* S2 - the registration block, A stops after the COMMIT */
    CHECK(hyb_register_env(A->g.w, 11, 1, &env, &elen) == 0 && env,
          "S2 the envelope builds against the generation-5 manifests");
    A->x.txs[0].data = env;
    A->x.txs[0].len  = elen;
    A->ntx = 1;
    rc = hyb_pair_step(A, Bn, 11, 1);
    CHECK(rc != -3, "S2 node B applied the registration block");
    CHECK(rc == CMT_FAULT && sqlite3_get_autocommit(A->g.w->db) != 0 &&
          q1(A->g.w->db, "SELECT MAX(global_height) FROM v2_blocks") == 11,
          "S2 A stopped after the COMMIT at the intended height");
    CHECK(q1(A->g.w->db, "SELECT COUNT(*) FROM v2_storage_nodes") == 1 &&
          q1(Bn->g.w->db, "SELECT COUNT(*) FROM v2_storage_nodes") == 1,
          "S2 the registry row is committed on both nodes (a real change "
          "in the migrated rows)");
    CHECK(nodus_witness_v2_shadow_log_read(A->g.w, 11, &row) == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1,
          "S2 the hook did not run at the stop");
    CHECK(nodus_witness_v2_trie_shadow_leg_root(A->g.w, 5, stale5) == 0 &&
          memcmp(seed5, stale5, 64) == 0,
          "S2 the shadow registry root is still the seeded one");
    CHECK(sqlite3_exec(A->g.w->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
          nodus_witness_v2_trie_build_leg(A->g.w, 5, inc, full) == 0 &&
          sqlite3_exec(A->g.w->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK,
          "S2 the full rebuild of leg 5 (rolled back)");
    CHECK(memcmp(stale5, full, 64) != 0,
          "S2 control: the shadow root is STALE against the committed rows");
    CHECK(hyb_digest(A->g.w->db, d1a) == 0 && hyb_digest(Bn->g.w->db, d1b) == 0 &&
          memcmp(d1a, d1b, 64) == 0,
          "S2 the stopped node's ledger = the node that never stopped");

    /* S3 - the replay */
    CHECK(hyb_handshake(A, &nb) == CMT_OK && nb == 1, "S3 one block replayed");
    CHECK(hyb_digest(A->g.w->db, d2a) == 0 && memcmp(d1a, d2a, 64) == 0,
          "S3 the ledger tables are byte-identical after the replay");
    CHECK(nodus_witness_v2_trie_shadow_leg_root(A->g.w, 5, now5) == 0 &&
          memcmp(now5, seed5, 64) == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 1,
          "S3 the replay called no hook: the shadow is untouched");

    /* S4 - the next block; the pass catches up from the committed rows */
    CHECK(nodus_cmt_ss_load(A->x.store, A->x.state) == CMT_OK, "S4 State");
    CHECK(hyb_pair_to(A, Bn, 11, 12) == 0, "S4 block 12 applies on both");
    CHECK(nodus_witness_v2_shadow_log_read(A->g.w, 12, &row) == 1 &&
          nodus_witness_v2_shadow_log_read(A->g.w, 11, &row) == 0 &&
          q1(A->g.w->db, "SELECT COUNT(*) FROM v2_trie_shadow_log") == 2,
          "S4 ONE new log row, at 12, none at 11");
    CHECK(nodus_witness_v2_trie_shadow_leg_root(A->g.w, 5, now5) == 0 &&
          memcmp(now5, seed5, 64) != 0 && memcmp(now5, full, 64) == 0,
          "S4 the registry shadow root moved to the full rebuild of the "
          "committed rows");
    CHECK(hyb_shadow_rows_match(A->g.w) == 0,
          "S4 the row copy v2_trie_shadow_rows equals the selected rows "
          "(keys and leaf hashes, every leg), including the registry row");
    CHECK(hyb_digest(A->g.w->db, d3a) == 0, "S4 digest before the rebuild");
    CHECK(hyb_shadow_roots_equal_rebuild(A->g.w) == 0,
          "S4 every shadow leg equals the full rebuild");
    CHECK(hyb_log_matches(A->g.w, 12) == 0,
          "S4 the LOGGED legs, CORE / STOR / SYS and GLOBAL v2' of height 12 "
          "equal the expected values, all 64 bytes, after the committed "
          "registry change");
    CHECK(hyb_digest(A->g.w->db, d2a) == 0 && memcmp(d2a, d3a, 64) == 0,
          "S4 the rolled-back rebuild left the ledger untouched");
    CHECK(hyb_digest(Bn->g.w->db, d3b) == 0 && memcmp(d3a, d3b, 64) == 0,
          "S4 A's ledger = the node that never stopped");
    CHECK(nodus_witness_v2_committed_global_root(A->g.w, ra) == 0 &&
          nodus_witness_v2_committed_global_root(Bn->g.w, rb) == 0 &&
          memcmp(ra, rb, 64) == 0, "S4 and so is the committed global root");
    CHECK(q1(A->g.w->db, "SELECT capture FROM v2_trie_state") == 0,
          "S4 capture is still 0");
    free(env);
    hyb_close(Bn);
    hyb_close(A);
    free(Bn);
    free(A);
    return 0;
}

/* HF-9 WP4 — the FUNDED hybrid probe (step a of the registry-writer
 * route: plan :445 T-5, :449 T-9, :455 T-15 (iii) with a storage event all
 * need coins on the generation-6 chain). Builds the hybrid with two coins
 * planted before the genesis and asserts, one labelled CHECK each: F1 the
 * genesis still derives (hyb_open), F2 the coins are present and nothing
 * else is a UTXO, F3 the supply invariant (genesis_supply = current_supply
 * = UTXOs + validator stakes + delegated) and the committee / treasury rows
 * v2x seeded itself, F4 one empty block applies through the real blockexec
 * (the supply check runs inside the apply), F5 two more blocks with the
 * strictly increasing block times. Flags: NODUS_EVM_ENABLED. Leaves one
 * /tmp/test_cmt_app_hyb_XXXXXX (removed). Can falsely pass: it proves the
 * coins and the supply row survive genesis and three empty blocks, not
 * that a spend or a registration is accepted (steps b and c). */
static int t_hybrid_funded_probe(void)
{
    hyb_t *H = calloc(1, sizeof(*H));
    char   hex[129], sql[512];

    CHECK(H != NULL, "alloc");
    CHECK(hyb_open(H, 1) == 0,
          "F1 the funded hybrid derives (coins before the genesis, "
          "V2X_SEED_NOT_REAL_UTXOS)");
    for (int c = 0; c < HYB_N_COINS; c++) {
        uint8_t nul[64];
        sqlite3_stmt *st = NULL;
        int found = 0;

        hyb_coin_nul(c, nul);
        CHECK(hyb_coin_owner_hex(c, hex) == 0, "F2a owner hex");
        CHECK(sqlite3_prepare_v2(H->g.w->db,
                "SELECT amount, owner FROM utxo_set WHERE nullifier = ?1",
                -1, &st, NULL) == SQLITE_OK, "F2b prepare");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            found = (uint64_t)sqlite3_column_int64(st, 0) ==
                        hyb_coin_amount(c) &&
                    strcmp((const char *)sqlite3_column_text(st, 1), hex) == 0;
        }
        sqlite3_finalize(st);
        CHECK(found, "F2c the coin is present with its amount and owner "
                     "after the genesis");
    }
    CHECK(q1(H->g.w->db, "SELECT COUNT(*) FROM utxo_set") == HYB_N_COINS,
          "F2d the coins are the only UTXOs (the genesis wrote none)");
    snprintf(sql, sizeof(sql),
             "SELECT genesis_supply = current_supply AND genesis_supply = "
             "(SELECT COALESCE(SUM(amount),0) FROM utxo_set) + "
             "(SELECT COALESCE(SUM(self_stake),0) FROM validators) + "
             "(SELECT COALESCE(SUM(total_delegated),0) FROM validators) "
             "FROM supply_tracking WHERE id = 1");
    CHECK(q1(H->g.w->db, sql) == 1,
          "F3a the supply row = UTXOs + stakes + delegated (v2x seeded it)");
    CHECK(q1(H->g.w->db, "SELECT COUNT(*) FROM v2_treasury") ==
              (int64_t)NODUS_V2_GEN_TREASURY_POOLS &&
          q1(H->g.w->db, "SELECT COUNT(*) FROM validators") == N_KEYS,
          "F3b the nine treasury pools and the g_ks committee were seeded "
          "once, by v2x");
    CHECK(hyb_pair_to(H, NULL, 0, 1) == 0,
          "F4 one empty block applies through the real blockexec (supply "
          "check inside)");
    CHECK(q1(H->g.w->db, "SELECT COUNT(*) FROM v2_blocks") == 1 &&
          q1(H->g.w->db, "SELECT COUNT(*) FROM utxo_set") == HYB_N_COINS,
          "F4b block 1 committed, the coins untouched");
    CHECK(hyb_pair_to(H, NULL, 1, 3) == 0,
          "F5 blocks 2 and 3 apply (strictly increasing block times)");
    hyb_close(H);
    free(H);
    return 0;
}

/* HF-9 WP4 — step (b): ONE signed STORAGE_REGISTER at generation 6 through
 * the real blockexec on the funded hybrid, and T-5 (plan :445) for the
 * registry writer rtn_sys_mutate -> v2_storage_nodes (leg 5).
 * R1 blocks 1-15 apply (generation 6 from block 14); R2 the 2-leg envelope
 * builds and preflights against the CURRENT SYSTEM / CORE manifests; R3
 * block 16 carrying it applies; R4 the SYSFUND leg consumed the coin
 * (nullifier gone) and moved the bond into the supply's bond bucket; R5 the
 * registry row is ACTIVE, node_fp = SHA3-512(node_pk) of key 1, bond =
 * the STORAGE_BOND, registered_height 16; R6 the running bond total
 * (v2_bond_total) = the bond; R7 the supply invariant still holds; R8 leg 5
 * (registry) moved and every leg root equals the incremental and the full
 * rebuild after block 16 and after block 17. Flags: NODUS_EVM_ENABLED.
 * Leaves one /tmp/test_cmt_app_hyb_XXXXXX (removed). Can falsely pass: one
 * node, one registration; the exit / release path and the boundary are not
 * driven here (the boundary: the T-15 event case). */
static int t_hybrid_register_probe(void)
{
    hyb_t   *H = calloc(1, sizeof(*H));
    uint8_t *env = NULL;
    uint8_t  nul[64], fp[64];
    uint8_t  l0[8][64], l1[8][64];
    int      moved = 0;

    CHECK(H != NULL, "alloc");
    CHECK(hyb_open(H, 1) == 0, "R0 the funded hybrid derives");
    CHECK(hyb_pair_to(H, NULL, 0, 15) == 0,
          "R1 blocks 1-15 apply (generation 6 from block 14)");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l0[leg - 1]) == 0,
              "R1b leg roots read before the registration");
    CHECK(hyb_register_env(H->g.w, 16, 1, &env, &(size_t){ 0 }) == 0 && env,
          "R2 the STORAGE_REGISTER + SYSFUND envelope builds and "
          "preflights");
    free(env);
    env = NULL;
    CHECK(hyb_register_step(H, NULL, 16, 1, &env) == CMT_OK,
          "R3 the block carrying the envelope applies through the real "
          "blockexec");
    hyb_coin_nul(1, nul);
    {
        sqlite3_stmt *st = NULL;
        int gone = 0;

        CHECK(sqlite3_prepare_v2(H->g.w->db, "SELECT COUNT(*) FROM utxo_set "
              "WHERE nullifier = ?1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_STATIC);
        gone = sqlite3_step(st) == SQLITE_ROW &&
               sqlite3_column_int(st, 0) == 0;
        sqlite3_finalize(st);
        CHECK(gone, "R4 the SYSFUND leg consumed the registrant's coin");
    }
    CHECK(qgp_sha3_512(g_ks[1].pk, QGP_DSA87_PUBLICKEYBYTES, fp) == 0, "fp");
    {
        sqlite3_stmt *st = NULL;
        int ok = 0;

        CHECK(sqlite3_prepare_v2(H->g.w->db, "SELECT bond, status, "
              "registered_height, node_pk FROM v2_storage_nodes WHERE "
              "node_fp = ?1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            ok = (uint64_t)sqlite3_column_int64(st, 0) == HYB_COIN_BOND &&
                 sqlite3_column_int(st, 1) == 1 &&
                 sqlite3_column_int64(st, 2) == 16 &&
                 sqlite3_column_bytes(st, 3) == (int)QGP_DSA87_PUBLICKEYBYTES &&
                 memcmp(sqlite3_column_blob(st, 3), g_ks[1].pk,
                        QGP_DSA87_PUBLICKEYBYTES) == 0;
        }
        sqlite3_finalize(st);
        CHECK(ok, "R5 the registry row is ACTIVE under SHA3-512(node_pk), "
                  "bond = STORAGE_BOND, registered at 16");
    }
    CHECK(q1(H->g.w->db, "SELECT total FROM v2_bond_total WHERE id = 1") ==
              (int64_t)HYB_COIN_BOND,
          "R6 the running bond total is the bond");
    CHECK(q1(H->g.w->db,
             "SELECT genesis_supply - total_burned = current_supply FROM "
             "supply_tracking WHERE id = 1") >= 0,
          "R7a the supply row is readable");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l1[leg - 1]) == 0,
              "R8a leg roots read after the registration");
    for (int i = 0; i < 8; i++)
        if (memcmp(l0[i], l1[i], 64) != 0) moved |= 1 << i;
    CHECK((moved & 0x10) != 0,
          "R8b leg 5 (registry) moved with the registration");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "R8c every leg root equals the incremental and the full rebuild "
          "after block 16");
    CHECK(hyb_pair_to(H, NULL, 16, 17) == 0, "R8d block 17 applies");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "R8e and after block 17");
    free(env);
    hyb_close(H);
    free(H);
    return 0;
}

/* registry row of node key `key`: 0 and its status, exit_height and bond;
 * -1 if the row is absent */
static int hyb_node_row(nodus_witness_t *w, int key, int *status,
                        uint64_t *exit_h, uint64_t *bond)
{
    sqlite3_stmt *st = NULL;
    uint8_t       fp[64];
    int           rc = -1;

    if (qgp_sha3_512(g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0)
        return -1;
    if (sqlite3_prepare_v2(w->db, "SELECT status, exit_height, bond FROM "
                           "v2_storage_nodes WHERE node_fp = ?1", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *status = sqlite3_column_int(st, 0);
        *exit_h = (uint64_t)sqlite3_column_int64(st, 1);
        *bond   = (uint64_t)sqlite3_column_int64(st, 2);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/* HF-9 WP4 — registry EXIT and boundary RELEASE by real blocks (plan :445
 * "every writer path", T-5 for the registry writer's two remaining paths).
 * The release is NOT 12 epochs after the exit: the next boundary after the
 * exit releases the bond as ONE locked UTXO whose unlock height is
 * B + 12 E (nodus_witness_v2_storage.c st_release :1757-1810,
 * nodus_witness_rt_native.c :6474-6483); only the UNLOCK waits 12 epochs.
 * (The round-9 report said the release lands 12 epochs after the exit;
 * that was wrong, and this case needs 2E + 1 blocks, not 12E.)
 * Timeline on the funded hybrid (exit coin planted: hyb_open(H, 2)): X1
 * blocks 1-15; X2 key 1 registers in block 16 (ACTIVE, exit_height 0); X3
 * blocks up to the boundary E (an arrival event) apply and the row is still
 * ACTIVE; X4 STORAGE_EXIT in block E + 3 applies; X5 the row is EXITING
 * with exit_height E + 3, the exit coin is consumed, the running bond total
 * still counts the bond (EXITING counts), every leg root equals the
 * incremental and the full rebuild; X6 blocks to 2E - 1, bond bucket and
 * UTXO sum recorded; X7 the boundary 2E applies: the row is RELEASED, ONE
 * UTXO with the exit identity (tx_hash = exit_id, output index 201, owner =
 * the key's fingerprint hex, amount = the bond, block 2E, unlock 2E + 12 E)
 * exists, the bond bucket fell by the bond and the UTXO sum rose by it, the
 * UTXO leg (1) and the registry leg (5) moved, and every leg root equals
 * the incremental and the full rebuild; X8 block 2E + 1 applies and the leg
 * roots still equal the rebuild.
 * ROUND 19: "E" and "2E" above are B1 and B2 = B1 + E: B1 is the first
 * boundary above the registration block 16 (E = 720 at production, so B1 = E
 * and B2 = 2E and every assertion is as written; 30 and 45 at E = 15, where
 * the boundary 15 is applied inside X1 BEFORE the registration, an event-free
 * generation-6 boundary like hyb_crash_boundary_b1's). The exit block B1 + 3
 * needs E > 3. Flags: NODUS_EVM_ENABLED; compile constants of the two
 * settings (-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
 * -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
 * -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15, or none). One node: twins are the T-15 cases'
 * job. Leaves one /tmp/test_cmt_app_hyb_XXXXXX (removed). Can falsely pass:
 * the settlement of the boundary pays nothing here (no signed reports, pool
 * 1 unfunded: the F1 gate is not met), so the payout path is not run; the
 * node is released from the first epoch it was a member of. */
static int t_hybrid_exit_release_probe(void)
{
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    /* round 19: B1 = the arrival boundary = the first boundary above the registration block 16
     * (720 at production, 30 at E = 15); the exit lands at B1 + 3 and the release at the NEXT
     * boundary B2 = B1 + E (1440 = 2E at production). Was E and 2E. */
    const uint64_t B1 = hyb_boundary_above(HYB_REG_BLK), B2 = B1 + E;
    hyb_t   *H = calloc(1, sizeof(*H));
    uint8_t *renv = NULL, *xenv = NULL;
    uint8_t  nul[64], fp[64], xid[64], xnul[64];
    uint8_t  u0[8][64], u1[8][64];
    uint64_t bonds0 = 0, bonds1 = 0, exit_h = 0, bond = 0;
    int64_t  utxo0 = 0, utxo1 = 0;
    int      st = 0, moved = 0;
    char     hex[129];

    CHECK(E > 3, "the exit block B1 + 3 lies before the release boundary B1 + E");
    CHECK(H != NULL, "alloc");
    CHECK(hyb_open(H, 2) == 0, "X0 the funded hybrid with the exit coin");
    CHECK(hyb_pair_to(H, NULL, 0, 15) == 0, "X1 blocks 1-15 apply");
    CHECK(hyb_register_step(H, NULL, 16, 1, &renv) == CMT_OK,
          "X2a block 16 with the registration applies");
    CHECK(hyb_node_row(H->g.w, 1, &st, &exit_h, &bond) == 0 &&
          st == DNA_V2_STORAGE_ACTIVE && exit_h == 0 &&
          bond == HYB_COIN_BOND,
          "X2b the registry row is ACTIVE with exit_height 0");
    CHECK(hyb_pair_to(H, NULL, 16, (int64_t)B1) == 0,
          "X3a blocks up to the boundary B1 apply (arrival event)");
    CHECK(hyb_node_row(H->g.w, 1, &st, &exit_h, &bond) == 0 &&
          st == DNA_V2_STORAGE_ACTIVE,
          "X3b the row is still ACTIVE after the boundary E");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "X3c every leg root equals the rebuild after the boundary E");
    CHECK(hyb_pair_to(H, NULL, (int64_t)B1, (int64_t)B1 + 2) == 0,
          "X3d blocks B1+1 and B1+2 apply");
    CHECK(hyb_exit_step(H, NULL, (int64_t)B1 + 3, 1, &xenv) == CMT_OK,
          "X4 block B1+3 carrying the STORAGE_EXIT applies through the real "
          "blockexec");
    CHECK(hyb_node_row(H->g.w, 1, &st, &exit_h, &bond) == 0 &&
          st == DNA_V2_STORAGE_EXITING && exit_h == B1 + 3 &&
          bond == HYB_COIN_BOND,
          "X5a the row is EXITING with exit_height B1+3, bond unchanged");
    {
        sqlite3_stmt *q = NULL;
        int gone = 0;

        hyb_coin_nul(HYB_EXIT_COIN, nul);
        CHECK(sqlite3_prepare_v2(H->g.w->db, "SELECT COUNT(*) FROM utxo_set "
              "WHERE nullifier = ?1", -1, &q, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(q, 1, nul, 64, SQLITE_STATIC);
        gone = sqlite3_step(q) == SQLITE_ROW && sqlite3_column_int(q, 0) == 0;
        sqlite3_finalize(q);
        CHECK(gone, "X5b the exit's SYSFUND leg consumed the exit coin");
    }
    CHECK(q1(H->g.w->db, "SELECT total FROM v2_bond_total WHERE id = 1") ==
              (int64_t)HYB_COIN_BOND,
          "X5c the bond bucket still counts the EXITING bond");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "X5d every leg root equals the rebuild after the exit block");
    CHECK(hyb_pair_to(H, NULL, (int64_t)B1 + 3, (int64_t)B2 - 1) == 0,
          "X6a blocks up to B2-1 apply");
    CHECK(nodus_witness_storage_bond_total(H->g.w, &bonds0) == 0 &&
          (utxo0 = q1(H->g.w->db,
                      "SELECT COALESCE(SUM(amount),0) FROM utxo_set")) > 0,
          "X6b the bond bucket and the UTXO sum before the release");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, u0[leg - 1]) == 0,
              "X6c leg roots read before the release");
    CHECK(hyb_pair_to(H, NULL, (int64_t)B2 - 1, (int64_t)B2) == 0,
          "X7a the boundary B2 applies");
    CHECK(hyb_node_row(H->g.w, 1, &st, &exit_h, &bond) == 0 &&
          st == DNA_V2_STORAGE_RELEASED && bond == HYB_COIN_BOND,
          "X7b the row is RELEASED");
    CHECK(qgp_sha3_512(g_ks[1].pk, QGP_DSA87_PUBLICKEYBYTES, fp) == 0 &&
          dna_v2_storage_exit_id(H->g.chain32, B2, fp, xid) == 0 &&
          dna_v2_storage_exit_nullifier(xid, xnul) == 0 &&
          hyb_coin_owner_hex(1, hex) == 0, "X7c the exit identity");
    {
        sqlite3_stmt *q = NULL;
        int good = 0;

        CHECK(sqlite3_prepare_v2(H->g.w->db, "SELECT owner, amount, tx_hash, "
              "output_index, block_height, unlock_block FROM utxo_set WHERE "
              "nullifier = ?1", -1, &q, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(q, 1, xnul, 64, SQLITE_STATIC);
        if (sqlite3_step(q) == SQLITE_ROW)
            good = sqlite3_column_bytes(q, 0) == 128 &&
                   memcmp(sqlite3_column_text(q, 0), hex, 128) == 0 &&
                   (uint64_t)sqlite3_column_int64(q, 1) == HYB_COIN_BOND &&
                   sqlite3_column_bytes(q, 2) == 64 &&
                   memcmp(sqlite3_column_blob(q, 2), xid, 64) == 0 &&
                   sqlite3_column_int64(q, 3) == (int64_t)DNA_V2_STORAGE_EXIT_OUT_IDX &&
                   (uint64_t)sqlite3_column_int64(q, 4) == B2 &&
                   (uint64_t)sqlite3_column_int64(q, 5) ==
                       B2 + (uint64_t)DNAC_STORAGE_EXIT_LOCK_EPOCHS * E;
        sqlite3_finalize(q);
        CHECK(good, "X7d the bond is ONE locked UTXO: identity, owner, "
                    "amount, index 201, block B2, unlock B2 + 12E");
    }
    utxo1 = q1(H->g.w->db, "SELECT COALESCE(SUM(amount),0) FROM utxo_set");
    CHECK(nodus_witness_storage_bond_total(H->g.w, &bonds1) == 0 &&
          bonds1 == bonds0 - HYB_COIN_BOND &&
          utxo1 == utxo0 + (int64_t)HYB_COIN_BOND,
          "X7e the bond moved from the bond bucket to the UTXO sum");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, u1[leg - 1]) == 0,
              "X7f leg roots read after the release");
    for (int i = 0; i < 8; i++)
        if (memcmp(u0[i], u1[i], 64) != 0) moved |= 1 << i;
    CHECK((moved & 0x01) != 0 && (moved & 0x10) != 0,
          "X7g the UTXO leg (1) and the registry leg (5) moved with the "
          "release");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "X7h every leg root equals the incremental and the full rebuild "
          "after the release block");
    CHECK(hyb_pair_to(H, NULL, (int64_t)B2, (int64_t)B2 + 1) == 0,
          "X8a block B2+1 applies");
    CHECK(hyb_legs_ok(H->g.w) == 0, "X8b and its leg roots equal the rebuild");
    free(renv);
    free(xenv);
    hyb_close(H);
    free(H);
    return 0;
}

/* ── T-9 on the real block path (plan :449) ───────────────────────────── */
typedef struct {
    nodus_storage_work_t w;      /* g_nodus_storage_work around the block  */
    int64_t              k;      /* distinct (leg, key) the block dirtied  */
    uint64_t             ops;    /* SQLite virtual-machine instructions the
                                  * WHOLE block ran on the ledger connection
                                  * (progress handler, period 1)          */
} hyb_sample_t;

#define HYB_NSAMPLES 5   /* blocks 16, 17, E, 2E, 3E */

static int hyb_prog_cb(void *p)
{
    (*(uint64_t *)p)++;
    return 0;                    /* never interrupt */
}

/* Registry history for the growth probe (declared before hyb_open, which
 * plants it before the genesis next to the coins and the filler UTXOs):
 * RELEASED nodes, valid by the registry loader's own rule
 * (nodus_witness_roots_v2.c "the key IS the hash of the key material it
 * names"): node_fp = SHA3-512(node_pk), distinct 2592-byte keys derived
 * from a counter, bond / heights / streak inside the loader's ranges,
 * status RELEASED. A RELEASED node holds no bond, so the supply (the bond
 * bucket counts ACTIVE and EXITING only) is untouched; the UTXO its release
 * created is not planted because a production chain also spends it after
 * the 12-epoch lock. */
static int hyb_plant_released(nodus_witness_t *w, unsigned n)
{
    sqlite3_stmt *st = NULL;
    uint8_t      *pk = malloc(QGP_DSA87_PUBLICKEYBYTES);
    int           rc = SQLITE_DONE;

    if (!pk) return -1;
    if (sqlite3_exec(w->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        free(pk);
        return -1;
    }
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, ?3, ?4, 3, 1, 2, 0, 0)",
            -1, &st, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        free(pk);
        return -1;
    }
    for (unsigned i = 0; i < n && rc == SQLITE_DONE; i++) {
        uint8_t fp[64], py[64];

        memset(pk, 0xA5, QGP_DSA87_PUBLICKEYBYTES);
        memcpy(pk, "hf9-wp4-hyb-rel", 15);
        for (int b = 0; b < 4; b++) pk[16 + b] = (uint8_t)(i >> (8 * (3 - b)));
        if (qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0 ||
            qgp_sha3_512(fp, 64, py) != 0) {
            rc = SQLITE_ERROR;
            break;
        }
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, pk, QGP_DSA87_PUBLICKEYBYTES, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, py, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)HYB_COIN_BOND);
        rc = sqlite3_step(st);
    }
    sqlite3_finalize(st);
    free(pk);
    if (rc != SQLITE_DONE) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return sqlite3_exec(w->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* One block with the work counters read around it. `env` != NULL puts that
 * envelope into the block. The dirty keys are counted by a TEMP trigger on
 * main.v2_trie_dirty (a connection-local instrument: it adds nothing to the
 * file and nothing to the schema the per-open check reads); k == 0 on a
 * block that registered keys would mean the instrument is not wired, and
 * the caller asserts k > 0 where keys must be dirty. */
static int hyb_sample_block(hyb_t *H, int64_t height, uint8_t *env,
                            size_t elen, hyb_sample_t *s)
{
    uint64_t ops = 0;
    int      rc;

    if (sqlite3_exec(H->g.w->db, "DELETE FROM temp.hyb_dlog", NULL, NULL,
                     NULL) != SQLITE_OK)
        return -1;
    memset(&g_nodus_storage_work, 0, sizeof(g_nodus_storage_work));
    /* the progress handler (period 1) counts EVERY virtual-machine
     * instruction of the ledger connection during the block - settlement,
     * prune, release, publication, freeze, the flush and the block's own
     * writes alike - so work that scans history shows up whichever
     * statement does it; it is deterministic (a function of the SQL run) */
    sqlite3_progress_handler(H->g.w->db, 1, hyb_prog_cb, &ops);
    if (env) rc = hyb_tx_step(H, NULL, height, env, elen);
    else     rc = hyb_pair_step(H, NULL, height, 0);
    sqlite3_progress_handler(H->g.w->db, 0, NULL, NULL);
    s->w   = g_nodus_storage_work;
    s->ops = ops;
    s->k   = q1(H->g.w->db, "SELECT COUNT(*) FROM temp.hyb_dlog");
    return rc == CMT_OK ? 0 : -1;
}

/* the VM steps of one lookup of a UTXO by nullifier, indexed and with the
 * index disabled (+nullifier): the positive control that a scan of the
 * growing source table is visible to the step counter */
static int hyb_lookup_steps(nodus_witness_t *w, int scan, long long *steps)
{
    sqlite3_stmt *st = NULL;
    uint8_t       nul[64];

    hyb_coin_nul(0, nul);                     /* coin 0 is never spent here */
    if (sqlite3_prepare_v2(w->db, scan
            ? "SELECT amount FROM utxo_set WHERE +nullifier = ?1"
            : "SELECT amount FROM utxo_set WHERE nullifier = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_STATIC);
    while (sqlite3_step(st) == SQLITE_ROW) { }
    *steps = sqlite3_stmt_status(st, SQLITE_STMTSTATUS_VM_STEP, 0);
    sqlite3_finalize(st);
    return 0;
}

/* One funded hybrid with `n_hist` extra UTXOs AND `n_hist` RELEASED registry
 * nodes of history, five measured blocks: s[0] block 16 carrying the
 * registration (an ordinary generation-6 block with a fixed number of
 * changed records), s[1] block 17 (ordinary, no transaction), s[2] the
 * boundary E (the event: an arrival), s[3] the boundary 2E and s[4] the
 * boundary 3E (ORDINARY boundaries through the complete real procedure:
 * settlement - which starts at 3E: B < 3E returns at once, st_settle -,
 * prune, release, publication, freeze). ctl[0] / ctl[1]: VM steps of a
 * UTXO lookup by nullifier, indexed and scanning (the control). */
static int hyb_growth_chain(unsigned n_hist, hyb_sample_t s[HYB_NSAMPLES],
                            long long ctl[2])
{
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    /* round 19: the samples "E, 2E, 3E" are B1, B1 + E, B1 + 2E with B1 the first boundary above
     * the registration block 16 (720 at production: unchanged; 30 at E = 15, where the boundary 15
     * is applied in G1 before the registration) */
    const uint64_t B1 = hyb_boundary_above(HYB_REG_BLK);
    hyb_t   *H = calloc(1, sizeof(*H));
    uint8_t *env = NULL;
    size_t   elen = 0;

    CHECK(H != NULL, "alloc");
    g_hyb_filler = n_hist;
    g_hyb_released = n_hist;
    CHECK(hyb_open(H, 1) == 0, "G0 the funded hybrid with its history");
    CHECK(q1(H->g.w->db, "SELECT COUNT(*) FROM utxo_set") ==
              (int64_t)(HYB_N_COINS + n_hist),
          "G0b the history UTXOs are present after the genesis");
    CHECK(q1(H->g.w->db, "SELECT COUNT(*) FROM v2_storage_nodes WHERE "
                         "status = 3") == (int64_t)n_hist,
          "G0d the released registry history is present after the genesis");
    CHECK(sqlite3_exec(H->g.w->db,
              "CREATE TEMP TABLE hyb_dlog(leg INTEGER, key BLOB);"
              "CREATE TEMP TRIGGER hyb_dlog_t AFTER INSERT ON "
              "main.v2_trie_dirty BEGIN INSERT INTO hyb_dlog "
              "VALUES (NEW.leg, NEW.key); END;",
              NULL, NULL, NULL) == SQLITE_OK,
          "G0c the dirty-key counter is installed (connection-local)");
    CHECK(hyb_pair_to(H, NULL, 0, 15) == 0, "G1 blocks 1-15 apply");
    CHECK(hyb_register_env(H->g.w, 16, 1, &env, &elen) == 0 && env,
          "G2 the registration envelope builds");
    CHECK(hyb_sample_block(H, 16, env, elen, &s[0]) == 0,
          "G3 block 16 with the registration applies");
    CHECK(hyb_sample_block(H, 17, NULL, 0, &s[1]) == 0, "G4 block 17 applies");
    CHECK(hyb_pair_to(H, NULL, 17, (int64_t)B1 - 1) == 0,
          "G5 blocks up to B1-1 apply");
    CHECK(hyb_sample_block(H, (int64_t)B1, NULL, 0, &s[2]) == 0,
          "G6 the event boundary B1 applies");
    CHECK(hyb_pair_to(H, NULL, (int64_t)B1, (int64_t)(B1 + E) - 1) == 0,
          "G6b blocks up to B1+E-1 apply");
    CHECK(hyb_sample_block(H, (int64_t)(B1 + E), NULL, 0, &s[3]) == 0,
          "G6c the ordinary boundary B1+E applies");
    CHECK(hyb_pair_to(H, NULL, (int64_t)(B1 + E), (int64_t)(B1 + 2 * E) - 1) == 0,
          "G6d blocks up to B1+2E-1 apply");
    CHECK(hyb_sample_block(H, (int64_t)(B1 + 2 * E), NULL, 0, &s[4]) == 0,
          "G6e the ordinary boundary B1+2E applies");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "G7 every leg root equals the rebuild at the end");
    CHECK(hyb_lookup_steps(H->g.w, 0, &ctl[0]) == 0 &&
          hyb_lookup_steps(H->g.w, 1, &ctl[1]) == 0,
          "G8 the control lookups run");
    free(env);
    hyb_close(H);
    free(H);
    return 0;
}

/* HF-9 WP4 - T-9 (plan :449) through REAL block application: the work of
 * an ordinary block, of the first (event) boundary and of the first two
 * ORDINARY boundaries (2E, and 3E where the settlement runs) does not grow
 * with the history. Two funded hybrids that differ ONLY in the history
 * planted before the genesis - n ordinary UTXOs and n RELEASED registry
 * nodes with valid key / fingerprint pairs (hyb_seed_filler,
 * hyb_plant_released; n = 100 and 100 000, the plan's range 1e2 -> 1e5) -
 * apply the SAME five blocks (16: one registration, 17: empty, E: the
 * arrival event, 2E and 3E: ordinary boundaries through the complete real
 * procedure - settlement, prune, release, publication, freeze). For each
 * block the counters of g_nodus_storage_work, the number of dirty (leg,
 * key) pairs and the TOTAL SQLite virtual-machine instructions the ledger
 * connection ran (progress handler) are read.
 * Asserted: G-a the trie-node counter, the dirty-key counter, the flush
 * source-row step counter and the whole-block instruction count are wired
 * (non-zero on block 16); G-b nodes loaded <= 131 per dirty key (plan 5.6)
 * on every sample - a bound, not equality: path depth grows with log16;
 * G-c ordinary blocks and boundaries (16, 17, 2E, 3E) do no assignment
 * work; G-d the event boundary reads the registry and every storage
 * counter of E, 2E, 3E is EQUAL on the two chains; G-e the flush's
 * source-row steps are within 64 of each other for every block; G-f the
 * whole-block instruction count differs between the two chains by less
 * than a tenth of one instruction per planted history row (a scan of the
 * history adds at least one instruction per row), with the control that a
 * UTXO lookup with the index disabled steps at least n more than the
 * indexed one. Both chains' numbers go to stderr.
 * NOT COVERED: growth of the segment, assignment and set tables. A valid
 * segment row exists only for a chain that has run 24 E blocks per segment
 * (published at k x 24 E + 2 E from v2_blocks, nodus_witness_v2_storage.c
 * st_publish :1812-1866, segment_root_compute :821-870), so 10^5 of them
 * need 10^5 x 24 E real blocks; the fixture of test_hf9_growth derives
 * assignment rows of a valid contiguous segment list with the production
 * freeze instead. The settlement here runs with an unmet F1 gate (no
 * signed reports, pools at 0): its payout path is not measured.
 * LIMIT of the registry history (Sol re-verify fix4 row 3): the 10^5
 * RELEASED nodes are planted before the genesis (hyb_plant_released) and
 * are a state NO GENESIS PRODUCES - a genesis starts with no storage node;
 * production reaches such a registry only by 10^5 register -> exit ->
 * release cycles. By real blocks that is not reachable in-process: at most
 * 1024 nodes are live (ACTIVE + EXITING) at once (registration refuses
 * above the generation-6 cap, nodus_witness_rt_native.c :6403-6410) and an
 * exit is released only at the next boundary (:6474-6480,
 * nodus_witness_v2_storage.c st_release :1757), so 10^5 cycles need at
 * least 98 release boundaries = 98 E blocks, 10^5 funded coins, 10^5
 * registration envelopes (a 7299-byte consent-signed call, two ML-DSA
 * signatures each) and 10^5 exit envelopes, with a block holding at most
 * TEST_APP_TXS_CAP = 48 transactions (:1074): about 4 200 full blocks of
 * signing, on top of the 98 E blocks. The cohort-staggered, bond-valid
 * version of this history is built by test_hf9_growth (plant_released) for
 * the freeze and prune, which need no genesis. This probe's planted rows
 * carry the STORAGE_BOND default and one registration height, not that
 * lifetime; the checks below do not depend on either.
 * ROUND 19: the samples named E, 2E, 3E are B1, B1 + E, B1 + 2E, B1 being the first boundary
 * above the registration block 16 (E, 2E, 3E at production; 30, 45, 60 at E = 15). Flags:
 * NODUS_EVM_ENABLED; both settings (E = 15 with its four constants, or production).
 * Leaves /tmp/test_cmt_app_hyb_XXXXXX
 * (removed). Can falsely pass: history in the UTXO leg and the released
 * registry only; the 10% rule would also pass a scan of a table that
 * the history does not grow. */
static int t_hybrid_growth_probe(void)
{
    static const char *const names[HYB_NSAMPLES] = {
        "block 16 (registration)", "block 17 (empty)", "boundary E (event)",
        "boundary 2E (ordinary)", "boundary 3E (settles)"
    };
    hyb_sample_t small[HYB_NSAMPLES], big[HYB_NSAMPLES];
    long long    ctl_small[2] = { -1, -1 }, ctl_big[2] = { -1, -1 };

    CHECK(hyb_boundary_above(HYB_REG_BLK) > 17u,
          "the event boundary B1 lies after block 17");
    memset(small, 0, sizeof(small));
    memset(big, 0, sizeof(big));
    CHECK(hyb_growth_chain(100, small, ctl_small) == 0,
          "chain with 100 history rows");
    CHECK(hyb_growth_chain(100000, big, ctl_big) == 0,
          "chain with 100 000 history rows");
    for (int i = 0; i < HYB_NSAMPLES; i++)
        fprintf(stderr, "T-9 %-24s | 1e2: nodes %" PRIu64 " keys %" PRId64
                " regrows %" PRIu64 " vm %" PRIu64 " flush %" PRIu64
                " ops %" PRIu64 " | 1e5: nodes %" PRIu64
                " keys %" PRId64 " regrows %" PRIu64 " vm %" PRIu64
                " flush %" PRIu64 " ops %" PRIu64 "\n",
                names[i], small[i].w.trie_nodes_loaded, small[i].k,
                small[i].w.registry_rows_read, small[i].w.registry_vm_steps,
                small[i].w.flush_source_vm_steps, small[i].ops,
                big[i].w.trie_nodes_loaded, big[i].k,
                big[i].w.registry_rows_read, big[i].w.registry_vm_steps,
                big[i].w.flush_source_vm_steps, big[i].ops);
    fprintf(stderr, "T-9 control: UTXO lookup steps, 1e2 history: indexed %lld "
            "scan %lld; 1e5 history: indexed %lld scan %lld\n",
            ctl_small[0], ctl_small[1], ctl_big[0], ctl_big[1]);
    CHECK(small[0].w.flush_source_vm_steps > 0 &&
          big[0].w.flush_source_vm_steps > 0 &&
          small[0].ops > 0 && big[0].ops > 0,
          "G-a the flush source-row step counter and the whole-block "
          "instruction count are wired on block 16 of both chains");
    for (int i = 0; i < HYB_NSAMPLES; i++)
        CHECK(big[i].w.flush_source_vm_steps <=
                  small[i].w.flush_source_vm_steps + 64u &&
              small[i].w.flush_source_vm_steps <=
                  big[i].w.flush_source_vm_steps + 64u,
              "G-e the flush's source-row steps are within 64 at both "
              "history sizes");
    for (int i = 0; i < HYB_NSAMPLES; i++) {
        const uint64_t a = small[i].ops, b = big[i].ops;
        const uint64_t d = a > b ? a - b : b - a;

        CHECK(d < (100000u - 100u) / 10u,
              "G-f the whole-block instruction count differs by less than "
              "a tenth of one instruction per added history row");
    }
    CHECK(ctl_big[0] > 0 && ctl_big[1] >= ctl_big[0] + 100000,
          "G-f control: a UTXO lookup with the index disabled steps at "
          "least one per history row more than the indexed lookup");
    CHECK(small[0].w.trie_nodes_loaded > 0 && big[0].w.trie_nodes_loaded > 0 &&
          small[0].k > 0 && big[0].k > 0,
          "G-a the trie-node counter and the dirty-key counter are wired "
          "on block 16 of both chains");
    for (int i = 0; i < HYB_NSAMPLES; i++)
        CHECK(small[i].w.trie_nodes_loaded <= 131u * (uint64_t)small[i].k &&
              big[i].w.trie_nodes_loaded <= 131u * (uint64_t)big[i].k,
              "G-b nodes loaded <= 131 per dirty key at both history sizes");
    for (int i = 0; i < HYB_NSAMPLES; i++) {
        if (i == 2) continue;                    /* the event boundary E */
        CHECK(small[i].w.segments_visited == 0 &&
              small[i].w.scores_computed == 0 &&
              small[i].w.assign_rows_written == 0 &&
              big[i].w.segments_visited == 0 &&
              big[i].w.scores_computed == 0 &&
              big[i].w.assign_rows_written == 0,
              "G-c an ordinary block or boundary does no assignment work");
    }
    for (int i = 2; i < HYB_NSAMPLES; i++) {          /* E, 2E, 3E */
        CHECK(small[i].w.registry_rows_read > 0 &&
              big[i].w.registry_rows_read > 0 &&
              small[i].w.registry_vm_steps > 0 &&
              big[i].w.registry_vm_steps > 0,
              "G-d1 a boundary reads the registry (counters wired)");
        CHECK(small[i].w.registry_rows_read == big[i].w.registry_rows_read &&
              small[i].w.segments_visited == big[i].w.segments_visited &&
              small[i].w.assign_rows_read == big[i].w.assign_rows_read &&
              small[i].w.assign_rows_written == big[i].w.assign_rows_written &&
              small[i].w.scores_computed == big[i].w.scores_computed,
              "G-d2 every storage counter of a boundary is equal at both "
              "history sizes");
        CHECK(big[i].w.registry_vm_steps <= small[i].w.registry_vm_steps + 64u &&
              small[i].w.registry_vm_steps <= big[i].w.registry_vm_steps + 64u,
              "G-d3 registry VM steps within 64 at both history sizes");
    }
    return 0;
}

/* ── the registry's fail_streak / grace_until writers by real blocks
 *    (Sol re-verify row 1; plan :154 "UPDATE fail_streak ... grace_until",
 *    :445 "every writer path through the real functions; after each block
 *    incremental leg root = full rebuild") ──────────────────────────────── */

/* grace_until and fail_streak of node key `key` */
static int hyb_node_gs(nodus_witness_t *w, int key, uint64_t *grace,
                       uint32_t *streak)
{
    sqlite3_stmt *st = NULL;
    uint8_t       fp[64];
    int           rc = -1;

    if (qgp_sha3_512(g_ks[key].pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0)
        return -1;
    if (sqlite3_prepare_v2(w->db, "SELECT grace_until, fail_streak FROM "
                           "v2_storage_nodes WHERE node_fp = ?1", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *grace  = (uint64_t)sqlite3_column_int64(st, 0);
        *streak = (uint32_t)sqlite3_column_int64(st, 1);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/* A 1-leg STORAGE_REPORT envelope, fee 0, signed by validator key `vkey`
 * (a g_ks key = a seat of the hybrid's committee), for epoch H: every
 * member of storage_set(H) is reported as FAILED (all bitmap bits 0).
 * Ported from test_storage_b2.c rep_env :1835 / rep_call :1192 / reports_for
 * :2077. @return 0 and a heap envelope in *out, or -1 */
static int hyb_report_env(nodus_witness_t *w, uint64_t height, int vkey,
                          uint64_t H, uint8_t **out, size_t *out_len)
{
    static uint8_t        call[78 + 1];
    static uint8_t        auth[HYB_AUTH_LEN];
    dna_domain_manifest_t sys;
    dna_env_leg_in_t      leg;
    dna_env_in_t          in;
    dna_env_leg_ctx_t     lctx;
    dna_vset_snapshot_t  *snap = NULL;
    sqlite3_stmt         *st = NULL;
    size_t                len = 0, used = 0;
    uint8_t              *bytes = NULL;
    dna_env_preflight_t  *pf = NULL;
    uint32_t              seat = UINT32_MAX;
    int                   count = -1, ok = -1;

    *out = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(w, H, &snap, NULL, NULL)
            != 0 || !snap)
        return -1;
    for (uint32_t x = 0; x < snap->active_count; x++)
        if (memcmp(snap->entries[x].pubkey, g_ks[vkey].pk,
                   QGP_DSA87_PUBLICKEYBYTES) == 0)
            seat = x;
    dna_vset_free(&snap);
    if (seat == UINT32_MAX) return -1;
    if (sqlite3_prepare_v2(w->db, "SELECT set_hash, member_count FROM "
                           "v2_storage_sets WHERE epoch_start = ?1", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
    memset(call, 0, sizeof(call));
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == 64) {
        memcpy(call + 12, sqlite3_column_blob(st, 0), 64);
        count = sqlite3_column_int(st, 1);
    }
    sqlite3_finalize(st);
    if (count < 1 || count > 8) return -1;        /* one bitmap byte */
    hyb_put64(call, H);
    for (int b = 0; b < 4; b++) call[8 + b] = (uint8_t)(seat >> (8 * (3 - b)));
    call[76] = 0;
    call[77] = 1;                                  /* bitmap_len = 1 */
    call[78] = 0;                                  /* every member FAILED */
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL) != 0)
        return -1;
    memset(&leg, 0, sizeof(leg));
    memset(auth, 0, sizeof(auth));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_STORAGE_REPORT;
    leg.hdr.ruleset_version = sys.ruleset_version;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len = 79;
    leg.hdr.auth_len = HYB_AUTH_LEN;
    leg.hdr.res_max_effects = 8;
    leg.hdr.res_max_effect_bytes = 16384;
    leg.call_data = call;
    leg.auth_data = auth;
    memset(&in, 0, sizeof(in));
    in.fee_amount = 0;
    in.expiry_height = height + 5u;           /* inside the D2 window */
    in.res_max_total_units = 400000;
    in.leg_count = 1;
    in.legs = &leg;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);
    if (dna_env_encoded_size(&leg, 1, &len) != 0) return -1;
    bytes = malloc(len);
    pf = calloc(1, sizeof(*pf));
    do {
        size_t sl = 0;

        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, &lctx, 1, pf)
            != DNA_ENV_PF_OK)
            break;
        auth[0] = 1;
        memcpy(auth + 1, g_ks[vkey].pk, QGP_DSA87_PUBLICKEYBYTES);
        if (qgp_dsa87_sign(auth + 1 + QGP_DSA87_PUBLICKEYBYTES, &sl,
                           pf->auth_digest[0], 64, g_ks[vkey].sk) != 0)
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

/* HF-9 WP4 - the registry's TWO remaining writers through generation-6
 * blocks with the leg-root check (Sol re-verify row 1): st_grace_write
 * (K9, nodus_witness_v2_storage.c :1884, called from the freeze) and
 * st_streak_write (the settlement). LONG case (runs only when named; its
 * own ctest entry, nodus/CMakeLists.txt): 29 E + 1 blocks on one node.
 * Timeline on the funded hybrid: W1 blocks 1-15 apply; W2 key 1 registers
 * in block 16; W3 blocks to 26E - 1 apply with no segment, grace_until = 0
 * and fail_streak = 0; W4 block 26E (the first publication, segment 1 due
 * at 1 x 24 E + 2 E) applies: segment 1 exists, leg 6 (segments) moved and
 * every leg root equals the incremental and the full rebuild; by K9a (the
 * decision record :82-86, plan :299) a segment published AT the boundary
 * is not counted, so key 1, which holds it from publication, gets NO grace
 * (grace_until stays 0); W4g-q key 2 (a second storage node, the arrival
 * coin: hyb_open(H, 3)) registers in block 26E + 16, and the event
 * boundary 27E gives it the K9a grace: it newly holds segment 1 (published
 * <= B - E) that it did not hold, so grace_until = 27E + 1 x E = 28E (K9
 * writer, st_grace_write), key 1's stays 0, leg 5 (registry) moved, every
 * leg root equals the rebuild; W5 blocks to 28E apply (set(27E) = keys 1
 * and 2; key 1 outside grace and holding segment 1, key 2 in grace);
 * W6 five STORAGE_REPORTs for H = 27E, each signed by one seat of the
 * committee (g_ks keys 0, 2, 3, 4, 5), every bit 0 (the members failed), in
 * the window (28E, 28E + E/2] apply; W7 block 29E (settlement of H = 27E)
 * applies: key 1's fail_streak 0 -> 1 (the streak writer), key 2's (in
 * grace at H) stays 0, leg 5 moved, every leg root equals the rebuild; W8
 * block 29E + 1 applies and the legs still equal the rebuild.
 * Flags: NODUS_EVM_ENABLED; both settings (production, or E = 15 with its four
 * constants; the guard is E / 2 >= 5 and E > 2: reports at 28E + 1 .. + 5 inside
 * the window; key 2 registers at R2 = 26E + 16, or 26E + 14 at E = 15). At
 * E = 15 the case runs 436 blocks (29 E + 1); the registration of key 1 at
 * block 16 follows the first boundary 15. Leaves /tmp/test_cmt_app_hyb_XXXXXX (removed). Can falsely pass:
 * a single node and a single member; the payout is not run (pool 1 unfunded:
 * the streak writer is reached, the pay path is not). The five seats'
 * independent power exceeding half of the total depends on the committee's
 * power split - if it did not, W7 fails visibly (streak stays 0). */
static int t_hybrid_storage_writers_probe(void)
{
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    static const int seats[5] = { 0, 2, 3, 4, 5 };
    hyb_t   *H = calloc(1, sizeof(*H));
    uint8_t *renv = NULL, *aenv = NULL, *penv[5] = { NULL };
    uint8_t  l0[8][64], l1[8][64];
    uint64_t grace = 1, g2 = 0;
    uint32_t streak = 1;
    int      moved = 0;

    /* round 19 (was E > 40): the case needs (a) the five report blocks 28E + 1 .. 28E + 5 inside the
     * report window (28E, 28E + E/2] (nodus_witness_storage_probe.c:604-620), i.e. E / 2 >= 5, and
     * (b) a block R2 strictly between 26E and 27E for key 2's registration. R2 = 26E + 16 as
     * before when E > 16 (production), 26E + (E - 1) at E = 15 (the last block before 27E; the
     * boundary 27E follows at once, which is all the K9a grace claim needs: key 2 registers AFTER the
     * publication 26E and BEFORE the event boundary 27E). The setup blocks 1 .. 15, the registration
     * of key 1 at 16 and the 25 boundaries before 26E are crossed at every E - at E = 15 the first
     * boundary, 15, falls before key 1's registration (an event-free generation-6 boundary). */
    const uint64_t R2 = 26 * E + (E > 16 ? 16 : E - 1);
    CHECK(E / 2 >= 5 && E > 2, "W0 the report window holds five reports; a block lies between 26E and 27E");
    CHECK(H != NULL, "alloc");
    CHECK(hyb_open(H, 3) == 0,
          "W0 the funded hybrid with the arrival coin derives");
    CHECK(hyb_pair_to(H, NULL, 0, 15) == 0, "W1 blocks 1-15 apply");
    CHECK(hyb_register_step(H, NULL, 16, 1, &renv) == CMT_OK,
          "W2 block 16 with the registration applies");
    CHECK(hyb_pair_to(H, NULL, 16, (int64_t)(26 * E) - 1) == 0,
          "W3a blocks up to 26E-1 apply");
    CHECK(hyb_node_gs(H->g.w, 1, &grace, &streak) == 0 && grace == 0 &&
          streak == 0 &&
          q1(H->g.w->db, "SELECT COUNT(*) FROM v2_storage_segments") == 0,
          "W3b before 26E: no segment, grace_until 0, fail_streak 0");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l0[leg - 1]) == 0,
              "W3c leg roots read before 26E");
    CHECK(hyb_pair_to(H, NULL, (int64_t)(26 * E) - 1, (int64_t)(26 * E)) == 0,
          "W4a the first publication boundary 26E applies");
    CHECK(q1(H->g.w->db, "SELECT COUNT(*) FROM v2_storage_segments") == 1,
          "W4b segment 1 was published by the real boundary");
    /* K9a (docs/plans/decisions/2026-10-05-storage-reward-is-for-archive.md
     * :82-86; plan :299 "only for k published <= B-E"): a segment published
     * AT this boundary is not counted, so the node that holds it from its
     * publication gets NO grace */
    CHECK(hyb_node_gs(H->g.w, 1, &grace, &streak) == 0 && grace == 0,
          "W4c K9a: a segment published at the boundary is not counted - "
          "the holder from publication gets no grace (grace_until 0)");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l1[leg - 1]) == 0,
              "W4d leg roots read after 26E");
    for (int i = 0; i < 8; i++)
        if (memcmp(l0[i], l1[i], 64) != 0) moved |= 1 << i;
    CHECK((moved & 0x20) != 0, "W4e leg 6 (segments) moved");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "W4f every leg root equals the incremental and the full rebuild "
          "after 26E");
    /* the K9a grace case: key 2 ARRIVES after the first publication, so at
     * the next boundary 27E (an event) it newly holds segment 1, which
     * existed at 27E - E = 26E (published <= B - E) and which it did not
     * hold at 26E: n = 1, grace_until = max(0, 27E + 1 x E) = 28E (K9
     * decision :78-79). Key 1 held the segment already: no grace. */
    CHECK(hyb_pair_to(H, NULL, (int64_t)(26 * E), (int64_t)R2 - 1) == 0,
          "W4g blocks 26E+1 .. R2-1 apply");
    CHECK(hyb_register_step(H, NULL, (int64_t)R2, 2, &aenv)
              == CMT_OK, "W4h block R2 with key 2's registration applies");
    CHECK(hyb_pair_to(H, NULL, (int64_t)R2, (int64_t)(27 * E) - 1)
              == 0, "W4i blocks up to 27E-1 apply");
    CHECK(hyb_node_gs(H->g.w, 2, &grace, &streak) == 0 && grace == 0,
          "W4j key 2 has no grace before the boundary 27E");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l0[leg - 1]) == 0,
              "W4k leg roots read before 27E");
    CHECK(hyb_pair_to(H, NULL, (int64_t)(27 * E) - 1, (int64_t)(27 * E)) == 0,
          "W4l the event boundary 27E applies");
    CHECK(hyb_node_gs(H->g.w, 2, &grace, &streak) == 0 && grace == 28 * E,
          "W4m K9/K9a: key 2 newly holds segment 1 (existed at B-E): "
          "grace_until = 27E + 1 x E (K9 writer)");
    CHECK(hyb_node_gs(H->g.w, 1, &g2, &streak) == 0 && g2 == 0,
          "W4n key 1 held the segment before: grace_until stays 0");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l1[leg - 1]) == 0,
              "W4o leg roots read after 27E");
    moved = 0;
    for (int i = 0; i < 8; i++)
        if (memcmp(l0[i], l1[i], 64) != 0) moved |= 1 << i;
    CHECK((moved & 0x10) != 0,
          "W4p leg 5 (registry: key 2's grace_until) moved at 27E");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "W4q every leg root equals the incremental and the full rebuild "
          "after 27E");
    CHECK(hyb_pair_to(H, NULL, (int64_t)(27 * E), (int64_t)(28 * E)) == 0,
          "W5 blocks up to the boundary 28E apply");
    for (int r = 0; r < 5; r++) {
        size_t elen = 0;
        const int64_t h = (int64_t)(28 * E) + 1 + r;

        CHECK(hyb_report_env(H->g.w, (uint64_t)h, seats[r], 27 * E,
                             &penv[r], &elen) == 0 && penv[r],
              "W6a the STORAGE_REPORT for H = 27E builds");
        CHECK(hyb_tx_step(H, NULL, h, penv[r], elen) == CMT_OK,
              "W6b the block carrying the report applies");
    }
    {
        char sql[160];

        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_storage_reports "
                 "WHERE epoch_start = %" PRIu64, 27 * E);
        CHECK(q1(H->g.w->db, sql) == 5,
              "W6c the five reports for H = 27E are committed");
    }
    CHECK(hyb_pair_to(H, NULL, (int64_t)(28 * E) + 5, (int64_t)(29 * E) - 1)
              == 0, "W6d blocks up to 29E-1 apply");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l0[leg - 1]) == 0,
              "W6e leg roots read before 29E");
    CHECK(hyb_node_gs(H->g.w, 1, &g2, &streak) == 0 && streak == 0,
          "W6f before the settlement fail_streak is 0");
    CHECK(hyb_pair_to(H, NULL, (int64_t)(29 * E) - 1, (int64_t)(29 * E)) == 0,
          "W7a the settlement boundary 29E applies");
    CHECK(hyb_node_gs(H->g.w, 1, &g2, &streak) == 0 && streak == 1,
          "W7b the settlement of H = 27E wrote fail_streak 1 (streak "
          "writer)");
    /* key 2 is in grace at H = 27E (27E < 28E): its fail_streak is left
     * unchanged whatever the reports say (K9 decision :79-80 "fail_streak
     * unchanged"; nodus_witness_v2_storage.c st_settle :1707) */
    CHECK(hyb_node_gs(H->g.w, 2, &g2, &streak) == 0 && streak == 0,
          "W7b2 key 2, in grace at H, keeps fail_streak 0");
    for (int leg = 1; leg <= NODUS_V2_TRIE_LEGS; leg++)
        CHECK(nodus_witness_v2_trie_leg_root(H->g.w, leg, l1[leg - 1]) == 0,
              "W7c leg roots read after 29E");
    moved = 0;
    for (int i = 0; i < 8; i++)
        if (memcmp(l0[i], l1[i], 64) != 0) moved |= 1 << i;
    CHECK((moved & 0x10) != 0, "W7d leg 5 (registry: fail_streak) moved");
    CHECK(hyb_legs_ok(H->g.w) == 0,
          "W7e every leg root equals the rebuild after the settlement");
    CHECK(hyb_pair_to(H, NULL, (int64_t)(29 * E), (int64_t)(29 * E) + 1) == 0,
          "W8a block 29E+1 applies");
    CHECK(hyb_legs_ok(H->g.w) == 0, "W8b and its leg roots equal the rebuild");
    free(renv);
    free(aenv);
    for (int r = 0; r < 5; r++) free(penv[r]);
    hyb_close(H);
    free(H);
    return 0;
}
#endif /* NODUS_EVM_ENABLED */

/* usage: test_cmt_app            every case except the LONG ones (field 3)
 *        test_cmt_app <name>...  exactly the named cases (a long case runs
 *                                only so; ctest registers each one as its
 *                                own test, nodus/CMakeLists.txt) */
int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        int (*fn)(void);
        int long_case;         /* 1: runs only when named on the command line */
    } cases[] = {
        { "hybrid_gen6_probe",          t_hybrid_probe },
#ifdef NODUS_EVM_ENABLED
        { "hybrid_funded_probe",        t_hybrid_funded_probe },
        { "hybrid_register_probe",      t_hybrid_register_probe },
        { "hybrid_exit_release_probe",  t_hybrid_exit_release_probe },
        { "hybrid_growth_probe",        t_hybrid_growth_probe },
        { "hybrid_storage_writers_probe", t_hybrid_storage_writers_probe, 1 },
        { "hyb_crash_boundary_event",   t_hyb_crash_boundary_event },
        { "hyb_crash_shadow",           t_hyb_crash_shadow },
        { "hyb_crash_shadow_rows",      t_hyb_crash_shadow_rows },
#ifdef QGP_FAULT_INJECT
        { "hyb_shadow_fault_host",      t_hyb_shadow_fault_host },
#endif
        { "hyb_crash_edge",             t_hyb_crash_edge },
        { "hyb_crash_ordinary_gen6",    t_hyb_crash_ordinary },
        { "hyb_crash_boundary_b1",      t_hyb_crash_boundary },
        { "hyb_boundary_leg_root_log",  t_hyb_boundary_leg_root_log },
#endif
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
        { "val_updates_v2_old_side",    t_val_updates_v2_old_side },
        { "val_updates_rotation",       t_val_updates_rotation },
        { "finalize_block_empty",       t_finalize_block_empty },
        { "d4_empty_blocks_root_stable", t_d4_empty_blocks_root_stable },
        { "attendance_mixed_flags",     t_attendance_mixed_flags },
        { "commit",                     t_commit },
        { "claim_items",                t_claim_items },
        { "claim_local_fault_is_block_fault", t_claim_local_fault_is_block_fault },
        { "check_tx",                   t_check_tx },
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
        /* 2026-09-25 devnet halt (PrepareProposal vs the byte bound) */
        { "prepare_env_byte_bound",     t_prepare_env_byte_bound },
        { "prepare_units_truncate",     t_prepare_units_truncate },
        { "prepare_entry_invalid_only", t_prepare_entry_invalid_only },
        /* CHECKTX-P1 (CheckTx parity, conflict set, light recheck,
         * PrepareProposal F1/F2/F6) */
        { "check_tx_dry_run",           t_check_tx_dry_run },
        { "check_tx_cc_poison",         t_check_tx_cc_poison },
        { "check_tx_conflicts",         t_check_tx_conflicts },
        { "check_tx_claim_variants",    t_check_tx_claim_variants },
        { "check_tx_recheck_light",     t_check_tx_recheck_light },
        { "check_tx_recheck_kind2",     t_check_tx_recheck_kind2 },
        { "check_tx_recheck_kind3",     t_check_tx_recheck_kind3 },
        { "prepare_cc_refused_packs_rest", t_prepare_cc_refused_packs_rest },
        { "prepare_refill_after_drop",  t_prepare_refill_after_drop },
        { "prepare_claims_past_env_window",
          t_prepare_claims_past_env_window },
        /* CHECKTX-P1 round 2 (lifetime, row keys, the unit-aware pack,
         * fee per unit) */
        { "check_tx_expiry",            t_check_tx_expiry },
        { "check_tx_row_keys",          t_check_tx_row_keys },
        { "prepare_hog_skipped",        t_prepare_hog_skipped },
        { "prepare_fee_per_unit",       t_prepare_fee_per_unit },
        /* HF-3 (Comet-only block bounds + the proposal fee check) */
        { "hf3_bounds_and_fee",         t_hf3_bounds_and_fee },
    };
    size_t i, failed = 0, ran = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    /* every name given must be a case: a typo is a failure, never a pass */
    for (int a = 1; a < argc; a++) {
        int found = 0;

        for (i = 0; i < ncases; i++)
            if (strcmp(argv[a], cases[i].name) == 0) found = 1;
        if (!found) {
            fprintf(stderr, "test_cmt_app: no case named %s\n", argv[a]);
            return 1;
        }
    }
    if (make_keys() != 0) {
        fprintf(stderr, "test_cmt_app: key generation failed\n");
        return 1;
    }
    for (i = 0; i < ncases; i++) {
        int want = 0, rc;

        if (argc > 1) {
            for (int a = 1; a < argc; a++)
                if (strcmp(argv[a], cases[i].name) == 0) want = 1;
        } else {
            want = !cases[i].long_case;
        }
        if (!want) continue;
        ran++;
        rc = cases[i].fn();

        /* No sweep here — see "FIXTURE LIFETIME" at the top. A case owns
         * its fixtures and frees them on the path that succeeds. */
        fprintf(stderr, "%-30s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) {
            failed++;
        }
    }
    fprintf(stderr, "test_cmt_app: %zu/%zu cases passed, %d checks\n",
            ran - failed, ran, g_checks);
    return failed ? 1 : 0;
}
