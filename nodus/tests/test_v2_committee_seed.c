/**
 * @file nodus/tests/test_v2_committee_seed.c
 * @brief Ledger V2 O15E Faz A — the successor committee seed source.
 *
 * Closes ACTIVATION OBLIGATION 2 (nodus_witness_v2_epoch.h): on a
 * SUCCESSOR chain, nodus_committee_compute_for_epoch's state_seed comes
 * from the committed `v2_blocks` BlockID at the lookback height, NEVER
 * from the terminal legacy `blocks` table, and an unusable seed row
 * fails closed.
 *
 * R3 W3 delta 10 — THE FIXTURE MOVED TO THE COMET LANE. Schema S14
 * dropped `v2_blocks.header` (and `qc`, `commit_cert` — R3 W1,
 * nodus_witness_v2_schema.c, D-17 rev 5): the header the seed reader
 * used to strict-decode out of that column now lives in the Comet
 * blockstore (`H:<height>` BlockMeta, nodus_witness_cmt_store.c), and
 * `v2_blocks.block_id` is the Comet HEADER HASH verbatim (R3-C1a-10).
 * The OLD fixture's `insert_row`-style helper wrote `header`/`qc`
 * columns that no longer exist at S14, so every case here now derives a
 * REAL version-3 chain and commits block 1 through the REAL Comet apply
 * lane (`nodus_cmt_app_finalize_block` + `nodus_cmt_app_commit` +
 * `nodus_cmt_bs_save_block` — no mocks, the same recipe R3 W3 delta 8's
 * preflight fixture used for the identical reason) instead of
 * hand-inserting rows the engine never actually produces.
 *
 * THE LOOKBACK HEIGHT IS 1, NOT `DNAC_EPOCH_LENGTH - 1`. The v2_seed
 * reader's behaviour does not depend on WHICH height is asked for, only
 * on what is stored there, so re-anchoring the epoch-boundary math to
 * `e_start = DNAC_EPOCH_LENGTH + 2` (giving lookback = 1) exercises
 * EXACTLY the same code paths `e_start = 2 * DNAC_EPOCH_LENGTH` (the
 * chain's real second epoch, lookback = DNAC_EPOCH_LENGTH - 1 = 719 at
 * the shipped 720-block epoch) would, without committing 719 real
 * blocks through the Comet apply lane in a unit test — the BlockStore's
 * own contiguous-height requirement (nodus_witness_cmt_store.c's
 * save_block_to_batch) means every intermediate height would have to be
 * committed for real to reach height 719, which buys no additional
 * coverage of this reader. `nodus_committee_compute_for_epoch` does not
 * require `e_start` to be an epoch multiple to reach `v2_seed_block_id`
 * — only `e_start >= DNAC_EPOCH_LENGTH + 1` (the bootstrap-path cutoff,
 * unchanged by this delta) — so `E_START + lookback = 1` is a
 * legitimate, non-degenerate call into the same function the real
 * second epoch boundary makes.
 *
 * Driven through the REAL production functions
 * (nodus_committee_compute_for_epoch / nodus_witness_vset_commit_next)
 * over real committed fixtures — no parallel test-only selector. The
 * expected committee order is derived INDEPENDENTLY in this file from
 * the documented tiebreak (SHA3-512(0x02 ‖ pubkey ‖ seed), ascending,
 * within tied-stake groups) so the assertions cannot pass by echoing
 * the implementation's output back at itself.
 *
 * THE CANDIDATE SET IS EXACTLY DNAC_COMMITTEE_SIZE (7), NOT A WIDER
 * POOL — delta 10b correction. A version-3 genesis config's own
 * validator loop enforces "L2-F6 Rule P.1 — EXACT initial validator
 * count" (nodus_witness_v2_gen.c:578-587): `cfg->n_validators` must
 * equal `DNAC_COMMITTEE_SIZE` exactly, not merely be at least that
 * many — a derived chain cannot be born with 9 candidates for a 7-seat
 * committee the way the pre-Comet fixture's hand-planted validator rows
 * could. All 7 still carry the SAME self_stake by construction (the
 * SAME per-validator shape check requires `self_stake ==
 * DNAC_SELF_STAKE_AMOUNT` exactly, nodus_witness_v2_gen.c:600-606), so
 * the tied group the tiebreak test needs still falls out of genesis
 * itself — the property under test is now "the committee equals the
 * seed-ordered 7", not "the seed-ordered top-K of a wider pool", since
 * candidates == target here; that is still a real, falsifiable claim
 * about the ORDER (a wrong seed produces a different permutation of
 * the same 7 with overwhelming probability), not a tautology. No
 * separate "seed_validators" step is needed the way the pre-Comet
 * fixture needed one — the derivation's own genesis validators ARE the
 * candidate set.
 *
 * RED TODAY (before this delta's `nodus_witness_committee.c` fix): the
 * VALID-SEED case itself. `v2_seed_block_id`'s old
 * `SELECT block_id, header FROM v2_blocks` prepare fails ("no such
 * column: header" — confirmed with sqlite3 on the harness's evidence
 * DB, /tmp/stagef-20260917T114650Z) on every version-3 chain, so the
 * function always returns MISSING/-1 regardless of what is actually
 * committed. That is the exact live defect the short-epoch harness
 * (E=15) hit at every chain's first epoch boundary (height 15): all
 * seven nodes logged "compute_for_epoch: V2 seed row at 14 missing or
 * unusable — failing closed" and stopped.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <dirent.h>

#include "crypto/hash/qgp_sha3.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_gen.h"      /* the v3 fixture */
#include "witness/nodus_witness_cmt_store.h"   /* the Comet blockstore */
#include "witness/nodus_witness_cmt_host.h"    /* nodus_abci_* request/resp */
#include "witness/nodus_witness_cmt_app.h"     /* the REAL FinalizeBlock/Commit */
#include "witness/nodus_witness_emission.h"    /* DNAC_BLOCKS_PER_YEAR,
                                                 * DNAC_DECIMAL_UNIT */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_pb_store.h"                 /* cmt_pb_store_block_meta_* */

#include "../tests/v2_genesis_fixture.h"        /* v2x_db_digest (schema-
                                                  * independent) + the
                                                  * §7 legacy sub-fixture */

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ══ THE VERSION-3 FIXTURE (duplicated locally from the pattern R3 W3
 * delta 8 used in test_v2_preflight.c — copied, not shared across test
 * files, per this package's own convention) ═══════════════════════════ */

/* delta 10b: N_VAL MUST equal DNAC_COMMITTEE_SIZE exactly — Rule P.1
 * (nodus_witness_v2_gen.c:578-587) refuses any other count at
 * derivation time. There is no wider candidate pool on this lane; see
 * the file header for what the tiebreak assertion still proves with
 * candidates == target. */
#define N_VAL 7   /* == DNAC_COMMITTEE_SIZE — test_v2_preflight.c's
                   * V3PF_N_VAL uses the same value for the same
                   * reason. A _Static_assert right after DNAC_COMMITTEE_SIZE
                   * is declared (dnac/dnac.h) pins it at 7 today; if that
                   * ever changes this file's own compile-time check below
                   * catches the drift instead of silently deriving with
                   * the wrong count again. */
#define TREASURY_RAW 93000000000000000ULL /* N_VAL self-bonds (7 *
                                            * DNAC_SELF_STAKE_AMOUNT ==
                                            * 7e15) + this ==
                                            * DNAC_DEFAULT_TOTAL_SUPPLY
                                            * (1e17) — the exact value
                                            * test_v2_preflight.c's
                                            * V3PF_TREASURY_RAW already
                                            * uses */
_Static_assert(N_VAL == DNAC_COMMITTEE_SIZE,
              "delta 10b: Rule P.1 requires n_validators == "
              "DNAC_COMMITTEE_SIZE exactly");

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

static int cfg_make(cfgbox_t *b, uint8_t salt) {
    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 1ULL;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = N_VAL;

    for (uint16_t i = 0; i < N_VAL; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] = (uint8_t)(0x11 * (i + 1) + (bb & 0x3F) + salt);
            v->unstake_destination_pubkey[bb] =
                (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        {
            static const char hexd[] = "0123456789abcdef";
            uint8_t fpr[64];
            qgp_sha3_512(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                        fpr);
            for (int hb = 0; hb < 64; hb++) {
                v->unstake_destination_fp[2 * hb]     =
                    (uint8_t)hexd[fpr[hb] >> 4];
                v->unstake_destination_fp[2 * hb + 1] =
                    (uint8_t)hexd[fpr[hb] & 0xF];
            }
            v->unstake_destination_fp[128] = '\0';
        }
        /* self_stake MUST be exactly DNAC_SELF_STAKE_AMOUNT — a version-3
         * genesis config's own validator loop rejects anything else
         * (nodus_witness_v2_gen.c's per-validator shape check). Every
         * candidate therefore carries the SAME total_stake (no
         * delegations exist yet on a fresh genesis), which is exactly
         * the tied-stake group the tiebreak test needs. */
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }

    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    {
        uint8_t owner[DNAC_PUBKEY_SIZE];
        for (size_t bb = 0; bb < sizeof(owner); bb++)
            owner[bb] = (uint8_t)(0xA0 + (bb & 0x1F) + salt);
        qgp_sha3_512(owner, sizeof(owner), b->allocs[0].dest_binding);
    }
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) { cfg_free(b); return -1; }
    c->genesis_time_ms = 1700000000000ULL;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        cfg_free(b);
        return -1;
    }
    return 0;
}

static int mkdir_tmp(char dir[256], const char *tag) {
    snprintf(dir, 256, "/tmp/test_v2_cseed_v3_%s_XXXXXX", tag);
    return mkdtemp(dir) ? 0 : -1;
}

static int rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    return system(cmd);
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
    if (e) sqlite3_free(e);
    return rc == SQLITE_OK ? 0 : -1;
}

static int derive_v3(const char *dir, uint8_t out_chain32[32],
                     uint8_t salt) {
    cfgbox_t box;
    if (cfg_make(&box, salt) != 0) return -1;
    int rc = nodus_witness_v2_gen_derive_v3(dir, box.cfg, out_chain32);
    cfg_free(&box);
    return rc;
}

/* Open the single chain database `derive_v3` landed in `dir`, READ-WRITE,
 * WITHOUT going through nodus_witness_create_chain_db — that function's
 * role-derivation refuses a version-3 chain on REOPEN today
 * (nodus_witness_v2_gen.h's own doc comment names it a W3/C1c
 * obligation this package does not own; test_v2_preflight.c's `v3pf_open`
 * is the same idiom). */
static nodus_witness_t *open_v3(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return NULL;
    struct dirent *e;
    char path[600];
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        found = 1;
        break;
    }
    closedir(d);
    if (!found) return NULL;

    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open_v2(path, &w->db, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

typedef struct {
    nodus_witness_t          *w;
    cfgbox_t                   box;
    char                       dir[256];
    uint8_t                    chain32[32];
    /* delta 10c — the STORED document's config, read back through the
     * canonical-strict reader (see fx_open's own comment for why this
     * is not `box.cfg`). */
    nodus_v2_gen_config_t     *stored_cfg;
    nodus_v2_gen_alloc_t      *stored_allocs;
    cmt_genesis_doc_t          doc;
    cmt_genesis_validator_t    gvals[N_VAL];
    nodus_cmt_store_t         *store;
    cmt_state_storage_t       *stor;
    cmt_state_t               *state;
    cmt_valset_scratch_t      *vscratch;
    cmt_state_block_scratch_t *bscratch;
    cmt_block_t               *blk;
    cmt_commit_t               last_commit;   /* borrowed by pointer into
                                               * blk — MUST outlive it */
    uint8_t                   *part_scratch;
    size_t                     part_scratch_cap;
    cmt_part_t                *parts;
    size_t                     parts_cap;
    uint8_t                    meta_scratch[4096];
} fixture_t;

static void fx_close(fixture_t *x) {
    if (!x) return;
    if (x->store) { nodus_cmt_store_release(x->store); free(x->store); }
    if (x->w) {
        if (x->w->db) sqlite3_close(x->w->db);
        free(x->w);
    }
    cfg_free(&x->box);
    free(x->stored_allocs);
    free(x->stored_cfg);
    free(x->stor);
    free(x->state);
    free(x->vscratch);
    free(x->bscratch);
    free(x->blk);
    free(x->parts);
    free(x->part_scratch);
    if (x->dir[0]) rmrf(x->dir);
    memset(x, 0, sizeof(*x));
}

/* Derive + open a fresh v3 chain and complete a cometbft State from its
 * OWN genesis document.
 *
 * delta 10c — THE DOCUMENT COMES FROM THE STORE, NOT FROM `box.cfg`.
 * `box.cfg` is the CALLER's config, handed to `derive_v3` as an INPUT;
 * `chain_id` is a derivation OUTPUT (delta 8's own note on this exact
 * point) that `derive_v3` never writes back into the caller's copy — it
 * only writes the COMPLETED document into the chain's own `cmt_state`
 * table. Building the cometbft State from `box.cfg` therefore built a
 * genesis document whose `chain_id` was still its calloc'd-zero default,
 * so block 1's header carried an EMPTY chain id while `w->v2_chain32`
 * carried the real derived one — `v2_seed_block_id`'s WRONG CHAIN check
 * (the production code, unchanged and correct) rightly refused it. A
 * real node never makes this mistake because it never reads its own
 * config back this way: `nodus_cmt_node_init` loads the genesis document
 * through the canonical-strict reader,
 * `nodus_witness_v2_gen_stored_doc(n->w, n->gen_cfg, &n->gen_allocs)`
 * (nodus_witness_cmt_node.c:1316, inside `node_load_genesis_doc`,
 * mirroring the reference's `db.Get(genesisDocKey)` +
 * `LoadStateFromDBOrGenesisDocProvider`, node.go:590-602), and projects
 * THAT — the completed, chain_id-and-app_hash-whole document — through
 * `nodus_witness_v2_gen_to_cmt_doc`. This fixture now does exactly the
 * same, so its State is built the same way a running node's is, not a
 * shortcut that happens to look similar. `nodus_witness_v2_committed_
 * global_root` is no longer needed here either: the stored document
 * already carries the completed `app_hash`, which is what that call was
 * standing in for.
 *
 * delta 10b — EVERY failure exit below routes through `fx_close(x)`
 * rather than a bare `return -1`. `fx_close` already checks each field
 * for non-NULL before freeing/closing it (it has to, since a
 * successfully-built fixture is closed the same way at the end of
 * `main`), so it is SAFE to call at any point after the `memset` above,
 * however far construction got — this is what actually fixes the ASan
 * leak the coordinator measured (334 848 B in one allocation): `cfg_make`
 * had already calloc'd `x->box.cfg`/`x->box.allocs` by the time
 * `nodus_witness_v2_gen_derive_v3` failed Rule P.1, and the bare
 * `return -1` on that line freed neither. */
static int fx_open(fixture_t *x, const char *tag, uint8_t salt) {
    memset(x, 0, sizeof(*x));
    if (cfg_make(&x->box, salt) != 0) { fx_close(x); return -1; }
    if (mkdir_tmp(x->dir, tag) != 0) { fx_close(x); return -1; }
    if (nodus_witness_v2_gen_derive_v3(x->dir, x->box.cfg, x->chain32) != 0) {
        fx_close(x);
        return -1;
    }
    x->w = open_v3(x->dir);
    if (!x->w) { fx_close(x); return -1; }
    memcpy(x->w->chain_id, x->chain32, 16);
    memset(x->w->chain_id + 16, 0, 16);
    x->w->v2_successor = true;
    memcpy(x->w->v2_chain32, x->chain32, 32);

    /* the canonical-strict reader — the node's own path, cited above */
    x->stored_cfg = calloc(1, sizeof(*x->stored_cfg));   /* ~240 KB: never
                                                          * the stack */
    if (!x->stored_cfg) { fx_close(x); return -1; }
    if (nodus_witness_v2_gen_stored_doc(x->w, x->stored_cfg,
                                        &x->stored_allocs) != 0) {
        fx_close(x);
        return -1;
    }
    if (nodus_witness_v2_gen_to_cmt_doc(x->stored_cfg, &x->doc, x->gvals,
                                        N_VAL) != 0) {
        fx_close(x);
        return -1;
    }

    x->store    = calloc(1, sizeof(*x->store));
    x->stor     = calloc(1, sizeof(*x->stor));
    x->state    = calloc(1, sizeof(*x->state));
    x->vscratch = calloc(1, sizeof(*x->vscratch));
    x->bscratch = calloc(1, sizeof(*x->bscratch));
    x->blk      = calloc(1, sizeof(*x->blk));
    x->parts_cap        = 8;
    x->parts            = calloc(x->parts_cap, sizeof(*x->parts));
    x->part_scratch_cap = (size_t)8 * CMT_BLOCK_PART_SIZE_BYTES;
    x->part_scratch     = malloc(x->part_scratch_cap);
    if (!x->store || !x->stor || !x->state || !x->vscratch || !x->bscratch ||
        !x->blk || !x->parts || !x->part_scratch) {
        fx_close(x);
        return -1;
    }

    if (nodus_cmt_store_init(x->store, x->w->db, false) != CMT_OK) {
        fx_close(x);
        return -1;
    }
    if (cmt_state_init(x->state, x->stor) != CMT_OK) { fx_close(x); return -1; }
    if (cmt_state_make_genesis(&x->doc, NULL, NULL, x->vscratch, x->state)
            != CMT_OK) {
        fx_close(x);
        return -1;
    }
    return 0;
}

/* Commit ONE empty block at height 1 through the real apply lane
 * (finalize_block + commit) AND record it in the Comet blockstore
 * (bs_save_block) — R3 W3 delta 8's fixture used the identical recipe
 * for the identical reason: `nodus_cmt_app_finalize_block` +
 * `nodus_cmt_app_commit` alone do NOT populate `cmt_blockstore` — the
 * only caller of `nodus_cmt_bs_save_block` anywhere in this repository
 * is `shared/dnac/cmt_cs.c` (the consensus round driver), which this
 * fixture does not run. The "seen commit" this needs carries ZERO
 * signatures: `nodus_cmt_bs_save_block` never verifies a seen commit's
 * signatures, only its height, so this is the honest minimum rather
 * than a faked verification result.
 *
 * @param out_id receives the committed v2_blocks.block_id (64 B, the
 *        Comet header hash) — the value `v2_seed_block_id` must return
 *        on the honest path. */
static int commit_block1(fixture_t *x, uint8_t out_id[64]) {
    uint8_t proposer[32];
    {
        uint8_t digest[64];
        if (qgp_sha3_512(x->box.cfg->validators[0].pubkey, DNAC_PUBKEY_SIZE,
                         digest) != 0)
            return -1;
        memcpy(proposer, digest, 32);
    }

    cmt_data_t data;
    memset(&data, 0, sizeof(data));
    memset(&x->last_commit, 0, sizeof(x->last_commit));

    if (cmt_state_make_block(x->state, 1, &data, &x->last_commit, NULL,
                             proposer, sizeof(proposer),
                             x->bscratch, x->blk) != CMT_OK)
        return -1;

    cmt_block_id_t bid;
    memset(&bid, 0, sizeof(bid));
    if (cmt_block_hash(x->blk, bid.hash) != CMT_OK) return -1;
    bid.hash_len = CMT_TMHASH_SIZE;
    cmt_part_set_t ps;
    if (cmt_block_make_part_set(x->blk, CMT_BLOCK_PART_SIZE_BYTES,
                                x->part_scratch, x->part_scratch_cap,
                                x->parts, x->parts_cap, &ps) != CMT_OK)
        return -1;
    if (cmt_part_set_header(&ps, &bid.part_set_header) != CMT_OK) return -1;

    nodus_abci_request_finalize_block_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.hash, bid.hash, bid.hash_len);
    req.hash_len = bid.hash_len;
    memcpy(req.next_validators_hash, x->blk->header.next_validators_hash,
           x->blk->header.next_validators_hash_len);
    req.next_validators_hash_len = x->blk->header.next_validators_hash_len;
    memcpy(req.proposer_address, x->blk->header.proposer_address,
           x->blk->header.proposer_address_len);
    req.proposer_address_len = x->blk->header.proposer_address_len;
    req.height = x->blk->header.height;
    req.time = x->blk->header.time;
    req.txs = x->blk->data.txs;
    req.txs_len = x->blk->data.txs_len;

    nodus_cmt_app_ledger_t *app = calloc(1, sizeof(*app));
    if (!app) return -1;
    int rc = -1;
    if (nodus_cmt_app_ledger_init(app, x->w, &x->doc) == CMT_OK &&
        run_sql(x->w->db, "BEGIN IMMEDIATE") == 0) {
        nodus_abci_response_finalize_block_t resp;
        nodus_abci_response_commit_t cresp;
        memset(&resp, 0, sizeof(resp));
        memset(&cresp, 0, sizeof(cresp));
        if (nodus_cmt_app_finalize_block(app, &req, &resp) == CMT_OK &&
            nodus_cmt_app_commit(app, &cresp) == CMT_OK) {
            rc = 0;
        }
    }
    free(app);
    if (rc != 0) return -1;

    cmt_commit_t seen_commit;
    memset(&seen_commit, 0, sizeof(seen_commit));
    seen_commit.height = 1;
    seen_commit.round = 0;
    seen_commit.block_id = bid;
    if (nodus_cmt_bs_save_block(x->store, x->blk, &ps, &seen_commit,
                               x->meta_scratch, sizeof(x->meta_scratch))
            != CMT_OK)
        return -1;

    if (out_id) memcpy(out_id, bid.hash, 64);
    return 0;
}

/* ── raw capture/restore of the two committed rows a tamper case needs
 * to corrupt and then heal, so each sub-case does not have to re-derive
 * and re-commit a whole chain ────────────────────────────────────────── */

typedef struct {
    uint8_t v2_blocks_present;
    uint8_t meta[4096];
    size_t  meta_len;
} honest_backup_t;

static int backup_honest(fixture_t *x, honest_backup_t *b) {
    memset(b, 0, sizeof(*b));
    if (run_sql(x->w->db,
            "CREATE TEMP TABLE v2_blocks_backup AS "
            "SELECT * FROM v2_blocks WHERE global_height = 1") != 0)
        return -1;
    b->v2_blocks_present = 1;

    nodus_cmt_store_t s;
    if (nodus_cmt_store_init(&s, x->w->db, false) != CMT_OK) return -1;
    const uint8_t *v = NULL;
    size_t n = 0;
    int rc = nodus_cmt_store_get(&s, /*state_table=*/false, "H:1", &v, &n);
    if (rc == CMT_OK && v && n > 0 && n <= sizeof(b->meta)) {
        memcpy(b->meta, v, n);
        b->meta_len = n;
    }
    nodus_cmt_store_release(&s);
    return (b->meta_len > 0) ? 0 : -1;
}

static int restore_honest(fixture_t *x, const honest_backup_t *b) {
    if (run_sql(x->w->db, "DELETE FROM v2_blocks WHERE global_height = 1")
            != 0)
        return -1;
    if (b->v2_blocks_present &&
        run_sql(x->w->db,
                "INSERT INTO v2_blocks SELECT * FROM v2_blocks_backup") != 0)
        return -1;

    nodus_cmt_store_t s;
    if (nodus_cmt_store_init(&s, x->w->db, false) != CMT_OK) return -1;
    int rc = nodus_cmt_store_set(&s, /*state_table=*/false, "H:1", b->meta,
                                 b->meta_len);
    nodus_cmt_store_release(&s);
    return rc == CMT_OK ? 0 : -1;
}

/* Load, mutate via the caller's callback, and re-store the BlockMeta at
 * "H:1" — the DECODE / MODIFY / RE-ENCODE cycle that lets a test corrupt
 * one specific field (header.height, header.chain_id, block_id.hash)
 * without a raw byte-offset guess into a protobuf blob, which the
 * length-prefixed wire format makes unsafe to hand-tamper (a single
 * flipped byte can shift every field after it and produce a decode
 * fault instead of the intended, isolated corruption). */
typedef void (*meta_mutator_fn)(cmt_pb_block_meta_t *m);

static int tamper_meta(nodus_witness_t *w, meta_mutator_fn mutate) {
    nodus_cmt_store_t s;
    if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) return -1;
    const uint8_t *v = NULL;
    size_t n = 0;
    int rc = -1;
    if (nodus_cmt_store_get(&s, false, "H:1", &v, &n) == CMT_OK && v &&
        n > 0) {
        cmt_pb_block_meta_t m;
        memset(&m, 0, sizeof(m));
        if (cmt_pb_store_block_meta_unmarshal(v, n, &m) == CMT_OK) {
            mutate(&m);
            uint8_t buf[4096];
            size_t outlen = 0;
            if (cmt_pb_store_block_meta_marshal(&m, buf, sizeof(buf),
                                                &outlen) == CMT_OK &&
                nodus_cmt_store_set(&s, false, "H:1", buf, outlen)
                    == CMT_OK) {
                rc = 0;
            }
        }
    }
    nodus_cmt_store_release(&s);
    return rc;
}

static void mutate_height(cmt_pb_block_meta_t *m) { m->header.height = 2; }
static void mutate_chain(cmt_pb_block_meta_t *m) {
    memset(m->header.chain_id, 0x99, sizeof(m->header.chain_id));
    m->header.chain_id_len = 32;
}
static void mutate_block_id_hash(cmt_pb_block_meta_t *m) {
    memset(m->block_id.hash, 0x5A, sizeof(m->block_id.hash));
    m->block_id.hash_len = 64;
}

/* ── the INDEPENDENT expected order ─────────────────────────────────── */

/* All fixture stakes are equal, so the whole candidate set is ONE tied
 * group: expected order = tiebreak ASC, where
 * tiebreak = SHA3-512(0x02 ‖ pubkey ‖ seed). Derived here from the
 * documented rule, not from the implementation's helpers. */
static void expected_order(const fixture_t *fx, const uint8_t seed[64],
                           int order_out[N_VAL]) {
    uint8_t tb[N_VAL][64];
    uint8_t buf[1 + DNAC_PUBKEY_SIZE + 64];
    for (int i = 0; i < N_VAL; i++) {
        buf[0] = NODUS_TREE_TAG_VALIDATOR;
        memcpy(&buf[1], fx->box.cfg->validators[i].pubkey, DNAC_PUBKEY_SIZE);
        memcpy(&buf[1 + DNAC_PUBKEY_SIZE], seed, 64);
        (void)qgp_sha3_512(buf, sizeof(buf), tb[i]);
        order_out[i] = i;
    }
    for (int a = 0; a < N_VAL; a++)
        for (int b = a + 1; b < N_VAL; b++)
            if (memcmp(tb[order_out[b]], tb[order_out[a]], 64) < 0) {
                int t = order_out[a];
                order_out[a] = order_out[b];
                order_out[b] = t;
            }
}

static int committee_matches(const fixture_t *fx,
                             const nodus_committee_member_t *got, int n,
                             const int order[N_VAL]) {
    if (n > N_VAL) return 0;
    for (int i = 0; i < n; i++)
        if (memcmp(got[i].pubkey, fx->box.cfg->validators[order[i]].pubkey,
                   DNAC_PUBKEY_SIZE) != 0)
            return 0;
    return 1;
}

/* ── §7's legacy-chain sub-fixture (untouched branch, untouched shape) ──
 *
 * `v2_seed_block_id` is called ONLY when `w->v2_successor` is true
 * (nodus_witness_committee.c's own caller branch) — a legacy
 * (v2_successor == false) chain always takes the SIBLING branch
 * (`nodus_witness_block_get` over the terminal `blocks` table), which
 * this delta does not touch at all. This sub-fixture is therefore kept
 * in its PRE-delta-10 shape: the old S9-era construction, not the v3
 * derivation above — proving the legacy path still behaves exactly as
 * before is a claim about code this delta never changed. */
typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain_id[32];
} legacy_fixture_t;

static int legacy_seed_validators(legacy_fixture_t *fx, uint8_t pks[N_VAL][DNAC_PUBKEY_SIZE]) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_VAL; i++) {
        for (size_t b = 0; b < DNAC_PUBKEY_SIZE; b++)
            pks[i][b] = (uint8_t)(0x11 * (i + 1) + (b & 0x3F));

        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, pks[i], DNAC_PUBKEY_SIZE);
        v.self_stake         = 0;      /* ALL EQUAL — tiebreak decides */
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        uint8_t fpr[64];
        if (qgp_sha3_512(pks[i], DNAC_PUBKEY_SIZE, fpr) != 0) return -1;
        for (int b = 0; b < 64; b++) {
            v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
            v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    return 0;
}

static void legacy_fx_close(legacy_fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    if (fx->dir[0]) rmrf(fx->dir);
}

/* delta 10b — every failure exit routes through `legacy_fx_close(fx)`,
 * the same fix as `fx_open` above and for the same reason: `fx->w` (and
 * its open `db`, once `nodus_witness_create_chain_db` succeeds) would
 * otherwise leak on any later step's failure. `legacy_fx_close` (moved
 * ABOVE this function so it is declared before its first use here) is
 * already safe to call at any point after the `memset` below — it
 * checks `fx->w`/`fx->dir[0]` for non-NULL/non-empty. */
static int legacy_fx_open(legacy_fixture_t *fx) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_cseed_legacy_XXXXXX");
    if (!mkdtemp(fx->dir)) { legacy_fx_close(fx); return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t cid16[16];
    memset(cid16, 0x6E, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) {
        legacy_fx_close(fx);
        return -1;
    }
    if (nodus_chain_config_db_migrate(fx->w) != 0) {
        legacy_fx_close(fx);
        return -1;
    }
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) {
        legacy_fx_close(fx);
        return -1;
    }

    if (run_sql(fx->w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
            " total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 0, 0, 0, 0, zeroblob(64), 0)") != 0) {
        legacy_fx_close(fx);
        return -1;
    }

    uint8_t pks[N_VAL][DNAC_PUBKEY_SIZE];
    if (legacy_seed_validators(fx, pks) != 0) { legacy_fx_close(fx); return -1; }
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) {
        legacy_fx_close(fx);
        return -1;
    }

    uint8_t vset[64], gid[64];
    memset(vset, 0x77, sizeof(vset));
    if (v2x_genesis_min(fx->w, vset, gid, NULL) != 0) {
        legacy_fx_close(fx);
        return -1;
    }
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) {
        legacy_fx_close(fx);
        return -1;
    }

    fx->w->v2_successor = false;   /* a LEGACY chain */
    return 0;
}

static int legacy_plant_row(nodus_witness_t *w, uint64_t height,
                            uint8_t fill) {
    sqlite3_stmt *st = NULL;
    uint8_t root[64];
    memset(root, fill, sizeof(root));
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO blocks (height, tx_root, tx_count,"
            " timestamp, prev_hash, state_root) "
            "VALUES (?1, zeroblob(64), 0, 0, zeroblob(64), ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob (st, 2, root, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    const uint64_t E         = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t E_START   = E + 2;   /* NOT 2*E — see the file header
                                         * for why lookback=1 exercises
                                         * the identical reader */
    const uint64_t LOOKBACK  = E_START - E - 1;   /* == 1 */

    nodus_committee_member_t *out =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*out));
    CHECK(out != NULL, "member buffer");
    int count = 0;

    fixture_t fx;
    CHECK(fx_open(&fx, "m", 0x00) == 0, "v3 fixture + cometbft State"); OK();
    CHECK(LOOKBACK == 1, "sanity: this file's re-anchored lookback is 1");
    OK();

    /* §1 — MISSING seed row (nothing committed yet) fails closed, digest
     * unchanged. THIS IS THE RED CASE the harness's own log line names:
     * before this delta's fix the SAME -1 came back here for the WRONG
     * reason (the dropped `header` column made the prepare itself fail),
     * and after committing a real block below the valid case would have
     * STILL returned -1 — the old reader could never succeed on any
     * version-3 chain, seed present or not. */
    {
        uint8_t d0[64], d1[64];
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "missing V2 seed row must fail closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "failed compute left the DB byte-identical"); OK();
    }

    /* §2 — the committed Comet BlockID at height 1 IS the seed. RED
     * TODAY: this CHECK is exactly where the harness's defect lived —
     * before this delta's fix, `nodus_committee_compute_for_epoch`
     * returns -1 here too (the "no such column: header" prepare
     * failure), not 0, so this assertion is the one that turns the
     * whole harness chain-halt into a reproducible unit failure. */
    uint8_t seed_id[64];
    honest_backup_t backup;
    {
        CHECK(commit_block1(&fx, seed_id) == 0,
              "commit block 1 through the real Comet apply lane "
              "(finalize_block + commit + bs_save_block)"); OK();
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "SELECT COUNT(*) FROM v2_blocks", -1, &st, NULL)
                      == SQLITE_OK, "prep count");
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 1,
                  "the ledger committed exactly one block row");
            sqlite3_finalize(st);
            OK();
        }
        /* delta 10c — NAME the precondition `v2_seed_block_id`'s WRONG
         * CHAIN check actually verifies, before asking it to succeed:
         * block 1's committed Comet header must carry THIS chain's real
         * derived id. Without this assertion, a future regression in
         * this fixture (e.g. reverting to building the State from
         * `box.cfg` instead of the stored document) would surface only
         * as "compute returned -1" — indistinguishable from a genuine
         * regression in the reader itself, which is exactly the
         * confusion this delta's own diagnosis went through. */
        {
            nodus_cmt_store_t s;
            CHECK(nodus_cmt_store_init(&s, fx.w->db, false) == CMT_OK,
                  "store init for the chain-id precondition check"); OK();
            nodus_cmt_block_meta_t meta;
            bool found = false;
            memset(&meta, 0, sizeof(meta));
            CHECK(nodus_cmt_bs_load_block_meta(&s, 1, &meta, &found)
                      == CMT_OK && found, "block 1's BlockMeta loads");
            OK();
            CHECK(meta.header.chain_id_len == 32 &&
                  memcmp(meta.header.chain_id, fx.w->v2_chain32, 32) == 0,
                  "block 1's committed header chain_id equals this "
                  "chain's derived v2_chain32 — the fixture's own "
                  "precondition for the WRONG CHAIN check below to mean "
                  "anything"); OK();
            nodus_cmt_store_release(&s);
        }
        CHECK(backup_honest(&fx, &backup) == 0,
              "capture the honest v2_blocks row + BlockMeta for restore "
              "between the fail-closed sub-cases below"); OK();

        int ord[N_VAL];
        expected_order(&fx, seed_id, ord);

        uint8_t d0[64], d1[64];
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
              "compute with the committed Comet seed — RED before this "
              "delta's nodus_witness_committee.c fix (see file header)");
        OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "a successful compute wrote nothing"); OK();
        CHECK(count == DNAC_COMMITTEE_SIZE, "target-size committee"); OK();
        CHECK(committee_matches(&fx, out, count, ord),
              "order follows the Comet BlockID seed"); OK();
    }

    /* §3 — fail-closed matrix over unusable seed sources, restoring the
     * honest rows between sub-cases so each one starts from the same
     * committed block. Every compute call is digest-bracketed —
     * "unchanged across every call", not just the first one. */
    {
        uint8_t d0[64], d1[64];

        /* row missing (v2_blocks side) */
        CHECK(run_sql(fx.w->db, "DELETE FROM v2_blocks WHERE global_height = 1")
                  == 0, "drop v2_blocks row"); OK();
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "v2_blocks row missing fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the missing-row reject"); OK();
        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();

        /* block_id length wrong */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "UPDATE v2_blocks SET block_id = zeroblob(63) "
                      "WHERE global_height = 1", -1, &st, NULL)
                      == SQLITE_OK, "prep shorten");
            CHECK(sqlite3_step(st) == SQLITE_DONE, "shorten id");
            sqlite3_finalize(st);
            OK();
        }
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "short block_id fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the short-id reject"); OK();
        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();

        /* blockstore meta missing */
        {
            nodus_cmt_store_t s;
            CHECK(nodus_cmt_store_init(&s, fx.w->db, false) == CMT_OK,
                  "store init"); OK();
            CHECK(nodus_cmt_store_set(&s, false, "H:1", NULL, 0) == CMT_OK,
                  "clear H:1"); OK();
            nodus_cmt_store_release(&s);
        }
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "missing BlockMeta fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the missing-meta reject"); OK();
        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();

        /* meta height != row height */
        CHECK(tamper_meta(fx.w, mutate_height) == 0, "tamper height"); OK();
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "meta height disagreeing with the row key fails closed");
        OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the height-mismatch reject"); OK();
        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();

        /* wrong chain */
        CHECK(tamper_meta(fx.w, mutate_chain) == 0, "tamper chain_id");
        OK();
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "wrong-chain BlockMeta fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the wrong-chain reject"); OK();
        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();

        /* forged: block_id != meta's own block_id.hash */
        CHECK(tamper_meta(fx.w, mutate_block_id_hash) == 0,
              "tamper block_id.hash"); OK();
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "block_id disagreeing with the BlockMeta's own hash fails "
              "closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the forged-id reject"); OK();
        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();

        /* honest state, one more time, proven by a successful compute */
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
              "restored honest state computes again"); OK();
    }

    /* §4 — lookback height 0 (e_start == E+1, direct call): UNREACHABLE
     * on this lane now, and must fail closed, not succeed. A version-3
     * chain writes NO height-0 v2_blocks row at all (D-19 rev 6 — the
     * genesis document is the identity instead), so this always finds
     * MISSING. This REPLACES the pre-delta-10 test, which asserted the
     * OPPOSITE (a successful compute reading the genesis row's BlockID)
     * — that behaviour is deleted with the dna_bh2 genesis special case
     * in nodus_witness_committee.c. */
    {
        uint8_t d0[64], d1[64];
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E + 1, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "lookback height 0 is unreachable on a version-3 chain — "
              "fails closed, MISSING"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "the height-0 rejection wrote nothing"); OK();
    }

    /* §5 — commit_next drives the same path: absent seed fails the
     * boundary step with NO snapshot row; present seed commits one.
     *
     * nodus_witness_vset_commit_next(w, boundary_height) computes
     * `next_start = boundary_height + DNAC_EPOCH_LENGTH` and builds the
     * committee for THAT e_start (nodus_witness_vset.c:650-660) — so to
     * land on the SAME e_start=E_START (lookback=1) §1-§4 exercise,
     * `boundary_height` must be `E_START - E`, not `LOOKBACK` itself
     * (the pre-delta-10 test passed E for the same reason: its
     * E_START was 2E, so E_START - E == E). */
    const uint64_t BOUNDARY_HEIGHT = E_START - E;   /* == 2 */
    {
        uint8_t d0[64], d1[64];
        CHECK(run_sql(fx.w->db, "DELETE FROM v2_blocks WHERE global_height = 1")
                  == 0, "drop seed row"); OK();
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_witness_vset_commit_next(fx.w, BOUNDARY_HEIGHT) == -1,
              "commit_next without a Comet seed fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "failed commit_next wrote nothing"); OK();

        CHECK(restore_honest(&fx, &backup) == 0, "restore honest"); OK();
        CHECK(nodus_witness_vset_commit_next(fx.w, BOUNDARY_HEIGHT) == 0,
              "commit_next with the Comet seed commits"); OK();
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "SELECT COUNT(*) FROM validator_set_snapshots "
                      "WHERE epoch_start = ?1", -1, &st, NULL)
                      == SQLITE_OK, "prep snap count");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)E_START);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 1,
                  "epoch snapshot row exists");
            sqlite3_finalize(st);
            OK();
        }
    }

    /* §6 — reopen determinism: a fresh handle over the same committed
     * bytes recomputes the identical committee. */
    {
        int ord[N_VAL];
        expected_order(&fx, seed_id, ord);
        char dir[256];
        snprintf(dir, sizeof(dir), "%s", fx.dir);
        uint8_t chain32[32];
        memcpy(chain32, fx.chain32, 32);
        /* ORCHESTRATOR (integration): the fixture's own store holds six
         * prepared statements on THIS connection; closing the connection
         * with them un-finalized makes sqlite3_close return SQLITE_BUSY
         * and leaves the connection alive — LeakSanitizer reported it as
         * an 852-object cycle (statements ↔ connection, no external
         * reference). Release the store first, then close. */
        if (fx.store) {
            nodus_cmt_store_release(fx.store);
            free(fx.store);
            fx.store = NULL;
        }
        sqlite3_close(fx.w->db);
        free(fx.w);
        fx.w = open_v3(dir);
        CHECK(fx.w != NULL, "reopen chain db"); OK();
        memcpy(fx.w->chain_id, chain32, 16);
        memset(fx.w->chain_id + 16, 0, 16);
        fx.w->v2_successor = true;
        memcpy(fx.w->v2_chain32, chain32, 32);

        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0 &&
              committee_matches(&fx, out, count, ord),
              "reopen recomputes the identical committee"); OK();
    }

    /* §7 — legacy (v2_successor == false) chains: `v2_seed_block_id` is
     * never reached; the terminal legacy `blocks` table still serves the
     * seed exactly as before this delta (the sibling branch is
     * untouched). */
    {
        legacy_fixture_t lf;
        CHECK(legacy_fx_open(&lf) == 0, "legacy fixture open"); OK();

        CHECK(legacy_plant_row(lf.w, LOOKBACK, 0xCC) == 0,
              "plant legacy seed row"); OK();

        uint8_t legacy_root[64];
        memset(legacy_root, 0xCC, sizeof(legacy_root));
        /* the legacy fixture's own pubkeys are patterned identically to
         * this file's v3 fixture (same formula, no salt) — reuse
         * expected_order's shape via a throwaway v3-style box is not
         * worth it here; assert order directly against the legacy
         * pubkeys instead. */
        uint8_t pks[N_VAL][DNAC_PUBKEY_SIZE];
        for (int i = 0; i < N_VAL; i++)
            for (size_t b = 0; b < DNAC_PUBKEY_SIZE; b++)
                pks[i][b] = (uint8_t)(0x11 * (i + 1) + (b & 0x3F));
        uint8_t tb[N_VAL][64];
        int ord_legacy[N_VAL];
        for (int i = 0; i < N_VAL; i++) {
            uint8_t buf[1 + DNAC_PUBKEY_SIZE + 64];
            buf[0] = NODUS_TREE_TAG_VALIDATOR;
            memcpy(&buf[1], pks[i], DNAC_PUBKEY_SIZE);
            memcpy(&buf[1 + DNAC_PUBKEY_SIZE], legacy_root, 64);
            qgp_sha3_512(buf, sizeof(buf), tb[i]);
            ord_legacy[i] = i;
        }
        for (int a = 0; a < N_VAL; a++)
            for (int b = a + 1; b < N_VAL; b++)
                if (memcmp(tb[ord_legacy[b]], tb[ord_legacy[a]], 64) < 0) {
                    int t = ord_legacy[a];
                    ord_legacy[a] = ord_legacy[b];
                    ord_legacy[b] = t;
                }

        CHECK(nodus_committee_compute_for_epoch(lf.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
              "legacy compute"); OK();
        int matched = 1;
        for (int i = 0; i < count && matched; i++)
            if (memcmp(out[i].pubkey, pks[ord_legacy[i]], DNAC_PUBKEY_SIZE)
                != 0)
                matched = 0;
        CHECK(matched,
              "legacy chain follows the legacy state_root seed — the "
              "sibling branch this delta does not touch"); OK();
        legacy_fx_close(&lf);
    }

    free(out);
    fx_close(&fx);
    printf("test_v2_committee_seed: ALL %d CHECKS PASSED\n", g_checks);
    return 0;
}
