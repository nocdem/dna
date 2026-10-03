/**
 * @file nodus/tests/test_addr_index.c
 * @brief The node-local address history index (nodus_witness_addr_
 *        index.c) and its `dnac_addr_history` answer, over a REAL derived
 *        version-3 chain driven through the REAL host pipeline.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 * Governing record: docs/plans/decisions/2026-10-01-node-address-history-
 * index.md (rev 2). Blocks are committed exactly as a node commits them:
 * nodus_cmt_host_apply_verified_block (FinalizeBlock + the stored
 * response + Commit) then nodus_cmt_bs_save_block — the pipeline of
 * test_v3_block_query.c, whose fixture this file copies (the tree's
 * per-file fixture convention).
 *
 *  t_rows (flag ON) — height 1 = [a REAL claim (applied), envelope-marker
 *    bytes that do not decode (refused DECODE)]; height 2 = [a REAL SPEND
 *    of the claim coin, 1 DNAC to g_ks[1] + change (applied), a second
 *    SPEND of the SAME coin (refused EXEC)]. Then:
 *      · height 1 holds EXACTLY one row: the claimant's `claim` row with
 *        the leaf amount, native token, no peer, no fee, wire = SHA3-512
 *        of the claim bytes, i = 1 (the ENGINE position: the refused
 *        envelope is engine item 0 although the claim is block tx 0);
 *      · height 2 holds EXACTLY two rows, both at i = 0: the payer's
 *        `spend_out` (fee on it, peer = recipient) and the recipient's
 *        `spend_in` (no fee, peer = payer), wire = the preflight wire id;
 *        the change output writes no row; the refused item (i = 1) none;
 *      · every row's ts = that block's Comet header time (seconds);
 *      · the marker reads from 1 / last 2;
 *      · the builder: owner == session answers newest first with the
 *        values above; owner != session and no session are
 *        NOT_AUTHENTICATED; limit 0 / 101 and a non-hex owner are
 *        PROTOCOL_ERROR; the recipient sees its one spend_in row;
 *        limit 1 + the (h, i, q) cursor walks every row once and ends
 *        empty; a height-only cursor skips that height; two builds answer
 *        identical bytes;
 *      · height 3 = [a valid SPEND] with the engine interrupted at
 *        V2AP_FAIL_AFTER_TX_INDEX (after the item's rows and the block
 *        close were written): the host rolls back — no row at height 3,
 *        the marker still says last 2.
 *  t_flag_off — the same height 1 with the flag OFF: no row, no marker;
 *    the builder answers enabled = false, from_height = 0, count = 0.
 *  t_decoder_hostile — the client decoder refuses: entries not strictly
 *    descending, a count that disagrees with the array, an unknown kind,
 *    a 63-byte wire, and truncation at every length of a valid reply.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. SQLite
 * >= 3.35.0 (row-value comparison in the cursor query; the S14 rung
 * already requires 3.35.0). No network.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_addr_idx_*` directory per fixture, removed at close. A
 * case that aborts through CHECK leaves its directory behind.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The handler's argument decode (handle_dnac_addr_history: duplicate
 *     keys, bi/bq without before) and the client's round trip are NOT
 *     driven (no socket): the builder is called with the session
 *     fingerprint the handler would pass, and its frame is decoded by the
 *     client decoder directly.
 *  2. Only claim and SPEND rows come from a real chain. BURN,
 *     TOKEN_CREATE, the SYSTEM records (stake / delegate / undelegate /
 *     unstake / validator_update), the payout and the graduation release
 *     share the writer's code path but are not applied here — no
 *     assertion covers their row shapes.
 *  3. The payer convention (signer_fp[0], or the first satisfied
 *     multisig address) is exercised only for a single-signer kind-1
 *     spend; a multisig spend is not driven.
 *  4. The flag-off → on GAP rule of the marker (from_height restarts) is
 *     not driven: one witness keeps its flag for the whole case.
 *  5. "No row for a refused item" is proven for refusals that happen
 *     BEFORE the writer runs (EXEC, DECODE); no refusal path exists after
 *     it inside the item's savepoint today, so the savepoint argument is
 *     structural, and the whole-block rollback case is what exercises a
 *     rollback of rows that WERE written.
 *  6. Nothing here was RUN by its author (BUILDER: compile only). Every
 *     expectation is an expectation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
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

#include "nodus/nodus.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_emission.h"      /* DNAC_DECIMAL_UNIT   */
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_cmt_app.h"
#include "witness/nodus_witness_addr_index.h"
#include "server/nodus_server.h"
#include "protocol/nodus_cbor.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/manifest_wire.h"

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

/* ══ deterministic REAL keys — test_v3_block_query.c's shape ══════════ */

#define N_KEYS       ((int)DNAC_COMMITTEE_SIZE)
#define TREASURY_RAW 93000000000000000ULL   /* test_cmt_app.c:257 */
#define GEN_TIME_MS  1767225600000ULL       /* test_cmt_app.c:258 */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
    uint8_t fpraw[64];                       /* SHA3-512(pk)            */
    char    fp[129];                         /* its 128 lowercase hex   */
} keyset_t;

static keyset_t g_ks[N_KEYS];

static void hex64(const uint8_t raw[64], char out[129])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hexd[raw[i] >> 4];
        out[2 * i + 1] = hexd[raw[i] & 0x0F];
    }
    out[128] = '\0';
}

static int make_keys(void)
{
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];

        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES,
                         g_ks[i].fpraw) != 0)
            return -1;
        memcpy(g_ks[i].voter, g_ks[i].fpraw, 32);
        hex64(g_ks[i].fpraw, g_ks[i].fp);
    }
    return 0;
}

static void rmrf(const char *path)
{
    char cmd[300];

    if (!path || !path[0]) return;
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

/* ══ FIXTURE — a REAL version-3 chain (test_v3_block_query.c:233-370) ═ */

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

static int cfg_make_v3_real(cfgbox_t *b)
{
    nodus_v2_gen_config_t *c;

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
    c->inflation_start_block = 0ULL;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = (uint16_t)N_KEYS;
    for (uint16_t k = 0; k < (uint16_t)N_KEYS; k++) {
        nodus_v2_gen_validator_t *v = &c->validators[k];
        uint8_t d[64];
        char    h[129];

        memcpy(v->pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE);
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++)
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        qgp_sha3_512(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE, d);
        hex64(d, h);
        memcpy(v->unstake_destination_fp, h, 129);
        memset(v->unstake_destination_pubkey, 0, DNAC_PUBKEY_SIZE);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    /* the claim pipeline binds SHA3-512(claimant pubkey) to this field —
     * g_ks[0] is the claimant */
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    c->reward_pool_initial = 0;
    /* the spends pay the flat floor with a 200 000-unit ceiling; the
     * chain opts out of the gas price with a committed price-0 row
     * (test_v3_block_query.c, same reason) */
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

/* Opened by hand (no nodus_witness_init), so the index tables are
 * created HERE with the migrate the witness open path runs
 * (nodus_witness_db_migrate_v12), and the node flag is set on the
 * fixture's server struct — the place a node reads it from. */
static int gfx_open(gfx_t *g, const char *tag, bool flag_on)
{
    char path[600];

    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real(&g->box) != 0) return -1;
    if (nodus_witness_v2_gen_v3_validate(g->box.cfg) != 0) return -1;
    snprintf(g->dir, sizeof(g->dir), "/tmp/test_addr_idx_%s_XXXXXX", tag);
    if (!mkdtemp(g->dir)) return -1;
    if (nodus_witness_v2_gen_derive_v3(g->dir, g->box.cfg, g->chain32) != 0)
        return -1;
    {
        char hex[33];
        for (int i = 0; i < 16; i++)
            snprintf(hex + 2 * i, 3, "%02x", g->chain32[i]);
        hex[32] = '\0';
        snprintf(path, sizeof(path), "%s/witness_%s.db", g->dir, hex);
    }
    g->w   = calloc(1, sizeof(*g->w));           /* multi-MB: never stack */
    g->srv = calloc(1, sizeof(*g->srv));
    if (!g->w || !g->srv) return -1;
    if (sqlite3_open_v2(path, &g->w->db, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK)
        return -1;
    snprintf(g->w->data_path, sizeof(g->w->data_path), "%s", g->dir);
    g->w->cached_committee_epoch_start = UINT64_MAX;
    g->w->v2_successor     = true;
    g->w->v2_ingress_armed = true;
    memcpy(g->w->v2_chain32, g->chain32, 32);
    memcpy(g->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(g->srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(g->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    g->srv->config.addr_history_index = flag_on;
    nodus_server_witness_host(g->srv, &g->host);
    g->w->host = &g->host;
    memcpy(g->w->my_id, g_ks[0].voter, 32);
    return nodus_witness_addr_index_migrate(g->w);
}

static void gfx_close(gfx_t *g)
{
    if (g->w) {
        if (g->w->db) sqlite3_close(g->w->db);
        free(g->w);
        g->w = NULL;
    }
    free(g->srv);
    g->srv = NULL;
    cfg_free(&g->box);
    rmrf(g->dir);
}

/* ══ the blockexec + block store (test_v3_block_query.c:372-629) ══════ */

#define TXS_CAP   8u
#define PARTS_CAP 16u

static int t_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
    return CMT_OK;
}

static int t_mono(void *ctx, int64_t *out_ns)
{
    (void)ctx;
    *out_ns = 7LL * 1000000000LL;
    return CMT_OK;
}

typedef struct {
    nodus_cmt_store_t      *store;
    nodus_cmt_blockexec_t  *be;
    nodus_cmt_app_ledger_t *ledger;
    nodus_cmt_app_t         app_if;
    nodus_cmt_mempool_if_t  mp_if;
    nodus_cmt_evpool_if_t   ev_if;
    nodus_cmt_host_limits_t lim;
    cmt_state_storage_t    *stor;
    cmt_state_t            *state;
    cmt_valset_scratch_t   *vscratch;
    cmt_state_block_scratch_t *bscratch;
    cmt_genesis_doc_t       doc;
    cmt_genesis_validator_t gvals[DNAC_COMMITTEE_SIZE];
    cmt_block_t            *blk;
    cmt_pb_bytes_t          txs[TXS_CAP];
    cmt_commit_t            last_commit;
    cmt_commit_sig_t       *last_sigs;
    uint8_t                 chain_id[32];
    uint8_t                *part_scratch;
    size_t                  part_scratch_cap;
    cmt_part_t             *parts;
    uint8_t                *save_scratch;
    size_t                  save_cap;
    cmt_block_id_t          bid;
} exec_t;

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
    free(x->save_scratch);
    memset(x, 0, sizeof(*x));
}

static int gfx_doc(gfx_t *g, cmt_genesis_doc_t *doc,
                   cmt_genesis_validator_t *gvals)
{
    if (nodus_witness_v2_committed_global_root(g->w, g->box.cfg->app_hash)
        != 0)
        return -1;
    memcpy(g->box.cfg->chain_id, g->chain32, NODUS_V2_GEN_CHAIN_ID_LEN);
    return nodus_witness_v2_gen_to_cmt_doc(g->box.cfg, doc, gvals,
                                           DNAC_COMMITTEE_SIZE);
}

static int exec_init(exec_t *x, gfx_t *g)
{
    memset(x, 0, sizeof(*x));
    x->store     = calloc(1, sizeof(*x->store));
    x->be        = calloc(1, sizeof(*x->be));
    x->ledger    = calloc(1, sizeof(*x->ledger));
    x->stor      = calloc(1, sizeof(*x->stor));
    x->state     = calloc(1, sizeof(*x->state));
    x->vscratch  = calloc(1, sizeof(*x->vscratch));
    x->bscratch  = calloc(1, sizeof(*x->bscratch));
    x->blk       = calloc(1, sizeof(*x->blk));
    x->last_sigs = calloc(CMT_VALSET_MAX, sizeof(*x->last_sigs));
    x->parts     = calloc(PARTS_CAP, sizeof(*x->parts));
    x->part_scratch_cap = (size_t)PARTS_CAP * CMT_BLOCK_PART_SIZE_BYTES;
    x->part_scratch     = malloc(x->part_scratch_cap);
    x->save_cap         = (size_t)1u << 20;
    x->save_scratch     = malloc(x->save_cap);
    if (!x->store || !x->be || !x->ledger || !x->stor || !x->state ||
        !x->vscratch || !x->bscratch || !x->blk || !x->last_sigs ||
        !x->parts || !x->part_scratch || !x->save_scratch)
        return -1;
    if (nodus_cmt_store_init(x->store, g->w->db, false) != CMT_OK) return -1;
    memcpy(x->chain_id, g->chain32, 32);
    if (gfx_doc(g, &x->doc, x->gvals) != 0) return -1;
    if (nodus_cmt_app_ledger_init(x->ledger, g->w, &x->doc) != CMT_OK ||
        nodus_cmt_app_ledger_build(&x->app_if, x->ledger) != CMT_OK)
        return -1;
    x->mp_if = nodus_cmt_nop_mempool;
    x->ev_if = nodus_cmt_empty_evpool;
    x->lim.max_txs      = TXS_CAP;
    x->lim.tx_arena_cap = 2u * 1024u * 1024u;
    x->lim.max_evidence = 4;
    if (nodus_cmt_blockexec_init(x->be, x->store, &x->app_if, &x->mp_if,
                                 &x->ev_if, NULL, NULL, t_now, NULL, t_mono,
                                 NULL, NULL, NULL, &x->lim) != CMT_OK)
        return -1;
    if (cmt_state_init(x->state, x->stor) != CMT_OK ||
        cmt_state_make_genesis(&x->doc, NULL, NULL, x->vscratch, x->state)
            != CMT_OK)
        return -1;
    return nodus_cmt_ss_save(x->store, x->state) == CMT_OK ? 0 : -1;
}

static bool block_id_is_complete(const cmt_block_id_t *bid)
{
    return bid->hash_len == CMT_TMHASH_SIZE &&
           bid->part_set_header.total > 0 &&
           bid->part_set_header.hash_len == CMT_TMHASH_SIZE;
}

static int app_sign_vote(void *ctx, const uint8_t *chain_id,
                         size_t chain_id_len, cmt_pb_vote_t *v)
{
    const keyset_t *k = (const keyset_t *)ctx;
    uint8_t         sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t          sb_len = 0, sig_len = 0;

    if (cmt_vote_sign_bytes(chain_id, chain_id_len, v, sb, sizeof(sb),
                            &sb_len) != CMT_OK)
        return CMT_FAULT;
    if (qgp_dsa87_sign(v->signature, &sig_len, sb, sb_len, k->sk) != 0)
        return CMT_FAULT;
    v->signature_len = sig_len;
    return CMT_OK;
}

static int exec_make_last_commit(exec_t *x, int64_t height,
                                 const cmt_block_id_t *bid)
{
    cmt_validator_set_t  vals;
    cmt_validator_t     *storage = NULL;
    cmt_vote_t          *vote = NULL;
    size_t               i;
    int                  rc = -1;

    storage = calloc(CMT_VALSET_MAX, sizeof(*storage));
    vote    = calloc(1, sizeof(*vote));
    if (!storage || !vote || !block_id_is_complete(bid)) goto done;
    if (cmt_validator_set_init(&vals, storage, CMT_VALSET_MAX) != CMT_OK ||
        nodus_cmt_ss_load_validators(x->store, height, &vals) != CMT_OK)
        goto done;
    if (vals.validators_len > CMT_VALSET_MAX) goto done;
    for (i = 0; i < vals.validators_len; i++) {
        const keyset_t *k = NULL;
        bool recoverable = false;

        for (int j = 0; j < N_KEYS; j++) {
            if (memcmp(g_ks[j].voter, vals.validators[i].address, 32) == 0) {
                k = &g_ks[j];
                break;
            }
        }
        if (!k) goto done;
        memset(vote, 0, sizeof(*vote));
        memcpy(vote->validator_address, k->voter, 32);
        vote->validator_address_len = 32;
        vote->validator_index = (int32_t)i;
        vote->height          = height;
        vote->round           = 0;
        vote->type            = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
        vote->block_id        = *bid;
        vote->timestamp       = x->state->last_block_time;
        if (cmt_sign_and_check_vote(vote, app_sign_vote, (void *)k,
                                    x->chain_id, 32, false,
                                    &recoverable) != CMT_OK)
            goto done;
        if (cmt_vote_commit_sig(vote, &x->last_sigs[i]) != CMT_OK) goto done;
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

/* Commit height `h` carrying x->txs[0..n) — MakeBlock, the COMPLETE
 * BlockID, ApplyVerifiedBlock, SaveBlock. */
static int commit_height(exec_t *x, int64_t h, size_t n)
{
    cmt_data_t     data;
    cmt_part_set_t ps;
    cmt_commit_t   seen;

    if (h > 1 && exec_make_last_commit(x, h - 1, &x->bid) != 0) return -1;
    if (h == x->state->initial_height) {
        memset(&x->last_commit, 0, sizeof(x->last_commit));
        x->last_commit.signatures     = x->last_sigs;
        x->last_commit.signatures_cap = CMT_VALSET_MAX;
        x->last_commit.signatures_len = 0;
    }
    memset(&data, 0, sizeof(data));
    data.txs     = x->txs;
    data.txs_cap = TXS_CAP;
    data.txs_len = n;
    memset(x->blk, 0, sizeof(*x->blk));
    if (cmt_state_make_block(x->state, h, &data, &x->last_commit, NULL,
                             x->state->validators.proposer.address,
                             x->state->validators.proposer.address_len,
                             x->bscratch, x->blk) != CMT_OK)
        return -1;
    memset(&x->bid, 0, sizeof(x->bid));
    if (cmt_block_hash(x->blk, x->bid.hash) != CMT_OK) return -1;
    x->bid.hash_len = CMT_TMHASH_SIZE;
    if (cmt_block_make_part_set(x->blk, CMT_BLOCK_PART_SIZE_BYTES,
                                x->part_scratch, x->part_scratch_cap,
                                x->parts, PARTS_CAP, &ps) != CMT_OK ||
        cmt_part_set_header(&ps, &x->bid.part_set_header) != CMT_OK ||
        !block_id_is_complete(&x->bid))
        return -1;
    if (nodus_cmt_host_apply_verified_block(x->be, &x->bid, x->blk,
                                            x->state) != CMT_OK)
        return -1;
    memset(&seen, 0, sizeof(seen));
    seen.height   = h;
    seen.round    = 0;
    seen.block_id = x->bid;
    return nodus_cmt_bs_save_block(x->store, x->blk, &ps, &seen,
                                   x->save_scratch, x->save_cap) == CMT_OK
               ? 0 : -1;
}

/* ══ items (test_v3_block_query.c:631-802) ═══════════════════════════ */

static const uint8_t POISON[20] = {
    'N','D','S','.','E','N','V','W','I','R','E','.','v','1', 0, 0,
    0xFF, 0xFF, 0xFF, 0xFF
};

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
} test_env_t;

static int build_claim(gfx_t *g, uint8_t *out, size_t cap, size_t *len)
{
    dna_gman_t      m;
    dna_dist_leaf_t leaf;
    dna_claim_t    *c = calloc(1, sizeof(*c));      /* ~5 KB: heap       */
    uint8_t         mh[64];
    uint8_t         pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t          pre_len = 0, siglen = 0;
    int             rc = -1;

    if (!c) return -1;
    if (nodus_witness_v2_manifest_load(g->w, 0, &m) != 0 ||
        dna_gman_hash(&m, mh) != 0)
        goto done;
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version  = DNA_DIST_VERSION;
    leaf.source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
    memcpy(leaf.source_id, g->box.allocs[0].source_id, NODUS_V2_GEN_SRCID_LEN);
    leaf.source_amount = g->box.allocs[0].amount;
    memcpy(leaf.dest_binding, g->box.allocs[0].dest_binding, 64);

    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, g->chain32, DNA_CHAIN_ID_LEN);
    memcpy(c->manifest_hash, mh, 64);
    c->leaf_index    = 0;
    c->source_id_len = leaf.source_id_len;
    memcpy(c->source_id, leaf.source_id, leaf.source_id_len);
    c->source_amount = leaf.source_amount;
    memcpy(c->dest_binding, leaf.dest_binding, 64);
    c->n_siblings = 0;                    /* a one-leaf tree             */
    c->auth_mode  = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, g_ks[0].pk, QGP_DSA87_PUBLICKEYBYTES);
    if (dna_claim_preimage(c, pre, &pre_len) != 0 ||
        qgp_dsa87_sign(c->signature, &siglen, pre, pre_len, g_ks[0].sk) != 0 ||
        siglen != DNA_CLAIM_SIG_LEN)
        goto done;
    if (dna_claim_encode(c, out, cap, len) != 0) goto done;
    rc = 0;
done:
    free(c);
    return rc;
}

typedef struct {
    int      owner;
    uint64_t amount;
    uint8_t  seed_byte;
} out_spec_t;

static uint32_t spend_call(uint8_t *dst, size_t cap, const uint8_t in[64],
                           const out_spec_t *outs, int n_out)
{
    size_t off = 0;
    size_t need = 2 + 64 + (size_t)n_out * 232;

    if (need > cap) return 0;
    dst[off++] = 1;
    memcpy(dst + off, in, 64);
    off += 64;
    dst[off++] = (uint8_t)n_out;
    for (int o = 0; o < n_out; o++) {
        memcpy(dst + off, g_ks[outs[o].owner].fp, 128);
        for (int i = 0; i < 8; i++)
            dst[off + 128 + i] = (uint8_t)(outs[o].amount >> (56 - 8 * i));
        memset(dst + off + 136, 0, 64);           /* native token        */
        memset(dst + off + 200, outs[o].seed_byte, 32);
        off += 232;
    }
    return (uint32_t)off;
}

static void out_id(int owner, uint8_t seed_byte, uint8_t out[64])
{
    uint8_t pre[160];
    memcpy(pre, g_ks[owner].fp, 128);
    memset(pre + 128, seed_byte, 32);
    qgp_sha3_512(pre, sizeof(pre), out);
}

/* A one-leg CORE SPEND envelope, auth kind 1, signed by g_ks[0] at the
 * candidate height `cand`. */
static int build_spend_env(gfx_t *g, uint64_t cand, const uint8_t *call,
                           uint32_t call_len, uint64_t fee, test_env_t *out)
{
    dna_domain_manifest_t man;
    dna_env_preflight_t  *pf = calloc(1, sizeof(*pf));
    uint8_t              *auth = NULL, *env = NULL;
    size_t                auth_len = 1 + NODUS_RT_AUTH_SIGNER_LEN;
    size_t                env_len = 0, used = 0, sl = 0;
    dna_env_leg_in_t      leg;
    dna_env_in_t          in;
    dna_env_leg_ctx_t     lctx;
    int                   rc = -1;

    memset(out, 0, sizeof(*out));
    if (!pf) return -1;
    if (nodus_witness_domreg_get(g->w, DNA_DOMAIN_CORE, NULL, &man, NULL)
        != 0)
        goto done;
    auth = calloc(1, auth_len);
    if (!auth) goto done;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_CORE;
    leg.hdr.runtime_op           = DNA_CORERULE_SPEND;
    leg.hdr.ruleset_version      = man.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len             = call_len;
    leg.hdr.auth_len             = (uint32_t)auth_len;
    leg.hdr.res_max_effects      = 40;
    leg.hdr.res_max_effect_bytes = 16384;
    leg.call_data                = call;
    leg.auth_data                = auth;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = cand + (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD;
    in.fee_amount          = fee;
    in.res_max_total_units = 200000;
    in.leg_count           = 1;
    in.legs                = &leg;
    if (dna_env_encoded_size(&leg, 1, &env_len) != 0) goto done;
    env = malloc(env_len);
    if (!env) goto done;
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = man.ruleset_version;
    memcpy(lctx.ruleset_hash, man.ruleset_hash, 64);
    if (dna_env_encode(&in, env, env_len, &used) != 0 || used != env_len ||
        dna_env_preflight(env, env_len, g->chain32, cand, &lctx, 1, pf)
            != DNA_ENV_PF_OK)
        goto done;
    auth[0] = 1;
    memcpy(auth + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
    if (qgp_dsa87_sign(auth + 1 + DNAC_PUBKEY_SIZE, &sl, pf->auth_digest[0],
                       64, g_ks[0].sk) != 0)
        goto done;
    if (dna_env_encode(&in, env, env_len, &used) != 0 || used != env_len ||
        dna_env_preflight(env, env_len, g->chain32, cand, &lctx, 1, pf)
            != DNA_ENV_PF_OK)
        goto done;
    out->bytes = env;
    out->len   = env_len;
    memcpy(out->wire_id, pf->wire_id, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    env = NULL;
    rc = 0;
done:
    free(env);
    free(auth);
    free(pf);
    return rc;
}

/* ══ index readers (independent of the module: plain SQL) ════════════ */

static long long q1(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    long long     v = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

typedef struct {
    uint8_t  owner[64];
    char     kind[24];
    uint64_t amount;
    uint8_t  token[64];
    uint64_t fee;
    bool     has_peer;
    uint8_t  peer[64];
    bool     has_wire;
    uint8_t  wire[64];
    bool     has_ts;
    uint64_t ts;
} row_t;

/* The row at (h, i, seq). @return 1 found, 0 absent, -1 error. */
static int row_get(nodus_witness_t *w, uint64_t h, uint32_t i, uint32_t seq,
                   row_t *r)
{
    sqlite3_stmt *st = NULL;
    int           rc, ret = -1;

    memset(r, 0, sizeof(*r));
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, kind, amount, token, fee, peer, wire, ts "
            "FROM addr_history WHERE h = ?1 AND i = ?2 AND seq = ?3",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)i);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)seq);
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { ret = 0; goto done; }
    if (rc != SQLITE_ROW) goto done;
    if (sqlite3_column_bytes(st, 0) != 64 ||
        sqlite3_column_bytes(st, 3) != 64 ||
        sqlite3_column_bytes(st, 1) <= 0 ||
        sqlite3_column_bytes(st, 1) >= (int)sizeof(r->kind))
        goto done;
    memcpy(r->owner, sqlite3_column_blob(st, 0), 64);
    memcpy(r->kind, sqlite3_column_text(st, 1),
           (size_t)sqlite3_column_bytes(st, 1));
    r->amount = (uint64_t)sqlite3_column_int64(st, 2);
    memcpy(r->token, sqlite3_column_blob(st, 3), 64);
    r->fee = (uint64_t)sqlite3_column_int64(st, 4);
    if (sqlite3_column_type(st, 5) == SQLITE_BLOB &&
        sqlite3_column_bytes(st, 5) == 64) {
        r->has_peer = true;
        memcpy(r->peer, sqlite3_column_blob(st, 5), 64);
    } else if (sqlite3_column_type(st, 5) != SQLITE_NULL) {
        goto done;
    }
    if (sqlite3_column_type(st, 6) == SQLITE_BLOB &&
        sqlite3_column_bytes(st, 6) == 64) {
        r->has_wire = true;
        memcpy(r->wire, sqlite3_column_blob(st, 6), 64);
    } else if (sqlite3_column_type(st, 6) != SQLITE_NULL) {
        goto done;
    }
    if (sqlite3_column_type(st, 7) == SQLITE_INTEGER) {
        r->has_ts = true;
        r->ts = (uint64_t)sqlite3_column_int64(st, 7);
    }
    ret = 1;
done:
    sqlite3_finalize(st);
    return ret;
}

static long long rows_at(nodus_witness_t *w, uint64_t h)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM addr_history WHERE "
             "h = %llu", (unsigned long long)h);
    return q1(w->db, sql);
}

static int mark_get(nodus_witness_t *w, long long *from_h, long long *last_h)
{
    *from_h = q1(w->db, "SELECT from_height FROM addr_history_mark "
                        "WHERE id = 1");
    *last_h = q1(w->db, "SELECT last_height FROM addr_history_mark "
                        "WHERE id = 1");
    return (*from_h > 0 && *last_h > 0) ? 0 : -1;
}

/* Build + decode one page. @return 0 / -1 (the builder refused: *ecode). */
static int page(gfx_t *g, const uint8_t *session, const char *owner,
                const nodus_witness_addr_cursor_t *cur, uint32_t limit,
                nodus_dnac_addr_history_result_t *r, int *ecode)
{
    uint8_t *f = NULL;
    size_t   fl = 0;
    int      ec = 0;
    char     m[128];

    memset(r, 0, sizeof(*r));
    if (nodus_witness_addr_history_build(g->w, 7, session, owner, cur, limit,
                                         &f, &fl, &ec, m, sizeof(m)) != 0) {
        if (ecode) *ecode = ec;
        return -1;
    }
    if (nodus_dnac_addr_history_decode(f, fl, r) != 0) {
        free(f);
        if (ecode) *ecode = -999;
        return -1;
    }
    free(f);
    return 0;
}

static const uint8_t ZERO64[64] = {0};

/* ══ the real-chain case, flag ON ════════════════════════════════════ */

static int t_rows(void)
{
    gfx_t        g;
    exec_t       x;
    uint8_t      cbytes[DNA_CLAIM_MAX_WIRE];
    size_t       clen = 0;
    uint8_t      claim_nul[64], claim_coin[64], claim_wire[64];
    uint64_t     ts1 = 0, ts2 = 0;
    long long    from_h = 0, last_h = 0;
    const uint64_t fee = DNAC_MIN_FEE_RAW;
    const uint64_t pay = 100000000ULL;           /* 1 DNAC to g_ks[1]    */
    test_env_t   spend_a, spend_b, spend_c;
    row_t        r;
    int          ec = 0;
    static uint8_t call_a[4096], call_b[4096], call_c[4096];

    CHECK(gfx_open(&g, "on", true) == 0, "version-3 fixture, flag ON");
    CHECK(nodus_witness_addr_index_enabled(g.w), "the flag reads ON");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM addr_history") == 0 &&
          q1(g.w->db, "SELECT COUNT(*) FROM addr_history_mark") == 0,
          "the index starts EMPTY — no backfill (rev 2 item 3)");

    /* ── height 1: [claim (applied), POISON (refused DECODE)] ───────── */
    CHECK(build_claim(&g, cbytes, sizeof(cbytes), &clen) == 0, "claim");
    CHECK(nodus_witness_v2_claim_nullifier(g.w, cbytes, clen, claim_nul)
              == 0, "the claim's nullifier");
    CHECK(dna_claim_utxo_id(claim_nul, claim_coin) == 0, "its coin id");
    CHECK(qgp_sha3_512(cbytes, clen, claim_wire) == 0, "claim hash");
    x.txs[0].data = cbytes; x.txs[0].len = clen;
    x.txs[1].data = POISON; x.txs[1].len = sizeof(POISON);
    CHECK(commit_height(&x, 1, 2) == 0, "height 1 commits");
    ts1 = (uint64_t)x.blk->header.time.seconds;

    CHECK(rows_at(g.w, 1) == 1, "height 1: exactly one row");
    CHECK(row_get(g.w, 1, 1, 0, &r) == 1,
          "the claim row sits at ENGINE position 1 (the refused envelope "
          "is engine item 0; the claim is block tx 0)");
    CHECK(memcmp(r.owner, g_ks[0].fpraw, 64) == 0 &&
          strcmp(r.kind, NODUS_ADDR_KIND_CLAIM) == 0 &&
          r.amount == TREASURY_RAW && memcmp(r.token, ZERO64, 64) == 0 &&
          r.fee == 0 && !r.has_peer,
          "owner = the claimant's raw fp, kind claim, the leaf amount, "
          "native, no fee, no invented sender");
    CHECK(r.has_wire && memcmp(r.wire, claim_wire, 64) == 0,
          "wire = SHA3-512 of the claim's canonical bytes");
    CHECK(r.has_ts && r.ts == ts1, "ts = block 1's Comet header time");
    CHECK(mark_get(g.w, &from_h, &last_h) == 0 && from_h == 1 && last_h == 1,
          "marker: the first indexed height is 1");

    /* ── height 2: [SPEND a (applied), SPEND b same input (refused)] ── */
    {
        out_spec_t oa[2] = {
            { 1, pay,                              0xA1 },
            { 0, TREASURY_RAW - pay - fee,         0xA2 },
        };
        out_spec_t ob[1] = { { 1, TREASURY_RAW - fee, 0xB1 } };
        uint32_t la = spend_call(call_a, sizeof(call_a), claim_coin, oa, 2);
        uint32_t lb = spend_call(call_b, sizeof(call_b), claim_coin, ob, 1);

        CHECK(la && lb, "spend calls");
        CHECK(build_spend_env(&g, 2, call_a, la, fee, &spend_a) == 0,
              "spend a");
        CHECK(build_spend_env(&g, 2, call_b, lb, fee, &spend_b) == 0,
              "spend b (the same input)");
    }
    x.txs[0].data = spend_a.bytes; x.txs[0].len = spend_a.len;
    x.txs[1].data = spend_b.bytes; x.txs[1].len = spend_b.len;
    CHECK(commit_height(&x, 2, 2) == 0, "height 2 commits");
    ts2 = (uint64_t)x.blk->header.time.seconds;

    CHECK(rows_at(g.w, 2) == 2, "height 2: exactly two rows");
    CHECK(row_get(g.w, 2, 0, 0, &r) == 1 &&
          memcmp(r.owner, g_ks[0].fpraw, 64) == 0 &&
          strcmp(r.kind, NODUS_ADDR_KIND_SPEND_OUT) == 0 &&
          r.amount == pay && memcmp(r.token, ZERO64, 64) == 0 &&
          r.fee == fee && r.has_peer &&
          memcmp(r.peer, g_ks[1].fpraw, 64) == 0 &&
          r.has_wire && memcmp(r.wire, spend_a.wire_id, 64) == 0 &&
          r.has_ts && r.ts == ts2,
          "(2,0,0): the payer's spend_out, the fee on it, peer = the "
          "recipient, wire = the preflight wire id, ts = block 2's time");
    CHECK(row_get(g.w, 2, 0, 1, &r) == 1 &&
          memcmp(r.owner, g_ks[1].fpraw, 64) == 0 &&
          strcmp(r.kind, NODUS_ADDR_KIND_SPEND_IN) == 0 &&
          r.amount == pay && r.fee == 0 && r.has_peer &&
          memcmp(r.peer, g_ks[0].fpraw, 64) == 0 &&
          r.has_wire && memcmp(r.wire, spend_a.wire_id, 64) == 0,
          "(2,0,1): the recipient's spend_in, no fee, peer = the payer");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM addr_history WHERE h = 2 "
                      "AND i = 1") == 0,
          "the refused double spend (engine item 1) left NO row");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM addr_history WHERE ts IS NULL")
              == 0, "no committed row carries a NULL ts");
    CHECK(mark_get(g.w, &from_h, &last_h) == 0 && from_h == 1 && last_h == 2,
          "marker: from 1, last 2");

    /* ── the answer builder ──────────────────────────────────────────── */
    {
        nodus_dnac_addr_history_result_t p;

        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, NULL, 100, &p, NULL) == 0,
              "owner == session answers and decodes");
        CHECK(p.enabled && p.from_height == 1 && p.count == 2,
              "enabled, from 1, two rows for g_ks[0]");
        CHECK(p.entries[0].h == 2 && p.entries[0].i == 0 &&
              p.entries[0].q == 0 &&
              strcmp(p.entries[0].kind, "spend_out") == 0 &&
              p.entries[0].amount == pay && p.entries[0].fee == fee &&
              strcmp(p.entries[0].peer, g_ks[1].fp) == 0 &&
              p.entries[0].has_wire &&
              memcmp(p.entries[0].wire_id, spend_a.wire_id, 64) == 0 &&
              p.entries[0].ts == ts2,
              "newest first: the spend_out");
        CHECK(p.entries[1].h == 1 && p.entries[1].i == 1 &&
              strcmp(p.entries[1].kind, "claim") == 0 &&
              p.entries[1].amount == TREASURY_RAW &&
              p.entries[1].peer[0] == '\0' && p.entries[1].fee == 0 &&
              p.entries[1].ts == ts1,
              "then the claim, no peer");
        nodus_client_free_addr_history_result(&p);

        CHECK(page(&g, g_ks[1].fpraw, g_ks[1].fp, NULL, 100, &p, NULL) == 0 &&
              p.count == 1 && strcmp(p.entries[0].kind, "spend_in") == 0 &&
              strcmp(p.entries[0].peer, g_ks[0].fp) == 0,
              "the recipient sees its one spend_in");
        nodus_client_free_addr_history_result(&p);

        ec = 0;
        CHECK(page(&g, g_ks[1].fpraw, g_ks[0].fp, NULL, 100, &p, &ec) == -1 &&
              ec == NODUS_ERR_NOT_AUTHENTICATED,
              "C11: another session's history is refused");
        ec = 0;
        CHECK(page(&g, NULL, g_ks[0].fp, NULL, 100, &p, &ec) == -1 &&
              ec == NODUS_ERR_NOT_AUTHENTICATED,
              "C11: an unauthenticated session is refused");
        ec = 0;
        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, NULL, 0, &p, &ec) == -1 &&
              ec == NODUS_ERR_PROTOCOL_ERROR, "limit 0 refused");
        ec = 0;
        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, NULL, 101, &p, &ec) == -1 &&
              ec == NODUS_ERR_PROTOCOL_ERROR, "limit 101 refused");
        {
            char upper[129];
            memcpy(upper, g_ks[0].fp, 129);
            for (int k = 0; k < 128; k++)
                if (upper[k] >= 'a' && upper[k] <= 'f')
                    upper[k] = (char)(upper[k] - 'a' + 'A');
            ec = 0;
            CHECK(page(&g, g_ks[0].fpraw, upper, NULL, 100, &p, &ec) == -1 &&
                  ec == NODUS_ERR_PROTOCOL_ERROR,
                  "an uppercase owner is refused, never normalised");
        }
    }

    /* ── paging: limit 1 walks every row once, then ends empty ─────── */
    {
        nodus_dnac_addr_history_result_t p;
        nodus_witness_addr_cursor_t cur;

        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, NULL, 1, &p, NULL) == 0 &&
              p.count == 1 && p.entries[0].h == 2, "page 1 = (2,0,0)");
        cur.h = p.entries[0].h; cur.i = p.entries[0].i; cur.q = p.entries[0].q;
        nodus_client_free_addr_history_result(&p);
        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, &cur, 1, &p, NULL) == 0 &&
              p.count == 1 && p.entries[0].h == 1 && p.entries[0].i == 1,
              "page 2 = (1,1,0)");
        cur.h = p.entries[0].h; cur.i = p.entries[0].i; cur.q = p.entries[0].q;
        nodus_client_free_addr_history_result(&p);
        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, &cur, 1, &p, NULL) == 0 &&
              p.count == 0 && p.entries == NULL, "page 3 is empty");
        nodus_client_free_addr_history_result(&p);

        cur.h = 2; cur.i = 0; cur.q = 0;
        CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, &cur, 100, &p, NULL) == 0 &&
              p.count == 1 && p.entries[0].h == 1,
              "a height-only cursor (2,0,0) = every row below height 2");
        nodus_client_free_addr_history_result(&p);
    }

    /* ── Determinism: two builds, identical bytes ───────────────────── */
    {
        uint8_t *f1 = NULL, *f2 = NULL;
        size_t   l1 = 0, l2 = 0;
        int      c1 = 0, c2 = 0;
        char     m[128];

        CHECK(nodus_witness_addr_history_build(g.w, 9, g_ks[0].fpraw,
                                               g_ks[0].fp, NULL, 100, &f1,
                                               &l1, &c1, m, sizeof(m)) == 0 &&
              nodus_witness_addr_history_build(g.w, 9, g_ks[0].fpraw,
                                               g_ks[0].fp, NULL, 100, &f2,
                                               &l2, &c2, m, sizeof(m)) == 0,
              "two builds");
        CHECK(l1 == l2 && memcmp(f1, f2, l1) == 0, "the same bytes");
        free(f1);
        free(f2);
    }

    /* ── height 3 FAULTS after the rows were written: the host's
     * ROLLBACK takes them ─────────────────────────────────────────── */
    {
        out_spec_t oc[1] = { { 1, TREASURY_RAW - pay - 2 * fee, 0xC1 } };
        uint8_t    change[64];
        uint32_t   lc;

        out_id(0, 0xA2, change);
        lc = spend_call(call_c, sizeof(call_c), change, oc, 1);
        CHECK(lc != 0, "spend c call");
        CHECK(build_spend_env(&g, 3, call_c, lc, fee, &spend_c) == 0,
              "spend c (g_ks[0]'s change → g_ks[1])");
        x.txs[0].data = spend_c.bytes; x.txs[0].len = spend_c.len;
        x.ledger->test_fail_at = V2AP_FAIL_AFTER_TX_INDEX;
        CHECK(commit_height(&x, 3, 1) != 0,
              "the engine is interrupted after the item's rows");
        x.ledger->test_fail_at = V2AP_FAIL_NONE;
        CHECK(sqlite3_get_autocommit(g.w->db) != 0,
              "the host rolled its transaction back");
        CHECK(rows_at(g.w, 3) == 0, "no row of the failed block survives");
        CHECK(mark_get(g.w, &from_h, &last_h) == 0 && from_h == 1 &&
              last_h == 2, "and the marker still says last 2");
    }

    free(spend_a.bytes);
    free(spend_b.bytes);
    free(spend_c.bytes);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ flag OFF writes nothing ═════════════════════════════════════════ */

static int t_flag_off(void)
{
    gfx_t   g;
    exec_t  x;
    uint8_t cbytes[DNA_CLAIM_MAX_WIRE];
    size_t  clen = 0;
    nodus_dnac_addr_history_result_t p;

    CHECK(gfx_open(&g, "off", false) == 0, "version-3 fixture, flag OFF");
    CHECK(!nodus_witness_addr_index_enabled(g.w), "the flag reads OFF");
    CHECK(exec_init(&x, &g) == 0, "blockexec");
    CHECK(build_claim(&g, cbytes, sizeof(cbytes), &clen) == 0, "claim");
    x.txs[0].data = cbytes; x.txs[0].len = clen;
    CHECK(commit_height(&x, 1, 1) == 0, "height 1 commits");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM v2_claims_spent") == 1,
          "the claim DID apply");
    CHECK(q1(g.w->db, "SELECT COUNT(*) FROM addr_history") == 0 &&
          q1(g.w->db, "SELECT COUNT(*) FROM addr_history_mark") == 0,
          "and the index wrote nothing — no row, no marker");
    CHECK(page(&g, g_ks[0].fpraw, g_ks[0].fp, NULL, 100, &p, NULL) == 0 &&
          !p.enabled && p.from_height == 0 && p.count == 0,
          "the answer says so: enabled false, from 0, empty");
    nodus_client_free_addr_history_result(&p);

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ the client decoder over hostile replies ═════════════════════════ */

typedef struct {
    int         n;
    uint64_t    count;
    uint64_t    h[2];
    const char *kind;
    size_t      wire_len;
} hostile_t;

static size_t build_reply(const hostile_t *hs, uint8_t *buf, size_t cap)
{
    cbor_encoder_t e;
    static const uint8_t z[64] = {0};

    cbor_encoder_init(&e, buf, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t");  cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "y");  cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "dnac_addr_history");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "count");       cbor_encode_uint(&e, hs->count);
    cbor_encode_cstr(&e, "enabled");     cbor_encode_bool(&e, true);
    cbor_encode_cstr(&e, "from_height"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "entries");
    cbor_encode_array(&e, (size_t)hs->n);
    for (int k = 0; k < hs->n; k++) {
        cbor_encode_map(&e, 10);
        cbor_encode_cstr(&e, "h");      cbor_encode_uint(&e, hs->h[k]);
        cbor_encode_cstr(&e, "i");      cbor_encode_uint(&e, 0);
        cbor_encode_cstr(&e, "q");      cbor_encode_uint(&e, 0);
        cbor_encode_cstr(&e, "kind");   cbor_encode_cstr(&e, hs->kind);
        cbor_encode_cstr(&e, "amount"); cbor_encode_uint(&e, 5);
        cbor_encode_cstr(&e, "token");  cbor_encode_bstr(&e, z, 64);
        cbor_encode_cstr(&e, "fee");    cbor_encode_uint(&e, 0);
        cbor_encode_cstr(&e, "peer");   cbor_encode_tstr(&e, "", 0);
        cbor_encode_cstr(&e, "wire");   cbor_encode_bstr(&e, z, hs->wire_len);
        cbor_encode_cstr(&e, "ts");     cbor_encode_uint(&e, 1);
    }
    return cbor_encoder_len(&e);
}

static int t_decoder_hostile(void)
{
    static uint8_t buf[4096];
    nodus_dnac_addr_history_result_t r;
    hostile_t ok = { 2, 2, { 5, 4 }, "payout", 0 };
    hostile_t hs;
    size_t    len;

    len = build_reply(&ok, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_addr_history_decode(buf, len, &r) == 0 &&
          r.count == 2 && r.entries[0].h == 5 && r.entries[1].h == 4 &&
          !r.entries[0].has_wire,
          "a valid reply decodes (the control)");
    nodus_client_free_addr_history_result(&r);
    for (size_t cut = 0; cut < len; cut++)
        CHECK(nodus_dnac_addr_history_decode(buf, cut, &r) == -1 &&
              r.entries == NULL, "every truncation is refused");

    hs = ok; hs.h[0] = 4; hs.h[1] = 5;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(nodus_dnac_addr_history_decode(buf, len, &r) == -1,
          "ascending entries are refused");
    hs = ok; hs.h[1] = 5;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(nodus_dnac_addr_history_decode(buf, len, &r) == -1,
          "a repeated (h, i, q) is refused");
    hs = ok; hs.count = 1;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(nodus_dnac_addr_history_decode(buf, len, &r) == -1,
          "a count that disagrees with the array is refused");
    hs = ok; hs.kind = "mint";
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(nodus_dnac_addr_history_decode(buf, len, &r) == -1,
          "an unknown kind is refused");
    hs = ok; hs.wire_len = 63;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(nodus_dnac_addr_history_decode(buf, len, &r) == -1,
          "a 63-byte wire is refused");
    return 0;
}

int main(void)
{
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "rows",             t_rows },
        { "flag_off",         t_flag_off },
        { "decoder_hostile",  t_decoder_hostile },
    };
    size_t i, failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_addr_index: key generation failed\n");
        return 1;
    }
    for (i = 0; i < ncases; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_addr_index: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
