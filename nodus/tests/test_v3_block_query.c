/**
 * @file nodus/tests/test_v3_block_query.c
 * @brief scan-v3 — the `dnac_v3_block` client query
 *        (nodus_witness_v3_block_build, the handler's answer without its
 *        send) and its client decoder (nodus_dnac_v3_block_decode), over
 *        a REAL derived version-3 chain driven through the REAL host
 *        pipeline.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 * Governing records: docs/plans/decisions/2026-09-28-scan-v3-query.md,
 * docs/plans/2026-09-28-scan-v3-design.md (items 1-3, Determinism, G1/G2/
 * G4). Blocks are committed exactly as a node commits them:
 * `nodus_cmt_host_apply_verified_block` (FinalizeBlock + the stored
 * response + Commit) then `nodus_cmt_bs_save_block` (the block store) —
 * test_cmt_app.c `vu_host_drive_to`'s pipeline, with transactions.
 *
 *  t_block_query — height 1 = [a REAL claim (applied), envelope-marker
 *    bytes that do not decode (refused DECODE)]; height 2 = [a REAL native
 *    SPEND of the claim's coin (applied), a second SPEND of the SAME coin
 *    (refused EXEC), a REAL chain_config envelope (applied)]. Then:
 *      · the header equals the v2_blocks row (block id, previous id,
 *        global root, tx_count) and the tip is MAX(global_height);
 *      · every item's code equals the STORED FinalizeBlock response;
 *      · the applied claim's created coin id is dna_claim_utxo_id of its
 *        nullifier AND equals the utxo_set row the apply wrote (queried at
 *        tip 1, before height 2 spends it), owner / amount / token too;
 *      · the applied SPEND's wire / intent ids equal v2_tx_index /
 *        v2_intent_index AND this file's own preflight; it consumed the
 *        claim coin; each created coin id is a live utxo_set row with the
 *        same owner / amount / token;
 *      · the applied chain_config carries its record (param / value /
 *        effective) and no coins;
 *      · the two refused items carry their code and NO effects and NO ids;
 *      · paging at the smallest budget returns "nx" and the concatenation
 *        of the pages equals the one-page answer, byte for byte;
 *      · two calls answer byte-identical frames (Determinism);
 *      · h = 0 / h > tip / an index past the block are refused.
 *  t_decoder_hostile — a hand-built VALID reply decodes (the control);
 *    the same reply with a duplicate key, truncated at several lengths,
 *    with an oversize item array, an oversize consumed array, a
 *    non-contiguous item index, or an inconsistent "nx" is REFUSED.
 *  t_balance — `dnac_balance` (decision 3a; nodus_witness_dnac_balance_
 *    build + nodus_dnac_balance_decode) over the same REAL chain: after
 *    the claim commits, g_ks[0]'s answer equals an independent row-by-row
 *    sum of its utxo_set rows (and the claim's leaf). Crafted utxo_set
 *    rows then pin: unlock == tip counts as spendable and unlock == tip+1
 *    does not (the exec's `unlock >= H` gate at H = tip + 1); a non-CORE
 *    domain row is excluded; tokens come back id-ascending; two builds
 *    answer identical bytes; an owner holding nothing answers an EMPTY
 *    list (not an error); an uppercase / short / non-hex / empty owner is
 *    PROTOCOL_ERROR; 2 × INT64_MAX is answered exactly but a third row
 *    (past UINT64_MAX) is INTERNAL_ERROR; a negative amount, a negative
 *    unlock and a REAL-typed amount are INTERNAL_ERROR; exactly
 *    NODUS_DNAC_BALANCE_MAX_TOKENS tokens answer and decode, one more is
 *    TOO_LARGE; a non-version-3 node answers NOT_FOUND.
 *  t_balance_decoder_hostile — a hand-built VALID balance reply decodes;
 *    truncation at every length, a duplicate top-level or token key, a
 *    missing "tk", descending or repeated token ids, s > a, c == 0, a
 *    missing "s", an array head that over-claims, and MAX + 1 tokens are
 *    REFUSED; MAX tokens and an empty list decode.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. SQLite
 * >= 3.35.0 (the S14 rung's own requirement). No network.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_v3bq_*` directory per fixture, removed at close. A case
 * that aborts through CHECK leaves its directory behind (test_cmt_app.c
 * "FIXTURE LIFETIME").
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The handler's own layer (argument decode, the w->cmt_node store /
 *     limits lookup, the send) is NOT driven: the test calls
 *     nodus_witness_v3_block_build with the fixture's own store and
 *     limits, which are the objects the host pipeline wrote through.
 *  2. The dnac_supply "tip" key is not exercised here (its handler only
 *     sends); the client accessor nodus_client_dnac_supply_tip is not
 *     driven either (no socket).
 *  3. Only SPEND, chain_config and the native claim are described from a
 *     real chain; BURN, TOKEN_CREATE and the stake-lifecycle ops (incl.
 *     the UNDELEGATE release coin) share the describer's code path but
 *     are not applied here.
 *  4. Nothing here was RUN by its author (BUILDER: compile only). Every
 *     expectation is an expectation.
 *  5. dnac_balance: the handler's own argument decode (duplicate "owner",
 *     a non-text owner) and nodus_client_dnac_balance's pre-send owner
 *     check are NOT driven (no socket). The lock boundary, the domain
 *     exclusion and every fail-closed case run on rows INSERTED by the
 *     test, not written by an apply; only g_ks[0]'s single unlocked
 *     native coin comes from the real pipeline. The independent sum reads
 *     the same utxo_set table — it cross-checks the aggregation, not the
 *     table's contents.
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
#include "witness/nodus_witness_handlers.h"
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

/* ══ deterministic REAL keys — test_cmt_app.c:273-292's shape ═════════ */

#define N_KEYS       ((int)DNAC_COMMITTEE_SIZE)
#define TREASURY_RAW 93000000000000000ULL   /* test_cmt_app.c:257 */
#define GEN_TIME_MS  1767225600000ULL       /* test_cmt_app.c:258 */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
    char    fp[129];                         /* hex SHA3-512(pk)        */
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
        uint8_t seed[32], full[64];

        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0)
            return -1;
        memcpy(g_ks[i].voter, full, 32);
        hex64(full, g_ks[i].fp);
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

/* ══ FIXTURE — a REAL version-3 chain (test_cmt_app.c:369-627's shape,
 * this file's own copy: the tree's per-file fixture convention) ═══════ */

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
        /* general multisig ONAY 2: a genesis row's destination pubkey is
         * ALL ZERO (the fp above is only a shape-valid address) */
        memset(v->unstake_destination_pubkey, 0, DNAC_PUBKEY_SIZE);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    /* the claim pipeline binds SHA3-512(claimant pubkey) to this field
     * (nodus_witness_v2_claims.c) — g_ks[0] is the claimant */
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    c->reward_pool_initial = 0;
    /* W-C: the builder's default genesis gas price (121) switches the
     * fee rule ON from block 1; this file's spends pay the flat 0.01
     * floor with a 200 000-unit ceiling (which at 121 would need 24.2M
     * raw) and test the block QUERY, not fees — the chain opts out
     * explicitly with a committed price-0 row. */
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
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
} gfx_t;

static int gfx_open(gfx_t *g, const char *tag)
{
    char path[600];

    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real(&g->box) != 0) return -1;
    if (nodus_witness_v2_gen_v3_validate(g->box.cfg) != 0) return -1;
    snprintf(g->dir, sizeof(g->dir), "/tmp/test_v3bq_%s_XXXXXX", tag);
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
    g->w->server = g->srv;
    memcpy(g->w->my_id, g_ks[0].voter, 32);
    return 0;
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

/* ══ the blockexec + block store over the fixture — test_cmt_app.c
 * exec_* (:1053-1407) and vu_host_drive_to (:2231-2305) ════════════════ */

#define TXS_CAP   8u
#define PARTS_CAP 16u

static int t_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
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
    cmt_commit_t            last_commit;     /* the block borrows it     */
    cmt_commit_sig_t       *last_sigs;
    uint8_t                 chain_id[32];
    uint8_t                *part_scratch;
    size_t                  part_scratch_cap;
    cmt_part_t             *parts;
    uint8_t                *save_scratch;    /* NOT part_scratch         */
    size_t                  save_cap;
    cmt_block_id_t          bid;             /* the last committed block */
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

/* test_cmt_app.c gfx_doc: the document carries the app_hash and chain id
 * the derivation completed it with. */
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
                                 &x->ev_if, NULL, NULL, t_now, NULL, NULL,
                                 NULL, &x->lim) != CMT_OK)
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

/* test_cmt_app.c exec_make_last_commit — a precommit per validator. */
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

/**
 * Commit height `h` carrying x->txs[0..n): MakeBlock, its COMPLETE
 * BlockID, the host's ApplyVerifiedBlock (FinalizeBlock, the stored
 * response, Commit) and the block store's SaveBlock — the two halves a
 * node performs (vu_host_drive_to, test_cmt_app.c:2231-2305).
 */
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

/* ══ items ═══════════════════════════════════════════════════════════ */

/* Bytes that classify as an ENVELOPE (the family marker) and do not
 * decode — the DECODE class (test_cmt_app.c POISON). */
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

/* The ONE genesis leaf's claim — test_cmt_app.c t_claim_items. */
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

/* SPEND call v1 (nodus_witness_rt_native.c header): in_count ‖ inputs ‖
 * out_count ‖ outputs (fp128 ‖ amount BE ‖ token64 ‖ seed32) — the
 * builder test_v2_native.c spend_call_build uses. */
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

/* The identity the SPEND exec derives for output `o`: SHA3-512(fp ‖ seed)
 * — recomputed HERE, independently of the node's describer. */
static void out_id(int owner, uint8_t seed_byte, uint8_t out[64])
{
    uint8_t pre[160];
    memcpy(pre, g_ks[owner].fp, 128);
    memset(pre + 128, seed_byte, 32);
    qgp_sha3_512(pre, sizeof(pre), out);
}

/* A one-leg CORE SPEND envelope, auth kind 1, signed by g_ks[0] at the
 * candidate height `cand` (test_cmt_app.c build_cc_env_units' shape). */
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

/* A REAL chain_config envelope (param 4 TARGET_ACTIVE_COUNT := 7,
 * effective tip + 100000) — test_cmt_app.c build_cc_env_units, retyped. */
#define CC_CALL_LEN 41u
#define CC_UNITS    200000u
#define CC_VALUE    7u
#define CC_EFF_AHEAD 100000u

static int build_cc_env(gfx_t *g, uint64_t nonce, test_env_t *out)
{
    dna_domain_manifest_t     sys_man;
    nodus_committee_member_t *cm = NULL;
    dna_env_preflight_t      *pf = NULL;
    uint8_t                  *fps = NULL, *auth = NULL, *env_bytes = NULL;
    uint8_t                  *call = NULL;
    uint64_t                  tip = 0;
    int                       cmn = 0, rc = -1;

    memset(out, 0, sizeof(*out));
    if (nodus_witness_domreg_get(g->w, DNA_DOMAIN_SYSTEM, NULL, &sys_man,
                                 NULL) != 0)
        return -1;
    if (nodus_witness_v2_tip_height(g->w, &tip) != 0) return -1;
    if (nodus_committee_get_for_block_alloc(g->w, tip, &cm, &cmn) != 0 ||
        cmn < 1)
        return -1;
    fps  = malloc((size_t)cmn * 64);
    pf   = calloc(1, sizeof(*pf));
    call = calloc(1, CC_CALL_LEN);
    do {
        uint8_t  set_hash[64];
        uint64_t appr_epoch, nv = CC_VALUE, eff, vb, sa = 1;
        uint32_t quorum, emitted = 0;
        size_t   auth_len, env_len = 0, used = 0, sl = 0;
        dna_env_leg_in_t  leg;
        dna_env_in_t      env_in;
        dna_env_leg_ctx_t lctx;
        uint8_t          *p;
        int i, s, bad = 0;

        if (!fps || !pf || !call) break;
        for (i = 0; i < cmn; i++)
            if (qgp_sha3_512(cm[i].pubkey, DNAC_PUBKEY_SIZE,
                             fps + (size_t)i * 64) != 0)
                bad = 1;
        if (bad ||
            nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                        (uint32_t)cmn, set_hash) != 0)
            break;
        appr_epoch = nodus_v2_epoch_for_height(tip);
        quorum     = dna_bft_quorum((uint32_t)cmn);
        eff = tip + CC_EFF_AHEAD;
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
        if (!auth) break;
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
        env_in.expiry_height       = tip +
                                     (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD;
        env_in.fee_amount          = 0;   /* a CHAIN_CONFIG leg requires 0 */
        env_in.res_max_total_units = CC_UNITS;
        env_in.leg_count           = 1;
        env_in.legs                = &leg;
        if (dna_env_encoded_size(&leg, 1, &env_len) != 0) break;
        env_bytes = malloc(env_len);
        if (!env_bytes) break;
        lctx.domain_id       = DNA_DOMAIN_SYSTEM;
        lctx.ruleset_version = sys_man.ruleset_version;
        memcpy(lctx.ruleset_hash, sys_man.ruleset_hash, 64);
        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len ||
            dna_env_preflight(env_bytes, env_len, g->chain32, tip + 1, &lctx,
                              1, pf) != DNA_ENV_PF_OK)
            break;
        p = auth;
        p[0] = 1;
        memcpy(p + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
        if (qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl, pf->auth_digest[0],
                           64, g_ks[0].sk) != 0)
            break;
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)(quorum >> 8);
        p[1] = (uint8_t)quorum;
        p += 2;
        for (s = 0; s < cmn && emitted < quorum; s++) {
            int     ki = -1;
            uint8_t adg[64];

            for (int k = 0; k < N_KEYS; k++)
                if (memcmp(cm[s].pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE) == 0) {
                    ki = k;
                    break;
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
        if (bad || emitted != quorum) break;
        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len ||
            dna_env_preflight(env_bytes, env_len, g->chain32, tip + 1, &lctx,
                              1, pf) != DNA_ENV_PF_OK)
            break;
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

/* ══ query helpers ═══════════════════════════════════════════════════ */

/* Build + decode one page. @return 0 / -1 build refused (code in *ecode)
 * / -2 the decoder refused the node's own frame. */
static int query(gfx_t *g, exec_t *x, uint64_t h, uint32_t from,
                 uint32_t budget, nodus_dnac_v3_block_result_t *res,
                 int *ecode)
{
    uint8_t *frame = NULL;
    size_t   flen = 0;
    char     emsg[128];
    int      code = 0;

    memset(res, 0, sizeof(*res));
    if (nodus_witness_v3_block_build(g->w, x->store, &x->lim, 77, h, from,
                                     budget, &frame, &flen, &code, emsg,
                                     sizeof(emsg)) != 0) {
        if (ecode) *ecode = code;
        return -1;
    }
    int drc = nodus_dnac_v3_block_decode(frame, flen, res);
    free(frame);
    return drc == 0 ? 0 : -2;
}

/* The v2_blocks row's columns for `h`. */
static int ledger_row(nodus_witness_t *w, uint64_t h, uint8_t bid[64],
                      uint8_t pbid[64], uint8_t groot[64], uint64_t *txc)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id, prev_block_id, global_root, tx_count "
            "FROM v2_blocks WHERE global_height = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == 64 &&
        sqlite3_column_bytes(st, 1) == 64 &&
        sqlite3_column_bytes(st, 2) == 64) {
        memcpy(bid, sqlite3_column_blob(st, 0), 64);
        memcpy(pbid, sqlite3_column_blob(st, 1), 64);
        memcpy(groot, sqlite3_column_blob(st, 2), 64);
        *txc = (uint64_t)sqlite3_column_int64(st, 3);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/* The stored FinalizeBlock response's per-item codes for `h`. */
static int stored_codes(exec_t *x, uint64_t h, uint32_t *codes, size_t cap,
                        size_t *n)
{
    cmt_pb_response_finalize_block_t *resp = calloc(1, sizeof(*resp));
    cmt_pb_rfb_storage_t rst;
    cmt_pb_arena_t       arena;
    int                  rc = -1;

    memset(&rst, 0, sizeof(rst));
    memset(&arena, 0, sizeof(arena));
    rst.events            = calloc(64, sizeof(cmt_pb_event_t));
    rst.events_cap        = 64;
    rst.attributes        = calloc(256, sizeof(cmt_pb_event_attribute_t));
    rst.attributes_cap    = 256;
    rst.tx_results        = calloc(TXS_CAP, sizeof(*rst.tx_results));
    rst.tx_results_cap    = TXS_CAP;
    rst.validator_updates = calloc(CMT_VALSET_MAX,
                                   sizeof(*rst.validator_updates));
    rst.validator_updates_cap = CMT_VALSET_MAX;
    arena.buf = malloc(64u * 1024u);
    arena.cap = 64u * 1024u;
    rst.arena = &arena;
    if (resp && rst.events && rst.attributes && rst.tx_results &&
        rst.validator_updates && arena.buf &&
        nodus_cmt_ss_load_finalize_block_response(x->store, (int64_t)h, &rst,
                                                  resp) == CMT_OK &&
        resp->tx_results_len <= cap) {
        for (size_t i = 0; i < resp->tx_results_len; i++)
            codes[i] = resp->tx_results[i].det.code;
        *n = resp->tx_results_len;
        rc = 0;
    }
    free(resp);
    free(rst.events);
    free(rst.attributes);
    free(rst.tx_results);
    free(rst.validator_updates);
    free(arena.buf);
    return rc;
}

/* The utxo_set row for `id` matches (owner, amount, token)? 1 / 0 / -1. */
static int utxo_matches(nodus_witness_t *w, const nodus_dnac_v3_coin_t *c)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, amount, token_id FROM utxo_set "
            "WHERE nullifier = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, c->id, 64, SQLITE_TRANSIENT);
    int s = sqlite3_step(st);
    if (s == SQLITE_ROW) {
        const unsigned char *o = sqlite3_column_text(st, 0);
        rc = (o && strcmp((const char *)o, c->owner) == 0 &&
              (uint64_t)sqlite3_column_int64(st, 1) == c->amount &&
              sqlite3_column_bytes(st, 2) == 64 &&
              memcmp(sqlite3_column_blob(st, 2), c->token_id, 64) == 0)
                 ? 1 : 0;
    } else if (s == SQLITE_DONE) {
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/* v2_tx_index.tx_id / v2_intent_index.intent_id at (h, gidx). */
static int index_ids(nodus_witness_t *w, uint64_t h, uint32_t gidx,
                     uint8_t wire[64], uint8_t intent[64])
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(w->db,
            "SELECT t.tx_id, i.intent_id FROM v2_tx_index t JOIN "
            "v2_intent_index i ON i.tx_id = t.tx_id "
            "WHERE t.global_height = ?1 AND t.global_index = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)gidx);
    if (sqlite3_step(st) == SQLITE_ROW) {
        memcpy(wire, sqlite3_column_blob(st, 0), 64);
        memcpy(intent, sqlite3_column_blob(st, 1), 64);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static bool no_effects(const nodus_dnac_v3_item_t *it)
{
    return !it->has_effects && it->n_consumed == 0 && it->n_created == 0 &&
           it->burned == 0 && it->rec_kind == NODUS_DNAC_V3_REC_NONE;
}

/* Walk `h` page by page at `budget`; the concatenated items must equal
 * `full` byte for byte. @return pages walked, -1 on any mismatch. */
static int walk_pages(gfx_t *g, exec_t *x, uint64_t h, uint32_t budget,
                      const nodus_dnac_v3_block_result_t *full)
{
    uint32_t from = 0;
    size_t   got = 0;
    int      pages = 0;

    for (;;) {
        nodus_dnac_v3_block_result_t p;
        if (query(g, x, h, from, budget, &p, NULL) != 0) return -1;
        if (p.count == 0 || got + p.count > full->count) {
            nodus_client_free_v3_block_result(&p);
            return -1;
        }
        if (memcmp(p.items, full->items + got,
                   p.count * sizeof(*p.items)) != 0) {
            nodus_client_free_v3_block_result(&p);
            return -1;
        }
        got += p.count;
        pages++;
        bool more = p.has_next;
        from = p.next_index;
        nodus_client_free_v3_block_result(&p);
        if (!more) break;
        if (from != got) return -1;
    }
    return got == full->count ? pages : -1;
}

/* ══ the real-chain case ═════════════════════════════════════════════ */

static int t_block_query(void)
{
    gfx_t        g;
    exec_t       x;
    uint8_t      cbytes[DNA_CLAIM_MAX_WIRE];
    size_t       clen = 0;
    uint8_t      claim_nul[64], claim_coin[64], claim_wire[64];
    uint8_t      bid[64], pbid[64], groot[64];
    uint64_t     txc = 0;
    uint32_t     codes[TXS_CAP];
    size_t       ncodes = 0;
    int          ecode = 0;
    const uint64_t fee = DNAC_MIN_FEE_RAW;
    const uint64_t pay = 100000000ULL;           /* 1 DNAC to g_ks[1]    */
    nodus_dnac_v3_block_result_t r1, r2;
    test_env_t   spend_a, spend_b, cc;
    static uint8_t call_a[4096], call_b[4096];

    CHECK(gfx_open(&g, "chain") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    /* ── height 1: [claim (applied), POISON (refused DECODE)] ───────── */
    CHECK(build_claim(&g, cbytes, sizeof(cbytes), &clen) == 0, "claim");
    CHECK(nodus_witness_v2_claim_nullifier(g.w, cbytes, clen, claim_nul)
              == 0, "the claim's nullifier (the apply's own derivation)");
    CHECK(dna_claim_utxo_id(claim_nul, claim_coin) == 0,
          "the native coin id \"NDS.CLUTXO.v1\"");
    CHECK(qgp_sha3_512(cbytes, clen, claim_wire) == 0, "claim hash");
    x.txs[0].data = cbytes; x.txs[0].len = clen;
    x.txs[1].data = POISON; x.txs[1].len = sizeof(POISON);
    CHECK(commit_height(&x, 1, 2) == 0, "height 1 commits");

    CHECK(query(&g, &x, 1, 0, 0, &r1, NULL) == 0, "h=1 answers and decodes");
    CHECK(ledger_row(g.w, 1, bid, pbid, groot, &txc) == 0, "v2_blocks row 1");
    CHECK(r1.height == 1 && r1.tip == 1, "height / tip");
    CHECK(memcmp(r1.block_id, bid, 64) == 0 &&
          memcmp(r1.block_id, x.bid.hash, 64) == 0,
          "bid = v2_blocks.block_id = the cometbft block hash");
    CHECK(memcmp(r1.prev_block_id, pbid, 64) == 0, "pb = prev_block_id");
    CHECK(memcmp(r1.global_root, groot, 64) == 0, "gr = global_root");
    CHECK(r1.applied_count == txc, "ac = tx_count");
    CHECK(r1.total_items == 2 && r1.count == 2 && !r1.has_next,
          "both items, one page");
    CHECK(r1.proposer_len == x.blk->header.proposer_address_len &&
          memcmp(r1.proposer, x.blk->header.proposer_address,
                 r1.proposer_len) == 0, "pa = the header's proposer");
    CHECK(r1.time_ms ==
              (uint64_t)x.blk->header.time.seconds * 1000u +
              (uint64_t)x.blk->header.time.nanos / 1000000u,
          "tm = the header time in ms");
    CHECK(stored_codes(&x, 1, codes, TXS_CAP, &ncodes) == 0 && ncodes == 2,
          "the stored FinalizeBlock response of height 1");
    CHECK(r1.items[0].code == codes[0] && r1.items[1].code == codes[1],
          "codes = the stored response");
    /* item 0: the applied claim */
    {
        const nodus_dnac_v3_item_t *it = &r1.items[0];

        CHECK(it->index == 0 && it->kind == NODUS_DNAC_V3_KIND_CLAIM &&
              it->code == 0, "claim applied");
        CHECK(it->has_wire_id && memcmp(it->wire_id, claim_wire, 64) == 0 &&
              !it->has_intent_id && strcmp(it->op, "claim") == 0,
              "claim ids / op");
        CHECK(it->has_effects && it->n_consumed == 0 && it->n_created == 1,
              "a claim consumes nothing and creates one coin");
        CHECK(memcmp(it->created[0].id, claim_coin, 64) == 0,
              "its id is dna_claim_utxo_id(nullifier)");
        CHECK(strcmp(it->created[0].owner, g_ks[0].fp) == 0 &&
              it->created[0].amount == TREASURY_RAW,
              "owner = the claimant's fp, amount = the leaf");
        CHECK(utxo_matches(g.w, &it->created[0]) == 1,
              "the utxo_set row the apply wrote carries the same coin");
    }
    /* item 1: POISON, refused */
    CHECK(r1.items[1].kind == NODUS_DNAC_V3_KIND_ENVELOPE &&
          r1.items[1].code == (uint32_t)NODUS_V2_TX_ERR_DECODE &&
          no_effects(&r1.items[1]) && !r1.items[1].has_wire_id &&
          !r1.items[1].has_intent_id && !r1.items[1].has_fee &&
          r1.items[1].op[0] == '\0',
          "the undecodable item: code DECODE, no ids, no effects");
    nodus_client_free_v3_block_result(&r1);

    /* ── height 2: [SPEND a (applied), SPEND b same input (refused EXEC),
     *               chain_config (applied)] ─────────────────────────── */
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
    CHECK(build_cc_env(&g, 0x5C01, &cc) == 0, "chain_config envelope");
    x.txs[0].data = spend_a.bytes; x.txs[0].len = spend_a.len;
    x.txs[1].data = spend_b.bytes; x.txs[1].len = spend_b.len;
    x.txs[2].data = cc.bytes;      x.txs[2].len = cc.len;
    CHECK(commit_height(&x, 2, 3) == 0, "height 2 commits");

    CHECK(query(&g, &x, 2, 0, 0, &r2, NULL) == 0, "h=2 answers and decodes");
    CHECK(ledger_row(g.w, 2, bid, pbid, groot, &txc) == 0, "v2_blocks row 2");
    CHECK(r2.height == 2 && r2.tip == 2 && r2.total_items == 3 &&
          r2.count == 3 && !r2.has_next, "height 2, three items");
    CHECK(memcmp(r2.block_id, bid, 64) == 0 &&
          memcmp(r2.prev_block_id, pbid, 64) == 0 &&
          memcmp(r2.global_root, groot, 64) == 0 && r2.applied_count == txc,
          "header = v2_blocks row 2");
    CHECK(txc == 2, "two applied envelopes (spend a, chain_config)");
    CHECK(stored_codes(&x, 2, codes, TXS_CAP, &ncodes) == 0 && ncodes == 3,
          "the stored FinalizeBlock response of height 2");
    for (size_t i = 0; i < 3; i++)
        CHECK(r2.items[i].code == codes[i], "codes = the stored response");
    /* item 0: spend a */
    {
        const nodus_dnac_v3_item_t *it = &r2.items[0];
        uint8_t w0[64], i0[64], id[64];

        CHECK(it->kind == NODUS_DNAC_V3_KIND_ENVELOPE && it->code == 0 &&
              strcmp(it->op, "spend") == 0 && it->has_fee && it->fee == fee,
              "spend a applied, op / fee");
        CHECK(index_ids(g.w, 2, 0, w0, i0) == 0, "index rows (2, 0)");
        CHECK(it->has_wire_id && memcmp(it->wire_id, w0, 64) == 0 &&
              memcmp(it->wire_id, spend_a.wire_id, 64) == 0,
              "w = v2_tx_index.tx_id = the preflight wire id");
        CHECK(it->has_intent_id && memcmp(it->intent_id, i0, 64) == 0 &&
              memcmp(it->intent_id, spend_a.intent_id, 64) == 0,
              "in = v2_intent_index.intent_id = the preflight intent id");
        CHECK(it->has_effects && it->n_consumed == 1 &&
              memcmp(it->consumed[0], claim_coin, 64) == 0,
              "it consumed the claim coin");
        CHECK(it->n_created == 2, "two outputs");
        out_id(1, 0xA1, id);
        CHECK(memcmp(it->created[0].id, id, 64) == 0 &&
              strcmp(it->created[0].owner, g_ks[1].fp) == 0 &&
              it->created[0].amount == pay &&
              it->created[0].unlock_block == 0,
              "output 0 = SHA3-512(fp ‖ seed), owner, amount");
        out_id(0, 0xA2, id);
        CHECK(memcmp(it->created[1].id, id, 64) == 0 &&
              it->created[1].amount == TREASURY_RAW - pay - fee,
              "output 1 = the change");
        CHECK(utxo_matches(g.w, &it->created[0]) == 1 &&
              utxo_matches(g.w, &it->created[1]) == 1,
              "both created ids are the utxo_set rows the apply wrote");
        CHECK(it->burned == 0 && it->rec_kind == NODUS_DNAC_V3_REC_NONE,
              "no burn, no record");
    }
    /* item 1: spend b, refused */
    {
        const nodus_dnac_v3_item_t *it = &r2.items[1];
        uint8_t id[64];
        nodus_dnac_v3_coin_t probe;

        CHECK(it->code == (uint32_t)NODUS_V2_TX_ERR_EXEC,
              "the double spend is refused at EXEC");
        CHECK(strcmp(it->op, "spend") == 0 && it->has_fee && it->fee == fee,
              "a refused envelope still names its op and fee");
        CHECK(!it->has_wire_id && !it->has_intent_id && no_effects(it),
              "and carries no ids and no effects");
        memset(&probe, 0, sizeof(probe));
        out_id(1, 0xB1, id);
        memcpy(probe.id, id, 64);
        CHECK(utxo_matches(g.w, &probe) == 0,
              "its output was never created");
    }
    /* item 2: chain_config */
    {
        const nodus_dnac_v3_item_t *it = &r2.items[2];
        uint8_t w1[64], i1[64];

        CHECK(it->code == 0 && strcmp(it->op, "chain_config") == 0 &&
              it->has_fee && it->fee == 0, "chain_config applied");
        CHECK(index_ids(g.w, 2, 1, w1, i1) == 0 &&
              memcmp(it->wire_id, w1, 64) == 0 &&
              memcmp(it->wire_id, cc.wire_id, 64) == 0 &&
              memcmp(it->intent_id, i1, 64) == 0,
              "its ids are index row (2, 1) — the second APPLIED envelope");
        CHECK(it->has_effects && it->n_consumed == 0 && it->n_created == 0,
              "no coins");
        CHECK(it->rec_kind == NODUS_DNAC_V3_REC_CHAIN_CONFIG &&
              it->cc_param_id == 4 && it->cc_new_value == CC_VALUE &&
              it->cc_effective == 1 + CC_EFF_AHEAD,
              "the record: param / value / effective of the call");
    }

    /* ── paging: the smallest budget splits the block; the pages
     * concatenate to the one-page answer ──────────────────────────── */
    {
        /* ORCHESTRATOR correction: this block's three items encode in
         * fewer than NODUS_DNAC_V3_BLOCK_BUDGET_MIN (1024) bytes — measured,
         * the minimum budget returns all three in ONE page — so "budget 1
         * splits the block" was a false premise. What holds, and is
         * asserted: the walk at the minimum budget concatenates to the
         * full answer. A page that ends early (`nx`) is exercised by the
         * index-1 start below and by the decoder cases in t_decoder_hostile;
         * the handler's own early end on a real block is NOT driven here. */
        int pages = walk_pages(&g, &x, 2, 1, &r2);
        CHECK(pages >= 1, "the walk at the minimum budget concatenates to "
                          "the full answer");
    }
    {
        nodus_dnac_v3_block_result_t p;
        CHECK(query(&g, &x, 2, 1, 0, &p, NULL) == 0 && p.count == 2 &&
              p.items[0].index == 1 &&
              memcmp(p.items, r2.items + 1, 2 * sizeof(*p.items)) == 0,
              "a page from index 1 = the tail of the full answer (the "
              "applied-envelope index is counted past the page start)");
        nodus_client_free_v3_block_result(&p);
    }

    /* ── Determinism: two calls, byte-identical frames ─────────────── */
    {
        uint8_t *f1 = NULL, *f2 = NULL;
        size_t   l1 = 0, l2 = 0;
        int      c1 = 0, c2 = 0;
        char     m[128];

        CHECK(nodus_witness_v3_block_build(g.w, x.store, &x.lim, 9, 2, 0, 0,
                                           &f1, &l1, &c1, m, sizeof(m)) == 0 &&
              nodus_witness_v3_block_build(g.w, x.store, &x.lim, 9, 2, 0, 0,
                                           &f2, &l2, &c2, m, sizeof(m)) == 0,
              "two builds");
        CHECK(l1 == l2 && memcmp(f1, f2, l1) == 0,
              "the same height answers the same bytes");
        free(f1);
        free(f2);
    }

    /* ── refusals ──────────────────────────────────────────────────── */
    {
        nodus_dnac_v3_block_result_t p;

        ecode = 0;
        CHECK(query(&g, &x, 0, 0, 0, &p, &ecode) == -1 &&
              ecode == NODUS_ERR_PROTOCOL_ERROR, "h = 0 refused");
        ecode = 0;
        CHECK(query(&g, &x, 3, 0, 0, &p, &ecode) == -1 &&
              ecode == NODUS_ERR_NOT_FOUND, "h > tip refused");
        ecode = 0;
        CHECK(query(&g, &x, 2, 3, 0, &p, &ecode) == -1 &&
              ecode == NODUS_ERR_PROTOCOL_ERROR, "an index past the block "
                                                 "refused");
    }

    nodus_client_free_v3_block_result(&r2);
    free(spend_a.bytes);
    free(spend_b.bytes);
    free(cc.bytes);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ the decoder over hostile replies ════════════════════════════════ */

/* A hand-built reply. `dup` repeats the "h" key; `n_items` item maps
 * (index 0..), `it_count` the array head (may lie); `sp_n` consumed ids
 * on item 0; `nx` < 0 = no "nx" key. */
typedef struct {
    int      dup;
    uint32_t n;              /* "n"                                     */
    uint32_t n_items;        /* item maps actually written              */
    uint32_t it_count;       /* the array head                          */
    uint32_t first_index;
    int      gap;            /* item 1 skips an index                   */
    uint32_t sp_n;
    int64_t  nx;
} hostile_t;

static size_t build_reply(const hostile_t *hs, uint8_t *buf, size_t cap)
{
    cbor_encoder_t e;
    uint8_t        z64[64];
    size_t         keys = 10 + (hs->dup ? 1 : 0) + (hs->nx >= 0 ? 1 : 0);

    memset(z64, 0x11, sizeof(z64));
    cbor_encoder_init(&e, buf, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_v3_block");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, keys);
    cbor_encode_cstr(&e, "h");   cbor_encode_uint(&e, 5);
    if (hs->dup) { cbor_encode_cstr(&e, "h"); cbor_encode_uint(&e, 5); }
    cbor_encode_cstr(&e, "bid"); cbor_encode_bstr(&e, z64, 64);
    cbor_encode_cstr(&e, "pb");  cbor_encode_bstr(&e, z64, 64);
    cbor_encode_cstr(&e, "tm");  cbor_encode_uint(&e, 1000);
    cbor_encode_cstr(&e, "pa");  cbor_encode_bstr(&e, z64, 32);
    cbor_encode_cstr(&e, "gr");  cbor_encode_bstr(&e, z64, 64);
    cbor_encode_cstr(&e, "ac");  cbor_encode_uint(&e, 0);
    cbor_encode_cstr(&e, "n");   cbor_encode_uint(&e, hs->n);
    cbor_encode_cstr(&e, "tip"); cbor_encode_uint(&e, 9);
    if (hs->nx >= 0) {
        cbor_encode_cstr(&e, "nx"); cbor_encode_uint(&e, (uint64_t)hs->nx);
    }
    cbor_encode_cstr(&e, "it");  cbor_encode_array(&e, hs->it_count);
    for (uint32_t j = 0; j < hs->n_items; j++) {
        uint32_t idx = hs->first_index + j + ((hs->gap && j > 0) ? 1 : 0);
        bool     eff = (j == 0 && hs->sp_n > 0);

        cbor_encode_map(&e, eff ? 5 : 3);
        cbor_encode_cstr(&e, "i"); cbor_encode_uint(&e, idx);
        cbor_encode_cstr(&e, "k"); cbor_encode_uint(&e, 1);
        cbor_encode_cstr(&e, "c"); cbor_encode_uint(&e, eff ? 0 : 7);
        if (eff) {
            cbor_encode_cstr(&e, "sp");
            cbor_encode_array(&e, hs->sp_n);
            for (uint32_t s = 0; s < hs->sp_n; s++)
                cbor_encode_bstr(&e, z64, 64);
            cbor_encode_cstr(&e, "cr");
            cbor_encode_array(&e, 0);
        }
    }
    return cbor_encoder_len(&e);
}

static int t_decoder_hostile(void)
{
    static uint8_t buf[1u << 20];
    nodus_dnac_v3_block_result_t r;
    hostile_t hs;
    size_t    len;

    /* the CONTROL: a well-formed two-item page decodes */
    memset(&hs, 0, sizeof(hs));
    hs.n = 2; hs.n_items = 2; hs.it_count = 2; hs.sp_n = 1; hs.nx = -1;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0, "control encodes");
    CHECK(nodus_dnac_v3_block_decode(buf, len, &r) == 0 && r.count == 2 &&
          r.height == 5 && r.items[0].n_consumed == 1 &&
          r.items[0].has_effects && !r.items[1].has_effects,
          "the well-formed reply decodes");
    nodus_client_free_v3_block_result(&r);

    /* truncated at every length: never accepted, never read past */
    for (size_t cut = 1; cut < len; cut++)
        CHECK(nodus_dnac_v3_block_decode(buf, len - cut, &r) == -1 &&
              r.items == NULL && r.count == 0,
              "a truncated reply is refused and leaves nothing to free");

    /* a duplicate header key */
    hs.dup = 1;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == -1,
          "a duplicate key is refused");
    hs.dup = 0;

    /* an item array above the page bound — 257 REAL, contiguous,
     * well-formed items, so the page bound is the only check it fails
     * (the control right after shows 256 of them decode) */
    hs.n = hs.n_items = hs.it_count = NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS + 1;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == -1,
          "an oversize item array is refused");
    hs.n = hs.n_items = hs.it_count = NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == 0 &&
          r.count == NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS,
          "control: exactly the page bound decodes");
    nodus_client_free_v3_block_result(&r);
    hs.n = hs.n_items = hs.it_count = 2;

    /* a consumed array above the per-item bound (16 REAL ids; 15
     * decode — the control) */
    hs.sp_n = NODUS_DNAC_V3_ITEM_MAX_IN + 1;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == -1,
          "an oversize consumed array is refused");
    hs.sp_n = NODUS_DNAC_V3_ITEM_MAX_IN;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == 0 &&
          r.items[0].n_consumed == NODUS_DNAC_V3_ITEM_MAX_IN,
          "control: exactly the consumed bound decodes");
    nodus_client_free_v3_block_result(&r);
    hs.sp_n = 1;

    /* a gap in the item indices */
    hs.gap = 1; hs.n = 3;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == -1,
          "non-contiguous item indices are refused");
    hs.gap = 0; hs.n = 2;

    /* "nx" that does not follow the last item; a page ending early
     * without "nx" */
    hs.n = 4; hs.nx = 3;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == -1,
          "an nx that skips items is refused");
    hs.nx = -1;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == -1,
          "a short page without nx is refused");
    hs.nx = 2;
    len = build_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_v3_block_decode(buf, len, &r) == 0 &&
          r.has_next && r.next_index == 2,
          "control: the same short page WITH a consistent nx decodes");
    nodus_client_free_v3_block_result(&r);
    return 0;
}

/* ══ dnac_balance (decision 2026-09-28-scan-v3-query.md 3a) ═══════════ */

/* A fingerprint-shaped owner that no key produced: 128 lowercase hex
 * characters of the byte `b`. */
static void fake_fp(uint8_t b, char out[129])
{
    uint8_t raw[64];
    memset(raw, b, sizeof(raw));
    hex64(raw, out);
}

/* Insert one utxo_set row directly (nullifier = 64 × nb, 63 bytes of `nb`
 * and a last byte `nb2` so many rows can share a first byte). `amount_real`
 * stores amount as a REAL instead of an INTEGER (a malformed row). */
static int put_row(nodus_witness_t *w, uint8_t nb, uint8_t nb2,
                   const char *owner, int64_t amount, int amount_real,
                   const uint8_t token[64], int64_t unlock, int64_t domain)
{
    sqlite3_stmt *st = NULL;
    uint8_t       nul[64], txh[64];
    int           rc;

    memset(nul, nb, sizeof(nul));
    nul[63] = nb2;
    memset(txh, 0x77, sizeof(txh));
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) "
            "VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, 0, ?6, ?7)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, owner, 128, SQLITE_TRANSIENT);
    if (amount_real)
        sqlite3_bind_double(st, 3, (double)amount + 0.5);
    else
        sqlite3_bind_int64(st, 3, amount);
    sqlite3_bind_blob(st, 4, token, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, txh, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, unlock);
    sqlite3_bind_int64(st, 7, domain);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* An INDEPENDENT reading of the same rows: every CORE row of `owner` for
 * `token`, summed here, row by row (the rows are small in this fixture —
 * no overflow is possible). */
static int indep_sum(nodus_witness_t *w, const char *owner,
                     const uint8_t token[64], uint64_t spend_h,
                     uint64_t *total, uint64_t *spendable, uint64_t *coins)
{
    sqlite3_stmt *st = NULL;
    int           rc;

    *total = *spendable = *coins = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount, unlock_block FROM utxo_set "
            "WHERE owner = ?1 AND token_id = ?2 AND domain_id = ?3",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, owner, 128, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, token, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)DNA_DOMAIN_CORE);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
        uint64_t u = (uint64_t)sqlite3_column_int64(st, 1);
        *total += a;
        if (u < spend_h) *spendable += a;
        (*coins)++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Build + decode one balance answer. @return 0 / -1 build refused (code
 * in *ecode) / -2 the decoder refused the node's own frame. */
static int bal_query(gfx_t *g, const char *owner,
                     nodus_dnac_balance_result_t *res, int *ecode)
{
    uint8_t *frame = NULL;
    size_t   flen = 0;
    char     emsg[128];
    int      code = 0;

    memset(res, 0, sizeof(*res));
    if (ecode) *ecode = 0;
    if (nodus_witness_dnac_balance_build(g->w, 41, owner, &frame, &flen,
                                         &code, emsg, sizeof(emsg)) != 0) {
        if (ecode) *ecode = code;
        return -1;
    }
    int drc = nodus_dnac_balance_decode(frame, flen, res);
    free(frame);
    return drc == 0 ? 0 : -2;
}

static int t_balance(void)
{
    gfx_t    g;
    exec_t   x;
    uint8_t  cbytes[DNA_CLAIM_MAX_WIRE];
    size_t   clen = 0;
    uint8_t  zero[64], tok7[64], tokn[64];
    uint64_t tip = 0, it_total, it_spend, it_coins;
    int      ecode = 0;
    char     who[129], bad[129];
    nodus_dnac_balance_result_t r;

    memset(zero, 0, sizeof(zero));
    memset(tok7, 0x07, sizeof(tok7));

    CHECK(gfx_open(&g, "bal") == 0, "version-3 fixture");
    CHECK(exec_init(&x, &g) == 0, "blockexec + real application");

    /* height 1: the REAL claim — g_ks[0] then holds one native coin the
     * apply wrote */
    CHECK(build_claim(&g, cbytes, sizeof(cbytes), &clen) == 0, "claim");
    x.txs[0].data = cbytes; x.txs[0].len = clen;
    CHECK(commit_height(&x, 1, 1) == 0, "height 1 commits");
    CHECK(nodus_witness_v2_tip_height(g.w, &tip) == 0 && tip == 1, "tip 1");

    /* ── the applied chain: totals = the utxo_set rows ──────────────── */
    CHECK(bal_query(&g, g_ks[0].fp, &r, NULL) == 0, "g_ks[0] answers");
    CHECK(r.tip == 1 && r.count == 1 &&
          memcmp(r.tokens[0].token_id, zero, 64) == 0,
          "one token: native, at tip 1");
    CHECK(indep_sum(g.w, g_ks[0].fp, zero, tip + 1, &it_total, &it_spend,
                    &it_coins) == 0, "independent row sum");
    CHECK(r.tokens[0].total == it_total &&
          r.tokens[0].spendable == it_spend &&
          r.tokens[0].coins == it_coins,
          "total / spendable / coins = the utxo_set rows, summed here");
    CHECK(r.tokens[0].total == TREASURY_RAW && r.tokens[0].coins == 1 &&
          r.tokens[0].spendable == TREASURY_RAW,
          "the claim's coin: the whole leaf, unlocked");
    nodus_client_free_balance_result(&r);

    /* ── crafted rows: the lock boundary, a second token, another
     * domain ───────────────────────────────────────────────────────── */
    fake_fp(0xC1, who);
    CHECK(put_row(g.w, 0xD1, 0, who, 100, 0, zero, 0, DNA_DOMAIN_CORE) == 0 &&
          put_row(g.w, 0xD2, 0, who, 200, 0, zero, (int64_t)tip,
                  DNA_DOMAIN_CORE) == 0 &&
          put_row(g.w, 0xD3, 0, who, 400, 0, zero, (int64_t)tip + 1,
                  DNA_DOMAIN_CORE) == 0 &&
          put_row(g.w, 0xD4, 0, who, 5, 0, tok7, 0, DNA_DOMAIN_CORE) == 0 &&
          put_row(g.w, 0xD5, 0, who, 800, 0, zero, 0,
                  (int64_t)DNA_DOMAIN_CORE + 1) == 0,
          "crafted rows (domain_id column present)");
    CHECK(bal_query(&g, who, &r, NULL) == 0 && r.count == 2,
          "two tokens (the non-CORE row is not a token of its own)");
    CHECK(memcmp(r.tokens[0].token_id, zero, 64) == 0 &&
          memcmp(r.tokens[1].token_id, tok7, 64) == 0,
          "token ids ascending: native first");
    CHECK(r.tokens[0].total == 700 && r.tokens[0].coins == 3,
          "native total = the three CORE rows; the other domain's 800 "
          "is excluded");
    CHECK(r.tokens[0].spendable == 300,
          "unlock == tip is spendable, unlock == tip + 1 is not "
          "(rtn_xfer_exec: unlock >= H refuses, H = tip + 1)");
    CHECK(indep_sum(g.w, who, zero, tip + 1, &it_total, &it_spend,
                    &it_coins) == 0 && it_total == 700 && it_spend == 300 &&
          it_coins == 3, "the independent sum agrees");
    CHECK(r.tokens[1].total == 5 && r.tokens[1].spendable == 5 &&
          r.tokens[1].coins == 1, "the second token");
    nodus_client_free_balance_result(&r);

    /* ── Determinism: two builds, byte-identical frames ────────────── */
    {
        uint8_t *f1 = NULL, *f2 = NULL;
        size_t   l1 = 0, l2 = 0;
        int      c1 = 0, c2 = 0;
        char     m[128];

        CHECK(nodus_witness_dnac_balance_build(g.w, 9, who, &f1, &l1, &c1,
                                               m, sizeof(m)) == 0 &&
              nodus_witness_dnac_balance_build(g.w, 9, who, &f2, &l2, &c2,
                                               m, sizeof(m)) == 0,
              "two builds");
        CHECK(l1 == l2 && memcmp(f1, f2, l1) == 0,
              "the same state answers the same bytes");
        free(f1);
        free(f2);
    }

    /* ── an owner holding nothing: a real, empty answer ────────────── */
    fake_fp(0xC2, bad);
    CHECK(bal_query(&g, bad, &r, NULL) == 0 && r.tip == 1 &&
          r.count == 0 && r.tokens == NULL,
          "nothing held = an empty token list, not an error");
    nodus_client_free_balance_result(&r);

    /* ── owner validation ─────────────────────────────────────────── */
    memcpy(bad, g_ks[0].fp, 129);
    for (int i = 0; i < 128; i++)
        if (bad[i] >= 'a' && bad[i] <= 'f') { bad[i] = (char)(bad[i] - 32); break; }
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "an uppercase owner is refused");
    memcpy(bad, g_ks[0].fp, 129);
    bad[127] = '\0';
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "a 127-character owner");
    memcpy(bad, g_ks[0].fp, 129);
    bad[5] = 'g';
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "a non-hex owner");
    CHECK(bal_query(&g, "", &r, &ecode) == -1 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "an empty owner");

    /* ── fail-closed rows ─────────────────────────────────────────── */
    fake_fp(0xC3, bad);                  /* overflow: 3 × INT64_MAX > u64 */
    CHECK(put_row(g.w, 0xE1, 0, bad, INT64_MAX, 0, zero, 0,
                  DNA_DOMAIN_CORE) == 0 &&
          put_row(g.w, 0xE2, 0, bad, INT64_MAX, 0, zero, 0,
                  DNA_DOMAIN_CORE) == 0, "two INT64_MAX rows");
    CHECK(bal_query(&g, bad, &r, NULL) == 0 && r.count == 1 &&
          r.tokens[0].total == 2ULL * (uint64_t)INT64_MAX,
          "control: 2 × INT64_MAX still fits a u64 and is answered exactly");
    nodus_client_free_balance_result(&r);
    CHECK(put_row(g.w, 0xE3, 0, bad, INT64_MAX, 0, zero, 0,
                  DNA_DOMAIN_CORE) == 0, "a third one");
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_INTERNAL_ERROR,
          "a total past UINT64_MAX is a fault, never a wrapped value");

    fake_fp(0xC4, bad);                  /* a negative stored amount     */
    CHECK(put_row(g.w, 0xE4, 0, bad, 10, 0, zero, 0, DNA_DOMAIN_CORE) == 0 &&
          put_row(g.w, 0xE5, 0, bad, -1, 0, zero, 0, DNA_DOMAIN_CORE) == 0,
          "a negative row");
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_INTERNAL_ERROR,
          "a negative amount refuses the answer (never a huge u64)");

    fake_fp(0xC5, bad);                  /* a negative unlock_block      */
    CHECK(put_row(g.w, 0xE6, 0, bad, 10, 0, zero, -5, DNA_DOMAIN_CORE) == 0,
          "a negative unlock row");
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_INTERNAL_ERROR, "a negative unlock refuses");

    fake_fp(0xC6, bad);                  /* a REAL amount                */
    CHECK(put_row(g.w, 0xE7, 0, bad, 10, 1, zero, 0, DNA_DOMAIN_CORE) == 0,
          "a REAL-typed row");
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_INTERNAL_ERROR,
          "a non-integer amount refuses the answer");

    /* ── the token bound: exactly MAX answers, MAX + 1 is TOO_LARGE ── */
    fake_fp(0xC7, bad);
    /* nullifier 0xF0… ‖ t: 256 distinct ids for t = 0..255 */
    _Static_assert(NODUS_DNAC_BALANCE_MAX_TOKENS == 256u,
                   "the row ids below assume a bound of 256");
    for (uint32_t t = 0; t < NODUS_DNAC_BALANCE_MAX_TOKENS; t++) {
        memset(tokn, 0, sizeof(tokn));
        tokn[0] = 0x80;
        tokn[63] = (uint8_t)t;
        CHECK(put_row(g.w, 0xF0, (uint8_t)t, bad, 1, 0, tokn, 0,
                      DNA_DOMAIN_CORE) == 0, "one row per token");
    }
    CHECK(bal_query(&g, bad, &r, NULL) == 0 &&
          r.count == NODUS_DNAC_BALANCE_MAX_TOKENS,
          "exactly the bound answers, and the client decodes it");
    nodus_client_free_balance_result(&r);
    memset(tokn, 0, sizeof(tokn));
    tokn[0] = 0x90;
    CHECK(put_row(g.w, 0xF2, 0, bad, 1, 0, tokn, 0, DNA_DOMAIN_CORE) == 0,
          "one token more");
    CHECK(bal_query(&g, bad, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_TOO_LARGE,
          "past the bound: TOO_LARGE, never a truncated list");

    /* ── not a version-3 node ─────────────────────────────────────── */
    g.w->v2_successor = false;
    CHECK(bal_query(&g, g_ks[0].fp, &r, &ecode) == -1 &&
          ecode == NODUS_ERR_NOT_FOUND, "no version-3 chain: NOT_FOUND");
    g.w->v2_successor = true;

    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/* A hand-built dnac_balance reply. */
typedef struct {
    int      dup_tip;        /* "tip" twice                              */
    int      dup_t;          /* token 0 carries "t" twice                */
    int      no_tk;          /* no "tk" key                              */
    uint32_t n_tok;          /* token maps written                       */
    uint32_t tk_count;       /* the array head (may lie)                 */
    int      desc;           /* token ids descending                     */
    int      same;           /* token 1 repeats token 0's id             */
    int      s_gt_a;         /* token 0: spendable > total               */
    int      zero_c;         /* token 0: coins 0                         */
    int      drop_s;         /* token 0 lacks "s"                        */
} bal_hostile_t;

static size_t build_bal_reply(const bal_hostile_t *hs, uint8_t *buf,
                              size_t cap)
{
    cbor_encoder_t e;
    uint8_t        id[64];

    cbor_encoder_init(&e, buf, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_balance");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, (size_t)(1 + (hs->dup_tip ? 1 : 0) +
                                 (hs->no_tk ? 0 : 1)));
    cbor_encode_cstr(&e, "tip"); cbor_encode_uint(&e, 9);
    if (hs->dup_tip) { cbor_encode_cstr(&e, "tip"); cbor_encode_uint(&e, 9); }
    if (hs->no_tk) return cbor_encoder_len(&e);
    cbor_encode_cstr(&e, "tk");
    cbor_encode_array(&e, hs->tk_count);
    for (uint32_t j = 0; j < hs->n_tok; j++) {
        uint32_t v = hs->desc ? (hs->n_tok - j) : j;
        if (hs->same && j == 1) v = 0;
        bool first = (j == 0);
        size_t keys = 4 + ((first && hs->dup_t) ? 1 : 0) -
                      ((first && hs->drop_s) ? 1 : 0);

        memset(id, 0, sizeof(id));
        id[62] = (uint8_t)(v >> 8);
        id[63] = (uint8_t)v;
        cbor_encode_map(&e, keys);
        cbor_encode_cstr(&e, "t"); cbor_encode_bstr(&e, id, 64);
        if (first && hs->dup_t) {
            cbor_encode_cstr(&e, "t"); cbor_encode_bstr(&e, id, 64);
        }
        cbor_encode_cstr(&e, "a"); cbor_encode_uint(&e, 50);
        if (!(first && hs->drop_s)) {
            cbor_encode_cstr(&e, "s");
            cbor_encode_uint(&e, (first && hs->s_gt_a) ? 51 : 20);
        }
        cbor_encode_cstr(&e, "c");
        cbor_encode_uint(&e, (first && hs->zero_c) ? 0 : 2);
    }
    return cbor_encoder_len(&e);
}

static int t_balance_decoder_hostile(void)
{
    static uint8_t buf[1u << 16];
    nodus_dnac_balance_result_t r;
    bal_hostile_t hs;
    size_t len;

#define BAL_REFUSED(msg) do {                                               \
        len = build_bal_reply(&hs, buf, sizeof(buf));                       \
        CHECK(len > 0 && nodus_dnac_balance_decode(buf, len, &r) == -1 &&   \
              r.tokens == NULL && r.count == 0, (msg));                     \
    } while (0)

    /* the CONTROL */
    memset(&hs, 0, sizeof(hs));
    hs.n_tok = hs.tk_count = 3;
    len = build_bal_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_balance_decode(buf, len, &r) == 0 &&
          r.tip == 9 && r.count == 3 && r.tokens[2].token_id[63] == 2 &&
          r.tokens[0].total == 50 && r.tokens[0].spendable == 20 &&
          r.tokens[0].coins == 2, "the well-formed reply decodes");
    nodus_client_free_balance_result(&r);

    /* truncated at every length */
    for (size_t cut = 1; cut < len; cut++)
        CHECK(nodus_dnac_balance_decode(buf, len - cut, &r) == -1 &&
              r.tokens == NULL && r.count == 0,
              "a truncated reply is refused and leaves nothing to free");

    hs.dup_tip = 1; BAL_REFUSED("a duplicate top-level key"); hs.dup_tip = 0;
    hs.dup_t = 1;   BAL_REFUSED("a duplicate token key");     hs.dup_t = 0;
    hs.no_tk = 1;   BAL_REFUSED("a missing \"tk\"");          hs.no_tk = 0;
    hs.desc = 1;    BAL_REFUSED("descending token ids");      hs.desc = 0;
    hs.same = 1;    BAL_REFUSED("a token listed twice");      hs.same = 0;
    hs.s_gt_a = 1;  BAL_REFUSED("spendable above total");     hs.s_gt_a = 0;
    hs.zero_c = 1;  BAL_REFUSED("a token with zero coins");   hs.zero_c = 0;
    hs.drop_s = 1;  BAL_REFUSED("a token without \"s\"");     hs.drop_s = 0;
    hs.tk_count = 4; BAL_REFUSED("an array head that claims more maps");
    hs.tk_count = 3;

    /* the bound: MAX + 1 REAL, ascending tokens refused; MAX decodes */
    hs.n_tok = hs.tk_count = NODUS_DNAC_BALANCE_MAX_TOKENS + 1;
    BAL_REFUSED("a token array above the bound");
    hs.n_tok = hs.tk_count = NODUS_DNAC_BALANCE_MAX_TOKENS;
    len = build_bal_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_balance_decode(buf, len, &r) == 0 &&
          r.count == NODUS_DNAC_BALANCE_MAX_TOKENS,
          "control: exactly the bound decodes");
    nodus_client_free_balance_result(&r);

    /* an empty list is a valid answer */
    hs.n_tok = hs.tk_count = 0;
    len = build_bal_reply(&hs, buf, sizeof(buf));
    CHECK(len > 0 && nodus_dnac_balance_decode(buf, len, &r) == 0 &&
          r.count == 0 && r.tokens == NULL, "an empty token list decodes");
    nodus_client_free_balance_result(&r);
#undef BAL_REFUSED
    return 0;
}

int main(void)
{
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "block_query",      t_block_query },
        { "decoder_hostile",  t_decoder_hostile },
        { "balance",          t_balance },
        { "balance_decoder",  t_balance_decoder_hostile },
    };
    size_t i, failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_v3_block_query: key generation failed\n");
        return 1;
    }
    for (i = 0; i < ncases; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_v3_block_query: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
