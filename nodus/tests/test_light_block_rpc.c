/**
 * @file nodus/tests/test_light_block_rpc.c
 * @brief `dnac_light_block` — the light client's block source over pinned
 *        4001: the node's answer (nodus_witness_light_block_build, the
 *        handler without its send), the client's request encoder and
 *        reply decoder, and the pinned provider
 *        (nodus/src/client/nodus_light_provider.c).
 *
 * Governing records: docs/plans/decisions/2026-10-16-dnac-light-block-
 * rpc.md (APPROVED B1-B4), docs/plans/decisions/2026-10-16-kurultay-25-
 * summary.md item 8 (never an unpinned provider). Reference @v0.38.26:
 * rpc/core/blocks.go:153-174 (Commit), rpc/core/consensus.go:20-45
 * (Validators), rpc/core/env.go:173-191 (getHeight),
 * light/provider/http/http.go, light/provider/errors.go.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 *  t_server — over a REAL derived version-3 chain driven through the REAL
 *    host pipeline (test_v3_block_query.c's fixture, this file's own copy):
 *      · an empty block store answers h = 0 with NOT_FOUND;
 *      · four empty blocks are committed; the tip's SEEN commit is
 *        replaced by a real signed one (the fixture's commit_height saves
 *        an unsigned seen commit, which CommitFromProto refuses);
 *      · the client encoder's request reaches the node's argument decode
 *        (the round trip: client encode → node build → client decode);
 *      · h = 0 resolves to the store height and answers the SAME bytes as
 *        h = tip; two builds answer identical frames (Determinism);
 *      · a mid height (2) answers the CANONICAL commit — the C:2 row,
 *        which is the commit block 3 carries — and the tip (4) the SEEN
 *        commit just saved (no C:4 exists; blocks.go:166-174);
 *      · every answered "lb" decodes (cmt_light_block_decode) AND passes
 *        LightBlock.ValidateBasic for the chain id (header ↔ set hash,
 *        commit ↔ header), with header height = the resolved height and a
 *        full signature list;
 *      · h above the tip answers NODUS_ERR_HEIGHT_TOO_HIGH (22);
 *      · a deleted C:3 row answers NOT_FOUND; after PruneBlocks(3) heights
 *        1 and 2 (below the base) answer NOT_FOUND;
 *      · a malformed request (no args map, "h" not a uint, "h" twice, no
 *        "h") answers PROTOCOL_ERROR; an open transaction on the
 *        connection answers INTERNAL_ERROR;
 *      · the wire ceiling NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES holds the
 *        codec's bound for a full set.
 *  t_decoder — the client decoder on hand-built replies: a valid reply
 *    decodes (and an unknown key carrying a map is skipped); h = 0, a
 *    missing "h" or "lb", a duplicate key, a non-uint "h", a text "lb", an
 *    empty "lb", an "lb" of MAX + 1 bytes and every truncation are
 *    REFUSED; the request encoder refuses a buffer that is too small.
 *  t_provider_pin — nodus_light_provider_init REFUSES a client with no
 *    pin list, with a NULL list and a count, with a list and count 0; a
 *    pinned client is accepted and its table's chain_id row answers the
 *    configured bytes; a chain id of length 0 or > CMT_MAX_CHAIN_ID_LEN is
 *    refused; light_block on a client whose pin was removed after init is
 *    CMT_FAULT.
 *  t_provider_errors — nodus_light_provider_map_error over every class
 *    (NOT_FOUND, HEIGHT_TOO_HIGH, another node error, timeout, transport,
 *    a refused reply, success); light_block on a pinned client that is
 *    not connected answers NO_RESPONSE through the REAL client call; a
 *    negative height is CMT_FAULT; report_evidence records locally and
 *    refuses NULL.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (NODUS_WITNESS_INTERNAL_API
 * is set by the CMake target, as for test_v3_block_query). Environment:
 * none. SQLite >= 3.35.0. No network, no port.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_lbrpc_*` directory per fixture, removed at close. A case
 * that aborts through CHECK leaves its directory behind.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The handler's own layer (the w->cmt_node lookup, the "no version-3
 *     chain" refusal, the send) is NOT driven: the builder is called with
 *     the fixture's store. The front-door charge (nodus_server.c) is not
 *     driven either.
 *  2. nodus_client_dnac_light_block's network half (send, wait, the
 *     height-match refusal, the copy) is NOT driven — no socket; only its
 *     "not ready" exit is. Its decoder and encoder are driven directly.
 *  3. The tip's seen commit is written by the TEST (a real signed commit
 *     through nodus_cmt_bs_save_seen_commit), not by consensus; the
 *     missing C:3 is a row the test DELETED. The blocks are empty.
 *  4. A validator set that is absent at a held height (ErrNoValSetForHeight
 *     → NOT_FOUND) is not constructed here.
 *  5. The declaration of nodus_witness_light_block_build is a LOCAL extern
 *     below: nodus_witness_handlers.h was outside this package's file
 *     whitelist. If the definition's signature changes and this copy does
 *     not, the link still succeeds and the call is undefined behaviour.
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
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_emission.h"      /* DNAC_DECIMAL_UNIT   */
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_cmt_app.h"
#include "witness/nodus_witness_handlers.h"
#include "server/nodus_server.h"
#include "protocol/nodus_cbor.h"
#include "client/nodus_light_provider.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_light_block.h"
#include "dnac/cmt_light_provider.h"

/* nodus_witness_handlers.c — the dnac_light_block answer without its send.
 * LOCAL declaration: nodus_witness_handlers.h was outside this package's
 * whitelist ("HOW IT CAN LIE" 5). */
int nodus_witness_light_block_build(nodus_cmt_store_t *store,
                                    const uint8_t *payload, size_t len,
                                    uint32_t txn_id,
                                    uint8_t **out, size_t *out_len,
                                    int *err_code, char *err_msg,
                                    size_t err_cap);

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

static const uint8_t TOKEN[NODUS_SESSION_TOKEN_LEN] = { 0x5A };

/* ══ deterministic REAL keys — test_v3_block_query.c make_keys ════════ */

#define N_KEYS       ((int)DNAC_COMMITTEE_SIZE)
#define TREASURY_RAW 93000000000000000ULL
#define GEN_TIME_MS  1767225600000ULL

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
    char    fp[129];
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

/* ══ FIXTURE — test_v3_block_query.c:248-655, this file's own copy (the
 * tree's per-file fixture convention) ═════════════════════════════════ */

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
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    c->reward_pool_initial    = 0;
    c->gas_price_raw_per_unit = 0;
    c->genesis_time_ms        = GEN_TIME_MS;
    c->initial_height         = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        cfg_free(b);
        return -1;
    }
    return 0;
}

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;
    nodus_witness_host_t host;
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
    snprintf(g->dir, sizeof(g->dir), "/tmp/test_lbrpc_%s_XXXXXX", tag);
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
    nodus_server_witness_host(g->srv, &g->host);
    g->w->host = &g->host;
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

/* A precommit per validator for (height, bid) into x->last_commit. */
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

/* Commit height `h` with x->txs[0..n): MakeBlock, its COMPLETE BlockID,
 * ApplyVerifiedBlock and SaveBlock — test_v3_block_query.c commit_height. */
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

/* ══ helpers ═════════════════════════════════════════════════════════ */

/** One request through the client encoder and the node builder.
 *  Returns the builder's rc; `*frame` is heap on 0. */
static int ask(nodus_cmt_store_t *store, uint64_t h, uint8_t **frame,
               size_t *frame_len, int *ecode)
{
    uint8_t req[512];
    size_t  req_len = 0;
    char    emsg[128];

    *frame = NULL;
    *frame_len = 0;
    *ecode = 0;
    if (nodus_dnac_light_block_request_encode(7, TOKEN, h, req, sizeof(req),
                                              &req_len) != 0)
        return -2;
    return nodus_witness_light_block_build(store, req, req_len, 7, frame,
                                           frame_len, ecode, emsg,
                                           sizeof(emsg));
}

/** A hand-built request whose args map is `args_body` (raw CBOR, `n`
 *  entries); with n < 0 the "a" key is left out. */
static int ask_raw(nodus_cmt_store_t *store, int n,
                   void (*args_body)(cbor_encoder_t *), int *ecode)
{
    uint8_t        req[512];
    cbor_encoder_t e;
    uint8_t       *frame = NULL;
    size_t         frame_len = 0;
    char           emsg[128];
    int            rc;

    cbor_encoder_init(&e, req, sizeof(req));
    cbor_encode_map(&e, n < 0 ? 4 : 5);
    cbor_encode_cstr(&e, "t");   cbor_encode_uint(&e, 9);
    cbor_encode_cstr(&e, "y");   cbor_encode_cstr(&e, "q");
    cbor_encode_cstr(&e, "q");   cbor_encode_cstr(&e, "dnac_light_block");
    cbor_encode_cstr(&e, "tok"); cbor_encode_bstr(&e, TOKEN, sizeof(TOKEN));
    if (n >= 0) {
        cbor_encode_cstr(&e, "a");
        cbor_encode_map(&e, (size_t)n);
        if (args_body) args_body(&e);
    }
    *ecode = 0;
    rc = nodus_witness_light_block_build(store, req, cbor_encoder_len(&e), 9,
                                         &frame, &frame_len, ecode, emsg,
                                         sizeof(emsg));
    free(frame);
    return rc;
}

static void args_h_text(cbor_encoder_t *e)
{
    cbor_encode_cstr(e, "h"); cbor_encode_cstr(e, "4");
}

static void args_h_twice(cbor_encoder_t *e)
{
    cbor_encode_cstr(e, "h"); cbor_encode_uint(e, 2);
    cbor_encode_cstr(e, "h"); cbor_encode_uint(e, 3);
}

static void args_no_h(cbor_encoder_t *e)
{
    cbor_encode_cstr(e, "x"); cbor_encode_uint(e, 2);
}

/** Decode a reply frame through the client decoder and the codec, and
 *  check the light block's shape against `want_h`. */
static int check_lb(const uint8_t *frame, size_t frame_len, uint64_t want_h,
                    const uint8_t chain32[32], size_t want_sigs,
                    cmt_light_block_buf_t *buf)
{
    uint64_t       h = 0;
    const uint8_t *lb = NULL;
    size_t         lb_len = 0;

    CHECK(nodus_dnac_light_block_decode(frame, frame_len, &h, &lb, &lb_len)
              == 0, "the reply decodes");
    CHECK(h == want_h, "the reply carries the resolved height");
    CHECK(lb_len > 0 && lb_len <= NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES,
          "lb within the ceiling");
    CHECK(cmt_light_block_decode(lb, lb_len, CMT_BLOCK_PROTOCOL, buf)
              == CMT_OK, "lb decodes as a LightBlock");
    CHECK(buf->lb.signed_header != NULL &&
          buf->lb.signed_header->header != NULL &&
          buf->lb.signed_header->commit != NULL &&
          buf->lb.validator_set != NULL, "every member present");
    CHECK(buf->lb.signed_header->header->height == (int64_t)want_h,
          "header height = resolved height");
    CHECK(buf->lb.signed_header->commit->height == (int64_t)want_h,
          "commit height = resolved height");
    CHECK(buf->lb.signed_header->commit->signatures_len == want_sigs,
          "a full signature list");
    CHECK(buf->lb.validator_set->validators_len == (size_t)N_KEYS,
          "the whole validator set");
    CHECK(cmt_light_block_validate_basic(&buf->lb, chain32, 32,
                                         CMT_BLOCK_PROTOCOL) == CMT_OK,
          "LightBlock.ValidateBasic passes");
    return 0;
}

/* ══ t_server ════════════════════════════════════════════════════════ */

static int t_server(void)
{
    gfx_t                  g;
    exec_t                 x;
    cmt_light_block_buf_t *buf = NULL;
    cmt_commit_sig_t      *c3sigs = NULL;
    cmt_commit_t           c3;
    uint8_t               *f0 = NULL, *ftip = NULL, *ftip2 = NULL, *f2 = NULL;
    size_t                 l0 = 0, ltip = 0, ltip2 = 0, l2 = 0;
    uint8_t               *f = NULL;
    size_t                 fl = 0;
    int                    ecode = 0;
    bool                   found = false;
    uint64_t               pruned = 0;
    int64_t                evp = 0;

    CHECK(cmt_pb_light_block_upper_bound(CMT_VALSET_MAX, CMT_VALSET_MAX) > 0 &&
          cmt_pb_light_block_upper_bound(CMT_VALSET_MAX, CMT_VALSET_MAX) <=
              NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES,
          "the wire ceiling holds a full set's light block");

    CHECK(gfx_open(&g, "srv") == 0, "fixture opens");
    CHECK(exec_init(&x, &g) == 0, "executor initialises");
    buf    = cmt_light_block_buf_new();
    c3sigs = calloc(CMT_VALSET_MAX, sizeof(*c3sigs));
    CHECK(buf != NULL && c3sigs != NULL, "allocations");

    /* an empty block store: nothing to answer */
    CHECK(ask(x.store, 0, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_NOT_FOUND, "empty store: h=0 is NOT_FOUND");

    for (int64_t h = 1; h <= 4; h++)
        CHECK(commit_height(&x, h, 0) == 0, "an empty block commits");
    CHECK(nodus_cmt_bs_height(x.store) == 4, "store height 4");

    /* the tip's SEEN commit: a real signed one (HOW IT CAN LIE 3) */
    CHECK(exec_make_last_commit(&x, 4, &x.bid) == 0, "tip commit signed");
    CHECK(nodus_cmt_bs_save_seen_commit(x.store, 4, &x.last_commit,
                                        x.save_scratch, x.save_cap) == CMT_OK,
          "tip seen commit saved");

    /* h = 0 → the store height; same bytes as h = tip; deterministic */
    CHECK(ask(x.store, 0, &f0, &l0, &ecode) == 0, "h=0 answers");
    CHECK(ask(x.store, 4, &ftip, &ltip, &ecode) == 0, "h=tip answers");
    CHECK(ask(x.store, 4, &ftip2, &ltip2, &ecode) == 0, "h=tip again");
    CHECK(ltip == ltip2 && memcmp(ftip, ftip2, ltip) == 0,
          "two builds answer identical frames");
    {
        uint64_t       h0 = 0, ht = 0;
        const uint8_t *lb0 = NULL, *lbt = NULL;
        size_t         n0 = 0, nt = 0;

        CHECK(nodus_dnac_light_block_decode(f0, l0, &h0, &lb0, &n0) == 0 &&
              nodus_dnac_light_block_decode(ftip, ltip, &ht, &lbt, &nt) == 0,
              "both decode");
        CHECK(h0 == 4 && ht == 4, "h=0 resolves to the tip");
        CHECK(n0 == nt && memcmp(lb0, lbt, n0) == 0,
              "h=0 and h=tip carry the same light block");
    }

    /* the tip: the SEEN commit (no C:4 exists — blocks.go:166-170) */
    CHECK(nodus_cmt_bs_load_block_commit(x.store, 4, c3sigs, CMT_VALSET_MAX,
                                         &c3, &found) == CMT_OK && !found,
          "no canonical commit at the tip");
    if (check_lb(ftip, ltip, 4, g.chain32, (size_t)N_KEYS, buf) != 0)
        return 1;
    CHECK(memcmp(buf->lb.signed_header->commit->block_id.hash,
                 x.bid.hash, CMT_TMHASH_SIZE) == 0,
          "tip commit is for the tip block");
    CHECK(memcmp(buf->lb.signed_header->commit->signatures[0].signature,
                 x.last_commit.signatures[0].signature,
                 x.last_commit.signatures[0].signature_len) == 0,
          "tip commit is the seen commit saved");

    /* a mid height: the CANONICAL commit (C:2, carried by block 3) */
    CHECK(ask(x.store, 2, &f2, &l2, &ecode) == 0, "h=2 answers");
    if (check_lb(f2, l2, 2, g.chain32, (size_t)N_KEYS, buf) != 0) return 1;
    CHECK(nodus_cmt_bs_load_block_commit(x.store, 2, c3sigs, CMT_VALSET_MAX,
                                         &c3, &found) == CMT_OK && found,
          "C:2 held");
    CHECK(c3.signatures_len ==
              buf->lb.signed_header->commit->signatures_len &&
          memcmp(c3.block_id.hash,
                 buf->lb.signed_header->commit->block_id.hash,
                 CMT_TMHASH_SIZE) == 0 &&
          memcmp(c3.signatures[0].signature,
                 buf->lb.signed_header->commit->signatures[0].signature,
                 c3.signatures[0].signature_len) == 0,
          "mid-height commit = the canonical C:2 row");

    /* above the tip → 22 */
    CHECK(ask(x.store, 5, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_HEIGHT_TOO_HIGH && f == NULL,
          "h above the tip is HEIGHT_TOO_HIGH");
    CHECK(NODUS_ERR_HEIGHT_TOO_HIGH == 22, "the code is 22");
    CHECK(ask(x.store, UINT64_MAX, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_HEIGHT_TOO_HIGH, "h = UINT64_MAX too");

    /* malformed requests */
    CHECK(ask_raw(x.store, -1, NULL, &ecode) != 0 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "no args map");
    CHECK(ask_raw(x.store, 1, args_h_text, &ecode) != 0 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "h not a uint");
    CHECK(ask_raw(x.store, 2, args_h_twice, &ecode) != 0 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "h twice");
    CHECK(ask_raw(x.store, 1, args_no_h, &ecode) != 0 &&
          ecode == NODUS_ERR_PROTOCOL_ERROR, "no h");

    /* an open transaction: only committed state answers */
    CHECK(sqlite3_exec(g.w->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK,
          "begin");
    CHECK(ask(x.store, 2, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_INTERNAL_ERROR, "open transaction refused");
    CHECK(sqlite3_exec(g.w->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK,
          "rollback");

    /* a missing commit row at a held height → NOT_FOUND */
    CHECK(nodus_cmt_store_delete(x.store, false, "C:3") == CMT_OK,
          "C:3 deleted");
    CHECK(ask(x.store, 3, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_NOT_FOUND, "absent commit is NOT_FOUND");

    /* pruned: below the base → NOT_FOUND (env.go:183-187) */
    CHECK(nodus_cmt_bs_prune_blocks(x.store, 3, x.state, &pruned, &evp)
              == CMT_OK, "prune to 3");
    CHECK(nodus_cmt_bs_base(x.store) == 3, "base moved to 3");
    CHECK(ask(x.store, 1, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_NOT_FOUND, "pruned h=1 is NOT_FOUND");
    CHECK(ask(x.store, 2, &f, &fl, &ecode) != 0 &&
          ecode == NODUS_ERR_NOT_FOUND, "pruned h=2 is NOT_FOUND");
    CHECK(ask(x.store, 4, &f, &fl, &ecode) == 0, "the tip still answers");
    free(f);
    f = NULL;

    free(f0);
    free(ftip);
    free(ftip2);
    free(f2);
    free(c3sigs);
    cmt_light_block_buf_free(buf);
    exec_free(&x);
    gfx_close(&g);
    return 0;
}

/* ══ t_decoder — hand-built replies ══════════════════════════════════ */

/* R_VALID, not R_OK: <unistd.h> defines R_OK (access(2)) */
enum { R_VALID, R_H0, R_NO_H, R_NO_LB, R_DUP_H, R_H_TEXT, R_LB_TEXT,
       R_LB_EMPTY, R_LB_OVER, R_UNKNOWN_MAP };

static size_t build_reply(int mode, const uint8_t *lb, size_t lb_len,
                          uint8_t *out, size_t cap)
{
    cbor_encoder_t e;
    size_t         n = 2;

    if (mode == R_NO_H || mode == R_NO_LB) n = 1;
    if (mode == R_DUP_H || mode == R_UNKNOWN_MAP) n = 3;
    cbor_encoder_init(&e, out, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 3);
    cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_light_block");
    cbor_encode_cstr(&e, "r");
    cbor_encode_map(&e, n);
    if (mode == R_UNKNOWN_MAP) {
        cbor_encode_cstr(&e, "zz");
        cbor_encode_map(&e, 1);
        cbor_encode_cstr(&e, "k"); cbor_encode_uint(&e, 1);
    }
    if (mode != R_NO_H) {
        cbor_encode_cstr(&e, "h");
        if (mode == R_H_TEXT) cbor_encode_cstr(&e, "5");
        else cbor_encode_uint(&e, mode == R_H0 ? 0 : 5);
    }
    if (mode == R_DUP_H) {
        cbor_encode_cstr(&e, "h"); cbor_encode_uint(&e, 5);
    }
    if (mode != R_NO_LB) {   /* R_DUP_H: h, h, lb — three whole pairs */
        cbor_encode_cstr(&e, "lb");
        if (mode == R_LB_TEXT) cbor_encode_cstr(&e, "x");
        else if (mode == R_LB_EMPTY) cbor_encode_bstr(&e, lb, 0);
        else cbor_encode_bstr(&e, lb, lb_len);
    }
    return cbor_encoder_len(&e);
}

static int t_decoder(void)
{
    uint8_t        lb[16];
    uint8_t        frame[256];
    uint8_t        req[64];
    size_t         len, req_len = 0;
    uint64_t       h = 0;
    const uint8_t *out = NULL;
    size_t         out_len = 0;
    uint8_t       *big = NULL, *bigf = NULL;

    memset(lb, 0xAB, sizeof(lb));

    /* the control */
    len = build_reply(R_VALID, lb, sizeof(lb), frame, sizeof(frame));
    CHECK(len > 0, "control encodes");
    CHECK(nodus_dnac_light_block_decode(frame, len, &h, &out, &out_len) == 0,
          "a valid reply decodes");
    CHECK(h == 5 && out_len == sizeof(lb) && memcmp(out, lb, sizeof(lb)) == 0,
          "fields as sent");
    CHECK(out >= frame && out + out_len <= frame + len,
          "lb points into the reply");

    /* every truncation is refused */
    for (size_t cut = 0; cut < len; cut++)
        CHECK(nodus_dnac_light_block_decode(frame, cut, &h, &out, &out_len)
                  != 0 && out == NULL && h == 0, "a truncated reply is refused");

    len = build_reply(R_UNKNOWN_MAP, lb, sizeof(lb), frame, sizeof(frame));
    CHECK(nodus_dnac_light_block_decode(frame, len, &h, &out, &out_len) == 0 &&
          h == 5, "an unknown key carrying a map is skipped");

    {
        static const int bad[] = { R_H0, R_NO_H, R_NO_LB, R_DUP_H, R_H_TEXT,
                                   R_LB_TEXT, R_LB_EMPTY };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            len = build_reply(bad[i], lb, sizeof(lb), frame, sizeof(frame));
            CHECK(len > 0, "hostile reply encodes");
            CHECK(nodus_dnac_light_block_decode(frame, len, &h, &out,
                                                &out_len) != 0 &&
                  out == NULL && out_len == 0 && h == 0,
                  "a hostile reply is refused");
        }
    }

    /* an lb one byte above the ceiling */
    big  = calloc(1, (size_t)NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES + 1u);
    bigf = malloc((size_t)NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES + 256u);
    CHECK(big != NULL && bigf != NULL, "allocations");
    len = build_reply(R_LB_OVER, big,
                      (size_t)NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES + 1u, bigf,
                      (size_t)NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES + 256u);
    CHECK(len > NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES, "oversize reply encodes");
    CHECK(nodus_dnac_light_block_decode(bigf, len, &h, &out, &out_len) != 0,
          "lb above the ceiling is refused");
    /* exactly the ceiling decodes */
    len = build_reply(R_LB_OVER, big, (size_t)NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES,
                      bigf, (size_t)NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES + 256u);
    CHECK(nodus_dnac_light_block_decode(bigf, len, &h, &out, &out_len) == 0 &&
          out_len == NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES,
          "lb at the ceiling decodes");
    free(big);
    free(bigf);

    /* NULL arguments */
    len = build_reply(R_VALID, lb, sizeof(lb), frame, sizeof(frame));
    CHECK(nodus_dnac_light_block_decode(NULL, len, &h, &out, &out_len) != 0 &&
          nodus_dnac_light_block_decode(frame, len, NULL, &out, &out_len) != 0,
          "NULL refused");

    /* the request encoder */
    CHECK(nodus_dnac_light_block_request_encode(1, TOKEN, 42, req,
                                                sizeof(req), &req_len) == 0 &&
          req_len > 0, "request encodes");
    CHECK(nodus_dnac_light_block_request_encode(1, TOKEN, 42, req, 8,
                                                &req_len) != 0 &&
          req_len == 0, "request encoder refuses a small buffer");
    return 0;
}

/* ══ t_provider_pin ══════════════════════════════════════════════════ */

static const uint8_t CHAIN[32] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static int t_provider_pin(void)
{
    nodus_client_t         *c = calloc(1, sizeof(*c));
    nodus_light_provider_t  p;
    cmt_light_provider_t    t;
    nodus_key_t             pins[1];
    const uint8_t          *cid = NULL;
    size_t                  cid_len = 0;
    cmt_light_block_buf_t  *buf = cmt_light_block_buf_new();
    cmt_light_provider_error_t err;
    uint8_t                 long_id[CMT_MAX_CHAIN_ID_LEN + 1];

    CHECK(c != NULL && buf != NULL, "allocations");
    memset(pins, 0x11, sizeof(pins));
    memset(long_id, 0x22, sizeof(long_id));

    /* no pin at all */
    c->config.pinned_server_fps      = NULL;
    c->config.pinned_server_fp_count = 0;
    CHECK(nodus_light_provider_init(&p, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_REJECT,
          "an unpinned client is refused");
    CHECK(t.light_block == NULL && t.ctx == NULL && p.client == NULL,
          "a refused init leaves nothing bound");
    /* a count without a list */
    c->config.pinned_server_fp_count = 1;
    CHECK(nodus_light_provider_init(&p, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_REJECT,
          "count without a list is refused");
    /* a list with count 0 */
    c->config.pinned_server_fps      = pins;
    c->config.pinned_server_fp_count = 0;
    CHECK(nodus_light_provider_init(&p, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_REJECT,
          "list with count 0 is refused");
    CHECK(!nodus_light_provider_config_pinned(&c->config) &&
          !nodus_light_provider_config_pinned(NULL), "pinned predicate");

    /* pinned */
    c->config.pinned_server_fp_count = 1;
    CHECK(nodus_light_provider_config_pinned(&c->config), "pinned");
    CHECK(nodus_light_provider_init(&p, c, CHAIN, 0, CMT_BLOCK_PROTOCOL, &t)
              == CMT_REJECT, "empty chain id refused");
    CHECK(nodus_light_provider_init(&p, c, long_id, sizeof(long_id),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_REJECT,
          "chain id above MaxChainIDLen refused");
    CHECK(nodus_light_provider_init(&p, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_OK,
          "a pinned client is accepted");
    CHECK(t.ctx == &p && t.chain_id && t.light_block && t.report_evidence,
          "every row bound");
    CHECK(t.chain_id(t.ctx, &cid, &cid_len) == CMT_OK &&
          cid_len == sizeof(CHAIN) && memcmp(cid, CHAIN, sizeof(CHAIN)) == 0,
          "chain_id answers the configured bytes");
    CHECK(nodus_light_provider_init(NULL, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_FAULT &&
          nodus_light_provider_init(&p, NULL, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_FAULT,
          "NULL is CMT_FAULT");

    /* the pin removed after init: the call refuses */
    CHECK(nodus_light_provider_init(&p, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_OK,
          "re-init");
    c->config.pinned_server_fps = NULL;
    CHECK(t.light_block(t.ctx, 1, buf, &err) == CMT_FAULT &&
          err.code == CMT_LIGHT_PROVIDER_ERR_NONE,
          "an unpinned client at call time is CMT_FAULT");

    cmt_light_block_buf_free(buf);
    free(c);
    return 0;
}

/* ══ t_provider_errors ═══════════════════════════════════════════════ */

static int t_provider_errors(void)
{
    static const struct {
        int rc, server_err, want_ret, want_code;
    } rows[] = {
        { 0, 0, CMT_OK, CMT_LIGHT_PROVIDER_ERR_NONE },
        { NODUS_ERR_NOT_FOUND, NODUS_ERR_NOT_FOUND, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND },
        { NODUS_ERR_HEIGHT_TOO_HIGH, NODUS_ERR_HEIGHT_TOO_HIGH, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH },
        { NODUS_ERR_INTERNAL_ERROR, NODUS_ERR_INTERNAL_ERROR, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_NONE },
        { NODUS_ERR_RATE_LIMITED, NODUS_ERR_RATE_LIMITED, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_NONE },
        /* the node ANSWERED protocol error (e.g. an older node without
         * the method): unnamed, not a bad block */
        { NODUS_ERR_PROTOCOL_ERROR, NODUS_ERR_PROTOCOL_ERROR, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_NONE },
        { NODUS_ERR_TIMEOUT, 0, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE },
        { -1, 0, CMT_REJECT, CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE },
        /* the reply was refused HERE: a bad light block */
        { NODUS_ERR_PROTOCOL_ERROR, 0, CMT_REJECT,
          CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK },
    };
    nodus_client_t            *c = calloc(1, sizeof(*c));
    nodus_light_provider_t     p;
    cmt_light_provider_t       t;
    nodus_key_t                pins[1];
    cmt_light_block_buf_t     *buf = cmt_light_block_buf_new();
    cmt_light_provider_error_t err;
    cmt_pb_evidence_t         *ev = calloc(1, sizeof(*ev));

    CHECK(c != NULL && buf != NULL && ev != NULL, "allocations");
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        memset(&err, 0x7F, sizeof(err));
        CHECK(nodus_light_provider_map_error(rows[i].rc, rows[i].server_err,
                                             &err) == rows[i].want_ret,
              "map: return");
        CHECK(err.code == rows[i].want_code, "map: code");
        CHECK(err.reason == (rows[i].want_code ==
                                     CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK
                                 ? CMT_REJECT : CMT_OK),
              "map: reason only on BAD_LIGHT_BLOCK");
    }
    CHECK(nodus_light_provider_map_error(NODUS_ERR_TIMEOUT, 0, NULL)
              == CMT_REJECT, "map: NULL err allowed");

    /* the REAL call on a pinned client that is not connected */
    memset(pins, 0x33, sizeof(pins));
    c->config.pinned_server_fps      = pins;
    c->config.pinned_server_fp_count = 1;
    c->state = NODUS_CLIENT_DISCONNECTED;
    CHECK(nodus_light_provider_init(&p, c, CHAIN, sizeof(CHAIN),
                                    CMT_BLOCK_PROTOCOL, &t) == CMT_OK,
          "pinned provider");
    CHECK(t.light_block(t.ctx, 3, buf, &err) == CMT_REJECT &&
          err.code == CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE,
          "a client that is not connected answers NO_RESPONSE");
    CHECK(buf->lb.signed_header == NULL && buf->lb.validator_set == NULL,
          "nothing decoded on a refusal");
    CHECK(t.light_block(t.ctx, -1, buf, &err) == CMT_FAULT &&
          err.code == CMT_LIGHT_PROVIDER_ERR_NONE,
          "a negative height is CMT_FAULT");
    CHECK(t.light_block(t.ctx, 3, NULL, &err) == CMT_FAULT, "NULL out");

    /* report_evidence: local record only */
    ev->has_duplicate_vote_evidence = true;
    CHECK(t.report_evidence(t.ctx, ev) == CMT_OK && p.evidence_recorded == 1,
          "evidence recorded locally");
    CHECK(t.report_evidence(t.ctx, ev) == CMT_OK && p.evidence_recorded == 2,
          "and counted");
    CHECK(t.report_evidence(t.ctx, NULL) == CMT_FAULT &&
          p.evidence_recorded == 2, "NULL evidence is CMT_FAULT");

    free(ev);
    cmt_light_block_buf_free(buf);
    free(c);
    return 0;
}

int main(void)
{
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "server",          t_server },
        { "decoder",         t_decoder },
        { "provider_pin",    t_provider_pin },
        { "provider_errors", t_provider_errors },
    };
    size_t i, failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_light_block_rpc: key generation failed\n");
        return 1;
    }
    for (i = 0; i < ncases; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_light_block_rpc: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
