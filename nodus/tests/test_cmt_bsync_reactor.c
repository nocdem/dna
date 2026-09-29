/**
 * Nodus — cometbft @709fd12b C port, blocksync: the block sync reactor of
 * `shared/dnac/cmt_bsync_reactor.c` (blocksync/reactor.go) over an
 * IN-MEMORY switch in this file, with a real chain of signed blocks.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a node with an empty store reaches the SAME state as the chain it
 * syncs from, through the reference's verify → save → apply order, and
 * that a peer serving a block whose successor carries a bad commit is
 * stopped, banned and routed around. If this file failed, one of these
 * would be false:
 *   · SERVING (reactor.go:190-305): AddPeer sends StatusResponse{base 1,
 *     height NB}; a StatusRequest is answered with the same; a
 *     BlockRequest for a missing height gets NoBlockResponse{height}; a
 *     BlockRequest for a stored height gets a BlockResponse whose Block
 *     decodes to the stored block's hash and carries NO ExtendedCommit
 *     (vote extensions are disabled by default, :228, :246);
 *   · REFUSALS at the boundary stop the peer: a message longer than
 *     MaxMsgSize (:184), bytes that do not decode (p2p/peer.go:407-412),
 *     a BlockRequest with a negative height (:253-257, msgs.go:29-31);
 *   · SYNC (reactor.go:318-572): node B (genesis state, empty store,
 *     blockSync) connected to node A (NB signed blocks, serving only)
 *     requests after peerConnWait, verifies block h with block h+1's
 *     LastCommit (VerifyCommitLight, :496-497 — REAL ML-DSA-87 signatures
 *     over Commit.VoteSignBytes), saves h with h+1's LastCommit as its
 *     seen commit (:544) BEFORE applying it (:549), and ends with
 *     last_block_height NB−1, the same last BlockID and the same app hash
 *     as the chain's own state at NB−1 — every stored block's hash equal
 *     to the chain's;
 *   · the SWITCH (:382-438): once caught up (pool.go:220) B calls
 *     SwitchToConsensus exactly once, with its OWN state at NB−1 and
 *     skipWAL = true (blocksSynced > 0, :431), and its poolRoutine ends;
 *   · a BAD COMMIT (:515-531): node X serves honest blocks 1..K and a
 *     block K+1 whose LastCommit has a corrupted signature at index 0 (the
 *     largest power, so VerifyCommitLight's early exit cannot pass it by);
 *     B applies 1..K−1, refuses K, stops X with ErrReactorValidation, bans
 *     it, and when an honest node A is connected afterwards finishes at
 *     NB−1 with the honest chain's state — block K included, from A.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION` (every cmt_* target). A DEFAULT
 *   BUILD is enough.
 * ENVIRONMENT: nothing. The clock is a variable in this file; keys come
 *   from `qgp_dsa87_keypair_derand` with fixed seeds; no network, no
 *   files. Safe under `ctest -j`. Several MB of heap (state storages).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing: no files, no processes.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The EXECUTOR IS A FAKE: `validate_block` accepts everything and
 *     `apply_verified_block` sets height, BlockID, time, last validators
 *     and app hash = BlockID hash. So "same state" here means "the same
 *     blocks were applied in the same order", NOT that the ledger's
 *     FinalizeBlock gives the same root — that is the Genesis Protocol
 *     scenario test_cmt_blocksync.sh's job (7/7 state_root).
 *  2. ML-DSA-87 signing is hedged: signatures are never compared as bytes,
 *     only verified.
 *  3. The switch is in-memory and FIFO, with no send-queue limits: a full
 *     queue (TrySend false, :362-363) is not exercised.
 *  4. Vote extensions stay disabled (the default consensus params), so the
 *     ext-commit branches (:503-514, :537-538) are not driven.
 *  5. `validate_block`'s REJECT branch and the BS-7 MakePartSet failure
 *     are not driven.
 *
 * @file test_cmt_bsync_reactor.c
 */

#include "dnac/cmt_bsync_reactor.h"
#include "dnac/cmt_bsync_msgs.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_part_set.h"

#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define NVALS 4
#define NB    8          /* the honest chain: blocks 1..NB           */
#define KBAD  4          /* X serves 1..KBAD honest and KBAD+1 bad   */
#define MS    ((int64_t)1000000)
#define SEC   ((int64_t)1000000000)
#define GENESIS_SECONDS 1700000000

/* ══ the chain fixture ════════════════════════════════════════════════ */

static uint8_t              g_pk[NVALS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t              g_sk[NVALS][QGP_DSA87_SECRETKEYBYTES];
static int                  g_key_of_index[NVALS];
static cmt_genesis_validator_t g_gvals[NVALS];
static cmt_valset_scratch_t *g_vscratch;
static cmt_state_block_scratch_t *g_bscratch;

static cmt_state_t          g_genesis;       /* pristine, for B */
static cmt_state_storage_t *g_genesis_stor;
static cmt_state_t          g_chain;         /* advanced to NB */
static cmt_state_storage_t *g_chain_stor;

static cmt_block_t          g_blocks[NB + 1];
static cmt_pb_bytes_t       g_txs[NB + 1][1];
static uint8_t              g_txbytes[NB + 1][16];
static cmt_block_id_t       g_ids[NB + 1];
static cmt_commit_t         g_commits[NB + 1];     /* g_commits[0] empty */
static cmt_commit_sig_t     g_csigs[NB + 1][NVALS];
static uint8_t              g_app_hash_at[NB + 1][64];

static cmt_block_t          g_bad_block;           /* height KBAD + 1 */
static cmt_commit_t         g_bad_commit;          /* commit KBAD, sig 0 bad */
static cmt_commit_sig_t     g_bad_sigs[NVALS];

/* The fake executor's apply (header, "HOW IT CAN LIE" 1). The generator
 * and the syncing node use this SAME function. */
static int fake_apply(const cmt_block_id_t *id, cmt_block_t *b, cmt_state_t *st)
{
    st->last_block_height = b->header.height;
    st->last_block_id     = *id;
    st->last_block_time   = b->header.time;
    if (cmt_validator_set_init(&st->last_validators,
                               st->storage->last_validators,
                               CMT_VALSET_MAX) != CMT_OK ||
        cmt_validator_set_copy(&st->validators, &st->last_validators) != CMT_OK) {
        return CMT_FAULT;
    }
    memcpy(st->app_hash, id->hash, CMT_TMHASH_SIZE);
    st->app_hash_len = CMT_TMHASH_SIZE;
    return CMT_OK;
}

static int block_id_of(cmt_block_t *b, cmt_block_id_t *out)
{
    uint8_t        *scratch = (uint8_t *)malloc(1u << 20);
    cmt_part_t     *parts = (cmt_part_t *)calloc(32, sizeof(cmt_part_t));
    cmt_part_set_t  ps;
    int             rc = CMT_FAULT;

    if (scratch && parts) {
        memset(&ps, 0, sizeof(ps));
        cmt_pb_block_id_init(out);
        if (cmt_block_make_part_set(b, (uint32_t)CMT_BLOCK_PART_SIZE_BYTES,
                                    scratch, 1u << 20, parts, 32, &ps) == CMT_OK &&
            cmt_block_hash(b, out->hash) == CMT_OK) {
            out->hash_len = CMT_TMHASH_SIZE;
            rc = cmt_part_set_header(&ps, &out->part_set_header);
        }
    }
    free(scratch);
    free(parts);
    return rc;
}

/* Every validator signs COMMIT for `id` at `height`. */
static int sign_commit(cmt_commit_t *c, cmt_commit_sig_t *sigs, int64_t height,
                       const cmt_block_id_t *id, cmt_time_t t,
                       const cmt_state_t *st)
{
    size_t i;

    memset(c, 0, sizeof(*c));
    cmt_pb_commit_init(c);
    c->signatures     = sigs;
    c->signatures_cap = NVALS;
    c->height         = height;
    c->round          = 0;
    c->block_id       = *id;
    c->signatures_len = NVALS;
    for (i = 0; i < NVALS; i++) {
        memset(&sigs[i], 0, sizeof(sigs[i]));
        sigs[i].block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
        memcpy(sigs[i].validator_address, st->validators.validators[i].address, 32);
        sigs[i].validator_address_len = 32u;
        sigs[i].timestamp.seconds = t.seconds + 1;
        sigs[i].timestamp.nanos   = 0;
    }
    for (i = 0; i < NVALS; i++) {
        uint8_t sb[CMT_VOTE_SIGN_BYTES_MAX];
        size_t  sb_len = 0, siglen = 0;

        if (cmt_commit_vote_sign_bytes(c, st->chain_id, st->chain_id_len,
                                       (int32_t)i, sb, sizeof(sb), &sb_len) != CMT_OK ||
            qgp_dsa87_sign(sigs[i].signature, &siglen, sb, sb_len,
                           g_sk[g_key_of_index[i]]) != 0) {
            return 1;
        }
        sigs[i].signature_len = siglen;
    }
    return 0;
}

static int make_block_at(int64_t h, cmt_commit_t *last, cmt_block_t *out)
{
    cmt_data_t d;

    memset(&d, 0, sizeof(d));
    cmt_pb_data_init(&d);
    d.txs     = g_txs[h];
    d.txs_cap = 1;
    d.txs_len = 1;
    return cmt_state_make_block(&g_chain, h, &d, last, NULL,
                                g_chain.validators.validators[0].address, 32,
                                g_bscratch, out);
}

static int build_chain(void)
{
    cmt_genesis_doc_t doc;
    size_t            i;
    int               j;
    int64_t           h;

    g_vscratch = (cmt_valset_scratch_t *)calloc(1, sizeof(*g_vscratch));
    g_bscratch = (cmt_state_block_scratch_t *)calloc(1, sizeof(*g_bscratch));
    g_genesis_stor = (cmt_state_storage_t *)calloc(1, sizeof(*g_genesis_stor));
    g_chain_stor = (cmt_state_storage_t *)calloc(1, sizeof(*g_chain_stor));
    if (!g_vscratch || !g_bscratch || !g_genesis_stor || !g_chain_stor) {
        return 1;
    }
    for (j = 0; j < NVALS; j++) {
        uint8_t seed[32];

        memset(seed, (uint8_t)(0x31 + j), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[j], g_sk[j], seed) != 0) {
            return 1;
        }
    }
    memset(&doc, 0, sizeof(doc));
    doc.genesis_time.seconds = GENESIS_SECONDS;
    for (i = 0; i < (size_t)CMT_PB_CHAINID_MAX; i++) {
        doc.chain_id[i] = (uint8_t)(0x60u + i);
    }
    doc.chain_id_len         = (size_t)CMT_PB_CHAINID_MAX;
    doc.initial_height       = 1;
    doc.has_consensus_params = false;      /* defaults: extensions off */
    doc.validators           = g_gvals;
    doc.validators_cap       = NVALS;
    doc.validators_len       = NVALS;
    for (j = 0; j < NVALS; j++) {
        memset(&g_gvals[j], 0, sizeof(g_gvals[j]));
        g_gvals[j].pub_key.present = true;
        memcpy(g_gvals[j].pub_key.key, g_pk[j], QGP_DSA87_PUBLICKEYBYTES);
        g_gvals[j].power = 10 * (j + 1);
    }
    if (cmt_state_init(&g_genesis, g_genesis_stor) != CMT_OK ||
        cmt_state_make_genesis(&doc, NULL, NULL, g_vscratch, &g_genesis) != CMT_OK ||
        cmt_state_init(&g_chain, g_chain_stor) != CMT_OK ||
        cmt_state_copy(&g_genesis, &g_chain) != CMT_OK) {
        return 1;
    }
    /* key for each index of the SORTED set */
    for (i = 0; i < NVALS; i++) {
        g_key_of_index[i] = -1;
        for (j = 0; j < NVALS; j++) {
            uint8_t addr[32];

            if (cmt_pubkey_address(g_pk[j], addr) == CMT_OK &&
                memcmp(g_chain.validators.validators[i].address, addr, 32) == 0) {
                g_key_of_index[i] = j;
            }
        }
        if (g_key_of_index[i] < 0) {
            return 1;
        }
    }
    /* block 1's LastCommit is the empty Commit (height 0) */
    memset(&g_commits[0], 0, sizeof(g_commits[0]));
    cmt_pb_commit_init(&g_commits[0]);

    for (h = 1; h <= NB; h++) {
        snprintf((char *)g_txbytes[h], sizeof(g_txbytes[h]), "tx-%lld",
                 (long long)h);
        g_txs[h][0].data = g_txbytes[h];
        g_txs[h][0].len  = strlen((const char *)g_txbytes[h]);
        if (make_block_at(h, &g_commits[h - 1], &g_blocks[h]) != CMT_OK ||
            block_id_of(&g_blocks[h], &g_ids[h]) != CMT_OK) {
            fprintf(stderr, "block %lld not built\n", (long long)h);
            return 1;
        }
        if (h == KBAD + 1) {
            /* X's block KBAD+1: the same commit KBAD with signature 0
             * flipped — a LastCommit whose hash the header matches
             * (fillHeader) but which does not verify. */
            g_bad_commit = g_commits[KBAD];
            memcpy(g_bad_sigs, g_csigs[KBAD], sizeof(g_bad_sigs));
            g_bad_commit.signatures = g_bad_sigs;
            g_bad_sigs[0].signature[10] ^= 0x01;
            if (make_block_at(h, &g_bad_commit, &g_bad_block) != CMT_OK) {
                return 1;
            }
        }
        if (sign_commit(&g_commits[h], g_csigs[h], h, &g_ids[h],
                        g_blocks[h].header.time, &g_chain) != 0 ||
            fake_apply(&g_ids[h], &g_blocks[h], &g_chain) != CMT_OK) {
            return 1;
        }
        memcpy(g_app_hash_at[h], g_chain.app_hash, CMT_TMHASH_SIZE);
    }
    return 0;
}

/* ══ the in-memory switch ═════════════════════════════════════════════ */

static int64_t g_now = (int64_t)GENESIS_SECONDS * SEC + 100 * SEC;

static int h_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    out->seconds = g_now / SEC;
    out->nanos   = (int32_t)(g_now % SEC);
    return CMT_OK;
}

#define MAXNODES 4
#define MAXPEERS 4
#define MAXSTOPS 16

typedef struct node node_t;
struct node {
    char                 id[CMT_P2P_ID_CAP];
    bool                 has_reactor;
    cmt_bsync_reactor_t  r;
    /* store */
    cmt_block_t         *serve[NB + 2];
    int64_t              base, height;
    bool                 saved[NB + 2];
    uint8_t              saved_hash[NB + 2][64];
    int64_t              saved_seen_height[NB + 2];
    /* switch */
    node_t              *peers[MAXPEERS];
    int                  npeers;
    char                 stop_id[MAXSTOPS][CMT_P2P_ID_CAP];
    int                  stop_reason[MAXSTOPS];
    int                  nstops, stops_done;
    /* SwitchToConsensus */
    int                  switch_calls;
    int64_t              switch_height;
    bool                 switch_skip_wal;
    /* a reactor-less peer's inbox */
    cmt_bsync_msg_t      inbox[32];
    int                  ninbox;
};

typedef struct {
    node_t  *from, *to;
    uint8_t *bytes;
    size_t   len;
} qmsg_t;

static qmsg_t g_q[4096];
static size_t g_qh, g_qt;

static node_t *peer_of(node_t *n, const char *id)
{
    int i;

    for (i = 0; i < n->npeers; i++) {
        if (strcmp(n->peers[i]->id, id) == 0) {
            return n->peers[i];
        }
    }
    return NULL;
}

static bool enqueue(node_t *from, node_t *to, const uint8_t *msg, size_t len)
{
    uint8_t *b;

    if (g_qt >= sizeof(g_q) / sizeof(g_q[0])) {
        return false;
    }
    b = (uint8_t *)malloc(len ? len : 1u);
    if (!b) {
        return false;
    }
    memcpy(b, msg, len);
    g_q[g_qt].from = from;
    g_q[g_qt].to = to;
    g_q[g_qt].bytes = b;
    g_q[g_qt].len = len;
    g_qt++;
    return true;
}

static bool h_try_send(void *ctx, const char *peer_id, const uint8_t *msg, size_t len)
{
    node_t *n = (node_t *)ctx;
    node_t *p = peer_of(n, peer_id);

    return p != NULL && enqueue(n, p, msg, len);
}

static void h_broadcast(void *ctx, const uint8_t *msg, size_t len)
{
    node_t *n = (node_t *)ctx;
    int     i;

    for (i = 0; i < n->npeers; i++) {
        (void)enqueue(n, n->peers[i], msg, len);
    }
}

static void h_stop(void *ctx, const char *peer_id, int reason)
{
    node_t *n = (node_t *)ctx;

    if (peer_of(n, peer_id) == NULL || n->nstops >= MAXSTOPS) {
        return;
    }
    snprintf(n->stop_id[n->nstops], CMT_P2P_ID_CAP, "%s", peer_id);
    n->stop_reason[n->nstops] = reason;
    n->nstops++;
}

static int h_bs_base(void *ctx, int64_t *out)
{
    *out = ((node_t *)ctx)->base;
    return CMT_OK;
}

static int h_bs_height(void *ctx, int64_t *out)
{
    *out = ((node_t *)ctx)->height;
    return CMT_OK;
}

static int h_bs_load_block(void *ctx, int64_t height, cmt_block_t **out,
                           size_t *hint, bool *found)
{
    node_t *n = (node_t *)ctx;

    *found = false;
    *out = NULL;
    if (height >= 1 && height <= NB + 1 && n->serve[height] != NULL) {
        *out = n->serve[height];
        *hint = 8192;
        *found = true;
    }
    return CMT_OK;
}

static int h_bs_load_ext(void *ctx, int64_t height, cmt_extended_commit_t *out,
                         bool *found)
{
    (void)ctx; (void)height; (void)out;
    *found = false;
    return CMT_OK;
}

static int h_bs_save(void *ctx, cmt_block_t *block, const cmt_part_set_t *parts,
                     const cmt_commit_t *seen)
{
    node_t *n = (node_t *)ctx;
    int64_t h = block->header.height;

    (void)parts;
    if (h < 1 || h > NB + 1 || cmt_block_hash(block, n->saved_hash[h]) != CMT_OK) {
        return CMT_FAULT;
    }
    n->saved[h] = true;
    n->saved_seen_height[h] = seen != NULL ? seen->height : -1;
    n->height = h;
    if (n->base == 0) {
        n->base = h;
    }
    return CMT_OK;
}

static int h_bs_save_ext(void *ctx, cmt_block_t *block, const cmt_part_set_t *parts,
                         const cmt_extended_commit_t *ec)
{
    (void)ctx; (void)block; (void)parts; (void)ec;
    return CMT_FAULT;                  /* extensions are off here */
}

static int h_abci(void *ctx, cmt_abci_params_t *out)
{
    (void)ctx;
    *out = g_genesis.consensus_params.abci;
    return CMT_OK;
}

static int h_validate(void *ctx, const cmt_state_t *st, cmt_block_t *b)
{
    (void)ctx; (void)st; (void)b;
    return CMT_OK;                     /* HOW IT CAN LIE 1 */
}

static int h_apply(void *ctx, const cmt_block_id_t *id, cmt_block_t *b,
                   cmt_state_t *st)
{
    (void)ctx;
    return fake_apply(id, b, st);
}

static int h_switch(void *ctx, const cmt_state_t *st, bool skip_wal)
{
    node_t *n = (node_t *)ctx;

    n->switch_calls++;
    n->switch_height = st->last_block_height;
    n->switch_skip_wal = skip_wal;
    return CMT_OK;
}

/* `top` > 0 makes a serving store over blocks 1..top (X's block KBAD+1
 * is the bad one when `bad`); the store is filled BEFORE the reactor is
 * built, whose :93 check compares it with the state. */
static int node_init(node_t *n, const char *id, const cmt_state_t *state,
                     bool block_sync, int64_t top, bool bad)
{
    cmt_bsync_host_t   h;
    cmt_bsync_limits_t lim;
    int64_t            k;

    memset(n, 0, sizeof(*n));
    snprintf(n->id, CMT_P2P_ID_CAP, "%s", id);
    for (k = 1; k <= top; k++) {
        n->serve[k] = (bad && k == KBAD + 1) ? &g_bad_block : &g_blocks[k];
    }
    n->base = top > 0 ? 1 : 0;
    n->height = top;
    memset(&h, 0, sizeof(h));
    h.ctx = n;
    h.try_send = h_try_send;
    h.send = h_try_send;
    h.broadcast = h_broadcast;
    h.stop_peer_for_error = h_stop;
    h.exec_ctx = n;
    h.bs_base = h_bs_base;
    h.bs_height = h_bs_height;
    h.bs_load_block = h_bs_load_block;
    h.bs_load_block_extended_commit = h_bs_load_ext;
    h.bs_save_block = h_bs_save;
    h.bs_save_block_with_extended_commit = h_bs_save_ext;
    h.ss_load_abci_params = h_abci;
    h.validate_block = h_validate;
    h.apply_verified_block = h_apply;
    h.switch_to_consensus = h_switch;
    h.now = h_now;
    lim.max_txs = 1024;
    lim.max_evidence = 8;
    n->has_reactor = true;
    return cmt_bsync_reactor_init(&n->r, state, block_sync, NULL, 0, &h, &lim);
}

/* A serving node over the honest chain (blocks 1..top), or X's. */
static int serving_node(node_t *n, const char *id, int64_t top, bool bad)
{
    cmt_state_storage_t *stor = (cmt_state_storage_t *)calloc(1, sizeof(*stor));
    cmt_state_t          st;
    int                  rc;

    if (!stor || cmt_state_init(&st, stor) != CMT_OK ||
        cmt_state_copy(&g_genesis, &st) != CMT_OK) {
        free(stor);
        return 1;
    }
    st.last_block_height = top;    /* only :93's check reads it */
    rc = node_init(n, id, &st, false, top, bad);
    free(stor);
    return rc == CMT_OK ? 0 : 1;
}

static void net_connect(node_t *a, node_t *b)
{
    a->peers[a->npeers++] = b;
    b->peers[b->npeers++] = a;
    if (a->has_reactor) (void)cmt_bsync_reactor_add_peer(&a->r, b->id);
    if (b->has_reactor) (void)cmt_bsync_reactor_add_peer(&b->r, a->id);
}

static void net_disconnect(node_t *a, node_t *b)
{
    int i;

    for (i = 0; i < a->npeers; i++) {
        if (a->peers[i] == b) {
            a->peers[i] = a->peers[--a->npeers];
            break;
        }
    }
    for (i = 0; i < b->npeers; i++) {
        if (b->peers[i] == a) {
            b->peers[i] = b->peers[--b->npeers];
            break;
        }
    }
    if (a->has_reactor) cmt_bsync_reactor_remove_peer(&a->r, b->id);
    if (b->has_reactor) cmt_bsync_reactor_remove_peer(&b->r, a->id);
}

/* Deliver everything queued now (FIFO), then the deferred stops. */
static int deliver(node_t **nodes, int n)
{
    size_t end = g_qt;
    int    i;

    while (g_qh < end) {
        qmsg_t *m = &g_q[g_qh++];

        if (peer_of(m->to, m->from->id) != NULL) {     /* link still up */
            if (m->to->has_reactor) {
                if (cmt_bsync_reactor_receive(&m->to->r, m->from->id, m->bytes,
                                              m->len) == CMT_FAULT) {
                    free(m->bytes);
                    return 1;
                }
            } else if (m->to->ninbox < 32) {
                cmt_bsync_msg_t *im = &m->to->inbox[m->to->ninbox];

                cmt_bsync_msg_init(im);
                if (cmt_bsync_msg_unmarshal(m->bytes, m->len, im) == CMT_OK) {
                    /* keep an owned copy of the block view; the bytes
                     * are freed below. The ext-commit view is dropped
                     * (only its presence flag is read). */
                    if (im->has_block && im->block_owned == NULL) {
                        uint8_t *c = (uint8_t *)malloc(im->block_len + 1u);

                        if (c) {
                            memcpy(c, im->block, im->block_len);
                            im->block_owned = c;
                            im->block = c;
                        }
                    }
                    if (im->ext_owned == NULL) {
                        im->ext_commit = NULL;
                    }
                    m->to->ninbox++;
                }
            }
        }
        free(m->bytes);
    }
    if (g_qh == g_qt) {
        g_qh = g_qt = 0;
    }
    for (i = 0; i < n; i++) {
        node_t *nd = nodes[i];

        while (nd->stops_done < nd->nstops) {
            node_t *p = peer_of(nd, nd->stop_id[nd->stops_done]);

            if (p != NULL) {
                net_disconnect(nd, p);
            }
            nd->stops_done++;
        }
    }
    return 0;
}

/* Tick every node and deliver, 1 ms at a time, until `until_ns` or
 * `stop_when` holds. */
static int pump(node_t **nodes, int n, int64_t until_ns,
                bool (*stop_when)(node_t *), node_t *watched)
{
    while (g_now <= until_ns) {
        int i;

        for (i = 0; i < n; i++) {
            if (nodes[i]->has_reactor &&
                cmt_bsync_reactor_tick(&nodes[i]->r, NULL) != CMT_OK) {
                return 1;
            }
        }
        if (deliver(nodes, n) != 0) {
            return 1;
        }
        if (stop_when != NULL && stop_when(watched)) {
            return 0;
        }
        g_now += 1 * MS;
    }
    return 0;
}

static bool switched(node_t *n)
{
    return n->switch_calls > 0;
}

static void node_free(node_t *n)
{
    int i;

    cmt_bsync_reactor_free(&n->r);
    for (i = 0; i < n->ninbox; i++) {
        cmt_bsync_msg_release(&n->inbox[i]);
    }
}

#define ID_A "a000000000000000000000000000000000000000"
#define ID_B "b000000000000000000000000000000000000000"
#define ID_X "c000000000000000000000000000000000000000"
#define ID_P "d000000000000000000000000000000000000000"

/* ══ cases ════════════════════════════════════════════════════════════ */

static int t_serving(void)
{
    static node_t  a, p;
    node_t        *nodes[2] = { &a, &p };
    uint8_t        buf[64];
    size_t         n = 0;
    cmt_bsync_msg_t m;

    CHECK(serving_node(&a, ID_A, NB, false) == 0, "A"); OK();
    memset(&p, 0, sizeof(p));
    snprintf(p.id, CMT_P2P_ID_CAP, "%s", ID_P);
    CHECK(cmt_bsync_reactor_start(&a.r) == CMT_OK, "start A"); OK();
    net_connect(&a, &p);
    CHECK(deliver(nodes, 2) == 0, "deliver"); OK();
    CHECK(p.ninbox == 1 && p.inbox[0].kind == CMT_BSYNC_MSG_STATUS_RESPONSE &&
          p.inbox[0].base == 1 && p.inbox[0].height == NB,
          "AddPeer sends StatusResponse{1, NB} (:190-203)"); OK();

    /* StatusRequest → StatusResponse (:287-295) */
    cmt_bsync_msg_init(&m);
    m.kind = CMT_BSYNC_MSG_STATUS_REQUEST;
    CHECK(cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) == CMT_OK, "marshal"); OK();
    CHECK(cmt_bsync_reactor_receive(&a.r, ID_P, buf, n) == CMT_OK, "receive"); OK();
    CHECK(deliver(nodes, 2) == 0 && p.ninbox == 2 &&
          p.inbox[1].kind == CMT_BSYNC_MSG_STATUS_RESPONSE &&
          p.inbox[1].height == NB, "answered"); OK();

    /* BlockRequest for a missing height → NoBlockResponse (:214-219) */
    cmt_bsync_msg_init(&m);
    m.kind = CMT_BSYNC_MSG_BLOCK_REQUEST;
    m.height = NB + 1;
    CHECK(cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) == CMT_OK, "marshal"); OK();
    CHECK(cmt_bsync_reactor_receive(&a.r, ID_P, buf, n) == CMT_OK, "receive"); OK();
    CHECK(deliver(nodes, 2) == 0 && p.ninbox == 3 &&
          p.inbox[2].kind == CMT_BSYNC_MSG_NO_BLOCK_RESPONSE &&
          p.inbox[2].height == NB + 1, "NoBlockResponse{NB+1}"); OK();

    /* BlockRequest{2} → BlockResponse with block 2, no ext commit */
    m.height = 2;
    CHECK(cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) == CMT_OK, "marshal"); OK();
    CHECK(cmt_bsync_reactor_receive(&a.r, ID_P, buf, n) == CMT_OK, "receive"); OK();
    CHECK(deliver(nodes, 2) == 0 && p.ninbox == 4 &&
          p.inbox[3].kind == CMT_BSYNC_MSG_BLOCK_RESPONSE &&
          p.inbox[3].has_block && !p.inbox[3].has_ext_commit,
          "BlockResponse, ExtCommit nil (:246)"); OK();
    {
        uint8_t *mine = (uint8_t *)malloc(1u << 20);
        size_t   ml = 0;

        CHECK(mine != NULL && cmt_block_marshal(&g_blocks[2], mine, 1u << 20, &ml)
              == CMT_OK, "marshal block 2"); OK();
        CHECK(ml == p.inbox[3].block_len &&
              memcmp(mine, p.inbox[3].block, ml) == 0,
              "the served bytes ARE block 2's ToProto (:236-247)"); OK();
        free(mine);
    }

    /* refusals stop the peer */
    CHECK(cmt_bsync_reactor_receive(&a.r, ID_P, buf, CMT_BSYNC_MAX_MSG_SIZE + 1u)
          == CMT_REJECT && a.nstops == 1 &&
          a.stop_reason[0] == (int)CMT_BSYNC_STOP_OVERSIZE,
          "oversize → stop (:184)"); OK();
    {
        static const uint8_t junk[] = { 0x0c };

        CHECK(cmt_bsync_reactor_receive(&a.r, ID_P, junk, sizeof(junk)) == CMT_REJECT &&
              a.nstops == 2 && a.stop_reason[1] == (int)CMT_BSYNC_STOP_UNDECODABLE,
              "undecodable → stop (peer.go:407-412)"); OK();
    }
    m.height = -1;
    CHECK(cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) == CMT_OK, "marshal"); OK();
    CHECK(cmt_bsync_reactor_receive(&a.r, ID_P, buf, n) == CMT_REJECT &&
          a.nstops == 3 && a.stop_reason[2] == (int)CMT_BSYNC_STOP_INVALID_MSG,
          "negative height → stop (:253-257)"); OK();
    CHECK(deliver(nodes, 2) == 0, "deliver"); OK();
    node_free(&a);
    node_free(&p);
    return 0;
}

static int t_sync_and_switch(void)
{
    static node_t a, b;
    node_t       *nodes[2] = { &a, &b };
    const cmt_state_t *st;
    int64_t       h;

    CHECK(serving_node(&a, ID_A, NB, false) == 0, "A"); OK();
    CHECK(node_init(&b, ID_B, &g_genesis, true, 0, false) == CMT_OK,
          "B (blockSync)"); OK();
    CHECK(cmt_bsync_reactor_start(&a.r) == CMT_OK &&
          cmt_bsync_reactor_start(&b.r) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_reactor_is_syncing(&b.r) && !cmt_bsync_reactor_is_syncing(&a.r),
          "only B runs the poolRoutine (:134-145)"); OK();
    net_connect(&a, &b);
    CHECK(pump(nodes, 2, g_now + 20 * SEC, switched, &b) == 0, "pump"); OK();

    CHECK(b.switch_calls == 1, "SwitchToConsensus once (:429-431)"); OK();
    CHECK(b.switch_height == NB - 1, "at NB−1: NB needs NB+1's commit"); OK();
    CHECK(b.switch_skip_wal, "skipWAL = blocksSynced > 0 (:431)"); OK();
    CHECK(!cmt_bsync_reactor_is_syncing(&b.r) && cmt_bsync_reactor_switched(&b.r),
          "the poolRoutine ended (:437)"); OK();
    CHECK(cmt_bsync_reactor_blocks_synced(&b.r) == (uint64_t)(NB - 1),
          "NB−1 blocks synced"); OK();
    st = cmt_bsync_reactor_state(&b.r);
    CHECK(st->last_block_height == NB - 1 &&
          cmt_block_id_equals(&st->last_block_id, &g_ids[NB - 1]) &&
          st->app_hash_len == CMT_TMHASH_SIZE &&
          memcmp(st->app_hash, g_app_hash_at[NB - 1], CMT_TMHASH_SIZE) == 0,
          "B's state = the chain's state at NB−1"); OK();
    for (h = 1; h <= NB - 1; h++) {
        CHECK(b.saved[h] && memcmp(b.saved_hash[h], g_ids[h].hash, 64) == 0,
              "every stored block is the chain's"); OK();
        CHECK(b.saved_seen_height[h] == h,
              "saved with h+1's LastCommit, a commit FOR h (:544)"); OK();
    }
    CHECK(!b.saved[NB], "NB is not stored"); OK();
    CHECK(b.nstops == 0, "no peer stopped on an honest chain"); OK();

    /* after the switch B keeps SERVING (Receive has no switched branch) */
    {
        cmt_bsync_msg_t m;
        uint8_t         buf[16];
        size_t          n = 0;
        size_t          before;

        cmt_bsync_msg_init(&m);
        m.kind = CMT_BSYNC_MSG_STATUS_REQUEST;
        CHECK(cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) == CMT_OK, "m"); OK();
        before = g_qt;
        CHECK(cmt_bsync_reactor_receive(&b.r, ID_A, buf, n) == CMT_OK &&
              g_qt == before + 1, "B still answers after the switch"); OK();
        CHECK(deliver(nodes, 2) == 0, "deliver"); OK();
    }
    node_free(&a);
    node_free(&b);
    return 0;
}

static int t_bad_commit(void)
{
    static node_t a, b, x;
    node_t       *nodes[3] = { &a, &b, &x };
    const cmt_state_t *st;
    int           i;
    bool          stopped_x = false;

    CHECK(serving_node(&x, ID_X, KBAD + 1, true) == 0, "X (bad KBAD+1)"); OK();
    CHECK(serving_node(&a, ID_A, NB, false) == 0, "A"); OK();
    CHECK(node_init(&b, ID_B, &g_genesis, true, 0, false) == CMT_OK, "B"); OK();
    CHECK(cmt_bsync_reactor_start(&a.r) == CMT_OK &&
          cmt_bsync_reactor_start(&b.r) == CMT_OK &&
          cmt_bsync_reactor_start(&x.r) == CMT_OK, "start"); OK();
    net_connect(&x, &b);
    /* one millisecond at a time until X has been stopped (or 10 s) */
    {
        int64_t end = g_now + 10 * SEC;

        while (g_now <= end && b.nstops == 0) {
            if (pump(nodes, 3, g_now, NULL, NULL) != 0) {   /* +1 ms */
                fprintf(stderr, "pump failed\n");
                return 1;
            }
        }
    }
    for (i = 0; i < b.nstops; i++) {
        if (strcmp(b.stop_id[i], ID_X) == 0 &&
            b.stop_reason[i] == (int)CMT_BSYNC_STOP_VALIDATION) {
            stopped_x = true;
        }
    }
    CHECK(stopped_x, "X stopped with ErrReactorValidation (:522)"); OK();
    CHECK(cmt_bsync_pool_is_peer_banned(cmt_bsync_reactor_pool(&b.r), ID_X, g_now),
          "X banned (pool.go:280)"); OK();
    st = cmt_bsync_reactor_state(&b.r);
    CHECK(st->last_block_height == KBAD - 1,
          "1..KBAD−1 applied, KBAD refused (its successor's commit is bad)"); OK();
    CHECK(!b.saved[KBAD], "KBAD not stored"); OK();
    CHECK(b.switch_calls == 0, "not switched: no peer left"); OK();

    /* an honest peer arrives: B finishes on the honest chain */
    net_connect(&a, &b);
    CHECK(pump(nodes, 3, g_now + 30 * SEC, switched, &b) == 0, "pump"); OK();
    CHECK(b.switch_calls == 1 && b.switch_height == NB - 1, "switched at NB−1"); OK();
    st = cmt_bsync_reactor_state(&b.r);
    CHECK(cmt_block_id_equals(&st->last_block_id, &g_ids[NB - 1]) &&
          memcmp(st->app_hash, g_app_hash_at[NB - 1], CMT_TMHASH_SIZE) == 0,
          "the honest chain's state"); OK();
    CHECK(b.saved[KBAD] && memcmp(b.saved_hash[KBAD], g_ids[KBAD].hash, 64) == 0,
          "KBAD stored — the honest one, from A"); OK();
    node_free(&a);
    node_free(&b);
    node_free(&x);
    return 0;
}

typedef struct {
    const char *name;
    int (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "serving + boundary refusals (reactor.go:190-305)",  t_serving },
        { "two-store sync + SwitchToConsensus (:318-572)",     t_sync_and_switch },
        { "bad commit → stop + ban + redo (:515-531)",         t_bad_commit },
    };
    size_t i;
    size_t failed = 0u;

    if (build_chain() != 0) {
        fprintf(stderr, "FAIL building the chain fixture\n");
        return 1;
    }
    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            failed++;
        } else {
            printf("ok   %s\n", cases[i].name);
        }
    }
    printf("%d checks, %zu case(s) failed\n", g_checks, failed);
    free(g_vscratch);
    free(g_bscratch);
    free(g_genesis_stor);
    free(g_chain_stor);
    return failed == 0u ? 0 : 1;
}
