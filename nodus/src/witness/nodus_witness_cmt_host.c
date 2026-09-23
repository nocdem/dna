/**
 * @file nodus_witness_cmt_host.c
 * @brief cometbft @709fd12b state/execution.go + state/validation.go as
 *        the host behind cmt_cs_host_t. Contract and every file:line:
 *        nodus_witness_cmt_host.h.
 */

#include "witness/nodus_witness_cmt_host.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#include "dnac/cmt_validation.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_part_set.h"

#define LOG_TAG "W_CMTHOST"

/* ═══════════════════════════════════════════════════════════════════════
 * The two empty collaborators (the reference's own)
 * ═══════════════════════════════════════════════════════════════════════ */

/* mempool/nop_mempool.go:36 ReapMaxBytesMaxGas → nil */
static int nop_reap(void *ctx, int64_t max_bytes, int64_t max_gas,
                    cmt_pb_bytes_t *out, size_t out_cap, size_t *out_len)
{
    (void)ctx; (void)max_bytes; (void)max_gas; (void)out; (void)out_cap;
    if (out_len) {
        *out_len = 0;
    }
    return CMT_OK;
}

static void nop_lock(void *ctx) { (void)ctx; }     /* :45 */
static void nop_unlock(void *ctx) { (void)ctx; }   /* :48 */

/* :51-59 Update → nil */
static int nop_update(void *ctx, int64_t height, const cmt_pb_bytes_t *txs,
                      size_t txs_len,
                      const cmt_pb_stored_exec_tx_result_t *tx_results,
                      size_t tx_results_len, nodus_cmt_pre_check_t pre,
                      nodus_cmt_post_check_t post)
{
    (void)ctx; (void)height; (void)txs; (void)txs_len; (void)tx_results;
    (void)tx_results_len; (void)pre; (void)post;
    return CMT_OK;
}

static int nop_flush_app_conn(void *ctx) { (void)ctx; return CMT_OK; }  /* :62 */

const nodus_cmt_mempool_if_t nodus_cmt_nop_mempool = {
    NULL, nop_reap, nop_lock, nop_unlock, nop_update, nop_flush_app_conn
};

/* state/services.go:59-61 PendingEvidence → nil, 0 */
static int empty_pending_evidence(void *ctx, int64_t max_bytes,
                                  cmt_pb_evidence_t *out, size_t out_cap,
                                  size_t *out_len, int64_t *out_size)
{
    (void)ctx; (void)max_bytes; (void)out; (void)out_cap;
    if (out_len) {
        *out_len = 0;
    }
    if (out_size) {
        *out_size = 0;
    }
    return CMT_OK;
}

static int empty_add_evidence(void *ctx, const cmt_pb_evidence_t *ev)   /* :62 */
{
    (void)ctx; (void)ev;
    return CMT_OK;
}

static int empty_update(void *ctx, const cmt_state_t *state,
                        const cmt_pb_evidence_t *evl, size_t evl_len)   /* :63 */
{
    (void)ctx; (void)state; (void)evl; (void)evl_len;
    return CMT_OK;
}

static int empty_check_evidence(void *ctx, const cmt_pb_evidence_t *evl,
                                size_t evl_len)                          /* :64 */
{
    (void)ctx; (void)evl; (void)evl_len;
    return CMT_OK;
}

static int empty_report_conflicting_votes(void *ctx, const cmt_vote_t *a,
                                          const cmt_vote_t *b)           /* :65 */
{
    (void)ctx; (void)a; (void)b;
    return CMT_OK;
}

const nodus_cmt_evpool_if_t nodus_cmt_empty_evpool = {
    NULL, empty_pending_evidence, empty_add_evidence, empty_update,
    empty_check_evidence, empty_report_conflicting_votes
};

/* ═══════════════════════════════════════════════════════════════════════
 * Small ports from other files (header: "PORTED HERE")
 * ═══════════════════════════════════════════════════════════════════════ */

/* types/tx.go:188-192 ComputeProtoSizeForTxs([]Tx{tx}) — the size of
 * Data{Txs: [tx]}: one field-1 tag, the length varint, the bytes. */
int64_t nodus_cmt_compute_proto_size_for_tx(size_t tx_len)
{
    return (int64_t)(1u + cmt_pb_uvarint_size((uint64_t)tx_len) + tx_len);
}

/* types/tx.go:107-116 Txs.Validate */
int nodus_cmt_txs_validate(const cmt_pb_bytes_t *txs, size_t n,
                           int64_t max_size_bytes)
{
    int64_t size = 0;
    size_t  i;

    if (n != 0 && txs == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {
        size += nodus_cmt_compute_proto_size_for_tx(txs[i].len);   /* :110 */
        if (size > max_size_bytes) {                                /* :111 */
            QGP_LOG_ERROR(LOG_TAG, "transaction data size exceeds maximum %"
                          PRId64, max_size_bytes);
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* state/tx_filter.go:10-20 TxPreCheck */
int nodus_cmt_tx_pre_check(const cmt_state_t *state, nodus_cmt_pre_check_t *out)
{
    int64_t max_bytes, max_data_bytes = 0;

    if (!state || !out) {
        return CMT_FAULT;
    }
    max_bytes = state->consensus_params.block.max_bytes;             /* :11 */
    if (max_bytes == -1) {                                            /* :12-14 */
        max_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;
    }
    if (cmt_max_data_bytes_no_evidence(max_bytes,
                                       (int64_t)state->validators.validators_len,
                                       &max_data_bytes) != CMT_OK) {  /* :15-18 */
        return CMT_FAULT;                 /* the reference's panic */
    }
    out->max_bytes = max_data_bytes;                                  /* :19 */
    return CMT_OK;
}

/* state/tx_filter.go:24-26 TxPostCheck */
nodus_cmt_post_check_t nodus_cmt_tx_post_check(const cmt_state_t *state)
{
    nodus_cmt_post_check_t p;

    p.max_gas = state ? state->consensus_params.block.max_gas : 0;   /* :25 */
    return p;
}

/* types/protobuf.go:43-48 TM2PB.Validator — the address RE-DERIVED from
 * the key (:45 `val.PubKey.Address()`), not copied from the struct. */
static int tm2pb_validator(const cmt_validator_t *val, nodus_abci_validator_t *out)
{
    if (cmt_pub_key_address(&val->pub_key, out->address) != CMT_OK) {
        return CMT_FAULT;
    }
    out->address_len = CMT_PB_ADDRESS_MAX;
    out->power = val->voting_power;                                  /* :46 */
    return CMT_OK;
}

/* crypto/encoding/codec.go:42-63 PubKeyFromProto — the ML-DSA-87 branch
 * (K-2) is `present`; the nil oneof is the default case's error (:61). */
static int pub_key_from_proto(const cmt_pb_public_key_t *k)
{
    return k->present ? CMT_OK : CMT_REJECT;
}

/* execution.go:567-591 validateValidatorUpdates */
int nodus_cmt_validate_validator_updates(const cmt_pb_validator_update_t *updates,
                                         size_t n,
                                         const cmt_validator_params_t *params)
{
    size_t i;

    if ((n != 0 && updates == NULL) || params == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {
        const cmt_pb_validator_update_t *u = &updates[i];

        if (u->power < 0) {                                          /* :570-571 */
            QGP_LOG_ERROR(LOG_TAG, "voting power can't be negative %" PRId64,
                          u->power);
            return CMT_REJECT;
        } else if (u->power == 0) {                                  /* :572-575 */
            continue;
        }
        if (pub_key_from_proto(&u->pub_key) != CMT_OK) {             /* :578-581 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "fromproto: key type <nil> is not "
                          "supported");
            return CMT_REJECT;
        }
        if (!cmt_is_valid_pubkey_type(params, CMT_PUBKEY_TYPE_MLDSA87_NAME)) {
            QGP_LOG_ERROR(LOG_TAG, "validator is using pubkey %s, which is "
                          "unsupported for consensus",
                          CMT_PUBKEY_TYPE_MLDSA87_NAME);              /* :583-586 */
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* types/protobuf.go:103-113 PB2TM.ValidatorUpdates */
int nodus_cmt_pb2tm_validator_updates(const cmt_pb_validator_update_t *updates,
                                      size_t n, cmt_validator_t *out,
                                      size_t out_cap)
{
    size_t i;

    if ((n != 0 && (updates == NULL || out == NULL))) {
        return CMT_FAULT;
    }
    if (n > out_cap) {
        return CMT_REJECT;                /* capacity */
    }
    for (i = 0; i < n; i++) {
        if (pub_key_from_proto(&updates[i].pub_key) != CMT_OK) {    /* :106-109 */
            return CMT_REJECT;
        }
        if (cmt_validator_new(&updates[i].pub_key, updates[i].power, &out[i])
            != CMT_OK) {                                             /* :110 */
            return CMT_FAULT;
        }
    }
    return CMT_OK;
}

/* types/evidence.go:483-489 EvidenceList.ToABCI, each item through
 * DuplicateVoteEvidence.ABCI (:81-92). */
int nodus_cmt_evidence_to_abci(nodus_cmt_blockexec_t *ctx,
                               const cmt_evidence_data_t *ev,
                               const nodus_abci_misbehavior_t **out,
                               size_t *out_len)
{
    size_t i;

    if (!ctx || !ev || !out || !out_len) {
        return CMT_FAULT;
    }
    if (ev->evidence_len > ctx->limits.max_evidence) {
        return CMT_REJECT;
    }
    for (i = 0; i < ev->evidence_len; i++) {
        const cmt_pb_evidence_t *e = &ev->evidence[i];
        const cmt_pb_duplicate_vote_evidence_t *dve;
        nodus_abci_misbehavior_t *m = &ctx->misbehavior[i];

        if (!e->has_duplicate_vote_evidence) {
            return CMT_FAULT;             /* the decoder admits no other */
        }
        dve = &e->duplicate_vote_evidence;
        if (!dve->has_vote_a) {
            return CMT_FAULT;             /* :86 nil VoteA dereference */
        }
        memset(m, 0, sizeof(*m));
        m->type = NODUS_ABCI_MISBEHAVIOR_DUPLICATE_VOTE;             /* :83 */
        memcpy(m->validator.address, dve->vote_a.validator_address,
               dve->vote_a.validator_address_len);                   /* :85 */
        m->validator.address_len = dve->vote_a.validator_address_len;
        m->validator.power = dve->validator_power;                   /* :86 */
        m->height = dve->vote_a.height;                              /* :89 */
        m->time = dve->timestamp;                                    /* :90 */
        m->total_voting_power = dve->total_voting_power;             /* :91 */
    }
    *out = ev->evidence_len ? ctx->misbehavior : NULL;
    *out_len = ev->evidence_len;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * init / release / slot lookup
 * ═══════════════════════════════════════════════════════════════════════ */

static void slot_free(nodus_cmt_slot_storage_t *s)
{
    free(s->dec.txs);
    free(s->dec.pb_evidence);
    free(s->dec.pb_sigs);
    free(s->dec.evidence);
    free(s->dec.sigs);
    free(s->arena.buf);
    memset(s, 0, sizeof(*s));
}

void nodus_cmt_blockexec_release(nodus_cmt_blockexec_t *ctx)
{
    int k;

    if (!ctx) {
        return;
    }
    for (k = 0; k < CMT_CS_BLOCK_SLOTS; k++) {
        slot_free(&ctx->slot[k]);
    }
    free(ctx->state_storage);
    free(ctx->valset_scratch);
    free(ctx->block_scratch);
    free(ctx->vals_a);
    free(ctx->vals_b);
    free(ctx->changes);
    free(ctx->votes);
    free(ctx->ext_votes);
    free(ctx->misbehavior);
    free(ctx->reap_txs);
    free(ctx->reap_arena.buf);
    free(ctx->tmp_block);
    free(ctx->commit_sigs);
    free(ctx->seen_sigs);
    free(ctx->ext_sigs);
    free(ctx->ext_load_arena.buf);
    free(ctx->tocommit_sigs);
    free(ctx->marshal_scratch);
    /* delta 3, item B: det_results/results/leaf_scratch/items are no
     * longer ctx fields — nodus_cmt_update_state allocates and frees
     * them per apply, locally. Nothing to release here. */
    free(ctx->valset_hash_scratch);
    free(ctx->valset_items);
    memset(ctx, 0, sizeof(*ctx));
}

int nodus_cmt_blockexec_set_wal(nodus_cmt_blockexec_t *ctx,
                                nodus_cmt_wal_t *wal)
{
    if (!ctx) {
        return CMT_FAULT;
    }
    ctx->wal = wal;
    return CMT_OK;
}

static int slot_alloc(nodus_cmt_slot_storage_t *s,
                      const nodus_cmt_host_limits_t *lim)
{
    memset(s, 0, sizeof(*s));
    s->dec.txs = (cmt_pb_bytes_t *)calloc(lim->max_txs ? lim->max_txs : 1,
                                          sizeof(cmt_pb_bytes_t));
    s->dec.txs_cap = lim->max_txs;
    s->dec.pb_evidence = (cmt_pb_evidence_t *)
        calloc(lim->max_evidence ? lim->max_evidence : 1, sizeof(cmt_pb_evidence_t));
    s->dec.pb_evidence_cap = lim->max_evidence;
    s->dec.pb_sigs = (cmt_commit_sig_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    s->dec.pb_sigs_cap = CMT_VALSET_MAX;
    s->dec.evidence = (cmt_pb_evidence_t *)
        calloc(lim->max_evidence ? lim->max_evidence : 1, sizeof(cmt_pb_evidence_t));
    s->dec.evidence_cap = lim->max_evidence;
    s->dec.sigs = (cmt_commit_sig_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    s->dec.sigs_cap = CMT_VALSET_MAX;
    s->arena.buf = (uint8_t *)malloc(lim->tx_arena_cap ? lim->tx_arena_cap : 1);
    s->arena.cap = lim->tx_arena_cap;
    s->arena.used = 0;
    s->dec.arena = &s->arena;
    if (!s->dec.txs || !s->dec.pb_evidence || !s->dec.pb_sigs ||
        !s->dec.evidence || !s->dec.sigs || !s->arena.buf) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_blockexec_init(nodus_cmt_blockexec_t *ctx,
                             nodus_cmt_store_t *store,
                             nodus_cmt_app_t *app,
                             nodus_cmt_mempool_if_t *mempool,
                             nodus_cmt_evpool_if_t *evpool,
                             nodus_cmt_wal_t *wal,
                             cmt_file_pv_t *pv,
                             cmt_now_fn now, void *now_ctx,
                             cmt_cs_slots_t *slots,
                             cmt_pb_arena_t *ext_arena[2],
                             const nodus_cmt_host_limits_t *limits)
{
    int k;
    size_t n_changes = CMT_VALSET_MAX_CHANGES;

    if (!ctx || !store || !app || !mempool || !evpool || !now || !limits) {
        return CMT_FAULT;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->store = store;                                              /* :70 */
    ctx->app = app;                                                  /* :71 */
    ctx->mempool = mempool;                                          /* :73 */
    ctx->evpool = evpool;                                            /* :74 */
    ctx->wal = wal;
    ctx->pv = pv;
    ctx->now = now;
    ctx->now_ctx = now_ctx;
    ctx->slots = slots;
    /* PACKAGE W4-X (register R3-W3-C2e-4): a plain NULL means "no arenas
     * at all" (the replay handshaker's throwaway executor, hs_exec_open,
     * node.c — extend_vote is never reached on that path); a non-NULL
     * pointer names both halves. */
    if (ext_arena != NULL) {
        ctx->ext_arena[0] = ext_arena[0];
        ctx->ext_arena[1] = ext_arena[1];
    } else {
        ctx->ext_arena[0] = NULL;
        ctx->ext_arena[1] = NULL;
    }
    ctx->limits = *limits;

    for (k = 0; k < CMT_CS_BLOCK_SLOTS; k++) {
        if (slot_alloc(&ctx->slot[k], limits) != CMT_OK) {
            nodus_cmt_blockexec_release(ctx);
            return CMT_FAULT;
        }
    }
    ctx->state_storage = (cmt_state_storage_t *)calloc(1, sizeof(cmt_state_storage_t));
    ctx->valset_scratch = (cmt_valset_scratch_t *)calloc(1, sizeof(cmt_valset_scratch_t));
    ctx->block_scratch = (cmt_state_block_scratch_t *)
        calloc(1, sizeof(cmt_state_block_scratch_t));
    ctx->vals_a = (cmt_validator_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_validator_t));
    ctx->vals_b = (cmt_validator_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_validator_t));
    ctx->changes = (cmt_validator_t *)calloc(n_changes, sizeof(cmt_validator_t));
    ctx->votes = (nodus_abci_vote_info_t *)
        calloc(CMT_VALSET_MAX, sizeof(nodus_abci_vote_info_t));
    ctx->ext_votes = (nodus_abci_extended_vote_info_t *)
        calloc(CMT_VALSET_MAX, sizeof(nodus_abci_extended_vote_info_t));
    ctx->misbehavior = (nodus_abci_misbehavior_t *)
        calloc(limits->max_evidence ? limits->max_evidence : 1,
               sizeof(nodus_abci_misbehavior_t));
    ctx->reap_txs = (cmt_pb_bytes_t *)
        calloc(limits->max_txs ? limits->max_txs : 1, sizeof(cmt_pb_bytes_t));
    ctx->reap_arena.buf = (uint8_t *)malloc(limits->tx_arena_cap ? limits->tx_arena_cap : 1);
    ctx->reap_arena.cap = limits->tx_arena_cap;
    ctx->tmp_block = (cmt_block_t *)calloc(1, sizeof(cmt_block_t));
    ctx->commit_sigs = (cmt_commit_sig_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    ctx->seen_sigs = (cmt_commit_sig_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    ctx->ext_sigs = (cmt_extended_commit_sig_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_extended_commit_sig_t));
    ctx->ext_load_arena.cap = (size_t)CMT_VALSET_MAX * 4096u;
    ctx->ext_load_arena.buf = (uint8_t *)malloc(ctx->ext_load_arena.cap);
    ctx->tocommit_sigs = (cmt_commit_sig_t *)calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    ctx->marshal_scratch_cap = (size_t)CMT_MAX_BLOCK_SIZE_BYTES;
    ctx->marshal_scratch = (uint8_t *)malloc(ctx->marshal_scratch_cap);
    /* delta 3, item B: det_results/results/leaf_scratch/items dropped
     * from this init — nodus_cmt_update_state now allocates them per
     * apply, sized to that apply's own item count. Nothing to allocate
     * here. */
    ctx->valset_hash_scratch = (uint8_t *)
        malloc((size_t)CMT_VALSET_MAX * (size_t)CMT_VALIDATOR_BYTES_MAX);
    ctx->valset_items = (cmt_merkle_item_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_merkle_item_t));

    if (!ctx->state_storage || !ctx->valset_scratch || !ctx->block_scratch ||
        !ctx->vals_a || !ctx->vals_b || !ctx->changes || !ctx->votes ||
        !ctx->ext_votes || !ctx->misbehavior || !ctx->reap_txs ||
        !ctx->reap_arena.buf || !ctx->tmp_block || !ctx->commit_sigs ||
        !ctx->seen_sigs || !ctx->ext_sigs || !ctx->ext_load_arena.buf ||
        !ctx->tocommit_sigs || !ctx->marshal_scratch ||
        !ctx->valset_hash_scratch || !ctx->valset_items) {
        nodus_cmt_blockexec_release(ctx);
        return CMT_FAULT;
    }
    if (cmt_state_init(&ctx->state_scratch, ctx->state_storage) != CMT_OK) {
        nodus_cmt_blockexec_release(ctx);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* Which slot a block pointer is — pointer identity against the slots. */
static nodus_cmt_slot_storage_t *slot_of(nodus_cmt_blockexec_t *ctx,
                                         const cmt_block_t *b)
{
    int k;

    if (!ctx->slots || !b) {
        return NULL;
    }
    for (k = 0; k < CMT_CS_BLOCK_SLOTS; k++) {
        if (b == &ctx->slots->blocks[k]) {
            return &ctx->slot[k];
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════
 * CommitInfo / ExtendedCommitInfo builders (execution.go:432-565)
 * ═══════════════════════════════════════════════════════════════════════ */

/* :450-483 BuildLastCommitInfo */
int nodus_cmt_build_last_commit_info(nodus_cmt_blockexec_t *ctx,
                                     const cmt_block_t *block,
                                     const cmt_validator_set_t *last_val_set,
                                     int64_t initial_height,
                                     nodus_abci_commit_info_t *out)
{
    size_t commit_size, val_set_len, i;

    if (!ctx || !block || !last_val_set || !out) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    if (block->header.height == initial_height) {                    /* :451-455 */
        return CMT_OK;
    }
    commit_size = cmt_commit_size(block->last_commit);               /* :458 */
    val_set_len = last_val_set->validators_len;                      /* :459 */
    if (commit_size != val_set_len) {                                /* :464-469 */
        QGP_LOG_ERROR(LOG_TAG, "commit size (%zu) doesn't match validator set "
                      "length (%zu) at height %" PRId64, commit_size,
                      val_set_len, block->header.height);
        return CMT_FAULT;                 /* panic */
    }
    for (i = 0; i < val_set_len; i++) {                              /* :472-478 */
        const cmt_commit_sig_t *sig = &block->last_commit->signatures[i];

        if (tm2pb_validator(&last_val_set->validators[i],
                            &ctx->votes[i].validator) != CMT_OK) {
            return CMT_FAULT;
        }
        ctx->votes[i].block_id_flag = sig->block_id_flag;
    }
    out->round = block->last_commit->round;                          /* :481 */
    out->votes = val_set_len ? ctx->votes : NULL;
    out->votes_len = val_set_len;
    return CMT_OK;
}

/* :432-448 buildLastCommitInfoFromStore — LoadValidators(height-1) into
 * ctx->vals_a; a load error is the panic at :445. */
static int build_last_commit_info_from_store(nodus_cmt_blockexec_t *ctx,
                                             const cmt_block_t *block,
                                             int64_t initial_height,
                                             nodus_abci_commit_info_t *out)
{
    cmt_validator_set_t last_val_set;

    memset(out, 0, sizeof(*out));
    if (block->header.height == initial_height) {                    /* :433-437 */
        return CMT_OK;
    }
    if (cmt_validator_set_init(&last_val_set, ctx->vals_a, CMT_VALSET_MAX)
        != CMT_OK) {
        return CMT_FAULT;
    }
    if (nodus_cmt_ss_load_validators(ctx->store, block->header.height - 1,
                                     &last_val_set) != CMT_OK) {     /* :439 */
        QGP_LOG_ERROR(LOG_TAG, "failed to load validator set at height %" PRId64,
                      block->header.height - 1);
        return CMT_FAULT;                                            /* :441 panic */
    }
    return nodus_cmt_build_last_commit_info(ctx, block, &last_val_set,
                                            initial_height, out);    /* :444 */
}

/* :512-565 BuildExtendedCommitInfo */
int nodus_cmt_build_extended_commit_info(nodus_cmt_blockexec_t *ctx,
                                         const cmt_extended_commit_t *ec,
                                         const cmt_validator_set_t *val_set,
                                         int64_t initial_height,
                                         cmt_abci_params_t ap,
                                         nodus_abci_extended_commit_info_t *out)
{
    size_t ec_size, val_set_len, i;
    bool   enabled = false;

    if (!ctx || !ec || !val_set || !out) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    if (ec->height < initial_height) {                               /* :513-516 */
        return CMT_OK;
    }
    ec_size = cmt_extended_commit_size(ec);                          /* :519 */
    val_set_len = val_set->validators_len;                           /* :520 */
    if (ec_size != val_set_len) {                                    /* :525-530 */
        QGP_LOG_ERROR(LOG_TAG, "extended commit size (%zu) does not match "
                      "validator set length (%zu) at height %" PRId64,
                      ec_size, val_set_len, ec->height);
        return CMT_FAULT;                 /* panic */
    }
    if (cmt_abci_params_vote_extensions_enabled(ap, ec->height, &enabled)
        != CMT_OK) {                                                 /* :551 */
        return CMT_FAULT;
    }
    for (i = 0; i < val_set_len; i++) {                              /* :533-561 */
        const cmt_extended_commit_sig_t *ecs = &ec->extended_signatures[i];
        const cmt_validator_t *val = &val_set->validators[i];
        nodus_abci_extended_vote_info_t *v = &ctx->ext_votes[i];

        if (ecs->commit_sig.block_id_flag != CMT_PB_BLOCK_ID_FLAG_ABSENT &&
            (ecs->commit_sig.validator_address_len != val->address_len ||
             memcmp(ecs->commit_sig.validator_address, val->address,
                    val->address_len) != 0)) {                       /* :538-542 */
            QGP_LOG_ERROR(LOG_TAG, "validator address of extended commit "
                          "signature in position %zu does not match the "
                          "corresponding validator's at height %" PRId64,
                          i, ec->height);
            return CMT_FAULT;             /* panic */
        }
        if (cmt_ecs_ensure_extension(ecs, enabled) != CMT_OK) {      /* :551-553 */
            QGP_LOG_ERROR(LOG_TAG, "commit at height %" PRId64 " has problems "
                          "with vote extension data", ec->height);
            return CMT_FAULT;             /* panic */
        }
        memset(v, 0, sizeof(*v));
        if (tm2pb_validator(val, &v->validator) != CMT_OK) {         /* :556 */
            return CMT_FAULT;
        }
        v->block_id_flag = ecs->commit_sig.block_id_flag;            /* :557 */
        v->vote_extension = ecs->extension;                          /* :558 */
        v->extension_signature.data = ecs->extension_signature;      /* :559 */
        v->extension_signature.len = ecs->extension_signature_len;
    }
    out->round = ec->round;                                          /* :563 */
    out->votes = val_set_len ? ctx->ext_votes : NULL;
    out->votes_len = val_set_len;
    return CMT_OK;
}

/* :495-510 buildExtendedCommitInfoFromStore */
static int build_extended_commit_info_from_store(nodus_cmt_blockexec_t *ctx,
                                                 const cmt_extended_commit_t *ec,
                                                 int64_t initial_height,
                                                 cmt_abci_params_t ap,
                                                 nodus_abci_extended_commit_info_t *out)
{
    cmt_validator_set_t val_set;

    memset(out, 0, sizeof(*out));
    if (ec->height < initial_height) {                               /* :496-499 */
        return CMT_OK;
    }
    if (cmt_validator_set_init(&val_set, ctx->vals_a, CMT_VALSET_MAX) != CMT_OK) {
        return CMT_FAULT;
    }
    if (nodus_cmt_ss_load_validators(ctx->store, ec->height, &val_set)
        != CMT_OK) {                                                 /* :501 */
        QGP_LOG_ERROR(LOG_TAG, "failed to load validator set at height %" PRId64
                      ", initial height %" PRId64, ec->height, initial_height);
        return CMT_FAULT;                                            /* :503 panic */
    }
    return nodus_cmt_build_extended_commit_info(ctx, ec, &val_set,
                                                initial_height, ap, out); /* :506 */
}

/* The block fields every request carries (hash / height / time /
 * next_validators_hash / proposer_address), from a block whose header
 * hash may be nil. */
static int block_hash_of(cmt_block_t *block, uint8_t out[CMT_PB_HASH_MAX],
                         size_t *out_len)
{
    int rc = cmt_block_hash(block, out);

    if (rc == CMT_OK) {
        *out_len = CMT_TMHASH_SIZE;
        return CMT_OK;
    }
    if (rc == CMT_HASH_NIL) {
        *out_len = 0;
        return CMT_OK;
    }
    return CMT_FAULT;
}

/* ═══════════════════════════════════════════════════════════════════════
 * CreateProposalBlock — execution.go:101-160
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_host_create_proposal_block(void *vctx, int64_t height,
                                         const cmt_state_t *state,
                                         const cmt_extended_commit_t *last_ext_commit,
                                         const uint8_t *proposer_addr,
                                         size_t proposer_addr_len,
                                         cmt_block_t *out)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    nodus_cmt_slot_storage_t *slot;
    int64_t max_bytes, max_gas, ev_size = 0, max_data_bytes = 0, max_reap_bytes;
    bool    empty_max_bytes;
    size_t  n_ev = 0, n_txs = 0, i;
    cmt_data_t          data;
    cmt_evidence_data_t evidence;
    nodus_abci_request_prepare_proposal_t  req;
    nodus_abci_response_prepare_proposal_t resp;
    int rc;

    if (!ctx || !state || !last_ext_commit || !out) {
        return CMT_FAULT;
    }
    slot = slot_of(ctx, out);
    if (!slot) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "create_proposal_block: out is not a slot");
        return CMT_FAULT;
    }

    max_bytes = state->consensus_params.block.max_bytes;             /* :109 */
    empty_max_bytes = (max_bytes == -1);                             /* :110 */
    if (empty_max_bytes) {
        max_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;               /* :112 */
    }
    max_gas = state->consensus_params.block.max_gas;                 /* :115 */

    /* :117 evpool.PendingEvidence(MaxBytes) → the slot's evidence array */
    rc = ctx->evpool->pending_evidence(ctx->evpool->ctx,
                                       state->consensus_params.evidence.max_bytes,
                                       slot->dec.evidence, slot->dec.evidence_cap,
                                       &n_ev, &ev_size);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    memset(&evidence, 0, sizeof(evidence));
    evidence.evidence = slot->dec.evidence;
    evidence.evidence_cap = slot->dec.evidence_cap;
    evidence.evidence_len = n_ev;
    evidence.byte_size = 0;               /* the lazy cache, unset (:1390) */

    /* :120 types.MaxDataBytes — the reference PANICS on a negative result */
    if (cmt_max_data_bytes(max_bytes, ev_size,
                           (int64_t)state->validators.validators_len,
                           &max_data_bytes) != CMT_OK) {
        return CMT_FAULT;
    }
    max_reap_bytes = max_data_bytes;                                 /* :121 */
    if (empty_max_bytes) {
        max_reap_bytes = -1;                                         /* :123 */
    }

    /* :126 mempool.ReapMaxBytesMaxGas → copied into reap_arena */
    rc = ctx->mempool->reap_max_bytes_max_gas(ctx->mempool->ctx, max_reap_bytes,
                                              max_gas, ctx->reap_txs,
                                              ctx->limits.max_txs, &n_txs);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    ctx->reap_arena.used = 0;
    for (i = 0; i < n_txs; i++) {
        cmt_pb_bytes_t *t = &ctx->reap_txs[i];

        if (t->len > ctx->reap_arena.cap - ctx->reap_arena.used) {
            return CMT_FAULT;             /* capacity */
        }
        if (t->len) {
            memcpy(ctx->reap_arena.buf + ctx->reap_arena.used, t->data, t->len);
            t->data = ctx->reap_arena.buf + ctx->reap_arena.used;
            ctx->reap_arena.used += t->len;
        } else {
            t->data = NULL;
        }
    }

    /* :127 commit := lastExtCommit.ToCommit() → the slot's LastCommit */
    memset(&slot->dec.last_commit, 0, sizeof(slot->dec.last_commit));
    if (cmt_extended_commit_to_commit(last_ext_commit, slot->dec.sigs,
                                      slot->dec.sigs_cap,
                                      &slot->dec.last_commit) != CMT_OK) {
        return CMT_FAULT;
    }

    /* :128 the FIRST MakeBlock, on the reaped txs, into tmp_block */
    memset(&data, 0, sizeof(data));
    data.txs = ctx->reap_txs;
    data.txs_cap = ctx->limits.max_txs;
    data.txs_len = n_txs;
    rc = cmt_state_make_block(state, height, &data, &slot->dec.last_commit,
                              &evidence, proposer_addr, proposer_addr_len,
                              ctx->block_scratch, ctx->tmp_block);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }

    /* :129-141 RequestPrepareProposal */
    memset(&req, 0, sizeof(req));
    req.max_tx_bytes = max_data_bytes;                               /* :132 */
    req.txs = ctx->tmp_block->data.txs;                              /* :133 */
    req.txs_len = ctx->tmp_block->data.txs_len;
    rc = build_extended_commit_info_from_store(ctx, last_ext_commit,
                                               state->initial_height,
                                               state->consensus_params.abci,
                                               &req.local_last_commit); /* :134 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_evidence_to_abci(ctx, &ctx->tmp_block->evidence,
                                    &req.misbehavior, &req.misbehavior_len); /* :135 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    req.height = ctx->tmp_block->header.height;                      /* :136 */
    req.time = ctx->tmp_block->header.time;                          /* :137 */
    memcpy(req.next_validators_hash, ctx->tmp_block->header.next_validators_hash,
           ctx->tmp_block->header.next_validators_hash_len);         /* :138 */
    req.next_validators_hash_len = ctx->tmp_block->header.next_validators_hash_len;
    memcpy(req.proposer_address, ctx->tmp_block->header.proposer_address,
           ctx->tmp_block->header.proposer_address_len);             /* :139 */
    req.proposer_address_len = ctx->tmp_block->header.proposer_address_len;

    memset(&resp, 0, sizeof(resp));
    rc = ctx->app->prepare_proposal(ctx->app->ctx, &req, &resp);    /* :129 */
    if (rc != CMT_OK) {                                              /* :143-153 */
        QGP_LOG_ERROR(LOG_TAG, "PrepareProposal failed (rc %d)", rc);
        return CMT_FAULT;                 /* state.go:1309-1311 panics */
    }

    /* :155-158 txl := ToTxs(rpp.Txs); txl.Validate(maxDataBytes) */
    if (nodus_cmt_txs_validate(resp.txs, resp.txs_len, max_data_bytes) != CMT_OK) {
        return CMT_FAULT;                 /* :157 → state.go:1309-1311 */
    }
    if (resp.txs_len > slot->dec.txs_cap) {
        return CMT_FAULT;                 /* capacity */
    }
    slot->arena.used = 0;
    for (i = 0; i < resp.txs_len; i++) {
        const cmt_pb_bytes_t *t = &resp.txs[i];

        if (t->len > slot->arena.cap - slot->arena.used) {
            return CMT_FAULT;             /* capacity */
        }
        if (t->len) {
            memcpy(slot->arena.buf + slot->arena.used, t->data, t->len);
            slot->dec.txs[i].data = slot->arena.buf + slot->arena.used;
            slot->arena.used += t->len;
        } else {
            slot->dec.txs[i].data = NULL;
        }
        slot->dec.txs[i].len = t->len;
    }
    memset(&data, 0, sizeof(data));
    data.txs = slot->dec.txs;
    data.txs_cap = slot->dec.txs_cap;
    data.txs_len = resp.txs_len;

    /* :159 the SECOND MakeBlock, into the slot */
    rc = cmt_state_make_block(state, height, &data, &slot->dec.last_commit,
                              &evidence, proposer_addr, proposer_addr_len,
                              ctx->block_scratch, out);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ProcessProposal — execution.go:162-188
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_host_process_proposal(void *vctx, cmt_block_t *block,
                                    const cmt_state_t *state, bool *out_accept)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    nodus_abci_request_process_proposal_t  req;
    nodus_abci_response_process_proposal_t resp;
    int rc;

    if (!ctx || !block || !state || !out_accept) {
        return CMT_FAULT;
    }
    *out_accept = false;
    memset(&req, 0, sizeof(req));
    if (cmt_header_hash(&block->header, req.hash) == CMT_OK) {      /* :167 */
        req.hash_len = CMT_TMHASH_SIZE;
    }
    req.height = block->header.height;                               /* :168 */
    req.time = block->header.time;                                   /* :169 */
    req.txs = block->data.txs;                                       /* :170 */
    req.txs_len = block->data.txs_len;
    rc = build_last_commit_info_from_store(ctx, block, state->initial_height,
                                           &req.proposed_last_commit); /* :171 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_evidence_to_abci(ctx, &block->evidence, &req.misbehavior,
                                    &req.misbehavior_len);          /* :172 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    memcpy(req.proposer_address, block->header.proposer_address,
           block->header.proposer_address_len);                      /* :173 */
    req.proposer_address_len = block->header.proposer_address_len;
    memcpy(req.next_validators_hash, block->header.next_validators_hash,
           block->header.next_validators_hash_len);                  /* :174 */
    req.next_validators_hash_len = block->header.next_validators_hash_len;

    memset(&resp, 0, sizeof(resp));
    rc = ctx->app->process_proposal(ctx->app->ctx, &req, &resp);    /* :166 */
    if (rc != CMT_OK) {
        return CMT_FAULT;                 /* :176-178 → state.go:1383-1387 */
    }
    if (resp.status == NODUS_ABCI_PROPOSAL_STATUS_UNKNOWN ||
        (resp.status != NODUS_ABCI_PROPOSAL_STATUS_ACCEPT &&
         resp.status != NODUS_ABCI_PROPOSAL_STATUS_REJECT)) {        /* :180 */
        QGP_LOG_ERROR(LOG_TAG, "ProcessProposal responded with status %d",
                      (int)resp.status);
        return CMT_FAULT;                 /* panic */
    }
    *out_accept = (resp.status == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT); /* :184 */
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * validateBlock — state/validation.go:15-150
 * ═══════════════════════════════════════════════════════════════════════ */

static bool bytes_equal(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

static bool time_after(cmt_time_t a, cmt_time_t b)
{
    if (a.seconds != b.seconds) {
        return a.seconds > b.seconds;
    }
    return a.nanos > b.nanos;
}

static bool time_equal(cmt_time_t a, cmt_time_t b)
{
    return a.seconds == b.seconds && a.nanos == b.nanos;
}

int nodus_cmt_validate_block(nodus_cmt_blockexec_t *ctx,
                             const cmt_state_t *state, cmt_block_t *block)
{
    uint8_t hash[CMT_TMHASH_SIZE];
    int     rc;

    if (!ctx || !state || !block) {
        return CMT_FAULT;
    }
    /* :17-19 */
    rc = cmt_block_validate_basic(block, CMT_BLOCK_PROTOCOL);
    if (rc != CMT_OK) {
        return CMT_REJECT;
    }
    /* :22-28 */
    if (block->header.version.app != state->version.consensus.app ||
        block->header.version.block != state->version.consensus.block) {
        QGP_LOG_ERROR(LOG_TAG, "wrong Block.Header.Version. Expected {%" PRIu64
                      " %" PRIu64 "}, got {%" PRIu64 " %" PRIu64 "}",
                      state->version.consensus.block, state->version.consensus.app,
                      block->header.version.block, block->header.version.app);
        return CMT_REJECT;
    }
    /* :29-34 */
    if (!bytes_equal(block->header.chain_id, block->header.chain_id_len,
                     state->chain_id, state->chain_id_len)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.ChainID");
        return CMT_REJECT;
    }
    /* :35-38 */
    if (state->last_block_height == 0 &&
        block->header.height != state->initial_height) {
        QGP_LOG_ERROR(LOG_TAG, "wrong Block.Header.Height. Expected %" PRId64
                      " for initial block, got %" PRId64,
                      block->header.height, state->initial_height);
        return CMT_REJECT;
    }
    /* :39-44 */
    if (state->last_block_height > 0 &&
        block->header.height != state->last_block_height + 1) {
        QGP_LOG_ERROR(LOG_TAG, "wrong Block.Header.Height. Expected %" PRId64
                      ", got %" PRId64, state->last_block_height + 1,
                      block->header.height);
        return CMT_REJECT;
    }
    /* :46-51 */
    if (!cmt_block_id_equals(&block->header.last_block_id, &state->last_block_id)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.LastBlockID.");
        return CMT_REJECT;
    }
    /* :54-59 (D-23 rev 4) */
    if (!bytes_equal(block->header.app_hash, block->header.app_hash_len,
                     state->app_hash, state->app_hash_len)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.AppHash.");
        return CMT_REJECT;
    }
    /* :60-65 */
    if (cmt_consensus_params_hash(&state->consensus_params, hash) != CMT_OK) {
        return CMT_FAULT;
    }
    if (!bytes_equal(block->header.consensus_hash, block->header.consensus_hash_len,
                     hash, CMT_TMHASH_SIZE)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.ConsensusHash.");
        return CMT_REJECT;
    }
    /* :66-71 (D-23 rev 4) */
    if (!bytes_equal(block->header.last_results_hash,
                     block->header.last_results_hash_len,
                     state->last_results_hash, state->last_results_hash_len)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.LastResultsHash.");
        return CMT_REJECT;
    }
    /* :72-77 */
    rc = cmt_validator_set_hash(&state->validators, ctx->valset_hash_scratch,
                                (size_t)CMT_VALSET_MAX * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                ctx->valset_items, CMT_VALSET_MAX, hash);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!bytes_equal(block->header.validators_hash, block->header.validators_hash_len,
                     hash, CMT_TMHASH_SIZE)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.ValidatorsHash.");
        return CMT_REJECT;
    }
    /* :78-83 */
    rc = cmt_validator_set_hash(&state->next_validators, ctx->valset_hash_scratch,
                                (size_t)CMT_VALSET_MAX * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                ctx->valset_items, CMT_VALSET_MAX, hash);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!bytes_equal(block->header.next_validators_hash,
                     block->header.next_validators_hash_len, hash, CMT_TMHASH_SIZE)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "wrong Block.Header.NextValidatorsHash.");
        return CMT_REJECT;
    }
    /* :86-97 */
    if (block->header.height == state->initial_height) {
        if (cmt_commit_size(block->last_commit) != 0) {              /* :88 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "initial block can't have LastCommit "
                          "signatures");
            return CMT_REJECT;
        }
    } else {
        cmt_validator_set_t last_vals;

        /* VerifyCommit writes the set's total-power cache; the state is
         * const here, so verify on a copy (header: OWNERSHIP). */
        if (cmt_validator_set_init(&last_vals, ctx->vals_b, CMT_VALSET_MAX)
                != CMT_OK ||
            cmt_validator_set_copy(&state->last_validators, &last_vals) != CMT_OK) {
            return CMT_FAULT;
        }
        rc = cmt_verify_commit(state->chain_id, state->chain_id_len, &last_vals,
                               &state->last_block_id, block->header.height - 1,
                               block->last_commit, NULL);            /* :92-93 */
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "LastCommit does not verify (rc %d)", rc);
            return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
        }
    }
    /* :102-107 */
    if (block->header.proposer_address_len != CMT_ADDRESS_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "expected ProposerAddress size %d, got %zu",
                      (int)CMT_ADDRESS_SIZE, block->header.proposer_address_len);
        return CMT_REJECT;
    }
    /* :108-112 */
    if (!cmt_validator_set_has_address(&state->validators,
                                       block->header.proposer_address,
                                       block->header.proposer_address_len)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "block.Header.ProposerAddress is not a "
                      "validator");
        return CMT_REJECT;
    }
    /* :115-142 block Time */
    if (block->header.height > state->initial_height) {              /* :116 */
        cmt_time_t median;

        if (!time_after(block->header.time, state->last_block_time)) { /* :117 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "block time not greater than last "
                          "block time");
            return CMT_REJECT;
        }
        rc = cmt_state_median_time(block->last_commit, &state->last_validators,
                                   &median);                         /* :122 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        if (!time_equal(block->header.time, median)) {               /* :123 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "invalid block time.");
            return CMT_REJECT;
        }
    } else if (block->header.height == state->initial_height) {      /* :130 */
        cmt_time_t genesis_time = state->last_block_time;            /* :131 */

        if (!time_equal(block->header.time, genesis_time)) {         /* :132 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "block time is not equal to genesis "
                          "time");
            return CMT_REJECT;
        }
    } else {                                                         /* :139 */
        QGP_LOG_ERROR(LOG_TAG, "block height %" PRId64 " lower than initial "
                      "height %" PRId64, block->header.height,
                      state->initial_height);
        return CMT_REJECT;
    }
    /* :145-147 */
    {
        int64_t max = state->consensus_params.evidence.max_bytes, got = 0;

        if (cmt_evidence_data_byte_size(&block->evidence, &got) != CMT_OK) {
            return CMT_FAULT;
        }
        if (got > max) {
            QGP_LOG_ERROR(LOG_TAG, "evidence overflow: max %" PRId64 ", got %"
                          PRId64, max, got);
            return CMT_REJECT;
        }
    }
    return CMT_OK;                                                   /* :149 */
}

/* :190-197 ValidateBlock */
int nodus_cmt_host_validate_block(void *vctx, const cmt_state_t *state,
                                  cmt_block_t *block)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    int rc;

    if (!ctx || !state || !block) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_validate_block(ctx, state, block);                /* :191 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = ctx->evpool->check_evidence(ctx->evpool->ctx, block->evidence.evidence,
                                     block->evidence.evidence_len);  /* :195 */
    /* R3-AUD-17's second half (tasks/reference-deviation-register.md:245,
     * which cites this site as `:1116-1117`): the class is passed
     * through, so an evidence pool reporting a NODE-LOCAL failure is not
     * read as "the block's evidence is bad". */
    if (rc == CMT_OK) {
        return CMT_OK;
    }
    return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
}

/* ═══════════════════════════════════════════════════════════════════════
 * updateState — execution.go:593-664
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_update_state(nodus_cmt_blockexec_t *ctx, const cmt_state_t *state,
                           const cmt_block_id_t *block_id,
                           const cmt_header_t *header,
                           const cmt_pb_response_finalize_block_t *resp,
                           const cmt_validator_t *validator_updates,
                           size_t n_updates)
{
    cmt_state_t           *ns;
    cmt_state_version_t    version;
    int64_t                last_height_vals_changed, last_height_params_changed;
    cmt_consensus_params_t next_params;
    size_t                 i;
    int                    rc;

    if (!ctx || !state || !block_id || !header || !resp) {
        return CMT_FAULT;
    }
    ns = &ctx->state_scratch;
    if (cmt_state_init(ns, ctx->state_storage) != CMT_OK) {
        return CMT_FAULT;
    }

    /* :603 nValSet := state.NextValidators.Copy() */
    if (cmt_validator_set_init(&ns->next_validators,
                               ctx->state_storage->next_validators,
                               CMT_VALSET_MAX) != CMT_OK ||
        cmt_validator_set_copy(&state->next_validators, &ns->next_validators)
            != CMT_OK) {
        return CMT_FAULT;
    }
    /* :606-614 */
    last_height_vals_changed = state->last_height_validators_changed;
    if (n_updates > 0) {
        rc = cmt_validator_set_update_with_change_set(&ns->next_validators,
                                                      validator_updates, n_updates,
                                                      ctx->valset_scratch); /* :608 */
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "changing validator set failed (rc %d)", rc);
            return CMT_REJECT;                                       /* :610 */
        }
        last_height_vals_changed = header->height + 1 + 1;           /* :613 */
    }
    /* :617 */
    rc = cmt_validator_set_increment_proposer_priority(&ns->next_validators, 1);
    if (rc != CMT_OK) {
        return CMT_FAULT;                 /* the reference's panic sites */
    }
    /* :620-637 */
    next_params = state->consensus_params;                           /* :620 */
    last_height_params_changed = state->last_height_consensus_params_changed;
    version = state->version;
    if (resp->has_consensus_param_updates) {                         /* :622 */
        rc = cmt_consensus_params_update(&state->consensus_params,
                                         &resp->consensus_param_updates,
                                         &next_params);              /* :624 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        rc = cmt_consensus_params_validate_basic(&next_params);      /* :625 */
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "validating new consensus params failed "
                          "(rc %d)", rc);
            return CMT_REJECT;                                       /* :627 */
        }
        rc = cmt_consensus_params_validate_update(&state->consensus_params,
                                                  &resp->consensus_param_updates,
                                                  header->height);   /* :630 */
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "updating consensus params failed (rc %d)", rc);
            return CMT_REJECT;                                       /* :632 */
        }
        version.consensus.app = next_params.version.app;             /* :635 */
        last_height_params_changed = header->height + 1;             /* :638 */
    }
    /* :641 nextVersion := state.Version */

    /* :645-663 the State literal */
    ns->version = version;                                           /* :646 */
    memcpy(ns->chain_id, state->chain_id, state->chain_id_len);      /* :647 */
    ns->chain_id_len = state->chain_id_len;
    ns->initial_height = state->initial_height;                      /* :648 */
    ns->last_block_height = header->height;                          /* :649 */
    ns->last_block_id = *block_id;                                   /* :650 */
    ns->last_block_time = header->time;                              /* :651 */
    /* :652 NextValidators: nValSet — already in place */
    /* :653 Validators: state.NextValidators.Copy() */
    if (cmt_validator_set_init(&ns->validators, ctx->state_storage->validators,
                               CMT_VALSET_MAX) != CMT_OK ||
        cmt_validator_set_copy(&state->next_validators, &ns->validators) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :654 LastValidators: state.Validators.Copy() */
    if (cmt_validator_set_init(&ns->last_validators,
                               ctx->state_storage->last_validators,
                               CMT_VALSET_MAX) != CMT_OK ||
        cmt_validator_set_copy(&state->validators, &ns->last_validators) != CMT_OK) {
        return CMT_FAULT;
    }
    ns->last_height_validators_changed = last_height_vals_changed;   /* :655 */
    ns->consensus_params = next_params;                              /* :656 */
    ns->last_height_consensus_params_changed = last_height_params_changed; /* :657 */
    /* :658 LastResultsHash: TxResultsHash(abciResponse.TxResults)
     *
     * ORCHESTRATOR delta 3, item B — PER-APPLY, not bind-time: refuse a
     * count above `limits.max_txs` (the node's own configured ceiling,
     * unchanged derivation in nodus_cmt_node.c) BEFORE allocating
     * anything — a decided block above it is a node-local invariant
     * broken, the same class FinalizeBlock's own env_bound guard is —
     * then allocate `det_results`/`items` sized to THIS apply's actual
     * `resp->tx_results_len`, and `leaf_scratch` sized the same way the
     * bind-time version was (the marshal-size formula is unchanged; only
     * the item-count term now uses this apply's own count instead of the
     * compile-time ceiling). All three are LOCAL and freed INLINE
     * before every return (delta 8, item B: wording corrected — this
     * block has no `goto`; the three frees are duplicated at the early
     * failure return and again right after the hash call, covering both
     * the hash-failure and success paths) — verified (whole-tree grep) that
     * nothing outside this function ever reads them, so unlike the
     * application layer's `fb_pb` there is no ABCI-response reason to
     * keep them ctx-owned between calls. An allocation failure is
     * CMT_FAULT (node-local, umbrella panic rule). */
    {
        cmt_pb_exec_tx_result_t *det_results = NULL;
        cmt_pb_exec_tx_result_t *out_results = NULL;
        cmt_merkle_item_t       *items       = NULL;
        uint8_t                 *leaf_scratch = NULL;
        size_t                   leaf_scratch_cap;
        cmt_abci_results_t       results;
        int                      hash_rc;

        if (resp->tx_results_len > ctx->limits.max_txs) {
            return CMT_FAULT;                 /* capacity */
        }
        memset(&results, 0, sizeof(results));
        if (resp->tx_results_len > 0) {
            det_results = (cmt_pb_exec_tx_result_t *)
                calloc(resp->tx_results_len, sizeof(*det_results));
            /* ORCHESTRATOR TV3-P0 item 1 — `out_results` MUST be a
             * SEPARATE allocation from `det_results`, never the same
             * array bound through `results.results` (the aliasing this
             * fixes). `cmt_new_results` (results.go:13-19,
             * cmt_results.c:29-49) writes `out->results[i]` through
             * `cmt_deterministic_exec_tx_result`, whose FIRST statement
             * is `cmt_pb_exec_tx_result_init(out)` — a zeroing init —
             * BEFORE it reads `response->code`/`data`/`gas_wanted`/
             * `gas_used`. When `out` and `response` were the SAME
             * pointer (`results.results == det_results`, `i` equal on
             * both sides), that init zeroed the source struct out from
             * under itself: every field the function then "copied" read
             * back as 0. The state's LastResultsHash
             * (state/execution.go:658 `LastResultsHash:
             * TxResultsHash(abciResponse.TxResults)`, state/store.go
             * :411-413 `TxResultsHash` = types/results.go NewResults +
             * Hash) was therefore the hash
             * of an ALL-ZERO-CODE result list on EVERY block, regardless
             * of what the ledger actually returned — a block whose items
             * carried a real nonzero code (8, …) committed the SAME
             * LastResultsHash as an all-code-0 block of the same
             * length. */
            out_results = (cmt_pb_exec_tx_result_t *)
                calloc(resp->tx_results_len, sizeof(*out_results));
            items = (cmt_merkle_item_t *)
                calloc(resp->tx_results_len, sizeof(*items));
        }
        /* A deterministic result marshals to at most 1+5 + 1+2+data +
         * 2×11; the data is application bytes of unbounded length in the
         * reference and of tx_arena_cap in this port's arena — that term
         * is a fixed byte-budget config, not item-count-scaled, so it is
         * unchanged from the bind-time formula. */
        leaf_scratch_cap = ctx->limits.tx_arena_cap +
                           resp->tx_results_len * 32u + 64u;
        leaf_scratch = (uint8_t *)malloc(leaf_scratch_cap);
        if (!leaf_scratch ||
            (resp->tx_results_len > 0 &&
             (!det_results || !out_results || !items))) {
            free(det_results);
            free(out_results);
            free(items);
            free(leaf_scratch);
            return CMT_FAULT;
        }
        for (i = 0; i < resp->tx_results_len; i++) {
            det_results[i] = resp->tx_results[i].det;
        }
        results.results     = out_results;
        results.results_cap = resp->tx_results_len;
        hash_rc = nodus_cmt_ss_tx_results_hash(det_results,
                                               resp->tx_results_len,
                                               &results, leaf_scratch,
                                               leaf_scratch_cap, items,
                                               resp->tx_results_len,
                                               ns->last_results_hash);
        free(det_results);
        free(out_results);
        free(items);
        free(leaf_scratch);
        if (hash_rc != CMT_OK) {
            return CMT_FAULT;
        }
    }
    ns->last_results_hash_len = CMT_TMHASH_SIZE;
    ns->app_hash_len = 0;                                            /* :659 nil */
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Commit — execution.go:387-430
 * ═══════════════════════════════════════════════════════════════════════ */

static int blockexec_commit(nodus_cmt_blockexec_t *ctx, const cmt_state_t *state,
                            const cmt_block_t *block,
                            const cmt_pb_response_finalize_block_t *resp,
                            int64_t *out_retain_height)
{
    nodus_abci_response_commit_t res;
    nodus_cmt_pre_check_t  pre;
    nodus_cmt_post_check_t post;
    int rc;

    ctx->mempool->lock(ctx->mempool->ctx);                           /* :392 */
    rc = ctx->mempool->flush_app_conn(ctx->mempool->ctx);            /* :397 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "client error during mempool.FlushAppConn (rc %d)",
                      rc);
        ctx->mempool->unlock(ctx->mempool->ctx);                     /* :393 defer */
        return CMT_REJECT;                                           /* :400 */
    }
    memset(&res, 0, sizeof(res));
    rc = ctx->app->commit(ctx->app->ctx, &res);                      /* :404 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "client error during proxyAppConn.CommitSync "
                      "(rc %d)", rc);
        ctx->mempool->unlock(ctx->mempool->ctx);
        return CMT_REJECT;                                           /* :407 */
    }
    /* :418-425 mempool.Update(height, txs, results, TxPreCheck(state),
     * TxPostCheck(state)) — `state` is the UPDATED state (:284, :289). */
    if (nodus_cmt_tx_pre_check(state, &pre) != CMT_OK) {
        ctx->mempool->unlock(ctx->mempool->ctx);
        return CMT_FAULT;
    }
    post = nodus_cmt_tx_post_check(state);
    rc = ctx->mempool->update(ctx->mempool->ctx, block->header.height,
                              block->data.txs, block->data.txs_len,
                              resp->tx_results, resp->tx_results_len, pre, post);
    ctx->mempool->unlock(ctx->mempool->ctx);                         /* :393 defer */
    *out_retain_height = res.retain_height;                          /* :427 */
    return rc == CMT_OK ? CMT_OK : CMT_REJECT;
}

/* ═══════════════════════════════════════════════════════════════════════
 * pruneBlocks — execution.go:773-789
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_blockexec_prune_blocks(nodus_cmt_blockexec_t *ctx,
                                     int64_t retain_height,
                                     const cmt_state_t *state,
                                     uint64_t *out_pruned)
{
    int64_t  base, pruned_header_height = -1;
    uint64_t amount_pruned = 0;
    int      rc;

    if (!ctx || !state || !out_pruned) {
        return CMT_FAULT;
    }
    *out_pruned = 0;
    base = nodus_cmt_bs_base(ctx->store);                            /* :774 */
    if (retain_height <= base) {                                     /* :775-777 */
        return CMT_OK;
    }
    rc = nodus_cmt_bs_prune_blocks(ctx->store, retain_height, state,
                                   &amount_pruned, &pruned_header_height); /* :779 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "failed to prune block store (rc %d)", rc);
        return rc;                                                   /* :781 */
    }
    rc = nodus_cmt_ss_prune_states(ctx->store, base, retain_height,
                                   pruned_header_height, ctx->vals_a,
                                   CMT_VALSET_MAX, ctx->valset_scratch); /* :784 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "failed to prune state store (rc %d)", rc);
        return rc;                                                   /* :786 */
    }
    *out_pruned = amount_pruned;                                     /* :788 */
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * applyBlock — execution.go:222-323
 * ═══════════════════════════════════════════════════════════════════════ */

/* The RequestFinalizeBlock of :224-233 and :740-749 (ExecCommitBlock),
 * one builder. */
static int build_finalize_request(nodus_cmt_blockexec_t *ctx, cmt_block_t *block,
                                  int64_t initial_height,
                                  nodus_abci_request_finalize_block_t *req)
{
    int rc;

    memset(req, 0, sizeof(*req));
    if (block_hash_of(block, req->hash, &req->hash_len) != CMT_OK) { /* :225 */
        return CMT_FAULT;
    }
    memcpy(req->next_validators_hash, block->header.next_validators_hash,
           block->header.next_validators_hash_len);                  /* :226 */
    req->next_validators_hash_len = block->header.next_validators_hash_len;
    memcpy(req->proposer_address, block->header.proposer_address,
           block->header.proposer_address_len);                      /* :227 */
    req->proposer_address_len = block->header.proposer_address_len;
    req->height = block->header.height;                              /* :228 */
    req->time = block->header.time;                                  /* :229 */
    rc = build_last_commit_info_from_store(ctx, block, initial_height,
                                           &req->decided_last_commit); /* :230 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_evidence_to_abci(ctx, &block->evidence, &req->misbehavior,
                                    &req->misbehavior_len);          /* :231 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    req->txs = block->data.txs;                                      /* :232 */
    req->txs_len = block->data.txs_len;
    return CMT_OK;
}

/* ── THE ONE LEDGER TRANSACTION (D-23 rev 5 (5)) ─────────────────────
 *
 * `applyBlock` opens ONE SQLite transaction on the MAIN ledger connection
 * BEFORE `app.finalize_block` and `app.commit` closes it. Inside it the
 * application's ledger writes, `SaveFinalizeBlockResponse`'s
 * `abciResponsesKey:<h>` row (:259) and whatever `updateState` (:284)
 * persists are ONE atomic unit, so no crash can leave the reference's
 * Handshaker a combination it does not handle: before the COMMIT is
 * "we haven't run Commit" (consensus/replay.go:428-436) and after it,
 * before `store.Save`, is "we ran Commit but didn't save the state"
 * (:437-453).
 *
 * The connection is the store's, which BORROWS the witness's own handle
 * (nodus_witness_cmt_store.h:208), and the store's batch JOINS an open
 * transaction rather than nesting (nodus_witness_cmt_store.c:44-53) —
 * the rule D-4 rev 3 point 5 relies on.
 *
 * UNCONDITIONAL, exactly as D-23 rev 5 (5) reads: every application
 * bound to this executor must have a `commit` that CLOSES the
 * transaction this opens. The ledger application does (it issues the
 * COMMIT); so does the test fixture's mock (test_cmt_host.c's
 * `tapp_commit`).
 */

static sqlite3 *blockexec_db(nodus_cmt_blockexec_t *ctx)
{
    return (ctx && ctx->store) ? ctx->store->db : NULL;
}

/** @return CMT_OK, or CMT_FAULT — a missing connection and an ALREADY
 *  open transaction are both node-local invariants (umbrella rev 6's
 *  panic rule); no peer can produce either. */
static int ledger_txn_begin(nodus_cmt_blockexec_t *ctx)
{
    sqlite3 *db = blockexec_db(ctx);
    char    *err = NULL;

    if (!db) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "apply: no ledger connection");
        return CMT_FAULT;
    }
    if (!sqlite3_get_autocommit(db)) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "apply: the ledger connection is already inside a "
                      "transaction");
        return CMT_FAULT;
    }
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "apply: BEGIN IMMEDIATE failed: %s",
                      err ? err : "?");
        sqlite3_free(err);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/** Rolls back IFF a transaction is still open, so it is a no-op after
 *  `app.commit` has executed the COMMIT. */
static void ledger_txn_rollback(nodus_cmt_blockexec_t *ctx)
{
    sqlite3 *db = blockexec_db(ctx);

    if (db && !sqlite3_get_autocommit(db)) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
}

static int apply_block(nodus_cmt_blockexec_t *ctx, const cmt_block_id_t *block_id,
                       cmt_block_t *block, cmt_state_t *in_out_state)
{
    nodus_abci_request_finalize_block_t   req;
    nodus_abci_response_finalize_block_t *resp;
    int64_t retain_height = 0;
    int     rc;

    resp = (nodus_abci_response_finalize_block_t *)calloc(1, sizeof(*resp));
    if (!resp) {
        return CMT_FAULT;
    }
    rc = build_finalize_request(ctx, block, in_out_state->initial_height, &req);
    if (rc != CMT_OK) {
        free(resp);
        return CMT_FAULT;
    }
    /* BEGIN IMMEDIATE — before :224, so everything below joins it. */
    if (ledger_txn_begin(ctx) != CMT_OK) {
        free(resp);
        return CMT_FAULT;
    }
    rc = ctx->app->finalize_block(ctx->app->ctx, &req, resp);       /* :224 */
    if (rc != CMT_OK) {                                              /* :236-239 */
        QGP_LOG_ERROR(LOG_TAG, "error in proxyAppConn.FinalizeBlock (rc %d)", rc);
        goto fail;                        /* state.go:1783-1785 panics */
    }
    /* :249-251 */
    if (block->data.txs_len != resp->tx_results_len) {
        QGP_LOG_ERROR(LOG_TAG, "expected tx results length to match size of "
                      "transactions in block. Expected %zu, got %zu",
                      block->data.txs_len, resp->tx_results_len);
        goto fail;
    }
    CMT_FAIL_POINT();                                                /* :256 */
    /* :259 SaveFinalizeBlockResponse — joins the transaction */
    rc = nodus_cmt_ss_save_finalize_block_response(ctx->store,
                                                   block->header.height, resp);
    if (rc != CMT_OK) {
        goto fail;                                                   /* :260 */
    }
    CMT_FAIL_POINT();                                                /* :263 */
    /* :266-269 validateValidatorUpdates */
    rc = nodus_cmt_validate_validator_updates(
        resp->validator_updates, resp->validator_updates_len,
        &in_out_state->consensus_params.validator);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "error in validator updates (rc %d)", rc);
        goto fail;                                                   /* :268 */
    }
    /* :271-274 PB2TM.ValidatorUpdates */
    rc = nodus_cmt_pb2tm_validator_updates(resp->validator_updates,
                                           resp->validator_updates_len,
                                           ctx->changes, CMT_VALSET_MAX_CHANGES);
    if (rc != CMT_OK) {
        goto fail;                                                   /* :273 */
    }
    /* :284-287 updateState */
    rc = nodus_cmt_update_state(ctx, in_out_state, block_id, &block->header, resp,
                                ctx->changes, resp->validator_updates_len);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "commit failed for application (rc %d)", rc);
        goto fail;                                                   /* :286 */
    }
    /* :290-293 Commit — `app.commit` IS the COMMIT of the transaction
     * opened above (D-23 rev 5 (5)). */
    rc = blockexec_commit(ctx, &ctx->state_scratch, block, resp, &retain_height);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "commit failed for application (rc %d)", rc);
        goto fail;                                                   /* :292 */
    }
    /* :296 evpool.Update */
    (void)ctx->evpool->update(ctx->evpool->ctx, &ctx->state_scratch,
                              block->evidence.evidence, block->evidence.evidence_len);
    CMT_FAIL_POINT();                                                /* :298 */
    /* :301 state.AppHash = abciResponse.AppHash */
    memcpy(ctx->state_scratch.app_hash, resp->app_hash, resp->app_hash_len);
    ctx->state_scratch.app_hash_len = resp->app_hash_len;
    /* TEST-ONLY: the "ran Commit, didn't save the state" window
     * (replay.go:437-453). The ledger and the response row are durable;
     * `stateKey` still names h−1. */
    if (ctx->test_fail_after_commit) {
        QGP_LOG_WARN(LOG_TAG, "%s",
                     "test fault point: stopping between Commit and "
                     "store.Save(state)");
        goto fail;
    }
    /* :302-304 store.Save — its own autocommit statement, AFTER the
     * COMMIT (D-23 rev 5 (5)). */
    rc = nodus_cmt_ss_save(ctx->store, &ctx->state_scratch);
    if (rc != CMT_OK) {
        goto fail;                                                   /* :303 */
    }
    CMT_FAIL_POINT();                                                /* :306 */
    /* :309-316 pruneBlocks — errors only logged */
    if (retain_height > 0) {
        uint64_t pruned = 0;

        rc = nodus_cmt_blockexec_prune_blocks(ctx, retain_height,
                                              &ctx->state_scratch, &pruned);
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "failed to prune blocks: retain_height %"
                          PRId64 " (rc %d)", retain_height, rc);
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "pruned blocks: %" PRIu64 ", retain_height %"
                          PRId64, pruned, retain_height);
        }
    }
    /* :320 fireEvents — YOK */
    free(resp);
    /* :322 return state, nil — the reference's value; here the copy. */
    return cmt_state_copy(&ctx->state_scratch, in_out_state) == CMT_OK
               ? CMT_OK : CMT_FAULT;

fail:
    /* Every failure of the reference's `applyBlock` is state.go:1783-1785's
     * panic class — the node stops — so the class is CMT_FAULT at every
     * one of these exits, exactly as before the bracket existed. The
     * rollback is conditional, so an exit AFTER `app.commit` (which
     * already closed the transaction) does not attempt one. */
    ledger_txn_rollback(ctx);
    free(resp);
    return CMT_FAULT;
}

/* :199-203 ApplyVerifiedBlock */
int nodus_cmt_host_apply_verified_block(void *vctx, const cmt_block_id_t *block_id,
                                        cmt_block_t *block,
                                        cmt_state_t *in_out_state)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !block_id || !block || !in_out_state) {
        return CMT_FAULT;
    }
    return apply_block(ctx, block_id, block, in_out_state);          /* :202 */
}

/* :211-220 ApplyBlock */
int nodus_cmt_blockexec_apply_block(nodus_cmt_blockexec_t *ctx,
                                    const cmt_block_id_t *block_id,
                                    cmt_block_t *block,
                                    cmt_state_t *in_out_state)
{
    int rc;

    if (!ctx || !block_id || !block || !in_out_state) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_validate_block(ctx, in_out_state, block);         /* :215 */
    if (rc != CMT_OK) {
        return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;             /* :216 */
    }
    return apply_block(ctx, block_id, block, in_out_state);          /* :219 */
}

/* :731-771 ExecCommitBlock */
int nodus_cmt_exec_commit_block(nodus_cmt_blockexec_t *ctx, cmt_block_t *block,
                                int64_t initial_height,
                                uint8_t out_app_hash[CMT_PB_HASH_MAX],
                                size_t *out_app_hash_len)
{
    nodus_abci_request_finalize_block_t   req;
    nodus_abci_response_finalize_block_t *resp;
    nodus_abci_response_commit_t          cres;
    int rc;

    if (!ctx || !block || !out_app_hash || !out_app_hash_len) {
        return CMT_FAULT;
    }
    resp = (nodus_abci_response_finalize_block_t *)calloc(1, sizeof(*resp));
    if (!resp) {
        return CMT_FAULT;
    }
    rc = build_finalize_request(ctx, block, initial_height, &req);   /* :738-749 */
    if (rc != CMT_OK) {
        free(resp);
        return CMT_FAULT;
    }
    /* The SAME bracket as `applyBlock` (D-23 rev 5 (5)): the Handshaker's
     * replay applies blocks through this function, so a block it replays
     * must become durable in ONE transaction too — `app.commit` is its
     * COMMIT. No state is saved here (:731-771 touches no state store). */
    if (ledger_txn_begin(ctx) != CMT_OK) {
        free(resp);
        return CMT_FAULT;
    }
    /* R3-AUD-17, same class as decode_block: these three sites used to
     * narrow EVERY non-OK answer to CMT_REJECT, so an application's
     * CMT_FAULT — this node failing to apply — was reported as "the
     * block is bad". The class is passed through; only a genuine REJECT
     * stays the reference's `:750-753` / `:756-758` / `:764-767` error. */
    rc = ctx->app->finalize_block(ctx->app->ctx, &req, resp);       /* :740 */
    if (rc != CMT_OK) {                                              /* :750-753 */
        QGP_LOG_ERROR(LOG_TAG, "error in proxyAppConn.FinalizeBlock (rc %d)", rc);
        ledger_txn_rollback(ctx);
        free(resp);
        return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
    }
    if (block->data.txs_len != resp->tx_results_len) {               /* :756-758 */
        QGP_LOG_ERROR(LOG_TAG, "expected tx results length to match size of "
                      "transactions in block. Expected %zu, got %zu",
                      block->data.txs_len, resp->tx_results_len);
        ledger_txn_rollback(ctx);
        free(resp);
        return CMT_REJECT;
    }
    memset(&cres, 0, sizeof(cres));
    rc = ctx->app->commit(ctx->app->ctx, &cres);                     /* :763 */
    if (rc != CMT_OK) {                                              /* :764-767 */
        QGP_LOG_ERROR(LOG_TAG, "client error during proxyAppConn.Commit (rc %d)",
                      rc);
        ledger_txn_rollback(ctx);
        free(resp);
        return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
    }
    memcpy(out_app_hash, resp->app_hash, resp->app_hash_len);        /* :770 */
    *out_app_hash_len = resp->app_hash_len;
    free(resp);
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ExtendVote / VerifyVoteExtension — execution.go:325-385
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_host_extend_vote(void *vctx, const cmt_vote_t *vote,
                               cmt_block_t *block, const cmt_state_t *state,
                               cmt_pb_bytes_t *out_ext)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    nodus_abci_request_extend_vote_t  req;
    nodus_abci_response_extend_vote_t resp;
    cmt_pb_arena_t *arena;
    int rc;

    if (!ctx || !vote || !block || !state || !out_ext) {
        return CMT_FAULT;
    }
    if (!cmt_block_hashes_to(block, vote->block_id.hash, vote->block_id.hash_len)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "vote's hash does not match the block it "
                      "is referring to");
        return CMT_FAULT;                                            /* :331-333 panic */
    }
    if (vote->height != block->header.height) {                      /* :334-336 */
        QGP_LOG_ERROR(LOG_TAG, "vote's and block's heights do not match %" PRId64
                      "!=%" PRId64, block->header.height, vote->height);
        return CMT_FAULT;                 /* panic */
    }
    memset(&req, 0, sizeof(req));
    memcpy(req.hash, vote->block_id.hash, vote->block_id.hash_len);  /* :339 */
    req.hash_len = vote->block_id.hash_len;
    req.height = vote->height;                                       /* :340 */
    req.time = block->header.time;                                   /* :341 */
    req.txs = block->data.txs;                                       /* :342 */
    req.txs_len = block->data.txs_len;
    rc = build_last_commit_info_from_store(ctx, block, state->initial_height,
                                           &req.proposed_last_commit); /* :343 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_evidence_to_abci(ctx, &block->evidence, &req.misbehavior,
                                    &req.misbehavior_len);          /* :344 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    memcpy(req.next_validators_hash, block->header.next_validators_hash,
           block->header.next_validators_hash_len);                  /* :345 */
    req.next_validators_hash_len = block->header.next_validators_hash_len;
    memcpy(req.proposer_address, block->header.proposer_address,
           block->header.proposer_address_len);                      /* :346 */
    req.proposer_address_len = block->header.proposer_address_len;

    memset(&resp, 0, sizeof(resp));
    rc = ctx->app->extend_vote(ctx->app->ctx, &req, &resp);         /* :349 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "ExtendVote call failed (rc %d)", rc);
        return CMT_FAULT;                                            /* :351 panic */
    }
    /* :353 — the bytes into the per-height-parity extension arena
     * (cmt_cs.h OWNERSHIP (2)); an empty extension is the reference's
     * nil. PACKAGE W4-X (register R3-W3-C2e-4): picked by THIS vote's
     * own height (already proven == block->header.height above), never
     * by any notion of the "current" height — this row has no `cs` to
     * read one from, and the vote being extended is always for the
     * height it names. */
    if (resp.vote_extension.len == 0) {
        out_ext->data = NULL;
        out_ext->len = 0;
        return CMT_OK;
    }
    arena = ctx->ext_arena[(uint64_t)vote->height & 1u];
    if (!arena || !arena->buf ||
        resp.vote_extension.len > arena->cap - arena->used) {
        return CMT_FAULT;                 /* capacity */
    }
    memcpy(arena->buf + arena->used, resp.vote_extension.data,
           resp.vote_extension.len);
    out_ext->data = arena->buf + arena->used;
    out_ext->len = resp.vote_extension.len;
    arena->used += resp.vote_extension.len;
    return CMT_OK;
}

int nodus_cmt_host_verify_vote_extension(void *vctx, const cmt_vote_t *vote)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    nodus_abci_request_verify_vote_extension_t  req;
    nodus_abci_response_verify_vote_extension_t resp;
    int rc;

    if (!ctx || !vote) {
        return CMT_FAULT;
    }
    memset(&req, 0, sizeof(req));
    memcpy(req.hash, vote->block_id.hash, vote->block_id.hash_len);  /* :358 */
    req.hash_len = vote->block_id.hash_len;
    memcpy(req.validator_address, vote->validator_address,
           vote->validator_address_len);                             /* :359 */
    req.validator_address_len = vote->validator_address_len;
    req.height = vote->height;                                       /* :360 */
    req.vote_extension = vote->extension;                            /* :361 */

    memset(&resp, 0, sizeof(resp));
    rc = ctx->app->verify_vote_extension(ctx->app->ctx, &req, &resp); /* :364 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "VerifyVoteExtension call failed (rc %d)", rc);
        return CMT_FAULT;                                            /* :366 panic */
    }
    if (resp.status == NODUS_ABCI_VERIFY_STATUS_UNKNOWN ||
        (resp.status != NODUS_ABCI_VERIFY_STATUS_ACCEPT &&
         resp.status != NODUS_ABCI_VERIFY_STATUS_REJECT)) {          /* :368 */
        QGP_LOG_ERROR(LOG_TAG, "VerifyVoteExtension responded with status %d",
                      (int)resp.status);
        return CMT_FAULT;                 /* panic */
    }
    if (resp.status != NODUS_ABCI_VERIFY_STATUS_ACCEPT) {            /* :372 */
        return CMT_REJECT;                /* types.ErrInvalidVoteExtension */
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The BlockStore rows (forwarders)
 * ═══════════════════════════════════════════════════════════════════════ */

static int host_bs_height(void *vctx, int64_t *out)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !out) {
        return CMT_FAULT;
    }
    *out = nodus_cmt_bs_height(ctx->store);
    return CMT_OK;
}

static int host_bs_load_block_commit(void *vctx, int64_t height,
                                     cmt_commit_t *out, bool *out_found)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    return nodus_cmt_bs_load_block_commit(ctx->store, height, ctx->commit_sigs,
                                          CMT_VALSET_MAX, out, out_found);
}

static int host_bs_load_block_extended_commit(void *vctx, int64_t height,
                                              cmt_extended_commit_t *out,
                                              bool *out_found)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    ctx->ext_load_arena.used = 0;
    return nodus_cmt_bs_load_block_extended_commit(ctx->store, height,
                                                   ctx->ext_sigs, CMT_VALSET_MAX,
                                                   &ctx->ext_load_arena, out,
                                                   out_found);
}

static int host_bs_load_block_meta(void *vctx, int64_t height,
                                   cmt_header_t *out, bool *out_found)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    nodus_cmt_block_meta_t *meta;
    int rc;

    if (!ctx || !out || !out_found) {
        return CMT_FAULT;
    }
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (!meta) {
        return CMT_FAULT;
    }
    rc = nodus_cmt_bs_load_block_meta(ctx->store, height, meta, out_found);
    if (rc == CMT_OK && *out_found) {
        *out = meta->header;              /* the HEADER, cmt_cs.h:438-444 */
    }
    free(meta);
    return rc;
}

static int host_bs_load_seen_commit(void *vctx, int64_t height,
                                    cmt_commit_t *out, bool *out_found)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    return nodus_cmt_bs_load_seen_commit(ctx->store, height, ctx->seen_sigs,
                                         CMT_VALSET_MAX, out, out_found);
}

static int host_bs_save_block(void *vctx, cmt_block_t *block,
                              const cmt_part_set_t *parts,
                              const cmt_commit_t *seen_commit)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    return nodus_cmt_bs_save_block(ctx->store, block, parts, seen_commit,
                                   ctx->marshal_scratch, ctx->marshal_scratch_cap);
}

static int host_bs_save_block_with_extended_commit(
        void *vctx, cmt_block_t *block, const cmt_part_set_t *parts,
        const cmt_extended_commit_t *seen_extended_commit)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    return nodus_cmt_bs_save_block_with_extended_commit(
        ctx->store, block, parts, seen_extended_commit, ctx->tocommit_sigs,
        CMT_VALSET_MAX, ctx->marshal_scratch, ctx->marshal_scratch_cap);
}

/* ── evidence pool row ─────────────────────────────────────────────── */

static int host_report_conflicting_votes(void *vctx, const cmt_vote_t *a,
                                         const cmt_vote_t *b)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    return ctx->evpool->report_conflicting_votes(ctx->evpool->ctx, a, b);
}

/* ── privval rows ──────────────────────────────────────────────────── */

static int host_sign_vote(void *vctx, const uint8_t *chain_id,
                          size_t chain_id_len, cmt_pb_vote_t *v)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !ctx->pv) {
        return CMT_FAULT;
    }
    return cmt_pv_sign_vote_adapter(ctx->pv, chain_id, chain_id_len, v);
}

static int host_sign_proposal(void *vctx, const uint8_t *chain_id,
                              size_t chain_id_len, cmt_proposal_t *p)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !ctx->pv) {
        return CMT_FAULT;
    }
    return cmt_pv_sign_proposal_adapter(ctx->pv, chain_id, chain_id_len, p);
}

static int host_get_pub_key(void *vctx, cmt_pb_public_key_t *out)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !ctx->pv || !out) {
        return CMT_FAULT;
    }
    if (cmt_pv_get_pub_key(ctx->pv, out->key) != CMT_OK) {          /* file.go:256 */
        return CMT_FAULT;
    }
    out->present = true;
    return CMT_OK;
}

/* ── WAL rows ──────────────────────────────────────────────────────── */

static int host_wal_write(void *vctx, const cmt_wal_message_t *msg)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    /* FLEET-TM-R3 W3 (item 8, R3-C1c-6), delta 7 item A (delta 8, item B:
     * citation corrected) — `ctx->wal == NULL` is the reference's
     * `nilWAL` (state.go:174 `cs.wal = nilWAL{}`, installed BEFORE
     * OnStart's real WAL open, state.go:319-336), a SILENT no-op here
     * too (wal.go:426 `func (nilWAL) Write(WALMessage) error { return
     * nil }`), not a fault: `cmt_cs_init` writes a newStep row before
     * `nodus_cmt_node_start` ever opens the
     * real WAL (delta 7: `nodus_cmt_blockexec_init` is now called with
     * `wal = NULL`, exactly mirroring nilWAL's construction-time binding;
     * `nodus_cmt_node_start` binds the real WAL only after it opens), so
     * this path is reached on the very first `cmt_cs_init` and must not
     * refuse it. A WAL that exists but fails to WRITE is still this
     * node's own fault, unchanged below. */
    if (!ctx->wal) {
        return CMT_OK;
    }
    return nodus_cmt_wal_write(ctx->wal, msg);
}

static int host_wal_write_sync(void *vctx, const cmt_wal_message_t *msg)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    /* delta 7 item A (delta 8, item B: citation corrected) — wal.go:427
     * `func (nilWAL) WriteSync(WALMessage) error { return nil }` is ALSO
     * a silent no-op, the same nilWAL binding as `host_wal_write`
     * above. */
    if (!ctx->wal) {
        return CMT_OK;
    }
    return nodus_cmt_wal_write_sync(ctx->wal, msg);
}

static int host_wal_flush_and_sync(void *vctx)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    /* delta 7 item A (delta 8, item B: citation corrected) — wal.go:428
     * `func (nilWAL) FlushAndSync() error { return nil }` is ALSO a
     * silent no-op. */
    if (!ctx->wal) {
        return CMT_OK;
    }
    return nodus_cmt_wal_flush_and_sync(ctx->wal);
}

static int host_wal_search_end_height(void *vctx, int64_t height, bool *out_found)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    /* delta 7 item A (delta 8, item B: citation added) — wal.go:429-431
     * `func (nilWAL) SearchForEndHeight(...) (rd io.ReadCloser, found
     * bool, err error) { return nil, false, nil }`: a SUCCESSFUL "not
     * found" answer, never an error, so this reports CMT_OK with
     * *out_found = false rather than CMT_FAULT. `height` is unused on
     * this path — a nilWAL has nothing to search regardless of which
     * height is asked for. */
    if (!ctx->wal) {
        if (out_found) {
            *out_found = false;
        }
        return CMT_OK;
    }
    return nodus_cmt_wal_search_end_height(ctx->wal, height, out_found);
}

/* delta 7 item A — `read_next` stays a FAULT on a NULL wal, unlike the
 * four rows above: the `WAL` interface itself (wal.go:58-69) declares
 * only Write/WriteSync/FlushAndSync/SearchForEndHeight plus the service
 * methods Start/Stop/Wait — there is no ReadNext row for nilWAL
 * (wal.go:422-434) to answer at all. A replay read is reached only
 * through `catchupReplay`, which OnStart runs strictly AFTER binding the
 * real WAL (state.go:318-329's `loadWalFile`: `cs.OpenWAL` then
 * `cs.wal = wal`, BEFORE the `cs.doWALCatchup` block at :338), never
 * before it — so the reference has no path that reads before opening,
 * and reaching this row with no WAL open is this node's own invariant
 * broken, not a case the reference has an answer for. */
static int host_wal_read_next(void *vctx, cmt_timed_wal_message_t *out,
                              bool *out_eof)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !ctx->wal) {
        return CMT_FAULT;
    }
    return nodus_cmt_wal_read_next(ctx->wal, out, out_eof);
}

/* ── decode_block (state.go:2005-2019) ─────────────────────────────── */

static int host_decode_block(void *vctx, const uint8_t *bytes, size_t len,
                             cmt_block_t *out)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    nodus_cmt_slot_storage_t *slot;
    int rc;

    if (!ctx || !out) {
        return CMT_FAULT;
    }
    slot = slot_of(ctx, out);
    if (!slot) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "decode_block: out is not a slot");
        return CMT_FAULT;
    }
    /* R3-AUD-17 (tasks/reference-deviation-register.md:245): this line
     * used to narrow EVERY non-OK answer to CMT_REJECT, so a CMT_FAULT
     * the decoder raises for a node-local failure (a NULL storage
     * pointer, nodus_witness_cmt_store.h:195-201) would have been
     * reported as a peer's bad bytes. The class is passed through: a
     * REJECT stays the reference's "these bytes do not decode / fail
     * ValidateBasic" (state.go:2007/:2013/:2018), a FAULT stays this
     * node's. The evpool half of the same register row
     * (`check_evidence` in `nodus_cmt_host_validate_block`) is passed
     * through the same way — see that function. */
    rc = nodus_cmt_block_decode(bytes, len, &slot->dec, out);
    if (rc == CMT_OK) {
        return CMT_OK;
    }
    return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
}

/* ── the clock and the timer ───────────────────────────────────────── */

static int host_now(void *vctx, cmt_time_t *out)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx || !ctx->now) {
        return CMT_FAULT;
    }
    return ctx->now(ctx->now_ctx, out);
}

/* ticker.go:126 `timer.Reset(ti.Duration)` — one pending deadline. A
 * non-positive duration fires on the next tick (ticker.go:16, :124). */
static int host_timer_arm(void *vctx, int64_t duration_ns)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;
    cmt_time_t now;
    int64_t    now_ns;

    if (!ctx || !ctx->now) {
        return CMT_FAULT;
    }
    if (ctx->now(ctx->now_ctx, &now) != CMT_OK) {
        return CMT_FAULT;
    }
    now_ns = cmt_time_unix_nano(now);
    if (duration_ns <= 0) {
        ctx->timer_deadline_ns = now_ns;
    } else if (duration_ns > INT64_MAX - now_ns) {
        ctx->timer_deadline_ns = INT64_MAX;
    } else {
        ctx->timer_deadline_ns = now_ns + duration_ns;
    }
    ctx->timer_armed = true;
    return CMT_OK;
}

/* ticker.go:83-92 `stopTimer`: cancel, and DISCARD a fired-but-unread
 * expiry (:88-90) — here the same flag, so an undelivered expiry is gone. */
static int host_timer_disarm(void *vctx)
{
    nodus_cmt_blockexec_t *ctx = (nodus_cmt_blockexec_t *)vctx;

    if (!ctx) {
        return CMT_FAULT;
    }
    ctx->timer_armed = false;
    return CMT_OK;
}

bool nodus_cmt_host_timer_due(nodus_cmt_blockexec_t *ctx, int64_t now_ns)
{
    if (!ctx || !ctx->timer_armed || now_ns < ctx->timer_deadline_ns) {
        return false;
    }
    ctx->timer_armed = false;             /* the channel receive */
    return true;
}

bool nodus_cmt_host_next_deadline(const nodus_cmt_blockexec_t *ctx,
                                  int64_t *out_deadline_ns)
{
    if (!ctx || !ctx->timer_armed) {
        return false;
    }
    if (out_deadline_ns) {
        *out_deadline_ns = ctx->timer_deadline_ns;
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The table
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_host_build(cmt_cs_host_t *out, nodus_cmt_blockexec_t *ctx)
{
    if (!out || !ctx) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    /* sm.BlockExecutor */
    out->create_proposal_block           = nodus_cmt_host_create_proposal_block;
    out->process_proposal                = nodus_cmt_host_process_proposal;
    out->validate_block                  = nodus_cmt_host_validate_block;
    out->apply_verified_block            = nodus_cmt_host_apply_verified_block;
    out->extend_vote                     = nodus_cmt_host_extend_vote;
    out->verify_vote_extension           = nodus_cmt_host_verify_vote_extension;
    /* sm.BlockStore */
    out->bs_height                       = host_bs_height;
    out->bs_load_block_commit            = host_bs_load_block_commit;
    out->bs_load_block_extended_commit   = host_bs_load_block_extended_commit;
    out->bs_load_block_meta              = host_bs_load_block_meta;
    out->bs_load_seen_commit             = host_bs_load_seen_commit;
    out->bs_save_block                   = host_bs_save_block;
    out->bs_save_block_with_extended_commit = host_bs_save_block_with_extended_commit;
    /* evidencePool */
    out->report_conflicting_votes        = host_report_conflicting_votes;
    /* types.PrivValidator */
    out->sign_vote                       = host_sign_vote;
    out->sign_proposal                   = host_sign_proposal;
    out->get_pub_key                     = host_get_pub_key;
    /* WAL */
    out->wal_write                       = host_wal_write;
    out->wal_write_sync                  = host_wal_write_sync;
    out->wal_flush_and_sync              = host_wal_flush_and_sync;
    out->wal_search_end_height           = host_wal_search_end_height;
    out->wal_read_next                   = host_wal_read_next;
    /* decode, clock, timer */
    out->decode_block                    = host_decode_block;
    out->now                             = host_now;
    out->timer_arm                       = host_timer_arm;
    out->timer_disarm                    = host_timer_disarm;
    return CMT_OK;
}
