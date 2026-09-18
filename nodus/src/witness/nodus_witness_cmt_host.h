/**
 * @file nodus/src/witness/nodus_witness_cmt_host.h
 * @brief cometbft @709fd12b `state/execution.go` (BlockExecutor) and
 *        `state/validation.go`, literal, as the HOST behind
 *        `cmt_cs_host_t` — every one of its 26 rows — with the ABCI
 *        application, mempool and evidence-pool interface tables the
 *        BlockExecutor talks to.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W1, package R3-B. Nothing in the running chain calls
 * anything here; R3-C2 constructs `nodus_cmt_blockexec_t`, calls
 * `nodus_cmt_host_build` and hands the table to `cmt_cs_init`.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── THE OBJECT ─────────────────────────────────────────────────────────
 * `nodus_cmt_blockexec_t` is `BlockExecutor` (execution.go:25-45):
 *   store      (:27)  the state store       → nodus_cmt_store_t (one
 *   blockStore (:30)  the block store         object, two tables)
 *   proxyApp   (:33)  → nodus_cmt_app_t, the consensus connection
 *                      (proxy/app_conn.go:18-27 `AppConnConsensus`)
 *   eventBus   (:36)  YOK — `types.NopEventBus{}`; no consensus decision
 *                      reads an event
 *   mempool    (:40)  → nodus_cmt_mempool_if_t (mempool/mempool.go:31-102)
 *   evpool     (:41)  → nodus_cmt_evpool_if_t (state/services.go:47-52)
 *   logger     (:43)  YOK — QGP_LOG
 *   metrics    (:45)  YOK
 * plus what the other host rows forward to: the WAL storage, the file
 * privval, the clock, the block slots and the vote-extension arena.
 *
 * ── THE 26 ROWS OF cmt_cs_host_t (cmt_cs.h:367-563) ────────────────────
 *   6 BlockExecutor  create_proposal_block :101, process_proposal :162,
 *                    validate_block :190, apply_verified_block :199,
 *                    extend_vote :325, verify_vote_extension :356
 *   7 BlockStore     bs_height, bs_load_block_commit,
 *                    bs_load_block_extended_commit, bs_load_block_meta
 *                    (the HEADER), bs_load_seen_commit, bs_save_block,
 *                    bs_save_block_with_extended_commit → the store
 *   1 evidence pool  report_conflicting_votes → the evpool table
 *   3 privval        sign_vote, sign_proposal, get_pub_key → cmt_privval's
 *                    adapters over the `cmt_file_pv_t` R3-C2 binds
 *   3 WAL write      wal_write, wal_write_sync, wal_flush_and_sync
 *   2 WAL read       wal_search_end_height, wal_read_next
 *   1 decode_block   state.go:2005-2019 → nodus_cmt_block_decode into the
 *                    slot's storage
 *   1 now            the ONE clock, forwarded
 *   2 timer          timer_arm, timer_disarm — one pending deadline
 * The dispatch counted 27; the table has 26 (reported).
 *
 * ── PORT ROWS OF execution.go, and where each is ────────────────────────
 *   NewBlockExecutor :58 → nodus_cmt_blockexec_init; Store :85 →
 *   `->store`; CreateProposalBlock :101; ProcessProposal :162;
 *   ValidateBlock :190; ApplyVerifiedBlock :199; ApplyBlock :211 →
 *   nodus_cmt_blockexec_apply_block; applyBlock :222; ExtendVote :325;
 *   VerifyVoteExtension :356; Commit :387; buildLastCommitInfoFromStore
 *   :432; BuildLastCommitInfo :450; buildExtendedCommitInfoFromStore
 *   :495; BuildExtendedCommitInfo :512; validateValidatorUpdates :567;
 *   updateState :593; ExecCommitBlock :731 → nodus_cmt_exec_commit_block
 *   (the Handshaker that calls it is R3-C1's); pruneBlocks :773.
 *   validation.go validateBlock :15-150 → validate_block's body.
 *   YOK: BlockExecutorWithMetrics :50, SetEventBus :91, fireEvents
 *   :670-723 (events), every `blockExec.metrics` and `logger` line.
 *
 * ── PORTED HERE FROM OTHER FILES (no cmt_ home exists) ──────────────────
 *   types/evidence.go:81-92 `DuplicateVoteEvidence.ABCI` and :483-489
 *   `EvidenceList.ToABCI` (cmt_evidence.h left them as "ABCI application
 *   layer"); types/tx.go:107-116 `Txs.Validate` and :188-192
 *   `ComputeProtoSizeForTxs`; types/protobuf.go:43-48 `TM2PB.Validator`
 *   and :103-113 `PB2TM.ValidatorUpdates`; crypto/encoding/codec.go:42-63
 *   `PubKeyFromProto`'s nil-oneof refusal; state/tx_filter.go:10-26
 *   `TxPreCheck`/`TxPostCheck`. QUESTION in the report: a better home.
 *
 * ── THE CLOSURE PROBLEM, STATED ONCE ───────────────────────────────────
 * `mempool.Update` (execution.go:418-424) receives two CLOSURES,
 * `TxPreCheck(state)` and `TxPostCheck(state)` (tx_filter.go), each
 * capturing one number: `PreCheckMaxBytes(maxDataBytes)` and
 * `PostCheckMaxGas(maxGas)` (mempool.go:114-145). Here the closures are
 * their captured values — `nodus_cmt_pre_check_t{max_bytes}` and
 * `nodus_cmt_post_check_t{max_gas}` — and the mempool implementation
 * (R3-M) applies mempool.go:114-145 on them. RISK in the report.
 *
 * ── OWNERSHIP ──────────────────────────────────────────────────────────
 *   · The application owns the memory it returns until the next call of
 *     the same method (every response struct). The host copies what it
 *     keeps (a proposal's txs into the slot's arena, a vote extension
 *     into the per-height extension arena).
 *   · Every block slot has its own storage (`nodus_cmt_slot_storage_t`):
 *     the txs array and arena, the evidence arrays, the LastCommit and
 *     its signatures. `create_proposal_block` and `decode_block` write
 *     ONLY into the storage of the slot `out` is (the slot is found by
 *     pointer identity against `cmt_cs_slots_t.blocks`).
 *   · `apply_verified_block` builds the new state in a host-owned
 *     scratch and copies it into `in_out_state` ONLY on success: the
 *     reference returns `state, err` with the input state unchanged on
 *     every error path (:236, :250, :260, :277, :282, :286, :291, :303).
 *   · `validate_block` takes `const cmt_state_t *` while `VerifyCommit`
 *     writes the set's total-power cache (cmt_validation.h:288-290): the
 *     host copies `last_validators` into its own set and verifies on the
 *     copy. test_cmt_common.h's fixture punted on this (HOW IT CAN LIE
 *     3); the real host cannot.
 *
 * ── CAPACITY BOUNDS (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07) ─
 * `nodus_cmt_host_limits_t` is the caller's: transactions per block,
 * transaction bytes per block, evidence items per block. A block that
 * exceeds them is REFUSED (CMT_REJECT at the decode boundary, CMT_FAULT
 * where the reference would already hold the block). The reference's
 * slices are unbounded; the consensus parameter `Block.MaxBytes`
 * (D-25 rev 3) is the only bound it knows.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * The clock is `now` and is read by this module at exactly ONE site of
 * its own: `timer_arm` (`now + duration`, ticker.go:126). Every other
 * read is `cmt_cs`'s through the forwarded row. No randomness, no
 * unordered iteration (validator index order, transaction order,
 * evidence order — all the reference's).
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   state/execution.go   789 lines
 *   state/validation.go  150 lines
 *   state/services.go, state/tx_filter.go, mempool/mempool.go,
 *   mempool/nop_mempool.go, proxy/app_conn.go, abci/types/application.go,
 *   proto/tendermint/abci/types.proto, types/protobuf.go — pin table of
 *   the R3-B report. The report listed types/evidence.go, types/tx.go and
 *   crypto/encoding/codec.go as unpinned; all three are PINNED (rev 3 and
 *   its rev-2 addendum), hashes equal. Genuinely unpinned when the wave
 *   opened them, pinned by rev 16: libs/json/{encoder,decoder,structs}.go
 *   (the last-sign-state file), state/helpers_test.go and
 *   internal/test/tx.go (the test fixtures), libs/math/math.go.
 * Governing records: D-23 rev 4 (atlas-dec-cb08dde681aa3c4ab1d1f1b33cdb68e1,
 * APPROVED 2026-09-14), D-4 rev 3
 * (atlas-dec-d5ddcba654eb48d861c03a0ecd170718), D-25 rev 3
 * (atlas-dec-f8319da0758745dbe615150ed939c34a, APPROVED 2026-09-11), D-20 rev 3
 * (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19), umbrella rev 4
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8), PQ POLICY
 * (atlas-dec-652be084b95d02d253834906271e9fb0).
 */

#ifndef NODUS_WITNESS_CMT_HOST_H
#define NODUS_WITNESS_CMT_HOST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dnac/cmt_tmhash.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_params.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_results.h"
#include "dnac/cmt_privval.h"
#include "dnac/cmt_cs.h"

#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_cmt_wal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ abci/types.proto — the in-process request/response shapes ═══════
 * Field for field, in the .proto's order. IN-PROCESS: no wire codec
 * (only ResponseFinalizeBlock is stored — cmt_pb_store.h). Byte fields
 * are descriptors into memory the sender owns for the call. */

/** :433-437 Validator. `address` is the ML-DSA-87 address (32 bytes). */
typedef struct {
    uint8_t address[CMT_PB_ADDRESS_MAX];  /* 1 */
    size_t  address_len;
    int64_t power;                        /* 3 */
} nodus_abci_validator_t;

/** :444-449 VoteInfo. */
typedef struct {
    nodus_abci_validator_t validator;      /* 1 */
    int32_t                block_id_flag;  /* 3 cmt_pb_block_id_flag */
} nodus_abci_vote_info_t;

/** :451-462 ExtendedVoteInfo. */
typedef struct {
    nodus_abci_validator_t validator;            /* 1 */
    cmt_pb_bytes_t         vote_extension;       /* 3 */
    cmt_pb_bytes_t         extension_signature;  /* 4 */
    int32_t                block_id_flag;        /* 5 */
} nodus_abci_extended_vote_info_t;

/** :371-374 CommitInfo. `votes` NULL/0 is the reference's empty value. */
typedef struct {
    int32_t                 round;      /* 1 */
    nodus_abci_vote_info_t *votes;      /* 2 */
    size_t                  votes_len;
} nodus_abci_commit_info_t;

/** :379-386 ExtendedCommitInfo. */
typedef struct {
    int32_t                          round;   /* 1 */
    nodus_abci_extended_vote_info_t *votes;   /* 2 */
    size_t                           votes_len;
} nodus_abci_extended_commit_info_t;

/** :464-468 MisbehaviorType. */
typedef enum {
    NODUS_ABCI_MISBEHAVIOR_UNKNOWN             = 0,
    NODUS_ABCI_MISBEHAVIOR_DUPLICATE_VOTE      = 1,
    NODUS_ABCI_MISBEHAVIOR_LIGHT_CLIENT_ATTACK = 2
} nodus_abci_misbehavior_type_t;

/** :470-483 Misbehavior. */
typedef struct {
    int32_t                type;                /* 1 */
    nodus_abci_validator_t validator;           /* 2 */
    int64_t                height;              /* 3 */
    cmt_time_t             time;                /* 4 */
    int64_t                total_voting_power;  /* 5 */
} nodus_abci_misbehavior_t;

/** :76-83 RequestInitChain. */
typedef struct {
    cmt_time_t                       time;                 /* 1 */
    uint8_t                          chain_id[CMT_PB_CHAINID_MAX]; /* 2 */
    size_t                           chain_id_len;
    bool                             has_consensus_params; /* 3 POINTER */
    cmt_pb_consensus_params_t        consensus_params;
    const cmt_pb_validator_update_t *validators;           /* 4 */
    size_t                           validators_len;
    cmt_pb_bytes_t                   app_state_bytes;      /* 5 */
    int64_t                          initial_height;       /* 6 */
} nodus_abci_request_init_chain_t;

/** :243-247 ResponseInitChain. */
typedef struct {
    bool                             has_consensus_params; /* 1 POINTER */
    cmt_pb_consensus_params_t        consensus_params;
    const cmt_pb_validator_update_t *validators;           /* 2 */
    size_t                           validators_len;
    uint8_t                          app_hash[CMT_PB_HASH_MAX]; /* 3 */
    size_t                           app_hash_len;
} nodus_abci_response_init_chain_t;

/** :129-143 RequestPrepareProposal. */
typedef struct {
    int64_t                           max_tx_bytes;          /* 1 */
    const cmt_pb_bytes_t             *txs;                   /* 2 */
    size_t                            txs_len;
    nodus_abci_extended_commit_info_t local_last_commit;     /* 3 */
    const nodus_abci_misbehavior_t   *misbehavior;           /* 4 */
    size_t                            misbehavior_len;
    int64_t                           height;                /* 5 */
    cmt_time_t                        time;                  /* 6 */
    uint8_t                           next_validators_hash[CMT_PB_HASH_MAX]; /* 7 */
    size_t                            next_validators_hash_len;
    uint8_t                           proposer_address[CMT_PB_ADDRESS_MAX];  /* 8 */
    size_t                            proposer_address_len;
} nodus_abci_request_prepare_proposal_t;

/** :320-322 ResponsePrepareProposal. */
typedef struct {
    const cmt_pb_bytes_t *txs;   /* 1 */
    size_t                txs_len;
} nodus_abci_response_prepare_proposal_t;

/** :144-157 RequestProcessProposal. */
typedef struct {
    const cmt_pb_bytes_t           *txs;                    /* 1 */
    size_t                          txs_len;
    nodus_abci_commit_info_t        proposed_last_commit;   /* 2 */
    const nodus_abci_misbehavior_t *misbehavior;            /* 3 */
    size_t                          misbehavior_len;
    uint8_t                         hash[CMT_PB_HASH_MAX];  /* 4 */
    size_t                          hash_len;
    int64_t                         height;                 /* 5 */
    cmt_time_t                      time;                   /* 6 */
    uint8_t                         next_validators_hash[CMT_PB_HASH_MAX]; /* 7 */
    size_t                          next_validators_hash_len;
    uint8_t                         proposer_address[CMT_PB_ADDRESS_MAX];  /* 8 */
    size_t                          proposer_address_len;
} nodus_abci_request_process_proposal_t;

/** :326-331 ResponseProcessProposal.ProposalStatus. */
typedef enum {
    NODUS_ABCI_PROPOSAL_STATUS_UNKNOWN = 0,
    NODUS_ABCI_PROPOSAL_STATUS_ACCEPT  = 1,
    NODUS_ABCI_PROPOSAL_STATUS_REJECT  = 2
} nodus_abci_proposal_status_t;

/** :324-332 ResponseProcessProposal. */
typedef struct {
    int32_t status;   /* 1 */
} nodus_abci_response_process_proposal_t;

/** :158-173 RequestExtendVote. */
typedef struct {
    uint8_t                         hash[CMT_PB_HASH_MAX];  /* 1 */
    size_t                          hash_len;
    int64_t                         height;                 /* 2 */
    cmt_time_t                      time;                   /* 3 */
    const cmt_pb_bytes_t           *txs;                    /* 4 */
    size_t                          txs_len;
    nodus_abci_commit_info_t        proposed_last_commit;   /* 5 */
    const nodus_abci_misbehavior_t *misbehavior;            /* 6 */
    size_t                          misbehavior_len;
    uint8_t                         next_validators_hash[CMT_PB_HASH_MAX]; /* 7 */
    size_t                          next_validators_hash_len;
    uint8_t                         proposer_address[CMT_PB_ADDRESS_MAX];  /* 8 */
    size_t                          proposer_address_len;
} nodus_abci_request_extend_vote_t;

/** :334-336 ResponseExtendVote. */
typedef struct {
    cmt_pb_bytes_t vote_extension;   /* 1 */
} nodus_abci_response_extend_vote_t;

/** :174-182 RequestVerifyVoteExtension. */
typedef struct {
    uint8_t        hash[CMT_PB_HASH_MAX];                /* 1 */
    size_t         hash_len;
    uint8_t        validator_address[CMT_PB_ADDRESS_MAX]; /* 2 */
    size_t         validator_address_len;
    int64_t        height;                               /* 3 */
    cmt_pb_bytes_t vote_extension;                       /* 4 */
} nodus_abci_request_verify_vote_extension_t;

/** :340-347 ResponseVerifyVoteExtension.VerifyStatus. */
typedef enum {
    NODUS_ABCI_VERIFY_STATUS_UNKNOWN = 0,
    NODUS_ABCI_VERIFY_STATUS_ACCEPT  = 1,
    NODUS_ABCI_VERIFY_STATUS_REJECT  = 2
} nodus_abci_verify_status_t;

/** :338-348 ResponseVerifyVoteExtension. */
typedef struct {
    int32_t status;   /* 1 */
} nodus_abci_response_verify_vote_extension_t;

/** :183-198 RequestFinalizeBlock. */
typedef struct {
    const cmt_pb_bytes_t           *txs;                    /* 1 */
    size_t                          txs_len;
    nodus_abci_commit_info_t        decided_last_commit;    /* 2 */
    const nodus_abci_misbehavior_t *misbehavior;            /* 3 */
    size_t                          misbehavior_len;
    uint8_t                         hash[CMT_PB_HASH_MAX];  /* 4 */
    size_t                          hash_len;
    int64_t                         height;                 /* 5 */
    cmt_time_t                      time;                   /* 6 */
    uint8_t                         next_validators_hash[CMT_PB_HASH_MAX]; /* 7 */
    size_t                          next_validators_hash_len;
    uint8_t                         proposer_address[CMT_PB_ADDRESS_MAX];  /* 8 */
    size_t                          proposer_address_len;
} nodus_abci_request_finalize_block_t;

/** :352-370 ResponseFinalizeBlock IS cmt_pb_response_finalize_block_t. */
typedef cmt_pb_response_finalize_block_t nodus_abci_response_finalize_block_t;

/** :279-282 ResponseCommit (RequestCommit :104 is empty). */
typedef struct {
    int64_t retain_height;   /* 3 */
} nodus_abci_response_commit_t;

/**
 * proxy/app_conn.go:18-27 — `AppConnConsensus`: the seven methods, each
 * returning CMT_OK or the reference's `error` (any other value). The
 * application owns the memory it returns until the next call of the
 * same method. `Error()` (:19) is the connection's sticky error and has
 * no in-process counterpart.
 */
typedef struct {
    void *ctx;
    int (*init_chain)(void *ctx, const nodus_abci_request_init_chain_t *req,
                      nodus_abci_response_init_chain_t *resp);            /* :20 */
    int (*prepare_proposal)(void *ctx,
                            const nodus_abci_request_prepare_proposal_t *req,
                            nodus_abci_response_prepare_proposal_t *resp); /* :21 */
    int (*process_proposal)(void *ctx,
                            const nodus_abci_request_process_proposal_t *req,
                            nodus_abci_response_process_proposal_t *resp); /* :22 */
    int (*extend_vote)(void *ctx, const nodus_abci_request_extend_vote_t *req,
                       nodus_abci_response_extend_vote_t *resp);           /* :23 */
    int (*verify_vote_extension)(
            void *ctx, const nodus_abci_request_verify_vote_extension_t *req,
            nodus_abci_response_verify_vote_extension_t *resp);           /* :24 */
    int (*finalize_block)(void *ctx,
                          const nodus_abci_request_finalize_block_t *req,
                          nodus_abci_response_finalize_block_t *resp);    /* :25 */
    int (*commit)(void *ctx, nodus_abci_response_commit_t *resp);         /* :26 */
} nodus_cmt_app_t;

/* ══ mempool/mempool.go:31-102 — the rows the BlockExecutor calls ════ */

/** tx_filter.go:10-20 `TxPreCheck(state)` = `PreCheckMaxBytes(
 *  maxDataBytes)` (mempool.go:114-125) — the closure's captured value. */
typedef struct {
    int64_t max_bytes;
} nodus_cmt_pre_check_t;

/** tx_filter.go:24-26 `TxPostCheck(state)` = `PostCheckMaxGas(maxGas)`
 *  (mempool.go:129-145) — the closure's captured value. */
typedef struct {
    int64_t max_gas;
} nodus_cmt_post_check_t;

typedef struct {
    void *ctx;
    /** :46 ReapMaxBytesMaxGas(maxBytes, maxGas) Txs — into the caller's
     *  `out` array (a capacity bound of this port); the bytes are the
     *  mempool's until `update` removes them; the host copies. */
    int (*reap_max_bytes_max_gas)(void *ctx, int64_t max_bytes, int64_t max_gas,
                                  cmt_pb_bytes_t *out, size_t out_cap,
                                  size_t *out_len);
    void (*lock)(void *ctx);                                  /* :57 */
    void (*unlock)(void *ctx);                                /* :60 */
    /** :68-74 Update(height, txs, txResults, preFn, postFn) error */
    int (*update)(void *ctx, int64_t height, const cmt_pb_bytes_t *txs,
                  size_t txs_len,
                  const cmt_pb_stored_exec_tx_result_t *tx_results,
                  size_t tx_results_len, nodus_cmt_pre_check_t pre,
                  nodus_cmt_post_check_t post);
    int (*flush_app_conn)(void *ctx);                         /* :81 */
} nodus_cmt_mempool_if_t;

/** mempool/nop_mempool.go:24-75 — `NopMempool`, row for row for the five
 *  rows above (:36 Reap nil, :45 Lock, :48 Unlock, :51-59 Update nil,
 *  :62 FlushAppConn nil). W1's binding (D-4 rev 3). */
extern const nodus_cmt_mempool_if_t nodus_cmt_nop_mempool;

/* ══ state/services.go:47-52 (+ :68) — the evidence pool ═════════════ */

typedef struct {
    void *ctx;
    /** :48 PendingEvidence(maxBytes) (ev, size) — into the caller's array. */
    int (*pending_evidence)(void *ctx, int64_t max_bytes,
                            cmt_pb_evidence_t *out, size_t out_cap,
                            size_t *out_len, int64_t *out_size);
    int (*add_evidence)(void *ctx, const cmt_pb_evidence_t *ev);        /* :49 */
    int (*update)(void *ctx, const cmt_state_t *state,
                  const cmt_pb_evidence_t *evl, size_t evl_len);        /* :50 */
    int (*check_evidence)(void *ctx, const cmt_pb_evidence_t *evl,
                          size_t evl_len);                              /* :51 */
    int (*report_conflicting_votes)(void *ctx, const cmt_vote_t *vote_a,
                                    const cmt_vote_t *vote_b);          /* :68 */
} nodus_cmt_evpool_if_t;

/** state/services.go:57-68 — `EmptyEvidencePool`, row for row. W1's
 *  binding. */
extern const nodus_cmt_evpool_if_t nodus_cmt_empty_evpool;

/* ══ the BlockExecutor ═══════════════════════════════════════════════ */

/** The caller's capacity bounds (header). */
typedef struct {
    size_t max_txs;        /* transactions per block                      */
    size_t tx_arena_cap;   /* transaction bytes per block (≥ Block.MaxBytes
                              for a proposal the app fills to the brim)  */
    size_t max_evidence;   /* evidence items per block                    */
} nodus_cmt_host_limits_t;

/** One block slot's storage (cmt_cs.h "OWNERSHIP" (1)). */
typedef struct {
    nodus_cmt_block_decode_t dec;    /* txs, both evidence arrays, both
                                        commits and their signatures      */
    cmt_pb_arena_t           arena;  /* the transaction bytes             */
} nodus_cmt_slot_storage_t;

typedef struct {
    /* execution.go:25-45 */
    nodus_cmt_store_t      *store;      /* :27 store + :30 blockStore */
    nodus_cmt_app_t        *app;        /* :33 proxyApp               */
    nodus_cmt_mempool_if_t *mempool;    /* :40                        */
    nodus_cmt_evpool_if_t  *evpool;     /* :41                        */

    /* the other host rows forward to */
    nodus_cmt_wal_t        *wal;
    cmt_file_pv_t          *pv;         /* raw_sign is R3-C2's binding */
    cmt_now_fn              now;
    void                   *now_ctx;
    cmt_cs_slots_t         *slots;      /* the block slots the rows write */
    cmt_pb_arena_t         *ext_arena[2]; /* cmt_cs.h "OWNERSHIP" (2), by
                                             height parity (PACKAGE W4-X) */

    nodus_cmt_host_limits_t limits;

    /* ticker.go as one pending deadline */
    bool    timer_armed;
    int64_t timer_deadline_ns;

    /* per-slot storage */
    nodus_cmt_slot_storage_t slot[CMT_CS_BLOCK_SLOTS];

    /* row scratch, all heap */
    cmt_state_storage_t       *state_storage;   /* updateState's result   */
    cmt_state_t                state_scratch;
    cmt_valset_scratch_t      *valset_scratch;
    cmt_state_block_scratch_t *block_scratch;   /* MakeBlock's hashes     */
    cmt_validator_t           *vals_a;          /* LoadValidators results */
    cmt_validator_t           *vals_b;          /* VerifyCommit's copy    */
    cmt_validator_t           *changes;         /* PB2TM.ValidatorUpdates */
    nodus_abci_vote_info_t    *votes;           /* CommitInfo.Votes       */
    nodus_abci_extended_vote_info_t *ext_votes; /* ExtendedCommitInfo     */
    nodus_abci_misbehavior_t  *misbehavior;     /* EvidenceList.ToABCI    */
    cmt_pb_bytes_t            *reap_txs;        /* ReapMaxBytesMaxGas     */
    cmt_pb_arena_t             reap_arena;
    cmt_block_t               *tmp_block;       /* the FIRST MakeBlock    */
    cmt_commit_sig_t          *commit_sigs;     /* bs_load_block_commit   */
    cmt_commit_sig_t          *seen_sigs;       /* bs_load_seen_commit    */
    cmt_extended_commit_sig_t *ext_sigs;        /* bs_load_block_ext…     */
    cmt_pb_arena_t             ext_load_arena;
    cmt_commit_sig_t          *tocommit_sigs;   /* ExtendedCommit.ToCommit */
    uint8_t                   *marshal_scratch; /* block.Size()           */
    size_t                     marshal_scratch_cap;
    /* ORCHESTRATOR delta 3, item B — TxResultsHash's `det_results`/
     * `results`/`leaf_scratch`/`items` are GONE from this struct: they
     * were allocated ONCE at bind time, sized to `limits.max_txs`
     * (≈293 525 after round 1 raised it from 10), costing ≈26 MiB
     * resident forever for a worst case ordinary blocks never approach.
     * Verified (whole-tree grep) that nothing reads them outside
     * `nodus_cmt_update_state`'s own body — no cross-call reader exists,
     * unlike the application layer's `fb_pb` (an actual ABCI response
     * the CALLER reads after return) — so they are now fully LOCAL to
     * that function: calloc'd per apply, sized to `resp->tx_results_len`
     * (refused above `limits.max_txs` before anything is allocated,
     * the same rule as the application layer's byte-bound seam), and
     * freed via goto-cleanup before every return. See
     * `nodus_cmt_update_state`'s own comment for the per-apply sizing. */
    uint8_t                   *valset_hash_scratch; /* Validators.Hash()  */
    cmt_merkle_item_t         *valset_items;

    /**
     * TEST-ONLY fault point, runtime, off by default — the same
     * discipline as the apply engine's `V2AP_FAIL_*`
     * (nodus_witness_v2_apply.h:319-469): a field the tests set, never a
     * production caller. When true, `applyBlock` returns CMT_FAULT in the
     * ONE window between `Commit` returning (execution.go:290 — the
     * ledger transaction is COMMITTED) and `store.Save(state)`
     * (:302 — the state is not). That is the Handshaker's "we ran Commit
     * but didn't save the state" branch (consensus/replay.go:437-453),
     * and it is not reachable through `CMT_FAIL_POINT()` because that
     * needs a build option and an environment variable
     * (libs/fail/fail.go:9-47). No production path sets it.
     */
    bool test_fail_after_commit;
} nodus_cmt_blockexec_t;

/**
 * execution.go:58-83 `NewBlockExecutor(stateStore, logger, proxyApp,
 * mempool, evpool, blockStore, options...)` — the six stored fields plus
 * the forwarded rows; allocates every scratch buffer.
 * @return CMT_OK, CMT_FAULT (NULL, or an allocation failed).
 */
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
                             const nodus_cmt_host_limits_t *limits);

/** Frees the scratch; the collaborators stay the caller's. */
void nodus_cmt_blockexec_release(nodus_cmt_blockexec_t *ctx);

/**
 * ORCHESTRATOR delta 7, item A — bind (or unbind) the WAL AFTER
 * construction, mirroring the reference's `cs.wal = nilWAL{}` at
 * construction (state.go:174) followed by the REAL wal installed only
 * in `OnStart` (state.go:318-329's `loadWalFile`: `cs.OpenWAL` then
 * `cs.wal = wal`). `nodus_cmt_blockexec_init` is called with `wal =
 * NULL` (the port's own nilWAL — every `host_wal_*` row above treats a
 * NULL `ctx->wal` as the reference's nilWAL would); the caller
 * (`nodus_cmt_node_start`) calls this ONLY after `nodus_cmt_wal_open` +
 * `nodus_cmt_wal_start` both succeed, and `nodus_cmt_node_release` calls
 * it with `wal = NULL` to UNBIND before closing the WAL object itself —
 * so nothing can reach a freed WAL through `ctx->wal` during teardown.
 * @return CMT_OK, CMT_FAULT on a NULL `ctx`.
 */
int nodus_cmt_blockexec_set_wal(nodus_cmt_blockexec_t *ctx,
                                nodus_cmt_wal_t *wal);

/** Fills all 26 rows of `out` with this module's functions; `ctx` is the
 *  `host_ctx` for `cmt_cs_init`. @return CMT_OK, CMT_FAULT on NULL. */
int nodus_cmt_host_build(cmt_cs_host_t *out, nodus_cmt_blockexec_t *ctx);

/* ── the 6 BlockExecutor rows (also callable directly) ─────────────── */

int nodus_cmt_host_create_proposal_block(void *ctx, int64_t height,
                                         const cmt_state_t *state,
                                         const cmt_extended_commit_t *last_ext_commit,
                                         const uint8_t *proposer_addr,
                                         size_t proposer_addr_len,
                                         cmt_block_t *out);
int nodus_cmt_host_process_proposal(void *ctx, cmt_block_t *block,
                                    const cmt_state_t *state, bool *out_accept);
int nodus_cmt_host_validate_block(void *ctx, const cmt_state_t *state,
                                  cmt_block_t *block);
int nodus_cmt_host_apply_verified_block(void *ctx, const cmt_block_id_t *block_id,
                                        cmt_block_t *block,
                                        cmt_state_t *in_out_state);
int nodus_cmt_host_extend_vote(void *ctx, const cmt_vote_t *vote,
                               cmt_block_t *block, const cmt_state_t *state,
                               cmt_pb_bytes_t *out_ext);
int nodus_cmt_host_verify_vote_extension(void *ctx, const cmt_vote_t *vote);

/** execution.go:211-220 `ApplyBlock`: validateBlock, then applyBlock.
 *  @return CMT_OK; CMT_REJECT for `ErrInvalidBlock` (:216); the
 *  applyBlock failures as in `apply_verified_block`. */
int nodus_cmt_blockexec_apply_block(nodus_cmt_blockexec_t *ctx,
                                    const cmt_block_id_t *block_id,
                                    cmt_block_t *block,
                                    cmt_state_t *in_out_state);

/** execution.go:731-771 `ExecCommitBlock`: FinalizeBlock + Commit without
 *  touching the state; `out_app_hash` is the response's. The Handshaker
 *  that calls it (consensus/replay.go) is R3-C1's. */
int nodus_cmt_exec_commit_block(nodus_cmt_blockexec_t *ctx, cmt_block_t *block,
                                int64_t initial_height,
                                uint8_t out_app_hash[CMT_PB_HASH_MAX],
                                size_t *out_app_hash_len);

/** execution.go:773-789 `pruneBlocks`. */
int nodus_cmt_blockexec_prune_blocks(nodus_cmt_blockexec_t *ctx,
                                     int64_t retain_height,
                                     const cmt_state_t *state,
                                     uint64_t *out_pruned);

/* ── the timer, C only (the server tick calls these) ───────────────── */

/** true when armed and `now_ns` has reached the deadline; a true return
 *  CONSUMES the expiry (the ticker's channel receive, ticker.go:130-134),
 *  so it is delivered exactly once. */
bool nodus_cmt_host_timer_due(nodus_cmt_blockexec_t *ctx, int64_t now_ns);

/** @return true with the deadline when armed. */
bool nodus_cmt_host_next_deadline(const nodus_cmt_blockexec_t *ctx,
                                  int64_t *out_deadline_ns);

/* ── exposed for the tests ─────────────────────────────────────────── */

/** state/validation.go:15-150 `validateBlock(state, block)`. */
int nodus_cmt_validate_block(nodus_cmt_blockexec_t *ctx,
                             const cmt_state_t *state, cmt_block_t *block);

/** execution.go:567-591 `validateValidatorUpdates`. */
int nodus_cmt_validate_validator_updates(const cmt_pb_validator_update_t *updates,
                                         size_t n,
                                         const cmt_validator_params_t *params);

/** types/protobuf.go:103-113 `PB2TM.ValidatorUpdates` into `out`. */
int nodus_cmt_pb2tm_validator_updates(const cmt_pb_validator_update_t *updates,
                                      size_t n, cmt_validator_t *out,
                                      size_t out_cap);

/** execution.go:593-664 `updateState` into `ctx->state_scratch`. */
int nodus_cmt_update_state(nodus_cmt_blockexec_t *ctx, const cmt_state_t *state,
                           const cmt_block_id_t *block_id,
                           const cmt_header_t *header,
                           const cmt_pb_response_finalize_block_t *resp,
                           const cmt_validator_t *validator_updates,
                           size_t n_updates);

/** execution.go:450-483 `BuildLastCommitInfo` into `ctx->votes`. */
int nodus_cmt_build_last_commit_info(nodus_cmt_blockexec_t *ctx,
                                     const cmt_block_t *block,
                                     const cmt_validator_set_t *last_val_set,
                                     int64_t initial_height,
                                     nodus_abci_commit_info_t *out);

/** execution.go:512-565 `BuildExtendedCommitInfo` into `ctx->ext_votes`. */
int nodus_cmt_build_extended_commit_info(nodus_cmt_blockexec_t *ctx,
                                         const cmt_extended_commit_t *ec,
                                         const cmt_validator_set_t *val_set,
                                         int64_t initial_height,
                                         cmt_abci_params_t ap,
                                         nodus_abci_extended_commit_info_t *out);

/** types/evidence.go:483-489 `EvidenceList.ToABCI` into `ctx->misbehavior`. */
int nodus_cmt_evidence_to_abci(nodus_cmt_blockexec_t *ctx,
                               const cmt_evidence_data_t *ev,
                               const nodus_abci_misbehavior_t **out,
                               size_t *out_len);

/** types/tx.go:188-192 `ComputeProtoSizeForTxs` for one tx: the size
 *  of `Data{Txs: [tx]}` = 1 + uvarint(len) + len. */
int64_t nodus_cmt_compute_proto_size_for_tx(size_t tx_len);

/** types/tx.go:107-116 `Txs.Validate(maxSizeBytes)`. */
int nodus_cmt_txs_validate(const cmt_pb_bytes_t *txs, size_t n,
                           int64_t max_size_bytes);

/** state/tx_filter.go:10-26. */
int nodus_cmt_tx_pre_check(const cmt_state_t *state, nodus_cmt_pre_check_t *out);
nodus_cmt_post_check_t nodus_cmt_tx_post_check(const cmt_state_t *state);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_HOST_H */
