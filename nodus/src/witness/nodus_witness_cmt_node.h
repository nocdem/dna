/**
 * @file nodus/src/witness/nodus_witness_cmt_node.h
 * @brief THE STARTUP TABLE — cometbft @709fd12b's node construction and
 *        start over the Ledger V2 engine: `node/node.go:285-422`
 *        (NewNodeWithContext), `node/setup.go:551-611` (the genesis
 *        document under "genesisDoc"), `consensus/replay.go:201-565`
 *        (the Handshaker) with `consensus/replay_stubs.go:60-79` (the
 *        mock application), and `consensus/state.go:318-405` (OnStart).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W2, package R3-C1c. Nothing in the running chain calls
 * anything here; `nodus-server` still starts the legacy BFT lane. This is
 * nevertheless the FIRST PRODUCTION CALLER of `cmt_cs_init` (D-23 rev 5
 * (8)) — the object it builds is a complete, startable consensus node
 * minus the reactor and the tick, which are W3's.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IS HERE, IN THE REFERENCE'S ORDER ─────────────────────────────
 * `nodus_cmt_node_init` walks node.go:296-418 step for step:
 *
 *   node.go:296-303  initDBs + NewStore        → nodus_cmt_store_init
 *   node.go:305      LoadStateFromDBOrGenesis… → setup.go:556-587, below
 *   node.go:313      createAndStartProxyApp…   → the C1a application
 *   node.go:318-331  EventBus + IndexerService → NOT PORTED (no consumer)
 *   node.go:333-347  privValidator             → the C1b privval file,
 *                    built with `LoadOrGenFilePV` as the reference's own
 *                    caller builds it (setup.go:71, file.go:237-245)
 *   node.go:356-362  doHandshake               → the Handshaker, below
 *   node.go:364-370  stateStore.Load()         → the state is re-read
 *   node.go:379      createMempoolAnd…Reactor  → the Flood mempool
 *                                                (the REACTOR is W3's)
 *   node.go:381      createEvidenceReactor     → the empty evidence pool
 *   node.go:386-395  NewBlockExecutor          → nodus_cmt_blockexec_init
 *   node.go:397-403  offlineStateSyncHeight    → the store
 *   node.go:410-413  createConsensusReactor    → cmt_cs_init (the REACTOR
 *                                                is W3's)
 *   node.go:415-418  SetOfflineStateSyncHeight(0)
 *
 * and `nodus_cmt_node_start` walks state.go:318-405:
 *
 *   state.go:319-325 OpenWAL                   → nodus_cmt_wal_open/_start
 *                                                (this port's WAL is the
 *                                                HOST's SQLite log, D-15)
 *   state.go:338-343 catchupReplay             ┐
 *   state.go:393     checkDoubleSigningRisk    ├ all three already inside
 *   state.go:402     scheduleRound0            ┘ `cmt_cs_start`
 *
 * ── WHAT IS NOT HERE, AND WHOSE IT IS ──────────────────────────────────
 *   · the consensus REACTOR, the blocksync reactor, state sync, p2p and
 *     the TICK (node.go:405-408 the blocksync reactor, the reactor half
 *     of :410-413, :423-470 the switch and state sync, and OnStart
 *     :518-585) — W3. The seam where W3 registers its listener is named
 *     at `nodus_cmt_node_init`'s tail.
 *   · `raw_sign` — the ML-DSA-87 signature over a vote's sign bytes is
 *     R3-C2's binding (W1 recorded it). It is an OPTIONAL field of
 *     `nodus_cmt_node_opts_t` here: a caller that supplies one gets a
 *     signing node, a caller that does not gets a node whose
 *     `sign_vote` / `sign_proposal` rows FAULT when reached — the
 *     unbound-signer refusal inside the privval layer
 *     (shared/dnac/cmt_privval.c:400, :550). Nothing is invented.
 *   · `FilePVKey` (privval/file.go:47-53) — the private key is never
 *     written to disk on this chain (PQ POLICY); only the LAST-SIGN
 *     STATE file is, which is exactly what `nodus_cmt_privval_open`
 *     loads. Because there is no key file, `LoadOrGenFilePV`'s
 *     existence test moves onto the state file: DEVIATION R3-C1c-5, on
 *     `nodus_cmt_node_opts_t.privval_state_path`.
 *   · the EventBus and the indexer (node.go:318-331) — they exist in the
 *     reference so that a replayed block's transactions get indexed; this
 *     port has no indexer and no RPC to serve one, so the Handshaker's
 *     `SetEventBus` (replay.go:232-234) has no counterpart and every
 *     publish site is absent rather than stubbed.
 *
 * ── THE TRANSACTION RULE (D-23 rev 5 (5)) ──────────────────────────────
 * Every ledger apply on this path goes through the host's UNCONDITIONAL
 * bracket (`nodus_witness_cmt_host.c` `ledger_txn_begin` / the
 * application's `commit`). Two consequences are load-bearing here:
 *   1. the MOCK application's `commit` must issue the SQL `COMMIT`, not
 *      BaseApplication's empty response — see `nodus_cmt_mock_app_t`;
 *   2. the WAL is opened in `nodus_cmt_node_start`, OUTSIDE any ledger
 *      transaction (nodus_witness_cmt_wal.h's §B.4 caller contract). The
 *      Handshaker's applies have all committed by then, which is the
 *      reference's own order (node.go:360 precedes state.go:319).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Startup is not a consensus path, but two of its products are consensus
 * state and are derived deterministically:
 *   · the STATE written at replay.go:369 is a pure function of the stored
 *     genesis document (`cmt_state_make_genesis`) plus the application's
 *     InitChain answer, which the C1a application derives from committed
 *     ledger rows in a stable total order;
 *   · `LastResultsHash` at :367 is `cmt_merkle_empty_hash()` = H(""),
 *     a constant.
 * The only clock read here is the caller's `now` callback, and it is read
 * exactly where the reference reads one: never for a branch, only to
 * stamp the WAL rows and the privval file (D-20, the clock POLICY). The
 * genesis document is never completed from the clock — the loader refuses
 * a zero genesis time before that branch can be reached (D-18 rev 2).
 *
 * Reference @709fd12b (pin rev 19, atlas-dec-483ec17cbb352ef0ec2267ccd953339c):
 *   node/node.go:285-422          NORMATIVE, the startup order
 *   node/setup.go:551-611         NORMATIVE, genesisDocKey and the loader
 *   node/setup.go:173-190,        the three helpers the order above names
 *                :228-265, :307-340
 *   consensus/replay.go:201-565   NORMATIVE, the Handshaker
 *   consensus/replay_stubs.go:60-79  NORMATIVE, the mock application
 *   consensus/state.go:318-405    NORMATIVE, OnStart
 *   abci/types/application.go:40-42, :48-119 BaseApplication and its
 *                                 defaults
 *   proxy/app_conn.go, proxy/version.go  the Info request
 * Governing records: D-23 rev 5 (atlas-dec-cb08dde681aa3c4ab1d1f1b33cdb68e1,
 * APPROVED), D-18 rev 4 (atlas-dec-4e84dbb5629353b78af6d04d704bd744,
 * APPROVED) and its rev 5 (PROPOSED), D-24 rev 3
 * (atlas-dec-8a88ea40d4ac8cd6d8c361dca9b7b2c7), D-17 rev 7
 * (atlas-dec-9d96e2ec31ad4840cf258df21732b67f), D-4 rev 3
 * (atlas-dec-d5ddcba654eb48d861c03a0ecd170718), umbrella rev 6
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8 — the panic rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NODUS_WITNESS_CMT_NODE_H
#define NODUS_WITNESS_CMT_NODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dnac/cmt_config.h"
#include "dnac/cmt_cs.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_mem.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/cmt_privval.h"
#include "dnac/cmt_state.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cmt_app.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_cmt_privval.h"
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_cmt_wal.h"
#include "witness/nodus_witness_v2_gen.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ abci/types.proto — RequestInfo / ResponseInfo ════════════════════ */

/**
 * `ResponseInfo` (abci/types.proto, fields 1-5), as this port answers it.
 *
 * ⚠ DEVIATION R3-C1c-1, reported. In the reference the handshake's Info
 * is an APPLICATION row on the QUERY connection (proxy/app_conn.go:42,
 * abci/types/application.go:11). The application table package C1a landed
 * (`nodus_cmt_app_t`, nodus_witness_cmt_host.h:368-387)
 * has SEVEN rows and no `info` among them, and that header is read-only
 * for this package. The answer is therefore computed HERE, in the startup
 * table, from the very accessors the application itself uses for the same
 * two quantities (`nodus_witness_v2_tip_height`,
 * `nodus_witness_v2_committed_global_root`) — one reader per quantity is
 * preserved, the ROW is not. W3 may move it into the application table;
 * nothing else about the handshake changes if it does.
 *
 * `data` (field 1) is not carried: the reference logs it and nothing
 * else reads it.
 */
typedef struct {
    const char *version;                              /* 2 */
    uint64_t    app_version;                          /* 3 */
    int64_t     last_block_height;                    /* 4 */
    uint8_t     last_block_app_hash[CMT_PB_HASH_MAX]; /* 5 */
    size_t      last_block_app_hash_len;
} nodus_cmt_app_info_t;

/**
 * The ledger's `Info` answer.
 *
 * `last_block_height` is the successor tip (`nodus_witness_v2_tip_height`,
 * 0 on a chain whose only committed state is its genesis);
 * `last_block_app_hash` is the committed global root after that block
 * (`nodus_witness_v2_committed_global_root`, 64 bytes);
 * `app_version` is 0 — this application declares no ABCI app version and
 * D-4 rev 3 (2) writes `Version.App 0` into the genesis document;
 * `version` is the build's own `CMT_SOFTWARE_VERSION` (cmt_state.h:149,
 * defined by nodus/CMakeLists.txt from NODUS_VERSION_STRING), the port's
 * counterpart of `version.TMCoreSemVer` (proxy/version.go:12).
 *
 * @return CMT_OK; CMT_FAULT on NULL, on a ledger read failure, or when
 *         the tip height exceeds INT64_MAX (a node-local invariant —
 *         `RequestInfo`'s height is an int64 and replay.go:256-258
 *         refuses a negative one).
 */
int nodus_cmt_node_app_info(nodus_witness_t *w, nodus_cmt_app_info_t *out);

/* ══ consensus/replay_stubs.go:60-79 — the mock application ═══════════ */

/**
 * `mockProxyApp` (replay_stubs.go:72-79): an `abci.BaseApplication` whose
 * `FinalizeBlock` returns the STORED `ResponseFinalizeBlock` of the
 * height being replayed. It exists for exactly one reason, stated at
 * replay_stubs.go:56-58: "we don't want to call Commit() twice for the
 * same block on the real app" — the branch at replay.go:437-453, where
 * the ledger transaction of height h is already COMMITTED but the state
 * was not saved.
 *
 * ── WHY `commit` IS NOT BaseApplication's EMPTY ANSWER ─────────────────
 * In the reference `Commit` on the mock is `BaseApplication.Commit`
 * (application.go:56-58), a no-op returning an empty response, because
 * the reference's application owns its own storage and a mock that
 * touches none is correct. In THIS port the ledger connection is the
 * consensus store's connection and the HOST opens ONE transaction on it
 * before `finalize_block` and requires `app.commit` to CLOSE it (D-23
 * rev 5 (5), nodus_witness_cmt_host.c:1392-1396, unconditional). A mock
 * that returned without committing would leave the replay's transaction
 * open, and `nodus_cmt_ss_save` would then join it instead of being the
 * separate autocommit statement execution.go:302 requires — the exact
 * crash window this branch exists to heal would be re-created.
 *
 * So the mock's `commit` issues the SQL `COMMIT` and nothing else. The
 * transaction it closes carries ONLY the consensus store's own rows —
 * `SaveFinalizeBlockResponse`'s re-save of the response and
 * `updateState`'s validator/params rows — because the mock's
 * `finalize_block` runs no ledger statement at all. The ledger tables are
 * untouched, which is what "don't Commit twice" means here.
 */
typedef struct {
    /** The response loaded from `lastABCIResponseKey`, and its storage;
     *  `resp.tx_results` and friends POINT INTO the pools below, so both
     *  must outlive every `finalize_block` the Handshaker makes. */
    cmt_pb_response_finalize_block_t resp;
    cmt_pb_rfb_storage_t             storage;
    cmt_pb_event_t                  *pool_events;
    cmt_pb_event_attribute_t        *pool_attributes;
    cmt_pb_stored_exec_tx_result_t  *pool_tx_results;
    cmt_pb_validator_update_t       *pool_validator_updates;
    cmt_pb_arena_t                   arena;

    /** The ledger connection whose transaction `commit` closes. */
    sqlite3 *db;

    /* observable by the tests; the reference has no counterpart */
    int finalize_calls;
    int commit_calls;
} nodus_cmt_mock_app_t;

/**
 * Allocate the mock's pools and load the stored `ResponseFinalizeBlock`
 * of `height` through `nodus_cmt_ss_load_last_finalize_block_response`
 * (replay.go:439), applying the :443-449 fallback: a response whose
 * `app_hash` is EMPTY takes the one the Info handshake returned.
 *
 * @param info_app_hash / len the :448 fallback value; may be len 0.
 * @param max_txs the pool bound for `tx_results` — the response is this
 *        node's own product, so a stored response above it is a
 *        node-local invariant broken and the load FAULTs.
 * @return CMT_OK; CMT_REJECT when there is no stored response for that
 *         height (the reference's error return at :440-442); CMT_FAULT
 *         on NULL, allocation failure or a store fault.
 */
int nodus_cmt_mock_app_open(nodus_cmt_mock_app_t *m, nodus_cmt_store_t *store,
                            sqlite3 *db, int64_t height,
                            const uint8_t *info_app_hash,
                            size_t info_app_hash_len, size_t max_txs);

/** Frees the pools. The connection is not closed. NULL is a no-op. */
void nodus_cmt_mock_app_close(nodus_cmt_mock_app_t *m);

/** Fills all seven rows of `out` with the mock's functions: `finalize_block`
 *  and `commit` as described above, the other five as BaseApplication
 *  (application.go:64-66 InitChain, :84-95 PrepareProposal, :97-99
 *  ProcessProposal, :101-103 ExtendVote, :105-109 VerifyVoteExtension).
 *  @return CMT_OK, CMT_FAULT on NULL. */
int nodus_cmt_mock_app_build(nodus_cmt_app_t *out, nodus_cmt_mock_app_t *m);

/* ══ consensus/replay.go:201-565 — the Handshaker ═════════════════════ */

/**
 * `type Handshaker struct` (replay.go:201-210), with the port's
 * substitutions:
 *   · `stateStore` and `store` are ONE `nodus_cmt_store_t` — this port's
 *     state store and block store are two key spaces on one connection
 *     (nodus_witness_cmt_store.h);
 *   · `eventBus` has no counterpart (see the file header);
 *   · `logger` is QGP_LOG;
 *   · `w`, `now`/`now_ctx` and `limits` are what the port's transient
 *     block executors need and Go's `sm.NewBlockExecutor` gets from its
 *     closure over the node.
 */
typedef struct {
    nodus_cmt_store_t       *store;        /* :202 stateStore + :204 store */
    const cmt_genesis_doc_t *gendoc;       /* :206                         */
    nodus_witness_t         *w;            /* the Info answer's source     */
    cmt_now_fn               now;          /* the executors' clock row     */
    void                    *now_ctx;
    nodus_cmt_host_limits_t  limits;       /* the executors' capacity       */

    /** The two stand-ins `replayBlock` hands its fresh BlockExecutor
     *  (replay.go:529-531): `emptyMempool{}` (replay_stubs.go:15-52) and
     *  `sm.EmptyEvidencePool{}` (state/services.go:57-68). Held BY VALUE
     *  because `nodus_cmt_blockexec_init` takes non-const pointers and
     *  the module's tables are `const` — the same copy test_cmt_app.c:797
     *  makes. */
    nodus_cmt_mempool_if_t nop_mempool;
    nodus_cmt_evpool_if_t  empty_evpool;

    /** :203 `initialState`. The reference holds a COPY of the node's
     *  state and mutates it at :269-271; the node reloads from the store
     *  afterwards (node.go:364-370), so the copy is never read back.
     *  Owned here, with its own storage, for the same reason. */
    cmt_state_t          *initial_state;
    cmt_state_storage_t  *initial_storage;

    /** The block-loading storage `LoadBlock` needs (store.go:137-167).
     *  Go allocates per call; this port allocates once. */
    nodus_cmt_block_decode_t dec;
    cmt_pb_arena_t           dec_arena;
    uint8_t                 *dec_buf;
    size_t                   dec_buf_cap;

    int nblocks;                            /* :209 / :237-239 NBlocks()   */
} nodus_cmt_handshaker_t;

/**
 * `NewHandshaker(stateStore, state, store, genDoc)` (replay.go:212-224),
 * plus the storage this port's `LoadBlock` and transient executors need.
 * `state` is COPIED into `initial_state`.
 *
 * @return CMT_OK; CMT_FAULT on NULL or allocation failure; the code
 *         `cmt_state_copy` returns for a state it refuses.
 */
int nodus_cmt_handshaker_init(nodus_cmt_handshaker_t *h,
                              nodus_cmt_store_t *store,
                              const cmt_state_t *state,
                              const cmt_genesis_doc_t *gendoc,
                              nodus_witness_t *w,
                              cmt_now_fn now, void *now_ctx,
                              const nodus_cmt_host_limits_t *limits);

/** Frees everything `..._init` allocated; the collaborators stay the
 *  caller's. NULL is a no-op. */
void nodus_cmt_handshaker_release(nodus_cmt_handshaker_t *h);

/**
 * `HandshakeWithContext(ctx, proxyApp)` (replay.go:247-285): Info, the
 * :269-271 app-version assignment, then `ReplayBlocksWithContext`.
 *
 * @param app the REAL application table — the Handshaker builds the mock
 *        itself where the reference does (:450).
 * @return CMT_OK; CMT_FAULT for every failure. Every one of the
 *         reference's exits on this path — two `panic`s (:395, :399,
 *         :458), the two `assert*` panics (:545-553, :555-565) and the
 *         Err returns that make `NewNode` fail (:383, :387, :391) — is
 *         this node refusing to start, never a verdict about a peer's
 *         input: there is no peer in a handshake. Umbrella rev 6's panic
 *         rule maps all of them to CMT_FAULT and each site says so.
 */
int nodus_cmt_handshaker_handshake(nodus_cmt_handshaker_t *h,
                                   nodus_cmt_app_t *app);

/* ══ the mempool adapter ═════════════════════════════════════════════ */

/**
 * The five `nodus_cmt_mempool_if_t` rows (nodus_witness_cmt_host.h:403-420,
 * `mempool/mempool.go:31-102`) over the Flood mempool (`cmt_mem_t`).
 *
 * Two shape differences between the two C APIs, both mechanical:
 *   · the host row hands `cmt_pb_stored_exec_tx_result_t` (the STORED
 *     eight-field form) while `cmt_mem_update` takes the DETERMINISTIC
 *     four (`cmt_pb_exec_tx_result_t`), which is the `.det` sub-struct of
 *     the former (cmt_pb_store.h:270-278) — copied through `det` below;
 *   · the host row hands the CAPTURED VALUES of `TxPreCheck`/`TxPostCheck`
 *     (`max_bytes`, `max_gas`) while `cmt_mem_update` takes the closures,
 *     which `cmt_mem_pre_check_max_bytes` / `cmt_mem_post_check_max_gas`
 *     build. The closures' captured storage lives HERE, not on a stack
 *     frame: the mempool KEEPS the pair and calls it on every later
 *     CheckTx (clist_mempool.go:595-600).
 */
typedef struct {
    cmt_mem_t                    *mem;
    cmt_pb_exec_tx_result_t      *det;      /* n = det_cap              */
    size_t                        det_cap;
    cmt_mem_pre_check_max_bytes_t pre_storage;
    cmt_mem_post_check_max_gas_t  post_storage;
} nodus_cmt_node_mempool_t;

/* ══ the node ════════════════════════════════════════════════════════ */

/**
 * What the caller supplies. Zero it, then set what is named MANDATORY.
 */
typedef struct {
    /**
     * MANDATORY. `lss.filePath` (privval/file.go:82) — the last-sign
     * state file, which is what stops a double sign across a restart.
     *
     * `LoadOrGenFilePV` (file.go:237-245) is ported onto it, so the two
     * boots differ exactly as the reference's do:
     *   · THE FILE EXISTS → it is LOADED (:240 `LoadFilePV`), and a file
     *     that exists but is unreadable or malformed stops the node
     *     (:219, :223 `cmtos.Exit`). It is never regenerated over.
     *   · IT DOES NOT EXIST → an EMPTY state is generated and SAVED
     *     (:242-243 `GenFilePV` + `pv.Save()`), so after a first start
     *     the file is on disk at height 0, round 0, step `stepNone`
     *     (file.go:171-174). A save failure stops the node (:137-146).
     *
     * ⚠ DEVIATION R3-C1c-5, reported: the reference takes that
     * existence test on the KEY file (`FileExists(keyFilePath)`, :239),
     * and this port has no key file — the private key is never written
     * to disk (PQ policy) — so the test is taken on the STATE file, the
     * only file it has. `FileExists` (libs/os/os.go:58-61) is TRUE for
     * every `os.Stat` outcome except ENOENT, and that is reproduced:
     * a state file that cannot be statted is treated as PRESENT, never
     * silently replaced.
     */
    const char *privval_state_path;

    /** MANDATORY. The only clock on this path (D-20). */
    cmt_now_fn now;
    void      *now_ctx;

    /**
     * OPTIONAL — `GenesisDocProvider` (node/setup.go:45-48, called at
     * :563). The version-3 genesis document's BYTES, in the canonical
     * container the derivation and the join write.
     *
     * Consulted ONLY when `cmt_state` has no "genesisDoc" row — the
     * reference's `len(b) == 0` at :594-596. A row that EXISTS is
     * authority and the provider is never called, and that holds EVEN IF
     * THE ROW IS UNREADABLE: the reference panics there (:597-601), so
     * this port returns CMT_FAULT and leaves the row exactly as it is. A
     * start-up argument never replaces a chain's genesis document.
     *
     * When it IS consulted the bytes go through the SAME four-check
     * acceptance the stored row gets (`nodus_witness_v2_gen_stored_doc`)
     * and are saved under the key (:574, :606-611) — or the node refuses
     * to start and nothing is written. NULL with no row is a refusal, as
     * the reference's provider error is.
     */
    const uint8_t *genesis_doc_bytes;
    size_t         genesis_doc_len;

    /**
     * OPTIONAL — `pv.Key.PrivKey.Sign` (privval/file.go:328, :359).
     * R3-C2's production binding; NULL leaves the signing rows FAULTing
     * when reached, which is where an unbound signer belongs (see the
     * file header). A test supplies its own.
     */
    cmt_pv_raw_sign_fn raw_sign;
    void              *sign_ctx;

    /**
     * OPTIONAL capacity bounds for the block executor, the block loader
     * and the three block slots. A zeroed field takes the default named
     * at `nodus_cmt_node_init`.
     *
     * ⚠ DETERMINISM, and the reason the default is the only value a
     * PRODUCTION caller may use: Go allocates a block's storage per
     * block, this port preallocates it. `tx_arena_cap` is therefore the
     * largest block this node can DECODE or BUILD, and the consensus
     * params say the largest block the CHAIN allows
     * (`Block.MaxBytes`). A node given a smaller `tx_arena_cap` would
     * refuse a block every other node accepts — one node faulting where
     * the chain is healthy, which is a node-local divergence, not a
     * verdict. The default is `Block.MaxBytes` for exactly that reason;
     * a smaller value belongs to a test that knows its blocks are small.
     */
    nodus_cmt_host_limits_t limits;
} nodus_cmt_node_opts_t;

/**
 * Everything `node.go:285-422` builds, in the order it builds it.
 *
 * ⚠ NEVER A STACK OBJECT — the application context alone is ~85 KB, the
 * three `cmt_state_storage_t` are ~1 MB each and the genesis config is
 * ~240 KB. Every large member is a pointer and `..._init` allocates it.
 */
typedef struct {
    nodus_witness_t *w;                     /* BORROWED, the ledger      */

    /* node.go:296-303 */
    nodus_cmt_store_t store;
    bool              store_ready;

    /* node.go:305 / setup.go:556-587 — the genesis document */
    nodus_v2_gen_config_t   *gen_cfg;       /* the DECODED stored doc    */
    nodus_v2_gen_alloc_t    *gen_allocs;    /* its allocation list       */
    cmt_genesis_doc_t        doc;           /* the port's document       */
    cmt_genesis_validator_t *gvals;         /* doc.validators' storage   */

    /* node.go:305's second product — the State */
    cmt_state_storage_t *state_storage;
    cmt_state_t         *state;

    /* node.go:313 — the application */
    nodus_cmt_app_ledger_t *app_ctx;
    nodus_cmt_app_t         app_if;
    cmt_mem_app_t           app_mem_if;

    /* node.go:333-347 — the privval */
    nodus_cmt_privval_t pv_file;            /* the FILE side (C1b)       */
    bool                pv_file_open;
    cmt_file_pv_t      *pv;                 /* privval/file.go:157-160   */

    /* node.go:379 — the Flood mempool (the REACTOR is W3's) */
    cmt_mempool_config_t     mem_config;
    cmt_mem_t               *mem;
    bool                     mem_ready;
    nodus_cmt_node_mempool_t mem_ctx;
    nodus_cmt_mempool_if_t   mem_if;

    /* node.go:381 — the evidence pool stand-in (state/services.go:57-68) */
    nodus_cmt_evpool_if_t ev_if;

    /* node.go:386-395 — the BlockExecutor and the host table */
    nodus_cmt_wal_t         wal;
    bool                    wal_open;
    cmt_cs_slots_t         *slots;
    /* PACKAGE W4-X (register R3-W3-C2e-4): two arenas alternating by
     * height parity — cmt_cs.h "OWNERSHIP" (2). Both allocated by
     * nodus_cmt_node_init (64 KiB each), both freed by
     * nodus_cmt_node_release; borrowed by both `n->be` and `n->cs` as the
     * shared pair. */
    cmt_pb_arena_t          ext_arena[2];
    nodus_cmt_host_limits_t limits;
    nodus_cmt_blockexec_t  *be;
    bool                    be_ready;
    cmt_cs_host_t           host;

    /* node.go:410-418 — the consensus state */
    cmt_config_t         config;
    cmt_state_storage_t *cs_storage;
    cmt_state_storage_t *cs_scratch_storage;
    cmt_cs_t            *cs;
    bool                 cs_ready;
    /** FLEET-TM-R3 W3 (D-23 rev 7 item 17) — `nodus_cmt_node_start` no
     *  longer sets this itself: it stops at the WAL open, and `cs`'s
     *  actual start happens only inside `cmt_conr_start(conr)`, which the
     *  caller (nodus_witness_init) builds and owns because the reactor's
     *  host table lives on `nodus_cmt_net_t`, not on this struct (package
     *  C2b). The caller sets `n->cs_started = true` itself, directly,
     *  right after `cmt_conr_start` returns CMT_OK — this field is
     *  public exactly so it can. `nodus_cmt_node_release`'s cleanup order
     *  depends on it being accurate: an unset `cs_started` on a node
     *  whose reactor DID start would skip `cmt_cs_stop` on release. */
    bool                 cs_started;
    int64_t              offline_state_sync_height;

    cmt_now_fn now;
    void      *now_ctx;

    /** `Handshaker.NBlocks()` (replay.go:237-239) of the handshake this
     *  node performed — 0 on a clean restart. Diagnostic only. */
    int handshake_nblocks;
} nodus_cmt_node_t;

/**
 * `NewNodeWithContext` (node/node.go:285-422) over the ledger `w`.
 *
 * `w` must be an OPEN Ledger V2 successor chain at schema S14 whose
 * `cmt_state` carries the version-3 genesis document (or whose document
 * arrives through `opts->genesis_doc_bytes`). `w->db` is BORROWED and
 * must outlive the node.
 *
 * DEFAULTS when `opts->limits` is zeroed: `max_txs` = the SAME
 * byte-bound derivation the application uses for its own `env_bound`
 * (ORCHESTRATOR delta 1, item B — node_derive_env_bound, the .c file:
 * MaxDataBytes at the smallest possible committee, divided by an
 * envelope's framing minimum; NODUS_CMT_APP_MAX_TXS is RETIRED and no
 * longer exists as a compile-time bound anywhere in this pair of
 * files), `tx_arena_cap` = the genesis document's `Block.MaxBytes`,
 * `max_evidence` = 8.
 *
 * INVARIANTS enforced here, each a named FAULT (found by C1a):
 *   · the application's ledger connection and the store's are the SAME
 *     `sqlite3 *` — the host's transaction bracket opens on the store's
 *     connection and the ledger apply runs on the application's, and two
 *     handles would make the bracket a lie;
 *   · `limits.max_txs <= ` the application's derived `env_bound` (the
 *     SAME formula, recomputed here because the application is not
 *     built yet at this point) — the application REFUSES a request
 *     above its own array bound, so an executor sized larger would
 *     produce blocks its own application faults on.
 *
 * @return CMT_OK or CMT_FAULT, and CMT_FAULT for EVERY failure — a
 *         startup has no peer input, so nothing it can see is a verdict
 *         about somebody else's bytes; a callee's CMT_REJECT (a genesis
 *         document `ValidateAndComplete` refuses, a stored block that
 *         does not validate) is this node refusing to start and is
 *         narrowed here, with the callee's own code logged. On a failure
 *         the context is released internally and is safe to discard.
 */
int nodus_cmt_node_init(nodus_cmt_node_t *n, nodus_witness_t *w,
                        const nodus_cmt_node_opts_t *opts);

/**
 * The HOST's half of `(cs *State) OnStart()` (consensus/state.go:318-336
 * only): `nodus_cmt_wal_open` + `nodus_cmt_wal_start` (the EndHeight{0}
 * seed of wal.go:124-131).
 *
 * FLEET-TM-R3 W3 (D-23 rev 7 item 17) — THIS FUNCTION NO LONGER REACHES
 * `cmt_cs_start`. state.go:332-402 (the ticker start, the catch-up
 * replay, the double-sign check at :393-395, `scheduleRound0` at :402 —
 * all inside `cmt_cs_start`, shared/dnac/cmt_cs.h:966-982) is reached
 * only through `cmt_conr_start(conr)` (consensus/reactor.go:74-91,
 * `OnStart`), which this port's `cmt_conr_start` calls when
 * `!conr->wait_sync` — always true under D-23 rev 7 item 18's
 * no-blocksync deviation. The caller (nodus_witness_init) builds and
 * starts `cmt_conr_t` AFTER this function returns, because the reactor's
 * host table is a field of `nodus_cmt_net_t` (package C2b), which this
 * module does not depend on. See `nodus_cmt_node_start`'s own comment
 * (the .c file) for the discrepancy this leaves against D-23 rev 7 (17)'s
 * literal text.
 *
 * The WAL open happens OUTSIDE any ledger transaction: nothing here has
 * one open, and the Handshaker's applies all committed during
 * `nodus_cmt_node_init`. That is the reference's own order.
 *
 * @return CMT_OK; CMT_FAULT on NULL, a node not built, a WAL that cannot
 *         open, or a second call. `cmt_cs_start`'s own CMT_REJECT
 *         (double-sign refusal, :393-395) is the CALLER's return now,
 *         from `cmt_conr_start`, not this function's.
 */
int nodus_cmt_node_start(nodus_cmt_node_t *n);

/**
 * Stop and close, in reverse construction order: `cmt_cs_stop` then
 * `cmt_cs_free`; the WAL closed AFTER the state machine has stopped
 * (its `FlushAndSync` on close is wal.go:164-173's `OnStop`, the call at
 * :166); the executor,
 * the mempool, the privval file, the store; then every allocation. NULL
 * is a no-op, and a partly-built node is safe — every failure path of
 * `..._init` calls this.
 */
void nodus_cmt_node_release(nodus_cmt_node_t *n);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_NODE_H */
