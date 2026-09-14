/**
 * @file nodus/src/witness/nodus_witness_cmt_store.h
 * @brief cometbft @709fd12b `store/store.go` (BlockStore) and
 *        `state/store.go` (dbStore) over the two SQLite key/value tables
 *        of schema S14 (`cmt_blockstore`, `cmt_state`), plus
 *        `types/block_meta.go` and the block decode step the BlockStore
 *        and the host share.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W1, package R3-B. Nothing in the running chain calls
 * anything here; `nodus_witness_cmt_host.c` binds the block-store rows
 * of `cmt_cs_host_t` to it and R3-C1 flips the live path.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── THE MAPPING (D-17 rev 5, PROPOSED, operator ruling 2026-09-11) ─────
 *   dbm.DB           → one (key BLOB PRIMARY KEY, value BLOB NOT NULL)
 *                      table per store: `cmt_blockstore` for store.go,
 *                      `cmt_state` for state/store.go. A key is the
 *                      reference's byte string: `H:<h>`, `P:<h>:<i>`,
 *                      `C:<h>`, `SC:<h>`, `EC:<h>`, `BH:<hex>`,
 *                      `blockStore` (store.go:632-662); `stateKey`,
 *                      `validatorsKey:<h>`, `consensusParamsKey:<h>`,
 *                      `abciResponsesKey:<h>`, `lastABCIResponseKey`,
 *                      `offlineStateSyncHeightKey` (state/store.go:25-45,
 *                      state.go:20). `%v` of an int64 is its decimal
 *                      without padding; the lexical order of the keys is
 *                      irrelevant because every access is a point lookup
 *                      (the reference cannot range over them either —
 *                      store.go:56-57, state/store.go:258-262).
 *   db.Get           → SELECT value; a missing row is the reference's
 *                      `len(bz) == 0` (an absent key AND an empty value
 *                      are the same "not found" in the reference).
 *   db.Set / SetSync → INSERT OR REPLACE. On this connection
 *                      (`synchronous=NORMAL`, nodus_witness.c:487) a
 *                      COMMIT is a COMMIT: `Write`, `WriteSync` and
 *                      `SetSync` collapse into the same durability
 *                      class, said once here.
 *   dbm.Batch        → ONE SQLite transaction on the MAIN connection
 *                      (`BEGIN IMMEDIATE` … `COMMIT`), unless the
 *                      connection is ALREADY inside a transaction, in
 *                      which case the batch JOINS it — SQLite cannot nest,
 *                      and D-4 rev 3 point 5 lets the host wrap
 *                      ApplyVerifiedBlock in one transaction of its own.
 *   panic            → CMT_FAULT (a corrupted value, a SQLite failure);
 *   error return     → CMT_REJECT; "not found" → `*out_found = false`.
 *
 * ── NOT PORTED, with the reason ─────────────────────────────────────────
 *   · `addCaches` and the three `lru.Cache` reads/writes (store.go:57-59,
 *     :82-97, :265-268/:284, :292-295/:311, :320-323/:341) — an external
 *     library (hashicorp/golang-lru) whose only observable effect is the
 *     reference's OWN asymmetry: `PruneBlocks` evicts only the extended
 *     commit cache (:405) and `DeleteLatestBlock` evicts nothing, so a
 *     pruned commit can still be served from the reference's cache. Here
 *     every load reads the table, so a pruned commit is "not found".
 *     Recorded as a DEVIATION (CLAUDE.md's cache-symmetry rule is the
 *     reason a cache with that asymmetry is not reproduced).
 *   · `mtx` (store.go:53) — a single-threaded event loop.
 *   · `LoadFromDBOrGenesisFile` (state/store.go:118-131) — the JSON
 *     genesis FILE is the host's (cmt_genesis.h); the doc variant is
 *     ported.
 *   · `responseFinalizeBlockFromLegacy` (:743-799) and the legacy branch
 *     of `LoadFinalizeBlockResponse` (:432-445) and of
 *     `LoadLastFinalizeBlockResponse` (:478-485) — this chain has no
 *     legacy ABCI format (D-23 rev 4). The reference takes the branch on
 *     `err != nil || resp.AppHash == nil` (:431), so a VALID response
 *     with an EMPTY app hash takes it too; ported as written, the branch
 *     is CMT_FAULT here, and a genuine empty app hash is therefore not
 *     loadable through `LoadFinalizeBlockResponse` (the reference's own
 *     tests give it a one-byte AppHash for this reason).
 *   · `Close` (store.go:627, state/store.go:730) — the connection is the
 *     witness's, borrowed.
 *   · `IsEmpty(store)` (state/store.go:106-112) — `Load` + `IsEmpty`;
 *     kept as the two calls.
 *   · `saveBlockPart`'s `db.Set` branch for a part set larger than
 *     `maxBlockPartsToBatch` (store.go:541, :590-594): inside one SQLite
 *     transaction both branches are one write. DEVIATION: the reference
 *     can crash between an individually written part and the meta and
 *     leave orphan parts; SQLite leaves nothing. A strengthening.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * No clock: `PruneBlocks` compares the STATE's LastBlockTime to the
 * header's time (store.go:377 through evidence/verify.go:295-303), both
 * on-chain values. No unordered iteration: every loop is over heights or
 * list order.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   store/store.go       765 lines
 *   state/store.go       839 lines
 *   types/block_meta.go   86 lines
 *   evidence/verify.go   303 lines (:295-303 IsEvidenceExpired;
 *     6025cb953abb6fbe955b2c22fed82472f630c98102771c3eba0e8b074508875e —
 *     the R3-B report called this unpinned; it is PINNED, rev 12)
 *   libs/math/safemath.go 65 lines (:36-43;
 *     be592544331912400aecaee1ccdc8834afdf8508857d32d475e3f6bfaf3b33d2 —
 *     the report called this unpinned; it is PINNED, rev 3)
 *   libs/math/math.go     31 lines (:3-8; genuinely unpinned when opened,
 *     90148a8e991c5060237ca6fb78440ce2585ca071844e36273c7a53fc601babcf,
 *     pinned by rev 16)
 *   config/config.go    1283 lines (:1154 DiscardABCIResponses default)
 * Governing records: D-17 rev 5 (atlas-dec-9d96e2ec31ad4840cf258df21732b67f,
 * PROPOSED, operator ruling 2026-09-11), D-23 rev 4
 * (atlas-dec-cb08dde681aa3c4ab1d1f1b33cdb68e1, PROPOSED, operator ruling
 * 2026-09-11), D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718),
 * umbrella rev 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8).
 */

#ifndef NODUS_WITNESS_CMT_STORE_H
#define NODUS_WITNESS_CMT_STORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <sqlite3.h>

#include "dnac/cmt_tmhash.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_params.h"
#include "dnac/cmt_results.h"

#ifdef __cplusplus
extern "C" {
#endif

/** store.go:25 `maxBlockPartsToBatch` — kept for the row, moot in SQLite
 *  (header). */
#define NODUS_CMT_MAX_BLOCK_PARTS_TO_BATCH 10

/** state/store.go:27 `valSetCheckpointInterval`. */
#define NODUS_CMT_VALSET_CHECKPOINT_INTERVAL 100000

/** The longest key this module builds: `P:<int64>:<int>` = 2 + 20 + 1 +
 *  11 + NUL; `BH:` + 128 hex + NUL is the other bound. */
#define NODUS_CMT_STORE_KEY_MAX 160

/* ══ types/block_meta.go ═════════════════════════════════════════════ */

/** block_meta.go:12-17 — `type BlockMeta struct`. `cmt_header_t` IS
 *  `cmt_pb_header_t` and `cmt_block_id_t` IS `cmt_pb_block_id_t`, so the
 *  domain struct is the wire struct (cmt_pb_store.h). */
typedef cmt_pb_block_meta_t nodus_cmt_block_meta_t;

/** block_meta.go:20-27 — `NewBlockMeta(block, blockParts)`: BlockID
 *  {block.Hash(), blockParts.Header()}, block.Size(), block.Header,
 *  len(block.Txs). `scratch` is `Size()`'s marshal target
 *  (cmt_block.h:874-876). @return CMT_OK, CMT_REJECT, CMT_FAULT. */
int nodus_cmt_new_block_meta(cmt_block_t *block, const cmt_part_set_t *parts,
                             uint8_t *scratch, size_t scratch_cap,
                             nodus_cmt_block_meta_t *out);

/** block_meta.go:51-74 — `BlockMetaFromTrustedProto`: BlockIDFromProto
 *  (:58), HeaderFromProto (:63), the two ints. The wire struct is the
 *  domain struct, so this VALIDATES in place. */
int nodus_cmt_block_meta_from_trusted_proto(nodus_cmt_block_meta_t *bm,
                                            uint64_t block_protocol);

/** block_meta.go:77-86 — `ValidateBasic`: BlockID.ValidateBasic and
 *  BlockID.Hash == Header.Hash(). */
int nodus_cmt_block_meta_validate_basic(const nodus_cmt_block_meta_t *bm);

/** block_meta.go:43-49 — `BlockMetaFromProto`: the trusted form, then
 *  ValidateBasic. */
int nodus_cmt_block_meta_from_proto(nodus_cmt_block_meta_t *bm,
                                    uint64_t block_protocol);

/* ══ the block decode step, shared by LoadBlock and the host ═════════ */

/**
 * Storage for `proto.Unmarshal(buf, pbb)` + `types.BlockFromProto(pbb)`
 * (store.go:143-165; state.go:2005-2019). Two sets because the decoder
 * fills a proto VIEW and `cmt_block_from_proto` copies out of it into
 * the domain block; the txs array and the arena are SHARED (DataFromProto
 * is the identity, cmt_block.h:690-696). All caller-owned, all heap.
 */
typedef struct {
    /* the proto view's storage */
    cmt_pb_bytes_t    *txs;             size_t txs_cap;
    cmt_pb_evidence_t *pb_evidence;     size_t pb_evidence_cap;
    cmt_commit_sig_t  *pb_sigs;         size_t pb_sigs_cap;
    cmt_pb_arena_t    *arena;
    cmt_commit_t       pb_last_commit;  /* uses pb_sigs */
    cmt_block_t        pb_block;        /* the view itself */
    /* the domain block's storage */
    cmt_pb_evidence_t *evidence;        size_t evidence_cap;
    cmt_commit_sig_t  *sigs;            size_t sigs_cap;
    cmt_commit_t       last_commit;     /* uses sigs */
} nodus_cmt_block_decode_t;

/**
 * store.go:154-165 / state.go:2011-2018: `cmt_pb_block_unmarshal` into
 * the view, then `cmt_block_from_proto` (which ends in ValidateBasic)
 * into `out`. `out->data.txs` and `out->last_commit` point into `st`.
 * @return CMT_OK; CMT_REJECT for bytes that do not decode or a block
 *         that fails ValidateBasic; CMT_FAULT on NULL.
 */
int nodus_cmt_block_decode(const uint8_t *bytes, size_t len,
                           nodus_cmt_block_decode_t *st, cmt_block_t *out);

/* ══ the store ═══════════════════════════════════════════════════════ */

typedef struct {
    sqlite3 *db;                 /* BORROWED — the witness's main handle */

    /* store.go:55-56 */
    int64_t base;
    int64_t height;

    /* state/store.go:104 `StoreOptions.DiscardABCIResponses`
     * (config/config.go:1154 default false) */
    bool discard_abci_responses;

    /* prepared statements, both tables */
    sqlite3_stmt *bs_get, *bs_set, *bs_del;
    sqlite3_stmt *ss_get, *ss_set, *ss_del;

    /* heap scratch: one marshal buffer sized for the widest value (a
     * State with three full sets), the proto-side storage of the three
     * validator sets, and the proto-side signature storage the commit
     * loaders decode into before FromProto copies out. */
    uint8_t                   *buf;
    size_t                     buf_cap;
    cmt_pb_validator_t        *pb_vals[3];
    cmt_commit_sig_t          *pb_sigs;
    cmt_extended_commit_sig_t *pb_ext_sigs;
    cmt_pb_evidence_t         *pb_evidence;      /* PruneBlocks' meta loads
                                                    need none; kept NULL */
    bool                       own_txn;          /* this call opened it   */
} nodus_cmt_store_t;

/**
 * `NewBlockStore(db)` (store.go:66-75: `LoadBlockStoreState`, :679-702,
 * with its `Height > 0 && Base == 0 → Base = 1` compatibility rule
 * :697-699) and `NewStore(db, options)` (state/store.go:115-117) on the
 * same borrowed connection. Tables must exist (schema S14).
 * @return CMT_OK, CMT_FAULT.
 */
int nodus_cmt_store_init(nodus_cmt_store_t *s, sqlite3 *db,
                         bool discard_abci_responses);

/** Finalizes statements and frees scratch; the connection stays open. */
void nodus_cmt_store_release(nodus_cmt_store_t *s);

/* ── store/store.go — BlockStore ───────────────────────────────────── */

/** :99-103 IsEmpty, :106-110 Base, :113-117 Height, :120-127 Size. */
bool    nodus_cmt_bs_is_empty(const nodus_cmt_store_t *s);
int64_t nodus_cmt_bs_base(const nodus_cmt_store_t *s);
int64_t nodus_cmt_bs_height(const nodus_cmt_store_t *s);
int64_t nodus_cmt_bs_size(const nodus_cmt_store_t *s);

/** :130-137 LoadBaseMeta. `*out_found` false when base is 0 or the meta
 *  is absent. */
int nodus_cmt_bs_load_base_meta(nodus_cmt_store_t *s,
                                nodus_cmt_block_meta_t *out, bool *out_found);

/** :139-166 LoadBlock: the meta, every part concatenated into `buf`
 *  (`*out_found` false if any is missing, :146-151), then the decode
 *  step. A block that does not decode is the reference's panic (:158,
 *  :163) → CMT_FAULT. */
int nodus_cmt_bs_load_block(nodus_cmt_store_t *s, int64_t height,
                            uint8_t *buf, size_t buf_cap,
                            nodus_cmt_block_decode_t *st, cmt_block_t *out,
                            bool *out_found);

/** :170-186 LoadBlockByHash: `BH:<hex>` → decimal height → LoadBlock. A
 *  value that does not parse as an int64 is the panic at :183. */
int nodus_cmt_bs_load_block_by_hash(nodus_cmt_store_t *s,
                                    const uint8_t *hash, size_t hash_len,
                                    uint8_t *buf, size_t buf_cap,
                                    nodus_cmt_block_decode_t *st,
                                    cmt_block_t *out, bool *out_found);

/** :190-212 LoadBlockPart: `cmt_pb_part_unmarshal` (payload into
 *  `arena`) then PartFromProto (:206). */
int nodus_cmt_bs_load_block_part(nodus_cmt_store_t *s, int64_t height,
                                 int index, cmt_pb_arena_t *arena,
                                 cmt_part_t *out, bool *out_found);

/** :216-237 LoadBlockMeta: unmarshal (:227) then
 *  BlockMetaFromTrustedProto (:232). */
int nodus_cmt_bs_load_block_meta(nodus_cmt_store_t *s, int64_t height,
                                 nodus_cmt_block_meta_t *out, bool *out_found);

/** :241-258 LoadBlockMetaByHash. */
int nodus_cmt_bs_load_block_meta_by_hash(nodus_cmt_store_t *s,
                                         const uint8_t *hash, size_t hash_len,
                                         nodus_cmt_block_meta_t *out,
                                         bool *out_found);

/** :263-286 LoadBlockCommit: unmarshal into module scratch, then
 *  CommitFromProto (:280) into the CALLER's `sigs` — the `Clone()` of
 *  :285 is that copy. */
int nodus_cmt_bs_load_block_commit(nodus_cmt_store_t *s, int64_t height,
                                   cmt_commit_sig_t *sigs, size_t sigs_cap,
                                   cmt_commit_t *out, bool *out_found);

/** :290-313 LoadBlockExtendedCommit: unmarshal (extensions into `arena`)
 *  then ExtendedCommitFromProto (:307) into the caller's `sigs`. */
int nodus_cmt_bs_load_block_extended_commit(nodus_cmt_store_t *s,
                                            int64_t height,
                                            cmt_extended_commit_sig_t *sigs,
                                            size_t sigs_cap,
                                            cmt_pb_arena_t *arena,
                                            cmt_extended_commit_t *out,
                                            bool *out_found);

/** :318-342 LoadSeenCommit. */
int nodus_cmt_bs_load_seen_commit(nodus_cmt_store_t *s, int64_t height,
                                  cmt_commit_sig_t *sigs, size_t sigs_cap,
                                  cmt_commit_t *out, bool *out_found);

/** :345-432 PruneBlocks. `*out_evidence_point` is the reference's second
 *  return; -1 on every error (:347, :352, :356). The 1000-block flushes
 *  (:419-426) and the final `WriteSync` (:428) are each one COMMIT.
 *  @return CMT_OK; CMT_REJECT for the three argument errors; CMT_FAULT. */
int nodus_cmt_bs_prune_blocks(nodus_cmt_store_t *s, int64_t height,
                              const cmt_state_t *state,
                              uint64_t *out_pruned,
                              int64_t *out_evidence_point);

/** :434-457 SaveBlock. The reference panics on every failure inside;
 *  CMT_FAULT here. `scratch` is the marshal target for the parts, the
 *  meta and the commits — at least `cmt_block_size`'s need. */
int nodus_cmt_bs_save_block(nodus_cmt_store_t *s, cmt_block_t *block,
                            const cmt_part_set_t *parts,
                            const cmt_commit_t *seen_commit,
                            uint8_t *scratch, size_t scratch_cap);

/** :465-500 SaveBlockWithExtendedCommit: EnsureExtensions(true) (:470),
 *  saveBlockToBatch with `ToCommit()` (:478), `EC:<h>` (:483-487).
 *  `commit_sigs` is `ToCommit()`'s storage. */
int nodus_cmt_bs_save_block_with_extended_commit(
        nodus_cmt_store_t *s, cmt_block_t *block, const cmt_part_set_t *parts,
        const cmt_extended_commit_t *seen_ext_commit,
        cmt_commit_sig_t *commit_sigs, size_t commit_sigs_cap,
        uint8_t *scratch, size_t scratch_cap);

/** :617-624 SaveSeenCommit (a lone `db.Set`). */
int nodus_cmt_bs_save_seen_commit(nodus_cmt_store_t *s, int64_t height,
                                  const cmt_commit_t *seen_commit,
                                  uint8_t *scratch, size_t scratch_cap);

/** :735-764 DeleteLatestBlock. */
int nodus_cmt_bs_delete_latest_block(nodus_cmt_store_t *s);

/** :679-702 LoadBlockStoreState (exposed for the tests). */
int nodus_cmt_bs_load_block_store_state(nodus_cmt_store_t *s,
                                        cmt_pb_block_store_state_t *out);

/** :664-666 SaveBlockStoreState — a lone `SetSync` (exposed for the
 *  tests; the reference marks it deprecated and keeps it). */
int nodus_cmt_bs_save_block_store_state(nodus_cmt_store_t *s,
                                        const cmt_pb_block_store_state_t *bss);

/* ── state/store.go — dbStore ──────────────────────────────────────── */

/** :135-151 LoadFromDBOrGenesisDoc: `Load`, and if empty
 *  `MakeGenesisState(genesisDoc)` (cmt_state_make_genesis). `out` must
 *  be `cmt_state_init`ialised with its own storage. */
int nodus_cmt_ss_load_from_db_or_genesis_doc(nodus_cmt_store_t *s,
                                             cmt_genesis_doc_t *genesis_doc,
                                             cmt_now_fn now, void *now_ctx,
                                             cmt_valset_scratch_t *scratch,
                                             cmt_state_t *out);

/** :154-179 Load / loadState: an absent row leaves `out` EMPTY
 *  (`cmt_state_is_empty`); a row that does not unmarshal is the
 *  `cmtos.Exit` of :171 → CMT_FAULT; a FromProto error → CMT_REJECT. */
int nodus_cmt_ss_load(nodus_cmt_store_t *s, cmt_state_t *out);

/** :181-217 Save / save: the two ValidatorsInfo rows (:198, :203), the
 *  ConsensusParamsInfo row (:207), `stateKey` (:211), one COMMIT
 *  (:214 WriteSync — a failure there is a panic → CMT_FAULT). */
int nodus_cmt_ss_save(nodus_cmt_store_t *s, const cmt_state_t *state);

/** :220-262 Bootstrap. */
int nodus_cmt_ss_bootstrap(nodus_cmt_store_t *s, const cmt_state_t *state);

/** :264-395 PruneStates. `vals_storage`/`scratch` are what the
 *  re-materialisation of a kept height needs (:319-336 through
 *  `LoadValidators`). */
int nodus_cmt_ss_prune_states(nodus_cmt_store_t *s, int64_t from, int64_t to,
                              int64_t evidence_threshold_height,
                              cmt_validator_t *vals_storage, size_t vals_cap,
                              cmt_valset_scratch_t *scratch);

/** :404-406 TxResultsHash: `types.NewResults(txResults).Hash()`.
 *  `results`/`leaf_scratch`/`items` are cmt_results.h's storage. */
int nodus_cmt_ss_tx_results_hash(const cmt_pb_exec_tx_result_t *tx_results,
                                 size_t n, cmt_abci_results_t *results,
                                 uint8_t *leaf_scratch, size_t leaf_cap,
                                 cmt_merkle_item_t *items, size_t items_cap,
                                 uint8_t out[CMT_TMHASH_SIZE]);

/** :412-448 LoadFinalizeBlockResponse. @return CMT_OK; CMT_REJECT for
 *  DiscardABCIResponses (:413-415) and for an absent row (:421-423,
 *  ErrNoABCIResponsesForHeight); CMT_FAULT for the legacy branch
 *  (:431-445 — see the header) and SQLite failures. */
int nodus_cmt_ss_load_finalize_block_response(nodus_cmt_store_t *s,
                                              int64_t height,
                                              cmt_pb_rfb_storage_t *storage,
                                              cmt_pb_response_finalize_block_t *out);

/** :454-488 LoadLastFinalizeBlockResponse. @return CMT_OK; CMT_REJECT for
 *  no row (:460-462) and a height mismatch (:472-474); CMT_FAULT for the
 *  `cmtos.Exit` of :467 and the legacy branch (:479-485). */
int nodus_cmt_ss_load_last_finalize_block_response(
        nodus_cmt_store_t *s, int64_t height, cmt_pb_rfb_storage_t *storage,
        cmt_pb_response_finalize_block_t *out);

/** :494-528 SaveFinalizeBlockResponse: `abciResponsesKey:<h>` unless
 *  discarding (:507-515), then `lastABCIResponseKey` (:519-527). The nil
 *  stripping of :496-502 has no C counterpart (the array holds values). */
int nodus_cmt_ss_save_finalize_block_response(
        nodus_cmt_store_t *s, int64_t height,
        const cmt_pb_response_finalize_block_t *resp);

/** :534-586 LoadValidators, with `lastStoredHeightFor` (:588-591) and
 *  the `IncrementProposerPriority(SafeConvertInt32(height -
 *  lastStoredHeight))` replay (:570) — SafeConvertInt32's panic
 *  (safemath.go:36-43) is CMT_FAULT, node-local. `out` must be
 *  `cmt_validator_set_init`ialised. @return CMT_OK; CMT_REJECT for
 *  ErrNoValSetForHeight (:537) and the :556-562 error; CMT_FAULT for
 *  the `cmtos.Exit` of :606. */
int nodus_cmt_ss_load_validators(nodus_cmt_store_t *s, int64_t height,
                                 cmt_validator_set_t *out);

/** :639-666 LoadConsensusParams. @return CMT_OK; CMT_REJECT for :646 and
 *  :652-657; CMT_FAULT for the `cmtos.Exit` of :681. */
int nodus_cmt_ss_load_consensus_params(nodus_cmt_store_t *s, int64_t height,
                                       cmt_consensus_params_t *out);

/** :709-715 SetOfflineStateSyncHeight — `binary.PutVarint` (zigzag,
 *  :823-827). */
int nodus_cmt_ss_set_offline_state_sync_height(nodus_cmt_store_t *s,
                                               int64_t height);

/** :718-733 GetOfflineStateSyncHeight — `binary.Varint` (:818-821);
 *  CMT_REJECT for "value empty" (:727) and a negative height (:731). */
int nodus_cmt_ss_get_offline_state_sync_height(nodus_cmt_store_t *s,
                                               int64_t *out);

/* ── exposed for the tests ─────────────────────────────────────────── */

/** evidence/verify.go:295-303 — `IsEvidenceExpired`. `time_now.Sub(
 *  time_ev)` saturates like Go's (time.go:884-907). */
bool nodus_cmt_is_evidence_expired(int64_t height_now, cmt_time_t time_now,
                                   int64_t height_ev, cmt_time_t time_ev,
                                   const cmt_evidence_params_t *params);

/** state/store.go:588-591 — `lastStoredHeightFor`. */
int64_t nodus_cmt_last_stored_height_for(int64_t height,
                                         int64_t last_height_changed);

/** state/store.go:818-827 — `int64ToBytes` / `int64FromBytes`
 *  (encoding/binary's zigzag varint). */
size_t  nodus_cmt_int64_to_bytes(int64_t v, uint8_t out[10]);
int64_t nodus_cmt_int64_from_bytes(const uint8_t *in, size_t len);

/** Raw access to the two tables, for the tests and the host: `key` is
 *  the reference's byte string. `*out_len` 0 = not found. `value` is a
 *  pointer into a statement's row that is valid until the next call. */
int nodus_cmt_store_get(nodus_cmt_store_t *s, bool state_table,
                        const char *key, const uint8_t **out_value,
                        size_t *out_len);
int nodus_cmt_store_set(nodus_cmt_store_t *s, bool state_table,
                        const char *key, const uint8_t *value, size_t len);
int nodus_cmt_store_delete(nodus_cmt_store_t *s, bool state_table,
                           const char *key);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_STORE_H */
