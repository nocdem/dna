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
 * ── THE MAPPING (D-17 rev 6, APPROVED 2026-09-14; rev 5 ruled 2026-09-11) ─
 *   dbm.DB           → one (key BLOB PRIMARY KEY, value BLOB NOT NULL)
 *                      table per store: `cmt_blockstore` for store.go,
 *                      `cmt_state` for state/store.go. A key is the
 *                      reference's byte string: `H:<h>`, `P:<h>:<i>`,
 *                      `C:<h>`, `SC:<h>`, `EC:<h>`, `BH:<hex>`,
 *                      `blockStore` (store.go:632-658); `stateKey`,
 *                      `validatorsKey:<h>`, `consensusParamsKey:<h>`,
 *                      `abciResponsesKey:<h>`, `lastABCIResponseKey`,
 *                      `offlineStateSyncHeightKey` (state/store.go:30-45,
 *                      state.go:21). `%v` of an int64 is its decimal
 *                      without padding; the lexical order of the keys is
 *                      irrelevant because every access is a point lookup
 *                      (the reference cannot range over them either —
 *                      store.go:53-55, state/store.go:273-274).
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
 *   · `addCaches` and the three `lru.Cache` reads/writes (store.go:60-62,
 *     :78-93, :265-268/:285, :293-296/:313, :321-324/:342) — an external
 *     library (hashicorp/golang-lru) whose only observable effect is the
 *     reference's OWN asymmetry: `PruneBlocks` evicts only the extended
 *     commit cache (:414) and `DeleteLatestBlock` evicts nothing, so a
 *     pruned commit can still be served from the reference's cache. Here
 *     every load reads the table, so a pruned commit is "not found".
 *     Recorded as a DEVIATION (CLAUDE.md's cache-symmetry rule is the
 *     reason a cache with that asymmetry is not reproduced).
 *   · `mtx` (store.go:56) — a single-threaded event loop.
 *   · `LoadFromDBOrGenesisFile` (state/store.go:118-132) — the JSON
 *     genesis FILE is the host's (cmt_genesis.h); the doc variant is
 *     ported.
 *   · `responseFinalizeBlockFromLegacy` (:769-816) and the legacy branch
 *     of `LoadFinalizeBlockResponse` (:440-453) and of
 *     `LoadLastFinalizeBlockResponse` (:491-497) — this chain has no
 *     legacy ABCI format (D-23 rev 4). The reference takes the branch on
 *     `err != nil || resp.AppHash == nil` (:440), so a VALID response
 *     with an EMPTY app hash takes it too; ported as written, the branch
 *     is CMT_FAULT here, and a genuine empty app hash is therefore not
 *     loadable through `LoadFinalizeBlockResponse` (the reference's own
 *     tests give it a one-byte AppHash for this reason).
 *   · `Close` (store.go:627, state/store.go:757) — the connection is the
 *     witness's, borrowed.
 *   · `IsEmpty(store)` (state/store.go:103-109) — `Load` + `IsEmpty`;
 *     kept as the two calls.
 *   · `saveBlockPart`'s `db.Set` branch for a part set larger than
 *     `maxBlockPartsToBatch` (store.go:541, :590-594): inside one SQLite
 *     transaction both branches are one write. DEVIATION: the reference
 *     can crash between an individually written part and the meta and
 *     leave orphan parts; SQLite leaves nothing. A strengthening.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * No clock: `PruneBlocks` compares the STATE's LastBlockTime to the
 * header's time (store.go:387 through evidence/verify.go:295-303), both
 * on-chain values. No unordered iteration: every loop is over heights or
 * list order.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   store/store.go       765 lines
 *   state/store.go       827 lines
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
 * Governing records: D-17 rev 6 (atlas-dec-9d96e2ec31ad4840cf258df21732b67f,
 * APPROVED 2026-09-14), D-23 rev 4
 * (atlas-dec-cb08dde681aa3c4ab1d1f1b33cdb68e1, APPROVED 2026-09-14),
 * D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718),
 * umbrella rev 5 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8).
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

/** state/store.go:25 `valSetCheckpointInterval`. */
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
 * (store.go:143-164; consensus/state.go:2005-2019). Two sets: the decoder
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
 * store.go:154-164 / consensus/state.go:2011-2018: `cmt_pb_block_unmarshal` into
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

    /* store.go:57-58 */
    int64_t base;
    int64_t height;

    /* state/store.go:98 `StoreOptions.DiscardABCIResponses`
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
 * `NewBlockStore(db)` (store.go:67-76: `LoadBlockStoreState`, :692-715,
 * with its `Height > 0 && Base == 0 → Base = 1` compatibility rule
 * :711-713) and `NewStore(db, options)` (state/store.go:112-114) on the
 * same borrowed connection. Tables must exist (schema S14).
 * @return CMT_OK, CMT_FAULT.
 */
int nodus_cmt_store_init(nodus_cmt_store_t *s, sqlite3 *db,
                         bool discard_abci_responses);

/** Finalizes statements and frees scratch; the connection stays open. */
void nodus_cmt_store_release(nodus_cmt_store_t *s);

/* ── store/store.go — BlockStore ───────────────────────────────────── */

/** :95-99 IsEmpty, :102-106 Base, :109-113 Height, :116-123 Size. */
bool    nodus_cmt_bs_is_empty(const nodus_cmt_store_t *s);
int64_t nodus_cmt_bs_base(const nodus_cmt_store_t *s);
int64_t nodus_cmt_bs_height(const nodus_cmt_store_t *s);
int64_t nodus_cmt_bs_size(const nodus_cmt_store_t *s);

/** :126-133 LoadBaseMeta. `*out_found` false when base is 0 or the meta
 *  is absent. */
int nodus_cmt_bs_load_base_meta(nodus_cmt_store_t *s,
                                nodus_cmt_block_meta_t *out, bool *out_found);

/** :137-167 LoadBlock: the meta, every part concatenated into `buf`
 *  (`*out_found` false if any is missing, :146-151), then the decode
 *  step. A block that does not decode is the reference's panic (:158,
 *  :163) → CMT_FAULT. */
int nodus_cmt_bs_load_block(nodus_cmt_store_t *s, int64_t height,
                            uint8_t *buf, size_t buf_cap,
                            nodus_cmt_block_decode_t *st, cmt_block_t *out,
                            bool *out_found);

/** :172-187 LoadBlockByHash: `BH:<hex>` → decimal height → LoadBlock. A
 *  value that does not parse as an int64 is the panic at :184. */
int nodus_cmt_bs_load_block_by_hash(nodus_cmt_store_t *s,
                                    const uint8_t *hash, size_t hash_len,
                                    uint8_t *buf, size_t buf_cap,
                                    nodus_cmt_block_decode_t *st,
                                    cmt_block_t *out, bool *out_found);

/** :192-213 LoadBlockPart: `cmt_pb_part_unmarshal` (payload into
 *  `arena`) then PartFromProto (:207). */
int nodus_cmt_bs_load_block_part(nodus_cmt_store_t *s, int64_t height,
                                 int index, cmt_pb_arena_t *arena,
                                 cmt_part_t *out, bool *out_found);

/** :217-239 LoadBlockMeta: unmarshal (:228) then
 *  BlockMetaFromTrustedProto (:233). */
int nodus_cmt_bs_load_block_meta(nodus_cmt_store_t *s, int64_t height,
                                 nodus_cmt_block_meta_t *out, bool *out_found);

/** :243-258 LoadBlockMetaByHash. */
int nodus_cmt_bs_load_block_meta_by_hash(nodus_cmt_store_t *s,
                                         const uint8_t *hash, size_t hash_len,
                                         nodus_cmt_block_meta_t *out,
                                         bool *out_found);

/** :264-287 LoadBlockCommit: unmarshal into module scratch, then
 *  CommitFromProto (:281) into the CALLER's `sigs` — the `Clone()` of
 *  :286 is that copy. */
int nodus_cmt_bs_load_block_commit(nodus_cmt_store_t *s, int64_t height,
                                   cmt_commit_sig_t *sigs, size_t sigs_cap,
                                   cmt_commit_t *out, bool *out_found);

/** :292-315 LoadBlockExtendedCommit: unmarshal (extensions into `arena`)
 *  then ExtendedCommitFromProto (:309) into the caller's `sigs`. */
int nodus_cmt_bs_load_block_extended_commit(nodus_cmt_store_t *s,
                                            int64_t height,
                                            cmt_extended_commit_sig_t *sigs,
                                            size_t sigs_cap,
                                            cmt_pb_arena_t *arena,
                                            cmt_extended_commit_t *out,
                                            bool *out_found);

/** :320-344 LoadSeenCommit. */
int nodus_cmt_bs_load_seen_commit(nodus_cmt_store_t *s, int64_t height,
                                  cmt_commit_sig_t *sigs, size_t sigs_cap,
                                  cmt_commit_t *out, bool *out_found);

/** :347-440 PruneBlocks. `*out_evidence_point` is the reference's second
 *  return; -1 on every error (:349, :354, :359). The 1000-block flushes
 *  (:425-432) and the final `flush` call (:435) are each one COMMIT.
 *  @return CMT_OK; CMT_REJECT for the three argument errors; CMT_FAULT. */
int nodus_cmt_bs_prune_blocks(nodus_cmt_store_t *s, int64_t height,
                              const cmt_state_t *state,
                              uint64_t *out_pruned,
                              int64_t *out_evidence_point);

/** :449-473 SaveBlock. The reference panics on every failure inside;
 *  CMT_FAULT here. `scratch` is the marshal target for the parts, the
 *  meta and the commits — at least `cmt_block_size`'s need. */
int nodus_cmt_bs_save_block(nodus_cmt_store_t *s, cmt_block_t *block,
                            const cmt_part_set_t *parts,
                            const cmt_commit_t *seen_commit,
                            uint8_t *scratch, size_t scratch_cap);

/** :480-514 SaveBlockWithExtendedCommit: EnsureExtensions(true) (:484),
 *  saveBlockToBatch with `ToCommit()` (:491), `EC:<h>` (:496-500).
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

/** :730-765 DeleteLatestBlock. */
int nodus_cmt_bs_delete_latest_block(nodus_cmt_store_t *s);

/** :692-715 LoadBlockStoreState (exposed for the tests). */
int nodus_cmt_bs_load_block_store_state(nodus_cmt_store_t *s,
                                        cmt_pb_block_store_state_t *out);

/** :662-664 SaveBlockStoreState — a lone `SetSync`, at :683 inside
 *  `saveBlockStoreStateBatchInternal` (:672-688) (exposed for the
 *  tests; the reference marks it deprecated and keeps it). */
int nodus_cmt_bs_save_block_store_state(nodus_cmt_store_t *s,
                                        const cmt_pb_block_store_state_t *bss);

/* ── state/store.go — dbStore ──────────────────────────────────────── */

/** :136-151 LoadFromDBOrGenesisDoc: `Load`, and if empty
 *  `MakeGenesisState(genesisDoc)` (cmt_state_make_genesis). `out` must
 *  be `cmt_state_init`ialised with its own storage. */
int nodus_cmt_ss_load_from_db_or_genesis_doc(nodus_cmt_store_t *s,
                                             cmt_genesis_doc_t *genesis_doc,
                                             cmt_now_fn now, void *now_ctx,
                                             cmt_valset_scratch_t *scratch,
                                             cmt_state_t *out);

/** :154-181 Load / loadState: an absent row leaves `out` EMPTY
 *  (`cmt_state_is_empty`); a row that does not unmarshal is the
 *  `cmtos.Exit` of :172 → CMT_FAULT; a FromProto error → CMT_REJECT. */
int nodus_cmt_ss_load(nodus_cmt_store_t *s, cmt_state_t *out);

/** :185-223 Save / save: the two ValidatorsInfo rows (:203, :208), the
 *  ConsensusParamsInfo row (:212), `stateKey` (:216), one COMMIT
 *  (:219 WriteSync — a failure there is a panic → CMT_FAULT). */
int nodus_cmt_ss_save(nodus_cmt_store_t *s, const cmt_state_t *state);

/** :226-267 Bootstrap. */
int nodus_cmt_ss_bootstrap(nodus_cmt_store_t *s, const cmt_state_t *state);

/** :277-403 PruneStates. `vals_storage`/`scratch` are what the
 *  re-materialisation of a kept height needs (:316-338 through
 *  `LoadValidators`). */
int nodus_cmt_ss_prune_states(nodus_cmt_store_t *s, int64_t from, int64_t to,
                              int64_t evidence_threshold_height,
                              cmt_validator_t *vals_storage, size_t vals_cap,
                              cmt_valset_scratch_t *scratch);

/** :411-413 TxResultsHash: `types.NewResults(txResults).Hash()`.
 *  `results`/`leaf_scratch`/`items` are cmt_results.h's storage. */
int nodus_cmt_ss_tx_results_hash(const cmt_pb_exec_tx_result_t *tx_results,
                                 size_t n, cmt_abci_results_t *results,
                                 uint8_t *leaf_scratch, size_t leaf_cap,
                                 cmt_merkle_item_t *items, size_t items_cap,
                                 uint8_t out[CMT_TMHASH_SIZE]);

/** :418-458 LoadFinalizeBlockResponse. @return CMT_OK; CMT_REJECT for
 *  DiscardABCIResponses (:419-421) and for an absent row (:427-429,
 *  ErrNoABCIResponsesForHeight); CMT_FAULT for the legacy branch
 *  (:440-453 — see the header) and SQLite failures. */
int nodus_cmt_ss_load_finalize_block_response(nodus_cmt_store_t *s,
                                              int64_t height,
                                              cmt_pb_rfb_storage_t *storage,
                                              cmt_pb_response_finalize_block_t *out);

/** :466-500 LoadLastFinalizeBlockResponse. @return CMT_OK; CMT_REJECT for
 *  no row (:472-474) and a height mismatch (:484-486); CMT_FAULT for the
 *  `cmtos.Exit` of :479 and the legacy branch (:491-497). */
int nodus_cmt_ss_load_last_finalize_block_response(
        nodus_cmt_store_t *s, int64_t height, cmt_pb_rfb_storage_t *storage,
        cmt_pb_response_finalize_block_t *out);

/** :508-542 SaveFinalizeBlockResponse: `abciResponsesKey:<h>` unless
 *  discarding (:520-528), then `lastABCIResponseKey` (:530-541). The nil
 *  stripping of :509-516 has no C counterpart (the array holds values).
 *  The encoded ABCIResponsesInfo must fit the module's scratch,
 *  `cmt_pb_store_state_upper_bound(CMT_VALSET_MAX)` bytes
 *  (nodus_witness_cmt_store.c, `nodus_cmt_store_init`); the response is
 *  this node's own FinalizeBlock product, never a peer's input, so
 *  exceeding that bound is a NODE-LOCAL invariant broken → CMT_FAULT.
 *  @return CMT_OK; CMT_FAULT on NULL, the bound, or a SQLite failure
 *          (:525, :541); an encode failure returns the codec's own code
 *          (cmt_pb_store.h). The host treats every non-OK as the
 *          execution.go:260 error → CMT_FAULT. */
int nodus_cmt_ss_save_finalize_block_response(
        nodus_cmt_store_t *s, int64_t height,
        const cmt_pb_response_finalize_block_t *resp);

/** :548-586 LoadValidators, with `lastStoredHeightFor` (:588-591) and
 *  the `IncrementProposerPriority(SafeConvertInt32(height -
 *  lastStoredHeight))` replay (:570) — SafeConvertInt32's panic
 *  (safemath.go:36-43) is CMT_FAULT, node-local. `out` must be
 *  `cmt_validator_set_init`ialised. @return CMT_OK; CMT_REJECT for
 *  ErrNoValSetForHeight (:551) and the :556-562 error; CMT_FAULT for
 *  the `cmtos.Exit` of :608. */
int nodus_cmt_ss_load_validators(nodus_cmt_store_t *s, int64_t height,
                                 cmt_validator_set_t *out);

/** :656-681 LoadConsensusParams. @return CMT_OK; CMT_REJECT for :663 and
 *  :669-674; CMT_FAULT for the `cmtos.Exit` of :695. */
int nodus_cmt_ss_load_consensus_params(nodus_cmt_store_t *s, int64_t height,
                                       cmt_consensus_params_t *out);

/** :728-735 SetOfflineStateSyncHeight — `binary.PutVarint` (zigzag,
 *  :823-827). */
int nodus_cmt_ss_set_offline_state_sync_height(nodus_cmt_store_t *s,
                                               int64_t height);

/** :738-754 GetOfflineStateSyncHeight — `binary.Varint` (:818-821);
 *  CMT_REJECT for "value empty" (:746) and a negative height (:751). */
int nodus_cmt_ss_get_offline_state_sync_height(nodus_cmt_store_t *s,
                                               int64_t *out);

/* ── exposed for the tests ─────────────────────────────────────────── */

/** evidence/verify.go:295-303 — `IsEvidenceExpired`. `time_now.Sub(
 *  time_ev)` saturates like Go's — Go stdlib `time.Time.Sub`, not
 *  pinned, behaviour stated, not verified. */
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
