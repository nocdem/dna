/**
 * @file nodus_witness_v2_trie.h
 * @brief HF-9 WP2 — the eight keyed Patricia tries (plan docs/plans/
 *        approved/2026-11-04-hf9.md §4, §5): the SQLite node store, the
 *        per-leg row readers, the build from rows, the flush of the dirty
 *        keys, the leg roots.
 *
 * INERT until generation 6. Nothing in this build calls the build or the
 * flush from the block path: the capture flag v2_trie_state.capture is 0
 * for every generation this build compiles, so the S20 triggers write no
 * dirty key (nodus_witness_v2_schema.h). The generation >= 6 wiring (the
 * activation edge, phase 8-pre, the dirty-empty assertion, the
 * head_activate guard's call site) arrives with the generation (plan §13
 * WP3). EVM-only, like nodus_witness_rt_evm.c: the tries are
 * shared/evm/trie/evm_trie.{c,h} (SHA3-512 Patricia, plan §4.1) and the
 * full-rebuild cross-check shared/evm/trie/evm_trie_full.c, which both
 * live in the EVM library.
 *
 * LEGS (plan §4.2). One trie per leg; leg id = the plan's L-number.
 *
 *   leg  table                    key bytes              value (64 B)
 *   1    utxo_set                 nullifier, 64 raw      SHA3-512(0x00 ‖ D),
 *                                                         D = nodus_witness_
 *                                                         merkle_leaf_hash
 *   2    tokens                   token_id, 64 raw       dna_v2_token_leaf_hash
 *   3    v2_claims_spent          nullifier, 64 raw      dna_claims_leaf_hash
 *                                 (rows of the CORE domain only)
 *   4    v2_names                 name bytes, raw        dna_v2_name_leaf_hash
 *   5    v2_storage_nodes         node_fp, 64 raw        dna_v2_storage_node_leaf_hash
 *   6    v2_storage_segments      k, 8 B big-endian      dna_v2_segment_leaf_hash_v2
 *   7    validator_set_snapshots  epoch_start, 8 B BE    dna_v2_vset_leaf_hash
 *   8    v2_attendance_epoch      epoch_start, 8 B BE    dna_v2_attendance_leaf_hash
 *
 * ROW CHECKS. Every reader mirrors the existing generation <= 5 loader's
 * checks for its table (the line ranges are cited at each reader in the
 * .c file): a malformed row, a mid-scan error or an interrupted scan is a
 * FAULT, never a shorter trie. They are mirrors, not shared code: the
 * loaders stay byte-identical for replay. The one whole-table check the
 * segments loader makes (k = exactly 1..n) is made in the BUILD scan only;
 * a flush reads single rows.
 *
 * ERRORS. 0 ok; -1 FAULT or invalid argument, never a value (nodus/
 * CLAUDE.md "A DB failure is never a value"); the caller turns -1 into a
 * node FAULT and the host rolls the block back. Every sqlite3_bind_* result
 * is checked before its statement is stepped (HF-9 review row Z-51), also
 * in the node store here.
 *
 * DETERMINISM. Legs are processed in ascending leg id; inside a leg the
 * dirty keys are read in ascending key order (blobs by memcmp, integers
 * numerically); no unordered container decides anything.
 */
#ifndef NODUS_WITNESS_V2_TRIE_H
#define NODUS_WITNESS_V2_TRIE_H

#include <stdint.h>
#include <stddef.h>

#include "witness/nodus_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_V2_TRIE_LEG_UTXO        1
#define NODUS_V2_TRIE_LEG_TOKENS      2
#define NODUS_V2_TRIE_LEG_CLAIMS      3
#define NODUS_V2_TRIE_LEG_NAMES       4
#define NODUS_V2_TRIE_LEG_REGISTRY    5
#define NODUS_V2_TRIE_LEG_SEGMENTS    6
#define NODUS_V2_TRIE_LEG_VSET        7
#define NODUS_V2_TRIE_LEG_ATTENDANCE  8
#define NODUS_V2_TRIE_LEGS            8

/** Build one leg's trie from the table's rows (plan §7.2 step 4, §7.4):
 *  scan ORDER BY primary key with the reader's row checks and a post-loop
 *  SQLITE_DONE check, build by evm_trie_set in that order, commit
 *  (writing the nodes to v2_trie_nodes) -> root_inc; then compute
 *  evm_trie_full_root(kvs, secured = 1, SHA3-512) over the same list ->
 *  root_full. Writes no v2_trie_roots row and no dirty row. The two roots
 *  are returned so the caller compares them (a mismatch is the caller's
 *  FAULT: the node stops and does not vote, D12).
 *  @return 0 / -1. */
int nodus_witness_v2_trie_build_leg(nodus_witness_t *w, int leg,
                                    uint8_t root_inc[64],
                                    uint8_t root_full[64]);

/** Build all eight legs (build_leg for leg 1..8), require root_inc ==
 *  root_full for every leg, then write v2_trie_roots (INSERT OR REPLACE,
 *  one row per leg). Nothing is written to v2_trie_roots unless all eight
 *  legs agree. @return 0 / -1 (a mismatch is -1). */
int nodus_witness_v2_trie_build_all(nodus_witness_t *w);

/** The flush (plan §5.3): for each leg in ascending leg id that has dirty
 *  keys: open the trie at v2_trie_roots(leg) (a missing or malformed row
 *  is -1), read the leg's dirty keys in ascending key order, for each key
 *  read the row by primary key with the reader's row checks (row present
 *  and selected -> evm_trie_set, else evm_trie_delete), commit, write the
 *  leg's v2_trie_roots row, close the handle, delete the leg's dirty
 *  rows. A leg without dirty keys is left untouched. Any trie -2, store
 *  fault or malformed row is -1 (the handle is closed; the next flush
 *  reopens from the committed row). Must run inside the host's block
 *  transaction (-1 outside one). @return 0 / -1. */
int nodus_witness_v2_trie_flush(nodus_witness_t *w);

/** The committed root of `leg` from v2_trie_roots (64 bytes). Refuses
 *  (-1) while v2_trie_dirty still holds a key of that leg: a root read
 *  with pending keys would be stale (plan §5.3, the head_activate
 *  guard). A missing or malformed row is -1. @return 0 / -1. */
int nodus_witness_v2_trie_leg_root(nodus_witness_t *w, int leg,
                                   uint8_t root[64]);

/** Number of rows in v2_trie_dirty (all legs). @return 0 with *n, -1. */
int nodus_witness_v2_trie_dirty_count(nodus_witness_t *w, int64_t *n);

/** Write v2_trie_state.capture (0 or 1). Only the activation edge and a
 *  generation >= 6 genesis may call it (plan §5.1); nothing in this build
 *  does. Refused (-1) outside a transaction, for any value but 0 / 1 and
 *  when the row is missing. @return 0 / -1. */
int nodus_witness_v2_trie_set_capture(nodus_witness_t *w, int capture);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_TRIE_H */
