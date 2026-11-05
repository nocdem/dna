/**
 * @file nodus_witness_v2_shadow.h
 * @brief HF-9 WP5 - the shadow run (plan docs/plans/approved/2026-11-04-hf9.md
 *        §11; decisions D9, D12, D16, D17; the operator's answer to Q1,
 *        "Tamam, 3 ile devam et." = Option C).
 *
 * WHAT IT IS. A candidate binary runs the keyed-trie roots of generation 6
 * on a live generation-5 node for about 1-2 days BEFORE the vote, so the
 * eight nodes' roots can be compared byte for byte. It is NODE-LOCAL and
 * NEVER CONSENSUS: after the host has committed a block and saved the
 * consensus state, one job reads the committed rows, finds what changed
 * against its own copy of the previous rows, updates its own tries with
 * the consensus flush's code (nodus_witness_v2_trie.c apply_key) and logs
 * the eight leg roots plus the four shadow compositions of that height.
 *
 * ISOLATION (plan §11, D17 report 1 finding 1).
 *  - It writes NOTHING inside a block transaction (the hook runs after the
 *    host's COMMIT and state save; with capture = 0 no trigger writes a
 *    dirty key);
 *  - it writes only the node-local tables below and v2_trie_shadow_state;
 *    NEVER v2_trie_nodes, v2_trie_roots, v2_trie_dirty or v2_trie_state
 *    (in particular never the capture flag);
 *  - a failure of any step rolls the shadow's own transaction back, logs
 *    `HF9-SHADOW FAULT <height> <reason>`, sets the status to FAULTED and
 *    returns; it never returns a fault to the host and never touches
 *    AppHash, ProcessProposal or a vote.
 *
 * STATUS (v2_trie_shadow_state.status; the physical values are this
 * package's - plan §5.1 names only "stopped / running / faulted"; no row
 * = never seeded = "off"). The status never selects a consensus behaviour.
 *
 * TABLES (node-local, created by the seeding in its own transaction with
 * CREATE TABLE IF NOT EXISTS; not part of the S20 shape check, plan §5.1
 * lists only v2_trie_shadow_state there):
 *   v2_trie_shadow_nodes (digest BLOB NOT NULL PRIMARY KEY, rlp BLOB NOT NULL)
 *   v2_trie_shadow_roots (leg INTEGER PRIMARY KEY, root BLOB NOT NULL)
 *   v2_trie_shadow_rows  (leg, key BLOB, value BLOB) - each selected row's
 *       canonical key and 64-byte leaf hash as of the last pass
 *   v2_trie_shadow_log   (height PRIMARY KEY, leg1..leg8, core, stor, sys,
 *       glob) - all 64 bytes of every value. The seeding writes the first
 *       row (the seeded height); every pass writes one row at the tip it
 *       covers; a pass after a stop covers every change since the last
 *       logged height in one step (§11 catch-up: the comparison is state
 *       based, a change is never applied twice).
 *
 * THE RUN.
 *   seed   - one transaction between blocks: the eight tries built from
 *            rows into the shadow tables with the edge's own build code
 *            (root_inc == root_full checked), the row copy filled, the
 *            first log row, status RUNNING. Refused (-1, nothing written)
 *            when the committed generation is >= 6 and when a status row
 *            already exists.
 *   pass   - after each commit, status RUNNING: the committed generation
 *            first (>= 6: status STOPPED, no row read, never again on this
 *            database); then every row of the eight tables is read with
 *            the legs' row checks, compared with the copy (new key or
 *            changed value -> set; key gone or no longer selected ->
 *            delete), the sorted change list goes to the consensus flush's
 *            update code against the shadow tables, the copy and the shadow
 *            roots are updated and one log row is written.
 *   `full` - additionally evm_trie_full_root over all rows of every leg
 *            after every pass, compared with the shadow incremental roots.
 *
 * GENERATION WINDOW. The shadow job acts only while the committed SYSTEM
 * runtime is of a generation >= NODUS_RT_GEN_ROOTS and < NODUS_RT_GEN_TRIE:
 * the log row's GLOBAL v2' (nodus_witness_roots_v2.h) is defined for the
 * head-bearing ROOTS composition. Below it the job is idle (no status is
 * written); from the generation-6 edge on it only ever sets STOPPED.
 *
 * Reachable only with NODUS_EVM_ENABLED (the tries live there).
 */
#ifndef NODUS_WITNESS_V2_SHADOW_H
#define NODUS_WITNESS_V2_SHADOW_H

#include <stdint.h>

#include "witness/nodus_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

/* v2_trie_shadow_state.status */
#define NODUS_V2_SHADOW_STOPPED  0
#define NODUS_V2_SHADOW_RUNNING  1
#define NODUS_V2_SHADOW_FAULTED  2
/** nodus_witness_v2_shadow_status: no row (never seeded). */
#define NODUS_V2_SHADOW_NONE    (-1)

/** One log row: the eight leg roots L1..L8 and the four shadow
 *  compositions of `height`, 64 bytes each. */
typedef struct {
    uint64_t height;
    uint8_t  leg[8][64];
    uint8_t  core[64];     /* CORE  v4'   */
    uint8_t  stor[64];     /* STOR  v3'   */
    uint8_t  sys[64];      /* SYS   v7'   */
    uint8_t  glob[64];     /* GLOBAL v2'  */
} nodus_v2_shadow_log_t;

/** THE BUILDING BLOCKS of the seeding and of a pass, with no gating, no
 *  height, no log row and no status - each runs inside the CALLER'S open
 *  transaction (-1 with none open) and writes only the node-local shadow
 *  tables. seed / pass wrap them; the tests drive them on a database that
 *  has no chain behind it (T-10's equality against the trigger capture).
 *
 *  build  creates the shadow tables (IF NOT EXISTS), empties them and builds
 *         the eight tries from the rows into them with the edge's own build
 *         (root_inc == root_full required), copying each selected row into
 *         v2_trie_shadow_rows. @return 0 / -1.
 *  sync   compares every row of the eight tables with the copy, updates the
 *         shadow tries with the consensus flush's update code, stores the
 *         shadow roots and refreshes the copy; `full` != 0 also compares
 *         each leg with evm_trie_full_root. @return 0 / -1 (the caller
 *         rolls back). */
int nodus_witness_v2_shadow_build(nodus_witness_t *w);
int nodus_witness_v2_shadow_sync(nodus_witness_t *w, int full);

/** The shadow status: *status = STOPPED / RUNNING / FAULTED, or NONE when
 *  there is no row. A row whose value is none of those, a non-integer
 *  value or a read fault is -1. @return 0 / -1. */
int nodus_witness_v2_shadow_status(nodus_witness_t *w, int *status);

/** The seeding (see the header). Needs autocommit (between blocks) and
 *  schema S20. @return 0 seeded and RUNNING; -1 refused or failed. A
 *  refusal (generation >= 6 / below the ROOTS generation, a status row
 *  already there, a transaction open) writes nothing and does not change
 *  the status; a failure after the seeding began rolls it back and sets
 *  FAULTED. */
int nodus_witness_v2_shadow_seed(nodus_witness_t *w);

/** One shadow pass (see the header). Same preconditions and the same
 *  fault discipline as the hook. @return 0 a pass ran or nothing was due;
 *  -1 a fault (status FAULTED, logged). */
int nodus_witness_v2_shadow_pass(nodus_witness_t *w);

/** THE HOOK the node's block executor calls after a block is committed
 *  and its consensus state saved (nodus_cmt_blockexec_t.on_block_saved,
 *  bound in nodus_witness_cmt_node.c). Configuration-gated by
 *  w->config.hf9_shadow (off = nothing): decides stopped / seed / pass as
 *  described above. NEVER fails the caller. */
void nodus_witness_v2_shadow_after_commit(void *w);

/** Read a log row: `height` 0 = the newest. @return 1 found, 0 no such
 *  row, -1 fault. */
int nodus_witness_v2_shadow_log_read(nodus_witness_t *w, uint64_t height,
                                     nodus_v2_shadow_log_t *out);

/** Rows delivered to the shadow's row comparison since the process
 *  started (a node-local work counter, T-10 "does no further row read"). */
uint64_t nodus_witness_v2_shadow_rows_scanned(void);

#ifdef QGP_FAULT_INJECT
/* Test-only fault points (compiled only under -DQGP_FAULT_INJECT=ON), one
 * shot: the point fires once, at its place, then disarms.
 *   1  the row comparison of a pass        2  the shadow trie update
 *   3  the log write                       4  the full-rebuild check
 *      (mode `full` only: one bit of the rebuilt root is flipped)
 *   5  the seeding, after leg 1 was built
 * Arming 0 disarms. nodus_witness_v2_shadow_test_hits() counts the points
 * that fired (false-pass guard: assert it). @return 0 / -1 bad point. */
int nodus_witness_v2_shadow_test_fault(int point);
int nodus_witness_v2_shadow_test_hits(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_SHADOW_H */
