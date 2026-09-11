/**
 * @file shared/dnac/cmt_replay.h
 * @brief cometbft @709fd12b `consensus/replay.go`'s HANDSHAKE DECISION in
 *        C — which of the reference's twelve branches a node is in.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything here yet; additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IS HERE ───────────────────────────────────────────────────────
 * `Handshaker.ReplayBlocksWithContext` (replay.go:300-460) is two things
 * wound together: I/O — InitChain against the app (:319-373), replaying
 * blocks (:462-523) and replaying one block (:525-543) — and a PURE
 * DECISION over a handful of integers, which chooses among those. The
 * decision is extracted here as `cmt_replay_handshake_classify`; the I/O
 * belongs to the host and to wave R3.
 *
 * The two app-hash assertions (:545-553, :555-565) are here too, because
 * they are pure comparisons.
 *
 * ── WHAT IS NOT HERE ───────────────────────────────────────────────────
 * `(cs *State) readReplayMessage` (:39-90) and `(cs *State) catchupReplay`
 * (:94-167) are METHODS ON THE CONSENSUS STATE. They belong to `cmt_cs`,
 * which is another executor's module in this same season; they are not in
 * this file and are not silently omitted.
 *
 * Also not here, all of it HOST or R3: `NewHandshaker` and the Handshaker
 * struct (:180-230), `Handshake` (:232-288), `ReplayBlocks` (:290-297),
 * the InitChain block (:318-373), `replayBlocks` (:462-523), `replayBlock`
 * (:525-543), and `consensus/replay_file.go` / `replay_stubs.go`, which
 * are the CLI replay tool and its mock application.
 *
 * ── panic → CMT_FAULT, AND WHY, FOR THIS FILE ──────────────────────────
 * The reference panics in three places reachable from here: the state
 * ahead of the store (:393-396), the store more than one ahead of the
 * state (:397-400), and the uncovered case (:458-459); and in both
 * assertions when an app hash does not match (:546-552, :556-563).
 *
 * EVERY ONE OF THEM IS NODE-LOCAL. The four heights come from THIS node's
 * own block store and state store, and the app hash from THIS node's
 * application. No peer can put a value there. A node in one of these
 * states cannot decide anything correctly — it must HALT and be looked at,
 * which is exactly CMT_FAULT's contract in this port ("this process could
 * not decide; a caller MUST NOT count it as a negative vote or as invalid
 * input"). Answering a peer or continuing would be worse than stopping.
 * The two `ErrAppBlockHeightTooLow` / `TooHigh` returns (:381-391) are
 * ERRORS in the reference, not panics, and stay distinguishable as their
 * own outcomes below.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * A pure function of five integers, evaluated in the reference's order.
 * No clock, no allocation, no I/O.
 *
 * Reference @709fd12b: consensus/replay.go, 565 lines, SHA-256
 * 5609c4d4174a536389cb2814bac09557a66e3299292141b54c635e31425284fe.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-15 rev 5 (atlas-dec-c0bfc5344204b9282ceaaa5e06042350, PROPOSED).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_REPLAY_H
#define SHARED_DNAC_CMT_REPLAY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT, hash size */
#include "cmt_block.h"    /* cmt_block_t */
#include "cmt_state.h"    /* cmt_state_t */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * One outcome per distinct branch of
 * `ReplayBlocksWithContext` (replay.go:376-459), named after the branch
 * and carrying its lines.
 *
 * The order of the constants is the order the reference evaluates them,
 * and `cmt_replay_handshake_classify` walks them in exactly that order —
 * a Go `switch { case ... }` is top-to-bottom and several of these
 * conditions overlap.
 */
typedef enum {
    /** :377-379 `storeBlockHeight == 0` — an empty block store. Assert the
     *  app hash equals the state's, then return it. Nothing to replay. */
    CMT_REPLAY_STORE_EMPTY_RETURN_APP_HASH = 0,

    /** :381-383 `appBlockHeight == 0 && state.InitialHeight <
     *  storeBlockBase` — the app has no state and the store is truncated
     *  above the initial height. ErrAppBlockHeightTooLow. */
    CMT_REPLAY_ERR_APP_HEIGHT_TOO_LOW_AT_GENESIS,

    /** :385-387 `appBlockHeight > 0 && appBlockHeight < storeBlockBase-1`
     *  — the app is too far behind a truncated store.
     *  ErrAppBlockHeightTooLow. */
    CMT_REPLAY_ERR_APP_HEIGHT_TOO_LOW,

    /** :389-391 `storeBlockHeight < appBlockHeight` — the app is ahead of
     *  the store, which is under the APP's control.
     *  ErrAppBlockHeightTooHigh. */
    CMT_REPLAY_ERR_APP_HEIGHT_TOO_HIGH,

    /** :393-396 `storeBlockHeight < stateBlockHeight` — the state is ahead
     *  of the store, which is under CometBFT's own control. PANIC. */
    CMT_REPLAY_FAULT_STATE_AHEAD_OF_STORE,

    /** :397-400 `storeBlockHeight > stateBlockHeight+1` — the store is
     *  more than one block ahead of the state. PANIC. */
    CMT_REPLAY_FAULT_STORE_TOO_FAR_AHEAD,

    /** :409-411 store == state and the app is behind: replay blocks from
     *  appBlockHeight+1 to storeBlockHeight WITHOUT the WAL and without
     *  mutating the state (`mutateState = false`). */
    CMT_REPLAY_BLOCKS_NO_MUTATE,

    /** :413-416 store == state == app: nothing to do. Assert the app hash
     *  equals the state's and return it. */
    CMT_REPLAY_IN_SYNC_RETURN_APP_HASH,

    /** :423-426 store == state+1 and the app is behind the state: replay
     *  blocks but leave the LAST one to the WAL (`mutateState = true`). */
    CMT_REPLAY_BLOCKS_MUTATE,

    /** :428-435 store == state+1 and app == state: Commit did not run.
     *  Replay the last block against the REAL application. */
    CMT_REPLAY_LAST_BLOCK_REAL_APP,

    /** :437-453 store == state+1 and app == store: Commit ran but the
     *  state was not saved. Replay the last block against a MOCK
     *  application built from the stored FinalizeBlock response. */
    CMT_REPLAY_LAST_BLOCK_MOCK_APP,

    /** :458-459 — the uncovered case. PANIC. */
    CMT_REPLAY_FAULT_UNCOVERED
} cmt_replay_action_t;

/**
 * The pure decision of cometbft@709fd12b consensus/replay.go:375-459.
 *
 * ⚠ FIVE INTEGERS, NOT FOUR. The edge-case switch reads `state.InitialHeight`
 * at :381 as well as the three heights and the store's base, so the
 * classifier cannot be written over four. (The dispatch for this wave said
 * four; the fifth is named here because the reference needs it.)
 *
 * @param store_height  `h.store.Height()` (:308).
 * @param store_base    `h.store.Base()` (:307).
 * @param state_height  `state.LastBlockHeight` (:309).
 * @param app_height    the height the application reported (:293).
 * @param initial_height `state.InitialHeight`, read at :381.
 * @param out_action    the branch, never NULL.
 * @return CMT_OK when a branch was chosen — INCLUDING the three that make
 *         the reference panic and the two that return an error, because
 *         "which branch" is always answerable. The CALLER acts on
 *         `*out_action`: the three CMT_REPLAY_FAULT_* outcomes mean HALT.
 *         CMT_FAULT on a NULL argument and on a NEGATIVE height — no
 *         height the reference reads can be negative, and one of the
 *         overflow-free rewrites below depends on saying so (INVARIANT
 *         atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 */
int cmt_replay_handshake_classify(int64_t store_height, int64_t store_base,
                                  int64_t state_height, int64_t app_height,
                                  int64_t initial_height,
                                  cmt_replay_action_t *out_action);

/**
 * cometbft@709fd12b consensus/replay.go:545-553 —
 * `assertAppHashEqualsOneFromBlock()`.
 *
 * @param app_hash the application's hash and its length (64 bytes under
 *        the SHA3-512 substitution, but the reference compares slices, so
 *        the length is compared too).
 * @return CMT_OK when they are equal; CMT_FAULT where the reference panics
 *         (:546-552) — see the file header on why this is FAULT.
 */
int cmt_replay_assert_app_hash_equals_one_from_block(
        const uint8_t *app_hash, size_t app_hash_len,
        const cmt_block_t *block);

/**
 * cometbft@709fd12b consensus/replay.go:555-565 —
 * `assertAppHashEqualsOneFromState()`. The reference's panic text is the
 * one that ends "Did you reset CometBFT without resetting your
 * application's data?".
 * @return CMT_OK, CMT_FAULT (:556-563), CMT_FAULT on NULL.
 */
int cmt_replay_assert_app_hash_equals_one_from_state(
        const uint8_t *app_hash, size_t app_hash_len,
        const cmt_state_t *state);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_REPLAY_H */
