/**
 * @file shared/dnac/cmt_replay.c
 * @brief cometbft @709fd12b `consensus/replay.go`'s handshake decision in
 *        C — see cmt_replay.h for the contract, the panic→FAULT reasoning
 *        and what is deliberately elsewhere.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_replay.h"

#include <string.h>

/*
 * cometbft@709fd12b consensus/replay.go:375-459 — the two switches of
 * `ReplayBlocksWithContext`, with the I/O of each branch left to the host.
 *
 * ── ONE C-SPECIFIC DIFFERENCE IN HOW A COMPARISON IS FORMED ────────────
 * The reference writes `storeBlockBase-1` (:385) and `stateBlockHeight+1`
 * (:397, :419). Forming either can overflow, which is defined (wrapping)
 * in Go and UNDEFINED in C. Each is rewritten below into an equivalent
 * that cannot overflow, and each rewrite carries the argument for why it
 * answers the same question on every input the reference itself answers
 * well. The PREDICATE is unchanged.
 */
int cmt_replay_handshake_classify(int64_t store_height, int64_t store_base,
                                  int64_t state_height, int64_t app_height,
                                  int64_t initial_height,
                                  cmt_replay_action_t *out_action)
{
    if (out_action == NULL) {
        return CMT_FAULT;
    }

    /* EXPLICIT BOUND — INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07.
     * All five arguments are block heights: the store's, the store's base,
     * the state's, the application's and the genesis initial height. None
     * can be negative in the reference — they come from `store.Height()`,
     * `store.Base()`, `state.LastBlockHeight`, the ABCI Info response and
     * `state.InitialHeight` — but Go's int64 permits it and Go's arithmetic
     * merely WRAPS where C's is UNDEFINED. The rewritten test at :397
     * below forms a difference, so the bound has to be stated rather than
     * assumed. A negative height is the host handing this node an
     * impossible value: node-local, fail-stop. */
    if (store_height < 0 || store_base < 0 || state_height < 0 ||
        app_height < 0 || initial_height < 0) {
        return CMT_FAULT;
    }

    /* ── :376-400, the edge cases, IN THE REFERENCE'S ORDER ────────── */

    if (store_height == 0) {                                 /* :377 */
        *out_action = CMT_REPLAY_STORE_EMPTY_RETURN_APP_HASH;
        return CMT_OK;                                       /* :378-379 */
    }
    if (app_height == 0 && initial_height < store_base) {    /* :381 */
        *out_action = CMT_REPLAY_ERR_APP_HEIGHT_TOO_LOW_AT_GENESIS;
        return CMT_OK;                                       /* :383 */
    }
    /* :385 `appBlockHeight > 0 && appBlockHeight < storeBlockBase-1`.
     * With app_height > 0, a store_base of 1 or less makes
     * `storeBlockBase-1` at most 0 and the comparison false, so requiring
     * store_base >= 2 removes the underflow without changing any
     * answer. */
    if (app_height > 0 && store_base >= 2 &&
        app_height < store_base - 1) {
        *out_action = CMT_REPLAY_ERR_APP_HEIGHT_TOO_LOW;
        return CMT_OK;                                       /* :387 */
    }
    if (store_height < app_height) {                         /* :389 */
        *out_action = CMT_REPLAY_ERR_APP_HEIGHT_TOO_HIGH;
        return CMT_OK;                                       /* :391 */
    }
    if (store_height < state_height) {                       /* :393 */
        /* :395 PANIC — the state is ahead of the store. Node-local. */
        *out_action = CMT_REPLAY_FAULT_STATE_AHEAD_OF_STORE;
        return CMT_OK;
    }
    /* :397 `storeBlockHeight > stateBlockHeight+1`. The case above has
     * already established store_height >= state_height, and the entry
     * bound has established state_height >= 0, so their difference is
     * non-negative AND cannot overflow; the rewritten test is the same
     * predicate. Both halves of that argument are needed: without the
     * entry bound, state_height = -1 with store_height = INT64_MAX would
     * overflow here while the reference answers it without wrapping. */
    if (store_height - state_height > 1) {
        /* :399 PANIC — the store is more than one ahead of the state. */
        *out_action = CMT_REPLAY_FAULT_STORE_TOO_FAR_AHEAD;
        return CMT_OK;
    }

    /* ── :405-456, store is now equal to state or exactly one ahead ── */

    if (store_height == state_height) {                      /* :406 */
        if (app_height < store_height) {                     /* :409 */
            *out_action = CMT_REPLAY_BLOCKS_NO_MUTATE;
            return CMT_OK;                                   /* :411 */
        }
        if (app_height == store_height) {                    /* :413 */
            *out_action = CMT_REPLAY_IN_SYNC_RETURN_APP_HASH;
            return CMT_OK;                                   /* :415-416 */
        }
        /* app_height > store_height was refused at :389, so nothing else
         * can reach here; the reference falls through to :458 all the
         * same, and so does this. */
    } else if (store_height - state_height == 1) {           /* :419 */
        if (app_height < state_height) {                     /* :423 */
            *out_action = CMT_REPLAY_BLOCKS_MUTATE;
            return CMT_OK;                                   /* :426 */
        }
        if (app_height == state_height) {                    /* :428 */
            *out_action = CMT_REPLAY_LAST_BLOCK_REAL_APP;
            return CMT_OK;                                   /* :434-435 */
        }
        if (app_height == store_height) {                    /* :437 */
            *out_action = CMT_REPLAY_LAST_BLOCK_MOCK_APP;
            return CMT_OK;                                   /* :452-453 */
        }
    }

    /* :458-459 PANIC — uncovered case. */
    *out_action = CMT_REPLAY_FAULT_UNCOVERED;
    return CMT_OK;
}

/* cometbft@709fd12b consensus/replay.go:545-553 —
 * assertAppHashEqualsOneFromBlock() */
int cmt_replay_assert_app_hash_equals_one_from_block(
        const uint8_t *app_hash, size_t app_hash_len,
        const cmt_block_t *block)
{
    if (block == NULL || (app_hash == NULL && app_hash_len != 0)) {
        return CMT_FAULT;
    }
    /* :546 `bytes.Equal(appHash, block.AppHash)` — lengths first, as
     * bytes.Equal compares them. */
    if (app_hash_len != block->header.app_hash_len) {
        return CMT_FAULT;                                    /* :547-552 */
    }
    if (app_hash_len != 0u &&
        memcmp(app_hash, block->header.app_hash, app_hash_len) != 0) {
        return CMT_FAULT;                                    /* :547-552 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/replay.go:555-565 —
 * assertAppHashEqualsOneFromState() */
int cmt_replay_assert_app_hash_equals_one_from_state(
        const uint8_t *app_hash, size_t app_hash_len,
        const cmt_state_t *state)
{
    if (state == NULL || (app_hash == NULL && app_hash_len != 0)) {
        return CMT_FAULT;
    }
    if (app_hash_len != state->app_hash_len) {               /* :556 */
        return CMT_FAULT;                                    /* :557-563 */
    }
    if (app_hash_len != 0u &&
        memcmp(app_hash, state->app_hash, app_hash_len) != 0) {
        return CMT_FAULT;                                    /* :557-563 */
    }
    return CMT_OK;
}
