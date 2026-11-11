/**
 * @file amm_nodus_watch.h
 * @brief nodus-amm Nodus observation: the native NODUS payments that reach
 *        the bot's own address, read from its LOCAL node's address history
 *        through the amm_node.h seam, matched to the approvals of NODUS ->
 *        USDT swaps, held when they match none, recorded in the journal.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 8 step 6 and "Payment matching on the Nodus side" (lines 240, 244),
 * section 11 (lines 282-289: finality, node-local history, startup refusal,
 * owner-only history), section 13 (window rule, Nodus sub-bullet, lines
 * 315-317), section 14 (line 328: Nodus liquidity wait), section 17 (the
 * marker keyed by the incoming transfer id, line 369), givens items 32, 49,
 * 54, 59.
 *
 * WHAT A STEP DOES (amm_nodus_watch_step; every read through the seam, all
 * state in the journal, no clock read, no randomness):
 *  1. Tip T: the node's committed height (ruleset_info). The header time of
 *     block T (block_time). Unreadable -> AMM_NW_UNKNOWN, nothing written.
 *  2. Resume height: the stored cursor `nodus_scan` + 1, else the caller's
 *     start_height. Nothing to read above T.
 *  3. The bot's own address history, newest first, page by page, down to the
 *     resume height. EVERY answer carries `enabled` and `from_height`; the
 *     step refuses (AMM_NW_REFUSED, nothing written) when the node is not
 *     indexing or its gap-free run starts above the bot's START height (plan
 *     line 283: "its from_height must be at or below the bot's start height;
 *     else the bot refuses to start"), whatever the stored cursor is. READING:
 *     the same facts are judged at every step, not only at start.
 *  4. Only `spend_in` rows with the native token (token all zero) are
 *     payments (plan line 240: "token all zero (native NODUS ...)"). Every
 *     other row is ignored; a TOKEN row is ignored (the dispatch: "A token
 *     row is ignored"), not held.
 *  5. Matching, per row, oldest first (the row's (height, item, seq) order):
 *       WIRE id kind:   the swap named in the request by the transfer's WIRE
 *                       id: the id text "nodus:<128 hex of the row's wire
 *                       id>" is looked up among the open approvals (plan
 *                       line 240: `wire` = the transfer named in the
 *                       request);
 *       INTENT id kind: the row's wire id is resolved to the transfer's
 *                       INTENT id by a block walk of the row's height (the
 *                       applied item with that wire id, seam item_intent);
 *                       the id text is "nodus:<128 hex of the intent id>"
 *                       (plan line 240: "matched through the block walk").
 *     WHICH id the request carries is the operator's open question 12 (plan
 *     line 445): the watcher takes it as an EXPLICIT parameter with NO
 *     DEFAULT (amm_nw_id_kind_t, 0 is refused). Both are implemented and
 *     tested; neither is chosen here.
 *     A found approval (state approved, NODUS -> USDT, sender = the row's
 *     peer, amount = the row's amount) is judged by amm_nodus_watch_match:
 *     the row's BLOCK time `ts` must be at most the expiry -- never the
 *     bot's clock (givens item 54: a payment whose block time is within the
 *     validity follows its approval even when the bot reads it later), and
 *     its block HEIGHT must be above the committed tip the bot read at
 *     approval (orchestrator's review finding (a): the plan's order is
 *     approval first, then payment; bound by chain height so that no wall
 *     clock is compared with chain state).
 *  6. Outcome of a row, in ONE journal transaction with the cursor move:
 *       MATCH      the swap moves approved -> paid_waiting_depth -> counted
 *                  (plan line 282: "a payment in a committed block is counted
 *                  with no extra depth"); counting writes the permanent
 *                  marker "nodus:<hex>" in the same transaction (plan line
 *                  369, givens item 59); the row is stored `counted` with the
 *                  swap. If another swap already carries the id, or the
 *                  marker exists, the row is HELD instead and nothing about
 *                  the swap changes (one incoming transfer, one payout);
 *       otherwise  the row is stored `held` with the reason (givens item 32:
 *                  "A payment that matches no approval is held for manual
 *                  handling"; not added to the ledger).
 *  7. A row that cannot be judged (a block walk that is incomplete or the
 *     block not held) makes the step AMM_NW_UNKNOWN: the rows before it are
 *     written, the cursor does NOT move, and the same rows are skipped
 *     (already recorded) next time. "A failed read changes no state" (plan
 *     line 372) is kept for the cursor and for the row itself.
 *  8. The cursor `nodus_scan` = T and `nodus_scan_ts` = the header time of T
 *     move together with the rows.
 *
 * WINDOW OBSERVATION (plan line 315, givens item 54): the payment window of an
 * approval is FULLY OBSERVED when the bot has processed the history through a
 * committed height whose block time is later than the approval's expiry
 * (amm_nodus_watch_window_observed). Why that is enough: block time does not
 * decrease from one committed block to the next. The implementing line is
 * nodus/src/witness/nodus_witness_cmt_host.c:1178 (nodus_cmt_validate_block:
 * `if (!time_after(block->header.time, state->last_block_time)) ... return
 * CMT_REJECT`, the port of CometBFT v0.38.26 state/validation.go:132-137),
 * with time_after strict on (seconds, nanos) at :967 and last_block_time set
 * at :1380. The `ts` of the address history and the block time read here are
 * the header time in WHOLE SECONDS (nodus_witness_addr_index.h:58-64; the
 * handler's `tm` / 1000), so in the unit the bot compares the block time is
 * non-decreasing, not strictly increasing: once one block has ts > expiry no
 * later block has ts <= expiry, which is all the window needs. The rule is
 * read for blocks above the initial height (the genesis block is the other
 * branch of that function, :1197).
 *
 * LIQUIDITY (plan line 328, givens item 49): amm_nodus_watch_depth_reached
 * counts a deposit when the Nodus tip is at least `liquidity_wait_blocks`
 * (setting liquidity_wait_nodus_blocks, 3) above the block that holds it.
 * Which request ties a liquidity deposit to its provider is open question 12;
 * a deposit that matches no swap approval is held, and the row's height is
 * what the depth is measured from.
 *
 * NOT HERE (other packages): moving a counted swap on (the engine), the
 * payout (amm_nodus_pay), the request parsing (question 12), any transport.
 *
 * DETERMINISM: rows are processed sorted by (height, item, seq); nothing here
 * reads a clock or random bytes.
 */
#ifndef AMM_NODUS_WATCH_H
#define AMM_NODUS_WATCH_H

#include <stdint.h>
#include <stddef.h>

#include "amm_journal.h"
#include "amm_node.h"

/** Which transfer id a request names (plan question 12, UNDECIDED). 0 is
 *  refused by amm_nodus_watch_new: there is no default. */
typedef enum {
    AMM_NW_ID_WIRE   = 1,   /* the wire id: matched through the address history */
    AMM_NW_ID_INTENT = 2    /* the intent id: matched through the block walk    */
} amm_nw_id_kind_t;

typedef struct amm_nodus_watch amm_nodus_watch_t;

typedef struct {
    const amm_node_t *node;            /* copied (the table, not ctx)        */
    amm_journal_t *journal;            /* not owned                          */
    amm_nw_id_kind_t id_kind;          /* REQUIRED, no default (question 12) */
    uint64_t start_height;             /* the bot's start height (>= 1)      */
    uint64_t liquidity_wait_blocks;    /* liquidity_wait_nodus_blocks (>= 1) */
    uint32_t page_limit;               /* history rows per page, 1..100      */
    uint64_t inflight_max;             /* inflight_max_usdt (>= 1): the room a
                                        * payment takes in the transaction that
                                        * first records it (plan section 13,
                                        * givens item 94)                    */
    int      held_keeps_room;          /* the setting (0 | 1)                */
    uint32_t max_pages;                /* history pages per step (>= 1): the
                                        * history is read newest first down to
                                        * the resume height, so a backlog of
                                        * more than page_limit * max_pages rows
                                        * is UNKNOWN until the bound is raised
                                        * (nothing is cut: the oldest rows are
                                        * the first to be judged)            */
} amm_nodus_watch_cfg_t;

typedef enum {
    AMM_NW_OK      = 0,   /* the step ended with nothing unresolved          */
    AMM_NW_UNKNOWN = 1,   /* a required read failed or is incomplete: rows
                           * written so far stay, the cursor did not move    */
    AMM_NW_REFUSED = 2,   /* the node's index is off or starts above the
                           * start height: nothing is written; the bot does
                           * not start / stops                               */
    AMM_NW_ERR     = -1   /* a journal fault or a bad configuration          */
} amm_nw_rc_t;

typedef struct {
    uint64_t tip;         /* the committed tip read (0 when unread)          */
    uint64_t through;     /* the stored cursor after the step                */
    int      rows;        /* payment rows judged this step                   */
    int      counted;     /* rows counted by a swap (it holds room)          */
    int      waiting;     /* rows taken by a swap that waits in line for
                           * room, not yet counted (plan section 13)         */
    int      held;        /* rows stored held                                */
    int      skipped;     /* rows already recorded                           */
    int      ignored;     /* history rows that are not native spend_in       */
} amm_nodus_step_t;

/** Validate the configuration and build a watcher. NULL on a bad config (a
 *  missing journal or seam function, id_kind not WIRE / INTENT, a zero
 *  bound, page_limit above the node's 100). */
amm_nodus_watch_t *amm_nodus_watch_new(const amm_nodus_watch_cfg_t *cfg);
void amm_nodus_watch_free(amm_nodus_watch_t *w);

/** PURE. The node's index facts against the bot's start height (plan line
 *  283): 1 = usable (indexing, from_height non-zero and at or below
 *  `resume`, here the START height), 0 = refuse. */
int amm_nodus_watch_index_ok(int enabled, uint64_t from_height,
                             uint64_t resume);

/** The startup refusal (plan line 283): read one page of the address history
 *  and judge `enabled` / `from_height` against the start height. @return
 *  AMM_NW_OK / AMM_NW_REFUSED (`why` says which fact) / AMM_NW_UNKNOWN (the
 *  node could not be read) / AMM_NW_ERR. `why` may be NULL. */
int amm_nodus_watch_start_check(amm_nodus_watch_t *w, uint64_t deadline_ms,
                                char *why, size_t why_cap);

/** One observation step (see the list above). `out` may be NULL. */
int amm_nodus_watch_step(amm_nodus_watch_t *w, uint64_t deadline_ms,
                         amm_nodus_step_t *out);

/** The id text of a transfer id: "nodus:" + 128 lowercase hex (the
 *  journal's incoming-id form, amm_journal.h). `cap` >= AMM_TID_MAX. */
void amm_nodus_watch_id_text(const uint8_t id[64], char *out, size_t cap);

typedef enum {
    AMM_NM_IGNORED      = 0,  /* not a native incoming payment: another kind,
                               * or a TOKEN row (never a payment, never held) */
    AMM_NM_NONE         = 1,  /* another sender: not this approval's payment  */
    AMM_NM_MATCH        = 2,  /* sender, exact amount, height above the
                               * approval's tip, block time <= expiry          */
    AMM_NM_HELD_VALUE   = 3,  /* this sender, another amount                  */
    AMM_NM_HELD_EXPIRED = 4,  /* this sender and amount, block time after the
                               * expiry: matches no approval -> held (item 54) */
    AMM_NM_HELD_EARLY   = 5   /* this sender and amount, in a block at or
                               * BELOW the tip read at approval -> held
                               * (review finding (a))                          */
} amm_nm_t;

/** PURE. Judge one address-history row against one NODUS -> USDT approval
 *  by kind (spend_in), token (all zero), peer (= the approval's sender),
 *  exact amount, the block HEIGHT `h` against the swap's `approved_tip` (must
 *  be above) and the BLOCK time `ts` against the expiry. The transfer id is
 *  matched by the caller (the journal lookup). The height bound rests on the
 *  orchestrator's finding, not on a plan sentence. */
amm_nm_t amm_nodus_watch_match(const nodus_dnac_addr_history_entry_t *row,
                               const amm_swap_t *swap);

/** The window rule of plan section 13 / givens item 54 for a NODUS payment:
 *  1 = the payment window of an approval that expires at `expiry_ts` is FULLY
 *  OBSERVED, 0 = not yet, -1 = fault. Observed means the history has been
 *  processed through a committed height whose block time is later than
 *  `expiry_ts` (the stored `nodus_scan_ts`); see the header comment for why
 *  that closes the window. The caller matches rows first (a counted row for
 *  the approval is a payment, not an unpaid window). No clock is read; no
 *  node call is made (the time was stored with the cursor). */
int amm_nodus_watch_window_observed(amm_nodus_watch_t *w, uint64_t expiry_ts);

/** PURE. A deposit in block `height` counts when the tip is at least `wait`
 *  blocks above it (plan line 328, `tip - block >= wait`). */
int amm_nodus_depth_ok(uint64_t tip, uint64_t height, uint64_t wait);

/** Has the Nodus block `height` reached the configured liquidity wait
 *  (liquidity_wait_nodus_blocks)? Reads the tip through the seam, writes
 *  nothing. @return 0 (`*reached` = 0 / 1) / 1 (the tip could not be read:
 *  unknown, `*reached` untouched) / -1. */
int amm_nodus_watch_depth_reached(amm_nodus_watch_t *w, uint64_t height,
                                  uint64_t deadline_ms, int *reached);

#endif /* AMM_NODUS_WATCH_H */
