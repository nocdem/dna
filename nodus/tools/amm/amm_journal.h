/**
 * @file amm_journal.h
 * @brief nodus-amm durable state (SQLite, WAL, synchronous=FULL), after
 *        tools/faucet/faucet_journal.h.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 17 (journal: WAL, synchronous=FULL, every state change one
 * transaction against a legal-transition table, permanent markers keyed by
 * the incoming transfer id, restart from every state), section 13 (in-flight
 * sum from the rows), section 7 step 4 and section 6.1 (approval in ONE
 * transaction: row, request-number marker, in-flight reservation), section 9
 * (cursors, block hashes, payment records), section 16 (pauses), givens
 * items 31, 54, 55, 57, 59.
 *
 * WHAT IS KEPT
 *   swaps         one row per approved request (state machine below)
 *   req_numbers   permanent (sender, request number) markers, written in the
 *                 approval transaction, never deleted (plan section 6.1)
 *   paid_markers  permanent markers keyed by the INCOMING TRANSFER ID,
 *                 written in the same transaction that counts the payment,
 *                 never deleted, checked before any payout or refund is
 *                 planned (plan section 17, givens item 59). Id text: the
 *                 Nodus transfer id named in the request ("nodus:<hex>") or
 *                 the Ethereum transaction ("eth:<64 hex tx hash>",
 *                 amm_journal_eth_key): the hash ALONE, not hash + log
 *                 index. Grounds: givens item 59 ("keyed by the incoming
 *                 transfer id"); the plan's Orbiter reference keys its
 *                 send-once marker by the SOURCE HASH (plan section 17,
 *                 sequencer.ts:256-264,309); a counted payment is one
 *                 top-level USDT `transfer` call (the watcher requires the
 *                 transfer selector, THORChain direct_erc20_transfer.go:
 *                 172-174), which emits one Transfer to the recipient
 *                 (TetherToken.sol:122-135: Transfer(msg.sender, _to,
 *                 sendAmount), plus Transfer(msg.sender, owner, fee) to the
 *                 owner only when a fee is set), so a re-mined transaction
 *                 under another log index is the same payment.
 *   pool          the ledger reserves and total units (plan section 12;
 *                 INFERENCE: the bot prices from its own ledger, so the
 *                 ledger must survive a restart)
 *   liq_withdraws the liquidity withdrawals (schema 8, see the end of this
 *                 file): accepted, acted on after 300 Ethereum blocks, their
 *                 two payouts written as rows of `swaps`
 *   flags         reversal_pause: set by a confirmed reversal (plan section
 *                 9, givens item 55); there is NO clear call, the clearing
 *                 action is DEFERRED (plan section 9). The effective
 *                 `swaps_paused` is the settings flag OR this one.
 *   cursors       named scan cursors (plan section 9, "stored cursor")
 *   blocks        retained block hashes: height, hash, parent hash, header
 *                 timestamp (plan section 9; timestamp for the window rule,
 *                 section 13)
 *   eth_records   payment records of the Ethereum watcher
 *   nodus_rows    incoming native `spend_in` rows of the Nodus watcher
 *                 (package 2): counted by a swap, or held (givens item 32)
 *   nodus_attempts the signed NODUS payout envelopes, stored before they are
 *                 sent (plan section 17; package 2)
 *   eth_attempts  the signed USDT payout transactions (hash, nonce, raw
 *                 bytes), stored before they are broadcast, UNIQUE on hash
 *                 and on (chain, nonce) (plan section 10; package 3)
 *
 * SWAP STATES (plan section 13 names approved, paid-waiting-depth, counted,
 * payout-pending, payout done, refund done, expired; section 9/16
 * reversed; sections 7, 8, 10, 14 held; section 17 unknown):
 *   approved            row + reservation written (7 step 4)
 *   paid_waiting_depth  a payment within the validity is seen, waiting for
 *                       its blocks (13); it carries the incoming id
 *   counted             the payment counted; marker written (17)
 *   payout_pending      output computed, ledger updated, payout planned (7)
 *   paid                payout done (13: "released when the payout is done")
 *   refund_pending      refund planned (7 step 7, 8 step 7, 16)
 *   refunded            refund done (13)
 *   expired             approval ended unpaid after its window was fully
 *                       observed (13, givens items 31, 54)
 *   held                held for manual handling (givens items 32, 53)
 *   reversed            a counted or paid payment reversed (9, item 55)
 *   unknown             a payout result cannot be established; stops new
 *                       approvals (17)
 * LEGAL TRANSITIONS (one table, amm_journal.c `legal`; each with its plan
 * line):
 *   approved -> paid_waiting_depth       13 ("A payment already seen within
 *                                        the approval's validity")
 *   approved -> expired                  13 window rule, item 31
 *   paid_waiting_depth -> counted        7 step 6 (depth reached)
 *   paid_waiting_depth -> approved       13 ("the record is dropped, the
 *                                        approval is again unpaid"); ONLY
 *                                        through amm_journal_payment_gone
 *   counted -> payout_pending            7 step 7 / 8 step 7 (output pays)
 *   counted -> refund_pending            7 step 7 / 8 step 7 (below the
 *                                        minimum or zero), 16 (paused)
 *   payout_pending -> paid               13
 *   payout_pending -> unknown            17
 *   payout_pending -> held               plan l.264, 277: the USDT delivered
 *                                        (Transfer log) differs from the USDT
 *                                        sent (TetherToken fee, TetherToken.sol:
 *                                        123-134); held for manual handling,
 *                                        what follows is DEFERRED
 *   (payout_pending -> refund_pending is REMOVED in revision 12: the decision
 *   of plan section 12 is made once, in one transaction, so no payout turns
 *   into a refund after it and nothing is reversed)
 *   refund_pending -> refunded           13
 *   refund_pending -> held               (edge kept; no payer uses it since
 *                                        givens items 89, 90: dropped)
 *   refund_pending -> unknown            17
 *   counted | payout_pending | paid | refund_pending | refunded | held |
 *   unknown -> reversed                  9, item 55 ("counted and paid
 *                                        payments"); READING: a payment
 *                                        counted whose swap later reached a
 *                                        payout, refund, held or unknown
 *                                        state is still a counted payment.
 *                                        ONLY through
 *                                        amm_journal_payment_gone.
 *   expired, held, unknown, reversed, paid, refunded: otherwise terminal here
 *   (the operator's resolution tools are DEFERRED, plan sections 17, 20).
 * ROOM (revision 12, plan section 13, givens item 94: "Yer, kullanicinin parasi
 * goruldugunde tutulsun ... Fiyat sormak hicbir sey tutmaz."): an approval holds
 * NOTHING. A swap takes room (`room` = 1) in the transaction that first records
 * its matching payment as seen (amm_journal_swap_seen: approved ->
 * paid_waiting_depth), and writes the next `seen_seq` on its row: the seen
 * order, one strict line. It takes room when (sum of value_usdt over the swaps
 * holding room) + its v <= the in-flight limit AND no payment seen before it
 * still waits (room = 0); otherwise it waits in the line, not counted
 * (`counted` needs room = 1: AMM_J_NO_ROOM). amm_journal_room_grant gives room
 * to the head of the line, in seen order, while it fits, never passing a head
 * that does not. Rows holding room: room = 1 in paid_waiting_depth, counted,
 * payout_pending, refund_pending (and held when `held_keeps_room` is 1: the
 * plan keeps the setting, it decides nothing here). Room is released when the
 * swap leaves those states: paid, refunded, dropped (a refund that is zero
 * after its fee), or its seen record is dropped before the count
 * (payment_gone / payment_unmatched clear room and seen_seq). unknown and
 * reversed do not hold room. The sums are computed from the rows, never kept
 * as a counter.
 *
 * A DB failure is never a value: every function returns -1 on a database
 * fault and the caller must not treat the fact as "none" or "zero"; a column
 * of the wrong type, a NULL text, a text that does not fit its field or a
 * blob of the wrong length fails the whole read (-1); every bind is checked.
 *
 * TRANSACTIONS: every call is one BEGIN IMMEDIATE ... COMMIT. A caller that
 * must make several calls atomic (the watcher's reorganisation write) wraps
 * them in amm_journal_tx_begin / amm_journal_tx_commit: the journal mutex is
 * recursive and the calls inside join that one transaction; a database
 * fault inside poisons it (commit then rolls back and returns -1). A
 * refusal (-2, a duplicate marker, ...) changes nothing and does not
 * poison it.
 *
 * Thread safety: one connection, one recursive mutex.
 */
#ifndef AMM_JOURNAL_H
#define AMM_JOURNAL_H

#include <stdint.h>
#include <stddef.h>

#include "amm_ledger.h"

#define AMM_S_APPROVED       "approved"
#define AMM_S_PAID_WAITING   "paid_waiting_depth"
#define AMM_S_COUNTED        "counted"
#define AMM_S_PAYOUT_PENDING "payout_pending"
#define AMM_S_PAID           "paid"
#define AMM_S_REFUND_PENDING "refund_pending"
#define AMM_S_REFUNDED       "refunded"
#define AMM_S_EXPIRED        "expired"
#define AMM_S_HELD           "held"
#define AMM_S_REVERSED       "reversed"
#define AMM_S_UNKNOWN        "unknown"
#define AMM_S_DROPPED        "dropped"   /* a refund that is zero after its
                                          * fee: not sent, not held (givens
                                          * items 89, 90; THORChain
                                          * manager_txout_current.go:991);
                                          * from refund_pending, terminal
                                          * (reversed only through
                                          * amm_journal_payment_gone);
                                          * holds no room                    */

#define AMM_STATE_MAX   20
#define AMM_MSG_MAX     160
/** Incoming transfer id text + NUL. Longest id: "nodus:" + 128 hex (a wire
 *  id or an intent id is 64 bytes, nodus_v2_spend.h:448-449) = 134 chars. */
#define AMM_TID_MAX     136
#define AMM_ADDR_ETH    40      /* lowercase hex digits                    */
#define AMM_ADDR_NODUS  128

/** Journal return codes. Gets: AMM_J_OK found / AMM_J_NONE none; every
 *  function: AMM_J_ERR a database fault. */
typedef enum {
    AMM_J_OK            = 0,
    AMM_J_NONE          = 1,   /* a get: no such row                        */
    /* approval refusals (nothing written, no request number consumed) */
    AMM_J_PAUSED        = 2,   /* swaps paused (settings flag or reversal)  */
    AMM_J_STOPPED       = 3,   /* a swap is in state unknown (plan s.17)    */
    AMM_J_REQ_REUSED    = 4,   /* (sender, request number) already used     */
    AMM_J_OPEN_DUP      = 5,   /* an open approval with the same sender and
                                * amount exists; `out` is that swap (item 57) */
    AMM_J_SWAP_LIMIT    = 6,   /* v above the per-swap limit                */
    AMM_J_INFLIGHT      = 7,   /* in-flight total would pass its limit      */
    AMM_J_DUP_TRANSFER  = 8,   /* the incoming transfer id already counted
                                * (permanent marker), or already carried by
                                * another swap that has taken the payment
                                * (see amm_journal_swap_transition); nothing
                                * changed                                   */
    AMM_J_RANGE         = 9,   /* a field outside its format or bounds      */
    AMM_J_NUMBER_TAKEN  = 10,  /* quote: the bot's request number is already
                                * the number of another approval; redraw    */
    AMM_J_NO_APPROVAL   = 11,  /* accept: no approval carries that number   */
    AMM_J_AMOUNT        = 12,  /* accept: the signed amount or direction
                                * differs from the approval's (item 87)     */
    AMM_J_NO_ROOM       = 13,  /* counted: the swap holds no room (it waits in
                                * line, plan section 13)                    */
    AMM_J_BELOW_MIN     = 14,  /* liquidity add question: the NODUS side is
                                * below liquidity_min_nodus (givens item 96) */
    AMM_J_BUSY          = 15,  /* a price or liquidity question: the open
                                * unpaid questions are at `open_max` (givens
                                * item 98); nothing written                  */
    AMM_J_NO_POSITION   = 16,  /* a withdrawal: the two addresses are not a
                                * stored position with units (plan 6.4.6)    */
    AMM_J_ILLEGAL       = -2,  /* illegal transition / unknown row          */
    AMM_J_ERR           = -1
} amm_jrc_t;

typedef struct amm_journal amm_journal_t;

typedef struct {
    int64_t   seq;
    char      id[33];                 /* 32 lowercase hex                   */
    amm_dir_t dir;
    char      state[AMM_STATE_MAX];
    char      sender[AMM_ADDR_NODUS + 1];
    char      dest[AMM_ADDR_NODUS + 1];
    uint64_t  amount;                 /* input side, raw                    */
    uint64_t  minimum;                /* signed minimum to receive, raw     */
    uint64_t  value_usdt;             /* v of plan section 13, USDT raw     */
    uint64_t  approved_at;            /* unix seconds, caller-supplied      */
    uint64_t  expiry;                 /* unix seconds, written at approval  */
    uint64_t  approved_tip;           /* the chain tip HEIGHT the bot read
                                       * for the payment's chain at approval
                                       * (Ethereum quorum tip / Nodus
                                       * committed tip), > 0: a payment
                                       * counts only in a block ABOVE it    */
    char      incoming_id[AMM_TID_MAX]; /* "" until known                   */
    char      message[AMM_MSG_MAX];
    /* revision 10 (approval at the price question; schema 5): */
    uint64_t  quote_out;              /* the INDICATIVE number the bot gave at
                                       * the question: the output before the
                                       * network fee (givens 82, 93); 0 for a
                                       * row written by amm_journal_approve  */
    uint64_t  est_fee;               /* the estimated network fee it showed
                                       * apart (shown only, never charged)   */
    uint64_t  req_no_bot;             /* the bot's 32-bit request number, the
                                       * swap id of the API (givens 85-87);
                                       * 0 = none (an old-style row)         */
    /* revision 12 (schema 6): the decision and the room */
    uint64_t  out_amount;             /* the output computed in the decision from
                                       * the depths then, before the network fee
                                       * (givens 93); 0 until decided, 0 for a
                                       * refund                              */
    uint64_t  out_fee;                /* the network fee deducted in the decision
                                       * (USDT: the ceiling, givens 95; NODUS: the
                                       * planner's fee)                      */
    uint64_t  out_paid;               /* out_amount - out_fee, what the payout
                                       * carries                             */
    int64_t   seen_seq;               /* the seen order, 0 = payment not seen  */
    int       room;                   /* 1 = holds room under the in-flight total */
} amm_swap_t;

/** Input of one approval. All fields are caller values; the journal reads no
 *  clock. `incoming_id` may be "" (Ethereum direction: not known yet) or
 *  the Nodus transfer id named in the request ("nodus:<hex>"). */
typedef struct {
    amm_dir_t dir;
    const char *sender;               /* 40 hex (USDT->NODUS) or 128 hex     */
    const char *dest;                 /* the other kind                      */
    uint64_t amount, minimum, value_usdt;
    uint64_t approved_at, expiry;
    uint64_t approved_tip;            /* the tip height the caller READ for the
                                       * payment's chain; 0 = unreadable and
                                       * the approval is refused (AMM_J_RANGE),
                                       * never stored as 0                    */
    uint8_t  req_no[32];              /* big-endian request number           */
    const char *incoming_id;
    uint8_t  rand16[16];              /* the swap id's randomness            */
    uint64_t swap_max, inflight_max;  /* settings (plan s.15)                */
    int      swaps_paused_cfg;        /* the settings flag                   */
    int      held_keeps_room;         /* the setting (0 | 1, plan l.312/407) */
} amm_approve_t;

/** Open (and create) the journal. Refuses a newer schema. @return 0 / -1. */
int  amm_journal_open(const char *path, amm_journal_t **out);
void amm_journal_close(amm_journal_t *j);

/** Group several calls into one transaction (see TRANSACTIONS). */
int amm_journal_tx_begin(amm_journal_t *j);
int amm_journal_tx_commit(amm_journal_t *j);
void amm_journal_tx_rollback(amm_journal_t *j);

/** TEST ONLY -- production never calls it. `fn` (NULL = none) runs right
 *  before every COMMIT; a non-zero return rolls the transaction back and the
 *  call returns -1, so a test can end a write exactly between the decision
 *  and its commit without killing the process. */
void amm_journal_test_precommit_hook(int (*fn)(void));

/** The one approval transaction (plan section 7 step 4): refusals in this
 *  order -- paused, stopped (a swap in unknown), request number reused, open
 *  approval with the same sender and amount (item 57; `out` = that swap),
 *  v above swap_max, in-flight sum + v above inflight_max -- else row
 *  `approved` + request-number marker, in ONE transaction. A refusal writes
 *  nothing, so it consumes no request number. @return AMM_J_OK (`out` = the
 *  new swap) / a refusal code / AMM_J_RANGE / -1. */
int amm_journal_approve(amm_journal_t *j, const amm_approve_t *a,
                        amm_swap_t *out);

/** Input of the approval given at the PRICE QUESTION (plan section 7 step 3,
 *  section 8 step 3; givens items 66, 68, 82, 85-87): direction and amount
 *  only, no sender yet. All fields are caller values; the journal reads no
 *  clock and draws no randomness (`bot_req` is the caller's 32-bit random
 *  number, 1..UINT32_MAX). */
typedef struct {
    amm_dir_t dir;
    uint64_t amount;                  /* input side, raw                     */
    uint64_t quote_out;               /* the bot's number (output before the
                                       * network fee)                        */
    uint64_t est_fee;                 /* the estimated network fee, shown     */
    uint64_t value_usdt;              /* v of plan section 13                */
    uint64_t approved_at, expiry;
    uint64_t approved_tip;            /* as amm_approve_t; 0 is refused      */
    uint32_t bot_req;
    uint8_t  rand16[16];              /* the swap id's randomness            */
    uint64_t swap_max, inflight_max;
    int      swaps_paused_cfg;
    int      held_keeps_room;
    uint64_t open_max;                /* quote_open_max (givens item 98): the
                                       * approval is refused (AMM_J_BUSY) when
                                       * the open unpaid questions are at it;
                                       * 0 = no limit (tests)                 */
} amm_quote_t;

/** The approval transaction of the price question: refusals in this order --
 *  paused, stopped (a swap in unknown), number already taken (AMM_J_NUMBER_
 *  TAKEN, nothing written: redraw), v above swap_max, in-flight sum + v above
 *  inflight_max -- else row `approved` (sender and destination empty, the
 *  bot's number, estimated fee, request number, expiry, value) and its
 *  in-flight reservation, in ONE transaction. Item 57 is NOT checked here
 *  (no sender yet): it runs in amm_journal_accept_request. */
int amm_journal_quote_approve(amm_journal_t *j, const amm_quote_t *q,
                              amm_swap_t *out);

/** The approval whose bot request number is `bot_req`. 0 / 1 none / -1. */
int amm_journal_swap_by_botreq(amm_journal_t *j, uint32_t bot_req,
                               amm_swap_t *out);

/** Input of the signed request (after amm_req verified it). */
typedef struct {
    uint32_t bot_req;                 /* the request number in the signed text */
    amm_dir_t dir;
    const char *sender;               /* as amm_approve_t                    */
    const char *dest;
    uint64_t amount;                  /* the signed amount (item 87)         */
    uint64_t minimum;
    const char *incoming_id;          /* "nodus:<hex>" for NODUS -> USDT, else ""  */
    uint8_t  req_no[32];              /* big-endian request number           */
} amm_accept_t;

/** The signed-request transaction (givens items 83, 84, 87): the approval
 *  numbered `bot_req` must exist (AMM_J_NO_APPROVAL), be `approved` and not yet
 *  signed (else AMM_J_ILLEGAL: a number is accepted once), and its direction
 *  and amount must equal the signed ones (AMM_J_AMOUNT). Then the permanent
 *  (sender, request number) marker is checked (AMM_J_REQ_REUSED) and item 57:
 *  another signed open approval (approved, paid_waiting_depth) with the same
 *  sender and amount gives AMM_J_OPEN_DUP (`out` = that swap). Else sender,
 *  destination, minimum and incoming id are written to the row and the marker
 *  is inserted, in ONE transaction. `out` = the swap. */
int amm_journal_accept_request(amm_journal_t *j, const amm_accept_t *a,
                               amm_swap_t *out);

/** 0 found / 1 none / -1. `swap_by_incoming` returns the OLDEST swap that
 *  carries the id (several can: two approvals may name one Nodus transfer). */
int amm_journal_swap_get(amm_journal_t *j, const char *id, amm_swap_t *out);
int amm_journal_swap_by_seq(amm_journal_t *j, int64_t seq, amm_swap_t *out);
int amm_journal_swap_by_incoming(amm_journal_t *j, const char *incoming_id,
                                 amm_swap_t *out);

/** The OLDEST NODUS -> USDT swap in state `approved` that carries
 *  `incoming_id` (the transfer id its request names, "nodus:<hex>"), whose
 *  sender is `sender` (128 hex) and whose amount is `amount`. Item 57 lets at
 *  most one such swap be open at a time; the oldest is returned if there are
 *  several. Time rules are NOT applied here (amm_nodus_watch_match). 0 found /
 *  1 none / -1. */
int amm_journal_swap_open_nodus(amm_journal_t *j, const char *incoming_id,
                                const char *sender, uint64_t amount,
                                amm_swap_t *out);

/** Move a swap to `to` (legal table above; `approved`, `paid_waiting_depth`
 *  and `reversed` are refused here: the first and the last only through
 *  payment_gone / payment_unmatched, the middle one only through
 *  amm_journal_swap_seen, which takes the room). `incoming_id` (NULL = keep)
 *  is stored; for `counted` the swap must carry one AND hold room (else
 *  AMM_J_NO_ROOM, nothing changed) and its PERMANENT marker is inserted in
 *  this same transaction -- an existing marker returns AMM_J_DUP_TRANSFER and
 *  nothing changes (plan section 17, givens item 59). An incoming id, once
 *  set, is never changed: naming another id on a swap that already carries one
 *  is AMM_J_ILLEGAL. `pool` MUST be NULL: a non-NULL pool is refused
 *  (AMM_J_ILLEGAL, nothing written); the ledger changes only in
 *  amm_journal_swap_decide and amm_journal_add_commit. `message` (NULL = keep) is stored. 0 / AMM_J_ILLEGAL /
 *  AMM_J_NO_ROOM / AMM_J_DUP_TRANSFER / -1. */
int amm_journal_swap_transition(amm_journal_t *j, int64_t seq, const char *to,
                                const char *incoming_id,
                                const amm_pool_t *pool, const char *message);

/** A matching payment is SEEN (plan section 13; givens item 94): ONE
 *  transaction moves the `approved` swap to paid_waiting_depth with its
 *  incoming id, writes the next seen_seq and takes room or joins the line (see
 *  ROOM above). ONE INCOMING TRANSFER, ONE SWAP (orchestrator's review finding
 *  on package 1; plan section 8): refused with AMM_J_DUP_TRANSFER, nothing
 *  changed, when ANOTHER swap already carrying the same incoming id is in a
 *  state that has taken the payment -- every state except `approved` (a
 *  request may name a transfer before any payment exists) and `expired` -- or
 *  when the permanent marker of the id exists. `took_room` (may be NULL) = 1
 *  when the swap holds room afterwards, 0 when it waits. 0 / AMM_J_ILLEGAL /
 *  AMM_J_DUP_TRANSFER / AMM_J_RANGE / -1. */
int amm_journal_swap_seen(amm_journal_t *j, int64_t seq, const char *incoming_id,
                          const char *message, uint64_t inflight_max,
                          int held_keeps_room, int *took_room);

/** Give room to the head of the line while it fits (ROOM above): in seen
 *  order, the earliest paid_waiting_depth swap with room = 0 takes room when
 *  (sum) + its v <= inflight_max; a head that does not fit stops the line, a
 *  later smaller swap never passes it. ONE transaction. `granted` (may be
 *  NULL) = the number of swaps that took room. 0 / -1. */
int amm_journal_room_grant(amm_journal_t *j, uint64_t inflight_max,
                           int held_keeps_room, int *granted);

/** The sum of value_usdt over the swaps holding room (ROOM above), computed
 *  from the rows with checked addition. 0 / -1 (an overflow of the sum is a
 *  fault). `held_keeps_room` = 1 adds the swaps in state held that hold room. */
int amm_journal_inflight_sum(amm_journal_t *j, int held_keeps_room,
                             uint64_t *out);

/** The sum the bot still owes in ONE payout asset (want_usdt = 1: USDT, 0:
 *  NODUS) over the swaps whose payment is SEEN and not finished (plan section
 *  12, "the bot-key balance estimate counts only swaps whose payment is seen";
 *  an unpaid approval holds nothing): paid_waiting_depth and counted swaps owe
 *  their indicative number `quote_out` in their payout asset, payout_pending
 *  swaps their decided `out_amount`, refund_pending swaps their input `amount`
 *  in the input asset. Streamed row by row (no cap), checked addition. 0 / -1. */
int amm_journal_owed_sum(amm_journal_t *j, int want_usdt, uint64_t *out);

/* amm_journal_swap_decide (the decision of a counted swap, one transaction) is
 * declared at the end of this file, after the payout attempt types. */

/** One page of swaps in `state`: the rows whose key is greater than `after`
 *  (0 = from the start), ordered by that key, at most `cap` (>= 1); the caller
 *  asks again with the last key it got until fewer than `cap` come back, so no
 *  number of rows can stop a walk. by_seen = 0: key = seq; by_seen = 1: key =
 *  seen_seq (the line and the decisions, plan sections 13, 14; rows without a
 *  seen_seq are not listed). The key of the last row is its seq or seen_seq.
 *  0 / -1. */
int amm_journal_swap_page(amm_journal_t *j, const char *state, int by_seen,
                          int64_t after, amm_swap_t *out, int cap, int *n);

/** The signed, still unpaid USDT -> NODUS approval of `sender` (40 lowercase
 *  hex) for exactly `amount` (state `approved`), if any: a keyed lookup (item
 *  57 lets at most one signed open approval exist per sender and amount). 0
 *  found / 1 none / -1. */
int amm_journal_swap_find_open_usdt(amm_journal_t *j, const char *sender,
                                    uint64_t amount, amm_swap_t *out);

/** Swaps in `state`, oldest first, up to `cap`; a result that would exceed
 *  `cap` is a fault (-1), never cut. KEPT for tests and bounded callers; the
 *  engine pages with amm_journal_swap_page. 0 / -1. */
int amm_journal_swap_list_state(amm_journal_t *j, const char *state,
                                amm_swap_t *out, int cap, int *n);

/** Paid NODUS -> USDT swaps (USDT payouts) with NO fee_book row and
 *  seq > `after_seq`, oldest first, at most `cap` (a page: the caller passes
 *  the last seq it read as `after_seq` until fewer than `cap` come back; no
 *  lifetime row limit). 0 / -1. */
int amm_journal_swap_list_unbooked_paid(amm_journal_t *j, int64_t after_seq,
                                        amm_swap_t *out, int cap, int *n);

/** The network fee deducted from a USDT payout, kept by the Foundation AS USDT
 *  (givens items 80, 92: "Vakfa kalsın. Ücreti ödeyen geri alır."): ONE
 *  transaction inserts the row of swap `swap_seq` (it must be in state paid,
 *  and have no row: AMM_J_ILLEGAL). `fee` = the USDT deducted. The pool is not
 *  written: its USDT depth already fell by the full gross payout at the ledger
 *  update and the NODUS depth is not touched by the fee. */
int amm_journal_book_fee(amm_journal_t *j, int64_t swap_seq, uint64_t fee);
/** 0 booked / 1 not booked / -1. `fee` may be NULL. */
int amm_journal_fee_booked(amm_journal_t *j, int64_t swap_seq, uint64_t *fee);
/** The USDT booked to the Foundation in total. 0 / -1. */
int amm_journal_foundation_usdt(amm_journal_t *j, uint64_t *out);

/** Number of swaps in `state`. 0 / -1. */
int amm_journal_state_count(amm_journal_t *j, const char *state, int *out);

/** 0 marker exists / 1 none / -1 (plan section 17: checked before any
 *  payout or refund is planned). */
int amm_journal_marker_exists(amm_journal_t *j, const char *transfer_id);
int amm_journal_req_marker_exists(amm_journal_t *j, const char *sender,
                                  const uint8_t req_no[32]);

/** Ledger reserves. pool_get: 0 found / 1 none / -1. pool_put replaces them.
 *  The stored blobs are 32-byte big-endian. */
int amm_journal_pool_get(amm_journal_t *j, amm_pool_t *out);
int amm_journal_pool_put(amm_journal_t *j, const amm_pool_t *p);

/** The reversal pause (plan section 9, item 55): *out = 0 / 1. There is no
 *  clear call. 0 / -1. */
int amm_journal_reversal_pause_get(amm_journal_t *j, int *out);

/** Named cursors. get: 0 / 1 none / -1. put moves FORWARD only (a lower or
 *  equal value is refused with AMM_J_ILLEGAL, "never backwards"); reset sets
 *  any value (the reorganisation rescan). */
int amm_journal_cursor_get(amm_journal_t *j, const char *name, uint64_t *out);
int amm_journal_cursor_put(amm_journal_t *j, const char *name, uint64_t v);
int amm_journal_cursor_reset(amm_journal_t *j, const char *name, uint64_t v);

/* ── Ethereum block hashes (plan section 9) ───────────────────────────── */

typedef struct {
    uint64_t height;
    uint8_t  hash[32];
    uint8_t  parent[32];
    uint64_t ts;                      /* header timestamp, unix seconds     */
} amm_blk_t;

int amm_journal_block_put(amm_journal_t *j, const amm_blk_t *b);   /* replace */
int amm_journal_block_get(amm_journal_t *j, uint64_t height, amm_blk_t *out);
/** Delete every stored block with height >= `height` (reorganisation). */
int amm_journal_blocks_delete_from(amm_journal_t *j, uint64_t height);
/** Delete every stored block with height < `height` (the window prune). */
int amm_journal_blocks_prune_below(amm_journal_t *j, uint64_t height);
/** 0 found / 1 none: the lowest stored block with timestamp > `ts` and
 *  height <= `max_height` (`out_height`). */
int amm_journal_block_after_ts(amm_journal_t *j, uint64_t ts,
                               uint64_t max_height, uint64_t *out_height);

/* ── Ethereum payment records (plan section 9) ────────────────────────── */

#define AMM_R_CANDIDATE "candidate"   /* below quorum, retained (9)          */
#define AMM_R_SEEN      "seen"        /* quorum, below the confirmation depth */
#define AMM_R_DEEP      "deep"        /* confirmation depth reached           */
#define AMM_R_HELD      "held"        /* matches no approval (7 matching)     */
#define AMM_R_DROPPED   "dropped"     /* block hash gone before counting (9)  */
#define AMM_R_REVERSED  "reversed"    /* a counted/paid payment reversed (9)  */

typedef struct {
    uint8_t  tx[32];
    uint32_t log_index;
    uint64_t block_number;
    uint8_t  block_hash[32];
    uint64_t block_ts;
    uint8_t  from[20];
    uint8_t  to[20];
    uint8_t  value[32];               /* the LOGGED value, big-endian        */
    char     state[12];
} amm_rec_t;

/** "eth:<64 hex tx hash>" (the permanent marker key and the swap's incoming
 *  id, see the header comment). `cap` must be >= AMM_TID_MAX. */
void amm_journal_eth_key(const uint8_t tx[32], char *out, size_t cap);

/** Insert a record, or refresh an existing one (block fields and state).
 *  Record state table: candidate -> seen|dropped; seen -> candidate|deep|
 *  dropped; deep -> seen|held|dropped; held -> deep|dropped; dropped ->
 *  candidate|seen; reversed is terminal; a same-state refresh is allowed
 *  except on dropped and reversed. An illegal change: AMM_J_ILLEGAL.
 *  ONE LIVE RECORD PER TRANSACTION (candidate/seen/deep/held): a record
 *  that would become live (a new row, or dropped -> candidate|seen) while
 *  another LIVE record of the same transaction hash exists is refused with
 *  AMM_J_ILLEGAL, except that a SEEN record (a quorum record) displaces
 *  other records of the transaction that are only CANDIDATES (they become
 *  dropped, in the same transaction); a live record that is not a candidate
 *  is never displaced. */
int amm_journal_rec_put(amm_journal_t *j, const amm_rec_t *r);
int amm_journal_rec_get(amm_journal_t *j, const uint8_t tx[32],
                        uint32_t log_index, amm_rec_t *out);
/** Records with block_number >= min_block in `state` (NULL = any of
 *  candidate/seen/deep/held), ordered by (block_number, tx, log_index). Up to
 *  `cap`; *n = count; a result that would exceed `cap` is a fault (-1),
 *  never cut. */
int amm_journal_rec_list(amm_journal_t *j, uint64_t min_block,
                         const char *state, amm_rec_t *out, int cap, int *n);
/** 0 found / 1 none / -1: another LIVE record (candidate/seen/deep/held) with
 *  the same transaction hash and another log index. */
int amm_journal_rec_other_live(amm_journal_t *j, const uint8_t tx[32],
                               uint32_t log_index);
/** Records in `state` (any block height) that no swap has consumed: no swap
 *  carries the record's transaction key, or the swap that does is still in
 *  paid_waiting_depth (the payment waits to be counted). Ordered by (block,
 *  tx, log index); one page of at most `cap` (> 0) records strictly after the
 *  record `after` in that order (NULL: from the start). The caller pages
 *  until a page holds fewer than `cap`, so any number of records is read (Sol
 *  verify 10, claim 6). The engine reads these, not a block window: a payment
 *  stored by the watcher but not yet matched stays readable after any
 *  downtime. 0 / -1. */
int amm_journal_rec_list_unconsumed(amm_journal_t *j, const char *state,
                                    const amm_rec_t *after,
                                    amm_rec_t *out, int cap, int *n);
/** A deep record whose payment no longer matches the approval that carries it
 *  (a reorganisation moved it outside the approval's validity): ONE
 *  transaction returns the carrying paid_waiting_depth swap to approved (link
 *  cleared) and holds the record (givens item 32: a payment that matches no
 *  approval is held). AMM_J_ILLEGAL when the record is not deep. 0 / -1 /
 *  AMM_J_ILLEGAL. */
int amm_journal_payment_unmatched(amm_journal_t *j, const uint8_t tx[32],
                                  uint32_t log_index);
/** 0 found / 1 none: a candidate record with this from and logged value
 *  that is FOR the approval: its block height is ABOVE `approved_tip` (the
 *  tip the bot read at approval; a payment in or below that block is not a
 *  payment for it -- the orchestrator's review finding, bound by chain
 *  height, never by the wall clock) and its block time is within the
 *  validity, block_ts <= `max_block_ts` (plan lines 314, 319), or unknown
 *  (block_ts == 0, kept conservatively on the time bound). Plan section 13:
 *  "no below-quorum record retained for that approval is still
 *  unresolved". */
int amm_journal_rec_candidate_exists(amm_journal_t *j, const uint8_t from[20],
                                     const uint8_t value[32],
                                     uint64_t approved_tip,
                                     uint64_t max_block_ts);

typedef enum {
    AMM_GONE_DROPPED  = 0,   /* the record is dropped; a swap waiting for its
                              * depth is unpaid again (13)                  */
    AMM_GONE_REVERSED = 1    /* a counted/paid payment: swap -> reversed,
                              * reversal_pause set (9, item 55)            */
} amm_gone_t;

/** The payment of record (tx, log_index) is gone (block hash disappeared, or
 *  its transaction is no longer found at the quorum), ONE transaction. EVERY
 *  swap that carries the record's key as incoming id is handled (several can:
 *  orchestrator's review finding), each by its own state:
 *  - approved / expired / reversed: left as it is;
 *  - paid_waiting_depth -> approved with its incoming id cleared;
 *  - counted/payout_pending/paid/refund_pending/refunded/held/unknown (a
 *    payment that was counted): swap -> reversed;
 *  and the record: -> reversed and reversal_pause set (AMM_GONE_REVERSED,
 *  givens item 55) when at least one swap was reversed, else -> dropped
 *  (AMM_GONE_DROPPED).
 *  The record must be in candidate/seen/deep/held, else AMM_J_ILLEGAL. */
int amm_journal_payment_gone(amm_journal_t *j, const uint8_t tx[32],
                             uint32_t log_index, amm_gone_t *outcome);

/* ── Nodus incoming payments (plan sections 8, 11, 17) ────────────────── */

#define AMM_NR_HELD     "held"        /* matches no approval (givens item 32) */
#define AMM_NR_COUNTED  "counted"     /* taken by a swap (marker written)     */

/** One `spend_in` row of the bot's own address history with the native
 *  token, as the Nodus watcher recorded it. Key: (height, item, seq) = the
 *  row's (h, i, q) of dnac_addr_history, unique per row. `wire` is the
 *  item's 64-byte wire id. A recorded row is never processed twice. Kept
 *  for the operator (held rows are the "held for manual handling" of givens
 *  item 32) and for the liquidity depth (plan line 328). */
typedef struct {
    uint64_t height;
    uint32_t item;
    uint32_t seq;
    uint8_t  wire[64];
    char     peer[AMM_ADDR_NODUS + 1];
    uint64_t amount;
    uint64_t ts;                      /* block time, unix seconds           */
    char     state[8];                /* AMM_NR_*                           */
    int64_t  swap_seq;                /* the swap that took it, 0 = none    */
    char     reason[AMM_MSG_MAX];     /* why it is held                     */
} amm_nrow_t;

/** Insert a row. An existing (height, item, seq) -> AMM_J_ILLEGAL, nothing
 *  changed. 0 / AMM_J_ILLEGAL / AMM_J_RANGE (a value above INT64_MAX, a
 *  malformed peer, an unknown state) / -1. */
int amm_journal_nrow_put(amm_journal_t *j, const amm_nrow_t *r);
/** 0 found / 1 none / -1. */
int amm_journal_nrow_get(amm_journal_t *j, uint64_t height, uint32_t item,
                         uint32_t seq, amm_nrow_t *out);
/** The oldest row with this wire id. 0 found / 1 none / -1. */
int amm_journal_nrow_by_wire(amm_journal_t *j, const uint8_t wire[64],
                             amm_nrow_t *out);
/** Rows in `state` (NULL = any), ordered by (height, item, seq). Up to
 *  `cap`; a result that would exceed `cap` is a fault (-1), never cut. */
int amm_journal_nrow_list(amm_journal_t *j, const char *state, amm_nrow_t *out,
                          int cap, int *n);

/* ── NODUS payout attempts (plan sections 11, 17: write-ahead) ────────── */

#define AMM_MAX_INPUTS  15        /* one SPEND takes 1..15 inputs (s.11)  */
#define AMM_A_SIGNED    "signed"
#define AMM_A_SUBMITTED "submitted"
#define AMM_A_EXPIRED   "expired"
#define AMM_A_CONFIRMED "confirmed"

/** One signed NODUS payout envelope of one swap, stored BEFORE it is sent
 *  (plan section 17 write-ahead rule; faucet_journal.h attempts). The swap
 *  must be in payout_pending or refund_pending. `gross` is the amount the
 *  swap owes the user, `fee` the Nodus fee deducted from it (givens item
 *  39), `net` = gross - fee the amount the recipient output carries. */
typedef struct {
    int64_t  swap_seq;
    int      n;                       /* attempt number, 1-based (assigned)  */
    uint64_t gross, net, fee;
    char     dest[AMM_ADDR_NODUS + 1];
    uint8_t *env;                     /* heap; amm_attempt_free              */
    size_t   env_len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
    uint8_t  inputs[AMM_MAX_INPUTS][64];
    int      n_in;
    uint64_t build_tip;
    uint64_t expiry;                  /* expiry height of the envelope       */
    uint64_t scan_next;               /* next height to scan                 */
    uint64_t last_submit_tip;         /* 0 = never submitted                 */
    char     state[12];               /* AMM_A_*                             */
} amm_attempt_t;

void amm_attempt_free(amm_attempt_t *a);

/** The OLDEST swap that owes a NODUS payout: a USDT -> NODUS swap in
 *  payout_pending or a NODUS -> USDT swap in refund_pending (the one payout in
 *  flight, as the faucet's head claim; the other two combinations are USDT
 *  payouts and are not the Nodus payer's). 0 found / 1 none / -1. */
int amm_journal_swap_head_payout(amm_journal_t *j, amm_swap_t *out);

/** As amm_journal_swap_head_payout, but a swap WITHOUT an open attempt is
 *  chosen only when its seq is above `after_seq` (>= 0): the engine defers a
 *  swap whose expired replacement was not stored and goes on to the next owed
 *  swap in seq order, never selecting the deferred one again in the same round.
 *  A swap whose attempt is signed or submitted is returned whatever `after_seq`
 *  says. 0 found / 1 none / -1. */
int amm_journal_swap_head_payout_after(amm_journal_t *j, int64_t after_seq,
                                       amm_swap_t *out);

/** The input coins (nullifiers, 64 bytes each) the payer must NOT plan a spend
 *  over: the inputs of the LATEST attempt of every swap other than
 *  `except_seq` (-1 = none) whose latest attempt is expired and which still
 *  owes a NODUS payout (a USDT -> NODUS swap in payout_pending or a
 *  NODUS -> USDT swap in refund_pending). Derived from nodus_attempts joined
 *  with swaps: no table of its own, so it survives a restart and a swap that
 *  leaves the owed states (paid, refunded, dropped, unknown) releases its coins.
 *  Written to `nul[0..*n)`, at most `cap`; duplicates are possible. @return 0 /
 *  1 = more than `cap` inputs (`nul` holds the first `cap`: the caller must not
 *  plan) / -1. */
int amm_journal_nodus_reserved(amm_journal_t *j, int64_t except_seq,
                               uint8_t (*nul)[64], int cap, int *n);

/** Store a NEW signed attempt (a->swap_seq, gross, net, fee, dest, env,
 *  ids, inputs, ticks filled by the caller; a->n and a->state assigned) in
 *  ONE transaction. Legal only when the swap is in payout_pending or
 *  refund_pending, `a->net` + `a->fee` == `a->gross` with net > 0, 1..15
 *  inputs, and the swap has no attempt yet or its latest attempt is expired
 *  (a replacement is made only after expiry, plan section 11), and NO OTHER
 *  swap has an attempt in signed or submitted (one payout in flight: the
 *  bot's coins are not reserved per swap, so two open envelopes would spend
 *  the same coin; READING, the plan says nothing of concurrent payouts). 0 /
 *  AMM_J_ILLEGAL / AMM_J_RANGE / -1. */
int amm_journal_attempt_sign(amm_journal_t *j, amm_attempt_t *a);
/** The latest attempt of a swap (env heap). 0 / 1 none / -1. */
int amm_journal_attempt_latest(amm_journal_t *j, int64_t swap_seq,
                               amm_attempt_t *out);
/** Record a submit CALL on the latest attempt: last_submit_tip = tip and,
 *  from signed, the attempt becomes submitted. The node's answer is not an
 *  input. 0 / AMM_J_ILLEGAL (no attempt, or not signed/submitted) / -1. */
int amm_journal_attempt_submitted(amm_journal_t *j, int64_t swap_seq,
                                  uint64_t tip);
/** Advance the scan cursor of the latest attempt. Never backwards: a value
 *  not above the stored cursor is AMM_J_ILLEGAL. 0 / AMM_J_ILLEGAL / -1. */
int amm_journal_attempt_scanned(amm_journal_t *j, int64_t swap_seq,
                                uint64_t scan_next);
/** confirmed | expired, on the latest attempt, from signed or submitted.
 *  The swap's own state is NOT moved here (the caller does it in the same
 *  outer transaction, amm_journal_tx_begin). 0 / AMM_J_ILLEGAL / -1. */
int amm_journal_attempt_finish(amm_journal_t *j, int64_t swap_seq,
                               const char *state);

/* ── USDT payout attempts (package 3; plan sections 10, 17: write-ahead) ─ */

#define AMM_EA_SIGNED    "signed"     /* stored, never broadcast               */
#define AMM_EA_SUBMITTED "submitted"  /* broadcast at least once               */
#define AMM_EA_CONFIRMED "confirmed"  /* receipt status 1 at the final depth   */
#define AMM_EA_FAILED    "failed"     /* receipt status != 1 at the final depth
                                       * (plan line 268: "failed send")        */
#define AMM_EA_ORPHANED  "orphaned"   /* no receipt and the nonce is below the
                                       * confirmed nonce (plan line 268)       */
#define AMM_EA_UNKNOWN   "unknown"    /* receipt status 1 at the final depth but
                                       * no USDT Transfer log from the bot to
                                       * the recipient (plan line 264)         */

/** One signed USDT payout transaction of one swap, stored BEFORE it is
 *  broadcast (plan section 10 line 265: "the signed transaction (hash,
 *  nonce, raw bytes) written to the journal BEFORE broadcast"). UNIQUE on
 *  the hash and on (chain_id, nonce) in the database (Boltz
 *  PendingEthereumTransaction.ts:51-60). A swap has AT MOST ONE attempt: the
 *  plan builds no replacement of a stuck or failed payout (fee raising is
 *  DEFERRED, plan lines 270, 278). `gross` is the USDT the swap owes the
 *  user, `fee` the Ethereum fee deducted from it (givens item 34), `net` =
 *  gross - fee the amount the transfer carries. */
typedef struct {
    int64_t  swap_seq;
    int      n;                       /* 1 (assigned)                        */
    uint64_t chain_id;                /* 1 = Ethereum mainnet                */
    uint64_t nonce;
    uint8_t  hash[32];                /* keccak256(raw)                      */
    uint8_t  recipient[20];           /* the user's Ethereum address         */
    uint64_t gross, net, fee;         /* USDT raw                            */
    uint64_t gas_limit;
    uint64_t max_fee_per_gas;
    uint64_t max_priority_fee_per_gas;
    uint8_t *raw;                     /* heap; amm_eattempt_free             */
    size_t   raw_len;
    uint64_t last_submit_tip;         /* 0 = never submitted                 */
    char     state[12];               /* AMM_EA_*                            */
} amm_eattempt_t;

void amm_eattempt_free(amm_eattempt_t *a);

/** The swaps that owe a USDT payout, oldest first: a NODUS -> USDT swap in
 *  payout_pending (the payout) or a USDT -> NODUS swap in refund_pending (the
 *  refund); the other two combinations are NODUS payouts (the Nodus payer's,
 *  amm_journal_swap_head_payout). Up to `cap`; *n = count; more than `cap` is
 *  a fault (-1), never cut. */
int amm_journal_swap_list_usdt_owed(amm_journal_t *j, amm_swap_t *out, int cap,
                                    int *n);

/** The next free nonce of `chain_id` from the stored attempts: the highest
 *  stored nonce + 1. 0 found / 1 none stored (the caller's chain read is then
 *  the only floor) / -1. The caller (amm_eth_pay) takes
 *  max(this, the chain's pending count) under its one lock (plan line 265). */
int amm_journal_eth_next_nonce(amm_journal_t *j, uint64_t chain_id,
                               uint64_t *next);

/** Store a NEW signed attempt in ONE transaction (a->swap_seq, chain_id,
 *  nonce, hash, recipient, gross, net, fee, gas_limit, fees, raw filled by the
 *  caller; a->n and a->state assigned). Legal only when the swap owes a USDT
 *  payout (amm_journal_swap_list_usdt_owed's states), the recipient is the
 *  swap's own Ethereum address (destination of a payout, sender of a refund),
 *  `net` + `fee` == `gross` with net > 0 (givens item 52: nothing of zero is
 *  ever stored for broadcast), keccak256(raw) == hash, gas_limit > 0, every
 *  number within INT64_MAX, and the swap has no attempt yet. A duplicate hash or a duplicate
 *  (chain_id, nonce) is refused by the database's UNIQUE constraints.
 *  0 / AMM_J_ILLEGAL / AMM_J_RANGE / -1. */
int amm_journal_eth_attempt_sign(amm_journal_t *j, amm_eattempt_t *a);
/** The (only) attempt of a swap (raw heap; amm_eattempt_free). The stored
 *  bytes are checked against the stored hash on every read: a mismatch is a
 *  fault (-1). 0 / 1 none / -1. */
int amm_journal_eth_attempt_latest(amm_journal_t *j, int64_t swap_seq,
                                   amm_eattempt_t *out);
int amm_journal_eth_attempt_by_hash(amm_journal_t *j, const uint8_t hash[32],
                                    amm_eattempt_t *out);
/** Record a broadcast: state submitted, last_submit_tip = tip (from signed or
 *  submitted). 0 / AMM_J_ILLEGAL / -1. */
int amm_journal_eth_attempt_submitted(amm_journal_t *j, int64_t swap_seq,
                                      uint64_t tip);
/** confirmed | failed | orphaned | unknown, from signed or submitted. The swap's own
 *  state is NOT moved here (the caller does it in the same outer
 *  transaction, amm_journal_tx_begin). 0 / AMM_J_ILLEGAL / -1. */
int amm_journal_eth_attempt_finish(amm_journal_t *j, int64_t swap_seq,
                                   const char *state);
/** The USDT of the bot's own pending payouts: the sum of `net` over the
 *  attempts in signed or submitted (plan line 266: "subtracts the USDT of its
 *  own pending payouts from the journal rows"), checked addition. 0 / -1. */
int amm_journal_eth_pending_usdt(amm_journal_t *j, uint64_t *out);

/* ── the decision of a counted swap (revision 12) ─────────────────────── */

/** The decision of a counted swap, written in ONE transaction (plan section
 *  12; givens items 93-95): the caller computed everything first (the output
 *  from the depths of that moment, the payout's network fee, the minimum
 *  check, the signed payout) and hands the result here; either all of it is
 *  stored or none.
 *    refund = 0: the swap must be `counted`, the stored pool must equal
 *      `pool_before` byte for byte (the depths the output was computed from),
 *      then in this transaction: the pool becomes `pool_after`, out_amount /
 *      out_fee / out_paid are written, the swap moves to payout_pending and
 *      the signed payout (`nattempt` for a USDT -> NODUS swap, `eattempt` for
 *      a NODUS -> USDT swap; exactly one) is stored before anything is sent
 *      (plan section 17). A refused attempt (a duplicate nonce, another NODUS
 *      payout in flight) rolls everything back.
 *    refund = 1: the swap must be `counted`; it moves to refund_pending with
 *      `message`, the pool UNTOUCHED (pool arguments and attempts ignored).
 *  Anything refused writes nothing. @return 0 / AMM_J_ILLEGAL (state, pool or
 *  attempt refused) / AMM_J_RANGE / -1. */
typedef struct {
    int64_t seq;
    int refund;
    const char *message;               /* the refund's reason (may be NULL)    */
    uint64_t out_amount, out_fee, out_paid;
    const amm_pool_t *pool_before, *pool_after;
    amm_attempt_t *nattempt;           /* USDT -> NODUS payout                 */
    amm_eattempt_t *eattempt;          /* NODUS -> USDT payout                 */
} amm_decision_t;

int amm_journal_swap_decide(amm_journal_t *j, const amm_decision_t *d);

/** 1 = a NODUS payout attempt is signed or submitted (in flight), 0 = none.
 *  -1 fault. The decision of a USDT -> NODUS swap waits while one is (plan
 *  section 7 step 7: another NODUS payout still signed or submitted).
 *  amm_journal_swap_head_payout returns the swap with an open attempt first, so
 *  the payer settles it even when an older refund still has to be signed. */
int amm_journal_nodus_payout_owed(amm_journal_t *j);

/** The swaps that owe a USDT payout (as amm_journal_swap_list_usdt_owed), one
 *  page: seq > `after_seq`, oldest first, at most `cap` (>= 1). 0 / -1. */
int amm_journal_swap_page_usdt_owed(amm_journal_t *j, int64_t after_seq,
                                    amm_swap_t *out, int cap, int *n);

/* ── liquidity add (revision 12; plan sections 6.4.6, 14; givens items 25,
 *    35, 49, 91, 96) ─────────────────────────────────────────────────────── */

#define AMM_L_APPROVED   "approved"   /* the add question answered, nothing signed */
#define AMM_L_SIGNED     "signed"     /* both halves verified and accepted         */
#define AMM_L_COMMITTED  "committed"  /* both sides counted: units added            */
#define AMM_L_EXPIRED    "expired"    /* no side seen and both windows observed     */
#define AMM_L_REVERSED   "reversed"   /* a payment of a committed add was reversed  */

/** One liquidity add: the exact pair the bot answered at the add question
 *  (usdt_amount, nodus_amount at the pool's ratio), the two addresses and the
 *  NODUS transfer id once both signed halves arrived, and the two deposits as
 *  they are matched. Holds NO in-flight room (givens item 25: no 100 / 500
 *  limits on liquidity). */
typedef struct {
    int64_t  seq;
    uint32_t bot_req;                  /* the bot's 32-bit request number        */
    char     state[AMM_STATE_MAX];     /* AMM_L_*                                */
    uint64_t usdt_amount, nodus_amount;/* raw                                    */
    char     eth_addr[AMM_ADDR_ETH + 1];     /* "" until signed                  */
    char     nodus_addr[AMM_ADDR_NODUS + 1]; /* "" until signed                  */
    char     transfer_id[AMM_TID_MAX]; /* "nodus:<128 hex>", "" until signed     */
    uint64_t approved_at, expiry;      /* unix seconds                           */
    uint64_t eth_tip, nodus_tip;       /* the tips read at the question: a
                                        * deposit counts only in a block above  */
    char     eth_tx[AMM_TID_MAX];      /* "eth:<hash>" once the USDT deposit is
                                        * matched, else ""                       */
    uint32_t eth_log;
    uint64_t nodus_height;             /* block of the NODUS deposit, 0 = none   */
    int64_t  seen_seq;                 /* its place in the shared seen order, set
                                        * when both deposits are linked; 0 = not
                                        * yet (plan line 575)                    */
} amm_add_t;

/** Signed adds with both deposits linked, one page by seen_seq (> after, at most
 *  cap >= 1), the order in which they are committed together with the swaps'
 *  decisions. 0 / -1. */
int amm_journal_add_page_ready(amm_journal_t *j, int64_t after, amm_add_t *out, int cap,
                               int *n);

/** Input of the add question's approval (the pair is the engine's, computed at
 *  the pool's ratio). Refusals, in this order, writing nothing: liquidity
 *  paused (AMM_J_PAUSED), a swap in `unknown` (AMM_J_STOPPED), the number taken
 *  (AMM_J_NUMBER_TAKEN: redraw), NODUS side below `nodus_min`
 *  (AMM_J_BELOW_MIN, givens item 96). Else row `approved`. */
typedef struct {
    uint32_t bot_req;
    uint64_t usdt_amount, nodus_amount;
    uint64_t approved_at, expiry;
    uint64_t eth_tip, nodus_tip;       /* > 0 */
    uint64_t nodus_min;                /* liquidity_min_nodus */
    int      liquidity_paused_cfg;
    uint64_t open_max;                 /* quote_open_max: AMM_J_BUSY at it; 0 = no limit */
} amm_add_q_t;

/** The open unpaid questions (givens item 98): swaps in `approved` with no
 *  payment seen (seen_seq NULL, room 0 -- amm_journal_swap_seen sets both and
 *  moves the swap out of `approved` in the same transaction) plus liquidity
 *  adds in `approved`, or `signed` with no deposit matched (eth_tx empty,
 *  nodus_height 0). *n = the count. 0 / -1. */
int amm_journal_open_questions(amm_journal_t *j, int64_t *n);

/** Delete the unused expired questions, at most `cap` swap rows and `cap`
 *  liquidity adds per call, in ONE transaction: a swap in `expired` that never
 *  received a signed request or a payment (empty sender, incoming id and
 *  destination, no seen_seq, no room) and an add in `expired` that was never
 *  signed (no addresses, transfer id, deposit). The bot request number of each
 *  deleted row is first written to bot_req_used, so it is never given out again
 *  (the quote and add approvals refuse it: AMM_J_NUMBER_TAKEN). *swaps / *adds
 *  = the rows deleted (either may be NULL). 0 / -1. */
int amm_journal_purge_expired_questions(amm_journal_t *j, int cap, int *swaps,
                                        int *adds);

/** 0 = the bot request number was used by a question that has been deleted
 *  (kind 0: a price question, 1: a liquidity add question), 1 = not, -1. */
int amm_journal_bot_req_used(amm_journal_t *j, int kind, uint32_t req_no);

/** The add question's approval (input amm_add_q_t above). With `open_max` set,
 *  AMM_J_BUSY is refused before the number check (givens item 98). */
int amm_journal_add_approve(amm_journal_t *j, const amm_add_q_t *q, amm_add_t *out);

typedef struct {
    uint32_t bot_req;
    const char *eth_addr;              /* 40 lowercase hex                       */
    const char *nodus_addr;            /* 128 lowercase hex                      */
    uint64_t usdt_amount, nodus_amount;
    const char *transfer_id;           /* "nodus:<128 hex>"                      */
    uint8_t  eth_req_no[32], nodus_req_no[32];
} amm_add_accept_t;

/** The signed pair of an add (after amm_req_liquidity_add_verify): the add
 *  numbered `bot_req` must exist (AMM_J_NO_APPROVAL), be `approved` (else
 *  AMM_J_ILLEGAL: a number is accepted once) and the two amounts must equal
 *  the approved pair exactly (AMM_J_AMOUNT). Then the request number under BOTH
 *  addresses must be unused (AMM_J_REQ_REUSED), the NODUS transfer id must have
 *  no permanent marker (AMM_J_DUP_TRANSFER), and (plan 6.4.6) no open swap
 *  approval or other open add may carry the same Ethereum address and USDT
 *  amount (AMM_J_OPEN_DUP; `*open_req` = the request number of that open swap
 *  or add). Else addresses and transfer id are written, the state becomes
 *  `signed` and the markers are inserted under both addresses (swap_seq column
 *  = minus the add's seq), in ONE transaction. `out` and `open_req` may be
 *  NULL. */
int amm_journal_add_accept(amm_journal_t *j, const amm_add_accept_t *a,
                           amm_add_t *out, uint32_t *open_req);

int amm_journal_add_by_botreq(amm_journal_t *j, uint32_t bot_req, amm_add_t *out);
int amm_journal_add_by_seq(amm_journal_t *j, int64_t seq, amm_add_t *out);
/** Signed adds, one page (seq > after, at most cap >= 1). 0 / -1. */
int amm_journal_add_page(amm_journal_t *j, const char *state, int64_t after,
                         amm_add_t *out, int cap, int *n);
/** The signed add of (eth address, USDT amount) whose USDT deposit is not
 *  matched yet. 0 found / 1 none / -1. */
int amm_journal_add_find_eth(amm_journal_t *j, const char *eth_addr,
                             uint64_t usdt_amount, amm_add_t *out);
/** Link the USDT deposit record to the add (state signed, no deposit linked,
 *  the key has no permanent marker). 0 / AMM_J_ILLEGAL / AMM_J_DUP_TRANSFER. */
int amm_journal_add_link_eth(amm_journal_t *j, int64_t seq, const char *eth_key,
                             uint32_t log_index);
/** Link the NODUS deposit (block height) to the add. 0 / AMM_J_ILLEGAL. */
int amm_journal_add_link_nodus(amm_journal_t *j, int64_t seq, uint64_t height);
/** Commit the add (state signed, both deposits linked): ONE transaction
 *  computes the units from the stored pool of that moment (THORChain's formula,
 *  amm_units_for_add; an empty pool: the NODUS side, handler_add_liquidity.go:
 *  444-448), replaces the pool, adds the units to the position (eth address,
 *  nodus address), inserts the permanent markers of both deposits and moves the
 *  add to `committed`. `units_out` (may be NULL) = the units of this add. The
 *  caller has checked both waits (liquidity_wait_eth_blocks, _nodus_blocks).
 *  0 / AMM_J_ILLEGAL / AMM_J_DUP_TRANSFER / AMM_J_RANGE (the units cannot be
 *  computed) / -1. */
int amm_journal_add_commit(amm_journal_t *j, int64_t seq, evm_u256 *units_out);
/** The add moves to expired (no deposit linked, state approved or signed).
 *  0 / AMM_J_ILLEGAL / -1. */
int amm_journal_add_expire(amm_journal_t *j, int64_t seq);
/** The units of the position (eth address 40 hex, nodus address 128 hex);
 *  0 found / 1 none / -1. */
int amm_journal_position_get(amm_journal_t *j, const char *eth_addr,
                             const char *nodus_addr, evm_u256 *units);

/* ── liquidity withdraw (schema 8; plan sections 6.4.6, 14; givens items 24,
 *    25, 34, 52, 80, 90, 92, 96) ───────────────────────────────────────────
 *
 * A withdrawal is ACCEPTED when its signed request arrives (a row of
 * liq_withdraws: the two addresses, the basis points, the Ethereum tip read at
 * that moment, a place in the ONE seen sequence shared with the swaps and the
 * adds), and ACTED ON once the Ethereum tip is liquidity_wait_eth_blocks above
 * that tip (plan section 14: "The bot acts 300 Ethereum blocks after the
 * request is accepted"; PLAN READING of "after the request is accepted": no
 * Ethereum record exists for a withdrawal, so the tip stored at acceptance is
 * the reference point, as the add stores `eth_tip`). The shares are computed
 * when it acts, from the ledger of that moment (plan section 14).
 *
 * HOW A PAYOUT ENTERS THE QUEUES. When it acts, the withdrawal writes TWO rows
 * of `swaps` in state payout_pending, each with its signed first attempt
 * (write-ahead), so the existing payers, the NODUS owed queue (one live attempt,
 * reserved inputs, the cursor and its wrap, at most 8 steps a round), the paged
 * USDT owed list, the fee booking and amm_journal_owed_sum serve them with NO
 * change of their own:
 *   NODUS payout  dir = AMM_USDT_TO_NODUS, sender = the position's Ethereum
 *                 address, dest = its Nodus address (the payer pays `dest`);
 *   USDT payout   dir = AMM_NODUS_TO_USDT, sender = the Nodus address, dest =
 *                 the Ethereum address (the payer pays `dest`).
 * Such a row has no input side (amount 0), no minimum, no value and no room
 * (value_usdt 0, room 0: the limits of givens item 19 do not apply to
 * liquidity, item 25), no incoming id and no request number of the bot (it is
 * no question). Its output (out_amount = the share, out_fee, out_paid) is what
 * amm_journal_owed_sum counts, like any owed payout. Its id is fixed by the
 * withdrawal (16 x 'f' + 15 hex digits of the withdrawal's seq + the side), so a
 * restart cannot make a second one. */

#define AMM_W_ACCEPTED "accepted"  /* the request is accepted, not yet acted on   */
#define AMM_W_DONE     "done"      /* acted on: units and depths reduced, the
                                    * payouts written                              */
#define AMM_W_REFUSED  "refused"   /* refused whole when it acted: nothing changed
                                    * (the NODUS side is nothing after the Nodus
                                    * fee, plan section 14)                        */

typedef struct {
    int64_t  seq;
    char     state[AMM_STATE_MAX];
    char     eth_addr[AMM_ADDR_ETH + 1];
    char     nodus_addr[AMM_ADDR_NODUS + 1];
    uint32_t bp;                       /* 1..10000                                */
    uint8_t  req_no[32];               /* the signed request number               */
    uint64_t eth_tip;                  /* the Ethereum tip read at acceptance (>0) */
    int64_t  seen_seq;                 /* its place in the shared seen order       */
    int64_t  nodus_swap, usdt_swap;    /* the payout rows written when it acted
                                        * (0 = none)                               */
    evm_u256 units_claimed;            /* the units reduced (zero until done)      */
    uint64_t out_n, out_u;             /* the shares, before the network fees      */
    char     message[AMM_MSG_MAX];
} amm_wd_t;

typedef struct {
    const char *eth_addr;              /* 40 lowercase hex                         */
    const char *nodus_addr;            /* 128 lowercase hex: the signer            */
    uint32_t    bp;                    /* 1..10000                                 */
    uint8_t     req_no[32];            /* big-endian request number                */
    uint64_t    eth_tip;               /* > 0: the tip the caller READ             */
    int         liquidity_paused_cfg;  /* the settings flag                        */
} amm_wd_accept_t;

/** The accept transaction (plan 6.4.6, 6.4.7): refusals in this order, writing
 *  nothing -- liquidity paused (AMM_J_PAUSED), the request number already used
 *  under the signer's Nodus address (AMM_J_REQ_REUSED, the permanent marker of
 *  the other signed requests), the two addresses not a stored position with
 *  units (AMM_J_NO_POSITION), a field outside its format (AMM_J_RANGE) -- else
 *  the row `accepted`, the next seen_seq and the (Nodus address, request number)
 *  marker, in ONE transaction. `out` may be NULL. */
int amm_journal_withdraw_accept(amm_journal_t *j, const amm_wd_accept_t *a,
                                amm_wd_t *out);
/** 0 found / 1 none / -1. */
int amm_journal_withdraw_get(amm_journal_t *j, int64_t seq, amm_wd_t *out);
/** Accepted withdrawals whose acceptance tip is at most `max_eth_tip` (the
 *  Ethereum tip less the wait: the ones that are due), one page by seen_seq
 *  (> after, at most cap >= 1). The shared order is merged with the swaps' and
 *  the adds' by the engine. 0 / -1. */
int amm_journal_withdraw_page_due(amm_journal_t *j, uint64_t max_eth_tip, int64_t after,
                                  amm_wd_t *out, int cap, int *n);

/** What the engine hands over when a withdrawal acts (everything computed from
 *  the ledger of that moment; plan section 14, 12). `refuse` = 1: the whole
 *  withdrawal is refused (state `refused` with `message`), nothing else is read
 *  or written. Otherwise ONE transaction: the withdrawal must be `accepted`; the
 *  stored pool must equal `pool_before` and the position's units `units_before`
 *  byte for byte (the numbers were computed from them); `w` must be
 *  consistent (units_before - units_claimed = units_after); then the pool is
 *  reduced (amm_pool_apply_withdraw), the position set to `units_after`, the
 *  NODUS payout row and its signed attempt (`nattempt`) and the USDT payout row
 *  and its signed attempt (`eattempt`) are written (both: a side that comes out
 *  zero is the engine's to refuse, plan section 14), and the withdrawal is
 *  `done`. Anything refused writes nothing. @return 0 / AMM_J_ILLEGAL (state,
 *  pool, position or an attempt refused) / AMM_J_RANGE / -1. */
typedef struct {
    int64_t seq;
    int refuse;
    const char *message;               /* the refusal's reason (may be NULL)       */
    const amm_pool_t *pool_before;
    evm_u256 units_before;
    amm_withdraw_t w;
    uint64_t n_gross, n_fee, n_net;    /* NODUS: share, Nodus fee, amount carried  */
    uint64_t u_gross, u_fee, u_net;    /* USDT: share, Ethereum fee (the ceiling,
                                        * givens item 95), amount carried          */
    amm_attempt_t  *nattempt;
    amm_eattempt_t *eattempt;
} amm_wd_act_t;

int amm_journal_withdraw_act(amm_journal_t *j, const amm_wd_act_t *a);

#endif /* AMM_JOURNAL_H */
