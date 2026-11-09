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
 *   payout_pending -> refund_pending     7 step 7 / 8 step 7 (plan line 226:
 *                                        zero or below the minimum after the
 *                                        Nodus fee -> refund); ONLY while no
 *                                        attempt of the swap is signed or
 *                                        submitted (the ledger reversal is
 *                                        the caller's, via `pool`)
 *   refund_pending -> refunded           13
 *   refund_pending -> held               items 52/53 (fee >= amount)
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
 * IN-FLIGHT STATES (the sum of value_usdt, plan section 13): approved,
 * paid_waiting_depth, counted, payout_pending, refund_pending (13 lists the
 * first four at line 311 and releases at "payout done; refund done", so a
 * refund still pending holds its room: INFERENCE). `held` holds its room
 * only when the setting `held_keeps_room` is 1: the plan DEFERS the question
 * (plan lines 312, 407), so the journal takes the value as a parameter and
 * decides nothing. unknown and reversed do not hold room.
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

/** Move a swap to `to` (legal table above; `approved` as target and
 *  `reversed` are refused here). `incoming_id` (NULL = keep) is stored: it is
 *  required for paid_waiting_depth; for `counted` the swap must carry one and
 *  its PERMANENT marker is inserted in this same transaction -- an existing
 *  marker returns AMM_J_DUP_TRANSFER and nothing changes (plan section 17,
 *  givens item 59). ONE INCOMING TRANSFER, ONE SWAP (orchestrator's review
 *  finding on package 1; plan section 8 "a second approval naming the same
 *  transfer is never paid"): a move to paid_waiting_depth is refused with
 *  AMM_J_DUP_TRANSFER, nothing changed, when ANOTHER swap already carrying the
 *  same incoming id is in a state that has taken the payment -- every state
 *  except `approved` (a request may name a transfer before any payment exists,
 *  so approved swaps naming one id do not block each other; READING of "live")
 *  and `expired` (it never took a payment). That carrier check runs on EVERY
 *  transition that names an id, and an id once set is never changed: naming
 *  another id on a swap that already carries one is AMM_J_ILLEGAL (the same id
 *  again is accepted). payout_pending -> refund_pending is refused
 *  (AMM_J_ILLEGAL) while an attempt of the swap is signed or submitted.
 *  `pool` (NULL = none) replaces the ledger reserves in the same
 *  transaction. `message` (NULL = keep) is
 *  stored. 0 / AMM_J_ILLEGAL / AMM_J_DUP_TRANSFER / -1. */
int amm_journal_swap_transition(amm_journal_t *j, int64_t seq, const char *to,
                                const char *incoming_id,
                                const amm_pool_t *pool, const char *message);

/** The in-flight sum of value_usdt over the in-flight states (see above),
 *  computed from the rows with checked addition. 0 / -1 (an overflow of the
 *  sum is a fault). `held_keeps_room` = 1 adds the swaps in state held. */
int amm_journal_inflight_sum(amm_journal_t *j, int held_keeps_room,
                             uint64_t *out);
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

#endif /* AMM_JOURNAL_H */
