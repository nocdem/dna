/**
 * @file amm_engine.h
 * @brief nodus-amm engine: drives each swap through its states, over the
 *        modules already built (journal, ledger, both watchers, both payers),
 *        against stub or real chains.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 12)
 * sections 7, 8 (the flows), 12 (the decision), 13 (room from the seen
 * payment, the line, the window rule), 14 (liquidity add), 16 (pauses), 17
 * (restart recovery, a required fact that cannot be read leaves the swap in
 * its state); givens items 51, 52, 54, 57, 59, 66-68, 72, 79, 80, 82-97.
 *
 * THE FLOW (operator, givens items 68, 82-88, 93-95):
 *   1. amm_engine_quote   the site asks the bot for a price (unsigned:
 *      direction and amount). The bot answers with its INDICATIVE number (the
 *      output before the network fee, computed from the depths at that
 *      moment), an ESTIMATED network fee shown apart, a random 32-bit request
 *      number and the time the approval holds (approval_valid_seconds). The
 *      approval row is ONE journal transaction and HOLDS NO ROOM (givens item
 *      94: "Fiyat sormak hicbir sey tutmaz"). Refusals (amm_q_rc_t): paused,
 *      stopped, below swap_min_usdt, above swap_max_usdt, the swaps whose
 *      payment is SEEN leave no room ((sum of v over the swaps holding room) +
 *      v > the in-flight limit), nothing to give / pool unusable, the bot
 *      cannot pay the output (an estimate that counts only seen payments), a
 *      read that failed (unavailable). Item 57 needs the sender and so runs at
 *      step 2.
 *   2. amm_engine_accept_*  the paying extension sends the user's signed
 *      request (already verified by amm_req). The bot looks the request
 *      number up, finds the answer it gave under it and accepts only when
 *      direction and amount match (givens item 87); item 57; the permanent
 *      (sender, number) marker. The answer is a DELIVERY RESULT only. An
 *      approval is not accepted after its expiry (the bot's clock set the
 *      expiry).
 *   3. amm_engine_step    the worker.
 *
 * WHAT STEP DOES, IN ORDER (each part is idempotent, so a kill at any point
 * and a restart repeat it safely; every list it walks is read PAGE BY PAGE by
 * a stable key, so no number of rows can stop it):
 *   a. amm_eth_watch_step and amm_nodus_watch_step. The Nodus watcher records
 *      a matching NODUS payment as SEEN in the transaction that stores its row
 *      (amm_journal_swap_seen: the swap takes room or waits in line) and counts
 *      it when it holds room.
 *   b. the line for room: amm_journal_room_grant gives room to the earliest
 *      waiting payment first (strict, in seen order).
 *   c. Ethereum records (seen / deep, EVERY unconsumed record, paged): a record
 *      that matches the signed USDT -> NODUS approval of its sender and exact
 *      amount (a keyed lookup; amm_eth_watch_match: block above the tip read at
 *      the approval, block time within the validity) is recorded as SEEN in one
 *      transaction (room or the line), and counted when it is deep AND holds
 *      room; a deep record that matches no approval and no liquidity add is
 *      held (plan section 7 "Payment matching", givens items 32, 54). The
 *      validity is checked AGAIN when a linked payment becomes deep.
 *   d. waiting Nodus payments that hold room are counted.
 *   e. liquidity adds (plan section 14): see below.
 *   f. THE DECISION of every counted swap, in the seen order, ONE journal
 *      transaction each (plan section 12, givens items 93-95): the output from
 *      the depths of that moment, the payout's network fee (USDT: the ceiling
 *      of the transaction signed; NODUS: the planner's fee), the minimum check,
 *      the signed payout stored before anything is sent and the ledger update;
 *      or a refund with the ledger untouched (below the minimum, nothing after
 *      the fee, an empty side or the depth reached, a zero output, swaps
 *      paused). A swap whose decision cannot be completed (price, estimate,
 *      fee or balance unreadable, the bot key short, payouts paused, another
 *      NODUS payout in flight) writes nothing and stays counted with its room,
 *      to be decided at the depths of the round that completes it. Nothing is
 *      ever reversed.
 *   g. NODUS payouts through amm_nodus_pay: settlement and resubmission of the
 *      stored envelopes; the REFUND of a NODUS -> USDT swap is signed here (a
 *      refund that is zero after the Nodus fee is DROPPED: givens items 89,
 *      90). A signed or submitted attempt keeps priority; an expired payout
 *      whose replacement cannot be stored this round is deferred to the next
 *      round and the next owed swap is served (amm_nodus_pay.h, RESERVED
 *      COINS).
 *   h. USDT payouts through amm_eth_pay: settlement and broadcast of the stored
 *      transactions; a USDT refund is signed here (dropped when its Ethereum
 *      fee is not below it).
 *   i. the line for room again (a payout or a refund done released room).
 *   j. the Ethereum fee deducted from a paid USDT payout is booked to the
 *      Foundation AS USDT (givens items 80, 92; amm_journal_book_fee).
 *   k. release: an `approved` swap whose payment window is FULLY OBSERVED
 *      becomes expired (plan section 13 window rule: it holds no room, so this
 *      only decides when it stops matching payments).
 *
 * LIQUIDITY ADD (plan sections 6.4.6, 14; givens items 25, 35, 49, 91, 96):
 *   amm_engine_add_question  the site names ONE side's amount; the bot answers
 *      with the exact pair at the pool's ratio (an empty pool: the ratio of the
 *      settings pool_start_usdt : pool_start_nodus), where to pay each side,
 *      Valid Until and a random 32-bit request number; refused when the NODUS
 *      side is below liquidity_min_nodus. The row holds no room (no 100 / 500
 *      limits on liquidity).
 *   amm_engine_accept_add    the extension's signed pair (both halves verified
 *      by amm_req) with that request number.
 *   step e: the USDT deposit is matched at its Ethereum record (address, exact
 *      amount, block above the tip read at the question, time within the
 *      validity) and counted after liquidity_wait_eth_blocks (300); the NODUS
 *      deposit is matched by its transfer id in the Nodus history rows and
 *      counted after liquidity_wait_nodus_blocks (3); when both are counted the
 *      add commits in one transaction: units by THORChain's formula (an empty
 *      pool: units = the NODUS side), pool, position (address pair -> units).
 *      Withdraw is NOT built here.
 *
 * NOT BUILT HERE (reported): liquidity withdraw; the replacement of an expired
 * NODUS payout at another fee (givens item 97); fee raising of a stuck payout;
 * coin joining.
 */
#ifndef AMM_ENGINE_H
#define AMM_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "amm_cfg.h"
#include "amm_eth.h"
#include "amm_eth_pay.h"
#include "amm_eth_watch.h"
#include "amm_journal.h"
#include "amm_node.h"
#include "amm_nodus_pay.h"
#include "amm_nodus_watch.h"
#include "amm_req.h"

#define AMM_ENGINE_PAGE 256      /* rows per page of every list the engine walks */
#define AMM_ENGINE_PAGE_MAX 1024

typedef struct amm_engine amm_engine_t;

typedef struct {
    const amm_cfg_t *cfg;              /* copied                              */
    amm_journal_t *journal;            /* not owned                           */
    amm_eth_watch_t *eth_watch;        /* not owned                           */
    amm_eth_pay_t *eth_pay;            /* not owned                           */
    amm_nodus_watch_t *nodus_watch;    /* not owned                           */
    amm_nodus_pay_t *nodus_pay;        /* not owned                           */
    amm_node_t node;                   /* copied                              */
    const amm_eth_provider_t *providers; /* copied; every payout call set      */
    int n_providers;                   /* 1..AMM_ETH_MAX_PROVIDERS            */
    int quorum;                        /* 1..n_providers                      */
    amm_eth_price_t price;             /* copied; fee_usdt required           */
    /** Wall-clock unix seconds: it only sets an approval's time and expiry
     *  and refuses a request that arrives after it (plan section 13: block
     *  times, never this clock, decide what a payment counts for and when
     *  an unpaid approval is marked expired). */
    uint64_t (*now_unix)(void *ctx);
    void *now_ctx;
    /** A random 32-bit number for the request number (never from a global
     *  RNG in the engine). 0 = ok, -1 = failed. */
    int (*rand_fn)(void *ctx, uint8_t *buf, size_t len);
    void *rand_ctx;
    /** Rows per page of every list the step walks: 0 = AMM_ENGINE_PAGE;
     *  1..AMM_ENGINE_PAGE_MAX. A test sets a small value to prove that more
     *  rows than one page do not stop the step. */
    int page;
    /** A MONOTONIC clock in milliseconds, used only by the price and liquidity
     *  questions to reuse their provider and balance reads for
     *  `quote_read_fresh_ms` (givens item 98: the reads of a question are
     *  shared, never the decision's or a payout's). NULL = CLOCK_MONOTONIC.
     *  A test sets its own to move time. */
    uint64_t (*mono_ms)(void *ctx);
    void *mono_ctx;
} amm_engine_cfg_t;

/** NULL on a bad configuration (a missing module or function, a quorum out of
 *  range, a missing payout call in a provider, a page above the maximum). */
amm_engine_t *amm_engine_new(const amm_engine_cfg_t *cfg);
void amm_engine_free(amm_engine_t *e);

/* ── 1. the price question ───────────────────────────────────────────── */

typedef enum {
    AMM_Q_OK          = 0,
    AMM_Q_PAUSED      = 1,   /* swaps paused (setting or a reversal)           */
    AMM_Q_STOPPED     = 2,   /* a swap is in `unknown`: new approvals stop      */
    AMM_Q_BELOW_MIN   = 3,   /* USDT side below swap_min_usdt (givens item 89)  */
    AMM_Q_ABOVE_MAX   = 4,   /* USDT side above swap_max_usdt                   */
    AMM_Q_INFLIGHT    = 5,   /* the seen payments leave no room for it          */
    AMM_Q_NO_LIQUIDITY = 6,  /* the pool gives nothing for that amount          */
    AMM_Q_CANNOT_PAY  = 7,   /* the payout is larger than the bot's key holds   */
    AMM_Q_UNAVAILABLE = 8,   /* a read failed or no pool: never an approval     */
    AMM_Q_BAD         = 9,   /* direction or amount not valid                   */
    AMM_Q_BUSY        = 10,  /* the open unpaid questions are at quote_open_max
                              * (givens item 98); no read was made, nothing
                              * written                                         */
    AMM_Q_ERR         = -1   /* a journal fault                                 */
} amm_q_rc_t;

typedef struct {
    amm_dir_t dir;
    uint64_t  amount;          /* input side, raw                              */
    uint64_t  number;          /* the bot's INDICATIVE number: the output before
                                * the network fee (NODUS raw for USDT -> NODUS,
                                * USDT raw for NODUS -> USDT), computed again
                                * when the payment counts (givens item 93)     */
    uint64_t  est_fee;         /* the estimated network fee in the same unit as
                                * `number` (shown apart; the fee deducted is the
                                * one of the payout signed in the decision)    */
    uint32_t  request_number;  /* random 32 bits; the swap id                  */
    uint64_t  valid_until;     /* unix seconds                                 */
    char      pay_to[AMM_ADDR_NODUS + 3];  /* "0x" + 40 hex or 128 hex         */
} amm_quote_answer_t;

int amm_engine_quote(amm_engine_t *e, amm_dir_t dir, uint64_t amount,
                     uint64_t deadline_ms, amm_quote_answer_t *out);

/* ── 2. the signed request ───────────────────────────────────────────── */

typedef enum {
    AMM_ACC_RECEIVED  = 0,   /* delivered: the bot has the request           */
    AMM_ACC_NO_NUMBER = 1,   /* no approval carries that request number      */
    AMM_ACC_AMOUNT    = 2,   /* direction or amount differs from the answer
                              * the bot gave (givens item 87)                */
    AMM_ACC_REUSED    = 3,   /* the signer already used that number          */
    AMM_ACC_OPEN      = 4,   /* item 57: a second open approval with the
                              * same sender and amount; `swap_out->req_no_bot`
                              * = the open one's request number              */
    AMM_ACC_USED      = 5,   /* the number was already accepted              */
    AMM_ACC_EXPIRED   = 6,   /* the approval is past its expiry              */
    AMM_ACC_DUP_TRANSFER = 7,/* the NODUS transfer id is already used        */
    AMM_ACC_ERR       = -1
} amm_acc_rc_t;

/** The verified signed requests of amm_req (the signature, the chain id, the
 *  address and the per-sender reuse refusal are amm_req's). `swap_out` may be
 *  NULL; it is filled for AMM_ACC_RECEIVED and AMM_ACC_OPEN. */
int amm_engine_accept_usdt(amm_engine_t *e, const amm_req_usdt_t *r,
                           amm_swap_t *swap_out);
int amm_engine_accept_nodus(amm_engine_t *e, const amm_req_nodus_to_usdt_t *r,
                            amm_swap_t *swap_out);

/* ── 2b. the liquidity add ───────────────────────────────────────────── */

typedef enum { AMM_SIDE_USDT = 0, AMM_SIDE_NODUS = 1 } amm_side_t;

typedef enum {
    AMM_AQ_OK         = 0,
    AMM_AQ_PAUSED     = 1,   /* liquidity_paused                                */
    AMM_AQ_STOPPED    = 2,   /* a swap is in `unknown`                          */
    AMM_AQ_BELOW_MIN  = 3,   /* the NODUS side is below liquidity_min_nodus     */
    AMM_AQ_BAD        = 4,   /* side or amount not valid, or a side of the pair
                              * comes out zero or above 64 bits                 */
    AMM_AQ_UNAVAILABLE = 5,  /* a read failed                                   */
    AMM_AQ_BUSY       = 6,   /* the open unpaid questions are at quote_open_max
                              * (givens item 98); no read was made, nothing
                              * written                                         */
    AMM_AQ_ERR        = -1
} amm_aq_rc_t;

typedef struct {
    uint64_t usdt_amount;      /* the exact pair, raw                           */
    uint64_t nodus_amount;
    uint32_t request_number;   /* random 32 bits                                */
    uint64_t valid_until;      /* unix seconds                                  */
    char     pay_eth[43];      /* "0x" + 40 hex: where the USDT goes            */
    char     pay_nodus[AMM_ADDR_NODUS + 1]; /* where the NODUS goes             */
} amm_add_answer_t;

/** The add question (unsigned): the amount of ONE side; the other is the
 *  amount x the other side's depth / the named side's depth, truncated (PLAN
 *  PROPOSAL 6.4.6), at the pool's ratio, or at the settings' start ratio when
 *  the pool is empty (plan section 14). */
int amm_engine_add_question(amm_engine_t *e, amm_side_t side, uint64_t amount,
                            uint64_t deadline_ms, amm_add_answer_t *out);

/** The signed pair of an add (both halves verified and agreeing: amm_req).
 *  `open_req` (may be NULL) = the open swap's or add's request number for
 *  AMM_ACC_OPEN. */
int amm_engine_accept_add(amm_engine_t *e, const amm_req_liq_add_t *r,
                          uint32_t *open_req);

/* ── 3. the worker ───────────────────────────────────────────────────── */

typedef struct {
    int eth_rc, nodus_rc;      /* the watchers' return codes                    */
    int matched;               /* approvals that took an Ethereum payment (seen) */
    int counted;               /* swaps moved to counted by this step           */
    int waiting;               /* payments seen that wait in line for room      */
    int room_granted;          /* waiting payments that took room               */
    int decided;               /* counted swaps decided to a payout             */
    int to_refund;             /* counted swaps decided to a refund             */
    int undecided;             /* counted swaps whose decision cannot be completed */
    int dropped;               /* refunds dropped                               */
    int held_records;          /* Ethereum records held                         */
    int fees_booked;
    int expired;
    int adds_linked;           /* add deposits matched                          */
    int adds_committed;
    int adds_expired;
    int questions_deleted;     /* unused expired price and add questions deleted (givens item 98) */
    int rows_examined;         /* open approved swaps examined by this round's release walk (bounded by round_rows_max) */
    int adds_examined;         /* liquidity add rows examined by this round's three add walks (each bounded by round_rows_max) */
} amm_engine_step_t;

/** One worker round (see the list above). @return 0 / -1 (a journal fault;
 *  a failed chain read is not a fault). `out` may be NULL. */
int amm_engine_step(amm_engine_t *e, uint64_t deadline_ms, amm_engine_step_t *out);

/* ── status ──────────────────────────────────────────────────────────── */

typedef struct {
    int        have_pool;
    amm_pool_t pool;
    int        swaps_paused, liquidity_paused, payouts_paused;
    int        stopped;               /* a swap in unknown                      */
    uint64_t   inflight_usdt;         /* sum of v over the swaps holding room   */
    uint64_t   room_usdt;             /* inflight_max - inflight (0 when full)  */
} amm_engine_status_t;

int amm_engine_status(amm_engine_t *e, amm_engine_status_t *out);

#endif /* AMM_ENGINE_H */
