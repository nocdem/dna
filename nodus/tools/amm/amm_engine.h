/**
 * @file amm_engine.h
 * @brief nodus-amm engine: drives each swap through its states, over the
 *        modules already built (journal, ledger, both watchers, both payers),
 *        against stub or real chains.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 10)
 * sections 7, 8 (the flows with the operator corrections of 2026-11-10), 12
 * (ledger and pricing), 13 (in-flight room, window rule, expiry), 16
 * (pauses), 17 (restart recovery, a required fact that cannot be read leaves
 * the swap in its state); givens items 51, 52, 54, 57, 59, 66-68, 72, 79, 80,
 * 82-90.
 *
 * THE FLOW (operator, givens items 68, 82-88):
 *   1. amm_engine_quote   the site asks the bot for a price (unsigned:
 *      direction and amount). The bot answers with its number (the output
 *      BEFORE the network fee), an ESTIMATED network fee shown apart, a
 *      random 32-bit request number and the time the approval holds
 *      (approval_valid_seconds). The approval row, its in-flight room and the
 *      number are ONE journal transaction. Refusals (amm_q_rc_t): paused,
 *      stopped, below swap_min_usdt, above swap_max_usdt, in-flight total,
 *      nothing to give / pool unusable, the bot cannot pay the output, a read
 *      that failed (unavailable). Item 57 (a second open approval of the
 *      same sender and amount) needs the sender and so runs at step 2.
 *   2. amm_engine_accept_*  the paying extension sends the user's signed
 *      request (already verified by amm_req). The bot looks the request
 *      number up, finds the answer it gave under it and accepts only when
 *      direction and amount match (givens item 87); item 57; the permanent
 *      (sender, number) marker. The answer is a DELIVERY RESULT only
 *      (received / a refusal reason): there is no acceptance step and no
 *      second approval (givens items 83, 84, 88). An approval is not
 *      accepted after its expiry (the bot's clock set the expiry).
 *   3. amm_engine_step    the worker: the watchers, then matching of the
 *      payments to the signed approvals, counting, the ledger update (the
 *      approval's number, NOT recomputed: givens items 66, 68, plan section
 *      12), the payouts through the payers (the REAL network fee is deducted
 *      at payout and the minimum compared AFTER it: givens items 51, 82),
 *      refunds, drops, the network-fee booking, release of room, restart
 *      recovery. Every state change is a journal transaction; a failed read
 *      leaves the swap in its state.
 *
 * WHAT STEP DOES, IN ORDER (each part is idempotent, so a kill at any point
 * and a restart repeat it safely):
 *   a. amm_eth_watch_step and amm_nodus_watch_step (the Nodus watcher also
 *      moves a matching NODUS payment to counted, amm_nodus_watch.h).
 *   b. Ethereum records (seen / deep, EVERY unconsumed record: no block
 *      window, so a payment stored before a long downtime is still read; a
 *      record whose swap is counted or later is consumed): a record
 *      that matches a signed USDT -> NODUS approval (sender, exact amount,
 *      block above the tip read at approval, block time within the validity:
 *      amm_eth_watch_match) moves the approval to paid_waiting_depth and,
 *      when the record is deep, to counted; a deep record that matches no
 *      approval is held (plan section 7 "Payment matching", givens items 32,
 *      54). The validity is checked AGAIN when a linked payment becomes deep:
 *      a payment a reorganisation moved outside the approval's validity
 *      matches no approval (the swap is approved again, the record held).
 *   c. counted swaps: during swaps_paused (setting or reversal) a refund
 *      (plan section 16); else the ledger update of the approval's number and
 *      payout_pending in ONE transaction; when the number cannot be applied
 *      (the output depth fell below it, plan section 12 "DEFERRED") the
 *      payment is REFUNDED (the engine's reading, reported).
 *   d. NODUS payouts (a USDT -> NODUS payout, a NODUS -> USDT refund) through
 *      amm_nodus_pay: judged BEFORE signing from amm_nodus_pay_quote: a refund
 *      that is zero after the Nodus fee is DROPPED (givens items 89, 90); a
 *      payout below the minimum or zero becomes a refund.
 *   e. USDT payouts (a NODUS -> USDT payout, a USDT refund) through
 *      amm_eth_pay: a USDT refund whose estimated Ethereum fee is not below
 *      its amount is DROPPED (items 89, 90); the payer itself drops one whose
 *      real fee turns out to be at or above it.
 *   f. a refund_pending swap whose ledger update is still in the reserves
 *      (payout became refund before anything was signed) gets it reversed
 *      (amm_journal_ledger_reverse).
 *   g. the Ethereum fee deducted from a paid USDT payout is booked to the
 *      Foundation AS USDT (givens items 80, 92; amm_journal_book_fee): the
 *      pool's USDT depth fell by the full gross payout at the ledger update,
 *      the NODUS depth is untouched. The paid rows are read in pages.
 *   h. release: an `approved` swap whose payment window is FULLY OBSERVED
 *      (amm_eth_watch_window_observed / _unsigned,
 *      amm_nodus_watch_window_observed) becomes expired, by the same window
 *      rule for a signed and an unsigned approval of its direction (plan
 *      section 13: the bot's clock passing the expiry does not release room).
 *
 * NOT BUILT HERE (reported): liquidity add / withdraw (the journal holds no
 * position and the payers are keyed by swap rows); the Foundation's start
 * pool (plan section 14 names no seed rule); fee raising of a stuck payout;
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
     *  room is released). */
    uint64_t (*now_unix)(void *ctx);
    void *now_ctx;
    /** A random 32-bit number for the request number (never from a global
     *  RNG in the engine). 0 = ok, -1 = failed. */
    int (*rand_fn)(void *ctx, uint8_t *buf, size_t len);
    void *rand_ctx;
} amm_engine_cfg_t;

/** NULL on a bad configuration (a missing module or function, a quorum out of
 *  range, a missing payout call in a provider). */
amm_engine_t *amm_engine_new(const amm_engine_cfg_t *cfg);
void amm_engine_free(amm_engine_t *e);

/* ── 1. the price question ───────────────────────────────────────────── */

typedef enum {
    AMM_Q_OK          = 0,
    AMM_Q_PAUSED      = 1,   /* swaps paused (setting or a reversal)           */
    AMM_Q_STOPPED     = 2,   /* a swap is in `unknown`: new approvals stop      */
    AMM_Q_BELOW_MIN   = 3,   /* USDT side below swap_min_usdt (givens item 89)  */
    AMM_Q_ABOVE_MAX   = 4,   /* USDT side above swap_max_usdt                   */
    AMM_Q_INFLIGHT    = 5,   /* the in-flight total would pass its limit        */
    AMM_Q_NO_LIQUIDITY = 6,  /* the pool gives nothing for that amount          */
    AMM_Q_CANNOT_PAY  = 7,   /* the payout is larger than the bot's key holds   */
    AMM_Q_UNAVAILABLE = 8,   /* a read failed or no pool: never an approval     */
    AMM_Q_BAD         = 9,   /* direction or amount not valid                   */
    AMM_Q_ERR         = -1   /* a journal fault                                 */
} amm_q_rc_t;

typedef struct {
    amm_dir_t dir;
    uint64_t  amount;          /* input side, raw                              */
    uint64_t  number;          /* the bot's number: the output before the
                                * network fee (NODUS raw for USDT -> NODUS,
                                * USDT raw for NODUS -> USDT)                  */
    uint64_t  est_fee;         /* the estimated network fee in the same unit as
                                * `number` (shown apart, never charged: the
                                * real fee is deducted at payout)              */
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
                              * same sender and amount; `swap_out` = the
                              * open one                                     */
    AMM_ACC_USED      = 5,   /* the number was already accepted              */
    AMM_ACC_EXPIRED   = 6,   /* the approval is past its expiry              */
    AMM_ACC_ERR       = -1
} amm_acc_rc_t;

/** The verified signed requests of amm_req (the signature, the chain id, the
 *  address and the per-sender reuse refusal are amm_req's). `swap_out` may be
 *  NULL; it is filled for AMM_ACC_RECEIVED and AMM_ACC_OPEN. */
int amm_engine_accept_usdt(amm_engine_t *e, const amm_req_usdt_t *r,
                           amm_swap_t *swap_out);
int amm_engine_accept_nodus(amm_engine_t *e, const amm_req_nodus_to_usdt_t *r,
                            amm_swap_t *swap_out);

/* ── 3. the worker ───────────────────────────────────────────────────── */

typedef struct {
    int eth_rc, nodus_rc;      /* the watchers' return codes                    */
    int matched;               /* approvals that took an Ethereum payment       */
    int counted;               /* swaps moved to counted by this step           */
    int to_payout, to_refund;  /* counted swaps moved on                        */
    int dropped;               /* refunds dropped                               */
    int held_records;          /* Ethereum records held                         */
    int reversed_ledger;       /* ledger updates reversed                       */
    int fees_booked;
    int expired;
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
    uint64_t   inflight_usdt;         /* sum of v over the in-flight swaps      */
    uint64_t   room_usdt;             /* inflight_max - inflight (0 when full)  */
} amm_engine_status_t;

int amm_engine_status(amm_engine_t *e, amm_engine_status_t *out);

#endif /* AMM_ENGINE_H */
