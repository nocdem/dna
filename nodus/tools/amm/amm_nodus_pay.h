/**
 * @file amm_nodus_pay.h
 * @brief nodus-amm NODUS payout and refund: an ordinary native CORE SPEND
 *        from the bot's own coins to the user's own address, built and signed
 *        with the bot's key, stored before it is sent, resubmitted as the
 *        same bytes, replaced only after it expired, settled by scanning
 *        committed blocks for its intent id.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 11 payout paragraph (line 287: "ordinary CORE SPEND built and
 * signed by nodus_v2_spend_build ... states planned -> signed -> submitted ->
 * confirmed | expired | unknown, the same signed bytes resubmitted,
 * replacement only after expiry, settlement by scanning committed blocks for
 * the intent id"), line 288 (1..15 inputs per SPEND; coin joining DEFERRED),
 * line 289 (destination: the user's native 128-hex address, a normal native
 * transfer), section 17 (write-ahead rule, line 369: "every outgoing payment
 * ... is stored before it is sent; at restart, stored-but-unconfirmed
 * payments are looked up on chain by hash / intent id and never rebuilt"),
 * sections 7 step 7 and 8 step 7 (the Nodus fee is deducted from the output;
 * the minimum is compared AFTER it; zero is never broadcast), section 16
 * (payouts_paused: "nothing broadcast, all payouts stay queued"), givens
 * items 28, 39, 51, 52, 53.
 *
 * THE FAUCET'S PATTERN, CARRIED AS THE BOT'S OWN COPY (tools/faucet/
 * faucet_core.c do_plan_and_sign / do_settle, faucet_journal.h): whether the
 * bot shares code with the faucet is DEFERRED to the build package (plan line
 * 287) and is NOT decided here; the faucet is not edited. COIN JOINING IS
 * DEFERRED and is not built: the planner runs with its dust sweep and change
 * absorption OFF (no_dust_sweep = 1), so the inputs are exactly what the
 * payout needs; a payout that would need more than 15 inputs is refused
 * (AMM_NP_FUNDS, "the operator must consolidate", as the faucet).
 *
 * THE NODUS FEE IS DEDUCTED FROM THE AMOUNT (givens item 39; plan line 226):
 * the swap owes `gross`; the envelope's recipient output is net = gross - fee
 * and the bot's coins are debited net + fee == gross. The fee is the
 * planner's (units x gas price, never below the floor max(DNAC_MIN_FEE_RAW,
 * NODUS_W_BASE_TX_FEE)). The plan runs with a FIXED fee (the SDK's own
 * mechanism, nodus_v2_spend.c:915): a fee below what the shape needs is
 * refused with the needed fee, which is then the fee deducted from gross, so
 * a coin that exactly equals gross funds amount (gross - fee) + fee. The
 * minimum and zero are judged with the FINAL fee. The subtraction saturates
 * at zero and never wraps (givens item 52, plan section 5).
 *   net == 0 (fee at or above the amount): nothing is signed or broadcast
 *     (givens item 52), on the first attempt and on a replacement alike. A
 *     REFUND (a NODUS -> USDT swap in refund_pending) is moved to `held`
 *     (item 53 "held for manual handling"; PLAN READING of plan line 241,
 *     which applies the same hold to the NODUS side). A PAYOUT (a USDT ->
 *     NODUS swap in payout_pending) is moved to refund_pending (plan line
 *     226: zero or below the minimum -> refund; the journal edge exists only
 *     while no attempt of the swap is signed or submitted) and AMM_NP_ZERO is
 *     returned. The LEDGER is not touched here: reversing the pool update of
 *     the payout is the engine's duty, as is the USDT refund itself.
 *   net < the swap's signed minimum, for a payout: nothing is signed
 *     (givens item 51: the minimum is compared after the Nodus fee); the swap
 *     moves to refund_pending as above; AMM_NP_BELOW_MIN.
 *
 * ONE PAYOUT IN FLIGHT: the head swap (the oldest in payout_pending or
 * refund_pending, amm_journal_swap_head_payout) is driven, as the faucet's
 * head claim. Nothing else spends the bot's coins meanwhile, so no coin
 * reservation table exists. ENFORCED in the journal: amm_journal_attempt_sign
 * refuses an attempt while another swap's attempt is signed or submitted
 * (AMM_J_ILLEGAL, which amm_nodus_pay_sign reports as AMM_NP_ERR). The engine
 * contract: sign only the swap that amm_nodus_pay_step names with
 * AMM_NP_NEED_SIGN. READING of the plan, which says nothing of concurrent
 * payouts; a stuck head (funds short) holds the queue.
 *
 * WHERE THE AMOUNT COMES FROM: the swap row carries no output amount (the
 * engine computes it from the ledger when the payment counts). The engine
 * hands `gross` to amm_nodus_pay_sign once; every later attempt (a
 * replacement) reads it back from the stored attempt. How the engine keeps
 * `gross` between counting and signing across a restart is the engine
 * package's decision (reported).
 *
 * WRITE-AHEAD AND RESTART: amm_nodus_pay_sign stores the signed envelope
 * (amm_journal_attempt_sign, ONE journal transaction) and nothing is
 * submitted by it; amm_nodus_pay_step reads the STORED bytes from the journal
 * and submits those exact bytes, so a restart between store and broadcast
 * resends the same bytes and an envelope is never rebuilt while an attempt
 * is open. The node's answer to a submit moves no state; only a complete
 * block scan does.
 *
 * AN UNREADABLE ANSWER IS NEVER A ZERO (amm_node.h): a failed read leaves the
 * swap and the attempt as they are (AMM_NP_UNKNOWN); a committed block the
 * node does not hold makes the swap `unknown` (plan line 371, which stops new
 * approvals until the operator resolves it).
 *
 * DETERMINISM: scheduling reads no clock; the random bytes of the output
 * seeds come from the caller's `rand` (never a global RNG); the hedged
 * ML-DSA signature makes two builds of the same payout differ in bytes, which
 * is why the bytes are stored and never rebuilt.
 */
#ifndef AMM_NODUS_PAY_H
#define AMM_NODUS_PAY_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus_v2_spend.h"
#include "amm_journal.h"
#include "amm_node.h"

typedef struct amm_nodus_pay amm_nodus_pay_t;

typedef struct {
    const amm_node_t *node;            /* copied (the table, not ctx)        */
    amm_journal_t *journal;            /* not owned                          */
    const uint8_t *pk;                 /* the bot's ML-DSA-87 key: signer and
                                        * owner of every coin (2592 B)       */
    const uint8_t *sk;                 /* 4896 B                             */
    nodus_v2_rand_fn rand;             /* output seeds -- never a global RNG */
    void *rand_ctx;
    uint8_t chain_id[32];              /* the Nodus chain served             */
    uint64_t expiry_ahead;             /* envelope expiry = tip + this, in
                                        * 1..NODUS_CMT_APP_MAX_EXPIRY_AHEAD.
                                        * No amm_cfg key carries it yet: the
                                        * caller supplies it, no default     */
    uint64_t resubmit_blocks;          /* resubmit the SAME bytes every this
                                        * many blocks (>= 1; faucet: 3)      */
    uint32_t scan_blocks;              /* blocks scanned per step (>= 1;
                                        * faucet: 64)                        */
    int payouts_paused;                /* the setting (plan section 16):
                                        * nothing is signed or broadcast;
                                        * settlement scans continue          */
} amm_nodus_pay_cfg_t;

typedef enum {
    AMM_NP_OK          = 0,
    AMM_NP_UNKNOWN     = 1,  /* a read failed, is incomplete or does not
                              * report what is needed; nothing changed       */
    AMM_NP_FUNDS       = 2,  /* the bot's coins cannot cover the payout (or
                              * it would need more than 15 inputs, or the
                              * coin listing is incomplete); nothing signed  */
    AMM_NP_ZERO        = 3,  /* nothing is left after the Nodus fee; nothing
                              * signed or broadcast (a refund moved to held,
                              * a payout moved to refund_pending)            */
    AMM_NP_BELOW_MIN   = 4,  /* a payout's amount after the fee is below the
                              * swap's minimum; nothing signed; the swap
                              * moved to refund_pending                      */
    AMM_NP_UNSUPPORTED = 5,  /* the node's rule-set generation is not carried
                              * by this build (or its pins fail); nothing
                              * signed                                       */
    AMM_NP_PAUSED      = 6,  /* payouts_paused: nothing signed or broadcast  */
    AMM_NP_NEED_SIGN   = 7,  /* step: the head swap has no attempt yet: the
                              * engine calls amm_nodus_pay_sign with gross   */
    AMM_NP_ERR         = -1  /* a journal fault or a bad argument            */
} amm_np_rc_t;

/** Validate the configuration and build a payer. NULL on a bad config (a
 *  missing journal, key, rand or seam function, expiry_ahead outside
 *  1..NODUS_CMT_APP_MAX_EXPIRY_AHEAD, a zero bound). */
amm_nodus_pay_t *amm_nodus_pay_new(const amm_nodus_pay_cfg_t *cfg);
void amm_nodus_pay_free(amm_nodus_pay_t *p);

/** The bot's own Nodus address (128 lowercase hex, SHA3-512 of its key). */
const char *amm_nodus_pay_self(const amm_nodus_pay_t *p);

typedef enum {
    AMM_NP_PAY        = 0,   /* net > 0 and net >= minimum                   */
    AMM_NP_BELOW      = 1,   /* net > 0 but net < minimum                    */
    AMM_NP_NOTHING    = 2    /* net == 0 (fee >= gross)                      */
} amm_np_verdict_t;

/** PURE. net = gross - fee, saturating at zero (never wraps: givens item
 *  52); the verdict compares `minimum` with net AFTER the fee (givens item
 *  51; for a refund pass minimum 0). `net_out` may be NULL. */
amm_np_verdict_t amm_nodus_pay_judge(uint64_t gross, uint64_t fee,
                                     uint64_t minimum, uint64_t *net_out);

typedef struct {
    uint64_t gross;
    uint64_t fee;           /* the planner's fee for this payout             */
    uint64_t net;           /* gross - fee, saturating                       */
    int      n_in;          /* inputs the plan takes                         */
    uint64_t tip;           /* the committed tip the quote was made at       */
    char     msg[AMM_MSG_MAX];   /* why a refusal, "" otherwise              */
} amm_np_quote_t;

/** READ-ONLY planning: what a payout of `gross` would cost now and what the
 *  recipient would get. Nothing is signed or stored. The engine calls it to
 *  decide payout versus refund BEFORE the swap enters payout_pending (the
 *  minimum is compared after the fee, amm_nodus_pay_judge). The fee at the
 *  later signing is read again; a fee that rose in between is handled there
 *  (AMM_NP_BELOW_MIN / AMM_NP_ZERO: the payout moves to refund_pending). @return AMM_NP_OK (`q` filled) / AMM_NP_ZERO (`q->net` is 0) /
 *  AMM_NP_FUNDS / AMM_NP_UNKNOWN / AMM_NP_UNSUPPORTED / AMM_NP_ERR. */
int amm_nodus_pay_quote(amm_nodus_pay_t *p, uint64_t gross, uint64_t deadline_ms,
                        amm_np_quote_t *q);

typedef struct {
    int64_t swap_seq;
    int     worked;         /* 1 = a state moved or a submit was made        */
    int     signed_;        /* 1 = an envelope was stored                    */
    int     submitted;      /* 1 = a submit call was made                    */
    int     confirmed;      /* 1 = the swap moved to paid / refunded         */
    int     expired;        /* 1 = the attempt was found expired             */
    char    msg[AMM_MSG_MAX];
} amm_np_step_t;

/** Plan, build, sign and STORE the envelope for the swap `swap_seq` (in
 *  payout_pending: a USDT -> NODUS payout to its destination; in
 *  refund_pending: a NODUS -> USDT refund to its sender), owing `gross`.
 *  Refused (nothing signed) as described above. Nothing is submitted here.
 *  Legal only when the swap has no attempt (the first) -- a replacement is
 *  made by amm_nodus_pay_step after the attempt expired. `out` may be NULL.
 *  @return AMM_NP_OK (stored) / AMM_NP_ZERO / AMM_NP_BELOW_MIN / AMM_NP_FUNDS
 *  / AMM_NP_UNKNOWN / AMM_NP_UNSUPPORTED / AMM_NP_PAUSED / AMM_NP_ERR. */
int amm_nodus_pay_sign(amm_nodus_pay_t *p, int64_t swap_seq, uint64_t gross,
                       uint64_t deadline_ms, amm_np_step_t *out);

/** Drive the head payout ONE step: settle (scan committed blocks from the
 *  attempt's cursor up to min(tip, expiry) for its intent id; found ->
 *  confirmed and the swap paid / refunded in ONE transaction; a block the
 *  node does not hold -> the swap unknown), expire (tip past the expiry and
 *  every block up to it scanned -> expired), replace (an expired attempt ->
 *  a new one sharing at least one input with it; never while the attempt is
 *  open), submit (the stored bytes, when signed or `resubmit_blocks` after
 *  the last submit). @return AMM_NP_OK (`out->worked` says whether anything
 *  moved; nothing to do is OK with worked 0) / AMM_NP_NEED_SIGN / the
 *  refusals of amm_nodus_pay_sign for a replacement / AMM_NP_UNKNOWN / ERR. */
int amm_nodus_pay_step(amm_nodus_pay_t *p, uint64_t deadline_ms,
                       amm_np_step_t *out);

#endif /* AMM_NODUS_PAY_H */
