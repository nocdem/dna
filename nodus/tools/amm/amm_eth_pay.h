/**
 * @file amm_eth_pay.h
 * @brief nodus-amm USDT payout and refund on Ethereum: an EIP-1559
 *        transaction calling USDT `transfer(user, amount)` from the bot's own
 *        key, signed, STORED before it is broadcast, broadcast, settled by its
 *        receipt. The payer's chain-id, balance, estimate and receipt groups
 *        ask every usable provider at once (amm_eth_fanout.h, one thread per
 *        provider) and examine the answers after all have returned, in
 *        provider index order; the quorum rules are unchanged.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 10 (lines 263-272), section 17 (write-ahead rule, line 369: "every
 * outgoing payment ... is stored before it is sent; at restart,
 * stored-but-unconfirmed payments are looked up on chain by hash ... and never
 * rebuilt"; line 371: a payout whose result cannot be established becomes
 * `unknown`), sections 7 step 7 and 8 step 7 (the Ethereum fee is deducted in
 * USDT; the minimum is compared AFTER it; zero is never broadcast), section 16
 * (payouts_paused), section 9 (providers and quorum), givens items 17, 34, 50,
 * 52, 53, 58.
 *
 * WHAT A PAYOUT IS. The USDT payouts are: the payout of a NODUS -> USDT swap
 * (state payout_pending, to its Ethereum destination) and the refund of a
 * USDT -> NODUS swap (state refund_pending, to its Ethereum sender)
 * (amm_journal_swap_list_usdt_owed). The USDT side of a liquidity withdrawal is
 * ALSO one of these: when the withdrawal acts, the engine stores a row of
 * `swaps` (dir NODUS -> USDT, payout_pending, `dest` = the position's Ethereum
 * address) with its first transaction in the same journal transaction
 * (amm_journal_withdraw_act; amm_journal.h: HOW A PAYOUT ENTERS THE QUEUES), so
 * this module pays, settles and books its fee like any NODUS -> USDT payout. The
 * engine computes the output of a swap from the ledger when its payment counts
 * and stores it in the decision; this module hands nothing but `gross` to
 * amm_eth_pay_sign, for a refund only, exactly as amm_nodus_pay does.
 *
 * THE FEE (plan line 271, givens items 34, 50). The user pays the Ethereum
 * gas: fee = the USDT the price seam (amm_eth.h amm_eth_price_t) quotes for
 * the gas limit and max fee per gas the transaction will carry; net = gross -
 * fee with the SATURATING subtraction of amm_ledger (amm_payout_after_fee:
 * plan section 5, givens item 52). Nothing about the price source, format or
 * conversion is decided here (DEFERRED, plan section 10): an unreadable price
 * is AMM_ETH_ERR from the seam and nothing is signed (never zero).
 *   net == 0 (fee at or above the amount): nothing is signed or broadcast
 *     (givens item 52). The payer only RETURNS AMM_EP_ZERO, for a payout
 *     (amm_eth_pay_prepare), a refund (amm_eth_pay_sign) and a re-send after a
 *     failed attempt (amm_eth_pay_resend): since revision 12 (plan section 12)
 *     the engine decides a swap once, in one journal transaction, and turns a
 *     payout into a refund there; this module never moves a swap and touches
 *     no ledger. What happens to the USDT of a refund or re-send that cannot
 *     cover its fee (it goes to the pool and the swap is `dropped`, givens
 *     items 113 "3 a", 114 "4 a", evm-fee plan 6.10) is the engine's journal
 *     write (amm_journal_usdt_to_pool).
 *   net < the swap's signed minimum, for a payout: nothing is signed (the
 *     minimum is compared after the fee, plan line 241); AMM_EP_BELOW_MIN is
 *     returned by amm_eth_pay_prepare, the engine refunds.
 *
 * GAS AND NET ARE INTERDEPENDENT: eth_estimateGas needs the call data, the
 * call data carries net, net depends on the gas. The payer iterates (READING;
 * the plan says only "gas estimated first", line 267): estimate with the
 * amount a, fee from the estimate, net = gross - fee; the estimate is final
 * when net == a (the transaction carries exactly the call data that was
 * estimated), else a = net and again, at most AMM_EP_ITER_MAX rounds; no
 * fixed point is AMM_EP_UNKNOWN (unsent, retried). Any estimate failure
 * (execution reverted: USDT paused, a blacklisted sender, a short balance;
 * or no answer) leaves the payout UNSENT and retried, never lost (plan line
 * 267; THORChain ethereum.go:989-997).
 *
 * FEES OF THE TRANSACTION (evm-fee plan docs/plans/approved/2026-11-13-evm-fee.md
 * section 2, rule F1). The transaction is type 2 and its fields are
 *   max priority fee per gas = eth_maxPriorityFeePerGas
 *   max fee per gas          = 2 x baseFeePerGas(latest block) + that tip
 * with both reads the Q-th largest answer of the usable providers (the
 * `base_fee` seam call reads the latest block's baseFeePerGas); the references
 * behind the rule are listed in the plan, section 2.2. The cap keeps the
 * transaction valid while the base fee rises by at most one eighth per block,
 * and the tip is what block builders are paid. The formula is ONE pure function
 * (amm_eth_pay_max_fee) called by every planning path. A quote that cannot be
 * read is AMM_EP_UNKNOWN. GAS LIMIT: Boltz raises the estimated limit by 25%,
 * rounded up, (gasLimit * 125 + 99) / 100 (EthereumUtils.ts:83-85
 * bumpGasLimit); the payer ports it: every estimate is bumped, and the bumped
 * limit is what the price seam is quoted and what is signed. The fee DEDUCTED
 * from the user is the ceiling: gas limit x max fee per gas converted into USDT
 * (givens item 95).
 * A payout whose max fee per gas the base fee has passed is REPLACED with the
 * same nonce (section REPLACEMENT below).
 *
 * READS (plan section 10 names no quorum for the payer; givens item 17 "Ethereum
 * read through ready-made RPC providers, more than one checked" and the
 * watcher's section 9 rule are the reading): every provider is used only when
 * it reports the configured chain id (eth_chain_id); every read that decides a money state needs Q usable
 * answers (Q = the quorum setting, givens item 58):
 *   tip, transaction counts   the Q-th largest answer (at least Q providers
 *                             report that value or more)
 *   gas estimate, base fee    the Q-th largest answer (with Q >= 2 one provider
 *                             can move the value only within the other
 *                             providers' answers; with Q = 1 it sets it alone)
 *   balances                  the SMALLEST answer (a balance is never taken
 *                             higher than what a provider says)
 *   receipt                   at least Q providers return the IDENTICAL
 *                             receipt (status, block number, block hash), or
 *                             at least Q say "no receipt"; anything else is
 *                             unknown
 * The broadcast goes to EVERY usable provider.
 *
 * NONCE (plan line 265, Boltz SequentialSigner.ts:95-136): allocated under
 * ONE lock (the payer's mutex, held from the nonce read to the journal
 * write): nonce = max(Q-th largest eth_getTransactionCount `pending`, the
 * journal's highest stored nonce + 1). The signed transaction (hash, nonce,
 * raw bytes) is written to the journal BEFORE it is broadcast; the journal is
 * UNIQUE on the hash and on (chain, nonce) (amm_journal.h); the next nonce
 * sees the stored row.
 *
 * BALANCE CHECK (plan line 266; evm-fee plan 6.13): the USDT `balanceOf` of the
 * bot's key minus the USDT of the bot's own pending payouts must cover `net`,
 * and the ether (eth_getBalance) minus the ether of the bot's own pending
 * payouts must cover gas limit x max fee per gas (the most the transaction can
 * pay). A pending payout counts ONCE per nonce, at the largest of its attempts
 * in signed, submitted or replaced (amm_journal_eth_pending); a payout decided
 * earlier in the same round, not yet broadcast, is counted. Short =
 * AMM_EP_FUNDS: nothing signed, nothing stored, retried.
 *
 * SETTLEMENT (plan line 268; evm-fee plan 6.9, 6.11.5). amm_eth_pay_step
 * reads the receipt of EVERY attempt of the head's nonce (the head and the
 * attempts it replaced: only one of them can be included) and settles the one
 * that landed with its OWN net; every other attempt of the nonce becomes
 * `voided` in the same journal transaction. For that attempt:
 *   DEPTH is a JOINT vote (plan line 252; package 1 amm_eth_watch.c classify):
 *     at least Q providers return the identical receipt (status, block
 *     number, block hash, logs) AND each of those same providers reports a
 *     tip at least payout_final_depth_eth above the receipt's block; a tip
 *     read from another provider does not count;
 *   status 1 at that depth AND exactly one USDT Transfer log from the bot to
 *     the recipient whose value equals the value sent (plan line 264: "receipt
 *     status and the Transfer log"; log checked like an incoming log in
 *     amm_eth_watch.c: USDT emitter, three topics, Transfer topic0, 32-byte
 *     data) -> attempt confirmed and the swap paid / refunded in ONE journal
 *     transaction (the depth setting is required, no default, DEFERRED value);
 *   status 1 but no such log (none, two, a receipt whose logs do not fit the
 *     table, a Transfer to another recipient) -> attempt `unknown` and swap
 *     `unknown`, the bot stops (AMM_EP_NO_LOG);
 *   status 1 and the log's value differs from the value sent (a TetherToken
 *     fee, TetherToken.sol:123-134) -> attempt confirmed, swap `held` with the
 *     delivered value in its message (AMM_EP_HELD); what follows is DEFERRED
 *     (plan line 277);
 *   status other than 1 at that depth -> attempt `failed` ("failed send");
 *     the swap stays as it is and the step returns AMM_EP_FAILED; the engine
 *     then calls amm_eth_pay_resend, which stores a NEW attempt (givens item
 *     113 "3 a"; the depth requirement is a READING, so that a receipt that a
 *     reorganisation could still replace is never final);
 *   no receipt of any attempt at the quorum and the confirmed nonce (`latest`
 *     count, Q-th largest) above the stored nonce -> the head is ORPHANED, the
 *     attempts it replaced are `voided` and the swap becomes `unknown` (plan
 *     line 268; "the bot stops": unknown refuses new approvals, plan section
 *     17);
 *   no receipt, the nonce not used, and the latest block's base fee (Q-th
 *     largest) above the head's max fee per gas -> the head cannot be included
 *     as it is: the step writes nothing and returns AMM_EP_STUCK (givens item
 *     115 "1"); the engine then calls amm_eth_pay_replace;
 *   otherwise: a `signed` head (never broadcast, or a restart between store and
 *     broadcast) is broadcast again as the SAME STORED BYTES; a `submitted`
 *     head is broadcast again as the same stored bytes to every usable
 *     provider when the latest block is above its last_submit_tip (at most once
 *     per new block; it stays `submitted` whatever the answers); an attempt it
 *     replaced is never broadcast again.
 * An unreadable fact (providers below the quorum, a disagreement, an attempt of
 * the group whose receipt is not readable) changes nothing: AMM_EP_UNKNOWN.
 *
 * RE-SEND (evm-fee plan 6.9; givens item 113 "3 a"). After AMM_EP_FAILED,
 * amm_eth_pay_resend plans a new attempt of gross = the failed attempt's net and
 * minimum 0 (the signed minimum was compared at the decision and is not
 * compared again), with fresh fee reads and a new nonce, and stores it before
 * anything is sent. The failed attempt's ceiling is already off that gross and
 * the new attempt's ceiling comes off it: both are deducted from the user, and
 * neither the Foundation's key nor the pool pays (items 95, 112). When nothing
 * is left after the new fee it returns AMM_EP_ZERO and stores nothing.
 *
 * REPLACEMENT (evm-fee plan 6.11; givens item 115 "1"). amm_eth_pay_replace
 * signs, for a head the step called stuck, a transaction with the SAME nonce,
 * gross unchanged, minimum 0 and the fields of the same formula at the current
 * base fee, the tip raised to the pool's replacement minimum (both fields at
 * least 10 % above the old ones, amm_eth_pay_replacement_fees); the extra fee is
 * deducted from the same user. It stores the replacement and marks the head
 * `replaced` in one journal transaction.
 *
 * PAUSE (plan section 16): payouts_paused signs and broadcasts nothing;
 * settlement reads continue.
 *
 * LOCKS. `p->mu` is the one lock of nonce allocation: it is held around
 * prepare, sign, step, resend and replace. amm_eth_pay_fee_facts and
 * amm_eth_pay_plan write nothing (no journal row, no nonce, no signature, no
 * broadcast) and read only the payer's configuration, providers and own address,
 * which nothing writes after amm_eth_pay_new: they take NO payer lock (their
 * callers are serialised by the engine's mutex).
 *
 * DETERMINISM: no clock (deadlines are the caller's); RFC 6979 signing; the
 * only randomness is the optional caller-supplied blinding seed.
 */
#ifndef AMM_ETH_PAY_H
#define AMM_ETH_PAY_H

#include <stdint.h>
#include <stddef.h>

#include "amm_eth.h"
#include "amm_journal.h"

#define AMM_EP_ITER_MAX 4

typedef struct amm_eth_pay amm_eth_pay_t;

typedef struct {
    const amm_eth_provider_t *providers;   /* copied; every payout call set  */
    int n_providers;                       /* 1..AMM_ETH_MAX_PROVIDERS       */
    int quorum;                            /* 1..n_providers (givens item 58) */
    amm_eth_price_t price;                 /* copied; fee_usdt required      */
    amm_journal_t *journal;                /* not owned                      */
    uint64_t chain_id;                     /* eth_chain_id (givens item 77), >= 1:
                                            * providers must report it; the nonce
                                            * key and the signature carry it   */
    const uint8_t *sk;                    /* the bot's secp256k1 key, 32 B  */
    const uint8_t *blind;                  /* NULL or 32 bytes (see amm_eth_tx.h) */
    uint8_t usdt[20];                      /* the USDT contract              */
    uint64_t final_depth;                  /* payout_final_depth_eth, >= 1   */
    int payouts_paused;                    /* the setting (plan section 16)  */
} amm_eth_pay_cfg_t;

typedef enum {
    AMM_EP_OK        = 0,
    AMM_EP_UNKNOWN   = 1,  /* a read failed, is below the quorum, disagrees, the
                            * estimate or the price is unreadable, no fixed
                            * point, no provider took a broadcast; nothing
                            * changed (or nothing moved)                      */
    AMM_EP_FUNDS     = 2,  /* the bot's USDT or ether cannot cover it; nothing
                            * signed or stored                                */
    AMM_EP_ZERO      = 3,  /* nothing is left after the fee; nothing signed
                            * or stored and no swap moved: the engine decides
                            * what follows (a refund or a re-send: the USDT
                            * goes to the pool; a payout: a NODUS refund; a
                            * replacement: nothing, the old payout waits)     */
    AMM_EP_BELOW_MIN = 4,  /* a payout's net is below the swap's minimum;
                            * nothing signed; moved to refund_pending         */
    AMM_EP_PAUSED    = 5,  /* payouts_paused                                  */
    AMM_EP_NEED_SIGN = 6,  /* step: the swap has no attempt yet               */
    AMM_EP_FAILED    = 7,  /* the receipt says failed (status != 1) at the
                            * final depth; attempt `failed`; the engine calls
                            * amm_eth_pay_resend                              */
    AMM_EP_ORPHANED  = 8,  /* the nonce was used by another transaction; the
                            * swap is now `unknown`                           */
    AMM_EP_NO_LOG    = 9,  /* status 1 at the final depth but no USDT Transfer
                            * log from the bot to the recipient: the attempt
                            * and the swap are now `unknown`, the bot stops   */
    AMM_EP_HELD      = 10, /* the Transfer log's value differs from the value
                            * sent (a TetherToken fee): the attempt is
                            * confirmed, the swap `held`, the delivered value
                            * is in its message; what follows is DEFERRED     */
    AMM_EP_STUCK     = 11, /* step: no receipt, the nonce unused and the base
                            * fee above the head's max fee per gas; nothing
                            * written: amm_eth_pay_replace is the next call   */
    AMM_EP_ERR       = -1  /* a journal fault or a bad argument               */
} amm_ep_rc_t;

/** NULL on a bad config (a missing journal, key, price function, provider
 *  call; a quorum outside 1..n; a zero final depth; an invalid secret key). */
amm_eth_pay_t *amm_eth_pay_new(const amm_eth_pay_cfg_t *cfg);
void amm_eth_pay_free(amm_eth_pay_t *p);
/** The bot's own Ethereum address (from its key). */
void amm_eth_pay_self(const amm_eth_pay_t *p, uint8_t out[20]);

typedef enum {
    AMM_EP_PAY     = 0,   /* net > 0 and net >= minimum                      */
    AMM_EP_BELOW   = 1,   /* net > 0 but net < minimum                       */
    AMM_EP_NOTHING = 2    /* net == 0 (fee >= gross)                         */
} amm_ep_verdict_t;

/** PURE. net = gross - fee, saturating at zero (never wraps: givens item
 *  52, amm_ledger amm_payout_after_fee); the verdict compares `minimum` with
 *  net AFTER the fee (for a refund pass minimum 0). `net_out` may be NULL. */
amm_ep_verdict_t amm_eth_pay_judge(uint64_t gross, uint64_t fee, uint64_t minimum,
                                   uint64_t *net_out);

/** The fee formula of rule F1 (evm-fee plan 6.3), PURE: max fee per gas =
 *  2 x `base` + `prio`. -1 (nothing written) when prio > INT64_MAX (checked
 *  first), when base > (INT64_MAX - prio) / 2 (the result stays within
 *  INT64_MAX), when the result is 0 or when it is below `prio`; otherwise 0. */
int amm_eth_pay_max_fee(uint64_t base, uint64_t prio, uint64_t *max_fee);
/** The pool's replacement bump, PURE: bump(x) = max(x + 1, floor(x x 110 /
 *  100)) (= x + max(1, x / 10)); -1 when it exceeds INT64_MAX, else 0. */
int amm_eth_pay_bump(uint64_t x, uint64_t *out);
/** The fields of a replacement (evm-fee plan 6.3, 6.11.3), PURE: prio_out =
 *  max(prio, bump(old_prio)), max_fee = amm_eth_pay_max_fee(base, prio_out),
 *  refused (-1) when that fails or max_fee < bump(old_max_fee). */
int amm_eth_pay_replacement_fees(uint64_t base, uint64_t prio, uint64_t old_max_fee,
                                 uint64_t old_prio, uint64_t *max_fee, uint64_t *prio_out);

/** What a payout's fee depends on that is NOT the recipient or the amount
 *  (evm-fee plan 6.5.2 (a)): the providers that report the configured chain
 *  id, and the base fee, tip and max fee per gas at the quorum. */
typedef struct {
    int      use[AMM_ETH_MAX_PROVIDERS];
    int      n_usable;
    uint64_t base, prio, max_fee;
} amm_ep_facts_t;

/** The result of the planning loop (evm-fee plan 6.5.2 (b)). `fee` is the
 *  ceiling deducted (gas limit x max fee, converted and rounded up, givens item
 *  95), `net` = gross - fee saturating, `gas` the bumped gas limit. */
typedef struct {
    uint64_t         gas, fee, net;
    amm_ep_verdict_t verdict;
    char             msg[AMM_MSG_MAX];
} amm_ep_plan_t;

/** READ-ONLY (no journal, no nonce, no signature, no broadcast, no payer lock):
 *  qualify the providers by chain id and read the base fee and the tip at the
 *  quorum. @return AMM_EP_OK / AMM_EP_UNKNOWN (below the quorum or malformed). */
int amm_eth_pay_fee_facts(amm_eth_pay_t *p, uint64_t deadline_ms, amm_ep_facts_t *out);

/** READ-ONLY, as amm_eth_pay_fee_facts: the gas loop exactly as the payout runs
 *  it (the estimate of transfer(recipient, a) at the quorum, bumped by 25 %, the
 *  price seam with facts->max_fee, the verdict of amm_eth_pay_judge, iterated
 *  until the call data that was estimated is the call data that will be signed)
 *  for `gross`, `minimum` (0 = none). It does not read the pause setting. @return
 *  AMM_EP_OK (`out` filled, verdict PAY / BELOW / NOTHING) or AMM_EP_UNKNOWN
 *  (an estimate or the price is unreadable, or no fixed point in AMM_EP_ITER_MAX
 *  rounds). The price question and the payout call this one function, so the
 *  shown estimate and the deducted fee are one computation. */
int amm_eth_pay_plan(amm_eth_pay_t *p, const amm_ep_facts_t *facts, const uint8_t recipient[20],
                     uint64_t gross, uint64_t minimum, uint64_t deadline_ms,
                     amm_ep_plan_t *out);

/** A USDT payout planned, estimated, balance-checked and SIGNED but not stored
 *  (plan section 12, revision 12): the decision of a NODUS -> USDT swap stores
 *  it together with the ledger update in one journal transaction
 *  (amm_journal_swap_decide). `fee` is the Ethereum fee DEDUCTED: the ceiling
 *  of the transaction signed (its gas limit -- the estimate raised by 25 %,
 *  rounded up -- times its max fee per gas, converted into USDT with the price
 *  seam and rounded up, givens item 95); `net` = gross - fee saturating. */
typedef struct {
    uint64_t       fee, net;
    amm_eattempt_t attempt;     /* ready to store when the call returned OK;
                                 * raw is heap: amm_ep_prepared_free            */
    char           msg[AMM_MSG_MAX];
} amm_ep_prepared_t;
void amm_ep_prepared_free(amm_ep_prepared_t *pre);

/** Plan and SIGN a USDT payout of `gross` (> 0) to `recipient_hex` (40 lowercase
 *  hex) WITHOUT touching the journal; `minimum` (0 = none) is compared with the
 *  amount after the fee. @return AMM_EP_OK (`out->attempt` ready) /
 *  AMM_EP_ZERO / AMM_EP_BELOW_MIN (nothing signed; `fee`, `net` set) /
 *  AMM_EP_FUNDS / AMM_EP_UNKNOWN / AMM_EP_PAUSED / AMM_EP_ERR. This module
 *  never moves a swap: the engine decides. The payer's nonce lock is released
 *  at return; the engine (one worker thread) stores the attempt right after. */
int amm_eth_pay_prepare(amm_eth_pay_t *p, const char *recipient_hex, uint64_t gross,
                        uint64_t minimum, uint64_t deadline_ms,
                        amm_ep_prepared_t *out);

typedef struct {
    int64_t  swap_seq;
    int      worked;        /* 1 = a state moved, a broadcast was recorded    */
    int      signed_;       /* 1 = a transaction was stored                   */
    int      submitted;     /* 1 = a broadcast was accepted by a provider     */
    int      confirmed;     /* 1 = the swap moved to paid / refunded          */
    uint64_t fee, net;      /* sign: the fee deducted and the amount carried  */
    char     msg[AMM_MSG_MAX];
} amm_ep_step_t;

/** Sign and STORE the transaction of the USDT REFUND of swap `swap_seq` (a
 *  USDT -> NODUS swap in refund_pending), owing `gross` USDT raw (> 0), as
 *  described above. A NODUS -> USDT swap's PAYOUT is not signed here
 *  (AMM_EP_ERR): its transaction is stored by the decision
 *  (amm_eth_pay_prepare, amm_journal_swap_decide). A refund whose fee is not
 *  below it returns AMM_EP_ZERO and nothing moves (the engine puts its USDT in
 *  the pool). Nothing is broadcast here. Legal only
 *  when the swap has no attempt. `out` may be NULL.
 *  @return AMM_EP_OK (stored) / AMM_EP_ZERO / AMM_EP_BELOW_MIN / AMM_EP_FUNDS /
 *  AMM_EP_UNKNOWN / AMM_EP_PAUSED / AMM_EP_ERR. */
int amm_eth_pay_sign(amm_eth_pay_t *p, int64_t swap_seq, uint64_t gross,
                     uint64_t deadline_ms, amm_ep_step_t *out);

/** Drive the payout of swap `swap_seq` ONE step: settle, or broadcast the
 *  stored bytes, as described above. @return AMM_EP_OK (`out->worked` says
 *  whether anything moved; waiting for the final depth is OK with worked 0) /
 *  AMM_EP_NEED_SIGN / AMM_EP_FAILED / AMM_EP_STUCK / AMM_EP_ORPHANED /
 *  AMM_EP_PAUSED / AMM_EP_UNKNOWN / AMM_EP_ERR. */
int amm_eth_pay_step(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                     amm_ep_step_t *out);

/** The automatic re-send of a payout or refund whose head attempt FAILED in a
 *  block (givens item 113 "3 a"; see RE-SEND above): sign and STORE a new
 *  attempt (n + 1, a new nonce) of gross = the failed attempt's net, minimum 0.
 *  Nothing is broadcast here: the next step sends the stored bytes. Legal only
 *  for a swap that owes a USDT payout whose head is `failed`; any other head is
 *  AMM_EP_ERR. @return AMM_EP_OK (stored; `out->fee`, `out->net`) / AMM_EP_ZERO
 *  (nothing left after the new fee: nothing stored, the engine puts the USDT in
 *  the pool) / AMM_EP_FUNDS / AMM_EP_UNKNOWN / AMM_EP_PAUSED / AMM_EP_ERR. */
int amm_eth_pay_resend(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                       amm_ep_step_t *out);

/** The REPLACEMENT of a stuck head (givens item 115 "1"; see REPLACEMENT above):
 *  after fresh reads confirm the trigger (no receipt of any attempt of the nonce,
 *  the nonce unused, the base fee above the head's max fee per gas), sign and
 *  STORE the replacement and mark the head `replaced`. Nothing is broadcast
 *  here. @return AMM_EP_OK (stored; `out->fee`, `out->net`) / AMM_EP_ZERO
 *  (nothing left after the replacement's fee: nothing stored, the old attempt
 *  stays and waits) / AMM_EP_OK with `out->worked` 0 when the trigger no longer
 *  holds / AMM_EP_FUNDS / AMM_EP_UNKNOWN / AMM_EP_PAUSED / AMM_EP_ERR. */
int amm_eth_pay_replace(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                        amm_ep_step_t *out);

#endif /* AMM_ETH_PAY_H */
