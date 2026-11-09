/**
 * @file amm_eth_pay.h
 * @brief nodus-amm USDT payout and refund on Ethereum: an EIP-1559
 *        transaction calling USDT `transfer(user, amount)` from the bot's own
 *        key, signed, STORED before it is broadcast, broadcast, settled by its
 *        receipt.
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
 * (amm_journal_swap_list_usdt_owed). Liquidity withdrawals are the engine's
 * (a later package). The swap row carries no output amount (the engine
 * computes it from the ledger when the payment counts), so the engine hands
 * `gross` to amm_eth_pay_sign once, exactly as amm_nodus_pay does.
 *
 * THE FEE (plan line 271, givens items 34, 50). The user pays the Ethereum
 * gas: fee = the USDT the price seam (amm_eth.h amm_eth_price_t) quotes for
 * the gas limit and max fee per gas the transaction will carry; net = gross -
 * fee with the SATURATING subtraction of amm_ledger (amm_payout_after_fee:
 * plan section 5, givens item 52). Nothing about the price source, format or
 * conversion is decided here (DEFERRED, plan section 10): an unreadable price
 * is AMM_ETH_ERR from the seam and nothing is signed (never zero).
 *   net == 0 (fee at or above the amount): nothing is signed or broadcast
 *     (givens item 52). A payout (NODUS -> USDT, payout_pending) is moved to
 *     refund_pending BEFORE any attempt is signed (plan line 241, as
 *     amm_nodus_pay); a refund (USDT -> NODUS, refund_pending) is moved to
 *     `held` (givens item 53). The LEDGER is not touched here: reversing the
 *     pool update of the payout is the engine's duty.
 *   net < the swap's signed minimum, for a payout: nothing is signed (the
 *     minimum is compared after the fee, plan line 241); the swap moves to
 *     refund_pending; AMM_EP_BELOW_MIN.
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
 * FEES OF THE TRANSACTION (plan silent: PLAN READING). References searched:
 * Boltz sends type 2 with `maxFeePerGas` and `maxPriorityFeePerGas` taken
 * from the provider's own fee data as reported, no own margin
 * (lib/wallet/ethereum/EthereumUtils.ts:86-101, getGasPrices; the ethers
 * `getFeeData` derivation is not in the pinned tree); THORChain's Ethereum
 * client derives the cap from THORChain's network gas rate and the tip as a
 * configured percentage of it (bifrost/pkg/chainclients/ethereum/
 * ethereum.go:925-979), neither of which exists here. So: no reference line
 * for deriving maxFeePerGas from JSON-RPC calls; the code keeps "provider's
 * own values, no margin" (max fee per gas from eth_gasPrice is PLAN READING:
 * no reference line). GAS LIMIT: Boltz raises the estimated limit by 25%,
 * rounded up, (gasLimit * 125 + 99) / 100 (EthereumUtils.ts:83-85
 * bumpGasLimit); the payer ports it: every estimate is bumped, and the bumped
 * limit is what the price seam is quoted and what is signed. Max fee per gas
 * = eth_gasPrice and max priority fee per gas = eth_maxPriorityFeePerGas as the
 * providers report them (the Q-th largest answer), the priority fee never
 * above the max fee (execution-specs osaka/fork.py:493-496: the effective
 * priority fee is min(max_priority, max_fee - base_fee), so the clamp changes
 * nothing that is paid). No margin, no multiplier is invented. Raising the fee
 * of a stuck payout is DEFERRED (plan line 270) and not built.
 *
 * READS (plan section 10 names no quorum for the payer; givens item 17 "Ethereum
 * read through ready-made RPC providers, more than one checked" and the
 * watcher's section 9 rule are the reading): every provider is used only when
 * it reports chain id 1; every read that decides a money state needs Q usable
 * answers (Q = the quorum setting, givens item 58):
 *   tip, transaction counts   the Q-th largest answer (at least Q providers
 *                             report that value or more)
 *   gas estimate, gas price   the Q-th largest / the largest answer
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
 * BALANCE CHECK (plan line 266): the USDT `balanceOf` of the bot's key minus
 * the USDT of the bot's own pending payouts (the sum of `net` over the stored
 * attempts that are signed or submitted) must cover `net`, and the ether
 * (eth_getBalance) must cover gas limit x max fee per gas (the most the
 * transaction can pay). Short = AMM_EP_FUNDS: nothing signed, nothing stored,
 * retried. (The plan subtracts pending USDT only; the ether of other pending
 * transactions is not subtracted: READING, reported.)
 *
 * SETTLEMENT (plan line 268). amm_eth_pay_step reads the receipt of the
 * stored transaction:
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
 *     the swap stays as it is, nothing is sent again by this module (plan
 *     line 278: what happens to a payout that cannot be sent is DEFERRED; the
 *     depth requirement is a READING, so that a receipt that a reorganisation
 *     could still replace is never final);
 *   no receipt at the quorum and the confirmed nonce (`latest` count, Q-th
 *     largest) above the stored nonce -> the attempt is ORPHANED and the swap
 *     becomes `unknown` (plan line 268; "the bot stops": unknown refuses new
 *     approvals, plan section 17);
 *   otherwise: a `signed` attempt (never broadcast, or a restart between
 *     store and broadcast) is broadcast again as the SAME STORED BYTES; a
 *     `submitted` attempt is not rebroadcast (the plan builds no rebroadcast
 *     or replacement: fee raising is DEFERRED; reported).
 * An unreadable fact (providers below the quorum, a disagreement) changes
 * nothing: AMM_EP_UNKNOWN.
 *
 * PAUSE (plan section 16): payouts_paused signs and broadcasts nothing;
 * settlement reads continue.
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
    const uint8_t *sk;                     /* the bot's secp256k1 key, 32 B  */
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
    AMM_EP_ZERO      = 3,  /* nothing is left after the fee; nothing signed;
                            * a payout moved to refund_pending, a refund to
                            * held                                            */
    AMM_EP_BELOW_MIN = 4,  /* a payout's net is below the swap's minimum;
                            * nothing signed; moved to refund_pending         */
    AMM_EP_PAUSED    = 5,  /* payouts_paused                                  */
    AMM_EP_NEED_SIGN = 6,  /* step: the swap has no attempt yet               */
    AMM_EP_FAILED    = 7,  /* the receipt says failed (status != 1) at the
                            * final depth; attempt `failed`                   */
    AMM_EP_ORPHANED  = 8,  /* the nonce was used by another transaction; the
                            * swap is now `unknown`                           */
    AMM_EP_NO_LOG    = 9,  /* status 1 at the final depth but no USDT Transfer
                            * log from the bot to the recipient: the attempt
                            * and the swap are now `unknown`, the bot stops   */
    AMM_EP_HELD      = 10, /* the Transfer log's value differs from the value
                            * sent (a TetherToken fee): the attempt is
                            * confirmed, the swap `held`, the delivered value
                            * is in its message; what follows is DEFERRED     */
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

typedef struct {
    int64_t  swap_seq;
    int      worked;        /* 1 = a state moved, a broadcast was recorded    */
    int      signed_;       /* 1 = a transaction was stored                   */
    int      submitted;     /* 1 = a broadcast was accepted by a provider     */
    int      confirmed;     /* 1 = the swap moved to paid / refunded          */
    uint64_t fee, net;      /* sign: the fee deducted and the amount carried  */
    char     msg[AMM_MSG_MAX];
} amm_ep_step_t;

/** Sign and STORE the payout transaction of swap `swap_seq`, owing `gross`
 *  USDT raw (> 0), as described above. Nothing is broadcast here. Legal only
 *  when the swap owes a USDT payout and has no attempt. `out` may be NULL.
 *  @return AMM_EP_OK (stored) / AMM_EP_ZERO / AMM_EP_BELOW_MIN / AMM_EP_FUNDS /
 *  AMM_EP_UNKNOWN / AMM_EP_PAUSED / AMM_EP_ERR. */
int amm_eth_pay_sign(amm_eth_pay_t *p, int64_t swap_seq, uint64_t gross,
                     uint64_t deadline_ms, amm_ep_step_t *out);

/** Drive the payout of swap `swap_seq` ONE step: settle, or broadcast the
 *  stored bytes, as described above. @return AMM_EP_OK (`out->worked` says
 *  whether anything moved; waiting for the final depth is OK with worked 0) /
 *  AMM_EP_NEED_SIGN / AMM_EP_FAILED / AMM_EP_ORPHANED / AMM_EP_PAUSED /
 *  AMM_EP_UNKNOWN / AMM_EP_ERR. */
int amm_eth_pay_step(amm_eth_pay_t *p, int64_t swap_seq, uint64_t deadline_ms,
                     amm_ep_step_t *out);

#endif /* AMM_ETH_PAY_H */
