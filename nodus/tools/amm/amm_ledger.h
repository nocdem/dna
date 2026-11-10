/**
 * @file amm_ledger.h
 * @brief nodus-amm pure integer ledger math: swap output and fee, liquidity
 *        units, withdraw shares, saturating fee subtraction, in-flight room.
 *        No I/O, no clock, no allocation.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 10)
 * sections 5 (units, width, subtraction, rounding), 12 (ledger and pricing),
 * 13 (in-flight room), 14 (units, withdraw shares); givens items 51, 52.
 *
 * WIDTH (plan section 5): every quantity is a 256-bit unsigned integer
 * (shared/evm/evm_u256.h). The EVM operations wrap modulo 2^256 and divide
 * by zero to 0; this module therefore
 *   - refuses (AMM_E_OVERFLOW) any product or sum that would pass 2^256 - 1:
 *     the bit lengths are checked first (la + lb <= 256 always fits,
 *     la + lb >= 258 never fits), the one undecided case (la + lb == 257) is
 *     settled exactly by r / a == b on the wrapped product;
 *   - refuses (AMM_E_ZERO_DIV) a zero divisor BEFORE calling divide;
 *   - refuses (AMM_E_BORROW) every subtraction that would borrow, except the
 *     one saturating fee subtraction amm_sub_sat (givens item 52).
 * Every function that updates a pool is all-or-nothing: on any refusal the
 * pool is left exactly as it was.
 *
 * ROUNDING (plan section 5): swap output and fee truncate (THORChain `Quo`,
 * swap_current.go:570-603); withdraw shares round half up at the final
 * division (THORChain GetSafeShare / GetUncappedShare, type_convert.go:25-58).
 * Liquidity units: amm_units_for_add reproduces THORChain's cosmos LegacyDec
 * division (18 decimals, banker's rounding) and then TruncateInt, see
 * amm_dec_quo_trunc (plan line 193: "rounding follows the reference per
 * function").
 *
 * SIDES (plan section 14, "Mapping: R = NODUS side, A = USDT side"): the
 * pool holds depth_n (NODUS raw, 10^8 per NODUS) and depth_u (USDT raw,
 * 10^6 per USDT).
 */
#ifndef AMM_LEDGER_H
#define AMM_LEDGER_H

#include <stdint.h>
#include <stddef.h>

#include "evm/evm_u256.h"

typedef enum {
    AMM_OK            = 0,
    AMM_E_OVERFLOW    = -1,  /* a result would pass 2^256 - 1             */
    AMM_E_ZERO_DIV    = -2,  /* a divisor is zero                         */
    AMM_E_DEPTH       = -3,  /* output would reach the output-side depth  */
    AMM_E_BORROW      = -4,  /* a (non-saturating) subtraction would borrow */
    AMM_E_RANGE       = -5,  /* an argument outside its rule (a zero pool,
                              * basis points above 10000, ...)            */
    AMM_E_SWAP_LIMIT  = -6,  /* in-flight room: v above the per-swap limit */
    AMM_E_INFLIGHT    = -7   /* in-flight room: total would pass the limit */
} amm_rc_t;

typedef enum {
    AMM_USDT_TO_NODUS = 0,   /* input side depth_u, output side depth_n   */
    AMM_NODUS_TO_USDT = 1    /* input side depth_n, output side depth_u   */
} amm_dir_t;

typedef struct {
    evm_u256 depth_n;        /* NODUS side, raw units                      */
    evm_u256 depth_u;        /* USDT side, raw units                       */
    evm_u256 units;          /* total liquidity units                      */
} amm_pool_t;

/* ── checked primitives ───────────────────────────────────────────────── */

/** r = a + b; AMM_E_OVERFLOW on carry (r untouched). */
int amm_add(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** r = a * b; AMM_E_OVERFLOW when the product passes 2^256 - 1 (r untouched). */
int amm_mul(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** r = a / b truncated; AMM_E_ZERO_DIV for b == 0 (r untouched). */
int amm_div(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** r = a - b; AMM_E_BORROW when b > a (r untouched). */
int amm_sub(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** r = a - b, or 0 when b > a (THORChain SafeSub, type_convert.go:64-71;
 *  givens item 52: fee subtraction saturates at zero and never wraps). */
void amm_sub_sat(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);

/* ── swap (plan section 12) ───────────────────────────────────────────── */

/** The swap output: THORChain GetSwapCalc with the floor 0 (commission
 *  setting 0, givens item 73): the slip branch, (x*X*Y)/(x+X)^2 truncated
 *  (swap_current.go:570-579, :636-650). The slip fee (x^2*Y)/(x+X)^2
 *  (:594-603) is NOT paid out: the ledger update takes only the output from
 *  the output side, so the fee stays in the pool (givens item 79). X = input-side depth,
 *  Y = output-side depth, x = input. AMM_E_ZERO_DIV for x + X == 0,
 *  AMM_E_OVERFLOW, AMM_E_DEPTH when the output would reach Y
 *  (swap_current.go:380-385). */
int amm_swap_output(evm_u256 *out, const evm_u256 *X, const evm_u256 *x,
                    const evm_u256 *Y);

/** THORChain's no-floor emission (x*X*Y)/(x+X)^2 truncated
 *  (swap_current.go:570-579); amm_swap_output is this function. */
int amm_swap_emission_slip(evm_u256 *out, const evm_u256 *X,
                           const evm_u256 *x, const evm_u256 *Y);

/** THORChain's liquidity fee (x^2*Y)/(x+X)^2 truncated
 *  (swap_current.go:594-603): the slip fee, which stays in the pool. */
int amm_swap_liquidity_fee(evm_u256 *fee, const evm_u256 *X,
                           const evm_u256 *x, const evm_u256 *Y);

/** Quote for a direction against a pool (no change). */
int amm_pool_quote(const amm_pool_t *p, amm_dir_t dir, const evm_u256 *x,
                   evm_u256 *out);

/** Ledger update after a counted swap: input side += x, output side -=
 *  `paid`. `paid` is THE NUMBER THE BOT GAVE AT APPROVAL (plan section 12,
 *  givens items 66, 68), not a quote of today's depths: it is not computed
 *  again. Refusals (nothing changes): AMM_E_DEPTH when `paid` reaches the
 *  output-side depth, AMM_E_OVERFLOW on the input side, AMM_E_RANGE for a bad
 *  direction. All-or-nothing. */
int amm_pool_apply_swap(amm_pool_t *p, amm_dir_t dir, const evm_u256 *x,
                        const evm_u256 *paid);

/** Reverse a counted swap's ledger update (a payout that turned into a
 *  refund before anything was signed): input side -= x, output side += paid.
 *  AMM_E_BORROW / AMM_E_OVERFLOW refuse, nothing changes. */
int amm_pool_unapply_swap(amm_pool_t *p, amm_dir_t dir, const evm_u256 *x,
                          const evm_u256 *paid);

/** THORChain GetUncappedShare (type_convert.go): zero part, total or
 *  allocation -> 0; part == total -> allocation; else (allocation*part +
 *  floor(total/2)) / total, NOT capped at the total (GetSafeShare caps). */
int amm_uncapped_share(evm_u256 *out, const evm_u256 *part, const evm_u256 *total,
                       const evm_u256 *allocation);

/* The network fee deducted from a USDT payout is NOT a pool operation: it is
 * USDT kept by the Foundation (givens items 80, 92), booked in the journal
 * (amm_journal_book_fee). The THORChain asset-fee form (USDT into the pool,
 * NODUS out to the Foundation) was withdrawn by the operator's reading of item
 * 80; amm_pool_book_usdt_fee is removed. */

/* ── payout after the network fee (plan sections 7, 8 step 7; 10) ─────── */

typedef enum {
    AMM_PAYOUT_PAY       = 0,  /* net > 0 and net >= minimum                */
    AMM_PAYOUT_BELOW_MIN = 1   /* net < minimum, or net == 0 (also when the
                                * minimum is zero): refund path; no zero
                                * payout is ever broadcast (givens item 52) */
} amm_payout_t;

/** net = output - fee (saturating); then the verdict. The minimum is
 *  compared with the amount AFTER the fee (givens item 51 for a NODUS
 *  payout, THORChain's order for a USDT payout, plan section 8 step 7). */
amm_payout_t amm_payout_after_fee(const evm_u256 *output, const evm_u256 *fee,
                                  const evm_u256 *minimum, evm_u256 *net);

/* ── liquidity (plan section 14) ──────────────────────────────────────── */

/** Units for an add of r NODUS and a USDT into the pool state (P, R, A):
 *  THORChain calculatePoolUnits (handler_add_liquidity.go:444-460, 479-489):
 *      empty pool (R, A or P zero): s = r; when r == 0, s = a*R/A if A != 0
 *      else a;
 *      else s = P*(r*A + a*R + 2*r*a) / (r*A + a*R + 2*R*A).
 *  The quotient of the third case is THORChain's LegacyDec `Quo` followed by
 *  `TruncateInt` (handler_add_liquidity.go:489-499), see amm_dec_quo_trunc.
 *  `new_total` = P + s.
 *  Refusals: r + R == 0 or a + A == 0 (AMM_E_RANGE, handler_add_liquidity.go:
 *  434-439), overflow, zero denominator. */
/** out = TruncateInt(Dec(N).Quo(Dec(D))) for whole numbers N, D, exactly as
 *  cosmossdk.io/math v1.5.3 legacy_dec.go computes it:
 *    QuoMut (:383-388): i = floor(N*10^18 * 10^36 / (D*10^18));
 *      chopPrecisionAndRound (:624-656): q = i / 10^18, rem = i mod 10^18;
 *      rem < 5*10^17 -> q; rem > 5*10^17 -> q+1; rem == 5*10^17 -> banker's
 *      rounding, to the EVEN of q and q+1;
 *    TruncateInt (:723-725): floor(q' / 10^18).
 *  The intermediate N*10^36 is computed in 512 bits. AMM_E_ZERO_DIV for
 *  D == 0; AMM_E_OVERFLOW when the rounded Dec would pass the LegacyDec range
 *  (2^256 * 10^18 - 1), i.e. the result would not fit 256 bits. */
int amm_dec_quo_trunc(evm_u256 *out, const evm_u256 *N, const evm_u256 *D);

int amm_units_for_add(evm_u256 *s, evm_u256 *new_total, const evm_u256 *P,
                      const evm_u256 *R, const evm_u256 *A,
                      const evm_u256 *r, const evm_u256 *a);

/** Ledger update of an add: depth_n += r, depth_u += a, units += s.
 *  All-or-nothing. `s_out` may be NULL. */
int amm_pool_apply_add(amm_pool_t *p, const evm_u256 *r, const evm_u256 *a,
                       evm_u256 *s_out);

/** THORChain GetSafeShare (type_convert.go:25-58): part capped at total;
 *  zero part, total or allocation -> 0; part == total -> allocation; else
 *  (allocation*part + floor(total/2)) / total (round half up). */
int amm_safe_share(evm_u256 *out, const evm_u256 *part, const evm_u256 *total,
                   const evm_u256 *allocation);

typedef struct {
    evm_u256 units_claimed;  /* provider units burned                       */
    evm_u256 units_after;    /* provider units left (SafeSub)               */
    evm_u256 out_n;          /* NODUS paid                                  */
    evm_u256 out_u;          /* USDT paid                                   */
} amm_withdraw_t;

/** THORChain calculateWithdraw, symmetric branch (withdraw.go:197-218):
 *  refuses pool units, either depth or provider units zero, and bp > 10000
 *  (AMM_E_RANGE); units_claimed = GetSafeShare(bp, 10000, lp_units); each
 *  side = GetSafeShare(units_claimed, pool_units, depth). Pure: no pool
 *  change. */
int amm_withdraw_calc(amm_withdraw_t *w, const amm_pool_t *p,
                      const evm_u256 *lp_units, uint32_t bp);

/** Ledger update of a withdrawal: depths and total units reduced by the
 *  computed amounts. A borrow refuses (AMM_E_BORROW), nothing changes. */
int amm_pool_apply_withdraw(amm_pool_t *p, const amm_withdraw_t *w);

/* ── in-flight room (plan section 13) ─────────────────────────────────── */

/** Admission test of one swap value v (USDT raw): v <= swap_max (else
 *  AMM_E_SWAP_LIMIT) and sum_open + v <= inflight_max (else AMM_E_INFLIGHT;
 *  the sum overflowing is AMM_E_OVERFLOW). `sum_open` is the sum of v over
 *  the swaps that hold room, computed by the caller from the journal rows
 *  (plan line 311), never kept as a counter here. */
int amm_inflight_admit(uint64_t v, uint64_t sum_open, uint64_t swap_max,
                       uint64_t inflight_max);

/** Convert a 256-bit value to u64; AMM_E_OVERFLOW when it does not fit. */
int amm_to_u64(uint64_t *out, const evm_u256 *a);

#endif /* AMM_LEDGER_H */
