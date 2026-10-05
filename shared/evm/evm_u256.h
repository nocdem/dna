/**
 * @file evm_u256.h
 * @brief 256-bit unsigned integer arithmetic for the Nodus EVM (phase 1).
 *
 * Representation: four 64-bit limbs, LITTLE-endian limb order (w[0] is the
 * least significant). Signed operations interpret the value as two's
 * complement, exactly as the EVM does (execution-specs @a87891f7,
 * src/ethereum/forks/prague/vm/instructions/arithmetic.py and bitwise.py).
 *
 * Every function is total and deterministic: no undefined behaviour for any
 * input (shift counts >= 64 are handled explicitly, division by zero yields
 * zero as the EVM specifies), no allocation, no global state. The result
 * pointer may alias any operand.
 */
#ifndef EVM_U256_H
#define EVM_U256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t w[4];               /* w[0] = least significant limb */
} evm_u256;

/* ── construction / conversion ─────────────────────────────────────── */
void evm_u256_zero(evm_u256 *r);
void evm_u256_from_u64(evm_u256 *r, uint64_t v);
/** 32 big-endian bytes -> value. */
void evm_u256_from_be(evm_u256 *r, const uint8_t b[32]);
/** value -> 32 big-endian bytes. */
void evm_u256_to_be(uint8_t b[32], const evm_u256 *a);
/** 0..32 big-endian bytes (left-padded with zero) -> value.
 *  @return 0, or -1 if len > 32 (r untouched). */
int  evm_u256_from_be_var(evm_u256 *r, const uint8_t *b, size_t len);
/** @return 1 if a < 2^64 (then *out = value), else 0. */
int  evm_u256_to_u64(const evm_u256 *a, uint64_t *out);

/* ── predicates / comparison ───────────────────────────────────────── */
int evm_u256_is_zero(const evm_u256 *a);
/** unsigned compare: -1, 0, 1 */
int evm_u256_cmp(const evm_u256 *a, const evm_u256 *b);
/** two's-complement signed compare: -1, 0, 1 */
int evm_u256_scmp(const evm_u256 *a, const evm_u256 *b);
/** number of significant bits (0 for zero, 256 max). */
unsigned evm_u256_bitlen(const evm_u256 *a);

/* ── arithmetic (all modulo 2^256) ─────────────────────────────────── */
/** r = a + b; @return carry out (0/1). */
int  evm_u256_add(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** r = a - b; @return borrow out (0/1). */
int  evm_u256_sub(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
void evm_u256_mul(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** EVM DIV / MOD: b == 0 -> 0. */
void evm_u256_div(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
void evm_u256_mod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** EVM SDIV / SMOD (two's complement; SDIV(-2^255, -1) = -2^255; b == 0 -> 0;
 *  SMOD result takes the sign of the dividend). */
void evm_u256_sdiv(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
void evm_u256_smod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
/** EVM ADDMOD / MULMOD: computed over the full 257 / 512-bit intermediate;
 *  n == 0 -> 0. */
void evm_u256_addmod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b,
                     const evm_u256 *n);
void evm_u256_mulmod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b,
                     const evm_u256 *n);
/** EVM EXP: a^e mod 2^256. */
void evm_u256_exp(evm_u256 *r, const evm_u256 *a, const evm_u256 *e);
/** EVM SIGNEXTEND(b, x): if b >= 31 -> x. */
void evm_u256_signextend(evm_u256 *r, const evm_u256 *b, const evm_u256 *x);

/* ── bitwise ───────────────────────────────────────────────────────── */
void evm_u256_and(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
void evm_u256_or (evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
void evm_u256_xor(evm_u256 *r, const evm_u256 *a, const evm_u256 *b);
void evm_u256_not(evm_u256 *r, const evm_u256 *a);
/** EVM BYTE(i, x): i >= 32 -> 0; i = 0 is the MOST significant byte. */
void evm_u256_byte(evm_u256 *r, const evm_u256 *i, const evm_u256 *x);
/** EVM SHL/SHR/SAR(shift, value): shift >= 256 -> 0 (SAR: 0 or all-ones). */
void evm_u256_shl(evm_u256 *r, const evm_u256 *shift, const evm_u256 *v);
void evm_u256_shr(evm_u256 *r, const evm_u256 *shift, const evm_u256 *v);
void evm_u256_sar(evm_u256 *r, const evm_u256 *shift, const evm_u256 *v);

#ifdef __cplusplus
}
#endif

#endif /* EVM_U256_H */
