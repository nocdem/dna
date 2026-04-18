#ifndef QGP_U128_H
#define QGP_U128_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Portable 128-bit unsigned integer.
 *
 *  Explicit 64-bit limbs — NO compiler __uint128_t — so byte-level
 *  serialization is bit-identical across gcc / clang / MSVC on any
 *  endianness. Required for Merkle state_root determinism across
 *  the 7-node witness cluster (F-CRYPTO-08).
 */
typedef struct {
    uint64_t hi;   /**< most-significant 64 bits */
    uint64_t lo;   /**< least-significant 64 bits */
} qgp_u128_t;

/* ---- Constructors ---- */
qgp_u128_t qgp_u128_zero(void);
qgp_u128_t qgp_u128_from_u64(uint64_t v);
qgp_u128_t qgp_u128_from_limbs(uint64_t hi, uint64_t lo);

/* ---- Arithmetic (overflow aborts — supply invariance demands exactness) ---- */
qgp_u128_t qgp_u128_add(qgp_u128_t a, qgp_u128_t b);
qgp_u128_t qgp_u128_sub(qgp_u128_t a, qgp_u128_t b);       /* a >= b required, underflow aborts */
qgp_u128_t qgp_u128_mul_u64(qgp_u128_t a, uint64_t b);     /* overflow aborts */
qgp_u128_t qgp_u128_shl(qgp_u128_t a, unsigned bits);      /* bits < 128 */

/* ---- Division with remainder ---- */
qgp_u128_t qgp_u128_div_u64(qgp_u128_t a, uint64_t b, uint64_t *rem_out);  /* b != 0 required */

/* ---- Comparison ---- */
int qgp_u128_cmp(qgp_u128_t a, qgp_u128_t b);  /* returns -1, 0, +1 */

/* ---- Serialization (big-endian 16 bytes, MANDATORY for Merkle) ---- */
void       qgp_u128_serialize_be(qgp_u128_t v, uint8_t out[16]);
qgp_u128_t qgp_u128_deserialize_be(const uint8_t in[16]);

#ifdef __cplusplus
}
#endif

#endif /* QGP_U128_H */
