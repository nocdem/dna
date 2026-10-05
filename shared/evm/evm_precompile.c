/**
 * @file evm_precompile.c
 * @brief The Prague precompiled contracts 0x01-0x11.
 *
 * Ports of execution-specs@a87891f7
 * src/ethereum/forks/prague/vm/precompiled_contracts/:
 *   0x01 ecrecover.py        (libsecp256k1 v0.8.0, recovery module,
 *                             third_party/secp256k1)
 *   0x02 sha256.py           (blst v0.3.17 blst_sha256, third_party/blst)
 *   0x03 ripemd160.py        (trezor-crypto ripemd160, third_party/ripemd160)
 *   0x04 identity.py
 *   0x05 modexp.py           (GMP 6.3.0, third_party/gmp; EIP-2565 gas;
 *                             EIP-7823 input bound —
 *                             a documented Nodus deviation, see pc_modexp)
 *   0x06-0x08 alt_bn128.py   (mcl v4.20, third_party/mcl)
 *   0x09 blake2f.py          (EIP-152 F, ported from ethereum/crypto/blake2.py)
 *   0x0a point_evaluation.py (c-kzg-4844 v2.1.8 + its mainnet setup)
 *   0x0b-0x11 bls12_381/     (blst v0.3.17; __init__.py, bls12_381_g1.py,
 *                             bls12_381_g2.py, bls12_381_pairing.py)
 * The vendored libraries are pinned in third_party/<name>/PINNED.md. No
 * precompile reads a digest from the system OpenSSL (operator decision
 * 2026-10-05, extending D2 of 2026-10-05-nodus-evm-redteam1-operator.md).
 *
 * Every function charges gas exactly where the reference calls charge_gas;
 * a failed charge is EVM_PC_OOG (OutOfGasError). The reference's other
 * exceptions map to:
 *   InvalidParameter / KZGProofError / ExceptionalHalt -> EVM_PC_INVALID
 *   OutOfGasError raised on bad input (alt_bn128.py)   -> EVM_PC_OOG
 * Both consume all gas (vm/exceptions.py: subclasses of ExceptionalHalt).
 * A library that cannot initialise, or answers with an internal error, is a
 * node fault (EVM_FAULT), never an EVM-visible result.
 */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <gmp.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "blst.h"
#include "ckzg.h"
#include "ripemd160.h"
#include <mcl/bn_c256.h>

#include "evm_internal.h"
#include "evm_gas.h"
#include "evm_precompile.h"
#include "crypto/hash/keccak256.h"

/* prague/vm/memory.py:buffer_read for a 64-bit start/size (zero padded) */
static void buf_read(uint8_t *dst, const uint8_t *data, size_t len,
                     uint64_t start, size_t size)
{
    if (size == 0) return;
    if (start >= len) {
        memset(dst, 0, size);
        return;
    }
    size_t avail = len - (size_t)start;
    size_t n = avail < size ? avail : size;
    memcpy(dst, data + start, n);
    if (n < size) memset(dst + n, 0, size - n);
}

static int charge(uint64_t *gas_left, uint64_t cost)
{
    if (*gas_left < cost) return 0;
    *gas_left -= cost;
    return 1;
}

static int out_copy(uint8_t **out, size_t *out_len, const uint8_t *src, size_t n)
{
    *out = NULL;
    *out_len = 0;
    if (n == 0) return 0;
    *out = malloc(n);
    if (!*out) return EVM_FAULT;
    memcpy(*out, src, n);
    *out_len = n;
    return 0;
}

/* a * b + c in 64 bits; 0 when the exact value does not fit. A cost that
 * does not fit in 64 bits exceeds every gas_left, so the caller reports
 * OutOfGas — exactly what the reference's unbounded Uint charge does. */
static int u64_mul_add(uint64_t a, uint64_t b, uint64_t c, uint64_t *r)
{
    uint64_t hi, lo;
    evm_mul64(a, b, &hi, &lo);
    if (hi != 0 || lo > UINT64_MAX - c) return 0;
    *r = lo + c;
    return 1;
}

/* floor(a * b / d) exactly, d != 0; 0 when the quotient exceeds 64 bits.
 * Long division of the 128-bit product in 32-bit limbs (no __int128,
 * design §4 D2). */
static int u64_mul_div(uint64_t a, uint64_t b, uint32_t d, uint64_t *q)
{
    uint64_t hi, lo, rem = 0;
    uint32_t limb[4], qd[4];
    evm_mul64(a, b, &hi, &lo);
    limb[0] = (uint32_t)(hi >> 32);
    limb[1] = (uint32_t)hi;
    limb[2] = (uint32_t)(lo >> 32);
    limb[3] = (uint32_t)lo;
    for (int i = 0; i < 4; i++) {
        uint64_t cur = (rem << 32) | limb[i];     /* rem < d < 2^32 */
        qd[i] = (uint32_t)(cur / d);
        rem = cur % d;
    }
    if (qd[0] != 0 || qd[1] != 0) return 0;
    *q = ((uint64_t)qd[2] << 32) | qd[3];
    return 1;
}

/* 32-byte big-endian word holding the small value v */
static void be32_u64(uint8_t out[32], uint64_t v)
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

/* ── 0x01 ecrecover ──────────────────────────────────────────────── */

/* SECP256K1N (ethereum/crypto/elliptic_curve.py), big-endian */
static const uint8_t SECP256K1N_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

/* 0 < x < N */
static int in_range_n(const uint8_t x[32])
{
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= x[i];
    if (!nonzero) return 0;
    return memcmp(x, SECP256K1N_BE, 32) < 0;
}

/* execution-specs@a87891f7 prague/vm/precompiled_contracts/ecrecover.py:
 * ecrecover (+ ethereum/crypto/elliptic_curve.py:secp256k1_recover) */
static int pc_ecrecover(const uint8_t *data, size_t len, uint64_t *gas,
                        evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    if (!charge(gas, EVM_G_PRECOMPILE_ECRECOVER)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    *res = EVM_PC_OK;
    uint8_t in[128];
    buf_read(in, data, len, 0, 128);
    const uint8_t *hash = in, *v = in + 32, *r = in + 64, *s = in + 96;
    /* v must be exactly 27 or 28 as a full word */
    for (int i = 0; i < 31; i++)
        if (v[i] != 0) return 0;             /* invalid: empty output */
    if (v[31] != 27 && v[31] != 28) return 0;
    if (!in_range_n(r) || !in_range_n(s)) return 0;   /* s >= N rejected */

    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_pubkey pub;
    uint8_t rs[64];
    memcpy(rs, r, 32);
    memcpy(rs + 32, s, 32);
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_static, &sig, rs, v[31] - 27))
        return 0;
    /* fails when r is not an x coordinate on the curve or the result is
     * the point at infinity: InvalidSignatureError -> empty output */
    if (!secp256k1_ecdsa_recover(secp256k1_context_static, &pub, &sig, hash))
        return 0;
    uint8_t ser[65];
    size_t ser_len = sizeof(ser);
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, ser, &ser_len,
                                       &pub, SECP256K1_EC_UNCOMPRESSED) ||
        ser_len != 65)
        return EVM_FAULT;
    uint8_t h[32];
    if (keccak256(ser + 1, 64, h) != 0) return EVM_FAULT;
    uint8_t padded[32];
    memset(padded, 0, 12);
    memcpy(padded + 12, h + 12, 20);
    return out_copy(out, out_len, padded, 32);
}

/* ── 0x02 sha256 / 0x03 ripemd160 ─────────────────────────────────── */

/* Both digests come from pinned, vendored code, never from the system
 * OpenSSL (operator decision 2026-10-05, extending D2): SHA-256 from blst
 * v0.3.17 (bindings/blst_aux.h blst_sha256, src/exports.c), RIPEMD-160
 * from trezor-crypto (third_party/ripemd160/PINNED.md). Neither has an
 * initialisation step that can fail; the start-up self-test checks both
 * through the precompile entry points (PC_KATS).
 *
 * trezor-crypto's ripemd160.c byte-swaps only when PCT_BIG_ENDIAN is
 * defined by hand, and nothing defines it: a big-endian target is refused
 * here rather than computing wrong digests. */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "the vendored RIPEMD-160 (third_party/ripemd160) needs a little-endian target"
#endif

/* data may be NULL when len is 0 (an empty call): both libraries get a
 * valid pointer — trezor-crypto's ripemd160_process asserts p != NULL even
 * for length 0. */
static const uint8_t g_empty_msg = 0;

static void evm_sha256(const uint8_t *data, size_t len, uint8_t md[32])
{
    blst_sha256(md, len ? data : &g_empty_msg, len);
}

static void evm_ripemd160(const uint8_t *data, size_t len, uint8_t md[20])
{
    ripemd160(len ? data : &g_empty_msg, len, md);
}

/* execution-specs@a87891f7 prague/vm/precompiled_contracts/sha256.py:sha256 */
static int pc_sha256(const uint8_t *data, size_t len, uint64_t *gas,
                     evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t cost = evm_gas_add(EVM_G_PRECOMPILE_SHA256_BASE,
                    evm_gas_mul(EVM_G_PRECOMPILE_SHA256_PER_WORD,
                                evm_words((uint64_t)len)));
    if (!charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    uint8_t md[32];
    evm_sha256(data, len, md);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, md, 32);
}

/* execution-specs@a87891f7 prague/vm/precompiled_contracts/ripemd160.py:
 * ripemd160 */
static int pc_ripemd160(const uint8_t *data, size_t len, uint64_t *gas,
                        evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t cost = evm_gas_add(EVM_G_PRECOMPILE_RIPEMD160_BASE,
                    evm_gas_mul(EVM_G_PRECOMPILE_RIPEMD160_PER_WORD,
                                evm_words((uint64_t)len)));
    if (!charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    uint8_t md[20];
    evm_ripemd160(data, len, md);
    uint8_t padded[32];
    memset(padded, 0, 12);
    memcpy(padded + 12, md, 20);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, padded, 32);
}

/* ── 0x04 identity ────────────────────────────────────────────────── */

/* execution-specs@a87891f7 prague/vm/precompiled_contracts/identity.py */
static int pc_identity(const uint8_t *data, size_t len, uint64_t *gas,
                       evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t cost = evm_gas_add(EVM_G_PRECOMPILE_IDENTITY_BASE,
                    evm_gas_mul(EVM_G_PRECOMPILE_IDENTITY_PER_WORD,
                                evm_words((uint64_t)len)));
    if (!charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    *res = EVM_PC_OK;
    return out_copy(out, out_len, data, len);
}

/* ── 0x05 modexp ──────────────────────────────────────────────────── */

/* EIP-7823 bound: execution-specs@a87891f7
 * src/ethereum/forks/osaka/vm/precompiled_contracts/modexp.py:32-41 */
#define EVM_MODEXP_MAX_LEN 1024u

/* Uint.from_be_bytes(buffer_read(data, start, size)): the available bytes,
 * then the zero padding as a left shift. Every caller passes
 * size <= EVM_MODEXP_MAX_LEN (pc_modexp refuses larger lengths first), so
 * the shift is at most 8192 bits on every platform; a larger size is a
 * broken invariant (-2), never a result. */
static int mpz_read(mpz_t r, const uint8_t *data, size_t len,
                    uint64_t start, uint64_t size)
{
    mpz_set_ui(r, 0);
    if (size > EVM_MODEXP_MAX_LEN) return EVM_FAULT;
    if (size == 0) return 0;
    uint64_t avail = 0;
    if (start < len) {
        avail = (uint64_t)len - start;
        if (avail > size) avail = size;
        mpz_import(r, (size_t)avail, 1, 1, 1, 0, data + start);
    }
    uint64_t pad = size - avail;
    if (mpz_sgn(r) != 0) mpz_mul_2exp(r, r, (mp_bitcnt_t)(pad * 8u));
    return 0;
}

/* U256.from_be_bytes(word) > U256(1024)? (osaka modexp.py:32-41) */
static int modexp_len_word(const uint8_t w[32], uint64_t *v)
{
    for (int i = 0; i < 30; i++)
        if (w[i] != 0) return 0;
    *v = ((uint64_t)w[30] << 8) | w[31];
    return *v <= EVM_MODEXP_MAX_LEN;
}

/* execution-specs@a87891f7 prague/vm/precompiled_contracts/modexp.py:
 * modexp, complexity, iterations, gas_cost — with the input bound of
 * osaka/vm/precompiled_contracts/modexp.py:32-41.
 *
 * DEVIATION: EIP-7823 bound adopted (Ethereum Osaka) to cap modexp work and
 * GMP memory; Prague has no bound. A base, exponent or modulus length word
 * above 1024 is an ExceptionalHalt (EVM_PC_INVALID: all gas consumed)
 * before any gas is computed, exactly as the Osaka reference raises it.
 * The GAS formula stays Prague's (EIP-2565: words**2, 8 * (len - 32),
 * // 3, floor 200); EIP-7883's Osaka repricing is NOT adopted.
 *
 * With every length <= 1024 the whole gas computation fits in 64 bits:
 * complexity <= 128**2, iterations <= 8 * 992 + 255. */
static int pc_modexp(const uint8_t *data, size_t len, uint64_t *gas,
                     evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    int rc = 0;
    uint8_t w[32];
    uint64_t bl, el, ml;

    /* base_length, exp_length, modulus_length, each refused above 1024 in
     * the reference's order (osaka modexp.py:31-41) */
    buf_read(w, data, len, 0, 32);
    if (!modexp_len_word(w, &bl)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    buf_read(w, data, len, 32, 32);
    if (!modexp_len_word(w, &el)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    buf_read(w, data, len, 64, 32);
    if (!modexp_len_word(w, &ml)) {
        *res = EVM_PC_INVALID;
        return 0;
    }

    mpz_t ehead, base, ex, mod, r;
    mpz_inits(ehead, base, ex, mod, r, NULL);

    /* exp_start = U256(96) + base_length (<= 1120); exp_head = the first
     * min(32, exp_length) bytes at exp_start */
    uint64_t es = 96u + bl;
    if (mpz_read(ehead, data, len, es, el < 32 ? el : 32) != 0) {
        rc = EVM_FAULT;
        goto done;
    }
    {
        /* complexity: words = (max(base_len, mod_len) + 7) // 8; words**2 */
        uint64_t maxl = bl > ml ? bl : ml;
        uint64_t words = (maxl + 7u) / 8u;
        uint64_t cplx = words * words;
        /* iterations */
        uint64_t hbits = mpz_sgn(ehead) == 0 ? 0 : (uint64_t)mpz_sizeinbase(ehead, 2);
        uint64_t iters;
        if (el <= 32 && hbits == 0)
            iters = 0;
        else if (el <= 32)
            iters = hbits - 1;
        else
            iters = 8u * (el - 32u) + (hbits > 0 ? hbits - 1 : 0);
        if (iters < 1) iters = 1;
        uint64_t cost = cplx * iters / EVM_G_MODEXP_QUAD_DIVISOR;
        if (cost < EVM_G_MODEXP_MIN) cost = EVM_G_MODEXP_MIN;
        if (!charge(gas, cost)) {
            *res = EVM_PC_OOG;
            goto done;
        }
    }
    *res = EVM_PC_OK;
    if (bl == 0 && ml == 0) {
        *out = NULL;
        *out_len = 0;
        goto done;
    }
    {
        if (mpz_read(base, data, len, 96, bl) != 0 ||
            mpz_read(ex, data, len, es, el) != 0 ||
            mpz_read(mod, data, len, es + el, ml) != 0) {
            rc = EVM_FAULT;
            goto done;
        }
        if (ml == 0) {
            *out = NULL;
            *out_len = 0;
            goto done;
        }
        uint8_t *o = calloc(1, (size_t)ml);
        if (!o) {
            rc = EVM_FAULT;
            goto done;
        }
        if (mpz_sgn(mod) != 0) {
            /* pow(base, exp, modulus).to_bytes(modulus_length, "big") */
            mpz_powm(r, base, ex, mod);
            mpz_mod(r, r, mod);
            if (mpz_sgn(r) != 0) {
                size_t nb = (mpz_sizeinbase(r, 2) + 7) / 8;
                if (nb > ml) {
                    free(o);
                    rc = EVM_FAULT;
                    goto done;
                }
                size_t cnt = 0;
                mpz_export(o + ((size_t)ml - nb), &cnt, 1, 1, 1, 0, r);
                if (cnt != nb) {
                    free(o);
                    rc = EVM_FAULT;
                    goto done;
                }
            }
        }
        /* modulus == 0: b"\x00" * modulus_length */
        *out = o;
        *out_len = (size_t)ml;
    }
done:
    mpz_clears(ehead, base, ex, mod, r, NULL);
    return rc;
}

/* ── 0x09 blake2f (EIP-152) ───────────────────────────────────────── */

/* ethereum/crypto/blake2.py: Blake2.sigma, Blake2.IV, Blake2.MIX_TABLE,
 * Blake2b (w=64, R1..R4 = 32, 24, 16, 63) */
static const uint8_t B2_SIGMA[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};
static const uint64_t B2_IV[8] = {
    0x6A09E667F3BCC908ull, 0xBB67AE8584CAA73Bull,
    0x3C6EF372FE94F82Bull, 0xA54FF53A5F1D36F1ull,
    0x510E527FADE682D1ull, 0x9B05688C2B3E6C1Full,
    0x1F83D9ABFB41BD6Bull, 0x5BE0CD19137E2179ull,
};
static const uint8_t B2_MIX[8][4] = {
    { 0, 4, 8, 12 }, { 1, 5, 9, 13 }, { 2, 6, 10, 14 }, { 3, 7, 11, 15 },
    { 0, 5, 10, 15 }, { 1, 6, 11, 12 }, { 2, 7, 8, 13 }, { 3, 4, 9, 14 },
};

static uint64_t rotr64(uint64_t x, unsigned r)
{
    return (x >> r) | (x << (64u - r));      /* r in {32,24,16,63} */
}

/* ethereum/crypto/blake2.py:Blake2.G */
static void b2_g(uint64_t v[16], unsigned a, unsigned b, unsigned c, unsigned d,
                 uint64_t x, uint64_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 63);
}

static uint64_t le64(const uint8_t *p)
{
    uint64_t x = 0;
    for (int i = 7; i >= 0; i--) x = (x << 8) | p[i];
    return x;
}

/* execution-specs@a87891f7 prague/vm/precompiled_contracts/blake2f.py:
 * blake2f (+ ethereum/crypto/blake2.py get_blake2_parameters, compress).
 * The reference's `v[8:15] = self.IV` slice assignment grows the list to
 * 17 entries; v[16] is never read, so v[8..15] = IV[0..7] is equivalent. */
static int pc_blake2f(const uint8_t *data, size_t len, uint64_t *gas,
                      evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    if (len != 213) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    uint32_t rounds = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                      ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    uint64_t h[8], m[16], v[16];
    for (int i = 0; i < 8; i++) h[i] = le64(data + 4 + 8 * i);
    for (int i = 0; i < 16; i++) m[i] = le64(data + 68 + 8 * i);
    uint64_t t0 = le64(data + 196), t1 = le64(data + 204);
    uint8_t fflag = data[212];
    if (!charge(gas, (uint64_t)EVM_G_PRECOMPILE_BLAKE2F_PER_ROUND * rounds)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (fflag != 0 && fflag != 1) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[8 + i] = B2_IV[i];
    v[12] = t0 ^ B2_IV[4];
    v[13] = t1 ^ B2_IV[5];
    if (fflag) v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFull;
    for (uint32_t r = 0; r < rounds; r++) {
        const uint8_t *s = B2_SIGMA[r % 10];
        for (int k = 0; k < 8; k++)
            b2_g(v, B2_MIX[k][0], B2_MIX[k][1], B2_MIX[k][2], B2_MIX[k][3],
                 m[s[2 * k]], m[s[2 * k + 1]]);
    }
    uint8_t o[64];
    for (int i = 0; i < 8; i++) {
        uint64_t x = h[i] ^ v[i] ^ v[i + 8];
        for (int b = 0; b < 8; b++) o[8 * i + b] = (uint8_t)(x >> (8 * b));
    }
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 64);
}

/* ── 0x06-0x08 alt_bn128 (EIP-196/197, EIP-1108 gas) ─────────────── */
/*
 * mcl v4.20 C API (third_party/mcl), curve MCL_BN_SNARK1
 * (include/mcl/curve_type.h:15; parameters include/mcl/curve_type.hpp:46:
 * z = 4965661367192848881, y^2 = x^3 + 3, xi = 9 + i, D-type twist), the
 * curve of py_ecc.optimized_bn128 used by the reference. Every failure of
 * the reference here is `raise OutOfGasError` -> EVM_PC_OOG.
 */

/* py_ecc optimized_bn128 field_modulus / curve_order (py_ecc v8.0.0
 * fields/field_properties.py:24, optimized_bn128/optimized_curve.py:17) */
static const char BN_P_DEC[] =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";
static const char BN_R_DEC[] =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
static const uint8_t BN_P_BE[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47
};

static pthread_once_t g_bn_once = PTHREAD_ONCE_INIT;
static int            g_bn_ok;

static int dec_equals(const char *buf, size_t n, const char *want)
{
    return n == strlen(want) && memcmp(buf, want, n) == 0;
}

static void bn_init(void)
{
    char buf[128];
    size_t n;
    if (mclBn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR) != 0) return;
    /* isValid() = on-curve only; the order checks are called explicitly
     * where the reference makes them (pairing only) */
    mclBn_verifyOrderG1(0);
    mclBn_verifyOrderG2(0);
    /* the library must be on the reference's curve */
    memset(buf, 0, sizeof(buf));
    n = mclBn_getFieldOrder(buf, sizeof(buf));
    if (!dec_equals(buf, n, BN_P_DEC)) return;
    memset(buf, 0, sizeof(buf));
    n = mclBn_getCurveOrder(buf, sizeof(buf));
    if (!dec_equals(buf, n, BN_R_DEC)) return;
    g_bn_ok = 1;
}

static int bn_ready(void)
{
    if (pthread_once(&g_bn_once, bn_init) != 0) return 0;
    return g_bn_ok;
}

static int is_zero_bytes(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* x < field_modulus for a 32-byte big-endian x */
static int bn_fp_canonical(const uint8_t x[32])
{
    return memcmp(x, BN_P_BE, 32) < 0;
}

/* alt_bn128.py:bytes_to_g1 — 1 point, 0 InvalidParameter, -2 fault */
static int bn_g1_decode(mclBnG1 *pt, const uint8_t in[64])
{
    if (!bn_fp_canonical(in) || !bn_fp_canonical(in + 32)) return 0;
    if (is_zero_bytes(in, 64)) {         /* x == 0 and y == 0: z = 0 */
        mclBnG1_clear(pt);
        return 1;                        /* is_on_curve(inf) is True */
    }
    if (mclBnFp_setBigEndianMod(&pt->x, in, 32) != 0 ||
        mclBnFp_setBigEndianMod(&pt->y, in + 32, 32) != 0)
        return EVM_FAULT;
    mclBnFp_setInt(&pt->z, 1);
    return mclBnG1_isValid(pt) ? 1 : 0;
}

/* alt_bn128.py:bytes_to_g2 — x = FQ2((x1, x0)): the first word is the
 * imaginary coefficient, the second the real one; same for y. */
static int bn_g2_decode(mclBnG2 *pt, const uint8_t in[128])
{
    for (int i = 0; i < 4; i++)
        if (!bn_fp_canonical(in + 32 * i)) return 0;
    if (is_zero_bytes(in, 128)) {
        mclBnG2_clear(pt);
        return 1;
    }
    if (mclBnFp_setBigEndianMod(&pt->x.d[0], in + 32, 32) != 0 ||
        mclBnFp_setBigEndianMod(&pt->x.d[1], in, 32) != 0 ||
        mclBnFp_setBigEndianMod(&pt->y.d[0], in + 96, 32) != 0 ||
        mclBnFp_setBigEndianMod(&pt->y.d[1], in + 64, 32) != 0)
        return EVM_FAULT;
    mclBnFp_setInt(&pt->z.d[0], 1);
    mclBnFp_setInt(&pt->z.d[1], 0);
    return mclBnG2_isValid(pt) ? 1 : 0;
}

/* normalize(p); Uint(x).to_be_bytes32() + Uint(y).to_be_bytes32().
 * normalize(inf) divides by z = 0, which py_ecc defines as 0
 * (utils.py:prime_field_inv), so infinity encodes as 64 zero bytes. */
static int bn_g1_encode(uint8_t out[64], const mclBnG1 *pt)
{
    mclBnG1 a;
    uint8_t le[32];
    memset(out, 0, 64);
    if (mclBnG1_isZero(pt)) return 0;
    mclBnG1_normalize(&a, pt);
    const mclBnFp *c[2] = { &a.x, &a.y };
    for (int k = 0; k < 2; k++) {
        memset(le, 0, sizeof(le));
        size_t n = mclBnFp_getLittleEndian(le, sizeof(le), c[k]);
        if (n == 0 || n > 32) return EVM_FAULT;
        for (size_t i = 0; i < n; i++) out[32 * k + 31 - i] = le[i];
    }
    return 0;
}

/* alt_bn128.py:alt_bn128_add */
static int pc_bn_add(const uint8_t *data, size_t len, uint64_t *gas,
                     evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint8_t in[128], o[64];
    mclBnG1 p0, p1, r;
    int d0, d1;
    if (!charge(gas, EVM_G_PRECOMPILE_ECADD)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bn_ready()) return EVM_FAULT;
    buf_read(in, data, len, 0, 128);
    d0 = bn_g1_decode(&p0, in);
    if (d0 < 0) return EVM_FAULT;
    d1 = d0 ? bn_g1_decode(&p1, in + 64) : 0;
    if (d1 < 0) return EVM_FAULT;
    if (!d0 || !d1) {
        *res = EVM_PC_OOG;                       /* OutOfGasError from e */
        return 0;
    }
    mclBnG1_add(&r, &p0, &p1);
    if (bn_g1_encode(o, &r) != 0) return EVM_FAULT;
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 64);
}

/* alt_bn128.py:alt_bn128_mul. multiply(p0, n) takes n unreduced; every
 * point on y^2 = x^3 + 3 over Fp has order dividing curve_order (the BN
 * curve's group of points has prime order r, EIP-196; not re-derived
 * here), so n*P = (n mod r)*P and mcl's Fr scalar is exact. */
static int pc_bn_mul(const uint8_t *data, size_t len, uint64_t *gas,
                     evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint8_t in[96], o[64];
    mclBnG1 p0, r;
    mclBnFr s;
    int d;
    if (!charge(gas, EVM_G_PRECOMPILE_ECMUL)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bn_ready()) return EVM_FAULT;
    buf_read(in, data, len, 0, 96);
    d = bn_g1_decode(&p0, in);
    if (d < 0) return EVM_FAULT;
    if (!d) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (mclBnFr_setBigEndianMod(&s, in + 64, 32) != 0) return EVM_FAULT;
    mclBnG1_mul(&r, &p0, &s);
    if (bn_g1_encode(o, &r) != 0) return EVM_FAULT;
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 64);
}

/* alt_bn128.py:alt_bn128_pairing_check. Gas first (on len // 192), then
 * the length check. pairing() returns FQ12.one() when either point is the
 * point at infinity (py_ecc v8.0.0 optimized_bn128/optimized_pairing.py:
 * 235-236), so such pairs are skipped. The product of the per-pair
 * pairings is one iff the final exponentiation of the product of the
 * Miller loops is one (the final exponentiation is a homomorphism, and any
 * two non-degenerate pairings G2 x G1 -> mu_r differ by a fixed exponent
 * coprime to r). */
static int pc_bn_pairing(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t k = (uint64_t)len / 192u, cost;
    uint8_t o[32];
    mclBnGT acc, ml, fe;
    int any = 0;
    if (!u64_mul_add(EVM_G_PRECOMPILE_ECPAIRING_PER_POINT, k,
                     EVM_G_PRECOMPILE_ECPAIRING_BASE, &cost) ||
        !charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (len % 192u != 0) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bn_ready()) return EVM_FAULT;
    for (uint64_t i = 0; i < k; i++) {
        mclBnG1 p;
        mclBnG2 q;
        int dp = bn_g1_decode(&p, data + 192u * i);
        if (dp < 0) return EVM_FAULT;
        int dq = dp ? bn_g2_decode(&q, data + 192u * i + 64u) : 0;
        if (dq < 0) return EVM_FAULT;
        if (!dp || !dq) {
            *res = EVM_PC_OOG;
            return 0;
        }
        /* is_inf(multiply(p, curve_order)); multiply(inf, n) is inf */
        int pz = mclBnG1_isZero(&p), qz = mclBnG2_isZero(&q);
        if ((!pz && !mclBnG1_isValidOrder(&p)) ||
            (!qz && !mclBnG2_isValidOrder(&q))) {
            *res = EVM_PC_OOG;
            return 0;
        }
        if (pz || qz) continue;
        mclBn_millerLoop(&ml, &p, &q);
        if (any) {
            mclBnGT t = acc;
            mclBnGT_mul(&acc, &t, &ml);
        } else {
            acc = ml;
            any = 1;
        }
    }
    int one = 1;
    if (any) {
        mclBn_finalExp(&fe, &acc);
        one = mclBnGT_isOne(&fe) ? 1 : 0;
    }
    memset(o, 0, sizeof(o));
    o[31] = (uint8_t)one;
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 32);
}

/* ── BLS12-381 field and point codecs (EIP-2537) ──────────────────── */
/*
 * blst v0.3.17 (third_party/blst). Ports of execution-specs@a87891f7
 * prague/vm/precompiled_contracts/bls12_381/__init__.py.
 */

/* py_ecc optimized_bls12_381 field_modulus (fields/field_properties.py:29)
 * = blst src/consts.c:10-14 BLS12_381_P, big-endian */
static const uint8_t BLS_P_BE[48] = {
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a,
    0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf,
    0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff,
    0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab
};

/* bls12_381/__init__.py:G1_K_DISCOUNT, G2_K_DISCOUNT (128 entries each),
 * G1_MAX_DISCOUNT = 519, G2_MAX_DISCOUNT = 524, MULTIPLIER = 1000 */
static const uint16_t BLS_G1_K_DISCOUNT[128] = {
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698,
    692, 687, 682, 677, 673, 669, 665, 661, 658, 654, 651, 648,
    645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619,
    617, 615, 613, 611, 609, 608, 606, 604, 603, 601, 599, 598,
    596, 595, 593, 592, 591, 589, 588, 586, 585, 584, 582, 581,
    580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567,
    566, 565, 564, 563, 562, 561, 560, 559, 558, 557, 556, 555,
    554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545, 544,
    543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534,
    533, 532, 532, 531, 530, 529, 528, 528, 527, 526, 525, 525,
    524, 523, 522, 522, 521, 520, 520, 519
};
static const uint16_t BLS_G2_K_DISCOUNT[128] = {
    1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749,
    740, 732, 724, 717, 711, 704, 699, 693, 688, 683, 679, 674,
    670, 666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634,
    632, 629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607,
    606, 604, 602, 600, 598, 597, 595, 593, 592, 590, 589, 587,
    586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571,
    570, 569, 568, 567, 566, 565, 563, 562, 561, 560, 559, 558,
    557, 556, 555, 554, 553, 552, 552, 551, 550, 549, 548, 547,
    546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537,
    537, 536, 535, 535, 534, 533, 532, 532, 531, 530, 530, 529,
    528, 528, 527, 526, 526, 525, 524, 524
};
#define BLS_G1_MAX_DISCOUNT 519u
#define BLS_G2_MAX_DISCOUNT 524u
#define BLS_MULTIPLIER      1000u

/* bytes_to_fq: int.from_bytes(64 bytes, "big") >= field_modulus raises.
 * p < 2^381, so a non-zero top 16 bytes is always >= p. */
static int bls_fp_decode(blst_fp *out, const uint8_t in[64])
{
    if (!is_zero_bytes(in, 16)) return 0;
    if (memcmp(in + 16, BLS_P_BE, 48) >= 0) return 0;
    blst_fp_from_bendian(out, in + 16);
    return 1;
}

static void bls_fp_encode(uint8_t out[64], const blst_fp *a)
{
    memset(out, 0, 16);
    blst_bendian_from_fp(out + 16, a);
}

/* _bytes_to_g1_cached: field checks, (0, 0) is infinity, on-curve check,
 * optional subgroup check (is_inf(multiply(point, curve_order)); the
 * infinity passes it). 1 point, 0 InvalidParameter. */
static int bls_g1_decode(blst_p1_affine *pt, const uint8_t in[128],
                         int subgroup_check)
{
    if (!bls_fp_decode(&pt->x, in) || !bls_fp_decode(&pt->y, in + 64))
        return 0;
    if (is_zero_bytes(in, 128)) return 1;   /* blst affine (0,0) = infinity */
    if (!blst_p1_affine_on_curve(pt)) return 0;
    if (subgroup_check && !blst_p1_affine_in_g1(pt)) return 0;
    return 1;
}

/* _bytes_to_g2_cached; bytes_to_fq2: c0 = data[:64] (real), c1 = data[64:]
 * -> blst_fp2.fp[0], fp[1] ("0 is real part", bindings/blst.h:64) */
static int bls_g2_decode(blst_p2_affine *pt, const uint8_t in[256],
                         int subgroup_check)
{
    if (!bls_fp_decode(&pt->x.fp[0], in) ||
        !bls_fp_decode(&pt->x.fp[1], in + 64) ||
        !bls_fp_decode(&pt->y.fp[0], in + 128) ||
        !bls_fp_decode(&pt->y.fp[1], in + 192))
        return 0;
    if (is_zero_bytes(in, 256)) return 1;
    if (!blst_p2_affine_on_curve(pt)) return 0;
    if (subgroup_check && !blst_p2_affine_in_g2(pt)) return 0;
    return 1;
}

/* g1_to_bytes(normalize(p)); infinity normalizes to (0, 0) (py_ecc
 * inv0(0) = 0), i.e. 128 zero bytes */
static void bls_g1_encode(uint8_t out[128], const blst_p1 *pt)
{
    blst_p1_affine a;
    if (blst_p1_is_inf(pt)) {
        memset(out, 0, 128);
        return;
    }
    blst_p1_to_affine(&a, pt);
    bls_fp_encode(out, &a.x);
    bls_fp_encode(out + 64, &a.y);
}

/* g2_to_bytes: fq2_to_bytes(x) + fq2_to_bytes(y), coeffs[0] first */
static void bls_g2_encode(uint8_t out[256], const blst_p2 *pt)
{
    blst_p2_affine a;
    if (blst_p2_is_inf(pt)) {
        memset(out, 0, 256);
        return;
    }
    blst_p2_to_affine(&a, pt);
    bls_fp_encode(out, &a.x.fp[0]);
    bls_fp_encode(out + 64, &a.x.fp[1]);
    bls_fp_encode(out + 128, &a.y.fp[0]);
    bls_fp_encode(out + 192, &a.y.fp[1]);
}

/* k * mul * discount // 1000 with discount = table[k-1] for k <= 128,
 * else the max discount (bls12_g1_msm / bls12_g2_msm "GAS") */
static int bls_msm_gas(uint64_t k, uint64_t mul, const uint16_t table[128],
                       uint64_t max_discount, uint64_t *cost)
{
    uint64_t discount = k <= 128 ? table[k - 1] : max_discount;
    return u64_mul_div(k, mul * discount, BLS_MULTIPLIER, cost);
}

/* ── 0x0b-0x0d, 0x0e, 0x10 G1 / G2 (bls12_381_g1.py, bls12_381_g2.py) ── */

/* bls12_381_g1.py:bls12_g1_add — no subgroup check */
static int pc_bls_g1_add(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    blst_p1_affine a1, a2;
    blst_p1 p1, p2, r;
    uint8_t o[128];
    if (len != 256) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (!charge(gas, EVM_G_PRECOMPILE_BLS_G1ADD)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bls_g1_decode(&a1, data, 0) || !bls_g1_decode(&a2, data + 128, 0)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    blst_p1_from_affine(&p1, &a1);
    blst_p1_from_affine(&p2, &a2);
    blst_p1_add_or_double(&r, &p1, &p2);    /* complete: inf, P == Q */
    bls_g1_encode(o, &r);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 128);
}

/* bls12_381_g2.py:bls12_g2_add — no subgroup check */
static int pc_bls_g2_add(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    blst_p2_affine a1, a2;
    blst_p2 p1, p2, r;
    uint8_t o[256];
    if (len != 512) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (!charge(gas, EVM_G_PRECOMPILE_BLS_G2ADD)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bls_g2_decode(&a1, data, 0) || !bls_g2_decode(&a2, data + 256, 0)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    blst_p2_from_affine(&p1, &a1);
    blst_p2_from_affine(&p2, &a2);
    blst_p2_add_or_double(&r, &p1, &p2);
    bls_g2_encode(o, &r);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 256);
}

/* bls12_381_g1.py:bls12_g1_msm. Each pair: decode_g1_scalar_pair (point
 * with subgroup check, 32-byte big-endian scalar m, unreduced), product =
 * multiply(p, m), summed in order. A subgroup point times m equals the
 * point times (m mod r); blst_p1_mult takes the 256-bit scalar as is (GLV
 * below r, windowed otherwise, src/e1.c blst_p1_mult). Infinity or m = 0
 * gives infinity and is skipped. A naive loop, as the reference; the gas is
 * the reference's formula, not a function of this implementation. */
static int pc_bls_g1_msm(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t k, cost;
    blst_p1 acc, pt, prod;
    uint8_t o[128];
    if (len == 0 || len % 160u != 0) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    k = (uint64_t)len / 160u;
    if (!bls_msm_gas(k, EVM_G_PRECOMPILE_BLS_G1MUL, BLS_G1_K_DISCOUNT,
                     BLS_G1_MAX_DISCOUNT, &cost) ||
        !charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    memset(&acc, 0, sizeof(acc));               /* Z = 0: infinity */
    for (uint64_t i = 0; i < k; i++) {
        const uint8_t *pair = data + 160u * i;
        blst_p1_affine a;
        blst_scalar s;
        if (!bls_g1_decode(&a, pair, 1)) {
            *res = EVM_PC_INVALID;
            return 0;
        }
        if (blst_p1_affine_is_inf(&a) || is_zero_bytes(pair + 128, 32))
            continue;
        blst_scalar_from_bendian(&s, pair + 128);
        blst_p1_from_affine(&pt, &a);
        blst_p1_mult(&prod, &pt, s.b, 256);
        blst_p1_add_or_double(&acc, &acc, &prod);
    }
    bls_g1_encode(o, &acc);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 128);
}

/* bls12_381_g2.py:bls12_g2_msm (as pc_bls_g1_msm; pair = 288 bytes) */
static int pc_bls_g2_msm(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t k, cost;
    blst_p2 acc, pt, prod;
    uint8_t o[256];
    if (len == 0 || len % 288u != 0) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    k = (uint64_t)len / 288u;
    if (!bls_msm_gas(k, EVM_G_PRECOMPILE_BLS_G2MUL, BLS_G2_K_DISCOUNT,
                     BLS_G2_MAX_DISCOUNT, &cost) ||
        !charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    memset(&acc, 0, sizeof(acc));
    for (uint64_t i = 0; i < k; i++) {
        const uint8_t *pair = data + 288u * i;
        blst_p2_affine a;
        blst_scalar s;
        if (!bls_g2_decode(&a, pair, 1)) {
            *res = EVM_PC_INVALID;
            return 0;
        }
        if (blst_p2_affine_is_inf(&a) || is_zero_bytes(pair + 256, 32))
            continue;
        blst_scalar_from_bendian(&s, pair + 256);
        blst_p2_from_affine(&pt, &a);
        blst_p2_mult(&prod, &pt, s.b, 256);
        blst_p2_add_or_double(&acc, &acc, &prod);
    }
    bls_g2_encode(o, &acc);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 256);
}

/* bls12_381_g1.py:bls12_map_fp_to_g1 — clear_cofactor_G1(map_to_curve_G1)
 * = blst map_to_g1 with v = NULL (src/map_to_g1.c:404-420: SSWU onto the
 * 11-isogenous curve, isogeny map, then multiplication by 1 - z =
 * 0xd201000000010001 = py_ecc H_EFF_G1, optimized_bls12_381/constants.py) */
static int pc_bls_map_g1(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    blst_fp u;
    blst_p1 r;
    uint8_t o[128];
    if (len != 64) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (!charge(gas, EVM_G_PRECOMPILE_BLS_G1MAP)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bls_fp_decode(&u, data)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    blst_map_to_g1(&r, &u, NULL);
    bls_g1_encode(o, &r);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 128);
}

/* bls12_381_g2.py:bls12_map_fp2_to_g2 — clear_cofactor_G2(map_to_curve_G2)
 * = blst map_to_g2 with v = NULL (src/map_to_g2.c:355-368). py_ecc
 * multiplies by H_EFF_G2 (optimized_clear_cofactor.py:24-27); blst uses the
 * Budroni-Pintore endomorphism form (map_to_g2.c:327-351), which the hash-
 * to-curve specification gives as equal to that multiplication (blst's
 * disabled h_eff path, map_to_g2.c:291-302, holds the same h_eff). */
static int pc_bls_map_g2(const uint8_t *data, size_t len, uint64_t *gas,
                         evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    blst_fp2 u;
    blst_p2 r;
    uint8_t o[256];
    if (len != 128) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (!charge(gas, EVM_G_PRECOMPILE_BLS_G2MAP)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    if (!bls_fp_decode(&u.fp[0], data) || !bls_fp_decode(&u.fp[1], data + 64)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    blst_map_to_g2(&r, &u, NULL);
    bls_g2_encode(o, &r);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 256);
}

/* ── 0x0f pairing (bls12_381_pairing.py) ──────────────────────────── */

/* bls12_381_pairing.py:bls12_pairing. Per pair: G1 decode, G1 subgroup
 * check, G2 decode, G2 subgroup check (infinity passes both), then the
 * pairing; pairs with an infinity contribute FQ12.one() (py_ecc
 * optimized_bls12_381/optimized_pairing.py:230-231) and are skipped. See
 * pc_bn_pairing for why one final exponentiation of the Miller-loop
 * product decides the same equality. */
static int pc_bls_pairing(const uint8_t *data, size_t len, uint64_t *gas,
                          evm_pc_result_t *res, uint8_t **out, size_t *out_len)
{
    uint64_t k, cost;
    blst_fp12 acc, ml, fe;
    int any = 0;
    uint8_t o[32];
    if (len == 0 || len % 384u != 0) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    k = (uint64_t)len / 384u;
    if (!u64_mul_add(EVM_G_PRECOMPILE_BLS_PAIRING_PER_PAIR, k,
                     EVM_G_PRECOMPILE_BLS_PAIRING_BASE, &cost) ||
        !charge(gas, cost)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    for (uint64_t i = 0; i < k; i++) {
        blst_p1_affine p;
        blst_p2_affine q;
        if (!bls_g1_decode(&p, data + 384u * i, 1) ||
            !bls_g2_decode(&q, data + 384u * i + 128u, 1)) {
            *res = EVM_PC_INVALID;
            return 0;
        }
        if (blst_p1_affine_is_inf(&p) || blst_p2_affine_is_inf(&q)) continue;
        blst_miller_loop(&ml, &q, &p);
        if (any) {
            blst_fp12 t = acc;
            blst_fp12_mul(&acc, &t, &ml);
        } else {
            acc = ml;
            any = 1;
        }
    }
    int one = 1;
    if (any) {
        blst_final_exp(&fe, &acc);
        one = blst_fp12_is_one(&fe) ? 1 : 0;
    }
    memset(o, 0, sizeof(o));
    o[31] = (uint8_t)one;
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 32);
}

/* ── 0x0a point evaluation (EIP-4844) ─────────────────────────────── */

/* point_evaluation.py: FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS (the latter
 * also blst src/consts.c BLS12_381_r and ethereum/crypto/kzg.py) */
#define EVM_KZG_FIELD_ELEMENTS_PER_BLOB 4096u
_Static_assert(FIELD_ELEMENTS_PER_BLOB == EVM_KZG_FIELD_ELEMENTS_PER_BLOB,
               "c-kzg-4844 blob size differs from the reference");
static const uint8_t BLS_R_BE[32] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
};

/* The mainnet trusted setup text, embedded at build time (Makefile:
 * xxd -i third_party/c-kzg-4844/src/trusted_setup.txt). */
extern unsigned char evm_kzg_trusted_setup_txt[];
extern unsigned int evm_kzg_trusted_setup_txt_len;

/* sha256 of that file (third_party/c-kzg-4844/PINNED.md) */
static const uint8_t KZG_SETUP_SHA256[32] = {
    0xd3, 0x9b, 0x9f, 0x2d, 0x04, 0x7c, 0xc9, 0xdc,
    0xa2, 0xde, 0x58, 0xf2, 0x64, 0xb6, 0xa0, 0x94,
    0x48, 0xcc, 0xd3, 0x4d, 0xb9, 0x67, 0x88, 0x1a,
    0x67, 0x13, 0xea, 0xca, 0xcf, 0x0f, 0x26, 0xb7
};
/* ethereum/crypto/kzg.py:KZG_SETUP_G2_MONOMIAL_1 — the only setup point the
 * reference's verify_kzg_proof_impl uses ([tau]G2, compressed) */
static const uint8_t KZG_SETUP_G2_MONOMIAL_1[96] = {
    0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28,
    0x84, 0x3b, 0xc2, 0x87, 0x23, 0x0a, 0xf3, 0x89,
    0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xa8,
    0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a, 0xc5, 0x3d,
    0x29, 0x14, 0xe5, 0x87, 0x0c, 0xb4, 0x52, 0xd2,
    0xaf, 0xaa, 0xab, 0x24, 0xf3, 0x49, 0x9f, 0x72,
    0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14,
    0x73, 0x44, 0x29, 0xb7, 0xb3, 0x86, 0x08, 0xe2,
    0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9,
    0xa3, 0x68, 0x51, 0x47, 0x7b, 0xa4, 0xc6, 0x0b,
    0x08, 0x70, 0x41, 0xde, 0x62, 0x10, 0x00, 0xed,
    0xc9, 0x8e, 0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2
};

/* c-kzg-4844 src/setup/setup.c:34-43 (private there) */
#define KZG_NUM_G1    4096u
#define KZG_NUM_G2    65u
#define KZG_BYTES_G1  48u
#define KZG_BYTES_G2  96u

static pthread_once_t g_kzg_once = PTHREAD_ONCE_INIT;
static KZGSettings    g_kzg;
static int            g_kzg_ok;

/* Parser for the setup text, the format setup.c:load_trusted_setup_file
 * reads with fscanf: two decimal counts, then hex bytes (two digits each,
 * whitespace allowed between bytes). Stricter than fscanf: exactly two hex
 * digits per byte and nothing but whitespace after the last point. */
typedef struct {
    const uint8_t *p;
    size_t n, i;
} ts_cursor;

static void ts_ws(ts_cursor *c)
{
    while (c->i < c->n && (c->p[c->i] == ' ' || c->p[c->i] == '\n' ||
                           c->p[c->i] == '\r' || c->p[c->i] == '\t'))
        c->i++;
}

static int ts_u64(ts_cursor *c, uint64_t *v)
{
    uint64_t x = 0;
    size_t start;
    ts_ws(c);
    start = c->i;
    while (c->i < c->n && c->p[c->i] >= '0' && c->p[c->i] <= '9') {
        if (x > (UINT64_MAX - 9u) / 10u) return 0;
        x = x * 10u + (uint64_t)(c->p[c->i] - '0');
        c->i++;
    }
    if (c->i == start) return 0;
    *v = x;
    return 1;
}

static int hex_nibble(uint8_t ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int ts_bytes(ts_cursor *c, uint8_t *out, size_t count)
{
    for (size_t k = 0; k < count; k++) {
        int hi, lo;
        ts_ws(c);
        if (c->n - c->i < 2) return 0;
        hi = hex_nibble(c->p[c->i]);
        lo = hex_nibble(c->p[c->i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[k] = (uint8_t)((hi << 4) | lo);
        c->i += 2;
    }
    return 1;
}

/* Load once: the embedded bytes must be the pinned file (sha256) and its
 * G2 point 1 the reference's constant; then c-kzg's load_trusted_setup
 * (precompute 0 — the table only speeds up EIP-7594 cell proofs, which no
 * precompile uses). Any failure leaves g_kzg_ok = 0: every point
 * evaluation is then a node fault, never "proof invalid". */
static void kzg_init(void)
{
    const uint8_t *txt = evm_kzg_trusted_setup_txt;
    size_t n = evm_kzg_trusted_setup_txt_len;
    uint8_t md[32];
    uint8_t *g1l = NULL, *g2m = NULL, *g1m = NULL;
    uint64_t n1 = 0, n2 = 0;
    ts_cursor c;

    evm_sha256(txt, n, md);
    if (memcmp(md, KZG_SETUP_SHA256, 32) != 0)
        return;
    g1l = malloc((size_t)KZG_NUM_G1 * KZG_BYTES_G1);
    g2m = malloc((size_t)KZG_NUM_G2 * KZG_BYTES_G2);
    g1m = malloc((size_t)KZG_NUM_G1 * KZG_BYTES_G1);
    if (!g1l || !g2m || !g1m) goto done;
    c.p = txt;
    c.n = n;
    c.i = 0;
    /* setup.c:542-582: counts, G1 Lagrange, G2 monomial, G1 monomial */
    if (!ts_u64(&c, &n1) || n1 != KZG_NUM_G1 ||
        !ts_u64(&c, &n2) || n2 != KZG_NUM_G2 ||
        !ts_bytes(&c, g1l, (size_t)KZG_NUM_G1 * KZG_BYTES_G1) ||
        !ts_bytes(&c, g2m, (size_t)KZG_NUM_G2 * KZG_BYTES_G2) ||
        !ts_bytes(&c, g1m, (size_t)KZG_NUM_G1 * KZG_BYTES_G1))
        goto done;
    ts_ws(&c);
    if (c.i != c.n) goto done;
    if (memcmp(g2m + KZG_BYTES_G2, KZG_SETUP_G2_MONOMIAL_1, KZG_BYTES_G2) != 0)
        goto done;
    if (load_trusted_setup(&g_kzg, g1m, (uint64_t)KZG_NUM_G1 * KZG_BYTES_G1,
                           g1l, (uint64_t)KZG_NUM_G1 * KZG_BYTES_G1,
                           g2m, (uint64_t)KZG_NUM_G2 * KZG_BYTES_G2,
                           0) != C_KZG_OK)
        goto done;
    g_kzg_ok = 1;
done:
    free(g1l);
    free(g2m);
    free(g1m);
}

static int kzg_ready(void)
{
    if (pthread_once(&g_kzg_once, kzg_init) != 0) return 0;
    return g_kzg_ok;
}

/* point_evaluation.py:point_evaluation (+ ethereum/crypto/kzg.py:
 * kzg_commitment_to_versioned_hash, verify_kzg_proof). c-kzg's
 * verify_kzg_proof (src/eip4844/eip4844.c:302-328) performs the same input
 * validation as kzg.py (bytes_to_kzg_commitment / bytes_to_bls_field /
 * bytes_to_kzg_proof: on-curve, subgroup, infinity accepted, z and y < r)
 * and returns C_KZG_BADARGS where kzg.py's asserts raise; both are
 * KZGProofError. C_KZG_ERROR / C_KZG_MALLOC are internal: fault. */
static int pc_point_evaluation(const uint8_t *data, size_t len, uint64_t *gas,
                               evm_pc_result_t *res, uint8_t **out,
                               size_t *out_len)
{
    uint8_t md[32], o[64];
    Bytes48 commitment, proof;
    Bytes32 z, y;
    bool ok = false;
    C_KZG_RET kr;
    if (len != 192) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (!charge(gas, EVM_G_PRECOMPILE_POINT_EVALUATION)) {
        *res = EVM_PC_OOG;
        return 0;
    }
    /* VERSIONED_HASH_VERSION_KZG + sha256(commitment)[1:] */
    evm_sha256(data + 96, 48, md);
    md[0] = 0x01;
    if (memcmp(md, data, 32) != 0) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (!kzg_ready()) return EVM_FAULT;
    memcpy(z.bytes, data + 32, 32);
    memcpy(y.bytes, data + 64, 32);
    memcpy(commitment.bytes, data + 96, 48);
    memcpy(proof.bytes, data + 144, 48);
    kr = verify_kzg_proof(&ok, &commitment, &z, &y, &proof, &g_kzg);
    if (kr == C_KZG_BADARGS || (kr == C_KZG_OK && !ok)) {
        *res = EVM_PC_INVALID;
        return 0;
    }
    if (kr != C_KZG_OK) return EVM_FAULT;
    /* U256(FIELD_ELEMENTS_PER_BLOB).to_be_bytes32() +
     * U256(BLS_MODULUS).to_be_bytes32() */
    be32_u64(o, EVM_KZG_FIELD_ELEMENTS_PER_BLOB);
    memcpy(o + 32, BLS_R_BE, 32);
    *res = EVM_PC_OK;
    return out_copy(out, out_len, o, 64);
}

/* ── dispatch (prague/vm/precompiled_contracts/mapping.py) ────────── */

int evm_precompile_run(const evm_addr *addr, const uint8_t *data, size_t len,
                       uint64_t *gas_left, evm_pc_result_t *res,
                       uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    *res = EVM_PC_INVALID;
    if (!evm_is_precompile(addr)) return EVM_FAULT;
    switch (addr->b[31]) {
    case 0x01: return pc_ecrecover(data, len, gas_left, res, out, out_len);
    case 0x02: return pc_sha256(data, len, gas_left, res, out, out_len);
    case 0x03: return pc_ripemd160(data, len, gas_left, res, out, out_len);
    case 0x04: return pc_identity(data, len, gas_left, res, out, out_len);
    case 0x05: return pc_modexp(data, len, gas_left, res, out, out_len);
    case 0x06: return pc_bn_add(data, len, gas_left, res, out, out_len);
    case 0x07: return pc_bn_mul(data, len, gas_left, res, out, out_len);
    case 0x08: return pc_bn_pairing(data, len, gas_left, res, out, out_len);
    case 0x09: return pc_blake2f(data, len, gas_left, res, out, out_len);
    case 0x0a: return pc_point_evaluation(data, len, gas_left, res, out, out_len);
    case 0x0b: return pc_bls_g1_add(data, len, gas_left, res, out, out_len);
    case 0x0c: return pc_bls_g1_msm(data, len, gas_left, res, out, out_len);
    case 0x0d: return pc_bls_g2_add(data, len, gas_left, res, out, out_len);
    case 0x0e: return pc_bls_g2_msm(data, len, gas_left, res, out, out_len);
    case 0x0f: return pc_bls_pairing(data, len, gas_left, res, out, out_len);
    case 0x10: return pc_bls_map_g1(data, len, gas_left, res, out, out_len);
    case 0x11: return pc_bls_map_g2(data, len, gas_left, res, out, out_len);
    default:
        /* evm_is_precompile admits 0x01..0x11 only: unreachable */
        return EVM_FAULT;
    }
}

/* ── start-up self-test (evm_precompile.h) ────────────────────────── */

/* One known answer per precompile family. Sources (execution-specs@a87891f7
 * tests/ unless stated):
 *  sha256      FIPS 180-2 Appendix B.1 ("abc")
 *  ripemd160   frontier/precompiles/test_ripemd.py id=ripemd_abc
 *  ecrecover   frontier/precompiles/test_ecrecover.py id=valid_signature_1
 *  modexp      byzantium/eip198_modexp_precompile/test_modexp.py
 *              id=EIP-198-case1
 *  blake2f     istanbul/eip152_blake2/test_blake2.py id=valid-rounds-12
 *              (input assembled from spec.py SpecTestVectors, common.py)
 *  ecadd       byzantium/eip196_ec_add_mul/test_ecadd.py id=p1_plus_q1
 *              (spec.py P1, Q1, R1)
 *  ecpairing   byzantium/eip197_ec_pairing/test_ecpairing.py
 *              id=two_pairs_negated_g1 (true) and id=one_pair (false)
 *  kzg         cancun/eip4844_blobs/point_evaluation_vectors/
 *              go_kzg_4844_verify_kzg_proof.json
 *              verify_kzg_proof_case_correct_proof_26b753dec0560daa
 *              (input = versioned hash ‖ z ‖ y ‖ commitment ‖ proof)
 *  bls         prague/eip2537_bls_12_381_precompiles/vectors/
 *              add_G1_bls.json bls_g1add_g1+p1,
 *              pairing_check_bls.json bls_pairing_e(aG1,bG2)=e(abG1,G2)
 *              and bls_pairing_non-degeneracy_e(P,Q)!= 1,
 *              map_fp2_to_G2_bls.json bls_g2map_ */
typedef struct {
    uint8_t     addr;
    const char *in;
    const char *out;
} pc_kat_t;

static const pc_kat_t PC_KATS[] = {
    { 0x02, "616263",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { 0x03, "616263",
      "0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
    { 0x01,
      "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
      "000000000000000000000000000000000000000000000000000000000000001c"
      "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
      "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
      "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b" },
    { 0x05,
      "0000000000000000000000000000000000000000000000000000000000000001"
      "0000000000000000000000000000000000000000000000000000000000000020"
      "0000000000000000000000000000000000000000000000000000000000000020"
      "03"
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
      "0000000000000000000000000000000000000000000000000000000000000001" },
    { 0x09,
      "0000000c"
      "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
      "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
      "6162630000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0300000000000000" "0000000000000000" "01",
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" },
    { 0x06,
      "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa9"
      "01e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c"
      "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869"
      "073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98",
      "15bf2bb17880144b5d1cd2b1f46eff9d617bffd1ca57c37fb5a49bd84e53cf66"
      "049c797f9ce0d17083deb32b5e36f2ea2a212ee036598dd7624c168993d1355f" },
    { 0x08,
      "0000000000000000000000000000000000000000000000000000000000000001"
      "0000000000000000000000000000000000000000000000000000000000000002"
      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
      "0000000000000000000000000000000000000000000000000000000000000001"
      "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"
      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
      "0000000000000000000000000000000000000000000000000000000000000001" },
    { 0x08,
      "0000000000000000000000000000000000000000000000000000000000000001"
      "0000000000000000000000000000000000000000000000000000000000000002"
      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
      "0000000000000000000000000000000000000000000000000000000000000000" },
    { 0x0a,
      "01ad7666ef9d8f53b5adf54f029b13b6f171b1d0bd346a2ede315d3e243484ef"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001"
      "93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878"
      "d97b05f5c8d900acf1fbbbca6f146556"
      "b82ded761997f2c6f1bb3db1e1dada2ef06d936551667c82f659b75f99d2da20"
      "68b81340823ee4e829a93c9fbed7810d",
      "0000000000000000000000000000000000000000000000000000000000001000"
      "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001" },
    { 0x0b,
      "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f"
      "c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
      "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
      "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
      "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec9"
      "7977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca9426"
      "00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbd"
      "ede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21",
      "000000000000000000000000000000000a40300ce2dec9888b60690e9a41d300"
      "4fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d"
      "0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226"
      "754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025" },
    { 0x0f,
      "000000000000000000000000000000000491d1b0ecd9bb917989f0e74f0dea04"
      "22eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
      "0000000000000000000000000000000017cd7061575d3e8034fcea62adaa1a3b"
      "c38dca4b50e4c5c01d04dd78037c9cee914e17944ea99e7ad84278e5d49f36c4"
      "000000000000000000000000000000000bc2357c6782bbb6a078d9e171fc7a81"
      "f7bd8ca73eb485e76317359908bb09bd372fd362a637512a9d48019b383e5489"
      "0000000000000000000000000000000004b8f49c3bac0247a09487049492b0ed"
      "99cf90c56263141daa35f011330d3ced3f3ad78d252c51a3bb42fc7d8f182594"
      "000000000000000000000000000000000982d17b17404ac198a0ff5f2dffa56a"
      "328d95ec4732d9cca9da420ec7cf716dc63d56d0f5179a8b1ec71fe0328fe882"
      "00000000000000000000000000000000147c92cb19e43943bb20c5360a6c4347"
      "411eb8ffb3d6f19cc428a8dc0cb3fd1eb3ad02b1c21e21c78f65a7691ee63de9"
      "0000000000000000000000000000000016cae74dc6523e5273dbd2d9d25c53f1"
      "e2c453e6d9ba3f605021cfb514fa0bdf721b05f2200f32591d733e739fabf438"
      "000000000000000000000000000000001405df65fb71b738510b3a2fc31c33ef"
      "3d884ccc84efb1017341a368bf40727b7ad8cdc8e3fd6b0eb94102488c5cb770"
      "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
      "c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
      "0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
      "596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
      "000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bc"
      "b679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa"
      "0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d"
      "993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed",
      "0000000000000000000000000000000000000000000000000000000000000001" },
    { 0x0f,
      "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f"
      "c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
      "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
      "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
      "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
      "c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
      "0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
      "596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
      "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a"
      "adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
      "000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99"
      "cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
      "0000000000000000000000000000000000000000000000000000000000000000" },
    { 0x11,
      "0000000000000000000000000000000007355d25caf6e7f2f0cb2812ca0e513b"
      "d026ed09dda65b177500fa31714e09ea0ded3a078b526bed3307f804d4b93b04"
      "0000000000000000000000000000000002829ce3c021339ccb5caf3e187f6370"
      "e1e2a311dec9b75363117063ab2015603ff52c3d3b98f19c2f65575e99e8b78c",
      "0000000000000000000000000000000000e7f4568a82b4b7dc1f14c6aaa055ed"
      "f51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb7"
      "00000000000000000000000000000000126b855e9e69b1f691f816e48ac69776"
      "64d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b"
      "000000000000000000000000000000000caead0fd7b6176c01436833c79d305c"
      "78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42"
      "000000000000000000000000000000001498aadcf7ae2b345243e281ae076df6"
      "de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d" },
};

/* hex string -> fresh buffer; NULL on malformed input or allocation */
static uint8_t *kat_hex(const char *hex, size_t *n)
{
    size_t hl = strlen(hex);
    uint8_t *b;
    if (hl % 2 != 0) return NULL;
    *n = hl / 2;
    b = malloc(*n ? *n : 1);
    if (!b) return NULL;
    for (size_t i = 0; i < *n; i++) {
        int hi = hex_nibble((uint8_t)hex[2 * i]);
        int lo = hex_nibble((uint8_t)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(b);
            return NULL;
        }
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    return b;
}

/* What a failed known-answer vector of precompile 0x01..0x11 means: the
 * capability a node lacks. Index = address. */
static const char *const PC_KAT_WHAT[0x12] = {
    NULL,
    "precompile 0x01 ecrecover (libsecp256k1, recovery module)",
    "precompile 0x02 sha256 (blst SHA-256)",
    "precompile 0x03 ripemd160 (trezor-crypto RIPEMD-160)",
    "precompile 0x04 identity",
    "precompile 0x05 modexp (GMP)",
    "precompile 0x06 bn254 add (mcl)",
    "precompile 0x07 bn254 mul (mcl)",
    "precompile 0x08 bn254 pairing (mcl)",
    "precompile 0x09 blake2f",
    "precompile 0x0a point evaluation (c-kzg-4844)",
    "precompile 0x0b bls12-381 G1 add (blst)",
    "precompile 0x0c bls12-381 G1 MSM (blst)",
    "precompile 0x0d bls12-381 G2 add (blst)",
    "precompile 0x0e bls12-381 G2 MSM (blst)",
    "precompile 0x0f bls12-381 pairing (blst)",
    "precompile 0x10 bls12-381 map to G1 (blst)",
    "precompile 0x11 bls12-381 map to G2 (blst)",
};

int evm_precompile_selftest_report(const char **failed)
{
    int rc = 0;
    const char *what = NULL;
    if (!bn_ready()) {
        /* mcl src/fp.cpp Op::init: x86-64 needs AVX + BMI2 + ADX */
        what = "bn254 / alt_bn128 (mcl; on x86-64 the CPU must have AVX, "
               "BMI2 and ADX) for precompiles 0x06-0x08";
        rc = EVM_FAULT;
    } else if (!kzg_ready()) {
        what = "the KZG trusted setup (c-kzg-4844, precompile 0x0a)";
        rc = EVM_FAULT;
    }
    for (size_t k = 0; k < sizeof(PC_KATS) / sizeof(PC_KATS[0]) && rc == 0; k++) {
        size_t in_len = 0, want_len = 0, out_len = 0;
        uint8_t *in = kat_hex(PC_KATS[k].in, &in_len);
        uint8_t *want = kat_hex(PC_KATS[k].out, &want_len);
        uint8_t *out = NULL;
        uint64_t gas = 10000000u;
        evm_pc_result_t res = EVM_PC_INVALID;
        evm_addr a;
        memset(&a, 0, sizeof(a));
        a.b[31] = PC_KATS[k].addr;
        if (!in || !want ||
            evm_precompile_run(&a, in, in_len, &gas, &res, &out, &out_len) != 0 ||
            res != EVM_PC_OK || out_len != want_len ||
            (want_len != 0 && memcmp(out, want, want_len) != 0)) {
            rc = EVM_FAULT;
            what = (!in || !want) ? "memory for the known-answer vectors"
                                  : PC_KAT_WHAT[PC_KATS[k].addr];
        }
        free(in);
        free(want);
        free(out);
    }
    if (failed) *failed = what;
    return rc;
}

int evm_precompile_selftest(void)
{
    return evm_precompile_selftest_report(NULL);
}
