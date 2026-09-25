/* ML-KEM-1024 (FIPS 203) — thin wrapper over the pq-crystals/kyber
 * `standard` @ d5b791c reference (shared/crypto/enc/kem/), plus the two
 * input checks FIPS 203 requires that no reference implementation
 * performs (§7.2, §7.3 — see qgp_mlkem.h and the design doc §4.5). No
 * K-PKE / FO-wrapper logic is written here — that is 100% upstream kem.c.
 */

#include "crypto/enc/qgp_mlkem.h"

#include "crypto/enc/kem/kem.h"
#include "crypto/enc/kem/params.h"
#include "crypto/enc/kem/fips202.h"   /* namespaced sha3_256 */
#include "crypto/enc/kem/verify.h"    /* verify — constant-time compare */
#include "crypto/utils/qgp_random.h"    /* qgp_randombytes, return checked (see below) */
#include "crypto/utils/qgp_platform.h"  /* qgp_secure_memzero */

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Compile-time cross-check: this wrapper's fixed sizes must match the
 * vendored ML-KEM-1024 (KYBER_K=4) parameter set it wraps. */
#if QGP_MLKEM1024_PUBLICKEYBYTES != KYBER_PUBLICKEYBYTES || \
    QGP_MLKEM1024_SECRETKEYBYTES != KYBER_SECRETKEYBYTES || \
    QGP_MLKEM1024_CIPHERTEXTBYTES != KYBER_CIPHERTEXTBYTES || \
    QGP_MLKEM1024_SHAREDSECRET_BYTES != KYBER_SSBYTES
#error "qgp_mlkem.h sizes no longer match kem/params.h — KYBER_K changed?"
#endif

/* FIPS 203 §7.3 hash-check offsets, k=4 (fips203.txt:2080-2100):
 * 384k = 1536 (start of the embedded ek/pk copy inside dk)
 * 768k+32 = 3104 (start of the stored H(ek))
 * 768k+64 = 3136 (== KYBER_SECRETKEYBYTES, end of dk) */
#define MLKEM_DK_HCHECK_OFFSET 1536
#define MLKEM_DK_HASH_OFFSET   3104

int qgp_mlkem1024_keypair(uint8_t *ek, uint8_t *dk)
{
    /* Upstream crypto_kem_keypair (kem.c:50-57) draws its own coins via
     * randombytes(...) and does NOT check its return value. In this tree
     * randombytes == qgp_randombytes (kem/randombytes.h), which CAN fail
     * (qgp_random.c:28-34) — so that path is taken here explicitly, with
     * the return value checked, rather than inside the unmodified upstream
     * function. */
    uint8_t coins[QGP_MLKEM1024_COINS_BYTES];
    int rc;

    if (!ek || !dk)
        return -1;
    if (qgp_randombytes(coins, sizeof(coins)) != 0)
        return -1;
    rc = crypto_kem_keypair_derand(ek, dk, coins);
    qgp_secure_memzero(coins, sizeof(coins));
    return rc;
}

int qgp_mlkem1024_keypair_derand(uint8_t *ek, uint8_t *dk, const uint8_t *coins)
{
    if (!ek || !dk || !coins)
        return -1;
    return crypto_kem_keypair_derand(ek, dk, coins);
}

int qgp_mlkem1024_ek_check(const uint8_t *ek)
{
    /* FIPS 203 §7.2 (fips203.txt:2035-2050): test <- ByteEncode12(
     * ByteDecode12(ek[0:384k])); reject if test != ek[0:384k]. ByteDecode12
     * reduces mod q (Alg 6 step 3); upstream poly_frombytes does NOT, so
     * that round-trip is a no-op and cannot be used here (F5 in the
     * migration design doc). Implemented instead as the equivalent
     * per-coefficient check: reject if any of the 1024 twelve-bit
     * coefficients packed in ek[0:KYBER_POLYVECBYTES] is >= KYBER_Q,
     * matching poly_frombytes's own bit layout (kem/poly.c
     * poly_frombytes): c0 = a0 | (a1&0x0F)<<8, c1 = a1>>4 | a2<<4.
     * No early exit (not required for a public key) — every group is
     * checked and the failures are OR'd together. */
    unsigned int g;
    uint32_t bad = 0;

    if (!ek)
        return -1;

    for (g = 0; g < KYBER_POLYVECBYTES / 3; g++) {
        const uint8_t a0 = ek[3 * g + 0];
        const uint8_t a1 = ek[3 * g + 1];
        const uint8_t a2 = ek[3 * g + 2];
        uint16_t c0 = ((uint16_t)a0 | ((uint16_t)a1 << 8)) & 0xFFF;
        uint16_t c1 = ((uint16_t)(a1 >> 4) | ((uint16_t)a2 << 4)) & 0xFFF;
        bad |= (uint32_t)(c0 >= KYBER_Q);
        bad |= (uint32_t)(c1 >= KYBER_Q);
    }

    return bad ? -1 : 0;
}

int qgp_mlkem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *ek)
{
    /* Same reasoning as qgp_mlkem1024_keypair above: upstream
     * crypto_kem_enc (kem.c:113-121) draws its own coins via
     * randombytes(...) unchecked; drawn here explicitly instead, checked. */
    uint8_t m[32];
    int rc;

    if (!ct || !ss || !ek)
        return -1;
    if (qgp_mlkem1024_ek_check(ek) != 0)
        return -1;
    if (qgp_randombytes(m, sizeof(m)) != 0)
        return -1;
    rc = crypto_kem_enc_derand(ct, ss, ek, m);
    qgp_secure_memzero(m, sizeof(m));
    return rc;
}

int qgp_mlkem1024_encapsulate_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                     const uint8_t *m)
{
    if (!ct || !ss || !ek || !m)
        return -1;
    if (qgp_mlkem1024_ek_check(ek) != 0)
        return -1;
    return crypto_kem_enc_derand(ct, ss, ek, m);
}

int qgp_mlkem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *dk)
{
    uint8_t test_hash[32];

    if (!ss || !ct || !dk)
        return -1;

    /* FIPS 203 §7.3 (fips203.txt:2080-2100): ct/dk length are by contract
     * (fixed-size API). Hash check, performed on EVERY call
     * (fips203.txt:2099-2100): test <- H(dk[384k:768k+32]); reject if
     * test != dk[768k+32:768k+64]. Constant-time compare, no decapsulation
     * work done before this check passes. */
    sha3_256(test_hash, dk + MLKEM_DK_HCHECK_OFFSET,
             MLKEM_DK_HASH_OFFSET - MLKEM_DK_HCHECK_OFFSET);
    if (verify(test_hash, dk + MLKEM_DK_HASH_OFFSET, 32) != 0)
        return -1;

    return crypto_kem_dec(ss, ct, dk);
}
