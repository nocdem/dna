/* Kyber round-3 (pre-FIPS-203) — LEGACY. See kyber_r3_legacy.h for what this
 * is and why it exists. Every function body below is a verbatim transplant
 * of commit c86cad72's kem/kem.c + kyber_deterministic.c, re-hosted on the
 * new std@d5b791c K-PKE primitives (gen_matrix, poly_getnoise_eta1,
 * polyvec_ntt/basemul_acc_montgomery/add/reduce/tobytes, indcpa_enc,
 * indcpa_dec, verify, cmov) — no poly/ntt/indcpa code is duplicated here.
 * The two OLD divergences from those new primitives' FO wrapper (round-3's
 * G(d) vs ML-KEM's G(d||k); round-3's SHAKE256(K'||H(c)) final KDF, absent
 * from ML-KEM) are reproduced exactly below. */

#include "crypto/enc/kyber_r3_legacy.h"

#include "crypto/enc/kem/params.h"
#include "crypto/enc/kem/indcpa.h"
#include "crypto/enc/kem/poly.h"
#include "crypto/enc/kem/polyvec.h"
#include "crypto/enc/kem/symmetric.h"   /* hash_h = sha3_256, hash_g = sha3_512 */
#include "crypto/enc/kem/verify.h"      /* verify, cmov */
#include "crypto/enc/kem/fips202.h"     /* namespaced shake256, for r3_kdf */
#include "crypto/utils/qgp_random.h"    /* qgp_randombytes */

#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#if KYBER_PUBLICKEYBYTES != KYBER_R3_PUBLICKEYBYTES || \
    KYBER_SECRETKEYBYTES != KYBER_R3_SECRETKEYBYTES || \
    KYBER_CIPHERTEXTBYTES != KYBER_R3_CIPHERTEXTBYTES || \
    KYBER_SSBYTES != KYBER_R3_SHAREDSECRETBYTES
#error "kem/params.h sizes no longer match kyber_r3_legacy.h — KYBER_K changed?"
#endif

/* Round-3's final shared-secret KDF: ss = SHAKE256(kr, 2*KYBER_SYMBYTES).
 * FIPS 203 removed this step (the shared secret is G's output directly);
 * upstream symmetric.h therefore no longer defines `kdf` — this is that
 * missing round-3-only definition, old symmetric.h:38. */
#define r3_kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SYMBYTES, IN, INBYTES)

/*
 * r3_indcpa_keypair_derand — old kyber_deterministic.c indcpa_keypair_derand
 * (:61-97), unchanged: G is fed exactly KYBER_SYMBYTES (32) bytes of seed,
 * with NO trailing k byte (that k byte, added at kem/indcpa.c:217-218 in the
 * new ML-KEM indcpa_keypair_derand, is FIPS 203's domain separation and is
 * exactly what round-3 lacks — F1 in the migration design doc).
 */
static void r3_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                     uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                     const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);
    hash_g(buf, buf, KYBER_SYMBYTES);      /* round-3: G(d) — 32 bytes, no k byte */

    gen_matrix(a, publicseed, 0);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    /* matrix-vector multiplication */
    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    polyvec_tobytes(sk, &skpv);
    /* pack_pk: polyvec bytes || publicseed (old kem/indcpa.c pack_pk, static
     * there — reproduced here since it is not exported) */
    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);
}

int kyber_r3_keypair(uint8_t pk[KYBER_R3_PUBLICKEYBYTES],
                     uint8_t sk[KYBER_R3_SECRETKEYBYTES])
{
    uint8_t d[KYBER_SYMBYTES];

    if (!pk || !sk)
        return -1;

    /* old kem.c crypto_kem_keypair -> indcpa_keypair drew its own random d
     * internally; here that draw is explicit, feeding the same derand core. */
    if (qgp_randombytes(d, KYBER_SYMBYTES) != 0)
        return -1;
    r3_indcpa_keypair_derand(pk, sk, d);

    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject — independent random draw,
     * old kem.c:34 (NOT derived from d, unlike FIPS 203's coupled (d,z)). */
    if (qgp_randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES) != 0)
        return -1;
    return 0;
}

int kyber_r3_keypair_derand(uint8_t pk[KYBER_R3_PUBLICKEYBYTES],
                            uint8_t sk[KYBER_R3_SECRETKEYBYTES],
                            const uint8_t seed[32])
{
    if (!pk || !sk || !seed)
        return -1;

    r3_indcpa_keypair_derand(pk, sk, seed);

    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* old kyber_deterministic.c crypto_kem_keypair_derand :125-128:
     * z = SHA3-256(seed), i.e. hash_h(seed) — this repo's own choice, not a
     * round-3 spec requirement (round-3 leaves z's derivation to the caller;
     * FIPS 203 instead takes an independent 32-byte z as half of coins). */
    hash_h(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, seed, KYBER_SYMBYTES);
    return 0;
}

int kyber_r3_encapsulate(uint8_t ct[KYBER_R3_CIPHERTEXTBYTES],
                         uint8_t ss[KYBER_R3_SHAREDSECRETBYTES],
                         const uint8_t pk[KYBER_R3_PUBLICKEYBYTES])
{
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];  /* key, coins */

    if (!ct || !ss || !pk)
        return -1;

    if (qgp_randombytes(buf, KYBER_SYMBYTES) != 0)
        return -1;
    /* Don't release system RNG output — old kem.c:63 (F2: round-3 pre-hashes
     * the encaps randomness; FIPS 203 uses m directly, App. C.1 point 3). */
    hash_h(buf, buf, KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    /* F3: round-3's final KDF — FIPS 203 has no equivalent step (App. C.1
     * point 2: the shared secret is G's first half, K, directly). */
    r3_kdf(ss, kr, 2 * KYBER_SYMBYTES);
    return 0;
}

int kyber_r3_decapsulate(uint8_t ss[KYBER_R3_SHAREDSECRETBYTES],
                         const uint8_t ct[KYBER_R3_CIPHERTEXTBYTES],
                         const uint8_t sk[KYBER_R3_SECRETKEYBYTES])
{
    size_t i;
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    if (!ss || !ct || !sk)
        return -1;

    indcpa_dec(buf, ct, sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    for (i = 0; i < KYBER_SYMBYTES; i++)
        buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

    fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

    /* Overwrite pre-k with z on re-encryption failure (implicit rejection) */
    cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, (uint8_t)fail);

    /* F4: round-3's rejection KDF is the SAME SHAKE256(kr,64) as the success
     * path (kr already holds z||H(c) on failure thanks to cmov above) — NOT
     * FIPS 203's separate J(z||c) function (kem/symmetric.h rkprf). */
    r3_kdf(ss, kr, 2 * KYBER_SYMBYTES);
    return 0;
}
