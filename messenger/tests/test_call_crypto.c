/*
 * test_call_crypto.c — PQ VoIP Faz A call-key agreement (dna_call_derive_key).
 *
 * Validates K_call = HKDF-SHA3-256(salt=caller_fp[:32]||callee_fp[:32],
 *   ikm=ss_eph||ss_static, info="dna-call-v1"||call_id||SHA3-512(eph_pk)[:32]).
 * Design: docs/plans/2026-07-12-pq-voip-faz-a-signaling-design.md §4.3.
 *
 * Tests are spec-conformance (independently reconstruct the construction with
 * the audited hkdf_sha3_256 primitive) + forward-secrecy/pair-binding property
 * checks + a full Kyber1024 encapsulate/decapsulate round-trip proving both
 * endpoints derive an identical key (determinism invariant §1.1.2).
 */

#include "dna_call_crypto.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/enc/qgp_kyber.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

/* Independently build the spec inputs and compute the expected K_call using the
 * audited HKDF directly — NOT by calling dna_call_derive_key (non-circular). */
static void expected_key(const uint8_t ss_eph[32], const uint8_t ss_static[32],
                         const uint8_t caller_fp[64], const uint8_t callee_fp[64],
                         const uint8_t call_id[16], const uint8_t *eph_pk,
                         uint8_t out[32])
{
    uint8_t salt[64];
    memcpy(salt, caller_fp, 32);
    memcpy(salt + 32, callee_fp, 32);

    uint8_t ikm[64];
    memcpy(ikm, ss_eph, 32);
    memcpy(ikm + 32, ss_static, 32);

    uint8_t info[59];
    memcpy(info, "dna-call-v1", 11);
    memcpy(info + 11, call_id, 16);
    uint8_t h[64];
    qgp_sha3_512(eph_pk, DNA_CALL_KYBER_PK_LEN, h);
    memcpy(info + 27, h, 32);

    hkdf_sha3_256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), out, 32);
}

static void test_spec_conformance(void)
{
    printf("test_spec_conformance\n");
    uint8_t ss_eph[32], ss_static[32], caller_fp[64], callee_fp[64], call_id[16];
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(ss_eph, 0x01, 32);
    memset(ss_static, 0x02, 32);
    memset(caller_fp, 0x03, 64);
    memset(callee_fp, 0x04, 64);
    memset(call_id, 0x05, 16);
    memset(eph_pk, 0x11, sizeof(eph_pk));

    uint8_t exp[32], got[32];
    expected_key(ss_eph, ss_static, caller_fp, callee_fp, call_id, eph_pk, exp);
    int rc = dna_call_derive_key(ss_eph, ss_static, caller_fp, callee_fp,
                                 call_id, eph_pk, got);
    CHECK(rc == DNA_CALL_OK, "returns OK");
    CHECK(memcmp(exp, got, 32) == 0, "K_call matches independent HKDF-SHA3-256 construction");
}

static void test_deterministic(void)
{
    printf("test_deterministic\n");
    uint8_t ss_eph[32], ss_static[32], caller_fp[64], callee_fp[64], call_id[16];
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(ss_eph, 0x21, 32); memset(ss_static, 0x22, 32);
    memset(caller_fp, 0x23, 64); memset(callee_fp, 0x24, 64);
    memset(call_id, 0x25, 16); memset(eph_pk, 0x26, sizeof(eph_pk));

    uint8_t a[32], b[32];
    dna_call_derive_key(ss_eph, ss_static, caller_fp, callee_fp, call_id, eph_pk, a);
    dna_call_derive_key(ss_eph, ss_static, caller_fp, callee_fp, call_id, eph_pk, b);
    CHECK(memcmp(a, b, 32) == 0, "same inputs -> identical key");
}

static void test_forward_secrecy_property(void)
{
    printf("test_forward_secrecy_property\n");
    /* Static secret alone must NOT reproduce the key: flipping only ss_eph
     * yields a different K_call, so a stolen static key cannot recover it. */
    uint8_t ss_eph[32], ss_eph2[32], ss_static[32], caller_fp[64], callee_fp[64], call_id[16];
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(ss_eph, 0x31, 32); memset(ss_eph2, 0x99, 32);
    memset(ss_static, 0x32, 32);
    memset(caller_fp, 0x33, 64); memset(callee_fp, 0x34, 64);
    memset(call_id, 0x35, 16); memset(eph_pk, 0x36, sizeof(eph_pk));

    uint8_t k1[32], k2[32];
    dna_call_derive_key(ss_eph,  ss_static, caller_fp, callee_fp, call_id, eph_pk, k1);
    dna_call_derive_key(ss_eph2, ss_static, caller_fp, callee_fp, call_id, eph_pk, k2);
    CHECK(memcmp(k1, k2, 32) != 0, "different ephemeral secret -> different key (FS)");
}

static void test_pair_binding(void)
{
    printf("test_pair_binding\n");
    /* Swapping caller/callee fingerprints must change the key (F-BIND): the key
     * binds the intended pair, not just the caller. */
    uint8_t ss_eph[32], ss_static[32], fpA[64], fpB[64], call_id[16];
    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    memset(ss_eph, 0x41, 32); memset(ss_static, 0x42, 32);
    memset(fpA, 0x43, 64); memset(fpB, 0x44, 64);
    memset(call_id, 0x45, 16); memset(eph_pk, 0x46, sizeof(eph_pk));

    uint8_t k_ab[32], k_ba[32];
    dna_call_derive_key(ss_eph, ss_static, fpA, fpB, call_id, eph_pk, k_ab);
    dna_call_derive_key(ss_eph, ss_static, fpB, fpA, call_id, eph_pk, k_ba);
    CHECK(memcmp(k_ab, k_ba, 32) != 0, "swapping caller/callee fp -> different key");
}

static void test_kem_roundtrip(void)
{
    printf("test_kem_roundtrip\n");
    /* Full agreement: caller mints an ephemeral keypair and owns a static
     * keypair; callee encapsulates to BOTH pks; caller decapsulates BOTH cts.
     * Both sides derive K_call and must agree (determinism invariant §1.1.2). */
    uint8_t eph_pk[QGP_KEM1024_PUBLICKEYBYTES], eph_sk[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t stat_pk[QGP_KEM1024_PUBLICKEYBYTES], stat_sk[QGP_KEM1024_SECRETKEYBYTES];
    if (qgp_kem1024_keypair(eph_pk, eph_sk) != 0 ||
        qgp_kem1024_keypair(stat_pk, stat_sk) != 0) {
        CHECK(0, "keypair generation");
        return;
    }

    /* Callee side: encapsulate to each pk. */
    uint8_t eph_ct[QGP_KEM1024_CIPHERTEXTBYTES], ss_eph_callee[32];
    uint8_t stat_ct[QGP_KEM1024_CIPHERTEXTBYTES], ss_static_callee[32];
    CHECK(qgp_kem1024_encapsulate(eph_ct, ss_eph_callee, eph_pk) == 0, "encapsulate ephemeral");
    CHECK(qgp_kem1024_encapsulate(stat_ct, ss_static_callee, stat_pk) == 0, "encapsulate static");

    /* Caller side: decapsulate each ct with the matching secret key. */
    uint8_t ss_eph_caller[32], ss_static_caller[32];
    CHECK(qgp_kem1024_decapsulate(ss_eph_caller, eph_ct, eph_sk) == 0, "decapsulate ephemeral");
    CHECK(qgp_kem1024_decapsulate(ss_static_caller, stat_ct, stat_sk) == 0, "decapsulate static");

    uint8_t caller_fp[64], callee_fp[64], call_id[16];
    memset(caller_fp, 0x51, 64); memset(callee_fp, 0x52, 64); memset(call_id, 0x53, 16);

    uint8_t k_caller[32], k_callee[32];
    dna_call_derive_key(ss_eph_caller, ss_static_caller, caller_fp, callee_fp,
                        call_id, eph_pk, k_caller);
    dna_call_derive_key(ss_eph_callee, ss_static_callee, caller_fp, callee_fp,
                        call_id, eph_pk, k_callee);
    CHECK(memcmp(k_caller, k_callee, 32) == 0, "caller and callee derive identical K_call");
}

int main(void)
{
    printf("=== test_call_crypto (PQ VoIP Faz A) ===\n");
    test_spec_conformance();
    test_deterministic();
    test_forward_secrecy_property();
    test_pair_binding();
    test_kem_roundtrip();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
