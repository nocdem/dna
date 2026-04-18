/**
 * Hard-Fork v1 Stage C -- vote primitive tests.
 *
 * Pure-function primitives (no network, no witness context):
 *   - nodus_chain_config_compute_digest
 *   - nodus_chain_config_sign_vote
 *   - nodus_chain_config_verify_vote
 *   - nodus_chain_config_derive_witness_id
 *
 * Round-trip (sign -> verify) with real Dilithium5 key pairs, plus the
 * critical tamper-rejection cases (wrong pubkey, flipped digest bit,
 * truncated signature).
 */

#include "nodus/nodus_chain_config.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

/* Fresh Dilithium5 key pair. */
static void gen_key(uint8_t pk[NODUS_CC_PUBKEY_SIZE],
                     uint8_t sk[NODUS_CC_SECKEY_SIZE]) {
    CHECK(qgp_dsa87_keypair(pk, sk) == 0);
}

int main(void) {
    uint8_t chain_id[32];
    memset(chain_id, 0xC1, 32);

    /* Test 1: digest is deterministic + sensitive to every field. */
    {
        uint8_t d1[NODUS_CC_DIGEST_SIZE], d2[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain_id, 1, 5, 1000,
                                                 0xDEADULL, 800, 1100, d1) == 0);
        CHECK(nodus_chain_config_compute_digest(chain_id, 1, 5, 1000,
                                                 0xDEADULL, 800, 1100, d2) == 0);
        CHECK(memcmp(d1, d2, NODUS_CC_DIGEST_SIZE) == 0);

        /* Change param_id -> different digest. */
        uint8_t d3[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain_id, 2, 5, 1000,
                                                 0xDEADULL, 800, 1100, d3) == 0);
        CHECK(memcmp(d1, d3, NODUS_CC_DIGEST_SIZE) != 0);

        /* Change chain_id -> different digest. */
        uint8_t chain2[32]; memset(chain2, 0xC2, 32);
        uint8_t d4[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain2, 1, 5, 1000,
                                                 0xDEADULL, 800, 1100, d4) == 0);
        CHECK(memcmp(d1, d4, NODUS_CC_DIGEST_SIZE) != 0);

        /* Change nonce -> different digest (even with same other fields). */
        uint8_t d5[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain_id, 1, 5, 1000,
                                                 0xBEEFULL, 800, 1100, d5) == 0);
        CHECK(memcmp(d1, d5, NODUS_CC_DIGEST_SIZE) != 0);

        /* NULL args rejected. */
        CHECK(nodus_chain_config_compute_digest(NULL, 1, 5, 1000,
                                                 0, 800, 1100, d1) == -1);
        CHECK(nodus_chain_config_compute_digest(chain_id, 1, 5, 1000,
                                                 0, 800, 1100, NULL) == -1);
    }

    /* Test 2: sign + verify round-trip with real Dilithium5 key. */
    {
        uint8_t pk[NODUS_CC_PUBKEY_SIZE], sk[NODUS_CC_SECKEY_SIZE];
        gen_key(pk, sk);

        uint8_t digest[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain_id, 1, 5, 1000,
                                                 0xABCDULL, 800, 1100, digest) == 0);

        uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
        uint8_t sig[NODUS_CC_SIG_SIZE];
        CHECK(nodus_chain_config_sign_vote(pk, sk, digest, wid, sig) == 0);

        /* witness_id matches derive_witness_id(pk). */
        uint8_t wid_expected[NODUS_CC_WITNESS_ID_SIZE];
        CHECK(nodus_chain_config_derive_witness_id(pk, wid_expected) == 0);
        CHECK(memcmp(wid, wid_expected, NODUS_CC_WITNESS_ID_SIZE) == 0);

        /* Verify with the right pubkey -> success. */
        CHECK(nodus_chain_config_verify_vote(pk, digest, sig) == 0);
    }

    /* Test 3: wrong-pubkey rejected. */
    {
        uint8_t pk_a[NODUS_CC_PUBKEY_SIZE], sk_a[NODUS_CC_SECKEY_SIZE];
        uint8_t pk_b[NODUS_CC_PUBKEY_SIZE], sk_b[NODUS_CC_SECKEY_SIZE];
        gen_key(pk_a, sk_a);
        gen_key(pk_b, sk_b);

        uint8_t digest[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain_id, 2, 5, 2000,
                                                 0x1234ULL, 1500, 2100, digest) == 0);

        uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
        uint8_t sig[NODUS_CC_SIG_SIZE];
        CHECK(nodus_chain_config_sign_vote(pk_a, sk_a, digest, wid, sig) == 0);

        /* Verify under pk_b fails. */
        CHECK(nodus_chain_config_verify_vote(pk_b, digest, sig) == -1);
        /* Verify under pk_a succeeds. */
        CHECK(nodus_chain_config_verify_vote(pk_a, digest, sig) == 0);
    }

    /* Test 4: tampered digest rejected. */
    {
        uint8_t pk[NODUS_CC_PUBKEY_SIZE], sk[NODUS_CC_SECKEY_SIZE];
        gen_key(pk, sk);
        uint8_t digest[NODUS_CC_DIGEST_SIZE];
        CHECK(nodus_chain_config_compute_digest(chain_id, 3, 42, 3000,
                                                 0x5555ULL, 2500, 3100, digest) == 0);
        uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
        uint8_t sig[NODUS_CC_SIG_SIZE];
        CHECK(nodus_chain_config_sign_vote(pk, sk, digest, wid, sig) == 0);

        /* Flip one bit in digest -> verify rejects. */
        uint8_t bad_digest[NODUS_CC_DIGEST_SIZE];
        memcpy(bad_digest, digest, NODUS_CC_DIGEST_SIZE);
        bad_digest[17] ^= 0x01;
        CHECK(nodus_chain_config_verify_vote(pk, bad_digest, sig) == -1);

        /* Flip one bit in signature -> verify rejects. */
        uint8_t bad_sig[NODUS_CC_SIG_SIZE];
        memcpy(bad_sig, sig, NODUS_CC_SIG_SIZE);
        bad_sig[100] ^= 0x80;
        CHECK(nodus_chain_config_verify_vote(pk, digest, bad_sig) == -1);

        /* Untampered still passes. */
        CHECK(nodus_chain_config_verify_vote(pk, digest, sig) == 0);
    }

    /* Test 5: NULL args rejected across the board. */
    {
        uint8_t pk[NODUS_CC_PUBKEY_SIZE], sk[NODUS_CC_SECKEY_SIZE];
        uint8_t digest[NODUS_CC_DIGEST_SIZE] = {0};
        uint8_t wid[NODUS_CC_WITNESS_ID_SIZE];
        uint8_t sig[NODUS_CC_SIG_SIZE];
        CHECK(nodus_chain_config_sign_vote(NULL, sk, digest, wid, sig) == -1);
        CHECK(nodus_chain_config_sign_vote(pk, NULL, digest, wid, sig) == -1);
        CHECK(nodus_chain_config_sign_vote(pk, sk, NULL, wid, sig) == -1);
        CHECK(nodus_chain_config_sign_vote(pk, sk, digest, NULL, sig) == -1);
        CHECK(nodus_chain_config_sign_vote(pk, sk, digest, wid, NULL) == -1);

        CHECK(nodus_chain_config_verify_vote(NULL, digest, sig) == -1);
        CHECK(nodus_chain_config_verify_vote(pk, NULL, sig) == -1);
        CHECK(nodus_chain_config_verify_vote(pk, digest, NULL) == -1);

        CHECK(nodus_chain_config_derive_witness_id(NULL, wid) == -1);
        CHECK(nodus_chain_config_derive_witness_id(pk, NULL) == -1);
    }

    /* Test 6: witness_id collision resistance.
     * Two different pubkeys -> two different witness_ids. */
    {
        uint8_t pk_a[NODUS_CC_PUBKEY_SIZE], sk_a[NODUS_CC_SECKEY_SIZE];
        uint8_t pk_b[NODUS_CC_PUBKEY_SIZE], sk_b[NODUS_CC_SECKEY_SIZE];
        gen_key(pk_a, sk_a);
        gen_key(pk_b, sk_b);
        uint8_t wid_a[NODUS_CC_WITNESS_ID_SIZE], wid_b[NODUS_CC_WITNESS_ID_SIZE];
        CHECK(nodus_chain_config_derive_witness_id(pk_a, wid_a) == 0);
        CHECK(nodus_chain_config_derive_witness_id(pk_b, wid_b) == 0);
        CHECK(memcmp(wid_a, wid_b, NODUS_CC_WITNESS_ID_SIZE) != 0);
    }

    printf("test_chain_config_votes: ALL CHECKS PASSED\n");
    return 0;
}
