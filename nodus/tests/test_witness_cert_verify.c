/**
 * Nodus — Phase 7.5 / Task 7.5.5 — sync cert sign/verify roundtrip tests
 *
 * Generates a Dilithium5 keypair, builds a roster of one, signs a cert
 * preimage and runs it through nodus_witness_verify_sync_certs under
 * various tamper conditions. Catches the security regressions called
 * out in the design doc:
 *   - test_precommit_cert_sign_verify_roundtrip — happy path
 *   - test_sync_cert_forged_rejected             — random sig
 *   - test_sync_cert_tampered_block_hash_rejected — wrong bh on verify
 *   - test_sync_cert_wrong_chain_id              — wrong cid on verify
 *
 * The bft_view_change_cert_signing and sync_quorum_fault_log scenarios
 * from the plan need a full multi-witness BFT fixture and the Phase 11
 * sync receiver; they ship with Phase 11.
 */

#include "witness/nodus_witness_cert.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Fixture: one witness, one cert, signed over (bh, vid, height, cid). */
typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[NODUS_SK_BYTES];
    uint8_t voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t block_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t chain_id[32];
    uint64_t height;
    nodus_witness_roster_t roster;
    nodus_t3_sync_cert_t cert;
} fixture_t;

static int build_fixture(fixture_t *f) {
    memset(f, 0, sizeof(*f));
    if (qgp_dsa87_keypair(f->pk, f->sk) != 0) return -1;

    /* voter_id mimics nodus_witness ID derivation — for the test it's
     * just an arbitrary 32 bytes that the roster lookup will match. */
    for (int i = 0; i < NODUS_T3_WITNESS_ID_LEN; i++)
        f->voter_id[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++)
        f->block_hash[i] = (uint8_t)(0x80 + i);
    for (int i = 0; i < 32; i++)
        f->chain_id[i] = (uint8_t)(0xC0 + i);
    f->height = 42;

    f->roster.n_witnesses = 1;
    memcpy(f->roster.witnesses[0].witness_id, f->voter_id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(f->roster.witnesses[0].pubkey, f->pk, NODUS_PK_BYTES);

    /* Sign cert preimage */
    uint8_t preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    if (nodus_witness_compute_cert_preimage(f->block_hash, f->voter_id,
                                              f->height, f->chain_id,
                                              preimage) != 0)
        return -1;

    size_t siglen = 0;
    if (qgp_dsa87_sign(f->cert.signature, &siglen,
                        preimage, sizeof(preimage), f->sk) != 0)
        return -1;
    if (siglen < NODUS_SIG_BYTES)
        memset(f->cert.signature + siglen, 0, NODUS_SIG_BYTES - siglen);
    memcpy(f->cert.voter_id, f->voter_id, NODUS_T3_WITNESS_ID_LEN);
    return 0;
}

static void test_sign_verify_roundtrip(void) {
    TEST("precommit cert sign/verify roundtrip");
    fixture_t f;
    if (build_fixture(&f) != 0) { FAIL("fixture"); return; }

    int verified = nodus_witness_verify_sync_certs(f.block_hash, f.height,
                                                     f.chain_id, &f.roster,
                                                     &f.cert, 1, 1);
    if (verified != 1) { FAIL("expected 1 verified cert"); return; }
    PASS();
}

static void test_forged_cert_rejected(void) {
    TEST("forged cert (random sig) rejected");
    fixture_t f;
    if (build_fixture(&f) != 0) { FAIL("fixture"); return; }

    /* Replace signature with random garbage */
    for (int i = 0; i < NODUS_SIG_BYTES; i++)
        f.cert.signature[i] = (uint8_t)(i & 0xFF);

    int verified = nodus_witness_verify_sync_certs(f.block_hash, f.height,
                                                     f.chain_id, &f.roster,
                                                     &f.cert, 1, 1);
    if (verified != -1) { FAIL("forged cert accepted"); return; }
    PASS();
}

static void test_tampered_block_hash_rejected(void) {
    TEST("verify against different block_hash rejected");
    fixture_t f;
    if (build_fixture(&f) != 0) { FAIL("fixture"); return; }

    uint8_t tampered_bh[NODUS_T3_TX_HASH_LEN];
    memcpy(tampered_bh, f.block_hash, NODUS_T3_TX_HASH_LEN);
    tampered_bh[0] ^= 0x01;  /* flip one bit */

    int verified = nodus_witness_verify_sync_certs(tampered_bh, f.height,
                                                     f.chain_id, &f.roster,
                                                     &f.cert, 1, 1);
    if (verified != -1) { FAIL("tampered block_hash accepted"); return; }
    PASS();
}

static void test_wrong_chain_id_rejected(void) {
    TEST("cert from wrong chain rejected");
    fixture_t f;
    if (build_fixture(&f) != 0) { FAIL("fixture"); return; }

    uint8_t other_chain[32];
    memset(other_chain, 0xEE, 32);

    int verified = nodus_witness_verify_sync_certs(f.block_hash, f.height,
                                                     other_chain, &f.roster,
                                                     &f.cert, 1, 1);
    if (verified != -1) { FAIL("cross-chain cert accepted"); return; }
    PASS();
}

static void test_unknown_voter_dropped(void) {
    TEST("cert from unknown voter silently dropped");
    fixture_t f;
    if (build_fixture(&f) != 0) { FAIL("fixture"); return; }

    /* Empty roster — voter_id won't resolve */
    nodus_witness_roster_t empty_roster;
    memset(&empty_roster, 0, sizeof(empty_roster));

    int verified = nodus_witness_verify_sync_certs(f.block_hash, f.height,
                                                     f.chain_id, &empty_roster,
                                                     &f.cert, 1, 1);
    if (verified != -1) { FAIL("unknown voter contributed to quorum"); return; }
    PASS();
}

int main(void) {
    printf("Witness cert sign/verify tests\n");
    printf("==============================\n");

    test_sign_verify_roundtrip();
    test_forged_cert_rejected();
    test_tampered_block_hash_rejected();
    test_wrong_chain_id_rejected();
    test_unknown_voter_dropped();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
