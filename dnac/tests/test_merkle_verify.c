/**
 * @file test_merkle_verify.c
 * @brief Fixed-vector test for dnac_merkle_verify_proof.
 *
 * The vector in merkle_vector.inc was produced by the server-side
 * nodus_witness_merkle_build_proof (DELETED since the root-layout round,
 * K3 — the vector stays valid: it pins only the RFC 6962 verifier and
 * its direction convention, which did not change). If test_positive
 * fails, the direction convention between server and client has
 * drifted — debug dnac_merkle_verify_proof before any other work.
 *
 * Root-layout round K1 (2026-09-25): test_leaf_kat_340 pins the client
 * mirror dnac_utxo_compute_leaf_hash on the 340-byte preimage (the
 * 332-byte leaf ‖ unlock_block u64 LE) — the SAME fixture row and the
 * SAME literals as the node-side KAT in
 * nodus/tests/test_merkle_utxo_root.c, both taken from
 * shared/dnac/tests/ledger_roots_v2_accrual_oracle.py (same author,
 * same day: SELF-CONSISTENT, not an external audit), and re-derived here
 * from a hand-built preimage.
 */

/* Every check in this file (and the EVP calls in test_leaf_kat_340) lives
 * inside assert(). The dnac build is Release (-O3 -DNDEBUG, dnac/
 * CMakeLists.txt:13-14), where assert() compiles to nothing and every
 * failure would print FAIL and still exit 0. Force assertions on for this
 * test regardless of build type (root-layout round zk-auditor N1). */
#undef NDEBUG
#include "dnac/ledger.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "merkle_vector.inc"

static dnac_merkle_proof_t build_proof_from_vector(void) {
    dnac_merkle_proof_t p;
    memset(&p, 0, sizeof(p));

    memcpy(p.leaf_hash, MERKLE_VECTOR_LEAF, DNAC_MERKLE_ROOT_SIZE);
    memcpy(p.root, MERKLE_VECTOR_ROOT, DNAC_MERKLE_ROOT_SIZE);
    p.proof_length = MERKLE_VECTOR_PROOF_LENGTH;

    /* Convert flat server siblings + bitfield positions to dnac struct.
     * Vector bit layout (per Task 14): bit i = sibling direction at level i,
     * leaf-first. directions[i] == 1 → sibling LEFT. */
    for (int i = 0; i < MERKLE_VECTOR_PROOF_LENGTH; i++) {
        memcpy(p.siblings[i],
               MERKLE_VECTOR_SIBLINGS_FLAT + i * DNAC_MERKLE_ROOT_SIZE,
               DNAC_MERKLE_ROOT_SIZE);
        p.directions[i] = (MERKLE_VECTOR_POSITIONS >> i) & 1u;
    }
    return p;
}

static void test_positive(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    if (!dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_positive — DIRECTION CONVENTION DRIFT!\n");
        fprintf(stderr, "  leaf[0..8]:  ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p.leaf_hash[i]);
        fprintf(stderr, "\n  root[0..8]:  ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p.root[i]);
        fprintf(stderr, "\n  directions:  ");
        for (int i = 0; i < p.proof_length; i++) fprintf(stderr, "%d", p.directions[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Try flipping bit order: p.directions[i] = (POSITIONS >> (PROOF_LENGTH - 1 - i)) & 1\n");
        fprintf(stderr, "Or flip the inner_hash argument order in merkle_verify.c\n");
        assert(0);
    }
    printf("PASS test_positive\n");
}

static void test_tampered_sibling(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.siblings[0][0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_tampered_sibling — verifier accepted flipped sibling\n");
        assert(0);
    }
    printf("PASS test_tampered_sibling\n");
}

static void test_tampered_root(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.root[0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_tampered_root\n");
        assert(0);
    }
    printf("PASS test_tampered_root\n");
}

static void test_tampered_leaf(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.leaf_hash[0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_tampered_leaf\n");
        assert(0);
    }
    printf("PASS test_tampered_leaf\n");
}

static void test_null_proof(void) {
    if (dnac_merkle_verify_proof(NULL)) {
        fprintf(stderr, "FAIL test_null_proof\n");
        assert(0);
    }
    printf("PASS test_null_proof\n");
}

static void test_invalid_depth(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.proof_length = -1;
    if (dnac_merkle_verify_proof(&p)) { fprintf(stderr, "FAIL depth=-1\n"); assert(0); }

    p.proof_length = DNAC_MERKLE_MAX_DEPTH + 1;
    if (dnac_merkle_verify_proof(&p)) { fprintf(stderr, "FAIL depth>max\n"); assert(0); }

    printf("PASS test_invalid_depth\n");
}

static void test_single_leaf(void) {
    /* Single-leaf tree: the root IS the leaf-tagged hash of the
     * composite leaf digest. proof_length == 0, no siblings. */
    dnac_merkle_proof_t p;
    memset(&p, 0, sizeof(p));

    /* Arbitrary 64-byte composite leaf digest (not a real UTXO hash,
     * but the verifier doesn't care — it's just bytes). */
    for (int i = 0; i < DNAC_MERKLE_ROOT_SIZE; i++) {
        p.leaf_hash[i] = (uint8_t)(0x5a ^ i);
    }

    /* Hand-compute the expected root: SHA3-512(0x00 || leaf_hash). */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    assert(md);
    assert(EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1);
    uint8_t prefix = 0x00;
    assert(EVP_DigestUpdate(md, &prefix, 1) == 1);
    assert(EVP_DigestUpdate(md, p.leaf_hash, DNAC_MERKLE_ROOT_SIZE) == 1);
    unsigned int hash_len = 0;
    assert(EVP_DigestFinal_ex(md, p.root, &hash_len) == 1);
    assert(hash_len == DNAC_MERKLE_ROOT_SIZE);
    EVP_MD_CTX_free(md);

    p.proof_length = 0;

    if (!dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_single_leaf — verifier rejected valid single-leaf proof\n");
        assert(0);
    }

    /* Negative case: flip a bit in the root, expect rejection. */
    p.root[0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_single_leaf — verifier accepted tampered single-leaf root\n");
        assert(0);
    }

    printf("PASS test_single_leaf\n");
}

/* ── Root-layout round K1 — the 340-byte client leaf ─────────────────── */

static const char *KAT_UTXO_LEAF_UB =
    "ea456d4a87981fd399ebdf635ff7707b9c8e7a3e502afb46f5880421fb1b17c6"
    "dd28a87da24519a9e396686fd92db2a06d1ed6efa83be20c01e8701f2da2c86c";
static const char *KAT_UTXO_LEAF_UB0 =
    "f8f07fe0e0ddcfc238f52d3815ab4988a07033e9e6e6bedd9824d31b7a7edddb"
    "544da24c962549fd8e6f6b99d6c7f67235f04cbde794663dd699d6f07b7448a0";

static int kat_hex_eq(const uint8_t h[64], const char *hex) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i] = d[h[i] >> 4];
        got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "  pinned: %s\n  got:    %s\n", hex, got);
        return 0;
    }
    return 1;
}

static void kat_fill(uint8_t *dst, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static void test_leaf_kat_340(void) {
    /* the oracle's fixture row (ledger_roots_v2_accrual_oracle.py UTXO_*) */
    uint8_t nullifier[64], token_id[64], tx_hash[64];
    char owner[129];
    kat_fill(nullifier, 64, 0x11);
    for (int i = 0; i < 128; i += 2) { owner[i] = 'a'; owner[i + 1] = 'b'; }
    owner[128] = '\0';
    kat_fill(token_id, 64, 0x22);
    kat_fill(tx_hash, 64, 0x33);

    uint8_t leaf[DNAC_MERKLE_ROOT_SIZE], leaf0[DNAC_MERKLE_ROOT_SIZE];
    if (dnac_utxo_compute_leaf_hash(nullifier, owner,
                                    0x0102030405060708ULL, token_id,
                                    tx_hash, 0x0A0B0C0Du, leaf,
                                    0x1122334455667788ULL) != 0 ||
        dnac_utxo_compute_leaf_hash(nullifier, owner,
                                    0x0102030405060708ULL, token_id,
                                    tx_hash, 0x0A0B0C0Du, leaf0, 0) != 0) {
        fprintf(stderr, "FAIL test_leaf_kat_340 — leaf hash failed\n");
        assert(0);
    }

    /* Independent path: every byte of the 340-byte preimage written out
     * by hand (little-endian scalars spelled explicitly), hashed with
     * OpenSSL SHA3-512 directly. */
    uint8_t pre[340];
    size_t off = 0;
    memcpy(pre + off, nullifier, 64); off += 64;
    memcpy(pre + off, owner, 128);    off += 128;
    static const uint8_t amount_le[8] =
        { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    memcpy(pre + off, amount_le, 8);  off += 8;
    memcpy(pre + off, token_id, 64);  off += 64;
    memcpy(pre + off, tx_hash, 64);   off += 64;
    static const uint8_t oi_le[4] = { 0x0D, 0x0C, 0x0B, 0x0A };
    memcpy(pre + off, oi_le, 4);      off += 4;
    static const uint8_t ub_le[8] =
        { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    memcpy(pre + off, ub_le, 8);      off += 8;
    assert(off == 340);

    uint8_t manual[64];
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    assert(md);
    unsigned int hl = 0;
    assert(EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1);
    assert(EVP_DigestUpdate(md, pre, sizeof(pre)) == 1);
    assert(EVP_DigestFinal_ex(md, manual, &hl) == 1 && hl == 64);
    EVP_MD_CTX_free(md);

    if (memcmp(leaf, manual, 64) != 0) {
        fprintf(stderr, "FAIL test_leaf_kat_340 — client leaf != hand-built "
                        "340-byte preimage\n");
        assert(0);
    }
    if (!kat_hex_eq(leaf, KAT_UTXO_LEAF_UB) ||
        !kat_hex_eq(leaf0, KAT_UTXO_LEAF_UB0)) {
        fprintf(stderr, "FAIL test_leaf_kat_340 — client leaf drifted from "
                        "the node-side pin\n");
        assert(0);
    }
    if (memcmp(leaf, leaf0, 64) == 0) {
        fprintf(stderr, "FAIL test_leaf_kat_340 — unlock_block does not "
                        "reach the client leaf\n");
        assert(0);
    }
    printf("PASS test_leaf_kat_340\n");
}

int main(void) {
    test_positive();
    test_tampered_sibling();
    test_tampered_root();
    test_tampered_leaf();
    test_null_proof();
    test_invalid_depth();
    test_single_leaf();
    test_leaf_kat_340();
    printf("ALL PASS\n");
    return 0;
}
