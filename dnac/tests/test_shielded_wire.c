/**
 * @file test_shielded_wire.c
 * @brief Dual-mode S5.3 — round-trip + reject KATs for the DNAC_TX_SHIELDED wire.
 *
 * Standalone (links libdna.so): does NOT touch dnac/build (prebuilt binaries).
 *   cc test_shielded_wire.c -I../include -I../../shared -L<msgbuild> -ldna -o ...
 *
 * T1  serialize -> deserialize round-trips every shielded field byte-for-byte.
 * T2  transparent-exclusion (D7.1): a shielded TX with input_count != 0 is rejected.
 * T3  canonical (DET-S5-3): a nonzero UNUSED nf slot is rejected.
 * T4  canonical (A-9): a lane >= Goldilocks p is rejected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "dnac/dnac.h"
#include "dnac/transaction.h"

#define SEC_OFF (DNAC_TX_HEADER_SIZE + 4) /* header + input/output/witness/signer counts (all 0) */
#define P_GOLD  0xFFFFFFFF00000001ULL

static int fails = 0;
#define CHECK(cond, name) do { \
    printf("  %-58s %s\n", name, (cond) ? "PASS" : "FAIL"); \
    if (!(cond)) fails++; \
} while (0)

static dnac_transaction_t *make_shielded(void) {
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SHIELDED);
    if (!tx) return NULL;
    tx->version = DNAC_PROTOCOL_VERSION;
    tx->timestamp = 0x0102030405060708ULL;
    tx->committed_fee = 1000000;
    tx->input_count = 0;
    tx->output_count = 0;
    dnac_tx_shielded_fields_t *sf = &tx->shielded_fields;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) sf->anchor[j] = 0x1111 + j;
    sf->num_input = 2;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        sf->nf_set[0][j] = 0xAA00 + j;
        sf->nf_set[1][j] = 0xBB00 + j;
    }
    sf->num_output = 1;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) sf->output_commit[0][j] = 0xCC00 + j;
    sf->fee = 1000000;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) sf->tx_binding[j] = 0xDD00 + j;
    static uint8_t blob[40];
    for (unsigned i = 0; i < sizeof blob; i++) blob[i] = (uint8_t)(i * 7 + 1);
    sf->fri_proof = blob;      /* borrowed for serialize; not owned by this tx */
    sf->fri_proof_len = sizeof blob;
    return tx;
}

int main(void) {
    printf("test_shielded_wire: DNAC_TX_SHIELDED (V4) round-trip + reject KATs\n");

    /* ---- T1: round-trip ---- */
    dnac_transaction_t *tx = make_shielded();
    if (!tx) { printf("  make_shielded FAIL\n"); return 1; }
    uint8_t buf[4096];
    size_t written = 0;
    int rc = dnac_tx_serialize(tx, buf, sizeof buf, &written);
    CHECK(rc == DNAC_SUCCESS, "T1a serialize -> SUCCESS");

    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buf, written, &tx2);
    CHECK(rc == DNAC_SUCCESS && tx2, "T1b deserialize -> SUCCESS");

    if (tx2) {
        dnac_tx_shielded_fields_t *a = &tx->shielded_fields, *b = &tx2->shielded_fields;
        int eq = tx2->type == DNAC_TX_SHIELDED
              && memcmp(a->anchor, b->anchor, sizeof a->anchor) == 0
              && a->num_input == b->num_input
              && memcmp(a->nf_set, b->nf_set, sizeof a->nf_set) == 0
              && a->num_output == b->num_output
              && memcmp(a->output_commit, b->output_commit, sizeof a->output_commit) == 0
              && a->fee == b->fee
              && memcmp(a->tx_binding, b->tx_binding, sizeof a->tx_binding) == 0
              && a->fri_proof_len == b->fri_proof_len
              && b->fri_proof && memcmp(a->fri_proof, b->fri_proof, a->fri_proof_len) == 0;
        CHECK(eq, "T1c all shielded fields round-trip byte-identical");
        dnac_tx_free(tx2);
    }

    /* ---- T2: transparent-exclusion (flip input_count byte @82 to 1) ---- */
    {
        uint8_t bad[4096];
        memcpy(bad, buf, written);
        bad[DNAC_TX_HEADER_SIZE] = 1; /* input_count = 1 */
        dnac_transaction_t *t = NULL;
        rc = dnac_tx_deserialize(bad, written, &t);
        CHECK(rc != DNAC_SUCCESS, "T2 shielded with input_count!=0 rejected (D7.1)");
        if (rc == DNAC_SUCCESS) dnac_tx_free(t);
    }

    /* ---- T3: canonical — nonzero UNUSED nf slot (num_input=2, slot 2 nonzero) ---- */
    {
        uint8_t bad[4096];
        memcpy(bad, buf, written);
        /* nf_set base = SEC_OFF + anchor(32) + num_input(1); slot 2 lane 0 byte 7 (BE LSB). */
        size_t nf_base = SEC_OFF + DNAC_SHIELDED_LANES * 8 + 1;
        size_t off = nf_base + 2 * (DNAC_SHIELDED_LANES * 8) + 7;
        bad[off] = 0x01;
        dnac_transaction_t *t = NULL;
        rc = dnac_tx_deserialize(bad, written, &t);
        CHECK(rc != DNAC_SUCCESS, "T3 nonzero unused nf slot rejected (DET-S5-3)");
        if (rc == DNAC_SUCCESS) dnac_tx_free(t);
    }

    /* ---- T4: canonical — a lane == p (>= Goldilocks p) rejected ---- */
    {
        dnac_transaction_t *tp = make_shielded();
        tp->shielded_fields.anchor[0] = P_GOLD; /* not canonical */
        uint8_t pbuf[4096]; size_t pw = 0;
        if (dnac_tx_serialize(tp, pbuf, sizeof pbuf, &pw) == DNAC_SUCCESS) {
            dnac_transaction_t *t = NULL;
            rc = dnac_tx_deserialize(pbuf, pw, &t);
            CHECK(rc != DNAC_SUCCESS, "T4 lane >= p rejected (A-9 canonical)");
            if (rc == DNAC_SUCCESS) dnac_tx_free(t);
        } else {
            CHECK(0, "T4 serialize of p-lane tx");
        }
        free(tp);
    }

    /* ---- T5-T8: sighash_v4 (design D3) ---- */
    {
        uint8_t chain_id[32];
        for (unsigned i = 0; i < 32; i++) chain_id[i] = (uint8_t)(0x40 + i);
        uint8_t h1[64], h2[64], h3[64], h4[64];
        int r5 = dnac_tx_shielded_sighash(&tx->shielded_fields, chain_id, h1);
        int r5b = dnac_tx_shielded_sighash(&tx->shielded_fields, chain_id, h2);
        CHECK(r5 == DNAC_SUCCESS && r5b == DNAC_SUCCESS && memcmp(h1, h2, 64) == 0,
              "T5 sighash_v4 deterministic (same input -> same 64B)");

        /* Tamper the fee -> different sighash. */
        dnac_transaction_t *tt = make_shielded();
        tt->shielded_fields.fee += 1;
        dnac_tx_shielded_sighash(&tt->shielded_fields, chain_id, h3);
        CHECK(memcmp(h1, h3, 64) != 0, "T6 sighash binds fee (tamper -> differs)");
        free(tt);

        /* Different chain_id -> different sighash (G6 cross-zone). */
        uint8_t chain_id2[32];
        memcpy(chain_id2, chain_id, 32); chain_id2[0] ^= 0xFF;
        dnac_tx_shielded_sighash(&tx->shielded_fields, chain_id2, h4);
        CHECK(memcmp(h1, h4, 64) != 0, "T7 sighash binds chain_id (differs -> differs)");

        /* Non-NUL sighash (sanity). */
        int nz = 0; for (unsigned i = 0; i < 64; i++) if (h1[i]) nz = 1;
        CHECK(nz, "T8 sighash_v4 is non-zero");
    }

    /* ---- T9 (re-audit Finding 6): shielded fee != committed_fee rejected ---- */
    {
        dnac_transaction_t *tf = make_shielded();
        tf->committed_fee = tf->shielded_fields.fee + 1; /* dual-channel mismatch */
        uint8_t fbuf[4096]; size_t fw = 0;
        if (dnac_tx_serialize(tf, fbuf, sizeof fbuf, &fw) == DNAC_SUCCESS) {
            dnac_transaction_t *t = NULL;
            rc = dnac_tx_deserialize(fbuf, fw, &t);
            CHECK(rc != DNAC_SUCCESS, "T9 shielded fee != committed_fee rejected (D7.2)");
            if (rc == DNAC_SUCCESS) dnac_tx_free(t);
        } else { CHECK(0, "T9 serialize"); }
        free(tf);
    }

    /* ---- T10 (re-audit Finding 5): tx_hash binds the shielded statement ---- */
    {
        uint8_t h_a[64], h_b[64];
        dnac_transaction_t *ta = make_shielded();
        ta->chain_id[0] = 0x55;
        int rh = dnac_tx_compute_hash(ta, h_a);
        CHECK(rh == DNAC_SUCCESS, "T10a compute_hash(shielded) -> SUCCESS");
        dnac_transaction_t *tb = make_shielded();
        tb->chain_id[0] = 0x55;
        tb->shielded_fields.output_commit[0][0] ^= 0x1ULL; /* different statement */
        dnac_tx_compute_hash(tb, h_b);
        CHECK(memcmp(h_a, h_b, 64) != 0, "T10b tx_hash binds output_commit (differs)");
        free(ta);
        free(tb);
    }

    free(tx);
    printf("test_shielded_wire: %s (%d fail)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
