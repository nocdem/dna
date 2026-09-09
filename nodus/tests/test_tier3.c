/**
 * Nodus — Tier 3 Protocol Unit Test
 *
 * Round-trip encode/decode test for all 11 BFT message types.
 * Tests: encode → decode → verify field equality.
 * Also tests sign/verify round-trip.
 *
 * ── Tendermint T3 sections (verbs 28-34, T2 wire design §4.2) ────────
 *
 * WHAT THEY PROVE. That the Tendermint reactor codec is a bijection over
 * its declared domain and rejects everything outside it: each encodable
 * verb survives encode → decode with every field equal; the method tables
 * agree in both directions; a message that differs from the specification
 * in ANY single way — a range, a byte-string length, a missing key, an
 * extra key, a repeated key, a wrong CBOR type — is refused rather than
 * silently zero-filled. They also prove the per-verb class buffer (D-14
 * rev 2) is large enough to verify the largest message its class can
 * carry, and that NODUS_T3_TM_ENVELOPE_OVERHEAD is an over-estimate of the
 * envelope's real cost, measured rather than asserted.
 *
 * AND ONE MORE, WHICH IS A PIN RATHER THAN A FEATURE:
 * test_tm_legacy_negint_pin proves that teaching pass 1 to step over
 * negative integers (D-22 rev 2) did NOT widen what a legacy verb accepts
 * — a negative anywhere in `a` still returns -1 for verbs 1-27 and 30-34,
 * under a known key, an unknown key, or nested in an array. It would fail
 * if the type gate in nodus_t3_decode were dropped or widened, or if the
 * shared cbor_decode_skip were made tolerant.
 *
 * WHAT THEY REQUIRE. Nothing beyond a default build: no compile flag, no
 * environment variable, no network, no filesystem. Keys come from
 * qgp_dsa87_keypair_derand with a fixed seed, so there is no RNG, no clock
 * and no port — the file is `ctest -j` safe and byte-reproducible.
 *
 * WHAT THEY LEAVE BEHIND. Nothing. No files, no processes, no global state
 * beyond this process's own static buffers; every heap buffer is freed.
 *
 * HOW THEY CAN LIE. (1) The negative cases drive a HAND-BUILT envelope, so
 * a mistake in the builder would make every negative "pass" by rejecting
 * for the wrong reason. test_tm_decode_control, and the two controls at the
 * top of test_tm_signed_decode_negatives, exist solely to prove the builder
 * can produce a message the decoder ACCEPTS; a failure in any of them
 * invalidates every negative that follows. (2) A green run says nothing
 * about the host rules — the inner vote signature, the wh.cid gate and the
 * gossip predicates are wave 2 and are not exercised by this codec at all;
 * `sst` and the D-19 value are carried as opaque bytes, never interpreted.
 * (3) The maximal-proposal section proves the 2.8 MB class buffer holds a
 * maximal message on THIS host's allocator; it says nothing about the
 * frame layer or about peer.c's receive buffers, which are still 128 KB.
 * (4) Nothing here enforces CBOR shortest-argument form on decode, so a
 * non-minimal encoding of a signed field would round-trip its VALUE while
 * changing its BYTES — the T2 wave-2 red-team item. (5) The legacy pin
 * drives ONE legacy verb (w_sync_req) and one of 30-34 (w_tm_has). The gate
 * it gates is type-based and therefore verb-independent, but this file
 * demonstrates it on two verbs, not on all thirty-two. (6) THE DECODED
 * MESSAGE IS ONLY AS VALID AS THE BUFFER IT WAS DECODED FROM, in two ways:
 * verb 29's `v` is zero-copy, and `out.wsig` points into the buffer for
 * EVERY verb because it sits outside the union (nodus_tier3.h:913). So any
 * test that reads `v`, reads `wsig`, or calls nodus_t3_verify after the
 * fixture returns must own the buffer and free it afterwards. Both
 * instances of getting this wrong were real and both were in this file:
 * the `v` one crashed ctest outright, because the 2.8 MB PROP-class buffer
 * is above glibc's mmap threshold and free() unmaps it; the `wsig` one, in
 * the 8 KB SMALL class, was recycled rather than unmapped, so it PASSED and
 * was found by the verifier reading the code, not by the suite. A green run
 * of this file is therefore not evidence that its own memory discipline is
 * sound — only ASan or a reviewer is.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/sign/qgp_dilithium.h"   /* qgp_dsa87_keypair_derand */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)
#define TEST_FAIL(name, msg) do { \
    fprintf(stderr, "  FAIL: %s — %s\n", name, msg); \
    failures++; \
} while(0)

static int failures = 0;

/* Test identity (generated once) */
static nodus_identity_t test_id;
static int identity_ready = 0;

static void ensure_identity(void) {
    if (identity_ready) return;
    if (nodus_identity_generate(&test_id) != 0) {
        fprintf(stderr, "FATAL: cannot generate test identity\n");
        exit(1);
    }
    identity_ready = 1;
}

/* Fill a header with test data */
static void fill_header(nodus_t3_header_t *hdr) {
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round = 42;
    hdr->view = 3;
    memset(hdr->sender_id, 0xAA, NODUS_T3_WITNESS_ID_LEN);
    hdr->timestamp = 1709300000;
    hdr->nonce = 12345678;
    memset(hdr->chain_id, 0xBB, 32);
}

static void check_header(const nodus_t3_header_t *a, const nodus_t3_header_t *b,
                           const char *test_name) {
    if (a->version != b->version ||
        a->round != b->round ||
        a->view != b->view ||
        memcmp(a->sender_id, b->sender_id, NODUS_T3_WITNESS_ID_LEN) != 0 ||
        a->timestamp != b->timestamp ||
        a->nonce != b->nonce ||
        memcmp(a->chain_id, b->chain_id, 32) != 0) {
        TEST_FAIL(test_name, "header mismatch");
    }
}

/* ── Test data ───────────────────────────────────────────────────── */

static uint8_t test_tx_hash[NODUS_T3_TX_HASH_LEN];
static uint8_t test_nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
static uint8_t test_tx_data[256];
static uint8_t test_pubkey[NODUS_PK_BYTES];
static uint8_t test_sig[NODUS_SIG_BYTES];

static void init_test_data(void) {
    memset(test_tx_hash, 0x11, sizeof(test_tx_hash));
    for (int i = 0; i < NODUS_T3_MAX_TX_INPUTS; i++)
        memset(test_nullifiers[i], 0x20 + i, NODUS_T3_NULLIFIER_LEN);
    for (int i = 0; i < (int)sizeof(test_tx_data); i++)
        test_tx_data[i] = (uint8_t)(i & 0xFF);
    memset(test_pubkey, 0x33, NODUS_PK_BYTES);
    memset(test_sig, 0x44, NODUS_SIG_BYTES);
}

/* ── Test: method ↔ type mapping ─────────────────────────────────── */

static void test_method_type_mapping(void) {
    const char *name = "method_type_mapping";

    for (int t = NODUS_T3_PROPOSE; t <= NODUS_T3_IDENT; t++) {
        const char *method = nodus_t3_type_to_method((nodus_t3_msg_type_t)t);
        if (!method) { TEST_FAIL(name, "type_to_method returned NULL"); return; }
        nodus_t3_msg_type_t back = nodus_t3_method_to_type(method);
        if (back != t) { TEST_FAIL(name, "round-trip type mismatch"); return; }
    }

    if (nodus_t3_type_to_method(0) != NULL) {
        TEST_FAIL(name, "type 0 should return NULL"); return;
    }
    if (nodus_t3_method_to_type("invalid") != 0) {
        TEST_FAIL(name, "invalid method should return 0"); return;
    }

    TEST_PASS(name);
}

/* ── Encode/decode round-trip helper ─────────────────────────────── */

static uint8_t enc_buf[NODUS_T3_MAX_MSG_SIZE];

static int roundtrip(nodus_t3_msg_t *in, nodus_t3_msg_t *out) {
    ensure_identity();

    size_t len = 0;
    if (nodus_t3_encode(in, &test_id.sk, enc_buf, sizeof(enc_buf), &len) != 0)
        return -1;
    if (len == 0) return -1;

    if (nodus_t3_decode(enc_buf, len, out) != 0)
        return -2;

    return 0;
}

/* ── Test: w_propose round-trip ──────────────────────────────────── */

static void test_propose(void) {
    const char *name = "w_propose";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_PROPOSE;
    in.txn_id = 100;
    fill_header(&in.header);

    /* Phase 9 / Task 9.1 — propose is now batch-shaped only. Build a
     * 1-entry batch round-trip. */
    memcpy(in.propose.tx_root, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.propose.batch_count = 1;
    nodus_t3_batch_tx_t *btx = &in.propose.batch_txs[0];
    memcpy(btx->tx_hash, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    btx->nullifier_count = 3;
    for (int i = 0; i < 3; i++)
        btx->nullifiers[i] = test_nullifiers[i];
    btx->tx_type = 2;
    btx->tx_data = test_tx_data;
    btx->tx_len = 128;
    btx->client_pubkey = test_pubkey;
    btx->client_sig = test_sig;
    btx->fee = 500;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    check_header(&in.header, &out.header, name);

    if (out.txn_id != 100) { TEST_FAIL(name, "txn_id"); return; }
    if (out.type != NODUS_T3_PROPOSE) { TEST_FAIL(name, "type"); return; }
    if (memcmp(out.propose.tx_root, test_tx_hash, NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "block_hash"); return;
    }
    if (out.propose.batch_count != 1) { TEST_FAIL(name, "batch_count"); return; }
    const nodus_t3_batch_tx_t *obtx = &out.propose.batch_txs[0];
    if (memcmp(obtx->tx_hash, test_tx_hash, NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "btx tx_hash"); return;
    }
    if (obtx->nullifier_count != 3) { TEST_FAIL(name, "btx nlc"); return; }
    if (obtx->tx_type != 2) { TEST_FAIL(name, "btx tx_type"); return; }
    if (obtx->tx_len != 128) { TEST_FAIL(name, "btx tx_len"); return; }
    if (obtx->fee != 500) { TEST_FAIL(name, "btx fee"); return; }

    /* Verify signature */
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify failed"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_prevote round-trip ──────────────────────────────────── */

static void test_prevote(void) {
    const char *name = "w_prevote";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_PREVOTE;
    in.txn_id = 101;
    fill_header(&in.header);

    memcpy(in.vote.vote_target, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.vote.vote = 0; /* approve */
    snprintf(in.vote.reason, sizeof(in.vote.reason), "valid transaction");

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    check_header(&in.header, &out.header, name);
    if (out.type != NODUS_T3_PREVOTE) { TEST_FAIL(name, "type"); return; }
    if (memcmp(out.vote.vote_target, test_tx_hash, NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "tx_hash"); return;
    }
    if (out.vote.vote != 0) { TEST_FAIL(name, "vote"); return; }
    if (strcmp(out.vote.reason, "valid transaction") != 0) {
        TEST_FAIL(name, "reason"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_precommit round-trip ────────────────────────────────── */

static void test_precommit(void) {
    const char *name = "w_precommit";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_PRECOMMIT;
    in.txn_id = 102;
    fill_header(&in.header);

    memcpy(in.vote.vote_target, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.vote.vote = 1; /* reject */
    snprintf(in.vote.reason, sizeof(in.vote.reason), "invalid nullifier");

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_PRECOMMIT) { TEST_FAIL(name, "type"); return; }
    if (out.vote.vote != 1) { TEST_FAIL(name, "vote"); return; }
    if (strcmp(out.vote.reason, "invalid nullifier") != 0) {
        TEST_FAIL(name, "reason"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_commit round-trip ───────────────────────────────────── */

static void test_commit(void) {
    const char *name = "w_commit";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_COMMIT;
    in.txn_id = 103;
    fill_header(&in.header);

    /* Phase 9 / Task 9.1 — commit is batch-shaped only. */
    memcpy(in.commit.tx_root, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.commit.batch_count = 1;
    nodus_t3_batch_tx_t *cbtx = &in.commit.batch_txs[0];
    memcpy(cbtx->tx_hash, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    cbtx->nullifier_count = 2;
    cbtx->nullifiers[0] = test_nullifiers[0];
    cbtx->nullifiers[1] = test_nullifiers[1];
    cbtx->tx_type = 1;
    cbtx->tx_data = test_tx_data;
    cbtx->tx_len = 64;
    cbtx->client_pubkey = test_pubkey;
    cbtx->client_sig = test_sig;
    in.commit.proposal_timestamp = 1709300100;
    memset(in.commit.proposer_id, 0xCC, NODUS_T3_WITNESS_ID_LEN);
    in.commit.n_precommits = 3;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    check_header(&in.header, &out.header, name);
    if (out.type != NODUS_T3_COMMIT) { TEST_FAIL(name, "type"); return; }
    if (out.commit.batch_count != 1) { TEST_FAIL(name, "batch_count"); return; }
    if (memcmp(out.commit.tx_root, test_tx_hash, NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "block_hash"); return;
    }
    if (out.commit.proposal_timestamp != 1709300100) {
        TEST_FAIL(name, "pts"); return;
    }
    if (memcmp(out.commit.proposer_id, in.commit.proposer_id,
               NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "proposer_id"); return;
    }
    if (out.commit.n_precommits != 3) { TEST_FAIL(name, "npc"); return; }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_viewchg round-trip ──────────────────────────────────── */

static void test_viewchg(void) {
    const char *name = "w_viewchg";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_VIEWCHG;
    in.txn_id = 104;
    fill_header(&in.header);
    in.viewchg.new_view = 5;
    in.viewchg.last_committed_round = 41;
    /* has_prepared defaults to false (memset) — legacy 2-key wire. */

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_VIEWCHG) { TEST_FAIL(name, "type"); return; }
    if (out.viewchg.new_view != 5) { TEST_FAIL(name, "new_view"); return; }
    if (out.viewchg.last_committed_round != 41) { TEST_FAIL(name, "lcr"); return; }
    if (out.viewchg.has_prepared) {
        TEST_FAIL(name, "has_prepared should be false"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_newview round-trip ──────────────────────────────────── */

static void test_newview(void) {
    const char *name = "w_newview";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_NEWVIEW;
    in.txn_id = 105;
    fill_header(&in.header);
    in.newview.new_view = 5;
    in.newview.n_proofs = 3;
    /* has_reproposal defaults to false (memset) — legacy 2-key wire. */

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_NEWVIEW) { TEST_FAIL(name, "type"); return; }
    if (out.newview.new_view != 5) { TEST_FAIL(name, "new_view"); return; }
    if (out.newview.n_proofs != 3) { TEST_FAIL(name, "n_proofs"); return; }
    if (out.newview.has_reproposal) {
        TEST_FAIL(name, "has_reproposal should be false"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_viewchg with prepared-cert (C5) ─────────────────────── */

static void test_viewchg_with_prepared(void) {
    const char *name = "w_viewchg (prepared)";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_VIEWCHG;
    in.txn_id = 120;
    fill_header(&in.header);
    in.viewchg.new_view = 7;
    in.viewchg.last_committed_round = 99;
    in.viewchg.has_prepared = true;
    in.viewchg.prepared_height = 42;
    in.viewchg.prepared_view = 6;
    memset(in.viewchg.prepared_tx_hash, 0x55, NODUS_T3_TX_HASH_LEN);
    in.viewchg.prepared_n_sigs = 3;
    for (uint32_t i = 0; i < 3; i++) {
        memset(in.viewchg.prepared_sigs[i].voter_id,
               0x60 + (int)i, NODUS_T3_WITNESS_ID_LEN);
        memset(in.viewchg.prepared_sigs[i].signature,
               0x70 + (int)i, NODUS_SIG_BYTES);
    }

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_VIEWCHG) { TEST_FAIL(name, "type"); return; }
    if (out.viewchg.new_view != 7) { TEST_FAIL(name, "new_view"); return; }
    if (out.viewchg.last_committed_round != 99) { TEST_FAIL(name, "lcr"); return; }
    if (!out.viewchg.has_prepared) {
        TEST_FAIL(name, "has_prepared not set"); return;
    }
    if (out.viewchg.prepared_height != 42) {
        TEST_FAIL(name, "prepared_height"); return;
    }
    if (out.viewchg.prepared_view != 6) {
        TEST_FAIL(name, "prepared_view"); return;
    }
    if (memcmp(out.viewchg.prepared_tx_hash, in.viewchg.prepared_tx_hash,
               NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "prepared_tx_hash"); return;
    }
    if (out.viewchg.prepared_n_sigs != 3) {
        TEST_FAIL(name, "prepared_n_sigs"); return;
    }
    for (uint32_t i = 0; i < 3; i++) {
        if (memcmp(out.viewchg.prepared_sigs[i].voter_id,
                   in.viewchg.prepared_sigs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN) != 0) {
            TEST_FAIL(name, "prepared voter_id"); return;
        }
        if (memcmp(out.viewchg.prepared_sigs[i].signature,
                   in.viewchg.prepared_sigs[i].signature,
                   NODUS_SIG_BYTES) != 0) {
            TEST_FAIL(name, "prepared signature"); return;
        }
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_newview with re-proposal (C5) ───────────────────────── */

static void test_newview_with_reproposal(void) {
    const char *name = "w_newview (reproposal)";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_NEWVIEW;
    in.txn_id = 121;
    fill_header(&in.header);
    in.newview.new_view = 8;
    in.newview.n_proofs = 5;
    in.newview.has_reproposal = true;
    in.newview.reproposal_height = 42;
    memset(in.newview.reproposal_tx_hash, 0x88, NODUS_T3_TX_HASH_LEN);
    /* O15C-D.3 — the message now also carries the CERTIFICATE proving
     * the reproposal (prepared view + per-voter sigs), so followers
     * verify the same decision instead of consulting their own frozen
     * VIEW_CHANGE subset. Round-trip those fields too. */
    in.newview.reproposal_prepared_view = 3;
    in.newview.reproposal_n_sigs = 5;
    for (uint32_t i = 0; i < in.newview.reproposal_n_sigs; i++) {
        memset(in.newview.reproposal_sigs[i].voter_id,
               (int)(0xC0 + i), NODUS_T3_WITNESS_ID_LEN);
        memset(in.newview.reproposal_sigs[i].signature,
               (int)(0x40 + i), NODUS_SIG_BYTES);
    }

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_NEWVIEW) { TEST_FAIL(name, "type"); return; }
    if (out.newview.new_view != 8) { TEST_FAIL(name, "new_view"); return; }
    if (out.newview.n_proofs != 5) { TEST_FAIL(name, "n_proofs"); return; }
    if (!out.newview.has_reproposal) {
        TEST_FAIL(name, "has_reproposal not set"); return;
    }
    if (out.newview.reproposal_height != 42) {
        TEST_FAIL(name, "reproposal_height"); return;
    }
    if (memcmp(out.newview.reproposal_tx_hash, in.newview.reproposal_tx_hash,
               NODUS_T3_TX_HASH_LEN) != 0) {
        TEST_FAIL(name, "reproposal_tx_hash"); return;
    }
    /* O15C-D.3 — carried certificate must survive the round trip byte
     * for byte, or a follower would reject an honest leader's proof. */
    if (out.newview.reproposal_prepared_view != 3) {
        TEST_FAIL(name, "reproposal_prepared_view"); return;
    }
    if (out.newview.reproposal_n_sigs != in.newview.reproposal_n_sigs) {
        TEST_FAIL(name, "reproposal_n_sigs"); return;
    }
    for (uint32_t i = 0; i < in.newview.reproposal_n_sigs; i++) {
        if (memcmp(out.newview.reproposal_sigs[i].voter_id,
                   in.newview.reproposal_sigs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN) != 0) {
            TEST_FAIL(name, "reproposal_sigs voter_id"); return;
        }
        if (memcmp(out.newview.reproposal_sigs[i].signature,
                   in.newview.reproposal_sigs[i].signature,
                   NODUS_SIG_BYTES) != 0) {
            TEST_FAIL(name, "reproposal_sigs signature"); return;
        }
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_fwd_req round-trip ──────────────────────────────────── */

static void test_fwd_req(void) {
    const char *name = "w_fwd_req";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_FWD_REQ;
    in.txn_id = 106;
    fill_header(&in.header);

    memcpy(in.fwd_req.tx_hash, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.fwd_req.tx_data = test_tx_data;
    in.fwd_req.tx_len = 200;
    in.fwd_req.client_pubkey = test_pubkey;
    in.fwd_req.client_sig = test_sig;
    in.fwd_req.fee = 1000;
    memset(in.fwd_req.forwarder_id, 0xDD, NODUS_T3_WITNESS_ID_LEN);

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_FWD_REQ) { TEST_FAIL(name, "type"); return; }
    if (out.fwd_req.tx_len != 200) { TEST_FAIL(name, "tx_len"); return; }
    if (!out.fwd_req.tx_data ||
        memcmp(out.fwd_req.tx_data, test_tx_data, 200) != 0) {
        TEST_FAIL(name, "tx_data"); return;
    }
    if (out.fwd_req.fee != 1000) { TEST_FAIL(name, "fee"); return; }
    if (memcmp(out.fwd_req.forwarder_id, in.fwd_req.forwarder_id,
               NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "forwarder_id"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_fwd_rsp round-trip ──────────────────────────────────── */

static void test_fwd_rsp(void) {
    const char *name = "w_fwd_rsp";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    /* Need static buffers for pointer fields */
    static uint8_t wid1[NODUS_T3_WITNESS_ID_LEN];
    static uint8_t wsig1[NODUS_SIG_BYTES];
    static uint8_t wpk1[NODUS_PK_BYTES];

    memset(wid1, 0xE1, NODUS_T3_WITNESS_ID_LEN);
    memset(wsig1, 0xE2, NODUS_SIG_BYTES);
    memset(wpk1, 0xE3, NODUS_PK_BYTES);

    in.type = NODUS_T3_FWD_RSP;
    in.txn_id = 107;
    fill_header(&in.header);

    in.fwd_rsp.status = 1; /* success */
    memcpy(in.fwd_rsp.tx_hash, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.fwd_rsp.witness_count = 1;
    in.fwd_rsp.witnesses[0].witness_id = wid1;
    in.fwd_rsp.witnesses[0].signature = wsig1;
    in.fwd_rsp.witnesses[0].pubkey = wpk1;
    in.fwd_rsp.witnesses[0].timestamp = 1709300200;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_FWD_RSP) { TEST_FAIL(name, "type"); return; }
    if (out.fwd_rsp.status != 1) { TEST_FAIL(name, "status"); return; }
    if (out.fwd_rsp.witness_count != 1) { TEST_FAIL(name, "wc"); return; }
    if (!out.fwd_rsp.witnesses[0].witness_id ||
        memcmp(out.fwd_rsp.witnesses[0].witness_id, wid1,
               NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "witness_id"); return;
    }
    if (out.fwd_rsp.witnesses[0].timestamp != 1709300200) {
        TEST_FAIL(name, "witness timestamp"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_rost_q round-trip ───────────────────────────────────── */

static void test_rost_q(void) {
    const char *name = "w_rost_q";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_ROST_Q;
    in.txn_id = 108;
    fill_header(&in.header);
    in.rost_q.version = 2;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_ROST_Q) { TEST_FAIL(name, "type"); return; }
    if (out.rost_q.version != 2) { TEST_FAIL(name, "version"); return; }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_rost_r round-trip ───────────────────────────────────── */

static void test_rost_r(void) {
    const char *name = "w_rost_r";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    static uint8_t rwid[NODUS_T3_WITNESS_ID_LEN];
    static uint8_t rpk[NODUS_PK_BYTES];
    static uint8_t rsig[NODUS_SIG_BYTES];

    memset(rwid, 0xF1, NODUS_T3_WITNESS_ID_LEN);
    memset(rpk, 0xF2, NODUS_PK_BYTES);
    memset(rsig, 0xF3, NODUS_SIG_BYTES);

    in.type = NODUS_T3_ROST_R;
    in.txn_id = 109;
    fill_header(&in.header);

    in.rost_r.version = 1;
    in.rost_r.n_witnesses = 1;
    in.rost_r.witnesses[0].witness_id = rwid;
    in.rost_r.witnesses[0].pubkey = rpk;
    snprintf(in.rost_r.witnesses[0].address,
             sizeof(in.rost_r.witnesses[0].address), "192.168.0.1:4001");
    in.rost_r.witnesses[0].joined_epoch = 10;
    in.rost_r.witnesses[0].active = true;
    in.rost_r.roster_sig = rsig;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_ROST_R) { TEST_FAIL(name, "type"); return; }
    if (out.rost_r.version != 1) { TEST_FAIL(name, "version"); return; }
    if (out.rost_r.n_witnesses != 1) { TEST_FAIL(name, "n_witnesses"); return; }
    if (!out.rost_r.witnesses[0].witness_id ||
        memcmp(out.rost_r.witnesses[0].witness_id, rwid,
               NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "witness_id"); return;
    }
    if (strcmp(out.rost_r.witnesses[0].address, "192.168.0.1:4001") != 0) {
        TEST_FAIL(name, "address"); return;
    }
    if (!out.rost_r.witnesses[0].active) { TEST_FAIL(name, "active"); return; }
    if (!out.rost_r.roster_sig ||
        memcmp(out.rost_r.roster_sig, rsig, NODUS_SIG_BYTES) != 0) {
        TEST_FAIL(name, "roster_sig"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_ident round-trip ────────────────────────────────────── */

static void test_ident(void) {
    const char *name = "w_ident";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    static uint8_t iwid[NODUS_T3_WITNESS_ID_LEN];
    static uint8_t ipk[NODUS_PK_BYTES];
    memset(iwid, 0xA1, NODUS_T3_WITNESS_ID_LEN);
    memset(ipk, 0xA2, NODUS_PK_BYTES);

    in.type = NODUS_T3_IDENT;
    in.txn_id = 110;
    fill_header(&in.header);
    in.ident.witness_id = iwid;
    in.ident.pubkey = ipk;
    snprintf(in.ident.address, sizeof(in.ident.address), "10.0.0.1:4001");

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_IDENT) { TEST_FAIL(name, "type"); return; }
    if (!out.ident.witness_id ||
        memcmp(out.ident.witness_id, iwid, NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "witness_id"); return;
    }
    if (!out.ident.pubkey ||
        memcmp(out.ident.pubkey, ipk, NODUS_PK_BYTES) != 0) {
        TEST_FAIL(name, "pubkey"); return;
    }
    if (strcmp(out.ident.address, "10.0.0.1:4001") != 0) {
        TEST_FAIL(name, "address"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_sync_req round-trip ─────────────────────────────────── */

static void test_sync_req(void) {
    const char *name = "w_sync_req";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_SYNC_REQ;
    in.txn_id = 42;
    fill_header(&in.header);
    in.sync_req.height = 7;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    check_header(&in.header, &out.header, name);
    if (out.type != NODUS_T3_SYNC_REQ) { TEST_FAIL(name, "type"); return; }
    if (out.sync_req.height != 7) { TEST_FAIL(name, "height"); return; }
    if (out.txn_id != 42) { TEST_FAIL(name, "txn_id"); return; }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_sync_rsp round-trip ────────────────────────────────── */

static void test_sync_rsp(void) {
    const char *name = "w_sync_rsp";

    ensure_identity();

    /* Test 1: not-found response */
    {
        nodus_t3_msg_t in, out;
        memset(&in, 0, sizeof(in));

        in.type = NODUS_T3_SYNC_RSP;
        in.txn_id = 50;
        fill_header(&in.header);
        in.sync_rsp.found = false;
        in.sync_rsp.height = 99;

        int rc = roundtrip(&in, &out);
        if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed (not-found)"); return; }

        if (out.type != NODUS_T3_SYNC_RSP) { TEST_FAIL(name, "type (not-found)"); return; }
        if (out.sync_rsp.found != false) { TEST_FAIL(name, "found should be false"); return; }
        if (out.sync_rsp.height != 99) { TEST_FAIL(name, "height (not-found)"); return; }
        if (nodus_t3_verify(&out, &test_id.pk) != 0) {
            TEST_FAIL(name, "wsig verify (not-found)"); return;
        }
    }

    /* Test 2: found response with multi-tx batch (Phase 11 / Task 11.1) */
    {
        nodus_t3_msg_t in, out;
        memset(&in, 0, sizeof(in));

        in.type = NODUS_T3_SYNC_RSP;
        in.txn_id = 99;
        fill_header(&in.header);

        in.sync_rsp.found = true;
        in.sync_rsp.height = 3;
        in.sync_rsp.timestamp = 1700000001;
        memset(in.sync_rsp.proposer_id, 0xCC, NODUS_T3_WITNESS_ID_LEN);
        memset(in.sync_rsp.prev_hash, 0xDD, NODUS_T3_TX_HASH_LEN);
        memset(in.sync_rsp.tx_root, 0xAA, NODUS_T3_TX_HASH_LEN);

        /* One TX in the batch */
        in.sync_rsp.tx_count = 1;
        nodus_t3_batch_tx_t *btx = &in.sync_rsp.batch_txs[0];
        memset(btx->tx_hash, 0xAB, NODUS_T3_TX_HASH_LEN);
        btx->tx_type = 1;  /* SPEND */
        uint8_t fake_tx[128];
        memset(fake_tx, 0xBB, sizeof(fake_tx));
        btx->tx_data = fake_tx;
        btx->tx_len = sizeof(fake_tx);
        uint8_t nul[NODUS_T3_NULLIFIER_LEN];
        memset(nul, 0xEE, NODUS_T3_NULLIFIER_LEN);
        btx->nullifiers[0] = nul;
        btx->nullifier_count = 1;
        btx->client_pubkey = test_pubkey;
        btx->client_sig = test_sig;

        /* One cert */
        in.sync_rsp.cert_count = 1;
        memset(in.sync_rsp.certs[0].voter_id, 0x11, NODUS_T3_WITNESS_ID_LEN);
        memset(in.sync_rsp.certs[0].signature, 0x22, NODUS_SIG_BYTES);

        int rc = roundtrip(&in, &out);
        if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed (found)"); return; }

        if (out.type != NODUS_T3_SYNC_RSP) { TEST_FAIL(name, "type (found)"); return; }
        if (out.sync_rsp.found != true) { TEST_FAIL(name, "found should be true"); return; }
        if (out.sync_rsp.height != 3) { TEST_FAIL(name, "height"); return; }
        if (out.sync_rsp.tx_count != 1) { TEST_FAIL(name, "tx_count"); return; }
        if (memcmp(out.sync_rsp.tx_root, in.sync_rsp.tx_root,
                   NODUS_T3_TX_HASH_LEN) != 0) {
            TEST_FAIL(name, "tx_root"); return;
        }
        if (out.sync_rsp.batch_txs[0].tx_type != 1) { TEST_FAIL(name, "btx tx_type"); return; }
        if (out.sync_rsp.batch_txs[0].tx_len != 128) { TEST_FAIL(name, "btx tx_len"); return; }
        if (memcmp(out.sync_rsp.proposer_id, in.sync_rsp.proposer_id,
                   NODUS_T3_WITNESS_ID_LEN) != 0) {
            TEST_FAIL(name, "proposer_id"); return;
        }
        if (out.sync_rsp.cert_count != 1) { TEST_FAIL(name, "cert_count"); return; }
        if (out.sync_rsp.certs[0].signature[0] != 0x22) {
            TEST_FAIL(name, "cert signature"); return;
        }

        if (nodus_t3_verify(&out, &test_id.pk) != 0) {
            TEST_FAIL(name, "wsig verify (found)"); return;
        }
    }

    TEST_PASS(name);
}

/* ── Test: verify with wrong key fails ───────────────────────────── */

static void test_verify_wrong_key(void) {
    const char *name = "verify_wrong_key";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_VIEWCHG;
    in.txn_id = 200;
    fill_header(&in.header);
    in.viewchg.new_view = 1;
    in.viewchg.last_committed_round = 0;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, "roundtrip"); return; }

    /* Generate a different identity */
    nodus_identity_t other;
    if (nodus_identity_generate(&other) != 0) {
        TEST_FAIL(name, "generate other identity"); return;
    }

    /* Verify with wrong key should fail */
    if (nodus_t3_verify(&out, &other.pk) == 0) {
        TEST_FAIL(name, "should have failed with wrong key"); return;
    }

    TEST_PASS(name);
}

/* ── Test: zero nullifiers ───────────────────────────────────────── */

static void test_propose_zero_nullifiers(void) {
    const char *name = "propose_zero_nullifiers";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_PROPOSE;
    in.txn_id = 300;
    fill_header(&in.header);

    /* Phase 9 / Task 9.1 — genesis is now batch-of-1 with zero nullifiers. */
    memcpy(in.propose.tx_root, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    in.propose.batch_count = 1;
    nodus_t3_batch_tx_t *btx = &in.propose.batch_txs[0];
    memcpy(btx->tx_hash, test_tx_hash, NODUS_T3_TX_HASH_LEN);
    btx->nullifier_count = 0;
    btx->tx_type = 0; /* genesis */
    btx->tx_data = test_tx_data;
    btx->tx_len = 32;
    btx->client_pubkey = test_pubkey;
    btx->client_sig = test_sig;
    btx->fee = 0;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.propose.batch_count != 1) { TEST_FAIL(name, "batch_count"); return; }
    if (out.propose.batch_txs[0].nullifier_count != 0) { TEST_FAIL(name, "btx nlc"); return; }
    if (out.propose.batch_txs[0].tx_len != 32) { TEST_FAIL(name, "btx tx_len"); return; }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ══════════════════════════════════════════════════════════════════
 * Tendermint T3 — verbs 28-34 (T2 wire design §4.2, D-16 rev 4)
 * ══════════════════════════════════════════════════════════════════ */

/* Deterministic keypair — qgp_dsa87_keypair_derand with a fixed seed (the
 * test_qc_v2.c idiom). Deliberately NOT ensure_identity() above, which
 * draws from the RNG: these sections must be reproducible. */
static nodus_pubkey_t tm_pk;
static nodus_seckey_t tm_sk;
static int            tm_keys_ready = 0;

static void tm_ensure_keys(void) {
    if (tm_keys_ready) return;
    uint8_t seed[32];
    memset(seed, 0x5A, sizeof(seed));
    if (qgp_dsa87_keypair_derand(tm_pk.bytes, tm_sk.bytes, seed) != 0) {
        fprintf(stderr, "FATAL: derand keypair failed\n");
        exit(1);
    }
    tm_keys_ready = 1;
}

/* Encode through the type's OWN class buffer, then decode. Using
 * nodus_t3_max_msg_size for the allocation is the point: if a class bound
 * were too small for its own maximal message, encode would fail here. */
/* ⚠ BUFFER LIFETIME IS PART OF THE CONTRACT — for TWO reasons, and the
 * second one applies to every verb:
 *
 *   1. Verb 29's `v` points INTO the buffer this helper allocates
 *      (zero-copy, the w_v2_range_r.frames idiom — nodus_t3_tm_prop_t in
 *      nodus_tier3.h).
 *   2. `out.wsig` points into it too, for EVERY verb. It lives OUTSIDE the
 *      union (nodus_tier3.h:913) and is set to a pointer into the decode
 *      buffer in pass 1 (nodus_tier3.c:2248); nodus_t3_verify memcpy's
 *      4627 bytes from it (nodus_tier3.c:3000).
 *
 * So `out` is only as valid as the buffer, and the rule is:
 *
 * keep == NULL  → the buffer is freed here. Safe ONLY for a caller that
 *                 neither reads out.wsig nor calls nodus_t3_verify after
 *                 the return, and does not read out.tm_prop.v. Reading the
 *                 copied union fields (scalars and fixed arrays) is fine.
 *                 The helper's own verify below is the only verify such a
 *                 caller gets, and it runs while the buffer is alive.
 * keep != NULL  → the buffer is handed over on success and *keep is the
 *                 caller's to free, after its last read of `out`. On every
 *                 failure path *keep is NULL and the buffer is already
 *                 freed, so the caller can free(*keep) unconditionally. */
static int tm_roundtrip(nodus_t3_msg_t *in, nodus_t3_msg_t *out,
                        size_t *enc_len_out, uint8_t **keep) {
    tm_ensure_keys();
    if (keep) *keep = NULL;

    size_t cap = nodus_t3_max_msg_size(in->type);
    if (cap == 0) return -3;
    uint8_t *buf = malloc(cap);
    if (!buf) return -4;

    size_t len = 0;
    int rc = nodus_t3_encode(in, &tm_sk, buf, cap, &len);
    if (rc != 0 || len == 0) { free(buf); return -1; }
    if (nodus_t3_decode(buf, len, out) != 0) { free(buf); return -2; }
    /* Verify inside the class buffer — a failure here would mean the
     * bound nodus_t3_verify allocates cannot hold this message. */
    if (nodus_t3_verify(out, &tm_pk) != 0) { free(buf); return -5; }

    if (enc_len_out) *enc_len_out = len;
    if (keep) *keep = buf;      /* caller owns it now */
    else      free(buf);
    return 0;
}

/* ── Test: method ↔ type table for the Tendermint verbs ──────────── */

static void test_tm_method_table(void) {
    const char *name = "tm_method_table";

    static const struct { nodus_t3_msg_type_t t; const char *m; } tbl[] = {
        { NODUS_T3_TM_STEP,  "w_tm_step"  },
        { NODUS_T3_TM_PROP,  "w_tm_prop"  },
        { NODUS_T3_TM_POL,   "w_tm_pol"   },
        { NODUS_T3_TM_VOTE,  "w_tm_vote"  },
        { NODUS_T3_TM_HAS,   "w_tm_has"   },
        { NODUS_T3_TM_MAJ23, "w_tm_maj23" },
        { NODUS_T3_TM_BITS,  "w_tm_bits"  },
    };

    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        const char *m = nodus_t3_type_to_method(tbl[i].t);
        if (!m || strcmp(m, tbl[i].m) != 0) {
            TEST_FAIL(name, "type_to_method string mismatch"); return;
        }
        if (nodus_t3_method_to_type(tbl[i].m) != tbl[i].t) {
            TEST_FAIL(name, "method_to_type round-trip"); return;
        }
    }

    /* Values do not move: 27 is still the last legacy verb and 28..34 are
     * the Tendermint block. */
    if (NODUS_T3_VIEWOK_REQ != 27 || NODUS_T3_TM_STEP != 28 ||
        NODUS_T3_TM_PROP != 29 || NODUS_T3_TM_POL != 30 ||
        NODUS_T3_TM_VOTE != 31 || NODUS_T3_TM_HAS != 32 ||
        NODUS_T3_TM_MAJ23 != 33 || NODUS_T3_TM_BITS != 34) {
        TEST_FAIL(name, "enum values moved"); return;
    }

    /* Every method string must fit nodus_t3_msg_t.method[16] with its NUL,
     * or pass 1 truncates it and method_to_type silently returns 0. The
     * longest Tendermint name is "w_tm_maj23" (10). */
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (strlen(tbl[i].m) > 15) {
            TEST_FAIL(name, "method string would be truncated at decode"); return;
        }
    }

    TEST_PASS(name);
}

/* ── Test: per-verb round-trip ───────────────────────────────────── */

static void test_tm_step_roundtrip(void) {
    const char *name = "tm_step_roundtrip";

    /* sst is an unconstrained i64 (T2 §4.2) — both edges must survive.
     * lcr is >= -1, where -1 is the reference's "no last commit round". */
    static const struct { int64_t sst; int32_t lcr; uint8_t s; } cases[] = {
        { INT64_MIN,  -1, NODUS_T3_TM_STEP_PROPOSE    },
        {        -1,   0, NODUS_T3_TM_STEP_PREVOTE    },
        {         0,   7, NODUS_T3_TM_STEP_PRECOMMIT  },
        { INT64_MAX, INT32_MAX, NODUS_T3_TM_STEP_NEW_HEIGHT },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        nodus_t3_msg_t in, out;
        memset(&in, 0, sizeof(in));
        in.type = NODUS_T3_TM_STEP;
        in.txn_id = 2800;
        fill_header(&in.header);
        in.tm_step.h   = 77;
        in.tm_step.r   = 3;
        in.tm_step.s   = cases[i].s;
        in.tm_step.sst = cases[i].sst;
        in.tm_step.lcr = cases[i].lcr;

        /* keep = NULL: verb 28 has no pointer field. */
        if (tm_roundtrip(&in, &out, NULL, NULL) != 0) {
            fprintf(stderr, "    case sst=%lld lcr=%ld\n",
                    (long long)cases[i].sst, (long)cases[i].lcr);
            TEST_FAIL(name, "roundtrip"); return;
        }
        check_header(&in.header, &out.header, name);
        if (out.tm_step.h != 77 || out.tm_step.r != 3 ||
            out.tm_step.s != cases[i].s) {
            TEST_FAIL(name, "scalar mismatch"); return;
        }
        if (out.tm_step.sst != cases[i].sst) {
            fprintf(stderr, "    sst want %lld got %lld\n",
                    (long long)cases[i].sst, (long long)out.tm_step.sst);
            TEST_FAIL(name, "sst"); return;
        }
        if (out.tm_step.lcr != cases[i].lcr) {
            TEST_FAIL(name, "lcr"); return;
        }
    }
    TEST_PASS(name);
}

/* The `sst` twin (T2 §4.2): two frames identical but for sst must decode to
 * structs identical but for sst. It is written and never read by the host,
 * so it may never leak into another field. */
static void test_tm_step_sst_twin(void) {
    const char *name = "tm_step_sst_twin";
    nodus_t3_msg_t a_in, a_out, b_in, b_out;

    memset(&a_in, 0, sizeof(a_in));
    a_in.type = NODUS_T3_TM_STEP;
    a_in.txn_id = 2801;
    fill_header(&a_in.header);
    a_in.tm_step.h = 900; a_in.tm_step.r = 12;
    a_in.tm_step.s = NODUS_T3_TM_STEP_PREVOTE;
    a_in.tm_step.lcr = 4;

    b_in = a_in;
    a_in.tm_step.sst = 0;
    b_in.tm_step.sst = -6148914691236517206LL;   /* an arbitrary negative i64 */

    /* keep = NULL: verb 28 has no pointer field. */
    if (tm_roundtrip(&a_in, &a_out, NULL, NULL) != 0 ||
        tm_roundtrip(&b_in, &b_out, NULL, NULL) != 0) {
        TEST_FAIL(name, "roundtrip"); return;
    }
    if (a_out.tm_step.sst == b_out.tm_step.sst) {
        TEST_FAIL(name, "the two sst values did not survive as distinct"); return;
    }
    if (a_out.tm_step.h   != b_out.tm_step.h   ||
        a_out.tm_step.r   != b_out.tm_step.r   ||
        a_out.tm_step.s   != b_out.tm_step.s   ||
        a_out.tm_step.lcr != b_out.tm_step.lcr) {
        TEST_FAIL(name, "sst leaked into another field"); return;
    }
    if (a_out.tm_step.sst != a_in.tm_step.sst ||
        b_out.tm_step.sst != b_in.tm_step.sst) {
        TEST_FAIL(name, "sst value not carried faithfully"); return;
    }
    TEST_PASS(name);
}

static void test_tm_prop_roundtrip(void) {
    const char *name = "tm_prop_roundtrip";
    static const uint8_t v[64] = { 0x02, 0xDE, 0xAD, 0xBE, 0xEF };
    static const int32_t vrs[] = { -1, 0, 5 };

    for (size_t i = 0; i < sizeof(vrs) / sizeof(vrs[0]); i++) {
        nodus_t3_msg_t in, out;
        uint8_t *keep = NULL;
        memset(&in, 0, sizeof(in));
        in.type = NODUS_T3_TM_PROP;
        in.txn_id = 2900;
        fill_header(&in.header);
        in.tm_prop.h     = 42;
        in.tm_prop.r     = 1;
        in.tm_prop.vr    = vrs[i];
        in.tm_prop.v     = v;
        in.tm_prop.v_len = (uint32_t)sizeof(v);

        /* `keep` because out.tm_prop.v points into the encode buffer; every
         * read of `out` below happens while that buffer is still mapped,
         * and the free is the last statement on every path out. */
        if (tm_roundtrip(&in, &out, NULL, &keep) != 0) {
            TEST_FAIL(name, "roundtrip"); return;
        }
        check_header(&in.header, &out.header, name);
        if (out.tm_prop.h != 42 || out.tm_prop.r != 1) {
            free(keep); TEST_FAIL(name, "scalar mismatch"); return;
        }
        if (out.tm_prop.vr != vrs[i]) {
            free(keep); TEST_FAIL(name, "vr"); return;
        }
        if (out.tm_prop.v_len != sizeof(v)) {
            free(keep); TEST_FAIL(name, "v_len"); return;
        }
        if (!out.tm_prop.v || memcmp(out.tm_prop.v, v, sizeof(v)) != 0) {
            free(keep); TEST_FAIL(name, "v bytes"); return;
        }
        free(keep);
    }
    TEST_PASS(name);
}

/* The one that actually exercises the 2.8 MB class buffer. */
static void test_tm_prop_maximal_value(void) {
    const char *name = "tm_prop_maximal_value";
    tm_ensure_keys();

    const size_t v_len = (size_t)DNA_TM_VALUE_MAX_LEN;
    uint8_t *v = malloc(v_len);
    if (!v) { TEST_FAIL(name, "alloc value"); return; }
    for (size_t i = 0; i < v_len; i++) v[i] = (uint8_t)(i & 0xFF);

    size_t cap = nodus_t3_max_msg_size(NODUS_T3_TM_PROP);
    if (cap != NODUS_T3_TM_PROP_MAX_MSG) {
        TEST_FAIL(name, "PROP class bound"); free(v); return;
    }
    uint8_t *buf = malloc(cap);
    if (!buf) { TEST_FAIL(name, "alloc buffer"); free(v); return; }

    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_TM_PROP;
    in.txn_id = 2901;
    fill_header(&in.header);
    in.tm_prop.h = 1; in.tm_prop.r = 0; in.tm_prop.vr = -1;
    in.tm_prop.v = v; in.tm_prop.v_len = (uint32_t)v_len;

    size_t len = 0;
    if (nodus_t3_encode(&in, &tm_sk, buf, cap, &len) != 0 || len == 0) {
        TEST_FAIL(name, "a maximal value did not fit its own class buffer");
        free(buf); free(v); return;
    }
    if (nodus_t3_decode(buf, len, &out) != 0) {
        TEST_FAIL(name, "decode"); free(buf); free(v); return;
    }
    if (out.tm_prop.v_len != v_len ||
        memcmp(out.tm_prop.v, v, v_len) != 0) {
        TEST_FAIL(name, "maximal value bytes"); free(buf); free(v); return;
    }
    /* Verify allocates the class bound internally — a bound too small
     * makes this fail, which is the property under test. */
    if (nodus_t3_verify(&out, &tm_pk) != 0) {
        TEST_FAIL(name, "wsig verify of a maximal proposal");
        free(buf); free(v); return;
    }

    /* MEASURED envelope overhead at maximal value size (design §6 (c)). */
    if (len <= v_len) {
        TEST_FAIL(name, "encoded no larger than its value"); free(buf); free(v); return;
    }
    size_t overhead = len - v_len;
    if (overhead >= (size_t)NODUS_T3_TM_ENVELOPE_OVERHEAD) {
        fprintf(stderr, "    measured overhead %llu >= %llu\n",
                (unsigned long long)overhead,
                (unsigned long long)NODUS_T3_TM_ENVELOPE_OVERHEAD);
        TEST_FAIL(name, "NODUS_T3_TM_ENVELOPE_OVERHEAD is not an over-estimate");
        free(buf); free(v); return;
    }
    fprintf(stderr, "    prop: value %llu B, encoded %llu B, overhead %llu B (< %llu)\n",
            (unsigned long long)v_len, (unsigned long long)len,
            (unsigned long long)overhead,
            (unsigned long long)NODUS_T3_TM_ENVELOPE_OVERHEAD);

    free(buf);
    free(v);
    TEST_PASS(name);
}

static void test_tm_pol_roundtrip(void) {
    const char *name = "tm_pol_roundtrip";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_TM_POL;
    in.txn_id = 3000;
    fill_header(&in.header);
    in.tm_pol.h  = 0x0102030405060708ULL;
    in.tm_pol.pr = 7;
    for (int i = 0; i < NODUS_T3_TM_BITMAP_MAX; i++)
        in.tm_pol.bm[i] = (uint8_t)(0xA0 + i);
    in.tm_pol.bm_len = NODUS_T3_TM_BITMAP_MAX;

    /* keep = NULL: this verb copies every field out of the buffer. */
    if (tm_roundtrip(&in, &out, NULL, NULL) != 0) { TEST_FAIL(name, "roundtrip"); return; }
    check_header(&in.header, &out.header, name);

    if (out.tm_pol.h != in.tm_pol.h)   { TEST_FAIL(name, "h"); return; }
    if (out.tm_pol.pr != in.tm_pol.pr) { TEST_FAIL(name, "pr"); return; }
    if (out.tm_pol.bm_len != in.tm_pol.bm_len) { TEST_FAIL(name, "bm_len"); return; }
    if (memcmp(out.tm_pol.bm, in.tm_pol.bm, in.tm_pol.bm_len) != 0) {
        TEST_FAIL(name, "bm"); return;
    }
    TEST_PASS(name);
}

static void test_tm_vote_roundtrip(void) {
    const char *name = "tm_vote_roundtrip";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_TM_VOTE;
    in.txn_id = 3100;
    fill_header(&in.header);
    in.tm_vote.ty = 2;                       /* PRECOMMIT (D-12) */
    in.tm_vote.h  = 0xFFFFFFFFFFFFFFFFULL;   /* u64 upper edge */
    in.tm_vote.r  = 0xFFFFFFFFu;             /* u32 upper edge */
    memset(in.tm_vote.bi,  0xCC, 64);
    memset(in.tm_vote.vid, 0xDD, 32);
    in.tm_vote.ix = 127;
    in.tm_vote.ts = 1800000000000ULL;        /* T2 §4.1 KAT timestamp */
    for (int i = 0; i < QGP_DSA87_SIGNATURE_BYTES; i++)
        in.tm_vote.sig[i] = (uint8_t)(i & 0xFF);

    size_t enc_len = 0;
    /* keep = NULL: verb 31 copies bi/vid/sig into the struct. */
    if (tm_roundtrip(&in, &out, &enc_len, NULL) != 0) {
        TEST_FAIL(name, "roundtrip"); return;
    }
    check_header(&in.header, &out.header, name);

    if (out.tm_vote.ty != in.tm_vote.ty) { TEST_FAIL(name, "ty"); return; }
    if (out.tm_vote.h  != in.tm_vote.h)  { TEST_FAIL(name, "h");  return; }
    if (out.tm_vote.r  != in.tm_vote.r)  { TEST_FAIL(name, "r");  return; }
    if (memcmp(out.tm_vote.bi, in.tm_vote.bi, 64) != 0)   { TEST_FAIL(name, "bi"); return; }
    if (memcmp(out.tm_vote.vid, in.tm_vote.vid, 32) != 0) { TEST_FAIL(name, "vid"); return; }
    if (out.tm_vote.ix != in.tm_vote.ix) { TEST_FAIL(name, "ix"); return; }
    if (out.tm_vote.ts != in.tm_vote.ts) { TEST_FAIL(name, "ts"); return; }
    if (memcmp(out.tm_vote.sig, in.tm_vote.sig, QGP_DSA87_SIGNATURE_BYTES) != 0) {
        TEST_FAIL(name, "sig"); return;
    }

    /* MEASURED envelope overhead: everything the wire costs on top of the
     * inner signature — the CBOR envelope, the 7-key wh, the method
     * string, the fixed fields and the 4627-byte frame wsig. The class
     * macro must be an over-estimate of it, not a guess that happens to
     * hold. */
    if (enc_len <= (size_t)QGP_DSA87_SIGNATURE_BYTES) {
        TEST_FAIL(name, "encoded shorter than its own inner signature"); return;
    }
    size_t overhead = enc_len - (size_t)QGP_DSA87_SIGNATURE_BYTES;
    if (overhead >= (size_t)NODUS_T3_TM_ENVELOPE_OVERHEAD) {
        fprintf(stderr, "    measured envelope overhead %llu >= %llu\n",
                (unsigned long long)overhead,
                (unsigned long long)NODUS_T3_TM_ENVELOPE_OVERHEAD);
        TEST_FAIL(name, "NODUS_T3_TM_ENVELOPE_OVERHEAD is not an over-estimate");
        return;
    }
    if (enc_len > nodus_t3_max_msg_size(NODUS_T3_TM_VOTE)) {
        TEST_FAIL(name, "maximal vote exceeds its class bound"); return;
    }
    fprintf(stderr, "    vote: encoded %llu B, envelope overhead %llu B (< %llu)\n",
            (unsigned long long)enc_len, (unsigned long long)overhead,
            (unsigned long long)NODUS_T3_TM_ENVELOPE_OVERHEAD);

    TEST_PASS(name);
}

static void test_tm_has_roundtrip(void) {
    const char *name = "tm_has_roundtrip";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_TM_HAS;
    in.txn_id = 3200;
    fill_header(&in.header);
    in.tm_has.h  = 9;
    in.tm_has.r  = 4;
    in.tm_has.ty = 1;                        /* PREVOTE */
    in.tm_has.ix = 63;

    /* keep = NULL: this verb copies every field out of the buffer. */
    if (tm_roundtrip(&in, &out, NULL, NULL) != 0) { TEST_FAIL(name, "roundtrip"); return; }
    check_header(&in.header, &out.header, name);
    if (out.tm_has.h != 9 || out.tm_has.r != 4 ||
        out.tm_has.ty != 1 || out.tm_has.ix != 63) {
        TEST_FAIL(name, "field mismatch"); return;
    }
    TEST_PASS(name);
}

static void test_tm_maj23_roundtrip(void) {
    const char *name = "tm_maj23_roundtrip";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_TM_MAJ23;
    in.txn_id = 3300;
    fill_header(&in.header);
    in.tm_maj23.h  = 11;
    in.tm_maj23.r  = 2;
    in.tm_maj23.ty = 2;
    memset(in.tm_maj23.bi, 0x5C, 64);

    /* keep = NULL: this verb copies every field out of the buffer. */
    if (tm_roundtrip(&in, &out, NULL, NULL) != 0) { TEST_FAIL(name, "roundtrip"); return; }
    check_header(&in.header, &out.header, name);
    if (out.tm_maj23.h != 11 || out.tm_maj23.r != 2 || out.tm_maj23.ty != 2) {
        TEST_FAIL(name, "scalar mismatch"); return;
    }
    if (memcmp(out.tm_maj23.bi, in.tm_maj23.bi, 64) != 0) {
        TEST_FAIL(name, "bi"); return;
    }
    TEST_PASS(name);
}

static void test_tm_bits_roundtrip(void) {
    const char *name = "tm_bits_roundtrip";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_TM_BITS;
    in.txn_id = 3400;
    fill_header(&in.header);
    in.tm_bits.h  = 12;
    in.tm_bits.r  = 0;
    in.tm_bits.ty = 1;
    memset(in.tm_bits.bi, 0x77, 64);
    in.tm_bits.bm[0] = 0x0F;
    in.tm_bits.bm_len = 1;                   /* lower edge: 1 byte */

    /* keep = NULL: this verb copies every field out of the buffer. */
    if (tm_roundtrip(&in, &out, NULL, NULL) != 0) { TEST_FAIL(name, "roundtrip"); return; }
    check_header(&in.header, &out.header, name);
    if (out.tm_bits.h != 12 || out.tm_bits.r != 0 || out.tm_bits.ty != 1) {
        TEST_FAIL(name, "scalar mismatch"); return;
    }
    if (memcmp(out.tm_bits.bi, in.tm_bits.bi, 64) != 0) { TEST_FAIL(name, "bi"); return; }
    if (out.tm_bits.bm_len != 1 || out.tm_bits.bm[0] != 0x0F) {
        TEST_FAIL(name, "bm"); return;
    }
    TEST_PASS(name);
}

/* ── Test: encoder refuses out-of-range fields ───────────────────── */

static void test_tm_encode_range_negatives(void) {
    const char *name = "tm_encode_range_negatives";
    tm_ensure_keys();

    /* Sized to the LARGEST Tendermint class that can encode, so a refusal
     * can only come from the range check under test and never from a
     * buffer that was too small. */
    const size_t cap = NODUS_T3_TM_VOTE_MAX_MSG;
    uint8_t *buf = malloc(cap);
    if (!buf) { TEST_FAIL(name, "alloc"); return; }
    size_t len = 0;

    /* ONE message, rebuilt per case: nodus_t3_msg_t carries the 128-entry
     * certificate arrays of the legacy union members and is ~600 KB, so an
     * array of them would be megabytes of stack. */
    static const uint8_t small_v[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    static const struct {
        const char         *what;
        nodus_t3_msg_type_t type;
        uint8_t             ty;       /* vote type byte to plant    */
        uint8_t             bm_len;   /* bitmap length to plant     */
        uint8_t             s;        /* step value to plant (28)   */
        int32_t             signed_v; /* lcr (28) or vr (29)        */
        uint32_t            v_len;    /* value length to plant (29) */
        int                 v_null;   /* plant a NULL value pointer */
    } cases[] = {
        /* bitmap length 0 and 17 on both bitmap-carrying verbs */
        { "pol bm_len 0",    NODUS_T3_TM_POL,   0,    0,  0, 0,  0, 0 },
        { "pol bm_len 17",   NODUS_T3_TM_POL,   0,    NODUS_T3_TM_BITMAP_MAX + 1,
                                                          0, 0,  0, 0 },
        { "bits bm_len 0",   NODUS_T3_TM_BITS,  1,    0,  0, 0,  0, 0 },
        { "bits bm_len 17",  NODUS_T3_TM_BITS,  1,    NODUS_T3_TM_BITMAP_MAX + 1,
                                                          0, 0,  0, 0 },
        /* vote type byte outside D-12's {1, 2}, on every verb carrying it */
        { "vote ty 0",       NODUS_T3_TM_VOTE,  0,    0,  0, 0,  0, 0 },
        { "vote ty 3",       NODUS_T3_TM_VOTE,  3,    0,  0, 0,  0, 0 },
        { "has ty 0",        NODUS_T3_TM_HAS,   0,    0,  0, 0,  0, 0 },
        { "maj23 ty 0x20",   NODUS_T3_TM_MAJ23, 0x20, 0,  0, 0,  0, 0 },
        { "bits ty 0",       NODUS_T3_TM_BITS,  0,    1,  0, 0,  0, 0 },
        /* verb 28: step outside 0..3, lcr below -1 */
        { "step s 4",        NODUS_T3_TM_STEP,  0,    0,  4, 0,  0, 0 },
        { "step s 255",      NODUS_T3_TM_STEP,  0,    0,  255, 0, 0, 0 },
        { "step lcr -2",     NODUS_T3_TM_STEP,  0,    0,  0, -2, 0, 0 },
        { "step lcr INT32_MIN", NODUS_T3_TM_STEP, 0,  0,  0, INT32_MIN, 0, 0 },
        /* verb 29: vr below -1, empty value, oversize value, NULL value */
        { "prop vr -2",      NODUS_T3_TM_PROP,  0,    0,  0, -2, 8, 0 },
        { "prop v_len 0",    NODUS_T3_TM_PROP,  0,    0,  0, -1, 0, 0 },
        { "prop v NULL",     NODUS_T3_TM_PROP,  0,    0,  0, -1, 8, 1 },
        /* One byte past the derived ceiling. enc_args refuses on the
         * LENGTH before enc_tm_prop_args ever dereferences v, so an
         * 8-byte buffer is safe to name here. */
        { "prop v_len VALUE_MAX+1", NODUS_T3_TM_PROP, 0, 0, 0, -1,
          (uint32_t)DNA_TM_VALUE_MAX_LEN + 1u, 0 },
    };

    nodus_t3_msg_t m;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&m, 0, sizeof(m));
        m.type = cases[i].type;
        fill_header(&m.header);
        switch (cases[i].type) {
            case NODUS_T3_TM_POL:   m.tm_pol.bm_len   = cases[i].bm_len; break;
            case NODUS_T3_TM_VOTE:  m.tm_vote.ty      = cases[i].ty;     break;
            case NODUS_T3_TM_HAS:   m.tm_has.ty       = cases[i].ty;     break;
            case NODUS_T3_TM_MAJ23: m.tm_maj23.ty     = cases[i].ty;     break;
            case NODUS_T3_TM_BITS:  m.tm_bits.ty      = cases[i].ty;
                                    m.tm_bits.bm_len  = cases[i].bm_len; break;
            case NODUS_T3_TM_STEP:  m.tm_step.s       = cases[i].s;
                                    m.tm_step.lcr     = cases[i].signed_v; break;
            case NODUS_T3_TM_PROP:  m.tm_prop.vr      = cases[i].signed_v;
                                    m.tm_prop.v_len   = cases[i].v_len;
                                    m.tm_prop.v       = cases[i].v_null ? NULL
                                                                        : small_v;
                                    break;
            default: break;
        }
        if (nodus_t3_encode(&m, &tm_sk, buf, cap, &len) == 0) {
            fprintf(stderr, "    ACCEPTED: %s\n", cases[i].what);
            TEST_FAIL(name, "encoder accepted what it must refuse");
            free(buf);
            return;
        }
    }

    free(buf);
    TEST_PASS(name);
}

/* ── Decoder negatives: a hand-built envelope, one deviation each ──
 *
 * The builder writes a complete {t, y, q, wh, a, wsig} frame so the
 * decoder sees a well-formed envelope and the ONLY thing under test is the
 * `a` map. wsig is filler — nodus_t3_decode does not verify it. */

typedef struct {
    size_t   map_count;      /* the map header the decoder is told to expect */
    uint64_t ty;             /* vote type byte                              */
    int      ty_as_bstr;     /* emit ty as a byte string (type mismatch)    */
    uint64_t h;
    int      h_as_bstr;
    uint64_t r;              /* > UINT32_MAX exercises the u32 clamp        */
    size_t   bi_len, vid_len, sig_len;
    int      omit_ts;        /* leave the ts key out entirely               */
    int      dup_h;          /* emit h a second time                        */
    int      extra_key;      /* emit a key the verb does not define         */
} vote_tweak_t;

static void tm_default_vote_tweak(vote_tweak_t *t) {
    memset(t, 0, sizeof(*t));
    t->map_count = 8;
    t->ty = 1;
    t->h  = 5;
    t->r  = 1;
    t->bi_len  = 64;
    t->vid_len = 32;
    t->sig_len = QGP_DSA87_SIGNATURE_BYTES;
}

static uint8_t tm_filler[QGP_DSA87_SIGNATURE_BYTES];

static void tm_enc_vote_map(cbor_encoder_t *enc, const vote_tweak_t *t) {
    cbor_encode_map(enc, t->map_count);

    cbor_encode_cstr(enc, "ty");
    if (t->ty_as_bstr) cbor_encode_bstr(enc, tm_filler, 1);
    else               cbor_encode_uint(enc, t->ty);

    cbor_encode_cstr(enc, "h");
    if (t->h_as_bstr) cbor_encode_bstr(enc, tm_filler, 8);
    else              cbor_encode_uint(enc, t->h);

    cbor_encode_cstr(enc, "r");   cbor_encode_uint(enc, t->r);
    cbor_encode_cstr(enc, "bi");  cbor_encode_bstr(enc, tm_filler, t->bi_len);
    cbor_encode_cstr(enc, "vid"); cbor_encode_bstr(enc, tm_filler, t->vid_len);
    cbor_encode_cstr(enc, "ix");  cbor_encode_uint(enc, 3);
    if (!t->omit_ts) {
        cbor_encode_cstr(enc, "ts"); cbor_encode_uint(enc, 1800000000000ULL);
    }
    cbor_encode_cstr(enc, "sig"); cbor_encode_bstr(enc, tm_filler, t->sig_len);
    if (t->dup_h)     { cbor_encode_cstr(enc, "h");   cbor_encode_uint(enc, 6); }
    if (t->extra_key) { cbor_encode_cstr(enc, "zzz"); cbor_encode_uint(enc, 1); }
}

/* The envelope, written once. The caller supplies the `a` map between the
 * two halves; wsig is filler because nodus_t3_decode does not verify it. */
static uint8_t tm_frame[64 * 1024];

static void tm_frame_begin(cbor_encoder_t *enc, const char *method) {
    cbor_encoder_init(enc, tm_frame, sizeof(tm_frame));
    cbor_encode_map(enc, 6);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, 42);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "q");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, method);
    /* wh — the 7 keys enc_wh emits, same order */
    cbor_encode_cstr(enc, "wh");
    cbor_encode_map(enc, 7);
    cbor_encode_cstr(enc, "v");   cbor_encode_uint(enc, NODUS_T3_BFT_PROTOCOL_VER);
    cbor_encode_cstr(enc, "rnd"); cbor_encode_uint(enc, 0);
    cbor_encode_cstr(enc, "vw");  cbor_encode_uint(enc, 0);
    cbor_encode_cstr(enc, "sid"); cbor_encode_bstr(enc, tm_filler, 32);
    cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, 1);
    cbor_encode_cstr(enc, "nc");  cbor_encode_uint(enc, 2);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, tm_filler, 32);
    cbor_encode_cstr(enc, "a");
}

static int tm_frame_end(cbor_encoder_t *enc, nodus_t3_msg_t *out) {
    cbor_encode_cstr(enc, "wsig");
    cbor_encode_bstr(enc, tm_filler, QGP_DSA87_SIGNATURE_BYTES);
    size_t len = cbor_encoder_len(enc);
    if (len == 0) return -99;               /* builder overflowed */
    return nodus_t3_decode(tm_frame, len, out);
}

/* Build the whole frame around a vote `a` map and decode it. */
static int tm_decode_vote(const vote_tweak_t *t, nodus_t3_msg_t *out) {
    cbor_encoder_t enc;
    tm_frame_begin(&enc, "w_tm_vote");
    tm_enc_vote_map(&enc, t);
    return tm_frame_end(&enc, out);
}

/* The control. If this fails, every negative below is meaningless. */
static void test_tm_decode_control(void) {
    const char *name = "tm_decode_control";
    vote_tweak_t t;
    nodus_t3_msg_t out;

    tm_default_vote_tweak(&t);
    if (tm_decode_vote(&t, &out) != 0) {
        TEST_FAIL(name, "the hand-built valid frame was REJECTED — every "
                        "negative in this file is now unproven");
        return;
    }
    if (out.type != NODUS_T3_TM_VOTE || out.tm_vote.ty != 1 ||
        out.tm_vote.h != 5 || out.tm_vote.ix != 3) {
        TEST_FAIL(name, "control decoded to the wrong fields"); return;
    }
    TEST_PASS(name);
}

static void test_tm_decode_negatives(void) {
    const char *name = "tm_decode_negatives";
    nodus_t3_msg_t out;
    vote_tweak_t t;
    int i;

    struct { const char *what; vote_tweak_t t; } cases[10];
    memset(cases, 0, sizeof(cases));
    int n = 0;

    tm_default_vote_tweak(&t); t.ty = 0;
    cases[n].what = "ty 0";            cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.ty = 3;
    cases[n].what = "ty 3";            cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.bi_len = 63;
    cases[n].what = "bi 63";           cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.bi_len = 65;
    cases[n].what = "bi 65";           cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.vid_len = 31;
    cases[n].what = "vid 31";          cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.sig_len = QGP_DSA87_SIGNATURE_BYTES - 1;
    cases[n].what = "sig 4626";        cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.omit_ts = 1; t.map_count = 7;
    cases[n].what = "missing ts key";  cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.extra_key = 1; t.map_count = 9;
    cases[n].what = "unknown key";     cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.dup_h = 1; t.map_count = 9;
    cases[n].what = "duplicate key";   cases[n].t = t; n++;
    tm_default_vote_tweak(&t); t.h_as_bstr = 1;
    cases[n].what = "h wrong type";    cases[n].t = t; n++;

    for (i = 0; i < n; i++) {
        int rc = tm_decode_vote(&cases[i].t, &out);
        if (rc == -99) {
            fprintf(stderr, "    builder overflow on: %s\n", cases[i].what);
            TEST_FAIL(name, "frame builder overflowed"); return;
        }
        if (rc == 0) {
            fprintf(stderr, "    ACCEPTED: %s\n", cases[i].what);
            TEST_FAIL(name, "decoder accepted a malformed message"); return;
        }
    }

    /* r above UINT32_MAX: the field is a u32 on the wire and in the
     * struct, so a larger value must reject rather than truncate. */
    tm_default_vote_tweak(&t);
    t.r = 0x1FFFFFFFFULL;
    if (tm_decode_vote(&t, &out) == 0) {
        TEST_FAIL(name, "r > UINT32_MAX accepted"); return;
    }

    TEST_PASS(name);
}

/* ── Decode negatives for the SIGNED fields (verbs 28/29, D-22) ──── */

static void test_tm_signed_decode_negatives(void) {
    const char *name = "tm_signed_decode_negatives";
    nodus_t3_msg_t out;
    cbor_encoder_t enc;
    int rc;

    /* CONTROLS FIRST: both builders must be able to produce something the
     * decoder ACCEPTS, or the negatives below prove nothing. */
    tm_frame_begin(&enc, "w_tm_step");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");   cbor_encode_uint(&enc, 3);
    cbor_encode_cstr(&enc, "sst"); cbor_encode_int(&enc, INT64_MIN);
    cbor_encode_cstr(&enc, "lcr"); cbor_encode_int(&enc, -1);
    if (tm_frame_end(&enc, &out) != 0) {
        TEST_FAIL(name, "the valid step control was REJECTED"); return;
    }
    if (out.tm_step.sst != INT64_MIN || out.tm_step.lcr != -1 ||
        out.tm_step.s != 3) {
        TEST_FAIL(name, "step control decoded to the wrong fields"); return;
    }

    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, -1);
    cbor_encode_cstr(&enc, "v");  cbor_encode_bstr(&enc, tm_filler, 4);
    if (tm_frame_end(&enc, &out) != 0) {
        TEST_FAIL(name, "the valid prop control was REJECTED"); return;
    }
    if (out.tm_prop.vr != -1 || out.tm_prop.v_len != 4) {
        TEST_FAIL(name, "prop control decoded to the wrong fields"); return;
    }

    /* lcr = -2 — below the reference's "none". */
    tm_frame_begin(&enc, "w_tm_step");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");   cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "sst"); cbor_encode_int(&enc, 0);
    cbor_encode_cstr(&enc, "lcr"); cbor_encode_int(&enc, -2);
    if (tm_frame_end(&enc, &out) == 0) { TEST_FAIL(name, "lcr -2 accepted"); return; }

    /* lcr above INT32_MAX — a legal CBOR uint that the i32 field cannot
     * hold; it must reject rather than truncate. */
    tm_frame_begin(&enc, "w_tm_step");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");   cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "sst"); cbor_encode_int(&enc, 0);
    cbor_encode_cstr(&enc, "lcr"); cbor_encode_int(&enc, (int64_t)INT32_MAX + 1);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "lcr above INT32_MAX accepted"); return;
    }

    /* s = 4 — outside 0..3 (D-16 rev 4 F6 added 3 = new_height). */
    tm_frame_begin(&enc, "w_tm_step");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");   cbor_encode_uint(&enc, 4);
    cbor_encode_cstr(&enc, "sst"); cbor_encode_int(&enc, 0);
    cbor_encode_cstr(&enc, "lcr"); cbor_encode_int(&enc, -1);
    if (tm_frame_end(&enc, &out) == 0) { TEST_FAIL(name, "s 4 accepted"); return; }

    /* sst as a byte string — type mismatch on a signed field. */
    tm_frame_begin(&enc, "w_tm_step");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");   cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "sst"); cbor_encode_bstr(&enc, tm_filler, 8);
    cbor_encode_cstr(&enc, "lcr"); cbor_encode_int(&enc, -1);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "sst as a bstr accepted"); return;
    }

    /* step: a key short. */
    tm_frame_begin(&enc, "w_tm_step");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "s");   cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "sst"); cbor_encode_int(&enc, 0);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "step missing lcr accepted"); return;
    }

    /* vr = -2. */
    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, -2);
    cbor_encode_cstr(&enc, "v");  cbor_encode_bstr(&enc, tm_filler, 4);
    if (tm_frame_end(&enc, &out) == 0) { TEST_FAIL(name, "vr -2 accepted"); return; }

    /* v empty — the value has no meaningful zero length. */
    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, -1);
    cbor_encode_cstr(&enc, "v");  cbor_encode_bstr(&enc, tm_filler, 0);
    if (tm_frame_end(&enc, &out) == 0) { TEST_FAIL(name, "empty v accepted"); return; }

    /* v as an unsigned integer — type mismatch. */
    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, -1);
    cbor_encode_cstr(&enc, "v");  cbor_encode_uint(&enc, 7);
    if (tm_frame_end(&enc, &out) == 0) { TEST_FAIL(name, "v as uint accepted"); return; }

    /* prop: an unknown key. */
    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr");  cbor_encode_int(&enc, -1);
    cbor_encode_cstr(&enc, "v");   cbor_encode_bstr(&enc, tm_filler, 4);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_uint(&enc, 1);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "prop unknown key accepted"); return;
    }

    /* prop: a duplicate key. */
    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "r");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, -1);
    cbor_encode_cstr(&enc, "v");  cbor_encode_bstr(&enc, tm_filler, 4);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, 0);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "prop duplicate key accepted"); return;
    }

    /* A NEGATIVE where an UNSIGNED field lives: `h` is a u64, and the only
     * door to major type 1 is cbor_decode_int, which tm_get_u64 does not
     * use — so this must reject exactly as any legacy field would. */
    tm_frame_begin(&enc, "w_tm_prop");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");  cbor_encode_int(&enc, -5);
    cbor_encode_cstr(&enc, "r");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vr"); cbor_encode_int(&enc, -1);
    cbor_encode_cstr(&enc, "v");  cbor_encode_bstr(&enc, tm_filler, 4);
    rc = tm_frame_end(&enc, &out);
    if (rc == 0) { TEST_FAIL(name, "a negative height was accepted"); return; }

    TEST_PASS(name);
}

/* ── THE LEGACY PIN (D-22 rev 2) ─────────────────────────────────────
 *
 * This test is the pin on the equivalence claim behind teaching pass 1 to
 * step over negative integers. Pass 1 now walks `a` with
 * cbor_decode_skip_signed, which does NOT error on major type 1; what keeps
 * a legacy verb's acceptance set unchanged is the type gate that follows —
 * a negative in `a` is admitted for verbs 28 and 29 only.
 *
 * IT WOULD FAIL if anyone later made the shared cbor_decode_skip tolerant
 * of negatives, or dropped the gate, or widened it past 28/29. That is the
 * whole point: the safety here is one `if`, and an `if` with no test on it
 * is one refactor away from gone.
 *
 * The control runs FIRST. If a hand-built w_sync_req frame carrying an
 * ordinary unsigned integer is not accepted, the three negatives below
 * prove nothing at all. */
static void test_tm_legacy_negint_pin(void) {
    const char *name = "tm_legacy_negint_pin";
    nodus_t3_msg_t out;
    cbor_encoder_t enc;

    /* CONTROL: w_sync_req with an unsigned `h` — must be ACCEPTED. */
    tm_frame_begin(&enc, "w_sync_req");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "h"); cbor_encode_uint(&enc, 7);
    if (tm_frame_end(&enc, &out) != 0) {
        TEST_FAIL(name, "the legacy control frame was REJECTED — the three "
                        "negatives below would prove nothing");
        return;
    }
    if (out.type != NODUS_T3_SYNC_REQ || out.sync_req.height != 7) {
        TEST_FAIL(name, "legacy control decoded to the wrong fields"); return;
    }

    /* (i) a negative under a key this verb's decoder KNOWS */
    tm_frame_begin(&enc, "w_sync_req");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "h"); cbor_encode_int(&enc, -7);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "legacy verb accepted a negative under a known key"); return;
    }

    /* (ii) a negative under a key it does NOT know — the dangerous one,
     * because the legacy arg decoder's own idiom is "unknown key -> skip". */
    tm_frame_begin(&enc, "w_sync_req");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 7);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_int(&enc, -1);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "legacy verb accepted a negative under an unknown key"); return;
    }

    /* (iii) a negative NESTED inside an array under an unknown key —
     * proves the flag propagates through the signed walker's recursion. */
    tm_frame_begin(&enc, "w_sync_req");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 7);
    cbor_encode_cstr(&enc, "zzz");
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 1);
    cbor_encode_int(&enc, -5);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "legacy verb accepted a negative nested in an array"); return;
    }

    /* And one of the NEW verbs that has no signed field either: 30-34 are
     * gated exactly like the legacy ones. */
    tm_frame_begin(&enc, "w_tm_has");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "ty");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "ix");  cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_int(&enc, -1);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "verb 32 accepted a negative in `a`"); return;
    }

    /* Sanity in the other direction: the SAME unknown key with an
     * UNSIGNED value is still rejected by verb 32's exact-key-set rule,
     * so the previous case is not passing merely because of the gate. */
    tm_frame_begin(&enc, "w_tm_has");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "h");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "r");   cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "ty");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "ix");  cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_uint(&enc, 1);
    if (tm_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "verb 32 accepted an unknown key"); return;
    }

    TEST_PASS(name);
}

/* ── Test: the per-verb ceiling table ────────────────────────────── */

static void test_tm_max_msg_size(void) {
    const char *name = "tm_max_msg_size";

    if (nodus_t3_max_msg_size(NODUS_T3_TM_PROP) != NODUS_T3_TM_PROP_MAX_MSG) {
        TEST_FAIL(name, "29 not the PROP class"); return;
    }
    if (nodus_t3_max_msg_size(NODUS_T3_TM_VOTE) != NODUS_T3_TM_VOTE_MAX_MSG) {
        TEST_FAIL(name, "31 not the VOTE class"); return;
    }
    const nodus_t3_msg_type_t small[] = {
        NODUS_T3_TM_STEP, NODUS_T3_TM_POL, NODUS_T3_TM_HAS,
        NODUS_T3_TM_MAJ23, NODUS_T3_TM_BITS
    };
    for (size_t i = 0; i < sizeof(small) / sizeof(small[0]); i++) {
        if (nodus_t3_max_msg_size(small[i]) != NODUS_T3_TM_SMALL_MAX_MSG) {
            TEST_FAIL(name, "small class mismatch"); return;
        }
    }

    /* Legacy verbs keep the bound the legacy path uses today. */
    const nodus_t3_msg_type_t legacy[] = {
        NODUS_T3_PROPOSE, NODUS_T3_COMMIT, NODUS_T3_SYNC_RSP,
        NODUS_T3_VIEWOK, NODUS_T3_V2_RANGE_RSP
    };
    for (size_t i = 0; i < sizeof(legacy) / sizeof(legacy[0]); i++) {
        if (nodus_t3_max_msg_size(legacy[i]) != (size_t)NODUS_W_MAX_SYNC_RSP_SIZE) {
            TEST_FAIL(name, "legacy bound changed"); return;
        }
    }

    /* Not a verb at all → no ceiling to report. */
    if (nodus_t3_max_msg_size((nodus_t3_msg_type_t)0) != 0 ||
        nodus_t3_max_msg_size((nodus_t3_msg_type_t)35) != 0) {
        TEST_FAIL(name, "non-verb must report 0"); return;
    }

    /* The derived bounds are the T2 §4.8 numbers. tm_bounds.h asserts this
     * at compile time; restating it here makes the value visible in the
     * test log rather than only in a build that did not fail. */
    if ((size_t)DNA_TM_VALUE_MAX_LEN != 2807586u ||
        (size_t)DNA_TM_COMMIT_MAX_LEN != 593502u) {
        TEST_FAIL(name, "derived bounds drifted from T2 §4.8"); return;
    }
    if (NODUS_T3_TM_PROP_MAX_MSG + 4u + DNA_TM_COMMIT_MAX_LEN >=
        (size_t)NODUS_MAX_FRAME_TCP) {
        TEST_FAIL(name, "T3_TM_HEAP no longer fits the TCP frame"); return;
    }
    fprintf(stderr, "    VALUE_MAX %llu, CERT_MAX %llu, PROP class %llu\n",
            (unsigned long long)DNA_TM_VALUE_MAX_LEN,
            (unsigned long long)DNA_TM_COMMIT_MAX_LEN,
            (unsigned long long)NODUS_T3_TM_PROP_MAX_MSG);

    TEST_PASS(name);
}

/* ── Test: wrong key still fails for a Tendermint verb ───────────── */

static void test_tm_verify_wrong_key(void) {
    const char *name = "tm_verify_wrong_key";
    nodus_t3_msg_t in, out;
    uint8_t *keep = NULL;
    memset(&in, 0, sizeof(in));

    /* The foreign keypair is derived FIRST, deliberately: it removes the
     * only early return that would otherwise sit between the buffer
     * hand-over and its free, so this test has exactly one free site. */
    nodus_pubkey_t other_pk;
    nodus_seckey_t other_sk;
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    if (qgp_dsa87_keypair_derand(other_pk.bytes, other_sk.bytes, seed) != 0) {
        TEST_FAIL(name, "derand keypair"); return;
    }

    in.type = NODUS_T3_TM_HAS;
    in.txn_id = 3500;
    fill_header(&in.header);
    in.tm_has.h = 1; in.tm_has.r = 0; in.tm_has.ty = 1; in.tm_has.ix = 0;

    /* `keep`, even though verb 32 copies every UNION field out: this test
     * calls nodus_t3_verify AFTER the helper returns, and verify memcpy's
     * 4627 bytes from out.wsig — which points into the encode buffer for
     * EVERY verb (nodus_tier3.h:913, set at nodus_tier3.c:2248). */
    if (tm_roundtrip(&in, &out, NULL, &keep) != 0) {
        TEST_FAIL(name, "roundtrip"); return;
    }

    int rc = nodus_t3_verify(&out, &other_pk);
    free(keep);                       /* last read of `out` is done */
    if (rc == 0) {
        TEST_FAIL(name, "verified under the wrong key"); return;
    }
    TEST_PASS(name);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void) {
    fprintf(stderr, "=== Tier 3 Protocol Tests ===\n");

    init_test_data();

    test_method_type_mapping();
    test_propose();
    test_prevote();
    test_precommit();
    test_commit();
    test_viewchg();
    test_viewchg_with_prepared();
    test_newview();
    test_newview_with_reproposal();
    test_fwd_req();
    test_fwd_rsp();
    test_rost_q();
    test_rost_r();
    test_ident();
    test_sync_req();
    test_sync_rsp();
    test_verify_wrong_key();
    test_propose_zero_nullifiers();

    /* Tendermint T3 — verbs 28-34 (T2 wire design §4.2, D-16 rev 4).
     * The control runs BEFORE the negatives it underwrites. */
    fprintf(stderr, "--- Tendermint T3 (verbs 28-34) ---\n");
    test_tm_method_table();
    test_tm_step_roundtrip();
    test_tm_step_sst_twin();
    test_tm_prop_roundtrip();
    test_tm_prop_maximal_value();
    test_tm_pol_roundtrip();
    test_tm_vote_roundtrip();
    test_tm_has_roundtrip();
    test_tm_maj23_roundtrip();
    test_tm_bits_roundtrip();
    test_tm_encode_range_negatives();
    test_tm_decode_control();
    test_tm_decode_negatives();
    test_tm_signed_decode_negatives();
    test_tm_legacy_negint_pin();
    test_tm_max_msg_size();
    test_tm_verify_wrong_key();

    fprintf(stderr, "\n%d test(s) failed\n", failures);
    return failures > 0 ? 1 : 0;
}
