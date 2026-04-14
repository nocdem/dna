/**
 * Nodus — Tier 3 Protocol Unit Test
 *
 * Round-trip encode/decode test for all 11 BFT message types.
 * Tests: encode → decode → verify field equality.
 * Also tests sign/verify round-trip.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

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

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_VIEWCHG) { TEST_FAIL(name, "type"); return; }
    if (out.viewchg.new_view != 5) { TEST_FAIL(name, "new_view"); return; }
    if (out.viewchg.last_committed_round != 41) { TEST_FAIL(name, "lcr"); return; }
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

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_NEWVIEW) { TEST_FAIL(name, "type"); return; }
    if (out.newview.new_view != 5) { TEST_FAIL(name, "new_view"); return; }
    if (out.newview.n_proofs != 3) { TEST_FAIL(name, "n_proofs"); return; }
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
    test_newview();
    test_fwd_req();
    test_fwd_rsp();
    test_rost_q();
    test_rost_r();
    test_ident();
    test_sync_req();
    test_sync_rsp();
    test_verify_wrong_key();
    test_propose_zero_nullifiers();

    fprintf(stderr, "\n%d test(s) failed\n", failures);
    return failures > 0 ? 1 : 0;
}
