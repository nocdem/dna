/**
 * Nodus — Tier 3 oversize sync_rsp wsig verify regression
 *
 * Reproduces the production halt of 2026-05-03: post-genesis chain
 * e154cff9... wedged at heights 389/396 because sync_rsp messages
 * carrying batch_txs whose serialized {q, wh, a} payload exceeds the
 * 128 KB NODUS_T3_MAX_MSG_SIZE could be encoded by the sender
 * (which uses NODUS_W_MAX_SYNC_RSP_SIZE = 1 MB at
 * nodus/src/witness/nodus_witness_sync.c:647) but failed wsig
 * verification on every receiver, because nodus_t3_verify allocates
 * its re-encode buffer at the smaller 128 KB cap.
 *
 * Block 390 on the live cluster: 8 TXs × 7912 B tx_data each + full
 * pk/csig per TX → ~146 KB sync_rsp args, exceeds 128 KB.
 *
 * Test shape: build the same kind of message, encode with the 1 MB
 * sender cap, assert wire-size crosses the 128 KB boundary so we
 * know we're exercising the bug, then call nodus_t3_verify and
 * expect success. Without the fix, verify fails.
 */

#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } } while (0)

int main(void) {
    fprintf(stderr, "=== Tier 3 oversize sync_rsp verify ===\n");

    nodus_identity_t id;
    CHECK(nodus_identity_generate(&id) == 0);

    /* Build sync_rsp matching live cluster block 390 shape.
     * 8 TXs, each with tx_data sized to push args > 128 KB. */
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    msg.type = NODUS_T3_SYNC_RSP;
    msg.txn_id = 0xdeadbeef;
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    msg.header.round = 390;
    msg.header.view = 0;
    memset(msg.header.sender_id, 0xAA, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = 1714700000;
    msg.header.nonce = 0x1234;
    memset(msg.header.chain_id, 0xCD, 32);

    msg.sync_rsp.found = true;
    msg.sync_rsp.height = 390;
    msg.sync_rsp.timestamp = 1714700000;
    memset(msg.sync_rsp.proposer_id, 0xBB, NODUS_T3_WITNESS_ID_LEN);
    memset(msg.sync_rsp.prev_hash, 0xCC, NODUS_T3_TX_HASH_LEN);
    memset(msg.sync_rsp.tx_root, 0xDD, NODUS_T3_TX_HASH_LEN);
    memset(msg.sync_rsp.state_root, 0xEE, NODUS_KEY_BYTES);

    /* Per-TX payload — observed live-cluster size 7912 B. */
    static uint8_t tx_data[7912];
    static uint8_t tx_pk[NODUS_PK_BYTES];
    static uint8_t tx_sig[NODUS_SIG_BYTES];
    for (size_t i = 0; i < sizeof(tx_data); i++) tx_data[i] = (uint8_t)(i & 0xFF);
    memset(tx_pk, 0x11, NODUS_PK_BYTES);
    memset(tx_sig, 0x22, NODUS_SIG_BYTES);

    msg.sync_rsp.tx_count = 8;
    for (int i = 0; i < 8; i++) {
        nodus_t3_batch_tx_t *btx = &msg.sync_rsp.batch_txs[i];
        memset(btx->tx_hash, (uint8_t)(0x40 + i), NODUS_T3_TX_HASH_LEN);
        btx->nullifier_count = 0;
        btx->tx_type = 1; /* SPEND */
        btx->tx_data = tx_data;
        btx->tx_len = sizeof(tx_data);
        btx->client_pubkey = tx_pk;
        btx->client_sig = tx_sig;
        btx->fee = 1;
    }

    /* Five precommit certs — typical 7-node-cluster quorum. */
    msg.sync_rsp.cert_count = 5;
    for (uint32_t i = 0; i < msg.sync_rsp.cert_count; i++) {
        memset(msg.sync_rsp.certs[i].voter_id, (uint8_t)(0x80 + i),
               NODUS_T3_WITNESS_ID_LEN);
        memset(msg.sync_rsp.certs[i].signature, (uint8_t)(0x90 + i),
               NODUS_SIG_BYTES);
    }

    /* Encode with the same cap the production sender uses
     * (nodus/src/witness/nodus_witness_sync.c:647). */
    uint8_t *wire = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    CHECK(wire != NULL);
    size_t wire_len = 0;
    int rc = nodus_t3_encode(&msg, &id.sk, wire, NODUS_W_MAX_SYNC_RSP_SIZE,
                              &wire_len);
    CHECK(rc == 0);
    fprintf(stderr, "  encoded wire bytes : %zu\n", wire_len);

    /* The whole point of the regression: wire must cross the 128 KB
     * boundary, otherwise we are not actually exercising the bug. */
    CHECK(wire_len > NODUS_T3_MAX_MSG_SIZE);

    /* Decode (receiver path) — must succeed. Decoder is not capped. */
    nodus_t3_msg_t out;
    CHECK(nodus_t3_decode(wire, wire_len, &out) == 0);
    CHECK(out.type == NODUS_T3_SYNC_RSP);
    CHECK(out.sync_rsp.tx_count == 8);

    /* Receiver wsig verify — this is the bug. Without the fix it
     * returns -1 because nodus_t3_verify mallocs only
     * NODUS_T3_MAX_MSG_SIZE for the re-encode buffer and the CBOR
     * encoder hits cap before the {q, wh, a} payload is rebuilt. */
    int verify_rc = nodus_t3_verify(&out, &id.pk);
    fprintf(stderr, "  nodus_t3_verify rc : %d\n", verify_rc);

    free(wire);

    if (verify_rc != 0) {
        fprintf(stderr, "FAIL — wsig verify failed for oversize sync_rsp "
                "(receiver re-encode cap < sender cap)\n");
        return 1;
    }

    fprintf(stderr, "PASS\n");
    return 0;
}
