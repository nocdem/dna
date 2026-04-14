/**
 * Nodus — Phase 9 / Task 9.6 — strict top-level decoder tests
 *
 * Locks the Phase 9.3 invariant that nodus_t3_decode rejects any
 * top-level CBOR key outside the canonical envelope set
 *   { t, q, y, wh, wsig, a }.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;
static nodus_identity_t test_id;

static void test_canonical_envelope_decodes(void) {
    TEST("canonical 6-key envelope decodes");

    /* Build a minimal valid w_sync_req via the encoder so we know
     * the layout matches production. */
    nodus_identity_generate(&test_id);
    nodus_t3_msg_t in;
    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_SYNC_REQ;
    in.txn_id = 1;
    in.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(in.header.sender_id, test_id.node_id.bytes, NODUS_T3_WITNESS_ID_LEN);
    in.header.timestamp = 1700000000;
    in.header.nonce = 1;
    memset(in.header.chain_id, 0xC0, 32);
    in.sync_req.height = 5;

    uint8_t buf[8192];
    size_t len = 0;
    if (nodus_t3_encode(&in, &test_id.sk, buf, sizeof(buf), &len) != 0) {
        FAIL("encode"); return;
    }

    nodus_t3_msg_t out;
    if (nodus_t3_decode(buf, len, &out) != 0) {
        FAIL("decode of canonical envelope"); return;
    }
    PASS();
}

static void test_extra_top_level_key_rejected(void) {
    TEST("extra top-level shadow key rejected");

    /* Hand-craft a CBOR envelope with a bogus 'XXX' key alongside
     * the legit ones. Build using the cbor encoder to avoid raw byte
     * footguns. */
    uint8_t buf[1024];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "t");    cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y");    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");    cbor_encode_cstr(&enc, "w_sync_req");
    /* fake wh map with empty content */
    cbor_encode_cstr(&enc, "wh");   cbor_encode_map(&enc, 0);
    cbor_encode_cstr(&enc, "a");    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "h");    cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "wsig"); cbor_encode_bstr(&enc, (uint8_t[NODUS_SIG_BYTES]){0}, NODUS_SIG_BYTES);
    /* SHADOW: bogus key */
    cbor_encode_cstr(&enc, "XXX");  cbor_encode_uint(&enc, 0xDEADBEEF);

    size_t len = cbor_encoder_len(&enc);
    nodus_t3_msg_t out;
    int rc = nodus_t3_decode(buf, len, &out);
    if (rc == 0) {
        FAIL("strict decoder accepted shadow key"); return;
    }
    PASS();
}

static void test_unknown_key_in_first_position_rejected(void) {
    TEST("shadow key in first position rejected");

    uint8_t buf[1024];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 6);
    /* SHADOW first */
    cbor_encode_cstr(&enc, "Z");    cbor_encode_uint(&enc, 0);
    cbor_encode_cstr(&enc, "t");    cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y");    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");    cbor_encode_cstr(&enc, "w_sync_req");
    cbor_encode_cstr(&enc, "wh");   cbor_encode_map(&enc, 0);
    cbor_encode_cstr(&enc, "a");    cbor_encode_map(&enc, 0);

    size_t len = cbor_encoder_len(&enc);
    nodus_t3_msg_t out;
    int rc = nodus_t3_decode(buf, len, &out);
    if (rc == 0) {
        FAIL("strict decoder accepted leading shadow key"); return;
    }
    PASS();
}

int main(void) {
    printf("T3 strict top-level decoder tests\n");
    printf("=================================\n");

    test_canonical_envelope_decodes();
    test_extra_top_level_key_rejected();
    test_unknown_key_in_first_position_rejected();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
