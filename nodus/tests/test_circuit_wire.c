/**
 * Circuit wire protocol encode/decode roundtrip tests (Faz 1)
 */
#include "protocol/nodus_tier2.h"
#include <stdio.h>
#include <string.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;
static uint8_t msgbuf[4096];

static void test_circ_open_roundtrip(void) {
    TEST("circ_open encode/decode");
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xAB, sizeof(token));
    nodus_key_t peer_fp;
    for (int i = 0; i < NODUS_KEY_BYTES; i++) peer_fp.bytes[i] = (uint8_t)(0x40 + i);

    size_t len = 0;
    int rc = nodus_t2_circ_open(42, token, 0x1234567890ABCDEFULL, &peer_fp,
                                 msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc == 0 && msg.txn_id == 42 && msg.type == 'q' &&
        strcmp(msg.method, "circ_open") == 0 &&
        msg.has_circ &&
        msg.circ_cid == 0x1234567890ABCDEFULL &&
        nodus_key_cmp(&msg.circ_peer_fp, &peer_fp) == 0) {
        PASS();
    } else {
        FAIL("decode mismatch");
    }
    nodus_t2_msg_free(&msg);
}

int main(void) {
    printf("Circuit wire protocol tests:\n");
    test_circ_open_roundtrip();
    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
