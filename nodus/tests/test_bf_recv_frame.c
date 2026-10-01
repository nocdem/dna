/**
 * Nodus — DHT Package A (A3): the batch-forward receive path reads the
 * frame header the way the wire writes it.
 *
 * bf_recv_frame (nodus_server.c) delegates its header check to
 * nodus_server_bf_frame_status (nodus_server.h, internal section); this
 * test drives that helper in-process with frames built by
 * nodus_frame_encode, the encoder every sender uses.
 *
 * Pins down:
 *   1. A frame built with nodus_frame_encode is complete at exactly its
 *      length, and incomplete one byte short of it (and with the header
 *      itself short).
 *   2. A declared length whose frame is larger than the receive buffer
 *      can ever hold is an error (-1), not "need more".
 *   3. Bad magic is an error (-1).
 *   4. A frame version the transport does not accept is an error (-1);
 *      the legacy version it does accept is not.
 *
 * RED on the tree before A3: the length was parsed BIG-endian, so the
 * 300-byte payload of check 1 was read as 0x2C010000 (~738 M) bytes and
 * the frame never completed; check 2 and 4 did not exist.
 */

#include "server/nodus_server.h"
#include "protocol/nodus_wire.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

#define PAYLOAD_LEN 300u
#define CAP         4096u

static uint8_t frame_buf[CAP];
static size_t  frame_len;

static int build_frame(void) {
    uint8_t payload[PAYLOAD_LEN];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i * 7u + 1u);
    frame_len = nodus_frame_encode(frame_buf, sizeof(frame_buf),
                                   payload, PAYLOAD_LEN);
    return frame_len == NODUS_FRAME_HEADER_SIZE + PAYLOAD_LEN ? 0 : -1;
}

static void test_complete_at_exact_length(void) {
    TEST("encoded frame: complete at its length, not one byte short");
    CHECK(build_frame() == 0, "nodus_frame_encode");
    CHECK(nodus_server_bf_frame_status(frame_buf, frame_len, CAP) == 1,
          "full frame not recognised as complete");
    CHECK(nodus_server_bf_frame_status(frame_buf, frame_len - 1, CAP) == 0,
          "frame one byte short not 'need more'");
    CHECK(nodus_server_bf_frame_status(frame_buf, NODUS_FRAME_HEADER_SIZE, CAP) == 0,
          "header only not 'need more'");
    CHECK(nodus_server_bf_frame_status(frame_buf, NODUS_FRAME_HEADER_SIZE - 1, CAP) == 0,
          "short header not 'need more'");
    CHECK(nodus_server_bf_frame_status(frame_buf, 0, CAP) == 0,
          "empty buffer not 'need more'");
    PASS();
out:
    return;
}

static void test_length_over_cap(void) {
    TEST("declared frame larger than the receive buffer: -1");
    CHECK(build_frame() == 0, "nodus_frame_encode");
    /* Exactly the frame size fits; one byte less cap can never hold it. */
    CHECK(nodus_server_bf_frame_status(frame_buf, NODUS_FRAME_HEADER_SIZE,
                                       frame_len) == 0,
          "frame that exactly fits the buffer refused");
    CHECK(nodus_server_bf_frame_status(frame_buf, NODUS_FRAME_HEADER_SIZE,
                                       frame_len - 1) == -1,
          "frame one byte over the buffer not refused");
    /* A header declaring ~4 GB in a 4 KB buffer, header only received. */
    uint8_t hdr[NODUS_FRAME_HEADER_SIZE];
    memcpy(hdr, frame_buf, sizeof(hdr));
    hdr[3] = 0xFF; hdr[4] = 0xFF; hdr[5] = 0xFF; hdr[6] = 0xFF;
    CHECK(nodus_server_bf_frame_status(hdr, sizeof(hdr), CAP) == -1,
          "huge declared length not refused");
    PASS();
out:
    return;
}

static void test_bad_magic(void) {
    TEST("bad magic: -1");
    CHECK(build_frame() == 0, "nodus_frame_encode");
    uint8_t bad[CAP];
    memcpy(bad, frame_buf, frame_len);
    bad[0] ^= 0xFF;
    CHECK(nodus_server_bf_frame_status(bad, frame_len, CAP) == -1,
          "bad first magic byte accepted");
    memcpy(bad, frame_buf, frame_len);
    bad[1] ^= 0xFF;
    CHECK(nodus_server_bf_frame_status(bad, NODUS_FRAME_HEADER_SIZE, CAP) == -1,
          "bad second magic byte accepted (header only)");
    PASS();
out:
    return;
}

static void test_version(void) {
    TEST("unknown frame version: -1; legacy version accepted");
    CHECK(build_frame() == 0, "nodus_frame_encode");
    uint8_t v[CAP];
    memcpy(v, frame_buf, frame_len);
    v[2] = 0x7F;
    CHECK(nodus_server_bf_frame_status(v, frame_len, CAP) == -1,
          "unknown version accepted");
    v[2] = NODUS_FRAME_VERSION_LEGACY;
    CHECK(nodus_server_bf_frame_status(v, frame_len, CAP) == 1,
          "legacy version refused (transport accepts it)");
    PASS();
out:
    return;
}

int main(void) {
    printf("test_bf_recv_frame\n");
    test_complete_at_exact_length();
    test_length_over_cap();
    test_bad_magic();
    test_version();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
