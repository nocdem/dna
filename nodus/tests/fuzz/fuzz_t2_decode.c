/**
 * @file fuzz_t2_decode.c
 * @brief libFuzzer harness: tier-2 reply decode (what a client runs on
 *        every frame a node sends it).
 *
 * Entry points (all exported, none modified):
 *   nodus_frame_decode      src/protocol/nodus_wire.c:41
 *   nodus_frame_validate    src/protocol/nodus_wire.c  (after decode)
 *   nodus_t2_decode         src/protocol/nodus_tier2.c:2898
 *   nodus_value_verify      src/core/nodus_value.c     (on every decoded value)
 *   nodus_t2_msg_free       src/protocol/nodus_tier2.c:2914
 *
 * Input: if the bytes parse as one complete, valid TCP frame (magic 0x4E44,
 * 7-byte header), the frame payload is decoded; otherwise the whole input is
 * treated as a decrypted tier-2 payload. After the channel handshake the
 * payload a client decodes is the plaintext of an AES-256-GCM frame the NODE
 * produced, so a malicious or buggy node (web Connect design §5 A4) controls
 * every byte that reaches nodus_t2_decode — the channel layer authenticates
 * the node, not the content.
 *
 * Every value the decoder hands back is signature-checked the way the web
 * core's read primitive (design §1.4 R0) will do it, so the verify path runs
 * on attacker-shaped owner_pk / sig / data lengths too.
 */

#include <stdint.h>
#include <stddef.h>

#include "protocol/nodus_wire.h"
#include "protocol/nodus_tier2.h"
#include "core/nodus_value.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *payload = data;
    size_t payload_len = size;

    nodus_frame_t frame;
    int consumed = nodus_frame_decode(data, size, &frame);
    if (consumed > 0 && nodus_frame_validate(&frame, false)) {
        payload = frame.payload;
        payload_len = frame.payload_len;
    }

    nodus_tier2_msg_t msg;
    if (nodus_t2_decode(payload, payload_len, &msg) != 0) {
        /* nodus_t2_decode frees and zeroes msg on failure */
        return 0;
    }

    if (msg.value) {
        (void)nodus_value_verify(msg.value);
    }
    if (msg.values) {
        for (size_t i = 0; i < msg.value_count; i++) {
            if (msg.values[i]) {
                (void)nodus_value_verify(msg.values[i]);
            }
        }
    }

    nodus_t2_msg_free(&msg);
    return 0;
}
