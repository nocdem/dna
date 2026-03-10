/**
 * Nodus — Wire Frame Protocol
 *
 * 7-byte header: Magic("ND") + Version(1) + Length(4, LE32)
 */

#include "protocol/nodus_wire.h"
#include <string.h>

size_t nodus_frame_encode(uint8_t *buf, size_t buf_cap,
                          const uint8_t *payload, uint32_t payload_len) {
    size_t total = NODUS_FRAME_HEADER_SIZE + payload_len;
    if (!buf || buf_cap < total)
        return 0;

    /* Magic "ND" */
    buf[0] = (NODUS_FRAME_MAGIC >> 8) & 0xFF;  /* 'N' = 0x4E */
    buf[1] = NODUS_FRAME_MAGIC & 0xFF;          /* 'D' = 0x44 */

    /* Version */
    buf[2] = NODUS_FRAME_VERSION;

    /* Length (little-endian 32-bit) */
    buf[3] = (uint8_t)(payload_len);
    buf[4] = (uint8_t)(payload_len >> 8);
    buf[5] = (uint8_t)(payload_len >> 16);
    buf[6] = (uint8_t)(payload_len >> 24);

    /* Payload */
    if (payload_len > 0 && payload)
        memcpy(buf + NODUS_FRAME_HEADER_SIZE, payload, payload_len);

    return total;
}

int nodus_frame_decode(const uint8_t *buf, size_t buf_len, nodus_frame_t *frame) {
    if (!buf || !frame)
        return -1;

    /* Need at least the header */
    if (buf_len < NODUS_FRAME_HEADER_SIZE)
        return 0;  /* Incomplete */

    /* Verify magic */
    uint16_t magic = ((uint16_t)buf[0] << 8) | buf[1];
    if (magic != NODUS_FRAME_MAGIC)
        return -1;

    frame->version = buf[2];

    /* Length (little-endian) */
    frame->payload_len = (uint32_t)buf[3] |
                         ((uint32_t)buf[4] << 8) |
                         ((uint32_t)buf[5] << 16) |
                         ((uint32_t)buf[6] << 24);

    size_t total = NODUS_FRAME_HEADER_SIZE + frame->payload_len;

    /* Check if full frame available */
    if (buf_len < total)
        return 0;  /* Need more data */

    frame->payload = buf + NODUS_FRAME_HEADER_SIZE;
    return (int)total;
}

bool nodus_frame_validate(const nodus_frame_t *frame, bool is_udp) {
    if (!frame)
        return false;

    if (frame->version != NODUS_FRAME_VERSION)
        return false;

    uint32_t max_size = is_udp ? NODUS_MAX_FRAME_UDP : NODUS_MAX_FRAME_TCP;
    if (frame->payload_len > max_size)
        return false;

    return true;
}
