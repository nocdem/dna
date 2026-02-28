/**
 * Nodus v5 — Wire Frame Protocol
 *
 * 7-byte header: Magic("ND") + Version(1) + Length(4, LE32)
 * Shared by both UDP and TCP transports.
 *
 * @file nodus_wire.h
 */

#ifndef NODUS_WIRE_H
#define NODUS_WIRE_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Wire frame (header + payload reference) */
typedef struct {
    uint8_t  version;
    uint32_t payload_len;
    const uint8_t *payload;     /* Points into source buffer */
} nodus_frame_t;

/**
 * Write frame header into buffer.
 *
 * @param buf        Output buffer (must be >= NODUS_FRAME_HEADER_SIZE + payload_len)
 * @param buf_cap    Buffer capacity
 * @param payload    Payload data
 * @param payload_len Payload length
 * @return Total frame size (header + payload), or 0 on error
 */
size_t nodus_frame_encode(uint8_t *buf, size_t buf_cap,
                          const uint8_t *payload, uint32_t payload_len);

/**
 * Parse frame header from buffer.
 *
 * @param buf     Input buffer
 * @param buf_len Available bytes
 * @param frame   Output parsed frame
 * @return Total frame size consumed, 0 if incomplete, -1 on error
 *
 * On success, frame->payload points into buf (no copy).
 * Returns 0 if buf_len < header size or < header + payload_len (need more data).
 */
int nodus_frame_decode(const uint8_t *buf, size_t buf_len, nodus_frame_t *frame);

/**
 * Validate frame for given transport.
 *
 * @param frame     Parsed frame
 * @param is_udp    true = enforce UDP size limit, false = TCP limit
 * @return true if valid
 */
bool nodus_frame_validate(const nodus_frame_t *frame, bool is_udp);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WIRE_H */
