/**
 * @file eth_rlp.c
 * @brief RLP Encoding Implementation
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "eth_rlp.h"
#include "../../crypto/utils/qgp_log.h"
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "ETH_RLP"

/* Default buffer capacity */
#define DEFAULT_CAPACITY    256

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

/**
 * Ensure buffer has capacity for additional bytes
 */
static int ensure_capacity(eth_rlp_buffer_t *buf, size_t additional) {
    if (buf->len + additional <= buf->capacity) {
        return 0;
    }

    /* Grow buffer */
    size_t new_cap = buf->capacity * 2;
    if (new_cap < buf->len + additional) {
        new_cap = buf->len + additional + DEFAULT_CAPACITY;
    }

    uint8_t *new_data = realloc(buf->data, new_cap);
    if (!new_data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to grow RLP buffer");
        return -1;
    }

    buf->data = new_data;
    buf->capacity = new_cap;
    return 0;
}

/**
 * Count bytes needed to encode length as big-endian
 */
static int count_length_bytes(size_t len) {
    if (len <= 0xFF) return 1;
    if (len <= 0xFFFF) return 2;
    if (len <= 0xFFFFFF) return 3;
    if (len <= 0xFFFFFFFF) return 4;
    return 8;
}

/**
 * Write length as big-endian bytes
 */
static void write_length_be(uint8_t *out, size_t len, int num_bytes) {
    for (int i = num_bytes - 1; i >= 0; i--) {
        out[i] = (uint8_t)(len & 0xFF);
        len >>= 8;
    }
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int eth_rlp_init(eth_rlp_buffer_t *buf, size_t capacity) {
    if (!buf) {
        return -1;
    }

    if (capacity == 0) {
        capacity = DEFAULT_CAPACITY;
    }

    buf->data = malloc(capacity);
    if (!buf->data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate RLP buffer");
        return -1;
    }

    buf->len = 0;
    buf->capacity = capacity;
    return 0;
}

void eth_rlp_free(eth_rlp_buffer_t *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = 0;
    }
}

void eth_rlp_reset(eth_rlp_buffer_t *buf) {
    if (buf) {
        buf->len = 0;
    }
}

int eth_rlp_encode_bytes(eth_rlp_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!buf) {
        return -1;
    }

    /* Single byte 0x00-0x7f: encoded as itself */
    if (len == 1 && data && data[0] <= 0x7f) {
        if (ensure_capacity(buf, 1) != 0) {
            return -1;
        }
        buf->data[buf->len++] = data[0];
        return 0;
    }

    /* String 0-55 bytes: 0x80 + len, then string */
    if (len <= 55) {
        if (ensure_capacity(buf, 1 + len) != 0) {
            return -1;
        }
        buf->data[buf->len++] = (uint8_t)(0x80 + len);
        if (len > 0 && data) {
            memcpy(buf->data + buf->len, data, len);
            buf->len += len;
        }
        return 0;
    }

    /* String >55 bytes: 0xb7 + len_of_len, then len, then string */
    int len_bytes = count_length_bytes(len);
    if (ensure_capacity(buf, 1 + len_bytes + len) != 0) {
        return -1;
    }

    buf->data[buf->len++] = (uint8_t)(0xb7 + len_bytes);
    write_length_be(buf->data + buf->len, len, len_bytes);
    buf->len += len_bytes;

    if (data) {
        memcpy(buf->data + buf->len, data, len);
        buf->len += len;
    }

    return 0;
}

int eth_rlp_encode_uint64(eth_rlp_buffer_t *buf, uint64_t value) {
    if (!buf) {
        return -1;
    }

    /* Zero is encoded as empty string (0x80) */
    if (value == 0) {
        if (ensure_capacity(buf, 1) != 0) {
            return -1;
        }
        buf->data[buf->len++] = 0x80;
        return 0;
    }

    /* Convert to big-endian bytes, strip leading zeros */
    uint8_t bytes[8];
    int num_bytes = 0;

    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)((value >> (i * 8)) & 0xFF);
        if (num_bytes > 0 || b != 0) {
            bytes[num_bytes++] = b;
        }
    }

    /* Single byte 0x00-0x7f: encoded directly */
    if (num_bytes == 1 && bytes[0] <= 0x7f) {
        if (ensure_capacity(buf, 1) != 0) {
            return -1;
        }
        buf->data[buf->len++] = bytes[0];
        return 0;
    }

    /* Encode as short string */
    if (ensure_capacity(buf, 1 + num_bytes) != 0) {
        return -1;
    }

    buf->data[buf->len++] = (uint8_t)(0x80 + num_bytes);
    memcpy(buf->data + buf->len, bytes, num_bytes);
    buf->len += num_bytes;

    return 0;
}

int eth_rlp_encode_uint256(eth_rlp_buffer_t *buf, const uint8_t value[32]) {
    if (!buf || !value) {
        return -1;
    }

    /* Find first non-zero byte */
    int first_nonzero = 0;
    while (first_nonzero < 32 && value[first_nonzero] == 0) {
        first_nonzero++;
    }

    /* All zeros - encode as empty string */
    if (first_nonzero == 32) {
        if (ensure_capacity(buf, 1) != 0) {
            return -1;
        }
        buf->data[buf->len++] = 0x80;
        return 0;
    }

    /* Encode remaining bytes */
    int num_bytes = 32 - first_nonzero;
    const uint8_t *data = value + first_nonzero;

    return eth_rlp_encode_bytes(buf, data, num_bytes);
}

int eth_rlp_begin_list(eth_rlp_buffer_t *buf) {
    if (!buf) {
        return -1;
    }

    /* Reserve maximum space for list header (9 bytes for very long lists) */
    if (ensure_capacity(buf, 9) != 0) {
        return -1;
    }

    /* Return current position (before we start the list) */
    int pos = (int)buf->len;

    /* Reserve 9 bytes for header - we'll patch this later */
    buf->len += 9;

    return pos;
}

int eth_rlp_end_list(eth_rlp_buffer_t *buf, int pos) {
    if (!buf || pos < 0 || (size_t)pos > buf->len) {
        return -1;
    }

    /* Calculate payload length (everything after the reserved 9 bytes) */
    size_t payload_start = (size_t)pos + 9;
    size_t payload_len = buf->len - payload_start;

    /* Determine header size */
    int header_size;
    uint8_t header[9];

    if (payload_len <= 55) {
        /* Short list: 0xc0 + len */
        header_size = 1;
        header[0] = (uint8_t)(0xc0 + payload_len);
    } else {
        /* Long list: 0xf7 + len_of_len, then len */
        int len_bytes = count_length_bytes(payload_len);
        header_size = 1 + len_bytes;
        header[0] = (uint8_t)(0xf7 + len_bytes);
        write_length_be(header + 1, payload_len, len_bytes);
    }

    /* Calculate how much to shift */
    int shift = 9 - header_size;

    /* Move payload to remove excess header space */
    if (shift > 0) {
        memmove(buf->data + pos + header_size, buf->data + payload_start, payload_len);
        buf->len -= shift;
    }

    /* Write header */
    memcpy(buf->data + pos, header, header_size);

    return 0;
}

int eth_rlp_wrap_list(const uint8_t *items, size_t items_len, eth_rlp_buffer_t *out) {
    if (!out) {
        return -1;
    }

    eth_rlp_reset(out);

    if (items_len <= 55) {
        /* Short list */
        if (ensure_capacity(out, 1 + items_len) != 0) {
            return -1;
        }
        out->data[out->len++] = (uint8_t)(0xc0 + items_len);
    } else {
        /* Long list */
        int len_bytes = count_length_bytes(items_len);
        if (ensure_capacity(out, 1 + len_bytes + items_len) != 0) {
            return -1;
        }
        out->data[out->len++] = (uint8_t)(0xf7 + len_bytes);
        write_length_be(out->data + out->len, items_len, len_bytes);
        out->len += len_bytes;
    }

    if (items && items_len > 0) {
        memcpy(out->data + out->len, items, items_len);
        out->len += items_len;
    }

    return 0;
}
