#ifndef QGP_FINGERPRINT_H
#define QGP_FINGERPRINT_H

/**
 * @file qgp_fingerprint.h
 * @brief Fingerprint hex <-> raw byte converters (DNAC-agnostic utility).
 *
 * The canonical fingerprint form in this codebase is SHA3-512(pubkey), a
 * 64-byte digest. On the wire and in UTXO ownership fields it is carried
 * as 128 lowercase hex chars + NUL (129-byte buffer). These helpers
 * consolidate the ad-hoc inline converters that previously lived in
 * dnac/src/transaction/stake.c, nodus/src/witness/nodus_witness_bft.c,
 * dnac/src/nodus/discovery.c, and dnac/src/nodus/tcp_client.c.
 */

#include <stdint.h>
#include <stddef.h>

#define QGP_FP_RAW_BYTES     64
#define QGP_FP_HEX_CHARS     128
#define QGP_FP_HEX_BUFFER    129  /* 128 hex + NUL */

#ifdef __cplusplus
extern "C" {
#endif

/** Encode a 64-byte raw fingerprint as a 128-char lowercase hex string.
 *  @param raw 64 input bytes (SHA3-512 digest).
 *  @param out Buffer of at least QGP_FP_HEX_BUFFER bytes.
 *             Written as NUL-terminated C string. */
void qgp_fp_raw_to_hex(const uint8_t raw[QGP_FP_RAW_BYTES],
                       char out[QGP_FP_HEX_BUFFER]);

/** Parse a 128-char lowercase hex string into a 64-byte raw fingerprint.
 *  Only characters [0-9a-f] are accepted (no uppercase, no separators).
 *  @param hex NUL-terminated input; must be exactly 128 characters.
 *  @param raw_out 64-byte destination.
 *  @return 0 on success, -1 on length or charset error. */
int qgp_fp_hex_to_raw(const char *hex,
                      uint8_t raw_out[QGP_FP_RAW_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* QGP_FINGERPRINT_H */
