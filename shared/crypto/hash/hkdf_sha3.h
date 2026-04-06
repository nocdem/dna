/**
 * HKDF-SHA3-256 Key Derivation Function
 *
 * RFC 5869-style Extract-then-Expand using HMAC-SHA3-256.
 * Single-iteration expand (max 32 bytes output = SHA3-256 digest size).
 *
 * Used by: GEK ratchet, Nodus channel encryption key derivation.
 *
 * @file hkdf_sha3.h
 */

#ifndef HKDF_SHA3_H
#define HKDF_SHA3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC-SHA3-256
 *
 * @param key       HMAC key
 * @param key_len   Key length
 * @param data      Data to authenticate
 * @param data_len  Data length
 * @param mac_out   Output buffer (must be at least 32 bytes)
 * @param mac_len   Output: actual MAC length
 * @return          0 on success, -1 on error
 */
int hmac_sha3_256(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t *mac_out, size_t *mac_len);

/**
 * HKDF-SHA3-256: Extract-then-Expand key derivation
 *
 * @param salt     Salt bytes
 * @param salt_len Salt length
 * @param ikm      Input keying material
 * @param ikm_len  IKM length
 * @param info     Context/application info string
 * @param info_len Info length
 * @param okm      Output keying material buffer
 * @param okm_len  Desired output length (max 32 bytes)
 * @return 0 on success, -1 on error
 */
int hkdf_sha3_256(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_SHA3_H */
