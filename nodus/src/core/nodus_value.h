/**
 * Nodus — DHT Value Operations
 *
 * Create, sign, verify, serialize/deserialize NodusValue.
 * Signature covers: key + data + type + ttl + vid + seq
 *
 * @file nodus_value.h
 */

#ifndef NODUS_VALUE_H
#define NODUS_VALUE_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new NodusValue (unsigned — call nodus_value_sign() after).
 *
 * @param key_hash  SHA3-512 of the DHT key
 * @param data      Payload bytes (copied)
 * @param data_len  Payload length
 * @param type      EPHEMERAL or PERMANENT
 * @param ttl       TTL in seconds (0 = permanent)
 * @param value_id  Writer-specific value ID
 * @param seq       Sequence number
 * @param owner_pk  Owner's Dilithium5 public key
 * @param val_out   Output value (caller must free with nodus_value_free)
 * @return 0 on success, -1 on error
 */
int nodus_value_create(const nodus_key_t *key_hash,
                       const uint8_t *data, size_t data_len,
                       nodus_value_type_t type, uint32_t ttl,
                       uint64_t value_id, uint64_t seq,
                       const nodus_pubkey_t *owner_pk,
                       nodus_value_t **val_out);

/**
 * Sign a NodusValue with owner's secret key.
 * Signs: key_hash + data + type + ttl + value_id + seq
 *
 * @param val  Value to sign (signature field written)
 * @param sk   Owner's Dilithium5 secret key
 * @return 0 on success, -1 on error
 */
int nodus_value_sign(nodus_value_t *val, const nodus_seckey_t *sk);

/**
 * Verify a NodusValue's signature against its owner_pk.
 *
 * @param val  Value to verify
 * @return 0 if valid, -1 if invalid or error
 */
int nodus_value_verify(const nodus_value_t *val);

/**
 * Serialize NodusValue to CBOR.
 *
 * @param val       Value to serialize
 * @param buf_out   Output buffer (allocated, caller must free)
 * @param len_out   Output length
 * @return 0 on success, -1 on error
 */
int nodus_value_serialize(const nodus_value_t *val,
                          uint8_t **buf_out, size_t *len_out);

/**
 * Deserialize NodusValue from CBOR.
 *
 * @param buf       CBOR data
 * @param len       CBOR data length
 * @param val_out   Output value (caller must free with nodus_value_free)
 * @return 0 on success, -1 on error
 */
int nodus_value_deserialize(const uint8_t *buf, size_t len,
                            nodus_value_t **val_out);

/**
 * Free a NodusValue (and its data buffer).
 */
void nodus_value_free(nodus_value_t *val);

/**
 * Check if a value has expired.
 *
 * @param val       Value to check
 * @param now_unix  Current unix timestamp
 * @return true if expired
 */
bool nodus_value_is_expired(const nodus_value_t *val, uint64_t now_unix);

/**
 * Build the signing payload for a value.
 * Internal helper exposed for testing.
 *
 * @param val       Value
 * @param buf_out   Allocated buffer (caller frees)
 * @param len_out   Length
 * @return 0 on success
 */
int nodus_value_sign_payload(const nodus_value_t *val,
                             uint8_t **buf_out, size_t *len_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_VALUE_H */
