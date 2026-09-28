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
 * @param type      EPHEMERAL, PERMANENT or EXCLUSIVE; any other value is
 *                  refused (nodus_value_type_valid)
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
 * Refused (-1, nothing allocated): *val_out already non-NULL (the caller
 * would lose that value), a repeated map key, or a "type" outside
 * nodus_value_type_valid().
 *
 * @param val_out   Output value; *val_out must be NULL on entry
 *                  (caller must free the result with nodus_value_free)
 * @return 0 on success, -1 on error
 */
int nodus_value_deserialize(const uint8_t *buf, size_t len,
                            nodus_value_t **val_out);

/**
 * True if @p type is one of the three value types this protocol defines
 * (EPHEMERAL=1, PERMANENT=2, EXCLUSIVE=3). The signing payload carries only
 * the low byte of the type (nodus_value_sign_payload), so any wider integer
 * whose low byte is legal (259 → 3) would verify while failing every
 * `type == NODUS_VALUE_EXCLUSIVE` check; the decoders and the constructor
 * refuse such values instead.
 */
bool nodus_value_type_valid(uint64_t type);

/* ── Duplicate-key refusal for CBOR map decoders ─────────────────────
 *
 * Shared by the decoders that include this header (nodus_value.c,
 * nodus_tier1.c, nodus_tier2.c, nodus_client.c). No encoder in this tree
 * writes the same key twice into one map, so a repeated key is always a
 * malformed or hostile frame — and a decoder that stores into one field per
 * key would either overwrite (leaking a heap field) or append twice (running
 * a count past its allocation). Every text key of a map is recorded here and
 * a second occurrence refuses the whole decode. A map with more than
 * NODUS_MAP_MAX_KEYS text keys is refused too, so the check stays complete.
 * Same discipline as the v3d_keys_t reader in nodus_client.c. */
#define NODUS_MAP_MAX_KEYS 64

typedef struct {
    const char *p[NODUS_MAP_MAX_KEYS];
    size_t      l[NODUS_MAP_MAX_KEYS];
    size_t      n;
} nodus_map_keys_t;

/**
 * Record one text key of a map.
 *
 * @param ks       Per-map key set (zero-initialised by the caller per map)
 * @param key      Key bytes (points into the frame being decoded)
 * @param key_len  Key length
 * @return 0 if the key is new, -1 if it was already seen or the set is full
 */
int nodus_map_key_once(nodus_map_keys_t *ks, const char *key, size_t key_len);

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
