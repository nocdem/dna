/**
 * @file contact_request_codec.h
 * @brief Contact-request codec additions (NC-1b) — codec unit
 *
 * The NC-1 contact-request functions (inbox key, value_id, serialize,
 * deserialize, verify) keep their declarations in
 * dht/shared/dht_contact_request.h. This header declares what NC-1b added
 * to codec/contact_request_codec.c.
 */

#ifndef DNA_CODEC_CONTACT_REQUEST_CODEC_H
#define DNA_CODEC_CONTACT_REQUEST_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include "dht/shared/dht_contact_request.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The exact bytes a contact request's ML-DSA-87 signature covers — the one
 * builder used by BOTH dht_send_contact_request (sign) and
 * dht_verify_contact_request (verify). Previously built inline in each.
 *
 *   magic(4, BE) version(1) timestamp(8, BE as two 4-byte halves)
 *   expiry(8, idem) sender_fingerprint(129, NUL-padded, <= 128 chars)
 *   sender_name(64, NUL-padded, <= 63) sender_dilithium_pubkey(2592)
 *   message(256, NUL-padded, <= 255) [dht_salt(32) when version >= 2]
 *
 * *out is malloc'd (caller frees). 0 / -1 (bad arguments, allocation).
 */
int dht_contact_request_signing_preimage(const dht_contact_request_t *request,
                                         uint8_t **out, size_t *len_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_CODEC_CONTACT_REQUEST_CODEC_H */
