/**
 * @file contactlist_codec.h
 * @brief Contact-list JSON codec (v2: {identity, version, timestamp,
 *        contacts:[{fp, salt}]}) — codec unit
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * moved verbatim out of dht/client/dht_contactlist.c (which also does the
 * DHT I/O). Both functions were `static serialize_to_json` /
 * `static deserialize_from_json` there; they are external now and carry the
 * `dht_contactlist_` prefix so libdna does not export generic names (six
 * other dht/client files keep their own static serialize_to_json). Bodies
 * are unchanged.
 *
 * NC-1b: the CLST binary blob build/parse, formerly inline in
 * dht_contactlist_publish ("Step 4") / dht_contactlist_fetch ("Step 3"),
 * moved here as dht_contactlist_blob_encode / dht_contactlist_blob_parse.
 * The I/O functions call them; the web thin core calls the same code.
 *
 * Blob layout (big-endian): magic "CLST"(4) version(1) timestamp(8)
 * expiry(8) enc_len(4) enc(enc_len) sig_len(4) sig(sig_len).
 */

#ifndef DNA_CODEC_CONTACTLIST_CODEC_H
#define DNA_CODEC_CONTACTLIST_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Serialize contact list to JSON string (v2: contacts as objects with salt).
 * Returns a malloc'd string (caller frees) or NULL.
 */
char* dht_contactlist_serialize_to_json(const char *identity, const char **contacts,
                                        const uint8_t **salts, size_t contact_count,
                                        uint64_t timestamp);

/**
 * Deserialize JSON string to contact list (v1 + v2 compatible).
 * 0 on success, -1 on error. salts_out and timestamp_out may be NULL.
 */
int dht_contactlist_deserialize_from_json(const char *json_str, char ***contacts_out,
                                          size_t *count_out, uint8_t ***salts_out,
                                          uint64_t *timestamp_out);

/**
 * Build the CLST blob around an already-sealed JSON (`encrypted_data`, the
 * dna_encrypt_message_raw output) and the ML-DSA-87 signature over the
 * plaintext JSON. Writes DHT_CONTACTLIST_VERSION. *blob_out is malloc'd
 * (caller frees). 0 on success, -1 on bad arguments / allocation failure.
 * The caller keeps ownership of encrypted_data and signature.
 */
int dht_contactlist_blob_encode(uint64_t timestamp, uint64_t expiry,
                                const uint8_t *encrypted_data, size_t encrypted_len,
                                const uint8_t *signature, size_t sig_len,
                                uint8_t **blob_out, size_t *blob_size_out);

/**
 * Parse a CLST blob header: magic, version 1..DHT_CONTACTLIST_VERSION,
 * enc_len within the blob, sig_len == exactly the remaining bytes.
 * On 0, *encrypted_out points INTO `blob` (no copy) and *encrypted_len_out
 * is its length; timestamp_out / expiry_out (nullable) get the header
 * values. -1 on any header error. The embedded expiry is NOT enforced
 * (logged only, as the fetch always did).
 */
int dht_contactlist_blob_parse(const uint8_t *blob, size_t blob_size,
                               uint64_t *timestamp_out, uint64_t *expiry_out,
                               const uint8_t **encrypted_out,
                               uint32_t *encrypted_len_out);

#ifdef __cplusplus
}
#endif

#endif /* DNA_CODEC_CONTACTLIST_CODEC_H */
