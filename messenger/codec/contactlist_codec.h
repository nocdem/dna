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
 * The CLST binary blob build/parse is still inline in dht_contactlist_publish
 * / dht_contactlist_fetch — not separate functions, not moved.
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

#ifdef __cplusplus
}
#endif

#endif /* DNA_CODEC_CONTACTLIST_CODEC_H */
