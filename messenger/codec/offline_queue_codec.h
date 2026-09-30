/**
 * @file offline_queue_codec.h
 * @brief Offline-queue codec additions (NC-1b) — codec unit
 *
 * The NC-1 functions of codec/offline_queue_codec.c (message blob
 * serialize/deserialize/free, ACK key) keep their declarations in
 * dht/shared/dht_offline_queue.h. This header declares what NC-1b added.
 */

#ifndef DNA_CODEC_OFFLINE_QUEUE_CODEC_H
#define DNA_CODEC_OFFLINE_QUEUE_CODEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The DHT ACK value: `timestamp` as 8 bytes big-endian (formerly inline
 *  in dht_publish_ack). */
void dht_ack_value_encode(uint64_t timestamp, uint8_t value[8]);

/** Inverse of dht_ack_value_encode (formerly inline in the ACK listen
 *  callback). The caller checks that the stored value is exactly 8 bytes. */
uint64_t dht_ack_value_decode(const uint8_t value[8]);

#ifdef __cplusplus
}
#endif

#endif /* DNA_CODEC_OFFLINE_QUEUE_CODEC_H */
