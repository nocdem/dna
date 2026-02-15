/**
 * @file epoch.h
 * @brief DNAC Epoch-based DHT key rotation
 *
 * Epochs provide time-based rotation of DHT keys to prevent
 * unbounded key accumulation. Each epoch is 60 seconds.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_EPOCH_H
#define DNAC_EPOCH_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Epoch duration in seconds (60s for practical testing) */
#define DNAC_EPOCH_DURATION_SEC 60

/**
 * @brief Get current epoch number
 * @return Current epoch (hours since Unix epoch)
 */
static inline uint64_t dnac_get_current_epoch(void) {
    return (uint64_t)time(NULL) / DNAC_EPOCH_DURATION_SEC;
}

/**
 * @brief Get epoch start timestamp
 * @param epoch Epoch number
 * @return Unix timestamp of epoch start
 */
static inline uint64_t dnac_epoch_start_time(uint64_t epoch) {
    return epoch * DNAC_EPOCH_DURATION_SEC;
}

/**
 * @brief Get seconds remaining in current epoch
 * @return Seconds until next epoch
 */
static inline uint64_t dnac_epoch_seconds_remaining(void) {
    return DNAC_EPOCH_DURATION_SEC - ((uint64_t)time(NULL) % DNAC_EPOCH_DURATION_SEC);
}

/**
 * @brief Get epoch number for a given timestamp
 * @param timestamp Unix timestamp
 * @return Epoch number
 */
static inline uint64_t dnac_epoch_from_timestamp(uint64_t timestamp) {
    return timestamp / DNAC_EPOCH_DURATION_SEC;
}

#ifdef __cplusplus
}
#endif

#endif /* DNAC_EPOCH_H */
