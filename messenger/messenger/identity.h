/*
 * DNA Messenger - Identity Module
 *
 * Pure utility functions for working with identity fingerprints and display names.
 * No state, no dependencies on other messenger modules.
 */

#ifndef MESSENGER_IDENTITY_H
#define MESSENGER_IDENTITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "messenger_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute SHA3-512 fingerprint of identity's Dilithium5 public key
 *
 * Loads the Dilithium5 key file and computes its SHA3-512 fingerprint.
 *
 * @param identity: Identity name (e.g., "alice")
 * @param fingerprint_out: Output buffer (must be at least 129 bytes for 128 hex chars + null terminator)
 * @return: 0 on success, -1 on error
 */
int messenger_compute_identity_fingerprint(const char *identity, char *fingerprint_out);

/**
 * Check if string is a valid fingerprint (128 hex characters)
 *
 * @param str: String to check
 * @return: true if valid fingerprint, false otherwise
 */
bool messenger_is_fingerprint(const char *str);

/**
 * Get display name for identity (name or shortened fingerprint)
 *
 * If identifier is a fingerprint, attempts DHT reverse lookup for registered name.
 * If no name found, returns shortened fingerprint (first10...last10).
 * If identifier is not a fingerprint, returns it as-is (assumes it's already a name).
 *
 * @param ctx: Messenger context (for DHT access)
 * @param identifier: Fingerprint or DNA name
 * @param display_name_out: Output buffer (must be at least 256 bytes)
 * @return: 0 on success, -1 on error
 */
int messenger_get_display_name(messenger_context_t *ctx, const char *identifier, char *display_name_out);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_IDENTITY_H
