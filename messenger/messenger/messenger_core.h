/*
 * DNA Messenger - Core Internal Header
 *
 * Shared internal definitions for modular messenger components.
 * This header provides access to the messenger_context_t structure
 * by including the main messenger.h header.
 */

#ifndef MESSENGER_CORE_H
#define MESSENGER_CORE_H

// Include the main messenger header for type definitions
// This ensures we use the same struct definition everywhere
#include "../messenger.h"

/**
 * Get the path to a key file (.dsa or .kem)
 * v0.3.0: Flat structure - always keys/identity.{dsa,kem}
 *
 * @param data_dir Base data directory (from qgp_platform_app_data_dir())
 * @param fingerprint Ignored in v0.3.0 flat structure (kept for API compat)
 * @param extension The file extension (e.g., ".dsa" or ".kem")
 * @param path_out Output buffer for found path (must be at least 512 bytes)
 * @return 0 on success, -1 if not found
 */
int messenger_find_key_path(const char *data_dir, const char *fingerprint,
                            const char *extension, char *path_out);

#endif // MESSENGER_CORE_H
