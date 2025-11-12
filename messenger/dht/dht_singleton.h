/*
 * DNA Messenger - Global DHT Singleton
 *
 * Provides a single, shared DHT context for the entire application.
 * This eliminates the need for temporary DHT contexts and ensures
 * DHT is properly bootstrapped before any operations.
 *
 * Architecture:
 * ┌────────────────────────────────────────────────┐
 * │  App Startup (main.cpp)                        │
 * │  └─ dht_singleton_init()                       │
 * │     └─ Bootstrap DHT (5 seconds)               │
 * │                                                 │
 * │  Identity Creation / Key Publishing            │
 * │  └─ messenger_store_pubkey()                   │
 * │     └─ dht_singleton_get() ← Use global DHT    │
 * │                                                 │
 * │  Messaging (MainWindow)                        │
 * │  └─ messenger_p2p_init()                       │
 * │     └─ dht_singleton_get() ← Use global DHT    │
 * │                                                 │
 * │  App Shutdown                                  │
 * │  └─ dht_singleton_cleanup()                    │
 * └────────────────────────────────────────────────┘
 *
 * Benefits:
 * - DHT bootstraps once at startup (no delays later)
 * - All operations use the same DHT (consistent state)
 * - No temporary DHT contexts (cleaner code)
 * - Works for identity creation before any identity exists
 */

#ifndef DHT_SINGLETON_H
#define DHT_SINGLETON_H

#include "dht_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize global DHT singleton (with ephemeral identity)
 *
 * DEPRECATED: This creates DHT with ephemeral identity. Use dht_singleton_init_with_identity()
 * for encrypted backup system.
 *
 * Creates and bootstraps a single DHT context for the entire application.
 * This should be called once at application startup (in main.cpp).
 *
 * Bootstrap nodes are hardcoded:
 * - dna-bootstrap-us-1: 154.38.182.161:4000
 * - dna-bootstrap-eu-1: 164.68.105.227:4000
 * - dna-bootstrap-eu-2: 164.68.116.180:4000
 *
 * @return: 0 on success, -1 on error
 */
int dht_singleton_init(void);

/**
 * Initialize global DHT singleton with user identity
 *
 * Creates and bootstraps DHT context using user's permanent DHT identity
 * (loaded from encrypted backup). This should be called after user login.
 *
 * @param user_identity: User's DHT identity (from dht_identity_backup system)
 * @return: 0 on success, -1 on error
 */
int dht_singleton_init_with_identity(dht_identity_t *user_identity);

/**
 * Get global DHT singleton instance
 *
 * Returns the shared DHT context for use by all operations.
 * Returns NULL if dht_singleton_init() hasn't been called yet.
 *
 * @return: DHT context pointer, or NULL if not initialized
 */
dht_context_t* dht_singleton_get(void);

/**
 * Check if global DHT singleton is initialized
 *
 * @return: true if initialized, false otherwise
 */
bool dht_singleton_is_initialized(void);

/**
 * Cleanup global DHT singleton
 *
 * Shuts down and frees the global DHT context.
 * This should be called once at application shutdown.
 */
void dht_singleton_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // DHT_SINGLETON_H
