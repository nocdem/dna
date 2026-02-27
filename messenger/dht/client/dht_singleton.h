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
 * │  └─ messenger_transport_init()                       │
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

#include "../core/dht_context.h"

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
 * Check if global DHT singleton is connected (ready for operations)
 *
 * This checks if the DHT has successfully connected to at least one peer.
 * Use this to query current connection status (e.g., for UI indicators).
 *
 * @return: true if connected and ready, false otherwise
 */
bool dht_singleton_is_ready(void);

/**
 * Cleanup global DHT singleton
 *
 * Shuts down and frees the global DHT context.
 * This should be called once at application shutdown.
 */
void dht_singleton_cleanup(void);

/**
 * Reinitialize DHT singleton after network change
 *
 * Restarts the DHT with the current identity when network connectivity
 * changes (e.g., WiFi to cellular switch on mobile). This is necessary
 * because the underlying UDP socket becomes invalid when IP changes.
 *
 * Flow:
 * 1. Cancel all active listeners
 * 2. Stop current DHT context
 * 3. Create new DHT context with same identity
 * 4. Bootstrap to seed nodes
 * 5. Resubscribe all listeners
 *
 * @return: 0 on success, -1 on error
 */
int dht_singleton_reinit(void);

/**
 * Set callback for DHT connection status changes
 *
 * The callback will be invoked from OpenDHT's internal thread when the
 * connection status changes between connected and disconnected states.
 * Call this after dht_singleton_init() to receive status updates.
 *
 * @param callback Function to call on status change (NULL to clear)
 * @param user_data User context passed to callback
 */
void dht_singleton_set_status_callback(dht_status_callback_t callback, void *user_data);

/**
 * Create a new DHT context with identity (v0.6.0+ engine-owned model)
 *
 * Unlike dht_singleton_init_with_identity(), this creates a DHT context
 * that is owned by the caller, not stored in the global singleton.
 * Used by dna_engine to create per-engine DHT contexts.
 *
 * The caller is responsible for:
 * - Storing the returned context
 * - Calling dht_context_stop() + dht_context_free() on cleanup
 * - Managing any status callbacks
 *
 * @param user_identity DHT identity to use (ownership transferred to DHT)
 * @return Created DHT context, or NULL on error
 */
dht_context_t* dht_create_context_with_identity(dht_identity_t *user_identity);

/**
 * Set the global singleton context (v0.6.0+ engine bridging)
 *
 * Allows engine-owned contexts to be accessible via dht_singleton_get().
 * This is a transitional mechanism for backwards compatibility with code
 * that still uses the singleton pattern.
 *
 * NOTE: The engine still owns the context - singleton does NOT free it.
 * When calling this with NULL, it just clears the pointer.
 *
 * @param ctx DHT context to set (NULL to clear)
 */
void dht_singleton_set_borrowed_context(dht_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // DHT_SINGLETON_H
