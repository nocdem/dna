/**
 * Nodus — Messenger Init/Lifecycle Module
 *
 * Replaces dht_singleton.c. Manages the Nodus singleton lifecycle
 * for the messenger: init, connect, reinit, close.
 *
 * @file nodus_init.h
 */

#ifndef NODUS_INIT_H
#define NODUS_INIT_H

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Status callback type (same shape as old dht_status_callback_t).
 */
typedef void (*nodus_messenger_status_cb_t)(bool is_connected, void *user_data);

/**
 * Initialize and connect the Nodus singleton with the given identity.
 *
 * Loads bootstrap nodes from dna_config, inits the singleton,
 * connects, and wires up the nodus_ops_dispatch callback.
 *
 * @param identity  Caller's identity (value-copied internally)
 * @return 0 on success, -1 on error
 */
int nodus_messenger_init(const nodus_identity_t *identity);

/**
 * Close the Nodus singleton and cancel all listeners.
 * Safe to call multiple times (idempotent).
 */
void nodus_messenger_close(void);

/**
 * Reinitialize after network change (close + re-init with stored identity).
 * @return 0 on success, -1 on error
 */
int nodus_messenger_reinit(void);

/**
 * Check if the singleton is connected and authenticated.
 */
bool nodus_messenger_is_ready(void);

/**
 * Check if the singleton has been initialized (may not be connected yet).
 */
bool nodus_messenger_is_initialized(void);

/**
 * Set a callback for connection status changes.
 */
void nodus_messenger_set_status_callback(nodus_messenger_status_cb_t cb, void *user_data);

/**
 * Poll the Nodus TCP connection for events.
 * Processes incoming frames (listener notifications, responses) and
 * handles auto-reconnect if the connection was lost.
 * @param timeout_ms  Maximum time to block in epoll/select
 * @return Number of events processed, or -1 on error
 */
int nodus_messenger_poll(int timeout_ms);

/**
 * Force-disconnect TCP to interrupt blocking nodus operations.
 * Call before joining threads that may be blocked on nodus ops.
 * Does not free memory — call nodus_messenger_close() later for cleanup.
 */
void nodus_messenger_force_disconnect(void);

/**
 * Suspend DHT — close TCP, prevent auto-reconnect (app background).
 */
void nodus_messenger_suspend(void);

/**
 * Resume DHT — trigger immediate reconnect (app foreground).
 */
void nodus_messenger_resume(void);

/**
 * Wait for the singleton to become ready (polling).
 * @param timeout_ms  Maximum wait time in milliseconds
 * @return true if ready, false if timed out
 */
bool nodus_messenger_wait_for_ready(int timeout_ms);

/**
 * Copy the active bootstrap server list into a caller-provided buffer.
 * Used by quorum-based protocols (e.g., DNAC genesis anchor bootstrap)
 * that need to fan out queries across all bootstrap peers.
 *
 * @param out        Caller buffer (at least `max_count` entries)
 * @param max_count  Capacity of `out`
 * @return Number of servers copied (>=0), -1 on error
 */
int nodus_messenger_get_bootstrap_servers(nodus_server_endpoint_t *out,
                                           int max_count);

/**
 * Return a const reference to the loaded identity, or NULL if no
 * identity has been loaded via nodus_messenger_init().
 *
 * Used by quorum-based protocols that spin up short-lived nodus clients
 * against individual bootstrap peers and need to pass the same identity
 * for authentication.
 *
 * @return Const pointer to the loaded identity, or NULL.
 */
const nodus_identity_t *nodus_messenger_get_identity_ref(void);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_INIT_H */
