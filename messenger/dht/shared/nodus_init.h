/**
 * Nodus v5 — Messenger Init/Lifecycle Module
 *
 * Replaces dht_singleton.c. Manages the Nodus singleton lifecycle
 * for the messenger: init, connect, reinit, close.
 *
 * @file nodus_init.h
 */

#ifndef NODUS_INIT_H
#define NODUS_INIT_H

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
 * Wait for the singleton to become ready (polling).
 * @param timeout_ms  Maximum wait time in milliseconds
 * @return true if ready, false if timed out
 */
bool nodus_messenger_wait_for_ready(int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_INIT_H */
