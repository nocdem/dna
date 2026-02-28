/**
 * Nodus v5 — Singleton Client Instance
 *
 * Global client for use by the messenger engine.
 * Thread-safe init/connect/poll/close lifecycle.
 *
 * @file nodus_singleton.h
 */

#ifndef NODUS_SINGLETON_H
#define NODUS_SINGLETON_H

#include "nodus/nodus.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the global Nodus client.
 * Must be called once before any other nodus_singleton_* call.
 *
 * @param config  Client configuration (servers, callbacks, etc.)
 * @param identity  Caller's identity (keypair + node_id)
 * @return 0 on success, -1 on error
 */
int nodus_singleton_init(const nodus_client_config_t *config,
                          const nodus_identity_t *identity);

/**
 * Connect to a Nodus server (tries configured servers in order).
 * @return 0 on success, -1 if all servers unreachable
 */
int nodus_singleton_connect(void);

/**
 * Get the global client instance.
 * @return Pointer to client, or NULL if not initialized
 */
nodus_client_t *nodus_singleton_get(void);

/**
 * Check if the singleton is initialized and connected.
 */
bool nodus_singleton_is_ready(void);

/**
 * Poll for events. Call from your event loop.
 * @return Number of events, or -1 on error
 */
int nodus_singleton_poll(int timeout_ms);

/**
 * Get the singleton's identity.
 */
const nodus_identity_t *nodus_singleton_identity(void);

/**
 * Disconnect and clean up the global client.
 */
void nodus_singleton_close(void);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SINGLETON_H */
