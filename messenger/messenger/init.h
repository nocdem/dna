/*
 * DNA Messenger - Initialization Module
 *
 * Context management and initialization functions.
 * This is the foundation module - all other modules depend on the context created here.
 */

#ifndef MESSENGER_INIT_H
#define MESSENGER_INIT_H

#include "messenger_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize messenger context
 *
 * Creates a new messenger context for the given identity.
 * Initializes SQLite database, DNA crypto context, and keyserver cache.
 *
 * @param identity: User's identity name or fingerprint
 * @return: Messenger context on success, NULL on error
 */
messenger_context_t* messenger_init(const char *identity);

/**
 * Free messenger context
 *
 * Cleans up all resources associated with the messenger context.
 * Does NOT cleanup global keyserver cache (shared across contexts).
 *
 * @param ctx: Messenger context to free
 */
void messenger_free(messenger_context_t *ctx);

/**
 * Load DHT identity and reinitialize DHT singleton with permanent identity
 *
 * This function:
 * 1. Loads Kyber1024 private key (for decryption)
 * 2. Tries to load DHT identity from local encrypted file
 * 3. If local fails, tries to fetch from DHT (recovery on new device)
 * 4. If loaded, reinitializes DHT singleton with permanent identity
 *
 * This prevents DHT value accumulation bug by using a permanent RSA-2048 identity
 * instead of ephemeral identities that change on each restart.
 *
 * @param fingerprint: User fingerprint (128 hex chars)
 * @return: 0 on success, -1 on error (non-fatal, messenger can work without)
 */
int messenger_load_dht_identity(const char *fingerprint);

/**
 * Prepare DHT connection from mnemonic (before identity creation)
 *
 * v0.3.0+: Called when user enters seed phrase and presses "Next".
 * Starts DHT connection early so it's ready when identity is created.
 *
 * @param mnemonic: BIP39 mnemonic (24 words)
 * @return: 0 on success, -1 on error
 */
int messenger_prepare_dht_from_mnemonic(const char *mnemonic);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_INIT_H
