/*
 * DNA Messenger - Contacts Module
 *
 * DHT contact list synchronization.
 * Multi-device sync using Kyber1024 self-encryption + Dilithium5 signatures.
 */

#ifndef MESSENGER_CONTACTS_H
#define MESSENGER_CONTACTS_H

#include "messenger_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sync contacts to DHT (local → DHT)
 *
 * Publishes encrypted contact list to DHT with Kyber1024 self-encryption
 * and Dilithium5 signature. Only the owner can decrypt (multi-device sync).
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_sync_contacts_to_dht(messenger_context_t *ctx);

/**
 * Sync contacts from DHT (DHT → local)
 *
 * Fetches encrypted contact list from DHT, decrypts with Kyber1024 private key,
 * verifies Dilithium5 signature. REPLACES local contacts (DHT is source of truth).
 *
 * Safety checks prevent accidental data loss:
 * - Aborts if DHT not ready
 * - Aborts if local has contacts but DHT returns 0 (likely DHT failure)
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error, -2 if not found (OK for first-time users)
 */
int messenger_sync_contacts_from_dht(messenger_context_t *ctx);

/**
 * Auto-sync on first access
 *
 * Try to fetch from DHT first (DHT is source of truth).
 * If not found, publish local contacts to DHT.
 * Called once per session automatically.
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_contacts_auto_sync(messenger_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_CONTACTS_H
