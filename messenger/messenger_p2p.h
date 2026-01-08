/*
 * DNA Messenger - P2P Integration Layer
 *
 * Phase 14: DHT-Only Messaging
 *
 * This module bridges the messenger core (messenger.c) with the DHT layer.
 * All messaging uses DHT-only path (Spillway protocol) for reliability.
 *
 * Architecture (Phase 14):
 * ┌──────────────────────────────────────────────┐
 * │  messenger_send_message()                    │
 * │  ↓                                           │
 * │  messenger_queue_to_dht() [THIS MODULE]      │
 * │  └─ Queue to DHT Spillway (7-day TTL)        │
 * └──────────────────────────────────────────────┘
 *
 * P2P infrastructure (TCP, ICE) is preserved for future voice/video only.
 * Presence system still uses DHT for online status tracking.
 *
 * Removed in v0.3.154:
 * - messenger_send_p2p() - hybrid P2P+DHT path (was dead code)
 * - messenger_broadcast_p2p() - called messenger_send_p2p()
 */

#ifndef MESSENGER_P2P_H
#define MESSENGER_P2P_H

#include "messenger.h"
#include "p2p/p2p_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// P2P INITIALIZATION
// ============================================================================

/**
 * Initialize P2P transport for messenger
 *
 * Creates P2P transport instance and announces identity to DHT.
 * Bootstrap nodes are hardcoded (dna-bootstrap-us-1, dna-bootstrap-eu-1, dna-bootstrap-eu-2).
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_p2p_init(messenger_context_t *ctx);

/**
 * Shutdown P2P transport for messenger
 *
 * Unannounces identity from DHT and destroys P2P transport.
 *
 * @param ctx: Messenger context
 */
void messenger_p2p_shutdown(messenger_context_t *ctx);

// ============================================================================
// DHT-ONLY MESSAGING (Phase 14)
// ============================================================================
// NOTE: messenger_send_p2p() and messenger_broadcast_p2p() removed in v0.3.152
// All messaging now uses messenger_queue_to_dht() directly

/**
 * Queue message directly to DHT (Spillway) - PRIMARY messaging path
 *
 * Phase 14: DHT-only messaging. Messages are queued directly to DHT
 * without attempting P2P direct delivery. This is the only path
 * for messaging, ensuring reliability on all platforms including
 * mobile where P2P connections are unreliable due to background
 * execution restrictions.
 *
 * P2P infrastructure is preserved for future audio/video use.
 *
 * @param ctx: Messenger context
 * @param recipient: Recipient identity (name or fingerprint)
 * @param encrypted_message: Encrypted message data
 * @param encrypted_len: Encrypted message length
 * @return: 0 on success (DHT queued), -1 on error
 */
int messenger_queue_to_dht(
    messenger_context_t *ctx,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len
);

// ============================================================================
// P2P RECEIVE CALLBACKS
// ============================================================================

/**
 * P2P message received callback
 *
 * Called by p2p_transport when a message arrives via P2P.
 * Stores the message in SQLite for retrieval via messenger_list_messages().
 *
 * This callback is registered with p2p_set_message_callback() during init.
 *
 * @param identity: Sender's identity
 * @param data: Message data (encrypted)
 * @param len: Message length
 * @param user_data: Messenger context (messenger_context_t*)
 */
void messenger_p2p_message_callback(
    const char *identity,
    const uint8_t *data,
    size_t len,
    void *user_data
);

// ============================================================================
// PRESENCE & PEER DISCOVERY
// ============================================================================

/**
 * Check if peer is online via DHT
 *
 * Queries DHT to see if peer has announced their presence.
 *
 * @param ctx: Messenger context
 * @param identity: Peer identity to check
 * @return: true if online, false if offline or error
 */
bool messenger_p2p_peer_online(messenger_context_t *ctx, const char *identity);

/**
 * Get list of online peers
 *
 * Returns array of identities currently announced on DHT.
 * Caller must free the array and strings.
 *
 * @param ctx: Messenger context
 * @param identities_out: Output array of identity strings (caller must free)
 * @param count_out: Number of identities returned
 * @return: 0 on success, -1 on error
 */
int messenger_p2p_list_online_peers(
    messenger_context_t *ctx,
    char ***identities_out,
    int *count_out
);

/**
 * Refresh presence announcement
 *
 * Re-announces identity to DHT (called periodically by GUI timer).
 * DHT announcements expire after ~10 minutes, so refresh every 5 minutes.
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_p2p_refresh_presence(messenger_context_t *ctx);

/**
 * Lookup peer presence from DHT
 *
 * Queries DHT for peer's presence record using their fingerprint.
 * Returns timestamp when peer last registered presence (last online time).
 *
 * @param ctx: Messenger context
 * @param fingerprint: Peer's fingerprint (128 hex chars)
 * @param last_seen_out: Output - Unix timestamp when last seen (0 if not found)
 * @return: 0 on success, -1 on error/not found
 */
int messenger_p2p_lookup_presence(
    messenger_context_t *ctx,
    const char *fingerprint,
    uint64_t *last_seen_out
);

// ============================================================================
// OFFLINE MESSAGE QUEUE (Phase 9.2)
// ============================================================================

/**
 * Check for offline messages in DHT
 *
 * Retrieves messages that were queued in DHT while recipient was offline.
 * Messages are automatically stored in SQLite via the message callback.
 * Queue is cleared after retrieval.
 *
 * This should be called periodically (e.g., every 2 minutes) by GUI timer.
 *
 * @param ctx: Messenger context
 * @param sender_fp: If non-NULL, fetch only from this contact's outbox. If NULL, fetch from all contacts.
 * @param messages_received: Output - number of messages retrieved (optional)
 * @return: 0 on success, -1 on error
 */
int messenger_p2p_check_offline_messages(
    messenger_context_t *ctx,
    const char *sender_fp,
    size_t *messages_received
);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_P2P_H
