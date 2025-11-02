/*
 * DNA Messenger - P2P Integration Layer
 *
 * Phase 9.1b: Hybrid P2P Transport Integration
 *
 * This module bridges the messenger core (messenger.c) with the P2P transport layer (p2p_transport.h).
 * It implements a hybrid messaging approach:
 * - P2P direct messaging when both peers are online (via DHT + TCP)
 * - PostgreSQL fallback for offline message delivery
 *
 * Architecture:
 * ┌──────────────────────────────────────────────┐
 * │  messenger_send_message()                    │
 * │  ↓                                           │
 * │  messenger_send_p2p() [THIS MODULE]          │
 * │  ├─ Check if recipient online (DHT)          │
 * │  ├─ If online: p2p_send() → TCP direct       │
 * │  └─ If offline: PostgreSQL INSERT (fallback) │
 * └──────────────────────────────────────────────┘
 *
 * Message Flow:
 * 1. Sender: messenger_send_p2p() tries P2P first
 * 2. If P2P succeeds: message delivered instantly
 * 3. If P2P fails: message stored in PostgreSQL
 * 4. Receiver: p2p_message_callback() → store in PostgreSQL for retrieval
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
// HYBRID MESSAGING (P2P + PostgreSQL Fallback)
// ============================================================================

/**
 * Send message via P2P with PostgreSQL fallback
 *
 * Hybrid sending logic:
 * 1. Query DHT to check if recipient is online
 * 2. If online: Send via P2P directly (p2p_send)
 * 3. If offline or P2P fails: Store in PostgreSQL
 *
 * @param ctx: Messenger context
 * @param recipient: Recipient identity
 * @param encrypted_message: Encrypted message data
 * @param encrypted_len: Encrypted message length
 * @return: 0 on success (P2P or PostgreSQL), -1 on error
 */
int messenger_send_p2p(
    messenger_context_t *ctx,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len
);

/**
 * Broadcast message to multiple recipients via P2P
 *
 * Sends to each recipient using messenger_send_p2p() logic.
 * Some may go via P2P, others via PostgreSQL fallback.
 *
 * @param ctx: Messenger context
 * @param recipients: Array of recipient identities
 * @param recipient_count: Number of recipients
 * @param encrypted_message: Encrypted message data
 * @param encrypted_len: Encrypted message length
 * @return: 0 on success, -1 on error
 */
int messenger_broadcast_p2p(
    messenger_context_t *ctx,
    const char **recipients,
    size_t recipient_count,
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
 * Stores the message in PostgreSQL for retrieval via messenger_list_messages().
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

// ============================================================================
// OFFLINE MESSAGE QUEUE (Phase 9.2)
// ============================================================================

/**
 * Check for offline messages in DHT
 *
 * Retrieves messages that were queued in DHT while recipient was offline.
 * Messages are automatically delivered to PostgreSQL via the message callback.
 * Queue is cleared after retrieval.
 *
 * This should be called periodically (e.g., every 2 minutes) by GUI timer.
 *
 * @param ctx: Messenger context
 * @param messages_received: Output - number of messages retrieved (optional)
 * @return: 0 on success, -1 on error
 */
int messenger_p2p_check_offline_messages(
    messenger_context_t *ctx,
    size_t *messages_received
);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_P2P_H
