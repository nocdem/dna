/*
 * DNA Messenger - CLI Messenger Module
 *
 * Storage Architecture:
 * - Private keys: ~/.dna/<identity>-dilithium.pqkey, <identity>-kyber512.pqkey (filesystem)
 * - Public keys: PostgreSQL keyserver table (shared, network-ready)
 * - Messages: PostgreSQL messages table (shared, network-ready)
 *
 * Network transport will be added in Phase 4
 */

#ifndef MESSENGER_H
#define MESSENGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <libpq-fe.h>
#include "dna_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// MESSENGER CONTEXT
// ============================================================================

/**
 * Messenger Context
 * Manages PostgreSQL connection and DNA API context
 */
typedef struct {
    char *identity;              // User's identity name (e.g., "alice")
    PGconn *pg_conn;             // PostgreSQL connection
    dna_context_t *dna_ctx;      // DNA API context
} messenger_context_t;

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize messenger context
 *
 * Connects to PostgreSQL database (local or network)
 * Connection string: postgresql://dna:dna_password@localhost:5432/dna_messenger
 *
 * @param identity: User's identity name
 * @return: Messenger context, or NULL on error
 */
messenger_context_t* messenger_init(const char *identity);

/**
 * Free messenger context
 *
 * @param ctx: Messenger context to free
 */
void messenger_free(messenger_context_t *ctx);

// ============================================================================
// KEY GENERATION
// ============================================================================

/**
 * Generate new key pair for identity
 *
 * Creates:
 * - ~/.dna/<identity>-dilithium.pqkey (private signing key)
 * - ~/.dna/<identity>-kyber512.pqkey (private encryption key)
 * - Uploads public keys to PostgreSQL keyserver
 *
 * @param ctx: Messenger context
 * @param identity: Identity name (e.g., "alice")
 * @return: 0 on success, -1 on error
 */
int messenger_generate_keys(messenger_context_t *ctx, const char *identity);

/**
 * Restore key pair from BIP39 recovery seed
 *
 * Prompts user for 24-word mnemonic and optional passphrase.
 * Regenerates keys deterministically and uploads to keyserver.
 *
 * @param ctx: Messenger context
 * @param identity: Identity name (e.g., "alice")
 * @return: 0 on success, -1 on error
 */
int messenger_restore_keys(messenger_context_t *ctx, const char *identity);

/**
 * Restore key pair from file containing BIP39 recovery seed
 *
 * File format: "word1 word2 word3 ... word24 [passphrase]"
 * Passphrase is optional (on same line after 24 words).
 *
 * @param ctx: Messenger context
 * @param identity: Identity name (e.g., "alice")
 * @param seed_file: Path to file containing seed phrase
 * @return: 0 on success, -1 on error
 */
int messenger_restore_keys_from_file(messenger_context_t *ctx, const char *identity, const char *seed_file);

// ============================================================================
// PUBLIC KEY MANAGEMENT (keyserver table)
// ============================================================================

/**
 * Store public key in keyserver
 *
 * Called when generating or importing a key pair.
 *
 * @param ctx: Messenger context
 * @param identity: Key owner's identity
 * @param signing_pubkey: Dilithium3 public key
 * @param signing_pubkey_len: Signing key length
 * @param encryption_pubkey: Kyber512 public key
 * @param encryption_pubkey_len: Encryption key length
 * @return: 0 on success, -1 on error
 */
int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
);

/**
 * Load public key from keyserver
 *
 * @param ctx: Messenger context
 * @param identity: Key owner's identity
 * @param signing_pubkey_out: Output signing key (caller must free)
 * @param signing_pubkey_len_out: Output signing key length
 * @param encryption_pubkey_out: Output encryption key (caller must free)
 * @param encryption_pubkey_len_out: Output encryption key length
 * @return: 0 on success, -1 on error
 */
int messenger_load_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **signing_pubkey_out,
    size_t *signing_pubkey_len_out,
    uint8_t **encryption_pubkey_out,
    size_t *encryption_pubkey_len_out
);

/**
 * List all public keys in keyserver
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_pubkeys(messenger_context_t *ctx);

/**
 * Delete public key from keyserver
 *
 * @param ctx: Messenger context
 * @param identity: Key owner's identity
 * @return: 0 on success, -1 on error
 */
int messenger_delete_pubkey(messenger_context_t *ctx, const char *identity);

// ============================================================================
// MESSAGE OPERATIONS (messages table)
// ============================================================================

/**
 * Send message to recipient
 *
 * Encrypts message and stores in messages table.
 * In Phase 3, messages are stored in PostgreSQL (ready for network access).
 *
 * @param ctx: Messenger context
 * @param recipient: Recipient's identity
 * @param message: Plaintext message
 * @return: 0 on success, -1 on error
 */
int messenger_send_message(
    messenger_context_t *ctx,
    const char *recipient,
    const char *message
);

/**
 * List messages for current user
 *
 * Shows messages where recipient = current identity
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_messages(messenger_context_t *ctx);

/**
 * List sent messages
 *
 * Shows messages where sender = current identity
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_sent_messages(messenger_context_t *ctx);

/**
 * Read and decrypt specific message
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID
 * @return: 0 on success, -1 on error
 */
int messenger_read_message(messenger_context_t *ctx, int message_id);

/**
 * Delete message
 *
 * @param ctx: Messenger context
 * @param message_id: Message ID
 * @return: 0 on success, -1 on error
 */
int messenger_delete_message(messenger_context_t *ctx, int message_id);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_H
