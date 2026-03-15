/**
 * @file dna_group_channel.h
 * @brief Group Channel Connector — bridges groups and nodus channel system
 *
 * Maps group UUIDs to nodus channel UUIDs and provides high-level
 * connect/subscribe/send/receive operations for encrypted group messaging.
 *
 * Uses:
 *   - nodus_ops_ch_* API for channel transport (TCP 4003)
 *   - dna_group_channel_crypto for encrypt/decrypt
 *   - GEK subsystem for key management
 *
 * Part of DNA Connect - Group Channel System (Phase 2)
 *
 * @date 2026-03-15
 */

#ifndef DNA_GROUP_CHANNEL_H
#define DNA_GROUP_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Maximum number of concurrent group channel connections */
#define DNA_GROUP_CHANNEL_MAX  64

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum {
    DNA_GROUP_CH_OK            =  0,
    DNA_GROUP_CH_ERR_PARAM     = -1,
    DNA_GROUP_CH_ERR_NO_GEK    = -2,
    DNA_GROUP_CH_ERR_ENCRYPT   = -3,
    DNA_GROUP_CH_ERR_DECRYPT   = -4,
    DNA_GROUP_CH_ERR_CHANNEL   = -5,
    DNA_GROUP_CH_ERR_FULL      = -6,
    DNA_GROUP_CH_ERR_NOT_FOUND = -7,
    DNA_GROUP_CH_ERR_SIGN      = -8,
    DNA_GROUP_CH_ERR_ALLOC     = -9
} dna_group_ch_error_t;

/*============================================================================
 * Callback Types
 *============================================================================*/

/**
 * Callback for received group channel messages.
 *
 * Called when an encrypted message is received, decrypted, and verified.
 *
 * @param group_uuid    Group UUID string
 * @param sender_fp     Sender fingerprint (128-char hex)
 * @param timestamp     Message timestamp (Unix seconds)
 * @param plaintext     Decrypted message content
 * @param plaintext_len Length of plaintext
 * @param user_data     User-provided context
 */
typedef void (*dna_group_channel_msg_cb)(const char *group_uuid,
                                          const char *sender_fp,
                                          uint64_t timestamp,
                                          const uint8_t *plaintext,
                                          size_t plaintext_len,
                                          void *user_data);

/*============================================================================
 * Initialization
 *============================================================================*/

/**
 * Initialize the group channel subsystem.
 *
 * Must be called after nodus_ops_ch_init(). Registers internal push callback.
 *
 * @return 0 on success, -1 on error
 */
int dna_group_channel_init(void);

/**
 * Shut down the group channel subsystem.
 *
 * Disconnects all group channels and cleans up resources.
 */
void dna_group_channel_shutdown(void);

/*============================================================================
 * Connection Management
 *============================================================================*/

/**
 * Connect to a group's channel on nodus.
 *
 * Maps group_uuid to a 16-byte channel UUID and creates the channel
 * on the responsible nodus node if it doesn't exist.
 *
 * @param dna_engine    Opaque engine pointer (for identity/key access)
 * @param group_uuid    Group UUID string (36 chars)
 * @return DNA_GROUP_CH_OK on success, error code on failure
 */
int dna_group_channel_connect(void *dna_engine, const char *group_uuid);

/**
 * Subscribe to receive push messages for a group channel.
 *
 * Must be called after connect. Incoming messages will be decrypted
 * and delivered to the registered callback.
 *
 * @param dna_engine    Opaque engine pointer
 * @param group_uuid    Group UUID string
 * @return DNA_GROUP_CH_OK on success, error code on failure
 */
int dna_group_channel_subscribe(void *dna_engine, const char *group_uuid);

/**
 * Send an encrypted message to a group channel.
 *
 * Encrypts plaintext with the group's active GEK, signs with Dilithium5,
 * and posts the encrypted blob to the nodus channel.
 *
 * @param dna_engine    Opaque engine pointer
 * @param group_uuid    Group UUID string
 * @param plaintext     Message content
 * @param plaintext_len Length of plaintext
 * @return DNA_GROUP_CH_OK on success, error code on failure
 */
int dna_group_channel_send(void *dna_engine, const char *group_uuid,
                            const uint8_t *plaintext, size_t plaintext_len);

/**
 * Disconnect from a group channel.
 *
 * Unsubscribes and closes the channel connection.
 *
 * @param dna_engine    Opaque engine pointer
 * @param group_uuid    Group UUID string
 * @return DNA_GROUP_CH_OK on success, error code on failure
 */
int dna_group_channel_disconnect(void *dna_engine, const char *group_uuid);

/*============================================================================
 * Callback Management
 *============================================================================*/

/**
 * Set the callback for received group channel messages.
 *
 * Only one callback is active at a time. Setting a new callback
 * replaces the previous one.
 *
 * @param cb        Callback function (NULL to disable)
 * @param user_data User-provided context passed to callback
 */
void dna_group_channel_set_callback(dna_group_channel_msg_cb cb,
                                     void *user_data);

/*============================================================================
 * Sync (store-and-forward retrieval)
 *============================================================================*/

/**
 * Fetch missed messages from a group channel (store-and-forward).
 *
 * Retrieves posts since the given timestamp, decrypts them, and
 * delivers each to the registered callback.
 *
 * @param dna_engine        Opaque engine pointer
 * @param group_uuid        Group UUID string
 * @param since_received_at Get posts after this nodus timestamp (ms, 0 = all)
 * @param count_out         Output: number of messages delivered (optional)
 * @return DNA_GROUP_CH_OK on success, error code on failure
 */
int dna_group_channel_sync(void *dna_engine, const char *group_uuid,
                            uint64_t since_received_at, size_t *count_out);

/*============================================================================
 * Utility
 *============================================================================*/

/**
 * Convert group UUID string to 16-byte channel UUID.
 *
 * Uses SHA3-512 hash of "dna:group:channel:" + group_uuid, truncated to 16 bytes.
 * This ensures a deterministic mapping from group to channel.
 *
 * @param group_uuid    Group UUID string (36 chars)
 * @param ch_uuid_out   Output: 16-byte channel UUID
 * @return 0 on success, -1 on error
 */
int dna_group_channel_uuid(const char *group_uuid, uint8_t ch_uuid_out[16]);

/**
 * Check if a group is connected via channel.
 *
 * @param group_uuid    Group UUID string
 * @return 1 if connected, 0 if not
 */
int dna_group_channel_is_connected(const char *group_uuid);

#ifdef __cplusplus
}
#endif

#endif /* DNA_GROUP_CHANNEL_H */
