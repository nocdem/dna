/**
 * @file dna_dm_channel.h
 * @brief DM Channel Connector — push-based 1-to-1 direct message delivery
 *
 * Maps contact pairs to deterministic nodus channels for real-time DM push.
 * Each contact pair derives a shared channel UUID:
 *   dm_channel_uuid = SHA3-512("dna:dm:channel:" + sort(fp_a, fp_b))[0:16]
 *
 * Channel posts contain the ALREADY ENCRYPTED DM blob (same bytes as DHT
 * outbox). No additional encryption layer — channel encrypted=true flag
 * skips nodus-level signature verification.
 *
 * Uses:
 *   - nodus_ops_ch_* API for channel transport (TCP 4003)
 *   - Existing DM encryption (Kyber1024 KEM + AES-256-GCM)
 *
 * Part of DNA Connect - DM Channel System
 *
 * @date 2026-03-15
 */

#ifndef DNA_DM_CHANNEL_H
#define DNA_DM_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Maximum number of concurrent DM channel connections */
#define DNA_DM_CHANNEL_MAX  256

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum {
    DNA_DM_CH_OK            =  0,
    DNA_DM_CH_ERR_PARAM     = -1,
    DNA_DM_CH_ERR_CHANNEL   = -2,
    DNA_DM_CH_ERR_FULL      = -3,
    DNA_DM_CH_ERR_NOT_FOUND = -4,
    DNA_DM_CH_ERR_ALLOC     = -5
} dna_dm_ch_error_t;

/*============================================================================
 * Callback Types
 *============================================================================*/

/**
 * Callback for received DM channel messages.
 *
 * Called when an encrypted DM blob arrives via channel push.
 * The blob is the raw encrypted message — caller is responsible for
 * decryption using the existing DM decrypt path.
 *
 * @param peer_fp       Peer fingerprint (128-char hex) — derived from channel
 * @param blob          Raw encrypted message blob (same format as DHT outbox)
 * @param blob_len      Length of blob
 * @param user_data     User-provided context
 */
typedef void (*dna_dm_channel_msg_cb)(const char *peer_fp,
                                      const uint8_t *blob,
                                      size_t blob_len,
                                      void *user_data);

/*============================================================================
 * Initialization
 *============================================================================*/

/**
 * Initialize the DM channel subsystem.
 *
 * Must be called after nodus_ops_ch_init().
 *
 * @return 0 on success, -1 on error
 */
int dna_dm_channel_init(void);

/**
 * Shut down the DM channel subsystem.
 *
 * Unsubscribes all DM channels and cleans up resources.
 */
void dna_dm_channel_shutdown(void);

/*============================================================================
 * Connection Management
 *============================================================================*/

/**
 * Derive deterministic channel UUID for a contact pair.
 *
 * Uses SHA3-512("dna:dm:channel:" + sort(fp_a, fp_b))[0:16].
 * Fingerprints are sorted alphabetically so both sides derive the same UUID.
 *
 * @param my_fp         Own fingerprint (128-char hex)
 * @param peer_fp       Peer fingerprint (128-char hex)
 * @param ch_uuid_out   Output: 16-byte channel UUID
 * @return 0 on success, -1 on error
 */
int dna_dm_channel_uuid(const char *my_fp, const char *peer_fp,
                         uint8_t ch_uuid_out[16]);

/**
 * Connect to a DM channel for a specific peer.
 *
 * Derives the channel UUID and creates the channel on nodus if needed.
 *
 * @param dna_engine    Opaque engine pointer (for identity access)
 * @param peer_fp       Peer fingerprint (128-char hex)
 * @return DNA_DM_CH_OK on success, error code on failure
 */
int dna_dm_channel_connect(void *dna_engine, const char *peer_fp);

/**
 * Subscribe to receive push messages for a DM channel.
 *
 * Must be called after connect. Incoming messages will be delivered
 * to the registered callback.
 *
 * @param dna_engine    Opaque engine pointer
 * @param peer_fp       Peer fingerprint (128-char hex)
 * @return DNA_DM_CH_OK on success, error code on failure
 */
int dna_dm_channel_subscribe(void *dna_engine, const char *peer_fp);

/**
 * Send an encrypted DM blob via channel push.
 *
 * Posts the already-encrypted message blob to the DM channel.
 * This is a TRANSPORT ONLY operation — no encryption is done here.
 *
 * @param dna_engine    Opaque engine pointer
 * @param peer_fp       Peer fingerprint (128-char hex)
 * @param blob          Already-encrypted message blob
 * @param blob_len      Blob length
 * @return DNA_DM_CH_OK on success, error code on failure
 */
int dna_dm_channel_send(void *dna_engine, const char *peer_fp,
                         const uint8_t *blob, size_t blob_len);

/**
 * Disconnect from a DM channel.
 *
 * Unsubscribes and removes the channel entry.
 *
 * @param dna_engine    Opaque engine pointer
 * @param peer_fp       Peer fingerprint (128-char hex)
 * @return DNA_DM_CH_OK on success, error code on failure
 */
int dna_dm_channel_disconnect(void *dna_engine, const char *peer_fp);

/*============================================================================
 * Callback Management
 *============================================================================*/

/**
 * Set the callback for received DM channel messages.
 *
 * Only one callback is active at a time.
 *
 * @param cb        Callback function (NULL to disable)
 * @param user_data User-provided context passed to callback
 */
void dna_dm_channel_set_callback(dna_dm_channel_msg_cb cb, void *user_data);

/*============================================================================
 * Bulk Operations
 *============================================================================*/

/**
 * Subscribe to DM channels for all contacts.
 *
 * Iterates the contacts database, connects and subscribes to a DM channel
 * for each contact. Called during engine stabilization.
 *
 * @param dna_engine    Opaque engine pointer
 * @return Number of contacts subscribed, or -1 on error
 */
int dna_dm_channel_subscribe_all_contacts(void *dna_engine);

/*============================================================================
 * Push Handler
 *============================================================================*/

/**
 * Handle a push post for DM channels.
 *
 * Called by the engine's global push callback to forward channel posts
 * to the DM channel subsystem. If the channel_uuid matches a known
 * DM channel, the blob is delivered to the registered callback.
 *
 * @param channel_uuid  16-byte channel UUID
 * @param post          Post data from nodus push
 * @param user_data     Unused (for callback signature compatibility)
 */
void dna_dm_channel_handle_push(const uint8_t channel_uuid[16],
                                 const void *post,
                                 void *user_data);

/**
 * Check if a peer has an active DM channel connection.
 *
 * @param peer_fp   Peer fingerprint (128-char hex)
 * @return 1 if connected, 0 if not
 */
int dna_dm_channel_is_connected(const char *peer_fp);

#ifdef __cplusplus
}
#endif

#endif /* DNA_DM_CHANNEL_H */
