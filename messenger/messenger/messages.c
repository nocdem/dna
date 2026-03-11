/*
 * DNA Messenger - Messages Module Implementation
 */

#include "messages.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Windows byte order conversion macros (be64toh, htobe64 not available)
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>

// 64-bit big-endian conversions for Windows
#define htobe64(x) ( \
    ((uint64_t)(htonl((uint32_t)((x) & 0xFFFFFFFF))) << 32) | \
    ((uint64_t)(htonl((uint32_t)((x) >> 32)))) \
)
#define be64toh(x) htobe64(x)  // Same operation for bidirectional conversion

#else
#include <endian.h>
#endif

#include "../dna_api.h"
#include "crypto/utils/qgp_types.h"

#include "crypto/utils/qgp_platform.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/enc/qgp_aes.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/enc/aes_keywrap.h"
#include "../message_backup.h"
#include "../messenger_transport.h"
#include "../transport/transport.h"
#include "../dht/shared/dht_dm_outbox.h"
#include "../dht/shared/dht_offline_queue.h"
#include "../dht/shared/nodus_ops.h"
#include "../database/contacts_db.h"
#include "keys.h"
#include "crypto/utils/qgp_log.h"
#include <json-c/json.h>

#define LOG_TAG "MSG"

/* v0.6.47: Thread-safe localtime wrapper (security fix) */
static inline struct tm *safe_localtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (localtime_s(result, timer) == 0) ? result : NULL;
#else
    return localtime_r(timer, result);
#endif
}

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

// Multi-recipient encryption header and entry structures
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x08 (Category 5 + encrypted timestamp)
    uint8_t enc_key_type;       // QGP_KEY_TYPE_KEM1024
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t message_type;       // MSG_TYPE_DIRECT_PQC or MSG_TYPE_GROUP_GEK
    uint32_t encrypted_size;    // Size of encrypted data
    uint32_t signature_size;    // Size of signature
} messenger_enc_header_t;

typedef struct {
    uint8_t kyber_ciphertext[1568];   // Kyber1024 ciphertext
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte + 8-byte IV)
} messenger_recipient_entry_t;

/**
 * Multi-recipient encryption (adapted from encrypt.c)
 *
 * @param plaintext: Message to encrypt
 * @param plaintext_len: Message length
 * @param recipient_enc_pubkeys: Array of recipient Kyber1024 public keys (1568 bytes each)
 * @param recipient_count: Number of recipients (including sender)
 * @param sender_sign_key: Sender's Dilithium5 signing key (ML-DSA-87)
 * @param ciphertext_out: Output ciphertext (caller must free)
 * @param ciphertext_len_out: Output ciphertext length
 * @return: 0 on success, -1 on error
 */
static int messenger_encrypt_multi_recipient(
    const char *plaintext,
    size_t plaintext_len,
    uint8_t **recipient_enc_pubkeys,
    size_t recipient_count,
    qgp_key_t *sender_sign_key,
    uint64_t timestamp,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
) {
    uint8_t *dek = NULL;
    uint8_t *encrypted_data = NULL;
    uint8_t *payload = NULL;
    messenger_recipient_entry_t *recipient_entries = NULL;
    uint8_t *signature_data = NULL;
    uint8_t *output_buffer = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    size_t encrypted_size = 0;
    size_t signature_size = 0;
    int ret = -1;

    // Step 1: Generate random 32-byte DEK
    dek = malloc(32);
    if (!dek) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for DEK");
        goto cleanup;
    }

    if (qgp_randombytes(dek, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random DEK");
        goto cleanup;
    }

    // Step 2: Sign plaintext with Dilithium5 (ML-DSA-87)
    qgp_signature_t *signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM,
                                                     QGP_DSA87_PUBLICKEYBYTES,
                                                     QGP_DSA87_SIGNATURE_BYTES);
    if (!signature) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for signature");
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sender_sign_key->public_key,
           QGP_DSA87_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dsa87_sign(qgp_signature_get_bytes(signature), &actual_sig_len,
                                  (const uint8_t*)plaintext, plaintext_len,
                                  sender_sign_key->private_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DSA-87 signature creation failed");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;

    // Round-trip verification
    if (qgp_dsa87_verify(qgp_signature_get_bytes(signature), actual_sig_len,
                               (const uint8_t*)plaintext, plaintext_len,
                               qgp_signature_get_pubkey(signature)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Round-trip verification FAILED");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature_size = qgp_signature_get_size(signature);
    signature_data = malloc(signature_size);
    if (!signature_data) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        qgp_signature_free(signature);
        goto cleanup;
    }

    if (qgp_signature_serialize(signature, signature_data) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature serialization failed");
        qgp_signature_free(signature);
        goto cleanup;
    }
    qgp_signature_free(signature);

    // Step 3a: Compute sender fingerprint (SHA3-512 of Dilithium5 pubkey)
    uint8_t sender_fingerprint[64];
    if (qgp_sha3_512(sender_sign_key->public_key, QGP_DSA87_PUBLICKEYBYTES, sender_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint");
        goto cleanup;
    }

    // Step 3b: Build v0.08 payload = fingerprint(64) || timestamp(8) || plaintext
    size_t payload_len = 64 + 8 + plaintext_len;
    payload = malloc(payload_len);
    if (!payload) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for payload");
        goto cleanup;
    }

    // Copy fingerprint
    memcpy(payload, sender_fingerprint, 64);

    // Copy timestamp (big-endian)
    uint64_t timestamp_be = htobe64(timestamp);
    memcpy(payload + 64, &timestamp_be, 8);

    // Copy plaintext
    memcpy(payload + 64 + 8, plaintext, plaintext_len);

    // Step 3c: Encrypt payload with AES-256-GCM using DEK
    messenger_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, "PQSIGENC", 8);
    header_for_aad.version = 0x08;  // v0.08: encrypted timestamp
    header_for_aad.enc_key_type = (uint8_t)QGP_KEY_TYPE_KEM1024;
    header_for_aad.recipient_count = (uint8_t)recipient_count;
    header_for_aad.encrypted_size = (uint32_t)payload_len;  // fingerprint + timestamp + plaintext
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(payload_len);
    if (!encrypted_data) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for ciphertext");
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, payload, payload_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        goto cleanup;
    }

    // Payload encrypted, can free now
    free(payload);
    payload = NULL;

    // Step 4: Create recipient entries (wrap DEK for each recipient)
    recipient_entries = calloc(recipient_count, sizeof(messenger_recipient_entry_t));
    if (!recipient_entries) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for recipient entries");
        goto cleanup;
    }

    for (size_t i = 0; i < recipient_count; i++) {
        uint8_t kyber_ciphertext[1568];  // Kyber1024 ciphertext size
        uint8_t kek[32];  // KEK = shared secret from Kyber

        // Kyber1024 encapsulation (ML-KEM-1024)
        if (qgp_kem1024_encapsulate(kyber_ciphertext, kek, recipient_enc_pubkeys[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "KEM-1024 encapsulation failed for recipient %zu", i+1);
            qgp_secure_memzero(kek, 32);
            goto cleanup;
        }

        // Wrap DEK with KEK
        uint8_t wrapped_dek[40];
        if (aes256_wrap_key(dek, 32, kek, wrapped_dek) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to wrap DEK for recipient %zu", i+1);
            qgp_secure_memzero(kek, 32);
            goto cleanup;
        }

        // Store recipient entry
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 1568);  // Kyber1024 ciphertext size
        memcpy(recipient_entries[i].wrapped_dek, wrapped_dek, 40);

        // Wipe KEK
        qgp_secure_memzero(kek, 32);
    }

    // Step 5: Build output buffer
    // Format: [header | recipient_entries | nonce | ciphertext | tag | signature]
    size_t total_size = sizeof(messenger_enc_header_t) +
                       (sizeof(messenger_recipient_entry_t) * recipient_count) +
                       12 + encrypted_size + 16 + signature_size;

    output_buffer = malloc(total_size);
    if (!output_buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for output");
        goto cleanup;
    }

    size_t offset = 0;

    // Header
    messenger_enc_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "PQSIGENC", 8);
    header.version = 0x08;  // v0.08: fingerprint + timestamp + plaintext
    header.enc_key_type = (uint8_t)QGP_KEY_TYPE_KEM1024;
    header.recipient_count = (uint8_t)recipient_count;
    header.message_type = MSG_TYPE_DIRECT_PQC;  // Per-recipient Kyber1024
    header.encrypted_size = (uint32_t)encrypted_size;
    header.signature_size = (uint32_t)signature_size;

    memcpy(output_buffer + offset, &header, sizeof(header));
    offset += sizeof(header);

    // Recipient entries
    memcpy(output_buffer + offset, recipient_entries,
           sizeof(messenger_recipient_entry_t) * recipient_count);
    offset += sizeof(messenger_recipient_entry_t) * recipient_count;

    // Nonce (12 bytes)
    memcpy(output_buffer + offset, nonce, 12);
    offset += 12;

    // Encrypted data
    memcpy(output_buffer + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    // Tag (16 bytes)
    memcpy(output_buffer + offset, tag, 16);
    offset += 16;

    // Signature
    memcpy(output_buffer + offset, signature_data, signature_size);

    *ciphertext_out = output_buffer;
    *ciphertext_len_out = total_size;
    ret = 0;

cleanup:
    if (dek) {
        qgp_secure_memzero(dek, 32);
        free(dek);
    }
    if (payload) free(payload);
    if (encrypted_data) free(encrypted_data);
    if (recipient_entries) free(recipient_entries);
    if (signature_data) free(signature_data);
    if (ret != 0 && output_buffer) free(output_buffer);

    return ret;
}

int messenger_send_message(
    messenger_context_t *ctx,
    const char **recipients,
    size_t recipient_count,
    const char *message,
    int group_id,
    int message_type,
    time_t timestamp
) {
    if (!ctx || !recipients || !message || recipient_count == 0 || recipient_count > 254) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments (recipient_count must be 1-254)");
        return -1;
    }

    // M6: Validate message size before encryption (DoS prevention)
    size_t message_len = strlen(message);
    if (message_len > DNA_MESSAGE_MAX_PLAINTEXT_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Message too large: %zu bytes (max %d)",
                      message_len, DNA_MESSAGE_MAX_PLAINTEXT_SIZE);
        return -1;
    }

    // Build full recipient list: sender + recipients (sender as first recipient)
    // This allows sender to decrypt their own sent messages
    size_t total_recipients = recipient_count + 1;
    const char **all_recipients = malloc(sizeof(char*) * total_recipients);
    if (!all_recipients) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        return -1;
    }

    all_recipients[0] = ctx->identity;  // Sender is first recipient
    for (size_t i = 0; i < recipient_count; i++) {
        all_recipients[i + 1] = recipients[i];
    }

    // Load sender's private signing key from filesystem
    // v0.3.0: Flat structure - keys/identity.dsa
    const char *data_dir = qgp_platform_app_data_dir();
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *sender_sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sender_sign_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot load sender's signing key from %s", dilithium_path);
        free(all_recipients);
        return -1;
    }

    // Load all recipient public keys from keyserver (including sender)
    uint8_t **enc_pubkeys = calloc(total_recipients, sizeof(uint8_t*));
    uint8_t **sign_pubkeys = calloc(total_recipients, sizeof(uint8_t*));
    // Allocate fingerprint storage for actual recipients (not sender at index 0)
    char (*recipient_fps)[129] = calloc(recipient_count, sizeof(*recipient_fps));

    if (!enc_pubkeys || !sign_pubkeys || !recipient_fps) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        free(enc_pubkeys);
        free(sign_pubkeys);
        free(recipient_fps);
        free(all_recipients);
        qgp_key_free(sender_sign_key);
        return -1;
    }

    // Load public keys for all recipients from keyserver
    for (size_t i = 0; i < total_recipients; i++) {
        size_t sign_len = 0, enc_len = 0;
        // Capture fingerprint for actual recipients (index > 0)
        char *fp_out = (i > 0) ? recipient_fps[i - 1] : NULL;
        if (messenger_load_pubkey(ctx, all_recipients[i],
                                   &sign_pubkeys[i], &sign_len,
                                   &enc_pubkeys[i], &enc_len, fp_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot load public key for '%s' - key not cached and DHT unavailable", all_recipients[i]);
            QGP_LOG_WARN(LOG_TAG, "MESSAGE NOT SAVED: Cannot encrypt without recipient's public key");

            // Cleanup on error
            for (size_t j = 0; j < total_recipients; j++) {
                free(enc_pubkeys[j]);
                free(sign_pubkeys[j]);
            }
            free(enc_pubkeys);
            free(sign_pubkeys);
            free(recipient_fps);
            free(all_recipients);
            qgp_key_free(sender_sign_key);
            return -3;  // KEY_UNAVAILABLE - distinct from network error
        }
    }

    // Multi-recipient encryption implementation
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint64_t send_timestamp = (uint64_t)time(NULL);
    int ret = messenger_encrypt_multi_recipient(
        message, strlen(message),
        enc_pubkeys, total_recipients,
        sender_sign_key,
        send_timestamp,
        &ciphertext, &ciphertext_len
    );

    // Cleanup keys
    for (size_t i = 0; i < total_recipients; i++) {
        free(enc_pubkeys[i]);
        free(sign_pubkeys[i]);
    }
    free(enc_pubkeys);
    free(sign_pubkeys);
    free(all_recipients);
    qgp_key_free(sender_sign_key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Multi-recipient encryption failed");
        free(recipient_fps);
        return -1;
    }

    // Generate unique message_group_id (use microsecond timestamp for uniqueness)
#ifdef _WIN32
    // Windows: Use GetSystemTimeAsFileTime()
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Convert 100-nanosecond intervals to microseconds
    int message_group_id = (int)(uli.QuadPart / 10);
#else
    // POSIX: Use clock_gettime()
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int message_group_id = (int)(ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
#endif
    (void)message_group_id;  // Suppress unused variable warning

    // Store in SQLite local database - one row per actual recipient (not sender)
    // Track message IDs and sequence numbers for status updates
    time_t now = (timestamp > 0) ? timestamp : time(NULL);
    // v15: Removed seq_num tracking - ACK-based delivery instead of watermarks
    int *message_ids = malloc(recipient_count * sizeof(int));
    if (!message_ids) {
        free(ciphertext);
        free(recipient_fps);
        return -1;
    }

    for (size_t i = 0; i < recipient_count; i++) {
        int result = message_backup_save(
            ctx->backup_ctx,
            ctx->identity,      // sender
            recipients[i],      // recipient
            message,            // plaintext (v14 - decrypted message)
            ctx->identity,      // sender_fingerprint (v14)
            now,                // timestamp
            true,               // is_outgoing = true (we're sending)
            group_id,           // group_id (0 for direct, >0 for group) - Phase 6.2
            message_type        // message_type (chat or invitation) - Phase 6.2
        );

        if (result == -1) {
            QGP_LOG_ERROR(LOG_TAG, "Store message failed for recipient '%s' in SQLite", recipients[i]);
            free(ciphertext);
            free(message_ids);
            free(recipient_fps);
            return -1;
        }

        if (result == 1) {
            // Duplicate - message already exists, don't get last_id (would be wrong)
            message_ids[i] = 0;
            QGP_LOG_WARN(LOG_TAG, "[SEND] Duplicate message for recipient %.20s..., skipping status update",
                         recipients[i]);
        } else {
            // New message inserted - get its ID for status update
            message_ids[i] = message_backup_get_last_id(ctx->backup_ctx);
            QGP_LOG_DEBUG(LOG_TAG, "[SEND] Saved message id=%d for recipient %.20s...",
                         message_ids[i], recipients[i]);
        }
    }

    // Outbox flush: build complete blob from messages.db for each recipient.
    // This is the ONLY DHT PUT — no per-message PUT to avoid races between
    // concurrent CLI processes. The flush always builds the complete blob
    // from messages.db (the single source of truth), so even if two processes
    // race, the later one's blob contains ALL messages.
    //
    // Message status flow (v15):
    // 1. PENDING (0) - message saved, clock icon
    // 2. SENT (1) - DHT PUT succeeded (flush), single tick
    // 3. RECEIVED (2) - ACK from recipient, double tick
    size_t dht_success = 0;
    for (size_t i = 0; i < recipient_count; i++) {
        if (message_ids[i] == 0) {
            QGP_LOG_INFO(LOG_TAG, "[SEND] Skipping flush for duplicate to %.20s...", recipients[i]);
            dht_success++;
            continue;
        }

        int flush_rc = messenger_flush_recipient_outbox(ctx, recipients[i]);
        if (flush_rc > 0) {
            QGP_LOG_INFO(LOG_TAG, "[SEND] Flush OK: %d messages in blob for %.20s...",
                         flush_rc, recipients[i]);
            dht_success++;
        } else if (flush_rc == 0) {
            QGP_LOG_WARN(LOG_TAG, "[SEND] Flush empty for %.20s...", recipients[i]);
        } else {
            QGP_LOG_WARN(LOG_TAG, "[SEND] Flush failed for %.20s..., marking FAILED", recipients[i]);
            if (message_ids[i] > 0) {
                message_backup_update_status(ctx->backup_ctx, message_ids[i], MESSAGE_STATUS_FAILED);
            }
        }
    }

    free(message_ids);
    free(recipient_fps);
    free(ciphertext);

    if (dht_success == 0) {
        QGP_LOG_WARN(LOG_TAG, "All flushes failed - messages saved with FAILED status");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * OUTBOX FLUSH — Build complete blob from messages.db, PUT to DHT
 *
 * Eliminates GET→append→PUT race condition. On each call, reads ALL PENDING
 * outgoing messages for the recipient from messages.db, re-encrypts each one,
 * serializes into a single blob, and PUTs. The blob always reflects the
 * complete set of pending messages — no stale reads possible.
 * ============================================================================ */

int messenger_flush_recipient_outbox(messenger_context_t *ctx, const char *recipient) {
    if (!ctx || !recipient) return -1;

    /* 1. Resolve recipient to fingerprint */
    char recipient_fp[129];
    {
        uint8_t *spk = NULL, *epk = NULL;
        size_t slen = 0, elen = 0;
        if (messenger_load_pubkey(ctx, recipient, &spk, &slen, &epk, &elen, recipient_fp) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Cannot resolve recipient '%s'", recipient);
            return -1;
        }
        free(spk);
        free(epk);
    }

    /* 2. Get ALL pending outgoing messages for this recipient */
    backup_message_t *pending = NULL;
    int pending_count = 0;
    if (message_backup_get_pending_for_recipient(ctx->backup_ctx, recipient,
                                                   &pending, &pending_count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Failed to query pending messages for %.20s...", recipient);
        return -1;
    }

    if (pending_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[FLUSH] No pending messages for %.20s...", recipient);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[FLUSH] Building outbox blob: %d pending messages for %.20s...",
                 pending_count, recipient);

    /* 3. Load sender signing key (needed for re-encryption) */
    const char *data_dir = qgp_platform_app_data_dir();
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *sender_sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sender_sign_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Cannot load sender signing key");
        message_backup_free_messages(pending, pending_count);
        return -1;
    }

    /* 4. Load recipient + sender encryption pubkeys (for multi-recipient encrypt) */
    uint8_t *sender_enc_pk = NULL, *recip_enc_pk = NULL;
    size_t sender_enc_len = 0, recip_enc_len = 0;
    {
        uint8_t *spk = NULL;
        size_t slen = 0;
        if (messenger_load_pubkey(ctx, ctx->identity, &spk, &slen,
                                   &sender_enc_pk, &sender_enc_len, NULL) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Cannot load sender enc pubkey");
            qgp_key_free(sender_sign_key);
            message_backup_free_messages(pending, pending_count);
            return -1;
        }
        free(spk);
    }
    {
        uint8_t *spk = NULL;
        size_t slen = 0;
        if (messenger_load_pubkey(ctx, recipient, &spk, &slen,
                                   &recip_enc_pk, &recip_enc_len, NULL) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Cannot load recipient enc pubkey");
            free(sender_enc_pk);
            qgp_key_free(sender_sign_key);
            message_backup_free_messages(pending, pending_count);
            return -1;
        }
        free(spk);
    }

    /* Two recipients for multi-recipient encrypt: sender (index 0) + recipient (index 1) */
    uint8_t *enc_pubkeys[2] = { sender_enc_pk, recip_enc_pk };

    /* 5. Re-encrypt each pending message and build offline message array */
    dht_offline_message_t *offline_msgs = calloc(pending_count, sizeof(dht_offline_message_t));
    if (!offline_msgs) {
        free(sender_enc_pk);
        free(recip_enc_pk);
        qgp_key_free(sender_sign_key);
        message_backup_free_messages(pending, pending_count);
        return -1;
    }

    int built_count = 0;
    for (int i = 0; i < pending_count; i++) {
        uint8_t *ciphertext = NULL;
        size_t ciphertext_len = 0;
        uint64_t send_ts = (uint64_t)pending[i].timestamp;

        int enc_rc = messenger_encrypt_multi_recipient(
            pending[i].plaintext, strlen(pending[i].plaintext),
            enc_pubkeys, 2,
            sender_sign_key,
            send_ts,
            &ciphertext, &ciphertext_len
        );

        if (enc_rc != 0) {
            QGP_LOG_WARN(LOG_TAG, "[FLUSH] Re-encrypt failed for msg id=%d, skipping", pending[i].id);
            continue;
        }

        offline_msgs[built_count].seq_num = (uint64_t)pending[i].id;
        offline_msgs[built_count].timestamp = (uint64_t)pending[i].timestamp;
        offline_msgs[built_count].expiry = (uint64_t)pending[i].timestamp + DNA_DM_OUTBOX_TTL;
        offline_msgs[built_count].sender = strdup(ctx->identity);
        offline_msgs[built_count].recipient = strdup(recipient_fp);
        offline_msgs[built_count].ciphertext = ciphertext;
        offline_msgs[built_count].ciphertext_len = ciphertext_len;
        built_count++;
    }

    free(sender_enc_pk);
    free(recip_enc_pk);
    qgp_key_free(sender_sign_key);

    if (built_count == 0) {
        QGP_LOG_WARN(LOG_TAG, "[FLUSH] All re-encryptions failed");
        free(offline_msgs);
        message_backup_free_messages(pending, pending_count);
        return -1;
    }

    /* 6. Serialize into blob */
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    if (dht_serialize_messages(offline_msgs, built_count, &serialized, &serialized_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Serialize failed");
        dht_offline_messages_free(offline_msgs, built_count);
        message_backup_free_messages(pending, pending_count);
        return -1;
    }

    /* 7. Generate bucket key */
    uint64_t today = dht_dm_outbox_get_day_bucket();
    char base_key[512];

    uint8_t salt_buf[32];
    const uint8_t *salt_ptr = NULL;
    if (contacts_db_get_salt(recipient_fp, salt_buf) == 0) {
        salt_ptr = salt_buf;
    }

    if (dht_dm_outbox_make_key(ctx->identity, recipient_fp, today, salt_ptr,
                                base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[FLUSH] Failed to generate bucket key");
        free(serialized);
        dht_offline_messages_free(offline_msgs, built_count);
        message_backup_free_messages(pending, pending_count);
        return -1;
    }

    /* 8. PUT to DHT */
    QGP_LOG_INFO(LOG_TAG, "[FLUSH] PUT %d msgs, blob=%zu bytes", built_count, serialized_len);
    int put_rc = nodus_ops_put_str(base_key, serialized, serialized_len,
                                    DNA_DM_OUTBOX_TTL, nodus_ops_value_id());
    free(serialized);
    dht_offline_messages_free(offline_msgs, built_count);

    if (put_rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "[FLUSH] DHT PUT failed for %.20s...", recipient);
        message_backup_free_messages(pending, pending_count);
        return -1;
    }

    /* 9. Update PENDING/FAILED messages to SENT (1) — skip already-SENT */
    int updated = 0;
    for (int i = 0; i < pending_count; i++) {
        if (pending[i].id > 0 && pending[i].status != MESSAGE_STATUS_SENT) {
            message_backup_update_status(ctx->backup_ctx, pending[i].id, MESSAGE_STATUS_SENT);
            updated++;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "[FLUSH] OK: %d messages in blob, %d updated to SENT for %.20s...",
                 built_count, updated, recipient);

    message_backup_free_messages(pending, pending_count);
    return built_count;
}

int messenger_list_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Search SQLite for all messages involving this identity
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "List messages failed from SQLite");
        return -1;
    }

    // Filter for incoming messages only (where recipient == ctx->identity)
    int incoming_count = 0;
    for (int i = 0; i < all_count; i++) {
        if (strcmp(all_messages[i].recipient, ctx->identity) == 0) {
            incoming_count++;
        }
    }

    printf("\n=== Inbox for %s (%d messages) ===\n\n", ctx->identity, incoming_count);

    if (incoming_count == 0) {
        printf("  (no messages)\n");
    } else {
        // Print incoming messages in reverse chronological order
        for (int i = all_count - 1; i >= 0; i--) {
            if (strcmp(all_messages[i].recipient, ctx->identity) == 0) {
                struct tm tm_buf;
                struct tm *tm_info = safe_localtime(&all_messages[i].timestamp, &tm_buf);
                char timestamp_str[32];
                if (tm_info) {
                    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
                } else {
                    strncpy(timestamp_str, "0000-00-00 00:00:00", sizeof(timestamp_str));
                }

                printf("  [%d] From: %s (%s)\n", all_messages[i].id, all_messages[i].sender, timestamp_str);
            }
        }
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

int messenger_list_sent_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Search SQLite for all messages involving this identity
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "List sent messages failed from SQLite");
        return -1;
    }

    // Filter for outgoing messages only (where sender == ctx->identity)
    int sent_count = 0;
    for (int i = 0; i < all_count; i++) {
        if (strcmp(all_messages[i].sender, ctx->identity) == 0) {
            sent_count++;
        }
    }

    printf("\n=== Sent by %s (%d messages) ===\n\n", ctx->identity, sent_count);

    if (sent_count == 0) {
        printf("  (no sent messages)\n");
    } else {
        // Print sent messages in reverse chronological order
        for (int i = all_count - 1; i >= 0; i--) {
            if (strcmp(all_messages[i].sender, ctx->identity) == 0) {
                struct tm tm_buf;
                struct tm *tm_info = safe_localtime(&all_messages[i].timestamp, &tm_buf);
                char timestamp_str[32];
                if (tm_info) {
                    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
                } else {
                    strncpy(timestamp_str, "0000-00-00 00:00:00", sizeof(timestamp_str));
                }

                printf("  [%d] To: %s (%s)\n", all_messages[i].id, all_messages[i].recipient, timestamp_str);
            }
        }
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

int messenger_read_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Search SQLite for all messages to find the one with matching ID
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Fetch message failed from SQLite");
        return -1;
    }

    // Find message with matching ID where we are the recipient
    backup_message_t *target_msg = NULL;
    for (int i = 0; i < all_count; i++) {
        if (all_messages[i].id == message_id && strcmp(all_messages[i].recipient, ctx->identity) == 0) {
            target_msg = &all_messages[i];
            break;
        }
    }

    if (!target_msg) {
        QGP_LOG_ERROR(LOG_TAG, "Message %d not found or not for you", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    const char *sender = target_msg->sender;

    printf("\n========================================\n");
    printf(" Message #%d from %s\n", message_id, sender);
    printf("========================================\n\n");

    // v14: Messages are stored as plaintext - no decryption needed
    const char *plaintext = target_msg->plaintext;
    if (!plaintext) {
        QGP_LOG_ERROR(LOG_TAG, "Message %d has no plaintext content", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    // Display message
    printf("Message:\n");
    printf("----------------------------------------\n");
    printf("%s\n", plaintext);
    printf("----------------------------------------\n");

    // Display timestamp - v0.6.47: Use thread-safe localtime
    struct tm tm_buf;
    struct tm *tm_info = safe_localtime(&target_msg->timestamp, &tm_buf);
    char time_str[64];
    if (tm_info) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(time_str, "0000-00-00 00:00:00", sizeof(time_str));
    }
    printf("Sent: %s\n", time_str);

    // Display sender fingerprint if available
    if (target_msg->sender_fingerprint[0] != '\0') {
        printf("Sender fingerprint: %.20s...\n", target_msg->sender_fingerprint);
    }

    // Cleanup
    message_backup_free_messages(all_messages, all_count);
    printf("\n");
    return 0;
}

int messenger_decrypt_message(messenger_context_t *ctx, int message_id,
                                char **plaintext_out, size_t *plaintext_len_out) {
    if (!ctx || !plaintext_out || !plaintext_len_out) {
        return -1;
    }

    // Fetch message from SQLite local database
    // Support both received messages (recipient = identity) AND sent messages (sender = identity)
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Fetch message failed from SQLite");
        return -1;
    }

    // Find message with matching ID (either as sender OR recipient)
    backup_message_t *target_msg = NULL;
    for (int i = 0; i < all_count; i++) {
        if (all_messages[i].id == message_id) {
            target_msg = &all_messages[i];
            break;
        }
    }

    if (!target_msg) {
        QGP_LOG_ERROR(LOG_TAG, "Message %d not found", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    // v14: Messages are stored as plaintext - no decryption needed
    const char *plaintext = target_msg->plaintext;
    if (!plaintext) {
        QGP_LOG_ERROR(LOG_TAG, "Message %d has no plaintext content", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    size_t plaintext_len = strlen(plaintext);

    // Return plaintext as null-terminated string (caller must free)
    *plaintext_out = strdup(plaintext);
    if (!*plaintext_out) {
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    *plaintext_len_out = plaintext_len;
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

// NOTE: messenger_delete_pubkey() removed - DHT keys are PERMANENT by design
// (see CLAUDE.md:205 - Identity keys persist indefinitely for security)

int messenger_delete_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Delete from SQLite local database
    int result = message_backup_delete(ctx->backup_ctx, message_id);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Delete message failed from SQLite");
        return -1;
    }

    printf("✓ Message %d deleted\n", message_id);
    return 0;
}

// ============================================================================
// MESSAGE SEARCH/FILTERING
// ============================================================================

int messenger_search_by_sender(messenger_context_t *ctx, const char *sender) {
    if (!ctx || !sender) {
        return -1;
    }

    // Search SQLite for all messages involving this identity
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Search by sender failed from SQLite");
        return -1;
    }

    // Filter for messages from specified sender to current user (incoming messages only)
    int matching_count = 0;
    for (int i = 0; i < all_count; i++) {
        if (strcmp(all_messages[i].sender, sender) == 0 &&
            strcmp(all_messages[i].recipient, ctx->identity) == 0) {
            matching_count++;
        }
    }

    printf("\n=== Messages from %s to %s (%d messages) ===\n\n", sender, ctx->identity, matching_count);

    // Print matching messages in reverse chronological order
    if (matching_count == 0) {
        printf("  (no messages from %s)\n", sender);
    } else {
        for (int i = all_count - 1; i >= 0; i--) {
            if (strcmp(all_messages[i].sender, sender) == 0 &&
                strcmp(all_messages[i].recipient, ctx->identity) == 0) {
                struct tm tm_buf;
                struct tm *tm_info = safe_localtime(&all_messages[i].timestamp, &tm_buf);
                char timestamp_str[32];
                if (tm_info) {
                    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
                } else {
                    strncpy(timestamp_str, "0000-00-00 00:00:00", sizeof(timestamp_str));
                }
                printf("  [%d] %s\n", all_messages[i].id, timestamp_str);
            }
        }
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

int messenger_show_conversation(messenger_context_t *ctx, const char *other_identity) {
    if (!ctx || !other_identity) {
        return -1;
    }

    // Get conversation from SQLite local database
    backup_message_t *messages = NULL;
    int count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx, other_identity, &messages, &count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Show conversation failed from SQLite");
        return -1;
    }

    printf("\n");
    printf("========================================\n");
    printf(" Conversation: %s <-> %s\n", ctx->identity, other_identity);
    printf(" (%d messages)\n", count);
    printf("========================================\n\n");

    for (int i = 0; i < count; i++) {
        struct tm tm_buf;
        struct tm *tm_info = safe_localtime(&messages[i].timestamp, &tm_buf);
        char timestamp_str[32];
        if (tm_info) {
            strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strncpy(timestamp_str, "0000-00-00 00:00:00", sizeof(timestamp_str));
        }

        // Format: [ID] timestamp sender -> recipient
        if (strcmp(messages[i].sender, ctx->identity) == 0) {
            // Message sent by current user
            printf("  [%d] %s  You -> %s\n", messages[i].id, timestamp_str, messages[i].recipient);
        } else {
            // Message received by current user
            printf("  [%d] %s  %s -> You\n", messages[i].id, timestamp_str, messages[i].sender);
        }
    }

    if (count == 0) {
        printf("  (no messages exchanged)\n");
    }

    printf("\n");
    message_backup_free_messages(messages, count);
    return 0;
}

/**
 * Get conversation with another user (returns message array for GUI)
 */
int messenger_get_conversation(messenger_context_t *ctx, const char *other_identity,
                                 message_info_t **messages_out, int *count_out) {
    if (!ctx || !other_identity || !messages_out || !count_out) {
        return -1;
    }

    // Get conversation from SQLite local database
    backup_message_t *backup_messages = NULL;
    int backup_count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx, other_identity, &backup_messages, &backup_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Get conversation failed from SQLite");
        return -1;
    }

    *count_out = backup_count;

    if (backup_count == 0) {
        *messages_out = NULL;
        return 0;
    }

    // Convert backup_message_t to message_info_t for GUI compatibility
    message_info_t *messages = (message_info_t*)calloc(backup_count, sizeof(message_info_t));
    if (!messages) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        message_backup_free_messages(backup_messages, backup_count);
        return -1;
    }

    // v14: No decryption needed - messages stored as plaintext
    for (int i = 0; i < backup_count; i++) {
        messages[i].id = backup_messages[i].id;
        messages[i].sender = strdup(backup_messages[i].sender);
        messages[i].recipient = strdup(backup_messages[i].recipient);

        // Convert time_t to string - v0.6.47: Use thread-safe localtime
        struct tm tm_buf;
        struct tm *tm_info = safe_localtime(&backup_messages[i].timestamp, &tm_buf);
        messages[i].timestamp = (char*)malloc(32);
        if (messages[i].timestamp) {
            if (tm_info) {
                strftime(messages[i].timestamp, 32, "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                strncpy(messages[i].timestamp, "0000-00-00 00:00:00", 32);
            }
        }

        // Convert status int to string (v15): 0=pending, 1=sent, 2=received, 3=failed
        if (backup_messages[i].status == 3) {
            messages[i].status = strdup("failed");
        } else if (backup_messages[i].status == 2) {
            messages[i].status = strdup("received");
        } else if (backup_messages[i].status == 1) {
            messages[i].status = strdup("sent");
        } else if (backup_messages[i].status == 0) {
            messages[i].status = strdup("pending");
        } else {
            // Old messages without status field - fall back to boolean flags
            if (backup_messages[i].read || backup_messages[i].delivered) {
                messages[i].status = strdup("received");  // v15: read/delivered → received
            } else {
                messages[i].status = strdup("sent");  // Default for old messages
            }
        }

        messages[i].delivered_at = backup_messages[i].delivered ? strdup(messages[i].timestamp) : NULL;
        messages[i].read_at = backup_messages[i].read ? strdup(messages[i].timestamp) : NULL;
        messages[i].message_type = backup_messages[i].message_type;
        messages[i].deleted_by_sender = backup_messages[i].deleted_by_sender;

        // v14: Direct plaintext copy - no decryption needed
        messages[i].plaintext = backup_messages[i].plaintext ? strdup(backup_messages[i].plaintext) : strdup("");

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp || !messages[i].status) {
            // Clean up on failure
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].status);
                free(messages[j].delivered_at);
                free(messages[j].read_at);
                free(messages[j].plaintext);
            }
            free(messages);
            message_backup_free_messages(backup_messages, backup_count);
            return -1;
        }
    }

    *messages_out = messages;
    message_backup_free_messages(backup_messages, backup_count);
    return 0;
}

/**
 * Get conversation with pagination (for efficient chat loading)
 * Returns messages in DESC order (newest first) for reverse-scroll UI
 */
int messenger_get_conversation_page(messenger_context_t *ctx, const char *other_identity,
                                     int limit, int offset,
                                     message_info_t **messages_out, int *count_out,
                                     int *total_out) {
    if (!ctx || !other_identity || !messages_out || !count_out) {
        return -1;
    }

    // Get paginated conversation from SQLite
    backup_message_t *backup_messages = NULL;
    int backup_count = 0;
    int total = 0;

    int result = message_backup_get_conversation_page(ctx->backup_ctx, other_identity,
                                                       limit, offset,
                                                       &backup_messages, &backup_count, &total);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Get conversation page failed from SQLite");
        return -1;
    }

    *count_out = backup_count;
    if (total_out) *total_out = total;

    if (backup_count == 0) {
        *messages_out = NULL;
        return 0;
    }

    // Convert backup_message_t to message_info_t for GUI compatibility
    message_info_t *messages = (message_info_t*)calloc(backup_count, sizeof(message_info_t));
    if (!messages) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        message_backup_free_messages(backup_messages, backup_count);
        return -1;
    }

    // v14: No decryption needed - messages stored as plaintext
    for (int i = 0; i < backup_count; i++) {
        messages[i].id = backup_messages[i].id;
        messages[i].sender = strdup(backup_messages[i].sender);
        messages[i].recipient = strdup(backup_messages[i].recipient);

        // Convert time_t to string - v0.6.47: Use thread-safe localtime
        struct tm tm_buf;
        struct tm *tm_info = safe_localtime(&backup_messages[i].timestamp, &tm_buf);
        messages[i].timestamp = (char*)malloc(32);
        if (messages[i].timestamp) {
            if (tm_info) {
                strftime(messages[i].timestamp, 32, "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                strncpy(messages[i].timestamp, "0000-00-00 00:00:00", 32);
            }
        }

        // Convert status int to string (v15): 0=pending, 1=sent, 2=received, 3=failed
        if (backup_messages[i].status == 3) {
            messages[i].status = strdup("failed");
        } else if (backup_messages[i].status == 2) {
            messages[i].status = strdup("received");
        } else if (backup_messages[i].status == 1) {
            messages[i].status = strdup("sent");
        } else if (backup_messages[i].status == 0) {
            messages[i].status = strdup("pending");
        } else {
            // Old messages without status field
            if (backup_messages[i].read || backup_messages[i].delivered) {
                messages[i].status = strdup("received");  // v15: read/delivered → received
            } else {
                messages[i].status = strdup("sent");
            }
        }

        messages[i].delivered_at = backup_messages[i].delivered ? strdup(messages[i].timestamp) : NULL;
        messages[i].read_at = backup_messages[i].read ? strdup(messages[i].timestamp) : NULL;
        messages[i].message_type = backup_messages[i].message_type;
        messages[i].deleted_by_sender = backup_messages[i].deleted_by_sender;

        // v14: Direct plaintext copy - no decryption needed
        messages[i].plaintext = backup_messages[i].plaintext ? strdup(backup_messages[i].plaintext) : strdup("");

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp || !messages[i].status) {
            // Clean up on failure
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].status);
                free(messages[j].delivered_at);
                free(messages[j].read_at);
                free(messages[j].plaintext);
            }
            free(messages);
            message_backup_free_messages(backup_messages, backup_count);
            return -1;
        }
    }

    *messages_out = messages;
    message_backup_free_messages(backup_messages, backup_count);

    QGP_LOG_DEBUG(LOG_TAG, "Retrieved page: %d messages (offset=%d, total=%d)",
                  backup_count, offset, total);
    return 0;
}

/**
 * Free message array
 */
void messenger_free_messages(message_info_t *messages, int count) {
    if (!messages) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(messages[i].sender);
        free(messages[i].recipient);
        free(messages[i].timestamp);
        free(messages[i].status);
        free(messages[i].delivered_at);
        free(messages[i].read_at);
        free(messages[i].plaintext);
    }
    free(messages);
}

int messenger_search_by_date(messenger_context_t *ctx, const char *start_date,
                              const char *end_date, bool include_sent, bool include_received) {
    if (!ctx) {
        return -1;
    }

    if (!include_sent && !include_received) {
        QGP_LOG_ERROR(LOG_TAG, "Must include either sent or received messages");
        return -1;
    }

    // Parse date strings to time_t for comparison (format: YYYY-MM-DD)
    time_t start_time = 0;
    time_t end_time = 0;

    if (start_date) {
        struct tm tm = {0};
        if (sscanf(start_date, "%d-%d-%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3) {
            tm.tm_year -= 1900;  // Years since 1900
            tm.tm_mon -= 1;      // Months since January (0-11)
            start_time = mktime(&tm);
        }
    }

    if (end_date) {
        struct tm tm = {0};
        if (sscanf(end_date, "%d-%d-%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;
            end_time = mktime(&tm);
        }
    }

    // Get all messages from SQLite
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Search by date failed from SQLite");
        return -1;
    }

    // Filter by date range and sent/received criteria
    int matching_count = 0;
    for (int i = 0; i < all_count; i++) {
        // Check sent/received filter
        bool is_sent = (strcmp(all_messages[i].sender, ctx->identity) == 0);
        bool is_received = (strcmp(all_messages[i].recipient, ctx->identity) == 0);

        if (!include_sent && is_sent) continue;
        if (!include_received && is_received) continue;

        // Check date range
        if (start_date && all_messages[i].timestamp < start_time) continue;
        if (end_date && all_messages[i].timestamp >= end_time) continue;

        matching_count++;
    }

    printf("\n=== Messages");
    if (start_date || end_date) {
        printf(" (");
        if (start_date) printf("from %s", start_date);
        if (start_date && end_date) printf(" ");
        if (end_date) printf("to %s", end_date);
        printf(")");
    }
    if (include_sent && include_received) {
        printf(" - Sent & Received");
    } else if (include_sent) {
        printf(" - Sent Only");
    } else {
        printf(" - Received Only");
    }
    printf(" ===\n\n");

    printf("Found %d messages:\n\n", matching_count);

    // Print matching messages in reverse chronological order
    for (int i = all_count - 1; i >= 0; i--) {
        // Apply same filters
        bool is_sent = (strcmp(all_messages[i].sender, ctx->identity) == 0);
        bool is_received = (strcmp(all_messages[i].recipient, ctx->identity) == 0);

        if (!include_sent && is_sent) continue;
        if (!include_received && is_received) continue;

        if (start_date && all_messages[i].timestamp < start_time) continue;
        if (end_date && all_messages[i].timestamp >= end_time) continue;

        struct tm tm_buf;
        struct tm *tm_info = safe_localtime(&all_messages[i].timestamp, &tm_buf);
        char timestamp_str[32];
        if (tm_info) {
            strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strncpy(timestamp_str, "0000-00-00 00:00:00", sizeof(timestamp_str));
        }

        if (strcmp(all_messages[i].sender, ctx->identity) == 0) {
            printf("  [%d] %s  To: %s\n", all_messages[i].id, timestamp_str, all_messages[i].recipient);
        } else {
            printf("  [%d] %s  From: %s\n", all_messages[i].id, timestamp_str, all_messages[i].sender);
        }
    }

    if (matching_count == 0) {
        printf("  (no messages found)\n");
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

// ============================================================================
// MESSAGE DELETION (v17)
// ============================================================================

int messenger_delete_message_full(messenger_context_t *ctx, int message_id,
                                   bool send_notices) {
    if (!ctx || !ctx->backup_ctx) return -1;

    (void)send_notices;  // Notice sending handled at engine layer

    int rc = message_backup_delete(ctx->backup_ctx, message_id);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete message id=%d", message_id);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted message id=%d", message_id);
    return 0;
}

int messenger_delete_conversation_full(messenger_context_t *ctx,
                                        const char *contact_identity) {
    if (!ctx || !ctx->backup_ctx || !contact_identity) return -1;

    int count = message_backup_delete_conversation(ctx->backup_ctx, contact_identity);
    if (count < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete conversation with %s", contact_identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted %d messages in conversation with %s",
                 count, contact_identity);
    return count;
}

int messenger_delete_all_messages(messenger_context_t *ctx) {
    if (!ctx || !ctx->backup_ctx) return -1;

    int count = message_backup_delete_all(ctx->backup_ctx);
    if (count < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete all messages");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted all messages (count=%d)", count);
    return count;
}

int messenger_send_delete_notice(messenger_context_t *ctx,
                                  const char *recipient,
                                  delete_action_t action,
                                  const char **content_hashes,
                                  int hash_count) {
    if (!ctx || !recipient) return -1;

    json_object *j_notice = json_object_new_object();
    if (!j_notice) return -1;

    json_object_object_add(j_notice, "type", json_object_new_string("delete"));
    json_object_object_add(j_notice, "action", json_object_new_int(action));

    if (content_hashes && hash_count > 0) {
        json_object *j_hashes = json_object_new_array();
        for (int i = 0; i < hash_count; i++) {
            json_object_array_add(j_hashes,
                                  json_object_new_string(content_hashes[i]));
        }
        json_object_object_add(j_notice, "hashes", j_hashes);
    }

    if (action == DELETE_ACTION_CONVERSATION) {
        json_object_object_add(j_notice, "contact",
                               json_object_new_string(recipient));
    }

    const char *json_str = json_object_to_json_string(j_notice);
    const char *recipients[1] = { recipient };
    int rc = messenger_send_message(ctx, recipients, 1, json_str,
                                     0, MESSAGE_TYPE_DELETE, 0);
    json_object_put(j_notice);
    return rc;
}

// ============================================================================
// MESSAGE STATUS / READ RECEIPTS
// ============================================================================
// MODULARIZATION: Moved to messenger/status.{c,h}

/*
 * messenger_mark_delivered() - MOVED to messenger/status.c
 * messenger_mark_conversation_read() - MOVED to messenger/status.c
 */
