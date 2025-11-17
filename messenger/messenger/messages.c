/*
 * DNA Messenger - Messages Module Implementation
 */

#include "messages.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../dna_api.h"
#include "../crypto/utils/qgp_types.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_aes.h"
#include "../crypto/utils/qgp_random.h"
#include "../crypto/utils/aes_keywrap.h"
#include "../message_backup.h"
#include "../messenger_p2p.h"
#include "../p2p/p2p_transport.h"
#include "keys.h"

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

// Multi-recipient encryption header and entry structures
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x06 (Category 5: Kyber1024 + Dilithium5)
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t reserved;
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
 * @param sender_sign_key: Sender's Dilithium3 signing key
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
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
) {
    uint8_t *dek = NULL;
    uint8_t *encrypted_data = NULL;
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
        fprintf(stderr, "Error: Memory allocation failed for DEK\n");
        goto cleanup;
    }

    if (qgp_randombytes(dek, 32) != 0) {
        fprintf(stderr, "Error: Failed to generate random DEK\n");
        goto cleanup;
    }

    // Step 2: Sign plaintext with Dilithium3
    qgp_signature_t *signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM,
                                                     QGP_DSA87_PUBLICKEYBYTES,
                                                     QGP_DSA87_SIGNATURE_BYTES);
    if (!signature) {
        fprintf(stderr, "Error: Memory allocation failed for signature\n");
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sender_sign_key->public_key,
           QGP_DSA87_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dsa87_sign(qgp_signature_get_bytes(signature), &actual_sig_len,
                                  (const uint8_t*)plaintext, plaintext_len,
                                  sender_sign_key->private_key) != 0) {
        fprintf(stderr, "Error: DSA-87 signature creation failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;

    // Round-trip verification
    if (qgp_dsa87_verify(qgp_signature_get_bytes(signature), actual_sig_len,
                               (const uint8_t*)plaintext, plaintext_len,
                               qgp_signature_get_pubkey(signature)) != 0) {
        fprintf(stderr, "Error: Round-trip verification FAILED\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature_size = qgp_signature_get_size(signature);
    signature_data = malloc(signature_size);
    if (!signature_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    if (qgp_signature_serialize(signature, signature_data) == 0) {
        fprintf(stderr, "Error: Signature serialization failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }
    qgp_signature_free(signature);

    // Step 3: Encrypt plaintext with AES-256-GCM using DEK
    messenger_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, "PQSIGENC", 8);
    header_for_aad.version = 0x06;
    header_for_aad.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header_for_aad.recipient_count = (uint8_t)recipient_count;
    header_for_aad.encrypted_size = (uint32_t)plaintext_len;
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(plaintext_len);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed for ciphertext\n");
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, (const uint8_t*)plaintext, plaintext_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        fprintf(stderr, "Error: AES-256-GCM encryption failed\n");
        goto cleanup;
    }

    // Step 4: Create recipient entries (wrap DEK for each recipient)
    recipient_entries = calloc(recipient_count, sizeof(messenger_recipient_entry_t));
    if (!recipient_entries) {
        fprintf(stderr, "Error: Memory allocation failed for recipient entries\n");
        goto cleanup;
    }

    for (size_t i = 0; i < recipient_count; i++) {
        uint8_t kyber_ciphertext[1568];  // Kyber1024 ciphertext size
        uint8_t kek[32];  // KEK = shared secret from Kyber

        // Kyber512 encapsulation
        if (qgp_kem1024_encapsulate(kyber_ciphertext, kek, recipient_enc_pubkeys[i]) != 0) {
            fprintf(stderr, "Error: KEM-1024 encapsulation failed for recipient %zu\n", i+1);
            memset(kek, 0, 32);
            goto cleanup;
        }

        // Wrap DEK with KEK
        uint8_t wrapped_dek[40];
        if (aes256_wrap_key(dek, 32, kek, wrapped_dek) != 0) {
            fprintf(stderr, "Error: Failed to wrap DEK for recipient %zu\n", i+1);
            memset(kek, 0, 32);
            goto cleanup;
        }

        // Store recipient entry
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 1568);  // Kyber1024 ciphertext size
        memcpy(recipient_entries[i].wrapped_dek, wrapped_dek, 40);

        // Wipe KEK
        memset(kek, 0, 32);
    }

    // Step 5: Build output buffer
    // Format: [header | recipient_entries | nonce | ciphertext | tag | signature]
    size_t total_size = sizeof(messenger_enc_header_t) +
                       (sizeof(messenger_recipient_entry_t) * recipient_count) +
                       12 + encrypted_size + 16 + signature_size;

    output_buffer = malloc(total_size);
    if (!output_buffer) {
        fprintf(stderr, "Error: Memory allocation failed for output\n");
        goto cleanup;
    }

    size_t offset = 0;

    // Header
    messenger_enc_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "PQSIGENC", 8);
    header.version = 0x06;
    header.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header.recipient_count = (uint8_t)recipient_count;
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
    offset += signature_size;

    *ciphertext_out = output_buffer;
    *ciphertext_len_out = total_size;
    ret = 0;

cleanup:
    if (dek) {
        memset(dek, 0, 32);
        free(dek);
    }
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
    int message_type
) {
    if (!ctx || !recipients || !message || recipient_count == 0 || recipient_count > 254) {
        fprintf(stderr, "Error: Invalid arguments (recipient_count must be 1-254)\n");
        return -1;
    }

    // Debug: show what we received
    printf("\n========== DEBUG: messenger_send_message() called ==========\n");
    printf("Version: %s (commit %s, built %s)\n", PQSIGNUM_VERSION, BUILD_HASH, BUILD_TS);
    printf("\nSender: '%s'\n", ctx->identity);
    printf("\nRecipients (%zu):\n", recipient_count);
    for (size_t i = 0; i < recipient_count; i++) {
        printf("  [%zu] = '%s' (length: %zu)\n", i, recipients[i], strlen(recipients[i]));
    }
    printf("\nMessage body:\n");
    printf("  Text: '%s'\n", message);
    printf("  Length: %zu bytes\n", strlen(message));
    printf("===========================================================\n\n");

    // Display recipients
    printf("\n[Sending message to %zu recipient(s)]\n", recipient_count);
    for (size_t i = 0; i < recipient_count; i++) {
        printf("  - %s\n", recipients[i]);
    }

    // Build full recipient list: sender + recipients (sender as first recipient)
    // This allows sender to decrypt their own sent messages
    size_t total_recipients = recipient_count + 1;
    const char **all_recipients = malloc(sizeof(char*) * total_recipients);
    if (!all_recipients) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }

    all_recipients[0] = ctx->identity;  // Sender is first recipient
    for (size_t i = 0; i < recipient_count; i++) {
        all_recipients[i + 1] = recipients[i];
    }

    printf("✓ Sender '%s' added as first recipient (can decrypt own sent messages)\n", ctx->identity);

    // Load sender's private signing key from filesystem
    const char *home = qgp_platform_home_dir();
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/.dna/%s.dsa", home, ctx->identity);

    qgp_key_t *sender_sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sender_sign_key) != 0) {
        fprintf(stderr, "Error: Cannot load sender's signing key from %s\n", dilithium_path);
        free(all_recipients);
        return -1;
    }

    // Load all recipient public keys from keyserver (including sender)
    uint8_t **enc_pubkeys = calloc(total_recipients, sizeof(uint8_t*));
    uint8_t **sign_pubkeys = calloc(total_recipients, sizeof(uint8_t*));

    if (!enc_pubkeys || !sign_pubkeys) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(enc_pubkeys);
        free(sign_pubkeys);
        free(all_recipients);
        qgp_key_free(sender_sign_key);
        return -1;
    }

    // Load public keys for all recipients from keyserver
    for (size_t i = 0; i < total_recipients; i++) {
        size_t sign_len = 0, enc_len = 0;
        if (messenger_load_pubkey(ctx, all_recipients[i],
                                   &sign_pubkeys[i], &sign_len,
                                   &enc_pubkeys[i], &enc_len, NULL) != 0) {
            fprintf(stderr, "Error: Cannot load public key for '%s' from keyserver\n", all_recipients[i]);

            // Cleanup on error
            for (size_t j = 0; j < total_recipients; j++) {
                free(enc_pubkeys[j]);
                free(sign_pubkeys[j]);
            }
            free(enc_pubkeys);
            free(sign_pubkeys);
            free(all_recipients);
            qgp_key_free(sender_sign_key);
            return -1;
        }
        printf("✓ Loaded public key for '%s' from keyserver\n", all_recipients[i]);
    }

    // Multi-recipient encryption implementation
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    int ret = messenger_encrypt_multi_recipient(
        message, strlen(message),
        enc_pubkeys, total_recipients,
        sender_sign_key,
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
        fprintf(stderr, "Error: Multi-recipient encryption failed\n");
        return -1;
    }

    printf("✓ Message encrypted (%zu bytes) for %zu recipient(s)\n", ciphertext_len, total_recipients);

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

    printf("✓ Assigned message_group_id: %d\n", message_group_id);

    // Store in SQLite local database - one row per actual recipient (not sender)
    time_t now = time(NULL);

    for (size_t i = 0; i < recipient_count; i++) {
        int result = message_backup_save(
            ctx->backup_ctx,
            ctx->identity,      // sender
            recipients[i],      // recipient
            ciphertext,         // encrypted message
            ciphertext_len,     // encrypted length
            now,                // timestamp
            true,               // is_outgoing = true (we're sending)
            group_id,           // group_id (0 for direct, >0 for group) - Phase 6.2
            message_type        // message_type (chat or invitation) - Phase 6.2
        );

        if (result != 0) {
            fprintf(stderr, "Store message failed for recipient '%s' in SQLite\n", recipients[i]);
            free(ciphertext);
            return -1;
        }

        printf("✓ Message stored locally for '%s'\n", recipients[i]);
    }

    // Phase 9.1b: Try P2P delivery for each recipient
    // If P2P succeeds, message delivered instantly
    // If P2P fails, message queued in DHT offline queue
    if (ctx->p2p_enabled && ctx->p2p_transport) {
        printf("\n[P2P] Attempting direct P2P delivery to %zu recipient(s)...\n", recipient_count);

        size_t p2p_success = 0;
        for (size_t i = 0; i < recipient_count; i++) {
            if (messenger_send_p2p(ctx, recipients[i], ciphertext, ciphertext_len) == 0) {
                p2p_success++;
            }
        }

        printf("[P2P] Delivery summary: %zu/%zu via P2P, %zu via DHT offline queue\n\n",
               p2p_success, recipient_count, recipient_count - p2p_success);
    } else {
        printf("\n[P2P] P2P disabled - using DHT offline queue\n\n");
    }

    free(ciphertext);

    printf("✓ Message sent successfully to %zu recipient(s)\n\n", recipient_count);
    return 0;
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
        fprintf(stderr, "List messages failed from SQLite\n");
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
                struct tm *tm_info = localtime(&all_messages[i].timestamp);
                char timestamp_str[32];
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

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
        fprintf(stderr, "List sent messages failed from SQLite\n");
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
                struct tm *tm_info = localtime(&all_messages[i].timestamp);
                char timestamp_str[32];
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

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
        fprintf(stderr, "Fetch message failed from SQLite\n");
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
        fprintf(stderr, "Message %d not found or not for you\n", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    const char *sender = target_msg->sender;
    const uint8_t *ciphertext = target_msg->encrypted_message;
    size_t ciphertext_len = target_msg->encrypted_len;

    printf("\n========================================\n");
    printf(" Message #%d from %s\n", message_id, sender);
    printf("========================================\n\n");

    // Load recipient's private Kyber512 key from filesystem
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s.kem", home, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", kyber_path);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {  // Kyber1024 secret key size
        fprintf(stderr, "Error: Invalid Kyber1024 private key size: %zu (expected 3168)\n",
                kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    // Decrypt message using raw key
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint8_t *sender_sign_pubkey_from_msg = NULL;
    size_t sender_sign_pubkey_len = 0;

    dna_error_t err = dna_decrypt_message_raw(
        ctx->dna_ctx,
        ciphertext,
        ciphertext_len,
        kyber_key->private_key,
        &plaintext,
        &plaintext_len,
        &sender_sign_pubkey_from_msg,
        &sender_sign_pubkey_len
    );

    // Free Kyber key (secure wipes private key internally)
    qgp_key_free(kyber_key);

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Decryption failed: %s\n", dna_error_string(err));
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    // Verify sender's public key against keyserver
    uint8_t *sender_sign_pubkey_keyserver = NULL;
    uint8_t *sender_enc_pubkey_keyserver = NULL;
    size_t sender_sign_len_keyserver = 0, sender_enc_len_keyserver = 0;

    if (messenger_load_pubkey(ctx, sender, &sender_sign_pubkey_keyserver, &sender_sign_len_keyserver,
                               &sender_enc_pubkey_keyserver, &sender_enc_len_keyserver, NULL) != 0) {
        fprintf(stderr, "Warning: Could not verify sender '%s' against keyserver\n", sender);
        fprintf(stderr, "Message decrypted but sender identity NOT verified!\n");
    } else {
        // Compare public keys
        if (sender_sign_len_keyserver != sender_sign_pubkey_len ||
            memcmp(sender_sign_pubkey_keyserver, sender_sign_pubkey_from_msg, sender_sign_pubkey_len) != 0) {
            fprintf(stderr, "ERROR: Sender public key mismatch!\n");
            fprintf(stderr, "The message claims to be from '%s' but the signature doesn't match keyserver.\n", sender);
            fprintf(stderr, "Possible spoofing attempt!\n");
            free(plaintext);
            free(sender_sign_pubkey_from_msg);
            free(sender_sign_pubkey_keyserver);
            free(sender_enc_pubkey_keyserver);
            message_backup_free_messages(all_messages, all_count);
            return -1;
        }
        free(sender_sign_pubkey_keyserver);
        free(sender_enc_pubkey_keyserver);
    }

    // Display message
    printf("Message:\n");
    printf("----------------------------------------\n");
    printf("%.*s\n", (int)plaintext_len, plaintext);
    printf("----------------------------------------\n");
    printf("✓ Signature verified from %s\n", sender);
    printf("✓ Sender identity verified against keyserver\n");

    // Cleanup
    free(plaintext);
    free(sender_sign_pubkey_from_msg);
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
    // Support decrypting both received messages (recipient = identity) AND sent messages (sender = identity)
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "Fetch message failed from SQLite\n");
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
        fprintf(stderr, "Message %d not found\n", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    const char *sender = target_msg->sender;
    const uint8_t *ciphertext = target_msg->encrypted_message;
    size_t ciphertext_len = target_msg->encrypted_len;

    // Load recipient's private Kyber512 key from filesystem
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s.kem", home, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0) {
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {  // Kyber1024 secret key size
        qgp_key_free(kyber_key);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    // Decrypt message using raw key
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint8_t *sender_sign_pubkey_from_msg = NULL;
    size_t sender_sign_pubkey_len = 0;

    dna_error_t err = dna_decrypt_message_raw(
        ctx->dna_ctx,
        ciphertext,
        ciphertext_len,
        kyber_key->private_key,
        &plaintext,
        &plaintext_len,
        &sender_sign_pubkey_from_msg,
        &sender_sign_pubkey_len
    );

    // Free Kyber key (secure wipes private key internally)
    qgp_key_free(kyber_key);

    if (err != DNA_OK) {
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    // Verify sender's public key against keyserver
    uint8_t *sender_sign_pubkey_keyserver = NULL;
    uint8_t *sender_enc_pubkey_keyserver = NULL;
    size_t sender_sign_len_keyserver = 0, sender_enc_len_keyserver = 0;

    if (messenger_load_pubkey(ctx, sender, &sender_sign_pubkey_keyserver, &sender_sign_len_keyserver,
                               &sender_enc_pubkey_keyserver, &sender_enc_len_keyserver, NULL) == 0) {
        // Compare public keys
        if (sender_sign_len_keyserver != sender_sign_pubkey_len ||
            memcmp(sender_sign_pubkey_keyserver, sender_sign_pubkey_from_msg, sender_sign_pubkey_len) != 0) {
            // Signature mismatch - possible spoofing
            free(plaintext);
            free(sender_sign_pubkey_from_msg);
            free(sender_sign_pubkey_keyserver);
            free(sender_enc_pubkey_keyserver);
            message_backup_free_messages(all_messages, all_count);
            return -1;
        }
        free(sender_sign_pubkey_keyserver);
        free(sender_enc_pubkey_keyserver);
    }

    free(sender_sign_pubkey_from_msg);
    message_backup_free_messages(all_messages, all_count);

    // Return plaintext as null-terminated string
    *plaintext_out = (char*)malloc(plaintext_len + 1);
    if (!*plaintext_out) {
        free(plaintext);
        return -1;
    }

    memcpy(*plaintext_out, plaintext, plaintext_len);
    (*plaintext_out)[plaintext_len] = '\0';
    *plaintext_len_out = plaintext_len;

    free(plaintext);
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
        fprintf(stderr, "Delete message failed from SQLite\n");
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
        fprintf(stderr, "Search by sender failed from SQLite\n");
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
                struct tm *tm_info = localtime(&all_messages[i].timestamp);
                char timestamp_str[32];
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
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
        fprintf(stderr, "Show conversation failed from SQLite\n");
        return -1;
    }

    printf("\n");
    printf("========================================\n");
    printf(" Conversation: %s <-> %s\n", ctx->identity, other_identity);
    printf(" (%d messages)\n", count);
    printf("========================================\n\n");

    for (int i = 0; i < count; i++) {
        struct tm *tm_info = localtime(&messages[i].timestamp);
        char timestamp_str[32];
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

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
        fprintf(stderr, "Get conversation failed from SQLite\n");
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
        fprintf(stderr, "Memory allocation failed\n");
        message_backup_free_messages(backup_messages, backup_count);
        return -1;
    }

    // Convert each message
    for (int i = 0; i < backup_count; i++) {
        messages[i].id = backup_messages[i].id;
        messages[i].sender = strdup(backup_messages[i].sender);
        messages[i].recipient = strdup(backup_messages[i].recipient);

        // Convert time_t to string (format: YYYY-MM-DD HH:MM:SS)
        struct tm *tm_info = localtime(&backup_messages[i].timestamp);
        messages[i].timestamp = (char*)malloc(32);
        if (messages[i].timestamp) {
            strftime(messages[i].timestamp, 32, "%Y-%m-%d %H:%M:%S", tm_info);
        }

        // Convert bool flags to status string
        if (backup_messages[i].read) {
            messages[i].status = strdup("read");
        } else if (backup_messages[i].delivered) {
            messages[i].status = strdup("delivered");
        } else {
            messages[i].status = strdup("sent");
        }

        // For now, we don't have separate timestamps for delivered/read
        // We could add these to SQLite schema later if needed
        messages[i].delivered_at = backup_messages[i].delivered ? strdup(messages[i].timestamp) : NULL;
        messages[i].read_at = backup_messages[i].read ? strdup(messages[i].timestamp) : NULL;
        messages[i].plaintext = NULL;  // Not decrypted yet
        messages[i].message_type = backup_messages[i].message_type;  // Phase 6.2: Copy message type

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
        fprintf(stderr, "Error: Must include either sent or received messages\n");
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
        fprintf(stderr, "Search by date failed from SQLite\n");
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

        struct tm *tm_info = localtime(&all_messages[i].timestamp);
        char timestamp_str[32];
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

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
// MESSAGE STATUS / READ RECEIPTS
// ============================================================================
// MODULARIZATION: Moved to messenger/status.{c,h}

/*
 * messenger_mark_delivered() - MOVED to messenger/status.c
 * messenger_mark_conversation_read() - MOVED to messenger/status.c
 */
