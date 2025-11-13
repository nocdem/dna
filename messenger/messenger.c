/*
 * DNA Messenger - PostgreSQL Implementation
 *
 * Phase 3: Local PostgreSQL (localhost)
 * Phase 4: Network PostgreSQL (remote server)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
// Windows doesn't have htonll/ntohll, define them
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#else
#include <sys/time.h>
#include <unistd.h>  // For unlink(), close()
#include <dirent.h>  // For directory operations (migration detection)
#include <arpa/inet.h>  // For htonl, htonll
// Define htonll/ntohll if not available
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#endif
#endif
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "messenger.h"
#include "messenger_p2p.h"  // Phase 9.1b: P2P delivery integration
#include "dna_config.h"
#include "qgp_platform.h"
#include "qgp_dilithium.h"
#include "qgp_kyber.h"
#include "qgp_sha3.h"  // For SHA3-512 fingerprint computation
#include "dht/dht_singleton.h"  // Global DHT singleton
#include "dht/dht_identity_backup.h"  // DHT identity encrypted backup
#include "qgp_types.h"  // For qgp_key_load, qgp_key_free
#include "qgp.h"  // For cmd_gen_key_from_seed, cmd_export_pubkey
#include "bip39.h"  // For BIP39_MAX_MNEMONIC_LENGTH, bip39_validate_mnemonic, qgp_derive_seeds_from_mnemonic
#include "kyber_deterministic.h"  // For crypto_kem_keypair_derand
#include "qgp_aes.h"  // For qgp_aes256_encrypt
#include "aes_keywrap.h"  // For aes256_wrap_key
#include "qgp_random.h"  // For qgp_randombytes
#include "keyserver_cache.h"  // Phase 4: Keyserver cache
#include "dht/dht_keyserver.h"   // Phase 9.4: DHT-based keyserver
#include "dht/dht_context.h"     // Phase 9.4: DHT context management
#include "dht/dht_contactlist.h" // DHT contact list sync
#include "p2p/p2p_transport.h"   // For getting DHT context
#include "contacts_db.h"         // Phase 9.4: Local contacts database
#include "messenger/identity.h"  // Phase: Modularization - Identity utilities
#include "messenger/init.h"      // Phase: Modularization - Context management
#include "messenger/status.h"    // Phase: Modularization - Message status
#include "messenger/keys.h"      // Phase: Modularization - Public key management
#include "messenger/contacts.h"  // Phase: Modularization - DHT contact sync
#include "messenger/keygen.h"    // Phase: Modularization - Key generation

// Global configuration
static dna_config_t g_config;

// ============================================================================
// INITIALIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/init.{c,h}

/*
 * resolve_identity_to_fingerprint() - MOVED to messenger/init.c (static helper)
 * messenger_init() - MOVED to messenger/init.c
 * messenger_free() - MOVED to messenger/init.c
 * messenger_load_dht_identity() - MOVED to messenger/init.c
 */
// ============================================================================
// KEY GENERATION
// ============================================================================
// MODULARIZATION: Moved to messenger/keygen.{c,h}

/*
 * messenger_generate_keys() - MOVED to messenger/keygen.c
 * messenger_generate_keys_from_seeds() - MOVED to messenger/keygen.c
 * messenger_register_name() - MOVED to messenger/keygen.c
 * messenger_restore_keys() - MOVED to messenger/keygen.c
 * messenger_restore_keys_from_file() - MOVED to messenger/keygen.c
 */

// ============================================================================
// FINGERPRINT UTILITIES (Phase 4: Fingerprint-First Identity)
// ============================================================================
// MODULARIZATION: Moved to messenger/identity.{c,h}

/*
 * messenger_compute_identity_fingerprint() - MOVED to messenger/identity.c
 * messenger_is_fingerprint() - MOVED to messenger/identity.c
 * messenger_get_display_name() - MOVED to messenger/identity.c
 */

// ============================================================================
// IDENTITY MIGRATION (Phase 4: Old Names → Fingerprints)
// ============================================================================

/**
 * Detect old-style identity files that need migration
 */
int messenger_detect_old_identities(char ***identities_out, int *count_out) {
    if (!identities_out || !count_out) {
        fprintf(stderr, "ERROR: Invalid arguments to messenger_detect_old_identities\n");
        return -1;
    }

    const char *home = qgp_platform_home_dir();
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Scan for .dsa files
    char **identities = NULL;
    int count = 0;
    int capacity = 10;

    identities = malloc(capacity * sizeof(char*));
    if (!identities) {
        return -1;
    }

#ifdef _WIN32
    // Windows directory iteration
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s\\*.dsa", dna_dir);

    WIN32_FIND_DATAA find_data;
    HANDLE handle = FindFirstFileA(search_path, &find_data);

    if (handle == INVALID_HANDLE_VALUE) {
        *identities_out = NULL;
        *count_out = 0;
        free(identities);
        return 0;  // No .dsa files found
    }

    do {
        const char *filename = find_data.cFileName;
        size_t len = strlen(filename);

        if (len < 5) continue;

        // Extract name (remove .dsa extension)
        char name[256];
        strncpy(name, filename, len - 4);
        name[len - 4] = '\0';
#else
    // POSIX directory iteration
    DIR *dir = opendir(dna_dir);
    if (!dir) {
        *identities_out = NULL;
        *count_out = 0;
        free(identities);
        return 0;  // No .dna directory, no identities to migrate
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Look for .dsa files
        size_t len = strlen(entry->d_name);
        if (len < 5 || strcmp(entry->d_name + len - 4, ".dsa") != 0) {
            continue;
        }

        // Extract name (remove .dsa extension)
        char name[256];
        strncpy(name, entry->d_name, len - 4);
        name[len - 4] = '\0';
#endif

        // Skip if already a fingerprint (128 hex chars)
        if (messenger_is_fingerprint(name)) {
            continue;
        }

        // Skip backup directory
        if (strstr(name, "backup") != NULL) {
            continue;
        }

        // This is an old-style identity that needs migration
        if (count >= capacity) {
            capacity *= 2;
            char **new_identities = realloc(identities, capacity * sizeof(char*));
            if (!new_identities) {
                for (int i = 0; i < count; i++) free(identities[i]);
                free(identities);
#ifdef _WIN32
                FindClose(handle);
#else
                closedir(dir);
#endif
                return -1;
            }
            identities = new_identities;
        }

        identities[count] = strdup(name);
        if (!identities[count]) {
            for (int i = 0; i < count; i++) free(identities[i]);
            free(identities);
#ifdef _WIN32
            FindClose(handle);
#else
            closedir(dir);
#endif
            return -1;
        }
        count++;
#ifdef _WIN32
    } while (FindNextFileA(handle, &find_data));

    FindClose(handle);
#else
    }

    closedir(dir);
#endif

    *identities_out = identities;
    *count_out = count;
    return 0;
}

/**
 * Migrate identity files from old naming to fingerprint naming
 */
int messenger_migrate_identity_files(const char *old_name, char *fingerprint_out) {
    if (!old_name || !fingerprint_out) {
        fprintf(stderr, "ERROR: Invalid arguments to messenger_migrate_identity_files\n");
        return -1;
    }

    const char *home = qgp_platform_home_dir();
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    printf("[MIGRATION] Migrating identity '%s' to fingerprint-based naming...\n", old_name);

    // 1. Compute fingerprint from existing key file
    if (messenger_compute_identity_fingerprint(old_name, fingerprint_out) != 0) {
        fprintf(stderr, "[MIGRATION] Failed to compute fingerprint for '%s'\n", old_name);
        return -1;
    }

    printf("[MIGRATION] Computed fingerprint: %s\n", fingerprint_out);

    // 2. Create backup directory
    char backup_dir[512];
    snprintf(backup_dir, sizeof(backup_dir), "%s/backup_pre_migration", dna_dir);

    if (qgp_platform_mkdir(backup_dir) != 0) {
        // Directory might already exist, check if it's actually a directory
        if (!qgp_platform_is_directory(backup_dir)) {
            fprintf(stderr, "[MIGRATION] Failed to create backup directory\n");
            return -1;
        }
    }

    printf("[MIGRATION] Created backup directory: %s\n", backup_dir);

    // 3. Define file paths
    char old_dsa[512], old_kem[512], old_contacts[512];
    char new_dsa[512], new_kem[512], new_contacts[512];
    char backup_dsa[512], backup_kem[512], backup_contacts[512];

    snprintf(old_dsa, sizeof(old_dsa), "%s/%s.dsa", dna_dir, old_name);
    snprintf(old_kem, sizeof(old_kem), "%s/%s.kem", dna_dir, old_name);
    snprintf(old_contacts, sizeof(old_contacts), "%s/%s_contacts.db", dna_dir, old_name);

    snprintf(new_dsa, sizeof(new_dsa), "%s/%s.dsa", dna_dir, fingerprint_out);
    snprintf(new_kem, sizeof(new_kem), "%s/%s.kem", dna_dir, fingerprint_out);
    snprintf(new_contacts, sizeof(new_contacts), "%s/%s_contacts.db", dna_dir, fingerprint_out);

    snprintf(backup_dsa, sizeof(backup_dsa), "%s/%s.dsa", backup_dir, old_name);
    snprintf(backup_kem, sizeof(backup_kem), "%s/%s.kem", backup_dir, old_name);
    snprintf(backup_contacts, sizeof(backup_contacts), "%s/%s_contacts.db", backup_dir, old_name);

    // 4. Copy files to backup (before renaming)
    bool has_errors = false;

    if (file_exists(old_dsa)) {
        FILE *src = fopen(old_dsa, "rb");
        FILE *dst = fopen(backup_dsa, "wb");
        if (src && dst) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fclose(src);
            fclose(dst);
            printf("[MIGRATION] Backed up: %s.dsa\n", old_name);
        } else {
            fprintf(stderr, "[MIGRATION] Warning: Failed to backup %s.dsa\n", old_name);
            if (src) fclose(src);
            if (dst) fclose(dst);
            has_errors = true;
        }
    }

    if (file_exists(old_kem)) {
        FILE *src = fopen(old_kem, "rb");
        FILE *dst = fopen(backup_kem, "wb");
        if (src && dst) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fclose(src);
            fclose(dst);
            printf("[MIGRATION] Backed up: %s.kem\n", old_name);
        } else {
            fprintf(stderr, "[MIGRATION] Warning: Failed to backup %s.kem\n", old_name);
            if (src) fclose(src);
            if (dst) fclose(dst);
            has_errors = true;
        }
    }

    if (file_exists(old_contacts)) {
        FILE *src = fopen(old_contacts, "rb");
        FILE *dst = fopen(backup_contacts, "wb");
        if (src && dst) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fclose(src);
            fclose(dst);
            printf("[MIGRATION] Backed up: %s_contacts.db\n", old_name);
        } else {
            if (src) fclose(src);
            if (dst) fclose(dst);
            // Contacts DB is optional, not an error if missing
        }
    }

    if (has_errors) {
        fprintf(stderr, "[MIGRATION] Backup had errors, aborting migration\n");
        return -1;
    }

    // 5. Rename files to use fingerprint
    if (file_exists(old_dsa)) {
        if (rename(old_dsa, new_dsa) != 0) {
            fprintf(stderr, "[MIGRATION] Failed to rename %s.dsa\n", old_name);
            return -1;
        }
        printf("[MIGRATION] Renamed: %s.dsa → %s.dsa\n", old_name, fingerprint_out);
    }

    if (file_exists(old_kem)) {
        if (rename(old_kem, new_kem) != 0) {
            fprintf(stderr, "[MIGRATION] Failed to rename %s.kem\n", old_name);
            // Try to rollback .dsa
            rename(new_dsa, old_dsa);
            return -1;
        }
        printf("[MIGRATION] Renamed: %s.kem → %s.kem\n", old_name, fingerprint_out);
    }

    if (file_exists(old_contacts)) {
        if (rename(old_contacts, new_contacts) != 0) {
            fprintf(stderr, "[MIGRATION] Warning: Failed to rename %s_contacts.db (non-fatal)\n", old_name);
            // Non-fatal, continue
        } else {
            printf("[MIGRATION] Renamed: %s_contacts.db → %s_contacts.db\n", old_name, fingerprint_out);
        }
    }

    printf("[MIGRATION] ✓ Migration complete for '%s'\n", old_name);
    printf("[MIGRATION] New fingerprint: %s\n", fingerprint_out);
    printf("[MIGRATION] Backups stored in: %s/\n", backup_dir);

    return 0;
}

/**
 * Check if an identity has already been migrated
 */
bool messenger_is_identity_migrated(const char *name) {
    if (!name) return false;

    // Compute fingerprint
    char fingerprint[129];
    if (messenger_compute_identity_fingerprint(name, fingerprint) != 0) {
        return false;
    }

    // Check if fingerprint-named files exist
    const char *home = qgp_platform_home_dir();
    char fingerprint_dsa[512];
    snprintf(fingerprint_dsa, sizeof(fingerprint_dsa), "%s/.dna/%s.dsa", home, fingerprint);

    return file_exists(fingerprint_dsa);
}

// ============================================================================
// PUBLIC KEY MANAGEMENT
// ============================================================================
// MODULARIZATION: Moved to messenger/keys.{c,h}

/*
 * base64_encode() - MOVED to messenger/keys.c (static helper)
 * base64_decode() - MOVED to messenger/keys.c (static helper)
 * messenger_store_pubkey() - MOVED to messenger/keys.c
 * messenger_load_pubkey() - MOVED to messenger/keys.c
 * messenger_list_pubkeys() - MOVED to messenger/keys.c
 * messenger_get_contact_list() - MOVED to messenger/keys.c
 */


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
    const char *message
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
            true                // is_outgoing = true (we're sending)
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

int messenger_delete_pubkey(messenger_context_t *ctx, const char *identity) {
    // TODO: Phase 2/4 - Migrate to DHT keyserver
    fprintf(stderr, "ERROR: messenger_delete_pubkey() not yet implemented (DHT migration pending)\n");
    (void)ctx; (void)identity;
    return -1;
}

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

// ============================================================================
// GROUP MANAGEMENT
// ============================================================================
// NOTE: Group functions temporarily disabled - being migrated to DHT (Phase 3)
// See messenger_stubs.c for temporary stub implementations

#if 0  // DISABLED: PostgreSQL group functions (Phase 3 - DHT migration pending)

/**
 * Create a new group
 */
int messenger_create_group(
    messenger_context_t *ctx,
    const char *name,
    const char *description,
    const char **members,
    size_t member_count,
    int *group_id_out
) {
    if (!ctx || !name || !members || member_count == 0) {
        fprintf(stderr, "Error: Invalid arguments for group creation\n");
        return -1;
    }

    // Validate group name
    if (strlen(name) == 0) {
        fprintf(stderr, "Error: Group name cannot be empty\n");
        return -1;
    }

    // Begin transaction
    PGresult *res = PQexec(ctx->pg_conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Begin transaction failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Insert group
    const char *insert_group_query =
        "INSERT INTO groups (name, description, creator) "
        "VALUES ($1, $2, $3) RETURNING id";

    const char *group_params[3] = {name, description ? description : "", ctx->identity};
    res = PQexecParams(ctx->pg_conn, insert_group_query, 3, NULL, group_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Create group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }

    int group_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    // Add creator as member with role 'creator'
    const char *add_creator_query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'creator')";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *creator_params[2] = {group_id_str, ctx->identity};

    res = PQexecParams(ctx->pg_conn, add_creator_query, 2, NULL, creator_params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Add creator to group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }
    PQclear(res);

    // Add other members with role 'member'
    const char *add_member_query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'member')";

    for (size_t i = 0; i < member_count; i++) {
        const char *member_params[2] = {group_id_str, members[i]};
        res = PQexecParams(ctx->pg_conn, add_member_query, 2, NULL, member_params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Add member '%s' to group failed: %s\n",
                    members[i], PQerrorMessage(ctx->pg_conn));
            PQclear(res);
            PQexec(ctx->pg_conn, "ROLLBACK");
            return -1;
        }
        PQclear(res);
    }

    // Commit transaction
    res = PQexec(ctx->pg_conn, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Commit transaction failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }
    PQclear(res);

    if (group_id_out) {
        *group_id_out = group_id;
    }

    printf("✓ Group '%s' created with ID %d\n", name, group_id);
    printf("✓ Added %zu member(s) to group\n", member_count);
    return 0;
}

/**
 * Get list of all groups current user belongs to
 */
int messenger_get_groups(
    messenger_context_t *ctx,
    group_info_t **groups_out,
    int *count_out
) {
    if (!ctx || !groups_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT g.id, g.name, g.description, g.creator, g.created_at, COUNT(gm.member) as member_count "
        "FROM groups g "
        "JOIN group_members gm ON g.id = gm.group_id "
        "WHERE g.id IN (SELECT group_id FROM group_members WHERE member = $1) "
        "GROUP BY g.id, g.name, g.description, g.creator, g.created_at "
        "ORDER BY g.created_at DESC";

    const char *params[1] = {ctx->identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get groups failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *groups_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    group_info_t *groups = (group_info_t*)calloc(rows, sizeof(group_info_t));
    if (!groups) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy data
    for (int i = 0; i < rows; i++) {
        groups[i].id = atoi(PQgetvalue(res, i, 0));
        groups[i].name = strdup(PQgetvalue(res, i, 1));
        const char *desc = PQgetvalue(res, i, 2);
        groups[i].description = (desc && strlen(desc) > 0) ? strdup(desc) : NULL;
        groups[i].creator = strdup(PQgetvalue(res, i, 3));
        groups[i].created_at = strdup(PQgetvalue(res, i, 4));
        groups[i].member_count = atoi(PQgetvalue(res, i, 5));

        if (!groups[i].name || !groups[i].creator || !groups[i].created_at) {
            // Cleanup on error
            for (int j = 0; j <= i; j++) {
                free(groups[j].name);
                free(groups[j].description);
                free(groups[j].creator);
                free(groups[j].created_at);
            }
            free(groups);
            PQclear(res);
            return -1;
        }
    }

    *groups_out = groups;
    PQclear(res);
    return 0;
}

/**
 * Get group info by ID
 */
int messenger_get_group_info(
    messenger_context_t *ctx,
    int group_id,
    group_info_t *group_out
) {
    if (!ctx || !group_out) {
        return -1;
    }

    const char *query =
        "SELECT g.id, g.name, g.description, g.creator, g.created_at, COUNT(gm.member) as member_count "
        "FROM groups g "
        "JOIN group_members gm ON g.id = gm.group_id "
        "WHERE g.id = $1 "
        "GROUP BY g.id, g.name, g.description, g.creator, g.created_at";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group info failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Group %d not found\n", group_id);
        PQclear(res);
        return -1;
    }

    group_out->id = atoi(PQgetvalue(res, 0, 0));
    group_out->name = strdup(PQgetvalue(res, 0, 1));
    const char *desc = PQgetvalue(res, 0, 2);
    group_out->description = (desc && strlen(desc) > 0) ? strdup(desc) : NULL;
    group_out->creator = strdup(PQgetvalue(res, 0, 3));
    group_out->created_at = strdup(PQgetvalue(res, 0, 4));
    group_out->member_count = atoi(PQgetvalue(res, 0, 5));

    PQclear(res);

    if (!group_out->name || !group_out->creator || !group_out->created_at) {
        free(group_out->name);
        free(group_out->description);
        free(group_out->creator);
        free(group_out->created_at);
        return -1;
    }

    return 0;
}

/**
 * Get members of a specific group
 */
int messenger_get_group_members(
    messenger_context_t *ctx,
    int group_id,
    char ***members_out,
    int *count_out
) {
    if (!ctx || !members_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT member FROM group_members WHERE group_id = $1 ORDER BY joined_at ASC";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group members failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *members_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    char **members = (char**)malloc(sizeof(char*) * rows);
    if (!members) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy member names
    for (int i = 0; i < rows; i++) {
        members[i] = strdup(PQgetvalue(res, i, 0));
        if (!members[i]) {
            // Cleanup on error
            for (int j = 0; j < i; j++) {
                free(members[j]);
            }
            free(members);
            PQclear(res);
            return -1;
        }
    }

    *members_out = members;
    PQclear(res);
    return 0;
}

/**
 * Add member to group
 */
int messenger_add_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
) {
    if (!ctx || !member) {
        return -1;
    }

    const char *query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'member')";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[2] = {group_id_str, member};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Add group member failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Added '%s' to group %d\n", member, group_id);
    return 0;
}

/**
 * Remove member from group
 */
int messenger_remove_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
) {
    if (!ctx || !member) {
        return -1;
    }

    const char *query =
        "DELETE FROM group_members WHERE group_id = $1 AND member = $2";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[2] = {group_id_str, member};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Remove group member failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Removed '%s' from group %d\n", member, group_id);
    return 0;
}

/**
 * Leave a group
 */
int messenger_leave_group(
    messenger_context_t *ctx,
    int group_id
) {
    if (!ctx) {
        return -1;
    }

    return messenger_remove_group_member(ctx, group_id, ctx->identity);
}

/**
 * Delete a group (creator only)
 */
int messenger_delete_group(
    messenger_context_t *ctx,
    int group_id
) {
    if (!ctx) {
        return -1;
    }

    // Verify current user is the creator
    const char *check_query = "SELECT creator FROM groups WHERE id = $1";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *check_params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, check_query, 1, NULL, check_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Check group creator failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Group %d not found\n", group_id);
        PQclear(res);
        return -1;
    }

    const char *creator = PQgetvalue(res, 0, 0);
    if (strcmp(creator, ctx->identity) != 0) {
        fprintf(stderr, "Error: Only the group creator can delete the group\n");
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Delete group (CASCADE will delete members automatically)
    const char *delete_query = "DELETE FROM groups WHERE id = $1";
    const char *delete_params[1] = {group_id_str};

    res = PQexecParams(ctx->pg_conn, delete_query, 1, NULL, delete_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Group %d deleted\n", group_id);
    return 0;
}

/**
 * Update group info (name, description)
 */
int messenger_update_group_info(
    messenger_context_t *ctx,
    int group_id,
    const char *name,
    const char *description
) {
    if (!ctx) {
        return -1;
    }

    if (!name && !description) {
        fprintf(stderr, "Error: Must provide at least name or description to update\n");
        return -1;
    }

    // Build dynamic query
    char query[512] = "UPDATE groups SET ";
    bool need_comma = false;

    if (name) {
        strcat(query, "name = $2");
        need_comma = true;
    }

    if (description) {
        if (need_comma) strcat(query, ", ");
        if (name) {
            strcat(query, "description = $3");
        } else {
            strcat(query, "description = $2");
        }
    }

    strcat(query, " WHERE id = $1");

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);

    const char *params[3] = {group_id_str, NULL, NULL};
    int param_count = 1;

    if (name) {
        params[param_count++] = name;
    }
    if (description) {
        params[param_count++] = description;
    }

    PGresult *res = PQexecParams(ctx->pg_conn, query, param_count, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Update group info failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Group %d updated\n", group_id);
    return 0;
}

/**
 * Send message to group
 */
int messenger_send_group_message(
    messenger_context_t *ctx,
    int group_id,
    const char *message
) {
    if (!ctx || !message) {
        return -1;
    }

    // Get all group members except current user
    char **members = NULL;
    int member_count = 0;

    if (messenger_get_group_members(ctx, group_id, &members, &member_count) != 0) {
        fprintf(stderr, "Error: Failed to get group members\n");
        return -1;
    }

    if (member_count == 0) {
        fprintf(stderr, "Error: Group has no members\n");
        return -1;
    }

    // Filter out current user from recipients
    const char **recipients = (const char**)malloc(sizeof(char*) * member_count);
    size_t recipient_count = 0;

    for (int i = 0; i < member_count; i++) {
        if (strcmp(members[i], ctx->identity) != 0) {
            recipients[recipient_count++] = members[i];
        }
    }

    if (recipient_count == 0) {
        fprintf(stderr, "Error: No other members in group besides sender\n");
        free(recipients);
        for (int i = 0; i < member_count; i++) free(members[i]);
        free(members);
        return -1;
    }

    // Send message to all recipients
    int ret = messenger_send_message(ctx, recipients, recipient_count, message);

    // Cleanup
    free(recipients);
    for (int i = 0; i < member_count; i++) free(members[i]);
    free(members);

    if (ret == 0) {
        printf("✓ Message sent to group %d (%zu recipients)\n", group_id, recipient_count);
    }

    return ret;
}

/**
 * Get conversation for a group
 */
int messenger_get_group_conversation(
    messenger_context_t *ctx,
    int group_id,
    message_info_t **messages_out,
    int *count_out
) {
    if (!ctx || !messages_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT id, sender, recipient, created_at, status, delivered_at, read_at "
        "FROM messages "
        "WHERE group_id = $1 "
        "ORDER BY created_at ASC";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group conversation failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *messages_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    message_info_t *messages = (message_info_t*)calloc(rows, sizeof(message_info_t));
    if (!messages) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy message data
    for (int i = 0; i < rows; i++) {
        messages[i].id = atoi(PQgetvalue(res, i, 0));
        messages[i].sender = strdup(PQgetvalue(res, i, 1));
        messages[i].recipient = strdup(PQgetvalue(res, i, 2));
        messages[i].timestamp = strdup(PQgetvalue(res, i, 3));
        const char *status = PQgetvalue(res, i, 4);
        messages[i].status = strdup(status ? status : "sent");
        const char *delivered_at = PQgetvalue(res, i, 5);
        messages[i].delivered_at = (delivered_at && strlen(delivered_at) > 0) ? strdup(delivered_at) : NULL;
        const char *read_at = PQgetvalue(res, i, 6);
        messages[i].read_at = (read_at && strlen(read_at) > 0) ? strdup(read_at) : NULL;
        messages[i].plaintext = NULL;

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp || !messages[i].status) {
            // Cleanup on error
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].status);
                free(messages[j].delivered_at);
                free(messages[j].read_at);
            }
            free(messages);
            PQclear(res);
            return -1;
        }
    }

    *messages_out = messages;
    PQclear(res);
    return 0;
}

/**
 * Free group array
 */
void messenger_free_groups(group_info_t *groups, int count) {
    if (!groups) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(groups[i].name);
        free(groups[i].description);
        free(groups[i].creator);
        free(groups[i].created_at);
    }
    free(groups);
}

#endif  // DISABLED: PostgreSQL group functions


// ============================================================================
// DHT CONTACT LIST SYNCHRONIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/contacts.{c,h}

/*
 * messenger_sync_contacts_to_dht() - MOVED to messenger/contacts.c
 * messenger_sync_contacts_from_dht() - MOVED to messenger/contacts.c
 * messenger_contacts_auto_sync() - MOVED to messenger/contacts.c
 */


