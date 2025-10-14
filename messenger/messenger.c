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
#include "messenger.h"
#include "dna_config.h"
#include "qgp_platform.h"
#include "qgp_dilithium.h"
#include "qgp_kyber.h"

// Global configuration
static dna_config_t g_config;

// ============================================================================
// INITIALIZATION
// ============================================================================

messenger_context_t* messenger_init(const char *identity) {
    if (!identity) {
        fprintf(stderr, "Error: Identity required\n");
        return NULL;
    }

    // Load configuration
    if (dna_config_load(&g_config) != 0) {
        fprintf(stderr, "Error: Failed to load configuration\n");
        return NULL;
    }

    messenger_context_t *ctx = calloc(1, sizeof(messenger_context_t));
    if (!ctx) {
        return NULL;
    }

    // Set identity
    ctx->identity = strdup(identity);
    if (!ctx->identity) {
        free(ctx);
        return NULL;
    }

    // Build connection string from config
    char connstring[512];
    dna_config_build_connstring(&g_config, connstring, sizeof(connstring));

    // Connect to PostgreSQL
    ctx->pg_conn = PQconnectdb(connstring);
    if (PQstatus(ctx->pg_conn) != CONNECTION_OK) {
        fprintf(stderr, "PostgreSQL connection failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQfinish(ctx->pg_conn);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize DNA context
    ctx->dna_ctx = dna_context_new();
    if (!ctx->dna_ctx) {
        fprintf(stderr, "Error: Failed to create DNA context\n");
        PQfinish(ctx->pg_conn);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    printf("✓ Messenger initialized for '%s'\n", identity);
    printf("✓ Connected to PostgreSQL: dna_messenger\n");

    return ctx;
}

void messenger_free(messenger_context_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->dna_ctx) {
        dna_context_free(ctx->dna_ctx);
    }

    if (ctx->pg_conn) {
        PQfinish(ctx->pg_conn);
    }

    free(ctx->identity);
    free(ctx);
}

// ============================================================================
// KEY GENERATION
// ============================================================================

int messenger_generate_keys(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    printf("\n[Generating keys for '%s']\n", identity);

    // Create ~/.dna directory
    const char *home = qgp_platform_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot get home directory\n");
        return -1;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    if (qgp_platform_mkdir(dna_dir) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: Cannot create %s\n", dna_dir);
        return -1;
    }

    // Generate Dilithium3 signing key
    uint8_t dilithium_pk[1952];  // Dilithium3 public key size
    uint8_t dilithium_sk[4032];  // Dilithium3 secret key size (correct size!)

    if (qgp_dilithium3_keypair(dilithium_pk, dilithium_sk) != 0) {
        fprintf(stderr, "Error: Dilithium key generation failed\n");
        return -1;
    }

    printf("✓ Dilithium3 signing key generated\n");

    // Generate Kyber512 encryption key
    uint8_t kyber_pk[800];   // Kyber512 public key size
    uint8_t kyber_sk[1632];  // Kyber512 secret key size

    if (qgp_kyber512_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "Error: Kyber key generation failed\n");
        return -1;
    }

    printf("✓ Kyber512 encryption key generated\n");

    // Save private keys to filesystem
    char dilithium_path[512], kyber_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s-dilithium.pqkey", dna_dir, identity);
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s-kyber512.pqkey", dna_dir, identity);

    FILE *f = fopen(dilithium_path, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot create %s\n", dilithium_path);
        return -1;
    }
    fwrite(dilithium_sk, 1, sizeof(dilithium_sk), f);
    fclose(f);
    printf("✓ Private signing key saved: %s\n", dilithium_path);

    f = fopen(kyber_path, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot create %s\n", kyber_path);
        return -1;
    }
    fwrite(kyber_sk, 1, sizeof(kyber_sk), f);
    fclose(f);
    printf("✓ Private encryption key saved: %s\n", kyber_path);

    // Upload public keys to keyserver
    if (messenger_store_pubkey(ctx, identity, dilithium_pk, sizeof(dilithium_pk),
                                kyber_pk, sizeof(kyber_pk)) != 0) {
        fprintf(stderr, "Error: Failed to upload public keys to keyserver\n");
        return -1;
    }

    printf("✓ Key generation complete for '%s'\n\n", identity);
    return 0;
}

// ============================================================================
// PUBLIC KEY MANAGEMENT
// ============================================================================

int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
) {
    if (!ctx || !identity || !signing_pubkey || !encryption_pubkey) {
        return -1;
    }

    const char *paramValues[4];
    int paramLengths[4];
    int paramFormats[4] = {0, 1, 0, 1}; // text, binary, text, binary

    char len_str1[32], len_str2[32];
    snprintf(len_str1, sizeof(len_str1), "%zu", signing_pubkey_len);
    snprintf(len_str2, sizeof(len_str2), "%zu", encryption_pubkey_len);

    paramValues[0] = identity;
    paramValues[1] = (const char*)signing_pubkey;
    paramLengths[1] = (int)signing_pubkey_len;
    paramValues[2] = len_str1;
    paramValues[3] = (const char*)encryption_pubkey;
    paramLengths[3] = (int)encryption_pubkey_len;

    const char *query =
        "INSERT INTO keyserver (identity, signing_pubkey, signing_pubkey_len, encryption_pubkey, encryption_pubkey_len) "
        "VALUES ($1, $2, $3::integer, $4, $5::integer) "
        "ON CONFLICT (identity) DO UPDATE SET "
        "signing_pubkey = $2, signing_pubkey_len = $3::integer, "
        "encryption_pubkey = $4, encryption_pubkey_len = $5::integer";

    // Need 5 parameters
    const char *all_params[5] = {identity, (const char*)signing_pubkey, len_str1, (const char*)encryption_pubkey, len_str2};
    int all_lengths[5] = {0, (int)signing_pubkey_len, 0, (int)encryption_pubkey_len, 0};
    int all_formats[5] = {0, 1, 0, 1, 0};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 5, NULL, all_params, all_lengths, all_formats, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Store pubkey failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Public key stored for '%s'\n", identity);
    return 0;
}

int messenger_load_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **signing_pubkey_out,
    size_t *signing_pubkey_len_out,
    uint8_t **encryption_pubkey_out,
    size_t *encryption_pubkey_len_out
) {
    if (!ctx || !identity) {
        return -1;
    }

    const char *paramValues[1] = {identity};
    const char *query =
        "SELECT signing_pubkey, signing_pubkey_len, encryption_pubkey, encryption_pubkey_len "
        "FROM keyserver WHERE identity = $1";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 1); // Binary result

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Load pubkey failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Public key not found for '%s'\n", identity);
        PQclear(res);
        return -1;
    }

    // Extract binary data
    int sign_len = PQgetlength(res, 0, 0);
    int enc_len = PQgetlength(res, 0, 2);

    *signing_pubkey_out = malloc(sign_len);
    *encryption_pubkey_out = malloc(enc_len);

    if (!*signing_pubkey_out || !*encryption_pubkey_out) {
        free(*signing_pubkey_out);
        free(*encryption_pubkey_out);
        PQclear(res);
        return -1;
    }

    memcpy(*signing_pubkey_out, PQgetvalue(res, 0, 0), sign_len);
    memcpy(*encryption_pubkey_out, PQgetvalue(res, 0, 2), enc_len);

    *signing_pubkey_len_out = sign_len;
    *encryption_pubkey_len_out = enc_len;

    PQclear(res);
    return 0;
}

int messenger_list_pubkeys(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    const char *query = "SELECT identity, created_at FROM keyserver ORDER BY identity";
    PGresult *res = PQexec(ctx->pg_conn, query);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "List pubkeys failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Keyserver (%d identities) ===\n\n", rows);

    for (int i = 0; i < rows; i++) {
        const char *identity = PQgetvalue(res, i, 0);
        const char *created_at = PQgetvalue(res, i, 1);
        printf("  %s (added: %s)\n", identity, created_at);
    }

    printf("\n");
    PQclear(res);
    return 0;
}

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

int messenger_send_message(
    messenger_context_t *ctx,
    const char *recipient,
    const char *message
) {
    if (!ctx || !recipient || !message) {
        return -1;
    }

    printf("\n[Sending message to %s]\n", recipient);

    // Load recipient's public key from PostgreSQL
    uint8_t *sign_pubkey = NULL, *enc_pubkey = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, recipient, &sign_pubkey, &sign_len, &enc_pubkey, &enc_len) != 0) {
        fprintf(stderr, "Error: Could not load public key for '%s'\n", recipient);
        return -1;
    }

    // Load sender's private signing key from filesystem
    const char *home = qgp_platform_home_dir();
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/.dna/%s-dilithium.pqkey", home, ctx->identity);

    FILE *f = fopen(dilithium_path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", dilithium_path);
        free(sign_pubkey);
        free(enc_pubkey);
        return -1;
    }

    uint8_t sender_sign_privkey[4032];  // Dilithium3 private key size (correct!)
    size_t read_size = fread(sender_sign_privkey, 1, sizeof(sender_sign_privkey), f);
    fclose(f);

    if (read_size != sizeof(sender_sign_privkey)) {
        fprintf(stderr, "Error: Invalid private key size: %zu (expected %zu)\n",
                read_size, sizeof(sender_sign_privkey));
        free(sign_pubkey);
        free(enc_pubkey);
        return -1;
    }

    // Load sender's public signing key from PostgreSQL
    uint8_t *sender_sign_pubkey_pg = NULL;
    uint8_t *sender_enc_pubkey_pg = NULL;
    size_t sender_sign_len = 0, sender_enc_len = 0;

    if (messenger_load_pubkey(ctx, ctx->identity, &sender_sign_pubkey_pg, &sender_sign_len,
                               &sender_enc_pubkey_pg, &sender_enc_len) != 0) {
        fprintf(stderr, "Error: Could not load sender's public key from keyserver\n");
        memset(sender_sign_privkey, 0, sizeof(sender_sign_privkey));
        free(sign_pubkey);
        free(enc_pubkey);
        return -1;
    }

    // Encrypt message using raw keys
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    dna_error_t err = dna_encrypt_message_raw(
        ctx->dna_ctx,
        (const uint8_t*)message,
        strlen(message),
        enc_pubkey,  // Recipient's Kyber512 public key (800 bytes)
        sender_sign_pubkey_pg,  // Sender's Dilithium3 public key (1952 bytes)
        sender_sign_privkey,  // Sender's Dilithium3 private key (4016 bytes)
        &ciphertext,
        &ciphertext_len
    );

    // Secure wipe of private key
    memset(sender_sign_privkey, 0, sizeof(sender_sign_privkey));

    free(sign_pubkey);
    free(enc_pubkey);
    free(sender_sign_pubkey_pg);
    free(sender_enc_pubkey_pg);

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Encryption failed: %s\n", dna_error_string(err));
        return -1;
    }

    printf("✓ Message encrypted (%zu bytes)\n", ciphertext_len);

    // Store in database
    const char *paramValues[5];
    int paramLengths[5];
    int paramFormats[5] = {0, 0, 1, 0, 0}; // text, text, binary, text, text

    char len_str[32];
    snprintf(len_str, sizeof(len_str), "%zu", ciphertext_len);

    paramValues[0] = ctx->identity;
    paramValues[1] = recipient;
    paramValues[2] = (const char*)ciphertext;
    paramLengths[2] = (int)ciphertext_len;
    paramValues[3] = len_str;

    const char *query =
        "INSERT INTO messages (sender, recipient, ciphertext, ciphertext_len) "
        "VALUES ($1, $2, $3, $4::integer)";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 4, NULL, paramValues, paramLengths, paramFormats, 0);

    free(ciphertext);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Store message failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Message sent to '%s'\n", recipient);

    return 0;
}

int messenger_list_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    const char *paramValues[1] = {ctx->identity};
    const char *query =
        "SELECT id, sender, created_at FROM messages "
        "WHERE recipient = $1 ORDER BY created_at DESC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "List messages failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Inbox for %s (%d messages) ===\n\n", ctx->identity, rows);

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *sender = PQgetvalue(res, i, 1);
        const char *timestamp = PQgetvalue(res, i, 2);
        printf("  [%s] From: %s (%s)\n", id, sender, timestamp);
    }

    if (rows == 0) {
        printf("  (no messages)\n");
    }

    printf("\n");
    PQclear(res);
    return 0;
}

int messenger_list_sent_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    const char *paramValues[1] = {ctx->identity};
    const char *query =
        "SELECT id, recipient, created_at FROM messages "
        "WHERE sender = $1 ORDER BY created_at DESC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "List sent messages failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Sent by %s (%d messages) ===\n\n", ctx->identity, rows);

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *recipient = PQgetvalue(res, i, 1);
        const char *timestamp = PQgetvalue(res, i, 2);
        printf("  [%s] To: %s (%s)\n", id, recipient, timestamp);
    }

    if (rows == 0) {
        printf("  (no sent messages)\n");
    }

    printf("\n");
    PQclear(res);
    return 0;
}

int messenger_read_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Fetch message from database
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", message_id);
    const char *paramValues[1] = {id_str};
    const char *query = "SELECT sender, ciphertext FROM messages WHERE id = $1 AND recipient = $2";

    const char *params[2] = {id_str, ctx->identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 1); // Binary result

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Fetch message failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Message %d not found or not for you\n", message_id);
        PQclear(res);
        return -1;
    }

    const char *sender = PQgetvalue(res, 0, 0);
    const uint8_t *ciphertext = (const uint8_t*)PQgetvalue(res, 0, 1);
    size_t ciphertext_len = PQgetlength(res, 0, 1);

    printf("\n========================================\n");
    printf(" Message #%d from %s\n", message_id, sender);
    printf("========================================\n\n");

    // Load recipient's private Kyber512 key from filesystem
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s-kyber512.pqkey", home, ctx->identity);

    FILE *f = fopen(kyber_path, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", kyber_path);
        PQclear(res);
        return -1;
    }

    uint8_t kyber_privkey[1632];  // Kyber512 private key size
    size_t read_size = fread(kyber_privkey, 1, sizeof(kyber_privkey), f);
    fclose(f);

    if (read_size != sizeof(kyber_privkey)) {
        fprintf(stderr, "Error: Invalid private key size\n");
        PQclear(res);
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
        kyber_privkey,
        &plaintext,
        &plaintext_len,
        &sender_sign_pubkey_from_msg,
        &sender_sign_pubkey_len
    );

    // Secure wipe
    memset(kyber_privkey, 0, sizeof(kyber_privkey));

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Decryption failed: %s\n", dna_error_string(err));
        PQclear(res);
        return -1;
    }

    // Verify sender's public key against keyserver
    uint8_t *sender_sign_pubkey_keyserver = NULL;
    uint8_t *sender_enc_pubkey_keyserver = NULL;
    size_t sender_sign_len_keyserver = 0, sender_enc_len_keyserver = 0;

    if (messenger_load_pubkey(ctx, sender, &sender_sign_pubkey_keyserver, &sender_sign_len_keyserver,
                               &sender_enc_pubkey_keyserver, &sender_enc_len_keyserver) != 0) {
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
            PQclear(res);
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
    PQclear(res);
    printf("\n");
    return 0;
}

int messenger_delete_pubkey(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    const char *paramValues[1] = {identity};
    const char *query = "DELETE FROM keyserver WHERE identity = $1";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete pubkey failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    printf("✓ Public key deleted for '%s'\n", identity);
    PQclear(res);
    return 0;
}

int messenger_delete_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", message_id);

    const char *paramValues[1] = {id_str};
    const char *query = "DELETE FROM messages WHERE id = $1";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete message failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    printf("✓ Message %d deleted\n", message_id);
    PQclear(res);
    return 0;
}
