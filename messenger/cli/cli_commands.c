/*
 * DNA Messenger CLI - Command Implementation
 *
 * Interactive CLI tool for testing DNA Messenger without GUI.
 */

#include "cli_commands.h"
#include "bip39.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_types.h"
#include "dht/core/dht_keyserver.h"
#include "dht/shared/nodus_ops.h"
#include "dht/shared/nodus_init.h"
#include "dht/shared/dht_gek_storage.h"
#include "dht/shared/dht_groups.h"
#include "dht/shared/dht_contact_request.h"
#include "transport/internal/transport_core.h"
/* ICE/TURN removed in v0.4.61 for privacy */
#include "messenger.h"
#include "messenger/gek.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#define LOG_TAG "CLI"

/* v0.6.47: Thread-safe localtime wrapper (security fix) */
static inline struct tm *safe_localtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (localtime_s(result, timer) == 0) ? result : NULL;
#else
    return localtime_r(timer, result);
#endif
}

/* v0.6.47: Thread-safe gmtime wrapper (security fix) */
static inline struct tm *safe_gmtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (gmtime_s(result, timer) == 0) ? result : NULL;
#else
    return gmtime_r(timer, result);
#endif
}

/* ============================================================================
 * SYNCHRONIZATION HELPERS
 * ============================================================================ */

void cli_wait_init(cli_wait_t *wait) {
    pthread_mutex_init(&wait->mutex, NULL);
    pthread_cond_init(&wait->cond, NULL);
    wait->done = false;
    wait->result = 0;
    wait->fingerprints = NULL;
    wait->fingerprint_count = 0;
    wait->fingerprint[0] = '\0';
    wait->display_name[0] = '\0';
    wait->contacts = NULL;
    wait->contact_count = 0;
    wait->messages = NULL;
    wait->message_count = 0;
    wait->requests = NULL;
    wait->request_count = 0;
    wait->wallets = NULL;
    wait->wallet_count = 0;
    wait->balances = NULL;
    wait->balance_count = 0;
    wait->profile = NULL;
}

void cli_wait_destroy(cli_wait_t *wait) {
    pthread_mutex_destroy(&wait->mutex);
    pthread_cond_destroy(&wait->cond);
}

int cli_wait_for(cli_wait_t *wait) {
    pthread_mutex_lock(&wait->mutex);
    while (!wait->done) {
        pthread_cond_wait(&wait->cond, &wait->mutex);
    }
    int result = wait->result;
    pthread_mutex_unlock(&wait->mutex);
    return result;
}

static void cli_wait_signal(cli_wait_t *wait, int result) {
    pthread_mutex_lock(&wait->mutex);
    wait->result = result;
    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

/* ============================================================================
 * CALLBACKS
 * ============================================================================ */

static void on_completion(dna_request_id_t request_id, int error, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;
    cli_wait_signal(wait, error);
}

/* v0.3.0: on_identities_listed callback removed - single-user model */

static void on_display_name(dna_request_id_t request_id, int error,
                            const char *display_name, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;
    if (error == 0 && display_name) {
        strncpy(wait->display_name, display_name, sizeof(wait->display_name) - 1);
        wait->display_name[sizeof(wait->display_name) - 1] = '\0';
    }
    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    /* Free the strdup'd string from dna_handle_lookup_name */
    if (display_name) {
        free((void*)display_name);
    }
}

static void on_contacts_listed(dna_request_id_t request_id, int error,
                                dna_contact_t *contacts, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && contacts && count > 0) {
        wait->contacts = malloc(count * sizeof(dna_contact_t));
        if (wait->contacts) {
            wait->contact_count = count;
            memcpy(wait->contacts, contacts, count * sizeof(dna_contact_t));
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (contacts) {
        dna_free_contacts(contacts, count);
    }
}

static void on_messages_listed(dna_request_id_t request_id, int error,
                                dna_message_t *messages, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && messages && count > 0) {
        wait->messages = malloc(count * sizeof(dna_message_t));
        if (wait->messages) {
            wait->message_count = count;
            for (int i = 0; i < count; i++) {
                wait->messages[i] = messages[i];
                /* Deep copy plaintext */
                if (messages[i].plaintext) {
                    wait->messages[i].plaintext = strdup(messages[i].plaintext);
                }
            }
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (messages) {
        dna_free_messages(messages, count);
    }
}

static void on_requests_listed(dna_request_id_t request_id, int error,
                                dna_contact_request_t *requests, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && requests && count > 0) {
        wait->requests = malloc(count * sizeof(dna_contact_request_t));
        if (wait->requests) {
            wait->request_count = count;
            memcpy(wait->requests, requests, count * sizeof(dna_contact_request_t));
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (requests) {
        dna_free_contact_requests(requests, count);
    }
}

static void on_wallets_listed(dna_request_id_t request_id, int error,
                               dna_wallet_t *wallets, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && wallets && count > 0) {
        wait->wallets = malloc(count * sizeof(dna_wallet_t));
        if (wait->wallets) {
            wait->wallet_count = count;
            memcpy(wait->wallets, wallets, count * sizeof(dna_wallet_t));
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (wallets) {
        dna_free_wallets(wallets, count);
    }
}

static void on_balances_listed(dna_request_id_t request_id, int error,
                                dna_balance_t *balances, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && balances && count > 0) {
        wait->balances = malloc(count * sizeof(dna_balance_t));
        if (wait->balances) {
            wait->balance_count = count;
            memcpy(wait->balances, balances, count * sizeof(dna_balance_t));
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (balances) {
        dna_free_balances(balances, count);
    }
}

static void on_profile(dna_request_id_t request_id, int error,
                       dna_profile_t *profile, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && profile) {
        wait->profile = malloc(sizeof(dna_profile_t));
        if (wait->profile) {
            memcpy(wait->profile, profile, sizeof(dna_profile_t));
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (profile) {
        dna_free_profile(profile);
    }
}

/* ============================================================================
 * BASIC COMMANDS
 * ============================================================================ */

void cmd_help(void) {
    printf("\nDNA Messenger CLI - Interactive Mode\n\n");
    printf("Command Groups:\n");
    printf("  identity    Identity management (create, restore, load, profile, ...)\n");
    printf("  contact     Contact management (add, remove, request, block, ...)\n");
    printf("  message     Messaging (send, list, queue, backup, ...)\n");
    printf("  group       Group chat (create, invite, send, sync, ...)\n");
    printf("  channel     Channels (create, post, subscribe, ...)\n");
    printf("  wallet      Wallet operations (balance, send, transactions, ...)\n");
    printf("  dex         DEX trading (quote, pairs)\n");
    printf("  network     Network & presence (online, dht-status, ...)\n");
    printf("  version     Version management (publish, check)\n");
    printf("  sign        Signing (data, pubkey)\n");
    printf("  debug       Debug & logging (log-level, entries, export, ...)\n");
    printf("\n");
    printf("Type '<group>' to see subcommands (e.g., 'identity' or 'wallet').\n");
    printf("Type 'quit' to exit.\n\n");
}

int cmd_create(dna_engine_t *engine, const char *name) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!name || strlen(name) < 3 || strlen(name) > 20) {
        printf("Error: Name must be 3-20 characters\n");
        return -1;
    }

    for (size_t i = 0; i < strlen(name); i++) {
        if (!isalnum((unsigned char)name[i]) && name[i] != '_') {
            printf("Error: Name can only contain letters, numbers, and underscores\n");
            return -1;
        }
    }

    printf("Generating BIP39 mnemonic (24 words)...\n");

    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
    if (bip39_generate_mnemonic(BIP39_WORDS_24, mnemonic, sizeof(mnemonic)) != 0) {
        printf("Error: Failed to generate mnemonic\n");
        return -1;
    }

    printf("\n*** IMPORTANT: Save this mnemonic phrase! ***\n");
    printf("This is the ONLY way to recover your identity.\n\n");
    qgp_display_mnemonic(mnemonic);
    printf("\n");

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];
    uint8_t master_seed[64];

    if (qgp_derive_seeds_with_master(mnemonic, "", signing_seed, encryption_seed,
                                      master_seed) != 0) {
        printf("Error: Failed to derive seeds from mnemonic\n");
        return -1;
    }

    // Start DHT early (same as Flutter)
    printf("Connecting to DHT network...\n");
    dna_engine_prepare_dht_from_mnemonic(engine, mnemonic);

    printf("Creating identity '%s'...\n", name);

    char fingerprint[129];
    int result = dna_engine_create_identity_sync(
        engine, name, signing_seed, encryption_seed,
        master_seed, mnemonic, fingerprint
    );

    qgp_secure_memzero(signing_seed, sizeof(signing_seed));
    qgp_secure_memzero(encryption_seed, sizeof(encryption_seed));
    qgp_secure_memzero(master_seed, sizeof(master_seed));
    qgp_secure_memzero(mnemonic, sizeof(mnemonic));

    if (result != 0) {
        printf("Error: Failed to create identity: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("\n✓ Identity created successfully!\n");
    printf("  Fingerprint: %s\n", fingerprint);
    printf("✓ Wallets created\n");
    printf("✓ Name '%s' registered on keyserver\n", name);
    return 0;
}

/* v0.3.0: cmd_list simplified - single-user model */
int cmd_list(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (dna_engine_has_identity(engine)) {
        const char *current_fp = dna_engine_get_fingerprint(engine);
        if (current_fp) {
            printf("\nIdentity: %.16s... (loaded)\n\n", current_fp);
        } else {
            printf("\nIdentity exists. Use 'load' to load it.\n\n");
        }
    } else {
        printf("No identity found. Use 'create <name>' to create one.\n");
    }

    return 0;
}

int cmd_load(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    /* v0.3.0: fingerprint is optional - computed internally from flat key file */
    if (fingerprint && strlen(fingerprint) > 0) {
        printf("Loading identity %s...\n", fingerprint);
    } else {
        printf("Loading identity...\n");
        fingerprint = "";  /* Pass empty string to trigger auto-compute */
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_load_identity(engine, fingerprint, NULL, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to load identity: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Identity loaded successfully!\n");
    cmd_whoami(engine);
    return 0;
}

int cmd_send(dna_engine_t *engine, const char *recipient, const char *message) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *my_fp = dna_engine_get_fingerprint(engine);
    if (!my_fp) {
        printf("Error: No identity loaded. Use 'load <fingerprint>' first.\n");
        return -1;
    }

    if (!recipient || strlen(recipient) == 0) {
        printf("Error: Recipient fingerprint required\n");
        return -1;
    }

    if (!message || strlen(message) == 0) {
        printf("Error: Message cannot be empty\n");
        return -1;
    }

    printf("Sending message to %.16s...\n", recipient);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_send_message(engine, recipient, message, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to send message: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Message sent successfully!\n");

    // Wait for DHT PUT to complete (offline queue uses async DHT operations)
    printf("Waiting for DHT propagation...\n");
    struct timespec ts = {.tv_sec = 3, .tv_nsec = 0};
    nanosleep(&ts, NULL);

    return 0;
}

void cmd_whoami(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (fp) {
        printf("Current identity: %s\n", fp);
    } else {
        printf("No identity loaded. Use 'load <fingerprint>' or 'create <name>'.\n");
    }
}

void cmd_change_password(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded. Use 'load <fingerprint>' first.\n");
        return;
    }

    /* Prompt for old password */
    char old_password[256] = {0};
    printf("Enter current password (or press Enter if none): ");
    fflush(stdout);
    if (fgets(old_password, sizeof(old_password), stdin)) {
        /* Remove trailing newline */
        size_t len = strlen(old_password);
        if (len > 0 && old_password[len - 1] == '\n') {
            old_password[len - 1] = '\0';
        }
    }

    /* Prompt for new password */
    char new_password[256] = {0};
    printf("Enter new password (or press Enter to remove password): ");
    fflush(stdout);
    if (fgets(new_password, sizeof(new_password), stdin)) {
        /* Remove trailing newline */
        size_t len = strlen(new_password);
        if (len > 0 && new_password[len - 1] == '\n') {
            new_password[len - 1] = '\0';
        }
    }

    /* Confirm new password if setting one */
    if (strlen(new_password) > 0) {
        char confirm_password[256] = {0};
        printf("Confirm new password: ");
        fflush(stdout);
        if (fgets(confirm_password, sizeof(confirm_password), stdin)) {
            size_t len = strlen(confirm_password);
            if (len > 0 && confirm_password[len - 1] == '\n') {
                confirm_password[len - 1] = '\0';
            }
        }

        if (strcmp(new_password, confirm_password) != 0) {
            printf("Error: Passwords do not match\n");
            qgp_secure_memzero(old_password, sizeof(old_password));
            qgp_secure_memzero(new_password, sizeof(new_password));
            qgp_secure_memzero(confirm_password, sizeof(confirm_password));
            return;
        }
        qgp_secure_memzero(confirm_password, sizeof(confirm_password));
    }

    /* Change password */
    const char *old_pwd = (strlen(old_password) > 0) ? old_password : NULL;
    const char *new_pwd = (strlen(new_password) > 0) ? new_password : NULL;

    int result = dna_engine_change_password_sync(engine, old_pwd, new_pwd);

    /* Clear passwords from memory */
    qgp_secure_memzero(old_password, sizeof(old_password));
    qgp_secure_memzero(new_password, sizeof(new_password));

    if (result == 0) {
        if (new_pwd) {
            printf("Password changed successfully.\n");
        } else {
            printf("Password removed successfully.\n");
        }
    } else if (result == DNA_ENGINE_ERROR_WRONG_PASSWORD) {
        printf("Error: Current password is incorrect\n");
    } else {
        printf("Error: Failed to change password (code: %d)\n", result);
    }
}

/* ============================================================================
 * IDENTITY COMMANDS (new)
 * ============================================================================ */

int cmd_restore(dna_engine_t *engine, const char *mnemonic) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!mnemonic || strlen(mnemonic) == 0) {
        printf("Error: Mnemonic required\n");
        return -1;
    }

    if (!bip39_validate_mnemonic(mnemonic)) {
        printf("Error: Invalid mnemonic phrase\n");
        return -1;
    }

    printf("Restoring identity from mnemonic...\n");

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];
    uint8_t master_seed[64];

    if (qgp_derive_seeds_with_master(mnemonic, "", signing_seed, encryption_seed,
                                      master_seed) != 0) {
        printf("Error: Failed to derive seeds from mnemonic\n");
        return -1;
    }

    char fingerprint[129];
    int result = dna_engine_restore_identity_sync(
        engine, signing_seed, encryption_seed,
        master_seed, mnemonic, fingerprint
    );

    qgp_secure_memzero(signing_seed, sizeof(signing_seed));
    qgp_secure_memzero(encryption_seed, sizeof(encryption_seed));
    qgp_secure_memzero(master_seed, sizeof(master_seed));

    if (result != 0) {
        printf("Error: Failed to restore identity: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Identity restored successfully!\n");
    printf("Fingerprint: %s\n", fingerprint);
    return 0;
}

int cmd_delete(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Deleting identity %.16s...\n", fingerprint);

    int result = dna_engine_delete_identity_sync(engine, fingerprint);

    if (result != 0) {
        printf("Error: Failed to delete identity: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Identity deleted successfully!\n");
    return 0;
}

int cmd_register(dna_engine_t *engine, const char *name) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!name || strlen(name) < 3 || strlen(name) > 20) {
        printf("Error: Name must be 3-20 characters\n");
        return -1;
    }

    printf("Registering name '%s' on DHT...\n", name);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_register_name(engine, name, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to register name: %s\n", dna_engine_error_string(result));
        return result;
    }

    /* Wait for DHT put to propagate (async operation) */
    printf("Waiting for DHT propagation...\n");
    struct timespec ts = {3, 0};  /* 3 seconds */
    nanosleep(&ts, NULL);

    printf("Name '%s' registered successfully!\n", name);
    return 0;
}

int cmd_lookup(dna_engine_t *engine, const char *name) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!name || strlen(name) == 0) {
        printf("Error: Name required\n");
        return -1;
    }

    printf("Looking up name '%s'...\n", name);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_lookup_name(engine, name, on_display_name, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Lookup failed: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (strlen(wait.display_name) > 0) {
        printf("Name '%s' is TAKEN by: %s\n", name, wait.display_name);
    } else {
        printf("Name '%s' is AVAILABLE\n", name);
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_name(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_registered_name(engine, on_display_name, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get name: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (strlen(wait.display_name) > 0) {
        printf("Registered name: %s\n", wait.display_name);
    } else {
        printf("No name registered. Use 'register <name>' to register one.\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_profile(dna_engine_t *engine, const char *field, const char *value) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    /* If updating profile */
    if (field && value) {
        /* First get current profile */
        dna_engine_get_profile(engine, on_profile, &wait);
        int result = cli_wait_for(&wait);

        if (result != 0 || !wait.profile) {
            printf("Error: Failed to get profile\n");
            cli_wait_destroy(&wait);
            return -1;
        }

        /* Update field */
        dna_profile_t *profile = wait.profile;
        if (strcmp(field, "bio") == 0) {
            strncpy(profile->bio, value, sizeof(profile->bio) - 1);
        } else if (strcmp(field, "location") == 0) {
            strncpy(profile->location, value, sizeof(profile->location) - 1);
        } else if (strcmp(field, "website") == 0) {
            strncpy(profile->website, value, sizeof(profile->website) - 1);
        } else if (strcmp(field, "telegram") == 0) {
            strncpy(profile->telegram, value, sizeof(profile->telegram) - 1);
        } else if (strcmp(field, "twitter") == 0) {
            strncpy(profile->twitter, value, sizeof(profile->twitter) - 1);
        } else if (strcmp(field, "github") == 0) {
            strncpy(profile->github, value, sizeof(profile->github) - 1);
        } else {
            printf("Unknown field: %s\n", field);
            printf("Valid fields: bio, location, website, telegram, twitter, github\n");
            free(wait.profile);
            cli_wait_destroy(&wait);
            return -1;
        }

        /* Reset wait and update */
        wait.done = false;
        dna_engine_update_profile(engine, profile, on_completion, &wait);
        result = cli_wait_for(&wait);
        free(wait.profile);
        cli_wait_destroy(&wait);

        if (result != 0) {
            printf("Error: Failed to update profile: %s\n", dna_engine_error_string(result));
            return result;
        }

        printf("Profile updated: %s = %s\n", field, value);
        return 0;
    }

    /* Show profile */
    dna_engine_get_profile(engine, on_profile, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get profile: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.profile) {
        printf("\nProfile:\n");
        /* NOTE: display_name removed in v0.6.24 - name comes from registered_name */
        if (strlen(wait.profile->bio) > 0)
            printf("  Bio:      %s\n", wait.profile->bio);
        if (strlen(wait.profile->location) > 0)
            printf("  Location: %s\n", wait.profile->location);
        if (strlen(wait.profile->website) > 0)
            printf("  Website:  %s\n", wait.profile->website);
        if (strlen(wait.profile->telegram) > 0)
            printf("  Telegram: %s\n", wait.profile->telegram);
        if (strlen(wait.profile->twitter) > 0)
            printf("  Twitter:  %s\n", wait.profile->twitter);
        if (strlen(wait.profile->github) > 0)
            printf("  GitHub:   %s\n", wait.profile->github);
        if (strlen(wait.profile->backbone) > 0)
            printf("  Backbone: %s\n", wait.profile->backbone);
        if (strlen(wait.profile->eth) > 0)
            printf("  ETH:      %s\n", wait.profile->eth);
        printf("\n");
        free(wait.profile);
    } else {
        printf("No profile data.\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_lookup_profile(dna_engine_t *engine, const char *identifier) {
    (void)engine;  /* Not needed - uses DHT singleton directly */

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Name or fingerprint required\n");
        return -1;
    }

    if (!nodus_ops_is_ready()) {
        printf("Error: DHT not initialized\n");
        return -1;
    }

    printf("Looking up profile for '%s'...\n", identifier);

    /* Lookup identity from DHT (handles both name and fingerprint) */
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(identifier, &identity);

    if (ret == -2) {
        printf("Error: Identity not found in DHT\n");
        return -1;
    }

    if (ret != 0 || !identity) {
        printf("Error: Failed to lookup identity (error %d)\n", ret);
        return -1;
    }

    /* Print profile info */
    printf("\n========================================\n");

    /* Compute fingerprint from pubkey */
    char fingerprint[129];
    dna_compute_fingerprint(identity->dilithium_pubkey, fingerprint);
    printf("Fingerprint: %s\n", fingerprint);

    printf("Name: %s\n", identity->has_registered_name ? identity->registered_name : "(none)");
    printf("Registered: %lu\n", (unsigned long)identity->name_registered_at);
    printf("Expires: %lu\n", (unsigned long)identity->name_expires_at);
    printf("Version: %u\n", identity->version);
    printf("Timestamp: %lu\n", (unsigned long)identity->timestamp);

    printf("\n--- Wallet Addresses ---\n");
    if (identity->wallets.backbone[0])
        printf("Backbone: %s\n", identity->wallets.backbone);
    if (identity->wallets.eth[0])
        printf("Ethereum: %s\n", identity->wallets.eth);
    if (identity->wallets.sol[0])
        printf("Solana: %s\n", identity->wallets.sol);

    printf("\n--- Social Links ---\n");
    if (identity->socials.x[0])
        printf("X: %s\n", identity->socials.x);
    if (identity->socials.telegram[0])
        printf("Telegram: %s\n", identity->socials.telegram);
    if (identity->socials.github[0])
        printf("GitHub: %s\n", identity->socials.github);

    printf("\n--- Profile ---\n");
    if (identity->bio[0])
        printf("Bio: %s\n", identity->bio);
    else
        printf("(no bio)\n");

    printf("\n--- Avatar ---\n");
    if (identity->avatar_base64[0] != '\0') {
        size_t avatar_len = strlen(identity->avatar_base64);
        printf("Avatar: %zu bytes (base64)\n", avatar_len);
    } else {
        printf("(no avatar)\n");
    }

    printf("========================================\n\n");

    dna_identity_free(identity);
    return 0;
}

/* ============================================================================
 * CONTACT COMMANDS
 * ============================================================================ */

int cmd_contacts(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    /* Refresh presence before listing contacts */
    cli_wait_t pw;
    cli_wait_init(&pw);
    dna_engine_refresh_presence(engine, on_completion, &pw);
    cli_wait_for(&pw);
    cli_wait_destroy(&pw);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_contacts(engine, on_contacts_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get contacts: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.contact_count == 0) {
        printf("No contacts. Use 'add-contact <name|fingerprint>' to add one.\n");
    } else {
        printf("\nContacts (%d):\n", wait.contact_count);
        for (int i = 0; i < wait.contact_count; i++) {
            printf("  %d. %s\n", i + 1, wait.contacts[i].display_name);
            printf("     Fingerprint: %.32s...\n", wait.contacts[i].fingerprint);
            if (wait.contacts[i].is_online) {
                printf("     Status: ONLINE\n");
            } else if (wait.contacts[i].last_seen > 0) {
                time_t ls = (time_t)wait.contacts[i].last_seen;
                struct tm *tm = localtime(&ls);
                char tbuf[64];
                strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
                time_t ago = time(NULL) - ls;
                if (ago < 60)
                    printf("     Last seen: %s (%llds ago)\n", tbuf, (long long)ago);
                else if (ago < 3600)
                    printf("     Last seen: %s (%lldm ago)\n", tbuf, (long long)(ago / 60));
                else if (ago < 86400)
                    printf("     Last seen: %s (%lldh ago)\n", tbuf, (long long)(ago / 3600));
                else
                    printf("     Last seen: %s (%lldd ago)\n", tbuf, (long long)(ago / 86400));
            } else {
                printf("     Status: offline\n");
            }
        }
        free(wait.contacts);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_request(dna_engine_t *engine, const char *identifier, const char *message);

int cmd_add_contact(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Name or fingerprint required\n");
        return -1;
    }

    printf("Adding contact '%s'...\n", identifier);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_add_contact(engine, identifier, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to add contact: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Contact added successfully!\n");

    /* Also send a contact request so the other side knows about us */
    printf("Sending contact request...\n");
    cmd_request(engine, identifier, NULL);

    return 0;
}

int cmd_remove_contact(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Removing contact %.16s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_remove_contact(engine, fingerprint, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to remove contact: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Contact removed successfully!\n");
    return 0;
}

int cmd_request(dna_engine_t *engine, const char *identifier, const char *message) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Name or fingerprint required\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    size_t id_len = strlen(identifier);

    if (id_len == 128) {
        /* Already a fingerprint */
        strncpy(resolved_fp, identifier, 128);
    } else {
        /* Assume it's a name - resolve via DHT lookup */
        printf("Resolving name '%s'...\n", identifier);

        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
        printf("Resolved to: %.16s...\n", resolved_fp);
    }

    printf("Sending contact request to %.16s...\n", resolved_fp);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_send_contact_request(engine, resolved_fp, message, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to send request: %s\n", dna_engine_error_string(result));
        return result;
    }

    /* Wait for DHT put to propagate (async operation) */
    printf("Waiting for DHT propagation...\n");
    struct timespec ts = {2, 0};  /* 2 seconds */
    nanosleep(&ts, NULL);

    printf("Contact request sent successfully!\n");
    return 0;
}

int cmd_requests(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_contact_requests(engine, on_requests_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get requests: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.request_count == 0) {
        printf("No pending contact requests.\n");
    } else {
        printf("\nPending contact requests (%d):\n", wait.request_count);
        for (int i = 0; i < wait.request_count; i++) {
            printf("  %d. %s\n", i + 1, wait.requests[i].display_name);
            printf("     Fingerprint: %.32s...\n", wait.requests[i].fingerprint);
            if (strlen(wait.requests[i].message) > 0) {
                printf("     Message: %s\n", wait.requests[i].message);
            }
        }
        free(wait.requests);
        printf("\nUse 'approve <fingerprint>' to accept a request.\n\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_check_inbox(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    if (strlen(identifier) == 128) {
        strncpy(resolved_fp, identifier, 128);
    } else {
        printf("Resolving name '%s'...\n", identifier);
        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);
        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lr = cli_wait_for(&lookup_wait);
        if (lr != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }
        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
        printf("Resolved to: %.16s...\n", resolved_fp);
    }

    /* Directly call dht_fetch_contact_requests with this fingerprint */
    printf("Checking inbox for %.16s...\n", resolved_fp);
    dht_contact_request_t *requests = NULL;
    size_t count = 0;
    int rc = dht_fetch_contact_requests(resolved_fp, &requests, &count);
    printf("dht_fetch_contact_requests: rc=%d count=%zu\n", rc, count);

    for (size_t i = 0; i < count; i++) {
        printf("  [%zu] from: %.32s... name='%s' msg='%s'\n",
               i, requests[i].sender_fingerprint,
               requests[i].sender_name, requests[i].message);
    }

    if (requests) free(requests);
    return 0;
}

int cmd_approve(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Approving contact request from %.16s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_approve_contact_request(engine, fingerprint, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to approve request: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Contact request approved! They are now a contact.\n");
    return 0;
}

/* ============================================================================
 * MESSAGING COMMANDS
 * ============================================================================ */

int cmd_messages(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Contact name or fingerprint required\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    size_t id_len = strlen(identifier);

    if (id_len == 128) {
        /* Already a fingerprint */
        strncpy(resolved_fp, identifier, 128);
    } else {
        /* Assume it's a name - resolve via DHT lookup */
        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_conversation(engine, resolved_fp, on_messages_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get messages: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.message_count == 0) {
        printf("No messages with this contact.\n");
    } else {
        printf("\nConversation with %.16s... (%d messages):\n\n", resolved_fp, wait.message_count);
        for (int i = 0; i < wait.message_count; i++) {
            time_t ts = (time_t)wait.messages[i].timestamp;
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
            } else {
                strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
            }

            const char *direction = wait.messages[i].is_outgoing ? ">>>" : "<<<";
            printf("[%s] %s %s\n", time_str, direction,
                   wait.messages[i].plaintext ? wait.messages[i].plaintext : "(empty)");

            if (wait.messages[i].plaintext) {
                free(wait.messages[i].plaintext);
            }
        }
        free(wait.messages);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_check_offline(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    printf("Checking for offline messages...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_check_offline_messages(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to check offline messages: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Offline message check complete.\n");
    return 0;
}

/* Keep CLI alive while listening */
static volatile bool g_listening = true;

static void listen_signal_handler(int sig) {
    (void)sig;
    g_listening = false;
    printf("\nStopping listener...\n");
}

int cmd_listen(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    printf("Subscribing to contacts' outboxes for push notifications...\n");

    /* Start listeners for all contacts */
    int count = dna_engine_listen_all_contacts(engine);
    if (count < 0) {
        printf("Error: Failed to start listeners\n");
        return -1;
    }

    printf("Listening to %d contact(s). Press Ctrl+C to stop.\n", count);
    printf("Incoming messages will be displayed in real-time.\n\n");

    /* Set up signal handler */
    g_listening = true;
    signal(SIGINT, listen_signal_handler);
    signal(SIGTERM, listen_signal_handler);

    /* Keep running until interrupted */
    while (g_listening) {
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&ts, NULL);
    }

    /* Cancel all listeners */
    dna_engine_cancel_all_outbox_listeners(engine);
    printf("Listeners cancelled.\n");

    return 0;
}

/* ============================================================================
 * WALLET COMMANDS
 * ============================================================================ */

int cmd_wallets(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_list_wallets(engine, on_wallets_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to list wallets: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.wallet_count == 0) {
        printf("No wallets found.\n");
    } else {
        printf("\nWallets (%d):\n", wait.wallet_count);
        for (int i = 0; i < wait.wallet_count; i++) {
            printf("  %d. %s\n", i, wait.wallets[i].name);
            printf("     Address: %s\n", wait.wallets[i].address);
        }
        free(wait.wallets);
        printf("\nUse 'balance <index>' to see balances.\n\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_balance(dna_engine_t *engine, int wallet_index) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (wallet_index < 0) {
        printf("Error: Invalid wallet index\n");
        return -1;
    }

    printf("Getting balances for wallet %d...\n", wallet_index);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_balances(engine, wallet_index, on_balances_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get balances: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.balance_count == 0) {
        printf("No balances found.\n");
    } else {
        printf("\nBalances:\n");
        for (int i = 0; i < wait.balance_count; i++) {
            printf("  %s %s (%s)\n",
                   wait.balances[i].balance,
                   wait.balances[i].token,
                   wait.balances[i].network);
        }
        free(wait.balances);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

/* ============================================================================
 * PRESENCE COMMANDS
 * ============================================================================ */

int cmd_online(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    bool online = dna_engine_is_peer_online(engine, fingerprint);
    printf("Peer %.16s... is %s\n", fingerprint, online ? "ONLINE" : "OFFLINE");

    return 0;
}

/* ============================================================================
 * VERSION COMMANDS
 * ============================================================================ */

int cmd_publish_version(dna_engine_t *engine,
                        const char *lib_ver, const char *lib_min,
                        const char *app_ver, const char *app_min,
                        const char *nodus_ver, const char *nodus_min) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded. Use 'load' first.\n");
        return -1;
    }

    if (!lib_ver || !app_ver || !nodus_ver) {
        printf("Error: All version parameters required\n");
        return -1;
    }

    printf("Publishing version info to DHT...\n");
    printf("  Library: %s (min: %s)\n", lib_ver, lib_min ? lib_min : lib_ver);
    printf("  App:     %s (min: %s)\n", app_ver, app_min ? app_min : app_ver);
    printf("  Nodus:   %s (min: %s)\n", nodus_ver, nodus_min ? nodus_min : nodus_ver);
    printf("  Publisher: %.16s...\n", fp);

    int result = dna_engine_publish_version(
        engine,
        lib_ver, lib_min,
        app_ver, app_min,
        nodus_ver, nodus_min
    );

    if (result != 0) {
        printf("Error: Failed to publish version: %s\n", dna_engine_error_string(result));
        return result;
    }

    /* Wait for DHT propagation */
    printf("Waiting for DHT propagation...\n");
    struct timespec ts = {.tv_sec = 3, .tv_nsec = 0};
    nanosleep(&ts, NULL);

    printf("✓ Version info published successfully!\n");
    return 0;
}

int cmd_check_version(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Checking version info from DHT...\n");

    dna_version_check_result_t result;
    int check_result = dna_engine_check_version_dht(engine, &result);

    if (check_result == -2) {
        printf("No version info found in DHT.\n");
        printf("Use 'publish-version' to publish version info.\n");
        return 0;
    }

    if (check_result != 0) {
        printf("Error: Failed to check version: %s\n", dna_engine_error_string(check_result));
        return check_result;
    }

    /* Get local library version for comparison */
    const char *local_lib = dna_engine_get_version();

    printf("\nVersion Info from DHT:\n");
    printf("  Library: %s (min: %s)", result.info.library_current, result.info.library_minimum);
    if (result.library_update_available) {
        printf(" [UPDATE AVAILABLE - local: %s]", local_lib);
    } else {
        printf(" [local: %s]", local_lib);
    }
    printf("\n");

    printf("  App:     %s (min: %s)", result.info.app_current, result.info.app_minimum);
    if (result.app_update_available) {
        printf(" [UPDATE AVAILABLE]");
    }
    printf("\n");

    printf("  Nodus:   %s (min: %s)", result.info.nodus_current, result.info.nodus_minimum);
    if (result.nodus_update_available) {
        printf(" [UPDATE AVAILABLE]");
    }
    printf("\n");

    if (result.info.published_at > 0) {
        time_t ts = (time_t)result.info.published_at;
        char time_str[32];
        struct tm tm_buf;
        if (safe_gmtime(&ts, &tm_buf)) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M UTC", &tm_buf);
        } else {
            strncpy(time_str, "0000-00-00 00:00 UTC", sizeof(time_str));
        }
        printf("  Published: %s\n", time_str);
    }

    if (strlen(result.info.publisher) > 0) {
        printf("  Publisher: %.16s...\n", result.info.publisher);
    }

    return 0;
}

/* ============================================================================
 * DHT DEBUG COMMANDS
 * ============================================================================ */

#include "dht/core/dht_bootstrap_registry.h"

int cmd_bootstrap_registry(dna_engine_t *engine) {
    (void)engine;  /* Not needed, uses singleton */

    printf("Fetching bootstrap registry from DHT...\n\n");

    if (!nodus_messenger_is_initialized()) {
        printf("Error: DHT not initialized\n");
        return -1;
    }

    /* Wait for DHT to be ready */
    if (!nodus_messenger_is_ready()) {
        printf("Waiting for DHT connection...\n");
        if (!nodus_messenger_wait_for_ready(5000)) {
            printf("Error: DHT not connected\n");
            return -1;
        }
    }

    bootstrap_registry_t registry;
    memset(&registry, 0, sizeof(registry));

    int ret = dht_bootstrap_registry_fetch(&registry);

    if (ret != 0) {
        printf("Error: Failed to fetch bootstrap registry (error: %d)\n", ret);
        printf("\nPossible causes:\n");
        printf("  - Bootstrap nodes not registered in DHT\n");
        printf("  - DHT network connectivity issue\n");
        printf("  - Registry key mismatch\n");
        return ret;
    }

    if (registry.node_count == 0) {
        printf("Registry is empty (no nodes registered)\n");
        return 0;
    }

    printf("Found %zu bootstrap nodes:\n\n", registry.node_count);
    printf("%-18s %-6s %-10s %-12s %-12s %s\n",
           "IP", "PORT", "VERSION", "UPTIME", "LAST_SEEN", "NODE_ID");
    printf("%-18s %-6s %-10s %-12s %-12s %s\n",
           "------------------", "------", "----------", "------------", "------------", "--------------------");

    time_t now = time(NULL);

    for (size_t i = 0; i < registry.node_count; i++) {
        bootstrap_node_entry_t *node = &registry.nodes[i];

        /* Calculate time since last seen */
        int64_t age_sec = (int64_t)(now - node->last_seen);
        char age_str[32];
        if (age_sec < 0) {
            snprintf(age_str, sizeof(age_str), "future?");
        } else if (age_sec < 60) {
            snprintf(age_str, sizeof(age_str), "%llds ago", (long long)age_sec);
        } else if (age_sec < 3600) {
            snprintf(age_str, sizeof(age_str), "%lldm ago", (long long)(age_sec / 60));
        } else if (age_sec < 86400) {
            snprintf(age_str, sizeof(age_str), "%lldh ago", (long long)(age_sec / 3600));
        } else {
            snprintf(age_str, sizeof(age_str), "%lldd ago", (long long)(age_sec / 86400));
        }

        /* Format uptime */
        char uptime_str[32];
        if (node->uptime < 60) {
            snprintf(uptime_str, sizeof(uptime_str), "%llus", (unsigned long long)node->uptime);
        } else if (node->uptime < 3600) {
            snprintf(uptime_str, sizeof(uptime_str), "%llum", (unsigned long long)(node->uptime / 60));
        } else if (node->uptime < 86400) {
            snprintf(uptime_str, sizeof(uptime_str), "%lluh", (unsigned long long)(node->uptime / 3600));
        } else {
            snprintf(uptime_str, sizeof(uptime_str), "%llud", (unsigned long long)(node->uptime / 86400));
        }

        /* Status indicator */
        const char *status = (age_sec < DHT_BOOTSTRAP_STALE_TIMEOUT) ? "✓" : "✗";

        printf("%s %-17s %-6d %-10s %-12s %-12s %s\n",
               status,
               node->ip,
               node->port,
               node->version,
               uptime_str,
               age_str,
               node->node_id);
    }

    /* Filter and show active count */
    dht_bootstrap_registry_filter_active(&registry);
    printf("\nActive nodes (< %d min old): %zu\n",
           DHT_BOOTSTRAP_STALE_TIMEOUT / 60, registry.node_count);

    return 0;
}

/* ============================================================================
 * GROUP COMMANDS (GEK System)
 * ============================================================================ */

/* Callback storage for group operations */
typedef struct {
    cli_wait_t wait;
    dna_group_t *groups;
    int group_count;
    char group_uuid[37];
} cli_group_wait_t;

static void on_groups_list(dna_request_id_t request_id, int error,
                           dna_group_t *groups, int count, void *user_data) {
    (void)request_id;
    cli_group_wait_t *ctx = (cli_group_wait_t *)user_data;

    pthread_mutex_lock(&ctx->wait.mutex);
    ctx->wait.result = error;
    if (error == 0 && groups && count > 0) {
        ctx->groups = malloc(sizeof(dna_group_t) * count);
        if (ctx->groups) {
            memcpy(ctx->groups, groups, sizeof(dna_group_t) * count);
            ctx->group_count = count;
        }
        free(groups);  /* Free original from engine */
    }
    ctx->wait.done = true;
    pthread_cond_signal(&ctx->wait.cond);
    pthread_mutex_unlock(&ctx->wait.mutex);
}

static void on_group_created(dna_request_id_t request_id, int error,
                             const char *group_uuid, void *user_data) {
    (void)request_id;
    cli_group_wait_t *ctx = (cli_group_wait_t *)user_data;

    pthread_mutex_lock(&ctx->wait.mutex);
    ctx->wait.result = error;
    if (error == 0 && group_uuid) {
        strncpy(ctx->group_uuid, group_uuid, sizeof(ctx->group_uuid) - 1);
        ctx->group_uuid[sizeof(ctx->group_uuid) - 1] = '\0';
    }
    ctx->wait.done = true;
    pthread_cond_signal(&ctx->wait.cond);
    pthread_mutex_unlock(&ctx->wait.mutex);
}

static void on_group_message_sent(dna_request_id_t request_id, int error, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;
    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

/**
 * Check if string looks like a UUID (36 chars with dashes)
 */
static bool is_uuid_format(const char *str) {
    if (!str || strlen(str) != 36) return false;
    /* Check format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx */
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (str[i] != '-') return false;
        } else {
            if (!isxdigit((unsigned char)str[i])) return false;
        }
    }
    return true;
}

/**
 * Resolve group name or UUID to UUID
 * If input is already a UUID, returns it. Otherwise searches by name.
 * Returns 0 on success with uuid_out filled, -1 on error.
 */
static int resolve_group_identifier(dna_engine_t *engine, const char *name_or_uuid, char *uuid_out) {
    if (!engine || !name_or_uuid || !uuid_out) return -1;

    /* If already a UUID, just copy it */
    if (is_uuid_format(name_or_uuid)) {
        strncpy(uuid_out, name_or_uuid, 36);
        uuid_out[36] = '\0';
        return 0;
    }

    /* Otherwise, look up by name */
    cli_group_wait_t ctx = {0};
    cli_wait_init(&ctx.wait);
    ctx.groups = NULL;
    ctx.group_count = 0;

    dna_request_id_t req_id = dna_engine_get_groups(engine, on_groups_list, &ctx);
    if (req_id == 0) {
        cli_wait_destroy(&ctx.wait);
        return -1;
    }

    int result = cli_wait_for(&ctx.wait);
    cli_wait_destroy(&ctx.wait);

    if (result != 0 || !ctx.groups) {
        if (ctx.groups) free(ctx.groups);
        return -1;
    }

    /* Search by name (case-insensitive) */
    int found = -1;
    for (int i = 0; i < ctx.group_count; i++) {
        if (strcasecmp(ctx.groups[i].name, name_or_uuid) == 0) {
            strncpy(uuid_out, ctx.groups[i].uuid, 36);
            uuid_out[36] = '\0';
            found = 0;
            break;
        }
    }

    free(ctx.groups);
    return found;
}

int cmd_group_list(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    cli_group_wait_t ctx = {0};
    cli_wait_init(&ctx.wait);
    ctx.groups = NULL;
    ctx.group_count = 0;

    dna_request_id_t req_id = dna_engine_get_groups(engine, on_groups_list, &ctx);
    if (req_id == 0) {
        printf("Error: Failed to request groups list\n");
        cli_wait_destroy(&ctx.wait);
        return -1;
    }

    int result = cli_wait_for(&ctx.wait);
    cli_wait_destroy(&ctx.wait);

    if (result != 0) {
        printf("Error: Failed to get groups: %s\n", dna_engine_error_string(result));
        return result;
    }

    if (ctx.group_count == 0) {
        printf("No groups found.\n");
        printf("Use 'group-create <name>' to create a new group.\n");
        return 0;
    }

    printf("Groups (%d):\n", ctx.group_count);
    for (int i = 0; i < ctx.group_count; i++) {
        dna_group_t *g = &ctx.groups[i];
        printf("  %d. %s\n", i + 1, g->name);
        printf("     UUID: %s\n", g->uuid);
        printf("     Members: %d\n", g->member_count);
        printf("     Creator: %.16s...\n", g->creator);
    }

    if (ctx.groups) {
        free(ctx.groups);
    }

    return 0;
}

int cmd_group_create(dna_engine_t *engine, const char *name) {
    if (!engine || !name) {
        printf("Error: Engine not initialized or name missing\n");
        return -1;
    }

    printf("Creating group '%s'...\n", name);

    cli_group_wait_t ctx = {0};
    cli_wait_init(&ctx.wait);
    ctx.group_uuid[0] = '\0';

    /* Create group with no initial members (owner only) */
    dna_request_id_t req_id = dna_engine_create_group(engine, name, NULL, 0, on_group_created, &ctx);
    if (req_id == 0) {
        printf("Error: Failed to initiate group creation\n");
        cli_wait_destroy(&ctx.wait);
        return -1;
    }

    int result = cli_wait_for(&ctx.wait);
    cli_wait_destroy(&ctx.wait);

    if (result != 0) {
        printf("Error: Failed to create group: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("✓ Group created successfully!\n");
    printf("  UUID: %s\n", ctx.group_uuid);
    printf("\nUse 'group-invite %s <fingerprint>' to add members.\n", ctx.group_uuid);

    return 0;
}

int cmd_group_send(dna_engine_t *engine, const char *name_or_uuid, const char *message) {
    if (!engine || !name_or_uuid || !message) {
        printf("Error: Missing arguments\n");
        return -1;
    }

    /* Resolve name to UUID if needed */
    char resolved_uuid[37];
    if (resolve_group_identifier(engine, name_or_uuid, resolved_uuid) != 0) {
        printf("Error: Group '%s' not found\n", name_or_uuid);
        return -1;
    }

    printf("Sending message to group %s...\n", resolved_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_request_id_t req_id = dna_engine_send_group_message(engine, resolved_uuid, message, on_group_message_sent, &wait);
    if (req_id == 0) {
        printf("Error: Failed to initiate group message send\n");
        cli_wait_destroy(&wait);
        return -1;
    }

    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to send group message: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("✓ Message sent to group!\n");
    return 0;
}

int cmd_group_info(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Missing group UUID\n");
        return -1;
    }

    /* Get groups list and find the matching one */
    cli_group_wait_t ctx = {0};
    cli_wait_init(&ctx.wait);
    ctx.groups = NULL;
    ctx.group_count = 0;

    dna_request_id_t req_id = dna_engine_get_groups(engine, on_groups_list, &ctx);
    if (req_id == 0) {
        printf("Error: Failed to request groups\n");
        cli_wait_destroy(&ctx.wait);
        return -1;
    }

    int result = cli_wait_for(&ctx.wait);
    cli_wait_destroy(&ctx.wait);

    if (result != 0) {
        printf("Error: Failed to get groups: %s\n", dna_engine_error_string(result));
        return result;
    }

    /* Find the group */
    dna_group_t *found = NULL;
    for (int i = 0; i < ctx.group_count; i++) {
        if (strcmp(ctx.groups[i].uuid, group_uuid) == 0) {
            found = &ctx.groups[i];
            break;
        }
    }

    if (!found) {
        printf("Error: Group not found: %s\n", group_uuid);
        if (ctx.groups) free(ctx.groups);
        return -1;
    }

    printf("========================================\n");
    printf("Group: %s\n", found->name);
    printf("UUID: %s\n", found->uuid);
    printf("Members: %d\n", found->member_count);
    printf("Creator: %s\n", found->creator);
    if (found->created_at > 0) {
        time_t ts = (time_t)found->created_at;
        char time_str[32];
        struct tm tm_buf;
        if (safe_localtime(&ts, &tm_buf)) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
        } else {
            strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
        }
        printf("Created: %s\n", time_str);
    }
    printf("========================================\n");

    if (ctx.groups) free(ctx.groups);
    return 0;
}

int cmd_group_invite(dna_engine_t *engine, const char *group_uuid, const char *identifier) {
    if (!engine || !group_uuid || !identifier) {
        printf("Error: Missing arguments\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    if (strlen(identifier) >= 128) {
        /* Already looks like a fingerprint */
        strncpy(resolved_fp, identifier, 128);
    } else {
        /* Assume it's a name - resolve via DHT lookup */
        printf("Resolving name '%s'...\n", identifier);

        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
        printf("Resolved to: %.16s...\n", resolved_fp);
    }

    printf("Inviting %.16s... to group %s...\n", resolved_fp, group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_request_id_t req_id = dna_engine_add_group_member(
        engine, group_uuid, resolved_fp, on_completion, &wait);
    if (req_id == 0) {
        printf("Error: Failed to initiate group invite\n");
        cli_wait_destroy(&wait);
        return -1;
    }

    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to invite member: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("✓ Member invited successfully!\n");
    return 0;
}

int cmd_group_sync(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Missing group UUID\n");
        return -1;
    }

    printf("Syncing group %s from DHT...\n", group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_request_id_t req_id = dna_engine_sync_group_by_uuid(
        engine, group_uuid, on_completion, &wait);
    if (req_id == 0) {
        printf("Error: Failed to initiate group sync\n");
        cli_wait_destroy(&wait);
        return -1;
    }

    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync group: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Group synced successfully from DHT!\n");
    return 0;
}

int cmd_group_publish_gek(dna_engine_t *engine, const char *name_or_uuid) {
    if (!engine || !name_or_uuid) {
        printf("Error: Missing group name or UUID\n");
        return -1;
    }

    /* Resolve name to UUID if needed */
    char resolved_uuid[37];
    if (resolve_group_identifier(engine, name_or_uuid, resolved_uuid) != 0) {
        printf("Error: Group '%s' not found\n", name_or_uuid);
        return -1;
    }

    printf("Publishing GEK for group %s to DHT...\n", resolved_uuid);

    /* Get the fingerprint from engine */
    const char *fingerprint = dna_engine_get_fingerprint(engine);
    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    /* Call gek_rotate_on_member_add to generate and publish GEK */
    /* This works because it:
     * 1. Generates new GEK (or uses existing if version 0)
     * 2. Builds IKP for all current members
     * 3. Publishes to DHT
     */
    extern int gek_rotate_on_member_add(const char *group_uuid, const char *owner_identity);

    int ret = gek_rotate_on_member_add(resolved_uuid, fingerprint);
    if (ret != 0) {
        printf("Error: Failed to publish GEK\n");
        return -1;
    }

    printf("GEK published successfully to DHT!\n");
    return 0;
}

int cmd_gek_fetch(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Missing group UUID\n");
        return -1;
    }

    printf("Fetching GEK for group %s from DHT...\n", group_uuid);

    /* Check nodus is ready */
    if (!nodus_ops_is_ready()) {
        printf("Error: DHT not initialized\n");
        return -1;
    }

    /* Get data directory for key loading */
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        printf("Error: No data directory\n");
        return -1;
    }

    /* Load Kyber private key for GEK decryption */
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
        printf("Error: Failed to load Kyber key\n");
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {
        printf("Error: Invalid Kyber key size: %zu\n", kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        return -1;
    }

    /* Load Dilithium key to compute fingerprint */
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *dilithium_key = NULL;
    if (qgp_key_load(dilithium_path, &dilithium_key) != 0 || !dilithium_key) {
        printf("Error: Failed to load Dilithium key\n");
        qgp_key_free(kyber_key);
        return -1;
    }

    /* Compute fingerprint (SHA3-512 of Dilithium public key) */
    uint8_t my_fingerprint[64];
    if (qgp_sha3_512(dilithium_key->public_key, 2592, my_fingerprint) != 0) {
        printf("Error: Failed to compute fingerprint\n");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        return -1;
    }
    qgp_key_free(dilithium_key);

    /* Get group metadata to find current GEK version */
    printf("Fetching group metadata...\n");
    dht_group_metadata_t *group_meta = NULL;
    int ret = dht_groups_get(group_uuid, &group_meta);
    if (ret != 0 || !group_meta) {
        printf("Error: Failed to get group metadata (group may not exist in DHT)\n");
        qgp_key_free(kyber_key);
        return -1;
    }

    uint32_t gek_version = group_meta->gek_version;
    printf("Group metadata: name='%s', GEK version=%u, members=%u\n",
           group_meta->name, gek_version, group_meta->member_count);
    dht_groups_free_metadata(group_meta);

    /* Fetch the IKP (Initial Key Packet) from DHT */
    printf("Fetching IKP for GEK version %u...\n", gek_version);
    uint8_t *ikp_packet = NULL;
    size_t ikp_size = 0;
    ret = dht_gek_fetch(group_uuid, gek_version, &ikp_packet, &ikp_size);

    if (ret != 0 || !ikp_packet || ikp_size == 0) {
        printf("Error: No GEK v%u found in DHT for group %s\n", gek_version, group_uuid);
        qgp_key_free(kyber_key);
        return -1;
    }

    printf("Found IKP: %zu bytes\n", ikp_size);

    /* Get member count from IKP */
    uint8_t member_count = 0;
    if (ikp_get_member_count(ikp_packet, ikp_size, &member_count) == 0) {
        printf("IKP contains entries for %u members\n", member_count);
    }

    /* Try to extract GEK from IKP using my fingerprint and Kyber private key */
    printf("Attempting to extract GEK...\n");
    uint8_t gek[GEK_KEY_SIZE];
    uint32_t extracted_version = 0;
    ret = ikp_extract(ikp_packet, ikp_size, my_fingerprint,
                      kyber_key->private_key, gek, &extracted_version);
    free(ikp_packet);
    qgp_key_free(kyber_key);

    if (ret != 0) {
        printf("Error: Failed to extract GEK from IKP\n");
        printf("  - You may not be a member of this group\n");
        printf("  - Or the IKP may be corrupted/malformed\n");
        return -1;
    }

    /* Store GEK locally */
    ret = gek_store(group_uuid, extracted_version, gek);

    /* Print success and GEK info (first 8 bytes for debugging) */
    printf("\nGEK extracted successfully!\n");
    printf("  Version: %u\n", extracted_version);
    printf("  Key (first 8 bytes): ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", gek[i]);
    }
    printf("...\n");

    /* Zero sensitive data */
    qgp_secure_memzero(gek, GEK_KEY_SIZE);

    if (ret != 0) {
        printf("Warning: Failed to store GEK locally\n");
        return -1;
    }

    printf("  Stored locally: yes\n");
    return 0;
}

int cmd_group_messages(dna_engine_t *engine, const char *name_or_uuid) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!name_or_uuid || strlen(name_or_uuid) == 0) {
        printf("Error: Group name or UUID required\n");
        return -1;
    }

    /* Resolve name to UUID if needed */
    char resolved_uuid[37];
    if (resolve_group_identifier(engine, name_or_uuid, resolved_uuid) != 0) {
        printf("Error: Group '%s' not found\n", name_or_uuid);
        return -1;
    }

    printf("Fetching messages for group %s...\n", resolved_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_group_conversation(engine, resolved_uuid, on_messages_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get group messages: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.message_count == 0) {
        printf("No messages in this group.\n");
    } else {
        printf("\nGroup conversation (%d messages):\n\n", wait.message_count);
        for (int i = 0; i < wait.message_count; i++) {
            time_t ts = (time_t)wait.messages[i].timestamp;
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
            } else {
                strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
            }

            const char *direction = wait.messages[i].is_outgoing ? ">>>" : "<<<";

            /* For group messages, show sender fingerprint (truncated) */
            if (wait.messages[i].is_outgoing) {
                printf("[%s] %s %s\n", time_str, direction,
                       wait.messages[i].plaintext ? wait.messages[i].plaintext : "(empty)");
            } else {
                /* Show first 16 chars of sender fingerprint */
                printf("[%s] %s [%.16s] %s\n", time_str, direction,
                       wait.messages[i].sender,
                       wait.messages[i].plaintext ? wait.messages[i].plaintext : "(empty)");
            }

            if (wait.messages[i].plaintext) {
                free(wait.messages[i].plaintext);
            }
        }
        free(wait.messages);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

/* ============================================================================
 * PHASE 1: CONTACT BLOCKING & REQUESTS (6 commands)
 * ============================================================================ */

/* Callback for blocked users list */
static void on_blocked_users(dna_request_id_t request_id, int error,
                              dna_blocked_user_t *users, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && users && count > 0) {
        wait->fingerprint_count = count;
        printf("\nBlocked users (%d):\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %d. %.32s...\n", i + 1, users[i].fingerprint);
            if (users[i].reason[0]) {
                printf("     Reason: %s\n", users[i].reason);
            }
            if (users[i].blocked_at > 0) {
                time_t ts = (time_t)users[i].blocked_at;
                char time_str[32];
                struct tm tm_buf;
                if (safe_localtime(&ts, &tm_buf)) {
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
                } else {
                    strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
                }
                printf("     Blocked: %s\n", time_str);
            }
        }
        printf("\n");
    } else if (error == 0) {
        printf("No blocked users.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (users) {
        dna_free_blocked_users(users, count);
    }
}

int cmd_block(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Name or fingerprint required\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    size_t id_len = strlen(identifier);

    if (id_len == 128) {
        strncpy(resolved_fp, identifier, 128);
    } else {
        printf("Resolving name '%s'...\n", identifier);
        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
        printf("Resolved to: %.16s...\n", resolved_fp);
    }

    printf("Blocking user %.16s...\n", resolved_fp);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_block_user(engine, resolved_fp, NULL, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to block user: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("User blocked successfully!\n");
    return 0;
}

int cmd_unblock(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Unblocking user %.16s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_unblock_user(engine, fingerprint, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to unblock user: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("User unblocked successfully!\n");
    return 0;
}

int cmd_blocked(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_blocked_users(engine, on_blocked_users, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get blocked users: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_is_blocked(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    bool blocked = dna_engine_is_user_blocked(engine, fingerprint);
    printf("User %.16s... is %s\n", fingerprint, blocked ? "BLOCKED" : "not blocked");

    return 0;
}

int cmd_deny(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Denying contact request from %.16s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_deny_contact_request(engine, fingerprint, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to deny request: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Contact request denied.\n");
    return 0;
}

int cmd_request_count(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    int count = dna_engine_get_contact_request_count(engine);
    if (count < 0) {
        printf("Error: Failed to get request count\n");
        return -1;
    }

    printf("Pending contact requests: %d\n", count);
    return 0;
}

/* ============================================================================
 * PHASE 2: MESSAGE QUEUE OPERATIONS (5 commands)
 * ============================================================================ */

int cmd_queue_status(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    int size = dna_engine_get_message_queue_size(engine);
    int capacity = dna_engine_get_message_queue_capacity(engine);

    printf("\nMessage Queue Status:\n");
    printf("  Size:     %d messages\n", size);
    printf("  Capacity: %d messages\n", capacity);
    printf("  Usage:    %.1f%%\n", capacity > 0 ? (100.0 * size / capacity) : 0.0);
    printf("\n");

    return 0;
}

int cmd_queue_send(dna_engine_t *engine, const char *recipient, const char *message) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!recipient || strlen(recipient) == 0) {
        printf("Error: Recipient required\n");
        return -1;
    }

    if (!message || strlen(message) == 0) {
        printf("Error: Message required\n");
        return -1;
    }

    printf("Queuing message to %.16s...\n", recipient);

    int result = dna_engine_queue_message(engine, recipient, message);
    if (result != 0) {
        printf("Error: Failed to queue message: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Message queued successfully!\n");
    return 0;
}

int cmd_set_queue_capacity(dna_engine_t *engine, int capacity) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (capacity < 1) {
        printf("Error: Capacity must be at least 1\n");
        return -1;
    }

    int result = dna_engine_set_message_queue_capacity(engine, capacity);
    if (result != 0) {
        printf("Error: Failed to set queue capacity: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Message queue capacity set to %d\n", capacity);
    return 0;
}

int cmd_retry_pending(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Retrying all pending messages...\n");

    int result = dna_engine_retry_pending_messages(engine);
    if (result < 0) {
        printf("Error: Failed to retry messages: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Retried %d pending messages.\n", result);
    return 0;
}

int cmd_retry_message(dna_engine_t *engine, int64_t message_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Retrying message %lld...\n", (long long)message_id);

    int result = dna_engine_retry_message(engine, message_id);
    if (result != 0) {
        printf("Error: Failed to retry message: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Message retry initiated.\n");
    return 0;
}

/* ============================================================================
 * PHASE 3: MESSAGE MANAGEMENT (4 commands)
 * ============================================================================ */

int cmd_delete_message(dna_engine_t *engine, int64_t message_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Deleting message %lld...\n", (long long)message_id);

    int result = dna_engine_delete_message_sync(engine, message_id);
    if (result != 0) {
        printf("Error: Failed to delete message: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Message deleted.\n");
    return 0;
}

int cmd_mark_read(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Contact name or fingerprint required\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    size_t id_len = strlen(identifier);

    if (id_len == 128) {
        strncpy(resolved_fp, identifier, 128);
    } else {
        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
    }

    printf("Marking conversation with %.16s... as read...\n", resolved_fp);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_mark_conversation_read(engine, resolved_fp, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to mark as read: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Conversation marked as read.\n");
    return 0;
}

int cmd_unread(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Contact name or fingerprint required\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    size_t id_len = strlen(identifier);

    if (id_len == 128) {
        strncpy(resolved_fp, identifier, 128);
    } else {
        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
    }

    int count = dna_engine_get_unread_count(engine, resolved_fp);
    if (count < 0) {
        printf("Error: Failed to get unread count\n");
        return -1;
    }

    printf("Unread messages with %.16s...: %d\n", resolved_fp, count);
    return 0;
}

/* Callback for paginated messages (with total count) */
static void on_messages_page(dna_request_id_t request_id, int error,
                              dna_message_t *messages, int count, int total, void *user_data) {
    (void)request_id;
    (void)total;  /* Could use this for pagination info */
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;
    wait->message_count = 0;
    wait->messages = NULL;

    if (error == 0 && messages && count > 0) {
        wait->messages = malloc(count * sizeof(dna_message_t));
        if (wait->messages) {
            memcpy(wait->messages, messages, count * sizeof(dna_message_t));
            /* Copy plaintext strings */
            for (int i = 0; i < count; i++) {
                if (messages[i].plaintext) {
                    wait->messages[i].plaintext = strdup(messages[i].plaintext);
                }
            }
            wait->message_count = count;
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    /* Free original messages */
    if (messages) {
        for (int i = 0; i < count; i++) {
            if (messages[i].plaintext) free(messages[i].plaintext);
        }
        free(messages);
    }
}

int cmd_messages_page(dna_engine_t *engine, const char *identifier, int limit, int offset) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!identifier || strlen(identifier) == 0) {
        printf("Error: Contact name or fingerprint required\n");
        return -1;
    }

    /* Resolve name to fingerprint if needed */
    char resolved_fp[129] = {0};
    size_t id_len = strlen(identifier);

    if (id_len == 128) {
        strncpy(resolved_fp, identifier, 128);
    } else {
        cli_wait_t lookup_wait;
        cli_wait_init(&lookup_wait);

        dna_engine_lookup_name(engine, identifier, on_display_name, &lookup_wait);
        int lookup_result = cli_wait_for(&lookup_wait);

        if (lookup_result != 0 || strlen(lookup_wait.display_name) == 0) {
            printf("Error: Name '%s' not found in DHT\n", identifier);
            cli_wait_destroy(&lookup_wait);
            return -1;
        }

        strncpy(resolved_fp, lookup_wait.display_name, 128);
        cli_wait_destroy(&lookup_wait);
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_conversation_page(engine, resolved_fp, limit, offset, on_messages_page, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get messages: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.message_count == 0) {
        printf("No messages in this range (offset=%d, limit=%d).\n", offset, limit);
    } else {
        printf("\nMessages with %.16s... (offset=%d, limit=%d, got %d):\n\n",
               resolved_fp, offset, limit, wait.message_count);
        for (int i = 0; i < wait.message_count; i++) {
            time_t ts = (time_t)wait.messages[i].timestamp;
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
            } else {
                strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
            }

            const char *direction = wait.messages[i].is_outgoing ? ">>>" : "<<<";
            printf("[%s] %s %s\n", time_str, direction,
                   wait.messages[i].plaintext ? wait.messages[i].plaintext : "(empty)");

            if (wait.messages[i].plaintext) {
                free(wait.messages[i].plaintext);
            }
        }
        free(wait.messages);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

/* ============================================================================
 * PHASE 4: DHT SYNC OPERATIONS (5 commands)
 * ============================================================================ */

int cmd_sync_contacts_up(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Syncing contacts to DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_sync_contacts_to_dht(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync contacts to DHT: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Contacts synced to DHT successfully!\n");
    return 0;
}

int cmd_sync_contacts_down(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Syncing contacts from DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_sync_contacts_from_dht(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync contacts from DHT: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Contacts synced from DHT successfully!\n");
    return 0;
}

int cmd_sync_groups(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Syncing all groups from DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_sync_groups(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync groups: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Groups synced from DHT successfully!\n");
    return 0;
}

int cmd_sync_groups_up(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Syncing groups to DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_sync_groups_to_dht(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync groups to DHT: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Groups synced to DHT successfully!\n");
    return 0;
}

int cmd_sync_groups_down(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Restoring groups from DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_restore_groups_from_dht(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to restore groups from DHT: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Groups restored from DHT successfully!\n");
    return 0;
}

int cmd_refresh_presence(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Refreshing presence in DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_refresh_presence(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to refresh presence: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Presence refreshed in DHT!\n");
    return 0;
}


/* ============================================================================
 * PHASE 5: DEBUG LOGGING (7 commands)
 * ============================================================================ */

int cmd_log_level(dna_engine_t *engine, const char *level) {
    (void)engine;  /* Not needed for global log settings */

    if (!level) {
        /* Get current level */
        const char *current = dna_engine_get_log_level();
        printf("Current log level: %s\n", current ? current : "(not set)");
        return 0;
    }

    /* Set level */
    int result = dna_engine_set_log_level(level);
    if (result != 0) {
        printf("Error: Failed to set log level\n");
        printf("Valid levels: DEBUG, INFO, WARN, ERROR\n");
        return -1;
    }

    printf("Log level set to: %s\n", level);
    return 0;
}

int cmd_log_tags(dna_engine_t *engine, const char *tags) {
    (void)engine;

    if (!tags) {
        /* Get current tags */
        const char *current = dna_engine_get_log_tags();
        printf("Current log tags: %s\n", current ? current : "(all)");
        return 0;
    }

    /* Set tags */
    int result = dna_engine_set_log_tags(tags);
    if (result != 0) {
        printf("Error: Failed to set log tags\n");
        return -1;
    }

    printf("Log tags set to: %s\n", tags);
    return 0;
}

int cmd_debug_log(dna_engine_t *engine, bool enable) {
    (void)engine;

    dna_engine_debug_log_enable(enable);
    printf("Debug logging %s\n", enable ? "ENABLED" : "DISABLED");
    return 0;
}

int cmd_debug_entries(dna_engine_t *engine, int max_entries) {
    (void)engine;

    if (max_entries <= 0) max_entries = 50;
    if (max_entries > 200) max_entries = 200;

    dna_debug_log_entry_t *entries = malloc(sizeof(dna_debug_log_entry_t) * max_entries);
    if (!entries) {
        printf("Error: Out of memory\n");
        return -1;
    }

    int count = dna_engine_debug_log_get_entries(entries, max_entries);
    if (count < 0) {
        printf("Error: Failed to get debug log entries\n");
        free(entries);
        return -1;
    }

    if (count == 0) {
        printf("No debug log entries.\n");
    } else {
        printf("\nDebug log entries (%d):\n", count);
        printf("----------------------------------------\n");
        for (int i = 0; i < count; i++) {
            time_t ts = (time_t)(entries[i].timestamp_ms / 1000);
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%H:%M:%S", &tm_buf);
            } else {
                strncpy(time_str, "00:00:00", sizeof(time_str));
            }

            const char *level_str = "???";
            switch (entries[i].level) {
                case 0: level_str = "DBG"; break;
                case 1: level_str = "INF"; break;
                case 2: level_str = "WRN"; break;
                case 3: level_str = "ERR"; break;
            }

            printf("[%s] [%s] [%s] %s\n",
                   time_str, level_str, entries[i].tag, entries[i].message);
        }
        printf("----------------------------------------\n");
    }

    free(entries);
    return 0;
}

int cmd_debug_count(dna_engine_t *engine) {
    (void)engine;

    int count = dna_engine_debug_log_count();
    printf("Debug log entries: %d\n", count);
    return 0;
}

int cmd_debug_clear(dna_engine_t *engine) {
    (void)engine;

    dna_engine_debug_log_clear();
    printf("Debug log cleared.\n");
    return 0;
}

int cmd_debug_export(dna_engine_t *engine, const char *filepath) {
    (void)engine;

    if (!filepath || strlen(filepath) == 0) {
        printf("Error: File path required\n");
        return -1;
    }

    int result = dna_engine_debug_log_export(filepath);
    if (result != 0) {
        printf("Error: Failed to export debug log\n");
        return -1;
    }

    printf("Debug log exported to: %s\n", filepath);
    return 0;
}

/* ============================================================================
 * PHASE 6: GROUP EXTENSIONS (4 commands)
 * ============================================================================ */

/* Callback for group members */
static void on_group_members(dna_request_id_t request_id, int error,
                              dna_group_member_t *members, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && members && count > 0) {
        printf("\nGroup members (%d):\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %d. %.32s...\n", i + 1, members[i].fingerprint);
            printf("     Role: %s\n", members[i].is_owner ? "owner" : "member");
            if (members[i].added_at > 0) {
                time_t ts = (time_t)members[i].added_at;
                char time_str[32];
                struct tm tm_buf;
                if (safe_localtime(&ts, &tm_buf)) {
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
                } else {
                    strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
                }
                printf("     Added: %s\n", time_str);
            }
        }
        printf("\n");
    } else if (error == 0) {
        printf("No members in group.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (members) {
        dna_free_group_members(members, count);
    }
}

int cmd_group_members(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Engine not initialized or UUID missing\n");
        return -1;
    }

    printf("Getting members for group %s...\n", group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_group_members(engine, group_uuid, on_group_members, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get group members: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

/* Callback for invitations */
static void on_invitations(dna_request_id_t request_id, int error,
                           dna_invitation_t *invitations, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && invitations && count > 0) {
        printf("\nPending group invitations (%d):\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %d. Group: %s\n", i + 1, invitations[i].group_name);
            printf("     UUID: %s\n", invitations[i].group_uuid);
            printf("     From: %.32s...\n", invitations[i].inviter);
            if (invitations[i].invited_at > 0) {
                time_t ts = (time_t)invitations[i].invited_at;
                char time_str[32];
                struct tm tm_buf;
                if (safe_localtime(&ts, &tm_buf)) {
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
                } else {
                    strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
                }
                printf("     Invited: %s\n", time_str);
            }
        }
        printf("\nUse 'invite-accept <uuid>' or 'invite-reject <uuid>' to respond.\n\n");
    } else if (error == 0) {
        printf("No pending group invitations.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (invitations) {
        dna_free_invitations(invitations, count);
    }
}

int cmd_invitations(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_invitations(engine, on_invitations, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get invitations: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_invite_accept(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Engine not initialized or UUID missing\n");
        return -1;
    }

    printf("Accepting invitation to group %s...\n", group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_accept_invitation(engine, group_uuid, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to accept invitation: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Invitation accepted! You are now a member of the group.\n");
    return 0;
}

int cmd_invite_reject(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Engine not initialized or UUID missing\n");
        return -1;
    }

    printf("Rejecting invitation to group %s...\n", group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_reject_invitation(engine, group_uuid, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to reject invitation: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Invitation rejected.\n");
    return 0;
}

/* ============================================================================
 * PHASE 7: PRESENCE CONTROL (3 commands)
 * ============================================================================ */

int cmd_pause_presence(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    dna_engine_pause_presence(engine);
    printf("Presence updates paused.\n");
    return 0;
}

int cmd_resume_presence(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    dna_engine_resume_presence(engine);
    printf("Presence updates resumed.\n");
    return 0;
}

int cmd_network_changed(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Reinitializing DHT after network change...\n");

    int result = dna_engine_network_changed(engine);
    if (result != 0) {
        printf("Error: Failed to reinitialize: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("DHT reinitialized successfully.\n");
    return 0;
}

/* ============================================================================
 * PHASE 8: CONTACT & IDENTITY EXTENSIONS (5 commands)
 * ============================================================================ */

int cmd_set_nickname(dna_engine_t *engine, const char *fingerprint, const char *nickname) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    if (!nickname) {
        printf("Error: Nickname required (use empty string to clear)\n");
        return -1;
    }

    int result = dna_engine_set_contact_nickname_sync(engine, fingerprint, nickname);
    if (result != 0) {
        printf("Error: Failed to set nickname: %s\n", dna_engine_error_string(result));
        return result;
    }

    if (strlen(nickname) > 0) {
        printf("Nickname set to '%s' for %.16s...\n", nickname, fingerprint);
    } else {
        printf("Nickname cleared for %.16s...\n", fingerprint);
    }
    return 0;
}

/* Callback for avatar (receives base64 string via dna_display_name_cb) */
static void on_avatar_result(dna_request_id_t request_id, int error,
                              const char *avatar_base64, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && avatar_base64 && strlen(avatar_base64) > 0) {
        printf("Avatar: %zu bytes (base64)\n", strlen(avatar_base64));
    } else if (error == 0) {
        printf("No avatar set.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_get_avatar(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Getting avatar for %.16s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_avatar(engine, fingerprint, on_avatar_result, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get avatar: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_get_mnemonic(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    char mnemonic[512];
    int result = dna_engine_get_mnemonic(engine, mnemonic, sizeof(mnemonic));
    if (result != 0) {
        printf("Error: Failed to get mnemonic: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("\n*** RECOVERY PHRASE (24 words) ***\n");
    printf("Keep this safe! Anyone with this phrase can access your identity.\n\n");
    qgp_display_mnemonic(mnemonic);
    printf("\n");

    /* Clear from memory */
    qgp_secure_memzero(mnemonic, sizeof(mnemonic));
    return 0;
}

/* Callback for profile refresh */
static void on_profile_refresh(dna_request_id_t request_id, int error,
                                dna_profile_t *profile, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && profile) {
        printf("Profile refreshed successfully!\n");
        /* NOTE: display_name removed in v0.6.24 - name comes from registered_name */
        if (profile->bio[0]) {
            printf("  Bio: %s\n", profile->bio);
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (profile) {
        dna_free_profile(profile);
    }
}

int cmd_refresh_profile(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Refreshing profile for %.16s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_refresh_contact_profile(engine, fingerprint, on_profile_refresh, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to refresh profile: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_dht_status(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    int connected = dna_engine_is_dht_connected(engine);
    printf("DHT Status: %s\n", connected ? "CONNECTED" : "DISCONNECTED");
    return 0;
}

/* ============================================================================
 * PHASE 9: WALLET OPERATIONS (3 commands)
 * ============================================================================ */

/* Callback for send tokens (receives tx_hash) */
static void on_send_tokens(dna_request_id_t request_id, int error,
                            const char *tx_hash, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && tx_hash) {
        printf("Transaction hash: %s\n", tx_hash);
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_send_tokens(dna_engine_t *engine, int wallet_idx, const char *network,
                    const char *token, const char *to_address, const char *amount) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!network || !token || !to_address || !amount) {
        printf("Error: All parameters required\n");
        return -1;
    }

    printf("Sending %s %s to %s on %s...\n", amount, token, to_address, network);

    cli_wait_t wait;
    cli_wait_init(&wait);

    /* API: (engine, wallet_index, recipient_address, amount, token, network, gas_speed, callback, user_data) */
    dna_engine_send_tokens(engine, wallet_idx, to_address, amount, token, network, 0, on_send_tokens, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to send tokens: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Tokens sent successfully!\n");
    return 0;
}

/* Callback for transactions */
static void on_transactions(dna_request_id_t request_id, int error,
                            dna_transaction_t *transactions, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && transactions && count > 0) {
        printf("\nTransactions (%d):\n", count);
        for (int i = 0; i < count; i++) {
            /* direction is "sent" or "received" string */
            const char *dir_label = (strcmp(transactions[i].direction, "sent") == 0) ? "SENT" : "RECEIVED";
            printf("  %d. [%s] %s %s %s\n", i + 1, transactions[i].timestamp, dir_label,
                   transactions[i].amount, transactions[i].token);
            printf("     %s: %s\n",
                   (strcmp(transactions[i].direction, "sent") == 0) ? "To" : "From",
                   transactions[i].other_address);
            printf("     Status: %s\n", transactions[i].status);
            if (transactions[i].tx_hash[0]) {
                printf("     Hash: %.16s...\n", transactions[i].tx_hash);
            }
        }
        printf("\n");
    } else if (error == 0) {
        printf("No transactions found.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (transactions) {
        dna_free_transactions(transactions, count);
    }
}

int cmd_transactions(dna_engine_t *engine, int wallet_idx) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Getting transactions for wallet %d...\n", wallet_idx);

    cli_wait_t wait;
    cli_wait_init(&wait);

    /* API requires network parameter - use "Backbone" as default */
    dna_engine_get_transactions(engine, wallet_idx, "Backbone", on_transactions, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get transactions: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_estimate_gas(dna_engine_t *engine, int network_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    dna_gas_estimate_t estimate;
    int result = dna_engine_estimate_eth_gas(network_id, &estimate);
    if (result != 0) {
        printf("Error: Failed to estimate gas\n");
        return result;
    }

    printf("\nGas Estimate (Network %d):\n", network_id);
    printf("  Gas Price: %lu wei\n", (unsigned long)estimate.gas_price);
    printf("  Gas Limit: %lu\n", (unsigned long)estimate.gas_limit);
    printf("  Est. Fee:  %s ETH\n", estimate.fee_eth);
    printf("\n");

    return 0;
}

/* ============================================================================
 * PHASE 11: MESSAGE BACKUP (2 commands)
 * ============================================================================ */

/* Callback for backup/restore results */
static void on_backup_result(dna_request_id_t request_id, int error,
                              int processed_count, int skipped_count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0) {
        printf("  Processed: %d messages\n", processed_count);
        printf("  Skipped: %d messages (duplicates)\n", skipped_count);
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_backup_messages(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Backing up messages to DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_backup_messages(engine, on_backup_result, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to backup messages: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Messages backed up to DHT successfully!\n");
    return 0;
}

int cmd_restore_messages(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Restoring messages from DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_restore_messages(engine, on_backup_result, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to restore messages: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Messages restored from DHT successfully!\n");
    return 0;
}

/* ============================================================================
 * PHASE 12: SIGNING API (2 commands)
 * ============================================================================ */

int cmd_sign(dna_engine_t *engine, const char *data) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!data || strlen(data) == 0) {
        printf("Error: Data to sign required\n");
        return -1;
    }

    uint8_t signature[4627];  /* Dilithium5 max signature size */
    size_t sig_len = 0;

    int result = dna_engine_sign_data(engine, (const uint8_t *)data, strlen(data),
                                       signature, &sig_len);
    if (result != 0) {
        printf("Error: Failed to sign data: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Signature (%zu bytes):\n", sig_len);
    /* Print as hex */
    for (size_t i = 0; i < sig_len && i < 64; i++) {
        printf("%02x", signature[i]);
    }
    if (sig_len > 64) {
        printf("... (truncated)");
    }
    printf("\n");

    return 0;
}

/* ============================================================================
 * DEX COMMANDS
 * ============================================================================ */

static void on_dex_quote(dna_request_id_t request_id, int error,
                          const dna_dex_quote_t *quotes, int count,
                          void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && quotes && count > 0) {
        printf("\n%d DEX quote(s) found:\n", count);
        for (int i = 0; i < count; i++) {
            const dna_dex_quote_t *q = &quotes[i];
            printf("\n  [%d] %s — %s\n", i + 1, q->chain, q->dex_name);
            printf("      %s %s -> %s %s\n", q->amount_in, q->from_token,
                   q->amount_out, q->to_token);
            printf("      Price:        1 %s = %s %s\n", q->from_token, q->price, q->to_token);
            printf("      Slippage:     %s%%\n", q->price_impact);
            printf("      Fee:          %s %s\n", q->fee, q->from_token);
            printf("      Pool:         %s\n", q->pool_address);
            if (q->warning[0]) {
                printf("      WARNING:      %s\n", q->warning);
            }
        }
        printf("\n");
    }

    cli_wait_signal(wait, error);
}

static void on_dex_pairs(dna_request_id_t request_id, int error,
                          const char **pairs, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && pairs && count > 0) {
        printf("\nAvailable DEX pairs (%d):\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %s\n", pairs[i]);
        }
        printf("\nUsage: dex-quote <from> <to> <amount>\n");
        printf("Example: dex-quote SOL USDC 1.0\n\n");
    } else if (error == 0) {
        printf("No DEX pairs available.\n");
    }

    cli_wait_signal(wait, error);
}

int cmd_dex_quote(dna_engine_t *engine, const char *from_token,
                  const char *to_token, const char *amount,
                  const char *dex_filter) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (dex_filter) {
        printf("Getting quote: %s %s -> %s (filter: %s) ...\n",
               amount, from_token, to_token, dex_filter);
    } else {
        printf("Getting quotes: %s %s -> %s (all DEXes) ...\n",
               amount, from_token, to_token);
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_dex_quote(engine, from_token, to_token, amount, dex_filter,
                         on_dex_quote, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        if (result == -2) {
            printf("Error: No pool found for %s/%s\n", from_token, to_token);
            printf("Use 'dex-pairs' to see available pairs.\n");
        } else {
            printf("Error: Failed to get quote: %s\n", dna_engine_error_string(result));
        }
    }

    cli_wait_destroy(&wait);
    return result;
}

int cmd_dex_pairs(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_dex_list_pairs(engine, on_dex_pairs, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to list pairs: %s\n", dna_engine_error_string(result));
    }

    cli_wait_destroy(&wait);
    return result;
}

int cmd_signing_pubkey(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    uint8_t pubkey[2592];  /* Dilithium5 public key size */
    int result = dna_engine_get_signing_public_key(engine, pubkey, sizeof(pubkey));
    if (result < 0) {
        printf("Error: Failed to get signing public key: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Signing public key (%d bytes):\n", result);
    /* Print first 64 bytes as hex */
    for (int i = 0; i < 64 && i < result; i++) {
        printf("%02x", pubkey[i]);
    }
    if (result > 64) {
        printf("... (truncated)");
    }
    printf("\n");

    return 0;
}

/* ============================================================================
 * CHANNELS (10 commands) - RSS-like channel system
 * ============================================================================ */

/* Callback for single channel info */
static void on_channel_info(dna_request_id_t request_id, int error,
                            dna_channel_info_t *channel, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && channel) {
        time_t ts = (time_t)channel->created_at;
        char time_str[32];
        struct tm tm_buf;
        if (safe_localtime(&ts, &tm_buf)) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
        } else {
            strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
        }

        printf("\nChannel: %s\n", channel->name);
        printf("  UUID: %s\n", channel->channel_uuid);
        printf("  Description: %s\n", channel->description ? channel->description : "(none)");
        printf("  Creator: %.16s...\n", channel->creator_fingerprint);
        printf("  Created: %s\n", time_str);
        printf("  Public: %s\n", channel->is_public ? "yes" : "no");
        printf("  Verified: %s\n", channel->verified ? "yes" : "no");
        if (channel->deleted) {
            printf("  Status: DELETED\n");
        }
        printf("\n");

        dna_free_channel_info(channel);
    }

    cli_wait_signal(wait, error);
}

/* Callback for channel list (discover) */
static void on_channels_list(dna_request_id_t request_id, int error,
                             dna_channel_info_t *channels, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && channels && count > 0) {
        printf("\nChannels (%d):\n", count);
        for (int i = 0; i < count; i++) {
            time_t ts = (time_t)channels[i].created_at;
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
            } else {
                strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
            }

            printf("\n  %d. %s%s\n", i + 1, channels[i].name,
                   channels[i].deleted ? " [DELETED]" : "");
            printf("     UUID: %s\n", channels[i].channel_uuid);
            printf("     Description: %s\n", channels[i].description ? channels[i].description : "(none)");
            printf("     Creator: %.16s...  |  Created: %s\n",
                   channels[i].creator_fingerprint, time_str);
        }
        printf("\n");

        dna_free_channel_infos(channels, count);
    } else if (error == 0) {
        printf("No channels found.\n");
    }

    cli_wait_signal(wait, error);
}

/* Callback for single channel post */
static void on_channel_post_created(dna_request_id_t request_id, int error,
                                     dna_channel_post_info_t *post, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && post) {
        printf("Post created:\n");
        printf("  UUID: %s\n", post->post_uuid);
        printf("  Channel: %s\n", post->channel_uuid);
        printf("  Body: %s\n", post->body ? post->body : "(empty)");
        dna_free_channel_post(post);
    }

    cli_wait_signal(wait, error);
}

/* Callback for channel posts list */
static void on_channel_posts_list(dna_request_id_t request_id, int error,
                                   dna_channel_post_info_t *posts, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && posts && count > 0) {
        printf("\nPosts (%d):\n", count);
        for (int i = 0; i < count; i++) {
            time_t ts = (time_t)posts[i].created_at;
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
            } else {
                strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
            }

            printf("\n  [%s] %.16s...:\n", time_str, posts[i].author_fingerprint);
            printf("    %s\n", posts[i].body ? posts[i].body : "(empty)");
            printf("    UUID: %s  Verified: %s\n", posts[i].post_uuid,
                   posts[i].verified ? "yes" : "no");
        }
        printf("\n");

        dna_free_channel_posts(posts, count);
    } else if (error == 0) {
        printf("No posts in this channel.\n");
    }

    cli_wait_signal(wait, error);
}

/* Callback for channel subscriptions list */
static void on_channel_subscriptions(dna_request_id_t request_id, int error,
                                      dna_channel_subscription_info_t *subs, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    if (error == 0 && subs && count > 0) {
        printf("\nSubscriptions (%d):\n", count);
        for (int i = 0; i < count; i++) {
            time_t ts = (time_t)subs[i].subscribed_at;
            char time_str[32];
            struct tm tm_buf;
            if (safe_localtime(&ts, &tm_buf)) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", &tm_buf);
            } else {
                strncpy(time_str, "0000-00-00 00:00", sizeof(time_str));
            }

            printf("  %d. %s (subscribed: %s)\n", i + 1, subs[i].channel_uuid, time_str);
        }
        printf("\n");

        dna_free_channel_subscriptions(subs, count);
    } else if (error == 0) {
        printf("No subscriptions.\n");
    }

    cli_wait_signal(wait, error);
}

int cmd_channel_create(dna_engine_t *engine, const char *name, const char *description) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!name || strlen(name) == 0) { printf("Error: Channel name required\n"); return -1; }

    printf("Creating channel '%s'...\n", name);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_create(engine, name, description, true, on_channel_info, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to create channel: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Channel created successfully!\n");
    return 0;
}

int cmd_channel_get(dna_engine_t *engine, const char *uuid) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!uuid || strlen(uuid) == 0) { printf("Error: Channel UUID required\n"); return -1; }

    printf("Getting channel %s...\n", uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_get(engine, uuid, on_channel_info, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get channel: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_channel_delete(dna_engine_t *engine, const char *uuid) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!uuid || strlen(uuid) == 0) { printf("Error: Channel UUID required\n"); return -1; }

    printf("Deleting channel %s...\n", uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_delete(engine, uuid, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to delete channel: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Channel deleted successfully!\n");
    return 0;
}

int cmd_channel_discover(dna_engine_t *engine, int days) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }

    if (days < 1) days = 7;
    if (days > 30) days = 30;

    printf("Discovering channels (last %d days)...\n", days);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_discover(engine, days, on_channels_list, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to discover channels: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_channel_post(dna_engine_t *engine, const char *channel_uuid, const char *body) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!channel_uuid || strlen(channel_uuid) == 0) { printf("Error: Channel UUID required\n"); return -1; }
    if (!body || strlen(body) == 0) { printf("Error: Post body required\n"); return -1; }

    printf("Posting to channel %s...\n", channel_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_post(engine, channel_uuid, body, on_channel_post_created, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to post: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Posted successfully!\n");
    return 0;
}

int cmd_channel_posts(dna_engine_t *engine, const char *channel_uuid, int days_back) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!channel_uuid || strlen(channel_uuid) == 0) { printf("Error: Channel UUID required\n"); return -1; }

    printf("Getting posts for channel %s (%d days)...\n", channel_uuid,
           days_back > 0 ? days_back : 3);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_get_posts(engine, channel_uuid, days_back, on_channel_posts_list, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get posts: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_channel_subscribe(dna_engine_t *engine, const char *uuid) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!uuid || strlen(uuid) == 0) { printf("Error: Channel UUID required\n"); return -1; }

    int result = dna_engine_channel_subscribe(engine, uuid);
    if (result != 0) {
        printf("Error: Failed to subscribe: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Subscribed to channel %s\n", uuid);
    return 0;
}

int cmd_channel_unsubscribe(dna_engine_t *engine, const char *uuid) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }
    if (!uuid || strlen(uuid) == 0) { printf("Error: Channel UUID required\n"); return -1; }

    int result = dna_engine_channel_unsubscribe(engine, uuid);
    if (result != 0) {
        printf("Error: Failed to unsubscribe: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Unsubscribed from channel %s\n", uuid);
    return 0;
}

int cmd_channel_subscriptions(dna_engine_t *engine) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }

    printf("Getting subscriptions...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_get_subscriptions(engine, on_channel_subscriptions, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get subscriptions: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_channel_sync(dna_engine_t *engine) {
    if (!engine) { printf("Error: Engine not initialized\n"); return -1; }

    printf("Syncing subscriptions to DHT...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_channel_sync_subs_to_dht(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync to DHT: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Subscriptions synced to DHT!\n");

    printf("Syncing subscriptions from DHT...\n");

    cli_wait_init(&wait);

    dna_engine_channel_sync_subs_from_dht(engine, on_completion, &wait);
    result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to sync from DHT: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Subscriptions synced from DHT!\n");
    return 0;
}

/* ============================================================================
 * GROUP DISPATCHERS — argv-based (for main.c single-command mode)
 * ============================================================================ */

/* ---------- identity ---------- */
int dispatch_identity(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: identity <subcommand>\n");
        fprintf(stderr, "  identity create <name>\n");
        fprintf(stderr, "  identity restore <mnemonic...>\n");
        fprintf(stderr, "  identity delete <fingerprint>\n");
        fprintf(stderr, "  identity list\n");
        fprintf(stderr, "  identity load <fingerprint>\n");
        fprintf(stderr, "  identity whoami\n");
        fprintf(stderr, "  identity change-password\n");
        fprintf(stderr, "  identity register <name>\n");
        fprintf(stderr, "  identity name\n");
        fprintf(stderr, "  identity lookup <name>\n");
        fprintf(stderr, "  identity lookup-profile <name|fp>\n");
        fprintf(stderr, "  identity profile [field=value]\n");
        fprintf(stderr, "  identity set-nickname <fp> <nickname>\n");
        fprintf(stderr, "  identity get-avatar <fp>\n");
        fprintf(stderr, "  identity get-mnemonic\n");
        fprintf(stderr, "  identity refresh-profile <fp>\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "create") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity create <name>\n"); return 1; }
        return cmd_create(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "restore") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity restore <mnemonic...>\n"); return 1; }
        /* Concatenate remaining args as mnemonic */
        static char mnemonic[2048];
        mnemonic[0] = '\0';
        for (int i = sub + 1; i < argc; i++) {
            if (i > sub + 1) strncat(mnemonic, " ", sizeof(mnemonic) - strlen(mnemonic) - 1);
            strncat(mnemonic, argv[i], sizeof(mnemonic) - strlen(mnemonic) - 1);
        }
        return cmd_restore(engine, mnemonic);
    } else if (strcmp(subcmd, "delete") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity delete <fingerprint>\n"); return 1; }
        return cmd_delete(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "list") == 0) {
        return cmd_list(engine);
    } else if (strcmp(subcmd, "load") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity load <fingerprint>\n"); return 1; }
        return cmd_load(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "whoami") == 0) {
        cmd_whoami(engine); return 0;
    } else if (strcmp(subcmd, "change-password") == 0) {
        cmd_change_password(engine); return 0;
    } else if (strcmp(subcmd, "register") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity register <name>\n"); return 1; }
        return cmd_register(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "name") == 0) {
        return cmd_name(engine);
    } else if (strcmp(subcmd, "lookup") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity lookup <name>\n"); return 1; }
        return cmd_lookup(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "lookup-profile") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity lookup-profile <name|fp>\n"); return 1; }
        return cmd_lookup_profile(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "profile") == 0) {
        if (sub + 1 >= argc) {
            return cmd_profile(engine, NULL, NULL);
        }
        /* Parse field=value */
        char *eq = strchr(argv[sub + 1], '=');
        if (!eq) { fprintf(stderr, "Usage: identity profile [field=value]\n"); return 1; }
        *eq = '\0';
        return cmd_profile(engine, argv[sub + 1], eq + 1);
    } else if (strcmp(subcmd, "set-nickname") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: identity set-nickname <fp> <nickname>\n"); return 1; }
        return cmd_set_nickname(engine, argv[sub + 1], argv[sub + 2]);
    } else if (strcmp(subcmd, "get-avatar") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity get-avatar <fp>\n"); return 1; }
        return cmd_get_avatar(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "get-mnemonic") == 0) {
        return cmd_get_mnemonic(engine);
    } else if (strcmp(subcmd, "refresh-profile") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity refresh-profile <fp>\n"); return 1; }
        return cmd_refresh_profile(engine, argv[sub + 1]);
    } else {
        fprintf(stderr, "Unknown identity subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- contact ---------- */
int dispatch_contact(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: contact <subcommand>\n");
        fprintf(stderr, "  contact list\n");
        fprintf(stderr, "  contact add <name|fp>\n");
        fprintf(stderr, "  contact remove <fp>\n");
        fprintf(stderr, "  contact request <fp> [message]\n");
        fprintf(stderr, "  contact requests\n");
        fprintf(stderr, "  contact request-count\n");
        fprintf(stderr, "  contact approve <fp>\n");
        fprintf(stderr, "  contact deny <fp>\n");
        fprintf(stderr, "  contact block <name|fp>\n");
        fprintf(stderr, "  contact unblock <fp>\n");
        fprintf(stderr, "  contact blocked\n");
        fprintf(stderr, "  contact is-blocked <fp>\n");
        fprintf(stderr, "  contact check-inbox <name|fp>\n");
        fprintf(stderr, "  contact sync-up\n");
        fprintf(stderr, "  contact sync-down\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "list") == 0) {
        return cmd_contacts(engine);
    } else if (strcmp(subcmd, "add") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact add <name|fp>\n"); return 1; }
        return cmd_add_contact(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "remove") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact remove <fp>\n"); return 1; }
        return cmd_remove_contact(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "request") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact request <fp> [message]\n"); return 1; }
        const char *msg = NULL;
        if (sub + 2 < argc) {
            /* Concatenate remaining args as message */
            static char req_msg[2048];
            req_msg[0] = '\0';
            for (int i = sub + 2; i < argc; i++) {
                if (i > sub + 2) strncat(req_msg, " ", sizeof(req_msg) - strlen(req_msg) - 1);
                strncat(req_msg, argv[i], sizeof(req_msg) - strlen(req_msg) - 1);
            }
            msg = req_msg;
        }
        return cmd_request(engine, argv[sub + 1], msg);
    } else if (strcmp(subcmd, "requests") == 0) {
        return cmd_requests(engine);
    } else if (strcmp(subcmd, "request-count") == 0) {
        return cmd_request_count(engine);
    } else if (strcmp(subcmd, "approve") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact approve <fp>\n"); return 1; }
        return cmd_approve(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "deny") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact deny <fp>\n"); return 1; }
        return cmd_deny(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "block") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact block <name|fp>\n"); return 1; }
        return cmd_block(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "unblock") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact unblock <fp>\n"); return 1; }
        return cmd_unblock(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "blocked") == 0) {
        return cmd_blocked(engine);
    } else if (strcmp(subcmd, "is-blocked") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact is-blocked <fp>\n"); return 1; }
        return cmd_is_blocked(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "check-inbox") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: contact check-inbox <name|fp>\n"); return 1; }
        return cmd_check_inbox(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "sync-up") == 0) {
        return cmd_sync_contacts_up(engine);
    } else if (strcmp(subcmd, "sync-down") == 0) {
        return cmd_sync_contacts_down(engine);
    } else {
        fprintf(stderr, "Unknown contact subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- message ---------- */
int dispatch_message(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: message <subcommand>\n");
        fprintf(stderr, "  message send <recipient> <message...>\n");
        fprintf(stderr, "  message list <fp>\n");
        fprintf(stderr, "  message page <fp> <limit> <offset>\n");
        fprintf(stderr, "  message delete <message_id>\n");
        fprintf(stderr, "  message mark-read <name|fp>\n");
        fprintf(stderr, "  message unread <name|fp>\n");
        fprintf(stderr, "  message check-offline\n");
        fprintf(stderr, "  message listen\n");
        fprintf(stderr, "  message queue-status\n");
        fprintf(stderr, "  message queue-send <recipient> <message...>\n");
        fprintf(stderr, "  message queue-capacity <n>\n");
        fprintf(stderr, "  message retry-pending\n");
        fprintf(stderr, "  message retry-message <message_id>\n");
        fprintf(stderr, "  message backup\n");
        fprintf(stderr, "  message restore\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "send") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: message send <recipient> <message...>\n"); return 1; }
        /* Concatenate remaining args as message */
        static char msg_buf[4096];
        msg_buf[0] = '\0';
        for (int i = sub + 2; i < argc; i++) {
            if (i > sub + 2) strncat(msg_buf, " ", sizeof(msg_buf) - strlen(msg_buf) - 1);
            strncat(msg_buf, argv[i], sizeof(msg_buf) - strlen(msg_buf) - 1);
        }
        return cmd_send(engine, argv[sub + 1], msg_buf);
    } else if (strcmp(subcmd, "list") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: message list <fp>\n"); return 1; }
        return cmd_messages(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "page") == 0) {
        if (sub + 3 >= argc) { fprintf(stderr, "Usage: message page <fp> <limit> <offset>\n"); return 1; }
        return cmd_messages_page(engine, argv[sub + 1], atoi(argv[sub + 2]), atoi(argv[sub + 3]));
    } else if (strcmp(subcmd, "delete") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: message delete <message_id>\n"); return 1; }
        return cmd_delete_message(engine, strtoll(argv[sub + 1], NULL, 10));
    } else if (strcmp(subcmd, "mark-read") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: message mark-read <name|fp>\n"); return 1; }
        return cmd_mark_read(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "unread") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: message unread <name|fp>\n"); return 1; }
        return cmd_unread(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "check-offline") == 0) {
        return cmd_check_offline(engine);
    } else if (strcmp(subcmd, "listen") == 0) {
        return cmd_listen(engine);
    } else if (strcmp(subcmd, "queue-status") == 0) {
        return cmd_queue_status(engine);
    } else if (strcmp(subcmd, "queue-send") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: message queue-send <recipient> <message...>\n"); return 1; }
        static char qmsg_buf[4096];
        qmsg_buf[0] = '\0';
        for (int i = sub + 2; i < argc; i++) {
            if (i > sub + 2) strncat(qmsg_buf, " ", sizeof(qmsg_buf) - strlen(qmsg_buf) - 1);
            strncat(qmsg_buf, argv[i], sizeof(qmsg_buf) - strlen(qmsg_buf) - 1);
        }
        return cmd_queue_send(engine, argv[sub + 1], qmsg_buf);
    } else if (strcmp(subcmd, "queue-capacity") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: message queue-capacity <n>\n"); return 1; }
        return cmd_set_queue_capacity(engine, atoi(argv[sub + 1]));
    } else if (strcmp(subcmd, "retry-pending") == 0) {
        return cmd_retry_pending(engine);
    } else if (strcmp(subcmd, "retry-message") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: message retry-message <message_id>\n"); return 1; }
        return cmd_retry_message(engine, strtoll(argv[sub + 1], NULL, 10));
    } else if (strcmp(subcmd, "backup") == 0) {
        return cmd_backup_messages(engine);
    } else if (strcmp(subcmd, "restore") == 0) {
        return cmd_restore_messages(engine);
    } else {
        fprintf(stderr, "Unknown message subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- group ---------- */
int dispatch_group(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: group <subcommand>\n");
        fprintf(stderr, "  group list\n");
        fprintf(stderr, "  group create <name>\n");
        fprintf(stderr, "  group send <uuid> <message...>\n");
        fprintf(stderr, "  group info <uuid>\n");
        fprintf(stderr, "  group members <uuid>\n");
        fprintf(stderr, "  group invite <uuid> <fp>\n");
        fprintf(stderr, "  group messages <name|uuid>\n");
        fprintf(stderr, "  group sync <uuid>\n");
        fprintf(stderr, "  group sync-all\n");
        fprintf(stderr, "  group sync-up\n");
        fprintf(stderr, "  group sync-down\n");
        fprintf(stderr, "  group publish-gek <name|uuid>\n");
        fprintf(stderr, "  group gek-fetch <uuid>\n");
        fprintf(stderr, "  group invitations\n");
        fprintf(stderr, "  group invite-accept <uuid>\n");
        fprintf(stderr, "  group invite-reject <uuid>\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "list") == 0) {
        return cmd_group_list(engine);
    } else if (strcmp(subcmd, "create") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group create <name>\n"); return 1; }
        return cmd_group_create(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "send") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: group send <uuid> <message...>\n"); return 1; }
        static char gmsg_buf[4096];
        gmsg_buf[0] = '\0';
        for (int i = sub + 2; i < argc; i++) {
            if (i > sub + 2) strncat(gmsg_buf, " ", sizeof(gmsg_buf) - strlen(gmsg_buf) - 1);
            strncat(gmsg_buf, argv[i], sizeof(gmsg_buf) - strlen(gmsg_buf) - 1);
        }
        return cmd_group_send(engine, argv[sub + 1], gmsg_buf);
    } else if (strcmp(subcmd, "info") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group info <uuid>\n"); return 1; }
        return cmd_group_info(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "members") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group members <uuid>\n"); return 1; }
        return cmd_group_members(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "invite") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: group invite <uuid> <fp>\n"); return 1; }
        return cmd_group_invite(engine, argv[sub + 1], argv[sub + 2]);
    } else if (strcmp(subcmd, "messages") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group messages <name|uuid>\n"); return 1; }
        return cmd_group_messages(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "sync") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group sync <uuid>\n"); return 1; }
        return cmd_group_sync(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "sync-all") == 0) {
        return cmd_sync_groups(engine);
    } else if (strcmp(subcmd, "sync-up") == 0) {
        return cmd_sync_groups_up(engine);
    } else if (strcmp(subcmd, "sync-down") == 0) {
        return cmd_sync_groups_down(engine);
    } else if (strcmp(subcmd, "publish-gek") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group publish-gek <name|uuid>\n"); return 1; }
        return cmd_group_publish_gek(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "gek-fetch") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group gek-fetch <uuid>\n"); return 1; }
        return cmd_gek_fetch(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "invitations") == 0) {
        return cmd_invitations(engine);
    } else if (strcmp(subcmd, "invite-accept") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group invite-accept <uuid>\n"); return 1; }
        return cmd_invite_accept(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "invite-reject") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: group invite-reject <uuid>\n"); return 1; }
        return cmd_invite_reject(engine, argv[sub + 1]);
    } else {
        fprintf(stderr, "Unknown group subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- channel ---------- */
int dispatch_channel(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: channel <subcommand>\n");
        fprintf(stderr, "  channel create <name> [description]\n");
        fprintf(stderr, "  channel get <uuid>\n");
        fprintf(stderr, "  channel delete <uuid>\n");
        fprintf(stderr, "  channel discover [--days N]\n");
        fprintf(stderr, "  channel post <uuid> <body>\n");
        fprintf(stderr, "  channel posts <uuid> [--days N]\n");
        fprintf(stderr, "  channel subscribe <uuid>\n");
        fprintf(stderr, "  channel unsubscribe <uuid>\n");
        fprintf(stderr, "  channel subscriptions\n");
        fprintf(stderr, "  channel sync\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "create") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: channel create <name> [description]\n"); return 1; }
        const char *desc = (sub + 2 < argc) ? argv[sub + 2] : NULL;
        return cmd_channel_create(engine, argv[sub + 1], desc);
    } else if (strcmp(subcmd, "get") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: channel get <uuid>\n"); return 1; }
        return cmd_channel_get(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "delete") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: channel delete <uuid>\n"); return 1; }
        return cmd_channel_delete(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "discover") == 0) {
        int days = 7;
        for (int i = sub + 1; i < argc; i++) {
            if (strcmp(argv[i], "--days") == 0 && i + 1 < argc) {
                days = atoi(argv[++i]);
            }
        }
        return cmd_channel_discover(engine, days);
    } else if (strcmp(subcmd, "post") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: channel post <uuid> <body>\n"); return 1; }
        /* Concatenate remaining args as body */
        static char post_buf[4096];
        post_buf[0] = '\0';
        for (int i = sub + 2; i < argc; i++) {
            if (i > sub + 2) strncat(post_buf, " ", sizeof(post_buf) - strlen(post_buf) - 1);
            strncat(post_buf, argv[i], sizeof(post_buf) - strlen(post_buf) - 1);
        }
        return cmd_channel_post(engine, argv[sub + 1], post_buf);
    } else if (strcmp(subcmd, "posts") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: channel posts <uuid> [--days N]\n"); return 1; }
        int days = 0;
        for (int i = sub + 2; i < argc; i++) {
            if (strcmp(argv[i], "--days") == 0 && i + 1 < argc) {
                days = atoi(argv[++i]);
            }
        }
        return cmd_channel_posts(engine, argv[sub + 1], days);
    } else if (strcmp(subcmd, "subscribe") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: channel subscribe <uuid>\n"); return 1; }
        return cmd_channel_subscribe(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "unsubscribe") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: channel unsubscribe <uuid>\n"); return 1; }
        return cmd_channel_unsubscribe(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "subscriptions") == 0) {
        return cmd_channel_subscriptions(engine);
    } else if (strcmp(subcmd, "sync") == 0) {
        return cmd_channel_sync(engine);
    } else {
        fprintf(stderr, "Unknown channel subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- wallet ---------- */
int dispatch_wallet(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: wallet <subcommand>\n");
        fprintf(stderr, "  wallet list\n");
        fprintf(stderr, "  wallet balance <wallet_index>\n");
        fprintf(stderr, "  wallet send <wallet_idx> <network> <token> <to_address> <amount>\n");
        fprintf(stderr, "  wallet transactions <wallet_index>\n");
        fprintf(stderr, "  wallet estimate-gas <network_id>\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "list") == 0) {
        return cmd_wallets(engine);
    } else if (strcmp(subcmd, "balance") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: wallet balance <wallet_index>\n"); return 1; }
        return cmd_balance(engine, atoi(argv[sub + 1]));
    } else if (strcmp(subcmd, "send") == 0) {
        if (sub + 5 >= argc) { fprintf(stderr, "Usage: wallet send <wallet_idx> <network> <token> <to_address> <amount>\n"); return 1; }
        return cmd_send_tokens(engine, atoi(argv[sub + 1]), argv[sub + 2], argv[sub + 3], argv[sub + 4], argv[sub + 5]);
    } else if (strcmp(subcmd, "transactions") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: wallet transactions <wallet_index>\n"); return 1; }
        return cmd_transactions(engine, atoi(argv[sub + 1]));
    } else if (strcmp(subcmd, "estimate-gas") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: wallet estimate-gas <network_id>\n"); return 1; }
        return cmd_estimate_gas(engine, atoi(argv[sub + 1]));
    } else {
        fprintf(stderr, "Unknown wallet subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- dex ---------- */
int dispatch_dex(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: dex <subcommand>\n");
        fprintf(stderr, "  dex quote <from_token> <to_token> <amount> [dex_filter]\n");
        fprintf(stderr, "  dex pairs\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "quote") == 0) {
        if (sub + 3 >= argc) { fprintf(stderr, "Usage: dex quote <from_token> <to_token> <amount> [dex_filter]\n"); return 1; }
        const char *filter = (sub + 4 < argc) ? argv[sub + 4] : NULL;
        return cmd_dex_quote(engine, argv[sub + 1], argv[sub + 2], argv[sub + 3], filter);
    } else if (strcmp(subcmd, "pairs") == 0) {
        return cmd_dex_pairs(engine);
    } else {
        fprintf(stderr, "Unknown dex subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- network ---------- */
int dispatch_network(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: network <subcommand>\n");
        fprintf(stderr, "  network online <fp>\n");
        fprintf(stderr, "  network dht-status\n");
        fprintf(stderr, "  network pause-presence\n");
        fprintf(stderr, "  network resume-presence\n");
        fprintf(stderr, "  network refresh-presence\n");
        fprintf(stderr, "  network changed\n");
        fprintf(stderr, "  network bootstrap-registry\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "online") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: network online <fp>\n"); return 1; }
        return cmd_online(engine, argv[sub + 1]);
    } else if (strcmp(subcmd, "dht-status") == 0) {
        return cmd_dht_status(engine);
    } else if (strcmp(subcmd, "pause-presence") == 0) {
        return cmd_pause_presence(engine);
    } else if (strcmp(subcmd, "resume-presence") == 0) {
        return cmd_resume_presence(engine);
    } else if (strcmp(subcmd, "refresh-presence") == 0) {
        return cmd_refresh_presence(engine);
    } else if (strcmp(subcmd, "changed") == 0) {
        return cmd_network_changed(engine);
    } else if (strcmp(subcmd, "bootstrap-registry") == 0) {
        return cmd_bootstrap_registry(engine);
    } else {
        fprintf(stderr, "Unknown network subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- version ---------- */
int dispatch_version(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: version <subcommand>\n");
        fprintf(stderr, "  version publish --lib <ver> --app <ver> --nodus <ver>\n");
        fprintf(stderr, "                  [--lib-min <ver>] [--app-min <ver>] [--nodus-min <ver>]\n");
        fprintf(stderr, "  version check\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "publish") == 0) {
        char *lib_ver = NULL, *lib_min = NULL;
        char *app_ver = NULL, *app_min = NULL;
        char *nodus_ver = NULL, *nodus_min = NULL;
        for (int i = sub + 1; i < argc; i++) {
            if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
                lib_ver = argv[++i];
            } else if (strcmp(argv[i], "--lib-min") == 0 && i + 1 < argc) {
                lib_min = argv[++i];
            } else if (strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
                app_ver = argv[++i];
            } else if (strcmp(argv[i], "--app-min") == 0 && i + 1 < argc) {
                app_min = argv[++i];
            } else if (strcmp(argv[i], "--nodus") == 0 && i + 1 < argc) {
                nodus_ver = argv[++i];
            } else if (strcmp(argv[i], "--nodus-min") == 0 && i + 1 < argc) {
                nodus_min = argv[++i];
            }
        }
        if (!lib_ver || !app_ver || !nodus_ver) {
            fprintf(stderr, "Usage: version publish --lib <ver> --app <ver> --nodus <ver>\n");
            fprintf(stderr, "       [--lib-min <ver>] [--app-min <ver>] [--nodus-min <ver>]\n");
            return 1;
        }
        return cmd_publish_version(engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min);
    } else if (strcmp(subcmd, "check") == 0) {
        return cmd_check_version(engine);
    } else {
        fprintf(stderr, "Unknown version subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- sign ---------- */
int dispatch_sign(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: sign <subcommand>\n");
        fprintf(stderr, "  sign data <data...>\n");
        fprintf(stderr, "  sign pubkey\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "data") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: sign data <data...>\n"); return 1; }
        /* Concatenate remaining args as data */
        static char sign_buf[4096];
        sign_buf[0] = '\0';
        for (int i = sub + 1; i < argc; i++) {
            if (i > sub + 1) strncat(sign_buf, " ", sizeof(sign_buf) - strlen(sign_buf) - 1);
            strncat(sign_buf, argv[i], sizeof(sign_buf) - strlen(sign_buf) - 1);
        }
        return cmd_sign(engine, sign_buf);
    } else if (strcmp(subcmd, "pubkey") == 0) {
        return cmd_signing_pubkey(engine);
    } else {
        fprintf(stderr, "Unknown sign subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- debug ---------- */
int dispatch_debug(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc || strcmp(argv[sub], "help") == 0) {
        fprintf(stderr, "Usage: debug <subcommand>\n");
        fprintf(stderr, "  debug log-level [level]\n");
        fprintf(stderr, "  debug log-tags [tags]\n");
        fprintf(stderr, "  debug log <on|off>\n");
        fprintf(stderr, "  debug entries [max_entries]\n");
        fprintf(stderr, "  debug count\n");
        fprintf(stderr, "  debug clear\n");
        fprintf(stderr, "  debug export <filepath>\n");
        return 1;
    }
    const char *subcmd = argv[sub];
    if (strcmp(subcmd, "log-level") == 0) {
        const char *level = (sub + 1 < argc) ? argv[sub + 1] : NULL;
        return cmd_log_level(engine, level);
    } else if (strcmp(subcmd, "log-tags") == 0) {
        const char *tags = (sub + 1 < argc) ? argv[sub + 1] : NULL;
        return cmd_log_tags(engine, tags);
    } else if (strcmp(subcmd, "log") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: debug log <on|off>\n"); return 1; }
        bool enable = (strcmp(argv[sub + 1], "on") == 0);
        return cmd_debug_log(engine, enable);
    } else if (strcmp(subcmd, "entries") == 0) {
        int n = (sub + 1 < argc) ? atoi(argv[sub + 1]) : 50;
        return cmd_debug_entries(engine, n);
    } else if (strcmp(subcmd, "count") == 0) {
        return cmd_debug_count(engine);
    } else if (strcmp(subcmd, "clear") == 0) {
        return cmd_debug_clear(engine);
    } else if (strcmp(subcmd, "export") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: debug export <filepath>\n"); return 1; }
        return cmd_debug_export(engine, argv[sub + 1]);
    } else {
        fprintf(stderr, "Unknown debug subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ============================================================================
 * GROUP DISPATCHERS — REPL-based (for execute_command)
 * ============================================================================ */

/* ---------- identity (REPL) ---------- */
int dispatch_identity_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: identity <subcommand>\n");
        fprintf(stderr, "  create | restore | delete | list | load | whoami | change-password\n");
        fprintf(stderr, "  register | name | lookup | lookup-profile | profile\n");
        fprintf(stderr, "  set-nickname | get-avatar | get-mnemonic | refresh-profile\n");
        return 1;
    }
    if (strcmp(subcmd, "create") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) { fprintf(stderr, "Usage: identity create <name>\n"); return 1; }
        return cmd_create(engine, name);
    } else if (strcmp(subcmd, "restore") == 0) {
        char *mnemonic = strtok(NULL, "");
        if (!mnemonic) { fprintf(stderr, "Usage: identity restore <mnemonic...>\n"); return 1; }
        return cmd_restore(engine, mnemonic);
    } else if (strcmp(subcmd, "delete") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: identity delete <fingerprint>\n"); return 1; }
        return cmd_delete(engine, fp);
    } else if (strcmp(subcmd, "list") == 0) {
        return cmd_list(engine);
    } else if (strcmp(subcmd, "load") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: identity load <fingerprint>\n"); return 1; }
        return cmd_load(engine, fp);
    } else if (strcmp(subcmd, "whoami") == 0) {
        cmd_whoami(engine); return 0;
    } else if (strcmp(subcmd, "change-password") == 0) {
        cmd_change_password(engine); return 0;
    } else if (strcmp(subcmd, "register") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) { fprintf(stderr, "Usage: identity register <name>\n"); return 1; }
        return cmd_register(engine, name);
    } else if (strcmp(subcmd, "name") == 0) {
        return cmd_name(engine);
    } else if (strcmp(subcmd, "lookup") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) { fprintf(stderr, "Usage: identity lookup <name>\n"); return 1; }
        return cmd_lookup(engine, name);
    } else if (strcmp(subcmd, "lookup-profile") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: identity lookup-profile <name|fp>\n"); return 1; }
        return cmd_lookup_profile(engine, id);
    } else if (strcmp(subcmd, "profile") == 0) {
        char *arg = strtok(NULL, " \t");
        if (!arg) {
            return cmd_profile(engine, NULL, NULL);
        }
        char *eq = strchr(arg, '=');
        if (!eq) { fprintf(stderr, "Usage: identity profile [field=value]\n"); return 1; }
        *eq = '\0';
        return cmd_profile(engine, arg, eq + 1);
    } else if (strcmp(subcmd, "set-nickname") == 0) {
        char *fp = strtok(NULL, " \t");
        char *nick = strtok(NULL, " \t");
        if (!fp || !nick) { fprintf(stderr, "Usage: identity set-nickname <fp> <nickname>\n"); return 1; }
        return cmd_set_nickname(engine, fp, nick);
    } else if (strcmp(subcmd, "get-avatar") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: identity get-avatar <fp>\n"); return 1; }
        return cmd_get_avatar(engine, fp);
    } else if (strcmp(subcmd, "get-mnemonic") == 0) {
        return cmd_get_mnemonic(engine);
    } else if (strcmp(subcmd, "refresh-profile") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: identity refresh-profile <fp>\n"); return 1; }
        return cmd_refresh_profile(engine, fp);
    } else {
        fprintf(stderr, "Unknown identity subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- contact (REPL) ---------- */
int dispatch_contact_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: contact <subcommand>\n");
        fprintf(stderr, "  list | add | remove | request | requests | request-count\n");
        fprintf(stderr, "  approve | deny | block | unblock | blocked | is-blocked\n");
        fprintf(stderr, "  check-inbox | sync-up | sync-down\n");
        return 1;
    }
    if (strcmp(subcmd, "list") == 0) {
        return cmd_contacts(engine);
    } else if (strcmp(subcmd, "add") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: contact add <name|fp>\n"); return 1; }
        return cmd_add_contact(engine, id);
    } else if (strcmp(subcmd, "remove") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: contact remove <fp>\n"); return 1; }
        return cmd_remove_contact(engine, fp);
    } else if (strcmp(subcmd, "request") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: contact request <fp> [message]\n"); return 1; }
        char *msg = strtok(NULL, "");
        return cmd_request(engine, fp, msg);
    } else if (strcmp(subcmd, "requests") == 0) {
        return cmd_requests(engine);
    } else if (strcmp(subcmd, "request-count") == 0) {
        return cmd_request_count(engine);
    } else if (strcmp(subcmd, "approve") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: contact approve <fp>\n"); return 1; }
        return cmd_approve(engine, fp);
    } else if (strcmp(subcmd, "deny") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: contact deny <fp>\n"); return 1; }
        return cmd_deny(engine, fp);
    } else if (strcmp(subcmd, "block") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: contact block <name|fp>\n"); return 1; }
        return cmd_block(engine, id);
    } else if (strcmp(subcmd, "unblock") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: contact unblock <fp>\n"); return 1; }
        return cmd_unblock(engine, fp);
    } else if (strcmp(subcmd, "blocked") == 0) {
        return cmd_blocked(engine);
    } else if (strcmp(subcmd, "is-blocked") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: contact is-blocked <fp>\n"); return 1; }
        return cmd_is_blocked(engine, fp);
    } else if (strcmp(subcmd, "check-inbox") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: contact check-inbox <name|fp>\n"); return 1; }
        return cmd_check_inbox(engine, id);
    } else if (strcmp(subcmd, "sync-up") == 0) {
        return cmd_sync_contacts_up(engine);
    } else if (strcmp(subcmd, "sync-down") == 0) {
        return cmd_sync_contacts_down(engine);
    } else {
        fprintf(stderr, "Unknown contact subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- message (REPL) ---------- */
int dispatch_message_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: message <subcommand>\n");
        fprintf(stderr, "  send | list | page | delete | mark-read | unread\n");
        fprintf(stderr, "  check-offline | listen | queue-status | queue-send\n");
        fprintf(stderr, "  queue-capacity | retry-pending | retry-message | backup | restore\n");
        return 1;
    }
    if (strcmp(subcmd, "send") == 0) {
        char *recipient = strtok(NULL, " \t");
        if (!recipient) { fprintf(stderr, "Usage: message send <recipient> <message...>\n"); return 1; }
        char *msg = strtok(NULL, "");
        if (!msg) { fprintf(stderr, "Usage: message send <recipient> <message...>\n"); return 1; }
        return cmd_send(engine, recipient, msg);
    } else if (strcmp(subcmd, "list") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: message list <fp>\n"); return 1; }
        return cmd_messages(engine, fp);
    } else if (strcmp(subcmd, "page") == 0) {
        char *fp = strtok(NULL, " \t");
        char *lim = strtok(NULL, " \t");
        char *off = strtok(NULL, " \t");
        if (!fp || !lim || !off) { fprintf(stderr, "Usage: message page <fp> <limit> <offset>\n"); return 1; }
        return cmd_messages_page(engine, fp, atoi(lim), atoi(off));
    } else if (strcmp(subcmd, "delete") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: message delete <message_id>\n"); return 1; }
        return cmd_delete_message(engine, strtoll(id, NULL, 10));
    } else if (strcmp(subcmd, "mark-read") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: message mark-read <name|fp>\n"); return 1; }
        return cmd_mark_read(engine, id);
    } else if (strcmp(subcmd, "unread") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: message unread <name|fp>\n"); return 1; }
        return cmd_unread(engine, id);
    } else if (strcmp(subcmd, "check-offline") == 0) {
        return cmd_check_offline(engine);
    } else if (strcmp(subcmd, "listen") == 0) {
        return cmd_listen(engine);
    } else if (strcmp(subcmd, "queue-status") == 0) {
        return cmd_queue_status(engine);
    } else if (strcmp(subcmd, "queue-send") == 0) {
        char *recipient = strtok(NULL, " \t");
        if (!recipient) { fprintf(stderr, "Usage: message queue-send <recipient> <message...>\n"); return 1; }
        char *msg = strtok(NULL, "");
        if (!msg) { fprintf(stderr, "Usage: message queue-send <recipient> <message...>\n"); return 1; }
        return cmd_queue_send(engine, recipient, msg);
    } else if (strcmp(subcmd, "queue-capacity") == 0) {
        char *n = strtok(NULL, " \t");
        if (!n) { fprintf(stderr, "Usage: message queue-capacity <n>\n"); return 1; }
        return cmd_set_queue_capacity(engine, atoi(n));
    } else if (strcmp(subcmd, "retry-pending") == 0) {
        return cmd_retry_pending(engine);
    } else if (strcmp(subcmd, "retry-message") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: message retry-message <message_id>\n"); return 1; }
        return cmd_retry_message(engine, strtoll(id, NULL, 10));
    } else if (strcmp(subcmd, "backup") == 0) {
        return cmd_backup_messages(engine);
    } else if (strcmp(subcmd, "restore") == 0) {
        return cmd_restore_messages(engine);
    } else {
        fprintf(stderr, "Unknown message subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- group (REPL) ---------- */
int dispatch_group_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: group <subcommand>\n");
        fprintf(stderr, "  list | create | send | info | members | invite | messages\n");
        fprintf(stderr, "  sync | sync-all | sync-up | sync-down | publish-gek | gek-fetch\n");
        fprintf(stderr, "  invitations | invite-accept | invite-reject\n");
        return 1;
    }
    if (strcmp(subcmd, "list") == 0) {
        return cmd_group_list(engine);
    } else if (strcmp(subcmd, "create") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) { fprintf(stderr, "Usage: group create <name>\n"); return 1; }
        return cmd_group_create(engine, name);
    } else if (strcmp(subcmd, "send") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group send <uuid> <message...>\n"); return 1; }
        char *msg = strtok(NULL, "");
        if (!msg) { fprintf(stderr, "Usage: group send <uuid> <message...>\n"); return 1; }
        return cmd_group_send(engine, uuid, msg);
    } else if (strcmp(subcmd, "info") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group info <uuid>\n"); return 1; }
        return cmd_group_info(engine, uuid);
    } else if (strcmp(subcmd, "members") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group members <uuid>\n"); return 1; }
        return cmd_group_members(engine, uuid);
    } else if (strcmp(subcmd, "invite") == 0) {
        char *uuid = strtok(NULL, " \t");
        char *fp = strtok(NULL, " \t");
        if (!uuid || !fp) { fprintf(stderr, "Usage: group invite <uuid> <fp>\n"); return 1; }
        return cmd_group_invite(engine, uuid, fp);
    } else if (strcmp(subcmd, "messages") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: group messages <name|uuid>\n"); return 1; }
        return cmd_group_messages(engine, id);
    } else if (strcmp(subcmd, "sync") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group sync <uuid>\n"); return 1; }
        return cmd_group_sync(engine, uuid);
    } else if (strcmp(subcmd, "sync-all") == 0) {
        return cmd_sync_groups(engine);
    } else if (strcmp(subcmd, "sync-up") == 0) {
        return cmd_sync_groups_up(engine);
    } else if (strcmp(subcmd, "sync-down") == 0) {
        return cmd_sync_groups_down(engine);
    } else if (strcmp(subcmd, "publish-gek") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: group publish-gek <name|uuid>\n"); return 1; }
        return cmd_group_publish_gek(engine, id);
    } else if (strcmp(subcmd, "gek-fetch") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group gek-fetch <uuid>\n"); return 1; }
        return cmd_gek_fetch(engine, uuid);
    } else if (strcmp(subcmd, "invitations") == 0) {
        return cmd_invitations(engine);
    } else if (strcmp(subcmd, "invite-accept") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group invite-accept <uuid>\n"); return 1; }
        return cmd_invite_accept(engine, uuid);
    } else if (strcmp(subcmd, "invite-reject") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: group invite-reject <uuid>\n"); return 1; }
        return cmd_invite_reject(engine, uuid);
    } else {
        fprintf(stderr, "Unknown group subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- channel (REPL) ---------- */
int dispatch_channel_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: channel <subcommand>\n");
        fprintf(stderr, "  create | get | delete | discover | post | posts\n");
        fprintf(stderr, "  subscribe | unsubscribe | subscriptions | sync\n");
        return 1;
    }
    if (strcmp(subcmd, "create") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) { fprintf(stderr, "Usage: channel create <name> [description]\n"); return 1; }
        char *desc = strtok(NULL, "");
        return cmd_channel_create(engine, name, desc);
    } else if (strcmp(subcmd, "get") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: channel get <uuid>\n"); return 1; }
        return cmd_channel_get(engine, uuid);
    } else if (strcmp(subcmd, "delete") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: channel delete <uuid>\n"); return 1; }
        return cmd_channel_delete(engine, uuid);
    } else if (strcmp(subcmd, "discover") == 0) {
        int days = 7;
        char *arg = strtok(NULL, " \t");
        while (arg) {
            if (strcmp(arg, "--days") == 0) {
                char *val = strtok(NULL, " \t");
                if (val) days = atoi(val);
            }
            arg = strtok(NULL, " \t");
        }
        return cmd_channel_discover(engine, days);
    } else if (strcmp(subcmd, "post") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: channel post <uuid> <body>\n"); return 1; }
        char *body = strtok(NULL, "");
        if (!body) { fprintf(stderr, "Usage: channel post <uuid> <body>\n"); return 1; }
        return cmd_channel_post(engine, uuid, body);
    } else if (strcmp(subcmd, "posts") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: channel posts <uuid> [--days N]\n"); return 1; }
        int days = 0;
        char *arg = strtok(NULL, " \t");
        while (arg) {
            if (strcmp(arg, "--days") == 0) {
                char *val = strtok(NULL, " \t");
                if (val) days = atoi(val);
            }
            arg = strtok(NULL, " \t");
        }
        return cmd_channel_posts(engine, uuid, days);
    } else if (strcmp(subcmd, "subscribe") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: channel subscribe <uuid>\n"); return 1; }
        return cmd_channel_subscribe(engine, uuid);
    } else if (strcmp(subcmd, "unsubscribe") == 0) {
        char *uuid = strtok(NULL, " \t");
        if (!uuid) { fprintf(stderr, "Usage: channel unsubscribe <uuid>\n"); return 1; }
        return cmd_channel_unsubscribe(engine, uuid);
    } else if (strcmp(subcmd, "subscriptions") == 0) {
        return cmd_channel_subscriptions(engine);
    } else if (strcmp(subcmd, "sync") == 0) {
        return cmd_channel_sync(engine);
    } else {
        fprintf(stderr, "Unknown channel subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- wallet (REPL) ---------- */
int dispatch_wallet_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: wallet <subcommand>\n");
        fprintf(stderr, "  list | balance | send | transactions | estimate-gas\n");
        return 1;
    }
    if (strcmp(subcmd, "list") == 0) {
        return cmd_wallets(engine);
    } else if (strcmp(subcmd, "balance") == 0) {
        char *idx = strtok(NULL, " \t");
        if (!idx) { fprintf(stderr, "Usage: wallet balance <wallet_index>\n"); return 1; }
        return cmd_balance(engine, atoi(idx));
    } else if (strcmp(subcmd, "send") == 0) {
        char *idx = strtok(NULL, " \t");
        char *net = strtok(NULL, " \t");
        char *tok = strtok(NULL, " \t");
        char *to = strtok(NULL, " \t");
        char *amt = strtok(NULL, " \t");
        if (!idx || !net || !tok || !to || !amt) {
            fprintf(stderr, "Usage: wallet send <wallet_idx> <network> <token> <to_address> <amount>\n");
            return 1;
        }
        return cmd_send_tokens(engine, atoi(idx), net, tok, to, amt);
    } else if (strcmp(subcmd, "transactions") == 0) {
        char *idx = strtok(NULL, " \t");
        if (!idx) { fprintf(stderr, "Usage: wallet transactions <wallet_index>\n"); return 1; }
        return cmd_transactions(engine, atoi(idx));
    } else if (strcmp(subcmd, "estimate-gas") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) { fprintf(stderr, "Usage: wallet estimate-gas <network_id>\n"); return 1; }
        return cmd_estimate_gas(engine, atoi(id));
    } else {
        fprintf(stderr, "Unknown wallet subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- dex (REPL) ---------- */
int dispatch_dex_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: dex <subcommand>\n");
        fprintf(stderr, "  quote | pairs\n");
        return 1;
    }
    if (strcmp(subcmd, "quote") == 0) {
        char *from = strtok(NULL, " \t");
        char *to = strtok(NULL, " \t");
        char *amt = strtok(NULL, " \t");
        if (!from || !to || !amt) {
            fprintf(stderr, "Usage: dex quote <from_token> <to_token> <amount> [dex_filter]\n");
            return 1;
        }
        char *filter = strtok(NULL, " \t");
        return cmd_dex_quote(engine, from, to, amt, filter);
    } else if (strcmp(subcmd, "pairs") == 0) {
        return cmd_dex_pairs(engine);
    } else {
        fprintf(stderr, "Unknown dex subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- network (REPL) ---------- */
int dispatch_network_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: network <subcommand>\n");
        fprintf(stderr, "  online | dht-status | pause-presence | resume-presence\n");
        fprintf(stderr, "  refresh-presence | changed | bootstrap-registry\n");
        return 1;
    }
    if (strcmp(subcmd, "online") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) { fprintf(stderr, "Usage: network online <fp>\n"); return 1; }
        return cmd_online(engine, fp);
    } else if (strcmp(subcmd, "dht-status") == 0) {
        return cmd_dht_status(engine);
    } else if (strcmp(subcmd, "pause-presence") == 0) {
        return cmd_pause_presence(engine);
    } else if (strcmp(subcmd, "resume-presence") == 0) {
        return cmd_resume_presence(engine);
    } else if (strcmp(subcmd, "refresh-presence") == 0) {
        return cmd_refresh_presence(engine);
    } else if (strcmp(subcmd, "changed") == 0) {
        return cmd_network_changed(engine);
    } else if (strcmp(subcmd, "bootstrap-registry") == 0) {
        return cmd_bootstrap_registry(engine);
    } else {
        fprintf(stderr, "Unknown network subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- version (REPL) ---------- */
int dispatch_version_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: version <subcommand>\n");
        fprintf(stderr, "  publish --lib <ver> --app <ver> --nodus <ver> [--lib-min ...] [--app-min ...] [--nodus-min ...]\n");
        fprintf(stderr, "  check\n");
        return 1;
    }
    if (strcmp(subcmd, "publish") == 0) {
        char *lib_ver = NULL, *lib_min = NULL;
        char *app_ver = NULL, *app_min = NULL;
        char *nodus_ver = NULL, *nodus_min = NULL;
        char *arg = strtok(NULL, " \t");
        while (arg) {
            if (strcmp(arg, "--lib") == 0) {
                lib_ver = strtok(NULL, " \t");
            } else if (strcmp(arg, "--lib-min") == 0) {
                lib_min = strtok(NULL, " \t");
            } else if (strcmp(arg, "--app") == 0) {
                app_ver = strtok(NULL, " \t");
            } else if (strcmp(arg, "--app-min") == 0) {
                app_min = strtok(NULL, " \t");
            } else if (strcmp(arg, "--nodus") == 0) {
                nodus_ver = strtok(NULL, " \t");
            } else if (strcmp(arg, "--nodus-min") == 0) {
                nodus_min = strtok(NULL, " \t");
            }
            arg = strtok(NULL, " \t");
        }
        if (!lib_ver || !app_ver || !nodus_ver) {
            fprintf(stderr, "Usage: version publish --lib <ver> --app <ver> --nodus <ver>\n");
            fprintf(stderr, "       [--lib-min <ver>] [--app-min <ver>] [--nodus-min <ver>]\n");
            return 1;
        }
        return cmd_publish_version(engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min);
    } else if (strcmp(subcmd, "check") == 0) {
        return cmd_check_version(engine);
    } else {
        fprintf(stderr, "Unknown version subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- sign (REPL) ---------- */
int dispatch_sign_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: sign <subcommand>\n");
        fprintf(stderr, "  data <data...> | pubkey\n");
        return 1;
    }
    if (strcmp(subcmd, "data") == 0) {
        char *data = strtok(NULL, "");
        if (!data) { fprintf(stderr, "Usage: sign data <data...>\n"); return 1; }
        return cmd_sign(engine, data);
    } else if (strcmp(subcmd, "pubkey") == 0) {
        return cmd_signing_pubkey(engine);
    } else {
        fprintf(stderr, "Unknown sign subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ---------- debug (REPL) ---------- */
int dispatch_debug_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd || strcmp(subcmd, "help") == 0) {
        fprintf(stderr, "Usage: debug <subcommand>\n");
        fprintf(stderr, "  log-level | log-tags | log | entries | count | clear | export\n");
        return 1;
    }
    if (strcmp(subcmd, "log-level") == 0) {
        char *level = strtok(NULL, " \t");
        return cmd_log_level(engine, level);
    } else if (strcmp(subcmd, "log-tags") == 0) {
        char *tags = strtok(NULL, " \t");
        return cmd_log_tags(engine, tags);
    } else if (strcmp(subcmd, "log") == 0) {
        char *arg = strtok(NULL, " \t");
        if (!arg) { fprintf(stderr, "Usage: debug log <on|off>\n"); return 1; }
        bool enable = (strcmp(arg, "on") == 0);
        return cmd_debug_log(engine, enable);
    } else if (strcmp(subcmd, "entries") == 0) {
        char *n = strtok(NULL, " \t");
        int max_entries = n ? atoi(n) : 50;
        return cmd_debug_entries(engine, max_entries);
    } else if (strcmp(subcmd, "count") == 0) {
        return cmd_debug_count(engine);
    } else if (strcmp(subcmd, "clear") == 0) {
        return cmd_debug_clear(engine);
    } else if (strcmp(subcmd, "export") == 0) {
        char *filepath = strtok(NULL, " \t");
        if (!filepath) { fprintf(stderr, "Usage: debug export <filepath>\n"); return 1; }
        return cmd_debug_export(engine, filepath);
    } else {
        fprintf(stderr, "Unknown debug subcommand: %s\n", subcmd);
        return 1;
    }
}

/* ============================================================================
 * COMMAND PARSER
 * ============================================================================ */

static char *trim(char *str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

bool execute_command(dna_engine_t *engine, const char *line) {
    if (!line) return true;

    char *input = strdup(line);
    if (!input) return true;

    char *trimmed = trim(input);

    if (strlen(trimmed) == 0) {
        free(input);
        return true;
    }

    char *cmd = strtok(trimmed, " \t");
    if (!cmd) {
        free(input);
        return true;
    }

    for (char *p = cmd; *p; p++) {
        *p = tolower((unsigned char)*p);
    }

    /* Dispatch to group */
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        cmd_help();
    }
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) {
        free(input);
        return false;
    }
    else if (strcmp(cmd, "identity") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_identity_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "contact") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_contact_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "message") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_message_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "group") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_group_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "channel") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_channel_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "wallet") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_wallet_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "dex") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_dex_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "network") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_network_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "version") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_version_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "sign") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_sign_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "debug") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_debug_repl(engine, subcmd);
    }
    else {
        printf("Unknown command group: %s\n", cmd);
        printf("Type 'help' for available groups.\n");
    }

    free(input);
    return true;
}
