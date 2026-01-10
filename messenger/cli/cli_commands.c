/*
 * DNA Messenger CLI - Command Implementation
 *
 * Interactive CLI tool for testing DNA Messenger without GUI.
 */

#include "cli_commands.h"
#include "bip39.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "dht/core/dht_keyserver.h"
#include "dht/client/dht_singleton.h"
#include "p2p/transport/transport_core.h"
#include "p2p/transport/transport_ice.h"
#include "p2p/transport/turn_credentials.h"
#include "messenger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#define LOG_TAG "CLI"

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
    printf("\nDNA Messenger CLI Commands:\n\n");

    printf("IDENTITY:\n");
    printf("  create <name>              - Create new identity (generates BIP39 mnemonic)\n");
    printf("  restore <mnemonic...>      - Restore identity from 24-word mnemonic\n");
    printf("  delete <fingerprint>       - Delete an identity permanently\n");
    printf("  list                       - List all available identities\n");
    printf("  load <fingerprint>         - Load an identity (can use prefix)\n");
    printf("  whoami                     - Show current identity\n");
    printf("  change-password            - Change password for current identity\n");
    printf("  register <name>            - Register a name on DHT\n");
    printf("  name                       - Show registered name\n");
    printf("  lookup <name>              - Check if name is available\n");
    printf("  lookup-profile <name|fp>   - View any user's DHT profile\n");
    printf("  profile [field=value]      - Show or update profile\n");
    printf("\n");

    printf("CONTACTS:\n");
    printf("  contacts                   - List all contacts\n");
    printf("  add-contact <name|fp>      - Add contact by name or fingerprint\n");
    printf("  remove-contact <fp>        - Remove a contact\n");
    printf("  request <fp> [message]     - Send contact request\n");
    printf("  requests                   - List pending contact requests\n");
    printf("  approve <fp>               - Approve a contact request\n");
    printf("\n");

    printf("MESSAGING:\n");
    printf("  send <fp> <message>        - Send message to recipient\n");
    printf("  messages <fp>              - Show conversation with contact\n");
    printf("  check-offline              - Check for offline messages\n");
    printf("  listen                     - Subscribe to contacts' outboxes (stay running)\n");
    printf("\n");

    printf("WALLET:\n");
    printf("  wallets                    - List wallets\n");
    printf("  balance <index>            - Show wallet balances\n");
    printf("\n");

    printf("NETWORK:\n");
    printf("  online <fp>                - Check if peer is online\n");
    printf("\n");

    printf("NAT TRAVERSAL:\n");
    printf("  stun-test                  - Test STUN connectivity\n");
    printf("  ice-status                 - Show ICE connection status\n");
    printf("  turn-creds [--force]       - Show/request TURN credentials\n");
    printf("  turn-test                  - Test TURN relay with all servers\n");
    printf("\n");

    printf("VERSION:\n");
    printf("  publish-version            - Publish version info to DHT\n");
    printf("    --lib <ver> --lib-min <ver> --app <ver> --app-min <ver> --nodus <ver> --nodus-min <ver>\n");
    printf("  check-version              - Check latest version from DHT\n");
    printf("\n");

    printf("OTHER:\n");
    printf("  help                       - Show this help message\n");
    printf("  quit / exit                - Exit the CLI\n");
    printf("\n");
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
        if (strlen(wait.profile->display_name) > 0)
            printf("  Name:     %s\n", wait.profile->display_name);
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

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        printf("Error: DHT not initialized\n");
        return -1;
    }

    printf("Looking up profile for '%s'...\n", identifier);

    /* Lookup identity from DHT (handles both name and fingerprint) */
    dna_unified_identity_t *identity = NULL;
    int ret = dht_keyserver_lookup(dht, identifier, &identity);

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
            printf("     Status: %s\n", wait.contacts[i].is_online ? "ONLINE" : "offline");
        }
        free(wait.contacts);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

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
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));

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
 * NAT TRAVERSAL COMMANDS (STUN/ICE/TURN)
 * ============================================================================ */

int cmd_stun_test(void) {
    printf("Testing STUN connectivity...\n");
    printf("========================================\n");

    // Test multiple STUN servers
    const char *stun_servers[] = {
        "stun.l.google.com",
        "stun1.l.google.com",
        "stun.cloudflare.com"
    };
    const uint16_t stun_ports[] = {19302, 19302, 3478};
    const int num_servers = 3;

    char public_ip[64] = {0};
    int success = 0;

    // Try stun_get_public_ip first (uses internal implementation)
    if (stun_get_public_ip(public_ip, sizeof(public_ip)) == 0) {
        printf("✓ STUN Test PASSED\n");
        printf("  Public IP: %s\n", public_ip);
        success = 1;
    } else {
        printf("✗ STUN Test FAILED\n");
        printf("  Could not discover public IP via STUN\n");
    }

    printf("========================================\n");
    printf("\nSTUN Servers Tested:\n");
    for (int i = 0; i < num_servers; i++) {
        printf("  %d. %s:%d\n", i + 1, stun_servers[i], stun_ports[i]);
    }

    if (success) {
        printf("\nNAT Type: Likely Open/Full Cone (direct P2P possible)\n");
    } else {
        printf("\nNAT Type: Unknown (may need TURN relay)\n");
    }

    return success ? 0 : -1;
}

int cmd_ice_status(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("ICE Connection Status\n");
    printf("========================================\n");

    // Get messenger context from engine
    messenger_context_t *messenger = (messenger_context_t *)dna_engine_get_messenger_context(engine);
    if (!messenger) {
        printf("Messenger: NOT INITIALIZED\n");
        return -1;
    }

    // Get P2P transport from messenger
    p2p_transport_t *transport = messenger->p2p_transport;
    if (!transport) {
        printf("P2P Transport: NOT INITIALIZED\n");
        printf("  (Start P2P with identity load)\n");
        return -1;
    }

    printf("P2P Transport: ACTIVE\n");
    printf("  Listen Port: 4001 (TCP)\n");

    // Check ICE readiness
    if (transport->ice_ready) {
        printf("  ICE Status: READY\n");

        // Get local candidates if available
        if (transport->ice_context) {
            const char *local_cands = ice_get_local_candidates(transport->ice_context);
            if (local_cands && strlen(local_cands) > 0) {
                printf("\nLocal ICE Candidates:\n");
                // Parse and display candidates
                char *cands_copy = strdup(local_cands);
                char *line = strtok(cands_copy, "\n");
                int count = 0;
                while (line && count < 10) {
                    if (strlen(line) > 0) {
                        // Extract type from candidate line
                        if (strstr(line, "typ host")) {
                            printf("  [HOST]  %s\n", line);
                        } else if (strstr(line, "typ srflx")) {
                            printf("  [SRFLX] %s\n", line);
                        } else if (strstr(line, "typ relay")) {
                            printf("  [RELAY] %s\n", line);
                        } else {
                            printf("  %s\n", line);
                        }
                        count++;
                    }
                    line = strtok(NULL, "\n");
                }
                free(cands_copy);
                printf("  (Total: %d candidates)\n", count);
            } else {
                printf("\nLocal ICE Candidates: None gathered\n");
            }
        }
    } else {
        printf("  ICE Status: NOT READY\n");
        printf("  (ICE initializes on first P2P connection attempt)\n");
    }

    // Show active connections
    printf("\nActive Connections: %zu\n", transport->connection_count);
    if (transport->connection_count > 0) {
        pthread_mutex_lock(&transport->connections_mutex);
        for (size_t i = 0; i < transport->connection_count && i < 10; i++) {
            p2p_connection_t *conn = transport->connections[i];
            if (conn && conn->active) {
                const char *type = (conn->type == CONNECTION_TYPE_ICE) ? "ICE" : "TCP";
                printf("  %zu. [%s] %.16s...\n", i + 1, type, conn->peer_fingerprint);
            }
        }
        pthread_mutex_unlock(&transport->connections_mutex);
    }

    printf("========================================\n");
    return 0;
}

int cmd_turn_creds(dna_engine_t *engine, bool force_request) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("TURN Credentials\n");
    printf("========================================\n");

    // Get identity fingerprint from engine
    const char *fingerprint = dna_engine_get_fingerprint(engine);

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    printf("Identity: %.16s...\n\n", fingerprint);

    // Initialize TURN credential system if needed
    turn_credentials_init();

    turn_credentials_t creds;
    memset(&creds, 0, sizeof(creds));

    if (force_request) {
        printf("Requesting TURN credentials from DNA Nodus...\n");

        int result = dna_engine_request_turn_credentials(engine, 10000);
        if (result != 0) {
            printf("✗ Failed to obtain TURN credentials\n");
            printf("  (Bootstrap servers may be unreachable)\n");
            return -1;
        }

        printf("✓ Credentials obtained!\n\n");
    }

    // Show cached credentials
    if (turn_credentials_get_cached(fingerprint, &creds) != 0) {
        printf("No cached credentials found.\n");
        printf("\nUse 'turn-creds --force' to request credentials from DNA Nodus.\n");
        printf("\nTURN credentials are also obtained automatically when:\n");
        printf("  1. ICE direct connection fails\n");
        printf("  2. STUN-only candidates are insufficient\n");
        printf("  3. Symmetric NAT requires relay\n");
        return 0;
    }

    printf("Cached credentials:\n\n");

    // Display credentials
    printf("TURN Servers (%zu):\n", creds.server_count);
    for (size_t i = 0; i < creds.server_count; i++) {
        turn_server_info_t *srv = &creds.servers[i];
        printf("  %zu. %s:%d\n", i + 1, srv->host, srv->port);
        printf("     Username: %s\n", srv->username);
        printf("     Password: %s\n", srv->password);

        // Calculate expiry
        time_t now = time(NULL);
        if (srv->expires_at > now) {
            int hours_left = (int)((srv->expires_at - now) / 3600);
            int days_left = hours_left / 24;
            if (days_left > 0) {
                printf("     Expires:  %d days, %d hours\n", days_left, hours_left % 24);
            } else {
                printf("     Expires:  %d hours\n", hours_left);
            }
        } else {
            printf("     Expires:  EXPIRED\n");
        }
    }

    printf("========================================\n");
    return 0;
}

int cmd_turn_test(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: No identity loaded.\n");
        return -1;
    }

    printf("\nTURN Relay Test\n");
    printf("========================================\n");

    // Get identity fingerprint
    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp || strlen(fp) == 0) {
        printf("Error: No identity loaded.\n");
        return -1;
    }
    printf("Identity: %.16s...\n\n", fp);

    // Get list of TURN servers
    const char *servers[4];
    int num_servers = turn_credentials_get_server_list(servers, 4);
    if (num_servers == 0) {
        printf("Error: No TURN servers configured.\n");
        return -1;
    }

    printf("Testing %d TURN servers...\n\n", num_servers);

    int success_count = 0;

    for (int i = 0; i < num_servers; i++) {
        const char *server_ip = servers[i];
        printf("[%d/%d] %s\n", i + 1, num_servers, server_ip);

        // Check for cached credentials first
        turn_server_info_t creds;
        int have_creds = (turn_credentials_get_for_server(server_ip, &creds) == 0);

        if (have_creds) {
            printf("      Cached credentials: %s\n", creds.username);
        } else {
            // Request credentials
            printf("      Requesting credentials...\n");
            int ret = dna_engine_request_turn_credentials(engine, 5000);
            if (ret == 0) {
                have_creds = (turn_credentials_get_for_server(server_ip, &creds) == 0);
                if (have_creds) {
                    printf("      ✓ Got credentials: %s\n", creds.username);
                }
            }
        }

        if (have_creds) {
            // Show credential status
            time_t now = time(NULL);
            if (creds.expires_at > now) {
                int hours_left = (int)((creds.expires_at - now) / 3600);
                printf("      Expires: %d hours\n", hours_left);
                printf("      Status: ✓ READY\n");
                success_count++;
            } else {
                printf("      Status: ✗ EXPIRED\n");
            }
        } else {
            printf("      Status: ✗ NO CREDENTIALS\n");
        }
        printf("\n");
    }

    printf("========================================\n");
    printf("Result: %d/%d servers ready for TURN relay\n", success_count, num_servers);

    if (success_count == 0) {
        printf("\n⚠ No TURN servers available. ICE will use STUN-only.\n");
        printf("  TURN servers may need to be deployed with signature verification.\n");
    } else if (success_count < num_servers) {
        printf("\n⚠ Some TURN servers unavailable. Failover will use available servers.\n");
    } else {
        printf("\n✓ All TURN servers ready. Full NAT traversal capability available.\n");
    }

    return (success_count > 0) ? 0 : -1;
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
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M UTC", gmtime(&ts));
        printf("  Published: %s\n", time_str);
    }

    if (strlen(result.info.publisher) > 0) {
        printf("  Publisher: %.16s...\n", result.info.publisher);
    }

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

int cmd_group_send(dna_engine_t *engine, const char *group_uuid, const char *message) {
    if (!engine || !group_uuid || !message) {
        printf("Error: Missing arguments\n");
        return -1;
    }

    printf("Sending message to group %s...\n", group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_request_id_t req_id = dna_engine_send_group_message(engine, group_uuid, message, on_group_message_sent, &wait);
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
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));
        printf("Created: %s\n", time_str);
    }
    printf("========================================\n");

    if (ctx.groups) free(ctx.groups);
    return 0;
}

int cmd_group_invite(dna_engine_t *engine, const char *group_uuid, const char *fingerprint) {
    if (!engine || !group_uuid || !fingerprint) {
        printf("Error: Missing arguments\n");
        return -1;
    }

    printf("Inviting %s to group %s...\n", fingerprint, group_uuid);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_request_id_t req_id = dna_engine_add_group_member(
        engine, group_uuid, fingerprint, on_completion, &wait);
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

    /* Dispatch commands */
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        cmd_help();
    }
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) {
        free(input);
        return false;
    }
    else if (strcmp(cmd, "create") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) {
            printf("Usage: create <name>\n");
        } else {
            cmd_create(engine, name);
        }
    }
    else if (strcmp(cmd, "restore") == 0) {
        char *mnemonic = strtok(NULL, "");
        if (!mnemonic) {
            printf("Usage: restore <24-word mnemonic>\n");
        } else {
            cmd_restore(engine, trim(mnemonic));
        }
    }
    else if (strcmp(cmd, "list") == 0 || strcmp(cmd, "ls") == 0) {
        cmd_list(engine);
    }
    else if (strcmp(cmd, "load") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) {
            printf("Usage: load <fingerprint>\n");
        } else {
            cmd_load(engine, fp);
        }
    }
    else if (strcmp(cmd, "send") == 0) {
        char *recipient = strtok(NULL, " \t");
        char *message = strtok(NULL, "");
        if (!recipient || !message) {
            printf("Usage: send <fingerprint> <message>\n");
        } else {
            cmd_send(engine, recipient, trim(message));
        }
    }
    else if (strcmp(cmd, "whoami") == 0) {
        cmd_whoami(engine);
    }
    else if (strcmp(cmd, "change-password") == 0) {
        cmd_change_password(engine);
    }
    else if (strcmp(cmd, "register") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) {
            printf("Usage: register <name>\n");
        } else {
            cmd_register(engine, name);
        }
    }
    else if (strcmp(cmd, "lookup") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) {
            printf("Usage: lookup <name>\n");
        } else {
            cmd_lookup(engine, name);
        }
    }
    else if (strcmp(cmd, "lookup-profile") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) {
            printf("Usage: lookup-profile <name|fingerprint>\n");
        } else {
            cmd_lookup_profile(engine, id);
        }
    }
    else if (strcmp(cmd, "name") == 0) {
        cmd_name(engine);
    }
    else if (strcmp(cmd, "profile") == 0) {
        char *arg = strtok(NULL, "");
        if (!arg || strlen(trim(arg)) == 0) {
            cmd_profile(engine, NULL, NULL);
        } else {
            arg = trim(arg);
            char *eq = strchr(arg, '=');
            if (!eq) {
                printf("Usage: profile [field=value]\n");
                printf("Fields: bio, location, website, telegram, twitter, github\n");
            } else {
                *eq = '\0';
                cmd_profile(engine, trim(arg), trim(eq + 1));
            }
        }
    }
    else if (strcmp(cmd, "contacts") == 0) {
        cmd_contacts(engine);
    }
    else if (strcmp(cmd, "add-contact") == 0) {
        char *id = strtok(NULL, " \t");
        if (!id) {
            printf("Usage: add-contact <name|fingerprint>\n");
        } else {
            cmd_add_contact(engine, id);
        }
    }
    else if (strcmp(cmd, "remove-contact") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) {
            printf("Usage: remove-contact <fingerprint>\n");
        } else {
            cmd_remove_contact(engine, fp);
        }
    }
    else if (strcmp(cmd, "request") == 0) {
        char *fp = strtok(NULL, " \t");
        char *msg = strtok(NULL, "");
        if (!fp) {
            printf("Usage: request <fingerprint> [message]\n");
        } else {
            cmd_request(engine, fp, msg ? trim(msg) : NULL);
        }
    }
    else if (strcmp(cmd, "requests") == 0) {
        cmd_requests(engine);
    }
    else if (strcmp(cmd, "approve") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) {
            printf("Usage: approve <fingerprint>\n");
        } else {
            cmd_approve(engine, fp);
        }
    }
    else if (strcmp(cmd, "messages") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) {
            printf("Usage: messages <fingerprint>\n");
        } else {
            cmd_messages(engine, fp);
        }
    }
    else if (strcmp(cmd, "check-offline") == 0) {
        cmd_check_offline(engine);
    }
    else if (strcmp(cmd, "listen") == 0) {
        cmd_listen(engine);
    }
    else if (strcmp(cmd, "wallets") == 0) {
        cmd_wallets(engine);
    }
    else if (strcmp(cmd, "balance") == 0) {
        char *idx = strtok(NULL, " \t");
        if (!idx) {
            printf("Usage: balance <wallet_index>\n");
        } else {
            cmd_balance(engine, atoi(idx));
        }
    }
    else if (strcmp(cmd, "online") == 0) {
        char *fp = strtok(NULL, " \t");
        if (!fp) {
            printf("Usage: online <fingerprint>\n");
        } else {
            cmd_online(engine, fp);
        }
    }
    /* NAT Traversal Commands */
    else if (strcmp(cmd, "stun-test") == 0) {
        cmd_stun_test();
    }
    else if (strcmp(cmd, "ice-status") == 0) {
        cmd_ice_status(engine);
    }
    else if (strcmp(cmd, "turn-creds") == 0) {
        char *arg = strtok(NULL, " \t");
        bool force = (arg && strcmp(arg, "--force") == 0);
        cmd_turn_creds(engine, force);
    }
    else if (strcmp(cmd, "turn-test") == 0) {
        cmd_turn_test(engine);
    }
    /* Version Commands */
    else if (strcmp(cmd, "publish-version") == 0) {
        /* Parse arguments: --lib X --lib-min Y --app X --app-min Y --nodus X --nodus-min Y */
        char *lib_ver = NULL, *lib_min = NULL;
        char *app_ver = NULL, *app_min = NULL;
        char *nodus_ver = NULL, *nodus_min = NULL;

        char *arg;
        while ((arg = strtok(NULL, " \t")) != NULL) {
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
        }

        if (!lib_ver || !app_ver || !nodus_ver) {
            printf("Usage: publish-version --lib <ver> --app <ver> --nodus <ver>\n");
            printf("       [--lib-min <ver>] [--app-min <ver>] [--nodus-min <ver>]\n");
        } else {
            cmd_publish_version(engine, lib_ver, lib_min, app_ver, app_min, nodus_ver, nodus_min);
        }
    }
    else if (strcmp(cmd, "check-version") == 0) {
        cmd_check_version(engine);
    }
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Type 'help' for available commands.\n");
    }

    free(input);
    return true;
}
