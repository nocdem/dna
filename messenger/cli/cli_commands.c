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
#include "transport/internal/transport_core.h"
/* ICE/TURN removed in v0.4.61 for privacy */
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
    printf("  create <name>              Create new identity (generates BIP39 mnemonic)\n");
    printf("  restore <mnemonic...>      Restore identity from 24-word mnemonic\n");
    printf("  delete <fingerprint>       Delete an identity permanently\n");
    printf("  list                       List all available identities\n");
    printf("  load <fingerprint>         Load an identity (can use prefix)\n");
    printf("  whoami                     Show current identity\n");
    printf("  change-password            Change password for current identity\n");
    printf("  register <name>            Register a name on DHT\n");
    printf("  name                       Show registered name\n");
    printf("  lookup <name>              Check if name is available\n");
    printf("  lookup-profile <name|fp>   View any user's DHT profile\n");
    printf("  profile [field=value]      Show or update profile\n");
    printf("\n");

    printf("CONTACT COMMANDS:\n");
    printf("  contacts                    List all contacts\n");
    printf("  add-contact <name|fp>       Add contact\n");
    printf("  remove-contact <fp>         Remove contact\n");
    printf("  request <name|fp> [msg]     Send contact request\n");
    printf("  requests                    List pending requests\n");
    printf("  approve <fp>                Approve contact request\n");
    printf("  listen                      Subscribe to contacts and listen (stays running)\n");
    printf("  turn-creds [--force]        Show/request TURN credentials\n");
    printf("\n");

    printf("MESSAGING:\n");
    printf("  send <name|fp> <message>   Send message to recipient\n");
    printf("  messages <name|fp>         Show conversation with contact\n");
    printf("  check-offline              Check for offline messages\n");
    printf("\n");

    printf("GROUP COMMANDS:\n");
    printf("  group-list                  List all groups\n");
    printf("  group-create <name>         Create a new group\n");
    printf("  group-send <name|uuid> <msg>  Send message to group\n");
    printf("  group-info <uuid>           Show group info and members\n");
    printf("  group-invite <uuid> <name|fp>  Invite member to group\n");
    printf("  group-sync <uuid>           Sync group from DHT to local cache\n");
    printf("  group-publish-gek <uuid>    Publish GEK to DHT (owner only)\n");
    printf("\n");

    printf("WALLET:\n");
    printf("  wallets                    List wallets\n");
    printf("  balance <index>            Show wallet balances\n");
    printf("\n");

    printf("NETWORK:\n");
    printf("  online <name|fp>           Check if peer is online\n");
    printf("\n");

    printf("VERSION:\n");
    printf("  publish-version            Publish version info to DHT\n");
    printf("    --lib <ver> --lib-min <ver> --app <ver> --app-min <ver> --nodus <ver> --nodus-min <ver>\n");
    printf("  check-version              Check latest version from DHT\n");
    printf("\n");

    printf("OTHER:\n");
    printf("  help                       Show this help message\n");
    printf("  quit / exit                Exit the CLI\n");
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
 * DHT DEBUG COMMANDS
 * ============================================================================ */

#include "dht/core/dht_bootstrap_registry.h"

int cmd_bootstrap_registry(dna_engine_t *engine) {
    (void)engine;  /* Not needed, uses singleton */

    printf("Fetching bootstrap registry from DHT...\n\n");

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        printf("Error: DHT not initialized\n");
        return -1;
    }

    /* Wait for DHT to be ready */
    if (!dht_context_is_ready(dht)) {
        printf("Waiting for DHT connection...\n");
        for (int i = 0; i < 50; i++) {
            if (dht_context_is_ready(dht)) break;
            struct timespec ts = {0, 100000000};  /* 100ms */
            nanosleep(&ts, NULL);
        }
        if (!dht_context_is_ready(dht)) {
            printf("Error: DHT not connected\n");
            return -1;
        }
    }

    bootstrap_registry_t registry;
    memset(&registry, 0, sizeof(registry));

    int ret = dht_bootstrap_registry_fetch(dht, &registry);

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
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));
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

int cmd_group_publish_gek(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Missing group UUID\n");
        return -1;
    }

    printf("Publishing GEK for group %s to DHT...\n", group_uuid);

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
    extern int gek_rotate_on_member_add(void *dht_ctx, const char *group_uuid, const char *owner_identity);

    void *dht_ctx = dna_engine_get_dht_context(engine);
    if (!dht_ctx) {
        printf("Error: DHT not initialized\n");
        return -1;
    }

    int ret = gek_rotate_on_member_add(dht_ctx, group_uuid, fingerprint);
    if (ret != 0) {
        printf("Error: Failed to publish GEK\n");
        return -1;
    }

    printf("GEK published successfully to DHT!\n");
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
