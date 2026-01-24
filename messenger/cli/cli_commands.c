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
#include "dht/client/dht_singleton.h"
#include "dht/shared/dht_gek_storage.h"
#include "dht/shared/dht_groups.h"
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

int cmd_gek_fetch(dna_engine_t *engine, const char *group_uuid) {
    if (!engine || !group_uuid) {
        printf("Error: Missing group UUID\n");
        return -1;
    }

    printf("Fetching GEK for group %s from DHT...\n", group_uuid);

    /* Get DHT context */
    void *dht_ctx = dna_engine_get_dht_context(engine);
    if (!dht_ctx) {
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
    int ret = dht_groups_get(dht_ctx, group_uuid, &group_meta);
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
    ret = dht_gek_fetch(dht_ctx, group_uuid, gek_version, &ikp_packet, &ikp_size);

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
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));
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

/* Callback for presence lookup */
static void on_presence_lookup(dna_request_id_t request_id, int error,
                                uint64_t last_seen, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0) {
        if (last_seen > 0) {
            time_t ts = (time_t)last_seen;
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));
            /* If last_seen is recent (within 5 min), consider online */
            time_t now = time(NULL);
            if (now - ts < 300) {
                printf("Status: ONLINE\n");
            } else {
                printf("Status: OFFLINE\n");
            }
            printf("Last seen: %s\n", time_str);
        } else {
            printf("Status: Unknown (never seen)\n");
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_presence(dna_engine_t *engine, const char *identifier) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
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

    printf("Looking up presence for %.16s...\n", resolved_fp);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_lookup_presence(engine, resolved_fp, on_presence_lookup, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to lookup presence: %s\n", dna_engine_error_string(result));
        return result;
    }

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
            strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&ts));

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
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));
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
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));
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
 * PHASE 10: FEED/DNA BOARD (11 commands)
 * ============================================================================ */

/* Callback for feed channels */
static void on_feed_channels(dna_request_id_t request_id, int error,
                              dna_channel_info_t *channels, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && channels && count > 0) {
        printf("\nFeed channels (%d):\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %d. %s\n", i + 1, channels[i].name);
            printf("     ID: %s\n", channels[i].channel_id);
            if (channels[i].description[0]) {
                printf("     Description: %s\n", channels[i].description);
            }
            printf("     Posts: %d\n", channels[i].post_count);
        }
        printf("\n");
    } else if (error == 0) {
        printf("No feed channels found.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (channels) {
        dna_free_feed_channels(channels, count);
    }
}

int cmd_feed_channels(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_feed_channels(engine, on_feed_channels, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get feed channels: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

int cmd_feed_init(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    printf("Initializing default feed channels...\n");

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_init_default_channels(engine, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to initialize channels: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Default channels initialized.\n");
    return 0;
}

/* Callback for channel creation */
static void on_channel_created(dna_request_id_t request_id, int error,
                                dna_channel_info_t *channel, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && channel) {
        printf("Channel created:\n");
        printf("  Name: %s\n", channel->name);
        printf("  ID: %s\n", channel->channel_id);
        if (channel->description[0]) {
            printf("  Description: %s\n", channel->description);
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_feed_create_channel(dna_engine_t *engine, const char *name, const char *description) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!name || strlen(name) == 0) {
        printf("Error: Channel name required\n");
        return -1;
    }

    printf("Creating feed channel '%s'...\n", name);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_create_feed_channel(engine, name, description ? description : "", on_channel_created, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to create channel: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Channel '%s' created successfully!\n", name);
    return 0;
}

/* Callback for feed posts */
static void on_feed_posts(dna_request_id_t request_id, int error,
                          dna_post_info_t *posts, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && posts && count > 0) {
        printf("\nFeed posts (%d):\n", count);
        for (int i = 0; i < count; i++) {
            time_t ts = (time_t)(posts[i].timestamp / 1000);  /* Convert ms to seconds */
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));

            printf("\n  --- Post %d ---\n", i + 1);
            printf("  ID: %s\n", posts[i].post_id);
            printf("  Author: %.16s...\n", posts[i].author_fingerprint);
            printf("  Time: %s\n", time_str);
            printf("  Content: %s\n", posts[i].text ? posts[i].text : "(empty)");
            printf("  Votes: +%d / -%d\n", posts[i].upvotes, posts[i].downvotes);
            printf("  Comments: %d\n", posts[i].comment_count);
        }
        printf("\n");
    } else if (error == 0) {
        printf("No posts in this channel.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (posts) {
        dna_free_feed_posts(posts, count);
    }
}

int cmd_feed_posts(dna_engine_t *engine, const char *channel_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!channel_id || strlen(channel_id) == 0) {
        printf("Error: Channel ID required\n");
        return -1;
    }

    printf("Getting posts for channel %s...\n", channel_id);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_feed_posts(engine, channel_id, NULL, on_feed_posts, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get posts: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

/* Callback for post creation */
static void on_post_created(dna_request_id_t request_id, int error,
                             dna_post_info_t *post, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && post) {
        printf("Post created:\n");
        printf("  ID: %s\n", post->post_id);
        printf("  Content: %s\n", post->text ? post->text : "(empty)");
        dna_free_feed_post(post);
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_feed_post(dna_engine_t *engine, const char *channel_id, const char *content) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!channel_id || !content) {
        printf("Error: Channel ID and content required\n");
        return -1;
    }

    printf("Creating post in channel %s...\n", channel_id);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_create_feed_post(engine, channel_id, content, on_post_created, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to create post: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Post created successfully!\n");
    return 0;
}

int cmd_feed_vote(dna_engine_t *engine, const char *post_id, bool upvote) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!post_id) {
        printf("Error: Post ID required\n");
        return -1;
    }

    printf("Voting %s on post %s...\n", upvote ? "UP" : "DOWN", post_id);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_cast_feed_vote(engine, post_id, upvote ? 1 : -1, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to vote: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Vote cast successfully!\n");
    return 0;
}

/* Callback for post vote counts (returns post with vote data) */
static void on_post_votes(dna_request_id_t request_id, int error,
                          dna_post_info_t *post, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && post) {
        printf("Post votes: +%d / -%d (score: %d)\n",
               post->upvotes, post->downvotes, post->upvotes - post->downvotes);
        printf("Your vote: %s\n", post->user_vote > 0 ? "UP" :
                                   post->user_vote < 0 ? "DOWN" : "none");
        dna_free_feed_post(post);
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_feed_votes(dna_engine_t *engine, const char *post_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!post_id) {
        printf("Error: Post ID required\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_feed_votes(engine, post_id, on_post_votes, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get votes: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

/* Callback for feed comments */
static void on_feed_comments(dna_request_id_t request_id, int error,
                              dna_comment_info_t *comments, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && comments && count > 0) {
        printf("\nComments (%d):\n", count);
        for (int i = 0; i < count; i++) {
            time_t ts = (time_t)(comments[i].timestamp / 1000);  /* Convert ms to seconds */
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&ts));

            printf("  %d. [%s] %.16s...: %s\n", i + 1, time_str,
                   comments[i].author_fingerprint,
                   comments[i].text ? comments[i].text : "(empty)");
            printf("     ID: %s  Votes: +%d/-%d\n",
                   comments[i].comment_id, comments[i].upvotes, comments[i].downvotes);
        }
        printf("\n");
    } else if (error == 0) {
        printf("No comments on this post.\n");
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (comments) {
        dna_free_feed_comments(comments, count);
    }
}

int cmd_feed_comments(dna_engine_t *engine, const char *post_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!post_id) {
        printf("Error: Post ID required\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_feed_comments(engine, post_id, on_feed_comments, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get comments: %s\n", dna_engine_error_string(result));
        return result;
    }

    return 0;
}

/* Callback for comment creation */
static void on_comment_created(dna_request_id_t request_id, int error,
                                dna_comment_info_t *comment, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && comment) {
        printf("Comment created:\n");
        printf("  ID: %s\n", comment->comment_id);
        printf("  Content: %s\n", comment->text ? comment->text : "(empty)");
        dna_free_feed_comment(comment);
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_feed_comment(dna_engine_t *engine, const char *post_id, const char *content) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!post_id || !content) {
        printf("Error: Post ID and content required\n");
        return -1;
    }

    printf("Adding comment to post %s...\n", post_id);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_add_feed_comment(engine, post_id, content, on_comment_created, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to add comment: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Comment added successfully!\n");
    return 0;
}

int cmd_feed_comment_vote(dna_engine_t *engine, const char *comment_id, bool upvote) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!comment_id) {
        printf("Error: Comment ID required\n");
        return -1;
    }

    printf("Voting %s on comment %s...\n", upvote ? "UP" : "DOWN", comment_id);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_cast_comment_vote(engine, comment_id, upvote ? 1 : -1, on_completion, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to vote: %s\n", dna_engine_error_string(result));
        return result;
    }

    printf("Vote cast successfully!\n");
    return 0;
}

/* Callback for comment vote counts (returns comment with vote data) */
static void on_comment_votes(dna_request_id_t request_id, int error,
                              dna_comment_info_t *comment, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && comment) {
        printf("Comment votes: +%d / -%d (score: %d)\n",
               comment->upvotes, comment->downvotes, comment->upvotes - comment->downvotes);
        printf("Your vote: %s\n", comment->user_vote > 0 ? "UP" :
                                   comment->user_vote < 0 ? "DOWN" : "none");
        dna_free_feed_comment(comment);
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
}

int cmd_feed_comment_votes(dna_engine_t *engine, const char *comment_id) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!comment_id) {
        printf("Error: Comment ID required\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_comment_votes(engine, comment_id, on_comment_votes, &wait);
    int result = cli_wait_for(&wait);
    cli_wait_destroy(&wait);

    if (result != 0) {
        printf("Error: Failed to get votes: %s\n", dna_engine_error_string(result));
        return result;
    }

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
