/*
 * DNA Messenger CLI - Command Implementation
 *
 * Interactive CLI tool for testing DNA Messenger without GUI.
 */

#include "cli_commands.h"
#include "bip39.h"
#include "crypto/utils/qgp_log.h"
#include "dht/core/dht_keyserver.h"
#include "dht/client/dht_singleton.h"

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

static void on_identities_listed(dna_request_id_t request_id, int error,
                                  char **fingerprints, int count, void *user_data) {
    (void)request_id;
    cli_wait_t *wait = (cli_wait_t *)user_data;

    pthread_mutex_lock(&wait->mutex);
    wait->result = error;

    if (error == 0 && fingerprints && count > 0) {
        wait->fingerprints = malloc(count * sizeof(char *));
        if (wait->fingerprints) {
            wait->fingerprint_count = count;
            for (int i = 0; i < count; i++) {
                wait->fingerprints[i] = strdup(fingerprints[i]);
            }
        }
    }

    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);

    if (fingerprints) {
        dna_free_strings(fingerprints, count);
    }
}

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
    uint8_t wallet_seed[32];
    uint8_t master_seed[64];

    if (qgp_derive_seeds_with_master(mnemonic, "", signing_seed, encryption_seed,
                                      wallet_seed, master_seed) != 0) {
        printf("Error: Failed to derive seeds from mnemonic\n");
        return -1;
    }

    printf("Creating identity '%s'...\n", name);

    char fingerprint[129];
    int result = dna_engine_create_identity_sync(
        engine, name, signing_seed, encryption_seed,
        wallet_seed, master_seed, mnemonic, fingerprint
    );

    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));
    memset(wallet_seed, 0, sizeof(wallet_seed));
    memset(master_seed, 0, sizeof(master_seed));
    memset(mnemonic, 0, sizeof(mnemonic));

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

int cmd_list(dna_engine_t *engine) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_list_identities(engine, on_identities_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to list identities: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.fingerprint_count == 0) {
        printf("No identities found. Use 'create <name>' to create one.\n");
    } else {
        const char *current_fp = dna_engine_get_fingerprint(engine);

        printf("\nAvailable identities (%d):\n", wait.fingerprint_count);
        for (int i = 0; i < wait.fingerprint_count; i++) {
            bool is_loaded = current_fp && strcmp(current_fp, wait.fingerprints[i]) == 0;
            printf("  %d. %.16s...%s\n", i + 1, wait.fingerprints[i],
                   is_loaded ? " (loaded)" : "");
            free(wait.fingerprints[i]);
        }
        free(wait.fingerprints);
        printf("\n");
    }

    cli_wait_destroy(&wait);
    return 0;
}

int cli_list_identities(dna_engine_t *engine, char ***fingerprints_out, int *count_out) {
    if (!engine || !fingerprints_out || !count_out) {
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_list_identities(engine, on_identities_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        cli_wait_destroy(&wait);
        *fingerprints_out = NULL;
        *count_out = 0;
        return result;
    }

    /* Transfer ownership to caller */
    *fingerprints_out = wait.fingerprints;
    *count_out = wait.fingerprint_count;
    wait.fingerprints = NULL;
    wait.fingerprint_count = 0;

    cli_wait_destroy(&wait);
    return 0;
}

int cmd_load(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Fingerprint required\n");
        return -1;
    }

    printf("Loading identity %s...\n", fingerprint);

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_load_identity(engine, fingerprint, on_completion, &wait);
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
    uint8_t wallet_seed[32];
    uint8_t master_seed[64];

    if (qgp_derive_seeds_with_master(mnemonic, "", signing_seed, encryption_seed,
                                      wallet_seed, master_seed) != 0) {
        printf("Error: Failed to derive seeds from mnemonic\n");
        return -1;
    }

    char fingerprint[129];
    int result = dna_engine_restore_identity_sync(
        engine, signing_seed, encryption_seed,
        wallet_seed, master_seed, mnemonic, fingerprint
    );

    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));
    memset(wallet_seed, 0, sizeof(wallet_seed));
    memset(master_seed, 0, sizeof(master_seed));

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
    if (identity->wallets.btc[0])
        printf("Bitcoin: %s\n", identity->wallets.btc);
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

int cmd_messages(dna_engine_t *engine, const char *fingerprint) {
    if (!engine) {
        printf("Error: Engine not initialized\n");
        return -1;
    }

    const char *fp = dna_engine_get_fingerprint(engine);
    if (!fp) {
        printf("Error: No identity loaded\n");
        return -1;
    }

    if (!fingerprint || strlen(fingerprint) == 0) {
        printf("Error: Contact fingerprint required\n");
        return -1;
    }

    cli_wait_t wait;
    cli_wait_init(&wait);

    dna_engine_get_conversation(engine, fingerprint, on_messages_listed, &wait);
    int result = cli_wait_for(&wait);

    if (result != 0) {
        printf("Error: Failed to get messages: %s\n", dna_engine_error_string(result));
        cli_wait_destroy(&wait);
        return result;
    }

    if (wait.message_count == 0) {
        printf("No messages with this contact.\n");
    } else {
        printf("\nConversation with %.16s... (%d messages):\n\n", fingerprint, wait.message_count);
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
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Type 'help' for available commands.\n");
    }

    free(input);
    return true;
}
