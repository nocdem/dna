/*
 * DNA Messenger CLI - Command Definitions
 *
 * Interactive CLI tool for testing DNA Messenger without GUI.
 */

#ifndef CLI_COMMANDS_H
#define CLI_COMMANDS_H

#include <dna/dna_engine.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SYNCHRONIZATION HELPERS
 * ============================================================================ */

/**
 * Blocking wait structure for async callbacks
 */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    int result;
    /* Result data storage */
    char **fingerprints;
    int fingerprint_count;
    char fingerprint[129];
    char display_name[256];
    /* Contacts storage */
    dna_contact_t *contacts;
    int contact_count;
    /* Messages storage */
    dna_message_t *messages;
    int message_count;
    /* Contact requests storage */
    dna_contact_request_t *requests;
    int request_count;
    /* Wallets storage */
    dna_wallet_t *wallets;
    int wallet_count;
    /* Balances storage */
    dna_balance_t *balances;
    int balance_count;
    /* Profile storage */
    dna_profile_t *profile;
} cli_wait_t;

/**
 * Initialize wait structure
 */
void cli_wait_init(cli_wait_t *wait);

/**
 * Destroy wait structure
 */
void cli_wait_destroy(cli_wait_t *wait);

/**
 * Block until async operation completes
 * Returns: result code from callback
 */
int cli_wait_for(cli_wait_t *wait);

/**
 * List identities and return them (for auto-load)
 * @param engine DNA engine instance
 * @param fingerprints_out Output array of fingerprints (caller frees)
 * @param count_out Output count
 * @return 0 on success, negative on error
 */
int cli_list_identities(dna_engine_t *engine, char ***fingerprints_out, int *count_out);

/* ============================================================================
 * BASIC COMMANDS (existing)
 * ============================================================================ */

void cmd_help(void);
int cmd_create(dna_engine_t *engine, const char *name);
int cmd_list(dna_engine_t *engine);
int cmd_load(dna_engine_t *engine, const char *fingerprint);
int cmd_send(dna_engine_t *engine, const char *recipient, const char *message);
void cmd_whoami(dna_engine_t *engine);

/* ============================================================================
 * IDENTITY COMMANDS (new)
 * ============================================================================ */

/**
 * Restore identity from BIP39 mnemonic
 * @param engine DNA engine instance
 * @param mnemonic Space-separated 24-word mnemonic
 * @return 0 on success, negative on error
 */
int cmd_restore(dna_engine_t *engine, const char *mnemonic);

/**
 * Register a name for current identity on DHT
 * @param engine DNA engine instance
 * @param name Name to register (3-20 chars)
 * @return 0 on success, negative on error
 */
int cmd_register(dna_engine_t *engine, const char *name);

/**
 * Lookup if a name is available or taken
 * @param engine DNA engine instance
 * @param name Name to lookup
 * @return 0 on success, negative on error
 */
int cmd_lookup(dna_engine_t *engine, const char *name);

/**
 * Get registered name for current identity
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_name(dna_engine_t *engine);

/**
 * Get or update profile
 * @param engine DNA engine instance
 * @param field Field to update (NULL to show profile)
 * @param value Value to set (NULL to show profile)
 * @return 0 on success, negative on error
 */
int cmd_profile(dna_engine_t *engine, const char *field, const char *value);

/* ============================================================================
 * CONTACT COMMANDS (new)
 * ============================================================================ */

/**
 * List all contacts
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_contacts(dna_engine_t *engine);

/**
 * Add a contact by fingerprint or name
 * @param engine DNA engine instance
 * @param identifier Fingerprint or registered name
 * @return 0 on success, negative on error
 */
int cmd_add_contact(dna_engine_t *engine, const char *identifier);

/**
 * Remove a contact
 * @param engine DNA engine instance
 * @param fingerprint Contact fingerprint
 * @return 0 on success, negative on error
 */
int cmd_remove_contact(dna_engine_t *engine, const char *fingerprint);

/**
 * Send a contact request
 * @param engine DNA engine instance
 * @param fingerprint Recipient fingerprint
 * @param message Optional message (can be NULL)
 * @return 0 on success, negative on error
 */
int cmd_request(dna_engine_t *engine, const char *fingerprint, const char *message);

/**
 * List pending contact requests
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_requests(dna_engine_t *engine);

/**
 * Approve a contact request
 * @param engine DNA engine instance
 * @param fingerprint Requester fingerprint
 * @return 0 on success, negative on error
 */
int cmd_approve(dna_engine_t *engine, const char *fingerprint);

/* ============================================================================
 * MESSAGING COMMANDS (new)
 * ============================================================================ */

/**
 * Get conversation with a contact
 * @param engine DNA engine instance
 * @param fingerprint Contact fingerprint
 * @return 0 on success, negative on error
 */
int cmd_messages(dna_engine_t *engine, const char *fingerprint);

/**
 * Check for offline messages
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_check_offline(dna_engine_t *engine);

/**
 * Subscribe to contacts' outboxes and listen for push notifications
 * Stays running until Ctrl+C
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_listen(dna_engine_t *engine);

/* ============================================================================
 * WALLET COMMANDS (new)
 * ============================================================================ */

/**
 * List wallets
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_wallets(dna_engine_t *engine);

/**
 * Get wallet balances
 * @param engine DNA engine instance
 * @param wallet_index Wallet index (0-based)
 * @return 0 on success, negative on error
 */
int cmd_balance(dna_engine_t *engine, int wallet_index);

/* ============================================================================
 * PRESENCE COMMANDS (new)
 * ============================================================================ */

/**
 * Check if a peer is online
 * @param engine DNA engine instance
 * @param fingerprint Peer fingerprint
 * @return 0 on success, negative on error
 */
int cmd_online(dna_engine_t *engine, const char *fingerprint);

/* ============================================================================
 * COMMAND PARSER
 * ============================================================================ */

/**
 * Parse and execute a command line
 * @param engine DNA engine instance
 * @param line Input line from user
 * @return true to continue REPL, false to exit
 */
bool execute_command(dna_engine_t *engine, const char *line);

#ifdef __cplusplus
}
#endif

#endif /* CLI_COMMANDS_H */
