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

/* v0.3.0: cli_list_identities removed - single-user model, use dna_engine_has_identity() */

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
 * Delete an identity and all associated data
 * @param engine DNA engine instance
 * @param fingerprint Identity fingerprint to delete
 * @return 0 on success, negative on error
 */
int cmd_delete(dna_engine_t *engine, const char *fingerprint);

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

/**
 * Lookup another user's profile from DHT
 * @param engine DNA engine instance
 * @param identifier Name or fingerprint to lookup
 * @return 0 on success, negative on error
 */
int cmd_lookup_profile(dna_engine_t *engine, const char *identifier);

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
 * NAT TRAVERSAL COMMANDS (STUN/ICE/TURN)
 * ============================================================================ */

/**
 * Test STUN connectivity and show public IP
 * @return 0 on success, negative on error
 */
int cmd_stun_test(void);

/**
 * Show ICE connection status and candidates
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_ice_status(dna_engine_t *engine);

/**
 * Request or show TURN credentials
 * @param engine DNA engine instance
 * @param request If true, request new credentials; if false, show cached
 * @return 0 on success, negative on error
 */
int cmd_turn_creds(dna_engine_t *engine, bool request);

/**
 * Test TURN relay connectivity with all servers
 * Requests credentials and tests allocation on each TURN server.
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_turn_test(dna_engine_t *engine);

/* ============================================================================
 * VERSION COMMANDS
 * ============================================================================ */

/**
 * Publish version info to DHT (requires identity loaded)
 * @param engine DNA engine instance
 * @param lib_ver Library version (e.g., "0.3.90")
 * @param lib_min Library minimum version
 * @param app_ver App version (e.g., "0.99.29")
 * @param app_min App minimum version
 * @param nodus_ver Nodus version (e.g., "0.4.3")
 * @param nodus_min Nodus minimum version
 * @return 0 on success, negative on error
 */
int cmd_publish_version(dna_engine_t *engine,
                        const char *lib_ver, const char *lib_min,
                        const char *app_ver, const char *app_min,
                        const char *nodus_ver, const char *nodus_min);

/**
 * Check version info from DHT
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_check_version(dna_engine_t *engine);

/* ============================================================================
 * GROUP COMMANDS (GEK System)
 * ============================================================================ */

/**
 * List all groups the user belongs to
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_group_list(dna_engine_t *engine);

/**
 * Create a new group
 * @param engine DNA engine instance
 * @param name Group name
 * @return 0 on success, negative on error
 */
int cmd_group_create(dna_engine_t *engine, const char *name);

/**
 * Send a message to a group
 * @param engine DNA engine instance
 * @param group_uuid Group UUID
 * @param message Message text
 * @return 0 on success, negative on error
 */
int cmd_group_send(dna_engine_t *engine, const char *group_uuid, const char *message);

/**
 * Show group info and members
 * @param engine DNA engine instance
 * @param group_uuid Group UUID
 * @return 0 on success, negative on error
 */
int cmd_group_info(dna_engine_t *engine, const char *group_uuid);

/**
 * Invite a member to a group
 * @param engine DNA engine instance
 * @param group_uuid Group UUID
 * @param fingerprint Member fingerprint to invite
 * @return 0 on success, negative on error
 */
int cmd_group_invite(dna_engine_t *engine, const char *group_uuid, const char *fingerprint);

/**
 * Sync a specific group from DHT to local cache
 * @param engine DNA engine instance
 * @param group_uuid Group UUID to sync
 * @return 0 on success, negative on error
 */
int cmd_group_sync(dna_engine_t *engine, const char *group_uuid);

/**
 * Publish GEK for a group to DHT
 *
 * Only the group creator/owner can publish GEK. This generates or rotates
 * the GEK and publishes it to DHT so members can fetch it.
 *
 * @param engine DNA engine instance
 * @param group_uuid Group UUID to publish GEK for
 * @return 0 on success, negative on error
 */
int cmd_group_publish_gek(dna_engine_t *engine, const char *group_uuid);

/* ============================================================================
 * DHT DEBUG COMMANDS
 * ============================================================================ */

/**
 * Fetch and display the DHT bootstrap registry
 * Shows all registered bootstrap nodes with their status.
 * @param engine DNA engine instance
 * @return 0 on success, negative on error
 */
int cmd_bootstrap_registry(dna_engine_t *engine);

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
