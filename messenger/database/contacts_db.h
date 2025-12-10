/**
 * Contacts Database
 * Local SQLite database for contact management (per-identity)
 *
 * Architecture:
 * - Per-identity database: ~/.dna/<owner_identity>/db/contacts.db
 * - ICQ-style contact request workflow
 * - Query DHT for public keys when needed
 * - No global directory listing
 * - DHT synchronization for multi-device support
 *
 * Database Schema:
 * CREATE TABLE contacts (
 *     identity TEXT PRIMARY KEY,
 *     added_timestamp INTEGER,
 *     notes TEXT,
 *     status INTEGER DEFAULT 0   -- 0=mutual, 1=pending_outgoing
 * );
 *
 * CREATE TABLE contact_requests (
 *     fingerprint TEXT PRIMARY KEY,
 *     display_name TEXT,
 *     message TEXT,
 *     requested_at INTEGER,
 *     status INTEGER DEFAULT 0   -- 0=pending, 1=approved, 2=denied
 * );
 *
 * CREATE TABLE blocked_users (
 *     fingerprint TEXT PRIMARY KEY,
 *     blocked_at INTEGER,
 *     reason TEXT
 * );
 */

#ifndef CONTACTS_DB_H
#define CONTACTS_DB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Contact status enum
 */
typedef enum {
    CONTACT_STATUS_MUTUAL = 0,            /* Both parties approved (default) */
    CONTACT_STATUS_PENDING_OUTGOING = 1,  /* I sent request, awaiting approval */
} contact_status_t;

/**
 * Contact request status enum
 */
typedef enum {
    REQUEST_STATUS_PENDING = 0,   /* Awaiting response */
    REQUEST_STATUS_APPROVED = 1,  /* Request accepted */
    REQUEST_STATUS_DENIED = 2,    /* Request denied (can retry) */
} request_status_t;

/**
 * Contact entry
 */
typedef struct {
    char identity[256];        /* DNA identity (fingerprint or name) */
    uint64_t added_timestamp;  /* When added to contacts */
    char notes[512];           /* Optional notes */
    int status;                /* contact_status_t: 0=mutual, 1=pending_outgoing */
} contact_entry_t;

/**
 * Incoming contact request entry
 */
typedef struct {
    char fingerprint[129];     /* Requester's fingerprint (128 hex + null) */
    char display_name[64];     /* Requester's display name */
    char message[256];         /* Optional request message */
    uint64_t requested_at;     /* When request was received */
    int status;                /* request_status_t: 0=pending, 1=approved, 2=denied */
} incoming_request_t;

/**
 * Blocked user entry
 */
typedef struct {
    char fingerprint[129];     /* Blocked user's fingerprint */
    uint64_t blocked_at;       /* When user was blocked */
    char reason[256];          /* Optional reason for blocking */
} blocked_user_t;

/**
 * Contact list
 */
typedef struct {
    contact_entry_t *contacts;
    size_t count;
} contact_list_t;

/**
 * Initialize contacts database for a specific identity
 * Creates database file at ~/.dna/<owner_identity>_contacts.db if it doesn't exist
 *
 * @param owner_identity: Identity who owns this contact list (e.g., "alice")
 * @return: 0 on success, -1 on error
 */
int contacts_db_init(const char *owner_identity);

/**
 * Add contact to database
 *
 * @param identity: DNA identity name
 * @param notes: Optional notes (can be NULL)
 * @return: 0 on success, -1 on error, -2 if already exists
 */
int contacts_db_add(const char *identity, const char *notes);

/**
 * Remove contact from database
 *
 * @param identity: DNA identity name
 * @return: 0 on success, -1 on error
 */
int contacts_db_remove(const char *identity);

/**
 * Update contact notes
 *
 * @param identity: DNA identity name
 * @param notes: New notes (can be NULL to clear)
 * @return: 0 on success, -1 on error
 */
int contacts_db_update_notes(const char *identity, const char *notes);

/**
 * Check if contact exists
 *
 * @param identity: DNA identity name
 * @return: true if exists, false otherwise
 */
bool contacts_db_exists(const char *identity);

/**
 * Get all contacts
 *
 * @param list_out: Output contact list (caller must free with contacts_db_free_list)
 * @return: 0 on success, -1 on error
 */
int contacts_db_list(contact_list_t **list_out);

/**
 * Get contact count
 *
 * @return: Number of contacts, or -1 on error
 */
int contacts_db_count(void);

/**
 * Clear all contacts from database
 * Used for REPLACE sync mode when syncing from DHT
 *
 * @return: 0 on success, -1 on error
 */
int contacts_db_clear_all(void);

/**
 * Free contact list
 *
 * @param list: Contact list to free
 */
void contacts_db_free_list(contact_list_t *list);

/**
 * Close database
 * Call on shutdown
 */
void contacts_db_close(void);

/**
 * Migrate contacts from global database to per-identity database
 * Copies all contacts from ~/.dna/contacts.db to ~/.dna/<owner_identity>_contacts.db
 * Only runs if global database exists and per-identity database doesn't
 *
 * @param owner_identity: Identity to migrate contacts to
 * @return: Number of contacts migrated, 0 if nothing to migrate, -1 on error
 */
int contacts_db_migrate_from_global(const char *owner_identity);

/* ============================================================================
 * CONTACT REQUEST FUNCTIONS (ICQ-style approval system)
 * ============================================================================ */

/**
 * Add an incoming contact request
 *
 * @param fingerprint: Requester's fingerprint (128 hex chars)
 * @param display_name: Requester's display name (can be empty)
 * @param message: Optional request message (can be NULL)
 * @param timestamp: Unix timestamp when request was received
 * @return: 0 on success, -1 on error, -2 if already exists
 */
int contacts_db_add_incoming_request(
    const char *fingerprint,
    const char *display_name,
    const char *message,
    uint64_t timestamp
);

/**
 * Get all pending incoming contact requests
 *
 * @param requests_out: Output array (caller must free with contacts_db_free_requests)
 * @param count_out: Number of requests returned
 * @return: 0 on success, -1 on error
 */
int contacts_db_get_incoming_requests(incoming_request_t **requests_out, int *count_out);

/**
 * Get count of pending incoming requests
 *
 * @return: Number of pending requests, or -1 on error
 */
int contacts_db_pending_request_count(void);

/**
 * Approve a contact request (moves to contacts table as mutual)
 *
 * @param fingerprint: Requester's fingerprint
 * @return: 0 on success, -1 on error
 */
int contacts_db_approve_request(const char *fingerprint);

/**
 * Deny a contact request (marks as denied, can be retried)
 *
 * @param fingerprint: Requester's fingerprint
 * @return: 0 on success, -1 on error
 */
int contacts_db_deny_request(const char *fingerprint);

/**
 * Remove a contact request from database
 *
 * @param fingerprint: Requester's fingerprint
 * @return: 0 on success, -1 on error
 */
int contacts_db_remove_request(const char *fingerprint);

/**
 * Check if a request exists from this fingerprint
 *
 * @param fingerprint: Fingerprint to check
 * @return: true if request exists, false otherwise
 */
bool contacts_db_request_exists(const char *fingerprint);

/**
 * Free incoming requests array
 *
 * @param requests: Array to free
 * @param count: Number of elements
 */
void contacts_db_free_requests(incoming_request_t *requests, int count);

/* ============================================================================
 * BLOCKED USER FUNCTIONS
 * ============================================================================ */

/**
 * Block a user permanently
 *
 * @param fingerprint: User's fingerprint to block
 * @param reason: Optional reason for blocking (can be NULL)
 * @return: 0 on success, -1 on error, -2 if already blocked
 */
int contacts_db_block_user(const char *fingerprint, const char *reason);

/**
 * Unblock a user
 *
 * @param fingerprint: User's fingerprint to unblock
 * @return: 0 on success, -1 on error
 */
int contacts_db_unblock_user(const char *fingerprint);

/**
 * Check if a user is blocked
 *
 * @param fingerprint: Fingerprint to check
 * @return: true if blocked, false otherwise
 */
bool contacts_db_is_blocked(const char *fingerprint);

/**
 * Get all blocked users
 *
 * @param blocked_out: Output array (caller must free with contacts_db_free_blocked)
 * @param count_out: Number of blocked users returned
 * @return: 0 on success, -1 on error
 */
int contacts_db_get_blocked_users(blocked_user_t **blocked_out, int *count_out);

/**
 * Get count of blocked users
 *
 * @return: Number of blocked users, or -1 on error
 */
int contacts_db_blocked_count(void);

/**
 * Free blocked users array
 *
 * @param blocked: Array to free
 * @param count: Number of elements
 */
void contacts_db_free_blocked(blocked_user_t *blocked, int count);

#ifdef __cplusplus
}
#endif

#endif // CONTACTS_DB_H
