/**
 * Contacts Database
 * Local SQLite database for contact management (per-identity)
 *
 * Architecture:
 * - Per-identity database: ~/.dna/<owner_identity>_contacts.db
 * - Manual "Add Contact" workflow
 * - Query DHT for public keys when needed
 * - No global directory listing
 * - DHT synchronization for multi-device support
 *
 * Database Schema:
 * CREATE TABLE contacts (
 *     identity TEXT PRIMARY KEY,
 *     added_timestamp INTEGER,
 *     notes TEXT
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
 * Contact entry
 */
typedef struct {
    char identity[256];        // DNA identity name
    uint64_t added_timestamp;  // When added to contacts
    char notes[512];           // Optional notes
} contact_entry_t;

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

#ifdef __cplusplus
}
#endif

#endif // CONTACTS_DB_H
