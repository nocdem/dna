/**
 * Address Book Database
 * Local SQLite database for wallet address management (per-identity)
 *
 * Architecture:
 * - Per-identity database: ~/.dna/db/addressbook.db
 * - Stores external wallet addresses with user-defined labels
 * - DHT synchronization for multi-device support
 * - Usage tracking for recently used addresses
 *
 * Database Schema:
 * CREATE TABLE addresses (
 *     id INTEGER PRIMARY KEY AUTOINCREMENT,
 *     address TEXT NOT NULL,
 *     label TEXT NOT NULL,
 *     network TEXT NOT NULL,        -- 'backbone', 'ethereum', 'solana', 'tron'
 *     notes TEXT DEFAULT NULL,
 *     created_at INTEGER NOT NULL,
 *     updated_at INTEGER NOT NULL,
 *     last_used INTEGER DEFAULT 0,
 *     use_count INTEGER DEFAULT 0,
 *     UNIQUE(address, network)
 * );
 */

#ifndef ADDRESSBOOK_DB_H
#define ADDRESSBOOK_DB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Address book entry
 */
typedef struct {
    int id;                    /* Database row ID */
    char address[128];         /* Wallet address */
    char label[64];            /* User-defined label */
    char network[32];          /* Network: backbone, ethereum, solana, tron */
    char notes[256];           /* Optional notes */
    uint64_t created_at;       /* When address was added */
    uint64_t updated_at;       /* When address was last modified */
    uint64_t last_used;        /* When address was last used for sending */
    uint32_t use_count;        /* Number of times used for sending */
} addressbook_entry_t;

/**
 * Address book list
 */
typedef struct {
    addressbook_entry_t *entries;
    size_t count;
} addressbook_list_t;

/**
 * Initialize address book database for a specific identity
 * Creates ~/.dna/db/addressbook.db if it doesn't exist
 *
 * @param owner_identity: Identity who owns this address book (kept for API compat)
 * @return: 0 on success, -1 on error
 */
int addressbook_db_init(const char *owner_identity);

/**
 * Add address to database
 *
 * @param address: Wallet address
 * @param label: User-defined label (required)
 * @param network: Network name (backbone, ethereum, solana, tron)
 * @param notes: Optional notes (can be NULL)
 * @return: 0 on success, -1 on error, -2 if already exists
 */
int addressbook_db_add(const char *address, const char *label, const char *network, const char *notes);

/**
 * Update address in database
 *
 * @param id: Database row ID
 * @param label: New label (required)
 * @param notes: New notes (can be NULL to clear)
 * @return: 0 on success, -1 on error
 */
int addressbook_db_update(int id, const char *label, const char *notes);

/**
 * Remove address from database by ID
 *
 * @param id: Database row ID
 * @return: 0 on success, -1 on error
 */
int addressbook_db_remove(int id);

/**
 * Remove address from database by address and network
 *
 * @param address: Wallet address
 * @param network: Network name
 * @return: 0 on success, -1 on error
 */
int addressbook_db_remove_by_address(const char *address, const char *network);

/**
 * Check if address exists in database
 *
 * @param address: Wallet address
 * @param network: Network name
 * @return: true if exists, false otherwise
 */
bool addressbook_db_exists(const char *address, const char *network);

/**
 * Get all addresses
 *
 * @param list_out: Output address list (caller must free with addressbook_db_free_list)
 * @return: 0 on success, -1 on error
 */
int addressbook_db_list(addressbook_list_t **list_out);

/**
 * Get addresses filtered by network
 *
 * @param network: Network name to filter by
 * @param list_out: Output address list (caller must free with addressbook_db_free_list)
 * @return: 0 on success, -1 on error
 */
int addressbook_db_list_by_network(const char *network, addressbook_list_t **list_out);

/**
 * Get address by address string and network
 *
 * @param address: Wallet address
 * @param network: Network name
 * @param entry_out: Output entry (caller must free with addressbook_db_free_entry)
 * @return: 0 on success, -1 on error, 1 if not found
 */
int addressbook_db_get_by_address(const char *address, const char *network, addressbook_entry_t **entry_out);

/**
 * Get address by database ID
 *
 * @param id: Database row ID
 * @param entry_out: Output entry (caller must free with addressbook_db_free_entry)
 * @return: 0 on success, -1 on error, 1 if not found
 */
int addressbook_db_get_by_id(int id, addressbook_entry_t **entry_out);

/**
 * Search addresses by query (matches label or address)
 *
 * @param query: Search query (case-insensitive)
 * @param list_out: Output address list (caller must free with addressbook_db_free_list)
 * @return: 0 on success, -1 on error
 */
int addressbook_db_search(const char *query, addressbook_list_t **list_out);

/**
 * Get recently used addresses
 *
 * @param limit: Maximum number of addresses to return
 * @param list_out: Output address list (caller must free with addressbook_db_free_list)
 * @return: 0 on success, -1 on error
 */
int addressbook_db_get_recent(int limit, addressbook_list_t **list_out);

/**
 * Increment usage count and update last_used timestamp
 *
 * @param id: Database row ID
 * @return: 0 on success, -1 on error
 */
int addressbook_db_increment_usage(int id);

/**
 * Get address count
 *
 * @return: Number of addresses, or -1 on error
 */
int addressbook_db_count(void);

/**
 * Clear all addresses from database
 * Used for REPLACE sync mode when syncing from DHT
 *
 * @return: 0 on success, -1 on error
 */
int addressbook_db_clear_all(void);

/**
 * Free address book list
 *
 * @param list: Address list to free
 */
void addressbook_db_free_list(addressbook_list_t *list);

/**
 * Free single address book entry
 *
 * @param entry: Entry to free
 */
void addressbook_db_free_entry(addressbook_entry_t *entry);

/**
 * Close database
 * Call on shutdown
 */
void addressbook_db_close(void);

#ifdef __cplusplus
}
#endif

#endif // ADDRESSBOOK_DB_H
