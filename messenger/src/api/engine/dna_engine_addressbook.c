/*
 * DNA Engine - Address Book Module
 *
 * Wallet address book management:
 *   - CRUD operations for saved addresses
 *   - Network filtering (ETH, SOL, TRX, CELL, etc.)
 *   - Usage tracking for recent addresses
 *
 * Functions:
 *   - dna_free_addressbook_entries()           // Free entry array
 *   - dna_engine_add_address()                 // Add new address
 *   - dna_engine_update_address()              // Update address
 *   - dna_engine_remove_address()              // Remove address
 *   - dna_engine_address_exists()              // Check if exists
 *   - dna_engine_lookup_address()              // Lookup by address
 *   - dna_engine_increment_address_usage()     // Track usage
 *   - dna_engine_get_addressbook()             // Get all addresses
 *   - dna_engine_get_addressbook_by_network()  // Filter by network
 *   - dna_engine_get_recent_addresses()        // Get recent
 *
 * Note: DHT sync functions moved to dna_engine_backup.c
 */

#define DNA_ENGINE_ADDRESSBOOK_IMPL
#include "engine_includes.h"

/* ============================================================================
 * MEMORY MANAGEMENT
 * ============================================================================ */

void dna_free_addressbook_entries(dna_addressbook_entry_t *entries, int count) {
    (void)count;
    free(entries);
}

/* ============================================================================
 * SYNCHRONOUS CRUD OPERATIONS
 * ============================================================================ */

/* Synchronous: Add address to address book */
int dna_engine_add_address(
    dna_engine_t *engine,
    const char *address,
    const char *label,
    const char *network,
    const char *notes)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (!address || !label || !network) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for add_address");
        return -1;
    }

    /* Initialize address book database if needed */
    if (addressbook_db_init(engine->fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize address book database");
        return -1;
    }

    return addressbook_db_add(address, label, network, notes);
}

/* Synchronous: Update address in address book */
int dna_engine_update_address(
    dna_engine_t *engine,
    int id,
    const char *label,
    const char *notes)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (id <= 0 || !label) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for update_address");
        return -1;
    }

    return addressbook_db_update(id, label, notes);
}

/* Synchronous: Remove address from address book */
int dna_engine_remove_address(dna_engine_t *engine, int id) {
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (id <= 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid id for remove_address");
        return -1;
    }

    return addressbook_db_remove(id);
}

/* Synchronous: Check if address exists */
bool dna_engine_address_exists(
    dna_engine_t *engine,
    const char *address,
    const char *network)
{
    if (!engine || !engine->identity_loaded || !address || !network) {
        return false;
    }

    /* Initialize address book database if needed */
    if (addressbook_db_init(engine->fingerprint) != 0) {
        return false;
    }

    return addressbook_db_exists(address, network);
}

/* Synchronous: Lookup address */
int dna_engine_lookup_address(
    dna_engine_t *engine,
    const char *address,
    const char *network,
    dna_addressbook_entry_t *entry_out)
{
    if (!engine || !engine->identity_loaded) {
        QGP_LOG_ERROR(LOG_TAG, "Engine not initialized or identity not loaded");
        return -1;
    }

    if (!address || !network || !entry_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for lookup_address");
        return -1;
    }

    /* Initialize address book database if needed */
    if (addressbook_db_init(engine->fingerprint) != 0) {
        return -1;
    }

    addressbook_entry_t *db_entry = NULL;
    int result = addressbook_db_get_by_address(address, network, &db_entry);

    if (result != 0 || !db_entry) {
        return result;  /* -1 for error, 1 for not found */
    }

    /* Copy to output struct */
    entry_out->id = db_entry->id;
    strncpy(entry_out->address, db_entry->address, sizeof(entry_out->address) - 1);
    strncpy(entry_out->label, db_entry->label, sizeof(entry_out->label) - 1);
    strncpy(entry_out->network, db_entry->network, sizeof(entry_out->network) - 1);
    strncpy(entry_out->notes, db_entry->notes, sizeof(entry_out->notes) - 1);
    entry_out->created_at = db_entry->created_at;
    entry_out->updated_at = db_entry->updated_at;
    entry_out->last_used = db_entry->last_used;
    entry_out->use_count = db_entry->use_count;

    addressbook_db_free_entry(db_entry);
    return 0;
}

/* Synchronous: Increment address usage */
int dna_engine_increment_address_usage(dna_engine_t *engine, int id) {
    if (!engine || !engine->identity_loaded) {
        return -1;
    }

    if (id <= 0) {
        return -1;
    }

    return addressbook_db_increment_usage(id);
}

/* ============================================================================
 * ASYNC TASK INFRASTRUCTURE
 * ============================================================================ */

/* Async task data for address book operations */
typedef struct {
    dna_engine_t *engine;
    dna_addressbook_cb callback;
    void *user_data;
    char network[32];  /* For network filter */
    int limit;         /* For recent addresses */
} addressbook_task_t;

/* Helper: Convert addressbook_list_t to dna_addressbook_entry_t array */
static dna_addressbook_entry_t* convert_addressbook_list(
    addressbook_list_t *list,
    int *count_out)
{
    if (!list || list->count == 0) {
        *count_out = 0;
        return NULL;
    }

    dna_addressbook_entry_t *entries = calloc(list->count, sizeof(dna_addressbook_entry_t));
    if (!entries) {
        *count_out = 0;
        return NULL;
    }

    for (size_t i = 0; i < list->count; i++) {
        entries[i].id = list->entries[i].id;
        strncpy(entries[i].address, list->entries[i].address, sizeof(entries[i].address) - 1);
        strncpy(entries[i].label, list->entries[i].label, sizeof(entries[i].label) - 1);
        strncpy(entries[i].network, list->entries[i].network, sizeof(entries[i].network) - 1);
        strncpy(entries[i].notes, list->entries[i].notes, sizeof(entries[i].notes) - 1);
        entries[i].created_at = list->entries[i].created_at;
        entries[i].updated_at = list->entries[i].updated_at;
        entries[i].last_used = list->entries[i].last_used;
        entries[i].use_count = list->entries[i].use_count;
    }

    *count_out = (int)list->count;
    return entries;
}

/* ============================================================================
 * ASYNC TASK WORKERS
 * ============================================================================ */

/* Task: Get all addresses */
static void task_get_addressbook(void *data) {
    addressbook_task_t *task = (addressbook_task_t*)data;
    if (!task) return;

    dna_addressbook_entry_t *entries = NULL;
    int count = 0;
    int error = 0;

    /* Initialize address book database if needed */
    if (addressbook_db_init(task->engine->fingerprint) != 0) {
        error = -1;
    } else {
        addressbook_list_t *list = NULL;
        if (addressbook_db_list(&list) == 0 && list) {
            entries = convert_addressbook_list(list, &count);
            addressbook_db_free_list(list);
        } else {
            error = -1;
        }
    }

    if (task->callback) {
        task->callback(0, error, entries, count, task->user_data);
    }

    free(task);
}

/* Task: Get addresses by network */
static void task_get_addressbook_by_network(void *data) {
    addressbook_task_t *task = (addressbook_task_t*)data;
    if (!task) return;

    dna_addressbook_entry_t *entries = NULL;
    int count = 0;
    int error = 0;

    /* Initialize address book database if needed */
    if (addressbook_db_init(task->engine->fingerprint) != 0) {
        error = -1;
    } else {
        addressbook_list_t *list = NULL;
        if (addressbook_db_list_by_network(task->network, &list) == 0 && list) {
            entries = convert_addressbook_list(list, &count);
            addressbook_db_free_list(list);
        } else {
            error = -1;
        }
    }

    if (task->callback) {
        task->callback(0, error, entries, count, task->user_data);
    }

    free(task);
}

/* Task: Get recent addresses */
static void task_get_recent_addresses(void *data) {
    addressbook_task_t *task = (addressbook_task_t*)data;
    if (!task) return;

    dna_addressbook_entry_t *entries = NULL;
    int count = 0;
    int error = 0;

    /* Initialize address book database if needed */
    if (addressbook_db_init(task->engine->fingerprint) != 0) {
        error = -1;
    } else {
        addressbook_list_t *list = NULL;
        if (addressbook_db_get_recent(task->limit, &list) == 0 && list) {
            entries = convert_addressbook_list(list, &count);
            addressbook_db_free_list(list);
        } else {
            error = -1;
        }
    }

    if (task->callback) {
        task->callback(0, error, entries, count, task->user_data);
    }

    free(task);
}

/* ============================================================================
 * ASYNC PUBLIC API
 * ============================================================================ */

/* Async: Get all addresses */
dna_request_id_t dna_engine_get_addressbook(
    dna_engine_t *engine,
    dna_addressbook_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded || !callback) {
        if (callback) {
            callback(0, -1, NULL, 0, user_data);
        }
        return 0;
    }

    addressbook_task_t *task = calloc(1, sizeof(addressbook_task_t));
    if (!task) {
        callback(0, -1, NULL, 0, user_data);
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;

    /* Run synchronously for now (can be made async with thread pool if needed) */
    task_get_addressbook(task);
    return 1;
}

/* Async: Get addresses by network */
dna_request_id_t dna_engine_get_addressbook_by_network(
    dna_engine_t *engine,
    const char *network,
    dna_addressbook_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded || !network || !callback) {
        if (callback) {
            callback(0, -1, NULL, 0, user_data);
        }
        return 0;
    }

    addressbook_task_t *task = calloc(1, sizeof(addressbook_task_t));
    if (!task) {
        callback(0, -1, NULL, 0, user_data);
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;
    strncpy(task->network, network, sizeof(task->network) - 1);

    task_get_addressbook_by_network(task);
    return 1;
}

/* Async: Get recent addresses */
dna_request_id_t dna_engine_get_recent_addresses(
    dna_engine_t *engine,
    int limit,
    dna_addressbook_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded || limit <= 0 || !callback) {
        if (callback) {
            callback(0, -1, NULL, 0, user_data);
        }
        return 0;
    }

    addressbook_task_t *task = calloc(1, sizeof(addressbook_task_t));
    if (!task) {
        callback(0, -1, NULL, 0, user_data);
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;
    task->limit = limit;

    task_get_recent_addresses(task);
    return 1;
}

/* DHT Sync moved to src/api/engine/dna_engine_backup.c */
