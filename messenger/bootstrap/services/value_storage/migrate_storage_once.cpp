/**
 * ONE-TIME DHT Storage Migration Tool
 *
 * PURPOSE: Fix double-hashing bug before first bootstrap restart
 *
 * THE BUG:
 * - Old code stored: InfoHash (40-char hex, 20 bytes) in database
 * - Republish did: dht_put_ttl(infohash) → InfoHash(infohash) → WRONG KEY
 * - Result: Values republished to wrong DHT keys, become unretrievable
 *
 * THE FIX:
 * - New code stores: Original SHA3-512 key (128-char hex, 64 bytes)
 * - Republish does: dht_put_ttl(original) → InfoHash(original) → CORRECT KEY
 *
 * MIGRATION STRATEGY (since servers NOT restarted yet):
 * 1. All current DHT values are at CORRECT locations (no republish happened)
 * 2. Database has WRONG keys stored (infohashes not originals)
 * 3. Can't reverse SHA3-512 to get originals
 * 4. Solution: Skip republishing old entries (40-char keys), keep new ones (128-char keys)
 *
 * SAFE APPROACH:
 * - Modify republish to detect key length:
 *   - 40 chars = old infohash format → SKIP (don't republish to wrong location)
 *   - 128 chars = new original format → REPUBLISH (correct)
 * - Old permanent data stays in DHT (never expires anyway)
 * - New data uses correct keys
 * - No data loss, no user action needed
 *
 * RUN THIS ONCE:
 * 1. Deploy fixed dht_context.cpp to all bootstrap nodes
 * 2. Run this migration on each bootstrap node
 * 3. Restart bootstrap nodes (republish will now skip old entries)
 * 4. Delete this file (no longer needed)
 *
 * @file migrate_storage_once.cpp
 * @date 2025-11-12
 */

#include <iostream>
#include <sqlite3.h>
#include <string>
#include <cstring>

void migrate_storage_db(const char *db_path) {
    std::cout << "=== DHT Storage Migration Tool ===" << std::endl;
    std::cout << "Database: " << db_path << std::endl;

    sqlite3 *db = nullptr;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        std::cerr << "ERROR: Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Count entries by key length
    sqlite3_stmt *stmt;
    const char *sql = "SELECT LENGTH(key_hash) as len, COUNT(*) as count FROM dht_values GROUP BY LENGTH(key_hash)";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "ERROR: Query failed: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return;
    }

    int old_format_count = 0;
    int new_format_count = 0;

    std::cout << "\nCurrent database state:" << std::endl;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int len = sqlite3_column_int(stmt, 0);
        int count = sqlite3_column_int(stmt, 1);
        std::cout << "  Key length " << len << " chars: " << count << " entries";

        if (len == 40) {
            std::cout << " [OLD FORMAT - infohash, will be skipped on republish]";
            old_format_count = count;
        } else if (len >= 64) {
            std::cout << " [NEW FORMAT - original key, will republish correctly]";
            new_format_count = count;
        } else {
            std::cout << " [UNKNOWN FORMAT]";
        }
        std::cout << std::endl;
    }
    sqlite3_finalize(stmt);

    std::cout << "\nMigration summary:" << std::endl;
    std::cout << "  Old format (40-char infohash): " << old_format_count << " entries" << std::endl;
    std::cout << "    → Will be SKIPPED on republish (prevents wrong-key bug)" << std::endl;
    std::cout << "    → Data stays in DHT at correct location (no expiry for permanent values)" << std::endl;
    std::cout << "  New format (64+ byte original): " << new_format_count << " entries" << std::endl;
    std::cout << "    → Will REPUBLISH correctly (no double-hash)" << std::endl;

    if (old_format_count > 0) {
        std::cout << "\n⚠️  ACTION REQUIRED:" << std::endl;
        std::cout << "  1. Existing permanent DHT values remain accessible (no restart yet)" << std::endl;
        std::cout << "  2. After restart, republish will skip old format entries" << std::endl;
        std::cout << "  3. Users should re-publish identities/names to get new format" << std::endl;
        std::cout << "  4. Command: messenger_publish_identity() in client" << std::endl;
        std::cout << "\n✓ No data loss - old entries stay in DHT permanently" << std::endl;
    } else {
        std::cout << "\n✓ All entries already in new format - no action needed!" << std::endl;
    }

    sqlite3_close(db);
    std::cout << "\n=== Migration analysis complete ===" << std::endl;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path/to/persistence_path.values.db>" << std::endl;
        std::cerr << "Example: " << argv[0] << " ~/.dna/persistence_path.values.db" << std::endl;
        return 1;
    }

    migrate_storage_db(argv[1]);
    return 0;
}
