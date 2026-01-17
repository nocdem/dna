# PQ SQLite VFS Encryption - Implementation Plan

**Created:** 2026-01-16
**Status:** PENDING (saved for future integration)
**Target Version:** v0.5.0
**Estimated Duration:** ~7 days

---

## Summary

Transparent post-quantum encryption for all SQLite databases using a custom VFS layer with page-level AES-256-GCM encryption. The Local Encryption Key (LEK) is derived from the BIP39 master seed using SHAKE256 and stored encrypted with Kyber1024 KEM.

---

## Security Properties

| Property | Implementation |
|----------|----------------|
| PQ Key Derivation | SHAKE256 (256-bit quantum security) |
| Key Storage | Kyber1024 KEM (NIST Category 5) |
| Data Encryption | AES-256-GCM (128-bit quantum security) |
| Page Authentication | AEAD tag per page |
| Tampering Prevention | Page number in AAD |
| Memory Security | `qgp_secure_memzero()` |

---

## Key Hierarchy

```
BIP39 Mnemonic
    │
    ▼
Master Seed (64 bytes)
    │
    ▼
SHAKE256(master_seed || "dna-lek-v1", 32)
    │
    ▼
LEK (32 bytes) ──► Stored in keys/identity.lek (Kyber1024 encrypted)
    │
    ▼
Per-DB keys: SHAKE256(LEK || "messages", 32)
             SHAKE256(LEK || "contacts", 32)
             SHAKE256(LEK || "groups", 32)
             ...
```

---

## Encrypted Page Format

```
Plaintext:  4096 bytes (SQLite page)
Encrypted:  4124 bytes total
  ├─ Nonce:      12 bytes (page_number || random)
  ├─ Ciphertext: 4096 bytes
  └─ Tag:        16 bytes (AES-GCM auth)
```

---

## New Files to Create

| File | Purpose | Est. Lines |
|------|---------|------------|
| `crypto/sqlite/qgp_lek.h` | LEK derivation API | ~40 |
| `crypto/sqlite/qgp_lek.c` | LEK derivation (SHAKE256) | ~80 |
| `crypto/sqlite/lek_storage.h` | LEK file storage API | ~60 |
| `crypto/sqlite/lek_storage.c` | Kyber1024 encrypted LEK | ~250 |
| `crypto/sqlite/pq_vfs.h` | VFS encryption API | ~80 |
| `crypto/sqlite/pq_vfs.c` | 24 VFS callbacks | ~600 |
| `crypto/sqlite/db_migrate.h` | Migration API | ~40 |
| `crypto/sqlite/db_migrate.c` | Plaintext → encrypted | ~200 |

---

## Files to Modify

| File | Line | Change |
|------|------|--------|
| `src/api/dna_engine_internal.h` | ~486 | Add `uint8_t lek[32]`, `bool lek_available` |
| `src/api/dna_engine.c` | ~1633 | LEK derivation after DHT identity load |
| `message_backup.c` | 141 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `database/contacts_db.c` | 176 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `messenger/group_database.c` | 176 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `database/profile_cache.c` | 77 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `database/keyserver_cache.c` | 84 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `database/group_invitations.c` | 63 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `database/addressbook_db.c` | 171 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `dht/shared/dht_groups.c` | 287 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `dht/client/bootstrap_cache.c` | 66 | `sqlite3_open_v2(..., PQ_VFS_NAME)` |
| `CMakeLists.txt` | ~137 | Add `crypto/sqlite/` sources |

---

## Implementation Phases

### Phase 1: LEK Infrastructure

**qgp_lek.h:**
```c
#ifndef QGP_LEK_H
#define QGP_LEK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Derive Local Encryption Key from BIP39 master seed
 * Uses SHAKE256(master_seed || "dna-lek-v1", 32)
 */
int qgp_lek_derive(const uint8_t master_seed[64], uint8_t lek_out[32]);

/**
 * Derive per-database key from LEK
 * Uses SHAKE256(lek || "dna-dbkey-" || db_name, 32)
 */
int qgp_lek_derive_db_key(const uint8_t lek[32], const char *db_name, uint8_t db_key_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* QGP_LEK_H */
```

**Pattern source:** Copy from `crypto/bip39/seed_derivation.c:62-77`

### Phase 2: LEK Storage

**lek_storage.h:**
```c
#ifndef LEK_STORAGE_H
#define LEK_STORAGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LEK_STORAGE_FILE        "identity.lek"
#define LEK_STORAGE_KEM_CT_SIZE 1568    /* Kyber1024 ciphertext */
#define LEK_STORAGE_NONCE_SIZE  12      /* AES-256-GCM nonce */
#define LEK_STORAGE_TAG_SIZE    16      /* AES-256-GCM tag */
#define LEK_STORAGE_LEK_SIZE    32      /* LEK size */
#define LEK_STORAGE_TOTAL_SIZE  (LEK_STORAGE_KEM_CT_SIZE + \
                                 LEK_STORAGE_NONCE_SIZE + \
                                 LEK_STORAGE_TAG_SIZE + \
                                 LEK_STORAGE_LEK_SIZE)  /* 1628 bytes */

int lek_storage_save(const uint8_t lek[32], const uint8_t kem_pubkey[1568], const char *keys_dir);
int lek_storage_load(uint8_t lek_out[32], const uint8_t kem_privkey[3168], const char *keys_dir);
bool lek_storage_exists(const char *keys_dir);
int lek_storage_delete(const char *keys_dir);

#ifdef __cplusplus
}
#endif

#endif /* LEK_STORAGE_H */
```

**Pattern source:** Copy from `crypto/utils/seed_storage.c:72-280`

### Phase 3: VFS Core

**pq_vfs.h:**
```c
#ifndef PQ_VFS_H
#define PQ_VFS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_VFS_NAME "pq-encrypted"

/**
 * Register the PQ-encrypted VFS with SQLite
 * Must be called once at startup before any database opens
 */
int pq_vfs_register(void);

/**
 * Unregister the VFS (cleanup)
 */
void pq_vfs_unregister(void);

/**
 * Set encryption key for a database path
 * Must be called before opening the database
 */
int pq_vfs_set_key(const char *db_path, const uint8_t db_key[32]);

/**
 * Clear encryption key for a database path
 * Called after database close
 */
void pq_vfs_clear_key(const char *db_path);

/**
 * Check if VFS is registered
 */
bool pq_vfs_is_registered(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_VFS_H */
```

**VFS Callbacks to implement (24 total):**
- `xOpen` → Load key, wrap real file, set up encryption context
- `xRead` → Read encrypted page, decrypt, return plaintext
- `xWrite` → Encrypt page, write to file
- `xClose` → Secure wipe key, close underlying file
- `xDelete`, `xAccess`, `xFullPathname` → Pass-through
- `xRandomness`, `xSleep`, `xCurrentTime`, etc. → Pass-through

### Phase 4: Engine Integration

**dna_engine_internal.h addition (~line 486):**
```c
    /* Password protection (session state) */
    char *session_password;          /* Password for current session (NULL if unprotected) */
    bool keys_encrypted;             /* True if identity keys are password-protected */

    /* Database encryption (v0.5.0+) */
    uint8_t lek[32];                 /* Local Encryption Key for database encryption */
    bool lek_available;              /* True if LEK has been derived/loaded */
```

**dna_engine.c integration (~line 1633):**
```c
    /* Load DHT identity */
    messenger_load_dht_identity(fingerprint);

    /* Derive/load LEK for database encryption (v0.5.0+) */
    {
        char keys_dir[512];
        snprintf(keys_dir, sizeof(keys_dir), "%s/keys", engine->data_dir);

        /* Load KEM keys for LEK operations */
        qgp_key_t *kem_key = NULL;
        char kem_path[512];
        snprintf(kem_path, sizeof(kem_path), "%s/identity.kem", keys_dir);

        int load_rc;
        if (engine->keys_encrypted && engine->session_password) {
            load_rc = qgp_key_load_encrypted(kem_path, engine->session_password, &kem_key);
        } else {
            load_rc = qgp_key_load(kem_path, &kem_key);
        }

        if (load_rc == 0 && kem_key) {
            if (lek_storage_exists(keys_dir)) {
                /* Load existing LEK */
                if (lek_storage_load(engine->lek, kem_key->private_key, keys_dir) == 0) {
                    engine->lek_available = true;
                    QGP_LOG_INFO(LOG_TAG, "Loaded LEK for database encryption");
                }
            } else {
                /* Derive new LEK - need master seed */
                uint8_t master_seed[64];
                if (seed_storage_load(master_seed, kem_key->private_key, keys_dir) == 0) {
                    if (qgp_lek_derive(master_seed, engine->lek) == 0) {
                        lek_storage_save(engine->lek, kem_key->public_key, keys_dir);
                        engine->lek_available = true;
                        QGP_LOG_INFO(LOG_TAG, "Derived and saved LEK for database encryption");
                    }
                    qgp_secure_memzero(master_seed, sizeof(master_seed));
                }
            }
            qgp_key_free(kem_key);
        }

        /* Register VFS if LEK available */
        if (engine->lek_available) {
            pq_vfs_register();
        }
    }
```

### Phase 5: Migration

**db_migrate.h:**
```c
#ifndef DB_MIGRATE_H
#define DB_MIGRATE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if database needs migration (is plaintext)
 */
bool db_needs_migration(const char *db_path);

/**
 * Migrate plaintext database to encrypted
 * Creates .bak backup, encrypts, replaces original
 */
int db_migrate_to_encrypted(const char *db_path, const uint8_t db_key[32]);

#ifdef __cplusplus
}
#endif

#endif /* DB_MIGRATE_H */
```

**Migration strategy:**
1. Check first 16 bytes - if "SQLite format 3\0", it's plaintext
2. Create temp encrypted copy using SQLite backup API
3. Rename: original → .bak, temp → original
4. Delete .bak on success

### Phase 6: Database Integration

Each database file changes from:
```c
int rc = sqlite3_open_v2(db_path, &g_db,
    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
```

To:
```c
int rc = sqlite3_open_v2(db_path, &g_db,
    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
    pq_vfs_is_registered() ? PQ_VFS_NAME : NULL);
```

### Phase 7: CMake Integration

Add to `CMakeLists.txt` COMMON_SOURCES (~line 137):
```cmake
    crypto/sqlite/qgp_lek.c
    crypto/sqlite/lek_storage.c
    crypto/sqlite/pq_vfs.c
    crypto/sqlite/db_migrate.c
```

---

## Verification Plan

1. **Build test:** `cmake .. && make -j$(nproc)`
2. **Unit tests:** Create `tests/test_lek.c`, `tests/test_pq_vfs.c`
3. **Integration:** Create identity, send messages, restart, verify data
4. **Migration:** Backup v0.4.x DB, upgrade, verify migration
5. **Raw file check:** `xxd messages.db | head` should show encrypted data

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Data loss during migration | Backup .bak file, rollback on error |
| WAL mode issues | Encrypt both .db and .db-wal |
| Performance regression | Benchmark before/after |
| Cross-platform bugs | Test Linux, Windows, Android |

---

## Confidence Summary

| Component | Confidence | Evidence |
|-----------|------------|----------|
| LEK derivation | 95/100 | Exact pattern in seed_derivation.c:62-77 |
| LEK storage | 95/100 | Exact pattern in seed_storage.c:72-280 |
| VFS core | 85/100 | SQLite VFS well-documented, but complex |
| Migration | 80/100 | SQLite backup API standard |
| WAL mode | 75/100 | Needs thorough testing |

---

## Notes for Future Implementation

1. **Branch sync:** Before implementing, ensure all branch changes are merged
2. **Test on all platforms:** Linux, Windows, Android before merge
3. **Breaking change:** This affects database format - needs migration path
4. **Backward compatibility:** Old apps can't read new encrypted DBs
5. **Version check:** Consider version field in header for future format changes

---

## Related Documentation

- `docs/SECURITY_AUDIT.md` - Security review
- `docs/functions/crypto.md` - Crypto function reference
- `crypto/utils/seed_storage.c` - Pattern for Kyber1024+AES-GCM
- `crypto/bip39/seed_derivation.c` - Pattern for SHAKE256 derivation
