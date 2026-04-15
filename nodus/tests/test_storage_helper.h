/**
 * Nodus — Shared Storage Test Fixture
 *
 * Provides unique-per-invocation on-disk SQLite DBs for storage tests,
 * plus full cleanup including WAL (`-wal`) and shared-memory (`-shm`)
 * sibling files that SQLite creates in WAL mode. Tests that used
 * hardcoded `/tmp/nodus_test_*.db` paths were fragile on shared
 * machines because `/tmp` has the sticky bit: leftover `-wal`/`-shm`
 * files owned by another user couldn't be removed and SQLite picked
 * them up on open.
 *
 * Two usage modes:
 *
 *   (a) Simple open/close — the 95% case:
 *       nodus_storage_t store;
 *       test_storage_open(&store);
 *       ...
 *       test_storage_close(&store);   // closes AND unlinks db+wal+shm
 *
 *   (b) Close/reopen on the same path (persistence tests):
 *       char path[32];
 *       test_storage_make_path(path, sizeof(path));
 *       nodus_storage_t s1; nodus_storage_open(path, &s1);
 *       ...; nodus_storage_close(&s1);
 *       nodus_storage_t s2; nodus_storage_open(path, &s2);
 *       ...; nodus_storage_close(&s2);
 *       test_storage_cleanup_path(path);
 */

#ifndef NODUS_TEST_STORAGE_HELPER_H
#define NODUS_TEST_STORAGE_HELPER_H

#include "core/nodus_storage.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* (a) Open a fresh storage backed by a unique mkstemp() file.
 * Returns 0 on success, -1 on error. */
int test_storage_open(nodus_storage_t *store);

/* (a) Close the storage AND unlink the underlying .db, .db-wal, .db-shm. */
void test_storage_close(nodus_storage_t *store);

/* (b) Allocate a unique path via mkstemp() for manual open/close cycles.
 * `buf` must be at least 32 bytes. The caller is responsible for calling
 * test_storage_cleanup_path(buf) once finished. Returns 0 on success. */
int test_storage_make_path(char *buf, size_t bufsz);

/* (b) Unlink the db, -wal, and -shm siblings for the given path. */
void test_storage_cleanup_path(const char *path);

#ifdef __cplusplus
}
#endif

#endif
