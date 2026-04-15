/**
 * Nodus — Shared Storage Test Fixture (implementation)
 *
 * See test_storage_helper.h for rationale.
 */

#include "test_storage_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NODUS_TEST_PATH_TEMPLATE  "/tmp/nodus_test_fxXXXXXX"
#define NODUS_TEST_PATH_BUFSZ     32   /* template + NUL + slack */

/* ── Path-based helpers (mode (b)) ──────────────────────────────────── */

int test_storage_make_path(char *buf, size_t bufsz) {
    if (!buf || bufsz < sizeof(NODUS_TEST_PATH_TEMPLATE)) return -1;
    strcpy(buf, NODUS_TEST_PATH_TEMPLATE);
    int fd = mkstemp(buf);
    if (fd < 0) {
        perror("test_storage_make_path: mkstemp");
        buf[0] = '\0';
        return -1;
    }
    /* SQLite will reopen and initialize the empty file itself. */
    close(fd);
    return 0;
}

void test_storage_cleanup_path(const char *path) {
    if (!path || !path[0]) return;
    char sibling[64];
    unlink(path);
    snprintf(sibling, sizeof(sibling), "%s-wal", path);
    unlink(sibling);
    snprintf(sibling, sizeof(sibling), "%s-shm", path);
    unlink(sibling);
}

/* ── Handle-based helpers (mode (a)) ────────────────────────────────── */

/* Tiny fixed-size registry mapping a storage handle to the on-disk path
 * that was allocated for it. Tests are single-threaded and rarely hold
 * more than a couple of stores open at once; linear scan is fine. */
#define NODUS_TEST_STORAGE_SLOTS 8

typedef struct {
    nodus_storage_t *store;
    char path[NODUS_TEST_PATH_BUFSZ];
} slot_t;

static slot_t g_slots[NODUS_TEST_STORAGE_SLOTS];

static slot_t *find_slot(nodus_storage_t *store) {
    for (int i = 0; i < NODUS_TEST_STORAGE_SLOTS; i++) {
        if (g_slots[i].store == store) return &g_slots[i];
    }
    return NULL;
}

static slot_t *alloc_slot(void) {
    for (int i = 0; i < NODUS_TEST_STORAGE_SLOTS; i++) {
        if (g_slots[i].store == NULL) return &g_slots[i];
    }
    return NULL;
}

int test_storage_open(nodus_storage_t *store) {
    if (!store) return -1;

    slot_t *slot = alloc_slot();
    if (!slot) {
        fprintf(stderr, "test_storage_open: no free fixture slots\n");
        return -1;
    }

    if (test_storage_make_path(slot->path, sizeof(slot->path)) != 0) {
        return -1;
    }

    if (nodus_storage_open(slot->path, store) != 0) {
        fprintf(stderr, "test_storage_open: nodus_storage_open(%s) failed\n",
                slot->path);
        test_storage_cleanup_path(slot->path);
        slot->path[0] = '\0';
        return -1;
    }

    slot->store = store;
    return 0;
}

void test_storage_close(nodus_storage_t *store) {
    if (!store) return;

    nodus_storage_close(store);

    slot_t *slot = find_slot(store);
    if (!slot) return;

    test_storage_cleanup_path(slot->path);
    slot->store = NULL;
    slot->path[0] = '\0';
}
