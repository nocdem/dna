/*
 * nodus_republish.c - Nodus v5 migration flag management
 *
 * Simple file-based flag: <data_dir>/.nodus_v5_migrated
 * Presence of the file means migration is complete.
 */

#include "client/nodus_republish.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define MIGRATION_FLAG_FILE ".nodus_v5_migrated"

int nodus_republish_check_migrated(const char *data_dir) {
    if (!data_dir) return -1;

    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", data_dir, MIGRATION_FLAG_FILE);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;

    struct stat st;
    if (stat(path, &st) == 0) {
        return 1;  /* Flag exists — already migrated */
    }
    return 0;  /* Flag missing — migration needed */
}

int nodus_republish_mark_done(const char *data_dir) {
    if (!data_dir) return -1;

    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", data_dir, MIGRATION_FLAG_FILE);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    /* Write timestamp for debugging */
    fprintf(f, "migrated_at=%lld\n", (long long)time(NULL));
    fclose(f);
    return 0;
}
