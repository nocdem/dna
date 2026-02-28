/*
 * nodus_republish.h - Nodus v5 migration flag management
 *
 * When upgrading from OpenDHT v0.4 to Nodus v5, local data (contacts, groups,
 * GEKs, address book, profile) must be republished to the new DHT network.
 * This module manages a one-time migration flag so republish runs exactly once.
 *
 * Flag file: <data_dir>/.nodus_v5_migrated
 */

#ifndef NODUS_REPUBLISH_H
#define NODUS_REPUBLISH_H

/*
 * Check if Nodus v5 migration has already been completed.
 * Returns 1 if already migrated, 0 if migration needed, -1 on error.
 */
int nodus_republish_check_migrated(const char *data_dir);

/*
 * Mark Nodus v5 migration as complete by creating the flag file.
 * Returns 0 on success, -1 on error.
 */
int nodus_republish_mark_done(const char *data_dir);

#endif /* NODUS_REPUBLISH_H */
