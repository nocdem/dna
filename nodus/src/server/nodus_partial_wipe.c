/**
 * Nodus — the partial-wipe boot gate (H-10, PR 3 / E5)
 *
 * Moved out of nodus_server.c unchanged (split S5b; see
 * nodus_partial_wipe.h). The refusal message keeps the "NODUS_SRV" prefix
 * it always had, in core and in nodus-storage alike.
 *
 * @file nodus_partial_wipe.c
 */

#include "server/nodus_partial_wipe.h"
#include "witness/nodus_witness_host.h"   /* NODUS_PARTIAL_WIPE_GENESIS_MARKER */

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "NODUS_SRV"

int nodus_server_check_partial_wipe(const char *data_path) {
    if (!data_path) return -1;

    /* If the orphan-bootstrap sentinel (.bootstrap_in_progress) is
     * present the previous bootstrap's FETCH_GENESIS crashed mid-
     * write. The downstream witness init runs E0
     * (nodus_witness_check_orphan_bootstrap_sentinel) which archives
     * any partial witness_*.db, clears the sentinel, and lets
     * DISCOVER restart. If we run the strict-XOR gate first, the
     * crashed-mid-bootstrap state (marker present, only the partial
     * witness file present) trips the gate and we never reach the
     * E0 cleanup — operator has to manually clear sentinel + wipe.
     * The orphan sentinel takes precedence; defer to E0. */
    char sentinel[640];
    int ns = snprintf(sentinel, sizeof(sentinel),
                      "%s/.bootstrap_in_progress", data_path);
    if (ns > 0 && (size_t)ns < sizeof(sentinel)) {
        struct stat sst;
        if (stat(sentinel, &sst) == 0) return 0;
    }

    /* The strict XOR invariant only applies AFTER the chain DB has
     * been created at least once. Without the marker, the file-level
     * state (nodus.db + channels.db present, witness_*.db absent) is
     * the legitimate mid-bootstrap state — stagef_up.sh's identity-gen
     * pre-spawn produces it, and a real production node can land
     * there too if it crashes between storage_open and the first
     * FETCH_GENESIS commit. Gating on the marker prevents false
     * positives in both cases without weakening the post-genesis
     * operator-mistake detection. */
    char marker[640];
    int nm = snprintf(marker, sizeof(marker), "%s/%s",
                      data_path, NODUS_PARTIAL_WIPE_GENESIS_MARKER);
    if (nm < 0 || (size_t)nm >= sizeof(marker)) return -1;

    struct stat mst;
    if (stat(marker, &mst) != 0) {
        /* No marker: pre-genesis state (or operator wiped marker +
         * everything, which is the intended fresh-restart path). Any
         * subset of the 3 DB files is allowed. */
        return 0;
    }

    char nodus_db[640];
    char channels_db[640];
    int n1 = snprintf(nodus_db, sizeof(nodus_db),
                      "%s/nodus.db", data_path);
    int n2 = snprintf(channels_db, sizeof(channels_db),
                      "%s/channels.db", data_path);
    if (n1 < 0 || (size_t)n1 >= sizeof(nodus_db) ||
        n2 < 0 || (size_t)n2 >= sizeof(channels_db))
        return -1;

    struct stat st;
    int has_nodus    = (stat(nodus_db,    &st) == 0) ? 1 : 0;
    int has_channels = (stat(channels_db, &st) == 0) ? 1 : 0;

    /* Witness DB filename is chain-id-suffixed and not known until
     * genesis lands, so scan for any witness_<hex>.db (excluding the
     * -wal / -shm sidecars whose presence alone is not enough — they
     * vanish on clean shutdown). */
    int has_witness = 0;
    DIR *dir = opendir(data_path);
    if (dir) {
        struct dirent *e;
        while ((e = readdir(dir)) != NULL) {
            if (strncmp(e->d_name, "witness_", 8) != 0) continue;
            size_t len = strlen(e->d_name);
            if (len < 11) continue;  /* "witness_" + at least 1 char + ".db" */
            if (strcmp(e->d_name + len - 3, ".db") != 0) continue;
            has_witness = 1;
            break;
        }
        closedir(dir);
    }

    int present = has_nodus + has_channels + has_witness;
    if (present == 0 || present == 3) return 0;

    fprintf(stderr,
        "%s: PARTIAL WIPE DETECTED at %s — "
        "nodus.db=%s channels.db=%s witness_*.db=%s "
        "(genesis marker " NODUS_PARTIAL_WIPE_GENESIS_MARKER " present). "
        "REFUSING START. After this node has crossed genesis the 3 "
        "SQLite DBs MUST be all-present (normal boot) or all-absent "
        "(treated as fresh-restart). Investigate the missing file(s); "
        "restore from backup, OR wipe ALL 3 DBs (keep the marker) to "
        "trigger a clean re-bootstrap from peers, OR wipe ALL 3 DBs "
        "AND the marker to force a fresh first-boot path.\n",
        LOG_TAG, data_path,
        has_nodus    ? "yes" : "MISSING",
        has_channels ? "yes" : "MISSING",
        has_witness  ? "yes" : "MISSING");
    return -1;
}
