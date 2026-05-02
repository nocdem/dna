/**
 * Nodus — Faz 1.6 — recovery sentinel crash safety (concrete)
 *
 * Audit B-2: persisted sentinel at <data_path>/.recovery_in_progress
 * gates DB drop with crash safety.
 *
 * Sub-A: create writes file
 * Sub-B: check returns 1 (present) + correct halt_height
 * Sub-C: clear removes file → check returns 0 (absent)
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_sync.h"
#include "nodus/nodus_types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

int main(void) {
    printf("\nFaz 1.6 — recovery sentinel crash safety\n");

    /* Tmpdir for sentinel — never pollute /var/lib/nodus */
    char tmpdir[] = "/tmp/nodus_test_sentinel_XXXXXX";
    CHECK(mkdtemp(tmpdir) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", tmpdir);
    memset(w.chain_id, 0xC1, 32);

    /* Sub-A: create */
    CHECK_EQ(nodus_witness_recovery_sentinel_create(&w, /*halt_height*/42),
             0);

    char sentinel_path[512];
    snprintf(sentinel_path, sizeof(sentinel_path),
             "%s/.recovery_in_progress", tmpdir);
    struct stat st;
    CHECK_EQ(stat(sentinel_path, &st), 0);
    CHECK(st.st_size == 40);  /* 32B chain_id + 8B halt_height */
    printf("  sub-A: create wrote 40-byte sentinel ✓\n");

    /* Sub-B: check returns 1 + recovers halt_height */
    uint64_t recovered = 0;
    int rc = nodus_witness_recovery_sentinel_check(tmpdir, &recovered);
    CHECK_EQ(rc, 1);
    CHECK_EQ(recovered, 42);
    printf("  sub-B: check present + halt_height=42 ✓\n");

    /* Sub-C: clear → check returns 0 */
    CHECK_EQ(nodus_witness_recovery_sentinel_clear(&w), 0);
    rc = nodus_witness_recovery_sentinel_check(tmpdir, NULL);
    CHECK_EQ(rc, 0);
    printf("  sub-C: clear → absent ✓\n");

    /* Cleanup */
    rmdir(tmpdir);

    printf("Faz 1.6 PASS\n");
    return 0;
}
