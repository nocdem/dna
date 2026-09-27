/**
 * Nodus — cometbft @709fd12b `libs/autofile` port (AutoFile, Group,
 * GroupReader) and the crc32c the consensus WAL records carry
 * (nodus_witness_cmt_autofile.h, nodus_witness_cmt_wal.h).
 * Governing record: docs/plans/decisions/2026-09-26-cmt-wal-file-group.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  · crc32c: the table built from Castagnoli 0x82f63b78 (Go 1.21.5
 *    hash/crc32/crc32.go:34) reproduces the Castagnoli column of Go's own
 *    golden table (hash/crc32/crc32_test.go:33-65, go1.21.5 — the library
 *    the reference calls, replay.go:20) for all 31 inputs; plus the
 *    RFC 3720 §B.4 vectors and the "123456789" check value as the
 *    decision names them (see HOW IT CAN LIE 1).
 *  · Group write classes: a small Write stays in the 40 KiB head buffer
 *    (file size unchanged, `Buffered` = n); FlushAndSync puts it in the
 *    file; a write larger than the buffer into an empty buffer goes
 *    straight to the file (bufio.go:679-682); a write that overflows a
 *    non-empty buffer flushes the filled buffer and keeps the rest.
 *  · checkHeadSizeLimit (group.go:252-266): below the limit nothing
 *    happens; at the limit the head is flushed, renamed to `wal.000`,
 *    max index +1, and the next write creates a fresh head.
 *  · checkTotalSizeLimit (group.go:268-299): at or above the limit the
 *    OLDEST file goes first, at most 4 per check, never the head; with
 *    only the head left the head stays ("may grow without bound").
 *  · the 5 s check ticker as a deadline: not due one ns early, due at the
 *    deadline, and the next deadline is the next point of the period grid
 *    after `now` (Go runtime/time.go:854-857).
 *  · readGroupInfo / reopen: the indexes come back from the directory
 *    and a reopened group appends to the same head.
 *  · GroupReader: reads across the rotated files into the head, EOF at
 *    the end of the last file, an empty read is "given empty slice", an
 *    index above max is EOF, and bytes flushed AFTER an EOF are read by
 *    the next call (nothing is sticky).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 *  Compile flags: the nodus default build. Environment: none. A writable
 *  current working directory.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 *  Nothing on success: each case removes its `test_cmt_autofile.XXXXXX`
 *  directory. A crashed run leaves that directory in the cwd.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The RFC 3720 §B.4 and "123456789" values are copied from the
 *     decision / dispatch text; the RFC itself is NOT on this machine,
 *     so they are not independently confirmed here. The Go golden
 *     vectors ARE on disk and are the grounded KAT. If the two blocks
 *     disagree, the RFC block is the one to re-check against the RFC.
 *  2. fsync is not observable from inside the process: FlushAndSync is
 *     checked only as "the bytes are in the file"; durability across a
 *     power cut is not tested.
 *  3. The limits are lowered on the handle (the reference's option
 *     functions, group.go:115-134); the shipped 10 MB / 1 GB magnitudes
 *     are not exercised.
 *
 * @file test_cmt_autofile.c
 */

#include "witness/nodus_witness_cmt_autofile.h"
#include "witness/nodus_witness_cmt_wal.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int g_checks = 0;

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

/* ══ fixture ═══════════════════════════════════════════════════════════ */

static void rmrf(const char *path)
{
    DIR *d = opendir(path);

    if (d) {
        struct dirent *ent;

        while ((ent = readdir(d)) != NULL) {
            char        child[1024];
            struct stat st;

            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    rmrf(child);
                } else {
                    (void)unlink(child);
                }
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    char dir[64];
    char head[128];
} fx_t;

static int fx_open(fx_t *fx)
{
    snprintf(fx->dir, sizeof(fx->dir), "test_cmt_autofile.XXXXXX");
    if (!mkdtemp(fx->dir)) {
        return -1;
    }
    snprintf(fx->head, sizeof(fx->head), "%s/wal", fx->dir);
    return 0;
}

/* -1 when the file does not exist */
static long long fsize(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 ? (long long)st.st_size : -1;
}

static long long fsize_idx(const fx_t *fx, int index)
{
    char p[160];

    snprintf(p, sizeof(p), "%s.%03d", fx->head, index);
    return fsize(p);
}

/* write `n` bytes of `fill` into `path`, replacing it */
static int put_file(const char *path, size_t n, int fill)
{
    FILE  *f = fopen(path, "wb");
    size_t i;

    if (!f) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (fputc(fill, f) == EOF) {
            fclose(f);
            return -1;
        }
    }
    return fclose(f) == 0 ? 0 : -1;
}

static uint32_t crc32c(const nodus_cmt_crc32_table_t tab, const void *p,
                       size_t n)
{
    return nodus_cmt_crc32_update(0, tab, (const uint8_t *)p, n);
}

/* ══ crc32c KATs ═══════════════════════════════════════════════════════ */

/* Go 1.21.5 hash/crc32/crc32_test.go:33-65 — `golden`, the Castagnoli
 * column (second field) with its input, copied verbatim. */
static const struct {
    uint32_t    castagnoli;
    const char *in;
} GO_GOLDEN[] = {
    { 0x0,        "" },
    { 0xc1d04330, "a" },
    { 0xe2a22936, "ab" },
    { 0x364b3fb7, "abc" },
    { 0x92c80a31, "abcd" },
    { 0xc450d697, "abcde" },
    { 0x53bceff1, "abcdef" },
    { 0xe627f441, "abcdefg" },
    { 0xa9421b7,  "abcdefgh" },
    { 0x2ddc99fc, "abcdefghi" },
    { 0xe6599437, "abcdefghij" },
    { 0xb2cc01fe, "Discard medicine more than two years old." },
    { 0xe28207f,  "He who has a shady past knows that nice guys finish last." },
    { 0xbe93f964, "I wouldn't marry him with a ten foot pole." },
    { 0x9e3be0c3, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave" },
    { 0xf505ef04, "The days of the digital watch are numbered.  -Tom Stoppard" },
    { 0x85d3dc82, "Nepal premier won't resign." },
    { 0xc5142380, "For every action there is an equal and opposite government program." },
    { 0x75eb77dd, "His money is twice tainted: 'taint yours and 'taint mine." },
    { 0x91ebe9f7, "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977" },
    { 0xf0b1168e, "It's a tiny change to the code and not completely disgusting. - Bob Manchek" },
    { 0x572b74e2, "size:  a.out:  bad magic" },
    { 0x8a58a6d5, "The major problem is with sendmail.  -Mark Horton" },
    { 0x9c426c50, "Give me a rock, paper and scissors and I will move the world.  CCFestoon" },
    { 0x735400a4, "If the enemy is within range, then so are you." },
    { 0xbec49c95, "It's well we cannot hear the screams/That we create in others' dreams." },
    { 0xa95a2079, "You remind me of a TV show, but that's all right: I watch it anyway." },
    { 0xde2e65c5, "C is as portable as Stonehedge!!" },
    { 0x297a88ed, "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley" },
    { 0x66ed1d8b, "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule" },
    { 0xdcded527, "How can you write a big system without C++?  -Paul Glick" },
};

static int t_crc32c_go_golden(void)
{
    nodus_cmt_crc32_table_t tab;
    size_t i;

    nodus_cmt_crc32_make_table(NODUS_CMT_CRC32C_POLY, tab);
    CHECK(NODUS_CMT_CRC32C_POLY == 0x82f63b78u, "crc32.go:34 Castagnoli");
    for (i = 0; i < sizeof(GO_GOLDEN) / sizeof(GO_GOLDEN[0]); i++) {
        CHECK(crc32c(tab, GO_GOLDEN[i].in, strlen(GO_GOLDEN[i].in)) ==
              GO_GOLDEN[i].castagnoli, GO_GOLDEN[i].in);
    }
    CHECK(i == 31, "all 31 golden rows");
    /* incremental == one shot (the reference only ever calls Checksum,
     * but update's contract is chaining) */
    {
        const char *s = GO_GOLDEN[11].in;
        size_t      n = strlen(s);
        uint32_t    c = nodus_cmt_crc32_update(0, tab, (const uint8_t *)s, 10);

        c = nodus_cmt_crc32_update(c, tab, (const uint8_t *)s + 10, n - 10);
        CHECK(c == GO_GOLDEN[11].castagnoli, "chained update");
    }
    return 0;
}

/* RFC 3720 §B.4 "CRC Examples" and the CRC-32C check value, as stated in
 * docs/plans/decisions/2026-09-26-cmt-wal-file-group.md item 2 and the
 * dispatch. NOT confirmed against the RFC text on this machine (HOW IT
 * CAN LIE 1). The §B.4 figures are the CRC as a 32-bit value. */
static int t_crc32c_rfc3720_as_stated(void)
{
    nodus_cmt_crc32_table_t tab;
    uint8_t buf[32];
    int     i;

    nodus_cmt_crc32_make_table(NODUS_CMT_CRC32C_POLY, tab);
    memset(buf, 0x00, sizeof(buf));
    CHECK(crc32c(tab, buf, 32) == 0x8A9136AAu, "32 bytes of 0x00");
    memset(buf, 0xFF, sizeof(buf));
    CHECK(crc32c(tab, buf, 32) == 0x62A8AB43u, "32 bytes of 0xFF");
    for (i = 0; i < 32; i++) {
        buf[i] = (uint8_t)i;
    }
    CHECK(crc32c(tab, buf, 32) == 0x46DD794Eu, "0x00..0x1F ascending");
    for (i = 0; i < 32; i++) {
        buf[i] = (uint8_t)(31 - i);
    }
    CHECK(crc32c(tab, buf, 32) == 0x113FDB5Cu, "0x1F..0x00 descending");
    CHECK(crc32c(tab, "123456789", 9) == 0xE3069283u, "check value 123456789");
    return 0;
}

/* ══ Group ═════════════════════════════════════════════════════════════ */

static int t_group_write_classes(void)
{
    fx_t              fx;
    nodus_cmt_group_t g;
    uint8_t          *big;
    uint8_t           small[100];

    CHECK(fx_open(&fx) == 0, "fixture");
    big = (uint8_t *)malloc(NODUS_CMT_GROUP_HEAD_BUF_SIZE + 5);
    CHECK(big != NULL, "alloc");
    memset(big, 0xAB, NODUS_CMT_GROUP_HEAD_BUF_SIZE + 5);
    memset(small, 0x11, sizeof(small));

    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "OpenGroup");
    CHECK(g.head_size_limit == NODUS_CMT_GROUP_HEAD_SIZE_LIMIT &&
          g.total_size_limit == NODUS_CMT_GROUP_TOTAL_SIZE_LIMIT &&
          g.group_check_duration_ns == NODUS_CMT_GROUP_CHECK_DURATION_NS &&
          g.head_buf_cap == 40960, "the reference's defaults (group.go:20-22, :93)");
    CHECK(g.min_index == 0 && g.max_index == 0, "empty dir: head is index 0");
    CHECK(fsize(fx.head) == 0, "the head file exists, empty (O_CREATE)");

    /* a buffered Write does not reach the file */
    CHECK(nodus_cmt_group_write(&g, small, 10) == CMT_OK, "Write 10");
    CHECK(nodus_cmt_group_buffered(&g) == 10 && fsize(fx.head) == 0,
          "buffered, not in the file");
    CHECK(nodus_cmt_group_flush_and_sync(&g) == CMT_OK, "FlushAndSync");
    CHECK(nodus_cmt_group_buffered(&g) == 0 && fsize(fx.head) == 10,
          "flushed into the file");

    /* bufio.go:679-682: larger than the buffer, buffer empty → direct */
    CHECK(nodus_cmt_group_write(&g, big, NODUS_CMT_GROUP_HEAD_BUF_SIZE + 5)
          == CMT_OK, "large Write");
    CHECK(nodus_cmt_group_buffered(&g) == 0 &&
          fsize(fx.head) == 10 + NODUS_CMT_GROUP_HEAD_BUF_SIZE + 5,
          "a large write into an empty buffer goes straight to the file");

    /* bufio.go:683-686: overflowing a non-empty buffer flushes the FULL
     * buffer and buffers the remainder */
    CHECK(nodus_cmt_group_write(&g, small, 100) == CMT_OK, "Write 100");
    CHECK(nodus_cmt_group_write(&g, big, NODUS_CMT_GROUP_HEAD_BUF_SIZE)
          == CMT_OK, "Write a buffer's worth");
    CHECK(fsize(fx.head) == 10 + (NODUS_CMT_GROUP_HEAD_BUF_SIZE + 5) +
                            NODUS_CMT_GROUP_HEAD_BUF_SIZE &&
          nodus_cmt_group_buffered(&g) == 100,
          "one full buffer flushed, 100 bytes still buffered");
    nodus_cmt_group_close(&g);
    CHECK(fsize(fx.head) == 10 + (NODUS_CMT_GROUP_HEAD_BUF_SIZE + 5) +
                            NODUS_CMT_GROUP_HEAD_BUF_SIZE + 100,
          "Close flushed the rest (group.go:161-169)");
    /* a second close is harmless */
    nodus_cmt_group_close(&g);

    free(big);
    rmrf(fx.dir);
    return 0;
}

static int t_group_rotate_and_reopen(void)
{
    fx_t              fx;
    nodus_cmt_group_t g;
    uint8_t           buf[150];
    char              p[160];

    CHECK(fx_open(&fx) == 0, "fixture");
    memset(buf, 0x22, sizeof(buf));
    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "OpenGroup");
    g.head_size_limit = 100;                    /* GroupHeadSizeLimit */

    /* below the limit: nothing */
    CHECK(nodus_cmt_group_write(&g, buf, 60) == CMT_OK &&
          nodus_cmt_group_flush_and_sync(&g) == CMT_OK, "60 bytes");
    CHECK(nodus_cmt_group_check_head_size_limit(&g) == CMT_OK &&
          g.max_index == 0 && fsize_idx(&fx, 0) == -1, "60 < 100: no rotation");

    /* the check reads the FILE size: 40 more buffered bytes (=100 with
     * the file's 60) do not count until flushed */
    CHECK(nodus_cmt_group_write(&g, buf, 40) == CMT_OK, "40 buffered");
    CHECK(nodus_cmt_group_check_head_size_limit(&g) == CMT_OK &&
          g.max_index == 0, "buffered bytes are not the head's size");
    CHECK(nodus_cmt_group_flush_and_sync(&g) == CMT_OK &&
          fsize(fx.head) == 100, "flushed: 100");

    /* at the limit (size >= limit, :263): RotateFile */
    CHECK(nodus_cmt_group_check_head_size_limit(&g) == CMT_OK, "check");
    CHECK(g.max_index == 1 && fsize_idx(&fx, 0) == 100 && fsize(fx.head) == -1,
          "head renamed to wal.000, max index 1, no head until the next open");
    /* the next write lands in a fresh head (lazy O_CREATE) */
    CHECK(nodus_cmt_group_write(&g, buf, 7) == CMT_OK &&
          nodus_cmt_group_flush_and_sync(&g) == CMT_OK && fsize(fx.head) == 7,
          "fresh head");
    /* a rotation flushes the buffer first (:309-311) */
    CHECK(nodus_cmt_group_write(&g, buf, 3) == CMT_OK &&
          nodus_cmt_group_rotate_file(&g) == CMT_OK, "RotateFile with 3 buffered");
    CHECK(g.max_index == 2 && fsize_idx(&fx, 1) == 10, "wal.001 got all 10 bytes");

    /* filePathForIndex (group.go:413-418) */
    CHECK(nodus_cmt_group_file_path_for_index(fx.head, 2, 2, p, sizeof(p)) == CMT_OK &&
          strcmp(p, fx.head) == 0, "the max index is the head path");
    CHECK(nodus_cmt_group_file_path_for_index(fx.head, 1, 2, p, sizeof(p)) == CMT_OK &&
          strlen(p) == strlen(fx.head) + 4 && strcmp(p + strlen(fx.head), ".001") == 0,
          "an older index is <head>.%03d");
    CHECK(nodus_cmt_group_file_path_for_index(fx.head, 1, 2, p, 4) == CMT_FAULT,
          "a path that does not fit is refused");

    /* reopen: readGroupInfo recovers the indexes; writes append */
    CHECK(nodus_cmt_group_write(&g, buf, 5) == CMT_OK, "5 buffered at close");
    nodus_cmt_group_close(&g);
    CHECK(fsize(fx.head) == 5, "close flushed into the new head");
    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "reopen");
    CHECK(g.min_index == 0 && g.max_index == 2, "indexes 0..2 from the directory");
    {
        nodus_cmt_group_info_t gi;

        CHECK(nodus_cmt_group_read_info(&g, &gi) == CMT_OK &&
              gi.min_index == 0 && gi.max_index == 2 &&
              gi.total_size == 100 + 10 + 5 && gi.head_size == 5,
              "GroupInfo: sizes summed over wal*, head separately");
    }
    CHECK(nodus_cmt_group_write(&g, buf, 4) == CMT_OK &&
          nodus_cmt_group_flush_and_sync(&g) == CMT_OK && fsize(fx.head) == 9,
          "a reopened group appends to the same head (O_APPEND)");
    nodus_cmt_group_close(&g);
    rmrf(fx.dir);
    return 0;
}

static int t_group_total_size_limit(void)
{
    fx_t              fx;
    nodus_cmt_group_t g;
    int               i;

    CHECK(fx_open(&fx) == 0, "fixture");
    /* six rotated files of 100 bytes (wal.000 … wal.005) and a head of 50 */
    for (i = 0; i < 6; i++) {
        char p[160];

        snprintf(p, sizeof(p), "%s.%03d", fx.head, i);
        CHECK(put_file(p, 100, 'a' + i) == 0, "rotated file");
    }
    CHECK(put_file(fx.head, 50, 'h') == 0, "head");
    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "OpenGroup");
    CHECK(g.min_index == 0 && g.max_index == 6, "0..6");

    /* total 650; limit 1000 → nothing */
    g.total_size_limit = 1000;
    CHECK(nodus_cmt_group_check_total_size_limit(&g) == CMT_OK &&
          fsize_idx(&fx, 0) == 100, "below the limit: nothing removed");

    /* limit 450: remove oldest while total >= limit — 650→550→450→350 */
    g.total_size_limit = 450;
    CHECK(nodus_cmt_group_check_total_size_limit(&g) == CMT_OK, "check");
    CHECK(fsize_idx(&fx, 0) == -1 && fsize_idx(&fx, 1) == -1 &&
          fsize_idx(&fx, 2) == -1 && fsize_idx(&fx, 3) == 100,
          "the three OLDEST went; the fourth stays (350 < 450)");

    /* at most maxFilesToRemove (4) per check (group.go:23, :276): limit 1
     * would need every rotated file gone; one check removes 3..5 (three
     * files) and then meets the head index and stops. */
    g.total_size_limit = 1;
    CHECK(nodus_cmt_group_check_total_size_limit(&g) == CMT_OK, "check 2");
    CHECK(fsize_idx(&fx, 3) == -1 && fsize_idx(&fx, 4) == -1 &&
          fsize_idx(&fx, 5) == -1 && fsize(fx.head) == 50,
          "every rotated file went; the head stays (never removed, :281-285)");
    CHECK(nodus_cmt_group_check_total_size_limit(&g) == CMT_OK &&
          fsize(fx.head) == 50, "only the head left, above the limit: kept");
    nodus_cmt_group_close(&g);
    rmrf(fx.dir);

    /* the 4-per-check cap on its own: eight rotated files, limit 1 */
    CHECK(fx_open(&fx) == 0, "fixture 2");
    for (i = 0; i < 8; i++) {
        char p[160];

        snprintf(p, sizeof(p), "%s.%03d", fx.head, i);
        CHECK(put_file(p, 10, 'a') == 0, "rotated file");
    }
    CHECK(put_file(fx.head, 10, 'h') == 0, "head");
    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "OpenGroup 2");
    g.total_size_limit = 1;
    CHECK(nodus_cmt_group_check_total_size_limit(&g) == CMT_OK, "check 3");
    CHECK(fsize_idx(&fx, 3) == -1 && fsize_idx(&fx, 4) == 10,
          "exactly four files removed in one check");
    nodus_cmt_group_close(&g);
    rmrf(fx.dir);
    return 0;
}

static int t_group_check_ticker(void)
{
    fx_t              fx;
    nodus_cmt_group_t g;
    uint8_t           buf[64];
    int64_t           dl = 0;
    const int64_t     t0 = 1700000000LL * 1000000000LL;
    const int64_t     P  = NODUS_CMT_GROUP_CHECK_DURATION_NS;

    CHECK(fx_open(&fx) == 0, "fixture");
    memset(buf, 0x33, sizeof(buf));
    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "OpenGroup");
    CHECK(!nodus_cmt_group_next_check_deadline(&g, &dl), "not armed before Start");
    CHECK(nodus_cmt_group_check_if_due(&g, t0 + 100 * P) == CMT_OK &&
          g.max_index == 0, "an unarmed ticker never fires");
    g.head_size_limit = 32;
    nodus_cmt_group_start(&g, t0);
    CHECK(nodus_cmt_group_next_check_deadline(&g, &dl) && dl == t0 + P,
          "OnStart: first tick at start + 5 s");
    CHECK(nodus_cmt_group_write(&g, buf, 64) == CMT_OK &&
          nodus_cmt_group_flush_and_sync(&g) == CMT_OK, "64 bytes in the head");
    CHECK(nodus_cmt_group_check_if_due(&g, t0 + P - 1) == CMT_OK &&
          g.max_index == 0, "one ns early: nothing");
    CHECK(nodus_cmt_group_check_if_due(&g, t0 + P) == CMT_OK &&
          g.max_index == 1 && fsize_idx(&fx, 0) == 64,
          "due: checkHeadSizeLimit rotated");
    CHECK(nodus_cmt_group_next_check_deadline(&g, &dl) && dl == t0 + 2 * P,
          "next tick one period later");
    /* a late wake-up drops the missed ticks (runtime/time.go:854-857) */
    CHECK(nodus_cmt_group_check_if_due(&g, t0 + 3 * P + 7) == CMT_OK &&
          nodus_cmt_group_next_check_deadline(&g, &dl) && dl == t0 + 4 * P,
          "late: next is the next grid point after now");
    nodus_cmt_group_stop(&g);
    CHECK(!nodus_cmt_group_next_check_deadline(&g, &dl), "OnStop disarms");
    nodus_cmt_group_close(&g);
    rmrf(fx.dir);
    return 0;
}

static int t_group_reader(void)
{
    fx_t                      fx;
    nodus_cmt_group_t         g;
    nodus_cmt_group_reader_t *gr;
    uint8_t                   out[64];
    size_t                    n = 0;
    int                       i;

    CHECK(fx_open(&fx) == 0, "fixture");
    gr = (nodus_cmt_group_reader_t *)calloc(1, sizeof(*gr));
    CHECK(gr != NULL, "alloc");
    CHECK(nodus_cmt_group_open(&g, fx.head) == CMT_OK, "OpenGroup");
    /* wal.000 = "ABCD", wal.001 = "EF", head = "GHI" */
    CHECK(nodus_cmt_group_write(&g, (const uint8_t *)"ABCD", 4) == CMT_OK &&
          nodus_cmt_group_rotate_file(&g) == CMT_OK, "file 0");
    CHECK(nodus_cmt_group_write(&g, (const uint8_t *)"EF", 2) == CMT_OK &&
          nodus_cmt_group_rotate_file(&g) == CMT_OK, "file 1");
    CHECK(nodus_cmt_group_write(&g, (const uint8_t *)"GHI", 3) == CMT_OK &&
          nodus_cmt_group_flush_and_sync(&g) == CMT_OK, "head");
    CHECK(g.max_index == 2, "three files");

    /* one read spanning all three files (group.go:476-495) */
    CHECK(nodus_cmt_group_new_reader(&g, 0, gr) == NODUS_CMT_GROUP_READ_OK, "NewReader(0)");
    CHECK(nodus_cmt_group_reader_read(gr, out, 9, &n) == NODUS_CMT_GROUP_READ_OK &&
          n == 9 && memcmp(out, "ABCDEFGHI", 9) == 0, "reads across the files");
    CHECK(nodus_cmt_group_reader_read(gr, out, 1, &n) == NODUS_CMT_GROUP_READ_EOF &&
          n == 0, "EOF at the end of the last file");
    /* bytes flushed after the EOF are read next — nothing sticks */
    CHECK(nodus_cmt_group_write(&g, (const uint8_t *)"JK", 2) == CMT_OK, "buffered JK");
    CHECK(nodus_cmt_group_reader_read(gr, out, 2, &n) == NODUS_CMT_GROUP_READ_EOF,
          "still buffered in the writer: not visible");
    CHECK(nodus_cmt_group_flush_and_sync(&g) == CMT_OK &&
          nodus_cmt_group_reader_read(gr, out, 2, &n) == NODUS_CMT_GROUP_READ_OK &&
          n == 2 && memcmp(out, "JK", 2) == 0, "flushed: visible");
    /* a short tail: some bytes, then EOF */
    CHECK(nodus_cmt_group_write(&g, (const uint8_t *)"L", 1) == CMT_OK &&
          nodus_cmt_group_flush_and_sync(&g) == CMT_OK, "L");
    CHECK(nodus_cmt_group_reader_read(gr, out, 4, &n) == NODUS_CMT_GROUP_READ_EOF &&
          n == 1 && out[0] == 'L', "a short read returns what it has with EOF");
    CHECK(nodus_cmt_group_reader_read(gr, out, 0, &n) == NODUS_CMT_GROUP_READ_EMPTY,
          "\"given empty slice\" (group.go:462-464)");
    nodus_cmt_group_reader_close(gr);

    /* starting at the middle file reads on into the head */
    CHECK(nodus_cmt_group_new_reader(&g, 1, gr) == NODUS_CMT_GROUP_READ_OK, "NewReader(1)");
    for (i = 0; i < 6; i++) {
        CHECK(nodus_cmt_group_reader_read(gr, out + i, 1, &n) == NODUS_CMT_GROUP_READ_OK &&
              n == 1, "byte by byte");
    }
    CHECK(memcmp(out, "EFGHIJ", 6) == 0, "file 1 then the head");
    nodus_cmt_group_reader_close(gr);

    /* above the max index: EOF (group.go:505-507) */
    CHECK(nodus_cmt_group_new_reader(&g, 3, gr) == NODUS_CMT_GROUP_READ_EOF,
          "index > max is EOF");
    nodus_cmt_group_reader_close(gr);
    nodus_cmt_group_close(&g);
    free(gr);
    rmrf(fx.dir);
    return 0;
}

/* ══ main ══════════════════════════════════════════════════════════════ */

typedef struct {
    const char *name;
    int (*fn)(void);
} t_case_t;

int main(void)
{
    static const t_case_t cases[] = {
        { "crc32c_go_golden",          t_crc32c_go_golden },
        { "crc32c_rfc3720_as_stated",  t_crc32c_rfc3720_as_stated },
        { "group_write_classes",       t_group_write_classes },
        { "group_rotate_and_reopen",   t_group_rotate_and_reopen },
        { "group_total_size_limit",    t_group_total_size_limit },
        { "group_check_ticker",        t_group_check_ticker },
        { "group_reader",              t_group_reader },
    };
    size_t i, failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    for (i = 0; i < ncases; i++) {
        int rc = cases[i].fn();

        fprintf(stderr, "%-32s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) {
            failed++;
        }
    }
    fprintf(stderr, "test_cmt_autofile: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
