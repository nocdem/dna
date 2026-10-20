/**
 * @file nodus/tests/test_seg_file_win.c
 * @brief Windows test of the portable segment files — package P-B4 of
 *        docs/plans/2026-10-19-windows-light-storage-design.md (§3 "Rev 1
 *        corrections", B4): the file layer storage/nodus_fs.{c,h} and the
 *        segment file (witness/nodus_witness_storage_segment.c) on its
 *        Windows arm. The Linux side is test_storage_segment.c.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *  A. nodus_fs (no fixture needed):
 *   1. positional I/O: bytes written at offset 0 and across the 2^31
 *      boundary (2^31 − 8 … 2^31 + 8) read back from the same offsets, a
 *      read starting at the end of the file says "end of file" (1), a read
 *      running past it says 1, nodus_fs_size is 2^31 + 8, fsync answers 0;
 *      nodus_fs_read_once on a fresh descriptor returns the first bytes.
 *      ⚠ An offset at or above 2^32 (OffsetHigh != 0) is NOT tested: on
 *      NTFS a write there allocates the whole 4 GiB unless the file is
 *      made sparse (another API, not used here) — the 2^31 case already
 *      allocates ≈ 2 GiB on NTFS for the duration of the case.
 *   2. truncate cuts the file to the requested size.
 *   3. rename-replace: a rename onto an existing file replaces it (the
 *      target holds the source's bytes, the source is gone) — also when
 *      the source is STILL OPEN through a descriptor (the segment build's
 *      order: .dat.tmp → .dat before its close), and that descriptor still
 *      writes into the renamed file.
 *   4. unlink-if-exists: an existing file goes, an absent one is not an
 *      error, a file with an open descriptor can be unlinked (gone after
 *      the close).
 *   5. mkdir / mkdir -p: three missing levels created, a second mkdir -p is
 *      0, mkdir on an existing directory is -1 with errno EEXIST, mkdir -p
 *      over a FILE is -1; is_dir says 1 / 0 / -1.
 *   6. UTF-8 names: a file named "Çağrı" (UTF-8) in a directory named
 *      "Çağrı-dir" is written, found by exists and read back by the same
 *      UTF-8 name; a path that is not valid UTF-8 is refused (-1, EINVAL).
 *   7. an absent file opened for reading is -1 with errno ENOENT — the
 *      segment reader's "not held" (1) versus "fault" (-1) rests on it;
 *      the directory sync answers 0 (a documented no-op on Windows).
 *  B. the segment READER on a real segment file made on Linux (fixture):
 *   8. nodus_seg_held == 1, nodus_seg_reader_open == 0, flags 0x01; for
 *      every height in expected.bin: header(h+1) and every stored part
 *      proto equal the Linux fixture store's bytes; the terminal commit and
 *      the set record equal them too.
 *  C. the segment BUILD on Windows from the same pieces (fixture):
 *   9. segment k rebuilt piece by piece (pieces read from the fixture with
 *      the reader) into a fresh directory, INTERRUPTED half way (build
 *      freed), reopened (the resume scan re-verifies the partial file),
 *      finished: the new seg-<k>.dat / .idx / .ok are byte-identical to
 *      the fixture's. Then the marker is deleted (a publication cut short
 *      before the marker): not held; a reopen moves .dat back to .dat.tmp
 *      (a rename), the resume scan finds it complete, finish publishes the
 *      same three files again, byte-identical.
 *
 * THE FIXTURE (cases 8 and 9): a directory holding seg-<k>.dat, .idx, .ok
 *   and expected.bin, made on Linux by the Linux test's producer case:
 *     cd nodus/build && NODUS_SEG_WIN_FIXTURE=/tmp/segfx ./test_storage_segment
 *   (case "win_fixture"; it copies segment 1 as the roundtrip case
 *   published it and writes expected.bin from the fixture STORE — layout in
 *   test_storage_segment.c above t_win_fixture). Copy the directory to the
 *   Windows machine and pass it: test_seg_file_win.exe <dir>.
 *   ⚠ The fixture and this .exe must be built with the SAME
 *   DNAC_EPOCH_LENGTH (the index length depends on it,
 *   nodus_witness_storage_segment.h NODUS_SEG_INDEX_LEN): a short-epoch
 *   fixture reads as "not held" in a default-epoch .exe — case 8 FAILS
 *   with a note, it never passes.
 *
 * REQUIRES: compile — a Windows build of nodus (nodus/README.md "Windows
 *   cross build", llvm-mingw; target test_seg_file_win, linked -static);
 *   environment — none. Run natively on Windows or under Wine. Disk: ≈ 2 GiB
 *   free on NTFS for case 1 (see above), plus ≈ 2 × the fixture size.
 *
 * EXIT: 0 every case ran and passed; 1 a case failed; 2 the nodus_fs
 *   cases passed but no fixture was given — cases 8 and 9 print
 *   "SKIPPED: no fixture". A SKIP IS NOT A PASS: exit 2 means the segment
 *   file itself was not exercised on this platform.
 *
 * LEAVES BEHIND: nothing on success — the work directory
 *   (%TEMP%\nodus_seg_win_<pid>) and everything in it are removed; on a
 *   failure the directory is kept and its path printed. The fixture
 *   directory is only read.
 *
 * HOW IT CAN LIE:
 *   · WINE IS NOT WINDOWS. Under Wine, CreateFileW sharing modes,
 *     MoveFileExW over an open file, unlink of an open file
 *     (FILE_SHARE_DELETE), ReadFile's end-of-file answer, _commit and the
 *     '/' separator inside a wide path are Wine's emulation over the Linux
 *     kernel (ext4: sparse files, POSIX rename / unlink of open files). A
 *     PASS under Wine proves the logic against Wine; cases 1, 3 and 4 in
 *     particular must be run on native Windows (NTFS) before Windows is
 *     claimed (design §3 B4: "interrupted-publication + restart test on
 *     Windows before claiming Windows").
 *   · Durability is not tested: fsync, WRITE_THROUGH and the directory-sync
 *     no-op are only called, never followed by a power cut.
 *   · Case 9's HASH SOURCE is derived from the fixture's own headers
 *     (hash(h+1) = cmt_header_hash(header(h+1)), hash(first) =
 *     header(first+1).last_block_id.hash): the build's verification is
 *     exercised but proves nothing about the hashes — the case tests the
 *     Windows WRITE path (open, positional writes, truncate, the publish
 *     order, the rename while open), not trust. Byte identity with the
 *     fixture is the check.
 *   · Case 8 compares the reader with expected.bin, which the Linux
 *     producer wrote from the fixture STORE; four heights are sampled
 *     (1, 7, P/2, P), not every height. Case 9 reads every height.
 *   · Mixed separators ("…\nodus_seg_win_1/seg-1.dat") are accepted by the
 *     Win32 file API in this file's reading — not verified against
 *     Microsoft's documentation; a failure shows as an open failure.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>
#include <wchar.h>

#include "storage/nodus_fs.h"
#include "witness/nodus_witness_storage_segment.h"

#include "dnac/cmt_block.h"
#include "dnac/cmt_pb.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while (0)
#define CHECK(c)   do { if (!(c)) { ok = 0; printf("\n    check failed: %s (line %d)", #c, __LINE__); } } while (0)
#define DONE()     do { if (ok) { printf("PASS\n"); passed++; } \
                        else { printf("\n    FAIL\n"); failed++; } } while (0)

#define WPATH_MAX 1024
#define PATH_CAP  NODUS_SEG_PATH_MAX

static char g_work[PATH_CAP];           /* %TEMP%\nodus_seg_win_<pid>       */

/* ── small helpers ───────────────────────────────────────────────────── */

static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int join(char *out, size_t cap, const char *a, const char *b) {
    int n = snprintf(out, cap, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* Write `len` bytes as the whole file (nodus_fs). @return 0 / -1 */
static int put_file(const char *path, const void *p, size_t len) {
    int fd = nodus_fs_open_write_trunc(path);
    if (fd < 0) return -1;
    int ok = nodus_fs_pwrite_all(fd, (const uint8_t *)p, len, 0) == 0 &&
             nodus_fs_fsync(fd) == 0;
    if (nodus_fs_close(fd) != 0) ok = 0;
    return ok ? 0 : -1;
}

/* The whole file into a malloc'd buffer (nodus_fs). NULL on failure. */
static uint8_t *get_file(const char *path, size_t *len) {
    int fd = nodus_fs_open_read(path);
    if (fd < 0) return NULL;
    uint64_t sz = 0;
    uint8_t *b = NULL;
    if (nodus_fs_size(fd, &sz) == 0 && sz < ((uint64_t)1 << 31)) {
        b = malloc(sz ? (size_t)sz : 1);
        if (b && nodus_fs_pread_all(fd, b, (size_t)sz, 0) != 0) {
            free(b);
            b = NULL;
        }
    }
    nodus_fs_close(fd);
    if (b) *len = (size_t)sz;
    return b;
}

static int same_file(const char *a, const char *b) {
    size_t la = 0, lb = 0;
    uint8_t *x = get_file(a, &la), *y = get_file(b, &lb);
    int eq = x && y && la == lb && memcmp(x, y, la) == 0;
    free(x);
    free(y);
    return eq;
}

/* Remove an (empty) directory by its UTF-8 name. */
static int rm_dir(const char *path) {
    wchar_t w[WPATH_MAX];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, w,
                            WPATH_MAX) <= 0)
        return -1;
    return _wrmdir(w);
}

static int work_path(char *out, const char *name) {
    return join(out, PATH_CAP, g_work, name);
}

/* ══ A. nodus_fs ═══════════════════════════════════════════════════════ */

static void t_offsets(void) {
    int ok = 1;
    char p[PATH_CAP];
    const uint64_t big = (uint64_t)1 << 31;
    uint8_t a[16], b[16], r[32];
    for (int i = 0; i < 16; i++) {
        a[i] = (uint8_t)(0xA0 + i);
        b[i] = (uint8_t)(0x30 + i * 7);
    }
    TEST("1 positional I/O at 0 and across 2^31; EOF; size; fsync");
    CHECK(work_path(p, "offsets.bin") == 0);
    int fd = nodus_fs_open_rw_create(p);
    CHECK(fd >= 0);
    if (fd >= 0) {
        uint64_t sz = 0;
        CHECK(nodus_fs_pwrite_all(fd, a, sizeof(a), 0) == 0);
        CHECK(nodus_fs_pwrite_all(fd, b, sizeof(b), big - 8u) == 0);
        CHECK(nodus_fs_fsync(fd) == 0);
        CHECK(nodus_fs_size(fd, &sz) == 0 && sz == big + 8u);
        memset(r, 0, sizeof(r));
        CHECK(nodus_fs_pread_all(fd, r, 16, big - 8u) == 0 &&
              memcmp(r, b, 16) == 0);
        CHECK(nodus_fs_pread_all(fd, r, 8, big) == 0 &&
              memcmp(r, b + 8, 8) == 0);
        CHECK(nodus_fs_pread_all(fd, r, 16, 0) == 0 && memcmp(r, a, 16) == 0);
        CHECK(nodus_fs_pread_all(fd, r, 1, big + 8u) == 1);
        CHECK(nodus_fs_pread_all(fd, r, 32, big - 8u) == 1);
        /* 2. truncate */
        CHECK(nodus_fs_truncate(fd, 10) == 0);
        CHECK(nodus_fs_size(fd, &sz) == 0 && sz == 10u);
        CHECK(nodus_fs_pread_all(fd, r, 11, 0) == 1);
        CHECK(nodus_fs_close(fd) == 0);
    }
    fd = nodus_fs_open_read(p);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(nodus_fs_read_once(fd, r, sizeof(r)) == 10 &&
              memcmp(r, a, 10) == 0);
        nodus_fs_close(fd);
    }
    CHECK(nodus_fs_unlink_if_exists(p) == 0);
    DONE();
}

static void t_rename(void) {
    int ok = 1;
    char a[PATH_CAP], b[PATH_CAP];
    uint8_t r[16];
    TEST("3 rename-replace, also with the source still open");
    CHECK(work_path(a, "target.bin") == 0 && work_path(b, "source.bin") == 0);
    CHECK(put_file(a, "old-old", 7) == 0 && put_file(b, "new", 3) == 0);
    CHECK(nodus_fs_rename(b, a) == 0);
    CHECK(!nodus_fs_exists(b));
    {
        size_t n = 0;
        uint8_t *x = get_file(a, &n);
        CHECK(x && n == 3 && memcmp(x, "new", 3) == 0);
        free(x);
    }
    /* the build's order: rename while its descriptor is open, write on */
    int fd = nodus_fs_open_rw_create(b);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(nodus_fs_pwrite_all(fd, (const uint8_t *)"abc", 3, 0) == 0);
        CHECK(nodus_fs_rename(b, a) == 0);
        CHECK(nodus_fs_pwrite_all(fd, (const uint8_t *)"def", 3, 3) == 0);
        CHECK(nodus_fs_fsync(fd) == 0);
        CHECK(nodus_fs_close(fd) == 0);
    }
    CHECK(!nodus_fs_exists(b));
    fd = nodus_fs_open_read(a);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(nodus_fs_pread_all(fd, r, 6, 0) == 0 &&
              memcmp(r, "abcdef", 6) == 0);
        CHECK(nodus_fs_pread_all(fd, r, 7, 0) == 1);
        nodus_fs_close(fd);
    }
    CHECK(nodus_fs_unlink_if_exists(a) == 0);
    DONE();
}

static void t_unlink(void) {
    int ok = 1;
    char a[PATH_CAP];
    TEST("4 unlink-if-exists: present, absent, open");
    CHECK(work_path(a, "gone.bin") == 0);
    CHECK(put_file(a, "x", 1) == 0 && nodus_fs_exists(a));
    CHECK(nodus_fs_unlink_if_exists(a) == 0 && !nodus_fs_exists(a));
    CHECK(nodus_fs_unlink_if_exists(a) == 0);
    int fd = nodus_fs_open_rw_create(a);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(nodus_fs_unlink_if_exists(a) == 0);
        CHECK(nodus_fs_close(fd) == 0);
    }
    CHECK(!nodus_fs_exists(a));
    DONE();
}

static void t_mkdir(void) {
    int ok = 1;
    char d1[PATH_CAP], d2[PATH_CAP], d3[PATH_CAP], f[PATH_CAP];
    TEST("5 mkdir / mkdir -p / is_dir");
    CHECK(work_path(d1, "m1") == 0 && join(d2, PATH_CAP, d1, "m2") == 0 &&
          join(d3, PATH_CAP, d2, "m3") == 0);
    CHECK(nodus_fs_is_dir(d1) == -1);
    CHECK(nodus_fs_mkdir_p(d3) == 0);
    CHECK(nodus_fs_is_dir(d1) == 1 && nodus_fs_is_dir(d2) == 1 &&
          nodus_fs_is_dir(d3) == 1);
    CHECK(nodus_fs_mkdir_p(d3) == 0);
    errno = 0;
    CHECK(nodus_fs_mkdir(d3) == -1 && errno == EEXIST);
    CHECK(join(f, PATH_CAP, d3, "file") == 0 && put_file(f, "f", 1) == 0);
    CHECK(nodus_fs_is_dir(f) == 0);
    CHECK(nodus_fs_mkdir_p(f) == -1);
    CHECK(nodus_fs_unlink_if_exists(f) == 0);
    CHECK(rm_dir(d3) == 0 && rm_dir(d2) == 0 && rm_dir(d1) == 0);
    DONE();
}

static void t_utf8(void) {
    int ok = 1;
    /* "Çağrı" in UTF-8 */
    static const char name[] = "\xC3\x87" "a" "\xC4\x9F" "r" "\xC4\xB1";
    char d[PATH_CAP], f[PATH_CAP], dn[64];
    TEST("6 UTF-8 names (\"Cagri\" with its Turkish letters); bad UTF-8");
    snprintf(dn, sizeof(dn), "%s-dir", name);
    CHECK(work_path(d, dn) == 0 && join(f, PATH_CAP, d, name) == 0);
    CHECK(nodus_fs_mkdir_p(d) == 0 && nodus_fs_is_dir(d) == 1);
    CHECK(put_file(f, "utf8", 4) == 0);
    CHECK(nodus_fs_exists(f));
    {
        size_t n = 0;
        uint8_t *x = get_file(f, &n);
        CHECK(x && n == 4 && memcmp(x, "utf8", 4) == 0);
        free(x);
    }
    {
        char bad[PATH_CAP];
        CHECK(work_path(bad, "\xFF\xFE") == 0);
        errno = 0;
        CHECK(nodus_fs_open_write_trunc(bad) == -1 && errno == EINVAL);
        CHECK(!nodus_fs_exists(bad));
    }
    CHECK(nodus_fs_unlink_if_exists(f) == 0 && rm_dir(d) == 0);
    DONE();
}

static void t_absent(void) {
    int ok = 1;
    char a[PATH_CAP];
    TEST("7 absent file: ENOENT; directory sync 0");
    CHECK(work_path(a, "never-written.bin") == 0);
    errno = 0;
    CHECK(nodus_fs_open_read(a) == -1 && errno == ENOENT);
    CHECK(!nodus_fs_exists(a));
    CHECK(nodus_fs_dir_sync(g_work) == 0);
    DONE();
}

/* ══ B / C. the segment file (fixture) ═════════════════════════════════ */

typedef struct {
    uint8_t *buf;                       /* expected.bin                    */
    size_t   len;
    uint64_t k;
    uint32_t n;                         /* heights in it                   */
} fx_t;

static int fx_load(const char *dir, fx_t *fx) {
    char p[PATH_CAP];
    memset(fx, 0, sizeof(*fx));
    if (join(p, PATH_CAP, dir, "expected.bin") != 0) return -1;
    fx->buf = get_file(p, &fx->len);
    if (!fx->buf || fx->len < 28u ||
        memcmp(fx->buf, "NDS.SEGWINFX.v1", 15) != 0 || fx->buf[15] != 0)
        return -1;
    fx->k = be64(fx->buf + 16);
    fx->n = be32(fx->buf + 24);
    return fx->k == 0 ? -1 : 0;
}

/* A bounded cursor over expected.bin. */
static const uint8_t *fx_take(const fx_t *fx, size_t *off, size_t n) {
    if (n > fx->len - *off) return NULL;
    const uint8_t *p = fx->buf + *off;
    *off += n;
    return p;
}

static void t_reader(const char *dir, const fx_t *fx) {
    int ok = 1;
    nodus_seg_reader_t *r = NULL;
    uint8_t *hdr = malloc(NODUS_SEG_HEADER_MAX);
    uint8_t *part = malloc(NODUS_SEG_PART_PROTO_MAX);
    uint8_t *big = malloc(NODUS_SEG_COMMIT_MAX);
    TEST("8 reader on the Linux fixture: headers, parts, commit, set");
    CHECK(hdr && part && big);
    int held = nodus_seg_held(dir, fx->k);
    CHECK(held == 1);
    if (held != 1)
        printf("\n    note: not held — a fixture from a build with another "
               "DNAC_EPOCH_LENGTH (index length %u here)?",
               (unsigned)NODUS_SEG_INDEX_LEN);
    CHECK(nodus_seg_reader_open(dir, fx->k, &r) == 0);
    if (r && hdr && part && big) {
        CHECK(nodus_seg_reader_flags(r) == NODUS_SEG_FLAG_SIGS);
        size_t off = 28;
        for (uint32_t i = 0; ok && i < fx->n; i++) {
            const uint8_t *e = fx_take(fx, &off, 16);
            CHECK(e != NULL);
            if (!e) break;
            const uint64_t h = be64(e);
            const uint32_t np = be32(e + 8), hl = be32(e + 12);
            const uint8_t *eh = fx_take(fx, &off, hl);
            size_t gl = 0;
            uint32_t gn = 0;
            CHECK(eh != NULL);
            CHECK(nodus_seg_reader_get(r, h, hdr, &gl, &gn, 0, NULL, NULL) ==
                  0);
            CHECK(eh && gl == hl && gn == np && memcmp(hdr, eh, hl) == 0);
            for (uint32_t j = 0; ok && j < np; j++) {
                const uint8_t *pl = fx_take(fx, &off, 4);
                const uint8_t *pp = pl ? fx_take(fx, &off, be32(pl)) : NULL;
                size_t got = 0;
                CHECK(pp != NULL);
                CHECK(nodus_seg_reader_get(r, h, NULL, NULL, &gn, j, part,
                                           &got) == 0);
                CHECK(pp && got == be32(pl) && memcmp(part, pp, got) == 0);
            }
        }
        const uint8_t *cl = fx_take(fx, &off, 4);
        const uint8_t *cp = cl ? fx_take(fx, &off, be32(cl)) : NULL;
        size_t got = 0;
        CHECK(cp != NULL);
        CHECK(nodus_seg_reader_commit(r, big, NODUS_SEG_COMMIT_MAX, &got) ==
                  0 && cp && got == be32(cl) && memcmp(big, cp, got) == 0);
        const uint8_t *vl = fx_take(fx, &off, 4);
        const uint8_t *vp = vl ? fx_take(fx, &off, be32(vl)) : NULL;
        CHECK(vp != NULL);
        CHECK(nodus_seg_reader_valset(r, big, NODUS_SEG_VALSET_MAX, &got) ==
                  0 && vp && got == be32(vl) && memcmp(big, vp, got) == 0);
        CHECK(off == fx->len);
    }
    nodus_seg_reader_close(r);
    free(big);
    free(part);
    free(hdr);
    DONE();
}

/* The hash source of case 9: hashes derived from the fixture's headers. */
typedef struct {
    uint64_t first, last;
    uint8_t (*h)[64];                   /* h[x − first], x = first … last+1 */
} hsrc_t;

static int hsrc_at(void *ctx, uint64_t h, uint8_t out[64]) {
    const hsrc_t *s = (const hsrc_t *)ctx;
    if (!s || h < s->first || h > s->last + 1u) return 1;
    memcpy(out, s->h[h - s->first], 64);
    return 0;
}

static int hsrc_build(nodus_seg_reader_t *r, uint64_t k, hsrc_t *s) {
    const uint64_t P = (uint64_t)NODUS_SEG_COUNT;
    s->first = (k - 1u) * P + 1u;
    s->last = k * P;
    s->h = calloc((size_t)P + 1u, 64);
    uint8_t *hdr = malloc(NODUS_SEG_HEADER_MAX);
    cmt_pb_header_t *d = malloc(sizeof(*d));
    int ret = -1;
    if (!s->h || !hdr || !d) goto done;
    for (uint64_t x = s->first; x <= s->last; x++) {
        size_t hl = 0;
        uint32_t n = 0;
        if (nodus_seg_reader_get(r, x, hdr, &hl, &n, 0, NULL, NULL) != 0)
            goto done;
        cmt_pb_header_init(d);
        if (cmt_pb_header_unmarshal(hdr, hl, d) != CMT_OK ||
            cmt_header_hash(d, s->h[x + 1u - s->first]) != CMT_OK)
            goto done;
        if (x == s->first) {
            if (d->last_block_id.hash_len != 64) goto done;
            memcpy(s->h[0], d->last_block_id.hash, 64);
        }
    }
    ret = 0;
done:
    free(d);
    free(hdr);
    return ret;
}

/* Feed the build from the reader until it is complete or (stop_h != 0)
 * its next height is above stop_h. @return 0 / -1 */
static int feed(nodus_seg_build_t *b, nodus_seg_reader_t *r, uint64_t stop_h,
                uint8_t *io) {
    for (;;) {
        uint64_t h = 0;
        uint32_t part = 0, n = 0;
        bool need_hdr = false;
        size_t len = 0;
        int rc = nodus_seg_build_next(b, &h, &part, &need_hdr);
        if (rc == 1) return 0;
        if (rc != 0) return -1;
        nodus_seg_v_t v;
        if (part == NODUS_SEG_PART_VALSET) {
            if (nodus_seg_reader_valset(r, io, NODUS_SEG_COMMIT_MAX, &len) != 0)
                return -1;
            v = nodus_seg_build_put_valset(b, io, len);
        } else if (part == NODUS_SEG_PART_COMMIT) {
            if (nodus_seg_reader_commit(r, io, NODUS_SEG_COMMIT_MAX, &len) != 0)
                return -1;
            v = nodus_seg_build_put_commit(b, io, len);
        } else if (stop_h && h > stop_h) {
            return 0;
        } else if (need_hdr) {
            if (nodus_seg_reader_get(r, h, io, &len, &n, 0, NULL, NULL) != 0)
                return -1;
            v = nodus_seg_build_put_header(b, h, io, len);
        } else {
            if (nodus_seg_reader_get(r, h, NULL, NULL, &n, part, io, &len) != 0)
                return -1;
            v = nodus_seg_build_put_part_proto(b, h, part, io, len);
        }
        if (v != NODUS_SEG_V_OK) {
            printf("\n    build refused height %" PRIu64 " part %" PRIu32
                   ": %s", h, part, nodus_seg_v_str(v));
            return -1;
        }
    }
}

static int resume_all(nodus_seg_build_t *b) {
    int rc;
    while ((rc = nodus_seg_build_resume_step(b, 4096)) == 0) { }
    return rc == 1 ? 0 : -1;
}

static int same_three(const char *a, const char *b, uint64_t k) {
    static const nodus_seg_file_t f[3] = {
        NODUS_SEG_F_DAT, NODUS_SEG_F_IDX, NODUS_SEG_F_OK };
    for (int i = 0; i < 3; i++) {
        char x[PATH_CAP], y[PATH_CAP];
        if (nodus_seg_path(a, k, f[i], x, sizeof(x)) != 0 ||
            nodus_seg_path(b, k, f[i], y, sizeof(y)) != 0 || !same_file(x, y))
            return 0;
    }
    return 1;
}

static void t_build(const char *dir, const fx_t *fx) {
    int ok = 1;
    char out[PATH_CAP], p[PATH_CAP];
    nodus_seg_reader_t *r = NULL;
    nodus_seg_build_t *b = NULL;
    hsrc_t hs;
    memset(&hs, 0, sizeof(hs));
    uint8_t *io = malloc(NODUS_SEG_COMMIT_MAX);
    const uint64_t k = fx->k;
    TEST("9 build on Windows: interrupt, resume, publish, lost marker");
    CHECK(io != NULL);
    CHECK(work_path(out, "rebuild") == 0);
    CHECK(nodus_seg_reader_open(dir, k, &r) == 0);
    CHECK(r && hsrc_build(r, k, &hs) == 0);
    nodus_seg_hash_src_t src = { &hs, hsrc_at };
    if (ok) {
        /* first half, then the build is dropped (a stop mid-segment) */
        CHECK(nodus_seg_build_open_src(out, k, &src, &b) == 0);
        CHECK(b && resume_all(b) == 0);
        CHECK(b && feed(b, r, hs.first + (uint64_t)NODUS_SEG_COUNT / 2u, io) ==
              0);
        nodus_seg_build_free(b);
        b = NULL;
        CHECK(nodus_seg_held(out, k) == 0);
        /* reopen: the resume scan re-verifies the partial file */
        CHECK(nodus_seg_build_open_src(out, k, &src, &b) == 0);
        CHECK(b && resume_all(b) == 0);
        CHECK(b && feed(b, r, 0, io) == 0);
        /* finish frees the build on success only */
        CHECK(b && nodus_seg_build_finish(b) == 0 && (b = NULL) == NULL);
        CHECK(nodus_seg_held(out, k) == 1);
        CHECK(same_three(dir, out, k));
        /* the marker lost: not held; reopen gives .dat back to the scan */
        CHECK(nodus_seg_path(out, k, NODUS_SEG_F_OK, p, sizeof(p)) == 0 &&
              nodus_fs_unlink_if_exists(p) == 0);
        CHECK(nodus_seg_held(out, k) == 0);
        CHECK(nodus_seg_build_open_src(out, k, &src, &b) == 0);
        CHECK(b && resume_all(b) == 0);
        {
            uint64_t h = 0;
            uint32_t part = 0;
            bool need = false;
            CHECK(b && nodus_seg_build_next(b, &h, &part, &need) == 1);
        }
        CHECK(b && nodus_seg_build_finish(b) == 0 && (b = NULL) == NULL);
        CHECK(same_three(dir, out, k));
    }
    nodus_seg_build_free(b);
    nodus_seg_reader_close(r);
    if (ok) {
        CHECK(nodus_seg_delete(out, k) == 0 && rm_dir(out) == 0);
    }
    free(hs.h);
    free(io);
    DONE();
}

/* ── the work directory ──────────────────────────────────────────────── */

static int work_make(void) {
    wchar_t wt[MAX_PATH + 1];
    char t[PATH_CAP];
    DWORD n = GetTempPathW(MAX_PATH + 1, wt);
    if (n == 0 || n > MAX_PATH) return -1;
    if (WideCharToMultiByte(CP_UTF8, 0, wt, -1, t, (int)sizeof(t), NULL,
                            NULL) <= 0)
        return -1;
    int m = snprintf(g_work, sizeof(g_work), "%snodus_seg_win_%lu", t,
                     (unsigned long)GetCurrentProcessId());
    if (m < 0 || (size_t)m >= sizeof(g_work) - 64u) return -1;
    return nodus_fs_mkdir_p(g_work);
}

int main(int argc, char **argv) {
    printf("test_seg_file_win (nodus_fs + segment file, Windows)\n");
    if (work_make() != 0) {
        printf("  cannot create the work directory\n");
        return 1;
    }
    printf("  work directory: %s\n", g_work);
    t_offsets();
    t_rename();
    t_unlink();
    t_mkdir();
    t_utf8();
    t_absent();

    int skipped = 0;
    if (argc < 2 || !argv[1][0]) {
        printf("  8 reader on the Linux fixture                              "
               "SKIPPED: no fixture\n");
        printf("  9 build on Windows                                         "
               "SKIPPED: no fixture\n");
        skipped = 1;
    } else {
        fx_t fx;
        if (fx_load(argv[1], &fx) != 0) {
            printf("  fixture %s: expected.bin missing or malformed — FAIL\n",
                   argv[1]);
            failed++;
        } else {
            t_reader(argv[1], &fx);
            t_build(argv[1], &fx);
        }
        free(fx.buf);
    }

    if (failed == 0) {
        if (rm_dir(g_work) != 0)
            printf("  note: work directory not removed: %s\n", g_work);
    } else {
        printf("  work directory kept: %s\n", g_work);
    }
    printf("\n%d passed, %d failed%s\n", passed, failed,
           skipped ? ", 2 SKIPPED (no fixture) — NOT a pass" : "");
    if (failed) return 1;
    return skipped ? 2 : 0;
}
