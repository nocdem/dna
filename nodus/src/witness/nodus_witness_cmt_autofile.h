/**
 * @file nodus/src/witness/nodus_witness_cmt_autofile.h
 * @brief cometbft @v0.38.26 `libs/autofile` — `AutoFile` (autofile.go)
 *        and `Group` + `GroupReader` (group.go) — only what
 *        `consensus/wal.go` uses, in C, for the consensus WAL
 *        (nodus_witness_cmt_wal.h).
 *
 * Governing record: docs/plans/decisions/2026-09-26-cmt-wal-file-group.md
 * (operator APPROVED 2026-09-26) — "The consensus WAL is a literal port
 * of `libs/autofile` (AutoFile + Group) and `consensus/wal.go`'s
 * BaseWAL/encoder/decoder/SearchForEndHeight". It supersedes the storage
 * half of D-15 rev 5/6 and the row-truncation mechanism of
 * 2026-09-26-cmt-wal-size-bound.md. Its item 4 (operator, 2026-09-26)
 * keeps the reference's own limits: head 10 MB, total 1 GB.
 *
 * ── ON DISK ────────────────────────────────────────────────────────────
 * group.go:26-53 (the reference's own picture):
 *
 *     Dir/
 *     - <HeadPath>.000   first rolled file
 *     - <HeadPath>.001   second rolled file
 *     - ...
 *     - <HeadPath>       the head, index = MaxIndex
 *
 * `filePathForIndex` (group.go:413-418): the head is `<HeadPath>` when
 * index == maxIndex, otherwise `<HeadPath>.%03d`.
 *
 * ── WHAT RUNS WHEN ─────────────────────────────────────────────────────
 * The reference's `processTicks` goroutine (group.go:239-250) wakes every
 * `groupCheckDuration` (5 s, group.go:20) and runs `checkHeadSizeLimit`
 * then `checkTotalSizeLimit`. This port has no thread: the ticker is a
 * deadline, armed by `nodus_cmt_group_start` (group.go:138-142 OnStart)
 * and fired by `nodus_cmt_group_check_if_due(now_ns)` from the owner's
 * event-loop tick — the single-loop form of the goroutine's wait. When it
 * fires, the next deadline is the Go runtime ticker's own rule
 * (Go 1.21.5 runtime/time.go:854-857: `when += period * (1 +
 * -delta/period)`, delta = when - now — the next point of the period
 * grid strictly after `now`, missed ticks dropped). NOT in the pinned
 * tree: the Go runtime is the reference's runtime, read at
 * /usr/local/go/src (go1.21.5).
 *
 * ── NOT PORTED, with the reason ────────────────────────────────────────
 *   · AutoFile's 1 s close ticker and SIGHUP handler (autofile.go:37,
 *     :69-86, :102-111) — they exist so an EXTERNAL logrotate can move
 *     the file; closing and lazily reopening the fd (O_APPEND) changes no
 *     byte on disk, and a signal handler inside the witness is not this
 *     module's to install. The lazy reopen they rely on IS ported
 *     (every AutoFile op opens the file when it is closed).
 *   · AutoFile.ID's `cmtrand.Str(12)` (autofile.go:67) and Group.ID
 *     (group.go:91) — log labels only.
 *   · `WriteLine` (group.go:210-218), `HeadSizeLimit`/`TotalSizeLimit`/
 *     `MinIndex`/`MaxIndex` getters (:171-197), `CurIndex` (:527-532),
 *     `Wait` (:153-158) — wal.go does not call them; the fields are read
 *     directly (single thread, no mutex — group.go:62's `mtx` and
 *     :425's are the goroutine's, not needed on one loop).
 *   · Go's `panic` (group.go:309-323 RotateFile, :363-371 and :387-390
 *     readGroupInfo) — CMT_FAULT here; the caller logs and decides.
 *
 * ── HARDENING BEYOND THE REFERENCE (no reference counterpart) ─────────
 * Decision docs/plans/decisions/2026-09-27-p2p-fix-2.md item 1 (operator
 * APPROVED 2026-09-27); each is a register row, labelled HARDENING:
 *   · 1(c) directory durability — the head file is opened O_EXCL first;
 *     when that created it, its directory is fsynced (autofile.go:161
 *     never does); after RotateFile's rename the directory is fsynced
 *     (group.go:321-324 never does). `nodus_cmt_fsync_dir`.
 *   · 1(d) a `readdir` error fails `readGroupInfo` (errno cleared before
 *     every call), as the reference's `Readdir` error does (group.go:
 *     367-371).
 *   · 1(a) `nodus_cmt_autofile_truncate` (ftruncate + fsync) — used only
 *     by the WAL's torn-tail trim at start (nodus_witness_cmt_wal.h).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local storage: nothing here reaches a hash, a vote or a block.
 * The clock appears only as the `now_ns` the owner passes to arm and fire
 * the check deadline. `readGroupInfo` iterates the directory in
 * readdir() order, but computes only a sum, a min and a max, which do
 * not depend on the order.
 *
 * Reference @v0.38.26 (SHA-256 verified before use):
 *   libs/autofile/autofile.go  194 lines
 *                   e87460d9a185c97e81f33915177c6cbe68ab20c9d6cbb0d97101630e14d18809
 *   libs/autofile/group.go     540 lines
 *                   303335e062ea54354e3117da79ee9bf52340650fdc2a1c058d4372cbbcdd0770
 * Go standard library (the reference's runtime, NOT in the pinned tree —
 * go1.21.5 at /usr/local/go/src): bufio/bufio.go (Writer :579-584,
 * Flush :635-656, Write :676-700; Reader :32-40, Read :215-260, default
 * size :19 via NewReader :62-63), internal/poll/fd_unix.go:366-399
 * (File.Write loops until every byte is written), runtime/time.go:854-857
 * (ticker reschedule).
 */

#ifndef NODUS_WITNESS_CMT_AUTOFILE_H
#define NODUS_WITNESS_CMT_AUTOFILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dnac/cmt_tmhash.h"     /* CMT_OK / CMT_REJECT / CMT_FAULT */

#ifdef __cplusplus
extern "C" {
#endif

/** autofile.go:38 `autoFilePerms = os.FileMode(0600)`. */
#define NODUS_CMT_AUTOFILE_PERMS 0600

/** group.go:20 `defaultGroupCheckDuration = 5000 * time.Millisecond`, ns. */
#define NODUS_CMT_GROUP_CHECK_DURATION_NS 5000000000LL

/** group.go:21 `defaultHeadSizeLimit = 10 * 1024 * 1024 // 10MB`. */
#define NODUS_CMT_GROUP_HEAD_SIZE_LIMIT (10LL * 1024 * 1024)

/** group.go:22 `defaultTotalSizeLimit = 1 * 1024 * 1024 * 1024 // 1GB` —
 *  the reference's default, and the consensus WAL's bound (decision
 *  2026-09-26-cmt-wal-file-group.md item 4): state.go:453 opens the WAL
 *  with no group option. The field stays per handle so a test can lower
 *  it (`GroupTotalSizeLimit`, group.go:129-134). */
#define NODUS_CMT_GROUP_TOTAL_SIZE_LIMIT (1LL * 1024 * 1024 * 1024)

/** group.go:23 `maxFilesToRemove = 4 // needs to be greater than 1`. */
#define NODUS_CMT_GROUP_MAX_FILES_TO_REMOVE 4

/** group.go:93 `bufio.NewWriterSize(head, 4096*10)`. */
#define NODUS_CMT_GROUP_HEAD_BUF_SIZE (4096 * 10)

/** group.go:514 `bufio.NewReader(curFile)` — Go 1.21.5 bufio.go:19
 *  `defaultBufSize = 4096` (NewReader :62-63). Go stdlib, not the
 *  pinned tree. */
#define NODUS_CMT_GROUP_READER_BUF_SIZE 4096

/** A path buffer. The witness's data_path is `char[256]`
 *  (nodus_witness.h:405); every path here is that plus a short suffix. */
#define NODUS_CMT_AUTOFILE_PATH_MAX 512

/* ── AutoFile (autofile.go:45-55) ────────────────────────────────────── */

typedef struct {
    char path[NODUS_CMT_AUTOFILE_PATH_MAX];   /* autofile.go:47 Path     */
    int  fd;                                  /* autofile.go:54 file; -1 */
} nodus_cmt_autofile_t;

/** HARDENING (decision 2026-09-27-p2p-fix-2.md 1(c); no reference
 *  counterpart): open `dir` read-only and fsync(2) it, so a create or a
 *  rename inside it survives a power cut. @return CMT_OK, CMT_FAULT. */
int nodus_cmt_fsync_dir(const char *dir);

/** autofile.go:60-89 `OpenAutoFile` — `af.openFile()` (:160-174:
 *  O_RDWR|O_CREATE|O_APPEND, 0600; HARDENING: when the open CREATES the
 *  file its directory is fsynced — a failed directory fsync removes the
 *  fresh empty file and is CMT_FAULT). The path is kept as given (the
 *  reference's `filepath.Abs` at :62 only makes the log label absolute;
 *  every open here uses the same string, so relative and absolute name
 *  the same file for the process's lifetime — the witness does not
 *  chdir). @return CMT_OK, CMT_FAULT. */
int nodus_cmt_autofile_open(nodus_cmt_autofile_t *af, const char *path);

/** autofile.go:113-124 `closeFile` — closes the fd if open. The next
 *  Write/Sync/Size reopens it (the lazy reopen). @return CMT_OK,
 *  CMT_FAULT (close(2) failed; the fd is released either way). */
int nodus_cmt_autofile_close_file(nodus_cmt_autofile_t *af);

/** autofile.go:130-142 `Write` — opens if needed, then the whole buffer
 *  (Go's File.Write loops, fd_unix.go:374-399). `*out_n` is the byte
 *  count actually written, also on failure. @return CMT_OK, CMT_FAULT. */
int nodus_cmt_autofile_write(nodus_cmt_autofile_t *af, const uint8_t *p,
                             size_t n, size_t *out_n);

/** autofile.go:148-158 `Sync` — opens if needed, then fsync(2) (Go's
 *  File.Sync is fsync, not fdatasync). @return CMT_OK, CMT_FAULT. */
int nodus_cmt_autofile_sync(nodus_cmt_autofile_t *af);

/** autofile.go:179-194 `Size` — opens if needed, then fstat(2).
 *  @return CMT_OK, CMT_FAULT (the reference's -1 + error). */
int nodus_cmt_autofile_size(nodus_cmt_autofile_t *af, int64_t *out);

/** HARDENING (decision 2026-09-27-p2p-fix-2.md 1(a); AutoFile has no
 *  Truncate) — opens if needed, ftruncate(2) to `size`, then fsync(2).
 *  @return CMT_OK, CMT_FAULT. */
int nodus_cmt_autofile_truncate(nodus_cmt_autofile_t *af, int64_t size);

/* ── Group (group.go:54-76) ──────────────────────────────────────────── */

typedef struct {
    nodus_cmt_autofile_t head;          /* :58 Head                      */

    /* :59 headBuf — Go's bufio.Writer (bufio.go:579-584): buf, n, err.
     * `head_buf_err` is STICKY exactly like bufio's `b.err`: once a
     * write to the head fails, every later Write and Flush returns it. */
    uint8_t *head_buf;
    size_t   head_buf_cap;
    size_t   head_buf_n;
    bool     head_buf_err;              /* bufio's b.err != nil (sticky) */

    int64_t  head_size_limit;           /* :63; 0 = no limit (:255-257)  */
    int64_t  total_size_limit;          /* :64; 0 = no limit (:270-272)  */
    int64_t  group_check_duration_ns;   /* :65                           */
    int      min_index;                 /* :66 includes head             */
    int      max_index;                 /* :67 includes head             */

    /* :61 ticker, as a deadline (header: WHAT RUNS WHEN) */
    bool     check_armed;
    int64_t  check_deadline_ns;
} nodus_cmt_group_t;

/** group.go:341-346 `GroupInfo`. */
typedef struct {
    int     min_index;
    int     max_index;
    int64_t total_size;
    int64_t head_size;
} nodus_cmt_group_info_t;

/**
 * group.go:80-113 `OpenGroup` — opens the head AutoFile, allocates the
 * 40 KiB head buffer, sets the defaults (head 10 MB, total 1 GB, check
 * 5 s) and reads min/max index from the directory (`readGroupInfo`).
 * The directory must exist (wal.go:92 `EnsureDir` is the WAL's step).
 * Options (group.go:115-134) are applied by assigning the fields after
 * this returns; none of them is read by `readGroupInfo`.
 * @return CMT_OK, CMT_FAULT.
 */
int nodus_cmt_group_open(nodus_cmt_group_t *g, const char *head_path);

/** group.go:138-142 `OnStart` — arms the check deadline at
 *  `now_ns + group_check_duration_ns` (`time.NewTicker`). */
void nodus_cmt_group_start(nodus_cmt_group_t *g, int64_t now_ns);

/** group.go:146-151 `OnStop` — disarms the check deadline, then
 *  FlushAndSync; an error is logged ("Error flushin to disk"), as the
 *  reference does. */
void nodus_cmt_group_stop(nodus_cmt_group_t *g);

/** group.go:161-169 `Close` — FlushAndSync (logged on error), close the
 *  head's fd, and free the head buffer. Safe on a zeroed or failed-open
 *  handle. */
void nodus_cmt_group_close(nodus_cmt_group_t *g);

/** group.go:204-208 `Write` — `headBuf.Write(p)`: buffered; a write that
 *  does not fit fills the buffer, flushes it to the head file and
 *  continues; a write larger than the buffer into an EMPTY buffer goes
 *  straight to the file (bufio.go:676-700). No fsync.
 *  @return CMT_OK, CMT_FAULT (the sticky error). */
int nodus_cmt_group_write(nodus_cmt_group_t *g, const uint8_t *p, size_t n);

/** group.go:220-225 `Buffered`. */
size_t nodus_cmt_group_buffered(const nodus_cmt_group_t *g);

/** group.go:227-237 `FlushAndSync` — `headBuf.Flush()` then, only if
 *  that succeeded, `Head.Sync()` (fsync). @return CMT_OK, CMT_FAULT. */
int nodus_cmt_group_flush_and_sync(nodus_cmt_group_t *g);

/** @return true with the deadline when the check ticker is armed. */
bool nodus_cmt_group_next_check_deadline(const nodus_cmt_group_t *g,
                                         int64_t *out_deadline_ns);

/** group.go:239-250 `processTicks`, one wake-up: if the ticker is armed
 *  and `now_ns` has reached the deadline, `checkHeadSizeLimit` then
 *  `checkTotalSizeLimit`, and the deadline moves to the next period
 *  point after `now_ns`. @return CMT_OK; CMT_FAULT only when the
 *  rotation failed (the reference panics there, group.go:309-323) or the
 *  directory could not be read (it panics, :363-371). */
int nodus_cmt_group_check_if_due(nodus_cmt_group_t *g, int64_t now_ns);

/** group.go:252-266 `checkHeadSizeLimit` (the reference calls it
 *  manually in its tests, :252). @return as check_if_due. */
int nodus_cmt_group_check_head_size_limit(nodus_cmt_group_t *g);

/** group.go:268-299 `checkTotalSizeLimit` — while the total is at or
 *  above the limit, remove the OLDEST file, at most 4 per call, never the
 *  head ("Group's head may grow without bound", :281-285); a stat
 *  failure skips that index (:287-291), a remove failure stops (:292-
 *  296). @return CMT_OK, CMT_FAULT (the directory could not be read). */
int nodus_cmt_group_check_total_size_limit(nodus_cmt_group_t *g);

/** group.go:301-327 `RotateFile` — flush, fsync, close the head, rename
 *  it to `<head>.%03d` of the current max index, max index + 1; then
 *  (HARDENING 1(c)) fsync the directory. The new head is created by the
 *  next open (lazy, O_CREAT).
 *  @return CMT_OK, CMT_FAULT (each step the reference panics on; a failed
 *  directory fsync is CMT_FAULT with max index already advanced — the
 *  rename happened). */
int nodus_cmt_group_rotate_file(nodus_cmt_group_t *g);

/** group.go:348-411 `ReadGroupInfo`/`readGroupInfo` — scans the head's
 *  directory: the head's own size, every `<headBase>*` file's size into
 *  the total, and the index of every name matching `^.+\.([0-9]{3,})$`.
 *  @return CMT_OK, CMT_FAULT (the directory could not be opened or read —
 *  readdir(3) NULL with errno set, HARDENING 1(d) — a stat failed, or an
 *  index does not fit an int — the reference panics on each, :363-371,
 *  :387-390). */
int nodus_cmt_group_read_info(const nodus_cmt_group_t *g,
                              nodus_cmt_group_info_t *out);

/** group.go:413-418 `filePathForIndex`. @return CMT_OK, CMT_FAULT (the
 *  path does not fit `cap`). */
int nodus_cmt_group_file_path_for_index(const char *head_path, int index,
                                        int max_index, char *out,
                                        size_t cap);

/* ── GroupReader (group.go:422-430) ──────────────────────────────────── */

typedef struct {
    const nodus_cmt_group_t *g;        /* :424 *Group — BORROWED        */
    int      cur_index;                /* :426                          */
    int      cur_fd;                   /* :427 curFile; -1 when none    */
    /* :428 curReader — Go's bufio.Reader (bufio.go:32-40): buf, r, w */
    uint8_t  buf[NODUS_CMT_GROUP_READER_BUF_SIZE];
    size_t   r;
    size_t   w;
} nodus_cmt_group_reader_t;

/** Read results — the reference's `(n int, err error)` classes. */
#define NODUS_CMT_GROUP_READ_OK     0    /* err == nil                    */
#define NODUS_CMT_GROUP_READ_EOF    1    /* err == io.EOF                 */
#define NODUS_CMT_GROUP_READ_EMPTY  2    /* :462-464 "given empty slice"  */
#define NODUS_CMT_GROUP_READ_IO   (-1)   /* any other error (open, read)  */

/** group.go:329-338 `NewReader` — `newGroupReader` + `SetIndex(index)`
 *  (:534-540 → `openFile`, :500-525: O_RDONLY|O_CREATE, 0600; an index
 *  above the group's max index is io.EOF).
 *  @return a NODUS_CMT_GROUP_READ_* class; OK means `gr` is open. */
int nodus_cmt_group_new_reader(const nodus_cmt_group_t *g, int index,
                               nodus_cmt_group_reader_t *gr);

/** group.go:458-496 `Read` — reads until `len` bytes are in `p`, moving
 *  on to the next file at each file's end; at the end of the LAST file
 *  it returns what it has with EOF. `*out_n` is always set.
 *  @return a NODUS_CMT_GROUP_READ_* class. */
int nodus_cmt_group_reader_read(nodus_cmt_group_reader_t *gr, uint8_t *p,
                                size_t len, size_t *out_n);

/** group.go:442-456 `Close`. Safe on a closed reader. */
void nodus_cmt_group_reader_close(nodus_cmt_group_reader_t *gr);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_AUTOFILE_H */
