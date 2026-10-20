/**
 * @file nodus_fs.c
 * @brief The portable file layer (nodus_fs.h). POSIX arm: the calls the
 *        segment code made before this layer (same call, flags, mode,
 *        EINTR loops), compiled with a 64-bit off_t (_FILE_OFFSET_BITS 64
 *        below — the one change: their *64 forms on a 32-bit ABI).
 *        nodus_fs_is_dir and nodus_fs_mkdir_p are compositions, not one
 *        call (nodus_fs.h). Windows arm: the counterparts named in
 *        nodus_fs.h.
 *
 * ── WINDOWS CHOICES (none of them run on native Windows yet; the API
 *    behaviours below are this file's reading, NOT checked against
 *    Microsoft's documentation — no copy of it is in the tree) ───────────
 *  - Positional I/O: ReadFile / WriteFile on the descriptor's HANDLE
 *    (_get_osfhandle) with an OVERLAPPED whose Offset / OffsetHigh carry
 *    the 64-bit offset. The handle is synchronous (no
 *    FILE_FLAG_OVERLAPPED), so the call completes before it returns. It
 *    MOVES the handle's file pointer as a side effect; nothing in this
 *    layer or its callers reads that pointer (every read and write names
 *    its offset; nodus_fs_read_once is only used on a freshly opened
 *    descriptor), so no I/O depends on a shared position. Chosen over
 *    _lseeki64 + _read / _write, which would depend on it.
 *    End of file: a positional ReadFile at or past the end is read as
 *    "end of file" whether it returns FALSE with ERROR_HANDLE_EOF or TRUE
 *    with 0 bytes — both forms are accepted because which one Windows
 *    gives was not verified.
 *  - Opening: CreateFileW with FILE_SHARE_READ | FILE_SHARE_WRITE |
 *    FILE_SHARE_DELETE, then _open_osfhandle. FILE_SHARE_DELETE is what
 *    lets the segment build rename .dat.tmp → .dat (and discard unlink
 *    .dat.tmp) while its own descriptor is still open — the POSIX order,
 *    kept. A CRT _wopen handle does not share delete. Not inheritable
 *    (NULL security attributes).
 *  - fsync: _commit (the CRT's FlushFileBuffers), as nodus_p2p_host.c's
 *    atomic replace does.
 *  - Rename: MoveFileExW(MOVEFILE_REPLACE_EXISTING |
 *    MOVEFILE_WRITE_THROUGH), as nodus_p2p_host.c does —
 *    REPLACE_EXISTING is POSIX rename's replace, WRITE_THROUGH returns
 *    only once the move is on disk (the job the directory fsync does after
 *    a rename on POSIX).
 *    A rename onto a target ANOTHER descriptor holds open is NOT given the
 *    unlink's move-aside below: it stays one MoveFileExW, and where
 *    Windows refuses it the caller gets -1 (test_seg_file_win case 10
 *    prints which). No caller needs more: the segment build renames onto
 *    names it has just unlinked (.ok, .idx, .dat — nodus_seg_build_open)
 *    or never created, and the unlink below frees those names even while a
 *    reader holds the files. A move-aside of the target would open a
 *    window in which the published name is absent; not taken without a
 *    caller that needs it.
 *  - Unlink: "free the name first". MoveFileExW(path → a sibling
 *    "<path>.deleted.<pid>.<n>" in the same directory, flags 0 — no
 *    replace; <n> a process counter), then DeleteFileW on the moved name.
 *    Why: a file unlinked while another handle holds it (FILE_SHARE_DELETE)
 *    becomes delete-pending UNDER ITS NAME until the last close, so the
 *    name could not be created again as a new file — under Wine 8.0 a
 *    re-create even reached the held file (its holder read the new bytes;
 *    observed by the ORCHESTRATOR, test_seg_file_win case 10). After the
 *    move the name is free and a holder keeps the old bytes, as POSIX
 *    unlink. The delete then succeeds (delete-pending under the aside name,
 *    gone at the last close); if it is refused the aside file stays and
 *    the answer is still 0 (the name is free). Source absent → 0 (ENOENT,
 *    as before); an aside name already taken → the next counter, at most
 *    FS_ASIDE_TRIES times; any other move failure, an aside name that does
 *    not fit, or a directory → the previous direct _wunlink with its
 *    errno. The aside name is logged at DEBUG only. Leftovers: a crash
 *    between the move and the last close (or a refused delete) can leave
 *    "*.deleted.*" files. Nothing reads them: nodus_seg_name_parse accepts
 *    only "seg-<k>" followed by EXACTLY one of its six suffixes
 *    (nodus_witness_storage_segment.c), so "seg-<k>.dat.deleted.…" is not
 *    a segment file; no startup cleanup removes them.
 *  - Directory fsync: the directory opened with CreateFileW(GENERIC_WRITE,
 *    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS) and FlushFileBuffers on
 *    that handle; an open or flush failure is -1 with errno (the publish
 *    and the deletion then fail — never a silent success). Whether NTFS
 *    makes the directory's entries (an UNLINK, a new file's entry before
 *    its rename) durable through that flush is NOT verified here; under
 *    Wine the flush may be a no-op. The renames are WRITE_THROUGH on top.
 *    If the entries are not durable, after a crash an unlinked segment
 *    file may reappear: a reappearing complete set (.ok, .idx, .dat) is
 *    the segment exactly as it was published; a partial one fails the
 *    reader's marker / size / index-hash checks and is not held
 *    (nodus_seg_reader_open).
 *  - Errors: Win32 codes → errno in win_errno (its comment has the
 *    delete-pending case). _wunlink (the unlink's fallback), _wmkdir, _wstat64, _commit,
 *    _fstat64 and _chsize_s set errno through the CRT's OWN mapping, not
 *    win_errno — that mapping is NOT verified (no CRT source in the
 *    tree).
 *  - _open_osfhandle failure: the HANDLE is closed here (win_open says
 *    why, and that the CRT's behaviour is NOT verified).
 *  - Modes: no POSIX mode on Windows; files and directories take their
 *    parent directory's ACL.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

/* 64-bit off_t on every POSIX ABI — BEFORE any include, the only place
 * the C library reads it. A 32-bit ABI (Android armeabi-v7a: messenger
 * builds this file through add_subdirectory(nodus)) otherwise has a 32-bit
 * off_t, and the (off_t) casts below would truncate every offset >= 2 GiB
 * (the segment format addresses its .dat with u64 offsets — data_size
 * u64, nodus_witness_storage_segment.h). With it, glibc / bionic declare
 * pread / pwrite / ftruncate / fstat / stat / open under their *64 names.
 * On 64-bit Linux (x86_64 glibc, checked for this file): the compiled
 * instructions are the same, only the called symbol names change
 * (open → open64, pread → pread64, ...), and each pair is the same libc
 * entry point (one address, `nm -D libc.so.6`). Not on Windows: that arm
 * names the 64-bit CRT calls itself (_fstat64, _wstat64, _chsize_s). */
#if !defined(_WIN32) && !defined(_FILE_OFFSET_BITS)
  #define _FILE_OFFSET_BITS 64
#endif

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <direct.h>                   /* _wmkdir                       */
  #include <io.h>
  #include <wchar.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/types.h>
#else
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <unistd.h>
#endif

#include "storage/nodus_fs.h"

#include "crypto/utils/qgp_log.h"

#include <errno.h>
#include <stdio.h>                      /* rename                        */
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NODUS_FS"

#ifndef _WIN32

/* ══════════════════════════════════════════════════════════════════════
 * POSIX — the segment code's own calls, moved here unchanged
 * ════════════════════════════════════════════════════════════════════ */

/* A build whose off_t stayed 32-bit (a _FILE_OFFSET_BITS set elsewhere)
 * fails here instead of truncating offsets >= 2 GiB. */
_Static_assert(sizeof(off_t) == 8, "nodus_fs needs a 64-bit off_t");

int nodus_fs_open_write_trunc(const char *path) {
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
}

int nodus_fs_open_rw_create(const char *path) {
    return open(path, O_RDWR | O_CREAT, 0600);
}

int nodus_fs_open_read(const char *path) {
    return open(path, O_RDONLY);
}

int nodus_fs_close(int fd) {
    return close(fd);
}

/* @return 0 all written / -1 */
int nodus_fs_pwrite_all(int fd, const uint8_t *p, size_t n, uint64_t off) {
    while (n > 0) {
        ssize_t w = pwrite(fd, p, n, (off_t)off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += w;
        n -= (size_t)w;
        off += (uint64_t)w;
    }
    return 0;
}

/* @return 0 all read / 1 end of file first / -1 */
int nodus_fs_pread_all(int fd, uint8_t *p, size_t n, uint64_t off) {
    while (n > 0) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 1;
        p += r;
        n -= (size_t)r;
        off += (uint64_t)r;
    }
    return 0;
}

int64_t nodus_fs_read_once(int fd, uint8_t *p, size_t n) {
    return (int64_t)read(fd, p, n);
}

int nodus_fs_fsync(int fd) {
    return fsync(fd);
}

int nodus_fs_size(int fd, uint64_t *size_out) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    *size_out = (uint64_t)st.st_size;
    return 0;
}

int nodus_fs_truncate(int fd, uint64_t len) {
    return ftruncate(fd, (off_t)len);
}

int nodus_fs_dir_sync(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc == 0 ? 0 : -1;
}

int nodus_fs_rename(const char *from, const char *to) {
    return rename(from, to);
}

int nodus_fs_unlink_if_exists(const char *path) {
    if (unlink(path) == 0 || errno == ENOENT) return 0;
    return -1;
}

int nodus_fs_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int nodus_fs_is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

int nodus_fs_mkdir(const char *path) {
    return mkdir(path, 0700);
}

#define FS_IS_SEP(c) ((c) == '/')

#else /* _WIN32 */

/* ══════════════════════════════════════════════════════════════════════
 * Windows
 * ════════════════════════════════════════════════════════════════════ */

/* UTF-16 room for one path: NODUS_SEG_PATH_MAX (512) and the 4004 host's
 * paths fit with margin. */
#define FS_WPATH_MAX 1024

/* The largest single ReadFile / WriteFile (a DWORD count). */
#define FS_CHUNK_MAX ((size_t)1 << 30)

/* errno from a Win32 error; the code is logged unless it is "not found"
 * or "exists" (ordinary answers on the segment paths). The log comes
 * FIRST and errno is set LAST: the logger may itself open or create files
 * and overwrite errno before the caller reads it.
 *
 * A name whose delete is pending (unlinked while another handle still
 * holds it, FILE_SHARE_DELETE) answers ERROR_DELETE_PENDING → EBUSY, or —
 * this file's reading, not verified — ERROR_ACCESS_DENIED → EACCES; the
 * two cannot be told apart without the NTSTATUS (ntdll), which this layer
 * does not read. Either way it is neither ENOENT nor EEXIST, so no caller
 * reads it as "absent" or "already there". */
static void win_errno(DWORD e, const char *what, const char *path) {
    int en;
    int quiet = 0;
    switch (e) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        en = ENOENT;
        quiet = 1;
        break;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        en = EEXIST;
        quiet = 1;
        break;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        en = EACCES;
        break;
    case ERROR_DELETE_PENDING:
        en = EBUSY;
        break;
    case ERROR_FILENAME_EXCED_RANGE:
        en = ENAMETOOLONG;
        break;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        en = ENOSPC;
        break;
    default:
        en = EIO;
        break;
    }
    if (!quiet)
        QGP_LOG_DEBUG(LOG_TAG, "%s %s: Windows error %lu", what,
                      path ? path : "(fd)", (unsigned long)e);
    errno = en;
}

/* UTF-8 → UTF-16 (the one conversion every path call uses). A path that
 * does not fit FS_WPATH_MAX is ENAMETOOLONG, one that is not valid UTF-8
 * EINVAL. */
static int widen(const char *s, wchar_t out[FS_WPATH_MAX]) {
    if (!s) {
        errno = EINVAL;
        return -1;
    }
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out,
                                FS_WPATH_MAX);
    if (n <= 0) {
        errno = GetLastError() == ERROR_INSUFFICIENT_BUFFER ? ENAMETOOLONG
                                                            : EINVAL;
        return -1;
    }
    return 0;
}

static int win_open(const char *path, DWORD access, DWORD disposition,
                    int crt_flags) {
    wchar_t w[FS_WPATH_MAX];
    if (widen(path, w) != 0) return -1;
    HANDLE h = CreateFileW(w, access,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                               FILE_SHARE_DELETE,
                           NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        win_errno(GetLastError(), "open", path);
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)h, crt_flags);
    if (fd < 0) {
        /* Ownership on failure: NOT VERIFIED — the UCRT's source is not in
         * the tree (the llvm-mingw sysroot carries only its headers and
         * import libraries). This file's reading: a -1 from
         * _open_osfhandle means no descriptor took the HANDLE, so it is
         * still ours, and closing it is the choice that cannot leak it.
         * The case this reading would get wrong: a CRT that CLOSES the
         * handle itself before returning -1 — then this CloseHandle hits
         * a closed (or, in a threaded process, reused) handle value. */
        int e = errno;                  /* the CRT's code, kept */
        CloseHandle(h);
        errno = e ? e : EMFILE;
        return -1;
    }
    return fd;
}

static HANDLE fd_handle(int fd) {
    intptr_t h = _get_osfhandle(fd);
    if (h == -1) {
        errno = EBADF;
        return INVALID_HANDLE_VALUE;
    }
    return (HANDLE)h;
}

int nodus_fs_open_write_trunc(const char *path) {
    return win_open(path, GENERIC_WRITE, CREATE_ALWAYS,
                    _O_WRONLY | _O_BINARY);
}

int nodus_fs_open_rw_create(const char *path) {
    return win_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS,
                    _O_RDWR | _O_BINARY);
}

int nodus_fs_open_read(const char *path) {
    return win_open(path, GENERIC_READ, OPEN_EXISTING,
                    _O_RDONLY | _O_BINARY);
}

int nodus_fs_close(int fd) {
    return _close(fd);
}

int nodus_fs_pwrite_all(int fd, const uint8_t *p, size_t n, uint64_t off) {
    HANDLE h = fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    while (n > 0) {
        DWORD want = (DWORD)(n > FS_CHUNK_MAX ? FS_CHUNK_MAX : n);
        DWORD done = 0;
        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)(off >> 32);
        if (!WriteFile(h, p, want, &done, &ov)) {
            win_errno(GetLastError(), "write", NULL);
            return -1;
        }
        if (done == 0) {
            errno = EIO;
            return -1;
        }
        p += done;
        n -= (size_t)done;
        off += (uint64_t)done;
    }
    return 0;
}

int nodus_fs_pread_all(int fd, uint8_t *p, size_t n, uint64_t off) {
    HANDLE h = fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    while (n > 0) {
        DWORD want = (DWORD)(n > FS_CHUNK_MAX ? FS_CHUNK_MAX : n);
        DWORD got = 0;
        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)(off >> 32);
        if (!ReadFile(h, p, want, &got, &ov)) {
            DWORD e = GetLastError();
            if (e == ERROR_HANDLE_EOF) return 1;
            win_errno(e, "read", NULL);
            return -1;
        }
        if (got == 0) return 1;
        p += got;
        n -= (size_t)got;
        off += (uint64_t)got;
    }
    return 0;
}

int64_t nodus_fs_read_once(int fd, uint8_t *p, size_t n) {
    HANDLE h = fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD want = (DWORD)(n > FS_CHUNK_MAX ? FS_CHUNK_MAX : n);
    DWORD got = 0;
    if (!ReadFile(h, p, want, &got, NULL)) {
        DWORD e = GetLastError();
        if (e == ERROR_HANDLE_EOF) return 0;
        win_errno(e, "read", NULL);
        return -1;
    }
    return (int64_t)got;
}

int nodus_fs_fsync(int fd) {
    return _commit(fd);
}

int nodus_fs_size(int fd, uint64_t *size_out) {
    struct _stat64 st;
    if (_fstat64(fd, &st) != 0) return -1;
    if (st.st_size < 0) {
        errno = EIO;
        return -1;
    }
    *size_out = (uint64_t)st.st_size;
    return 0;
}

int nodus_fs_truncate(int fd, uint64_t len) {
    if (len > (uint64_t)INT64_MAX) {
        errno = EINVAL;
        return -1;
    }
    errno_t e = _chsize_s(fd, (__int64)len);
    if (e != 0) {
        errno = e;
        return -1;
    }
    return 0;
}

int nodus_fs_dir_sync(const char *dir) {
    /* The directory itself, flushed (file header "Directory fsync").
     * FILE_FLAG_BACKUP_SEMANTICS is what lets CreateFileW open a
     * directory; GENERIC_WRITE because FlushFileBuffers needs a handle
     * with write access — both this file's reading, NOT verified against
     * Microsoft's documentation, and under Wine the flush may be a no-op.
     * A failure is -1 with errno, never a silent 0. */
    wchar_t w[FS_WPATH_MAX];
    if (widen(dir, w) != 0) return -1;
    HANDLE h = CreateFileW(w, GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                               FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        win_errno(GetLastError(), "open directory", dir);
        return -1;
    }
    int ret = 0;
    if (!FlushFileBuffers(h)) {
        win_errno(GetLastError(), "flush directory", dir);
        ret = -1;
    }
    CloseHandle(h);                     /* as the POSIX arm's close(fd) */
    return ret;
}

int nodus_fs_rename(const char *from, const char *to) {
    wchar_t wf[FS_WPATH_MAX], wt[FS_WPATH_MAX];
    if (widen(from, wf) != 0 || widen(to, wt) != 0) return -1;
    if (!MoveFileExW(wf, wt,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        win_errno(GetLastError(), "rename", from);
        return -1;
    }
    return 0;
}

/* Attempts at a free aside name before falling back to _wunlink: a name
 * is only taken when a crashed earlier process with the same pid left it
 * (file header "Unlink"). */
#define FS_ASIDE_TRIES 8

/* Today's unlink: _wunlink, ENOENT accepted (its errno is the CRT's). */
static int unlink_direct(const wchar_t *w) {
    if (_wunlink(w) == 0 || errno == ENOENT) return 0;
    return -1;
}

int nodus_fs_unlink_if_exists(const char *path) {
    /* Free the NAME first (file header "Unlink"): move the file to a
     * sibling "<path>.deleted.<pid>.<n>", then delete that. A descriptor
     * still holding the file keeps reading its bytes; the name can be
     * created again at once, as a NEW file. */
    static volatile LONG counter = 0;
    wchar_t w[FS_WPATH_MAX], wa[FS_WPATH_MAX];
    if (widen(path, w) != 0) return -1;

    /* a directory keeps today's answer (_wunlink refuses it) — the move
     * below would otherwise rename it aside and leave it there */
    DWORD attr = GetFileAttributesW(w);
    if (attr != INVALID_FILE_ATTRIBUTES &&
        (attr & FILE_ATTRIBUTE_DIRECTORY))
        return unlink_direct(w);

    const size_t plen = strlen(path);
    char *aside = malloc(plen + 64);
    if (!aside) return unlink_direct(w);

    for (int t = 0; t < FS_ASIDE_TRIES; t++) {
        unsigned long n = (unsigned long)InterlockedIncrement(&counter);
        int len = snprintf(aside, plen + 64, "%s" NODUS_FS_ASIDE_TAG
                           "%lu.%lu", path,
                           (unsigned long)GetCurrentProcessId(), n);
        if (len < 0 || (size_t)len >= plen + 64 || widen(aside, wa) != 0)
            break;                      /* no aside name: today's unlink */
        if (MoveFileExW(w, wa, 0)) {
            QGP_LOG_DEBUG(LOG_TAG, "unlink %s: moved aside to %s", path,
                          aside);
            /* With FILE_SHARE_DELETE on every handle this layer opens, a
             * held file is marked delete-pending under the aside name and
             * goes at its last close. A refusal (an opener without
             * FILE_SHARE_DELETE — this layer has none) leaves the aside
             * file; the name is free either way, so the answer is 0. */
            if (!DeleteFileW(wa))
                QGP_LOG_DEBUG(LOG_TAG, "unlink %s: delete of %s: Windows "
                              "error %lu", path, aside,
                              (unsigned long)GetLastError());
            free(aside);
            return 0;
        }
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
            free(aside);
            win_errno(e, "unlink", path);       /* ENOENT, as _wunlink */
            return 0;
        }
        if (e != ERROR_ALREADY_EXISTS && e != ERROR_FILE_EXISTS) {
            QGP_LOG_DEBUG(LOG_TAG, "unlink %s: move aside: Windows error "
                          "%lu — direct unlink", path, (unsigned long)e);
            break;
        }
        /* the aside name is taken (a crash leftover): the next counter */
    }
    free(aside);
    return unlink_direct(w);
}

int nodus_fs_exists(const char *path) {
    wchar_t w[FS_WPATH_MAX];
    struct _stat64 st;
    if (widen(path, w) != 0) return 0;
    return _wstat64(w, &st) == 0;
}

int nodus_fs_is_dir(const char *path) {
    wchar_t w[FS_WPATH_MAX];
    struct _stat64 st;
    if (widen(path, w) != 0) return -1;
    if (_wstat64(w, &st) != 0) return -1;
    return (st.st_mode & _S_IFDIR) ? 1 : 0;
}

int nodus_fs_mkdir(const char *path) {
    wchar_t w[FS_WPATH_MAX];
    if (widen(path, w) != 0) return -1;
    return _wmkdir(w);
}

#define FS_IS_SEP(c) ((c) == '/' || (c) == '\\')

#endif /* _WIN32 */

/* ══════════════════════════════════════════════════════════════════════
 * Both platforms
 * ════════════════════════════════════════════════════════════════════ */

int nodus_fs_mkdir_p(const char *path) {
    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    size_t len = strlen(path);
    char *p = malloc(len + 1);
    if (!p) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(p, path, len + 1);
    size_t i = 0;
#ifdef _WIN32
    if (len >= 2 && p[1] == ':') i = 2;         /* the drive: not created */
#endif
    while (i < len && FS_IS_SEP(p[i])) i++;      /* the root: not created  */
    /* every parent level: created when missing; a failure here is not
     * decisive (an existing level, a share root, an unreadable ancestor),
     * the last level and the final check are */
    for (; i < len; i++) {
        if (!FS_IS_SEP(p[i]) || FS_IS_SEP(p[i - 1])) continue;
        char c = p[i];
        p[i] = '\0';
        (void)nodus_fs_mkdir(p);
        p[i] = c;
    }
    int ret = 0;
    if (nodus_fs_mkdir(p) != 0 && errno != EEXIST) ret = -1;
    if (ret == 0) {
        int d = nodus_fs_is_dir(p);
        if (d != 1) {
            if (d == 0) errno = ENOTDIR;
            ret = -1;
        }
    }
    free(p);
    return ret;
}
