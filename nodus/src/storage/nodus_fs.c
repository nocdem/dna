/**
 * @file nodus_fs.c
 * @brief The portable file layer (nodus_fs.h). POSIX arm: the calls the
 *        segment code made before this layer, moved here unchanged (same
 *        call, flags, mode, EINTR loops). Windows arm: the counterparts
 *        named in nodus_fs.h.
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
 *  - Directory fsync: a no-op. The CRT has no directory descriptor to
 *    flush; the renames it follows are already WRITE_THROUGH. NOT covered:
 *    the durability of an UNLINK (nodus_seg_delete) and of a newly created
 *    file's directory entry before its rename — after a crash an unlinked
 *    segment file may reappear. Stated, not fixed: a reappearing complete
 *    set (.ok, .idx, .dat) is the segment exactly as it was published; a
 *    partial one fails the reader's marker / size / index-hash checks and
 *    is not held (nodus_seg_reader_open).
 *  - Modes: no POSIX mode on Windows; files and directories take their
 *    parent directory's ACL.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

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
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NODUS_FS"

#ifndef _WIN32

/* ══════════════════════════════════════════════════════════════════════
 * POSIX — the segment code's own calls, moved here unchanged
 * ════════════════════════════════════════════════════════════════════ */

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
 * or "exists" (ordinary answers on the segment paths). */
static void win_errno(DWORD e, const char *what, const char *path) {
    switch (e) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        errno = ENOENT;
        return;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        errno = EEXIST;
        return;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        errno = EACCES;
        break;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        errno = ENOSPC;
        break;
    default:
        errno = EIO;
        break;
    }
    QGP_LOG_DEBUG(LOG_TAG, "%s %s: Windows error %lu", what,
                  path ? path : "(fd)", (unsigned long)e);
}

/* UTF-8 → UTF-16 (the one conversion every path call uses). */
static int widen(const char *s, wchar_t out[FS_WPATH_MAX]) {
    if (!s) {
        errno = EINVAL;
        return -1;
    }
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out,
                                FS_WPATH_MAX);
    if (n <= 0) {
        errno = EINVAL;
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
    /* No-op on Windows (file header "Directory fsync"). */
    (void)dir;
    return 0;
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

int nodus_fs_unlink_if_exists(const char *path) {
    wchar_t w[FS_WPATH_MAX];
    if (widen(path, w) != 0) return -1;
    if (_wunlink(w) == 0 || errno == ENOENT) return 0;
    return -1;
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
