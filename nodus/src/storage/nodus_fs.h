/**
 * @file nodus_fs.h
 * @brief A small portable FILE layer for the segment files (design
 *        docs/plans/2026-10-19-windows-light-storage-design.md §3 "Rev 1
 *        corrections", B4 portable segment files).
 *
 * Every call is one POSIX call on Linux / Android — the exact call, flags
 * and mode the segment code issued before this layer existed — and its
 * Windows counterpart on Windows. Nothing here decides anything: the
 * callers keep every rule (what to open, in which order to rename, when a
 * short read means a torn record).
 *
 * File handles are C runtime file descriptors (`int`) on both platforms.
 * On Windows the descriptor wraps a HANDLE opened with CreateFileW and
 * FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, so a file may be
 * renamed or unlinked while a descriptor on it is still open — the segment
 * build renames its data file before it closes it, as on POSIX.
 *
 * PATHS are UTF-8 on both platforms. On Windows every call that takes a
 * path (open, rename, unlink, stat, mkdir) converts it to UTF-16 with
 * MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS) and calls the wide
 * API, so a writer and a reader always name the same file; a path that is
 * not valid UTF-8 is refused (-1, errno EINVAL). No "\\?\" long-path
 * prefix is added: a path longer than the Windows limit fails.
 *
 * ERRORS: -1 with errno set. POSIX: the call's own errno, untouched.
 * Windows: the Win32 error mapped to an errno — ENOENT (file / path not
 * found), EEXIST (already exists), EACCES (access denied, sharing or lock
 * violation), ENOSPC (disk full), EINVAL (a bad path), EBADF (a descriptor
 * without a handle), EIO (anything else) — and every code other than the
 * ENOENT / EEXIST ones logged at DEBUG with its number. Callers that test
 * `errno == ENOENT` / `errno == EEXIST` work the same on both platforms.
 *
 * DETERMINISM: node-local file I/O; nothing here reads a clock, draws
 * randomness or touches a consensus value.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_FS_H
#define NODUS_FS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Open for writing, created when absent, TRUNCATED when present.
 *  POSIX open(O_WRONLY | O_CREAT | O_TRUNC, 0600); Windows CreateFileW
 *  (GENERIC_WRITE, CREATE_ALWAYS — no POSIX mode: the file takes its
 *  directory's ACL). @return fd / -1. */
int nodus_fs_open_write_trunc(const char *path);

/** Open for reading and writing, created when absent, NOT truncated.
 *  POSIX open(O_RDWR | O_CREAT, 0600); Windows CreateFileW
 *  (GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS). @return fd / -1. */
int nodus_fs_open_rw_create(const char *path);

/** Open an existing file for reading. POSIX open(O_RDONLY); Windows
 *  CreateFileW(GENERIC_READ, OPEN_EXISTING). @return fd / -1 (errno
 *  ENOENT when the file does not exist). */
int nodus_fs_open_read(const char *path);

/** Close. POSIX close; Windows _close (which closes the HANDLE).
 *  @return 0 / -1. */
int nodus_fs_close(int fd);

/** Write all `n` bytes at the 64-bit offset `off`, never through a shared
 *  file position. POSIX: pwrite until done, EINTR retried, a 0-byte write
 *  is an error. Windows: WriteFile with an OVERLAPPED offset in chunks of
 *  at most 1 GiB. @return 0 / -1. */
int nodus_fs_pwrite_all(int fd, const uint8_t *p, size_t n, uint64_t off);

/** Read all `n` bytes at the 64-bit offset `off`. POSIX: pread until done,
 *  EINTR retried. Windows: ReadFile with an OVERLAPPED offset in chunks of
 *  at most 1 GiB. @return 0 all read / 1 end of file first / -1. */
int nodus_fs_pread_all(int fd, uint8_t *p, size_t n, uint64_t off);

/** ONE read at the descriptor's current position (a freshly opened
 *  descriptor: offset 0). POSIX: a single read(); Windows: a single
 *  ReadFile without OVERLAPPED. Not a loop: the caller sizes `n` to see a
 *  file that is longer than it should be. @return bytes read (0 at end of
 *  file) / -1. */
int64_t nodus_fs_read_once(int fd, uint8_t *p, size_t n);

/** Flush the file to stable storage. POSIX fsync; Windows _commit (the
 *  CRT's FlushFileBuffers). @return 0 / -1. */
int nodus_fs_fsync(int fd);

/** The file's size. POSIX fstat; Windows _fstat64. @return 0 / -1. */
int nodus_fs_size(int fd, uint64_t *size_out);

/** Cut (or extend with zeros) the file to `len` bytes. POSIX ftruncate;
 *  Windows _chsize_s. @return 0 / -1. */
int nodus_fs_truncate(int fd, uint64_t len);

/** Make the directory's entries (renames, new files) durable. POSIX:
 *  open(O_RDONLY | O_DIRECTORY), fsync, close. Windows: a NO-OP returning
 *  0 — Windows has no directory fsync through the CRT; nodus_fs_rename
 *  uses MOVEFILE_WRITE_THROUGH instead (nodus_fs.c says what is and is not
 *  covered). @return 0 / -1. */
int nodus_fs_dir_sync(const char *dir);

/** Rename `from` to `to`, replacing `to` when it exists, in one step.
 *  POSIX rename; Windows MoveFileExW(MOVEFILE_REPLACE_EXISTING |
 *  MOVEFILE_WRITE_THROUGH). @return 0 / -1. */
int nodus_fs_rename(const char *from, const char *to);

/** Remove `path`; a file that does not exist is not an error. POSIX
 *  unlink (ENOENT accepted); Windows _wunlink (ENOENT accepted).
 *  @return 0 removed or absent / -1 (errno). */
int nodus_fs_unlink_if_exists(const char *path);

/** Whether `path` exists. POSIX stat; Windows _wstat64. @return 1 / 0. */
int nodus_fs_exists(const char *path);

/** What `path` is. POSIX stat + S_ISDIR; Windows _wstat64 + _S_IFDIR.
 *  @return 1 a directory / 0 exists, not a directory / -1 stat failed
 *  (errno). */
int nodus_fs_is_dir(const char *path);

/** Create ONE directory level. POSIX mkdir(path, 0700); Windows _wmkdir
 *  (no mode: the directory takes its parent's ACL). An existing entry is
 *  -1 with errno EEXIST, as mkdir. @return 0 / -1. */
int nodus_fs_mkdir(const char *path);

/** Create `path` and every missing parent (nodus_fs_mkdir per level, an
 *  existing level accepted); the last level must end up a directory.
 *  Separators: '/' — and on Windows also '\\'; a Windows drive prefix
 *  ("C:") is skipped. @return 0 / -1. */
int nodus_fs_mkdir_p(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_FS_H */
