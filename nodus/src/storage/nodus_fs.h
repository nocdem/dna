/**
 * @file nodus_fs.h
 * @brief A small portable FILE layer for the segment files (design
 *        docs/plans/2026-10-19-windows-light-storage-design.md §3 "Rev 1
 *        corrections", B4 portable segment files).
 *
 * On Linux / Android every call except two is one POSIX call — the call,
 * flags and mode the segment code issued before this layer existed — and
 * its Windows counterpart on Windows. The two exceptions:
 * nodus_fs_is_dir is a COMPOSITION (stat, then S_ISDIR — the segment
 * code's own two steps), and nodus_fs_mkdir_p is NEW (no call before this
 * layer; one nodus_fs_mkdir per level). Nothing here decides anything:
 * the callers keep every rule (what to open, in which order to rename,
 * when a short read means a torn record).
 *
 * 64-BIT OFFSETS: nodus_fs.c is compiled with _FILE_OFFSET_BITS 64 on
 * POSIX (and fails to compile if off_t is not 8 bytes), so a 32-bit ABI
 * — Android armeabi-v7a, which builds this file through messenger — calls
 * the *64 forms (pread64, pwrite64, ftruncate64, ...) and an offset at or
 * above 2 GiB is not truncated. On 64-bit Linux the instructions are the
 * same; only the libc symbol names differ, aliases of one entry point.
 *
 * File handles are C runtime file descriptors (`int`) on both platforms.
 * On Windows the descriptor wraps a HANDLE opened with CreateFileW and
 * FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, so a file may be
 * renamed or unlinked while a descriptor on it is still open — the segment
 * build renames its data file before it closes it, as on POSIX. An unlink
 * moves the file aside before deleting it, so its name is free at once
 * (nodus_fs_unlink_if_exists).
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
 * violation), EBUSY (a name whose delete is pending; it may also surface
 * as EACCES), ENAMETOOLONG (a path over the Win32 limit or over this
 * layer's UTF-16 buffer), ENOSPC (disk full), EINVAL (a path that is not
 * valid UTF-8), EBADF (a descriptor without a handle), EIO (anything
 * else) — and every code other than the ENOENT / EEXIST ones logged at
 * DEBUG with its number, BEFORE errno is set (the logger cannot overwrite
 * it). The calls that go through the CRT (_wunlink, _wmkdir, _wstat64,
 * _commit, _fstat64, _chsize_s) carry the CRT's own errno mapping (not
 * verified in this tree). Callers that test `errno == ENOENT` /
 * `errno == EEXIST` work the same on both platforms: ENOENT and EEXIST
 * are only ever "not found" and "already exists".
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
 *  open(O_RDONLY | O_DIRECTORY), fsync, close. Windows: CreateFileW
 *  (GENERIC_WRITE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS) on the
 *  directory, FlushFileBuffers, CloseHandle — a failure is -1, never a
 *  silent 0; what NTFS makes durable through it is NOT verified (under
 *  Wine it may be a no-op), and nodus_fs_rename is WRITE_THROUGH on top
 *  (nodus_fs.c). @return 0 / -1. */
int nodus_fs_dir_sync(const char *dir);

/** Rename `from` to `to`, replacing `to` when it exists, in one step.
 *  POSIX rename; Windows MoveFileExW(MOVEFILE_REPLACE_EXISTING |
 *  MOVEFILE_WRITE_THROUGH). @return 0 / -1. */
int nodus_fs_rename(const char *from, const char *to);

/** The tag of the aside name the Windows unlink moves a file to before it
 *  deletes it: "<path>" NODUS_FS_ASIDE_TAG "<pid>.<n>". Never a segment
 *  file name (nodus_seg_name_parse wants one of its six suffixes exactly
 *  after "seg-<k>"). */
#define NODUS_FS_ASIDE_TAG ".deleted."

/** Remove `path`; a file that does not exist is not an error. POSIX
 *  unlink (ENOENT accepted). Windows: the NAME is freed first — the file
 *  is moved to "<path>.deleted.<pid>.<n>" (MoveFileExW, no replace) and
 *  that is deleted (DeleteFileW; a file still held is delete-pending under
 *  the aside name and goes at its last close), so the name can be created
 *  again at once while a holder keeps reading the old bytes, as on POSIX;
 *  absent → 0 (ENOENT); a move refused for another reason, or a directory
 *  → _wunlink (ENOENT accepted), as before. A crash can leave
 *  "*.deleted.*" files; nothing reads them (nodus_fs.c "Unlink").
 *  @return 0 removed or absent / -1 (errno). */
int nodus_fs_unlink_if_exists(const char *path);

/** Whether `path` exists. POSIX stat; Windows _wstat64. @return 1 / 0. */
int nodus_fs_exists(const char *path);

/** What `path` is — a composition, not one call. POSIX stat + S_ISDIR;
 *  Windows _wstat64 + _S_IFDIR.
 *  @return 1 a directory / 0 exists, not a directory / -1 stat failed
 *  (errno). */
int nodus_fs_is_dir(const char *path);

/** Create ONE directory level. POSIX mkdir(path, 0700); Windows _wmkdir
 *  (no mode: the directory takes its parent's ACL). An existing entry is
 *  -1 with errno EEXIST, as mkdir. @return 0 / -1. */
int nodus_fs_mkdir(const char *path);

/** NEW with this layer (the segment code had no equivalent).
 *  Create `path` and every missing parent (nodus_fs_mkdir per level, an
 *  existing level accepted); the last level must end up a directory.
 *  Separators: '/' — and on Windows also '\\'; a Windows drive prefix
 *  ("C:") is skipped. @return 0 / -1. */
int nodus_fs_mkdir_p(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_FS_H */
