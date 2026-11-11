/**
 * Nodus — log shim: the opt-in log file
 *
 * The standalone nodus build links src/nodus_log_shim.c instead of the shared
 * qgp_log.c. Its lines go to stderr only. This header adds ONE opt-in
 * facility: a timestamped log file. Until nodus_log_file_open() is called the
 * shim behaves exactly as before (stderr line unchanged, no file, no lock
 * taken); every binary that never calls it is unaffected.
 *
 * Once open, every line that passes the shim's level filter (INFO and above,
 * the same filter as the stderr line, qgp_log_should_log in the shim) is also
 * appended to "<dir>/nodus-amm.log" as
 *
 *     2026-11-11T18:12:40.123Z [WRN] AMM_RPC: text
 *
 * (UTC, milliseconds; level DBG/INF/WRN/ERR; the line is built in a 1024-byte
 * buffer and cut, never overflowed; carriage returns and newlines inside the
 * text become spaces so one call is one line). Writes are serialised by one
 * mutex (safe from several threads). A write that fails is dropped: logging
 * never crashes or retries the caller.
 */
#ifndef NODUS_LOG_SHIM_H
#define NODUS_LOG_SHIM_H

#include <stddef.h>

/**
 * Start writing the log file "<dir>/nodus-amm.log" (created with mode 0640,
 * opened O_APPEND; `dir` is created, one level, mode 0750, if missing).
 *
 * Rotation: when the file holds `max_bytes` or more, it becomes "<file>.1",
 * the old ".1" becomes ".2", and so on up to ".<keep_files>"; the oldest is
 * dropped. `keep_files` counts rotated files (not the current one).
 *
 * A second call closes the first file and starts again.
 *
 * @param dir         existing or creatable directory, at most 200 bytes
 * @param max_bytes   rotation size, >= 1
 * @param keep_files  rotated files kept, >= 1
 * @return 0, or -1 (bad argument or the file cannot be opened; nothing opened)
 */
int nodus_log_file_open(const char *dir, size_t max_bytes, int keep_files);

/** Stop the file sink and close the file (the shim returns to stderr only). */
void nodus_log_file_close(void);

#endif /* NODUS_LOG_SHIM_H */
