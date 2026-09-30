/**
 * @file nodus/src/witness/nodus_witness_cmt_wal.h
 * @brief cometbft @v0.38.26 `consensus/wal.go` — `BaseWAL` (:76-218),
 *        `SearchForEndHeight` (:231-284), `WALEncoder` (:289-330) and
 *        `WALDecoder` (:356-420) — over the file group of
 *        `libs/autofile` (nodus_witness_cmt_autofile.h).
 *
 * Governing record: docs/plans/decisions/2026-09-26-cmt-wal-file-group.md
 * (operator APPROVED 2026-09-26). It supersedes the STORAGE half of D-15
 * rev 5/6 (rows in `cmt_wal`, two SQLite connections, the `cmt_wal_sync`
 * barrier) and the row-truncation MECHANISM of
 * 2026-09-26-cmt-wal-size-bound.md; its item 4 replaces that record's
 * 32 MB bound with the reference's 1 GB (see SIZE). The S14
 * tables `cmt_wal` / `cmt_wal_sync` are left in the schema, unused
 * (decision item 6): nothing here writes them, and the only read is the
 * one-time carry-over of item 6's AMENDED block
 * (`nodus_cmt_wal_carry_sqlite`, NOT GROUNDED).
 *
 * `shared/dnac/cmt_wal.h` is the RECORD (the four kinds and the
 * TimedWALMessage codec, `P`). This module is the LOG.
 *
 * ── ON DISK ────────────────────────────────────────────────────────────
 * Head `<data_path>/cs.wal/wal` (config.go:1036 `filepath.Join(
 * DefaultDataDir, "cs.wal", "wal")` — the witness's data_path is the
 * reference's data dir: the priv-validator state file sits beside it,
 * nodus_witness.c's `<data_path>/priv_validator_state.json`), rotated
 * files `wal.000`, `wal.001`, … (group.go:26-53, :413-418). The
 * directory is created 0700 (wal.go:92). Each record (wal.go:288,
 * :316-326):
 *
 *     crc32c(P)  4 bytes big-endian   Castagnoli, replay.go:20
 *     len(P)     4 bytes big-endian   len(P) <= CMT_WAL_MAX_MSG_SIZE_BYTES
 *     P          the marshalled TimedWALMessage (cmt_timed_wal_message_encode)
 *
 * `CMT_WAL_MAX_MSG_SIZE_BYTES` (shared/dnac/cmt_wal.h:100) is wal.go:25
 * `maxMsgSizeBytes = maxMsgSize + 24`, where `maxMsgSize` is
 * reactor.go:30 (1 MiB) = cmt_wal.h:95 `CMT_MAX_MSG_SIZE`, which
 * cmt_conr.c:30-33 static-asserts equal to the port's own consensus
 * reactor bound `CMT_CONR_MAX_MSG_SIZE`: one value, 1 048 600.
 *
 * ── THE THREE WRITE CLASSES (wal.go) ───────────────────────────────────
 *   `Write` (:184-196; state.go:760, :831, :859) — encode into the
 *            group's 40 KiB head buffer. NO fsync. Bytes reach the file
 *            when the buffer fills (bufio), at a FlushAndSync, at a
 *            rotation, or at close.
 *   `WriteSync` (:201-217; state.go:839, :1755) — `Write`, then
 *            `FlushAndSync`: durable before it returns.
 *   `FlushAndSync` (:155-159 → group.go:227-237; state.go:1227, :2367,
 *            and the 2 s ticker) — flush the head buffer, then fsync the
 *            head file. Always both; there is no "nothing pending"
 *            shortcut in the reference and there is none here.
 *
 * ── THE TWO TICKERS, AS DEADLINES ──────────────────────────────────────
 * The reference runs two goroutines: `processFlushTicks` (wal.go:137-153,
 * every `walDefaultFlushInterval` = 2 s, :28) and the group's
 * `processTicks` (group.go:239-250, every 5 s, :20: `checkHeadSizeLimit`
 * then `checkTotalSizeLimit`). Here both are deadlines armed by
 * `nodus_cmt_wal_start` (wal.go:133 `group.Start()`, :137 `NewTicker`)
 * and fired by `nodus_cmt_wal_flush_if_due` / `nodus_cmt_wal_group_check_
 * if_due` from the owner's event-loop tick; the next deadline follows
 * the Go runtime ticker's grid rule (nodus_witness_cmt_autofile.h).
 *
 * The caller is the witness loop, `witness_cmt_tick` (nodus_witness.c),
 * which also folds both deadlines into the deadline it returns
 * (decision 2026-09-26-cmt-wal-file-group.md item 4a).
 *
 * ── SIZE ───────────────────────────────────────────────────────────────
 * The reference's defaults, unchanged (decision item 4): the head file
 * rotates at `NODUS_CMT_GROUP_HEAD_SIZE_LIMIT` (10 MB, group.go:21) and
 * the group's total is bounded at `NODUS_CMT_GROUP_TOTAL_SIZE_LIMIT`
 * (1 GB, group.go:22 `defaultTotalSizeLimit`) — `NewWAL(walFile)` with
 * no group option, as state.go:452-453 `OpenWAL` calls it. At each 5 s check
 * the OLDEST files are removed while the total is at or above the bound,
 * at most 4 per check, never the head (group.go:268-299). A head that
 * alone exceeds the bound is logged ("Group's head may grow without
 * bound") and kept. The limits stay per-handle fields
 * (`group.head_size_limit`, `group.total_size_limit`) so a test can
 * lower them, as the reference's option functions do (group.go:122-134).
 *
 * ── THE READ SIDE ──────────────────────────────────────────────────────
 * `SearchForEndHeight` (wal.go:231-284): for every file index from the
 * newest to the oldest, a GroupReader starting at that file (and reading
 * ON into the later files, group.go:486-488) decodes records until EOF;
 * the first `EndHeight(height)` found leaves that reader as the replay
 * cursor. Both reference callers (replay.go:106, :129) pass
 * `IgnoreDataCorruptionErrors: true`, and the host row has no option
 * argument, so a corrupted record is logged and SKIPPED here (:263-266).
 * `nodus_cmt_wal_read_next` is `dec.Decode()` on that cursor
 * (replay.go:147). The reader sees what is in the FILES: a Write-class
 * record still in the head buffer is not visible until a flush — the
 * reference's own behaviour (its TODO, wal.go:73-75).
 *
 * ── CORRUPTION (wal.go:332-420) ────────────────────────────────────────
 * `Decode` classes: EOF while reading the CRC (0-3 bytes — `errors.Is(err,
 * io.EOF)`, :369-371) is a clean EOF; a short length, a length above
 * the bound, a zero length (group.go:462-464 "given empty slice"), a
 * short payload, a CRC mismatch, a payload that does not unmarshal or
 * convert, and a MsgInfo whose message fails `ValidateBasic` — each is a
 * `DataCorruptionError`. The last one is msgs.go:316 `MsgFromProto`,
 * whose final act is `ValidateBasic()` (msgs.go:232-234), reached from
 * wal.go:410 `WALFromProto`; the port's `cmt_timed_wal_message_decode`
 * stops short of it (cmt_wal.h), so the decoder here runs it itself.
 *
 * THE CORRUPTION CLASS (cmt_cs.h, `wal_read_next`): `read_next` returns
 * CMT_REJECT for a DataCorruptionError and for NOTHING else — the
 * reference's `Decode` has no other error class (wal.go:366-420 wraps
 * every failure in DataCorruptionError), so the row's REJECT IS the
 * reference's `IsDataCorruptionError(err)` (wal.go:333-336, used at
 * state.go:348 and replay.go:151). `cmt_cs_start` repairs on it
 * (state.go:338-386). DEVIATION, stated: an OS-level read error
 * (read(2)/open(2) failing, not a content check) is CMT_FAULT here; the
 * reference wraps it as a DataCorruptionError too (:373-374, :380-381,
 * :394-395), and its search loop's `continue` on such an error never
 * terminates while the error persists (:263-266).
 *
 * ── TORN TAIL (HARDENING, no reference counterpart) ───────────────────
 * Decision docs/plans/decisions/2026-09-27-p2p-fix-2.md 1(a). The
 * reference appends behind whatever the head ends with (wal.go:124-133,
 * group.go:204-208); a 1-3-byte CRC left by a crash decodes as a clean
 * io.EOF (wal.go:369-371), so the next record lands behind the torn bytes.
 * `nodus_cmt_wal_start` — before OnStart's own write and before any
 * append — walks the HEAD's 8-byte headers from offset 0: if the file
 * ends inside a header (1-7 bytes) or inside a body whose length is
 * 1..CMT_WAL_MAX_MSG_SIZE_BYTES, the head is truncated to the end of the
 * last complete, crc32c-valid record and fsynced. A zero or over-bound
 * length, or a complete record with a bad crc32c, stops the walk with
 * NOTHING changed: that is corruption, reported by the replay and
 * repaired as above. The read side is unchanged; only a torn head is
 * ever written. Consequence, stated: a torn 4-7-byte header or short body
 * that the reference would send through repair (with a `.CORRUPTED`
 * backup) is trimmed at start with no backup — the same records are
 * lost either way (repair keeps what precedes the first bad record).
 * The walk cannot tell a torn tail from a MID-FILE length field corrupted
 * to point past EOF (verifier F2, 2026-09-27): that case is trimmed too,
 * with every record behind it and no backup — again the same records
 * repair would drop, only without the `.CORRUPTED` copy.
 *
 * ── REPAIR (state.go:352-385, `repairWalFile` :2614-2646) ─────────────
 * `nodus_cmt_wal_repair` is the host's half of the reference's retry
 * loop: stop the WAL, copy the HEAD file to `<wal>.CORRUPTED`
 * (state.go:366, `cmtos.CopyFile` libs/os/os.go:88-112), re-encode every
 * record of that copy up to the first decode error into a fresh head
 * (os.Create — truncated), and reload the WAL (`loadWalFile` → `OpenWAL`
 * → `NewWAL` + `Start`, state.go:420-429, :452-467). Only the head is touched:
 * `cs.config.WalFile()` is the head path (config.go:1105-1110, default
 * `data/cs.wal/wal` at :1036), and rotated `wal.NNN` files are left as
 * they are — a corruption in one of them survives the repair, and the
 * retried replay then refuses to start, as the reference's does.
 *
 * HARDENING (decision 2026-09-27-p2p-fix-2.md 1(b), no reference
 * counterpart; departs from state.go:2621 `os.Create(dst)`, which
 * truncates the head before re-encoding into it): the `.CORRUPTED` copy
 * is fsynced and its directory fsynced BEFORE anything is rewritten; the
 * kept records go to `<dir>/NODUS_CMT_WAL_REPAIR_TMP_NAME` (a stale one
 * removed first), which is fsynced, renamed over the head, and the
 * directory fsynced. A crash at any step leaves the old head or the
 * complete repaired head. When no record is kept, the temp file holds
 * `EndHeight{0}` — what OnStart would write into the empty re-created
 * head one step later (wal.go:124-131) — so the head is never empty,
 * because an empty head would re-arm the one-time SQLite carry.
 *
 * ── OnStart's ONE WRITE ────────────────────────────────────────────────
 * wal.go:124-131: when the HEAD FILE's size is 0 — the head, not the
 * group; after a rotation with no later write the fresh head is empty
 * and gets it again, harmless because the search needs
 * `lastHeightFound > 0` to stop early (:256) — `WriteSync(EndHeight{0})`.
 * `catchupReplay` depends on it (replay.go:125-137).
 *
 * ── ERRORS ─────────────────────────────────────────────────────────────
 * The reference returns errors from Write/WriteSync/FlushAndSync and its
 * callers panic at the WriteSync sites (state.go:841-844, :1756-1759);
 * the port keeps each function's CMT_OK / CMT_REJECT / CMT_FAULT
 * contract below. Go's bufio error is STICKY (bufio.go:636-638, :691-
 * 693): after one failed write to the head file every later
 * Write/FlushAndSync fails too.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local: no byte of this log reaches a hash, a vote or a block. The
 * clock is read to stamp `TimedWALMessage.Time` (wal.go:189 — replay
 * never reads it, cmt_wal.h) and to arm the two tickers at start. The
 * record order is the append order, a total order.
 *
 * Reference @v0.38.26 (SHA-256 verified before use):
 *   consensus/wal.go     434 lines
 *                        f6bd6d512bbda08f31231d535b97df3c9c6feb3ddaf01a2054e2f0cf994f2a2d
 *   consensus/replay.go  :20 (crc32c table), :94-167 (catchupReplay)
 *   libs/autofile        see nodus_witness_cmt_autofile.h
 * crc32 (the reference's `hash/crc32`, Go 1.21.5 at /usr/local/go/src,
 * NOT in the pinned tree): Castagnoli polynomial 0x82f63b78
 * (hash/crc32/crc32.go:34), `simplePopulateTable` / `simpleUpdate`
 * (hash/crc32/crc32_generic.go:26-48).
 */

#ifndef NODUS_WITNESS_CMT_WAL_H
#define NODUS_WITNESS_CMT_WAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <sqlite3.h>             /* nodus_cmt_wal_carry_sqlite     */

#include "dnac/cmt_tmhash.h"     /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "dnac/cmt_time.h"       /* cmt_now_fn                      */
#include "dnac/cmt_wal.h"        /* cmt_wal_message_t, timed, codec */
#include "witness/nodus_witness_cmt_autofile.h"

#ifdef __cplusplus
extern "C" {
#endif

/** wal.go:28 `walDefaultFlushInterval = 2 * time.Second`, in ns. */
#define NODUS_CMT_WAL_FLUSH_INTERVAL_NS 2000000000LL

/** state.go:366 `fmt.Sprintf("%s.CORRUPTED", cs.config.WalFile())`. */
#define NODUS_CMT_WAL_CORRUPTED_SUFFIX ".CORRUPTED"

/** HARDENING (decision 2026-09-27-p2p-fix-2.md 1(b)): the repair's
 *  temporary file, in the head's directory. The repair refuses (CMT_FAULT)
 *  a head whose base name is a prefix of it, so `readGroupInfo`'s prefix
 *  match (group.go:380) never counts or indexes it. */
#define NODUS_CMT_WAL_REPAIR_TMP_NAME "repair-cs-wal.tmp"

/** wal.go:288 — the 4-byte CRC and the 4-byte length before `P`. */
#define NODUS_CMT_WAL_RECORD_HEADER_LEN 8u

/** Go 1.21.5 hash/crc32/crc32.go:34 `Castagnoli = 0x82f63b78` (the
 *  reversed polynomial), the table replay.go:20 builds. */
#define NODUS_CMT_CRC32C_POLY 0x82F63B78u

/** hash/crc32 `Table` — 256 entries. */
typedef uint32_t nodus_cmt_crc32_table_t[256];

/** Go 1.21.5 hash/crc32/crc32_generic.go:26-38 `simplePopulateTable`. */
void nodus_cmt_crc32_make_table(uint32_t poly, nodus_cmt_crc32_table_t tab);

/** Go 1.21.5 hash/crc32/crc32_generic.go:42-48 `simpleUpdate`;
 *  `crc32.Checksum(data, tab)` is `update(0, tab, data)`. */
uint32_t nodus_cmt_crc32_update(uint32_t crc,
                                const nodus_cmt_crc32_table_t tab,
                                const uint8_t *p, size_t n);

typedef struct {
    nodus_cmt_group_t group;          /* wal.go:79 group               */
    nodus_cmt_crc32_table_t crc32c;   /* replay.go:20                  */
    char     path[NODUS_CMT_AUTOFILE_PATH_MAX]; /* walFile (wal.go:91);
                                       * the repair reopens it         */

    cmt_now_fn now;                   /* wal.go:189 `cmttime.Now()`    */
    void      *now_ctx;

    bool     started;                 /* OnStart ran (service state)   */
    int64_t  flush_interval_ns;       /* wal.go:83-84, :104            */
    bool     flush_armed;             /* wal.go:83 flushTicker         */
    int64_t  flush_deadline_ns;

    /* the replay cursor — the GroupReader `SearchForEndHeight` returns
     * (wal.go:276) and `Decode` reads from (replay.go:143-147) */
    bool     cursor_valid;
    nodus_cmt_group_reader_t *cursor; /* heap: carries a 4 KiB buffer  */

    cmt_timed_wal_message_t *stamp;   /* heap scratch for Write (:189) */
    uint8_t *enc_buf;                 /* header + CMT_WAL_MAX_MSG_SIZE_BYTES */
    size_t   enc_cap;
    uint8_t *dec_buf;                 /* CMT_WAL_MAX_MSG_SIZE_BYTES    */
    cmt_pb_arena_t read_arena;        /* reset at every decoded record */
} nodus_cmt_wal_t;

/**
 * wal.go:91-108 `NewWAL(walFile)` — `EnsureDir(filepath.Dir(walFile),
 * 0700)` (:92; os.MkdirAll), then `auto.OpenGroup(walFile)` (:97) with
 * the reference's default limits, the 2 s flush interval (:104), and the
 * buffers. Nothing is written.
 * @param wal_file the head path, `<data_path>/cs.wal/wal` in production.
 * @return CMT_OK, CMT_FAULT.
 */
int nodus_cmt_wal_open(nodus_cmt_wal_t *w, const char *wal_file,
                       cmt_now_fn now, void *now_ctx);

/**
 * wal.go:124-140 `OnStart` — first (HARDENING 1(a), header: TORN TAIL) a
 * head ending in a torn record is truncated to its last complete record
 * and fsynced; then, when the head file's size is 0,
 * `WriteSync(EndHeightMessage{0})`; then `group.Start()` (the 5 s
 * check deadline) and the 2 s flush deadline, both from `now`.
 * @return CMT_OK, CMT_FAULT (also when the torn-tail check cannot read
 * the head or the truncate fails).
 */
int nodus_cmt_wal_start(nodus_cmt_wal_t *w);

/** wal.go:164-173 `OnStop` + `group.Close()` — when started: disarm the
 *  flush ticker, FlushAndSync (an error is logged, "error on flush data
 *  to disk"), `group.Stop()` (group.go:146-151); then `group.Close()`
 *  (group.go:161-169) and free the buffers. Safe on a zeroed handle. */
void nodus_cmt_wal_close(nodus_cmt_wal_t *w);

/* ── the five host rows (ctx is a `nodus_cmt_wal_t *`) ────────────── */

/** state.go:760 / :831 / :859 — `wal.Write(msg)` (wal.go:184-196):
 *  stamp, encode, append to the head buffer. No fsync.
 *  @return CMT_OK; CMT_REJECT for the reference's `Encode` error (the
 *  message does not convert, or `len(P)` exceeds the bound — :302-305,
 *  :318-320), logged as :190-191; CMT_FAULT when the clock or the group
 *  write fails. */
int nodus_cmt_wal_write(void *ctx, const cmt_wal_message_t *msg);

/** state.go:839 / :1755 — `wal.WriteSync(msg)` (wal.go:201-217):
 *  `Write`, then `FlushAndSync`; durable when CMT_OK returns.
 *  @return CMT_OK; CMT_FAULT for any failure — the reference panics at
 *  both call sites (state.go:841-844, :1756-1759). */
int nodus_cmt_wal_write_sync(void *ctx, const cmt_wal_message_t *msg);

/** state.go:1227 / :2367 — `wal.FlushAndSync()` (wal.go:157-159 →
 *  group.go:227-237): flush the head buffer and fsync the head file.
 *  @return CMT_OK, CMT_FAULT. */
int nodus_cmt_wal_flush_and_sync(void *ctx);

/** replay.go:106 / :129 — `wal.SearchForEndHeight(height,
 *  &WALSearchOptions{IgnoreDataCorruptionErrors: true})` (wal.go:231-
 *  284). Any previous cursor is closed first. On `*out_found` the cursor
 *  sits just after that EndHeight record.
 *  @return CMT_OK; CMT_FAULT for an OS-level read/open error or a
 *  failed allocation (header: CORRUPTION). */
int nodus_cmt_wal_search_end_height(void *ctx, int64_t height,
                                    bool *out_found);

/** replay.go:147 — `dec.Decode()` (wal.go:366-420) on the cursor.
 *  Without a cursor (no successful search) one is opened at the group's
 *  first file (`NewReader(MinIndex)`). `*out` and every payload it points
 *  at live in the module's arena until the NEXT call.
 *  @return CMT_OK with `*out_eof`; CMT_REJECT for a DataCorruptionError
 *  and for nothing else (header: THE CORRUPTION CLASS); CMT_FAULT for an
 *  OS-level read/open error or a failed allocation. */
int nodus_cmt_wal_read_next(void *ctx, cmt_timed_wal_message_t *out,
                            bool *out_eof);

/** The host's half of state.go:352-385 (header: REPAIR), on a STARTED
 *  WAL: `wal.Stop()` (:359-361 — a WAL that was never started is the
 *  reference's ErrNotStarted, CMT_FAULT), `CopyFile(walFile,
 *  walFile+".CORRUPTED")` (:366-369; HARDENING: fsynced with its
 *  directory), `repairWalFile(corrupted, walFile)` (:374-377, :2614-2646;
 *  HARDENING 1(b): temp file + fsync + rename + directory fsync, never an
 *  empty head), `loadWalFile()` (:382-384) — reopened and
 *  started into the SAME handle, so a host that holds `w` keeps a valid
 *  pointer. The clock callback is carried over.
 *  @return CMT_OK; CMT_FAULT at the first failing step (the reference
 *  returns that error from OnStart, :360/:367/:376/:383 — the node does
 *  not start). After a failure the handle is closed. */
int nodus_cmt_wal_repair(nodus_cmt_wal_t *w);

/* ── the two tickers as deadlines (header: THE TWO TICKERS) ─────────── */

/* ── the one-time carry-over from the SQLite-era WAL ───────────────── */

/** `cmt_wal.protocol_id` of every row the SQLite-era WAL wrote (the old
 *  header's `NODUS_CMT_WAL_PROTOCOL_ID 1u`, nodus 0.19.80 /
 *  d123b7e6 nodus_witness_cmt_wal.h:204). */
#define NODUS_CMT_WAL_SQLITE_PROTOCOL_ID 1

/** The old row's `bytes` prefix: SHA3-512(P) (old header :210
 *  `NODUS_CMT_WAL_DIGEST_LEN 64u`). */
#define NODUS_CMT_WAL_SQLITE_DIGEST_LEN 64u

/** The carry's temporary file, in the head's directory. Its name does
 *  not start with the head's base name, so `readGroupInfo`'s prefix
 *  match (group.go:380) never counts or indexes it. */
#define NODUS_CMT_WAL_CARRY_TMP_NAME "carry-sqlite.tmp"

/**
 * ⚠ NOT GROUNDED — the reference never migrates WAL storage. Decision
 * 2026-09-26-cmt-wal-file-group.md item 6, AMENDED 2026-09-27 (operator
 * "1 aktarma kodu", red-team R5 F1): the SQLite-era WAL (schema S14
 * table `cmt_wal`, rows `(protocol_id, height, seq, kind,
 * SHA3-512(P) ‖ P)`, written by nodus <= 0.19.80) is read ONCE, at the
 * first start of the file-WAL build, and its TAIL is re-framed into the
 * file group, so a node that had signed at the tip before a stop-all
 * upgrade replays its own signed messages instead of starting at
 * (H, round 0) against a privval that refuses to sign again.
 *
 * Runs only when ALL hold — otherwise it is a no-op (CMT_OK, `*out_rows`
 * 0): the head `wal_file` is absent or 0 bytes; no rotated `wal.NNN`
 * exists; the table `cmt_wal` exists; it holds rows of protocol 1.
 *
 * The TAIL is the latest EndHeight row (kind 4, the highest seq) and
 * every row of the protocol after it, in seq order — the append order,
 * which is the file's order (the SQLite reader's replay order was
 * (height, seq); the file group's is the append order, wal.go:231-284).
 * Every row is checked exactly as the old reader's `wal_decode_row` did
 * (d123b7e6 nodus_witness_cmt_wal.c:455-506): the digest prefix present,
 * `len(P) <= CMT_WAL_MAX_MSG_SIZE_BYTES`, SHA3-512(P) equal, kind 1-4,
 * P decodes, the decoded kind and height equal the row's columns — and
 * (decision 2026-09-27-p2p-fix-2.md item 1) a MsgInfo passes
 * `cmt_msg_validate_basic`, the file reader's own check (header:
 * CORRUPTION), so no carried record can be a DataCorruptionError that
 * the first replay's repair would cut the tail at. The
 * payload P is written unchanged as `crc32c(P) ‖ len(P) ‖ P`.
 *
 * A row that fails a check, a seq that does not increase, or rows with
 * no EndHeight row at all (unreachable: the old OnStart seeded
 * EndHeight{0} into an empty table and nothing ever deleted a row) is
 * CMT_FAULT with an ERROR naming it, and NO file is left behind: the
 * rows were written under D-15 rev 5 "stop, never skip", so the node
 * refuses to start and recovery is manual (the rows are untouched —
 * rolling back to the old build replays them).
 *
 * Atomic: the directory is ensured (0700, as `nodus_cmt_wal_open`), a
 * stale temp file is removed, the frames go to
 * `<dir>/NODUS_CMT_WAL_CARRY_TMP_NAME` (0600, autofile.go:38's mode),
 * which is fsynced, renamed onto `wal_file`, and the directory fsynced.
 * Any failure removes the temp file (and, when only the directory fsync
 * after the rename failed, the renamed head too, so the next start
 * carries again). The SQLite rows are NEVER deleted
 * or modified. Memory is bounded by one row (sqlite3_step streaming).
 *
 * The carried head may exceed the 10 MB head limit; the group's 5 s
 * check rotates it whole on its first tick (`checkHeadSizeLimit`,
 * group.go:263-265 `size >= limit` → `RotateFile`).
 *
 * @param db       the chain DB's main connection (read only here).
 * @param wal_file the head path, `<data_path>/cs.wal/wal`.
 * @param out_rows optional: rows carried (0 on a no-op).
 * @return CMT_OK (carried, or nothing to do), CMT_FAULT.
 */
int nodus_cmt_wal_carry_sqlite(sqlite3 *db, const char *wal_file,
                               size_t *out_rows);

/** @return true with the deadline when the 2 s flush ticker is armed. */
bool nodus_cmt_wal_next_flush_deadline(const nodus_cmt_wal_t *w,
                                       int64_t *out_deadline_ns);

/** wal.go:142-153 `processFlushTicks`, one wake-up: if armed and
 *  `now_ns` has reached the deadline, `FlushAndSync`, and the deadline
 *  moves on. @return CMT_OK, CMT_FAULT (the reference logs "Periodic
 *  WAL flush failed" at :146-148 and keeps ticking — so does this, the
 *  deadline moves on either way). */
int nodus_cmt_wal_flush_if_due(nodus_cmt_wal_t *w, int64_t now_ns);

/** @return true with the deadline when the group's 5 s check ticker is
 *  armed. */
bool nodus_cmt_wal_next_group_check_deadline(const nodus_cmt_wal_t *w,
                                             int64_t *out_deadline_ns);

/** group.go:239-250 `processTicks`, one wake-up —
 *  `nodus_cmt_group_check_if_due` on the WAL's group (rotation at 10 MB,
 *  the 1 GB total). @return CMT_OK; CMT_FAULT when the rotation or the
 *  directory scan failed (the reference panics there). */
int nodus_cmt_wal_group_check_if_due(nodus_cmt_wal_t *w, int64_t now_ns);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_WAL_H */
