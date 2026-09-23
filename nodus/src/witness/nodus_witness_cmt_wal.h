/**
 * @file nodus/src/witness/nodus_witness_cmt_wal.h
 * @brief cometbft @709fd12b `consensus/wal.go`'s STORAGE side — the
 *        `BaseWAL` write classes (:184-217), the periodic flush
 *        (:137-155), `SearchForEndHeight` (:231-292) and the record
 *        reader `catchupReplay` drives (replay.go:147) — over the
 *        `cmt_wal` SQLite table of D-15 rev 5 / D-17 rev 5.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W1, package R3-B. Nothing in the running chain calls
 * anything here; R3-C2 binds the five row functions into
 * `cmt_cs_host_t` and drives the flush deadline from the server tick.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE IS ──────────────────────────────────────────────────
 * `shared/dnac/cmt_wal.h` is the RECORD (the four kinds, their proto
 * form, `P` = the marshalled TimedWALMessage). This module is the LOG:
 *
 *   row     (protocol_id, height, seq, kind, bytes)          D-15 rev 5
 *           protocol_id  = 1
 *           height       = the height the message carries (below)
 *           seq          = per protocol_id, monotonic ACROSS heights,
 *                          restored as max(seq)+1 at open
 *           kind         = the WALMessage oneof field number, 1-4
 *           bytes        = SHA3-512(P) ‖ P
 *
 * ── THE THREE WRITE CLASSES (D-13 + D-15 rev 5 (4), both APPROVED) ─────
 * The reference writes every record into an autofile group BUFFER and
 * fsyncs that buffer at three distinct call classes; it never holds a
 * transaction of any kind (`Write`, wal.go:184-197, is a buffered write
 * whose own comment says "does not call fsync()"). The approved records
 * map those classes onto two connections, and EVERY row is written in
 * AUTOCOMMIT — no transaction is ever left open here:
 *
 *   `Write` (wal.go:184-197; state.go:760 round state, :831 peer
 *            message, :859 timeout) — one INSERT on the MAIN connection,
 *            which the witness opened at `synchronous=NORMAL`
 *            (nodus_witness.c:486-487). In WAL journal mode a NORMAL
 *            commit appends to the `-wal` file and does NOT fsync
 *            (measured: three such rows issue zero `fdatasync`), which
 *            is exactly the reference's buffered write. D-13: "received
 *            messages and timeout records are inserted through the
 *            existing synchronous=NORMAL connection".
 *   `WriteSync` (wal.go:201-217; state.go:839 own message, :1760
 *            EndHeight) — one INSERT on the SECOND connection, opened at
 *            `synchronous=FULL`, so the autocommit IS the fsync of :211
 *            (measured: exactly one `fdatasync`, on the `-wal` fd).
 *            D-13: the INSERT must return before the message is handed
 *            to the network.
 *   `FlushAndSync` (wal.go:157-159; state.go:1232 before publishing the
 *            proposal, :2374 before signing a vote) — D-15 rev 5 (4)
 *            makes this a HOST OBLIGATION ("every row written before
 *            that point is durable before the signature exists") and
 *            leaves the MECHANISM to R3 under D-13. SQLite has no
 *            fsync-on-demand and an EMPTY transaction commits nothing
 *            and syncs nothing (measured), so the mechanism is: bump the
 *            one `cmt_wal_sync` counter row on the FULL connection. That
 *            commit fdatasyncs the `-wal` file — the SAME file the main
 *            connection appended its Write-class rows to — so every one
 *            of them becomes durable with it (measured across the two
 *            connections). It is a no-op when nothing is pending.
 *            `PRAGMA wal_checkpoint` was the alternative and is REFUSED:
 *            it can return BUSY and then syncs nothing, so durability
 *            would depend on timing (NO FLAKY).
 *   the 2 s ticker (wal.go:28 `walDefaultFlushInterval`, :137-155
 *            `processFlushTicks`) — a `not_before` deadline armed at
 *            the first UNSYNCED Write-class row; the host's tick asks
 *            `nodus_cmt_wal_next_flush_deadline` and calls
 *            `nodus_cmt_wal_flush_if_due(now_ns)`; there is no thread.
 *
 * ── ONE CONTRACT THE CALLER MUST HONOUR ────────────────────────────────
 * A Write-class row joins whatever transaction the MAIN connection has
 * open, so the host must never call `nodus_cmt_wal_write` from INSIDE a
 * store transaction — a rolled-back ledger apply would take the WAL row
 * with it. The single-threaded event loop satisfies this by
 * construction: the ledger's transaction opens and closes inside
 * `apply_block`, and the core makes no WAL call from within it.
 *
 * `TimedWALMessage.Time` is stamped here from the host's `now`
 * (wal.go:189 `cmttime.Now()`); replay never reads it (cmt_wal.h).
 *
 * ── THE READ SIDE READS THROUGH THE MAIN CONNECTION ────────────────────
 * `SearchForEndHeight` and the record reader run on the MAIN connection.
 * Every row of both classes is committed the moment it is written, so
 * either connection can see all of them; the main one is chosen because
 * D-15 rev 5 point 5 requires rows appended DURING a replay to be
 * visible to the cursor in order, and during a replay the core's
 * `newStep` writes are Write-class — i.e. the main connection's own. A
 * reader there sees its own writes without waiting for anything. The
 * cursor is (height, seq); `wal_read_next` fetches the first row
 * strictly after it in `ORDER BY height, seq` and advances.
 *
 * `SearchForEndHeight` (wal.go:231-292) scans files newest → oldest and
 * returns at the FIRST EndHeight(h) it meets in the newest file holding
 * one; with one EndHeight per height (state.go:1760 writes it once per
 * height) that is the LAST EndHeight(h) in the log, which is what the
 * query below returns. The reference skips corrupted entries while
 * searching (`IgnoreDataCorruptionErrors: true`, replay.go:106); D-15
 * rev 5 makes a digest mismatch a STOP, so a corrupted EndHeight row is
 * CMT_FAULT here, never skipped — the strictness is the storage
 * layer's, stated in cmt_cs.h at the row.
 *
 * ── THE ROW DIGEST IS THE ONLY INTEGRITY CHECK ─────────────────────────
 * A kind-2/3 row carries no signature. On read the 64-byte prefix is
 * recomputed over P; a mismatch, a row shorter than the prefix, a kind
 * outside 1-4, a kind column disagreeing with the oneof inside P, or a
 * P longer than `CMT_WAL_MAX_MSG_SIZE_BYTES` (wal.go:385-390) is
 * CMT_FAULT. Replay stops; nothing is skipped (D-15 rev 5 (1)).
 *
 * ── WHERE EACH KIND KEEPS ITS HEIGHT (the row's `height` column) ───────
 *   1 EventDataRoundState  .height                   (events.go:94)
 *   2 MsgInfo              the consensus message's own height:
 *                          NewRoundStep/NewValidBlock/ProposalPOL/
 *                          BlockPart/HasVote/VoteSetMaj23/VoteSetBits
 *                          `.height`; Proposal `.proposal.height`;
 *                          Vote `.vote.height` (0 when the message
 *                          carries no vote — cmt_msgs.h says that is
 *                          unreachable in practice)
 *   3 timeoutInfo          .height                   (state.go:56)
 *   4 EndHeightMessage     .height                   (wal.go:43)
 *
 * ── THE TWO CONNECTIONS SHARE ONE FILE — measured ──────────────────────
 * SQLite allows ONE writer at a time on a file. While either connection
 * holds an OPEN write transaction the other's write waits out its busy
 * timeout and fails "database is locked" — measured, in both directions,
 * reads unaffected. That is why nothing here opens one: both classes are
 * single-statement autocommit, so each writer holds the lock only for
 * the duration of its own statement. The one remaining rule is the
 * caller contract above — the host must not call `Write` while the
 * ledger's own transaction is open on the main connection, and the
 * single-threaded loop never does.
 *
 * ⚠ HISTORY, so the earlier shape is not restored by accident: W1 first
 * shipped a version in which the `Write` class opened a transaction on
 * the WAL connection and left it open until the next COMMIT. That was an
 * ORCHESTRATOR mistranslation of the approved records, not a rule of
 * either: `finalizeCommit` saves the block on the main connection
 * (state.go:1737) while such a transaction would still be open from the
 * round-state and peer-message writes (:760, :831), so the store's write
 * deadlocked against the WAL's. The approved routing above has no such
 * state and the interaction disappears.
 *
 * ── `OnStart`'s ONE WRITE ──────────────────────────────────────────────
 * wal.go:124-131: an EMPTY log gets `WriteSync(EndHeightMessage{0})`
 * before anything else, and `catchupReplay` depends on it: replay.go
 * :125-128 sets `endHeight = 0` when `csHeight == InitialHeight`, :129
 * searches for it and :135-137 refuses to replay when it is absent.
 * "OnStart is YOK" in cmt_wal.h covers the lifecycle boilerplate, not
 * this write; it is `nodus_cmt_wal_start`, called once after open by
 * whoever owns the startup order — R3-C1's STARTUP TABLE, which is
 * where that call site lands. Not an operator question: the reference
 * fixes both the write and its position, only the owner is ours.
 *
 * ── PRUNE ──────────────────────────────────────────────────────────────
 * The reference's autofile group rotates and drops old files
 * (`auto.Group`, YOK); D-15 rev 5 names "prune below" instead:
 * `nodus_cmt_wal_prune_below(h)` deletes every row with height < h.
 * One caller later (R3-C1's height-close order).
 *
 * ── BUSY TIMEOUT ───────────────────────────────────────────────────────
 * The main connection waits `NODUS_W_DB_BUSY_TIMEOUT_MS /
 * NODUS_W_DB_OPEN_ATTEMPTS` per lock (nodus_witness.c:404-406, :484).
 * Both macros are file-local there, so this module re-derives the same
 * figure from the same published root (nodus_types.h:269) and the same
 * divisor — exactly as the deleted `nodus_witness_tm_wal.c` did. Two
 * connections contending on one file must wait the same amount.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * The clock is read only to stamp `TimedWALMessage.Time` (wal.go:189)
 * and to arm the flush deadline; neither value reaches consensus. The
 * replay order is the (height, seq) primary key, a total order.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/wal.go     434 lines
 *                        f6bd6d512bbda08f31231d535b97df3c9c6feb3ddaf01a2054e2f0cf994f2a2d
 *   consensus/replay.go  565 lines (:94-167)
 *                        5609c4d4174a536389cb2814bac09557a66e3299292141b54c635e31425284fe
 * Governing records: D-15 rev 6 (atlas-dec-c0bfc5344204b9282ceaaa5e06042350,
 * APPROVED 2026-09-14 — rev 5's routing plus the FlushAndSync barrier),
 * D-17 rev 6 (atlas-dec-9d96e2ec31ad4840cf258df21732b67f, APPROVED
 * 2026-09-14 — S14 with cmt_wal_sync), D-13 rev 1
 * (atlas-dec-c4ad532ce8434fe7d434ed61bc22804a), umbrella rev 5
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8).
 */

#ifndef NODUS_WITNESS_CMT_WAL_H
#define NODUS_WITNESS_CMT_WAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <sqlite3.h>

#include "dnac/cmt_tmhash.h"     /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "dnac/cmt_time.h"       /* cmt_now_fn                      */
#include "dnac/cmt_wal.h"        /* cmt_wal_message_t, timed, codec */

#ifdef __cplusplus
extern "C" {
#endif

/** D-15 rev 5: the consensus protocol's row namespace. */
#define NODUS_CMT_WAL_PROTOCOL_ID 1u

/** wal.go:28 `walDefaultFlushInterval = 2 * time.Second`, in ns. */
#define NODUS_CMT_WAL_FLUSH_INTERVAL_NS 2000000000LL

/** The digest prefix of every row: SHA3-512. */
#define NODUS_CMT_WAL_DIGEST_LEN 64u

typedef struct {
    sqlite3 *full;              /* OWNED — the second, synchronous=FULL   */
    sqlite3 *main_db;           /* BORROWED — the witness's, NORMAL       */
    uint32_t protocol_id;
    uint64_t next_seq;          /* max(seq)+1 at open, then monotonic     */
    bool     unsynced;          /* a Write-class row is not yet fsynced   */

    cmt_now_fn now;             /* wal.go:189 `cmttime.Now()`             */
    void      *now_ctx;

    bool     flush_armed;       /* the ticker, as a deadline              */
    int64_t  flush_deadline_ns;

    /* read cursor (SearchForEndHeight / Decode) */
    bool     cursor_valid;
    int64_t  cursor_height;
    uint64_t cursor_seq;

    /* host-owned storage for the record reader */
    cmt_pb_arena_t read_arena;  /* reset at every `wal_read_next`         */
    uint8_t *enc_buf;           /* CMT_WAL_MAX_MSG_SIZE_BYTES + digest    */
    size_t   enc_cap;

    sqlite3_stmt *st_insert;      /* WriteSync class — on `full`          */
    sqlite3_stmt *st_insert_main; /* Write class     — on `main_db`       */
    sqlite3_stmt *st_sync;        /* the FlushAndSync barrier — on `full` */
    sqlite3_stmt *st_max_seq;
    sqlite3_stmt *st_search;
    sqlite3_stmt *st_next;
    sqlite3_stmt *st_prune;
} nodus_cmt_wal_t;

/**
 * Opens the second connection on `sqlite3_db_filename(main_db, "main")`
 * (a file-less database is refused with CMT_FAULT before anything is
 * opened), sets WAL journal mode and `synchronous=FULL`, the shared busy
 * timeout, prepares the statements on BOTH connections, seeds the
 * `cmt_wal_sync` barrier row and restores `next_seq`. `main_db` is
 * BORROWED and must outlive this handle; the caller keeps it at
 * `synchronous=NORMAL`.
 * The `cmt_wal` and `cmt_wal_sync` tables must already exist (schema S14;
 * a chain opened by this build is at S15, the live rung as of
 * tokenomics-v3 P1 round 5 — S15 does not touch these tables, only
 * `validators` and the new attendance tables).
 * @return CMT_OK, CMT_FAULT.
 */
int nodus_cmt_wal_open(nodus_cmt_wal_t *w, sqlite3 *main_db,
                       cmt_now_fn now, void *now_ctx);

/**
 * wal.go:124-131 — the write inside `OnStart`: when the log holds no
 * row for this protocol, `WriteSync(EndHeightMessage{0})`.
 * @return CMT_OK, CMT_FAULT.
 */
int nodus_cmt_wal_start(nodus_cmt_wal_t *w);

/** Runs the durability barrier if anything is unsynced (wal.go:168 —
 *  `FlushAndSync` in `OnStop`), finalizes the statements on both
 *  connections and closes the OWNED one. `main_db` is not closed. */
void nodus_cmt_wal_close(nodus_cmt_wal_t *w);

/* ── the five host rows (ctx is a `nodus_cmt_wal_t *`) ────────────── */

/** state.go:760 / :831 / :859 — `wal.Write(msg)` (wal.go:184-197): one
 *  autocommit INSERT on the MAIN connection, no fsync. MUST NOT be
 *  called while a store transaction is open on that connection (see the
 *  header's caller contract). @return CMT_OK; CMT_REJECT for the reference's
 *  :190-194 error (the record will not encode, or exceeds
 *  CMT_WAL_MAX_MSG_SIZE_BYTES — wal.go:318-320); CMT_FAULT when SQLite
 *  fails. The caller logs, as the reference does. */
int nodus_cmt_wal_write(void *ctx, const cmt_wal_message_t *msg);

/** state.go:839 / :1760 — `wal.WriteSync(msg)` (wal.go:201-217): one
 *  autocommit INSERT on the FULL connection, which IS the fsync, and
 *  which also makes every earlier Write-class row durable (same `-wal`
 *  file), so the flush deadline is disarmed by it. @return CMT_OK;
 *  CMT_FAULT for anything else — the reference panics at both sites. */
int nodus_cmt_wal_write_sync(void *ctx, const cmt_wal_message_t *msg);

/** state.go:1232 / :2374 — `wal.FlushAndSync()` (wal.go:157-159): the
 *  `cmt_wal_sync` barrier on the FULL connection when a Write-class row
 *  is unsynced, otherwise nothing. @return CMT_OK, CMT_FAULT. */
int nodus_cmt_wal_flush_and_sync(void *ctx);

/** replay.go:106 / :129 — `wal.SearchForEndHeight(height, …)`
 *  (wal.go:231-292). On `*out_found` the cursor sits just after that
 *  EndHeight row. @return CMT_OK; CMT_FAULT for a corrupted row or a
 *  SQLite failure. */
int nodus_cmt_wal_search_end_height(void *ctx, int64_t height,
                                    bool *out_found);

/** replay.go:147 — `dec.Decode()` (wal.go:366-420's message half after
 *  the row digest). `*out` and every payload it points at live in the
 *  module's arena until the NEXT call. Without a prior successful
 *  search the cursor is the start of the log (a GroupReader from the
 *  first file). @return CMT_OK with `*out_eof`; CMT_FAULT for a
 *  corrupted row (see the header). */
int nodus_cmt_wal_read_next(void *ctx, cmt_timed_wal_message_t *out,
                            bool *out_eof);

/* ── the flush ticker as a deadline ───────────────────────────────── */

/** @return true with the deadline when a flush is pending. */
bool nodus_cmt_wal_next_flush_deadline(const nodus_cmt_wal_t *w,
                                       int64_t *out_deadline_ns);

/** wal.go:142-153 — one tick: if a flush is pending and `now_ns` has
 *  reached the deadline, `FlushAndSync`. @return CMT_OK, CMT_FAULT (the
 *  reference logs the error at :146 and keeps ticking; so may the
 *  caller). */
int nodus_cmt_wal_flush_if_due(nodus_cmt_wal_t *w, int64_t now_ns);

/* ── prune (D-15 rev 5 "prune below") ─────────────────────────────── */

/** Deletes every row of this protocol with height < `height`, as one
 *  autocommit statement on the FULL connection — so the delete is
 *  itself fsynced and, sharing the `-wal` file, it also makes any
 *  pending Write-class row durable; the flush deadline is disarmed with
 *  it. @return CMT_OK, CMT_FAULT. */
int nodus_cmt_wal_prune_below(nodus_cmt_wal_t *w, int64_t height);

/* ── exposed for the tests ────────────────────────────────────────── */

/** The row's `height` for a message (table in the header).
 *  @return CMT_OK; CMT_REJECT for kind NONE or an unknown MsgInfo kind. */
int nodus_cmt_wal_message_height(const cmt_wal_message_t *msg, int64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_WAL_H */
