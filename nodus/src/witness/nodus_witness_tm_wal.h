/**
 * @file nodus_witness_tm_wal.h
 * @brief Tendermint consensus write-ahead log (`tm_wal`) and validator
 *        state row (`tm_state`) — T3 wave 1 (T2 wire design §4.6, §4.10;
 *        Atlas D-13, D-15 rev 4).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * NOTHING in the witness runtime calls this module in wave 1. The host
 * that opens it, replays it and acts on the startup classification is
 * wave 2 (T3 host design §5). Only the ctest `test_tm_wal` drives it.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── What this module is ───────────────────────────────────────────────
 * A Tendermint node may not forget what it signed. If a crash loses the
 * node's own PRECOMMIT and it then signs a different value at the same
 * (height, round), it has double-signed — the one fault a BFT safety
 * proof does not survive. The reference makes its own messages durable
 * before they are sent (cometbft `spec/consensus/wal.md` @709fd12b); this
 * module is that guarantee expressed in the witness's SQLite database.
 *
 * ── The two connections (D-13, APPROVED) ──────────────────────────────
 * The main witness connection runs `PRAGMA synchronous=NORMAL`
 * (`nodus_witness.c:487`), and SQLite documents that a WAL-mode
 * transaction committed at NORMAL "might roll back following a power
 * loss or system crash". So this module opens a SECOND connection to the
 * SAME database file with `synchronous=FULL` and routes writes by who
 * produced them:
 *
 *   FULL (fsync before the call returns)   NORMAL (main handle, borrowed)
 *   ────────────────────────────────────   ──────────────────────────────
 *   own signed messages (own = 1)          received messages (own = 0)
 *   END_HEIGHT rows (kind 3)               TIMEOUT rows (kind 2)
 *   tm_state rows
 *   prune
 *   EVERY read (replay, last_end_height,
 *   state_read) — one reader, one answer
 *
 * The asymmetry is the point (G20): losing a received PREVOTE costs a
 * catch-up round, losing our own PRECOMMIT costs safety. `emit` is
 * ordered persist → fsync → broadcast: the append call returning IS the
 * permission to send.
 *
 * ── Row integrity (D-15 rev 4 (1), DG-15, G21) ────────────────────────
 * Every `tm_wal` and `tm_state` row stores `SHA3-512(payload) ‖ payload`.
 * Reads recompute the digest and compare. A mismatch is -2 FAULT and, in
 * replay, STOPS: the callback is not invoked for that row nor for any
 * later one. There is deliberately NO skip path — a WAL with a hole in
 * it cannot reconstruct the state it exists to reconstruct.
 *
 * The digest covers the `bytes` column ONLY. `protocol_id`, `height`,
 * `seq` and `kind` are SQLite integers outside it (the approved D-15
 * shape); replay therefore range-checks `kind` rather than trusting it.
 *
 * ── Payload layouts (T3 host design §4.E; all integers big-endian) ─────
 *   kind 1 MSG        the signed T3 message body as-is, without the frame
 *                     header. OPAQUE to this module — it neither parses
 *                     nor validates it.
 *   kind 2 TIMEOUT    height u64 ‖ round u32 ‖ step u8            (13 B)
 *   kind 3 END_HEIGHT height u64                                   (8 B)
 *   tm_state          height u64 ‖ vset_hash[64] ‖ n u32
 *                     ‖ n × voter_id[32] ‖ n × priority i64
 *                     ‖ proposer_idx u32                    (80 + 40n B)
 *
 * ── Return contract (tree idiom, `qc_v2.h` O15A separation) ───────────
 *   0   accepted
 *  -1   REJECT — the bytes or the arguments are bad. Deterministic: every
 *       node given the same input answers the same way.
 *  -2   FAULT — THIS PROCESS could not decide (out of memory, hash
 *       backend, SQLite). Says nothing about the input.
 *
 * @file nodus_witness_tm_wal.h
 */

#ifndef NODUS_WITNESS_TM_WAL_H
#define NODUS_WITNESS_TM_WAL_H

#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#include "dnac/ledger_ids.h"   /* DNA_MAX_ACTIVE_VALIDATORS */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Row kinds (D-15 rev 4; the set is CLOSED — a fourth kind was
 * proposed as START_HEIGHT in rev 1 and withdrawn for want of a
 * reference). Replay refuses anything else. */
#define NODUS_TM_WAL_KIND_MSG         1u
#define NODUS_TM_WAL_KIND_TIMEOUT     2u
#define NODUS_TM_WAL_KIND_END_HEIGHT  3u

/* SHA3-512 digest prefix carried by every stored row. */
#define NODUS_TM_WAL_DIGEST_LEN       64u

/* Fixed payload lengths of the two structured kinds. */
#define NODUS_TM_WAL_TIMEOUT_PAYLOAD_LEN  13u   /* u64 + u32 + u8 */
#define NODUS_TM_WAL_END_PAYLOAD_LEN       8u   /* u64            */

/* tm_state payload length for a set of `n` validators, and its ceiling.
 * 80 + 40n: 8 height + 64 vset_hash + 4 n + 4 proposer_idx, plus 32 + 8
 * per validator. n = 4 → 240; n = 128 → 5 200 (T3 host design §4.E). */
#define NODUS_TM_STATE_PAYLOAD_LEN(n)  (80u + 40u * (unsigned)(n))
#define NODUS_TM_STATE_MAX_PAYLOAD \
    NODUS_TM_STATE_PAYLOAD_LEN(DNA_MAX_ACTIVE_VALIDATORS)

/** Opaque handle: the FULL second connection (owned), the NORMAL main
 *  connection (borrowed — never closed here), the protocol id and the
 *  next sequence number. */
typedef struct nodus_tm_wal nodus_tm_wal_t;

/** Open the SECOND connection on the same database file as `main_db`
 *  (`sqlite3_db_filename(main_db, "main")`), with
 *  `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL` and the same busy
 *  timeout the main connection carries.
 *
 *  REFUSES (-1) an in-memory or temporary `main_db`: both report an empty
 *  filename and have no file a second connection could attach to. The
 *  refusal is checked BEFORE anything is opened.
 *
 *  Restores `next_seq = max(seq) + 1` for `protocol_id` (0 when the log
 *  is empty), so sequence numbers stay monotonic across restarts.
 *
 *  The `tm_wal` / `tm_state` tables must already exist: the database is
 *  expected at schema version 13 (S13).
 *
 *  @return 0 opened; -1 bad arguments / not a file-backed database;
 *          -2 SQLite or allocation fault. */
int nodus_tm_wal_open(nodus_tm_wal_t **out, sqlite3 *main_db,
                      uint32_t protocol_id);

/** Close and free. The borrowed main connection is NOT closed. Safe on
 *  NULL and on an already-closed handle; `*w` is set to NULL. */
void nodus_tm_wal_close(nodus_tm_wal_t **w);

/** Append a kind-1 MSG row carrying `body` verbatim.
 *
 *  `own = 1` → the FULL connection: the INSERT has been fsynced when this
 *  returns, which is what makes the message safe to broadcast (D-13:
 *  emit = persist, fsync, then send). `own = 0` → the NORMAL connection.
 *
 *  @param seq_out optional; receives the sequence number written.
 *  @return 0 / -1 bad arguments / -2 fault. */
int nodus_tm_wal_append_msg(nodus_tm_wal_t *w, uint64_t height,
                            const uint8_t *body, size_t len, int own,
                            uint64_t *seq_out);

/** Append a kind-2 TIMEOUT row (13-byte payload). NORMAL connection: a
 *  lost timeout costs a re-scheduled step, never a second signature. */
int nodus_tm_wal_append_timeout(nodus_tm_wal_t *w, uint64_t height,
                                uint32_t round, uint8_t step);

/** Append a kind-3 END_HEIGHT row (8-byte payload). FULL connection —
 *  this row is what tells the next startup that `height` is closed and
 *  must never be replayed (D-15 rev 4, `replay.go:101-116`). */
int nodus_tm_wal_append_end_height(nodus_tm_wal_t *w, uint64_t height);

/** Highest END_HEIGHT recorded for this protocol_id — the `E` of the
 *  startup table. `*have` is 0 when no such row exists (and `*height` is
 *  then left at 0). Read through the FULL connection.
 *  @return 0 / -1 bad arguments / -2 fault. */
int nodus_tm_wal_last_end_height(nodus_tm_wal_t *w, int *have,
                                 uint64_t *height);

/** Replay callback. `payload` points into SQLite-owned memory and is
 *  valid ONLY for the duration of the call — copy what must outlive it.
 *  @return 0 to continue, non-zero to stop the replay. */
typedef int (*nodus_tm_wal_replay_cb)(void *ctx, uint8_t kind,
                                      uint64_t height, uint64_t seq,
                                      const uint8_t *payload, size_t len);

/** Replay every row with `height > from_height_exclusive`, in
 *  (height, seq) order, verifying each row's digest first.
 *
 *  A digest mismatch, an unreadable row or a `kind` outside 1..3 STOPS
 *  the replay and returns -2; the offending row and every row after it
 *  are NOT delivered. A callback returning non-zero also stops, and is
 *  reported as -1.
 *
 *  @return 0 the whole range was delivered; -1 bad arguments or the
 *          callback asked to stop; -2 fault (integrity or SQLite). */
int nodus_tm_wal_replay(nodus_tm_wal_t *w, uint64_t from_height_exclusive,
                        nodus_tm_wal_replay_cb cb, void *ctx);

/** Delete every row with `height < height` for this protocol_id (FULL).
 *  @return 0 / -1 bad arguments / -2 fault. */
int nodus_tm_wal_prune_below(nodus_tm_wal_t *w, uint64_t height);

/* ── tm_state: the validator set the node is running a height with ──── */

typedef struct {
    uint64_t height;
    uint8_t  vset_hash[64];
    uint32_t n;
    uint8_t  voter_id[DNA_MAX_ACTIVE_VALIDATORS][32];
    int64_t  priority[DNA_MAX_ACTIVE_VALIDATORS];
    uint32_t proposer_idx;
} nodus_tm_state_row_t;

/** Encode a state row into its payload bytes (NO digest prefix — the
 *  digest is added when the row is written).
 *  @param written optional; receives `NODUS_TM_STATE_PAYLOAD_LEN(n)`.
 *  @return 0; -1 bad arguments, `n > DNA_MAX_ACTIVE_VALIDATORS`, or
 *          `cap` too small. */
int nodus_tm_state_encode(const nodus_tm_state_row_t *row, uint8_t *dst,
                          size_t cap, size_t *written);

/** Decode a state-row payload. STRICT: the length must be exactly
 *  `80 + 40n` for the encoded `n`, and `n` must not exceed
 *  `DNA_MAX_ACTIVE_VALIDATORS` — a trailing byte, a missing byte or an
 *  oversized set is -1, never a repaired row.
 *  @return 0 / -1. */
int nodus_tm_state_decode(const uint8_t *src, size_t len,
                          nodus_tm_state_row_t *row);

/** Write (INSERT OR REPLACE) the single tm_state row through the FULL
 *  connection. @return 0 / -1 / -2. */
int nodus_tm_state_write(nodus_tm_wal_t *w, const nodus_tm_state_row_t *row);

/** Read the tm_state row. `*have` is 0 when the table holds no row for
 *  this protocol_id. A digest mismatch is -2 (and `*have` is not set).
 *  @return 0 / -1 bad arguments / -2 fault. */
int nodus_tm_state_read(nodus_tm_wal_t *w, int *have,
                        nodus_tm_state_row_t *row);

/* ── Startup classification ──────────────────────────────────────────── */

typedef enum {
    NODUS_TM_STARTUP_NORMAL            = 0,
    NODUS_TM_STARTUP_FAST_FORWARD      = 1,
    NODUS_TM_STARTUP_WRITE_END_THEN_FF = 2,
    NODUS_TM_STARTUP_FAULT             = 3
} nodus_tm_startup_t;

/** Classify a startup from three heights — PURE (DG-16): no clock, no
 *  randomness, no file system, no database. T = tip height in v2_blocks
 *  (0 at genesis), E = last END_HEIGHT (0 if none), S = tm_state.height
 *  (0 if none). T2 §4.6 table, D-15 rev 4 (2), `replay.go:407-449`:
 *
 *    S == E+1, T == E     NORMAL             replay rows above E
 *    S == E,   T == E     FAST_FORWARD       crash between END_HEIGHT and
 *                                            the tm_state write
 *    S == E+1, T == E+1   WRITE_END_THEN_FF  crash between the block
 *                                            INSERT and END_HEIGHT
 *    anything else        FAULT              invariant violated; halt
 *
 *  The host ACTIONS named above are wave 2; this function only names the
 *  case. */
nodus_tm_startup_t nodus_tm_wal_startup_classify(uint64_t tip_T,
                                                 uint64_t last_end_E,
                                                 uint64_t state_S);

#ifdef NODUS_WITNESS_INTERNAL_API
/* ── Test-visible internals (idiom: nodus_witness.h:1330) ─────────────
 * The FULL connection's handle. `PRAGMA synchronous` is PER-CONNECTION
 * state, so D-13's verification obligation — "assert it reads 2 on the
 * FULL connection and 1 on the NORMAL one, do not assume it" — cannot be
 * met without the handle. Nothing in the host path needs this, which is
 * why the declaration is behind the test define. */
sqlite3 *nodus_tm_wal_full_conn(const nodus_tm_wal_t *w);
#endif /* NODUS_WITNESS_INTERNAL_API */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_TM_WAL_H */
