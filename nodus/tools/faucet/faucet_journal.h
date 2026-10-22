/**
 * @file faucet_journal.h
 * @brief The faucet's durable journal (SQLite, WAL, synchronous=FULL).
 *
 * Governing records: docs/plans/2026-10-22-testnet-faucet-design.md section
 * 6.4-6.7 and the operator's "Yeni istekleri durdur" (at the storage limit
 * new claims stop; paid markers are never deleted).
 *
 * WHAT IS KEPT
 *   claims        one row per claim: kind full|start, address, name, state
 *   paid          the permanent paid markers: "full:<name>" / "start:<addr>"
 *                 (written in the SAME transaction as the claim, never
 *                 deleted — the single source of "already paid", G1)
 *   attempts      one row per signed envelope of a claim: the stored bytes,
 *                 wire id, intent id, input nullifiers, build tip, expiry,
 *                 scan cursor, last submit tip
 *   reservations  the nullifiers an open claim holds (survive restart)
 *
 * STATES  planned -> signed -> submitted -> confirmed | expired | unknown
 *         (paused = nothing signed, waiting; expired -> signed on a
 *         replacement attempt). Every transition is checked against the
 *         legal table here and runs inside one BEGIN IMMEDIATE transaction;
 *         an illegal request is refused and changes nothing.
 *
 * A DB failure is never a value: every function returns -1 on a database
 * fault and the caller must not treat the fact as "none" or "zero". That
 * covers the READ side too: a column of the wrong type, a NULL text, a text
 * that does not fit its field or a blob of the wrong length fails the whole
 * read (-1); every bind is checked.
 *
 * STORAGE CEILING (db + wal bytes, "Yeni istekleri durdur"): the ceiling is
 * a hard DISK ceiling. The bytes counted are the LIVE pages of the database
 * (page_count minus the free list — SQLite reuses freed pages but never
 * shrinks the file) plus the -wal file. The -wal file is bounded: the
 * journal sets wal_autocheckpoint to FJ_WAL_CKPT_PAGES pages and
 * journal_size_limit to the same number of bytes, so it is truncated back
 * after a checkpoint. A NEW claim is admitted only while
 *     live + wal + margin + reserve  <  ceiling
 * where margin = FJ_WAL_CKPT_PAGES * page_size + FJ_TX_BOUND_BYTES (the WAL
 * growth the next commit and the checkpoint lag can add) and reserve =
 * FJ_CLAIM_RESERVE_BYTES for every open claim and for the new one — AND
 * the on-disk size (page_count * page_size + wal) PLUS THE SAME WAL MARGIN
 * is still below the ceiling (disk + margin < ceiling). journal_size_limit
 * bounds the -wal file retained after a checkpoint reset, it is not a
 * write-time quota. A ceiling that cannot hold margin + two reserves is
 * refused at open. A REPLACEMENT attempt (the second or
 * later of a claim) first frees the claim's earlier, expired envelope
 * payloads — wire id, intent id, inputs, expiry and scan cursor stay as
 * evidence, the paid markers are never touched — and is refused (-4,
 * nothing recorded) when the live bytes are still at the ceiling or the
 * on-disk size plus the WAL margin has reached it. The
 * envelope payloads of a CONFIRMED claim are freed the same way.
 *
 * Thread safety: one connection, one mutex; every call takes the lock.
 *
 * DEADLINES (HTTP path): the HTTP handler runs in the single poll loop, so a
 * journal call on its path must not wait longer than the request. The
 * calling thread may set a deadline (faucet_journal_thread_deadline, an
 * absolute CLOCK_MONOTONIC millisecond time; 0 = none): while it is set the
 * mutex wait and the SQLite busy timeout of every call of that thread are
 * bounded by the time left, and a call that cannot start or finish in time
 * returns FJ_BUSY with NOTHING written (a claim insert is one transaction).
 * The settlement thread sets none and keeps its 5 s busy timeout.
 */
#ifndef FAUCET_JOURNAL_H
#define FAUCET_JOURNAL_H

#include <stdint.h>
#include <stddef.h>

#define FJ_KIND_MAX    8
#define FJ_STATE_MAX   12
#define FJ_MSG_MAX     160
#define FJ_MAX_INPUTS  15
/** Bytes reserved per open claim (and for the claim being admitted) for its
 *  first signed attempt and settlement rows — an ML-DSA-87 spend envelope
 *  is a few KiB; the reserve is generous. */
#define FJ_CLAIM_RESERVE_BYTES  (64u * 1024u)
/** wal_autocheckpoint (pages) and journal_size_limit (pages * page_size). */
#define FJ_WAL_CKPT_PAGES       100u
/** Bound of ONE write transaction's WAL growth (a claim, or a signed
 *  attempt of at most a few KiB plus up to 15 reservation rows). */
#define FJ_TX_BOUND_BYTES       (256u * 1024u)
/** The longest SQLite busy wait of one call. */
#define FJ_BUSY_MS              5000u
#define FJ_NO_DEADLINE          0u

typedef struct faucet_journal faucet_journal_t;

typedef struct {
    int64_t seq;
    char    claim_id[33];            /* 32 lowercase hex                    */
    char    kind[FJ_KIND_MAX];       /* "full" | "start"                    */
    char    address[129];
    char    name[37];                /* full only                           */
    char    state[FJ_STATE_MAX];
    char    message[FJ_MSG_MAX];
} faucet_claim_t;

typedef struct {
    int      n;                      /* attempt number, 1-based             */
    uint8_t *env;                    /* heap; faucet_attempt_free           */
    size_t   env_len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
    uint8_t  inputs[FJ_MAX_INPUTS][64];
    int      n_in;
    uint64_t build_tip;
    uint64_t expiry;
    uint64_t scan_next;              /* next height to scan                 */
    uint64_t last_submit_tip;        /* 0 = never submitted                 */
} faucet_attempt_t;

typedef enum {
    FJ_CREATED      = 0,
    FJ_EXISTS       = 1,   /* a marker or an open claim for the address    */
    FJ_QUEUE_FULL   = 2,
    FJ_STORAGE_FULL = 3,
    FJ_STOPPED      = 4,   /* a claim is in state unknown                  */
    FJ_ERR          = -1,
    FJ_BUSY         = -5   /* the thread's deadline passed before the call
                            * could take the journal; nothing was written.
                            * Also the (negative) return of claim_get,
                            * claim_by_address, storage_full and counts.   */
} faucet_jcreate_rc_t;

typedef struct { int open; int paused; int unknown; } faucet_jcounts_t;

/** Open (and create) the journal. `storage_ceiling` bytes (db + wal).
 *  Refuses a newer schema and a ceiling that cannot hold the WAL margin plus
 *  two claim reserves. @return 0 / -1. */
int  faucet_journal_open(const char *path, uint64_t storage_ceiling,
                         faucet_journal_t **out);
void faucet_journal_close(faucet_journal_t *j);

/** Set (0 = clear) the CALLING THREAD's absolute CLOCK_MONOTONIC deadline in
 *  milliseconds (the faucet_now_ms() clock) for the journal calls it makes
 *  from now on: claim_create, claim_get, claim_by_address, storage_full and
 *  counts then return FJ_BUSY when it passes (see DEADLINES above). */
void faucet_journal_thread_deadline(uint64_t deadline_ms);

/** TEST ONLY — production never calls it. `fn` (NULL = none) runs inside
 *  claim_create right before its pre-commit deadline check, so a test can let
 *  the deadline pass at that point deterministically. */
void faucet_journal_test_precommit_hook(void (*fn)(void));

/** The WAL pragmas in force on the journal's connection: journal_size_limit
 *  (bytes) and wal_autocheckpoint (pages). 0 / -1. */
int faucet_journal_wal_limits(faucet_journal_t *j, int64_t *size_limit,
                              int64_t *autockpt_pages);

/** Create a claim atomically with its paid marker. kind "full" needs a
 *  name (marker "full:<name>"), "start" marker "start:<address>".
 *  Checks, in order: marker exists -> FJ_EXISTS (that claim); an open
 *  claim for the address -> FJ_EXISTS; a claim in state unknown ->
 *  FJ_STOPPED; storage ceiling -> FJ_STORAGE_FULL; open claims >=
 *  queue_cap -> FJ_QUEUE_FULL; else insert -> FJ_CREATED. `out` is the
 *  created or the existing claim. */
int faucet_journal_claim_create(faucet_journal_t *j, const char *kind,
                                const char *address, const char *name,
                                int queue_cap, const uint8_t rand16[16],
                                faucet_claim_t *out);

/** @return 0 found, 1 not found, -1 fault. */
int faucet_journal_claim_get(faucet_journal_t *j, const char *claim_id,
                             faucet_claim_t *out);
/** The latest claim (highest seq) of an address. 0 / 1 / -1. */
int faucet_journal_claim_by_address(faucet_journal_t *j, const char *address,
                                    faucet_claim_t *out);
/** The oldest claim that is not confirmed. 0 found / 1 none / -1. */
int faucet_journal_head(faucet_journal_t *j, faucet_claim_t *out);

/** planned/paused/submitted (the non-signing, non-terminal moves) with a
 *  message. Illegal -> -2, nothing changed. 0 / -2 / -1. */
int faucet_journal_set_state(faucet_journal_t *j, int64_t seq,
                             const char *state, const char *message);

/** confirmed | expired | unknown. confirmed releases the reservations.
 *  Illegal -> -2. 0 / -2 / -1. */
int faucet_journal_finish(faucet_journal_t *j, int64_t seq, const char *state,
                          const char *message);

/** Store a NEW signed attempt (a->env etc. filled by the caller; a->n is
 *  assigned) and flip the claim to signed, replacing the claim's
 *  reservations with a->inputs — all in ONE transaction. Legal only from
 *  planned, paused or expired. A nullifier reserved by ANOTHER claim ->
 *  -3 and nothing changes. A replacement (attempt 2+) that would leave the
 *  live bytes at the storage ceiling, after the claim's obsolete envelope
 *  payloads were freed -> -4 and nothing changes.
 *  0 / -2 illegal / -3 reserved / -4 storage / -1. */
int faucet_journal_attempt_sign(faucet_journal_t *j, int64_t seq,
                                faucet_attempt_t *a);

/** The latest attempt of a claim (env heap). 0 / 1 none / -1. */
int faucet_journal_attempt_latest(faucet_journal_t *j, int64_t seq,
                                  faucet_attempt_t *out);
void faucet_attempt_free(faucet_attempt_t *a);

/** Record a submit CALL on the latest attempt: last_submit_tip = tip and,
 *  from signed, the claim becomes submitted. (The node's answer is not an
 *  input — design section 6.4.) 0 / -2 illegal / -1. */
int faucet_journal_attempt_submitted(faucet_journal_t *j, int64_t seq,
                                     uint64_t tip);

/** Advance the scan cursor of the latest attempt. Never backwards.
 *  0 / -2 (not above the stored cursor) / -1. */
int faucet_journal_attempt_scanned(faucet_journal_t *j, int64_t seq,
                                   uint64_t scan_next);

/** Nullifiers reserved by claims OTHER than `except_seq`. Up to `cap`
 *  (cap is large enough: 15 inputs per open claim, queue-bounded).
 *  @return the number, or -1. */
int faucet_journal_reserved_other(faucet_journal_t *j, int64_t except_seq,
                                  uint8_t (*out)[64], int cap);

int faucet_journal_counts(faucet_journal_t *j, faucet_jcounts_t *out);

/** 1 when a new claim would not fit (live + wal + the WAL margin + the
 *  settlement reserve of every open claim and of the new one have reached
 *  the ceiling, or the on-disk size has), 0 room, FJ_BUSY (deadline), -1
 *  fault (an absent -wal file is not a fault; any other stat() error is). */
int faucet_journal_storage_full(faucet_journal_t *j);

#endif /* FAUCET_JOURNAL_H */
