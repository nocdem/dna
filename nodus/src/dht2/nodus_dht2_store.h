/**
 * Nodus — DHT v2: the holder store and admission (package 5).
 *
 * Design docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN): §3.1 "Stored
 * form", §3.3 classes + inbox control semantics, §4.1 admission order, §4.2
 * order of versions, §4.5 (i) insertion counter / (v) hand-over, §5 lifetime
 * and deletion, §6 quotas, §9 D3 / D4 / D6; §13 rows 5, 6, 7, 8, 12, 15, 16,
 * 18. Operator decision 2026-10-23-dht-v2-k23-three-items.md (HANDLED cutoff
 * as rows 7 / 15 write it).
 *
 * WHAT IT IS: a SQLite store of CANONICAL envelopes keyed by address, and
 * the one admission path (`put`) every ingress uses — client write,
 * pull-sync delivery, read-repair. `put` runs §4.1 in its order and answers
 * with the row-7 code of the FIRST failing check:
 *
 *   no snapshot, witness in block sync (cu false),
 *   no sets for the snapshot's `e`                 15  (call level; the
 *                       same gate refuses get / list / sweep / scan)
 *   snapshot of another chain than the store's     16  (G8, recorded at
 *                       create; open refuses a store of another chain)
 *   size, envelope, strict data, `_chain`, address  1 2 3 4
 *   holder check  eligible(placement key)            5
 *   class rules (incl. ValidityType <=> Validity and
 *   the inbox-control signer)                        6
 *   writer's name status (a fault)                  16
 *   expiry lower / upper bound (class max by name)  7 8
 *   signature                                        9
 *   inbox control: DENIED 12 (while listed), HANDLED [18, through] — from the
 *   SELECTED, live control record only
 *   Select (§4.2): equal -> acknowledged, loser -> winner's hash, cost 0;
 *   a held row whose expiry has passed counts as ABSENT (kad-dht
 *   existingForSelect, boxo expired = invalid) and is replaced
 *   stored-state change, then ONE transaction: a winning control record
 *   first drops the entries it marks (its freed bytes are credited), then
 *   inbox pool 11, per-identity quota 10, node pool 13, store, re-index.
 *   A tombstone is charged to the pool of the record it replaces.
 *
 * DEFERRED (not here, on purpose): the per-put SUM cost and the per-inbox
 * tombstone row bound (measure first). A refusal that leaves an older
 * version behind is handled by the puller's cursor rule (row 12:
 * nodus_dht2_pull.c, package 7).
 *
 * CONTROL RECORDS follow rev 5 literally: only the control record that WINS
 * Select is stored and applied (HANDLED and DENIED drops, credited before
 * the quota checks in the same transaction); a losing or quota-refused one
 * changes nothing (row 16); admission of an inbox entry looks only at the
 * selected, live control record. There is no holder memory of dropped
 * entries. Keeping a HANDLED request from coming back is a CLIENT rule
 * (docs/plans/decisions/2026-10-24-dht-v2-handled-client-rule.md): the
 * owner keeps a HANDLED writer listed, with its cutoff, until that writer's
 * dropped entries have expired (≤ 7 d + 3 h), so the newest control record
 * always carries the mark and arrival order does not change the result.
 * A holder that receives a newer record without the writer BEFORE the older
 * one keeps the entry; the client rule prevents that case in practice.
 *
 * Nothing here reads a clock: chain time is the injected snapshot's `t`.
 * Nothing here is unordered: every query that decides what is stored or
 * returned has an ORDER BY on a total key. A SQLite error is a FAULT
 * (row 7 code 16, `NODUS_DHT2_STORE_FAULT` for the non-put calls) — never
 * absence, never "no change" (nodus/CLAUDE.md: a DB failure is never a
 * value).
 *
 * THE NAME FAULT RULE (package plan, package 4 ledger note): an unread name
 * fault in nodus_dht2_wview blocks further name requests until it has been
 * reported. `put` asks the name callback exactly once, on every admission
 * that gets past the class rules, and turns a FAULT answer into code 16 —
 * so the fault is always consumed by the call that met it.
 *
 * NO CALLER YET: nothing in nodus/tools/ or any running loop calls it
 * (package 6 is the serving layer; the pull exchange is
 * nodus_dht2_pull.{c,h}). The exchange is NOT here: only its data
 * (insertion index scan, store generation, hand-over flag and its reads,
 * the pull cursor per source).
 *
 * @file nodus_dht2_store.h
 */

#ifndef NODUS_DHT2_STORE_H
#define NODUS_DHT2_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dht2/dht2_msg.h"
#include "dht2/dht2_types.h"
#include "witness/nodus_witness_ipc.h"   /* nodus_witness_dht_snap_t */

struct sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

/** Row 8: 100 writers per inbox, 80 with a chain name, 20 without. */
#define NODUS_DHT2_POOL_NAMED     80u
#define NODUS_DHT2_POOL_UNNAMED   20u

/** §6: per identity per holder, bytes of the whole canonical envelope. */
#define NODUS_DHT2_QUOTA_UNNAMED  (4ull  * 1024ull * 1024ull)
#define NODUS_DHT2_QUOTA_NAMED    (64ull * 1024ull * 1024ull)
/** §6: node pools, "10 GB each by default" (read as decimal, 10^10 bytes). */
#define NODUS_DHT2_NODE_POOL_DEFAULT 10000000000ull

/** Row 11: a LIST page carries ≤ 2 MiB of envelopes. */
#define NODUS_DHT2_LIST_PAGE_BYTES (2u * 1024u * 1024u)

/** get / list / scan / sweep / open results that are not a row-7 code. */
#define NODUS_DHT2_GET_HELD        0
#define NODUS_DHT2_GET_NOT_HELD    1
#define NODUS_DHT2_STORE_FAULT     DHT2_E_HOLDER_FAULT   /* 16 */

/** §6 limits. Set per call, so an operator setting can change at run time. */
typedef struct {
    uint64_t ident_unnamed;    /* bytes per identity, writer without a name */
    uint64_t ident_named;      /* bytes per identity, writer with a name    */
    uint64_t pool_unnamed;     /* node pool, records of unnamed writers     */
    uint64_t pool_named;       /* node pool, records of named writers       */
} nodus_dht2_limits_t;

/** The §6 defaults. */
void nodus_dht2_limits_default(nodus_dht2_limits_t *out);

/** The name status of a writer, as the admission needs it. */
typedef enum {
    NODUS_DHT2_NAME_UNNAMED = 0,
    NODUS_DHT2_NAME_NAMED,
    NODUS_DHT2_NAME_FAULT        /* the witness answered {err}: code 16 */
} nodus_dht2_name_t;

typedef nodus_dht2_name_t (*nodus_dht2_name_fn)(void *user,
                                                const uint8_t fp[DHT2_FP_LEN]);

/**
 * What the admission needs of the world, injected (a test builds one; the
 * serving layer fills it from nodus_dht2_wview_snap / _sets / _name).
 * Pointers are borrowed for the call.
 */
typedef struct {
    const nodus_witness_dht_snap_t *snap;     /* NULL = no fresh snapshot  */
    /* S(H) and S(H − E): the frozen sets for the snapshot's `e`. Both NULL
     * with counts 0 is a valid (empty) set; `have_sets` false = the sets
     * for this `e` are not available (wview_sets returned NULL). */
    bool                            have_sets;
    const uint8_t                 (*s0)[DHT2_FP_LEN];
    size_t                          n0;
    const uint8_t                 (*s1)[DHT2_FP_LEN];
    size_t                          n1;
    uint8_t                         self_fp[DHT2_FP_LEN];
    nodus_dht2_name_fn              name;     /* required by put           */
    void                           *name_user;
    nodus_dht2_limits_t             limits;
} nodus_dht2_ctx_t;

typedef struct nodus_dht2_store nodus_dht2_store_t;

/** Open (creating when absent) the store at `path` for `chain`. The first
 *  creation records the chain id, draws and persists the 64-bit generation
 *  g (row 12) and sets the insertion counter to 0 (the first index handed
 *  out is 1). NULL on any failure — including a store of another chain,
 *  incomplete meta, records without a counter, or a counter below the
 *  highest insertion index (never reset, never opened). */
nodus_dht2_store_t *nodus_dht2_store_open(const char *path,
                                          const uint8_t chain[DHT2_CHAIN_LEN]);
void                nodus_dht2_store_close(nodus_dht2_store_t *s);

/** The store generation g (equality compared only). */
uint64_t nodus_dht2_store_generation(const nodus_dht2_store_t *s);

/** The insertion counter's top (0 = nothing was ever stored). 0 / 16. */
int nodus_dht2_store_top(nodus_dht2_store_t *s, uint64_t *top);

/** The SQLite handle, for a test that forces a database fault
 *  (`PRAGMA query_only`); production code has no use for it. */
struct sqlite3 *nodus_dht2_store_db(nodus_dht2_store_t *s);

/* ── put ─────────────────────────────────────────────────────────────── */

typedef enum {
    NODUS_DHT2_PUT_STORED = 1,   /* the incoming version was stored         */
    NODUS_DHT2_PUT_EQUAL,        /* equal to the held version: acknowledged */
    NODUS_DHT2_PUT_LOST          /* the held version wins: its hash, cost 0 */
} nodus_dht2_put_outcome_t;

typedef struct {
    nodus_dht2_put_outcome_t outcome;           /* valid when the code is 0 */
    uint8_t                  hash[DHT2_HASH_LEN]; /* SHA3-512 of the canonical
                                                 * envelope stored / held   */
    uint64_t                 through;           /* code 18: the HANDLED cutoff */
    bool                     has_address;       /* the envelope parsed as far
                                                 * as its address — set for
                                                 * ANY code after that point
                                                 * (also on failure)        */
    uint8_t                  address[DHT2_HASH_LEN]; /* valid when has_address */
} nodus_dht2_put_t;

/**
 * Admit one envelope (§4.1). `expect_address` (64 B, may be NULL) is the
 * address the caller expects (pull-sync checks it; a client PUT has none).
 * @return 0 (outcome + hash in `res`), a row-7 code 1..13 / 16 / 18,
 *         or 15 (no snapshot / sets). 18 carries the cutoff in
 *         res->through. Any SQLite or allocation error is 16. A NULL
 *         argument is DHT2_E_ARG (-1), as for get / list / sweep / scan.
 */
int nodus_dht2_store_put(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                         const uint8_t *env, size_t len,
                         const uint8_t *expect_address, nodus_dht2_put_t *res);

/* ── get ─────────────────────────────────────────────────────────────── */

/**
 * The canonical envelope held at `address` and its hash. Never serves a
 * record whose expiry ≤ the snapshot's tip time (§5); tombstones are
 * served until their own expiry. `out` needs DHT2_ENVELOPE_MAX bytes.
 * @return NODUS_DHT2_GET_HELD (0), NODUS_DHT2_GET_NOT_HELD (1), 15 (no
 *         snapshot), 16 (fault).
 */
int nodus_dht2_store_get(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                         const uint8_t address[DHT2_HASH_LEN], uint8_t *out,
                         size_t cap, size_t *out_len,
                         uint8_t hash[DHT2_HASH_LEN]);

/* ── list ────────────────────────────────────────────────────────────── */

/**
 * One LIST page of `inbox` (row 11, row 18): live inbox entries in
 * ascending writer fp, strictly after `cursor` (NULL = first page), ≤ 16
 * and ≤ 2 MiB of envelopes, the selected control record's hash beside it.
 * Fills the row-18 fields of `out` except `q` (the request's nonce, left
 * zero): n = this node's fp, c, h, t from the snapshot, r (k = inbox, v =
 * SHA3-512 over the listed hashes concatenated), ctl, list, cursor,
 * complete, req_cursor. The owner-signature check is package 6's.
 * @return 0, 15, 16.
 */
int nodus_dht2_store_list(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                          const uint8_t inbox[DHT2_HASH_LEN],
                          const uint8_t *cursor, dht2_list_answer_t *out);

/* ── sweep ───────────────────────────────────────────────────────────── */

/** §5: delete every record whose expiry + 3 h ≤ the snapshot's tip time
 *  (tombstones included: kept until their own expiry, then the same
 *  slack). Quota is derived from what is stored, so a delete refunds it.
 *  @return 0 (`*deleted` set, may be NULL), 15, 16. */
int nodus_dht2_store_sweep(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                           uint64_t *deleted);

/* ── insertion index scan (§4.5 i, row 12) ───────────────────────────── */

typedef struct {
    uint64_t index;                              /* insertion index         */
    uint8_t  address[DHT2_HASH_LEN];
    uint8_t  hash[DHT2_HASH_LEN];                /* SHA3-512 of canonical   */
    uint8_t  placement[DHT2_HASH_LEN];           /* placement-key hint      */
} nodus_dht2_scan_entry_t;

/**
 * Entries with insertion index ≥ `from`, ascending, at most `max` (≤ 250).
 * `*topmost` = the highest index scanned, or the store's top when none.
 * Expired-but-unswept records are listed (§4.5 v: a holder keeps answering
 * pulls for them until they are deleted).
 * A `from` above INT64_MAX (never an index) is an empty page with the
 * current top.
 * @return 0, 15, 16; DHT2_E_ARG for max 0 or > 250.
 */
int nodus_dht2_store_scan(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx,
                          uint64_t from, nodus_dht2_scan_entry_t *out,
                          size_t max, size_t *count, uint64_t *topmost);

/* ── hand-over obligation (§4.5 v) — data only ───────────────────────── */

/** Mark (`pending` true) or RETIRE (`pending` false) the persisted hand-over
 *  obligation of the record at `address` (package 7 decides when). A retired
 *  record is not offered to the epoch check's flagging again
 *  (nodus_dht2_store_permanent_scan returns rows with no obligation only).
 *  *`found` false when no such record. Replacement of the record keeps a
 *  pending flag. Either way (set or retire) the
 *  acknowledgements recorded for the address below are deleted. @return
 *  0 / 16. */
int nodus_dht2_store_handover_set(nodus_dht2_store_t *s,
                                  const uint8_t address[DHT2_HASH_LEN],
                                  bool pending, bool *found);

/** Decision 2026-10-27-dht-v2-handover-one-receipt.md: the fps that sent a
 *  valid pull-receipt for the pending record at `address`, persisted one row
 *  per (address, fp) — adding a fp twice keeps one. The rows are deleted when
 *  the record row is deleted or REPLACED (the receipts named its old hash),
 *  and by every handover_set. Whether a fp counts (member of the current
 *  nearest_R) is the caller's to decide. @return 0 / 16. */
int nodus_dht2_store_handover_ack_add(nodus_dht2_store_t *s,
                                      const uint8_t address[DHT2_HASH_LEN],
                                      const uint8_t fp[DHT2_FP_LEN]);
int nodus_dht2_store_handover_ack_has(nodus_dht2_store_t *s,
                                      const uint8_t address[DHT2_HASH_LEN],
                                      const uint8_t fp[DHT2_FP_LEN], bool *has);
int nodus_dht2_store_handover_get(nodus_dht2_store_t *s,
                                  const uint8_t address[DHT2_HASH_LEN],
                                  bool *pending, bool *found);

/** The row of `address` as the hand-over needs it: whether it is held,
 *  its flag, the hash of the canonical envelope and its placement key.
 *  An expired-but-unswept row is read like any other. @return 0 / 16. */
int nodus_dht2_store_handover_info(nodus_dht2_store_t *s,
                                   const uint8_t address[DHT2_HASH_LEN],
                                   bool *found, bool *pending,
                                   uint8_t hash[DHT2_HASH_LEN],
                                   uint8_t placement[DHT2_HASH_LEN]);

typedef struct {
    uint64_t index;                              /* insertion index         */
    uint8_t  address[DHT2_HASH_LEN];
    uint8_t  placement[DHT2_HASH_LEN];
} nodus_dht2_perm_entry_t;

/**
 * §4.5 (v): the PERMANENT records (stored with no expiry, ValidityType 1,
 * tombstones included, §5) that carry no hand-over flag yet, insertion
 * index ≥ `from`, ascending, at most `max` (≤ 250). `*next` = the index to
 * continue from (last index + 1; `from` when the page is empty). A page
 * shorter than `max` is the end. @return 0, 16; DHT2_E_ARG.
 */
int nodus_dht2_store_permanent_scan(nodus_dht2_store_t *s, uint64_t from,
                                    nodus_dht2_perm_entry_t *out, size_t max,
                                    size_t *count, uint64_t *next);

/* ── pull cursors (§4.5 iii, row 12) — data only ─────────────────────── */

/** The persisted state of the pull from source `fp`: the source's store
 *  generation g last seen and the cursor (the next insertion index to ask
 *  for = top + 1). `*found` false when the source was never pulled from.
 *  @return 0 / 16. */
int nodus_dht2_store_pull_get(nodus_dht2_store_t *s,
                              const uint8_t fp[DHT2_FP_LEN], bool *found,
                              uint64_t *gen, uint64_t *cursor);
/** Persist (insert or replace) it. `cursor` ≤ INT64_MAX. @return 0 / 16. */
int nodus_dht2_store_pull_set(nodus_dht2_store_t *s,
                              const uint8_t fp[DHT2_FP_LEN], uint64_t gen,
                              uint64_t cursor);
/** Every source's cursor := 0 (a re-scan from 0 at the next exchange). */
int nodus_dht2_store_pull_reset(nodus_dht2_store_t *s);
/** The epoch the pull cursors were last checked against (meta "pull_e");
 *  *found false before the first check. @return 0 / 16. */
int nodus_dht2_store_pull_epoch_get(nodus_dht2_store_t *s, bool *found,
                                    uint64_t *e);
/** Persist it (e ≤ INT64_MAX). @return 0 / 16. */
int nodus_dht2_store_pull_epoch_set(nodus_dht2_store_t *s, uint64_t e);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT2_STORE_H */
