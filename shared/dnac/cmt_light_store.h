/**
 * @file shared/dnac/cmt_light_store.h
 * @brief cometbft @v0.38.26 `light/store` — the `Store` interface
 *        (light/store/store.go:5-48) as a C callback table, and its
 *        database implementation (light/store/db/db.go) over SQLite.
 *
 * ═══ STATUS: NO PRODUCTION CALLER ═══════════════════════════════════════
 * Package 1 of the light client (Kurultay #25 item 1, docs/plans/
 * decisions/2026-10-16-kurultay-25-summary.md). Nothing in a node opens a
 * light store yet. It sits in nodus's COMMON source list next to
 * cmt_light_verifier.c so that it compiles on Windows; SQLite is already
 * used from that list (nodus_witness_v2_schema.c:11).
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── THE MAPPING ────────────────────────────────────────────────────────
 *   dbm.DB + prefix  → one SQLite FILE this module opens and owns, with
 *                      two tables:
 *                        cmt_light_block (prefix BLOB, height INTEGER,
 *                                         value BLOB, PRIMARY KEY
 *                                         (prefix, height))
 *                        cmt_light_size  (prefix BLOB PRIMARY KEY,
 *                                         size INTEGER)
 *                      The reference's key `lb/<prefix>/<%020d height>`
 *                      (db.go:289-291) exists so that a byte-string store
 *                      can be range-iterated in height order; an INTEGER
 *                      height column is the same total order for every
 *                      height > 0, and every query here says ORDER BY
 *                      height.
 *   stored value     → the marshalled `tendermint.types.LightBlock` proto
 *                      (db.go:47-55), via `cmt_light_block_encode`.
 *   load             → `Unmarshal` + `LightBlockFromProto` (db.go:120-
 *                      129), via `cmt_light_block_decode`, bounded by the
 *                      row's length.
 *   WriteSync / Batch→ ONE SQLite transaction (`BEGIN IMMEDIATE` …
 *                      `COMMIT`) with `PRAGMA synchronous=FULL`: a
 *                      COMMIT is durable when it returns, the class
 *                      WriteSync / SetSync promise (db.go:68, :96, :262,
 *                      :273).
 *   panic            → CMT_FAULT (a height <= 0 at db.go:43-45, :81-83,
 *                      :108-110, :189-191; a database failure at :113-
 *                      115, :142-144, :167-169, :197-199; a nil-pointer
 *                      dereference of the light block's height). A
 *                      SQLite failure is CMT_FAULT EVERYWHERE, also where
 *                      the reference returns the database's error instead
 *                      of panicking (Save :62-70, Delete :90-98, Prune
 *                      :237-275) — the convention of
 *                      nodus_witness_cmt_store.h:45, "a SQLite failure";
 *   error return     → CMT_REJECT (an undecodable row, db.go:121-129);
 *   ErrLightBlockNotFound (light/store/errors.go:5-9)
 *                    → CMT_OK with `*found = false`, the convention of
 *                      nodus_witness_cmt_store.h:46.
 *
 * ── DEVIATIONS (Kurultay #25 item 7: "Do not copy the reference store's
 *    accounting. It uses a uint16 counter, increments it on duplicate
 *    saves, and writes the counter separately from the rows (R/light/
 *    store/db/db.go:24, :62, :262). Our store does an atomic, idempotent
 *    save.") ───────────────────────────────────────────────────────────
 *  D1 A 64-BIT COUNT. The reference's `size uint16` (db.go:24) wraps at
 *     65536 pairs; `Prune(size uint16)` / `Size() uint16` (store.go:44,
 *     :47) take and return it. Here the count is uint64 in the API and a
 *     SQLite INTEGER in the file.
 *  D2 AN IDEMPOTENT SAVE. The reference writes `size+1` on EVERY save
 *     (db.go:65), so re-saving a height it already holds counts it twice.
 *     Here a save of an existing height REPLACES its bytes (the
 *     reference's `Set` overwrites too, db.go:62) and leaves the count
 *     alone; only a new height adds one.
 *  D3 ROWS AND COUNT IN ONE TRANSACTION, everywhere. Save and Delete
 *     already batch the two in the reference (db.go:60-70, :88-98), but
 *     Prune deletes the rows in one batch (:242-265) and writes the count
 *     with a SEPARATE SetSync afterwards (:267-275) — a crash between the
 *     two leaves a count that no longer matches the rows. Here Prune's
 *     deletes and its count update are one transaction.
 *  D4 THE COUNT FOLLOWS THE ROWS, NOT THE CALLS. The reference's Delete
 *     writes `size-1` whether or not the height existed (db.go:93), and
 *     its Prune counts loop iterations, not deleted rows (:246-257).
 *     Here every count change is the number of rows the statement
 *     actually inserted or deleted (`sqlite3_changes`).
 *  D5 A COUNT PER PREFIX. The reference keys its size as the bare
 *     `size` (db.go:17), SHARED by every prefix in one DB — two light
 *     clients on one DB corrupt each other's count, which contradicts
 *     New's own "one DB with many light clients" (:27-28). Here the
 *     count is keyed by the prefix.
 *  D6 THE COUNT IS CHECKED AT OPEN. The reference trusts the stored size
 *     (db.go:30-34). Here open refuses (CMT_REJECT) a file whose stored
 *     count differs from the rows it holds for that prefix — the D1-D5
 *     invariant, which only an outside writer can break.
 *  D7 A ROW MUST BE THE HEIGHT IT IS STORED UNDER. The reference returns
 *     whatever block the bytes decode to (db.go:126-131). Here a row
 *     whose decoded light block has no header, or whose header height
 *     differs from the row's key, is CMT_REJECT.
 *  D8 `block_protocol` is an OPEN parameter: decoding a row reaches
 *     `HeaderFromProto` → `Header.ValidateBasic`, which compares
 *     Version.Block with `version.BlockProtocol` — a build-time constant
 *     of the reference binary and a chain parameter here
 *     (cmt_light_verifier.h:47-53).
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `mtx` (db.go:23, every "Safe for concurrent use" method) — the
 *     store has ONE owner on one event loop, as nodus_witness_cmt_store.h
 *     :58 does for store.go's mtx. NOT thread-safe.
 *   · `parseKey` / `parseLbKey` / `keyPattern` (db.go:293-317) and
 *     `marshalSize` / `unmarshalSize` (:319-327) — the key and the count
 *     are SQLite columns, not byte strings (see THE MAPPING).
 *   · `dbm.NewMemDB` — tests use a temporary file (they need restart).
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock, no randomness, no unordered iteration: First / Last /
 * Before / Prune each select by `ORDER BY height` with a LIMIT. What one
 * node stores is node-local and is never part of any consensus value.
 *
 * Reference @v0.38.26:
 *   light/store/store.go    48 lines
 *   light/store/errors.go    9 lines
 *   light/store/db/db.go   327 lines
 * Governing records: Kurultay #25 (item 7 above); pin decision
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_LIGHT_STORE_H
#define SHARED_DNAC_CMT_LIGHT_STORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"          /* CMT_OK / CMT_REJECT / CMT_FAULT       */
#include "cmt_light_block.h"     /* cmt_light_block_t, _buf_t             */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ light/store/store.go:5-48 — Store ════════════════════════════════ */

/**
 * "Store is anything that can persistently store headers."
 * (store.go:5-6) — a callback table over an opaque `ctx`, the shape of
 * `cmt_mem_app_t` (cmt_mem.h:354-373). EVERY ROW IS REQUIRED.
 * `cmt_light_store_db_bind` fills one for the SQLite store below.
 */
typedef struct {
    void *ctx;

    /** store.go:7-11 — `SaveLightBlock(lb)`; "height must be > 0". */
    int (*save_light_block)(void *ctx, const cmt_light_block_t *lb);

    /** store.go:13-17 — `DeleteLightBlock(height)`; "height must be > 0". */
    int (*delete_light_block)(void *ctx, int64_t height);

    /** store.go:19-25 — `LightBlock(height)`; "height must be > 0". Not
     *  found (ErrLightBlockNotFound) is CMT_OK with `*found = false`. */
    int (*light_block)(void *ctx, int64_t height,
                       cmt_light_block_buf_t *out, bool *found);

    /** store.go:27-30 — `LastLightBlockHeight()`; "If the store is empty,
     *  -1 and nil error are returned." */
    int (*last_light_block_height)(void *ctx, int64_t *out);

    /** store.go:32-35 — `FirstLightBlockHeight()`; empty → -1. */
    int (*first_light_block_height)(void *ctx, int64_t *out);

    /** store.go:37-40 — `LightBlockBefore(height)`; "height must be > 0".
     *  Not found is CMT_OK with `*found = false`. */
    int (*light_block_before)(void *ctx, int64_t height,
                              cmt_light_block_buf_t *out, bool *found);

    /** store.go:42-44 — `Prune(size)` — 64-bit, D1. */
    int (*prune)(void *ctx, uint64_t size);

    /** store.go:46-47 — `Size()` — 64-bit, D1. */
    int (*size)(void *ctx, uint64_t *out);
} cmt_light_store_t;

/* ══ light/store/db/db.go — the SQLite store ══════════════════════════ */

/** The longest prefix this store accepts, in bytes. The reference's is
 *  an unbounded Go string; a bound keeps every row's key finite. */
#define CMT_LIGHT_STORE_PREFIX_MAX 64u

typedef struct cmt_light_store_db cmt_light_store_db_t;

/**
 * cometbft@v0.38.26 light/store/db/db.go:27-37 — `New(db, prefix)`.
 * Opens (creating if absent) the SQLite file at `path`, creates the two
 * tables if absent, and loads the count for `prefix` (:30-34) — checking
 * it against the rows (D6). A fresh prefix starts at 0.
 *
 * @param prefix may be NULL with `prefix_len` 0 (the empty prefix).
 * @param block_protocol D8.
 * @param out receives the store; close it with cmt_light_store_db_close.
 * @return CMT_OK; CMT_REJECT for a prefix above
 *         CMT_LIGHT_STORE_PREFIX_MAX or a count that does not match the
 *         rows (D6); CMT_FAULT on NULL, an allocation failure or any
 *         SQLite failure.
 */
int cmt_light_store_db_open(const char *path,
                            const uint8_t *prefix, size_t prefix_len,
                            uint64_t block_protocol,
                            cmt_light_store_db_t **out);

/** Close the connection and free the store. NULL is a no-op. */
void cmt_light_store_db_close(cmt_light_store_db_t *s);

/** Fill `out` with this store's rows; `out->ctx` is `s`. */
void cmt_light_store_db_bind(cmt_light_store_db_t *s,
                             cmt_light_store_t *out);

/**
 * db.go:39-74 — `SaveLightBlock`. `lb.Height <= 0` panics (:43-45) →
 * CMT_FAULT, as does a light block without a signed header or header
 * (Go dereferences them to read the height). ToProto / Marshal failures
 * (:47-55) are CMT_REJECT. The row and the count are one transaction;
 * an existing height is REPLACED and does not change the count (D2).
 */
int cmt_light_store_db_save_light_block(cmt_light_store_db_t *s,
                                        const cmt_light_block_t *lb);

/** db.go:76-102 — `DeleteLightBlock`. `height <= 0` → CMT_FAULT
 *  (:81-83). Deleting an absent height is CMT_OK and leaves the count
 *  alone (D4). */
int cmt_light_store_db_delete_light_block(cmt_light_store_db_t *s,
                                          int64_t height);

/** db.go:104-132 — `LightBlock`. `height <= 0` → CMT_FAULT (:108-110).
 *  Not found → CMT_OK, `*found = false` (:116-118). An undecodable row
 *  (:121-129) or one that is not the height it is stored under (D7) →
 *  CMT_REJECT. On anything but (CMT_OK, found) `out->lb` is empty. */
int cmt_light_store_db_light_block(cmt_light_store_db_t *s, int64_t height,
                                   cmt_light_block_buf_t *out, bool *found);

/** db.go:134-157 — `LastLightBlockHeight`; empty → -1 (:156). */
int cmt_light_store_db_last_light_block_height(cmt_light_store_db_t *s,
                                               int64_t *out);

/** db.go:159-182 — `FirstLightBlockHeight`; empty → -1 (:181). */
int cmt_light_store_db_first_light_block_height(cmt_light_store_db_t *s,
                                                int64_t *out);

/** db.go:184-215 — `LightBlockBefore`: the stored block with the
 *  GREATEST height strictly below `height` (the reverse iterator's end is
 *  exclusive, :193-196). `height <= 0` → CMT_FAULT (:189-191). None →
 *  CMT_OK, `*found = false` (:214). The block is then loaded as
 *  `cmt_light_store_db_light_block` loads it (:206). */
int cmt_light_store_db_light_block_before(cmt_light_store_db_t *s,
                                          int64_t height,
                                          cmt_light_block_buf_t *out,
                                          bool *found);

/** db.go:217-278 — `Prune(size)`: removes the OLDEST pairs (the
 *  ascending iterator, :233-257) until `size` remain. Nothing to do when
 *  the count is already <= size (:227-229). The deletes and the count
 *  update are ONE transaction (D3). */
int cmt_light_store_db_prune(cmt_light_store_db_t *s, uint64_t size);

/** db.go:280-287 — `Size()`: the count, from memory. The in-memory value
 *  changes only after a COMMIT succeeds, so it always equals the file's.
 *  @return CMT_OK; CMT_FAULT on NULL. */
int cmt_light_store_db_size(cmt_light_store_db_t *s, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_LIGHT_STORE_H */
