/**
 * @file shared/dnac/cmt_mem.h
 * @brief cometbft @709fd12b's Flood mempool — `mempool/clist_mempool.go`,
 *        `cache.go`, `ids.go`, `mempoolTx.go`, `tx.go`, `errors.go`,
 *        `mempool.go` and the mempool section of `config/config.go` —
 *        ported to C as ONE synchronous module.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R3-M of the cometbft → C consensus port. Nothing in the running
 * chain constructs a `cmt_mem_t` yet: R3-C1 binds the ledger's admission
 * check as the application, R3-B's BlockExecutor calls Update/Reap, and
 * R3-C2 wires the reactor (cmt_memr.h) to the transport. The old
 * fee-sorted `nodus_witness_mempool.{h,c}` is untouched by this wave and
 * is deleted by R3-D. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS IS (D-4 rev 3, atlas-dec-d5ddcba654eb48d861c03a0ecd170718)
 * A FIFO pool of application-validated transactions. A transaction enters
 * through the application's CheckTx, is kept in arrival order in a linked
 * list, is offered to every peer that did not send it (cmt_memr), is
 * removed when a block that carries it is committed, and is re-checked
 * against the application after every block. That is the whole
 * behaviour; there is NO fee order, NO "chain_config alone" rule and NO
 * per-block transaction cap here — those live in PrepareProposal, which
 * the reference grants the application (D-4 rev 3 item 3; R3-C1).
 *
 * ── THREADS → SYNCHRONOUS CALLS (umbrella rev 4, substitution item 7) ──
 * The reference is written for an ASYNCHRONOUS ABCI client: `CheckTx`
 * (clist_mempool.go:223-278) sends `CheckTxAsync` (:271) and returns; the
 * application's answer arrives later in `globalCb` (:289-318) or
 * `reqResCb` (:329-351), which then run `resCbRecheck` (:480-503) or
 * `resCbFirstTime` (:401-474). Rechecking (:647-689) sends every request
 * (:658-671), flushes (:674) and WAITS for the responses or a timeout
 * (:678-683), tracking the in-flight responses with the `recheck` cursor
 * (:697-801). Its own comment at :662-663 describes the other client:
 * "If we're using a sync client, the resCbRecheck callback will be
 * called right after receiving the response."
 *
 * THIS PORT IS THAT SYNC CLIENT. The application is a callback table
 * (`cmt_mem_app_t`, the `AppConnMempool` of proxy/app_conn.go:29-36)
 * whose `check_tx` RETURNS the response. So:
 *   · `cmt_mem_check_tx` runs :223-278 up to the request, calls the
 *     application, and then runs what `reqResCb` (:334-350) does with the
 *     answer — the "rechecking has not finished" guard (:335-338), then
 *     `resCbFirstTime` (:340), then the external callback (:347-349),
 *     which is the `out_res` parameter here. `globalCb` and `reqResCb`
 *     have no C body of their own: they are the asynchronous plumbing,
 *     and every line of logic they carry is at the site named above.
 *   · `recheckTxs` sends one request per resident transaction, front to
 *     back (:658-671), and processes each answer AT ONCE through
 *     `globalCb`'s recheck branch (:301-311: the "rechecking has
 *     finished; discard late recheck response" guard, then
 *     `resCbRecheck`). The `recheck` cursor struct is ported literally
 *     and driven in the order the reference drives it; its `doneCh`
 *     (:700, :749-752, :785-787) is gone because nothing waits on it.
 *     The `select` of :678-683 collapses: after the loop, nothing
 *     asynchronous can ever complete the recheck, so the timeout branch
 *     (:679-681, `setDone` and the error log) is taken immediately when
 *     the recheck is not already done — which, with every answer
 *     processed in line, it always is. `RecheckTimeout` (config.go:739)
 *     therefore stays a field of the config, set by the default, and is
 *     NEVER READ (D-20 rev 3: the mempool reads no clock).
 *   · `Lock`/`Unlock` (:154-164) keep `setRecheckFull` (:155) and lose
 *     the mutex; `updateMtx.RLock` at :228, :188, :525, :566 is dropped;
 *     the `atomic` fields (:27-31, :701-703) are plain fields.
 *   · `TxsWaitChan` (:211-213) and `TxsAvailable`'s channel (:32, :506)
 *     are replaced: the reactor polls `cmt_mem_txs_front`, and the
 *     TxsAvailable signal is a CALLBACK the host registers with
 *     `cmt_mem_enable_txs_available`, fired exactly where
 *     `notifyTxsAvailable` (:510-521) sends on the channel — once per
 *     height, as the `notifiedTxsAvailable` flag (:31, :514, :593)
 *     makes it. A direct call is equivalent to a capacity-1 channel with
 *     an idempotent consumer, and the consumer IS idempotent:
 *     `cmt_cs_notify_txs_available` sets a bool (cmt_cs.h:673).
 *   · `SetResponseCallback` (:89; app_conn.go:30) → gone with the async
 *     client. `proxyAppConn.Error()` (:253) and `Flush()` (:178, :674)
 *     stay as rows of the application table.
 *
 * ── THE MEMPOOL WAL IS OFF ─────────────────────────────────────────────
 * D-4 rev 3: `WalPath ""` (config.go:793) — the reference's default. This
 * file at @709fd12b carries no WAL branch in `CheckTx` (:223-278 has
 * none; the dispatch's ":277-280 wal nil branch" does not exist in the
 * pinned bytes, and nothing is ported for it). `WalPath`, `RootDir`,
 * `WalDir` and `WalEnabled` (config.go:723, :750, :813-820) are not
 * fields here.
 *
 * ── SUBSTITUTIONS (umbrella rev 4 table) ───────────────────────────────
 *   1. `TxKey` (mempool.go:149; types/tx.go:25) is `sha256.Size` bytes
 *      and `Tx.Key()` is SHA-256 (types/tx.go:33-35) while `Tx.Hash()`
 *      is tmhash (:29-31). Under substitution 1 both become SHA3-512, so
 *      they COINCIDE here: a key is the 64-byte `cmt_tx_hash`
 *      (cmt_block.h:672), which is also the DataHash leaf.
 *   9. `p2p.ID` → the host's peer SLOT index 0..127 (`CMT_MEM_MAX_PEERS`
 *      = NODUS_T3_MAX_WITNESSES, cited below); the uint16 mempool ID
 *      SPACE of ids.go is unchanged.
 *
 * ── SENDER IDS: the one memory-shape choice this wave had to make ──────
 * `mempoolTx.senders` (mempoolTx.go:18) is a set of uint16 sender ids.
 * The ids come from `mempoolIDs.nextPeerID` (ids.go:30-43), whose counter
 * increments on every reservation and is never reset (:41), so under
 * peer churn the ids a resident transaction can accumulate range over
 * the WHOLE uint16 space, not over the 128 slots. The set is therefore a
 * 65 536-bit bitmap — 8 KiB per resident transaction, up to 40 MiB at
 * `Size` = 5 000 — which reproduces the reference exactly and, like Go's
 * `addSender`, CANNOT FAIL. The alternatives (a growable array with an
 * allocation-failure path Go does not have; narrowing the id space
 * against ids.go) are recorded in the wave report as a QUESTION, not
 * chosen here.
 *
 * ── Panics (umbrella rev 4 rule) — ALL node-local, ALL CMT_FAULT ───────
 *   · :273  CheckTx request failed          — the ABCI connection, not a peer
 *   · :336  "rechecking has not finished"   — ordering inside this node
 *   · :512  "notified txs available but mempool is empty!"
 *   · :669  (re-)CheckTx request failed
 *   · :714  "more than one rechecking process at a time"
 *   · ids.go:32 "maximum active IDs"        — reachable only through
 *     re-reserving without reclaiming (see cmt_mem_ids_reserve_for_peer)
 *   · Go's implicit index panic at :603 (`txResults[i]` shorter than
 *     `txs`) — made explicit, the BlockExecutor's contract
 * Go `error` returns (errors.go) → CMT_REJECT with the kind and its
 * fields in `cmt_mem_error_t`, because the reactor switches on the kind
 * (reactor.go:159-167) and the RPC renders it.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * No clock. No randomness. The two hash maps of the reference — `txsMap`
 * (:50) and the cache's `cacheMap` (cache.go:37) — are open-addressing
 * tables here whose ITERATION ORDER IS NEVER OBSERVABLE: `txsMap.Range`
 * (:118-121) only deletes everything, and nothing else iterates either
 * table. The only observable order is the CList's, which is insertion
 * order. Two nodes fed the same calls in the same order hold the same
 * pool.
 *
 * Reference @709fd12b (SHA-256 verified before use; pin record rev 12 →
 * rev 15, atlas-dec-483ec17cbb352ef0ec2267ccd953339c):
 *   mempool/mempool.go        149  1fab7e19…    mempool/clist_mempool.go 801  284ebb49…
 *   mempool/cache.go          120  aac20c69…    mempool/ids.go            71  eff4c115…
 *   mempool/tx.go              17  32f0416a…    mempool/mempoolTx.go      34  9a055237…
 *   mempool/errors.go          89  ecfbfc51…    mempool/doc.go            23  8ac76674…
 *   mempool/nop_mempool.go    107  45e556b0… (read to keep the interface identical)
 *   config/config.go         1283  f0c2f601… (:43-44, :702-850)
 *   types/tx.go               192  186fd682… (:15-35, :186-192)
 *   state/tx_filter.go         26  be0d7434…
 *   proto/tendermint/abci/types.proto 494 b0b78373… (:94-102, :262-277)
 *   proxy/app_conn.go         230  03e9cd0b… (:29-36)
 * Governing records: D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718),
 * umbrella rev 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * PQ POLICY (atlas-dec-652be084b95d02d253834906271e9fb0),
 * D-20 rev 3 (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19),
 * D-25 rev 3 (atlas-dec-f8319da0758745dbe615150ed939c34a),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_MEM_H
#define SHARED_DNAC_CMT_MEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"     /* CMT_OK / CMT_REJECT / CMT_FAULT, CMT_TMHASH_SIZE */
#include "cmt_pb.h"         /* cmt_pb_bytes_t, cmt_pb_exec_tx_result_t          */
#include "cmt_block.h"      /* cmt_tx_hash                                      */
#include "cmt_clist.h"      /* the list                                         */
#include "ledger_ids.h"     /* DNA_MAX_ACTIVE_VALIDATORS                        */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ config/config.go:702-850 — MempoolConfig ═════════════════════════ */

/** config.go:43-44 — `MempoolTypeFlood = "flood"`, `MempoolTypeNop =
 *  "nop"`; the empty string is the backwards-compatible value
 *  `ValidateBasic` also accepts (:827). The Go field is a string; here
 *  an enum whose zero value is that empty string. Only FLOOD is
 *  implemented in this tree (D-4 rev 3); NOP exists so ValidateBasic can
 *  be ported check for check. */
typedef enum {
    CMT_MEMPOOL_TYPE_EMPTY = 0,
    CMT_MEMPOOL_TYPE_FLOOD = 1,
    CMT_MEMPOOL_TYPE_NOP   = 2
} cmt_mempool_type_t;

/**
 * config.go:710-784 — `type MempoolConfig`, field for field, minus the
 * two path fields (`RootDir` :723, `WalPath` :750 — the mempool WAL is
 * off, see the header). Go's `int` is 64 bits on this project's targets;
 * the `int` fields here are C `int`, which holds every default and every
 * value the port sizes with.
 */
typedef struct {
    cmt_mempool_type_t type;                     /* :719 */
    bool    recheck;                             /* :729 */
    int64_t recheck_timeout;                     /* :739 — nanoseconds; NEVER READ (header) */
    bool    broadcast;                           /* :745 */
    int     size;                                /* :752 */
    int64_t max_txs_bytes;                       /* :756 */
    int     cache_size;                          /* :758 */
    bool    keep_invalid_txs_in_cache;           /* :762 */
    int     max_tx_bytes;                        /* :765 */
    int     max_batch_bytes;                     /* :769 — "XXX: Unused" in the reference too */
    int     experimental_max_gossip_connections_to_persistent_peers;      /* :782 */
    int     experimental_max_gossip_connections_to_non_persistent_peers;  /* :783 */
} cmt_mempool_config_t;

/** config.go:786-803 — `DefaultMempoolConfig()`, every value at its
 *  cited line. `max_batch_bytes` is not set there and is 0.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_mempool_config_default(cmt_mempool_config_t *out);

/** config.go:824-850 — `(*MempoolConfig) ValidateBasic()`: the type
 *  must be flood, nop or empty (:825-830); `Size`, `MaxTxsBytes`,
 *  `CacheSize`, `MaxTxBytes` and the two experimental bounds must not be
 *  negative (:831-848). `TestMempoolConfig` (:806-810), `WalDir`
 *  (:813-815) and `WalEnabled` (:818-820) are not ported.
 *  @return CMT_OK, CMT_REJECT (the reference's error), CMT_FAULT on NULL. */
int cmt_mempool_config_validate_basic(const cmt_mempool_config_t *cfg);

/* ══ mempool/mempool.go constants ═════════════════════════════════════ */

/** mempool.go:13 — `MempoolChannel = byte(0x30)`. */
#define CMT_MEM_CHANNEL 0x30u
/** mempool.go:16 — `PeerCatchupSleepIntervalMS = 100`. */
#define CMT_MEM_PEER_CATCHUP_SLEEP_INTERVAL_MS 100
/** mempool.go:20 — `UnknownPeerID uint16 = 0`. */
#define CMT_MEM_UNKNOWN_PEER_ID ((uint16_t)0)
/** mempool.go:22 — `MaxActiveIDs = math.MaxUint16`. */
#define CMT_MEM_MAX_ACTIVE_IDS 65535u
/** The uint16 id space of ids.go — every value a sender id can take. */
#define CMT_MEM_SENDER_ID_SPACE 65536u

/**
 * The number of PEER SLOTS the host may hand this module (substitution
 * item 9): `nodus_witness_peer_t peers[NODUS_T3_MAX_WITNESSES]`
 * (nodus/src/witness/nodus_witness.h:901) with `#define
 * NODUS_T3_MAX_WITNESSES 128` (nodus/include/nodus/nodus_types.h:156).
 * Those files are CITED, not included — shared/dnac must not depend on
 * nodus/ — so the constant this header can see is
 * DNA_MAX_ACTIVE_VALIDATORS (ledger_ids.h:103), the same 128, tied to the
 * literal by the assertion exactly as cmt_vote_set.h:186-190 does for
 * CMT_PEER_MAX.
 */
#define CMT_MEM_MAX_PEERS DNA_MAX_ACTIVE_VALIDATORS

_Static_assert((int)CMT_MEM_MAX_PEERS == 128,
               "CMT_MEM_MAX_PEERS must equal NODUS_T3_MAX_WITNESSES "
               "(nodus/include/nodus/nodus_types.h:156); change both");

/* ══ types/tx.go — TxKey and ComputeProtoSizeForTxs ═══════════════════ */

/** mempool.go:149 / types/tx.go:16,25 — `TxKey [TxKeySize]byte`. 64 here
 *  (substitution 1; header). */
#define CMT_MEM_TX_KEY_SIZE CMT_TMHASH_SIZE

/** types/tx.go:33-35 — `(tx Tx) Key()`. SHA3-512 of the bytes, which is
 *  `cmt_tx_hash` (the reference's `Hash()` at :29-31 and `Key()` are two
 *  different functions over SHA-256; under substitution 1 they are one).
 *  @return CMT_OK, CMT_FAULT on NULL / hash backend failure. */
int cmt_mem_tx_key(const uint8_t *tx, size_t tx_len,
                   uint8_t out[CMT_MEM_TX_KEY_SIZE]);

/** types/tx.go:186-192 — `ComputeProtoSizeForTxs(txs)`: the proto size
 *  of `Data{Txs: txs}`, i.e. Σ (1 + uvarint_size(len) + len). Pinned by
 *  the test against the LENGTH `cmt_pb_data_marshal` produces for the
 *  same input, which is the definition. Reads only lengths. */
int64_t cmt_mem_compute_proto_size_for_txs(const cmt_pb_bytes_t *txs,
                                           size_t n);

/* ══ abci — RequestCheckTx / ResponseCheckTx ══════════════════════════ */

/** proto/tendermint/abci/types.proto:94-97 — `enum CheckTxType`. */
typedef enum {
    CMT_MEM_CHECK_TX_TYPE_NEW     = 0,
    CMT_MEM_CHECK_TX_TYPE_RECHECK = 1
} cmt_mem_check_tx_type_t;

/** abci/types.proto:99-102 — `RequestCheckTx {bytes tx = 1; CheckTxType
 *  type = 2}`. A view of the caller's bytes. */
typedef struct {
    const uint8_t          *tx;
    size_t                  tx_len;
    cmt_mem_check_tx_type_t type;
} cmt_mem_request_check_tx_t;

/** abci/types/types.go:11 — `CodeTypeOK uint32 = 0`. */
#define CMT_MEM_CODE_TYPE_OK ((uint32_t)0)

/**
 * abci/types.proto:262-277 — `ResponseCheckTx`, RESTRICTED to the fields
 * the mempool reads — `code` (:263, at clist_mempool.go:412, :492) and
 * `gas_wanted` (:267, at :441 and mempool.go:135-139) — plus `gas_used`
 * (:268). `data`, `log`, `info`, `events` and `codespace` (:264-266,
 * :269-271) are not carried: no consumer in this wave reads them, and
 * the RPC that would render them to a client is a later wave's
 * (reported as a QUESTION, not decided here).
 */
typedef struct {
    uint32_t code;         /* :263 */
    int64_t  gas_wanted;   /* :267 */
    int64_t  gas_used;     /* :268 */
} cmt_mem_response_check_tx_t;

/* ══ proxy/app_conn.go:29-36 — AppConnMempool, as a callback table ════ */

/**
 * The application connection. EVERY ROW IS REQUIRED; a NULL row reached
 * at run time is CMT_FAULT. `SetResponseCallback` (:30) has no row: the
 * client is synchronous (header).
 *
 * ⚠ A callback MUST NOT re-enter the mempool. The reference's
 * application runs on its own connection and cannot; a `check_tx` that
 * called `cmt_mem_check_tx` from inside a recheck would meet the
 * "rechecking has not finished" FAULT (:336), which is the right answer
 * for that mistake.
 */
typedef struct {
    void *ctx;

    /** app_conn.go:31 — `Error()`. CMT_OK is the reference's nil; any
     *  other value is the error that becomes `ErrAppConnMempool`
     *  (clist_mempool.go:253-255). */
    int (*error)(void *ctx);

    /** app_conn.go:33-34 — `CheckTx` / `CheckTxAsync`, synchronous: the
     *  answer is written to `res` before returning. CMT_OK means the
     *  REQUEST was delivered (whatever `res->code` says); any other
     *  value is the request failure the reference panics on (:273,
     *  :669) → CMT_FAULT in the caller. `res` arrives zeroed. */
    int (*check_tx)(void *ctx, const cmt_mem_request_check_tx_t *req,
                    cmt_mem_response_check_tx_t *res);

    /** app_conn.go:35 — `Flush()`. CMT_OK is nil. Its error is
     *  `ErrFlushAppConn` from `FlushAppConn` (:177-184) and IGNORED by
     *  `recheckTxs` (:674 discards it), exactly as the reference does. */
    int (*flush)(void *ctx);
} cmt_mem_app_t;

/* ══ mempool/mempool.go:104-146 — PreCheckFunc / PostCheckFunc ════════ */

/** mempool.go:107 — `PreCheckFunc func(types.Tx) error`. CMT_OK is nil;
 *  any other value is the error, wrapped as `ErrPreCheck` (errors.go:50). */
typedef int (*cmt_mem_pre_check_fn)(void *ctx, const uint8_t *tx,
                                    size_t tx_len);

/** mempool.go:112 — `PostCheckFunc func(types.Tx, *ResponseCheckTx)
 *  error`. CMT_OK is nil. */
typedef int (*cmt_mem_post_check_fn)(void *ctx, const uint8_t *tx,
                                     size_t tx_len,
                                     const cmt_mem_response_check_tx_t *res);

/** A Go closure is a function plus its captured state; here the pair.
 *  `fn == NULL` is the reference's nil filter (clist_mempool.go:246,
 *  :409). */
typedef struct {
    cmt_mem_pre_check_fn fn;
    void                *ctx;
} cmt_mem_pre_check_t;

typedef struct {
    cmt_mem_post_check_fn fn;
    void                 *ctx;
} cmt_mem_post_check_t;

/** The captured `maxBytes` of `PreCheckMaxBytes` (mempool.go:116). */
typedef struct {
    int64_t max_bytes;
} cmt_mem_pre_check_max_bytes_t;

/** mempool.go:117-124 — the closure body of `PreCheckMaxBytes`: the tx's
 *  `ComputeProtoSizeForTxs` (:118) must not exceed `max_bytes` (:120).
 *  `ctx` is a `cmt_mem_pre_check_max_bytes_t *`. */
int cmt_mem_pre_check_max_bytes_fn(void *ctx, const uint8_t *tx,
                                   size_t tx_len);

/** mempool.go:116-126 — `PreCheckMaxBytes(maxBytes)`: binds `storage`
 *  (which must outlive `out`) and fills the pair. This is what
 *  state/tx_filter.go:10-20 `TxPreCheck` builds from
 *  `MaxDataBytesNoEvidence` (cmt_block.h) — that binding is R3-B's.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_mem_pre_check_max_bytes(int64_t max_bytes,
                                cmt_mem_pre_check_max_bytes_t *storage,
                                cmt_mem_pre_check_t *out);

/** The captured `maxGas` of `PostCheckMaxGas` (mempool.go:130). */
typedef struct {
    int64_t max_gas;
} cmt_mem_post_check_max_gas_t;

/** mempool.go:131-145 — the closure body of `PostCheckMaxGas`: nil when
 *  `max_gas == -1` (:132-134); an error for a negative `gas_wanted`
 *  (:135-138) or one above `max_gas` (:139-142). */
int cmt_mem_post_check_max_gas_fn(void *ctx, const uint8_t *tx,
                                  size_t tx_len,
                                  const cmt_mem_response_check_tx_t *res);

/** mempool.go:130-146 — `PostCheckMaxGas(maxGas)`; the counterpart of
 *  state/tx_filter.go:24-26 `TxPostCheck`.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_mem_post_check_max_gas(int64_t max_gas,
                               cmt_mem_post_check_max_gas_t *storage,
                               cmt_mem_post_check_t *out);

/* ══ mempool/errors.go ════════════════════════════════════════════════ */

/** errors.go — the error KINDS, one per `var`/`type`. */
typedef enum {
    CMT_MEM_ERR_NONE             = 0,
    CMT_MEM_ERR_TX_NOT_FOUND     = 1,   /* :9  ErrTxNotFound        */
    CMT_MEM_ERR_TX_IN_CACHE      = 2,   /* :12 ErrTxInCache         */
    CMT_MEM_ERR_RECHECK_FULL     = 3,   /* :16 ErrRecheckFull       */
    CMT_MEM_ERR_TX_TOO_LARGE     = 4,   /* :20-27 ErrTxTooLarge     */
    CMT_MEM_ERR_MEMPOOL_IS_FULL  = 5,   /* :31-47 ErrMempoolIsFull  */
    CMT_MEM_ERR_PRE_CHECK        = 6,   /* :50-60 ErrPreCheck       */
    CMT_MEM_ERR_APP_CONN_MEMPOOL = 7,   /* :67-77 ErrAppConnMempool */
    CMT_MEM_ERR_FLUSH_APP_CONN   = 8    /* :79-89 ErrFlushAppConn   */
} cmt_mem_err_kind_t;

/**
 * The error value: the kind plus the fields the typed errors carry, so a
 * caller can render the reference's messages (:26, :40-46, :55, :72,
 * :84) or branch on the kind as the reactor does (reactor.go:159-167).
 * `Unwrap` (:58-60, :75-77, :87-89) is `wrapped`: the code the wrapped
 * callback returned.
 */
typedef struct {
    cmt_mem_err_kind_t kind;

    /* ErrTxTooLarge (:20-23) */
    int64_t max;            /* :21 Max    */
    int64_t actual;         /* :22 Actual */

    /* ErrMempoolIsFull (:31-37) */
    int64_t num_txs;        /* :32 */
    int64_t max_txs;        /* :33 */
    int64_t txs_bytes;      /* :34 */
    int64_t max_txs_bytes;  /* :35 */
    bool    recheck_full;   /* :36 — never set by the reference either */

    /* ErrPreCheck.Err (:51), ErrAppConnMempool.Err (:68),
     * ErrFlushAppConn.Err (:80) */
    int     wrapped;
} cmt_mem_error_t;

/** Sets `e` to "no error". NULL is a no-op. */
void cmt_mem_error_init(cmt_mem_error_t *e);

/** errors.go:63-65 — `IsPreCheckError(err)`. */
bool cmt_mem_is_pre_check_error(const cmt_mem_error_t *e);

/* ══ mempool/tx.go:9-17 — TxInfo ══════════════════════════════════════ */

typedef struct {
    uint16_t       sender_id;          /* :13 — the mempool id, 0 = unknown */
    const uint8_t *sender_p2p_id;      /* :16 — the witness id, logging only */
    size_t         sender_p2p_id_len;  /* 0 when there is none (:150-152 of reactor.go) */
} cmt_mem_tx_info_t;

/* ══ mempool/mempoolTx.go:11-19 — mempoolTx ═══════════════════════════ */

/**
 * One resident transaction. Allocated by the mempool when the
 * application accepts a transaction (clist_mempool.go:439-443), owned by
 * its CList element (cmt_clist.h "Value") and freed with it — which may
 * be AFTER removal, while a reactor cursor still reads it.
 *
 * `tx` is a COPY of the bytes (the reference keeps the request's slice,
 * which the decoder allocated fresh at types.pb.go:365-366); the copy
 * lives in the same allocation as the struct.
 */
typedef struct {
    int64_t  height;       /* :12 — height it was validated in */
    int64_t  gas_wanted;   /* :13 */
    uint8_t *tx;           /* :14 */
    size_t   tx_len;
    /** :18 — `senders sync.Map` (PeerID → bool): a bitmap over the whole
     *  uint16 id space, see the header. */
    uint8_t  senders[CMT_MEM_SENDER_ID_SPACE / 8u];
} cmt_mem_tx_t;

/** mempoolTx.go:22-24 — `Height()`. 0 for NULL. */
int64_t cmt_mem_tx_height(const cmt_mem_tx_t *tx);

/** mempoolTx.go:26-29 — `isSender(peerID)`. false for NULL. */
bool cmt_mem_tx_is_sender(const cmt_mem_tx_t *tx, uint16_t peer_id);

/** mempoolTx.go:31-34 — `addSender(senderID)`: records the sender and
 *  returns whether it was ALREADY there (the reference returns
 *  `LoadOrStore`'s `loaded`, which its callers ignore). false for NULL. */
bool cmt_mem_tx_add_sender(cmt_mem_tx_t *tx, uint16_t sender_id);

/* ══ mempool/cache.go ═════════════════════════════════════════════════ */

/** One node of the LRU list: a key, in a `container/list`-shaped doubly
 *  linked chain from `front` (oldest) to `back` (newest). Private. */
typedef struct cmt_mem_lru_node {
    uint8_t                  key[CMT_MEM_TX_KEY_SIZE];   /* the list's Value */
    struct cmt_mem_lru_node *prev;
    struct cmt_mem_lru_node *next;
    bool                     in_use;
} cmt_mem_lru_node_t;

/** One slot of the open-addressing index both maps of this module use:
 *  a 64-byte key and the object it names. Private. */
typedef struct {
    uint8_t key[CMT_MEM_TX_KEY_SIZE];
    void   *val;
    bool    used;
} cmt_mem_index_entry_t;

/** A fixed-capacity open-addressing map from TxKey to a pointer. Linear
 *  probing on the key's first eight bytes (a SHA3-512 digest needs no
 *  second hash), backward-shift deletion, never iterated. Private. */
typedef struct {
    cmt_mem_index_entry_t *entries;
    size_t                 cap;     /* a power of two */
    size_t                 count;
} cmt_mem_index_t;

/**
 * cache.go:35-39 — `LRUTxCache`, minus the mutex. `cacheMap` (:37) is
 * the index; `list` (:38) is the node chain. Node storage is
 * `max(size, 1)` entries: with `size` 0 the reference's `Push` still
 * keeps one key, because it evicts only when `Front()` is non-nil
 * (:76-82) and then pushes (:84).
 */
typedef struct {
    int                  size;        /* :36 */
    cmt_mem_lru_node_t  *nodes;
    size_t               nodes_cap;
    cmt_mem_lru_node_t  *free_list;   /* unused nodes, chained through `next` */
    cmt_mem_lru_node_t  *front;       /* list.Front(): least recently pushed */
    cmt_mem_lru_node_t  *back;        /* list.Back():  most recently pushed  */
    int                  len;         /* list.Len() == len(cacheMap)         */
    cmt_mem_index_t      map;         /* :37 */
} cmt_mem_lru_tx_cache_t;

/** cache.go:42-48 — `NewLRUTxCache(cacheSize)`. Allocates the node
 *  storage and the index.
 *  @return CMT_OK, CMT_FAULT on NULL, a negative size, or allocation. */
int cmt_mem_lru_tx_cache_init(cmt_mem_lru_tx_cache_t *c, int cache_size);

/** C-only: releases what init allocated. NULL is a no-op. */
void cmt_mem_lru_tx_cache_free(cmt_mem_lru_tx_cache_t *c);

/** cache.go:56-62 — `Reset()`: an empty map and an empty list. */
void cmt_mem_lru_tx_cache_reset(cmt_mem_lru_tx_cache_t *c);

/** cache.go:64-89 — `Push(tx)`: a key already present is moved to the
 *  BACK (:70-73) and false is returned; otherwise, when the list is at
 *  `size`, the FRONT is evicted (:75-82); the key is appended at the
 *  back (:84-85) and true is returned.
 *  @return true iff newly added; false for NULL or a hash failure. */
bool cmt_mem_lru_tx_cache_push(cmt_mem_lru_tx_cache_t *c,
                               const uint8_t *tx, size_t tx_len);

/** cache.go:91-102 — `Remove(tx)`. A missing key is a no-op. */
void cmt_mem_lru_tx_cache_remove(cmt_mem_lru_tx_cache_t *c,
                                 const uint8_t *tx, size_t tx_len);

/** cache.go:104-111 — `Has(tx)`. "Checking for presence is not treated
 *  as an access" (:26-27): the list is not touched. */
bool cmt_mem_lru_tx_cache_has(const cmt_mem_lru_tx_cache_t *c,
                              const uint8_t *tx, size_t tx_len);

/** `c.list.Len()` and `len(c.cacheMap)`, which are one count here. */
int cmt_mem_lru_tx_cache_len(const cmt_mem_lru_tx_cache_t *c);

/** cache.go:52-54 — `GetList()`, "for testing purposes only": the walk
 *  cache_test.go:88-109 makes. `front` is the oldest key; `next` steps
 *  towards the newest; `key` is the node's Value. */
const cmt_mem_lru_node_t *cmt_mem_lru_tx_cache_front(
        const cmt_mem_lru_tx_cache_t *c);
const cmt_mem_lru_node_t *cmt_mem_lru_node_next(const cmt_mem_lru_node_t *n);
const uint8_t *cmt_mem_lru_node_key(const cmt_mem_lru_node_t *n);

/** cache.go:15-29 — the `TxCache` interface's two implementations:
 *  `LRUTxCache` (:35-111) and `NopTxCache` (:113-120). */
typedef enum {
    CMT_MEM_TX_CACHE_NOP = 0,
    CMT_MEM_TX_CACHE_LRU = 1
} cmt_mem_tx_cache_kind_t;

typedef struct {
    cmt_mem_tx_cache_kind_t kind;
    cmt_mem_lru_tx_cache_t  lru;   /* valid when kind == LRU */
} cmt_mem_tx_cache_t;

/** cache.go:117 / :56 — `Reset()`. */
void cmt_mem_tx_cache_reset(cmt_mem_tx_cache_t *c);
/** cache.go:118 / :64 — `Push()`; the Nop cache always returns true. */
bool cmt_mem_tx_cache_push(cmt_mem_tx_cache_t *c, const uint8_t *tx,
                           size_t tx_len);
/** cache.go:119 / :91 — `Remove()`. */
void cmt_mem_tx_cache_remove(cmt_mem_tx_cache_t *c, const uint8_t *tx,
                             size_t tx_len);
/** cache.go:120 / :104 — `Has()`; the Nop cache always returns false. */
bool cmt_mem_tx_cache_has(const cmt_mem_tx_cache_t *c, const uint8_t *tx,
                          size_t tx_len);

/* ══ mempool/ids.go ═══════════════════════════════════════════════════ */

/**
 * ids.go:10-15 — `mempoolIDs`, minus the mutex. `peerMap` (:12) keyed by
 * `p2p.ID` becomes an array indexed by the host's peer SLOT (substitution
 * item 9), with a presence flag for the map's "key exists". `activeIDs`
 * (:14) is a bitmap over the uint16 space with its count kept alongside
 * for the `len(ids.activeIDs)` of :31.
 */
typedef struct {
    uint16_t peer_map[CMT_MEM_MAX_PEERS];      /* :12 */
    bool     peer_present[CMT_MEM_MAX_PEERS];
    uint16_t next_id;                          /* :13 */
    uint8_t  active_ids[CMT_MEM_SENDER_ID_SPACE / 8u];  /* :14 */
    uint32_t active_count;                     /* len(activeIDs) */
} cmt_mem_ids_t;

/** ids.go:65-71 — `newMempoolIDs()`: id 0 active (reserved for
 *  UnknownPeerID, :68-69), `nextID` = 1.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_mem_ids_init(cmt_mem_ids_t *ids);

/**
 * ids.go:19-26 — `ReserveForPeer(peer)`: the next unused id (:23,
 * `nextPeerID` :30-43 — the scan from `nextID` over the active set,
 * wrapping with the uint16) is assigned to the slot and marked active.
 *
 * PORTED LITERALLY, including what the reference does NOT check: a slot
 * that already holds an id gets a NEW one and the OLD id stays active
 * (:24-25 overwrite the map entry and never reclaim). That is the only
 * way `len(activeIDs)` can reach `MaxActiveIDs` with 128 slots, and it
 * is exactly how ids_test.go:25-42 drives the panic; a host that calls
 * this twice for one slot without `reclaim` between is leaking ids
 * exactly as a Go host that called `InitPeer` twice would.
 *
 * @return CMT_OK; CMT_REJECT for a slot outside [0, CMT_MEM_MAX_PEERS);
 *         CMT_FAULT on NULL or at :31-33, the "maximum active IDs" panic
 *         (node-local: only this node's own reservations reach it).
 */
int cmt_mem_ids_reserve_for_peer(cmt_mem_ids_t *ids, int slot);

/** ids.go:46-55 — `Reclaim(peer)`: if the slot holds an id, the id
 *  leaves the active set and the slot is cleared; otherwise nothing.
 *  @return CMT_OK; CMT_REJECT for a slot out of range; CMT_FAULT on NULL. */
int cmt_mem_ids_reclaim(cmt_mem_ids_t *ids, int slot);

/** ids.go:58-63 — `GetForPeer(peer)`: the slot's id, or 0 — the Go map's
 *  zero value — when the slot holds none (or is out of range / NULL). */
uint16_t cmt_mem_ids_get_for_peer(const cmt_mem_ids_t *ids, int slot);

/* ══ clist_mempool.go:697-704 — the recheck cursor ════════════════════ */

/**
 * `type recheck struct`, minus `doneCh` (:700, header). `cursor` and
 * `end` hold cursor references on their elements (cmt_clist.h) while
 * rechecking; `set_done` releases both and clears `end` as well as
 * `cursor` — the reference leaves `end` stale (:730 clears only the
 * cursor), which is unobservable through the public surface.
 */
typedef struct {
    cmt_clist_elem_t *cursor;            /* :698 */
    cmt_clist_elem_t *end;               /* :699 */
    int32_t           num_pending_txs;   /* :701 */
    bool              is_rechecking;     /* :702 */
    bool              recheck_full;      /* :703 */
} cmt_mem_recheck_t;

/* ══ clist_mempool.go:26-58 — CListMempool ════════════════════════════ */

/** The consumer of the TxsAvailable signal (header). */
typedef void (*cmt_mem_txs_available_fn)(void *ctx);

/**
 * `type CListMempool struct`, field for field. `logger` (:56) is
 * QGP_LOG; `metrics` (:57) is not ported (the port map's YOK). Every
 * field is PRIVATE to cmt_mem.c and the tests; use the functions.
 */
typedef struct {
    int64_t height;                       /* :27 — the last block Update()'d to */
    int64_t txs_bytes;                    /* :28 */
    bool    notified_txs_available;       /* :31 */
    bool    txs_available_enabled;        /* :32 — the channel exists */
    cmt_mem_txs_available_fn txs_available_fn;   /* the channel's reader */
    void                    *txs_available_ctx;
    const cmt_mempool_config_t *config;   /* :34, borrowed */
    cmt_mem_pre_check_t   pre_check;      /* :39 */
    cmt_mem_post_check_t  post_check;     /* :40 */
    cmt_clist_t           txs;            /* :42 */
    const cmt_mem_app_t  *app;            /* :43 proxyAppConn, borrowed */
    cmt_mem_recheck_t     recheck;        /* :46 */
    cmt_mem_index_t       txs_map;        /* :50 txKey → *CElement */
    cmt_mem_tx_cache_t    cache;          /* :54 */
} cmt_mem_t;

/**
 * clist_mempool.go:67-96 — `NewCListMempool(cfg, proxyAppConn, height,
 * options...)`. `cfg` and `app` are BORROWED and must outlive the pool.
 * The cache is an LRU of `CacheSize` when that is > 0 and the Nop cache
 * otherwise (:83-87). `SetResponseCallback` (:89) is gone with the async
 * client. The two options that matter are parameters: `WithPreCheck`
 * (:137-139) and `WithPostCheck` (:144-146); NULL is "not given".
 * `WithMetrics` (:149-151) is not ported.
 *
 * Storage: the tx map is sized to hold `cfg->size` entries; the cache
 * to `cfg->cache_size` keys.
 *
 * @return CMT_OK; CMT_FAULT on NULL, a negative `size`/`cache_size`, or
 *         allocation failure.
 */
int cmt_mem_init(cmt_mem_t *mem, const cmt_mempool_config_t *cfg,
                 const cmt_mem_app_t *app, int64_t height,
                 const cmt_mem_pre_check_t *pre_check,
                 const cmt_mem_post_check_t *post_check);

/** C-only: releases everything `cmt_mem_init` allocated. Elements a
 *  reactor cursor still references survive until it lets go. NULL is a
 *  no-op. */
void cmt_mem_free(cmt_mem_t *mem);

/** clist_mempool.go:98-103 — `getCElement(txKey)`. NULL when absent. */
cmt_clist_elem_t *cmt_mem_get_celement(const cmt_mem_t *mem,
                                       const uint8_t key[CMT_MEM_TX_KEY_SIZE]);

/** clist_mempool.go:105-110 — `getMemTx(txKey)`. NULL when absent. */
cmt_mem_tx_t *cmt_mem_get_mem_tx(const cmt_mem_t *mem,
                                 const uint8_t key[CMT_MEM_TX_KEY_SIZE]);

/** clist_mempool.go:125-127 — `EnableTxsAvailable()`: "should only be
 *  called once, on startup". Registers the signal's consumer (header);
 *  `fn` may be NULL (a channel nobody reads — the flag still flips).
 *  @return CMT_OK, CMT_FAULT on NULL `mem`. */
int cmt_mem_enable_txs_available(cmt_mem_t *mem,
                                 cmt_mem_txs_available_fn fn, void *ctx);

/** clist_mempool.go:154-159 — `Lock()`: `setRecheckFull` (:155), then
 *  the mutex, which is gone. Returns what the reference logs at :156:
 *  whether the `recheckFull` flag flipped. false for NULL. */
bool cmt_mem_lock(cmt_mem_t *mem);

/** clist_mempool.go:162-164 — `Unlock()`. A no-op (single thread). */
void cmt_mem_unlock(cmt_mem_t *mem);

/** clist_mempool.go:167-169 — `Size()`. */
int cmt_mem_size(const cmt_mem_t *mem);

/** clist_mempool.go:172-174 — `SizeBytes()`. */
int64_t cmt_mem_size_bytes(const cmt_mem_t *mem);

/** clist_mempool.go:177-184 — `FlushAppConn()`: `app->flush`, its
 *  error wrapped as `ErrFlushAppConn` (:180).
 *  @return CMT_OK, CMT_REJECT with `out_err`, CMT_FAULT on NULL. */
int cmt_mem_flush_app_conn(cmt_mem_t *mem, cmt_mem_error_t *out_err);

/** clist_mempool.go:187-195 — `Flush()`: bytes to 0, cache reset, every
 *  transaction removed (`removeAllTxs` :112-122). "XXX: Unsafe!" (:186)
 *  in the reference because of the threads; here it is not.
 *  @return CMT_OK, CMT_FAULT on NULL or a corrupted list. */
int cmt_mem_flush(cmt_mem_t *mem);

/** clist_mempool.go:202-204 — `TxsFront()`: the reactor's starting
 *  cursor (reactor.go:201). `TxsWaitChan` (:211-213) is not ported — the
 *  reactor polls this instead. */
cmt_clist_elem_t *cmt_mem_txs_front(const cmt_mem_t *mem);

/**
 * clist_mempool.go:223-278 — `CheckTx(tx, cb, txInfo)`, continued by
 * `reqResCb` (:334-350) and `resCbFirstTime` (:401-474) as the header
 * describes. In order: `isFull` (:234-237), `MaxTxBytes` (:239-244),
 * `preCheck` (:246-250), `app->error` (:253-255), the cache (:257-269 —
 * a duplicate records the sender on the resident transaction and is
 * `ErrTxInCache`), the application (:271), the "rechecking has not
 * finished" guard (:335-338), then `resCbFirstTime`: `postCheck`
 * (:408-411); on acceptance a second `isFull` (:415-422, refusal drops
 * the cache entry), the "already there" duplicate (:425-437), the new
 * `mempoolTx` at the current height (:439-445), `addTx` (:445) and
 * `notifyTxsAvailable` (:453); on rejection the cache entry is dropped
 * unless `KeepInvalidTxsInCache` (:465-468).
 *
 * The reference's CONTRACT at :220 — "Either cb will get called, or err
 * returned" — is the return contract here: CMT_REJECT with `out_err`
 * means one of the errors of :234-269 and the application was NOT
 * called; CMT_OK means the application WAS called and `out_res` (if
 * given) holds its answer, whatever `res.code` says — a transaction the
 * APPLICATION refuses is CMT_OK with a non-zero code, exactly as the Go
 * CheckTx returns nil and the callback sees the code.
 *
 * @param info the sender (tx.go); required.
 * @param out_res the `cb` of :225 — the RPC's external callback; may be
 *        NULL (the reactor passes nil at reactor.go:157).
 * @param out_err receives the error kind on CMT_REJECT; may be NULL.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT (NULL; the panics at :273 and
 *         :336; allocation; `notifyTxsAvailable`'s :512).
 */
int cmt_mem_check_tx(cmt_mem_t *mem, const uint8_t *tx, size_t tx_len,
                     const cmt_mem_tx_info_t *info,
                     cmt_mem_response_check_tx_t *out_res,
                     cmt_mem_error_t *out_err);

/** clist_mempool.go:366-376 — `RemoveTxByKey(txKey)`: the element is
 *  removed from the list (:368) and detached (:369), the map entry
 *  deleted (:370), the bytes subtracted (:372).
 *  @return CMT_OK; CMT_REJECT with `ErrTxNotFound` (:375); CMT_FAULT on
 *          NULL or a corrupted list. */
int cmt_mem_remove_tx_by_key(cmt_mem_t *mem,
                             const uint8_t key[CMT_MEM_TX_KEY_SIZE],
                             cmt_mem_error_t *out_err);

/** clist_mempool.go:506-508 — `TxsAvailable()`: whether the channel
 *  exists, i.e. whether `EnableTxsAvailable` was called. The channel
 *  itself is the callback. */
bool cmt_mem_txs_available(const cmt_mem_t *mem);

/**
 * clist_mempool.go:524-562 — `ReapMaxBytesMaxGas(maxBytes, maxGas)`.
 * Front to back: each transaction's `ComputeProtoSizeForTxs` (:542) is
 * added to a running size and refused, ending the reap, when it would
 * exceed `max_bytes` (:545-547, unless `max_bytes` is -1); then its
 * `gasWanted` is added to a running total and refused when the total
 * would exceed `max_gas` (:555-558, unless -1). The reference appends
 * first and truncates on refusal (:540, :546, :557); check-then-append
 * here yields the same list. The gas addition (:555) is done in uint64
 * so that it wraps as Go's int64 does instead of being undefined.
 *
 * @param out receives VIEWS of the resident transactions' bytes, valid
 *        until the next call that removes transactions (`update`,
 *        `flush`, `remove_tx_by_key`); the reference's slices alias the
 *        same storage.
 * @param out_cap the caller's room; `cfg->size` always suffices.
 * @return CMT_OK; CMT_FAULT on NULL or when `out_cap` is too small — a
 *         caller sizing error, not a peer's doing.
 */
int cmt_mem_reap_max_bytes_max_gas(const cmt_mem_t *mem, int64_t max_bytes,
                                   int64_t max_gas, cmt_pb_bytes_t *out,
                                   size_t out_cap, size_t *out_len);

/**
 * clist_mempool.go:565-579 — `ReapMaxTxs(max)`. A negative `max` means
 * the whole list (:569-571).
 *
 * NOTE reference quirk, reproduced: the loop condition at :574 is
 * `len(txs) <= max`, so the reap returns up to `max + 1` transactions,
 * not `max`. `out_cap` must allow for that: `min(Size(), max) + 1`
 * suffices, and `cfg->size + 1` always does.
 *
 * @return CMT_OK; CMT_FAULT on NULL or when `out_cap` is too small.
 */
int cmt_mem_reap_max_txs(const cmt_mem_t *mem, int max, cmt_pb_bytes_t *out,
                         size_t out_cap, size_t *out_len);

/**
 * clist_mempool.go:582-643 — `Update(height, txs, txResults, preCheck,
 * postCheck)`. "Lock() must be held by the caller" (:581) — here the
 * caller is the single thread. Sets the height and clears the notified
 * flag (:592-593); replaces the filters that are given (:595-600); for
 * each committed transaction in block order, a committed-OK one enters
 * the cache and a failed one leaves it unless `KeepInvalidTxsInCache`
 * (:602-609), and it is removed from the pool — "not in mempool" is not
 * an error (:621-625); then `recheckTxs` when `Recheck` (:629-631); then
 * `notifyTxsAvailable` when transactions remain (:634-636).
 *
 * @param tx_results one per transaction, indexed alike (:603). Fewer
 *        than `n_txs` is Go's index panic → CMT_FAULT (the
 *        BlockExecutor's contract, node-local).
 * @param pre_check / post_check NULL keeps the current one (:595, :598).
 * @return CMT_OK (the reference returns nil, :642); CMT_FAULT on NULL,
 *         the panics of `recheckTxs`, or `notifyTxsAvailable`'s.
 */
int cmt_mem_update(cmt_mem_t *mem, int64_t height,
                   const cmt_pb_bytes_t *txs, size_t n_txs,
                   const cmt_pb_exec_tx_result_t *tx_results,
                   size_t n_results,
                   const cmt_mem_pre_check_t *pre_check,
                   const cmt_mem_post_check_t *post_check);

/** clist_mempool.go:724-726 — `(rc *recheck) done()`: no recheck in
 *  progress. Exposed because clist_mempool_test.go asserts it. */
bool cmt_mem_recheck_done(const cmt_mem_t *mem);

/** clist_mempool.go:799-801 — `consideredFull()`. */
bool cmt_mem_recheck_considered_full(const cmt_mem_t *mem);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_MEM_H */
