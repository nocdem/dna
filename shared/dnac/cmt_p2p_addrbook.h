/**
 * @file shared/dnac/cmt_p2p_addrbook.h
 * @brief cometbft @709fd12b `p2p/pex/addrbook.go`, `known_address.go`,
 *        `params.go`, `errors.go` (the address-book half) and `file.go`
 *        ported to C — the address book, plus the signed ADDR record of
 *        R-P2P-4.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F4 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "p2p/pex/ *", §9). Only its tests and the PEX reactor of the same
 * phase construct one; the nodus glue (F5) owns the host table. Additive
 * only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * "N7 SON" (validator addresses leave the DHT; each validator signs its
 * own address record; a node keeps, per bonded identity, only the highest
 * sequence) and "N7 ADDR bayt düzeni" (the record's bytes, below — operator
 * approved); session design §2R3 N7 FINAL, §2R4 P4 (persisted book,
 * re-verified at load), P5 (valid + routable gated by addr_book_strict;
 * equal seq is NOT newer).
 *
 * ── THE SIGNED ADDR RECORD (R-P2P-4) ───────────────────────────────────
 * Signed payload, CMT_P2P_ADDR_REC_PAYLOAD_SIZE = 141 bytes:
 *   "nodus.wsess.addr.v1" (19 ASCII bytes, no NUL) ‖ chain_id32 (32, the
 *   version-3 chain id) ‖ pk_fp (64, SHA3-512(ML-DSA-87 pk)) ‖ ip (16,
 *   IPv4 as ::ffff:a.b.c.d) ‖ port (u16 BE) ‖ seq (u64 BE)
 * signed with ML-DSA-87 under the strict purpose 0x0B
 * NODUS_PURPOSE_WITNESS_ADDR (nodus/src/crypto/nodus_sign.h). The record
 * as it travels and is stored is `payload ‖ signature` —
 * CMT_P2P_ADDR_REC_SIZE = 141 + 4627 = 4768 bytes. ⚠ The CONCATENATION
 * (payload then the raw 4627-byte signature, no length prefix, no
 * separator) is NOT GROUNDED — the decision record fixes the signed bytes,
 * not how the pair is carried; operator to confirm.
 * shared/dnac never signs or verifies itself: the host's `verify_addr`
 * (the nodus host binds nodus_verify_witness_addr) does, against the
 * public key the host's `bonded_pubkey` returns for the ID the record
 * names — NEVER a key carried in a message.
 *
 * An entry for a BONDED identity (host `bonded_pubkey(id)` answers) is
 * accepted ONLY through `cmt_p2p_addrbook_add_signed` with a record that
 *   · has the exact size and tag, and chain_id32 == ours;
 *   · pk_fp == SHA3-512(the chain's pubkey), and the entry's ID is
 *     hex(pk_fp[0..31]) (key.go:44 via cmt_p2p_pubkey_to_id);
 *   · verifies (0x0B);
 *   · names the entry's ip and port;
 *   · has seq > the seq of the record the book already holds for that ID
 *     (equal is NOT newer, P5).
 * A newer record whose ip/port differ REPLACES the entry (the old one is
 * removed from its buckets, the new one enters a new bucket) — the
 * reference keeps the first address of an old entry (addrbook.go:676-681,
 * anti-eclipse); a validator's own signature is the stronger proof here.
 * `cmt_p2p_addrbook_add_address` (the reference's unsigned AddAddress:
 * the switch's persistent peers, the PEX reactor's inbound NodeInfo
 * address, a PexAddrs list) REFUSES a bonded ID with
 * CMT_P2P_AB_ERR_UNSIGNED_BONDED. Records naming an ID the chain does not
 * know as bonded are refused (N7: ignored). Unbonded addresses stay
 * unsigned hints exactly as in the reference.
 * A record naming OUR identity (`self_id`) is verified, its seq is
 * remembered (`cmt_p2p_addrbook_own_seq_seen` — N7's "max(stored,
 * highest own seq learned from peers) + 1", consumed by the F5 host) and
 * then refused with ErrAddrBookSelf.
 *
 * ── DEVIATIONS (proposed register rows) ────────────────────────────────
 *   R-P2P-34 (hash) the bucket hash is `highwayhash.New64(key32)` over the
 *            bytes (addrbook.go:112-119, :943-947); HighwayHash is not in
 *            the tree, so hash(b) = the first 8 bytes of
 *            SHA3-512(hasher_key32 ‖ b). Both keys are drawn from the
 *            host's randomness as in the reference — `key` (24 hex
 *            characters, :141, persisted) and the hasher key (32 bytes,
 *            :113, NOT persisted, so after a reload the recomputed
 *            buckets differ from the saved ones exactly as the
 *            reference's do). Transport-local (design §6 D4).
 *   R-P2P-35 (clock) `known_address.go`'s LastAttempt / LastSuccess /
 *            LastBanTime are `time.Now()` WALL time and are persisted
 *            (file.go): the host's `now_ns` here MUST be a wall clock
 *            (Unix ns). Design §6 D3's "monotonic" holds for the rest of
 *            the port; a monotonic value persisted across a restart would
 *            make isBad / isBanned meaningless. The book's save TICKER
 *            (saveRoutine, :497-512) runs on the caller's monotonic clock
 *            (`cmt_p2p_addrbook_tick`). The Go zero time is INT64_MIN.
 *   R-P2P-36 (order) every Go map the book ranges over (addrLookup,
 *            badPeers, the buckets — :314, :370, :415, :634, :718, :743,
 *            file.go :25) is an array here: addrLookup sorted by ID,
 *            buckets and badPeers in insertion order. The random choices
 *            (PickAddress's index, GetSelection's shuffle,
 *            randomPickAddresses' shuffle) are the reference's; only the
 *            order they index into is fixed.
 *   R-P2P-37 (file) the on-disk encoding is this port's own (file.go's
 *            JSON has no C counterpart here) — a protobuf message with the
 *            tree's cmt_pb writer, field numbers in the JSON's field
 *            order (below). ⚠ NOT GROUNDED — a format, not a reference
 *            value. The host owns the file (the reference's AddrBookFile,
 *            written with tempfile.WriteFileAtomic): `save` / `load` hand
 *            bytes in and out.
 *   R-P2P-38 (load) the reference trusts the file (file.go:66-81) and
 *            panics on a corrupt one (:56, :63). Here a file that does
 *            not DECODE makes `start` fail (the reference's panic → the
 *            reactor's OnStart error); every decoded entry is then
 *            RE-VALIDATED with AddAddress's admission checks (valid, not
 *            banned / private / private-source / ours, strict
 *            routability), its bucket type / indices / fullness checked,
 *            duplicate IDs dropped, and an entry of a BONDED identity kept
 *            only if its stored record re-verifies against today's chain
 *            key (§2R4 P4); an entry that fails is dropped, not fatal. A
 *            stored record for an identity that is no longer bonded is
 *            dropped and the address kept as an unsigned hint.
 *   R-P2P-39 (PickAddress loop) "loop until we pick a random non-empty
 *            bucket" (:305-311) spins forever if the counters and the
 *            buckets disagree; here it stops after 4 × the bucket count
 *            tries and then takes the first non-empty bucket from a random
 *            start — never reached while the counters are right.
 *   R-P2P-43 (verify off the loop, phase F5) a record received from a
 *            peer has its ML-DSA-87 check run on the host's bounded
 *            worker (`verify_addr_submit`, `cmt_p2p_addrbook_verify_done`
 *            — below); the entry is added when the verdict comes back,
 *            after every other check has been re-run against the book's
 *            state at that moment. Load-time re-verification (R-P2P-38)
 *            stays synchronous: `start` runs before the event loop.
 *   R-P2P-4  (approved) the signed records, above.
 * The reference's `service.Service` (Start/Stop/Wait) is the three calls
 * start / stop / tick; the mutex is gone (one event loop).
 *
 * ── THE FILE (R-P2P-37) ────────────────────────────────────────────────
 *   AddrBookFile { string key = 1; repeated KnownAddress addrs = 2; }
 *   KnownAddress { NetAddress addr = 1; NetAddress src = 2;
 *                  repeated int32 buckets = 3 (unpacked);
 *                  int32 attempts = 4; uint32 bucket_type = 5;
 *                  int64 last_attempt = 6; int64 last_success = 7;
 *                  int64 last_ban_time = 8; bytes signed_addr = 9; }
 * NetAddress is types.proto's (cmt_p2p_netaddr_pb_*).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local transport state (design §6 D1): nothing here enters a block,
 * a vote or a root. Randomness is the host's (D4). Clock: the host's wall
 * clock for the persisted timestamps (R-P2P-35).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_ADDRBOOK_H
#define CMT_P2P_ADDRBOOK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_p2p_netaddr.h"
#include "cmt_p2p_switch.h"
#include "crypto/sign/qgp_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ params.go ════════════════════════════════════════════════════════ */

#define CMT_P2P_AB_NEED_ADDRESS_THRESHOLD   1000                  /* :7  */
#define CMT_P2P_AB_DUMP_ADDRESS_INTERVAL_NS (120LL * 1000 * 1000 * 1000) /* :10 */
#define CMT_P2P_AB_OLD_BUCKET_SIZE          64                    /* :13 */
#define CMT_P2P_AB_OLD_BUCKET_COUNT         64                    /* :16 */
#define CMT_P2P_AB_NEW_BUCKET_SIZE          64                    /* :19 */
#define CMT_P2P_AB_NEW_BUCKET_COUNT         256                   /* :22 */
#define CMT_P2P_AB_OLD_BUCKETS_PER_GROUP    4                     /* :25 */
#define CMT_P2P_AB_NEW_BUCKETS_PER_GROUP    32                    /* :28 */
#define CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS 4                  /* :31 */
#define CMT_P2P_AB_NUM_MISSING_DAYS         7                     /* :35 */
#define CMT_P2P_AB_NUM_RETRIES              3                     /* :38 */
#define CMT_P2P_AB_MAX_FAILURES             10                    /* :41 */
#define CMT_P2P_AB_MIN_BAD_DAYS             7                     /* :44 */
#define CMT_P2P_AB_GET_SELECTION_PERCENT    23                    /* :47 */
#define CMT_P2P_AB_MIN_GET_SELECTION        32                    /* :50 */
#define CMT_P2P_AB_MAX_GET_SELECTION        250                   /* :54 */

/** A bucket holds one more than its size: the reference expires only
 *  when `len(bucket) > newBucketSize` (:544) and refuses an old add only
 *  when `len(bucket) > oldBucketSize` (:582). */
#define CMT_P2P_AB_BUCKET_CAP (CMT_P2P_AB_NEW_BUCKET_SIZE + 1)

/* addrbook.go:28-31 */
#define CMT_P2P_AB_BUCKET_TYPE_NEW 0x01
#define CMT_P2P_AB_BUCKET_TYPE_OLD 0x02

/** addrbook.go:141 `CRandHex(24)` — 24 hex characters. */
#define CMT_P2P_AB_KEY_LEN      24
/** highwayhash.Size (the hasher key, :113). */
#define CMT_P2P_AB_HASH_KEY_LEN 32

/** The Go zero `time.Time` (R-P2P-35). */
#define CMT_P2P_AB_TIME_ZERO INT64_MIN

#define CMT_P2P_AB_NS_PER_SEC  (1000LL * 1000 * 1000)
#define CMT_P2P_AB_NS_PER_DAY  (24LL * 3600 * CMT_P2P_AB_NS_PER_SEC)

/* ══ the signed ADDR record (R-P2P-4; file header) ════════════════════ */

#define CMT_P2P_ADDR_REC_TAG            "nodus.wsess.addr.v1"
#define CMT_P2P_ADDR_REC_TAG_LEN        19
#define CMT_P2P_ADDR_REC_CHAIN_LEN      32
#define CMT_P2P_ADDR_REC_FP_LEN         64
#define CMT_P2P_ADDR_REC_IP_LEN         16
#define CMT_P2P_ADDR_REC_PAYLOAD_SIZE   (CMT_P2P_ADDR_REC_TAG_LEN + \
    CMT_P2P_ADDR_REC_CHAIN_LEN + CMT_P2P_ADDR_REC_FP_LEN + \
    CMT_P2P_ADDR_REC_IP_LEN + 2 + 8)
#define CMT_P2P_ADDR_REC_SIG_SIZE       QGP_DSA87_SIGNATURE_BYTES
#define CMT_P2P_ADDR_REC_SIZE \
    (CMT_P2P_ADDR_REC_PAYLOAD_SIZE + CMT_P2P_ADDR_REC_SIG_SIZE)

_Static_assert(sizeof(CMT_P2P_ADDR_REC_TAG) - 1 == CMT_P2P_ADDR_REC_TAG_LEN,
               "ADDR tag length");
_Static_assert(CMT_P2P_ADDR_REC_PAYLOAD_SIZE == 141, "ADDR payload is 141 bytes");
_Static_assert(CMT_P2P_ADDR_REC_SIZE == 4768, "ADDR record is 4768 bytes");

/** A parsed record (pointers into nothing — every field copied). */
typedef struct {
    uint8_t  chain_id[CMT_P2P_ADDR_REC_CHAIN_LEN];
    uint8_t  pk_fp[CMT_P2P_ADDR_REC_FP_LEN];
    cmt_p2p_ip_t ip;                 /* the 16-byte form */
    uint16_t port;
    uint64_t seq;
    char     id[CMT_P2P_ID_CAP];     /* hex(pk_fp[0..31]) */
} cmt_p2p_addr_rec_t;

/**
 * Build the signed payload (file header bytes). `ip` IPv4 (4- or 16-byte
 * form) is written as ::ffff:a.b.c.d, IPv6 as its 16 bytes.
 * @return CMT_OK; CMT_REJECT on a nil IP; CMT_FAULT on NULL.
 */
int cmt_p2p_addr_rec_payload(const uint8_t chain_id[CMT_P2P_ADDR_REC_CHAIN_LEN],
                             const uint8_t pk_fp[CMT_P2P_ADDR_REC_FP_LEN],
                             const cmt_p2p_ip_t *ip, uint16_t port,
                             uint64_t seq,
                             uint8_t out[CMT_P2P_ADDR_REC_PAYLOAD_SIZE]);

/** Parse `payload ‖ signature` (size and tag checked; nothing verified).
 *  @return CMT_OK; CMT_REJECT (size / tag); CMT_FAULT on NULL. */
int cmt_p2p_addr_rec_parse(const uint8_t *rec, size_t len,
                           cmt_p2p_addr_rec_t *out);

/* ══ errors.go (the address-book errors) + R-P2P-4 ════════════════════ */

/** Positive and above cmt_p2p_err_t / CMT_P2P_PEER_ERR_UNKNOWN_CHANNEL. */
typedef enum {
    CMT_P2P_AB_OK                     = 0,
    CMT_P2P_AB_ERR_NIL_ADDR           = 201,  /* ErrAddrBookNilAddr      :61-68  */
    CMT_P2P_AB_ERR_INVALID_ADDR       = 202,  /* ErrAddrBookInvalidAddr  :70-77  */
    CMT_P2P_AB_ERR_BANNED             = 203,  /* ErrAddressBanned        :80-86  */
    CMT_P2P_AB_ERR_PRIVATE            = 204,  /* ErrAddrBookPrivate      :37-47  */
    CMT_P2P_AB_ERR_PRIVATE_SRC        = 205,  /* ErrAddrBookPrivateSrc   :49-59  */
    CMT_P2P_AB_ERR_SELF               = 206,  /* ErrAddrBookSelf         :29-35  */
    CMT_P2P_AB_ERR_NON_ROUTABLE       = 207,  /* ErrAddrBookNonRoutable  :10-16  */
    CMT_P2P_AB_ERR_OLD_ADDRESS_NEW_BUCKET = 208, /* errAddrBookOldAddressNewBucket :18-27 */
    /* R-P2P-4 */
    CMT_P2P_AB_ERR_UNSIGNED_BONDED    = 220,  /* a bonded ID without a record   */
    CMT_P2P_AB_ERR_NOT_BONDED         = 221,  /* a record for an unbonded ID    */
    CMT_P2P_AB_ERR_RECORD_MALFORMED   = 222,  /* size / tag                     */
    CMT_P2P_AB_ERR_RECORD_CHAIN       = 223,  /* chain_id32 is not ours         */
    CMT_P2P_AB_ERR_RECORD_KEY         = 224,  /* pk_fp ≠ SHA3-512(chain pk)      */
    CMT_P2P_AB_ERR_RECORD_SIG         = 225,  /* the 0x0B signature fails       */
    CMT_P2P_AB_ERR_RECORD_MISMATCH    = 226,  /* ip / port / ID ≠ the entry      */
    CMT_P2P_AB_ERR_RECORD_NOT_NEWER   = 227,  /* seq ≤ the held record's seq    */
    /* R-P2P-43 — not an error: the record passed every check but the
     * signature, which is now queued on the host's worker; the verdict
     * arrives through cmt_p2p_addrbook_verify_done. */
    CMT_P2P_AB_PENDING                = 228,
    CMT_P2P_AB_ERR_VERIFY_QUEUE_FULL  = 229   /* the host refused the job / too
                                                 many verifications in flight  */
} cmt_p2p_ab_err_t;

/** The most received-record verifications one book keeps in flight
 *  (R-P2P-43). One PEX response part carries at most maxGetSelection
 *  records; a bound above it lets one full part be queued at once.
 *  ⚠ NOT GROUNDED — a size, not a reference value. */
#define CMT_P2P_AB_MAX_PENDING_VERIFY (CMT_P2P_AB_MAX_GET_SELECTION + 6)

const char *cmt_p2p_ab_err_str(int err);

/* ══ host + config ════════════════════════════════════════════════════ */

typedef struct {
    void *ctx;
    /** WALL clock, Unix ns (R-P2P-35). Required. */
    int64_t (*now_ns)(void *ctx);
    /** n random bytes (crypto.CRandBytes / CRandHex). 0 = success.
     *  Required. */
    int (*rand_bytes)(void *ctx, uint8_t *out, size_t n);
    /** [0, n) — the book's `rand` (Intn, Int31n, Float64) and cmtrand's
     *  global functions (GetSelection :424). Required. */
    int64_t (*rand_int63n)(void *ctx, int64_t n);
    /** R-P2P-4: true and the chain's ML-DSA-87 public key when `id` is in
     *  the local chain's bonded set (session design N5). NULL = nobody is
     *  bonded. */
    bool (*bonded_pubkey)(void *ctx, const char *id,
                          uint8_t pk[QGP_DSA87_PUBLICKEYBYTES]);
    /** R-P2P-4: verify `sig` over `payload` under purpose 0x0B with `pk`
     *  (nodus_verify_witness_addr). 0 = valid. Required when
     *  `bonded_pubkey` is set. */
    int (*verify_addr)(void *ctx, const uint8_t *payload, size_t len,
                       const uint8_t sig[CMT_P2P_ADDR_REC_SIG_SIZE],
                       const uint8_t pk[QGP_DSA87_PUBLICKEYBYTES]);
    /** R-P2P-43 (phase F5): the same check, off the event loop. The host
     *  COPIES `payload`, `sig` and `pk` (valid only during the call),
     *  runs `verify_addr`'s check on its bounded worker and later — on
     *  the loop thread — hands the verdict back with
     *  `cmt_p2p_addrbook_verify_done(book, ticket, rc)` — never from
     *  inside this call. Verdicts still queued when the book is freed
     *  are dropped by the host.
     *  @return 0 = queued; non-zero = refused (the record is dropped,
     *  exactly as a full queue drops any other job).
     *  NULL = records received from peers are verified synchronously
     *  through `verify_addr` (the F4 behaviour). Records re-verified at
     *  load (R-P2P-38) always use `verify_addr`: `start` runs before the
     *  loop does. */
    int (*verify_addr_submit)(void *ctx, uint64_t ticket,
                              const uint8_t *payload, size_t len,
                              const uint8_t sig[CMT_P2P_ADDR_REC_SIG_SIZE],
                              const uint8_t pk[QGP_DSA87_PUBLICKEYBYTES]);
    /** file.go saveToFile: write these bytes as the AddrBookFile (atomic
     *  replace is the host's). 0 = written. NULL = never saved. */
    int (*save)(void *ctx, const uint8_t *bytes, size_t len);
    /** file.go loadFromFile: 1 = no file; 0 = `*bytes` (malloc'd, the
     *  book frees it) / `*len` set; < 0 = read error. NULL = no file. */
    int (*load)(void *ctx, uint8_t **bytes, size_t *len);
} cmt_p2p_ab_host_t;

typedef struct {
    /** config.go:561 `addr_book_strict` (NewAddrBook routabilityStrict). */
    bool    routability_strict;
    /** The version-3 chain id every record must carry. */
    uint8_t chain_id[CMT_P2P_ADDR_REC_CHAIN_LEN];
    /** This node's ID (for the own-seq capture). Empty = unknown. */
    char    self_id[CMT_P2P_ID_CAP];
} cmt_p2p_ab_config_t;

typedef struct cmt_p2p_addrbook cmt_p2p_addrbook_t;

/* ══ addrbook.go — construction and service (:121-181) ════════════════ */

/** addrbook.go:123-153 `NewAddrBook` + `init` (both keys from the host).
 *  @return NULL on a missing host row, a rand failure or memory. */
cmt_p2p_addrbook_t *cmt_p2p_addrbook_new(const cmt_p2p_ab_config_t *cfg,
                                         const cmt_p2p_ab_host_t *host);

void cmt_p2p_addrbook_free(cmt_p2p_addrbook_t *a);

/** addrbook.go:156-168 `OnStart` → loadFromFile (R-P2P-38). Starting a
 *  started book is a no-op (service.ErrAlreadyStarted, which PEX's
 *  OnStart ignores, pex_reactor.go:147-150).
 *  @return CMT_OK; CMT_REJECT — the file does not decode or the host's
 *  load failed. */
int  cmt_p2p_addrbook_start(cmt_p2p_addrbook_t *a);

/** addrbook.go:171-173 + saveRoutine's final save (:510-511). */
void cmt_p2p_addrbook_stop(cmt_p2p_addrbook_t *a);

/** saveRoutine's ticker (:497-509): saves every dumpAddressInterval on
 *  the caller's MONOTONIC clock (the first call arms it). */
void cmt_p2p_addrbook_tick(cmt_p2p_addrbook_t *a, int64_t mono_now_ns);

/* ══ the AddrBook interface (:37-82) ══════════════════════════════════ */

void cmt_p2p_addrbook_add_our_address(cmt_p2p_addrbook_t *a,
                                      const cmt_p2p_netaddr_t *addr);   /* :186-192 */
bool cmt_p2p_addrbook_our_address(const cmt_p2p_addrbook_t *a,
                                  const cmt_p2p_netaddr_t *addr);       /* :195-201 */
void cmt_p2p_addrbook_add_private_ids(cmt_p2p_addrbook_t *a,
                                      const char *const *ids, int n);   /* :203-210 */

/** addrbook.go:216-221 `AddAddress` (+ R-P2P-4: a bonded ID is refused).
 *  @return CMT_P2P_AB_OK or a cmt_p2p_ab_err_t; CMT_FAULT on memory. */
int  cmt_p2p_addrbook_add_address(cmt_p2p_addrbook_t *a,
                                  const cmt_p2p_netaddr_t *addr,
                                  const cmt_p2p_netaddr_t *src);

/**
 * R-P2P-4: add the address a signed record describes (file header rules).
 * `addr` may be NULL (the entry is the record's own id@ip:port); when
 * given, its ID, IP and port must be the record's.
 * @param addr_out  the record's address (when non-NULL, set once parsed)
 * @return CMT_P2P_AB_OK (added, replaced or refreshed) or a
 *         cmt_p2p_ab_err_t; CMT_FAULT on NULL / memory.
 */
int  cmt_p2p_addrbook_add_signed(cmt_p2p_addrbook_t *a,
                                 const cmt_p2p_netaddr_t *addr,
                                 const cmt_p2p_netaddr_t *src,
                                 const uint8_t *rec, size_t rec_len,
                                 cmt_p2p_netaddr_t *addr_out);

/*
 * R-P2P-43 (phase F5) — with the host's `verify_addr_submit` set,
 * `cmt_p2p_addrbook_add_signed` runs every check EXCEPT the ML-DSA-87
 * signature, then (unless the book already holds a record for that ID
 * with an equal or higher seq, or the same record is already in flight)
 * keeps a copy of the record, the source and the chain key it checked
 * against, hands the signature check to the host and returns
 * CMT_P2P_AB_PENDING. At most CMT_P2P_AB_MAX_PENDING_VERIFY records are
 * in flight; a further one is CMT_P2P_AB_ERR_VERIFY_QUEUE_FULL (dropped).
 */

/**
 * The verdict of a queued check (`verify_rc` 0 = the signature is valid).
 * Every check `add_signed` runs is run AGAIN against the book's state NOW
 * (the bonded set, the held seq, the admission checks may have changed
 * while the job ran); the chain key must still be the one the job
 * verified against. Then the entry is added exactly as the synchronous
 * path adds it.
 * @return the add result (CMT_P2P_AB_OK or a cmt_p2p_ab_err_t);
 *         CMT_REJECT for a ticket the book does not know; CMT_FAULT on
 *         NULL / memory.
 */
int  cmt_p2p_addrbook_verify_done(cmt_p2p_addrbook_t *a, uint64_t ticket,
                                  int verify_rc);

/** Received records whose signature check is in flight (tests). */
int  cmt_p2p_addrbook_pending_verifications(const cmt_p2p_addrbook_t *a);

void cmt_p2p_addrbook_remove_address(cmt_p2p_addrbook_t *a,
                                     const cmt_p2p_netaddr_t *addr);    /* :224-229 */
bool cmt_p2p_addrbook_is_good(const cmt_p2p_addrbook_t *a,
                              const cmt_p2p_netaddr_t *addr);           /* :233-238 */
bool cmt_p2p_addrbook_is_banned(const cmt_p2p_addrbook_t *a,
                                const cmt_p2p_netaddr_t *addr);         /* :241-247 */
bool cmt_p2p_addrbook_has_address(const cmt_p2p_addrbook_t *a,
                                  const cmt_p2p_netaddr_t *addr);       /* :250-256 */
bool cmt_p2p_addrbook_need_more_addrs(const cmt_p2p_addrbook_t *a);     /* :259-261 */
bool cmt_p2p_addrbook_empty(const cmt_p2p_addrbook_t *a);               /* :265-267 */

/** addrbook.go:275-321 `PickAddress`. @return true and `*out`, or false
 *  (the reference's nil). */
bool cmt_p2p_addrbook_pick_address(cmt_p2p_addrbook_t *a, int bias_new,
                                   cmt_p2p_netaddr_t *out);

void cmt_p2p_addrbook_mark_good(cmt_p2p_addrbook_t *a, const char *id);  /* :325-339 */
void cmt_p2p_addrbook_mark_attempt(cmt_p2p_addrbook_t *a,
                                   const cmt_p2p_netaddr_t *addr);      /* :342-351 */
/** :355-362 MarkBad — except that a BONDED ID (host `bonded_pubkey`) is
 *  never banned (red-team Z2-F11; see the definition). */
void cmt_p2p_addrbook_mark_bad(cmt_p2p_addrbook_t *a,
                               const cmt_p2p_netaddr_t *addr,
                               int64_t ban_ns);                         /* :355-362 */
void cmt_p2p_addrbook_reinstate_bad_peers(cmt_p2p_addrbook_t *a);       /* :366-389 */

/** addrbook.go:394-430 `GetSelection`. `out` holds at least
 *  CMT_P2P_AB_MAX_GET_SELECTION. @return the number written. */
int  cmt_p2p_addrbook_get_selection(cmt_p2p_addrbook_t *a,
                                    cmt_p2p_netaddr_t *out);
/** addrbook.go:444-474 `GetSelectionWithBias`. */
int  cmt_p2p_addrbook_get_selection_with_bias(cmt_p2p_addrbook_t *a,
                                              int bias_new,
                                              cmt_p2p_netaddr_t *out);

int  cmt_p2p_addrbook_size(const cmt_p2p_addrbook_t *a);                /* :479-488 */

/** addrbook.go:493-495 `Save` → file.go saveToFile. */
void cmt_p2p_addrbook_save(cmt_p2p_addrbook_t *a);

/* ══ R-P2P-4 accessors ════════════════════════════════════════════════ */

/** The signed record held for `id` (`payload ‖ sig`, CMT_P2P_ADDR_REC_SIZE
 *  bytes), or NULL. Valid until the next call that changes the book. */
const uint8_t *cmt_p2p_addrbook_record(const cmt_p2p_addrbook_t *a,
                                       const char *id, uint64_t *seq);

/** True when the host's `bonded_pubkey` answers for `id` (R-P2P-4; the
 *  PEX reactor does not gossip an unsigned address for such an ID). */
bool cmt_p2p_addrbook_is_bonded(const cmt_p2p_addrbook_t *a, const char *id);

/** The highest VERIFIED seq seen in a record naming `self_id`
 *  (file header). @return false if none was seen. */
bool cmt_p2p_addrbook_own_seq_seen(const cmt_p2p_addrbook_t *a,
                                   uint64_t *seq);

/** Red-team Z2-F11 — call after the host's bonded set changed: every
 *  UNSIGNED entry whose ID is bonded now is removed (a bonded identity
 *  keeps only a signed record, R-P2P-4 — a stale unsigned address would
 *  be dialed, fail and pile up attempts), and every ban on a bonded ID is
 *  lifted (`cmt_p2p_addrbook_mark_bad` never bans a bonded ID; a ban
 *  from before it bonded would refuse its signed record for the rest of
 *  the ban). No reference counterpart (no bonded set there).
 *  @return the number of entries removed or unbanned. */
int cmt_p2p_addrbook_purge_bonded_unsigned(cmt_p2p_addrbook_t *a);

/** At the highest own seq seen: was any record naming us there OTHER
 *  than `rec` (our own record's bytes)? True when the first one seen
 *  differs from `rec`, or two different ones were seen at that seq —
 *  someone else signs with our key (a reinstalled node). False when
 *  nothing was seen, or only `rec` itself came back (our record echoed
 *  by peers — no reason to re-sign; red-team M1). No reference
 *  counterpart: signed ADDR records are nodus's own (R-P2P-4). */
bool cmt_p2p_addrbook_own_seq_differs(const cmt_p2p_addrbook_t *a,
                                      const uint8_t rec[CMT_P2P_ADDR_REC_SIZE]);

/** Fill the switch's AddrBook seam (cmt_p2p_switch.h, R-P2P-31) with
 *  this book. The table's `ctx` is the book. */
void cmt_p2p_addrbook_switch_seam(cmt_p2p_addrbook_t *a,
                                  cmt_p2p_addr_book_t *out);

/* ══ exposed for tests (the reference's own tests reach them) ═════════ */

/** addrbook.go:833-857 `calcNewBucket`. @return the index or -1. */
int  cmt_p2p_addrbook_calc_new_bucket(const cmt_p2p_addrbook_t *a,
                                      const cmt_p2p_netaddr_t *addr,
                                      const cmt_p2p_netaddr_t *src);
/** addrbook.go:860-883 `calcOldBucket`. @return the index or -1. */
int  cmt_p2p_addrbook_calc_old_bucket(const cmt_p2p_addrbook_t *a,
                                      const cmt_p2p_netaddr_t *addr);
/** addrbook.go:893-941 `groupKeyFor`. @return length, 0 if too small. */
size_t cmt_p2p_addrbook_group_key(const cmt_p2p_netaddr_t *na, bool strict,
                                  char *out, size_t cap);
/** The entry for `id`: bucket type, its bucket indices (≤ 4). */
bool cmt_p2p_addrbook_entry(const cmt_p2p_addrbook_t *a, const char *id,
                            uint8_t *bucket_type, int *buckets, int *n_buckets,
                            int32_t *attempts);
/** `key` (CMT_P2P_AB_KEY_LEN hex characters + NUL). */
const char *cmt_p2p_addrbook_key(const cmt_p2p_addrbook_t *a);
/** nNew / nOld. */
void cmt_p2p_addrbook_counts(const cmt_p2p_addrbook_t *a, int *n_new,
                             int *n_old);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_ADDRBOOK_H */
