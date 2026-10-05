/**
 * @file nodus_witness_storage_segment.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the SEGMENT FILE: one file per payday segment k (heights
 *        (k−1)·17280+1 … k·17280) with its index and its completeness
 *        marker, built from verified pieces only (an export from this
 *        node's block store or a fetch from other nodes), published
 *        atomically, resumable after a restart, and read back to answer
 *        archive probes (0x72) and fetches (0x73) once the block store no
 *        longer has the blocks.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (reward = the block archive; R = 3; G = 1), 2026-10-05-
 * archive-reward-bytes-approved.md (bytes doc §6 chain, §7 file),
 * 2026-10-05-kurultay-7-archive-reward-summary.md (items 2, 4, 5: the
 * successor-header chain; segments are exported FILES and block-store
 * pruning is unchanged; every chunk verified before it is written),
 * 2026-10-03-block-pruning-7-paydays.md (its 2026-10-05 rollout change:
 * a storage node may prune only once this package is live). Design
 * docs/plans/2026-10-05-archive-reward-design.md rev 4 §3.
 *
 * ── DETERMINISM (design rev 4 §7 D4) ──────────────────────────────────
 * A segment file is NODE-LOCAL. Nothing here is read by the state
 * machine, by a root, by a vote or by replication; whether a file exists,
 * how far a build got and what a disk holds never change state. The only
 * consensus-fixed input is READ: `v2_blocks.block_id` (the ledger's
 * per-height header hash, never pruned) — every piece is verified against
 * it before it is written.
 *
 * ── THE FILES (in the segment directory, nodus_witness.h
 *    NODUS_SEG_DIR_DEFAULT under the witness data path) ────────────────
 *   seg-<k>.dat.tmp   the data file while it is built (export or fetch);
 *                     append-only, resumable
 *   seg-<k>.dat       the published data file
 *   seg-<k>.idx       its index
 *   seg-<k>.ok        the completeness marker — a segment is HELD iff
 *                     this marker exists and agrees with .dat and .idx
 *   (seg-<k>.idx.tmp, seg-<k>.ok.tmp: the atomic-publish temporaries)
 *   <k> is the decimal segment number without padding.
 * All integers big-endian. ⚠ NODE-LOCAL LAYOUT, NOT CONSENSUS: bytes doc
 * §7 says WHAT the file holds; the framing below is this package's.
 *
 *   DATA FILE  seg-<k>.dat
 *     "NDS.SEGFILE.v1" padded with 0x00 to 16 ‖ k u64 ‖ count u32 (17280)
 *                                                   — NODUS_SEG_DATA_HDR_LEN
 *     then for h = (k−1)·17280+1 … k·17280, in order, one HEIGHT RECORD:
 *       h u64 ‖ hdr_len u32 ‖ header(h+1) proto [hdr_len] ‖ n_parts u32 ‖
 *       n_parts × ( plen u32 ‖ the stored part proto [plen] )
 *       — "the stored part proto" is the block store's P:h:i value
 *       (cmt_pb_part: index, bytes, Merkle proof — "parts + proofs as
 *       stored", bytes doc §7); n_parts == header(h+1).last_block_id.
 *       part_set_header.total; parts in index order 0 … n_parts−1.
 *     then the TERMINAL COMMIT RECORD:
 *       clen u32 ‖ the commit of k·17280 as a cmt_pb_commit proto [clen]
 *       (block k·17280+1's LastCommit = the block store's C:k·17280).
 *     Each commit is stored once: the commits of the other heights travel
 *     inside the parts of their successor block (its LastCommit), never
 *     separately.
 *   ⚠ DEVIATION from bytes doc §7 (recorded, for the operator): §7 lists
 *     the part set per height and the terminal commit; each height record
 *     here ALSO carries header(h+1) — the SUCCESSOR header. The §6 chain
 *     authenticates block h's parts only through header(h+1) (whose hash
 *     is v2_blocks[h+1] and whose last_block_id names block h's part-set
 *     root), the 0x72 answer sends exactly header(h+1), and the terminal
 *     commit is checked against header(k·17280+1) — none of which a
 *     pruned block store still has. Each header is still stored once
 *     (header(h+1) for h+1 = (k−1)·17280+2 … k·17280+1).
 *
 *   INDEX FILE  seg-<k>.idx  (NODUS_SEG_INDEX_LEN bytes)
 *     "NDS.SEGINDEX.v1" padded to 16 ‖ k u64 ‖ count u32 (17280) ‖
 *     count × ( offset u64 ‖ n_parts u32 )  — offset of height record i
 *                                              in the data file ‖
 *     commit_off u64 ‖ commit_len u32 ‖ data_size u64
 *     One part is read without scanning the file: the entry gives the
 *     record, the record's own length prefixes give the part (at most
 *     n_parts four-byte reads).
 *
 *   COMPLETENESS MARKER  seg-<k>.ok  (NODUS_SEG_DONE_LEN bytes)
 *     "NDS.SEGDONE.v1" padded to 16 ‖ k u64 ‖ data_size u64 ‖
 *     index_size u64 ‖ flags u8 ‖ SHA3-512(the index file bytes) [64]
 *     flags bit 0 (NODUS_SEG_FLAG_SIGS): the terminal commit's signatures
 *     were verified (below); every other bit 0.
 *
 * ── WHAT IS VERIFIED BEFORE ANY BYTE IS WRITTEN (bytes doc §6 chain, the
 *    0x72 reporter's checks, nodus_witness_storage_probe.h "THE CHECKS")
 *   header(h+1): decodes; cmt_header_hash == v2_blocks[h+1]; height ==
 *     h+1; last_block_id.hash == v2_blocks[h]; part total 1 …
 *     CMT_PART_SET_MAX_PARTS with a 64-byte part-set hash.
 *   part i of h: decodes; part.index == proof.index == i; proof.total ==
 *     the header's total; the reference's Part.ValidateBasic; and
 *     cmt_proof_verify against that part-set hash.
 *   the terminal commit: decodes (CommitFromProto, which ends in
 *     ValidateBasic); height == k·17280; block_id ==
 *     header(k·17280+1).last_block_id; cmt_commit_hash ==
 *     header(k·17280+1).last_commit_hash — the HASH BINDING; then the
 *     SIGNATURES (Kurultay #7 item 2: "plus signature verification against
 *     the historical validator set") when this node's state store still
 *     has validators(k·17280): its cmt_validator_set_hash must equal
 *     header(k·17280).validators_hash (header(k·17280) is record k·17280−1's
 *     successor header) and cmt_verify_commit must accept the commit.
 *   ⚠ LIMIT (recorded): a node whose state store has pruned
 *     validators(k·17280) (nodus_cmt_ss_prune_states runs with block
 *     pruning, nodus_witness_cmt_host.c) cannot verify the signatures —
 *     the function exists, the authenticated validator set does not. Such
 *     a file completes on the hash binding alone and its marker carries
 *     flags bit 0 = 0, logged. Commit.Hash covers the signatures only
 *     (Kurultay #7 item 2): the hash binding fixes every signature byte,
 *     and height / block_id are checked above, but the commit's `round`
 *     is bound by nothing but the signatures.
 *   COMPLETE = every height verified and written, the terminal commit
 *     verified and written; only then the index and the marker
 *     (bytes doc §7 "Completeness").
 *
 * ── ATOMIC PUBLISH ─────────────────────────────────────────────────────
 *   fsync(seg-<k>.dat.tmp); write + fsync seg-<k>.idx.tmp;
 *   rename .dat.tmp → .dat; rename .idx.tmp → .idx; fsync(directory);
 *   write + fsync seg-<k>.ok.tmp; rename → .ok; fsync(directory).
 *   A crash before the marker leaves no .ok: the next build of k finds
 *   .dat without a marker, moves it back to .dat.tmp and RE-VERIFIES it
 *   (the resume scan below) — a half-published file is never "held".
 *
 * ── RESUME ─────────────────────────────────────────────────────────────
 *   Opening a build over an existing seg-<k>.dat.tmp scans it from the
 *   start in bounded steps, verifying every record exactly as it was
 *   verified when written; the first short, torn or failing record and
 *   everything after it is cut off (ftruncate) and the build continues
 *   from that height. Nothing is trusted because it is on disk.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_STORAGE_SEGMENT_H
#define NODUS_WITNESS_STORAGE_SEGMENT_H

#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_storage_probe.h"   /* the §6 bounds        */
#include "dnac/ledger_roots_v2.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_validator_set.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── layout constants ───────────────────────────────────────────────── */

#define NODUS_SEG_TAG_LEN        16u
#define NODUS_SEG_FILE_TAG       "NDS.SEGFILE.v1"
#define NODUS_SEG_INDEX_TAG      "NDS.SEGINDEX.v1"
#define NODUS_SEG_DONE_TAG       "NDS.SEGDONE.v1"

/** Heights per segment: the consensus constant (bytes doc item 1). */
#define NODUS_SEG_COUNT          ((uint32_t)DNA_V2_SEGMENT_BLOCKS)

/** tag ‖ k ‖ count. */
#define NODUS_SEG_DATA_HDR_LEN   (16u + 8u + 4u)
/** One index entry: offset u64 ‖ n_parts u32. */
#define NODUS_SEG_INDEX_ENTRY_LEN 12u
/** tag ‖ k ‖ count ‖ entries ‖ commit_off ‖ commit_len ‖ data_size. */
#define NODUS_SEG_INDEX_LEN      (16u + 8u + 4u +                            \
                                  NODUS_SEG_COUNT * NODUS_SEG_INDEX_ENTRY_LEN \
                                  + 8u + 4u + 8u)
/** tag ‖ k ‖ data_size ‖ index_size ‖ flags ‖ SHA3-512(index). */
#define NODUS_SEG_DONE_LEN       (16u + 8u + 8u + 8u + 1u + 64u)
/** Marker flag: the terminal commit's signatures were verified. */
#define NODUS_SEG_FLAG_SIGS      0x01u

/** The widest header(h+1) proto (the 0x72 bound). */
#define NODUS_SEG_HEADER_MAX     NODUS_STPROBE_HEADER_MAX
/** The widest stored part proto: index varint, the part bytes and the
 *  proof message, each with its tag and length — under the part, the
 *  0x72 proof bound and 64 bytes of framing. */
#define NODUS_SEG_PART_PROTO_MAX (CMT_BLOCK_PART_SIZE_BYTES +                \
                                  NODUS_STPROBE_PROOF_MAX + 64u)
/** The widest terminal commit: the reference's MaxCommitBytes at the
 *  largest validator set this port holds (cmt_block.h
 *  CMT_MAX_COMMIT_OVERHEAD_BYTES + CMT_VALSET_MAX ×
 *  CMT_MAX_COMMIT_SIG_BYTES = 599 839 bytes). */
#define NODUS_SEG_COMMIT_MAX     ((uint32_t)(CMT_MAX_COMMIT_OVERHEAD_BYTES + \
                                  (int64_t)CMT_VALSET_MAX *                  \
                                  CMT_MAX_COMMIT_SIG_BYTES))

/** The segment directory's file name length bound. */
#define NODUS_SEG_PATH_MAX       512u

_Static_assert(NODUS_SEG_INDEX_LEN == 207408u, "index layout");
_Static_assert(NODUS_SEG_DONE_LEN == 105u, "marker layout");
_Static_assert(NODUS_SEG_COMMIT_MAX == 599839u, "MaxCommitBytes(128)");

/* ── what a piece's verification says ───────────────────────────────── */

typedef enum {
    NODUS_SEG_V_OK = 0,
    NODUS_SEG_V_ORDER,          /* not the piece the build needs next     */
    NODUS_SEG_V_BOUNDS,         /* a length outside its bound             */
    NODUS_SEG_V_NO_LEDGER,      /* v2_blocks has no 64-byte row at h/h+1  */
    NODUS_SEG_V_HEADER_DECODE,
    NODUS_SEG_V_HEADER_HASH,    /* != v2_blocks[h+1]                      */
    NODUS_SEG_V_HEADER_HEIGHT,  /* != h+1                                 */
    NODUS_SEG_V_BLOCK_ID,       /* last_block_id.hash != v2_blocks[h]     */
    NODUS_SEG_V_PART_TOTAL,     /* 0 / above the cap / no 64-byte root    */
    NODUS_SEG_V_PART_DECODE,    /* the part proto does not decode         */
    NODUS_SEG_V_PART_INDEX,     /* part / proof index != the one needed   */
    NODUS_SEG_V_PROOF_TOTAL,    /* proof.total != the header's total      */
    NODUS_SEG_V_PART_BASIC,     /* Part.ValidateBasic refused             */
    NODUS_SEG_V_PROOF,          /* the Merkle proof does not hold         */
    NODUS_SEG_V_COMMIT_DECODE,  /* does not decode / ValidateBasic        */
    NODUS_SEG_V_COMMIT_HEIGHT,  /* != k·17280                             */
    NODUS_SEG_V_COMMIT_BLOCK_ID,/* != header(k·P+1).last_block_id         */
    NODUS_SEG_V_COMMIT_HASH,    /* != header(k·P+1).last_commit_hash      */
    NODUS_SEG_V_COMMIT_VALSET,  /* stored validators(k·P) do not hash to
                                 * header(k·P).validators_hash            */
    NODUS_SEG_V_COMMIT_SIGS,    /* cmt_verify_commit refused              */
    NODUS_SEG_V_IO,             /* the file could not be written / read   */
    NODUS_SEG_V_FAULT           /* allocation / hash backend / NULL       */
} nodus_seg_v_t;

/** A short name for logs. Never NULL. */
const char *nodus_seg_v_str(nodus_seg_v_t v);

/* ── paths ──────────────────────────────────────────────────────────── */

typedef enum {
    NODUS_SEG_F_DAT_TMP = 0,
    NODUS_SEG_F_DAT,
    NODUS_SEG_F_IDX_TMP,
    NODUS_SEG_F_IDX,
    NODUS_SEG_F_OK_TMP,
    NODUS_SEG_F_OK
} nodus_seg_file_t;

/** `dir`/seg-<k>.<suffix>. @return 0 / -1 (does not fit, NULL, k == 0). */
int nodus_seg_path(const char *dir, uint64_t k, nodus_seg_file_t which,
                   char *out, size_t cap);

/** Parse a directory entry name: "seg-<k>.<one of the six suffixes>".
 *  @return 0 (*k_out) / -1 (any other name). */
int nodus_seg_name_parse(const char *name, uint64_t *k_out);

/** Create `dir` (one level, mode 0700) when it does not exist.
 *  @return 0 / -1. */
int nodus_seg_dir_ensure(const char *dir);

/** The segment of height h >= 1: (h − 1) / 17280 + 1. */
uint64_t nodus_seg_of_height(uint64_t h);

/* ── building a segment ─────────────────────────────────────────────── */

typedef struct nodus_seg_build nodus_seg_build_t;

/**
 * Open the build of segment k in `dir`, reading the ledger hashes from
 * `ledger` (the witness database: SELECT block_id FROM v2_blocks). A
 * published .dat without a valid marker is moved back to .dat.tmp first
 * (header "ATOMIC PUBLISH"); an existing .dat.tmp is resumed — run
 * nodus_seg_build_resume_step until it returns 1 before adding pieces. A
 * .dat.tmp whose data header names another k or count is started over.
 * *out is heap (nodus_seg_build_free).
 * @return 0 / -1 (the segment is already held — nothing is touched —,
 *         I/O, NULL).
 */
int nodus_seg_build_open(const char *dir, uint64_t k, sqlite3 *ledger,
                         nodus_seg_build_t **out);

/** Close the build. The .dat.tmp stays (resumable). NULL-safe. */
void nodus_seg_build_free(nodus_seg_build_t *b);

/** Close the build and delete its temporaries. NULL-safe. */
void nodus_seg_build_discard(nodus_seg_build_t *b);

/** The segment number of the build. */
uint64_t nodus_seg_build_k(const nodus_seg_build_t *b);

/**
 * One bounded step of the resume scan: verifies up to `max_heights`
 * height records of the existing .dat.tmp (and the commit record after
 * the last height), cutting the file at the first record that is short
 * or fails. @return 1 the scan is over (pieces may be added), 0 more to
 * scan, -1 fault (I/O, a ledger read fault). A build opened over no
 * temporary returns 1 at once.
 */
int nodus_seg_build_resume_step(nodus_seg_build_t *b, uint32_t max_heights);

/** What the build needs next. `*h_out` the height; `*part_out` the part
 *  index, or NODUS_SEG_PART_COMMIT for the terminal commit (then *h_out
 *  = k·17280); `*header_needed` true when header(h+1) is not yet held
 *  for that height (a part can only be added after its header).
 *  @return 0 something is needed / 1 the build is complete (call
 *  nodus_seg_build_finish) / -1 the resume scan is not over or NULL. */
#define NODUS_SEG_PART_COMMIT    0xFFFFFFFFu
int nodus_seg_build_next(const nodus_seg_build_t *b, uint64_t *h_out,
                         uint32_t *part_out, bool *header_needed);

/** The verified header(h+1) proto of the height the build is on, so a
 *  fetch can resume a block whose header it already holds. @return 0
 *  (*hdr, *len point into the build) / -1 none held. */
int nodus_seg_build_cur_header(const nodus_seg_build_t *b,
                               const uint8_t **hdr, size_t *len);

/** Add header(h+1) for the height the build is on (header "WHAT IS
 *  VERIFIED"); written with the record's prefix only when it verifies. */
nodus_seg_v_t nodus_seg_build_put_header(nodus_seg_build_t *b, uint64_t h,
                                         const uint8_t *hdr, size_t len);

/** Add part `i` of height h as the STORED part proto (the export form). */
nodus_seg_v_t nodus_seg_build_put_part_proto(nodus_seg_build_t *b,
                                             uint64_t h, uint32_t i,
                                             const uint8_t *proto,
                                             size_t len);

/** Add part `i` of height h as part bytes + proof proto (the 0x72 / 0x73
 *  wire form); verified, then written as the stored part proto. */
nodus_seg_v_t nodus_seg_build_put_part(nodus_seg_build_t *b, uint64_t h,
                                       uint32_t i,
                                       const uint8_t *part, size_t part_len,
                                       const uint8_t *proof,
                                       size_t proof_len);

/**
 * Add the terminal commit (a cmt_pb_commit proto). `state` is this
 * node's cmt store for the signature check (header "WHAT IS VERIFIED");
 * NULL, or a store without validators(k·17280), completes on the hash
 * binding alone (flags bit 0 = 0, logged).
 */
nodus_seg_v_t nodus_seg_build_put_commit(nodus_seg_build_t *b,
                                         const uint8_t *commit, size_t len,
                                         nodus_cmt_store_t *state);

/** Publish a complete build atomically (header "ATOMIC PUBLISH") and
 *  close it. On success the build is freed and the segment is held.
 *  @return 0 / -1 (not complete, I/O — the build stays open). */
int nodus_seg_build_finish(nodus_seg_build_t *b);

/* ── reading a held segment ─────────────────────────────────────────── */

typedef struct nodus_seg_reader nodus_seg_reader_t;

/**
 * Open the HELD segment k of `dir`: the marker parses, names k, matches
 * the .dat and .idx sizes, and SHA3-512 of the index equals the marker's;
 * the index names k, 17280 heights and the data size. *out is heap.
 * @return 0 held / 1 not held (no marker, or a marker that does not
 *         agree — the segment is treated as absent) / -1 fault.
 */
int nodus_seg_reader_open(const char *dir, uint64_t k,
                          nodus_seg_reader_t **out);
void nodus_seg_reader_close(nodus_seg_reader_t *r);

/** 1 held / 0 not / -1 fault (nodus_seg_reader_open's rule). */
int nodus_seg_held(const char *dir, uint64_t k);

/** The marker flags of an open reader. */
uint8_t nodus_seg_reader_flags(const nodus_seg_reader_t *r);

/**
 * Height h of the open segment: header(h+1) into `hdr` (cap >=
 * NODUS_SEG_HEADER_MAX, may be NULL), the part count, and when `part_i`
 * < the count and `part` is not NULL the stored part proto of part
 * `part_i` (cap >= NODUS_SEG_PART_PROTO_MAX).
 * @return 0 / 1 (h outside the segment, part_i >= the count) / -1 I/O
 *         or a record that does not match its index.
 */
int nodus_seg_reader_get(nodus_seg_reader_t *r, uint64_t h,
                         uint8_t *hdr, size_t *hdr_len,
                         uint32_t *n_parts, uint32_t part_i,
                         uint8_t *part, size_t *part_len);

/** The terminal commit proto into `out` (cap >= NODUS_SEG_COMMIT_MAX).
 *  @return 0 / -1. */
int nodus_seg_reader_commit(nodus_seg_reader_t *r, uint8_t *out, size_t cap,
                            size_t *len);

/* ── helpers shared with the wire ───────────────────────────────────── */

/** Split a stored part proto into the part bytes and its marshalled
 *  proof (the 0x72 / 0x73 wire form). `part_out` cap >=
 *  CMT_BLOCK_PART_SIZE_BYTES, `proof_out` cap >= NODUS_STPROBE_PROOF_MAX.
 *  @return 0 / -1 (does not decode, does not fit). */
int nodus_seg_part_split(const uint8_t *proto, size_t len,
                         uint8_t *part_out, size_t *part_len,
                         uint8_t *proof_out, size_t *proof_len,
                         uint32_t *index_out);

/** Delete every file of segment k in `dir` (the marker first, so the
 *  segment stops being held before its data goes), then fsync the
 *  directory. Absent files are not an error. @return 0 / -1. */
int nodus_seg_delete(const char *dir, uint64_t k);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_STORAGE_SEGMENT_H */
