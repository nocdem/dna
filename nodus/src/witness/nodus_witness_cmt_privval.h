/**
 * @file nodus/src/witness/nodus_witness_cmt_privval.h
 * @brief cometbft @709fd12b `privval/file.go`'s FILE side for the
 *        last-sign state — `FilePVLastSignState.Save` (:135-147) over
 *        `libs/tempfile.WriteFileAtomic` (:76-129), the state half of
 *        `loadFilePV` (:198-233), and the `libs/json` shape of the file.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W1, package R3-B. Nothing in the running chain calls
 * anything here; R3-C2 binds `nodus_cmt_privval_save_lss` into the
 * `cmt_file_pv_t.save_last_sign_state` row.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE IS ──────────────────────────────────────────────────
 * `shared/dnac/cmt_privval.h` holds the double-sign guard in memory and
 * leaves ONE host callback that must be DURABLE before it returns:
 * `save_last_sign_state` (cmt_privval.h:220). This module is that
 * callback, ported from the reference's own file code:
 *
 *   · the JSON the reference writes — `cmtjson.MarshalIndent(lss, "",
 *     "  ")` (file.go:140) under libs/json's rules: an int64 is a QUOTED
 *     decimal string (encoder.go:107), int32/int8 are bare numbers
 *     (encoder.go:114 → stdlib), a `[]byte` is a base64 string
 *     (encoder.go:124-133 → stdlib), `HexBytes` is an UPPER-CASE hex
 *     string (libs/bytes/bytes.go:24-31), `omitempty` drops a nil slice
 *     (encoder.go:189, structs.go:78), and `json.Indent` (encoder.go:38)
 *     lays the members out one per line with a two-space indent;
 *   · the write — `tempfile.WriteFileAtomic` (tempfile.go:76-129): a
 *     temp name `write-file-atomic-<lcg>` in the target's directory,
 *     `O_WRONLY|O_CREAT|O_SYNC|O_TRUNC|O_EXCL` mode 0600 (:30, file.go:142),
 *     the whole payload, close, `rename` over the target;
 *   · the read — `loadFilePV`'s state half (file.go:213-224): the file
 *     is read and parsed with `cmtjson.Unmarshal` (decoder.go), or an
 *     empty state is used (`LoadFilePVEmptyState`, :193-195).
 *
 * ── DEVIATION R3-B-1 (operator ruling S23, 2026-09-11) ─────────────────
 * After the `rename` the DIRECTORY is fsync'd. The reference's `O_SYNC`
 * makes the file's DATA durable (tempfile.go:27-30) but a rename is a
 * directory-entry change, and POSIX does not promise that the new entry
 * has reached the disk until the directory itself is synced. Without it
 * a power loss after "the signature left the node" can bring the node
 * back with the PREVIOUS last-sign state, which is precisely the
 * double-sign window `cmt_privval.h` exists to close. This is a
 * strengthening: every byte the reference writes is written, in the same
 * order, and one more fsync follows.
 *
 * ── NOT PORTED ─────────────────────────────────────────────────────────
 * `FilePVKey` and its `Save` (file.go:47-70): the KEY file. The
 * reference keeps an ed25519 private key in a JSON file; under the PQ
 * POLICY (atlas-dec-652be084b95d02d253834906271e9fb0) a classical
 * primitive met in the reference is reported, not ported, and the
 * ML-DSA-87 key lives where Nodus keeps it today (nodus_witness.c) —
 * the `raw_sign` row is R3-C2's binding. `LoadOrGenFilePV` (:237-246)
 * decides on the KEY file's existence and is therefore R3-C2's as well.
 * `GenFilePV` (:180-183) generates an ed25519 key — not ported.
 *
 * ── THE ONE NON-`now` SOURCE ───────────────────────────────────────────
 * `writeFileRandReseed` (tempfile.go:38-47) seeds the temp-name LCG from
 * `time.Now().UnixNano() + int64(os.Getpid()<<20)`. The clock is the
 * host's `cmt_now_fn` (the APPROVED clock POLICY's one clock); the pid
 * is `getpid()`, read here and nowhere else in the port. Neither value
 * reaches consensus: they name a temporary file that is renamed away.
 *
 * ── JSON DECODER LIMITS (deviations, recorded) ─────────────────────────
 * The file is written only by this node, by the encoder below. The
 * decoder ports libs/json's observable rules for this ONE struct:
 * whitespace (space, tab, CR, LF) anywhere a JSON grammar allows it;
 * unknown keys ignored (decoder.go:184-198 reads the object into a map
 * and looks up the five names); a later duplicate key wins (Go map);
 * `null` → the zero value (decoder.go:44-47); `height` must be a quoted
 * decimal (decoder.go:88-93); `round`/`step` bare integers in range;
 * `signature` standard padded base64, an EMPTY result becoming nil
 * (decoder.go:129-132); `signbytes` hex of either case, an empty string
 * becoming an empty NON-nil slice (bytes.go:34-44 — `hex.DecodeString("")`
 * is `[]byte{}`). Departures, all refusals of input this node never
 * writes: a backslash escape inside one of the five known values is
 * refused (stdlib would decode it); a document larger than
 * NODUS_CMT_LSS_FILE_MAX bytes is refused (stdlib reads any size); a
 * signature or sign-bytes value longer than `cmt_lss_t`'s fixed
 * capacity (CMT_MAX_SIGNATURE_SIZE, CMT_PV_SIGN_BYTES_MAX) is refused
 * (Go's slices are unbounded).
 */

#ifndef NODUS_WITNESS_CMT_PRIVVAL_H
#define NODUS_WITNESS_CMT_PRIVVAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#include "dnac/cmt_tmhash.h"     /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "dnac/cmt_time.h"       /* cmt_now_fn                      */
#include "dnac/cmt_privval.h"    /* cmt_lss_t, cmt_pv_save_lss_fn   */

#ifdef __cplusplus
extern "C" {
#endif

/** Upper bound on the JSON this module writes: the five members with a
 *  4627-byte signature (6172 base64 chars) and 256 sign bytes (512 hex
 *  chars), indented. Measured shape, rounded up. */
#define NODUS_CMT_LSS_JSON_MAX   8192u

/** Upper bound on a state file this module will READ (see the header). */
#define NODUS_CMT_LSS_FILE_MAX   (1024u * 1024u)

/** tempfile.go:16 `atomicWriteFilePrefix`. */
#define NODUS_CMT_ATOMIC_WRITE_FILE_PREFIX "write-file-atomic-"

/**
 * The file side of one `FilePV` (file.go:157-160): `lss.filePath`
 * (:82) and the process-wide temp-name LCG state of tempfile.go:33-36,
 * held per context because there is one FilePV per node.
 */
typedef struct {
    char      *state_path;              /* file.go:82 `filePath`, OWNED   */
    cmt_now_fn now;                     /* tempfile.go:46 `time.Now()`    */
    void      *now_ctx;
    uint64_t   atomic_write_file_rand;  /* tempfile.go:34, 0 = unseeded   */
} nodus_cmt_privval_t;

/**
 * `loadFilePV`'s STATE half (file.go:211-224) — `LoadFilePV` (:187-189)
 * when `load_state` is true, `LoadFilePVEmptyState` (:193-195) when it is
 * false. Binds `state_file_path` as `lss.filePath` (:224).
 *
 * @param out_lss receives the loaded (or empty, :211) last-sign state.
 * @return CMT_OK; CMT_FAULT for the reference's `cmtos.Exit` at :216
 *         (file unreadable) and :220 (JSON rejected) — this node's own
 *         disk contradicting itself, never a peer.
 */
int nodus_cmt_privval_open(nodus_cmt_privval_t *ctx,
                           const char *state_file_path,
                           cmt_now_fn now, void *now_ctx,
                           bool load_state, cmt_lss_t *out_lss);

/** Releases the path; the context is reusable after another open. */
void nodus_cmt_privval_close(nodus_cmt_privval_t *ctx);

/**
 * `(lss *FilePVLastSignState) Save()` — file.go:135-147 — as a
 * `cmt_pv_save_lss_fn` row (`ctx` is a `nodus_cmt_privval_t *`).
 * MarshalIndent (:140) then WriteFileAtomic (:144) at perm 0600, plus
 * DEVIATION R3-B-1 (directory fsync).
 * @return CMT_OK once the file AND its directory entry are durable;
 *         CMT_FAULT for any of the reference's panics (:137, :142, :146).
 */
int nodus_cmt_privval_save_lss(void *ctx, const cmt_lss_t *lss);

/**
 * `cmtjson.Marshal(lss)` (encoder.go:22-29) — the compact form,
 * `{"height":"1","round":1,"step":1}` for file_test.go:82-105's vector.
 * @return CMT_OK, CMT_FAULT if `cap` is too small or on NULL.
 */
int nodus_cmt_lss_marshal(const cmt_lss_t *lss, char *out, size_t cap,
                          size_t *out_len);

/**
 * `cmtjson.MarshalIndent(lss, "", "  ")` (encoder.go:32-43): the compact
 * form passed through `json.Indent` — one member per line, two-space
 * indent, a space after each colon, no trailing newline.
 * @return CMT_OK, CMT_FAULT if `cap` is too small or on NULL.
 */
int nodus_cmt_lss_marshal_indent(const cmt_lss_t *lss, char *out,
                                 size_t cap, size_t *out_len);

/**
 * `cmtjson.Unmarshal(bz, &lss)` (decoder.go:13-36) for
 * `FilePVLastSignState` under the rules in the header.
 * @return CMT_OK; CMT_REJECT for anything the reference's decoder would
 *         return an error for (the caller maps it: at load time that is
 *         :220's Exit → CMT_FAULT); CMT_FAULT on NULL.
 */
int nodus_cmt_lss_unmarshal(const uint8_t *in, size_t len, cmt_lss_t *out);

/**
 * `tempfile.WriteFileAtomic(filename, data, perm)` (tempfile.go:76-129)
 * plus DEVIATION R3-B-1. `ctx` supplies the LCG state and the clock.
 * @return CMT_OK; CMT_FAULT for every error return of the reference
 *         (:107, :112, :120, :122, :128) and for a failed directory sync.
 */
int nodus_cmt_write_file_atomic(nodus_cmt_privval_t *ctx,
                                const char *filename,
                                const uint8_t *data, size_t len,
                                mode_t perm);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_PRIVVAL_H */
