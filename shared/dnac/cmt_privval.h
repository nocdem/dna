/**
 * @file shared/dnac/cmt_privval.h
 * @brief cometbft @709fd12b `privval/file.go`'s SIGNING LOGIC in C — the
 *        double-sign guard, without the two JSON files.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything here yet; additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE IS ──────────────────────────────────────────────────
 * THE ONE THING THAT STOPS A VALIDATOR SIGNING TWICE AT ONE HEIGHT. It is
 * the last-sign state (height, round, step, the signature and the exact
 * bytes that were signed) and the rules that read it:
 *   · `CheckHRS` refuses a regression and reports when the last signature
 *     may be reused;
 *   · `signVote` / `signProposal` reuse it when the sign bytes are
 *     identical, and reuse it WITH THE OLD TIMESTAMP when the two differ
 *     only in that field — the crash-after-signing case;
 *   · `saveSigned` records the new one before the signature leaves.
 *
 * D-15 rev 5 names this module as the reason a replayed WAL cannot double
 * sign: the reference relies on this state, not on a replay rule
 * (atlas-dec-c0bfc5344204b9282ceaaa5e06042350).
 *
 * ── HOST BOUNDARY ──────────────────────────────────────────────────────
 * The reference reads and writes two JSON files. This port holds the state
 * in memory and gives the host three callbacks:
 *   · `raw_sign` — `pv.Key.PrivKey.Sign(signBytes)` (file.go:328, :359,
 *     :403). The private key never enters this module.
 *   · `save_last_sign_state` — `lss.Save()` (file.go:421), reached through
 *     `saveSigned`. IT MUST BE DURABLE BEFORE IT RETURNS: the reference
 *     writes the file atomically (:135-155) precisely so a crash between
 *     signing and using the signature cannot lose it. A host that returns
 *     before the write is durable has removed the guarantee this module
 *     exists for.
 *   · `now` — `cmttime.Now()` at :441 and :461, the single clock callback
 *     of the APPROVED clock POLICY. The reference reads the clock there
 *     only to put the SAME value in both timestamps before comparing, so
 *     the comparison ignores them; the call is kept because the port is
 *     literal, and its value never reaches a signature.
 *
 * taşınmadı, with the reason — all of it file I/O or construction:
 *   `FilePVKey.Save` (:56-70), `FilePVLastSignState.Save` (:135-155),
 *   `NewFilePV` (:163-176), `GenFilePV` (:180-183),
 *   `LoadFilePV` (:187-189), `LoadFilePVEmptyState` (:193-195),
 *   `loadFilePV` (:198-233), `LoadOrGenFilePV` (:237-246),
 *   `GetAddress` (:250-252), `(pv *FilePV) Save` (:279-282), `Reset`
 *   (:286-289), `String` (:292-300).
 *   `GetPubKey` (:256-258) is the stored `pub_key` field.
 *
 * ── SUBSTITUTIONS ──────────────────────────────────────────────────────
 * ML-DSA-87 signatures (4627 B) and public keys (2592 B); a 32-byte
 * address; a 32-byte chain id; Go panics become CMT_REJECT or CMT_FAULT,
 * each named at its site. `bytes.Equal` and `proto.Equal` become an
 * explicit byte comparison and an explicit field comparison.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Given the same last-sign state and the same vote, every function here
 * takes the same branch on every node. The clock is read at exactly the
 * two reference sites and its value is discarded — it can change no
 * decision and no byte. The signature itself comes from the host.
 *
 * ⚠ ML-DSA-87 SIGNATURES ARE NOT DETERMINISTIC unless the host's signer
 * makes them so; nothing here assumes they are. The reuse rules compare
 * SIGN BYTES, never signatures.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   privval/file.go       466 lines
 *                         e685aed7ac222738f8f623fe2d5e8a7132aeefad3e4cdc909cd1168e6012db98
 *   libs/protoio/reader.go 107 lines — NOT in any pin table; opened for
 *                         `UnmarshalDelimited` (:104-107) and `ReadMsg`
 *                         (:67-95), SHA-256
 *                         fc5f95050b989b238a34e84b332e841b424654929e19f1be2bf000b334a27c0d
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-15 rev 5 (atlas-dec-c0bfc5344204b9282ceaaa5e06042350, PROPOSED),
 * D-16 rev 4 (atlas-dec-0c86593601db977cd5af648b78910004),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PRIVVAL_H
#define SHARED_DNAC_CMT_PRIVVAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_time.h"
#include "cmt_block.h"      /* CMT_ADDRESS_SIZE, CMT_MAX_SIGNATURE_SIZE */
#include "cmt_vote.h"       /* CMT_VOTE_SIGN_BYTES_MAX, cmt_sign_vote_fn */
#include "cmt_proposal.h"   /* CMT_PROPOSAL_SIGN_BYTES_MAX               */

#ifdef __cplusplus
extern "C" {
#endif

/* ── the four steps ─────────────────────────────────────────────────── */

/** cometbft@709fd12b privval/file.go:26 — `stepNone`. */
#define CMT_STEP_NONE      ((int8_t)0)
/** privval/file.go:27 — `stepPropose`. */
#define CMT_STEP_PROPOSE   ((int8_t)1)
/** privval/file.go:28 — `stepPrevote`. */
#define CMT_STEP_PREVOTE   ((int8_t)2)
/** privval/file.go:29 — `stepPrecommit`. */
#define CMT_STEP_PRECOMMIT ((int8_t)3)

/**
 * The widest sign bytes this module ever stores: a vote's or a proposal's.
 * Both are 256 in this port (cmt_vote.h, cmt_proposal.h) and the assert
 * below keeps this definition tied to them rather than to a literal.
 */
#define CMT_PV_SIGN_BYTES_MAX CMT_PROPOSAL_SIGN_BYTES_MAX

_Static_assert((int)CMT_PV_SIGN_BYTES_MAX >= (int)CMT_VOTE_SIGN_BYTES_MAX,
               "last-sign-state buffer must hold a vote's sign bytes");
_Static_assert((int)CMT_PV_SIGN_BYTES_MAX >=
                   (int)CMT_PROPOSAL_SIGN_BYTES_MAX,
               "last-sign-state buffer must hold a proposal's sign bytes");

/**
 * cometbft@709fd12b privval/file.go:33-42 — `voteToStep()`.
 *
 * The reference PANICS on any type that is neither a prevote nor a
 * precommit (:40). CMT_FAULT here, under the panic rule
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8 rev 4): the vote a signer
 * is given is built by this node's own state machine
 * (consensus/state.go:2385-2392), and all ten callers of `signAddVote`
 * pass a literal vote type, so a third type is a broken node-local
 * invariant and never a peer's message. The one caller that could carry a
 * foreign vote — the remote signer, privval/signer_requestHandler.go:56 —
 * is excluded from this port by pin rev 6.
 *
 * @return CMT_OK, CMT_FAULT (:39-41, and on NULL).
 */
int cmt_vote_to_step(const cmt_pb_vote_t *vote, int8_t *out);

/* ── the mutable state ──────────────────────────────────────────────── */

/**
 * cometbft@709fd12b privval/file.go:75-83 —
 * `type FilePVLastSignState struct`, minus its `filePath`.
 *
 * `has_signature` and `has_sign_bytes` are Go's nil-versus-set slices, and
 * they are NOT cosmetic: `CheckHRS` tests `lss.SignBytes != nil` at :121
 * and `lss.Signature == nil` at :122, and `reset` sets both to nil
 * (:89-90). A zero length is not the same state as absent.
 */
typedef struct {
    int64_t height;                                  /* file.go:76 */
    int32_t round;                                   /* :77        */
    int8_t  step;                                    /* :78        */
    bool    has_signature;                           /* :79 nil?   */
    uint8_t signature[CMT_MAX_SIGNATURE_SIZE];
    size_t  signature_len;
    bool    has_sign_bytes;                          /* :80 nil?   */
    uint8_t sign_bytes[CMT_PV_SIGN_BYTES_MAX];
    size_t  sign_bytes_len;
} cmt_lss_t;

/** cometbft@709fd12b privval/file.go:85-91 —
 *  `(lss *FilePVLastSignState) reset()`.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_lss_reset(cmt_lss_t *lss);

/**
 * cometbft@709fd12b privval/file.go:100-132 —
 * `(lss *FilePVLastSignState) CheckHRS()`.
 *
 * Refuses a regression in height (:102-104), round (:107-109) or step
 * (:112-119); at an exact match it reports whether the last signature may
 * be reused (:120-128).
 *
 * @param out_same_hrs true when the HRS matches AND SignBytes is set, i.e.
 *        "we already signed this; reuse the signature" (:125).
 * @return CMT_OK; CMT_REJECT for a regression (:103, :108, :113) and for
 *         the "no SignBytes found" case of :127; CMT_FAULT for the
 *         reference's PANIC at :123 (SignBytes set but Signature nil) —
 *         that is this node's own state contradicting itself, not
 *         anything a peer can cause, and it MUST stop the node rather than
 *         be answered.
 */
int cmt_lss_check_hrs(const cmt_lss_t *lss, int64_t height, int32_t round,
                      int8_t step, bool *out_same_hrs);

/* ── host callbacks ─────────────────────────────────────────────────── */

/**
 * `pv.Key.PrivKey.Sign(signBytes)` — cometbft@709fd12b privval/file.go:328,
 * :359 and :403.
 *
 * @param sign_bytes the exact bytes to sign; `len` at most
 *        CMT_PV_SIGN_BYTES_MAX for a vote or proposal, more for a vote
 *        extension (which is unbounded application data).
 * @param sig_out receives the signature.
 * @param sig_len receives its length, at most CMT_MAX_SIGNATURE_SIZE.
 * @return CMT_OK, or any other value, which is passed through as the
 *         reference passes its error through (:329-331, :360-362,
 *         :404-406).
 */
typedef int (*cmt_pv_raw_sign_fn)(void *ctx, const uint8_t *sign_bytes,
                                  size_t len,
                                  uint8_t sig_out[CMT_MAX_SIGNATURE_SIZE],
                                  size_t *sig_len);

/**
 * `pv.LastSignState.Save()` — cometbft@709fd12b privval/file.go:421,
 * reached from `saveSigned`.
 *
 * MUST BE DURABLE BEFORE IT RETURNS — see the file header.
 * @return CMT_OK, or CMT_FAULT if the state could not be made durable, in
 *         which case the signature MUST NOT be used. The reference panics
 *         inside `Save` (:138, :142, :146) rather than returning.
 */
typedef int (*cmt_pv_save_lss_fn)(void *ctx, const cmt_lss_t *lss);

/**
 * cometbft@709fd12b privval/file.go:157-160 — `type FilePV struct`, with
 * `FilePVKey` (:47-53) flattened into it and the private key replaced by
 * the signing callback.
 */
typedef struct {
    uint8_t            address[CMT_ADDRESS_SIZE];    /* file.go:48 */
    uint8_t            pub_key[CMT_PB_PUBKEY_LEN];   /* :49        */
    cmt_lss_t          last_sign_state;              /* :159       */

    cmt_pv_raw_sign_fn raw_sign;                     /* :50 PrivKey */
    void              *sign_ctx;
    cmt_pv_save_lss_fn save_last_sign_state;         /* :421        */
    void              *save_ctx;
    cmt_now_fn         now;                          /* :441, :461  */
    void              *now_ctx;
} cmt_file_pv_t;

/**
 * cometbft@709fd12b privval/file.go:256-258 —
 * `(pv *FilePV) GetPubKey()`. The stored key; the reference's error return
 * has no C counterpart because there is nothing here that can fail.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_pv_get_pub_key(const cmt_file_pv_t *pv,
                       uint8_t out[CMT_PB_PUBKEY_LEN]);

/* ── signing ────────────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b privval/file.go:308-368 —
 * `(pv *FilePV) signVote()`.
 *
 * The walk, line by line: `voteToStep` (:309); `CheckHRS` (:313-316);
 * `VoteSignBytes` (:318); the extension signature, which is ALWAYS re-made
 * for a non-nil precommit and refused for anything else that carries an
 * extension (:325-334); then either the same-HRS reuse path (:341-356) or
 * a fresh signature followed by `saveSigned` (:359-365).
 *
 * ⚠ THE ORDER AT :353 IS THE REFERENCE'S AND IT MATTERS: on the reuse
 * path the extension signature is written into the vote even when the
 * branch is about to return the "conflicting data" error.
 *
 * @param chain_id 32 raw bytes (the substitution).
 * @param vote modified in place: `signature`, `extension_signature` and,
 *        on the timestamp-only branch, `timestamp` (:347).
 * @return CMT_OK; CMT_REJECT for "conflicting data" (:350), for the
 *         unexpected-extension case (:332-333) and for a CheckHRS
 *         regression; CMT_FAULT on NULL, on `cmt_vote_to_step`'s fail-stop
 *         (:39-41), on CheckHRS's panic case, or when
 *         `save_last_sign_state` fails; otherwise whatever `raw_sign`
 *         returned.
 */
int cmt_pv_sign_vote(cmt_file_pv_t *pv, const uint8_t *chain_id,
                     size_t chain_id_len, cmt_pb_vote_t *vote);

/**
 * cometbft@709fd12b privval/file.go:373-410 —
 * `(pv *FilePV) signProposal()`. The same shape as `cmt_pv_sign_vote`
 * with `stepPropose` (:374) and no extension.
 * @return as `cmt_pv_sign_vote`.
 */
int cmt_pv_sign_proposal(cmt_file_pv_t *pv, const uint8_t *chain_id,
                         size_t chain_id_len, cmt_pb_proposal_t *proposal);

/** cometbft@709fd12b privval/file.go:262-267 —
 *  `(pv *FilePV) SignVote()`, the PrivValidator method: signVote, and its
 *  error wrapped. The wrapping has no C counterpart, so this is the
 *  interface entry point and nothing more. */
int cmt_pv_sign_vote_iface(cmt_file_pv_t *pv, const uint8_t *chain_id,
                           size_t chain_id_len, cmt_pb_vote_t *vote);

/** cometbft@709fd12b privval/file.go:271-276 —
 *  `(pv *FilePV) SignProposal()`. */
int cmt_pv_sign_proposal_iface(cmt_file_pv_t *pv, const uint8_t *chain_id,
                               size_t chain_id_len,
                               cmt_pb_proposal_t *proposal);

/**
 * cometbft@709fd12b privval/file.go:413-422 —
 * `(pv *FilePV) saveSigned()`.
 *
 * Records height, round, step, signature and sign bytes (:416-420) and
 * then makes them durable (:421).
 *
 * @return CMT_OK; CMT_REJECT if the sign bytes or the signature do not fit
 *         the state's buffers (the explicit bound Go's slices carry
 *         implicitly — INVARIANT 7495d337); CMT_FAULT on NULL or when the
 *         host could not make the state durable.
 */
int cmt_pv_save_signed(cmt_file_pv_t *pv, int64_t height, int32_t round,
                       int8_t step, const uint8_t *sign_bytes,
                       size_t sign_bytes_len, const uint8_t *sig,
                       size_t sig_len);

/**
 * cometbft@709fd12b privval/file.go:430-446 —
 * `checkVotesOnlyDifferByTimestamp()`.
 *
 * Decodes both sign-byte strings as CanonicalVote, reads the OLD
 * timestamp, then sets BOTH timestamps to the same value and compares the
 * two messages. `proto.Equal` (:445) is a field-by-field comparison here.
 *
 * ⚠ The reference PANICS when either input will not decode (:433, :436).
 * CMT_FAULT: `lastSignBytes` comes from this node's own state file and
 * `newSignBytes` from bytes this node just built, so a failure there is
 * local corruption and not a peer's message.
 *
 * @param now the value the reference gets from `cmttime.Now()` at :441.
 *        It is written into BOTH copies and therefore cannot change the
 *        result; it is a parameter so the clock read stays where the
 *        reference has it.
 * @param out_ts receives the OLD timestamp (:439, :445's first return).
 * @param out_ok true when the two differ in nothing else (:445).
 * @return CMT_OK, CMT_FAULT (see above or NULL).
 */
int cmt_check_votes_only_differ_by_timestamp(const uint8_t *last_sign_bytes,
                                             size_t last_len,
                                             const uint8_t *new_sign_bytes,
                                             size_t new_len,
                                             cmt_time_t now,
                                             cmt_time_t *out_ts,
                                             bool *out_ok);

/** cometbft@709fd12b privval/file.go:450-466 —
 *  `checkProposalsOnlyDifferByTimestamp()`. The same over
 *  CanonicalProposal; the panics of :453 and :456 are CMT_FAULT for the
 *  same reason. */
int cmt_check_proposals_only_differ_by_timestamp(
        const uint8_t *last_sign_bytes, size_t last_len,
        const uint8_t *new_sign_bytes, size_t new_len, cmt_time_t now,
        cmt_time_t *out_ts, bool *out_ok);

/* ── the adapters the R1 layer expects ──────────────────────────────── */

/**
 * A `cmt_sign_vote_fn` (cmt_vote.h:332-333) backed by a FilePV, so
 * `cmt_sign_and_check_vote` (cmt_vote.h:351) can be given one.
 *
 * THIS IS THE REFERENCE'S OWN LAYERING: `state.go`'s `signAddVote` calls
 * `types.SignAndCheckVote`, which calls `PrivValidator.SignVote`, which
 * for a file-backed validator is `FilePV.signVote`. Pass the
 * `cmt_file_pv_t *` as `ctx`.
 */
int cmt_pv_sign_vote_adapter(void *ctx, const uint8_t *chain_id,
                             size_t chain_id_len, cmt_pb_vote_t *v);

/**
 * The proposal counterpart: signs `proposal` through `cmt_pv_sign_proposal`
 * over the sign bytes `cmt_proposal_sign_bytes` (cmt_proposal.h:129)
 * produces. Present so a caller holds one shape for both, as the
 * reference's `PrivValidator` interface does.
 */
int cmt_pv_sign_proposal_adapter(void *ctx, const uint8_t *chain_id,
                                 size_t chain_id_len,
                                 cmt_pb_proposal_t *p);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PRIVVAL_H */
