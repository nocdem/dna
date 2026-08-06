/**
 * @file native_verify_v3.h
 * @brief Ledger V2 S9 Gate 2 (W3) — the STATELESS native verifier for the
 *        three V3 shielded transaction types (11 TRANSFER / 12 SHIELD /
 *        13 UNSHIELD).
 *
 * dnac_v3_native_verify_stateless() takes ONE serialized Transaction Wire V3
 * transaction plus the consensus-authoritative execution context and decides
 * everything that is decidable WITHOUT a chain database: the wire decode, the
 * per-type cardinality/boundary windows the shared codec deliberately does not
 * enforce, the transparent-leg commitment, sighash_v5, the tx_binding equality,
 * the type-12 spend authorization, and the in-TX private-nullifier distinctness.
 * Everything that needs state is EXPORTED, never decided (dnac_v3_native_out_t).
 *
 * It is the runtime layer that sits ABOVE the policy-neutral codec: shared
 * shared/dnac/tx_wire.{h,c} enforces STRUCTURE (versions, caps, ordering,
 * zero-amount, exact lengths) and refuses to grow a transaction-type branch
 * (tx_wire.h §6 "POLICY NEUTRALITY"); the per-type rules — "SHIELD needs at
 * least one transparent input", "UNSHIELD carries exactly one output",
 * "TRANSFER's boundary_out IS the fee" — live HERE.
 *
 * ── ZERO PRODUCTION CALLERS (S9 Gate 2 hard requirement) ──────────────────
 * NOTHING in any admission, mempool, BFT, apply or replication path calls this
 * function. Its only callers are unit tests. That is not an accident of the
 * current wiring: live admission of types 11/12/13 remains impossible after
 * this file lands, through SIX independent stops, each alone sufficient. All
 * six were re-read in the tree at the time this file was written (S9 W0 and W2
 * applied) — line numbers cited from the source, not from a design document:
 *
 *   1. WIRE VERSION. Every live ingress gates on wire version byte 2, so V3
 *      bytes never even parse: client `dnac_tx_deserialize`
 *      (dnac/src/transaction/serialize.c:457 `buffer[0] != DNAC_PROTOCOL_VERSION`)
 *      and witness Check 0 (nodus/src/witness/nodus_witness_verify.c:527
 *      `tx_data[0] != DNAC_PROTOCOL_VERSION`).
 *   2. V2 TYPE SET FROZEN. On the legacy V2 wire the acceptance set is pinned
 *      at 0..11 by a LITERAL (serialize.c:484 `tx->type > 11`), and the witness
 *      carries an explicit named reject for 12/13
 *      (nodus_witness_verify.c:614-623), firing on either the caller-declared
 *      type or the wire type byte.
 *   3. TYPE-11 TERMINAL REJECT. The V2 shielded lane `verify_shielded_tx` ends
 *      in an unconditional `return -1` (nodus_witness_verify.c:496) with the
 *      "shielded admission disabled until C3" reason; the accept-flip is a C3
 *      insertion point, not a flag.
 *   4. RUNTIME ADMISSION. `rt_admit_common` hard-stops types 11, 12 AND 13
 *      unconditionally, and that stop runs BEFORE the pool rule, so the
 *      shielded pool id can never become an admit path
 *      (nodus/src/witness/nodus_witness_runtime.c, the `tx_type == 11 || 12 ||
 *      13` block). ⚠ UPDATED at S9 W4: an earlier revision of this comment
 *      said 12/13 were rejected because they were ABSENT from the CORE
 *      descriptor (`CORE_TYPES[4] = {1,2,3,11}`). W4 made CORE OWN them
 *      (`CORE_TYPES[6] = {1,2,3,11,12,13}`) so the domain boundary is
 *      expressible — ownership is what the explicit hard stop above now
 *      carries. The stop is stronger than the old absence, not weaker.
 *   5. DOMREG V2 BOUNDARY. The inactive V2 semantic admission rejects every
 *      proof-bearing context: `ctx->statement_version != 0` returns -1
 *      (nodus/src/witness/nodus_witness_domreg.c:866).
 *   6. NO CALLER. No production translation unit calls
 *      dnac_v3_native_verify_stateless. The identical linkage-without-
 *      consumption seam already carries dnac_shielded_verify_statement, whose
 *      only callers today are nodus/tests/test_zk_link.c and the zk tests.
 *
 * A VALID verdict from this function therefore cannot propagate anywhere. The
 * only future caller is the single atomic activation gate (S10/C3).
 *
 * ── Validation order (frozen; first failure wins, each fail-closed) ───────
 * The steps are numbered as in the S9 freeze report §D.1:
 *    2  wire decode              dnac_txw3_decode (exact length)
 *    2b type gate                tx_type ∈ {11,12,13}
 *    3  body split by type       11: section only · 12/13: leg ‖ section
 *    4  context match + build    header copies == the caller's context, then
 *                                dna_exec_context_init over the CALLER's values
 *    5  header mirrors           dnac_txw3_shielded_check_header + min-fee floor
 *    6  per-type count windows   the native rules (below)
 *    7  per-type boundary rules  + CHECKED transparent arithmetic
 *    8  transparent-leg commit   dnac_tleg_commit / dnac_tleg_commit_empty
 *    9  sighash_v5               dnac_sighash_v5 (shared codec, never re-implemented)
 *   10  tx_binding equality      conf_txbind_map(sighash) == wire tx_binding
 *   11  type-12 signatures       Dilithium5 over the 64-byte sighash, AFTER 10
 *   12  in-TX nullifier dedup    private nf_set pairwise distinct
 *   13  proof                    type 11 only (see the DEFERRAL note below)
 *   14  export state expectations, then OK
 *
 * ── Per-type native rules (S9 freeze report §B; user locks O-1 / O-1b) ────
 *   type 11 TRANSFER: no transparent leg · private in 1..4 · private out 1..4
 *                     · boundary_in == 0 · boundary_out == committed_fee
 *   type 12 SHIELD:   num_tin >= 1 · num_signers >= 1 · num_tout 0..16
 *                     · private in == 0 · private out 1..4 · boundary_out == 0
 *                     · boundary_in >= 1 · boundary_in + Σtout + fee must not
 *                       overflow u64 (the EQUALITY is DB-authoritative — the
 *                       transparent input sum is not on the wire — so it is
 *                       EXPORTED as an S10 expectation, never decided here)
 *   type 13 UNSHIELD: num_tin == 0 · num_signers == 0 · num_tout == 1
 *                     · private in 1..4 · private out 0..1 · boundary_in == 0
 *                     · boundary_out == tout[0].amount + fee (CHECKED add)
 * Rules the CODEC already owns are NOT restated here (restating them would be
 * an unreachable branch): counts <= their caps, all-zero anchor when
 * num_input == 0, unused-slot zeroing, lane canonicality, boundary < 2^63,
 * strictly-ascending transparent inputs, amount >= 1 per transparent output,
 * fri_len != 0. See tx_wire.c:564-622 (section) and tx_wire.c:841-856 (leg).
 *
 * ── SEAM 1: SIGNATURE VERIFICATION IS CALLER-SUPPLIED ─────────────────────
 * The type-12 spend authorization is a Dilithium5 verify over sighash_v5 (user
 * lock O-2). This module does NOT link a signature primitive, because the two
 * builds that compile it cannot agree on one:
 *   - libnodus HAS qgp_dsa87_verify (nodus/CMakeLists.txt:67 compiles
 *     shared/crypto/sign/qgp_dilithium.c);
 *   - the standalone zk suite (shared/crypto/zk/Makefile) links NO signature
 *     source, and pulling one in would drag the whole vendored dsa library plus
 *     `randombytes` — a dependency the nodus build itself documents as circular
 *     (nodus/CMakeLists.txt:449 "dsa -> qgp_randombytes -> nodus circular dep").
 * So the verifier is a REQUIRED function pointer on the context. This keeps the
 * translation unit byte-identical in both builds — no #ifdef, no per-build
 * divergence in a consensus path — and the pointer type is deliberately the
 * EXACT signature of qgp_dsa87_verify (shared/crypto/sign/qgp_dilithium.h:49),
 * so the witness passes that symbol directly with no adapter to get wrong.
 * A NULL pointer on a type-12 transaction is DNAC_SHIELDED_VERIFY_ERR_SIG:
 * "cannot check" is a REJECT, never a skip.
 *
 * ── SEAM 2 (WAS: the proof step is deferred for 12/13) — CLOSED ───────────
 * ✔ CLOSED by the S9 CORRECTION PASS. Recorded here because the shape of the
 * fix is the load-bearing part.
 *
 * The hole: `dnac_shielded_verify_statement` derived the transparent-leg
 * commitment itself, always calling dnac_tleg_commit_empty(). For types 12/13
 * the leg is POPULATED, so the sighash it rebuilt differed from the one this
 * entry computed BY CONSTRUCTION — every honest SHIELD/UNSHIELD would have been
 * rejected on ERR_TXBIND, a verdict claiming "binding failed" while the binding
 * was in fact correct. This entry therefore called it for type 11 only and
 * returned a distinct deferral status for 12/13.
 *
 * The fix: the commitment moved INTO the caller-supplied context
 * (`dnac_shielded_verify_ctx_t.tleg_commit`). This entry computes the digest
 * once — tagged-empty for type 11, the real DNA.TLEG.v1 commitment for 12/13 —
 * and hands it over, so ALL THREE types now run the SAME real aggregate
 * verifier. `DNAC_SHIELDED_VERIFY_ERR_PROOF_DEFERRED` is DELETED; its enum
 * value now carries ERR_TIMESTAMP (see below).
 *
 * What did NOT move, and this is the point: the 581-byte sighash_v5 preimage,
 * its offsets, its tag, the 45-public layout, D, the trace width, the FRI
 * parameters and every tracked vector. Only the VALUE written into an
 * already-frozen slot varies — the case tx_wire.h §5 anticipated when it said
 * "S9/S10 supply real digests through these SAME two parameters". The
 * ciphertext slot stays tagged-empty.
 *
 * The digest is computed ONCE and consumed TWICE — by this module's own
 * sighash and by the statement entry's independent recompute. They must agree
 * or the statement fails ERR_TXBIND, which is exactly what makes a transparent
 * leg substituted under an unchanged proof unforgeable.
 *
 * ── The timestamp rule (OBL-S9-TS-BIND — CLOSED) ──────────────────────────
 * For types 11/12/13 the V3 header `timestamp` is CONSENSUS-INERT and its sole
 * canonical value is 0; a non-zero value is DNAC_SHIELDED_VERIFY_ERR_TIMESTAMP,
 * returned BEFORE any proof work. sighash_v5 deliberately excludes
 * consensus-time fields, and the transparent leg's signers sign sighash_v5 —
 * so a free timestamp would be a wire byte nothing binds, letting a relayer
 * re-stamp a signed transaction into a different txid for the SAME accepted
 * statement. Pinning the value removes the freedom without enlarging the frozen
 * preimage. `expiry_height` is untouched: it remains a real consensus field,
 * bound inside sighash_v5 and mirrored by the section. The GENERIC codec is
 * unchanged and still policy-neutral — the restriction lives in this
 * type-specific layer.
 *
 * ── Determinism ──────────────────────────────────────────────────────────
 * The verdict is a PURE function of (tx bytes, the caller's context bytes).
 * No clock, no RNG, no database, no map iteration, no allocation-address
 * dependence. The only loops are over wire-ordered, count-bounded arrays; the
 * nullifier-distinctness scan is an O(n^2) pairwise memcmp over at most 4
 * entries, so it carries no ordering or hashing dependence. Two witnesses with
 * the same block execution context and the same TX bytes reach the same verdict.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_NATIVE_VERIFY_V3_H
#define DNAC_ZK_NATIVE_VERIFY_V3_H

#include <stddef.h>
#include <stdint.h>

#include "dnac/tx_wire.h"  /* V3 header/section/leg codec + sighash_v5        */
#include "shielded_verify.h" /* dnac_shielded_verify_status_t (SHARED status) */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Detached signature verification callback (type 12 only).
 *
 * Byte-compatible with qgp_dsa87_verify (shared/crypto/sign/qgp_dilithium.h:49)
 * so libnodus can pass that symbol directly — no adapter, nothing to get wrong.
 *
 * @param sig      the signature bytes (DNAC_TXW_SIG_LEN for Dilithium5)
 * @param sig_len  signature length
 * @param msg      the message — ALWAYS the 64-byte sighash_v5 here
 * @param msg_len  message length (DNAC_TXW_HASH_LEN)
 * @param pubkey   the signer public key (DNAC_TXW_PK_LEN)
 * @return 0 iff the signature is valid; any non-zero value REJECTS.
 */
typedef int (*dnac_v3_native_sig_verify_fn)(const uint8_t *sig, size_t sig_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *pubkey);

/**
 * @brief The consensus-authoritative context for one V3 native verification.
 *
 * Mirrors dnac_shielded_verify_ctx_t minus tx_type: the TYPE is read from the
 * WIRE header (it selects the rule set being applied), while every value below
 * comes from the verifier's own consensus state — the block's execution context
 * and the ACTIVE domain-registry/runtime ruleset — and is NEVER parsed out of
 * the transaction (S9 freeze report §C.7 / §D.3 N-0). The V3 header carries its
 * own copies of domain_id / pool_id / ruleset_version / statement_version; they
 * are equality-checked against these values and the CALLER's values are what
 * enter the ExecutionContext, so a transaction can never select its own rules.
 *
 * wire_version is not a field: this entry pins DNAC_TXW3_WIRE_VERSION, and the
 * shielded section version is pinned to DNAC_TXW3_SECT_VERSION, exactly as
 * dnac_shielded_verify_statement does.
 *
 * NOTE on statement_version: it is equality-checked against the header, not
 * pinned to DNAC_SHIELDED_STATEMENT_VERSION here — the pin belongs to the proof
 * entry, which applies it (its step 0, shielded_verify.c). Since the correction
 * pass all three types go through that entry, so the version pin now covers
 * 11, 12 and 13 alike.
 */
typedef struct {
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];   /**< 32-byte chain id             */
    uint32_t domain_id;                    /**< executing domain             */
    uint32_t pool_id;                      /**< executing pool               */
    uint32_t ruleset_version;              /**< ACTIVE ruleset version       */
    uint32_t statement_version;            /**< ACTIVE ZK statement version  */
    uint8_t  ruleset_hash[DNAC_TXW_HASH_LEN]; /**< ACTIVE ruleset digest     */
    /** Dilithium5 verifier for type-12 signers. REQUIRED for type 12 — NULL
     *  yields DNAC_SHIELDED_VERIFY_ERR_SIG (a missing checker is a reject,
     *  never a skip). Unused by types 11 and 13, which carry no signers. */
    dnac_v3_native_sig_verify_fn sig_verify;
} dnac_v3_native_ctx_t;

/**
 * @brief The DEFERRED (state, S10) expectations this transaction asserts.
 *
 * PLAIN DATA ONLY — parsed wire values, no verdict, no database access, no
 * callback. It is what an S10 stateful pass would need to check against the
 * chain: anchor window membership, pool/transparent nullifier absence, UTXO
 * existence/ownership, the type-12 transparent input-sum equality, pool balance
 * and note-tree capacity, and expiry against the commit height.
 *
 * VALIDITY: populated when every STATELESS step (2 through 12) passed —
 * independently of the proof step's verdict, because the proof is step 13 and
 * the export is step 14. So it is filled for OK, for ERR_PROOF_DEFERRED, and
 * also when the type-11 proof itself rejected. On every EARLIER (stateless)
 * reject it is left ZEROED: it is zeroed on entry, before the first byte of the
 * transaction is examined, so a caller can never read a half-written export.
 * A populated export therefore means "the wire and the binding were sound", and
 * is exactly how the unit tests distinguish reaching the proof step from dying
 * at the decode. It carries NO verdict: only the return value does.
 *
 * SIZE: roughly 4 KB (1 KB of transparent input references + 16 padded
 * transparent outputs). Fine on a server stack, but do not casually put two of
 * them in one frame; the same caution the leg struct carries (tx_wire.h §6).
 *
 * Signer PUBKEYS are deliberately NOT exported: S10's "input UTXO owner must
 * match a signer" rule re-decodes the leg (the bytes are in the transaction it
 * already holds), and copying 4 x 2592 bytes into every result would quadruple
 * this struct for one state rule.
 */
typedef struct {
    /* identity */
    uint8_t  tx_type;                       /**< 11 / 12 / 13 (from the wire) */
    uint32_t domain_id;                     /**< == ctx (equality-checked)    */
    uint32_t pool_id;                       /**< == ctx (equality-checked)    */
    uint8_t  sighash[DNAC_TXW_HASH_LEN];    /**< the sighash_v5 that bound it */

    /* header-authoritative amounts / lifetime */
    uint64_t committed_fee;                 /**< header fee (section mirrors) */
    uint64_t expiry_height;                 /**< 0 = no expiry; S10: height <= */
    uint64_t boundary_in;                   /**< transparent -> pool           */
    uint64_t boundary_out;                  /**< pool -> transparent           */

    /* shielded side — S10: anchor window, pool nullifier set, note capacity */
    uint64_t anchor[DNAC_TXW3_SHIELDED_LANES];
    uint8_t  num_nullifier;                 /**< == section num_input          */
    uint64_t nullifier[DNAC_TXW3_SHIELDED_MAX_INPUTS][DNAC_TXW3_SHIELDED_LANES];
    uint8_t  num_output_commit;             /**< == section num_output         */
    uint64_t output_commit[DNAC_TXW3_SHIELDED_MAX_OUTPUTS][DNAC_TXW3_SHIELDED_LANES];

    /* transparent side — S10: UTXO exist/unspent/unlocked/owner-match (12),
     * recipient/change UTXO creation (12 and 13), input-sum equality (12) */
    uint8_t  num_tin;                       /**< transparent inputs spent      */
    uint8_t  tin_nullifier[DNAC_TXW_MAX_INPUTS][DNAC_TXW_NULLIFIER_LEN];
    uint8_t  num_tout;                      /**< transparent outputs created   */
    dnac_txw3_tout_t tout[DNAC_TXW_MAX_OUTPUTS];
    uint8_t  num_signers;                   /**< count only (see note above)   */

    /** Type 12 ONLY: the value the transparent input set MUST sum to, i.e.
     *  boundary_in + Σ tout[i].amount + committed_fee, computed with checked
     *  adds (an overflow is DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH and never
     *  reaches here). The input sum itself is DB-authoritative — the wire does
     *  not carry transparent input amounts — so THIS ENTRY DOES NOT DECIDE the
     *  equality; S10 does. Zero for types 11 and 13. */
    uint64_t tin_sum_expected;
    /** 1 when tin_sum_expected is meaningful (type 12), else 0. */
    uint8_t  has_tin_sum_expected;
} dnac_v3_native_out_t;

/**
 * @brief Stateless native verification of one serialized V3 transaction.
 *
 * @param tx_bytes  the FULL serialized Transaction Wire V3 transaction
 * @param tx_len    its length (must equal 110 + body_len exactly — the codec
 *                  rejects both truncation and trailing bytes)
 * @param nctx      the consensus-authoritative context (never NULL)
 * @param out       optional; when non-NULL it is zeroed on entry and filled
 *                  with the deferred STATE expectations once every stateless
 *                  step has passed. May be NULL if the caller only wants the
 *                  verdict.
 *
 * @return DNAC_SHIELDED_VERIFY_OK  iff every stateless check passed AND the
 *         aggregate proof verified — for ALL THREE types 11/12/13 since the
 *         S9 correction pass;
 *         the first failing check's distinct status otherwise.
 *
 * Status mapping for the classes this entry adds to the shared enum:
 *   ERR_DECODE (8)        V3 header decode, or shielded-section decode, failed
 *   ERR_FEE (6)           header/section fee mirror, or the min-fee floor
 *   ERR_TXBIND (7)        context init, header/context disagreement (domain,
 *                         pool, ruleset), expiry mirror, commitment/sighash
 *                         computation, or tx_binding inequality
 *   ERR_STATEMENT_VERSION (15)  header statement_version != the context's
 *   ERR_TLEG_DECODE (18)  the transparent leg failed to decode (12/13)
 *   ERR_TYPE_RULE (20)    unknown type, or a per-type count/boundary rule
 *   ERR_TLEG_ARITH (21)   a checked transparent sum overflowed u64
 *   ERR_SIG (22)          missing verifier, or a type-12 signature rejected
 *   ERR_NF_DUP (23)       two identical private nullifiers in one transaction
 */
dnac_shielded_verify_status_t dnac_v3_native_verify_stateless(
    const uint8_t *tx_bytes, size_t tx_len,
    const dnac_v3_native_ctx_t *nctx,
    dnac_v3_native_out_t *out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_NATIVE_VERIFY_V3_H */
