/**
 * @file native_verify_v3.c
 * @brief Ledger V2 S9 Gate 2 (W3) — the stateless native verifier (see header).
 *
 * The header carries the full contract: the frozen step order, the per-type
 * rule tables, the two honest seams (caller-supplied signature verifier, the
 * deferred proof step for types 12/13) and the six-stop proof that live
 * admission of types 11/12/13 remains impossible. This file is the mechanism.
 *
 * Two disciplines govern every line below:
 *
 *   1. ONE codec, never a re-implementation. Decode, the leg commitment,
 *      sighash_v5 and the tx_binding map all go through the SHARED
 *      shared/dnac/tx_wire.{h,c} + conf_txbind.h entries that libdna and
 *      libnodus compile identically. A second walk of the same bytes here
 *      would be exactly the drift this layer exists to prevent.
 *
 *   2. NO restated codec rule. If tx_wire.c already rejects a shape, this file
 *      does not check it again — a duplicate check is either dead code (it can
 *      never fire) or, worse, a second opinion that could one day disagree with
 *      the first. Every rule here is one the policy-neutral codec deliberately
 *      does NOT own (tx_wire.h §6 "POLICY NEUTRALITY").
 *
 * Grounding map (KAFADAN YASAK):
 *   - V3 header / shielded section / transparent leg codec .. shared/dnac/tx_wire.h
 *   - sighash_v5 (581-B preimage, tleg slot @453) ........... dnac_sighash_v5, tx_wire.h §5
 *   - populated leg commitment "DNA.TLEG.v1" ................ dnac_tleg_commit, tx_wire.h §6
 *   - tagged-empty leg / ct commitments ..................... dnac_tleg_commit_empty /
 *                                                             dnac_ct_commit_empty, tx_wire.h §5
 *   - tx_binding rejection map .............................. conf_txbind_map, conf_txbind.h
 *   - the type-11 proof verdict ............................. dnac_shielded_verify_statement,
 *                                                             shielded_verify.h
 *   - min fee ............................................... DNAC_MIN_FEE_RAW, dnac/dnac.h:143
 *   - checked addition ...................................... safe_add_u64, dnac/safe_math.h:21
 *   - type numbers 11/12/13 ................................. dnac_tx_type_t, dnac/dnac.h:382-389
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "native_verify_v3.h"

#include <stdlib.h>
#include <string.h>

#include "conf_txbind.h"
#include "dnac/dnac.h"       /* DNAC_MIN_FEE_RAW + the tx type numbers        */
#include "dnac/safe_math.h"  /* safe_add_u64 — the ONE checked-add helper     */
#include "dnac/transaction.h" /* dnac_tx_shielded_fields_t (type-11 proof step) */

/* ── Shape pins. The wire struct (dnac_txw3_shielded_t) and the proof-entry
 * struct (dnac_tx_shielded_fields_t) are declared in two different headers with
 * two different macro families; the type-11 hand-off below copies field by
 * field, so a silent drift between the families would copy the wrong number of
 * lanes. Pin them here the same way shielded_verify.c pins its own
 * (shielded_verify.c:86-101). ── */
_Static_assert(DNAC_TXW3_SHIELDED_LANES == DNAC_SHIELDED_LANES &&
                   DNAC_TXW3_SHIELDED_MAX_INPUTS == DNAC_SHIELDED_MAX_INPUTS &&
                   DNAC_TXW3_SHIELDED_MAX_OUTPUTS == DNAC_SHIELDED_MAX_OUTPUTS,
               "V3 wire shielded shape != dnac shielded-fields shape");
/* The transparent-leg commitment and sighash_v5 are both SHA3-512, and the
 * tx_binding map consumes exactly that width. */
_Static_assert(DNAC_TXW_HASH_LEN == CONF_TXBIND_SIGHASH_LEN,
               "sighash width != tx_binding map input width");
_Static_assert(DNAC_TXW3_SHIELDED_LANES == CONF_TXBIND_LANES,
               "tx_binding lane count != wire tx_binding lane count");
/* The type numbers this entry serves. They are the WIRE's, read from the V3
 * header; pinning them against the dnac enum makes a renumber a compile error
 * rather than a silently widened accept set. */
_Static_assert(DNAC_TX_SHIELDED == 11 && DNAC_TX_SHIELD == 12 &&
                   DNAC_TX_UNSHIELD == 13,
               "V3 shielded/boundary type numbers moved");

/* Per-type private-output windows (user locks O-1 / O-1b). Only the LOWER
 * bounds appear as code: every upper bound is already enforced by the codec
 * (txw3_stmt_common_ok, tx_wire.c:565-566), so restating it would be an
 * unreachable branch.
 * The constants are plain ints (no `u` suffix) so every comparison below is
 * int-vs-int after the uint8_t promotion — no signed/unsigned mix for -Wextra
 * to flag in a -Werror build (nodus/CMakeLists.txt:352). */
#define NV3_MIN_PRIV_OUT_TRANSFER 1 /* O-1  : reject the 0-output fee sink    */
#define NV3_MIN_PRIV_OUT_SHIELD   1 /* §B   : 0 out would force b_in == 0     */
#define NV3_MAX_PRIV_OUT_UNSHIELD 1 /* O-1b : one optional change note        */

/**
 * Pairwise in-TX distinctness of the PRIVATE nullifiers (step 12).
 *
 * O(n^2) over at most DNAC_TXW3_SHIELDED_MAX_INPUTS (4) entries, compared with
 * memcmp over the raw lanes. Deliberately NOT a sort or a hash set: with n <= 4
 * the pairwise scan is both faster and free of any ordering or hashing
 * dependence, so the verdict cannot vary with anything but the bytes.
 * Slots at or beyond num_input are all-zero (codec-enforced) and are not
 * scanned — two zeroed unused slots are not a duplicate spend.
 * @return 0 when all used slots are distinct, -1 on the first duplicate.
 */
static int nv3_nullifiers_distinct(const dnac_txw3_shielded_t *st) {
    for (unsigned a = 0; a + 1u < (unsigned)st->num_input; a++)
        for (unsigned b = a + 1u; b < (unsigned)st->num_input; b++)
            if (memcmp(st->nf_set[a], st->nf_set[b],
                       sizeof(st->nf_set[0])) == 0)
                return -1;
    return 0;
}

/**
 * Sum of every transparent output amount, with CHECKED adds.
 * @return 0 on success (*sum_out written), -1 on u64 overflow.
 */
static int nv3_tout_sum(const dnac_txw3_tleg_t *leg, uint64_t *sum_out) {
    uint64_t acc = 0;
    for (unsigned i = 0; i < (unsigned)leg->num_tout; i++)
        if (safe_add_u64(acc, leg->tout[i].amount, &acc) != 0) return -1;
    *sum_out = acc;
    return 0;
}

dnac_shielded_verify_status_t dnac_v3_native_verify_stateless(
    const uint8_t *tx_bytes, size_t tx_len,
    const dnac_v3_native_ctx_t *nctx,
    dnac_v3_native_out_t *out) {
    /* Fail closed FIRST: the export struct is zeroed before the first byte of
     * the transaction is examined, so no reject path can leave a caller reading
     * stale expectations (the tx_wire.c:675 / :922 discipline). */
    if (out) memset(out, 0, sizeof(*out));
    if (tx_bytes == NULL || tx_len == 0 || nctx == NULL)
        return DNAC_SHIELDED_VERIFY_ERR_NULL;

    /* ── Step 2: generic V3 decode. EXACT length — a truncated transaction and
     *    one with trailing bytes both reject here (tx_wire.h §2). ── */
    dnac_txw3_header_t hdr;
    const uint8_t    *body     = NULL;
    uint32_t          body_len = 0;
    if (dnac_txw3_decode(tx_bytes, tx_len, &hdr, &body, &body_len) != 0)
        return DNAC_SHIELDED_VERIFY_ERR_DECODE;

    /* ── Step 2b: type gate. This entry serves exactly three types; anything
     *    else — including the unassigned 14 — is rejected before a single
     *    per-type rule runs. ── */
    if (hdr.tx_type != DNAC_TX_SHIELDED && hdr.tx_type != DNAC_TX_SHIELD &&
        hdr.tx_type != DNAC_TX_UNSHIELD)
        return DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
    const int has_leg = (hdr.tx_type != DNAC_TX_SHIELDED);

    /* ── Step 2c: the timestamp rule (S9 CORRECTION PASS — closes
     *    OBL-S9-TS-BIND).
     *
     *    FROZEN: for the shielded types 11/12/13 the V3 header `timestamp` is
     *    CONSENSUS-INERT and its SOLE canonical value is 0.
     *
     *    Why a rule and not a binding: sighash_v5 deliberately excludes
     *    consensus-time fields so a proof is independent of when it was built
     *    (tx_wire.h §5), and the transparent leg's signers sign sighash_v5, not
     *    the txid. A non-zero timestamp would therefore be a wire byte that
     *    NOTHING binds — a relayer could re-stamp a signed transaction and
     *    produce a different V5 txid for the SAME accepted statement. Pinning
     *    the value to 0 removes the degree of freedom instead of enlarging the
     *    frozen 581-byte preimage: the field is still carried and still hashed
     *    into the txid, it simply has exactly one legal value here.
     *
     *    This is a WIRE-CANONICALITY rule, so it runs BEFORE any proof work,
     *    before the leg is even decoded — deterministic, byte-derived, no
     *    crypto. `expiry_height` is untouched: it stays a real consensus field,
     *    bound inside sighash_v5 at offset 445 and mirrored by the section.
     *
     *    The GENERIC codec is not involved: dnac_txw3_decode still accepts any
     *    timestamp for any type (tx_wire.h "the codec deliberately does NOT
     *    judge ... tx_type assignment"). The restriction lives here, in the
     *    type-specific layer that owns per-type policy. ── */
    if (hdr.timestamp != 0)
        return DNAC_SHIELDED_VERIFY_ERR_TIMESTAMP;

    /* ── Step 3: body split by type.
     *    11 : the body IS the shielded section (no transparent leg). A body
     *         that carried a leg would fail the section's EXACT length
     *         equality, so "type 11 has no leg" is enforced by construction.
     *    12 : leg ‖ section. 13: leg ‖ section. The leg decode is a PREFIX walk
     *         reporting what it consumed; the section decode's exact-length
     *         equality over the REMAINDER is what rejects truncation and
     *         trailing bytes (tx_wire.h §6 "PREFIX decode"). ──
     *
     *    The leg struct is ~32 KB, which its own header warns against putting
     *    on a small thread stack (tx_wire.h §6 SIZE note) — heap it. */
    dnac_txw3_tleg_t     *leg      = NULL;
    dnac_txw3_shielded_t  st;
    const uint8_t        *fri      = NULL;
    uint32_t              fri_len  = 0;
    uint64_t              tout_sum = 0;
    dnac_shielded_verify_status_t rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;

    if (has_leg) {
        size_t consumed = 0;
        leg = (dnac_txw3_tleg_t *)calloc(1, sizeof(*leg));
        if (leg == NULL) return DNAC_SHIELDED_VERIFY_ERR_NULL; /* fail-close */
        if (dnac_txw3_tleg_decode(body, (size_t)body_len, leg, &consumed) != 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE;
            goto done;
        }
        /* consumed <= body_len is the decoder's own invariant (every bound
         * check there is the subtraction form against body_len). */
        if (dnac_txw3_shielded_decode(body + consumed,
                                      (uint32_t)((size_t)body_len - consumed),
                                      &st, &fri, &fri_len) != 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_DECODE;
            goto done;
        }
    } else {
        if (dnac_txw3_shielded_decode(body, body_len, &st, &fri, &fri_len) != 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_DECODE;
            goto done; /* one exit past this point, even with leg == NULL */
        }
    }

    /* ── Step 4: context match, then build the ExecutionContext.
     *    The header carries COPIES of the four context ids; they are
     *    equality-checked and then DISCARDED — what enters the context is the
     *    CALLER's consensus state (§C.7 / §D.3 N-0), so a transaction can
     *    never select the chain, domain, pool or ruleset it is judged under.
     *    This early check is STRICTER than the tx_binding equality two steps
     *    down: a proof bound to the caller's context but shipped under a
     *    mismatched header copy would satisfy the binding and still die here. ── */
    if (hdr.statement_version != nctx->statement_version) {
        rc = DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION;
        goto done;
    }
    if (hdr.domain_id != nctx->domain_id || hdr.pool_id != nctx->pool_id ||
        hdr.ruleset_version != nctx->ruleset_version) {
        rc = DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        goto done;
    }
    dna_exec_context_t ectx;
    if (dna_exec_context_init(&ectx, nctx->chain_id, nctx->domain_id,
                              nctx->pool_id, hdr.tx_type,
                              (uint8_t)DNAC_TXW3_WIRE_VERSION,
                              nctx->ruleset_version,
                              nctx->statement_version) != 0) {
        rc = DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        goto done;
    }

    /* ── Step 5: header mirrors + the min-fee floor.
     *    check_header is the single AUTHORITY for the fee/expiry mirror gate
     *    (one-way: the header wins, tx_wire.h §4). The branch below only
     *    CLASSIFIES a failure it has already decided — it cannot turn a reject
     *    into an accept. An expiry-mirror disagreement is reported as a binding
     *    failure because expiry_height sits inside the sighash_v5 preimage
     *    (off 445): the statement would be bound to a different expiry than the
     *    header declares. ── */
    if (dnac_txw3_shielded_check_header(&hdr, &st) != 0) {
        rc = (hdr.committed_fee != st.fee) ? DNAC_SHIELDED_VERIFY_ERR_FEE
                                           : DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        goto done;
    }
    if (hdr.committed_fee < DNAC_MIN_FEE_RAW) {
        rc = DNAC_SHIELDED_VERIFY_ERR_FEE;
        goto done;
    }

    /* ── Steps 6 + 7: the per-type count windows and boundary equalities, plus
     *    the checked transparent arithmetic. These are the rules the shared
     *    codec deliberately does not own. ── */
    switch (hdr.tx_type) {
    case DNAC_TX_SHIELDED:
        /* TRANSFER: pool-internal. Nothing transparent moves, and the fee is
         * the ONLY value leaving the pool. */
        if (st.num_input == 0 ||
            st.num_output < NV3_MIN_PRIV_OUT_TRANSFER) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        if (st.boundary_in != 0 || st.boundary_out != hdr.committed_fee) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        break;

    case DNAC_TX_SHIELD:
        /* SHIELD: transparent -> pool. At least one transparent input is spent
         * and at least one signer authorizes it; nothing leaves the pool, so
         * boundary_out is 0 and the fee is paid on the transparent side (it is
         * NOT inside boundary_in). num_tout 0..16 is entirely codec-enforced —
         * a SHIELD with no change output is legal. */
        if (leg->num_tin == 0 || leg->num_signers == 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        if (st.num_input != 0 || st.num_output < NV3_MIN_PRIV_OUT_SHIELD) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        if (st.boundary_out != 0 || st.boundary_in == 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        /* Well-formedness ONLY: boundary_in + Σ change + fee must be
         * expressible in u64. The EQUALITY against the transparent input sum is
         * DB-authoritative (the wire carries no input amounts — outpoint model,
         * §C.2), so it is EXPORTED as an S10 expectation and never decided. */
        if (nv3_tout_sum(leg, &tout_sum) != 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH;
            goto done;
        }
        {
            uint64_t expect = 0;
            if (safe_add_u64(st.boundary_in, tout_sum, &expect) != 0 ||
                safe_add_u64(expect, hdr.committed_fee, &expect) != 0) {
                rc = DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH;
                goto done;
            }
            tout_sum = expect; /* reused below as the exported expectation */
        }
        break;

    case DNAC_TX_UNSHIELD:
        /* UNSHIELD: pool -> transparent. The pool is the source, so nothing
         * transparent is spent and there is nothing for a signer to authorize
         * (spend authority is the proof's ak/nk binding). Exactly one recipient
         * output; its amount plus the fee is what leaves the pool. */
        if (leg->num_tin != 0 || leg->num_signers != 0 || leg->num_tout != 1) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        if (st.num_input == 0 || st.num_output > NV3_MAX_PRIV_OUT_UNSHIELD) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        if (st.boundary_in != 0) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
            goto done;
        }
        {
            uint64_t need = 0;
            if (safe_add_u64(leg->tout[0].amount, hdr.committed_fee,
                             &need) != 0) {
                rc = DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH;
                goto done;
            }
            if (st.boundary_out != need) {
                rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
                goto done;
            }
        }
        break;

    default:
        /* Unreachable: the type gate above admitted exactly three values. Kept
         * so a future type added to the gate without a rule block fails CLOSED
         * instead of falling through to the binding steps. */
        rc = DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE;
        goto done;
    }

    /* ── Step 8: the two commitments that fill the frozen sighash_v5 slots.
     *    A populated leg uses the "DNA.TLEG.v1" domain; an absent one uses the
     *    distinct tagged-empty "DNA.E.TLEG.v1" domain, so an empty leg and a
     *    populated-but-empty-looking one can never collide (tx_wire.h §6).
     *    ct_commit stays tagged-empty through S9 — encrypted-note delivery is
     *    out of scope, and the slot stays bound so S10 can populate it without
     *    a statement re-pin. ── */
    uint8_t tleg_commit[DNAC_TXW_HASH_LEN];
    uint8_t ct_commit[DNAC_TXW_HASH_LEN];
    const int commit_rc = has_leg ? dnac_tleg_commit(leg, tleg_commit)
                                  : dnac_tleg_commit_empty(tleg_commit);
    if (commit_rc != 0 || dnac_ct_commit_empty(ct_commit) != 0) {
        rc = DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        goto done;
    }

    /* ── Step 9: sighash_v5 through the SHARED codec (never re-implemented).
     *    The section version is PINNED here, not taken from the wire copy. ── */
    uint8_t sighash[DNAC_TXW_HASH_LEN];
    if (dnac_sighash_v5(&ectx, (uint8_t)DNAC_TXW3_SECT_VERSION,
                        nctx->ruleset_hash, &st, tleg_commit, ct_commit,
                        sighash) != 0) {
        rc = DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        goto done;
    }

    /* ── Step 10: tx_binding equality. This is the ONE equality object: every
     *    other public is built FROM the wire, so wire/public agreement is by
     *    construction. A type-12 statement replayed as type-13 yields a
     *    different sighash (tx_type sits at preimage offset 56) and dies here. ── */
    uint64_t txbind[CONF_TXBIND_LANES];
    if (!conf_txbind_map(sighash, txbind)) {
        rc = DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        goto done;
    }
    for (unsigned j = 0; j < CONF_TXBIND_LANES; j++) {
        if (txbind[j] != st.tx_binding[j]) {
            rc = DNAC_SHIELDED_VERIFY_ERR_TXBIND;
            goto done;
        }
    }

    /* ── Step 11: type-12 spend authorization, AFTER the binding check.
     *    Ordering is deliberate: the signature covers sighash_v5, so verifying
     *    it before the binding is established would spend Dilithium5 verifies on
     *    a statement that is not yet known to be the one on the wire. Types 11
     *    and 13 carry no signers (step 6 pins num_signers == 0 for 13; 11 has no
     *    leg at all), so there is nothing to authorize.
     *    The signers sign the 64-byte sighash — NOT the txid, which hashes the
     *    signatures themselves and would be circular (§C.5, user lock O-2). ── */
    if (hdr.tx_type == DNAC_TX_SHIELD) {
        if (nctx->sig_verify == NULL) {
            rc = DNAC_SHIELDED_VERIFY_ERR_SIG; /* cannot check == reject */
            goto done;
        }
        for (unsigned i = 0; i < (unsigned)leg->num_signers; i++) {
            if (nctx->sig_verify(leg->signer[i].signature, DNAC_TXW_SIG_LEN,
                                 sighash, DNAC_TXW_HASH_LEN,
                                 leg->signer[i].pubkey) != 0) {
                rc = DNAC_SHIELDED_VERIFY_ERR_SIG;
                goto done;
            }
        }
    }

    /* ── Step 12: in-TX private nullifier distinctness (stateless half of
     *    double-spend detection; on-chain absence is S10). Transparent input
     *    duplicates are already dead — the codec's strictly-ascending rule
     *    rejects them (tx_wire.c:847-850). ── */
    if (nv3_nullifiers_distinct(&st) != 0) {
        rc = DNAC_SHIELDED_VERIFY_ERR_NF_DUP;
        goto done;
    }

    /* ── Step 13: the proof — ALL THREE TYPES (S9 CORRECTION PASS).
     *    The former "SEAM 2" is CLOSED. dnac_shielded_verify_statement used to
     *    derive the transparent-leg commitment itself (always the tagged-empty
     *    form), which restricted it to legless transactions; it now takes the
     *    commitment through dnac_shielded_verify_ctx_t.tleg_commit. So the very
     *    digest computed at step 7 above — tagged-empty for type 11, the real
     *    DNA.TLEG.v1 commitment for 12/13 — is what the statement entry binds,
     *    and every type runs the SAME real aggregate verifier: the frozen 45
     *    publics recomputed from the wire, the DZKF v4 decode, the pinned FRI
     *    params and the N-chunk AIR constraint check.
     *
     *    ONE digest, computed ONCE (step 7), consumed TWICE (this module's own
     *    sighash at step 8 and the statement entry's independent recompute) —
     *    they must agree or the statement fails ERR_TXBIND, which is exactly
     *    the cross-check that makes a leg substitution unforgeable. ── */
    {
        dnac_tx_shielded_fields_t sf;
        memset(&sf, 0, sizeof(sf));
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
            sf.anchor[j] = st.anchor[j];
        sf.num_input = st.num_input;
        for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++)
            for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                sf.nf_set[s][j] = st.nf_set[s][j];
        sf.num_output = st.num_output;
        for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++)
            for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                sf.output_commit[s][j] = st.output_commit[s][j];
        sf.fee = st.fee;
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
            sf.tx_binding[j] = st.tx_binding[j];
        sf.boundary_in   = st.boundary_in;
        sf.boundary_out  = st.boundary_out;
        sf.expiry_height = st.expiry_height;
        /* The blob stays where it is — a pointer INTO the caller's transaction
         * bytes, no copy. The const is cast away only because the struct field
         * is non-const for the client-side builder that OWNS the blob; the
         * verify entry never writes through it (it hands the pointer straight
         * to dnac_batch_wire_decode, shielded_verify.c:284). */
        sf.fri_proof     = (uint8_t *)(uintptr_t)fri;
        sf.fri_proof_len = fri_len;

        dnac_shielded_verify_ctx_t vctx;
        memset(&vctx, 0, sizeof(vctx));
        memcpy(vctx.chain_id, nctx->chain_id, sizeof(vctx.chain_id));
        vctx.domain_id         = nctx->domain_id;
        vctx.pool_id           = nctx->pool_id;
        vctx.tx_type           = hdr.tx_type;
        vctx.ruleset_version   = nctx->ruleset_version;
        vctx.statement_version = nctx->statement_version;
        memcpy(vctx.ruleset_hash, nctx->ruleset_hash,
               sizeof(vctx.ruleset_hash));
        /* The step-7 digest, handed over explicitly. This is the whole of the
         * correction: type 11 passes the tagged-empty form, 12/13 pass their
         * real leg commitment, and the statement entry binds what it is given
         * instead of assuming an empty leg. */
        memcpy(vctx.tleg_commit, tleg_commit, sizeof(vctx.tleg_commit));
        /* Forwarded VERBATIM: one status space, so the proof verdict reaches
         * the caller unflattened (this is why the new classes were appended to
         * the shared enum rather than declared in a private one). */
        rc = dnac_shielded_verify_statement(&sf, &vctx, hdr.committed_fee);
    }

    /* ── Step 14: export the DEFERRED (state, S10) expectations. Reached only
     *    when every stateless step passed, so `out` is either fully populated
     *    or fully zeroed — never half-written. Plain data: no verdict, no DB
     *    access, no callback. ── */
    if (out) {
        out->tx_type   = hdr.tx_type;
        out->domain_id = nctx->domain_id;
        out->pool_id   = nctx->pool_id;
        memcpy(out->sighash, sighash, sizeof(out->sighash));

        out->committed_fee = hdr.committed_fee;
        out->expiry_height = hdr.expiry_height;
        out->boundary_in   = st.boundary_in;
        out->boundary_out  = st.boundary_out;

        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
            out->anchor[j] = st.anchor[j];
        out->num_nullifier = st.num_input;
        for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++)
            for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                out->nullifier[s][j] = st.nf_set[s][j];
        out->num_output_commit = st.num_output;
        for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++)
            for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                out->output_commit[s][j] = st.output_commit[s][j];

        if (has_leg) {
            out->num_tin = leg->num_tin;
            for (unsigned i = 0; i < (unsigned)leg->num_tin; i++)
                memcpy(out->tin_nullifier[i], leg->tin_nullifier[i],
                       DNAC_TXW_NULLIFIER_LEN);
            out->num_tout = leg->num_tout;
            for (unsigned i = 0; i < (unsigned)leg->num_tout; i++)
                out->tout[i] = leg->tout[i];
            out->num_signers = leg->num_signers;
        }
        if (hdr.tx_type == DNAC_TX_SHIELD) {
            out->tin_sum_expected     = tout_sum; /* b_in + Σtout + fee */
            out->has_tin_sum_expected = 1u;
        }
    }

done:
    if (leg) {
        /* Transaction material hygiene, the dnac_tleg_commit convention
         * (tx_wire.c:1044): wipe before releasing. */
        memset(leg, 0, sizeof(*leg));
        free(leg);
    }
    return rc;
}
