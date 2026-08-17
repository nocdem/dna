/**
 * @file nodus/src/witness/nodus_witness_v2_finalize.h
 * @brief Ledger V2 O14 — the PRODUCTION V2 block-acceptance seam.
 *
 * ═══ ACTIVATION: NO EXTERNAL INGRESS ════════════════════════════════════
 * This is production code on the production call graph, and it is the
 * first and only production caller of `nodus_witness_v2_qc_verify`. It is
 * NOT reachable from the network: no wire message can carry a header v3,
 * a QC V2 or a Ledger V2 envelope, because `nodus/src/{protocol,server,
 * client,transport}` reference no Ledger V2 identity object at all. The
 * live tx-admission gate (`nodus_witness_verify.c`, wire version byte)
 * rejects every non-V2 transaction wire before signature work.
 *
 * So V2 blocks cannot be SUBMITTED — not because a flag is off, but
 * because no wire form exists to express one. Opening that ingress is
 * O15 work and needs its own authorization. Tests and harnesses drive
 * this entry point directly.
 *
 * The LEGACY path is untouched. Legacy blocks continue through
 * `finalize_block` (nodus_witness_bft.c) and the 144-byte certificate
 * path (nodus_witness_cert.{h,c}); this file adds no branch to either,
 * and nothing here can be reached from them.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHY A SEPARATE ENTRY POINT, NOT A BRANCH ──────────────────────────
 * A v3 failure must NEVER fall back to legacy verification. Making that
 * structural rather than a flag is the point of a distinct function with
 * a distinct signature: there is no shared retry, no shared error path,
 * and no way to "try v3, then try legacy" without writing that loop
 * explicitly somewhere a reviewer would see it.
 *
 * ── ORDER (all authority BEFORE any durable mutation) ─────────────────
 *   1. Explicit version dispatch on the ENCODED header's version byte.
 *      The retired version 2 and any unknown version are two distinct
 *      fail-closed classes; neither is reinterpreted under the v3 layout.
 *   2. Strict decode — exactly DNA_BH2_ENC_SIZE bytes.
 *   3. Compute the claimed BlockID from the decoded header, ONCE.
 *   4. `nodus_witness_v2_qc_verify` — resolves the governing snapshot
 *      from COMMITTED state itself, recomputes the BlockID itself, and
 *      checks every signature over it. No snapshot, set hash, N or
 *      quorum can be proposed here, because that function takes no such
 *      argument.
 *   5. ── nothing durable has happened yet ──
 *   6. `nodus_witness_v2_apply_block`, handed the claimed header's
 *      commitments as EQUALITY ASSERTIONS and the encoded QC as opaque
 *      bytes that ride the block's ONE transaction.
 *   7. Require the engine's independently derived BlockID to equal the
 *      one the QC certified.
 *
 * ── THE RESULT CLASSES ─────────────────────────────────────────────────
 * The full contract is `nodus_witness_v2_result.h` (nodus_v2_result_t);
 * this seam returns those values unchanged. In summary:
 *
 *   NODUS_V2_ACCEPTED (0) / IDEMPOTENT_REPLAY (1) / ACCEPTED_PRECACHE (2)
 *      the block was accepted.
 *   NODUS_V2_CONSENSUS_INVALID (-1) / RETIRED_VERSION (-4) /
 *   UNSUPPORTED_VERSION (-5)
 *      VERDICTS: deterministic judgements about the block. Every honest
 *      node with the same committed state agrees. Only these may be held
 *      against the peer that offered the block.
 *   NODUS_V2_NOT_YET_LINKABLE (-3)
 *      NO judgement. Required predecessor state is absent HERE, so the
 *      block could not be evaluated. It may be perfectly valid.
 *   NODUS_V2_INTERNAL_FAULT (-2)
 *      NO judgement. THIS NODE could not compute — absent committed
 *      authority for the epoch, storage, hashing or allocation failure.
 *
 * O15A CLOSED A HAZARD HERE. Until this season the apply engine returned
 * -1 for local SEQUENCING conditions as well as for genuine invalidity,
 * so a height gap — "not the next block in MY chain" — was indistinguish-
 * able from "this block is bad". A node that was merely behind reported
 * the same code that synced peers never produced for those bytes, and a
 * caller that blacklisted on -1 would have punished honest proposers for
 * its own lag. That caveat used to live in this comment because the type
 * system had no way to express it; it is now NODUS_V2_NOT_YET_LINKABLE,
 * and the rule is enforced by the type rather than by the reader.
 *
 * Neither -2 nor -3 is ever folded into a reject. A node that cannot
 * learn who was permitted to sign, or that does not yet hold the block's
 * predecessors, has to stay silent: silence is survivable at f=2, and a
 * confident wrong answer forks the chain.
 *
 * Requesting or queueing the history behind a -3 is a SYNC concern and is
 * deliberately not implemented here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_FINALIZE_H
#define NODUS_WITNESS_V2_FINALIZE_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_apply.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Accept one FINALIZED Ledger V2 block: verify its certificate against
 * committed authority, then execute and commit it atomically.
 *
 * `blk` carries the block's CONTENT (envelopes, claims, pool batches,
 * proposer_id, timestamp, fault-injection selectors). Its identity
 * fields are ignored as inputs and filled as outputs — this function
 * sets the `expect_*` assertions from the decoded header itself, so a
 * caller cannot weaken them.
 *
 * @param w            witness handle.
 * @param header_bytes canonical encoded BlockHeader (any version — the
 *                     version byte is dispatched here).
 * @param header_len   length of `header_bytes`.
 * @param qc_bytes     canonical encoded QC V2.
 * @param qc_len       length of `qc_bytes`.
 * @param blk          the block content; identity outputs are filled.
 * @return a nodus_v2_result_t. Callers MUST distinguish the classes and
 *         must not collapse them into accept/reject — see the class list
 *         above and nodus_witness_v2_result.h.
 */
int nodus_witness_v2_finalize_block(nodus_witness_t *w,
                                    const uint8_t *header_bytes,
                                    size_t header_len,
                                    const uint8_t *qc_bytes,
                                    size_t qc_len,
                                    nodus_v2_block_t *blk);

/**
 * Startup assertion that this build's V2 version firewall is intact.
 *
 * Runs from nodus_witness_create_chain_db, beside the S7 pool check, and
 * drives the REAL entry point above with committed-state-free inputs.
 *
 * SCOPE (O14 review R3-F3, CLOSED by O15A): O14 recorded that this ran on
 * the DB-CREATION path only, because `witness_scan_chain_db` — the
 * RESTART route — opened an existing chain database without running
 * either this check or the S7 pool check. That seam is now closed: both
 * paths go through the single `witness_post_open_gate`
 * (nodus_witness.c), so "once per database open" is accurate for both,
 * and the S7 bypass on the restart path is closed with it.
 *
 * Probes:
 *   - a RETIRED (v2) header byte must be NODUS_V2_RETIRED_VERSION;
 *   - an UNKNOWN header byte must be NODUS_V2_UNSUPPORTED_VERSION —
 *     a DIFFERENT class, so this probe also proves the two remain
 *     distinguishable rather than merely both non-zero;
 *   - a NULL argument must be NODUS_V2_INTERNAL_FAULT, not a verdict.
 *
 * PURE and INERT by construction: every probe returns from the version
 * dispatch or the NULL guard, so it resolves no snapshot, verifies no
 * certificate, reads no row and requires no schema version. It passes
 * vacuously on a legacy v0 database exactly as it does on a v9 one — a
 * legacy chain's open MUST NOT come to depend on Ledger V2 state.
 *
 * This is also what puts the production seam — and therefore the
 * finalize → nodus_witness_v2_qc_verify link edge — into the linked
 * server binary rather than leaving it as an object the linker discards.
 *
 * @return 0 intact, -1 the firewall is broken on this build (the caller
 *         refuses the database, mirroring the S7 pool check).
 */
int nodus_witness_v2_finalize_selfcheck(nodus_witness_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_FINALIZE_H */
