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
 * ── FAULT vs VERDICT ───────────────────────────────────────────────────
 * The engine convention, preserved end to end:
 *   0  accept (committed)
 *   1  idempotent replay — already committed, nothing written
 *  -1  VERDICT: this block is invalid as judged against COMMITTED chain
 *      state. Every honest node with the same committed state agrees.
 *      CAVEAT (O14 review R2-F4): the apply engine also returns -1 for
 *      local SEQUENCING conditions — notably a height gap, "not the next
 *      block in MY chain" — which a node that is merely behind will
 *      report while synced peers accept the same bytes. A caller must
 *      NOT read -1 as proof of proposer misbehaviour, and must not
 *      blacklist on it. Splitting that into its own not-yet-linkable
 *      code is deferred design, not something to fake here.
 *  -2  FAULT: THIS NODE could not decide (no committed authority for the
 *      epoch, storage/hash/alloc failure). The caller must not vote and
 *      must never convert -2 into a rejection.
 * A -2 from the QC verifier surfaces as -2 here. It is never folded into
 * a reject: a node that cannot learn who was permitted to sign has to
 * stay silent, because silence is survivable at f=2 and a confident
 * wrong answer forks the chain.
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
 * @return 0 committed / 1 idempotent replay / -1 verdict / -2 fault.
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
 * HONEST SCOPE (O14 review R3-F3): that is the DB-CREATION path only.
 * `witness_scan_chain_db` opens an existing chain DB by another route and
 * runs neither this check nor the S7 pool check — so "once per database
 * open" would be wrong. It matters little for THIS check, which is pure
 * and build-dependent rather than data-dependent (a broken build is
 * broken on every path, and the link edge it secures is a compile-time
 * property), but the claim is stated accurately rather than
 * conveniently. The S7 bypass on the same path is a pre-existing seam.
 *
 * Probes:
 *   - a RETIRED (v2) header byte must be a verdict (-1);
 *   - an UNKNOWN header byte must be a verdict (-1);
 *   - a NULL argument must be a node fault (-2), not a verdict.
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
