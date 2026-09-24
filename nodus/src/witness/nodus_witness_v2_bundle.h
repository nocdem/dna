/**
 * @file nodus/src/witness/nodus_witness_v2_bundle.h
 * @brief Ledger V2 O15E Faz D — the canonical successor GENESIS BUNDLE.
 *
 * ═══ WHAT THIS IS ═══════════════════════════════════════════════════════
 * A fresh node joining a successor chain has no way to acquire the
 * successor's genesis over the legacy bootstrap path (a successor answers
 * no legacy w_chain_q — bootstrap.c:707-708), and it MUST NOT accept a
 * peer's claimed genesis on trust. The bundle is the byte material a
 * joiner needs to RE-DERIVE the genesis itself and prove it equals a
 * locally-pinned successor genesis BlockID.
 *
 * ═══ WHY IT IS PERSISTED AT DERIVATION TIME, NOT REBUILT ════════════════
 * The genesis-time rows CANNOT be reconstructed from committed state once
 * the successor has produced even one block: Rule N attendance mutates
 * `validators` every block (the O15C seam runs the attendance writer
 * inside the apply transaction), and CHAIN_CONFIG envelopes add
 * `chain_config_history` rows. Filtering current rows back to their
 * genesis shape would be fabrication. So the seam serializes the exact
 * genesis-time bytes ONCE, immediately after genesis commits and before
 * any block can be produced, into the immutable `v2_genesis_bundle` row.
 * Serving reads those bytes; a successor DB without the row fails closed
 * as a bootstrap source. This mirrors Faz B's envelope-byte persistence.
 *
 * ═══ INTEGRITY MODEL ════════════════════════════════════════════════════
 * The bundle is NOT trusted for being well-formed. The joiner replants the
 * rows, re-runs the SAME genesis derivation the seam ran, and the engine
 * derives the genesis BlockID — which must equal the joiner's LOCAL pin
 * (operator-supplied, never wire-settable). A wrong bundle produces a
 * different BlockID and the pin assertion refuses; nothing is adopted.
 * The bundle format is therefore a CONTAINER of already-canonical row
 * bytes, not a crypto-committed structure — no KAFADAN gate applies.
 *
 * ═══ CANONICAL LAYOUT (R3 W3, D-24 rev 4 (2); root-layout round K2) ═════
 *   magic "DNA.GBUNDLE.v4\0\0" (16 B) ‖ manifest_len u32 BE ‖ manifest ‖
 *   table_count u32 BE (= 5: validators, delegations,
 *   chain_config_history, supply_tracking, validator_stats) ‖ per table:
 *     name_len u16 BE ‖ name ‖ row_count u32 BE ‖ col_count u16 BE ‖
 *     per row (row_count of them), per column (col_count of them):
 *       type u8 (0 NULL / 1 INT / 2 TEXT / 3 BLOB — FLOAT rejects) ‖
 *       INT: 8 B BE ; TEXT/BLOB: len u32 BE ‖ bytes ; NULL: nothing
 *   ‖ doc_len u32 BE ‖ doc (the version-3 genesis DOCUMENT's canonical
 *     bytes)
 *   Rows are emitted in PRIMARY-KEY order (the table's ORDER BY), so two
 *   nodes serialize the same committed state to the same bytes.
 *
 * ═══ ROOT-LAYOUT ROUND (K2, 2026-09-25) — v3 → v4 ═══════════════════════
 * The `epoch_state` table is dropped from the schema, so the bundle
 * carries FIVE tables (was six) and the magic moved to
 * `DNA.GBUNDLE.v4\0\0`. A `DNA.GBUNDLE.v3\0\0` bundle is refused BY ITS
 * MAGIC ("version-3 bundle format, refused"), the same way the v1 magic
 * is below — never read as a v4 frame.
 *
 * ═══ R3 W3 — THE MAGIC MOVED; THE OLD LANE CANNOT BE BUNDLED ════════════
 * R3 W3 moved the magic to `DNA.GBUNDLE.v3\0\0`. A version-2 chain (no stored
 * genesis DOCUMENT — D-19 rev 6 is v3-only) CANNOT be bundled at all:
 * `nodus_witness_v2_bundle_persist` refuses when there is no document to
 * carry, which is D-17 rev 10 (9)'s closure of the old lane applied here
 * — a chain that cannot serve a correct bundle must not claim to serve
 * one. `nodus_witness_v2_bundle_apply` refuses a bundle carrying the OLD
 * `DNA.GBUNDLE.v1\0\0` magic outright, logging "version-1 bundle format,
 * refused", before reading anything past it — an old-binary bundle is
 * refused BY ITS MAGIC, never by a short read further in. There is no
 * version-2 code path left in this file, and the version-2 engine
 * genesis it used to call (`nodus_witness_v2_genesis_ex`) no longer
 * exists — tokenomics-v3 P4 deleted it.
 * The version-2 DERIVATION (`nodus_witness_v2_gen_derive`), which after
 * R3 W3 derived with no persisted bundle, is DELETED by tokenomics-v3 P4
 * (OBLIGATION atlas-dec-71525f3b). The only derivation left,
 * `nodus_witness_v2_gen_derive_v3`, stores the document first and then
 * persists the bundle (its step 12). test_v2_bundle.c proves the refusal
 * above on a version-3 chain whose document was removed.
 *
 * ═══ THE VERSION-3 PIN, AND WHAT IT BINDS ═══════════════════════════════
 * `pin` is 32 bytes — the chain id (D-24 rev 4 (1); a version-3 chain has
 * no genesis BLOCK to pin a 64-byte BlockID to, D-19 rev 6). Accepting a
 * version-3 bundle requires TWO things to hold, not one: the stored
 * document's own `chain_id` field equals `pin` (the canonical-strict
 * reader, `nodus_witness_v2_gen_stored_doc`, already proves that field
 * hashes to the document itself), AND the document's `app_hash` field
 * equals the global root `nodus_witness_v2_genesis_cmt` ACTUALLY returned
 * from replanting THIS bundle's tables. The first proves the document is
 * intact; it does not prove the replanted rows produce that document's
 * claimed ledger effect — a bundle whose tables are tampered (a delegation
 * row edited) but whose untouched document still hashes to `pin` would
 * pass the first check and fail only the second. Both are required before
 * anything is renamed up; a wrong pin, a malformed bundle or a tampered
 * table leaves the caller's scratch DB to discard, exactly as before.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NODUS_WITNESS_V2_BUNDLE_H
#define NODUS_WITNESS_V2_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_V2_GBUNDLE_MAGIC   "DNA.GBUNDLE.v4\0\0"
#define NODUS_V2_GBUNDLE_MAGIC_LEN 16

/** The RETIRED six-table magic (root-layout round K2, 2026-09-25): a v3
 * bundle carries `epoch_state`, which this build's schema no longer has.
 * Kept only so `nodus_witness_v2_bundle_apply` names the refusal
 * ("version-3 bundle format, refused"), exactly like the v1 magic below.
 * Never written by this build. */
#define NODUS_V2_GBUNDLE_MAGIC_V3_RETIRED "DNA.GBUNDLE.v3\0\0"

/** The RETIRED version-2 magic, kept only so `nodus_witness_v2_bundle_
 * apply` can name the reason a pre-R3-W3 bundle is refused ("version-1
 * bundle format, refused") instead of failing on a generic short read
 * further into the frame. Never written by this build. */
#define NODUS_V2_GBUNDLE_MAGIC_V1_RETIRED "DNA.GBUNDLE.v1\0\0"

/**
 * Build the canonical genesis bundle for the committed successor genesis
 * on `w` and persist it into the `v2_genesis_bundle` singleton row.
 *
 * Called ONCE, after the genesis commits and before any block production.
 * Fails closed and writes nothing if the genesis manifest or any base
 * table cannot be serialized, the row already exists with different
 * bytes, OR — R3 W3 — `w` has no stored genesis DOCUMENT under
 * "genesisDoc" (a version-2 chain, or a version-3 chain not yet at S14):
 * a chain that cannot carry a document cannot serve a correct bundle.
 *
 * @return 0 persisted (or idempotent match); -1 fault / refused.
 */
int nodus_witness_v2_bundle_persist(nodus_witness_t *w);

/**
 * Read the persisted bundle bytes (malloc'd; caller frees).
 *
 * @return 0 with out and len set; 1 no bundle row (fail-closed source);
 *         -1 fault.
 */
int nodus_witness_v2_bundle_get(nodus_witness_t *w,
                                uint8_t **out, size_t *len);

/**
 * Apply a received bundle to a FRESH successor DB `w2` (empty base
 * tables), re-derive the genesis, and require it to match `pin` — the
 * 32-byte chain id (D-24 rev 4 (1)). On success the DB carries the
 * committed successor genesis and its own persisted bundle row.
 *
 * On a rejection (wrong magic, malformed frame, wrong pin, or a
 * tampered table caught by the app_hash check) this function guarantees
 * only that no genesis derivation step runs and no genesis document is
 * stored — it does NOT guarantee the scratch database is otherwise
 * unchanged: the base-table plant (its own BEGIN IMMEDIATE / COMMIT,
 * before the pin precheck even runs) is already durably committed by
 * the time any rejection can be detected, so a rejected `w2` still
 * holds the sender's rows in the six base tables. "Zero trace" is a
 * property of the CALLER, not of this function: `nodus_witness_v2_join.c`
 * (`join_adopt`) provides it by discarding the whole scratch directory
 * (`join_scratch_clear`) on every failure exit. A direct caller that
 * does not discard the scratch DB on a nonzero return keeps those
 * planted rows.
 *
 * A bundle carrying the RETIRED version-2 magic is refused immediately,
 * logged "version-1 bundle format, refused" — there is no version-2
 * code path in this function (the version-2 engine genesis,
 * `nodus_witness_v2_genesis_ex`, was deleted by tokenomics-v3 P4).
 *
 * ORDER: plant base rows → migrate the scratch database to S14
 * (cascades up from wherever it already is,
 * nodus_witness_v2_schema.c's ladder) → store the carried document
 * under "genesisDoc" → vset_commit_genesis → domreg_init_genesis →
 * nodus_witness_v2_genesis_cmt → ACCEPT only if BOTH the stored
 * document's `chain_id` equals `pin` AND its `app_hash` equals the
 * global root genesis_cmt just returned (the header's "what pin binds"
 * note explains why both are required). The pin's OWN self-consistency
 * (the carried document decodes and hashes to `pin`) is checked BEFORE
 * any of that runs, because genesis_cmt takes no pin parameter and is
 * not idempotent-safe to call on a pin that will turn out wrong.
 *
 * @param w2   fresh successor witness (chain DB created; any schema the
 *             migration ladder can reach S14 from).
 * @param bytes/len  the received bundle.
 * @param pin  the 32-byte chain id this joiner is pinned to.
 * @return 0 adopted; -1 rejected (wrong magic / wrong pin / malformed /
 *         tampered table / fault).
 */
int nodus_witness_v2_bundle_apply(nodus_witness_t *w2,
                                  const uint8_t *bytes, size_t len,
                                  const uint8_t pin[32]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_BUNDLE_H */
