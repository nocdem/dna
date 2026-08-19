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
 * ═══ CANONICAL LAYOUT ═══════════════════════════════════════════════════
 *   magic "DNA.GBUNDLE.v1\0\0" (16 B) ‖ manifest_len u32 BE ‖ manifest ‖
 *   table_count u32 BE ‖ per table:
 *     name_len u16 BE ‖ name ‖ row_count u32 BE ‖ col_count u16 BE ‖
 *     per row (row_count of them), per column (col_count of them):
 *       type u8 (0 NULL / 1 INT / 2 TEXT / 3 BLOB — FLOAT rejects) ‖
 *       INT: 8 B BE ; TEXT/BLOB: len u32 BE ‖ bytes ; NULL: nothing
 *   Rows are emitted in PRIMARY-KEY order (the table's ORDER BY), so two
 *   nodes serialize the same committed state to the same bytes.
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

#define NODUS_V2_GBUNDLE_MAGIC   "DNA.GBUNDLE.v1\0\0"
#define NODUS_V2_GBUNDLE_MAGIC_LEN 16

/**
 * Build the canonical genesis bundle for the committed successor genesis
 * on `w` and persist it into the `v2_genesis_bundle` singleton row.
 *
 * Called by the seam ONCE, after v2_genesis_ex commits and before any
 * block production. Fails closed and writes nothing if the genesis
 * manifest or any base table cannot be serialized, or the row already
 * exists with different bytes.
 *
 * @return 0 persisted (or idempotent match); -1 fault.
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
 * tables), re-derive the genesis, and require the derived genesis
 * BlockID to equal `pin` (the operator's local anchor). On success the
 * DB carries the committed successor genesis and its own persisted
 * bundle row; on any mismatch nothing is left committed (the caller
 * discards the scratch DB).
 *
 * ORDER (mirrors the seam, load-bearing): plant base rows →
 * vset_commit_genesis → domreg_init_genesis → v2_genesis_ex(pin
 * assertion). The vset snapshots feed the SYSTEM payload root that
 * domreg commits, so snapshots precede domreg precede genesis.
 *
 * @param w2   fresh successor witness (chain DB created, S11 migrated).
 * @param bytes/len  the received bundle.
 * @param pin  the 64-byte locally-pinned successor genesis BlockID.
 * @return 0 adopted; -1 rejected (wrong pin / malformed / fault).
 */
int nodus_witness_v2_bundle_apply(nodus_witness_t *w2,
                                  const uint8_t *bytes, size_t len,
                                  const uint8_t pin[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_BUNDLE_H */
