/**
 * Nodus — the partial-wipe boot gate (H-10, PR 3 / E5)
 *
 * Split S5b (decision docs/plans/decisions/2026-10-01-nodus-component-
 * split.md item 9): the check moved out of nodus_server.c into its own
 * object, unchanged, so the nodus-storage process can run the SAME check
 * before it opens nodus.db / channels.db (which would otherwise recreate a
 * wiped file before core's gate looks). Core still runs it first thing in
 * nodus_server_init. No server dependency: a data path in, a verdict out.
 *
 * @file nodus_partial_wipe.h
 */

#ifndef NODUS_PARTIAL_WIPE_H
#define NODUS_PARTIAL_WIPE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PR 3 / E5 — Partial-wipe XOR check (H-10 mitigation).
 *
 * The 3 SQLite DB files under <data_path> (nodus.db, channels.db,
 * any witness_<hex>.db) MUST be in a consistent state at boot, but
 * the invariant is gated on the genesis marker
 * NODUS_PARTIAL_WIPE_GENESIS_MARKER (witness/nodus_witness_host.h):
 *
 *   - marker absent  -> pre-genesis (fresh node or mid-bootstrap),
 *                       any subset of the 3 DBs is allowed; pass
 *   - marker present + all 3 absent  -> someone wiped DBs but left
 *                                       the marker; treat as fresh
 *   - marker present + all 3 present -> normal running, pass
 *   - marker present + 1 or 2 present -> partial wipe, REFUSE START
 *
 * MUST be called BEFORE nodus_storage_open / nodus_channel_store_open
 * — those calls auto-create the missing files and defeat detection.
 *
 * Returns: 0 on consistent state (caller proceeds),
 *         -1 on partial-wipe detected (caller MUST refuse init).
 */
int nodus_server_check_partial_wipe(const char *data_path);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_PARTIAL_WIPE_H */
