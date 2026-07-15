/**
 * @file conf_txbind.h
 * @brief tx_binding for the confidential sandbox (B1 Stage-1, SEC-5 mechanism).
 *
 * Binds a confidential proof to a specific transaction (the SEC-5 replay-resistance
 * MECHANISM) so a valid proof for one tx does not transfer to another. Two pieces:
 *
 *  1. **Byte→Goldilocks map** (design v3.1 §4a) — truncate the 64-byte SHA3-512
 *     sighash to N=4 canonical Goldilocks elements by the SAME rejection convention
 *     the DNAC challenger already uses (transcript.c:380-388: walk 8-byte LE groups,
 *     accept `u < p`, skip otherwise, take the first 4). Grounded, not invented;
 *     reduce-mod-p is FORBIDDEN (double-covers low residues → bias).
 *
 *  2. **tx-bound root** — fold `tx_binding` into the commitment-set root
 *     (`conf_root_air_fold_step`), so the proof's public output binds BOTH the
 *     ordered commitment set AND the tx sighash. A different tx ⇒ a different
 *     bound root ⇒ the proof does not transfer.
 *
 * SANDBOX scope (design v3.1 §1): the sighash is a self-contained SYNTHETIC one
 * — `SHA3-512("DNAC_B1_SANDBOX_V3\0" ‖ tx_context)` — it never reads/writes the
 * live DNAC tx wire. Honest caveat (§4c): real replay resistance additionally
 * needs the deferred nullifier layer; this demonstrates the binding MECHANISM.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_TXBIND_H
#define DNAC_ZK_CONF_TXBIND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of Goldilocks lanes in tx_binding (design v3.1 §4: N = 4, ~256-bit). */
#define CONF_TXBIND_LANES 4

/** SHA3-512 sighash length. */
#define CONF_TXBIND_SIGHASH_LEN 64

/**
 * @brief Rejection map: 64-byte sighash → N=4 canonical Goldilocks elements.
 *
 * Walks the digest in consecutive 8-byte little-endian groups; accepts a group
 * `u` iff `u < GOLDILOCKS_P`, else SKIPS it; takes the first 4 accepted. Mirrors
 * the DNAC challenger convention (transcript.c). Per-group reject prob ≈ 2^-32.
 *
 * @return true on success; false (fail-close) if fewer than 4 groups accept
 *         (probability ≪ 2^-100) — never reduce-mod-p as a fallback.
 */
bool conf_txbind_map(const uint8_t sighash[CONF_TXBIND_SIGHASH_LEN],
                     uint64_t out[CONF_TXBIND_LANES]);

/**
 * @brief Sandbox synthetic sighash = SHA3-512("DNAC_B1_SANDBOX_V3\0" ‖ ctx).
 *        Domain-separated from every live DNAC hash; never touches the tx wire.
 */
void conf_txbind_sandbox_sighash(const uint8_t *ctx, size_t ctx_len,
                                 uint8_t out[CONF_TXBIND_SIGHASH_LEN]);

/**
 * @brief tx-bound root = W(commitment_root, tx_binding) — one capacity-IV fold,
 *        binding the proof output to BOTH the commitment set and the tx.
 */
void conf_txbind_bound_root(const uint64_t commitment_root[CONF_TXBIND_LANES],
                            const uint64_t tx_binding[CONF_TXBIND_LANES],
                            uint64_t out[CONF_TXBIND_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_TXBIND_H */
