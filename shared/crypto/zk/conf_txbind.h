/**
 * @file conf_txbind.h
 * @brief tx_binding for the confidential sandbox (B1 Stage-1, SEC-5 mechanism).
 *
 * Binds a confidential proof to a specific transaction (the SEC-5 replay-resistance
 * MECHANISM) so a valid proof for one tx does not transfer to another. Two pieces:
 *
 *  1. **Byte→Goldilocks map** (design v3.1 §4a) — walk the 64-byte SHA3-512 sighash
 *     in 8 little-endian u64 groups, ACCEPT a group iff `u < GOLDILOCKS_P`, SKIP it
 *     otherwise, and take the first 4 accepted (`conf_txbind.c:36-43`). Fail-CLOSE if
 *     fewer than 4 of the 8 groups are canonical.
 *
 *     ⚠ GROUNDING STATUS: **DNAC-owned rejection convention, not upstream-grounded.**
 *     This block previously claimed grounding by pointing at "the SAME rejection
 *     convention the DNAC challenger already uses (transcript.c:380-388)". That
 *     citation is DEAD: the SHA3 HashChallenger it referred to was deleted in the P1c
 *     Poseidon2 cutover, and `transcript.c` is now a 124-line duplex wrapper — the
 *     cited range does not exist. It was in any case an INTERNAL citation, so it never
 *     grounded the convention against anything outside this tree; it only asserted that
 *     two DNAC sites agreed. Corrected 2026-07-28 rather than re-pointed, because
 *     re-pointing it at `conf_txbind.c:40` would make the claim circular.
 *
 *     What IS sound here, and is the actual argument: reduce-mod-p is FORBIDDEN because
 *     a 64-bit value reduced into p = 2^64 - 2^32 + 1 double-covers the low residues
 *     [0, 2^32 - 2), biasing the map. Rejection sampling is the standard fix and costs
 *     nothing: a uniform u64 is non-canonical with probability (2^32 - 1)/2^64 ≈ 2^-32,
 *     so with 8 candidate groups the chance that fewer than 4 are canonical is far
 *     below 2^-100 — which is why the fail-close path is unreachable in practice and
 *     is nevertheless kept fail-CLOSE rather than falling back to reduction.
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
