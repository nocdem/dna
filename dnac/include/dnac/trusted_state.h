/**
 * @file trusted_state.h
 * @brief Runtime accessor for the current chain's trusted state.
 *
 * Phase 11 (Tasks 58-61) — hardcoded-constant refactor.
 *
 * Client code that needs per-chain parameters (token decimals, token symbol,
 * initial supply, witness roster size) must read them from the verified
 * trusted state produced by `dnac_genesis_verify` rather than from
 * compile-time `#define`s. This header provides a process-wide singleton
 * to look up those values without threading a `dnac_trusted_state_t *`
 * through every API.
 *
 * Lifecycle:
 *   1. Wallet init loads the hardcoded chain_id and calls
 *      `dnac_genesis_verify`, populating a local `dnac_trusted_state_t`.
 *   2. Wallet init calls `dnac_set_current_trusted_state(&trust)` once.
 *   3. Client code (CLI formatting, balance display, etc.) calls the
 *      inline helpers below.
 *
 * The helpers return safe defaults if the trust state has not been
 * initialized yet — they never crash — but production code paths MUST
 * always run after initialization (Phase 12 wires this up).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_TRUSTED_STATE_H
#define DNAC_TRUSTED_STATE_H

#include "dnac/ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @return Pointer to the current trusted state, or NULL if not initialized.
 *
 * The returned pointer is owned by the library; callers MUST NOT free it.
 * The underlying data is not mutated by the library after
 * `dnac_set_current_trusted_state` returns, so the pointer is stable for
 * the life of the process (until a subsequent set call overwrites it).
 */
const dnac_trusted_state_t *dnac_current_trusted_state(void);

/**
 * @brief Install the process-wide current trusted state.
 *
 * Copies `trust` into a static storage area. Intended to be called once
 * during wallet initialization, after `dnac_genesis_verify` succeeds.
 *
 * @param trust Non-NULL trusted state to copy.
 * @return 0 on success, -1 if `trust` is NULL.
 */
int dnac_set_current_trusted_state(const dnac_trusted_state_t *trust);

/* ============================================================================
 * Convenience accessors — read chain parameters with safe fallback defaults.
 *
 * The defaults exist so that code running before wallet init (unit tests,
 * early startup) does not crash. Do not rely on the default values as
 * consensus parameters — the real values always come from the verified
 * genesis block once the wallet is initialized.
 * ========================================================================== */

/** @return token_decimals from current trust, or 8 if uninitialized. */
static inline uint8_t dnac_current_token_decimals(void) {
    const dnac_trusted_state_t *t = dnac_current_trusted_state();
    return t ? t->chain_def.token_decimals : 8;
}

/** @return token_symbol C-string from current trust, or "DNAC" if uninit.
 *
 *  The returned pointer is either static storage or points into the
 *  singleton trust state; it stays valid for the life of the process.
 *  The string is NOT guaranteed NUL-terminated within the 8-byte on-chain
 *  field, so callers that need a NUL-terminated copy should snprintf it
 *  through a local buffer of size DNAC_TOKEN_SYMBOL_LEN+1. The default
 *  fallback is a literal "DNAC" and is always NUL-terminated.
 */
static inline const char *dnac_current_token_symbol(void) {
    const dnac_trusted_state_t *t = dnac_current_trusted_state();
    return t ? t->chain_def.token_symbol : "DNAC";
}

/** @return initial_supply_raw from current trust, or 0 if uninitialized. */
static inline uint64_t dnac_current_initial_supply(void) {
    const dnac_trusted_state_t *t = dnac_current_trusted_state();
    return t ? t->chain_def.initial_supply_raw : 0;
}

/** @return witness_count from current trust, or 0 if uninitialized. */
static inline uint32_t dnac_current_witness_count(void) {
    const dnac_trusted_state_t *t = dnac_current_trusted_state();
    return t ? t->chain_def.witness_count : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* DNAC_TRUSTED_STATE_H */
