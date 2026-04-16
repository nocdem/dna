/**
 * @file current_trust.c
 * @brief Process-wide current trusted state singleton.
 *
 * Phase 11 (Tasks 58-61). See dnac/include/dnac/trusted_state.h for the
 * rationale. No locking is provided: the set path is expected to run
 * once during single-threaded wallet init. Once installed, the struct
 * is treated as immutable by readers; subsequent sets (e.g. hot chain
 * swap in tests) must serialize with all readers out-of-band.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/trusted_state.h"

#include <stdbool.h>
#include <string.h>

static dnac_trusted_state_t g_current_trust;
static bool                 g_current_trust_valid = false;

const dnac_trusted_state_t *dnac_current_trusted_state(void) {
    return g_current_trust_valid ? &g_current_trust : NULL;
}

int dnac_set_current_trusted_state(const dnac_trusted_state_t *trust) {
    if (!trust) {
        return -1;
    }
    memcpy(&g_current_trust, trust, sizeof(g_current_trust));
    g_current_trust_valid = true;
    return 0;
}
