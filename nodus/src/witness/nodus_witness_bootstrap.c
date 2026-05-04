/**
 * Nodus — Witness Auto-Bootstrap (PR 3 Yol B)
 *
 * State machine implementation. C1 ships only the skeleton with the
 * public entry point as a no-op so the rest of the witness module can
 * link against it. Subsequent commits add:
 *
 *   - C2  HAVE_CHAIN branch (chain DB present → refresh bft_config)
 *   - C3  DISCOVER branch (peer mesh query, C-1 / C-2 / C-4 mitigations)
 *   - C4  --cold-bootstrap operator override (C-2 cold-DR escape)
 *   - C5  FETCH_GENESIS branch (atomic chain_def + genesis write, H-7)
 *   - C6  Wire bootstrap_start into nodus_witness_init
 *
 * @file nodus_witness_bootstrap.c
 */

#include "witness/nodus_witness_bootstrap.h"
#include "witness/nodus_witness.h"

#include <stddef.h>

int nodus_witness_bootstrap_start(nodus_witness_t *w) {
    if (!w) return -1;

    /* C1 stub: leave state at INIT and return success. The state
     * machine is filled in by C2 / C3 / C5 / C6. nodus_witness_init
     * does not yet call this function — that hook lands in C6 so the
     * earlier phases can be merged independently. */
    (void)w;
    return 0;
}
