/**
 * Nodus — Faz 1.9 — heartbeat signed checksum (C-1, partial concrete)
 *
 * Faz 4F (commit f3d676ee) added nodus_t3_ident_t.checksum_sig wire
 * field. This test locks the wire-layer invariant: the field exists
 * with NODUS_SIG_BYTES capacity. End-to-end signed-handshake
 * acceptance / Byzantine rejection (sub-tests 2-7 in original spec)
 * needs a 7-peer roster + Dilithium5 keypair fixture and is covered
 * by stagef harness (test_view_change_fork exercises peer auth).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "protocol/nodus_tier3.h"
#include "nodus/nodus_types.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

int main(void) {
    printf("\nFaz 1.9 — heartbeat checksum_sig wire invariant\n");

    nodus_t3_ident_t id = {0};
    /* Field exists, sized for Dilithium5 sig */
    CHECK(sizeof(id.checksum_sig) == NODUS_SIG_BYTES);
    /* Field zero-initializes (no leftover sig) */
    for (size_t i = 0; i < sizeof(id.checksum_sig); i++) {
        CHECK(id.checksum_sig[i] == 0);
    }
    printf("  checksum_sig[%d] field present + zero-init ✓\n",
           NODUS_SIG_BYTES);

    printf("Faz 1.9 PASS (wire invariant; full Byzantine rejection in stagef)\n");
    return 0;
}
