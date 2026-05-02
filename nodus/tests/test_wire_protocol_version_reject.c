/**
 * Nodus — Faz 1.13 — wire protocol version cross-version reject (concrete)
 *
 * Audit C-5 mitigation, AS SHIPPED (revised from original spec):
 * The cluster carries NODUS_FRAME_VERSION = 0x02 plus dual-support for
 * NODUS_FRAME_VERSION_LEGACY = 0x01 (commit 139e4073) so pre-v0.18
 * client APKs continue to connect after the v0.18.0 wire bump
 * (commit 9494d402). Frame-level reject still gates clearly-invalid
 * versions.
 *
 * Sub-A: current (0x02) accepted
 * Sub-B: legacy (0x01) accepted (backward compat shim)
 * Sub-C: future (0x03) rejected (forward-incompat defense)
 * Sub-D: arbitrary non-listed (0x99) rejected
 *
 * Original C-5 spec (NODUS_PROTOCOL_VERSION v2→v3 with hard cutover
 * reject of 0x02) was REVERSED — production users with old APKs were
 * locked out for hours. Dual-support is the production-viable shape
 * of C-5; documentation in nodus_types.h "Wire frame" comment.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "protocol/nodus_wire.h"
#include "nodus/nodus_types.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

int main(void) {
    printf("\nFaz 1.13 — wire protocol version reject\n");

    nodus_frame_t f = {0};
    f.payload_len = 10;
    f.payload = NULL;

    /* Sub-A: current accept */
    f.version = NODUS_FRAME_VERSION;          /* 0x02 */
    CHECK(nodus_frame_validate(&f, false));
    CHECK(nodus_frame_validate(&f, true));
    printf("  sub-A: 0x02 accepted (TCP+UDP) ✓\n");

    /* Sub-B: legacy accept (backward compat shim, commit 139e4073) */
    f.version = NODUS_FRAME_VERSION_LEGACY;   /* 0x01 */
    CHECK(nodus_frame_validate(&f, false));
    printf("  sub-B: 0x01 legacy accepted ✓\n");

    /* Sub-C: forward-incompat reject */
    f.version = 0x03;
    CHECK(!nodus_frame_validate(&f, false));
    printf("  sub-C: 0x03 forward rejected ✓\n");

    /* Sub-D: clearly invalid reject */
    f.version = 0x99;
    CHECK(!nodus_frame_validate(&f, false));
    printf("  sub-D: 0x99 invalid rejected ✓\n");

    printf("Faz 1.13 PASS\n");
    return 0;
}
