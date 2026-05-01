/**
 * Nodus — Faz 1C / Test 1.13 — wire protocol version cross-version reject
 *
 * RED state — failing test by design until Faz 2.5 frame-layer
 * protocol version reject.
 *
 * Audit ref: C-5 (CRITICAL). With wire format change (commit_t.bh +
 * sync_rsp.state_root) plus chain wipe deploy, stop-all assumption
 * means same-version cluster post-deploy. But:
 *   - If one node has systemd auto-restart and boots old binary
 *     against new peers → v0.17 ↔ v0.18 mismatch
 *   - v0.17 sender → v0.18 receiver: cmt.bh missing → bh=0 → reject
 *     (safe-fail per Faz 1A test 1.3) ✓
 *   - v0.18 sender → v0.17 receiver: v0.17 ignores unknown CBOR key
 *     → applies commit at wrong height → ORIGINAL BUG TRIGGERS AGAIN
 *
 * Mitigation: NODUS_PROTOCOL_VERSION bump v2 → v3, frame header
 * version field, mismatch reject at TCP 4004 frame layer (before
 * CBOR decode).
 *
 * Scenario (target after Faz 2.5):
 *   Sub-test A — same version accepted:
 *     1. Build T3 frame with version = 3
 *     2. Frame layer accepts, dispatches to handler
 *
 *   Sub-test B — old version rejected at frame:
 *     1. Build T3 frame with version = 2
 *     2. Frame layer rejects with error before CBOR decode
 *     3. Verify log "wire protocol version mismatch (got=2, expected=3)"
 *
 *   Sub-test C — newer version (forward-incompat) rejected:
 *     1. Build T3 frame with version = 4
 *     2. Frame layer rejects (defensive — we don't know what's coming)
 *
 *   Sub-test D — non-T3 frames (T1/T2) unaffected:
 *     1. Build Tier 1 ping with version = 2 (current Tier 1 version)
 *     2. Verify still accepted (only Tier 3 bumped)
 *
 * Wire format: frame header layout per nodus_types.h —
 *   `magic(2) + version(1) + length(4) = 7 bytes`. Version is per-frame.
 *
 * Blocked on Faz 2.5 (frame layer protocol version check).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    fprintf(stderr,
        "test_wire_protocol_version_reject: STUB — failing by design.\n"
        "  Concrete assertion blocked on Faz 2.5 frame-layer protocol\n"
        "  version reject (NODUS_PROTOCOL_VERSION bump v2 -> v3).\n");
    return 1;
}
