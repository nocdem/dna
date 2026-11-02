/* Build plan 4.3: Dialer against an independent raw-machine acceptor: sealed stream, pin at ENCAPS, and missing pin.
 * Reuse the real-machine fixture and raw-peer checks of test_inter_session.
 * Flags: none; also ASan/UBSan. Environment: none. Leaves nothing.
 * Positive controls require delivered frames; no worker progress cannot pass.
 */
#define main inter_session_fixture_all_cases
#include "test_inter_session.c"
#undef main
int main(void) {
    (void)inter_session_fixture_all_cases;
    CHECK(nodus_identity_generate(&ids[0])==0 && nodus_identity_generate(&ids[1])==0);
    wire_and_pin(false); wire_and_pin(true); no_pin();
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]);
    return 0;
}
