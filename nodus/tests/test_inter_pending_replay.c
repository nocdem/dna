/* Build plan 4.3: Queued frames are released sealed in both directions; backpressure retains order; stale worker results cannot reopen reused slots.
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
    happy_path(); backpressure(); full_queue_and_generation();
    nodus_identity_clear(&ids[0]); nodus_identity_clear(&ids[1]);
    return 0;
}
