/*
 * test_call_fsm.c — PQ VoIP Faz A call state machine (dna_call_fsm_step).
 *
 * Pure (state,event)->(state',action) transition table. Covers caller and
 * callee happy paths, reject/busy/timeout, absorbing ENDED, idempotent no-op
 * for unexpected/late/duplicate events (design §4.1, §1.1.5 determinism),
 * and purity (same inputs -> same outputs). No wall-clock, no sleep.
 */

#include "dna_call_fsm.h"

#include <stdio.h>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

/* Assert one transition: (s,ev) -> expected state + expected action. */
static void expect(dna_call_state_t s, dna_call_event_t ev,
                   dna_call_state_t want_state, dna_call_action_t want_act,
                   const char *name)
{
    dna_call_action_t act = (dna_call_action_t)0xdead;
    dna_call_state_t ns = dna_call_fsm_step(s, ev, &act);
    CHECK(ns == want_state && act == want_act, name);
}

static void test_caller_happy_path(void)
{
    printf("test_caller_happy_path\n");
    expect(CALL_IDLE,     CALL_EV_USER_CALL,  CALL_INVITING, CALL_ACT_SEND_INVITE, "IDLE + USER_CALL -> INVITING/SEND_INVITE");
    expect(CALL_INVITING, CALL_EV_RX_RINGING, CALL_INVITING, CALL_ACT_NONE,        "INVITING + RX_RINGING -> INVITING/NONE");
    expect(CALL_INVITING, CALL_EV_RX_ACCEPT,  CALL_ACTIVE,   CALL_ACT_OPEN_MEDIA,  "INVITING + RX_ACCEPT -> ACTIVE/OPEN_MEDIA");
    expect(CALL_ACTIVE,   CALL_EV_USER_HANGUP,CALL_ENDED,    CALL_ACT_END,         "ACTIVE + USER_HANGUP -> ENDED/END");
}

static void test_callee_happy_path(void)
{
    printf("test_callee_happy_path\n");
    expect(CALL_IDLE,    CALL_EV_RX_INVITE,   CALL_RINGING, CALL_ACT_SEND_RINGING, "IDLE + RX_INVITE -> RINGING/SEND_RINGING");
    expect(CALL_RINGING, CALL_EV_USER_ACCEPT, CALL_ACTIVE,  CALL_ACT_ACCEPT,       "RINGING + USER_ACCEPT -> ACTIVE/ACCEPT");
    expect(CALL_ACTIVE,  CALL_EV_RX_END,      CALL_ENDED,   CALL_ACT_TEARDOWN,     "ACTIVE + RX_END -> ENDED/TEARDOWN");
}

static void test_reject_and_busy(void)
{
    printf("test_reject_and_busy\n");
    expect(CALL_RINGING,  CALL_EV_USER_REJECT, CALL_ENDED, CALL_ACT_SEND_REJECT, "RINGING + USER_REJECT -> ENDED/SEND_REJECT");
    expect(CALL_INVITING, CALL_EV_RX_REJECT,   CALL_ENDED, CALL_ACT_TEARDOWN,    "INVITING + RX_REJECT -> ENDED/TEARDOWN");
    expect(CALL_INVITING, CALL_EV_RX_BUSY,     CALL_ENDED, CALL_ACT_TEARDOWN,    "INVITING + RX_BUSY -> ENDED/TEARDOWN");
}

static void test_timeouts(void)
{
    printf("test_timeouts\n");
    expect(CALL_INVITING, CALL_EV_TIMEOUT, CALL_ENDED, CALL_ACT_END,      "INVITING + TIMEOUT -> ENDED/END");
    expect(CALL_RINGING,  CALL_EV_TIMEOUT, CALL_ENDED, CALL_ACT_TEARDOWN, "RINGING + TIMEOUT -> ENDED/TEARDOWN");
}

static void test_ended_absorbing(void)
{
    printf("test_ended_absorbing\n");
    expect(CALL_ENDED, CALL_EV_RX_ACCEPT,   CALL_ENDED, CALL_ACT_NONE, "ENDED + RX_ACCEPT -> ENDED/NONE");
    expect(CALL_ENDED, CALL_EV_RX_END,      CALL_ENDED, CALL_ACT_NONE, "ENDED + RX_END -> ENDED/NONE");
    expect(CALL_ENDED, CALL_EV_USER_HANGUP, CALL_ENDED, CALL_ACT_NONE, "ENDED + USER_HANGUP -> ENDED/NONE");
}

static void test_unexpected_events_are_noops(void)
{
    printf("test_unexpected_events_are_noops\n");
    /* Late/duplicate/cross-role signals must not corrupt state (§1.1.5). */
    expect(CALL_ACTIVE,   CALL_EV_RX_RINGING, CALL_ACTIVE,   CALL_ACT_NONE, "ACTIVE + RX_RINGING -> ACTIVE/NONE (stale)");
    expect(CALL_ACTIVE,   CALL_EV_RX_ACCEPT,  CALL_ACTIVE,   CALL_ACT_NONE, "ACTIVE + RX_ACCEPT -> ACTIVE/NONE (dup)");
    expect(CALL_INVITING, CALL_EV_RX_INVITE,  CALL_INVITING, CALL_ACT_NONE, "INVITING + RX_INVITE -> INVITING/NONE");
    expect(CALL_IDLE,     CALL_EV_RX_ACCEPT,  CALL_IDLE,     CALL_ACT_NONE, "IDLE + RX_ACCEPT -> IDLE/NONE");
}

static void test_purity(void)
{
    printf("test_purity\n");
    /* Same (state,event) always yields same (state',action). */
    dna_call_action_t a1, a2;
    dna_call_state_t s1 = dna_call_fsm_step(CALL_INVITING, CALL_EV_RX_ACCEPT, &a1);
    dna_call_state_t s2 = dna_call_fsm_step(CALL_INVITING, CALL_EV_RX_ACCEPT, &a2);
    CHECK(s1 == s2 && a1 == a2, "deterministic: repeated step yields identical result");
}

int main(void)
{
    printf("=== test_call_fsm (PQ VoIP Faz A) ===\n");
    test_caller_happy_path();
    test_callee_happy_path();
    test_reject_and_busy();
    test_timeouts();
    test_ended_absorbing();
    test_unexpected_events_are_noops();
    test_purity();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
