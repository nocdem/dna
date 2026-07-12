/*
 * test_call_driver.c — PQ VoIP Faz A orchestrator signal->FSM driver + glare.
 *
 * Deterministic (injected now_ms). Drives the FSM on top of the registry:
 * caller/callee happy paths, dedup drop, glare tie-break (raw 16B call_id),
 * consent-gate arming on accept, and replayed-ended-call suppression. §4.1/§4.5.
 */

#include "dna_call_orch.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

static void mk_id(uint8_t id[16], uint8_t v) { memset(id, v, 16); }
static void mk_fp(uint8_t fp[64], uint8_t v) { memset(fp, v, 64); }

/* Build a parsed signal for call id-byte `idv`, given kind + seq. */
static void mk_parsed(dna_call_parsed_t *p, const char *kind, uint8_t idv, uint32_t seq)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->kind, sizeof(p->kind), "%s", kind);
    for (int i = 0; i < 16; i++) snprintf(p->call_id_hex + i * 2, 3, "%02x", idv);
    p->seq = seq;
}

static void test_caller_flow(void)
{
    printf("test_caller_flow\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], P[64]; mk_id(id, 0x05); mk_fp(P, 0xAA);

    CHECK(dna_call_orch_start(o, id, P, 1000, 30000) == CALL_ACT_SEND_INVITE, "start -> SEND_INVITE");
    CHECK(dna_call_orch_state(o, id) == CALL_INVITING, "state INVITING");

    dna_call_parsed_t p;
    mk_parsed(&p, "RINGING", 0x05, 1);
    CHECK(dna_call_orch_on_signal(o, &p, P, 1100, 30000) == CALL_ACT_NONE, "RINGING -> NONE");
    CHECK(dna_call_orch_state(o, id) == CALL_INVITING, "still INVITING after RINGING");

    mk_parsed(&p, "ACCEPT", 0x05, 2);
    CHECK(dna_call_orch_on_signal(o, &p, P, 1200, 30000) == CALL_ACT_OPEN_MEDIA, "ACCEPT -> OPEN_MEDIA");
    CHECK(dna_call_orch_state(o, id) == CALL_ACTIVE, "state ACTIVE");

    CHECK(dna_call_orch_user(o, id, CALL_EV_USER_HANGUP, 1300, 5000) == CALL_ACT_END, "hangup -> END");
    CHECK(dna_call_orch_find(o, id) < 0, "call freed after hangup");
    CHECK(dna_call_orch_is_ended(o, id) == 1, "call in ended ring");

    dna_call_orch_destroy(o);
}

static void test_callee_flow_and_gate(void)
{
    printf("test_callee_flow_and_gate\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], P[64]; mk_id(id, 0x06); mk_fp(P, 0xBB);

    dna_call_parsed_t p;
    mk_parsed(&p, "INVITE", 0x06, 1);
    CHECK(dna_call_orch_on_signal(o, &p, P, 1000, 30000) == CALL_ACT_SEND_RINGING, "INVITE -> SEND_RINGING");
    CHECK(dna_call_orch_state(o, id) == CALL_RINGING, "state RINGING");

    /* Duplicate INVITE (same seq) is deduped. */
    CHECK(dna_call_orch_on_signal(o, &p, P, 1050, 30000) == CALL_ACT_NONE, "duplicate INVITE deduped");

    CHECK(dna_call_orch_user(o, id, CALL_EV_USER_ACCEPT, 1100, 5000) == CALL_ACT_ACCEPT, "accept -> ACCEPT");
    CHECK(dna_call_orch_state(o, id) == CALL_ACTIVE, "state ACTIVE");
    /* Accept armed the consent gate for the caller's inbound circuit. */
    CHECK(dna_call_orch_gate(o, P, 1150) == 1, "consent gate armed for peer after accept");

    mk_parsed(&p, "END", 0x06, 2);
    CHECK(dna_call_orch_on_signal(o, &p, P, 1200, 30000) == CALL_ACT_TEARDOWN, "peer END -> TEARDOWN");
    CHECK(dna_call_orch_state(o, id) == CALL_ENDED, "state ENDED");

    dna_call_orch_destroy(o);
}

static void test_glare_lower_id_wins(void)
{
    printf("test_glare_lower_id_wins\n");
    /* We call P (our id 0x05); P simultaneously calls us (their id 0x03 < ours).
     * Lower id wins -> their call survives, we become callee. */
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t our[16], their[16], P[64];
    mk_id(our, 0x05); mk_id(their, 0x03); mk_fp(P, 0xCC);

    dna_call_orch_start(o, our, P, 1000, 30000);
    dna_call_parsed_t p; mk_parsed(&p, "INVITE", 0x03, 1);
    CHECK(dna_call_orch_on_signal(o, &p, P, 1010, 30000) == CALL_ACT_SEND_RINGING,
          "lower-id inbound INVITE wins -> SEND_RINGING");
    CHECK(dna_call_orch_state(o, their) == CALL_RINGING, "their call now RINGING");
    CHECK(dna_call_orch_find(o, our) < 0, "our outbound call dropped");

    dna_call_orch_destroy(o);
}

static void test_glare_higher_id_dropped(void)
{
    printf("test_glare_higher_id_dropped\n");
    /* We call P (our id 0x03); P calls us (their id 0x05 > ours). Ours wins ->
     * drop their INVITE, keep our outbound. */
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t our[16], their[16], P[64];
    mk_id(our, 0x03); mk_id(their, 0x05); mk_fp(P, 0xDD);

    dna_call_orch_start(o, our, P, 1000, 30000);
    dna_call_parsed_t p; mk_parsed(&p, "INVITE", 0x05, 1);
    CHECK(dna_call_orch_on_signal(o, &p, P, 1010, 30000) == CALL_ACT_NONE,
          "higher-id inbound INVITE dropped");
    CHECK(dna_call_orch_state(o, our) == CALL_INVITING, "our outbound still INVITING");
    CHECK(dna_call_orch_find(o, their) < 0, "their call not registered");

    dna_call_orch_destroy(o);
}

static void test_replayed_ended_invite_suppressed(void)
{
    printf("test_replayed_ended_invite_suppressed\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], P[64]; mk_id(id, 0x07); mk_fp(P, 0xEE);

    dna_call_parsed_t p; mk_parsed(&p, "INVITE", 0x07, 1);
    dna_call_orch_on_signal(o, &p, P, 1000, 30000);
    dna_call_orch_user(o, id, CALL_EV_USER_REJECT, 1100, 5000);   /* ends the call */
    CHECK(dna_call_orch_is_ended(o, id) == 1, "call ended after reject");

    /* Replay the same INVITE: must not ring again. */
    dna_call_parsed_t p2; mk_parsed(&p2, "INVITE", 0x07, 1);
    CHECK(dna_call_orch_on_signal(o, &p2, P, 1200, 30000) == CALL_ACT_NONE,
          "replayed INVITE for ended call suppressed");

    dna_call_orch_destroy(o);
}

static void test_signal_from_wrong_peer_ignored(void)
{
    printf("test_signal_from_wrong_peer_ignored\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], P[64], X[64]; mk_id(id, 0x08); mk_fp(P, 0x01); mk_fp(X, 0x02);

    dna_call_orch_start(o, id, P, 1000, 30000);
    dna_call_parsed_t p; mk_parsed(&p, "ACCEPT", 0x08, 2);
    /* ACCEPT arrives but from a different fp than the call's peer. */
    CHECK(dna_call_orch_on_signal(o, &p, X, 1100, 30000) == CALL_ACT_NONE,
          "signal from non-peer ignored");
    CHECK(dna_call_orch_state(o, id) == CALL_INVITING, "state unchanged");

    dna_call_orch_destroy(o);
}

int main(void)
{
    printf("=== test_call_driver (PQ VoIP Faz A) ===\n");
    test_caller_flow();
    test_callee_flow_and_gate();
    test_glare_lower_id_wins();
    test_glare_higher_id_dropped();
    test_replayed_ended_invite_suppressed();
    test_signal_from_wrong_peer_ignored();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
