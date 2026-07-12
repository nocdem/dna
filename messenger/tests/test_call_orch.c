/*
 * test_call_orch.c — PQ VoIP Faz A call registry (dna_call_orch_*).
 *
 * Deterministic (injected now_ms) tests for the stateful red-team surfaces:
 * registration + capacity, peer-seq dedup (F-DEDUP), one-shot windowed consent
 * gate (F-GATE), bounded ended-call LRU ring (R8), and window expiry. Design §4.5.
 */

#include "dna_call_orch.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

static void mk_id(uint8_t id[16], uint8_t v)   { memset(id, v, 16); }
static void mk_fp(uint8_t fp[64], uint8_t v)   { memset(fp, v, 64); }

static void test_register_find_capacity(void)
{
    printf("test_register_find_capacity\n");
    dna_call_orch_t *o = dna_call_orch_create();
    CHECK(o != NULL, "create");

    uint8_t id[16], fp[64];
    mk_id(id, 0xA1); mk_fp(fp, 0xB1);
    int slot = dna_call_orch_register(o, id, fp, DNA_CALL_OUTBOUND, 1000, 30000);
    CHECK(slot >= 0, "register returns slot");
    CHECK(dna_call_orch_find(o, id) == slot, "find returns same slot");

    /* Duplicate id rejected. */
    CHECK(dna_call_orch_register(o, id, fp, DNA_CALL_OUTBOUND, 1000, 30000) < 0,
          "duplicate call_id rejected");

    /* Fill to capacity. */
    int registered = 1;
    for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS + 2; i++) {
        uint8_t id2[16], fp2[64];
        mk_id(id2, (uint8_t)(0x10 + i)); mk_fp(fp2, (uint8_t)(0x20 + i));
        if (dna_call_orch_register(o, id2, fp2, DNA_CALL_INBOUND, 1000, 30000) >= 0)
            registered++;
    }
    CHECK(registered == DNA_CALL_ORCH_MAX_CALLS, "register caps at MAX_CALLS");

    dna_call_orch_destroy(o);
}

static void test_dedup_high_water(void)
{
    printf("test_dedup_high_water\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], fp[64]; mk_id(id, 0xC1); mk_fp(fp, 0xD1);
    int s = dna_call_orch_register(o, id, fp, DNA_CALL_INBOUND, 0, 30000);

    CHECK(dna_call_orch_accept_seq(o, s, 1) == 1, "seq 1 accepted");
    CHECK(dna_call_orch_accept_seq(o, s, 1) == 0, "seq 1 again rejected (dup)");
    CHECK(dna_call_orch_accept_seq(o, s, 2) == 1, "seq 2 accepted");
    CHECK(dna_call_orch_accept_seq(o, s, 2) == 0, "seq 2 again rejected");
    CHECK(dna_call_orch_accept_seq(o, s, 1) == 0, "stale lower seq rejected");
    CHECK(dna_call_orch_accept_seq(o, s, 5) == 1, "higher seq accepted");

    dna_call_orch_destroy(o);
}

static void test_consent_gate(void)
{
    printf("test_consent_gate\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], fpA[64], fpB[64];
    mk_id(id, 0xE1); mk_fp(fpA, 0xAA); mk_fp(fpB, 0xBB);
    int s = dna_call_orch_register(o, id, fpA, DNA_CALL_INBOUND, 1000, 30000);

    /* Not armed yet -> gate denies. */
    CHECK(dna_call_orch_gate(o, fpA, 1000) == 0, "gate denies before arm");

    dna_call_orch_arm_gate(o, s, 1000, 5000);   /* window [1000, 6000) */
    CHECK(dna_call_orch_gate(o, fpB, 1500) == 0, "gate denies wrong fp");
    CHECK(dna_call_orch_gate(o, fpA, 1500) == 1, "gate accepts armed fp in window");
    CHECK(dna_call_orch_gate(o, fpA, 1500) == 0, "gate is one-shot (second denied)");

    /* Re-arm then let the window expire. */
    dna_call_orch_arm_gate(o, s, 2000, 1000);   /* window [2000, 3000) */
    CHECK(dna_call_orch_gate(o, fpA, 3500) == 0, "gate denies after window expiry");

    dna_call_orch_destroy(o);
}

static void test_ended_ring_lru(void)
{
    printf("test_ended_ring_lru\n");
    dna_call_orch_t *o = dna_call_orch_create();

    uint8_t id[16], fp[64]; mk_id(id, 0xF1); mk_fp(fp, 0x11);
    int s = dna_call_orch_register(o, id, fp, DNA_CALL_OUTBOUND, 0, 30000);
    dna_call_orch_end(o, s);
    CHECK(dna_call_orch_is_ended(o, id) == 1, "ended id is in ring");
    CHECK(dna_call_orch_find(o, id) < 0, "ended slot is freed");

    /* Overflow the ring: end RING+1 distinct ids; the first must be evicted. */
    uint8_t first[16]; mk_id(first, 0x00);
    for (int i = 0; i < DNA_CALL_ORCH_ENDED_RING + 1; i++) {
        uint8_t idn[16], fpn[64];
        memset(idn, 0, 16); idn[0] = (uint8_t)(i + 1); idn[1] = 0x77;
        mk_fp(fpn, (uint8_t)i);
        if (i == 0) memcpy(first, idn, 16);
        int sn = dna_call_orch_register(o, idn, fpn, DNA_CALL_OUTBOUND, 0, 30000);
        dna_call_orch_end(o, sn);
    }
    CHECK(dna_call_orch_is_ended(o, first) == 0, "oldest ended id evicted (LRU bound)");

    dna_call_orch_destroy(o);
}

static void test_expire(void)
{
    printf("test_expire\n");
    dna_call_orch_t *o = dna_call_orch_create();
    uint8_t id[16], fp[64]; mk_id(id, 0x33); mk_fp(fp, 0x44);
    int s = dna_call_orch_register(o, id, fp, DNA_CALL_OUTBOUND, 1000, 2000); /* expires 3000 */
    (void)s;

    CHECK(dna_call_orch_expire(o, 2500) == 0, "no expiry before window end");
    CHECK(dna_call_orch_find(o, id) >= 0, "still live before expiry");
    CHECK(dna_call_orch_expire(o, 3000) == 1, "expires at window end");
    CHECK(dna_call_orch_find(o, id) < 0, "expired slot freed");
    CHECK(dna_call_orch_is_ended(o, id) == 1, "expired id recorded as ended");

    dna_call_orch_destroy(o);
}

int main(void)
{
    printf("=== test_call_orch (PQ VoIP Faz A) ===\n");
    test_register_find_capacity();
    test_dedup_high_water();
    test_consent_gate();
    test_ended_ring_lru();
    test_expire();
    printf("=== %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES PRESENT");
    return g_fail == 0 ? 0 : 1;
}
