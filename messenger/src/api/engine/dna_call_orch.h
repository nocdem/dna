#ifndef DNA_CALL_ORCH_H
#define DNA_CALL_ORCH_H

/*
 * DNA Engine — Call Orchestrator: registry (PQ VoIP Faz A)
 *
 * Mutex-guarded table of live calls plus a bounded ended-call ring. This is the
 * stateful home of the red-team's consent/replay findings:
 *   - F-GATE : one-shot, windowed ACTIVE-calls consent gate keyed on peer fp,
 *              read on the client read-thread, written on the engine task-thread
 *              -> ALL access is mutex-guarded.
 *   - F-DEDUP: per-call peer-sequence high-water dedup (single direction: only
 *              the peer's signals are numbered here, so caller/callee seq=1 can
 *              never collide). Primary idempotency still comes from the FSM.
 *   - R8     : ended-call dedup is a fixed-capacity LRU ring (no unbounded set).
 *
 * DETERMINISM: time enters only as an injected `now_ms` parameter — never a
 * wall-clock read — so the registry is fully reproducible in tests.
 *
 * See docs/plans/2026-07-12-pq-voip-faz-a-signaling-design.md §4.5.
 * @file dna_call_orch.h
 */

#include <stdint.h>
#include "dna_call_fsm.h"      /* dna_call_event_t / dna_call_action_t / dna_call_state_t */
#include "dna_call_crypto.h"   /* dna_call_parsed_t */

#define DNA_CALL_ORCH_MAX_CALLS    8    /* concurrent calls (<< nodus 16 circuits) */
#define DNA_CALL_ORCH_ENDED_RING   32   /* bounded recently-ended dedup */
#define DNA_CALL_ORCH_ID_BYTES     16
#define DNA_CALL_ORCH_FP_BYTES     64

typedef enum {
    DNA_CALL_OUTBOUND = 0,   /* local user initiated (we are caller) */
    DNA_CALL_INBOUND  = 1    /* peer initiated (we are callee) */
} dna_call_dir_t;

typedef struct dna_call_orch dna_call_orch_t;

dna_call_orch_t *dna_call_orch_create(void);
void             dna_call_orch_destroy(dna_call_orch_t *o);

/* Register a new call. Returns slot index >= 0, or -1 if the table is full or
 * call_id is already registered. `window_ms` bounds the ring/answer timeout. */
int dna_call_orch_register(dna_call_orch_t *o,
                           const uint8_t call_id[DNA_CALL_ORCH_ID_BYTES],
                           const uint8_t peer_fp[DNA_CALL_ORCH_FP_BYTES],
                           dna_call_dir_t dir, uint64_t now_ms, uint64_t window_ms);

/* Find a live call by id. Returns slot index or -1. */
int dna_call_orch_find(dna_call_orch_t *o,
                       const uint8_t call_id[DNA_CALL_ORCH_ID_BYTES]);

/* Dedup an inbound peer signal: returns 1 if `seq` is new (records it), 0 if it
 * is a stale/duplicate replay (seq <= high-water). */
int dna_call_orch_accept_seq(dna_call_orch_t *o, int slot, uint32_t seq);

/* Arm the one-shot consent gate for this call's peer (called after the local
 * user accepts, so the caller's inbound media circuit is authorized). */
int dna_call_orch_arm_gate(dna_call_orch_t *o, int slot,
                           uint64_t now_ms, uint64_t window_ms);

/* Consent gate for an inbound circuit. Returns 1 and CONSUMES the one-shot
 * authorization iff some armed, unexpired call has peer_fp == originator_fp;
 * otherwise 0. This is the F-GATE check the circuit-inbound handler calls. */
int dna_call_orch_gate(dna_call_orch_t *o,
                       const uint8_t originator_fp[DNA_CALL_ORCH_FP_BYTES],
                       uint64_t now_ms);

/* End a call: free the slot and record its id in the bounded ended ring. */
void dna_call_orch_end(dna_call_orch_t *o, int slot);

/* Is this id in the recently-ended ring (for replay handling)? */
int dna_call_orch_is_ended(dna_call_orch_t *o,
                           const uint8_t call_id[DNA_CALL_ORCH_ID_BYTES]);

/* Expire calls whose window elapsed (now_ms >= expires_at): free them and add
 * to the ended ring. Returns the number expired. */
int dna_call_orch_expire(dna_call_orch_t *o, uint64_t now_ms);

/* ===================== signal->FSM driver (slice 2, §4.1/§4.5) =====================
 *
 * These drive the FSM on top of the registry. `now_ms`/`window_ms` are injected
 * (determinism). A parsed signal fed to on_signal MUST already be signature-
 * verified by the router (the driver does not verify crypto).
 */

/* Start an outbound call: register + FSM IDLE+USER_CALL. Returns the action to
 * perform (CALL_ACT_SEND_INVITE) or CALL_ACT_NONE if no slot. */
dna_call_action_t dna_call_orch_start(dna_call_orch_t *o,
                                      const uint8_t call_id[DNA_CALL_ORCH_ID_BYTES],
                                      const uint8_t peer_fp[DNA_CALL_ORCH_FP_BYTES],
                                      uint64_t now_ms, uint64_t window_ms);

/* Drive the FSM from a received, verified signal `p` sent by `sender_fp`.
 * Handles dedup (stale -> NONE), unknown/ended calls, new inbound INVITE (with
 * glare tie-break vs a concurrent outbound call to the same peer), and terminal
 * teardown. Returns the action to perform. */
dna_call_action_t dna_call_orch_on_signal(dna_call_orch_t *o,
                                          const dna_call_parsed_t *p,
                                          const uint8_t sender_fp[DNA_CALL_ORCH_FP_BYTES],
                                          uint64_t now_ms, uint64_t window_ms);

/* Local user action on an existing call (USER_ACCEPT / USER_REJECT / USER_HANGUP).
 * On accept, arms the one-shot consent gate for the peer's inbound circuit.
 * Returns the action to perform. */
dna_call_action_t dna_call_orch_user(dna_call_orch_t *o,
                                     const uint8_t call_id[DNA_CALL_ORCH_ID_BYTES],
                                     dna_call_event_t user_event,
                                     uint64_t now_ms, uint64_t gate_window_ms);

/* Test/introspection: current FSM state of a call (CALL_ENDED if unknown). */
dna_call_state_t dna_call_orch_state(dna_call_orch_t *o,
                                     const uint8_t call_id[DNA_CALL_ORCH_ID_BYTES]);

#endif /* DNA_CALL_ORCH_H */
