#ifndef DNA_CALL_FSM_H
#define DNA_CALL_FSM_H

/*
 * DNA Engine — Call State Machine (PQ VoIP Faz A)
 *
 * Pure, table-driven call-control FSM. See
 * docs/plans/2026-07-12-pq-voip-faz-a-signaling-design.md §4.1.
 *
 * DETERMINISM (design §1.1.1): the transition is a pure function
 * (state, event) -> (state', action). NO wall-clock branch lives inside it —
 * a ring/answer timeout enters as an explicit CALL_EV_TIMEOUT event produced by
 * a timer, never as a `now - t0 > X` read. Late/duplicate signals resolve by
 * state (they are no-ops in states that no longer expect them), so replays and
 * out-of-order Spillway delivery cannot corrupt the call.
 *
 * Glare (both peers INVITE at once), dedup on (call_id, direction, seq), and the
 * ACTIVE-calls consent gate live in the CALLER of this FSM, not in the step
 * function — they decide which events to feed it.
 *
 * @file dna_call_fsm.h
 */

typedef enum {
    CALL_IDLE = 0,
    CALL_INVITING,   /* caller: INVITE sent, awaiting ACCEPT/REJECT/timeout */
    CALL_RINGING,    /* callee: INVITE received, awaiting user accept/reject */
    CALL_ACTIVE,     /* both: call up (media in Faz B) */
    CALL_ENDED       /* terminal: keys wiped, slot freed */
} dna_call_state_t;

typedef enum {
    CALL_EV_USER_CALL = 0,  /* local user starts a call (caller) */
    CALL_EV_RX_INVITE,      /* inbound INVITE (callee) */
    CALL_EV_USER_ACCEPT,    /* local user answers (callee) */
    CALL_EV_USER_REJECT,    /* local user declines (callee) */
    CALL_EV_RX_RINGING,     /* peer signalled ringing (caller) */
    CALL_EV_RX_ACCEPT,      /* peer accepted (caller) */
    CALL_EV_RX_REJECT,      /* peer declined (caller) */
    CALL_EV_RX_BUSY,        /* peer busy (caller) */
    CALL_EV_RX_END,         /* peer ended (either) */
    CALL_EV_TIMEOUT,        /* ring/answer timer fired (either) */
    CALL_EV_USER_HANGUP     /* local user ends an active call (either) */
} dna_call_event_t;

typedef enum {
    CALL_ACT_NONE = 0,
    CALL_ACT_SEND_INVITE,   /* mint ephemeral key, sign+send INVITE */
    CALL_ACT_SEND_RINGING,  /* send RINGING */
    CALL_ACT_ACCEPT,        /* callee: encapsulate, derive K_call, send ACCEPT, arm gate */
    CALL_ACT_OPEN_MEDIA,    /* caller: decapsulate, derive K_call, open media circuit */
    CALL_ACT_SEND_REJECT,   /* send REJECT */
    CALL_ACT_END,           /* send END + teardown + wipe keys */
    CALL_ACT_TEARDOWN       /* teardown + wipe keys, no signal (peer already ended) */
} dna_call_action_t;

/*
 * Pure transition. Returns the next state; writes the side-effect to perform
 * into *action (CALL_ACT_NONE if none). Unexpected events in a given state are
 * no-ops that keep the current state with CALL_ACT_NONE (idempotent, §1.1.5).
 * ENDED is absorbing.
 */
dna_call_state_t dna_call_fsm_step(dna_call_state_t state,
                                   dna_call_event_t event,
                                   dna_call_action_t *action);

#endif /* DNA_CALL_FSM_H */
