/*
 * DNA Engine — Call State Machine (PQ VoIP Faz A)
 *
 * Pure table-driven transition. See dna_call_fsm.h and design §4.1.
 * No wall-clock, no allocation, no I/O — a timeout arrives as CALL_EV_TIMEOUT.
 * Any (state,event) pair not explicitly handled is an idempotent no-op that
 * preserves the current state (§1.1.5: late/duplicate signals cannot corrupt).
 *
 * @file dna_call_fsm.c
 */

#include "dna_call_fsm.h"

#define T(next_state, act) do { *action = (act); return (next_state); } while (0)

dna_call_state_t dna_call_fsm_step(dna_call_state_t state,
                                   dna_call_event_t event,
                                   dna_call_action_t *action)
{
    dna_call_action_t sink;
    if (!action) action = &sink;
    *action = CALL_ACT_NONE;

    switch (state) {
    case CALL_IDLE:
        switch (event) {
        case CALL_EV_USER_CALL: T(CALL_INVITING, CALL_ACT_SEND_INVITE);
        case CALL_EV_RX_INVITE: T(CALL_RINGING,  CALL_ACT_SEND_RINGING);
        default: return CALL_IDLE;
        }

    case CALL_INVITING:   /* caller: INVITE sent */
        switch (event) {
        case CALL_EV_RX_RINGING:  return CALL_INVITING;              /* informational */
        case CALL_EV_RX_ACCEPT:   T(CALL_ACTIVE, CALL_ACT_OPEN_MEDIA);
        case CALL_EV_RX_REJECT:   T(CALL_ENDED,  CALL_ACT_TEARDOWN);
        case CALL_EV_RX_BUSY:     T(CALL_ENDED,  CALL_ACT_TEARDOWN);
        case CALL_EV_RX_END:      T(CALL_ENDED,  CALL_ACT_TEARDOWN);
        case CALL_EV_TIMEOUT:     T(CALL_ENDED,  CALL_ACT_END);      /* give up: tell peer */
        case CALL_EV_USER_HANGUP: T(CALL_ENDED,  CALL_ACT_END);      /* cancel before answer */
        default: return CALL_INVITING;
        }

    case CALL_RINGING:    /* callee: INVITE received, awaiting user */
        switch (event) {
        case CALL_EV_USER_ACCEPT: T(CALL_ACTIVE, CALL_ACT_ACCEPT);
        case CALL_EV_USER_REJECT: T(CALL_ENDED,  CALL_ACT_SEND_REJECT);
        case CALL_EV_RX_END:      T(CALL_ENDED,  CALL_ACT_TEARDOWN);  /* caller canceled */
        case CALL_EV_TIMEOUT:     T(CALL_ENDED,  CALL_ACT_TEARDOWN);  /* missed call */
        default: return CALL_RINGING;
        }

    case CALL_ACTIVE:     /* both: call up */
        switch (event) {
        case CALL_EV_USER_HANGUP: T(CALL_ENDED, CALL_ACT_END);
        case CALL_EV_RX_END:      T(CALL_ENDED, CALL_ACT_TEARDOWN);
        default: return CALL_ACTIVE;
        }

    case CALL_ENDED:      /* absorbing */
    default:
        return CALL_ENDED;
    }
}
