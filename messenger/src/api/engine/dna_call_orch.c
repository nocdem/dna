/*
 * DNA Engine — Call Orchestrator: registry (PQ VoIP Faz A)
 *
 * Mutex-guarded live-call table + bounded ended-call LRU ring. All time is an
 * injected `now_ms` (no wall-clock). See dna_call_orch.h and design §4.5.
 *
 * @file dna_call_orch.c
 */

#include "dna_call_orch.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int            in_use;
    uint8_t        call_id[DNA_CALL_ORCH_ID_BYTES];
    uint8_t        peer_fp[DNA_CALL_ORCH_FP_BYTES];
    dna_call_dir_t dir;
    dna_call_state_t state;         /* current FSM state (slice 2) */
    uint64_t       expires_at;      /* call window / answer timeout */

    int            have_rx_seq;
    uint32_t       rx_seq_hw;       /* peer-sequence high-water (dedup) */

    int            gate_armed;
    int            gate_consumed;   /* one-shot */
    uint64_t       gate_expires_at;
} call_slot_t;

struct dna_call_orch {
    pthread_mutex_t mu;
    call_slot_t     slots[DNA_CALL_ORCH_MAX_CALLS];
    uint8_t         ended[DNA_CALL_ORCH_ENDED_RING][DNA_CALL_ORCH_ID_BYTES];
    int             ended_used;     /* number of valid ring entries (<= RING) */
    int             ended_next;     /* next write index (circular) */
};

dna_call_orch_t *dna_call_orch_create(void)
{
    dna_call_orch_t *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    pthread_mutex_init(&o->mu, NULL);
    return o;
}

void dna_call_orch_destroy(dna_call_orch_t *o)
{
    if (!o) return;
    pthread_mutex_destroy(&o->mu);
    free(o);
}

/* --- internal helpers (caller holds mu) --- */

static int find_locked(dna_call_orch_t *o, const uint8_t call_id[16])
{
    for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS; i++) {
        if (o->slots[i].in_use &&
            memcmp(o->slots[i].call_id, call_id, DNA_CALL_ORCH_ID_BYTES) == 0)
            return i;
    }
    return -1;
}

static void push_ended_locked(dna_call_orch_t *o, const uint8_t call_id[16])
{
    memcpy(o->ended[o->ended_next], call_id, DNA_CALL_ORCH_ID_BYTES);
    o->ended_next = (o->ended_next + 1) % DNA_CALL_ORCH_ENDED_RING;
    if (o->ended_used < DNA_CALL_ORCH_ENDED_RING) o->ended_used++;
}

static int slot_valid(int slot) {
    return slot >= 0 && slot < DNA_CALL_ORCH_MAX_CALLS;
}

/* --- public API --- */

int dna_call_orch_register(dna_call_orch_t *o, const uint8_t call_id[16],
                           const uint8_t peer_fp[64], dna_call_dir_t dir,
                           uint64_t now_ms, uint64_t window_ms)
{
    if (!o || !call_id || !peer_fp) return -1;
    pthread_mutex_lock(&o->mu);

    int rc = -1;
    if (find_locked(o, call_id) < 0) {         /* reject duplicate id */
        for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS; i++) {
            if (!o->slots[i].in_use) {
                call_slot_t *s = &o->slots[i];
                memset(s, 0, sizeof(*s));
                s->in_use = 1;
                memcpy(s->call_id, call_id, DNA_CALL_ORCH_ID_BYTES);
                memcpy(s->peer_fp, peer_fp, DNA_CALL_ORCH_FP_BYTES);
                s->dir = dir;
                s->expires_at = now_ms + window_ms;
                rc = i;
                break;
            }
        }
    }

    pthread_mutex_unlock(&o->mu);
    return rc;
}

int dna_call_orch_find(dna_call_orch_t *o, const uint8_t call_id[16])
{
    if (!o || !call_id) return -1;
    pthread_mutex_lock(&o->mu);
    int rc = find_locked(o, call_id);
    pthread_mutex_unlock(&o->mu);
    return rc;
}

int dna_call_orch_accept_seq(dna_call_orch_t *o, int slot, uint32_t seq)
{
    if (!o || !slot_valid(slot)) return 0;
    pthread_mutex_lock(&o->mu);
    int rc = 0;
    call_slot_t *s = &o->slots[slot];
    if (s->in_use) {
        if (!s->have_rx_seq || seq > s->rx_seq_hw) {
            s->rx_seq_hw = seq;
            s->have_rx_seq = 1;
            rc = 1;
        }
    }
    pthread_mutex_unlock(&o->mu);
    return rc;
}

int dna_call_orch_arm_gate(dna_call_orch_t *o, int slot,
                           uint64_t now_ms, uint64_t window_ms)
{
    if (!o || !slot_valid(slot)) return -1;
    pthread_mutex_lock(&o->mu);
    int rc = -1;
    call_slot_t *s = &o->slots[slot];
    if (s->in_use) {
        s->gate_armed = 1;
        s->gate_consumed = 0;
        s->gate_expires_at = now_ms + window_ms;
        rc = 0;
    }
    pthread_mutex_unlock(&o->mu);
    return rc;
}

int dna_call_orch_gate(dna_call_orch_t *o, const uint8_t originator_fp[64],
                       uint64_t now_ms)
{
    if (!o || !originator_fp) return 0;
    pthread_mutex_lock(&o->mu);
    int rc = 0;
    for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS; i++) {
        call_slot_t *s = &o->slots[i];
        if (s->in_use && s->gate_armed && !s->gate_consumed &&
            now_ms < s->gate_expires_at &&
            memcmp(s->peer_fp, originator_fp, DNA_CALL_ORCH_FP_BYTES) == 0) {
            s->gate_consumed = 1;   /* one-shot */
            rc = 1;
            break;
        }
    }
    pthread_mutex_unlock(&o->mu);
    return rc;
}

void dna_call_orch_end(dna_call_orch_t *o, int slot)
{
    if (!o || !slot_valid(slot)) return;
    pthread_mutex_lock(&o->mu);
    call_slot_t *s = &o->slots[slot];
    if (s->in_use) {
        push_ended_locked(o, s->call_id);
        memset(s, 0, sizeof(*s));   /* frees slot + wipes state */
    }
    pthread_mutex_unlock(&o->mu);
}

int dna_call_orch_is_ended(dna_call_orch_t *o, const uint8_t call_id[16])
{
    if (!o || !call_id) return 0;
    pthread_mutex_lock(&o->mu);
    int rc = 0;
    for (int i = 0; i < o->ended_used; i++) {
        if (memcmp(o->ended[i], call_id, DNA_CALL_ORCH_ID_BYTES) == 0) { rc = 1; break; }
    }
    pthread_mutex_unlock(&o->mu);
    return rc;
}

int dna_call_orch_expire(dna_call_orch_t *o, uint64_t now_ms)
{
    if (!o) return 0;
    pthread_mutex_lock(&o->mu);
    int n = 0;
    for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS; i++) {
        call_slot_t *s = &o->slots[i];
        if (s->in_use && now_ms >= s->expires_at) {
            push_ended_locked(o, s->call_id);
            memset(s, 0, sizeof(*s));
            n++;
        }
    }
    pthread_mutex_unlock(&o->mu);
    return n;
}

/* ===================== signal->FSM driver (slice 2) ===================== */

static int event_from_kind(const char *kind, dna_call_event_t *ev)
{
    if      (strcmp(kind, DNA_CALL_KIND_INVITE)  == 0) *ev = CALL_EV_RX_INVITE;
    else if (strcmp(kind, DNA_CALL_KIND_RINGING) == 0) *ev = CALL_EV_RX_RINGING;
    else if (strcmp(kind, DNA_CALL_KIND_ACCEPT)  == 0) *ev = CALL_EV_RX_ACCEPT;
    else if (strcmp(kind, DNA_CALL_KIND_REJECT)  == 0) *ev = CALL_EV_RX_REJECT;
    else if (strcmp(kind, DNA_CALL_KIND_BUSY)    == 0) *ev = CALL_EV_RX_BUSY;
    else if (strcmp(kind, DNA_CALL_KIND_END)     == 0) *ev = CALL_EV_RX_END;
    else return 0;
    return 1;
}

static int hexnib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex16(const char *hex, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        int hi = hexnib(hex[i * 2]), lo = hexnib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int is_ended_locked(dna_call_orch_t *o, const uint8_t id[16])
{
    for (int i = 0; i < o->ended_used; i++)
        if (memcmp(o->ended[i], id, DNA_CALL_ORCH_ID_BYTES) == 0) return 1;
    return 0;
}

static int free_slot_locked(dna_call_orch_t *o)
{
    for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS; i++)
        if (!o->slots[i].in_use) return i;
    return -1;
}

static int find_outbound_to_peer_locked(dna_call_orch_t *o, const uint8_t peer_fp[64])
{
    for (int i = 0; i < DNA_CALL_ORCH_MAX_CALLS; i++)
        if (o->slots[i].in_use && o->slots[i].dir == DNA_CALL_OUTBOUND &&
            memcmp(o->slots[i].peer_fp, peer_fp, DNA_CALL_ORCH_FP_BYTES) == 0)
            return i;
    return -1;
}

static void init_slot_locked(call_slot_t *s, const uint8_t id[16],
                             const uint8_t peer_fp[64], dna_call_dir_t dir,
                             uint64_t now_ms, uint64_t window_ms)
{
    memset(s, 0, sizeof(*s));
    s->in_use = 1;
    memcpy(s->call_id, id, DNA_CALL_ORCH_ID_BYTES);
    memcpy(s->peer_fp, peer_fp, DNA_CALL_ORCH_FP_BYTES);
    s->dir = dir;
    s->expires_at = now_ms + window_ms;
}

dna_call_action_t dna_call_orch_start(dna_call_orch_t *o, const uint8_t call_id[16],
                                      const uint8_t peer_fp[64],
                                      uint64_t now_ms, uint64_t window_ms)
{
    if (!o || !call_id || !peer_fp) return CALL_ACT_NONE;
    pthread_mutex_lock(&o->mu);

    dna_call_action_t action = CALL_ACT_NONE;
    if (find_locked(o, call_id) < 0) {
        int idx = free_slot_locked(o);
        if (idx >= 0) {
            call_slot_t *s = &o->slots[idx];
            init_slot_locked(s, call_id, peer_fp, DNA_CALL_OUTBOUND, now_ms, window_ms);
            s->state = dna_call_fsm_step(CALL_IDLE, CALL_EV_USER_CALL, &action);
        }
    }

    pthread_mutex_unlock(&o->mu);
    return action;
}

dna_call_action_t dna_call_orch_on_signal(dna_call_orch_t *o, const dna_call_parsed_t *p,
                                          const uint8_t sender_fp[64],
                                          uint64_t now_ms, uint64_t window_ms)
{
    if (!o || !p || !sender_fp) return CALL_ACT_NONE;

    dna_call_event_t ev;
    if (!event_from_kind(p->kind, &ev)) return CALL_ACT_NONE;

    uint8_t id[16];
    if (hex16(p->call_id_hex, id) != 0) return CALL_ACT_NONE;

    pthread_mutex_lock(&o->mu);
    dna_call_action_t action = CALL_ACT_NONE;

    int idx = find_locked(o, id);
    if (idx >= 0) {
        call_slot_t *s = &o->slots[idx];
        /* signal must come from the call's authenticated peer */
        if (memcmp(s->peer_fp, sender_fp, DNA_CALL_ORCH_FP_BYTES) != 0) goto out;
        /* peer-sequence dedup (stale/duplicate -> no-op) */
        if (s->have_rx_seq && p->seq <= s->rx_seq_hw) goto out;
        s->rx_seq_hw = p->seq; s->have_rx_seq = 1;

        dna_call_state_t ns = dna_call_fsm_step(s->state, ev, &action);
        s->state = ns;
        if (ns == CALL_ENDED) { push_ended_locked(o, id); memset(s, 0, sizeof(*s)); }
        goto out;
    }

    /* Unknown call. Only a fresh INVITE creates one. */
    if (ev != CALL_EV_RX_INVITE) goto out;
    if (is_ended_locked(o, id)) goto out;   /* replayed ended call */

    /* Glare: a concurrent outbound call to the same peer. Lower raw call_id
     * wins — deterministic, so both sides pick the same survivor. */
    int g = find_outbound_to_peer_locked(o, sender_fp);
    if (g >= 0) {
        if (memcmp(id, o->slots[g].call_id, DNA_CALL_ORCH_ID_BYTES) < 0) {
            /* incoming id lower -> their call wins: drop ours, become callee */
            push_ended_locked(o, o->slots[g].call_id);
            memset(&o->slots[g], 0, sizeof(o->slots[g]));
        } else {
            goto out;   /* ours wins -> ignore their INVITE */
        }
    }

    int idx2 = free_slot_locked(o);
    if (idx2 < 0) goto out;
    call_slot_t *s = &o->slots[idx2];
    init_slot_locked(s, id, sender_fp, DNA_CALL_INBOUND, now_ms, window_ms);
    s->rx_seq_hw = p->seq; s->have_rx_seq = 1;
    s->state = dna_call_fsm_step(CALL_IDLE, CALL_EV_RX_INVITE, &action);

out:
    pthread_mutex_unlock(&o->mu);
    return action;
}

dna_call_action_t dna_call_orch_user(dna_call_orch_t *o, const uint8_t call_id[16],
                                     dna_call_event_t user_event,
                                     uint64_t now_ms, uint64_t gate_window_ms)
{
    if (!o || !call_id) return CALL_ACT_NONE;
    pthread_mutex_lock(&o->mu);

    dna_call_action_t action = CALL_ACT_NONE;
    int idx = find_locked(o, call_id);
    if (idx >= 0) {
        call_slot_t *s = &o->slots[idx];
        dna_call_state_t ns = dna_call_fsm_step(s->state, user_event, &action);
        s->state = ns;
        if (user_event == CALL_EV_USER_ACCEPT && ns == CALL_ACTIVE) {
            s->gate_armed = 1;
            s->gate_consumed = 0;
            s->gate_expires_at = now_ms + gate_window_ms;
        }
        if (ns == CALL_ENDED) { push_ended_locked(o, call_id); memset(s, 0, sizeof(*s)); }
    }

    pthread_mutex_unlock(&o->mu);
    return action;
}

dna_call_state_t dna_call_orch_state(dna_call_orch_t *o, const uint8_t call_id[16])
{
    if (!o || !call_id) return CALL_ENDED;
    pthread_mutex_lock(&o->mu);
    int idx = find_locked(o, call_id);
    dna_call_state_t st = (idx >= 0) ? o->slots[idx].state : CALL_ENDED;
    pthread_mutex_unlock(&o->mu);
    return st;
}
