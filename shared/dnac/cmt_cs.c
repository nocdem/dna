/**
 * @file shared/dnac/cmt_cs.c
 * @brief cometbft @709fd12b `consensus/state.go` ported to C.
 *
 * The design, the ownership rules, the panic rule and the reference pins
 * are in cmt_cs.h. Every function below carries the Go function and line
 * range it ports; every `panic` site carries its class (REJECT or FAULT)
 * and the reason. Functions appear in the reference's own order.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_cs.h"

/* The state machine calls SafeSubInt32 (state.go:1074) and SafeAddInt32
 * (:1097) directly; cmt_cs.h does not pull them in because no type in its
 * interface needs them. */
#include "dnac/cmt_safemath.h"

#include "crypto/utils/qgp_log.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define LOG_TAG "CMT_CS"

/* ══════════════════════════════════════════════════════════════════════
 * The fail point — libs/fail/fail.go:9-47
 * ══════════════════════════════════════════════════════════════════════ */

#ifdef QGP_FAULT_INJECT

/** libs/fail/fail.go:26 — `var callIndex int`, the process-global counter
 *  that indexes Fail calls. */
static int g_cs_fail_call_index = 0;

/** libs/fail/fail.go:9-23 — `envSet()`. Returns the parsed index, or -1
 *  when the variable is unset (:12-14) or does not parse (:17-20). Go's
 *  `strconv.Atoi` rejects trailing rubbish and overflow, which is why
 *  this uses `strtol` with an end pointer rather than `atoi`. */
static int cs_fail_env_set(void)
{
    const char *s;
    char       *end;
    long        v;

    s = getenv("FAIL_TEST_INDEX");                              /* :10    */
    if (s == NULL || *s == '\0') {
        return -1;                                              /* :12-14 */
    }
    errno = 0;
    end   = NULL;
    v     = strtol(s, &end, 10);
    if (end == s || end == NULL || *end != '\0' || errno != 0 ||
        v > (long)INT_MAX || v < (long)INT_MIN) {
        return -1;                                              /* :17-20 */
    }
    return (int)v;                                              /* :22    */
}

void cmt_cs_fail_point(void)
{
    int to_fail;

    to_fail = cs_fail_env_set();                                /* :29    */
    if (to_fail < 0) {
        return;                       /* :30-32 — note: NO increment here */
    }
    if (g_cs_fail_call_index == to_fail) {                      /* :34    */
        /* fail.go:42-43 — the reference prints to stdout and exits 1. The
         * project forbids printf outside tests, so the same text goes to
         * the log; the EXIT is what the fail point is for. */
        QGP_LOG_ERROR(LOG_TAG, "*** fail-test %d ***", g_cs_fail_call_index);
        exit(1);
    }
    g_cs_fail_call_index++;                                     /* :38    */
}

#endif /* QGP_FAULT_INJECT */

/* ══════════════════════════════════════════════════════════════════════
 * C-only helpers
 * ══════════════════════════════════════════════════════════════════════ */

/** Go `time.Time.After` — strictly later. */
static bool cs_time_after(cmt_time_t a, cmt_time_t b)
{
    if (a.seconds != b.seconds) {
        return a.seconds > b.seconds;
    }
    return a.nanos > b.nanos;
}

/**
 * Go `t.Add(d)` for a nanosecond duration, with the carry `cmt_time_t`
 * needs (nanos always in [0, 1e9) — cmt_time.h:80-81). The arithmetic is
 * formed in unsigned words because Go's int64 arithmetic wraps and C's
 * signed overflow is undefined; the value is identical wherever the
 * reference is itself well defined. Same shape as cmt_config.h:205-231.
 */
static cmt_time_t cs_time_add_ns(cmt_time_t t, int64_t ns)
{
    cmt_time_t out;
    int64_t    add_secs;
    int64_t    add_nanos;
    uint64_t   secs;
    int64_t    nanos;

    add_secs  = ns / (int64_t)1000000000;
    add_nanos = ns % (int64_t)1000000000;

    secs  = (uint64_t)t.seconds + (uint64_t)add_secs;
    nanos = (int64_t)t.nanos + add_nanos;
    if (nanos >= (int64_t)CMT_TIME_NANOS_PER_SECOND) {
        nanos -= (int64_t)CMT_TIME_NANOS_PER_SECOND;
        secs  += 1u;
    } else if (nanos < 0) {
        nanos += (int64_t)CMT_TIME_NANOS_PER_SECOND;
        secs  -= 1u;
    }
    out.seconds = (int64_t)secs;
    out.nanos   = (int32_t)nanos;
    return out;
}

/**
 * Go `a.Sub(b)` as a nanosecond count — state.go:558 and :1033.
 *
 * ⚠ STATED LIMIT, not a guess. Go's `time.Time.Sub` is in the Go standard
 * library, which is NOT in the pinned tarball, so its behaviour at the
 * extremes of the range was not read and is not reproduced from memory.
 * What is written here is the wrapping int64 difference of the two
 * UnixNano values (cmt_time.h:152-163 defines that wrap), which is the
 * exact nanosecond difference for every pair of instants where neither
 * UnixNano overflows — roughly [1677-09-21, 2262-04-11]. Both call sites
 * subtract two instants seconds apart, so the difference is exact there.
 * Behaviour outside that window is UNKNOWN and is raised as a QUESTION in
 * this wave's report rather than invented here.
 */
static int64_t cs_time_sub_ns(cmt_time_t a, cmt_time_t b)
{
    uint64_t x;

    x = (uint64_t)cmt_time_unix_nano(a) - (uint64_t)cmt_time_unix_nano(b);
    return (int64_t)x;
}

/** The node's own peer id — the reference's `""` (state.go:479, :839). */
static bool cs_peer_is_self(const cmt_peer_id_t *p)
{
    cmt_peer_id_t self;

    self = cmt_peer_id_self();
    return cmt_peer_id_equals(p, &self);
}

/** `cmt_msg_info_t`'s wire-shaped peer id as the vote sets' peer id.
 *  `peer_id_len == 0` is the reference's `""` (cmt_msgs.h:241-245). */
static int cs_peer_of_msg(const cmt_msg_info_t *mi, cmt_peer_id_t *out)
{
    if (mi == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (mi->peer_id_len == 0u) {
        *out = cmt_peer_id_self();
        return CMT_OK;
    }
    if (mi->peer_id_len != sizeof(out->id)) {
        /* PEER-REACHABLE → CMT_REJECT. Nothing between 0 and 32 is a peer
         * id (cmt_msgs.h:245); a decoder that produced one gave us a
         * message we cannot attribute, so we refuse the message. */
        return CMT_REJECT;
    }
    memcpy(out->id, mi->peer_id, sizeof(out->id));
    return CMT_OK;
}

/** The reverse: a peer id as a message's id field. */
static void cs_msg_set_peer(cmt_msg_info_t *mi, const cmt_peer_id_t *p)
{
    if (p == NULL || cs_peer_is_self(p)) {
        mi->peer_id_len = 0u;
        memset(mi->peer_id, 0, sizeof(mi->peer_id));
        return;
    }
    memcpy(mi->peer_id, p->id, sizeof(p->id));
    mi->peer_id_len = sizeof(p->id);
}

/* ── the two message rings (state.go:110, :111, :168, :169) ─────────── */

static int cs_q_push(cmt_msg_info_t **ring, size_t *head, size_t *len,
                     const cmt_msg_info_t *mi)
{
    cmt_msg_info_t *copy;

    if (*len >= (size_t)CMT_CS_MSG_QUEUE_SIZE) {
        return CMT_REJECT;                        /* the caller decides   */
    }
    copy = (cmt_msg_info_t *)malloc(sizeof(*copy));
    if (copy == NULL) {
        return CMT_FAULT;             /* allocation failure = FAULT       */
    }
    *copy = *mi;
    ring[(*head + *len) % (size_t)CMT_CS_MSG_QUEUE_SIZE] = copy;
    *len += 1u;
    return CMT_OK;
}

static cmt_msg_info_t *cs_q_pop(cmt_msg_info_t **ring, size_t *head,
                                size_t *len)
{
    cmt_msg_info_t *mi;

    if (*len == 0u) {
        return NULL;
    }
    mi    = ring[*head];
    ring[*head] = NULL;
    *head = (*head + 1u) % (size_t)CMT_CS_MSG_QUEUE_SIZE;
    *len -= 1u;
    return mi;
}

static void cs_q_drain(cmt_msg_info_t **ring, size_t *head, size_t *len)
{
    cmt_msg_info_t *mi;

    while ((mi = cs_q_pop(ring, head, len)) != NULL) {
        free(mi);
    }
}

/* ── the three block slots and three part-set slots (cmt_cs.h) ──────── */

/**
 * Take a block slot no name points at, per "OWNERSHIP" (1). The caller
 * MUST have cleared the name it is about to overwrite first.
 *
 * @return CMT_OK; CMT_FAULT when all three are named — NODE-LOCAL, because
 *         the derivation (three names, therefore at most three live
 *         objects) says it cannot happen and a wrong answer here would
 *         corrupt a block another name still refers to.
 */
static int cs_take_block_slot(cmt_cs_t *cs, cmt_block_t **out)
{
    size_t i;

    for (i = 0; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
        cmt_block_t *b = &cs->slots->blocks[i];

        if (b != cs->rs.proposal_block && b != cs->rs.locked_block &&
            b != cs->rs.valid_block) {
            memset(b, 0, sizeof(*b));
            *out = b;
            return CMT_OK;
        }
    }
    QGP_LOG_ERROR(LOG_TAG, "no free block slot: all three are named");
    return CMT_FAULT;
}

/** As `cs_take_block_slot`, for part sets; hands back the INDEX because
 *  the caller needs `slots->parts[i]` and `slots->payload[i]` too. */
static int cs_take_part_slot(cmt_cs_t *cs, size_t *out_idx)
{
    size_t i;

    for (i = 0; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
        cmt_part_set_t *ps = &cs->slots->part_sets[i];

        if (ps != cs->rs.proposal_block_parts &&
            ps != cs->rs.locked_block_parts &&
            ps != cs->rs.valid_block_parts) {
            memset(ps, 0, sizeof(*ps));
            *out_idx = i;
            return CMT_OK;
        }
    }
    QGP_LOG_ERROR(LOG_TAG, "no free part-set slot: all three are named");
    return CMT_FAULT;
}

/**
 * `types.NewPartSetFromHeader(header)` (state.go:1553, :1647, :1945,
 * :2299) into a free slot. The caller clears the name first; this sets it.
 */
static int cs_new_part_set_from_header(cmt_cs_t *cs,
                                       const cmt_part_set_header_t *header,
                                       cmt_part_set_t **out)
{
    size_t idx;
    int    rc;

    rc = cs_take_part_slot(cs, &idx);
    if (rc != CMT_OK) {
        return rc;
    }
    if (cs->slots->parts[idx] == NULL) {
        /* NODE-LOCAL: the host promised this array in cmt_cs_slots_t. */
        QGP_LOG_ERROR(LOG_TAG, "part-set slot %zu has no parts array", idx);
        return CMT_FAULT;
    }
    rc = cmt_new_part_set_from_header(header, cs->slots->parts[idx],
                                      cs->slots->parts_cap[idx],
                                      &cs->slots->part_sets[idx]);
    if (rc != CMT_OK) {
        return rc;
    }
    *out = &cs->slots->part_sets[idx];
    return CMT_OK;
}

/** The index of a part-set slot, so its payload buffer can be reached. */
static int cs_part_slot_index(const cmt_cs_t *cs, const cmt_part_set_t *ps,
                              size_t *out)
{
    size_t i;

    for (i = 0; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
        if (ps == &cs->slots->part_sets[i]) {
            *out = i;
            return CMT_OK;
        }
    }
    return CMT_FAULT;   /* NODE-LOCAL: a part set that is not in the slots */
}

/* ── the validator-set copy of state.go:1073 ────────────────────────── */

/**
 * `validators = validators.Copy(); validators.IncrementProposerPriority(n)`
 * (state.go:1073-1074), which is `CopyIncrementProposerPriority`
 * (validator_set.go:122-126).
 *
 * The destination alternates between two buffers so that a copy is never
 * its own source; `rs.validators` may already point at one of them from
 * an earlier round of the same height.
 */
static int cs_copy_increment_validators(cmt_cs_t *cs, int32_t times)
{
    size_t dst;
    int    rc;

    dst = cs->vals_next;
    if (cs->rs.validators == &cs->vals_buf[dst]) {
        dst = 1u - dst;
    }
    rc = cmt_validator_set_init(&cs->vals_buf[dst], cs->vals_buf_storage[dst],
                                (size_t)CMT_VALSET_MAX);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_copy_increment_proposer_priority(
            cs->rs.validators, &cs->vals_buf[dst], times);
    if (rc != CMT_OK) {
        return rc;
    }
    cs->rs.validators = &cs->vals_buf[dst];
    cs->vals_next     = 1u - dst;
    return CMT_OK;
}

/* ── the ticker's action, applied to the host's timer ───────────────── */

static int cs_apply_ticker_action(cmt_cs_t *cs,
                                  const cmt_ticker_action_t *action)
{
    int rc;

    if (action->cancel_previous) {
        /* ticker.go:88-90 — stop AND discard an undelivered expiry. */
        rc = cs->host.timer_disarm(cs->host_ctx);
        if (rc != CMT_OK) {
            return CMT_FAULT;   /* NODE-LOCAL: our own timer refused us   */
        }
    }
    if (action->arm) {
        rc = cs->host.timer_arm(cs->host_ctx, action->duration); /* :126  */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
    }
    return CMT_OK;
}

/* ── WAL record builders ────────────────────────────────────────────── */

/** wal.Write of an `EventDataRoundState` (state.go:760). */
static int cs_wal_write_round_state(cmt_cs_t *cs)
{
    cmt_wal_message_t *m;
    const char        *step;
    int64_t            height;
    int32_t            round;
    size_t             n;
    int                rc;

    /* Heap: cmt_wal_message_t's MSG_INFO branch carries a whole
     * cmt_msg_t (cmt_wal.h:130-131). */
    m = (cmt_wal_message_t *)calloc(1u, sizeof(*m));
    if (m == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_round_state_event(&cs->rs, &height, &round, &step); /* :759  */
    if (rc != CMT_OK) {
        free(m);
        return rc;
    }
    n = strlen(step);
    if (n > (size_t)CMT_PB_ROUND_STEP_STR_MAX) {
        /* NODE-LOCAL: the eight strings are ours (round_state.go:41-58)
         * and the bound is derived from them (cmt_pb.h:750). */
        free(m);
        return CMT_FAULT;
    }
    m->kind = CMT_PB_WAL_EVENT_DATA_ROUND_STATE;
    m->u.event_data_round_state.height   = height;
    m->u.event_data_round_state.round    = round;
    memcpy(m->u.event_data_round_state.step, step, n);
    m->u.event_data_round_state.step_len = n;

    rc = cs->host.wal_write(cs->host_ctx, m);
    if (rc != CMT_OK) {
        /* :761 — the reference only logs. */
        QGP_LOG_ERROR(LOG_TAG, "failed writing to WAL: round state");
    }
    free(m);
    return CMT_OK;
}

/** wal.Write / wal.WriteSync of a `msgInfo` (state.go:831, :839). */
static int cs_wal_write_msg(cmt_cs_t *cs, const cmt_msg_info_t *mi, bool sync)
{
    cmt_wal_message_t *m;
    int                rc;

    m = (cmt_wal_message_t *)calloc(1u, sizeof(*m));
    if (m == NULL) {
        return CMT_FAULT;
    }
    m->kind        = CMT_PB_WAL_MSG_INFO;
    m->u.msg_info  = *mi;
    if (sync) {
        rc = cs->host.wal_write_sync(cs->host_ctx, m);
    } else {
        rc = cs->host.wal_write(cs->host_ctx, m);
    }
    free(m);
    if (rc != CMT_OK && sync) {
        /* :841-844 — the reference PANICS: "check your file system and
         * restart the node". NODE-LOCAL → CMT_FAULT: the message is this
         * node's own and the failure is its own storage. */
        QGP_LOG_ERROR(LOG_TAG,
                      "failed to write own msg to consensus WAL; "
                      "check your file system and restart the node");
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "failed writing to WAL: peer message"); /* :832 */
    }
    return CMT_OK;
}

/** wal.Write of a `timeoutInfo` (state.go:859). */
static int cs_wal_write_timeout(cmt_cs_t *cs, const cmt_timeout_info_t *ti)
{
    cmt_wal_message_t *m;
    int                rc;

    m = (cmt_wal_message_t *)calloc(1u, sizeof(*m));
    if (m == NULL) {
        return CMT_FAULT;
    }
    m->kind             = CMT_PB_WAL_TIMEOUT_INFO;
    m->u.timeout_info   = *ti;
    rc = cs->host.wal_write(cs->host_ctx, m);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "failed writing to WAL: timeout");   /* :860 */
    }
    free(m);
    return CMT_OK;
}

/** wal.WriteSync of an `EndHeightMessage` (state.go:1759-1765). */
static int cs_wal_write_end_height(cmt_cs_t *cs, int64_t height)
{
    cmt_wal_message_t *m;
    int                rc;

    m = (cmt_wal_message_t *)calloc(1u, sizeof(*m));
    if (m == NULL) {
        return CMT_FAULT;
    }
    m->kind                = CMT_PB_WAL_END_HEIGHT;
    m->u.end_height.height = height;                              /* :1759 */
    rc = cs->host.wal_write_sync(cs->host_ctx, m);
    free(m);
    if (rc != CMT_OK) {
        /* :1761-1764 — panic. NODE-LOCAL → CMT_FAULT. */
        QGP_LOG_ERROR(LOG_TAG,
                      "failed to write EndHeight msg to consensus WAL; "
                      "check your file system and restart the node");
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ── the memoized public key's address (crypto.PubKey.Address) ──────── */

/** `cs.privValidatorPubKey.Address()` — :1184, :1306, :2382, :2456,
 *  :2495. `cmt_pubkey_address` is the tree's one truncation
 *  (cmt_tmhash.h:52). */
static int cs_priv_validator_address(const cmt_cs_t *cs,
                                     uint8_t out[CMT_ADDRESS_SIZE])
{
    if (!cs->priv_validator_pub_key_present) {
        return CMT_FAULT;   /* every caller checks the flag first         */
    }
    return cmt_pubkey_address(cs->priv_validator_pub_key.key, out);
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:240-314 — accessors
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/state.go:240-244 — GetState() */
int cmt_cs_get_state(const cmt_cs_t *cs, cmt_state_t *out)
{
    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return cmt_state_copy(&cs->state, out);                        /* :243 */
}

/* cometbft@709fd12b consensus/state.go:248-252 — GetLastHeight() */
int64_t cmt_cs_get_last_height(const cmt_cs_t *cs)
{
    if (cs == NULL) {
        return 0;
    }
    return cs->rs.height - 1;                                      /* :251 */
}

/* cometbft@709fd12b consensus/state.go:255-260 — GetRoundState() */
int cmt_cs_get_round_state(const cmt_cs_t *cs, cmt_round_state_t *out)
{
    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = cs->rs;                            /* :257 — a shallow copy    */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:277-281 — GetValidators() */
int cmt_cs_get_validators(const cmt_cs_t *cs, int64_t *out_height,
                          cmt_validator_set_t *out)
{
    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (out_height != NULL) {
        *out_height = cs->state.last_block_height;                 /* :280 */
    }
    return cmt_validator_set_copy(&cs->state.validators, out);     /* :280 */
}

/* cometbft@709fd12b consensus/state.go:285-294 — SetPrivValidator() */
int cmt_cs_set_priv_validator(cmt_cs_t *cs, bool present)
{
    if (cs == NULL) {
        return CMT_FAULT;
    }
    cs->has_priv_validator = present;                              /* :289 */
    if (cmt_cs_update_priv_validator_pub_key(cs) != CMT_OK) {      /* :291 */
        QGP_LOG_ERROR(LOG_TAG, "failed to get private validator pubkey");
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:305-314 — LoadCommit() */
int cmt_cs_load_commit(cmt_cs_t *cs, int64_t height, cmt_commit_t *out,
                       bool *out_found)
{
    int64_t store_height;
    int     rc;

    if (cs == NULL || out == NULL || out_found == NULL) {
        return CMT_FAULT;
    }
    rc = cs->host.bs_height(cs->host_ctx, &store_height);          /* :309 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (height == store_height) {
        return cs->host.bs_load_seen_commit(cs->host_ctx, height,
                                            out, out_found);       /* :310 */
    }
    return cs->host.bs_load_block_commit(cs->host_ctx, height,
                                         out, out_found);          /* :313 */
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:477-532 — the public inputs
 * ══════════════════════════════════════════════════════════════════════ */

/** The shared tail of :477-510: choose the queue by whether the peer id is
 *  the empty one (:478, :490, :502) and push. */
static int cs_input(cmt_cs_t *cs, const cmt_msg_info_t *mi)
{
    if (mi->peer_id_len == 0u) {
        int rc = cs_q_push(cs->internal_q, &cs->internal_q_head,
                           &cs->internal_q_len, mi);
        if (rc == CMT_REJECT) {
            /* An overflow of the INTERNAL queue is CMT_FAULT — see
             * cmt_cs.h. The reference reorders instead (:572-577). */
            QGP_LOG_ERROR(LOG_TAG, "internal msg queue full: stopping "
                                   "rather than reordering our own msgs");
            return CMT_FAULT;
        }
        return rc;
    }
    /* The PEER queue refuses where Go blocks the reactor goroutine. */
    return cs_q_push(cs->peer_q, &cs->peer_q_head, &cs->peer_q_len, mi);
}

/* cometbft@709fd12b consensus/state.go:477-486 — AddVote() */
int cmt_cs_add_vote(cmt_cs_t *cs, const cmt_vote_t *vote,
                    const uint8_t *peer_id, size_t peer_id_len)
{
    cmt_msg_info_t *mi;
    int             rc;

    if (cs == NULL || vote == NULL) {
        return CMT_FAULT;
    }
    if (peer_id_len != 0u &&
        (peer_id == NULL || peer_id_len != (size_t)CMT_PB_PEER_ID_MAX)) {
        return CMT_REJECT;   /* explicit bound, INVARIANT atlas-dec-7495d3 */
    }
    mi = (cmt_msg_info_t *)calloc(1u, sizeof(*mi));
    if (mi == NULL) {
        return CMT_FAULT;
    }
    mi->msg.kind             = CMT_PB_CONS_MSG_VOTE;               /* :479 */
    mi->msg.u.vote.has_vote  = true;
    mi->msg.u.vote.vote      = *vote;
    if (peer_id_len != 0u) {
        memcpy(mi->peer_id, peer_id, peer_id_len);
    }
    mi->peer_id_len = peer_id_len;
    rc = cs_input(cs, mi);
    free(mi);
    return rc;                       /* :485 — the reference returns false */
}

/* cometbft@709fd12b consensus/state.go:489-498 — SetProposal() */
int cmt_cs_set_proposal_input(cmt_cs_t *cs, const cmt_proposal_t *proposal,
                              const uint8_t *peer_id, size_t peer_id_len)
{
    cmt_msg_info_t *mi;
    int             rc;

    if (cs == NULL || proposal == NULL) {
        return CMT_FAULT;
    }
    if (peer_id_len != 0u &&
        (peer_id == NULL || peer_id_len != (size_t)CMT_PB_PEER_ID_MAX)) {
        return CMT_REJECT;
    }
    mi = (cmt_msg_info_t *)calloc(1u, sizeof(*mi));
    if (mi == NULL) {
        return CMT_FAULT;
    }
    mi->msg.kind                  = CMT_PB_CONS_MSG_PROPOSAL;      /* :491 */
    mi->msg.u.proposal.proposal   = *proposal;
    if (peer_id_len != 0u) {
        memcpy(mi->peer_id, peer_id, peer_id_len);
    }
    mi->peer_id_len = peer_id_len;
    rc = cs_input(cs, mi);
    free(mi);
    return rc;
}

/* cometbft@709fd12b consensus/state.go:501-510 — AddProposalBlockPart() */
int cmt_cs_add_proposal_block_part_input(cmt_cs_t *cs, int64_t height,
                                         int32_t round,
                                         const cmt_part_t *part,
                                         const uint8_t *peer_id,
                                         size_t peer_id_len)
{
    cmt_msg_info_t *mi;
    int             rc;

    if (cs == NULL || part == NULL) {
        return CMT_FAULT;
    }
    if (peer_id_len != 0u &&
        (peer_id == NULL || peer_id_len != (size_t)CMT_PB_PEER_ID_MAX)) {
        return CMT_REJECT;
    }
    mi = (cmt_msg_info_t *)calloc(1u, sizeof(*mi));
    if (mi == NULL) {
        return CMT_FAULT;
    }
    mi->msg.kind                    = CMT_PB_CONS_MSG_BLOCK_PART;  /* :503 */
    mi->msg.u.block_part.height     = height;
    mi->msg.u.block_part.round      = round;
    mi->msg.u.block_part.part       = *part;
    if (peer_id_len != 0u) {
        memcpy(mi->peer_id, peer_id, peer_id_len);
    }
    mi->peer_id_len = peer_id_len;
    rc = cs_input(cs, mi);
    free(mi);
    return rc;
}

/* cometbft@709fd12b consensus/state.go:513-532 — SetProposalAndBlock() */
int cmt_cs_set_proposal_and_block(cmt_cs_t *cs, const cmt_proposal_t *proposal,
                                  const cmt_part_set_t *parts,
                                  const uint8_t *peer_id, size_t peer_id_len)
{
    uint32_t i;
    uint32_t total;
    int      rc;

    if (cs == NULL || proposal == NULL || parts == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_cs_set_proposal_input(cs, proposal, peer_id, peer_id_len);
    if (rc != CMT_OK) {
        return rc;                                             /* :520-522 */
    }
    total = cmt_part_set_total(parts);
    for (i = 0u; i < total; i++) {                             /* :524     */
        const cmt_part_t *part = cmt_part_set_get_part(parts, i);   /* :525 */

        if (part == NULL) {
            /* Go's `parts.GetPart(i)` returns a nil pointer for a part
             * that has not arrived and :526 dereferences it — a panic
             * NODE-LOCAL to the caller, which is expected to pass a
             * COMPLETE part set. Refusing to dereference is the same
             * stop, without the undefined read. */
            return CMT_FAULT;
        }
        rc = cmt_cs_add_proposal_block_part_input(cs, proposal->height,
                                                  proposal->round, part,
                                                  peer_id, peer_id_len);
        if (rc != CMT_OK) {
            return rc;                                         /* :526-528 */
        }
    }
    return CMT_OK;
}

void cmt_cs_notify_txs_available(cmt_cs_t *cs)
{
    if (cs != NULL) {
        cs->txs_available = true;                                  /* :827 */
    }
}

void cmt_cs_quit(cmt_cs_t *cs)
{
    if (cs != NULL) {
        cs->quit = true;                                           /* :867 */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:537-579 — the small internal setters
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/state.go:537-540 — updateHeight().
 * :538 is a metric and is not ported. */
static void cs_update_height(cmt_cs_t *cs, int64_t height)
{
    cs->rs.height = height;                                        /* :539 */
}

/* cometbft@709fd12b consensus/state.go:542-553 — updateRoundStep().
 * :543-550 is the metrics block, entirely `cs.metrics.*`, and is not
 * ported; the two assignments at :551-552 are the whole behaviour. */
static void cs_update_round_step(cmt_cs_t *cs, int32_t round,
                                 cmt_round_step_t step)
{
    cs->rs.round = round;                                          /* :551 */
    cs->rs.step  = step;                                           /* :552 */
}

/* cometbft@709fd12b consensus/state.go:556-560 — scheduleRound0() */
int cmt_cs_schedule_round0(cmt_cs_t *cs, const cmt_round_state_t *rs)
{
    cmt_time_t now;
    int64_t    sleep_ns;
    int        rc;

    if (cs == NULL || rs == NULL) {
        return CMT_FAULT;
    }
    rc = cs->host.now(cs->host_ctx, &now);      /* :558 — CLOCK SITE 1/5  */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    sleep_ns = cs_time_sub_ns(rs->start_time, now);                /* :558 */
    return cmt_cs_schedule_timeout(cs, sleep_ns, rs->height, 0,
                                   CMT_ROUND_STEP_NEW_HEIGHT);     /* :559 */
}

/* cometbft@709fd12b consensus/state.go:563-565 — scheduleTimeout() */
int cmt_cs_schedule_timeout(cmt_cs_t *cs, int64_t duration_ns, int64_t height,
                            int32_t round, cmt_round_step_t step)
{
    cmt_timeout_info_t  ti;
    cmt_ticker_action_t action;
    int                 rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    ti.duration = duration_ns;                                     /* :564 */
    ti.height   = height;
    ti.round    = round;
    ti.step     = step;
    memset(&action, 0, sizeof(action));
    rc = cmt_ticker_schedule_timeout(&cs->ticker, &ti, &action);
    if (rc != CMT_OK) {
        return rc;
    }
    return cs_apply_ticker_action(cs, &action);
}

/* cometbft@709fd12b consensus/state.go:568-579 — sendInternalMessage().
 *
 * The reference's `default` branch (:571-578) spawns a goroutine, and its
 * own comment at :572-575 says that lets our votes be processed out of
 * order. This port stops instead; see cmt_cs.h. */
static int cs_send_internal_message(cmt_cs_t *cs, const cmt_msg_info_t *mi)
{
    int rc;

    rc = cs_q_push(cs->internal_q, &cs->internal_q_head,
                   &cs->internal_q_len, mi);                       /* :570 */
    if (rc == CMT_REJECT) {
        QGP_LOG_ERROR(LOG_TAG, "internal msg queue is full");       /* :576 */
        return CMT_FAULT;
    }
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:585-643 — rebuilding LastCommit from the store
 * ══════════════════════════════════════════════════════════════════════ */

/** Release whatever `rs.last_commit` currently owns. */
static void cs_release_last_commit(cmt_cs_t *cs)
{
    switch (cs->last_commit_owner) {
    case CMT_CS_LC_OWNED:
        cmt_vote_set_free(cs->last_commit_owned);
        cs->last_commit_owned = NULL;
        break;
    case CMT_CS_LC_PREV_HVS:
        cmt_hvs_free(cs->prev_votes);
        cs->prev_votes = NULL;
        break;
    case CMT_CS_LC_NONE:
    default:
        break;
    }
    cs->last_commit_owner = CMT_CS_LC_NONE;
    cs->rs.last_commit    = NULL;
}

/**
 * C ONLY, and it exists because `cmt_state_t` is a VALUE here.
 *
 * A height vote set borrows its validator set (`cmt_hvs_t.val_set`, and
 * one per round vote set), and `updateToState` hands it
 * `&cs->state.validators` at :744/:746. In Go, `cs.state = state` at :752
 * REPLACES A POINTER: the old `*ValidatorSet` object is untouched and the
 * old height vote set keeps referring to it. Here the copy into
 * `cs->state` overwrites those bytes in place, so a height vote set that
 * outlives the rollover — the one `last_commit` points into, which this
 * module keeps as `prev_votes` — would silently start reading the NEXT
 * height's validators.
 *
 * That is not academic: after the rollover the reference still adds late
 * precommits to LastCommit (:2144 `LastCommit.AddVote`, which reaches
 * `valSet.GetByIndex` for the public key and the power) and still asks it
 * `HasAll` (:2161, which sums `TotalVotingPower`). At an epoch boundary,
 * where the validator set actually changes, those would be answered
 * against the wrong set — two nodes disagreeing on a late vote is a
 * chain-split class defect, not a leak.
 *
 * So before the state is overwritten, the OLD validator set is snapshotted
 * and every borrow inside the surviving height vote set is re-pointed at
 * the snapshot. `last_commit_vals` is the snapshot's home: the OWNED case
 * uses the same buffer and the two cases are mutually exclusive.
 *
 * ⚠ This reaches into wave R2-A's public `cmt_hvs_t` / `cmt_vote_set_t`
 * to rewrite `val_set`. A `cmt_hvs_rebind_val_set` belonging to that
 * module would be the right home; raised as a QUESTION for O7.
 */
static int cs_rebind_hvs_val_set(cmt_hvs_t *hvs, cmt_validator_set_t *vs)
{
    size_t i;

    if (hvs == NULL) {
        return CMT_OK;
    }
    hvs->val_set = vs;
    for (i = 0; i < hvs->round_vote_sets_len; i++) {
        if (hvs->round_vote_sets[i].rvs.prevotes != NULL) {
            hvs->round_vote_sets[i].rvs.prevotes->val_set = vs;
        }
        if (hvs->round_vote_sets[i].rvs.precommits != NULL) {
            hvs->round_vote_sets[i].rvs.precommits->val_set = vs;
        }
    }
    return CMT_OK;
}

/** The LastValidators a standalone LastCommit borrows — its own copy; see
 *  `last_commit_vals` in cmt_cs.h. */
static int cs_bind_last_commit_vals(cmt_cs_t *cs, const cmt_state_t *state)
{
    int rc;

    rc = cmt_validator_set_init(&cs->last_commit_vals,
                                cs->last_commit_vals_storage,
                                (size_t)CMT_VALSET_MAX);
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_validator_set_copy(&state->last_validators,
                                  &cs->last_commit_vals);
}

/* cometbft@709fd12b consensus/state.go:610-624 — votesFromExtendedCommit() */
static int cs_votes_from_extended_commit(cmt_cs_t *cs,
                                         const cmt_state_t *state,
                                         cmt_vote_set_t **out)
{
    cmt_extended_commit_t ec;
    bool                  found;
    int                   rc;

    memset(&ec, 0, sizeof(ec));
    found = false;
    rc = cs->host.bs_load_block_extended_commit(cs->host_ctx,
                                                state->last_block_height,
                                                &ec, &found);      /* :611 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!found) {
        return CMT_REJECT;                                     /* :612-614 */
    }
    if (cmt_extended_commit_get_height(&ec) != state->last_block_height) {
        return CMT_REJECT;                                     /* :615-618 */
    }
    rc = cs_bind_last_commit_vals(cs, state);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_extended_commit_to_extended_vote_set(&ec, state->chain_id,
                                                  state->chain_id_len,
                                                  &cs->last_commit_vals,
                                                  out);            /* :619 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!cmt_vote_set_has_two_thirds_majority(*out)) {             /* :620 */
        cmt_vote_set_free(*out);
        *out = NULL;
        return CMT_REJECT;                                         /* :621 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:626-643 — votesFromSeenCommit() */
static int cs_votes_from_seen_commit(cmt_cs_t *cs, const cmt_state_t *state,
                                     cmt_vote_set_t **out)
{
    cmt_commit_t commit;
    bool         found;
    int          rc;

    memset(&commit, 0, sizeof(commit));
    found = false;
    rc = cs->host.bs_load_seen_commit(cs->host_ctx, state->last_block_height,
                                      &commit, &found);            /* :627 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!found) {                                                  /* :628 */
        rc = cs->host.bs_load_block_commit(cs->host_ctx,
                                           state->last_block_height,
                                           &commit, &found);       /* :629 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
    }
    if (!found) {
        return CMT_REJECT;                                     /* :631-633 */
    }
    if (commit.height != state->last_block_height) {
        return CMT_REJECT;                                     /* :634-637 */
    }
    rc = cs_bind_last_commit_vals(cs, state);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_commit_to_vote_set(&commit, state->chain_id, state->chain_id_len,
                                &cs->last_commit_vals, out);       /* :638 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!cmt_vote_set_has_two_thirds_majority(*out)) {             /* :639 */
        cmt_vote_set_free(*out);
        *out = NULL;
        return CMT_REJECT;                                         /* :640 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:585-591 — reconstructSeenCommit() */
static int cs_reconstruct_seen_commit(cmt_cs_t *cs, const cmt_state_t *state)
{
    cmt_vote_set_t *votes;
    int             rc;

    votes = NULL;
    rc = cs_votes_from_seen_commit(cs, state, &votes);             /* :586 */
    if (rc != CMT_OK) {
        /* :587-589 — the reference PANICS. NODE-LOCAL → CMT_FAULT: the
         * commit came out of this node's own store and disagrees with
         * this node's own validator set; no peer is involved. */
        QGP_LOG_ERROR(LOG_TAG, "failed to reconstruct last commit");
        return CMT_FAULT;
    }
    cs_release_last_commit(cs);
    cs->rs.last_commit    = votes;                                 /* :590 */
    cs->last_commit_owned = votes;
    cs->last_commit_owner = CMT_CS_LC_OWNED;
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:597-608 — reconstructLastCommit() */
static int cs_reconstruct_last_commit(cmt_cs_t *cs, const cmt_state_t *state)
{
    cmt_vote_set_t *votes;
    bool            extensions_enabled;
    int             rc;

    extensions_enabled = false;
    rc = cmt_abci_params_vote_extensions_enabled(state->consensus_params.abci,
                                                 state->last_block_height,
                                                 &extensions_enabled);/* :598 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!extensions_enabled) {                                     /* :599 */
        return cs_reconstruct_seen_commit(cs, state);              /* :600 */
    }
    votes = NULL;
    rc = cs_votes_from_extended_commit(cs, state, &votes);         /* :603 */
    if (rc != CMT_OK) {
        /* :604-606 — panic. NODE-LOCAL → CMT_FAULT, same reason as :588. */
        QGP_LOG_ERROR(LOG_TAG, "failed to reconstruct last extended commit");
        return CMT_FAULT;
    }
    cs_release_last_commit(cs);
    cs->rs.last_commit    = votes;                                 /* :607 */
    cs->last_commit_owned = votes;
    cs->last_commit_owner = CMT_CS_LC_OWNED;
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:647-774 — updateToState and newStep
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/state.go:758-774 — newStep().
 * :767-773 is the event bus and the event switch; neither is ported. */
static int cs_new_step(cmt_cs_t *cs)
{
    int rc;

    rc = cs_wal_write_round_state(cs);                         /* :759-762 */
    if (rc != CMT_OK) {
        return rc;
    }
    cs->n_steps++;                                                 /* :764 */
    return CMT_OK;
}

int cmt_cs_update_to_state(cmt_cs_t *cs, const cmt_state_t *state)
{
    cmt_vote_set_t *new_last_commit;
    cmt_hvs_t      *old_votes;
    bool            take_prev_hvs;
    bool            keep_last_commit;
    bool            ext_enabled;
    int64_t         height;
    int             rc;

    if (cs == NULL || state == NULL) {
        return CMT_FAULT;
    }
    if (state == &cs->state) {
        /* NODE-LOCAL: the reference's `state` is always a COPY the caller
         * made (:1770), never `cs.state` itself, and the copy into
         * `cs->state` below would otherwise read its own destination. */
        QGP_LOG_ERROR(LOG_TAG, "updateToState() called with cs->state itself");
        return CMT_FAULT;
    }

    if (cs->rs.commit_round > -1 && 0 < cs->rs.height &&
        cs->rs.height != state->last_block_height) {
        /* :649-652 — panic. NODE-LOCAL → CMT_FAULT: this compares the
         * state machine's own height against the state its own caller
         * handed it; a peer cannot reach either number. */
        QGP_LOG_ERROR(LOG_TAG,
                      "updateToState() expected state height of %lld "
                      "but found %lld",
                      (long long)cs->rs.height,
                      (long long)state->last_block_height);
        return CMT_FAULT;
    }

    if (!cmt_state_is_empty(&cs->state)) {                         /* :655 */
        if (cs->state.last_block_height > 0 &&
            cs->state.last_block_height + 1 != cs->rs.height) {
            /* :659-662 — panic, and the reference's own comment says why:
             * "Someone forgot to pass in state.Copy() somewhere?!".
             * NODE-LOCAL → CMT_FAULT. */
            QGP_LOG_ERROR(LOG_TAG,
                          "inconsistent cs.state.LastBlockHeight+1 %lld "
                          "vs cs.Height %lld",
                          (long long)(cs->state.last_block_height + 1),
                          (long long)cs->rs.height);
            return CMT_FAULT;
        }
        if (cs->state.last_block_height > 0 &&
            cs->rs.height == cs->state.initial_height) {
            /* :665-668 — panic. NODE-LOCAL → CMT_FAULT, same reason. */
            QGP_LOG_ERROR(LOG_TAG,
                          "inconsistent cs.state.LastBlockHeight %lld, "
                          "expected 0 for initial height %lld",
                          (long long)cs->state.last_block_height,
                          (long long)cs->state.initial_height);
            return CMT_FAULT;
        }
        if (state->last_block_height <= cs->state.last_block_height) {
            /* :676-684 — the state is not further out than ours; signal
             * the step and do nothing else. */
            return cs_new_step(cs);                                /* :682 */
        }
    }

    /* :690-710 — decide what LastCommit becomes. `keep_last_commit` is the
     * reference's "no case matched", which leaves cs.LastCommit alone. */
    new_last_commit  = NULL;
    take_prev_hvs    = false;
    keep_last_commit = false;

    if (state->last_block_height == 0) {                           /* :691 */
        new_last_commit = NULL;                                    /* :692 */
    } else if (cs->rs.commit_round > -1 && cs->rs.votes != NULL) { /* :693 */
        cmt_vote_set_t *pc = cmt_hvs_precommits(cs->rs.votes,
                                                cs->rs.commit_round);

        if (!cmt_vote_set_has_two_thirds_majority(pc)) {           /* :694 */
            /* :695-698 — panic. NODE-LOCAL → CMT_FAULT: the state machine
             * is about to form a commit out of its own precommit set and
             * that set does not have the majority its own transition
             * guaranteed. */
            QGP_LOG_ERROR(LOG_TAG,
                          "wanted to form a commit, but precommits "
                          "(H/R: %lld/%d) didn't have 2/3+",
                          (long long)state->last_block_height,
                          (int)cs->rs.commit_round);
            return CMT_FAULT;
        }
        new_last_commit = pc;                                      /* :701 */
        take_prev_hvs   = true;
    } else if (cs->rs.last_commit == NULL) {                       /* :703 */
        /* :706-709 — panic. NODE-LOCAL → CMT_FAULT: reconstructLastCommit
         * is supposed to have run before this point (:704-705). */
        QGP_LOG_ERROR(LOG_TAG,
                      "last commit cannot be empty after initial block "
                      "(H:%lld)", (long long)(state->last_block_height + 1));
        return CMT_FAULT;
    } else {
        keep_last_commit = true;
    }

    /* Release the OLD LastCommit's owner, unless we are keeping it. This
     * is where the previous height's vote set finally dies; Go simply
     * drops the reference and lets the collector do it. */
    if (!keep_last_commit) {
        cs_release_last_commit(cs);
    }

    old_votes = cs->rs.votes;
    if (take_prev_hvs) {
        /* `new_last_commit` points INTO `old_votes`, so `old_votes` must
         * outlive it: it becomes prev_votes and is freed one height on. */
        cs->prev_votes        = old_votes;
        cs->last_commit_owner = CMT_CS_LC_PREV_HVS;

        /* And its borrowed validator set must outlive the state copy
         * below — see cs_rebind_hvs_val_set for why this is a chain-split
         * hazard and not a leak. Snapshot the OLD set first. */
        rc = cmt_validator_set_init(&cs->last_commit_vals,
                                    cs->last_commit_vals_storage,
                                    (size_t)CMT_VALSET_MAX);
        if (rc != CMT_OK) {
            return rc;
        }
        rc = cmt_validator_set_copy(&cs->state.validators,
                                    &cs->last_commit_vals);
        if (rc != CMT_OK) {
            return rc;
        }
        rc = cs_rebind_hvs_val_set(cs->prev_votes, &cs->last_commit_vals);
        if (rc != CMT_OK) {
            return rc;
        }
    } else if (old_votes != NULL && old_votes != cs->prev_votes) {
        cmt_hvs_free(old_votes);
    }
    cs->rs.votes       = NULL;
    cs->rs.last_commit = keep_last_commit ? cs->rs.last_commit
                                          : new_last_commit;
    if (!keep_last_commit && new_last_commit == NULL) {
        cs->last_commit_owner = CMT_CS_LC_NONE;
    }

    /* THE STATE COPY MOVES HERE, and this is the one reordering in this
     * function. In Go `cs.state = state` at :752 stores a struct whose
     * `Validators` and `LastValidators` are POINTERS the new
     * HeightVoteSet at :744/:746 already shares. Here `cmt_state_t` is a
     * value, so the height vote set must borrow `&cs->state.validators`
     * — which means the copy has to happen before :743-746 rather than
     * after. Nothing between :685 and :752 reads the OLD `cs.state`:
     * :713-716 read `state`, :743-746 read `state`, :749 reads `state`.
     * Verified line by line before moving it. */
    rc = cmt_state_copy(state, &cs->state);                        /* :752 */
    if (rc != CMT_OK) {
        return rc;
    }

    height = cs->state.last_block_height + 1;                      /* :713 */
    if (height == 1) {                                             /* :714 */
        height = cs->state.initial_height;                         /* :715 */
    }

    cs_update_height(cs, height);                                  /* :719 */
    cs_update_round_step(cs, 0, CMT_ROUND_STEP_NEW_HEIGHT);        /* :720 */

    if (cmt_time_is_zero(cs->rs.commit_time)) {                    /* :722 */
        cmt_time_t now;

        rc = cs->host.now(cs->host_ctx, &now);  /* :728 — CLOCK SITE 2/5  */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        rc = cmt_config_commit(cs->config, now, &cs->rs.start_time);/* :728 */
    } else {
        rc = cmt_config_commit(cs->config, cs->rs.commit_time,
                               &cs->rs.start_time);                /* :730 */
    }
    if (rc != CMT_OK) {
        return rc;
    }

    cs->rs.validators           = &cs->state.validators;           /* :733 */
    cs->rs.proposal             = NULL;                            /* :734 */
    cs->rs.proposal_block       = NULL;                            /* :735 */
    cs->rs.proposal_block_parts = NULL;                            /* :736 */
    cs->rs.locked_round         = -1;                              /* :737 */
    cs->rs.locked_block         = NULL;                            /* :738 */
    cs->rs.locked_block_parts   = NULL;                            /* :739 */
    cs->rs.valid_round          = -1;                              /* :740 */
    cs->rs.valid_block          = NULL;                            /* :741 */
    cs->rs.valid_block_parts    = NULL;                            /* :742 */

    ext_enabled = false;
    rc = cmt_abci_params_vote_extensions_enabled(
            cs->state.consensus_params.abci, height, &ext_enabled);/* :743 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (ext_enabled) {
        rc = cmt_new_extended_height_vote_set(cs->state.chain_id,
                                              cs->state.chain_id_len, height,
                                              &cs->state.validators,
                                              &cs->rs.votes);      /* :744 */
    } else {
        rc = cmt_new_height_vote_set(cs->state.chain_id,
                                     cs->state.chain_id_len, height,
                                     &cs->state.validators,
                                     &cs->rs.votes);               /* :746 */
    }
    if (rc != CMT_OK) {
        return rc;
    }
    cs->rs.commit_round                = -1;                       /* :748 */
    cs->rs.last_validators             = &cs->state.last_validators;/* :749 */
    cs->rs.triggered_timeout_precommit = false;                    /* :750 */

    return cs_new_step(cs);                                        /* :755 */
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:784-872 — the event loop, one iteration
 * ══════════════════════════════════════════════════════════════════════ */

bool cmt_cs_has_work(const cmt_cs_t *cs)
{
    if (cs == NULL) {
        return false;
    }
    return cs->txs_available || cs->peer_q_len > 0u ||
           cs->internal_q_len > 0u || cs->tock_pending || cs->quit;
}

int cmt_cs_on_timer_expired(cmt_cs_t *cs)
{
    cmt_timeout_info_t ti;
    int                rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->tock_pending) {
        /* NODE-LOCAL: the reference's tockChan carries one timeout and the
         * routine is the only reader. Two undelivered tocks means the host
         * armed or delivered a timer this module did not ask for. */
        QGP_LOG_ERROR(LOG_TAG, "timer fired while a tock is still pending");
        return CMT_FAULT;
    }
    rc = cmt_ticker_fire(&cs->ticker, &ti);              /* ticker.go:130-137 */
    if (rc != CMT_OK) {
        return rc;
    }
    cs->tock          = ti;
    cs->tock_pending  = true;
    return CMT_OK;
}

int cmt_cs_step(cmt_cs_t *cs, bool *out_worked)
{
    cmt_round_state_t  rs;
    cmt_msg_info_t    *mi;
    int                rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (out_worked != NULL) {
        *out_worked = false;
    }

    if (cs->max_steps > 0 && cs->n_steps >= cs->max_steps) {    /* :815-821 */
        cs->n_steps = 0;                                           /* :818 */
        return CMT_OK;
    }

    /* :823 — the round state as it is BEFORE the poll. handleTimeout
     * compares against THIS, not against the live one (:865). */
    rs = cs->rs;

    /* 1. :827-828 */
    if (cs->txs_available) {
        cs->txs_available = false;
        if (out_worked != NULL) {
            *out_worked = true;
        }
        return cmt_cs_handle_txs_available(cs);                    /* :828 */
    }

    /* 2. :830-836 */
    mi = cs_q_pop(cs->peer_q, &cs->peer_q_head, &cs->peer_q_len);
    if (mi != NULL) {
        if (out_worked != NULL) {
            *out_worked = true;
        }
        rc = cs_wal_write_msg(cs, mi, false);                      /* :831 */
        if (rc != CMT_OK) {
            free(mi);
            return rc;
        }
        rc = cmt_cs_handle_msg(cs, mi);                            /* :836 */
        free(mi);
        return rc;
    }

    /* 3. :838-856 */
    mi = cs_q_pop(cs->internal_q, &cs->internal_q_head, &cs->internal_q_len);
    if (mi != NULL) {
        bool is_vote;

        if (out_worked != NULL) {
            *out_worked = true;
        }
        rc = cs_wal_write_msg(cs, mi, true);                       /* :839 */
        if (rc != CMT_OK) {
            free(mi);
            return rc;                    /* :841-844 panic → CMT_FAULT   */
        }
        is_vote = (mi->msg.kind == CMT_PB_CONS_MSG_VOTE);          /* :847 */
        if (is_vote) {
            CMT_FAIL_POINT();                                      /* :852 */
        }
        rc = cmt_cs_handle_msg(cs, mi);                            /* :856 */
        free(mi);
        return rc;
    }

    /* 4. :858-865 */
    if (cs->tock_pending) {
        cmt_timeout_info_t ti = cs->tock;

        cs->tock_pending = false;
        if (out_worked != NULL) {
            *out_worked = true;
        }
        rc = cs_wal_write_timeout(cs, &ti);                        /* :859 */
        if (rc != CMT_OK) {
            return rc;
        }
        return cmt_cs_handle_timeout(cs, &ti, &rs);                /* :865 */
    }

    /* 5. :867-869 — onExit. The WAL is the host's and is stopped there;
     * `close(cs.done)` has no counterpart in a single-threaded port. */
    if (cs->quit) {
        if (out_worked != NULL) {
            *out_worked = true;
        }
        return CMT_OK;
    }
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:875-1039 — handleMsg, handleTimeout, handleTxsAvailable
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_handle_msg(cmt_cs_t *cs, const cmt_msg_info_t *mi)
{
    cmt_peer_id_t peer;
    bool          added;
    int           err;
    int           rc;

    if (cs == NULL || mi == NULL) {
        return CMT_FAULT;
    }
    rc = cs_peer_of_msg(mi, &peer);                                /* :883 */
    if (rc != CMT_OK) {
        if (rc == CMT_FAULT) {
            return CMT_FAULT;
        }
        /* An unattributable peer id. The reference's `handleMsg` returns
         * NOTHING — every message error it meets ends in the log line at
         * :955-962 — so a refusal here is logged the same way rather than
         * propagated out of the event loop. */
        QGP_LOG_ERROR(LOG_TAG, "failed to process message: peer id is "
                               "neither empty nor 32 bytes");
        return CMT_OK;
    }
    added = false;
    err   = CMT_OK;

    switch (mi->msg.kind) {                                        /* :885 */
    case CMT_PB_CONS_MSG_PROPOSAL:                                 /* :886 */
        err = cs->set_proposal(cs, &mi->msg.u.proposal.proposal);  /* :889 */
        if (err == CMT_FAULT) {
            return CMT_FAULT;
        }
        break;

    case CMT_PB_CONS_MSG_BLOCK_PART:                               /* :891 */
        err = cmt_cs_add_proposal_block_part(cs, &mi->msg.u.block_part,
                                             &peer, &added);       /* :893 */
        if (err == CMT_FAULT) {
            return CMT_FAULT;
        }
        /* :906-908 — the reference drops and retakes the mutex here so
         * that the reactor can read the round state. One thread has
         * nothing to yield to, and the reference's own comment says the
         * purpose is reactor visibility, not ordering. */
        if (added && cmt_part_set_is_complete(cs->rs.proposal_block_parts)) {
            rc = cmt_cs_handle_complete_proposal(cs,
                                                 mi->msg.u.block_part.height);
            if (rc == CMT_FAULT) {
                return CMT_FAULT;                              /* :909-911 */
            }
        }
        /* :912-914 — statsMsgQueue feeds the reactor's statistics only. */
        if (err != CMT_OK && mi->msg.u.block_part.round != cs->rs.round) {
            /* :916-924 — a block part from a round we have left is not an
             * error at all. */
            err = CMT_OK;                                          /* :923 */
        }
        break;

    case CMT_PB_CONS_MSG_VOTE:                                     /* :926 */
        if (!mi->msg.u.vote.has_vote) {
            /* Go carries a `*types.Vote` here and :929 passes it straight
             * to tryAddVote, which dereferences it at :2121. A nil is a
             * panic there. PEER-REACHABLE → CMT_REJECT: msgs.go:187 can
             * produce a VoteMessage from a wire message with no vote
             * field, so a peer's bytes reach it. */
            err = CMT_REJECT;
            break;
        }
        err = cmt_cs_try_add_vote(cs, &mi->msg.u.vote.vote, &peer, &added);
        if (err == CMT_FAULT) {
            return CMT_FAULT;                                      /* :929 */
        }
        /* :930-932 — statsMsgQueue, not ported. */
        break;

    default:                                                       /* :949 */
        QGP_LOG_ERROR(LOG_TAG, "unknown msg type %d", (int)mi->msg.kind);
        return CMT_OK;                                             /* :951 */
    }

    if (err != CMT_OK) {                                           /* :954 */
        /* :955-962 — the reference LOGS every message error and returns
         * normally; nothing propagates out of handleMsg. */
        QGP_LOG_ERROR(LOG_TAG,
                      "failed to process message: height %lld round %d "
                      "kind %d rc %d",
                      (long long)cs->rs.height, (int)cs->rs.round,
                      (int)mi->msg.kind, err);
    }
    return CMT_OK;
}

int cmt_cs_handle_timeout(cmt_cs_t *cs, const cmt_timeout_info_t *ti,
                          const cmt_round_state_t *rs)
{
    int rc;

    if (cs == NULL || ti == NULL || rs == NULL) {
        return CMT_FAULT;
    }
    /* :970 — the acceptance rule. A timeout for another height, an older
     * round, or an earlier step of the same round is dropped. */
    if (ti->height != rs->height || ti->round < rs->round ||
        (ti->round == rs->round && ti->step < rs->step)) {
        return CMT_OK;                                         /* :971-972 */
    }

    switch (ti->step) {                                            /* :979 */
    case CMT_ROUND_STEP_NEW_HEIGHT:                                /* :980 */
        return cmt_cs_enter_new_round(cs, ti->height, 0);           /* :983 */

    case CMT_ROUND_STEP_NEW_ROUND:                                 /* :985 */
        return cmt_cs_enter_propose(cs, ti->height, ti->round);     /* :986 */

    case CMT_ROUND_STEP_PROPOSE:                                   /* :988 */
        /* :989-991 — PublishEventTimeoutPropose, not ported. */
        return cmt_cs_enter_prevote(cs, ti->height, ti->round);      /* :993 */

    case CMT_ROUND_STEP_PREVOTE_WAIT:                              /* :995 */
        /* :996-998 — PublishEventTimeoutWait, not ported. */
        return cmt_cs_enter_precommit(cs, ti->height, ti->round);   /* :1000 */

    case CMT_ROUND_STEP_PRECOMMIT_WAIT:                           /* :1002 */
        /* :1003-1005 — PublishEventTimeoutWait; :1007
         * emitPrecommitTimeoutMetrics — neither is ported. */
        rc = cmt_cs_enter_precommit(cs, ti->height, ti->round);    /* :1008 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        return cmt_cs_enter_new_round(cs, ti->height, ti->round + 1);/* :1009 */

    default:                                                      /* :1011 */
        /* :1012 — panic("invalid timeout step"). NODE-LOCAL → CMT_FAULT:
         * every timeout in the queue was put there by this module's own
         * scheduleTimeout with a literal step, and the ticker only ever
         * hands back what it was given (ticker.go:125, :137). */
        QGP_LOG_ERROR(LOG_TAG, "invalid timeout step: %u",
                      (unsigned)ti->step);
        return CMT_FAULT;
    }
}

int cmt_cs_handle_txs_available(cmt_cs_t *cs)
{
    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.round != 0) {                                      /* :1021 */
        return CMT_OK;                                            /* :1022 */
    }

    switch (cs->rs.step) {                                        /* :1025 */
    case CMT_ROUND_STEP_NEW_HEIGHT: {                             /* :1026 */
        bool       need;
        cmt_time_t now;
        int64_t    timeout_commit;
        int        rc;

        need = false;
        rc = cmt_cs_need_proof_block(cs, cs->rs.height, &need);    /* :1027 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (need) {
            return CMT_OK;               /* :1028-1030 — enterNewRound will */
        }
        rc = cs->host.now(cs->host_ctx, &now); /* :1033 — CLOCK SITE 3/5   */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        /* :1032-1033 — "+1ms to ensure RoundStepNewRound timeout always
         * happens after RoundStepNewHeight". */
        timeout_commit = cs_time_sub_ns(cs->rs.start_time, now) +
                         CMT_CS_TIME_IOTA_NS;
        return cmt_cs_schedule_timeout(cs, timeout_commit, cs->rs.height, 0,
                                       CMT_ROUND_STEP_NEW_ROUND); /* :1034 */
    }

    case CMT_ROUND_STEP_NEW_ROUND:                                /* :1036 */
        return cmt_cs_enter_propose(cs, cs->rs.height, 0);        /* :1037 */

    default:
        return CMT_OK;      /* the reference's switch has no other case   */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:1053-1132 — enterNewRound, needProofBlock
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_enter_new_round(cmt_cs_t *cs, int64_t height, int32_t round)
{
    cmt_validator_t proposer;
    int32_t         times;
    int32_t         next_round;
    bool            need_proof;
    bool            wait_for_txs;
    int             rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || round < cs->rs.round ||
        (cs->rs.round == round && cs->rs.step != CMT_ROUND_STEP_NEW_HEIGHT)) {
        return CMT_OK;                                       /* :1056-1062 */
    }
    /* :1064-1066 is a log line about StartTime being in the future; it
     * reads the clock only to print it (cmt_cs.h's clock note). */

    if (cs->rs.round < round) {                                   /* :1072 */
        rc = cmt_safe_sub_int32(round, cs->rs.round, &times);     /* :1074 */
        if (rc != CMT_OK) {
            /* SafeSubInt32 panics on overflow (safemath.go:25-32).
             * NODE-LOCAL → CMT_FAULT: both rounds are this module's own
             * counters. */
            QGP_LOG_ERROR(LOG_TAG, "round arithmetic overflowed");
            return CMT_FAULT;
        }
        rc = cs_copy_increment_validators(cs, times);        /* :1073-1074 */
        if (rc != CMT_OK) {
            return rc;
        }
    }

    /* :1080-1081 — the round step first, then the validators. The copy
     * above has already installed them into rs.validators, which is what
     * :1081 does; the order of the two assignments is not observable
     * because nothing between them reads either. */
    cs_update_round_step(cs, round, CMT_ROUND_STEP_NEW_ROUND);    /* :1080 */

    rc = cmt_validator_set_get_proposer(cs->rs.validators, &proposer);/* :1084 */
    if (rc != CMT_OK) {
        /* GetProposer REJECTs on an empty set, where the reference returns
         * nil and :1084 nil-dereferences. NODE-LOCAL → CMT_FAULT: the
         * validator set is this node's own state. */
        QGP_LOG_ERROR(LOG_TAG, "no proposer for height %lld round %d",
                      (long long)height, (int)round);
        return CMT_FAULT;
    }
    if (round != 0) {                                             /* :1085 */
        cs->rs.proposal             = NULL;                       /* :1087 */
        cs->rs.proposal_block       = NULL;                       /* :1088 */
        cs->rs.proposal_block_parts = NULL;                       /* :1089 */
    }

    rc = cmt_safe_add_int32(round, 1, &next_round);               /* :1097 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "round+1 overflowed");   /* NODE-LOCAL     */
        return CMT_FAULT;
    }
    /* :1097 — also track round+1 so a round-skip has somewhere to land. */
    rc = cmt_hvs_set_round(cs->rs.votes, next_round);
    if (rc != CMT_OK) {
        return rc;
    }
    cs->rs.triggered_timeout_precommit = false;                   /* :1098 */
    /* :1100-1102 — PublishEventNewRound, not ported. */

    need_proof = false;
    rc = cmt_cs_need_proof_block(cs, height, &need_proof);        /* :1106 */
    if (rc != CMT_OK) {
        return rc;
    }
    wait_for_txs = cmt_config_wait_for_txs(cs->config) && round == 0 &&
                   !need_proof;                                   /* :1106 */
    if (wait_for_txs) {                                           /* :1107 */
        if (cs->config->create_empty_blocks_interval > 0) {       /* :1108 */
            return cmt_cs_schedule_timeout(
                    cs, cs->config->create_empty_blocks_interval, height,
                    round, CMT_ROUND_STEP_NEW_ROUND);        /* :1109-1110 */
        }
        return CMT_OK;
    }
    return cmt_cs_enter_propose(cs, height, round);               /* :1113 */
}

int cmt_cs_need_proof_block(cmt_cs_t *cs, int64_t height, bool *out)
{
    cmt_header_t *meta;
    bool          found;
    int           rc;

    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = false;
    if (height == cs->state.initial_height) {                     /* :1120 */
        *out = true;                                              /* :1121 */
        return CMT_OK;
    }
    /* Heap: a cmt_header_t carries fourteen fields, several of them
     * 64-byte hashes, and this is called from a deep call chain. */
    meta = (cmt_header_t *)calloc(1u, sizeof(*meta));
    if (meta == NULL) {
        return CMT_FAULT;
    }
    found = false;
    rc = cs->host.bs_load_block_meta(cs->host_ctx, height - 1, meta, &found);
    if (rc != CMT_OK) {                                           /* :1124 */
        free(meta);
        return CMT_FAULT;
    }
    if (!found) {
        /* :1125-1129 — "short-circuited needProofBlock", the reference's
         * own workaround for cometbft issue 370. */
        free(meta);
        *out = true;                                              /* :1128 */
        return CMT_OK;
    }
    /* :1131 — !bytes.Equal(cs.state.AppHash, lastBlockMeta.Header.AppHash) */
    *out = !(cs->state.app_hash_len == meta->app_hash_len &&
             memcmp(cs->state.app_hash, meta->app_hash,
                    cs->state.app_hash_len) == 0);
    free(meta);
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:1140-1313 — enterPropose and the proposal it makes
 * ══════════════════════════════════════════════════════════════════════ */

/** The `defer` of :1153-1164, which runs on EVERY return from
 *  enterPropose. Written out because C has no defer. */
static int cs_enter_propose_done(cmt_cs_t *cs, int64_t height, int32_t round)
{
    bool complete;
    int  rc;

    cs_update_round_step(cs, round, CMT_ROUND_STEP_PROPOSE);      /* :1155 */
    rc = cs_new_step(cs);                                         /* :1156 */
    if (rc != CMT_OK) {
        return rc;
    }
    complete = false;
    rc = cmt_cs_is_proposal_complete(cs, &complete);              /* :1161 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (complete) {
        return cmt_cs_enter_prevote(cs, height, cs->rs.round);    /* :1162 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:1200-1202 — isProposer() */
static bool cs_is_proposer(cmt_cs_t *cs, const uint8_t *address,
                           size_t address_len)
{
    cmt_validator_t proposer;

    if (cmt_validator_set_get_proposer(cs->rs.validators, &proposer) !=
        CMT_OK) {
        return false;
    }
    return proposer.address_len == address_len &&
           memcmp(proposer.address, address, address_len) == 0;   /* :1201 */
}

int cmt_cs_enter_propose(cmt_cs_t *cs, int64_t height, int32_t round)
{
    uint8_t address[CMT_ADDRESS_SIZE];
    int     rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || round < cs->rs.round ||
        (cs->rs.round == round && CMT_ROUND_STEP_PROPOSE <= cs->rs.step)) {
        return CMT_OK;                                       /* :1143-1149 */
    }

    /* :1167 — if the proposal does not arrive in time, prevote anyway. */
    rc = cmt_cs_schedule_timeout(cs, cmt_config_propose(cs->config, round),
                                 height, round, CMT_ROUND_STEP_PROPOSE);
    if (rc != CMT_OK) {
        return rc;
    }

    if (!cs->has_priv_validator) {                                /* :1170 */
        return cs_enter_propose_done(cs, height, round);          /* :1172 */
    }
    if (!cs->priv_validator_pub_key_present) {                    /* :1177 */
        QGP_LOG_ERROR(LOG_TAG, "propose step; empty priv validator "
                               "public key");                     /* :1180 */
        return cs_enter_propose_done(cs, height, round);          /* :1181 */
    }
    rc = cs_priv_validator_address(cs, address);                  /* :1184 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!cmt_validator_set_has_address(cs->rs.validators, address,
                                       sizeof(address))) {        /* :1187 */
        return cs_enter_propose_done(cs, height, round);          /* :1189 */
    }
    if (cs_is_proposer(cs, address, sizeof(address))) {           /* :1192 */
        rc = cs->decide_proposal(cs, height, round);              /* :1194 */
        if (rc == CMT_FAULT) {
            return rc;
        }
    }
    return cs_enter_propose_done(cs, height, round);
}

/* cometbft@709fd12b consensus/state.go:1279-1313 — createProposalBlock() */
static int cs_create_proposal_block(cmt_cs_t *cs, cmt_block_t **out)
{
    cmt_extended_commit_t     *last_ext_commit;
    cmt_extended_commit_sig_t *sigs;
    uint8_t                    proposer_addr[CMT_ADDRESS_SIZE];
    cmt_block_t               *slot;
    size_t                     n_sigs;
    int                        rc;

    if (!cs->has_priv_validator) {
        return CMT_REJECT;                                   /* :1280-1282 */
    }

    n_sigs = (size_t)cmt_vote_set_size(cs->rs.last_commit);
    if (n_sigs > (size_t)CMT_VALSET_MAX) {
        return CMT_FAULT;    /* NODE-LOCAL: our own set exceeds its bound */
    }
    last_ext_commit = (cmt_extended_commit_t *)calloc(1u,
                                                      sizeof(*last_ext_commit));
    sigs = (cmt_extended_commit_sig_t *)calloc(n_sigs == 0u ? 1u : n_sigs,
                                               sizeof(*sigs));
    if (last_ext_commit == NULL || sigs == NULL) {
        free(last_ext_commit);
        free(sigs);
        return CMT_FAULT;
    }

    if (cs->rs.height == cs->state.initial_height) {              /* :1287 */
        /* :1290 — `&types.ExtendedCommit{}`: empty, but not nil. */
        last_ext_commit->extended_signatures     = sigs;
        last_ext_commit->extended_signatures_cap = n_sigs;
        last_ext_commit->extended_signatures_len = 0u;
    } else if (cmt_vote_set_has_two_thirds_majority(cs->rs.last_commit)) {
        rc = cmt_vote_set_make_extended_commit(cs->rs.last_commit,
                                               cs->state.consensus_params.abci,
                                               sigs, n_sigs,
                                               last_ext_commit);  /* :1294 */
        if (rc != CMT_OK) {
            free(last_ext_commit);
            free(sigs);
            return rc;
        }
    } else {
        free(last_ext_commit);
        free(sigs);
        return CMT_REJECT;                                   /* :1296-1297 */
    }

    if (!cs->priv_validator_pub_key_present) {                    /* :1300 */
        free(last_ext_commit);
        free(sigs);
        return CMT_REJECT;                                   /* :1303      */
    }
    rc = cs_priv_validator_address(cs, proposer_addr);            /* :1306 */
    if (rc != CMT_OK) {
        free(last_ext_commit);
        free(sigs);
        return CMT_FAULT;
    }

    slot = NULL;
    rc = cs_take_block_slot(cs, &slot);
    if (rc != CMT_OK) {
        free(last_ext_commit);
        free(sigs);
        return rc;
    }
    rc = cs->host.create_proposal_block(cs->host_ctx, cs->rs.height,
                                        &cs->state, last_ext_commit,
                                        proposer_addr, sizeof(proposer_addr),
                                        slot);                    /* :1308 */
    free(last_ext_commit);
    free(sigs);
    if (rc != CMT_OK) {
        /* :1309-1311 — the reference PANICS on this error. NODE-LOCAL →
         * CMT_FAULT: the block executor is this node's own application
         * and no peer input reaches it here. */
        QGP_LOG_ERROR(LOG_TAG, "CreateProposalBlock failed: rc %d", rc);
        return CMT_FAULT;
    }
    *out = slot;
    return CMT_OK;
}

int cmt_cs_default_decide_proposal(cmt_cs_t *cs, int64_t height, int32_t round)
{
    cmt_block_t          *block;
    cmt_part_set_t       *block_parts;
    cmt_part_set_header_t psh;
    cmt_block_id_t        prop_block_id;
    cmt_proposal_t       *proposal;
    cmt_msg_info_t       *mi;
    uint8_t               block_hash[CMT_TMHASH_SIZE];
    uint32_t              i;
    uint32_t              total;
    int                   rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    block       = NULL;
    block_parts = NULL;

    if (cs->rs.valid_block != NULL) {                             /* :1209 */
        block       = cs->rs.valid_block;                         /* :1211 */
        block_parts = cs->rs.valid_block_parts;
    } else {
        rc = cs_create_proposal_block(cs, &block);                /* :1215 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        if (rc != CMT_OK) {
            /* :1216-1218 — the reference logs and returns. */
            QGP_LOG_ERROR(LOG_TAG, "unable to create proposal block");
            return CMT_OK;
        }
        if (block == NULL) {
            /* :1219-1221 — panic("createProposalBlock should not provide a
             * nil block without errors"). NODE-LOCAL → CMT_FAULT. */
            QGP_LOG_ERROR(LOG_TAG, "createProposalBlock gave a nil block "
                                   "without an error");
            return CMT_FAULT;
        }
        /* :1222 is a metric. :1223 — MakePartSet into the PROPOSER'S OWN
         * buffer, never into one of the three slots: the parts queued at
         * :1246-1249 point into it and `defaultSetProposal` would
         * otherwise be free to take that slot on the very next step. The
         * reasoning and the host's obligation are in cmt_cs.h. */
        if (cs->slots->marshal_parts == NULL ||
            cs->slots->marshal_scratch == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "proposer marshal buffer is not backed");
            return CMT_FAULT;                          /* NODE-LOCAL      */
        }
        memset(&cs->slots->marshal_part_set, 0,
               sizeof(cs->slots->marshal_part_set));
        rc = cmt_block_make_part_set(block, (uint32_t)CMT_BLOCK_PART_SIZE_BYTES,
                                     cs->slots->marshal_scratch,
                                     cs->slots->marshal_scratch_cap,
                                     cs->slots->marshal_parts,
                                     cs->slots->marshal_parts_cap,
                                     &cs->slots->marshal_part_set);
        if (rc != CMT_OK) {
            /* :1224-1227 — the reference logs and returns. */
            QGP_LOG_ERROR(LOG_TAG, "unable to create proposal block part set");
            return CMT_OK;
        }
        block_parts = &cs->slots->marshal_part_set;
    }

    /* :1232 — flush the WAL, or the privValidator may refuse to sign. */
    if (cs->host.wal_flush_and_sync(cs->host_ctx) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "failed flushing WAL to disk");    /* :1233 */
    }

    rc = cmt_block_hash(block, block_hash);                       /* :1237 */
    if (rc != CMT_OK) {
        return CMT_FAULT;         /* NODE-LOCAL: our own block will not hash */
    }
    rc = cmt_part_set_header(block_parts, &psh);                  /* :1237 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    memset(&prop_block_id, 0, sizeof(prop_block_id));
    memcpy(prop_block_id.hash, block_hash, sizeof(block_hash));
    prop_block_id.hash_len       = sizeof(block_hash);
    prop_block_id.part_set_header = psh;

    proposal = (cmt_proposal_t *)calloc(1u, sizeof(*proposal));
    mi       = (cmt_msg_info_t *)calloc(1u, sizeof(*mi));
    if (proposal == NULL || mi == NULL) {
        free(proposal);
        free(mi);
        return CMT_FAULT;
    }
    {
        cmt_time_t now;

        /* proposal.go:44 reads the clock inside NewProposal; this tree's
         * cmt_new_proposal takes it as an argument (cmt_proposal.h:98-101)
         * so that every clock read is at a call site. It is the same
         * instant the reference stamps. */
        if (cs->host.now(cs->host_ctx, &now) != CMT_OK) {
            free(proposal);
            free(mi);
            return CMT_FAULT;
        }
        rc = cmt_new_proposal(height, round, cs->rs.valid_round,
                              &prop_block_id, now, proposal);     /* :1238 */
    }
    if (rc != CMT_OK) {
        free(proposal);
        free(mi);
        return rc;
    }

    rc = cs->host.sign_proposal(cs->host_ctx, cs->state.chain_id,
                                cs->state.chain_id_len, proposal);/* :1240 */
    if (rc != CMT_OK) {
        /* :1252-1254 — a signing failure is logged (unless replaying) and
         * nothing is sent. */
        if (!cs->replay_mode) {
            QGP_LOG_ERROR(LOG_TAG, "propose step; failed signing proposal: "
                                   "height %lld round %d",
                          (long long)height, (int)round);
        }
        free(proposal);
        free(mi);
        return CMT_OK;
    }

    /* :1244 — our own proposal goes onto the internal queue like any
     * other message and is handled on a LATER step. */
    mi->msg.kind                = CMT_PB_CONS_MSG_PROPOSAL;
    mi->msg.u.proposal.proposal = *proposal;
    cs_msg_set_peer(mi, NULL);
    rc = cs_send_internal_message(cs, mi);
    if (rc != CMT_OK) {
        free(proposal);
        free(mi);
        return rc;
    }

    total = cmt_part_set_total(block_parts);                      /* :1246 */
    for (i = 0u; i < total; i++) {
        const cmt_part_t *part = cmt_part_set_get_part(block_parts, i);

        if (part == NULL) {
            /* Go indexes its own freshly built part set at :1247 and a
             * nil there is a panic at :1248. NODE-LOCAL → CMT_FAULT. */
            free(proposal);
            free(mi);
            return CMT_FAULT;
        }
        memset(mi, 0, sizeof(*mi));
        mi->msg.kind                = CMT_PB_CONS_MSG_BLOCK_PART;
        mi->msg.u.block_part.height = cs->rs.height;              /* :1248 */
        mi->msg.u.block_part.round  = cs->rs.round;
        mi->msg.u.block_part.part   = *part;
        cs_msg_set_peer(mi, NULL);
        rc = cs_send_internal_message(cs, mi);
        if (rc != CMT_OK) {
            free(proposal);
            free(mi);
            return rc;
        }
    }
    free(proposal);
    free(mi);
    return CMT_OK;
}

int cmt_cs_is_proposal_complete(cmt_cs_t *cs, bool *out)
{
    cmt_vote_set_t *prevotes;

    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = false;
    if (cs->rs.proposal == NULL || cs->rs.proposal_block == NULL) {
        return CMT_OK;                                       /* :1260-1262 */
    }
    if (cs->rs.proposal->pol_round < 0) {                         /* :1265 */
        *out = true;                                              /* :1266 */
        return CMT_OK;
    }
    prevotes = cmt_hvs_prevotes(cs->rs.votes, cs->rs.proposal->pol_round);
    *out = cmt_vote_set_has_two_thirds_majority(prevotes);        /* :1269 */
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:1319-1434 — enterPrevote, defaultDoPrevote, enterPrevoteWait
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_enter_prevote(cmt_cs_t *cs, int64_t height, int32_t round)
{
    int rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || round < cs->rs.round ||
        (cs->rs.round == round && CMT_ROUND_STEP_PREVOTE <= cs->rs.step)) {
        return CMT_OK;                                       /* :1322-1328 */
    }
    rc = cs->do_prevote(cs, height, round);                       /* :1339 */
    if (rc == CMT_FAULT) {
        return rc;
    }
    /* The defer of :1330-1334, which runs after doPrevote. */
    cs_update_round_step(cs, round, CMT_ROUND_STEP_PREVOTE);      /* :1332 */
    return cs_new_step(cs);                                       /* :1333 */
}

int cmt_cs_default_do_prevote(cmt_cs_t *cs, int64_t height, int32_t round)
{
    cmt_part_set_header_t psh;
    uint8_t               hash[CMT_TMHASH_SIZE];
    bool                  accept;
    int                   rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    (void)height;
    (void)round;

    if (cs->rs.locked_block != NULL) {                            /* :1349 */
        rc = cmt_block_hash(cs->rs.locked_block, hash);           /* :1351 */
        if (rc != CMT_OK) {
            return CMT_FAULT;      /* NODE-LOCAL: our own locked block     */
        }
        rc = cmt_part_set_header(cs->rs.locked_block_parts, &psh);
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        return cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PREVOTE, hash,
                                    sizeof(hash), &psh, NULL);    /* :1351 */
    }

    memset(&psh, 0, sizeof(psh));   /* the reference's PartSetHeader{}     */

    if (cs->rs.proposal_block == NULL) {                          /* :1356 */
        return cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PREVOTE, NULL, 0u,
                                    &psh, NULL);                  /* :1358 */
    }

    rc = cs->host.validate_block(cs->host_ctx, &cs->state,
                                 cs->rs.proposal_block);          /* :1363 */
    if (rc != CMT_OK) {
        /* :1364-1370 — an invalid proposal block is a PREVOTE FOR NIL, not
         * an error. This is the one ValidateBlock site of the three that
         * simply votes nil. */
        QGP_LOG_ERROR(LOG_TAG, "prevote step: consensus deems this block "
                               "invalid; prevoting nil");
        return cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PREVOTE, NULL, 0u,
                                    &psh, NULL);                  /* :1368 */
    }

    accept = false;
    rc = cs->host.process_proposal(cs->host_ctx, cs->rs.proposal_block,
                                   &cs->state, &accept);          /* :1382 */
    if (rc != CMT_OK) {
        /* :1383-1387 — panic("state machine returned an error when calling
         * ProcessProposal"). NODE-LOCAL → CMT_FAULT: the error is the
         * local application's, not the proposal's; a REJECTED proposal is
         * `accept == false` below and is a different thing entirely. */
        QGP_LOG_ERROR(LOG_TAG, "state machine returned an error when "
                               "calling ProcessProposal");
        return CMT_FAULT;
    }
    /* :1388 is a metric. */
    if (!accept) {                                                /* :1391 */
        QGP_LOG_ERROR(LOG_TAG, "prevote step: state machine rejected a "
                               "proposed block; prevoting nil");
        return cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PREVOTE, NULL, 0u,
                                    &psh, NULL);                  /* :1394 */
    }

    rc = cmt_block_hash(cs->rs.proposal_block, hash);             /* :1402 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    rc = cmt_part_set_header(cs->rs.proposal_block_parts, &psh);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    return cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PREVOTE, hash,
                                sizeof(hash), &psh, NULL);        /* :1402 */
}

int cmt_cs_enter_prevote_wait(cmt_cs_t *cs, int64_t height, int32_t round)
{
    bool has_any;
    int  rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || round < cs->rs.round ||
        (cs->rs.round == round &&
         CMT_ROUND_STEP_PREVOTE_WAIT <= cs->rs.step)) {
        return CMT_OK;                                       /* :1409-1415 */
    }
    has_any = false;
    rc = cmt_vote_set_has_two_thirds_any(cmt_hvs_prevotes(cs->rs.votes, round),
                                         &has_any);               /* :1417 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!has_any) {
        /* :1418-1421 — panic. NODE-LOCAL → CMT_FAULT: every caller of
         * enterPrevoteWait has just established +2/3-any on this very set
         * (:2319-2320), so reaching here means this module contradicted
         * itself. */
        QGP_LOG_ERROR(LOG_TAG,
                      "entering prevote wait step (%lld/%d), but prevotes "
                      "does not have any +2/3 votes",
                      (long long)height, (int)round);
        return CMT_FAULT;
    }
    /* :1433 — wait for more prevotes, then enterPrecommit. */
    rc = cmt_cs_schedule_timeout(cs, cmt_config_prevote(cs->config, round),
                                 height, round,
                                 CMT_ROUND_STEP_PREVOTE_WAIT);
    if (rc != CMT_OK) {
        return rc;
    }
    /* The defer of :1426-1430. */
    cs_update_round_step(cs, round, CMT_ROUND_STEP_PREVOTE_WAIT); /* :1428 */
    return cs_new_step(cs);                                       /* :1429 */
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:1442-1593 — enterPrecommit, enterPrecommitWait
 * ══════════════════════════════════════════════════════════════════════ */

/** The `defer` of :1455-1459. */
static int cs_enter_precommit_done(cmt_cs_t *cs, int32_t round)
{
    cs_update_round_step(cs, round, CMT_ROUND_STEP_PRECOMMIT);   /* :1457 */
    return cs_new_step(cs);                                      /* :1458 */
}

int cmt_cs_enter_precommit(cmt_cs_t *cs, int64_t height, int32_t round)
{
    cmt_part_set_header_t psh_nil;
    cmt_block_id_t        block_id;
    cmt_block_id_t        pol_block_id_unused;
    int32_t               pol_round;
    bool                  ok;
    int                   rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || round < cs->rs.round ||
        (cs->rs.round == round && CMT_ROUND_STEP_PRECOMMIT <= cs->rs.step)) {
        return CMT_OK;                                      /* :1445-1451 */
    }
    memset(&psh_nil, 0, sizeof(psh_nil));   /* types.PartSetHeader{}      */

    ok = false;
    rc = cmt_vote_set_two_thirds_majority(
            cmt_hvs_prevotes(cs->rs.votes, round), &block_id, &ok); /* :1462 */
    if (rc != CMT_OK) {
        return rc;
    }

    if (!ok) {                                                   /* :1465 */
        /* :1466-1470 are two log lines. :1472 — no polka, precommit nil. */
        rc = cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PRECOMMIT, NULL, 0u,
                                  &psh_nil, NULL);
        if (rc == CMT_FAULT) {
            return rc;
        }
        return cs_enter_precommit_done(cs, round);               /* :1473 */
    }
    /* :1477-1479 — PublishEventPolka, not ported. */

    /* :1482 — `polRound, _ := cs.Votes.POLInfo()`. Go discards the second
     * return; `cmt_hvs_pol_info` does NOT accept NULL for it (cmt_hvs.h:
     * "Always written", and its loop uses the buffer as working storage),
     * so the discard is spelled with a real one. */
    rc = cmt_hvs_pol_info(cs->rs.votes, &pol_round, &pol_block_id_unused);
    if (rc != CMT_OK) {
        return rc;
    }
    if (pol_round < round) {
        /* :1484 — panic("this POLRound should be %v but got %v").
         * NODE-LOCAL → CMT_FAULT: TwoThirdsMajority on THIS round's
         * prevotes just said yes at :1462, so POLInfo — which walks the
         * same height vote set downward from the current round
         * (height_vote_set.go:170-183) — cannot answer with a lower round
         * unless the two disagree with each other. */
        QGP_LOG_ERROR(LOG_TAG, "this POLRound should be %d but got %d",
                      (int)round, (int)pol_round);
        return CMT_FAULT;
    }

    if (block_id.hash_len == 0u) {                              /* :1488 */
        /* +2/3 prevoted nil: unlock and precommit nil. */
        if (cs->rs.locked_block != NULL) {                      /* :1489 */
            cs->rs.locked_round       = -1;                     /* :1493 */
            cs->rs.locked_block       = NULL;                   /* :1494 */
            cs->rs.locked_block_parts = NULL;                   /* :1495 */
            /* :1497-1499 — PublishEventUnlock, not ported. */
        }
        rc = cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PRECOMMIT, NULL, 0u,
                                  &psh_nil, NULL);              /* :1502 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        return cs_enter_precommit_done(cs, round);              /* :1503 */
    }

    /* At this point +2/3 prevoted for a particular block. */

    if (cmt_block_hashes_to(cs->rs.locked_block, block_id.hash,
                            block_id.hash_len)) {               /* :1509 */
        cs->rs.locked_round = round;                            /* :1511 */
        /* :1513-1515 — PublishEventRelock, not ported. */
        rc = cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PRECOMMIT,
                                  block_id.hash, block_id.hash_len,
                                  &block_id.part_set_header,
                                  cs->rs.locked_block);         /* :1517 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        return cs_enter_precommit_done(cs, round);              /* :1518 */
    }

    if (cmt_block_hashes_to(cs->rs.proposal_block, block_id.hash,
                            block_id.hash_len)) {               /* :1522 */
        rc = cs->host.validate_block(cs->host_ctx, &cs->state,
                                     cs->rs.proposal_block);    /* :1526 */
        if (rc != CMT_OK) {
            /* :1527 — panic("precommit step; +2/3 prevoted for an invalid
             * block"). CLASS: CMT_FAULT, and it is ARGUABLE — a byzantine
             * two thirds of the validator set can drive the node here with
             * a block this node itself considers invalid, so a peer's
             * input DOES reach it. The reference nevertheless halts
             * deliberately: at that point the chain has committed to a
             * block this node cannot validate, and continuing would mean
             * voting on state it disagrees with. Umbrella rev 4 requires an
             * arguable class to go to the operator rather than be chosen
             * silently; it was put to the operator on 2026-09-10 with the
             * causal chain (a byzantine +2/3, or this node's validation
             * diverging from everyone else's through a bug or a version
             * skew, in which case every node on the old build stops at the
             * same moment) and the answer was: THE NODE MAY STOP. FAULT
             * stands. */
            QGP_LOG_ERROR(LOG_TAG, "precommit step; +2/3 prevoted for an "
                                   "invalid block");
            return CMT_FAULT;
        }
        /* :1530-1532 — LOCK. Two names now point at one block and one part
         * set, exactly as Go's two assignments alias one object. */
        cs->rs.locked_round       = round;                      /* :1530 */
        cs->rs.locked_block       = cs->rs.proposal_block;      /* :1531 */
        cs->rs.locked_block_parts = cs->rs.proposal_block_parts;/* :1532 */
        /* :1534-1536 — PublishEventLock, not ported. */
        rc = cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PRECOMMIT,
                                  block_id.hash, block_id.hash_len,
                                  &block_id.part_set_header,
                                  cs->rs.proposal_block);       /* :1538 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        return cs_enter_precommit_done(cs, round);              /* :1539 */
    }

    /* :1542-1544 — a polka for a block we do not have: unlock, arrange to
     * fetch it, precommit nil. */
    cs->rs.locked_round       = -1;                             /* :1547 */
    cs->rs.locked_block       = NULL;                           /* :1548 */
    cs->rs.locked_block_parts = NULL;                           /* :1549 */

    if (!cmt_part_set_has_header(cs->rs.proposal_block_parts,
                                 &block_id.part_set_header)) {  /* :1551 */
        cs->rs.proposal_block       = NULL;                     /* :1552 */
        cs->rs.proposal_block_parts = NULL;   /* clear the name first     */
        rc = cs_new_part_set_from_header(cs, &block_id.part_set_header,
                                         &cs->rs.proposal_block_parts);
        if (rc != CMT_OK) {                                     /* :1553 */
            return rc;
        }
    }
    /* :1556-1558 — PublishEventUnlock, not ported. */
    rc = cmt_cs_sign_add_vote(cs, CMT_PB_MSG_TYPE_PRECOMMIT, NULL, 0u,
                              &psh_nil, NULL);                  /* :1560 */
    if (rc == CMT_FAULT) {
        return rc;
    }
    return cs_enter_precommit_done(cs, round);
}

int cmt_cs_enter_precommit_wait(cmt_cs_t *cs, int64_t height, int32_t round)
{
    bool has_any;
    int  rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || round < cs->rs.round ||
        (cs->rs.round == round && cs->rs.triggered_timeout_precommit)) {
        return CMT_OK;                                      /* :1567-1574 */
    }
    has_any = false;
    rc = cmt_vote_set_has_two_thirds_any(
            cmt_hvs_precommits(cs->rs.votes, round), &has_any);  /* :1576 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!has_any) {
        /* :1577-1580 — panic. NODE-LOCAL → CMT_FAULT, for the same reason
         * as :1418: every caller (:2351, :2355) has just established
         * +2/3-any on this same precommit set. */
        QGP_LOG_ERROR(LOG_TAG,
                      "entering precommit wait step (%lld/%d), but "
                      "precommits does not have any +2/3 votes",
                      (long long)height, (int)round);
        return CMT_FAULT;
    }
    /* :1592 — wait for more precommits, then enterNewRound. */
    rc = cmt_cs_schedule_timeout(cs, cmt_config_precommit(cs->config, round),
                                 height, round,
                                 CMT_ROUND_STEP_PRECOMMIT_WAIT);
    if (rc != CMT_OK) {
        return rc;
    }
    /* The defer of :1585-1589. Note it does NOT call updateRoundStep. */
    cs->rs.triggered_timeout_precommit = true;                  /* :1587 */
    return cs_new_step(cs);                                     /* :1588 */
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:1596-1810 — enterCommit, tryFinalizeCommit, finalizeCommit
 * ══════════════════════════════════════════════════════════════════════ */

/** The `defer` of :1609-1619, which ends in tryFinalizeCommit. */
static int cs_enter_commit_done(cmt_cs_t *cs, int64_t height,
                                int32_t commit_round)
{
    cmt_time_t now;
    int        rc;

    /* :1611-1612 — cs.Round is deliberately unchanged; commitRound names
     * the precommit set that carried the decision. */
    cs_update_round_step(cs, cs->rs.round, CMT_ROUND_STEP_COMMIT);/* :1612 */
    cs->rs.commit_round = commit_round;                          /* :1613 */
    rc = cs->host.now(cs->host_ctx, &now);   /* :1614 — CLOCK SITE 4/5    */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    cs->rs.commit_time = now;                                    /* :1614 */
    rc = cs_new_step(cs);                                        /* :1615 */
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_cs_try_finalize_commit(cs, height);               /* :1618 */
}

int cmt_cs_enter_commit(cmt_cs_t *cs, int64_t height, int32_t commit_round)
{
    cmt_block_id_t block_id;
    bool           ok;
    int            rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || CMT_ROUND_STEP_COMMIT <= cs->rs.step) {
        return CMT_OK;                                      /* :1599-1605 */
    }

    ok = false;
    rc = cmt_vote_set_two_thirds_majority(
            cmt_hvs_precommits(cs->rs.votes, commit_round), &block_id, &ok);
    if (rc != CMT_OK) {                                          /* :1621 */
        return rc;
    }
    if (!ok) {
        /* :1623 — panic("RunActionCommit() expects +2/3 precommits").
         * NODE-LOCAL → CMT_FAULT: the only caller (:2346) enters here
         * having just read the same majority off the same set. */
        QGP_LOG_ERROR(LOG_TAG, "enterCommit expects +2/3 precommits");
        return CMT_FAULT;
    }

    /* :1626-1633 — the Locked* names no longer matter; if they name the
     * committed block, move them onto ProposalBlock. This is the alias at
     * :1631-1632: two names, one slot. */
    if (cmt_block_hashes_to(cs->rs.locked_block, block_id.hash,
                            block_id.hash_len)) {                /* :1629 */
        cs->rs.proposal_block       = cs->rs.locked_block;       /* :1631 */
        cs->rs.proposal_block_parts = cs->rs.locked_block_parts; /* :1632 */
    }

    if (!cmt_block_hashes_to(cs->rs.proposal_block, block_id.hash,
                             block_id.hash_len)) {               /* :1636 */
        if (!cmt_part_set_has_header(cs->rs.proposal_block_parts,
                                     &block_id.part_set_header)) {/* :1637 */
            cs->rs.proposal_block       = NULL;                  /* :1646 */
            cs->rs.proposal_block_parts = NULL;   /* clear before taking  */
            rc = cs_new_part_set_from_header(cs, &block_id.part_set_header,
                                             &cs->rs.proposal_block_parts);
            if (rc != CMT_OK) {                                  /* :1647 */
                return rc;
            }
            /* :1649-1653 — PublishEventValidBlock and the event switch,
             * neither of which is ported. */
        }
    }
    return cs_enter_commit_done(cs, height, commit_round);
}

int cmt_cs_try_finalize_commit(cmt_cs_t *cs, int64_t height)
{
    cmt_block_id_t block_id;
    bool           ok;
    int            rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height) {
        /* :1663 — panic("tryFinalizeCommit() cs.Height vs height").
         * NODE-LOCAL → CMT_FAULT: both callers (:1618, :2064) pass a
         * height they read out of this same state machine. */
        QGP_LOG_ERROR(LOG_TAG, "tryFinalizeCommit() cs.Height %lld vs "
                               "height %lld",
                      (long long)cs->rs.height, (long long)height);
        return CMT_FAULT;
    }

    ok = false;
    rc = cmt_vote_set_two_thirds_majority(
            cmt_hvs_precommits(cs->rs.votes, cs->rs.commit_round),
            &block_id, &ok);                                     /* :1666 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!ok || block_id.hash_len == 0u) {                        /* :1667 */
        QGP_LOG_ERROR(LOG_TAG, "failed attempt to finalize commit; there "
                               "was no +2/3 majority or +2/3 was for nil");
        return CMT_OK;                                           /* :1669 */
    }
    if (!cmt_block_hashes_to(cs->rs.proposal_block, block_id.hash,
                             block_id.hash_len)) {               /* :1672 */
        /* :1675-1680 — we do not have the block yet; wait for it. */
        return CMT_OK;
    }
    return cmt_cs_finalize_commit(cs, height);                   /* :1683 */
}

int cmt_cs_finalize_commit(cmt_cs_t *cs, int64_t height)
{
    cmt_block_id_t             block_id;
    cmt_block_t               *block;
    cmt_part_set_t            *block_parts;
    cmt_extended_commit_t     *seen_ext_commit;
    cmt_extended_commit_sig_t *sigs;
    cmt_commit_t              *plain_commit;
    cmt_commit_sig_t          *plain_sigs;
    uint8_t                    block_hash[CMT_TMHASH_SIZE];
    cmt_part_set_header_t      psh;
    cmt_block_id_t             apply_block_id;
    int64_t                    store_height;
    size_t                     n_sigs;
    bool                       ok;
    bool                       ext_enabled;
    int                        rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.height != height || cs->rs.step != CMT_ROUND_STEP_COMMIT) {
        return CMT_OK;                                      /* :1690-1696 */
    }
    /* :1698 — calculatePrevoteMessageDelayMetrics, not ported. */

    ok = false;
    rc = cmt_vote_set_two_thirds_majority(
            cmt_hvs_precommits(cs->rs.votes, cs->rs.commit_round),
            &block_id, &ok);                                     /* :1700 */
    if (rc != CMT_OK) {
        return rc;
    }
    block       = cs->rs.proposal_block;                         /* :1701 */
    block_parts = cs->rs.proposal_block_parts;

    if (!ok) {
        /* :1704 — panic. NODE-LOCAL → CMT_FAULT: tryFinalizeCommit read
         * the same majority off the same set two calls ago (:1666). */
        QGP_LOG_ERROR(LOG_TAG, "cannot finalize commit; commit does not "
                               "have 2/3 majority");
        return CMT_FAULT;
    }
    if (!cmt_part_set_has_header(block_parts, &block_id.part_set_header)) {
        /* :1707 — panic. NODE-LOCAL → CMT_FAULT: enterCommit installed
         * these parts against this same header (:1637-1647). */
        QGP_LOG_ERROR(LOG_TAG, "expected ProposalBlockParts header to be "
                               "commit header");
        return CMT_FAULT;
    }
    if (!cmt_block_hashes_to(block, block_id.hash, block_id.hash_len)) {
        /* :1710 — panic. NODE-LOCAL → CMT_FAULT: tryFinalizeCommit
         * checked exactly this at :1672 before calling. */
        QGP_LOG_ERROR(LOG_TAG, "cannot finalize commit; proposal block does "
                               "not hash to commit hash");
        return CMT_FAULT;
    }

    rc = cs->host.validate_block(cs->host_ctx, &cs->state, block);/* :1713 */
    if (rc != CMT_OK) {
        /* :1714 — panic("+2/3 committed an invalid block"). CLASS:
         * CMT_FAULT, ARGUABLE for the same reason as :1527 — a byzantine
         * +2/3 is peer input that reaches it. The reference halts because
         * the alternative is applying a block this node judges invalid.
         * Settled with the operator on 2026-09-10 together with :1527: the
         * node may stop. FAULT stands. */
        QGP_LOG_ERROR(LOG_TAG, "+2/3 committed an invalid block");
        return CMT_FAULT;
    }
    /* :1717 — calculatePrecommitMessageDelayMetrics, not ported. */

    CMT_FAIL_POINT();                                            /* :1727 */

    rc = cs->host.bs_height(cs->host_ctx, &store_height);        /* :1730 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }

    n_sigs = (size_t)cmt_vote_set_size(
            cmt_hvs_precommits(cs->rs.votes, cs->rs.commit_round));
    if (n_sigs > (size_t)CMT_VALSET_MAX) {
        return CMT_FAULT;         /* NODE-LOCAL: our own set past its bound */
    }
    seen_ext_commit = NULL;
    sigs            = NULL;
    plain_commit    = NULL;
    plain_sigs      = NULL;

    if (store_height < block->header.height) {                   /* :1730 */
        seen_ext_commit = (cmt_extended_commit_t *)calloc(
                1u, sizeof(*seen_ext_commit));
        sigs = (cmt_extended_commit_sig_t *)calloc(
                n_sigs == 0u ? 1u : n_sigs, sizeof(*sigs));
        if (seen_ext_commit == NULL || sigs == NULL) {
            free(seen_ext_commit);
            free(sigs);
            return CMT_FAULT;
        }
        rc = cmt_vote_set_make_extended_commit(
                cmt_hvs_precommits(cs->rs.votes, cs->rs.commit_round),
                cs->state.consensus_params.abci, sigs, n_sigs,
                seen_ext_commit);                                /* :1733 */
        if (rc != CMT_OK) {
            free(seen_ext_commit);
            free(sigs);
            return rc;
        }
        ext_enabled = false;
        rc = cmt_abci_params_vote_extensions_enabled(
                cs->state.consensus_params.abci, block->header.height,
                &ext_enabled);                                   /* :1734 */
        if (rc != CMT_OK) {
            free(seen_ext_commit);
            free(sigs);
            return rc;
        }
        if (ext_enabled) {
            rc = cs->host.bs_save_block_with_extended_commit(
                    cs->host_ctx, block, block_parts, seen_ext_commit);
        } else {                                                 /* :1735 */
            plain_commit = (cmt_commit_t *)calloc(1u, sizeof(*plain_commit));
            plain_sigs   = (cmt_commit_sig_t *)calloc(
                    n_sigs == 0u ? 1u : n_sigs, sizeof(*plain_sigs));
            if (plain_commit == NULL || plain_sigs == NULL) {
                free(seen_ext_commit);
                free(sigs);
                free(plain_commit);
                free(plain_sigs);
                return CMT_FAULT;
            }
            rc = cmt_extended_commit_to_commit(seen_ext_commit, plain_sigs,
                                               n_sigs, plain_commit);/* :1737 */
            if (rc == CMT_OK) {
                rc = cs->host.bs_save_block(cs->host_ctx, block, block_parts,
                                            plain_commit);       /* :1737 */
            }
        }
        free(seen_ext_commit);
        free(sigs);
        free(plain_commit);
        free(plain_sigs);
        if (rc != CMT_OK) {
            /* The reference's SaveBlock family panics on every internal
             * failure (store/store.go). NODE-LOCAL → CMT_FAULT: this is
             * the node's own block store refusing its own block. */
            QGP_LOG_ERROR(LOG_TAG, "failed to save block at height %lld",
                          (long long)block->header.height);
            return CMT_FAULT;
        }
    }
    /* :1739-1742 — already stored; this is the replay path. */

    CMT_FAIL_POINT();                                            /* :1744 */

    /* :1746-1765 — EndHeight, and the reference's long comment on why it
     * comes AFTER the block is stored. */
    rc = cs_wal_write_end_height(cs, height);                    /* :1760 */
    if (rc != CMT_OK) {
        return rc;
    }

    CMT_FAIL_POINT();                                            /* :1767 */

    rc = cmt_state_copy(&cs->state, &cs->state_scratch);         /* :1770 */
    if (rc != CMT_OK) {
        return rc;
    }

    rc = cmt_block_hash(block, block_hash);                      /* :1778 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    rc = cmt_part_set_header(block_parts, &psh);                 /* :1779 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    memset(&apply_block_id, 0, sizeof(apply_block_id));
    memcpy(apply_block_id.hash, block_hash, sizeof(block_hash));
    apply_block_id.hash_len        = sizeof(block_hash);
    apply_block_id.part_set_header = psh;

    rc = cs->host.apply_verified_block(cs->host_ctx, &apply_block_id, block,
                                       &cs->state_scratch);      /* :1775 */
    if (rc != CMT_OK) {
        /* :1783-1785 — panic("failed to apply block"). NODE-LOCAL →
         * CMT_FAULT: the block was validated at :1713 and the failure is
         * the local application's. */
        QGP_LOG_ERROR(LOG_TAG, "failed to apply block at height %lld",
                      (long long)height);
        return CMT_FAULT;
    }

    CMT_FAIL_POINT();                                            /* :1787 */

    /* :1790 — recordMetrics, not ported (see cmt_cs.h). */

    rc = cmt_cs_update_to_state(cs, &cs->state_scratch);         /* :1793 */
    if (rc != CMT_OK) {
        return rc;
    }

    CMT_FAIL_POINT();                                            /* :1795 */

    if (cmt_cs_update_priv_validator_pub_key(cs) != CMT_OK) {    /* :1798 */
        QGP_LOG_ERROR(LOG_TAG, "failed to get private validator pubkey");
    }
    /* :1802-1804 — cs.StartTime is already set; schedule round 0. */
    return cmt_cs_schedule_round0(cs, &cs->rs);                  /* :1804 */
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:1903-2066 — the proposal and its block parts
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_default_set_proposal(cmt_cs_t *cs, const cmt_proposal_t *proposal)
{
    cmt_validator_t proposer;
    uint8_t        *sign_bytes;
    size_t          sb_len;
    int64_t         max_bytes;
    int64_t         max_parts;
    int             rc;

    if (cs == NULL || proposal == NULL) {
        return CMT_FAULT;
    }
    if (cs->rs.proposal != NULL) {                               /* :1906 */
        return CMT_OK;                                           /* :1907 */
    }
    if (proposal->height != cs->rs.height ||
        proposal->round != cs->rs.round) {                       /* :1911 */
        return CMT_OK;                                           /* :1912 */
    }
    if (proposal->pol_round < -1 ||
        (proposal->pol_round >= 0 &&
         proposal->pol_round >= proposal->round)) {              /* :1916 */
        return CMT_REJECT;               /* :1918 ErrInvalidProposalPOLRound */
    }

    /* :1921 `p := proposal.ToProto()` is the identity here: this tree's
     * cmt_proposal_t IS cmt_pb_proposal_t (cmt_proposal.h:78), so :1939's
     * `proposal.Signature = p.Signature` is a no-op round trip. */
    rc = cmt_validator_set_get_proposer(cs->rs.validators, &proposer);/* :1923 */
    if (rc != CMT_OK) {
        /* GetProposer REJECTs an empty set where :1923 nil-dereferences.
         * NODE-LOCAL → CMT_FAULT: the validator set is our own state. */
        return CMT_FAULT;
    }
    if (!proposer.pub_key.present) {
        return CMT_FAULT;   /* NODE-LOCAL: a member of our own set has no key */
    }
    sign_bytes = (uint8_t *)malloc((size_t)CMT_PROPOSAL_SIGN_BYTES_MAX);
    if (sign_bytes == NULL) {
        return CMT_FAULT;
    }
    sb_len = 0u;
    rc = cmt_proposal_sign_bytes(cs->state.chain_id, cs->state.chain_id_len,
                                 proposal, sign_bytes,
                                 (size_t)CMT_PROPOSAL_SIGN_BYTES_MAX,
                                 &sb_len);                       /* :1925 */
    if (rc != CMT_OK) {
        free(sign_bytes);
        return rc;
    }
    /* INVARIANT atlas-dec-7495d337…: Go's Signature is a slice carrying its
     * own bound; here the array does not, so the length is checked before
     * the verifier reads it. */
    if (proposal->signature_len == 0u ||
        proposal->signature_len > (size_t)CMT_PB_SIG_MAX) {
        free(sign_bytes);
        return CMT_REJECT;              /* :1927 ErrInvalidProposalSignature */
    }
    if (qgp_dsa87_verify(proposal->signature, proposal->signature_len,
                         sign_bytes, sb_len,
                         proposer.pub_key.key) != 0) {           /* :1924 */
        free(sign_bytes);
        return CMT_REJECT;              /* :1927 ErrInvalidProposalSignature */
    }
    free(sign_bytes);

    max_bytes = cs->state.consensus_params.block.max_bytes;      /* :1931 */
    if (max_bytes == -1) {                                       /* :1932 */
        max_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;           /* :1933 */
    }
    /* :1935 — (maxBytes-1)/BlockPartSizeBytes + 1 */
    max_parts = (max_bytes - 1) / (int64_t)CMT_BLOCK_PART_SIZE_BYTES + 1;
    if ((int64_t)proposal->block_id.part_set_header.total > max_parts) {
        return CMT_REJECT;                  /* :1936 ErrProposalTooManyParts */
    }

    /* :1939-1940 — `proposal.Signature = p.Signature; cs.Proposal =
     * proposal`. The first is the identity here (see above); the second
     * stores a POINTER in Go to an object the garbage collector keeps.
     * The message this proposal arrived in is freed as soon as handleMsg
     * returns, so it is COPIED into storage `cs` owns and the round state
     * names that (cmt_cs.h, `proposal_storage`). */
    cs->proposal_storage = *proposal;
    cs->rs.proposal      = &cs->proposal_storage;                /* :1940 */
    if (cs->rs.proposal_block_parts == NULL) {                   /* :1944 */
        rc = cs_new_part_set_from_header(cs,
                                         &proposal->block_id.part_set_header,
                                         &cs->rs.proposal_block_parts);
        if (rc != CMT_OK) {                                      /* :1945 */
            cs->rs.proposal = NULL;
            return rc;
        }
    }
    return CMT_OK;
}

int cmt_cs_add_proposal_block_part(cmt_cs_t *cs,
                                   const cmt_block_part_msg_t *msg,
                                   const cmt_peer_id_t *peer,
                                   bool *out_added)
{
    cmt_part_set_reader_t reader;
    cmt_block_t          *slot;
    uint8_t              *buf;
    size_t                buf_cap;
    size_t                slot_idx;
    size_t                total_read;
    int64_t               max_bytes;
    bool                  added;
    int                   rc;

    if (cs == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    (void)peer;
    added = false;
    if (out_added != NULL) {
        *out_added = false;
    }

    if (cs->rs.height != msg->height) {                          /* :1959 */
        return CMT_OK;                                           /* :1962 */
    }
    if (cs->rs.proposal_block_parts == NULL) {                   /* :1966 */
        /* :1968-1969 — a part from a round we have left; not a bad peer. */
        return CMT_OK;                                           /* :1977 */
    }

    rc = cmt_part_set_add_part(cs->rs.proposal_block_parts, &msg->part,
                               &added);                          /* :1980 */
    if (out_added != NULL) {
        *out_added = added;
    }
    if (rc != CMT_OK) {
        return rc;                                           /* :1981-1986 */
    }
    if (!added) {
        /* :1989-1993 — a duplicate part; a metric and nothing else. */
        return CMT_OK;
    }

    max_bytes = cs->state.consensus_params.block.max_bytes;      /* :1995 */
    if (max_bytes == -1) {                                       /* :1996 */
        max_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;           /* :1997 */
    }
    if (cmt_part_set_byte_size(cs->rs.proposal_block_parts) > max_bytes) {
        return CMT_REJECT;                                   /* :1999-2003 */
    }

    if (!cmt_part_set_is_complete(cs->rs.proposal_block_parts)) {/* :2004 */
        return CMT_OK;
    }

    /* :2005-2019 — the complete block. Go reads the parts out, unmarshals
     * the proto and runs BlockFromProto; this tree has no wire decoder for
     * a Block (cmt_pb.h:1043), so the three steps are the host's
     * `decode_block` row (cmt_cs.h). */
    rc = cs_part_slot_index(cs, cs->rs.proposal_block_parts, &slot_idx);
    if (rc != CMT_OK) {
        /* NODE-LOCAL: the part set being filled is always one of ours. */
        QGP_LOG_ERROR(LOG_TAG, "proposal block parts are not in a slot");
        return CMT_FAULT;
    }
    buf     = cs->slots->payload[slot_idx];
    buf_cap = cs->slots->payload_cap[slot_idx];
    if (buf == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "part-set slot %zu has no payload buffer",
                      slot_idx);
        return CMT_FAULT;                                /* NODE-LOCAL   */
    }
    rc = cmt_part_set_get_reader(cs->rs.proposal_block_parts, &reader);
    if (rc != CMT_OK) {
        return rc;                                           /* :2005    */
    }
    total_read = 0u;
    for (;;) {
        size_t n = 0u;

        if (total_read >= buf_cap) {
            /* The assembled block is larger than the buffer the host
             * sized for MaxBytes. PEER-REACHABLE → CMT_REJECT: the parts
             * came from the wire, and :1999-2003 already refuses on
             * ByteSize; this is the same refusal one layer down. */
            return CMT_REJECT;
        }
        rc = cmt_part_set_reader_read(&reader, buf + total_read,
                                      buf_cap - total_read, &n);
        if (rc == CMT_PART_SET_EOF) {
            total_read += n;
            break;
        }
        if (rc != CMT_OK) {
            return rc;                                       /* :2006-2008 */
        }
        if (n == 0u) {
            break;
        }
        total_read += n;
    }

    /* The block is decoded into a FREE slot; the name is cleared first so
     * that the slot the old proposal block occupied can be reused. */
    cs->rs.proposal_block = NULL;
    slot = NULL;
    rc = cs_take_block_slot(cs, &slot);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cs->host.decode_block(cs->host_ctx, buf, total_read, slot);
    if (rc != CMT_OK) {
        /* :2011-2019 — proto.Unmarshal and BlockFromProto both return
         * their error to the caller; neither panics. PEER-REACHABLE. */
        return rc;
    }
    cs->rs.proposal_block = slot;                                /* :2021 */
    /* :2026-2028 — PublishEventCompleteProposal, not ported. */
    return CMT_OK;
}

int cmt_cs_handle_complete_proposal(cmt_cs_t *cs, int64_t block_height)
{
    cmt_vote_set_t *prevotes;
    cmt_block_id_t  block_id;
    bool            has_two_thirds;
    bool            complete;
    int             rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    prevotes       = cmt_hvs_prevotes(cs->rs.votes, cs->rs.round);/* :2035 */
    has_two_thirds = false;
    rc = cmt_vote_set_two_thirds_majority(prevotes, &block_id,
                                          &has_two_thirds);       /* :2036 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (has_two_thirds && !cmt_block_id_is_zero(&block_id) &&
        cs->rs.valid_round < cs->rs.round) {                      /* :2037 */
        if (cmt_block_hashes_to(cs->rs.proposal_block, block_id.hash,
                                block_id.hash_len)) {             /* :2038 */
            /* :2045-2047 — Valid* takes the proposal's block and parts;
             * two names, one slot, exactly as Go aliases the objects. */
            cs->rs.valid_round       = cs->rs.round;              /* :2045 */
            cs->rs.valid_block       = cs->rs.proposal_block;     /* :2046 */
            cs->rs.valid_block_parts = cs->rs.proposal_block_parts;/* :2047 */
        }
        /* :2049-2053 — the reference's TODO on accountability. */
    }

    if (cs->rs.step <= CMT_ROUND_STEP_PROPOSE) {                  /* :2056 */
        complete = false;
        rc = cmt_cs_is_proposal_complete(cs, &complete);          /* :2056 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (complete) {
            rc = cmt_cs_enter_prevote(cs, block_height, cs->rs.round);/* :2058 */
            if (rc == CMT_FAULT) {
                return rc;
            }
            if (has_two_thirds) {                                 /* :2059 */
                return cmt_cs_enter_precommit(cs, block_height,
                                              cs->rs.round);      /* :2060 */
            }
            return CMT_OK;
        }
    }
    if (cs->rs.step == CMT_ROUND_STEP_COMMIT) {                   /* :2062 */
        return cmt_cs_try_finalize_commit(cs, block_height);      /* :2064 */
    }
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:2069-2363 — tryAddVote and addVote
 * ══════════════════════════════════════════════════════════════════════ */

/** The conflicting-vote pair `addVote` produced, if any. `addVote` reports
 *  it through this rather than through an error object, because the port
 *  has no error values (cmt_vote.h's note). */
typedef struct {
    bool       present;
    cmt_vote_t vote_a;   /* the vote already in the set (:236's VoteA) */
    cmt_vote_t vote_b;   /* the caller's own vote (VoteB)              */
} cs_conflict_t;

static int cs_add_vote(cmt_cs_t *cs, const cmt_vote_t *vote,
                       const cmt_peer_id_t *peer, bool *out_added,
                       cs_conflict_t *conflict);

int cmt_cs_try_add_vote(cmt_cs_t *cs, const cmt_vote_t *vote,
                        const cmt_peer_id_t *peer, bool *out_added)
{
    cs_conflict_t *conflict;
    uint8_t        my_addr[CMT_ADDRESS_SIZE];
    bool           added;
    int            rc;

    if (cs == NULL || vote == NULL || peer == NULL) {
        return CMT_FAULT;
    }
    /* Heap: two whole votes, ~19 KB of Dilithium signatures. */
    conflict = (cs_conflict_t *)calloc(1u, sizeof(*conflict));
    if (conflict == NULL) {
        return CMT_FAULT;
    }
    added = false;
    rc = cs_add_vote(cs, vote, peer, &added, conflict);           /* :2070 */
    if (out_added != NULL) {
        *out_added = added;
    }
    if (rc == CMT_FAULT) {
        free(conflict);
        return CMT_FAULT;
    }

    /* :2072 `if err != nil` — tested FIRST, and REGARDLESS of `added`.
     * vote_set.go:326 returns `(true, conflicting)` on the peer-maj23
     * path: when a peer has claimed +2/3 for the block the conflicting
     * vote names, the vote IS added, the transition at :2250-2359 IS run,
     * and the conflict IS STILL reported to the evidence pool at :2094.
     * The first version of this function returned on `rc == CMT_OK`
     * before looking at the conflict, and so dropped the evidence report
     * on exactly that path — an equivocating validator whose second vote
     * arrived after a VoteSetMaj23 went unreported. Found by the
     * multi-node byzantine partition test (nodus/tests/
     * test_cmt_byzantine.c), not by reading. The `added` half of Go's
     * `(added, err)` is already in `*out_added`; the `err` half is the
     * CMT_REJECT below, which the caller logs exactly as :954-962 does. */
    if (conflict->present) {                                     /* :2077 */
        if (!cs->priv_validator_pub_key_present) {               /* :2078 */
            free(conflict);
            return CMT_REJECT;                       /* :2079 errPubKeyIsNotSet */
        }
        if (cs_priv_validator_address(cs, my_addr) != CMT_OK) {
            free(conflict);
            return CMT_FAULT;
        }
        if (vote->validator_address_len == sizeof(my_addr) &&
            memcmp(vote->validator_address, my_addr,
                   sizeof(my_addr)) == 0) {                      /* :2082 */
            /* :2083-2090 — a conflicting vote from OURSELVES. The
             * reference logs "did you unsafe_reset a validator?" and
             * returns the error; it does NOT report itself to the
             * evidence pool. */
            QGP_LOG_ERROR(LOG_TAG, "found conflicting vote from ourselves; "
                                   "height %lld round %d",
                          (long long)vote->height, (int)vote->round);
            free(conflict);
            return CMT_REJECT;                                   /* :2090 */
        }
        rc = cs->host.report_conflicting_votes(cs->host_ctx,
                                               &conflict->vote_a,
                                               &conflict->vote_b);/* :2094 */
        free(conflict);
        if (rc != CMT_OK) {
            /* The reference's ReportConflictingVotes returns nothing and
             * cannot fail. A C host that failed here has an evidence pool
             * that did not record equivocation it was handed. NODE-LOCAL →
             * CMT_FAULT. */
            QGP_LOG_ERROR(LOG_TAG, "evidence pool refused conflicting votes");
            return CMT_FAULT;
        }
        return CMT_REJECT;                                       /* :2101 */
    }
    free(conflict);
    if (rc == CMT_OK) {
        return CMT_OK;                                           /* :2117 */
    }
    /* :2102-2114 — every other error is swallowed into a log line and
     * either nil (:2103, :2105) or ErrAddingVote (:2113). Both leave the
     * caller in the same place; this port reports the refusal. */
    return CMT_REJECT;
}

/** The precommit-for-the-previous-height branch, :2137-2168. */
static int cs_add_vote_last_commit(cmt_cs_t *cs, const cmt_vote_t *vote,
                                   bool *out_added)
{
    cmt_vote_set_err_t err;
    bool               added;
    bool               has_all;
    int                rc;

    if (cs->rs.step != CMT_ROUND_STEP_NEW_HEIGHT) {              /* :2138 */
        /* :2140-2141 — a late precommit for the prior height. */
        return CMT_OK;
    }
    if (cs->rs.last_commit == NULL) {
        /* types/vote_set.go:158-160 — `AddVote()` on a nil VoteSet
         * PANICS, and :2144 calls it without a nil check.
         * PEER-REACHABLE → CMT_REJECT: at the initial height LastCommit
         * is nil (:692), and a peer precommit whose height is
         * `cs.Height - 1` reaches this line while the step is still
         * RoundStepNewHeight. With an InitialHeight above 1 that vote's
         * height is positive and passes ValidateBasic, so a peer really
         * can produce it; refusing the vote is the message-boundary
         * equivalent of the reference's crash. */
        return CMT_REJECT;
    }
    added = false;
    err   = CMT_VOTE_SET_ERR_NONE;
    rc = cmt_vote_set_add_vote(cs->rs.last_commit, vote, &added, &err, NULL);
    *out_added = added;                                          /* :2144 */
    if (!added) {
        /* :2145-2151 — not added; a duplicate when there is no error. */
        return rc;
    }
    if (rc == CMT_FAULT) {
        return rc;
    }
    /* :2154-2158 — PublishEventVote and the event switch, not ported. */

    if (cs->config->skip_timeout_commit) {                       /* :2161 */
        has_all = false;
        if (cmt_vote_set_has_all(cs->rs.last_commit, &has_all) != CMT_OK) {
            return CMT_FAULT;
        }
        if (has_all) {
            /* :2164 — every vote is in; go straight to the new round. */
            return cmt_cs_enter_new_round(cs, cs->rs.height, 0);
        }
    }
    return rc;                                                   /* :2167 */
}

/** The vote-extension checks of :2177-2226. */
static int cs_add_vote_check_extension(cmt_cs_t *cs, const cmt_vote_t *vote,
                                       bool ext_enabled)
{
    cmt_validator_t val;
    uint8_t         my_addr[CMT_ADDRESS_SIZE];
    uint8_t        *scratch;
    size_t          scratch_cap;
    bool            is_mine;
    int             rc;

    if (!ext_enabled) {                                          /* :2216 */
        /* :2223-2225 — extensions are off, so a vote carrying one is
         * malformed. PEER-REACHABLE → CMT_REJECT (the reference returns
         * an error here, it does not panic). */
        if (vote->extension.len > 0u || vote->extension_signature_len > 0u) {
            return CMT_REJECT;
        }
        return CMT_OK;
    }

    is_mine = false;
    if (cs->priv_validator_pub_key_present) {                    /* :2185 */
        if (cs_priv_validator_address(cs, my_addr) != CMT_OK) {
            return CMT_FAULT;
        }
        is_mine = vote->validator_address_len == sizeof(my_addr) &&
                  memcmp(vote->validator_address, my_addr,
                         sizeof(my_addr)) == 0;                  /* :2191 */
    }
    /* :2190-2191 — only a NON-NIL PRECOMMIT from SOMEONE ELSE is checked. */
    if (vote->type != CMT_PB_MSG_TYPE_PRECOMMIT ||
        cmt_block_id_is_zero(&vote->block_id) || is_mine) {
        return CMT_OK;
    }

    rc = cmt_validator_set_get_by_index(&cs->state.validators,
                                        vote->validator_index, &val);/* :2197 */
    if (rc != CMT_OK) {
        /* :2198-2205 — "Peer sent us vote with invalid ValidatorIndex".
         * PEER-REACHABLE → CMT_REJECT, which is what the reference does
         * (ErrInvalidVote), and its own TODO says to disconnect. */
        return CMT_REJECT;
    }
    if (!val.pub_key.present) {
        return CMT_FAULT;   /* NODE-LOCAL: a member of our set has no key */
    }
    /* cmt_vote_verify_extension needs a buffer for the extension sign
     * bytes: 64 (chain id room) + 11 + the extension's own length
     * (cmt_vote.h:288-296). Heap, because the extension is unbounded. */
    scratch_cap = 64u + 11u + vote->extension.len + 64u;
    scratch     = (uint8_t *)malloc(scratch_cap);
    if (scratch == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_vote_verify_extension(cs->state.chain_id, cs->state.chain_id_len,
                                   vote, val.pub_key.key, scratch,
                                   scratch_cap);                 /* :2206 */
    free(scratch);
    if (rc != CMT_OK) {
        return rc;                                               /* :2207 */
    }
    rc = cs->host.verify_vote_extension(cs->host_ctx, vote);     /* :2210 */
    /* :2211 is a metric. */
    if (rc != CMT_OK) {
        return CMT_REJECT;                                       /* :2213 */
    }
    return CMT_OK;
}

/** The prevote arm of the switch at :2250-2328. */
static int cs_add_vote_prevote(cmt_cs_t *cs, const cmt_vote_t *vote,
                               int64_t height)
{
    cmt_vote_set_t *prevotes;
    cmt_block_id_t  block_id;
    bool            ok;
    bool            has_any;
    bool            complete;
    int             rc;

    prevotes = cmt_hvs_prevotes(cs->rs.votes, vote->round);      /* :2252 */

    ok = false;
    rc = cmt_vote_set_two_thirds_majority(prevotes, &block_id, &ok);/* :2256 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (ok) {
        /* :2263-2266 — unlock if `LockedRound < vote.Round <= cs.Round`
         * and the polka is for a different block. */
        if (cs->rs.locked_block != NULL &&
            cs->rs.locked_round < vote->round &&
            vote->round <= cs->rs.round &&
            !cmt_block_hashes_to(cs->rs.locked_block, block_id.hash,
                                 block_id.hash_len)) {
            cs->rs.locked_round       = -1;                      /* :2270 */
            cs->rs.locked_block       = NULL;                    /* :2271 */
            cs->rs.locked_block_parts = NULL;                    /* :2272 */
            /* :2274-2276 — PublishEventUnlock, not ported. */
        }

        if (block_id.hash_len != 0u && cs->rs.valid_round < vote->round &&
            vote->round == cs->rs.round) {                       /* :2281 */
            if (cmt_block_hashes_to(cs->rs.proposal_block, block_id.hash,
                                    block_id.hash_len)) {        /* :2282 */
                /* :2284-2286 — Valid* takes the proposal's block and parts. */
                cs->rs.valid_round       = vote->round;          /* :2284 */
                cs->rs.valid_block       = cs->rs.proposal_block;/* :2285 */
                cs->rs.valid_block_parts = cs->rs.proposal_block_parts;/* :2286 */
            } else {
                /* :2288-2295 — a valid block we do not have. */
                cs->rs.proposal_block = NULL;                    /* :2295 */
            }
            if (!cmt_part_set_has_header(cs->rs.proposal_block_parts,
                                         &block_id.part_set_header)) {
                cs->rs.proposal_block_parts = NULL;   /* clear, then take */
                rc = cs_new_part_set_from_header(
                        cs, &block_id.part_set_header,
                        &cs->rs.proposal_block_parts);           /* :2299 */
                if (rc != CMT_OK) {
                    return rc;
                }
            }
            /* :2302-2305 — the event switch and PublishEventValidBlock. */
        }
    }

    /* :2310-2328 — the three-way switch on where the prevote sits. */
    has_any = false;
    rc = cmt_vote_set_has_two_thirds_any(prevotes, &has_any);
    if (rc != CMT_OK) {
        return rc;
    }
    if (cs->rs.round < vote->round && has_any) {                 /* :2311 */
        return cmt_cs_enter_new_round(cs, height, vote->round);  /* :2313 */
    }
    if (cs->rs.round == vote->round &&
        CMT_ROUND_STEP_PREVOTE <= cs->rs.step) {                 /* :2315 */
        ok = false;
        rc = cmt_vote_set_two_thirds_majority(prevotes, &block_id, &ok);
        if (rc != CMT_OK) {                                      /* :2316 */
            return rc;
        }
        complete = false;
        rc = cmt_cs_is_proposal_complete(cs, &complete);         /* :2317 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (ok && (complete || block_id.hash_len == 0u)) {
            return cmt_cs_enter_precommit(cs, height, vote->round);/* :2318 */
        }
        if (has_any) {                                           /* :2319 */
            return cmt_cs_enter_prevote_wait(cs, height, vote->round);/* :2320 */
        }
        return CMT_OK;
    }
    if (cs->rs.proposal != NULL && 0 <= cs->rs.proposal->pol_round &&
        cs->rs.proposal->pol_round == vote->round) {             /* :2323 */
        complete = false;
        rc = cmt_cs_is_proposal_complete(cs, &complete);         /* :2325 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (complete) {
            return cmt_cs_enter_prevote(cs, height, cs->rs.round);/* :2326 */
        }
    }
    return CMT_OK;
}

/** The precommit arm of the switch at :2330-2356. */
static int cs_add_vote_precommit(cmt_cs_t *cs, const cmt_vote_t *vote,
                                 int64_t height)
{
    cmt_vote_set_t *precommits;
    cmt_block_id_t  block_id;
    bool            ok;
    bool            has_any;
    bool            has_all;
    int             rc;

    precommits = cmt_hvs_precommits(cs->rs.votes, vote->round);  /* :2331 */

    ok = false;
    rc = cmt_vote_set_two_thirds_majority(precommits, &block_id, &ok);/* :2339 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (ok) {                                                    /* :2340 */
        /* :2342-2343 — the majority may be from a HIGHER round, so catch
         * up to it before precommitting. */
        rc = cmt_cs_enter_new_round(cs, height, vote->round);    /* :2342 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        rc = cmt_cs_enter_precommit(cs, height, vote->round);    /* :2343 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        if (block_id.hash_len != 0u) {                           /* :2345 */
            rc = cmt_cs_enter_commit(cs, height, vote->round);   /* :2346 */
            if (rc == CMT_FAULT) {
                return rc;
            }
            if (cs->config->skip_timeout_commit) {               /* :2347 */
                has_all = false;
                if (cmt_vote_set_has_all(precommits, &has_all) != CMT_OK) {
                    return CMT_FAULT;
                }
                if (has_all) {
                    return cmt_cs_enter_new_round(cs, cs->rs.height, 0);/* :2348 */
                }
            }
            return CMT_OK;
        }
        return cmt_cs_enter_precommit_wait(cs, height, vote->round);/* :2351 */
    }

    has_any = false;
    rc = cmt_vote_set_has_two_thirds_any(precommits, &has_any);  /* :2353 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (cs->rs.round <= vote->round && has_any) {                /* :2353 */
        rc = cmt_cs_enter_new_round(cs, height, vote->round);    /* :2354 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        return cmt_cs_enter_precommit_wait(cs, height, vote->round);/* :2355 */
    }
    return CMT_OK;
}

static int cs_add_vote(cmt_cs_t *cs, const cmt_vote_t *vote,
                       const cmt_peer_id_t *peer, bool *out_added,
                       cs_conflict_t *conflict)
{
    cmt_vote_set_err_t err;
    cmt_vote_t        *conflicting;
    int64_t            height;
    bool               added;
    bool               ext_enabled;
    int                rc;

    *out_added = false;
    /* :2131-2133 is MarkLateVote, a metric. */

    /* :2137 — `vote.Height+1 == cs.Height`. FORMED THE OTHER WAY ROUND ON
     * PURPOSE. `vote->height` is a PEER'S number and nothing on the path to
     * here bounds it: this port stops before the reference's ValidateBasic
     * (cmt_msgs.h:28-35, deferred to R3), which is where `Height <= 0` is
     * refused (types/vote.go:283-285). Go's `vote.Height+1` at INT64_MAX
     * merely WRAPS and the comparison is false; in C that addition is
     * UNDEFINED. Subtracting from our OWN height cannot overflow —
     * `cs->rs.height` is set only by `updateToState` from
     * `last_block_height + 1` or `initial_height` (:713-715) — and the
     * `> 0` guard makes the rewrite total, so no input reaches an
     * undefined operation. Same predicate on every input the reference
     * itself answers without wrapping. INVARIANT
     * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07. */
    if (cs->rs.height > 0 && vote->height == cs->rs.height - 1 &&
        vote->type == CMT_PB_MSG_TYPE_PRECOMMIT) {               /* :2137 */
        return cs_add_vote_last_commit(cs, vote, out_added);
    }
    if (vote->height != cs->rs.height) {                         /* :2172 */
        /* :2173-2174 — a height mismatch is ignored, not an error. */
        return CMT_OK;
    }

    ext_enabled = false;
    rc = cmt_abci_params_vote_extensions_enabled(
            cs->state.consensus_params.abci, vote->height, &ext_enabled);
    if (rc != CMT_OK) {                                          /* :2178 */
        return rc;
    }
    rc = cs_add_vote_check_extension(cs, vote, ext_enabled);/* :2179-2226 */
    if (rc != CMT_OK) {
        return rc;
    }

    height = cs->rs.height;                                      /* :2228 */

    /* Heap: a conflicting vote is ~9.5 KB. */
    conflicting = (cmt_vote_t *)calloc(1u, sizeof(*conflicting));
    if (conflicting == NULL) {
        return CMT_FAULT;
    }
    added = false;
    err   = CMT_VOTE_SET_ERR_NONE;
    rc = cmt_hvs_add_vote(cs->rs.votes, vote, *peer, ext_enabled, &added,
                          &err, conflicting);                    /* :2229 */
    *out_added = added;
    if (err == CMT_VOTE_SET_ERR_CONFLICTING_VOTES && conflict != NULL) {
        /* vote_set.go:236 — NewConflictingVoteError(conflicting, vote):
         * VoteA is the one already in the set, VoteB the caller's. */
        conflict->present = true;
        conflict->vote_a  = *conflicting;
        conflict->vote_b  = *vote;
    }
    free(conflicting);
    if (rc == CMT_FAULT) {
        return rc;
    }
    if (!added) {
        /* :2230-2238 — either a duplicate (no error) or a refusal. */
        return rc;
    }
    /* :2239-2243 is MarkVoteReceived, a metric; :2245-2248 the event bus. */

    switch (vote->type) {                                        /* :2250 */
    case CMT_PB_MSG_TYPE_PREVOTE:
        return cs_add_vote_prevote(cs, vote, height);       /* :2251-2328 */
    case CMT_PB_MSG_TYPE_PRECOMMIT:
        return cs_add_vote_precommit(cs, vote, height);     /* :2330-2356 */
    default:
        /* :2359 — panic("unexpected vote type"). NODE-LOCAL → CMT_FAULT,
         * and the reason is a filter one layer up rather than a claim
         * about this function: HeightVoteSet.AddVote drops a vote whose
         * type is neither prevote nor precommit with a naked `return`
         * (height_vote_set.go:139-141), so `added` is false for it and
         * :2230 has already returned. Reaching this line means our own
         * vote set reported that it stored a vote it cannot have
         * stored. */
        QGP_LOG_ERROR(LOG_TAG, "unexpected vote type %d", (int)vote->type);
        return CMT_FAULT;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:2366-2474 — signing a vote
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_vote_time(cmt_cs_t *cs, cmt_time_t *out)
{
    cmt_time_t now;
    cmt_time_t min_vote_time;
    int        rc;

    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    rc = cs->host.now(cs->host_ctx, &now);      /* :2417 — CLOCK SITE 5/5 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    min_vote_time = now;                                         /* :2418 */

    /* :2420 — `const timeIota = time.Millisecond`, the minimum increment
     * between blocks. :2421-2422 carries the reference's own TODO. */
    if (cs->rs.locked_block != NULL) {                           /* :2423 */
        min_vote_time = cs_time_add_ns(cs->rs.locked_block->header.time,
                                       CMT_CS_TIME_IOTA_NS);     /* :2426 */
    } else if (cs->rs.proposal_block != NULL) {                  /* :2427 */
        min_vote_time = cs_time_add_ns(cs->rs.proposal_block->header.time,
                                       CMT_CS_TIME_IOTA_NS);     /* :2428 */
    }

    if (cs_time_after(now, min_vote_time)) {                     /* :2431 */
        *out = now;                                              /* :2432 */
        return CMT_OK;
    }
    *out = min_vote_time;                                        /* :2434 */
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:2366-2414 — signVote().
 * CONTRACT (:2365): the caller has checked that a priv validator exists. */
static int cs_sign_vote(cmt_cs_t *cs, int32_t msg_type, const uint8_t *hash,
                        size_t hash_len, const cmt_part_set_header_t *header,
                        cmt_block_t *block, cmt_vote_t *out, bool *recoverable)
{
    uint8_t  addr[CMT_ADDRESS_SIZE];
    int32_t  val_idx;
    bool     ext_enabled;
    int      rc;

    /* :2374 — flush the WAL, or we may not recompute the same vote and the
     * privValidator will refuse to sign. */
    rc = cs->host.wal_flush_and_sync(cs->host_ctx);
    if (rc != CMT_OK) {
        return CMT_REJECT;                                       /* :2375 */
    }
    if (!cs->priv_validator_pub_key_present) {                   /* :2378 */
        return CMT_REJECT;                       /* :2379 errPubKeyIsNotSet */
    }
    rc = cs_priv_validator_address(cs, addr);                    /* :2382 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    val_idx = -1;
    rc = cmt_validator_set_get_by_address(cs->rs.validators, addr,
                                          sizeof(addr), &val_idx, NULL);
    if (rc != CMT_OK) {                                          /* :2383 */
        return CMT_FAULT;   /* NODE-LOCAL: our own validator set          */
    }

    memset(out, 0, sizeof(*out));                            /* :2385-2393 */
    memcpy(out->validator_address, addr, sizeof(addr));          /* :2386 */
    out->validator_address_len = sizeof(addr);
    out->validator_index       = val_idx;                        /* :2387 */
    out->height                = cs->rs.height;                  /* :2388 */
    out->round                 = cs->rs.round;                   /* :2389 */
    rc = cmt_cs_vote_time(cs, &out->timestamp);                  /* :2390 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->type = msg_type;                                        /* :2391 */
    if (hash != NULL && hash_len > 0u) {                         /* :2392 */
        if (hash_len > sizeof(out->block_id.hash)) {
            return CMT_FAULT;   /* NODE-LOCAL: our own block's hash       */
        }
        memcpy(out->block_id.hash, hash, hash_len);
        out->block_id.hash_len = hash_len;
    }
    if (header != NULL) {
        out->block_id.part_set_header = *header;
    }

    ext_enabled = false;
    rc = cmt_abci_params_vote_extensions_enabled(
            cs->state.consensus_params.abci, out->height, &ext_enabled);
    if (rc != CMT_OK) {                                          /* :2395 */
        return rc;
    }
    if (msg_type == CMT_PB_MSG_TYPE_PRECOMMIT &&
        !cmt_block_id_is_zero(&out->block_id)) {                 /* :2396 */
        if (ext_enabled) {                                       /* :2399 */
            /* :2400 — the extension bytes come from the host and MUST live
             * in the per-height arena; cmt_vote_copy shares them into
             * every vote set this vote is added to (cmt_cs.h). */
            rc = cs->host.extend_vote(cs->host_ctx, out, block, &cs->state,
                                      &out->extension);
            if (rc != CMT_OK) {
                return CMT_REJECT;                               /* :2402 */
            }
        }
    }

    rc = cmt_sign_and_check_vote(out, cs->host.sign_vote, cs->host_ctx,
                                 cs->state.chain_id, cs->state.chain_id_len,
                                 ext_enabled &&
                                 (msg_type == CMT_PB_MSG_TYPE_PRECOMMIT),
                                 recoverable);                   /* :2408 */
    if (rc != CMT_OK && !(*recoverable)) {
        /* :2409-2411 — panic("non-recoverable error when signing vote").
         * NODE-LOCAL → CMT_FAULT: SignAndCheckVote's non-recoverable cases
         * (vote.go:428, :437, :445) are all "the signer returned a vote
         * that does not match the one we handed it", which is this node's
         * own signer contradicting itself. */
        QGP_LOG_ERROR(LOG_TAG, "non-recoverable error when signing vote");
        return CMT_FAULT;
    }
    return rc;                                                   /* :2413 */
}

int cmt_cs_sign_add_vote(cmt_cs_t *cs, int32_t msg_type,
                         const uint8_t *hash, size_t hash_len,
                         const cmt_part_set_header_t *header,
                         cmt_block_t *block)
{
    cmt_vote_t     *vote;
    cmt_msg_info_t *mi;
    uint8_t         addr[CMT_ADDRESS_SIZE];
    bool            recoverable;
    bool            has_ext;
    bool            ext_enabled;
    int             rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (!cs->has_priv_validator) {                               /* :2445 */
        return CMT_OK;                                           /* :2446 */
    }
    if (!cs->priv_validator_pub_key_present) {                   /* :2449 */
        QGP_LOG_ERROR(LOG_TAG, "signAddVote: pubkey is not set");/* :2451 */
        return CMT_OK;                                           /* :2452 */
    }
    rc = cs_priv_validator_address(cs, addr);                    /* :2456 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (!cmt_validator_set_has_address(cs->rs.validators, addr,
                                       sizeof(addr))) {          /* :2456 */
        return CMT_OK;                                           /* :2457 */
    }

    /* Heap: a vote carries two 4627-byte signatures, and this sits inside
     * the enter* call chain. */
    vote = (cmt_vote_t *)calloc(1u, sizeof(*vote));
    mi   = (cmt_msg_info_t *)calloc(1u, sizeof(*mi));
    if (vote == NULL || mi == NULL) {
        free(vote);
        free(mi);
        return CMT_FAULT;
    }
    recoverable = false;
    rc = cs_sign_vote(cs, msg_type, hash, hash_len, header, block, vote,
                      &recoverable);                             /* :2461 */
    if (rc == CMT_FAULT) {
        free(vote);
        free(mi);
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        /* :2462-2465 — a signing failure is logged and nothing is sent. */
        QGP_LOG_ERROR(LOG_TAG, "failed signing vote: height %lld round %d",
                      (long long)cs->rs.height, (int)cs->rs.round);
        free(vote);
        free(mi);
        return CMT_OK;
    }

    has_ext     = vote->extension_signature_len > 0u;            /* :2466 */
    ext_enabled = false;
    rc = cmt_abci_params_vote_extensions_enabled(
            cs->state.consensus_params.abci, vote->height, &ext_enabled);
    if (rc != CMT_OK) {                                          /* :2467 */
        free(vote);
        free(mi);
        return rc;
    }
    if (vote->type == CMT_PB_MSG_TYPE_PRECOMMIT &&
        !cmt_block_id_is_zero(&vote->block_id) &&
        has_ext != ext_enabled) {                                /* :2468 */
        /* :2469-2470 — panic. NODE-LOCAL → CMT_FAULT: the vote was built
         * and signed by this node a dozen lines ago, and the extension's
         * presence was decided from the same `ext_enabled` at :2399. */
        QGP_LOG_ERROR(LOG_TAG,
                      "vote extension absence/presence does not match "
                      "extensions enabled %d != %d, height %lld",
                      (int)has_ext, (int)ext_enabled,
                      (long long)vote->height);
        free(vote);
        free(mi);
        return CMT_FAULT;
    }

    /* :2472 — our own vote goes onto the internal queue. It is handled on
     * a LATER step, after the WriteSync at :839; this function never
     * transitions. */
    mi->msg.kind            = CMT_PB_CONS_MSG_VOTE;
    mi->msg.u.vote.has_vote = true;
    mi->msg.u.vote.vote     = *vote;
    cs_msg_set_peer(mi, NULL);
    rc = cs_send_internal_message(cs, mi);
    free(vote);
    free(mi);
    return rc;
}

/* cometbft@709fd12b consensus/state.go:2479-2490 —
 * updatePrivValidatorPubKey() */
int cmt_cs_update_priv_validator_pub_key(cmt_cs_t *cs)
{
    cmt_pb_public_key_t pk;
    int                 rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (!cs->has_priv_validator) {                               /* :2480 */
        return CMT_OK;                                           /* :2481 */
    }
    memset(&pk, 0, sizeof(pk));
    rc = cs->host.get_pub_key(cs->host_ctx, &pk);                /* :2484 */
    if (rc != CMT_OK) {
        /* :2485-2487 — the error is returned and the memo is LEFT
         * UNCHANGED; :2488 is not reached. */
        return rc;
    }
    cs->priv_validator_pub_key         = pk;                     /* :2488 */
    cs->priv_validator_pub_key_present = pk.present;
    return CMT_OK;
}

/* cometbft@709fd12b consensus/state.go:2493-2515 —
 * checkDoubleSigningRisk() */
int cmt_cs_check_double_signing_risk(cmt_cs_t *cs, int64_t height)
{
    cmt_commit_t *last_commit;
    uint8_t       val_addr[CMT_ADDRESS_SIZE];
    int64_t       check_height;
    int64_t       i;
    int           rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    if (!(cs->has_priv_validator && cs->priv_validator_pub_key_present &&
          cs->config->double_sign_check_height > 0 && height > 0)) {
        return CMT_OK;                                           /* :2494 */
    }
    rc = cs_priv_validator_address(cs, val_addr);                /* :2495 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    check_height = cs->config->double_sign_check_height;         /* :2496 */
    if (check_height > height) {                                 /* :2497 */
        check_height = height;                                   /* :2498 */
    }

    last_commit = (cmt_commit_t *)calloc(1u, sizeof(*last_commit));
    if (last_commit == NULL) {
        return CMT_FAULT;
    }
    for (i = 1; i < check_height; i++) {                         /* :2501 */
        bool   found = false;
        size_t s;

        memset(last_commit, 0, sizeof(*last_commit));
        rc = cs->host.bs_load_seen_commit(cs->host_ctx, height - i,
                                          last_commit, &found);  /* :2502 */
        if (rc != CMT_OK) {
            free(last_commit);
            return CMT_FAULT;
        }
        if (!found) {                                            /* :2503 */
            continue;
        }
        for (s = 0u; s < last_commit->signatures_len; s++) {     /* :2504 */
            const cmt_commit_sig_t *sig = &last_commit->signatures[s];

            if (sig->block_id_flag == CMT_BLOCK_ID_FLAG_COMMIT &&
                sig->validator_address_len == sizeof(val_addr) &&
                memcmp(sig->validator_address, val_addr,
                       sizeof(val_addr)) == 0) {                 /* :2505 */
                QGP_LOG_ERROR(LOG_TAG,
                              "found signature from the same key at "
                              "height %lld", (long long)(height - i));
                free(last_commit);
                return CMT_REJECT;      /* :2507 ErrSignatureFoundInPastBlocks */
            }
        }
    }
    free(last_commit);
    return CMT_OK;                                               /* :2514 */
}

/* cometbft@709fd12b consensus/state.go:2600-2617 — CompareHRS(), a free
 * function: no receiver, so no `cs` in the C name. */
int cmt_compare_hrs(int64_t h1, int32_t r1, cmt_round_step_t s1,
                    int64_t h2, int32_t r2, cmt_round_step_t s2)
{
    if (h1 < h2) {
        return -1;                                               /* :2602 */
    }
    if (h1 > h2) {
        return 1;                                                /* :2604 */
    }
    if (r1 < r2) {
        return -1;                                               /* :2607 */
    }
    if (r1 > r2) {
        return 1;                                                /* :2609 */
    }
    if (s1 < s2) {
        return -1;                                               /* :2612 */
    }
    if (s1 > s2) {
        return 1;                                                /* :2614 */
    }
    return 0;                                                    /* :2616 */
}

/* ══════════════════════════════════════════════════════════════════════
 * replay.go:39-167 — replaying the WAL
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_read_replay_message(cmt_cs_t *cs,
                               const cmt_timed_wal_message_t *msg)
{
    if (cs == NULL || msg == NULL) {
        return CMT_FAULT;
    }
    switch (msg->msg.kind) {
    case CMT_PB_WAL_END_HEIGHT:
        return CMT_OK;                                    /* replay.go:41-43 */

    case CMT_PB_WAL_EVENT_DATA_ROUND_STATE:
        /* replay.go:47-63 — the reference LOGS the step and, when a
         * `newStepSub` subscription was supplied, waits for the live
         * EventDataRoundState and compares the three fields (:55).
         * `catchupReplay` passes nil (:161), so on this path the
         * comparison never runs and there is nothing to port. */
        return CMT_OK;

    case CMT_PB_WAL_MSG_INFO:
        return cmt_cs_handle_msg(cs, &msg->msg.u.msg_info);   /* replay.go:82 */

    case CMT_PB_WAL_TIMEOUT_INFO:
        /* replay.go:85 — against the LIVE round state, not a snapshot. */
        return cmt_cs_handle_timeout(cs, &msg->msg.u.timeout_info, &cs->rs);

    case CMT_PB_WAL_NONE:
    default:
        /* replay.go:86-88 — "Unknown TimedWALMessage type". The record
         * came off this node's own WAL, but the kind is a stored value
         * the decoder read back, so a corrupted-but-verifying row is
         * DATA. CMT_REJECT, and the caller stops the replay with it. */
        QGP_LOG_ERROR(LOG_TAG, "replay: unknown WAL message kind %d",
                      (int)msg->msg.kind);
        return CMT_REJECT;
    }
}

int cmt_cs_catchup_replay(cmt_cs_t *cs, int64_t cs_height)
{
    cmt_timed_wal_message_t *msg;
    int64_t                  end_height;
    bool                     found;
    int                      rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    cs->replay_mode = true;                              /* replay.go:97 */

    /* :100-117 — #ENDHEIGHT for THIS height must not exist. */
    found = false;
    rc = cs->host.wal_search_end_height(cs->host_ctx, cs_height, &found);
    if (rc != CMT_OK) {                                          /* :106 */
        cs->replay_mode = false;
        return rc;                                               /* :107-109 */
    }
    if (found) {
        cs->replay_mode = false;
        QGP_LOG_ERROR(LOG_TAG, "wal should not contain #ENDHEIGHT %lld",
                      (long long)cs_height);
        return CMT_REJECT;                                       /* :116 */
    }

    if (cs_height < cs->state.initial_height) {                  /* :122 */
        cs->replay_mode = false;
        QGP_LOG_ERROR(LOG_TAG,
                      "cannot replay height %lld, below initial height %lld",
                      (long long)cs_height,
                      (long long)cs->state.initial_height);
        return CMT_REJECT;                                       /* :123 */
    }
    end_height = cs_height - 1;                                  /* :125 */
    if (cs_height == cs->state.initial_height) {                 /* :126 */
        end_height = 0;                                          /* :127 */
    }
    found = false;
    rc = cs->host.wal_search_end_height(cs->host_ctx, end_height, &found);
    if (rc != CMT_OK) {                                          /* :129 */
        cs->replay_mode = false;
        return rc;                                               /* :132-134 */
    }
    if (!found) {                                                /* :135 */
        cs->replay_mode = false;
        QGP_LOG_ERROR(LOG_TAG,
                      "cannot replay height %lld: WAL does not contain "
                      "#ENDHEIGHT for %lld",
                      (long long)cs_height, (long long)end_height);
        return CMT_REJECT;                                       /* :136 */
    }

    /* Heap: a TimedWALMessage's MsgInfo branch carries a whole message. */
    msg = (cmt_timed_wal_message_t *)calloc(1u, sizeof(*msg));
    if (msg == NULL) {
        cs->replay_mode = false;
        return CMT_FAULT;
    }
    for (;;) {                                                   /* :145-164 */
        bool eof = false;

        memset(msg, 0, sizeof(*msg));
        rc = cs->host.wal_read_next(cs->host_ctx, msg, &eof);     /* :147 */
        if (rc != CMT_OK) {
            /* :151-156 — a corruption error and any other error both end
             * the replay with that error. */
            free(msg);
            cs->replay_mode = false;
            return rc;
        }
        if (eof) {
            break;                                               /* :149-150 */
        }
        /* :158-160 — the reference's own note: the priv key is already
         * set, so replaying our own votes may look like double signing;
         * that is prevented by the privval last-sign state, not here. */
        rc = cmt_cs_read_replay_message(cs, msg);                /* :161 */
        if (rc != CMT_OK) {
            free(msg);
            cs->replay_mode = false;
            return rc;                                           /* :162 */
        }
    }
    free(msg);
    cs->replay_mode = false;                                     /* :98 */
    return CMT_OK;                                               /* :166 */
}

/* ══════════════════════════════════════════════════════════════════════
 * state.go:154-208, :318-441 — construction and lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_cs_init(cmt_cs_t *cs,
                const cmt_config_t *config,
                const cmt_state_t *state,
                const cmt_cs_host_t *host, void *host_ctx,
                cmt_cs_slots_t *slots,
                cmt_state_storage_t *state_storage,
                cmt_state_storage_t *scratch_storage,
                cmt_pb_arena_t *ext_arena,
                int64_t offline_state_sync_height)
{
    int rc;

    if (cs == NULL || config == NULL || state == NULL || host == NULL ||
        slots == NULL || state_storage == NULL || scratch_storage == NULL) {
        return CMT_FAULT;
    }
    if (state_storage == scratch_storage) {
        /* cmt_state_copy refuses a copy that shares its source's storage
         * (cmt_state.c:65-68); catching it here names the reason. */
        return CMT_FAULT;
    }

    memset(cs, 0, sizeof(*cs));
    cs->config                    = config;                       /* :164 */
    cs->host                      = *host;
    cs->host_ctx                  = host_ctx;
    cs->slots                     = slots;
    cs->ext_arena                 = ext_arena;
    cs->do_wal_catchup            = true;                         /* :173 */
    cs->offline_state_sync_height = offline_state_sync_height;    /* :230 */
    cs->last_commit_owner         = CMT_CS_LC_NONE;

    /* :183-185 — the three function defaults, which a caller may replace
     * before the first step exactly as the reference's tests do. */
    cs->decide_proposal = cmt_cs_default_decide_proposal;         /* :183 */
    cs->do_prevote      = cmt_cs_default_do_prevote;              /* :184 */
    cs->set_proposal    = cmt_cs_default_set_proposal;            /* :185 */

    cmt_round_state_init(&cs->rs);
    rc = cmt_ticker_init(&cs->ticker);                            /* :170 */
    if (rc != CMT_OK) {
        return rc;
    }

    /* cs->state must be EMPTY while updateToState runs its :655-685
     * checks; the incoming state is staged in the scratch instead. */
    rc = cmt_state_init(&cs->state, state_storage);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_state_init(&cs->state_scratch, scratch_storage);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_state_copy(state, &cs->state_scratch);
    if (rc != CMT_OK) {
        return rc;
    }

    cs->vals_buf_storage[0] = (cmt_validator_t *)calloc(
            (size_t)CMT_VALSET_MAX, sizeof(cmt_validator_t));
    cs->vals_buf_storage[1] = (cmt_validator_t *)calloc(
            (size_t)CMT_VALSET_MAX, sizeof(cmt_validator_t));
    cs->last_commit_vals_storage = (cmt_validator_t *)calloc(
            (size_t)CMT_VALSET_MAX, sizeof(cmt_validator_t));
    if (cs->vals_buf_storage[0] == NULL || cs->vals_buf_storage[1] == NULL ||
        cs->last_commit_vals_storage == NULL) {
        cmt_cs_free(cs);
        return CMT_FAULT;
    }
    cs->vals_next = 0u;

    /* :188-199 — no votes yet, so LastCommit is rebuilt from the store. */
    if (cs->state_scratch.last_block_height > 0) {                /* :188 */
        if (cs->offline_state_sync_height != 0) {                 /* :194 */
            rc = cs_reconstruct_seen_commit(cs, &cs->state_scratch);/* :195 */
        } else {
            rc = cs_reconstruct_last_commit(cs, &cs->state_scratch);/* :197 */
        }
        if (rc != CMT_OK) {
            cmt_cs_free(cs);
            return rc;
        }
    }

    rc = cmt_cs_update_to_state(cs, &cs->state_scratch);          /* :201 */
    if (rc != CMT_OK) {
        cmt_cs_free(cs);
        return rc;
    }
    /* :203 — scheduleRound0 is deliberately NOT called here; it is
     * cmt_cs_start's. */
    return CMT_OK;
}

void cmt_cs_free(cmt_cs_t *cs)
{
    if (cs == NULL) {
        return;
    }
    cs_q_drain(cs->peer_q, &cs->peer_q_head, &cs->peer_q_len);
    cs_q_drain(cs->internal_q, &cs->internal_q_head, &cs->internal_q_len);

    if (cs->rs.votes != NULL && cs->rs.votes != cs->prev_votes) {
        cmt_hvs_free(cs->rs.votes);
    }
    cs->rs.votes = NULL;
    cs_release_last_commit(cs);   /* frees prev_votes or the owned set    */

    free(cs->vals_buf_storage[0]);
    free(cs->vals_buf_storage[1]);
    free(cs->last_commit_vals_storage);
    cs->vals_buf_storage[0]      = NULL;
    cs->vals_buf_storage[1]      = NULL;
    cs->last_commit_vals_storage = NULL;
}

int cmt_cs_start(cmt_cs_t *cs)
{
    cmt_round_state_t rs;
    int               rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    /* :319-325 (loadWalFile) and :332-334 (ticker.Start) have no
     * counterpart: the WAL is the host's and the ticker is a value that
     * cmt_cs_init already initialised, disarmed (ticker.go:41-53). */

    if (cs->do_wal_catchup) {                                     /* :338 */
        rc = cmt_cs_catchup_replay(cs, cs->rs.height);            /* :343 */
        if (rc == CMT_FAULT) {
            return rc;
        }
        if (rc != CMT_OK) {
            /* :348-350 — the reference distinguishes a data-corruption
             * error, which it tries to REPAIR (:352-385, a file WAL this
             * port does not have), from every other error, which it logs
             * before starting anyway. With no repair path, both are
             * logged and the state machine starts: refusing to start on a
             * replay that found nothing to replay would be a stricter
             * rule than the reference's, and that is a decision for the
             * operator rather than for this port. Recorded as a QUESTION
             * in the wave report. */
            QGP_LOG_ERROR(LOG_TAG, "error on catchup replay; proceeding to "
                                   "start state anyway (rc %d)", rc);
        }
    }
    /* :388-390 — evsw.Start, not ported. */

    rc = cmt_cs_check_double_signing_risk(cs, cs->rs.height);      /* :393 */
    if (rc != CMT_OK) {
        return rc;                                               /* :394 */
    }
    /* :398 — `go cs.receiveRoutine(0)`: the caller drives cmt_cs_step. */

    /* :402 — the reference passes GetRoundState() so it does not race the
     * receive routine; there is no race here, and the copy is kept
     * because scheduleRound0 reads only StartTime and Height. */
    rc = cmt_cs_get_round_state(cs, &rs);
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_cs_schedule_round0(cs, &rs);                       /* :402 */
}

int cmt_cs_stop(cmt_cs_t *cs)
{
    cmt_ticker_action_t action;
    bool                cancel;
    int                 rc;

    if (cs == NULL) {
        return CMT_FAULT;
    }
    /* :433-435 — evsw.Stop, not ported. */
    cancel = false;
    rc = cmt_ticker_stop(&cs->ticker, &cancel);                   /* :437 */
    if (rc != CMT_OK) {
        return rc;
    }
    memset(&action, 0, sizeof(action));
    action.cancel_previous = cancel;
    /* :440 — "WAL is stopped in receiveRoutine"; the WAL is the host's. */
    return cs_apply_ticker_action(cs, &action);
}
