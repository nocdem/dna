/**
 * Shared 4002 SecretConnection glue, role-list lookup and inbound limits.
 * Governing: approved 2026-10-28 encrypted-sessions design, sections 2/3.3,
 * 2026-10-29 build plan sections 3/4; component-split decision item 28.
 * Primitive/wire implementation stays in cmt_p2p_secret, unchanged.
 */
#ifndef NODUS_INTER_SESSION_H
#define NODUS_INTER_SESSION_H

#include "transport/nodus_tcp.h"
#include "dnac/cmt_p2p_transport.h"  /* self-contained cmt_p2p_hs_job_t layout */
#include "dnac/dnac.h"             /* DNAC_MAX_VALIDATORS, DNAC_EPOCH_LENGTH */
#include "dnac/ledger_roots_v2.h"   /* DNA_V2_STORAGE_SET_MAX */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nodus_inter_session_module nodus_inter_session_module_t;
typedef struct nodus_inter_session_conn nodus_inter_session_conn_t;

/* Approved build plan 4.1 c: one sorted, bounded list read at one height. */
typedef struct {
    uint64_t height;
    size_t validator_count, storage_count;
    nodus_key_t validators[DNAC_MAX_VALIDATORS];
    nodus_key_t storage[DNA_V2_STORAGE_SET_MAX];
} nodus_inter_role_list_t;

void nodus_inter_roles_lookup(const nodus_inter_role_list_t *list,
                              const nodus_key_t *fp, bool *va, bool *st);
/* The two local control wires share exactly q, ok, h, va and st.
 * Failure encodes empty arrays; decoding is strict and bounded. */
size_t nodus_inter_roles_encode(const char *q, const nodus_inter_role_list_t *list,
                                bool ok, uint8_t *buf, size_t cap);
int nodus_inter_roles_decode(const char *q, const uint8_t *buf, size_t len,
                             nodus_inter_role_list_t *list, bool *ok);

typedef struct {
    /* The identity outlives the module and all its workers. ML-KEM is
     * required unless `initiator_only` is set: an initiator-only module (a
     * client) never accepts and needs none (design 3.1 "The client needs no
     * KEM key"). chain_id is copied; nothing here reads a chain database. */
    const nodus_identity_t *identity;
    /* Port/version of this module's sessions: CMT_P2P_SC_PROTO_VER_4001
     * (4001 and the WebSocket entry) or _4002. 0 keeps the 4002 value the
     * existing 4002 owners were built with; the 4001 owners state theirs. */
    uint32_t proto_ver;
    /* true = this owner only dials. Stated by the owner, never inferred from
     * a listener; an inbound connection on such a module is refused. */
    bool initiator_only;
    const uint8_t *chain_id;
    size_t inbound_depth;
    size_t outbound_depth;
    unsigned workers;              /* explicit; 0 = owner runs job_take/run/done */
    /* With workers == 0: true = the owner's poll pass takes, runs and
     * completes the queued jobs itself (the client and the browser build: no
     * thread, the owner's own loop does the work). false = the owner calls
     * job_take/run/done (the module tests). Ignored when workers > 0. */
    bool run_jobs_inline;
    uint64_t (*now_ms)(void *ctx);  /* NULL = nodus_time_mono_ms, deadline only */
    void *now_ctx;
    /* Loop thread only, after pin and reject-self. Authenticated != open.
     * The owner may open here, wait for admission, or disconnect. */
    void (*on_authenticated)(nodus_tcp_conn_t *, const nodus_pubkey_t *, void *);
    void *auth_ctx;
    /* status is false until the chain is known. role only looks up the
     * held list, on the owner thread: 1 = list held, -1 = no list.
     * It sends no query and never waits. Re-checks use that same list. */
    bool (*status)(void *, uint8_t chain_id[32], uint64_t *height);
    int (*role)(void *, const nodus_key_t *, bool *validator, bool *storage);
    void *admission_ctx;
    /* TEST SEAM (never set by a production owner): called with the context on
     * entry of every module function that touches a connection's machine
     * (start, submit, job_done, read, seal, open, the owner poll pass). A
     * test records the calling thread to assert that one thread alone owns
     * the machine (approved 4001 plan 2.1 e, 4.1 row 13). NULL = off. */
    void (*machine_hook)(void *ctx);
    void *machine_hook_ctx;
    unsigned inbound_cap;          /* 0 = no owner limit (module tests) */
    bool allow_duplicate_ip;       /* test harness, same-IP refusal only */
} nodus_inter_session_config_t;

#define NODUS_INTER_INBOUND_CAP 40u
/* ⚠ NOT GROUNDED: copied from the approved 4004 bound; measurement deferred. */
#define NODUS_INTER_JOB_DEPTH 64u
#define NODUS_INTER_WORKERS 2u

/* Job copies never point into a connection. The key copy is needed by a
 * DECAPS that outlives its connection. Workers touch only this object and
 * the module's immutable signing host (cmt_p2p_transport.h:68-87).
 * Owner must return every manually taken job before freeing the module. */
typedef struct nodus_inter_session_job {
    struct nodus_inter_session_job *next;
    cmt_p2p_hs_job_t work;
    uint8_t kem_sk[CMT_P2P_SC_KEM_SK_SIZE];
    /* The module that queued it (stats only; set by submit, never
     * dereferenced after nodus_inter_session_free). */
    struct nodus_inter_session_module *owner;
} nodus_inter_session_job_t;

/* Attaches session mode before any listen/connect. Refuses an existing
 * listener/connection, missing identity or chain/status provider, zero depth,
 * an unknown proto_ver, or a non-initiator-only identity without ML-KEM.
 * A transport with a write lock is allowed (the threaded client): then every
 * session send only queues plaintext and wakes the owner, and the machine is
 * called by the owner thread alone. A WebSocket listener may be added after.
 * No queue/worker defaults. tcp and identity outlive this module.
 * Close the transport before free; free joins every internal worker. */
nodus_inter_session_module_t *nodus_inter_session_new(nodus_tcp_t *tcp,
                                const nodus_inter_session_config_t *cfg);
void nodus_inter_session_free(nodus_inter_session_module_t *s);

/* Counters since the module was created: connections whose machine started,
 * sessions opened, key-exchange jobs refused because a class queue was full
 * (the connection is then closed) and connections that ran past the 3 s
 * handshake deadline. Read by the load-measurement driver (plan 4.5). */
typedef struct {
    uint64_t started, opened, queue_refused, deadline_closed;
    /* Run time of each job kind measured around cmt_p2p_sc_job_run (wall
     * nanoseconds on the monotonic clock, on whichever thread ran it, queue
     * wait excluded): index = CMT_P2P_SC_JOB_ENCAPS .. _VERIFY. */
    uint64_t job_count[5], job_ns_total[5], job_ns_max[5];
} nodus_inter_session_stats_t;
void nodus_inter_session_stats(nodus_inter_session_module_t *s, nodus_inter_session_stats_t *out);

bool nodus_inter_session_chain_ready(nodus_inter_session_module_t *s);
bool nodus_inter_session_is_open(const nodus_tcp_conn_t *conn);
int nodus_inter_session_open(nodus_tcp_conn_t *conn);

/* Loop entry points. submit snapshots the one outstanding machine job;
 * a full class queue is an error, the caller closes the handshake. */
int nodus_inter_session_submit(nodus_tcp_conn_t *conn);
nodus_inter_session_job_t *nodus_inter_session_job_take(nodus_inter_session_module_t *s);
size_t nodus_inter_session_job_queued(nodus_inter_session_module_t *s, bool outbound);
void nodus_inter_session_job_run(nodus_inter_session_job_t *job);
/* Always consumes/zeroes/frees job, including a stale (slot,generation). */
int nodus_inter_session_job_done(nodus_inter_session_module_t *s,
                                nodus_inter_session_job_t *job);
/* Owner may register this descriptor in its own event loop. poll drains
 * completions on the owner thread and checks every not-open deadline.
 * nodus_tcp_poll calls it even on passes without socket activity. */
int nodus_inter_session_wake_fd(const nodus_inter_session_module_t *s);
/* Any thread: makes the owner's next poll pass run (queued sends are sealed
 * there). The wake is a coalescing eventfd write; it never blocks. */
void nodus_inter_session_wake_owner(nodus_inter_session_module_t *s);
void nodus_inter_session_poll(nodus_inter_session_module_t *s);
int nodus_inter_session_poll_timeout(nodus_inter_session_module_t *s, int timeout_ms);

/* Transport glue. All connection access is on the owner thread. read
 * delivers plaintext only after open and drains read_pending without
 * needing another socket byte. The socket staging buffer is bounded by
 * CMT_P2P_SC_HS_MSG_MAX (also while a job is outstanding). */
int nodus_inter_session_start(nodus_tcp_conn_t *conn);
void nodus_inter_session_clear(nodus_tcp_conn_t *conn);
uint8_t *nodus_inter_session_read_buf(nodus_tcp_conn_t *conn, size_t *room);
void nodus_inter_session_read_done(nodus_tcp_conn_t *conn, size_t n);
int nodus_inter_session_read(nodus_tcp_conn_t *conn, uint8_t *plain,
                             size_t cap, size_t *n);
int nodus_inter_session_seal(nodus_tcp_conn_t *conn, const uint8_t *plain,
                             size_t n, uint8_t *out, size_t cap, size_t *written);

#ifdef __cplusplus
}
#endif

#endif
