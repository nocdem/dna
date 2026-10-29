/**
 * Shared 4002 SecretConnection glue (both roles, no server wiring).
 * Governing: approved 2026-10-28 encrypted-sessions design, sections 2/3.3,
 * 2026-10-29 build plan section 3; component-split decision item 28.
 * Primitive/wire implementation stays in cmt_p2p_secret, unchanged.
 */
#ifndef NODUS_INTER_SESSION_H
#define NODUS_INTER_SESSION_H

#include "transport/nodus_tcp.h"
#include "dnac/cmt_p2p_transport.h"  /* self-contained cmt_p2p_hs_job_t layout */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nodus_inter_session_module nodus_inter_session_module_t;
typedef struct nodus_inter_session_conn nodus_inter_session_conn_t;

typedef struct {
    /* The identity outlives the module and all its workers. ML-KEM required.
     * chain_id is copied; nothing here reads a chain database. */
    const nodus_identity_t *identity;
    const uint8_t *chain_id;
    size_t inbound_depth;
    size_t outbound_depth;
    unsigned workers;              /* explicit; 0 = owner runs job_take/run/done */
    uint64_t (*now_ms)(void *ctx);  /* NULL = nodus_time_mono_ms, deadline only */
    void *now_ctx;
    /* Loop thread only, after pin and reject-self. Authenticated != open.
     * The owner may open here, wait for admission, or disconnect. */
    void (*on_authenticated)(nodus_tcp_conn_t *, const nodus_pubkey_t *, void *);
    void *auth_ctx;
} nodus_inter_session_config_t;

/* Job copies never point into a connection. The key copy is needed by a
 * DECAPS that outlives its connection. Workers touch only this object and
 * the module's immutable signing host (cmt_p2p_transport.h:68-87).
 * Owner must return every manually taken job before freeing the module. */
typedef struct nodus_inter_session_job {
    struct nodus_inter_session_job *next;
    cmt_p2p_hs_job_t work;
    uint8_t kem_sk[CMT_P2P_SC_KEM_SK_SIZE];
} nodus_inter_session_job_t;

/* Attaches session mode before any listen/connect. Refuses an existing
 * listener/connection, missing identity/chain, or zero queue depth.
 * No queue/worker defaults. tcp and identity outlive this module.
 * Close the transport before free; free joins every internal worker. */
nodus_inter_session_module_t *nodus_inter_session_new(nodus_tcp_t *tcp,
                                const nodus_inter_session_config_t *cfg);
void nodus_inter_session_free(nodus_inter_session_module_t *s);

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
