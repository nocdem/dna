/**
 * Nodus — SecretConnection layer of the TCP / WebSocket transport
 * (DHT v2 sub-package 3b-1). See nodus_tcp_sc.h for the contract.
 *
 * This file owns the per-connection machine, the handshake-job worker and
 * the sealing of frames. The buffers of a connection (rbuf, wbuf, the
 * pending queue, the WebSocket framing) stay in nodus_tcp.c, which calls
 * the entry points declared in the header's "transport-internal" section.
 *
 * Only compiled into libnodus (nodus/CMakeLists.txt defines NODUS_TCP_SC for
 * it); the browser and web-wallet builds that compile nodus_tcp.c on its own
 * do not see this layer until 3c adds it to their source lists.
 */

#include "transport/nodus_tcp_sc.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#include <stdlib.h>
#include <string.h>

#ifndef NODUS_SC_INLINE
  #include <pthread.h>
#endif

#define LOG_TAG_SC "NODUS_TCP_SC"

/* The bytes a host sign / verify moves are the nodus types' bytes. */
_Static_assert(sizeof(((nodus_sig_t *)0)->bytes) == CMT_P2P_SC_SIG_SIZE,
               "nodus_sig_t must be CMT_P2P_SC_SIG_SIZE bytes");
_Static_assert(sizeof(((nodus_pubkey_t *)0)->bytes) == CMT_P2P_SC_DSA_PK_SIZE,
               "nodus_pubkey_t must be CMT_P2P_SC_DSA_PK_SIZE bytes");
_Static_assert(NODUS_TCP_SC_WBUF_FILL == 66824 && NODUS_TCP_SC_PORTION_WIRE == 33412 &&
               NODUS_TCP_SC_WBUF_MAX == 131072 && CMT_P2P_SC_OUT_CAP == 13684,
               "derived write-buffer bounds (header comment): 2 x (32 x 1044 + 4), 128 KiB");

/* The transport's write lock (nodus_tcp_set_write_lock), NULL = none. Every
 * public query of a connection's machine takes it: the machine is written
 * under it by the feed, the completions and the seals, and freed by
 * conn_free under it. */
static void sc_lk(const nodus_tcp_t *tcp, bool lock)
{
    if (tcp != NULL && tcp->write_lock != NULL)
        tcp->write_lock(tcp->write_lock_ctx, lock);
}

/* ── The per-connection state ─────────────────────────────────────────── */

typedef struct nodus_tcp_sc {
    cmt_p2p_sc_t           m;           /* about 42 KB: heap only            */
    cmt_p2p_sc_host_t      host;        /* the machine keeps a pointer here  */
    const uint8_t         *kem_sk;      /* responder's ML-KEM sk, caller-owned */
    uint64_t               gen;         /* this layer's generation           */
    int                    cls;         /* job class: 0 OUTBOUND, 1 INBOUND  */
    bool                   job_out;     /* a job copy is at the worker       */
    cmt_p2p_sc_job_kind_t  job_kind;    /* ... of this kind                  */
    bool                   ready_seen;  /* AUTHENTICATED has been noticed    */
    bool                   ready;       /* ... and on_session is still due   */
    uint8_t               *hold;        /* socket bytes held while a job runs */
    size_t                 hold_len;
    const nodus_key_t     *pin_set;     /* INITIATOR pin SET (cfg.expected_set), caller-owned */
    size_t                 pin_set_n;
    /* The pre-AUTHENTICATED input budget (see sc_presession_budget): bytes the
     * machine consumed so far, the most it may consume, and whether the
     * session is past it (authenticated: the budget no longer applies). */
    size_t                 pre_bytes;
    size_t                 pre_budget;
    bool                   pre_done;
} nodus_tcp_sc_t;

/* The sealed-frame budget of one handshake (Kurultay #43 O-5, "a combined
 * budget (... sealed frames per handshake ...)"): everything a peer may send
 * BEFORE the session is AUTHENTICATED, derived from the sizes the machine
 * itself defines (shared/dnac/cmt_p2p_secret.h) — nothing is added to
 * shared/dnac, 4004 is untouched:
 *   AUTHSIG on the wire  = uvarint(<=3) + kind(1) + signature(4627) = 4631 B
 *   sealed chunk         = CMT_P2P_SC_DATA_MAX_SIZE = 1024 B
 *   sealed frames        = ceil(4631 / 1024) = 5 (4 x 1024 + 535), each
 *                          CMT_P2P_SC_SEALED_FRAME_SIZE = 1044 B -> 5,220 B
 * plus the plaintext handshake messages the role RECEIVES (each at most its
 * uvarint prefix + body):
 *   RESPONDER  HELLO (3 + 2,661) + KEYX (3 + 1,569) -> 4,236 B
 *   INITIATOR  HELLO_R (3 + 4,229)                  -> 4,232 B
 * i.e. at most 5 sealed frames after the plaintext messages. A peer that
 * pushes more than that without completing the session is closed (the
 * feed fails). Sealed bytes that ARRIVE together with the AUTHSIG tail but
 * stay in the hold while the verify job runs are not consumed yet and are
 * counted when they are — by then the session is authenticated and the
 * budget has ended. */
static size_t sc_presession_budget(cmt_p2p_sc_role_t role)
{
    size_t plain = role == CMT_P2P_SC_ROLE_INITIATOR
                 ? (size_t)CMT_P2P_SC_UVARINT_MAX + CMT_P2P_SC_HELLO_R_BODY
                 : (size_t)CMT_P2P_SC_UVARINT_MAX + CMT_P2P_SC_HELLO_BODY +
                   (size_t)CMT_P2P_SC_UVARINT_MAX + CMT_P2P_SC_KEYX_BODY;
    return plain + (size_t)CMT_P2P_SC_AUTHSIG_FRAMES_MAX * CMT_P2P_SC_SEALED_FRAME_SIZE;
}

_Static_assert(CMT_P2P_SC_AUTHSIG_FRAMES_MAX == 5,
               "AUTHSIG is five sealed frames (4631 B / 1024 B, rounded up)");

/* ── Host bindings: the profile decides the signing purpose ───────────── */

static int host_sign_client(void *ctx, const uint8_t *msg, size_t msg_len,
                            uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    nodus_sig_t sig;
    int rc = nodus_sign_client_session_auth(&sig, msg, msg_len,
                                            (const nodus_seckey_t *)ctx);
    if (rc == 0)
        memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    qgp_secure_memzero(&sig, sizeof(sig));
    return rc;
}

static int host_verify_client(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_client_session_auth(&sig, msg, msg_len, &pk);
}

static int host_sign_node(void *ctx, const uint8_t *msg, size_t msg_len,
                          uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    nodus_sig_t sig;
    int rc = nodus_sign_node_session_auth(&sig, msg, msg_len,
                                          (const nodus_seckey_t *)ctx);
    if (rc == 0)
        memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    qgp_secure_memzero(&sig, sizeof(sig));
    return rc;
}

static int host_verify_node(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_node_session_auth(&sig, msg, msg_len, &pk);
}

/* ── The worker ───────────────────────────────────────────────────────── */

#ifndef NODUS_SC_INLINE

enum { SC_Q_OUTBOUND = 0, SC_Q_INBOUND = 1, SC_Q_N = 2 };

typedef struct nodus_sc_worker {
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    nodus_sc_job_t  *qh[SC_Q_N];        /* queued, per class                 */
    nodus_sc_job_t  *qt[SC_Q_N];
    nodus_sc_job_t  *dh, *dt;           /* finished, not yet taken by the loop */
    int              outstanding[SC_Q_N]; /* queued + running + finished-not-taken */
    bool             stop;
    pthread_t        th[NODUS_TCP_SC_WORKERS];
    int              n_th;
} nodus_sc_worker_t;

static const int sc_class_cap[SC_Q_N] = { NODUS_TCP_SC_JOBQ_OUT, NODUS_TCP_SC_JOBQ_IN };

#endif /* !NODUS_SC_INLINE */

static void job_free(nodus_sc_job_t *job)
{
    if (job != NULL) {
        qgp_secure_memzero(job, sizeof(*job));   /* shared secret, signature */
        free(job);
    }
}

#ifndef NODUS_SC_INLINE

static void *worker_main(void *arg)
{
    nodus_sc_worker_t *w = (nodus_sc_worker_t *)arg;

    for (;;) {
        nodus_sc_job_t *j = NULL;
        int q;

        pthread_mutex_lock(&w->mu);
        while (!w->stop && w->qh[SC_Q_OUTBOUND] == NULL && w->qh[SC_Q_INBOUND] == NULL)
            pthread_cond_wait(&w->cv, &w->mu);
        if (w->stop) {
            pthread_mutex_unlock(&w->mu);
            return NULL;
        }
        for (q = 0; q < SC_Q_N; q++) {      /* outbound never waits behind inbound */
            if (w->qh[q] != NULL) {
                j = w->qh[q];
                w->qh[q] = j->next;
                if (w->qh[q] == NULL)
                    w->qt[q] = NULL;
                break;
            }
        }
        pthread_mutex_unlock(&w->mu);
        if (j == NULL)
            continue;
        j->next = NULL;
        /* Touches only the job's own copies and the host's sign / verify. */
        j->rc = cmt_p2p_sc_job_run(&j->job, &j->host);
        pthread_mutex_lock(&w->mu);
        if (w->dt != NULL)
            w->dt->next = j;
        else
            w->dh = j;
        w->dt = j;
        pthread_mutex_unlock(&w->mu);
    }
}

static nodus_sc_worker_t *worker_start(void)
{
    nodus_sc_worker_t *w = (nodus_sc_worker_t *)calloc(1, sizeof(*w));

    if (w == NULL)
        return NULL;
    if (pthread_mutex_init(&w->mu, NULL) != 0) {
        free(w);
        return NULL;
    }
    if (pthread_cond_init(&w->cv, NULL) != 0) {
        pthread_mutex_destroy(&w->mu);
        free(w);
        return NULL;
    }
    for (int i = 0; i < NODUS_TCP_SC_WORKERS; i++) {
        if (pthread_create(&w->th[i], NULL, worker_main, w) != 0) {
            QGP_LOG_ERROR(LOG_TAG_SC, "worker thread %d not started", i);
            break;
        }
        w->n_th++;
    }
    if (w->n_th == 0) {
        pthread_cond_destroy(&w->cv);
        pthread_mutex_destroy(&w->mu);
        free(w);
        return NULL;
    }
    return w;
}

/* Queue `j` (the worker owns it until nodus_tcp_sc_take_done hands it back).
 * -1 when this class is full or the worker is stopping: the caller frees. */
static int worker_push(nodus_sc_worker_t *w, nodus_sc_job_t *j)
{
    pthread_mutex_lock(&w->mu);
    if (w->stop || w->outstanding[j->cls] >= sc_class_cap[j->cls]) {
        pthread_mutex_unlock(&w->mu);
        return -1;
    }
    j->next = NULL;
    j->charged = true;       /* released by nodus_tcp_sc_job_apply, once */
    if (w->qt[j->cls] != NULL)
        w->qt[j->cls]->next = j;
    else
        w->qh[j->cls] = j;
    w->qt[j->cls] = j;
    w->outstanding[j->cls]++;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mu);
    return 0;
}

/* Give back the charge of a job the worker accepted. Called when the loop
 * applies or discards it — never earlier: a batch taken off the worker and
 * waiting for its turn (a nested poll inside an apply callback) still counts
 * against the bound. Jobs that were never pushed (tests) carry no charge. */
static void worker_release(nodus_sc_worker_t *w, nodus_sc_job_t *j)
{
    if (w == NULL || !j->charged)
        return;
    pthread_mutex_lock(&w->mu);
    if (w->outstanding[j->cls] > 0)
        w->outstanding[j->cls]--;
    pthread_mutex_unlock(&w->mu);
    j->charged = false;
}

#endif /* !NODUS_SC_INLINE */

nodus_sc_job_t *nodus_tcp_sc_take_done(nodus_tcp_t *tcp)
{
#ifdef NODUS_SC_INLINE
    (void)tcp;
    return NULL;
#else
    nodus_sc_worker_t *w = tcp ? tcp->sc_worker : NULL;
    nodus_sc_job_t *list;

    if (w == NULL)
        return NULL;
    pthread_mutex_lock(&w->mu);
    list = w->dh;
    w->dh = w->dt = NULL;
    /* Still charged: each job gives its slot back when it is individually
     * applied or discarded (worker_release in nodus_tcp_sc_job_apply). */
    pthread_mutex_unlock(&w->mu);
    return list;
#endif
}

int nodus_tcp_sc_outstanding(const nodus_tcp_t *tcp)
{
#ifdef NODUS_SC_INLINE
    (void)tcp;
    return 0;
#else
    nodus_sc_worker_t *w = tcp ? tcp->sc_worker : NULL;
    int n;

    if (w == NULL)
        return 0;
    pthread_mutex_lock(&w->mu);
    n = w->outstanding[SC_Q_OUTBOUND] + w->outstanding[SC_Q_INBOUND];
    pthread_mutex_unlock(&w->mu);
    return n;
#endif
}

bool nodus_tcp_sc_busy(const nodus_tcp_t *tcp)
{
    bool closing;

    if (tcp == NULL)
        return false;
    if (nodus_tcp_sc_outstanding(tcp) > 0)
        return true;
    sc_lk(tcp, true);
    closing = tcp->sc_close_requests > 0;     /* a loop-owned teardown is due */
    sc_lk(tcp, false);
    return closing;
}

int nodus_tcp_sc_poll_timeout(const nodus_tcp_t *tcp, int timeout_ms)
{
    if (nodus_tcp_sc_busy(tcp) &&
        (timeout_ms < 0 || timeout_ms > NODUS_TCP_SC_POLL_MS))
        return NODUS_TCP_SC_POLL_MS;
    return timeout_ms;
}

void nodus_tcp_sc_worker_stop(nodus_tcp_t *tcp)
{
#ifdef NODUS_SC_INLINE
    (void)tcp;
#else
    nodus_sc_worker_t *w = tcp ? tcp->sc_worker : NULL;
    nodus_sc_job_t *j;

    if (w == NULL)
        return;
    pthread_mutex_lock(&w->mu);
    w->stop = true;
    pthread_cond_broadcast(&w->cv);
    pthread_mutex_unlock(&w->mu);
    for (int i = 0; i < w->n_th; i++)
        pthread_join(w->th[i], NULL);
    /* Every connection is gone (nodus_tcp_close freed the pool first): no
     * result has anywhere to land. Drop them all. */
    for (int q = 0; q < SC_Q_N; q++) {
        j = w->qh[q];
        while (j != NULL) {
            nodus_sc_job_t *next = j->next;
            job_free(j);
            j = next;
        }
    }
    j = w->dh;
    while (j != NULL) {
        nodus_sc_job_t *next = j->next;
        job_free(j);
        j = next;
    }
    pthread_cond_destroy(&w->cv);
    pthread_mutex_destroy(&w->mu);
    free(w);
    tcp->sc_worker = NULL;
#endif
}

/* ── Job submission, completion ───────────────────────────────────────── */

#ifndef NODUS_SC_INLINE

/* Copy the machine's outstanding job into a self-contained one and queue it
 * (cmt_p2p_transport.c:222-281 is the pattern). */
static int sc_submit(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn, nodus_tcp_sc_t *s,
                     const cmt_p2p_sc_job_t *sj)
{
    nodus_sc_job_t *j;

    if (tcp->sc_worker == NULL)
        return -1;
    j = (nodus_sc_job_t *)calloc(1, sizeof(*j));
    if (j == NULL)
        return -1;
    j->slot = conn->slot;
    j->gen = s->gen;
    j->cls = s->cls;
    j->kind = sj->kind;
    j->host = s->host;
    j->job.kind = sj->kind;
    switch (sj->kind) {
    case CMT_P2P_SC_JOB_ENCAPS:
        memcpy(j->kem_pk, sj->kem_pk, sizeof(j->kem_pk));
        j->job.kem_pk = j->kem_pk;
        j->job.kem_ct_out = j->kem_ct_out;
        j->job.kem_ss_out = j->kem_ss_out;
        break;
    case CMT_P2P_SC_JOB_DECAPS:
        memcpy(j->kem_ct, sj->kem_ct, sizeof(j->kem_ct));
        j->job.kem_ct = j->kem_ct;
        j->kem_sk = s->kem_sk;
        j->job.kem_sk = j->kem_sk;
        j->job.kem_ss_out = j->kem_ss_out;
        break;
    case CMT_P2P_SC_JOB_SIGN:
    case CMT_P2P_SC_JOB_VERIFY:
        if (sj->msg_len > sizeof(j->msg)) {
            job_free(j);
            return -1;
        }
        memcpy(j->msg, sj->msg, sj->msg_len);
        j->msg_len = sj->msg_len;
        j->job.msg = j->msg;
        j->job.msg_len = j->msg_len;
        if (sj->kind == CMT_P2P_SC_JOB_SIGN) {
            j->job.sig_out = j->sig_out;
        } else {
            memcpy(j->dsa_pk, sj->dsa_pk, sizeof(j->dsa_pk));
            memcpy(j->sig, sj->sig, sizeof(j->sig));
            j->job.dsa_pk = j->dsa_pk;
            j->job.sig = j->sig;
        }
        break;
    default:
        job_free(j);
        return -1;
    }
    if (worker_push(tcp->sc_worker, j) != 0) {
        QGP_LOG_WARN(LOG_TAG_SC, "handshake job queue full (class %d): slot %d closed",
                     s->cls, conn->slot);
        job_free(j);
        return -1;
    }
    s->job_out = true;
    s->job_kind = sj->kind;
    return 0;
}

#endif /* !NODUS_SC_INLINE */

static void sc_note_ready(nodus_tcp_sc_t *s)
{
    if (!s->ready_seen && cmt_p2p_sc_is_authenticated(&s->m)) {
        s->ready_seen = true;
        s->ready = true;
    }
}

/* The dial pin (decision 2026-09-26-witness-port-session.md; session design
 * rev 1 O-4): before the ENCAPS job, the responder's CLAIMED key must hash
 * to the identity the caller meant to dial. */
static int sc_pin_ok(nodus_tcp_conn_t *conn, nodus_tcp_sc_t *s)
{
    const uint8_t *rpk = cmt_p2p_sc_remote_pubkey(&s->m);
    nodus_pubkey_t pk;
    nodus_key_t fp;

    bool ok = false;

    if (rpk == NULL || (!conn->expected_peer_id_set && s->pin_set_n == 0))
        return -1;
    memcpy(pk.bytes, rpk, sizeof(pk.bytes));
    if (nodus_fingerprint(&pk, &fp) != 0) {
        QGP_LOG_WARN(LOG_TAG_SC, "dialed identity unreadable (slot %d): aborted before Encaps",
                     conn->slot);
        return -1;
    }
    if (conn->expected_peer_id_set && nodus_key_cmp(&fp, &conn->expected_peer_id) == 0)
        ok = true;
    for (size_t i = 0; !ok && i < s->pin_set_n; i++)
        ok = nodus_key_cmp(&fp, &s->pin_set[i]) == 0;
    if (!ok) {
        QGP_LOG_WARN(LOG_TAG_SC, "dialed identity mismatch (slot %d): aborted before Encaps",
                     conn->slot);
        return -1;
    }
    return 0;
}

/* Let the machine have its next job, if it wants one: pin check, then queue
 * it (async) or run it on the spot (inline) until it waits for bytes.
 * 0 = fine, -1 = fail the connection. */
static int sc_advance(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn, nodus_tcp_sc_t *s)
{
    for (;;) {
        const cmt_p2p_sc_job_t *sj;

        if (cmt_p2p_sc_is_authenticated(&s->m)) {
            sc_note_ready(s);
            return 0;
        }
        if (s->job_out)
            return 0;
        sj = cmt_p2p_sc_job(&s->m);
        if (sj == NULL)
            return 0;
        if (sj->kind == CMT_P2P_SC_JOB_ENCAPS &&
            s->m.role == CMT_P2P_SC_ROLE_INITIATOR && sc_pin_ok(conn, s) != 0) {
            cmt_p2p_sc_abort(&s->m);
            return -1;
        }
#ifdef NODUS_SC_INLINE
        {
            int rc = cmt_p2p_sc_job_run(sj, &s->host);

            (void)tcp;
            if (cmt_p2p_sc_job_done(&s->m, rc) != CMT_OK)
                return -1;
        }
#else
        return sc_submit(tcp, conn, s, sj);
#endif
    }
}

nodus_sc_apply_t nodus_tcp_sc_job_apply(nodus_tcp_t *tcp, nodus_sc_job_t *job,
                                        nodus_tcp_conn_t **conn_out)
{
    nodus_tcp_conn_t *conn = NULL;
    nodus_tcp_sc_t *s;
    const cmt_p2p_sc_job_t *sj;
    int r;

    if (conn_out != NULL)
        *conn_out = NULL;
    if (tcp == NULL || job == NULL || conn_out == NULL) {
        job_free(job);
        return NODUS_SC_APPLY_DISCARDED;
    }
#ifndef NODUS_SC_INLINE
    /* Applied or discarded, this job's slot in the bound is free again. */
    worker_release(tcp->sc_worker, job);
#endif
    if (job->slot >= 0 && job->slot < NODUS_TCP_MAX_CONNS)
        conn = tcp->pool[job->slot];
    /* (slot, generation): the slot must still hold the connection this job
     * was copied for, and its layer must be waiting for exactly this job. */
    if (conn == NULL || conn->close_pending || conn->sc_closing || conn->sc == NULL ||
        conn->sc->gen != job->gen || !conn->sc->job_out ||
        conn->sc->job_kind != job->kind) {
        QGP_LOG_DEBUG(LOG_TAG_SC, "stale handshake job (slot %d gen %llu) discarded",
                      job->slot, (unsigned long long)job->gen);
        job_free(job);
        return NODUS_SC_APPLY_DISCARDED;
    }
    s = conn->sc;
    s->job_out = false;
    *conn_out = conn;

    sj = cmt_p2p_sc_job(&s->m);
    if (sj == NULL || sj->kind != job->kind) {
        QGP_LOG_ERROR(LOG_TAG_SC, "handshake job does not match the machine (slot %d)",
                      conn->slot);
        job_free(job);
        return NODUS_SC_APPLY_FAIL;
    }
    if (job->rc == 0) {
        switch (job->kind) {
        case CMT_P2P_SC_JOB_ENCAPS:
            memcpy(sj->kem_ct_out, job->kem_ct_out, sizeof(job->kem_ct_out));
            memcpy(sj->kem_ss_out, job->kem_ss_out, sizeof(job->kem_ss_out));
            break;
        case CMT_P2P_SC_JOB_DECAPS:
            memcpy(sj->kem_ss_out, job->kem_ss_out, sizeof(job->kem_ss_out));
            break;
        case CMT_P2P_SC_JOB_SIGN:
            memcpy(sj->sig_out, job->sig_out, sizeof(job->sig_out));
            break;
        default:
            break;
        }
    }
    r = cmt_p2p_sc_job_done(&s->m, job->rc);
    job_free(job);
    if (r != CMT_OK)
        return NODUS_SC_APPLY_FAIL;
    if (sc_advance(tcp, conn, s) != 0)
        return NODUS_SC_APPLY_FAIL;
    return NODUS_SC_APPLY_OK;
}

/* ── Enable / queries / free ──────────────────────────────────────────── */

/* A connection the layer may be switched on for: it has carried NO byte in
 * either direction (the sticky io_started — empty buffers prove nothing:
 * bytes may have been consumed and answered), holds no leftover state of the
 * old hello / auth / key_init path, and is not closing. Write lock held. */
static bool conn_eligible(const nodus_tcp_conn_t *conn)
{
    static const uint8_t zero_token[NODUS_SESSION_TOKEN_LEN] = { 0 };

    if (conn->sc != NULL || conn->close_pending || conn->state == NODUS_CONN_CLOSED ||
        conn->is_unix)
        return false;
    if (atomic_load_explicit(&conn->io_started, memory_order_relaxed) ||
        conn->rlen != 0 || conn->wlen != 0 ||
        conn->pending_buf != NULL || conn->pending_count != 0)
        return false;
    if (conn->auth_state != NODUS_CONN_AUTH_NONE || conn->peer_id_set ||
        conn->authenticated || conn->auth_nonce_pending ||
        memcmp(conn->session_token, zero_token, sizeof(zero_token)) != 0)
        return false;
    return true;
}

int nodus_tcp_sc_enable(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                        const nodus_tcp_sc_cfg_t *cfg)
{
    bool eligible;
    nodus_tcp_sc_t *s;
    const uint8_t *kem_pk = NULL;
    const uint8_t *kem_sk = NULL;
    int (*do_sign)(void *, const uint8_t *, size_t, uint8_t *) = NULL;
    int (*do_verify)(void *, const uint8_t *, const uint8_t *, size_t, const uint8_t *) = NULL;

    if (tcp == NULL || conn == NULL || cfg == NULL || cfg->id == NULL)
        return -1;
    sc_lk(tcp, true);
    eligible = conn_eligible(conn);
    sc_lk(tcp, false);
    if (!eligible) {
        QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: connection not eligible (slot %d)", conn->slot);
        return -1;
    }
    if (cfg->profile == &CMT_P2P_SC_PROFILE_CLIENT) {
        do_sign = host_sign_client;
        do_verify = host_verify_client;
    } else if (cfg->profile == &CMT_P2P_SC_PROFILE_NODE) {
        do_sign = host_sign_node;
        do_verify = host_verify_node;
    } else {
        QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: profile is not CLIENT or NODE");
        return -1;
    }
    if (cfg->role == CMT_P2P_SC_ROLE_INITIATOR) {
        /* the dial pin is mandatory: one identity, a set, or both */
        if ((cfg->expected_set == NULL) != (cfg->expected_set_n == 0)) {
            QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: pin set pointer and count disagree");
            return -1;
        }
        if (cfg->expected_peer == NULL &&
            (cfg->expected_set == NULL || cfg->expected_set_n == 0)) {
            QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: initiator without a pin");
            return -1;
        }
    } else if (cfg->role == CMT_P2P_SC_ROLE_RESPONDER) {
        if (!cfg->id->has_mlkem) {
            QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: responder identity has no ML-KEM key");
            return -1;
        }
        kem_pk = cfg->id->mlkem_pk;
        kem_sk = cfg->id->mlkem_sk;
    } else {
        return -1;
    }

    s = (nodus_tcp_sc_t *)calloc(1, sizeof(*s));
    if (s == NULL)
        return -1;
    s->host.ctx = (void *)&cfg->id->sk;
    s->host.sign = do_sign;
    s->host.verify = do_verify;
    s->kem_sk = kem_sk;
    s->cls = cfg->role == CMT_P2P_SC_ROLE_INITIATOR ? 0 : 1;
    s->pre_budget = sc_presession_budget(cfg->role);
    if (cmt_p2p_sc_init_profile(&s->m, cfg->role, &s->host, cfg->profile,
                                cfg->id->pk.bytes, kem_pk, kem_sk,
                                cfg->proto_ver, cfg->chain_id) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: secret connection init failed");
        qgp_secure_memzero(s, sizeof(*s));
        free(s);
        return -1;
    }
    /* Publish under the write lock, re-checking: the checks above ran before
     * the (slow) machine init, and a sender on another thread may have used
     * the connection since. */
    sc_lk(tcp, true);
    eligible = conn_eligible(conn);
#ifndef NODUS_SC_INLINE
    if (eligible && tcp->sc_worker == NULL)
        tcp->sc_worker = worker_start();
    if (eligible && tcp->sc_worker == NULL)
        eligible = false;
#endif
    if (eligible) {
        s->gen = ++tcp->sc_gen_last;
        if (cfg->role == CMT_P2P_SC_ROLE_INITIATOR) {
            if (cfg->expected_peer != NULL) {
                conn->expected_peer_id = *cfg->expected_peer;
                conn->expected_peer_id_set = true;
            }
            s->pin_set = cfg->expected_set;
            s->pin_set_n = cfg->expected_set_n;
        }
        conn->sc = s;
    }
    sc_lk(tcp, false);
    if (!eligible) {
        QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: connection changed or no worker (slot %d)",
                      conn->slot);
        cmt_p2p_sc_clear(&s->m);
        qgp_secure_memzero(s, sizeof(*s));
        free(s);
        return -1;
    }
    /* An INITIATOR's HELLO is now in the machine's out queue: move it to the
     * write buffer (nodus_tcp.c owns the buffers). */
    if (nodus_tcp_sc_flush_hs(tcp, conn) != 0) {
        QGP_LOG_ERROR(LOG_TAG_SC, "enable refused: HELLO not buffered (slot %d)", conn->slot);
        sc_lk(tcp, true);
        nodus_tcp_sc_free(conn);
        conn->expected_peer_id_set = false;
        sc_lk(tcp, false);
        return -1;
    }
    return 0;
}

bool nodus_tcp_sc_authenticated(const nodus_tcp_conn_t *conn)
{
    nodus_tcp_t *tcp = conn ? conn->tcp_parent : NULL;
    bool r;

    if (conn == NULL)
        return false;
    sc_lk(tcp, true);
    r = conn->sc != NULL && cmt_p2p_sc_is_authenticated(&conn->sc->m);
    sc_lk(tcp, false);
    return r;
}

int nodus_tcp_sc_presession_sweep(nodus_tcp_t *tcp, uint64_t now_mono_ms,
                                  uint64_t idle_ms, uint64_t abs_ms)
{
    int closed = 0;

    if (tcp == NULL)
        return 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        bool layer;

        if (c == NULL || c->close_pending || c->auth_initiated_by_us)
            continue;
        sc_lk(tcp, true);
        layer = c->sc != NULL;
        sc_lk(tcp, false);
        if (!layer || nodus_tcp_sc_authenticated(c))
            continue;
        uint64_t idle_for = now_mono_ms > c->last_activity_mono_ms
                          ? now_mono_ms - c->last_activity_mono_ms : 0;
        uint64_t age = now_mono_ms > c->connected_mono_ms
                     ? now_mono_ms - c->connected_mono_ms : 0;
        if (idle_for >= idle_ms || age >= abs_ms) {
            QGP_LOG_WARN(LOG_TAG_SC, "pre-session deadline (slot %d, ip %s): closing",
                         c->slot, c->ip);
            nodus_tcp_disconnect(tcp, c);
            closed++;
        }
    }
    return closed;
}

int nodus_tcp_sc_peer_pubkey(const nodus_tcp_conn_t *conn,
                             uint8_t out[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_tcp_t *tcp = conn ? conn->tcp_parent : NULL;
    int rc = -1;

    if (conn == NULL || out == NULL)
        return -1;
    sc_lk(tcp, true);
    if (conn->sc != NULL && cmt_p2p_sc_is_authenticated(&conn->sc->m)) {
        const uint8_t *pk = cmt_p2p_sc_remote_pubkey(&conn->sc->m);

        if (pk != NULL) {
            memcpy(out, pk, CMT_P2P_SC_DSA_PK_SIZE);   /* a COPY: conn_free wipes the machine */
            rc = 0;
        }
    }
    sc_lk(tcp, false);
    return rc;
}

uint64_t nodus_tcp_sc_send_counter(const nodus_tcp_conn_t *conn)
{
    nodus_tcp_t *tcp = conn ? conn->tcp_parent : NULL;
    uint64_t r = 0;

    if (conn == NULL)
        return 0;
    sc_lk(tcp, true);
    if (conn->sc != NULL)
        r = conn->sc->m.send_counter;
    sc_lk(tcp, false);
    return r;
}

uint64_t nodus_tcp_sc_generation(const nodus_tcp_conn_t *conn)
{
    nodus_tcp_t *tcp = conn ? conn->tcp_parent : NULL;
    uint64_t r = 0;

    if (conn == NULL)
        return 0;
    sc_lk(tcp, true);
    if (conn->sc != NULL)
        r = conn->sc->gen;
    sc_lk(tcp, false);
    return r;
}

bool nodus_tcp_sc_dead(const nodus_tcp_conn_t *conn)
{
    return conn != NULL && conn->sc != NULL && conn->sc->m.state == CMT_P2P_SC_ST_DEAD;
}

void nodus_tcp_sc_free(nodus_tcp_conn_t *conn)
{
    nodus_tcp_sc_t *s = conn ? conn->sc : NULL;

    if (s == NULL)
        return;
    if (s->hold != NULL) {
        qgp_secure_memzero(s->hold, NODUS_TCP_SC_RAW_CHUNK);
        free(s->hold);
    }
    cmt_p2p_sc_clear(&s->m);
    qgp_secure_memzero(s, sizeof(*s));
    free(s);
    conn->sc = NULL;
}

bool nodus_tcp_sc_blocked(const nodus_tcp_conn_t *conn)
{
    const nodus_tcp_sc_t *s = conn ? conn->sc : NULL;

    return s != NULL && (s->job_out || s->hold_len > 0);
}

const uint8_t *nodus_tcp_sc_out(const nodus_tcp_conn_t *conn, size_t *len)
{
    if (len != NULL)
        *len = 0;
    if (conn == NULL || conn->sc == NULL)
        return NULL;
    return cmt_p2p_sc_out(&conn->sc->m, len);
}

void nodus_tcp_sc_out_consume(nodus_tcp_conn_t *conn, size_t n)
{
    if (conn != NULL && conn->sc != NULL)
        cmt_p2p_sc_out_consume(&conn->sc->m, n);
}

bool nodus_tcp_sc_take_ready(nodus_tcp_conn_t *conn)
{
    nodus_tcp_t *tcp = conn ? conn->tcp_parent : NULL;
    bool r = false;

    if (conn == NULL)
        return false;
    /* The machine is read (and the flag cleared) under the lock; the caller
     * invokes on_session AFTER this returns, lock released. */
    sc_lk(tcp, true);
    if (conn->sc != NULL) {
        sc_note_ready(conn->sc);
        r = conn->sc->ready;
        conn->sc->ready = false;
    }
    sc_lk(tcp, false);
    return r;
}

/* ── Feeding bytes in ─────────────────────────────────────────────────── */

static int hold_append(nodus_tcp_sc_t *s, const uint8_t *p, size_t n)
{
    if (n == 0)
        return 0;
    if (s->hold_len + n > NODUS_TCP_SC_RAW_CHUNK)
        return -1;                  /* fail closed: a peer pushing past the bound */
    if (s->hold == NULL) {
        s->hold = (uint8_t *)malloc(NODUS_TCP_SC_RAW_CHUNK);
        if (s->hold == NULL)
            return -1;
    }
    memcpy(s->hold + s->hold_len, p, n);
    s->hold_len += n;
    return 0;
}

static void hold_release(nodus_tcp_sc_t *s)
{
    if (s->hold != NULL) {
        qgp_secure_memzero(s->hold, NODUS_TCP_SC_RAW_CHUNK);
        free(s->hold);
        s->hold = NULL;
    }
    s->hold_len = 0;
}

/* Drive the machine over in[0..inlen). *used = bytes it took. */
static int sc_run(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn, nodus_tcp_sc_t *s,
                  const uint8_t *in, size_t inlen, size_t *used,
                  nodus_tcp_sc_plain_fn plain, void *plain_ctx)
{
    uint8_t pbuf[CMT_P2P_SC_DATA_MAX_SIZE];
    size_t off = 0;
    int ret = 0;

    for (;;) {
        const uint8_t *p = inlen > off ? in + off : NULL;
        size_t consumed = 0;
        int rc;

        if (!cmt_p2p_sc_is_authenticated(&s->m)) {
            bool had_job;

            if (s->job_out)
                break;                                  /* HOLD (header, N1) */
            rc = cmt_p2p_sc_recv(&s->m, p, inlen - off, &consumed);
            off += consumed;
            if (rc != CMT_OK) { ret = -1; break; }
            had_job = cmt_p2p_sc_job(&s->m) != NULL;
            if (sc_advance(tcp, conn, s) != 0) { ret = -1; break; }
            if (s->job_out)
                break;
            if (!had_job && consumed == 0 && !cmt_p2p_sc_is_authenticated(&s->m))
                break;                                  /* needs more bytes */
            continue;
        }

        sc_note_ready(s);
        {
            size_t got = 0;

            rc = cmt_p2p_sc_read(&s->m, p, inlen - off, &consumed, pbuf, sizeof(pbuf), &got);
            off += consumed;
            if (rc != CMT_OK) { ret = -1; break; }
            if (got > 0) {
                if (plain(plain_ctx, pbuf, got) != 0) { ret = -1; break; }
                continue;
            }
            if (consumed == 0)
                break;           /* nothing buffered, nothing more to open */
        }
    }
    qgp_secure_memzero(pbuf, sizeof(pbuf));
    *used = off;
    return ret;
}

int nodus_tcp_sc_feed(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                      const uint8_t *raw, size_t n,
                      nodus_tcp_sc_plain_fn plain, void *plain_ctx)
{
    nodus_tcp_sc_t *s = conn ? conn->sc : NULL;
    const uint8_t *in;
    size_t inlen, used = 0, left;
    bool from_hold = false;

    if (s == NULL || plain == NULL || (raw == NULL && n > 0))
        return -1;
    if (s->job_out)                                     /* cannot take it now */
        return hold_append(s, raw, n);
    if (s->hold_len > 0) {                              /* held bytes come first */
        if (hold_append(s, raw, n) != 0)
            return -1;
        in = s->hold;
        inlen = s->hold_len;
        from_hold = true;
    } else {
        in = raw;
        inlen = n;
    }
    if (sc_run(tcp, conn, s, in, inlen, &used, plain, plain_ctx) != 0)
        return -1;
    /* The pre-session input budget (sc_presession_budget): while the session
     * is not authenticated, only so many bytes may be consumed. */
    if (!s->pre_done) {
        if (cmt_p2p_sc_is_authenticated(&s->m)) {
            s->pre_done = true;
        } else {
            s->pre_bytes += used;
            if (s->pre_bytes > s->pre_budget) {
                QGP_LOG_WARN(LOG_TAG_SC, "pre-session input budget exceeded "
                             "(%zu > %zu bytes, slot %d): closing",
                             s->pre_bytes, s->pre_budget, conn->slot);
                return -1;
            }
        }
    }
    left = inlen - used;
    if (left > 0 && !s->job_out) {
        /* The machine stops early only to HOLD for a job. Anything else left
         * over would stall the connection (nothing reads it again): refuse. */
        QGP_LOG_ERROR(LOG_TAG_SC, "input left over with no job outstanding (slot %d)", conn->slot);
        return -1;
    }
    if (from_hold) {
        if (left > 0) {
            memmove(s->hold, s->hold + used, left);
            s->hold_len = left;
        } else {
            hold_release(s);
        }
    } else if (left > 0) {
        if (hold_append(s, in + used, left) != 0)
            return -1;
    }
    return 0;
}

/* ── Sealing ──────────────────────────────────────────────────────────── */

size_t nodus_tcp_sc_sealed_size(size_t plain_len)
{
    return ((plain_len + CMT_P2P_SC_DATA_MAX_SIZE - 1) / CMT_P2P_SC_DATA_MAX_SIZE) *
           (size_t)CMT_P2P_SC_SEALED_FRAME_SIZE;
}

bool nodus_tcp_sc_can_seal(const nodus_tcp_conn_t *conn, size_t nframes)
{
    const nodus_tcp_sc_t *s = conn ? conn->sc : NULL;

    /* N3 (cmt_p2p_secret.c sc_send_room): the counter can take them all. */
    return s != NULL && cmt_p2p_sc_is_authenticated(&s->m) &&
           (uint64_t)nframes <= UINT64_MAX - s->m.send_counter;
}

int nodus_tcp_sc_seal(nodus_tcp_conn_t *conn,
                      const uint8_t *a, size_t alen,
                      const uint8_t *b, size_t blen,
                      size_t first, size_t nframes, uint8_t *out)
{
    nodus_tcp_sc_t *s = conn ? conn->sc : NULL;
    uint8_t buf[CMT_P2P_SC_DATA_MAX_SIZE];
    size_t total = alen + blen;

    if (s == NULL || out == NULL)
        return -1;
    for (size_t i = 0; i < nframes; i++) {
        size_t pos = (first + i) * CMT_P2P_SC_DATA_MAX_SIZE;
        size_t n, w = 0, got = 0;

        if (pos >= total)
            return -1;
        n = total - pos;
        if (n > CMT_P2P_SC_DATA_MAX_SIZE)
            n = CMT_P2P_SC_DATA_MAX_SIZE;
        /* Gather [pos, pos + n) of a || b. */
        if (pos < alen) {
            size_t from_a = alen - pos < n ? alen - pos : n;

            memcpy(buf, a + pos, from_a);
            got = from_a;
        }
        if (got < n) {
            size_t bpos = pos + got - alen;

            memcpy(buf + got, b + bpos, n - got);
        }
        if (cmt_p2p_sc_write(&s->m, buf, n, out + i * CMT_P2P_SC_SEALED_FRAME_SIZE,
                             CMT_P2P_SC_SEALED_FRAME_SIZE, &w) != CMT_OK ||
            w != CMT_P2P_SC_SEALED_FRAME_SIZE) {
            qgp_secure_memzero(buf, sizeof(buf));
            return -1;
        }
    }
    qgp_secure_memzero(buf, sizeof(buf));
    return 0;
}
