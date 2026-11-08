/**
 * 4002 machine host, pin, reject-self, admission gate and bounded worker.
 * Reference: cometbft 94d77f9f51a72e2b7d832798859f6222f08028f8,
 * p2p/transport.go:411-486, conn/secret_connection.go:194-273.
 * Approved PQ substitutions stay in cmt_p2p_secret (ML-KEM-1024,
 * SHA3-512, ML-DSA-87); this file constructs no new crypto or wire format.
 * Job-copy discipline: shared/dnac/cmt_p2p_transport.c:193-281.
 */
#include "server/nodus_inter_session.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __linux__
#include <sys/eventfd.h>
#include <unistd.h>
#endif

#define LOG_TAG "INTER_SESSION"
/* One accept/connect-complete-to-open interval, approved build plan 3.1 g;
 * reference transport.go:22 defaultHandshakeTimeout. */
#define HANDSHAKE_MS 3000u

struct nodus_inter_session_conn {
    cmt_p2p_sc_t sc;
    nodus_inter_session_job_t *job;  /* identity only; never worker dereferenced */
    uint64_t started_ms;
    bool reported;
    bool open;
    bool deadline_counted;
    uint8_t wire[CMT_P2P_SC_HS_MSG_MAX];
    size_t wire_len;
};

struct nodus_inter_session_module {
    nodus_tcp_t *tcp;
    nodus_inter_session_config_t cfg;
    uint32_t proto_ver;              /* resolved from cfg.proto_ver, never 0 */
    nodus_inter_session_stats_t stats;   /* counters; stats under `mu` */
    uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE];
    cmt_p2p_sc_host_t host;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool stop;
    pthread_t *threads;
    unsigned n_threads;
    nodus_inter_session_job_t *head[2], *tail[2];
    size_t queued[2];
    nodus_inter_session_job_t *done_head, *done_tail;
    int wake_fd;
};

void nodus_inter_roles_lookup(const nodus_inter_role_list_t *list,
                              const nodus_key_t *fp, bool *va, bool *st) {
    *va = *st = false;
    if (!list || !fp) return;
    for (size_t i=0;i<list->validator_count;++i)
        if (!nodus_key_cmp(&list->validators[i],fp)) { *va=true; break; }
    for (size_t i=0;i<list->storage_count;++i)
        if (!nodus_key_cmp(&list->storage[i],fp)) { *st=true; break; }
}

size_t nodus_inter_roles_encode(const char *q, const nodus_inter_role_list_t *list,
                                bool ok, uint8_t *buf, size_t cap) {
    if (!q || !buf || !list) return 0;
    if (list->validator_count>DNAC_MAX_VALIDATORS ||
        list->storage_count>DNA_V2_STORAGE_SET_CAP) ok=false;
    cbor_encoder_t e; cbor_encoder_init(&e,buf,cap);
    cbor_encode_map(&e,5);
    cbor_encode_cstr(&e,"q"); cbor_encode_cstr(&e,q);
    cbor_encode_cstr(&e,"ok"); cbor_encode_bool(&e,ok);
    cbor_encode_cstr(&e,"h"); cbor_encode_uint(&e,list->height);
    cbor_encode_cstr(&e,"va"); cbor_encode_array(&e,ok ? list->validator_count : 0);
    if (ok) for (size_t i=0;i<list->validator_count;++i)
        cbor_encode_bstr(&e,list->validators[i].bytes,NODUS_KEY_BYTES);
    cbor_encode_cstr(&e,"st"); cbor_encode_array(&e,ok ? list->storage_count : 0);
    if (ok) for (size_t i=0;i<list->storage_count;++i)
        cbor_encode_bstr(&e,list->storage[i].bytes,NODUS_KEY_BYTES);
    return e.error ? 0 : cbor_encoder_len(&e);
}

int nodus_inter_roles_decode(const char *q, const uint8_t *buf, size_t len,
                             nodus_inter_role_list_t *list, bool *ok) {
    if (!q || !buf || !list || !ok) return -1;
    cbor_decoder_t d; cbor_decoder_init(&d,buf,len);
    cbor_item_t m=cbor_decode_next(&d);
    if (m.type!=CBOR_ITEM_MAP || m.count!=5) return -1;
    unsigned seen=0; *ok=false; memset(list,0,sizeof(*list));
    for (size_t i=0;i<m.count;++i) {
        cbor_item_t k=cbor_decode_next(&d), v=cbor_decode_next(&d);
        if (k.type!=CBOR_ITEM_TSTR) return -1;
        unsigned bit;
        if (k.tstr.len==1 && !memcmp(k.tstr.ptr,"q",1)) {
            bit=1;
            if (v.type!=CBOR_ITEM_TSTR || v.tstr.len!=strlen(q) ||
                memcmp(v.tstr.ptr,q,v.tstr.len)) return -1;
        } else if (k.tstr.len==2 && !memcmp(k.tstr.ptr,"ok",2)) {
            bit=2; if (v.type!=CBOR_ITEM_BOOL) return -1; *ok=v.bool_val;
        } else if (k.tstr.len==1 && !memcmp(k.tstr.ptr,"h",1)) {
            bit=4; if (v.type!=CBOR_ITEM_UINT) return -1; list->height=v.uint_val;
        } else if (k.tstr.len==2 && (!memcmp(k.tstr.ptr,"va",2) || !memcmp(k.tstr.ptr,"st",2))) {
            bool va=!memcmp(k.tstr.ptr,"va",2); bit=va ? 8 : 16;
            size_t max=va ? DNAC_MAX_VALIDATORS : DNA_V2_STORAGE_SET_CAP;
            if (v.type!=CBOR_ITEM_ARRAY || v.count>max) return -1;
            nodus_key_t *entries=va ? list->validators : list->storage;
            if (va) list->validator_count=v.count; else list->storage_count=v.count;
            for (size_t j=0;j<v.count;++j) {
                cbor_item_t item=cbor_decode_next(&d);
                if (item.type!=CBOR_ITEM_BSTR || item.bstr.len!=NODUS_KEY_BYTES) return -1;
                memcpy(entries[j].bytes,item.bstr.ptr,NODUS_KEY_BYTES);
            }
        } else return -1;
        if (seen & bit) return -1;
        seen |= bit;
    }
    if (d.error || d.pos!=len || seen!=31 ||
        (!*ok && (list->validator_count || list->storage_count))) return -1;
    return 0;
}

static bool chain_status(nodus_inter_session_module_t *s) {
    if (!s->cfg.status) return true;
    uint8_t ci[32]; uint64_t height;
    if (!s->cfg.status(s->cfg.admission_ctx, ci, &height)) return false;
    memcpy(s->chain_id, ci, sizeof(s->chain_id));
    return true;
}

bool nodus_inter_session_chain_ready(nodus_inter_session_module_t *s) {
    return s && chain_status(s);
}

static void admit(nodus_inter_session_module_t *s, nodus_tcp_conn_t *conn) {
    nodus_inter_session_conn_t *c = conn->session;
    if (!s->cfg.role || !c->reported) return;
    bool va = false, st = false;
    int rc = s->cfg.role(s->cfg.admission_ctx, &conn->peer_id, &va, &st);
    if (rc != 1 || (!va && !st)) {
        nodus_tcp_disconnect(s->tcp, conn); return;
    }
    if (!c->open && nodus_inter_session_open(conn) == 0)
        QGP_LOG_INFO(LOG_TAG, "4002 authenticated, admitted session slot=%d peer=%s:%u",
                     conn->slot, conn->ip, (unsigned)conn->port);
}

static uint64_t now_ms(const nodus_inter_session_module_t *s) {
    return s->cfg.now_ms ? s->cfg.now_ms(s->cfg.now_ctx) : nodus_time_mono_ms();
}

/* True once the not-open handshake has run past HANDSHAKE_MS. The first time
 * a connection is seen expired it is counted (stats.deadline_closed): every
 * caller closes the connection on a true answer. */
static bool expired(nodus_inter_session_module_t *s, nodus_inter_session_conn_t *c) {
    if (c->open || now_ms(s) - c->started_ms < HANDSHAKE_MS) return false;
    if (!c->deadline_counted) { c->deadline_counted = true; s->stats.deadline_closed++; }
    return true;
}

/* Purpose 0x0A, deliberately independent of net/nodus_p2p_host.c so the
 * storage link never pulls in the 4004 host (storage_linked.cmake:30-43). */
static int sign_auth(void *ctx, const uint8_t *msg, size_t n, uint8_t *out) {
    const nodus_identity_t *id = ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, msg, n, &id->sk);
    if (rc == 0) memcpy(out, sig.bytes, sizeof(sig.bytes));
    qgp_secure_memzero(&sig, sizeof(sig));
    return rc;
}

static int verify_auth(void *ctx, const uint8_t *sig_in, const uint8_t *msg,
                        size_t n, const uint8_t *pk_in) {
    nodus_sig_t sig;
    nodus_pubkey_t pk;
    (void)ctx;
    memcpy(sig.bytes, sig_in, sizeof(sig.bytes));
    memcpy(pk.bytes, pk_in, sizeof(pk.bytes));
    return nodus_verify_session_auth(&sig, msg, n, &pk);
}

static void job_free(nodus_inter_session_job_t *j) {
    if (j) { qgp_secure_memzero(j, sizeof(*j)); free(j); }
}

static nodus_inter_session_job_t *take_locked(nodus_inter_session_module_t *s) {
    /* Outbound jobs never queue behind inbound jobs (transport.h:68-87). */
    for (int q = CMT_P2P_JOB_CLASS_OUTBOUND; q >= CMT_P2P_JOB_CLASS_INBOUND; --q) {
        nodus_inter_session_job_t *j = s->head[q];
        if (!j) continue;
        s->head[q] = j->next;
        if (!s->head[q]) s->tail[q] = NULL;
        s->queued[q]--;
        j->next = NULL;
        return j;
    }
    return NULL;
}

nodus_inter_session_job_t *nodus_inter_session_job_take(nodus_inter_session_module_t *s) {
    if (!s) return NULL;
    pthread_mutex_lock(&s->mu);
    nodus_inter_session_job_t *j = s->stop ? NULL : take_locked(s);
    pthread_mutex_unlock(&s->mu);
    return j;
}

size_t nodus_inter_session_job_queued(nodus_inter_session_module_t *s, bool outbound) {
    if (!s) return 0;
    pthread_mutex_lock(&s->mu);
    size_t n = s->queued[outbound ? CMT_P2P_JOB_CLASS_OUTBOUND : CMT_P2P_JOB_CLASS_INBOUND];
    pthread_mutex_unlock(&s->mu);
    return n;
}

void nodus_inter_session_job_run(nodus_inter_session_job_t *j) {
    if (!j) return;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    j->work.rc = cmt_p2p_sc_job_run(&j->work.job, j->work.sc_host);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* Measurement only: nothing in the session reads these (the load driver,
     * plan 4.5). owner is the module that queued the job; a job taken by hand
     * after the module is gone is not timed. */
    nodus_inter_session_module_t *s = j->owner;
    int k = (int)j->work.kind;
    if (s && k >= 1 && k <= 4) {
        uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000u + (uint64_t)t1.tv_nsec - (uint64_t)t0.tv_nsec;
        pthread_mutex_lock(&s->mu);
        s->stats.job_count[k]++; s->stats.job_ns_total[k] += ns;
        if (ns > s->stats.job_ns_max[k]) s->stats.job_ns_max[k] = ns;
        pthread_mutex_unlock(&s->mu);
    }
}

static void wake(nodus_inter_session_module_t *s) {
#ifdef __linux__
    uint64_t one = 1;
    /* Nonblocking eventfd: EAGAIN means an earlier wake is still pending. */
    ssize_t rc;
    do { rc = write(s->wake_fd, &one, sizeof(one)); } while (rc < 0 && errno == EINTR);
#else
    (void)s;
#endif
}

static void *worker(void *ctx) {
    nodus_inter_session_module_t *s = ctx;
    for (;;) {
        pthread_mutex_lock(&s->mu);
        while (!s->stop && !s->head[0] && !s->head[1]) pthread_cond_wait(&s->cv, &s->mu);
        if (s->stop) { pthread_mutex_unlock(&s->mu); return NULL; }
        nodus_inter_session_job_t *j = take_locked(s);
        pthread_mutex_unlock(&s->mu);
        nodus_inter_session_job_run(j);
        pthread_mutex_lock(&s->mu);
        if (s->done_tail) s->done_tail->next = j;
        else s->done_head = j;
        s->done_tail = j;
        pthread_mutex_unlock(&s->mu);
        wake(s);
    }
}

nodus_inter_session_module_t *nodus_inter_session_new(nodus_tcp_t *tcp,
                                const nodus_inter_session_config_t *cfg) {
    /* proto_ver 0 = the 4002 value the 4002 owners were built with. */
    uint32_t proto = cfg ? (cfg->proto_ver ? cfg->proto_ver : CMT_P2P_SC_PROTO_VER_4002) : 0;
    if (!tcp || !cfg || !cfg->identity ||
        (!cfg->initiator_only && !cfg->identity->has_mlkem) ||
        (proto != CMT_P2P_SC_PROTO_VER_4001 && proto != CMT_P2P_SC_PROTO_VER_4002) ||
        (!cfg->chain_id && !cfg->status) || !cfg->inbound_depth || !cfg->outbound_depth ||
        (cfg->inbound_cap && cfg->inbound_depth < cfg->inbound_cap) ||
        tcp->session_mode || tcp->count || tcp->listen_fd >= 0 ||
        tcp->unix_listen_fd >= 0) return NULL;   /* a WebSocket listener may exist (plan 2.1 f) */
    nodus_inter_session_module_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->tcp = tcp; s->cfg = *cfg; s->wake_fd = -1; s->proto_ver = proto;
    if (cfg->chain_id) memcpy(s->chain_id, cfg->chain_id, sizeof(s->chain_id));
    s->cfg.chain_id = s->chain_id;
    s->host.ctx = (void *)cfg->identity;
    s->host.sign = sign_auth; s->host.verify = verify_auth;
    if (pthread_mutex_init(&s->mu, NULL) != 0) { free(s); return NULL; }
    if (pthread_cond_init(&s->cv, NULL) != 0) {
        pthread_mutex_destroy(&s->mu); free(s); return NULL;
    }
#ifdef __linux__
    s->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (s->wake_fd < 0) { nodus_inter_session_free(s); return NULL; }
#endif
    if (cfg->workers) {
        s->threads = calloc(cfg->workers, sizeof(*s->threads));
        if (!s->threads) { nodus_inter_session_free(s); return NULL; }
        for (; s->n_threads < cfg->workers; ++s->n_threads) {
            if (pthread_create(&s->threads[s->n_threads], NULL, worker, s) != 0) {
                nodus_inter_session_free(s); return NULL;
            }
        }
    }
    if (nodus_tcp_set_session_mode(tcp, s) != 0) { nodus_inter_session_free(s); return NULL; }
    return s;
}

void nodus_inter_session_free(nodus_inter_session_module_t *s) {
    if (!s) return;
    /* Stop every connection before releasing the immutable signing host. */
    if (s->tcp->session_mode == s) {
        for (int i = 0; i < NODUS_TCP_MAX_CONNS; ++i) {
            nodus_tcp_conn_t *c = s->tcp->pool[i];
            if (c && c->session) nodus_tcp_disconnect(s->tcp, c);
        }
        s->tcp->session_mode = NULL;
    }
    pthread_mutex_lock(&s->mu);
    s->stop = true; pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    for (unsigned i = 0; i < s->n_threads; ++i) pthread_join(s->threads[i], NULL);
    for (int q = 0; q < 2; ++q) {
        nodus_inter_session_job_t *j = s->head[q];
        while (j) { nodus_inter_session_job_t *next = j->next; job_free(j); j = next; }
    }
    nodus_inter_session_job_t *j = s->done_head;
    while (j) { nodus_inter_session_job_t *next = j->next; job_free(j); j = next; }
#ifdef __linux__
    if (s->wake_fd >= 0) close(s->wake_fd);
#endif
    free(s->threads);
    pthread_cond_destroy(&s->cv); pthread_mutex_destroy(&s->mu);
    qgp_secure_memzero(s, sizeof(*s)); free(s);
}

void nodus_inter_session_stats(nodus_inter_session_module_t *s, nodus_inter_session_stats_t *out) {
    memset(out, 0, sizeof(*out));
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    *out = s->stats;
    pthread_mutex_unlock(&s->mu);
}

int nodus_inter_session_wake_fd(const nodus_inter_session_module_t *s) {
    return s ? s->wake_fd : -1;
}

void nodus_inter_session_wake_owner(nodus_inter_session_module_t *s) {
    if (s) wake(s);
}

/* Test seam (config.machine_hook): the entry of a machine-touching function. */
static void machine_hook(const nodus_inter_session_module_t *s) {
    if (s && s->cfg.machine_hook) s->cfg.machine_hook(s->cfg.machine_hook_ctx);
}

int nodus_inter_session_start(nodus_tcp_conn_t *conn) {
    nodus_inter_session_module_t *s = conn->tcp_parent->session_mode;
    machine_hook(s);
    if (!s || conn->is_unix || conn->session) return -1;
    /* An outbound connection needs a non-empty trusted list (D4); an
     * initiator-only module (a client) never takes an inbound one. */
    if (conn->auth_initiated_by_us ? (!conn->trusted_ids || !conn->trusted_count)
                                   : s->cfg.initiator_only) return -1;
    if (!chain_status(s)) return -1;
    if (!conn->auth_initiated_by_us && s->cfg.inbound_cap) {
        unsigned pending = 0;
        for (int i = 0; i < NODUS_TCP_MAX_CONNS; ++i) {
            nodus_tcp_conn_t *other = s->tcp->pool[i];
            if (!other || other == conn || other->close_pending ||
                other->auth_initiated_by_us || nodus_inter_session_is_open(other)) continue;
            pending++;
            if (!s->cfg.allow_duplicate_ip && strcmp(other->ip, conn->ip) == 0) return -1;
        }
        if (pending >= s->cfg.inbound_cap) return -1;
    }
    nodus_inter_session_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    pthread_mutex_lock(&s->mu); s->stats.started++; pthread_mutex_unlock(&s->mu);
    conn->session = c;
    c->started_ms = now_ms(s);
    bool outbound = conn->auth_initiated_by_us;
    if (cmt_p2p_sc_init(&c->sc, outbound ? CMT_P2P_SC_ROLE_INITIATOR : CMT_P2P_SC_ROLE_RESPONDER,
          &s->host, s->cfg.identity->pk.bytes,
          outbound ? NULL : s->cfg.identity->mlkem_pk,
          outbound ? NULL : s->cfg.identity->mlkem_sk,
          s->proto_ver, s->chain_id) != CMT_OK) return -1;
    size_t n; const uint8_t *out = cmt_p2p_sc_out(&c->sc, &n);
    if (n && nodus_tcp_session_queue_wire(conn, out, n) != 0) return -1;
    cmt_p2p_sc_out_consume(&c->sc, n);
    return 0;
}

void nodus_inter_session_clear(nodus_tcp_conn_t *conn) {
    if (!conn || !conn->session) return;
    cmt_p2p_sc_clear(&conn->session->sc);
    qgp_secure_memzero(conn->session, sizeof(*conn->session)); free(conn->session); conn->session = NULL;
}

/* Any listed fingerprint is trusted (D3). A 4002 dial is a list of one. */
static bool pin_matches(nodus_tcp_conn_t *conn, const uint8_t *remote) {
    nodus_pubkey_t pk; nodus_key_t fp;
    if (!remote || !conn->trusted_ids || !conn->trusted_count) return false;
    memcpy(pk.bytes, remote, sizeof(pk.bytes));
    if (nodus_fingerprint(&pk, &fp) != 0) return false;
    for (size_t i = 0; i < conn->trusted_count; ++i)
        if (nodus_key_cmp(&fp, &conn->trusted_ids[i]) == 0) return true;
    return false;
}

int nodus_inter_session_submit(nodus_tcp_conn_t *conn) {
    nodus_inter_session_conn_t *c = conn->session;
    nodus_inter_session_module_t *s = conn->tcp_parent->session_mode;
    machine_hook(s);
    const cmt_p2p_sc_job_t *sj = cmt_p2p_sc_job(&c->sc);
    if (!sj || c->job) return CMT_OK;
    if (sj->kind == CMT_P2P_SC_JOB_ENCAPS &&
        !pin_matches(conn, cmt_p2p_sc_remote_pubkey(&c->sc))) {
        cmt_p2p_sc_abort(&c->sc);
        QGP_LOG_WARN(LOG_TAG, "dial identity mismatch before encapsulation, slot=%d", conn->slot);
        return CMT_REJECT;
    }
    nodus_inter_session_job_t *j = calloc(1, sizeof(*j));
    if (!j) return CMT_FAULT;
    cmt_p2p_hs_job_t *w = &j->work;
    j->owner = s;
    w->slot = conn->slot; w->gen = conn->generation;
    w->job_class = conn->auth_initiated_by_us ? CMT_P2P_JOB_CLASS_OUTBOUND : CMT_P2P_JOB_CLASS_INBOUND;
    w->kind = w->job.kind = sj->kind; w->sc_host = &s->host;
    switch (sj->kind) {
    case CMT_P2P_SC_JOB_ENCAPS:
        memcpy(w->kem_pk, sj->kem_pk, sizeof(w->kem_pk));
        w->job.kem_pk = w->kem_pk; w->job.kem_ct_out = w->kem_ct_out;
        w->job.kem_ss_out = w->kem_ss_out;
        break;
    case CMT_P2P_SC_JOB_DECAPS:
        memcpy(w->kem_ct, sj->kem_ct, sizeof(w->kem_ct));
        memcpy(j->kem_sk, sj->kem_sk, sizeof(j->kem_sk));
        w->job.kem_ct = w->kem_ct; w->job.kem_sk = j->kem_sk;
        w->job.kem_ss_out = w->kem_ss_out;
        break;
    case CMT_P2P_SC_JOB_SIGN:
    case CMT_P2P_SC_JOB_VERIFY:
        if (sj->msg_len > sizeof(w->msg)) { job_free(j); return CMT_FAULT; }
        memcpy(w->msg, sj->msg, sj->msg_len);
        w->job.msg = w->msg; w->job.msg_len = w->msg_len = sj->msg_len;
        if (sj->kind == CMT_P2P_SC_JOB_SIGN) w->job.sig_out = w->sig_out;
        else {
            memcpy(w->dsa_pk, sj->dsa_pk, sizeof(w->dsa_pk));
            memcpy(w->sig, sj->sig, sizeof(w->sig));
            w->job.dsa_pk = w->dsa_pk; w->job.sig = w->sig;
        }
        break;
    default: job_free(j); return CMT_FAULT;
    }
    int q = w->job_class;
    size_t depth = q == CMT_P2P_JOB_CLASS_INBOUND ? s->cfg.inbound_depth : s->cfg.outbound_depth;
    pthread_mutex_lock(&s->mu);
    if (s->stop || s->queued[q] >= depth) {
        if (!s->stop) s->stats.queue_refused++;
        pthread_mutex_unlock(&s->mu); job_free(j); return CMT_REJECT;
    }
    c->job = j;
    if (s->tail[q]) s->tail[q]->next = j; else s->head[q] = j;
    s->tail[q] = j; s->queued[q]++;
    pthread_cond_signal(&s->cv); pthread_mutex_unlock(&s->mu);
    return CMT_OK;
}

int nodus_inter_session_job_done(nodus_inter_session_module_t *s, nodus_inter_session_job_t *j) {
    if (!s || !j) { job_free(j); return CMT_FAULT; }
    machine_hook(s);
    cmt_p2p_hs_job_t *w = &j->work;
    nodus_tcp_conn_t *conn = w->slot >= 0 && w->slot < NODUS_TCP_MAX_CONNS ? s->tcp->pool[w->slot] : NULL;
    if (!conn || conn->generation != w->gen || !conn->session || conn->session->job != j) {
        job_free(j); return CMT_REJECT;
    }
    nodus_inter_session_conn_t *c = conn->session;
    c->job = NULL;
    const cmt_p2p_sc_job_t *sj = cmt_p2p_sc_job(&c->sc);
    int rc = CMT_FAULT;
    if (sj && sj->kind == w->kind && !expired(s, c)) {
        if (w->rc == 0) {
            if (sj->kem_ct_out) memcpy(sj->kem_ct_out, w->kem_ct_out, sizeof(w->kem_ct_out));
            if (sj->kem_ss_out) memcpy(sj->kem_ss_out, w->kem_ss_out, sizeof(w->kem_ss_out));
            if (sj->sig_out) memcpy(sj->sig_out, w->sig_out, sizeof(w->sig_out));
        }
        rc = cmt_p2p_sc_job_done(&c->sc, w->rc);
    }
    job_free(j);
    if (rc != CMT_OK) {
        cmt_p2p_sc_abort(&c->sc); nodus_tcp_disconnect(s->tcp, conn);
    } else nodus_tcp_session_resume(conn);
    return rc;
}

void nodus_inter_session_poll(nodus_inter_session_module_t *s) {
    if (!s) return;
    machine_hook(s);
    bool known = chain_status(s);
#ifdef __linux__
    uint64_t value;
    while (read(s->wake_fd, &value, sizeof(value)) < 0 && errno == EINTR) {}
#endif
    if (!s->cfg.workers && s->cfg.run_jobs_inline) {
        /* The owner is the only thread: run each queued job here, on the
         * owner's loop, and complete it as a worker's result would. */
        nodus_inter_session_job_t *queued;
        while ((queued = nodus_inter_session_job_take(s)) != NULL) {
            nodus_inter_session_job_run(queued);
            nodus_inter_session_job_done(s, queued);
        }
    }
    pthread_mutex_lock(&s->mu);
    nodus_inter_session_job_t *j = s->done_head;
    s->done_head = s->done_tail = NULL;
    pthread_mutex_unlock(&s->mu);
    while (j) {
        nodus_inter_session_job_t *next = j->next;
        nodus_inter_session_job_done(s, j); j = next;
    }
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; ++i) {
        nodus_tcp_conn_t *conn = s->tcp->pool[i];
        if (conn && conn->session && known && s->cfg.role) admit(s, conn);
        conn = s->tcp->pool[i];
        /* A transport with a write lock only queues plaintext from sender
         * threads; this owner pass seals it, in send order. */
        if (conn && conn->session && conn->session->open && s->tcp->write_lock &&
            nodus_tcp_pending_flush(conn) != 0) {
            cmt_p2p_sc_abort(&conn->session->sc);
            nodus_tcp_disconnect(s->tcp, conn);
            continue;
        }
        if (conn && conn->session &&
            (conn->session->sc.state == CMT_P2P_SC_ST_DEAD || expired(s, conn->session))) {
            cmt_p2p_sc_abort(&conn->session->sc);
            nodus_tcp_disconnect(s->tcp, conn);
        }
    }
}

int nodus_inter_session_poll_timeout(nodus_inter_session_module_t *s, int timeout_ms) {
    if (!s) return timeout_ms;
    uint64_t now = now_ms(s);
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; ++i) {
        nodus_tcp_conn_t *conn = s->tcp->pool[i];
        if (!conn || !conn->session || conn->session->open) continue;
        uint64_t elapsed = now - conn->session->started_ms;
        int left = elapsed >= HANDSHAKE_MS ? 0 : (int)(HANDSHAKE_MS - elapsed);
        if (timeout_ms < 0 || left < timeout_ms) timeout_ms = left;
    }
    /* The owner also has the pollable wake. Until it registers it, avoid
     * sleeping across completed work already in the result queue. */
    pthread_mutex_lock(&s->mu);
    if (s->done_head) timeout_ms = 0;
    pthread_mutex_unlock(&s->mu);
    return timeout_ms;
}

bool nodus_inter_session_is_open(const nodus_tcp_conn_t *conn) {
    return conn && conn->session && conn->session->open;
}

int nodus_inter_session_open(nodus_tcp_conn_t *conn) {
    if (!conn || conn->close_pending || !conn->session) return -1;
    nodus_inter_session_conn_t *c = conn->session;
    nodus_inter_session_module_t *s = conn->tcp_parent->session_mode;
    machine_hook(s);
    if (!c->reported || !cmt_p2p_sc_is_authenticated(&c->sc)) return -1;
    if (expired(s, c)) {
        cmt_p2p_sc_abort(&c->sc); nodus_tcp_disconnect(s->tcp, conn); return -1;
    }
    if (c->open) return 0;
    c->open = true;
    {   /* measurement only (plan 4.5): accept-to-open time at the node */
        uint64_t t = now_ms(s) - c->started_ms;
        uint64_t b = t / NODUS_INTER_OPEN_BUCKET_MS;
        if (b >= NODUS_INTER_OPEN_BUCKETS) b = NODUS_INTER_OPEN_BUCKETS - 1;
        pthread_mutex_lock(&s->mu);
        s->stats.opened++;
        s->stats.open_ms_total += t;
        if (t > s->stats.open_ms_max) s->stats.open_ms_max = t;
        s->stats.open_hist[b]++;
        pthread_mutex_unlock(&s->mu);
    }
    conn->auth_state = NODUS_CONN_AUTH_OK;
    if (nodus_tcp_pending_flush(conn) != 0) {
        cmt_p2p_sc_abort(&c->sc); nodus_tcp_disconnect(s->tcp, conn); return -1;
    }
    nodus_tcp_session_resume(conn);
    return 0;
}

uint8_t *nodus_inter_session_read_buf(nodus_tcp_conn_t *conn, size_t *room) {
    nodus_inter_session_conn_t *c = conn->session;
    *room = 0;
    if (!c || conn->close_pending || (c->reported && !c->open)) return NULL;
    *room = sizeof(c->wire) - c->wire_len;
    return c->wire + c->wire_len;
}

void nodus_inter_session_read_done(nodus_tcp_conn_t *conn, size_t n) {
    nodus_inter_session_conn_t *c = conn->session;
    if (n > sizeof(c->wire) - c->wire_len) cmt_p2p_sc_abort(&c->sc);
    else c->wire_len += n;
}

int nodus_inter_session_read(nodus_tcp_conn_t *conn, uint8_t *plain, size_t cap, size_t *n) {
    nodus_inter_session_conn_t *c = conn->session;
    nodus_inter_session_module_t *s = conn->tcp_parent->session_mode;
    machine_hook(s);
    *n = 0;
    for (;;) {
        if (expired(s, c)) return CMT_REJECT;
        size_t used = 0;
        int rc;
        if (!cmt_p2p_sc_is_authenticated(&c->sc))
            rc = cmt_p2p_sc_recv(&c->sc, c->wire, c->wire_len, &used);
        else rc = CMT_OK;
        if (rc != CMT_OK) return rc;
        if (used) { c->wire_len -= used; memmove(c->wire, c->wire + used, c->wire_len); }
        size_t out_n; const uint8_t *out = cmt_p2p_sc_out(&c->sc, &out_n);
        if (out_n && nodus_tcp_session_queue_wire(conn, out, out_n) != 0) return CMT_FAULT;
        cmt_p2p_sc_out_consume(&c->sc, out_n);
        rc = nodus_inter_session_submit(conn);
        if (rc != CMT_OK) return rc;
        if (!cmt_p2p_sc_is_authenticated(&c->sc)) return CMT_OK;
        if (!c->reported) {
            const uint8_t *remote = cmt_p2p_sc_remote_pubkey(&c->sc);
            if (!remote || (conn->auth_initiated_by_us && !pin_matches(conn, remote)) ||
                memcmp(remote, s->cfg.identity->pk.bytes, NODUS_PK_BYTES) == 0) return CMT_REJECT;
            memcpy(conn->peer_pk.bytes, remote, NODUS_PK_BYTES);
            if (nodus_fingerprint(&conn->peer_pk, &conn->peer_id) != 0) return CMT_FAULT;
            conn->peer_id_set = true; conn->authenticated = true;
            c->reported = true;
            if (s->cfg.on_authenticated) s->cfg.on_authenticated(conn, &conn->peer_pk, s->cfg.auth_ctx);
            if (conn->close_pending) return CMT_REJECT;
            if (s->cfg.role) admit(s, conn);
            if (conn->close_pending) return CMT_REJECT;
        }
        if (!c->open) return CMT_OK;
        used = 0;
        rc = cmt_p2p_sc_read(&c->sc, c->wire, c->wire_len, &used, plain, cap, n);
        if (rc != CMT_OK) { conn->decrypt_skip_count++; return rc; }
        if (used) { c->wire_len -= used; memmove(c->wire, c->wire + used, c->wire_len); }
        if (*n || !used) return CMT_OK;
        /* A legal empty sealed frame can consume input without plaintext.
         * Continue only over the bounded bytes already in wire. */
    }
}

int nodus_inter_session_seal(nodus_tcp_conn_t *conn, const uint8_t *plain,
                             size_t n, uint8_t *out, size_t cap, size_t *written) {
    if (!nodus_inter_session_is_open(conn)) return CMT_REJECT;
    machine_hook(conn->tcp_parent->session_mode);
    int rc = cmt_p2p_sc_write(&conn->session->sc, plain, n, out, cap, written);
    if (rc != CMT_OK) cmt_p2p_sc_abort(&conn->session->sc);
    return rc;
}
