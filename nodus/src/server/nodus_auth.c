/**
 * Nodus — client session identity (ports 4001 and the WebSocket entry)
 *
 * The secret-connection handshake (shared/dnac/cmt_p2p_secret, hosted by
 * server/nodus_inter_session.c) authenticates the client key. This file is
 * what the node does with that key: it becomes the session identity, the
 * per-identity session limit is applied and presence is added. The T2
 * hello / challenge / auth / auth_ok / key_init / key_ack path that stood
 * here is gone (approved 4001 plan 2.2 c; decisions D6, A6).
 */

#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"

#include <string.h>
#include <stdio.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ── Sessions of one identity (nodus_server.h) ───────────────────── */

static bool session_live_as(const nodus_session_t *s, const nodus_key_t *fp) {
    return s->authenticated && s->conn != NULL &&
           nodus_key_cmp(&s->client_fp, fp) == 0;
}

int nodus_sessions_count_fp(const nodus_session_t *sessions, int n,
                            const nodus_key_t *fp,
                            const nodus_session_t *exclude) {
    if (!sessions || !fp) return 0;
    int count = 0;
    for (int i = 0; i < n; i++) {
        if (&sessions[i] == exclude) continue;
        if (session_live_as(&sessions[i], fp)) count++;
    }
    return count;
}

nodus_session_t *nodus_sessions_newest_fp(nodus_session_t *sessions, int n,
                                          const nodus_key_t *fp) {
    if (!sessions || !fp) return NULL;
    nodus_session_t *best = NULL;
    for (int i = 0; i < n; i++) {
        nodus_session_t *s = &sessions[i];
        if (!session_live_as(s, fp)) continue;
        if (!best || s->auth_seq > best->auth_seq) best = s;
    }
    return best;
}

int nodus_sessions_evict_plan(const nodus_session_t *sessions, int n,
                              const nodus_session_t *keep,
                              int max_per_identity,
                              int *slots_out, int cap) {
    if (!sessions || !keep || !slots_out || cap <= 0 || max_per_identity < 1)
        return 0;
    const nodus_key_t *fp = &keep->client_fp;
    /* keep counts as one of the max_per_identity, whatever its state */
    int excess = nodus_sessions_count_fp(sessions, n, fp, keep) -
                 (max_per_identity - 1);
    int out = 0;
    /* Pick the oldest remaining one each round: at most `excess` rounds of
     * one pass each. auth_seq values are unique (one counter), so the
     * order is total; the slot index breaks a tie that cannot occur. */
    uint64_t floor_seq = 0;
    int floor_slot = -1;
    while (excess > 0 && out < cap) {
        int pick = -1;
        for (int i = 0; i < n; i++) {
            const nodus_session_t *s = &sessions[i];
            if (s == keep || !session_live_as(s, fp)) continue;
            /* strictly after the previous pick in (auth_seq, slot) order */
            if (floor_slot >= 0 &&
                (s->auth_seq < floor_seq ||
                 (s->auth_seq == floor_seq && i <= floor_slot)))
                continue;
            if (pick < 0 || s->auth_seq < sessions[pick].auth_seq ||
                (s->auth_seq == sessions[pick].auth_seq && i < pick))
                pick = i;
        }
        if (pick < 0) break;
        slots_out[out++] = pick;
        floor_seq = sessions[pick].auth_seq;
        floor_slot = pick;
        excess--;
    }
    return out;
}

int nodus_auth_session_authenticated(nodus_server_t *srv, nodus_session_t *sess,
                                     const nodus_pubkey_t *pk) {
    if (!srv || !sess || !sess->conn || !pk) return -1;

    /* The authenticated key is the session identity. */
    sess->client_pk = *pk;
    if (nodus_fingerprint(pk, &sess->client_fp) != 0) return -1;

    /* A random server-side token. It is never sent and never compared with
     * anything a client sends (A6); it is only the handle the witness.sock
     * preface and the delayed cc_collect reply lookup use. */
    if (nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN) != 0) return -1;
    sess->authenticated = true;

    sess->auth_seq = ++srv->next_auth_seq;

    /* Per-identity session limit (NODUS_MAX_SESSIONS_PER_IDENTITY, see
     * nodus_server.h): keep this session and the 3 most recently
     * authenticated others of the same identity; disconnect the older
     * ones. Ghost connections of dead mobile sockets (alive until the idle
     * sweep notices) are the oldest sessions of their identity, so a
     * reconnecting device still clears its own ghost once the limit is
     * reached. The plan is taken first: each disconnect runs
     * on_tcp_disconnect, which clears only that session. */
    {
        int victims[NODUS_MAX_SESSIONS];
        int nv = nodus_sessions_evict_plan(srv->sessions, NODUS_MAX_SESSIONS,
                                           sess, NODUS_MAX_SESSIONS_PER_IDENTITY,
                                           victims, NODUS_MAX_SESSIONS);
        for (int v = 0; v < nv; v++) {
            nodus_session_t *old = &srv->sessions[victims[v]];
            if (!old->conn) continue;
            char old_fp[33];
            for (int k = 0; k < 16; k++)
                snprintf(old_fp + k*2, sizeof(old_fp) - k*2, "%02x", old->client_fp.bytes[k]);
            old_fp[32] = '\0';
            fprintf(stderr, "SESSION_EVICT: old slot=%d ip=%s fp=%s... auth_seq=%llu "
                    "(rule: max %d sessions per identity, oldest out; new slot=%d)\n",
                    old->conn->slot, old->conn->ip, old_fp,
                    (unsigned long long)old->auth_seq,
                    NODUS_MAX_SESSIONS_PER_IDENTITY, sess->conn->slot);
            nodus_tcp_disconnect(&srv->tcp, old->conn);
            old->conn = NULL;
            old->authenticated = false;
        }
    }

    /* Track presence */
    nodus_presence_add_local(srv, &sess->client_fp);
    {
        char fp_hex[33];
        for (int k = 0; k < 16; k++)
            snprintf(fp_hex + k*2, sizeof(fp_hex) - k*2, "%02x", sess->client_fp.bytes[k]);
        fp_hex[32] = '\0';
        fprintf(stderr, "AUTH_OK: client %s... authenticated (presence added)\n", fp_hex);
    }
    return 0;
}
