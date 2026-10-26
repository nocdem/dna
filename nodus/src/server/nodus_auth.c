/**
 * Nodus — client session start (4001 / WebSocket)
 *
 * The client authenticates inside the SecretConnection (nodus_tcp_sc.h,
 * CLIENT profile, purpose 0x0C): both ends prove their ML-DSA-87 key in the
 * handshake. What the old T2 exchange did around that proof — hello,
 * challenge, auth, auth_ok with the KEM keys, key_init, key_ack and the
 * channel crypto it set up — is gone (DHT v2 3b-2, Kurultay #43 O-1). What
 * the server did when the AUTH signature verified is done in
 * nodus_auth_session_start, when the layer reports AUTHENTICATED.
 */

#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp_sc.h"

#include <string.h>
#include <stdio.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ── Sessions of one identity (nodus_server.h) ───────────────────── */

static bool session_live_as(const nodus_session_t *s, const nodus_key_t *fp) {
    /* An ANON session has no identity (its client_fp is zero, not "the zero
     * identity"): it is never one of any identity's sessions. */
    return s->authenticated && !s->anonymous && s->conn != NULL &&
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

/* ── The session starts ───────────────────────────────────────────── */

_Static_assert(sizeof(((nodus_pubkey_t *)0)->bytes) == CMT_P2P_SC_DSA_PK_SIZE,
               "nodus_pubkey_t must be the SecretConnection's key size");

int nodus_auth_session_start(nodus_server_t *srv, nodus_session_t *sess) {
    if (!srv || !sess || !sess->conn) return -1;

    /* ANON (no-login wallet session, design 2026-10-26-dht-v2-3d-no-login-
     * design.md §2): the layer proved the SERVER to the client, not the client
     * to the server — there is no client key (nodus_tcp_sc_peer_pubkey would
     * fail) and so no principal. No client_pk / client_fp, peer_id_set stays
     * false (the witness reads "no principal" from it), no per-identity
     * eviction, no presence, no role exemption (the caller's has_role needs
     * peer_id_set). The token is still minted and sent. */
    if (nodus_tcp_sc_is_anonymous(sess->conn)) {
        nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);
        sess->anonymous = true;
        sess->authenticated = true;
        sess->conn->authenticated = true;
        sess->auth_seq = ++srv->next_auth_seq;

        uint8_t abuf[256];
        size_t alen = 0;
        if (nodus_t2_auth_ok(0, sess->token, abuf, sizeof(abuf), &alen) != 0)
            return -1;
        return nodus_tcp_send(sess->conn, abuf, alen) == 0 ? 0 : -1;
    }

    /* The identity the layer proved. A copy of the key (the layer's own
     * storage is wiped with the machine), its fingerprint is the node-local
     * "who" of this connection. */
    uint8_t pkb[CMT_P2P_SC_DSA_PK_SIZE];
    if (nodus_tcp_sc_peer_pubkey(sess->conn, pkb) != 0) return -1;
    memcpy(sess->client_pk.bytes, pkb, sizeof(sess->client_pk.bytes));
    if (nodus_fingerprint(&sess->client_pk, &sess->client_fp) != 0) return -1;

    /* Authenticated — generate the session token (a correlation key only:
     * identity is the connection, O-2 b). */
    nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);
    sess->authenticated = true;

    /* Set peer identity on connection */
    sess->conn->peer_id = sess->client_fp;
    sess->conn->peer_pk = sess->client_pk;
    sess->conn->peer_id_set = true;
    sess->conn->authenticated = true;

    sess->auth_seq = ++srv->next_auth_seq;

    /* Per-identity session limit (NODUS_MAX_SESSIONS_PER_IDENTITY, see
     * nodus_server.h): keep this session and the 3 most recently
     * authenticated others of the same identity; disconnect the older
     * ones. Ghost connections of dead mobile sockets (alive until the 30 s
     * idle sweep notices) are the oldest sessions of their identity, so a
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

    /* The token message: the first sealed frame, T2 auth_ok (txn 0) with the
     * token and nothing else (no KEM fields: the layer has done the key
     * exchange). */
    uint8_t buf[256];
    size_t len = 0;
    if (nodus_t2_auth_ok(0, sess->token, buf, sizeof(buf), &len) != 0)
        return -1;
    return nodus_tcp_send(sess->conn, buf, len) == 0 ? 0 : -1;
}
