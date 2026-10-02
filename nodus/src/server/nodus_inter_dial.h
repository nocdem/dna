/**
 * Nodus — the DIALER side of the 4002 inter-node handshake, one shared module
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md item 28
 * (approved 2026-10-02: "no new handshake, the existing code moves into a
 * shared module"): the dialer half of the 4002 handshake that used to live
 * inline in core's dispatch_inter moves here, unchanged, so core and the
 * S5 storage process link the SAME code — the CRIT-1 identity pin cannot
 * be lost in a copy. The ACCEPTOR half stays in core.
 *
 * The exchange (dialer's view; every frame is a T2 message):
 *   send  hello(0, pk, node_id)                      nodus_inter_dial_start
 *   recv  challenge(nonce)  → send auth(txn, sign(nonce))
 *   recv  auth_ok(server_pk, kyber_pk, kpk_sig[, mlkem_pk, mpk_sig])
 *         CRIT-1: kpk_sig verifies over (kyber_pk || our challenge nonce)
 *         under server_pk AND fingerprint(server_pk) == the expected peer
 *         identity, or the connection is refused; then KEM-encapsulate
 *         (ML-KEM-1024 when mpk_sig verifies under the same server_pk, else
 *         Kyber round-3) → send key_init(txn, ct, nc, alg)
 *   recv  key_ack(ns)       → channel crypto (INITIATOR) from (ss, nc, ns)
 * A node without a Kyber identity cannot encrypt: at auth_ok it opens the
 * connection in plaintext (established, encrypted = false).
 *
 * The module knows no server, session or transport type: it works on its
 * own per-connection state (nodus_inter_dial_t) and reaches the
 * connection through the callbacks in nodus_inter_dial_io_t. What it does
 * NOT do (the caller's job, before calling it): the role split (only a
 * connection we dialed may receive challenge / auth_ok / key_ack), the
 * pre-session-key gate, and "error" frames.
 *
 * Single-threaded per connection; no clock, no global state.
 *
 * @file nodus_inter_dial.h
 */

#ifndef NODUS_INTER_DIAL_H
#define NODUS_INTER_DIAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus_types.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_channel_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Per-connection dialer state. Zero-initialised = a fresh connection. */
typedef struct {
    /* CRIT-1: the challenge nonce we received and signed, retained so the
     * auth_ok handler can rebuild the message the peer signed
     * (kyber_pk || nonce) and verify its kpk_sig. */
    uint8_t         challenge_nonce[NODUS_NONCE_LEN];
    bool            has_challenge_nonce;

    /* Between key_init (sent) and key_ack (received): the KEM shared secret
     * and our nonce. Zeroed on key_ack. */
    uint8_t         pending_ss[32];
    uint8_t         pending_nc[32];
    bool            pending_kem;

    /* An auth_ok was received (set on receipt, before its checks — exactly
     * as the inline code did; a refused auth_ok ends the connection). */
    bool            authenticated;

    /* The peer's identity once auth_ok passed signature + pin. */
    nodus_key_t     peer_id;
    nodus_pubkey_t  peer_pk;
    bool            peer_id_set;
} nodus_inter_dial_t;

/** What the module needs from the connection, per call. */
typedef struct {
    /** This node's identity (signs the challenge; has_kyber decides whether
     *  the channel is encrypted at all). */
    const nodus_identity_t *identity;
    /** Who we believe we dialed (the routing / roster node_id recorded at
     *  dial time); NULL when none was recorded — refused at auth_ok under
     *  Kyber. Read at each call, not stored: a localhost connect completes
     *  inside the dial, before the dialer records the pin. */
    const nodus_key_t      *expected_peer_id;
    /** The connection's channel crypto, initialised (INITIATOR) at key_ack. */
    nodus_channel_crypto_t *crypto;
    /** For log lines only. */
    const char             *peer_ip;
    uint16_t                peer_port;
    int                     slot;
    /** Write one handshake payload to the peer WITHOUT the send gate (the
     *  gate stays closed until the session key exists). Its result is not
     *  acted on, as before the move. */
    int  (*send_raw)(void *ctx, const uint8_t *payload, size_t len);
    /** The handshake finished: `encrypted` true at key_ack (channel crypto
     *  set), false at auth_ok on a node with no Kyber identity (plaintext).
     *  The caller opens its send gate. */
    void (*established)(void *ctx, bool encrypted);
    void                   *ctx;
} nodus_inter_dial_io_t;

typedef enum {
    /** Not a frame the dialer handshake consumes in this state (a method
     *  other than challenge / auth_ok / key_ack, or key_ack with no key
     *  exchange pending): the caller dispatches it as before. */
    NODUS_INTER_DIAL_NOT_MINE = 0,
    /** Consumed (acted on, or dropped with a log line). */
    NODUS_INTER_DIAL_DONE,
    /** Fail closed (CRIT-1): the caller marks the connection AUTH_FAILED
     *  and disconnects it. */
    NODUS_INTER_DIAL_REFUSED
} nodus_inter_dial_rc_t;

/**
 * Start the handshake on a connection we dialed: encode hello(0, this
 * node's pk, node_id) and write it through io->send_raw.
 * @return 0 hello sent (the caller records HELLO_SENT), -1 it could not be
 *         encoded (nothing sent; the caller records AUTH_FAILED).
 */
int nodus_inter_dial_start(const nodus_inter_dial_io_t *io);

/**
 * Feed one decoded T2 frame received on a connection we dialed.
 * Handles challenge, auth_ok and key_ack (see the file comment); the
 * frames it sends are byte-for-byte those the inline handler sent.
 */
nodus_inter_dial_rc_t nodus_inter_dial_on_frame(nodus_inter_dial_t *d,
                                                const nodus_inter_dial_io_t *io,
                                                const nodus_tier2_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_INTER_DIAL_H */
