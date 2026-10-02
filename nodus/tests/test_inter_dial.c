/**
 * Nodus — the shared 4002 DIALER handshake module (component split S5a,
 * decision 2026-10-01-nodus-component-split item 28).
 *
 * server/nodus_inter_dial.{h,c} is the dialer half of the 4002 handshake
 * moved out of core's dispatch_inter so core and the S5 storage process
 * link one copy. This drives it against an in-memory peer: the test plays
 * the ACCEPTOR by hand with the public nodus_t2_* encoders and the peer's
 * own keys (seeded identities), and captures what the module sends through
 * its send_raw callback. No socket, no server, no clock.
 *
 * Pins down:
 *   1. Full exchange with an ML-KEM-capable peer and the correct pin:
 *      hello carries this node's pk; the auth answers the challenge (it
 *      verifies under this node's pk, with the challenge's txn id); auth_ok
 *      with valid kpk_sig + mpk_sig → key_init with alg 1 whose ciphertext
 *      the PEER decapsulates to the module's pending secret; key_ack →
 *      established(encrypted) and a channel key equal to the peer's (a
 *      frame the dialer encrypts, the peer's responder state decrypts);
 *      the proven peer identity is recorded.
 *   2. Kyber-only peer (no mpk in auth_ok): key_init alg 0, decapsulated
 *      by the peer's Kyber round-3 key.
 *   3. Refusals (CRIT-1), each from a fresh state, each REFUSED with no
 *      key_init sent and no peer identity recorded:
 *        - wrong identity pinned (fingerprint(server_pk) != expected);
 *        - no expected identity at all;
 *        - kpk_sig not over (kyber_pk || our nonce) — one bit flipped;
 *        - downgrade: a plain auth_ok without kyber_pk / kpk_sig / server_pk.
 *   4. Edges kept from the inline code: a repeated challenge is not signed
 *      again; key_ack with no key exchange pending is NOT_MINE (the caller
 *      dispatches it as before); a node without a Kyber identity opens the
 *      connection in plaintext at auth_ok (established, encrypted=false).
 *
 * Byte identity with the pre-move code is NOT asserted here: sig, ct and
 * nc are randomised per run. It is a property of the diff (same encoder
 * calls, same arguments) — see the S5a commit message.
 *
 * Requires: default build. Leaves behind: nothing.
 * RED on the tree before S5a: server/nodus_inter_dial.h does not exist.
 */

#include "server/nodus_inter_dial.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-62s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t id_dialer, id_peer, id_other;
static uint8_t frame[16384];

/* ── What the module sends / reports ──────────────────────────────── */

typedef struct {
    int     sends;
    uint8_t last[16384];
    size_t  last_len;
    int     established_calls;
    bool    established_encrypted;
} capture_t;

static int cap_send(void *ctx, const uint8_t *p, size_t len) {
    capture_t *c = ctx;
    c->sends++;
    c->last_len = len < sizeof(c->last) ? len : sizeof(c->last);
    memcpy(c->last, p, c->last_len);
    return 0;
}

static void cap_established(void *ctx, bool encrypted) {
    capture_t *c = ctx;
    c->established_calls++;
    c->established_encrypted = encrypted;
}

static void io_init(nodus_inter_dial_io_t *io, capture_t *cap,
                    nodus_channel_crypto_t *cc, const nodus_identity_t *self,
                    const nodus_key_t *expected) {
    memset(io, 0, sizeof(*io));
    io->identity = self;
    io->expected_peer_id = expected;
    io->crypto = cc;
    io->peer_ip = "10.9.9.9";
    io->peer_port = 4002;
    io->slot = 3;
    io->send_raw = cap_send;
    io->established = cap_established;
    io->ctx = cap;
}

/* Decode `len` bytes of `buf` and feed them to the module. */
static nodus_inter_dial_rc_t feed(nodus_inter_dial_t *d, const nodus_inter_dial_io_t *io,
                                  const uint8_t *buf, size_t len) {
    nodus_tier2_msg_t *m = calloc(1, sizeof(*m));
    if (!m) return (nodus_inter_dial_rc_t)-1;
    if (nodus_t2_decode(buf, len, m) != 0) { free(m); return (nodus_inter_dial_rc_t)-1; }
    nodus_inter_dial_rc_t rc = nodus_inter_dial_on_frame(d, io, m);
    nodus_t2_msg_free(m);
    free(m);
    return rc;
}

/* The decode of the module's last send (caller frees with msg_free + free). */
static nodus_tier2_msg_t *last_sent(const capture_t *cap) {
    nodus_tier2_msg_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    if (nodus_t2_decode(cap->last, cap->last_len, m) != 0) { free(m); return NULL; }
    return m;
}

static void msg_drop(nodus_tier2_msg_t *m) {
    if (!m) return;
    nodus_t2_msg_free(m);
    free(m);
}

/* The peer's auth_ok for challenge nonce `nonce`, signed by `signer`'s
 * keys. mlkem: include mpk + mpk_sig. corrupt_kpk: flip one bit of kpk_sig. */
static int peer_auth_ok(const nodus_identity_t *signer, const uint8_t *nonce,
                        bool mlkem, bool corrupt_kpk, uint32_t txn, size_t *len) {
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x3c, sizeof(token));
    uint8_t kd[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
    memcpy(kd, signer->kyber_pk, NODUS_KYBER_PK_BYTES);
    memcpy(kd + NODUS_KYBER_PK_BYTES, nonce, NODUS_NONCE_LEN);
    nodus_sig_t kpk_sig, mpk_sig;
    if (nodus_sign_kyber_bind(&kpk_sig, kd, sizeof(kd), &signer->sk) != 0) return -1;
    if (corrupt_kpk) kpk_sig.bytes[17] ^= 0x01;
    if (mlkem) {
        uint8_t md[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
        memcpy(md, signer->mlkem_pk, NODUS_MLKEM_PK_BYTES);
        memcpy(md + NODUS_MLKEM_PK_BYTES, nonce, NODUS_NONCE_LEN);
        if (nodus_sign_mlkem_bind(&mpk_sig, md, sizeof(md), &signer->sk) != 0) return -1;
    }
    return nodus_t2_auth_ok_kyber(txn, token, signer->kyber_pk, &signer->pk, &kpk_sig,
                                  mlkem ? signer->mlkem_pk : NULL,
                                  mlkem ? &mpk_sig : NULL,
                                  frame, sizeof(frame), len);
}

/* hello + challenge on a fresh state; leaves the challenge nonce in `nonce`. */
static int run_to_auth_ok(nodus_inter_dial_t *d, const nodus_inter_dial_io_t *io,
                          capture_t *cap, uint8_t nonce[NODUS_NONCE_LEN]) {
    size_t len = 0;
    if (nodus_inter_dial_start(io) != 0 || cap->sends != 1) return -1;
    memset(nonce, 0x6d, NODUS_NONCE_LEN);
    if (nodus_t2_challenge(7, nonce, frame, sizeof(frame), &len) != 0) return -1;
    if (feed(d, io, frame, len) != NODUS_INTER_DIAL_DONE || cap->sends != 2) return -1;
    return 0;
}

/* ── 1 + 2: the full exchange ─────────────────────────────────────── */

static void full_exchange(bool mlkem) {
    nodus_inter_dial_t d;
    nodus_inter_dial_io_t io;
    capture_t *cap = calloc(1, sizeof(*cap));
    nodus_channel_crypto_t cc, peer_cc;
    nodus_tier2_msg_t *m = NULL;
    uint8_t nonce[NODUS_NONCE_LEN], ss_peer[32], nc[32], ns[32];
    size_t len = 0;
    memset(&d, 0, sizeof(d));
    memset(&cc, 0, sizeof(cc));
    memset(&peer_cc, 0, sizeof(peer_cc));
    CHECK(cap, "alloc");
    io_init(&io, cap, &cc, &id_dialer, &id_peer.node_id);

    /* hello */
    CHECK(nodus_inter_dial_start(&io) == 0 && cap->sends == 1, "hello not sent");
    m = last_sent(cap);
    CHECK(m && strcmp(m->method, "hello") == 0, "first frame is not hello");
    CHECK(m->txn_id == 0, "hello txn is not 0");
    CHECK(memcmp(&m->pk, &id_dialer.pk, sizeof(m->pk)) == 0, "hello pk is not ours");
    CHECK(nodus_key_cmp(&m->fp, &id_dialer.node_id) == 0, "hello fp is not ours");
    msg_drop(m); m = NULL;

    /* challenge → auth over that nonce, same txn */
    memset(nonce, 0x6d, sizeof(nonce));
    CHECK(nodus_t2_challenge(7, nonce, frame, sizeof(frame), &len) == 0, "enc challenge");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_DONE, "challenge not consumed");
    CHECK(cap->sends == 2, "no auth sent");
    m = last_sent(cap);
    CHECK(m && strcmp(m->method, "auth") == 0 && m->txn_id == 7, "auth frame / txn");
    CHECK(nodus_verify_auth_challenge(&m->sig, nonce, &id_dialer.pk) == 0,
          "auth signature does not verify under our pk over the nonce");
    msg_drop(m); m = NULL;
    CHECK(d.has_challenge_nonce && memcmp(d.challenge_nonce, nonce, sizeof(nonce)) == 0,
          "challenge nonce not retained");

    /* auth_ok → key_init, the peer decapsulates the module's secret */
    CHECK(peer_auth_ok(&id_peer, nonce, mlkem, false, 9, &len) == 0, "enc auth_ok");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_DONE, "auth_ok not consumed");
    CHECK(cap->sends == 3, "no key_init sent");
    CHECK(d.authenticated && d.pending_kem, "state after auth_ok");
    CHECK(d.peer_id_set && nodus_key_cmp(&d.peer_id, &id_peer.node_id) == 0,
          "proven peer identity not recorded");
    CHECK(cap->established_calls == 0, "established before key_ack");
    m = last_sent(cap);
    CHECK(m && strcmp(m->method, "key_init") == 0 && m->txn_id == 9, "key_init frame / txn");
    CHECK(m->has_kyber_ct && m->has_key_nonce, "key_init fields");
    CHECK(m->key_alg == (mlkem ? 1 : 0), "key_init alg");
    CHECK((mlkem ? qgp_mlkem1024_decapsulate(ss_peer, m->kyber_ct, id_peer.mlkem_sk)
                 : qgp_kem1024_decapsulate(ss_peer, m->kyber_ct, id_peer.kyber_sk)) == 0,
          "peer decapsulation failed");
    CHECK(memcmp(ss_peer, d.pending_ss, 32) == 0, "peer's secret != module's pending secret");
    memcpy(nc, m->key_nonce, 32);
    CHECK(memcmp(nc, d.pending_nc, 32) == 0, "key_init nonce != pending nonce");
    msg_drop(m); m = NULL;

    /* key_ack → established(encrypted); same key on both sides */
    memset(ns, 0x4e, sizeof(ns));
    CHECK(nodus_t2_key_ack(9, ns, frame, sizeof(frame), &len) == 0, "enc key_ack");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_DONE, "key_ack not consumed");
    CHECK(cap->established_calls == 1 && cap->established_encrypted,
          "established(encrypted) not reported");
    CHECK(cc.established && !d.pending_kem, "channel crypto not set");
    {
        static const uint8_t zero[32];
        CHECK(memcmp(d.pending_ss, zero, 32) == 0 && memcmp(d.pending_nc, zero, 32) == 0,
              "pending secret not zeroed");
    }
    CHECK(nodus_channel_crypto_init(&peer_cc, ss_peer, nc, ns,
                                    NODUS_CHANNEL_ROLE_RESPONDER) == 0, "peer crypto");
    {
        const uint8_t pt[] = "s5a-dialer";
        uint8_t ctb[64], back[64];
        size_t clen = 0, blen = 0;
        CHECK(nodus_channel_encrypt(&cc, pt, sizeof(pt), ctb, sizeof(ctb), &clen) == 0,
              "dialer encrypt");
        CHECK(nodus_channel_decrypt(&peer_cc, ctb, clen, back, sizeof(back), &blen) == 0,
              "peer cannot decrypt the dialer's frame — keys differ");
        CHECK(blen == sizeof(pt) && memcmp(back, pt, blen) == 0, "roundtrip bytes");
    }
    PASS();
out:
    msg_drop(m);
    nodus_channel_crypto_clear(&cc);
    nodus_channel_crypto_clear(&peer_cc);
    free(cap);
}

static void test_full_mlkem(void) {
    TEST("pinned peer, ML-KEM: hello/auth/key_init/key_ack, same key");
    full_exchange(true);
}

static void test_full_kyber(void) {
    TEST("pinned peer, Kyber-only auth_ok: key_init alg 0, same key");
    full_exchange(false);
}

/* ── 3: refusals ──────────────────────────────────────────────────── */

typedef enum { R_WRONG_ID, R_NO_ID, R_BAD_KPK, R_DOWNGRADE } refusal_t;

static int refused(refusal_t kind) {
    nodus_inter_dial_t d;
    nodus_inter_dial_io_t io;
    capture_t *cap = calloc(1, sizeof(*cap));
    nodus_channel_crypto_t cc;
    uint8_t nonce[NODUS_NONCE_LEN];
    size_t len = 0;
    int ok = 0;
    memset(&d, 0, sizeof(d));
    memset(&cc, 0, sizeof(cc));
    if (!cap) return 0;
    const nodus_key_t *expected = kind == R_WRONG_ID ? &id_other.node_id
                                : kind == R_NO_ID    ? NULL
                                                     : &id_peer.node_id;
    io_init(&io, cap, &cc, &id_dialer, expected);
    if (run_to_auth_ok(&d, &io, cap, nonce) != 0) goto done;
    if (kind == R_DOWNGRADE) {
        uint8_t token[NODUS_SESSION_TOKEN_LEN];
        memset(token, 0x3c, sizeof(token));
        if (nodus_t2_auth_ok(9, token, frame, sizeof(frame), &len) != 0) goto done;
    } else if (peer_auth_ok(&id_peer, nonce, true, kind == R_BAD_KPK, 9, &len) != 0) {
        goto done;
    }
    ok = feed(&d, &io, frame, len) == NODUS_INTER_DIAL_REFUSED &&
         cap->sends == 2 &&                 /* hello + auth; no key_init */
         !d.pending_kem && !d.peer_id_set &&
         cap->established_calls == 0 && !cc.established;
done:
    free(cap);
    return ok;
}

static void test_refusals(void) {
    TEST("CRIT-1: wrong id / no id / bad kpk_sig / downgrade → REFUSED");
    CHECK(refused(R_WRONG_ID), "a peer with another identity was not refused");
    CHECK(refused(R_NO_ID), "a dial with no expected identity was not refused");
    CHECK(refused(R_BAD_KPK), "an invalid kpk_sig was not refused");
    CHECK(refused(R_DOWNGRADE), "an auth_ok without kyber_pk was not refused");
    PASS();
out:
    return;
}

/* ── 4: edges kept from the inline code ───────────────────────────── */

static void test_edges(void) {
    TEST("repeat challenge unsigned; early key_ack NOT_MINE; no-Kyber");
    nodus_inter_dial_t d;
    nodus_inter_dial_io_t io;
    capture_t *cap = calloc(1, sizeof(*cap));
    nodus_channel_crypto_t cc;
    nodus_identity_t *plain = calloc(1, sizeof(*plain));
    uint8_t nonce[NODUS_NONCE_LEN], ns[32];
    size_t len = 0;
    memset(&d, 0, sizeof(d));
    memset(&cc, 0, sizeof(cc));
    memset(ns, 0x4e, sizeof(ns));
    CHECK(cap && plain, "alloc");
    io_init(&io, cap, &cc, &id_dialer, &id_peer.node_id);

    /* key_ack before any key exchange: not the dialer's — the caller
     * dispatches it as before. */
    CHECK(nodus_t2_key_ack(4, ns, frame, sizeof(frame), &len) == 0, "enc key_ack");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_NOT_MINE, "early key_ack consumed");
    /* An unrelated method is not the dialer's either. */
    CHECK(nodus_t2_error(5, NODUS_ERR_PROTOCOL_ERROR, "x", frame, sizeof(frame), &len) == 0,
          "enc error");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_NOT_MINE, "error frame consumed");
    CHECK(cap->sends == 0, "something was sent");

    /* A second challenge on the same conn is not signed. */
    CHECK(run_to_auth_ok(&d, &io, cap, nonce) == 0, "hello + challenge");
    memset(nonce, 0x11, sizeof(nonce));
    CHECK(nodus_t2_challenge(8, nonce, frame, sizeof(frame), &len) == 0, "enc challenge 2");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_DONE, "repeat challenge");
    CHECK(cap->sends == 2, "a repeated challenge was signed again");

    /* This node without a Kyber identity: plaintext at auth_ok. */
    *plain = id_dialer;
    plain->has_kyber = false;
    memset(&d, 0, sizeof(d));
    memset(cap, 0, sizeof(*cap));
    io_init(&io, cap, &cc, plain, &id_peer.node_id);
    CHECK(run_to_auth_ok(&d, &io, cap, nonce) == 0, "hello + challenge (no Kyber)");
    CHECK(peer_auth_ok(&id_peer, nonce, true, false, 9, &len) == 0, "enc auth_ok");
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_DONE, "auth_ok (no Kyber)");
    CHECK(cap->established_calls == 1 && !cap->established_encrypted,
          "no plaintext established");
    CHECK(cap->sends == 2 && !d.pending_kem && !cc.established, "a key exchange started");

    /* A repeated auth_ok after that is dropped. */
    CHECK(feed(&d, &io, frame, len) == NODUS_INTER_DIAL_DONE, "repeat auth_ok");
    CHECK(cap->established_calls == 1 && cap->sends == 2, "repeat auth_ok acted on");
    PASS();
out:
    if (plain) memset(plain, 0, sizeof(*plain));
    free(plain);
    free(cap);
}

int main(void) {
    printf("=== Split S5a item 28: the shared 4002 dialer handshake ===\n");
    uint8_t seed[32];
    memset(seed, 0x81, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_dialer) != 0) { printf("FATAL: id_dialer\n"); return 1; }
    memset(seed, 0x82, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_peer) != 0) { printf("FATAL: id_peer\n"); return 1; }
    memset(seed, 0x83, sizeof(seed));
    if (nodus_identity_from_seed(seed, &id_other) != 0) { printf("FATAL: id_other\n"); return 1; }
    if (!id_dialer.has_kyber || !id_peer.has_kyber || !id_peer.has_mlkem) {
        printf("FATAL: seeded identities lack Kyber / ML-KEM keys\n");
        return 1;
    }

    test_full_mlkem();
    test_full_kyber();
    test_refusals();
    test_edges();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
