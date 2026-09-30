/**
 * Nodus Connect thin core — wire bytes against the verbatim codecs
 * (package NC-2; design rev 5 §1.4 R2 / R5, §6.4 F3).
 *
 * What it proves (no network):
 *   K1  nc_keys_from_words gives a fingerprint = SHA3-512(ML-DSA pk) and is
 *       deterministic (same words twice -> same keys); different words ->
 *       different identity. SELF-CONSISTENT ONLY: this is not design D1 —
 *       D1 needs an expected fingerprint produced by the NATIVE app binary
 *       and stored in a file, which this package does not have.
 *   Q1  A v2 request (with salt) built by nc_request_build passes the
 *       codec's own dht_deserialize_contact_request + dht_verify_contact_request
 *       — the check the frozen app runs on receipt — with sender, version,
 *       message and salt intact.
 *   Q2  Without salt the request is v1 and still verifies.
 *   Q3  The ACCEPT (F3) carries exactly "Contact request accepted" and the
 *       echoed salt (dna_engine_contacts.c CONTACT_ACCEPTED_MSG / approve).
 *   Q4  A message longer than 255 bytes or a malformed recipient is refused
 *       before any signing.
 *   O1  An outbox blob built by A for B (B's record has ML-KEM) uses alg 3
 *       (all-or-nothing, messages.c), deserialises with the codec, and B
 *       decrypts each message with dna_decrypt_message_raw_alg; the Seal's
 *       sender is A, the authorship check passes under A's key, and seq +
 *       the original timestamp are kept.
 *   O2  B's record without ML-KEM -> alg 2 (round-3), still decryptable.
 *   O3  The same Seal checked against another identity's key fails the
 *       authorship gate (nc_outbox_fetch_day would drop it).
 *
 * What it requires: the native build of web-wallet/connect/tests; no
 * environment, no port.
 * What it leaves behind: nothing.
 * How it can lie: every check runs the SAME C as the web build, so it
 * proves the web core and the codecs agree with each other, not that the
 * frozen app (an older binary) reads these bytes — that is NC-3's test
 * against real app records.
 */

#include "nc_core.h"
#include "dht/shared/dht_contact_request.h"
#include "dht/shared/dht_offline_queue.h"
#include "dna_api.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed, failed;
#define CHECK(cond, name) do {                                        \
    if (cond) { passed++; printf("  PASS %s\n", name); }              \
    else { failed++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

/* BIP39 reference vectors (24 words, valid checksums). */
static const char *WORDS_A =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";
static const char *WORDS_B =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

static nc_keys_t *A, *B;
static nodus_identity_t *C;              /* an unrelated identity (random) */

static void peer_from(const nc_keys_t *k, bool with_mlkem, nc_peer_t *p) {
    memset(p, 0, sizeof(*p));
    memcpy(p->fp, k->fp, NC_FP_HEX_LEN);
    memcpy(p->dsa_pk, k->id.pk.bytes, sizeof(p->dsa_pk));
    memcpy(p->kyber_pk, k->kyber_pk, sizeof(p->kyber_pk));
    if (with_mlkem) {
        memcpy(p->mlkem_pk, k->mlkem_pk, sizeof(p->mlkem_pk));
        p->has_mlkem = true;
    }
}

static void test_keys(void) {
    char fp[NC_FP_HEX_LEN + 1];
    qgp_sha3_512_fingerprint(A->id.pk.bytes, QGP_DSA87_PUBLICKEYBYTES, fp);
    nc_keys_t *again = calloc(1, sizeof(*again));
    int rc = again ? nc_keys_from_words(WORDS_A, again) : -1;
    CHECK(strcmp(fp, A->fp) == 0 && rc == 0 &&
          memcmp(again->id.pk.bytes, A->id.pk.bytes, QGP_DSA87_PUBLICKEYBYTES) == 0 &&
          memcmp(again->kyber_pk, A->kyber_pk, NC_KYBER_PK_LEN) == 0 &&
          memcmp(again->mlkem_pk, A->mlkem_pk, QGP_MLKEM1024_PUBLICKEYBYTES) == 0 &&
          strcmp(A->fp, B->fp) != 0,
          "K1 fingerprint = SHA3-512(pk); deterministic; words differ -> identity differs");
    if (again) { nc_keys_wipe(again); free(again); }
}

static int decode_verify(const uint8_t *b, size_t n, dht_contact_request_t *out) {
    memset(out, 0, sizeof(*out));
    return dht_deserialize_contact_request(b, n, out) == 0 &&
           dht_verify_contact_request(out) == 0 ? 0 : -1;
}

static void test_requests(void) {
    dht_contact_request_t *r = calloc(1, sizeof(*r));
    uint8_t salt[NC_SALT_LEN];
    for (int i = 0; i < NC_SALT_LEN; i++) salt[i] = (uint8_t)(i * 7 + 1);
    uint8_t *bytes = NULL;
    size_t len = 0;

    int rc = nc_request_build(A, B->fp, "hi there", salt, &bytes, &len);
    CHECK(rc == 0 && decode_verify(bytes, len, r) == 0 &&
          strcmp(r->sender_fingerprint, A->fp) == 0 &&
          r->version == DHT_CONTACT_REQUEST_VERSION_SALT && r->has_dht_salt &&
          memcmp(r->dht_salt, salt, NC_SALT_LEN) == 0 &&
          strcmp(r->message, "hi there") == 0 && r->sender_name[0] == '\0',
          "Q1 v2 request passes the codec's deserialize + verify");
    free(bytes); bytes = NULL;

    rc = nc_request_build(A, B->fp, NULL, NULL, &bytes, &len);
    CHECK(rc == 0 && decode_verify(bytes, len, r) == 0 &&
          r->version == DHT_CONTACT_REQUEST_VERSION && !r->has_dht_salt &&
          r->message[0] == '\0', "Q2 v1 request (no salt) verifies");
    free(bytes); bytes = NULL;

    rc = nc_request_build(B, A->fp, NC_CONTACT_ACCEPTED_MSG, salt, &bytes, &len);
    CHECK(rc == 0 && decode_verify(bytes, len, r) == 0 &&
          strcmp(r->message, "Contact request accepted") == 0 &&
          memcmp(r->dht_salt, salt, NC_SALT_LEN) == 0 &&
          strcmp(r->sender_fingerprint, B->fp) == 0,
          "Q3 ACCEPT = the app's literal + the echoed salt (F3)");
    free(bytes); bytes = NULL;

    char longmsg[300];
    memset(longmsg, 'x', sizeof(longmsg) - 1);
    longmsg[sizeof(longmsg) - 1] = '\0';
    CHECK(nc_request_build(A, B->fp, longmsg, NULL, &bytes, &len) == NC_ERR_ARG && !bytes &&
          nc_request_build(A, "not-a-fingerprint", NULL, NULL, &bytes, &len) == NC_ERR_ARG,
          "Q4 overlong message / bad recipient refused");
    free(r);
}

static int open_seal(const nc_keys_t *rcpt, const uint8_t *ct, size_t ct_len,
                     const uint8_t *signer_pk, char *text, size_t text_cap,
                     uint64_t *ts, uint8_t claimed[64]) {
    dna_context_t *ctx = dna_context_new();
    uint8_t *pt = NULL, *cl = NULL, *sig = NULL;
    size_t pt_len = 0, cl_len = 0, sig_len = 0;
    int ok = ctx && dna_decrypt_message_raw_alg(ctx, ct, ct_len, rcpt->kyber_sk,
                                                rcpt->mlkem_sk, &pt, &pt_len,
                                                &cl, &cl_len, &sig, &sig_len,
                                                ts) == DNA_OK &&
             cl && cl_len == 64 && pt_len < text_cap;
    if (ok) {
        memcpy(text, pt, pt_len);
        text[pt_len] = '\0';
        memcpy(claimed, cl, 64);
        ok = dna_verify_seal_authorship(pt, pt_len, sig, sig_len, signer_pk,
                                        QGP_DSA87_PUBLICKEYBYTES, cl, NULL) == DNA_OK;
    }
    free(pt); free(cl); free(sig);
    if (ctx) dna_context_free(ctx);
    return ok ? 0 : -1;
}

static void test_outbox(void) {
    nc_peer_t pb;
    nc_outmsg_t msgs[2] = {
        { 7, 1700000000ULL, "first" },
        { 9, 1700000123ULL, "second message" },
    };
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t alg = 0;
    uint8_t a_fp[64];
    {
        nodus_key_t k;
        nc_fp_parse(A->fp, &k);
        memcpy(a_fp, k.bytes, 64);
    }

    peer_from(B, true, &pb);
    int rc = nc_outbox_build(A, &pb, msgs, 2, &blob, &blob_len, &alg);
    dht_offline_message_t *om = NULL;
    size_t n = 0;
    int ok = rc == 0 && alg == QGP_KEY_TYPE_MLKEM1024 &&
             dht_deserialize_messages(blob, blob_len, &om, &n) == 0 && n == 2;
    for (size_t i = 0; ok && i < n; i++) {
        char text[64];
        uint64_t ts = 0;
        uint8_t claimed[64];
        ok = open_seal(B, om[i].ciphertext, om[i].ciphertext_len, A->id.pk.bytes,
                       text, sizeof(text), &ts, claimed) == 0 &&
             strcmp(text, msgs[i].text) == 0 && ts == msgs[i].timestamp &&
             om[i].seq_num == msgs[i].seq &&
             memcmp(claimed, a_fp, 64) == 0 &&
             strcmp(om[i].sender, A->fp) == 0 && strcmp(om[i].recipient, B->fp) == 0;
    }
    CHECK(ok, "O1 ML-KEM blob: B decrypts, sender A, authorship, seq + timestamp kept");

    /* O3 on the same blob: authorship under C's key must fail. */
    if (om && n > 0) {
        char text[64];
        uint64_t ts = 0;
        uint8_t claimed[64];
        CHECK(open_seal(B, om[0].ciphertext, om[0].ciphertext_len, C->pk.bytes,
                        text, sizeof(text), &ts, claimed) != 0,
              "O3 authorship under another identity's key fails");
    }
    dht_offline_messages_free(om, n);
    free(blob); blob = NULL;

    peer_from(B, false, &pb);
    rc = nc_outbox_build(A, &pb, msgs, 1, &blob, &blob_len, &alg);
    om = NULL; n = 0;
    ok = rc == 0 && alg == QGP_KEY_TYPE_KEM1024 &&
         dht_deserialize_messages(blob, blob_len, &om, &n) == 0 && n == 1;
    if (ok) {
        char text[64];
        uint64_t ts = 0;
        uint8_t claimed[64];
        ok = open_seal(B, om[0].ciphertext, om[0].ciphertext_len, A->id.pk.bytes,
                       text, sizeof(text), &ts, claimed) == 0 &&
             strcmp(text, "first") == 0;
    }
    CHECK(ok, "O2 peer without ML-KEM -> round-3 (alg 2), decryptable");
    dht_offline_messages_free(om, n);
    free(blob);
}

int main(void) {
    printf("=== Nodus Connect: wire bytes vs the verbatim codecs ===\n");
    A = calloc(1, sizeof(*A));
    B = calloc(1, sizeof(*B));
    C = calloc(1, sizeof(*C));
    if (!A || !B || !C || nc_keys_from_words(WORDS_A, A) != 0 ||
        nc_keys_from_words(WORDS_B, B) != 0 || nodus_identity_generate(C) != 0) {
        printf("FATAL: key derivation\n");
        return 1;
    }
    test_keys();
    test_requests();
    test_outbox();
    nc_keys_wipe(A); nc_keys_wipe(B); nodus_identity_clear(C);
    free(A); free(B); free(C);
    printf("=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
