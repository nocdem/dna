/**
 * @file test_codec_extract_vectors.c
 * @brief NC-1 before/after vectors for the codec units extracted from the
 *        messenger I/O files (Web Connect design rev 5 §1.3, §4 D2/D3).
 *
 * Calls every moved codec with fixed inputs and prints one "name=value" line
 * per result (hex for bytes). The same source is built once against the
 * pre-move libdna and once against the post-move libdna; the two outputs
 * must be byte-identical. It also checks round-trip invariants and exits
 * non-zero if one fails, so it runs as a normal ctest.
 *
 * Determinism: the tree has NO deterministic-RNG hook (qgp_randombytes and
 * the KEM/DSA randombytes() are not overridable). So:
 *  - deterministic codecs are printed byte for byte: offline blob
 *    serialize/deserialize, DM outbox key, ACK key, salt-agreement key,
 *    fp_hex_to_bin, packet data size, contact-list JSON serialize/parse,
 *    contact-request inbox key / value_id / serialize / deserialize;
 *  - randomized encoders (2-recipient Seal, GEK KEM-wrap, ML-DSA signing
 *    inside the salt packet / contact request) are NOT printed as bytes;
 *    only their deterministic parts are: output length, the Seal header
 *    (20 bytes), and what decrypt / verify returns for a fixed input.
 *    Signing keys come from qgp_dsa87_keypair_derand with a fixed seed and
 *    ML-KEM keys from qgp_mlkem1024_keypair_derand with fixed coins; the
 *    round-3 Kyber keys are random (the tree has no derand for them), which
 *    changes no printed value.
 *
 * NC-1b adds vectors for the four sequences moved out of I/O functions in a
 * second step (vec_nc1b_*): the ACK value encode/decode, the contact-list
 * CLST blob encode/parse, the salt-agreement packet build, and the
 * contact-request signing preimage. Same rules: the blob, the ACK value and
 * the preimage are deterministic and printed byte for byte; the salt
 * packet's KEM wraps and signature are randomized, so only its version,
 * fingerprint order, alg bytes, size, and what the parse helpers return are
 * printed; for signatures only the preimage and the verify result are.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "dna_api.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "messenger/gek.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/shared/dht_dm_outbox.h"
#include "dht/shared/dht_salt_agreement.h"
#include "dht/shared/dht_contact_request.h"
#include "codec/seal_multi_codec.h"
#include "codec/salt_agreement_codec.h"
#include "codec/contactlist_codec.h"
#include "codec/contact_request_codec.h"
#include "codec/offline_queue_codec.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

static int g_failures = 0;

#define CHECK(cond, what) do { \
    if (!(cond)) { printf("FAIL %s\n", (what)); g_failures++; } \
} while (0)

static const char *FP_ALICE = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                              "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
static const char *FP_BOB   = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
                              "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5";
static const char *FP_CAROL = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
                              "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

static void fill_pattern(uint8_t *buf, size_t len, uint8_t start) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(start + i * 7u);
}

static void print_hex(const char *name, const uint8_t *buf, size_t len) {
    printf("%s=", name);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static void fp_hex_of_pubkey(const uint8_t *pubkey, char out[129]) {
    uint8_t fp[64];
    qgp_sha3_512(pubkey, QGP_DSA87_PUBLICKEYBYTES, fp);
    for (int i = 0; i < 64; i++) snprintf(out + i * 2, 3, "%02x", fp[i]);
    out[128] = '\0';
}

/* Fixed-seed ML-DSA-87 keypair (qgp_dsa87_keypair_derand). */
static void dsa_keypair(uint8_t seed_byte, uint8_t *pk, uint8_t *sk) {
    uint8_t seed[32];
    memset(seed, seed_byte, sizeof(seed));
    int rc = qgp_dsa87_keypair_derand(pk, sk, seed);
    CHECK(rc == 0, "qgp_dsa87_keypair_derand");
}

/* Fixed-coins ML-KEM-1024 keypair (qgp_mlkem1024_keypair_derand). */
static void mlkem_keypair(uint8_t coin_byte, uint8_t *ek, uint8_t *dk) {
    uint8_t coins[64];
    memset(coins, coin_byte, sizeof(coins));
    int rc = qgp_mlkem1024_keypair_derand(ek, dk, coins);
    CHECK(rc == 0, "qgp_mlkem1024_keypair_derand");
}

/* ============================================================================
 * offline_queue_codec: dht_serialize_messages / dht_deserialize_messages /
 * dht_offline_messages_free / dht_generate_ack_key
 * ============================================================================ */
static void vec_offline_queue(void) {
    uint8_t ct1[37], ct2[5];
    fill_pattern(ct1, sizeof(ct1), 0x11);
    fill_pattern(ct2, sizeof(ct2), 0xA0);

    dht_offline_message_t msgs[2];
    memset(msgs, 0, sizeof(msgs));
    msgs[0].seq_num = 0x0102030405060708ULL;
    msgs[0].timestamp = 1727700000ULL;
    msgs[0].expiry = 1728304800ULL;
    msgs[0].sender = (char *)FP_ALICE;
    msgs[0].recipient = (char *)FP_BOB;
    msgs[0].ciphertext = ct1;
    msgs[0].ciphertext_len = sizeof(ct1);
    msgs[1].seq_num = 42;
    msgs[1].timestamp = 0xFFFFFFFF00000001ULL;
    msgs[1].expiry = 0;
    msgs[1].sender = "s";
    msgs[1].recipient = "";
    msgs[1].ciphertext = ct2;
    msgs[1].ciphertext_len = sizeof(ct2);

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = dht_serialize_messages(msgs, 2, &blob, &blob_len);
    printf("offline.serialize.rc=%d\n", rc);
    CHECK(rc == 0, "dht_serialize_messages");
    if (rc != 0) return;
    print_hex("offline.serialize.blob", blob, blob_len);

    dht_offline_message_t *out = NULL;
    size_t out_count = 0;
    rc = dht_deserialize_messages(blob, blob_len, &out, &out_count);
    printf("offline.deserialize.rc=%d count=%zu\n", rc, out_count);
    CHECK(rc == 0 && out_count == 2, "dht_deserialize_messages round-trip");
    if (rc == 0) {
        for (size_t i = 0; i < out_count; i++) {
            printf("offline.deserialize.msg%zu seq=%llu ts=%llu exp=%llu sender=%s recipient=%s\n",
                   i, (unsigned long long)out[i].seq_num,
                   (unsigned long long)out[i].timestamp,
                   (unsigned long long)out[i].expiry,
                   out[i].sender, out[i].recipient);
            char name[64];
            snprintf(name, sizeof(name), "offline.deserialize.msg%zu.ct", i);
            print_hex(name, out[i].ciphertext, out[i].ciphertext_len);
        }
        uint8_t *blob2 = NULL;
        size_t blob2_len = 0;
        rc = dht_serialize_messages(out, out_count, &blob2, &blob2_len);
        CHECK(rc == 0 && blob2_len == blob_len && memcmp(blob, blob2, blob_len) == 0,
              "offline blob re-serialize identical");
        free(blob2);
        dht_offline_messages_free(out, out_count);
    }

    /* Empty array, truncated blob, bad magic */
    uint8_t *empty = NULL;
    size_t empty_len = 0;
    rc = dht_serialize_messages(NULL, 0, &empty, &empty_len);
    printf("offline.serialize.empty.rc=%d\n", rc);
    if (rc == 0) {
        print_hex("offline.serialize.empty.blob", empty, empty_len);
        free(empty);
    }
    out = NULL;
    out_count = 0;
    rc = dht_deserialize_messages(blob, blob_len - 1, &out, &out_count);
    printf("offline.deserialize.truncated.rc=%d\n", rc);
    CHECK(rc == -1, "truncated blob rejected");
    blob[4] ^= 0xFF;
    rc = dht_deserialize_messages(blob, blob_len, &out, &out_count);
    printf("offline.deserialize.badmagic.rc=%d\n", rc);
    CHECK(rc == -1, "bad magic rejected");
    free(blob);

    /* ACK key */
    uint8_t salt[32], ack_key[64];
    fill_pattern(salt, sizeof(salt), 0x5A);
    rc = dht_generate_ack_key(FP_BOB, FP_ALICE, salt, ack_key);
    printf("ack.key.rc=%d\n", rc);
    if (rc == 0) print_hex("ack.key", ack_key, sizeof(ack_key));
    rc = dht_generate_ack_key(FP_BOB, FP_ALICE, NULL, ack_key);
    printf("ack.key.nullsalt.rc=%d\n", rc);
    CHECK(rc == -1, "ACK key refuses NULL salt");
}

/* ============================================================================
 * dm_outbox_codec: dht_dm_outbox_make_key (explicit day bucket)
 * ============================================================================ */
static void vec_dm_outbox(void) {
    uint8_t salt[32];
    fill_pattern(salt, sizeof(salt), 0x03);
    char key[512];
    int rc = dht_dm_outbox_make_key(FP_ALICE, FP_BOB, 20361, salt, key, sizeof(key));
    printf("outbox.key.rc=%d\n", rc);
    if (rc == 0) printf("outbox.key=%s\n", key);
    rc = dht_dm_outbox_make_key(FP_ALICE, FP_BOB, 20361, NULL, key, sizeof(key));
    printf("outbox.key.nullsalt.rc=%d\n", rc);
    CHECK(rc == -1, "outbox key refuses NULL salt");
    rc = dht_dm_outbox_make_key(FP_ALICE, FP_BOB, 20361, salt, key, 299);
    printf("outbox.key.smallbuf.rc=%d\n", rc);
    CHECK(rc == -1, "outbox key refuses buffer < 300");
}

/* ============================================================================
 * salt_agreement_codec: make_key, fp_hex_to_bin, packet_data_size_for_version,
 * packet_decrypt_salt, packet_verify_signature
 * ============================================================================ */

/* Builds a salt packet (v1 or v2) the way salt_agreement_publish_internal
 * lays it out (dht_salt_agreement.c), signed by `signer_sk`. The KEM wrap
 * and the signature are randomized; the packet bytes are therefore not
 * printed — only what the parse helpers return for it. */
static size_t build_salt_packet(bool v2, const uint8_t salt[32],
                                const char *lower_fp, const uint8_t *lower_kem_pub,
                                const char *higher_fp, const uint8_t *higher_kem_pub,
                                const uint8_t *signer_sk, uint8_t *packet) {
    size_t off = 0;
    uint16_t version = htons(v2 ? SALT_AGREEMENT_VERSION_V2 : SALT_AGREEMENT_VERSION);
    memcpy(packet + off, &version, 2);
    off += 2;

    const char *fps[2] = { lower_fp, higher_fp };
    const uint8_t *pubs[2] = { lower_kem_pub, higher_kem_pub };
    for (int e = 0; e < 2; e++) {
        CHECK(salt_agreement_fp_hex_to_bin(fps[e], packet + off) == 0, "fp_hex_to_bin in packet");
        off += FP_BIN_SIZE;
        if (v2) {
            packet[off++] = SALT_AGREEMENT_ALG_MLKEM1024;
            CHECK(gek_encrypt_alg(SALT_AGREEMENT_ALG_MLKEM1024, salt, pubs[e], packet + off) == 0,
                  "gek_encrypt_alg ML-KEM in packet");
        } else {
            CHECK(gek_encrypt(salt, pubs[e], packet + off) == 0, "gek_encrypt in packet");
        }
        off += GEK_ENC_TOTAL_SIZE;
    }
    size_t sig_len = 0;
    CHECK(qgp_dsa87_sign(packet + off, &sig_len, packet, off, signer_sk) == 0, "sign packet");
    return off + sig_len;
}

static void vec_salt_agreement(void) {
    char key[300];
    int rc = salt_agreement_make_key(FP_ALICE, FP_BOB, key, sizeof(key));
    printf("salt.key.rc=%d\n", rc);
    if (rc == 0) printf("salt.key=%s\n", key);
    char key_rev[300];
    rc = salt_agreement_make_key(FP_BOB, FP_ALICE, key_rev, sizeof(key_rev));
    CHECK(rc == 0 && strcmp(key, key_rev) == 0, "salt key order-independent");
    rc = salt_agreement_make_key("abc", FP_BOB, key, sizeof(key));
    printf("salt.key.shortfp.rc=%d\n", rc);

    uint8_t bin[FP_BIN_SIZE];
    rc = salt_agreement_fp_hex_to_bin(FP_CAROL, bin);
    printf("salt.fp_hex_to_bin.rc=%d\n", rc);
    if (rc == 0) print_hex("salt.fp_hex_to_bin", bin, sizeof(bin));
    printf("salt.fp_hex_to_bin.short.rc=%d\n", salt_agreement_fp_hex_to_bin("a1b2", bin));

    printf("salt.data_size.v1=%zu\n", salt_agreement_packet_data_size_for_version(SALT_AGREEMENT_VERSION));
    printf("salt.data_size.v2=%zu\n", salt_agreement_packet_data_size_for_version(SALT_AGREEMENT_VERSION_V2));
    printf("salt.data_size.v3=%zu\n", salt_agreement_packet_data_size_for_version(3));
    printf("salt.packet_total.v1=%d v2=%d\n", (int)PACKET_TOTAL_SIZE, (int)PACKET_TOTAL_SIZE_V2);

    /* Keys: A = alice (signer), B = bob, C = carol (third party). */
    uint8_t *a_sign_pk = malloc(QGP_DSA87_PUBLICKEYBYTES), *a_sign_sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t *c_sign_pk = malloc(QGP_DSA87_PUBLICKEYBYTES), *c_sign_sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t *a_kyb_pk = malloc(1568), *a_kyb_sk = malloc(3168);
    uint8_t *b_kyb_pk = malloc(1568), *b_kyb_sk = malloc(3168);
    uint8_t *a_ml_pk = malloc(1568), *a_ml_sk = malloc(3168);
    uint8_t *b_ml_pk = malloc(1568), *b_ml_sk = malloc(3168);
    uint8_t *packet = malloc(PACKET_TOTAL_SIZE_V2);
    if (!a_sign_pk || !a_sign_sk || !c_sign_pk || !c_sign_sk || !a_kyb_pk || !a_kyb_sk ||
        !b_kyb_pk || !b_kyb_sk || !a_ml_pk || !a_ml_sk || !b_ml_pk || !b_ml_sk || !packet) {
        CHECK(0, "salt vector allocation");
        goto out;
    }
    dsa_keypair(0x41, a_sign_pk, a_sign_sk);
    dsa_keypair(0x43, c_sign_pk, c_sign_sk);
    CHECK(qgp_kem1024_keypair(a_kyb_pk, a_kyb_sk) == 0, "kyber keypair A");
    CHECK(qgp_kem1024_keypair(b_kyb_pk, b_kyb_sk) == 0, "kyber keypair B");
    mlkem_keypair(0x61, a_ml_pk, a_ml_sk);
    mlkem_keypair(0x62, b_ml_pk, b_ml_sk);

    uint8_t salt[32], got[32], a_bin[FP_BIN_SIZE], b_bin[FP_BIN_SIZE], c_bin[FP_BIN_SIZE];
    fill_pattern(salt, sizeof(salt), 0x77);
    salt_agreement_fp_hex_to_bin(FP_ALICE, a_bin);
    salt_agreement_fp_hex_to_bin(FP_BOB, b_bin);
    salt_agreement_fp_hex_to_bin(FP_CAROL, c_bin);

    for (int v = 1; v <= 2; v++) {
        bool v2 = (v == 2);
        size_t plen = build_salt_packet(v2, salt, FP_ALICE, v2 ? a_ml_pk : a_kyb_pk,
                                        FP_BOB, v2 ? b_ml_pk : b_kyb_pk, a_sign_sk, packet);
        size_t dsize = salt_agreement_packet_data_size_for_version(
                           v2 ? SALT_AGREEMENT_VERSION_V2 : SALT_AGREEMENT_VERSION);
        printf("salt.v%d.packet_len=%zu\n", v, plen);
        printf("salt.v%d.verify.signer=%d\n", v,
               salt_agreement_packet_verify_signature(packet, plen, dsize, c_sign_pk, a_sign_pk));
        printf("salt.v%d.verify.third_party=%d\n", v,
               salt_agreement_packet_verify_signature(packet, plen, dsize, c_sign_pk, NULL));

        memset(got, 0, sizeof(got));
        rc = salt_agreement_packet_decrypt_salt(packet, plen, a_bin, a_kyb_sk, a_ml_sk, got);
        printf("salt.v%d.decrypt.alice.rc=%d\n", v, rc);
        if (rc == 0) print_hex(v2 ? "salt.v2.decrypt.alice" : "salt.v1.decrypt.alice", got, 32);
        CHECK(rc == 0 && memcmp(got, salt, 32) == 0, "salt decrypt alice");

        memset(got, 0, sizeof(got));
        rc = salt_agreement_packet_decrypt_salt(packet, plen, b_bin, b_kyb_sk, b_ml_sk, got);
        printf("salt.v%d.decrypt.bob.rc=%d\n", v, rc);
        if (rc == 0) print_hex(v2 ? "salt.v2.decrypt.bob" : "salt.v1.decrypt.bob", got, 32);
        CHECK(rc == 0 && memcmp(got, salt, 32) == 0, "salt decrypt bob");

        rc = salt_agreement_packet_decrypt_salt(packet, plen, c_bin, a_kyb_sk, a_ml_sk, got);
        printf("salt.v%d.decrypt.carol.rc=%d\n", v, rc);
        CHECK(rc == -1, "salt decrypt carol rejected");

        if (v2) {
            rc = salt_agreement_packet_decrypt_salt(packet, plen, a_bin, a_kyb_sk, NULL, got);
            printf("salt.v2.decrypt.no_mlkem_key.rc=%d\n", rc);
            CHECK(rc == -1, "v2 ML-KEM entry needs ML-KEM key");
        }
    }

out:
    free(a_sign_pk); free(a_sign_sk); free(c_sign_pk); free(c_sign_sk);
    free(a_kyb_pk); free(a_kyb_sk); free(b_kyb_pk); free(b_kyb_sk);
    free(a_ml_pk); free(a_ml_sk); free(b_ml_pk); free(b_ml_sk);
    free(packet);
}

/* ============================================================================
 * gek_wrap_codec: gek_encrypt_alg / gek_decrypt_alg / gek_encrypt / gek_decrypt
 * ============================================================================ */
static void vec_gek_wrap(void) {
    uint8_t *kyb_pk = malloc(1568), *kyb_sk = malloc(3168);
    uint8_t *ml_pk = malloc(1568), *ml_sk = malloc(3168);
    uint8_t *blob = malloc(GEK_ENC_TOTAL_SIZE);
    if (!kyb_pk || !kyb_sk || !ml_pk || !ml_sk || !blob) {
        CHECK(0, "gek vector allocation");
        goto out;
    }
    CHECK(qgp_kem1024_keypair(kyb_pk, kyb_sk) == 0, "kyber keypair");
    mlkem_keypair(0x33, ml_pk, ml_sk);

    uint8_t secret[32], got[32];
    fill_pattern(secret, sizeof(secret), 0xC1);
    printf("gek.total_size=%d\n", (int)GEK_ENC_TOTAL_SIZE);

    int rc = gek_encrypt(secret, kyb_pk, blob);
    printf("gek.r3.encrypt.rc=%d\n", rc);
    rc = gek_decrypt(blob, GEK_ENC_TOTAL_SIZE, kyb_sk, got);
    printf("gek.r3.decrypt.rc=%d\n", rc);
    if (rc == 0) print_hex("gek.r3.decrypt", got, 32);
    CHECK(rc == 0 && memcmp(got, secret, 32) == 0, "gek r3 round-trip");

    rc = gek_encrypt_alg(IKP_ALG_MLKEM1024, secret, ml_pk, blob);
    printf("gek.mlkem.encrypt.rc=%d\n", rc);
    rc = gek_decrypt_alg(IKP_ALG_MLKEM1024, blob, GEK_ENC_TOTAL_SIZE, ml_sk, got);
    printf("gek.mlkem.decrypt.rc=%d\n", rc);
    if (rc == 0) print_hex("gek.mlkem.decrypt", got, 32);
    CHECK(rc == 0 && memcmp(got, secret, 32) == 0, "gek ML-KEM round-trip");

    blob[GEK_ENC_TOTAL_SIZE - 1] ^= 0x01;
    rc = gek_decrypt_alg(IKP_ALG_MLKEM1024, blob, GEK_ENC_TOTAL_SIZE, ml_sk, got);
    printf("gek.mlkem.decrypt.tampered.rc=%d\n", rc);
    CHECK(rc == -1, "gek tampered rejected");
    printf("gek.encrypt.badalg.rc=%d\n", gek_encrypt_alg(7, secret, ml_pk, blob));
    printf("gek.decrypt.badlen.rc=%d\n", gek_decrypt_alg(IKP_ALG_KYBER_R3, blob, 1627, kyb_sk, got));

out:
    free(kyb_pk); free(kyb_sk); free(ml_pk); free(ml_sk); free(blob);
}

/* ============================================================================
 * seal_multi_codec: messenger_encrypt_multi_recipient (2 recipients)
 * ============================================================================ */
static void vec_seal_multi(void) {
    uint8_t *sign_pk = malloc(QGP_DSA87_PUBLICKEYBYTES), *sign_sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t *r3_pk[2], *r3_sk[2], *ml_pk[2], *ml_sk[2];
    for (int i = 0; i < 2; i++) {
        r3_pk[i] = malloc(1568); r3_sk[i] = malloc(3168);
        ml_pk[i] = malloc(1568); ml_sk[i] = malloc(3168);
    }
    dna_context_t *ctx = dna_context_new();
    if (!sign_pk || !sign_sk || !ctx) {
        CHECK(0, "seal vector allocation");
        goto out;
    }
    dsa_keypair(0x51, sign_pk, sign_sk);
    for (int i = 0; i < 2; i++) {
        CHECK(qgp_kem1024_keypair(r3_pk[i], r3_sk[i]) == 0, "kyber keypair");
        mlkem_keypair((uint8_t)(0x70 + i), ml_pk[i], ml_sk[i]);
    }

    char sender_fp[129];
    fp_hex_of_pubkey(sign_pk, sender_fp);
    printf("seal.sender_fp=%s\n", sender_fp);

    qgp_key_t key;
    memset(&key, 0, sizeof(key));
    key.type = QGP_KEY_TYPE_DSA87;
    key.purpose = QGP_KEY_PURPOSE_SIGNING;
    key.public_key = sign_pk;
    key.public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    key.private_key = sign_sk;
    key.private_key_size = QGP_DSA87_SECRETKEYBYTES;

    const char *plaintext = "NC-1 vector: hello from the codec unit";
    const uint64_t ts = 1727700123ULL;

    for (int pass = 0; pass < 2; pass++) {
        uint8_t alg = pass == 0 ? (uint8_t)QGP_KEY_TYPE_KEM1024 : (uint8_t)QGP_KEY_TYPE_MLKEM1024;
        uint8_t *pubs[2] = { pass == 0 ? r3_pk[0] : ml_pk[0], pass == 0 ? r3_pk[1] : ml_pk[1] };
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        int rc = messenger_encrypt_multi_recipient(plaintext, strlen(plaintext), pubs, 2,
                                                   &key, ts, alg, &ct, &ct_len);
        printf("seal.alg%u.encrypt.rc=%d len=%zu\n", (unsigned)alg, rc, ct_len);
        CHECK(rc == 0, "seal encrypt");
        if (rc != 0) continue;
        char name[64];
        snprintf(name, sizeof(name), "seal.alg%u.header", (unsigned)alg);
        print_hex(name, ct, ct_len < 20 ? ct_len : 20);

        for (int r = 0; r < 2; r++) {
            uint8_t *pt = NULL, *fp = NULL, *sig = NULL;
            size_t pt_len = 0, fp_len = 0, sig_len = 0;
            uint64_t got_ts = 0;
            dna_error_t drc = dna_decrypt_message_raw_alg(ctx, ct, ct_len,
                                  r3_sk[r], ml_sk[r], &pt, &pt_len, &fp, &fp_len,
                                  &sig, &sig_len, &got_ts);
            printf("seal.alg%u.recipient%d.decrypt.rc=%d\n", (unsigned)alg, r, (int)drc);
            CHECK(drc == DNA_OK, "seal decrypt");
            if (drc == DNA_OK) {
                printf("seal.alg%u.recipient%d.plaintext=%.*s\n", (unsigned)alg, r, (int)pt_len, (const char *)pt);
                printf("seal.alg%u.recipient%d.timestamp=%llu\n", (unsigned)alg, r, (unsigned long long)got_ts);
                snprintf(name, sizeof(name), "seal.alg%u.recipient%d.sender_fp", (unsigned)alg, r);
                print_hex(name, fp, fp_len);
                char verified[129];
                dna_error_t arc = dna_verify_seal_authorship(pt, pt_len, sig, sig_len,
                                      sign_pk, QGP_DSA87_PUBLICKEYBYTES, fp, verified);
                printf("seal.alg%u.recipient%d.authorship.rc=%d\n", (unsigned)alg, r, (int)arc);
                CHECK(arc == DNA_OK && pt_len == strlen(plaintext) &&
                      memcmp(pt, plaintext, pt_len) == 0 && got_ts == ts,
                      "seal round-trip + authorship");
            }
            free(pt); free(fp); free(sig);
        }
        free(ct);
    }

out:
    if (ctx) dna_context_free(ctx);
    free(sign_pk); free(sign_sk);
    for (int i = 0; i < 2; i++) { free(r3_pk[i]); free(r3_sk[i]); free(ml_pk[i]); free(ml_sk[i]); }
}

/* ============================================================================
 * contactlist_codec: dht_contactlist_serialize_to_json / _deserialize_from_json
 * ============================================================================ */
static void vec_contactlist(void) {
    uint8_t salt0[32];
    fill_pattern(salt0, sizeof(salt0), 0x2B);
    const char *contacts[3] = { FP_BOB, FP_CAROL, "" };
    const uint8_t *salts[3] = { salt0, NULL, NULL };

    char *json = dht_contactlist_serialize_to_json(FP_ALICE, contacts, salts, 3, 1727700456ULL);
    printf("contactlist.json=%s\n", json ? json : "(null)");
    CHECK(json != NULL, "contactlist serialize");
    if (json) {
        char **out = NULL;
        uint8_t **out_salts = NULL;
        size_t count = 0;
        uint64_t ts = 0;
        int rc = dht_contactlist_deserialize_from_json(json, &out, &count, &out_salts, &ts);
        printf("contactlist.parse.rc=%d count=%zu ts=%llu\n", rc, count, (unsigned long long)ts);
        CHECK(rc == 0 && count == 3 && ts == 1727700456ULL, "contactlist parse");
        for (size_t i = 0; rc == 0 && i < count; i++) {
            printf("contactlist.parse.fp%zu=%s\n", i, out[i]);
            if (out_salts[i]) {
                char name[64];
                snprintf(name, sizeof(name), "contactlist.parse.salt%zu", i);
                print_hex(name, out_salts[i], 32);
            } else {
                printf("contactlist.parse.salt%zu=(none)\n", i);
            }
            free(out[i]);
            free(out_salts[i]);
        }
        if (rc == 0) { free(out); free(out_salts); }
        free(json);
    }

    /* v1 list (plain strings), a v2 entry with a bad salt, malformed JSON. */
    const char *v1 = "{\"identity\":\"x\",\"version\":1,\"timestamp\":7,\"contacts\":[\"aa\",\"bb\"]}";
    const char *bad_salt = "{\"version\":2,\"contacts\":[{\"fp\":\"cc\",\"salt\":\"zz"
                           "00000000000000000000000000000000000000000000000000000000000000\"}]}";
    const char *inputs[3] = { v1, bad_salt, "{not json" };
    for (int k = 0; k < 3; k++) {
        char **out = NULL;
        uint8_t **out_salts = NULL;
        size_t count = 0;
        uint64_t ts = 0;
        int rc = dht_contactlist_deserialize_from_json(inputs[k], &out, &count, &out_salts, &ts);
        printf("contactlist.input%d.rc=%d count=%zu ts=%llu\n", k, rc, count, (unsigned long long)ts);
        for (size_t i = 0; rc == 0 && i < count; i++) {
            printf("contactlist.input%d.fp%zu=%s salt=%s\n", k, i, out[i],
                   out_salts[i] ? "present" : "(none)");
            free(out[i]);
            free(out_salts[i]);
        }
        if (rc == 0) { free(out); free(out_salts); }
    }
}

/* ============================================================================
 * contact_request_codec: inbox key, value_id, serialize, deserialize, verify
 * ============================================================================ */
static void vec_contact_request(void) {
    uint8_t inbox[64];
    dht_generate_requests_inbox_key(FP_BOB, inbox);
    print_hex("request.inbox_key", inbox, sizeof(inbox));

    printf("request.value_id.alice=%llu\n", (unsigned long long)dht_fingerprint_to_value_id(FP_ALICE));
    printf("request.value_id.upper=%llu\n", (unsigned long long)dht_fingerprint_to_value_id("ABCDEF0123456789ffff"));
    printf("request.value_id.zero=%llu\n", (unsigned long long)dht_fingerprint_to_value_id("0000000000000000zz"));
    printf("request.value_id.short=%llu\n", (unsigned long long)dht_fingerprint_to_value_id("abc"));
    printf("request.value_id.null=%llu\n", (unsigned long long)dht_fingerprint_to_value_id(NULL));

    dht_contact_request_t *req = calloc(1, sizeof(*req));
    dht_contact_request_t *back = calloc(1, sizeof(*back));
    uint8_t *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    if (!req || !back || !sk) {
        CHECK(0, "request vector allocation");
        goto out;
    }

    /* Deterministic serialize: fixed fields and a fixed (not real) signature. */
    for (int v = 1; v <= 2; v++) {
        memset(req, 0, sizeof(*req));
        req->magic = DHT_CONTACT_REQUEST_MAGIC;
        req->version = (uint8_t)v;
        req->timestamp = 1727700789ULL;
        req->expiry = 1728305589ULL;
        snprintf(req->sender_fingerprint, sizeof(req->sender_fingerprint), "%s", FP_ALICE);
        snprintf(req->sender_name, sizeof(req->sender_name), "%s", "alice");
        fill_pattern(req->sender_dilithium_pubkey, DHT_DILITHIUM5_PUBKEY_SIZE, 0x09);
        snprintf(req->message, sizeof(req->message), "%s", "Hey, add me!");
        if (v == 2) {
            fill_pattern(req->dht_salt, DHT_CONTACT_SALT_SIZE_CR, 0xE4);
            req->has_dht_salt = true;
        }
        req->signature_len = 100;
        fill_pattern(req->signature, req->signature_len, 0x3C);

        uint8_t *buf = NULL;
        size_t len = 0;
        int rc = dht_serialize_contact_request(req, &buf, &len);
        printf("request.v%d.serialize.rc=%d len=%zu\n", v, rc, len);
        CHECK(rc == 0, "request serialize");
        if (rc != 0) continue;
        char name[64];
        snprintf(name, sizeof(name), "request.v%d.serialize", v);
        print_hex(name, buf, len);

        memset(back, 0xAA, sizeof(*back));
        rc = dht_deserialize_contact_request(buf, len, back);
        printf("request.v%d.deserialize.rc=%d version=%u ts=%llu exp=%llu name=%s msg=%s has_salt=%d siglen=%zu\n",
               v, rc, back->version, (unsigned long long)back->timestamp,
               (unsigned long long)back->expiry, back->sender_name, back->message,
               (int)back->has_dht_salt, back->signature_len);
        CHECK(rc == 0, "request deserialize");
        if (rc == 0) {
            uint8_t *buf2 = NULL;
            size_t len2 = 0;
            rc = dht_serialize_contact_request(back, &buf2, &len2);
            CHECK(rc == 0 && len2 == len && memcmp(buf, buf2, len) == 0,
                  "request re-serialize identical");
            free(buf2);
        }
        rc = dht_deserialize_contact_request(buf, len - 1, back);
        printf("request.v%d.deserialize.truncated.rc=%d\n", v, rc);
        free(buf);
    }

    /* Verify: real ML-DSA-87 key (fixed seed); the signature over the
     * preimage is randomized, the verify result is not. The preimage is the
     * serialized request with an empty signature minus its 2-byte length. */
    memset(req, 0, sizeof(*req));
    req->magic = DHT_CONTACT_REQUEST_MAGIC;
    req->version = DHT_CONTACT_REQUEST_VERSION_SALT;
    req->timestamp = 1727700789ULL;
    req->expiry = UINT64_MAX;  /* verify reads time(NULL); never expires */
    dsa_keypair(0x52, req->sender_dilithium_pubkey, sk);
    fp_hex_of_pubkey(req->sender_dilithium_pubkey, req->sender_fingerprint);
    snprintf(req->sender_name, sizeof(req->sender_name), "%s", "alice");
    snprintf(req->message, sizeof(req->message), "%s", "Contact request accepted");
    fill_pattern(req->dht_salt, DHT_CONTACT_SALT_SIZE_CR, 0x19);
    req->has_dht_salt = true;
    req->signature_len = 0;
    printf("request.verify.sender_fp=%s\n", req->sender_fingerprint);

    uint8_t *pre = NULL;
    size_t pre_len = 0;
    if (dht_serialize_contact_request(req, &pre, &pre_len) == 0) {
        size_t sig_len = 0;
        CHECK(qgp_dsa87_sign(req->signature, &sig_len, pre, pre_len - 2, sk) == 0, "sign request");
        req->signature_len = sig_len;
        free(pre);
        printf("request.verify.valid.rc=%d\n", dht_verify_contact_request(req));
        CHECK(dht_verify_contact_request(req) == 0, "request verify valid");
        req->message[0] ^= 0x20;
        printf("request.verify.tampered.rc=%d\n", dht_verify_contact_request(req));
        req->message[0] ^= 0x20;
        req->sender_fingerprint[0] = (req->sender_fingerprint[0] == '0') ? '1' : '0';
        printf("request.verify.fp_mismatch.rc=%d\n", dht_verify_contact_request(req));
        req->expiry = 1;
        printf("request.verify.expired.rc=%d\n", dht_verify_contact_request(req));
    } else {
        CHECK(0, "request preimage serialize");
    }

out:
    free(req); free(back); free(sk);
}

/* ============================================================================
 * NC-1b: offline_queue_codec — dht_ack_value_encode / dht_ack_value_decode
 * ============================================================================ */
static void vec_nc1b_ack_value(void) {
    const uint64_t ts[5] = { 0ULL, 1ULL, 1727700000ULL, 0x0102030405060708ULL, UINT64_MAX };
    for (int i = 0; i < 5; i++) {
        uint8_t v[8];
        memset(v, 0xEE, sizeof(v));
        dht_ack_value_encode(ts[i], v);
        char name[64];
        snprintf(name, sizeof(name), "nc1b.ack.encode%d", i);
        print_hex(name, v, sizeof(v));
        uint64_t back = dht_ack_value_decode(v);
        printf("nc1b.ack.decode%d=%llu\n", i, (unsigned long long)back);
        CHECK(back == ts[i], "ACK value round-trip");
    }
    const uint8_t fixed[8] = { 0x80, 0x00, 0x00, 0x00, 0x66, 0xFA, 0x0B, 0x20 };
    printf("nc1b.ack.decode.fixed=%llu\n", (unsigned long long)dht_ack_value_decode(fixed));
}

/* ============================================================================
 * NC-1b: contactlist_codec — dht_contactlist_blob_encode / _blob_parse
 * ============================================================================ */
static void print_blob_parse(const char *label, const uint8_t *blob, size_t len) {
    uint64_t ts = 0, exp = 0;
    const uint8_t *enc = NULL;
    uint32_t enc_len = 0;
    int rc = dht_contactlist_blob_parse(blob, len, &ts, &exp, &enc, &enc_len);
    if (rc == 0) {
        printf("nc1b.clst.parse.%s.rc=%d ts=%llu exp=%llu enc_off=%lld enc_len=%u\n", label, rc,
               (unsigned long long)ts, (unsigned long long)exp,
               (long long)(enc - blob), enc_len);
    } else {
        printf("nc1b.clst.parse.%s.rc=%d\n", label, rc);
    }
}

static void vec_nc1b_contactlist_blob(void) {
    uint8_t enc[97], sig[64];
    fill_pattern(enc, sizeof(enc), 0x21);
    fill_pattern(sig, sizeof(sig), 0x9D);
    const uint64_t ts = 1727700456ULL, exp = 1727700456ULL + 604800ULL;

    uint8_t *blob = NULL;
    size_t len = 0;
    int rc = dht_contactlist_blob_encode(ts, exp, enc, sizeof(enc), sig, sizeof(sig), &blob, &len);
    printf("nc1b.clst.encode.rc=%d len=%zu\n", rc, len);
    CHECK(rc == 0 && len == 4 + 1 + 8 + 8 + 4 + sizeof(enc) + 4 + sizeof(sig), "CLST encode");
    if (rc != 0) return;
    print_hex("nc1b.clst.encode", blob, len);

    uint64_t pts = 0, pexp = 0;
    const uint8_t *penc = NULL;
    uint32_t penc_len = 0;
    rc = dht_contactlist_blob_parse(blob, len, &pts, &pexp, &penc, &penc_len);
    CHECK(rc == 0 && pts == ts && pexp == exp && penc_len == sizeof(enc) &&
          memcmp(penc, enc, sizeof(enc)) == 0, "CLST parse round-trip");
    print_blob_parse("valid", blob, len);

    /* Header variants: one field broken at a time. */
    uint8_t *m = malloc(len + 1);
    if (!m) { CHECK(0, "CLST vector allocation"); free(blob); return; }
    print_blob_parse("short_by_one", blob, len - 1);
    memcpy(m, blob, len); m[len] = 0x00;
    print_blob_parse("long_by_one", m, len + 1);
    memcpy(m, blob, len); m[0] ^= 0x01;
    print_blob_parse("bad_magic", m, len);
    memcpy(m, blob, len); m[4] = 0;
    print_blob_parse("version0", m, len);
    memcpy(m, blob, len); m[4] = 1;
    print_blob_parse("version1", m, len);
    memcpy(m, blob, len); m[4] = 3;
    print_blob_parse("version3", m, len);
    memcpy(m, blob, len); m[21] = 0xFF; m[22] = 0xFF; m[23] = 0xFF; m[24] = 0xF0;
    print_blob_parse("enc_len_huge", m, len);
    memcpy(m, blob, len); m[24] ^= 0x01;
    print_blob_parse("enc_len_off_by_one", m, len);
    print_blob_parse("below_minimum", blob, 28);
    free(m);
    free(blob);

    /* Empty sealed part and empty signature: the smallest valid blob; the
     * largest expiry the publisher can write (timestamp + a uint32 TTL). */
    blob = NULL;
    len = 0;
    rc = dht_contactlist_blob_encode(1, 1ULL + 0xFFFFFFFFULL, enc, 0, sig, 0, &blob, &len);
    printf("nc1b.clst.encode.empty.rc=%d len=%zu\n", rc, len);
    if (rc == 0) {
        print_hex("nc1b.clst.encode.empty", blob, len);
        print_blob_parse("empty", blob, len);
        free(blob);
    }
}

/* ============================================================================
 * NC-1b: salt_agreement_codec — salt_agreement_build_packet
 * ============================================================================ */
static void vec_nc1b_salt_packet(void) {
    uint8_t *a_sign_pk = malloc(QGP_DSA87_PUBLICKEYBYTES), *a_sign_sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t *b_sign_pk = malloc(QGP_DSA87_PUBLICKEYBYTES), *b_sign_sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t *a_kyb_pk = malloc(1568), *a_kyb_sk = malloc(3168);
    uint8_t *b_kyb_pk = malloc(1568), *b_kyb_sk = malloc(3168);
    uint8_t *a_ml_pk = malloc(1568), *a_ml_sk = malloc(3168);
    uint8_t *b_ml_pk = malloc(1568), *b_ml_sk = malloc(3168);
    uint8_t *packet = malloc(PACKET_TOTAL_SIZE_V2);
    if (!a_sign_pk || !a_sign_sk || !b_sign_pk || !b_sign_sk || !a_kyb_pk || !a_kyb_sk ||
        !b_kyb_pk || !b_kyb_sk || !a_ml_pk || !a_ml_sk || !b_ml_pk || !b_ml_sk || !packet) {
        CHECK(0, "nc1b salt vector allocation");
        goto out;
    }
    dsa_keypair(0x44, a_sign_pk, a_sign_sk);
    dsa_keypair(0x45, b_sign_pk, b_sign_sk);
    CHECK(qgp_kem1024_keypair(a_kyb_pk, a_kyb_sk) == 0, "kyber keypair A");
    CHECK(qgp_kem1024_keypair(b_kyb_pk, b_kyb_sk) == 0, "kyber keypair B");
    mlkem_keypair(0x63, a_ml_pk, a_ml_sk);
    mlkem_keypair(0x64, b_ml_pk, b_ml_sk);

    uint8_t salt[32], got[32], a_bin[FP_BIN_SIZE], b_bin[FP_BIN_SIZE];
    fill_pattern(salt, sizeof(salt), 0x6B);
    salt_agreement_fp_hex_to_bin(FP_ALICE, a_bin);
    salt_agreement_fp_hex_to_bin(FP_BOB, b_bin);

    /* pass 0/1: alice publishes (v1, v2); pass 2/3: bob publishes (v1, v2).
     * FP_ALICE < FP_BOB, so alice's entry is first in all four. */
    for (int pass = 0; pass < 4; pass++) {
        bool v2 = (pass & 1) != 0;
        bool me_alice = pass < 2;
        const char *my_fp = me_alice ? FP_ALICE : FP_BOB;
        const char *peer_fp = me_alice ? FP_BOB : FP_ALICE;
        const uint8_t *my_kyb = me_alice ? a_kyb_pk : b_kyb_pk;
        const uint8_t *peer_kyb = me_alice ? b_kyb_pk : a_kyb_pk;
        const uint8_t *my_ml = v2 ? (me_alice ? a_ml_pk : b_ml_pk) : NULL;
        const uint8_t *peer_ml = v2 ? (me_alice ? b_ml_pk : a_ml_pk) : NULL;
        const uint8_t *signer_sk = me_alice ? a_sign_sk : b_sign_sk;
        const uint8_t *signer_pk = me_alice ? a_sign_pk : b_sign_pk;

        memset(packet, 0xCC, PACKET_TOTAL_SIZE_V2);
        size_t total = 0;
        int rc = salt_agreement_build_packet(my_fp, peer_fp, salt, my_kyb, peer_kyb,
                                             my_ml, peer_ml, signer_sk, packet, &total);
        printf("nc1b.salt.pass%d.rc=%d total=%zu\n", pass, rc, total);
        CHECK(rc == 0, "salt_agreement_build_packet");
        if (rc != 0) continue;
        char name[64];
        snprintf(name, sizeof(name), "nc1b.salt.pass%d.version", pass);
        print_hex(name, packet, PACKET_VERSION_SIZE);
        size_t e1 = PACKET_VERSION_SIZE;
        size_t e2 = e1 + (v2 ? PACKET_ENTRY_SIZE_V2 : PACKET_ENTRY_SIZE);
        snprintf(name, sizeof(name), "nc1b.salt.pass%d.entry1_fp", pass);
        print_hex(name, packet + e1, FP_BIN_SIZE);
        snprintf(name, sizeof(name), "nc1b.salt.pass%d.entry2_fp", pass);
        print_hex(name, packet + e2, FP_BIN_SIZE);
        if (v2) {
            printf("nc1b.salt.pass%d.alg=%u,%u\n", pass,
                   (unsigned)packet[e1 + FP_BIN_SIZE], (unsigned)packet[e2 + FP_BIN_SIZE]);
        }
        uint16_t ver_be;
        memcpy(&ver_be, packet, 2);
        size_t dsize = salt_agreement_packet_data_size_for_version(ntohs(ver_be));
        printf("nc1b.salt.pass%d.data_size=%zu\n", pass, dsize);
        CHECK(dsize != 0 && total == dsize + QGP_DSA87_SIGNATURE_BYTES, "salt packet size");
        printf("nc1b.salt.pass%d.verify.signer=%d\n", pass,
               salt_agreement_packet_verify_signature(packet, total, dsize, signer_pk, NULL));
        printf("nc1b.salt.pass%d.verify.other_party_only=%d\n", pass,
               salt_agreement_packet_verify_signature(packet, total, dsize,
                                                      me_alice ? b_sign_pk : a_sign_pk, NULL));
        memset(got, 0, sizeof(got));
        rc = salt_agreement_packet_decrypt_salt(packet, total, a_bin, a_kyb_sk, a_ml_sk, got);
        printf("nc1b.salt.pass%d.decrypt.alice.rc=%d\n", pass, rc);
        CHECK(rc == 0 && memcmp(got, salt, 32) == 0, "nc1b salt decrypt alice");
        memset(got, 0, sizeof(got));
        rc = salt_agreement_packet_decrypt_salt(packet, total, b_bin, b_kyb_sk, b_ml_sk, got);
        printf("nc1b.salt.pass%d.decrypt.bob.rc=%d\n", pass, rc);
        CHECK(rc == 0 && memcmp(got, salt, 32) == 0, "nc1b salt decrypt bob");
        if (rc == 0) {
            snprintf(name, sizeof(name), "nc1b.salt.pass%d.decrypt.bob", pass);
            print_hex(name, got, 32);
        }
    }

    /* Refused inputs: a short fingerprint (either side). */
    size_t total = 0;
    printf("nc1b.salt.short_my_fp.rc=%d\n",
           salt_agreement_build_packet("abc", FP_BOB, salt, a_kyb_pk, b_kyb_pk,
                                       NULL, NULL, a_sign_sk, packet, &total));
    printf("nc1b.salt.short_peer_fp.rc=%d\n",
           salt_agreement_build_packet(FP_ALICE, "abc", salt, a_kyb_pk, b_kyb_pk,
                                       NULL, NULL, a_sign_sk, packet, &total));

out:
    free(a_sign_pk); free(a_sign_sk); free(b_sign_pk); free(b_sign_sk);
    free(a_kyb_pk); free(a_kyb_sk); free(b_kyb_pk); free(b_kyb_sk);
    free(a_ml_pk); free(a_ml_sk); free(b_ml_pk); free(b_ml_sk);
    free(packet);
}

/* ============================================================================
 * NC-1b: contact_request_codec — dht_contact_request_signing_preimage
 * ============================================================================ */
static void vec_nc1b_request_preimage(void) {
    dht_contact_request_t *req = calloc(1, sizeof(*req));
    uint8_t *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    if (!req || !sk) {
        CHECK(0, "nc1b request vector allocation");
        goto out;
    }

    /* The shape dht_send_contact_request builds: expiry = timestamp + TTL,
     * version 2 iff a salt is given, fingerprint = SHA3-512(pubkey). */
    for (int v = 1; v <= 2; v++) {
        memset(req, 0, sizeof(*req));
        req->magic = DHT_CONTACT_REQUEST_MAGIC;
        req->version = (uint8_t)v;
        req->timestamp = 1727700789ULL;
        req->expiry = req->timestamp + DHT_CONTACT_REQUEST_DEFAULT_TTL;
        dsa_keypair(0x53, req->sender_dilithium_pubkey, sk);
        fp_hex_of_pubkey(req->sender_dilithium_pubkey, req->sender_fingerprint);
        snprintf(req->sender_name, sizeof(req->sender_name), "%s", "alice");
        snprintf(req->message, sizeof(req->message), "%s", "Hey, add me!");
        if (v == 2) {
            fill_pattern(req->dht_salt, DHT_CONTACT_SALT_SIZE_CR, 0xD2);
            req->has_dht_salt = true;
        }

        uint8_t *pre = NULL;
        size_t pre_len = 0;
        int rc = dht_contact_request_signing_preimage(req, &pre, &pre_len);
        printf("nc1b.request.v%d.preimage.rc=%d len=%zu\n", v, rc, pre_len);
        CHECK(rc == 0, "signing preimage");
        if (rc != 0) continue;
        char name[64];
        snprintf(name, sizeof(name), "nc1b.request.v%d.preimage", v);
        print_hex(name, pre, pre_len);

        /* The preimage is the serialisation with signature_len 0, minus
         * its 2-byte length field. */
        uint8_t *ser = NULL;
        size_t ser_len = 0;
        req->signature_len = 0;
        rc = dht_serialize_contact_request(req, &ser, &ser_len);
        CHECK(rc == 0 && ser_len == pre_len + 2 && memcmp(ser, pre, pre_len) == 0,
              "preimage == serialize prefix");
        free(ser);
        free(pre);
    }

    /* Sign the preimage, verify with the codec (expiry far in the future:
     * dht_verify_contact_request reads time(NULL)). */
    memset(req, 0, sizeof(*req));
    req->magic = DHT_CONTACT_REQUEST_MAGIC;
    req->version = DHT_CONTACT_REQUEST_VERSION_SALT;
    req->timestamp = 1727700789ULL;
    req->expiry = UINT64_MAX;
    dsa_keypair(0x54, req->sender_dilithium_pubkey, sk);
    fp_hex_of_pubkey(req->sender_dilithium_pubkey, req->sender_fingerprint);
    memset(req->message, 'm', sizeof(req->message) - 1);   /* 255 chars, the maximum */
    req->message[sizeof(req->message) - 1] = '\0';
    fill_pattern(req->dht_salt, DHT_CONTACT_SALT_SIZE_CR, 0x0F);
    req->has_dht_salt = true;

    uint8_t *pre = NULL;
    size_t pre_len = 0;
    int rc = dht_contact_request_signing_preimage(req, &pre, &pre_len);
    printf("nc1b.request.signed.preimage.rc=%d len=%zu\n", rc, pre_len);
    if (rc == 0) {
        print_hex("nc1b.request.signed.preimage", pre, pre_len);
        size_t sig_len = DHT_DILITHIUM5_SIG_MAX_SIZE;
        CHECK(qgp_dsa87_sign(req->signature, &sig_len, pre, pre_len, sk) == 0, "sign preimage");
        req->signature_len = sig_len;
        free(pre);
        printf("nc1b.request.signed.verify.rc=%d\n", dht_verify_contact_request(req));
        CHECK(dht_verify_contact_request(req) == 0, "verify over preimage");
        req->dht_salt[31] ^= 0x01;
        printf("nc1b.request.signed.verify.salt_changed.rc=%d\n", dht_verify_contact_request(req));
    }

out:
    free(req);
    free(sk);
}

int main(void) {
    printf("# NC-1 codec extraction vectors\n");
    vec_offline_queue();
    vec_dm_outbox();
    vec_salt_agreement();
    vec_gek_wrap();
    vec_seal_multi();
    vec_contactlist();
    vec_contact_request();
    vec_nc1b_ack_value();
    vec_nc1b_contactlist_blob();
    vec_nc1b_salt_packet();
    vec_nc1b_request_preimage();
    printf("# failures=%d\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
