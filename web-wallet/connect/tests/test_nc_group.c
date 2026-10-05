/**
 * Nodus Connect groups — the codec layer (package G1) against the
 * independent oracle's vectors, web-wallet/test/fixtures/groups_kat.json
 * (generator groups_oracle.py; spec docs/plans/2026-10-05-connect-groups-
 * bytes.md items 1-7 + REV 2, approved in docs/plans/decisions/
 * 2026-10-05-groups-apt-bytes-approved.md).
 *
 * What it proves (no network):
 *   K1  the 8 tags are the oracle's 16-byte padded forms.
 *   K2  salt_v (3 versions), every DHT address (HEAD, KEY_PACKET x3,
 *       RECORD x3, OUTBOX at the vector day and at day 2^32-1): K and the
 *       "ncg:" key string byte-equal the oracle's.
 *   K3  KEK and wrapped key of the single vector and of EVERY entry of the
 *       three packets (1, 2 and 64 members) byte-equal the oracle's.
 *   K4  nc_group_kp_assemble from the oracle's fixed (kem_ct, ss) pairs
 *       gives the oracle's signed_preimage byte for byte (header, entry
 *       order by kem_ct, wraps); nc_group_kp_parse accepts the full
 *       packets; nc_group_kp_digest == the oracle's digest (bytes before
 *       sig_len, R2-2); prev_digest chain v1 -> v2 -> v3.
 *   K5  nc_group_kp_open with a REAL ML-DSA-87 signature over the
 *       oracle's preimage (test key, the oracle's owner_fp) finds and
 *       unwraps the group key for EVERY member of every version by trial
 *       (the decap hook returns the oracle's ss for its kem_ct, as the
 *       oracle's ss_of_ct does).
 *   K6  records: record_digest of every record value == the oracle's;
 *       nc_group_record_open opens each (count, members, name, created_at
 *       equal the inputs); the plaintexts parse.
 *   K7  HEAD preimages byte-equal; full HEADs parse; a real signature over
 *       the oracle's preimage verifies with nc_group_head_verify.
 *   K8  messages: nc_group_msg_aad == the oracle's AAD (144 B), H = AAD ||
 *       nonce, the item parses and its signed span == the oracle's
 *       signed_preimage; messages[0] re-signed with a test key verifies
 *       and opens to the oracle's text. messages[1] (empty text) is REFUSED
 *       at parse — decision 11 (see "How it can lie").
 *   K9  bucket bytes of 1 item from nc_group_bucket_encode equal the
 *       oracle's and decode against (group_id, v, day); the 2-item bucket
 *       carries the empty-text item: its layout is byte-checked by hand and
 *       encode / decode REFUSE it (decision 11).
 *   K10 day edges from timestamp_be64: day / refusal as the oracle.
 *   K11 invite / accept / welcome encode to the oracle's exact strings and
 *       parse back to the same fields.
 *   R1  every reject_cases entry is refused (12 cases), at the layer that
 *       owns it: structure, record count vs packet count, plaintext,
 *       trailing bytes, sig_len 4626, unwrap failure, over-cap ct_len.
 *   N1  negative: wrong owner key, wrong owner_fp / group / version,
 *       prev_digest conflict, missing predecessor, non-member, tampered
 *       preimage; HEAD wrong key / group; message wrong key / sender key /
 *       tampered ct; the removed member's old-version message refused once
 *       a newer version is held (accept rule); bucket caps (101 items,
 *       > 1 MiB, ct_len 4,001), day mismatch, duplicate message_id,
 *       trailing byte; address argument rules; JSON extra / missing /
 *       duplicate key, wrong v, uppercase or short hex, trailing bytes,
 *       key_version 0 and 2^32, unknown type, long name, embedded NUL.
 *   T1  round trips with the real primitives: kp_build (fresh ML-KEM
 *       encapsulation per member) opened by each member with
 *       nc_group_decap_mlkem; a non-member's key gets NO_ENTRY; a member
 *       key failing ek_check fails the whole build; record seal/open;
 *       message seal/open; HEAD build/verify; empty text refused on seal
 *       (decision 11).
 *   G3  (package G3, not from the oracle) nc_group_kp_open_pinned: the
 *       welcomed member opens packet v with the welcome's kp_digest and no
 *       packet of v-1; a different digest is PREV_CONFLICT, the signature
 *       is still checked first, a non-member finds no entry. The leave of
 *       decision 13 encodes to exactly its text and parses back; an extra
 *       invite_id, a missing / duplicate group_id and v = 2 are refused.
 *
 * What it requires: the native build of web-wallet/connect/tests (OpenSSL,
 * json-c); the vector file at the path compiled in (GROUPS_KAT, set by
 * CMakeLists.txt to web-wallet/test/fixtures/groups_kat.json). No
 * environment, no port.
 * What it leaves behind: nothing.
 * How it can lie:
 *   - The vectors are self-consistency vectors from the spec text (the
 *     oracle's own label): they prove this C matches the oracle's reading,
 *     not that the spec is sound.
 *   - The oracle's kem_ct are fixed random bytes, NOT ML-KEM ciphertexts:
 *     K4/K5/R1 inject the oracle's ss through the decap hook. The real
 *     ML-KEM path is exercised only by T1 (round trip, self-consistent).
 *   - The oracle's owner_fp / sender_fp are fixed bytes, not SHA3-512 of
 *     any key: the signatures here are made with a test key and verified
 *     against that key; the fp <-> key binding is not in this codec (it
 *     lives in nc_profile_read) and is not tested here.
 *   - Seals draw their own nonce (qgp_aes), so record and message seals are
 *     covered by round trip only; the byte vectors are checked on the open
 *     side.
 *   - Decision 11 (docs/plans/decisions/2026-10-04-connect-groups.md item
 *     11, operator 2026-10-05: group message text >= 1 byte, refused at seal
 *     and parse) overrides the oracle's reading 13, which calls an empty
 *     text valid (messages[1], and the 2-item bucket that carries it). The
 *     oracle file is unchanged; those vectors are asserted as REFUSED at
 *     parse / bucket encode / decode, and only their layout is compared.
 *     The oracle has no non-empty 2-item bucket, so a 2-item bucket is
 *     byte-compared against the oracle nowhere.
 */

#include "nc_group.h"

#include "crypto/enc/aes_keywrap.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef GROUPS_KAT
#error "GROUPS_KAT (path of groups_kat.json) is set by CMakeLists.txt"
#endif

static int passed, failed;
#define CHECK(cond, name) do {                                        \
    if (cond) { passed++; printf("  PASS %s\n", name); }              \
    else { failed++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

typedef uint8_t fp_t[NC_GROUP_FP_LEN];
typedef uint8_t ct_t[NC_GROUP_KEM_CT_LEN];
typedef uint8_t ss_t[NC_GROUP_SS_LEN];

/* ── vector file helpers ─────────────────────────────────────────────── */

static json_object *jget(json_object *o, const char *k) {
    json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v)) return NULL;
    return v;
}

static const char *jstr(json_object *o, const char *k) {
    json_object *v = jget(o, k);
    return v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : NULL;
}

static int64_t jint(json_object *o, const char *k) {
    json_object *v = jget(o, k);
    return v ? json_object_get_int64(v) : -1;
}

static int unhex_n(const char *s, uint8_t *out, size_t n) {
    if (!s || strlen(s) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* Fixed-length hex field; aborts the test run when the vector is malformed
 * (a vector we cannot read is not a pass). */
static void jhex(json_object *o, const char *k, uint8_t *out, size_t n) {
    if (unhex_n(jstr(o, k), out, n) != 0) {
        printf("  FATAL vector field %s is not %zu bytes of hex\n", k, n);
        exit(2);
    }
}

/* Variable-length hex field -> malloc'd buffer (at least 1 byte). */
static uint8_t *jhexdup(json_object *o, const char *k, size_t *n) {
    const char *s = jstr(o, k);
    if (!s || strlen(s) % 2) { printf("  FATAL vector field %s\n", k); exit(2); }
    *n = strlen(s) / 2;
    uint8_t *b = malloc(*n ? *n : 1);
    if (!b || unhex_n(s, b, *n) != 0) { printf("  FATAL vector field %s\n", k); exit(2); }
    return b;
}

/* ── shared vector state ─────────────────────────────────────────────── */

static uint8_t G_GID[NC_GROUP_ID_LEN], G_OWNER[NC_GROUP_FP_LEN], G_ADDR[32];
static uint8_t G_KEY[4][NC_GROUP_KEY_LEN];          /* index = v (1..3)     */
static uint8_t G_KP_DIGEST[4][NC_GROUP_DIGEST_LEN];
static uint8_t G_REC_DIGEST[4][NC_GROUP_DIGEST_LEN];
static uint8_t G_NAME[NC_GROUP_NAME_MAX];
static size_t  G_NAME_LEN;
static uint64_t G_CREATED;

/* test signing keys (NOT the oracle's: it has none) */
static uint8_t OWN_PK[NC_GROUP_DSA_PK_LEN], OWN_SK[NC_GROUP_DSA_SK_LEN];
static uint8_t OTH_PK[NC_GROUP_DSA_PK_LEN], OTH_SK[NC_GROUP_DSA_SK_LEN];

static void keypair(uint8_t pk[NC_GROUP_DSA_PK_LEN], uint8_t sk[NC_GROUP_DSA_SK_LEN],
                    uint8_t fill) {
    uint8_t seed[32];
    memset(seed, fill, sizeof(seed));
    if (qgp_dsa87_keypair_derand(pk, sk, seed) != 0) { printf("  FATAL keygen\n"); exit(2); }
}

/* pre || 4627 || ML-DSA-87(sk, pre); malloc'd. */
static uint8_t *sign_append(const uint8_t *pre, size_t pre_len, const uint8_t *sk,
                            size_t *out_len) {
    uint8_t *b = malloc(pre_len + 2 + NC_GROUP_SIG_LEN);
    size_t sl = 0;
    if (!b) exit(2);
    memcpy(b, pre, pre_len);
    b[pre_len] = (uint8_t)(NC_GROUP_SIG_LEN >> 8);
    b[pre_len + 1] = (uint8_t)(NC_GROUP_SIG_LEN & 0xff);
    if (qgp_dsa87_sign(b + pre_len + 2, &sl, pre, pre_len, sk) != 0 || sl != NC_GROUP_SIG_LEN) {
        printf("  FATAL sign\n");
        exit(2);
    }
    *out_len = pre_len + 2 + NC_GROUP_SIG_LEN;
    return b;
}

/* The oracle's ss_of_ct: kem_ct -> ss from the vectors; -1 when unknown. */
typedef struct { const ct_t *cts; const ss_t *sss; size_t n; } kat_decap_t;

static int kat_decap(uint8_t ss[NC_GROUP_SS_LEN], const uint8_t ct[NC_GROUP_KEM_CT_LEN],
                     void *user) {
    const kat_decap_t *t = user;
    for (size_t i = 0; i < t->n; i++)
        if (memcmp(t->cts[i], ct, NC_GROUP_KEM_CT_LEN) == 0) {
            memcpy(ss, t->sss[i], NC_GROUP_SS_LEN);
            return 0;
        }
    return -1;
}

/* All (kem_ct, ss) of the three packets — the decap table of every test. */
static ct_t ALL_CT[1 + 2 + 64];
static ss_t ALL_SS[1 + 2 + 64];
static size_t ALL_N;
static uint8_t *KP_PRE[4];          /* oracle signed_preimage per v        */
static size_t   KP_PRE_LEN[4];
static fp_t     KP_MEMBERS[4][NC_GROUP_MAX_MEMBERS];
static size_t   KP_COUNT[4];

/* ── K1 / K2 / K3 ────────────────────────────────────────────────────── */

static void test_tags_salt_addr_kek(json_object *J) {
    printf("K1 tags\n");
    json_object *tags = jget(J, "tags");
    static const nc_group_tag_id_t order[] = {
        NC_GROUP_TAG_GSALT, NC_GROUP_TAG_GADDR, NC_GROUP_TAG_GKP, NC_GROUP_TAG_GKEK,
        NC_GROUP_TAG_GREC, NC_GROUP_TAG_GHEAD, NC_GROUP_TAG_GMSG, NC_GROUP_TAG_GBKT };
    CHECK(json_object_array_length(tags) == 8, "8 tags in the vectors");
    for (size_t i = 0; i < 8; i++) {
        uint8_t want[NC_GROUP_TAG_LEN];
        json_object *t = json_object_array_get_idx(tags, i);
        jhex(t, "bytes", want, sizeof(want));
        char nm[64];
        snprintf(nm, sizeof(nm), "tag %s", jstr(t, "name"));
        CHECK(nc_group_tag(order[i]) && memcmp(nc_group_tag(order[i]), want, 16) == 0, nm);
    }
    CHECK(nc_group_tag(NC_GROUP_TAG_COUNT) == NULL, "unknown tag id -> NULL");

    printf("K2 salt_v\n");
    json_object *sv = jget(J, "salt_v");
    uint8_t salts[4][32];
    for (size_t i = 0; i < json_object_array_length(sv); i++) {
        json_object *e = json_object_array_get_idx(sv, i);
        uint32_t v = (uint32_t)jint(e, "v");
        uint8_t want[32], got[32];
        jhex(e, "salt_v", want, 32);
        char nm[64];
        snprintf(nm, sizeof(nm), "salt_v v=%u", v);
        CHECK(nc_group_salt_v(G_GID, G_KEY[v], v, got) == 0 && memcmp(got, want, 32) == 0, nm);
        memcpy(salts[v], got, 32);
    }
    uint8_t junk[32];
    CHECK(nc_group_salt_v(G_GID, G_KEY[1], 0, junk) == NC_GROUP_REFUSED, "salt_v v=0 refused");

    printf("K2 addresses\n");
    json_object *ad = jget(J, "addresses");
    for (size_t i = 0; i < json_object_array_length(ad); i++) {
        json_object *e = json_object_array_get_idx(ad, i);
        int purpose = (int)jint(e, "purpose");
        uint64_t x = (uint64_t)jint(e, "x");
        uint8_t secret[32], want[64], got[64];
        char gs[NC_GROUP_ADDR_STR_LEN + 1];
        jhex(e, "secret", secret, 32);
        jhex(e, "K", want, 64);
        char nm[96];
        snprintf(nm, sizeof(nm), "address purpose %d x=%llu", purpose, (unsigned long long)x);
        int rc = nc_group_addr((nc_group_purpose_t)purpose, G_GID, secret, x, got, gs);
        CHECK(rc == 0 && memcmp(got, want, 64) == 0 && strcmp(gs, jstr(e, "key_string")) == 0, nm);
    }
    uint8_t k[64];
    CHECK(nc_group_addr(NC_GROUP_PURPOSE_HEAD, G_GID, G_ADDR, 1, k, NULL) == NC_GROUP_REFUSED,
          "HEAD address with x != 0 refused");
    CHECK(nc_group_addr(NC_GROUP_PURPOSE_KEY_PACKET, G_GID, G_ADDR, 0, k, NULL) == NC_GROUP_REFUSED,
          "KEY_PACKET address with v = 0 refused");
    CHECK(nc_group_addr(NC_GROUP_PURPOSE_RECORD, G_GID, salts[1], 1ull << 32, k, NULL) ==
          NC_GROUP_REFUSED, "RECORD address with v = 2^32 refused");
    CHECK(nc_group_addr(NC_GROUP_PURPOSE_OUTBOX, G_GID, salts[2], 1ull << 32, k, NULL) ==
          NC_GROUP_REFUSED, "OUTBOX address with day = 2^32 refused");
    CHECK(nc_group_addr((nc_group_purpose_t)5, G_GID, G_ADDR, 0, k, NULL) == NC_GROUP_REFUSED,
          "unknown purpose refused");

    printf("K3 KEK / wrap single vector\n");
    json_object *kw = json_object_array_get_idx(jget(J, "kek_wrap"), 0);
    uint8_t ss[32], mfp[64], gk[32], wk[32], ww[40], kek[32], wr[40];
    jhex(kw, "ss", ss, 32);
    jhex(kw, "member_fp", mfp, 64);
    jhex(kw, "group_key", gk, 32);
    jhex(kw, "kek", wk, 32);
    jhex(kw, "wrapped", ww, 40);
    uint32_t v = (uint32_t)jint(kw, "v");
    CHECK(nc_group_kek(ss, G_GID, v, mfp, G_OWNER, kek) == 0 && memcmp(kek, wk, 32) == 0,
          "KEK == oracle");
    CHECK(nc_group_wrap(ss, G_GID, v, mfp, G_OWNER, gk, wr) == 0 && memcmp(wr, ww, 40) == 0,
          "wrapped == oracle");
}

/* ── K4 / K5 / K6 / K7 ──────────────────────────────────────────────── */

static void test_records(json_object *J) {
    printf("K6 records\n");
    json_object *rs = jget(J, "records");
    for (size_t i = 0; i < json_object_array_length(rs); i++) {
        json_object *e = json_object_array_get_idx(rs, i);
        uint32_t v = (uint32_t)jint(e, "v");
        size_t count = (size_t)jint(e, "count");
        size_t len, ptl;
        uint8_t *val = jhexdup(e, "value", &len);
        uint8_t *pt = jhexdup(e, "plaintext", &ptl);
        uint8_t want[64], got[64];
        jhex(e, "record_digest", want, 64);
        memcpy(G_REC_DIGEST[v], want, 64);
        char nm[96];
        snprintf(nm, sizeof(nm), "record v=%u digest == oracle", v);
        CHECK(nc_group_record_digest(val, len, got) == 0 && memcmp(got, want, 64) == 0, nm);

        nc_group_record_t *r = malloc(sizeof(*r));
        nc_group_rec_status_t st = nc_group_record_open(val, len, G_KEY[v], G_GID, v, want,
                                                        count, G_OWNER, r);
        snprintf(nm, sizeof(nm), "record v=%u opens", v);
        CHECK(st == NC_GROUP_REC_OK, nm);
        snprintf(nm, sizeof(nm), "record v=%u fields == inputs", v);
        CHECK(st == NC_GROUP_REC_OK && r->count == count && r->name_len == G_NAME_LEN &&
              memcmp(r->name, G_NAME, G_NAME_LEN) == 0 && r->created_at_ms == G_CREATED &&
              r->count == KP_COUNT[v] &&
              memcmp(r->members, KP_MEMBERS[v], count * NC_GROUP_FP_LEN) == 0, nm);
        snprintf(nm, sizeof(nm), "record v=%u plaintext parses", v);
        CHECK(nc_group_record_pt_parse(pt, ptl, r) == 0 && r->count == count, nm);
        snprintf(nm, sizeof(nm), "record v=%u wrong v refused", v);
        CHECK(nc_group_record_open(val, len, G_KEY[v], G_GID, v + 1, want, count, G_OWNER, r) ==
              NC_GROUP_REC_MISMATCH, nm);
        snprintf(nm, sizeof(nm), "record v=%u wrong key refused", v);
        CHECK(nc_group_record_open(val, len, G_KEY[v == 1 ? 2 : 1], G_GID, v, want, count,
                                   G_OWNER, r) == NC_GROUP_REC_BAD_AUTH, nm);
        uint8_t bad[64];
        memcpy(bad, want, 64);
        bad[0] ^= 1;
        snprintf(nm, sizeof(nm), "record v=%u digest other than the packet's refused", v);
        CHECK(nc_group_record_open(val, len, G_KEY[v], G_GID, v, bad, count, G_OWNER, r) ==
              NC_GROUP_REC_BAD_DIGEST, nm);
        uint8_t stranger[64];
        memset(stranger, 0xEE, 64);
        snprintf(nm, sizeof(nm), "record v=%u without the owner refused", v);
        CHECK(nc_group_record_open(val, len, G_KEY[v], G_GID, v, want, count, stranger, r) ==
              NC_GROUP_REC_NO_OWNER, nm);

        uint8_t salt[32];
        char gs[NC_GROUP_ADDR_STR_LEN + 1];
        nc_group_salt_v(G_GID, G_KEY[v], v, salt);
        snprintf(nm, sizeof(nm), "record v=%u address == oracle", v);
        CHECK(nc_group_addr(NC_GROUP_PURPOSE_RECORD, G_GID, salt, v, got, gs) == 0 &&
              strcmp(gs, jstr(e, "address_key_string")) == 0, nm);
        free(r);
        free(val);
        free(pt);
    }
}

static void test_packets(json_object *J) {
    printf("K3/K4 key packets\n");
    json_object *ks = jget(J, "key_packets");
    for (size_t i = 0; i < json_object_array_length(ks); i++) {
        json_object *e = json_object_array_get_idx(ks, i);
        uint32_t v = (uint32_t)jint(e, "v");
        size_t count = (size_t)jint(e, "count");
        size_t full_len;
        uint8_t *full = jhexdup(e, "full_with_dummy_signature", &full_len);
        KP_PRE[v] = jhexdup(e, "signed_preimage", &KP_PRE_LEN[v]);
        json_object *ents = jget(e, "entries");
        CHECK(json_object_array_length(ents) == count, "entry rows == count");

        /* entries in packet order (kem_ct ascending) */
        fp_t fps[NC_GROUP_MAX_MEMBERS];
        ct_t *cts = malloc(count * sizeof(ct_t));
        ss_t sss[NC_GROUP_MAX_MEMBERS];
        int kek_ok = 1, wrap_ok = 1;
        for (size_t j = 0; j < count; j++) {
            json_object *r = json_object_array_get_idx(ents, j);
            jhex(r, "member_fp", fps[j], 64);
            jhex(r, "ss", sss[j], 32);
            size_t off = (size_t)jint(r, "kem_ct_offset_in_packet");
            if (off + NC_GROUP_KEM_CT_LEN > full_len) { printf("  FATAL offset\n"); exit(2); }
            memcpy(cts[j], full + off, NC_GROUP_KEM_CT_LEN);   /* v=3 rows carry no kem_ct */
            if (jstr(r, "kem_ct")) {
                uint8_t c[NC_GROUP_KEM_CT_LEN];
                jhex(r, "kem_ct", c, sizeof(c));
                if (memcmp(c, cts[j], sizeof(c)) != 0) kek_ok = 0;
            }
            uint8_t wk[32], ww[40], kek[32], wr[40];
            jhex(r, "kek", wk, 32);
            jhex(r, "wrapped", ww, 40);
            if (nc_group_kek(sss[j], G_GID, v, fps[j], G_OWNER, kek) != 0 || memcmp(kek, wk, 32))
                kek_ok = 0;
            if (nc_group_wrap(sss[j], G_GID, v, fps[j], G_OWNER, G_KEY[v], wr) != 0 ||
                memcmp(wr, ww, 40))
                wrap_ok = 0;
            memcpy(ALL_CT[ALL_N], cts[j], NC_GROUP_KEM_CT_LEN);
            memcpy(ALL_SS[ALL_N], sss[j], NC_GROUP_SS_LEN);
            ALL_N++;
        }
        char nm[96];
        snprintf(nm, sizeof(nm), "packet v=%u every KEK == oracle (%zu)", v, count);
        CHECK(kek_ok, nm);
        snprintf(nm, sizeof(nm), "packet v=%u every wrapped key == oracle", v);
        CHECK(wrap_ok, nm);

        /* members ascending by fp, with their (ct, ss) */
        size_t idx[NC_GROUP_MAX_MEMBERS];
        for (size_t j = 0; j < count; j++) {
            size_t q = j;
            while (q > 0 && memcmp(fps[idx[q - 1]], fps[j], 64) > 0) { idx[q] = idx[q - 1]; q--; }
            idx[q] = j;
        }
        fp_t mf[NC_GROUP_MAX_MEMBERS];
        ct_t *mc = malloc(count * sizeof(ct_t));
        ss_t ms[NC_GROUP_MAX_MEMBERS];
        for (size_t j = 0; j < count; j++) {
            memcpy(mf[j], fps[idx[j]], 64);
            memcpy(mc[j], cts[idx[j]], NC_GROUP_KEM_CT_LEN);
            memcpy(ms[j], sss[idx[j]], 32);
        }
        memcpy(KP_MEMBERS[v], mf, count * 64);
        KP_COUNT[v] = count;

        nc_group_kp_hdr_t h;
        memset(&h, 0, sizeof(h));
        memcpy(h.group_id, G_GID, 32);
        memcpy(h.owner_fp, G_OWNER, 64);
        h.v = v;
        jhex(e, "prev_digest", h.prev_digest, 64);
        jhex(e, "record_digest", h.record_digest, 64);
        h.issued_at_ms = (uint64_t)jint(e, "issued_at_ms");
        uint8_t *pre = NULL;
        size_t pre_len = 0;
        int rc = nc_group_kp_assemble(&h, G_KEY[v], (const fp_t *)mf, (const ct_t *)mc,
                                      (const ss_t *)ms, count, &pre, &pre_len);
        snprintf(nm, sizeof(nm), "packet v=%u assemble == oracle signed_preimage", v);
        CHECK(rc == 0 && pre_len == KP_PRE_LEN[v] && memcmp(pre, KP_PRE[v], pre_len) == 0, nm);
        uint8_t hdr_want[NC_GROUP_KP_HEADER_LEN];
        jhex(e, "header", hdr_want, sizeof(hdr_want));
        snprintf(nm, sizeof(nm), "packet v=%u header == oracle", v);
        CHECK(rc == 0 && memcmp(pre, hdr_want, sizeof(hdr_want)) == 0, nm);
        free(pre);
        if (count >= 2) {
            memcpy(mc[1], mc[0], NC_GROUP_KEM_CT_LEN);
            pre = NULL;
            snprintf(nm, sizeof(nm), "packet v=%u assemble refuses a duplicate kem_ct", v);
            CHECK(nc_group_kp_assemble(&h, G_KEY[v], (const fp_t *)mf, (const ct_t *)mc,
                                       (const ss_t *)ms, count, &pre, &pre_len) ==
                  NC_GROUP_REFUSED && pre == NULL, nm);
            snprintf(nm, sizeof(nm), "packet v=%u assemble refuses unsorted members", v);
            fp_t sw[NC_GROUP_MAX_MEMBERS];
            memcpy(sw, mf, count * 64);
            memcpy(sw[0], mf[1], 64);
            memcpy(sw[1], mf[0], 64);
            CHECK(nc_group_kp_assemble(&h, G_KEY[v], (const fp_t *)sw, (const ct_t *)cts,
                                       (const ss_t *)ms, count, &pre, &pre_len) ==
                  NC_GROUP_REFUSED, nm);
        }

        size_t pc = 0;
        nc_group_kp_hdr_t ph;
        snprintf(nm, sizeof(nm), "packet v=%u full packet parses (count %zu, length %lld)",
                 v, count, (long long)jint(e, "full_length"));
        CHECK(nc_group_kp_parse(full, full_len, &ph, &pc) == 0 && pc == count &&
              ph.v == v && full_len == (size_t)jint(e, "full_length"), nm);
        uint8_t dw[64], dg[64];
        jhex(e, "digest", dw, 64);
        memcpy(G_KP_DIGEST[v], dw, 64);
        snprintf(nm, sizeof(nm), "packet v=%u digest (bytes before sig_len) == oracle", v);
        CHECK(nc_group_kp_digest(full, full_len, dg) == 0 && memcmp(dg, dw, 64) == 0, nm);
        snprintf(nm, sizeof(nm), "packet v=%u prev_digest chains to v-1", v);
        CHECK(v == 1 ? memcmp(h.prev_digest, (uint8_t[64]){0}, 64) == 0
                     : memcmp(h.prev_digest, G_KP_DIGEST[v - 1], 64) == 0, nm);

        char gs[NC_GROUP_ADDR_STR_LEN + 1];
        uint8_t k[64];
        snprintf(nm, sizeof(nm), "packet v=%u address == oracle", v);
        CHECK(nc_group_addr(NC_GROUP_PURPOSE_KEY_PACKET, G_GID, G_ADDR, v, k, gs) == 0 &&
              strcmp(gs, jstr(e, "address_key_string")) == 0, nm);
        free(cts);
        free(mc);
        free(full);
    }
}

static void test_packet_open(void) {
    printf("K5 key packet open (real signature over the oracle's preimage)\n");
    kat_decap_t tab = { (const ct_t *)ALL_CT, (const ss_t *)ALL_SS, ALL_N };
    for (uint32_t v = 1; v <= 3; v++) {
        size_t len;
        uint8_t *pkt = sign_append(KP_PRE[v], KP_PRE_LEN[v], OWN_SK, &len);
        const uint8_t *prev = v == 1 ? NULL : G_KP_DIGEST[v - 1];
        int all = 1;
        nc_group_kp_open_t o;
        for (size_t j = 0; j < KP_COUNT[v]; j++) {
            nc_group_kp_status_t st = nc_group_kp_open(pkt, len, OWN_PK, G_GID, G_OWNER, v, prev,
                                                       KP_MEMBERS[v][j], kat_decap, &tab, &o);
            if (st != NC_GROUP_KP_OK || memcmp(o.group_key, G_KEY[v], 32) != 0 ||
                memcmp(o.digest, G_KP_DIGEST[v], 64) != 0 || o.count != KP_COUNT[v])
                all = 0;
        }
        char nm[96];
        snprintf(nm, sizeof(nm), "v=%u every member (%zu) unwraps the group key by trial",
                 v, KP_COUNT[v]);
        CHECK(all, nm);

        if (v == 2) {
            const uint8_t *me = KP_MEMBERS[2][0];
            uint8_t other[64];
            memset(other, 0x5A, 64);
            CHECK(nc_group_kp_open(pkt, len, OTH_PK, G_GID, G_OWNER, 2, prev, me, kat_decap, &tab,
                                   &o) == NC_GROUP_KP_BAD_SIG, "N1 packet: another key's signature -> BAD_SIG");
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, G_GID, other, 2, prev, me, kat_decap, &tab,
                                   &o) == NC_GROUP_KP_MISMATCH, "N1 packet: wrong owner_fp -> MISMATCH");
            uint8_t gid2[32];
            memcpy(gid2, G_GID, 32);
            gid2[31] ^= 1;
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, gid2, G_OWNER, 2, prev, me, kat_decap, &tab,
                                   &o) == NC_GROUP_KP_MISMATCH, "N1 packet: wrong group -> MISMATCH");
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, G_GID, G_OWNER, 3, prev, me, kat_decap, &tab,
                                   &o) == NC_GROUP_KP_MISMATCH, "N1 packet: wrong version -> MISMATCH");
            uint8_t conflict[64];
            memcpy(conflict, prev, 64);
            conflict[10] ^= 0x80;
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, G_GID, G_OWNER, 2, conflict, me, kat_decap,
                                   &tab, &o) == NC_GROUP_KP_PREV_CONFLICT,
                  "N1 packet: prev_digest != stored digest of v-1 -> PREV_CONFLICT");
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, G_GID, G_OWNER, 2, NULL, me, kat_decap, &tab,
                                   &o) == NC_GROUP_KP_PREV_UNAVAILABLE,
                  "N1 packet: no stored digest of v-1 -> PREV_UNAVAILABLE");
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, G_GID, G_OWNER, 2, prev, other, kat_decap,
                                   &tab, &o) == NC_GROUP_KP_NO_ENTRY && o.group_key[0] == 0,
                  "N1 packet: a non-member finds no entry");
            /* G3: the welcomed member holds no packet of v-1; the welcome's
             * kp_digest (R2-7) pins packet v instead. */
            CHECK(nc_group_kp_open_pinned(pkt, len, OWN_PK, G_GID, G_OWNER, 2, G_KP_DIGEST[2], me,
                                          kat_decap, &tab, &o) == NC_GROUP_KP_OK &&
                  memcmp(o.group_key, G_KEY[2], 32) == 0 && memcmp(o.digest, G_KP_DIGEST[2], 64) == 0,
                  "pinned open: the welcome's kp_digest of v=2 opens packet 2 without packet 1");
            uint8_t wrong_pin[64];
            memcpy(wrong_pin, G_KP_DIGEST[2], 64);
            wrong_pin[0] ^= 1;
            CHECK(nc_group_kp_open_pinned(pkt, len, OWN_PK, G_GID, G_OWNER, 2, wrong_pin, me,
                                          kat_decap, &tab, &o) == NC_GROUP_KP_PREV_CONFLICT &&
                  o.group_key[0] == 0,
                  "N1 pinned open: a packet whose digest != the welcome's -> PREV_CONFLICT, no key");
            CHECK(nc_group_kp_open_pinned(pkt, len, OTH_PK, G_GID, G_OWNER, 2, G_KP_DIGEST[2], me,
                                          kat_decap, &tab, &o) == NC_GROUP_KP_BAD_SIG,
                  "N1 pinned open: another key's signature -> BAD_SIG (checked first)");
            CHECK(nc_group_kp_open_pinned(pkt, len, OWN_PK, G_GID, G_OWNER, 3, G_KP_DIGEST[2], me,
                                          kat_decap, &tab, &o) == NC_GROUP_KP_MISMATCH,
                  "N1 pinned open: wrong version -> MISMATCH");
            CHECK(nc_group_kp_open_pinned(pkt, len, OWN_PK, G_GID, G_OWNER, 2, NULL, me,
                                          kat_decap, &tab, &o) == NC_GROUP_KP_BAD_STRUCTURE,
                  "N1 pinned open: no pinned digest -> refused");
            CHECK(nc_group_kp_open_pinned(pkt, len, OWN_PK, G_GID, G_OWNER, 2, G_KP_DIGEST[2], other,
                                          kat_decap, &tab, &o) == NC_GROUP_KP_NO_ENTRY,
                  "N1 pinned open: a non-member finds no entry");
            pkt[100] ^= 1;
            CHECK(nc_group_kp_open(pkt, len, OWN_PK, G_GID, G_OWNER, 2, prev, me, kat_decap, &tab,
                                   &o) == NC_GROUP_KP_BAD_SIG, "N1 packet: tampered preimage -> BAD_SIG");
        }
        free(pkt);
    }
}

static void test_heads(json_object *J) {
    printf("K7 HEAD\n");
    json_object *hs = jget(J, "heads");
    for (size_t i = 0; i < json_object_array_length(hs); i++) {
        json_object *e = json_object_array_get_idx(hs, i);
        nc_group_head_t h;
        memset(&h, 0, sizeof(h));
        memcpy(h.group_id, G_GID, 32);
        memcpy(h.owner_fp, G_OWNER, 64);
        h.v = (uint32_t)jint(e, "v");
        jhex(e, "kp_digest", h.kp_digest, 64);
        h.issued_at_ms = (uint64_t)jint(e, "issued_at_ms");
        uint8_t want[NC_GROUP_HEAD_SIGNED_LEN], got[NC_GROUP_HEAD_SIGNED_LEN];
        jhex(e, "signed_preimage", want, sizeof(want));
        char nm[96];
        snprintf(nm, sizeof(nm), "HEAD v=%u preimage == oracle", h.v);
        CHECK(nc_group_head_preimage(&h, got) == 0 && memcmp(got, want, sizeof(got)) == 0, nm);
        snprintf(nm, sizeof(nm), "HEAD v=%u kp_digest == packet v digest", h.v);
        CHECK(memcmp(h.kp_digest, G_KP_DIGEST[h.v], 64) == 0, nm);
        size_t fl;
        uint8_t *full = jhexdup(e, "full_with_dummy_signature", &fl);
        nc_group_head_t ph;
        snprintf(nm, sizeof(nm), "HEAD v=%u full parses (%zu bytes)", h.v, fl);
        CHECK(nc_group_head_parse(full, fl, &ph) == 0 && ph.v == h.v && fl == NC_GROUP_HEAD_LEN, nm);
        snprintf(nm, sizeof(nm), "HEAD v=%u dummy signature does not verify", h.v);
        CHECK(nc_group_head_verify(full, fl, OWN_PK, G_GID, G_OWNER, &ph) == NC_GROUP_HEAD_BAD_SIG, nm);
        size_t sl;
        uint8_t *signed_head = sign_append(want, sizeof(want), OWN_SK, &sl);
        snprintf(nm, sizeof(nm), "HEAD v=%u real signature over the oracle preimage verifies", h.v);
        CHECK(nc_group_head_verify(signed_head, sl, OWN_PK, G_GID, G_OWNER, &ph) == NC_GROUP_HEAD_OK &&
              ph.v == h.v && memcmp(ph.kp_digest, h.kp_digest, 64) == 0, nm);
        if (h.v == 2) {
            CHECK(nc_group_head_verify(signed_head, sl, OTH_PK, G_GID, G_OWNER, &ph) ==
                  NC_GROUP_HEAD_BAD_SIG, "N1 HEAD: another key -> BAD_SIG");
            uint8_t gid2[32];
            memcpy(gid2, G_GID, 32);
            gid2[0] ^= 1;
            CHECK(nc_group_head_verify(signed_head, sl, OWN_PK, gid2, G_OWNER, &ph) ==
                  NC_GROUP_HEAD_MISMATCH, "N1 HEAD: wrong group -> MISMATCH");
            char gs[NC_GROUP_ADDR_STR_LEN + 1];
            uint8_t k[64];
            CHECK(nc_group_addr(NC_GROUP_PURPOSE_HEAD, G_GID, G_ADDR, 0, k, gs) == 0 &&
                  strcmp(gs, jstr(e, "address_key_string")) == 0, "HEAD address == oracle");
            uint8_t built[NC_GROUP_HEAD_LEN];
            CHECK(nc_group_head_build(&h, OWN_PK, OWN_SK, built) == 0 &&
                  memcmp(built, want, sizeof(want)) == 0 &&
                  nc_group_head_verify(built, sizeof(built), OWN_PK, G_GID, G_OWNER, &ph) ==
                      NC_GROUP_HEAD_OK, "T1 HEAD build -> verify");
        }
        free(signed_head);
        free(full);
    }
}

/* ── K8 / K9 / K10 ───────────────────────────────────────────────────── */

static uint8_t *MSG_ITEM[2];
static size_t   MSG_ITEM_LEN[2];
static uint32_t MSG_DAY;

static void test_messages(json_object *J) {
    printf("K8 messages\n");
    json_object *ms = jget(J, "messages");
    for (size_t i = 0; i < json_object_array_length(ms); i++) {
        json_object *e = json_object_array_get_idx(ms, i);
        uint32_t v = (uint32_t)jint(e, "v");
        uint8_t sender[64], mid[16], nonce[12], aad_w[144], H_w[156], aad[144];
        jhex(e, "sender_fp", sender, 64);
        jhex(e, "message_id", mid, 16);
        jhex(e, "nonce", nonce, 12);
        jhex(e, "aad", aad_w, 144);
        jhex(e, "H", H_w, 156);
        uint64_t ts = (uint64_t)jint(e, "timestamp_ms");
        char nm[96];
        snprintf(nm, sizeof(nm), "message %zu AAD (144 B) == oracle", i);
        CHECK(nc_group_msg_aad(G_GID, v, sender, mid, ts, aad) == 0 &&
              memcmp(aad, aad_w, 144) == 0, nm);
        snprintf(nm, sizeof(nm), "message %zu H = AAD || nonce", i);
        CHECK(memcmp(H_w, aad, 144) == 0 && memcmp(H_w + 144, nonce, 12) == 0, nm);

        MSG_ITEM[i] = jhexdup(e, "item_with_dummy_signature", &MSG_ITEM_LEN[i]);
        size_t spl, tl;
        uint8_t *sp = jhexdup(e, "signed_preimage", &spl);
        uint8_t *text = jhexdup(e, "text_utf8", &tl);
        nc_group_msg_t m;
        int prc = nc_group_msg_parse(MSG_ITEM[i], MSG_ITEM_LEN[i], true, &m);
        if (tl == 0) {
            /* DECISION 11 (docs/plans/decisions/2026-10-04-connect-groups.md
             * item 11, operator 2026-10-05: group message text >= 1 byte,
             * refused at seal AND parse). The oracle's reading 13 — written
             * before the decision — calls this empty-text item valid; the
             * oracle file is not changed. The item is refused at PARSE (the
             * ct_len field), so it is never opened; its signed span is
             * checked by hand against the oracle's layout instead. */
            snprintf(nm, sizeof(nm), "message %zu (empty text) REFUSED at parse (decision 11)", i);
            CHECK(prc == NC_GROUP_REFUSED && m.h == NULL, nm);
            snprintf(nm, sizeof(nm), "message %zu (empty text) layout: H || ct_len 0 || tag", i);
            CHECK(spl == NC_GROUP_MSG_H_LEN + 4 + NC_GROUP_GCM_TAG_LEN &&
                  memcmp(sp, H_w, NC_GROUP_MSG_H_LEN) == 0 &&
                  sp[NC_GROUP_MSG_H_LEN] == 0 && sp[NC_GROUP_MSG_H_LEN + 1] == 0 &&
                  sp[NC_GROUP_MSG_H_LEN + 2] == 0 && sp[NC_GROUP_MSG_H_LEN + 3] == 0 &&
                  MSG_ITEM_LEN[i] == spl + 2 + NC_GROUP_SIG_LEN &&
                  memcmp(MSG_ITEM[i], sp, spl) == 0, nm);
            size_t sl0;
            uint8_t *item0 = sign_append(sp, spl, OWN_SK, &sl0);
            nc_group_msg_t m0;
            snprintf(nm, sizeof(nm), "message %zu (empty text) with a real signature REFUSED at parse", i);
            CHECK(nc_group_msg_parse(item0, sl0, true, &m0) == NC_GROUP_REFUSED &&
                  nc_group_msg_parse(item0, sl0, false, &m0) == NC_GROUP_REFUSED, nm);
            free(item0);
            free(sp);
            free(text);
            continue;
        }
        snprintf(nm, sizeof(nm), "message %zu item parses, signed span == oracle", i);
        CHECK(prc == 0 && m.signed_len == spl && memcmp(MSG_ITEM[i], sp, spl) == 0 &&
              m.v == v && m.day == (uint32_t)jint(e, "day") && m.timestamp_ms == ts &&
              memcmp(m.sender_fp, sender, 64) == 0 && m.ct_len == tl, nm);
        if (prc == 0) MSG_DAY = m.day;

        size_t sl;
        uint8_t *item = sign_append(sp, spl, OWN_SK, &sl);
        nc_group_msg_t ms2;
        uint8_t out[NC_GROUP_TEXT_MAX];
        size_t ol = 0;
        nc_group_msg_parse(item, sl, true, &ms2);
        nc_group_msg_status_t st = nc_group_msg_open(&ms2, G_KEY[v], OWN_PK, out, &ol);
        snprintf(nm, sizeof(nm), "message %zu re-signed verifies and opens to the oracle text", i);
        CHECK(st == NC_GROUP_MSG_OK && ol == tl && memcmp(out, text, tl) == 0, nm);
        CHECK(nc_group_msg_open(&ms2, G_KEY[1], OWN_PK, out, &ol) == NC_GROUP_MSG_BAD_AUTH,
              "N1 message: key of another version -> BAD_AUTH");
        CHECK(nc_group_msg_open(&ms2, G_KEY[v], OTH_PK, out, &ol) == NC_GROUP_MSG_BAD_SIG,
              "N1 message: another sender key -> BAD_SIG");
        item[NC_GROUP_MSG_H_LEN + 4] ^= 1;                    /* first ct byte */
        CHECK(nc_group_msg_open(&ms2, G_KEY[v], OWN_PK, out, &ol) == NC_GROUP_MSG_BAD_SIG,
              "N1 message: tampered ct -> BAD_SIG (signature first)");
        CHECK(nc_group_msg_open(&m, G_KEY[v], OWN_PK, out, &ol) == NC_GROUP_MSG_BAD_SIG,
              "message with the oracle's dummy signature -> BAD_SIG");
        free(item);
        free(sp);
        free(text);
    }
}

static void test_buckets(json_object *J) {
    printf("K9 buckets\n");
    json_object *bs = jget(J, "buckets");
    uint8_t salt2[32];
    nc_group_salt_v(G_GID, G_KEY[2], 2, salt2);
    for (size_t i = 0; i < json_object_array_length(bs); i++) {
        json_object *e = json_object_array_get_idx(bs, i);
        json_object *its = jget(e, "items");
        size_t n = json_object_array_length(its);
        const uint8_t *items[2];
        size_t lens[2];
        int has_empty = 0;
        for (size_t j = 0; j < n; j++) {
            int which = json_object_get_int(json_object_array_get_idx(its, j));
            items[j] = MSG_ITEM[which];
            lens[j] = MSG_ITEM_LEN[which];
            const uint8_t *cl = items[j] + NC_GROUP_MSG_H_LEN;      /* ct_len field */
            if (lens[j] > NC_GROUP_MSG_H_LEN + 4 && (cl[0] | cl[1] | cl[2] | cl[3]) == 0)
                has_empty = 1;
        }
        size_t wl;
        uint8_t *want = jhexdup(e, "bytes", &wl);
        uint8_t *got = NULL;
        size_t gl = 0;
        char nm[96];
        if (has_empty) {
            /* DECISION 11 (2026-10-04-connect-groups.md item 11): this oracle
             * bucket carries messages[1], the empty-text item (reading 13,
             * written before the decision). Its layout is checked by hand
             * (tag || count || items in order); encode and decode REFUSE it. */
            size_t o = 18;
            int layout = wl >= 18 && memcmp(want, nc_group_tag(NC_GROUP_TAG_GBKT), 16) == 0 &&
                         want[16] == (uint8_t)(n >> 8) && want[17] == (uint8_t)n;
            for (size_t j = 0; layout && j < n; j++) {
                layout = o + lens[j] <= wl && memcmp(want + o, items[j], lens[j]) == 0;
                o += lens[j];
            }
            snprintf(nm, sizeof(nm), "bucket of %zu item(s) with empty text: layout == oracle", n);
            CHECK(layout && o == wl, nm);
            snprintf(nm, sizeof(nm), "bucket of %zu item(s) with empty text: encode REFUSED (decision 11)", n);
            CHECK(nc_group_bucket_encode(items, lens, n, &got, &gl) == NC_GROUP_REFUSED &&
                  got == NULL, nm);
            nc_group_msg_t *dec = NULL;
            size_t dc = 0;
            snprintf(nm, sizeof(nm), "bucket of %zu item(s) with empty text: decode REFUSED (decision 11)", n);
            CHECK(nc_group_bucket_decode(want, wl, G_GID, 2, MSG_DAY, &dec, &dc) ==
                  NC_GROUP_REFUSED && dec == NULL && dc == 0, nm);
            char gs0[NC_GROUP_ADDR_STR_LEN + 1];
            uint8_t k0[64];
            snprintf(nm, sizeof(nm), "bucket %zu address == oracle", i);
            CHECK(nc_group_addr(NC_GROUP_PURPOSE_OUTBOX, G_GID, salt2, MSG_DAY, k0, gs0) == 0 &&
                  strcmp(gs0, jstr(e, "address_key_string")) == 0, nm);
            free(want);
            continue;
        }
        snprintf(nm, sizeof(nm), "bucket of %zu item(s) == oracle", n);
        CHECK(nc_group_bucket_encode(items, lens, n, &got, &gl) == 0 && gl == wl &&
              memcmp(got, want, wl) == 0, nm);
        nc_group_msg_t *dec = NULL;
        size_t dc = 0;
        snprintf(nm, sizeof(nm), "bucket of %zu item(s) decodes", n);
        CHECK(nc_group_bucket_decode(want, wl, G_GID, 2, MSG_DAY, &dec, &dc) == 0 && dc == n &&
              dec[n - 1].item_len == lens[n - 1], nm);
        free(dec);
        dec = NULL;
        CHECK(nc_group_bucket_decode(want, wl, G_GID, 2, MSG_DAY + 1, &dec, &dc) ==
              NC_GROUP_REFUSED, "N1 bucket: day other than the address day refused");
        CHECK(nc_group_bucket_decode(want, wl, G_GID, 3, MSG_DAY, &dec, &dc) ==
              NC_GROUP_REFUSED, "N1 bucket: version other than the address version refused");
        uint8_t *tr = malloc(wl + 1);
        memcpy(tr, want, wl);
        tr[wl] = 0;
        CHECK(nc_group_bucket_decode(tr, wl + 1, G_GID, 2, MSG_DAY, &dec, &dc) ==
              NC_GROUP_REFUSED, "N1 bucket: trailing byte refused");
        free(tr);
        char gs[NC_GROUP_ADDR_STR_LEN + 1];
        uint8_t k[64];
        snprintf(nm, sizeof(nm), "bucket %zu address == oracle", i);
        CHECK(nc_group_addr(NC_GROUP_PURPOSE_OUTBOX, G_GID, salt2, MSG_DAY, k, gs) == 0 &&
              strcmp(gs, jstr(e, "address_key_string")) == 0, nm);
        free(got);
        free(want);
    }

    /* caps and duplicates */
    const uint8_t *many[101];
    size_t many_len[101];
    for (int j = 0; j < 101; j++) { many[j] = MSG_ITEM[0]; many_len[j] = MSG_ITEM_LEN[0]; }
    uint8_t *out = NULL;
    size_t ol = 0;
    CHECK(nc_group_bucket_encode(many, many_len, 101, &out, &ol) == NC_GROUP_REFUSED,
          "N1 bucket: 101 items refused (encode)");
    CHECK(nc_group_bucket_encode(many, many_len, 2, &out, &ol) == NC_GROUP_REFUSED,
          "N1 bucket: duplicate message_id refused (encode)");
    /* hand-made: count field 101 */
    uint8_t hdr[18];
    memcpy(hdr, nc_group_tag(NC_GROUP_TAG_GBKT), 16);
    hdr[16] = 0; hdr[17] = 101;
    nc_group_msg_t *dec = NULL;
    size_t dc = 0;
    CHECK(nc_group_bucket_decode(hdr, sizeof(hdr), G_GID, 2, MSG_DAY, &dec, &dc) ==
          NC_GROUP_REFUSED, "N1 bucket: count field 101 refused (decode)");
    hdr[17] = 0;
    CHECK(nc_group_bucket_decode(hdr, sizeof(hdr), G_GID, 2, MSG_DAY, &dec, &dc) == 0 &&
          dc == 0 && dec == NULL, "bucket with count 0 decodes to nothing");
    /* two copies of the same item: duplicate message_id */
    size_t dl = 18 + 2 * MSG_ITEM_LEN[0];
    uint8_t *dup = malloc(dl);
    memcpy(dup, hdr, 18);
    dup[17] = 2;
    memcpy(dup + 18, MSG_ITEM[0], MSG_ITEM_LEN[0]);
    memcpy(dup + 18 + MSG_ITEM_LEN[0], MSG_ITEM[0], MSG_ITEM_LEN[0]);
    CHECK(nc_group_bucket_decode(dup, dl, G_GID, 2, MSG_DAY, &dec, &dc) == NC_GROUP_REFUSED,
          "N1 bucket: duplicate message_id refused (decode)");
    free(dup);
    /* over 1 MiB */
    uint8_t *big = calloc(1, NC_GROUP_BUCKET_MAX + 1);
    memcpy(big, hdr, 18);
    big[17] = 1;
    CHECK(nc_group_bucket_decode(big, NC_GROUP_BUCKET_MAX + 1, G_GID, 2, MSG_DAY, &dec, &dc) ==
          NC_GROUP_REFUSED, "N1 bucket: more than 1 MiB refused before parsing");
    free(big);
    /* ct_len 4,001: an item whose length field is over the text cap */
    size_t il = NC_GROUP_MSG_H_LEN + 4 + 4001 + 16 + 2 + NC_GROUP_SIG_LEN;
    uint8_t *it = calloc(1, il);
    memcpy(it, MSG_ITEM[0], NC_GROUP_MSG_H_LEN);
    it[NC_GROUP_MSG_H_LEN + 2] = 0x0f; it[NC_GROUP_MSG_H_LEN + 3] = 0xa1;   /* 4001 */
    it[NC_GROUP_MSG_H_LEN + 4 + 4001 + 16] = 0x12; it[NC_GROUP_MSG_H_LEN + 4 + 4001 + 17] = 0x13;
    nc_group_msg_t m;
    CHECK(nc_group_msg_parse(it, il, true, &m) == NC_GROUP_REFUSED,
          "N1 message: ct_len 4,001 (> 4,000 text cap) refused");
    free(it);
}

static void test_days(json_object *J) {
    printf("K10 day edges\n");
    json_object *de = jget(J, "day_edges");
    for (size_t i = 0; i < json_object_array_length(de); i++) {
        json_object *e = json_object_array_get_idx(de, i);
        uint8_t be[8];
        jhex(e, "timestamp_be64", be, 8);
        uint64_t ts = 0;
        for (int j = 0; j < 8; j++) ts = ts << 8 | be[j];
        json_object *jv = jget(e, "valid");
        int valid = jv && json_object_get_boolean(jv);
        uint32_t d = 0xdeadbeef;
        int rc = nc_group_day(ts, &d);
        char nm[128];
        snprintf(nm, sizeof(nm), "day: %s", jstr(e, "note"));
        if (valid)
            CHECK(rc == 0 && d == (uint32_t)jint(e, "day"), nm);
        else
            CHECK(rc == NC_GROUP_REFUSED && d == 0, nm);
    }
}

/* ── K11 JSON ────────────────────────────────────────────────────────── */

static int json_refused(const char *s) {
    nc_group_json_t j;
    return nc_group_json_parse(s, strlen(s), &j) == NC_GROUP_REFUSED;
}

static void test_json(json_object *J) {
    printf("K11 invite / accept / welcome JSON\n");
    json_object *js = jget(J, "json_1to1");
    uint8_t iid[16];
    jhex(js, "invite_id", iid, 16);
    char *s = NULL;
    size_t n = 0;
    nc_group_json_t p;

    CHECK(nc_group_invite_encode(G_GID, G_OWNER, (const char *)G_NAME, G_NAME_LEN, iid, &s, &n) == 0 &&
          strcmp(s, jstr(js, "invite")) == 0, "invite encodes to the oracle string");
    CHECK(nc_group_json_parse(s, n, &p) == 0 && p.type == NC_GROUP_JSON_INVITE &&
          memcmp(p.group_id, G_GID, 32) == 0 && memcmp(p.owner_fp, G_OWNER, 64) == 0 &&
          p.name_len == G_NAME_LEN && memcmp(p.name, G_NAME, G_NAME_LEN) == 0 &&
          memcmp(p.invite_id, iid, 16) == 0, "invite parses back");
    free(s);

    CHECK(nc_group_accept_encode(G_GID, iid, &s, &n) == 0 && strcmp(s, jstr(js, "accept")) == 0,
          "accept encodes to the oracle string");
    CHECK(nc_group_json_parse(s, n, &p) == 0 && p.type == NC_GROUP_JSON_ACCEPT &&
          memcmp(p.group_id, G_GID, 32) == 0 && memcmp(p.invite_id, iid, 16) == 0,
          "accept parses back");
    free(s);

    CHECK(nc_group_welcome_encode(G_GID, G_OWNER, G_ADDR, 2, G_KP_DIGEST[2], iid, &s, &n) == 0 &&
          strcmp(s, jstr(js, "welcome")) == 0, "welcome encodes to the oracle string");
    CHECK(nc_group_json_parse(s, n, &p) == 0 && p.type == NC_GROUP_JSON_WELCOME &&
          memcmp(p.addr_secret, G_ADDR, 32) == 0 && p.key_version == 2 &&
          memcmp(p.kp_digest, G_KP_DIGEST[2], 64) == 0 && memcmp(p.owner_fp, G_OWNER, 64) == 0,
          "welcome parses back (binds key_version 2 + kp_digest of packet 2)");
    free(s);

    /* reordered keys are accepted (reading 16) */
    CHECK(!json_refused("{\"v\":1,\"type\":\"nodus_group_accept\",\"invite_id\":"
                        "\"66a4748139466f1eb8cde7d992b792e8\",\"group_id\":"
                        "\"046288016855da5ecd5322faee0847801c86fb6f305514547854d381171789ba\"}"),
          "accept with keys in another order parses");
    const char *gid = "046288016855da5ecd5322faee0847801c86fb6f305514547854d381171789ba";
    const char *iids = "66a4748139466f1eb8cde7d992b792e8";
    char b[1024];
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\",\"x\":1}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: extra key refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\"}", gid);
    CHECK(json_refused(b), "N1 JSON: missing invite_id refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"group_id\":\"%s\",\"invite_id\":\"%s\"}", gid, gid, iids);
    CHECK(json_refused(b), "N1 JSON: duplicate key refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":2,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: v = 2 refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":\"1\",\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: v as a string refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1.0,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: v as a double refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"66A4748139466F1EB8CDE7D992B792E8\"}", gid);
    CHECK(json_refused(b), "N1 JSON: uppercase hex refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"66a4748139466f1eb8cde7d992b792\"}", gid);
    CHECK(json_refused(b), "N1 JSON: short invite_id refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"} ", gid, iids);
    CHECK(json_refused(b), "N1 JSON: trailing whitespace refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}x", gid, iids);
    CHECK(json_refused(b), "N1 JSON: trailing non-whitespace byte refused");
    snprintf(b, sizeof(b), " {\"type\":\"nodus_group_accept\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: leading whitespace refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_join\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: unknown type refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_accept\\u0000x\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: type with a NUL suffix refused");
    char own[129];
    for (int i = 0; i < 128; i++) own[i] = 'a';
    own[128] = 0;
    char dig[129];
    memcpy(dig, own, sizeof(dig));
    const char *sec = "bf16d9d9d48839395692712733e5618baf18c83c8877f2d444cbeba7190487f5";
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_welcome\",\"v\":1,\"group_id\":\"%s\","
             "\"owner\":\"%s\",\"addr_secret\":\"%s\",\"key_version\":0,\"kp_digest\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, own, sec, dig, iids);
    CHECK(json_refused(b), "N1 JSON: key_version 0 refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_welcome\",\"v\":1,\"group_id\":\"%s\","
             "\"owner\":\"%s\",\"addr_secret\":\"%s\",\"key_version\":4294967296,"
             "\"kp_digest\":\"%s\",\"invite_id\":\"%s\"}", gid, own, sec, dig, iids);
    CHECK(json_refused(b), "N1 JSON: key_version 2^32 refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_welcome\",\"v\":1,\"group_id\":\"%s\","
             "\"owner\":\"%s\",\"addr_secret\":\"%s\",\"key_version\":4294967295,"
             "\"kp_digest\":\"%s\",\"invite_id\":\"%s\"}", gid, own, sec, dig, iids);
    CHECK(!json_refused(b), "welcome with key_version 2^32-1 parses");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_invite\",\"v\":1,\"group_id\":\"%s\","
             "\"owner\":\"%s\",\"name\":\"%s\",\"invite_id\":\"%s\"}", gid, own,
             "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN", iids);
    CHECK(json_refused(b), "N1 JSON: 65-byte name refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_invite\",\"v\":1,\"group_id\":\"%s\","
             "\"owner\":\"%s\",\"name\":\"a\\u0000b\",\"invite_id\":\"%s\"}", gid, own, iids);
    CHECK(json_refused(b), "N1 JSON: NUL inside the name refused");
    CHECK(nc_group_invite_encode(G_GID, G_OWNER, "\xff\xfe", 2, iid, &s, &n) != 0 && s == NULL,
          "N1 JSON: invite with a non-UTF-8 name is not encoded");
    char nul[] = "{\"type\":\"nodus_group_accept\"}";
    CHECK(nc_group_json_parse(nul, sizeof(nul), &p) == NC_GROUP_REFUSED,
          "N1 JSON: NUL byte inside the input refused");

    /* G3 — the leave (decision 13): exactly its text, three fields. */
    char want_leave[160];
    snprintf(want_leave, sizeof(want_leave),
             "{\"type\":\"nodus_group_leave\",\"v\":1,\"group_id\":\"%s\"}", gid);
    CHECK(nc_group_leave_encode(G_GID, &s, &n) == 0 && strcmp(s, want_leave) == 0 &&
          n == strlen(want_leave), "leave encodes to the text of decision 13");
    CHECK(nc_group_json_parse(s, n, &p) == 0 && p.type == NC_GROUP_JSON_LEAVE &&
          memcmp(p.group_id, G_GID, 32) == 0 &&
          memcmp(p.invite_id, (uint8_t[16]){0}, 16) == 0, "leave parses back (no invite_id)");
    free(s);
    CHECK(!json_refused(want_leave), "leave of decision 13 parses");
    snprintf(b, sizeof(b), "{\"v\":1,\"group_id\":\"%s\",\"type\":\"nodus_group_leave\"}", gid);
    CHECK(!json_refused(b), "leave with keys in another order parses");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_leave\",\"v\":1,\"group_id\":\"%s\","
             "\"invite_id\":\"%s\"}", gid, iids);
    CHECK(json_refused(b), "N1 JSON: leave with an invite_id refused (extra key)");
    CHECK(json_refused("{\"type\":\"nodus_group_leave\",\"v\":1}"),
          "N1 JSON: leave without group_id refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_leave\",\"v\":1,\"group_id\":\"%s\","
             "\"group_id\":\"%s\"}", gid, gid);
    CHECK(json_refused(b), "N1 JSON: leave with a duplicate group_id refused");
    snprintf(b, sizeof(b), "{\"type\":\"nodus_group_leave\",\"v\":2,\"group_id\":\"%s\"}", gid);
    CHECK(json_refused(b), "N1 JSON: leave v = 2 refused");
    CHECK(nc_group_leave_encode(NULL, &s, &n) == NC_GROUP_REFUSED && s == NULL,
          "N1 JSON: leave without a group id is not encoded");
}

/* ── R1 reject cases ─────────────────────────────────────────────────── */

static void test_rejects(json_object *J) {
    printf("R1 reject cases\n");
    json_object *rs = jget(J, "reject_cases");
    kat_decap_t tab = { (const ct_t *)ALL_CT, (const ss_t *)ALL_SS, ALL_N };
    size_t seen = 0;
    for (size_t i = 0; i < json_object_array_length(rs); i++) {
        json_object *e = json_object_array_get_idx(rs, i);
        const char *id = jstr(e, "id");
        char nm[128];
        snprintf(nm, sizeof(nm), "reject %s", id);
        size_t len = 0;
        uint8_t *b = NULL;
        nc_group_record_t *r = malloc(sizeof(*r));
        seen++;
        if (strcmp(id, "kp_count_field_vs_entries") == 0 ||
            strcmp(id, "kp_duplicate_kem_ct") == 0 ||
            strcmp(id, "kp_trailing_byte") == 0 ||
            strcmp(id, "kp_sig_len_4626") == 0) {
            b = jhexdup(e, "bytes", &len);
            uint8_t d[64];
            CHECK(nc_group_kp_parse(b, len, NULL, NULL) == NC_GROUP_REFUSED &&
                  nc_group_kp_digest(b, len, d) == NC_GROUP_REFUSED, nm);
        } else if (strcmp(id, "head_trailing_byte") == 0 ||
                   strcmp(id, "head_sig_len_4626") == 0) {
            b = jhexdup(e, "bytes", &len);
            nc_group_head_t h;
            CHECK(nc_group_head_parse(b, len, &h) == NC_GROUP_REFUSED &&
                  nc_group_head_verify(b, len, OWN_PK, G_GID, G_OWNER, &h) ==
                      NC_GROUP_HEAD_BAD_STRUCTURE, nm);
        } else if (strcmp(id, "kp_count_vs_record_count") == 0) {
            size_t rl;
            uint8_t *pk = jhexdup(e, "packet_bytes", &len);
            uint8_t *rec = jhexdup(e, "record_bytes", &rl);
            uint8_t rd[64], gk[32];
            jhex(e, "record_digest", rd, 64);
            jhex(e, "group_key", gk, 32);
            size_t pc = 0;
            nc_group_kp_hdr_t h;
            int prc = nc_group_kp_parse(pk, len, &h, &pc);
            CHECK(prc == 0 && pc == 2 && memcmp(h.record_digest, rd, 64) == 0 &&
                  nc_group_record_open(rec, rl, gk, G_GID, 2, h.record_digest, pc, G_OWNER, r) ==
                      NC_GROUP_REC_COUNT, nm);
            free(pk);
            free(rec);
        } else if (strcmp(id, "record_count_field_vs_members") == 0 ||
                   strcmp(id, "record_duplicate_member") == 0) {
            size_t ptl;
            uint8_t *pt = jhexdup(e, "plaintext", &ptl);
            b = jhexdup(e, "bytes", &len);
            uint8_t gk[32], d[64];
            jhex(e, "group_key", gk, 32);
            nc_group_record_digest(b, len, d);
            CHECK(nc_group_record_pt_parse(pt, ptl, r) == NC_GROUP_REFUSED &&
                  nc_group_record_open(b, len, gk, G_GID, 2, d, 2, G_OWNER, r) ==
                      NC_GROUP_REC_BAD_PLAINTEXT, nm);
            free(pt);
        } else if (strcmp(id, "record_trailing_byte") == 0 ||
                   strcmp(id, "record_over_cap") == 0) {
            b = jhexdup(e, "bytes", &len);
            uint8_t gk[32], d[64];
            jhex(e, "group_key", gk, 32);
            nc_group_record_digest(b, len, d);      /* digest would match: structure refuses */
            CHECK(nc_group_record_open(b, len, gk, G_GID, 2, d,
                                       strcmp(id, "record_over_cap") == 0 ? 64 : 2,
                                       G_OWNER, r) == NC_GROUP_REC_BAD_STRUCTURE, nm);
            if (strcmp(id, "record_over_cap") == 0)
                CHECK(jint(e, "ct_len") == 4172 &&
                      ((size_t)b[64] << 24 | (size_t)b[65] << 16 | (size_t)b[66] << 8 | b[67]) == 4172,
                      "record_over_cap carries ct_len 4,172 in its field");
        } else if (strcmp(id, "kp_unwrap_failure") == 0) {
            b = jhexdup(e, "bytes", &len);
            uint8_t mfp[64], kek[32], tw[40], dummy[32];
            jhex(e, "member_fp", mfp, 64);
            jhex(e, "kek", kek, 32);
            jhex(e, "tampered_wrapped", tw, 40);
            CHECK(aes256_unwrap_key(tw, 40, kek, dummy) != 0,
                  "kp_unwrap_failure: RFC 3394 refuses the tampered wrap under the right KEK");
            size_t pc = 0;
            CHECK(nc_group_kp_parse(b, len, NULL, &pc) == 0, "kp_unwrap_failure is structurally valid");
            size_t pre_len = NC_GROUP_KP_HEADER_LEN + pc * NC_GROUP_ENTRY_LEN, sl;
            uint8_t *signed_pkt = sign_append(b, pre_len, OWN_SK, &sl);
            nc_group_kp_open_t o;
            CHECK(nc_group_kp_open(signed_pkt, sl, OWN_PK, G_GID, G_OWNER, 2, G_KP_DIGEST[1], mfp,
                                   kat_decap, &tab, &o) == NC_GROUP_KP_NO_ENTRY &&
                  o.group_key[0] == 0 && o.group_key[31] == 0, nm);
            /* with the oracle's dummy signature it never gets that far */
            CHECK(nc_group_kp_open(b, len, OWN_PK, G_GID, G_OWNER, 2, G_KP_DIGEST[1], mfp,
                                   kat_decap, &tab, &o) == NC_GROUP_KP_BAD_SIG,
                  "kp_unwrap_failure with the dummy signature -> BAD_SIG first");
            free(signed_pkt);
        } else {
            seen--;
            CHECK(0, nm);                         /* a case this test does not know */
        }
        free(b);
        free(r);
    }
    CHECK(seen == 12, "all 12 reject cases exercised");
}

/* ── T1 round trips with the real primitives + accept rule ───────────── */

typedef struct { uint8_t ek[NC_GROUP_KEM_PK_LEN]; uint8_t dk[NC_GROUP_KEM_SK_LEN]; fp_t fp; } member_t;

static void test_round_trips(void) {
    printf("T1 round trips (real ML-KEM / ML-DSA / GCM)\n");
    enum { N = 4 };
    member_t *m = calloc(N + 1, sizeof(member_t));      /* [N] = a non-member */
    for (int i = 0; i <= N; i++) {
        uint8_t coins[QGP_MLKEM1024_COINS_BYTES];
        memset(coins, 0x30 + i, sizeof(coins));
        if (qgp_mlkem1024_keypair_derand(m[i].ek, m[i].dk, coins) != 0) exit(2);
        qgp_sha3_512(m[i].ek, NC_GROUP_KEM_PK_LEN, m[i].fp);   /* any distinct fp */
    }
    uint8_t owner_fp[64];
    qgp_sha3_512(OWN_PK, sizeof(OWN_PK), owner_fp);
    memcpy(m[0].fp, owner_fp, 64);                      /* member 0 is the owner */
    /* ascending by fp */
    for (int i = 1; i < N; i++)
        for (int j = i; j > 0 && memcmp(m[j - 1].fp, m[j].fp, 64) > 0; j--) {
            member_t t = m[j]; m[j] = m[j - 1]; m[j - 1] = t;
        }
    fp_t fps[N];
    uint8_t (*eks)[NC_GROUP_KEM_PK_LEN] = malloc(N * NC_GROUP_KEM_PK_LEN);
    for (int i = 0; i < N; i++) { memcpy(fps[i], m[i].fp, 64); memcpy(eks[i], m[i].ek, NC_GROUP_KEM_PK_LEN); }

    uint8_t gid[32], gk[32];
    memset(gid, 0x11, 32);
    memset(gk, 0x22, 32);

    /* record first: the packet binds its digest */
    uint8_t *rec = NULL, rdig[64];
    size_t rl = 0;
    CHECK(nc_group_record_seal(gid, 1, gk, owner_fp, (const uint8_t *)"grup", 4,
                               (const fp_t *)fps, N, 1791158400000ull, &rec, &rl, rdig) == 0,
          "record seal");
    nc_group_record_t *r = malloc(sizeof(*r));
    CHECK(nc_group_record_open(rec, rl, gk, gid, 1, rdig, N, owner_fp, r) == NC_GROUP_REC_OK &&
          r->count == N && r->name_len == 4, "record seal -> open");
    uint8_t *rec2 = NULL, rdig2[64];
    size_t rl2 = 0;
    nc_group_record_seal(gid, 1, gk, owner_fp, (const uint8_t *)"grup", 4, (const fp_t *)fps, N,
                         1791158400000ull, &rec2, &rl2, rdig2);
    CHECK(rec2 && memcmp(rec + 52, rec2 + 52, 12) != 0, "two record seals use different nonces");
    free(rec2);
    rec[rl - 1] ^= 1;
    CHECK(nc_group_record_open(rec, rl, gk, gid, 1, rdig, N, owner_fp, r) == NC_GROUP_REC_BAD_DIGEST,
          "tampered record -> BAD_DIGEST");
    uint8_t *x = NULL;
    size_t xl = 0;
    uint8_t stranger[64];
    memset(stranger, 0xEE, 64);
    CHECK(nc_group_record_seal(gid, 1, gk, stranger, NULL, 0, (const fp_t *)fps, N, 0, &x, &xl,
                               NULL) == NC_GROUP_REFUSED, "record seal without the owner refused");
    fp_t sw[N];
    memcpy(sw, fps, sizeof(sw));
    memcpy(sw[0], fps[1], 64);
    memcpy(sw[1], fps[0], 64);
    CHECK(nc_group_record_seal(gid, 1, gk, owner_fp, NULL, 0, (const fp_t *)sw, N, 0, &x, &xl,
                               NULL) == NC_GROUP_REFUSED, "record seal with unsorted members refused");

    nc_group_kp_hdr_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.group_id, gid, 32);
    memcpy(h.owner_fp, owner_fp, 64);
    h.v = 1;
    memcpy(h.record_digest, rdig, 64);
    h.issued_at_ms = 1791158460000ull;
    uint8_t *pkt = NULL, dig[64];
    size_t pl = 0;
    CHECK(nc_group_kp_build(&h, gk, (const fp_t *)fps, (const uint8_t (*)[NC_GROUP_KEM_PK_LEN])eks,
                            N, OWN_PK, OWN_SK, &pkt, &pl, dig) == 0 &&
          pl == NC_GROUP_KP_HEADER_LEN + N * NC_GROUP_ENTRY_LEN + 2 + NC_GROUP_SIG_LEN,
          "kp_build with fresh ML-KEM encapsulations");
    int all = 1;
    nc_group_kp_open_t o;
    for (int i = 0; i < N; i++)
        if (nc_group_kp_open(pkt, pl, OWN_PK, gid, owner_fp, 1, NULL, m[i].fp,
                             nc_group_decap_mlkem, m[i].dk, &o) != NC_GROUP_KP_OK ||
            memcmp(o.group_key, gk, 32) != 0 || memcmp(o.digest, dig, 64) != 0)
            all = 0;
    CHECK(all, "every member decapsulates + unwraps the group key");
    CHECK(nc_group_kp_open(pkt, pl, OWN_PK, gid, owner_fp, 1, NULL, m[N].fp,
                           nc_group_decap_mlkem, m[N].dk, &o) == NC_GROUP_KP_NO_ENTRY,
          "a non-member's key finds no entry");
    CHECK(nc_group_kp_open(pkt, pl, OWN_PK, gid, owner_fp, 1, NULL, m[1].fp,
                           nc_group_decap_mlkem, m[2].dk, &o) == NC_GROUP_KP_NO_ENTRY,
          "a member's fp with another member's key finds no entry (KEK binds member_fp)");
    free(pkt);
    pkt = NULL;
    memset(eks[N - 1], 0xFF, 1536);                     /* coefficients >= q */
    CHECK(nc_group_kp_build(&h, gk, (const fp_t *)fps, (const uint8_t (*)[NC_GROUP_KEM_PK_LEN])eks,
                            N, OWN_PK, OWN_SK, &pkt, &pl, dig) == NC_GROUP_REFUSED && pkt == NULL,
          "a member key failing ek_check fails the whole build");

    /* message */
    uint8_t mid[16], *item = NULL, out[NC_GROUP_TEXT_MAX];
    size_t il = 0, ol = 0;
    const char *text = "selam";
    CHECK(nc_group_msg_seal(gk, gid, 1, owner_fp, 1791203696789ull, (const uint8_t *)text, 5,
                            OWN_PK, OWN_SK, mid, &item, &il) == 0, "message seal");
    nc_group_msg_t mm;
    CHECK(nc_group_msg_parse(item, il, true, &mm) == 0 &&
          memcmp(mm.message_id, mid, 16) == 0 && mm.day == 20731 &&
          nc_group_msg_open(&mm, gk, OWN_PK, out, &ol) == NC_GROUP_MSG_OK &&
          ol == 5 && memcmp(out, text, 5) == 0, "message seal -> open");
    free(item);
    item = NULL;
    CHECK(nc_group_msg_seal(gk, gid, 1, owner_fp, 0, (const uint8_t *)"", 0, OWN_PK, OWN_SK, mid,
                            &item, &il) == NC_GROUP_REFUSED,
          "empty text refused on seal (decision 11)");
    uint8_t *longtext = calloc(1, NC_GROUP_TEXT_MAX + 1);
    memset(longtext, 'a', NC_GROUP_TEXT_MAX + 1);
    CHECK(nc_group_msg_seal(gk, gid, 1, owner_fp, 0, longtext, NC_GROUP_TEXT_MAX + 1, OWN_PK,
                            OWN_SK, mid, &item, &il) == NC_GROUP_REFUSED,
          "4,001-byte text refused on seal");
    CHECK(nc_group_msg_seal(gk, gid, 1, owner_fp, 0, longtext, NC_GROUP_TEXT_MAX, OWN_PK,
                            OWN_SK, mid, &item, &il) == 0, "4,000-byte text seals");
    free(item);
    free(longtext);
    CHECK(nc_group_msg_seal(gk, gid, 1, owner_fp, UINT64_MAX, (const uint8_t *)"a", 1, OWN_PK,
                            OWN_SK, mid, &item, &il) == NC_GROUP_REFUSED,
          "timestamp whose day overflows u32 refused on seal");

    /* accept rule: B removed in N+1 */
    fp_t A, B, C, D;
    memset(A, 0xA0, 64); memset(B, 0xB0, 64); memset(C, 0xC0, 64); memset(D, 0xD0, 64);
    fp_t v_n[3], v_n1[2];
    memcpy(v_n[0], A, 64); memcpy(v_n[1], B, 64); memcpy(v_n[2], C, 64);
    memcpy(v_n1[0], A, 64); memcpy(v_n1[1], C, 64);
    CHECK(nc_group_msg_accept(B, (const fp_t *)v_n, 3, NULL, 0),
          "accept: member of v, no newer version held -> accepted");
    CHECK(!nc_group_msg_accept(B, (const fp_t *)v_n, 3, (const fp_t *)v_n1, 2),
          "N1 accept: removed member's old-version message refused once v+1 is held");
    CHECK(nc_group_msg_accept(A, (const fp_t *)v_n, 3, (const fp_t *)v_n1, 2),
          "accept: member of v and v+1 -> accepted");
    CHECK(!nc_group_msg_accept(D, (const fp_t *)v_n, 3, NULL, 0),
          "N1 accept: non-member of v refused");
    CHECK(!nc_group_msg_accept(D, (const fp_t *)v_n, 3, (const fp_t *)v_n1, 2),
          "N1 accept: non-member refused with a newer version too");

    free(rec);
    free(r);
    free(eks);
    memset(m, 0, (N + 1) * sizeof(member_t));
    free(m);
}

int main(void) {
    json_object *J = json_object_from_file(GROUPS_KAT);
    if (!J) {
        printf("FATAL cannot read %s\n", GROUPS_KAT);
        return 2;
    }
    json_object *in = jget(J, "inputs");
    jhex(in, "group_id", G_GID, 32);
    jhex(in, "owner_fp", G_OWNER, 64);
    jhex(in, "addr_secret", G_ADDR, 32);
    size_t nl;
    uint8_t *name = jhexdup(in, "group_name_utf8", &nl);
    if (nl > sizeof(G_NAME)) return 2;
    memcpy(G_NAME, name, nl);
    G_NAME_LEN = nl;
    free(name);
    G_CREATED = (uint64_t)jint(in, "created_at_ms");
    json_object *gks = jget(in, "group_keys");
    for (size_t i = 0; i < json_object_array_length(gks); i++) {
        json_object *e = json_object_array_get_idx(gks, i);
        int64_t v = jint(e, "v");
        if (v < 1 || v > 3) return 2;
        jhex(e, "group_key", G_KEY[v], 32);
    }
    keypair(OWN_PK, OWN_SK, 0x01);
    keypair(OTH_PK, OTH_SK, 0x02);

    test_tags_salt_addr_kek(J);
    test_packets(J);                  /* fills KP_*, ALL_*, G_KP_DIGEST    */
    test_records(J);                  /* needs KP_MEMBERS                  */
    test_packet_open();
    test_heads(J);
    test_messages(J);
    test_buckets(J);
    test_days(J);
    test_json(J);
    test_rejects(J);
    test_round_trips();

    for (int v = 1; v <= 3; v++) free(KP_PRE[v]);
    free(MSG_ITEM[0]);
    free(MSG_ITEM[1]);
    json_object_put(J);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
