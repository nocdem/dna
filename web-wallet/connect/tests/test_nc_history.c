/**
 * Nodus Connect (web) — at-rest history encryption (package NC-4a;
 * docs/plans/decisions/2026-09-30-connect-history-at-rest.md rev 2).
 *
 * What it proves (no network):
 *   H1  hmac_sha3_256 (shared/crypto/hash/hkdf_sha3.c) reproduces NIST's
 *       "HMAC using SHA3-256" example values, Samples #1-#4: key shorter
 *       than the 136-byte block (#1, #4), equal to it (#2), longer than it
 *       (#3 — the key is hashed first). #4 is the truncated-tag sample: the
 *       full 32-byte output is compared to the PDF's
 *       Hash((K0^opad)||...) line and its first 16 bytes to "Mac is".
 *       Source: NIST CSRC example "HMAC_SHA3-256.pdf",
 *       sha256 04461a0ccdf51ba6f0cbea97bce820603096f121c729e0f164794294a5ef6b56,
 *       values extracted with pdftotext -layout.
 *   H2  hkdf_sha3_256 with a zero-length (non-NULL) salt equals HKDF with
 *       32 zero bytes of salt (RFC 5869 §2.2: an absent salt is HashLen
 *       zeros).
 *   R1  hex(nc_history_root(sk)) == db_derive_encryption_key(sk), the app's
 *       SQLCipher passphrase derivation, compiled from
 *       messenger/database/db_encryption.c into this test binary.
 *   K1  nc_history_derive_key == HKDF computed step by step with
 *       hmac_sha3_256 from R: PRK = HMAC(vault_id, R),
 *       K = HMAC(PRK, "nodus-connect-history-v1" || 0x01) (no NUL in the
 *       info); deterministic; another vault id or another secret key gives
 *       another K; R's bytes are not K.
 *   E1  round trip (including empty store / empty id).
 *   E2  a changed ciphertext byte, tag byte, nonce byte, store, id, or
 *       swapped store/id does not decrypt, and the output buffer is wiped.
 *   E3  length-prefix AAD: a record sealed under ("ab","c") does not open
 *       under ("a","bc") and vice versa.
 *   E4  counter 2^32-1 encrypts once (-> 2^32), then refuses with -1 and
 *       stays 2^32; a refusal for another reason (store of 65536 bytes,
 *       empty plaintext) leaves the counter unchanged.
 *   E5  two encryptions of the same record use different nonces.
 *
 * What it requires: the native build of web-wallet/connect/tests (OpenSSL);
 * no environment, no port. db_encryption.c is linked without SQLCipher:
 * its sqlite-calling function (dna_db_open_encrypted) is unreferenced and
 * dropped by -Wl,--gc-sections (CMakeLists.txt, nc_core link options).
 * What it leaves behind: nothing.
 * How it can lie:
 *   - E1-E5 run the same qgp_aes code in both directions: self-consistent.
 *     There is no AES-GCM known-answer test here; GCM correctness rests on
 *     OpenSSL (qgp_aes.c uses EVP_aes_256_gcm).
 *   - The only external anchor is H1 (HMAC-SHA3-256). K1's step-by-step
 *     HKDF is written from RFC 5869 §2.2/§2.3 in this file, by the same
 *     author as nc_history.c.
 *   - R1 compares against the app's C function, not against a SQLCipher
 *     passphrase read from a real app installation.
 *   - The secret key is a fixed byte pattern, not a real Dilithium5 key;
 *     the derivation only hashes the bytes.
 */

#include "nc_history.h"
#include "database/db_encryption.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed, failed;
#define CHECK(cond, name) do {                                        \
    if (cond) { passed++; printf("  PASS %s\n", name); }              \
    else { failed++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static int unhex(const char *hex, uint8_t *out, size_t out_len) {
    size_t n = 0;
    for (const char *p = hex; *p; ) {
        if (*p == ' ') { p++; continue; }
        unsigned v;
        if (n >= out_len || sscanf(p, "%2x", &v) != 1) return -1;
        out[n++] = (uint8_t)v;
        p += 2;
    }
    return n == out_len ? 0 : -1;
}

static int all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

/* ── H1: NIST HMAC-SHA3-256 examples ──────────────────────────────────── */

static void kat(const char *name, size_t key_len, const char *msg,
                const char *full_hex, size_t tag_len, const char *mac_hex) {
    uint8_t key[168];
    for (size_t i = 0; i < key_len; i++) key[i] = (uint8_t)i;   /* 00 01 02 .. */

    uint8_t full[32], mac[32], out[32];
    char label[96];
    int ok = unhex(full_hex, full, sizeof(full)) == 0 &&
             unhex(mac_hex, mac, tag_len) == 0;
    size_t out_len = 0;
    int rc = hmac_sha3_256(key, key_len, (const uint8_t *)msg, strlen(msg),
                           out, &out_len);
    snprintf(label, sizeof(label), "H1 %s: returns 0, 32 bytes", name);
    CHECK(ok && rc == 0 && out_len == 32, label);
    snprintf(label, sizeof(label), "H1 %s: full output", name);
    CHECK(ok && memcmp(out, full, 32) == 0, label);
    snprintf(label, sizeof(label), "H1 %s: MAC (%zu bytes)", name, tag_len);
    CHECK(ok && memcmp(out, mac, tag_len) == 0, label);
}

static void test_hmac_kat(void) {
    printf("H1 NIST HMAC-SHA3-256\n");
    kat("sample 1 (keylen<blocklen)", 32,
        "Sample message for keylen<blocklen",
        "4fe8e202 c4f058e8 dddc23d8 c34e4673 43e23555 e24fc2f0 25d598f5 58f67205",
        32,
        "4fe8e202 c4f058e8 dddc23d8 c34e4673 43e23555 e24fc2f0 25d598f5 58f67205");
    kat("sample 2 (keylen=blocklen)", 136,
        "Sample message for keylen=blocklen",
        "68b94e2e 538a9be4 103bebb5 aa016d47 961d4d1a a9060613 13b557f8 af2c3faa",
        32,
        "68b94e2e 538a9be4 103bebb5 aa016d47 961d4d1a a9060613 13b557f8 af2c3faa");
    kat("sample 3 (keylen>blocklen)", 168,
        "Sample message for keylen>blocklen",
        "9bcf2c23 8e235c3c e88404e8 13bd2f3a 97185ac6 f238c63d 6229a00b 07974258",
        32,
        "9bcf2c23 8e235c3c e88404e8 13bd2f3a 97185ac6 f238c63d 6229a00b 07974258");
    kat("sample 4 (truncated tag)", 32,
        "Sample message for keylen<blocklen, with truncated tag",
        "c8dc7148 d8c1423a a549105d afdf9cad 2941471b 5c622070 88e56ccf 2dd80545",
        16,
        "c8dc7148 d8c1423a a549105d afdf9cad");
}

/* ── H2: HKDF empty salt = HashLen zeros ──────────────────────────────── */

static void test_hkdf_empty_salt(void) {
    printf("H2 HKDF zero-length salt\n");
    const uint8_t ikm[22] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                              0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                              0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    const uint8_t info[3] = { 0xf0, 0xf1, 0xf2 };
    const uint8_t empty[1] = { 0 };          /* non-NULL, length 0 */
    const uint8_t zeros[32] = { 0 };
    uint8_t a[32], b[32];
    memset(a, 0xaa, sizeof(a));
    memset(b, 0x55, sizeof(b));
    int ra = hkdf_sha3_256(empty, 0, ikm, sizeof(ikm), info, sizeof(info), a, 32);
    int rb = hkdf_sha3_256(zeros, sizeof(zeros), ikm, sizeof(ikm), info,
                           sizeof(info), b, 32);
    CHECK(ra == 0, "H2 zero-length salt accepted");
    CHECK(rb == 0, "H2 32 zero-byte salt accepted");
    CHECK(ra == 0 && rb == 0 && memcmp(a, b, 32) == 0,
          "H2 zero-length salt == 32 zero bytes (RFC 5869 §2.2)");
}

/* ── R1 / K1: root and key ────────────────────────────────────────────── */

static void fill_sk(uint8_t *sk, uint8_t seed) {
    for (size_t i = 0; i < NC_HISTORY_SK_LEN; i++)
        sk[i] = (uint8_t)(i * 131u + seed);
}

static void test_root(const uint8_t *sk) {
    printf("R1 root = app SQLCipher derivation\n");
    uint8_t root[NC_HISTORY_ROOT_LEN], app_raw[NC_HISTORY_ROOT_LEN];
    char app_hex[QGP_SHA3_512_HEX_LENGTH];

    int r1 = nc_history_root(sk, NC_HISTORY_SK_LEN, root);
    int r2 = db_derive_encryption_key(sk, NC_HISTORY_SK_LEN, app_hex,
                                      sizeof(app_hex));
    /* Decode the app's passphrase (128 hex chars) rather than re-encode R,
     * so the comparison does not depend on hex letter case. */
    int r3 = r2 == 0 ? unhex(app_hex, app_raw, sizeof(app_raw)) : -1;
    CHECK(r1 == 0 && r2 == 0 && r3 == 0, "R1 both derivations return 0");
    CHECK(r1 == 0 && r3 == 0 && memcmp(root, app_raw, sizeof(root)) == 0,
          "R1 hex(R) == db_derive_encryption_key");

    CHECK(nc_history_root(sk, NC_HISTORY_SK_LEN - 1, root) == NC_HISTORY_REFUSED &&
          all_zero(root, sizeof(root)), "R1 wrong sk length refused, output zeroed");
    CHECK(nc_history_root(NULL, NC_HISTORY_SK_LEN, root) == NC_HISTORY_REFUSED,
          "R1 NULL sk refused");
}

static void test_key(const uint8_t *sk, const uint8_t *sk2) {
    printf("K1 history key\n");
    const uint8_t vault_a[NC_HISTORY_VAULT_ID_LEN] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    uint8_t vault_b[NC_HISTORY_VAULT_ID_LEN];
    memcpy(vault_b, vault_a, sizeof(vault_b));
    vault_b[15] ^= 0x01;

    uint8_t k1[32], k2[32], kb[32], ks[32];
    CHECK(nc_history_derive_key(sk, NC_HISTORY_SK_LEN, vault_a, k1) == 0,
          "K1 derive returns 0");
    CHECK(nc_history_derive_key(sk, NC_HISTORY_SK_LEN, vault_a, k2) == 0 &&
          memcmp(k1, k2, 32) == 0, "K1 deterministic");
    CHECK(nc_history_derive_key(sk, NC_HISTORY_SK_LEN, vault_b, kb) == 0 &&
          memcmp(k1, kb, 32) != 0, "K1 other vault id -> other key");
    CHECK(nc_history_derive_key(sk2, NC_HISTORY_SK_LEN, vault_a, ks) == 0 &&
          memcmp(k1, ks, 32) != 0, "K1 other secret key -> other key");

    /* RFC 5869 §2.2 Extract + §2.3 Expand (L = 32 = HashLen: one block). */
    uint8_t root[NC_HISTORY_ROOT_LEN], prk[32], okm[32];
    size_t prk_len = 0, okm_len = 0;
    const char *info = "nodus-connect-history-v1";
    uint8_t t_in[64];
    size_t info_len = strlen(info);
    memcpy(t_in, info, info_len);
    t_in[info_len] = 0x01;
    int ok = nc_history_root(sk, NC_HISTORY_SK_LEN, root) == 0 &&
             hmac_sha3_256(vault_a, sizeof(vault_a), root, sizeof(root),
                           prk, &prk_len) == 0 && prk_len == 32 &&
             hmac_sha3_256(prk, prk_len, t_in, info_len + 1,
                           okm, &okm_len) == 0 && okm_len == 32;
    CHECK(info_len == 24, "K1 info is 24 bytes (no NUL)");
    CHECK(ok && memcmp(okm, k1, 32) == 0, "K1 == HKDF step by step");
    CHECK(ok && memcmp(root, k1, 32) != 0, "K1 key is not the root");

    uint8_t kz[32];
    memset(kz, 0xff, sizeof(kz));
    CHECK(nc_history_derive_key(sk, 100, vault_a, kz) == NC_HISTORY_REFUSED &&
          all_zero(kz, sizeof(kz)), "K1 wrong sk length refused, key zeroed");
    CHECK(nc_history_derive_key(sk, NC_HISTORY_SK_LEN, NULL, kz) ==
          NC_HISTORY_REFUSED, "K1 NULL vault id refused");
}

/* ── E1-E5: records ───────────────────────────────────────────────────── */

#define S(x) (const uint8_t *)(x), strlen(x)

static void test_records(const uint8_t *key) {
    printf("E records\n");
    const char *msg = "hello from the web history";
    const size_t n = strlen(msg);
    uint8_t ct[64], pt[64], nonce[12], tag[16];
    uint64_t ctr = 0;

    /* E1 */
    int rc = nc_history_encrypt(key, &ctr, S("dm:abc"), S("id-0001"),
                                (const uint8_t *)msg, n, ct, nonce, tag);
    CHECK(rc == 0 && ctr == 1, "E1 encrypt returns 0, counter 0 -> 1");
    CHECK(rc == 0 && memcmp(ct, msg, n) != 0, "E1 ciphertext differs from plaintext");
    rc = nc_history_decrypt(key, S("dm:abc"), S("id-0001"), ct, n, nonce, tag, pt);
    CHECK(rc == 0 && memcmp(pt, msg, n) == 0, "E1 round trip");

    {
        uint8_t c2[64], p2[64], n2[12], t2[16];
        uint64_t c = 0;
        int ok = nc_history_encrypt(key, &c, NULL, 0, NULL, 0,
                                    (const uint8_t *)msg, n, c2, n2, t2) == 0 &&
                 nc_history_decrypt(key, NULL, 0, NULL, 0, c2, n, n2, t2, p2) == 0 &&
                 memcmp(p2, msg, n) == 0;
        CHECK(ok, "E1 round trip with empty store and id");
    }

    /* E2 — each tamper on a fresh copy; output must be wiped. */
    struct { const char *name; int what; } cases[] = {
        { "E2 ciphertext byte flipped", 0 },
        { "E2 tag byte flipped",        1 },
        { "E2 nonce byte flipped",      2 },
        { "E2 other store",             3 },
        { "E2 other id",                4 },
        { "E2 store and id swapped",    5 },
        { "E2 wrong key",               6 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t c[64], nn[12], t[16], k[32];
        memcpy(c, ct, n); memcpy(nn, nonce, 12); memcpy(t, tag, 16);
        memcpy(k, key, 32);
        const char *store = "dm:abc", *id = "id-0001";
        switch (cases[i].what) {
        case 0: c[3] ^= 0x01; break;
        case 1: t[15] ^= 0x80; break;
        case 2: nn[0] ^= 0x01; break;
        case 3: store = "dm:abd"; break;
        case 4: id = "id-0002"; break;
        case 5: store = "id-0001"; id = "dm:abc"; break;
        case 6: k[0] ^= 0x01; break;
        }
        memset(pt, 0xcc, sizeof(pt));
        rc = nc_history_decrypt(k, S(store), S(id), c, n, nn, t, pt);
        CHECK(rc == NC_HISTORY_REFUSED && all_zero(pt, n), cases[i].name);
    }

    /* E3 */
    {
        uint8_t c[8], p[8], nn[12], t[16];
        uint64_t k = 0;
        const char *m = "xyz";
        int e = nc_history_encrypt(key, &k, S("ab"), S("c"),
                                   (const uint8_t *)m, 3, c, nn, t);
        CHECK(e == 0 && nc_history_decrypt(key, S("a"), S("bc"), c, 3, nn, t, p) ==
              NC_HISTORY_REFUSED, "E3 (\"ab\",\"c\") does not open as (\"a\",\"bc\")");
        e = nc_history_encrypt(key, &k, S("a"), S("bc"),
                               (const uint8_t *)m, 3, c, nn, t);
        CHECK(e == 0 && nc_history_decrypt(key, S("ab"), S("c"), c, 3, nn, t, p) ==
              NC_HISTORY_REFUSED, "E3 (\"a\",\"bc\") does not open as (\"ab\",\"c\")");
    }

    /* E4 */
    {
        uint64_t c = NC_HISTORY_MAX_INVOCATIONS - 1;
        uint8_t cc[64];
        rc = nc_history_encrypt(key, &c, S("s"), S("i"),
                                (const uint8_t *)msg, n, cc, nonce, tag);
        CHECK(rc == 0 && c == NC_HISTORY_MAX_INVOCATIONS,
              "E4 counter 2^32-1 encrypts once -> 2^32");
        rc = nc_history_encrypt(key, &c, S("s"), S("i"),
                                (const uint8_t *)msg, n, cc, nonce, tag);
        CHECK(rc == NC_HISTORY_REFUSED && c == NC_HISTORY_MAX_INVOCATIONS,
              "E4 counter 2^32 refused, unchanged");
        c = UINT64_MAX;
        rc = nc_history_encrypt(key, &c, S("s"), S("i"),
                                (const uint8_t *)msg, n, cc, nonce, tag);
        CHECK(rc == NC_HISTORY_REFUSED && c == UINT64_MAX,
              "E4 counter UINT64_MAX refused, unchanged");

        uint8_t *big = (uint8_t *)calloc(NC_HISTORY_NAME_MAX + 1, 1);
        c = 5;
        rc = big ? nc_history_encrypt(key, &c, big, NC_HISTORY_NAME_MAX + 1,
                                      S("i"), (const uint8_t *)msg, n, cc,
                                      nonce, tag) : -99;
        CHECK(rc == NC_HISTORY_REFUSED && c == 5,
              "E4 store of 65536 bytes refused, counter unchanged");
        rc = big ? nc_history_encrypt(key, &c, S("s"), big,
                                      NC_HISTORY_NAME_MAX + 1,
                                      (const uint8_t *)msg, n, cc,
                                      nonce, tag) : -99;
        CHECK(rc == NC_HISTORY_REFUSED && c == 5,
              "E4 id of 65536 bytes refused, counter unchanged");
        rc = big ? nc_history_encrypt(key, &c, big, NC_HISTORY_NAME_MAX,
                                      S("i"), (const uint8_t *)msg, n, cc,
                                      nonce, tag) : -99;
        CHECK(rc == 0 && c == 6, "E4 store of 65535 bytes accepted");
        free(big);

        rc = nc_history_encrypt(key, &c, S("s"), S("i"),
                                (const uint8_t *)msg, 0, cc, nonce, tag);
        CHECK(rc == NC_HISTORY_REFUSED && c == 6,
              "E4 empty plaintext refused, counter unchanged");
        rc = nc_history_encrypt(key, &c, NULL, 3, S("i"),
                                (const uint8_t *)msg, n, cc, nonce, tag);
        CHECK(rc == NC_HISTORY_REFUSED && c == 6,
              "E4 NULL store with nonzero length refused");
        rc = nc_history_encrypt(key, NULL, S("s"), S("i"),
                                (const uint8_t *)msg, n, cc, nonce, tag);
        CHECK(rc == NC_HISTORY_REFUSED, "E4 NULL counter refused");
    }

    /* E5 */
    {
        uint8_t c1[64], c2[64], n1[12], n2[12], t1[16], t2[16];
        uint64_t c = 0;
        int ok = nc_history_encrypt(key, &c, S("s"), S("i"),
                                    (const uint8_t *)msg, n, c1, n1, t1) == 0 &&
                 nc_history_encrypt(key, &c, S("s"), S("i"),
                                    (const uint8_t *)msg, n, c2, n2, t2) == 0;
        CHECK(ok && c == 2 && memcmp(n1, n2, 12) != 0,
              "E5 same record twice -> different nonces");
    }
}

int main(void) {
    printf("test_nc_history\n");
    uint8_t *sk = (uint8_t *)malloc(NC_HISTORY_SK_LEN);
    uint8_t *sk2 = (uint8_t *)malloc(NC_HISTORY_SK_LEN);
    if (!sk || !sk2) { free(sk); free(sk2); printf("alloc failed\n"); return 1; }
    fill_sk(sk, 7);
    fill_sk(sk2, 8);

    test_hmac_kat();
    test_hkdf_empty_salt();
    test_root(sk);
    test_key(sk, sk2);

    const uint8_t vault[NC_HISTORY_VAULT_ID_LEN] = { 0 };
    uint8_t key[NC_HISTORY_KEY_LEN];
    if (nc_history_derive_key(sk, NC_HISTORY_SK_LEN, vault, key) != 0) {
        failed++;
        printf("  FAIL key for record tests\n");
    } else {
        test_records(key);
    }

    free(sk);
    free(sk2);
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
