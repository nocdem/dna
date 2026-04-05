# Debug Log Inbox Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship a one-way encrypted debug log drop — any DNA user sends their recent log to the developer's workstation via a well-known DHT inbox key; a CLI listener running as systemd on the workstation decrypts and writes each log to a file.

**Architecture:** New C engine module `dna_engine_debug_log.c` exposes `dna_engine_debug_log_send()`. Hybrid encryption (Kyber1024 + AES-256-GCM) to the receiver's Kyber public key. Stored at `SHA3-512("dna-debug-inbox" || receiver_fp)` via `nodus_ops_put`. New CLI subcommand `dna-connect-cli debug inbox listen` uses `nodus_ops_listen` to receive, decrypt, and persist logs to `/var/log/dna-debug/`. Flutter adds a button in Debug Log settings with `LogSanitizer` pre-filter. Sender authenticity is inherited from Nodus value signing (Dilithium5, automatic).

**Tech Stack:** C (messenger engine, CLI, crypto primitives in `shared/crypto/`), Nodus client SDK (`nodus_ops_put`/`get_all`/`listen`), Dart/Flutter (FFI, UI), systemd

**Design Doc:** `docs/plans/2026-04-05-dna-debug-log-to-punk-design.md`

---

## Phase 1: Wire format helpers (C, pure crypto, TDD)

### Task 1: Create wire format header and test stub

**Files:**
- Create: `messenger/src/api/engine/dna_debug_log_wire.h`
- Create: `messenger/src/api/engine/dna_debug_log_wire.c`
- Create: `messenger/tests/test_debug_log_wire.c`
- Modify: `messenger/tests/CMakeLists.txt` — register `test_debug_log_wire`

**Step 1: Write the header file**

`dna_debug_log_wire.h`:
```c
#ifndef DNA_DEBUG_LOG_WIRE_H
#define DNA_DEBUG_LOG_WIRE_H

#include <stddef.h>
#include <stdint.h>

/* Wire format version */
#define DNA_DEBUG_LOG_WIRE_VERSION 0x01

/* Limits (enforced at encode/decode) */
#define DNA_DEBUG_LOG_MAX_HINT_LEN   128u
#define DNA_DEBUG_LOG_MAX_BODY_LEN   (3u * 1024u * 1024u)   /* 3 MB */

/* Fixed-size components */
#define DNA_DEBUG_LOG_KYBER_CT_LEN   1568u
#define DNA_DEBUG_LOG_GCM_NONCE_LEN  12u
#define DNA_DEBUG_LOG_GCM_TAG_LEN    16u

/* Inner plaintext header: 2B hint_len + 4B log_len */
#define DNA_DEBUG_LOG_INNER_HDR_LEN  6u

/* Max outer payload = version(1) + kyber_ct(1568) + nonce(12) + inner_hdr(6)
 *                   + max_hint(128) + max_body(3MB) + gcm_tag(16)
 *                  ~= 3.001 MB (comfortably under 4 MB DHT cap)
 */
#define DNA_DEBUG_LOG_MAX_OUTER_LEN \
    (1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN + \
     DNA_DEBUG_LOG_INNER_HDR_LEN + DNA_DEBUG_LOG_MAX_HINT_LEN + \
     DNA_DEBUG_LOG_MAX_BODY_LEN + DNA_DEBUG_LOG_GCM_TAG_LEN)

/* Return codes */
#define DNA_DEBUG_LOG_OK                  0
#define DNA_DEBUG_LOG_ERR_NULL           -1
#define DNA_DEBUG_LOG_ERR_OVERSIZE       -2
#define DNA_DEBUG_LOG_ERR_VERSION        -3
#define DNA_DEBUG_LOG_ERR_TRUNCATED      -4
#define DNA_DEBUG_LOG_ERR_HINT_INVALID   -5
#define DNA_DEBUG_LOG_ERR_BODY_INVALID   -6

/* Encode inner plaintext (does NOT encrypt) — caller passes this to AES-GCM.
 * inner_out buffer must be >= DNA_DEBUG_LOG_INNER_HDR_LEN + hint_len + log_len.
 */
int dna_debug_log_encode_inner(
    const char *hint, size_t hint_len,
    const uint8_t *log_body, size_t log_len,
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out);

/* Decode inner plaintext. Populates hint_out (NUL-terminated, copied) and
 * body_out_ptr/body_len_out (points into inner, NOT copied).
 */
int dna_debug_log_decode_inner(
    const uint8_t *inner, size_t inner_len,
    char *hint_out, size_t hint_cap,   /* must be >= 129 */
    const uint8_t **body_out_ptr, size_t *body_len_out);

/* Encode outer: version byte + kyber_ct + nonce + encrypted_inner + gcm_tag.
 * outer_out buffer must be >= 1 + 1568 + 12 + enc_inner_len + 16.
 */
int dna_debug_log_encode_outer(
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *outer_out, size_t outer_cap, size_t *outer_len_out);

/* Decode outer. On success, populates pointers into outer (no allocation). */
int dna_debug_log_decode_outer(
    const uint8_t *outer, size_t outer_len,
    const uint8_t **kyber_ct_ptr,
    const uint8_t **nonce_ptr,
    const uint8_t **enc_inner_ptr, size_t *enc_inner_len_out,
    const uint8_t **gcm_tag_ptr);

#endif /* DNA_DEBUG_LOG_WIRE_H */
```

**Step 2: Create empty .c stub**

`dna_debug_log_wire.c`:
```c
#include "dna_debug_log_wire.h"
#include <string.h>

/* Implementations come in Task 2. */
```

**Step 3: Write failing test file**

`messenger/tests/test_debug_log_wire.c`:
```c
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/api/engine/dna_debug_log_wire.h"

static void test_encode_decode_inner_roundtrip(void) {
    const char *hint = "alice-android-rc158";
    const uint8_t body[] = "[INFO] hello world\n[DEBUG] foo=42\n";
    size_t body_len = sizeof(body) - 1;

    uint8_t inner[256];
    size_t inner_len = 0;
    int rc = dna_debug_log_encode_inner(hint, strlen(hint), body, body_len,
                                         inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(inner_len == 6 + strlen(hint) + body_len);

    char hint_out[129] = {0};
    const uint8_t *body_out = NULL;
    size_t body_out_len = 0;
    rc = dna_debug_log_decode_inner(inner, inner_len,
                                     hint_out, sizeof(hint_out),
                                     &body_out, &body_out_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(strcmp(hint_out, hint) == 0);
    assert(body_out_len == body_len);
    assert(memcmp(body_out, body, body_len) == 0);
    printf("  OK: inner roundtrip\n");
}

static void test_encode_inner_oversize_body(void) {
    static uint8_t big[DNA_DEBUG_LOG_MAX_BODY_LEN + 1];
    uint8_t inner[32];
    size_t inner_len = 0;
    int rc = dna_debug_log_encode_inner("x", 1, big, sizeof(big),
                                         inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_ERR_OVERSIZE);
    printf("  OK: oversize body rejected\n");
}

static void test_encode_inner_oversize_hint(void) {
    char big_hint[DNA_DEBUG_LOG_MAX_HINT_LEN + 2];
    memset(big_hint, 'a', sizeof(big_hint) - 1);
    big_hint[sizeof(big_hint) - 1] = 0;
    uint8_t body[] = "x";
    uint8_t inner[256];
    size_t inner_len = 0;
    int rc = dna_debug_log_encode_inner(big_hint, sizeof(big_hint) - 1,
                                         body, 1, inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_ERR_HINT_INVALID);
    printf("  OK: oversize hint rejected\n");
}

static void test_decode_outer_bad_version(void) {
    uint8_t buf[1 + 1568 + 12 + 1 + 16] = {0};
    buf[0] = 0x02;  /* wrong version */
    const uint8_t *ct, *nonce, *enc, *tag;
    size_t enc_len = 0;
    int rc = dna_debug_log_decode_outer(buf, sizeof(buf),
                                         &ct, &nonce, &enc, &enc_len, &tag);
    assert(rc == DNA_DEBUG_LOG_ERR_VERSION);
    printf("  OK: bad version rejected\n");
}

static void test_decode_outer_truncated(void) {
    uint8_t buf[100] = { 0x01 };  /* too short for kyber_ct alone */
    const uint8_t *ct, *nonce, *enc, *tag;
    size_t enc_len = 0;
    int rc = dna_debug_log_decode_outer(buf, sizeof(buf),
                                         &ct, &nonce, &enc, &enc_len, &tag);
    assert(rc == DNA_DEBUG_LOG_ERR_TRUNCATED);
    printf("  OK: truncated outer rejected\n");
}

static void test_encode_decode_outer_roundtrip(void) {
    uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN];
    uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN];
    uint8_t tag[DNA_DEBUG_LOG_GCM_TAG_LEN];
    for (size_t i = 0; i < sizeof(kyber_ct); i++) kyber_ct[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(nonce); i++)    nonce[i]    = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < sizeof(tag); i++)      tag[i]      = (uint8_t)(0x80 + i);
    uint8_t enc_inner[] = { 0xAA, 0xBB, 0xCC, 0xDD };

    uint8_t outer[2048];
    size_t outer_len = 0;
    int rc = dna_debug_log_encode_outer(kyber_ct, nonce, enc_inner, sizeof(enc_inner),
                                         tag, outer, sizeof(outer), &outer_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(outer_len == 1 + 1568 + 12 + sizeof(enc_inner) + 16);
    assert(outer[0] == DNA_DEBUG_LOG_WIRE_VERSION);

    const uint8_t *ct_p, *n_p, *enc_p, *tag_p;
    size_t enc_len_out = 0;
    rc = dna_debug_log_decode_outer(outer, outer_len, &ct_p, &n_p, &enc_p, &enc_len_out, &tag_p);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(memcmp(ct_p, kyber_ct, sizeof(kyber_ct)) == 0);
    assert(memcmp(n_p, nonce, sizeof(nonce)) == 0);
    assert(enc_len_out == sizeof(enc_inner));
    assert(memcmp(enc_p, enc_inner, sizeof(enc_inner)) == 0);
    assert(memcmp(tag_p, tag, sizeof(tag)) == 0);
    printf("  OK: outer roundtrip\n");
}

int main(void) {
    printf("test_debug_log_wire:\n");
    test_encode_decode_inner_roundtrip();
    test_encode_inner_oversize_body();
    test_encode_inner_oversize_hint();
    test_decode_outer_bad_version();
    test_decode_outer_truncated();
    test_encode_decode_outer_roundtrip();
    printf("ALL PASS\n");
    return 0;
}
```

**Step 4: Add test to CMakeLists**

In `messenger/tests/CMakeLists.txt`, find an existing `add_executable(test_X ...)` line and add:
```cmake
add_executable(test_debug_log_wire
    test_debug_log_wire.c
    ${CMAKE_SOURCE_DIR}/src/api/engine/dna_debug_log_wire.c)
target_include_directories(test_debug_log_wire PRIVATE
    ${CMAKE_SOURCE_DIR}/src/api/engine
    ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_debug_log_wire COMMAND test_debug_log_wire)
```

(Copy the exact style of a nearby existing entry — adjust target_link_libraries only if needed; this test has no extra deps.)

**Step 5: Build and confirm it fails**

```bash
cd /opt/dna/messenger/build && cmake .. && make test_debug_log_wire
```
Expected: **link error** — undefined references to `dna_debug_log_encode_inner` etc. This is the failing test.

**Step 6: Commit**

```bash
cd /opt/dna
git add -f messenger/src/api/engine/dna_debug_log_wire.h \
           messenger/src/api/engine/dna_debug_log_wire.c \
           messenger/tests/test_debug_log_wire.c \
           messenger/tests/CMakeLists.txt
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "test: add failing wire format tests for debug log"
```

---

### Task 2: Implement wire format functions

**Files:**
- Modify: `messenger/src/api/engine/dna_debug_log_wire.c`

**Step 1: Implement `dna_debug_log_encode_inner`**

Add to `dna_debug_log_wire.c` (replace the stub):
```c
#include "dna_debug_log_wire.h"
#include <string.h>

static void write_be16(uint8_t *dst, uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v & 0xFF);
}
static uint16_t read_be16(const uint8_t *src) {
    return ((uint16_t)src[0] << 8) | (uint16_t)src[1];
}
static void write_be32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v & 0xFF);
}
static uint32_t read_be32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

int dna_debug_log_encode_inner(
    const char *hint, size_t hint_len,
    const uint8_t *log_body, size_t log_len,
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out)
{
    if (!log_body || !inner_out || !inner_len_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (hint_len > 0 && !hint) return DNA_DEBUG_LOG_ERR_NULL;
    if (hint_len > DNA_DEBUG_LOG_MAX_HINT_LEN) return DNA_DEBUG_LOG_ERR_HINT_INVALID;
    if (log_len > DNA_DEBUG_LOG_MAX_BODY_LEN) return DNA_DEBUG_LOG_ERR_OVERSIZE;

    size_t need = DNA_DEBUG_LOG_INNER_HDR_LEN + hint_len + log_len;
    if (inner_cap < need) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    write_be16(inner_out + 0, (uint16_t)hint_len);
    if (hint_len) memcpy(inner_out + 2, hint, hint_len);
    write_be32(inner_out + 2 + hint_len, (uint32_t)log_len);
    memcpy(inner_out + 6 + hint_len, log_body, log_len);
    *inner_len_out = need;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_decode_inner(
    const uint8_t *inner, size_t inner_len,
    char *hint_out, size_t hint_cap,
    const uint8_t **body_out_ptr, size_t *body_len_out)
{
    if (!inner || !hint_out || !body_out_ptr || !body_len_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (hint_cap < DNA_DEBUG_LOG_MAX_HINT_LEN + 1) return DNA_DEBUG_LOG_ERR_HINT_INVALID;
    if (inner_len < DNA_DEBUG_LOG_INNER_HDR_LEN) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint16_t hint_len = read_be16(inner);
    if (hint_len > DNA_DEBUG_LOG_MAX_HINT_LEN) return DNA_DEBUG_LOG_ERR_HINT_INVALID;
    if (inner_len < 2u + hint_len + 4u) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint32_t body_len = read_be32(inner + 2 + hint_len);
    if (body_len > DNA_DEBUG_LOG_MAX_BODY_LEN) return DNA_DEBUG_LOG_ERR_BODY_INVALID;
    if (inner_len != (size_t)(2u + hint_len + 4u + body_len)) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    if (hint_len) memcpy(hint_out, inner + 2, hint_len);
    hint_out[hint_len] = 0;
    *body_out_ptr = inner + 2 + hint_len + 4;
    *body_len_out = body_len;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_encode_outer(
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *outer_out, size_t outer_cap, size_t *outer_len_out)
{
    if (!kyber_ct || !nonce || !enc_inner || !gcm_tag || !outer_out || !outer_len_out)
        return DNA_DEBUG_LOG_ERR_NULL;
    size_t need = 1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN
                + enc_inner_len + DNA_DEBUG_LOG_GCM_TAG_LEN;
    if (need > DNA_DEBUG_LOG_MAX_OUTER_LEN) return DNA_DEBUG_LOG_ERR_OVERSIZE;
    if (outer_cap < need) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    size_t off = 0;
    outer_out[off++] = DNA_DEBUG_LOG_WIRE_VERSION;
    memcpy(outer_out + off, kyber_ct, DNA_DEBUG_LOG_KYBER_CT_LEN); off += DNA_DEBUG_LOG_KYBER_CT_LEN;
    memcpy(outer_out + off, nonce, DNA_DEBUG_LOG_GCM_NONCE_LEN);   off += DNA_DEBUG_LOG_GCM_NONCE_LEN;
    memcpy(outer_out + off, enc_inner, enc_inner_len);             off += enc_inner_len;
    memcpy(outer_out + off, gcm_tag, DNA_DEBUG_LOG_GCM_TAG_LEN);   off += DNA_DEBUG_LOG_GCM_TAG_LEN;
    *outer_len_out = off;
    return DNA_DEBUG_LOG_OK;
}

int dna_debug_log_decode_outer(
    const uint8_t *outer, size_t outer_len,
    const uint8_t **kyber_ct_ptr, const uint8_t **nonce_ptr,
    const uint8_t **enc_inner_ptr, size_t *enc_inner_len_out,
    const uint8_t **gcm_tag_ptr)
{
    if (!outer || !kyber_ct_ptr || !nonce_ptr || !enc_inner_ptr ||
        !enc_inner_len_out || !gcm_tag_ptr) return DNA_DEBUG_LOG_ERR_NULL;
    size_t fixed = 1u + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN
                 + DNA_DEBUG_LOG_GCM_TAG_LEN;
    if (outer_len < fixed + 1u) return DNA_DEBUG_LOG_ERR_TRUNCATED;
    if (outer[0] != DNA_DEBUG_LOG_WIRE_VERSION) return DNA_DEBUG_LOG_ERR_VERSION;

    *kyber_ct_ptr = outer + 1;
    *nonce_ptr    = outer + 1 + DNA_DEBUG_LOG_KYBER_CT_LEN;
    *enc_inner_ptr = outer + 1 + DNA_DEBUG_LOG_KYBER_CT_LEN + DNA_DEBUG_LOG_GCM_NONCE_LEN;
    *enc_inner_len_out = outer_len - fixed;
    *gcm_tag_ptr  = outer + outer_len - DNA_DEBUG_LOG_GCM_TAG_LEN;
    return DNA_DEBUG_LOG_OK;
}
```

**Step 2: Build and run tests**

```bash
cd /opt/dna/messenger/build && make test_debug_log_wire && ./tests/test_debug_log_wire
```
Expected: `ALL PASS`

**Step 3: Run full ctest to ensure no regression**

```bash
cd /opt/dna/messenger/build && ctest --output-on-failure
```
Expected: all tests pass (new test included).

**Step 4: Commit**

```bash
cd /opt/dna
git add messenger/src/api/engine/dna_debug_log_wire.c
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat: implement debug log wire format encode/decode"
```

---

## Phase 2: Crypto wrapper (Kyber + AES-GCM round-trip)

### Task 3: Add encrypt/decrypt helpers + round-trip test

**Files:**
- Modify: `messenger/src/api/engine/dna_debug_log_wire.h` (add crypto helpers)
- Modify: `messenger/src/api/engine/dna_debug_log_wire.c`
- Modify: `messenger/tests/test_debug_log_wire.c` (add crypto round-trip test)

Check which Kyber header + AES-GCM header the codebase uses:
```bash
grep -rn "qgp_kyber.h\|qgp_aes_gcm\|crypto_kem_enc" /opt/dna/shared/crypto/enc/ | head -5
```

**Step 1: Add crypto helper declarations to header**

In `dna_debug_log_wire.h` (before `#endif`):
```c
/* ============================================================================
 * Hybrid encryption helpers (Kyber1024 + AES-256-GCM)
 * ============================================================================ */

/* Encrypt inner plaintext for a receiver's Kyber1024 public key.
 * enc_inner_out capacity: inner_len + 16 (GCM tag is separate).
 * Outputs: kyber_ct (1568), nonce (12), enc_inner_out (inner_len), gcm_tag (16).
 */
int dna_debug_log_encrypt_inner(
    const uint8_t receiver_kyber_pub[1568],
    const uint8_t *inner, size_t inner_len,
    uint8_t kyber_ct_out[DNA_DEBUG_LOG_KYBER_CT_LEN],
    uint8_t nonce_out[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    uint8_t *enc_inner_out, size_t enc_inner_cap,
    uint8_t gcm_tag_out[DNA_DEBUG_LOG_GCM_TAG_LEN]);

/* Decrypt. Returns DNA_DEBUG_LOG_ERR_* on MAC failure or bad inputs. */
int dna_debug_log_decrypt_inner(
    const uint8_t *receiver_kyber_sk, size_t receiver_kyber_sk_len,
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out);

#define DNA_DEBUG_LOG_ERR_KEM_FAIL    -7
#define DNA_DEBUG_LOG_ERR_GCM_FAIL    -8
```

**Step 2: Implement encrypt/decrypt in .c**

Add to `dna_debug_log_wire.c`:
```c
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/aes_gcm.h"     /* TODO: confirm exact header via grep */
#include "crypto/utils/qgp_random.h"

int dna_debug_log_encrypt_inner(
    const uint8_t receiver_kyber_pub[1568],
    const uint8_t *inner, size_t inner_len,
    uint8_t kyber_ct_out[DNA_DEBUG_LOG_KYBER_CT_LEN],
    uint8_t nonce_out[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    uint8_t *enc_inner_out, size_t enc_inner_cap,
    uint8_t gcm_tag_out[DNA_DEBUG_LOG_GCM_TAG_LEN])
{
    if (!receiver_kyber_pub || !inner || !kyber_ct_out || !nonce_out ||
        !enc_inner_out || !gcm_tag_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (enc_inner_cap < inner_len) return DNA_DEBUG_LOG_ERR_TRUNCATED;

    uint8_t shared_secret[32];
    if (qgp_kyber_encapsulate(receiver_kyber_pub, kyber_ct_out, shared_secret) != 0)
        return DNA_DEBUG_LOG_ERR_KEM_FAIL;

    if (qgp_random_bytes(nonce_out, DNA_DEBUG_LOG_GCM_NONCE_LEN) != 0) {
        memset(shared_secret, 0, sizeof(shared_secret));
        return DNA_DEBUG_LOG_ERR_KEM_FAIL;
    }

    int rc = aes_gcm_encrypt(shared_secret, 32,
                              nonce_out, DNA_DEBUG_LOG_GCM_NONCE_LEN,
                              NULL, 0,
                              inner, inner_len,
                              enc_inner_out, gcm_tag_out);
    memset(shared_secret, 0, sizeof(shared_secret));
    return rc == 0 ? DNA_DEBUG_LOG_OK : DNA_DEBUG_LOG_ERR_GCM_FAIL;
}

int dna_debug_log_decrypt_inner(
    const uint8_t *receiver_kyber_sk, size_t receiver_kyber_sk_len,
    const uint8_t kyber_ct[DNA_DEBUG_LOG_KYBER_CT_LEN],
    const uint8_t nonce[DNA_DEBUG_LOG_GCM_NONCE_LEN],
    const uint8_t *enc_inner, size_t enc_inner_len,
    const uint8_t gcm_tag[DNA_DEBUG_LOG_GCM_TAG_LEN],
    uint8_t *inner_out, size_t inner_cap, size_t *inner_len_out)
{
    if (!receiver_kyber_sk || !kyber_ct || !nonce || !enc_inner || !gcm_tag ||
        !inner_out || !inner_len_out) return DNA_DEBUG_LOG_ERR_NULL;
    if (inner_cap < enc_inner_len) return DNA_DEBUG_LOG_ERR_TRUNCATED;
    (void)receiver_kyber_sk_len;  /* Kyber1024 secret key is fixed size */

    uint8_t shared_secret[32];
    if (qgp_kyber_decapsulate(kyber_ct, receiver_kyber_sk, shared_secret) != 0)
        return DNA_DEBUG_LOG_ERR_KEM_FAIL;

    int rc = aes_gcm_decrypt(shared_secret, 32,
                              nonce, DNA_DEBUG_LOG_GCM_NONCE_LEN,
                              NULL, 0,
                              enc_inner, enc_inner_len,
                              gcm_tag, inner_out);
    memset(shared_secret, 0, sizeof(shared_secret));
    if (rc != 0) return DNA_DEBUG_LOG_ERR_GCM_FAIL;
    *inner_len_out = enc_inner_len;
    return DNA_DEBUG_LOG_OK;
}
```

**IMPORTANT:** Confirm the exact Kyber + AES-GCM API names via grep before committing:
```bash
grep -n "qgp_kyber_encapsulate\|qgp_kyber_decapsulate" /opt/dna/shared/crypto/enc/qgp_kyber.h
grep -rn "aes_gcm_encrypt\|aes_gcm_decrypt\|qgp_aes_gcm" /opt/dna/shared/crypto/enc/ | head -10
```
If names differ, **adjust the call sites** to match. Similarly verify `qgp_random_bytes`.

**Step 3: Add crypto round-trip test to `test_debug_log_wire.c`**

Add before `main()`:
```c
/* Linked against shared crypto; keypair is generated ad-hoc */
#include "crypto/enc/qgp_kyber.h"

static void test_encrypt_decrypt_roundtrip(void) {
    uint8_t pub[1568], sk[3168];
    int rc = qgp_kyber_keypair(pub, sk);
    assert(rc == 0);

    const char *hint = "test-hint";
    const uint8_t body[] = "the quick brown fox";
    uint8_t inner[256];
    size_t inner_len = 0;
    rc = dna_debug_log_encode_inner(hint, strlen(hint), body, sizeof(body) - 1,
                                     inner, sizeof(inner), &inner_len);
    assert(rc == DNA_DEBUG_LOG_OK);

    uint8_t kyber_ct[1568], nonce[12], enc[256], tag[16];
    rc = dna_debug_log_encrypt_inner(pub, inner, inner_len,
                                      kyber_ct, nonce, enc, sizeof(enc), tag);
    assert(rc == DNA_DEBUG_LOG_OK);

    uint8_t decrypted[256];
    size_t decrypted_len = 0;
    rc = dna_debug_log_decrypt_inner(sk, sizeof(sk), kyber_ct, nonce,
                                      enc, inner_len, tag,
                                      decrypted, sizeof(decrypted), &decrypted_len);
    assert(rc == DNA_DEBUG_LOG_OK);
    assert(decrypted_len == inner_len);
    assert(memcmp(decrypted, inner, inner_len) == 0);

    /* Tamper test */
    enc[0] ^= 0x01;
    rc = dna_debug_log_decrypt_inner(sk, sizeof(sk), kyber_ct, nonce,
                                      enc, inner_len, tag,
                                      decrypted, sizeof(decrypted), &decrypted_len);
    assert(rc == DNA_DEBUG_LOG_ERR_GCM_FAIL);
    printf("  OK: encrypt/decrypt roundtrip + tamper\n");
}
```

Add to `main()`: `test_encrypt_decrypt_roundtrip();`

**Step 4: Update test CMakeLists to link crypto**

In `messenger/tests/CMakeLists.txt` for `test_debug_log_wire`:
```cmake
target_link_libraries(test_debug_log_wire PRIVATE dna)   # or whatever the crypto lib target is
```
(Copy the link line from a sibling test like `test_aes256_gcm` that uses these primitives.)

**Step 5: Build + test**

```bash
cd /opt/dna/messenger/build && make test_debug_log_wire && ./tests/test_debug_log_wire
```
Expected: `ALL PASS` including new roundtrip test.

**Step 6: Commit**

```bash
cd /opt/dna
git add messenger/src/api/engine/dna_debug_log_wire.h \
        messenger/src/api/engine/dna_debug_log_wire.c \
        messenger/tests/test_debug_log_wire.c \
        messenger/tests/CMakeLists.txt
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat: add hybrid encrypt/decrypt for debug log wire"
```

---

## Phase 3: Engine module (sender-side)

### Task 4: Inbox key derivation + test

**Files:**
- Modify: `messenger/src/api/engine/dna_debug_log_wire.h` (add key derivation)
- Modify: `messenger/src/api/engine/dna_debug_log_wire.c`
- Modify: `messenger/tests/test_debug_log_wire.c`

**Step 1: Add key derivation to header**

```c
/* Compute DHT inbox key: SHA3-512("dna-debug-inbox" || receiver_fp_raw_64).
 * receiver_fp_raw is the 64-byte Dilithium5 fingerprint (raw bytes).
 * Output: 64-byte SHA3-512 digest in key_out.
 */
int dna_debug_log_inbox_key(
    const uint8_t receiver_fp_raw[64],
    uint8_t key_out[64]);
```

**Step 2: Implement**

```c
#include "crypto/hash/qgp_sha3.h"

int dna_debug_log_inbox_key(const uint8_t receiver_fp_raw[64], uint8_t key_out[64]) {
    if (!receiver_fp_raw || !key_out) return DNA_DEBUG_LOG_ERR_NULL;
    static const char PREFIX[] = "dna-debug-inbox";
    uint8_t buf[sizeof(PREFIX) - 1 + 64];
    memcpy(buf, PREFIX, sizeof(PREFIX) - 1);
    memcpy(buf + sizeof(PREFIX) - 1, receiver_fp_raw, 64);
    qgp_sha3_512(buf, sizeof(buf), key_out);
    return DNA_DEBUG_LOG_OK;
}
```

(Confirm `qgp_sha3_512` signature: `grep -n "qgp_sha3_512" /opt/dna/shared/crypto/hash/qgp_sha3.h`.)

**Step 3: Test determinism**

Add to `test_debug_log_wire.c`:
```c
static void test_inbox_key_determinism(void) {
    uint8_t fp[64];
    for (size_t i = 0; i < 64; i++) fp[i] = (uint8_t)i;
    uint8_t k1[64], k2[64];
    assert(dna_debug_log_inbox_key(fp, k1) == DNA_DEBUG_LOG_OK);
    assert(dna_debug_log_inbox_key(fp, k2) == DNA_DEBUG_LOG_OK);
    assert(memcmp(k1, k2, 64) == 0);

    /* Different fp → different key */
    fp[0] ^= 1;
    uint8_t k3[64];
    assert(dna_debug_log_inbox_key(fp, k3) == DNA_DEBUG_LOG_OK);
    assert(memcmp(k1, k3, 64) != 0);
    printf("  OK: inbox key derivation deterministic + unique\n");
}
```
Add `test_inbox_key_determinism();` to `main()`.

**Step 4: Build + test + commit**

```bash
cd /opt/dna/messenger/build && make test_debug_log_wire && ./tests/test_debug_log_wire
```
Then:
```bash
cd /opt/dna
git add messenger/src/api/engine/dna_debug_log_wire.h \
        messenger/src/api/engine/dna_debug_log_wire.c \
        messenger/tests/test_debug_log_wire.c
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat: add SHA3-512 inbox key derivation for debug log"
```

---

### Task 5: Engine module skeleton + public API

**Files:**
- Create: `messenger/src/api/engine/dna_engine_debug_log.c`
- Modify: `messenger/src/api/dna_engine_internal.h` (add task type + handler decl)
- Modify: `messenger/include/dna/dna_engine.h` (add public API)
- Modify: `messenger/src/api/dna_engine.c` (add dispatch case)
- Modify: `messenger/src/api/engine/CMakeLists.txt` (add new .c to build)

**Step 1: Add task type**

In `messenger/src/api/dna_engine_internal.h`, add at end of the task enum (before closing `}`):
```c
    TASK_DEBUG_LOG_SEND,
```
And add handler declaration near other declarations:
```c
void dna_handle_debug_log_send(dna_engine_t *engine, dna_task_t *task);
```

**Step 2: Add public API declaration**

In `messenger/include/dna/dna_engine.h`, add near other send APIs:
```c
/* ============================================================================
 * DEBUG LOG DELIVERY (one-way, to developer's inbox via DHT)
 * ============================================================================ */

/* Send a debug log to the receiver's anonymous DHT inbox.
 * Log is hybrid-encrypted (Kyber1024 + AES-256-GCM) to the receiver's Kyber
 * public key, fetched via profile lookup. Stored 1h TTL.
 *
 * @param receiver_fp_hex  128-char hex Dilithium5 fingerprint of developer
 * @param log_body         UTF-8 log bytes (caller retains ownership)
 * @param log_len          Bytes; must be <= 3 MB
 * @param hint             Optional cleartext hint (e.g. "android-rc158"); may be NULL
 */
DNA_API dna_request_id_t dna_engine_debug_log_send(
    dna_engine_t *engine,
    const char *receiver_fp_hex,
    const uint8_t *log_body,
    size_t log_len,
    const char *hint,
    dna_completion_cb callback,
    void *user_data);
```

**Step 3: Create module file**

`messenger/src/api/engine/dna_engine_debug_log.c`:
```c
/*
 * DNA Engine — Debug Log Module
 *
 * One-way debug log delivery to a developer's DHT inbox. Hybrid encryption
 * (Kyber1024 + AES-256-GCM). Sender is authenticated by Nodus value-signing
 * layer (Dilithium5) automatically.
 */

#define DNA_ENGINE_DEBUG_LOG_IMPL
#include "engine_includes.h"
#include "dna_debug_log_wire.h"
#include "dht/shared/nodus_ops.h"

#define LOG_TAG "DEBUG_LOG"

#define DEBUG_LOG_TTL_SECONDS 3600   /* 1 hour */

/* Task params (allocated on submit, freed in handler). */
typedef struct {
    char      receiver_fp_hex[129];
    uint8_t  *log_body;    /* owned */
    size_t    log_len;
    char      hint[DNA_DEBUG_LOG_MAX_HINT_LEN + 1];
} debug_log_send_params_t;

/* Hex string (128 chars) → 64 raw bytes. Returns 0 on success. */
static int fp_hex_to_raw(const char *hex, uint8_t out[64]) {
    if (!hex || strlen(hex) != 128) return -1;
    for (size_t i = 0; i < 64; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

void dna_handle_debug_log_send(dna_engine_t *engine, dna_task_t *task) {
    debug_log_send_params_t *p = (debug_log_send_params_t *)task->params;
    int rc = DNA_ERROR_UNKNOWN;

    do {
        /* 1. Parse receiver fingerprint */
        uint8_t receiver_fp_raw[64];
        if (fp_hex_to_raw(p->receiver_fp_hex, receiver_fp_raw) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "invalid receiver fp");
            rc = DNA_ERROR_INVALID_ARG;
            break;
        }

        /* 2. Look up receiver Kyber pubkey (profile lookup).
         *    Use existing helper: dna_engine_lookup_profile_sync() or equivalent.
         *    ---> Confirm the exact function name via grep and use it here. <---
         */
        uint8_t receiver_kyber_pub[1568];
        if (dna_lookup_receiver_kyber_pub(engine, receiver_fp_raw, receiver_kyber_pub) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "kyber pubkey lookup failed");
            rc = DNA_ERROR_NOT_FOUND;
            break;
        }

        /* 3. Encode inner plaintext */
        size_t hint_len = strlen(p->hint);
        size_t inner_cap = DNA_DEBUG_LOG_INNER_HDR_LEN + hint_len + p->log_len;
        uint8_t *inner = (uint8_t *)malloc(inner_cap);
        if (!inner) { rc = DNA_ERROR_OUT_OF_MEMORY; break; }
        size_t inner_len = 0;
        if (dna_debug_log_encode_inner(p->hint, hint_len,
                                        p->log_body, p->log_len,
                                        inner, inner_cap, &inner_len) != DNA_DEBUG_LOG_OK) {
            free(inner);
            rc = DNA_ERROR_INVALID_ARG;
            break;
        }

        /* 4. Encrypt */
        uint8_t kyber_ct[1568], nonce[12], tag[16];
        uint8_t *enc = (uint8_t *)malloc(inner_len);
        if (!enc) { free(inner); rc = DNA_ERROR_OUT_OF_MEMORY; break; }
        int enc_rc = dna_debug_log_encrypt_inner(receiver_kyber_pub, inner, inner_len,
                                                  kyber_ct, nonce, enc, inner_len, tag);
        memset(inner, 0, inner_len);
        free(inner);
        if (enc_rc != DNA_DEBUG_LOG_OK) {
            memset(enc, 0, inner_len);
            free(enc);
            QGP_LOG_ERROR(LOG_TAG, "encrypt failed: %d", enc_rc);
            rc = DNA_ERROR_CRYPTO;
            break;
        }

        /* 5. Encode outer payload */
        size_t outer_cap = 1 + 1568 + 12 + inner_len + 16;
        uint8_t *outer = (uint8_t *)malloc(outer_cap);
        if (!outer) { free(enc); rc = DNA_ERROR_OUT_OF_MEMORY; break; }
        size_t outer_len = 0;
        int enc2 = dna_debug_log_encode_outer(kyber_ct, nonce, enc, inner_len, tag,
                                               outer, outer_cap, &outer_len);
        free(enc);
        if (enc2 != DNA_DEBUG_LOG_OK) {
            free(outer);
            rc = DNA_ERROR_UNKNOWN;
            break;
        }

        /* 6. Compute inbox key + PUT */
        uint8_t inbox_key[64];
        dna_debug_log_inbox_key(receiver_fp_raw, inbox_key);

        int put_rc = nodus_ops_put(inbox_key, 64, outer, outer_len, DEBUG_LOG_TTL_SECONDS);
        free(outer);
        if (put_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "nodus_ops_put failed: %d", put_rc);
            rc = DNA_ERROR_DHT;
            break;
        }

        QGP_LOG_INFO(LOG_TAG, "log sent: %zu bytes", p->log_len);
        rc = DNA_SUCCESS;
    } while (0);

    /* Completion callback */
    if (task->completion_cb) {
        task->completion_cb(task->request_id, rc, NULL, task->user_data);
    }

    /* Cleanup task params */
    if (p->log_body) { memset(p->log_body, 0, p->log_len); free(p->log_body); }
    free(p);
}

dna_request_id_t dna_engine_debug_log_send(
    dna_engine_t *engine,
    const char *receiver_fp_hex,
    const uint8_t *log_body, size_t log_len,
    const char *hint,
    dna_completion_cb callback, void *user_data)
{
    if (!engine || !receiver_fp_hex || !log_body) return 0;
    if (log_len == 0 || log_len > DNA_DEBUG_LOG_MAX_BODY_LEN) return 0;
    if (strlen(receiver_fp_hex) != 128) return 0;

    debug_log_send_params_t *p = calloc(1, sizeof(*p));
    if (!p) return 0;
    strncpy(p->receiver_fp_hex, receiver_fp_hex, 128);
    p->log_body = malloc(log_len);
    if (!p->log_body) { free(p); return 0; }
    memcpy(p->log_body, log_body, log_len);
    p->log_len = log_len;
    if (hint) strncpy(p->hint, hint, DNA_DEBUG_LOG_MAX_HINT_LEN);

    return dna_submit_task(engine, TASK_DEBUG_LOG_SEND, p, callback, user_data);
}
```

**IMPORTANT:** Replace `dna_lookup_receiver_kyber_pub` with the actual helper. Grep:
```bash
grep -rn "lookup_profile\|get_kyber_pubkey\|receiver_kyber" /opt/dna/messenger/src/api/engine/ | head -20
```
If no sync helper exists, use `dna_engine_lookup_profile` with a condvar, or make the task a 2-stage task (lookup → send). For v1, a blocking lookup inside the handler is acceptable.

**Step 4: Add dispatch in `dna_engine.c`**

In `messenger/src/api/dna_engine.c`, find the task dispatch switch (likely in `dna_execute_task` or similar), and add:
```c
        case TASK_DEBUG_LOG_SEND:
            dna_handle_debug_log_send(engine, task);
            break;
```

**Step 5: Add module to build**

In `messenger/src/api/engine/CMakeLists.txt`, find the list of engine module sources and add `dna_engine_debug_log.c` + `dna_debug_log_wire.c`.

**Step 6: Build messenger C library**

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)
```
Expected: builds clean, no warnings.

**Step 7: Commit**

```bash
cd /opt/dna
git add -A messenger/src/api/engine/ messenger/src/api/ messenger/include/dna/
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat: add debug log send engine module + public API"
```

---

## Phase 4: CLI receiver command

### Task 6: `debug inbox listen` CLI subcommand

**Files:**
- Modify: `messenger/cli/cli_commands.h` (declare `cmd_debug_inbox_listen`)
- Modify: `messenger/cli/cli_commands.c` (implement)
- Modify: `messenger/cli/main.c` (dispatch `debug inbox listen`)

**Step 1: Declare in header**

In `cli_commands.h`:
```c
int cmd_debug_inbox_listen(dna_engine_t *engine);
```

**Step 2: Implement in `cli_commands.c`**

Append to file:
```c
/* ============================================================================
 * DEBUG INBOX LISTEN
 * ============================================================================ */

#include "../src/api/engine/dna_debug_log_wire.h"
#include "dht/shared/nodus_ops.h"
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define DEBUG_INBOX_OUT_DIR "/var/log/dna-debug"

static volatile bool g_debug_listening = true;
static void debug_listen_sig(int sig) { (void)sig; g_debug_listening = false; }

static void ensure_out_dir(void) {
    struct stat st;
    if (stat(DEBUG_INBOX_OUT_DIR, &st) == 0) return;
    if (mkdir(DEBUG_INBOX_OUT_DIR, 0700) != 0) {
        fprintf(stderr, "warn: cannot create %s: %s\n",
                DEBUG_INBOX_OUT_DIR, strerror(errno));
    }
}

static void hex16(const uint8_t *src, char *out) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i*2]   = H[(src[i] >> 4) & 0xF];
        out[i*2+1] = H[src[i] & 0xF];
    }
    out[16] = 0;
}

static void iso8601_now(char *out, size_t cap) {
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, cap, "%Y%m%dT%H%M%SZ", tm);
}

/* Callback: a new value arrived at the inbox key. */
static bool on_inbox_value(const uint8_t *data, size_t data_len,
                            void *user_data) {
    dna_engine_t *engine = (dna_engine_t *)user_data;

    /* Fetch engine's own Kyber secret key (raw bytes).
     * ---> Use actual helper, e.g. dna_engine_get_kyber_secret(engine, sk_out). <--- */
    uint8_t kyber_sk[3168];
    if (dna_engine_get_kyber_secret(engine, kyber_sk, sizeof(kyber_sk)) != 0) {
        fprintf(stderr, "error: cannot load kyber secret\n");
        return true;
    }

    const uint8_t *ct, *nonce, *enc, *tag;
    size_t enc_len = 0;
    int rc = dna_debug_log_decode_outer(data, data_len, &ct, &nonce, &enc, &enc_len, &tag);
    if (rc != DNA_DEBUG_LOG_OK) {
        fprintf(stderr, "warn: malformed outer (rc=%d)\n", rc);
        memset(kyber_sk, 0, sizeof(kyber_sk));
        return true;
    }

    uint8_t *inner = malloc(enc_len);
    if (!inner) { memset(kyber_sk, 0, sizeof(kyber_sk)); return true; }
    size_t inner_len = 0;
    rc = dna_debug_log_decrypt_inner(kyber_sk, sizeof(kyber_sk),
                                      ct, nonce, enc, enc_len, tag,
                                      inner, enc_len, &inner_len);
    memset(kyber_sk, 0, sizeof(kyber_sk));
    if (rc != DNA_DEBUG_LOG_OK) {
        fprintf(stderr, "warn: decrypt failed (rc=%d)\n", rc);
        free(inner);
        return true;
    }

    char hint[129] = {0};
    const uint8_t *body; size_t body_len = 0;
    rc = dna_debug_log_decode_inner(inner, inner_len, hint, sizeof(hint), &body, &body_len);
    if (rc != DNA_DEBUG_LOG_OK) {
        fprintf(stderr, "warn: decode inner failed (rc=%d)\n", rc);
        free(inner);
        return true;
    }

    /* Sender fp not provided by listen callback in v1 — use timestamp as key.
     * If nodus_ops_listen provides owner_fp in a richer callback variant, use it. */
    ensure_out_dir();
    char ts[32];
    iso8601_now(ts, sizeof(ts));
    char path[256];
    snprintf(path, sizeof(path), "%s/debug_%s.log", DEBUG_INBOX_OUT_DIR, ts);

    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(body, 1, body_len, f);
        fclose(f);
        chmod(path, 0600);
        printf("[DEBUG-LOG] hint=\"%s\" size=%zu file=%s\n", hint, body_len, path);
    } else {
        fprintf(stderr, "error: cannot write %s: %s\n", path, strerror(errno));
    }

    memset(inner, 0, inner_len);
    free(inner);
    return true;   /* keep listening */
}

int cmd_debug_inbox_listen(dna_engine_t *engine) {
    /* Get my fp as raw 64 bytes. Use existing engine helper. */
    uint8_t my_fp_raw[64];
    if (dna_engine_get_fingerprint_raw(engine, my_fp_raw, sizeof(my_fp_raw)) != 0) {
        fprintf(stderr, "error: no identity loaded\n");
        return 1;
    }

    uint8_t inbox_key[64];
    dna_debug_log_inbox_key(my_fp_raw, inbox_key);

    printf("Listening on debug inbox (output: %s)\n", DEBUG_INBOX_OUT_DIR);
    printf("Press Ctrl+C to stop.\n");
    fflush(stdout);

    if (nodus_ops_listen(inbox_key, 64, on_inbox_value, engine, NULL) == 0) {
        fprintf(stderr, "error: listen registration failed\n");
        return 1;
    }

    signal(SIGINT, debug_listen_sig);
    signal(SIGTERM, debug_listen_sig);
    g_debug_listening = true;
    while (g_debug_listening) sleep(1);
    printf("\nListener stopped.\n");
    return 0;
}
```

**IMPORTANT:** Verify + replace function names:
```bash
grep -rn "get_fingerprint_raw\|engine_kyber_secret\|get_kyber" /opt/dna/messenger/src/api/ | head -20
grep -n "nodus_ops_listen" /opt/dna/messenger/dht/shared/nodus_ops.h
```
Adjust the call sites.

**Step 3: Wire into dispatch in `main.c`**

Add `debug` group handling. Find the `strcmp(group, "wallet")` (or similar) block, add a new branch:
```c
} else if (strcmp(group, "debug") == 0) {
    if (argc < 1) {
        fprintf(stderr, "Usage: debug <command>\n");
        fprintf(stderr, "  inbox listen     Listen for incoming debug logs\n");
        return 1;
    }
    const char *subcmd = argv[0];
    if (strcmp(subcmd, "inbox") == 0) {
        if (argc < 2 || strcmp(argv[1], "listen") != 0) {
            fprintf(stderr, "Usage: debug inbox listen\n");
            return 1;
        }
        return cmd_debug_inbox_listen(engine);
    }
    fprintf(stderr, "Unknown debug subcommand: %s\n", subcmd);
    return 1;
}
```

Also update the top-level help text in `print_usage` — add `debug` row with description "Receive debug logs sent to this identity".

**Step 4: Build**

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc) dna-connect-cli
```
Expected: clean build.

**Step 5: Smoke-test command dispatch**

```bash
/opt/dna/messenger/build/cli/dna-connect-cli debug
# Expected: prints "Usage: debug <command>" and exits
/opt/dna/messenger/build/cli/dna-connect-cli debug inbox listen
# Expected: "Listening on debug inbox..." (if identity loadable)
# Press Ctrl+C
```

**Step 6: Commit**

```bash
cd /opt/dna
git add messenger/cli/cli_commands.c messenger/cli/cli_commands.h messenger/cli/main.c
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat: add 'debug inbox listen' CLI subcommand"
```

---

### Task 7: Local end-to-end integration test (two identities on this machine)

**Files (no code changes):** validation-only.

**Step 1: Create a second test identity**

```bash
/opt/dna/messenger/build/cli/dna-connect-cli --data-dir /tmp/alice-test identity create alice
```
Note the printed fingerprint (call it `ALICE_FP`).

**Step 2: Get punk's fingerprint**

```bash
/opt/dna/messenger/build/cli/dna-connect-cli -i punk identity whoami
```
Note the printed fingerprint (call it `PUNK_FP`).

**Step 3: Start listener as punk in terminal 1**

```bash
sudo mkdir -p /var/log/dna-debug && sudo chown $USER:$USER /var/log/dna-debug
/opt/dna/messenger/build/cli/dna-connect-cli -i punk debug inbox listen
```

**Step 4: Send a test log as alice in terminal 2**

Write a tiny C test sender or use a temporary CLI command that calls `dna_engine_debug_log_send` with:
- receiver_fp = `PUNK_FP`
- log_body = some canned text (e.g., contents of `/etc/hostname` repeated to a few KB)
- hint = "integration-test"

**Alternative:** add a one-off `debug send <receiver_fp> <file> [hint]` CLI subcommand — simpler. Add to `cli_commands.c` + `main.c`, approximately 30 lines. Worth it because you will use this for manual debugging too.

**Step 5: Verify**

- Terminal 1 should print `[DEBUG-LOG] hint="integration-test" size=N file=/var/log/dna-debug/debug_XXXXX.log`
- `cat /var/log/dna-debug/debug_*.log` should show original contents

**Step 6: Commit any `debug send` helper added**

```bash
cd /opt/dna
git add messenger/cli/cli_commands.c messenger/cli/cli_commands.h messenger/cli/main.c
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat(cli): add 'debug send' helper for sending debug logs"
```

---

## Phase 5: systemd service

### Task 8: Install listener as systemd user service

**Files:**
- Create: `/etc/systemd/system/dna-punk-debug-inbox.service` (requires sudo)
- Create: `docs/deployment/dna-punk-debug-inbox.service` (tracked in repo for future reference)

**Step 1: Write the unit file in repo**

`docs/deployment/dna-punk-debug-inbox.service`:
```ini
[Unit]
Description=DNA Connect — punk debug log inbox listener
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nocdem
Group=nocdem
Environment=HOME=/home/nocdem
ExecStart=/opt/dna/messenger/build/cli/dna-connect-cli -i punk debug inbox listen
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true

[Install]
WantedBy=default.target
```

**Step 2: Install**

```bash
sudo cp docs/deployment/dna-punk-debug-inbox.service /etc/systemd/system/
sudo mkdir -p /var/log/dna-debug && sudo chown nocdem:nocdem /var/log/dna-debug
sudo systemctl daemon-reload
sudo systemctl enable --now dna-punk-debug-inbox.service
```

**Step 3: Verify**

```bash
systemctl status dna-punk-debug-inbox.service
journalctl -u dna-punk-debug-inbox.service -n 20 --no-pager
```
Expected: active, log shows "Listening on debug inbox..."

**Step 4: End-to-end test via service**

Send a test log from alice CLI (as in Task 7) and confirm `journalctl -u dna-punk-debug-inbox -f` shows the arrival.

**Step 5: Commit service file to repo**

```bash
cd /opt/dna
git add -f docs/deployment/dna-punk-debug-inbox.service
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "ops: add systemd unit for punk debug inbox listener"
```

---

## Phase 6: Flutter — sanitizer (TDD)

### Task 9: LogSanitizer Dart class + tests

**Files:**
- Create: `messenger/dna_messenger_flutter/lib/utils/log_sanitizer.dart`
- Create: `messenger/dna_messenger_flutter/test/utils/log_sanitizer_test.dart`

**Step 1: Write failing tests**

`test/utils/log_sanitizer_test.dart`:
```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:dna_messenger_flutter/utils/log_sanitizer.dart';

void main() {
  group('LogSanitizer', () {
    test('redacts 12-word BIP39 mnemonic', () {
      const input = '[DEBUG] seed=abandon ability able about above absent '
                    'absorb abstract absurd abuse access accident done';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('[MNEMONIC REDACTED]'));
      expect(out, isNot(contains('abandon ability able')));
    });

    test('redacts long hex keys (>= 64 chars)', () {
      const input = 'secret=0123456789abcdef0123456789abcdef'
                    '0123456789abcdef0123456789abcdef tail';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('[KEY-'));
      expect(out, contains('REDACTED]'));
      expect(out, contains('tail'));
    });

    test('redacts password=value', () {
      const input = 'connecting with password=hunter2 to server';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('password=[REDACTED]'));
      expect(out, isNot(contains('hunter2')));
    });

    test('redacts token=value and secret=value', () {
      const input = 'auth token=abc123xyz and secret=shh';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('token=[REDACTED]'));
      expect(out, contains('secret=[REDACTED]'));
    });

    test('leaves normal log text untouched', () {
      const input = '2026-04-05 [INFO] user tapped button "Send"\n'
                    '[DEBUG] message id = 42 (not a key)';
      final out = LogSanitizer.scrub(input);
      expect(out, equals(input));
    });

    test('redacts base64 block >= 88 chars', () {
      const input = 'payload=' + 'A' * 100 + '== done';
      final out = LogSanitizer.scrub(input);
      expect(out, contains('[B64-'));
    });
  });
}
```

**Step 2: Run test, verify it fails**

```bash
cd /opt/dna/messenger/dna_messenger_flutter
flutter test test/utils/log_sanitizer_test.dart
```
Expected: compile error, `log_sanitizer.dart` not found.

**Step 3: Implement LogSanitizer**

`lib/utils/log_sanitizer.dart`:
```dart
/// Scrubs secrets out of debug logs before they leave the device.
///
/// Conservative: prefers false positives over false negatives.
class LogSanitizer {
  /// BIP39 detection: 12+ consecutive lowercase words (3-8 letters each).
  /// This is heuristic — any 12 space-separated short words match.
  /// Cheap but catches mnemonic phrases reliably.
  static final RegExp _mnemonicRe =
      RegExp(r'(?:\b[a-z]{3,8}\b[ \t]+){11,}\b[a-z]{3,8}\b');

  /// Hex strings >= 64 chars.
  static final RegExp _hexRe = RegExp(r'\b[0-9a-fA-F]{64,}\b');

  /// Base64 strings >= 88 chars (32-byte keys encode to 44, 64-byte to 88).
  static final RegExp _base64Re = RegExp(r'\b[A-Za-z0-9+/]{88,}={0,2}');

  /// password/token/secret/apikey followed by : = or whitespace then a value.
  static final RegExp _credRe = RegExp(
      r'(?:password|passwd|token|secret|api[_-]?key)([:\s=]+)([^\s"]+)',
      caseSensitive: false);

  static String scrub(String input) {
    var out = input;
    out = out.replaceAllMapped(_mnemonicRe, (_) => '[MNEMONIC REDACTED]');
    out = out.replaceAllMapped(_hexRe,
        (m) => '[KEY-${m.group(0)!.length ~/ 2}B REDACTED]');
    out = out.replaceAllMapped(_base64Re,
        (m) => '[B64-${m.group(0)!.length} REDACTED]');
    out = out.replaceAllMapped(_credRe,
        (m) => '${m.input.substring(m.start, m.start + m.group(0)!.indexOf(m.group(1)!))}'
               '${m.group(1)}[REDACTED]');
    return out;
  }
}
```

*(Note: the `_credRe` replacement is slightly awkward — simplify if tests pass with a cleaner version. For v1, correctness > elegance.)*

**Step 4: Run tests**

```bash
cd /opt/dna/messenger/dna_messenger_flutter
flutter test test/utils/log_sanitizer_test.dart
```
Expected: all 6 tests pass.

**Step 5: Commit**

```bash
cd /opt/dna
git add messenger/dna_messenger_flutter/lib/utils/log_sanitizer.dart \
        messenger/dna_messenger_flutter/test/utils/log_sanitizer_test.dart
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat(flutter): add LogSanitizer with unit tests"
```

---

## Phase 7: Flutter — FFI binding + UI

### Task 10: Add FFI binding for `dna_engine_debug_log_send`

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_bindings.dart`
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart`

**Step 1: Add native signature to `dna_bindings.dart`**

Find a similar send-style binding (e.g., `dna_engine_send_message`) and copy its pattern:
```dart
// Debug log send
typedef _DebugLogSendNative = Int64 Function(
  Pointer<Void> engine,
  Pointer<Utf8> receiverFpHex,
  Pointer<Uint8> logBody,
  IntPtr logLen,
  Pointer<Utf8> hint,
  Pointer<NativeFunction<_CompletionCbNative>> callback,
  Pointer<Void> userData,
);
typedef _DebugLogSendDart = int Function(
  Pointer<Void> engine,
  Pointer<Utf8> receiverFpHex,
  Pointer<Uint8> logBody,
  int logLen,
  Pointer<Utf8> hint,
  Pointer<NativeFunction<_CompletionCbNative>> callback,
  Pointer<Void> userData,
);

final _DebugLogSendDart _dnaEngineDebugLogSend = _lib
    .lookup<NativeFunction<_DebugLogSendNative>>('dna_engine_debug_log_send')
    .asFunction();
```

**Step 2: Add Dart wrapper method**

In `dna_engine.dart`:
```dart
Future<void> sendDebugLog({
  required String receiverFpHex,
  required Uint8List logBody,
  String? hint,
}) async {
  final fpPtr = receiverFpHex.toNativeUtf8();
  final bodyPtr = calloc<Uint8>(logBody.length);
  bodyPtr.asTypedList(logBody.length).setAll(0, logBody);
  final hintPtr = (hint ?? '').toNativeUtf8();

  final completer = Completer<void>();
  // Use existing completion-callback plumbing (same pattern as sendMessage).
  // On callback: if status == 0 complete, else completeError.

  final reqId = _dnaEngineDebugLogSend(
    _enginePtr, fpPtr, bodyPtr, logBody.length, hintPtr,
    _completionCbPtr, _pendingUserData(completer));
  if (reqId == 0) {
    calloc.free(fpPtr); calloc.free(bodyPtr); calloc.free(hintPtr);
    throw Exception('debug_log_send: submit failed (arg validation)');
  }
  try {
    await completer.future;
  } finally {
    calloc.free(fpPtr); calloc.free(bodyPtr); calloc.free(hintPtr);
  }
}
```

*(Reuse the existing async wrapper pattern — the completer/callback plumbing is identical to `sendMessage`. Copy-paste from that wrapper and adjust only the FFI call.)*

**Step 3: Build library + Flutter, confirm no analyzer errors**

```bash
cd /opt/dna/messenger/build && make -j$(nproc)
cd /opt/dna/messenger/dna_messenger_flutter && flutter analyze lib/ffi/
```
Expected: no errors.

**Step 4: Commit**

```bash
cd /opt/dna
git add messenger/dna_messenger_flutter/lib/ffi/
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat(flutter): add FFI binding for debug_log_send"
```

---

### Task 11: "Send to Developer" button + i18n strings

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/settings/debug_log_screen.dart`
- Modify: `messenger/dna_messenger_flutter/lib/l10n/app_en.arb`
- Modify: `messenger/dna_messenger_flutter/lib/l10n/app_tr.arb`
- Create (if absent): `lib/config/app_config.dart` to hold `punkFingerprint` const

**Step 1: Add i18n strings**

`app_en.arb`:
```json
  "debugLogSendToDev": "Send Debug Log to Developer",
  "debugLogSendConfirmTitle": "Send debug log?",
  "debugLogSendConfirmBody": "Send the last 3 MB of the debug log to the developer? Secrets (passwords, keys, mnemonics) are automatically removed before sending.",
  "debugLogSendSending": "Sending debug log…",
  "debugLogSendSuccess": "Debug log sent",
  "debugLogSendFailed": "Send failed: {error}",
  "@debugLogSendFailed": { "placeholders": { "error": {"type": "String"} } },
  "debugLogSendTruncated": "Log was truncated to 3 MB before sending",
```

`app_tr.arb`:
```json
  "debugLogSendToDev": "Debug Log'unu Geliştiriciye Gönder",
  "debugLogSendConfirmTitle": "Debug log gönderilsin mi?",
  "debugLogSendConfirmBody": "Debug log'un son 3 MB'ı geliştiriciye gönderilecek. Sırlar (parolalar, anahtarlar, kurtarma cümleleri) gönderilmeden önce otomatik temizlenir.",
  "debugLogSendSending": "Debug log gönderiliyor…",
  "debugLogSendSuccess": "Debug log gönderildi",
  "debugLogSendFailed": "Gönderim başarısız: {error}",
  "debugLogSendTruncated": "Log gönderilmeden önce 3 MB'a kısaltıldı",
```

**Step 2: Regenerate localizations**

```bash
cd /opt/dna/messenger/dna_messenger_flutter && flutter gen-l10n
```

**Step 3: Add the `punkFingerprint` constant**

In `lib/config/app_config.dart` (create if missing):
```dart
class AppConfig {
  /// The developer's DNA fingerprint (hex, 128 chars). Debug logs are sent
  /// hybrid-encrypted to this identity's DHT inbox.
  static const String punkFingerprint =
      '<PASTE_PUNK_128_HEX_HERE>';   // TODO: set before release
}
```
Grab the real fingerprint from:
```bash
/opt/dna/messenger/build/cli/dna-connect-cli -i punk identity whoami
```
and paste it in place of the placeholder.

**Step 4: Add the button**

In `debug_log_screen.dart`, add a new list item (match the style of existing "Export Debug Log" button). Approximate code:
```dart
ListTile(
  leading: const FaIcon(FontAwesomeIcons.bug),
  title: Text(AppLocalizations.of(context).debugLogSendToDev),
  onTap: () => _sendLogToDeveloper(context),
),
```

And the handler method:
```dart
Future<void> _sendLogToDeveloper(BuildContext context) async {
  final l10n = AppLocalizations.of(context);
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(l10n.debugLogSendConfirmTitle),
      content: Text(l10n.debugLogSendConfirmBody),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(l10n.commonCancel)),
        FilledButton(onPressed: () => Navigator.pop(ctx, true), child: Text(l10n.debugLogSendToDev)),
      ],
    ),
  );
  if (confirmed != true) return;

  // 1. Get log text
  final raw = await DnaLogger.exportAsString();
  // 2. Sanitize
  var safe = LogSanitizer.scrub(raw);
  // 3. Truncate to last 3 MB
  const max = 3 * 1024 * 1024;
  final bytes = Uint8List.fromList(utf8.encode(safe));
  final truncated = bytes.length > max
      ? Uint8List.sublistView(bytes, bytes.length - max)
      : bytes;
  final wasTruncated = truncated.length < bytes.length;

  // 4. Build hint
  final info = await PackageInfo.fromPlatform();
  final hint = '${Platform.operatingSystem}-${info.version}';

  // 5. Send
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: Text(l10n.debugLogSendSending)),
  );
  try {
    await ref.read(dnaEngineProvider).sendDebugLog(
      receiverFpHex: AppConfig.punkFingerprint,
      logBody: truncated,
      hint: hint,
    );
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(wasTruncated
        ? '${l10n.debugLogSendSuccess} · ${l10n.debugLogSendTruncated}'
        : l10n.debugLogSendSuccess)),
    );
  } catch (e) {
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(l10n.debugLogSendFailed(e.toString()))),
    );
  }
}
```

Adjust imports: `package:package_info_plus/package_info_plus.dart`, `dart:io`, `dart:convert`, `../../utils/log_sanitizer.dart`, `../../config/app_config.dart`, etc.

**Step 5: Build Flutter Linux**

```bash
cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux
```
Expected: clean build.

**Step 6: Commit**

```bash
cd /opt/dna
git add messenger/dna_messenger_flutter/lib/ \
        messenger/dna_messenger_flutter/lib/l10n/app_en.arb \
        messenger/dna_messenger_flutter/lib/l10n/app_tr.arb
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat(flutter): add Send Debug Log button in Settings"
```

---

## Phase 8: Verification + version bump

### Task 12: Full build verification

**Files:** none modified in this task — verification only.

**Step 1: Run all tests in messenger**

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```
Expected: all tests pass, zero warnings in build.

**Step 2: Build Flutter Linux + Android (debug)**

```bash
cd /opt/dna/messenger/dna_messenger_flutter
flutter build linux
flutter build apk --debug
```
Expected: both succeed.

**Step 3: Run Flutter tests**

```bash
cd /opt/dna/messenger/dna_messenger_flutter && flutter test
```
Expected: all tests pass.

**Step 4: End-to-end manual test**

1. systemd service already running from Task 8
2. Launch Flutter Linux app
3. Navigate Settings > Debug Log
4. Tap "Send Debug Log to Developer"
5. Confirm dialog
6. Verify SnackBar "Debug log sent"
7. On workstation: `ls -lh /var/log/dna-debug/` — new file should exist
8. `cat` the newest file, verify it contains log text

### Task 13: Version bump

**Files:**
- Modify: `messenger/include/dna/version.h` (bump C library)
- Modify: `messenger/dna_messenger_flutter/pubspec.yaml` (bump app)

**Step 1: Bump C library PATCH**

In `messenger/include/dna/version.h`, bump PATCH (e.g., `v0.9.163` → `v0.9.164`).

**Step 2: Bump Flutter app PATCH + versionCode**

In `pubspec.yaml`, bump (e.g., `1.0.0-rc158+10508` → `1.0.0-rc159+10509`).

**Step 3: Commit**

```bash
cd /opt/dna
git add messenger/include/dna/version.h messenger/dna_messenger_flutter/pubspec.yaml
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" \
GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git commit -m "feat: debug log inbox — send phone logs to dev workstation (vX.Y.Z / vA.B.C-rcNNN) [BUILD]"
```

**Step 4: Push (with user confirmation)**

Do NOT push without explicit user instruction. Per checkpoint 9, wait for user to say `push` / `release` / `release enforced`.

---

## Open items during implementation

These must be resolved by the engineer as they go, not pre-answered here:

1. **Exact name of Kyber1024 encap/decap functions** in `shared/crypto/enc/qgp_kyber.h` — grep and adjust.
2. **Exact AES-GCM helper name/signature** in `shared/crypto/enc/` — grep and adjust.
3. **Random bytes helper** — verify `qgp_random_bytes` vs alternatives.
4. **Receiver Kyber pubkey lookup helper** — need a sync-or-blockable way to fetch a peer's Kyber pubkey from their DHT profile. If none exists synchronously, the debug_log_send handler should be split into a 2-stage async task: (1) lookup profile, (2) on success, do crypto + PUT.
5. **Engine fingerprint / secret key accessors** — `dna_engine_get_fingerprint_raw`, `dna_engine_get_kyber_secret` may not exist under those names. Grep + adjust.
6. **`nodus_ops_listen` callback signature** — verify it passes `owner_fp` of the publisher. If yes, use it to name files like `<owner_fp[0:16]>_<ISO>.log` (design doc preferred format). If not, fall back to timestamp-only as in Task 6 code.
7. **The `LogSanitizer._credRe` replacement** is awkward — clean it up if time permits, as long as all tests still pass.
