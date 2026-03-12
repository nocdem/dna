# Nodus DHT Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace OpenDHT (37,968 lines C++, 7 dependencies) with a DNA-specialized pure C DHT called Nodus.

**Architecture:** Two-tier model — Tier 1: Kademlia DHT between Nodus servers (TCP), Tier 2: simple TCP client protocol. All values Dilithium5-signed. Custom minimal CBOR wire format. SQLite persistence.

**Tech Stack:** Pure C99, SQLite3, OpenSSL (existing), Dilithium5 via `qgp_dsa87_*` (existing), TCP sockets (POSIX/Winsock).

**Design doc:** `docs/plans/2026-02-27-nodus-dht-rewrite-design.md`

---

## Phase 1: Foundation (No Network, No DHT)

Build the core data structures and serialization layer. Everything here is unit-testable without networking.

---

### Task 1: Create directory structure and CMake skeleton

**Files:**
- Create: `nodus/CMakeLists.txt`
- Create: `nodus/include/nodus/nodus_types.h`
- Modify: `CMakeLists.txt` (root) — add `add_subdirectory(nodus)`

**Step 1: Create directory tree**

```bash
mkdir -p nodus/include/nodus
mkdir -p nodus/src/{core,protocol,transport,crypto,client,server}
mkdir -p nodus/tools
mkdir -p nodus/tests
```

**Step 2: Write `nodus/include/nodus/nodus_types.h`**

Core types shared across all modules:

```c
#ifndef NODUS_TYPES_H
#define NODUS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Nodus protocol version */
#define NODUS_PROTOCOL_VERSION  1
#define NODUS_MAGIC             0x4E44  /* "ND" */

/* Kademlia parameters */
#define NODUS_K_BUCKET_SIZE     8       /* k = max nodes per bucket */
#define NODUS_REPLICATION       3       /* r = replicate to 3 nearest */
#define NODUS_KEY_BITS          256     /* SHA3-256 key space */
#define NODUS_KEY_BYTES         32      /* 256 / 8 */
#define NODUS_NODE_ID_BYTES     32      /* SHA3-256(pubkey) */
#define NODUS_NODE_ID_HEX       65      /* 64 hex chars + null */

/* Dilithium5 sizes */
#define NODUS_PUBKEY_BYTES      2592
#define NODUS_PRIVKEY_BYTES     4896
#define NODUS_SIG_BYTES         4627

/* Value types */
#define NODUS_VALUE_EPHEMERAL   0x01    /* 7-day TTL */
#define NODUS_VALUE_PERMANENT   0x02    /* never expires */

/* TTL constants */
#define NODUS_TTL_7DAY          (7 * 24 * 3600)
#define NODUS_TTL_PERMANENT     0

/* Limits (defaults, configurable per server) */
#define NODUS_DEFAULT_PORT              4000
#define NODUS_DEFAULT_MAX_VALUE_SIZE    (1 * 1024 * 1024)  /* 1 MB */
#define NODUS_DEFAULT_MAX_CONNECTIONS   1000
#define NODUS_MAX_FRAME_SIZE            (4 * 1024 * 1024)  /* 4 MB max frame */

/* Error codes */
typedef enum {
    NODUS_OK = 0,
    NODUS_ERR_INVALID_ARG = -1,
    NODUS_ERR_MEMORY = -2,
    NODUS_ERR_IO = -3,
    NODUS_ERR_TIMEOUT = -4,
    NODUS_ERR_AUTH = -5,
    NODUS_ERR_SIGNATURE = -6,
    NODUS_ERR_NOT_FOUND = -7,
    NODUS_ERR_FULL = -8,
    NODUS_ERR_CBOR = -9,
    NODUS_ERR_PROTOCOL = -10,
    NODUS_ERR_RATE_LIMIT = -11,
    NODUS_ERR_TOO_LARGE = -12,
} nodus_error_t;

/* Node ID (256-bit, SHA3-256 of public key) */
typedef struct {
    uint8_t bytes[NODUS_KEY_BYTES];
} nodus_id_t;

/* Nodus value */
typedef struct {
    uint64_t    id;             /* unique value ID per writer */
    uint8_t    *key;            /* raw DHT key (before hashing) */
    size_t      key_len;
    uint8_t    *data;           /* payload */
    size_t      data_len;
    uint8_t     type;           /* EPHEMERAL or PERMANENT */
    uint32_t    ttl;            /* TTL in seconds (0 = permanent) */
    uint64_t    created;        /* unix timestamp */
    uint64_t    seq;            /* sequence number for updates */
    uint8_t     owner[NODUS_PUBKEY_BYTES];   /* Dilithium5 public key */
    uint8_t     sig[NODUS_SIG_BYTES];        /* Dilithium5 signature */
    bool        has_sig;        /* true if sig is populated */
} nodus_value_t;

/* Peer info (for routing table) */
typedef struct {
    nodus_id_t  id;
    char        ip[64];
    uint16_t    port;
    uint8_t     pubkey[NODUS_PUBKEY_BYTES];
    uint64_t    last_seen;      /* unix timestamp */
    uint32_t    rtt_ms;         /* round-trip time */
} nodus_peer_t;

/* Allocate/free values */
nodus_value_t *nodus_value_new(void);
void nodus_value_free(nodus_value_t *val);
nodus_value_t *nodus_value_clone(const nodus_value_t *val);

#endif /* NODUS_TYPES_H */
```

**Step 3: Write CMake skeleton**

`nodus/CMakeLists.txt`:
```cmake
# Nodus — DNA Connect DHT Library
cmake_minimum_required(VERSION 3.10)

set(NODUS_SOURCES
    src/core/nodus_routing.c
    src/core/nodus_storage.c
    src/core/nodus_value.c
    src/protocol/nodus_wire.c
    src/protocol/nodus_cbor.c
    src/protocol/nodus_tier1.c
    src/protocol/nodus_tier2.c
    src/transport/nodus_tcp.c
    src/crypto/nodus_sign.c
    src/crypto/nodus_identity.c
    src/client/nodus_client.c
    src/server/nodus_server.c
    src/server/nodus_discovery.c
)

add_library(nodus STATIC ${NODUS_SOURCES})

target_include_directories(nodus PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/crypto/utils    # qgp_dsa87.h, qgp_sha3.h
    ${CMAKE_SOURCE_DIR}/crypto/dsa      # api.h (Dilithium5)
)

target_link_libraries(nodus PUBLIC
    ${SQLite3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    dsa     # Dilithium5 library
)

# Nodus server binary
add_executable(nodus-server tools/nodus-server.c)
target_link_libraries(nodus-server nodus dsa ${SQLite3_LIBRARIES} ${OPENSSL_LIBRARIES})

# Tests
add_executable(test_nodus_cbor tests/test_cbor.c)
target_link_libraries(test_nodus_cbor nodus)

add_executable(test_nodus_value tests/test_value.c)
target_link_libraries(test_nodus_value nodus dsa)

add_executable(test_nodus_routing tests/test_routing.c)
target_link_libraries(test_nodus_routing nodus)
```

**Step 4: Add to root CMakeLists.txt**

Add after the existing `add_subdirectory(vendor/opendht-pq)` line (don't remove it yet):
```cmake
add_subdirectory(nodus)
```

**Step 5: Create stub source files (empty, to let CMake pass)**

Create empty `.c` files for each source in `NODUS_SOURCES` with just a comment header. This allows the build to succeed while we implement piece by piece.

**Step 6: Verify build**

```bash
cd build && cmake .. && make nodus
```
Expected: compiles with no errors (empty stubs).

**Step 7: Commit**

```bash
git add nodus/ CMakeLists.txt
git commit -m "feat(nodus): scaffold directory structure and CMake build"
```

---

### Task 2: Implement minimal CBOR encoder/decoder

**Files:**
- Create: `nodus/src/protocol/nodus_cbor.c`
- Create: `nodus/src/protocol/nodus_cbor.h` (internal header)
- Create: `nodus/tests/test_cbor.c`

**Context:** CBOR (RFC 8949) is binary JSON. We only need: unsigned ints, byte strings, text strings, arrays, maps. No floats, tags, or indefinite-length. ~500 lines.

**Step 1: Write the test file `nodus/tests/test_cbor.c`**

```c
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/protocol/nodus_cbor.h"

static void test_encode_uint(void) {
    uint8_t buf[16];
    size_t len;

    /* Small uint (0-23 = 1 byte) */
    len = nodus_cbor_encode_uint(buf, sizeof(buf), 0);
    assert(len == 1 && buf[0] == 0x00);

    len = nodus_cbor_encode_uint(buf, sizeof(buf), 23);
    assert(len == 1 && buf[0] == 0x17);

    /* 1-byte uint (24-255 = 2 bytes) */
    len = nodus_cbor_encode_uint(buf, sizeof(buf), 24);
    assert(len == 2 && buf[0] == 0x18 && buf[1] == 24);

    len = nodus_cbor_encode_uint(buf, sizeof(buf), 255);
    assert(len == 2 && buf[0] == 0x18 && buf[1] == 0xFF);

    /* 2-byte uint (256-65535 = 3 bytes) */
    len = nodus_cbor_encode_uint(buf, sizeof(buf), 1000);
    assert(len == 3 && buf[0] == 0x19);

    /* 4-byte uint */
    len = nodus_cbor_encode_uint(buf, sizeof(buf), 100000);
    assert(len == 5 && buf[0] == 0x1A);

    /* 8-byte uint */
    len = nodus_cbor_encode_uint(buf, sizeof(buf), 0x100000000ULL);
    assert(len == 9 && buf[0] == 0x1B);

    printf("  PASS: test_encode_uint\n");
}

static void test_encode_bytes(void) {
    uint8_t buf[64];
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    size_t len;

    len = nodus_cbor_encode_bytes(buf, sizeof(buf), data, 4);
    assert(len == 5);  /* 1 byte header (0x44) + 4 bytes data */
    assert(buf[0] == 0x44);  /* major type 2, length 4 */
    assert(memcmp(buf + 1, data, 4) == 0);

    printf("  PASS: test_encode_bytes\n");
}

static void test_encode_text(void) {
    uint8_t buf[64];
    size_t len;

    len = nodus_cbor_encode_text(buf, sizeof(buf), "hello");
    assert(len == 6);  /* 1 byte header (0x65) + 5 bytes text */
    assert(buf[0] == 0x65);  /* major type 3, length 5 */
    assert(memcmp(buf + 1, "hello", 5) == 0);

    printf("  PASS: test_encode_text\n");
}

static void test_encode_map_header(void) {
    uint8_t buf[16];
    size_t len;

    len = nodus_cbor_encode_map_header(buf, sizeof(buf), 3);
    assert(len == 1 && buf[0] == 0xA3);  /* major type 5, length 3 */

    printf("  PASS: test_encode_map_header\n");
}

static void test_encode_array_header(void) {
    uint8_t buf[16];
    size_t len;

    len = nodus_cbor_encode_array_header(buf, sizeof(buf), 5);
    assert(len == 1 && buf[0] == 0x85);  /* major type 4, length 5 */

    printf("  PASS: test_encode_array_header\n");
}

static void test_decode_uint(void) {
    uint8_t buf[] = {0x19, 0x03, 0xE8};  /* uint 1000 */
    nodus_cbor_reader_t reader;
    nodus_cbor_reader_init(&reader, buf, sizeof(buf));

    uint8_t major;
    uint64_t val;
    assert(nodus_cbor_read_head(&reader, &major, &val) == 0);
    assert(major == 0);  /* unsigned int */
    assert(val == 1000);

    printf("  PASS: test_decode_uint\n");
}

static void test_decode_text(void) {
    uint8_t buf[] = {0x65, 'h', 'e', 'l', 'l', 'o'};
    nodus_cbor_reader_t reader;
    nodus_cbor_reader_init(&reader, buf, sizeof(buf));

    const uint8_t *str;
    size_t str_len;
    assert(nodus_cbor_read_text(&reader, &str, &str_len) == 0);
    assert(str_len == 5);
    assert(memcmp(str, "hello", 5) == 0);

    printf("  PASS: test_decode_text\n");
}

static void test_roundtrip_map(void) {
    /* Encode a simple map: {"t": 42, "y": "q"} */
    uint8_t buf[128];
    size_t pos = 0;

    pos += nodus_cbor_encode_map_header(buf + pos, sizeof(buf) - pos, 2);
    pos += nodus_cbor_encode_text(buf + pos, sizeof(buf) - pos, "t");
    pos += nodus_cbor_encode_uint(buf + pos, sizeof(buf) - pos, 42);
    pos += nodus_cbor_encode_text(buf + pos, sizeof(buf) - pos, "y");
    pos += nodus_cbor_encode_text(buf + pos, sizeof(buf) - pos, "q");

    /* Decode it back */
    nodus_cbor_reader_t reader;
    nodus_cbor_reader_init(&reader, buf, pos);

    uint8_t major;
    uint64_t map_len;
    assert(nodus_cbor_read_head(&reader, &major, &map_len) == 0);
    assert(major == 5);  /* map */
    assert(map_len == 2);

    /* Key "t" */
    const uint8_t *key;
    size_t key_len;
    assert(nodus_cbor_read_text(&reader, &key, &key_len) == 0);
    assert(key_len == 1 && key[0] == 't');

    /* Value 42 */
    uint64_t val;
    assert(nodus_cbor_read_head(&reader, &major, &val) == 0);
    assert(major == 0 && val == 42);

    /* Key "y" */
    assert(nodus_cbor_read_text(&reader, &key, &key_len) == 0);
    assert(key_len == 1 && key[0] == 'y');

    /* Value "q" */
    assert(nodus_cbor_read_text(&reader, &key, &key_len) == 0);
    assert(key_len == 1 && key[0] == 'q');

    printf("  PASS: test_roundtrip_map\n");
}

int main(void) {
    printf("=== CBOR Tests ===\n");
    test_encode_uint();
    test_encode_bytes();
    test_encode_text();
    test_encode_map_header();
    test_encode_array_header();
    test_decode_uint();
    test_decode_text();
    test_roundtrip_map();
    printf("=== ALL CBOR TESTS PASSED ===\n");
    return 0;
}
```

**Step 2: Run test to verify it fails**

```bash
cd build && cmake .. && make test_nodus_cbor && ./nodus/test_nodus_cbor
```
Expected: FAIL — linker errors, functions not defined.

**Step 3: Implement `nodus/src/protocol/nodus_cbor.h`**

The internal header defining the CBOR API. Reader struct holds buffer pointer + current position.

Key types:
- `nodus_cbor_reader_t` — stateful decoder (pointer into buffer)
- Encoder functions return bytes written (0 = buffer too small)
- Decoder functions return 0 on success, -1 on error

CBOR major types: 0=uint, 2=bytes, 3=text, 4=array, 5=map.

**Step 4: Implement `nodus/src/protocol/nodus_cbor.c`**

Encode functions: `nodus_cbor_encode_uint`, `_bytes`, `_text`, `_map_header`, `_array_header`.
Decode functions: `nodus_cbor_reader_init`, `nodus_cbor_read_head`, `_read_bytes`, `_read_text`, `_skip`.

Target: ~400-500 lines.

**Step 5: Run tests**

```bash
cd build && cmake .. && make test_nodus_cbor && ./nodus/test_nodus_cbor
```
Expected: ALL CBOR TESTS PASSED

**Step 6: Commit**

```bash
git add nodus/src/protocol/nodus_cbor.* nodus/tests/test_cbor.c
git commit -m "feat(nodus): minimal CBOR encoder/decoder (RFC 8949)"
```

---

### Task 3: Implement wire frame encoder/decoder

**Files:**
- Create: `nodus/src/protocol/nodus_wire.c`
- Create: `nodus/src/protocol/nodus_wire.h`
- Add tests to: `nodus/tests/test_cbor.c` (or separate test file)

**Context:** Frame format: `[Magic 2B 0x4E44][Version 1B][Length 4B LE32][CBOR payload]`. Total header = 7 bytes.

**Step 1: Write tests for frame encode/decode**

Test: encode a payload into a frame, decode it back, verify magic/version/payload match.

**Step 2: Implement `nodus_wire.h` and `nodus_wire.c`**

```c
/* Encode: write frame header + payload into buffer. Returns total frame size. */
size_t nodus_frame_encode(uint8_t *buf, size_t buf_size,
                          const uint8_t *payload, size_t payload_len);

/* Decode header: read magic, version, payload_len from buffer.
   Returns 0 on success, -1 on error (bad magic, truncated, etc.) */
int nodus_frame_decode_header(const uint8_t *buf, size_t buf_len,
                              uint8_t *version_out, uint32_t *payload_len_out);

#define NODUS_FRAME_HEADER_SIZE 7
```

Target: ~80 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): wire frame encoder/decoder"
```

---

### Task 4: Implement nodus_value (create, sign, verify, serialize)

**Files:**
- Create: `nodus/src/core/nodus_value.c`
- Create: `nodus/src/core/nodus_value.h` (internal)
- Create: `nodus/tests/test_value.c`

**Context:** A NodusValue holds data + Dilithium5 signature. Serialization uses CBOR. Signing covers: id, key, data, type, ttl, created, seq, owner. Signature verification is what prevents malicious Nodus from tampering.

**Step 1: Write test file**

Tests:
- `test_value_create_free` — allocate, set fields, free without leak
- `test_value_sign_verify` — create value, sign with test key, verify signature
- `test_value_tamper_detect` — sign, modify data, verify should fail
- `test_value_serialize_deserialize` — encode to CBOR, decode back, compare all fields

**Step 2: Implement**

Functions:
```c
nodus_value_t *nodus_value_new(void);
void nodus_value_free(nodus_value_t *val);
nodus_value_t *nodus_value_clone(const nodus_value_t *val);

/* Sign value with Dilithium5 private key */
int nodus_value_sign(nodus_value_t *val, const uint8_t *privkey);

/* Verify value signature against owner pubkey */
int nodus_value_verify(const nodus_value_t *val);

/* Serialize to CBOR (caller must free *out) */
int nodus_value_serialize(const nodus_value_t *val, uint8_t **out, size_t *out_len);

/* Deserialize from CBOR */
int nodus_value_deserialize(const uint8_t *data, size_t data_len, nodus_value_t **val_out);

/* Compute key hash: SHA3-256(raw_key) → nodus_id_t */
void nodus_key_hash(const uint8_t *key, size_t key_len, nodus_id_t *hash_out);
```

Uses: `qgp_dsa87_sign()`, `qgp_dsa87_verify()` from `crypto/utils/qgp_dilithium.h`.
Uses: `qgp_sha3_256()` from `crypto/utils/qgp_sha3.h`.

Target: ~400 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): value create/sign/verify/serialize"
```

---

### Task 5: Implement Dilithium5 crypto wrapper

**Files:**
- Create: `nodus/src/crypto/nodus_sign.c`
- Create: `nodus/src/crypto/nodus_sign.h`
- Create: `nodus/src/crypto/nodus_identity.c`
- Create: `nodus/src/crypto/nodus_identity.h`

**Context:** Thin wrapper around DNA's existing `qgp_dsa87_*` functions. Identity = Dilithium5 keypair + node_id (SHA3-256 of pubkey).

**Step 1: Write tests** — key generation, sign/verify, identity save/load.

**Step 2: Implement**

```c
/* nodus_sign.h */
int nodus_sign(uint8_t sig[NODUS_SIG_BYTES], const uint8_t *msg, size_t msg_len,
               const uint8_t privkey[NODUS_PRIVKEY_BYTES]);
int nodus_verify(const uint8_t sig[NODUS_SIG_BYTES],
                 const uint8_t *msg, size_t msg_len,
                 const uint8_t pubkey[NODUS_PUBKEY_BYTES]);

/* nodus_identity.h */
typedef struct {
    uint8_t pubkey[NODUS_PUBKEY_BYTES];
    uint8_t privkey[NODUS_PRIVKEY_BYTES];
    nodus_id_t node_id;   /* SHA3-256(pubkey) */
} nodus_identity_t;

int nodus_identity_generate(nodus_identity_t *id);
int nodus_identity_generate_from_seed(nodus_identity_t *id, const uint8_t seed[32]);
int nodus_identity_save(const nodus_identity_t *id, const char *dir_path);
int nodus_identity_load(nodus_identity_t *id, const char *dir_path);
void nodus_id_to_hex(const nodus_id_t *id, char hex_out[NODUS_NODE_ID_HEX]);
```

Target: ~250 lines total.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): Dilithium5 crypto wrapper and identity management"
```

---

## Phase 2: Kademlia Core (No Network Yet)

Build the routing table and storage. Test with in-memory operations.

---

### Task 6: Implement Kademlia routing table

**Files:**
- Create: `nodus/src/core/nodus_routing.c`
- Create: `nodus/src/core/nodus_routing.h`
- Create: `nodus/tests/test_routing.c`

**Context:** Kademlia routing table = 256 k-buckets. Each bucket holds up to k=8 peers. Bucket index = number of leading zero bits in `XOR(my_id, peer_id)`. Closest peers found by XOR distance sort.

**Step 1: Write tests**

- `test_xor_distance` — verify XOR metric properties
- `test_bucket_index` — correct bucket selection
- `test_add_peer` — add peer, verify it's in correct bucket
- `test_bucket_full` — add k+1 peers, verify oldest is evicted (or not)
- `test_find_closest` — add N peers, find k closest to target, verify order
- `test_routing_table_self` — own ID should not be added

**Step 2: Implement**

```c
/* Routing table */
typedef struct nodus_routing nodus_routing_t;

nodus_routing_t *nodus_routing_new(const nodus_id_t *self_id);
void nodus_routing_free(nodus_routing_t *rt);

/* Add/update peer in routing table. Returns 0 if added, 1 if updated, -1 if rejected */
int nodus_routing_add(nodus_routing_t *rt, const nodus_peer_t *peer);

/* Remove peer */
int nodus_routing_remove(nodus_routing_t *rt, const nodus_id_t *peer_id);

/* Find k closest peers to target (returns count, up to k) */
int nodus_routing_find_closest(nodus_routing_t *rt, const nodus_id_t *target,
                               nodus_peer_t *out, int max_count);

/* Get total peer count */
size_t nodus_routing_count(const nodus_routing_t *rt);

/* XOR distance */
void nodus_xor_distance(const nodus_id_t *a, const nodus_id_t *b, nodus_id_t *out);
int nodus_id_compare(const nodus_id_t *a, const nodus_id_t *b); /* -1, 0, 1 */

/* Mark peer as seen (update last_seen) */
void nodus_routing_touch(nodus_routing_t *rt, const nodus_id_t *peer_id);
```

Target: ~500 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): Kademlia routing table (k=8, 256-bit)"
```

---

### Task 7: Implement SQLite storage

**Files:**
- Create: `nodus/src/core/nodus_storage.c`
- Create: `nodus/src/core/nodus_storage.h`
- Create: `nodus/tests/test_storage.c` (add to CMake)

**Context:** SQLite-backed value storage for Nodus servers. Schema from design doc. Thread-safe with mutex.

**Step 1: Write tests**

- `test_storage_create` — create DB, verify tables exist
- `test_storage_put_get` — store value, retrieve it
- `test_storage_multi_writer` — same key, different owners → both stored
- `test_storage_update_seq` — same key+owner, higher seq → replaces
- `test_storage_expire` — store ephemeral, advance time, cleanup → deleted
- `test_storage_permanent` — store permanent, cleanup → NOT deleted

**Step 2: Implement**

```c
typedef struct nodus_storage nodus_storage_t;

nodus_storage_t *nodus_storage_new(const char *db_path);
void nodus_storage_free(nodus_storage_t *store);

/* Store value (validates signature before storing) */
int nodus_storage_put(nodus_storage_t *store, const nodus_value_t *val);

/* Get single value (first/newest) for key */
int nodus_storage_get(nodus_storage_t *store, const nodus_id_t *key_hash,
                      nodus_value_t **val_out);

/* Get all values for key (multi-writer) */
int nodus_storage_get_all(nodus_storage_t *store, const nodus_id_t *key_hash,
                          nodus_value_t ***vals_out, size_t *count_out);

/* Delete expired values. Returns count deleted. */
int nodus_storage_cleanup(nodus_storage_t *store);

/* Get stats */
typedef struct {
    uint64_t total_values;
    uint64_t storage_bytes;
    uint64_t put_count;
    uint64_t get_count;
} nodus_storage_stats_t;
int nodus_storage_get_stats(nodus_storage_t *store, nodus_storage_stats_t *stats);

/* Iterate all values for republish (callback returns 0 to continue, -1 to stop) */
int nodus_storage_iterate(nodus_storage_t *store,
                          int (*callback)(const nodus_value_t *val, void *ctx),
                          void *ctx);
```

Target: ~500 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): SQLite value storage with TTL cleanup"
```

---

## Phase 3: Networking (TCP Transport)

---

### Task 8: Implement TCP transport layer

**Files:**
- Create: `nodus/src/transport/nodus_tcp.c`
- Create: `nodus/src/transport/nodus_tcp.h`

**Context:** TCP server (accept connections) + client (connect to peer). Connection pool for persistent Nodus↔Nodus connections. Frame-based I/O (read/write full frames). Cross-platform: POSIX sockets + Winsock abstraction.

**Step 1: Write tests** — connect loopback, send frame, receive frame, verify payload.

**Step 2: Implement**

```c
/* TCP listener (server) */
typedef struct nodus_tcp_listener nodus_tcp_listener_t;

nodus_tcp_listener_t *nodus_tcp_listen(const char *bind_ip, uint16_t port);
void nodus_tcp_listener_free(nodus_tcp_listener_t *listener);
int nodus_tcp_listener_fd(nodus_tcp_listener_t *listener);  /* for poll/select */

/* TCP connection */
typedef struct nodus_tcp_conn nodus_tcp_conn_t;

nodus_tcp_conn_t *nodus_tcp_accept(nodus_tcp_listener_t *listener);
nodus_tcp_conn_t *nodus_tcp_connect(const char *host, uint16_t port, int timeout_ms);
void nodus_tcp_conn_free(nodus_tcp_conn_t *conn);
int nodus_tcp_conn_fd(nodus_tcp_conn_t *conn);

/* Frame I/O (blocking) */
int nodus_tcp_send_frame(nodus_tcp_conn_t *conn, const uint8_t *payload, size_t len);
int nodus_tcp_recv_frame(nodus_tcp_conn_t *conn, uint8_t **payload_out, size_t *len_out,
                         int timeout_ms);

/* Connection pool (for Nodus↔Nodus persistent connections) */
typedef struct nodus_conn_pool nodus_conn_pool_t;

nodus_conn_pool_t *nodus_conn_pool_new(int max_connections);
void nodus_conn_pool_free(nodus_conn_pool_t *pool);
nodus_tcp_conn_t *nodus_conn_pool_get(nodus_conn_pool_t *pool,
                                       const char *host, uint16_t port);
void nodus_conn_pool_release(nodus_conn_pool_t *pool, nodus_tcp_conn_t *conn);
```

Platform abstraction:
```c
#ifdef _WIN32
  #include <winsock2.h>
  typedef SOCKET nodus_socket_t;
  #define NODUS_INVALID_SOCKET INVALID_SOCKET
#else
  #include <sys/socket.h>
  typedef int nodus_socket_t;
  #define NODUS_INVALID_SOCKET (-1)
#endif
```

Target: ~600 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): TCP transport layer with connection pool"
```

---

### Task 9: Implement Tier 1 protocol (Nodus ↔ Nodus messages)

**Files:**
- Create: `nodus/src/protocol/nodus_tier1.c`
- Create: `nodus/src/protocol/nodus_tier1.h`

**Context:** Kademlia messages (PING, FIND_NODE, STORE, FIND_VALUE) + pub/sub messages (SUBSCRIBE, UNSUBSCRIBE, NOTIFY). Each message is CBOR-encoded with transaction ID for request/response matching.

**Step 1: Write tests** — encode each message type, decode back, verify fields.

**Step 2: Implement**

Message types enum + encode/decode functions:
```c
typedef enum {
    NODUS_MSG_PING = 1,
    NODUS_MSG_PONG,
    NODUS_MSG_FIND_NODE,
    NODUS_MSG_NODES_FOUND,
    NODUS_MSG_STORE,
    NODUS_MSG_STORE_ACK,
    NODUS_MSG_FIND_VALUE,
    NODUS_MSG_VALUE_FOUND,
    NODUS_MSG_SUBSCRIBE,
    NODUS_MSG_SUB_ACK,
    NODUS_MSG_UNSUBSCRIBE,
    NODUS_MSG_UNSUB_ACK,
    NODUS_MSG_NOTIFY,
    /* Auth */
    NODUS_MSG_HELLO,
    NODUS_MSG_CHALLENGE,
    NODUS_MSG_VERIFY,
    NODUS_MSG_AUTH_OK,
} nodus_msg_type_t;

/* Generic message container */
typedef struct {
    uint32_t txn_id;
    nodus_msg_type_t type;
    union { ... } body;  /* type-specific fields */
} nodus_msg_t;

int nodus_msg_encode(const nodus_msg_t *msg, uint8_t **out, size_t *out_len);
int nodus_msg_decode(const uint8_t *data, size_t data_len, nodus_msg_t *msg_out);
void nodus_msg_free(nodus_msg_t *msg);
```

Target: ~500 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): Tier 1 protocol messages (Kademlia + pub/sub)"
```

---

### Task 10: Implement Tier 2 protocol (Client ↔ Nodus messages)

**Files:**
- Create: `nodus/src/protocol/nodus_tier2.c`
- Create: `nodus/src/protocol/nodus_tier2.h`

**Context:** Client commands: HELLO, AUTH, PUT, GET, GET_ALL, LISTEN, UNLISTEN, BATCH_GET, PING. Server responses: CHALLENGE, AUTH_OK, RESULT, VALUE_CHANGED, ERROR.

**Step 1: Write tests** — encode/decode each client command and server response.

**Step 2: Implement** — similar structure to Tier 1, ~400 lines.

**Step 3: Run tests, commit**

```bash
git commit -m "feat(nodus): Tier 2 protocol messages (Client ↔ Nodus)"
```

---

## Phase 4: Nodus Server

---

### Task 11: Implement Nodus server core (main loop + client handling)

**Files:**
- Create: `nodus/src/server/nodus_server.c`
- Create: `nodus/src/server/nodus_server.h`

**Context:** Event-driven server: accept TCP connections, dispatch Tier 1 and Tier 2 messages. Uses `poll()` (or `select()` for Windows compat) for multiplexing.

**Step 1: Implement**

```c
typedef struct nodus_server nodus_server_t;

typedef struct {
    uint16_t port;
    const char *bind_ip;        /* NULL = 0.0.0.0 */
    const char *persistence_path;
    const char *identity_path;
    const char **seed_nodes;    /* NULL-terminated array of "ip:port" */
    /* Rate limits */
    int max_puts_per_minute;
    int max_value_size;
    int max_connections;
} nodus_server_config_t;

nodus_server_t *nodus_server_new(const nodus_server_config_t *config);
void nodus_server_free(nodus_server_t *srv);

/* Run server (blocking — runs event loop) */
int nodus_server_run(nodus_server_t *srv);

/* Stop server (from signal handler) */
void nodus_server_stop(nodus_server_t *srv);
```

Internally, server holds: routing table, storage, identity, listener/subscriber tables, connection pool.

Target: ~600 lines.

**Step 2: Write `nodus/tools/nodus-server.c` (entry point)**

```c
#include <nodus/nodus_server.h>
#include <signal.h>
#include <stdio.h>

static nodus_server_t *g_server = NULL;

void signal_handler(int sig) {
    (void)sig;
    if (g_server) nodus_server_stop(g_server);
}

int main(int argc, char **argv) {
    /* Load config from /etc/nodus.conf or defaults */
    nodus_server_config_t config = { .port = 4000, ... };
    /* ... JSON config loading ... */

    g_server = nodus_server_new(&config);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    return nodus_server_run(g_server);
}
```

**Step 3: Verify build**

```bash
cd build && cmake .. && make nodus-server
```

**Step 4: Commit**

```bash
git commit -m "feat(nodus): server core with event loop and config"
```

---

### Task 12: Implement Nodus ↔ Nodus authentication (mutual handshake)

**Files:**
- Modify: `nodus/src/server/nodus_server.c`
- Create: `nodus/src/server/nodus_auth.c`
- Create: `nodus/src/server/nodus_auth.h`

**Context:** When two Nodus nodes connect, they perform mutual Dilithium5 challenge-response. After auth, derive HMAC key for session.

**Step 1: Implement auth handshake**

```c
/* Initiate handshake (caller = connecting Nodus) */
int nodus_auth_initiate(nodus_tcp_conn_t *conn, const nodus_identity_t *self,
                        nodus_peer_t *peer_out);

/* Accept handshake (callee = listening Nodus) */
int nodus_auth_accept(nodus_tcp_conn_t *conn, const nodus_identity_t *self,
                      nodus_peer_t *peer_out);
```

**Step 2: Write integration test** — start two servers on localhost, verify they authenticate each other.

**Step 3: Commit**

```bash
git commit -m "feat(nodus): mutual Dilithium5 authentication for Nodus peers"
```

---

### Task 13: Implement Kademlia operations (PING, FIND_NODE, STORE, FIND_VALUE)

**Files:**
- Modify: `nodus/src/server/nodus_server.c` — add message handlers

**Context:** Server receives Tier 1 messages and responds. FIND_NODE returns k closest from routing table. STORE saves value. FIND_VALUE returns value or nearest nodes.

**Step 1: Implement message handlers**

- `handle_ping` → respond with PONG
- `handle_find_node` → lookup routing table, return closest k peers
- `handle_store` → validate signature, store in SQLite, check subscribers → NOTIFY
- `handle_find_value` → lookup storage, return value if found, else closest nodes

**Step 2: Implement Kademlia node lookup (iterative)**

```c
/* Find k nodes closest to target across the network (iterative Kademlia lookup) */
int nodus_kademlia_lookup(nodus_server_t *srv, const nodus_id_t *target,
                          nodus_peer_t *results, int *result_count);
```

**Step 3: Integration test** — 3 servers on localhost, PUT on one, GET from another.

**Step 4: Commit**

```bash
git commit -m "feat(nodus): Kademlia operations (PING, FIND_NODE, STORE, FIND_VALUE)"
```

---

### Task 14: Implement replication (r=3) and bootstrap

**Files:**
- Modify: `nodus/src/server/nodus_server.c`
- Create: `nodus/src/server/nodus_discovery.c`
- Create: `nodus/src/server/nodus_discovery.h`

**Context:** On PUT, replicate value to r=3 nearest Nodus nodes. On startup, bootstrap from seed nodes, build routing table.

**Step 1: Implement PUT replication**

```c
/* Replicate value to r nearest Nodus nodes */
int nodus_replicate(nodus_server_t *srv, const nodus_value_t *val, int r);
```

**Step 2: Implement bootstrap**

```c
/* Bootstrap from seed nodes: connect, auth, FIND_NODE(self) to populate routing table */
int nodus_bootstrap(nodus_server_t *srv, const char **seed_nodes);
```

**Step 3: Implement Nodus registry** (each Nodus publishes own info to DHT)

**Step 4: Commit**

```bash
git commit -m "feat(nodus): replication (r=3), bootstrap, and peer discovery"
```

---

### Task 15: Implement distributed LISTEN (pub/sub)

**Files:**
- Modify: `nodus/src/server/nodus_server.c` — add SUBSCRIBE/NOTIFY handlers

**Context:** When client LISTENs, Nodus routes SUBSCRIBE to responsible node. On new STORE, responsible node sends NOTIFY to subscribers. See design doc for full flow.

**Step 1: Add subscriptions table to storage**

**Step 2: Implement SUBSCRIBE/UNSUBSCRIBE handlers**

**Step 3: Implement NOTIFY dispatch on STORE**

**Step 4: Integration test** — client A LISTENs on key, client B PUTs to key, verify A receives VALUE_CHANGED.

**Step 5: Commit**

```bash
git commit -m "feat(nodus): distributed pub/sub for LISTEN"
```

---

## Phase 5: Client SDK

---

### Task 16: Implement Nodus client SDK

**Files:**
- Create: `nodus/src/client/nodus_client.c`
- Create: `nodus/include/nodus/nodus.h` (public API)

**Context:** This is what DNA Connect will use instead of `dht_context_*`. Simple API: connect to Nodus, authenticate, PUT/GET/LISTEN.

**Step 1: Implement public API**

```c
/* nodus.h — Public Client API */

typedef struct nodus_client nodus_client_t;

/* Lifecycle */
nodus_client_t *nodus_client_new(void);
void nodus_client_free(nodus_client_t *client);

/* Connect to a Nodus server and authenticate */
int nodus_client_connect(nodus_client_t *client, const char *host, uint16_t port,
                         const nodus_identity_t *identity);
void nodus_client_disconnect(nodus_client_t *client);
bool nodus_client_is_connected(nodus_client_t *client);

/* PUT value */
int nodus_put(nodus_client_t *client, const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len, uint8_t type, uint32_t ttl,
              uint64_t value_id, uint64_t seq);

/* GET single value */
int nodus_get(nodus_client_t *client, const uint8_t *key, size_t key_len,
              uint8_t **data_out, size_t *data_len_out);

/* GET all values for key (multi-writer) */
int nodus_get_all(nodus_client_t *client, const uint8_t *key, size_t key_len,
                  nodus_value_t ***vals_out, size_t *count_out);

/* Batch GET */
int nodus_get_batch(nodus_client_t *client,
                    const uint8_t **keys, const size_t *key_lens, size_t count,
                    nodus_value_t ***vals_out, size_t *counts_out);

/* LISTEN — callback invoked when value changes */
typedef void (*nodus_listen_cb)(const uint8_t *key, size_t key_len,
                                const nodus_value_t *val, void *user_data);

int nodus_listen(nodus_client_t *client, const uint8_t *key, size_t key_len,
                 nodus_listen_cb callback, void *user_data);
int nodus_unlisten(nodus_client_t *client, const uint8_t *key, size_t key_len);

/* Status callback */
typedef void (*nodus_status_cb)(bool connected, void *user_data);
void nodus_client_set_status_callback(nodus_client_t *client,
                                       nodus_status_cb callback, void *user_data);

/* Get this client's node ID */
int nodus_client_get_node_id(nodus_client_t *client, char *hex_out);
```

**Step 2: Write integration test** — client connects to test server, PUT, GET, verify.

**Step 3: Commit**

```bash
git commit -m "feat(nodus): client SDK with PUT/GET/LISTEN API"
```

---

## Phase 6: DNA Connect Integration

This is the critical phase — replacing OpenDHT with Nodus inside DNA Connect.

---

### Task 17: Create nodus_singleton (replaces dht_singleton)

**Files:**
- Create: `nodus/src/client/nodus_singleton.c`
- Create: `nodus/src/client/nodus_singleton.h`

**Context:** DNA engine uses `dht_singleton_get()` everywhere to access the DHT context. Create equivalent `nodus_singleton_get()` that returns a `nodus_client_t*`.

**Step 1: Implement**

```c
/* Global singleton — one Nodus client per process */
int nodus_singleton_init(const char *host, uint16_t port,
                         const nodus_identity_t *identity);
nodus_client_t *nodus_singleton_get(void);
void nodus_singleton_destroy(void);
bool nodus_singleton_is_initialized(void);
```

**Step 2: Commit**

```bash
git commit -m "feat(nodus): client singleton for DNA engine integration"
```

---

### Task 18: Create compatibility shim (dht_context API → nodus_client API)

**Files:**
- Create: `nodus/src/client/nodus_compat.c`
- Create: `nodus/src/client/nodus_compat.h`

**Context:** Instead of modifying all 30+ files that call `dht_put_signed()`, `dht_get()`, `dht_listen()` etc., create a thin compatibility layer that maps old function names to new Nodus calls. This allows gradual migration.

**Step 1: Implement compatibility functions**

Map the most-used DHT functions to Nodus equivalents:
```c
/* These match the old dht_context.h signatures but internally use nodus_client */

int dht_put_signed(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id, unsigned int ttl_seconds, const char *caller);
/* → calls nodus_put() */

int dht_get(dht_context_t *ctx, const uint8_t *key, size_t key_len,
            uint8_t **value_out, size_t *value_len_out);
/* → calls nodus_get() */

int dht_get_all(dht_context_t *ctx, ...);
/* → calls nodus_get_all() */

size_t dht_listen(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                  void (*callback)(...), void *userdata);
/* → calls nodus_listen() */

/* etc. for all functions in dht_context.h */
```

**Important:** `dht_context_t*` parameter is accepted but ignored — all calls go through `nodus_singleton_get()`. This matches the current pattern where most code already uses `dht_singleton_get()` anyway.

**Step 2: Commit**

```bash
git commit -m "feat(nodus): compatibility shim (dht_context API → nodus_client)"
```

---

### Task 19: Update CMake build — link nodus instead of opendht

**Files:**
- Modify: `dht/CMakeLists.txt` — replace opendht dependency with nodus
- Modify: `CMakeLists.txt` (root) — remove `add_subdirectory(vendor/opendht-pq)`

**Step 1: Update `dht/CMakeLists.txt`**

- Remove C++ source files: `dht_context.cpp`, `dht_listen.cpp`, `dht_stats.cpp`, `dht_identity.cpp`, `dht_value_storage.cpp`
- Remove `dht_chunked.c` (no longer needed with TCP)
- Add: `nodus_compat.c` and `nodus_singleton.c`
- Replace link target: `opendht` → `nodus`
- Change C++ standard requirement → pure C (no C++17 needed)

**Step 2: Remove OpenDHT from root CMakeLists.txt**

Comment out or remove: `add_subdirectory(vendor/opendht-pq)`

**Step 3: Verify build**

```bash
cd build && cmake .. && make -j$(nproc)
```

Fix any linker errors — there will be missing symbols from removed C++ files. The compat shim should provide all needed functions.

**Step 4: Commit**

```bash
git commit -m "build(nodus): replace opendht with nodus library in build system"
```

---

### Task 20: Update domain modules to use nodus (incremental)

**Files:**
- Modify: all files in `dht/shared/` and `dht/client/` that call `dht_chunked_*`

**Context:** With TCP transport, chunking is no longer needed. Files that use `dht_chunked_publish()` should call `nodus_put()` directly. Files that use `dht_chunked_fetch()` should call `nodus_get()`.

**Step 1: Grep for all dht_chunked_* calls**

```bash
grep -rn "dht_chunked_" dht/shared/ dht/client/ dht/keyserver/
```

**Step 2: Replace each chunked call**

| Old call | New call |
|----------|----------|
| `dht_chunked_publish(ctx, key, data, len, ttl)` | `nodus_put(singleton, key, key_len, data, len, type, ttl, vid, seq)` |
| `dht_chunked_fetch(ctx, key, &data, &len)` | `nodus_get(singleton, key, key_len, &data, &len)` |
| `dht_chunked_fetch_all(ctx, key, ...)` | `nodus_get_all(singleton, key, key_len, ...)` |
| `dht_chunked_fetch_mine(ctx, key, ...)` | `nodus_get(singleton, key, key_len, ...)` (owner filtered client-side) |

**Step 3: Build, fix errors iteratively**

**Step 4: Commit per module group**

```bash
git commit -m "refactor(nodus): migrate dht_chunked calls to nodus_put/get"
```

---

### Task 21: Update engine identity loading (nodus_singleton init)

**Files:**
- Modify: `src/api/engine/dna_engine_identity.c` — replace `dht_context` creation with `nodus_singleton_init()`
- Modify: `src/api/engine/dna_engine_helpers.c` — `dna_get_dht_ctx()` returns compat pointer
- Modify: `src/api/engine/dna_engine_presence.c` — lifecycle changes

**Context:** Currently the engine creates a `dht_context_t*` via `messenger_load_dht_identity_for_engine()` and sets it as singleton. Replace with Nodus client initialization.

**Step 1: Modify identity loading**

In `dna_engine_identity.c` around line 162, replace:
```c
// OLD:
messenger_load_dht_identity_for_engine(fingerprint, &engine->dht_ctx);
dht_singleton_set_borrowed_context(engine->dht_ctx);

// NEW:
nodus_identity_t nodus_id;
/* Load identity from mnemonic-derived seed */
nodus_identity_generate_from_seed(&nodus_id, seed);
nodus_singleton_init(bootstrap_host, bootstrap_port, &nodus_id);
```

**Step 2: Build and test**

**Step 3: Commit**

```bash
git commit -m "refactor(nodus): engine identity loading uses nodus_singleton"
```

---

### Task 22: Remove OpenDHT vendor directory

**Files:**
- Delete: `vendor/opendht-pq/` (entire directory — 37,968 lines)
- Delete: `dht/core/dht_context.cpp` (2,124 lines)
- Delete: `dht/core/dht_listen.cpp` (569 lines)
- Delete: `dht/core/dht_stats.cpp` (81 lines)
- Delete: `dht/client/dht_identity.cpp` (256 lines)
- Delete: `dht/shared/dht_value_storage.cpp` (971 lines)
- Delete: `dht/shared/dht_chunked.c` (1,999 lines) + `.h` (339 lines)

**Step 1: Verify build succeeds WITHOUT these files**

```bash
cd build && cmake .. && make -j$(nproc)
```

**Step 2: Delete files**

**Step 3: Verify build again**

**Step 4: Commit**

```bash
git commit -m "chore(nodus): remove OpenDHT vendor directory and C++ bridge files

Removed 37,968 lines of C++ (OpenDHT) + 5,000 lines of C++ bridge code.
Removed 7 external dependencies: GnuTLS, nettle, argon2, msgpack, fmt, ASIO, gmp."
```

---

### Task 23: Update transport layer

**Files:**
- Modify: `transport/transport.c` — use `nodus_singleton_get()` instead of `dht_singleton_get()`
- Modify: `transport/internal/transport_discovery.c`
- Modify: `transport/internal/transport_offline.c`

**Step 1: Replace DHT singleton calls with Nodus singleton**

**Step 2: Build, fix any remaining references**

**Step 3: Commit**

```bash
git commit -m "refactor(nodus): transport layer uses nodus_singleton"
```

---

## Phase 7: Server Deployment

---

### Task 24: Write nodus-server config loader

**Files:**
- Create: `nodus/src/server/nodus_config.c`
- Create: `nodus/src/server/nodus_config.h`

**Context:** JSON config from `/etc/nodus.conf`. Uses json-c (already a DNA dependency).

**Step 1: Implement config struct and loader**

Config file format from design doc. Includes: port, seed_nodes, persistence_path, identity_path, limits.

**Step 2: Commit**

```bash
git commit -m "feat(nodus): server JSON config loader"
```

---

### Task 25: Write systemd service + build script

**Files:**
- Create: `nodus/tools/nodus.service`
- Modify: `build-nodus.sh` — build new nodus-server instead of old dna-nodus

**Step 1: Write systemd service** (based on existing `dna-nodus.service` with updated paths)

**Step 2: Update build script** — build target is now `nodus-server` not `dna-nodus`

**Step 3: Commit**

```bash
git commit -m "feat(nodus): systemd service and build script for deployment"
```

---

### Task 26: Full integration test

**Files:**
- Create: `nodus/tests/test_integration.c`

**Context:** Start 3 Nodus servers + 2 clients. Verify:
1. Servers bootstrap and discover each other
2. Client PUT on server 1, GET from server 2 (replication works)
3. Client LISTEN on server 1, PUT from server 3, verify push received
4. Kill server 2, verify data still available from servers 1 and 3
5. Restart server 2, verify it republishes from SQLite

**Step 1: Write test**

**Step 2: Run and fix**

**Step 3: Commit**

```bash
git commit -m "test(nodus): full integration test (3 servers, 2 clients)"
```

---

### Task 27: Update documentation

**Files:**
- Modify: `docs/DNA_NODUS.md` — rewrite for new Nodus architecture
- Modify: `docs/DHT_SYSTEM.md` — update for two-tier model
- Modify: `docs/ARCHITECTURE_DETAILED.md` — update dependency list
- Modify: `docs/functions/dht.md` — update function reference
- Modify: `CLAUDE.md` — update version, nodus paths, build commands

**Step 1: Update all docs to reflect new architecture**

**Step 2: Commit**

```bash
git commit -m "docs(nodus): update all documentation for Nodus DHT rewrite"
```

---

## Task Dependency Graph

```
Phase 1 (Foundation):    T1 → T2 → T3 → T4 → T5
Phase 2 (Kademlia):      T5 → T6 → T7
Phase 3 (Networking):    T3 → T8 → T9 → T10
Phase 4 (Server):        T6+T7+T8+T9+T10 → T11 → T12 → T13 → T14 → T15
Phase 5 (Client SDK):    T10+T11 → T16 → T17 → T18 → T19 → T20 → T21 → T22 → T23
Phase 6 (Deployment):    T22 → T24 → T25 → T26 → T27
```

**Estimated total:** ~6,200 lines of new C code + ~42,000 lines removed.
