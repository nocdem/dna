# DHT v2 Record Codec Functions (`shared/dht2/`)

DHT v2 package 1: the byte layer of the storage-node DHT for Nodus Connect —
a strict DAG-CBOR reader / writer, the signed record (IPNS v2 envelope +
DAG-CBOR data map + canonical stored form), the `_id` / address
identifiers, the order of versions (Select), placement (`nearest_R` /
`eligible`), and the libp2p RFC 0002 Signed Envelope with the owner-signed
LIST request.

**No production caller.** Nothing in a node or a client calls any function
in this file yet; the only caller is `nodus/tests/test_dht2_codec.c`
(`nodus/CMakeLists.txt:593-598`: "Pure, no I/O; no caller yet"). Storage,
pull-sync, the client / node sessions, quotas and the answer / receipt /
refusal payload maps are LATER packages (`dht2_envelope.h:45-46`;
`test_dht2_codec.c:80-81`).

**Build.** The five `.c` files are in nodus's common source list
(`nodus/CMakeLists.txt` `set(NODUS_SOURCES` :114, entries :599-603), outside
the Linux-only list, "so it compiles on Windows (the browser / Connect core
will use it too)" (:597-598). Include pattern: `#include "dht2/dht2_record.h"`
(resolved through `-I shared`). Dependencies: `crypto/sign/qgp_dilithium.h`
(ML-DSA-87), `crypto/hash/qgp_sha3.h`, `dnac/cmt_pb.h` / `dnac/cmt_pb_wire.h`
(the tree's proto3 PublicKey codec and reader — `dht2_record.c:16`,
`dht2_envelope.c:16`), `dnac/res_meter.h` (checked u64 arithmetic).

**Normative design** (LOCAL-only, not in git — named, not linked):
`docs/plans/2026-10-14-dht-v2-design.md` rev 5 (FROZEN 2026-10-15) — §2
(placement, eligibility), §3.1 (encoding, stored form), §3.2 (identifiers),
§4.1 (admission order), §4.2 (order of versions), §13 rows 1, 3-7, 15, 21-23.
Governing decision records (also LOCAL-only, `docs/plans/decisions/`):
`2026-10-14-kurultay-21-summary.md` (the IPNS v2 spine; strict decode;
ctx labels and `_id` preimages), `2026-10-14-kurultay-22-summary.md`
(codec code may start; 3C removed), `2026-10-14-kurultay-23-summary.md`
(§13 wire table; khan decision B = the owner-signed LIST request).

Pinned references (`/home/nocdem/refs/`, as the headers cite them): ipfs specs
`3000be69` (`src/ipns/ipns-record.md`), boxo v0.43.0, ipld `bfd348aa`
(`specs/codecs/dag-cbor/spec.md`), libp2p specs `78e75c6f`
(`RFC/0002-signed-envelopes.md`, `kad-dht/README.md`), Bee v2.8.2
(`pkg/soc/soc.go`, `pkg/feeds/`), multicodec, unsigned-varint `dd184f1c`,
FIPS 204.

---

## 1. Conventions

### 1.1 Two return conventions

| Convention | Functions |
|---|---|
| `DHT2_OK` (0) / `DHT2_E_*` (§2) | `dht2_data_encode`, `dht2_data_decode`, `dht2_record_parse`, `dht2_record_check_class`, `dht2_record_check_expiry`, `dht2_record_verify`, `dht2_record_canonical`, `dht2_record_build`, `dht2_record_placement_key`, `dht2_env_seal`, `dht2_env_decode`, `dht2_env_verify`, `dht2_list_payload_encode`, `dht2_list_payload_decode`, `dht2_list_req_build`, `dht2_list_req_open` |
| plain `0` / `-1` | `dht2_cbor_rd_map/_key/_uint/_bytes/_text/_true`, `dht2_id`, `dht2_id_feed_entry`, `dht2_id_feed_head`, `dht2_id_inbox`, `dht2_id_inbox_ctl`, `dht2_address`, `dht2_fp`, `dht2_validity_parse`, `dht2_validity_format` |
| other | `dht2_bytes_compare` −1 / 0 / 1; `dht2_record_compare` sign (> 0 / < 0 / 0); `dht2_nearest_r` a count or −1; `dht2_eligible` 1 / 0 / −1; `dht2_cbor_rd_done`, `dht2_cbor_key_is`, `dht2_cbor_wr_ok` `bool`; the `dht2_cbor_wr_*` emitters `void` (errors are sticky in the writer) |

`DHT2_E_ARG` (−1) is always the CALLER's bug (a NULL argument, a buffer
too small) and never a verdict on input bytes (`dht2_types.h:82-84`).
`DHT2_E_HOLDER_FAULT` (16) is this node's own failure (hash, allocation,
signing, checked arithmetic) — never reported as `bad-signature` or as
absence (design §13 row 7).

### 1.2 Zero-copy lifetimes

- `dht2_cbor_rd_key` / `_bytes` / `_text` return pointers INTO the reader's
  buffer (`dht2_cbor.h:78`, `:85-89`).
- `dht2_data_t.data` / `.prev`: after `dht2_data_decode` they point into the
  decoded bytes, "which must outlive the struct"; for encoding the caller
  sets them (`dht2_record.h:96-98`).
- `dht2_record_t.sig` / `.data` point into the `in` buffer given to
  `dht2_record_parse` (`dht2_record.h:135-137`, `:153`), and `rec->d.data` /
  `rec->d.prev` point into `rec->data`, i.e. also into `in`. A parsed
  record is valid only as long as `in` is.
- `dht2_env_t.payload_type` / `.payload` / `.sig` point INTO the decoded
  input (`dht2_envelope.h:66`).
- `pk` (the 2592-byte key) and `fp` are COPIED into the structs
  (`cmt_pb_public_key_t`, `shared/dnac/cmt_pb.h:213-216`).

### 1.3 Determinism, state, heap, clock

No function reads a clock (chain time is the `chain_now` parameter), keeps
global state, or draws randomness except inside `qgp_dsa87_sign_ctx`'s
hedged signing (`dht2_record.h:72-73`). Heap: `dht2_id` allocates its
preimage and frees it on every path (`dht2_record.h:73-75`); the RFC 0002
signed buffer is allocated in seal / verify and freed on every path
(`dht2_envelope.h:42-43`); the CBOR layer and placement use no heap
(`dht2_cbor.h:43-44`, `dht2_place.h:22`). Because ML-DSA-87 signing is
hedged, two builds of the same record differ in their signature bytes; a
retry must resend the stored canonical bytes (design §4.2).

### 1.4 ⚠ API CONTRACT — signatures

**No function here except `dht2_record_verify`, `dht2_env_verify` and
`dht2_list_req_open` checks a signature.** `dht2_record_parse`,
`dht2_data_decode`, `dht2_record_canonical`, `dht2_record_compare` and
`dht2_record_placement_key` operate on UNVERIFIED bytes
(`dht2_record.h:63-70`); `dht2_env_decode` does not verify, and a decoded
envelope's payload and fp are unproven until `dht2_env_verify` returns
`DHT2_OK` (`dht2_envelope.h:31-35`). On an unverified record the signer fp
is a CLAIM (`dht2_record.h:209-211`).

Holder admission must run design §4.1's full order: size → envelope decode
→ strict data decode + re-encode → `_chain` = local chain → pubKey → owner
fp → address → holder check (`eligible`) → class rules → expiry →
SIGNATURE (`dht2_record_verify`) → Select (§4.2) → quota → store the
canonical form. A record must never be stored, compared against a held
version or hashed into a receipt before `dht2_record_verify` returned
`DHT2_OK` (`dht2_record.h:66-70`). This package provides the steps; the
holder check, quota and store belong to later packages.

---

## 2. Constants (`shared/dht2/dht2_types.h`)

### 2.1 Sizes

| Constant | Value | Source |
|---|---|---|
| `DHT2_ENVELOPE_MAX` | `262144u` — the WHOLE encoded envelope, checked before any decode | `:31`; design §3.1 "Size" |
| `DHT2_HASH_LEN` | `64u` (SHA3-512) | `:33` |
| `DHT2_FP_LEN` | `64u` — SHA3-512(raw ML-DSA-87 key) | `:34` |
| `DHT2_CHAIN_LEN` | `32u` — `_chain` | `:35` |
| `DHT2_ID_LEN` | `64u` — `_id` | `:36` |
| `DHT2_NONCE_LEN` | `32u` — `n` / `q` | `:37`; §13 rows 2, 23 |
| `DHT2_VALIDITY_LEN` | `20u` — `YYYY-MM-DDTHH:MM:SSZ` | `:38` |
| `DHT2_PUBKEY_LEN` | `QGP_DSA87_PUBLICKEYBYTES` = 2592 | `:39`; `qgp_dilithium.h:12` |
| `DHT2_SIG_LEN` | `QGP_DSA87_SIGNATURE_BYTES` = 4627 | `:40`; `qgp_dilithium.h:14` |
| `DHT2_R` | `4u` — holders per record | `:122`; design §2 (scope 4f) |
| `DHT2_SET_MAX` | `256u` — largest storage set `nearest_R` / `eligible` accept; bounds the O(n²) duplicate scan | `:127`; §13 row 13 |
| `DHT2_VALIDITY_MAX_SECONDS` | `253402300799ull` = 9999-12-31T23:59:59Z | `dht2_time.h:37` |

### 2.2 Classes, validity types, class max (§13 rows 5, 6)

| Constant | Value |
|---|---|
| `DHT2_CLASS_OWNER` / `_FEED_ENTRY` / `_FEED_HEAD` / `_INBOX_ENTRY` / `_INBOX_CTL` | 1 / 2 / 3 / 4 / 5 (`:43-47`) |
| `DHT2_VT_EOL` | 0 — `Validity` present, 20 B (`:50`) |
| `DHT2_VT_NONE` | 1 — no expiry (ours), `Validity` empty (`:51`) |
| `DHT2_SEC_7D` / `DHT2_SEC_24H` / `DHT2_SEC_SLACK_3H` | 604800 / 86400 / 10800 seconds (`:54-56`; the 3 h is §4.1's "class max + 3 h") |

### 2.3 Result codes (`:58-84`; §13 row 7)

`0` is not a wire code: it is this codec's "the check passed" (`:59`).

| Code | Value | Returned by this package |
|---|---|---|
| `DHT2_OK` | 0 | every `DHT2_*`-convention function on success |
| `DHT2_E_TOO_LARGE` | 1 | `dht2_record_parse`, `dht2_record_build`, `dht2_env_decode` |
| `DHT2_E_BAD_ENCODING` | 2 | `dht2_data_encode`, `dht2_data_decode`, `dht2_record_parse`, `dht2_record_build`, `dht2_env_decode` |
| `DHT2_E_BAD_CHAIN` | 3 | `dht2_record_parse`, `dht2_list_req_open` (internal there, see §6.3) |
| `DHT2_E_BAD_ADDRESS` | 4 | `dht2_record_parse` |
| `DHT2_E_NOT_HOLDER` | 5 | — (defined; the holder check is a later package) |
| `DHT2_E_BAD_CLASS` | 6 | `dht2_record_check_class`, `dht2_record_check_expiry` (class out of range) |
| `DHT2_E_EXPIRED` | 7 | `dht2_record_check_expiry` |
| `DHT2_E_TOO_LONG` | 8 | `dht2_record_check_expiry` |
| `DHT2_E_BAD_SIGNATURE` | 9 | `dht2_record_verify`, `dht2_record_canonical`, `dht2_env_verify`, `dht2_list_req_open` (internal there) |
| `DHT2_E_QUOTA` | 10 | — (defined; later package) |
| `DHT2_E_POOL_FULL` | 11 | — (defined; later package) |
| `DHT2_E_DENIED` | 12 | — (defined; later package) |
| `DHT2_E_NODE_FULL` | 13 | — (defined; later package) |
| `DHT2_E_BUSY` | 14 | — (defined; call-level, row 7 / row 18) |
| `DHT2_E_NOT_CAUGHT_UP` | 15 | — (defined; call-level, row 7 / row 18) |
| `DHT2_E_HOLDER_FAULT` | 16 | `dht2_record_parse`, `dht2_record_check_class`, `dht2_record_check_expiry`, `dht2_record_build`, `dht2_record_placement_key`, `dht2_env_seal`, `dht2_env_decode`, `dht2_env_verify`, `dht2_list_req_open` |
| `DHT2_E_NOT_OWNER` | 17 | `dht2_list_req_open` |
| `DHT2_E_HANDLED` | 18 | — (defined; later package) |
| `DHT2_E_MALFORMED_REQ` | −2 | NOT a row-7 code — "a tier-2 protocol error, no signed answer" (`:79-81`): `dht2_list_payload_decode`, `dht2_list_req_open` |
| `DHT2_E_ARG` | −1 | NOT a row-7 code — a NULL argument / too-small output buffer (`:82-84`): every `DHT2_*`-convention function |

### 2.4 Domain strings, payload types, `_id` labels

All ASCII, no NUL (Kurultay #21 "Signature ctx labels and record identifiers").

| Constant | Bytes | Use |
|---|---|---|
| `DHT2_CTX_RECORD` | `"nodus.dht.record.v1"` | FIPS 204 ctx of every record signature (`:88`; §3.1) |
| `DHT2_DOMAIN_ANSWER` | `"nodus.dht.answer.v1"` | RFC 0002 domain = ctx of a holder answer (`:89`; §4.4) |
| `DHT2_DOMAIN_ADDR` | `"nodus.dht.addr.v1"` | address announcement (`:90`; §2 "Endpoints") |
| `DHT2_DOMAIN_LIST` | `"nodus.dht.list.v1"` | owner-signed LIST request (`:91`; row 23) |
| `DHT2_PT_ANSWER` / `_RECEIPT` / `_REFUSAL` / `_PULL_RECEIPT` / `_ADDR` / `_LIST` | `"/nodus/dht/answer/v1"`, `"/nodus/dht/receipt/v1"`, `"/nodus/dht/refusal/v1"`, `"/nodus/dht/pull-receipt/v1"`, `"/nodus/dht/addr/v1"`, `"/nodus/dht/list/v1"` | RFC 0002 payload types (`:101-106`). The leading `/` IS the multicodec "path" code 0x2f (RFC 0002 :50-54), so each payload type is exactly its ASCII path, first byte 0x2f, ONE slash (`:93-100`; design §13 row 1 "Bytes (clarified 2026-10-19)") |
| `DHT2_LABEL_PROFILE`, `_CONTACTLIST`, `_GROUP_HEAD`, `_GROUP_RECORD`, `_GROUP_KEYS`, `_DM`, `_GROUP_FEED`, `_HEAD`, `_INBOX`, `_INBOX_CTL` | `"nodus.dht.profile.v1"`, `"nodus.dht.contactlist.v1"`, `"nodus.dht.group.head.v1"`, `"nodus.dht.group.record.v1"`, `"nodus.dht.group.keys.v1"`, `"nodus.dht.dm.v1"`, `"nodus.dht.group.feed.v1"`, `"nodus.dht.head.v1"`, `"nodus.dht.inbox.v1"`, `"nodus.dht.inbox.ctl.v1"` | §3.2 `_id` labels (`:110-119`) |

---

## 3. Strict DAG-CBOR (`shared/dht2/dht2_cbor.h`)

A TOKEN reader and a canonical writer — the schemas above it match fixed
text keys and never build a tree (`dht2_cbor.h:5-8`). Not
`nodus/src/protocol/nodus_cbor.h`: that decoder accepts long-form integers
and lengths and does not check map key order (design §13 row 22), and
`shared/` cannot depend on `nodus/src` (`dht2_cbor.h:10-15`).

**Rules enforced on decode** (`dht2_cbor.h:17-35`, dag-cbor `spec.md`
"Strictness" :46-66; the relaxed decoding of :68-78 is NOT offered):
integers and lengths of major types 0, 2-5 in their SHORTEST form; no
indefinite lengths, no break token; no tags at all (every major type 6 is
refused — tag 42 is not used by any DHT v2 schema); of major type 7 only
`true` (0xf5, `_del`) is accepted — floats, `false`, `null` refused; major
type 1 (negative integer) refused (design §13 row 6, named deviation);
map keys text only, STRICTLY ascending by their encoded bytes (length
first, then bytewise), so a duplicate key is refused too; one top-level
object with no trailing byte (the schema checks `dht2_cbor_rd_done`). The
schemas ALSO re-encode what they parsed and compare it byte for byte with
the input (§3.1 "re-encode check"). The writer emits only shortest forms,
definite lengths, no tags, no floats, and never sorts — each schema writes
its keys in the fixed canonical order (`:39-41`).

| Item | Description |
|------|-------------|
| `typedef struct { const uint8_t *buf; size_t len; size_t pos; bool err; } dht2_cbor_rd_t;` (`:63-68`) | Reader. `err` is STICKY: once set, every call fails. |
| `void dht2_cbor_rd_init(dht2_cbor_rd_t *r, const uint8_t *buf, size_t len)` (`:70`) | Starts a reader; a NULL `buf` reads as length 0 (`dht2_cbor.c`). |
| `int dht2_cbor_rd_map(dht2_cbor_rd_t *r, uint64_t *count)` (`:73`) | Map header, definite and shortest. 0 / −1. |
| `int dht2_cbor_rd_key(dht2_cbor_rd_t *r, const uint8_t *prev, size_t prev_len, const uint8_t **key, size_t *key_len)` (`:79`) | A map KEY: text string, shortest length. `prev` / `prev_len` = the previous key of the same map (NULL for the first); the new key must sort strictly after it (length first, then bytewise). Pointer INTO the buffer. 0 / −1. |
| `int dht2_cbor_rd_uint(dht2_cbor_rd_t *r, uint64_t *v)` (`:83`) | Major type 0, shortest. 0 / −1 (major type 1 is −1). |
| `int dht2_cbor_rd_bytes(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n)` (`:86`) | Major type 2, shortest length; pointer into the buffer; the length is bounded by the bytes remaining. 0 / −1. |
| `int dht2_cbor_rd_text(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n)` (`:89`) | Major type 3, same rules. 0 / −1. |
| `int dht2_cbor_rd_true(dht2_cbor_rd_t *r)` (`:92`) | Exactly 0xf5. 0 / −1. |
| `bool dht2_cbor_rd_done(const dht2_cbor_rd_t *r)` (`:95`) | True when every byte was consumed without error (spec :66). |
| `bool dht2_cbor_key_is(const uint8_t *key, size_t key_len, const char *lit)` (`:98`) | Key equality (exact length and bytes). |
| `typedef enum { DHT2_WR_WRITE = 0, DHT2_WR_COUNT, DHT2_WR_COMPARE } dht2_wr_mode_t;` (`:110-114`) | Three writer modes over ONE emission path, so the bytes counted, written and compared are the same bytes by construction (`:100-108`). WRITE into a caller buffer; COUNT stores nothing and `len` = the size; COMPARE stores nothing and compares every byte with `ref` at the same offset — the §3.1 re-encode identity check without a second buffer. |
| `typedef struct { dht2_wr_mode_t mode; uint8_t *buf; const uint8_t *ref; size_t cap; size_t len; bool err; } dht2_cbor_wr_t;` (`:116-123`) | Writer. `cap` = buffer size (WRITE) or `ref` length (COMPARE). `err` STICKY: overflow, a COMPARE mismatch, or a NULL pointer with a non-zero length. |
| `void dht2_cbor_wr_init(dht2_cbor_wr_t *w, uint8_t *buf, size_t cap)`, `void dht2_cbor_wr_init_count(dht2_cbor_wr_t *w)`, `void dht2_cbor_wr_init_compare(dht2_cbor_wr_t *w, const uint8_t *ref, size_t ref_len)` (`:125-128`) | Start WRITE (a NULL `buf` sets `err`), COUNT, or COMPARE. |
| `bool dht2_cbor_wr_ok(const dht2_cbor_wr_t *w)` (`:131`) | COMPARE: every emitted byte matched AND all of `ref` was emitted. WRITE / COUNT: no error occurred. |
| `void dht2_cbor_wr_map(dht2_cbor_wr_t *w, uint64_t count)`, `void dht2_cbor_wr_uint(dht2_cbor_wr_t *w, uint64_t v)`, `void dht2_cbor_wr_bytes(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)`, `void dht2_cbor_wr_text(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)`, `void dht2_cbor_wr_key(dht2_cbor_wr_t *w, const char *lit)`, `void dht2_cbor_wr_true(dht2_cbor_wr_t *w)` (`:132-138`) | Emit one item with the shortest head. `wr_key` = a text key from a C string literal. |
| `size_t dht2_cbor_head_size(uint64_t v)` (`:141`) | Bytes the head of an item with argument `v` takes: 1 / 2 / 3 / 5 / 9. |

---

## 4. `Validity` text (`shared/dht2/dht2_time.h`)

Design §3.1 / §13 row 6: exactly the 20 ASCII bytes `YYYY-MM-DDTHH:MM:SSZ`
of a chain time in whole seconds — proleptic Gregorian UTC, years
1970-9999, no fraction, seconds 00-59 (no leap second), as seconds since
1970-01-01T00:00:00Z; any other byte form is `bad-encoding`
(`dht2_time.h:5-9`). Pure arithmetic: no clock, no locale, no libc time
function (no `timegm` / `gmtime_r` / `strptime` — it builds on Windows);
the multiplications use the tree's checked `dna_ck_*_u64`
(`shared/dnac/res_meter.h`) (`:16-20`).

| Item | Description |
|------|-------------|
| `int dht2_validity_parse(const uint8_t *text, size_t len, uint64_t *out_seconds)` (`:43`) | Parse exactly `len` bytes. 0 with `*out_seconds` written; −1 for ANY other byte form — wrong length, a non-digit, a lowercase `T` / `Z`, an offset, a fraction, a field out of range, a day the month does not have, a year outside 1970-9999 (and NULL arguments). |
| `int dht2_validity_format(uint64_t seconds, uint8_t out[20])` (`:47`) | Format `seconds` (0 … `DHT2_VALIDITY_MAX_SECONDS`) as the 20 bytes, no NUL written. 0 / −1 (out of range or NULL). |

---

## 5. The signed record (`shared/dht2/dht2_record.h`)

**Envelope** (design §3.1; ipns-record.md:195-238): IPNS protobuf `pubKey`
7, `signatureV2` 8, `data` 9, under the tree's proto3 rules
(`shared/dnac/cmt_pb.h:22-52`). The envelope is UNSIGNED and re-encodable;
it takes no part in ordering. **Signature:** ML-DSA-87 over the `data`
bytes with FIPS 204 ctx `nodus.dht.record.v1`, hedged. **Data:** strict
DAG-CBOR map; eight keys in every record (`TTL` = 0, `_id` 64 B, `Value`
empty, `_chain` 32 B, `_class`, `Sequence` ≥ 1, `Validity`,
`ValidityType`) plus `_del` (true, tombstones), `_data`, `_prev`
(`dht2_record.c` `DATA_KEYS_MIN` 8 / `DATA_KEYS_MAX` 11). **Address** =
SHA3-512(`_id` ‖ owner fp). **Stored form** = the canonical envelope:
fields 7, 8, 9 only, in field order, each once, proto3 emission rules,
unknown fields dropped (§3.1, §13 row 4).

Row-5 matrix as implemented (`dht2_record_check_class`): a tombstone
(`_del`) has neither `_data` nor `_prev`; otherwise `_data` is required and
`_prev` is present exactly for class 2; class 3's `_data` is exactly 8 B;
class 5's `_data` is the row-15 control list (entries `fp 64 ‖ mark 1 ‖
through 8 BE`, strictly ascending by fp, mark 1 HANDLED / 2 DENIED, ≤ 3,500
entries — `dht2_record.c` `CTL_ENTRY_LEN`, `CTL_ENTRIES_MAX`); a class-5
record (tombstone included) is accepted only if
SHA3-512(`nodus.dht.inbox.ctl.v1` ‖ `_chain` ‖ signer fp) = its `_id` (§3.2).

Class max (`dht2_record_check_expiry`, row 5, by the WRITER's name status):
classes 1 / 3 / 5 — named: unbounded (ValidityType 1 allowed); unnamed:
7 d; class 2 — 7 d; class 4 — named 7 d, unnamed 24 h. A tombstone inherits
its class's max.

| Item | Description |
|------|-------------|
| `typedef struct { uint64_t sequence; uint64_t validity_type; uint64_t expiry; uint8_t chain[DHT2_CHAIN_LEN]; uint8_t id[DHT2_ID_LEN]; uint64_t cls; bool del; bool has_data; const uint8_t *data; size_t data_len; bool has_prev; const uint8_t *prev; size_t prev_len; } dht2_data_t;` (`:99-113`) | The data map. `expiry` (seconds) is meaningful only when `validity_type` is 0. `data` / `prev` are zero-copy (§1.2). `prev_len` ∈ {0, 64} (row 3: 0 = first feed entry). |
| `int dht2_data_encode(const dht2_data_t *d, uint8_t *out, size_t cap, size_t *out_len)` (`:122`) | Canonical DAG-CBOR of `d`, keys in the one order strict DAG-CBOR allows: `TTL, _id, _del, Value, _data, _prev, _chain, _class, Sequence, Validity, ValidityType` (each only when present). `out` NULL → only `*out_len`. `DHT2_OK`; `DHT2_E_BAD_ENCODING` (Sequence 0, ValidityType ∉ {0,1}, expiry beyond 9999-12-31T23:59:59Z, `_prev` length ∉ {0,64}); `DHT2_E_ARG` (NULL `d` / `out_len`, a NULL `data` / `prev` with a non-zero length, buffer too small). Does NOT check `_class` range or the row-5 matrix. |
| `int dht2_data_decode(const uint8_t *in, size_t len, dht2_data_t *d)` (`:128`) | Strict decode (§3) + the re-encode identity check (§3.1, rows 5-6, 22). Refuses (`DHT2_E_BAD_ENCODING`): fewer than 8 or more than 11 keys, an unknown key, unsorted / duplicate keys, `TTL` ≠ 0, `Value` not empty, `_id` ≠ 64 B, `_chain` ≠ 32 B, `_prev` ∉ {0, 64} B, `_del` other than `true`, `Sequence` 0, `ValidityType` ∉ {0, 1}, ValidityType 0 with a `Validity` that does not parse, ValidityType 1 with a non-empty `Validity`, a trailing byte, a missing required key. `DHT2_E_ARG` on NULL `d` or NULL `in` with `len` ≠ 0 (header `@return` lists only OK / BAD_ENCODING). Class rules NOT applied; no signature checked. `*d` is zeroed at entry. |
| `typedef struct { cmt_pb_public_key_t pk; uint8_t fp[DHT2_FP_LEN]; const uint8_t *sig; size_t sig_len; const uint8_t *data; size_t data_len; dht2_data_t d; uint8_t address[DHT2_HASH_LEN]; } dht2_record_t;` (`:132-141`) | A parsed record: `pk` field 7 decoded (copied); `fp` = SHA3-512(`pk.key`); `sig` field 8 and `data` field 9 point into the input; `d` = parsed field 9; `address` = H(`_id` ‖ fp). |
| `int dht2_record_parse(const uint8_t *in, size_t len, const uint8_t local_chain[DHT2_CHAIN_LEN], const uint8_t *expect_address, dht2_record_t *rec)` (`:158`) | §4.1 up to and including the address, in its order: `len` > 262,144 → `DHT2_E_TOO_LARGE` (BEFORE any decode); envelope decode fault → `DHT2_E_BAD_ENCODING`; `data` not strict / not re-encoding → `DHT2_E_BAD_ENCODING`; `_chain` ≠ `local_chain` → `DHT2_E_BAD_CHAIN`; pubKey missing or not the ML-DSA-87 branch of exactly 2592 B → `DHT2_E_BAD_ENCODING`; address ≠ a non-NULL `expect_address` → `DHT2_E_BAD_ADDRESS`. Also `DHT2_E_HOLDER_FAULT` (the fp or address hash failed) and `DHT2_E_ARG` (NULL `rec` / `local_chain`, NULL `in` with `len` ≠ 0) — neither is in the header comment. Envelope decode follows the generated Unmarshal: fields in any order, unknown fields (incl. IPNS V1 fields 1-6) skipped by wire type, a repeated field last-one-wins. `rec` points into `in`; `*rec` is zeroed at entry. Does NOT verify the signature (§1.4). |
| `int dht2_record_check_class(const dht2_record_t *rec)` (`:164`) | Row-5 class rules + row-15 control-list shape + the §3.2 inbox-control binding (above). `DHT2_OK`; `DHT2_E_BAD_CLASS`; also `DHT2_E_HOLDER_FAULT` (the control `_id` recompute failed) and `DHT2_E_ARG` (NULL) — not in the header comment. |
| `int dht2_record_check_expiry(const dht2_record_t *rec, uint64_t chain_now, bool writer_named)` (`:171`) | §4.1 "expiry > holder chain time and ≤ holder chain time + class max + 3 h", class max by the writer's name status (above). ValidityType 1 where the class max is finite → `DHT2_E_TOO_LONG`; expiry ≤ `chain_now` → `DHT2_E_EXPIRED` (stricter than boxo by one second: boxo accepts eol == now, `dht2_record.c` comment on `validation.go:73`); expiry > bound → `DHT2_E_TOO_LONG`; class out of range → `DHT2_E_BAD_CLASS` (never reached after `check_class`). Also `DHT2_E_HOLDER_FAULT` (checked add overflow) and `DHT2_E_ARG` (NULL) — not in the header comment. `chain_now` is the caller's (the snapshot's chain time, §2). |
| `int dht2_record_verify(const dht2_record_t *rec)` (`:176`) | ML-DSA-87 verify over the `data` bytes, ctx `nodus.dht.record.v1`. `DHT2_OK`; `DHT2_E_BAD_SIGNATURE` (no key, no signature, signature ≠ 4627 B, or verify fails); `DHT2_E_ARG` (NULL). |
| `int dht2_record_canonical(const dht2_record_t *rec, uint8_t *out, size_t cap, size_t *out_len)` (`:184`) | The stored form: fields 7, 8, 9 only, in field order, each once, proto3 emission rules (`cmt_pb.h:22`), unknown fields dropped. `out` NULL → only `*out_len`. Does NOT verify the signature, but REFUSES a signature that is not exactly 4627 B (`DHT2_E_BAD_SIGNATURE`) — no canonical form for a record that could never verify. `DHT2_OK`, `DHT2_E_BAD_SIGNATURE`, `DHT2_E_ARG` (NULL, no key, buffer too small). |
| `int dht2_record_build(const dht2_data_t *d, const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out, size_t cap, size_t *out_len)` (`:193`) | Client side: encode `d`, sign it (hedged, ctx `nodus.dht.record.v1`) with `sk` (4896 B), write the CANONICAL envelope with `pk` (2592 B). `out` NULL → `*out_len` = the exact size, no signing, and `sk` may then be NULL. `DHT2_OK`; `DHT2_E_BAD_ENCODING` (`d` not encodable); `DHT2_E_TOO_LARGE` (> 262,144 B); `DHT2_E_ARG` (NULL, `cap` < size); `DHT2_E_HOLDER_FAULT` (signing failed — the first `total` bytes of `out` are then zeroed). Does not check class rules. |
| `int dht2_record_compare(const dht2_record_t *a, const dht2_record_t *b)` (`:205`) | §4.2 order of two versions AT THE SAME ADDRESS: larger `Sequence` → later expiry (no expiry above any expiry) → larger canonical `data` bytes → larger signature bytes; "larger bytes" = Go `bytes.Compare` (first differing byte, then the shorter is smaller). A NULL side = "nothing held" and loses to a present one (both NULL → 0). > 0 `a` wins, < 0 `b` wins, 0 the same version. Does NOT verify either signature — both must have passed `dht2_record_verify`. Pure function of the two records: arrival order cannot change the winner (the A/B two-arrival vector, §9). |
| `int dht2_record_placement_key(const dht2_record_t *rec, uint8_t out[DHT2_HASH_LEN])` (`:212`) | §2 placement key: class 4 → its `_id` (the inbox id); class 5 → SHA3-512(`nodus.dht.inbox.v1` ‖ `_chain` ‖ signer fp) (the inbox its signer owns); otherwise the record's address. `DHT2_OK`, `DHT2_E_ARG`, `DHT2_E_HOLDER_FAULT`. On an unverified record the signer fp is a claim. |
| `int dht2_id(const char *label, const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t *params, size_t params_len, uint8_t out[DHT2_ID_LEN])` (`:220`) | §3.2: SHA3-512(label ‖ chain_id 32 B ‖ params). `label` = a `DHT2_LABEL_*` string (ASCII, no NUL hashed). `params` may be NULL when `params_len` is 0. Allocates the preimage, freed on every path. 0 / −1. |
| `int dht2_id_feed_entry(const uint8_t topic[DHT2_HASH_LEN], uint64_t index, uint8_t out[DHT2_ID_LEN])` (`:226`) | Feed entry `_id` = SHA3-512(topic ‖ index as 8-byte big-endian) — no label, no chain (Bee `pkg/feeds/feed.go:70-71`, `sequence/sequence.go:47-51`). 0 / −1. |
| `int dht2_id_feed_head(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t topic[DHT2_HASH_LEN], uint8_t out[DHT2_ID_LEN])` (`:230`) | SHA3-512(`nodus.dht.head.v1` ‖ chain ‖ topic) — the design rev 3+ form (§3.2 supersedes Kurultay #21 summary :139's `label ‖ topic`). 0 / −1. |
| `int dht2_id_inbox(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t recipient_fp[DHT2_FP_LEN], uint8_t out[DHT2_ID_LEN])` (`:235`) | Inbox id = SHA3-512(`nodus.dht.inbox.v1` ‖ chain ‖ recipient fp). 0 / −1. |
| `int dht2_id_inbox_ctl(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t recipient_fp[DHT2_FP_LEN], uint8_t out[DHT2_ID_LEN])` (`:241`) | Inbox control `_id` = SHA3-512(`nodus.dht.inbox.ctl.v1` ‖ chain ‖ recipient fp). 0 / −1. |
| `int dht2_address(const uint8_t id[DHT2_ID_LEN], const uint8_t owner_fp[DHT2_FP_LEN], uint8_t out[DHT2_HASH_LEN])` (`:246`) | Address = SHA3-512(`_id` ‖ owner fp), in that order (Bee `soc.go:199-207`). 0 / −1. |
| `int dht2_fp(const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t out[DHT2_FP_LEN])` (`:252`) | Owner fp = SHA3-512(raw 2592-byte ML-DSA-87 key) — the tree's fingerprint (`nodus/src/crypto/nodus_sign.c:392`). 0 / −1. |
| `int dht2_bytes_compare(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)` (`:255`) | Go `bytes.Compare`: −1 / 0 / 1. |

**Readings this file makes where the design names no code**
(`dht2_record.h:42-61` — labelled readings reported to the ORCHESTRATOR,
not design facts): class-independent byte-form faults → `bad-encoding`
(2); per-class faults (incl. `_class` ∉ 1…5, the feed-head 8-B rule, a
malformed row-15 list, the inbox-control binding) → `bad-class` (6);
ValidityType 1 where the class max is finite → `too-long` (8); a NAMED
writer's class 1 / 3 / 5 record may carry a finite expiry with no upper
bound (row 5 "no expiry allowed (ValidityType 1) with a name" read as
"the class max is unbounded"); an empty `_data` is valid for classes 1, 2,
4; a ValidityType ⇔ Validity mismatch is `bad-encoding`, not `bad-class`.

---

## 6. RFC 0002 envelope and the LIST request (`shared/dht2/dht2_envelope.h`)

libp2p `RFC/0002-signed-envelopes.md` (:77-93): `Envelope { PublicKey
public_key = 1; bytes payload_type = 2; bytes payload = 3; bytes signature
= 5; }`; signed buffer = uvarint(len domain) ‖ domain ‖ uvarint(len
payload_type) ‖ payload_type ‖ uvarint(len payload) ‖ payload (:111-122),
minimal unsigned varints. Emitted canonically (ascending, each once,
omit-empty); decoded in any order, unknown fields skipped, last-one-wins,
the embedded PublicKey MERGED — a later field 1 that carries the key
replaces it, an empty one keeps it (`dht2_envelope.h:11-20`,
`dht2_envelope.c` decode). The domain is used BOTH in the signed buffer
AND as the FIPS 204 ctx (§4.4). Only the envelope layer and the LIST
request live here; the answer / receipt / refusal payload maps (row 18) are
a later package (`:45-46`).

### 6.1 Envelope

| Item | Description |
|------|-------------|
| `typedef struct { cmt_pb_public_key_t pk; uint8_t fp[DHT2_FP_LEN]; const uint8_t *payload_type; size_t payload_type_len; const uint8_t *payload; size_t payload_len; const uint8_t *sig; size_t sig_len; } dht2_env_t;` (`:67-76`) | A decoded envelope; byte pointers INTO the decoded input; `fp` = SHA3-512(`pk.key`). |
| `int dht2_env_seal(const char *domain, const uint8_t *payload_type, size_t payload_type_len, const uint8_t *payload, size_t payload_len, const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out, size_t cap, size_t *out_len)` (`:85`) | Sign and encode. `domain` = a `DHT2_DOMAIN_*` string; `payload_type` = a `DHT2_PT_*` (bytes, no NUL). Hedged ML-DSA-87 with ctx = domain. `out` NULL → `*out_len` = the exact size, no signing (`sk` may then be NULL). `DHT2_OK`; `DHT2_E_ARG` (NULL arguments, `strlen(domain)` > `QGP_DSA87_CTX_MAX_BYTES` = 255 (`qgp_dilithium.h:54`), `cap` < size); `DHT2_E_HOLDER_FAULT` (allocation or signing failed). |
| `int dht2_env_decode(const uint8_t *in, size_t len, size_t max_len, dht2_env_t *env)` (`:95`) | Decode; `len` > `max_len` → `DHT2_E_TOO_LARGE` BEFORE decoding. `DHT2_E_BAD_ENCODING` (a bad tag / length, a field 1-3 / 5 with the wrong wire type, a malformed PublicKey, or no ML-DSA-87 key at the end); `DHT2_E_HOLDER_FAULT` (fp hash failed — not in the header comment); `DHT2_E_ARG`. Does NOT verify the signature — call `dht2_env_verify` before trusting payload or fp. |
| `int dht2_env_verify(const dht2_env_t *env, const char *domain)` (`:100`) | Verify the signature over RFC 0002's buffer under `domain` (= ctx). `DHT2_OK`; `DHT2_E_BAD_SIGNATURE` (no key, no signature, signature ≠ 4627 B, or verify fails); `DHT2_E_HOLDER_FAULT` (allocation); `DHT2_E_ARG` (NULL, domain > 255 B). |

### 6.2 LIST request (design §13 row 23)

The owner of an inbox signs a LIST (or inbox-control read) request as an
RFC 0002 envelope: domain / ctx `nodus.dht.list.v1`, payload type
`/nodus/dht/list/v1`, payload = strict DAG-CBOR `{op "list", n 32 B, c
32 B, inbox 64 B, cursor? 64 B}` written in the one canonical order
`c, n, op, inbox, cursor` (`:112-113`). The holder answers only the owner:
SHA3-512(`nodus.dht.inbox.v1` ‖ c ‖ SHA3-512(signer key)) must equal
`inbox`, otherwise `not-owner` (17). Accepted risk (design §13 "Deferred /
accepted"): the request carries no freshness, so a node that saw it can
replay it later.

| Item | Description |
|------|-------------|
| `typedef struct { uint8_t nonce[DHT2_NONCE_LEN]; uint8_t chain[DHT2_CHAIN_LEN]; uint8_t inbox[DHT2_ID_LEN]; bool has_cursor; uint8_t cursor[DHT2_FP_LEN]; } dht2_list_req_t;` (`:104-110`) | `n`, `c`, `inbox`, optional `cursor` (EXCLUSIVE — the last writer fp listed, row 11). All copied. |
| `int dht2_list_payload_encode(const dht2_list_req_t *req, uint8_t *out, size_t cap, size_t *out_len)` (`:115`) | Strict DAG-CBOR payload in canonical order. `out` NULL → size only. `DHT2_OK` / `DHT2_E_ARG`. |
| `int dht2_list_payload_decode(const uint8_t *in, size_t len, dht2_list_req_t *req)` (`:121`) | Strict decode + re-encode check. `DHT2_OK`; `DHT2_E_MALFORMED_REQ` (row 7: nonce ≠ 32 B, a cursor ≠ 64 B, `op` ≠ `"list"`, `c` ≠ 32 B, `inbox` ≠ 64 B, an unknown / unsorted / duplicate key, a missing key, fewer than 4 or more than 5 keys, any strict-CBOR fault, a trailing byte); `DHT2_E_ARG` (NULL). |
| `int dht2_list_req_build(const dht2_list_req_t *req, const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out, size_t cap, size_t *out_len)` (`:127`) | The owner signs: payload → `dht2_env_seal(DHT2_DOMAIN_LIST, DHT2_PT_LIST, …)`. `out` NULL → size only. Returns as `dht2_env_seal`. |
| `int dht2_list_req_open(const uint8_t *in, size_t len, const uint8_t local_chain[DHT2_CHAIN_LEN], dht2_list_req_t *req, uint8_t *owner_fp)` (`:145`) | Holder side, cheap checks first and the owner binding only after the key is proven: size ≤ 262,144 B, envelope decodes, payload type = `/nodus/dht/list/v1`, payload strict-decodes → else `DHT2_E_MALFORMED_REQ`; `c` ≠ `local_chain` → `DHT2_E_BAD_CHAIN`; signature under `nodus.dht.list.v1` → else `DHT2_E_BAD_SIGNATURE`; recomputed inbox id ≠ `inbox` → `DHT2_E_NOT_OWNER`. Also `DHT2_E_HOLDER_FAULT` (passed through from decode / verify, or the inbox-id hash) and `DHT2_E_ARG`. On `DHT2_OK` `req` holds the request and `owner_fp` (may be NULL) the signer's fp. Runs the full verify-before-use order itself. |

### 6.3 Reading (kept as written, `dht2_envelope.h:37-40`)

`dht2_list_req_open`'s `DHT2_E_BAD_CHAIN` (3) and `DHT2_E_BAD_SIGNATURE`
(9) are INTERNAL results; only `not-owner` (17) is a decided LIST answer
(row 23). How a holder answers 3 / 9 on a LIST request is decided in the
holder package.

---

## 7. Placement (`shared/dht2/dht2_place.h`)

Design §2 "Placement (4f, R = 4)" and "One eligibility function": a record
is held by the R = 4 members of S(H) nearest its placement key by XOR
(libp2p `kad-dht/README.md:175`); fewer than R members → all of them;
`eligible(key) = nearest_R(key, S(H)) ∪ nearest_R(key, S(H − E))`
(`dht2_place.h:5-17`). XOR over DISTINCT fps never ties, so the result
order is total (§9 D1); a set with a repeated fp is REFUSED rather than
tie-broken (`:18-20`). No heap, no clock, no randomness, no global state.

| Item | Description |
|------|-------------|
| `int dht2_nearest_r(const uint8_t key[DHT2_HASH_LEN], const uint8_t (*set)[DHT2_FP_LEN], size_t n, size_t *out_idx)` (`:48`) | The min(R, n) members of `set` (n fps, any order) nearest `key` by XOR distance compared as 512-bit big-endian numbers, nearest first. `out_idx` receives indices into `set` (capacity ≥ min(R, n); may be NULL when n = 0). Returns the number written (0 for an empty set), or −1 on a NULL argument, n > `DHT2_SET_MAX`, or a repeated fp. |
| `int dht2_eligible(const uint8_t key[DHT2_HASH_LEN], const uint8_t (*s0)[DHT2_FP_LEN], size_t n0, const uint8_t (*s1)[DHT2_FP_LEN], size_t n1, const uint8_t fp[DHT2_FP_LEN])` (`:55`) | Is `fp` in nearest_R(key, s0) ∪ nearest_R(key, s1)? `s1` may be empty (n1 = 0). 1 yes, 0 no, −1 on a bad argument, a set over `DHT2_SET_MAX`, or a repeated fp in either set. |

---

## 8. Named deviations

From design §13 row 21's list, as this package carries them:

- `pubKey` / RFC 0002 field 1 = the tree's ML-DSA-87 branch of the
  protobuf PublicKey (field 9, `cmt_pb.h:43-44`); libp2p's KeyType has only
  RSA / Ed25519 / Secp256k1 / ECDSA (row 1; `dht2_record.h:28-29`,
  `dht2_envelope.h:23-25`).
- FIPS 204 ctx `nodus.dht.record.v1` instead of the IPNS
  `"ipns-signature:" ‖ data` prefix (§3.1; `dht2_record.h:30-32`); the
  RFC 0002 domain doubles as the ctx (§4.4; `dht2_envelope.h:26-27`).
- Payload types (row 1) — the one-slash ASCII path (`dht2_types.h:93-100`).
- `Sequence` ≥ 1 (IPNS starts at 0) and negative integers refused (row 6;
  `dht2_record.h:33-34`).
- Unknown data keys refused (IPNS lets them be ignored) (row 5;
  `dht2_record.h:35-36`).
- `Validity` narrowed to the 20-byte form of boxo's RFC3339Nano — every
  text produced here is one boxo also produces; boxo accepts more (§3.1;
  `dht2_time.h:11-14`).
- The owner-signed LIST request (row 23; `dht2_envelope.h:28`).

Named in the headers / code but NOT in row 21's list:

- The order of versions ends "larger canonical data bytes → larger
  signature bytes", where boxo's `selectRecord` compares the whole
  (re-encodable) record bytes (Kurultay #21 khan 2; design §4.2;
  `dht2_record.h:38-40`).
- XOR distance over the raw 64 bytes, compared as a 512-bit big-endian
  number, with no `sha256` re-hash — kad-dht `README.md:51` defines
  XOR(sha256(key1), sha256(key2)); here both sides are already SHA3-512
  outputs (`dht2_place.h:10-15`).
- `expiry == chain time` is `expired` (boxo accepts eol == now) — design
  §4.1 "expiry > holder chain time" (`dht2_record.c:578-581`,
  `dht2_record_check_expiry`).

---

## 9. Tests

`nodus/tests/test_dht2_codec.c` (ctest `test_dht2_codec`,
`nodus/CMakeLists.txt:1873-1879`, linked `nodus dsa nodus crypto`). Twelve
sections run from `main` (`test_dht2_codec.c:1831-1842`):
`test_strict_decode`, `test_class_kats`, `test_preimages`, `test_envelope`,
`test_matrix`, `test_class_max`, `test_validity`, `test_order`,
`test_placement`, `test_envelopes_and_list`, `test_reader_shortest`,
`test_hardening`. 194 `CHECK(` sites in the source; 429 checks is the
ORCHESTRATOR's run count, not re-run for this reference.

- **Proves** (file header `:8-55`): every class's data map encodes to the
  exact pinned bytes in the canonical key order; a built record parses,
  verifies, and canonicalises to the built bytes, and a reordered /
  repeated / unknown-field envelope canonicalises to the SAME bytes; every
  row-22 strict-decode reject is `bad-encoding`; every §3.2 / §3.1
  identifier equals SHA3-512 of a HAND-ASSEMBLED preimage; §4.1's first
  codes come in its order; row 5's matrix and class max at their edges;
  §4.2's A/B two-arrival case — two holders with their own stores,
  admitting in opposite orders, end with the same stored bytes; the
  reader itself refuses every non-shortest head; proto3 merge rules (IPNS
  field 7 last-one-wins incl. a trailing empty one; RFC 0002 field 1
  merged); every prefix of an envelope and a data map refused; a
  non-4627-byte signature has no canonical form; a set over 256 refused;
  `nearest_R` over a fixed set; Validity fixed instants and month-boundary
  round trips; row 23 (round trip, `not-owner`, flipped payload byte and
  another domain → `bad-signature`, the RFC 0002 signed buffer checked
  against an independently built one).
- **Requires** (`:56-62`): a default build — no compile flags, no
  environment, no network, no files, no clock. Keys from
  `qgp_dsa87_keypair_derand` with fixed seeds; signing is hedged, so no
  signature byte is pinned (signatures are verified, never compared).
  Safe under `ctest -j`.
- **Leaves behind** (`:63-65`): nothing.
- **Can lie** (`:66-81`): the pinned data-map bytes are written by hand
  from the design text and the DAG-CBOR spec — self-consistent with the
  codec's author, not an oracle from another implementation (the design's
  C ↔ WASM cross-check is what will ground them); the Validity instants
  come from one external source (GNU `date`), the month sweep is a
  self round trip; the payload-type bytes are checked against the
  `DHT2_PT_*` strings and a 0x2f first byte, not another implementation;
  admission order across the holder check, quota, storage and pull-sync
  is not exercised (later packages).
