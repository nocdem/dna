# DHT v2 Functions (`shared/dht2/`, `nodus/src/dht/nodus_dht2_wview.*`, `nodus/src/dht2/` — store and holder service)

DHT v2 package 1: the byte layer of the storage-node DHT for Nodus Connect —
a strict DAG-CBOR reader / writer, the signed record (IPNS v2 envelope +
DAG-CBOR data map + canonical stored form), the `_id` / address
identifiers, the order of versions (Select), placement (`nearest_R` /
`eligible`), and the libp2p RFC 0002 Signed Envelope with the owner-signed
LIST request.

DHT v2 package 2 (§10): the wire messages — get / put requests, the read
answer / write receipt / LIST answer / refusal payloads with their seal and
open, the pull-sync messages and the `p_want` bit-vector, the inbox control
`_data` — plus the strict-CBOR array / false / null additions (§3) and five
typed client-side `_id` helpers (§5).

DHT v2 package 4 (§11): NOT in `shared/dht2/` — `nodus/src/dht/nodus_dht2_wview.{h,c}`,
the `nodus-storage` process's view of its local witness over the `ipc_dht`
connection kind of `<data_path>/witness.sock` (snapshot, frozen sets, name
check). The witness side of that kind (its fill functions, structs and the
derived frame bound) is in `messenger/docs/functions/ledger.md` §19.

DHT v2 package 5 (§12): NOT in `shared/dht2/` — `nodus/src/dht2/nodus_dht2_store.{h,c}`,
the holder store (SQLite, canonical envelopes) and the one §4.1 admission path,
over an INJECTED context (snapshot, frozen sets, name callback, limits). With it
the codec's `ValidityType` ⇔ `Validity` check moved from `dht2_data_decode`
(`bad-encoding` 2) to `dht2_record_check_class` (`bad-class` 6) — §5.

DHT v2 package 6a (§13): NOT in `shared/dht2/` — `nodus/src/dht2/nodus_dht2_holder.{h,c}`,
the holder service: the bytes of ONE get / put / list request in, the bytes
of ONE signed answer envelope (answer / receipt / refusal, domain
`nodus.dht.answer.v1`) or "no answer" out, over the package-5 store and an
INJECTED view of the witness. Transport-free. With it: `nodus_dht2_put_t`
carries the envelope's address, also across a refusal (§12); a LIST page
charges the control record's bytes first (§12); the package-4 view drops an
unread name fault after `NODUS_DHT2_WVIEW_FAULT_KEEP_MS` (§11); and an
envelope above 262,144 B inside a put is no longer a malformed request
(`DHT2_REQ_BUDGET` / `DHT2_REQ_MAX_LEN`, §10.2).

**No production caller.** Nothing in a node or a client calls any function
in this file yet; the only callers are `nodus/tests/test_dht2_codec.c`,
`nodus/tests/test_dht2_msg.c`, `nodus/tests/test_dht2_ipc.c`,
`nodus/tests/test_dht2_store.c` and `nodus/tests/test_dht2_holder.c` — the
package-6a holder service calls the store, the package-1 / 2 functions and
(through `nodus_dht2_holder_view_wview`) the package-4 view, but nothing calls
the holder service (`nodus/CMakeLists.txt:633-639`: "Pure, no I/O; no caller
yet"; `:710-712` for the package-4 view; `:714-717` for the package-5 store:
"No caller yet (package 6 serves it)"; `:719-722` for the package-6a holder
service: "No caller yet (package 6b serves it)"). The sessions, forwarding and
the pull exchange are LATER packages (6b, 7).

**Build.** The six `shared/dht2/*.c` files are in nodus's common source list
(`nodus/CMakeLists.txt` `set(NODUS_SOURCES` :114, entries :640-645), outside
the Linux-only list, "so it compiles on Windows (the browser / Connect core
will use it too)" (:638-639). The package-4 `nodus/src/dht/nodus_dht2_wview.c`
is NOT: it is in the Linux-only library list (`:710-713`), links the nodus
transport + `nodus_cbor` and includes `witness/nodus_witness_ipc.h` for
constants and plain structs only. The package-5 `nodus/src/dht2/nodus_dht2_store.c`
is in the same Linux-only list (`:714-718`) and links SQLite; the package-6a
`nodus/src/dht2/nodus_dht2_holder.c` is in the same list too (`:719-723`). Include pattern: `#include "dht2/dht2_record.h"`
(resolved through `-I shared`). Dependencies: `crypto/sign/qgp_dilithium.h`
(ML-DSA-87), `crypto/hash/qgp_sha3.h`, `dnac/cmt_pb.h` / `dnac/cmt_pb_wire.h`
(the tree's proto3 PublicKey codec and reader — `dht2_record.c:16`,
`dht2_envelope.c:16`), `dnac/res_meter.h` (checked u64 arithmetic).

**Normative design** (LOCAL-only, not in git — named, not linked):
`docs/plans/2026-10-14-dht-v2-design.md` rev 5 (FROZEN 2026-10-15) — §2
(placement, eligibility, the "Precondition" |S(H)| ≥ 2), §3.1 (encoding,
stored form), §3.2 (identifiers), §4.1 (admission order), §4.2 (order of
versions), §4.4 (answers), §4.5 (pull-sync), §13 rows 1, 3-7, 11, 12, 14, 15,
18, 20-23.
Governing decision records (also LOCAL-only, `docs/plans/decisions/`):
`2026-10-14-kurultay-21-summary.md` (the IPNS v2 spine; strict decode;
ctx labels and `_id` preimages), `2026-10-14-kurultay-22-summary.md`
(codec code may start; 3C removed), `2026-10-14-kurultay-23-summary.md`
(§13 wire table; khan decision B = the owner-signed LIST request),
`2026-10-23-dht-v2-wire-gaps-package2.md` (operator, 2026-10-23: get / put
requests and pull messages are strict DAG-CBOR maps with text keys; pull
messages carry no `op` and no `n`; read-repair is sent as `op` "put"; the
pull-receipt payload keys are `pf`, `sf`, `c`, `g`, `s`, `top`, `e`; the
LIST answer's `req_cursor` is ABSENT on a first page; the pull-receipt's
envelope domain stays OPEN), `2026-10-23-dht-v2-id-param-bytes.md`
(operator, 2026-10-23: dm salt 32 B, group id 32 B, group key version
8 B unsigned big-endian — amended the same day from a first answer of
4 B — carried only in the group.record and group.keys `_id`, not in
group.head or the group feed topic). Package 5 (§12) also follows
`2026-10-23-dht-v2-k23-three-items.md` (operator, 2026-10-23: the HANDLED
cutoff as rows 7 / 15 write it — entries with Sequence ≤ N dropped, a later PUT
at or below N answered 18 with only that writer's N; membership in the frozen
sets authoritative, registry status not) and
`2026-10-24-dht-v2-handled-client-rule.md` (operator, 2026-10-24: a HANDLED
request not coming back is a CLIENT rule — the owner keeps a HANDLED writer
listed ≤ 7 d + 3 h; holders apply only the selected control record, a losing
write changes nothing, no holder memory). Package 6a (§13) has no decision
record of its own: it follows rev 5 §2 "Precondition", §4.4 and rows 7, 11,
14, 18, 20, 23, and the code labels where it reads the text (§13.6) — in
particular the refusal code of the write precondition is an ORCHESTRATOR
reading awaiting the operator (`nodus_dht2_holder.h:48-53`).

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
| `DHT2_OK` (0) / `DHT2_E_*` (§2) | `dht2_data_encode`, `dht2_data_decode`, `dht2_record_parse`, `dht2_record_check_class`, `dht2_record_check_expiry`, `dht2_record_verify`, `dht2_record_canonical`, `dht2_record_build`, `dht2_record_placement_key`, `dht2_env_seal`, `dht2_env_decode`, `dht2_env_verify`, `dht2_list_payload_encode`, `dht2_list_payload_decode`, `dht2_list_req_build`, `dht2_list_req_open`; package 2 (§10): every `*_encode` / `*_decode` of `dht2_msg.h`, `dht2_answer_seal`, `dht2_answer_open`, `dht2_ctl_encode`, `dht2_ctl_check`, `dht2_ctl_at`, `dht2_ctl_lookup` |
| plain `0` / `-1` | `dht2_cbor_rd_map/_key/_uint/_bytes/_text/_array/_true/_bool/_null`, `dht2_id`, `dht2_id_feed_entry`, `dht2_id_feed_head`, `dht2_id_inbox`, `dht2_id_inbox_ctl`, `dht2_id_dm`, `dht2_id_group_head`, `dht2_id_group_record`, `dht2_id_group_keys`, `dht2_id_group_feed`, `dht2_address`, `dht2_fp`, `dht2_validity_parse`, `dht2_validity_format` |
| other | `dht2_bytes_compare` −1 / 0 / 1; `dht2_record_compare` sign (> 0 / < 0 / 0); `dht2_nearest_r` a count or −1; `dht2_eligible` 1 / 0 / −1; `dht2_cbor_rd_peek_mt` a major type 0-7 or −1; `dht2_cbor_rd_done`, `dht2_cbor_rd_peek_null`, `dht2_cbor_key_is`, `dht2_cbor_wr_ok`, `dht2_bits_get` `bool`; `dht2_bits_len` `size_t`; the `dht2_cbor_wr_*` emitters and `dht2_bits_set` `void` (writer errors are sticky in the writer) |
| package 5 (§12) | `nodus_dht2_store_put` 0 (outcome in `res`) / a row-7 code / `DHT2_E_ARG`; `nodus_dht2_store_get` `NODUS_DHT2_GET_HELD` 0 / `NODUS_DHT2_GET_NOT_HELD` 1 / 15 / 16 / `DHT2_E_ARG`; `_list`, `_sweep`, `_scan` 0 / 15 / 16 / `DHT2_E_ARG`; `_top`, `_handover_set`, `_handover_get` 0 / 16 (the hand-over calls also `DHT2_E_ARG`); `nodus_dht2_store_open` a pointer or NULL; `_generation` `uint64_t`; `_db` a `sqlite3 *`; `_close`, `nodus_dht2_limits_default` `void`. Package 4's `nodus_dht2_wview_*`: §11 |
| package 6a (§13) | `nodus_dht2_holder_serve` `NODUS_DHT2_HOLDER_ANSWER` 0 / `NODUS_DHT2_HOLDER_NO_ANSWER` 1 / `NODUS_DHT2_HOLDER_ERR` −1 (never a row-7 code: a code travels INSIDE the signed answer); `nodus_dht2_holder_init` 0 / −1; `nodus_dht2_holder_job_enter` `bool`; `nodus_dht2_holder_job_leave`, `nodus_dht2_holder_view_wview` `void` |

`DHT2_E_ARG` (−1) is always the CALLER's bug (a NULL argument, a buffer
too small) and never a verdict on input bytes (`dht2_types.h:82-84`).
`DHT2_E_HOLDER_FAULT` (16) is this node's own failure (hash, allocation,
signing, checked arithmetic) — never reported as `bad-signature` or as
absence (design §13 row 7).

### 1.2 Zero-copy lifetimes

- `dht2_cbor_rd_key` / `_bytes` / `_text` return pointers INTO the reader's
  buffer (`dht2_cbor.h:79-82`, `:89-93`).
- Package 2 (`dht2_msg.h:35-37`): `dht2_req_t.envs[]` (`:99`),
  `dht2_p_want_t.b` (`:237`) and `dht2_p_deliver_t.v` (`:247`) point INTO the
  decoded input; every other decoded field of a `dht2_msg.h` struct is copied
  into a fixed array. The `dht2_env_t` filled by `dht2_answer_open` points
  into its `in`, as for `dht2_env_decode`.
- `dht2_data_t.data` / `.prev`: after `dht2_data_decode` they point into the
  decoded bytes, "which must outlive the struct"; for encoding the caller
  sets them (`dht2_record.h:101-103`).
- `dht2_record_t.sig` / `.data` point into the `in` buffer given to
  `dht2_record_parse` (`dht2_record.h:140-142`, `:158`), and `rec->d.data` /
  `rec->d.prev` point into `rec->data`, i.e. also into `in`. A parsed
  record is valid only as long as `in` is.
- `dht2_env_t.payload_type` / `.payload` / `.sig` point INTO the decoded
  input (`dht2_envelope.h:66`).
- `pk` (the 2592-byte key) and `fp` are COPIED into the structs
  (`cmt_pb_public_key_t`, `shared/dnac/cmt_pb.h:213-216`).

### 1.3 Determinism, state, heap, clock

No function reads a clock (chain time is the `chain_now` parameter), keeps
global state, or draws randomness except inside `qgp_dsa87_sign_ctx`'s
hedged signing (`dht2_record.h:77-78`). Heap: `dht2_id` allocates its
preimage and frees it on every path (`dht2_record.h:78-80`); the RFC 0002
signed buffer is allocated in seal / verify and freed on every path
(`dht2_envelope.h:42-43`); the CBOR layer and placement use no heap
(`dht2_cbor.h:47-48`, `dht2_place.h:22`). The package-2 message layer
"reads no clock, keeps no state, draws no randomness, no heap"
(`dht2_msg.h:42`) — except that `dht2_answer_seal` / `dht2_answer_open`
call `dht2_env_seal` / `dht2_env_verify`, which allocate the RFC 0002 signed
buffer as above (`dht2_msg.c:695-725`). The five typed `_id` helpers
build their params on the stack and then call `dht2_id` (which allocates as
above) (`dht2_record.c:160-226`). Because ML-DSA-87 signing is
hedged, two builds of the same record differ in their signature bytes; a
retry must resend the stored canonical bytes (design §4.2).

The above is packages 1-2. **Package 4** (§11) reads no clock either (the
caller passes `now_ms`) but keeps per-view state and allocates (§11).
**Package 5** (§12) still reads no clock (chain time = the injected
snapshot's `tip_time`) but is stateful (a SQLite database) and draws ONE
random value: the store generation `g`, from `qgp_platform_random` when a
store is first created (`nodus_dht2_store.c:298-314`) — node-local,
compared for equality only, never a consensus input. It allocates per call
(`put_work_t` in `put`, `:893`; the held row's bytes, `:460`; the control
record's bytes, `:519`; the LIST hash buffer, `:1098`) and frees on every
path.
**Package 6a** (§13) reads no clock: `now_ms` (the caller's monotonic tick
count) is only handed on to the view, and chain time is the snapshot's `t`
(`nodus_dht2_holder.h:34-38`). Its QGP_LOG_* lines carry a log timestamp
read from the clock; no answer field depends on it (`:85-86`). Its state is
`queued` (the row-20 counter) and `chain_warned` (the foreign-chain log is
written once) in `nodus_dht2_holder_t` (`:149-158`). Each call allocates and
frees on every path: the `world_t` (`nodus_dht2_holder.c:384`, `:475`), the
answer struct (`:241`, `:306`, the LIST answer `:385`), and for a get a
`DHT2_ENVELOPE_MAX` record buffer and a `dht2_record_t` (`:242-243`). The
signature on every answer is hedged ML-DSA-87 (`dht2_answer_seal`), so two
answers to the same request differ in their signature bytes.

### 1.4 ⚠ API CONTRACT — signatures

**No function here except `dht2_record_verify`, `dht2_env_verify`,
`dht2_list_req_open`, `dht2_answer_open`, package 5's
`nodus_dht2_store_put` (which calls `dht2_record_verify` before Select and
store, `nodus_dht2_store.c:946-951`) and package 6a's
`nodus_dht2_holder_serve` (which verifies a LIST request through
`dht2_list_req_open`, `nodus_dht2_holder.c:374`, and admits every put
envelope through `nodus_dht2_store_put`) checks a signature.**
`nodus_dht2_holder_serve` also SIGNS: every answer it returns is sealed with
the node identity (`dht2_answer_seal`, `nodus_dht2_holder.c:180-181`). Every
package-2 `*_decode` reads a PAYLOAD and checks no signature; an answer /
receipt / refusal payload is trusted only after `dht2_answer_open` (or
`dht2_env_verify` under `nodus.dht.answer.v1`) returned `DHT2_OK` on its
envelope, and even then the client rules of §4.4 (the answering fp = `n`,
`q` = the request's nonce, `c`, eligibility) are the caller's
(`dht2_msg.h:202-207`). The pull-receipt payload has NO sealing or opening
function at all (its envelope domain is not decided). `dht2_record_parse`,
`dht2_data_decode`, `dht2_record_canonical`, `dht2_record_compare` and
`dht2_record_placement_key` operate on UNVERIFIED bytes
(`dht2_record.h:68-75`); `dht2_env_decode` does not verify, and a decoded
envelope's payload and fp are unproven until `dht2_env_verify` returns
`DHT2_OK` (`dht2_envelope.h:31-35`). On an unverified record the signer fp
is a CLAIM (`dht2_record.h:214-216`).

Holder admission must run design §4.1's full order: size → envelope decode
→ strict data decode + re-encode → `_chain` = local chain → pubKey → owner
fp → address → holder check (`eligible`) → class rules → expiry →
SIGNATURE (`dht2_record_verify`) → Select (§4.2) → quota → store the
canonical form. A record must never be stored, compared against a held
version or hashed into a receipt before `dht2_record_verify` returned
`DHT2_OK` (`dht2_record.h:71-75`). Packages 1-2 provide the steps; the
holder check, quota and store are package 5's `nodus_dht2_store_put` (§12),
which runs this order; package 6a's holder service (§13) runs every put
envelope through it and never parses or stores a put envelope itself (it
parses only a HELD record a get found, for its class — §13.4).

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
| `DHT2_R` | `4u` — holders per record | `:196`; design §2 (scope 4f) |
| `DHT2_SET_MAX` | `256u` — largest storage set `nearest_R` / `eligible` accept; bounds the O(n²) duplicate scan | `:201`; §13 row 13 |
| `DHT2_SALT_LEN` | `32u` — dm salt | `:138`; decision `2026-10-23-dht-v2-id-param-bytes.md` |
| `DHT2_GROUP_ID_LEN` | `32u` — group id | `:139`; same decision |
| `DHT2_KEY_VERSION_LEN` | `8u` — group key version, u64 big-endian ("as amended") | `:140`; same decision, Amendment |
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

Two different things below: a code a function RETURNS (a verdict of this
codec), and a code a package-2 message CARRIES as data (row-7 `v` in a read
answer / receipt / LIST answer, or the refusal's `e`). Codes 1…13, 16 and
17 may be carried in a row-7 `v`, 18 only as `[18, through]`, 14 / 15 only
as a refusal's `e` (§10.1, §10.4); "defined; later package" below means no
function RETURNS that code yet, not that a message cannot carry it.

| Code | Value | Returned by this package |
|---|---|---|
| `DHT2_OK` | 0 | every `DHT2_*`-convention function on success |
| `DHT2_E_TOO_LARGE` | 1 | `dht2_record_parse`, `dht2_record_build`, `dht2_env_decode`, `dht2_answer_open` (passed through from `dht2_env_decode`); package 5 `nodus_dht2_store_put` (through `dht2_record_parse`); package 6a writes it per key for an envelope above 262,144 B inside a put — with the all-zero key, since such an envelope has no address (§10.2, §13.4) |
| `DHT2_E_BAD_ENCODING` | 2 | `dht2_data_encode`, `dht2_data_decode`, `dht2_record_parse`, `dht2_record_build`, `dht2_env_decode`; package 2: `dht2_answer_encode/_decode`, `dht2_receipt_encode/_decode`, `dht2_list_answer_encode/_decode`, `dht2_refusal_encode/_decode`, `dht2_p_hello_decode`, `dht2_p_get_decode`, `dht2_p_offer_encode/_decode`, `dht2_p_want_encode/_decode`, `dht2_p_deliver_encode/_decode`, `dht2_pull_receipt_encode/_decode`, `dht2_ctl_encode`, `dht2_ctl_check`, `dht2_ctl_lookup`, `dht2_answer_open` (decode fault or another payload type) |
| `DHT2_E_BAD_CHAIN` | 3 | `dht2_record_parse`, `dht2_list_req_open` (internal there, see §6.3) |
| `DHT2_E_BAD_ADDRESS` | 4 | `dht2_record_parse` |
| `DHT2_E_NOT_HOLDER` | 5 | package 5: `nodus_dht2_store_put` (§12) |
| `DHT2_E_BAD_CLASS` | 6 | `dht2_record_check_class` (incl. a `ValidityType` ⇔ `Validity` disagreement since package 5), `dht2_record_check_expiry` (class out of range) |
| `DHT2_E_EXPIRED` | 7 | `dht2_record_check_expiry` |
| `DHT2_E_TOO_LONG` | 8 | `dht2_record_check_expiry` |
| `DHT2_E_BAD_SIGNATURE` | 9 | `dht2_record_verify`, `dht2_record_canonical`, `dht2_env_verify`, `dht2_list_req_open` (internal there), `dht2_answer_open` |
| `DHT2_E_QUOTA` | 10 | package 5: `nodus_dht2_store_put` |
| `DHT2_E_POOL_FULL` | 11 | package 5: `nodus_dht2_store_put` |
| `DHT2_E_DENIED` | 12 | package 5: `nodus_dht2_store_put` |
| `DHT2_E_NODE_FULL` | 13 | package 5: `nodus_dht2_store_put` |
| `DHT2_E_BUSY` | 14 | — returned by no function (call-level, row 7 / row 18; CARRIED as a refusal's `e`, §10.4); package 6a WRITES it: `nodus_dht2_holder_serve` answers the refusal 14 when the row-20 signing queue is full (§13.3) |
| `DHT2_E_NOT_CAUGHT_UP` | 15 | package 5: `nodus_dht2_store_put` / `_get` / `_list` / `_sweep` / `_scan` (the call-level gate; CARRIED as a refusal's `e`, §10.4); package 6a writes it as the refusal 15 for no fresh snapshot, block sync, a snapshot of another chain, a store 15, and — as `NODUS_DHT2_HOLDER_WRITE_REFUSAL`, a READING (§13.6) — for a put while |S(H)| < 2 |
| `DHT2_E_HOLDER_FAULT` | 16 | `dht2_record_parse`, `dht2_record_check_class`, `dht2_record_check_expiry`, `dht2_record_build`, `dht2_record_placement_key`, `dht2_env_seal`, `dht2_env_decode`, `dht2_env_verify`, `dht2_list_req_open`, `dht2_answer_seal` / `dht2_answer_open` (passed through); package 5: every `nodus_dht2_store_*` call returning an int (`NODUS_DHT2_STORE_FAULT`); package 6a writes it per key for a store fault, a name fault / pending name, and a held record that no longer parses (§13.4) |
| `DHT2_E_NOT_OWNER` | 17 | `dht2_list_req_open` (also CARRIED: the one code a LIST answer's `v` may be, §10.1); package 6a writes it as a LIST answer's `r.v` for a request not signed by the inbox owner, and per key for a GET that finds a held inbox-control (class 5) record (§13.4) |
| `DHT2_E_HANDLED` | 18 | package 5: `nodus_dht2_store_put` (the cutoff in `nodus_dht2_put_t.through`); on the wire CARRIED only as `v = [18, through]`, §10.1 — package 6a writes it so in a receipt, under the envelope's address |
| `DHT2_E_MALFORMED_REQ` | −2 | NOT a row-7 code — "a tier-2 protocol error, no signed answer" (`:79-81`): `dht2_list_payload_decode`, `dht2_list_req_open`, `dht2_req_encode`, `dht2_req_decode`; package 6a turns it into `NODUS_DHT2_HOLDER_NO_ANSWER` (§13.3) |
| `DHT2_E_ARG` | −1 | NOT a row-7 code — a NULL argument / too-small output buffer (`:82-84`): every `DHT2_*`-convention function; also `dht2_answer_seal` / `dht2_answer_open` given a payload type other than answer / receipt / refusal, and `dht2_ctl_at` with an index out of range; package 5: a NULL argument of `nodus_dht2_store_put` / `_get` / `_list` / `_sweep` / `_scan` / `_handover_set` / `_handover_get` (for `put` also a NULL name callback), and `_scan` with `max` 0 or > 250 |

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

### 2.5 Package 2 message bounds (`:121-134`; §13 rows 7, 11, 12, 14, 15)

| Constant | Value | Source |
|---|---|---|
| `DHT2_REQ_KEYS_MAX` | `8u` — get `keys` / put `envs` ≤ 8; also the `r` array of a read answer / receipt | `:124`; row 7 "> 8 keys" is malformed, row 14 |
| `DHT2_LIST_PAGE_MAX` | `16u` — entries in one LIST page | `:126`; row 11 |
| `DHT2_PULL_PAGE_MAX` | `250u` — `p_offer` / pull-receipt entries (Bee `DefaultMaxPage`) | `:128`; row 12 |
| `DHT2_CTL_ENTRY_LEN` | `73u` — control entry = fp 64 ‖ mark 1 ‖ through 8 (u64 BE) | `:131`; row 15 |
| `DHT2_CTL_ENTRIES_MAX` | `3500u` | `:132`; row 15 |
| `DHT2_CTL_HANDLED` / `DHT2_CTL_DENIED` | `1u` / `2u` — control marks | `:133-134`; row 15 |

`dht2_record.c:31-32` still carries its own private `CTL_ENTRY_LEN`
(`DHT2_FP_LEN + 1u + 8u`) and `CTL_ENTRIES_MAX` (`3500u`) for the class-5
check of package 1; the values are equal to the public ones above.

### 2.6 Row 11: the derived maximum answer message (`:142-193`)

Row 11 pins the largest answer MESSAGE (8 × 262,144 B of records beside one
signed answer envelope) in code and requires it to fit one frame. The
header derives every term (`:142-180`, every uint at its 9-byte maximum);
the macros are:

| Constant | Definition (copied from `dht2_types.h`) | Value |
|---|---|---|
| `DHT2_READ_ANSWER_PAYLOAD_MAX` (`:181-182`) | `1u + 36u + 11u + 68u + 36u + (2u + 1u + 8u * 137u) + 11u` — the 8-key read answer (`c`, `h`, `n`, `q`, `r` of 8 elements of 137 B, `t`) | 1,262 B — also measured by `test_dht2_msg.c` `test_seal_and_sizes` (`plen == 1262u`) |
| `DHT2_LIST_ANSWER_PAYLOAD_MAX` (`:183-185`) | `1u + 36u + 11u + 68u + 36u + 11u + (2u + 1u + 137u) + 70u + (5u + 1u + 16u * 137u) + 73u + 10u + 77u` — 16 `{w, d}` entries, both cursors, hash `ctl` | 2,731 B — measured (`lplen == 2731u`) |
| `DHT2_ANSWER_PAYLOAD_MAX` (`:186-188`) | the larger of the two (the LIST one; receipt and refusal payloads are smaller than the read answer, `:160-162`) | 2,731 B |
| `DHT2_ANSWER_ENV_MAX` (`:189-191`) | `(1u + 2u + (1u + 2u + DHT2_PUBKEY_LEN)) + (1u + 1u + 21u) + (1u + 2u + DHT2_ANSWER_PAYLOAD_MAX) + (1u + 2u + DHT2_SIG_LEN)` — RFC 0002 fields 1, 2 (21 B = the longest answer payload type, `/nodus/dht/receipt/v1` / `/nodus/dht/refusal/v1`), 3, 5 | 9,985 B (evaluated from the macro: 2598 + 23 + 2734 + 4630); the test checks the sealed maximal LIST payload under a 21-byte type equals it |
| `DHT2_ANSWER_MSG_MAX` (`:192-193`) | `DHT2_REQ_KEYS_MAX * DHT2_ENVELOPE_MAX + DHT2_ANSWER_ENV_MAX` | 2,107,137 B (evaluated from the macro: 8 × 262,144 + 9,985) |

The `_Static_assert(DHT2_ANSWER_MSG_MAX < NODUS_MAX_FRAME_TCP, …)` lives in
`nodus/tests/test_dht2_msg.c:93-95`, because `shared/` does not include nodus
headers (`dht2_types.h:179-180`). `NODUS_MAX_FRAME_TCP` = `(5 * 1024 * 1024)`
(`nodus/include/nodus/nodus_types.h:64`). The sealed 8-key read answer
measures 8,516 B (`test_seal_and_sizes`, `elen == 8516u`).

---

## 3. Strict DAG-CBOR (`shared/dht2/dht2_cbor.h`)

A TOKEN reader and a canonical writer — the schemas above it match fixed
text keys and never build a tree (`dht2_cbor.h:5-8`). Not
`nodus/src/protocol/nodus_cbor.h`: that decoder accepts long-form integers
and lengths and does not check map key order (design §13 row 22), and
`shared/` cannot depend on `nodus/src` (`dht2_cbor.h:10-15`).

**Rules enforced on decode** (`dht2_cbor.h:17-41`, dag-cbor `spec.md`
"Strictness" :46-66; the relaxed decoding of :68-78 is NOT offered):
integers and lengths of major types 0, 2-5 in their SHORTEST form; no
indefinite lengths, no break token; no tags at all (every major type 6 is
refused — tag 42 is not used by any DHT v2 schema); of major type 7 only
`false` / `true` / `null` (0xf4 / 0xf5 / 0xf6) are read, each by its own
single-byte reader — `_del` and the LIST answer's `complete` are booleans,
row-7 `v`, the LIST answer's `ctl` and `p_deliver.v` may be null — and
floats and every other simple value are refused (`:25-29`; until package 2
only `true` was offered); arrays (major type 4) definite and shortest-head
only, and the CALLER bounds the element count before it loops —
`dht2_cbor_rd_array` returns whatever count the head claims (`:30-32`);
major type 1 (negative integer) refused (design §13 row 6, named
deviation); map keys text only, STRICTLY ascending by their encoded bytes
(length first, then bytewise), so a duplicate key is refused too; one
top-level object with no trailing byte (the schema checks
`dht2_cbor_rd_done`). The schemas ALSO re-encode what they parsed and
compare it byte for byte with the input (§3.1 "re-encode check"). The
writer emits only shortest forms, definite lengths, no tags, no floats, and
never sorts — each schema writes its keys in the fixed canonical order
(`:43-45`).

| Item | Description |
|------|-------------|
| `typedef struct { const uint8_t *buf; size_t len; size_t pos; bool err; } dht2_cbor_rd_t;` (`:67-72`) | Reader. `err` is STICKY: once set, every call fails. |
| `void dht2_cbor_rd_init(dht2_cbor_rd_t *r, const uint8_t *buf, size_t len)` (`:74`) | Starts a reader; a NULL `buf` reads as length 0 (`dht2_cbor.c`). |
| `int dht2_cbor_rd_map(dht2_cbor_rd_t *r, uint64_t *count)` (`:77`) | Map header, definite and shortest. 0 / −1. |
| `int dht2_cbor_rd_key(dht2_cbor_rd_t *r, const uint8_t *prev, size_t prev_len, const uint8_t **key, size_t *key_len)` (`:83`) | A map KEY: text string, shortest length. `prev` / `prev_len` = the previous key of the same map (NULL for the first); the new key must sort strictly after it (length first, then bytewise). Pointer INTO the buffer. 0 / −1. |
| `int dht2_cbor_rd_uint(dht2_cbor_rd_t *r, uint64_t *v)` (`:87`) | Major type 0, shortest. 0 / −1 (major type 1 is −1). |
| `int dht2_cbor_rd_bytes(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n)` (`:90`) | Major type 2, shortest length; pointer into the buffer; the length is bounded by the bytes remaining. 0 / −1. |
| `int dht2_cbor_rd_text(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n)` (`:93`) | Major type 3, same rules. 0 / −1. |
| `int dht2_cbor_rd_array(dht2_cbor_rd_t *r, uint64_t *count)` (`:98`) | Package 2. Array header (major type 4), definite and shortest. The count is NOT checked against the remaining bytes — the schema bounds it before iterating (`dht2_msg.c` `rd_array_max`, `:95-104`). Any other major type sets `err`. 0 / −1. |
| `int dht2_cbor_rd_true(dht2_cbor_rd_t *r)` (`:101`) | Exactly 0xf5. 0 / −1. |
| `int dht2_cbor_rd_bool(dht2_cbor_rd_t *r, bool *v)` (`:104`) | Package 2. Exactly 0xf4 (`*v` = false) or 0xf5 (`*v` = true); any other byte, or no byte left, sets `err`. 0 / −1. |
| `int dht2_cbor_rd_null(dht2_cbor_rd_t *r)` (`:107`) | Package 2. Exactly 0xf6. 0 / −1. |
| `int dht2_cbor_rd_peek_mt(const dht2_cbor_rd_t *r)` (`:112`) | Package 2. The major type (0-7, = the next byte >> 5) of the next item WITHOUT consuming it; −1 at the end of input or after an error. Used where a value may be one of several types (row-7 `v`). |
| `bool dht2_cbor_rd_peek_null(const dht2_cbor_rd_t *r)` (`:115`) | Package 2. True when the next byte is exactly 0xf6; nothing consumed; false on error or at the end. |
| `bool dht2_cbor_rd_done(const dht2_cbor_rd_t *r)` (`:118`) | True when every byte was consumed without error (spec :66). |
| `bool dht2_cbor_key_is(const uint8_t *key, size_t key_len, const char *lit)` (`:121`) | Key equality (exact length and bytes). |
| `typedef enum { DHT2_WR_WRITE = 0, DHT2_WR_COUNT, DHT2_WR_COMPARE } dht2_wr_mode_t;` (`:133-137`) | Three writer modes over ONE emission path, so the bytes counted, written and compared are the same bytes by construction (`:123-131`). WRITE into a caller buffer; COUNT stores nothing and `len` = the size; COMPARE stores nothing and compares every byte with `ref` at the same offset — the §3.1 re-encode identity check without a second buffer. |
| `typedef struct { dht2_wr_mode_t mode; uint8_t *buf; const uint8_t *ref; size_t cap; size_t len; bool err; } dht2_cbor_wr_t;` (`:139-146`) | Writer. `cap` = buffer size (WRITE) or `ref` length (COMPARE). `err` STICKY: overflow, a COMPARE mismatch, or a NULL pointer with a non-zero length. |
| `void dht2_cbor_wr_init(dht2_cbor_wr_t *w, uint8_t *buf, size_t cap)`, `void dht2_cbor_wr_init_count(dht2_cbor_wr_t *w)`, `void dht2_cbor_wr_init_compare(dht2_cbor_wr_t *w, const uint8_t *ref, size_t ref_len)` (`:148-151`) | Start WRITE (a NULL `buf` sets `err`), COUNT, or COMPARE. |
| `bool dht2_cbor_wr_ok(const dht2_cbor_wr_t *w)` (`:154`) | COMPARE: every emitted byte matched AND all of `ref` was emitted. WRITE / COUNT: no error occurred. |
| `void dht2_cbor_wr_map(dht2_cbor_wr_t *w, uint64_t count)`, `void dht2_cbor_wr_uint(dht2_cbor_wr_t *w, uint64_t v)`, `void dht2_cbor_wr_bytes(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)`, `void dht2_cbor_wr_text(dht2_cbor_wr_t *w, const uint8_t *p, size_t n)`, `void dht2_cbor_wr_key(dht2_cbor_wr_t *w, const char *lit)`, `void dht2_cbor_wr_true(dht2_cbor_wr_t *w)` (`:155-161`) | Emit one item with the shortest head. `wr_key` = a text key from a C string literal. |
| `void dht2_cbor_wr_bool(dht2_cbor_wr_t *w, bool v)`, `void dht2_cbor_wr_null(dht2_cbor_wr_t *w)`, `void dht2_cbor_wr_array(dht2_cbor_wr_t *w, uint64_t count)` (`:162-165`) | Package 2. One byte 0xf5 / 0xf4; one byte 0xf6; an array header in shortest form, after which the caller writes `count` items. |
| `size_t dht2_cbor_head_size(uint64_t v)` (`:168`) | Bytes the head of an item with argument `v` takes: 1 / 2 / 3 / 5 / 9. |

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
| `typedef struct { uint64_t sequence; uint64_t validity_type; uint64_t expiry; uint8_t chain[DHT2_CHAIN_LEN]; uint8_t id[DHT2_ID_LEN]; uint64_t cls; bool del; bool has_data; const uint8_t *data; size_t data_len; bool has_prev; const uint8_t *prev; size_t prev_len; } dht2_data_t;` (`:104-118`) | The data map. `expiry` (seconds) is meaningful only when `validity_type` is 0 — except the decode-only MISMATCH marker `UINT64_MAX` below. `data` / `prev` are zero-copy (§1.2). `prev_len` ∈ {0, 64} (row 3: 0 = first feed entry). |
| `int dht2_data_encode(const dht2_data_t *d, uint8_t *out, size_t cap, size_t *out_len)` (`:127`) | Canonical DAG-CBOR of `d`, keys in the one order strict DAG-CBOR allows: `TTL, _id, _del, Value, _data, _prev, _chain, _class, Sequence, Validity, ValidityType` (each only when present). `out` NULL → only `*out_len`. `DHT2_OK`; `DHT2_E_BAD_ENCODING` (Sequence 0, ValidityType ∉ {0,1}, expiry beyond 9999-12-31T23:59:59Z, `_prev` length ∉ {0,64}, and — since package 5 — `expiry` = the MISMATCH marker `UINT64_MAX`, so a decoded disagreement is never re-emitted, `dht2_record.c:315-317`); `DHT2_E_ARG` (NULL `d` / `out_len`, a NULL `data` / `prev` with a non-zero length, buffer too small). Does NOT check `_class` range or the row-5 matrix. |
| `int dht2_data_decode(const uint8_t *in, size_t len, dht2_data_t *d)` (`:133`) | Strict decode (§3) + the re-encode identity check (§3.1, rows 5-6, 22). Refuses (`DHT2_E_BAD_ENCODING`): fewer than 8 or more than 11 keys, an unknown key, unsorted / duplicate keys, `TTL` ≠ 0, `Value` not empty, `_id` ≠ 64 B, `_chain` ≠ 32 B, `_prev` ∉ {0, 64} B, `_del` other than `true`, `Sequence` 0, `ValidityType` ∉ {0, 1}, ValidityType 0 with a NON-EMPTY `Validity` that does not parse, a trailing byte, a missing required key. **Since package 5 a `ValidityType` ⇔ `Validity` disagreement (type 0 with an EMPTY `Validity`, type 1 with a NON-EMPTY one) is NOT refused here**: it returns `DHT2_OK` with `d->expiry` = the private marker `VALIDITY_MISMATCH` = `UINT64_MAX` (`dht2_record.c:237`, `:440-453`; above `DHT2_VALIDITY_MAX_SECONDS`, so no real `Validity` produces it), the re-encode identity check still run over the raw `Validity` bytes (`:455-461`); `dht2_record_check_class` then refuses it as `DHT2_E_BAD_CLASS`. A caller that uses decode alone must not read `expiry` as a time without running the class check. `DHT2_E_ARG` on NULL `d` or NULL `in` with `len` ≠ 0 (header `@return` lists only OK / BAD_ENCODING). Class rules NOT applied; no signature checked. `*d` is zeroed at entry. |
| `typedef struct { cmt_pb_public_key_t pk; uint8_t fp[DHT2_FP_LEN]; const uint8_t *sig; size_t sig_len; const uint8_t *data; size_t data_len; dht2_data_t d; uint8_t address[DHT2_HASH_LEN]; } dht2_record_t;` (`:137-146`) | A parsed record: `pk` field 7 decoded (copied); `fp` = SHA3-512(`pk.key`); `sig` field 8 and `data` field 9 point into the input; `d` = parsed field 9; `address` = H(`_id` ‖ fp). |
| `int dht2_record_parse(const uint8_t *in, size_t len, const uint8_t local_chain[DHT2_CHAIN_LEN], const uint8_t *expect_address, dht2_record_t *rec)` (`:163`) | §4.1 up to and including the address, in its order: `len` > 262,144 → `DHT2_E_TOO_LARGE` (BEFORE any decode); envelope decode fault → `DHT2_E_BAD_ENCODING`; `data` not strict / not re-encoding → `DHT2_E_BAD_ENCODING`; `_chain` ≠ `local_chain` → `DHT2_E_BAD_CHAIN`; pubKey missing or not the ML-DSA-87 branch of exactly 2592 B → `DHT2_E_BAD_ENCODING`; address ≠ a non-NULL `expect_address` → `DHT2_E_BAD_ADDRESS`. Also `DHT2_E_HOLDER_FAULT` (the fp or address hash failed) and `DHT2_E_ARG` (NULL `rec` / `local_chain`, NULL `in` with `len` ≠ 0) — neither is in the header comment. Envelope decode follows the generated Unmarshal: fields in any order, unknown fields (incl. IPNS V1 fields 1-6) skipped by wire type, a repeated field last-one-wins. `rec` points into `in`; `*rec` is zeroed at entry. Does NOT verify the signature (§1.4). |
| `int dht2_record_check_class(const dht2_record_t *rec)` (`:169`) | Row-5 class rules + row-15 control-list shape + the §3.2 inbox-control binding (above) + — since package 5 — the §4.1 `ValidityType` ⇔ `Validity` rule: a record `dht2_data_decode` marked as a disagreement (`expiry` = `UINT64_MAX`) is `DHT2_E_BAD_CLASS`, checked right after the `_class` range (`dht2_record.c:594-596`), so a bad `_chain` (3, from `dht2_record_parse`) still comes first as §4.1 orders it. `DHT2_OK`; `DHT2_E_BAD_CLASS`; also `DHT2_E_HOLDER_FAULT` (the control `_id` recompute failed) and `DHT2_E_ARG` (NULL) — not in the header comment. |
| `int dht2_record_check_expiry(const dht2_record_t *rec, uint64_t chain_now, bool writer_named)` (`:176`) | §4.1 "expiry > holder chain time and ≤ holder chain time + class max + 3 h", class max by the writer's name status (above). ValidityType 1 where the class max is finite → `DHT2_E_TOO_LONG`; expiry ≤ `chain_now` → `DHT2_E_EXPIRED` (stricter than boxo by one second: boxo accepts eol == now, `dht2_record.c` comment on `validation.go:73`); expiry > bound → `DHT2_E_TOO_LONG`; class out of range → `DHT2_E_BAD_CLASS` (never reached after `check_class`). Also `DHT2_E_HOLDER_FAULT` (checked add overflow) and `DHT2_E_ARG` (NULL) — not in the header comment. `chain_now` is the caller's (the snapshot's chain time, §2). |
| `int dht2_record_verify(const dht2_record_t *rec)` (`:181`) | ML-DSA-87 verify over the `data` bytes, ctx `nodus.dht.record.v1`. `DHT2_OK`; `DHT2_E_BAD_SIGNATURE` (no key, no signature, signature ≠ 4627 B, or verify fails); `DHT2_E_ARG` (NULL). |
| `int dht2_record_canonical(const dht2_record_t *rec, uint8_t *out, size_t cap, size_t *out_len)` (`:189`) | The stored form: fields 7, 8, 9 only, in field order, each once, proto3 emission rules (`cmt_pb.h:22`), unknown fields dropped. `out` NULL → only `*out_len`. Does NOT verify the signature, but REFUSES a signature that is not exactly 4627 B (`DHT2_E_BAD_SIGNATURE`) — no canonical form for a record that could never verify. `DHT2_OK`, `DHT2_E_BAD_SIGNATURE`, `DHT2_E_ARG` (NULL, no key, buffer too small). |
| `int dht2_record_build(const dht2_data_t *d, const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out, size_t cap, size_t *out_len)` (`:198`) | Client side: encode `d`, sign it (hedged, ctx `nodus.dht.record.v1`) with `sk` (4896 B), write the CANONICAL envelope with `pk` (2592 B). `out` NULL → `*out_len` = the exact size, no signing, and `sk` may then be NULL. `DHT2_OK`; `DHT2_E_BAD_ENCODING` (`d` not encodable); `DHT2_E_TOO_LARGE` (> 262,144 B); `DHT2_E_ARG` (NULL, `cap` < size); `DHT2_E_HOLDER_FAULT` (signing failed — the first `total` bytes of `out` are then zeroed). Does not check class rules. |
| `int dht2_record_compare(const dht2_record_t *a, const dht2_record_t *b)` (`:210`) | §4.2 order of two versions AT THE SAME ADDRESS: larger `Sequence` → later expiry (no expiry above any expiry) → larger canonical `data` bytes → larger signature bytes; "larger bytes" = Go `bytes.Compare` (first differing byte, then the shorter is smaller). A NULL side = "nothing held" and loses to a present one (both NULL → 0). > 0 `a` wins, < 0 `b` wins, 0 the same version. Does NOT verify either signature — both must have passed `dht2_record_verify`. Pure function of the two records: arrival order cannot change the winner (the A/B two-arrival vector, §9). |
| `int dht2_record_placement_key(const dht2_record_t *rec, uint8_t out[DHT2_HASH_LEN])` (`:217`) | §2 placement key: class 4 → its `_id` (the inbox id); class 5 → SHA3-512(`nodus.dht.inbox.v1` ‖ `_chain` ‖ signer fp) (the inbox its signer owns); otherwise the record's address. `DHT2_OK`, `DHT2_E_ARG`, `DHT2_E_HOLDER_FAULT`. On an unverified record the signer fp is a claim. |
| `int dht2_id(const char *label, const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t *params, size_t params_len, uint8_t out[DHT2_ID_LEN])` (`:225`) | §3.2: SHA3-512(label ‖ chain_id 32 B ‖ params). `label` = a `DHT2_LABEL_*` string (ASCII, no NUL hashed). `params` may be NULL when `params_len` is 0. Allocates the preimage, freed on every path. 0 / −1. |
| `int dht2_id_feed_entry(const uint8_t topic[DHT2_HASH_LEN], uint64_t index, uint8_t out[DHT2_ID_LEN])` (`:231`) | Feed entry `_id` = SHA3-512(topic ‖ index as 8-byte big-endian) — no label, no chain (Bee `pkg/feeds/feed.go:70-71`, `sequence/sequence.go:47-51`). 0 / −1. |
| `int dht2_id_feed_head(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t topic[DHT2_HASH_LEN], uint8_t out[DHT2_ID_LEN])` (`:235`) | SHA3-512(`nodus.dht.head.v1` ‖ chain ‖ topic) — the design rev 3+ form (§3.2 supersedes Kurultay #21 summary :139's `label ‖ topic`). 0 / −1. |
| `int dht2_id_inbox(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t recipient_fp[DHT2_FP_LEN], uint8_t out[DHT2_ID_LEN])` (`:240`) | Inbox id = SHA3-512(`nodus.dht.inbox.v1` ‖ chain ‖ recipient fp). 0 / −1. |
| `int dht2_id_inbox_ctl(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t recipient_fp[DHT2_FP_LEN], uint8_t out[DHT2_ID_LEN])` (`:246`) | Inbox control `_id` = SHA3-512(`nodus.dht.inbox.ctl.v1` ‖ chain ‖ recipient fp). 0 / −1. |
| `int dht2_id_dm(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t recipient_fp[DHT2_FP_LEN], const uint8_t salt[DHT2_SALT_LEN], uint8_t out[DHT2_ID_LEN])` (`:255`) | Package 2, client side. 1:1 (dm) topic = SHA3-512(`nodus.dht.dm.v1` ‖ chain 32 ‖ recipient fp 64 ‖ salt 32) — via `dht2_id` with params = recipient fp ‖ salt (`dht2_record.c:160-173`). 0 / −1 (NULL `recipient_fp` / `salt`, or `dht2_id`'s −1). |
| `int dht2_id_group_head(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t group_id[DHT2_GROUP_ID_LEN], uint8_t out[DHT2_ID_LEN])` (`:262`) | Package 2, client side. Group head `_id` = SHA3-512(`nodus.dht.group.head.v1` ‖ chain 32 ‖ group id 32). No key version. 0 / −1. |
| `int dht2_id_group_record(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t group_id[DHT2_GROUP_ID_LEN], uint64_t key_version, uint8_t out[DHT2_ID_LEN])` (`:268`) | Package 2, client side. Group record `_id` = SHA3-512(`nodus.dht.group.record.v1` ‖ chain 32 ‖ group id 32 ‖ key version as 8-byte unsigned big-endian) (`dht2_record.c:185-210`). 0 / −1 (NULL `group_id`, or `dht2_id`'s −1). |
| `int dht2_id_group_keys(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t group_id[DHT2_GROUP_ID_LEN], uint64_t key_version, uint8_t out[DHT2_ID_LEN])` (`:274`) | Package 2, client side. Group key-packet `_id` = SHA3-512(`nodus.dht.group.keys.v1` ‖ chain 32 ‖ group id 32 ‖ key version u64 BE, 8 B). 0 / −1. |
| `int dht2_id_group_feed(const uint8_t chain[DHT2_CHAIN_LEN], const uint8_t group_id[DHT2_GROUP_ID_LEN], uint8_t out[DHT2_ID_LEN])` (`:280`) | Package 2, client side. Group feed topic = SHA3-512(`nodus.dht.group.feed.v1` ‖ chain 32 ‖ group id 32). No key version. 0 / −1. |
| `int dht2_address(const uint8_t id[DHT2_ID_LEN], const uint8_t owner_fp[DHT2_FP_LEN], uint8_t out[DHT2_HASH_LEN])` (`:285`) | Address = SHA3-512(`_id` ‖ owner fp), in that order (Bee `soc.go:199-207`). 0 / −1. |
| `int dht2_fp(const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t out[DHT2_FP_LEN])` (`:291`) | Owner fp = SHA3-512(raw 2592-byte ML-DSA-87 key) — the tree's fingerprint (`nodus/src/crypto/nodus_sign.c:392`). 0 / −1. |
| `int dht2_bytes_compare(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)` (`:294`) | Go `bytes.Compare`: −1 / 0 / 1. |

**The five typed `_id` helpers** (`dht2_record.h:250-252`): their preimages
are fixed by the operator's decision `2026-10-23-dht-v2-id-param-bytes.md`
— dm salt 32 B, group id 32 B, group key version 8 B unsigned big-endian
(the Amendment replaced a first answer of 4 B, because today's Connect group
ADDRESS preimage hashes the version as 8 bytes), the version present in the
group.record and group.keys `_id` only. Every field is fixed length, so
the concatenation is unambiguous. Only clients compute these; holders
never see the params (design §13 row 5). A later change of any of them is
a new label plus a migration (same decision, "Consequences").

**Readings this file makes where the design names no code**
(`dht2_record.h:42-66` — labelled readings reported to the ORCHESTRATOR,
not design facts): class-independent byte-form faults → `bad-encoding`
(2), incl. a `Validity` text that is not the 20-byte form; per-class faults
(incl. `_class` ∉ 1…5, the feed-head 8-B rule, a malformed row-15 list, the
inbox-control binding, and since package 5 a `ValidityType` ⇔ `Validity`
disagreement — §4.1 lists it among the class rules) → `bad-class` (6);
ValidityType 1 where the class max is finite → `too-long` (8); a NAMED
writer's class 1 / 3 / 5 record may carry a finite expiry with no upper
bound (row 5 "no expiry allowed (ValidityType 1) with a name" read as
"the class max is unbounded"); an empty `_data` is valid for classes 1, 2,
4; a ValidityType ⇔ Validity mismatch is `bad-class` (6), not
`bad-encoding` — decode lets it through (the re-encode identity check still
covers it) and `dht2_record_check_class` refuses it, so §4.1's order holds
(chain 3 before it). Until package 5 this reading was the opposite (2, in
decode), which answered 2 where §4.1 requires 3 for a record with both
faults.

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
request live here; the answer / receipt / refusal payload maps (row 18) and
their seal / open are package 2, `dht2_msg.h` (§10) — the header's own
`:45-46` still says "a later package".

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
- Package 2 — the request's fresh 32-byte nonce echoed as `q` in every
  answer / receipt / refusal payload (row 2; `dht2_answer_t.q`,
  `dht2_refusal_t.q`, `dht2_msg.h:128`, `:183`).
- Package 2 — the exact `p_want` bit-vector length: exactly ⌈n/8⌉ bytes
  with every bit ≥ n zero, any other length refused, where Bee allocates
  ⌊n/8⌋ + 1 bytes (row 12; `want_valid`, `dht2_msg.c:899-910`;
  `dht2_msg.h:279-281`). Row 21's other pull-sync items (one cursor per
  source, the shared session, stamps dropped) belong to the exchange
  (package 7), not to this codec.

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
  §4.1 "expiry > holder chain time" (`dht2_record.c:670-676`,
  `dht2_record_check_expiry`).

---

## 9. Tests

### 9.1 `test_dht2_codec` (package 1)

`nodus/tests/test_dht2_codec.c` (ctest `test_dht2_codec`,
`nodus/CMakeLists.txt:2075-2081`, linked `nodus dsa nodus crypto`). Twelve
sections run from `main` (`test_dht2_codec.c:1851-1862`):
`test_strict_decode`, `test_class_kats`, `test_preimages`, `test_envelope`,
`test_matrix`, `test_class_max`, `test_validity`, `test_order`,
`test_placement`, `test_envelopes_and_list`, `test_reader_shortest`,
`test_hardening`. 197 source lines match `CHECK(`, the macro's own
`#define` (`:107`) included; 433 passed / 0 failed is the ORCHESTRATOR's
run before the package-5 rebase (at `2f0478bcf`), not re-run for this
reference. Since package 5 `test_strict_decode` expects the two
`ValidityType` ⇔ `Validity` variants (`V_VT1_TEXT`, `V_VT0_EMPTY`) to DECODE
(`DHT2_OK`), then checks `dht2_record_check_class` returns
`DHT2_E_BAD_CLASS` and `dht2_data_encode` refuses the decoded struct with
`DHT2_E_BAD_ENCODING` (`test_dht2_codec.c:376-405`).

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

### 9.2 `test_dht2_msg` (package 2)

`nodus/tests/test_dht2_msg.c` (ctest `test_dht2_msg`,
`nodus/CMakeLists.txt:2092-2098`, linked `nodus dsa nodus crypto`). Ten
sections run from `main` (`test_dht2_msg.c:2063-2072`):
`test_cbor_additions`, `test_requests`, `test_answers`, `test_list`,
`test_refusal`, `test_seal_and_sizes`, `test_pull`, `test_want`,
`test_ctl`, `test_ids`. 209 source lines match `CHECK(`, the macro's own
`#define` (`:103`) included (package 6a added the oversize-envelope checks
to `test_requests`, `:730-819`); the ORCHESTRATOR's run at `50053ce72`
reported 335 passed / 0 failed (and `test_dht2_codec` 429 / 0, the full
nodus ctest 304 / 304, the build with 0 warnings) — counts from that run,
before package 6a; not re-run for this reference. The file
also holds the row-11 `_Static_assert(DHT2_ANSWER_MSG_MAX <
NODUS_MAX_FRAME_TCP, …)` (`:96-98`), so a too-large message bound fails the
build, not a run.

- **Proves** (file header `:9-47`): each message — get / put request, read
  answer, receipt, LIST answer, refusal, `p_hello`, `p_get`, `p_offer`,
  `p_want`, `p_deliver` (bytes and null), pull-receipt payload — encodes to
  EXACTLY bytes assembled by hand (keys length-first-then-bytewise),
  decodes back to the same struct and re-encodes to the same bytes; per
  message: a trailing byte, every strict prefix, an unsorted / duplicate /
  unknown key, a long-form integer and length, a wrong byte-string length
  and each count bound (9 keys / envs, 17 LIST entries, 251 offer /
  receipt entries, 3,501 control entries) are refused, incl. an unknown
  `op` and a 31-byte nonce (`MALFORMED_REQ`); since package 6a an envelope
  above 262,144 B inside a put is NOT malformed (it encodes and decodes;
  the holder answers it per-key 1), while envelopes totalling over
  `DHT2_REQ_BUDGET` (encode and decode) and a request over
  `DHT2_REQ_MAX_LEN` (decode) are; row-7 `v`: a 64-byte hash,
  null (read answer only), codes 1…13, 16, 17 and `[18, through]` accepted
  where the context allows, and 0, 14, 15, 19, a bare 18, a 63-byte hash,
  an array of another shape and a negative integer refused, null refused in
  a receipt and in a LIST answer; the LIST rules (non-ascending / equal
  `w`, a cursor ≠ the last `w`, a cursor on an empty page, an empty page
  with `complete` false refused; a first page without `req_cursor`; `ctl`
  null and hash); the refusal carries only `e` 14 / 15 and no `h` / `t`;
  the `p_want` vector for n = 0, 1, 7, 8, 9, 250 (⌈n/8⌉ bytes, LSB-first; a
  set bit ≥ n, a wrong length and n = 251 refused); the control `_data`
  (73-byte entries, ascending, marks 1 / 2, ≤ 3,500; lookup finds the entry
  and its u64 BE `through`); the five `_id` helpers against hand-assembled
  preimages; seal / open under `nodus.dht.answer.v1`, a tampered payload →
  `bad-signature`, another payload type refused; the row-11 sizes (8-key
  payload 1,262 B, envelope 8,516 B; maximal LIST payload 2,731 B); the
  CBOR additions.
- **Requires** (`:48-53`): a default build — no compile flags, no
  environment variables, no network, no files, no clock. One fixed-seed
  ML-DSA-87 key (`qgp_dsa87_keypair_derand`); signing is hedged, so no
  signature byte is pinned. Safe under `ctest -j`.
- **Leaves behind** (`:54-56`): nothing.
- **Can lie** (`:57-73`): (1) the pinned bytes are assembled by hand from
  the design rows and the two decisions — self-consistent with the
  codec's author, not an oracle from another implementation (the design's
  C ↔ WASM cross-check will ground them); (2) where the text is silent
  nothing is tested either way — 0 keys in a get, an empty env, offer
  entry order, which LIST fields accompany code 17, the `through` range,
  `[18, x]` in a read answer; (3) the prefix sweep proves truncation is
  refused, not that every malformed message is; (4) the `_id` helpers are
  compared to preimages hashed by the same SHA3-512, so a wrong label in
  the decision record itself would pass; (5) the pull-receipt envelope
  domain is undecided — only its payload is tested.

### 9.3 `test_dht2_ipc` (package 4)

`nodus/tests/test_dht2_ipc.c` (ctest `test_dht2_ipc`,
`nodus/CMakeLists.txt:2083-2090`, linked `nodus dsa nodus`). 24 cases, run
from `main` (`test_dht2_ipc.c:1152`, calls `:1195-1219`): nine against the REAL witness
listener (`nodus_witness_ipc_*`) with a raw peer and test handlers —
`test_snap`, `test_sets`, `test_sets_max`, `test_name`, `test_unserved`,
`test_nul_in_q`, `test_request_header_cap`, `test_null_handler`,
`test_status_unchanged` (defined `:357-608`); fourteen against
`nodus_dht2_wview` and a scripted socket server with INJECTED time —
`test_c_start`, `test_c_snap_age`, `test_c_late_reply`,
`test_c_snap_age_from_request`, `test_c_fault_kept`,
`test_c_fault_abandoned` (package 6a, `:998-1025`), `test_c_header_cap`,
`test_c_poll_rate`, `test_c_snap_err`, `test_c_sets`, `test_c_name`,
`test_c_name_fault`, `test_c_timeout`, `test_c_malformed` (defined
`:717-1109`); one end to end, `test_end_to_end` (`:1113`). The file repeats
two of the header's frame-bound `_Static_assert`s (`:112-115`). The ORCHESTRATOR's run at `793a85ef0`
(before package 6a, 23 cases): `test_dht2_ipc` 23 passed / 0 failed, build 0 warnings; `test_witness_ipc`,
`test_storage_linked`, `test_split_linked`, `test_dht2_codec`,
`test_dht2_msg` pass — counts from that run, not re-run for this reference.

- **Proves** (file header `:9-66`): the `ipc_dht` answers are EXACTLY
  `{q, ci, h, t, cu, e}`, `{q, e, s0, s1, rg:[{f, st}]}`, `{q, fp, h, n}`
  (bytes pinned by hand-built expectations); a handler fault is `{q, err}`
  (a name fault keeps `fp`), never empty or partial; the `e = 0` / `e ≤ E` /
  `e > E` arrays; a sets answer with `DNA_V2_STORAGE_SET_MAX` members in all
  three lists is EXACTLY `NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX` bytes and
  fits `NODUS_WITNESS_IPC_DHT_FRAME_MAX`; frames the kind does not serve
  close the connection (`ipc_status`, unknown `q`, extra key, `ipc_name`
  without / with a short `fp`, malformed map, a request over
  `CTL_FRAME_MAX`, a dht request on an `ipc_ctl` connection, a NULL
  handler, a NUL in `q`); `ipc_status` is unchanged byte for byte (true at
  package 4; since DHT v2 3b-2 `ipc_status` is an 8-key map with `c3`, the
  v3 chain id — `nodus_witness_ipc.c:484-494` — and the `ci` of
  `ipc_dht_snap` carries the v3 id, `:112-115`). The
  view: preface then snap and sets requests; fresh for 5000 ms, none from
  5001 ms; a request each 1000 ms, not before; a snapshot `{err}` clears it;
  sets only with a same-`e` fresh snapshot, one re-request on an `e` change;
  one outstanding request per type; positive name kept, negative until `h`
  moved, `{err}` reported once as FAULT and never cached; timeout close at
  5000 ms and redial only after 250 ms with empty state; malformed (registry
  status 3, missing key), unsolicited and over-FRAME_MAX answers close; a
  reply on the wire past its deadline is refused; a snapshot is aged from
  its request (reply at 3000 to a request at 1000 is fresh until 6000); an
  unread name fault blocks further name requests — until it is 1000 ms
  (`NODUS_DHT2_WVIEW_FAULT_KEEP_MS`) old: then it is dropped, the next
  writer's request goes out, and the dropped fp is asked afresh (PENDING),
  never answered FAULT or UNNAMED (`test_c_fault_abandoned`, package 6a);
  a header declaring more
  than the cap closes with no payload sent (client: FRAME_MAX, witness:
  CTL_FRAME_MAX).
- **Requires** (`:67-69`): a default build; no environment, no network, no
  ports; `mkdtemp` directories under `/tmp` (unix sockets only). Safe under
  `ctest -j`.
- **Leaves behind** (`:71-73`): nothing — sockets closed and unlinked,
  directories removed, heap fixtures freed.
- **Can lie** (`:75-88`): (1) the witness FILL functions
  (`nodus_witness_dht_*_fill`: tip meta, `nodus_witness_storage_set_get`,
  the registry SQL, the `v2_names` lookup) are NOT exercised — test
  handlers stand in; the wire and the client are proven, not the chain
  reads; (2) expected frames are hand-built by the encoder's author —
  self-consistent, not an independent oracle; (3) "no further request"
  checks are absences after a fixed number of poll rounds, each backed by a
  positive check in the same case; (4) time is whatever the test passes —
  it does not prove the later caller (package 6) passes a monotonic clock.

### 9.4 `test_dht2_store` (package 5)

`nodus/tests/test_dht2_store.c` (ctest `test_dht2_store`,
`nodus/CMakeLists.txt:2100-2107`, linked `nodus dsa nodus crypto`). Thirteen
sections run from `main` (`test_dht2_store.c:1891-1903`): `test_codes`,
`test_select`, `test_quota`, `test_inbox`, `test_expiry`, `test_index`,
`test_faults`, `test_gate`, `test_mismatch`, `test_memo`,
`test_select_pool`, and — added with package 6a — `test_list_ctl_budget`
and `test_put_address` (defined `:413-1848`). 267 source lines match `CHECK(`,
the macro's own `#define` (`:124`) included. The ORCHESTRATOR's runs before
the rebase, at `2f0478bcf` (before package 6a, eleven sections):
`test_dht2_store` 500 passed / 0 failed, three runs; build 0 warnings;
`test_dht2_codec` 433 / 0, `test_dht2_msg` 335 / 0, `test_dht2_ipc` 23 / 0
— counts from those runs, not re-run for this
reference. (`test_memo`, despite its name, asserts the opposite of a holder
memo — e.g. "and nothing remembers v1: the holder follows the selected
record", "control expired: it no longer applies (no memo)", and the
v2-before-v1 case "E is gone on C and still held on D".)

- **Proves** (file header `:9-66`): `put` answers the row-7 code of the
  FIRST failing check in §4.1's order — no snapshot / no sets 15; size 1;
  undecodable 2; chain 3; expected address 4; not-holder 5 (before class
  rules); class 6 (before expiry and signature); the name fault 16 (before
  expiry); expired 7 / too-long 8 by the writer's name status, edges exact;
  signature 9; the name callback is asked exactly once per admission that
  reaches it and a FAULT is never "no name"; Select (an equal write — also one
  with an unknown field the canonical form drops — acknowledged again, the
  stored bytes canonical; a losing write returns the winner's hash, stores
  nothing and costs 0 even with the quota full; A / B in opposite orders end
  with the same bytes); quota new − old at the exact limit, a tombstone
  refunds, the node pools refuse with 13 and are independent; inbox pools 80
  / 20 (11 when full), no second slot on update, pool move on gaining a name;
  a control record only from the recipient (6 otherwise), its HANDLED /
  DENIED drops free slots at once, then DENIED → 12 and HANDLED →
  `[18, through]`, a Sequence above the cutoff admitted again; LIST pages
  (ascending fp, exclusive cursor, ≤ 16, `complete`, `r.v`, the control hash,
  no expired entry); get never serves past expiry; sweep at expiry + 10,799 s
  nothing, + 10,800 s gone, a no-expiry record never swept; re-indexing,
  scan ≤ 250 from `s`, empty interval → top, equal / losing writes do not
  move the counter, top / g / the hand-over flag persist across reopen and
  the flag survives replacement; every call 15 in block sync or with an
  unrepresentable tip time, 16 for another chain (and open refuses that
  store); a failed bind is 16, never "not held"; an index above INT64_MAX is
  never handed out, a counter behind the records refuses open;
  ValidityType ⇔ Validity is 6 after the chain check (3); admission follows
  the SELECTED live control record only; a losing and a quota-refused control
  record leave entries, counter and bytes unchanged; v2 (writer unlisted)
  before v1 keeps the entry on that store (documented, accepted); a control
  record that frees space is accepted at a full pool (one that frees nothing
  is not); an expired held row is replaced by a fresh lower Sequence; a
  tombstone is never refused by the pool of a writer who gained a name; a
  SQLite fault is 16 on every call. The two package-6a sections are NOT in
  the file header's list; their own comments state them:
  `test_put_address` (`:1731-1771`) — a refusal AFTER the parse (an expired
  record, 7) keeps the envelope's address in `res`, a success carries it too,
  a parse failure (2) has none; `test_list_ctl_budget` (`:1773-1848`) — eight
  262,000-byte entries (2,096,000 B) fit the 2 MiB page alone but not beside
  a live control record: the first page lists 7 and is not `complete`, the
  next lists the eighth and is.
- **Requires** (`:67-77`): a default build — no compile flags, no
  environment variables, no network, no clock. Fixed-seed keys
  (`qgp_dsa87_keypair_derand`), hedged signing, so no signature byte is
  pinned; chain time injected (`T0` = 1792368000, 2026-10-19T00:00:00Z,
  `:130`). The one random value is the store generation `g`, only compared
  with itself across a reopen. Safe under `ctest -j` (own `mkdtemp` dir).
- **Leaves behind** (`:78-80`): nothing on success; a crash mid-run leaves
  `/tmp/test_dht2_store_XXXXXX`.
- **Can lie** (`:82-97`): (1) the context is injected — the real
  `nodus_dht2_wview` answers are not exercised, so a mis-mapping of
  PENDING / UNAVAILABLE name answers in the later serving layer is not
  covered; (2) the holder sets are tiny (3 members; 5 for the not-holder
  case); (3) the forced SQLite faults come through the store's own handle
  (`PRAGMA query_only`, `DROP TABLE`), not a real I/O error mid-scan; (4) the
  3 h slack and the class maxima are constants written by the code's author;
  (5) nothing runs concurrently.

### 9.5 `test_dht2_holder` (package 6a)

`nodus/tests/test_dht2_holder.c` (ctest `test_dht2_holder`,
`nodus/CMakeLists.txt:2109-2116`, linked `nodus dsa nodus crypto`). Eleven
sections run from `main` (`test_dht2_holder.c:1113`, calls `:1142-1152`):
`test_get_put`, `test_malformed`, `test_list`, `test_call_level`,
`test_write_precondition`, `test_name_fault`, `test_fault_abandoned`,
`test_chain_gate`, `test_ctl_get`, `test_oversize_put`,
`test_late_refusal` (defined `:477-1095`). 160 source lines match `CHECK(`,
the macro's own `#define` (`:100`) included. Five fixed-seed keys: the
node, a writer, an inbox owner, an inbox writer, a stranger (`:1139-1140`).
The view is a fake (`fv_t`, `:141-160`) whose name callback copies the real
view's single fault slot, including the `NODUS_DHT2_WVIEW_FAULT_KEEP_MS`
drop (`:192-195`). No run of this test is cited here: nothing was built or
run for this reference.

- **Proves** (file header `:8-47`): every answer is ONE RFC 0002 envelope
  signed by the node identity — it opens under its kind's payload type
  (`/nodus/dht/answer/v1` for get and LIST, `/nodus/dht/receipt/v1` for put,
  `/nodus/dht/refusal/v1` for a refusal), verifies under
  `nodus.dht.answer.v1` and NOT under another domain, carries the node's
  fp, and its payload says `q` = the request's nonce, `n` = the node's fp,
  `c` = the chain, `h` / `t` = the snapshot's (none in a refusal); get: a
  held key answers its hash, an unheld key null, in request order; put: the
  receipt names the stored hash (the same a later get returns), an
  undecodable envelope is code 2 with an all-zero key, a receipt never
  carries null; a malformed request gets NO answer (bytes that are not a
  request, a truncated request, a get sent as put and the reverse, a LIST
  envelope that does not decode); LIST: the owner's request lists the
  entries (`w`, `d`, `r.v` = SHA3-512 of the listed hashes, `q` = the
  request nonce), a request signed by another key for that inbox is
  `r.v` = 17 with nothing listed, a LIST of another chain and one with a
  flipped payload byte get no answer; `consensus_up` false and no snapshot
  answer the refusal 15 for get, put and list; a full signing queue (64)
  answers the refusal 14, and a slot given back lets the next call through;
  with |S(H)| = 1 a put is refused with `NODUS_DHT2_HOLDER_WRITE_REFUSAL`
  (15) and stores nothing while a get on the same view is answered, with
  |S(H)| = 3 the same put is stored; a name FAULT is code 16 for that key
  (nothing stored), asked once, and the next name request is possible (the
  same put then succeeds); a PENDING name answer is also 16, never
  "unnamed"; an ABANDONED name fault blocks another writer only until one
  poll period has passed; a snapshot of another chain is the refusal 15 (no
  `h` / `t`) for get, put, owner LIST and not-owner LIST alike; a GET of a
  held inbox-control record is per-key 17; an envelope above 262,144 B
  inside a put is per-key 1 with a zero key while its sibling is stored
  under its address. `test_late_refusal` (second fix round, its comment
  `:1009-1011`; not in the header list): in one receipt an expired record
  is `{k: its address, v: 7}`, an inbox entry under a HANDLED cutoff is
  `{k: its address, v: [18, 5]}`, and 10 bytes of `0xFF` are
  `{k: 64 zero bytes, v: 2}`.
- **Requires** (`:48-54`): a default build — no compile flags, no
  environment variables, no network, no clock. Fixed-seed keys
  (`qgp_dsa87_keypair_derand`); signing is hedged, so signatures are
  verified, never compared to a constant. Chain time injected (`T0` =
  1792368000, 2026-10-19T00:00:00Z, `:106`). Safe under `ctest -j` (own
  `mkdtemp` directory).
- **Leaves behind** (`:55-58`): nothing on success — the temp directory and
  its `.db` files are removed; a crash mid-run leaves
  `/tmp/test_dht2_holder_XXXXXX`.
- **Can lie** (`:59-75`): (1) the view is injected —
  `nodus_dht2_holder_view_wview` (the three trampolines onto the package-4
  view) is not exercised; the PENDING / FAULT fakes follow the view's
  documented behaviour, they are not the view; (2) the holder sets are
  tiny (1 or 3 members), so with ≤ 4 members every member is eligible for
  every key and eligibility is not exercised here; (3) answers are checked
  structurally and by signature — whether a CLIENT accepts them (§4.4 client
  rules) is package 8's; (4) hedged signatures differ run to run, the test
  never depends on two answers being byte-equal; (5) "write precondition =
  refusal 15" is the ORCHESTRATOR's reading, pinned by the test, so the test
  cannot detect that the operator later chooses another code.

---

## 10. Wire messages (`shared/dht2/dht2_msg.h`) — package 2

Design rev 5 §4.4, §4.5, §13 rows 7 (results), 11 (sizes), 12 (pull-sync),
14 (requests), 15 (inbox control), 18 (answer payloads); decision
`2026-10-23-dht-v2-wire-gaps-package2.md` (`dht2_msg.h:7-14`; its four
items are cited below as "decision 1-4": 1 strict text-key maps, no `op` /
`n` in pull messages; 2 read-repair = "put"; 3 the pull-receipt keys; 4
`req_cursor` absent on a first page). Every
message is ONE strict DAG-CBOR map, keys in the one canonical order
(length first, then bytewise), decoded with the strict reader of §3 and
then RE-ENCODED and compared byte for byte; counts are bounded BEFORE
iteration (`:16-23`). Each message has one `*_emit` (the one emission path
for WRITE / COUNT / COMPARE) and one `*_parse` that matches the keys in
canonical order against fixed literals, so an unknown, missing, repeated
or unsorted key fails (`dht2_msg.c:6-12`).

**Common behaviour of every `*_encode`** (`dht2_msg.c` `encode_with`,
`:111-132`; `dht2_msg.h:32-36`): `out` may be NULL — then only `*out_len`
(the exact size) is produced; NULL message or NULL `out_len`, or `cap`
smaller than the size → `DHT2_E_ARG`; content the matching decoder would
refuse → the same code that decoder returns, so nothing is emitted that
cannot be read back. **Every `*_decode`** (`decode_with`, `:135-154`):
NULL struct, or NULL `in` with `len` ≠ 0 → `DHT2_E_ARG`; the struct is
zeroed at entry; parse, require every byte consumed, re-emit in COMPARE
mode; any fault → the message's code (below).

**Error codes — a READING** (`dht2_msg.h:25-31`; row 7 names none for
these): requests (get / put) → `DHT2_E_MALFORMED_REQ` (row 7 "Malformed
request … a tier-2 protocol error, no signed answer"); answer / receipt /
refusal payloads, pull messages, control `_data` → `DHT2_E_BAD_ENCODING`;
a NULL argument / too-small buffer → `DHT2_E_ARG`.

### 10.1 Row 7: the per-key result

| Item | Description |
|------|-------------|
| `typedef enum { DHT2_RV_HASH = 0, DHT2_RV_NULL, DHT2_RV_CODE, DHT2_RV_HANDLED } dht2_rv_kind_t;` (`:64-69`) | What `v` is: a 64-byte bstr / `null` (not held) / a uint code / the array `[18, through]`. |
| `typedef enum { DHT2_RCTX_READ = 0, DHT2_RCTX_WRITE, DHT2_RCTX_LIST } dht2_rctx_t;` (`:73-77`) | Which message carries it: read answer (hash, null, code, `[18, through]`); write receipt (as read, NEVER null — row 7 "NEVER a PUT result"); LIST answer's single element (hash or code 17 only — row 18). Internal to the codec: chosen by which encode / decode function is called. |
| `typedef struct { uint8_t key[DHT2_HASH_LEN]; dht2_rv_kind_t kind; uint8_t hash[DHT2_HASH_LEN]; uint64_t code; uint64_t through; } dht2_result_t;` (`:79-85`) | One `{k, v}` element: `key` = `k`; `hash` for `DHT2_RV_HASH`, `code` for `DHT2_RV_CODE`, `through` for `DHT2_RV_HANDLED`. |

Wire form: `{k: bstr 64, v: …}`, keys `k`, `v` (`dht2_msg.c:183-210`). A
valid code is 1…13, 16 or 17 (`code_valid`, `:162-165`): 0 is not a wire
code, 14 / 15 are call-level (a refusal), and 18 only appears as
`[18, through]` — a bare 18 is refused. `[18, through]` must be an array of
exactly 2 uints whose first is 18 (`:240-246`). The `v` type is chosen with
`dht2_cbor_rd_peek_mt` / `_peek_null` (`:224-249`). These codes are DATA
the message carries; the codec never returns them.

### 10.2 Row 14: get / put requests

| Item | Description |
|------|-------------|
| `typedef enum { DHT2_REQ_GET = 0, DHT2_REQ_PUT } dht2_req_kind_t;` (`:89-92`) | `{n, op "get", keys [bstr 64] ≤ 8}` / `{n, op "put", envs [bstr] ≤ 8}`. Read-repair is `op` "put" (decision 2). The LIST request is NOT here — it is package 1's owner-signed envelope (§6.2). |
| `typedef struct { dht2_req_kind_t kind; uint8_t nonce[DHT2_NONCE_LEN]; size_t count; uint8_t keys[DHT2_REQ_KEYS_MAX][DHT2_HASH_LEN]; const uint8_t *envs[DHT2_REQ_KEYS_MAX]; size_t env_lens[DHT2_REQ_KEYS_MAX]; } dht2_req_t;` (`:94-101`) | `nonce` = `n`; `count` ≤ 8; `keys` for GET (copied); `envs` / `env_lens` for PUT (pointers INTO the input; since package 6a the SUM of `env_lens` ≤ `DHT2_REQ_BUDGET`, a single envelope may exceed 262,144 B — `:100`). |
| `#define DHT2_REQ_BUDGET (DHT2_REQ_KEYS_MAX * DHT2_ENVELOPE_MAX)` (`:109`) | Row 11: the record budget of one call, 8 × 262,144 = 2,097,152 B. (Defined in `dht2_msg.h`, not in `dht2_types.h`.) |
| `#define DHT2_REQ_MAX_LEN (DHT2_REQ_BUDGET + 128u)` (`:110`) | The largest request: the budget plus the map, nonce, `op` and 8 byte-string heads — "at most 90 B; 128 taken" (`:103-108`) — 2,097,280 B. |
| `int dht2_req_encode(const dht2_req_t *req, uint8_t *out, size_t cap, size_t *out_len)` (`:115-116`) | Canonical bytes, key order `n, op, keys` / `n, op, envs` (`dht2_msg.c:261-307`). `DHT2_OK`; `DHT2_E_MALFORMED_REQ` (count > 8, an unknown `kind`, a NULL env with a non-zero length, the envelopes' total above `DHT2_REQ_BUDGET` — checked with a running total that cannot overflow, `:271-286`); `DHT2_E_ARG`. One envelope longer than `DHT2_ENVELOPE_MAX` is encodable (package 6a; before it, it was `DHT2_E_MALFORMED_REQ`). |
| `int dht2_req_decode(const uint8_t *in, size_t len, dht2_req_t *req)` (`:121`) | First, BEFORE any parse: `len` > `DHT2_REQ_MAX_LEN` → `DHT2_E_MALFORMED_REQ` (`DHT2_E_ARG` if `req` is NULL) (`dht2_msg.c:357-362`). Then strict decode + re-encode check. `DHT2_E_MALFORMED_REQ` for every fault: nonce ≠ 32 B, more than 8 keys / envs, a key ≠ 64 B, an `op` other than "get" / "put", a `keys` with "put" or `envs` with "get", any strict-CBOR fault, a trailing byte, the envelopes' total above `DHT2_REQ_BUDGET` (refused by the re-encode, which runs `req_emit`'s budget check). `DHT2_E_ARG` (NULL). An envelope above 262,144 B is NOT malformed (since package 6a — row 7's malformed list does not name it, `:103-108`): the request decodes and the holder answers that key with code 1 (§13.4). The envelopes inside `envs` are NOT parsed here — each is a record for §4.1 admission. |

### 10.3 Row 18: read answer, write receipt, LIST answer

| Item | Description |
|------|-------------|
| `typedef struct { uint8_t q[DHT2_NONCE_LEN]; uint8_t n[DHT2_FP_LEN]; uint8_t c[DHT2_CHAIN_LEN]; uint64_t h; uint64_t t; size_t r_count; dht2_result_t r[DHT2_REQ_KEYS_MAX]; } dht2_answer_t;` (`:127-135`) | Read answer (`/nodus/dht/answer/v1`) and write receipt (`/nodus/dht/receipt/v1`) share one shape: `q` the request's nonce, `n` the holder fp, `c` the chain id, `h` the committed height, `t` the tip block time in seconds, `r` ≤ 8 results. Key order `c, h, n, q, r, t` (`dht2_msg.c:370-402`). |
| `int dht2_answer_encode(const dht2_answer_t *a, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_answer_decode(const uint8_t *in, size_t len, dht2_answer_t *a)` (`:138-140`) | Read answer; `v` may be null. `DHT2_OK`; `DHT2_E_BAD_ENCODING` (`r` > 8, a `v` invalid for a read answer, a field of the wrong length, any strict fault); `DHT2_E_ARG`. |
| `int dht2_receipt_encode(const dht2_answer_t *a, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_receipt_decode(const uint8_t *in, size_t len, dht2_answer_t *a)` (`:143-145`) | Write receipt; as the read answer except that `v` is NEVER null (row 7). Same codes. |
| `typedef struct { uint8_t w[DHT2_FP_LEN]; uint8_t d[DHT2_HASH_LEN]; } dht2_list_entry_t;` (`:147-150`) | One LIST entry `{d, w}`: writer fp and entry hash. |
| `typedef struct { uint8_t q[DHT2_NONCE_LEN]; uint8_t n[DHT2_FP_LEN]; uint8_t c[DHT2_CHAIN_LEN]; uint64_t h; uint64_t t; dht2_result_t r; bool has_ctl; uint8_t ctl[DHT2_HASH_LEN]; size_t list_count; dht2_list_entry_t list[DHT2_LIST_PAGE_MAX]; bool has_cursor; uint8_t cursor[DHT2_FP_LEN]; bool complete; bool has_req_cursor; uint8_t req_cursor[DHT2_FP_LEN]; } dht2_list_answer_t;` (`:157-173`) | LIST answer (`/nodus/dht/answer/v1`): the read answer's keys with `r` = ONE element, plus `ctl` (hash, or null when `has_ctl` is false), `list` ≤ 16, optional `cursor`, `complete`, optional `req_cursor` (absent on a first page — decision 4). Key order `c, h, n, q, r, t, ctl, list, cursor?, complete, req_cursor?` (`dht2_msg.c:487-539`). |
| `int dht2_list_answer_encode(const dht2_list_answer_t *a, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_list_answer_decode(const uint8_t *in, size_t len, dht2_list_answer_t *a)` (`:175-178`) | `DHT2_OK`; `DHT2_E_BAD_ENCODING` when any rule below fails or on a strict fault; `DHT2_E_ARG`. |

LIST rules enforced by both directions (`list_rules_ok`,
`dht2_msg.c:459-485`; row 11, §4.4, decision 4 — "exactly these rules,
nothing more"): `list` ≤ 16; `r` is a hash or code 17 (§10.1); `w`
strictly ascending (equal `w` refused); an EMPTY page must be
`complete` = true with no `cursor`; a `cursor`, when present, equals the
last `w` listed (EXCLUSIVE cursor, row 11); a `req_cursor`, when present,
must be strictly below the first `w` listed (the page starts strictly after
the request's cursor, row 11). Not enforced (the test header's "silent"
list): whether a non-empty `complete` page may also carry a `cursor`, which
fields accompany code 17, and that `v` equals the SHA3-512 over the listed
entry hashes (row 18) — the codec only checks it is 64 bytes.

### 10.4 Row 18: refusal, and the answer envelope

| Item | Description |
|------|-------------|
| `typedef struct { uint8_t q[DHT2_NONCE_LEN]; uint8_t n[DHT2_FP_LEN]; uint8_t c[DHT2_CHAIN_LEN]; uint64_t e; } dht2_refusal_t;` (`:182-187`) | Refusal (`/nodus/dht/refusal/v1`) `{c, e, n, q}` — `e` ∈ {14 `busy`, 15 `not-caught-up`}, and NO `h` / `t` (row 7: a refusal never counts as a time sample or a receipt). Key order `c, e, n, q` (`dht2_msg.c:632-650`). |
| `int dht2_refusal_encode(const dht2_refusal_t *m, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_refusal_decode(const uint8_t *in, size_t len, dht2_refusal_t *m)` (`:189-191`) | `DHT2_OK`; `DHT2_E_BAD_ENCODING` (`e` ∉ {14, 15}, a strict fault); `DHT2_E_ARG`. |
| `int dht2_answer_seal(const char *payload_type, const uint8_t *payload, size_t payload_len, const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out, size_t cap, size_t *out_len)` (`:197-200`) | §4.4: seal an answer / receipt / refusal payload — `dht2_env_seal` with domain = ctx `nodus.dht.answer.v1` (all three share it) and `payload_type` = `DHT2_PT_ANSWER` / `_RECEIPT` / `_REFUSAL` (C string; no NUL on the wire). `out` NULL → size only. Any other payload type (e.g. `/nodus/dht/list/v1`) → `DHT2_E_ARG` (`dht2_msg.c:687-706`); otherwise returns as `dht2_env_seal`. Does not decode or check the payload. |
| `int dht2_answer_open(const uint8_t *in, size_t len, const char *payload_type, dht2_env_t *env)` (`:208-209`) | Decode an answer envelope (≤ `DHT2_ENVELOPE_MAX`), require its payload type = `payload_type`, verify under `nodus.dht.answer.v1`. `DHT2_OK` (then `env` points into `in`); `DHT2_E_TOO_LARGE`; `DHT2_E_BAD_ENCODING` (decode fault, or another payload type); `DHT2_E_BAD_SIGNATURE`; `DHT2_E_HOLDER_FAULT`; `DHT2_E_ARG` (NULL `env`, or `payload_type` not answer / receipt / refusal). The §4.4 client rules — fp = `n`, `q` = the request's nonce, `c`, eligibility — come AFTER, in the caller; the payload is then decoded with the matching `*_decode`. |

### 10.5 Row 12: pull-sync messages

Per decision 1 the pull messages carry no `op` and no `n` (the tier-3
method name `dht2_pull_*` names the message, one exchange in flight per
pair).

| Item | Description |
|------|-------------|
| `typedef struct { uint64_t g; uint64_t top; } dht2_p_hello_t;` (`:213-216`) | `p_hello` `{g, top}`: store generation, global high-water mark. |
| `typedef struct { uint64_t g; uint64_t s; } dht2_p_get_t;` (`:218-221`) | `p_get` `{g, s}`: `s` = first insertion index wanted. |
| `typedef struct { uint8_t a[DHT2_HASH_LEN]; uint8_t h[DHT2_HASH_LEN]; uint8_t p[DHT2_HASH_LEN]; } dht2_offer_entry_t;` (`:223-227`) | Offer entry `{a, h, p}`: address, envelope hash, placement-key hint. |
| `typedef struct { uint64_t g; uint64_t top; size_t e_count; dht2_offer_entry_t e[DHT2_PULL_PAGE_MAX]; } dht2_p_offer_t;` (`:229-234`) | `p_offer` `{e, g, top}`, `e` ≤ 250. ~47 KB — the header says to keep it off small stacks (`:234`). |
| `typedef struct { const uint8_t *b; size_t b_len; } dht2_p_want_t;` (`:236-239`) | `p_want` `{b}`: `b` points into the input, `b_len` = ⌈n/8⌉. |
| `typedef struct { uint64_t i; bool has_v; const uint8_t *v; size_t v_len; } dht2_p_deliver_t;` (`:244-249`) | `p_deliver` `{i, v}`: `i` = the offer index; `v` = the canonical envelope (into the input, ≤ 262,144 B) or null (`has_v` false — gone). |
| `typedef struct { uint8_t a[DHT2_HASH_LEN]; uint8_t h[DHT2_HASH_LEN]; } dht2_receipt_entry_t;` (`:251-254`) | Pull-receipt entry `{a, h}`. |
| `typedef struct { uint8_t pf[DHT2_FP_LEN]; uint8_t sf[DHT2_FP_LEN]; uint8_t c[DHT2_CHAIN_LEN]; uint64_t g; uint64_t s; uint64_t top; size_t e_count; dht2_receipt_entry_t e[DHT2_PULL_PAGE_MAX]; } dht2_pull_receipt_t;` (`:258-267`) | Pull-receipt PAYLOAD (decision 3: `pf` puller fp, `sf` source fp, `c`, `g`, `s`, `top`, `e: [{a, h}]` ≤ 250); ~32 KB. Its envelope domain is NOT decided — nothing here seals or opens it (`:256-257`). |
| `int dht2_p_hello_encode(const dht2_p_hello_t *m, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_p_hello_decode(const uint8_t *in, size_t len, dht2_p_hello_t *m)` (`:269-271`) | Key order `g, top`. Encode returns only `DHT2_OK` / `DHT2_E_ARG`; decode `DHT2_OK` / `DHT2_E_BAD_ENCODING` / `DHT2_E_ARG`. |
| `int dht2_p_get_encode(const dht2_p_get_t *m, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_p_get_decode(const uint8_t *in, size_t len, dht2_p_get_t *m)` (`:272-274`) | Key order `g, s`. Codes as `p_hello`. |
| `int dht2_p_offer_encode(const dht2_p_offer_t *m, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_p_offer_decode(const uint8_t *in, size_t len, dht2_p_offer_t *m)` (`:275-277`) | Key order `e, g, top`; entry keys `a, h, p`, each 64 B. `DHT2_E_BAD_ENCODING` (`e` > 250, a field ≠ 64 B, a strict fault). Entry order is not checked (the test header lists it as untested). |
| `int dht2_p_want_encode(const dht2_p_want_t *m, size_t n, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_p_want_decode(const uint8_t *in, size_t len, size_t n, dht2_p_want_t *m)` (`:282-285`) | `n` = the offer's entry count, passed by the caller. `b` must be EXACTLY ⌈n/8⌉ bytes with every bit ≥ n zero, and n ≤ 250; anything else → `DHT2_E_BAD_ENCODING` (the exchange aborts, row 12) (`want_valid`, `dht2_msg.c:901-910`). A NULL `b` with a non-zero `b_len` on encode → `DHT2_E_BAD_ENCODING`. |
| `int dht2_p_deliver_encode(const dht2_p_deliver_t *m, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_p_deliver_decode(const uint8_t *in, size_t len, dht2_p_deliver_t *m)` (`:287-289`) | Key order `i, v`. `DHT2_E_BAD_ENCODING` (`i` ≥ 250, `v` > 262,144 B, on encode a NULL `v` with a non-zero length, a strict fault). The codec refuses `i` ≥ 250; `i` < the actual offer's entry count is the exchange code's check (package 7) (`:241-243`). `v` is not parsed. |
| `int dht2_pull_receipt_encode(const dht2_pull_receipt_t *m, uint8_t *out, size_t cap, size_t *out_len)`, `int dht2_pull_receipt_decode(const uint8_t *in, size_t len, dht2_pull_receipt_t *m)` (`:291-294`) | Key order `c, e, g, s, pf, sf, top` (length first: the one-letter keys, then `pf`, `sf`, `top`); entry keys `a, h`. `DHT2_E_BAD_ENCODING` (`e` > 250, a wrong field length, a strict fault). |
| `size_t dht2_bits_len(size_t n)` (`:299`) | ⌈n/8⌉, computed as `n / 8 + (n % 8 != 0)` (no overflow). |
| `bool dht2_bits_get(const uint8_t *b, size_t i)`, `void dht2_bits_set(uint8_t *b, size_t i)` (`:300-301`) | Bit i = byte ⌊i/8⌋, mask `1 << (i mod 8)` — LSB-first (Bee `bitvector.go`: Get :55-57, Set :61-65). NO bounds check: the caller holds ⌈n/8⌉ bytes and i < n (`:296-298`). |

### 10.6 Row 15: inbox control `_data`

The control record's `_data` (class 5) is a byte string of entries
`fp 64 ‖ mark 1 ‖ through 8 (u64 BE)`, strictly ascending by fp, mark 1
HANDLED / 2 DENIED, ≤ 3,500 entries.

| Item | Description |
|------|-------------|
| `typedef struct { uint8_t fp[DHT2_FP_LEN]; uint8_t mark; uint64_t through; } dht2_ctl_entry_t;` (`:305-309`) | One entry; `mark` = `DHT2_CTL_HANDLED` / `DHT2_CTL_DENIED`; `through` is u64 BE on the wire. |
| `int dht2_ctl_encode(const dht2_ctl_entry_t *e, size_t count, uint8_t *out, size_t cap, size_t *out_len)` (`:314-315`) | Write `count` entries (73 B each). `out` NULL → size only. `DHT2_OK`; `DHT2_E_BAD_ENCODING` (count > 3,500, a mark ∉ {1, 2}, fps not strictly ascending); `DHT2_E_ARG` (NULL `e` with `count` ≠ 0, NULL `out_len`, `cap` too small). |
| `int dht2_ctl_check(const uint8_t *data, size_t len, size_t *count)` (`:320`) | Validate: `len` a multiple of 73, ≤ 3,500 entries, marks 1 / 2, strictly ascending by fp. `DHT2_OK` (then `*count` = entries; `count` may be NULL, `dht2_msg.c:1176`); `DHT2_E_BAD_ENCODING`; `DHT2_E_ARG` (NULL `data` with `len` ≠ 0). |
| `int dht2_ctl_at(const uint8_t *data, size_t len, size_t idx, dht2_ctl_entry_t *out)` (`:324-325`) | Entry `idx` of data that `dht2_ctl_check` ALREADY accepted — it does NOT re-validate. `DHT2_OK`; `DHT2_E_ARG` (NULL, or `idx` ≥ `len / 73`). |
| `int dht2_ctl_lookup(const uint8_t *data, size_t len, const uint8_t fp[DHT2_FP_LEN], bool *found, dht2_ctl_entry_t *out)` (`:330-332`) | Runs `dht2_ctl_check` first, then a binary search by fp (`dht2_msg.c:1199-1235`). `DHT2_OK` with `*found` set (and `out` filled when found; `out` may be NULL); `DHT2_E_BAD_ENCODING` (invalid data); `DHT2_E_ARG` (NULL `fp` / `found`). |

Package 1's class-5 record check (`dht2_record_check_class`, §5) applies the
same shape rules through `dht2_record.c`'s own private constants
(`:31-32`); it does not call these functions.

### 10.7 Readings and what is NOT here

Readings this package makes where the design names no answer (labelled as
readings in `dht2_msg.h:25-31` and `test_dht2_msg.c:57-73`, not design
facts): requests → `DHT2_E_MALFORMED_REQ`, every other message →
`DHT2_E_BAD_ENCODING`; a LIST answer's `r` is a hash or code 17 only
(row 18 "v = the SHA3-512 … or 17"); `[18, through]` is accepted in a READ
answer as well as in a receipt — row 7 is silent on it there; `through` has
no range check. Since package 6a (`dht2_msg.h:103-108`): an envelope above
262,144 B inside a put is NOT a malformed request, because row 7's malformed
list (nonce, key count, key length, operation, cursor) does not name it; it
is the per-key `too-large` (1) the holder answers. The whole request is
bounded at row 11's budget (`DHT2_REQ_BUDGET`, `DHT2_REQ_MAX_LEN`).

NOT here (`dht2_msg.h:39-42`): the LIST request (package 1, §6.2); the
pull-receipt's envelope domain / FIPS 204 ctx — NOT decided (decision
`2026-10-23-dht-v2-wire-gaps-package2.md` "Still open": asked before
package 7), so nothing seals or opens a pull-receipt; the PeerRecord /
address announcement — moved to the endpoint package (package 6), because
rev 5 sets its size bounds there; admission (package 5, §12), the holder
service (package 6a, §13) and client logic; no caller in a node or a client.

---

## 11. The storage side's view of the witness (`nodus/src/dht/nodus_dht2_wview.h`) — package 4

Design rev 5 §2, §6 "Name check", §13 row 13; package plan
`docs/plans/2026-10-23-dht-v2-package-plan.md` package 4 and §5 (LOCAL-only).
The `nodus-storage` side of the `ipc_dht` connection kind of
`<data_path>/witness.sock`: it dials the socket (same euid,
`NODUS_TCP_UNIX_UID_SELF`), sends `{"q":"ipc_dht"}`, and keeps the snapshot,
the frozen sets and name answers (`nodus_dht2_wview.h:1-46`). The wire and
the witness side — `nodus_witness_dht_snap_t` / `_sets_t` / `_name_t`,
`NODUS_WITNESS_IPC_DHT_FRAME_MAX`, the fill functions — are
`messenger/docs/functions/ledger.md` §19; the narrative is
`nodus/docs/ARCHITECTURE.md` §10 "The `ipc_dht` kind (DHT v2 package 4)".

**NO CALLER YET** (`nodus_dht2_wview.h:41-43`: "the package-5 holder store
takes an injected context (nodus_dht2_store.h); filling it from this view is
package 6. Nothing in nodus/tools/ or any running loop calls it today").
Package 6a's holder service (§13) binds it — `nodus_dht2_holder_view_wview`
puts three trampolines onto `nodus_dht2_wview_snap` / `_sets` / `_name`
(`nodus_dht2_holder.c:28-55`) — but nothing calls the holder service either,
and no test runs that binding (`test_dht2_holder.c` "HOW IT CAN LIE" 1).
Today only `nodus/tests/test_dht2_ipc.c` calls the view.

**Time.** Nothing here reads a clock. Every call that can act on time takes
`now_ms`, a caller-supplied MONOTONIC millisecond count (the caller's own
tick clock); it only schedules this node's own polling and ages its own
cache — never a consensus input. All state is a function of the answers
received and the `now_ms` values passed in (`:31-35`).

**Transport.** It owns its own `nodus_tcp_t` and one connection, polled
with a 0 ms wait from `nodus_dht2_wview_tick` (`nodus_dht2_wview.c:5-6`).
The header says nothing about threads; no lock is taken anywhere in the
file.

| Item | Description |
|------|-------------|
| `NODUS_DHT2_WVIEW_SNAP_EVERY_MS` 1000, `NODUS_DHT2_WVIEW_SNAP_STALE_MS` 5000 (`:61-62`) | Row 13: the snapshot is asked once per second; an answer older than 5 s — counted from the tick that SENT its request — is no snapshot (the caller then refuses writes with `not-caught-up`). |
| `NODUS_DHT2_WVIEW_REQ_TIMEOUT_MS` 5000 (`:63`) | A request unanswered this long closes the connection. |
| `NODUS_DHT2_WVIEW_DIAL_BACKOFF_MIN_MS` 250, `NODUS_DHT2_WVIEW_DIAL_BACKOFF_MAX_MS` 5000 (`:64-65`) | A failed dial waits the current backoff, which then doubles up to the max; a successful dial resets it to the min (`nodus_dht2_wview.c:419-434`). |
| `NODUS_DHT2_WVIEW_NAME_CACHE_MAX` 1024 (`:66`) | Name cache slots. A new answer takes its own slot, else a free one, else the first negative, else round-robin (`nodus_dht2_wview.c:274-295`) — deterministic in the order of answers. |
| `#define NODUS_DHT2_WVIEW_FAULT_KEEP_MS NODUS_DHT2_WVIEW_SNAP_EVERY_MS` (`:68`, package 6a) | 1000 ms: "an unread name fault is dropped after one snapshot poll period" (`:67`). The tick that read the `{err}` is recorded (`fault_at_ms`, `nodus_dht2_wview.c:68`, set at `:313`); see `nodus_dht2_wview_name` below. |
| `typedef struct nodus_dht2_wview nodus_dht2_wview_t;` (`:70`) | Opaque. Holds the socket path, the connection, the snapshot, two heap sets structs (live + decode stage, swapped on a good answer) and the name cache. |
| `typedef enum { NODUS_DHT2_WVIEW_NAME_PENDING = 0, NODUS_DHT2_WVIEW_NAME_NAMED, NODUS_DHT2_WVIEW_NAME_UNNAMED, NODUS_DHT2_WVIEW_NAME_FAULT, NODUS_DHT2_WVIEW_NAME_UNAVAILABLE } nodus_dht2_wview_name_t;` (`:73-81`) | Result of `nodus_dht2_wview_name`: asked / being asked — call again; the key has a name (permanent); no name as of `*h_out`; the witness answered `{err}` — refuse the admission (`holder-fault`), reported once, then asked afresh (or, since package 6a, dropped unreported after `NODUS_DHT2_WVIEW_FAULT_KEEP_MS` and asked afresh — never reported as UNNAMED); no connection to the witness. |
| `nodus_dht2_wview_t *nodus_dht2_wview_new(const char *sock_path)` (`:86`) | A view of the socket at `sock_path` (copied). Not connected: the first `tick` dials. NULL when `sock_path` is NULL or does not fit `NODUS_TCP_UNIX_PATH_MAX`, on allocation failure, or when `nodus_tcp_init` fails (`nodus_dht2_wview.c:399-417`). |
| `void nodus_dht2_wview_tick(nodus_dht2_wview_t *wv, uint64_t now_ms)` (`:90`) | One pass, in this order (`nodus_dht2_wview.c:447-485`): dial if down and the backoff has passed (on connect: `max_payload` = `NODUS_WITNESS_IPC_DHT_FRAME_MAX`, all state cleared, sets marked wanted, the `ipc_dht` preface sent); close if any outstanding request is ≥ `REQ_TIMEOUT_MS` old — BEFORE the poll, so a late reply is never accepted; poll the socket (0 ms) and decode what arrived; send `ipc_dht_snap` when none is outstanding and `SNAP_EVERY_MS` has passed since the last one (or none was sent on this connection); send `ipc_dht_sets` when wanted, none is outstanding and any `{err}` retry time has passed. A send that cannot be queued closes the connection. NULL `wv` is a no-op. |
| `bool nodus_dht2_wview_snap(const nodus_dht2_wview_t *wv, uint64_t now_ms, nodus_witness_dht_snap_t *out)` (`:94-95`) | `true` and `*out` = the snapshot, or `false` when there is none: NULL argument, not connected, never answered, answered `{err}`, or older than `SNAP_STALE_MS` at `now_ms` (age from its request's send tick; a `now_ms` below that tick counts as fresh — `snap_fresh`, `nodus_dht2_wview.c:86-90`). |
| `const nodus_witness_dht_sets_t *nodus_dht2_wview_sets(const nodus_dht2_wview_t *wv, uint64_t now_ms)` (`:99-100`) | The frozen sets, or NULL unless a fresh snapshot exists AND carries the same `e` as these sets. The pointer is valid until the next tick (a new sets answer swaps the buffers). A snapshot with another `e` makes the next tick request new sets (`nodus_dht2_wview.c:181-182`); a sets `{err}` drops the held sets and delays the next request by `SNAP_EVERY_MS` (`:207-212`). |
| `nodus_dht2_wview_name_t nodus_dht2_wview_name(nodus_dht2_wview_t *wv, uint64_t now_ms, const uint8_t fp[64], uint64_t *h_out)` (`:105-108`) | The name state of `fp` (64 bytes); `*h_out` (may be NULL) = the answer's tip height for NAMED / UNNAMED. Order (`nodus_dht2_wview.c:502-545`): NULL `wv` / `fp` → UNAVAILABLE; FIRST (package 6a, `:507-512`), an unreported `{err}` whose read tick is ≥ `NODUS_DHT2_WVIEW_FAULT_KEEP_MS` before `now_ms` is dropped — "its caller may never come back, and the single slot must not block everyone else" — for ANY `fp`, the faulted one included, which then falls through and is asked afresh (never UNNAMED from the fault; a `now_ms` below the read tick never drops it); an unreported `{err}` for this `fp` → FAULT (once, then cleared); a cached positive → NAMED; a cached negative while a fresh snapshot's `h` ≤ the answer's `h` → UNNAMED; not connected → UNAVAILABLE; a request outstanding, or an `{err}` for another `fp` not yet reported → PENDING without sending; otherwise sends `ipc_name` and returns PENDING (a send that cannot be queued closes the connection → UNAVAILABLE). The caller asks again on a later tick. |
| `bool nodus_dht2_wview_connected(const nodus_dht2_wview_t *wv)` (`:111`) | Whether the socket to the witness is up (`false` for NULL). |
| `void nodus_dht2_wview_free(nodus_dht2_wview_t *wv)` (`:114`) | Close and free. NULL-safe. |

**Answer decoding** (`nodus_dht2_wview.c:115-366`): a map of 2-6 entries, `q`
first; the snap answer exactly `ci` (32 B), `h`, `t`, `cu` (bool), `e`; the
sets answer exactly `e`, `s0`, `s1` (arrays of 64-byte strings, ≤
`DNA_V2_STORAGE_SET_MAX`), `rg` (≤ the cap, each a 2-entry map `f` 64 B and
`st` ∈ {1, 2}); the name answer `fp` (equal to the outstanding request's)
then `h`, `n` ∈ {0, 1} — or the single key `err` (text) after `q` / `fp`;
every key once, no unknown key, no trailing byte. A malformed answer, an
answer with no such request outstanding, or a frame longer than
`NODUS_WITNESS_IPC_DHT_FRAME_MAX` closes the connection (`:370-380`). A close
(any cause) forgets the snapshot, the sets, every outstanding request and an
unreported fault, and schedules the redial after the current backoff
(`:382-395`); the name cache survives a reconnect. An unreported fault
also ends when it reaches `NODUS_DHT2_WVIEW_FAULT_KEEP_MS` (package 6a; see
`nodus_dht2_wview_name` above).

**Not here:** the callers. Package 6a's holder service (§13) fills the
package-5 context from these three calls — "no snapshot" / block sync →
`not-caught-up`; NAMED / UNNAMED → the store's NAMED / UNNAMED; FAULT,
PENDING and UNAVAILABLE → `NODUS_DHT2_NAME_FAULT` → per-key `holder-fault`
(`nodus_dht2_holder.c:107-122`) — but nothing calls the holder service
(package 6b), and `test_dht2_holder` injects a fake view, so the real
binding is untested (§9.5 "Can lie" 1). Anything that writes to the chain is
not here. Test: §9.3.

---

## 12. The holder store and admission (`nodus/src/dht2/nodus_dht2_store.h`) — package 5

Design rev 5 §3.1 "Stored form", §3.3, §4.1, §4.2, §4.5 (i) / (v), §5, §6, §9
D3 / D4 / D6, §13 rows 5-8, 12, 15, 16, 18 (`nodus_dht2_store.h:4-9`);
decisions `2026-10-23-dht-v2-k23-three-items.md` and
`2026-10-24-dht-v2-handled-client-rule.md` (header above; both LOCAL-only).
Narrative: `nodus/docs/ARCHITECTURE.md` "DHT v2 package 5". Linux-only
library list (`nodus/CMakeLists.txt:714-718`); links SQLite.

**NO CALLER YET** (`:69-72`): nothing in `nodus/tools/` or any running loop;
package 6 is the serving layer, package 7 the pull exchange. Package 6a's
holder service (§13) now calls `nodus_dht2_store_put`, `_get` and `_list`,
but nothing calls the holder service (package 6b). The pull exchange itself
is not here — only its data (index scan, generation, hand-over flag).

**Contract** (`:11-67`): a SQLite store of canonical envelopes keyed by
address and the ONE admission path every ingress uses. Nothing reads a
clock (chain time = the injected snapshot's `tip_time`); every query that
decides what is stored or returned has an ORDER BY on a total key; a SQLite
or allocation error is code 16 (`NODUS_DHT2_STORE_FAULT` for the non-put
calls) — never absence, never "no change". Single connection, no lock: the
test header calls it "single-writer by construction" (`test_dht2_store.c:96-97`);
the header says nothing about threads.

**Control records follow rev 5 literally** (`:43-54`): only the control
record that WINS Select is stored and applied (its HANDLED and DENIED drops,
credited before the quota checks in the same transaction); a losing or
quota-refused one changes nothing (row 16); an inbox entry's admission looks
only at the selected, live control record. No holder memory of dropped
entries — keeping a HANDLED request from coming back is the CLIENT rule of
`2026-10-24-dht-v2-handled-client-rule.md` (the owner keeps a HANDLED writer
listed, with its cutoff, ≤ 7 d + 3 h). A holder that receives a newer record
without the writer BEFORE the older one keeps the entry.

**Deferred on purpose** (`:38-41`): the |S(H)| ≥ 2 write precondition (the
serving layer, package 6 — now in package 6a's `nodus_dht2_holder_serve`,
§13.3, not in the store); the per-put SUM cost and the per-inbox tombstone
row bound (measure first); a refusal that leaves an older version behind
(package 7's cursor rule).

### 12.1 Constants and types

| Item | Description |
|------|-------------|
| `NODUS_DHT2_POOL_NAMED` `80u`, `NODUS_DHT2_POOL_UNNAMED` `20u` (`:95-96`) | Row 8: writers per inbox pool (100 per inbox). |
| `NODUS_DHT2_QUOTA_UNNAMED` `(4ull * 1024ull * 1024ull)`, `NODUS_DHT2_QUOTA_NAMED` `(64ull * 1024ull * 1024ull)` (`:99-100`) | §6: per identity per holder, bytes of the whole canonical envelope. |
| `NODUS_DHT2_NODE_POOL_DEFAULT` `10000000000ull` (`:102`) | §6 "10 GB each by default", read as decimal 10^10 bytes (the header's reading). |
| `NODUS_DHT2_LIST_PAGE_BYTES` `(2u * 1024u * 1024u)` (`:105`) | Row 11: a LIST page carries ≤ 2 MiB of envelopes. |
| `NODUS_DHT2_GET_HELD` `0`, `NODUS_DHT2_GET_NOT_HELD` `1`, `NODUS_DHT2_STORE_FAULT` `DHT2_E_HOLDER_FAULT` (16) (`:108-110`) | Results of get / list / scan / sweep / open that are not a row-7 code. |
| `typedef struct { uint64_t ident_unnamed; uint64_t ident_named; uint64_t pool_unnamed; uint64_t pool_named; } nodus_dht2_limits_t;` (`:113-118`) | §6 limits, passed per call (so an operator setting can change at run time). |
| `void nodus_dht2_limits_default(nodus_dht2_limits_t *out)` (`:121`) | Fills the defaults above (4 MiB / 64 MiB, 10^10 / 10^10). NULL `out` is a no-op (`nodus_dht2_store.c:241-250`). |
| `typedef enum { NODUS_DHT2_NAME_UNNAMED = 0, NODUS_DHT2_NAME_NAMED, NODUS_DHT2_NAME_FAULT } nodus_dht2_name_t;` (`:124-128`) | A writer's name status as admission needs it. FAULT = the witness answered `{err}` → code 16. |
| `typedef nodus_dht2_name_t (*nodus_dht2_name_fn)(void *user, const uint8_t fp[DHT2_FP_LEN]);` (`:130-131`) | The name callback. |
| `typedef struct { const nodus_witness_dht_snap_t *snap; bool have_sets; const uint8_t (*s0)[DHT2_FP_LEN]; size_t n0; const uint8_t (*s1)[DHT2_FP_LEN]; size_t n1; uint8_t self_fp[DHT2_FP_LEN]; nodus_dht2_name_fn name; void *name_user; nodus_dht2_limits_t limits; } nodus_dht2_ctx_t;` (`:138-152`) | The injected world; pointers borrowed for the call. `snap` NULL = no fresh snapshot. `s0` / `s1` = S(H) / S(H − E) for the snapshot's `e` (both NULL with counts 0 is a valid empty set); `have_sets` false = the sets for this `e` are not available. `self_fp` = this node's fp (holder check, LIST `n`). `name` required by `put`. `nodus_witness_dht_snap_t` (`nodus_witness_ipc.h:227-236`): `chain_id[32]`, `height`, `tip_time`, `consensus_up`, `epoch_start` — ledger.md §19. |
| `typedef struct nodus_dht2_store nodus_dht2_store_t;` (`:154`) | Opaque: the SQLite handle, the generation, the chain id recorded at create (`nodus_dht2_store.c:33-37`). |
| `typedef enum { NODUS_DHT2_PUT_STORED = 1, NODUS_DHT2_PUT_EQUAL, NODUS_DHT2_PUT_LOST } nodus_dht2_put_outcome_t;` (`:178-182`) | Stored; equal to the held version (acknowledged); the held version wins (its hash, cost 0). |
| `typedef struct { nodus_dht2_put_outcome_t outcome; uint8_t hash[DHT2_HASH_LEN]; uint64_t through; bool has_address; uint8_t address[DHT2_HASH_LEN]; } nodus_dht2_put_t;` (`:184-194`) | `outcome` valid when `put` returned 0; `hash` = SHA3-512 of the canonical envelope stored / held; `through` = the HANDLED cutoff with code 18. `has_address` / `address` (package 6a): set as soon as `dht2_record_parse` succeeded — "set for ANY code after that point (also on failure)" (`:189-193`) — to the envelope's address, from the ONE parse inside admission (`nodus_dht2_store.c:905-908`); false when the gate (15 / 16), `have_sets` (15) or the parse itself (1 / 2 / 3 / 4, or 16) refused first. On any non-zero code the struct is zeroed EXCEPT `through` for 18 and `has_address` / `address`, which survive (`:981-997`); the success-only fields `outcome` and `hash` are cleared. The holder service keys each put result by this address (§13.4). |
| `typedef struct { uint64_t index; uint8_t address[DHT2_HASH_LEN]; uint8_t hash[DHT2_HASH_LEN]; uint8_t placement[DHT2_HASH_LEN]; } nodus_dht2_scan_entry_t;` (`:249-254`) | One insertion-index scan entry: index, address, SHA3-512 of the canonical envelope, placement-key hint — the `p_offer` entry's `{a, h, p}` plus its index. |

### 12.2 The gate (every put / get / list / sweep / scan)

`gate` (`nodus_dht2_store.c:395-408`): `ctx` NULL, `snap` NULL or
`snap->consensus_up` false → 15 (`DHT2_E_NOT_CAUGHT_UP`); `snap->tip_time` >
`INT64_MAX − (DHT2_SEC_7D + DHT2_SEC_SLACK_3H)` → 15 (every time threshold
must fit SQLite's int64); `snap->chain_id` ≠ the chain recorded at create →
16 (G8). The hand-over calls and `top` / `generation` do not run the gate.
(For every gated call a NULL `ctx` is caught earlier as `DHT2_E_ARG`,
`nodus_dht2_store.c:879`, `:1012`, `:1069`, `:1184`, `:1231`.)

### 12.3 Functions

| Item | Description |
|------|-------------|
| `nodus_dht2_store_t *nodus_dht2_store_open(const char *path, const uint8_t chain[DHT2_CHAIN_LEN])` (`:162-163`) | Open, creating when absent, the store at `path` for `chain`, inside one `BEGIN IMMEDIATE` (`nodus_dht2_store.c:252-353`). The FIRST creation (no meta and no record rows) records the chain id, draws the 64-bit generation `g` from `qgp_platform_random` (node-local, equality-compared only, never a consensus input — `:298-301`) and sets the counter to 0 (the first index handed out is 1, row 12). NULL on: NULL arguments, allocation / SQLite failure, no randomness, a store of another chain, incomplete meta, records without a counter, a counter above `INT64_MAX` or below the highest stored index (never reset, never opened). |
| `void nodus_dht2_store_close(nodus_dht2_store_t *s)` (`:164`) | Close and free; NULL-safe. |
| `uint64_t nodus_dht2_store_generation(const nodus_dht2_store_t *s)` (`:167`) | The generation `g` (equality compared only); 0 for NULL. |
| `int nodus_dht2_store_top(nodus_dht2_store_t *s, uint64_t *top)` (`:170`) | The insertion counter's top (0 = nothing ever stored). 0, or 16 (NULL argument, missing / non-integer meta, a value above `INT64_MAX`). |
| `struct sqlite3 *nodus_dht2_store_db(nodus_dht2_store_t *s)` (`:174`) | The SQLite handle, for a test that forces a fault (`PRAGMA query_only`); "production code has no use for it". NULL for NULL. |
| `int nodus_dht2_store_put(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx, const uint8_t *env, size_t len, const uint8_t *expect_address, nodus_dht2_put_t *res)` (`:204-206`) | Admit one envelope (§4.1). `expect_address` (64 B, may be NULL) = the address the caller expects (pull-sync checks it; a client PUT has none). Order — the code of the FIRST failing check (`nodus_dht2_store.c:871-1000`): gate 15 / 16; `have_sets` false → 15; `dht2_record_parse` 1 / 2 / 3 / 4; from here on `res->has_address` / `res->address` = the envelope's address, kept whatever fails next (`:905-908`); placement key + `dht2_eligible(key, s0, n0, s1, n1, self_fp)` → 5 (a −1 from it → 16); `dht2_record_check_class` 6; the name callback, asked EXACTLY ONCE here, NAME_FAULT or any value other than NAMED / UNNAMED → 16; `dht2_record_check_expiry(rec, tip_time, named)` 7 / 8; `dht2_record_verify` 9; canonical form + SHA3-512 (failure → 16). Then ONE transaction (`admit_locked`, `:666-869`): an inbox entry (class 4) is checked against the selected LIVE control record of its inbox — writer DENIED → 12, writer's Sequence ≤ its HANDLED `through` → 18 with `res->through` (`ctl_check_entry`, `:557-590`); Select (§4.2, `dht2_record_compare` against the held row unless the held row's expiry ≤ `tip_time`, which counts as absent): equal → 0 / `NODUS_DHT2_PUT_EQUAL`, loser → 0 / `NODUS_DHT2_PUT_LOST`, `res->hash` = the HELD hash; a winning non-tombstone control record (class 5) drops the entries it marks (`ctl_apply`, `:604-660`: HANDLED with Sequence ≤ `through`, DENIED any Sequence), credited before the checks below; inbox pool 11 (live entries of the writer's pool at that inbox, its own row excluded, ≥ 80 / 20); per-identity quota 10 (sum of the owner fp's stored sizes − old + new > limit, only when the record grows); node pool 13 (same rule per pool; a pool move costs the whole new size in the new pool); a tombstone is charged to the pool of the record it replaces; store at index `top + 1` → 0 / `NODUS_DHT2_PUT_STORED`, `res->hash` = the new hash. Only a stored version commits; equal, losing and every refusal roll back (`:967-979`). On a non-zero code `res` keeps only the address and, for 18, `through` (`:981-997`). The order 11 → 10 → 13 is a READING (`:737-738`). Codes: 0, 1-13, 15, 16, 18; `DHT2_E_ARG` (−1) for NULL `s` / `ctx` / `res` / `ctx->name`, or NULL `env` with `len` ≠ 0 (the header, `:196-203`, lists "1..13 / 16 / 18, or 15" and `DHT2_E_ARG`). |
| `int nodus_dht2_store_get(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx, const uint8_t address[DHT2_HASH_LEN], uint8_t *out, size_t cap, size_t *out_len, uint8_t hash[DHT2_HASH_LEN])` (`:217-220`) | The canonical envelope at `address` and its hash. Never serves a record whose expiry ≤ `tip_time` (§5 — the 3 h slack is for deletion only); tombstones are served until their own expiry; no-expiry records always. `out` needs `DHT2_ENVELOPE_MAX` bytes (a row longer than `cap` → 16). `NODUS_DHT2_GET_HELD` (0), `NODUS_DHT2_GET_NOT_HELD` (1), 15, 16; `DHT2_E_ARG` for a NULL argument (`nodus_dht2_store.c:1004-1053`). |
| `int nodus_dht2_store_list(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx, const uint8_t inbox[DHT2_HASH_LEN], const uint8_t *cursor, dht2_list_answer_t *out)` (`:234-236`) | One LIST page of `inbox` (rows 11, 18): live, non-tombstone class-4 entries placed at `inbox`, ascending writer fp, strictly after `cursor` (NULL = first page; an all-zero fp is used, so an entry whose fp is all zero would never be listed on a first page — not tested), at most 16 and ≤ 2 MiB (`NODUS_DHT2_LIST_PAGE_BYTES`) counting the live control record's bytes FIRST (package 6a: "entries + control stay within the 2 MiB page budget", `nodus_dht2_store.c:1082-1096`; the first entry always fits, `:1128-1134`). Fills: `n` = `self_fp`, `c` / `h` / `t` from the snapshot, `r` = {k: `inbox`, v: SHA3-512 over the listed hashes concatenated, kind `DHT2_RV_HASH`}, `list`, `cursor` = the last `w` (when non-empty), `complete` = no further row, `req_cursor` = `cursor` when given, `ctl` = the selected live control record's hash (`has_ctl` false when none). `q` is left zero — the request's nonce is the caller's; the owner-signature check is the caller's (package 6a's holder service, §13.5). 0, 15, 16 (on 16 `*out` is zeroed — except when the hash buffer cannot be allocated, `:1098-1101`, which returns 16 with `n` / `c` / `h` / `t` / `ctl` already filled); `DHT2_E_ARG` for a NULL argument. |
| `int nodus_dht2_store_sweep(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx, uint64_t *deleted)` (`:244-245`) | §5: in one transaction, delete every record (tombstones included) with an expiry and expiry + 3 h ≤ `tip_time`; nothing when `tip_time` < 3 h. No-expiry records are never swept. Quota is derived from what is stored, so a delete refunds it. 0 (`*deleted` set; may be NULL), 15, 16; `DHT2_E_ARG` for NULL `s` / `ctx`. |
| `int nodus_dht2_store_scan(nodus_dht2_store_t *s, const nodus_dht2_ctx_t *ctx, uint64_t from, nodus_dht2_scan_entry_t *out, size_t max, size_t *count, uint64_t *topmost)` (`:265-267`) | §4.5 i / row 12: entries with insertion index ≥ `from`, ascending, at most `max` (≤ 250); `*topmost` = the highest index scanned, or the store's top when none (Bee `pullsync.go:251-254`). Expired-but-unswept records ARE listed (a holder keeps answering pulls for them until deleted). `from` > `INT64_MAX` → an empty page with the current top. 0, 15, 16; `DHT2_E_ARG` for a NULL argument or `max` 0 / > 250. |
| `int nodus_dht2_store_handover_set(nodus_dht2_store_t *s, const uint8_t address[DHT2_HASH_LEN], bool pending, bool *found)` (`:274-276`) | §4.5 v — data only: set / clear the persisted hand-over obligation of the record at `address`; `*found` (may be NULL) false when no such record. Package 7 decides when. A replacement of the record keeps the flag. 0 / 16; `DHT2_E_ARG` for NULL `s` / `address`. No gate. |
| `int nodus_dht2_store_handover_get(nodus_dht2_store_t *s, const uint8_t address[DHT2_HASH_LEN], bool *pending, bool *found)` (`:277-279`) | Read the flag: `*found`, `*pending` (false when not found). 0 / 16; `DHT2_E_ARG` for any NULL argument. No gate. |

### 12.4 Readings and what is NOT here

Readings (the code's, not design facts): the refusal order inbox pool 11 →
quota 10 → node pool 13 (`nodus_dht2_store.c:737-738`, "the text names no
order"); "10 GB" = 10^10 bytes (`nodus_dht2_store.h:101`); an expired held
row is ABSENT for Select whatever its class (kad-dht `existingForSelect`,
boxo `validation.go:73`, `:687-691`); the inbox control check (12 / 18) runs
BEFORE Select, so a re-put of a dropped entry is refused rather than
acknowledged (`:678-679`). The header's `@return` lists for get / list /
sweep do not name `DHT2_E_ARG`; the code returns it for NULL arguments
(put's header does, `nodus_dht2_store.h:196-203`).

Not here: the serving layer — request decode, answer sealing, the
|S(H)| ≥ 2 precondition and filling the context from `nodus_dht2_wview` are
package 6a (§13); sessions and forwarding are package 6b; the pull exchange
and its cursor rule — package 7; the client rule of
`2026-10-24-dht-v2-handled-client-rule.md` — the Connect core (package 9,
per that decision). Test: §9.4.

---

## 13. The holder service (`nodus/src/dht2/nodus_dht2_holder.h`) — package 6a

Design rev 5 §2 "Precondition", §4.4 (signed answers and receipts), §13
rows 7, 14, 18, 20, 23; request format per decision
`2026-10-23-dht-v2-wire-gaps-package2.md` (`nodus_dht2_holder.h:4-7`; all
LOCAL-only). Row 11 enters through the request bound (§10.2) and the LIST
page budget (§12.3). Narrative: `nodus/docs/ARCHITECTURE.md` "DHT v2
package 6a". Linux-only library list (`nodus/CMakeLists.txt:719-723`:
"Transport-free. No caller yet (package 6b serves it)").

**What it is** (`:9-23`): ONE transport-free function. It takes the bytes
of ONE request from one session — "get", "put" (also read-repair), or the
owner-signed "list" envelope — runs it against the holder store (§12) and
returns the bytes of ONE signed answer envelope, or "no answer":

| Request | Answer payload type | Payload |
|---|---|---|
| get | `/nodus/dht/answer/v1` | `{q, n, c, h, t, r}`, `r` per key: hash, null (not held), code, `[18, through]` |
| put | `/nodus/dht/receipt/v1` | as get, never null |
| list | `/nodus/dht/answer/v1` | the row-18 LIST payload; a request not signed by the inbox owner is answered `r.v` = 17 |
| (any) refusal | `/nodus/dht/refusal/v1` | `{q, n, c, e}`, `e` = 14 busy \| 15 not-caught-up; no `h` / `t` (row 18) |

Every one is sealed with `dht2_answer_seal` under the node identity, domain
/ ctx `nodus.dht.answer.v1`; `q` = the request's own nonce, `n` = this
node's fp. `c` is the holder's own chain (`h->chain`, set at init) in a
refusal, a get / put answer and a denied LIST; an owner LIST takes `c` from
the snapshot through the store, which the chain gate (§13.3) has made the
same chain. `h` / `t` are the snapshot's height and tip time
(`nodus_dht2_holder.c:247-251`, `:310-314`, `:398-401`).

**NO CALLER YET** (`:88`): nothing in `nodus/tools/` or any running loop
calls it; the only caller is `nodus/tests/test_dht2_holder.c`.

**NOT here — package 6b** (`:60-63`): sessions, the 16 outstanding calls /
8 MiB per session, forwarding and its fan-out of 8, the 10 s deadline, the
repair queue, and the records that travel BESIDE an answer — the caller
fetches a held record by the hash in `r` with `nodus_dht2_store_get`. Also
not here: the client rules of §4.4 (package 8, `test_dht2_holder.c` "HOW IT
CAN LIE" 3).

### 13.1 Constants and types

| Item | Description |
|------|-------------|
| `#define NODUS_DHT2_HOLDER_QUEUE_MAX 64u` (`:110`) | Row 20: per holder ≤ 64 queued signing jobs. |
| `#define NODUS_DHT2_HOLDER_WRITE_MIN_SET 2u` (`:113`) | §2 "Precondition": while S(H) has fewer members than this, every put is refused. |
| `#define NODUS_DHT2_HOLDER_WRITE_REFUSAL DHT2_E_NOT_CAUGHT_UP` (`:117`) | The refusal code of that write precondition: 15. A READING — "ORCHESTRATOR reading, to be confirmed by the operator … Must be 14 or 15" (`:115-116`); the design names no code for it. `_Static_assert` that it is `DHT2_E_BUSY` or `DHT2_E_NOT_CAUGHT_UP` (`nodus_dht2_holder.c:22-24`), because a refusal payload carries only 14 / 15. |
| `#define NODUS_DHT2_HOLDER_OUT_MIN DHT2_ANSWER_ENV_MAX` (`:120`) | `out` of `serve` must hold at least this many bytes (9,985 B, §2.6). |
| `typedef enum { NODUS_DHT2_HOLDER_GET = 0, NODUS_DHT2_HOLDER_PUT, NODUS_DHT2_HOLDER_LIST } nodus_dht2_holder_kind_t;` (`:123-127`) | Which request a byte string is — the METHOD it arrived on. `PUT` is also read-repair. |
| `#define NODUS_DHT2_HOLDER_ANSWER 0`, `#define NODUS_DHT2_HOLDER_NO_ANSWER 1`, `#define NODUS_DHT2_HOLDER_ERR (-1)` (`:130-134`) | `serve` results: `*out_len` bytes of ONE envelope; send nothing; "NULL / too-small buffer, signing or allocation failure: no answer could be made". |
| `typedef struct { bool (*snap)(void *user, uint64_t now_ms, nodus_witness_dht_snap_t *out); const nodus_witness_dht_sets_t *(*sets)(void *user, uint64_t now_ms); nodus_dht2_wview_name_t (*name)(void *user, uint64_t now_ms, const uint8_t fp[64], uint64_t *h_out); void *user; } nodus_dht2_holder_view_t;` (`:137-143`) | What the holder reads of the witness: snapshot, frozen sets, name answers — the signatures of `nodus_dht2_wview_snap` / `_sets` / `_name` (§11) with a `void *user`, so a test injects a fixed view. |
| `typedef struct { nodus_dht2_store_t *store; const nodus_identity_t *id; nodus_dht2_holder_view_t view; uint8_t chain[DHT2_CHAIN_LEN]; uint8_t self_fp[DHT2_FP_LEN]; nodus_dht2_limits_t limits; uint32_t queued; bool chain_warned; } nodus_dht2_holder_t;` (`:149-158`) | `store` and `id` borrowed (`id` signs every answer); `view` copied; `chain` = the chain the store was opened for; `self_fp` from the identity; `limits` = the §6 defaults; `queued` = the row-20 counter; `chain_warned` = the foreign-chain error was logged (once). `nodus_identity_t` is `nodus/include/nodus/nodus_types.h`'s node identity; `NODUS_PK_BYTES` = `DHT2_PUBKEY_LEN` is a `_Static_assert` (`nodus_dht2_holder.c:20-21`). |

### 13.2 Functions

| Item | Description |
|------|-------------|
| `void nodus_dht2_holder_view_wview(nodus_dht2_holder_view_t *v, nodus_dht2_wview_t *wv)` (`:146-147`) | Bind `v` to the real package-4 view: `snap` / `sets` / `name` become trampolines onto `nodus_dht2_wview_snap` / `_sets` / `_name`, `user` = `wv` ("borrowed for the holder's life", `:145`). NULL `v` is a no-op (`nodus_dht2_holder.c:45-55`). Not exercised by any test. |
| `int nodus_dht2_holder_init(nodus_dht2_holder_t *h, nodus_dht2_store_t *store, const nodus_identity_t *id, const uint8_t chain[DHT2_CHAIN_LEN], const nodus_dht2_holder_view_t *view)` (`:163-167`) | Zero `h`, borrow `store` / `id`, copy `view` and `chain`, `self_fp` = `dht2_fp(id->pk)`, `limits` = `nodus_dht2_limits_default`, queue empty. `chain` "names the chain of a refusal, which has no snapshot to take it from" (`:160-162`). 0; −1 for any NULL argument or view callback, or a failed `dht2_fp` (`nodus_dht2_holder.c:59-79`). |
| `bool nodus_dht2_holder_job_enter(nodus_dht2_holder_t *h)` (`:170`) | Row 20: take one signing-job slot. `false` (and nothing taken) at `NODUS_DHT2_HOLDER_QUEUE_MAX` or for NULL `h`. |
| `void nodus_dht2_holder_job_leave(nodus_dht2_holder_t *h)` (`:171`) | Give one slot back; a no-op on an empty queue or NULL `h`. `serve` itself takes no slot: the CALLER brackets each answer it has queued with enter / leave (`:55-58`); `serve` only reads the counter. |
| `int nodus_dht2_holder_serve(nodus_dht2_holder_t *h, nodus_dht2_holder_kind_t kind, uint64_t now_ms, const uint8_t *req, size_t req_len, uint8_t *out, size_t cap, size_t *out_len)` (`:177-180`) | Answer one request (§13.3). `now_ms` = the caller's monotonic tick count, only handed on to the view. `out` needs `NODUS_DHT2_HOLDER_OUT_MIN` bytes. `NODUS_DHT2_HOLDER_ANSWER` (`*out_len` set), `_NO_ANSWER`, `_ERR`. |

### 13.3 Order of one call (`nodus_dht2_holder_serve`, `nodus_dht2_holder.c:441-494`)

1. NULL `h` / `out` / `out_len`, NULL `req` with `req_len` ≠ 0, or `cap` <
   `NODUS_DHT2_HOLDER_OUT_MIN` → `_ERR`; then `*out_len` = 0 (`:451-456`).
2. `NODUS_DHT2_HOLDER_LIST` → the LIST path (§13.5). A `kind` that is none
   of the three → `_ERR` (`:457-462`).
3. `dht2_req_decode` (§10.2). `DHT2_E_MALFORMED_REQ`, or a request whose
   `op` is not the method it arrived on (a get sent as put or the
   reverse) → `_NO_ANSWER` (row 7: "a tier-2 protocol error, no signed
   answer"); any other failure → `_ERR` (`:464-473`).
4. The call's world (`world_load`, `:135-169`): the snapshot from
   `view.snap`; "fresh" only when the view returns one AND `consensus_up`
   is true. **Chain gate** (the one place, `:142-152`): a snapshot whose
   `chain_id` ≠ the holder's chain is NO snapshot — nothing reads its
   `h` / `t`, the error is logged once (`chain_warned`). With a fresh
   snapshot the sets come from `view.sets` (NULL = not available,
   `have_sets` false) and the store context is filled: `self_fp`, the name
   callback (§13.4), `limits`, `s0` / `n0` / `s1` / `n1`.
5. Call-level states (`call_state`, `:209-218`), in this order:
   `queued` ≥ 64 → refusal 14 (busy); no fresh snapshot → refusal 15
   (not-caught-up).
6. **Write precondition** (§2, `:481-484`): a put whose sets ARE available
   with `n0` (|S(H)|) < `NODUS_DHT2_HOLDER_WRITE_MIN_SET` → the refusal
   `NODUS_DHT2_HOLDER_WRITE_REFUSAL` (15). Read-repair is a put, so it is
   refused too; reads are still served. (With no sets for the snapshot's
   `e` the precondition is not checked here; the store then answers 15 for
   the first key, which becomes the whole-call refusal 15 — §13.4.)
7. A refusal is `{q: the request's nonce, n, c, e}` sealed under
   `/nodus/dht/refusal/v1` (`refuse`, `:188-205`). Otherwise get or put
   (§13.4). Every answer is sealed by `seal` (`:173-186`): `cap` <
   `OUT_MIN` or a failing `dht2_answer_seal` → `_ERR` (logged).

### 13.4 Per-key results of get and put

Each `r` element keeps the request's order (row 7).

**get** (`serve_get`, `:230-295`), per key `k` (the requested key), from
`nodus_dht2_store_get`:

| Store result | `v` |
|---|---|
| `NODUS_DHT2_GET_HELD`, and the held bytes re-parse (`dht2_record_parse` against the holder's chain) to a class other than 5 | the hash (from the store) |
| `NODUS_DHT2_GET_HELD` of an inbox-control record (class 5) | code 17 — row 23: inbox-control reads are answered to the inbox OWNER only, and a GET is not owner-signed; never its hash or bytes. Control records are read only through the owner-signed LIST (`:79-81`, `.c:261-271`) |
| `NODUS_DHT2_GET_HELD` whose stored bytes no longer parse | code 16 ("they passed admission; a parse failure now is a fault") |
| `NODUS_DHT2_GET_NOT_HELD` | null |
| 15 | the WHOLE call becomes the refusal 15 (no partial answer) |
| anything else (16, `DHT2_E_ARG`) | code 16 — "a store fault is 16, never absence" |

**put** (`serve_put`, `:297-357`), per envelope, through
`nodus_dht2_store_put(store, ctx, env, len, NULL, &pr)` — the store's ONE
parse; the holder never parses a put envelope itself:

- **Key.** `k` = `pr.address` when `pr.has_address` (the envelope parsed as
  far as its address, §12.1), else 64 zero bytes (`:321-332`): an envelope
  that does not parse that far has no address in the spec. A result is
  never given under another key; the client matches by position (row 7).

| Store result | `v` |
|---|---|
| 0 (`STORED`, `EQUAL` or `LOST`) | the hash in `pr.hash` — the stored version, or the held winner's (row 17: a losing write gets the winner's hash) |
| 18 | `[18, pr.through]` — this writer's own HANDLED cutoff |
| 0 or 18 WITHOUT an address | code 16 (defensive, `:333-335`) |
| 15 | the WHOLE call becomes the refusal 15 |
| 1…13 | that code (`result_code`, `:221-226`) |
| anything else (16, `DHT2_E_ARG`) | code 16 |

Which key a refusal carries (pinned by `test_late_refusal`): a code after
the parse — 5 … 13, 18, or a 16 after it — is under the envelope's address;
1 / 2 / 3 from the parse, and 16 from the parse (allocation / hashing),
under the zero key (the header's list, `:72-76`; the parse's 4 cannot occur
here, because the holder passes no expected address and
`dht2_record_parse` returns 4 only against one, `dht2_record.c:549-551`). An envelope above 262,144 B is the parse's 1 with the
zero key; its siblings in the same request are still processed (§10.2).

**The name callback** (`name_cb`, `:105-122`) given to the store maps the
view's answer: NAMED → NAMED, UNNAMED → UNNAMED, FAULT → FAULT (the store
turns it into 16 for that key, which consumes it), and PENDING /
UNAVAILABLE → FAULT for this call — "the request has been sent; the client
retries" (`:40-46`). A name answer is therefore always consumed by the call
that met it, and never read as "no name". (The view's own expiry of an
abandoned fault: §11.)

### 13.5 LIST (`serve_list`, `nodus_dht2_holder.c:361-437`)

1. FIRST `dht2_list_req_open(req, req_len, holder chain, &lr, NULL)` (§6.2),
   before the world is loaded: `DHT2_E_NOT_OWNER` → the request is DENIED
   but still answered; `DHT2_E_MALFORMED_REQ`, `DHT2_E_BAD_CHAIN` or
   `DHT2_E_BAD_SIGNATURE` → `_NO_ANSWER`; any other failure → `_ERR`
   (`:374-382`).
2. World and call state as for get / put — refusal 14 or 15 with the LIST
   request's nonce (`:384-394`). The write precondition does not apply.
3. DENIED (row 7 / row 23, `:395-409`): an answer with `n`, `c`, `h`, `t`,
   `r` = `{k: the requested inbox, v: 17}`, nothing listed, no `ctl`,
   `complete` = true, `req_cursor` echoed when the request had a cursor.
4. Owner: `nodus_dht2_store_list` (§12.3) — 15 → the refusal 15;
   `NODUS_DHT2_STORE_FAULT` → `_NO_ANSWER` (`:417-422`: "a LIST answer
   cannot carry 16 (row 18): no answer, never an empty page"); any other
   non-zero → `_ERR`.
5. `q` = the request's nonce; encoded with `dht2_list_answer_encode` and
   sealed under `/nodus/dht/answer/v1` (`:427-432`).

### 13.6 Rules added in the fix round, readings, and what has no answer

Rules the header adds "IN THE FIX ROUND (each pinned by a test)"
(`:65-86`):

- **Chain gate** — §13.3 step 4: a snapshot of another chain makes every
  request, the not-owner LIST included, the refusal 15 without `h` / `t`,
  never an answer that mixes our `c` with a foreign tip (`test_chain_gate`).
- **Key of a put result** — §13.4: `k` = the address from the store's one
  parse; the zero key and the parse code otherwise; an envelope above
  262,144 B is per-key 1 and its siblings are processed; the whole request
  is bounded at `DHT2_REQ_MAX_LEN` (`test_oversize_put`, `test_late_refusal`).
- **Inbox control via get** — §13.4: per-key 17 (`test_ctl_get`).
- **A LIST whose store read faults gets no answer** — §13.5 step 4: §4.4
  says a missing answer is "no answer", never "not found", and row 18 lets
  a LIST result carry only a hash or 17. No test forces it (the test header
  lists no LIST fault case).
- **Clock** — the module's QGP_LOG_* lines carry a log timestamp read from
  the clock; no answer field depends on it. Nothing else here reads a
  clock: chain time is the snapshot's `t`.

**What gets no signed answer** (`_NO_ANSWER`, `:25-32`): a malformed request
per row 7 (nonce, key count, key length, unknown op, a request whose op is
not the method it arrived on, any strict-CBOR fault, a LIST envelope that
does not decode); also — a READING, row 23 names only code 17 — a LIST whose
chain is not this chain or whose signature does not verify ("the signer is
not proven, so no signed answer is spent on it"); and a LIST whose store
read faulted. `_ERR` (no answer could be made) is separate: a caller bug
(NULL, a too-small `out`, an unknown `kind`), an allocation or signing
failure, or a decode / open code other than those above.

**Readings, not design facts:**
- the write-precondition refusal code 15 (`:48-53`, `:115-116`) — the
  design names no code; "one constant so it can change";
- a LIST of another chain or with a bad signature gets no answer (`:29-32`);
- an envelope above 262,144 B inside a put is per-key 1, not a malformed
  request (`:73-78`; §10.7).

Test: §9.5.
