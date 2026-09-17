# Nodus — Architecture Documentation

**Version:** 0.19.19 | **Language:** C (pure) | **License:** Proprietary | **Last Updated:** 2026-08-27 (header/deployment pass; foundational body from 2026-04-24)

> **Note (2026-04-24):** This document captures Nodus's foundational architecture (motivation, two-tier protocol, wire format, storage). Features landed since v0.10.11 — F17 committee enforcement, stake-delegation v1, hard-fork mechanism (`DNAC_TX_CHAIN_CONFIG`), Genesis Protocol harness, inflation — are documented in their own design docs under `dnac/docs/plans/` and in `nodus/CLAUDE.md`. The architecture below still applies; those features extend it rather than replace it.

---

## 1. Overview & Motivation

Nodus is a complete rewrite of the DNA Connect's DHT (Distributed Hash Table) layer. It
replaces OpenDHT-PQ — a C++ library with post-quantum patches — with a pure C implementation
built from the ground up for post-quantum security.

**Why replace OpenDHT-PQ:**

- **C++ dependency** — the only C++ component in an otherwise pure-C codebase, requiring
  `libstdc++` and complicating cross-compilation (Android NDK, Windows MinGW)
- **ASAN memory leaks** — OpenDHT's internal allocations created persistent leak reports
  that could not be resolved without upstream changes
- **No native post-quantum** — Dilithium5 support was bolted on via patches to OpenDHT's
  crypto layer rather than being a first-class design choice
- **Opaque failure modes** — debugging C++ template errors across OpenDHT internals was
  impractical for a small team

**What Nodus provides:**

- Pure C implementation — zero C++ dependencies, compiles with any C11 compiler
- Kademlia DHT with 512-bit key space (SHA3-512)
- Dilithium5 (ML-DSA-87) authentication and value signing throughout
- CBOR wire protocol with custom encoder/decoder (no external CBOR library)
- Heartbeat-based cluster membership
- Consistent hash ring for channel-to-node assignment
- Client SDK with auto-reconnect, multi-server failover, and real-time push
- SQLite persistent storage with TTL-based expiry

**Scale:** ~17,000+ lines of C across 32 source files and 15 test files. External
dependencies: OpenSSL (random bytes), SQLite (storage), and json-c (server config parsing).

---

## 2. System Architecture

### High-Level Design

Nodus uses a two-tier protocol architecture:

```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENTS                               │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                     │
│   │ Android │  │  Linux  │  │ Windows │                      │
│   │   App   │  │   App   │  │   App   │                      │
│   └────┬────┘  └────┬────┘  └────┬────┘                      │
│        │            │            │     Tier 2 (TCP 4001)      │
│        │    Dilithium5 Auth      │     PUT/GET/LISTEN         │
│        ▼            ▼            ▼                            │
├──────────────────────────────────────────────────────────────┤
│                     NODUS CLUSTER                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ... (6 nodes)   │
│   │ nodus-01 │◄─┤ nodus-02 │◄─┤ nodus-03 │                  │
│   │  (US-1)  │─►│  (EU-1)  │─►│  (EU-2)  │                  │
│   └──────────┘  └──────────┘  └──────────┘                   │
│        Tier 1: UDP 4000 (Kademlia) + TCP 4002 (replication)  │
│        TCP 4003: Channel system (PRIMARY/BACKUP per channel) │
│        Cluster heartbeat + hash ring + value replication        │
└──────────────────────────────────────────────────────────────┘
```

- **Tier 1 (T1)** — Server-to-server: Kademlia routing (UDP), value replication (TCP),
  Cluster heartbeats (UDP)
- **Tier 2 (T2)** — Client-to-server: authentication, DHT operations, channel messaging,
  real-time push notifications (all TCP)
- **Tier 3 (T3)** — DNAC witness: BFT consensus for double-spend prevention, UTXO
  management, hub/spoke TX/block queries (TCP, authenticated sessions)

### Directory Structure

```
nodus/
├── include/nodus/
│   ├── nodus_types.h          # All types, constants, enums
│   └── nodus.h                # Public client SDK API
├── src/
│   ├── core/
│   │   ├── nodus_value.c      # DHT value create/sign/verify/serialize
│   │   ├── nodus_routing.c    # Kademlia routing table (512 buckets × k=8)
│   │   └── nodus_storage.c    # SQLite persistent value storage
│   ├── protocol/
│   │   ├── nodus_cbor.c       # Custom CBOR encoder/decoder
│   │   ├── nodus_wire.c       # Wire frame format ("ND" + version + length)
│   │   ├── nodus_tier1.c      # T1 encode/decode (server ↔ server)
│   │   └── nodus_tier2.c      # T2 encode/decode (client ↔ server)
│   ├── transport/
│   │   ├── nodus_tcp.c        # TCP transport (epoll, framing, connections)
│   │   └── nodus_udp.c        # UDP transport (non-blocking recvfrom)
│   ├── crypto/
│   │   ├── nodus_sign.c       # Dilithium5 sign/verify/hash wrappers
│   │   └── nodus_identity.c   # Identity generation, save/load, seed derivation
│   ├── channel/
│   │   ├── nodus_channel_store.c       # SQLite channel + post storage
│   │   ├── nodus_hashring.c            # Consistent hash ring
│   │   ├── nodus_channel_server.c/h    # TCP 4003 session management + auth
│   │   ├── nodus_channel_primary.c/h   # PRIMARY role: post handling + broadcast
│   │   ├── nodus_channel_replication.c/h # BACKUP replication + hinted handoff + sync
│   │   └── nodus_channel_ring.c/h      # Heartbeat-based ring management (no PBFT)
│   ├── circuit/
│   │   ├── nodus_circuit.c        # Per-session circuit table (VPN mesh relay)
│   │   └── nodus_inter_circuit.c  # Inter-node circuit table (cross-nodus relay)
│   ├── consensus/
│   │   └── nodus_cluster.c       # Cluster membership + leader election
│   │   (src/bft/ — the T1 Tendermint core of 2026-09-08 — was DELETED in R2,
│   │    2026-09-11, as a second implementation of what the cometbft port
│   │    under shared/dnac/cmt_*.c provides; see "cometbft literal port" below)
│   ├── server/
│   │   ├── nodus_server.c     # Server event loop + message dispatch
│   │   └── nodus_auth.c       # Dilithium5 challenge-response auth
│   ├── client/
│   │   ├── nodus_client.c     # Client SDK (connect, auth, DHT, channels, DNAC)
│   │   ├── nodus_singleton.c  # Thread-safe global client instance
│   │   └── nodus_republish.c  # Migration republish helper
│   └── witness/               # DNAC BFT witness module (embedded)
│       ├── nodus_witness.c          # Witness init, DB schema, lifecycle
│       ├── nodus_witness_db.c/h     # SQLite ops (nullifiers, ledger, UTXOs, TXs, blocks)
│       ├── nodus_witness_bft.c/h    # BFT consensus state machine (PBFT)
│       ├── nodus_witness_peer.c/h   # TCP peer mesh management
│       ├── nodus_witness_handlers.c/h # DNAC message dispatch (spend, query, block)
│       ├── nodus_witness_verify.c/h # TX verification (hash, sig, balance, fee, nullifiers)
│       └── nodus_witness_v2_schema.c/h # Ledger V2 versioned schema S5..S13 (S13 = tm_wal, tm_state, v2_blocks.commit_cert;
│                                      #   the S13 tables stay — the wave-1 module that wrote them, nodus_witness_tm_wal.c/h,
│                                      #   was deleted in R2; the host that writes them to D-15 rev 5 is R3)
├── tests/
│   ├── test_wire.c            # Wire frame tests
│   ├── test_cbor.c            # CBOR encoder/decoder tests
│   ├── test_tier1.c           # T1 protocol tests
│   ├── test_tier2.c           # T2 protocol tests
│   ├── test_value.c           # Value create/sign/verify tests
│   ├── test_routing.c         # Routing table tests
│   ├── test_storage.c         # SQLite storage tests
│   ├── test_identity.c        # Identity generation tests
│   ├── test_hashring.c        # Hash ring tests
│   ├── test_channel_store.c      # Channel storage tests
│   ├── test_channel_server.c    # TCP 4003 session tests
│   ├── test_channel_primary.c   # PRIMARY role handler tests
│   ├── test_channel_replication.c # Replication + hinted handoff tests
│   ├── test_channel_ring.c      # Ring management tests
│   ├── test_channel_protocol.c  # Channel protocol message tests
│   ├── test_tcp.c               # TCP transport tests
│   ├── test_client.c          # Client SDK tests
│   ├── test_server.c          # Server integration tests
│   │   (test_tm_core / test_tm_proposer / test_tm_sim / test_tm_vote / test_tm_commit /
│   │    test_tm_wal were deleted in R2 with the T1 core and T3 wave-1 modules they tested)
│   ├── test_cmt_merkle.c      # cometbft port R1-A: RFC 6962 tree on SHA3-512 — roots, proofs, empty root H("")
│   ├── test_cmt_bits.c        # cometbft port R1-A: BitArray + packed wire form (Elems == (Bits+63)/64 enforced)
│   ├── test_cmt_safemath.c    # cometbft port R1-A: libs/math/safemath.go
│   ├── test_cmt_time.c        # cometbft port R1-A: BFT-time value, WeightedMedian (time_test.go vectors), zero time = year one
│   ├── test_cmt_pb.c          # cometbft port R1-A/B: proto3 codec against the generated encoders' rules (K-1 rev 2), oracle KATs
│   ├── test_cmt_block.c       # cometbft port R1-B: Header.Hash 14 leaves, Commit/CommitSig/ExtendedCommit, MakeBlock, size constants 790/159/4685
│   ├── test_cmt_vote.c        # cometbft port R1-B: CanonicalVote sign bytes, Verify with real ML-DSA-87 keys, ValidateBasic, signer callback
│   ├── test_cmt_part_set.c    # cometbft port R1-B: Part / PartSetHeader / PartSet, AddPart outcomes, reader
│   ├── test_cmt_validator_set.c # cometbft port R1-C: proposer priority (cometbft's ProposerSelection1/2 vectors), change sets, ValidatorsHash
│   ├── test_cmt_results.c     # cometbft port R1-C: ABCIResults root + proof
│   ├── test_cmt_params.c      # cometbft port R1-C: ConsensusParams flat hash, ValidateBasic / ValidateUpdate / Update
│   ├── test_cmt_genesis.c     # cometbft port R1-C: GenesisDoc ValidateAndComplete (clock via callback), ValidatorHash
│   ├── test_cmt_validation.c  # cometbft port R1-D: VerifyCommit with real signatures — +2/3 strict, NIL verified-not-counted, every signature checked
│   ├── test_cmt_evidence.c    # cometbft port R1-D: DuplicateVoteEvidence bare bytes / flat hash / canonical order, EvidenceList root
│   ├── test_cmt_state.c       # cometbft port R1-D: MedianTime (voting-power weights), MakeGenesisState, Copy, MakeBlock
│   ├── test_cmt_vote_set.c    # cometbft port R2-A: VoteSet — the seven vote_set_test.go scenarios, weight-vs-count, the C-only capacity bounds (128 peers, N+P blocks)
│   ├── test_cmt_hvs.c         # cometbft port R2-A: HeightVoteSet — the two height_vote_set_test.go scenarios, SetRound's round −1, POLInfo, peer catch-up bound
│   ├── test_cmt_msgs.c        # cometbft port R2-B: MsgToProto / MsgFromProto for the 9 reactor messages, the Message oneof, msgs_test.go golden hex
│   ├── test_cmt_wal.c         # cometbft port R2-B: WALToProto / WALFromProto, the 4 record kinds, TimedWALMessage, Duration range incl. INT64 extremes
│   ├── test_cmt_ticker.c      # cometbft port R2-B: the timeout ticker's ignore rule (ticker.go:108-118), every branch of the step guard
│   ├── test_cmt_privval.c     # cometbft port R2-B: FilePV signing — CheckHRS branch by branch, reuse / timestamp-only / conflicting-data, save-then-sign order, real ML-DSA-87
│   ├── test_cmt_replay.c      # cometbft port R2-B: the handshake classifier — one row per branch, the 4^5 sweep, the negative-height bound
│   ├── test_cmt_cs_unit.c     # cometbft port R2-C: the state machine's host-free parts — the seven entry guards as predicates, timeout acceptance, internal queue FIFO/overflow, voteTime clamp
│   ├── test_cmt_common.h      # cometbft port R2-T: the host fixture (C stand-in for common_test.go) — application, block store, MockPV signer, WAL ring, frozen clock, hand-fired timer; 10 "how it can lie" entries
│   ├── test_cmt_cs.c          # cometbft port R2-T + R2-T2: 39 whole-height scenarios from state_test.go / byzantine_test.go / mempool_test.go (every state_test.go func a single-node fixture can drive; 4 remain BLOCKED, listed with reasons); asserts WHICH block was committed; "how it can lie" items 11-21 (the fixture's 1-12 are in test_cmt_common.h)
│   ├── test_cmt_multinode.h   # cometbft port R2-BYZ: the reactor stand-in — N fixtures, connectivity matrix, router porting the three gossip routines as rules, step budget instead of wall clock; R3 W3 P0 added a third timer rule (M16 MN_TICKER_QUIESCENT: an honest node's timeout fires only when the whole network was quiet for a full round) and the bad-header byzantine override
│   ├── test_cmt_byzantine.c   # cometbft port R2-BYZ: TestByzantineConflictingProposalsWithPartition — 4 nodes, byzantine proposer, partition heals, all honest nodes commit the SAME block; + 2 C-only scenarios; + R3 W3 P0: the two part-set-bound OBLIGATION scenarios (atlas-dec-247e5c0e…): forged +2/3 prevotes for a BlockID the bound refuses → every honest node reaches setProposal / addVote / enterPrecommit, signs nil, commits an honest block later (parts_cap clause); forged precommits too → enterCommit parks the node with no block (MAX_PARTS clause)
│   ├── test_cmt_app.c         # cometbft port R3-C1a: the application over a REAL version-3 chain — InitChain as a genesis check, FinalizeBlock with per-item SAVEPOINT isolation, both crash windows, Commit as the COMMIT, CheckTx (incl. the signature stage), PrepareProposal / ProcessProposal; 18 cases
│   ├── test_cmt_node.c        # cometbft port R3-C1c: the startup table — genesis document loader (row / provider / refusals), the Handshaker's height cases and BOTH crash windows healed (real app / mock app), LoadOrGenFilePV, init/start/release; 14 cases
│   └── test_cmt_net.c         # cometbft port R3 W3 C2b: the transport glue (nodus_witness_cmt_net) — peer-set scan over a hand-built witness peer table driving a REAL cmt_conr/cmt_memr pair, send refused for a down/quarantined slot, verb 35/39 receive routing, receive-before-tick, the 64 MiB receive-arena runway + latches, deferred close bookkeeping, scan waits for both reactors; 8 cases
├── CMakeLists.txt             # Build system
└── docs/
    └── ARCHITECTURE.md        # This file
```

### Build System

Nodus uses CMake and builds in two modes:

**Standalone** (server binary + tests):
```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

**Messenger integration** (linked into `libdna.so`):
```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

The messenger CMake includes Nodus client sources directly — the server is not linked into
the messenger library. Shared crypto code lives in `shared/crypto/` and is resolved via
`-I /opt/dna/shared` include paths.

---

## 3. Wire Protocol

All Nodus communication uses a framed binary protocol. Every message — whether over TCP or
UDP — is wrapped in a wire frame containing a CBOR payload.

### Frame Format

```
Offset  Size   Field        Description
──────  ────   ─────        ───────────
0       2      Magic        0x4E44 ("ND") — big-endian
2       1      Version      0x01
3       4      Length       Payload length — little-endian uint32
7       N      Payload      CBOR-encoded message
```

Total header: 7 bytes. Maximum payload: 4 MB (TCP) or 1400 bytes (UDP, safe MTU).

**Encoding** (`nodus_wire.c:nodus_frame_encode`):
```c
buf[0] = 0x4E;  // 'N'
buf[1] = 0x44;  // 'D'
buf[2] = 0x01;  // version
buf[3..6] = payload_len (LE32)
buf[7..] = payload
```

**Decoding** (`nodus_wire.c:nodus_frame_decode`): Returns 0 if incomplete (need more
data), -1 on invalid magic, or the total frame length on success. This allows incremental
parsing of TCP streams.

### CBOR Encoding

Nodus implements a custom CBOR encoder/decoder (`nodus_cbor.c`) — no external library
dependency. Supported types:

| CBOR Type | C API | Usage |
|-----------|-------|-------|
| Unsigned int | `cbor_encode_uint` | txn IDs, timestamps, seq numbers |
| Byte string | `cbor_encode_bstr` | keys, signatures, data payloads |
| Text string | `cbor_encode_cstr` / `cbor_encode_tstr` | method names, map keys |
| Array | `cbor_encode_array` | peer lists, value arrays |
| Map | `cbor_encode_map` | message envelope, arguments |
| Boolean | `cbor_encode_bool` | flags (major type 7, values 20/21) |
| Null | `cbor_encode_null` | absent values (major type 7, value 22) |
| Signed int | `cbor_encode_int` / `cbor_decode_int` | RFC 8949 §3.1 — value < 0 is major type 1 with argument −1−value. NO live verb carries a signed field since R3 W3 C2b retired verbs 28-34 (2026-09-16); the primitives stay in `nodus_cbor` (D-22 rev 3). `cbor_decode_int` is a SEPARATE reader: `cbor_decode_next` / `cbor_decode_peek` / `cbor_decode_skip` still report major type 1 as an error, so every decoder keeps rejecting negative bytes |
| Signed skip | `cbor_decode_skip_signed` | ONE caller: `nodus_t3_decode` pass 1, which steps over the `a` body to reach the method name and `wsig`. Identical to `cbor_decode_skip` except that a major type 1 item is stepped over (via `cbor_decode_int`) and reported through `*saw_negint`; the admission set is EMPTY (D-22 rev 3): a negative anywhere inside `a` is refused (−1) for every verb, which `test_tier3`'s `universal_negint_pin` pins. The shared `cbor_decode_skip` (≈230 call sites in 12 files) is unchanged |

### Message Envelope

All messages share a common CBOR map structure:

```
{
    "t":   <uint32>     # Transaction ID
    "y":   <string>     # Type: "q" (query), "r" (response), "e" (error)
    "q":   <string>     # Method name
    "a":   {…}          # Arguments (queries)
    "r":   {…}          # Results (responses)
    "tok": <bytes[32]>  # Session token (T2 authenticated requests)
}
```

---

## 4. Tier 1 Protocol — Server-to-Server

Tier 1 handles inter-node communication for Kademlia routing and value replication.

### Transport

- **UDP** — Kademlia discovery (PING/PONG, FIND_NODE). Limited to 1400 bytes (safe MTU).
- **TCP** — Value operations (STORE, FIND_VALUE). Required because a single serialized
  `NodusValue` is ~7.3 KB (Dilithium5 public key 2592B + signature 4627B + data + metadata),
  which exceeds UDP MTU.

### Message Types

| Method | Type | Transport | Description |
|--------|------|-----------|-------------|
| `ping` | query | UDP | Heartbeat — includes sender's node_id |
| `pong` | response | UDP | Heartbeat response — includes responder's node_id |
| `fn` | query | UDP | FIND_NODE — find k closest nodes to target |
| `fn_r` | response | UDP | NODES_FOUND — returns array of peer info |
| `sv` | query | UDP/TCP | STORE_VALUE — replicate a signed value (rate-limited: 200/s) |
| `sv_ack` | response | UDP | STORE acknowledgement |
| `fv` | query | TCP | FIND_VALUE — retrieve value by key (rate-limited: 100/s) |
| `fv_r` | response | TCP | VALUE_FOUND — returns value or closest nodes |
| `sub` | query | TCP | SUBSCRIBE — watch a key for changes (*) |
| `unsub` | query | TCP | UNSUBSCRIBE — stop watching a key (*) |
| `ntf` | query | TCP | NOTIFY — push value change to subscriber (*) |

(*) `sub`, `unsub`, and `ntf` are defined in the T1 protocol layer (`nodus_tier1.c`) but
are not yet dispatched in the server. Inter-node value subscriptions currently use T2
`listen`/`value_changed` via TCP replication.

### CBOR Field Reference

**PING** (`"q": "ping"`):
```
{"t": txn, "y": "q", "q": "ping", "a": {"id": <bytes[64]>}}
```

**PONG** (`"q": "pong"`):
```
{"t": txn, "y": "r", "q": "pong", "r": {"id": <bytes[64]>}}
```

**FIND_NODE** (`"q": "fn"`):
```
{"t": txn, "y": "q", "q": "fn", "a": {"target": <bytes[64]>}}
```

**NODES_FOUND** (`"q": "fn_r"`):
```
{"t": txn, "y": "r", "q": "fn_r", "r": {"nodes": [
    {"id": <bytes[64]>, "ip": "1.2.3.4", "up": 4000, "tp": 4001}, …
]}}
```

**STORE_VALUE** (`"q": "sv"`):
```
{"t": txn, "y": "q", "q": "sv", "a": {"val": <bytes(serialized NodusValue)>}}
```

The `val` field contains a CBOR-serialized `NodusValue` (see Section 6).

### Kademlia Routing

- **Key space:** 512 bits (SHA3-512)
- **Buckets:** 512 (one per bit of key space)
- **Bucket size (k):** 8 nodes
- **Parallel lookups (α):** 3
- **DHT replication:** K=8 closest nodes (via `nodus_routing_find_closest()`)
- **Channel replication (R):** 3 (via consistent hash ring, separate system)
- **Distance metric:** XOR of 64-byte node IDs
- **Stale threshold:** `NODUS_ROUTING_STALE_SEC` (3600s) — entries older than 1h excluded from `find_closest()`
- **Bucket refresh:** Every `NODUS_BUCKET_REFRESH_SEC` (900s), stale buckets refreshed via FIND_NODE with random key (`nodus_key_random_in_bucket()`)

**Bucket index** = count of leading zero bits in `XOR(self_id, peer_id)`. Peers with a
longer common prefix (closer in key space) go into higher-numbered buckets.

**Dead peer removal:** When the cluster module marks a peer DEAD (60s timeout), `nodus_routing_remove()` is called. Dead peers can recover via the PING handler calling `nodus_cluster_on_pong()`.

**Eviction policy:** LRU — when a bucket is full, the least-recently-seen entry is replaced
by the new peer.

### Node Discovery Flow

1. Server starts with seed nodes configured in `/etc/nodus.conf`
2. Sends UDP PING to each seed node
3. On PONG, learns the seed's real node_id (replaces IP-hash placeholder)
4. Inserts seed into routing table
5. Sends FIND_NODE(self_id) to discover nearby peers
6. Iteratively queries returned peers until no closer nodes are found

---

## 5. Tier 2 Protocol — Client-to-Server

Tier 2 handles all client-facing operations over TCP. Every T2 session begins with a
Dilithium5 challenge-response authentication handshake.

### Authentication Handshake

```
Client                              Server
  │                                    │
  │─── HELLO(pk, fp, v=2) ───────────►│  1. Client sends Dilithium5 public key,
  │                                    │     fingerprint (SHA3-512 of pk), proto version
  │                                    │     Server verifies fp == SHA3-512(pk)
  │◄── CHALLENGE(nonce) ──────────────│  2. Server generates 32-byte random nonce
  │                                    │
  │─── AUTH(SIGN(nonce, sk)) ─────────►│  3. Client signs nonce with secret key
  │                                    │     Server verifies signature with pk
  │◄── AUTH_OK(token, kpk, spk, sig) ─│  4. Server returns:
  │                                    │     - 32-byte session token
  │                                    │     - Kyber1024 public key (kpk)
  │                                    │     - Server Dilithium5 public key (spk)
  │                                    │     - Dilithium5 signature over (kpk || nonce)
  │                                    │     Client verifies sig with spk (MITM protection)
  │─── KEY_INIT(ct, nonce_c) ─────────►│  5. Client encapsulates to server's Kyber PK
  │◄── KEY_ACK(nonce_s) ──────────────│  6. Shared secret established
  │    ═══ AES-256-GCM channel ═══    │     All subsequent traffic encrypted
```

**HELLO** (`"q": "hello"`):
```
{"t": txn, "y": "q", "q": "hello", "a": {"pk": <bytes[2592]>, "fp": <bytes[64]>}}
```

**CHALLENGE** (`"q": "challenge"`):
```
{"t": txn, "y": "r", "q": "challenge", "r": {"nonce": <bytes[32]>}}
```

**AUTH** (`"q": "auth"`):
```
{"t": txn, "y": "q", "q": "auth", "a": {"sig": <bytes[4627]>}}
```

**AUTH_OK** (`"q": "auth_ok"`):
```
{"t": txn, "y": "r", "q": "auth_ok", "r": {
    "tok": <bytes[32]>,
    "kpk": <bytes[1568]>,       // Server's Kyber1024 public key
    "spk": <bytes[2592]>,       // Server's Dilithium5 public key
    "kpk_sig": <bytes[4627]>    // Dilithium5 sign(kpk || nonce, server_sk)
}}
```
The `kpk_sig` binds the Kyber public key to this auth session via the challenge nonce,
preventing MITM key substitution. Client MUST verify this signature before encapsulating.
Legacy servers (proto < v0.10.10) omit `spk` and `kpk_sig` — client logs a warning.

### Authenticated DHT Operations

All operations below require a valid session token (`"tok"` field).

| Method | Direction | Description |
|--------|-----------|-------------|
| `put` | C→S | Store a signed value |
| `get` | C→S | Retrieve latest value by key |
| `get_all` | C→S | Retrieve all values for a key (all writers) |
| `get_batch` | C→S | Batch get_all for N keys (max 32) in one request |
| `cnt_batch` | C→S | Batch count + has_mine for N keys (no data transfer) |
| `listen` | C→S | Subscribe to value changes on a key |
| `unlisten` | C→S | Unsubscribe from a key |
| `ping` | C→S | Keepalive |
| `servers` | C→S | Get list of cluster nodes |
| `put_ok` | S→C | PUT acknowledgement |
| `result` | S→C | GET result (single value) |
| `result` (multi) | S→C | GET_ALL result (value array) |
| `result` (batch) | S→C | GET_BATCH result (per-key value arrays) |
| `result` (counts) | S→C | CNT_BATCH result (per-key count + has_mine) |
| `listen_ok` | S→C | LISTEN acknowledgement |
| `pong` | S→C | Keepalive response |
| `value_changed` | S→C | Push notification: watched key updated |
| `error` | S→C | Error response with code and message |

**PUT** (`"q": "put"`):
```
{"t": txn, "y": "q", "q": "put", "tok": <bytes[32]>, "a": {
    "k": <bytes[64]>,        # SHA3-512 key hash
    "d": <bytes>,            # Data payload
    "type": <uint>,          # 1=ephemeral, 2=permanent
    "ttl": <uint>,           # Seconds (0=permanent)
    "vid": <uint64>,         # Value ID
    "seq": <uint64>,         # Sequence number
    "sig": <bytes[4627]>     # Dilithium5 signature
}}
```

**GET** (`"q": "get"`):
```
{"t": txn, "y": "q", "q": "get", "tok": <bytes[32]>, "a": {"k": <bytes[64]>}}
```

**VALUE_CHANGED** (push, `"q": "value_changed"`):
```
{"t": 0, "y": "q", "q": "value_changed", "a": {
    "k": <bytes[64]>,
    "val": <bytes(serialized NodusValue)>
}}
```

**GET_BATCH** (`"q": "get_batch"`) — v0.9.20+:
```
{"t": txn, "y": "q", "q": "get_batch", "tok": <bytes[32]>, "a": {
    "ks": [<bytes[64]>, <bytes[64]>, ...]    # Array of key hashes (max 32)
}}
```
Response:
```
{"t": txn, "y": "r", "q": "result", "r": {"batch": [
    {"k": <bytes[64]>, "vs": [<serialized_value>, ...]},
    {"k": <bytes[64]>, "vs": []},
    ...
]}}
```

**CNT_BATCH** (`"q": "cnt_batch"`) — v0.9.20+:
```
{"t": txn, "y": "q", "q": "cnt_batch", "tok": <bytes[32]>, "a": {
    "ks": [<bytes[64]>, <bytes[64]>, ...],   # Array of key hashes (max 32)
    "fp": <bytes[64]>                         # Caller fingerprint for has_mine check
}}
```
Response:
```
{"t": txn, "y": "r", "q": "result", "r": {"counts": [
    {"k": <bytes[64]>, "c": <uint>, "my": <bool>},
    {"k": <bytes[64]>, "c": <uint>, "my": <bool>},
    ...
]}}
```

**ERROR** (`"y": "e"`):
```
{"t": txn, "y": "e", "r": {"code": <uint>, "msg": <string>}}
```

### Channel Operations

| Method | Direction | Description |
|--------|-----------|-------------|
| `ch_create` | C→S | Create a new channel (UUID v4) |
| `ch_post` | C→S | Post a message to a channel |
| `ch_get` | C→S | Get posts from a channel (since seq) |
| `ch_sub` | C→S | Subscribe to channel notifications |
| `ch_unsub` | C→S | Unsubscribe from a channel |
| `ch_ntf` | S→C | Push: new post in subscribed channel |
| `ch_rep` | S→S | Inter-node channel post replication |

**CH_POST** (`"q": "ch_post"`):
```
{"t": txn, "y": "q", "q": "ch_post", "tok": <bytes[32]>, "a": {
    "ch": <bytes[16]>,       # Channel UUID
    "pid": <bytes[16]>,      # Post UUID
    "d": <bytes>,            # Post body (UTF-8, max 4000 chars)
    "ts": <uint64>,          # Author's timestamp
    "sig": <bytes[4627]>     # Dilithium5 signature
}}
```

### Pre-Auth Dispatch

The server allows certain messages without authentication:

- `hello` / `auth` — the handshake itself
- `sv` — inter-node DHT value replication (verified by value signature)
- `ch_rep` — inter-node channel post replication

All other methods return `NODUS_ERR_NOT_AUTHENTICATED` (code 1) if the session is not
authenticated.

---

## 6. Core Data Structures

### NodusValue

The fundamental unit of DHT storage. Every value is cryptographically signed by its owner.

```c
typedef struct {
    nodus_key_t     key_hash;       // SHA3-512 of the logical key (64 bytes)
    uint64_t        value_id;       // Writer-specific identifier
    uint8_t        *data;           // Payload (up to 1 MB)
    size_t          data_len;
    nodus_value_type_t type;        // EPHEMERAL (0x01) or PERMANENT (0x02)
    uint32_t        ttl;            // Seconds until expiry (0 = permanent)
    uint64_t        created_at;     // Unix timestamp
    uint64_t        expires_at;     // 0 if permanent
    uint64_t        seq;            // Sequence number for updates
    nodus_pubkey_t  owner_pk;       // Dilithium5 public key (2592 bytes)
    nodus_key_t     owner_fp;       // SHA3-512(owner_pk) (64 bytes)
    nodus_sig_t     signature;      // Dilithium5 signature (4627 bytes)
} nodus_value_t;
```

**Signature payload** (concatenation, signed with Dilithium5):
```
key_hash    (64 bytes)
data        (variable)
type        (1 byte)
ttl         (4 bytes, LE)
value_id    (8 bytes, LE)
seq         (8 bytes, LE)
```

**CBOR serialization** (10-field map):
```
{"key": <bytes[64]>, "vid": <uint64>, "data": <bytes>, "type": <uint>,
 "ttl": <uint>, "created": <uint64>, "seq": <uint64>, "owner": <bytes[2592]>,
 "owner_fp": <bytes[64]>, "sig": <bytes[4627]>}
```

A typical serialized value is ~7.3 KB due to Dilithium5 key/signature sizes.

### nodus_identity_t

A node's cryptographic identity — derived from a Dilithium5 keypair.

```c
typedef struct {
    nodus_pubkey_t pk;                          // 2592 bytes
    nodus_seckey_t sk;                          // 4896 bytes
    nodus_key_t    node_id;                     // SHA3-512(pk) = 64 bytes
    char           fingerprint[129];            // Hex representation of node_id
} nodus_identity_t;
```

Total size: 7,681 bytes. Identities can be generated randomly, derived deterministically
from a 32-byte seed (BIP39 compatible), or loaded from files (`nodus.pk` + `nodus.sk`).

### nodus_key_t

The universal 512-bit key used throughout the system:

```c
typedef struct {
    uint8_t bytes[64];  // SHA3-512 = 64 bytes
} nodus_key_t;
```

Used for: node IDs, DHT key hashes, fingerprints, XOR distance calculations.

### Routing Table

```c
typedef struct {
    nodus_key_t    self_id;
    nodus_bucket_t buckets[512];    // 512 buckets
} nodus_routing_t;

typedef struct {
    struct { nodus_peer_t peer; bool active; } entries[8];  // k=8
    int count;
} nodus_bucket_t;
```

### Channel Post

```c
typedef struct {
    uint8_t     channel_uuid[16];   // UUID v4
    uint32_t    seq_id;             // Assigned by primary node
    uint8_t     post_uuid[16];      // UUID v4
    nodus_key_t author_fp;          // SHA3-512(author_pk)
    uint64_t    timestamp;          // Author's claimed time
    uint64_t    received_at;        // Server receive time
    char       *body;               // UTF-8, max 4000 chars
    size_t      body_len;
    nodus_sig_t signature;          // Dilithium5 signature
} nodus_channel_post_t;
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1 | `NOT_AUTHENTICATED` | No valid session or token |
| 2 | `NOT_FOUND` | Key not found in DHT |
| 3 | `INVALID_SIGNATURE` | Dilithium5 verification failed |
| 4 | `RATE_LIMITED` | Too many operations (60 puts/min) |
| 5 | `TOO_LARGE` | Value exceeds 1 MB or post exceeds 4000 chars |
| 6 | `TIMEOUT` | Operation timed out |
| 7 | `PROTOCOL_ERROR` | Unknown method or malformed message |
| 8 | `INTERNAL_ERROR` | Server-side failure |
| 10 | `CHANNEL_NOT_FOUND` | Channel UUID not registered |
| 11 | `NOT_RESPONSIBLE` | Node not in responsible set for channel |
| 12 | `RING_MISMATCH` | Hash ring version conflict |

---

## 7. Cryptography

All cryptographic operations use post-quantum algorithms from the `shared/crypto/` library.

### Dilithium5 (ML-DSA-87)

NIST Category 5 post-quantum digital signature scheme. Used for:

- **Value signing** — every DHT value carries a Dilithium5 signature that proves ownership
- **Client authentication** — 3-step challenge-response handshake
- **Channel post signing** — authors sign their posts
- **Kyber PK binding** — server signs its Kyber public key in AUTH_OK to prevent MITM

| Parameter | Size |
|-----------|------|
| Public key | 2,592 bytes |
| Secret key | 4,896 bytes |
| Signature | 4,627 bytes |
| Seed | 32 bytes |

**API** (`nodus_sign.c`):
```c
int nodus_sign(nodus_sig_t *sig, const uint8_t *data, size_t len, const nodus_seckey_t *sk);
int nodus_verify(const nodus_sig_t *sig, const uint8_t *data, size_t len, const nodus_pubkey_t *pk);
```

Wraps `qgp_dsa87_sign()` / `qgp_dsa87_verify()` from `shared/crypto/`.

### SHA3-512

Used for all hashing throughout the system:

- **Node IDs** — `node_id = SHA3-512(public_key)`
- **Fingerprints** — human-readable hex of node_id (128 hex chars)
- **DHT key hashes** — `key_hash = SHA3-512(raw_key)` before storage/lookup
- **Hash ring positions** — `SHA3-512(channel_uuid)` for ring placement

```c
int nodus_hash(const uint8_t *data, size_t len, nodus_key_t *hash_out);
int nodus_fingerprint(const nodus_pubkey_t *pk, nodus_key_t *fp_out);
```

### Identity Generation

Two modes:

1. **Random** — `qgp_dsa87_keypair()` generates a fresh random keypair
2. **Seed-based** — `qgp_dsa87_keypair_derand(pk, sk, seed)` produces a deterministic
   keypair from a 32-byte seed. Compatible with BIP39 mnemonic derivation. Produces
   identical keys to OpenDHT-PQ's `pqcrystals_dilithium5_ref_keypair_from_seed()`.

Identity files on disk:
- `nodus.pk` — public key (2,592 bytes, binary)
- `nodus.sk` — secret key (4,896 bytes, binary)
- `nodus.fp` — fingerprint (128 hex chars + newline)

### Shielded ZK verify stack (Phase-C C1, 2026-07-21 — linked, not yet called)

The server-side (non-WIN32) build compiles the pinned shielded-pool STARK/FRI
verify stack from `shared/crypto/zk` into `libnodus.a` (12 files: wire codec
v2 + FRI verifier + SHA3-512 transcript/sponge + Merkle-MMCS + Goldilocks
field). Entry point: `dnac_fri_verify_wire_shielded` — verifies a shielded
proof's WIRE bytes against the consensus-pinned FRI params
(`shielded_fri_params.h`: log_blowup 2, 100 queries, 16-bit query-PoW →
216-bit conjectured) and the pinned committed trace height (2^11).

- **Status:** LINKAGE ONLY. No witness code calls it yet — the witness verify
  hook (admission + wire-recomputed publics + `tx_binding` check) is Phase-C
  C2 (`dnac/docs/plans/2026-07-17-dm-s6-roadmap.md`). Consensus behavior is
  unchanged by C1.
- **M5 gate:** the unpinned `dnac_fri_verify_wire` (trusts wire params —
  test-only) is compiled ONLY under `DNAC_ZK_ENABLE_TEST_WIRE`, which only
  the zk standalone Makefile defines; `nm libnodus.a` shows no such symbol.
- **Test:** `test_zk_link` pulls the full verify chain out of the archive
  (missing-source = link error) and pins the six shielded params.
- Prover-side zk sources (client/wallet) are NOT in nodus.

---

## 8. Cluster Membership

Nodus uses heartbeat-based cluster membership for
cluster membership management and leader election.

### Purpose

- **Cluster membership** — track which nodes are alive, suspect, or dead
- **Leader election** — deterministic: lowest alive node_id is leader
- **Hash ring sync** — add/remove nodes from the consistent hash ring as their state changes

### Node States

```c
typedef enum {
    NODUS_NODE_ALIVE   = 0,   // Responding to heartbeats
    NODUS_NODE_SUSPECT = 1,   // No response for 30s
    NODUS_NODE_DEAD    = 2    // No response for 60s
} nodus_node_state_t;
```

### Heartbeat Protocol

1. Every **10 seconds** (`NODUS_CLUSTER_HEARTBEAT_SEC`), each node sends UDP PING to all
   non-dead peers
2. On PONG, the peer's `last_seen` timestamp is updated
3. On each tick, peer health is evaluated:
   - `< 30s` since last seen → **ALIVE**
   - `30-60s` since last seen → **SUSPECT**
   - `> 60s` since last seen → **DEAD** (removed from hash ring, no more pings)

### Leader Election

Leader = lowest `node_id` (lexicographic comparison of 64-byte keys) among all ALIVE nodes
plus self. Re-elected whenever a peer's state changes. The leader's `view` number increments
on each leadership change.

### Seed Node Discovery

Seed nodes are configured by IP:port. On startup, their node_ids are unknown — a placeholder
`SHA3-512(ip_string)` is used. When the seed responds to PING with its real node_id in the
PONG, the cluster module:

1. Finds the peer by IP + port match
2. Replaces the placeholder node_id with the real one
3. Updates the hash ring (remove old, add new)

### DHT Pubkey Registry

Every nodus server publishes its identity to the DHT key `"nodus:pk"` with a 10-minute TTL.
This allows any node or client to discover all active servers via `GET_ALL("nodus:pk")`.
The witness roster for DNAC BFT consensus is built from this registry.

**Published payload** (CBOR map, Dilithium5-signed):
```
{ "id": <node_id[64]>, "pk": <dilithium5_pk[2592]>, "ip": "x.x.x.x",
  "port": <witness_port>, "kpk": <kyber1024_pk[1568]> }
```

The `get_servers()` response also includes a 16-byte Dilithium fingerprint prefix
per server (`"fp"` field), enabling TOFU key caching on the client side.

---

## 9. Channels & Replication (v0.8.0+)

### Channel Model

Channels provide ordered, multi-writer messaging over a dedicated TCP 4003 port.
All post traffic uses TCP 4003 — no DHT PUT/GET for posts. Channel metadata (name,
description, creator) remains on DHT.

**Operations:**
- **Create** — register a UUID v4 channel on the server, announce nodes to DHT
- **Post** — submit a signed message (max 4,000 UTF-8 chars), server assigns `received_at`
- **Get Posts** — paginated retrieval (`since_received_at`, `max_count`)
- **Subscribe** — real-time push notifications for new posts

### Architecture: PRIMARY/BACKUP

Each channel has exactly 3 responsible nodes determined by the consistent hash ring:

```
Client → TCP 4003 → PRIMARY node (ring position [0])
                        ├→ push to subscribed clients (ch_post_notify)
                        ├→ replicate to BACKUP-1 (TCP 4003: ch_rep)
                        └→ replicate to BACKUP-2 (TCP 4003: ch_rep)
```

- **PRIMARY** — accepts client posts, verifies signatures, stores, broadcasts, replicates
- **BACKUPs** — store replicated posts, serve reads if PRIMARY is down
- **Role assignment** — deterministic via `SHA3-512(channel_uuid)` clockwise in hashring

Node discovery: clients GET `SHA3-512("dna:channel:nodes:" + raw_uuid)` from DHT to find
the ordered list of responsible nodes. Fallback: connect to current DHT server on port 4003.

### Modular Implementation

The channel system is split into 4 modules in `nodus/src/channel/`:

| Module | File | Responsibility |
|--------|------|---------------|
| **Channel Server** | `nodus_channel_server.c/h` | TCP 4003 listener, session management, client/node auth, message dispatch |
| **PRIMARY** | `nodus_channel_primary.c/h` | Post handling, signature verification, DHT announcement, subscriber broadcast |
| **Replication** | `nodus_channel_replication.c/h` | BACKUP replication, hinted handoff (SQLite, 24h TTL, 30s retry), incremental sync |
| **Ring Management** | `nodus_channel_ring.c/h` | Heartbeat-based dead detection (15s interval, 45s timeout), ring version tracking |

**Key design principle:** The cluster module has NOTHING to do with channels. Ring management uses
TCP 4003 heartbeats only. The hashring is populated from Kademlia routing, not cluster peers.

### Storage

Channel data is stored in a separate SQLite database (`channels.db`):

- **Per-channel tables** — each channel gets its own table named `channel_<uuid_hex>` with
  columns: `seq_id`, `post_uuid`, `author_fp`, `timestamp`, `body`, `signature`, `received_at`
- **hinted_handoff** — replication queue for failed cross-node deliveries (target_fp,
  channel_uuid, post data, retry_count, created_at)

Posts are deduplicated by a unique index on `post_uuid` per channel table — replicated
posts from peers are stored idempotently.

### Hash Ring Placement

Channel-to-node assignment uses consistent hashing:

1. `ring_position = SHA3-512(channel_uuid)`
2. Binary search the sorted ring for the first member with `node_id >= ring_position`
3. Collect R (=3) consecutive members clockwise (wrapping around)
4. These R nodes are the **responsible set**: [0]=PRIMARY, [1]=BACKUP-1, [2]=BACKUP-2

```c
int nodus_hashring_responsible(const nodus_hashring_t *ring,
                                const uint8_t *channel_uuid,
                                nodus_responsible_set_t *result);
```

### Cross-Node Replication

When the PRIMARY node receives a channel post:

1. Verifies author signature (Dilithium5)
2. Stores it locally (SQLite, assigns `received_at` timestamp)
3. Pushes `ch_post_notify` to ALL subscribed clients (user experience first)
4. Sends `ch_rep` to each BACKUP node via their TCP 4003 channel connection
5. If a BACKUP is unreachable, queues in **hinted handoff** (SQLite, 24h TTL)

### Ring Change Handling

When a node joins/leaves the cluster, the hashring changes:

1. Ring management detects dead node (45s timeout) or new node (heartbeat received)
2. Server pushes `ch_ring_changed` to all subscribed clients with new ring version
3. Client disconnects from old PRIMARY and reconnects to new PRIMARY
4. On reconnect, client issues `ch_get(since=last_received_at)` to catch up missed posts

**Hinted handoff retry** runs every 30 seconds (`NODUS_HINTED_RETRY_SEC`), querying distinct
node_ids and looking up current IP:port via the routing table. Successfully delivered entries
are deleted; failed entries have their retry count incremented.

---

## 10. Server Architecture

### Event Loop

The server uses a single-threaded, event-driven architecture based on Linux `epoll`
(edge-triggered):

```c
while (srv->running) {
    nodus_tcp_poll(&srv->tcp, 100);              // TCP 4001 events (100ms timeout)
    nodus_udp_poll(&srv->udp);                   // UDP 4000 datagrams (non-blocking)
    nodus_channel_server_poll(&srv->ch_server, 50); // TCP 4003 channel events
    nodus_cluster_tick(&srv->cluster);                 // Heartbeats + health checks
    dht_find_value_tick(srv);                    // Async FIND_VALUE state machines
    dht_republish(srv);                          // Periodic value republish (batch)
    dht_republish_tick(srv);                     // Republish connection timeouts
    dht_storage_cleanup(srv);                    // Expired value removal (hourly)
    dht_bucket_refresh(srv);                     // Routing table refresh (15 min)
    dht_hinted_retry(srv);                       // DHT hinted handoff retry
    nodus_channel_server_tick(&srv->ch_server, now_ms); // Channel session timeouts
    nodus_ch_replication_retry(&srv->ch_replication, now_ms); // Channel hinted handoff
    nodus_ch_ring_tick(&srv->ch_ring, now_ms);   // Ring heartbeat + dead detection
}
```

### Session Management

Each TCP 4001 connection is assigned a **session** (`nodus_session_t`) with:

- Authentication state (nonce, public key, fingerprint, token)
- Active DHT LISTEN subscriptions (up to 128 keys per session)
- Rate limiting state (60 puts per minute window)

Sessions are cleared on disconnect. The server supports up to `NODUS_MAX_SESSIONS`
concurrent clients.

**Channel sessions** (TCP 4003) are managed separately by `nodus_channel_server_t`:
- Client sessions (`nodus_ch_client_session_t`): auth state, channel subscriptions, rate limiting
- Node sessions (`nodus_ch_node_session_t`): inter-node replication connections
- Both use Dilithium5 challenge-response auth on TCP 4003

### Message Dispatch

TCP frames are dispatched through `dispatch_t2()`:

1. **Decode** the CBOR payload as a T2 message
2. **Pre-auth check**: if session is not authenticated, only `hello`, `auth`, `sv`
   (inter-node store, rate-limited: 200/s), and `fv` (inter-node FIND_VALUE, rate-limited: 100/s)
   are allowed. Channel operations (`ch_rep`, `ch_post`, etc.) go through TCP 4003, not 4001.
3. **Token verification**: authenticated requests must carry a valid session token
4. **Handler dispatch**: method name → handler function (`handle_t2_put`, `handle_t2_get`, etc.)

If T2 decode fails, a fallback T1 decode is attempted for inter-node `sv` (STORE_VALUE)
messages that arrive on the TCP port.

### Configuration

Server configuration via JSON file (default: `/etc/nodus.conf`):

```json
{
    "bind_ip": "0.0.0.0",
    "udp_port": 4000,
    "tcp_port": 4001,
    "ch_port": 4003,
    "identity_path": "/var/lib/nodus",
    "data_path": "/var/lib/nodus",
    "seed_nodes": ["161.97.85.25", "156.67.24.125", "156.67.25.251"],
    "seed_ports": [4000, 4000, 4000]
}
```

**Ports:**
- **UDP 4000** — Kademlia peer discovery (Tier 1)
- **TCP 4001** — Client DHT operations + auth (Tier 2)
- **TCP 4002** — Inter-node replication (Tier 1 TCP)
- **TCP 4003** — Channel system: client posts + inter-node replication (dedicated)

### Inter-node dialer authentication (TCP 4002, v0.18.11)

The acceptor authenticates the dialer via a Dilithium5 challenge/response. The
**dialer** in turn authenticates the acceptor's Kyber public key before
encapsulating to it — otherwise an active MITM on the (plaintext) handshake could
substitute its own key and own the resulting channel key, making every downstream
AEAD property moot. Three gates, all **fail-closed**, on both dialer paths (the
inter-node session and the DHT batch-forward):

1. **Downgrade-close** — if this node has a Kyber identity, an `auth_ok` missing
   `kyber_pk` / `kpk_sig` / `server_pk` is refused. It never falls through to the
   plaintext branch, so an attacker cannot force cleartext by stripping a field.
2. **Signature** — `kpk_sig` must verify over `(kyber_pk ‖ challenge_nonce)` under
   `server_pk`. The dialer therefore **retains the challenge nonce** it signed
   (previously it was signed and discarded, so the binding was uncheckable).
3. **Identity pin** — `fingerprint(server_pk)` must equal the `node_id` the dialer
   believed it was calling, recorded at connect time on the connection
   (`expected_peer_id`, deliberately distinct from the verified `peer_id`). Gate 2
   alone only proves the triple is *self-consistent* — an attacker signs its own
   key with its own identity and passes. The pin is what binds the channel to the
   intended peer.

On pin mismatch the dialer **fails closed and alarms**; it does **not** re-resolve
the identity, because FIND_NODE data is unsigned and re-pinning at attack time
would let the same adversary both trigger and answer the mismatch. Recovery is via
authenticated discovery refresh. Trust assumption: the routing-table `node_id`
used as the pin reference is trusted-discovery (adversarial UDP-4000 Kademlia
injection is out of scope, consistent with the honest-cluster-membership
assumption). A peer that legitimately rotates its identity is refused until
routing refreshes — a bounded replication-liveness gap; witness BFT (4004) carries
no channel crypto and is unaffected.

Data is stored in:
- `<data_path>/nodus.db` — DHT value storage (SQLite)
- `<data_path>/channels.db` — Channel post storage (SQLite)
- `<identity_path>/nodus.pk`, `nodus.sk`, `nodus.fp` — Node identity

---

## 11. Client SDK

### Public API

The client SDK (`nodus/nodus.h`) provides a complete API for applications:

```c
// Lifecycle
int  nodus_client_init(nodus_client_t *client, const nodus_client_config_t *config,
                        const nodus_identity_t *identity);
int  nodus_client_connect(nodus_client_t *client);
int  nodus_client_poll(nodus_client_t *client, int timeout_ms);
bool nodus_client_is_ready(const nodus_client_t *client);
void nodus_client_close(nodus_client_t *client);

// DHT
int nodus_client_put(…);           // Store a signed value
int nodus_client_get(…);           // Retrieve latest value
int nodus_client_get_all(…);       // Retrieve all values for key
int nodus_client_listen(…);        // Subscribe to value changes
int nodus_client_unlisten(…);      // Unsubscribe
int nodus_client_get_servers(…);   // Get cluster node list

// Channels
int nodus_client_ch_create(…);     // Create channel
int nodus_client_ch_post(…);       // Post to channel
int nodus_client_ch_get_posts(…);  // Get posts (paginated)
int nodus_client_ch_subscribe(…);  // Subscribe to channel
int nodus_client_ch_unsubscribe(…);// Unsubscribe
```

### Connection States

```
DISCONNECTED → CONNECTING → AUTHENTICATING → READY
                                                │
                                                ▼ (on disconnect)
                                          RECONNECTING ──► CONNECTING
                                                ▲                │
                                                └────────────────┘
                                              (exponential backoff)
```

### Auto-Reconnect

When enabled (`config.auto_reconnect = true`), the client automatically reconnects on
disconnection:

1. Tries the next server in the configured list (round-robin failover)
2. Uses exponential backoff: 1s → 2s → 4s → … → 30s max
3. On successful reconnect, automatically re-subscribes all active LISTEN keys and
   channel subscriptions

### Callbacks

Three callback types for asynchronous events:

```c
// DHT value change (from LISTEN)
typedef void (*nodus_on_value_changed_fn)(const nodus_key_t *key,
                                           const nodus_value_t *val, void *user_data);
// Channel post notification
typedef void (*nodus_on_ch_post_fn)(const uint8_t channel_uuid[16],
                                     const nodus_channel_post_t *post, void *user_data);
// Connection state change
typedef void (*nodus_on_state_change_fn)(nodus_client_state_t old_state,
                                          nodus_client_state_t new_state, void *user_data);
```

### Singleton Pattern

For applications that need a single global client (e.g., the DNA Connect), the singleton
module (`nodus_singleton.c`) provides thread-safe access:

```c
int  nodus_singleton_init(const nodus_client_config_t *config, const nodus_identity_t *id);
int  nodus_singleton_connect(void);
nodus_client_t *nodus_singleton_get(void);
bool nodus_singleton_is_ready(void);
int  nodus_singleton_poll(int timeout_ms);
void nodus_singleton_close(void);
```

### Concurrent Request Model (v0.5.5+)

The client supports up to 16 concurrent in-flight requests on a single TCP connection.
Each request is dispatched by transaction ID (`txn_id`) and uses per-request malloc'd
buffers instead of a shared static buffer.

**Internal concurrency primitives:**
- `nodus_pending_t pending[16]` — per-request response slots matched by `txn_id`
- `pending_mutex` — protects slot allocation/deallocation
- `send_mutex` — serializes TCP writes (wbuf is not thread-safe)
- `poll_mutex` — serializes `epoll_wait` calls
- `_Atomic uint32_t next_txn` — lock-free transaction ID generation

**Request flow:**
1. Caller allocates buffer (`malloc(CLIENT_BUF_SIZE)`) and pending slot (`alloc_pending`)
2. Encodes CBOR request into buffer with unique `txn_id`
3. Sends via `send_request()` (mutex-protected TCP write)
4. Calls `wait_response(client, req, timeout)` — polls for this specific slot's `ready` flag
5. `client_on_frame()` dispatches incoming responses to matching pending slot by `txn_id`
6. Caller extracts result and frees slot (`free_pending`)

This eliminates the serialization bottleneck where message sends would queue behind
startup sync operations (previously 9-31s delay on Android).

---

## 12. Messenger Integration

The DNA Connect integrates Nodus through two convenience layers that bridge the
messenger's application-level concepts to the raw client SDK.

### nodus_ops — Operations Layer

**Source:** `messenger/dht/shared/nodus_ops.c`

Provides a simplified API that handles key hashing, value creation, signing, and listener
dispatch. Operations are thread-safe — the underlying nodus client supports concurrent
requests internally (up to 16 in-flight on a single TCP connection).

**Key functions:**

| Function | Description |
|----------|-------------|
| `nodus_ops_put(key, len, data, len, ttl, vid)` | Hash key → create value → sign → PUT |
| `nodus_ops_put_str(str_key, data, len, ttl, vid)` | String key variant |
| `nodus_ops_put_permanent(key, len, data, len, vid)` | Permanent (TTL=0) variant |
| `nodus_ops_get(key, len, &data, &len)` | Hash key → GET → extract data payload |
| `nodus_ops_get_str(str_key, &data, &len)` | String key variant |
| `nodus_ops_get_all(key, len, &vals, &lens, &count)` | GET_ALL → extract all payloads |
| `nodus_ops_get_all_str(str_key, &vals, &lens, &count)` | String key GET_ALL variant |
| `nodus_ops_get_all_with_ids(key, len, &vals, &lens, &vids, &count)` | GET_ALL with value IDs |
| `nodus_ops_get_all_str_with_ids(str_key, &vals, &lens, &vids, &count)` | String key variant with IDs |
| `nodus_ops_listen(key, len, callback, user_data, cleanup)` | Register LISTEN + local callback |
| `nodus_ops_cancel_listen(token)` | Cancel by token |
| `nodus_ops_cancel_all()` | Cancel all listeners |
| `nodus_ops_listen_count()` | Number of active listeners |
| `nodus_ops_is_listener_active(token)` | Check if listener is still active |
| `nodus_ops_is_ready()` | Check singleton connection state |
| `nodus_ops_value_id()` | Get current identity's value ID |
| `nodus_ops_fingerprint()` | Get current identity's fingerprint string |

**Listener dispatch:** The `nodus_ops_dispatch()` function is registered as the singleton's
`on_value_changed` callback. When a value change notification arrives, it iterates through
up to 1024 registered listener slots, matching by key hash and invoking the application
callback. Callbacks return `true` to stay subscribed or `false` to auto-cancel.

### nodus_init — Lifecycle Layer

**Source:** `messenger/dht/shared/nodus_init.c`

Manages the complete lifecycle of the Nodus client within the messenger:

| Function | Description |
|----------|-------------|
| `nodus_messenger_init(identity)` | Load config → resolve bootstrap nodes → singleton init → connect |
| `nodus_messenger_close()` | Cancel listeners → close singleton → clear identity |
| `nodus_messenger_reinit()` | Save identity → close → re-init (network change recovery) |
| `nodus_messenger_is_ready()` | Check connection state (initialized + connected) |
| `nodus_messenger_is_initialized()` | Check if init was called (regardless of connection) |
| `nodus_messenger_set_status_callback(cb, data)` | Register connection status callback |
| `nodus_messenger_wait_for_ready(timeout_ms)` | Blocking wait for connection |

**Bootstrap resolution:**
1. Try cached bootstrap nodes from SQLite reliability database (best 3 by success rate)
2. Fall back to hardcoded nodes from `dna_config.c`
3. Parse `IP:port` format, default port = 4001

**Identity storage:** The identity is stored as a stack-allocated value type (not
heap-allocated) to prevent ASAN leak reports — one of the motivations for the rewrite.

### Bootstrap Cache

**Source:** `messenger/dht/client/bootstrap_cache.c`

SQLite database tracking bootstrap node reliability. Records success/failure counts and
latency for each server endpoint. The `bootstrap_cache_get_best()` function returns the
top N nodes sorted by success rate, enabling faster reconnection to known-good servers.

### Migration

On first connect to the v5 network, the messenger performs a one-time republish of local
DHT data (profiles, name registrations, etc.) to the new Nodus cluster. This is controlled
by a flag file and runs in the engine's stabilization thread.

---

## 13. Deployment

### Production Cluster

Seven production nodes (US-1, EU-1..EU-6) — the single live cluster; details and deploy procedure in `nodus/docs/DEPLOY_RUNBOOK.md` and internal ops docs. (The 3-node "test cluster" table that used to sit here was the pre-2026-04 bring-up set.)

### Systemd Service

The shipped unit is `nodus/deploy/nodus.service`, reproduced here verbatim:

```ini
[Unit]
Description=Nodus - Post-Quantum DHT Server
Documentation=https://github.com/nocdem/dna
After=network-online.target
Wants=network-online.target
StartLimitBurst=3
StartLimitIntervalSec=300

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/nodus-server -c /etc/nodus.conf
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/nodus
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nodus
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

⚠ **`Restart=on-failure` is bounded, and the bound is a design constraint, not
a detail.** `StartLimitBurst=3` with `StartLimitIntervalSec=300` means the unit
may be restarted at most **three times in any 300-second window**; after that
systemd stops it **permanently** and a human must `systemctl start` it. (Both
directives live in `[Unit]`, which is where systemd reads the start rate limit
— placing them under `[Service]` would silently do nothing.)

The consequence is that **"exit and let the supervisor retry" is not a backoff
strategy in this deployment** — it is a budget of three attempts in five
minutes, after which the node is down until an operator intervenes, and it
would retire the node's DHT role along with its witness role. That is why the
witness's chain-database open **waits inside the process** instead of exiting
(O15L Faz 2, `nodus_witness.c:355-407`: `NODUS_W_DB_OPEN_ATTEMPTS = 3`, the
`NODUS_W_DB_BUSY_TIMEOUT_MS` budget divided per attempt, plus a fixed 250 ms
pause), and why a witness that cannot start runs **degraded rather than
fatal** (`nodus_server.c:6114-6169`). See §15, *Witness startup and
chain-database faults*.

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4000 | UDP | Kademlia discovery (T1 PING/PONG/FIND_NODE) |
| 4001 | TCP | Client connections (T2) + circuit relay |
| 4002 | TCP | Inter-node: replication, heartbeat, circuit forwarding |
| 4003 | TCP | Channels (soft-disabled 2026-03-28, port still listens) |
| 4004 | TCP | Witness BFT (T3) |

### Identity Management

On first start, if no identity exists at `identity_path`, the server generates a random
Dilithium5 keypair and saves it. The identity persists across restarts — the node_id
(SHA3-512 of the public key) is the node's permanent identifier in the DHT.

### Redeploy

Each server has a `/tmp/nodus-redeploy.sh` script that pulls latest code, rebuilds, installs
to `/usr/local/bin/`, and restarts the systemd service.

---

## 14. Testing

### Test Suite

~125 test source files / 200+ ctest entries today (see `nodus/CLAUDE.md` Test Coverage for the current map). The table below is the foundational-era snapshot:

| Test File | Module Tested | Test Count |
|-----------|---------------|------------|
| `test_wire.c` | Wire frame encode/decode | ~10 |
| `test_cbor.c` | CBOR encoder/decoder; RFC 8949 §3.1 signed-integer vectors, rejects, legacy pin (`cbor_decode_next` on `0x20` stays ERROR), `cbor_decode_skip_signed` negatives + parity with `cbor_decode_skip` (13 shapes + depth 33) | 26 |
| `test_tier1.c` | T1 protocol encode/decode | ~12 |
| `test_tier2.c` | T2 protocol encode/decode | ~18 |
| `test_value.c` | Value create/sign/verify/serialize | ~12 |
| `test_routing.c` | Kademlia routing table | ~14 |
| `test_storage.c` | SQLite DHT storage | ~10 |
| `test_identity.c` | Identity generation/save/load | ~8 |
| `test_hashring.c` | Consistent hash ring | ~10 |
| `test_channel_store.c` | Channel storage | ~10 |
| `test_tcp.c` | TCP transport | ~5 |
| `test_client.c` | Client SDK | ~8 |
| `test_server.c` | Server integration | ~7 |
| `test_tier3.c` | T3 (DNAC BFT) protocol encode/decode — 18 legacy sections + 8 cometbft envelope sections (R3 W3 C2b: method table incl. retired 28-34 → NULL/0, round trip × 5 verbs, strict `{m: bstr}` key set with a control first, ceiling at `m_cap` accepted through the real encoder AND through a hand-built frame, `m_cap+1` refused by the decoder's pass-2 cap (the hand-built frame is proven to fit first), verify wrong key, the universal negative-integer pin, the max_msg_size table, the MEASURED envelope overhead ≤ 8192, the mempool ceiling pin against `cmt_memr_get_channels`) | 26 |
| `test_cmt_net.c` | The transport glue over the witness peer table (R3 W3 C2b) — see the tests tree above; 8 cases | 8 |
| `test_witness_verify.c` | TX verification (hash, sig, balance) | ~10 |

### Integration Tests

Genesis Protocol harness (`tests/integration/stagef/stagef_up.sh`) runs
a 7-node localhost cluster end-to-end:
- Identity bootstrap, genesis commit, witness BFT round
- DHT replication (PUT/GET/LISTEN) across all 7 nodes
- Cross-node state_root convergence (7/7 identical proof)
- Failover / round skip / recovery paths

### Build & Run

```bash
cd nodus/build
cmake ..
make -j$(nproc)

# Run all tests
ctest --output-on-failure

# Run individual test
./test_wire
./test_tier2
```

---

## 15. Tier 3 Protocol — DNAC Witness (BFT Consensus)

The DNAC witness module is embedded in the Nodus server as an optional component. When
enabled via config, it provides the DNA Chain UTXO ledger with BFT consensus for
double-spend prevention.

### Protocol Overview

Tier 3 uses the same CBOR wire format as T1/T2 but with DNAC-specific method names:

| Method | Direction | Description |
|--------|-----------|-------------|
| `dnac_spend` | Client→Witness | Submit spend TX for BFT consensus |
| `dnac_nullifier` | Client→Witness | Check if nullifier is spent |
| `dnac_supply` | Client→Witness | Query supply state |
| `dnac_utxo` | Client→Witness | Query UTXOs by owner |
| `dnac_utxo_proof` | Client→Witness | Query UTXO existence proof |
| `dnac_ledger` | Client→Witness | Query ledger entry by hash |
| `dnac_ledger_range` | Client→Witness | Query ledger entries by range |
| `dnac_tx` | Client→Witness | Query full TX data by hash |
| `dnac_block` | Client→Witness | Query block by height |
| `dnac_block_range` | Client→Witness | Query block range |

### cometbft envelope verbs 35-39 and the transport glue (R3 W3 C2b, 2026-09-16 — protocol version 7)

The wave-1 Tendermint verbs 28-34 (field-by-field CBOR copies of the nine reactor messages,
with `shared/dnac/tm_bounds.h`) are RETIRED — deleted, the numbers never reused (D-16 rev 5).
The ported reactors hand the host MARSHALLED proto3 bytes per channel (`cmt_ps_send_fn`,
`cmt_conr_receive`, `cmt_memr_host_t.send`, `cmt_memr_receive`), so the tier-3 layer now
carries those bytes unchanged inside Nodus's own signed envelope: five ENVELOPE verbs, one per
channel, appended after 34. `NODUS_T3_BFT_PROTOCOL_VER` 6 → 7; a v6 node has no decoder for
them, so mixed v6/v7 operation is refused. Values 1-27 do not move. The dispatcher that routes
them (`nodus_witness_dispatch_t3` → `nodus_cmt_net_receive`) is package C2a's; until it lands
nothing in the running node sends or receives them.

| Verb | Method | Channel | Args | `m` ceiling | `nodus_t3_max_msg_size` |
|------|--------|---------|------|-------------|--------------------------|
| 35 | `w_cmt_state` | 0x20 State | `{m: bstr}` | `NODUS_T3_CMT_CONS_M_MAX` 1 048 576 (= `CMT_CONR_MAX_MSG_SIZE`, consensus/reactor.go:30) | CONS + 8192 |
| 36 | `w_cmt_data` | 0x21 Data | `{m: bstr}` | CONS | CONS + 8192 |
| 37 | `w_cmt_vote` | 0x22 Vote | `{m: bstr}` | CONS | CONS + 8192 |
| 38 | `w_cmt_bits` | 0x23 VoteSetBits | `{m: bstr}` | CONS | CONS + 8192 |
| 39 | `w_cmt_txs` | 0x30 Mempool | `{m: bstr}` | `NODUS_T3_CMT_TXS_M_MAX` 1 048 584 (= the mempool descriptor's RecvMessageCapacity, `cmt_memr_get_channels` at the default config) | TXS + 8192 |

Rules: `dec_w_cmt_args` demands EXACTLY `{m: bstr}` (missing / duplicate / extra key / non-bstr
→ −1) and caps `m` at the verb's class; `m` is ZERO-COPY into the decode buffer. Both ceilings
are `_Static_assert`-pinned to the reactors' own constants; `NODUS_T3_CMT_ENVELOPE_OVERHEAD`
8192 is a bound on the envelope's cost over `m`, and `test_tier3` MEASURES the real cost
(4 774 B for a maximal TXS frame). `nodus_t3_encode` signs into the CALLER's buffer (no
internal 1 MiB buffer) and `nodus_t3_verify` sizes its sign buffer from the verb's class for
35-39 and the 1 MB literal otherwise. Pass 1 of `nodus_t3_decode` still steps over `a` with
`cbor_decode_skip_signed`, and the negative-integer admission set is EMPTY (D-22 rev 3).

**The transport glue — `src/witness/nodus_witness_cmt_net.{h,c}`** is the C stand-in for
`p2p.Switch` / `p2p.Peer`: it fills BOTH reactors' host tables (`cmt_conr_host_t`,
`cmt_memr_host_t`, embedded in `nodus_cmt_net_t` because `cmt_memr_init` BORROWS its table by
pointer while `cmt_conr_init` copies) over the witness peer table `w->peers[]` — peer slot =
witness peer index, the same index in all three tables (`_Static_assert`-pinned). None of the
reference's p2p layer (ed25519 station-to-station handshake, X25519 MConnection) is ported —
PQ policy; the ML-DSA-87-signed witness mesh on port 4004 IS the transport. `send == try_send`
(deviation R3-A-1): build the header (version 7, sender `w->my_id`, chain id `w->v2_chain32`
— populated by the binding from the stored genesis document, an all-zero id is refused),
`nodus_t3_encode` with the server identity key, `nodus_tcp_send`. The peer-set scan
(`net_scan_peers`, ascending slot order, only once BOTH reactors are running — p2p/switch.go
`OnStart` starts every reactor before `acceptRoutine`) adds a slot that is up (connection AND
identified) to both reactors as a PERSISTENT mempool peer and removes a slot that went down or
reconnected. It runs in `nodus_cmt_net_tick` AND at the top of `nodus_cmt_net_receive`, because
the server dispatches every frame of a poll batch before its tick runs and the reference
InitPeer's a peer before its receive loop starts (switch.go:813-860). `stop_peer_for_error`
clears both reactors' tables at once but DEFERS the socket close to the next tick
(`close_pending[]`): a synchronous `nodus_tcp_disconnect` from inside `on_frame` would free the
connection `try_parse_frames` still reads after the callback (nodus_tcp.c:501-519) — the
reference tears the peer down on its own goroutines. Contract for the binding: call
`nodus_cmt_net_tick` from the server loop after the witness transport's poll, never from inside
a frame callback. The reactor's receive arena is a 64 MiB RUNWAY owned by the glue
(`NODUS_CMT_NET_RECV_ARENA_BYTES` ≈ 3 maximal blocks of parts), never reset (register R3-A-5,
reset policy = R3-C2), with one-shot warnings at 50 % and 90 % and an accessor for the live
test. Known residual: the deferred close compares connection POINTERS; a same-witness
reconnect inside one poll batch that reuses the freed address gets one spurious disconnect
(no memory unsafety). Test: `test_cmt_net` (9 cases since the W3 harness run — see "THE LIVE FLIP" below for the mempool InitPeer defect the ninth case pins).

### cometbft @709fd12b literal port — R1 types layer (`shared/dnac/cmt_*`, DORMANT, zero consumers)

On 2026-09-09 the Tendermint migration became a function-by-function port of cometbft
v0.38.19 (commit `709fd12b`, `BlockProtocol` 11) into C under `shared/dnac/cmt_*`
(operator rule: every rule is the reference's, nothing is re-derived). R1 (2026-09-10)
is the TYPES layer; nothing in the running node calls it yet, `NODUS_T3_BFT_PROTOCOL_VER`
is unchanged and the live consensus path is byte-untouched (the R1 diff adds files and
CMake lines only). Every function carries its `cometbft@709fd12b <file>:<lines>`
citation; the only substitutions are the APPROVED ones (Atlas umbrella rev 3, K-1 rev 2,
K-2): SHA3-512 / 64-byte digests in place of SHA-256, ML-DSA-87 keys (2592 B, `PublicKey`
oneof field 9) and signatures (4627 B), a 32-byte address = SHA3-512(pubkey)[0..31] — the
tree's own witness id (`nodus_chain_config_derive_witness_id`) — a 32-byte raw chain id, a
single host clock callback type (`cmt_now_fn`, reached only from `GenesisDoc.ValidateAndComplete`),
and Go panics turned into explicit `CMT_REJECT` (bad input) or `CMT_FAULT` (this process
cannot decide). Return contract everywhere: 0 / −1 / −2, as in `qc_v2.h`.

| Module | Reference (cometbft @709fd12b) | Holds |
|---|---|---|
| `cmt_tmhash.h` | `crypto/tmhash/hash.go`, `crypto/crypto.go` | `Sum`, `SumMany`, `SumTruncated` (32), `AddressHash` — the ONE address derivation; `CMT_OK/REJECT/FAULT` |
| `cmt_merkle.{h,c}` | `crypto/merkle` | RFC 6962 tree: `HashFromByteSlices`, proofs, empty root H("") |
| `cmt_bits.{h,c}` | `libs/bits/bit_array.go` | `BitArray` and its wire form; the decoder enforces `Elems == (Bits+63)/64` (the reference's one unguarded read) |
| `cmt_safemath.{h,c}` | `libs/math/safemath.go` | checked int64 arithmetic |
| `cmt_time.{h,c}` | `types/time/time.go` | `{seconds, nanos}`; `CMT_TIME_ZERO` = year one, NOT the Unix epoch; `WeightedMedian` (stable sort); `is_zero`; the `cmt_now_fn` type |
| `cmt_pb.{h,c}` | `proto/tendermint/*.pb.go` (generated) | proto3 encode/decode written from the GENERATED code's rules: omit-zero, `nullable=false` always-emit, `StdTime`, wrapper leaves; `MarshalDelimited` |
| `cmt_canonical.{h,c}` | `types/canonical.go` | CanonicalVote / CanonicalProposal — the signed bytes |
| `cmt_vote.{h,c}` | `types/vote.go`, `crypto/ed25519/ed25519.go` | Vote verify (ML-DSA-87), `ValidateBasic`, `SignAndCheckVote` through a host signer callback (adopts the signer's timestamp, vote.go:451) |
| `cmt_proposal.{h,c}` | `types/proposal.go` | Proposal, sign bytes, `ValidateBasic` |
| `cmt_part_set.{h,c}` | `types/part_set.go` | Part / PartSetHeader / PartSet, `AddPart`, reader, `ValidateHash` (64) |
| `cmt_block.{h,c}` | `types/block.go`, `types/test_util.go` | Header (14-leaf hash), Commit / CommitSig / ExtendedCommit, Data, EvidenceData, BlockID, Block, `MakeBlock` + `fillHeader`; re-derived `MaxHeaderBytes` 790, `MaxCommitOverheadBytes` 159, `MaxCommitSigBytes` 4685 |
| `cmt_validator_set.{h,c}` | `types/validator.go`, `validator_set.go` | Validator, ValidatorSet, proposer priority (128-bit average, `MaxTotalVotingPower` → FAULT), change sets, `ValidatorsHash`, `VerifyCommit` method; superseded the T1 `tm_proposer.c`, which R2 deleted |
| `cmt_results.{h,c}` | `types/results.go` | ABCIResults root + proof |
| `cmt_params.{h,c}` | `types/params.go` | ConsensusParams flat hash, `ValidateBasic` / `ValidateUpdate` / `Update`, defaults, pubkey type name `"mldsa87"` |
| `cmt_genesis.{h,c}` | `types/genesis.go` | GenesisDoc `ValidateAndComplete` (addresses checked or derived; chain id ≤ 32 bytes by operator decision), `ValidatorHash` |
| `cmt_validation.{h,c}` | `types/validation.go` | `VerifyCommit`: strictly more than 2/3, EVERY non-absent signature verified, NIL verified but not counted; batch path unreachable (no ML-DSA-87 batch verifier); light-client family out of scope |
| `cmt_evidence.{h,c}` | `types/evidence.go` | DuplicateVoteEvidence — bare bytes, FLAT hash, canonical pair order; `EvidenceList.Hash` (the header's EvidenceHash), `Has`; wrapper codec (branch 1 only) |
| `cmt_state.{h,c}` | `state/state.go` | `State`, `Copy`, `IsEmpty`, `MakeBlock`, `MedianTime` (weighted by voting power, address lookup), `MakeGenesisState` |

Not ported, by rule: the light-client / evidence-pool / blocksync callers (scope rule of
the local port map), batch verification, JSON and file I/O (host). Every departure from
the reference is enumerated in the local `tasks/reference-deviation-register.md` (rows
R1A-*, R1B-*, R1C-*, R1D-*). Vectors come from four independent Python oracles under
`shared/dnac/tests/` (`hashlib.sha3_512`, the K-1 rules, no port code imported) and from
the reference's own test files. Open questions and pending Atlas revisions at any given
time are tracked in the local deviation register and the fleet ledger under `tasks/`,
not here.

### cometbft @709fd12b literal port — R2 consensus core (`shared/dnac/cmt_*`, DORMANT, zero consumers)

R2 (2026-09-10/11) ports the `consensus/` package's state machine and everything it
calls, on top of R1. Still no runtime consumer: the reactor that would drive `cmt_cs` —
what a peer may send, what is gossiped, peer-state bookkeeping — is R3, and until it lands
the state machine has no caller in the running node. The live witness BFT is byte-untouched.
Naming follows the Go receiver: `consensus/state.go`'s receiver is `cs`, so its functions are
`cmt_cs_*`; `state/state.go`'s is `state`, so R1's `cmt_state_*` stands.

| Module | Reference (cometbft @709fd12b) | Holds |
|---|---|---|
| `cmt_vote_set.{h,c}` | `types/vote_set.go` | VoteSet: `AddVote` with the peer-maj23 path, `TwoThirdsMajority`, `HasTwoThirdsAny`, `SetPeerMaj23`, `BitArrayByBlockID`, `MakeCommit` / `MakeExtendedCommit`; peer table bounded at `CMT_PEER_MAX` = 128 (= `NODUS_T3_MAX_WITNESSES`, `_Static_assert`ed), block table at N+P |
| `cmt_hvs.{h,c}` | `consensus/types/height_vote_set.go` | HeightVoteSet: rounds as a sparse list (round −1 exists, as `SetRound`'s `SafeSubInt32(0,1)` makes it), `POLInfo`, the two-round peer catch-up ceiling, the vote-type gate |
| `cmt_round_state.h` | `consensus/types/round_state.go` | `RoundState`, the eight `RoundStepType` values, `String()` (the one String the port carries — it goes into the WAL) |
| `cmt_msgs.{h,c}` | `consensus/msgs.go:21-238`, `reactor.go:1527-1794` | `MsgToProto` / `MsgFromProto` for the nine reactor messages; STOPS before `ValidateBasic` (R3's gate) and says so |
| `cmt_wal.{h,c}` | `consensus/msgs.go:240-347`, `wal.go` record types | `WALToProto` / `WALFromProto`, the four record kinds (kind = oneof field 1-4), `TimedWALMessage` encode/decode — the bytes D-15 rev 5 stores; the file frame (CRC32c) is the host's SQLite row |
| `cmt_ticker.{h,c}` | `consensus/ticker.go` | the one-pending timeout ticker and its drop rule (:108-118); the host arms/disarms a timer |
| `cmt_privval.{h,c}` | `privval/file.go` (signing logic) | FilePV: `CheckHRS`, `signVote` / `signProposal` with reuse / timestamp-only / conflicting-data, `saveSigned` before the signature is used; the state file itself is the host's |
| `cmt_replay.{h,c}` | `consensus/replay.go:375-459, :545-565` | the handshake classifier as a pure function of five heights (one action per branch; the three panics are FAULT actions), the two app-hash asserts; InitChain / replayBlocks are R3 host |
| `cmt_config.h` | `config/config.go:979-1085` | `ConsensusConfig`, the reference defaults, the five timeout helpers; the CHAIN's values (D-4: 60 s idle, block-interval commit) are the host's at R3 |
| `cmt_cs.{h,c}` | `consensus/state.go`, `replay.go:39-167`, `libs/fail/fail.go` | the state machine: `updateToState`, the single-threaded event loop (the four sources txs / peer queue / internal queue / timer polled in that order from a ROTATING start — the source just served goes to the back, so a continuously-ready source is served within four working steps, the deterministic form of Go `select`'s uniform-random fairness; quit checked last; W1.5 closed deviation R2C-12, under which the R2 fixed order let a peer that kept the peer queue non-empty starve this node's own messages and its timeouts), `handleMsg` / `handleTimeout`, the `enter*` chain with its seven entry guards, `finalizeCommit`, `addProposalBlockPart`, `addVote` / `tryAddVote` (the conflict reaches the evidence pool on EVERY path, added or not), `signVote` / `voteTime`, `catchupReplay`; everything outside the package is a row in `cmt_cs_host_t`; three host-owned block slots; six `CMT_FAIL_POINT()`s under `QGP_FAULT_INJECT` |

Two rules R2 made explicit (both APPROVED Atlas records): a Go `panic` a PEER's input can
reach becomes `CMT_REJECT`, one that guards a NODE-LOCAL invariant becomes `CMT_FAULT` and
the node stops — every ported panic site says which and why (umbrella rev 4); and
`State.Version.Software` is the Nodus version, supplied to the build as
`CMT_SOFTWARE_VERSION` from `nodus_types.h` (the header refuses to compile without it).

Tests: 15 `test_cmt_*` binaries from R1 plus `test_cmt_vote_set`, `test_cmt_hvs`,
`test_cmt_msgs`, `test_cmt_wal`, `test_cmt_ticker`, `test_cmt_privval`, `test_cmt_replay`,
`test_cmt_cs_unit` (host-free), `test_cmt_cs` (39 whole-height scenarios ported from
`state_test.go` / `byzantine_test.go` / `mempool_test.go` over a deterministic host fixture,
`test_cmt_common.h` — R2-T2 added the ten `state_test.go` tests R2-T had left as "drivable, not
done", among them the two lock-safety tests and the one that checks vote extensions survive the
height boundary, so every `state_test.go` test a single-node fixture can drive is now ported and
the four that remain are listed in the file with the reason each), and `test_cmt_byzantine` (four independent state machines behind a
deterministic router, `test_cmt_multinode.h`: a byzantine proposer sends conflicting blocks
to a partitioned network, the partition heals, and every honest node commits the SAME block;
since R3 W3 P0 also the two part-set-bound obligation scenarios of `atlas-dec-247e5c0e…`,
driven by a byzantine proposer plus two forged validator signatures: with a Total above the
host's `parts_cap` every honest node refuses at setProposal, addVote/prevote and
enterPrecommit, signs a nil precommit and commits an honest block in round 1; with a Total
above `CMT_PART_SET_MAX_PARTS` plus forged precommits the enterCommit refusal parks the node
at COMMIT with no block, forever — safety only, because +2/3 precommits for a block a node
cannot obtain is beyond the fault threshold. Leaving round 0 in the first scenario needs a
timeout the driver's mock ticker never fires, so the driver gained a third rule, M16: an
honest node's timeout fires only after a full round in which no node stepped, no timer
fired and no message was queued anywhere — the discrete-event reading of "timeouts are
longer than message delays", with no Go line).
All build with zero warnings and run clean under ASan/UBSan. Each test file's header states
what it proves, what it requires, what it leaves behind and — at length — how it can report
success without exercising its subject; the byzantine suite's and the scenario suite's lists
are the honest statement of what is NOT yet measured (one byzantine node only, one
interleaving only, no link cut, the has-bits model chattier than the reactor's).

What running the suites found that reading did not, all fixed in R2: a NULL passed where
wave A's header requires a value (every commit path faulted); a validator-set borrow that
the in-place state copy overwrote (a late precommit at an epoch boundary would have been
verified against the NEXT height's set); a proposal pointer into a freed queue element;
and — from the byzantine test — a conflicting vote that was ADDED (peer-maj23 path) was
never reported to the evidence pool, so an equivocating validator went unpunished on that
path. The R2 diff is additive with respect to live code: no live function loses a line,
so the Genesis Protocol harness was not run for R2 (it runs at R3, when the reactor is
rewritten on the `cmt_*` types). The T1 core (`src/bft/`), the T3 wave-1 codecs
(`tm_vote`, `tm_commit`) and the wave-1 WAL module were deleted in R2 as a second, dead
implementation; `shared/dnac/tm_bounds.h` stayed until R3 W3 C2b retired it with verbs 28-34
(2026-09-16).

### cometbft @709fd12b literal port — R3 wave W1: reactor, host, stores, mempool (`cmt_conr` / `cmt_ps`, `nodus_witness_cmt_*`, `cmt_mem`, DORMANT)

W1 (2026-09-11) is the first wave of R3, the season that writes `cmt_cs`'s consumer. It is
still DORMANT: nothing in the running node constructs a reactor, a host or a mempool — the
tier-3 verbs, the server tick and the engine binding are W2/W3 — and the live witness BFT,
the legacy lane and every ZK path are byte-untouched. Three packages landed together:

| Module | cometbft source | What it is |
|---|---|---|
| `shared/dnac/cmt_ps.{h,c}` | `consensus/reactor.go:1017-1482`, `consensus/types/peer_round_state.go` | PeerState and PeerRoundState: what THIS node believes a peer has — its height/round/step, its proposal and part-set header, its vote bit arrays and catch-up commit round — and the `Apply*` methods that update that picture from the peer's own announcements |
| `shared/dnac/cmt_conr.{h,c}` | `consensus/reactor.go` (57 PORT rows), `consensus/msgs.go:232-234` | the reactor: the four channel descriptors, `Receive` with the nine `ValidateBasic` gates (the gate R2 deliberately left out), the three broadcasts, and the three per-peer gossip routines — data, votes, VoteSetMaj23 — as TICK PASSES instead of goroutines |
| `nodus/src/witness/nodus_witness_cmt_host.{h,c}` | `state/execution.go`, `state/validation.go` | the BlockExecutor behind `cmt_cs_host_t`: CreateProposalBlock / ProcessProposal / ValidateBlock / ApplyVerifiedBlock / ExtendVote / VerifyVoteExtension / Commit / updateState, plus the application, mempool and evidence-pool interface tables the reference keeps |
| `nodus/src/witness/nodus_witness_cmt_store.{h,c}` | `store/store.go`, `state/store.go` | the two Comet stores over SQLite with the reference's OWN keys (`H:`/`P:`/`C:`/`SC:`/`EC:`/`BH:`/`blockStore`, `stateKey`/`validatorsKey:`/`consensusParamsKey:`/`abciResponsesKey:`/…) and proto values — schema S14 |
| `nodus/src/witness/nodus_witness_cmt_wal.{h,c}` | `consensus/wal.go` (write, search, decode) | the consensus WAL split by CALL CLASS across two connections (D-13, D-15 rev 5): `Write` is one autocommit row on the MAIN connection (`synchronous=NORMAL`, no fsync — the reference's buffered write), `WriteSync` one autocommit row on a SECOND connection at `synchronous=FULL` (the commit IS the fsync), `FlushAndSync` a one-row barrier on that same FULL connection, and the 2 s flush ticker a deadline the host's tick honours. No transaction is ever held, so the two connections never contend |
| `nodus/src/witness/nodus_witness_cmt_privval.{h,c}` | `privval/file.go:135-147`, `libs/tempfile`, `libs/json` | the last-sign-state file: the reference's JSON document written atomically (temp file, `O_SYNC`, rename) PLUS an fsync of the directory |
| `shared/dnac/cmt_pb_store.{h,c}` | `store/types.proto`, `state/types.proto`, `types/types.proto`, `params.proto`, `abci/types.proto` | the STORED values as proto3 under K-1: BlockMeta, BlockStoreState, State, ValidatorsInfo, ConsensusParamsInfo, ABCIResponsesInfo, ConsensusParams and the ResponseFinalizeBlock family — plus the block decoder the store needs to read a block back |
| `shared/dnac/cmt_mem.{h,c}`, `cmt_memr.{h,c}`, `cmt_clist.{h,c}`, `cmt_pb_mempool.{h,c}` | `mempool/*`, `libs/clist/clist.go`, `proto/tendermint/mempool` | the Flood mempool (D-4 rev 3): the CList, the LRU cache, peer ids, the synchronous CheckTx flow, recheck after every block, and the Txs gossip reactor |
| `shared/dnac/cmt_pb_wire.h` | — | the writer/reader primitives (varint, tag, bytes, skip, arena copy) that every `cmt_pb*` codec repeats, as ONE definition; merged at integration from the two executors' own reports, so a second codec can never drift from the first |

THE ONE STRUCTURAL SUBSTITUTION is threads → ticks. The reference runs three goroutines per
peer forever and sleeps inside them; here `cmt_conr_tick` runs each routine as far as the
reference would go before a `time.Sleep` or a refused send, records the sleep as a per-routine
DEADLINE, and reports the earliest one so the server's poll wait can honour it. A send never
blocks (the reference's blocks for up to 10 s), and a refused send ends that routine's pass
for the tick instead of spinning. Every one of the fourteen sleep sites maps to a deadline
site with its Go line beside it.

The reactor also gets what R2 could not have: the state machine's event switch. `cmt_cs` now
carries ONE listener with three callbacks — new round step, valid block, vote — fired at the
same five `state.go` lines the reference fires `evsw` at, and the reactor subscribes after
construction exactly as `OnStart` does. No listener installed means no fire, which is the
reference's own `eventBus != nil` guard.

Tests: `test_cmt_conr` (the ten ValidateBasic tables, the two Receive-before-InitPeer cases,
and multi-node scenarios over an in-memory switch where every byte crosses through the REAL
reactor), `test_cmt_host` (48 cases: schema S14, the ported store / state-store / execution /
validation tests, the WAL write classes against a real SQLite file, the last-sign-state JSON),
`test_cmt_mem` / `test_cmt_memr` / `test_cmt_clist`. Running them found four defects — all in
the tests, none in the port: a prune fixture whose genesis time was AFTER the state's last
block time (so the evidence retain height came out 1 instead of 1100), an expectation that a
validator set sorts by address when `UpdateWithChangeSet` sorts by voting power, an absent
commit signature built with `memset` (1970) where the reference's zero time is year one, and
a test constant (a 5000-byte block) that cannot hold a header plus one ML-DSA-87 signature.

One defect was found in the PORT, at the close, by re-reading the approved records rather
than by running: the WAL's `Write` class had been given an open transaction on the second
connection, which is in neither D-13 nor D-15 rev 5 nor the reference (`wal.go:184` is a
buffered write), and which deadlocked the store's `SaveBlock` against it. It came from the
wave's dispatch, not from an executor. The routing above is the approved one, every row is a
single autocommit statement, and `test_cmt_host` keeps the lock as a CONTROL in both
directions so the shape cannot return unnoticed. The one thing the records left to R3 —
how `FlushAndSync` fsyncs rows that are already committed — is a one-row barrier on the FULL
connection (table `cmt_wal_sync`, S14), because SQLite has no fsync-on-demand and an empty
transaction syncs nothing; `PRAGMA wal_checkpoint` was rejected for returning BUSY, which
would make durability timing-dependent.

### cometbft @709fd12b literal port — W1.7 audit round + fix package, W1.8 store citations (2026-09-15)

Six read-only auditors, one per module plus a panic-rule lens over every FAULT/REJECT site,
re-derived every deviation-register row from the C and the pinned Go at `7f21263c`; every
SAFETY/LIVENESS claim was re-opened by the ORCHESTRATOR in both sources. No fork-class
divergence was found. What the fix package changed, by module (Atlas `atlas-dec-b02c8de1…`):

| Module | Change | Reference line |
|---|---|---|
| `cmt_bits.h` | capacity `CMT_BITS_MAX_BITS` 1601 → **10 000** = `MaxVotesCount`; the part-set bound stays 1601 as `CMT_PART_SET_MAX_PARTS` | `types/vote_set.go:18`, `reactor.go:1663/:1806/:1614` |
| `cmt_msgs.{h,c}` | the nine `*_validate_basic` bodies and `cmt_msg_validate_basic` live here now (moved verbatim from the reactor) so the core can run the gate without including `cmt_conr.h` | `msgs.go:232-234` |
| `cmt_cs.{h,c}` | replay runs ValidateBasic on every WAL MsgInfo, failure = corruption → FAULT; tocks are a **10-deep FIFO ring** (`CMT_CS_TOCK_QUEUE_SIZE`) served one per step, eleventh = FAULT; the LastCommit branch fills the conflict sink so previous-height equivocation reaches the evidence pool; the four `NewPartSetFromHeader` sites log once, leave both names NULL and complete the step when the port's bound refuses; `cmt_cs_init` refuses a host table with any of 26 rows NULL; a REJECT from the node's own validator set is FAULT; a block of exactly `payload_cap` bytes is accepted (one-byte EOF probe) | `replay.go:147 → wal.go:410`, `ticker.go:11/:48/:137`, `state.go:970`, `:2144 → :2072-2094`, `:1553/:1647/:2299/:1945`, `:1999-2003` |
| `cmt_state.c` | `MedianTime`'s power sum is the wrapping add (Go wraps by specification; C was undefined) | `state/state.go:277-280` |
| `cmt_ps.c`, `cmt_conr.{h,c}` | `SetHasProposal` writes nothing on refusal; the reactor's Start/Stop pair answers as `BaseService` does — `ErrAlreadyStarted`, `ErrAlreadyStopped`, and `ErrNotStarted` without taking the latch (W1.7b, after verifier A) | `reactor.go:1096-1119`, `libs/service/service.go:130-190` |
| `nodus_witness_cmt_store.{h,c}` | 346 line citations re-anchored site by site against the pinned `store/store.go` (765) and `state/store.go` (827); comment-only, stripped translation units byte-identical | — |

Tests: `test_cmt_cs` 42 scenarios / 1211 checks (three port-only scenarios: part-set bound
continuation, LastCommit equivocation report, block of exactly payload_cap),
`test_cmt_cs_unit` 174 (host rows mandatory, own-set REJECT → FAULT, tock queue, replay
gate), `test_cmt_conr` 18/18 (535; the 10 001-bit ProposalPOL row is now drivable),
`test_cmt_bits` 39 groups (10 000-bit wire round trip, 10 001 refused by the decoder),
`test_cmt_state` 111 (the wrapping sum — meaningful only under UBSan). Two RED proofs were
run against the old files (`cmt_ps.c` in a plain build, `cmt_state.c` under UBSan); the
`cmt_cs.c` items rest on the diff reading, the green run and the verifier. Still DORMANT:
nothing in the running node calls any of it until W3.

### cometbft @709fd12b literal port — R3 wave W2: the application, genesis v3, the startup table (`nodus_witness_cmt_app`, `nodus_witness_cmt_node`, `nodus_witness_v2_gen` v3, DORMANT)

W2 (2026-09-16, v0.19.60) binds the consensus core to the Ledger V2 engine. Still DORMANT:
`nodus-server` starts the legacy BFT lane, nothing constructs `nodus_cmt_node_t`, the reactor
and the tick are W3's. The ONE live-path change is `nodus_witness_v2_chain_id`'s fallback to
the stored genesis document on a chain with no height-0 block row — every chain that exists
today has that row and takes the old branch unchanged.

| Module | cometbft source | What it is |
|---|---|---|
| `nodus/src/witness/nodus_witness_cmt_app.{h,c}` | `abci/types/application.go`, `proxy/app_conn.go`, `consensus/replay.go:318-373`, `state/execution.go:101-323` | the APPLICATION behind `AppConnConsensus`/`AppConnMempool` over the ledger: InitChain as a genesis CHECK (chain id, committed global root == the document's `app_hash`, validators as a multiset), PrepareProposal (the ledger's fee order and chain_config-alone rules, the byte budget, the capacity seam), ProcessProposal, the vote-extension defaults, FinalizeBlock over the engine's Comet lane, Commit = the SQL `COMMIT` of the host's transaction, CheckTx = the ledger's admission check PLUS the envelope's authorization stage (D-23 rev 5, D-4 rev 3) |
| `nodus/src/witness/nodus_witness_v2_apply.{h,c}` (Comet lane) | `state/execution.go:224-323` | `nodus_v2_block_t.cmt`: every item in its own SAVEPOINT inside the host's transaction, a per-item `nodus_v2_tx_code_t` (consensus data), claims as items, the ten-column S14 block row with consensus's own block hash, `tx_root`/`tx_count` over applied items only, the committed-global-root reader, `nodus_witness_v2_genesis_cmt` (no height-0 row) |
| `nodus/src/witness/nodus_witness_v2_gen.{h,c}` (version 3), `nodus/tools/nodus_v2_gen_config.c` | `types/genesis.go`, `proto/tendermint/types/params.proto`, `node/setup.go:551` | the version-3 genesis DOCUMENT (D-18 rev 4): v2 body ‖ Comet tail; two hashes (chain id with its own field zeroed, source commit with `app_hash` zeroed too); `derive_v3` (ledger genesis at S12, climb to S14, store under "genesisDoc"); the CANONICAL-STRICT reader (four checks); the tool's v3 keys; an independent Python oracle |
| `nodus/src/witness/nodus_witness_cmt_node.{h,c}` | `node/node.go:285-422`, `node/setup.go:551-611`, `consensus/replay.go:201-565`, `consensus/replay_stubs.go:60-79`, `consensus/state.go:318-405`, `privval/file.go:237-245` | THE STARTUP TABLE: `NewNodeWithContext` step for step, the Handshaker (InitChain branch, six edge cases, five height outcomes, replayBlocks/replayBlock), the mock application (its `commit` issues the COMMIT), the genesis document loader's three-way table, `LoadOrGenFilePV` on the state file, OnStart minus the file WAL; the first production caller of `cmt_cs_init` |

Register rows R3-C1a-1..11, R3-C1b-1..8, R3-C1c-1..5 (`tasks/reference-deviation-register.md`,
local); R3-AUD-17 closed. Tests: `test_cmt_app` (18 cases, real v3 chain, both crash windows,
per-item rollback proven against a twin chain), `test_cmt_node` (14 cases, both crash windows
healed through the REAL Handshaker, the tampered-row/provider table), `test_v2_gen` §5-§11
(oracle KATs, strict decoder, derive end to end, tampered stored document refused).

### cometbft @709fd12b literal port — R3 wave W3: THE LIVE FLIP (`nodus_witness.c` post-open gate + tick + dispatch, the preflight against the genesis document, bundle v3, pin = chain id; 2026-09-17)

W3 makes the port the running consensus. Three packages landed after P0 and C2b (above): **C2c** (the schema and readiness side) and **C2a** (the server binding), each with one writer and one independent verifier (C2c 22/8/0, C2a 24/4/1 — every REFUTED item a wording or citation except one silent clock-fault path, fixed), plus a separate writer for the live test. Nothing of the old consensus lane is deleted in W3: it is CLOSED (unreachable from a running node, byte-unchanged) and deleted in the next wave (D-17 rev 10 (9), Atlas OBLIGATION `71525f3b…`).

**The post-open gate (`witness_post_open_gate`, both open paths) has three outcomes.** (a) The S14 stores (`cmt_state` AND `cmt_blockstore`) exist and carry a canonical-strict stored genesis document (`nodus_witness_v2_gen_stored_chain_id` succeeds): a version-3 chain — accepted, `v2_successor` set, `v2_chain32` = the document's chain id. (b) No S14 stores, an empty legacy `blocks` table and no pure-V2 genesis manifest: genuinely pre-genesis — accepted with no role (an ordinary fresh boot, and the ceremony's own scratch database, which `nodus_witness_v2_gen_derive_v3` creates through `nodus_witness_create_chain_db` before its first migration). (c) Anything else — a non-empty legacy `blocks` table, a pre-Comet Ledger V2 chain below S14, exactly one of the two S14 catalogue rows (a half-migrated schema is never a fresh chain), or any catalogue/probe FAULT — REFUSED, fail closed, logged, the handle closed. `nodus_witness_v2_chain_id` is deliberately not the gate's probe: its row-present branch would admit a pre-Comet chain.

**The binding (`witness_cmt_live_init`, only when the gate set the role):** `nodus_cmt_node_init` builds the startup table (W2); the WITNESS then builds the transport glue (`nodus_cmt_net_init`, C2b) and the two reactors — `cmt_conr_init(wait_sync=false, host table = the glue's, recv_arena = the glue's 64 MiB runway)` and `cmt_memr_init` — binds them, and `nodus_cmt_node_start` opens the consensus WAL and only then binds it to the host (until that moment the host's WAL rows are the reference's `nilWAL` no-ops, state.go:174 / wal.go:426-431). `raw_sign` is ML-DSA-87 over the exact canonical bytes with the server's identity key — no NDS1/purpose wrapper, because peers verify the reference's canonical form. The reactors are NOT started here.

**The tick on a version-3 chain (`nodus_witness_tick` → `witness_mesh_tick` → `witness_cmt_tick`):** poll the witness transport (its wait narrowed to the earliest deadline the previous tick returned, at most 50 ms; the server's other polls are untouched) → transport-mesh maintenance (`nodus_witness_peer_tick`: dead-connection sweep, dialing every roster witness with backoff, the IDENT exchange; the 60 s roster refresh from the DHT registry with an IMMEDIATE swap — no legacy round phase exists on this lane) → the Comet share: the genesis-time wait (node.go:518-524, evaluated once per tick; when due, `cmt_memr_start` then `cmt_conr_start`, which is what reaches `cmt_cs_start`), a drain of `cmt_cs_step` bounded to 512 steps per tick, `nodus_cmt_net_tick` (deferred closes, the peer scan, both reactors' ticks), `cmt_cs_on_timer_expired` when the host's deadline has passed and a bounded drain again, the earliest deadline returned. A CMT_FAULT anywhere — a failed clock read included — logs and clears `witness->running`: the node stops participating (the W1.7 rule), never a peer blame. Nothing else of the legacy tick runs on a version-3 chain. The first C2a round omitted the mesh step and the reactors would have had zero peers forever — found by reading, proven by the live test's mesh case.

**The dispatcher (D-16 rev 5):** the version gate and the quarantine switch list exactly verbs 35-39; verbs 1-8, 12-23 and 26-27 are log-and-dropped (rate-limited per verb, 60 s), their handlers untouched in the source; 9-11 (roster, ident) and 24-25 (genesis bundle) are kept; 35-39 are routed whole to `nodus_cmt_net_receive` only while `witness->running` and the lane exists.

**The client lane (D-23 rev 7 (22)):** on a version-3 chain `handle_dnac_spend` runs `cmt_mem_check_tx` and answers the CheckTx result AT ONCE — `{status: APPROVED}` means accepted into the mempool (no block receipt, no `bnr`/`ti`/`wsig`); a refusal is mapped from the mempool's error kind or the application's code. The client learns the commit by query. There is no leader and no forward: the mempool reactor floods. `nodus-cli`'s "ENVELOPE committed: height=… index=…" prints now show zeros on this lane (package C2d's item).

**The bounds (D-23 rev 7 (24)):** derived at bind time from the genesis document, never hardcoded — `prep_bound` = the mempool's configured size (5 000), `env_bound` = MaxDataBytes at one validator divided by an envelope's 73-byte framing minimum (293 525 at Block.MaxBytes 22 020 096), `claim_bound` = MaxDataBytes / `DNA_CLAIM_FIXED_LEN` (2 972); the executor's `max_txs` uses the same helper; `NODUS_CMT_APP_MAX_TXS` is retired. Every working array is per-request; only the two ABCI response buffers persist across calls. FinalizeBlock hands the engine a non-NULL results array even for an EMPTY block (the engine's precondition refuses NULL before the count; a quiet chain's first block is empty). PrepareProposal's seam drop loop is bounded by `prep_bound` passes — worst case O(prep_bound²) item evaluations on a mempool full of budget-exceeding envelopes (a liveness/cost note for R3-T, register R3-W3-C2a-11).

**The readiness side (C2c, D-17 rev 10 (8)):** the schema gates accept S14 — `nodus_witness_v2_pools_startup_check` and CORE `state_init` ADD S14 (the pool verification really runs there; before W3 an S14 database fell through `return 0` and was reported green), the preflight accepts S14 only, `nodus_witness_v2_genesis_cmt` narrows to S14 only. The derivation migrates to S14 FIRST (the W2 S12-then-climb order is withdrawn). The preflight's genesis check is rewritten against the stored DOCUMENT: present (`cmt_state` "genesisDoc") → the canonical-strict reader (`nodus_witness_v2_gen_stored_doc`) → its `chain_id` against the handle's 16-byte filename prefix → its `app_hash` against `nodus_witness_v2_committed_global_root` (NEW id 17 `GENESIS_APP_HASH_MISMATCH`, appended; ids 6 and 7 retired, never raised); the required-table list gains the five S14 stores. The whole-database digest is unchanged by a preflight (asserted).

**The genesis bundle v3 and the pin (D-24 rev 4):** magic `DNA.GBUNDLE.v3\0\0`; layout magic ‖ manifest ‖ six base tables ‖ doc_len ‖ the genesis document; a v1 bundle is refused by its magic; a chain with no stored document cannot be bundled. `bundle_apply` plants the tables, checks the carried document's self-hash against the pin BEFORE any genesis step, migrates the scratch to S14, stores the document, runs vset → domreg → `genesis_cmt`, and ACCEPTS only when the stored `chain_id == pin` AND `app_hash == the root just recomputed` — a tampered table cannot ride an untouched document. Zero trace on rejection is the joiner's scratch discard (`join_adopt`), not `bundle_apply`'s. The pin IS the 32-byte chain id everywhere: `--v2-genesis-pin <64hex>` (a 128-hex value is refused), `nodus_server_config.v2_genesis_pin[32]`, `w->v2_join.pin[32]`, verbs 24/25 `p` (their decoders hard-refuse a non-32-byte `p`); the ceremony prints the same value as `chain-id` and `v2-genesis-pin`, read back from the landed database through the canonical-strict reader. Measured: a seven-validator v3 bundle is 95 942 B → 2 chunks at 49 152.

**What stays open, named:** `nodus_rt_core_invariant`'s genesis probe reads the height-0 `v2_blocks` row, so on a version-3 chain the absent-supply-row refusal is skipped (fail-open; `test_v2_gen` L2F1 stays RED; the fix — "a height-0 row OR a stored document" — is outside every W3 whitelist and is an OBLIGATION, D-17 rev 11 (11)); `gen_plan_build` still accepts `config_version` 2 because the closed lane's own unit tests drive the version-2 derivation (the ceremony refuses 2 earlier) — the deletion wave narrows it; four closed-lane unit tests (`test_v2_epoch`, `test_v2_econ_params`, `test_bft_view_change_hardening`, `test_bft_view_boundary`) reopen legacy fixtures the gate now refuses — the operator decides skip-with-reason or conversion; block PRODUCTION is proven by the Genesis Protocol harness's Comet lane (package C2d), not by any unit test — a single process holds one of seven equal votes.

**Tests:** `test_cmt_live` (NEW, 5 cases over a real version-3 chain through the REAL `nodus_witness_init` → `nodus_witness_tick` → `nodus_witness_dispatch_t3`: the genesis-time wait and the peer-admission gate; verb 35 at protocol version 7 accepted through the real dispatcher and refused at 6 and 8 with distinct heights; CheckTx admitting a real signed claim and refusing the same claim under another key; a restart reopening the same role; the mesh dialing a roster witness on a version-3 chain), `test_cmt_app` 21 cases (+ the empty block, the byte-bound seam with a policy-verified ceiling, the count guards at `env_bound + 1`), `test_cmt_host` 50 (+ the half-present S14 catalogue refusal; + `store_get_then_full_write_then_main_write`, below), `test_cmt_node` 14 (+ nilWAL before start), `test_witness_protocol_version_gate` §1-§4 now prove the closed lane stays closed at every version, `test_v2_preflight` (the five document cases with a whole-DB digest; + the two height-aware cases of the second harness run, below), `test_v2_bundle` (v3 round trip with the document, wrong pin / tampered table / foreign bundle / old magic refused), `test_v2_pools` `t_s14_flip` (the silent skip proven RED), `test_tier3` verb 24/25 (32-byte `p`, 31/33 refused, chunk ceiling), `test_v2_gate_pure` / `test_v2_gen` / `test_v2_gen_config` converted to version-3 fixtures where they touch the flip.

**Found by RUNNING the Genesis Protocol harness at production constants (2026-09-17), fixed in-wave — every node stopped after height 1.** Seven nodes, the mesh up in seconds, height 1 committed on all seven; then on every node every Write-class consensus-WAL row on the MAIN connection failed `database is locked` (≈ 50 lines), then the store's own `BEGIN IMMEDIATE` failed the same way, `failed to save block at height 2`, `CMT_FAULT in cmt_cs_step — consensus participation stops`. Root cause (register R3-W3-C2a-17; reproduced with an independent two-connection experiment against the linked SQLite 3.40.1): `nodus_cmt_store_get` left its SELECT statement STEPPED — the row pointer "valid until the next call" meant the statement stayed un-reset that long — which pins an open read transaction (a WAL snapshot) on the main connection; the moment the consensus WAL's separate `synchronous=FULL` connection commits anything (an own-vote `WriteSync`, `EndHeight`, the flush barrier) that snapshot is stale, and SQLite's `SQLITE_BUSY_SNAPSHOT` rule — a read transaction can never be promoted to a write once another connection has written since the snapshot was taken, and the busy handler is not invoked for it — fails every later write on that connection until the statement is reset. Height 1 survived because the first live store READ is the reactor's catch-up gossip for a peer one height behind (LoadBlockMeta / LoadBlockPart / LoadBlockCommit), which only exists after the first commit. The reference's store is goleveldb and has no such reader/writer interaction, so this is host hardening, not a port change: `get` now copies the row into a store-owned per-table buffer and resets the statement before returning; the observable contract ("valid until the next `get` on the same table") is unchanged. `test_cmt_host` gained `store_get_then_full_write_then_main_write`, proven RED on the old store with the harness's own log line and GREEN after; the W1 test `wal_main_connection_interaction` never caught it because its control was an explicit transaction, not a materialised read. Re-run by hand on the fixed binary: seven nodes at one block per ≈ 6 s with zero error lines, byte-identical at every floor, and the restart scenario (`kill -9` + respawn of one node at height 29: ABCI replay `app 29, store 29, state 29`, rejoined, fleet at 34 thirty seconds later) green. Two consequences the run made visible, both recorded, neither a defect of the port: the global root changes on EVERY block (Rule N attendance writes the proposer's `last_signed_block` into the validators leaf), so cometbft's `needProofBlock` is true at every height and empty blocks arrive at the `timeout_commit` pace (≈ 5-6 s), never waiting the 60 s `create_empty_blocks_interval` — an idle chain grows by ≈ 14 000 blocks a day; and the harness's scenarios compared "at the floor" before any block existed (the Comet lane has no height-0 row), which is why the first sweep reported seven failures in seven seconds — package C2d's bring-up now has to prove the chain PRODUCES before a scenario may compare.

**Two more, from the SECOND sweep (same day), both fixed in-wave.** (1) A wiped node restarted with only its genesis pin was never served the genesis bundle: `nodus_witness_v2_preflight`'s check 5 compared the stored document's `app_hash` with the CURRENT committed global root, which on this ledger changes at every block (Rule N attendance), so from height 1 on every healthy node reported `GENESIS_APP_HASH_MISMATCH`, the gate answered NOT_READY, and `nodus_witness_v2_sync_handle_gbundle_q` — which asks `nodus_witness_v2_activation_permitted` on every request — refused silently (27 `V2 ingress is ARMED while the activation gate is not OPEN` lines fleet-wide, one per request). Check 5 is now height-aware: with no committed block it compares as before; from the first block on it compares against BLOCK 1's header `AppHash` from the Comet blockstore, which is the genesis app hash by the reference's own rule (`state/state.go` `MakeGenesisState` sets `state.AppHash` from the document, `state/validation.go` `validateBlock` requires every block's `AppHash` to equal it). `test_v2_preflight` gained a fixture that commits one real empty block through the apply lane AND the blockstore and asserts READY (RED on the old check, exactly at issue 17) and that a block 1 carrying a wrong app hash still raises 17 (register R3-W3-C2c-14). Recorded, not changed: the reference has no run-time "may activation proceed?" question — a version-3 node's role is decided once by the post-open gate — yet `v2sync_ready` re-runs the whole preflight on every bundle request and sync tick. (2) The mempool never gossiped a client-submitted transaction: a claim submitted to node 1 was included only when node 1 itself proposed again, 6-7 heights later, and no other node ever received it. A debugger on the live node showed every peer slot's mempool id as 0 (`SENDER-CHECK slot=N peer_id=0 is_sender=1`): `net_scan_peers` called `cmt_conr_init_peer` + `cmt_conr_add_peer` for the consensus reactor but only `cmt_memr_add_peer` for the mempool reactor — never `cmt_memr_init_peer`, the port of `InitPeer` → `ids.ReserveForPeer` that the reference switch runs for EVERY reactor before any `AddPeer` (`p2p/switch.go:829-831`, `:858-860`; `mempool/ids.go` starts `nextID` at 1 so that 0 stays the RPC/unknown sender). With every peer at id 0 and the client lane stamping its transaction "from 0", `isSender` was true for every peer and nothing was ever sent. One call added in the reference's order; `test_cmt_net` gained a case that asserts reserved, distinct ids, one send per up slot for a sender-0 transaction, and receive-side stamping with the receiver's own id (RED on the old glue at "peer id not reserved (0)"; register R3-W3-C2b-15). The W1/C2b tests had never asked whether a locally admitted transaction LEAVES the node.

**Third sweep: the pinned joiner adopted the chain and then did nothing.** With the bundle now served, `test_v2_join.sh`'s wiped node received it, re-derived, adopted, and the post-open gate printed the COMETBFT role — and no startup table, no `lane LIVE`, tip −1 forever (the partial-wipe restore has the same shape). The cometbft server binding was built ONLY by `nodus_witness_init` at process start; `join_adopt`'s `nodus_witness_scan_chain_db` set the role and nothing built the startup table, the glue and the reactors, so the version-3 tick found `cmt_node == NULL` and returned at once, and with no blocksync the node could not catch up either. The reference has no mid-life adoption (a node starts with its genesis document); the honest port of "the joiner now starts with this genesis" is to run the same construction after adoption: the constructor is exported as `nodus_witness_cmt_live_init` (two callers, an entry guard against a double construction) and `join_adopt` calls it right after the scan, inside the same synchronous tick, so no tick can interleave (register rows R3-W3-C2a-18 and R3-W3-C2c-15). `test_cmt_live` gained `adopt_then_live`: a PINNED pre-genesis witness (the pin-less shape hits the legacy seed gate — measured), the derived database renamed into its data dir exactly as `join_adopt` does, scan → role with nothing built (the defect reproduced) → construct → LIVE at the next ticks → the second call refused with the four pointers unchanged.

**The short-epoch run (E=15) found two more, both at the ledger's edges.** (1) A 40-claim pump was packed whole into one proposal — PrepareProposal had only the byte budget and the unit-capacity seam since C2a delta 4 retired the request cap — and every node's FinalizeBlock hit the apply engine's per-block scratch bound (`claim_nuls[MAX_OPS]`, sixteen) with `the block declares 40 claims with an over-long array; this engine holds 16` → all seven stopped at height 7. The engine's bound is now exported as `NODUS_V2_APPLY_MAX_OPS`, an honest proposer packs at most that many items (drop from the tail of the fee order) and an honest validator REFUSES a proposal above it before any per-item work (a nil prevote, the ABCI REJECT path), so a decided block above the bound can only come from +2/3 running a different application — the reference's own "byzantine +2/3 committed an invalid block" class, where the node may stop. `test_cmt_app` gained the two gates (40 → 16; 17 refused, 16 accepted), RED-first (register R3-W3-C2a-19). Recorded for the operator: sixteen items per block is this engine's release resource bound, not a protocol number — throughput is sixteen items per ≈ 6 s until the engine's scratch moves to the heap; and the per-domain `n_tx` walk counts LEGS, so a single envelope with many legs on one domain is not covered by the item cap (RISK, apply.c, a later delta). (2) At the first epoch boundary (height 15, lookback 14) every node failed the block: the committee's version-3 seed reader (`v2_seed_block_id`, O15E) still ran `SELECT block_id, header FROM v2_blocks` and strict-decoded a 413-byte pre-Comet header — schema S14 dropped that column in W1 and on the Comet lane the header lives in the blockstore's BlockMeta, the row's `block_id` being the Comet header hash. The reader now takes the row's `block_id` and verifies it against the Comet BlockMeta at that height (height, chain id, hash), the same MISSING / MALFORMED / WRONG-CHAIN / FORGED ladder over the store that holds the header now (register R3-W3-C2c-16). The two other readers of the dropped column are on closed paths (the leader-mode replay probe is reached only with `expect_block_id`, which the Comet lane never sets; the height-0 insert is the pre-Comet genesis).

**Package C2e — the receive arena's release policy (register R3-A-5 closed, operator-approved the same day).** The fourth production-constants sweep stopped at height 347 after ≈ 1 h: the reactor's 64 MiB receive arena was never released, every part-carrying message was decoded into it (≈ 174 KB per height for one 34 KB part — each part arrives from every gossiping peer and the "already held" check sits inside `AddPart`, after the decode), the 90 % latch fired on every node, the next decode's exhaustion was reported as `Error decoding message` and the honest peer was quarantined, the two nodes that had rejoined earlier (their runway spent on catch-up) fell behind, and with one validator stopped 4 of 7 was under quorum. Measured consequences at those constants: a node lived ≈ 40 min and nothing could rejoin a chain older than ≈ 380 heights. The reference allocates per message and its GC keeps bytes alive exactly while some holder references them; the port now makes each holder own its bytes, the mempool reactor's own pattern (`cmt_memr_receive` resets its arena before every decode): (1) `cmt_conr_receive` resets `recv_arena` before every decode, and the arena is `CMT_CONR_MAX_MSG_SIZE` (1 MiB) with a `_Static_assert` — a decode copies only sub-slices of the wire bytes the channel admitted, so exhaustion is unreachable for an admitted message and the 50 %/90 % latches are dead by proof (kept as regression latches); (2) the state machine's queue element owns the one variable-length payload a queued message carries (a BlockPart's bytes or a Vote's extension — `cs_q_push` allocates it with the element, the mempool's `mem_tx_new` idiom); (3) the part set owns its payloads: `cmt_cs_slots_t` gained a per-slot `part_bytes` store and `cmt_part_set_add_part` copies into it when bound (the proposer's own `NewPartSetFromData` still points into its data, as the reference's slices do; `slots->payload[]` stays the assembled-block image); (4) a dequeued vote's extension is copied into `cs->ext_arena` before the vote set takes it — the reset of THAT arena is still open (register R3-W3-C2e-4: a single bump allocator cannot release the oldest height while the newest must survive; two arenas by height parity are needed and the host's `extend_vote` writer is outside this package — no live effect, vote extensions are disabled on this chain, and overflow is a loud FAULT). A duplicate part now costs one decode and `AddPart`'s "already held" drop, which is what dissolves the 5× multiplier. Memory: `part_bytes` ≈ 22 MB per slot × 3 against the 63 MiB the arena gives back. Tests: `test_cmt_conr` `recv_arena_resets_every_receive` (392 × 64 KB parts, `used` never above one message, no peer stopped — RED on the old arena at message 129), `test_cmt_cs` `block_part_survives_source_overwrite` and `vote_extension_survives_source_overwrite` (the decoded source overwritten before the step; the block still reassembles byte-identically), `test_cmt_part_set` `add_part_payload_store`, `test_cmt_net` `recv_arena_bounded_per_message`; all of the consensus suite unchanged and green, ASan clean. Found by the same case and recorded, not fixed: `test_cmt_common.h`'s `validate_block` refuses a genuinely byte-identical, untampered, unlocked peer block, and no existing scenario proves that positive path (the byte-identity assertions pass; the prevote path is the fixture's gap — a later wave's). The fifth and sixth sweeps ran past 96 heights with the latches silent.

**A harness shape defect, from the same runs:** a CheckTx-accepted transaction is not promised the very next block (the stake envelope admitted at tip 2 was applied at 4); every "wait tip+1 then assert the row" site was flaky by construction. `stagef_cmt_wait_row` now waits for the ledger effect itself, progress-bounded by the chain's tip, and the three transaction scenarios read the effect's height before comparing at the floor; the flood's three back-to-back claims are asserted within a two-height spread, not in one block (three separate submits can legitimately straddle a proposal).

### BFT Consensus Flow

```
Client → Any Witness → Forward to Leader → Consensus Round → Response

PROPOSE → PREVOTE → PRECOMMIT → COMMIT
  │         │          │          │
  └─ Leader creates proposal with TX data
            └─ Witnesses verify TX (6 checks) and vote
                      └─ Quorum (2/3) reached
                                 └─ Atomic commit: nullifiers + UTXOs + TX storage
```

**TX Verification (6 checks before PREVOTE):**
1. tx_hash integrity (recompute SHA3-512)
2. Sender signature verification (Dilithium5)
3. UTXO balance validation (sum(inputs) >= sum(outputs))
4. Fee validation (>= minimum fee rate)
5. Duplicate nullifier detection
6. Double-spend check against committed nullifiers

### Witness Database Schema

SQLite tables managed by the witness module (`nodus_witness_db.c`):

| Table | Purpose |
|-------|---------|
| `nullifiers` | Spent nullifier tracking (double-spend prevention) |
| `ledger` | Transaction ledger with Merkle roots |
| `utxo_set` | Shared UTXO set for balance validation |
| `blocks` | Block chain (height → tx_hash mapping) |
| `epochs` | BFT-signed epoch roots |
| `supply_state` | Genesis supply, burned fees, current supply |
| `committed_transactions` | Full serialized TX data (hub/spoke queries) |

### Witness startup and chain-database faults

A node scans its data directory for `witness_<chain_id>.db` at startup
(`nodus_witness_scan_chain_db`, `nodus_witness.c:835`). That scan has **three**
outcomes, not two (`:831-833`):

| Code | Meaning | What the node does |
|---|---|---|
| `NODUS_W_SCAN_ABSENT` (−1) | the directory was **read successfully** and holds no chain database | genuine pre-genesis; continue into the bootstrap state machine |
| `NODUS_W_SCAN_UNUSABLE_TRANSIENT` (−2) | a chain database is present; the open failed with a transient sqlite class and the retry budget was spent | **refuse witness init** |
| `NODUS_W_SCAN_UNUSABLE_PERMANENT` (−3) | a chain database is present and permanently unusable, the post-open integrity gate refused it, or the data directory itself could not be read | **refuse witness init** |

The chain id is parsed from the **filename** and installed *before* the open
(`:926`), so a node whose open fails still holds the identity it had. Only
`ABSENT` prints `no chain DB found — pre-genesis state`; every other non-zero
return prints an explicit `REFUSING START` block naming which class it was and
returns −1 (`:1344-1367`). The reason is not severity theatre: a node that
believes it is pre-genesis enters bootstrap, and a bootstrapping node may
create a chain database or adopt a peer's genesis **beside the chain it
already has and cannot see**.

**Error classes are separated on the sqlite PRIMARY code (`rc & 0xff`)**, so an
extended code such as `SQLITE_BUSY_RECOVERY` classifies as `SQLITE_BUSY`
(`witness_db_err_class`, `:338-353`):

- **transient** — `SQLITE_BUSY`, `SQLITE_LOCKED`, `SQLITE_IOERR`,
  `SQLITE_FULL`, `SQLITE_CANTOPEN`, `SQLITE_NOMEM`, `SQLITE_PROTOCOL`. Retried
  up to `NODUS_W_DB_OPEN_ATTEMPTS` (3) times, each attempt carrying
  `NODUS_W_DB_BUSY_TIMEOUT_MS / 3` of busy timeout so the **aggregate** lock
  wait is unchanged at `NODUS_W_DB_BUSY_TIMEOUT_MS`
  (`nodus/include/nodus/nodus_types.h:241`, 5000 ms), with a fixed 250 ms pause
  between attempts (`:404-407`, `:549-589`).
- **permanent** — `SQLITE_NOTADB`, `SQLITE_CORRUPT`, `SQLITE_PERM`,
  `SQLITE_AUTH` and anything the build does not recognise. **Never retried** —
  an unrecognised code fails closed rather than looping.

**A failed witness init does not kill the process.** `nodus_server_init` frees
the witness, NULLs it and continues (`nodus_server.c:6114-6169`) — nodus is
dual-role, the DHT half is unaffected, and exiting would spend the
`StartLimitBurst=3` budget described in §13 and retire the DHT role too. The
node is therefore **degraded, and says so loudly**: a multi-line `ERROR:` block
states that consensus is NOT PARTICIPATING (no block validated, no vote cast,
no certificate signed, no block produced), that the DHT is unaffected, where
the cause is named, and that the process is deliberately not exiting.
Witness-less operation is a defined mode, not a latent crash — but the
protection is layered, not uniform: `nodus_witness_dispatch_t3` returns
immediately on a NULL witness (`nodus_witness.c:1975`), the tick
(`nodus_server.c:6264`) and the post-auth T3 dispatch (`:5105`) are
additionally guarded by `if (srv->witness)`, while the witness-port dispatch
(`:5046`) passes the pointer unguarded and relies on that callee NULL check
alone.

---

## 16. Hub/Spoke Query Protocol (v0.10.0)

The hub/spoke model allows lightweight clients to trust witnesses and query the full
blockchain view without local verification.

### Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Wallet A  │      │   Wallet B  │      │   Wallet C  │
│  (client)   │      │  (client)   │      │  (client)   │
└──────┬──────┘      └──────┬──────┘      └──────┬──────┘
       │ TCP 4001           │ TCP 4001           │ TCP 4001
       ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────────┐
│                 WITNESS CLUSTER (3 nodes)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ witness-1│◄─┤ witness-2│◄─┤ witness-3│               │
│  │  BFT +   │─►│  BFT +   │─►│  BFT +   │               │
│  │  TX DB   │  │  TX DB   │  │  TX DB   │               │
│  └──────────┘  └──────────┘  └──────────┘               │
│  committed_transactions table stores full tx_data        │
└──────────────────────────────────────────────────────────┘
```

### Message Types (CBOR over Nodus Tier 2 TCP)

| Message | ID | CBOR Method | Description |
|---------|----|-------------|-------------|
| TX_QUERY | 144 | `dnac_tx` | Query full TX by hash |
| TX_RESPONSE | 145 | — | Returns tx_data blob, tx_type, block_height, timestamp |
| BLOCK_QUERY | 146 | `dnac_block` | Query block by height |
| BLOCK_RESPONSE | 147 | — | Returns tx_root (legacy key `hash` + explicit key `tx_root` since v0.18.22), tx_count, timestamp, proposer_id, prev_hash, state_root (v0.18.18+), commit_cert |
| BLOCK_RANGE_QUERY | 148 | `dnac_block_range` | Query block range |
| BLOCK_RANGE_RESPONSE | 149 | — | Returns array of blocks (max 100); per-block keys as BLOCK_RESPONSE minus state_root/commit_cert, `tx_root` since v0.18.22 |

### Client SDK Functions

```c
// Query full transaction by hash (caller frees tx_data)
int nodus_client_dnac_tx(nodus_client_t *client, const uint8_t *tx_hash,
                          nodus_dnac_tx_result_t *result);
void nodus_client_free_tx_result(nodus_dnac_tx_result_t *result);

// Query block by height
int nodus_client_dnac_block(nodus_client_t *client, uint64_t height,
                             nodus_dnac_block_result_t *result);

// Query block range (caller frees blocks array)
int nodus_client_dnac_block_range(nodus_client_t *client,
                                    uint64_t from_height, uint64_t to_height,
                                    nodus_dnac_block_range_result_t *result);
void nodus_client_free_block_range_result(nodus_dnac_block_range_result_t *result);
```

### TX Storage in BFT Commit

During `do_commit_db()`, after nullifier and UTXO set updates, the full serialized
`tx_data` is stored in the `committed_transactions` table:

```sql
INSERT OR IGNORE INTO committed_transactions
    (tx_hash, tx_type, tx_data, tx_len, block_height) VALUES (?,?,?,?,?);
```

This ensures every committed transaction is queryable by hash, enabling clients to
retrieve full transaction details without maintaining a local copy of the blockchain.

---

## 17. DHT Pubkey Registry

Every nodus server publishes its identity to the DHT key `"nodus:pk"` with a 10-minute TTL.
This allows any client to discover all active nodus servers by calling `GET_ALL` on that key.

The witness roster is built from this registry — witness nodes query `"nodus:pk"` to discover
peers and form the BFT consensus group for DNAC transaction processing.

---

## 18. CLI Commands (`nodus-cli`)

### `witness`

Shows the current witness roster and BFT consensus status by querying the DHT `"nodus:pk"` registry.

```bash
nodus-cli -s <server_ip> witness
```

**Output for each witness:**
- `node_id` — first 32 bytes of SHA3-512(pubkey), hex
- `address` — IP:port (TCP 4002 inter-node)
- `sig` — VALID/INVALID (Dilithium5 signature on DHT value)
- `seq` — sequence number (monotonic, used for value replacement)
- `expires` — seconds until DHT entry expires (re-published every 10 minutes)

**BFT summary:**
- `Valid witnesses` — total nodes with valid, non-expired DHT entries
- `Server index` — index of the connected server in the sorted roster
- `Consensus` — ACTIVE (>= 5 witnesses) or DISABLED
- `f_tolerance` — max faulty nodes tolerated: (n-1)/3
- `Quorum` — votes needed: 2f+1

**Example:**
```
Witness Roster (from DHT "nodus:pk")
=====================================
Total entries: 6

[0] (CONNECTED)
    node_id:  03499d1fae35f9e9...
    address:  154.38.182.161:4002
    sig:      VALID
    seq:      1773464845
    expires:  553s from now
...
─────────────────────────────────
Valid witnesses: 6
Server index:    0
Consensus:       ACTIVE
f_tolerance:     1
Quorum:          3
```

### Planned witness subcommands

These will be added as the DNAC consensus system matures:

| Command | Description |
|---------|-------------|
| `witness status` | Current block height, last committed round, current leader |
| `witness leader` | Current epoch's leader node |
| `witness blocks [n]` | Last n committed blocks with TX hashes |
| `witness supply` | Total supply, burned fees, circulating |
