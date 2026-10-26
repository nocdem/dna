# DNA Connect Function Reference

**Library version:** 0.11.35 (entries are updated in the same commit as signature changes — see `git log -- messenger/docs/functions/` for deltas)
**Last full audit sweep:** 2026-04-24 (triage via code-hit grep)
**Scope:** Public + static/internal function signatures, organized by module.

This directory provides a function-level reference for the DNA Connect codebase. Functions are grouped by subsystem.

> **Reading order:** start at `public-api.md` (the engine façade UI/FFI uses). Drop into subject files only when implementing a new feature in that subsystem.

> **Authoritative note:** file paths listed below are the current headers. When you update a function signature, update the corresponding `docs/functions/*.md` entry in the same commit.

---

## Quick Navigation

| Module | File | Description |
|--------|------|-------------|
| **Public API** | [public-api.md](public-api.md) | Main engine API (`dna_engine.h`) - all UI/FFI bindings |
| **DNA API** | [dna-api.md](dna-api.md) | Low-level cryptographic API (`dna_api.h`) |
| **Messenger** | [messenger.md](messenger.md) | Core messenger + message backup |
| **Cryptography** | [crypto.md](crypto.md) | Utils, KEM (Kyber), DSA (Dilithium), BIP39/BIP32 |
| **DHT** | [dht.md](dht.md) | Core, Shared, and Client DHT operations |
| **Transport** | [transport.md](transport.md) | DHT transport layer (presence, offline queue) + the nodus network readiness layer `nodus_net_poll` (`nodus/src/net/nodus_net_poll.h`, net-layer package N1: readiness set, connect probe, socket shims, `NODUS_NET_IS_*` error classes) and the 4004 host io-seam fields it changed + the witness-free 4004 host `nodus_p2p_host` (`nodus/src/net/nodus_p2p_host.h`, net-layer package N3: config, socket host `nodus_p2p_io_*`, policy rows, `_init` / `_start` / `_poll` / poll steps / `_free`, accessors) + the 4004 SecretConnection session profiles (`shared/dnac/cmt_p2p_secret.h`, DHT v2 sub-package 3a: `cmt_p2p_sc_profile_t`, the WITNESS / CLIENT / NODE const profiles, `cmt_p2p_sc_init_profile`, `cmt_p2p_sc_init` = WITNESS) and the session-auth signing purposes 0x0A / 0x0C / 0x0D with their sign / verify pairs (`nodus/src/crypto/nodus_sign.h`) + the optional SecretConnection layer of the nodus TCP / WebSocket transport (`nodus/src/transport/nodus_tcp_sc.h`, DHT v2 sub-package 3b-1: `nodus_tcp_sc_cfg_t`, `nodus_tcp_sc_enable` and the public queries, the bounded handshake-job worker and the transport-internal entry points, the incremental-sealing portion / fill-target constants and the derived buffer bounds) and the `nodus_tcp.h` fields it added (`nodus_pending_frame_t.sc_off`, `sc`, atomic `io_started`, the loop-owned teardown flags, the held WS close, `on_session`, `sc_worker`, `sc_gen_last`, `sc_close_requests`) + DHT v2 sub-package 3b-2, which enables that layer on 4001 / WS / 4002 (the server, the 4002 node session and pool, the storage process's dials, the client SDK; removed hello / auth / key_init functions) + the tool network identity `nodus_tool_network.h` (package 3c) + DHT v2 package 3d, the no-login (ANON) wallet session: the ANON family of `cmt_p2p_secret.h` (`CMT_P2P_SC_PROFILE_ANON`, kinds 0x05 / 0x06 / 0x07, `cmt_p2p_sc_init_anon`, `cmt_p2p_sc_init_responder_unbound`, `cmt_p2p_sc_kc_msg`, `cmt_p2p_sc_anon_pin_accepted`, `cmt_p2p_sc_is_anon`, `cmt_p2p_sc_transcript`, host `verify_kc`), purpose 0x0E `nodus_sign_kem_cert` / `nodus_verify_kem_cert`, the layer's `anon_kc_sig` / `nodus_tcp_sc_kc_sign` / `nodus_tcp_sc_is_anonymous` / `nodus_tcp_sc_transcript` / `NODUS_TCP_SC_JOBQ_IN_ANON_RESERVED`, the server's ANON allowlist and no-principal session, the storage no-identity origin preface, the client's `anon_session` / `nodus_client_set_owner_key`, and the NEW module `nodus/src/protocol/nodus_owner_query.h` (the owner-signed chain query `qa`) |
| **Database** | [database.md](database.md) | SQLite databases (contacts, cache, profiles) |
| **Blockchain** | [blockchain.md](blockchain.md) | Multi-chain wallet (Cellframe, ETH, Solana, TRON) |
| **DNA Chain ledger** | [ledger.md](ledger.md) | Tagged state-root hashing (`shared/dnac/ledger_roots_v2.h`, in libdna) + the nodus witness treasury / genesis entries it covers + §25 light client packages 1-3 (`cmt_light_*`, `cmt_fraction.h`, the moved `cmt_time_*` helpers; §25.9 the client `cmt_light_client.h`, §25.10 the detector `cmt_light_detector.h`) + §26 the `dnac_light_block` RPC (server builder, client SDK `nodus_client_dnac_light_block` + codec, `NODUS_ERR_HEIGHT_TOO_HIGH`, the pinned provider `nodus_light_provider.h`, the node-wide limiter `nodus_witness_light_block_admit` / `_serve`) + the K25-10 attack lock (`cmt_light_client_attack_locked` / `_attack_clear`, the light store's attack records §25.6) + §24.8 the archive segment files (`nodus_seg_*`, the P-B1 hash source `nodus_seg_hash_src_t`) + §24.11 the portable segment-file layer `nodus_fs` (`nodus/src/storage/nodus_fs.h`, storage P-B4: POSIX = the former libc calls, the Windows arm, errno contract, UTF-8 paths, the Windows unlink-aside `NODUS_FS_ASIDE_TAG`, 64-bit `off_t`) and the Linux-only segment export file + §19 the witness IPC (`nodus_witness_ipc.h`), incl. the DHT v2 package-4 `ipc_dht` kind (`nodus_witness_dht_*_fill`, the answer structs, `NODUS_WITNESS_IPC_DHT_FRAME_MAX` derived from `DNA_V2_STORAGE_SET_MAX`) and the DHT v2 package-3d chain side of the no-login session (chain backend op `dispatch_dnac_anon`, the no-identity `ipc_hello`, `nodus_chain_anon_method_ok`, `nodus_witness_handle_dnac_anon`, the owner-only reads under `qa`) |
| **DHT v2 record + wire-message codec + witness view + holder store + holder service** | [dht2.md](dht2.md) | DHT v2 packages 1, 2, 4, 5 and 6a (packages 1-2 in `shared/dht2/`, in nodus's common sources; package 4 in `nodus/src/dht/`, packages 5 and 6a in `nodus/src/dht2/`, all Linux-only; no production caller yet). Package 6a (§13): `nodus_dht2_holder.h` — the transport-free holder service `nodus_dht2_holder_serve`: one get / put / list request in, ONE signed answer envelope (answer / receipt / refusal 14 / 15, domain `nodus.dht.answer.v1`) or "no answer" out, over the store and an injected view of the witness (`nodus_dht2_holder_view_wview` binds the package-4 view); chain gate (a snapshot of another chain → refusal 15), the |S(H)| < 2 write precondition (refusal 15 — a reading), the row-20 signing-job limit (refusal 14), put results keyed by the envelope's address; with it `nodus_dht2_put_t` gained `has_address` / `address`, the LIST page budget counts the control record, `NODUS_DHT2_WVIEW_FAULT_KEEP_MS` drops an abandoned name fault, and `DHT2_REQ_BUDGET` / `DHT2_REQ_MAX_LEN` bound a request (an envelope above 262,144 B inside a put is per-key 1, not malformed). Package 5 (§12): `nodus_dht2_store.h` — the holder store (SQLite of canonical envelopes) and the one §4.1 admission path `nodus_dht2_store_put` over an injected context (snapshot, frozen sets, name callback, limits): row-7 codes 1-13 / 15 / 16 / 18, Select, per-identity quota, node and inbox pools, inbox control (only the selected live control record applies), get / LIST page / sweep / insertion-index scan / hand-over flag, store generation; with it a `ValidityType` ⇔ `Validity` disagreement became `bad-class` (6) in `dht2_record_check_class` instead of `bad-encoding` (2) in `dht2_data_decode`. Package 4 (§11): `nodus_dht2_wview.h` — the `nodus-storage` side of the `ipc_dht` kind of `witness.sock` (snapshot poll / staleness, frozen sets by epoch, name cache, timeouts, dial backoff; caller-supplied monotonic `now_ms`, no clock); its witness side is in ledger.md §19. Package 1: strict DAG-CBOR reader / writer (`dht2_cbor.h`), `Validity` text ↔ seconds (`dht2_time.h`), the IPNS v2 signed record — data map, class matrix, canonical stored envelope, `_id` / address, §4.2 Select, placement key (`dht2_record.h`), `nearest_R` / `eligible` (`dht2_place.h`), the RFC 0002 Signed Envelope + the owner-signed LIST request (`dht2_envelope.h`), the `DHT2_E_*` result codes and domain / label strings (`dht2_types.h`). Package 2: the wire messages (`dht2_msg.h`) — get / put requests, read answer / receipt / LIST answer / refusal payloads with `dht2_answer_seal` / `_open`, the pull-sync messages + `p_want` bit-vector, the inbox control `_data`; strict-CBOR array / false / null; five typed `_id` helpers (dm, group head / record / keys / feed); the message bounds and the row-11 maximum answer message (`dht2_types.h`) |
| **Nodus EVM** | [evm.md](evm.md) | EVM engine (`shared/evm/evm.h`, `evm_precompile.h`), node EVM runtime (`nodus_witness_rt_evm.h`), call wire codec (`shared/dnac/evm_call_wire.h`), envelope builder (`nodus_v2_evm.h`), S17 storage / log scan, apply-side EVM checks, client SDK `nodus_client_evm_*` |
| **Engine** | [engine.md](engine.md) | Internal engine implementation |
| **Calls** | [calls.md](calls.md) | PQ VoIP call subsystem (signaling, key agreement, FSM, orchestrator) |
| **Key Sizes** | [key-sizes.md](key-sizes.md) | Cryptographic key size reference |

---

## Module Overview

### 1. Public API ([public-api.md](public-api.md))
The main public API for DNA Connect. All UI/FFI bindings use these functions.
- Lifecycle management
- Identity management
- Contacts and contact requests
- Messaging (P2P + DHT)
- Groups (GEK encryption)
- Wallet (multi-chain)
- P2P & Presence
- Listeners (outbox, presence, delivery)
- Feed (DNA Board)
- Debug logging

### 2. DNA API ([dna-api.md](dna-api.md))
Low-level cryptographic API for message encryption/decryption.
- Context and buffer management
- Message encryption/decryption
- Signature operations
- GEK group messaging

### 3. Messenger ([messenger.md](messenger.md))
Core messenger functionality.
- Initialization and key generation
- Public key management
- Message operations and status
- Group management and GEK

### 4. Cryptography ([crypto.md](crypto.md))
All cryptographic primitives and utilities.
- AES-256-GCM, SHA3-512
- Kyber1024 KEM, Dilithium5 DSA
- Key encryption, seed storage
- Platform abstraction
- BIP39/BIP32 key derivation
- Internal Kyber and Dilithium implementations

### 5. DHT ([dht.md](dht.md))
Distributed Hash Table operations.
- Core context and operations
- Keyserver and name system
- Offline queue and watermarks
- Groups, profiles, and feeds
- Contact requests
- Message backup

### 6. Transport ([transport.md](transport.md))
DHT-based transport layer.
- Transport initialization
- DHT presence system
- Offline message queue
- Messenger transport integration
- Nodus network readiness layer (`nodus_net_poll`: epoll / Windows select, wake, connect probe, socket shims)
- Nodus witness-free 4004 host (`nodus_p2p_host`: policy rows, two-step start, poll steps, free, accessors)
- 4004 SecretConnection session profiles (WITNESS / CLIENT / NODE, `cmt_p2p_sc_init_profile`) and the session-auth signing purposes 0x0A / 0x0C / 0x0D (DHT v2 sub-package 3a)
- SecretConnection layer of the nodus TCP / WebSocket transport (`nodus_tcp_sc_*`: enable, queries, handshake-job worker, sealing; new `nodus_tcp.h` fields — DHT v2 sub-package 3b-1; enabled on 4001 / WS / 4002 since 3b-2)
- DHT v2 sub-package 3b-2: the 4001 / WS / 4002 sessions on that layer — per-port protocol versions, the pre-session sweep and the per-IP handshake rate, `nodus_auth_session_start`, `nodus_server_chain_id`, the 4002 node session (`nodus_inter_session_*`, tri-state `nodus_inter_send_t`), `nodus_dht_ipc_new` / `_open_wview`, the client's mandatory pin + chain id, the removed hello / auth / key_init functions

### 7. Database ([database.md](database.md))
Local SQLite databases.
- Contacts database
- Profile manager and cache
- Keyserver cache
- Presence cache
- Group invitations
- Bootstrap cache

### 8. Blockchain ([blockchain.md](blockchain.md))
Multi-chain wallet operations.
- Common interface
- Cellframe (Dilithium PQ signatures)
- Ethereum (secp256k1)
- Solana (Ed25519)
- TRON (secp256k1)

### 9. Engine ([engine.md](engine.md))
Internal engine implementation.
- Task queue
- Worker threading
- Task handlers (identity, contacts, messaging, groups, wallet, P2P, feed)

### 10. Key Sizes ([key-sizes.md](key-sizes.md))
Quick reference for cryptographic algorithm sizes.
- Post-quantum (Kyber, Dilithium)
- Symmetric (AES-256-GCM)
- Hash functions (SHA3)
- Key derivation (BIP39)
- Classical (Ed25519, secp256k1)

### 11. Nodus EVM ([evm.md](evm.md))
The Ethereum (Prague) execution engine and its integration into the version-3 chain as the third domain. Engine and node runtime are nodus-only (standalone nodus build, non-Windows, `NODUS_EVM_ENABLED`); the call wire codec is pure C shared with `nodus-cli` and the web wallet.
- Engine public API (`shared/evm/evm.h`) and the precompile self-test (`evm_precompile.h`)
- Node EVM runtime: descriptor, hooks, §18 simulation, per-leg trie batch (`nodus_witness_rt_evm.h`)
- Call-head decoder, pairing rule, conflict keys, block gas share (`nodus_witness_runtime.h`)
- EVM / EVMFUND call bytes and canonical receipt codec (`shared/dnac/evm_call_wire.h`)
- `[CORE EVMFUND] + [EVM op]` envelope builder (`nodus/src/client/nodus_v2_evm.h`)
- Schema S17, `evm_logs` cursor scan, apply-side checks (VM-less dry run, price-0 judge, block facts), CORE EVM reserve
- Client SDK §18 read RPC (`nodus_client_evm_*`, `nodus_client_dnac_query_raw`)

---

## Usage Guidelines

**ALWAYS check these files when:**
- Writing new code that calls existing functions
- Modifying existing function signatures
- Debugging issues (to understand available APIs)
- Adding new features (to find relevant functions)

**ALWAYS update these files when:**
- Adding new functions (public or internal)
- Changing function signatures
- Removing functions
- Adding new header files

**Format:** Each function entry follows table format:
```
| `return_type function_name(params)` | Brief one-line description |
```
