# Nodus — Post-Quantum DHT Server

<p align="center">
  <strong>Pure C Kademlia DHT with Dilithium5 signatures and Kyber1024 encryption</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v0.19.41-orange" alt="RC"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Crypto-Dilithium5%20(FIPS%20204)-red" alt="Dilithium5"></a>
</p>

---

## What is Nodus?

Nodus is the distributed hash table (DHT) infrastructure for the DNA ecosystem. It provides decentralized storage, replication, and real-time subscriptions — all signed with post-quantum cryptography. The network is open — anyone can run a Nodus node and join.

- **Pure C** — No C++ dependencies, minimal footprint
- **Dilithium5 signatures** — All stored values cryptographically signed (FIPS 204)
- **Kyber round-3 / ML-KEM-1024 channel encryption** — All client connections encrypted (AES-256-GCM after a KEM key exchange). Faz 1 KEM migration (`docs/plans/decisions/2026-09-23-kem-mlkem-migration.md`) in progress: a node opportunistically upgrades to ML-KEM-1024 (FIPS 203) whenever its peer has one and signs it, falling back to Kyber round-3 otherwise — see `shared/crypto/enc/qgp_kyber.h` (legacy) and `shared/crypto/enc/qgp_mlkem.h` (FIPS 203).
- **Cluster management** — Heartbeat-based health monitoring with Kademlia replication
- **512-bit keyspace** — Kademlia routing with k=8 buckets
- **7-day TTL** — Values persist across restarts with SQLite storage
- **CBOR wire format** — Efficient binary serialization
- **Embedded DNA Chain witness** — BFT consensus for DNA Chain (DNAC) transactions
- **Circuit relay** — Peer-to-peer VPN mesh with onion-style E2E encryption
- **Media storage and replication** — Binary blob storage with cluster-wide replication
- **Multi-token support** — Custom token creation and management on the DNA Chain
- **Open network** — Community-managed, anyone can run a node

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Nodus Server                              │
├──────────────────────────────────────────────────────────────────┤
│              Kyber1024 Encryption Layer (AES-256-GCM)            │
├──────────┬──────────┬──────────┬──────────┬──────────────────────┤
│ UDP 4000 │ TCP 4001 │ TCP 4002 │ TCP 4003 │ TCP 4004             │
│ Kademlia │ Client   │ Inter-   │ Channels │ Witness BFT          │
│          │          │ node     │          │                      │
│ ping     │ auth     │ repl.    │ channel  │ PROPOSE              │
│ find_node│ dht_put  │ heartbt  │ subs     │ PREVOTE              │
│ store    │ dht_get  │ circuit  │ (idle)   │ PRECOMMIT            │
│ find_val │ get_batch│ fwd      │          │ COMMIT               │
│          │ cnt_batch│          │          │                      │
│          │ listen   │          │          │                      │
│          │ presence │          │          │                      │
│          │ circuits │          │          │                      │
│          │ media    │          │          │                      │
├──────────┴──────────┴──────────┴──────────┴──────────────────────┤
│  Kademlia Routing   │  Cluster Management  │  Witness BFT        │
│  512-bit keyspace   │  Heartbeat health    │  DNAC consensus      │
│  k=8 buckets        │  K-closest repl.     │  PBFT phases         │
├─────────────────────┴──────────────────────┴─────────────────────┤
│  SQLite Storage     │  Presence Table      │  Media Storage       │
│  7-day TTL          │  45s TTL, p_sync 30s │  Binary blobs        │
└──────────────────────────────────────────────────────────────────┘
```

**Five Network Ports:**

| Port | Protocol | Purpose |
|------|----------|---------|
| UDP 4000 | Kademlia | Peer discovery (ping, find_node, store, find_value) |
| TCP 4001 | Client | Auth, dht_put, dht_get, get_batch, cnt_batch, listen, presence, circuits, media |
| TCP 4002 | Inter-node | Cluster replication, heartbeat, circuit forwarding |
| TCP 4003 | Channels | Dedicated channel traffic (currently disabled) |
| TCP 4004 | Witness BFT | DNAC consensus (PROPOSE, PREVOTE, PRECOMMIT, COMMIT) |

**Wire Protocol:** CBOR over framed TCP/UDP — 7-byte header (magic `0x4E44` + version + length)

---

## Source Layout

```
nodus/
├── src/
│   ├── server/      # Server event loop (epoll), nodus_server.c
│   ├── client/      # Client SDK, nodus_client.c
│   ├── protocol/    # Wire protocol, Tier 1 + Tier 2 dispatch
│   ├── core/        # Kademlia routing, storage
│   ├── transport/   # UDP/TCP transport
│   ├── channel/     # Channel/subscription system
│   ├── consensus/   # Cluster heartbeat + membership management
│   ├── crypto/      # Nodus-specific crypto helpers
│   ├── circuit/     # Circuit relay for P2P VPN mesh (onion-style E2E encryption)
│   └── witness/     # DNA Chain BFT witness (embedded in nodus-server; legacy + Ledger V2 lanes)
├── include/
│   └── nodus/
│       ├── nodus.h       # Client SDK public API
│       └── nodus_types.h # Constants, version
└── tests/               # Unit + integration tests
```

---

## Build

```bash
cd nodus/build
cmake ..
make -j$(nproc)
```

Produces:
- `nodus-server` — DHT server binary
- `nodus-cli` — CLI tool for testing and chain operations
- `nodus-circ` — circuit relay test tool
- `test_*` — Unit test binaries

### `nodus-cli` chain commands (version-3 chain)

`nodus-cli -h` prints the full list (DHT verbs included). The envelope and
claim builders — every one answers with the mempool **CheckTx** verdict
(`accepted: mempool CheckTx approved ...`), never a commit; inclusion is
read from the chain:

| Command | What it builds |
|---|---|
| `v2-claim --config <conf> --db <db> --keys <dir> (--dry-run \| --submit ip:port)` | GENESIS_CLAIM of every genesis leaf bound to the key, one session |
| `v2-envelope stake --db <db> --keys <dir> --bond <raw> --commission <bps> --dest-fp <hex128> (--dry-run \| --submit ip:port)` | two-leg SYSTEM STAKE + CORE SYSFUND |
| `v2-envelope spend --keys <dir> --to <fp128hex> --amount <raw> [--fee <raw>] [--token <hex128>] [--count <N>] [--submit ip:port] [--dry-run]` | single-leg CORE SPEND — a coin transfer. Networked end to end on ONE session authenticated as the sender: chain id from `dnac_supply`, the sender's coins from `dnac_utxo` (unlocked only, largest first, ties by nullifier), CORE ruleset from the binary's compiled table. Fee defaults to the chain floor (1 000 000 raw) and is refused below it; change returns to the sender; `--count N` submits N independent spends with disjoint inputs. `res_max_total_units` is right-sized per envelope (the block reserves every envelope's full ceiling at once, so the ceiling sets how many fit one block — ≈ 41 one-input spends). Prints `intent_id=` per envelope — the `tx_hash` of the UTXOs it creates. Refuses insufficient funds, more than 15 inputs, amount 0, a fee below the floor. `--dry-run` still needs the node (it lists the coins) and submits nothing. |
| `v2-envelope chain-config --db <db> --keys <dirs>` | offline-signed SYSTEM CHAIN_CONFIG (rehearsal driver) |
| `chain-config propose --param <NAME> --value <N> --effective <H>` | networked SYSTEM CHAIN_CONFIG with committee approvals collected over the wire |

## Run Tests

```bash
cd nodus/build
ctest --output-on-failure    # 189 registered tests (2026-09-18, D-16 rev 7 / W4-CC: +1 new target test_cc_appr; test_cc_client renamed onto the replacement function, no count change)
```

**Test coverage (representative areas — `ctest` runs all):**

| Area | Examples |
|------|-----------|
| Core Kademlia | `test_routing`, `test_bucket_refresh`, `test_storage`, `test_value`, `test_hashring` |
| Client SDK | `test_client`, `test_tier2`, `test_tcp`, `test_fetch_batch` |
| Protocol | `test_tier1`, `test_tier3`, `test_wire`, `test_cbor`, `test_strict_decoder` |
| Auth | `test_inter_auth`, `test_udp_auth`, `test_identity`, `test_sign_domain_separation` |
| Channels | `test_channel_*` (channel system currently disabled in production) |
| Circuits (VPN mesh) | `test_circuit_wire`, `test_circuit_table`, `test_circuit_live` |
| Media / DHT features | `test_media_storage`, `test_media_tier2`, `test_put_if_newer`, `test_hinted_handoff` |
| Presence / Server | `test_presence`, `test_server` |
| Witness (the ledger side; the legacy PBFT lane's tests are gone with it, R3 W4) | `test_witness_verify`, `test_vset_*`, `test_qc_v2`, `test_witness_state_root_failclose`, `test_witness_protocol_version_gate` (every retired tier-3 method string is refused at decode), `test_v2_seam_linked` (an `nm` gate: no old-lane symbol is linked into `nodus-server`) |
| cometbft literal port, R1 types (live since R3 W3; the only consensus since R3 W4) | `test_cmt_pb`, `test_cmt_merkle`, `test_cmt_bits`, `test_cmt_safemath`, `test_cmt_time`, `test_cmt_block`, `test_cmt_vote`, `test_cmt_part_set`, `test_cmt_validator_set`, `test_cmt_results`, `test_cmt_params`, `test_cmt_genesis`, `test_cmt_validation`, `test_cmt_evidence`, `test_cmt_state` |
| cometbft literal port, R2 consensus core (live since R3 W3) | `test_cmt_vote_set`, `test_cmt_hvs`, `test_cmt_msgs`, `test_cmt_wal`, `test_cmt_ticker`, `test_cmt_privval`, `test_cmt_replay`, `test_cmt_cs_unit`, `test_cmt_cs` (44 whole-height scenarios — every `state_test.go` test a single-node fixture can drive; + W3's two P0 part-set-bound scenarios and C2e's two ownership scenarios: a decoded block part and a vote extension survive the overwrite of their wire source), `test_cmt_byzantine` (4 nodes, byzantine proposer, partition — no fork; + R3 W3 P0: the two part-set-bound obligation scenarios — a forged +2/3 for a BlockID whose part count the port's bound refuses: the round recovers on a nil precommit / the commit site parks with no block) |
| cometbft literal port, R3 wave W1 — reactor / host+stores / mempool (live since R3 W3) | `test_cmt_conr` (19 scenarios: the `reactor_test.go` ValidateBasic tables plus four multi-node runs over an in-memory switch; + C2e's `recv_arena_resets_every_receive` — 392 full-size block parts from four peers leave the receive arena at one message's size and stop no peer), `test_cmt_host` (48 cases against a real SQLite database and real ML-DSA-87 keys: schema S14, the block and state stores, the WAL, the file privval, the BlockExecutor — S14 is no longer the live rung; the file also carries the S15 migration matrix added by tokenomics-v3 P1), `test_cmt_mem`, `test_cmt_memr`, `test_cmt_clist` |
| cometbft literal port, R3 wave W3 C2b — tier-3 envelope verbs 35-39 + transport glue (live since C2a routed them) | `test_tier3` (8 cometbft envelope sections: strict `{m: bstr}`, ceilings accepted via the real encoder and a hand-built frame, `m_cap+1` refused by the decoder, the universal negative-integer pin, measured envelope overhead, the mempool ceiling pin), `test_cmt_net` (9 cases: peer-set scan transitions over a REAL `cmt_conr`/`cmt_memr` pair, send refused for a down/quarantined slot, verb 35/39 routing, receive before any tick, the per-message receive arena (1 MiB since C2e) and its latches, deferred-close bookkeeping, the scan waits for both reactors, and — harness-found — the mempool peer ids are RESERVED so a client-submitted transaction is gossiped to every up slot and stamped by the receiver's own id) |
| cometbft literal port, R3 wave W3 — THE LIVE FLIP (C2a server binding + C2c readiness/bundle/pin) | `test_cmt_live` (NEW, 6 cases: a real version-3 chain brought up through the REAL `nodus_witness_init` → `nodus_witness_tick` → `nodus_witness_dispatch_t3` — the genesis-time wait and peer-admission gate, verb 35 accepted at protocol version 7 and refused at 6/8 through the real dispatcher, CheckTx admitting a real signed claim and refusing it under another key (needs the armed gate — C2c's preflight), a restart reopening the same role, the mesh dialing a roster witness, and — harness-found — a PINNED joiner that adopts a chain mid-life builds the server binding and goes LIVE; block PRODUCTION is the harness's — one process holds one of seven equal votes), `test_cmt_app` (21 cases: + the EMPTY decided block, the byte-bound seam with a policy-verified unit ceiling, the count guards at `env_bound + 1`), `test_cmt_host` (50: + the half-present S14 catalogue refusal through the real open path; + `store_get_then_full_write_then_main_write` — the harness-found SQLite snapshot lock that stopped every node after height 1, RED on the old store), `test_cmt_node` (14: + the nilWAL no-op before start), `test_witness_protocol_version_gate` (§1-§4 rewritten: the old lane stays closed at every header version), `test_v2_preflight` (the document-based genesis check: READY on a derived chain; absent row / one flipped byte / app_hash mismatch / chain-id disagreement each raised by one corruption, whole-DB digest unchanged; + harness-found: READY stays true after the FIRST committed block — the check reads block 1's header app hash from that height on — and a block 1 carrying a wrong app hash still raises the mismatch), `test_v2_bundle` (v3 round trip carrying the document, adopt only with the 32-byte chain id, wrong pin / tampered stake / foreign bundle / old magic refused), `test_v2_pools` (`t_s14_flip`: the pool replay REALLY runs at S14 — the old silent skip proven RED), `test_tier3` (verb 24/25: 32-byte `p` round trip, 31/33 refused, chunk at the ceiling accepted and +1 refused) |
| cometbft literal port, R3 wave W2 — application / genesis v3 / startup table (live since R3 W3) | `test_cmt_app` (18 cases on a REAL version-3 chain: InitChain as a genesis check, FinalizeBlock with per-item SAVEPOINT isolation proven against a twin chain, both crash windows, CheckTx incl. the signature stage, PrepareProposal/ProcessProposal), `test_cmt_node` (14 cases: the genesis-document loader's row/provider table, the Handshaker's height cases, both crash windows healed through the real Handshaker, LoadOrGenFilePV, init/start/release), `test_v2_gen` §5-§11 (the version-3 document: oracle KATs, strict decoder, derive end to end, tampered stored rows refused) |
| D-16 rev 7 (W4-CC) — SYSTEM-governance approval collection re-wired on the Comet lane, verbs 40-41 replacing the retired vote-collect pair (14-15) | `test_tier3` (+2 sections: verb 40/41 round trip incl. the maximal pre-auth envelope, the `ok`-conditional strict key set), `test_witness_protocol_version_gate` (`w_cc_vote_req`/`w_cc_vote_rsp` join the retired-method-string list), `test_cc_client` (renamed onto `nodus_client_cc_appr_send`, same transport-guard-path coverage), `test_cc_appr` (NEW — the responder, `nodus_witness_handle_cc_appr_req`, driven over a REAL derived version-3 chain with 7 REAL ML-DSA-87 committee keys and a REAL loopback `nodus_tcp_conn_t`: happy path from every seat through `nodus_witness_v2_env_authorize` AND through the Comet apply lane (`nodus_witness_v2_apply_block`, item code 0, the `chain_config_history` row committed — ORCHESTRATOR ORC-5), an independent digest recomputation against the wire LAYOUT, a refusal matrix — foreign chain id in the T3 header, non-member, wrong `auth_kind`, nonzero fee, `TARGET_ACTIVE_COUNT` above the V2 ceiling, effective below the grace floor, the per-proposer rate limit — and (since tokenomics-v3 P2, replacing the ORC-6 INFLATION_START pair) a quorum proposal for the RETIRED parameter 3 refused as "scalar rules rejected"; `test_tier3`'s strict-key section also refuses a duplicate `e` / `ok` / `i` (ORC-12)) |
| Merkle / state_root | `test_witness_merkle`, `test_merkle_proof`, `test_state_root_4subtree`, `test_merkle_scan_fail_close` |
| Ledger V2 (the engine; driven through the cometbft application on the live lane) | `test_v2_apply`, `test_v2_native`, `test_v2_epoch`, `test_block_v2`, `test_domain_wire`, `test_v2_pools`, `test_v2_claims`, `test_v2_gen` (§3.5 L2-F1: the supply probe fails closed on a version-3 chain — R3 W4-S), `test_v2_econ_params` (its reopening cases derive version-3 chains) |
| tokenomics-v3 P2 — rewards, fees, the reward pool (no mint; parameter 3 retired) | `test_v2_econ` (REWRITTEN: the frozen balance copy, the pro-rata distribution through the engine at a boundary, the source copy src(H) and the consistency gate, a mid-epoch withdrawal paid through L(h), partial withdraw + top-up (earned ≤ locked), the decimal_unit refusal, a bar miss forfeiting the whole share, payday, the payout-interval reader, the F55/F56/F59 and payday stage rollbacks, a determinism twin), `test_v2_native` / `test_v2_apply` (every fee leg credits `reward_pool`; an explicit BURN still burns; the supply gate's pool and accrual terms; P2-10 — the UNDELEGATE release UTXO born locked to L(h) + 12E, partial and full drain, refused by the SPEND / SYSFUND / TOKEN_CREATE gates at U and accepted at U+1), `test_roots_v2` (supply-leaf v2, accrual leaf/root and the 7-leg `core_state_root` KATs), `test_cmt_host` (the S16 migration matrix), `test_v2_gen` (Rule P.2 with the reserve). DELETED with their subjects: `test_epoch_state`, `test_emission_boundaries`, `test_epoch_snapshot`, `test_epoch_snapshot_failclose`. Harness: `test_v2_rewards.sh` |
| tokenomics-v3 P3 — stake parameters (okuma B, 84/12 locks, exit with delegators, min delegation, 32 seats, 2048 delegators, commission 50% / increase +2E, re-stake, Rule M) | `test_committee_election` (okuma B: ranking follows the frozen copy, status the live row; frozen 0 not seated), `test_v2_econ` (src = H−3E and 3-copy retention to 4E; the 2-epoch commission notice under okuma B, with the old writer reproduced), `test_v2_epoch` (84E / 12E locks; graduation auto-release of delegations — ranks, 0x40000000 band, F60 rollback restores rows and totals), `test_v2_native` (Rule A gone; min delegation and the partial-remainder rule; commission 5000; target [7, 32]; re-stake of an UNSTAKED row — hook level and through real blocks after a graduation; Rule M: the 129th STAKE refused), `test_stake_constants`, `test_v2_active_max`, `test_cc_appr`, `test_vset_boundary`, `test_vset_persist`, `test_committee_cache`, `test_v2_committee_seed`, `test_chain_config_failclose` (updated expectations). Measurement (LABELS bench, not in the default run): `test_v2_deleg_cap_bench` (32 × 2048: boundary, payday, auto-release wall times) |

Integration tests (Genesis Protocol harness, 7-node localhost) — **one
lane** (the legacy runner `genesis_protocol.sh`, its bring-up and its 23
scenarios were deleted in R3 W4-D; see the stagef README — this block
read "two lanes" until tokenomics-v3 P2 corrected it):
```bash
# Ledger V2 chain — genesis is DERIVED OFFLINE from an operator config
bash nodus/tests/integration/stagef/genesis_protocol_v2.sh
```
Several scenarios need a short-epoch build and matching `STAGEF_*`
exports BEFORE bring-up (including `STAGEF_PAYOUT_INTERVAL_EPOCHS=2` for
`test_v2_rewards.sh`) — read `nodus/tests/integration/stagef/README.md`
in full first.

---

## Deployment

### Configuration

Config file: `/etc/nodus.conf`

Each node seeds the other nodes in the cluster:
```
# /etc/nodus.conf on node-1
listen_port = 4000
tcp_port = 4001
data_dir = /var/lib/nodus
seed_nodes = 164.68.105.227:4000,164.68.116.180:4000
```

### Systemd

```ini
# /etc/systemd/system/nodus.service
[Unit]
Description=Nodus DHT Server
After=network.target

[Service]
ExecStart=/usr/local/bin/nodus-server -c /etc/nodus.conf
Restart=always

[Install]
WantedBy=multi-user.target
```

### Current Nodes (community-managed)

| Node | IP | UDP | TCP |
|------|-----|-----|-----|
| US-1 | 154.38.182.161 | 4000 | 4001 |
| EU-1 | 161.97.85.25 | 4000 | 4001 |
| EU-2 | 156.67.24.125 | 4000 | 4001 |
| EU-3 | 156.67.25.251 | 4000 | 4001 |
| EU-4 | 164.68.105.227 | 4000 | 4001 |
| EU-5 | 164.68.116.180 | 4000 | 4001 |
| EU-6 | 75.119.141.51 | 4000 | 4001 |

---

## Client SDK

The Nodus client SDK (`include/nodus/nodus.h`) is used by DNA Connect to connect to the DHT network. All connections are encrypted with Kyber1024 key exchange + AES-256-GCM.

```c
#include <nodus/nodus.h>

// Connect (Kyber1024 encrypted)
nodus_client_t *client = nodus_client_create(config);
nodus_client_connect(client, "154.38.182.161", 4001);

// Store a value (signed with Dilithium5)
nodus_client_put(client, key, value, value_len, callback, userdata);

// Retrieve a value
nodus_client_get(client, key, callback, userdata);

// Batch retrieve multiple values
nodus_client_get_batch(client, keys, key_count, callback, userdata);

// Count values by prefix
nodus_client_cnt_batch(client, prefix, prefix_len, callback, userdata);

// Subscribe to key changes
nodus_client_listen(client, key, on_update, userdata);

// Presence query
nodus_client_presence_query(client, fingerprints, count, callback, userdata);

// Media storage
nodus_client_media_put(client, key, data, data_len, callback, userdata);
nodus_client_media_get(client, key, callback, userdata);
```

---

## Channel Encryption (Kyber round-3 / ML-KEM-1024)

All TCP connections (ports 4001 and 4002) are encrypted with a KEM key exchange followed by AES-256-GCM symmetric encryption. The handshake occurs immediately after TCP connection, before any protocol messages are exchanged. This ensures all client operations, inter-node replication, and circuit relay traffic are protected against quantum adversaries.

**Faz 1 KEM migration** (`docs/plans/decisions/2026-09-23-kem-mlkem-migration.md`, rolling-compatible, no wire version bump): a node that has generated an ML-KEM-1024 (FIPS 203) keypair signs and advertises its public key (`mpk`/`mpk_sig`) in AUTH_OK, alongside the existing Kyber round-3 `kpk`/`kpk_sig` — unconditional, unchanged. A peer uses ML-KEM-1024 (`alg=1` on KEY_INIT) only when it has verified the OTHER side's signed `mpk`; a node never sends an ML-KEM ciphertext to a peer that did not itself advertise one. Every peer without an ML-KEM keypair still talks Kyber round-3 (NIST Level 5), exactly as before this migration — the divergences from FIPS 203 in that legacy path are documented in `shared/crypto/enc/qgp_kyber.h` (the wrapper API; the underlying implementation is `shared/crypto/enc/kyber_r3_legacy.h`); the FIPS 203 implementation is `shared/crypto/enc/qgp_mlkem.h`. The `mpk`/`mpk_sig` binding uses a new purpose byte, `NODUS_PURPOSE_MLKEM_BIND` (0x09) — the first **tier-2** purpose to be STRICT (no raw-signature fallback either side), because its preimage is the same shape as `KYBER_BIND`'s and a non-strict signature here would be swappable with a `kpk_sig`. Circuits (VPN mesh) carry the same optional `alg`, but `alg=1` is Faz-2-only: it must not be used until every relay on the path forwards the tag, or an old relay silently drops it and the far end decapsulates with the wrong algorithm. An inbound E2E circuit whose `alg` this client cannot decapsulate is refused outright, never accepted with encryption silently disabled. See `docs/ARCHITECTURE.md` §5 ("Faz 1 KEM migration") for the wire format and the four handshake sites' exact fallback rule.

---

## Witness System (DNA Chain)

Nodus embeds the DNA Chain witness for BFT consensus on DNAC transactions. The witness runs on TCP port 4004 and implements PBFT-style consensus with four phases: PROPOSE, PREVOTE, PRECOMMIT, and COMMIT. The leader collects pending transactions from the mempool and proposes blocks at 5-second intervals (max 10 TXs per round); non-leader nodes forward received transactions to the current leader.

**Voting authority is chain-derived, not gossip-derived:** the committee is the stake-ranked active validator set, frozen per epoch into a committed validator-set snapshot. Quorum is `dna_bft_quorum(n) = (2n)/3 + 1` over the set governing the height (7 seats ⇒ 5); leader election rotates `(epoch + view) % N`. The committee size is a governance parameter (`TARGET_ACTIVE_COUNT`, chain-config param 4). Every witness must produce a byte-identical `state_root` per block — any divergence is a chain split and blocks deploy (Genesis Protocol harness enforces 7/7 identity).

Source: `src/witness/`

### Ledger V2 (successor chain — staged for activation)

The witness carries **two lanes in one binary**. The legacy lane (V1) is what the live chain runs today: flat 5-leg `state_root`, block identity = batch digest, 144-byte finalization certificates. The **Ledger V2** lane is the successor architecture, built and tested across the S1–O15F seasons and staged for activation:

- **Canonical block identity** — 413-byte BlockHeader v3, BlockID over the full header, quorum certificates (QC v2) bound to the committed validator-set snapshot.
- **Domain model** — state is partitioned into registered domains (SYSTEM, DNA_CORE) with per-domain state roots composed into one global root; new state kinds register a domain instead of forking the root format.
- **Envelope transactions** — multi-leg envelopes with typed per-domain runtimes (verified authorization, mediated reads, metered execution) and a dual identity (`wire_id` + authorization-witness-stable `intent_id`).
- **Atomic apply** — one SQLite transaction per global block with deterministic fault-point rollback proofs.
- **Birth without an ancestor** — a V2 chain is derived directly from an operator config by `nodus_witness_v2_gen_derive()` (`src/witness/nodus_witness_v2_gen.c`): validators, allocations and the genesis manifest come from the config, and the chain id is the manifest hash. There is no V1→V2 migration and none is planned — moving to V2 means **wiping the V1 chain and starting fresh**.

Ledger V2 is **no longer compile-gated**. The `NODUS_V2_ACTIVATION` CMake option and the whole V1→V2 activation ceremony (quorum-voted SCHEDULE / all-validator READY, the terminal-chain seam, TX types 15 and 16) were removed in season O15J Faz 3.

Activation authority is now a property of the chain itself: `nodus_witness_v2_gate_authority_present()` (`src/witness/nodus_witness_v2_gate.c`) reads the chain's own committed height-0 genesis manifest and grants authority only when its `source_tag` is `NODUS_V2_GEN_SOURCE_TAG` (`"DNA.GENESIS.v1"`). A manifest that cannot be read or decoded yields `NODUS_V2_GATE_FAULT` — never a silent "no authority". A pure-V2 chain therefore opens the gate and arms its V2 ingress at database open, in an ordinary default build.

Nothing about this changes what is deployed: the production cluster still runs the V1 chain, and this change deploys nothing by itself. The grounded V1↔V2 difference reference is [`../docs/ledger-v1-vs-v2.md`](../docs/ledger-v1-vs-v2.md); season-by-season detail lives in [`CLAUDE.md`](CLAUDE.md).

---

## Circuit Relay

Nodus provides a peer-to-peer circuit relay for VPN mesh connectivity. Circuits are established via TCP 4001 (`circ_open`, `circ_data`, `circ_close`) and forwarded between nodes via TCP 4002 (`ri_open`, `ri_data`, `ri_close`). End-to-end encryption uses Kyber1024 key exchange, providing onion-style privacy where relay nodes cannot read the payload. See `docs/CIRCUIT_PROTOCOL.md` for the full protocol specification.

Source: `src/circuit/`

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Nodus system architecture and design |
| [Deploy Runbook](docs/DEPLOY_RUNBOOK.md) | Deploy procedure, health checks, rollback |
| [Mempool & Block Time](docs/MEMPOOL_BLOCK_TIME.md) | Mempool, block timing, witness rounds |
| [Bootstrap](docs/BOOTSTRAP.md) | Node bootstrap procedure |
| [Circuit Protocol](docs/CIRCUIT_PROTOCOL.md) | Circuit relay protocol specification |
| [Replication Design](docs/REPLICATION_DESIGN.md) | DHT value replication strategy |
| [Replication Issues](docs/REPLICATION_ISSUES.md) | Known replication issues and fixes |
| [Dynamic Witness Design](docs/DYNAMIC_WITNESS_DESIGN.md) | Witness discovery and roster (superseded for BFT voting — the committee is chain-derived since F17) |
| [Version Enforcement](docs/PLAN_VERSION_ENFORCEMENT.md) | Version update enforcement plan |
| [Channel Rewrite Design](docs/archive/CHANNEL_REWRITE_DESIGN.md) | Channel TCP 4003 redesign (archived — channels disabled) |
| [DNA Nodus Deployment](../messenger/docs/DNA_NODUS.md) | Full deployment guide |
| [DHT System](../messenger/docs/DHT_SYSTEM.md) | DHT architecture |
| [P2P Architecture](../messenger/docs/P2P_ARCHITECTURE.md) | Transport layer |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
