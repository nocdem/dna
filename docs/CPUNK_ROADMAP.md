# CPUNK Implementation Roadmap

**Version:** 1.0
**Date:** March 2026
**Status:** Post-Documentation — Ready for Implementation
**Confidentiality:** INTERNAL — Do not commit to git

---

## Current State

### Completed
- [x] DNAC transaction engine (UTXO, BFT, wallet, genesis) — `dnac/`
- [x] Nodus DHT network (Kademlia, PBFT, channels, presence) — `nodus/`
- [x] DNA Connect (encrypted messaging, multi-chain wallet) — `messenger/`
- [x] Shared crypto (Dilithium5, Kyber1024, SHA3-512, BIP39) — `shared/crypto/`
- [x] 6 production nodus nodes deployed and operational
- [x] DNAC witness logic embedded in nodus-server
- [x] BFT consensus working (2-of-3, PROPOSE/PREVOTE/PRECOMMIT/COMMIT)
- [x] UTXO transactions working (GENESIS, SPEND, BURN)
- [x] Block chain with Merkle proofs
- [x] Hub/spoke TX storage + query protocol
- [x] Cellframe RPC integration (balance, TX verify, TX history)
- [x] Multi-chain wallet in Flutter (Cellframe, ETH, SOL, TRON)

### Documentation Complete
- [x] Design document (`docs/DNAC_CPUNK_DESIGN.md`)
- [x] Whitepaper (`docs/CPUNK_WHITEPAPER.md`)
- [x] Tokenomics Paper (`docs/CPUNK_TOKENOMICS.md`)
- [x] Technical Specification (`docs/CPUNK_TECHNICAL_SPEC.md`)

### Not Started
- [ ] JSON-RPC API (port 4002)
- [ ] Staking (TX_STAKE_LOCK, TX_STAKE_UNLOCK)
- [ ] Proof of Space (challenge-response)
- [ ] Emission (TX_REWARD, halving)
- [ ] Burn bridge (TX_BRIDGE_MINT, CF20 verification)
- [ ] Slashing logic
- [ ] DNAC wallet UI in Flutter
- [ ] Block explorer
- [ ] Testnet deployment
- [ ] Exchange integration

---

## Phase 1: Decisions (1 week)

**Goal:** Finalize all TBD parameters before writing any code.

### 1.1 Tokenomics Decisions

| # | Decision | Options | Recommended | Impact |
|---|----------|---------|-------------|--------|
| 1 | Emission model | Halving / Smooth decay | **Halving** | Core emission logic |
| 2 | Initial reward (R₀) | 80-320 CPUNK/epoch | **~159 CPUNK/epoch** | Year 1 APY |
| 3 | Halving period | 1 / 3 / 5 years | **3 years** | Total emission timeline |
| 4 | Emission cap | 250M / 500M / 1B | **500M** | Terminal supply |
| 5 | TX fee | Zero / minimal | **Zero** | Wallet UX |

### 1.2 Protocol Decisions

| # | Decision | Options | Recommended | Impact |
|---|----------|---------|-------------|--------|
| 6 | Epoch duration | 30s / 60s / 300s | **60s** (current) | Challenge frequency |
| 7 | Unstaking period | 7 / 14 / 30 days | **14 days** | Validator flexibility |
| 8 | PoSpace challenge freq | Every epoch / every 10 epochs | **Every epoch** | Storage verification |
| 9 | Witness committee size | Fixed 3 / dynamic | **Start 3, grow** | Scalability |
| 10 | Reward split | Consensus/Storage ratio | **50/50** | Incentive balance |

### 1.3 Operational Decisions

| # | Decision | Options | Recommended | Impact |
|---|----------|---------|-------------|--------|
| 11 | Testnet token name | XXX / TCPUNK / TEST | **XXX** | Branding |
| 12 | Burn address | Provably unspendable / designated | **Provably unspendable** | Bridge security |
| 13 | RPC port | 4002 / 8545 | **4002** | Exchange docs |
| 14 | Block explorer stack | C / Python / Node | **Python (Flask)** | Dev speed |
| 15 | Exchange ticker | Same CPUNK / new | **Same CPUNK** | Market continuity |

**Deliverable:** All 15 decisions documented and approved.

---

## Phase 2: JSON-RPC API (2-3 weeks)

**Goal:** Exchange-ready API on nodus-server.

**Dependency:** None — can start immediately.

### 2.1 HTTP Listener

```
File: nodus/src/server/nodus_rpc.c (new)
- Add HTTP listener on port 4002
- Parse JSON-RPC 2.0 requests
- Route to handler functions
- Return JSON responses
```

### 2.2 Read Methods

| Method | Source | Complexity |
|--------|--------|-----------|
| `dnac_getBalance` | UTXO table aggregate | Easy |
| `dnac_getTransaction` | committed_transactions table | Easy |
| `dnac_getBlock` | Block query (existing msg 146) | Easy |
| `dnac_getBlockRange` | Block range query (existing msg 148) | Easy |
| `dnac_getUTXOs` | UTXO query (existing msg 135) | Easy |
| `dnac_getTransactionHistory` | Ledger range (existing msg 136) | Medium |
| `dnac_getChainHeight` | Ledger table max sequence | Easy |
| `dnac_getWitnessList` | Roster query (existing msg 137) | Easy |
| `dnac_validateAddress` | Fingerprint format check | Easy |

### 2.3 Write Method

| Method | Flow | Complexity |
|--------|------|-----------|
| `dnac_sendTransaction` | Deserialize → submit to BFT | Medium |

### 2.4 Infrastructure

- Rate limiting (per-IP, configurable)
- Error codes (JSON-RPC standard + DNAC-specific)
- Configuration in nodus.conf
- Unit tests (all methods)
- curl test script

**Deliverable:** All 10 RPC methods working, tested with curl.

---

## Phase 3: New Transaction Types (3-4 weeks)

**Goal:** Implement staking, bridge, and reward transactions.

**Dependency:** Phase 1 decisions finalized.

### 3.1 TX_BRIDGE_MINT (Burn Bridge)

```
Files:
- dnac/src/transaction/bridge_mint.c (new)
- dnac/include/dnac/bridge.h (new)
- nodus/src/witness/witness_bridge.c (new)

Steps:
1. Add TX_BRIDGE_MINT type to transaction.h
2. Implement Cellframe RPC burn verification
3. Add BRIDGE_MINT BFT message type (msg ID 152)
4. Implement burn dedup database (burn_history table)
5. BFT consensus flow for bridge mint
6. Unit tests: valid burn, duplicate burn, fake burn, RPC failure
```

### 3.2 TX_STAKE_LOCK / TX_STAKE_UNLOCK

```
Files:
- dnac/src/transaction/staking.c (new)
- dnac/include/dnac/staking.h (new)
- nodus/src/witness/witness_staking.c (new)

Steps:
1. Add TX_STAKE_LOCK and TX_STAKE_UNLOCK types
2. Implement stake_locks SQLite table
3. Lock validation: amount >= 10M, valid UTXOs
4. Unlock validation: waiting period enforcement
5. Add STAKE_LOCK/UNLOCK BFT message types (msg IDs 150-151)
6. Validator roster update on stake/unstake
7. STAKE_QUERY method (msg ID 156)
8. Unit tests: lock, unlock early (fail), unlock after period, minimum check
```

### 3.3 TX_REWARD (Emission)

```
Files:
- dnac/src/transaction/emission.c (new)
- dnac/include/dnac/emission.h (new)
- nodus/src/witness/witness_emission.c (new)

Steps:
1. Add TX_REWARD type
2. Implement halving calculation (compute_epoch_reward)
3. Implement emission_log table
4. Emission cap enforcement
5. Reward distribution logic (consensus + storage split)
6. BFT consensus for epoch reward (msg ID 153)
7. Unit tests: reward calc, halving, cap, distribution
```

### 3.4 Database Migration

```
Bump DNAC_DB_VERSION from 1 to 2.
New tables: stake_locks, burn_history, pos_challenges, emission_log
```

**Deliverable:** 4 new TX types implemented, all unit tests passing.

---

## Phase 4: Proof of Space (2-3 weeks)

**Goal:** Challenge-response verification for DHT storage.

**Dependency:** Phase 3 (needs TX_REWARD for reward distribution).

### 4.1 Challenge Generation

```
Files:
- nodus/src/witness/witness_pos.c (new)
- nodus/include/nodus/pos.h (new)

Steps:
1. Random DHT key selection per epoch
2. Challenge message format (msg ID 154)
3. Broadcast challenges to responsible validators
4. Challenge tracking in pos_challenges table
```

### 4.2 Challenge Response

```
Steps:
1. Validator receives challenge, looks up DHT key locally
2. Computes SHA3-512(stored_value)
3. Signs response with Dilithium5
4. Sends CHALLENGE_RESP (msg ID 155)
```

### 4.3 Scoring and Reward

```
Steps:
1. Verify response hash against DHT value
2. Verify Dilithium5 signature
3. Compute per-validator score (storage * 0.6 + uptime * 0.4)
4. Distribute storage_share of epoch reward proportionally
```

**Deliverable:** PoSpace working end-to-end, integrated with emission.

---

## Phase 5: Slashing (1-2 weeks)

**Goal:** Implement slashing logic (initially disabled).

**Dependency:** Phase 3 (needs staking).

### 5.1 Violation Detection

```
Files:
- nodus/src/witness/witness_slashing.c (new)

Violations:
1. Offline (full epoch) — detected via heartbeat absence
2. Equivocation (double signing) — detected via conflicting BFT messages
3. Fraudulent mint — detected via burn verification mismatch
4. PoSpace failure — detected via challenge timeout
```

### 5.2 Penalty Execution

```
Steps:
1. Compute penalty amount (1% / 50% / 100% of stake)
2. Create slashing TX (burns portion of locked stake)
3. BFT consensus on slashing
4. Update stake_locks table
5. For fraud: permanent ban (add to blacklist)
```

### 5.3 Phased Activation

```
Config flag: slashing_enabled = false  (Phase 1: launch)
             slashing_enabled = true   (Phase 2: community operators)
```

**Deliverable:** Slashing logic complete but disabled. Enable flag in config.

---

## Phase 6: Testnet (2-3 weeks)

**Goal:** Deploy everything to existing 6 nodus nodes with test token XXX.

**Dependency:** Phases 2-5 complete.

### 6.1 Deploy Updated Nodus

```bash
# For each of 6 nodes:
ssh root@<IP> "git -C /opt/dna pull && \
  systemctl stop nodus && \
  make -C /opt/dna/nodus/build -j4 && \
  cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && \
  systemctl start nodus"
```

### 6.2 Genesis

```
1. Generate XXX token genesis TX (1B supply)
2. 3-of-3 witness authorization
3. Distribute XXX to test wallets
4. Verify balances via RPC
```

### 6.3 Test Matrix

| Test | Method | Expected |
|------|--------|----------|
| Send XXX via messenger | Flutter UI | TX confirmed, balance updated |
| Send XXX via CLI | dna-connect-cli | TX confirmed |
| Send XXX via RPC | curl to port 4002 | TX hash returned |
| Query balance | RPC getBalance | Correct balance |
| Query TX | RPC getTransaction | Full TX details |
| Query blocks | RPC getBlockRange | Block list |
| Stake 10M XXX | CLI/RPC | stake_locks entry created |
| Unstake (early) | CLI/RPC | Rejected (waiting period) |
| Unstake (after period) | CLI/RPC | Stake returned |
| PoSpace challenge | Automatic per epoch | Rewards distributed |
| Double-spend | Adversarial test | Rejected by nullifier |
| Bridge simulation | Mock CF20 burn | XXX minted |
| RPC rate limit | Rapid curl loop | 429 after threshold |

### 6.4 Security Testing

```
Duration: 2+ weeks of active adversarial testing

1. Double-spend attacks (rapid same-UTXO submission)
2. BFT leader manipulation (kill leader, delay proposals)
3. Fake burn proofs (non-existent CF20 TX hashes)
4. PoSpace fraud (delete stored data, respond with garbage)
5. Stake manipulation (unlock without waiting period)
6. Replay attacks (resubmit old BFT messages)
7. Fuzz testing: RPC, CBOR, TX deserialize, BFT messages
8. Connection flooding (rate limit verification)
9. View change spam (trigger rapid leader changes)
10. Cross-chain replay (wrong chain_id)
```

**Exit criterion:** No critical vulnerabilities after 2 weeks of testing.

**Deliverable:** Testnet running with XXX token, all features working.

---

## Phase 7: Flutter Integration (3-4 weeks)

**Goal:** DNAC wallet UI in DNA Connect.

**Dependency:** Phase 6 testnet working.

### 7.1 DNAC Wallet Screen

```
Files:
- lib/screens/wallet/dnac_wallet_screen.dart (new)
- lib/providers/dnac_wallet_provider.dart (new)
- src/api/engine/dna_engine_dnac.c (new module)

Features:
- CPUNK (DNAC) balance display
- Send CPUNK to contact (in-chat)
- Receive (show address / QR)
- Transaction history
- Pending transactions
```

### 7.2 Burn Bridge UI

```
Files:
- lib/screens/wallet/burn_bridge_screen.dart (new)

Features:
- CF20 -> DNAC burn flow
- Amount input
- Confirmation dialog (irreversible warning)
- Progress tracking (burn TX -> verification -> mint)
- History of burns
```

### 7.3 Staking UI

```
Files:
- lib/screens/wallet/staking_screen.dart (new)

Features:
- Current stake status
- Stake button (10M minimum)
- Unstake button (shows waiting period)
- Reward history
- APY estimate
```

### 7.4 Reward Dashboard

```
Features:
- Total earned (all time)
- Earnings this epoch
- Storage contribution (TB)
- PoSpace success rate
- Uptime percentage
```

### 7.5 FFI Bindings

```
New C engine tasks:
- TASK_DNAC_GET_BALANCE
- TASK_DNAC_SEND
- TASK_DNAC_STAKE_LOCK
- TASK_DNAC_STAKE_UNLOCK
- TASK_DNAC_BRIDGE_BURN
- TASK_DNAC_GET_HISTORY
- TASK_DNAC_GET_REWARDS

Each follows the standard module pattern:
  dna_engine_internal.h (task type)
  dna_engine_dnac.c (handler)
  dna_engine.c (dispatch)
  dna_engine.h (public API)
```

### 7.6 i18n

All new strings in `app_en.arb` + `app_tr.arb`. No hardcoded strings.

**Deliverable:** Full DNAC wallet in messenger app, tested on testnet.

---

## Phase 8: Block Explorer (1-2 weeks)

**Goal:** Minimal web-based explorer for transparency.

**Dependency:** Phase 2 (RPC API).

### 8.1 Backend

```
Stack: Python (Flask) + DNAC RPC
Endpoint: Nodus RPC on port 4002

Routes:
- /tx/<hash>         -> Transaction details
- /address/<fp>      -> Balance + TX history
- /block/<height>    -> Block details
- /blocks            -> Latest blocks (paginated)
- /stats             -> Network stats (height, supply, validators)
- /bridge            -> Burn bridge history
- /api/*             -> JSON API for programmatic access
```

### 8.2 Frontend

```
Simple HTML/JS (no framework needed)
- Search bar (TX hash, address, block height)
- Latest blocks table (auto-refresh)
- Network stats sidebar
- Mobile-responsive
```

### 8.3 Deployment

```
Host: explorer.cpunk.io (or cpunk.io/explorer)
Server: cpunk-deploy (75.119.141.51)
```

**Deliverable:** Block explorer live at explorer.cpunk.io.

---

## Phase 9: Exchange Integration (2-3 weeks)

**Goal:** BitcoinTry can deposit/withdraw DNAC CPUNK.

**Dependency:** Phase 2 (RPC), Phase 6 (testnet), Phase 8 (explorer).

### 9.1 Integration Documentation

```
File: docs/EXCHANGE_INTEGRATION.md

Contents:
- RPC API reference (all methods with examples)
- Authentication (future: API keys)
- Deposit detection flow
- Withdrawal signing flow
- Confirmation depth recommendation
- Testnet endpoint for testing
- Error handling guide
- Rate limits
```

### 9.2 Exchange Test Environment

```
1. Provide testnet RPC endpoint to BitcoinTry
2. Provide test XXX tokens
3. Provide curl examples for every operation
4. Direct technical support (CEO relationship)
```

### 9.3 Integration Flow

```
Deposit:
1. Exchange generates DNAC address per user
2. Monitor RPC for incoming TXs to exchange addresses
3. After N confirmations: credit user balance
4. Display in exchange UI

Withdrawal:
1. User requests withdrawal
2. Exchange builds DNAC TX (coin selection from hot wallet UTXOs)
3. Sign with exchange hot wallet key
4. Submit via dnac_sendTransaction RPC
5. Return TX hash to user
```

### 9.4 Soft Migration on Exchange

```
Phase A: CF20 stays, DNAC added alongside
Phase B: Both chains active, user chooses
Phase C: DNAC becomes default, CF20 remains available
```

**Deliverable:** BitcoinTry integration docs + testnet access provided.

---

## Phase 10: Mainnet Launch

**Goal:** XXX -> CPUNK rename, fresh genesis, burn bridge live.

**Dependency:** ALL phases complete. Security hardened.

### 10.1 Pre-Launch Checklist

```
- [ ] All security tests passed (Phase 6.4)
- [ ] No critical bugs in 2+ weeks of testnet
- [ ] Exchange integration tested on testnet
- [ ] Flutter app tested on Android + Linux
- [ ] Block explorer operational
- [ ] Whitepaper published (cpunk.io)
- [ ] Tokenomics paper published
- [ ] All 6 nodus nodes updated to release version
- [ ] Burn address created and published
- [ ] Genesis parameters finalized
```

### 10.2 Launch Sequence

```
Day -7:  Final code freeze. Release candidate build.
Day -3:  Deploy release to all 6 nodus nodes.
Day -2:  Wipe testnet data. Fresh databases.
Day -1:  Genesis: mint CPUNK on DNAC (initial distribution from treasury).
Day  0:  LAUNCH
         - Burn bridge activated
         - RPC API public
         - Block explorer live
         - Whitepaper published on cpunk.io
         - Exchange notified: "DNAC chain is live"
         - Community announcement (Telegram, cpunk.club)
Day +1:  Monitor. Fix any issues.
Day +7:  First stability report.
Day +30: Enable slashing (if sufficient operators).
```

### 10.3 Post-Launch Monitoring

```
Daily checks:
- All 6 nodus nodes online
- BFT consensus operating (blocks being produced)
- No failed TXs in last 24h
- RPC API responsive
- Block explorer synced
- Bridge processing burns correctly
- Emission rewards distributing
```

---

## Phase 11: Growth

**Goal:** Community operators, exchange migration, ecosystem expansion.

### 11.1 Community Operator Onboarding

```
1. Publish "How to Run a CPUNK Nodus" guide
2. Open-source nodus-server binary
3. Provide nodus.conf template
4. Support community operators (Telegram)
5. Monitor new operators joining (stake events)
```

### 11.2 Exchange Full Migration

```
1. BitcoinTry adds DNAC deposit/withdraw
2. Both CF20 and DNAC supported in parallel
3. DNAC becomes default over time
4. CF20 deprecated when volume drops
```

### 11.3 Future Features

```
- Governance mechanism (stake-weighted voting)
- Dynamic committee size (scale with operators)
- Additional exchange listings
- Mobile notifications for rewards
- STARK-based amount privacy (v2 protocol)
- iOS app
- Web messenger (WebAssembly)
```

---

## Timeline Summary

```
Phase 1:  Decisions                    Week 1          (1 week)
Phase 2:  JSON-RPC API                 Week 2-4        (2-3 weeks)
Phase 3:  New TX Types                 Week 3-6        (3-4 weeks, parallel with Phase 2)
Phase 4:  Proof of Space               Week 7-9        (2-3 weeks)
Phase 5:  Slashing                     Week 8-9        (1-2 weeks, parallel with Phase 4)
Phase 6:  Testnet                      Week 10-12      (2-3 weeks)
Phase 7:  Flutter Integration          Week 10-13      (3-4 weeks, parallel with Phase 6)
Phase 8:  Block Explorer               Week 11-12      (1-2 weeks, parallel)
Phase 9:  Exchange Integration         Week 13-15      (2-3 weeks)
Phase 10: Mainnet Launch               Week 16         (1 week)
Phase 11: Growth                       Week 17+        (ongoing)

Total: ~4 months to mainnet launch
```

```
         W1   W2   W3   W4   W5   W6   W7   W8   W9   W10  W11  W12  W13  W14  W15  W16
Phase 1  ████
Phase 2       ████████████
Phase 3            ████████████████
Phase 4                              ████████████
Phase 5                                   ████████
Phase 6                                             ████████████
Phase 7                                             ████████████████
Phase 8                                                  ████████
Phase 9                                                            ████████████
Phase 10                                                                          ████
                                                                                   ^
                                                                              MAINNET
```

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|------------|------------|
| Cellframe RPC becomes unreachable | Bridge pauses | Medium | Bridge auto-pauses, DNAC continues independently |
| Low initial operator count | Centralization | Medium | Founder operates 6 nodes (60M staked) as baseline |
| Exchange refuses DNAC integration | Limited liquidity | Low | Strong CEO relationship, we provide all tech support |
| Security vulnerability in BFT | Loss of funds | Low | Extensive testnet, fuzz testing, adversarial testing |
| Slow CF20 migration | Split liquidity | Medium | No deadline pressure — natural market incentives |
| Quantum computer arrives early | Crypto broken | Very Low | Already post-quantum (Category 5) — this is our advantage |
| Community resistance to migration | Low adoption | Low | Voluntary, incentivized (staking rewards), no forced migration |

---

*This roadmap is a living document. Phases may overlap, timelines may shift, but the sequence and dependencies are fixed.*
