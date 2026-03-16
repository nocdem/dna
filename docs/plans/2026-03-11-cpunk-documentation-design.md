# CPUNK Documentation Suite — Design Document

**Date:** 2026-03-11
**Status:** Approved
**Confidentiality:** INTERNAL — Do not commit to git

---

## Overview

Three documents to be written for the CPUNK/DNAC ecosystem:

1. **CPUNK Whitepaper** — Public, vision-driven + mathematical references
2. **Technical Specification** — Internal, developer-facing
3. **Tokenomics Paper** — Public + internal, detailed economics

**Language:** English
**Style:** Vision-driven with formal mathematics and references where needed
**Branding:** CPUNK (no rebrand), DNAC = technical infrastructure name
**Cellframe:** Detailed coverage — CF20 history, why migrating, burn bridge mechanism
**DNA Connect:** Primary value proposition — messenger + token + network = one product

---

## Document 1: CPUNK Whitepaper

**Audience:** Public, community, investors
**Length:** 15-25 pages
**Tone:** Vision-driven, accessible, backed by math and references

### Outline

1. **Abstract**
   - CPUNK in one sentence: what it is, what it solves

2. **Introduction**
   - Problems with current crypto ecosystem
   - Post-quantum threat landscape
   - Why messenger + token + network matters
   - Independence from Cellframe

3. **Vision**
   - One product: encrypted messaging + native token + DHT network
   - Anyone can run a nodus, anyone can earn
   - Post-quantum security (Dilithium5, Kyber1024)
   - No other project combines these three

4. **Architecture**
   - Nodus DHT network overview
   - BFT consensus (PBFT)
   - UTXO transaction model
   - DNA Connect integration
   - System diagram

5. **Tokenomics**
   - Existing supply (1B CF20)
   - Burn bridge (CF20 → DNAC, one-way)
   - New emission (validator rewards, Bitcoin-style decay)
   - Dual supply model explained
   - Supply projections (charts/tables)

6. **Proof of Space / Storage**
   - Real DHT data storage (not fake plots)
   - Challenge-response mechanism
   - Reward distribution model
   - Comparison: Chia / Filecoin / Subspace

7. **Staking**
   - 10M CPUNK minimum stake
   - Equal rules — no privileged nodes
   - Governance-adjustable threshold
   - Stake economics overview

8. **Slashing**
   - Violation types and penalties
   - Phased activation (disabled → enabled → governance-tuned)
   - Attack cost analysis

9. **Burn Bridge**
   - CF20 → DNAC one-way burn mechanism
   - Verification via Cellframe RPC
   - Security model (no locked funds, no multisig risk)
   - Supply flow over time (CF20 shrinks, DNAC grows)

10. **Security**
    - Post-quantum cryptography (NIST Category 5)
    - Dilithium5 (ML-DSA-87): signatures
    - Kyber1024 (ML-KEM-1024): key encapsulation
    - SHA3-512: hashing
    - BFT consensus security properties
    - Attack vectors and defenses

11. **Roadmap**
    - Testnet (XXX token on existing nodus)
    - Mainnet launch
    - Exchange integration
    - Future: governance, dynamic committee, STARKs (v2)

12. **References**
    - Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System" (2008)
    - Buterin, V. "Ethereum: A Next-Generation Smart Contract and Decentralized Application Platform" (2014)
    - Cohen, B. "Chia Network" — Proof of Space and Time
    - Protocol Labs. "Filecoin: A Decentralized Storage Network" (2017)
    - Subspace Labs. "Proof-of-Archival-Storage"
    - NIST. "ML-KEM (FIPS 203)" and "ML-DSA (FIPS 204)" (2024)
    - Castro, M. & Liskov, B. "Practical Byzantine Fault Tolerance" (1999)

---

## Document 2: Technical Specification

**Audience:** Internal, developers
**Length:** 30-40 pages
**Tone:** Formal technical, precise, implementation-ready

### Outline

1. **Overview**
   - System components and dependencies
   - Code structure (nodus/, dnac/, messenger/, shared/crypto/)
   - Dependency graph

2. **Wire Protocol**
   - CBOR over TCP (existing nodus wire format)
   - New message types: BRIDGE_MINT, STAKE_LOCK, STAKE_UNLOCK
   - Message ID allocations
   - Serialization format

3. **BFT Consensus Protocol**
   - PROPOSE → PREVOTE → PRECOMMIT → COMMIT
   - Leader election: (epoch + view) % N
   - Quorum calculation: 2f+1 for N=3f+1
   - View change protocol (future)
   - New BFT message types for staking and bridge

4. **DNAC Transaction Format**
   - Existing: TX_GENESIS, TX_SPEND, TX_BURN
   - New: TX_BRIDGE_MINT, TX_STAKE_LOCK, TX_STAKE_UNLOCK, TX_REWARD
   - Byte-level serialization layout
   - Nullifier computation: SHA3-512(secret || UTXO_data)
   - Transaction hash computation

5. **Staking Protocol**
   - Stake lock TX format and fields
   - Stake unlock TX format (+ waiting period enforcement)
   - Stake database schema (SQLite)
   - Validator selection algorithm
   - Minimum stake verification

6. **Proof of Space Protocol**
   - Challenge generation (random DHT key selection)
   - Response format and verification
   - Storage scoring algorithm
   - Reward calculation formula
   - Challenge frequency and timing

7. **Emission Mechanism**
   - Block reward calculation per epoch
   - Halving/decay schedule implementation
   - Mint TX format (TX_REWARD)
   - Emission tracking in witness database

8. **Burn Bridge Protocol**
   - CF20 burn TX verification via Cellframe RPC
   - BRIDGE_MINT BFT consensus flow (step by step)
   - Burn dedup database schema
   - Error scenarios and recovery
   - Burn address specification

9. **JSON-RPC API**
   - Endpoint: POST /rpc (port 4002)
   - JSON-RPC 2.0 compliance
   - All methods with full request/response JSON schemas:
     - dnac_getBalance
     - dnac_getTransaction
     - dnac_getBlock / dnac_getBlockRange
     - dnac_getUTXOs
     - dnac_sendTransaction
     - dnac_getTransactionHistory
     - dnac_getChainHeight
     - dnac_getWitnessList
     - dnac_validateAddress
   - Error codes and meanings
   - Rate limiting
   - Authentication (future)

10. **Database Schemas**
    - Existing: dnac_utxos, dnac_transactions, committed_transactions
    - New: stake_locks, burn_history, pos_challenges, emission_log
    - Migration strategy
    - Index design

11. **Nodus Configuration**
    - nodus.conf new parameters
    - RPC port, stake parameters, PoSpace parameters
    - Default values

12. **Test Strategy**
    - Unit test plan (per module)
    - Integration test plan (end-to-end flows)
    - Adversarial test scenarios
    - Fuzz testing targets

---

## Document 3: Tokenomics Paper

**Audience:** Public + internal, economics-focused
**Length:** 15-20 pages
**Tone:** Vision-driven with formal mathematics

### Outline

1. **Abstract**
   - CPUNK economic model in one paragraph

2. **Current Supply Analysis**
   - CF20 distribution: holder breakdown
   - Top holder concentration
   - Exchange liquidity
   - Treasury position (~300M)

3. **Dual Supply Model**
   - CF20 (fixed, 1B) vs DNAC (growing)
   - Burn bridge supply flow
   - Mathematical model:
     ```
     CF20(t) = 1B - B(t)           // B(t) = cumulative burns
     DNAC(t) = B(t) + E(t)         // E(t) = cumulative emission
     Total(t) = 1B + E(t)          // total ecosystem supply
     ```

4. **Emission Curve**
   - Model selection: halving vs smooth decay
   - Halving model:
     ```
     R(n) = R₀ / 2^(n/H)          // R₀ = initial reward, H = halving period
     ```
   - Smooth decay model:
     ```
     R(t) = R₀ · e^(-λt)          // λ = decay constant
     ```
   - Total emission calculation: E(∞) = Σ R(n)
   - Charts: annual emission, cumulative supply
   - Parameter selection: R₀, H or λ, total cap

5. **Staking Economics**
   - Minimum stake: 10M CPUNK
   - Stake ratio vs reward ratio
   - APY calculation:
     ```
     APY = (annual_emission × operator_share) / total_staked
     ```
   - Scenario analysis:
     - 10 operators (100M staked) → APY = ?
     - 50 operators (500M staked) → APY = ?
     - 100 operators (1B staked) → APY = ?
   - Stake equilibrium point

6. **Slashing Economics**
   - Penalty amounts and deterrence analysis
   - Attack cost calculation:
     ```
     Attack_cost = stake × slash_rate
     ```
   - Attack profit vs attack cost ratio
   - Minimum stake as security threshold

7. **Proof of Space Economics**
   - Storage cost ($/TB/month)
   - Reward per TB calculation
   - Profitability threshold: minimum TB required
   - Comparison: Chia farming cost vs CPUNK nodus cost

8. **Burn Bridge Dynamics**
   - Migration velocity estimation
   - Game theory: when is burning rational?
   - Price impact model:
     ```
     CF20: decreasing supply → price pressure
     DNAC: increasing utility → demand
     ```
   - Equilibrium analysis

9. **Fee Model**
   - Zero fee vs minimal fee
   - Spam protection without fees
   - Rate limiting alternative

10. **Inflation Analysis**
    - Annual inflation rate:
      ```
      inflation(t) = E(t) / (1B + E(t-1))
      ```
    - Bitcoin comparison
    - Target: long-term < 1%/year

11. **Scenario Simulations**
    - Bull case: fast migration, 50+ operators
    - Base case: moderate migration, 20 operators
    - Bear case: slow migration, 10 operators
    - Per scenario: supply, APY, inflation, TVL

12. **Parameter Recommendations**
    - Recommended R₀, halving period, total cap
    - Recommended minimum stake
    - Recommended slashing rates
    - Sensitivity analysis

13. **References**
    - Bitcoin monetary policy (Nakamoto, 2008)
    - Ethereum EIP-1559 (Buterin et al., 2021)
    - Chia farming economics
    - Filecoin economic model (Protocol Labs, 2020)
    - Subspace/Autonomys tokenomics (2024)

---

## Security & Confidentiality

- **Design doc** (`DNAC_CPUNK_DESIGN.md`): NEVER commit — .gitignore
- **This plan**: NEVER commit — .gitignore
- **Whitepaper**: Public ONLY when ready for release
- **Technical Spec**: Internal only
- **Tokenomics Paper**: Public ONLY when ready for release
- All drafts stay local until explicit release approval

---

## Writing Order

| Priority | Document | Dependency |
|----------|----------|-----------|
| 1 | Whitepaper | None — can start immediately |
| 2 | Tokenomics Paper | Needs finalized emission parameters |
| 3 | Technical Specification | Needs implementation decisions |
