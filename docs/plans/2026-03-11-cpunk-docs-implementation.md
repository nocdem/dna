# CPUNK Documentation Suite — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Write three documents — Whitepaper, Technical Specification, Tokenomics Paper — for the CPUNK/DNAC ecosystem.

**Architecture:** Each document is written section-by-section, reviewed after each section, then assembled. Whitepaper first (no dependencies), Tokenomics second (needs emission parameter decisions), Technical Spec third (needs implementation decisions).

**Tech Stack:** Markdown, LaTeX math notation (for tokenomics), Mermaid diagrams

**Key References:**
- Internal design doc: `/opt/dna/docs/DNAC_CPUNK_DESIGN.md`
- Design outline: `/opt/dna/docs/plans/2026-03-11-cpunk-documentation-design.md`
- DNAC codebase: `/opt/dna/dnac/`
- Nodus codebase: `/opt/dna/nodus/`
- Messenger codebase: `/opt/dna/messenger/`
- DNAC README: `/opt/dna/dnac/README.md`
- DNAC public API: `/opt/dna/dnac/include/dnac/dnac.h`

**Confidentiality:** ALL documents stay in `/opt/dna/docs/` and are covered by `.gitignore`. NEVER commit until explicit release approval.

---

## DOCUMENT 1: CPUNK WHITEPAPER

### Task 1: Abstract + Introduction

**Files:**
- Create: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write Abstract**

One paragraph: what CPUNK is, what problem it solves, key innovation (messenger + token + DHT = one product).

**Step 2: Write Introduction**

Cover:
- Current crypto problems (centralized infrastructure dependency, quantum vulnerability)
- Post-quantum threat (Shor's algorithm, NIST timeline)
- Why combining messenger + token + network matters (no other project does this)
- Brief Cellframe history — started as CF20, now own chain
- Reference: NIST PQ standards (FIPS 203, 204)

**Step 3: Review with user**

Present section, get approval before continuing.

**Step 4: Save checkpoint**

---

### Task 2: Vision

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write Vision section**

Cover:
- Single product: encrypted messaging + native token + DHT network
- Post-quantum security stack (Dilithium5/Kyber1024/SHA3-512)
- Anyone can run a nodus = anyone can earn
- Decentralized infrastructure owned by the community
- Not just a token — a complete communication + financial ecosystem

**Step 2: Review with user**

---

### Task 3: Architecture

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`
- Read: `/opt/dna/dnac/README.md` (architecture section)
- Read: `/opt/dna/nodus/include/nodus/nodus_types.h` (constants)

**Step 1: Write Architecture section**

Cover:
- Nodus DHT network (Kademlia, 512-bit keyspace, k=8)
- BFT consensus (PBFT: PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- UTXO transaction model (Dilithium5 signed)
- DNA Connect integration (FFI, real-time messaging over DHT)
- System diagram (ASCII art or description for later graphic)

**Step 2: Add architecture diagram**

```
DNA Connect (Flutter)
    │ FFI
DNA Engine (C)
    │
    ├── Nodus Network (DHT + BFT)
    │   ├── Storage Layer (messages, TXs, channels)
    │   ├── Consensus Layer (PBFT witness)
    │   └── Transport Layer (TCP + UDP)
    │
    └── DNAC (native CPUNK)
        ├── UTXO Wallet
        ├── Staking
        ├── PoSpace Rewards
        └── Burn Bridge (CF20)
```

**Step 3: Review with user**

---

### Task 4: Tokenomics (Whitepaper version — summary)

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`
- Read: `/opt/dna/docs/DNAC_CPUNK_DESIGN.md` (tokenomics section)

**Step 1: Write Tokenomics section**

Cover:
- Existing supply: 1B CF20 (~70% community, ~30% treasury)
- One-way burn bridge: CF20 → DNAC (irreversible)
- New emission: validator rewards above 1B, Bitcoin-style decay
- Dual supply model: CF20 shrinks, DNAC grows
- Supply projection table (Year 0, 1, 5, 10, 20, 40)
- Reference to separate Tokenomics Paper for full mathematics

**Step 2: Review with user**

---

### Task 5: Proof of Space / Storage

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write PoSpace section**

Cover:
- Real DHT data storage (not fake plots like Chia)
- Challenge-response: "prove you store DHT key X"
- Reward proportional to: storage amount × uptime × challenge success
- Comparison table: Chia (fake data) vs Filecoin (real files) vs Subspace (blockchain archive) vs CPUNK (real DHT data)
- Why real data is better: useful storage strengthens the network
- Reference: Cohen (Chia), Protocol Labs (Filecoin)

**Step 2: Review with user**

---

### Task 6: Staking + Slashing

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write Staking section**

Cover:
- 10M CPUNK minimum stake
- Equal rules — protocol doesn't know who runs the node
- Governance can adjust threshold
- Unstaking waiting period

**Step 2: Write Slashing section**

Cover:
- Violation types: offline, equivocation, fraud
- Penalty table
- Phased activation (disabled → enabled → governance)
- Attack cost > attack profit (reference to Tokenomics Paper)

**Step 3: Review with user**

---

### Task 7: Burn Bridge

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write Burn Bridge section**

Cover:
- One-way: CF20 burned permanently → DNAC minted
- Why one-way: no locked funds, no multisig risk, no committee rotation
- Verification: witnesses check Cellframe RPC independently
- BFT consensus required (2-of-3+)
- Supply flow diagram over time
- Security: no funds to steal, burn dedup prevents double-mint

**Step 2: Review with user**

---

### Task 8: Security

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write Security section**

Cover:
- Post-quantum cryptography: NIST Category 5
  - Dilithium5 (ML-DSA-87): 4627-byte signatures, 2592-byte pubkeys
  - Kyber1024 (ML-KEM-1024): 1568-byte ciphertext
  - SHA3-512: 64-byte hashes
- BFT consensus security properties (Byzantine fault tolerance up to f < n/3)
- Attack vectors and defenses:
  - Double-spend → BFT consensus + nullifier database
  - Sybil → stake requirement (10M CPUNK)
  - Storage fraud → random PoSpace challenges
  - Bridge fraud → BFT quorum + Cellframe RPC verification
  - Quantum → native post-quantum cryptography
- Reference: NIST FIPS 203/204, Castro & Liskov (PBFT, 1999)

**Step 2: Review with user**

---

### Task 9: Roadmap + References

**Files:**
- Modify: `docs/CPUNK_WHITEPAPER.md`

**Step 1: Write Roadmap**

- Phase 0: Testnet (existing 6 nodus, XXX token)
- Phase 1: Mainnet launch (XXX → CPUNK, burn bridge active)
- Phase 2: Growth (community operators, slashing enabled)
- Phase 3: Maturity (50+ operators, governance)
- Future: STARKs for zero-knowledge amounts (v2)

**Step 2: Write References section**

Full academic references:
- Nakamoto (2008) — Bitcoin
- Buterin (2014) — Ethereum
- Cohen — Chia PoSpace
- Protocol Labs (2017) — Filecoin
- Subspace Labs — PoArchival Storage
- NIST FIPS 203, 204 (2024) — ML-KEM, ML-DSA
- Castro & Liskov (1999) — PBFT

**Step 3: Final review of complete whitepaper**

---

## DOCUMENT 2: TOKENOMICS PAPER

### Task 10: Tokenomics — Supply Model + Emission Math

**Files:**
- Create: `docs/CPUNK_TOKENOMICS.md`

**Step 1: Write Abstract + Current Supply Analysis**

**Step 2: Write Dual Supply Model with formal math**

```
CF20(t) = 1B - B(t)
DNAC(t) = B(t) + E(t)
Total(t) = 1B + E(t)
```

**Step 3: Write Emission Curve section**

Both models with full derivation:
- Halving: R(n) = R₀ / 2^(n/H)
- Smooth decay: R(t) = R₀ · e^(-λt)
- Total emission: E(∞) = Σ R(n) or ∫R(t)dt
- Parameter recommendations

**Step 4: Review with user — DECISION NEEDED: emission parameters**

---

### Task 11: Tokenomics — Staking + Slashing Economics

**Files:**
- Modify: `docs/CPUNK_TOKENOMICS.md`

**Step 1: Write Staking Economics**

- APY = (annual_emission × operator_share) / total_staked
- Scenario table: 10/50/100 operators
- Equilibrium analysis

**Step 2: Write Slashing Economics**

- Attack_cost = stake × slash_rate
- Attack profit vs cost ratio
- Security threshold

**Step 3: Review with user**

---

### Task 12: Tokenomics — PoSpace Economics + Bridge Dynamics

**Files:**
- Modify: `docs/CPUNK_TOKENOMICS.md`

**Step 1: Write PoSpace Economics**

- Storage cost ($/TB/month)
- Reward/TB calculation
- Profitability threshold
- Chia comparison

**Step 2: Write Burn Bridge Dynamics**

- Game theory: when is burning rational?
- Migration velocity model
- Price pressure analysis

**Step 3: Write Fee Model**

- Zero fee vs minimal fee
- Spam protection alternatives

**Step 4: Review with user**

---

### Task 13: Tokenomics — Inflation + Scenarios + Parameters

**Files:**
- Modify: `docs/CPUNK_TOKENOMICS.md`

**Step 1: Write Inflation Analysis**

- inflation(t) = E(t) / (1B + E(t-1))
- Bitcoin comparison chart
- Target: < 1%/year long-term

**Step 2: Write Scenario Simulations**

- Bull / Base / Bear case tables
- Per scenario: supply, APY, inflation, TVL

**Step 3: Write Parameter Recommendations**

- Final recommended values for all parameters
- Sensitivity analysis

**Step 4: Write References**

**Step 5: Final review of complete tokenomics paper**

---

## DOCUMENT 3: TECHNICAL SPECIFICATION

### Task 14: Tech Spec — Overview + Wire Protocol

**Files:**
- Create: `docs/CPUNK_TECHNICAL_SPEC.md`
- Read: `/opt/dna/nodus/include/nodus/nodus_types.h`
- Read: `/opt/dna/nodus/src/protocol/`

**Step 1: Write Overview**

- System components, dependency graph, code structure

**Step 2: Write Wire Protocol section**

- CBOR over TCP format
- New message type IDs
- Serialization details

**Step 3: Review with user**

---

### Task 15: Tech Spec — BFT + Transaction Format

**Files:**
- Modify: `docs/CPUNK_TECHNICAL_SPEC.md`
- Read: `/opt/dna/dnac/include/dnac/bft.h`
- Read: `/opt/dna/dnac/include/dnac/transaction.h`

**Step 1: Write BFT Consensus Protocol**

- Full protocol description with message flow
- Leader election formula
- Quorum math

**Step 2: Write Transaction Format**

- All TX types with byte-level layout
- New types: TX_BRIDGE_MINT, TX_STAKE_LOCK, TX_STAKE_UNLOCK, TX_REWARD

**Step 3: Review with user**

---

### Task 16: Tech Spec — Staking + PoSpace + Emission Protocol

**Files:**
- Modify: `docs/CPUNK_TECHNICAL_SPEC.md`

**Step 1: Write Staking Protocol**

- Lock/unlock TX format
- Database schema
- Validator selection algorithm

**Step 2: Write PoSpace Protocol**

- Challenge generation
- Response verification
- Scoring algorithm

**Step 3: Write Emission Mechanism**

- Block reward calculation
- Halving implementation
- Mint TX format

**Step 4: Review with user**

---

### Task 17: Tech Spec — Bridge + RPC API

**Files:**
- Modify: `docs/CPUNK_TECHNICAL_SPEC.md`
- Read: `/opt/dna/messenger/blockchain/cellframe/cellframe_rpc.h`

**Step 1: Write Burn Bridge Protocol**

- Step-by-step BFT flow for burn verification
- Cellframe RPC calls used
- Burn dedup schema
- Error scenarios

**Step 2: Write JSON-RPC API**

- Full request/response JSON for every method
- Error codes
- Rate limiting

**Step 3: Review with user**

---

### Task 18: Tech Spec — Database + Config + Test Strategy

**Files:**
- Modify: `docs/CPUNK_TECHNICAL_SPEC.md`

**Step 1: Write Database Schemas**

- All new tables with CREATE TABLE statements
- Migration strategy

**Step 2: Write Configuration**

- nodus.conf new parameters
- Defaults

**Step 3: Write Test Strategy**

- Unit tests per module
- Integration tests
- Adversarial scenarios
- Fuzz targets

**Step 4: Final review of complete tech spec**

---

## Execution Order

```
Week 1-2: Whitepaper (Tasks 1-9)
  ├── Task 1: Abstract + Introduction
  ├── Task 2: Vision
  ├── Task 3: Architecture
  ├── Task 4: Tokenomics summary
  ├── Task 5: Proof of Space
  ├── Task 6: Staking + Slashing
  ├── Task 7: Burn Bridge
  ├── Task 8: Security
  └── Task 9: Roadmap + References

Week 3: Tokenomics Paper (Tasks 10-13)
  ├── Task 10: Supply model + emission math
  ├── Task 11: Staking + slashing economics
  ├── Task 12: PoSpace economics + bridge dynamics
  └── Task 13: Inflation + scenarios + parameters

Week 4-5: Technical Specification (Tasks 14-18)
  ├── Task 14: Overview + wire protocol
  ├── Task 15: BFT + transaction format
  ├── Task 16: Staking + PoSpace + emission protocol
  ├── Task 17: Bridge + RPC API
  └── Task 18: Database + config + test strategy
```

---

## Decision Points (BLOCKING)

These decisions MUST be made before the relevant tasks can be completed:

| Decision | Needed for | Task |
|----------|-----------|------|
| Emission cap (e.g., +500M) | Tokenomics math | Task 10 |
| Halving vs smooth decay | Tokenomics math | Task 10 |
| Halving period (e.g., 3 years) | Tokenomics math | Task 10 |
| Initial block reward (R₀) | Tokenomics math | Task 10 |
| Epoch duration | Tech spec | Task 16 |
| Unstaking period | Tech spec | Task 16 |
| TX fee (zero/minimal) | Whitepaper + tokenomics | Task 4, 12 |
| PoSpace challenge frequency | Tech spec | Task 16 |
| Testnet token name | Whitepaper roadmap | Task 9 |
