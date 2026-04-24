> **ARCHIVED 2026-04-24** — v0.1 Draft (March 2026). Recommended parameters below (R₀ = 158.55 CPUNK/epoch, H = 3 years, E_cap = 500M, zero-fee) are **design proposals**, not deployed mainnet values. Since this was written, halving logic has shipped but not deployed, and a non-zero `DNAC_MIN_FEE_RAW` (0.01 DNAC) landed in v0.17.1. A replacement doc requires pinning actual deployed params against `dnac/include/dnac/*.h` + genesis config — that is a separate task. Kept for history and reasoning context.

# CPUNK Tokenomics: Economic Model and Parameter Analysis

**Version:** 0.1 (Draft)
**Date:** March 2026
**Authors:** CPUNK Development Team
**Companion to:** CPUNK Whitepaper

---

## Abstract

This paper presents the formal economic model of the CPUNK ecosystem. We define the dual supply model governing the migration from Cellframe (CF20) to the DNAC native chain, derive the emission curve that governs new token creation, and analyze the staking, slashing, and Proof of Space economics that determine validator incentives. The model is parameterized to allow governance adjustment while maintaining the core invariant: long-term annual inflation below 1%, converging toward a bounded total supply. We provide scenario simulations under bull, base, and bear market assumptions, and conclude with recommended parameter values and sensitivity analysis.

---

## 1. Current Supply Analysis

### 1.1 CF20 Distribution

CPUNK exists on the Cellframe blockchain as a CF20 token with a fixed, immutable supply of 1,000,000,000 (one billion) tokens. No mechanism exists to mint new CF20 tokens — the supply is permanently capped at genesis.

| Category | Amount | Share |
|----------|--------|-------|
| Community holders | ~700,000,000 | ~70% |
| CPUNK treasury | ~300,000,000 | ~30% |
| **Total** | **1,000,000,000** | **100%** |

The community allocation is fully distributed — no vesting schedules, no locked tranches, no cliff periods. Tokens are held in individual wallets and are freely transferable.

### 1.2 Exchange Liquidity

CPUNK is listed on BitcoinTry, the sole centralized exchange supporting the token. Cell DEX provides additional decentralized liquidity on the Cellframe network. Primary liquidity is controlled by the project team, providing stability but also concentration risk.

### 1.3 Treasury Position

The treasury holds approximately 300 million CPUNK (~30% of supply). These tokens are available for:
- Ecosystem development funding
- Strategic partnerships and exchange listings
- Community grants and incentive programs
- Initial staking on DNAC (founder operates 6 nodus nodes at 10M stake each = 60M from treasury)

---

## 2. Dual Supply Model

### 2.1 Formal Definition

The CPUNK ecosystem spans two chains. We define the following variables:

| Symbol | Definition |
|--------|-----------|
| B(t) | Cumulative CF20 tokens burned by time t |
| E(t) | Cumulative validator emission on DNAC by time t |
| S₀ | Initial CF20 supply = 1,000,000,000 |

The supply on each chain at time t:

```
CF20(t)      = S₀ − B(t)                          (1)
DNAC(t)      = B(t) + E(t)                          (2)
Ecosystem(t) = S₀ + E(t)                            (3)
```

**Equation (1):** CF20 supply is strictly decreasing. Every burn permanently removes tokens from Cellframe. The lower bound is 0 (all tokens burned).

**Equation (2):** DNAC supply has two sources — burn-minted tokens B(t) and emission-minted tokens E(t). Both are monotonically non-decreasing.

**Equation (3):** Total ecosystem supply equals the original billion plus cumulative emission. Burns do not increase total supply — they transfer supply across chains. Only emission creates new tokens.

### 2.2 Key Invariants

The model enforces several invariants that hold at all times:

```
B(t) ≤ S₀                                           (4)
    Burns cannot exceed the original supply.

E(t) ≤ E_cap                                        (5)
    Emission is bounded by a finite cap.

Ecosystem(t) ≤ S₀ + E_cap                           (6)
    Total supply is bounded.

CF20(t) ≥ 0                                          (7)
    CF20 supply cannot go negative.

DNAC(t) ≥ 0                                          (8)
    DNAC supply is non-negative (trivially true from definition).
```

### 2.3 Fungibility

All CPUNK on DNAC is fully fungible. There is no on-chain distinction between burn-minted and emission-minted tokens. This is a direct consequence of the one-way burn design:

- No `ORIGIN_BRIDGED` tag exists
- No `ORIGIN_MINED` tag exists
- No restricted UTXOs exist
- One CPUNK = one CPUNK, regardless of origin

This simplifies wallet software, exchange integration, and smart contract interactions. It also eliminates an entire class of bugs and attack vectors related to token origin tracking.

---

## 3. Emission Curve

### 3.1 Design Constraints

The emission curve must satisfy the following requirements:

1. **Finite total emission.** E(∞) must converge to a bounded value E_cap.
2. **Decreasing rate.** The emission rate must decrease over time, incentivizing early participation while ensuring long-term sustainability.
3. **Sub-1% terminal inflation.** Annual inflation must fall below 1% within a reasonable timeframe and continue declining.
4. **Simplicity.** The curve must be easily understood, verified, and implemented in consensus code.

### 3.2 Halving Model

The halving model, inspired by Bitcoin [1], divides time into fixed periods of H epochs. The reward per epoch halves at each period boundary:

```
R(n) = R₀ · 2^(−⌊n/H⌋)                             (9)
```

where:
- R(n) = reward at epoch n
- R₀ = initial reward per epoch
- H = halving period (in epochs)
- ⌊·⌋ = floor function

**Cumulative emission** after N epochs:

```
E(N) = Σ_{n=0}^{N-1} R(n)
     = R₀ · H · Σ_{k=0}^{⌊N/H⌋} 2^(-k)  +  remainder
```

**Total emission** (infinite horizon):

```
E(∞) = R₀ · H · Σ_{k=0}^{∞} 2^(-k)
     = R₀ · H · 2
     = 2 · R₀ · H                                   (10)
```

This gives a clean relationship: **total emission equals twice the product of initial reward and halving period.** To achieve a desired cap E_cap:

```
R₀ = E_cap / (2 · H)                                (11)
```

**Example parameterization:**

| Parameter | Value | Derivation |
|-----------|-------|-----------|
| E_cap | 500,000,000 CPUNK | Design choice — 50% of original supply |
| H | 1,576,800 epochs | ~3 years at 60s epochs (3 × 365.25 × 24 × 60) |
| R₀ | 158.55 CPUNK/epoch | E_cap / (2 × H) |
| Annual emission (year 1) | ~83,300,000 | R₀ × 525,960 epochs/year |
| Annual emission (year 4) | ~41,650,000 | Half of year 1 |
| Annual emission (year 7) | ~20,825,000 | Quarter of year 1 |

### 3.3 Smooth Decay Model

The smooth decay model replaces discrete halvings with continuous exponential decay:

```
R(t) = R₀ · e^(−λt)                                 (12)
```

where:
- R(t) = reward rate at time t (continuous)
- R₀ = initial reward rate
- λ = decay constant (1/s)
- t = time in seconds

**Cumulative emission:**

```
E(t) = ∫₀ᵗ R(τ) dτ
     = (R₀/λ) · (1 − e^(−λt))                      (13)
```

**Total emission:**

```
E(∞) = R₀/λ                                         (14)
```

To achieve a desired cap E_cap:

```
λ = R₀ / E_cap                                      (15)
```

The **half-life** (time for the reward to drop to 50%):

```
t_½ = ln(2) / λ ≈ 0.693 / λ                        (16)
```

**Example parameterization:**

| Parameter | Value | Derivation |
|-----------|-------|-----------|
| E_cap | 500,000,000 CPUNK | Design choice |
| t_½ | 3 years (94,672,800 s) | Design choice — comparable to halving model |
| λ | 7.32 × 10⁻⁹ s⁻¹ | ln(2) / t_½ |
| R₀ | 3.66 CPUNK/s | E_cap × λ |
| R₀ per epoch (60s) | 219.6 CPUNK/epoch | R₀ × 60 |
| Annual emission (year 1) | ~86,800,000 | Integral over first year |
| Annual emission (year 4) | ~43,400,000 | ~Half of year 1 |

### 3.4 Model Comparison

| Property | Halving | Smooth Decay |
|----------|---------|-------------|
| Emission curve | Step function | Continuous exponential |
| Market impact | Predictable "halving events" (can cause speculation) | Gradual, no discrete events |
| Implementation | Simple integer arithmetic | Requires floating-point or fixed-point exp() |
| Predictability | Easy to compute exact future rewards | Easy with the formula, harder to verify on-chain |
| Bitcoin precedent | Direct parallel — well-understood by market | Less familiar to crypto community |
| Total emission formula | E_cap = 2 · R₀ · H | E_cap = R₀ / λ |

**Recommendation:** The halving model is recommended for CPUNK due to its simplicity, Bitcoin precedent (market familiarity), and ease of on-chain verification using only integer arithmetic. The discrete halving events also create natural milestone points for the community.

### 3.5 Inflation Rate

Annual inflation rate at time t:

```
inflation(t) = E_annual(t) / Ecosystem(t−1)
             = E_annual(t) / (S₀ + E(t−1))          (17)
```

Under the halving model with recommended parameters:

| Year | Annual Emission | Cumulative Emission | Ecosystem Supply | Inflation Rate |
|------|----------------|--------------------|-----------------:|---------------:|
| 1 | ~83.3M | ~83.3M | ~1,083M | 7.69% |
| 2 | ~83.3M | ~166.6M | ~1,167M | 7.14% |
| 3 | ~83.3M | ~250.0M | ~1,250M | 6.67% |
| 4 | ~41.7M | ~291.7M | ~1,292M | 3.22% |
| 5 | ~41.7M | ~333.3M | ~1,333M | 3.13% |
| 6 | ~41.7M | ~375.0M | ~1,375M | 3.03% |
| 10 | ~20.8M | ~437.5M | ~1,438M | 1.45% |
| 15 | ~10.4M | ~478.1M | ~1,478M | 0.70% |
| 20 | ~5.2M | ~492.2M | ~1,492M | 0.35% |
| 40 | ~0.3M | ~499.9M | ~1,500M | 0.02% |

**Bitcoin comparison:** Bitcoin's inflation was ~4% after the first halving (2012), ~1.8% after the second (2016), and ~0.9% after the third (2020). CPUNK's inflation profile is comparable, reaching sub-1% by approximately year 13.

---

## 4. Staking Economics

### 4.1 Reward Distribution

Validator rewards are distributed from the emission pool. Each epoch, the block reward R(n) is allocated to the active validators based on their contributions:

```
reward_i(n) = R(n) · w_i / Σ w_j                    (18)
```

where w_i is the weight of validator i, determined by:
- Consensus participation (was the validator part of the committee this epoch?)
- PoSpace challenge success rate
- Uptime during the epoch

For simplicity of analysis, we assume equal weights among active validators:

```
reward_i(n) ≈ R(n) / N_active                       (19)
```

### 4.2 Annual Percentage Yield (APY)

The APY for a staking operator:

```
APY = (annual_reward_per_operator / stake_per_operator) × 100%
    = (annual_emission / N_active) / stake
    = annual_emission / (N_active × stake)           (20)
```

### 4.3 Scenario Analysis (Year 1)

Using R₀ = 158.55 CPUNK/epoch, annual emission ≈ 83.3M CPUNK, minimum stake = 10M:

| Operators | Total Staked | Reward/Operator/Year | APY |
|-----------|-------------|---------------------|-----|
| 6 | 60M | 13,883,333 | 138.8% |
| 10 | 100M | 8,330,000 | 83.3% |
| 20 | 200M | 4,165,000 | 41.7% |
| 50 | 500M | 1,666,000 | 16.7% |
| 100 | 1,000M | 833,000 | 8.3% |

**Interpretation:** Early operators receive extremely high APY due to low competition. As more operators join, APY decreases toward equilibrium. This creates a strong early-mover incentive that bootstraps the validator network.

### 4.4 Scenario Analysis (Year 5, post-halving)

Annual emission ≈ 41.7M CPUNK after first halving:

| Operators | Total Staked | Reward/Operator/Year | APY |
|-----------|-------------|---------------------|-----|
| 10 | 100M | 4,170,000 | 41.7% |
| 20 | 200M | 2,085,000 | 20.9% |
| 50 | 500M | 834,000 | 8.3% |
| 100 | 1,000M | 417,000 | 4.2% |

### 4.5 Staking Equilibrium

The equilibrium number of operators is reached when the APY from staking equals the opportunity cost of capital. Let r* be the market-clearing return rate:

```
N_eq = annual_emission / (stake × r*)               (21)
```

If the market expects 10% return:

| Year | Annual Emission | N_eq (at 10% target) |
|------|----------------|---------------------|
| 1 | 83.3M | 83 operators |
| 4 | 41.7M | 42 operators |
| 7 | 20.8M | 21 operators |
| 10 | 10.4M | 10 operators |

This natural equilibrium means the network self-regulates: if too few operators are staking, APY rises and attracts new entrants; if too many are staking, APY falls and marginal operators exit.

---

## 5. Slashing Economics

### 5.1 Attack Cost Analysis

The cost of a successful attack on BFT consensus requires controlling f+1 validators (for N = 3f+1). The minimum cost:

```
attack_cost = ⌈(N+1)/3⌉ × stake × (1 + slash_rate)  (22)
```

The `(1 + slash_rate)` term accounts for the fact that Byzantine validators will be slashed when detected.

### 5.2 Attack Scenarios

**Double-spend attack (equivocation):**

| N | f+1 needed | Stake at risk | Slash (50%) | Total cost |
|---|-----------|---------------|-------------|------------|
| 3 | 2 | 20M | 10M | 30M CPUNK |
| 6 | 3 | 30M | 15M | 45M CPUNK |
| 10 | 4 | 40M | 20M | 60M CPUNK |
| 20 | 7 | 70M | 35M | 105M CPUNK |
| 50 | 17 | 170M | 85M | 255M CPUNK |

**Fraudulent mint attack (100% slash + ban):**

| N | f+1 needed | Stake at risk | Slash (100%) | Total cost |
|---|-----------|---------------|--------------|------------|
| 3 | 2 | 20M | 20M | 40M CPUNK |
| 6 | 3 | 30M | 30M | 60M CPUNK |
| 10 | 4 | 40M | 40M | 80M CPUNK |
| 20 | 7 | 70M | 70M | 140M CPUNK |

### 5.3 Security Threshold

For an attack to be rational:

```
attack_profit > attack_cost
attack_profit > ⌈(N+1)/3⌉ × stake × (1 + slash_rate)  (23)
```

With N=10 and 50% slashing, a double-spend must yield more than 60M CPUNK profit to be rational. At 100 operators, the threshold rises to over 750M CPUNK — exceeding the total circulating supply and making the attack economically impossible.

### 5.4 Deterrence Properties

The slashing model provides three layers of deterrence:

1. **Economic deterrence.** The direct cost of slashing exceeds the profit of most attacks.
2. **Reputational deterrence.** Slashed validators lose their position in the network and cannot re-enter (for fraud violations).
3. **Detection certainty.** BFT consensus makes equivocation provably detectable — conflicting signed messages constitute irrefutable evidence.

---

## 6. Proof of Space Economics

### 6.1 Storage Cost Analysis

The cost of operating a nodus validator includes hardware, bandwidth, and electricity. Storage is the primary variable cost:

| Resource | Cost (est.) | Notes |
|----------|-------------|-------|
| Storage (HDD) | ~$15/TB/month | Commercial hosting |
| Storage (SSD) | ~$40/TB/month | Higher performance |
| Storage (home) | ~$3/TB/month | Amortized consumer hardware |
| Bandwidth | ~$5–20/TB | Varies by provider |
| Server (VPS) | ~$20–100/month | Base compute cost |

### 6.2 Reward per TB

Assuming total network storage of S_total TB and equal distribution:

```
reward_per_TB = (annual_emission × storage_share) / S_total  (24)
```

If 50% of emission goes to PoSpace rewards (the other 50% to consensus participation):

| Year | PoSpace Emission | Network Storage | Reward/TB/Year |
|------|-----------------|----------------|---------------|
| 1 | ~41.7M CPUNK | 1 TB | 41,700,000 |
| 1 | ~41.7M CPUNK | 10 TB | 4,170,000 |
| 1 | ~41.7M CPUNK | 100 TB | 417,000 |
| 5 | ~20.8M CPUNK | 100 TB | 208,000 |
| 5 | ~20.8M CPUNK | 1,000 TB | 20,800 |

### 6.3 Profitability Threshold

An operator is profitable when:

```
annual_reward > annual_cost
reward_per_TB × storage_TB > server_cost + storage_cost × storage_TB  (25)
```

Solving for minimum storage:

```
storage_min = server_cost / (reward_per_TB − storage_cost_per_TB)  (26)
```

The exact profitability threshold depends on CPUNK's market price, which converts token rewards to fiat costs. The Proof of Space mechanism is designed to remain profitable at modest token valuations, ensuring operator participation across market conditions.

### 6.4 Comparison: Chia Farming

| Metric | Chia | CPUNK |
|--------|------|-------|
| Data type | Synthetic plots (useless) | Real DHT data (useful) |
| Setup cost | Plot generation (CPU/time intensive) | Nodus installation (minutes) |
| Ongoing cost | Storage + electricity | Storage + bandwidth + server |
| Network value | Plots don't serve users | Storage directly serves messenger/wallet users |
| Entry barrier | Requires dedicated plotting hardware | Standard server + stake requirement |
| Reward basis | Luck-based (space lottery) | Deterministic (challenge-response + uptime) |

---

## 7. Burn Bridge Dynamics

### 7.1 Migration Incentive Model

The decision to burn CF20 and migrate to DNAC is driven by the expected return differential:

```
CF20 return = 0                (no staking, no emission)
DNAC return = APY(t)           (staking + PoSpace rewards)

Migration incentive = APY(t) − 0 = APY(t)           (27)
```

As long as DNAC offers positive staking returns and CF20 offers none, rational holders have an incentive to migrate. The migration velocity depends on:

1. **APY magnitude** — higher APY drives faster migration
2. **Liquidity on CF20** — exchange listing on Cellframe provides a reason to keep some CF20
3. **Risk perception** — early DNAC may be perceived as riskier than established CF20
4. **Friction** — the burn process must be simple (integrated into messenger UI)

### 7.2 Migration Velocity Scenarios

| Scenario | Year 1 Burn | Year 3 Burn | Year 5 Burn | Steady State |
|----------|------------|------------|------------|-------------|
| **Bull** (fast adoption) | 200M | 600M | 900M | ~1B (near-complete migration) |
| **Base** (moderate) | 100M | 400M | 700M | ~950M |
| **Bear** (slow) | 50M | 200M | 400M | ~800M |

### 7.3 Price Pressure Analysis

The burn bridge creates asymmetric price pressure:

**CF20 side:** Each burn permanently removes tokens from CF20 supply. Decreasing supply with constant or increasing demand (from remaining holders) creates upward price pressure on CF20. This is a self-limiting effect — as CF20 price rises relative to DNAC, the incentive to burn decreases.

**DNAC side:** Each burn mint plus emission increases DNAC supply. However, staking locks a significant portion of supply (operators must stake 10M each), reducing effective circulating supply. The net effect on DNAC price depends on the balance between new supply and new demand from utility.

### 7.4 Equilibrium

In the long run, CF20 approaches zero supply as rational holders migrate to capture staking rewards. The equilibrium is:

```
CF20(∞) → ε         (small residual — lost wallets, inactive holders)
DNAC(∞) → S₀ + E_cap ≈ 1,500,000,000
```

The "last mover" problem — where the final CF20 holders have diminishing liquidity — is mitigated by the lack of a migration deadline. CF20 can coexist with DNAC indefinitely, and exchanges can maintain CF20 support as long as there is demand.

---

## 8. Fee Model

### 8.1 Zero-Fee Approach

CPUNK transactions carry zero fees. The rationale:

1. **Operator incentive exists without fees.** Validators are compensated through emission rewards and PoSpace rewards. Fees are not needed to fund network security.
2. **User experience.** Zero fees eliminate dust problems, simplify wallet UX, and make micropayments viable.
3. **Messenger integration.** In-chat payments should feel as frictionless as sending a message.

### 8.2 Spam Protection

Without fees, the network must use alternative spam protection mechanisms:

| Mechanism | Description |
|-----------|-------------|
| Rate limiting | Per-identity transaction rate limits enforced by validators |
| Minimum amount | Transactions below a minimum threshold are rejected |
| Proof of identity | Only authenticated nodus clients can submit transactions |
| Validator discretion | Committee members can reject transactions they deem abusive |

### 8.3 Future Fee Consideration

If the network reaches a scale where spam becomes a material problem and rate limiting is insufficient, a minimal fee can be introduced through governance vote. Any fees collected would be burned (removed from circulation) rather than paid to validators, maintaining the emission-based incentive model and creating deflationary pressure.

---

## 9. Scenario Simulations

### 9.1 Bull Case: Fast Migration, 50+ Operators

**Assumptions:** Rapid CF20 migration, strong community growth, CPUNK gains traction.

| Metric | Year 1 | Year 3 | Year 5 | Year 10 |
|--------|--------|--------|--------|---------|
| CF20 remaining | 800M | 400M | 100M | ~0 |
| DNAC (burned) | 200M | 600M | 900M | 1,000M |
| DNAC (mined) | 83M | 250M | 333M | 438M |
| DNAC total | 283M | 850M | 1,233M | 1,438M |
| Operators | 20 | 50 | 80 | 100 |
| Total staked | 200M | 500M | 800M | 1,000M |
| APY | 41.7% | 6.7% | 5.2% | 1.0% |
| Inflation | 7.7% | 5.3% | 3.1% | 1.4% |

### 9.2 Base Case: Moderate Migration, 20 Operators

**Assumptions:** Steady migration, organic growth, moderate community expansion.

| Metric | Year 1 | Year 3 | Year 5 | Year 10 |
|--------|--------|--------|--------|---------|
| CF20 remaining | 900M | 600M | 300M | 50M |
| DNAC (burned) | 100M | 400M | 700M | 950M |
| DNAC (mined) | 83M | 250M | 333M | 438M |
| DNAC total | 183M | 650M | 1,033M | 1,388M |
| Operators | 10 | 20 | 30 | 50 |
| Total staked | 100M | 200M | 300M | 500M |
| APY | 83.3% | 13.3% | 13.9% | 2.1% |
| Inflation | 7.7% | 5.3% | 3.1% | 1.4% |

### 9.3 Bear Case: Slow Migration, 10 Operators

**Assumptions:** Slow adoption, minimal community growth, cautious migration.

| Metric | Year 1 | Year 3 | Year 5 | Year 10 |
|--------|--------|--------|--------|---------|
| CF20 remaining | 950M | 800M | 600M | 200M |
| DNAC (burned) | 50M | 200M | 400M | 800M |
| DNAC (mined) | 83M | 250M | 333M | 438M |
| DNAC total | 133M | 450M | 733M | 1,238M |
| Operators | 6 | 10 | 15 | 20 |
| Total staked | 60M | 100M | 150M | 200M |
| APY | 138.8% | 25.0% | 27.8% | 5.2% |
| Inflation | 7.7% | 5.3% | 3.1% | 1.4% |

**Key observation:** Inflation rate is independent of migration velocity — it depends only on emission, which follows the same schedule regardless of burn activity. APY is inversely proportional to operator count, creating a self-correcting equilibrium.

---

## 10. Parameter Recommendations

### 10.1 Recommended Values

Based on the analysis above, we recommend the following parameters for mainnet launch:

| Parameter | Recommended Value | Rationale |
|-----------|------------------|-----------|
| Emission model | **Halving** | Simplicity, Bitcoin precedent, integer arithmetic |
| Initial reward R₀ | **158.55 CPUNK/epoch** | Yields ~83.3M annual emission at 60s epochs |
| Halving period H | **~3 years** (1,576,800 epochs) | Balances early incentive with long-term sustainability |
| Total emission cap E_cap | **500,000,000 CPUNK** | 50% of original supply, 2 × R₀ × H |
| Minimum stake | **10,000,000 CPUNK** | Meaningful commitment, ~100 max operators |
| Unstaking period | **14 days** | Sufficient to detect and slash misbehavior |
| Epoch duration | **60 seconds** | Current implementation, sufficient for transaction throughput |
| PoSpace challenge frequency | **Once per epoch** | Regular verification without excessive overhead |
| Transaction fee | **Zero** | Emission-funded network, zero-friction UX |

### 10.2 Sensitivity Analysis

**Varying R₀ (initial reward):**

| R₀ | Annual Year 1 | E_cap (total) | Year to sub-1% inflation |
|----|--------------|--------------|-------------------------|
| 79 CPUNK/epoch | 41.5M | 250M | ~10 years |
| **159 CPUNK/epoch** | **83.3M** | **500M** | **~13 years** |
| 317 CPUNK/epoch | 166.6M | 1,000M | ~16 years |

**Varying H (halving period):**

| H | Halving Interval | E_cap (at R₀=159) | Emission Profile |
|---|-----------------|-------------------|-----------------|
| 1 year | Aggressive | 167M | Very front-loaded |
| **3 years** | **Balanced** | **500M** | **Moderate front-loading** |
| 5 years | Conservative | 834M | Gradual decrease |

**Varying minimum stake:**

| Stake | Max Operators | Attack Cost (N=10) | Decentralization |
|-------|-------------|-------------------|-----------------|
| 1M | ~1,000 | 6M | Very high |
| **10M** | **~100** | **60M** | **High** |
| 50M | ~20 | 300M | Moderate |
| 100M | ~10 | 600M | Low |

The recommended parameters represent a balanced tradeoff between early incentives, long-term sustainability, decentralization, and security.

---

## 11. References

[1] Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System." 2008.

[2] Buterin, V. et al. "EIP-1559: Fee Market Change for ETH 1.0 Chain." Ethereum Improvement Proposals, 2021.

[3] Cohen, B. and Pietrzak, K. "The Chia Network Blockchain." Chia Network, 2019.

[4] Protocol Labs. "Filecoin: A Decentralized Storage Network." 2017.

[5] Subspace Labs. "The Subspace Protocol: A Scalable, Incentive-Compatible, and Decentralized Blockchain Based on Proof-of-Archival-Storage." 2021.

[6] Protocol Labs. "Filecoin Economy." Filecoin Research, 2020.

[7] Castro, M. and Liskov, B. "Practical Byzantine Fault Tolerance." *Proceedings of the Third Symposium on Operating Systems Design and Implementation (OSDI)*, pp. 173–186, 1999.
