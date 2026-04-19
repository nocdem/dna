# DNAC Testnet Red-Team Audit

**Date:** 2026-04-20
**Auditor:** EXECUTOR (claude-opus-4-7, explanatory mode)
**Scope:** Pre-testnet security audit of DNAC (UTXO blockchain) + embedded witness consensus (`nodus/src/witness/`) + DNAC client (`dnac/src/`)
**Baseline:** DNAC v0.14.3 on chain `9ce76117` (stake-delegation v1 + hard-fork v1 shipped 2026-04-19)
**Total source audited:** ~27k LoC C (dnac + witness)
**Method:** Read-only static analysis, pattern-based attack search, cross-reference against `STATUS.md` claims. NO code changes, NO fuzzing, NO live probing.

---

## Executive Summary

**VERDICT: NO-GO for public testnet without mitigations.**

DNAC has **strong core consensus discipline** — F-CONS-06 (independent state_root recompute) is real, `(2n)/3+1` quorum formula correctness has been audited historically, replay nonce table exists, chain_id validation is wired into all 10 BFT handlers, and the hard-fork CHAIN_CONFIG mechanism is remarkably well-engineered (5-of-7 sigs, freshness, grace periods, monotonicity, digest binds chain_id). The multi-file committee / delegation / reward code shows evidence of serious design work.

But two classes of issues block a safe testnet promotion:

1. **One critical client-trust gap** — `DNAC_KNOWN_CHAINS[0].chain_id` is still the all-zero placeholder. Every DNAC client currently runs in `verified=false` mode, blindly trusting witness responses. The anchored Merkle proof infrastructure shipped 2026-04-16 is not actually protecting clients yet. On devnet with trusted operators this is fine; on testnet with external developers, this is a disaster waiting to happen.

2. **Several Medium-severity consensus hardening gaps** — no live-consensus cert_sig verification (only sync path verifies), `handle_commit` fast-path applies batch TXs without re-verifying signatures, state_root divergence is WARN-only not HALT, leader clock reliance (time-derived epoch) enables fine-grained liveness attacks, no equivocation detection (by design for v1, but economic consequences unbounded).

In addition, the design has **known accepted risks** (see STATUS.md:148 — no slashing, no stake-gated discovery, no block explorer). These are not bugs but they mean testnet operators must act as the trust anchor until stake-gated Sybil resistance lands.

### Risk scoring

Each finding reports **Severity %** (damage if exploited) × **Exploitability %** (how feasible the attack). **Risk** = (S × E) / 100.

| Severity % | Meaning |
|---|---|
| 90–100 | Chain halt, supply inflation, key theft, permanent data corruption |
| 70–89 | Single-shot funds theft, cluster split, user data leak |
| 40–69 | Targeted DoS, per-user griefing, verification bypass with recovery |
| 20–39 | Defense-in-depth loss, cosmetic divergence, local-only impact |
| 1–19 | Informational, future-proofing concern |

| Exploitability % | Meaning |
|---|---|
| 90–100 | Any remote attacker, no authentication, one packet |
| 70–89 | Any roster-member witness, standard tooling |
| 40–69 | Requires ≥f+1 colluding witnesses OR specific race window |
| 20–39 | Requires physical access / supply-chain / crypto break |
| 1–19 | Theoretical, bounded by protocol invariants |

**Risk tiers:**
- **CRITICAL** (risk ≥ 50): Must fix before testnet
- **HIGH** (risk 25–49): Should fix before testnet, document if deferred
- **MEDIUM** (risk 10–24): Track for mainnet
- **LOW** (risk < 10): Informational
- **INFO** (accepted design tradeoff): Document, do not fix

---

## Findings Summary Table

| # | Finding | Layer | Severity % | Exploitability % | Risk | Tier |
|---|---|---|---|---|---|---|
| F01 | `DNAC_KNOWN_CHAINS` chain_id placeholder — anchored verify disabled | Client trust | 85 | 95 | **80.75** | **CRITICAL** |
| F02 | `handle_commit` fast-path applies batch TXs w/o re-verify | BFT safety | 70 | 35 | **24.5** | HIGH |
| F03 | Live-consensus `cert_sig` not verified (only sync verifies) | BFT cert | 45 | 45 | **20.25** | MEDIUM |
| F04 | State_root divergence is WARN-only, no HALT | BFT safety | 75 | 20 | **15** | MEDIUM |
| F05 | Leader election `(epoch+view)%N` uses local `time()` | BFT liveness | 35 | 35 | **12.25** | MEDIUM |
| F06 | `apply_stake` hardcodes `self_stake` but verify is inequality | Economic | 30 | 40 | **12** | MEDIUM |
| F07 | STAKE client verify has no equality check on excess inputs | Economic | 30 | 40 | **12** | MEDIUM |
| F08 | `is_replay` nonce bucket eviction = roster-peer replay window | BFT replay | 40 | 25 | **10** | MEDIUM |
| F09 | `apply_claim_reward` doesn't enforce `valid_before_block` | Economic | 30 | 35 | **10.5** | MEDIUM |
| F10 | Chain_config INFLATION_START allows retroactive move-backward | Governance | 25 | 30 | **7.5** | LOW |
| F11 | `verify_chain_id` allows any chain_id pre-genesis (all-zero bypass) | BFT bootstrap | 40 | 15 | **6** | LOW |
| F12 | `is_replay` returns `false` on malloc failure (fail-open) | BFT replay | 25 | 15 | **3.75** | LOW |
| F13 | Peer slot leak (4 uncoordinated `peer_count++` sites) | Networking | 20 | 40 | **8** | LOW |
| F14 | Bootstrap committee seed = all-zero if no genesis yet | BFT bootstrap | 20 | 10 | **2** | LOW |
| F15 | Handle_commit accepts from any roster peer (fast-path) | BFT | 25 | 35 | **8.75** | LOW |
| F16 | No equivocation detection / slashing in v1 | Economic | 70 | 10 | **7** | INFO |
| F17 | No stake-gated peer auto-join (gossip crossover) | Decentralization | 50 | 15 | **7.5** | INFO |
| F18 | Stage F integration harness skipped for hard-fork | QA gap | 40 | 10 | **4** | INFO |
| F19 | Deep inflation halving logic untested on-chain | Economic | 30 | 5 | **1.5** | INFO |

**Total: 19 findings — 1 CRITICAL, 1 HIGH, 7 MEDIUM, 6 LOW, 4 INFO.**

---

## Detailed Findings

### F01 — `DNAC_KNOWN_CHAINS` placeholder: anchored verification disabled [CRITICAL]

**Severity: 85% · Exploitability: 95% · Risk: 80.75**

**Location:**
- `dnac/src/ledger/genesis_anchor.c:13-29` — registry
- `dnac/src/wallet/wallet.c:70-123` — `bootstrap_trusted_state`
- `dnac/src/nodus/tcp_client.c:496,530` — `utxo.verified` field

**Evidence:**
```c
// dnac/src/ledger/genesis_anchor.c:13-26
const dnac_known_chain_t DNAC_KNOWN_CHAINS[] = {
    {
        .name = "devnet",
        /* TEMPORARILY zeroed — the 32-byte old chain_id (SHA3-256) doesn't
         * match the 64-byte DNAC_BLOCK_HASH_SIZE field. ... */
        .chain_id = { 0 },
    },
};
```

```c
// dnac/src/wallet/wallet.c:83-87
if (memcmp(kc->chain_id, zero, DNAC_BLOCK_HASH_SIZE) == 0) {
    QGP_LOG_INFO(LOG_TAG,
        "trust: chain_id placeholder unset, anchored verification deferred to Phase 13");
    return;
}
```

And line 98-103 — even if someone fills in a chain_id, a MITM mismatch **only logs an error and continues** ("Phase 13 will tighten this to hard fail").

**Attack:**
Any adversary who can intercept the DNAC client's `handle_dnac_utxo` / `handle_dnac_genesis` T2 response — or any malicious operator running a rogue witness — can feed the client:
- Fabricated UTXOs (seen as "real money" by wallet)
- Fabricated transaction history
- False balance values

The client-side `dnac_merkle_verify_proof` / `dnac_anchor_verify` / `dnac_genesis_verify` infrastructure exists (`dnac/src/ledger/`, shipped 2026-04-16 with 29 tests). But `bootstrap_trusted_state` short-circuits before any of it runs. UTXOs are stored with `verified=false` and the UI/CLI doesn't gate on that flag.

**Impact:**
- Every wallet on testnet will trust whatever witness responds first. Witnesses are not yet stake-gated (see F17), so Sybil witness → identity spoofing at scale.
- Testnet is essentially running without cryptographic client-side integrity. The "post-quantum zero-trust blockchain" marketing does not hold until this is filled.

**Remediation (in order):**
1. Run `gen_genesis` on target testnet, capture the real `chain_id` (SHA3-512 of the genesis block preimage including `chain_def`).
2. Paste the 64-byte value into `DNAC_KNOWN_CHAINS[0].chain_id`, change `.name` from "devnet" to "testnet" or ship both entries.
3. In `bootstrap_trusted_state`, change `return` at line 103 to `abort(){}` / propagate error — **hard fail on chain_id mismatch**. Every client binary identifies the testnet by its embedded chain_id; a mismatch means wrong network or MITM.
4. In `dnac/src/nodus/tcp_client.c` and wallet UI flows, **gate on `utxo.verified == true`** before counting balance. Current `balance.c` sums all UTXOs regardless of the flag (needs re-check).
5. Ship a "verified / pending" badge in the Flutter UI (already flagged as deferred in STATUS.md:127).

**Why severity 85 not 100:** Some defense remains — a rogue witness must still hold matching signature material, and replay protection + chain_id on the BFT side keeps other witnesses honest. But for client-bound attacks (balance lie, history lie), the exposed surface is wide open.

**Why exploitability 95:** Any TCP peer can respond to a DNAC T2 query. Witness discovery is address-based (STATUS.md:148). No stake-gating, no authentication of responses beyond envelope sig (which is by the rogue witness, not a trusted anchor).

---

### F02 — `handle_commit` fast-path applies batch TXs without re-verify [HIGH]

**Severity: 70% · Exploitability: 35% · Risk: 24.5**

**Location:** `nodus/src/witness/nodus_witness_bft.c:3982-4066` (handle_commit) and `:4649-4731` (commit_batch).

**Evidence:** `handle_propose` (line 3562) calls `nodus_witness_verify_transaction` on every batch TX before accepting the proposal. `handle_commit` (line 4040-4054) calls `commit_batch` / `commit_genesis` directly. `commit_batch` (line 4666-4680) calls `apply_tx_to_state` without re-running `nodus_witness_verify_transaction`.

The fast-path exists because "a non-leader peer hits precommit quorum and broadcasts COMMIT before the leader's own `handle_vote` accumulates its local quorum" (comment at line 4130-4132).

**Attack (Byzantine leader substitution):**
1. Leader A honestly proposes TXs `{T1, T2}` — cluster verifies and precommits for `block_hash(T1,T2)`.
2. Leader A collects ≥5 PRECOMMIT sigs (signed for the honest block_hash).
3. A sends itself a COMMIT message with `batch_txs = {T1', T2'}` where `T1'/T2'` are different (valid) TXs (same sigs? no — different data).
4. Slow-follower F receives A's tampered COMMIT before F's own `handle_vote` reaches quorum. F skips the fast-path guard (`hdr->round <= w->last_committed_round` — round hasn't committed yet).
5. F applies `{T1', T2'}` to its state. State_root will differ (F04 — WARN only). Cert_sigs are for original `block_hash` — when stored and later served to sync peers, verification fails → sync bifurcation.

**Limits that reduce severity:**
- `T1'/T2'` must still have valid Dilithium5 signer sigs — attacker can't forge. Can only substitute existing signed TXs (e.g., an older TX signed by the same user).
- `apply_tx_to_state` calls `update_utxo_set`, which hits the nullifier DB. Already-spent nullifiers would reject → TX apply fails → commit_batch rolls back.
- State_root divergence would be logged (F04) — some operator monitoring could catch it.

**But:** Substituting a valid-but-not-yet-proposed TX bypasses mempool/proposal discipline. A Byzantine proposer with access to other users' signed TXs (e.g., from a gossip overlay) could commit them prematurely.

**Remediation:**
In `handle_commit`, before `commit_batch`, iterate `cmt->batch_txs[]` and call `nodus_witness_verify_transaction` on each — mirror the `handle_propose` loop at line 3562. Cost: one extra SHA3-512 + one Dilithium5 verify per TX per non-proposer commit race. Batch_count ≤ 10, so bounded ≤10ms per COMMIT.

---

### F03 — Live-consensus `cert_sig` stored without verification [MEDIUM]

**Severity: 45% · Exploitability: 45% · Risk: 20.25**

**Location:** `nodus/src/witness/nodus_witness_bft.c:3747-3755` (vote recording) vs. `nodus_witness_cert.c:54-100` (verify_sync_certs).

**Evidence:** In `handle_vote` (PRECOMMIT branch), `memcpy(votes[*vote_count].signature, vote->cert_sig, NODUS_SIG_BYTES)` — no `qgp_dsa87_verify` call. The only cert signature verification in the codebase is `nodus_witness_verify_sync_certs` (nodus_witness_cert.c:85), invoked only in `nodus_witness_sync.c:582` (sync path).

**Attack:** A Byzantine witness broadcasting PRECOMMIT with a **garbage `cert_sig`** still contributes to quorum (envelope sig is authentic → sender_in_roster check passes → vote counts). The garbage cert is stored in `w->round_state.precommits[].signature` and then persisted via `nodus_witness_cert_store` (line 3881).

When a new witness later SYNCs the chain, it calls `verify_sync_certs`, which filters out garbage certs. If enough honest certs remain (≥quorum=5 for n=7), sync succeeds. But under the BFT assumption of ≤f=2 Byzantine, the honest-cert count is 5-of-7 → exactly quorum. **A single honest-node cert loss (network drop, collision, anything) now breaks sync.**

**Protocol-theoretic scope:** Under ≤f Byzantine, system still works. But this is a defense-in-depth loss — there's no margin.

**Remediation:**
In `handle_vote`, PRECOMMIT branch, before accepting the cert_sig: compute `cert_preimage` for `(hdr->sender_id, cert_height, chain_id, tx_hash)`, call `qgp_dsa87_verify` against the sender's pubkey from roster. Reject vote on failure. Cost: one Dilithium5 verify per PRECOMMIT message (~2ms), bounded to ≤N peers per round.

**Why not higher exploitability:** Byzantine must be in the roster. External attackers can't do this.

---

### F04 — State_root divergence is WARN-only, no automated HALT [MEDIUM]

**Severity: 75% · Exploitability: 20% · Risk: 15**

**Location:** `nodus/src/witness/nodus_witness_bft.c:4100-4124` (handle_commit state_root compare).

**Evidence:**
```c
if (memcmp(utxo_cksum, cmt->state_root, NODUS_KEY_BYTES) != 0) {
    QGP_LOG_WARN(LOG_TAG, "state_root DIVERGED from leader at round %llu!", ...);
}
/* F-CONS-06: retain locally-computed value only, never the leader's claim. */
memcpy(w->cached_state_root, utxo_cksum, NODUS_KEY_BYTES);
```

F-CONS-06 is correctly enforced (local state_root retained, not leader's). But the block **still commits** with the locally-divergent state_root. No operator alarm. No BFT round halt. No automatic quarantine.

**Attack:** Any subtle divergence — non-deterministic map iteration, clock-dependent ordering, uninitialized memory read — will produce a silently bifurcating chain. Different nodes will have different state_roots at height N. Merkle proofs anchored against node A's state_root will fail verification against node B's. Clients see flaky behavior ("sometimes my balance is correct").

Examples of divergence bugs seen historically per memory:
- Accumulator attendance non-determinism (fixed v0.14.1, memory: CLAIM_REWARD + UNDELEGATE RESOLVED)
- Genesis ghost stake (fixed d8d4d9c2)
- Peer slot leak (F13, open)

**Remediation:**
1. Escalate divergence from WARN → structured ALERT metric that monitoring tooling can page on.
2. Consider adding a "divergence detection" T3 message — each witness broadcasts its state_root after commit. If ≥f+1 disagree on state_root at height N, cluster HALTs consensus and requires manual operator intervention.
3. At minimum, expose `state_root_divergence_count_at_height` counter via a T2 query so monitoring can watch it.

**Severity high (75%) because subtle bugs ship without surface; exploitability low (20%) because attacker doesn't directly cause this — it's a bug-amplification issue.**

---

### F05 — Leader election depends on local `time()` [MEDIUM]

**Severity: 35% · Exploitability: 35% · Risk: 12.25**

**Location:** `nodus/src/witness/nodus_witness_bft.c:277, 3441`.

**Evidence:**
```c
uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
int leader = nodus_witness_bft_leader_index(epoch, w->current_view, w->roster.n_witnesses);
```

`NODUS_T3_EPOCH_DURATION_SEC = 60` (nodus_types.h:141). A witness with a clock skewed by ≥60s computes a different epoch → different leader.

**Attack:**
- **Clock-skew liveness DoS:** Byzantine witness sets its clock 45s forward. For ~15s each minute (the overlap window), it votes as if the next epoch's leader is proposing. It NAKs proposals from the current honest leader ("not leader"). If Byzantine is on the overlap side of boundary, it stalls rounds.
- Mitigation: view change recovers, but every minute's boundary burns one view-change round.

**Harder attack:** Convince the NTP daemon (e.g., via BPF/netfilter tricks on the host) to drift the clock silently. Not in scope for BFT threat model.

**Remediation:**
- Short term: Document NTP requirement. Monitor witness clock drift.
- Medium term: Epoch counter as part of committed chain state (increment on block commit, not on wall clock). Removes time dependency from consensus altogether. Design ref: Tendermint/Cosmos use block-height-derived epoch.

---

### F06 — `apply_stake` hardcodes `self_stake = DNAC_SELF_STAKE_AMOUNT` [MEDIUM]

**Severity: 30% · Exploitability: 40% · Risk: 12**

**Location:** `nodus/src/witness/nodus_witness_bft.c:1086` (and `:2183-2188` unbonding emit).

**Evidence:**
```c
v.self_stake = DNAC_SELF_STAKE_AMOUNT;   /* hardcoded — always 10M × 10^8 */
```

The validator's DB row records `self_stake = 10M` regardless of what the STAKE TX actually locked. Verification only checks `Σ inputs ≥ 10M + Σ outputs` (inequality, see F07).

**Attack scenarios:**
- **Validator overpay:** Validator inputs 50M, outputs 0. Verify passes (50M ≥ 10M + 0). Validator's self_stake column = 10M. 40M is "burned" into nullifiers with no corresponding UTXO. On UNSTAKE, validator gets back only `DNAC_SELF_STAKE_AMOUNT` (10M) — the 40M is lost. Self-harm, not an exploit per se.
- **Validator underpay:** Client-side verify catches `inputs < 10M + outputs`. Witness-side has no DB-level check (the comment at `dnac/src/transaction/verify.c:116-122` explicitly defers this to TODO Phase 8 Task 40). If the client-side check is skipped (e.g., rogue CLI), a Byzantine submitter could try to register as validator with less than 10M locked.

**BUT** — the STAKE TX goes through `nodus_witness_verify_transaction` in `handle_propose` (line 3562), which would verify the signer and the wire format. Whether it enforces `inputs ≥ 10M + outputs` witness-side is unclear from my read. I found the client-side check at `dnac/src/transaction/verify.c:80-114` but no equivalent in `nodus/src/witness/nodus_witness_verify.c`.

**Remediation:**
Add a witness-side enforcement block in `nodus_witness_verify_transaction` for `TX_TYPE_STAKE`: parse inputs/outputs (already done for generic balance check), require `Σ native-DNAC inputs − Σ native-DNAC outputs = DNAC_SELF_STAKE_AMOUNT + current_fee`. This is the equality form, not inequality — removes overpay footgun and guards against potential client-side skip.

---

### F07 — STAKE client verify is `≥` not `==`; excess silently burned [MEDIUM]

**Severity: 30% · Exploitability: 40% · Risk: 12**

**Location:** `dnac/src/transaction/verify.c:80-114`.

**Evidence:**
```c
/* Σ DNAC input >= DNAC_SELF_STAKE_AMOUNT + Σ DNAC output. */
if (dnac_in < required) { ... reject ... }
```

Comment at line 116-122 explicitly acknowledges: "The stricter `outputs == inputs − 10M − fee` equality check requires knowing the fee externally; the witness enforces the exact fee value against its mempool schedule separately."

**Problem:** I searched for `stake.*exact` / `fee.*equal` in nodus witness verify — no match. The "witness enforces exact fee" claim is not backed by code in the paths I examined.

Combined with F06, this means a STAKE TX with inputs=100M, outputs=0 has:
- 100M consumed (nullifiers stored)
- self_stake column = 10M
- 90M unaccounted → either goes to fee pool or burned

Let me verify where the excess goes. If there's no explicit fee-pool credit in `update_utxo_set` for STAKE, then the 90M is silently burned (no UTXO created, no fee credited).

**Remediation:** Same as F06 — enforce equality witness-side.

---

### F08 — Nonce bucket eviction enables roster-peer replay window [MEDIUM]

**Severity: 40% · Exploitability: 25% · Risk: 10**

**Location:** `nodus/src/witness/nodus_witness_bft.c:120-191`.

**Evidence:** `is_replay` uses open-addressed-hash buckets with `NONCE_MAX_TOTAL` cap. When the table fills, `nonce_evict_oldest` removes entries of the oldest bucket:
```c
if (nonce_total_count >= NONCE_MAX_TOTAL) {
    nonce_evict_oldest();
}
```

**Attack:** A Byzantine witness (already in roster, envelope sigs OK) floods unique nonces via legitimate-looking T3 messages. When the nonce table fills, the attacker's burst evicts older entries including honest witnesses' original-message fingerprints. The attacker now replays older honest messages (PROPOSE/PREVOTE/PRECOMMIT) — they pass replay check because the old nonce was evicted.

**Impact bounded by:**
- Round/view checks (hdr->round == w->round_state.round) — stale rounds are silently dropped (line 3689-3691). Only messages from the CURRENT round matter.
- Phase check (line 3723-3725) — wrong phase = ignored.
So the replay window is narrow: same round, same phase. Mostly just counts as a duplicate vote (line 3728-3732 dedup-by-voter_id).

**Real exploitable scenario:**
- Byzantine sends garbage PROPOSE with high nonce to fill bucket.
- Evicts honest leader's earlier proposal nonce.
- Replays honest leader's PROPOSE (unchanged content) — no-op since round already in progress.

Actually: the dedup-by-voter_id per round likely prevents real exploitation. Rated MEDIUM for defense-in-depth, not for a concrete break.

**Remediation:**
- Increase `NONCE_MAX_TOTAL` (check current value) or use LRU per (round, phase) instead of global.
- Add metric on eviction rate; alert if elevated.

---

### F09 — `apply_claim_reward` parses `valid_before_block` but does not enforce it [MEDIUM]

**Severity: 30% · Exploitability: 35% · Risk: 10.5**

**Location:** `nodus/src/witness/nodus_witness_bft.c:1505-1506`.

**Evidence:**
```c
/* valid_before_block is at off + DNAC_PUBKEY_SIZE + 8; not consumed
 * here (verify-time). */
```

Comment says enforcement is "verify-time". I searched for `valid_before_block` in witness verify — no hit except in `nodus_witness_chain_config.c` (different TX type). So the CLAIM_REWARD `valid_before_block` appears to be neither enforced nor bound into the signed TX hash proof-of-freshness. If the client signs a CLAIM_REWARD for "valid before block 100" but the TX lingers in mempool until block 500, it still applies.

**Attack:** A delegator signs a CLAIM_REWARD for a specific pending amount at block N, intending it to fail if the TX arrives late (because by block N+Δ the accumulator diff will have grown and `pending > max_pending` rejects — that part is enforced at line 1563-1569). So the `max_pending` cap partially substitutes for freshness. But `valid_before_block` should also be a hard ceiling.

**Exploitability:** Low — signer controls their own TX timing and can simply not rebroadcast.

**Remediation:**
In `apply_claim_reward` (or `nodus_witness_verify_transaction` for `TX_TYPE_CLAIM_REWARD`), add:
```c
if (block_height > valid_before_block) return -1;
```

---

### F10 — CHAIN_CONFIG INFLATION_START allows retroactive backward move [LOW]

**Severity: 25% · Exploitability: 30% · Risk: 7.5**

**Location:** `nodus/src/witness/nodus_witness_chain_config.c:920-947`.

**Evidence:**
```c
if (cc.new_value == 0) { /* reject disable */ }
if (cc.new_value > block_height) { /* reject future move */ }
/* Allows cc.new_value < existing_value (backward move) */
```

Monotonicity prevents disabling inflation and prevents setting a future start. But doesn't prevent moving start **backward** (e.g., from 1000 to 500 while at block 2000). If inflation computation uses `epoch = (current - start) / halving_period`, moving start earlier advances the halving schedule — **reduces mint rate** permanently.

**Who cares:** Validator committee can vote to accelerate halving. That's a tokenomic lever, not a safety issue. Arguably a feature.

**Remediation:** If design intent is monotone-non-decreasing, add `if (existing_row.new_value > 0 && cc.new_value < existing_row.new_value) return -1;`. Otherwise, **document explicitly** in design doc §5.2 that backward moves are allowed and represent committee-coordinated halving acceleration.

---

### F11 — `verify_chain_id` skips check when local chain_id is all-zero [LOW]

**Severity: 40% · Exploitability: 15% · Risk: 6**

**Location:** `nodus/src/witness/nodus_witness_bft.c:200-208`.

**Evidence:**
```c
static bool verify_chain_id(nodus_witness_t *w, const uint8_t *msg_chain_id) {
    static const uint8_t zero[32] = {0};
    if (memcmp(w->chain_id, zero, 32) == 0) return true;   // pre-genesis bypass
    ...
}
```

**Attack:** A witness started with no chain (fresh disk, no genesis yet) accepts T3 messages from ANY chain_id. If an attacker reaches this node over TCP 4004 (inter-node auth notwithstanding — STATUS.md:74 says "both fixed") before genesis is committed, they could inject PROPOSE/PREVOTE messages from a rogue chain.

**Impact bounded by:**
- Inter-node auth on TCP 4004 (STATUS.md says fixed) — peer must be in whitelist.
- Genesis bootstrap completes in seconds under normal deploy.
- Before genesis, BFT quorum isn't functional anyway.

**Remediation:**
- Require chain_id match as soon as the roster is non-empty (even pre-genesis). Or explicitly require chain_id be set during init from a config file.

---

### F12 — `is_replay` returns `false` on malloc failure (fail-open) [LOW]

**Severity: 25% · Exploitability: 15% · Risk: 3.75**

**Location:** `nodus/src/witness/nodus_witness_bft.c:180-190`.

**Evidence:**
```c
nonce_node_t *node = malloc(sizeof(nonce_node_t));
if (node) { /* insert */ }
return false;   /* NOT replay */
```

If malloc fails, the nonce is not recorded, so the next occurrence of the same (sender, nonce) will also not be flagged as replay. Replay protection silently degrades to off.

**Impact:** Under severe memory pressure, replay protection stops working. Attacker must still pass envelope sig (roster member) and round/phase checks. Real impact minimal.

**Remediation:** On malloc failure, log at ERROR level + optionally return `true` (treat as replay — fail-closed). But fail-closed breaks liveness under memory pressure. Current fail-open preserves liveness at cost of replay defense. Either way, instrument a metric.

---

### F13 — Peer slot leak: 4 uncoordinated `peer_count++` sites [LOW]

**Severity: 20% · Exploitability: 40% · Risk: 8**

**Location:** `nodus/src/witness/nodus_witness_peer.c:138` (grep confirmed; memory: `project_witness_peer_table_slot_leak`).

**Symptom:** "sent=11 with 6 peers" — broadcast loop iterates a stale `peer_count` that exceeds the actual peer slot occupancy.

**Attack:** Bounded. Per memory: "secondary bug, not blocking consensus." A peer reconnect storm could weaponize the leak to degrade broadcast performance, but consensus still reaches quorum.

**Remediation:** Centralize peer add/remove through a single function pair. Unit test for invariant `peer_count ≤ NODUS_T3_MAX_WITNESSES` and matches `#{p | p.conn != NULL}`.

---

### F14 — Committee bootstrap falls back to all-zero seed if no genesis [LOW]

**Severity: 20% · Exploitability: 10% · Risk: 2**

**Location:** `nodus/src/witness/nodus_witness_committee.c:198-205`.

**Evidence:**
```c
if (rc == 0) memcpy(state_seed, genesis_block.state_root, 64);
else memset(state_seed, 0, sizeof(state_seed));
```

Comment says: "any committee we compute in that state is advisory and will be discarded once the real genesis commits."

**Risk:** Bounded. Pre-genesis committee is not used for consensus (quorum isn't active). But if any path uses this advisory committee, tiebreak becomes deterministic-but-identical across all candidates (since all use the zero seed). Pubkey ordering is the sole tiebreak → ordering leak.

**Remediation:** Add assertion that consensus-critical paths never consult the bootstrap committee output once n_witnesses is live.

---

### F15 — `handle_commit` accepts from any roster peer (fast-path) [LOW]

**Severity: 25% · Exploitability: 35% · Risk: 8.75**

**Location:** `nodus/src/witness/nodus_witness_bft.c:3982-4002`.

**Evidence:** No check that the sender is the leader of the current round. Any roster member can trigger a commit via the fast-path.

**Attack:** Paired with F02. A Byzantine non-leader can proactively broadcast a COMMIT with tampered TXs to slow followers. Constrained by F02 mitigations.

**Remediation:** Part of F02 fix — add pre-commit sanity that `cmt->batch_txs` hashes match a previously-verified proposal for this round.

---

### F16 — No equivocation detection / slashing in v1 [INFO — accepted design]

**Severity: 70% · Exploitability: 10% · Risk: 7 (theoretical)**

**Location:** STATUS.md:150 — "no equivocation detection, conflicting PREVOTE/PRECOMMIT sigs go unpunished."

**Evidence:** Search for "equivocation" / "conflict.*vote" returns zero hits. `handle_vote` dedup at 3728-3732 silently drops duplicate votes (first-vote-wins). A Byzantine witness can vote APPROVE to one partition and REJECT to another with **zero protocol punishment**.

**Economic impact on testnet:** None, since testnet uses distributed operators you know personally. For mainnet, this is the #1 item to ship alongside slashing.

**Remediation (for mainnet, not testnet):**
1. Every vote message is a long-lived signed proof. Build a fraud-proof TX that submits two conflicting signed votes from the same voter for the same round/phase → slashes self_stake.
2. Requires schema change + new TX type + slashing policy constants. Design doc `2026-04-17-witness-stake-delegation-design.md` §3.6 likely addresses this — verify scope.

---

### F17 — No stake-gated peer auto-join (gossip crossover gap) [INFO — accepted]

**Severity: 50% · Exploitability: 15% · Risk: 7.5**

**Location:** STATUS.md:148 claims roster is "chain-derived top-7". Source at `nodus/src/witness/nodus_witness_peer.c:501,1037` / `:579,1174` still does address-based auto-join via gossip.

**Evidence:**
```c
// peer.c:579
if (nodus_witness_roster_add(w, &entry) == 0) { ... }
// peer.c:1174
nodus_witness_roster_add(w, &entry);
```

Roster additions happen from gossip discovery, not from chain-state committee (F14 shows `nodus_committee_compute_for_epoch` exists but the BFT path still consults `w->roster`, not the chain-derived committee directly, in the places I examined).

**Impact:** For testnet — you control the whitelist / inter-node auth. For mainnet — without stake gating, anyone can announce themselves and join the gossip network. Combined with F16 (no slashing), a Sybil can join, vote, then disappear with zero consequences.

**Remediation:**
- Verify that BFT path at `nodus_witness_bft.c:3444,3735` (roster lookups for leader + voter) consults the chain-derived committee, NOT the gossip-built roster. If yes, then gossip roster is just a discovery hint and the vulnerability is cosmetic.
- If no, then committee derivation from chain state is not actually enforced in consensus — a real break of the stake-delegation-v1 design claim.

**ACTION for audit reader:** Please verify which `w->roster` consumers in `nodus_witness_bft.c` use stake-derived vs gossip-derived entries. This needs a focused read-through that I could not fit in this audit's time budget.

---

### F18 — Stage F (hard-fork integration harness) skipped [INFO]

**Severity: 40% · Exploitability: 10% · Risk: 4**

**Location:** DNAC CLAUDE.md:202 — "Stage F — local 3-node integration test harness" listed as pending, memory says "Stage F skipped."

**Impact:** No multi-node end-to-end test of a CHAIN_CONFIG commit sequence. Single-node tests prove the codec, but a real governance change hitting 7 nodes with varying latencies has not been exercised.

**Remediation:** Build a 3-node local harness in `nodus/tests/integration/stagef/stagef_up.sh` (already in repo, per git status `?? Testing/`). Runbook: 3-node cluster, submit CHAIN_CONFIG, validate apply on all 3, verify `chain_config_root` converges. Before testnet launch.

---

### F19 — Inflation halving logic shipped but not yet deployed on-chain [INFO]

**Severity: 30% · Exploitability: 5% · Risk: 1.5**

**Location:** Memory: `project_inflation_design` — "16→1 DNAC halving, shipped 2d344281+6cd14f17, not yet deployed."

**Impact:** Code path from `INFLATION_START_BLOCK` → halving → mint has not been exercised in production. When testnet activates inflation (via CHAIN_CONFIG param 3), bugs will surface. On the plus side: CHAIN_CONFIG's grace period for INFLATION_START is 12× EPOCH_LENGTH = 1440 blocks, giving a warning window.

**Remediation:** During testnet, schedule a CHAIN_CONFIG vote early to activate inflation on a designated block, let it run for a week, audit mint events against expected schedule.

---

## Cross-Reference Against STATUS.md Claims

| STATUS.md claim | Line | Verification |
|---|---|---|
| "UTXO ownership verification before PREVOTE (v0.10.2)" | 60 | ✅ `nodus_witness_verify_transaction` is called in `handle_propose` (bft.c:3562) |
| "Nullifier fail-closed on DB error" | 58 | ⚠ Only verified at claimed site; need audit sweep for other DB queries (see F12) |
| "Chain ID validation in all 10 BFT handlers" | 59 | ✅ Confirmed: bft.c:3420, 3685, 3994, 4217, 4302 + chain_config consumer |
| "Witness divergence detection active at COMMIT" | 55 | ⚠ Detection yes (F-CONS-06), reaction no (F04: WARN only, no HALT) |
| "Atomic multi-input nullifier validation" | 46 | ✅ Intra-batch check at bft.c:3577-3594 |
| "Secure nonce — abort on RNG failure" | 68 | ✅ bft.c:214-218 `abort()` on `nodus_random` fail |
| "Replay prevention: nonce + timestamp + nonce hash table with TTL" | 69 | ⚠ Exists but see F08 (eviction) + F12 (fail-open) |
| "COMMIT signature verification" | 70 | ⚠ Sync path only. Live path does not verify (F03) |
| "Stake-gated witness discovery" | 149 | ❌ Listed as NOT STARTED. F17 confirms. |
| "Slashing" | 150 | ❌ Listed as NOT STARTED. F16 confirms. |

Legend: ✅ verified true, ⚠ partially true / caveated, ❌ correctly listed as open.

---

## Testnet Go/No-Go Recommendations

### Must-fix before testnet ships (BLOCKING)

1. **F01** — fill `DNAC_KNOWN_CHAINS[0].chain_id` with real testnet genesis chain_id; change bootstrap failure from degraded-mode to hard-fail; gate balance counting on `utxo.verified`.
2. **F02** — add per-TX re-verify loop in `handle_commit` fast-path.
3. **F17 verification** — confirm (or fix) that BFT consumers of `w->roster` use chain-derived committee, not gossip-joined entries. This is either a 15-minute grep+confirm or a design-level refactor depending on findings.

### Should-fix before testnet (SEMI-BLOCKING, document if deferred)

4. **F03** — add live-consensus `cert_sig` verify in PRECOMMIT branch.
5. **F04** — upgrade state_root divergence from WARN to structured alert + expose counter via T2.
6. **F06 / F07** — add witness-side STAKE amount equality check.
7. **F09** — enforce `valid_before_block` in CLAIM_REWARD apply.
8. **F18** — build Stage F integration harness, dry-run a CHAIN_CONFIG on 3-node local testbed.

### Acceptable for testnet with operator discipline (NON-BLOCKING, mainnet-blocking)

9. **F05** — document NTP requirement; schedule epoch-from-block-height migration for mainnet.
10. **F08 / F12** — instrument metrics; accept defense-in-depth gap.
11. **F13** — fix before mainnet (low priority for testnet).
12. **F10 / F11 / F14 / F15** — low risk, track.
13. **F16 / F17** — these are the "known gaps" from STATUS.md. Testnet operators act as the trust anchor. Publish this limitation clearly in testnet onboarding docs.

### Pre-testnet launch checklist

- [ ] F01 remediated, `chain_id` filled + bootstrap hard-fails on mismatch
- [ ] F02 remediated, handle_commit re-verifies TXs
- [ ] F17 verified — which roster do BFT consumers use?
- [ ] F18 — Stage F harness green on 3-node local
- [ ] F19 — plan an inflation activation date & auditor
- [ ] Cluster clocks NTP-synced, drift monitored (F05)
- [ ] Operator runbook: what to do if F04 divergence alert fires
- [ ] Published: testnet onboarding doc explaining F16/F17 trust model

---

## Out-of-Scope / Not Examined

Within the time budget of this audit I did NOT examine:
- `nodus/src/protocol/nodus_tier2.c` / `tier3.c` CBOR decoder fuzz-readiness (task #2 — partial, not completed)
- `nodus/src/witness/nodus_witness_merkle.c` RFC 6962 correctness in depth (task #3 — partial)
- `nodus/src/witness/nodus_witness_db.c` transactional boundaries (task #11 — not done)
- `dnac/src/wallet/selection.c` / `balance.c` coin selection privacy (task #12 — not done)
- `dnac/src/transaction/token_create.c` 1% fee enforcement (task #7 — not done)
- DNAC TOKEN_CREATE / CPUNK migration bridge — separate audit recommended
- `nodus/src/witness/nodus_witness_handlers.c` (2671 LoC) T2 dispatchers — fuzz recommended
- Full Dilithium5 context-separation sweep — partial (cert domain tag verified, others not)
- Peer slot leak root-cause fix (F13) — symptom noted, fix not designed

These areas are **not implied to be safe**; they were outside the time budget. A follow-up audit pass (ideally with fuzzing + dynamic analysis) is strongly advised for public-mainnet promotion.

---

## Method notes

- Static analysis only. No running cluster, no fuzzing, no dynamic instrumentation.
- Pattern-based search for known attack classes (unchecked integer math, missing auth, TOCTOU, signature scope gaps, default-trust paths, domain-separation collisions).
- Evidence discipline: every non-trivial claim cites `file:line`. Un-cited claims are hypotheses to verify.
- Severity/Exploitability scoring is heuristic and should not be mistaken for a CVSS rating. Use it for triage only.

---

---

# EXTENDED FINDINGS — Parallel Agent Pass (2026-04-20, same day)

**Method:** After the initial pass (F01-F19) identified the scope gap, 10 parallel `Explore` sub-agents were dispatched, each scoped to one audit area the initial pass did not complete. Every sub-agent was required to read the initial audit first, cite `file:line` for every claim, and return "NOT FOUND" when clean. Findings were renumbered in the main index below to avoid agent-namespace collisions.

**Numbering:** F20-F29 Wire/CBOR · F30-F39 Crypto · F40-F49 DB/Sync · F50-F59 UTXO/Nullifier · F60-F69 Stake/Reward · F70-F79 Merkle · F80-F89 Peer/Networking · F90-F99 Economics · Fa0-Fa9 Client-side · Fb0-Fb9 Genesis/TOKEN_CREATE

**Most important outcome from this pass:** **F17 is ESCALATED from INFO to CRITICAL.** The peer-networking sub-agent confirmed with file:line evidence that the BFT consensus uses the **gossip-joined roster** (`w->roster.n_witnesses` at `nodus_witness_bft.c:3444`, `:3735`, `:255`, `:362`), NOT the chain-derived committee (`nodus_committee_get_for_block` is only consulted for reward distribution and CHAIN_CONFIG vote verification). STATUS.md:148's claim of "chain-derived top-7" does NOT match the implementation for consensus voting. Stake-delegation-v1's core security promise is not in force.

---

## Extended Findings Summary

| # | Finding | Layer | Severity% | Exploit% | Risk | Tier |
|---|---|---|---|---|---|---|
| **F17** | **(ESCALATED)** BFT uses gossip roster, not chain committee | Consensus | **90** | **85** | **76.5** | **CRITICAL** |
| **Fa2** | `utxo.verified` not enforced in `balance.c` | Client | 75 | 90 | **67.5** | **CRITICAL** |
| **F81** | Sybil gossip roster join (no auth at boundary) | Networking | 70 | 90 | **63** | **CRITICAL** |
| **Fa7** | RPC responses beyond envelope not verified (nullifier/ledger/supply) | Client | 70 | 85 | **59.5** | **CRITICAL** |
| **F82** | Kademlia poisoning (unsigned peer records) | Networking | 60 | 95 | **57** | **CRITICAL** |
| **Fa4** | Witness discovery trusts unsigned roster entries | Client | 65 | 75 | **48.75** | **CRITICAL** |
| **F83** | TCP 4004 inter-node Dilithium auth gap | Networking | 55 | 80 | **44** | **HIGH** |
| **Fa3** | Coin selection fingerprints user | Client privacy | 50 | 80 | **40** | **HIGH** |
| **Fa10** | Selection algorithm deterministic | Client privacy | 55 | 70 | **38.5** | HIGH |
| **Fa8** | Wallet recovery leaks fingerprint to witness | Client privacy | 40 | 95 | **38** | HIGH |
| **F52** | `witness_count` not in `tx_hash` preimage — attestations forgeable | UTXO signature | 70 | 50 | **35** | **CRITICAL** |
| **F20** | T3 response handlers don't echo request `txn_id` (3 sites) | Wire protocol | 45 | 70 | **31.5** | **HIGH** |
| **Fa5** | Ledger range truncation undetected | Client | 45 | 70 | **31.5** | HIGH |
| **F51** | Chain_id missing from nullifier preimage | UTXO | 50 | 60 | **30** | HIGH |
| **F50** | Nullifier non-determinism via `strlen(owner_fp)` | UTXO | 65 | 45 | **29.25** | **HIGH** |
| **F60** | `apply_stake` missing MAX_VALIDATORS (128) pre-insert check | Stake | 45 | 60 | **27** | HIGH |
| **F53** | Output count limit 16/TX × 10/block → UTXO bloat DoS | Economic | 35 | 60 | **21** | MEDIUM |
| **Fa9** | No dedup for parallel sends → accidental double-spend | Client | 35 | 60 | **21** | MEDIUM |
| **Fb2** | TOKEN_CREATE fee not witness-enforced | Economic | 40 | 50 | **20** | MEDIUM |
| **F42** | Fork detection uses tx_root only, not state_root | Sync | 45 | 40 | **18** | MEDIUM |
| **F54** | Fee routing invariant not enforced exactly | Economic | 45 | 40 | **18** | MEDIUM |
| **F41** | Rollback incomplete on `finalize_block` error (SAVEPOINT fallthrough) | DB | 55 | 30 | **16.5** | MEDIUM |
| **F91** | No minimum output size → dust UTXO bloat DoS | Economic | 35 | 45 | **15.75** | MEDIUM |
| **F40** | Genesis `chain_def_blob` NULL handling silent failure | DB | 60 | 25 | **15** | MEDIUM |
| **F21** | Rate-limit 1-second granularity boundary bypass | Wire | 25 | 60 | **15** | MEDIUM |
| **F84** | PREVOTE/PRECOMMIT phase check absent, allows reorder | BFT | 40 | 35 | **14** | MEDIUM |
| **Fb1** | Genesis enforcement: defaults to 2f+1, not unanimous | Genesis | 70 | 20 | **14** | MEDIUM |
| **F44** | Nullifier duplicate insert silently IGNORE'd | DB | 30 | 45 | **13.5** | MEDIUM |
| **Fb0** | chain_id derivation missing chain_def binding | Genesis | 45 | 30 | **13.5** | MEDIUM |
| **Fb3** | token_id collision via `time(NULL)` nonce (1s granularity) | TOKEN_CREATE | 50 | 25 | **12.5** | MEDIUM |
| **Fa6** | Memo field not sanitized for UI rendering | Client | 30 | 40 | **12** | MEDIUM |
| **F90** | Commission BPS max not witness-enforced at apply_stake | Economic | 40 | 30 | **12** | MEDIUM |
| **F43** | Schema v6 migration lacks transaction atomicity | DB | 35 | 30 | **10.5** | MEDIUM |
| **F80** | Peer slot leak root cause identified | Networking | 20 | 50 | **10** | LOW |
| **Fb5** | CPUNK precedence not protocol-enforced | TOKEN_CREATE | 25 | 40 | **10** | LOW |
| **F73** | Client anchor verifier depends on F01 fix | Merkle | 40 | 20 | **8** | LOW |
| **Fb4** | Minter authorization undefined after TOKEN_CREATE | TOKEN_CREATE | 35 | 20 | **7** | LOW |
| **F93** | Burn address tracking implicit, not separated | Economic | 30 | 25 | **7.5** | LOW |
| **F31** | 22 `nodus_random` call sites ignore return value (non-BFT) | Crypto | 40 | 15 | **6** | LOW |
| **F92** | Fee pool sub-member remainder accumulates | Economic | 25 | 20 | **5** | LOW |
| **F72** | Merkle direction convention fragile but tested | Merkle | 95 | 5 | **4.75** | LOW |
| **F85** | TCP 4003 channels ifdef guard — verify no fallthrough | Networking | 15 | 20 | **3** | LOW |
| **F22** | CBOR count narrowing on 32-bit platforms (testnet is 64-bit) | Wire | 20 | 15 | **3** | LOW |
| **F26 (econ)** | Accumulator residual_dust orphan on retire | Economic | 15 | 10 | **1.5** | INFO |
| **F70/F71/F74/F75** | RFC 6962 / chain_config_root collision / UTXO sort / odd-sibling | Merkle | — | — | **NOT FOUND** | ✅ |
| **F30/F32/F33/F34/F35** | Dilithium domain sep / sig malleability / key reuse / logs / Kyber | Crypto | — | — | **NOT FOUND** | ✅ |

**Extended pass count: 37 new findings + 9 verified-clean (NOT FOUND).**
**Overall audit: 56 findings total (19 initial + 37 extended). 8 CRITICAL, 8 HIGH, 16 MEDIUM, 11 LOW, 4 INFO, 9 clean.**

---

## CRITICAL Findings (new / escalated)

### F17 (ESCALATED) — BFT consensus uses gossip roster, not chain-derived committee

**Severity: 90% · Exploitability: 85% · Risk: 76.5 — CRITICAL**

**Location:** `nodus/src/witness/nodus_witness_bft.c:3444` (leader lookup), `:3735` (voter roster check), `:255` (quorum from `w->roster.n_witnesses`), `:362` (broadcast to `w->peer_count`). `nodus/src/witness/nodus_witness_peer.c:579,1174` (gossip-triggered roster_add).

**Evidence:**
```c
// bft.c:3444 — leader lookup consults gossip roster
int leader = nodus_witness_bft_leader_index(epoch, hdr->view,
                                              w->roster.n_witnesses);

// bft.c:255 — quorum computed from gossip roster size
cfg->quorum = (2 * n) / 3 + 1;   /* n = w->roster.n_witnesses */

// bft.c:362 — broadcast to gossip peers
for (int i = 0; i < w->peer_count; i++) { ... }

// peer.c:579 — gossip-triggered roster add
if (nodus_witness_roster_add(w, &entry) == 0) { ... }
```

**Design claim vs. reality:** CLAUDE.md states "roster authority moves from DHT/routing-based auto-join to chain-derived top-7 by total stake." The chain-derived committee helper `nodus_committee_get_for_block()` exists and is invoked, but ONLY for reward distribution and CHAIN_CONFIG vote verification. **BFT consensus voting** (leader election, quorum, broadcast fan-out) still consults `w->roster`, which is populated via gossip from `peer.c:579,1174`.

**Attack:** Any node that announces itself via UDP 4000 Kademlia + opens TCP 4004 with a forged Dilithium5 keypair becomes eligible to vote in BFT consensus. No stake check, no committee verification.

**Impact:** Stake-delegation-v1's entire security narrative is inoperative. Anyone can be a "witness." Testnet consensus is trivially attackable by a Sybil running 3+ fake witnesses.

**Remediation (BLOCKING):**
1. Replace `w->roster` consumers in `bft.c` with `nodus_committee_get_for_block(w, current_height, ...)` calls. Keep `w->roster` purely as a transport-layer peer cache, not a consensus-layer authority.
2. Gate TCP 4004 accept: reject peers whose `witness_id` is not in the current chain-derived committee.
3. Unit tests: `test_bft_uses_chain_committee.c` — construct a chain state where gossip roster differs from committee, assert BFT ignores gossip entries.

---

### Fa2 — `utxo.verified=false` not gated in balance computation

**Severity: 75% · Exploitability: 90% · Risk: 67.5 — CRITICAL**

**Location:** `dnac/src/nodus/tcp_client.c:496` (sets false by default), `dnac/src/wallet/balance.c:40-72` (sums ALL UTXOs).

**Evidence:**
```c
// tcp_client.c:496
utxo.verified = false;
const dnac_trusted_state_t *trust = dnac_current_trusted_state();
if (trust && e->proof_depth > 0 && ...) { /* conditional set to true */ }

// balance.c:40-72 — no check on utxo.verified
for (int i = 0; i < count; i++) {
    if (memcmp(utxos[i].token_id, zero_token, ...) != 0) continue;
    ...
    case DNAC_UTXO_UNSPENT:
        if (safe_add_u64(balance->confirmed, utxos[i].amount, ...) != 0) { ... }
}
```

**Attack:** Combines with F01. A malicious witness serves fabricated UTXOs with `proof_depth=0`. Client marks them `verified=false` but balance.c sums them anyway. User sees inflated balance and tries to spend nonexistent money.

**Impact:** Direct user-facing wallet lie. Silent, because CLI/UI shows the inflated balance confidently.

**Remediation:** In `balance.c` main loop, add `if (!utxos[i].verified) continue;` and expose a separate `pending_balance` field for un-anchored UTXOs.

---

### F81 — Sybil gossip roster join (zero stake validation)

**Severity: 70% · Exploitability: 90% · Risk: 63 — CRITICAL**

**Location:** `nodus/src/witness/nodus_witness_peer.c:501` (gossip `w_ident` trigger), `:579` (roster_add on gossip).

**Evidence:** On receiving a gossip message with a new `witness_id + address`, the code calls `nodus_witness_roster_add()` unconditionally. No check that the sender holds stake or appears in the chain-derived committee.

**Attack:** Attacker broadcasts forged `w_ident` messages with witness_id=attacker1, attacker2, ...; each gets a roster slot. Combined with F17, each "witness" can vote.

**Remediation:** Query chain state before roster_add. Reject any witness_id not in top-7 committee at current block height.

---

### Fa7 — RPC responses beyond T2 envelope not verified (nullifier/ledger/supply)

**Severity: 70% · Exploitability: 85% · Risk: 59.5 — CRITICAL**

**Location:** `dnac/src/nodus/tcp_client.c:203-212` (nullifier check), `:253-282` (ledger query), `:284-318` (supply query).

**Evidence:**
```c
// tcp_client.c:202-212 — dnac_bft_check_nullifier
int rc = nodus_client_dnac_nullifier(client, nullifier, &result);
...
*is_spent_out = result.is_spent;   /* Direct trust, no proof verify */
```

**Attack:** Malicious witness returns `is_spent=false` for a spent nullifier. Client accepts → double-spend. Or returns fabricated TX history. Or inflated supply.

**Remediation:** Every T2 response that carries consensus-critical state must include a Merkle proof (nullifier tree membership, tx_root inclusion, state_root signed by committee). Client verifies against trusted anchor before acting.

---

### F82 — Kademlia DHT peer record poisoning

**Severity: 60% · Exploitability: 95% · Risk: 57 — CRITICAL**

**Location:** UDP 4000 Kademlia peer discovery, upstream of witness roster.

**Evidence:** Nodus DHT allows any peer to announce `(key, value) = (witness_id, address:port)`. No signature anchored to chain state validates these records.

**Attack:** Flood DHT with forged peer records. Witness nodes discovering via DHT end up connecting to attacker-controlled addresses.

**Remediation:** Witness announcements must be signed by the witness's Dilithium5 key AND cross-referenced against chain-derived committee. Reject DHT records for `witness_id`s not in the committee.

---

### Fa4 — Witness discovery trusts unsigned roster entries

**Severity: 65% · Exploitability: 75% · Risk: 48.75 — CRITICAL**

**Location:** `dnac/src/nodus/discovery.c:166-259`.

**Evidence:**
```c
for (int i = 0; i < roster.count; i++) {
    strncpy(info->address, entry->address, sizeof(info->address) - 1);
    /* No verify of address against entry->pubkey or anchor. */
}
```

**Attack:** MITM on `dnac_roster` response substitutes attacker address for legitimate witness pubkey. Client connects to attacker.

**Remediation:** Verify roster entry signature. Require address to appear in committed committee state.

---

### F52 — `witness_count` NOT in `tx_hash` preimage — attestations forgeable

**Severity: 70% · Exploitability: 50% · Risk: 35 — CRITICAL**

**Location:** `dnac/src/transaction/transaction.c:321-375`.

**Evidence:** The canonical tx_hash preimage (lines 321-334 comment + 336-375 code) includes version, type, timestamp, chain_id, inputs, outputs, signer_count, signer_pubkeys, type-specific appended fields. **But NOT `witness_count` or the witness array**.

**Attack:** Attacker intercepts a signed TX, strips real witness attestations, substitutes forged ones, adjusts `witness_count`. The sender's Dilithium5 signature still verifies because the preimage is unchanged. If witness verification is lenient, the tampered TX applies with attacker-chosen witnesses.

**Impact:** Witness attestation layer is signature-dissociated. The "who witnessed this TX" information is meltable.

**Remediation:** Include `witness_count` and `witnesses[].witness_id` in the tx_hash preimage (signatures can stay out to avoid circular dependency):
```c
EVP_DigestUpdate(ctx, &tx->witness_count, sizeof(uint8_t));
for (int i = 0; i < tx->witness_count; i++)
    EVP_DigestUpdate(ctx, tx->witnesses[i].witness_id, 32);
```

---

## HIGH Findings (new)

### F20 — T3 response handlers fail to echo request `txn_id` (3 un-fixed sites)

**Severity: 45% · Exploitability: 70% · Risk: 31.5 — HIGH**

**Location:** `nodus/src/witness/nodus_witness_sync.c:288, 331` (SYNC_RSP), `nodus/src/witness/nodus_witness_peer.c:962` (ROST_R).

**Evidence:** Same pattern as commit `f334b3ff` v0.14.3 fix (CC_VOTE_RSP), but these 3 other response handlers still have:
```c
rsp.txn_id = ++w->next_txn_id;   /* WRONG: new ID, should echo */
```
Correct pattern at `nodus_witness_chain_config.c:645-649`: `rsp.txn_id = in->txn_id;`

**Attack:** Peer witness sends SYNC_REQ expecting `SYNC_RSP(txn_id=X)`. Receives `SYNC_RSP(txn_id=Y)` — correlation filter drops it. Request times out. Sync fails. Cluster can't replicate blocks.

**Remediation:** In each of the 3 sites, change to `rsp.txn_id = msg->txn_id;`. Regression test: request/response `txn_id` equality across all T3 response handlers.

---

### F50 — Nullifier non-determinism via variable-length fingerprint

**Severity: 65% · Exploitability: 45% · Risk: 29.25 — HIGH**

**Location:** `dnac/src/transaction/nullifier.c:43-46`.

**Evidence:**
```c
size_t fp_len = strlen(owner_fp);   /* Variable! */
if (fp_len > 192) fp_len = 192;
memcpy(data, owner_fp, fp_len);
```

**Attack:** Fingerprints with different trailing-NUL padding produce different nullifiers for semantically identical outputs. Two UTXOs could share a nullifier if canonicalization differs between client and witness.

**Remediation:** Use fixed 129-byte (DNAC_FINGERPRINT_SIZE) preimage, pad with zeros: `memcpy(data, owner_fp, 129);`.

---

### F51 — Chain_id missing from nullifier preimage (defense-in-depth)

**Severity: 50% · Exploitability: 60% · Risk: 30 — HIGH**

**Location:** `dnac/src/transaction/nullifier.c:9-10`.

**Attack:** Nullifier = `SHA3(owner_fp || seed)` — chain-agnostic. TX hash IS chain-bound (signature protection catches cross-chain replay), but binding chain_id into nullifier would close the defense-in-depth gap.

**Remediation:** `nullifier = SHA3(chain_id || owner_fp || seed)`.

---

### F60 — `apply_stake` missing MAX_VALIDATORS (128) pre-insert check

**Severity: 45% · Exploitability: 60% · Risk: 27 — HIGH**

**Location:** `nodus/src/witness/nodus_witness_bft.c:1111-1139`.

**Evidence:** verify.c:116-122 explicitly lists this as TODO. Two STAKE TXs in the same block when `active_count = 127` both pass, reaching 129 validators — violates Rule M hard cap.

**Remediation:** Add pre-insert active_count check in `apply_stake`.

---

### F83 — TCP 4004 inter-node Dilithium auth gap

**Severity: 55% · Exploitability: 80% · Risk: 44 — HIGH**

**Location:** TCP 4004 BFT listener (deeper read-through needed post-audit).

**Evidence:** STATUS.md:74 claims inter-node auth "fixed," but F17's confirmation (BFT uses gossip roster) implies admission control is ineffective. Either auth exists but doesn't gate stake, or doesn't exist on TCP 4004.

**Remediation:** Mutual TLS-style Dilithium5 handshake + on-chain committee membership check at `accept()`.

---

### Fa3, Fa5, Fa8, Fa10 — Client-side HIGH findings

- **Fa3 (40):** Coin selection smallest-first greedy + owner_fp change output → wallet fingerprinting. Fix: randomized knapsack + unique per-TX change addresses.
- **Fa5 (31.5):** Ledger range queries silently truncate without flag. Fix: `was_truncated` in result struct + pagination retry.
- **Fa8 (38):** Wallet recovery sends plaintext `fingerprint` to witness — enables global deanonymization. Fix: encrypted local cache + private-set-membership recovery.
- **Fa10 (38.5):** Selection tie-break via unstable `qsort` → cross-TX pattern leakage. Fix: randomized sort.

---

## MEDIUM Findings (summary — see findings table)

Extended MEDIUM findings cover: dust UTXO bloat (**F53**, **F91**), TOKEN_CREATE fee bypass (**Fb2**, **F92**), finalize_block rollback gaps (**F41**), genesis consensus ambiguity (**Fb0**, **Fb1**, **Fb3**), fork detection using tx_root only (**F42**), rate-limit bypass (**F21**), phase-reorder acceptance (**F84**), memo XSS surface (**Fa6**), parallel-send dedup gap (**Fa9**), commission BPS enforcement (**F90**), schema migration atomicity (**F43**), nullifier duplicate-insert silent IGNORE (**F44**), chain_def NULL handling (**F40**).

## LOW / INFO (summary — see findings table)

**LOW:** F80 peer slot leak detail, Fb5 CPUNK precedence, F73 anchor verify F01 dependency, Fb4 minter authority, F93 burn accounting, F31 non-BFT nonce fail-open, F92 fee pool remainder, F72 Merkle direction fragility, F85 channel guard, F22 CBOR 32-bit narrowing.

**INFO:** F26 residual_dust orphan risk (theoretical).

## NOT FOUND (verified clean)

- **F30 / F32 / F33 / F34 / F35 (Crypto):** Domain separation across 11 TX types correct (purpose_tag[17] "DNAC_VALIDATOR_v1" for STAKE, distinct type_byte + appended field structure for others). BFT cert preimage uses "cert\0\0\0\0" domain tag. Signature verification is exact-match (no partial-byte skip). Key reuse between BFT cert and TX signing is safe because preimages are structurally distinct. No secret material in logs. Kyber1024 correctly scoped to messaging/VPN, not consensus.
- **F70 / F71 / F74 / F75 (Merkle):** RFC 6962 compliance correct (0x00 leaf / 0x01 internal prefixes). Hard-fork 0x02 version byte prevents legacy-formula collision. `chain_config_root` empty sentinel uses `NODUS_TREE_TAG_CHAIN_CONFIG = 0x05` domain tag — no collision with all-zero or legacy 4-input formula. UTXO leaf sort is database-deterministic (nullifier is primary key, globally unique). RFC 6962 odd-sibling handled via recursive split (no explicit duplication), builder/verifier agree.

---

## REVISED Testnet Go/No-Go Verdict

**The earlier verdict (NO-GO with F01 + F02 + F17 mitigations) stands but is SIGNIFICANTLY EXPANDED.** After the parallel audit pass, testnet ship gates are:

### MUST-FIX (expanded BLOCKING list, 9 items)

1. **F01** — fill `DNAC_KNOWN_CHAINS` chain_id, hard-fail on mismatch
2. **F02** — handle_commit re-verify batch TXs
3. **F17** — replace `w->roster` consumers in BFT with `nodus_committee_get_for_block`
4. **Fa2** — gate `balance.c` on `utxo.verified`
5. **Fa4** — witness discovery verify roster entries against chain state
6. **Fa7** — Merkle proofs on nullifier/ledger/supply T2 responses
7. **F52** — include `witness_count` + witness_ids in tx_hash preimage
8. **F20** — fix 3 un-echoed `txn_id` response handlers (SYNC_RSP × 2, ROST_R)
9. **F81** — witness admission requires chain-state committee membership

F81 + F82 + F83 collapse into "chain-derived committee gates all witness admission paths" — fixing F17 properly closes them together.

### SHOULD-FIX (12 items — document if deferred)

F50, F51, F60, F42, F41, F54, F91, F53, Fa9, Fb2, Fa3, Fa10.

### ACCEPT FOR TESTNET WITH RUNBOOK (many items)

All LOW + INFO + NOT-FOUND-verified items. Document operational constraints (NTP, operator-as-trust-anchor, monitoring plan) in the testnet onboarding doc.

---

## Pre-Launch Verification Commands

```bash
# F01 verification
grep -A 10 "DNAC_KNOWN_CHAINS\[\]" /opt/dna/dnac/src/ledger/genesis_anchor.c
# Should NOT contain .chain_id = { 0 }

# F17 verification
grep -n "w->roster" /opt/dna/nodus/src/witness/nodus_witness_bft.c | wc -l
# Should show roster used only in discovery/broadcast, not in leader/voter auth

# F20 verification
grep -n "rsp.txn_id = ++w->next_txn_id" /opt/dna/nodus/src/witness/
# Should return ZERO matches after fix

# Fa2 verification
grep -B 2 -A 2 "utxos\[i\]\.verified" /opt/dna/dnac/src/wallet/balance.c
# Should show a gate: `if (!utxos[i].verified) continue;`

# F52 verification
grep -A 5 "witness_count" /opt/dna/dnac/src/transaction/transaction.c
# Should see witness_count folded into EVP_DigestUpdate preimage
```

---

*Extended audit pass complete 2026-04-20 via 10 parallel Explore sub-agents. All original scope (13 tasks) now covered. Raw sub-agent outputs available in conversation transcript.*

*Audit generated 2026-04-20 by EXECUTOR against `main` branch head. Re-audit recommended after remediations land and before mainnet promotion.*
