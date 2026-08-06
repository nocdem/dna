# DNAC Blockchain — Component Status

**Last verified:** 2026-04-15 (against source code, not memory)
**DNAC version:** v0.14.3
**Nodus version:** v0.12.12
**Chain:** `4a68e14678400c693f1cfefe723d7fa5876c3d2d121048961a83b1a18cc1dcbb` (9 blocks, 7/7 consistent)

This document is the **source of truth** for what DNAC has and what it lacks.
`ROADMAP.md` and `TODO.md` are historical; consult them only for phase history,
not current state.

> **Addendum 2026-08-05 — Ledger V2 Season 3 COMPLETE (DNAC v0.18.0-ledgerv2-s3 /
> nodus v0.19.0).** The header block above still reports the 2026-04-15 wholesale
> verification pass; only the S3 items below have been re-verified against source
> on 2026-08-05. Everything else in this file predates stake-delegation v1, the
> hard-fork mechanism and Ledger V2 S1/S2 and should be treated as historical
> until the next full pass.
>
> - **Dynamic active validator set** — committee size is chain-config param 4
>   `DNAC_CFG_TARGET_ACTIVE_COUNT`, range `[7, 128]`, SAFETY grace class, sampled
>   at epoch-start heights (`nodus/src/witness/nodus_witness_committee.c`
>   `committee_target_for_epoch`).
> - **Per-epoch validator-set snapshots** — canonical codec
>   `shared/dnac/vset_wire.h` (tag `"DNA.VSET.v1"`, 78-byte header + 2642 B/entry),
>   persisted in `validator_set_snapshots`, committed one epoch ahead at every
>   boundary and at genesis. **The snapshot is the committee authority**
>   (`nodus_committee_get_for_block`, `nodus_witness_vset_apply_boundary_flips`).
> - **`DNAC_VALIDATOR_ELIGIBLE = 4`** — bonded + tenured but not seated this
>   epoch; boundary flips move `ACTIVE ↔ ELIGIBLE`.
> - **Extra self-bond** — `bond = Σnative_in − Σnative_out − committed_fee`,
>   required `>= DNAC_SELF_STAKE_AMOUNT`; graduation repays the actual bond.
> - **Quorum from the governing set** — `dna_bft_quorum(n) = (2n)/3+1`
>   (`shared/dnac/ledger_ids.h`) in chain-config apply, halt recovery and SYNC
>   cert verification. The fixed `[5, 7]` threshold is gone.
> - **INACTIVE V2 layers** — QC V2 (`shared/dnac/qc_v2.h`, 216-byte
>   `"DNA.CERT.v2"` preimage) and `validator_set_root`
>   (`"DNA.VSLEAF.v1"`/`"DNA.VSNODE.v1"`, `shared/dnac/ledger_roots_v2.h`) are
>   built and tested but feed only the inactive V2 hierarchy; the live 144-byte
>   cert path and the v3 five-input `state_root` are byte-identically unchanged.

> **Addendum 2026-08-05 — Ledger V2 Season 4 COMPLETE (DNAC v0.18.1-ledgerv2-s4 /
> nodus v0.19.1). INACTIVE — no live consensus path touched.**
>
> - **DomainManifest v1 + canonical domain codec** — `shared/dnac/domain_wire.{h,c}`:
>   versioned manifest (BE, 199 + tx_type_count bytes, tag `"DNA.DOMMAN.v1"`),
>   RulesetDescriptor digest (`"DNA.RULESET.v1"`), 223-byte
>   DomainRegistryRecord (leaf `"DNA.DRLEAF.v1"`, node `"DNA.DRNODE.v1"`,
>   empty root = the frozen S2 `"DNA.E.DOMREG.v1"`), proposal digest
>   (`"DNA.DOMPROP.v1"`) and the 233-byte readiness preimage
>   (`"DNA.DOMRDY.v1"`, Dilithium5-signed, 4844-byte wire). Enum value 0 is
>   INVALID everywhere (fail-closed on zeroed memory).
> - **Compiled NATIVE_BUILTIN runtime table** —
>   `nodus/src/witness/nodus_witness_runtime.{h,c}`: exact-tuple lookup on
>   `(domain_id, runtime_kind, runtime_abi, ruleset_version, ruleset_hash)`;
>   SYSTEM + DNA_CORE only; pinned descriptor digests re-derived by
>   `nodus_witness_runtime_selfcheck()`; no closest-version, no implicit
>   latest; the S5 apply/root hooks are declared but must be NULL.
> - **Domain registry + staged activation scheduler** —
>   `nodus/src/witness/nodus_witness_domreg.{h,c}` over new tables
>   `domain_registry` / `domain_readiness` (`nodus_witness.c` schema):
>   register / propose / signal / schedule / cancel / pause / resume /
>   retire; readiness quorum `floor(2N/3)+1` schedules, ALL-ACTIVE readiness
>   activates; two-epoch deadline (`sched + 2E`); Stage-C unready exclusion
>   through the ordinary S3 snapshot transition (non-slashing, floor-guarded);
>   set-change and ruleset activation never share a boundary; postponement is
>   exactly one epoch at a time; historical-snapshot authority pinned.
> - **V2 semantic admission (inactive)** — `nodus_witness_domreg_admit_v2`:
>   chain/domain/status/ruleset/runtime/ownership/statement/pool/quota gates;
>   **Type 11 stays REJECT (C3 stop) and types 12-14 stay unavailable** at
>   this boundary too.
> - **Registry root live in the INACTIVE hierarchy** — the
>   `domain_registry_root` leg of `nodus_witness_system_root_v2` is real
>   (`nodus_witness_domreg_root`); an empty registry yields the byte-identical
>   S2 placeholder root, so every pre-registry chain is unchanged.
> - **Tests** — `nodus/tests/test_domain_wire.c` (oracle-pinned KATs +
>   62,000-mutant deterministic fuzz), `test_domain_runtime.c`,
>   `test_domreg.c` (real keys, N=7/9 quorum, restart identity,
>   cross-node root determinism). nodus ctest 152/152.

> **Addendum 2026-08-05 — Ledger V2 Season 5 COMPLETE (DNAC v0.18.2-ledgerv2-s5 /
> nodus v0.19.2). INACTIVE — no live consensus path touched.**
>
> - **Versioned schema + atomic migration** — `nodus_witness_v2_schema.{h,c}`:
>   `PRAGMA user_version = 5`; one BEGIN IMMEDIATE migration (six `v2_*`
>   tables + `utxo_set.domain_id` NOT NULL DEFAULT 1 = DNA_CORE backfill);
>   fresh/S4/legacy paths; per-stage failure = full rollback; unknown
>   version fails closed (`test_v2_schema`, 26 checks).
> - **DomainUpdate v1** — `shared/dnac/domain_wire.{h,c}`: 368-byte canonical
>   record (tags `DNA.DUPD.v1`, `DNA.DUNODE.v1`, `DNA.E.DUPD.v1`,
>   `DNA.DTXB.v1`, `DNA.E.DUPDPRV.v1`), oracle KATs + 20k-mutant fuzz.
> - **Atomic apply engine** — `nodus_witness_v2_apply.{h,c}`: ONE SQLite
>   transaction per global block; phase order SYSTEM → cross → domain-local
>   ASC → roots → updates/heads/history → indices → metadata → supply gate →
>   COMMIT; 15 deterministic fault points with FULL-DB-DIGEST rollback proof;
>   replay/idempotency matrix; untouched-domain guard (undeclared mutation =
>   cross-domain substitution rejects); declared no-ops reject (no fake
>   updates); per-domain quotas + global tx cap + verify budget
>   (`test_v2_apply`, 78 checks).
> - **V2 supply gate** — `nodus_witness_v2_supply_check`: genesis+minted−burned
>   == Σutxo + Σself_stake + Σtotal_delegated + Σepoch_pool + shielded(≡0;
>   any shielded/pool table = reject); checked arithmetic; official DNA
>   numbers test-pinned: raw 100000000000000000 total, 7 × 1000000000000000
>   bonds CARVED (additive 70M violates), 93000000000000000 transparent.
> - **Genesis-root cycle break** — `DNA.SYSPAYL.v1`
>   (`dna_v2_system_payload_root` + witness loader): manifest
>   `genesis_state_root` = runtime-owned payload root (SYSTEM excludes
>   registry/manifest commitments; CORE = full core root); final head root =
>   full 8-leg composition. Dependency DAG proven in-test; no zero
>   placeholder remains; independent fixtures land byte-identical roots.
> - nodus ctest **154/154**; messenger 35/35; zk 87 GREEN, zero vector
>   change; ASAN+UBSAN clean; Type 11 REJECT everywhere.

> **Addendum 2026-08-05 — Ledger V2 Season 6 COMPLETE (DNAC v0.18.3-ledgerv2-s6 /
> nodus v0.19.3). INACTIVE — no live consensus path touched; types 12-14
> stay UNASSIGNED (a claim has NO live transaction type).**
>
> - **Generic genesis/distribution manifest** — `shared/dnac/manifest_wire.{h,c}`:
>   GenesisManifest v1 (tag `DNA.GMAN.v1`; strict BE codec; presence byte
>   controls the distribution section's EXISTENCE — no hidden defaults;
>   unknown versions/enums/presence values fail closed; commits genesis
>   supply, the SYSTEM+DNA_CORE DomainManifest hashes — `DomainManifest v1`
>   UNCHANGED — and, when present: opaque source tag + source commitment
>   metadata, snapshot root, leaf count, exact conversion + FLOOR rounding,
>   excluded amount, total claimable, claim window, auth/fee/post-deadline
>   modes). NO chain_id field: chain_id = genesis_block_id[0..31] is
>   derived OVER the manifest bytes (block_v2.h) — embedding one would be
>   circular. Consumer-neutral: no project name/domain/policy anywhere.
> - **Distribution snapshot + inclusion proofs** — generic leaves
>   (`DNA.DSLEAF/DSNODE.v1`: opaque length-prefixed source id, source
>   amount, dest binding = SHA3-512(recipient pubkey)); canonical
>   length-aware source-id order, duplicates reject; promote-odd Merkle;
>   proofs carry sibling hashes only — the shape derives from
>   (index, leaf_count), count mismatch rejects.
> - **Generic claims** — `DNA.CLAIM.v1` signed preimage (ML-DSA-87,
>   DNA-native mode 1 only), nullifier `DNA.CLNUL.v1` from the committed
>   leaf context (chain ‖ manifest ‖ source id), deterministic output id
>   `DNA.CLUTXO.v1`; claims_root `DNA.CLLEAF/CLNODE.v1` sorted by
>   nullifier (insertion-order independent); empty roots byte-identical to
>   the frozen S2 `DNA.E.MANIF.v1`/`DNA.E.CLAIMS.v1` placeholders.
> - **Witness integration** — schema v6 (`v2_manifests`, `v2_dist_state`,
>   `v2_claims_spent`; atomic 5→6, unknown fails closed); REAL
>   manifest_root (SYSTEM leg) + claims_root (DNA_CORE leg) replacing only
>   the S6 tagged-empty placeholders; claims execute INSIDE the one S5
>   BEGIN IMMEDIATE (admit → spend insert [F16] → transparent DNA_CORE
>   output [F17] → remaining decrement [F18], all digest-proven rollback);
>   supply equation gains exactly one owner: `genesis + minted − burned ==
>   Σutxo + Σself_stake + Σdelegated + Σepoch_pool + unclaimed_distribution
>   + shielded(≡0)` — a claim MOVES value, never mints (supply_tracking
>   untouched, overdraw of a lying manifest rejects).
> - **Post-deadline v1 = RETAIN only**: late claims reject, remaining state
>   retained; any burn/transfer/disposition is an OPEN future versioned
>   mode (fail-closed today).
> - `test_manifest_wire` 97 checks (round-trips, per-field sensitivity,
>   truncation sweeps, 40k deterministic mutants, proof shapes 1..9);
>   `test_v2_claims` 54 checks (v6 migration matrix, twin-fixture root
>   identity, full adversarial matrix incl. destination substitution /
>   cross-chain replay / early / late / duplicate / spent-after-restart,
>   insertion-order independence, never-mint). nodus ctest **156/156**;
>   messenger 35/35; ASAN+UBSAN clean; Type 11 REJECT everywhere.

> **Addendum 2026-08-06 — Ledger V2 GENERICITY CORRECTION (uncommitted
> correction pass over S1-S6; INACTIVE layer only, no live consensus path
> touched, no version bump).** The S6 report's `domain_id = 1 (schema
> default)` claim-output rule violated the locked generic architecture;
> this pass removed every such default and re-pinned the affected S6
> fixtures:
>
> - **Explicit distribution target** — GenesisManifest v1 distribution
>   section now commits `target_domain_id` (u32 BE) + bounded opaque
>   `target_asset_ref` (1..64 B; the CORE runtime reads it as the
>   EXISTING 64-byte token_id namespace, native-only in v1). Unknown /
>   inactive / unregistered / hookless / asset-incompatible targets fail
>   closed at manifest commit AND claim time.
> - **Consensus identity** — a claim references its manifest BY
>   MANIFEST HASH; `manifest_seq` is demoted to an internal DB locator
>   (keys no signature, nullifier, root or replay check). Nullifier v1 =
>   SHA3-512(`DNA.CLNUL.v1` ‖ chain_id ‖ manifest_hash ‖ target_domain_id
>   ‖ target_asset_len ‖ target_asset_ref ‖ snapshot leaf hash) —
>   nullifiers of different domains/assets structurally cannot collide.
>   manifest_root sorts by manifest_hash bytes; claims_root leaves commit
>   manifest_hash + target_domain_id, and each RUNTIME owns the
>   claims_root over the claims targeting ITS domain.
> - **Runtime dispatch** — the generic claim engine routes an admitted
>   claim through the registered TARGET runtime's `claim_apply` hook
>   (new runtime hooks: `state_root` / `asset_check` / `claim_apply` /
>   `invariant`); the engine never creates an output or picks a domain.
>   The S5 apply engine + V2 genesis are registry-driven (any registered
>   domain set), domain roots dispatch through `state_root`.
> - **No domain defaults** — `utxo_set` rebuilt with `domain_id NOT NULL`
>   and NO schema default (legacy → CORE is an explicit one-time
>   migration literal); `v2_blocks` dropped the named `system_root` /
>   `core_root` columns (global structures carry generic commitments
>   only); `v2_dist_state`/`v2_claims_spent` are keyed by committed
>   identity + explicit target.
> - **Supply** — `nodus_witness_v2_supply_check` is now a runtime-owned
>   invariant DISPATCHER; the DNAC equation lives in the CORE runtime
>   hook and never sums another domain's asset (the codec's
>   `total_claimable <= genesis_supply` cross-asset comparison was
>   removed — native backing is the CORE invariant's job).
> - **Tests** — `test_manifest_wire` 104, `test_v2_schema` 28,
>   `test_v2_apply` 78, `test_v2_claims` 73 (new GENERICITY suite:
>   synthetic registered domains T3/T4, non-CORE targets through the
>   runtime hook, per-domain claims_root, no cross-asset summation, no
>   default domain, 3-domain fault rollback, sidecar-claim reject,
>   4-domain coexistence with zero Header/BlockID/schema change),
>   `test_domain_runtime` 44. nodus ctest **156/156**; messenger 35/35;
>   ASAN+UBSAN clean on the affected suites. Gate
>   `DEFERRED-V2-GATE-S3-LIVE-SHRINK-CRASH` unchanged (OPEN).

> **Addendum 2026-08-06 — Ledger V2 GENERICITY CORRECTION pass 2
> (uncommitted, on top of pass 1; INACTIVE layer only, schema stays v6,
> no version bump). Two locked owner decisions implemented:**
>
> - **Native supply ownership → DNA_CORE.** `supply_root`
>   (genesis/minted/burned) moved OUT of `system_state_root` (now 7
>   legs) INTO `core_state_root` (now 6 legs, supply last);
>   `DNA.SYSPAYL.v1` payload root is 5 legs. Composition KATs re-pinned
>   through the same independent python3 sha3_512 oracle (it reproduces
>   the retired 8-leg/5-leg literals byte-exactly). Issuance mutation
>   moves the CORE root only (test-pinned); mint-into-epoch-pool is a
>   generic cross-domain op updating BOTH DomainUpdates atomically; fee
>   burn is CORE-local; an issuance mutation not declaring CORE trips
>   the untouched-domain guard; cross-move faults roll both domains
>   back (digest-proven). No framework-global "every domain has a
>   supply root" assumption exists — the leg lives inside CORE's own
>   root composition.
> - **Canonical DomainHead lifecycle.** The "synthesized pre-head on
>   first touch" rule is GONE. One canonical activation constructor
>   (engine `head_activate`) creates the head in the exact activation
>   block: root = runtime state root, whose activation-payload form
>   (new OPTIONAL `payload_root` runtime hook — SYSTEM's cycle-break
>   composition; NULL = state root) MUST equal the registry-committed
>   `genesis_state_root`; height 0; last_updated = activation height;
>   status ACTIVE; height-0 history row. Genesis uses the same
>   constructor for genesis-ACTIVE domains; registered-not-ACTIVE
>   domains are registry-only (no head, absent from domains_root, no
>   execution). ACTIVE ⇒ exactly one persisted head + one resolvable
>   runtime, else consensus failure; PAUSED/RETIRED heads carried
>   byte-unchanged without the runtime; resume fail-closed; RETIRED
>   terminal; unknown lifecycle values fail closed; activation atomic
>   with the SYSTEM registry transition (fault-injected, digest-proven);
>   twin-node byte-identical activation heads/roots; restart identity
>   before and after activation.
> - **Tests** — `test_roots_v2` 122 (new 7/6-leg KATs + supply-ownership
>   root checks), `test_v2_apply` 88 (supply-ownership integration:
>   mint/settle/burn/undeclared-issuance-guard/cross-move faults),
>   `test_v2_claims` 97 (full lifecycle matrix). nodus ctest
>   **156/156**; messenger 35/35; ASAN+UBSAN clean on all affected
>   suites. Gate `DEFERRED-V2-GATE-S3-LIVE-SHRINK-CRASH` unchanged
>   (OPEN).

> **Addendum 2026-08-06 — Ledger V2 Season 7 COMPLETE (DNAC
> v0.18.4-ledgerv2-s7 / nodus v0.19.4). INACTIVE — consensus-owned
> D=24 pool state only; NO shielded transaction activates; Type 11
> stays REJECT; types 12-14 stay UNASSIGNED; C3 remains parked.**
>
> - **Shared codec** — `shared/dnac/pool_wire.{h,c}` (pure SHA3-512,
>   zk-include-free; libnodus + libdna): pool config hash
>   (`DNA.POOLCFG.v1` — pins pool id, config version, depth 24 and the
>   consensus-committed history limit), pool leaf (`DNA.POOLLEAF.v1`,
>   272-B field payload / 288-B hashed preimage incl. the 16-B tag),
>   per-domain pools_root (`DNA.POOLNODE.v1`; zero
>   pools = frozen S2 `DNA.E.POOLS.v1` byte-identical), incremental
>   nullifier accumulator (`DNA.PNUL.v1`/`DNA.E.PNUL.v1` — O(1) per
>   insert, never an unbounded rehash), bounded history commitment
>   (`DNA.PHIST.v1`/`DNA.E.PHIST.v1`). Lane encoding = 4 canonical
>   Goldilocks u64 BE (the shielded-TX wire encoding).
> - **Witness pool module** — `nodus_witness_v2_pools.{h,c}`: appends
>   THROUGH the shipped `shielded_tree` (capacity 2^24, FULL rejects
>   before mutation); persists the O(D) frontier/count/root and
>   mutually verifies them on every load (fail-closed, no silent
>   rebuild); canonical `(tx index, slot)` mutation order; devnet
>   **R = 720** finalized-root window (mainnet R OPEN) with
>   single-oldest eviction, quiet blocks consuming nothing,
>   reappearance fail-close and retained-window anchor authority
>   (`nodus_witness_v2_pool_anchor_check` — read-only, NO live
>   caller); strict nullifier inserts namespaced `(domain, pool)`;
>   checked u64 balance (INT64_MAX storage bound). Correction pass
>   (2026-08-06): `nodus_witness_v2_pools_startup_check` — production
>   startup gate in `nodus_witness_create_chain_db`, once per DB open:
>   full ordered nullifier-log replay per pool (contiguous positions
>   from 0, canonical bytes, replayed `DNA.PNUL.v1` root == committed
>   root/count) + derived note-table shape (COUNT/MIN/MAX/canonical);
>   mismatch refuses the DB fail-closed, never repairs; pre-v7 DBs
>   pass vacuously; per-block insert stays O(1). Eviction semantics
>   clarified: duplicate detection covers the RETAINED window only —
>   evicted-root non-reproducibility is a cryptographic assumption of
>   the append-only tree, not a stored permanent history. Leaf
>   preimage arithmetic corrected in docs: 272-B field payload, 288-B
>   hashed preimage incl. tag (code always hashed 288 — doc-only).
> - **Schema v7** — `v2_pools` / `v2_pool_notes` (DERIVED path-serving
>   list) / `v2_pool_nullifiers` / `v2_pool_roots`; atomic 6→7 with
>   exact column-shape verification, stage fault injection, v8+ fail
>   closed. Apply engine + V2 genesis now require v7.
> - **Apply + supply** — pool batches ride the ONE block transaction
>   (phase 6p, fault points **F19-F25**, digest-proven rollback;
>   S1-S6 fault ids frozen); the CORE runtime instantiates its
>   configured native pool (`DNAC_SHIELDED_POOL_V1`, D=24, R=720)
>   through the new generic OPTIONAL `state_init` activation hook
>   (genesis pre-registry + idempotent in `head_activate`);
>   `pools_root` is a REAL core leg and `shielded ≡ 0` is REPLACED by
>   real committed native-asset pool balances (foreign asset/domain
>   excluded; the "no pool table may exist" guard retired).
> - **Tests** — NEW `test_v2_pools` (175 checks, 10 groups:
>   python-reproduced outer KATs, bridge identity with shielded_tree
>   E_24, anchor matrix, canonical-order rejects, synthetic
>   near-capacity frontier, nullifier namespacing/accumulator,
>   limit-3 eviction/expiry/rollback, balance/root ownership, engine
>   supply-move fixtures + follower order-divergence reject +
>   F19-F25 digest rollback, v7 migration matrix + column drift,
>   inactivity boundary). nodus ctest **157/157**; messenger 35/35;
>   zk `make test` ALL GATES GREEN (no vector touched); ASAN+UBSAN
>   clean on the 8 affected suites; Stage F 7-node harness scripts
>   7/7 state_root identical. Gate
>   `DEFERRED-V2-GATE-S3-LIVE-SHRINK-CRASH` unchanged (OPEN).

---

## Architecture (current)

DNAC is a **witness-only post-quantum UTXO blockchain**. The standalone DHT
transport was removed in v0.12.0; all consensus state lives in nodus-server's
embedded witness module (`nodus/src/witness/`).

- **Token model:** UTXO (Bitcoin-style), nullifier-based double-spend prevention
- **Consensus:** PBFT-style BFT (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- **Quorum:** 2f+1 of N witnesses
- **Block production:** Multi-tx blocks, 5s interval, max 10 TXs/block, fee-sorted mempool
- **Finality:** Instant at COMMIT (no fork choice rule, no reorgs)
- **Cryptography:** Dilithium5 signatures, SHA3-512 hashing, Kyber1024 KEM, BIP39 seeds
- **Storage:** Per-chain SQLite at `/var/lib/nodus/data/witness_<chain_id_hex_16>.db`

---

## ✅ SHIPPED

### Consensus
- [x] Witness BFT (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- [x] Leader rotation `(epoch + view) % N`
- [x] View change on 5s round timeout, max 3 view changes per request
- [x] 2f+1 quorum
- [x] Commit certificates (replicated via COMMIT msg)
- [x] Multi-tx blocks (v0.14.0)
- [x] Fee-sorted mempool, 64 TX capacity, 10 TX/block batch
- [x] Block linking via prev_hash chain
- [x] State sync (block-by-block catch-up + fork detection + DB rebuild)

### State & Validation
- [x] UTXO set (persistent, post v0.12.0 DHT removal)
- [x] Nullifier-based double-spend prevention
- [x] Atomic multi-input nullifier validation (v0.4.0)
- [x] **Merkle state_root (RFC 6962, SHA3-512)** — `nodus/src/witness/nodus_witness_merkle.c` (521 lines)
  - Leaf hash includes `nullifier || owner || amount || token_id || tx_hash || output_index`
  - Nullifier-sorted leaves, odd-sibling duplication
  - `build_proof` / `verify_proof` API
  - `tx_root` (RFC 6962 over per-block TX hashes)
- [x] state_root bound into block hash preimage
  - `SHA3-512(height || prev_hash || state_root || tx_root || tx_count || timestamp || proposer_id)`
- [x] BFT commit path computes root inside transaction (`nodus_witness_bft.c:1054-1075`)
- [x] **Witness divergence detection** active at COMMIT (`nodus_witness_bft.c:2107-2108`) — mismatch caught
- [x] Cached state_root + invalidation (`nodus_witness.h:283-284`)
- [x] Block hash recomputed before DB commit (v0.11.0 — TX integrity)
- [x] Nullifier fail-closed on DB error (v0.10.2)
- [x] Chain ID validation in all 10 BFT handlers (v0.10.2)
- [x] UTXO ownership verification before PREVOTE (v0.10.2)
- [x] Genesis block + genesis TX handler

### Cryptography
- [x] Dilithium5 (PQ signatures, 2592B pubkey, 4627B sig)
- [x] Kyber1024 (PQ KEM)
- [x] SHA3-512 hashing
- [x] BIP39 wallet seed derivation
- [x] Secure nonce — abort on RNG failure, no weak fallback (v0.10.2)
- [x] Replay prevention: nonce + timestamp + nonce hash table with TTL (v0.11.0)
- [x] COMMIT signature verification (v0.10.2 / v0.11.0)

### Networking
- [x] Witness BFT P2P on dedicated TCP 4004 (v0.10+)
- [x] Inter-node auth on TCP 4002 + 4004 (both fixed)
- [x] T3 wire protocol (CBOR over framed TCP, magic `0x4E44`)
- [x] T2 status query carries state_root to clients (`nodus_tier2.c:1166,2533` — `"sr"` CBOR field)
- [x] T3 inter-witness COMMIT msg carries state_root (`nodus_tier3.h:138,221`)
- [x] Block propagation in cluster
- [x] Block production rate-limit (5s min interval)

### Economics (partial)
- [x] Burn address (all-zero fingerprint) with explicit fee UTXOs
- [x] Supply tracking + invariant check (bit-identical across 7/7 nodes)
- [x] Overflow-safe arithmetic (`safe_add_u64`)
- [x] 8-decimal token (1 DNAC = 100,000,000 raw units)

### Client Layer
- [x] CLI: `dna send`, `dna sync`, `dna balance`, `dna history` (with memo column)
- [x] CLI: `dna chain` for chain inspection
- [x] Flutter wallet UI: `wallet_screen`, `dnac_provider`, history view, UTXO view
- [x] Witness discovery (`dnac_discover_witnesses`) — address-based, no stake gating
- [x] Wallet sync from witnesses (polling)
- [x] Wallet recovery from seed phrase

### Storage / Schema
- [x] SQLite per-chain DB
- [x] Tables: nullifiers, utxo_set, blocks, committed_transactions, commit_certificates, supply_tracking, genesis_state, ledger_entries
- [x] `blocks.state_root BLOB NOT NULL`
- [x] Schema versioning (current schema v12)

---

## ✅ SHIPPED 2026-04-16 — Anchored Merkle Proofs (branch merged, Phase 13 deploy pending)

- [x] **Per-UTXO Merkle proof delivery to clients** — `handle_dnac_utxo` ships per-UTXO `state_root_proof` + `block_height` (`nodus_witness_handlers.c` extended)
- [x] **Per-TX tx_root proof delivery** — `handle_dnac_history` ships per-TX `tx_root_proof` (new `nodus_witness_merkle_build_tx_proof` helper)
- [x] **Client-side Merkle proof verification** — `dnac_merkle_verify_proof()` implemented (`dnac/src/ledger/merkle_verify.c`, RFC 6962, SHA3-512)
- [x] **Block anchor verification** — `dnac_anchor_verify()` verifies block hash + 2f+1 Dilithium5 PRECOMMIT sigs against roster (`dnac/src/ledger/anchor_verify.c`)
- [x] **Genesis verification** — `dnac_genesis_verify()` bootstraps trust from hardcoded `chain_id` (Bitcoin-tier model, single trust root)
- [x] **High-level wrappers** — `dnac_utxo_verify_anchored` + `dnac_tx_verify_anchored` orchestrate the three primitives
- [x] **Genesis block schema** — `dnac_chain_definition_t` embedded in height=0 block hash preimage (witness pubkeys, consensus params, token params, native_token_id, fee_recipient all committed transitively via chain_id)
- [x] **`handle_dnac_genesis` T2 query** — fetches genesis block bytes from any peer
- [x] **`handle_dnac_block` + commit_cert** — response includes 2f+1 signatures
- [x] **Chain registry** — `DNAC_KNOWN_CHAINS[]` array in `dnac/src/ledger/genesis_anchor.c` (multi-chain forward-compat)
- [x] **Runtime trust state** — `dnac_current_trusted_state()` accessor, wallet bootstrap wired into `dnac_init`
- [x] **UTXO verify loop in sync path** — `dnac/src/nodus/tcp_client.c` calls `dnac_utxo_verify_anchored`, flips `verified` flag
- [x] **`dnac_utxo_t.verified` field** — runtime-only, distinguishes anchored vs unverified UTXOs
- [x] **`gen_genesis` operator CLI** — `dnac/tools/gen_genesis.c` builds new genesis + prints chain_id for paste
- [x] **Witness DB schema v14** — `chain_def_blob` column persists chain_def for genesis blocks
- [x] **Hardcoded constant refactor** — `format_amount`, `token_symbol`, `token_decimals` read from trust state (not `#define`)
- [x] **Test coverage** — 29 dnac assertions across 5 test suites (`test_merkle_verify`, `test_anchor_verify`, `test_genesis_verify`, `test_chain_def_codec`, `test_anchored_proofs`) + 1 new nodus test (`test_merkle_tx_proof`, 62/62 ctest)

**Scope NOT yet done (Phase 13 deploy gated on operator approval):**
- Hard fork execution: archive old chain, submit new genesis, paste real `chain_id` into `DNAC_KNOWN_CHAINS`, cluster stop/start
- Per-block anchor fetch for UTXOs whose `block_height` lags `latest_verified_anchor` (minor follow-up)
- Flutter "verified" UI badge (design doc deferred to separate PR)

**Design + plan:** `docs/plans/2026-04-16-dnac-anchored-merkle-proofs-{design,impl}.md`

---

## ⚠️ PARTIAL

- [ ] **Witness peer table slot leak**
  - 4 uncoordinated `peer_count++` sites cause "sent=11" with 6 peers
  - Secondary bug, not blocking consensus

---

## ❌ NOT STARTED

### Decentralization (the real gap)
- [ ] **Witness stake mechanism** (`TX_STAKE`)
  - No `TX_STAKE` type in `dnac/include/dnac/dnac.h` (only GENESIS / SPEND / BURN / TOKEN_CREATE)
  - `nodus_witness.h:44` only has comment: "Struct kept for future extensibility (e.g. stake threshold)"
  - Designed: 10M DNAC self-stake (Ethereum 32 ETH model), unlimited delegation on top
- [ ] **Stake-gated witness discovery**
  - Current discovery is address-based auto-join via gossip (`nodus_witness_peer.c:501,1037`) — no gatekeeping
  - Friend-of-friend manual whitelist only
- [ ] **Slashing** — no equivocation detection, conflicting PREVOTE/PRECOMMIT sigs go unpunished
- [ ] **Unstake mechanism** — time-locked withdrawal (N blocks after request)
- [ ] **v2 weighted random sortition** — designed as "poor man's VRF", deferred until v1 deterministic top-21 ships

### Economics
- [ ] **Witness rewards / fee distribution** — fees currently burn, no payout to active witnesses
- [ ] **Block reward / inflation policy** — undefined
- [ ] **Stake-based incentive alignment** — pure altruism right now

### Operational / UX
- [ ] **Block explorer** — no public chain browser
- [ ] **Light client / SPV** — would unlock once client-side proof verify exists
- [ ] **Snapshot / fast state sync** — only block-by-block replay
- [ ] **T1 decode failure investigation** (Phase 3.2 — pre-existing, unrelated to consensus correctness)
- [ ] **T3 decode failure on peer connect** (pre-existing, doesn't block consensus)

### Future Protocol Versions — PQ ZK (STARKs)
Authoritative status: `shared/crypto/zk/RESUME.md` (top block).
- [x] STARK approach chosen: **Plonky3-grounded C ports** (pin `82cfad73`, Goldilocks,
      SHA3-512) — NOT winterfell/stone/ethSTARK. No Rust runtime; oracle byte-matched.
- [x] **Verifier stack + range/balance AIR built** (verify-only), soundness-audited,
      2 mints fixed, `make test` GREEN (36 gates). Parked, NOT in consensus.
- [ ] **Prover [MISSING]**, **B1 trace↔TX binding [OPEN]** (proof vacuous without it),
      full FRI param pin, consensus integration — all before-consensus MUST-FIX.
- [ ] **Confidential / hidden amounts = v4** (Poseidon2 in-AIR commitment) — deferred.
  - Proof size ~100 KB acceptable (DHT chunked storage).

---

## Skip-able by design (BFT consequence)

These are *not* gaps — they don't apply to a witness BFT chain:

- ~~Proof-of-Work mining / difficulty adjustment~~ — N/A
- ~~Fork choice rule / chain reorg handling~~ — N/A (instant finality at 2f+1)
- ~~Long-range attacks / weak subjectivity~~ — bounded by witness rotation policy
- ~~Uncle blocks / GHOST~~ — N/A

---

## Critical Path to "Trustless & Permissionless"

The chain **works** today as a permissioned witness federation. To become an
open decentralized chain, the remaining must-haves are:

1. **`TX_STAKE` + stake-gated roster** — defines who can be a witness
2. **Slashing** — defines the cost of misbehavior (paired with #1; alone meaningless)
3. ~~**Client-side Merkle proof verification**~~ — **SHIPPED 2026-04-16** (see shipped section above). Closes the "trust witness blindly" gap via anchored proofs backed by a single hardcoded `chain_id`.
4. **Witness rewards** — economic incentive to stay honest and online

Items 1+2+4 form one design (witness economics) and likely ship together as a
separate PR.

---

## Verification

To re-verify any "shipped" claim above, grep these anchors in source:

| Claim | File:line |
|---|---|
| Merkle implementation | `nodus/src/witness/nodus_witness_merkle.c` |
| state_root in block hash | `dnac/include/dnac/block.h:65,80-83` |
| BFT commit computes root | `nodus/src/witness/nodus_witness_bft.c:1054-1075` |
| Witness divergence detect | `nodus/src/witness/nodus_witness_bft.c:2107-2108` |
| Cached state_root | `nodus/src/witness/nodus_witness.h:283-284` |
| T2 wire ships root | `nodus/src/protocol/nodus_tier2.c:1166,2533` |
| T3 wire ships root | `nodus/src/protocol/nodus_tier3.c:133,251,581,975` |
| Schema NOT NULL | `nodus/src/witness/nodus_witness.c:80` |
| Merkle test | `nodus/tests/test_merkle_utxo_root.c` (169 lines) |
| Client merkle verify | `dnac/src/ledger/merkle_verify.c` (shipped 2026-04-16) |
| Client anchor verify | `dnac/src/ledger/anchor_verify.c` |
| Client genesis verify | `dnac/src/ledger/anchor_verify.c` (same file) |
| Chain registry | `dnac/src/ledger/genesis_anchor.c` (placeholder chain_id → filled at Phase 13) |
| gen_genesis tool | `dnac/tools/gen_genesis.c` |
| Merkle direction convention | `dnac/src/ledger/MERKLE_DIRECTION_CONVENTION.md` |
| Wallet bootstrap | `dnac/src/wallet/wallet.c` — `bootstrap_trusted_state()` |
| UTXO verify in sync | `dnac/src/nodus/tcp_client.c` — `dnac_utxo_verify_anchored` call site |
| No TX_STAKE | `dnac/include/dnac/dnac.h` (grep TX_STAKE → 0 hits) |
