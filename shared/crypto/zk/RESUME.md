# RESUME — DNAC v3 ZK stack (CURRENT STATUS: 2026-07-14)

> **This top block is authoritative and current. Everything under "═══ HISTORICAL
> BUILD LOG ═══" is the traceable module-by-module history and its numbers
> (widths, constraint counts, B6/B7 framing) are PRE-2026-07-12 — read them as
> history, not current state.**

## WHERE WE ARE

- **What it is:** a **prove + verify** STARK range/balance-proof stack over the
  Goldilocks field — Plonky3-grounded C ports of the verifier engine (field,
  NTT, Keccak-AIR, SHA3 sponge, transcript, Merkle-MMCS, FRI fold + verifier,
  STARK constraint check, proof codecs) plus two DNAC-original money AIRs
  (range_air, sum_balance), a **pure-C prover** (`stark_prover.{c,h}` S1-S13 +
  `stark_prover_prove.{c,h}` instance-generic `dnac_prover_prove`), and a Rust
  build-time oracle (test-vector generation only, not shipped).
- **Prover COMPLETE (2026-07-14).** The C prover generates is_zk=1 RangeProofAir
  proofs (hidden amounts) that the C verifier accepts (`dnac_fri_verify ==
  DNAC_FRI_OK`) — **Rust-free, end-to-end, arbitrary instance**. Every stage
  byte-matches the real `p3_uni_stark::prove` (82cfad73). Only the Rust oracle's
  SmallRng(1) draw stream is a KAT input (design pin D1-B); production proving
  swaps it for OS entropy (a C CSPRNG is the remaining production gate, G2).
- **PERF (P2 bench, 2026-07-14 — `make bench-prover`, desktop, TEST params
  num_queries=2 ~4-bit soundness).** prove_ms 18 (h=4) → 466 (h=1024), ~linear
  in height (LDE/quotient dominated); verify_ms ~8-11 FLAT; proof 7-20 KB.
  **Verdict: 1 TPS VIABLE** (prove = wallet UX, sub-second even huge; verify
  ~0.2-0.3s/proof projected at production params × 1 TPS = fine; storage needs
  the already-planned pruning/archive). **100 TPS NOT viable per-TX** — verify
  throughput (100 × ~0.3s = ~30 CPU-s/wall-s per witness) + storage (100 ×
  ~100 KB = ~1 TB/day full-history) both blow up ~100×; the 100-TPS path is
  **recursive proof aggregation** (one aggregate proof per BLOCK, not per-TX) —
  a major future track, aligned with the roadmap's "100 TPS = Cosmos migration
  2027+, not near-term." The C prover perf is NOT the 1-TPS blocker; B1 binding
  + production params are.
- **Parked, NOT in consensus.** `grep` confirms zero references to
  `shared/crypto/zk` from any CMakeLists (messenger/nodus/dnac) — it is compiled
  ONLY by its own standalone `Makefile`, not into `libdna.so`/`nodus-server`.
  Money conservation on the live chain is enforced by the native cleartext
  witness check (`verify.c` Check 4); this ZK stack is ADDITIVE (v3 ships
  transparent, hidden amounts are v4).
- **B1 CONFIDENTIAL AMOUNTS — 🎯 STAGE-2 (is_zk=1, num_qc=8) COMPLETE (2026-07-15).**
  Design: `dnac/docs/plans/2026-07-14-b1-confidential-amounts-design-v3.md` (v3.1,
  local-only) + memory `project_v3_zk_implementation_progress` (▶ current). Stage-1
  built the standalone confidential AIR by CONSTRUCTION (conf_balance/conf_commit/
  conf_root/conf_txbind, constraint-eval only). **Stage-2 takes the combined
  conf_root AIR (WIDTH=614) to a REAL STARK prove→verify at is_zk=1:**
  - **Rust oracle `ConfRootAir`** (17 publics `[root(4),c_claimed(4),c_fee(4),
    hash_id,tx_binding(4)]`, main_next=1) → REAL `p3_uni_stark::prove` is_zk=1,
    verify=Ok, **num_qc MEASURED=8** (STOP gate; the AIR canNOT inherit
    poseidon2-air's `Some(7)`), GATE3 negative-control (tampered proof rejected),
    2 vectors (h=8 full + h=16 padded/3-FRI-round), byte-identical regen.
  - **C N-chunk recompose** `dnac_stark_recompose_quotient_nchunk` (stark_constraints)
    → byte-matches the REAL `recompose_quotient_from_chunks` (verifier.rs:59-96;
    inverts Z_j at first_point_i, UNrandomized split domains, GENERATOR=7 shifts).
  - **C combined air_eval fold** `conf_root_fold.c` (fp2 Poseidon2 lift + all
    conf constraints in the ORACLE-pinned emission order) → `folded·inv_van ==
    REAL quotient(zeta)` on a REAL proof (`dnac_stark_verify_constraints_nchunk`).
  - **Pure-C conf prover** `stark_prover_conf.c` (`dnac_conf_prover_prove`) → zeta +
    3 commit roots + final_poly **byte-match the REAL Plonky3 is_zk=1 proof** (both
    instances) + self-verify (FRI == DNAC_FRI_OK **AND** N-chunk constraint check).
    S6 quotient REUSES the verifier-fold eval row-by-row (ONE emission source).
  - **tx_binding = FS public** (observed before alpha; tamper→zeta and position-swap
    →zeta KATs, closes design O-4). **Production CSPRNG** `zk_entropy.c`
    (getrandom rejection-sample, fail-close) wired into
    `dnac_conf_prover_prove_production`; OS-entropy proof self-verifies.
  - **Independent 12-agent red-team: 12/12 SOUND, 0 defects** (0 CRIT/HIGH/MED); 3
    LOW/hygiene notes all FIXED. Report `dnac/docs/plans/2026-07-15-b1-stage2-
    redteam-report.md` (local). Grounding: `2026-07-15-b1-stage2-grounding-specs.md`.
  - **🎯 M3b SALTED-LEAF MMCS — VERIFIER-side COMPLETE (2026-07-15).** Adds
    leaf-level salt hiding (`MerkleTreeHidingMmcs`, SALT_ELEMS=2 = 128-bit) on top
    of the Stage-2 random-codeword blinding. Design (3-section):
    `2026-07-15-b1-stage2-m3b-salted-mmcs-design.md` (local).
    - **Oracle:** `HidingValMmcs` + `HidingChallengeMmcs` (BOTH input AND FRI mmcs
      salted — no half-hiding); `dump_is_zk_stark` refactored to a MACRO
      instantiated for the plain AND salted configs (ONE priming/JSON codepath, no
      drift; the plain vectors stayed BYTE-IDENTICAL). Real `p3_uni_stark::prove` +
      GATE1 verify + GATE3 negative-control + num_qc=8. 2 vectors
      `conf_root_air_salted{,_h16}.json`; opening proofs carry the `(salts,siblings)`
      tuple, salt[m] length 2.
    - **C verify:** `fri_verifier.{c,h}` — optional salt fields on the batch-opening
      + commit-phase-step structs (`salt_elems=0` → unsalted, backward-compat);
      salted leaf = `row ‖ SALT_ELEMS salts` (input) / `fp2 arity row ‖ base salts`
      (commit-phase, ExtensionMmcs base-flattened). Real salted proof (h=8 + h=16) →
      `DNAC_FRI_OK`; salt-tamper (input + commit-phase) → REJECT.
    - **Latent bug FOUND+FIXED:** `FRI_LEAF_CAP` (4096) UNDER-sized the 618-wide
      conf input row (4944 B) — a pre-M3b stack overflow surfaced by the salted
      `(cols+salt)*8` bound-check; raised to 5248.
    - **Independent 10-agent red-team: 8/10 SOUND, 0 soundness/mint.** 2 LOW fixed:
      (a) the SEC-M3b-2 canonical-salt `>= p` guard was DEAD CODE (`gold_fp_to_u64`
      pre-canonicalizes) → replaced with an honest type-invariant comment;
      (b) the `--salted` JSON parser CPU-spun on a flag/vector mismatch → anti-spin
      backstop (both directions now clean-reject). Report
      `2026-07-15-b1-stage2-m3b-redteam-report.md`.
    - **🎯 C salted PROVER — FULL self-verify COMPLETE (2026-07-15):** the pure-C
      conf prover now PRODUCES a SALTED is_zk=1 proof that byte-matches the REAL
      Plonky3 salted proof AND self-verifies. Rust-free end-to-end.
      - **4 commit fns** (`dnac_prover_commit_matrix/_quotient_commit/_random_commit/
        _fri_commit_phase`) gained an optional salt param (`salt_elems=0` = unsalted,
        RangeProofAir path byte-identical; all 32 gates GREEN). ~33 caller sites
        updated (a fork swept the S3-S13 tests).
      - **Salt threading (`stark_prover_conf.c` salted mode):** stream A (input-mmcs,
        contiguous offsets trace `[0]` / quotient `[16h]` / random `[16h·9]`) into
        trace/quotient/random commits; stream B (FRI-mmcs, separate SmallRng(1) from
        pos 0) into the commit-phase layers; salted query openings (commit↔opening
        salt formulas symmetric per matrix). Transcript alpha/zeta/beta all derive
        from SALTED roots (commits salted before observe).
      - **Gate `test_prover_conf --salted` (h=8 + h=16):** trace/quotient/random
        roots + zeta + final_poly BYTE-MATCH the REAL salted proof (trace root
        `8e24ec9b`) + self-verify (FRI `DNAC_FRI_OK` + N-chunk constraint check).
      - **Production is GENUINELY SALTED (red-team fix):** `dnac_conf_prover_prove_
        production` fills BOTH the codeword stream (708h) AND the salt stream (160h)
        from OS entropy → a real hiding proof; the earlier version left `salt_draws=
        NULL` (unsalted, non-hiding — the sole red-team finding, LOW, non-soundness).
      - **Independent 10-agent red-team: 9/10 SOUND, 0 soundness/mint;** the 1 LOW
        (production-unsalted) FIXED. Report `2026-07-15-b1-stage2-m3b-prover-
        redteam-report.md`. Salt layout: design §3a.
  Still PARKED (grep-confirmed: no consensus CMake references crypto/zk);
  product-need for confidential amounts is an open question (v3 transparent gives
  the same privacy).
- **DUAL-MODE SHIELDED — S0 PRIMITIVES + PINS COMPLETE (2026-07-16).**
  Design: `dnac/docs/plans/2026-07-15-dual-mode-transparent-shielded-design.md` +
  component docs `dnac/docs/plans/2026-07-16-dm-c1..c7-*.md` (all local-only) +
  memory `project_dual_mode_design` (~25 red-team rounds, no open CRITICAL at
  design level). S0 is the first IMPLEMENTATION step: the byte-matched primitives
  and consensus pins that C1/C3/C4 (the shielded SPEND AIR) all rest on.
  - **Note-commitment sponge** (`note_commit.{c,h}`): stock Plonky3
    `PaddingFreeSponge<default_goldilocks_poseidon2_8,8,4,4>` (all-zero IV, rate-4/
    capacity-4 → CR 2^128 [BDPA08]). `cm = sponge(value, addr_pub[4], rcm[2],
    DOMSEP_NOTE)` — domain sep via a preimage ELEMENT, not a non-standard IV, so it
    IS a Plonky3 primitive (discharges the `conf_root_air.h:47` owed byte-match).
    8 elems = exactly 2 rate-4 permutations, squeeze 4 lanes = 256-bit cm.
  - **Merkle 2-to-1 compress** (`note_merkle_compress`): SAME PaddingFreeSponge over
    `(left[4]‖right[4])` — capacity-preserving (dm-c3 F1: a bare width-8
    TruncatedPermutation is zero-capacity/invertible = not CR).
  - **Byte-match KAT** `test_note_commit` (8/8 cases) vs oracle
    `dump-note-commit-sponge` → `tools/vectors/note_commit_sponge.json`.
  - **DOMSEP constants** (`shielded_domsep.h`): NOTE/RHO/NF/ADDR/MERKLE =
    `SHA3-512("...")[0:8]` BE, all < p, all distinct (incl. vs B1's VAL/ACC).
    `test_shielded_domsep` re-derives + checks canonicity + distinctness (also
    re-derives the two B1 constants to prove the rule).
  - **FRI params → consensus constant** (`shielded_fri_params.{c,h}`, EXISTENTIAL —
    sole in-pool-mint barrier): `DNAC_SHIELDED_FRI_PARAMS` = Plonky3
    `new_benchmark_zk` (config.rs:102-113) — log_blowup 2, num_queries 100, query_pow
    16 → 216-bit conjectured soundness. New hardened entry
    `dnac_fri_verify_wire_shielded` SUBSTITUTES the pinned params (never wire),
    REJECTS non-pinned wire params + off-height proofs (committed domain pinned to
    2^11 = base 10 + is_zk 1, dm-c5 C5e — see H1 below). Generic
    `dnac_fri_verify_wire` untouched (parked B1/test
    paths keep their test params). `test_shielded_fri_params` asserts grounding +
    the substitution/reject guard.
  - **Shielded-enc seed** (`seed_derivation.c` + `bip39.h`): new non-breaking
    `qgp_derive_shielded_enc_seed` = SHAKE256(master ‖ "qgp-shielded-enc-v1", 32),
    domain-separated from signing/encryption (D6/I3). Test in
    `messenger/tests/test_bip39_bip32.c` (determinism + separation).
  - **Gate:** `cd shared/crypto/zk && make test` GREEN, 0 warnings (3 new S0 gates);
    libdna builds clean; `test_bip39_bip32` GREEN.
  - **Independent 12-agent red-team (run w5deaevcv, 2026-07-16): 0 CRITICAL → gate
    passes.** Pre-commit fixes APPLIED: **H1** — the is_zk COMMITTED trace domain is
    `base+1` (conf_root_air_zk.json `base_degree_bits:3→degree_bits:4`), so the
    height pin is `DNAC_SHIELDED_COMMITTED_LOG_HEIGHT == 11`, NOT the physical 10
    (my first cut was wrong + had a false "is_zk doubling is FRI-internal only"
    comment — corrected); **M4** — `dnac_fri_verify_wire_shielded` is now fail-closed
    (NULL out rejected, non-OK verdict → `ERR_SHIELDED_VERIFY_FAILED`, pre-set
    rejecting default); **M1/M2** — leaf/internal domain-sep claim corrected to
    honest (~2^64 at the hash level; full separation is a C3-AIR fixed-height goal,
    NOT a Plonky3 "tree model"); citation drift + Makefile stale prereqs fixed; seed
    KAT + oracle canonicity assert added.
  - **⚠ RECORDED HARD BLOCKERS for S4/S8 consensus wiring (red-team, numbered):**
    **H2** — the DEEP/zeta opening point is currently WIRE-READ + transcript-unbound
    (`dec_point`); the S4 shielded verify MUST sample zeta after observing the
    trace/quotient roots (route through `dnac_stark_priming`) and fail-close on any
    wire opening point. **H3** — the wrapper pins the security LEVEL+height but not
    the STATEMENT (does not observe wire commitments into the transcript); S4 must
    prime the transcript per uni-stark. **M5** — the unpinned sibling
    `dnac_fri_verify_wire` must be gated/renamed test-only before consensus. **M1/M2**
    — C3 must pin tree height + reject the h+1 leaf-decomposition (leaf/internal
    separation) and bind value<2^52 + addr=H(ak,nk). These are documented in
    `fri_proof_codec.h` + `shielded_domsep.h` at the code they gate.
  - **S1 IN PROGRESS — C1 phase-block AIR (`conf_action_air.{c,h}`, is_zk=0
    construction-gate, built incrementally):**
    - **S1a DONE** — forced φ-counter (E1 range-gate, E2 is_zero wrap-indicator, E3
      forced transition, E13 anchor), K=32. `test_conf_action_air`: honest cycling
      accepted + 9 φ-deviations rejected. The prover-independent positioning.
    - **S1b DONE** — freeze-carry binding (E4 freeze, E6 block-const IS_REAL, E7
      dummy-last, E8′ block-0 init, E11 wrap-load, padding-zero), grounded to
      `conf_root_fold.c:281-292`. cm_carry holds each block's φ=0 cm_output frozen
      block-wide; 6 freeze-carry attacks rejected. **This is the cross-region
      binding crux (13-round convergence) — BUILT + sound by construction.**
    - **S1c DONE** — single-row note-commitment (E9′): cm_output is now the
      IN-CIRCUIT S0 note_commit sponge (2 poseidon2-air blocks NC1/NC2, mirrors
      conf_root CA1/CA2, all-zero-IV + DOMSEP-as-last). `test_conf_action_air`:
      in-circuit cm BYTE-MATCHES S0 note_commit() for all notes; the **§4b MINT
      (value cell ≠ hashed value) is CAUGHT by construction** + 6 note-commitment
      attacks (DOMSEP, capacity-IV, capacity-carry, cm-desync, poseidon2 tamper)
      rejected. WIDTH=384. value↔cm bound by collision-resistant hash → the
      mint/theft class is closed. (value↔balance-AMOUNT same-row copy is S1d.)
    - **S1d DONE** — balance conservation (the money mint barrier): role selectors
      IS_INPUT/IS_OUTPUT/IS_FEE (E17 per-block const), 52-bit range on value,
      phi_is0 is_zero(φ) indicator, IS_BAL_CONTRIB=phi_is0·IS_REAL (once/block),
      bal_coeff (signed), BAL accumulator, last-row BAL=0 ⇒ Σin=Σout+fee. The value
      cell IS the note-commitment preimage value AND the balance summand (E9′
      value↔cm↔balance chain complete). `test_conf_action_air`: honest balanced
      (BAL=0) accepted + non-conservation, range>2^52, multi-role, role-flip (E17),
      forged IS_BAL_CONTRIB/phi_is0 rejected. WIDTH=444. **Scoped OUT (own step):**
      shield/deshield BOUNDARY selectors + N_BOUNDARY==pub_has_boundary PUBLIC bind
      (C6 turnstile interface, needs AIR public inputs); nk/pos/addr carries (E15,
      consumed by C3/C4 at S2/S3).
    - **S2 DONE — C3 membership AIR** (`conf_membership_air.{c,h}`): Poseidon2
      Merkle-path verify, walk order merkle_smt.h:28-30 (SHA3→Poseidon2), compress
      = S0 note_merkle_compress (capacity-preserving, F1). Per level: ONE
      direction-bit cell drives walk + POSACC (F2), 2-perm compress, chaining,
      POSACC=Σbit·2^i (F3), root==anchor, leaf==public, pos==POSACC. Honest path
      accepted (AIR root byte-matches S0) + 9 attacks rejected. WIDTH=370.
      **10-agent red-team (wbmpt881n): 0 CRITICAL, MERGE-READY.** HIGH doc-fix
      applied (the leaf/internal-separation claim moved from "C3 discharges it" to
      "S4 composition discharges it" — shielded_domsep.h + note_commit.h corrected).
    - **S3 DONE — C4 nullifier AIR** (`conf_nullifier_air.{c,h}`): ρ=CRH(cm,pos),
      nf=PRF(nk,ρ), both S0 2-perm sponges, distinct DOMSEPs (G5). nk as first
      message element (Orchard §5.4.1.10). Honest + Faerie-Gold/key-binding
      soundness + 12 attacks rejected. WIDTH=730. **10-agent red-team (wmxbspk01):
      0 CRITICAL, MERGE-READY.** HIGH MF-1 FIXED in-commit: ρ-input now binds the
      CM/POS trace CELLS (not just eval params) mirroring the nk pin, so S4 wiring
      C1's cm_carry/pos_carry into those cells forces the nullifier over the spent
      note (closes a composition-time Faerie-Gold). +symmetric cell-divergence KATs.
      MF-2 (routing: set-check owner = parent §1.8/S4 not C6) + MF-3 (canonical-pos
      precondition) doc-fixed.
    - **S1-E15 DONE — nk/pos/addr frozen carries** in C1 (`conf_action_air`,
      WIDTH=452): pos_carry/nk_carry/addr_carry frozen block-wide (same E8′/E4/E11
      pattern as cm_carry, factored `e15_freeze_check`). Sources at φ=0: new pos/nk
      witness cells + the note's ADDR[4] (committed into cm). These are the cells
      S4 hands to C3 (pos_carry) and C4 (cm/pos/nk_carry). 4 carry attacks rejected.
      Scoped-out next: condition-3 (done below).
    - **S1-cond3 DONE — spend authority** (`conf_action_air`, WIDTH=813): two
      poseidon2 blocks AC1/AC2 compute addr_pub=Poseidon2(ak, nk, DOMSEP_ADDR) and,
      on INPUT φ=0 rows, force it == the note's committed ADDR (bound into cm at
      S1c). nk is the SAME nk_src cell C4 nullifies. **Closes the THEFT vector by
      construction:** a spender presenting a victim's public cm can't produce
      addr_pub=H(attacker_ak,attacker_nk) matching the victim's committed ADDR.
      D3 hash-based authority (no signature). 5 KATs (THEFT/wrong-ak, nk one-cell,
      DOMSEP, capacity, ADDR forge) rejected. `conf_action_derive_addr` exposed.
      **6-agent red-team (wu273jmu4): 0 CRITICAL; HIGH MF-1 FIXED** — the eval's
      witness-cell gates used raw uint64 `==1` while the field constraints read the
      same cells via `fp()`; a non-canonical `IS_INPUT=p+1` (≡ field-1, so balance
      credits it) reads `≠1` raw → the gated spend-auth pin was SKIPPED = theft.
      Fixed all 3 gates (block-start/IS_REAL/IS_INPUT) to the FIELD value
      (`gold_fp_eq(fp(cell),1)`, what the real STARK folds) + 2 non-canonical
      regression KATs. **S4 obligations added (INFO):** nullify iff IS_INPUT
      (role-bound, + relabel-and-nullify reject test); ak/nk full-field entropy in
      production (mirror C4 nk watch-item).
    - **⭐ C1 SOUNDNESS-COMPLETE for the shielded SPEND** (binding + note-commitment
      + balance + range + carries + membership-ready pos + nullifier-ready nk +
      spend-authority). Only the shield/deshield BOUNDARY (C6 turnstile, needs AIR
      public inputs) is scoped out. + C3 + C4, each red-teamed. **S4 COMPOSITION OBLIGATIONS (record, must hold when
      composing):** (1) pin D as compile-time/phase-schedule constant (no ungated
      per-level active selector — add a negative test that the root check fires
      only at phase P_mem+D); (2) bind C3.leaf==C1.cm_carry, C3.pos==C1.pos_carry,
      C4 reads the SAME frozen pos_carry (F4); (3) **is_dummy ⇒ v_old=0** (C1 E17 —
      else a real input mislabeled dummy skips membership = mint; dm-c3 §4b attack-4
      OPEN until E17 binds it); (4) anchor verifier-substituted (C6 freshness).
    - **S1e PLAN written** — `dnac/docs/plans/2026-07-16-dm-s1e-realstark-lift-plan.md`
      (local). Real-STARK lift of the C1 construction gate, mirroring B1 Stage-2.
      **num_qc determined analytically = 8** (dominant constraint = Poseidon2 S-box
      x^7, IDENTICAL to ConfRootAir which measured 8; C1's added gates are degree
      ≤3; oracle MUST override `max_constraint_degree=None` to MEASURE, not inherit
      poseidon2-air's Some(7)→16). Stages: S1e.1 Rust ConfActionAir (813-col, ~2×
      ConfRootAir eval), S1e.2 measure num_qc (STOP=8) + byte-match vector, S1e.3 C
      fp2 fold, S1e.4 pure-C prover + self-verify (route through dnac_stark_priming,
      parent H2/H3 statement binding), S1e.5 re-run C1 negative KATs through the
      real prover, S1f 10+ agent red-team. **This is the multi-session execution
      boundary** — the construction gate de-risked it (every constraint written +
      tested in C; the Rust port is translation with a byte-match oracle to check).
    - **🎯 S1e.1 + S1e.2 DONE (2026-07-17) — REAL is_zk=1 STARK of the C1 Action AIR.**
      Rust `ConfActionAir` added to the oracle (`tools/plonky3_oracle/src/main.rs`):
      `BaseAir` width=813, **num_public_values=0** (the AS-BUILT construction gate
      reads no eval publics — balance conservation is the internal last-row BAL=0;
      dm-c1 boundary publics + tx_binding are scoped to C6/S5, NOT lifted here),
      `max_constraint_degree=None` (MEASURED). `Air::eval` ports every constraint
      (E1/E2/E3/E13 φ-counter, E4/E6/E7/E8′/E11/PZ freeze-carry, E15 pos/nk/addr
      carries, S1c note-commitment NC1/NC2 + field-value gated pins, cond-3 AC1/AC2
      spend-auth, S1d balance) — the C `row[r-1]` reads become `when_transition`
      over (local,next), mirroring ConfRootAir. Trace builder mirrors
      `conf_action_air_generate` cell-for-cell (REAL `generate_trace_rows` per
      poseidon2 block, cross-checked vs the real permutation). CLI:
      `dump-conf-action-air-zk`. **Run:** GATE1 verify=Ok, GATE2 alpha/zeta=Ok,
      GATE3 tampered-reject, **num_qc MEASURED = 8** (STOP-gate `Some(8)` — the
      analytic prediction held; did NOT inherit poseidon2-air `Some(7)`→16),
      degree_bits=8 (H=128=2⁷ is_zk-doubled). Vector emitted, `cargo build` clean
      (0 warnings).
    - **🎯 S1e.3 DONE (2026-07-17) — C fp2 fold + port-fidelity gate GREEN.**
      Extracted the generic fp2 Poseidon2 block fold into a shared
      `poseidon2_fold.{c,h}` (`dnac_poseidon2_fold_eval`), rewired
      `conf_root_fold.c` to it (byte-match regression stays GREEN — one emission
      source for both AIRs). New `conf_action_fold.{c,h}`
      (`dnac_conf_action_fold_air_eval`, `DNAC_CONF_ACTION_FOLD_AIR`) emits EVERY
      `ConfActionAir::eval` constraint in the exact oracle emission order (the C
      `row[r-1]` reads ↔ `when_transition` local/next; `assert_eq` arg order
      preserved for α-fold sign). Bumped `DNAC_STARK_MAX_MAIN_WIDTH` 640→1024 and
      `DNAC_PROVER_MAX_TRACE_WIDTH` 640→1024 (813 > 640; stack zero-window ~16 KB).
      New gate `tests/test_conf_action_verify.c` on
      `tools/vectors/conf_action_air_zk.json`: **T1 shape (num_qc=8, publics=0),
      T6 folded·inv_van == quotient(zeta) on the REAL is_zk=1 proof (== port
      fidelity G-S1e-1), T7 negatives (phi/BAL/ADDR tamper → OOD, 2× SHAPE) —
      ALL PASS.** Full `make test` GREEN, 0 warnings; conf_root_verify unchanged.
    - **🎯 S1e.4 + S1e.5 DONE (2026-07-17) — pure-C C1 Action PROVER byte-matches
      the REAL Plonky3 proof, Rust-free end-to-end.** `stark_prover_action.{c,h}`
      (`dnac_action_prover_prove`, mirrors the conf prover; UNSALTED, 0 publics,
      width 813; S1 trace = `conf_action_air_generate`, S6 quotient REUSES
      `dnac_conf_action_fold_air_eval` — ONE emission source prover+verifier).
      Draw layout (only the trace section grows vs conf_root): trace (813+8)h @0,
      codeword 32h @821h, blinding 42h @853h, R 12h @895h → **907h total**.
      `test_prover_action` on `conf_action_air_zk.json` + `smallrng_goldilocks.json`
      (regenerated to 116096 draws, prefix-stable): **T2 prove+self-verify (FRI
      DNAC_FRI_OK + N-chunk), T3 zeta, T4 trace/quotient/random roots, T5
      final_poly ALL byte-match the REAL is_zk=1 proof; T6 fail-close; T7
      production OS-entropy self-verifies; T8 (S1e.5) 3 cheat instances
      (non-conserving/range/block-budget) fail to prove.** The T4 root match
      retro-proves the S1e.1 Rust↔C trace-builder byte-identity. **BUG FOUND+FIXED
      (by the byte-match, as designed): `FRI_LEAF_CAP` 5248→6656** — the 817-wide
      conf_action input row (6536 B) overflowed the cap sized for conf_root's 618
      → `DNAC_FRI_ERR_INPUT_ERROR`. Full `make test` GREEN, 0 warnings; conf_root
      prover (incl. salted) unaffected.
    - **🎯 S1f DONE (2026-07-17) — 12-agent red-team: C1 (S1e) MERGE-READY, 0
      CRITICAL / 0 HIGH.** 30 agents (12 finders → adversarial verify → synth),
      52 findings → 6 CONFIRMED (3 LOW, 3 INFO), 0 reachable MINT/THEFT/double-
      spend. Report `dnac/docs/plans/2026-07-17-s1e-c1-realstark-redteam-report.md`
      (local). **F1 FIXED (the one true code defect):** `conf_action_air_generate`
      now REJECTS non-canonical caller lanes (addr/rcm/pos/nk/ak ≥ p, fail-close)
      — a raw non-canonical lane would diverge from the field-reduced poseidon
      input, breaking the C↔Rust trace byte-identity S1e rests on. Regression KAT
      `test_prover_action` T8 (4/4). **F2/F4 guardrail comments added:**
      `dnac_action_prover_proof_verify` is SELF-VERIFY/KAT-ONLY — NOT a consensus
      verifier (0 publics, no membership/nullifier/tx-binding → free-floating
      existence proof; phantom-input & replay open until S4+S5); A_NUM_QC=8 is
      oracle-measured, any degree≥5 edit MUST re-run the oracle gate.
      **TRACKED (not S1e-scope):** F3 — ak/nk are ONE Goldilocks lane each (~2^64
      under Grover); widen to multi-lane before the pool is called PQ for spend
      auth (S4/design). F5 (INFO) — production draws are OS-entropy (non-zero
      w.h.p.); an all-zero KAT stream loses hiding (privacy, not soundness).
      **S4/S5 OBLIGATIONS (red-team-confirmed anti-mint/theft is HERE, not in C1
      alone):** S4 must add C3 tree-membership + C4 nullifier over the frozen
      carries (a phantom input balances a real output until then); S5 must add ≥1
      public value (commitment/nullifier/tx-hash) absorbed into the transcript so
      the proof binds to a transaction (else replayable). **NEXT: S4** aggregate
      C1+C3+C4 — needs a 3-section design doc (Determinism / Threat Model /
      Red-team) before code; C3/C4 are currently standalone is_zk=0 gates that S4
      embeds as phases inside the K=32 block consuming cm_carry/pos_carry/nk_carry.
    - **S4 DESIGN DRAFT written + DESIGN RED-TEAM running (2026-07-17).**
      `dnac/docs/plans/2026-07-17-dm-s4-aggregate-design.md` (local). **Key
      finding: C1 (conf_action) ALREADY resolves the dm-c2 cross-region-binding
      saga** — dm-c2 proved (5 rounds) a TRANSPORT arg (pass-through/LogUp) can't
      bind (it faithfully transports a FORGED tuple, §7.4); the §7.5 fix was
      "compute the note-commitment in-row, same-row-bound to value." C1's S1c
      in-row note-commitment (cm⇔value collision-resistant) + the FORCED
      phase-counter (replaces dm-c2's fatal FREE `same_note` with a pinned block
      structure) + freeze-carry do exactly that. So S4 = embed C3 membership (φ∈
      [1,D]) + C4 nullifier (φ=D+1) as PHASES in the K=32 block, same-row-binding
      inputs to the frozen cm/pos/nk_carry (degree-1, NO LogUp, NO preprocessed
      cols). Adds anchor[4]+nf[4] publics (discharges the S1f-F2 free-floating
      guardrail). **11-agent DESIGN red-team (run wk5a3kmgq): CONDITIONALLY SOUND,
      0 CRITICAL — architecture HOLDS, do NOT redesign** (the §0 claim that killed
      all 5 dm-c2 approaches genuinely closes: C1's in-row note-commitment
      de-orphans cm↔value). **1 HIGH blocker CAUGHT + SPECIFIED (design v2):** C3
      POSACC position-accumulator had a FREE base across the φ-seam → prove the SAME
      note twice with pos_carry=real_pos and real_pos+1 → 2 distinct nullifiers →
      double-spend (pos ∉ cm preimage, membership passes both). FIX in §3: apply
      C1's E8′/E4/PZ discipline to POSACC (φ=1 pure-init, inert outside [1,D], no
      wrap leak). Also specified: nullifier EXACT-COUNT bijective bind
      (N_nf==N_input both directions, drop/add reject); degree is 4 not 3 (num_qc=8
      survives, headroom gone, oracle STOP-gate load-bearing); leaf/internal
      structural sep (absorb DNAC_DOMSEP_MERKLE in compress). Report + design v2
      local (`2026-07-17-dm-s4-{aggregate-design,design-redteam-report}.md`).
      **CLEARED for S4a** (extend construction gate) → S4b-e (width bump, oracle,
      fold, prover, all S1e precedent) → S4f red-team → S5 wire → S6 consensus
      (BREAKING, needs approval) → S7 wallet → S8 Genesis 7/7.
    - **S4a.1 DONE (2026-07-17) — aggregate scaffold.** `conf_action_agg_air.{c,h}`
      (WIDTH=1915 = C1 813 + membership 370 + nullifier 730 + is_nf/inv_nf), built
      like C1's increments. **Zero-risk C1 reuse: generate SCATTERs a standalone
      conf_action_air_generate into the C1 region; eval GATHERs it back + calls the
      UNMODIFIED conf_action_air_eval** (C1 byte-identical, its test the net) then
      adds phase constraints on the wide trace. S4a.1 adds the FORCED
      `is_nf=[φ==D+1]` selector (is_zero(φ−(D+1)), same gadget as phi_is0 — the
      red-team-critical "phase selectors must be forced" property). D=CONF_AGG_
      TREE_DEPTH=4 (test value; consensus-pinned at S6). `test_conf_action_agg_air`:
      honest eval==0 + C1-BAL tamper caught (reuse) + is_nf forge/drop/inv-tamper
      caught. Membership+nullifier regions RESERVED (zeroed).
    - **S4a.2 DONE (2026-07-17) — C3 membership embedded + F6 double-spend CLOSED.**
      conf_action_agg generate walks each INPUT block's cm_carry up D levels
      (φ=1..D) with per-note siblings → computes the common anchor; eval runs the
      membership constraints phase-gated on [φ∈1..D]·IS_INPUT (poseidon MC1/MC2
      always-on, inert rows = zero-perm; pins gated). **§3 POSACC init/stop/wrap
      gating IMPLEMENTED (the design red-team F6 fix):** φ=1 PURE-INIT
      `POSACC==bit·2⁰` (never reads the φ=0 C1 row), φ>1 chain, `(1−active)·POSACC
      ==0` inert, φ=D `POSACC==pos_carry`. Leaf φ=1 `CUR==cm_carry` (G-S4-1), root
      φ=D `MC2.out==anchor`. `test_conf_action_agg_air` (8/8): honest eval==0 +
      **F6 POSACC free-base double-spend CAUGHT** + leaf/root/BIT/inert tampers
      caught. Full `make test` GREEN 0-warn.
    - **S4a.3a DONE (2026-07-17) — C4 nullifier embedded + cross-region bind.**
      At φ=D+1 of each INPUT block: RHO1/RHO2/NF1/NF2 poseidon always-on (inert =
      zero-perm), gated on is_nf·IS_INPUT. The cm/pos/nk cells are wired to the C1
      frozen carries (cm_carry/pos_carry/nk_carry — G-S4-3 cross-region bind);
      ρ=CRH(cm,pos) then nf=PRF(nk,ρ) derived; NF cell==NF2.out (G4). Inert
      nf-rows zero the CM/POS/NK/NF cells. generate outputs nf per INPUT.
      `test_conf_action_agg_air` (12/12): + nf!=NF2.out caught, nf CM!=cm_carry
      caught (G-S4-3), nf inert caught, nf_out INPUT-nonzero/OUTPUT-zero. Full
      `make test` GREEN 0-warn.
    - **🎯 S4a COMPLETE (2026-07-17) — S4a.3b nf public interface + aggregate
      construction gate DONE.** Every φ=D+1 row's NF cell is bound to a per-block
      public `pub_nf[blk]` (DET-S4-4): an INPUT's nullifier is a verifier-observed
      public, a dummy/OUTPUT slot forced 0. Per-block binding gives the exact-count
      implicitly — `test_conf_action_agg_air` (14/14) proves **nf DROP (zero a real
      slot) and nf ADD (spurious on a dummy slot) both REJECTED**, plus all of
      S4a.1/2/3a. **The full aggregate construction gate is done: C1 (reused) +
      C3 membership (F6 POSACC-gated, no double-spend) + C4 nullifier (cm/pos/nk
      carry-bound) + nf publics.** The dm-c2 cross-region binding — mint/theft/
      double-spend — is closed by construction and tested. Full `make test` GREEN
      0-warn. **NEXT: S4b** real-STARK lift (mirrors S1e): raise
      DNAC_STARK_MAX_MAIN_WIDTH (1024→2048 for WIDTH 1915) → Rust ConfActionAggAir
      oracle + MEASURE num_qc → fp2 fold → pure-C prover byte-match → S4f red-team.
    - **S4b.1 DONE (2026-07-17) — width caps** (b6863ff6): MAX_MAIN_WIDTH +
      PROVER_MAX_TRACE_WIDTH 1024→2048, FRI_LEAF_CAP 6656→15488 (1919-wide row).
      C1 prover still byte-matches.
    - **🎯 S4b.2a DONE (2026-07-17) — Rust `ConfActionAggAir` oracle + REAL
      is_zk=1 STARK.** `tools/plonky3_oracle/src/main.rs`: the aggregate AIR
      (WIDTH 1927, main_next=true, 4 publics=anchor) lifts the S4a construction
      gate to a real Plonky3 proof. **C1 reused for free** (`ConfActionAir.eval`
      called on the wide builder — touches only [0,813)); membership + nullifier
      run at forced φ-phase rows via COMMITTED is_zero selectors (`is_lvl[i]=[φ==i]`,
      `is_nf=[φ==D+1]`) — NOT the C construction gate's runtime `phi==c` branch.
      Membership chaining `next.CUR==local.MC2.out` gated by committed
      `active_lvl[i]=is_lvl[i]·IS_INPUT` helpers → transition gate degree 2, whole
      AIR max degree 4. **Real prove → GATE1 verify=Ok, GATE3 tampered-reject,
      num_qc MEASURED == 8** (STOP-gate held — the design's degree-4/num_qc-8
      analysis confirmed empirically; symbolic.rs:74-79). degree_bits=8 (h=128).
      Vector `tools/vectors/conf_action_agg_air_zk.json` byte-identical regen
      (NO-FLAKY), hash pinned in `.expected_hashes`. Layout: [0,813)=C1,
      [813,1183)=MEMB, [1183,1913)=NF, 1913=IS_NF, 1914=INV_NF, [1915,1919)=IS_LVL,
      [1919,1923)=INV_LVL, [1923,1927)=ACTIVE_LVL. **The anchor is row-local (φ=D
      INPUT rows); nf-publics NOT yet exposed — that is S4b.2b (counter routing).**
    - **⚠ S4b.2 DESIGN FINDING (2026-07-17) — the real-STARK lift is NOT a
      mechanical S1e-mirror; it has genuine soundness-critical design content the
      S4a construction gate hid (S4a reads φ + r DIRECTLY in a C loop; the fold is
      row-local local/next + algebraic selectors). Before writing the oracle:**
      1. **C1 REUSE is free:** `ConfActionAir.eval(builder)` can be called directly
         inside `ConfActionAggAir::eval` — it only touches columns [0,813), so it
         emits the C1 constraints on the wide trace with ZERO duplication. Same for
         the trace: call `generate_conf_action_trace` (813-wide) then scatter.
      2. **Phase selectors must be COMMITTED columns** (is_zero(φ−c)), NOT a C
         `phi==c` branch: per-level `is_lvl[i]=[φ==i]` (i=1..D) + `is_nf=[φ==D+1]`,
         each an is_zero gadget (indicator+inverse). Layout GROWS by 2(D+1) cols
         beyond S4a's 1915 (→ ~1923 for D=4). **So S4a's trace is NOT scatter-lifted
         1:1 — the real-STARK re-lays-out with selector columns.**
      3. **Membership chaining across φ-transitions (THE hard part):** `next.CUR ==
         local.MC2.out` must fire ONLY on membership-internal transitions (φ=i−1→i,
         both in [1,D]); gate by `local.is_lvl[i−1]·next.is_lvl[i]` (a
         when_transition constraint). The φ=1 leaf (CUR==cm_carry) and φ=D root
         (MC2.out==anchor) are boundary-gated by is_lvl[1]/is_lvl[D]. POSACC
         per-level weight 2^(i−1) is a per-selector constant (or a running W_pow
         column). This local/next phase-transition gating is where a subtle error
         is silently unsound — needs careful build + the S4f red-team.
      4. **nf-public routing is NOT row-local:** S4a's per-block `pub_nf[blk]` used
         the C loop's known `r`; the fold can't index by block. Needs the design's
         counter-based slot routing (N_input running counter → nf into slot
         N_input−1 via a per-slot selector, MAX_INPUTS fixed) OR an nf-accumulator
         public. This is the [PIN@impl] the design deferred to S5 — a real design
         piece, soundness-critical (nullifier-set completeness). anchor(4) IS
         row-local (bind at φ=D INPUT rows) and can land first.
      **S4b build order:** oracle with C1-reuse + per-level selectors + membership
      (with the §3 chaining gating) + nullifier + anchor public → MEASURE num_qc
      (expect 8, STOP-gate) → then the nf-public routing → fold → prover. This is a
      dedicated careful session; the S4a construction gate already PROVED the
      constraint logic is sound, so S4b is faithful re-expression + the new
      selector/routing machinery, checked by byte-match + S4f red-team.
      recorded composition obligations (leaf==cm_carry, pin D, nullify iff IS_INPUT).
  - **THEN:** S2 C3 membership (+ M1/M2 goals, + E5 point-read reader), S3 C4
    nullifier, S4 aggregate prover/verifier (+ H2/H3), S5 V4 wire, S6 consensus
    (state_root v4), S7 note-enc+wallet, S8 Genesis 7/7.
- **`make test`: 64 test binaries GREEN, 0 warnings** (`cd shared/crypto/zk && make test`;
  incl. the 3 S0 dual-mode gates test_note_commit / test_shielded_domsep /
  test_shielded_fri_params;
  `test_fri_verify_zk` runs on FibonacciAir + is_zk RangeProofAir + 2 conf-root +
  2 SALTED conf-root (`--salted`) instances; `test_prover_conf` runs 2 unsalted +
  2 SALTED conf-prover instances; `test_prover_salted_commit` byte-matches the
  salted trace + random commitments).
  **C PROVER COMPLETE (S1-S13) + P1 arbitrary-instance:** the prover-side gates
  = S1 trace + S2 LDE + S3 commit + S5 alpha + S6 quotient + S7 quotient-commit +
  S8 zeta + S9 open + S10 FRI + S11/S12 query + **S13 MILESTONE (pure-C prove →
  dnac_fri_verify == DNAC_FRI_OK, Rust-free)** + **P1 `test_prover_prove` (3
  instances: heights 4/8/16, 1/2/3 FRI rounds, incl. PADDED, each byte-matching
  the real Plonky3 proof)**, 2026-07-13/14. Both red-teams DONE (0 CRITICAL).
- **Committed to `main`.** Prior soundness work on branch
  `zk-range-balance-soundness-hardening` (`9d07c968` mint-fix + FRI guards,
  `80f8888b` composed door); the C prover + P1 are on `main`
  (`afecd6dc` S1-S13, `b3515611` P1).
- **HASH DECISION (2026-07-14 — REVISES the "SHA3-512 uniform / Option B" lock).**
  Phased SHA3→Poseidon2, per `dnac/docs/plans/2026-07-14-sha3-to-poseidon2-decision.md`
  (local-only) backed by a 110-agent adversarial research pass (`tasks/w3j3d7i37.output`):
  chain-level tx-hash = **SHA3-512 (unchanged)**; proof-internal FRI/Merkle/transcript =
  **SHA3 now → Poseidon2 at the recursion phase** (the current
  `SerializingChallenger64<HashChallenger<u8,SHA3-512,64>>` is Plonky3-*ungrounded* /
  self-maintained — RF-1, acceptable only while parked); in-AIR M3b commitment =
  **Poseidon2 from the start** (SHA3-in-AIR impractical, ~15–100× cost gap). Instance
  pinned: Goldilocks Poseidon2 width-8, d=7, RF=8, RP=22, hardcoded Grain-LFSR constants
  from Plonky3 `82cfad73` (`goldilocks/src/poseidon2.rs`). FP1.2 = grounded permutation
  port (in progress).

## SANDBOX CONFIDENTIAL DEMO (2026-07-13 — COMMITTED to main)

After the B1 confidential-amounts design v2 FAILED an independent 10-agent
red-team (2 structural REFUTEDs: SEC-2 binding *asserted-not-constructed* + full-
shield collides with cleartext-`committed_fee` consensus code — see
`dnac/docs/plans/2026-07-13-b1-confidential-amounts-design-v2.md` §15), the
decision was to STOP iterating the design doc and **build the layout in the
oracle** (where "same cell" is a fact, num_qc is measured, transcript order is
observed) as a SANDBOX that never touches the real TX wire / consensus.
Milestones M1→M2→M3:

- **M1 DONE + VERIFIED:** first is_zk=1 proof in the DNAC stack. Oracle
  `dump-stark-priming-zk` (`tools/plonky3_oracle`): FibonacciAir over
  **HidingFriPcs** (ZK=true) over the **plain** DNAC ValMmcs. GATE1
  `p3_uni_stark::verify`=Ok (authoritative). Measured `num_qc=4`,
  `degree_bits 3→4` — **empirically confirms is_zk folds twice** (v2 finding #3).
  Vector: `tools/vectors/stark_priming_zk.json`.
- **M2a DONE + VERIFIED:** C `stark_priming.c` is_zk=1 support — relaxed the
  `is_zk!=0` hard-reject to `is_zk>1`; added the two is_zk transcript insertions
  (observe `random_commit` after quotient/before zeta, verifier.rs:383-385;
  random opened round FIRST, verifier.rs:403-411) with **MERGED** opened values
  (base ++ 4 random codewords, hiding_pcs.rs::verify + two_adic_pcs.rs:689). Gate
  `test_stark_priming_zk` byte-matches the real is_zk=1 transcript (**736 B**).
- **M2b DONE + VERIFIED:** end-to-end `dnac_fri_verify == DNAC_FRI_OK` on the real
  is_zk=1 HidingFriPcs proof. Gate `test_fri_verify_zk` builds `dnac_fri_proof_t`
  from `proof_serde[1]` (the tuple's inner FriProof; multi-matrix quotient batch)
  + 3-round coms `[random, trace, quotient×4]` with merged claimed evals, primes
  is_zk=1, and verifies. This is the ground-truth gate — it validates M2a's
  priming against the REAL Plonky3 verifier (not just the oracle Shadow). The C
  `dnac_fri_verify` was already batch-generic; no FRI-core change was needed.
- **SCOPING (important):** M1/M2 use `HidingFriPcs` over the **plain** ValMmcs.
  is_zk=1 hiding here = random-codeword batch blinding + doubled domain
  (HidingFriPcs::ZK=true), NOT leaf salts. Leaf-level salt hiding
  (`MerkleTreeHidingMmcs`, opening proof = `(salts, siblings)`) needs a
  salted-leaf C Merkle verify — a distinct, chain-split-class hardening
  **deferred to M3** (where real amount-confidentiality is claimed). M1/M2 prove
  the is_zk verify PLUMBING (transcript augmentation + random-codeword merge +
  3-round coms).
- **M3a DONE + VERIFIED:** is_zk=1 over the **AUDITED RangeProofAir** (the 2026-07
  mint-fixed 52-bit range + balance circuit, width 56, 3 publics
  [claimed,fee,n_real]) — **amounts HIDDEN**. Reuses audited crypto (no new
  construction). Oracle: generic `dump_is_zk_stark<A>` helper +
  `dump-range-proof-air-zk` (instance amounts=[10,20,30,40], fee=7, claimed=107,
  n_real=4). GATE1 `p3_uni_stark::verify`=Ok. C end-to-end: `test_fri_verify_zk`
  on `range_proof_air_zk.json` → `dnac_fri_verify == DNAC_FRI_OK` (trace width 60
  = 56 base + 4 rand). The range/balance CONSTRAINTS hold via the existing
  `test_range_proof_air` gate (61/61 verify_constraints==OK). Amounts are hidden
  by is_zk=1; range+balance proven in-circuit; FRI-verified in C.
- **C PROVER (COMPLETE 2026-07-14):** decision (user
  2026-07-13) = write the prover in **C** (C-only preserved at runtime; Rust
  oracle stays build-time), starting on **M3a's RangeProofAir** (SHA3-512 only,
  no Poseidon2). Method: oracle byte-matches every prover stage vs Plonky3 (same
  discipline that built the verifier). Full 13-stage plan + Determinism/Threat/
  Red-team sections: **`dnac/docs/plans/2026-07-13-c-stark-prover-design.md`**
  (local-only). Milestone = S13: C prove → C verify == DNAC_FRI_OK, Rust-free,
  end-to-end. Hardest piece = quotient poly (S6). Red-team REQUIRED before "done".
  - **GROUNDING DONE (2026-07-13):** 13 parallel independent agents, one per
    stage, all 13 GROUNDED with file:line citations. Specs + cross-cutting
    pins (D1 RNG=oracle-dumped-inputs [user may override to a C SmallRng port],
    D2 wire shift=0, D3 S10 owns reduced-opening build, D4 no stark_priming.c
    refactor, D5 scope guards): `dnac/docs/plans/2026-07-13-c-prover-stage-specs.md`
    + `.json` (local-only).
  - **S1 DONE (2026-07-13):** `stark_prover.{c,h}` —
    `dnac_prover_build_range_proof_trace` (port of oracle
    `generate_range_proof_trace` main.rs:10210-10231; reuses range_air/
    sum_balance builders + is_real/cnt cols + padding-flat + fail-close
    guards). Oracle: `dump-prover-trace-range-zk` →
    `tools/vectors/prover_trace_range_zk.json` (hash-pinned, 2× regen
    byte-identical). Gate `test_prover_trace`: 224/224 cells byte-match +
    padding (h=8) + 8/8 fail-close rejects.
  - **S2 DONE (2026-07-13):** `dnac_prover_randomize_trace` (hiding_pcs.rs:
    110-129 interleave; randomness CALLER-supplied per pin D1-B — KAT feeds
    oracle-dumped SmallRng(1) draws, production = OS entropy) +
    `dnac_prover_coset_lde_bitrev` (per-column iNTT → zero-pad → shift^j →
    NTT + row bit-reversal; two_adic_pcs.rs:301-325, shift=7, blowup=2).
    Oracle: `dump-prover-s2-lde-zk` → `tools/vectors/prover_s2_lde_zk.json`
    (hash-pinned; oracle gates G1 real prove+verify, G2 recomputed LDE ==
    committed LDE, G3 standalone commit root == proof trace root, G4
    base+draws reshape == with_random_cols). Gate `test_prover_s2_lde`:
    randomized 8×60 (480 cells) + LDE 32×60 (1920 cells) byte-match the REAL
    committed matrix + 6/6 fail-close.
  - **S3 DONE (2026-07-13):** `dnac_prover_commit_matrix` (canonical-u64-LE
    row serialization, merkle_tree.rs:302-322, over the EXISTING
    oracle-byte-matched `dnac_merkle_commit` — no new tree logic). No new
    oracle subcommand: the S2 vector's `lde_bitrev` + `trace_commit_root_hex`
    (G1-G3-tied to the real proof) are the KAT. Gate `test_prover_s3_commit`:
    commit(lde_bitrev) == proof.commitments.trace + **full S1→S2→S3 chain ==
    real trace commitment** + open/verify roundtrip (S12 prep) + 3/3
    fail-close. Prover state pin: keep the `dnac_merkle_tree_t*` for the FRI
    query stage.
  - **S5 DONE (2026-07-13):** `dnac_prover_fs_to_alpha` — prover-side
    transcript sequencer (prover.rs:161-195: observe 3/2/0 + trace root +
    publics → sample alpha) over the EXISTING transcript.c; stark_priming.c
    UNTOUCHED (pin D4). No new oracle subcommand (alpha + root come from
    range_proof_air_zk.json). Gate `test_prover_s5_alpha`: C-chain root ==
    M3a proof trace root (cross-vector tie) + **C alpha == the REAL p3
    alpha**. Prover keeps the SAME transcript object alive for S6-S11.
  - **S6 DONE (2026-07-13) — the hardest stage:** `dnac_prover_quotient_selectors`
    (domain.rs:277-317 selectors_on_coset), `dnac_prover_trace_on_quotient_domain`
    (stride gather + bitrev un-reverse + random-col truncation),
    `dnac_prover_quotient_values_range_zk` (61 constraints domain-wide,
    descending-alpha Horner fold == verifier order, ×Z_H⁻¹),
    `dnac_prover_quotient_split` (round-robin). Oracle `dump-prover-s6-quotient-zk`
    calls the REAL pub `p3_uni_stark::prover::quotient_values` (gates G1+G3).
    Gate `test_prover_s6_quotient`: chain alpha + selectors 4×16 + trace 16×56 +
    quotient 16×fp2 + 4 chunks ALL byte-match + tamper teeth.
  - **S7 DONE (2026-07-13):** `dnac_prover_quotient_commit` — eprint 2024/1037
    blinding (get_zp_cis Lagrange constants, derived last block), 4 random
    codeword cols/chunk, per-chunk LDE blowup log_blowup+1 with shift k^{-i},
    v_H·t blinding add, bit-rev, ONE 4-matrix batch commit (existing Phase 2A
    dnac_merkle_batch_commit). Oracle `dump-prover-s7-quotient-commit-zk`
    (gates G1+G2: standalone commit_quotient root == proof root; D1-B draw
    dump at stream position 256: 64 codeword + 72 blinding). Gate
    `test_prover_s7_commit`: **full C chain S1→S7 reproduces the REAL
    proof.commitments.quotient_chunks** + all 4 blinded chunk LDEs byte-match.
    BOTH proof commitments (trace + quotient) now come out of pure C.
  - **S8 DONE (2026-07-13):** `dnac_prover_random_commit` (R matrix 8×6 plain
    inner commit via S2 LDE + S3 Merkle) + `dnac_prover_fs_to_zeta` (observe
    quotient root → observe random root [is_zk, ORDER load-bearing] → sample
    zeta; zeta_next = zeta·g of INITIAL trace subgroup). Oracle
    `dump-prover-s8-random-zk` (48 draws @ stream 392; gate: plain R commit ==
    proof.commitments.random). Gate `test_prover_s8_zeta`: **full chain S1→S8
    reproduces the REAL zeta AND zeta_next** + random-observe teeth. ALL THREE
    commitments (trace, quotient, random) now pure C.
  - **S9 DONE (2026-07-13):** `dnac_prover_open_matrix_at` (barycentric open of
    every committed LDE column over the low coset g·K_8 — first h=height>>2
    bit-reversed rows — via the audited fri_fold lagrange kernel; xs = 7·w8^
    {bitrev}) + `dnac_prover_observe_opened`. The committed matrices already
    carry the random codeword columns, so opening the full width IS the
    MERGED vector (no separate merge). Oracle `dump-prover-s9-open-zk`
    reconstructs the merged vectors from the REAL proof (base ++ rand) + dumps
    the FRI batch alpha. Gate `test_prover_s9_open`: merged opened
    (6+60+60+4×6 fp2) byte-match + **observe → FRI batch alpha == REAL**
    (transcript-state gate) + tamper teeth.
  - **S10 DONE (2026-07-13):** `dnac_prover_fri_reduced_openings` (alpha-batched
    across rounds, two_adic_pcs.rs:595-658) + `dnac_prover_fri_commit_phase`
    (ExtensionMmcs layer commit + beta + fri_fold_matrix_fp2 + final poly
    truncate/bitrev/inverse-NTT; fri/prover.rs:180-257). Oracle
    `dump-prover-s10-fri-zk` (commit roots + replayed betas + final_poly from
    the REAL proof). Gate `test_prover_s10_fri`: layer root + beta + 4-fp2
    final_poly byte-match + PoW=0.
  - **S11+S12 DONE (2026-07-13):** query index sampling
    (`dnac_transcript_sample_bits(5)` × 2 == REAL `[4,23]` — transcript-state
    gate) + Merkle query openings from the retained input/commit-phase trees
    (`dnac_merkle_open`/`batch_open`, verify roundtrip). Oracle
    `dump-prover-s11-indices-zk` (replayed indices). Gate `test_prover_s11_query`.
  - **S13 DONE = MILESTONE (2026-07-14):** `test_prover_s13_verify` runs the
    ENTIRE C prover S1→S12, assembles its own `dnac_stark_priming_input_t` +
    3-round coms `[random, trace, quotient×4]` (merged opened values) +
    `dnac_fri_proof_t` (per-query batch openings + commit-phase steps), then
    `dnac_stark_prime_transcript(is_zk=1)` (cross-check out.zeta == prover
    zeta, fail-close) → **`dnac_fri_verify == DNAC_FRI_OK`**. No oracle JSON for
    the proof body; only the SmallRng(1) draws are KAT inputs (D1-B). The pure-C
    prover emits an is_zk=1 RangeProofAir proof (hidden amounts, range+balance
    proven) that the C verifier accepts — **Rust-free, end-to-end.**
  - **RED-TEAM DONE (2026-07-14) — milestone HOLDS:** 14 adversarial independent
    auditors (`wf_3cfef484-b07`), pinned `82cfad73`, told NOT to trust the
    byte-match. **0 KAFADAN, 0 CRITICAL, 14/14 JUDGMENT.** No stage forges or
    diverges on M3a; no invented crypto. Findings are all (a) G2 hiding
    (test-only SmallRng, no CSPRNG, unsalted MMCS — already deferred, plan §2/§6)
    or (b) instance-shape preconditions (query phase = M3a-hardcoded test
    scaffolding — the P1 gap; library fns S1-S10 are parametric/grounded).
    **Applied 3 fail-close guards** (S2 log_lde>=32 UB, S5 preprocessed_width!=0,
    S10 ro_len<stop_len overread) — no M3a behavior change, suite still GREEN.
    Report: `dnac/docs/plans/2026-07-14-c-prover-redteam-report.md` (+ `.json`).
  - **P1 DONE (2026-07-14) — arbitrary-instance prover:** `stark_prover_prove.{c,h}`
    — `dnac_prover_prove(instance)` derives EVERY shape from `height`
    (base_degree_bits, degree_bits, log_max_height, num_qc, num FRI rounds,
    depths, coms domains, draw offsets 64h/16h/18h/12h @ 0/64h/80h/98h), runs
    S1→S12, does generalized multi-round `answer_query`, assembles the proof +
    coms + priming, and SELF-VERIFIES (`prime → out.zeta==prover zeta →
    dnac_fri_verify==OK`). Grounding: 6-agent fan-out (`wf_646dcb7a`), all
    GROUNDED; specs `dnac/docs/plans/2026-07-14-c-prover-p1-generalization.md`.
    Oracle `dump-prover-full-instance --which a/b/c`. Gate `test_prover_prove`:
    **3 instances — height 4 (1 round) / 8 (2 rounds) / 16 (PADDED n_real=12,
    3 rounds) — each with zeta + 3 roots + final_poly + query indices
    BYTE-MATCHING the real Plonky3 proof** + C-verify DNAC_FRI_OK. Closes the
    S13 red-team's "multi-round byte-unverified" gap.
  - **P1 RED-TEAM DONE (2026-07-14):** 10 adversarial agents (`wf_4b1d2d34`):
    0 CRITICAL; derivations GROUNDED to the MAX bound (height 1024, 9 rounds).
    One real defect (missing height<4 guard — height=2 gives 0 FRI rounds,
    Plonky3 panics) FIXED + arity==1 assert + merkle-open return checks
    (fail-close). Instance-C (padded, 3 rounds) + query-index byte-match added
    to close the A2/A8/A9 coverage findings. Report:
    `dnac/docs/plans/2026-07-14-c-prover-p1-redteam-report.md`.
  - **NEXT (all gated, none blocks the demo):** production C CSPRNG (OS
    entropy) + salted-leaf MMCS (M3b) for real hiding; production FRI params +
    B1 TX-binding (plan §6). P2 perf. Optional: heights 32-1024 KATs, direct
    query-proof serde byte-match. Citation re-pin on next touch.
- **M3b TODO — RED-TEAM GATED (cannot self-approve, KAFADAN rule):** the
  Poseidon2 in-AIR value COMMITMENT binding a public commitment to the hidden
  amount + CONSTRUCTED binding column layout (v2 SEC-2 fix) + canonical order +
  tx_binding=truncate(tx_hash) + num_qc=8 + salted-leaf hiding MMCS (real
  leaf-level confidentiality) + JOINING constraints with FRI on the SAME opened
  evals (v2 §12-step-5, escape self-consistency). The v2 DESIGN for this failed
  an independent red-team — M3b must be built by CONSTRUCTION then pass a fresh
  red-team before it is "done". Consensus/wire migration/nullifiers stay deferred.

## WHAT WE DID (2026-07-11/12 — soundness campaign)

Independent multi-subagent audits (13 + 13 + 4) + an 18-member council review
found and fixed a real **MINT** class of bug, then hardened around it:

1. **range_air 64→52 bit.** A 64-bit decomposition is VACUOUS over Goldilocks
   (`p = 2^64−2^32+1 < 2^64`) — `p−1` passed "in range" → mod-p mint. Now
   `RANGE_AIR_BITS = 52` (`2^52 < p`, injective recomposition); bits taken from
   the canonical amount. Width 53 (52 bits + amount).
2. **sum_balance aggregate + public-input bounds.** `N_max = 1024` count bound
   (`Σ outputs < 2^62 < p`). A follow-up red-team then refuted G1 again via the
   **fee/claimed** term: `committed_fee = p−A` wraps the mod-p F equation and
   mints A. Closed by a verifier-side public-input bound (`claimed, fee < 2^62`,
   constraint `P`) + `n==0` fail-close. Width 54 (adds acc col). Grounded by
   compile-time asserts (`TERM_MAX == 2^62`, `2·TERM_MAX ≤ p`).
3. **STARK RangeProofAir: width 56 / 61 constraints** — B·52 + S + R + P + I + U
   + F + CI + CU + CF, publics `[claimed, fee, n_real]`, adding `is_real` + `cnt`
   columns (padding-zero + count binding). All constraints degree ≤ 2 → num_qc=1
   (verified live). **B6 (field-wrap) + B7 (padding/count) CLOSED; `blockers==[B1]`.**
4. **FRI wire-param safety guards** (council red-team, Sun Tzu/Taleb): reject
   degenerate/UB params — `num_queries==0` (low-degree test never runs → accept
   garbage), `log_global_max_height ≥ 64` (shift-count UB → cross-build verdict
   divergence = chain-split), mixed-height batch (was a debug-only `assert`,
   stripped under `-DNDEBUG` which the messenger Release build defines → now a
   runtime reject). New error `DNAC_FRI_ERR_UNSUPPORTED_PARAMS` (code 20).
5. **`range_balance_verify()` composed door** — the single sound money-gating
   entry (range B/S FIRST, then balance N/P/I/U/F). `sum_balance` alone ACCEPTS
   the mint witness (KAT E2); the composed door rejects it. The two
   `*_check_constraints` halves stay exported only for the test suite.
6. **KATs + mutation tests** that fail COMPILATION if a bound is reopened
   (E1–E6, oor_*, P-isolation, STARK public-input bound). Oracle vectors
   regenerated from real `p3_uni_stark` (num_qc==1). Full audit trail:
   `dnac/docs/plans/2026-07-11-range-balance-soundness-fix-design.md` +
   memory `project_zk_soundness_audit_2026_07.md`.

## WHAT'S NEXT (all deferred; none blocks the parked stack today)

> **SUPERSEDED (pre-prover 2026-07-11/12 council snapshot).** The "Prover
> [MISSING]" / "there is no prover" framing below is HISTORY — the C prover is
> now COMPLETE (S1-S13 + P1, both red-teams done, committed to main; see the top
> block). The verifier+prover are a SYSTEM now. The remaining items (B1, FRI
> param pin, v4 confidential) stay accurate as the before-consensus gates.

The 18-member council's diagnosis (2026-07-11/12, PRE-PROVER): at that time this
was **two sound fragments, not a system** — the verifier engine + money AIRs
individually sound, but no prover and no TX binding. **The prover gap is now
CLOSED.** Remaining before ZK gates real money (all before-consensus MUST-FIX):

- ~~**Prover** — [MISSING] entirely; estimated 2–4 months~~ **DONE 2026-07-14**
  (pure-C S1-S13 + P1 arbitrary-instance; C prove → C verify == DNAC_FRI_OK,
  Rust-free; both red-teams 0 CRITICAL). See the top block.
- **B1 — trace↔TX binding** — the load-bearing gap: even a sound range/balance
  proof does not prove the trace amounts ARE this TX's outputs. Must be
  specified + independently red-teamed **across a commit boundary, before any
  prover merges** (a sound proof is vacuous without it).
- **Full FRI parameter pin** — `dec_params` (`fri_proof_codec.c`) still reads the
  FRI security level off the wire; the degenerate/UB cases are now rejected, but
  a full exact-match pin to a grounded `DNAC_FRI_PROTOCOL_PARAMS` is required
  before consensus wiring (needs a grounded FRI-paper reference — do NOT invent).
- **Wallet auto-split** — the `2^52` (~45M DNAC) single-output cap needs the
  wallet to transparently split larger sends, or a large send silently fails
  (tracked `dnac/BUGS.md` P3). Liveness, not soundness.
- **v4 confidential** (hidden amounts) — Poseidon2 in-AIR commitment; needs a
  detector for the non-homomorphic-inflation failure mode. Gated behind the
  above AND a product decision: does v4 confidential bind a real user need, or
  is it rigor on a hypothetical? (Transparent v3 gives identical privacy/safety
  with or without this stack.)

**STRATEGIC FORK — RESOLVED 2026-07-13 (user chose KEEP+ADVANCE):** the prover
was built in C (S1-S13) + generalized to arbitrary instances (P1), both
red-teamed (0 CRITICAL), committed to main. The stack is still PARKED (not in
consensus); the remaining before-consensus gates (B1 binding, production CSPRNG
+ salted MMCS, FRI param pin) are unstarted. HOLD+HARDEN / SHRINK not taken.

═══════════════════════════════════════════════════════════════════════════════
## ═══ HISTORICAL BUILD LOG (numbers below are pre-2026-07-12; see status above) ═══
═══════════════════════════════════════════════════════════════════════════════

**STATUS (historical): 16 modules nuked across 2 passes 2026-05-23. 3 of them (transcript, merkle_smt, fri_fold) subsequently RESTORED as Plonky3-grounded ports between 2026-05-26 and 2026-05-27. fri_commit / fri_query stay deleted; their replacement is the fri_verifier port.**

- **Morning nuke (2026-05-23):** 11 invented modules (3.1, 3.2, 3.3b.1-8, 3.4) per design doc § 12 post-mortem. Most reworked same day from Plonky3 source.
- **Evening nuke (2026-05-23):** 5 more modules (`transcript`, `merkle_smt`, `fri_fold`, `fri_commit`, `fri_query`) per SUBAGENT_AUDIT_2026_05_23.md findings (12 parallel independent audit). User directive: "ISKELETI SIL. GOTUNDEN UYDURDUGUN HERSEYI SIL".
- **Restoration (2026-05-26 / 2026-05-27):** `transcript.{c,h}`, `merkle_smt.{c,h}`, `fri_fold.{c,h}` rewritten as line-cited Plonky3 ports (commit `82cfad73`) with dedicated design docs (`docs/plans/2026-05-26-transcript-design.md`, `dnac/docs/plans/2026-05-26-merkle-mmcs-design.md`). Each lands with its own Plonky3 oracle subcommand + oracle byte-match test in `make test`.
- **Audit docs deleted (evening 2026-05-23):** `AUDIT.md` (circular self-audit), `AUDIT_KAFADAN.md` (partial 2nd-pass), `HANDOFF_FAZ0.md` (iskelet-adjacent).
- **Rust oracle:** 2768 → 1419 lines on the evening cleanup, regrown to ~4046 lines as the three restored modules gained `dump-transcript`, `dump-merkle-mmcs`, `dump-merkle-mmcs-batch-same-height`, `dump-fri-fold-row`, `dump-fri-fold-matrix-loga1`, and `dump-fri-fold-matrix` — every line traceable to Plonky3 source.

See: `SUBAGENT_AUDIT_2026_05_23.md` (the evening-of-nuke audit on disk) + memory `feedback_no_kafadan_crypto.md`.

Genuine cross-validation count (post-restore): the previously-circular ~2,400 cases were replaced by ~5,900 Plonky3-grounded oracle byte-match cases (transcript 14 cases / 48 ops, merkle_mmcs 501 + batch 511, fri_fold row 3125 + matrix loga1 330 + matrix generic 1080, primitive_ops 31). Combined with the existing field/ntt/sponge/range/sum_balance gates, `make test` runs ~14,000+ byte-match cases all GREEN.

---

## FRI verifier port — F2–F7 COMPLETE (integrated, V6 verifies) (2026-05-29)

F1 oracle suite APPROVED. F2 `fri_verifier.h` (ABI). F3 shape prefix. F4 transcript
flow. F5 MMCS call replay + verify_query isolated shapes. F6 terminal Horner.
**F7: integrated verifier SHIPPED — `dnac_fri_verify` is DEFINED and verifies the
locked V6 valid proof end-to-end (returns `DNAC_FRI_OK`).** All wired into
`make test` (29 binaries), GREEN, zero warnings.

**F1.6: multi-reduced-opening ROLL-IN gap CLOSED (2026-05-29).** New oracle
subcommand `dump-fri-verifier-rollin` → `tools/vectors/fri_verifier_rollin.json`
(hash-pinned): TWO single-matrix commitments at log_height 4 + 2 (Phase 2A, NOT
mixed-height) → two reduced openings → roll-in `beta^arity·ro` fires at round 1
with a no-roll-in round 0. C replay `tests/test_fri_verifier_rollin.c` GREEN:
production `dnac_fri_verify` = `DNAC_FRI_OK` end-to-end + capture cross-check +
an independent fold trace (via `fri_fold_row_fp2`) reproducing the Plonky3-
anchored `folded_before/after`. **Source-lock answer: exercising the roll-in
does NOT require Phase-2B mixed-height MMCS** — the height-homogeneity assert in
`fri_open_input` (fri_verifier.c:210-214) is per-batch, and N single-matrix
commitments give N distinct heights with every `verify_batch` single-matrix.

**Proof wire codec SHIPPED (2026-05-29) — STARK blocker #1 CLOSED.** Additive
module `fri_proof_codec.{c,h}` (de)serializes the exact `dnac_fri_verify` inputs
(params + proof + commitments; transcript excluded — that's blocker #2). Wire =
DNAC framing (magic `DZKF` + u16 version + u32 total_len; LE; u32 length
prefixes) over Plonky3-grounded element encodings (canonical u64-LE Goldilocks
reject ≥p; fp2 c0‖c1; digest raw 64 B; merkle siblings depth+level-0-first).
Decode is bounds-checked + canonical-only + allocation-registry (no partial
leak). `tools/vectors/fri_proof_wire.json` (hash-pinned, regenerate-identical)
holds V6 + roll-in wire + 8 negative malformed cases. `test_fri_proof_codec.c`
GREEN: both decode→`dnac_fri_verify`=`DNAC_FRI_OK`→encode==wire roundtrips + all
8 malformed rejected (specific codes, pkg NULL); ASan+UBSan clean. Multi-agent
red-team (4 independent subagents) found zero bugs. `dnac_fri_status_t`
UNCHANGED — codec uses a separate `dnac_fri_codec_status_t`. Design:
`docs/plans/2026-05-29-fri-proof-wire-codec-design.md`.

**B8 — PCS/STARK transcript priming SHIPPED (2026-05-30) — STARK blocker #2 CLOSED.**
The Fiat-Shamir front-half that primes the state `dnac_fri_verify` consumes
(uni-stark `verifier.rs:360-391`+`:398` observe instance/commitments/public →
sample STARK alpha → sample zeta; then PCS observe-opened-values
`two_adic_pcs.rs:687-693`). Grounding = real `p3_uni_stark::prove` (NOT synthetic).
- **P3/P4** `stark_priming.{c,h}` (`dnac_stark_prime_transcript`, public transcript
  API only; separate `dnac_stark_priming_status_t`) + replay test vs `stark_priming.json`.
- **P5** `stark_proof_codec.{c,h}` — additive **DZKS** wrapper (magic `DZKS` + degree_bits
  + public_values + opaque inner **DZKF**); FRI wire byte-unchanged.
- **P6** integrated `tests/test_stark_priming_integrated.c` (production APIs only):
  DZKS→DZKF decode → rebuild priming input from decoded coms → prime → assert derived
  ζ/ζ_next == wire points → `dnac_fri_verify==DNAC_FRI_OK`. **Both `main_next` paths:**
  FibonacciAir (`main_next=true`, 2 trace points) + **SquareAir** (`no_next_row.rs:16-49`
  vendored verbatim on the DNAC stack, `main_next=false`, 1 trace point, `trace_next=None`
  asserted). Oracle gained `dump-stark-priming-no-next` (both gates: `p3_uni_stark::verify`
  + `p3_verify_fri` on the 1-point round). Vectors hash-pinned: `stark_priming.json`
  `b0132311…`, `stark_priming_no_next.json` `a42faf3e…`, `stark_proof_wire.json`
  `1ebd0836…`, `stark_proof_wire_no_next.json` `f5267e96…`.
- **FRI terminal-index P0 fix (2026-05-30):** `fri_verify_query` shifted the fold index
  on a BY-VALUE copy, so the terminal Horner used the UNSHIFTED `domain_index` (vs
  Plonky3 `&mut` shift, `verifier.rs:301/444/308-312`). MASKED by V6/rollin
  (`log_final_poly_len=0` → constant final_poly); SURFACED by the first `>0` case.
  1-line fix `domain_index >>= sum_la;`; **permanently guarded** by the P6 integrated test.
- `make clean && make test` GREEN (**32 bins, 0 warnings**); 4 vectors 2× byte-identical;
  `dnac_fri_status_t`/`fri_verifier` semantics untouched. Design:
  `docs/plans/2026-05-30-pcs-transcript-priming-design.md`.

**STARK verifier constraint-check SOURCE-LOCKED (2026-05-30) — no code.** After B8 priming +
`dnac_fri_verify`, only TWO functions remain: `recompose_quotient_from_chunks` (verifier.rs:59-96)
+ `verify_constraints` (verifier.rs:103-162) → check `folded·inv_vanishing==quotient` (verifier.rs:157).
All deg-2 DNAC AIRs ⇒ num_qc=1 ⇒ trivial recompose; trace shift=ONE (two_adic_pcs.rs:286). Compat:
range_air↔SquareAir(no_next), sum_balance↔FibonacciAir. Smallest safe target = generic check vs
EXISTING fib/square vectors (no new AIR). range_proof_air BLOCKED on §4.5 rewrite. Doc:
`docs/plans/2026-05-30-stark-verifier-constraint-check-sourcelock.md` (local). **S1 impl design doc
DONE** (`docs/plans/2026-05-30-stark-constraint-check-implementation-design.md`, local): 15 sections,
3 mandatory first, proposed C API (separate `dnac_stark_verify_status_t`), fib/square emission order
pinned, selectors UNnormalized, `assert_bool` S3-test-gap noted. **S2 oracle DONE** — 2 subcommands
`dump-stark-verify-constraints[-no-next]` (fib/square) via Plonky3 pub `verify_constraints` +
`recompose_quotient_from_chunks`; per-constraint fold trace from a `RecordingFolder` mirroring
`VerifierConstraintFolder` (gated == real folder acc via GATE2∧GATE4 + per-constraint GATE5
selector·raw==received); vectors `stark_verify_constraints.json` `ce2af29c…` + `_no_next`
`fb9863b7…` (hash-pinned, byte-identical 2× regen, sha256sum -c 28 OK). No C, no Makefile. **S3 C generic primitives DONE** — `stark_constraints.{h,c}`:
`dnac_stark_selectors_at_point` (domain.rs:262-271, UNnormalized) + `recompose_quotient_1chunk`
(`ch0+ch1·X`) + fold ops (`assert_zero/eq/bool/when`, folder.rs:216-217 + filtered.rs:60-62) +
`dnac_stark_final_check`; separate `dnac_stark_verify_status_t` ({OK,OOD_MISMATCH,SHAPE});
`dnac_fri_status_t` UNTOUCHED. `test_stark_constraints_primitives.c` byte-matches the S2 vectors
(selectors 5/5+recompose+fold 5/5/1/1+final OK) + standalone `assert_bool`. **S4 verify_constraints
glue + fib/square air_eval DONE** — `dnac_stark_verify_constraints` (callback-dispatch
`dnac_stark_air_t`; `dnac_stark_folder_t` air_eval context + opt-in capture; shape→recompose→
selectors→air_eval→final_check, verifier.rs:463-498) + fib/square air_eval test fixtures.
`test_stark_verify_constraints.c`: verify_constraints==OK both, **per-constraint trace 5/5+1/1**,
5 negatives (OOD/SHAPE/zero-window). **S4 RED-TEAM: 6 independent auditors → ALL SOUND / TEST-HAS-TEETH**,
no defects (JUDGMENT boundaries for S5: stray-trace_next leniency [documented], num_qc=1/degree-2
unguarded precondition, non-ZK identity). `make clean && make test` GREEN (34 bins, 0 warnings);
`dnac_fri_status_t` UNTOUCHED. **S5.0 range_proof_air §4.5 RE-GROUNDING design DONE** (no code) —
`docs/plans/2026-05-30-dnac-range-proof-air-regrounding.md`: supersedes the kafadan §4.5 (200-col
keccak mega-trace), ratifies the 66-col unified trace (range 65 + acc), DROPS keccak/'M'.
range_proof_air = range(B+S)⊕balance(I+U+F), 68 constraints, width 66, main_next=true, 2 publics,
emission order [B₀..B₆₃,S,I,U,F]. Advisor-shaped: G5 trace↔TX binding = **OPEN/red-team#1** (no
existing integration; verifier-independent-vs-witness-trusted ungrounded); num_qc=1 **EXPECTED**
(S5.1-entry gate via get_log_num_quotient_chunks); phased (range-only first) + ≥2 degrees REQUIRED.
**S5.0 RED-TEAM RAN (12 independent auditors, 2026-06-01) → design APPROVED, no constraint defect.**
All 5 constraint forms + 66-col layout + selectors + emission order + num_qc=1 GROUNDED. 3 findings
folded into the doc: **B6/#8 field-wrap** (64-bit amounts but Goldilocks p<2⁶⁴ → Σ wraps → mint-past-
supply; fix B+M<64, B≈57-58 not 64; backstopped by cleartext bft.c:4113 for ADDITIVE, load-bearing for
CONFIDENTIAL); **#10** U is degree 1 not 2 (IsTransition deg 0), max=2 via B/I/F, num_qc=1 unchanged;
**B7/#12** no constraint forces padding=0 (G5 must zero padding/bind output count). ADDITIVE-vs-
CONFIDENTIAL undecided in any doc. **S5.1 Rust range_proof_air + ADDITIVE oracle vectors DONE** —
`RangeOnlyAir` (65 cols, B+S, 65 constraints) + `RangeProofAir` (66 cols, main_next=true, 2 public,
B+S+I+U+F, 68 constraints) in the oracle; reused S2 `capture_verify_constraints` + new `emit_range_case`
(GATE5 + num_qc STOP). Config lfp0 (log_final_poly_len=0 works at db 2 AND 3). **num_qc==1 CONFIRMED**
both. Vectors `range_air_only.json` `0d705f8d…` (2 cases) + `range_proof_air.json` `13180ddf…` (2 cases:
db2-full + db3-padded, claimed=Σ+fee); additive_only=true/confidential=false/blockers=[B1,B6,B7]. Gates:
prove/verify/verify_constraints=Ok, per-constraint 65/68, final_lhs==rhs, 2× byte-identical, sha256sum -c
30 OK, cargo clean 0 warn. No C, no confidential, no binding. **S5.x C range_proof_air air_eval DONE** — `test_range_proof_air.c`:
`range_only_air_eval` (B+S, 65) + `range_proof_air_eval` (B+S+I+U+F, 68) test fixtures via S4 folder
helpers (`dnac_stark_folder_assert_bool/eq/when`); descriptors {65,0,0}+{66,2,1}; reuses
`dnac_stark_verify_constraints` UNCHANGED. verify_constraints==OK all 4 cases, **per-constraint 65/65 +
68/68**, folded==vector, final OK, flags asserted (additive/confidential/blockers). 7 negatives
(OOD: corrupt bit/amount/acc/swap-public; SHAPE: wrong-width/missing-trace_next; OK: range-only-absent).
`make clean && make test` GREEN (35 bins, 0 warnings); sha256sum -c 30 OK; `dnac_fri_status_t` UNTOUCHED.
**ADDITIVE range_proof_air is now end-to-end C↔Plonky3 proven (S5.1 oracle + S5.x C). S6/P7 FULL-STACK
AUDIT DONE** (12 independent auditors, 2026-06-01): all 12 surfaces ADDITIVE-SOUND/GROUNDED, no KAFADAN,
no constraint defect; FRI guard mutation-proven non-vacuous, 65/65 + 68/68 byte-match non-tautological,
oracle 5-gate real-Plonky3, boundary grep-confirmed unlinked; B1/B6/B7 confirmed OPEN (B6 live-witness,
B7 live-exploit) but all backstopped for ADDITIVE by native-u64 cleartext recompute (verify.c Check 4).
Post-audit make test GREEN (35 bins). **2 findings: (i) DURABILITY — whole zk stack git-UNTRACKED →
RECOMMEND committing to lock guards; (ii) doc citation fixed.** **The ADDITIVE v3 STARK range_proof_air
milestone is COMPLETE + P7-audited.** Next (optional/separate, gated): commit the stack; CONFIDENTIAL
use needs B1+B6+B7 (a B+M<64 range_proof_air, B≈57-58); production integration is a separate decision.
All gated on APPROVED.

Per-phase tests (all GREEN in `make test`):
1. F3 `test_fri_verifier_shape` — 6/6 shape cases (`verifier.rs:146-246`), 13 deferred.
2. F4 `test_fri_verifier_transcript` — 18/18 milestones; pins `lgmh==4`, indices `{3,12}`.
3. F5a `test_fri_verifier_mmcs_calls` — 8/8 captured verify_batch (2 input + 6 commit).
4. F5b `test_fri_verifier_verify_query` — 3/3 isolated verify_query shape errors.
5. F6 `test_fri_verifier_terminal_horner` — 173/173 (incl. D7 trap).
6. F7 `test_fri_verifier_valid` — V6 end-to-end `DNAC_FRI_OK` + 6/6 integrated public errors.

F7 integrated components (in `fri_verifier.c`, always-compiled `static`):
`fri_open_input` (input MMCS verify + reduced-opening quotient `ro += alpha_pow·(p(z)−p(x))·(z−x)⁻¹`
+ open_input FinalPolyMismatch site `verifier.rs:647-651`), `fri_verify_query` (fold loop:
eval-row reconstruction, commit-phase MMCS verify, `fri_fold_row_fp2`, reduced_openings
consumption), terminal Horner final check, and `dnac_fri_verify` glue. `GENERATOR=7`
(`goldilocks.rs:400`) coset shift in open_input's x (terminal Horner x has NO GENERATOR).

Locked decisions (unchanged):
- **Pure FriError mirror:** `dnac_fri_status_t` = `DNAC_FRI_OK` + exactly **19** Plonky3
  FriError-equivalent values. **No** `NULL_ARG`/`INCOMPLETE`. Null = caller precondition
  (`assert`), never `InvalidProofShape`. F4/F5/F6/F7 added only additive types/helpers —
  the status enum is byte-identical.
- **No false-accept:** `DNAC_FRI_OK` is returned only after V6 verifies end-to-end.

Error coverage: **16/19 variants exercised** — 6 integrated-reachable public errors
through `dnac_fri_verify` (F7: InputProofBatchCount, BatchOpenedValuesCount,
PointEvaluationCount, SiblingValuesLength, CommitPhaseMmcsError, InputError) + 6 shape
(F3) + 3 verify_query isolated (F5) + 1 FinalPolyMismatch horner (F6).

Grounding audits (independent parallel subagents, source-locked to 82cfad73):
F6 4/4 GROUNDED; F7 **5/5 reported GROUNDED, 0 KAFADAN** (open_input, verify_query,
verify_fri glue, serialization, GENERATOR/x). Honest provenance: the F7 5th verdict was
recovered from the workflow output file (truncated tool result), corroborated by the V6
empirical gate + the test's own GENERATOR/x cross-check.

Deferred / NOT complete:
- ~~**Multi-reduced-opening path UNEXERCISED**~~ **DONE 2026-05-29 (F1.6).** The
  multi-entry descending sort + roll-in `beta^arity·ro` (`verifier.rs:477-480`)
  are now EXERCISED by `tools/vectors/fri_verifier_rollin.json` (2 commits at
  log_height 4 + 2) + `tests/test_fri_verifier_rollin.c`. No Phase-2B needed.
- `InvalidPowWitness` implemented but unexercised (V6 PoW bits = 0).
- `MissingInitialReducedOpening` implemented but unexercised (needs empty input).
- `InvalidProofShape` not reachable in DNAC (hiding-pcs only).
- Phase-2B mixed-height MMCS: asserted-out (out of v3.0 scope).
- Transcript priming (PCS/STARK layer producing the milestone-0 seed) NOT built.
- Proof wire deserialization NOT built (tests hand-parse JSON).

Blockers before a STARK verifier:
1. Transcript priming / PCS-STARK layer (B8) — the LAST remaining blocker.
   (Former blocker 2 — proof wire codec (B7) — CLOSED 2026-05-29
   (`fri_proof_codec.{c,h}` + `fri_proof_wire.json`). Former blocker 3 — a
   multi-matrix/multi-height FRI vector for the roll-in path — CLOSED via F1.6.)

**STARK verifier coding is GATED on explicit user approval.** Do not start without it.

---

## Quickest sanity check (next session, first thing)

```bash
cd /opt/dna/shared/crypto/zk
make clean && make test
```

Expected (2026-07-14): 57 test binaries GREEN, 0 warnings, all grounded against external references (Plonky3 pin `82cfad73`, NIST KAT, OpenSSL, FIPS-202).

---

## What's KEPT (grounded only)

### Reference-validated C code

| File | Validation source | Confidence |
|---|---|---|
| `field_goldilocks.{c,h}` | Plonky3 oracle JSON, ~13k cases byte-match | HIGH |
| `keccak_ref.{c,h}` | OpenSSL EVP + NIST KAT + spec re-derivation (strongest in stack) | HIGH |
| `ntt_goldilocks.{c,h}` | Plonky3 `Radix2Dit::default().dft()` direct call (`tools/vectors/ntt_goldilocks.json`, 64 cases across base + ext, log_n ∈ [1,8]) AND brute-force O(N²) DFT cross-check. Two independent references. | HIGH |
| `keccak_p3_{cols,trace,air}.{c,h}` | Direct port of Plonky3 `keccak-air` (commit 82cfad73); trace output byte-matches `keccak_ref_f1600` 15/15 | HIGH |
| `range_air.{c,h}` (Sprint 3.1 rework 2026-05-23) | Real `p3_air::utils::u64_to_bits_le::<Goldilocks>` call; 80 cases byte-match (`tools/vectors/range_air.json`); F7 column-layout binding test ships alongside | HIGH |
| `sum_balance.{c,h}` (Sprint 3.2 rework 2026-05-23) | U+F = Plonky3 fib_air idiom; I constraint = DNAC-original from § 6.1; 78 cases byte-match (`tools/vectors/sum_balance.json`); F7 column-layout binding test ships alongside | HIGH (partial — I constraint DNAC-original) |
| `sponge_sha3_512.{c,h}` (Sprint 3.3b.7 rework 2026-05-23) | Triple cross-validation: Plonky3 sha3 crate (74 oracle cases) + keccak_ref + incremental-absorb-vs-oneshot. | HIGH |
| `poseidon2_goldilocks.{c,h}` (FP1.2 2026-07-14) | Width-8 Poseidon2 permutation. Byte-matches the REAL `default_goldilocks_poseidon2_8().permute` (Plonky3 82cfad73, 16 cases incl. all-zero KAT / near-p / random). Constants (RC 8×4+8×4+22, MATRIX_DIAG_8, RF=8/RP=22/D=7) copied verbatim from `goldilocks/src/poseidon2.rs`. Also exposes the external/internal linear layers + round constants for AIR reuse. STANDALONE — not yet wired to any proof-internal path. | HIGH |
| `poseidon2_air_cols.{c,h}` (FP1c.1 2026-07-14) | Poseidon2Cols<8,7,1,4,22> column layout (180 cols, SBOX_REGISTERS=1 deg-3). Structural binding contract vs Plonky3 `poseidon2-air/src/columns.rs` repr(C) order (boundaries 8/72/116/180). | HIGH |
| `poseidon2_air_trace.{c,h}` (FP1c.2 2026-07-14) | Single-permutation trace-row generation. Byte-matches the REAL `p3_poseidon2_air::generate_trace_rows` (8 cases × 180 cols) + final post == permute cross-check. Port of `generation.rs` generate_trace_rows_for_perm. | HIGH |
| `poseidon2_air.{c,h}` (FP1c.3 2026-07-14) | Constraint eval (witness residual checker). Port of `poseidon2-air/src/air.rs` eval/eval_full_round/eval_partial_round/eval_sbox(7,1). Grounding: real Plonky3 traces accepted (0 viol) + all 1440 single-col tampers caught. Max constraint degree 3 (blowup-4 compatible). | HIGH |

### Rust reference oracle (build-time only, post-evening cleanup)

- `tools/plonky3_oracle/Cargo.toml` — Plonky3 pinned to `82cfad73`
- `tools/plonky3_oracle/Cargo.lock` — full dep graph pinned
- `tools/plonky3_oracle/src/main.rs` — 1419 lines (was 2768; kafadan sections removed). 7 grounded `dump-*` subcommands: `dump-field-ops`, `dump-field-ext`, `dump-two-adic-gens`, `dump-range-air`, `dump-sum-balance`, `dump-ntt-goldilocks`, `dump-sha3-512-sponge`. `dump-keccak-air` retained as retired no-op stub.
- `tools/vectors/*.json` (7 files) — committed test vectors: field_ext, field_ops, ntt_goldilocks, range_air, sha3_512_sponge, sum_balance, two_adic_gens
- `tools/vectors/.expected_hashes` — sha256 pin per vector

---

## Second nuke 2026-05-23 evening — restoration status

Per SUBAGENT_AUDIT_2026_05_23.md (12 parallel independent audit) the following 5 modules were flagged CIRCULAR — C ↔ Rust oracle byte-match where BOTH sides implemented DNAC's invented spec. Proves implementations agreed, NOT that the spec was sound. All 5 were deleted on the evening of 2026-05-23 per user directive: "ISKELETI SIL. GOTUNDEN UYDURDUGUN HERSEYI SIL".

Three of those modules have since been REBUILT as Plonky3-grounded ports; two remain deleted pending the FRI verifier port that replaces them.

| Module | Original deletion reason | Current status |
|---|---|---|
| `transcript.{c,h}` | DNAC hash-chain F-S construction had no Plonky3 byte-equivalent. Domain `"DNAC_RP_TRANSCRIPT_V1\0\0\0"` + `"CHAL"` tag invented. | **RESTORED 2026-05-26** as a line-cited port of Plonky3 `SerializingChallenger64<Goldilocks, HashChallenger<u8, _, 64>>` (challenger crate, commit `82cfad73`). Design doc: `docs/plans/2026-05-26-transcript-design.md`. Oracle subcommand `dump-transcript` → `tools/vectors/transcript.json` (14 cases / 48 ops). C replay: `tests/test_transcript_oracle.c` GREEN. |
| `merkle_smt.{c,h}` | Entire SMT design DNAC-invented (3 domain strings, index-bound null hash). Plonky3 `MerkleTreeMmcs` is N-ary field-element with no byte-level domain seps. | **RESTORED 2026-05-27** as a line-cited port of Plonky3 `MerkleTreeMmcs` (`merkle-tree/src/{mmcs.rs, merkle_tree.rs}` at commit `82cfad73`) using Strategy C (`[u64;8]` oracle representation, LE-byte wire form). Design doc: `dnac/docs/plans/2026-05-26-merkle-mmcs-design.md`. Single-matrix + Phase 2A same-height batch APIs. Oracle subcommands `dump-merkle-mmcs` + `dump-merkle-mmcs-batch-same-height` → 501 + 511 cases. C replays: `tests/test_merkle_mmcs.c` + `tests/test_merkle_mmcs_batch.c` GREEN (includes nm1 byte-identity regression 204/204). |
| `fri_fold.{c,h}` | C math fine (textbook); oracle was Rust transliteration of DNAC math, NOT a call into `p3_fri::TwoAdicFriFolding`. | **RESTORED** as a line-cited port of Plonky3 `TwoAdicFriFolding` (`fri/src/two_adic_pcs.rs:109-213` at commit `82cfad73`). Phases D.1 (lagrange) + D.2 (`fold_row`) + D.3 (`fold_matrix` log_arity==1) + D.4 (`fold_matrix` generic log_arity>1). Oracle subcommands `dump-fri-fold-row` + `dump-fri-fold-matrix-loga1` + `dump-fri-fold-matrix` → 3125 + 330 + 1080 cases. C replays: `tests/test_fri_fold*.c` GREEN. |
| `fri_commit.{c,h}` | SHAPE-only match; missing Plonky3's variable arity, 2-phase PoW, IDFT final poly, batch absorption. | **STILL DELETED.** Will be subsumed by the upcoming fri_verifier port (`docs/plans/2026-05-27-fri-verifier-design.md`) rather than reintroduced as a standalone module. |
| `fri_query.{c,h}` | SOUNDNESS GAP: DNAC verifier read `lo/hi_value` from proof at layer i+1 instead of carrying `folded_eval` (Plonky3 `verifier.rs:425`). | **STILL DELETED.** Same fri_verifier port handles query consumption with `folded_eval` chaining; no standalone fri_query module returns. |

Plus deleted on 2026-05-23 evening (NOT restored): audit docs (`AUDIT.md`, `AUDIT_KAFADAN.md`, `HANDOFF_FAZ0.md`), tests for the still-deleted modules (`test_fri_commit`, `test_fri_query_oracle`, `test_fri_e2e`), vectors for the still-deleted modules (`fri_commit.json`, `fri_query.json`), Plonky3 oracle sections backing the still-deleted modules (`run_fri_commit_oracle`, `run_fri_query_oracle` + helpers). The oracle sections backing the RESTORED modules were rewritten from Plonky3 source.

## What's DELETED — First nuke 2026-05-23 morning (11 modules, mostly reworked same day)

The following 11 modules + their 11 test files were authored from STARK + FIPS-202 textbook intuition without reading the Plonky3 reference. Tests for these were circular (same author wrote spec, implementation, and tests). All deleted from disk:

| Module | Old "sub-sprint" | Why deleted |
|---|---|---|
| `range_air.{c,h}` | 3.1 | 64-row × 2-col layout was invented; Plonky3 has lookup-based range patterns never consulted |
| `sum_balance.{c,h}` | 3.2 | Multi-output sum-balance composition invented; CT/Bulletproofs literature never consulted |
| `keccak_air_bits.{c,h}` | 3.3b.1 | XOR primitives with custom aux invented; Plonky3 uses `xor3` algebraic primitive |
| `keccak_air_theta.{c,h}` | 3.3b.2 | θ AIR encoding with c_xor5_witness aux invented; Plonky3 has different column layout |
| `keccak_air_rho_pi.{c,h}` | 3.3b.3 | ρπ encoding invented; Plonky3 inlines via `b(x,y,z)` accessor |
| `keccak_air_chi.{c,h}` | 3.3b.4 | χ encoding with t_bits aux invented; Plonky3 uses `andn` algebraic primitive |
| `keccak_air_iota.{c,h}` | 3.3b.5 | ι RC XOR invented; Plonky3 uses one-hot `step_flags` × `RC_BITS` aggregation |
| `keccak_air_f1600.{c,h}` | 3.3b.6 | 24-round chaining with 'L' link constraints invented; Plonky3 uses 24 ROWS of one trace with cross-row transitions (architecturally different) |
| `keccak_air_sha3_512.{c,h}` | 3.3b.7 | Single-block sponge invented; Plonky3 has `p3-symmetric::PaddingFreeSponge` |
| `keccak_air_sha3_512_multi.{c,h}` | 3.3b.8 | Multi-block sponge + 'C' chaining invented; same Plonky3 sponge layer never consulted |
| `range_proof_air.{c,h}` | 3.4 | Composition with 'B' binding + 'M' commitment-match constraints invented; 'M' constraint was known to be tautological (header warning); no published ZK-range-proof construction consulted |

`3.4r` (`keccak_p3_*`) replaces all 11 keccak_air_* with a single direct Plonky3 port — this is the pattern the rewrite must follow for everything else.

---

## What's REWORK-OWED (per design doc § 12)

Owed without compensation per user instruction 2026-05-23. Sequence (each requires Plonky3 source consultation OR audited published construction):

1. ~~**range_air** — port from Plonky3 lookup/range-check pattern (`p3-lookup` or `p3-air` builder helpers).~~ **DONE 2026-05-23** — Plonky3 `air/src/utils.rs::u64_to_bits_le` + `keccak-air/src/air.rs:102-125` production pattern ported; 80 oracle byte-match cases (78 reconstruction + 78 ACCEPT outcomes + 2 REJECT outcomes); F7 column-layout BINDING test included (`test_air_column_layout_range_air`); 0 circular self-tests. Validation source pinned in `tools/vectors/range_air.json`. See `tools/plonky3_oracle/src/main.rs::dump_range_air`.
2. ~~**sum_balance** — restate as constraints over the unified trace, no separate sub-witness struct.~~ **DONE 2026-05-23** — Plonky3 `uni-stark/tests/fib_air.rs::FibonacciAir::eval` pattern ported; ONE accumulator column at offset 65 of the range_air trace; 3 constraints (I/U/F) in base Goldilocks with `claimed_input_sum` + `committed_fee` as public inputs; 78 oracle byte-match cases (70 reconstruction + 70 ACCEPT outcomes + 8 REJECT outcomes + 78 residual matches); F7 column-layout BINDING test included; 0 circular self-tests. Validation source pinned in `tools/vectors/sum_balance.json`. See `tools/plonky3_oracle/src/main.rs::dump_sum_balance`.
3. **`test_air_column_layout`** — write the missing F7 test that asserts every column position by name (§ 9 F7 BINDING contract).
4. **range_proof_air** — design 'B' (range bits ↔ hash input bytes) and 'M' (commitment match against PUBLIC INPUT, not witness) from a published ZK-range-proof construction. The 'M' tautology trap from 3.4 must NOT recur.
5. ~~**Sponge layer** — port `p3-symmetric::PaddingFreeSponge` semantics for multi-block SHA3-512 absorption that wraps the 3.4r keccak_p3 permutation.~~ **DONE 2026-05-23** — implemented as `sponge_sha3_512.{c,h}`: standard FIPS-202 SHA3-512 (XOR absorption + `0x06|...|0x80` padding) over keccak_p3 permutation backend. Picked Option B (uniform FIPS-202) per locked spec from `project_v3_zk_bitcoin_style` + design doc § 4.2 — NOT strict overwrite-mode PaddingFreeSponge. Triple cross-validation: (A) 74 cases byte-match Plonky3 sha3 crate oracle, (B) byte-match keccak_ref (existing OpenSSL+NIST KAT), (C) incremental-absorb == oneshot for chunk sizes {1, 7, 17, 71, 72, 73}. Validation source pinned in `tools/vectors/sha3_512_sponge.json`. See `tools/plonky3_oracle/src/main.rs::dump_sha3_512_sponge`.
6. ~~**fri_query Plonky3 cross-validation** — extend `tools/plonky3_oracle/src/main.rs` with `dump-fri-query` subcommand; close the self-test gap.~~ **DONE 2026-05-23** — `dump-fri-query` added; implements DNAC's FRI query protocol in Rust using already-byte-matched primitives (OracleTranscript = SHA3-512, merkle_hash_* with DNAC domain separators, fri_fold_arity2_oracle, run_fri_commit_oracle pattern). 5 cases × ≤4 queries = 18 query proofs (4+4+4+4+2); `test_fri_query_oracle` byte-matches every layer opening (lo/hi index + value + Merkle path) AND round-trip-verifies via `fri_query_verify` → ACCEPT. The existing 5-tamper-type test_fri_e2e.c is retained as second independent reference. Validation source pinned in `tools/vectors/fri_query.json`.
7. ~~**ntt_goldilocks Plonky3 cross-validation** — extend oracle with `dump-ntt` subcommand for index-ordering byte-match (not just multiset).~~ **DONE 2026-05-23** — `dump-ntt-goldilocks` added (`tools/plonky3_oracle/src/main.rs`), uses Plonky3 `Radix2Dit::dft` for base and `dft_algebra` for extension; 64 oracle cases (32 base + 32 ext) at log_n ∈ [1,8] × {zero, delta_0, rand_a, rand_b}; `test_ntt_goldilocks_oracle` byte-matches every output cell. Both base-field NTT and ext-field NTT pass. The existing brute-force DFT cross-check in `test_ntt_goldilocks.c` is retained as a SECOND independent reference. Validation source pinned in `tools/vectors/ntt_goldilocks.json`.

### Prerequisite for ANY rewrite to be considered "done":

- Plonky3 source for the relevant crate (or other audited reference) MUST be opened first. `~/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/82cfad7/` has the source.
- Plonky3 oracle dump subcommand added BEFORE implementation, not after. Test gate = byte-match, not self-consistency.
- Per `feedback_no_kafadan_crypto.md`: if Plonky3 has no equivalent, STOP and ask. No kafadan adaptation.

### Faz 5 + 6 blocked until rework completes.

---

## Critical conventions (these remain locked)

1. **SHA3-512 (FIPS-202) for ALL hashing** — chain-level, proof-internal, AND in-AIR.
2. **Goldilocks² over `x² − 7`** — Plonky3 pinned commit `82cfad73`.
3. **Plonky3 commit pin `82cfad73`** — bump requires design-doc revision + full vector re-validation.
4. **No Rust at runtime** — Plonky3 oracle is build-time only. Production binaries are pure C.
5. **Bitcoin-style identity** — v3.0 is 1 TPS sustainable, full-history, no pruning.
6. **NEVER kafadan crypto** — per [[feedback_no_kafadan_crypto]] (2026-05-23 hard rule).

---

## Pitfalls to remember (filtered post-nuke)

1. **Goldilocks field bound:** `p < 2⁶⁴`. Amounts ≥ p reduce mod p — DNAC supply ~2⁵⁷ is fine.
2. **F4 fix:** transcript T₀ MUST bind chain_id + block_height + tx_index. Already in `transcript.c`.
3. **F8 fix:** range proof statement MUST include `claimed_input_sum` as public input. Was in deleted `range_proof_air.c`; must be re-implemented in the rewrite.
4. **F7 (NEVER IMPLEMENTED):** `test_air_column_layout` must exist for the rewritten range_proof to assert § 4.5 binding column contract.
5. **'M' tautology trap (filed 2026-05-22, deleted 2026-05-23):** rewritten range_proof must source `commitments[]` from TX-wire public input, NEVER from witness self-population.
6. **AIR witness memory:** Plonky3 keccak-air is ~21 KB per row × 24 rows ≈ 500 KB per Keccak-f. Reasonable for stack OR heap; heap is the conservative default.
