# RESUME — DNAC v3 ZK stack (CURRENT STATUS: 2026-07-12)

> **This top block is authoritative and current. Everything under "═══ HISTORICAL
> BUILD LOG ═══" is the traceable module-by-module history and its numbers
> (widths, constraint counts, B6/B7 framing) are PRE-2026-07-12 — read them as
> history, not current state.**

## WHERE WE ARE

- **What it is:** a **verify-only** STARK range/balance-proof stack over the
  Goldilocks field — Plonky3-grounded C ports of the verifier engine (field,
  NTT, Keccak-AIR, SHA3 sponge, transcript, Merkle-MMCS, FRI fold + verifier,
  STARK constraint check, proof codecs) plus two DNAC-original money AIRs
  (range_air, sum_balance) and a Rust build-time oracle.
- **The prover is [MISSING]** — nothing in this tree generates proofs; every
  test verifies proofs produced by the Rust oracle / real `p3_uni_stark::prove`.
- **Parked, NOT in consensus.** `grep` confirms zero references to
  `shared/crypto/zk` from any CMakeLists (messenger/nodus/dnac) — it is compiled
  ONLY by its own standalone `Makefile`, not into `libdna.so`/`nodus-server`.
  Money conservation on the live chain is enforced by the native cleartext
  witness check (`verify.c` Check 4); this ZK stack is ADDITIVE (v3 ships
  transparent, hidden amounts are v4).
- **`make test`: 36 gates GREEN, 0 warnings** (`cd shared/crypto/zk && make test`).
- **Committed** on branch `zk-range-balance-soundness-hardening` (commits
  `9d07c968` mint-fix + FRI guards, `80f8888b` composed door). Not on `main`.

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

The 18-member council's diagnosis: this is **two sound fragments, not a system**
— the verifier engine + money AIRs are individually sound, but there is no
prover and no TX binding, so no adversarial soundness claim can even be tested.
Remaining before ZK gates real money (all before-consensus MUST-FIX):

- **Prover** — [MISSING] entirely; estimated 2–4 months (FFT/LDE + FRI commit +
  trace Merkle + query opening orchestration). Do NOT start it on the current
  foundation before B1 is audited.
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

**STRATEGIC FORK (council escalated to user, unresolved):** HOLD+HARDEN (fix
done, stop auditing the AIR) vs KEEP+ADVANCE (proceed to prover/B1 under gates)
vs SHRINK (delete the parked verifier to a tagged branch, keep only
field+range+sum_balance as v4 seeds). No decision taken.

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

Expected (2026-07-12): 36 gate markers GREEN, 0 warnings, all grounded against external references (Plonky3 pin `82cfad73`, NIST KAT, OpenSSL, FIPS-202).

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
