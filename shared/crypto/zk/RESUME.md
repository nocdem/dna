# RESUME — DNAC v3 ZK stack (CURRENT STATUS: 2026-07-29)

## ⏭ WHAT IS LEFT — read this first (2026-07-29)

**The zk stack itself is GREEN and idle. Nothing in `shared/crypto/zk/` is blocking.**
`make test` 73 binaries / 0 warnings, 60/60 vectors hash-clean, nodus ctest 132/132. The whole
verify stack is consensus-LINKED but consensus-DEAD: type-11 is still REJECT-unconditional
(`nodus/src/witness/nodus_witness_verify.c:743-753` — verified 2026-07-27, the `return -1` is the
function's last statement, there is no accept path). **C3 is the door that opens it, and the work
left is NOT zk work — it is design and consensus work upstream of the circuits.**

### The four things standing between here and a live shielded pool

1. **F1 — the production note tree.** Design doc `dnac/docs/plans/2026-07-22-f1-note-commitment-
   tree-design.md` exists and is user-locked at D=24, but its red-team ran 2026-07-27 and came back
   **NOT-GREEN**: 10 findings, and **4 of the doc's own 20 "grounded" facts were REFUTED**. The two
   that cost real work: the doc claims the D flip changes "not the trace width (2318) nor the
   constraint SET" — **both false**. Width is `2306 + 3·D` (`conf_action_agg_fold.h:99-111`), so
   D=24 ⇒ **2378**; and the fold emits 4 constraints/level for i=1..D plus 5/level for i=2..D
   (`conf_action_agg_fold.c:61-72`, `:119-141`) ⇒ **31 → 211 constraints**, a different constraint
   polynomial because the alpha-fold is order-sensitive. Headroom is fine
   (`DNAC_PROVER_MAX_TRACE_WIDTH = 2560`, `stark_prover.h:80`). Also undefined in the doc: behaviour
   at tree capacity (the 2^24-th append — neither reject nor wrap is chosen), and §0 still cites
   `merkle_smt.h`/`merkle_smt.c`, **files deleted in the P1c cutover**.
   → **The doc needs revision before F1a can start.**

2. **The shield/unshield boundary — the real blocker, and it was mis-scoped.** What was tracked as
   "F2, the confidential-pool supply model" is **not a separate item**; it is answered by the
   boundary design. New doc: `dnac/docs/plans/2026-07-27-boundary-shield-unshield-design.md`
   (supersedes the 2026-07-16 C6 turnstile doc, which was comprehensively obsoleted — its dual-mode
   TX premise was outlawed by the S5 V4 wire **one day after C6 was written**, and 35 of its 55
   re-checked facts came back stale or false). User-locked shape: **dedicated TX types 12/13**
   (11 stays byte-identical, D7.1 intact), **two unsigned public slots** `pub_boundary_in/out`
   (publics 43 → 45), and **one combined re-ground with F1's D=24** so the vector regeneration and
   `num_qc` re-measure are paid once. **Its §3 red-team has NOT been run** — chartered at the
   consensus row, 8-13 agents, with a mandatory cost gate.
   ⚠ Two hard preconditions the doc pins as **G-DET-B-0**, because the pool balance would ride the
   same mechanisms: `state_root` currently substitutes tagged-empty sentinels on a transient DB
   fault (`nodus_witness_merkle.c:1218-1238`), and `nodus_witness_supply_get` returns an ambiguous
   -1 that makes the supply gate **skip entirely** (`bft.c:901-906`) while zeroed counters get
   hashed into every epoch_state leaf (`merkle.c:1105-1109`). Both are live, both are recorded in
   `nodus/BUGS.md`, **neither is fixed**.

3. **Why the pool cannot just be bolted on.** Two facts established by reading, not assumed:
   the supply counters `total_minted`/`total_burned` are **inside `state_root`** — hashed
   big-endian into every epoch_state leaf (`nodus_witness_merkle.c:1105`, `~:1154-1157`) — so the
   accounting model is a **determinism** constraint, not bookkeeping; and the pool is presently
   **unreachable in both directions**, because type-11 forbids a transparent leg (D7.1,
   `verify.c:591-604`) and the circuit cannot mint from nothing (balance accumulator must be zero
   at the last row, `conf_action_fold.c:288`, over 52-bit non-negative values).

4. **P2 recursion — a FULL upstream reference exists. `Plonky3/Plonky3-recursion`.**

   ⚠ **CORRECTION (2026-07-28). An earlier revision of this file stated "P2a's three core pieces
   have nothing to byte-match" and classified P2a as referenceless KAFADAN-risk. That was WRONG.**
   The 2026-07-27 grounding pass searched the **`Plonky3/Plonky3` repository** and correctly found
   no recursion there — then generalised that to "no reference exists". Recursion lives in a
   **separate repository of the same organisation**, which that pass never looked for. The right
   query was "who builds recursion on Plonky3", not "does Plonky3 contain recursion". Corrected
   after the user pushed back on the claim rather than accepting it.

   **PIN: `Plonky3/Plonky3-recursion` @ `b36339709a7a67ee9760fb578b3d4339fd983709`**
   (`b3633970`, 2026-07-06, no tags — pin by commit). Read it the same way as the main pin:
   `git show <pin>:<path>`, never checkout.

   Why it is usable, all verified on the clone:
   - **Licence `MIT OR Apache-2.0`** (`Cargo.toml:16` area, `LICENSE-APACHE` + `LICENSE-MIT`
     present) — compatible with this Apache-2.0 tree. No GPL hazard.
   - **Targets `p3-* = "0.6"`** (`Cargo.toml:50-73`: p3-batch-stark, p3-challenger, p3-fri,
     p3-goldilocks, p3-uni-stark) — the exact Plonky3 line DNAC migrated to at S2'.
   - **Goldilocks is a first-class, separately-tested configuration, and it is OURS.**
     `recursion/tests/goldilocks.rs:1-5`: *"Goldilocks uses a degree-2 extension (D=2), Poseidon2
     width-8, and 4-element digests — all distinct from the BabyBear/KoalaBear D=4, width-16,
     8-element configurations tested elsewhere."* That is DNAC's configuration exactly, and there
     is a dedicated `p3_circuit::ops::GoldilocksD2Width8`. The common upstream path is
     BabyBear/KoalaBear; the road DNAC took is the one explicitly covered here.

   **Piece-by-piece map — every P2 sub-design now has a reference:**

   | DNAC piece | Upstream file | Lines |
   |---|---|---|
   | **P2a** transcript-in-AIR | `recursion/src/challenger/circuit.rs` (+ `challenger_perm.rs` 102, `traits/challenger.rs` 137) | 440 |
   | **P2b** Merkle/MMCS-verify-in-AIR | `recursion/src/pcs/mmcs.rs` | 2572 |
   | **P2c** FRI-in-AIR | `recursion/src/pcs/fri/verifier.rs` (+ `fri/targets.rs` 1368, `fri/params.rs` 149, `backend/fri.rs` 852) | 1838 |
   | **P2d** constraint-check-in-AIR | `recursion/src/verifier/batch_stark.rs` 1324, `stark.rs` 502, `quotient.rs` 407, `periodic.rs` 231 | 2464 |
   | **P2e** WRAP + NODE composition | `recursion/src/recursion.rs` 1001, `examples/recursive_aggregation.rs` 1558 | 2559 |

   `pcs/whir/*` (~2.4k lines) is a DIFFERENT polynomial commitment scheme and is **not**
   applicable to DNAC, which is FRI-based. Ignore it.

   **P2a's two supposedly-unreferenced constraints are right there.**
   `recursion/src/challenger/circuit.rs:94-96` documents `duplexing()` as *"Matches native
   `DuplexChallenger::duplexing()` exactly"*, and the body contains both:
   - `:126` — `for slot in self.state.iter_mut().take(RATE).skip(num_absorbed)` = the rate clear
   - `:131` — `self.state[RATE] = circuit.add(self.state[RATE], length_tag)` = the length tag

   These are the in-circuit form of DNAC's `duplex_challenger.c:76-78` and `:80-82` — i.e. exactly
   the absorb-vs-squeeze preamble distinction the earlier pass declared unreferenceable.

   Directly relevant tests to mine: `recursion/tests/goldilocks.rs`, `challenger_transcript.rs`,
   `fri.rs`, **`zk_hiding_mmcs.rs`** (DNAC uses a salted/hiding MMCS), `arity4_mmcs_bus_balance.rs`,
   `zk_aggregation.rs`, `preprocessing.rs`, `test_lookups.rs`.

   **What this changes.** P2a moves from "referenceless crypto, argue it out with the user before
   delegating a line" to **"port against a pinned reference"** — the same P1a-P1d cycle: read,
   pin, byte-match, KAT. The KAFADAN rule's normal path is available; no bespoke design argument
   is required for the mechanism itself.

   **DS prefix — CORRECTED 2026-07-28: mechanism REFERENCED, only the VALUES are DNAC-owned.**
   An earlier revision here said "no upstream will cover it" — that conflated "no initial-state
   hook" (true, irrelevant) with "no reference for the mechanism" (false). DNAC applies the
   4-limb `"DNAC|ZK|FRI|TRANSCRIPT|V1"` prefix as **four ordinary observe calls** after a
   zero-state init (`duplex_challenger.c:96-103` — NOT a direct state write), and the in-circuit
   "observe a pinned constant" pattern exists verbatim upstream (`alloc_const` +
   `challenger.observe`, `targets.rs:796-800`). DNAC-owned remainder: the constant VALUES
   (`:32-37`) — a consensus value pin, runtime-KAT-bound (`:27-31`). No bespoke mechanism
   argument is needed for P2a. Caught by the user pushing back on "referansı yok" (again).

   **NOT YET VERIFIED — the honest limit of this pass.** Only the challenger's `duplexing()` body
   and the crate/test inventory were read. Whether the upstream semantics match DNAC's in every
   detail is unestablished; that is the first task of P2a, not a conclusion of this survey.

   **Scheduling (unchanged and still true):** P2a does **not** touch the shared verify surface —
   AIRs and lookups are caller-supplied descriptors (`batch_verify.h:112-123`, single call site
   `batch_verify.c:727`), so adding an AIR needs no edit to `batch_verify.c`, and P2b/P2c *mirror*
   `fri_verifier.c`/`poseidon2_mmcs.*` rather than modify them. **C3 and P2a are safe to run in
   parallel.** The one genuine collision is mechanical: F1a and P2a share
   `tools/plonky3_oracle/src/main.rs` (`const AGG_D` at `:14079`), the zk `Makefile`, and worst,
   `tools/vectors/.expected_hashes` — a **single 52-line file**.

   **⚑ K RE-DECIDED 2026-07-28: K = 4 → K = 2 (user-locked).** P2.0 chose K = 4 while
   believing no upstream recursion existed. The reference's aggregation API is
   **hard-shaped 2-to-1**: `prove_aggregation_layer` (`recursion/src/recursion.rs:661`)
   takes exactly `left` and `right`, separately typed, with separate verifier results;
   there is no slice, no `Vec<Proof>` and no loop over children anywhere in that file
   (searched — empty), and every entry point is documented "2-to-1 aggregation layer"
   (`:541`, `:648`, `:769`, `:891`, `:945`). ⚠ `recursion.rs:774` mentions an "arity-4
   proof" — that is the **MMCS (Merkle) arity inside a proof**, NOT the aggregation
   fan-in; the two must not be conflated. So K = 2 makes upstream's aggregation layer
   usable as P2e's reference, at the cost of one extra tree level per doubling; K = 4
   would have required writing the NODE with no upstream counterpart. Sections of P2.0
   that this invalidated (G-DET-4's 4-slot padding selector, the §3.2/F-R2-3 trace-size
   arithmetic, the four-way sorted-merge) were **REVISED IN PLACE 2026-07-28** — see the
   "K = 2 recompute" section of that doc: child-verify 15,567 perms (2^14, unchanged),
   NODE natural 2×15,567 = 31,134 → 2^15 (headroom condition ≤1,634 non-perm rows,
   P2e-validated), WRAP 76,105 → 2^17, **H_rec = H_wrap = 2^17 STANDS** (the F-R2-3
   inconsistency dissolves at K=2), interior padding 2×→4×, tree proofs 5461→8191=2N−1
   (N=4096 reconstruction labelled; N_max pinned at P2e), union bound 141.0 →
   **Q≈59 STANDS, margin +1.0 bit**. F-R2-3 RESOLVED; F-R2-4 (multiset-equality
   merge) now inline in G-DET-1, folded at P2e; F-R2-5 unchanged.

   **Challenger mapping, ORCHESTRATOR-verified 2026-07-28 (both sides opened).** All
   five DNAC state transitions have upstream circuit counterparts: T1/T2 →
   `observe` (`challenger/circuit.rs:337`), T3/T4/T5 → `sample` (`:351`), and the
   absorb-vs-squeeze split is `duplexing`'s `if num_absorbed > 0` guard (`:97`+), which
   skips both the rate clear and the length tag on a squeeze — exactly DNAC's
   `duplex_challenger.c:74`. Shape matches exactly: `impl CircuitChallenger<8, 4,
   Poseidon2Config>` with `new_goldilocks()` → `GOLDILOCKS_D2_W8` (`:307`).
   **A trap that was checked and does NOT bite us:** upstream binds the length tag only
   under `if !is_base`, where `is_base = config.d() == 1`. Our config is D2, so
   `d() == 2`, so the tag IS applied — consistent with DNAC applying it
   unconditionally. That branch exists for D1 base-field-challenge configs, which DNAC
   does not use.
   **The observe/observe_ext question is now ANSWERED (2026-07-28, both sides opened) —
   it is BOTH, and DNAC already carries the correct 1:1 split:**
   `dnac_duplex_observe_fp` ↔ `observe` (`circuit.rs:337`) ·
   `dnac_duplex_observe_fp2` ↔ `observe_ext` (`:366`) ·
   `dnac_duplex_sample_fp` ↔ `sample` (`:351`) ·
   `dnac_duplex_sample_fp2` ↔ `sample_ext` (`:378`).
   Upstream's `observe`/`sample` are the PRIMITIVES (one base element; duplex when the
   buffer hits RATE) and the `_ext` forms are WRAPPERS — `observe_ext` decomposes an
   extension element into D base coefficients and calls `observe` on each, `sample_ext`
   takes D samples and recomposes. DNAC does exactly that
   (`duplex_challenger.c:117-122`, `:134-140`). Basis ORDER also checked: native
   `observe_algebra_element` is `observe_slice(as_basis_coefficients_slice())`
   (`challenger/src/lib.rs:106-108` @ 82cfad73, `:105-107` @ 11cc5849 — identical at
   both pins), i.e. **c0 first**, matching DNAC's `observe_fp(v.a)` then
   `observe_fp(v.b)`.
   **Consequence, and it makes P2a SMALLER:** the AIR only has to constrain the
   BASE-element state machine. The fp2 surface needs no separate AIR — it decomposes
   into two primitive calls, and the extension level is handled in-circuit by a
   decompose/recompose gadget.
   **~~Unread~~ READ + MAPPED 2026-07-28 (FLEET 010: 2 zk-auditors; FLEET 011: independent
   verifier 15/15 CONFIRMED / 0 REFUTED; every load-bearing claim ALSO opened by the
   ORCHESTRATOR):** `pcs/mmcs.rs` (P2b) and the FRI surface (P2c) are fully mapped to
   DNAC's `poseidon2_mmcs.c` / `fri_verifier.c`. Facts the P2 designs build on:
   - ⚠ **The binary Merkle-walk constraint lives in `circuit/src/ops/mmcs.rs:81-207`**
     (same repo/pin), NOT in `pcs/mmcs.rs` — per level one perm row `merkle_path:true` +
     `mmcs_bit=direction`; siblings are op private data; mixed-height injection is a
     separate row, digest into `inputs[rate_ext..]`, combine order C(running, injected)
     == DNAC `poseidon2_mmcs.c:522`, same interleaving. AIR-level `mmcs_bit` placement
     constraint (`poseidon2-circuit-air`) still unread → P2b design work.
   - **F-S challenge order is IDENTICAL both sides** (`targets.rs:770-807` ==
     `fri_verifier.c:694-726`; both ORCHESTRATOR-opened): alpha → per-commit
     {observe, commit-PoW, beta} → final_poly → log_arities → query-PoW → indices after.
   - **Hiding/salt split:** upstream salts = circuit PRIVATE INPUTS
     (`targets.rs:595-600`), siblings = op private data (`SaltedMmcsProof` mmcs.rs:768);
     leaf preimage `[row‖salt]` per matrix == DNAC's caller-side append. Port rule:
     salt columns private + alu_recompose bus obligation (mmcs.rs:33-37).
   - **Real divergences (DNAC stricter, port must decide to keep):** unmatched roll-in
     DNAC REJECTS (`:613-615`) vs circuit connects-to-zero (`verifier.rs:1640-1643`);
     num_queries DNAC EXACT vs upstream lower-bound (`targets.rs:840-844`); lgmh bound
     DNAC 32 (two-adicity) vs circuit `Val::bits()` = 64 (GROUNDED:
     `field.rs:1056-1058` + Goldilocks P `goldilocks.rs:27` @ 82cfad73). DNAC-owned
     hardenings with NO circuit counterpart: empty-batch reject, z==x reject
     (circuit does bare `div`), FriError taxonomy.
   - **Port's main structural work:** public/private/op-data map (final_poly + PoW
     witness PUBLIC; siblings + opened values + salts PRIVATE; path digests op-data)
     and the u64 query index → bit-decomposed bool-pinned targets (`sample_bits` +
     `assert_bool` verifier.rs:1087-1089).
   - **Still unread** (named so the next session doesn't re-derive): `p3_circuit`
     builder semantics beyond decompose_to_bits (connect/div constraint meaning,
     div-by-zero), `tests/goldilocks.rs` + `tests/fri.rs`, circuit behaviour at
     lgmh∈(33,64], native-82cfad73 side of the roll-in divergence.

   **P2a DESIGN v2 GREEN-pending-code (2026-07-28).** Doc:
   `dnac/docs/plans/2026-07-28-p2a-transcript-in-air-design.md`. Round-1 red-team
   (FLEET 012, 1 agent) NOT-GREEN — 3 CRIT / 2 HIGH / 6 MED / 2 LOW, all
   ORCHESTRATOR-verified at source, ALL 13 FOLDED into v2 (constraint FORMS now
   committed, not prose: one-hot counters, merged eager-duplex rows, state
   threading + `sel_start` boundary, filler terminality, prefix_ctr chaining).
   **Two user-locked decisions:** (1) perm delegation = **INLINE 180-col
   embedding** (shipped `conf_action_fold.c` pattern; upstream table+CTL+bus NOT
   ported — `poseidon2_air` has no CTL columns and the shipped bus has never
   carried a permutation); (2) **recursion config NON-HIDING, `salt_elems=0`**
   (leaf stays salted) — dissolves the `batch_prover.c:581-589` salted+lookups
   fail-close for P2e's LogUp merge; leak argument = P2a §2 G-SEC-P2a-6.
   v1's booleanity claim RETRACTED (F9 — upstream `decompose_to_bits` asserts
   bool itself, `circuit_builder.rs:1212-1213`).
   **P2a-i1 DONE (2026-07-28, FLEET 013 + ORCHESTRATOR):** (a) oracle
   `dump-transcript-trace` mode landed (`plonky3_oracle/src/main.rs`, +513
   lines) — 8 scenario vectors (basic/rate_boundary/partial_absorb/
   squeeze_chain/pow_zero_bits/pow_nonzero/multi_instance/sample_bits_32),
   real-challenger tracing, upstream trigger predicates self-checked against
   post-conditions, composites cross-validated on clones; `.expected_hashes`
   52→60, `sha256sum -c` clean; (b) F7 closed — `test_duplex_challenger` Gate A
   pins its literal to the exported `DNAC_TRANSCRIPT_PROD_INIT_STATE` (recipe
   → `$(TRANSCRIPT_STACK)`), negative control executed (one-byte tamper →
   FAIL). zk `make test` ALL GATES GREEN, 70 binaries, 0 warnings; cargo build
   0 warnings. No version bump (zk-only, consensus-inert).
   **P2a-i2 DONE (2026-07-28, FLEET 014 + ORCHESTRATOR):** `transcript_air.{c,h}`
   — the DuplexChallenger control-AIR, `TAIR_WIDTH = 281` (101 control + INLINE
   180-col poseidon2_air embed), all §0.5 constraint forms discharged;
   `test_transcript_air` = 8 honest oracle scenarios (native-replay
   cross-checked) + 20 constraint-form negatives + 5 bit-gadget negatives
   (incl. the x+p alias and a lied is-zero witness). **Four beyond-doc
   additions user-approved** (is_pow column; the canonicality gadget as a
   degree-3 is-zero ADAPTATION of assert_bits_canonical, hand-verified,
   runtime shape-guarded; the il[4]=0 op-row guard; il/buffer threading on
   sample rows) — recorded in the design doc §0.5/§5.
   **P2a-i3 DONE (2026-07-28, FLEET 015: 2 zk-auditors + ORCHESTRATOR fixes).**
   A1 form-by-form: **26 GROUNDED / 8 JUDGMENT / 1 KAFADAN** — zero KAFADAN in
   the constraint code; the one KAFADAN was a DOC miscount ("20+5" negatives
   when there were 20 — fixed here, in the design doc and in root CLAUDE.md).
   A2 independent second-witness hunt (design doc withheld): **1 HIGH / 2 MED /
   3 LOW / 1 INFO**. **The HIGH is FIXED, not deferred:** a trace ending in a
   sampling row had a FREE challenge (no transition constraints on the last
   row) — `dnac_transcript_air_eval_trace` now enforces "final row is
   `sel_filler`"; test N20b (trace TRUNCATED at a sample row, no filler to
   trip terminality) is caught with exactly 1 violation, proving the new
   constraint carries it alone. Also folded: `eval_trace` saturates instead of
   overflowing `int`; the sentinel's "per-trace" claim corrected to per-row;
   the header now warns that `eval_row` standalone is a WEAKER system (next-row
   one-hot completion lives in that row's own local block). **10 new negatives**
   close A1's "discharged but untested" forms → suite = 8 accepts + 30
   negatives. Named consumer obligations carried to P2c/P2e: `is_pow` is a free
   column (composition must pin PoW rows + the witness-observe adjacency),
   `sel_start` may appear anywhere with no instance-ID column (bind row TYPES),
   non-canonical cells alias so the commitment layer must canonicalize.
   zk `make test` **71 binaries** ALL GATES GREEN, 0 warnings. No version bump
   (consensus-inert).
   **P2b DESIGN v2 (2026-07-28) — written, red-teamed, NOT-GREEN, folded.**
   Doc: `dnac/docs/plans/2026-07-28-p2b-mmcs-in-air-design.md`. O2 closed
   FLEET 010's last hole: the AIR-level `mmcs_bit` placement constraint is
   `P3rec poseidon2-circuit-air/src/air.rs:984-1002` (gated pair, degree 3),
   plus the `mmcs_index_sum` recurrence `:1022-1029`. User-locked at O3:
   preprocessed selectors + slice 1 = same-height binary walk.
   **FLEET 016 (2 red-teamers) — BOTH lenses independently found the SAME
   CRITICAL:** DNAC's preprocessed commitment is PROVER-SUPPLIED (committed at
   `batch_prover.c:820-825`, wire `fri_proof_codec.c:851`, verifier only checks
   PRESENCE `batch_verify.c:149`; no pinned comparison exists in the tree), so
   an all-zero selector table makes every gated constraint vacuous. Upstream
   does not have this hole structurally: its preprocessed commitment is NOT a
   proof field (`Plonky3 11cc5849 batch-stark/src/proof.rs:29-38`) but lives
   verifier-side in `CommonData` (`common.rs:47-51`), and the AIR says so:
   *"committed at setup time and cannot be changed"* (`air.rs:933-935`) —
   **DNAC has no setup time.** NOT live-exploitable: `shielded_verify.c:214-215`
   declares no preprocessed and `batch_verify.c:149` rejects an undeclared
   commit. **User-locked fix: PIN-1** — the P2b verify entry compares the
   preprocessed root against a consensus constant (S2'-d precedent; constant +
   generator KAT in the `shielded_domsep` style). **PIN-2** (forced by the
   port): `prep_next = 1` mandatory — the gates read the NEXT-row window
   (`air.rs:945-951`, `:987`) and with 0 the verifier zero-fills
   (`batch_verify.c:696-707`) while the prover uses real values
   (`batch_prover.c:311-313`) ⇒ silent vacuity, not fail-close.
   All 17 findings folded into v2 (opened-rows public equality, leaf zero-state,
   final-row threading, ungated block + degree horn, PaddingFreeSponge absorb
   semantics, bit-order correction — a KAT CANNOT settle it, OBL-1/2/3 named
   consumer obligations). **Nothing on the preprocessed path may be built
   before PIN-1 and PIN-2 exist.**
   **P2b PIN SLICE DONE (2026-07-29, FLEET 017: 1 code-executor + independent
   verifier 8/8 CONFIRMED + ORCHESTRATOR).** `mmcs_air_table.{c,h}` +
   `tests/test_mmcs_air_table.c` (53 checks) + Makefile; tests 71 → **72**,
   ALL GATES GREEN, 0 warnings, consensus-inert (no version bump).
   - **PIN-1 established:** deterministic row-type table generator
     (`is_leaf`/`is_compress`/`is_final`; leaf-row count derived from the
     PaddingFreeSponge schedule `poseidon2_mmcs.c:41-72` ↔ 11cc5849
     `sponge.rs:172-204` — exact-multiple ⇒ NO trailing permute) +
     `DNAC_P2B_PREP_ROOT[4]` = {0xfcc92a4ebbd79fc4, 0xb0c4a93617190754,
     0x3034244cd5325682, 0xa5c49b90e07500b9} + runtime KAT (T3: table →
     `dnac_prover_coset_lde_bitrev`(lb=2, shift=7) → `dnac_p2_mmcs_commit_mixed`
     == constant — the EXACT `batch_prover.c:787-826` pipeline, so T4 reads the
     same root back out of a REAL `dnac_batch_prove` proof) + fail-close
     comparator `dnac_p2b_prep_root_check` (caller-side, S2'-d style;
     `dnac_batch_verify` signature untouched). ⚠ MECHANISM pin against the
     REFERENCE schedule {2 mats, widths {8,5}, depth 4, H=16}; production
     constant re-pins when P2c fixes the real schedule (header says so).
   - **PIN-2 evidence:** N2a same proof + `prep_next=0` descriptor →
     BV_ERR_SHAPE (`batch_priming.c:352-363`); N2b with next-row openings ALSO
     trimmed (the shape a malicious prover would ship) → BV_ERR_FRI, asserted
     != SHAPE so the negative is not vacuous; N5 proves the harness's
     prep_next-consuming constraint is live (tampered main → PROVER_ERR_VERIFY).
   - **Bit order G-DET-P2b-3 DECIDED (user-locked): A1 — LSB-first, direction
     bits as PUBLICS.** New grounding in the design doc §0: upstream PRODUCTION
     never uses `mmcs_index_sum` (`ops/mmcs.rs:137/158/181` all pass None; the
     only Some is an example); real binding is per-level `path_bits[l]` from
     LE `sample_bits` (`recursion/src/pcs/mmcs.rs:365-367`,
     `circuit_builder.rs:1203-1217`, `fri/verifier.rs:615`) — LSB-first, same
     as native `poseidon2_mmcs.c:581-590`. Slice 1 has NO `idx_acc` column.
   - ⚠ NOT yet enforced anywhere: no verify entry calls the comparator yet, and
     nothing forces `prep_next=1` on a descriptor — both become real in the
     P2b/P2c composition entry.
   **P2b AIR SLICE 1 DONE (2026-07-29, FLEET 018: 1 code-executor + independent
   verifier 6/8 CONFIRMED / 2 description-level REFUTED (no code defect) +
   ORCHESTRATOR line-by-line).** `mmcs_air.{c,h}` — the same-height binary
   MMCS-verify control-AIR, `MAIR_WIDTH = 245` (1 dir + 64 pos + INLINE 180-col
   poseidon2_air embed, UNGATED, degree ≤ 3), all §0.5 forms discharged:
   placement pair (air.rs:984-1002 port), leaf zero-state + PaddingFreeSponge
   overwrite/carry, opened-rows public equality, **A1 index binding (LSB-first,
   dir bits as publics, NO accumulator)**, final-row threading + root equality,
   dir booleanity (+ dir=0 off compress — §4.6 settled), terminality in
   eval_trace, schedule conformance (n_rows from the pinned table only).
   Publics: `[root 4][dir bits depth][opened rows total_width]` — P2c binds to
   these offsets. `test_mmcs_air`: 5 native-replay accepts (3 configs incl.
   leaf==1, both sponge residue classes, NON-PALINDROMIC indices; byte-match
   INHERITED from P1b/FP1c — honest label) + 6 fail-close config gates + 25
   negatives (3 fail-close in mechanism) incl. the BIT-REVERSED-index
   composition trap (N6) and 4 exact-count isolations.
   Tests 72 → **73** ALL GATES GREEN, 0 warnings, consensus-inert.
   **4 BEYOND-DOC user-approved 2026-07-29** (design doc §5): pos[64] step
   one-hot (row-index-dependent forms need a carrier; upstream's in_ctl
   machinery unported; pinned 3-col table unwidenable), MAIR_MAX_STEPS=64,
   no-padding-config reject, main_next-without-prep_next reject (PIN-2 shape).
   **Carried obligation (verifier residual):** pos rigidity assumes typed rows
   form a PREFIX — a generator property under PIN-1; re-check at the P2c
   production-table pin (design doc §5).
   **P2b i-ROUND RED-VERIFY DONE (2026-07-29, FLEET 019: 2 zk-auditors,
   ALL FOLDED — design doc §5.1).** A1 form-by-form: 16 GROUNDED / 6 JUDGMENT /
   1 KAFADAN (the KAFADAN was AGAIN a count claim — "7 fail-close" was
   unsupported; suite recounted above). A2 second-witness hunt (doc withheld):
   **NO second witness constructible** under generator-exact table +
   verifier-constant cfg + canonical publics; 16-entry could-not-break table.
   Folded fixes: (1) **publics canonicality now FAIL-CLOSE in the eval entry**
   (A2-F1 MED — fp() aliases x/x+p while the native seam is representation-
   sensitive; N25); (2) mmcs_air_table.h residue claim CORRECTED (A2-F2
   KAFADAN — ceil not injective; the table encodes the ROW COUNT only);
   (3) **NEW OBL-4** (A2-F3 MED): PIN-1 binds the SCHEDULE not the cfg —
   {2,{8,5},4} and {1,{16},4} share one root; composition must pin cfg
   independently; (4) "example-only" mislabel fixed (A2-F4 — upstream's
   accumulator is production-constrained but DISABLED by the production op);
   (5) leaf==1 branch coverage (CFG_C accept + N24) + row-0 anchor negative
   (N23) + citation drifts. eval_trace table-gap slack recorded as accepted
   (soundness-neutral; binding artifact is PIN-1 + OBL-4). Gate re-run GREEN.
   **P2c DESIGN DONE + RED-TEAMED (2026-07-29, FLEET 020: A1 zk-auditor
   doc-given + A2 red-teamer BLINDED-bare-spec; ALL FOLDED — doc §3.1).**
   Doc: `dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md` —
   GREEN-pending-code. Four user-locked decisions: slice 1 = FOLD-WALK +
   TERMINAL only (open_input = next slice; MMCS binding at composition);
   P2b slice-2 (mixed-height) DEFERRED to the open_input slice (grounded:
   commit-phase walk uses SAME-HEIGHT `fri_verifier.c:585`, `_mixed` only
   at input-open `:392`); all 3 DNAC-strict divergences KEPT in-AIR (new
   grounding: upstream NATIVE also rejects unconsumed roll-ins 82cfad73
   verifier.rs:492-497; lgmh>32 upstream circuit PANICS at build —
   goldilocks two_adic_generator assert :527-530@82cfad73 /:547,:550
   @11cc5849); preprocessed PIN path, NO P2a retrofit. Design: `fri_air`
   control-AIR, NO embedded permutation (hash-free fold walk), 20 main
   lanes, one row per chain-step/fold-phase, x0 via DERIVED recurrence
   `x_{r+1}=x_r²·(1−2b)` (A1-CONFIRMED by independent algebra + A2
   could-not-break), publics `[bits lgmh][betas 2R][f_init 2][ro 2|RI|]
   [final_poly0 2]`. FLEET 020 catches, all design-time, all folded:
   **2 CRITICAL — C4 t1 SIGN (both lenses independently; folds at
   reflected challenge 2x0−β) + f_init READ BY NO CONSTRAINT (walk had no
   start boundary)**; 2 HIGH (last-fold-row gating; handoff-copy drops
   bit_1 factor); 3 MED (pos prep-vs-main contradiction; OBL-P2c-1 shape
   precedence; OBL-P2c-2 query multiplicity — both new composition
   obligations); + W=7 pin, degree ≤3 inclusive-of-gate restatement,
   G7 completeness. Consumer-obligation ledger now OBL-1..4 + OBL-P2c-1/2
   + typed-prefix residual.
   **P2c SLICE-1 IMPLEMENTED (2026-07-29, FLEET 021: 2 code-executors +
   2 independent verifiers + ORCHESTRATOR line-by-line + O9).**
   021a `fri_air_table.{c,h}` + `test_fri_air_table` (192 checks): table
   generator (73 prep cols = 8 flags + g_pow2 + GLOBAL 64-wide pos one-hot;
   pair-gates is_chainpair/is_handoff/is_foldpair/is_terminal/is_rollin
   emitted by the generator so every AIR transition is gated by ONE prep
   cell), 13-check structural validator (typed prefix, C3 multiplication
   count, placement-vs-count isolation), `DNAC_P2C_PREP_ROOT[4] =
   {bc18e697c2e82726, 249ab7d1a3b19403, e4b0ab20bf65f146, 1be1561acee2167c}`
   (MECHANISM pin, ref cfg lgmh=13 rollins {11,9}; ORCHESTRATOR-derived via
   --print-root; unfilled-placeholder contract: comparator rejects
   EVERYTHING until filled) + KAT through the real batch_prover LDE→commit
   pipeline. PIN-2 posture CORRECTED (O6 B1): at width 73 > 64 a
   prep_next=0 descriptor dies on the SHAPE guard (batch_verify.c:696-701),
   stronger than P2b's zero-window path.
   021b `fri_air.{c,h}` + `test_fri_air`: the fold-walk control-AIR, 21 main
   lanes (doc said 20 — 5th count-KAFADAN, in the DESIGN DOC; code derives
   FAIR_NUM_COLS so it cannot drift), NO embedded permutation, degree ≤ 3
   incl. the single prep gate, all §0.5 forms C2-C6 + §0.5b recurrence.
   Suite: 5 native-replay accepts (leaf/recursion/lgmh-4-hand-checked; every
   phase x0 cross-checked vs the native closed form AND f' vs
   fri_fold_row_fp2) + 8 cfg gates + 37 negatives (24 exact-count) + 19
   assertions — incl. the four FLEET 020 mandatory catches (t1-sign N1,
   free-f_init N2, handoff-copy N3, last-row N4a/b). O9 root-caused the one
   red: N6 expected 2 but the predecessor's C4k also reads the tampered b'
   (incoming edge, same accounting N7 already did) → expectation fixed to 3,
   AIR itself defect-free. Both verifiers: 021a 10 CONF/3 REF (all folded),
   021b 15/15 CONFIRMED / 0 REFUTED. zk make test **75 binaries ALL GATES
   GREEN, 0 warnings** (ORCHESTRATOR-run, twice). Consensus-inert (type-11
   REJECT; nothing links fri_air outside its own test) → no version bump.
   NOT YET ENFORCED (unchanged ledger): PIN-1-P2c comparator uncalled,
   PIN-2 descriptor unforced, OBL-P2c-1/2 composition duties, sibling `s`
   unbound until P2b composition.
   **P2c SLICE-1 i-ROUND DONE (2026-07-29, FLEET 022: 2 zk-auditors, ALL
   FOLDED — GREEN).** A1 (doc+code+3 pins): 41 GROUNDED / 7 JUDGMENT /
   1 KAFADAN (stale "design says 20" quote — the doc had been corrected
   AFTER the header was written); every §0.5 form discharged, ALL counts
   survived re-counting (a slice first), degree table re-derived ≤3, all
   24 exact violation counts re-derived from the constraint graph. A2
   (BLINDED, code only): **0 second witness / 22 could-not-break** — full
   six-pair transition-cell enumeration clean, lgmh=2/3 edges compose,
   fold arithmetic == native barycentric closed form incl. β=±x0
   degenerates. t1 sign + x0 recurrence now confirmed by THREE independent
   derivations each. Folds: TWO NEW composition obligations — **OBL-P2c-3**
   (C3a's `is_first_row` is a caller flag anchoring the whole x0 chain →
   composition must wire the real first-row selector; A2-F8) and
   **OBL-P2c-4** (final-height reduced opening must be ZERO — native
   fri_verifier.c:480-487 / upstream :647-651; rule lives in open_input,
   slice-1 AIR accepts any value there; A1-F3) — both in fri_air.h + doc
   §0.6; OBL-4c REGROUNDED (root DOES pin R/RI — residual is the
   table↔cfg-argument seam); stale quotes + P3→P3rec attribution + 2
   wrong-file cites fixed; DOC-CITE BASELINE notes added (RESUME practice)
   for the ±3-line doc drift. Suite re-run post-fold: **75 binaries ALL
   GATES GREEN, 0 warnings** (ORCHESTRATOR).
   **open_input slice v1 DESIGN red-teamed (2026-07-29, FLEET 023: A1
   grounding + A2 blinded) — NOT-GREEN, v2 revision pending USER
   RATIFICATION.** Doc: `dnac/docs/plans/2026-07-29-p2c-open-input-mixed-
   mmcs-design.md`. A1 (11 GROUNDED/5 JUDGMENT/1 KAFADAN): §0 grounding
   SOUND — coset GENERATOR factor (absent from fold x0, present in
   open_input, both sides), cross-batch alpha_pow persistence +
   one-big-Horner==per-column algebra, z==x preserved by div-unsat, native
   final-height-zero (OBL-P2c-4's home), mixed-MMCS injection combine order
   — verified at both pins. A2 (BLINDED, 3 CRIT/4 HIGH/5 MED, 3 second
   witnesses): the §0.5 CONSTRAINT SKETCH stated its bindings as PROSE not
   constraints — closeout rows disconnected from the accumulators (F1),
   x-on-accumulation-row not bound to the capture register (F2), p_z/z
   "publics-bound" with no equality (F3), group-boundary UNSAT without
   pair-gates (F5), lb roll-in slot fri_air reads left unexported (F6,
   cross-seam forgery), h_max==lgmh ungated (F7), + F8-F12. ALL fixes
   known + mechanical, folded into doc §5 + a v2-required list. **LOOP
   ("loop kur bitene kadar") HALTED here per its NOT-GREEN charter.** Loop
   deliverables (FLEET 020-023, ~1.865M subagent tokens, 15 agents): P2c
   slice-1 SHIPPED (fri_air + table, 75 binaries GREEN, both verifiers
   CONFIRMED) → i-round GREEN (2 new obligations OBL-P2c-3/4) → open_input
   v1 red-teamed NOT-GREEN.
   **open_input v2 (P-1/P-2/P-3 ratified at recommended) red-teamed
   2026-07-29, FLEET 024 — NOT-GREEN AGAIN (2nd consecutive).** A1
   re-grounded 11 G/2 J/4 K; A2 BLINDED independently reproduced the two
   core holes as full second witnesses + 2 more: F1 (the `is_accpair`
   two-sided gate disconnects every closeout row — closeout `ro` free, and
   the dual reading is a completeness break; fix = ONE-SIDED current-row
   gate), F2 (k capture registers with NO persistence/hold constraint —
   free at every read), F4 (dedicated lb-zero checkpoint rows sever the acc
   chain both sides), F5 (index-bit booleanity is an UNDECLARED cross-AIR
   dependency on fri_air.c:342). v2 reproduced v1's write-key/read-key class
   one level down. 8 v3 fixes known + grounded (doc §7): one-sided carry
   gate, explicit x_h hold, per-row capture seed copy, lb-zero folded onto
   an acc row, in-OI bit booleanity, degree-relief `t` column, roll-in
   set-equality duty, PIN-1-OI prerequisite block. **LOOP HALTED per
   RED-TEAM ÖLÇEĞİ item 3** (2 non-convergent rounds + gate finding errors
   in minutes-old design = expensive writing round; 3rd round needs
   explicit user approval). RECOMMENDATION: implement-with-TDD (executor
   writes each constraint explicitly; the impl red-verify reads REAL code —
   the fri_air slice-1 path that worked) OR park.
   **USER PICKED implement-with-TDD. open_input fri_oi_air SHIPPED
   (2026-07-29, FLEET 025: 2 code-executors + 2 verifiers + ORCHESTRATOR
   O9).** 025a `fri_oi_air_table.{c,h}` + test (150 checks): the
   accumulation schedule generator (chain rows n_chain=lgmh with
   INTERLEAVED capture blocks [seed][cum_h=lgmh-h squarings][store] per
   height, then DESCENDING acc groups each ending in ONE closeout, then
   padding), 10-check structural validator, `DNAC_P2C_OI_PREP_ROOT =
   {4bc948ef32b400c0, f736ee0aeca1140e, 496968789dfe55be,
   b4e0665ff6700e66}` (mechanism pin, ref cfg lgmh=4 H={4,2} lb=2) + KAT.
   Verifier 8/0. 025b `fri_oi_air.{c,h}` + test (5 accepts + 32 negatives):
   the hash-free reduced-opening accumulation control-AIR — ALL 6 v3 fixes,
   the two v1/v2 CRITICAL holes now closed WITH constructed-second-witness
   tests: **C3f ONE-SIDED carry (last-acc→closeout FIRES ⇒ closeout ro ==
   accumulation, closes A2-F1) + C2e UNGATED register HOLD (x_reg globally
   constant, closes A2-F2 — executor strengthened past the spec's
   store-exempt literal)** + C2a/C2d seed anchor + per-row g-resume (F3) +
   C5 lb-zero folded onto an acc row, no sever row (F4) + C1c in-OI
   booleanity (F5) + C3e degree-relief t (deg ≤3). x_h cross-checked vs the
   native coset form at every store row; exponent identity re-derived by
   the verifier. N32 root-caused (ungated C2e spans padding → x_reg pinned;
   AIR correct+stricter, test fixed + N32b proves the hold fires on
   padding). Verifier 6/6 CONFIRMED, 0 REFUTED, 0 CRITICAL. O9 make test
   **77 binaries ALL GATES GREEN, 0 warnings** (ORCHESTRATOR). FLEET 025 =
   787.6k tokens (under est). implement-with-TDD delivered what 2 design
   rounds could not. Consensus-inert, no version bump. NOT-YET-ENFORCED
   (composition scope): PIN-1-OI comparator uncalled, p_x↔MMCS + α/z↔
   transcript seams, OBL-P2c-3 row-0 selector, roll-in set-equality
   (OI.H ⊇ fri_air.rollin), multi-query. **P2b slice-2 mixed-height MMCS
   SHIPPED (2026-07-29, FLEET 026: 2 code-executors + 2 verifiers + O9).**
   Commit 5685f46d checkpointed the P2c work first (user "commit sonra
   slice2"), then a fresh worktree @ that HEAD. NEW module (shipped mmcs_air
   untouched). 026a `mmcs_mixed_air_table.{c,h}` + test (144 checks): the
   mixed schedule (leaf over the tallest group → per-level compress +
   injection block iff a group height == max_h>>(l+1)), `DNAC_P2C_MMIX_PREP_
   ROOT = {d0380af189cf4999, fe79194f82938956, 53616f3d705958cb,
   622631697e3f65f6}`. Verifier 10/0. 026b `mmcs_mixed_air.{c,h}` + test
   (5 accepts + 6 gates + 19 negatives): the injection-row AIR arithmetizing
   `dnac_p2_mmcs_verify_mixed`. LOAD-BEARING new form — **inject-compress
   C(running,injected) running-FIRST (native poseidon2_mmcs.c:522), the
   N-order swap caught (12 viol)**. Beyond-doc RDIG carry column (the running
   digest is non-adjacent to its inject-compress — inject-leaf rows sit
   between; SEEDED/HELD/READ, fully pinned, mirrors slice-1's pos column).
   HONEST-LABEL held: the native has NO verify-side per-matrix reduced-index
   /level check (OPEN-side only, :434-439) → declared OBL-5 composition seam,
   NO fabricated KAFADAN constraint (verifier CONFIRMED). Native-replay
   accepts byte-match the intermediate digests. Verifier 11/0 CONFIRMED, 0
   REFUTED. O9 make test **79 binaries ALL GATES GREEN, 0 warnings**. FLEET
   026 = 792k tokens. Consensus-inert, no version bump.
   **▶ ALL native FRI-verify pieces now have in-AIR counterparts:**
   transcript (P2a `transcript_air`), MMCS same-height (P2b-s1 `mmcs_air`),
   MMCS mixed-height (P2b-s2 `mmcs_mixed_air`), fold-walk (P2c `fri_air`),
   open_input accumulation (P2c `fri_oi_air`). Each standalone + consensus-
   inert; EVERY pin (PIN-1 for all 5 tables, PIN-2 shapes) and cross-AIR
   seam (p_x↔MMCS, α/z↔transcript, direction-bits↔shared-index, OBL-P2c-1..4,
   OBL-5 reduced-index, roll-in set-equality, multi-query) is deferred to the
   composition entry. Loop grand total 020-026: ~3.68M subagent tokens, 25
   agents. NEXT AFTER 026 was the COMPOSITION ENTRY; its slice 1a is DONE ↓.
   **COMPOSITION s1a — FOLD EVALUATORS SHIPPED (2026-07-29, FLEET 027:
   2 code-executors + 2 verifiers + ORCHESTRATOR line-by-line + O9).**
   User locked 4 composition decisions (all recommended): (1) verify-statement
   = the 5 AIRs as 5 instances of the EXISTING dnac_batch_verify
   (batch_verify.h:112-132 is already multi-instance — no new STARK infra);
   (2) publics aliasing = SHARED-PUBLICS (the s1b entry derives every
   instance's publics from ONE decoded statement; p_x binding at s2 extends
   fri_oi publics); (3) ALL pin enforcement in ONE composition entry;
   (4) small slices + implement-with-TDD. Hidden prerequisite surfaced BEFORE
   dispatch: the batch descriptor needs `air_eval(dnac_stark_folder_t*)`
   (stark_constraints.h:284-291) and the 5 AIRs only had u64 test evaluators
   → s1 split into s1a (fold evaluators) + s1b (entry). SHIPPED s1a: 5 NEW
   modules `{transcript,mmcs,mmcs_mixed,fri,fri_oi}_air_fold.{c,h}` —
   `dnac_*_fold_bind(cfg, dnac_stark_air_t*)` with MODULE-STATIC cfg snapshot
   (air_eval carries no ctx; shared surface untouched; bind-before-verify,
   single-thread, REJECTED BIND DISARMS — verifier-B H1 fold) — each a
   1:1 TRANSCRIPTION of its u64 evaluator (emission order pinned = u64 order;
   every block cites the u64 line; perm-embed AIRs call the SHIPPED
   `dnac_poseidon2_fold_eval` UNGATED; transition forms ×is_transition; u64
   eval_trace terminality gates became EXPLICIT is_last_row boundaries) + 5
   equivalence tests (T-EQ honest traces via #include of the SHIPPED test
   builders — zero fork; T-CNT step-count formulas re-derived; T-NEG tampers
   with EXACT u64-violation-count agreement incl. FLEET-020's four + oi
   N-F1/N-F2; T-TERM single-constraint isolation; T-RAIL; T-DISARM).
   Verifier A 10/10 CONFIRMED; verifier B 8 CONFIRMED / 1 REFUTED (H1
   disarm — FIXED in-slice + tested; M1 count-KAFADAN banners recounted).
   ⚠ s1b MUST size log_num_qc for DEGREE 4 (×is_transition pushes the
   transition families 3→4 in ALL FIVE folds — load-bearing: terminality
   pins only primary row types, not pair gates, else cyclic wrap; documented
   in every fold header). ⚠ mmcs/mmix fold terminality is 1-cell (is_pad /
   type-sum) vs the u64's 6-cell gate — residual leans on PIN-1
   TYPE_EXCLUSIVE, enforced at s1b. G4a schedule-conformance + G6 publics
   canonicality are S1B ENTRY DUTIES (folder publics are gold_fp_t; the
   entry must canonicality-check decoded publics BEFORE the folder). O9
   ORCHESTRATOR-run: zk make test **84 binaries ALL GATES GREEN, 0 warnings**
   (tests 79 → 84). FLEET 027 = 1.094M subagent tokens (est 0.7-1.0M).
   Consensus-inert, no version bump, UNCOMMITTED (user command awaited; ~9
   older commits also unpushed). NEXT: **s1b — the composition verify entry**:
   one entry decodes a statement, derives all 5 instances' publics from it
   (shared-index alias), calls the 5 dnac_*_prep_root_check comparators +
   hard-codes prep_next=1 + pins cfg scalars independently of the roots
   (OBL-4c/OBL-4-MMIX), enforces OBL-P2c-1 shape precedence, G4a/G6, sizes
   log_num_qc for degree 4, honest round-trip (single query) + PIN negatives.
   Then s2 p_x↔MMCS, s3 α/z/β↔transcript + ro-export↔f_init/roll-ins;
   multi-query (OBL-P2c-2) after. Type-11 still REJECT.
   **s1b — COMPOSITION VERIFY ENTRY SHIPPED (2026-07-30, FLEET 028: 1
   code-executor ×3 tur + 1 verifier + ORCHESTRATOR).** `fri_statement.{c,h}` —
   `dnac_p2_fri_statement_verify`: 7 fail-close adım (G6 kanonluk + bit rail →
   composed prep-root PIN + prep_map=={0,1,2} → pinli cfg'ler + fold_bind ×3 →
   G4a degree_bits=log2(tablo satırı) → log_num_qc KODDA türetilir
   (symbolic.rs:70-78; degree 4 ⇒ 2) → shared-index publics kurulumu →
   dnac_batch_verify is_zk=0/nrc=0/salt=0). REF statement = `prep_pair`
   fixture'ından türetilen TUTARLI cfg seti (fri{lgmh5,lb2,rollin{4},Q2} +
   mmcs-round0{1,{4},d4} + mmix{2,{1,1},{32,16},d5}); alias haritası
   kaynak-pinli (mmix dir=B[lgmh−depth+..] :252-255; mmcs dir=B[mla+..]
   :557-558/:585-588). `DNAC_P2S_PREP_ROOT` DOLU (ORCHESTRATOR bağımsız
   --print-roots, executor'la birebir): {eaff9f3c7d034d1b, 884685112df9a2a0,
   04df3d2a81697631, 5084f428a46e88f5}. **İKİ HALT bulgusu (kullanıcı
   kararlarıyla çözüldü):** (1) shipped fri_oi_air GERÇEK proof'u tarif
   EDEMİYOR — heights[son]==lb ŞART (fri_oi_air_table.c:92-95) ama native
   lb-zero KOŞULLU (fri_verifier.c:482-487) = COMPLETENESS defekti → s1b
   3-instance, oi düzeltmesi KENDİ diliminde (sıradaki iş); (2)
   batch_prover.c:288 pw>64 reddi + pl[64]/pn[64] sabit pencereler → prover
   73/136-kolon tabloları PROVE EDEMİYORDU → kullanıcı onayıyla heap-alloc'a
   (tek hunk, semantik değişmez, test_batch_prover 371/0 byte-match dahil tüm
   regresyonlar GREEN). Verifier 8 CONF / 0 REF / 1 UNVERIFIABLE(runtime —
   ORCHESTRATOR kapadı: placeholder 107/0, dolu 117/0 RT-1 OK); M1 (N-CFG
   sessiz kaçış) + M2 (mmcs arity-eşitliği varsayımı seam listesine) + L3/L4
   atıf düzeltmeleri FOLDED. Tek-pin sapması meşru (batch_prover.c:786-822 tek
   mixed commit — per-tablo root yok). O9: **85 binary ALL GATES GREEN 0
   uyarı** (tests 84 → 85). Konsensüs-inert, version bump yok, UNCOMMITTED.
   Dürüst seam'ler (header §HONEST LABELS): transcript-yok (s3), oi-yok
   (lb-fix dilimi), round 0 + tek query, p_x↔MMCS açık (s2), arity-eşitliği
   pinli şekle bağlı.
   **oi lb-kapısı DÜZELTİLDİ (2026-07-30, FLEET 029: 1 executor + 1 zk-auditor
   red-verify + ORCHESTRATOR).** TEK davranışsal değişiklik:
   fri_oi_air_table.c cfg kapısından `heights[son]==lb` ŞARTI silindi —
   final-closeout artık KOŞULLU, native fri_verifier.c:482-487'nin aynası
   (lb ∈ H ise C4b/C5 aynen; değilse `is_final_closeout` hiçbir satırda 1,
   n_lb_zero=0 — her iki türetim de cfg'den, u64+fold uyumu eşdeğerlik
   testleriyle). AIR/fold KOD değişikliği SIFIR (yalnız yorum/honest-label);
   `DNAC_P2C_OI_PREP_ROOT` DEĞİŞMEDİ (ref cfg lb'li, KAT aynı kökü türetir).
   Yeni testler: NOLB {lgmh5,lb2,H={5,4}} (gerçek prep_pair şekli!) + NOLB_MB
   honest kabuller, sahte-final-closeout validator reddi, "height below lb"
   negatifi; tablo testi 150→201 check. Auditor: 7 GROUNDED / 3 JUDGMENT /
   1 KAFADAN, 0 CRIT/HIGH, **ikinci tanık KURULAMADI** (A2-F1/A2-F2
   kapanışları lb'den bağımsız — kodda gösterildi). Kapatılan bulgular:
   F8 KAFADAN (table.h "yalnız num_queries kaçar" → lb'siz sınıfta log_blowup
   da tabloya girmez; cümle düzeltildi, cfg-pin yükü load-bearing etiketlendi)
   + F9 (fri_air.h OBL-P2c-4 koşullu forma revize: composition BOTH — roll-in
   ⊆ OI.H çapraz kontrolü [lb fri_air'da KABUL, final_h=lb+lfpl,
   fri_air_table.c:64/:89] + final-height roll-in ancak lb'li oi cfg'yle).
   Ayrıca ORCHESTRATOR'ın tasarım notundaki "lb aralık dışı" iddiası
   executor'ca çürütüldü — notta adıyla geri çekildi (KAFADAN dersi
   lessons.md'de). O9: **85 binary ALL GATES GREEN 0 uyarı**. Konsensüs-inert,
   pin/vektör değişimi yok, UNCOMMITTED.
   **s1c — oi STATEMENT'A KATILDI (2026-07-30, FLEET 030: 1 executor + 1
   verifier + ORCHESTRATOR).** fri_statement 3 → **4 instance** (mmix, mmcs-r0,
   fri, **oi**). KAPANAN SEAM: **ro-export ↔ f_init/roll-ins** — statement'ın
   `f_init`/`rollins` alanları SİLİNDİ; tek `ro_export` bölgesi üç tüketiciye
   inşa gereği alias'lanır (fri.f_init := ro_export[lgmh] per
   fri_verifier.c:524-527; fri.rollins := azalan eşleme :600-605; oi.ro publics
   aynı lane'ler) — T-SRC iki-tüketici assert'i + N-ALIAS/ro her lane'de iki
   publics'in birden oynadığını kanıtlar. oi REF cfg prep_pair'den ÖLÇÜLDÜ:
   H={5,4} lb'siz (FLEET 029'un mümkün kıldığı şekil), yükseklik başına 6 acc
   satırı (3 batch × [main 2·1 + quotient 1·2 + prep 2·1], dört iç içe döngü
   fri_verifier.c:207/:400/:436/:469), 12 toplam; uniform (3,1,2,1) çarpanlama
   DÜRÜST etiketli (yalnız total+boundary yük taşır; batch_sz lb'siz cfg'de
   yalnız fail-close rail). YENİ statik tutarlılık kontrolleri (bind öncesi,
   fail-close): fri roll-in ⊆ OI.H\{lgmh} + lb roll-in ⇒ lb'li oi cfg (FLEET
   029 F9 görevlerinin giriş yarısı) + lgmh/lb/descent eşitlikleri. Composed
   root 4 tabloya RE-PIN (prep genişlikleri 136/3/73/106; ORCHESTRATOR bağımsız
   --print-roots executor'la birebir): {cbf49fc544f375b3, 74adcd84b83da91c,
   33a40c6616608252, b12f5d1400263f49}. Verifier 9 CONF / 0 REF / 2
   UNVERIFIABLE(runtime — ORCHESTRATOR kapadı: placeholder 158/0, dolu 172/0
   RT-1 OK); HIGH'ı (Makefile oi kaynakları) ORCHESTRATOR O7'de uygulamıştı +
   :401 yorumu düzeltildi. NOT (LOW-3): batch_proof.json `prep_pair` senaryo
   YORUMU verisiyle çelişir ("no prep next-row" der ama main_next/prep_next
   true) — VERİ otoritedir, vektör hash-pinli olduğundan yorum düzeltilmedi;
   burada kayıt. O9: **85 binary ALL GATES GREEN 0 uyarı** (test_fri_statement
   suite-içi 172/0). Konsensüs-inert, UNCOMMITTED. Kalan seam'ler (header
   §HONEST LABELS): transcript/α/z/β (s3), p_x↔MMCS (s2), round replikasyonu +
   multi-query, arity-eşitliği.
   **s2 — p_x KISMEN BAĞLANDI (2026-07-30, FLEET 031: 1 executor + 1 zk-auditor
   + ORCHESTRATOR; kullanıcı kararları: mekanizma = oi publics genişletme,
   kapsam = main-batch kısmi).** fri_oi_air ailesine `[px total_acc]` publics
   bölgesi (SONA ek — mevcut offset'ler stabil) + **C3g** (pos-gated, C3c'ye
   bitişik, sıra pinli z0,z1,pz0,pz1,px; degree 2; native p_at_x =
   opened_values[m][j], fri_verifier.c:469-476) u64+fold. p_x artık SERBEST
   WITNESS DEĞİL. Statement: main-batch acc satırları `stmt.mmix_opened`
   lane'lerinden (yükseklik→matris türetimi fail-close: teklik + genişlik
   eşitliği + tam bölüntü; "batch 0 = main" ÖLÇÜMLE, batch_verify.c:544-563
   is_zk=0'da Round-0 atlanır), quotient/prep satırları YENİ `px_rest[8]`
   (DÜRÜST etiket: batch replikasyonuna dek bağsız statement girdisi — N-PXREST
   iki yönlü pinler: oi'ye ulaşır, mmix'e ulaşmaz). Pinler DEĞİŞMEDİ (px
   publics'te, tabloda değil; T-PINKAT canlı). Auditor: 10 G / 2 J / 1 K,
   0 CRIT/HIGH, **ikinci tanık KURULAMADI** (C3e↔C3g tutarlılığı, pos'suz
   satır serbestliği ro'ya girmiyor, kanonluk aliası kapalı — hepsi file:line
   ile). K = bayat placeholder yorumu (fri_statement.h:329) — O7'de düzeltildi.
   Testler: oi 36 negatif (N33/N34/N34b/N35), fold T-CNT 51 step/row REF,
   statement **237/0** (T-SRC/px + N-ALIAS/px + N-PXREST). O9: **85 binary ALL
   GATES GREEN 0 uyarı** (test_batch_prover 371/0 byte-match dahil — prover
   heap-pencere değişiminin vektör kanıtı). Konsensüs-inert, UNCOMMITTED.
   **s3a — TAIR OP-SCHEDULE TABLOSU SHIPPED (2026-07-30, FLEET 032: 1 executor
   + 1 zk-auditor + ORCHESTRATOR; kullanıcı kararı: s3a+s3b böl, FRI-tail
   only).** YENİ `transcript_air_table.{c,h}`: op-schedule preprocessed tablo
   üreteci (TAIR_TBL_COLS = TYPE 6 + IS_POW 1 + POS 64 = 71) — native
   challenger'ın duplex ZAMANLAMASINI simüle eder (eager duplex 4. observe'da,
   sample duplex koşulu in>0||out==0, LIFO pop, observe out'u geçersiz kılar,
   check_witness(0) SIFIR op — hepsi duplex_challenger.c file:line eşlemeli) ve
   op dizisi fri_verifier.c:693-737 FRI-tail sırası. REF script: R=3 lfpl=0 Q=2
   lgmh=5 pow=0/0 → **31 op / 64 satır / 41 public** (ORCHESTRATOR bağımsız
   türetti, executor+auditor ile üç yönlü eşleşti). `DNAC_P2A_PREP_ROOT` DOLU
   (bağımsız --print-roots, lane-lane eşleşti): {b689a4e626921aa3,
   9a08256aa5794c1d, db86740992ed646d, 443190c5257d97ea}. transcript_air'a
   publics `[payload n_ops][exported bits Q*lgmh]` + **CT-1..4** (u64+fold aynı
   pinli sırada): CT-1 tip konformansı (prep tip == main sel — P2a-i3'ün
   "sel_start herhangi bir yerde / satır her arketipi iddia edebilir"
   yükümlülüğü KAPANDI), CT-2 is_pow (i3'ün "serbest kolon"u KAPANDI), CT-3a
   Σpos==g_op + CT-3b payload==publics[slot], CT-4 index-bit İHRACI (s3b'nin
   alias yüzeyi). Mevcut A-M blokları BYTE-AYNI (diff kanıtlı). Executor TDD
   sırasında 2 gerçek defekt buldu+düzeltti (DEFECT_TERMINAL ölüydü — validator
   sırası; N3 tamper padding satırını hedefliyordu). Auditor: **0 CRITICAL,
   2 HIGH — ikisi de BELGE/YÜKÜMLÜLÜK, kodda düzeltme YOK** (ORCHESTRATOR ikisini
   de kaynakta doğruladı + folded): (#20) `pos` hücreleri hiçbir yerde boolean
   DEĞİL, CT-3a yalnız TOPLAMI pinler → pinlenmemiş tabloda `pos_a=x,
   pos_b=1−x` interpolasyonu payload'ı KEYFİ değere zorlar; header "all-zero →
   vacuous" diyordu, gerçek saldırı daha güçlü ⇒ PIN-1-P2a soundness için YÜK
   TAŞIR (aile duruşunun aynısı, yeni delik değil); (#30) **`pow_bits` tabloya
   HİÇ girmiyor** — 16-bit ve 1-bit grinding AYNI kökü üretir ⇒ OBL-P2a-T1'e
   eklendi, **s3b girişi pow_bits'i kökten BAĞIMSIZ pinlemek ZORUNDA** (FLEET
   029 #F8 lb-kaçışıyla aynı sınıf). Ayrıca folded: TERMINAL/MACHINE "DEAD"
   mutlak iddiası düzeltildi (filler'sız trace'te yanlış), yanlış makro adı, 4
   bayat batch_prover.c atıfı (⚠ aynı 4 atıf fri_air_table.h / mmcs_air_table.h
   / fri_oi_air_table.h / mmcs_mixed_air_table.h'ye de kopyalanmış — AYRI doc
   sweep işi). İkinci tanık: yalnız #20, o da modülün kendi beyan ettiği
   pinsiz rejimde; pin altında (a)-(e) denemelerinin hepsi KURULAMADI. O9:
   **86 binary ALL GATES GREEN 0 uyarı** (tests 85 → 86). Konsensüs-inert,
   UNCOMMITTED.
   **s3b — TRANSCRIPT STATEMENT'A KATILDI: ONAYLI DİLİM HARİTASI TAMAMLANDI
   (2026-07-31, FLEET 033: 1 executor + 1 verifier + ORCHESTRATOR).**
   fri_statement 4 → **5 instance** (mmix, mmcs-r0, fri, oi, **tair**).
   KAPANAN SEAM: **α / β / query-index ↔ Fiat-Shamir**. Statement'ın `betas` ve
   `alpha` ALANLARI SİLİNDİ; tek `tair_payload` bölgesi ÜÇ tüketiciye alias'lanır
   (ORCHESTRATOR saydı: fri betas :776/:778, oi alpha :832/:833, tair kendi
   publics'i :928 — dördüncü tüketim yok) ve tek `index_bits` hem tair'ın q=0
   exported-bit bloğuna hem dört tüketicinin bit/dir bölgelerine yazılır ⇒
   transcript'in ÜRETTİĞİ index ile dört AIR'ın TÜKETTİĞİ index aynı lane'ler.
   tair cfg s1 sabitlerinden türer; script `dnac_tair_fri_build_script` ile
   kurulur ve REF script ile op-op aynı (T-REF). Op indeksleri LİTERAL DEĞİL —
   `p2s_tair_pop_op` ordinal→op tarayıcısından türer. **FLEET 032 #30 KAPANDI:**
   `dnac_p2s_check_tair_pow_pin` (:150-176) script/params/AIR-cfg genişliklerinin
   üçünü birden eşitler + iki farklı non-zero width'i reddeder; çağrı zinciri
   :559 → :625 static-consistency → 5 bind :634-650, yani **bind'DAN ÖNCE**,
   fail-close. N-POWPIN sentetik pow=1/pow=16 script'leriyle sürer VE iki
   tablonun **byte-özdeşliğini** assert eder (kökün bu pini bağlayamadığının
   kanıtı). BLOKER + kanca: oi'nin alpha'sı build_honest İÇİNDE tohumdan türeyip
   build sırasında tüketiliyordu (tfp2 çıktısında b−a ≡ 0x100000007 sabit,
   transcript alpha'sında 0x4c42e371b14a9ec8 ⇒ hiçbir tohum tutturamaz) →
   kullanıcı onayıyla whitelist += tests/test_fri_oi_air.c, s2'nin shipped+
   denetlenmiş `g_px_ext` deseninin birebir aynısı olan `g_alpha_ext` kancası
   (ORCHESTRATOR diff'i okudu: 23 ekleme + 1 çağrı yeri, NULL'da byte-özdeş).
   ⚠ ORCHESTRATOR KAFADAN'ı: executor'a "fri betas de enjekte edilemez" dedim ve
   "kaynaktan doğruladım" diye ETİKETLEDİM — executor ÇÜRÜTTÜ (fixture_t
   çağıranın struct'ı; test_fri_statement.c zaten f_init/ro'yu eziyor), geri
   çektim, lessons.md'ye işlendi. Composed root 5 tabloya RE-PIN (genişlikler
   136/3/73/106/71; ORCHESTRATOR bağımsız --print-roots, executor'la lane-lane
   eşleşti): {0d61c566c046f50b, 6c028d283562f043, 5fc153486979664d,
   ba116b402a5fe146}. Verifier 8 CONF / 0 REF / 0 CRIT / 0 HIGH; CLAIM-7 notu
   folded (gözlemlenen-lane'ler-bağsız + RT-1-self-consistent etiketleri TEST
   dosyasından `fri_statement.h` honest-label listesine 6/7. madde olarak
   TAŞINDI — konsensüs çağıranının görmesi gereken yer). O9: **86 binary ALL
   GATES GREEN 0 uyarı**, statement girişi **353/0**, `dnac_batch_prove OK —
   5 instances`. Konsensüs-inert, UNCOMMITTED.
   ▶ **ONAYLI HARİTA BİTTİ (s1a→s1b→s1c→s2→s3a→s3b).** Kalan seam'ler
   (`fri_statement.h` §HONEST LABELS 1-7): priming transcript'i (ζ/z hâlâ
   statement girdisi — script yalnız FRI tail), commit-round 1..R-1 + input-batch
   replikasyonu (px_rest ve gözlemlenen lane'ler bunu bekliyor), multi-query
   (OBL-P2c-2; script Q örneklerken yalnız 1 tüketiliyor), arity-eşitliği,
   oi grup-şekli etiketi. HEPSİ yeni bir dilim haritası + muhtemelen
   ctx-redesign kararı ister (air_eval ctx taşımıyor, stark_constraints.h:289
   shared yüzey) — ORCHESTRATOR kullanıcıya sunmalı, kendi başlatmamalı.

### ⚑ CITATION BASELINE — read this before checking any Plonky3 `file:line` in this tree

**The `file:line` citations throughout `shared/crypto/zk/` are against Plonky3
`82cfad73`, not against the tree's current pin `11cc5849` (v0.6.2). They are CORRECT
— check them at the commit they name.**

This was verified, not assumed, on 2026-07-28. Worked example: `poseidon2_goldilocks.c`
cites `goldilocks/src/poseidon2.rs:75` for `RC_8_EXTERNAL_INITIAL` and `:177` for
`RC_8_INTERNAL`. At `82cfad73` those lines are exactly those two constants. At
`11cc5849` the same constants sit at `:111` and `:213` — a uniform **+36** in that file,
because the file grew between the two commits.

⚠ **An earlier revision of this document called those citations "stale" and reported a
"+36 line drift" as a defect. That was WRONG and is retracted.** A citation that names
its commit and is accurate at that commit is not stale; it is a correct citation about a
specific revision. The error was mine: I checked the citations against the CURRENT pin
instead of the one they name, then reported the mismatch as drift. Checking a reference
against a commit it never claimed is the same class of measurement error as running a
grep that cannot return positive.

**How to check a citation here:**
```bash
git -C <plonky3-clone> show 82cfad73:<path>        # for a bare or 82cfad73-labelled cite
git -C <plonky3-clone> show 11cc5849:<path>        # for anything explicitly marked v0.6.2
```
`82cfad73` is an ancestor of `11cc5849`, so a single clone serves both — no extra fetch.

**Scope, measured:** 132 full-path `crate/src/file.rs:N` citations plus 874 short-form
`rs:N` citations across the zk sources. Renumbering ~1000 citations to the new pin was
considered and REJECTED: it is a large mechanical edit on crypto-grounding text where a
single wrong number silently converts a true citation into a false one, and it buys
nothing — the old commit remains reachable and the citations remain checkable. The
correct fix was to state the baseline, which is what this block does.

**Where citations DO name v0.6.2 explicitly** (the S2' migration work: `batch_verify`,
`logup`, `logup_bus`, `batch_priming`, the FRI/MMCS verify hardening) they are against
`11cc5849` and say so. Mixed baselines in one tree are tolerable ONLY because each
citation carries its commit; a bare `rs:N` with no commit defaults to `82cfad73`.

### Standing cautions

- **The S2'-d descriptor pins (`num_random_codewords`, `salt_elems`) are STRICTER THAN UPSTREAM.**
  No upstream KAT stands behind them; they rest on the S2'-a red-team's reasoning. C3 makes that
  surface live — do not inherit any green as a soundness claim for it.
- **A red-team verdict expires when the substrate moves.** This is not a slogan; it is what
  destroyed C6 (verdict rendered 2026-07-16, premise outlawed 2026-07-17). Any charter in the
  boundary doc must run against the tree as it stands the day the code starts.
- **Size a verify stage to the finding count, never to a constant.** The 2026-07-27 C6 round
  produced 14 CRITICAL/HIGH and independently verified only 3, because the fan-out was hard-capped
  at 3 in the orchestration script. The other 11 are named but carry **no verdict**.
- `tools/vectors/fri_fold_matrix.json` is **65.2 MB** against GitHub's 100 MB hard limit. Any
  re-ground must not push it over; a push failure would be total.
- `fri_error_variants_total_in_enum = 26` is pinned BY HAND and must be updated on the next
  Plonky3 bump. `PointEvaluationCountMismatch` is no longer exercised, and the
  `DNAC_LOGUP_ERR_HEIGHT_BOUND → DNAC_BV_ERR_HEIGHT_BOUND` mapping is unreachable from any fixture
  (needs three maximal terms) — both documented in the tests themselves.

**Suggested order, given the above:** revise the F1 doc → run the boundary doc's §3 red-team
against the then-current tree → ONE combined re-ground (D=24 + boundary publics) → the C3 apply /
accept-flip. P2a can proceed independently at any point, but only after its no-upstream-reference
problem is argued out with the user.

---


> **This top block is authoritative and current. Everything under "═══ HISTORICAL
> BUILD LOG ═══" is the traceable module-by-module history and its numbers
> (widths, constraint counts, B6/B7 framing) are PRE-2026-07-12 — read them as
> history, not current state.**

## WHERE WE ARE

- **🔀 PQ ROLLUP PIVOT + P1a SHIPPED (2026-07-22, this working tree).** The
  1-TPS lock was REOPENED by the user → native pure-C PQ zk-rollup program
  P1-P6 (memory `pq-rollup-pivot`). P1 = proof-internal SHA3→Poseidon2
  (design doc `dnac/docs/plans/2026-07-22-p1-proof-hash-poseidon2-design.md`
  **v2 GATE GREEN**: round-1 NOT-GREEN 1 CRIT/2 HIGH §3.1 → revised → round-2
  GREEN §3.2; F3 = DS pre-absorb user-locked). **P1a DONE:**
  `duplex_challenger.{c,h}` — Poseidon2 `DuplexChallenger<Gold,Perm,8,4>`
  FULL-surface port (observe/duplex/sample + sample_bits/check_witness/grind
  + 4-limb DS prefix G-SEC-P1-7; least-witness grind determinization), oracle
  `dump-duplex-challenger` (12 scenarios / 76 steps, full state snapshots,
  regen 2× byte-identical, hash-pinned) + `test_duplex_challenger` KAT
  (byte-match + DS-derivation + init_default gates). `make test`: **all 76
  test binaries GREEN, 0 warn** (75 + the new KAT; NOTE the older "65/66
  GREEN" counters below were STALE — the committed pre-P1a TESTS list already
  had 75 binaries, grep-proven `awk '/^TESTS/,/^$/' | grep -o 'test_...' |
  sort -u | wc -l`; binary count is the counter from now on). STANDALONE at
  P1a — the SHA3 transcript was still the live challenger then; P1c (below)
  rewired the proof path onto the DuplexChallenger and deleted the SHA3 one.
- **P1b DONE (2026-07-22, same working tree):** `poseidon2_mmcs.{c,h}` —
  Poseidon2 MMCS port: `dnac_p2_mmcs_hash_iter` (PaddingFreeSponge<8,4,4>,
  arbitrary length, == note_sponge_hash8 at len 8, KAT-bridged) +
  `dnac_p2_mmcs_compress` (TruncatedPermutation<2,4,8>, ONE permutation —
  structurally distinct from note_merkle_compress) + lane-based batch
  commit/open/verify (N=2, same-height pow2, cap 0, 4-lane/32-byte digests,
  lane<p fail-close). SALT-AGNOSTIC core: hiding form = caller assembles
  `row ‖ salt` (the fri_verifier consumption shape; `salt_elems` stays a
  consensus pin per G-SEC-P1-6). Oracle `dump-poseidon2-mmcs`: REAL
  MerkleTreeMmcs + MerkleTreeHidingMmcs(SmallRng(1), SALT_ELEMS=2), 9 trees
  (6 plain / 3 salted), openings at EVERY index (all in-oracle
  verify_batch-checked), regen 2× byte-identical, hash-pinned.
  `test_poseidon2_mmcs`: 10 sponge + 6 compress KATs, 9 roots + 65 openings
  byte-matched, negatives (tamper/index/depth/non-canonical).
- **P1c + P1d DONE (2026-07-22, same working tree) — THE POSEIDON2 CUTOVER
  IS COMPLETE.** The ENTIRE proof-internal hash layer is now Poseidon2:
  - `transcript.{c,h}` REWRITTEN as a thin heap wrapper over `dnac_duplex_t`
    (byte observe surface GONE — `init_empty`/`init_default(DS prefix)`,
    `observe_digest` = 4 lane observes; SHA3 HashChallenger deleted).
  - `fri_verifier`/`stark_priming`/codec/all provers + gen tools swept to
    `dnac_p2_digest_t` (32 B) + lane leaves (input row ‖ salts; commit-phase
    `[c0,c1]×arity ‖ BASE salts`); `merkle_smt.{c,h}` + `sponge_sha3_512.{c,h}`
    + 5 SHA3-era tests + 4 vectors DELETED (G-SEC-P1-5 clean cutover;
    keccak_p3/keccak_ref stay — own gates + conf_txbind consumer).
  - DZKF wire v2→3: digest 64→32 B, per-lane `< p` decode guard (G-DET-P1-5
    NEW); `DNAC_SHIELDED_SALT_ELEMS=2` pin enforced fail-close in
    `dnac_fri_verify_wire_shielded` on EVERY batch opening + commit-phase step
    (G-SEC-P1-6), CT-asserted == A_SALT_ELEMS.
  - Rust oracle cut over (DuplexChallenger + Poseidon2 plain+hiding MMCS +
    DS-prefix `mk_prod_challenger`; SHA3 shadow/recorder machinery deleted;
    milestone snapshots = duplex triples; `dump-transcript` retired;
    digest JSON = 32-byte hex / serde `[{"value":N}×4]`).
  - P1d full re-ground: ALL 52 oracle vectors + 3 gen-tool wire vectors
    regenerated (each 2× byte-identical, every in-dump Plonky3 verify gate
    GREEN); **num_qc RE-MEASURED — STOP gate NOT triggered** (shielded agg=8
    == pin; conf=8, range/priming-zk=4, fib/square=1); `.expected_hashes`
    rebuilt.
  - **Verification: zk `make test` all 72 test binaries GREEN 0 warn; nodus
    build clean + ctest 132/132 PASS (test_zk_link chain incl.); messenger/
    libdna build clean.** Wire-format change is consensus-inert: type-11 is
    still REJECT-unconditional (C2) and `dnac_shielded_verify_statement` is
    not yet called by consensus — no nodus version bump (C1 linkage-only
    precedent).
- **P1e ✅ DONE (2026-07-22, same working tree) — CODE red-team GREEN + fixes
  applied.** 13 agents (Phase-0 AS-WIRED map + 12 REFUTE surfaces), ~2.05M
  tokens, user cost-gate approved. **VERDICT: GREEN on the verify/consensus
  surface — 0 CRITICAL, 0 soundness/determinism defect.** Every CRIT/HIGH
  candidate executor-verified vs the tree. One HIGH (prover-side ZK/hiding only,
  no live consumer) + several MED/LOW; fixes folded THIS commit (full record:
  P1 doc §3.3):
  - **HIGH-1 salt-stream reuse (FIXED):** the shielded production provers (agg +
    conf) reused ONE OS-entropy salt buffer for both the input-mmcs (stream A)
    and FRI-mmcs (stream B), aliasing trace and FRI-layer-0 leaf salts
    (contradicting the code's "independent streams" comment; Plonky3 uses a
    cloned-rng independent hiding-mmcs, main.rs:8757-8773). Added an independent
    `fri_salt_draws` (stream B); production fills it from its own entropy; KATs
    leave it NULL → fallback to `salt_draws@0` → **all salted vectors
    byte-identical**. S12 opening reads commit-phase salts from the same buffer
    commit used. ZK/hiding only — soundness/determinism untouched.
  - **[E]** consensus-linked `assert()`s (fri_verifier / zk_field_helpers
    log2_strict_usize / fri_fold / stark_priming) → ALWAYS-ON fail-close
    (survive `-DNDEBUG`): channel-bearing return an error, channel-less abort
    deterministically (mirror Plonky3 panic; new `DNAC_STARK_PRIMING_ERR_NULL`).
  - **[C]** `test_zk_entropy` (G2 CSPRNG) was built but never run by `make
    test` — added to the recipe.
  - **[D]** the LIVE 16-bit query-PoW grind had no Plonky3 cross-vector (all FRI
    vectors pow=0) — added a real Plonky3 `grind16` case to
    `dump-duplex-challenger`, regenerated `duplex_challenger.json` (2×
    byte-identical, re-pinned; 13 cases / 80 steps); hardened the KAT
    degenerate-vector floor.
  - **[F]** `dnac_conf_prover_prove_production` (~4-bit soundness under a
    "production" name) — WARNING added (NOT consensus-strength; use the agg
    shielded prover).
  - **Docs same-commit (S6 drift):** README top note + verifier-stack list,
    `conf_membership_air.h` dead-file pin re-pinned, `fri_proof_codec.h`
    "v2/64B"→v3/32B, the "NOT wired" headers (duplex / poseidon2_mmcs /
    poseidon2_goldilocks) → WIRED, stark_priming.h / fri_verifier.h "SHA3-512"→
    Poseidon2, nodus/CMakeLists.txt C1 comment.
  - **Verification: zk `make test` 72 binaries GREEN 0 warn (+grind16); nodus
    build clean + ctest 132/132; messenger/libdna clean.** Consensus-inert
    (type-11 still REJECT-only) → no version bump.
  - **Tracked follow-ups (NOT this commit):** commit-PoW-witness blob
    malleability (C3 dedup check), type-11 trailing-byte exact-length (C3),
    unpinned `dnac_fri_verify` footgun WARNING, poseidon2_mmcs sibling/root
    canonicality sweep (today closed by rd_digest).
  NEXT: **P2 — verifier-in-circuit** (now unblocked; the FRI + constraint +
  transcript verify can be expressed as an AIR at ~351× lower cost than
  SHA3-in-AIR — the recursion core the L2→L1 rollup needs).
- **P2 FOUNDATION (2026-07-23, design-only session): posture A + recursion
  architecture + P2-lookup design — all GREEN.** Soundness posture = A
  (CONJECTURED over Goldilocks²; proven-128 is a field-wall, memory
  `fri-proven-soundness-regate`). Recursion architecture v3 (proof-tree,
  WRAP+NODE, K=4, aggregate accumulators) UN-PARKED. Delegation = shared
  Poseidon2 table + lookup → P2-lookup design v3 GREEN (2 rounds;
  `dnac/docs/plans/2026-07-23-p2-lookup-{grounding-note,design}.md`).
  - **Posture-A documentation obligation DISCHARGED (2026-07-26).** Choosing
    the conjectured bound came with a written obligation (grounding-note §6):
    document the proven floor + the Nov-2025 caveat + an upgrade trigger. It
    was never written down until now. `shielded_fri_params.h` gains a
    "Soundness POSTURE" header block: (a) the PROVEN floor for the live pin set
    is **~87 bits, not 216**, and is query-INDEPENDENT — the additive
    commit-phase term over |F|=Goldilocks²≈2^128 at m=3 with n=2^13 (= pinned
    committed height 11 + log_blowup 2) caps it, so no query count reaches
    proven-128 (that needs |F| ≳ 2^170); (b) the Nov-2025 up-to-capacity
    disproof covers Goldilocks scale but bites only within O(1/log n) of
    capacity, NOT at the Johnson radius where verification operates; (c) a
    3-condition re-open trigger. `DNAC_SHIELDED_FRI_SOUNDNESS_TARGET` 100 →
    **128** (policy floor only — not runtime-enforced, sole consumer is
    `test_shielded_fri_params.c`; 216 conjectured clears it). Comment +
    one policy constant; no behavior change, consensus-inert (type-11 still
    unconditionally REJECT, `nodus_witness_verify.c:872-874` →
    `verify_shielded_tx`). Memory `fri-proven-soundness-regate` rewritten in the
    same pass — its "re-size before C3" / "P2 BLOCKED" items were stale and are
    now marked SUPERSEDED.
- **P2L-a ✅ DONE (2026-07-23, this working tree, UNCOMMITTED): LogUp gadget
  byte-matched port.** `logup.{c,h}` — the pure p3-lookup `LogUpGadget`
  (Plonky3 82cfad73 `lookup/src/logup.rs`): β-combine, numerator/common-
  denominator via prefix/suffix products (ONE ext-field inversion per
  (row,lookup); serial port of the chunked-parallel reference —
  output-invariant, G-DET-L1), aux-trace `generate_permutation` (exclusive
  running sum, WRAP next-row pinned = logup.rs:474), eval_local/eval_global
  residual streams (selector-multiplied per filtered.rs:78-86),
  `verify_global_sum` (FLAT — per-bus grouping is the P2L-b/d caller's job,
  G-DET-L4/F3), `constraint_degree`. Fail-close always-on: zero denominator
  (mirror of the Plonky3 batch-inversion panic), duplicate aux column,
  challenge-count, kind/cum mismatch. Oracle `dump-logup` (+`p3-lookup` dep,
  same pin; +hashbrown in Cargo.lock): 11 Goldilocks/Gold² instances
  (local/tuple/two-lookup/global send+recv/tampered-global/corrupted-aux/
  preprocessed/next-row/public-mult-expr) + 2 cross-instance global checks,
  regen 2× byte-identical, hash-pinned. `test_logup`: 347 checks GREEN
  (aux byte-match, cumulative sums, full residual streams incl. the
  corrupted-witness non-zero values, degrees, global verdicts, negatives).
  **`make test`: 73 test binaries ALL GREEN, 0 warn** (72 + test_logup).
  STANDALONE — no consumer yet; batch-stark shape/priming/wire = P2L-c/d.
- **P2L-b ✅ DONE (2026-07-23, same working tree, UNCOMMITTED): interaction/
  bus layer byte-matched port.** `logup_bus.{c,h}` — builder recording
  (`push_interaction`/`push_local_interaction`, builder.rs:59-94) +
  finalize column assignment (locals FIRST then globals, push order,
  types.rs:59-89; a global = single-tuple lookup) + per-bus challenge
  assignment (memo by bus name at first occurrence, locals fresh —
  batch-stark transcript.rs:74-102) + PER-BUS global-sum verification
  (each name-group == 0, verifier/mod.rs:623-643; grouping-key ≡ memo-key
  by construction, N4) + the height-bound OFFLINE precondition checker
  `Σ weight·height < p` (builder.rs:33-38 doc contract; F4 re-verified:
  count_weight is NEVER computed anywhere in Plonky3 — the runtime
  verifier won't catch it, configs must call the checker at param freeze).
  Bus conventions pinned per bus.rs (query/send +count w1, table −count w0,
  receive −count w1). Oracle `dump-logup-bus` (+`p3-batch-stark` dep, same
  pin): REAL `Lookups::from_air` mixed-push-order instances + REAL
  `BatchTranscript::sample_perm_challenges` over the production
  DuplexChallenger (draw stream independently replayed and byte-matched on
  the C duplex — binds P2L-b to the P1a surface) + 6 sum instances /
  3 grouping scenarios incl. the **F3 cross-bus-cancellation trap** (flat
  total == 0 while BOTH bus groups fail — per-bus grouping proven
  load-bearing); regen 2× byte-identical, hash-pinned. `test_logup_bus`:
  140 checks GREEN (builder-replay column assignment as interned expr ids,
  memo challenges, per-bus sums + verdicts + failed-bus name, height-bound
  exact p−1/p boundaries overflow-safe, fail-close negatives). Shared
  test JSON-DOM extracted to `tests/logup_test_util.h` (test_logup
  refactored, still GREEN). **`make test`: 74 test binaries ALL GREEN,
  0 warn** (73 + test_logup_bus). STANDALONE — no consumer yet.
- **P2L-c ✅ DONE (2026-07-23, same working tree, UNCOMMITTED): batch-stark
  proof shape + FULL batched priming, byte-matched.** `batch_priming.{c,h}`
  — the complete N1 transcript order over the P1 duplex (phase primitives
  1:1 with BatchTranscript, transcript.rs:27-146, in the verifier's call
  sequence verifier/mod.rs:143-300): instance-count → per-instance binding
  (log_ext, log_base, width, num_qc; each usize = TWO base observes (v,0)
  per challenger lib.rs:141-147) → main commit + publics → preprocessed
  widths + commit (AFTER main — the F2/N3 delta vs v3) → (α,β) via the
  P2L-b memo fed by pre-counted challenger draws (byte-identical to lazy
  sampling — no observes interleave) → perm commit + EVERY cumulative sum +
  constraint-alpha → quotient commit → random commit iff is_zk → ζ. Plus
  `dnac_batch_proof_shape_check` mirroring the verifier's structural gates
  (trace widths :162-180, qc count + dim==2 :183-199, random iff ZK
  :74-84/:201-209, preprocessed lens :211-231, perm lens = aux_width·2
  :482-484/:524-541, global_lookup_data metadata + locals-first columns
  :233-267) and a composed fail-close `dnac_batch_priming_run`. Oracle
  `dump-batch-priming` (+`p3-batch-stark` prove/verify): 4 scenarios —
  fib_pair (0-lookup batched preamble ≠ v3), lut_pair (perm commit + memo +
  cums-before-alpha), prep_pair (preprocessed commit, new PrepEqAir
  fixture), fib_zk (HidingFriPcs random commit; qc doubling; degree_bits+1)
  — EVERY scenario gated on a REAL `prove_batch`+`verify_batch == Ok`
  before dumping; duplex milestones after all 9 phases; regen 2×
  byte-identical, hash-pinned. `test_batch_priming`: 547 checks GREEN
  (all milestones + memo challenges + alpha/zeta + composed run + shape
  accept/mutation rejects + zk-flip negative). **`make test`: 75 test
  binaries ALL GREEN, 0 warn** (74 + test_batch_priming). v3
  `stark_priming.{c,h}` UNTOUCHED (stays live until the P2L-d cutover).
- **P2L-d ✅ COMPLETE (d0…d4.d + d5 green sweep, 2026-07-26, UNCOMMITTED) —
  70 binaries GREEN, 0 warn; nodus ctest 132/132; messenger/libdna clean.**
  (The per-stage records below were written as the stages landed; the final
  state is the d4.d + d5 block further down. Binary counts inside the older
  stage entries are historical — the v3 retirement took the total 80 → 70.)
  Original approved decomposition (user picked
  "continue stage-by-stage"): d1a mixed-MMCS → d1b full-proof oracle → d2
  batched verify → d3 batched prover → d4 DZKF v4 + regen + v3 RETIRE +
  num_qc STOP gate → d5 green sweep (zk+nodus ctest 132+messenger) → d6 docs.
  - **d0 (substrate) DONE — the load-bearing pins:** verifier constraint
    fold rule `acc = acc·α + x`, base+ext ONE stream, call order = fold
    order (lookup folder.rs:169-181); order = air.eval FIRST then lookups
    (protocol.rs:64-81); at ζ the permutation window is the RECOMPOSED EF
    matrix (aux_width wide; verifier/mod.rs:543-559; opened lens =
    aux_width·2, :524-541); final check `acc·inv_vanishing == quotient`
    (verifier/data.rs:99-103); C `dnac_fri_verify` is ALREADY fully generic
    over CommitmentWithOpeningPoints — the N2 batched rounds need only new
    round-assembly code, no FRI-core change; existing
    `dnac_stark_verify_constraints_nchunk` + P2L-a `sum_terms` cover most of
    the ζ-side lookup eval (missing piece: EF-window pool evaluation);
    DZKS v3 is a single-instance wrapper → v4 re-shape expected.
    **DISCOVERED GAP (user-approved scope add):** C poseidon2_mmcs was
    same-height-only, but batched commits need MIXED heights.
  - **d1a ✅ DONE: mixed-height Poseidon2 MMCS.**
    `dnac_p2_mmcs_{commit,open,verify}_mixed` — layer injection per
    merkle_tree.rs:127-176 (N=2 ⇒ arity schedule all 2s,
    select_arity_step:227-242): tallest group = leaf layer, shorter groups
    inject at the layer whose length equals their height via
    `C(C(prev2i,prev2i+1), H(rows))`; STABLE tallest-first grouping
    (insertion order within a height group — concat order inside H depends
    on it); per-matrix reduced index `index >> (log_max − log_h)`
    (mmcs.rs:989-998); sibling path = log2(max_height) digests (injection
    combines carry NO siblings, mmcs.rs:1109-1116); pow2 heights only
    (fail-close; the DNAC batch shapes). Same-height P1b paths untouched
    (KATs frozen). Salt-agnostic contract preserved (caller appends salt
    lanes). Oracle `dump-poseidon2-mmcs-mixed`: 7 REAL
    MerkleTreeMmcs/HidingMmcs trees incl. a scrambled-insertion-order tree
    + a degenerate same-height pair, openings at EVERY index all
    verify_batch-checked in-oracle, regen 2× byte-identical, hash-pinned.
    `test_poseidon2_mmcs_mixed`: 424 checks GREEN (plain roots byte-match,
    open replay = rows+siblings exact, salted verifies, 6 fail-close
    negative classes). **make test: 76 binaries GREEN 0 warn.**
  - **d1b ✅ DONE: full-proof oracle `dump-batch-proof`.** The COMPLETE
    REAL `prove_batch` output, EVERY scenario `verify_batch == Ok`-gated:
    commitments (hex + serde), per-instance opened values incl.
    permutation_local/next (asserted == aux_width·2, verifier/mod.rs
    :524-541), global_lookup_data, degree_bits, and the ENTIRE FRI opening
    proof in `proof_serde` (FriProof {commit_phase_commits,
    commit_pow_witnesses, query_proofs [{input_proof: Vec<BatchOpening>,
    commit_phase_openings [{log_arity, sibling_values, opening_proof}]}],
    final_poly, query_pow_witness}, fri/src/proof.rs:12-42; is_zk opening
    proof = (random OpenedValues, FriProof) tuple, hiding_pcs.rs:88-91).
    Emits the N2 opening-round schedule explicitly, length-asserted vs the
    proof (prover.rs:450-537): [random iff is_zk] → main (ζ, +g·ζ iff
    main_next) → quotient (ζ) → [preprocessed] → [permutation (ζ AND g·ζ,
    always)]; per-instance ζ_next = base trace domain next_point
    (verifier/mod.rs:306-310,:341-343). 5 scenarios: fib_single (0-lookup
    SINGLE-instance batch), lut_pair (Round-4 perm), prep_pair
    (Round-3 preprocessed + mixed heights 8/4), **lut_mixed_trio (the d1a
    full-proof consumer: sender h=8 = 4-row block ×2 (local balance
    preserved, LUT sends −2/tuple) + two h=4 receivers (+1 each) → LUT
    group zero; main AND permutation commits mixed-height 8/4/4)**, fib_zk
    (HidingFriPcs SmallRng(1), mixed 8/16, qc doubling).
    `vectors/batch_proof.json` (327858 B) regen 2× byte-identical,
    hash-pinned. **make test: EXIT 0, ALL GATES GREEN, 0 warn, 76
    binaries** (oracle-only slice — the C consumer KAT lands at d2).
  - **d2 ✅ DONE: C batched verify — `batch_verify.{c,h}`
    (`dnac_batch_verify`), full `verify_batch` mirror
    (verifier/mod.rs:29-646), END-TO-END GREEN against every d1b vector.**
    Pipeline: shape gates (dnac_batch_proof_shape_check + random-vs-ZK
    :74-84/:201-209 + perm-commit-iff-lookups :282-286) → full batched
    priming (dnac_batch_priming_run) → N2 round assembly (every matrix
    domain log_size = degree_bits[i]; ζ_next(i) = ζ·g(base_db) per
    :306-310/:341-343) → hiding merge iff is_zk (opening_proof.0 appended
    per (round,mat,point), zip_eq mirrored fail-close; preprocessed round
    carries len-0 entries, hiding_pcs.rs:343-348/:382-401) → PCS observe
    (two_adic_pcs.rs:687-693) + dnac_fri_verify → per-instance constraint
    check at ζ (nchunk recompose → selectors on base domain → air.eval
    FIRST then lookups per protocol.rs:64-81, ONE fold stream acc·α+x
    folder.rs:169-181; perm window RECOMPOSED EF :543-559; LogUp residuals
    = the P2L-a stream selector-multiplied, cum = permutation_values[pv_idx++];
    final acc·inv_vanishing == quotient data.rs:99-103) → per-bus global
    sums (dnac_logup_bus_verify_global_sums, :623-643). Substrate adds:
    `dnac_logup_eval_pool_window` (EF-window pool eval, logup.c),
    `dnac_transcript_init_from_duplex` (batch-primed duplex →
    dnac_fri_verify bridge), dnac_stark_folder_t + preprocessed window
    (ADDITIVE; v3 glue zero-inits, KATs frozen), and **fri_verifier.c
    open_input MIXED-HEIGHT batches** (same-height gate superseded:
    per-matrix heights, max drives reduced_index per verifier.rs:563-580,
    mixed batches verify via the d1a `dnac_p2_mmcs_verify_mixed`;
    same-height path byte-stable). **KAT `test_batch_verify`: all 5
    scenarios verify end-to-end with (α,ζ) byte-match — incl.
    lut_mixed_trio (mixed-height main+perm commits through the REAL FRI
    proof) and fib_zk (hiding merge + tuple proof) — + 8 fail-close
    negatives; 36 checks GREEN. Grounding catch: AddAir/PrepEqAir do NOT
    override main_next_row_columns → the default is ALL columns
    (air/src/air.rs:122-137), so their real proofs open main (and prep) at
    ζ AND g·ζ — fixture descs pin main_next=1.** `make test`: **77
    binaries ALL GREEN, 0 warn** (76 + test_batch_verify).
    **SCOPING NOTE (deviation surfaced): the todo's d2 line included
    "shielded_verify re-base" — moved to d4**, atomic with the DZKF v4
    codec + vector regen: re-basing shielded_verify before the v4 wire
    exists would break the live v3 KATs mid-slice ("tree stays GREEN
    between stages", design §4 header).
  - **d3 ✅ DONE: C batched prover — `batch_prover.{c,h}`
    (`dnac_batch_prove`), full `prove_batch` mirror (prover.rs:96-670),
    EVERY output byte-matched against the d1b vectors.**
    - d3.0 entry prereq: the oracle `dump-batch-proof` fib_zk scenario now
      dumps `zk_rng` — the FULL SmallRng(1) stream in BATCHED consumption
      order with a labeled block map (B1 main `with_random_cols` per
      instance, dense.rs:573-597 → B2 per-instance quotient chunk cols +
      blinding tail, hiding_pcs.rs:186-199 → B3 R matrices, dense.rs:
      527-533 / hiding_pcs.rs:404-424), replay-GATED in-oracle: Z1 (B1 →
      inner batch commit == commits.main) and Z2 (B3 at the post-B2 offset
      == commits.random — transitively pinning the B2 draw COUNT).
      `batch_proof.json` 376201 B, regen 2× byte-identical, re-pinned.
    - d3.2 substrate: `dnac_prover_fri_reduced_openings_mixed` (per-height
      codewords with INDEPENDENT alpha counters — the verifier fri_ro_t
      mirror, two_adic_pcs.rs:588-658) + `dnac_prover_fri_commit_phase_mixed`
      (descending-height inputs + ROLL-IN after the fold, prover.rs:238-245
      `next_if`, beta^{2^log_arity}; arity peeks the next input,
      config.rs:152-179). The single-input v3 `dnac_prover_fri_commit_phase`
      is now a thin wrapper over the mixed form — byte-identical sequence
      (no roll-in ever fires), proven by the untouched v3 KATs.
    - d3.3 pipeline: priming PHASE PRIMITIVES interleaved with the commits
      (the composed dnac_batch_priming_run wants every commit upfront —
      unusable prover-side); mixed-height Poseidon2 commits for
      main/preprocessed/permutation/quotient/random (d1a commit_mixed);
      aux traces = logup generate_permutation → flatten_to_base → LDE;
      quotient = at EVERY quotient-domain point the d2 constraint chain
      (EF-promoted windows + air.eval → LogUp residuals) folded through ONE
      serial Horner stream — VALUE-EQUAL to decompose_alpha's α^{K−1−i}
      emission weights (air/symbolic/builder.rs:401-423; SIMD base/ext
      split is performance-only); perm window rows (i, i+next_step) mod
      q_rows (prover.rs:850-868); zk chunk LDEs reuse the frozen S7
      pipeline (its same-height root is a throwaway; the REAL commit is
      the mixed one); N2 opens observe the FULL committed width then split
      the hiding tails (hiding_pcs.rs:333-358; preprocessed splits 0);
      query openings via open_mixed at per-batch reduced indices;
      SELF-VERIFY = dnac_batch_verify (fail-close) + (α,ζ) cross-check.
    - d3.4 KAT `test_batch_prover`: all 5 scenarios PROVED FROM SCRATCH in
      C (witness traces rebuilt: fib ramp, LUT tables, PrepEq 7+3i) and
      byte-matched on EVERYTHING — 5 commits, α/ζ, every opened value +
      cums + metadata, the ENTIRE FRI proof (commit-phase commits, PoW,
      final poly, per-query input rows/paths/steps), the fib_zk hiding
      rand-openings — + 5 fail-close negatives; 376 checks GREEN. Shared
      fixtures extracted to `tests/batch_test_util.h` (VERBATIM copy of
      the d2 fixtures; test_batch_verify.c deliberately untouched
      mid-slice — consolidation lands at d4). **`make test`: 78 binaries
      ALL GREEN, 0 warn.**
    - Guard fixes surfaced by d3 (source-grounded; every v3 KAT stayed
      GREEN): `dnac_prover_quotient_selectors` now accepts log_coset ==
      log_n (domain.rs:281 is `>=` — the num_qc=1 batched case; shift==1
      now REJECTED per the assert_ne, domain.rs:280);
      `dnac_prover_randomize_trace` dropped the v3-artifact
      `num_random <= width` reject (dense.rs has no such bound; the
      batched fib trace is width 2 with 4 codewords).
  - **d4.a + d4.b ✅ DONE (2026-07-23, same working tree): DZKF v4 codec +
    oracle wire + KAT — `make test` 79 binaries GREEN 0 warn.**
    - **d4.a codec:** `dnac_batch_wire_encode/decode` + package accessors in
      `fri_proof_codec.{c,h}` (allocation registry generalized `codec_reg_t`,
      shared with the v3 package; v3 paths untouched). Wire = the BatchProof
      tuple: is_zk, num_instances, the 5 commits (main/prep/perm/quotient/
      random — prep/perm/random presence-flagged 0/1 fail-close), per-instance
      UNMERGED opened values (dnac_batch_vopened_t shape: fp2vecs, u32 num_qc
      + chunk pairs, ONE permutation_len + local + next) + global_lookup_data
      entries (len-prefixed bus name 1..64 no-NUL, aux_column, fp2 sum —
      types.rs:108-115 field order), rand-openings iff is_zk, 6×u32 fri
      params, FriProof (v3 field conventions: u32 counts, canonical u64-LE
      fail-close, fp2 c0‖c1, 4-lane digests, salt tails). STRUCTURAL WIN vs
      v3: the v4 wire carries NO opening points — the verifier assembles the
      N2 rounds itself around the SAMPLED ζ (dnac_batch_verify), so the v3 H2
      class closes by construction. Version=4 under the DZKF magic; v3
      buffers REJECTED on VERSION (and v4 buffers on the v3 decoder —
      KAT-gated both ways).
    - **d4.b oracle+KAT:** oracle `dump-batch-proof` emits `wire_v4`
      (+`wire_v4_len`) per scenario — an INDEPENDENT second encoder (JSON
      walker over the same verify_batch-gated dump). **Grounding catch:** the
      Goldilocks serde derive emits the RAW internal `value: u64`, "Not
      necessarily canonical" (goldilocks.rs:32-38) — the oracle encoder
      canonicalizes (`% p` ≡ as_canonical for any u64 < 2p) before writing;
      caught by a real lut_pair FriProof value `p + 0xb0` on the wire.
      `batch_proof.json` (412172 B) regen 2× byte-identical, re-pinned. C KAT
      `test_batch_wire` (73 checks GREEN): per scenario decode == OK +
      is_zk/n cross-check + **the DECODED package verifies end-to-end**
      (dnac_batch_verify accept + (α,ζ) byte-match) + re-encode byte-match +
      **dnac_batch_prove from scratch → encode → oracle wire byte-match** +
      7 fail-close decode negatives (magic / v4-on-v3-decoder AND
      version-3-patch-on-v4-decoder / truncation / lane ≥ p / is_zk flag 2 /
      total_len mismatch / trailing byte). Fixture consolidation (partial,
      logup_test_util precedent): `pscenario_t`/`load_pscenario` + witness
      builders moved VERBATIM test_batch_prover.c → tests/batch_test_util.h
      (shared with the wire KAT; test_batch_verify.c still untouched — full
      consolidation stays d4.d).
  Remaining d4 decomposition:
  - **d4.c shielded re-base (ATOMIC, consensus-linked surface):** oracle
    shielded agg vectors re-proved via prove_batch (1-instance batch,
    is_zk=1, salted MMCS — the hiding input-MMCS leaf form enters the
    batched C path here); num_qc STOP gate re-measure (P1d precedent:
    deviation from the pin → HALT + report); stark_prover_agg
    production+KAT paths re-based onto the batched pipeline;
    shielded_verify.c re-bases onto v4 decode + dnac_batch_verify (pins
    UNCHANGED: params + height + SALT_ELEMS=2 + shape/publics);
    DZKS v4 outer wrapper; test_shielded_verify rejects re-anchored
    (T-R9 forge included). Consensus-inert (type-11 still
    REJECT-unconditional) → no nodus version bump (C1 precedent), but
    d5 MUST re-run nodus ctest 132 (test_zk_link chain).
    **d4.c IMPLEMENTATION SURVEY (banked 2026-07-23 after d4.a+b — grounded
    pins so the build doesn't re-derive them):**
    - **Draw-stream identity:** for the 1-instance agg batch the BATCHED zk
      draw order (B1 main h(W+2nrc) → B2 quotient nqc·h_chunk·nrc +
      (nqc−1)·h_chunk·(DIM+nrc) → B3 R ext_h·(nrc+DIM)) numerically EQUALS
      the v3 agg layout trace (W+8)h ‖ codeword 32h ‖ blinding 42h ‖ R 12h
      (h_chunk = 2^13/8 = h at ext_db=11, lq=2) — total (W+94)h unchanged,
      so DNAC_AGG_PROVER_TOTAL_DRAWS stays.
    - **Salt stream A identity:** v3 layout (stark_prover_agg.c:713-720) =
      trace 16h ‖ quotient 8×16h ‖ random 16h (offsets lde_h·SE,
      lde_h·SE·(1+8)) == the batched commit call order main → quotient →
      random (per-commit, per-matrix in order, lde rows × SE row-major) —
      DNAC_AGG_PROVER_SALT_DRAWS(h)=160h stays. Stream B: commit-phase
      mixed ALREADY takes salt_draws/salt_elems (stark_prover.h:651-663);
      NULL→salt_draws@0 fallback keeps the KAT clone-seed parity
      (P1e-HIGH1 precedent).
    - **Verify side is salt-ready:** fri_open_input appends bo->salts per
      matrix BEFORE the MMCS call on BOTH the same-height and the d1a mixed
      path (fri_verifier.c:256-308) — no verify change needed;
      dnac_batch_verify passes salts through the FriProof untouched.
    - **batch_prover salted mode (to build):** extend dnac_batch_prove with
      (salt_draws A, num, fri_salt_draws B, num, salt_elems); FAIL-CLOSE
      salted+preprocessed (prep commit is SETUP-time in the reference —
      stream order would be invented) AND salted+lookups (no byte-match
      vector yet; lift when a salted+perm vector lands); salted commits =
      widened matrices (row ‖ SE salt lanes) through commit_mixed, query
      opens return width+SE rows → split into opened_values (width) +
      bo->salts (SE per matrix); commit-phase steps get salts from the
      fres (stream B consumed inside the commit phase — mirror v3 S12
      "salts from the same buffer commit used").
    - **Oracle:** batch-stark over the EXISTING SaltedZkStarkCfg
      (HidingFriPcs + MerkleTreeHidingMmcs(SmallRng(1), SE=2) input AND
      HidingChallengeMmcs cloned rng — main.rs make_salted_zk_config);
      ConfActionAggAir needs a Clone derive (unit struct) for
      run_batch_proof_scenario's A: Clone bound; reuse the SAME notes/
      trace fixture as dump_conf_action_agg_air_zk (h=128, log_height 7)
      and the v4_wire_bytes builder (extend for salt tails — serde
      BatchOpening of the hiding mmcs carries salts; walk + canonicalize).
    - **Wire:** the shielded TX blob stays RAW DZKF (v4) — TODAY's
      consensus path decodes sf->fri_proof directly (shielded_verify.c:166,
      no DZKS layer); introducing DZKS there would be a NEW wire layer
      (not in scope). DZKS itself has only B1/test consumers
      (stark_prover_prove self-check + 2 tests + gen tool) → its re-base
      moves to d4.d with stark_prover_prove.
    - **T-R9 forge knob:** batched pipeline folds publics into BOTH priming
      and quotient from insts[].public_values — the forge (FS over forged,
      quotient over true) needs a DNAC_ZK_ENABLE_TEST_WIRE-gated
      dnac_batch_prove variant with an fs-publics override + self-verify
      skip (v3 precedent: dnac_agg_prover_prove_production_forged_publics_
      testonly).
    - **Shielded verify re-base shape:** v4 package pins = is_zk==1, n==1,
      params eq (tamper-detect) + pinned set SUBSTITUTED, every FriProof
      salt_elems == 2, insts[0] = {air DNAC_CONF_ACTION_AGG_FOLD_AIR,
      degree_bits 11, log_num_qc 2, publics 43 recomputed from wire};
      opened trace_local len == 2318 (air width — the 4 zk-codeword lanes
      live in rand_openings now, UNLIKE v3's 2322-wide opened trace);
      quotient chunks = 8 PAIRS (tails in rand_openings); random opened
      len == 2; no prep/perm commits (fail-close). N2 rounds are ASSEMBLED
      (no wire opening points) — the v3 step-7 wire-coordinate checks
      DISAPPEAR by construction.
    - **d4.c-1 ✅ DONE — SALTED batch_prover VALIDATED (2026-07-23, uncommitted):**
      `test_batch_shielded_agg.c` (heap streaming JSON scanner, reusing the
      test_prover_agg 1in/2in/4in note/sibling fixture builders) feeds the RAW
      agg witness to `dnac_batch_prove` as a 1-instance is_zk=1 batch — via the
      new gated export `dnac_agg_zk_generate_trace_testonly` (DNAC_ZK_ENABLE_
      TEST_WIRE only, stark_prover_agg.{h,c}; absent from consensus builds) — and
      **byte-matches all 5 scenarios** (agg_1in/1in_salted/2in/4in/4in_salted):
      commits, α/ζ, opened trace_local[2318]/next/quotient[8]/random, the ENTIRE
      FRI proof, the hiding rand-openings, AND the **M3b leaf salts** (input-batch
      per-matrix + commit-phase step) on the salted scenarios. Vector
      `tools/vectors/batch_shielded_agg.json` (15,395,223 B, regen 2× byte-
      identical, `.expected_hashes`-pinned). **549 checks, 0 fail; `make test` 80
      binaries GREEN 0 warn.** ⇒ **`batch_prover.c` UNCHANGED** — the staged salted
      path (grounded hiding_mmcs.rs:118-131) was byte-correct as banked; the only
      defect was a TEST bug (uninitialized `pubs`: agg_zk_generate writes only the
      USED output_commit/nf slots, production uses a calloc'd struct → calloc fix;
      the signature — main+random roots match while α + downstream diverge —
      confirmed independently via a Plonky3 DuplexChallenger replay that reproduced
      the vector's α from the exact observe sequence). Regressions clean:
      test_batch_prover + test_batch_wire stayed GREEN.
    - **d4.c STAGED prereq (banked, unchanged):**
      (1) `dnac_batch_prove` extended with SALTED mode (salt_elems,
      salt_draws A, fri_salt_draws B) — `bp_commit_mixed_salted` widens each
      committed matrix to `row ‖ SE salt lanes` and commits via commit_mixed;
      query opens split `width` (opened) + `SE` (bo->salts); commit-phase
      steps salt from stream B. **Salt order GROUNDED to hiding_mmcs.rs:
      118-131:** `commit` locks ONE persistent rng and draws
      `RowMajorMatrix::rand(rng, mat.height()=lde_h, SALT_ELEMS)` per matrix
      in input order, CONTINUOUS across the main→quotient→random commit
      calls == the single `salt_cur` cursor. Stream B = the FRI
      HidingChallengeMmcs's CLONED rng (make_salted_zk_config), a fresh
      SmallRng(1) → NULL fri_salt_draws falls back to salt_draws@0
      (same-seed parity). FAIL-CLOSE salted+preprocessed AND salted+lookups
      (no byte-match vector; the reference commits prep at setup-time —
      its stream position is un-exercised). Draw/salt totals verified ==
      the v3 agg 160h at h=128 (`dnac_batch_prove_num_salt_draws`).
      **Unsalted path byte-identical: test_batch_prover/wire GREEN.**
      (SALTED path now VALIDATED — see d4.c-1 above.)
      (2) Oracle `dump-batch-shielded-agg` (CLI wired, `ConfActionAggAir`
      got a `#[derive(Clone)]`): 5 scenarios (agg_1in / agg_1in_salted /
      agg_2in / agg_4in / agg_4in_salted) — the v3 agg fixtures re-proved
      via REAL prove_batch as 1-instance is_zk=1 batches over
      make_plain/salted_zk_config; every verify_batch==Ok + **num_qc STOP
      gate == 8 PASSED on all 5** (no pin deviation → no HALT); v4 wire
      bytes emitted (salt-aware `v4_push_friproof(salt_elems)` walks the
      hiding-mmcs Proof TUPLE (salts, siblings), hiding_mmcs.rs:118).
      Regen 2× byte-identical, ~15 MB. **NOT copied to tools/vectors (no C
      consumer yet)** — regen: `plonky3_oracle dump-batch-shielded-agg
      --out tools/vectors/batch_shielded_agg.json`.
    - **d4.c-2+3+4 ✅ DONE (2026-07-26, ORCHESTRATOR-verified) — v3→v4 agg-surface
      flip, GREEN.** `dnac_agg_prover_prove`/`_prove_production` re-based to a
      THIN WRAPPER delegating to `dnac_batch_prove` (agg trace via
      `agg_zk_generate` → 1-instance is_zk=1 batch; production=salted SE=2 + OS
      entropy; the v3 S1-S13 uni-stark pipeline retired). `shielded_verify.c`
      re-based onto `dnac_batch_wire_decode` (DZKF v4) + `dnac_batch_verify`
      (pins HELD: is_zk==1, n==1, params-eq→SUBSTITUTE pinned, opened shape
      trace 2318/trace_next 2318/8 qc/random 2/no prep-perm/0 globals,
      SALT_ELEMS==2 on every FRI opening, degree_bits==11 COMPILE-TIME pin).
      The v3 wire opening-coordinate check is GONE by construction (v4 carries
      no opening points → the verifier samples ζ; the v3 H2/OPENING_POINT class
      closes structurally). Tests re-anchored: test_prover_agg (delegation
      accessors, 5 invocations incl. salted), test_prover_shielded_production
      (PHASE-P GREEN), test_shielded_verify (T-A accept + 12 fail-close;
      T-R1/R4/R5 OPENING_POINT→FRI via FS-divergence, T-R7/R8 RETIRED, T-R9
      forge via a DNAC_ZK_ENABLE_TEST_WIRE-gated `dnac_batch_prove_forged_fs_
      testonly`).
      **5 defects the fork left (all surfaced by ORCHESTRATOR running every
      build/test — new-model validation): (1) Makefile dup-link
      test_batch_shielded_agg; (2) test_prover_agg `public_values` string-parse
      INFINITE LOOP (JSON emits u64 as strings; js_read_u64 stalled); (3)
      batch_prover.c query cap `query_indices[64]` < production 100 → PARAM,
      bumped BP_MAX_QUERIES=128; (4) Makefile prereqs missing batch_*.c →
      STALE-BINARY (incremental make ran old code) — added to all 3
      AGG_PROVER_SRCS consumers; (5) nodus/CMakeLists.txt missing
      batch_verify/priming/logup_bus/logup for the re-based shielded_verify →
      test_zk_link undefined-ref, added.**
      Verified GREEN: `make clean && make test` 80 binaries 0 warn (ALL GATES
      + C2.1 SHIELDED VERIFY + PHASE-P PRODUCTION + d4.c-1 SALTED), nodus build
      clean + `ctest` 132/132 (test_zk_link links the batched-verify chain).
      Consensus-inert (type-11 REJECT) → no nodus version bump. Commit/push YOK.
  - **d4.d ✅ DONE (2026-07-26) — v3 UNI-STARK RETIRED, P2L-d COMPLETE.**
    User scope decisions: D1=A (full retirement, not a re-base), D2=a (delete
    the v3 DZKF surface + DZKS and re-anchor the nodus pin), D3 (drop
    stark_priming.c from nodus/CMakeLists.txt).
    - **DELETED (31 files):** `stark_priming.{c,h}`, `stark_proof_codec.{c,h}`
      (DZKS), `stark_prover_{prove,conf,action}.{c,h}`; 10 tests
      (test_stark_priming{,_zk,_integrated}, test_fri_verify_zk,
      test_prover_s13_verify, test_prover_{prove,conf,action},
      test_stark_proof_codec, test_fri_proof_codec); 2 gen tools
      (gen_stark_proof_wire, gen_fri_proof_wire); 9 orphaned vectors
      (stark_priming*, stark_proof_wire*, fri_proof_wire, prover_full_{a,b,c}).
      NOTE vs the old plan: **nothing was regenerated under the batched shape** —
      D1=A retires these vectors outright, so no oracle run was needed.
    - **v3 codec surface GONE ENTIRELY** — `dnac_fri_proof_encode`/`_decode`,
      `dnac_fri_verify_wire`, `dnac_fri_verify_wire_shielded`, the read
      accessors, `dnac_fri_wire_{package_t,free}`, `enc/dec_{point,matrix,
      commitment}`, `DNAC_FRI_WIRE_VERSION` and the v3-only bounds. The shared
      static primitives the v4 codec uses were kept (grep-proven).
      PIN PRESERVATION checked line-by-line before deleting the shielded
      wrapper: every pin lives on the v4 path — is_zk/n==1 (shielded_verify.c
      :179-182), params-eq :188-196 → **SUBSTITUTE** pinned :197-204 passed at
      :252, opened shape :210-216, SALT_ELEMS==2 :91-103/:221, degree_bits==11
      compile-time :243, fail-close default :174.
    - **nodus:** `stark_priming.c` dropped from `NODUS_SOURCES`; the C1/M5
      comment restated (the unpinned v3 entries are no longer "compiled out" —
      they do not exist); `tests/test_zk_link.c` T2/T3/T4 re-anchored onto
      `dnac_shielded_verify_statement`. T3/T4 build a statement whose
      tx_binding is derived from its own sighash_v4 (via the LINKED
      `dnac_tx_shielded_sighash` + `conf_txbind_map`), so they run past
      canonicalization/fee/txbind and actually reach the DZKF v4 decode.
    - **bench_prover REWRITTEN** onto `dnac_batch_prove` + `dnac_batch_verify`
      (user chose keep-and-re-base over delete). The v3 uni-stark perf numbers
      in the PERF block below are therefore **historical** — they measure a
      pipeline that no longer exists.
    - **O6 dual verification** (executor + an independent `verifier` that never
      saw the ORCHESTRATOR verdict) returned 3 CONFIRMED / 3 REFUTED. All three
      refutations were re-confirmed at their file:line and fixed:
      1. `fri_proof_codec.c:9` claimed the v3 decoder survived — stale.
      2. `test_zk_link.c:15` claimed the re-anchored gate pulls a "STRICTLY
         LARGER" object set — **FALSE**: BEFORE's T5 already called the same
         entry, so the set SHRINKS. (Fabricated-strength claim in a comment;
         only the second pair of eyes caught it.)
      3. **COVERAGE HOLE:** `ERR_LENGTH_OVERFLOW` (rd_count_fixed/rd_count_var)
         and `ERR_BAD_DEPTH` (rd_depth) lost their only tests with
         `test_fri_proof_codec` while staying LIVE on the consensus-linked v4
         decode path. CLOSED in-slice: `test_batch_wire` N8/N9, a deterministic
         mutation sweep (every u32 field offset ≡ 10 mod 4 patched to
         0xFFFFFFFF; both guard classes MUST be observed). batch_wire checks
         73 → 74 (−N2a, +N8, +N9).
    - **Makefile prereq/stale-binary hygiene (pre-existing defect, fixed on
      user approval):** 19 recipes linked a source that was not a prerequisite,
      so an incremental build silently ran a STALE binary. The root cause was
      deeper than a missing name — `AGG_PROVER_SRCS` was defined ~300 lines
      AFTER `test_batch_shielded_agg`, and make expands prerequisites when it
      READS the rule, so naming the variable would have expanded to EMPTY.
      Definition moved into the top stack block + one global
      `$(TESTS): $(SHA3_SRC)`. Re-verified against the `make -pn` database:
      **70 recipes checked, 0 offending.**
    - Fixture consolidation done: `tests/batch_test_util.h` is the single
      definition (all `static inline`); `test_batch_verify.c` includes it.
    - Comment drift repaired: `shielded_verify.h` steps 4/5 (they still
      described the deleted v3 chain as the consensus path), `ERR_DECODE`,
      the three RETIRED verdicts 10/11/12 (never assigned since d4.c-3).
  - **d5 ✅ GREEN (ORCHESTRATOR-run, 2026-07-26):** zk `make clean && make test`
    → **70 binaries, ALL GATES GREEN, 0 compiler warnings** (`grep -c
    'warning:|error:'` = 0); nodus `cmake && make` 0 warnings + `ctest`
    **132/132** with `test_zk_link` PASSED (empirically confirming the
    re-anchored T2/T3/T4 reach the decoder); messenger/libdna build clean
    (`libdna`, `dna-connect-cli`, `dna-explorerd`). All 52 surviving vector
    hash pins verify. Consensus-inert (type-11 still REJECT-unconditional) →
    **no nodus version bump** (C1 linkage-only precedent).
  → d6 docs/memory (this block, design doc §4/§5, root CLAUDE.md, zk README,
  memory + ledger).
- **✅ COMMITTED + PUSHED (2026-07-26): `b30f2425`** — "feat(zk): P2L complete —
  LogUp + batched STARK, DZKF v4, v3 uni-stark retired". 88 files (26 added,
  31 deleted, 31 modified), pushed to `gitlab` then `origin`. NO `[BUILD]` tag
  (the messenger C library is untouched — zk+nodus commit, per the nodus-only
  rule) and NO version bump (consensus-inert, C1 linkage-only precedent).
  Everything P2L is now in history, including the 15 MB
  `tools/vectors/batch_shielded_agg.json` KAT input (user-approved: the pin in
  `.expected_hashes` needs it, and a fresh clone must be able to run the suite).
  The only working-tree items deliberately left OUT of the commit are unrelated
  and pre-existing: `Testing/`, `cpunk/cpunk.io/js/`, `dnac/tests/test_stress.c`,
  `docs/2026-07-08-project-assessment.md`, `scripts/punk-daily-summary.*`.
- **S2'-d ✅ COMPLETE (2026-07-27, this working tree) — the FRI/MMCS verify
  surface hardening that the v0.6.2 migration's red-team surfaced.** Six items,
  all landed; the first three shipped earlier in the day, the last three had to
  land as ONE block because the signature change makes half of it uncompilable.
  Consensus-INERT throughout (type-11 still REJECT-unconditional,
  `nodus_witness_verify.c:750-753`) but consensus-LINKED (the changed sources
  compile into libnodus, `nodus/CMakeLists.txt:192/194/222/223`), so everything
  here goes live the moment C3 flips shielded admission on.
  - **Fail-open #1 — empty batch skipped the MMCS verify entirely.**
    `have_height` stayed false at `cw->num_matrices == 0`, gating OUT the whole
    verify block; upstream calls `input_mmcs.verify_batch` unconditionally
    (82cfad73 fri/src/verifier.rs:590-597). Now fail-close in `dnac_fri_verify`
    itself, since that is a public entry.
  - **Fail-open #2 — a matrix opened at ZERO points had an unchecked row
    width.** The only width check lives inside the point loop, which never runs
    at `num_points == 0`, while the row is already hashed into the flat leaf.
    Upstream: `MatrixWithoutOpeningPoints` (v0.6.2 verifier.rs:698-707).
  - **Fail-open #3 — `z == x` silently DELETED a matrix's claim.**
    `gold_fp_inv(0)` returns 0 by its own documented contract
    (`field_goldilocks.c:170-181`), so the quotient became 0, every term
    vanished, and those claimed evaluations were never tested against anything —
    while `alpha_pow` advanced normally. Upstream rejects instead
    (`OpeningPointMatchesQueryPoint`, v0.6.2 verifier.rs:642-662, where the
    equivalent would panic in `batch_multiplicative_inverse`).
  - **Heap overread — the Merkle path length never crossed the API boundary.**
    `opening_proof.depth` was decoded from the wire and the siblings array
    allocated to exactly that (`fri_proof_codec.c:352-360`, whose own comment
    admits it "does NOT check depth == verifier-derived height"), but the walk
    was bounded by the depth the VERIFIER derived — and `.depth` was read
    nowhere in the tree. Patch it 13 → 1 and the MMCS read 384 bytes past a
    32-byte allocation, with nothing to catch it (query proofs are never
    observed into the transcript, so the PoW witness still validated). The
    verdict stayed deterministic (ROOT_MISMATCH) so this was memory-safety, not
    a soundness break — but Android is a declared target and its hardened
    allocator turns that into a probabilistic SIGSEGV.
    **FIX: `dnac_p2_mmcs_verify` / `_mixed` now take a `const dnac_p2_proof_t *`**
    — pointer and length inseparable, the C form of upstream's
    `opening_proof: &[Digest]` — and enforce
    `proof->depth == log2(height)` exactly as upstream's WrongHeight does
    (82cfad73 mmcs.rs:1110-1116, unchanged at v0.6.2 mmcs/batch.rs:174-179).
    24 call sites converted; `leaf_index`/`num_matrices` are documented as NOT
    read (the verifier derives both). Every producer already set `.depth`
    correctly — the bug was purely that the verifier threw it away.
  - **Row-width authority — half constant, half wire.** Under the Poseidon2
    PaddingFreeSponge the leaf is a flat, separator-free stream, so a row
    boundary is only as authenticated as the width the verifier asserts;
    `num_claimed_evals = BASE_LEN + tail` made half of it prover-chosen. A
    same-height group could be REPARTITIONED at constant total — the 8 quotient
    rows as 7,5,6,6,6,6,6,6 instead of 6×8 — for a byte-identical leaf under the
    same committed root. **FIX: `dnac_batch_verify` gained two REQUIRED pins,
    `num_random_codewords` and `salt_elems`**, mirroring the prover's own
    parameters (`batch_prover.h`). The salt pin MOVED DOWN from
    `shielded_verify.c` (where it guarded one entry) into the decode → verify
    pair itself, so P2 recursion cannot inherit the hole; `shielded_fri_params.h`
    gains `DNAC_SHIELDED_NUM_RANDOM 4` next to `DNAC_SHIELDED_SALT_ELEMS 2`,
    CT-asserted against the prover's `A_NUM_RANDOM`.
    ⚠ **STRICTER THAN UPSTREAM, deliberately — not a port.** Plonky3's hiding
    PCS checks only the NESTING SHAPE of the random openings (round/matrix/point
    counts, v0.6.2 hiding_pcs.rs:398-428); the per-point tail LENGTH is never
    pinned, and verifier.rs:698-711 pins width to `values.len()` = public + that
    unpinned tail. The reference carries the same freedom.
  - **FriError mirror completed to v0.6.2.** Upstream added EIGHT variants and
    dropped one between the two pins. All eight are declared (21-28, appended —
    the enum is DNAC-internal and crosses no wire, so renumbering would buy
    nothing); three bind to guards DNAC already had (`ZeroQueries`,
    `GlobalMaxHeightTooLarge`, `MatrixWithoutOpeningPoints`), one brings the new
    `z == x` guard, and four are declared-but-unraised with the reason written
    at each (`GlobalMaxHeightMismatch` is DEFERRED as its own item — DNAC has
    only a one-sided post-transcript version; the three `HidingRandomOpening*`
    live in `dnac_batch_verify`'s status enum, not FriError). `InvalidProofShape`
    is KEPT despite upstream removing it — DNAC raises it for local bound checks.
  - **Bound tightened 64 → `GOLDILOCKS_TWO_ADICITY` (32).** The old bound only
    closed shift-count UB and left 33..63 accepted, and there
    `gold_fp_two_adic_generator` returns `gold_fp_one()`
    (`field_goldilocks.c:206-209`) — it does not panic, it degrades. What
    degenerates is the FRI TERMINAL point (`two_adic_generator(lgmh)^rev`, no
    generator coset factor): past 32 it is 1 for every query, so the final
    polynomial is only ever tested at ONE fixed point. Upstream bounds by
    `Val::TWO_ADICITY` for the same reason (v0.6.2 verifier.rs:258-268).
    Honest shielded lgmh is **13** (log_blowup 2 + log_final_poly_len **0** +
    sum_la 11), and the prover rejects `degree_bits >= 30` outright.
  - **NO VECTOR CHANGES.** Every fix only rejects malformed proofs; the prover
    emits exactly `nrc` on non-preprocessed points and 0 on preprocessed ones,
    so honest behaviour is byte-identical. This is what let the block land green
    on its own, ahead of the rest of the v0.6.2 C re-port.
  - **New negatives:** `test_batch_wire` N10-N14 (short input-batch path, short
    commit-phase path, tail repartition at constant total, wrong salt pin, wrong
    nrc pin) driven on the LIVE decoded package with per-guard coverage
    assertions — 74 → **96 checks**; `test_fri_verifier_valid` 6 → **8/8** ERRCHK
    cases, the `z == x` one re-deriving the query point independently of
    `fri_verifier.c`.
  - **O9 (ORCHESTRATOR-run):** zk `make clean && make test` exit 0, **70
    binaries, 0 warnings, ALL GATES GREEN**; nodus cmake+make 0 warnings, **ctest
    132/132** (`test_zk_link` Passed); messenger 0 warnings, libdna.so built.
    No version bump (consensus-inert, C1 precedent).
  - **Still open from this thread:** the `GlobalMaxHeightMismatch` two-sided
    cross-check; then F2 (`generate_permutation` rewrite, aux width
    `num_lookups + 1`), then S2'-c remainder → S2'-e → S2'-f (the other 31
    vectors).
- **S2'-b (F1) ✅ REDONE (2026-07-27) — the challenger is prefix-free, and the
  tree is now deliberately RED until S2'-f.** `dc_duplexing` ports v0.6.2
  `challenger/src/duplex_challenger.rs:86-112`: after overwriting the leading
  rate slots it now CLEARS the rate slots the inputs did not reach (rs:102) and
  ADDS the absorbed length into the first capacity element (rs:104) — a field
  add, not a store, because the capacity carries sponge state across
  permutations. The `num_absorbed > 0` guard keeps a SQUEEZE from doing either
  (rs:98-99). Without this a k-element absorb and its zero-extension reached the
  same post-permutation state, so length and zero-padding could collide; every
  Fiat-Shamir challenge in the stack moves as a result.
  O2 note: the WHOLE file was diffed between the pins, not just the function —
  `duplexing` is the only semantic change (the rest is trait bounds + tests),
  and `absorb_rate_padded_with_tag` is not ported into DNAC.
  **Byte-match on the first attempt:** `test_duplex_challenger` PASS, 13 cases /
  80 steps; `tools/vectors/duplex_challenger.json` replaced by the v0.6.2 regen
  (format_version 2, commit 11cc5849) with its `.expected_hashes` line updated
  in the same step — that hash is a `make test` gate, so a stale one aborts the
  run before any test executes.
  **THE RED WINDOW IS MEASURED, NOT ASSUMED.** `make test` halts at the first
  failing recipe, so all 75 runner invocations were executed individually:
  **54 PASS / 21 FAIL**, and every one of the 21 failures links
  `duplex_challenger.c` — cross-tabbed against the actual link commands, with
  ZERO failures that do not. All 18 tests on S1c-unchanged vectors
  (poseidon2_mmcs{,_mixed}, fri_fold×3, fri_verifier_verify_query, range_air,
  sum_balance, ntt, note_commit, poseidon2_air_trace, poseidon2_goldilocks,
  prover_trace, primitive_ops, two_adic_gens, field_ops, field_ext, smallrng)
  stay GREEN, so nothing unrelated is hiding behind the red. nodus: 0 warnings,
  ctest 132/132 (nothing there pins challenger output values).
  NOT COMMITTED — F1 alone leaves the tree red; it commits at S2'-f.
- **S2'-c + S2'-e ✅ DONE as ONE MERGED SLICE (2026-07-27) — the LogUp terminal
  collapse, from the gadget through the DZKF v4 wire.** They could not be
  separated: `dnac_batch_vopened_t` is the seam between them and the terminal
  crosses it.
  **The model change (v0.6.2).** `global_lookup_data: Vec<Vec<LookupData>>` — a
  per-instance LIST of (bus name, aux column, cumulative sum) records — becomes
  `lookup_terminals: Vec<Option<LookupTerminal<Challenge>>>`, ONE optional value
  per AIR (`batch-stark/src/proof.rs:22`; `LookupTerminal<F>(pub F)` is a
  newtype over a single Challenge, `lookup/src/types.rs:301`). Bus names and aux
  columns stop being proof data at all, so v0.6.2 DELETES the metadata
  cross-check outright rather than relocating it; what survives is the Option
  discriminant, `TerminalPresenceMismatch`.
  **Aux layout.** `aux_width = num_lookups + 1` when the AIR declares any lookup
  and 0 otherwise (was `max(lookup.column) + 1`): column 0 is ONE shared
  accumulator, lookup slot c owns fraction column c+1.
  **Constraint order** (`lookup/src/protocol.rs:56-82`): `air.eval` first, then
  one UNGATED `U·f − V` per lookup on EVERY row (logup.rs:245 — the identity is
  cyclic so it needs no transition gate, and forcing it everywhere pins the
  last-row value the terminal binding consumes), THEN one accumulator block:
  `is_first·acc`, `is_transition·(acc_next − acc − row_sum)`,
  `is_last·(terminal − acc − row_sum)`. The `is_global` branch is gone — one
  accumulator covers local and global alike.
  **Cross-AIR check** is now the FLAT `dnac_logup_verify_terminal_sum`. That is
  sound at v0.6.2 where it was not before: bus separation moved DOWN into the
  challenge derivation (`prefix[bus] = α + (bus+1)·β^W`, one power above every
  payload term — `lookup/src/challenges.rs:19-23`), so two buses cannot produce
  cancelling contributions. The per-bus grouping entry point is deleted rather
  than kept as dead code implying a protection that now lives elsewhere.
  **W = max_message_width** is shared by prover and verifier through ONE helper,
  `dnac_logup_bus_max_message_width` (`transcript.rs:118-135`: seed **1**, max
  over every tuple of every lookup of every instance). It had been computed
  inline in the prover and not at all in the verifier; two implementations of
  the value feeding γ = β^W is a transcript fork waiting to happen.
  **DZKF v4 wire — REDEFINED IN PLACE, NOT BUMPED.** Per instance the record is
  now `u32 count (0 or 1) ‖ [fp2 terminal iff 1]`. The layout was NOT a design
  choice here: the migrated oracle already fixed it and left the instruction at
  `tools/plonky3_oracle/src/main.rs:18194-18207`. Version stays 4 because v4 has
  no live speaker — type-11 is REJECT-unconditional
  (`nodus/src/witness/nodus_witness_verify.c:749-753`) and the only reference
  outside `shared/crypto/zk` is a COMMENT (`nodus/tests/test_zk_link.c:14`), both
  grep-proven. The expiry condition for that reasoning is recorded in
  `fri_proof_codec.h`. `DNAC_BATCH_WIRE_MAX_GLOBALS` / `_MAX_BUS_NAME` are gone.
  **Vectors landed (5):** `logup.json`, `logup_bus.json`, `batch_priming.json`,
  `batch_proof.json`, `batch_shielded_agg.json` + their `.expected_hashes`
  lines; `sha256sum -c` clean across all 52.
  **Two serde/API changes the regeneration forced, worth knowing before S2'-f:**
  (1) `num_aux_cols` in the vectors is the aux WIDTH (`num_lookups + 1`) where it
  used to equal the lookup count; (2) **v0.6.2 emits Goldilocks base elements as
  BARE numbers where 82cfad73 wrapped them as `{"value": N}`.** The second one
  wedged the hand-rolled parser in `test_batch_shielded_agg.c` /
  `test_prover_agg.c` in an infinite loop (no token matched, `s->pos` never
  advanced) — a 41-second test ran past 15 minutes emitting nothing and looked
  exactly like a crypto hang until `gdb -p` showed `js_skip_ws / parse_base_obj`.
  Both now accept either vintage and carry a no-progress guard. **The identical
  parser is still in `test_fri_verifier_rollin.c` and `test_fri_verifier_valid.c`,
  which read 82cfad73-era vectors today and WILL hit this the moment S2'-f
  regenerates theirs — fix them in the same slice.**
  **Gate (per-binary, because `make test` halts at the first failure and the
  first failure is a stale-vector test):** 70 binaries run individually with the
  Makefile's own invocations. Every red links a changed source AND reads a stale
  vector; **no test that links none of the changed sources is red.** The agg
  path was baselined against a git worktree at HEAD (41s) to prove the timeout
  was the parser and not a crypto regression — after the fix, 42s / 549 checks /
  byte-matched.
  NOT COMMITTED — the tree stays deliberately RED until S2'-f lands the
  remaining stale vectors. Next: **S2'-f** (the other 31 vectors + full green).
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
- **LINKED into the nodus build (Phase-C C1, 2026-07-21) — but NOT yet CALLED
  by consensus.** The Phase-C gate was opened by the user 2026-07-21. C1 added
  the pinned shielded verify stack (codec v2 + FRI verifier + transcript/
  sponge + Merkle + field, 12 files) to `nodus/CMakeLists.txt` (the messenger
  tree inherits it via `add_subdirectory(nodus)` / libnodus.a — single link
  site, no dup symbols). LINKAGE ONLY: nothing in the witness calls it yet
  (that is C2), so consensus behavior is unchanged and no version was bumped.
  Gates: `nodus/tests/test_zk_link.c` (pulls the whole
  `dnac_fri_verify_wire_shielded` chain out of libnodus.a + pins the six
  shielded params from the nodus side); **M5 CLOSED** — the unpinned
  `dnac_fri_verify_wire` is compiled ONLY under `DNAC_ZK_ENABLE_TEST_WIRE`
  (zk standalone Makefile), `nm libnodus.a` proves the symbol absent.
  Prover-side sources are deliberately NOT in nodus (client/wallet side, S7).
  Money conservation on the live chain is still enforced by the native
  cleartext witness check (`verify.c` Check 4); the ZK stack stays ADDITIVE
  until C2/C3 (shielded pool, state_root v4 — BREAKING, own approvals).
  Remaining Phase-C order (user decisions 2026-07-21: ak/nk multi-lane FIRST;
  prune/heartbeat NOT bundled): **C1 ✅ → F3 ak/nk multi-lane ✅ (2026-07-22) →
  C2 witness verify ✅ (C2.1+C2.2+C2.3+C2.4 all 2026-07-22 — records below;
  C2.4 red-team GREEN, 0 confirmed defect) → C3 state_root v4 (minimal) →
  C4 Genesis 7/7.**
  - **C2 DESIGN v2 (2026-07-22):** `dnac/docs/plans/2026-07-22-c2-witness-
    shielded-verify-design.md` (local, 3 sections). Design red-team returned
    NOT-GREEN (2 CRIT + 2 HIGH, all confirmed against the tree); doc REVISED:
    (CRIT-2) C2 does NOT flip admission to accept — an admitted type-11 TX
    pre-C3 mints fee-pool credit with no debit (`bft.c:1907`→route_tx_fee) +
    records no nullifier (double-spend); the accept-flip MOVES to C3's first
    commit. C2 ships the verify FUNCTION + KATs behind an UNCONDITIONAL type-11
    REJECT. (CRIT-1) verify chain MUST include `dnac_stark_verify_constraints_
    nchunk` — FRI-verify alone is soundness-vacuous (mint). (HIGH-1) hook seam
    is AFTER Check 2 (extended for V4 tag + shielded section), dispatch to
    verify_shielded_tx() replacing Checks 3-6 (signer_count==0 for shielded);
    "between Check3↔Check4" was wrong (Check2 V2-only + Check3 no-signers both
    reject type-11 first). (HIGH-2) anchor is attacker-chosen → root-set
    membership deferred to C3 = 2nd reason no-accept-in-C2. Build order:
    C2.1 zk-side verify entry + KATs → C2.2 witness admission (REJECT-only) →
    C2.3 ctest/regression → C2.4 **10+-agent CODE red-team (cost-gate: consensus
    /shipped-crypto scale, needs user cost+park approval before opening)**.
  - **🎯 C2.1 DONE (2026-07-22, uncommitted — commits with the rest of C2):**
    `dnac_shielded_verify_statement(sf, chain_id, committed_fee)` in NEW
    `shielded_verify.{c,h}` (consensus-linked into libnodus, nodus CMake).
    Chain (all fail-close, distinct status per branch): wire canonicalization
    (counts, DET-S5-3 slot-zero, per-lane < p, fee==committed_fee) → sighash_v4
    via the LINKED libdna `dnac_tx_shielded_sighash` (G-DET-2, no re-impl) →
    `conf_txbind_map` == wire tx_binding → 43 publics recomputed FROM WIRE →
    decode + shape-pin (3 coms random/trace/quotient, widths 6/2322/6, num_qc=8,
    every domain == pinned height 11) → fresh transcript prime, zeta/zeta_next
    SAMPLED, every wire opening coordinate MUST equal the sampled point (H2/H3
    CLOSED) → `dnac_fri_verify_wire_shielded` **AND**
    `dnac_stark_verify_constraints_nchunk` (CRIT-1). Gates:
    - `tests/test_shielded_verify.c` (in `make test`, now **66 GREEN 0 warn**):
      production-proof ACCEPT + 13 distinct fail-close rejects incl. the
      **CRIT-1 isolator T-R9** — a forged-publics proof (honest FS over fee+1,
      quotient from true publics) that FRI ACCEPTS and only the constraint
      check rejects. Forge + wire-encode are `DNAC_ZK_ENABLE_TEST_WIRE`-gated
      test-only exports in stark_prover_agg (M5 pattern, absent from libnodus).
    - nodus `test_zk_link` T5: the whole C2.1 chain (verify entry + linked
      sighash) links out of libnodus.a; cheap fail-close branches fire.
      **nodus ctest 132/132; messenger/libdna build clean.**
    - Fix landed with C2.1: `DNAC_STAKE_PURPOSE_TAG` definition moved
      transaction.c → serialize.c (wire layer owns it; serialize.c now
      standalone-linkable — byte-identical constant, extern decl unchanged).
      Also fixed a committed F3 miss: test_prover_shielded_production nk[3]/
      ak[3] → nk[12]/ak[12] (9-u64 stack OOB read, UB — test was green by
      accident).
  - **🎯 C2.2 + C2.3 DONE (2026-07-22, uncommitted — one C2 commit):**
    witness admission, REJECT-only (design v2 §4.3, HIGH-1 seam):
    - `NODUS_W_TX_SHIELDED 11` (nodus_witness.h, == DNAC_TX_SHIELDED);
      `nodus_witness_recompute_tx_hash` gained the V4 arm (own domain tag +
      the 330-B shielded statement hashed VERBATIM, fri blob NOT hashed —
      byte-order-matched to libdna transaction.c:341-367); dispatch right
      after Check 2 to `verify_shielded_tx()` which REPLACES-and-RETURNS
      Checks 3-6: D7.1 empty transparent body, signer_count==0 pin, canonical
      shielded-section parse (lane<p, counts, slot-zero), fee==committed_fee
      (D7.2) — then **UNCONDITIONAL REJECT** ("disabled until C3"); the C3
      accept-flip insertion point is marked in-code. Check-5 mempool read is
      structurally unreachable for type-11 (G-DET-1). nodus v0.18.15→0.18.16.
    - Gates: test_witness_tx_hash_parity +SHIELDED V4 parity + blob-not-
      hashed/statement-hashed KATs; test_witness_verify +5 shielded admission
      rejects (well-formed/transparent-body/signer/fee/slot — each on its
      precise reason). nodus ctest 132/132; messenger build clean.
    - **C2.3 Genesis Protocol harness (STAGEF_EPOCH_LENGTH=3, 17 scripts):
      15 PASS, 2 documented SKIP stubs (halving_boundaries, supply_invariant_
      halt), every state_root assertion 7/7 IDENTICAL** (…19|E38C, 20|CB6A,
      21|9336 incl. post-pause-resume convergence). `test_view_change_fork`
      Phase B failed twice on a PRE-EXISTING liveness-recovery issue
      (SIGSTOP'd leader → 0/6 view-change quorum → commit stalls minutes;
      SAFETY intact both runs; type-11-gated C2 diff can't touch it) — root-
      caused + recorded in nodus/BUGS.md 2026-07-22 entry; harness helper
      `stagef_mk_funded_user` fixed to poll CHAIN truth after CLI timeout
      (kills the known project_genesis_client_false_error false-negative).
    - **C2.4 CODE RED-TEAM GREEN (~11 agents, wf_731fd475): 0 confirmed defect**
      (Phase-0 6/6 non-issue; 8/9 finders empty; 1 INFO refuted → cosmetic
      shielded-dispatch reorder above the is_genesis return). **C2 COMMITTED
      `06a1ecde`** (nodus+zk+dnac, tag YOK, push YOK).
  - **🛑 C3 DESIGN NOT-GREEN — BLOCKED (2026-07-22).** `dnac/docs/plans/
    2026-07-22-c3-state-root-v4-design.md`; single-agent design red-team =
    **2 CRIT + 1 HIGH** (§0 facts all correct). CRITs are UPSTREAM of C3, not
    doc revisions:
    - **F1 (note-tree agreement):** consensus note-tree ↔ prover
      `conf_membership_air` UNRESOLVED. `CONF_AGG_TREE_DEPTH=4` = a KAT
      placeholder ("production depth pinned at S6", conf_action_agg_air.h:104-105;
      depth-4 = permanent 16-note cap); production depth = a separate S6 CIRCUIT
      re-grounding (oracle vectors + num_qc + byte-match, 10+-agent KAFADAN
      gate). Hash primitive mis-mapped: proof uses Poseidon2 `note_merkle_compress`
      (note_commit.c:66-80), NOT SHA3 `compute_*_root` → SHA3 consensus root ≠
      Poseidon2 anchor = liveness break. Empty-leaf + leaf/internal domsep open.
    - **F2 (supply invariant):** "fee reconciliation keeps the invariant" FALSE
      vs `check_supply_invariant_v016` (bft.c:896-990, observed = plaintext sums,
      confidential pool invisible; committed_fee burn → block REJECT). No
      confidential-pool accounting model.
    - **F3 (HIGH, plan-fixable, folded into doc G-SEC-C3-2):** intra-TX
      `nf_set[i]!=nf_set[j]` + in-batch seen-shielded-nf guards were missing.
    - **REAL NEXT WORK (each its own grounded doc + red-team):** (1) production
      note-commitment tree (depth pin + Poseidon2 incremental-Merkle byte-matched
      to conf_membership_air + empty-leaf/domsep) [S6 crypto, KAFADAN 10+-agent];
      (2) confidential-pool supply-accounting model. **C3 CODE DOES NOT START
      until both land.** Push YOK, deploy YOK.
  - **🎯 F3 DONE (2026-07-22, S-F3.0→S-F3.5 one session, single commit):**
    ak/nk widened 1→4 Goldilocks lanes (user-locked A_LANES=N_LANES=4; nk alone
    was ~2^32 Grover via public (ρ,nf) → now ~2^128, matching the stack's
    128-bit PQ target). Design: `dnac/docs/plans/2026-07-21-f3-aknk-multilane-
    design.md` (local, status IMPLEMENTED + §3 run record).
    - **Widths:** conf_action 813→1002 (ak[4]/nk_src[4]/nk_carry[4], addr
      sponge AC1/AC2/AC3 over 12-slot `[ak0..3, nk0..3, DOMSEP_ADDR, 0,0,0]`);
      conf_nullifier 730→913 (nk[4], nf sponge NF1/NF2/NF3 over `[nk0..3,
      ρ0..3, DOMSEP_NF, 0,0,0]`; ρ unchanged); agg construction 1915→2287;
      proven CONF_AGGZK 1946→2318. Sponge = EXACTLY 3 perms (12=3·RATE, no pad
      permute — note_commit.c:18-48 / Plonky3 sponge.rs:176-203); preimage
      ORDER is our pinned §3b design choice.
    - **Oracle:** Rust ConfActionAir/ConfActionAggAir + builders widened;
      instances lane-matched to the C tests; **num_qc MEASURED=8 on all 6
      vectors (STOP gate)**; every vector regen 2× byte-identical; SmallRng KAT
      stream 524288→655360 draws (old stream proven a strict PREFIX).
    - **Caps (fail-close, all raised for W=2318):** DNAC_STARK_MAX_MAIN_WIDTH &
      DNAC_PROVER_MAX_TRACE_WIDTH 2048→2560; FRI_LEAF_CAP 16384→20480 (root
      cause of agg self-verify InputError(17): merged row 2322 cols = 18576 B).
      Action draw budget made SYMBOLIC `(CONF_ACTION_WIDTH+94)·h` (was literal
      907 — went silently stale).
    - **Gates:** construction 3/3 GREEN (+ per-lane tamper/canonical/lane-swap
      KATs); byte-match GREEN (test_prover_action T2-T8; test_prover_agg 5/5
      variants zeta+roots+final_poly+43 publics; production h=1024 salted wire
      accept); **`make test` 65/65 GREEN, 0 warnings; nodus ctest 132/132.**
    - **Red-team (S-F3.5): single independent agent, GREEN — 6/6 SOUND,
      0 CRIT/HIGH/MED**; 1 LOW (agg construction-gate raw-u64 φ branch,
      pre-F3 shape, zero consumers, documented in-code) + INFO hygiene all
      fixed same-commit. Carried forward: S7 wallet keygen MUST sample all 4
      nk lanes with full entropy (G2 depends on it); C1 action prover unsalted
      (M3b at S7).
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
      [1919,1923)=INV_LVL, [1923,1927)=ACTIVE_LVL.
    - **🎯 S4b.2b DONE (2026-07-17) — nf-public position-forced slot routing.**
      Extends the oracle to WIDTH 1936 / 21 publics (anchor[4], num_input,
      nf_slot[MAX_INPUTS=4][4]). A running `N_input` counter (col 1927) increments
      at each INPUT block's phi=0 row (`+= PHI0*IS_INPUT`); at an INPUT's phi=D+1
      row N_input == its 1-based ordinal, so its nullifier routes to public slot
      `N_input-1` via `slot_sel[s]=is_zero(N_input-1-s)` (cols 1928-1935). Last-row
      `N_input == num_input` public (EXACT total-count). **Position-forcing closes
      G-S4-3/4: no DROP (each input's nf forced into its slot), no ADD (slots
      [0,num_input) bijective to inputs; a spurious nf has no slot).** Routing bind
      degree gate_nf(2)*slot_sel(1)*1 = 4, so **num_qc still MEASURED == 8.** Real
      prove->verify=Ok, tampered-reject, byte-identical regen; vector hash re-pinned
      (be497233). Full `make test` GREEN.
    - **🎯 S4b.3 DONE (2026-07-17) — C fp2 verifier-fold byte-match.**
      `conf_action_agg_fold.{c,h}` (DNAC_CONF_ACTION_AGG_FOLD_AIR, width 1936,
      21 publics, main_next=1) emits the aggregate constraint polynomial in fp2
      at zeta in the EXACT oracle emission order. **C1 region reused by calling
      `dnac_conf_action_fold_air_eval(f)`** (the C analog of the oracle's
      `ConfActionAir.eval(builder)`), then the aggregate constraints. ZK trace
      layout (CONF_AGGZK_*, distinct from the 1915 construction gate) lives in the
      fold header. `test_conf_action_agg_verify` (T6): **folded*inv_van ==
      quotient(zeta) on the REAL Plonky3 proof — PASS on first run**, pinning both
      constraint CONTENT and EMISSION ORDER. T7 negatives: tampered
      C1/membership-CUR/nullifier-NF/N_input cell + tampered anchor public -> OOD;
      wrong publics count / missing trace_next -> SHAPE. Full `make test` GREEN
      0-warn.
    - **🎯 S4b.4 DONE (2026-07-17) — pure-C AGGREGATE prover FULL byte-match.**
      `stark_prover_agg.{c,h}` (`dnac_agg_prover_prove`): the S1→S12 pipeline over
      the parametric stage library with the 1936-wide ZK trace generator
      (`agg_zk_generate` — C1 scatter + membership walk + nullifier sponge + is_zero
      selector columns, byte-matching the Rust generate) and the aggregate fold as
      the S6 quotient source (WITH the 21 publics). Draw layout: trace (1936+8)h ‖
      codeword 32h ‖ blinding 42h ‖ R 12h = 2030h. `test_prover_agg`: **zeta + all
      3 commitment roots + final_poly + the 21 public values (anchor||num_input||
      nf_slots) byte-match the REAL Plonky3 is_zk=1 proof** + self-verify (FRI
      DNAC_FRI_OK + N-chunk constraint check) — Rust-free end-to-end. FRI_LEAF_CAP
      15488→16384 (the 1940-wide merged ZK leaf = 15520 B > old cap; S4b.1 had
      mis-sized it for the 1919 construction-gate width). smallrng vector regen to
      262144 draws (prefix-stable; existing provers unaffected), hash re-pinned.
      Full `make test` GREEN 0-warn. **S4b COMPLETE: oracle → fold → prover, the
      aggregate real-STARK is Rust-free byte-matched end-to-end.**
    - **🎯 S4b.5 + S4f DONE (2026-07-17) — negative KATs + 10-agent red-team.**
      S4b.5: `test_prover_agg` T8 — 4 cheat instances fail-close (non-conserving,
      range overflow, non-canonical addr, NULL siblings). S4f: **10 parallel
      independent subagents** (KAFADAN-mandated), 8 CLEAN, **1 HIGH gap FOUND +
      FIXED in-AIR**: `N_input` had no `≤ MAX_INPUTS` proven bound → a ≥5-input tx's
      5th+ nullifier escaped routing (unpublished-nullifier double-spend). **Fix:**
      `gate_nf·(Σ slot_sel[s] − 1) == 0` (exactly one slot per INPUT nf-row ⇒
      N_input ∈ [1,MAX_INPUTS]) in oracle + fold; degree 3, num_qc still 8; vector
      regen + fold/prover re-byte-match GREEN. CLEAN surfaces: forced selectors,
      membership chaining, cross-region binding (dm-c2 closed), fold↔oracle parity
      (24 groups), C1-reuse, generator parity, POSACC double-spend (F6 holds),
      num_qc/degree/anchor (publics FS-absorbed pre-alpha). Accepted-scope: GAP2 nf
      unused-slot zeroing = S5 consumer contract (read [0,num_input)); GAP3 tx_binding
      = S5; GAP4 leaf/internal domsep = deferred (design-flagged). Report (local):
      `dnac/docs/plans/2026-07-17-dm-s4b-aggregate-realstark-redteam-report.md`.
    - **🎯 S4b.6 DONE (2026-07-17) — multi-input byte-match KATs (red-team #7).**
      Closes the "multi-input C↔Rust parity inferred, not demonstrated" residual
      with REAL proofs. `test_prover_agg` now byte-matches at 1, **2 AND 4** inputs.
      **2-input** (`dump-conf-action-agg-air-zk-2in`, h=128): two INPUTs are level-0
      siblings of each other (pos 0,1) → one anchor; N_input=2, slots 0+1.
      **4-input** (`dump-...-4in`, h=256): four INPUTs in ONE depth-4 tree (pos 0..3,
      internal nodes via `agg_compress`/`note_merkle_compress`) → one anchor;
      **N_input=MAX_INPUTS=4, all 4 slots — the GAP-1 boundary.** C test recomputes
      each input's cm (`conf_action_derive_addr`+`note_commit`) to build the shared
      sibling tree; byte-matches zeta+3 roots+final_poly+21 publics. smallrng
      extended 262144→524288 (prefix-stable). make test GREEN 0-warn.
      **S4b MERGE-READY (0 deployed-exploitable holes).**
    - **🎯 S4c DONE (2026-07-17) — OUTPUT/fee promotion (closes S5.2 red-team A-6
      CRITICAL: GAP3 output side is an AIR step, not pure wire).** The S5 V4-wire
      design red-team (1 independent agent, zero-consumer scope) found that binding
      the proof to a tx requires the OUTPUT side to have the SAME routing rigor
      GAP-1 gave INPUTs — else an unbacked `output_commit`/`fee` public mints.
      **Extended oracle+fold+prover** (`ConfActionAggAir`/`conf_action_agg_fold.c`/
      `stark_prover_agg.c`): width 1936→**1946**, publics 21→**43**
      (+`num_output` +`output_commit[MAX_OUTPUTS=4][4]` +`fee` +`tx_binding[4]`
      FS-observed). New constraints (all the OUTPUT analog of the N_input machinery):
      `N_output` counter + `oslot_sel[s]=is_zero(N_output−1−s)` routing of the frozen
      OUTPUT-block `cm_carry` to `output_commit[N_output−1]` at `gate_out=PHI0·IS_OUTPUT`,
      + `gate_out·(Σ oslot_sel−1)==0` (exactly-one-slot); and a **`FEE_ACC` accumulator**
      `fee_pub==Σ(IS_FEE·value)` — binds fee EVEN with no FEE block (the single-gate
      version left `fee_pub` unbound → fee-pool mint; caught + fixed pre-build).
      `num_qc` MEASURED still **8** (degree stayed 4). Draw layout auto-tracks width
      ((W+94)h=2040h). 1/2/4-input proofs byte-match the REAL Plonky3 is_zk=1 proof;
      `make test` GREEN 0-warn. **Next: S5** V4 wire (DNAC_TX_V4/tx_binding
      preimage/nf-set consumer, per the revised `2026-07-17-dm-s5-v4-wire-design.md`
      §0 D1–D7) → S6 consensus (BREAKING, needs approval).
    - **🎯 S5 wire DONE + S6 ROADMAP + Phase-P (production-harden) STARTED (2026-07-17).**
      S5 V4 wire shipped (DNAC_TX_SHIELDED ser/deser + sighash_v4 + V4 tx_hash +
      fee-equality + transparent-exclusion, round-trip KAT 10/10 ASAN-clean, libdna
      GREEN; re-audit 0 CRIT, 2 findings fixed). Roadmap `2026-07-17-dm-s6-roadmap.md`
      splits S6 into **Phase P (non-breaking production-harden, parked)** + **Phase C
      (BREAKING consensus)**. Phase P progress:
      - **P1 DONE** — query-PoW grind (`dnac_transcript_grind`, Plonky3
        grinding_challenger.rs port + clone) wired into all 4 provers; unit-tested to
        production 16-bit; backward-compat (grind(0) no-op → vectors byte-identical).
      - **P2 grounded-RESOLVED** — H2 (zeta sampled, `stark_priming.c:84`) + H3
        (publics observed pre-alpha, `:63-65`) ALREADY satisfied; tx_binding
        verifier-loop needs the wire → Phase C.
      - **P3 RESOLVED** — "audited AIR ≠ proven AIR" is NOT a hole (proven 1946 AIR
        red-teamed); authoritative relationship documented (`conf_action_agg_air.h`).
      - **P4 DONE** — salted aggregate prover (M3b MerkleTreeHidingMmcs, SALT_ELEMS=2):
        threaded salt into S2-S8 commits + S12 per-query gather (mirror conf, 160h
        width-independent); oracle `--salted` → `conf_action_agg_air_zk_salted.json`;
        `test_prover_agg --salted` BYTE-MATCHES the real Plonky3 salted proof + self-
        verifies. **1-agent red-team: 0 CRIT/0 HIGH** (offsets exact conf mirror,
        unsalted byte-identical, C==real-Plonky3-salted, ASAN+UBSAN clean).
      - **🎯 Phase-P tails CLOSED (2026-07-21):**
        - **(a) DONE — production prover entry** `dnac_agg_prover_prove_production`:
          pinned params (100 queries + lfpl=0 + 16-bit query-PoW = 216-bit
          conjectured), OS-entropy draws AND salts (genuinely salted, independent
          streams), height pinned to `DNAC_SHIELDED_BASE_LOG_HEIGHT` (h=1024,
          fail-close). The prove pipeline became cfg-parametric (test A_* set
          byte-identical — all KATs re-byte-match). **Wire codec v2** (required
          discovery: v1 had NO salt fields, so a salted proof could not cross the
          wire at all): batch openings + commit-phase steps carry optional M3b
          salt blocks (design doc §8 addendum); `fri_proof_wire.json` +
          `stark_proof_wire{,_no_next}.json` regenerated (deterministic 2×).
          **Gate `test_prover_shielded_production` (the roadmap P1 milestone):
          a REAL 100-query 16-bit-PoW SALTED h=1024 proof serializes (wire v2)
          and is ACCEPTED by `dnac_fri_verify_wire_shielded`** (~15 s, value-
          independent = no-flaky); negatives: wrong height → entry ERR_PARAM,
          TEST-params proof → SHIELDED_PARAM_MISMATCH (the pin bites). CT-asserts
          tie A_LOG_BLOWUP/arity/is_zk to the DNAC_SHIELDED_* constants.
          Honest scope: transcript primed from the prover's own statement; the
          wire-recompute of publics is Phase C (S6/C2).
        - **(b) DONE — salted vector metadata:** `define_dump_is_zk_stark` now
          takes per-config mmcs/pcs/hiding-note strings; plain instantiation
          byte-identical (verified `cmp`), salted vectors regenerated with
          honest MerkleTreeHidingMmcs descriptions.
        - **(c) DONE — h=256 salted oracle vector:**
          `dump-conf-action-agg-air-zk-4in --salted` →
          `conf_action_agg_air_zk_4in_salted.json` (3 FRI rounds,
          N_input=MAX_INPUTS=4); `test_prover_agg 4in --salted` BYTE-MATCHES the
          real Plonky3 salted h=256 proof (zeta+3 roots+final_poly+43 publics).
        - Independent red-team (zero-consumer scope per
          feedback_red_team_scope_limit): see the Phase-P-tails red-team note in
          memory/commit.
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
- **`make test`: 65 test binaries GREEN, 0 warnings** (`cd shared/crypto/zk && make test`;
  incl. the 3 S0 dual-mode gates test_note_commit / test_shielded_domsep /
  test_shielded_fri_params and the Phase-P production gate
  test_prover_shielded_production (pinned 100q/16-bit-PoW salted h=1024 proof
  accepted on the dnac_fri_verify_wire_shielded path, ~15 s);
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
