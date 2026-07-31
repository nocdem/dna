/**
 * @file fri_statement.h
 * @brief Composition s1b — the FRI-verify statement ENTRY: ONE verify call that
 *        binds the s1a fold AIRs into a single batched STARK instance set and
 *        ENFORCES the pin class the per-module slices deferred.
 *
 * s1a shipped five fold-form evaluators, each with its OWN reference cfg, and
 * those cfgs were mutually INCONSISTENT (fri lgmh 13 vs oi lgmh 4). This module
 * fixes ONE consistent statement: a single query index, a single inner FRI
 * verification shape, and one pinned cfg per participating AIR. The entry only
 * ever CONSTRUCTS and REJECTS — it introduces no constraint and no column.
 *
 * ── 1 + (B+R+2)*Q instances (MULTI-QUERY + COMMIT-ROUND + INPUT-BATCH) ───────
 *   idx 0                    tair    the DuplexChallenger control AIR (F-S tail)
 *   idx 1 + S*q + b          mmix[b] mixed-height input-batch MMCS verify,
 *                                    INPUT BATCH b, q  (b < DNAC_P2S_OI_NUM_BATCHES)
 *   idx 1 + S*q + B + r      mmcs[r] same-height binary MMCS verify, ROUND r, q
 *                                    (r < DNAC_P2S_FRI_R)
 *   idx 1 + S*q + B + R      fri     the fold-walk control AIR,            q
 *   idx 1 + S*q + B + R + 1  oi      the reduced-opening accumulation AIR, q
 * with S == DNAC_P2S_SLOTS == B + R + 2, i.e. `DNAC_P2S_INST(q, slot)` where the
 * slot is one of DNAC_P2S_SLOT_MMIX(b) / _MMCS(r) / _FRI / _OI.
 *
 * ⚠ THE INSTANCE ORDER IS PART OF THE INTERFACE. The pinned preprocessed root
 * below is a commitment over the tables IN THIS ORDER, so the entry rejects any
 * other `prep_matrix_to_instance`. WHY this order:
 *   - the transcript is the ONE SHARED producer and every query's consumers
 *     read from it. At index 0 its position is INDEPENDENT of Q, of R and of B,
 *     so raising any of them APPENDS instances instead of renumbering the
 *     producer (in the s3b order, tair sat at 4 and would have had to move).
 *   - a query's consumers are CONTIGUOUS, so "the instances of query q" is one
 *     arithmetic expression and every per-query walk — in the entry, in the
 *     prep-table generator and in the gate — is a single nested loop rather
 *     than a lookup table.
 *   - the R commit rounds sit WHERE THE SINGLE mmcs SLOT WAS, in ROUND ORDER;
 *     round order is the native's own walk order (fri_verifier.c:532 iterates
 *     `round` ascending), so instance index and fold depth run the same way.
 *   - the B input batches sit WHERE THE SINGLE mmix SLOT WAS, in BATCH ORDER,
 *     so the surrounding slot order (mmix.., mmcs.., fri, oi) is the s1b..s3b
 *     one and the per-slot cfg / table / publics code is unchanged apart from
 *     its index.
 *
 * ⚠ THE BATCH ORDER IS THE NATIVE'S, READ OFF THE CODE — NOT CHOSEN HERE.
 * `fri_open_input` walks `for (batch = 0; batch < num_commitments; ++batch)`
 * and reads `qp->input_proof[batch]` / `commitments[batch]` at that index
 * (fri_verifier.c:207-209), so "batch b" means "position b in the commitments
 * array". `dnac_batch_verify` builds that array in ROUND-EMISSION order and,
 * with is_zk = 0 and no lookups (this composition's envelope), emits exactly
 * three rounds:
 *     b = 0  MAIN          batch_verify.c:545-564  (`main_commit`)
 *     b = 1  QUOTIENT      batch_verify.c:565-581  (`quotient_commit`)
 *     b = 2  PREPROCESSED  batch_verify.c:582-602  (`preprocessed_commit`)
 * (the is_zk RANDOM round at :531-544 and the lookup PERMUTATION round at
 * :603-620 are both skipped, which is what makes B == 3 rather than 5.)
 * DNAC_P2S_SLOT_MMIX(b) uses that same b, so the slot index, the statement's
 * `mmix_root[b]` and the native's batch loop are one numbering.
 *
 * ⚠ HONEST NOTE — WHICH copies are byte-identical, and which are NOT.
 * The pinned cfgs are per-SLOT, not per-query (a table encodes the AIR's
 * SCHEDULE, and every query runs the same schedule; `num_queries` is a
 * fail-close sanity rail that never enters a table — fri_air_table.h:215-217,
 * fri_oi_air_table.h:225-226). So across q the Q copies of one slot ARE
 * byte-identical, and the composed root commits them separately — redundancy,
 * not a defect: what differs per query is the MAIN trace and the PUBLICS.
 * Across ROUNDS they are NOT: round r's MMCS opens at depth
 * DNAC_P2S_MMCS_DEPTH(r), which shrinks by log_arity per round (4 / 3 / 2 at
 * this pin), so each round has its OWN cfg, its OWN table, its OWN row count
 * (8 / 8 / 8 at this pin — see below) and its OWN public count. That is why the mmcs accessors below
 * take a round and why `DNAC_P2S_MMCS_NUM_PUBLICS` is function-like.
 * Across BATCHES the answer is MIXED, and stated exactly because it is easy to
 * get wrong: the three batches differ in their opened-row WIDTH (1 / 2 / 1 at
 * this pin — MEASURED, see the cfg derivation below), so they have three
 * different cfgs and three different PUBLIC counts, and `DNAC_P2S_MMIX_*` is
 * function-like for the same reason the mmcs ones are. Their TABLES, however,
 * coincide: the mixed schedule's row types are a function of the per-height
 * CONCATENATED width only through `leaf_rows = ceil(concat / rate)`
 * (mmcs_mixed_air_table.c:271-272, :298), and 1 and 2 both round up to ONE leaf
 * row at rate 4 — so all 3B tables are byte-identical here. That is a property
 * of THIS pin, not of the mechanism (a batch with a 5-wide opened row would
 * separate them), and it is exactly the OBL-4-MMIX situation: the root binds
 * table CONTENT, so the WIDTH must be — and is — pinned independently, by the
 * cfg the entry hands the bind and by the `num_publics` comparison in
 * `p2s_fill_geometry`. N-PIN still discriminates all 3B tables because it
 * tampers one CELL of one table at a time and the composed root commits the
 * matrices SEPARATELY, in order.
 *
 * ── WHAT THE MULTI-QUERY SLICE CLOSES: OBL-P2c-2 (fri_air.h:163-169) ─────────
 * Until now the statement consumed exactly ONE of the Q query indices the
 * pinned script samples; the rest were the honest `tair_bits_rest` input with no
 * consumer. Q copies of one query is worth `lb + pow` bits of soundness, not
 * `lb*Q + pow`. Now every query has its own four instances, and the split
 * between what is SHARED and what is PER-QUERY is the native's own:
 *
 *   SHARED (sampled/observed ONCE, OUTSIDE the per-query loop at
 *   fri_verifier.c:736) — ONE statement field, aliased into all Q consumers:
 *     oi[q].alpha     := tair_payload[first two non-PoW pops]        (:694)
 *     fri[q].betas[r] := tair_payload[the round-r pop pair]          (:707)
 *     fri[q].final    := final_poly0  (observed once at :710-713; a single fp2
 *                        because log_final_poly_len == 0 is pinned)
 *     oi[q].p_z       := pz_shared    (the CLAIMED EVALUATIONS: :470 reads them
 *                        through `commitments`, which :743 passes unchanged on
 *                        every iteration of the query loop)
 *     mmix[q][b].root    := mmix_root[b], the ONE commitment OF INPUT BATCH b
 *                        (`commitments[batch]`, fri_verifier.c:209) — SHARED
 *                        across q, DISTINCT across b
 *     mmcs[q][r].root    := mmcs_root[r], the ONE commitment OF ROUND r
 *                        (`proof->commit_phase_commits` is an ARRAY indexed by
 *                        round, fri_verifier.c:585 reads `[round]`, and the
 *                        whole array is observed before the query loop at
 *                        :700-708) — SHARED across q, DISTINCT across r
 *
 *   PER-QUERY (produced INSIDE that loop) — one field PER QUERY, never aliased
 *   across q, because aliasing them is exactly the collapse OBL-P2c-2 forbids:
 *     index_bits[q]   the q-th index, and it is the tair instance's OWN q-th
 *                     exported bit block (:737 samples a FRESH index per query)
 *     ro_export[q]    the q-th `fri_open_input` result (:742), which is where
 *                     fri[q].f_init and its roll-ins come from
 *     mmix_opened[q]  EVERY input batch's row opened AT the q-th index, laid
 *                     out batch by batch (:471 reads p_x out of
 *                     `qp->input_proof`, which IS the q-th query proof, and
 *                     :383/:392 verify that same row's opening). The batch axis
 *                     lives INSIDE the row rather than as a second array index
 *                     because the batches have different widths — see the field
 *                     comment.
 *     mmcs_opened[q][r]     round r's leaf for query q — the arity fp2 evals
 *                     the walk reconstructs at :547-555 and hands the MMCS at
 *                     :585-588. PER QUERY *and* PER ROUND: the leaf is a
 *                     function of the query's folded index, which is shifted
 *                     once per round (:558)
 *     z_pq[q]         the q-th query's opening points — HONEST LABEL 8: the
 *                     native's z does NOT move with q either, this one does
 *                     only because the shipped honest-trace builder ties z to x
 *
 * ⚠ "Q DISTINCT indices" is about POSITION, not VALUE. The native samples
 * freshly per query (:737) and two samples may legitimately land on the same
 * index; what must not happen is Q consumers all reading the transcript's q = 0
 * export block. That is what the per-query alias establishes by construction.
 * (The pinned script is a fixed pin, so its Q indices are constants of this
 * composition — the gate reports them and requires them to differ, which is an
 * assertion about THIS pin, not a probabilistic claim.)
 *
 * ── WHAT s3b CLOSED: the challenge <-> Fiat-Shamir transcript seam ───────────
 * s1c closed ro_export; s2 closed the main batch's p_x; s3b closed the last one
 * the earlier slices declared open by name: alpha, the betas and the query
 * INDEX were plain statement inputs, unbound to any transcript. They are BY
 * CONSTRUCTION the transcript instance's own publics — the statement carries ONE
 * `tair_payload` region (the observed/popped lane of every script op) and the
 * entry aliases it into its consumers. The `betas` and `alpha` statement fields
 * are GONE; the struct shrank.
 *
 * ── WHAT s1c CLOSES: the ro-export <-> f_init / roll-in seam ─────────────────
 * s1b had no oi instance, so the fri walk's seed and roll-in publics were plain
 * statement inputs — nothing recomputed them. They are now BY CONSTRUCTION the
 * open_input instance's exported reduced openings: the statement carries ONE
 * `ro_export` region and the entry aliases it into BOTH consumers,
 *   fri.f_init      := ro_export[height == lgmh]  (native ro[0] -> folded_eval,
 *                                                  fri_verifier.c:524-527)
 *   fri.rollins[i]  := ro_export[height == the i-th roll-in height]
 *                                                 (fri_verifier.c:600-605)
 *   oi.ro publics   := the SAME ro_export lanes    (fri_oi_air.h:69,79-82)
 * so the two instances cannot be given different values for the same reduced
 * opening — there is no second field to disagree with. The `f_init` and
 * `rollins` statement fields of s1b are GONE; the struct shrank.
 *
 * The oi cfg's participation was blocked in s1b by a COMPLETENESS defect in the
 * oi module (its table required the lowest scheduled height to be log_blowup,
 * while the native runs that zero-test CONDITIONALLY, fri_verifier.c:482-487,
 * and a real proof has no matrix at height 2^log_blowup). FLEET 029 repaired
 * that — a height AT log_blowup is now OPTIONAL (fri_oi_air_table.h:366-372) —
 * which is what makes an oi cfg derivable from the REF proof at all.
 *
 * ⚠ HONEST LABELS — the seams that are still open:
 *   1. THE SCRIPT NOW COVERS THE WHOLE SPONGE RUN; THE ζ ALIAS DOES NOT EXIST
 *      YET. (Was: "the transcript instance covers the FRI TAIL ONLY".)
 *
 *      WHAT CLOSED — the SCOPE half. `dnac_p2s_tair_script()` is expanded by
 *      `dnac_tair_full_build_script` and runs BLOCK 0 (the DS prefix) → BLOCK 1
 *      (the batch-STARK priming, `dnac_batch_priming_run`) → BLOCK 2 (the PCS
 *      claimed-eval observe round, batch_verify.c:637-647) → BLOCK 3 (the FRI
 *      tail, with NO second prefix, because `dnac_transcript_init_from_duplex`
 *      copies the primed state verbatim — batch_verify.c:632 -> transcript.c:48).
 *      31 ops became 93. Everything the pop/observe ordinal maps address is
 *      therefore addressed inside a model of the REAL run, not of a tail that
 *      begins from a fresh sponge — which is what made the old alpha/beta/query
 *      aliases claims about a DIFFERENT transcript than the one the proof uses.
 *
 *      WHAT DID NOT CLOSE, by name:
 *        (a) ζ. The priming's last pop IS ζ (batch_priming.c:280) and it now has
 *            a payload slot, but NOTHING reads it: the oi instances' opening
 *            points still come from `z_pq[q]`, a plain statement field. Binding
 *            them means writing every acc row's z as ζ or g_{log_degree}·ζ (the
 *            two-adic factor batch_verify.c:27-31 / :366 applies), and the map
 *            from an acc row to its (batch, point, height) IS derivable from the
 *            pinned cfg — `DNAC_P2S_OI_BNP(b)` / `_BNC(b)` give the split and
 *            batch_verify.c:550-555 / :588-592 fix point 0 = ζ, point 1 = g·ζ.
 *            What blocks it is the WITNESS, not the map: the shipped oi honest
 *            trace builder derives z as `emb(x) + zoff_of(a)`
 *            (tests/test_fri_oi_air.c:262-263) with a fixed invertible `zoff`,
 *            so a ζ-derived z has no honest trace until that builder changes.
 *            See HONEST LABEL 8, whose "z stays per-query" reason is the same
 *            builder.
 *        (b) The three input-batch commitments. They ARE observed inside BLOCK 1
 *            now — main at batch_priming.c:72, preprocessed at :98, quotient at
 *            :276 — so unlike before there ARE observe ops to alias
 *            `mmix_root[b]` to. The alias is not made here: the priming's
 *            commitment ORDER (main, preprocessed, [permutation], quotient) is
 *            NOT the FRI batch order (main, quotient, preprocessed —
 *            batch_verify.c:545 / :565 / :582), so the mapping is a decision
 *            with its own soundness argument and its own gates. Label 6a is
 *            unchanged in substance and no longer blocked by scope.
 *        (c) Nothing here is bound to a WIRE proof, for the reason label 6(c)
 *            gives: the inner proof IS the statement.
 *        (d) ⚠ THE ACCEPTANCE SET WIDENED — READ THIS BEFORE READING "31 ops
 *            became 93" AS A STRENGTHENING. Before this slice the script began
 *            at the DS prefix, whose four lanes the AIR pins to constants
 *            (transcript_air.c:277-279), so the sponge state at the FRI alpha
 *            pop was FULLY DETERMINED and CT-3b forced that alpha to ONE value;
 *            each beta was determined by the DS prefix plus the round digests.
 *            Alpha now sits at op 66, downstream of 62 observes of which 58 are
 *            free statement lanes (`pub_tair[k] = stmt->tair_payload[k]`,
 *            canonicality-checked only). A party choosing the statement now
 *            chooses alpha, every beta and every query index.
 *            Why this is still the right trade: the old determinacy was a
 *            property of a sponge THE NATIVE NEVER RUNS — a tail starting from
 *            a fresh DS state — so it constrained the wrong object. Nothing
 *            cryptographically held was lost, because labels 3 and 6a already
 *            say the roots and openings are unbound statement fields and the
 *            statement carries no FRI binding on this axis either way. But the
 *            set of accepted statements is strictly larger than before, and
 *            that must not be discovered by a later reader from the code.
 *        (e) ⚠ 46 NEWLY MODELLED OBSERVE LANES ARE FREE, and label 6's
 *            "what did not close, by name" list did not cover them (it names
 *            the commitment digests, the final poly and the log arities).
 *            By block: `observe_usize(num_instances)` 2 lanes (ops 4-5), the
 *            4-field per-instance bindings 16 lanes (ops 6-21), the
 *            preprocessed widths 4 lanes (ops 26-29), and the ENTIRE PCS
 *            claimed-eval block 24 lanes (ops 42-65). Every one of them is
 *            DETERMINED by the pinned cfg (N=2, log_degree 3/2, width 1,
 *            num_qc 1, prep width 1) and could be pinned to a constant; leaving
 *            them free is a CHOICE, recorded here rather than left implicit.
 *            N-PRIMEDEAD is the tripwire for the PCS 24.
 *        (f) ⚠ THE MODELLED TRANSCRIPT IS A STRICT SUPERSET OF THE NATIVE ONE —
 *            11 lanes the native fixes at ZERO are unconstrained here.
 *            `dnac_batch_observe_usize` observes `(v, 0)`: the value then a zero
 *            second coefficient (batch_priming.c:26-27, upstream
 *            batch-stark/src/transcript.rs:206-209). A script records only op
 *            KINDS, so the two ops are indistinguishable and both lanes are
 *            copied from `tair_payload`. Affected: 1 count + 8 binding + 2
 *            prep-width high coefficients.
 *            ⚠ THIS IS NOT A STRUCTURAL LIMIT. The AIR CAN pin an observed lane
 *            to a constant — it does exactly that for the DS prefix
 *            (transcript_air.c:277-279). So closing (f) is available at any
 *            time; the reason to defer is that pinning the zero HALF while the
 *            value half beside it stays free barely narrows anything, and the
 *            meaningful unit is the whole binding block of (e). OBLIGATION:
 *            whichever slice re-shapes the script (see (g)) decides (e)+(f)
 *            together, or states why not.
 *        (g) ⚠ THE REF NOW SITS AT THE ROW CEILING. 1 start + 93 ops + 1
 *            terminal = 95 scheduled rows, padded to TAIR_TBL_MAX_ROWS = 128;
 *            `tair_script_check` fails closed past 126 ops (there are 33 spare,
 *            not zero — an earlier note in this tree said zero and was wrong).
 *            But the composed statement this module lives inside runs
 *            DNAC_P2S_NUM_INSTANCES = 17 instances, and modelling a 17-instance
 *            INNER proof needs 2 + 8*17 = 138 binding observes ALONE — past the
 *            ceiling before the main commit, the widths, the PCS block or the
 *            tail. So MAX_ROWS (and with it TAIR_TBL_COLS, both pins and the
 *            LDE) MUST move again for a production-shaped inner proof. Named
 *            here so P2e does not rediscover it.
 *   2. CLOSED (this slice). Both halves of the old label are now discharged:
 *      "only ONE query is CONSUMED (OBL-P2c-2)" went with the multi-query
 *      slice, and "commit rounds 1..R-1 are NOT replicated" goes here — every
 *      query now carries R mmcs instances, one per commit round, each at its
 *      OWN depth and driven by its OWN window of the query's index bits. What
 *      the round replication does NOT bring is the LEAF <-> FOLD-ROW alias:
 *      that is the seam fri_air.h:193-195 declares by name ("the sibling column
 *      `s` is UNCONSTRAINED witness data until the composition binds it to P2b
 *      opened-row publics"), and it is now the only reason an mmcs[r] instance
 *      and the fri instance can be handed different values for one row. Moved
 *      OUT of this label into label 9, so a closed label does not carry an open
 *      obligation.
 *   3. STRUCTURALLY CLOSED (this slice — INPUT-BATCH REPLICATION), and NOT YET
 *      CRYPTOGRAPHICALLY. Every acc row's `p_x` is now an MMCS-bound lane — the
 *      wiring is complete and there is no free `p_x` input left. But the root it
 *      is bound TO, `mmix_root[b]`, is still a plain statement field carrying
 *      only a canonicality check (`p2s_canon_span`, fri_statement.c:583-584);
 *      nothing ties it to the transcript. A party that chooses the statement
 *      chooses the root too: write any `p_x` lanes, compute that leaf's Merkle
 *      root, set `mmix_root[b]` to it, and both the mmix AIR and oi are
 *      satisfied. So this closure carries no soundness UNTIL label 6a closes.
 *      The heading says so because the body alone was not enough — the previous
 *      version read "CLOSED" and a reader who stopped at the heading would have
 *      taken a binding this does not yet have.
 *
 *      WHAT s2 LEFT OPEN, and why it is gone. s2 made `p_x` a C3g-bound public
 *      instead of free oi witness (fri_oi_air.h) and sourced the MAIN batch's
 *      acc rows from `stmt.mmix_opened` — the SAME lanes the mmix instance's
 *      opened-row publics are built from — but the QUOTIENT and PREPROCESSED
 *      batches' rows came from `stmt.px_rest`, a plain statement input: inside
 *      the mechanism, not bound to any commitment. The closure named here was
 *      "one mmix instance per input batch", and that is exactly what landed:
 *      every query now carries B mmix instances, batch b's opened row is
 *      instance `DNAC_P2S_SLOT_MMIX(b)`'s own opened public, and the oi
 *      instance's p_x for a row of batch b is an ALIAS of that same lane. The
 *      `px_rest` field is CONSUMED AND GONE, exactly as `tair_bits_rest` went
 *      with the multi-query slice; the struct shrank.
 *
 *      THE NATIVE GROUNDING — why the other two batches deserve an MMCS
 *      instance at all. `fri_open_input` treats every batch identically: the
 *      SAME loop body runs `dnac_p2_mmcs_verify` / `_verify_mixed` on batch b's
 *      opening against `cw->commitment` for EVERY b (fri_verifier.c:381-396,
 *      inside the `for (batch = ...)` at :207), and the p_x it then accumulates
 *      is `bo->opened_values[m][j]` off that SAME just-verified batch opening
 *      (:471). There is no privileged main batch in the native — the asymmetry
 *      was purely an artifact of the composition having modelled one batch. So
 *      the quotient and preprocessed openings are commitment-bound in the
 *      native, and the composition now says so too.
 *      ⚠ Which commitment: batch b's `cw->commitment` is `main_commit` /
 *      `quotient_commit` / `preprocessed_commit` for b = 0 / 1 / 2
 *      (batch_verify.c:557-559, :574-576, :595-597) — three DISTINCT roots,
 *      which is why `mmix_root` gained a batch axis.
 *      Gates: N-BSEP (batch b's opened lanes reach ONLY that batch's mmix
 *      instance and oi — never another batch's) and N-PXBOUND (the closure
 *      proper: EVERY acc row's p_x public IS its batch's mmix opened lane, all
 *      B batches, asserted on the entry's own output vectors).
 *
 *      WHAT DOES NOT CLOSE WITH IT, by name: the three roots themselves are
 *      still plain statement fields — the input batches are observed during the
 *      batch-STARK PRIMING, which label 1 puts outside the pinned script, so
 *      there is no observe op to alias them to (label 6a). "The p_x the walk
 *      accumulates is the row the MMCS opened" is closed; "that MMCS root is
 *      the one the challenger absorbed" is not, for any of the B batches.
 *   4. ARITY-EQUALITY ASSUMPTION (FLEET 028 verifier M2), still TEST-side.
 *      Round r's dir alias reads the index-bit window starting at
 *      `(r+1)*max_log_arity` over `DNAC_P2S_MMCS_DEPTH(r)` levels, while the
 *      native's round r consumes the window the ACTUAL per-round `log_arity`s
 *      put it at (`fri_verifier.c:558` shifts by `step->log_arity` each round,
 *      :557 derives that round's depth from the same number). The two coincide
 *      because the pinned shape has every log_arity == mla == 1 — which is what
 *      also makes R == lgmh - lb - lfpl the ROUND count rather than a level
 *      count. ⚠ ROUND REPLICATION DID NOT UNPIN THE ARITIES, so this obligation
 *      does NOT become an entry duty here: it is still asserted TEST-side
 *      (T-REF now measures EVERY round's log_arity and opening depth, not just
 *      round 0's). Unpinning them is its own slice and its own decision.
 *   5. OI GROUP SHAPE — the (matrices, points, columns) factorization of a
 *      height group is a LABEL, not a measurement (see the cfg derivation
 *      below). Only the group's acc-row TOTAL and its boundary are load-bearing
 *      here, and both are measured.
 *   6. THE TRANSCRIPT'S OBSERVED LANES — THE COMMIT DIGESTS ARE BOUND; THE
 *      REST IS NOT. (Was "NOT BOUND TO THIS PROOF" before this slice.)
 *
 *      WHAT CLOSED — all R commit-round digests. The script's per-round OBSERVE
 *      block IS that round's commit digest: the native runs
 *      `dnac_transcript_observe_digest(transcript,
 *      &proof->commit_phase_commits[round])` (fri_verifier.c:702) and the
 *      builder expands it into DNAC_P2M_DIGEST_LANES observe ops
 *      (transcript_air_table.c:586-588). Until round replication there was no
 *      per-round digest ANYWHERE in the statement to alias it to — the entry
 *      sourced those lanes from `stmt.tair_payload` while the single round-0
 *      root sat in an unrelated field. `mmcs_root[r]` now exists, and step 6a
 *      writes the transcript instance's round-r digest lanes FROM it, one
 *      source field with two consumers — the `ro_export` pattern. The SAME
 *      array element `fri_verifier.c:585` checks round r's Merkle walk against
 *      is the one the challenger absorbed, BY CONSTRUCTION: there is no second
 *      field for them to disagree in.
 *      Gates: N-OBSBIND (perturbing `mmcs_root[r]` must move the transcript
 *      instance AND every query's round-r MMCS instance, and nothing else) and,
 *      witness-side, RT-1 — the honest transcript is REPLAYED over the real
 *      roots, so the query indices it squeezes are downstream of them.
 *      ⚠ The ordinal map is not trusted blind: step 3a requires each digest
 *      block to be one contiguous observe run sitting strictly between the
 *      surrounding rounds' beta pops, which is where the native puts it
 *      (:702 inside the loop that samples beta at :707).
 *
 *      WHAT DID NOT CLOSE, by name:
 *        (a) `mmix_root[b]` — the B INPUT-batch commitments are NOT ALIASED.
 *            ⚠ THE REASON CHANGED AT THE PRIMING SLICE. It used to be SCOPE:
 *            the script began at the DS prefix and went straight into the tail,
 *            so there was no observe op to alias them to at all. There is now —
 *            BLOCK 1 observes all three (batch_priming.c:72 main, :98
 *            preprocessed, :276 quotient) — and what is left is a MAPPING
 *            decision: the priming observes them in main / preprocessed /
 *            quotient order while `fri_open_input` walks batches in main /
 *            quotient / preprocessed order (batch_verify.c:545 / :565 / :582),
 *            so `mmix_root[b]`'s observe ordinal is NOT `b`. Making that alias
 *            is its own slice with its own gates; until then they stay plain
 *            statement fields. ⚠ INPUT-BATCH REPLICATION
 *            MULTIPLIED THIS RESIDUE BY B: there are now three unbound roots
 *            where there was one. The honest accounting has a SECOND HALF that
 *            an earlier version of this note left out: the same slice took the
 *            quotient and preprocessed `p_x` lanes from bound-to-NOTHING
 *            (`px_rest`, deleted) to bound-to-a-root. So the ledger is
 *            roots 1 -> 3 unbound, and unbound `p_x` lanes
 *            (TOTAL_ACC - MAIN_ACC) -> 0. Neither "worse" nor "better": the
 *            residue concentrated from many free values into three roots, which
 *            is what makes closing label 6a close label 3 with it.
 *        (b) the FINAL-POLY lanes (fri_verifier.c:711-713) and the per-round
 *            LOG-ARITY lanes (:717-720). Both ARE in the script, and both are
 *            still deterministic `tair_payload` inputs: the final poly has a
 *            statement field (`final_poly0`) it could be aliased to, and the
 *            log arities have none because the arities are pinned constants
 *            (label 4). Aliasing the final poly is a two-line change this slice
 *            deliberately did NOT make — it is not part of the round axis and
 *            would land untested here.
 *        (c) NOTHING IN THIS ENTRY IS BOUND TO A *WIRE* PROOF, and cannot be:
 *            the inner proof IS the statement. The alias establishes agreement
 *            BETWEEN the composed instances, not agreement with an object no
 *            parameter of this entry carries. Read (a)+(b)+(c) together: what
 *            the closure buys is that a statement cannot name one root for the
 *            challenger and another for the Merkle walk — not that either is
 *            the root of some proof this entry was handed.
 *      Consequence: `tair_payload`'s digest lanes are now DEAD INPUT — read by
 *      nothing, overwritten by the alias. They keep their slots because the
 *      payload is indexed BY OP (`pub_tair[k] = tair_payload[k]`) and punching
 *      holes in it would make every index conditional. Gate: N-OBSDEAD.
 *
 *   7. RT-1's transcript vector is SELF-CONSISTENT, not an independent oracle:
 *      the test builds it by replaying the shipped `duplex_challenger.c` and
 *      checks it against its own replay of that same challenger. The Rust-oracle
 *      pinning for the transcript lives in `tests/test_transcript_air.c`'s 8
 *      dump-transcript-trace scenarios, not here.
 *   8. THE OPENING POINT `z` IS STILL PER-QUERY. WHAT ITS CLAIMED EVALUATION
 *      `p_z` USED TO BE IS FIXED.
 *
 *      In the native BOTH halves of an acc row's opening claim are query-
 *      invariant: `fri_open_input` receives `commitments` as an argument and the
 *      query loop passes the SAME pointer on every iteration (fri_verifier.c
 *      :743), so `cw = &commitments[batch]` (:209), `mo = &cw->matrices[m]`
 *      (:401) and `pt = &mo->points[point]` (:437) reach the same objects for
 *      every q — and from `pt` come BOTH `pt->point` (the opening point z, used
 *      at :464) and `pt->claimed_evals[j]` (p_z, :470). Only the OTHER two
 *      quantities move: `x` is derived from `index` (:425-430) and `p_at_x`
 *      comes from `qp->input_proof` (:471), i.e. from the q-th query proof.
 *
 *      ⚠ WHAT THE FIRST VERSION OF THIS LABEL MISSED. It kept ONE region,
 *      `zpz[q]`, carrying z at 4a and p_z at 4a+2, and justified the whole
 *      region with the builder argument in (b) below. That argument is about
 *      `z` ALONE. `p_z` was per-query as collateral damage, with NO reason
 *      given — an unjustified freedom that let two queries name two different
 *      claimed evaluations for the same opening. The region is now SPLIT:
 *        `pz_shared[2*TOTAL_ACC]` — ONE region, aliased into every oi instance,
 *                                   which is what the native says it is;
 *        `z_pq[q][2*TOTAL_ACC]`   — still per-query, for the reason below.
 *      Gate: N-PZSHARED (perturbing a `pz_shared` lane must move EVERY query's
 *      oi instance) and N-QINDEP/z (perturbing `z_pq[q]` must move ONLY q's).
 *
 *      WHY `z` STAYS PER-QUERY — the (b) argument, which is valid for z only:
 *      the shipped oi honest-trace builder derives z AS x + zoff
 *      (tests/test_fri_oi_air.c:262-263, chosen so that z - x is a fixed
 *      invertible fixture), and x IS query-dependent, so with two different
 *      indices it emits two different z. A shared z region would have no honest
 *      witness, and forcing one means a builder hook — a change to a file this
 *      slice does not own. `p_z` has no such obstacle: the same builder emits
 *      `pz = cur_is_lb ? emb(px) : tfp2(a_global + 3, 19)` (:265-266) and the
 *      pinned cfg takes the second branch on every row (heights {5, 4} vs
 *      log_blowup 2), so p_z is a pure function of the schedule ordinal and a
 *      shared region HAS a witness — which RT-1 now demonstrates by construction.
 *
 *      WHAT REMAINS OPEN, by name: a per-query z still admits a statement whose
 *      two queries name two DIFFERENT opening points. It costs nothing that is
 *      currently held — `z` is an unbound plain statement input either way.
 *      ⚠ THE OTHER HALF OF THAT SENTENCE IS NOW STALE AND IS CORRECTED HERE:
 *      ζ is NO LONGER unmodelled. The priming block is in the pinned script and
 *      its last pop IS `dnac_batch_sample_zeta` (batch_priming.c:280), so ζ has
 *      a transcript payload slot and the alias `z ∈ {ζ, g_{log_degree}·ζ}` is
 *      AVAILABLE — see label 1(a) for the derivation and for the one thing that
 *      still blocks it, which is the shipped oi honest-trace builder's
 *      `z = emb(x) + zoff_of(a)` (tests/test_fri_oi_air.c:262-263), not the map.
 *      Closing it is a builder change plus this alias; it is still NOT
 *      achievable by re-shaping this field alone.
 *
 *   9. THE COMMIT-ROUND LEAF IS NOT THE FOLDED ROW (fri_air.h:193-195; split
 *      out of the old label 2 by the round-replication slice). Natively ONE
 *      array `evals[]` is both hashed into round r's MMCS leaf
 *      (fri_verifier.c:568 over the row assembled at :550-555) and folded into
 *      the next running value (:594). In the composition they are two
 *      independent public regions — `mmcs_opened[q][r]` on the MMCS side, the
 *      fri instance's own `f` / `s` trace columns on the walk side — with no
 *      alias between them, so a statement may present a leaf that opens
 *      correctly under `mmcs_root[r]` while the walk folded something else.
 *      This was equally true of round 0 before this slice: replicating the
 *      rounds neither creates nor closes it, it makes it R times over. Closing
 *      it needs the fri AIR's sibling column to become a PUBLIC aliased to the
 *      round's opened lanes — the seam fri_air.h:193-195 declares by name, and
 *      the reason its soundness claims are labelled conditional.
 *
 * ── The pinned cfg set (DERIVED from a real inner proof, then FROZEN) ────────
 * Source: scenario `prep_pair` of `tools/vectors/batch_proof.json` — the
 * smallest shipped batch fixture that has BOTH >= 1 commit round AND a
 * mixed-height input batch. It is loaded by `tests/test_batch_verify.c:327` and
 * gated there by `dnac_batch_verify`. Its measured shape (query 0):
 *
 *   fri_params        log_blowup 2, log_final_poly_len 0, max_log_arity 1,
 *                     num_queries 2, both PoW bit counts 0
 *   commit rounds     3, each log_arity 1, sibling counts 1,
 *                     opening depths 4 / 3 / 2
 *   instances         log_ext_degree 3 and 2, main width 1 each
 *   input batches     3, EACH 2 matrices at LDE heights 2^5 and 2^4 (-> MIXED)
 *                     with opening depth 5. They differ ONLY in the opened-row
 *                     WIDTH, which is that batch's claimed-eval count:
 *                       b=0 MAIN          widths {1,1}   (the instances' main
 *                                                        width, batch_verify.c
 *                                                        :550 -> trace_local)
 *                       b=1 QUOTIENT      widths {2,2}   (one chunk per
 *                                                        instance at this pin,
 *                                                        emitted with
 *                                                        num_claimed_evals = 2
 *                                                        — the fp2 chunk's two
 *                                                        base lanes,
 *                                                        batch_verify.c:570-571)
 *                       b=2 PREPROCESSED  widths {1,1}   (the instances'
 *                                                        preprocessed width,
 *                                                        batch_verify.c:588)
 *                     MEASURED, not inferred: T-REF walks all three batches of
 *                     the fixture's query-0 input proof and compares matrix
 *                     count / per-matrix width / opening depth / mixedness
 *                     against the per-batch pins, for every batch.
 *   ⚠ The opened-row width and the oi group's COLUMN count are the SAME
 *   quantity by the native's own rule — `fri_verifier.c:333` rejects a batch
 *   whose `opened_values_lens[m]` differs from `points[0].num_claimed_evals`,
 *   and :469-471 indexes `opened_values[m][j]` by the claimed-eval ordinal j.
 *   They are nonetheless pinned as TWO constants here (the MMCS leaf's width
 *   and the accumulation loop's column count) and the entry CHECKS they agree,
 *   because that equality is a property of the native, not of this header.
 *
 * From those, exactly as `fri_verifier.c:640-650` derives them:
 *   lgmh = sum(log_arity) + log_blowup + log_final_poly_len = 3 + 2 + 0 = 5
 *   R    = lgmh - log_blowup - log_final_poly_len            = 3
 *   reduced-opening heights = {log_ext_degree_i + log_blowup} = {5, 4};
 *     height 5 SEEDS the walk (fri_verifier.c:524-527) and height 4 = lgmh-1
 *     ROLLS IN at fold round 0 (fri_verifier.c:600-605) -> rollin set {4}
 *   commit round r leaf = arity fp2 evals BASE-flattened = 2*arity = 4 lanes
 *     (fri_verifier.c:568 over the row assembled at :550-555), the SAME width
 *     for every round because every round's arity is the same;
 *   commit round r DEPTH = log_folded_height at that round = lgmh - (r+1)*
 *     log_arity, because :557 sets log_folded_height = log_current_height -
 *     log_arity, :596 carries it into the next round, and :585-588 hands the
 *     MMCS `1 << log_folded_height` together with the index :558 has already
 *     shifted down by the SAME log_arity. At this pin that is 4 / 3 / 2, which
 *     is exactly the fixture's three opening depths above — and the last one
 *     equals log_final_height (lb + lfpl = 2), which is the walk's closing
 *     condition at :609-611.
 *   input batch b depth = log2(max height of batch b) = 5 for every b
 *     (mmcs_mixed_air_table.h:361-368). All three coincide here because all
 *     three carry the tallest instance's matrix; the entry treats the depth as
 *     a per-pin constant and T-REF measures it per batch.
 *
 * ── The oi (open_input) cfg — DERIVED THE SAME WAY, from the same proof ──────
 * `fri_open_input` accumulates one reduced opening PER DISTINCT log-height over
 * every input batch (fri_verifier.c:207-478), so the oi cfg is a property of the
 * WHOLE input side of that proof, not of batch 0:
 *   lgmh / log_blowup   the same 5 / 2
 *   H (descending)      the distinct heights {5, 4} — NO height at log_blowup,
 *                       which is what FLEET 029 made expressible
 *   acc rows per height MEASURED: for each height h, the number of
 *                       (batch, matrix at h, opening point, claimed eval)
 *                       tuples the native visits — the four nested loops at
 *                       fri_verifier.c:207 / :400 / :436 / :469. prep_pair has
 *                       three input batches (main, quotient, preprocessed —
 *                       batch_verify.c:545-602 with is_zk 0 and no lookups) and
 *                       each contributes exactly 2 tuples at each height:
 *                         main         1 matrix x 2 points (zeta, zeta_next)
 *                                                  x 1 claimed eval  = 2
 *                         quotient     1 chunk   x 1 point (zeta)
 *                                                  x 2 lanes         = 2
 *                         preprocessed 1 matrix x 2 points x 1 eval   = 2
 *                       => 6 acc rows per height, 12 in total.
 *
 * ⚠ HONEST LABEL 5 — THE GROUP DESCRIPTOR IS A FACTORIZATION, NOT A SHAPE, AND
 * THE INPUT-BATCH SLICE IS WHERE THAT STOPS BEING FREE.
 * `dnac_p2c_oi_height_desc_t` describes a group as a UNIFORM product
 * (num_batches x num_matrices x num_points x num_columns). The real batches are
 * NOT uniform in the (points, columns) split — the quotient batch is 1x2 where
 * the other two are 2x1 — so the pinned (3, 1, 2, 1) reproduces the correct
 * PER-BATCH count (2), the correct group TOTAL (6) and the correct group
 * boundary, and mislabels only the internal split. That split carries no
 * semantics FOR THE AIR: `num_matrices*num_points*num_columns` is read ONLY as
 * `batch_sz` for the C5 per-batch lb-zero rule (fri_oi_air.c:170-182), which is
 * gated on `cur_is_lb` and therefore never fires for a cfg with no height at
 * log_blowup. What DOES carry semantics — the total and the per-acc-row public
 * slot ORDER — is pinned by the schedule and proved by the test's native replay.
 *
 * ⚠ BUT THE p_x ALIAS READS INSIDE A BATCH'S BLOCK, so it needs the REAL split.
 * s2 could ignore this: it only aliased batch 0, whose split IS the pinned
 * (2 points x 1 column). Aliasing all B means resolving, for acc row `a` of
 * batch b's block, WHICH COLUMN of batch b's opened row it accumulates — and
 * the native says the column is the innermost loop index, `j` in
 * `opened_values[m][j]` (fri_verifier.c:469-471), i.e. `a % nc_b` under the
 * batch-major (matrix -> point -> column) emission order. With the descriptor's
 * uniform nc = 1 that would read column 0 for BOTH of the quotient batch's two
 * acc rows, silently dropping its second claimed evaluation and duplicating the
 * first. So the per-batch (points, columns) split is pinned SEPARATELY here
 * (DNAC_P2S_OI_BNP / _BNC below). The descriptor itself is UNCHANGED: this is
 * extra information alongside it, not a re-shaping of it (the oi table module
 * owns the descriptor, and this slice does not modify that module).
 *
 * WHAT IS STILL A LABEL, WHAT IS MEASURED, AND WHERE IT FAILS CLOSED:
 *
 *  - STILL A LABEL: the descriptor's (num_matrices, num_points, num_columns)
 *    split. Both the AIR and the table module read those three ONLY through
 *    their product (fri_oi_air.c:170, fri_oi_air_table.c:54-64), so no consumer
 *    can observe the mislabel.
 *
 *  - MEASURED, not assumed: T-REF/px re-derives — per batch AND per height —
 *    the point count and the opened-row width from the fixture JSON and
 *    compares them against BNP(b) / BNC(b) (test_fri_statement.c:2356-2363),
 *    then requires at least one batch's real split to DIFFER from the uniform
 *    descriptor's (:2383), so the per-batch arithmetic cannot be vacuously
 *    exercised by an s2-shaped fixture.
 *
 *  - FAILS CLOSED on TWO equalities, each pinned at build time AND at run time:
 *      (i)  BNP(b) * BNC(b) == the block size. Build: three array-size asserts
 *           against ACC_PER_BATCH (fri_statement.c:101-109). Run: step 3a
 *           against the same constant (:1067), and again in the p_x build loop
 *           against the DESCRIPTOR's own `batch_sz` (:1475) — the second is the
 *           one that stops a re-shaped descriptor from re-partitioning that
 *           loop, since it reads the cfg rather than the constant.
 *      (ii) BNC(b) == DNAC_P2S_MMIX_BW(b), the width of batch b's mmix opened
 *           row. This is the native's own equality (fri_verifier.c:333 pins the
 *           opened row length to the claimed-eval count that :469-471 then
 *           indexes by). Build: fri_statement.c:117-122. Run: `mw != nc` at
 *           :1079 and :1485, against the cfg the bind will actually receive
 *           (OBL-4-MMIX). Without (ii) the alias would index a lane batch b's
 *           opened row does not have; without (i) it would index the wrong one.
 *
 *  - NOT CLOSED: the uniform descriptor can only describe a group whose B
 *    blocks are all the SAME size — :1465 forces the group total to be
 *    B * batch_sz and :1475 forces every batch onto that one `batch_sz`. A
 *    shape with genuinely different per-batch acc-row counts is therefore
 *    REJECTED rather than mis-verified, which is the safe direction but is
 *    still a shape this composition cannot express. If the production re-pin
 *    (P2e) needs one, the fix belongs in the oi TABLE module, not here.
 *
 * `tests/test_fri_statement.c` re-derives every one of those numbers from the
 * fixture JSON and compares them against the constants below, so the pin cannot
 * drift from the proof it claims to describe.
 *
 * ⚠ The cfg scalars are pinned INDEPENDENTLY of the preprocessed root — that is
 * OBL-4c / OBL-4-MMIX (fri_air_table.h:140-148): a root binds table CONTENT,
 * never the verifier's separate cfg ARGUMENT, so a root-checked table paired
 * with a mismatched cfg would aim cfg-derived loop bounds at the wrong publics.
 * Both are checked, from two independent sources.
 *
 * ⚠ MECHANISM PIN, NOT PRODUCTION. Neither the cfg set nor `dnac_p2s_fri_params`
 * is a security parameter choice: `prep_pair` is a 2-query toy fixture. This
 * slice proves the pin class can be established and that it binds. The
 * production re-pin (real recursion shape, real query count) is P2e.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_STATEMENT_H
#define DNAC_ZK_FRI_STATEMENT_H

#include <stddef.h>
#include <stdint.h>

#include "batch_verify.h"        /* dnac_batch_v{instance,opened,commits}_t   */
#include "fri_air_fold.h"       /* dnac_fair_fold_bind + the fri publics      */
#include "fri_air_table.h"      /* dnac_p2c_table_cfg_t                       */
#include "fri_oi_air_fold.h"    /* dnac_foi_fold_bind + the oi publics        */
#include "fri_oi_air_table.h"   /* dnac_p2c_oi_table_cfg_t                    */
#include "mmcs_air_fold.h"      /* dnac_mmcs_air_fold_bind                    */
#include "mmcs_air_table.h"     /* dnac_p2b_table_cfg_t                       */
#include "mmcs_mixed_air_fold.h" /* dnac_mmix_air_fold_bind                   */
#include "mmcs_mixed_air_table.h" /* dnac_p2c_mmix_table_cfg_t                */
#include "transcript_air_fold.h"  /* dnac_transcript_air_fold_bind            */
#include "transcript_air_table.h" /* dnac_tair_script_t + the script builder  */

#ifdef __cplusplus
extern "C" {
#endif

/* ── The inner FRI shape (see the header derivation) ─────────────────────── */
#define DNAC_P2S_LGMH           ((size_t)5)
#define DNAC_P2S_LOG_BLOWUP     ((size_t)2)
#define DNAC_P2S_LFPL           ((size_t)0)
#define DNAC_P2S_MAX_LOG_ARITY   ((size_t)1)
#define DNAC_P2S_NUM_QUERIES     ((size_t)2)

/** Fold rounds R = lgmh - log_blowup - log_final_poly_len (fri_verifier.c
 *  :640-650 with :609-611 closing the walk at log_final_height). DERIVED.
 *  ⚠ This is the COMMIT-ROUND count only while every round's log_arity equals
 *  `max_log_arity` — the arity-equality assumption of HONEST LABEL 4. Defined
 *  here, ahead of the slot map, because the slot map now depends on it. */
#define DNAC_P2S_FRI_R (DNAC_P2S_LGMH - DNAC_P2S_LOG_BLOWUP - DNAC_P2S_LFPL)

/** INPUT BATCHES — B. The count of `qp->input_proof` entries the native walks
 *  (fri_verifier.c:203-207 requires it to equal `num_commitments`), which for
 *  this composition's envelope (is_zk 0, no lookups) is the three rounds
 *  `dnac_batch_verify` emits: main / quotient / preprocessed
 *  (batch_verify.c:545 / :565 / :582).
 *
 *  ⚠ DEFINED HERE, ahead of the slot map, for the same reason R is: since the
 *  input-batch replication slice the slot map depends on it. It is ALSO the oi
 *  group descriptor's `num_batches` — one constant, because they are the same
 *  number by construction (the oi schedule's batch axis IS the native's batch
 *  loop index; see the s2 block further down). */
#define DNAC_P2S_OI_NUM_BATCHES  ((size_t)3) /* main / quotient / preprocessed */

/** Batch ordinals, so no call site writes 0 / 1 / 2. NOT a free choice — see
 *  the file header's "THE BATCH ORDER IS THE NATIVE'S". */
#define DNAC_P2S_BATCH_MAIN ((size_t)0)
#define DNAC_P2S_BATCH_QUOT ((size_t)1)
#define DNAC_P2S_BATCH_PREP ((size_t)2)

/* ── Instance indices (the ORDER the pinned prep root commits to) ─────────────
 * See the file header's instance map for why the transcript sits at 0 and each
 * query's consumers are contiguous. Nothing below is a written-out number: the
 * slot count is derived from B and R, and the instance COUNT from the slot
 * count and Q. */

/** Input batch 0's slot; batch b sits at DNAC_P2S_SLOT_MMIX(b). The B batches
 *  are CONTIGUOUS and in ASCENDING batch order — the order `fri_open_input`
 *  walks them (fri_verifier.c:207) and the order `dnac_batch_verify` emits the
 *  commitments in (batch_verify.c:545-602). */
#define DNAC_P2S_SLOT_MMIX0 ((uint32_t)0)
#define DNAC_P2S_SLOT_MMIX(b)                                                 \
    ((uint32_t)(DNAC_P2S_SLOT_MMIX0 + (uint32_t)(b)))
/** Commit round 0's slot; round r sits at DNAC_P2S_SLOT_MMCS(r). The R rounds
 *  are CONTIGUOUS and in ASCENDING round order — the order `fri_verify_query`
 *  walks them (fri_verifier.c:532) and the order their depths descend in. */
#define DNAC_P2S_SLOT_MMCS0                                                   \
    ((uint32_t)(DNAC_P2S_SLOT_MMIX0 + (uint32_t)DNAC_P2S_OI_NUM_BATCHES))
#define DNAC_P2S_SLOT_MMCS(r)                                                 \
    ((uint32_t)(DNAC_P2S_SLOT_MMCS0 + (uint32_t)(r)))
#define DNAC_P2S_SLOT_FRI                                                     \
    ((uint32_t)(DNAC_P2S_SLOT_MMCS0 + (uint32_t)DNAC_P2S_FRI_R))
#define DNAC_P2S_SLOT_OI    ((uint32_t)(DNAC_P2S_SLOT_FRI + 1u))
/** Consumers per query = B input batches + R commit rounds + fri + oi. Also the
 *  value `dnac_p2s_inst_slot` returns for the transcript instance and for an
 *  out-of-range index (i.e. "no slot"). */
#define DNAC_P2S_SLOTS      ((uint32_t)(DNAC_P2S_SLOT_OI + 1u))

/** 1 iff `s` is one of the B input-batch slots, and the batch it names. The
 *  "no slot" sentinel DNAC_P2S_SLOTS is excluded because SLOTS > SLOT_MMCS0
 *  whenever R >= 1 and there are two trailing slots — the static assert
 *  `p2s_slot_sentinel_is_not_a_batch_assert` in fri_statement.c says so rather
 *  than leaving it to this comment. */
#define DNAC_P2S_SLOT_IS_MMIX(s) ((uint32_t)(s) < DNAC_P2S_SLOT_MMCS0)
#define DNAC_P2S_SLOT_BATCH(s) ((size_t)((uint32_t)(s) - DNAC_P2S_SLOT_MMIX0))

/** 1 iff `s` is one of the R commit-round slots, and the round it names. Both
 *  used by the slot-keyed accessors; a caller that has an INSTANCE should use
 *  `dnac_p2s_inst_round` instead of decoding twice. */
#define DNAC_P2S_SLOT_IS_MMCS(s)                                             \
    ((uint32_t)(s) >= DNAC_P2S_SLOT_MMCS0 && (uint32_t)(s) < DNAC_P2S_SLOT_FRI)
#define DNAC_P2S_SLOT_ROUND(s) ((size_t)((uint32_t)(s) - DNAC_P2S_SLOT_MMCS0))

/** The ONE shared producer. Q-independent by construction (see the map). */
#define DNAC_P2S_INST_TAIR ((uint32_t)0)

/** Instance index of query `q`'s consumer in slot `slot`. */
#define DNAC_P2S_INST(q, slot)                                                \
    ((uint32_t)(1u + DNAC_P2S_SLOTS * (uint32_t)(q) + (uint32_t)(slot)))

/** DERIVED — 1 producer + (B + R + 2) consumers per query. Never a number. */
#define DNAC_P2S_NUM_INSTANCES                                                \
    ((uint32_t)(1u + DNAC_P2S_SLOTS * (uint32_t)DNAC_P2S_NUM_QUERIES))

/** MIRROR of the batch stack's instance cap, with its citation: `dnac_batch_
 *  verify` rejects `num_instances > BV_MAX_INSTANCES` (batch_verify.c:20 and
 *  :86) and `dnac_batch_prove` (batch_prover.c:555) rejects
 *  `> BP_MAX_INSTANCES` at batch_prover.c:572 (the constant is :22; the two
 *  helpers `dnac_batch_prove_num_draws` :210 and `_num_salt_draws` :247 carry
 *  the same bound but are NOT the prove entry — FLEET 035 verifier, citation
 *  corrected); both are 32 and NEITHER is exported by a header, so this is an
 *  honest duplicate rather than a shared constant. It exists only to DERIVE the
 *  Q ceiling below; the compile-time assert in fri_statement.c is what turns a
 *  Q past that ceiling into a build failure instead of a runtime reject. */
#define DNAC_P2S_BATCH_MAX_INSTANCES ((uint32_t)32)

/** The largest Q this composition shape can carry: (cap - 1 producer) divided
 *  by the per-query consumer count, which is now B + R + 2 rather than R + 3 —
 *  so the ceiling MOVES when either the round count OR the batch count does,
 *  and the assert in fri_statement.c is what turns an over-large pin into a
 *  build failure. At this pin (B 3, R 3) that is (32-1)/8 = 3, DOWN from 5.
 *
 *  ⚠ SINCE THE FRI_MAX_RO RAISE THIS IS THE BINDING CEILING AGAIN. Before it,
 *  DNAC_P2S_FRI_RO_MAX_INSTANCES was tighter and this pin exceeded it — that is
 *  what blocked the slice. At 128 the FRI-side ceiling is 128>>2 = 32, EQUAL to
 *  the batch cap, and this pin (17) is under both. T-QCAP asserts it. */
#define DNAC_P2S_MAX_QUERIES                                                  \
    ((size_t)((DNAC_P2S_BATCH_MAX_INSTANCES - 1u) / DNAC_P2S_SLOTS))

/* ── A SECOND INSTANCE CEILING — FOUND BY THIS SLICE, AND RAISED BY IT.
 *      Read this before raising Q, B or R again.
 *
 * The batch stack's own 32-instance cap (mirrored above) is not the only one.
 * The OUTER proof's QUOTIENT opening round is ONE FRI input batch carrying ONE
 * MATRIX PER QUOTIENT CHUNK OF EVERY INSTANCE, and `fri_open_input` caps the
 * matrices of a single input batch at FRI_MAX_RO. The chain, read end to end:
 *
 *   batch_prover.c:650    nqc[i] = 1 << (log_num_qc + is_zk)   = 4 here
 *                         (is_zk 0; log_num_qc 2, which is DERIVED from
 *                         DNAC_P2S_MAX_SYMBOLIC_DEGREE 4 by the upstream rule
 *                         and asserted per instance by T-ALIAS)
 *   batch_prover.c:1320   opened[i].num_quotient_chunks = nqc[i]
 *   batch_verify.c:373-374 total_qc = Σ_i opened[i].num_quotient_chunks
 *   batch_verify.c:579    the quotient round is ONE commitment whose
 *                         `num_matrices` IS total_qc
 *   fri_verifier.c:218    `if (cw->num_matrices > FRI_MAX_RO) return
 *                         DNAC_FRI_ERR_INPUT_ERROR;`
 *   fri_verifier.c        FRI_MAX_RO
 *
 * so the real bound is  N * (1 << log_num_qc) <= FRI_MAX_RO. At FRI_MAX_RO 64
 * that was N <= 16 at this degree, and THE PINNED SHAPE IS N = 17 — measured,
 * not inferred: at N = 9 (Q = 1) `dnac_batch_prove` returned OK; at N = 17 it
 * returned DNAC_PROVER_ERR_VERIFY, because its own self-verify
 * (batch_prover.c:1639-1646) runs `dnac_batch_verify` and the FRI input walk
 * rejected the 68-matrix quotient round.
 *
 * ⚠ RESOLVED IN THIS SLICE, by user decision: FRI_MAX_RO was raised 64 → 128,
 * chosen as 4 * 32 == (chunks per instance at the degree-4 class) * (the batch
 * stack's own instance cap) so the two ceilings ALIGN and the composition
 * cannot return to this gate by adding instances. The full rationale, the
 * relation assert and — importantly — the STACK TRIPWIRE (rowbuf went 1.25 MB
 * → 2.5 MB; safe only because fri_verifier.c is compiled into libnodus alone,
 * NOT into libdna) live at the constant itself in fri_verifier.c. Anyone
 * porting the verify stack to Android/S7 must read that tripwire first.
 *
 * ⚠ RETRACTED — an earlier version of this paragraph claimed `cw->num_matrices`
 * is PROOF-SUPPLIED, called FRI_MAX_RO "the only thing bounding an
 * attacker-forced allocation walk", and handed C3 an obligation to make the
 * bound caller-pinned. All of that was WRONG and none of it survives review.
 * The count is CALLER-pinned already: the proof's declared chunk count is
 * checked against the caller's binding BEFORE FRI runs (batch_priming.c:340,
 * reached from batch_verify.c:253), and that binding is `1 << (log_num_qc +
 * is_zk)` taken from the caller's own instance descriptor (batch_verify.c:180,
 * :207); `n` is a caller argument (:97). The proof-side count is
 * `bo->num_matrices`, bounded independently by DNAC_FRI_WIRE_MAX_MATRICES
 * (fri_proof_codec.h:71) and required to EQUAL the caller's value
 * (fri_verifier.c:332). And `rowbuf` is a fixed automatic, so the 2.5 MB is
 * paid whether the count is 1 or 128 — raising the cap doubled a CONSTANT cost,
 * not an attacker-scaled one. There is no C3 obligation here.
 *
 * Mirrored here (an honest duplicate, like DNAC_P2S_BATCH_MAX_INSTANCES —
 * fri_verifier.c exports neither the constant nor the bound) so the number is
 * derived in one place. The ceiling is FUNCTION-LIKE because `log_num_qc` is a
 * RUNTIME derivation (`dnac_p2s_log_num_qc`, the upstream log2_ceil rule) and
 * this header does not carry a preprocessor copy of it — writing one would be a
 * second, unchecked source for a number the entry already derives. T-QCAP
 * reports the headroom; the relation is asserted at the constant in
 * fri_verifier.c, which is where both halves of it are in scope. */
#define DNAC_P2S_FRI_MAX_RO ((size_t)128)
#define DNAC_P2S_FRI_RO_MAX_INSTANCES(log_num_qc)                             \
    (DNAC_P2S_FRI_MAX_RO >> (log_num_qc))

/** The grinding widths of the OUTER FRI params. SINGLE-SOURCED here because
 *  three consumers must agree on them: `dnac_p2s_fri_params()`, the transcript
 *  script the entry builds, and the `pow_bits` PIN that compares the two
 *  (see `dnac_p2s_check_tair_pow_pin` — OBL-P2a-T1's second half). */
#define DNAC_P2S_COMMIT_POW_BITS ((size_t)0)
#define DNAC_P2S_QUERY_POW_BITS  ((size_t)0)

/** The roll-in set: the ONE reduced opening below lgmh, at lgmh-1. */
#define DNAC_P2S_NUM_ROLLIN ((size_t)1)
#define DNAC_P2S_ROLLIN_0   (DNAC_P2S_LGMH - 1)

/* ── mmcs (the R commit rounds) ──────────────────────────────────────────────
 * One instance per round per query. The leaf WIDTH is round-independent, the
 * DEPTH and the index-bit WINDOW are not. */
/** Leaf lanes = the arity fp2 evals BASE-flattened, [c0,c1] x arity
 *  (fri_verifier.c:564-568 via extension_mmcs.rs:77-95). DERIVED from arity,
 *  and the same for every round because every round's arity is `mla`. */
#define DNAC_P2S_MMCS_TOTAL_WIDTH ((size_t)2 << DNAC_P2S_MAX_LOG_ARITY)

/** First index bit round `r`'s Merkle walk consumes. `fri_verify_query` shifts
 *  the index DOWN by `log_arity` once per round, BEFORE handing it to that
 *  round's MMCS (fri_verifier.c:558 then :585-588), so after r+1 rounds of
 *  shifting the walk starts at bit (r+1)*log_arity. */
#define DNAC_P2S_MMCS_BIT_OFF(r)                                              \
    (((size_t)(r) + 1) * DNAC_P2S_MAX_LOG_ARITY)
/** Round `r`'s Merkle depth = log_folded_height at that round = lgmh -
 *  (r+1)*log_arity (fri_verifier.c:557 with :596 carrying it forward; the
 *  height the MMCS is given at :585-588). DESCENDS by log_arity per round, so
 *  BIT_OFF(r) + DEPTH(r) == lgmh for every round — the invariant that makes
 *  "the window is the index's remaining high bits" true by construction. */
#define DNAC_P2S_MMCS_DEPTH(r)                                                \
    (DNAC_P2S_LGMH - DNAC_P2S_MMCS_BIT_OFF(r))

/* ── mmix (the B input batches) ──────────────────────────────────────────────
 * ONE instance per input batch per query. Every batch of this pin has the SAME
 * matrix count, the SAME per-matrix heights and the SAME opening depth — its
 * matrices are the SAME inner instances' (batch_verify.c gives every round one
 * matrix per instance at that instance's `log_ext_degree`). What DIFFERS is the
 * opened-row WIDTH, which is the batch's claimed-eval count. MEASURED per batch
 * by T-REF; nothing here is inferred from another batch. */
#define DNAC_P2S_MMIX_NUM_MATRICES ((size_t)2)
/** Per-matrix heights: 2^(log_ext_degree_i + log_blowup) for the two inner
 *  instances (log_ext_degree 3 and 2). SHARED across batches (see above). */
#define DNAC_P2S_MMIX_LH0 ((size_t)5)
#define DNAC_P2S_MMIX_LH1 ((size_t)4)
/** depth == log2(max height) == the tallest matrix's log-height. */
#define DNAC_P2S_MMIX_DEPTH DNAC_P2S_MMIX_LH0
/** Non-hiding recursion envelope (G-DET-3, user-locked at P2a): no leaf salt.
 *  Matches the fixture, whose input openings carry salt_elems 0
 *  (tests/batch_test_util.h:231-232).
 *
 *  ⚠ OBLIGATION — LABEL 3 DEPENDS ON THIS BEING ZERO. The native hashes
 *  `row_lane_lens[m] = cols + se` lanes: the opened row FOLLOWED BY `se` salt
 *  lanes (fri_verifier.c:410-428). At se == 0 the hashed preimage IS the opened
 *  row, so the mmix instance's opened publics cover all of it and label 3's
 *  `p_x` binding is total. At se > 0 the salt lanes enter the leaf but NOT the
 *  AIR publics, so the opened publics would cover only a PREFIX of the hashed
 *  row — label 3 REOPENS, and a pin with salts must either publish the salt
 *  lanes or state what the partial binding buys. Nothing enforces se == 0 at
 *  runtime here; it is a pinned scalar, and this note is the guard. */
#define DNAC_P2S_MMIX_SALT_ELEMS ((size_t)0)

/** PER-BATCH opened width — every matrix of batch b opens `DNAC_P2S_MMIX_BW(b)`
 *  lanes. A proof-shape scalar per batch; nothing derives it.
 *  ⚠ RENAMED from the old `DNAC_P2S_MMIX_W0/W1`, which meant the two MATRICES'
 *  widths of the single (main) batch. The axis moved, so the name did: `BW`
 *  is per BATCH, and the two matrices of a batch share it at this pin. */
#define DNAC_P2S_MMIX_BW0 ((size_t)1) /* main         — trace_local width      */
#define DNAC_P2S_MMIX_BW1 ((size_t)2) /* quotient     — an fp2 chunk's 2 lanes */
#define DNAC_P2S_MMIX_BW2 ((size_t)1) /* preprocessed — preprocessed_local     */
#define DNAC_P2S_MMIX_BW(b)                                                   \
    ((size_t)((b) == DNAC_P2S_BATCH_MAIN   ? DNAC_P2S_MMIX_BW0                \
              : (b) == DNAC_P2S_BATCH_QUOT ? DNAC_P2S_MMIX_BW1                \
                                           : DNAC_P2S_MMIX_BW2))

/** Batch b's flattened opened region: one row per matrix, concatenated in
 *  MATRIX order using the SEMANTIC widths (mmcs_mixed_air.h "Public values"). */
#define DNAC_P2S_MMIX_TOTAL_OPENED(b)                                         \
    (DNAC_P2S_MMIX_NUM_MATRICES * DNAC_P2S_MMIX_BW(b))
/** Σ over the B batches — the length of ONE query's `mmix_opened` row. Written
 *  as an explicit B-term sum because it must be a COMPILE-TIME expression (it
 *  bounds a C array); `p2s_mmix_batch_list_matches_b_assert` in fri_statement.c
 *  stops the build if B ever moves off 3. */
#define DNAC_P2S_MMIX_ALL_OPENED                                              \
    (DNAC_P2S_MMIX_TOTAL_OPENED(DNAC_P2S_BATCH_MAIN) +                        \
     DNAC_P2S_MMIX_TOTAL_OPENED(DNAC_P2S_BATCH_QUOT) +                        \
     DNAC_P2S_MMIX_TOTAL_OPENED(DNAC_P2S_BATCH_PREP))

/* ── oi (open_input: the WHOLE input side, all three inner batches) ──────────
 * The distinct reduced-opening heights, STRICTLY DESCENDING, heights[0] == lgmh
 * (fri_oi_air_table.h:362-364). NO height at log_blowup — that is the FLEET 029
 * shape and it is what makes C4b/C5 vacuous here (fri_oi_air_table.h:366-372). */
#define DNAC_P2S_OI_NUM_HEIGHTS ((size_t)2)
#define DNAC_P2S_OI_H0 DNAC_P2S_LGMH
#define DNAC_P2S_OI_H1 ((size_t)4)

/* The group descriptor. See the header's HONEST LABEL 5: only the PRODUCT (the
 * group's acc-row count) and the group boundary are load-bearing FOR THE AIR;
 * the (m,p,c) split is a label, unread for a group that is not the log_blowup
 * group. `num_batches` is DNAC_P2S_OI_NUM_BATCHES, defined with the slot map
 * above because the slot map depends on it. */
#define DNAC_P2S_OI_NUM_MATRICES ((size_t)1) /* per batch, at each height      */
#define DNAC_P2S_OI_NUM_POINTS   ((size_t)2)
#define DNAC_P2S_OI_NUM_COLUMNS  ((size_t)1)

/** Acc rows per height group = the four-loop tuple count (fri_verifier.c:207 /
 *  :400 / :436 / :469). Both pinned heights have the same shape here. */
#define DNAC_P2S_OI_ACC_PER_HEIGHT                                            \
    (DNAC_P2S_OI_NUM_BATCHES * DNAC_P2S_OI_NUM_MATRICES *                     \
     DNAC_P2S_OI_NUM_POINTS * DNAC_P2S_OI_NUM_COLUMNS)
/** Σ over the height groups — the length of the z / p_z public region. */
#define DNAC_P2S_OI_TOTAL_ACC                                                 \
    (DNAC_P2S_OI_ACC_PER_HEIGHT * DNAC_P2S_OI_NUM_HEIGHTS)

/* ── s2 + INPUT-BATCH REPLICATION: each batch's share of each height group ────
 * The oi schedule emits a group's acc rows BATCH-MAJOR (batch -> matrix ->
 * point -> column, fri_oi_air_table.h:104-114, the native's own nesting at
 * fri_verifier.c:207/400/436/469), and the batch index IS the native's batch
 * loop index, i.e. the position in `qp->input_proof`. So a height group is B
 * consecutive blocks of `DNAC_P2S_OI_ACC_PER_BATCH` rows, block b belonging to
 * input batch b — the batch mmix instance `DNAC_P2S_SLOT_MMIX(b)` describes —
 * and every one of those rows' `p_x` is that batch's mmix opened lane at that
 * height. s2 aliased block 0 only; every block is aliased now.
 * T-REF/px MEASURES the per-batch per-height shape rather than assuming it. */
#define DNAC_P2S_OI_ACC_PER_BATCH                                             \
    (DNAC_P2S_OI_NUM_MATRICES * DNAC_P2S_OI_NUM_POINTS *                      \
     DNAC_P2S_OI_NUM_COLUMNS)

/** PER-BATCH (points, columns) split of a batch's block — the REAL one, which
 *  the uniform group descriptor above does NOT carry (HONEST LABEL 5). The
 *  column count is what the p_x alias indexes batch b's opened row by, because
 *  the native's innermost loop index IS the claimed-eval / column ordinal
 *  (`opened_values[m][j]`, fri_verifier.c:469-471) under batch-major emission.
 *  BNP(b) * BNC(b) MUST equal DNAC_P2S_OI_ACC_PER_BATCH — checked at build time
 *  and again at step 3a, so the two descriptions of a block cannot disagree. */
#define DNAC_P2S_OI_BNP0 ((size_t)2) /* main:         zeta, zeta_next   */
#define DNAC_P2S_OI_BNC0 ((size_t)1) /*               x 1 claimed eval  */
#define DNAC_P2S_OI_BNP1 ((size_t)1) /* quotient:     zeta              */
#define DNAC_P2S_OI_BNC1 ((size_t)2) /*               x 2 fp2 lanes     */
#define DNAC_P2S_OI_BNP2 ((size_t)2) /* preprocessed: zeta, zeta_next   */
#define DNAC_P2S_OI_BNC2 ((size_t)1) /*               x 1 claimed eval  */
#define DNAC_P2S_OI_BNP(b)                                                    \
    ((size_t)((b) == DNAC_P2S_BATCH_MAIN   ? DNAC_P2S_OI_BNP0                 \
              : (b) == DNAC_P2S_BATCH_QUOT ? DNAC_P2S_OI_BNP1                 \
                                           : DNAC_P2S_OI_BNP2))
#define DNAC_P2S_OI_BNC(b)                                                    \
    ((size_t)((b) == DNAC_P2S_BATCH_MAIN   ? DNAC_P2S_OI_BNC0                 \
              : (b) == DNAC_P2S_BATCH_QUOT ? DNAC_P2S_OI_BNC1                 \
                                           : DNAC_P2S_OI_BNC2))

/* ── THE INNER BATCH PROOF'S SHAPE (the priming + PCS blocks read THESE) ─────
 * Until this slice the pinned transcript script covered the FRI TAIL ONLY, and
 * HONEST LABEL 1 said so: the batch-STARK priming and the PCS claimed-eval
 * observe round sit AHEAD of the tail in the SAME sponge (`dnac_batch_verify`
 * creates it at batch_verify.c:321 and hands the primed state to FRI verbatim at
 * :632 -> transcript.c:48), and neither was modelled. They are now, which means
 * the statement has to pin the shape of the proof being verified.
 *
 * ⚠ MEASURED, not chosen — scenario `prep_pair` of `tools/vectors/batch_proof.
 * json`, the SAME fixture the cfg set above is derived from. Its two instances
 * are IDENTICAL in shape, which is why one set of scalars serves both; the .c
 * writes the array out per instance and T-REF/inner re-reads every field out of
 * the JSON, so "uniform" is a measured property of this pin and not a modelling
 * shortcut. The build-time asserts below tie each scalar to the mmix/oi pin that
 * describes the SAME quantity from the other side — two independent statements,
 * reconciled, exactly as DNAC_P2S_MMIX_BW(b) is tied to DNAC_P2S_OI_BNC(b).
 *
 * ⚠ STILL A MECHANISM PIN. `prep_pair` is a toy fixture; the production re-pin
 * (P2e) replaces these together with everything else. */
/** The fixture's `num_instances`. Pinned INDEPENDENTLY of
 *  DNAC_P2S_MMIX_NUM_MATRICES and reconciled with it by a build-time assert:
 *  they are the same number only because the MAIN and PREPROCESSED rounds carry
 *  one matrix per INSTANCE (batch_verify.c:549 / :587), which is a property of
 *  those rounds, not a definition. */
#define DNAC_P2S_INNER_N        ((size_t)2)
#define DNAC_P2S_INNER_IS_ZK    0        /* the non-hiding recursion envelope   */
#define DNAC_P2S_INNER_NRC      ((size_t)0) /* num_random_codewords; 0 iff !zk  */
/** Base lanes observed per instance at batch_priming.c:77-79. The fixture's two
 *  `PrepEqAir` instances declare `public_values: []`. */
#define DNAC_P2S_INNER_PUBLICS  ((size_t)0)
/** `width` — the main trace width. DERIVED, not a second pin: it IS the MAIN
 *  batch's opened-row width, because `trace_local_len == width` is the shape the
 *  verifier enforces (batch_priming.c:330) and that row is what the main input
 *  batch opens. */
#define DNAC_P2S_INNER_MAIN_WIDTH DNAC_P2S_MMIX_BW0
/** `main_next_used` — the main round opens zeta AND g*zeta, which is what makes
 *  the MAIN batch a 2-point batch (DNAC_P2S_OI_BNP0). */
#define DNAC_P2S_INNER_MAIN_NEXT  1
/** `preprocessed_width` — likewise DERIVED: it IS the PREPROCESSED batch's
 *  opened-row width (batch_verify.c:588 opens `preprocessed_local`). */
#define DNAC_P2S_INNER_PREP_WIDTH DNAC_P2S_MMIX_BW2
/** `prep_next_used` — likewise a 2-point batch (DNAC_P2S_OI_BNP2). */
#define DNAC_P2S_INNER_PREP_NEXT  1
/** `num_quotient_chunks` PER INSTANCE. The QUOTIENT round is one matrix per
 *  CHUNK of every instance (batch_verify.c:567-573), so N * this is the
 *  quotient batch's matrix count — the equality the assert below pins. */
#define DNAC_P2S_INNER_NUM_QC   ((size_t)1)
/** `num_locals + num_globals`. Zero everywhere: this envelope has no lookups,
 *  which is also why B == 3 rather than 5 (the permutation round is skipped —
 *  see the file header's batch-order note). */
#define DNAC_P2S_INNER_LOOKUPS  ((size_t)0)

/* ── tair (the transcript instance — s3b, extended to the WHOLE run) ─────────
 * The cfg is DERIVED from the statement constants above, never written out:
 * `dnac_p2s_tair_full_cfg()` fills a `dnac_tair_full_cfg_t` from the inner-proof
 * scalars and from R / lfpl / Q / lgmh / the two PoW widths, and the script is
 * then EXPANDED from it by the shipped `dnac_tair_full_build_script` — the same
 * authority `dnac_tair_ref_script` uses, so "the REF script" and "the statement
 * script" cannot be two different things. The test asserts they are op-for-op
 * equal at this pin.
 *
 * The op COUNT is mirrored here as a compile-time expression only because the
 * statement struct needs a fixed array bound; it is the same sum
 * `dnac_tair_full_num_ops` computes, and the entry COMPARES the two and fails
 * closed on any disagreement (the count-KAFADAN discipline, exactly as
 * DNAC_P2S_FRI_NUM_PUBLICS is compared against `dnac_fair_num_publics`).
 *
 * `powops(bits)` is 2 for a non-zero width and 0 for zero — the ZERO-OP
 * `check_witness` branch (duplex_challenger.c:153-155). */
#define DNAC_P2S_TAIR_POW_OPS(bits) ((bits) != 0 ? (size_t)2 : (size_t)0)

/** BLOCK 1 — the batch-STARK priming (batch_priming.c:250-281). The uniform-
 *  instance form of `dnac_tair_priming_num_ops`; the entry compares the two.
 *    2                                 observe_usize(num_instances)     :47
 *  + 8*N                               4 usize per instance          :52-55
 *  + DIGEST_LANES                      the main commit                  :72
 *  + N*publics                         CONDITIONAL, 0 here           :77-79
 *  + 2*N                               the preprocessed widths       :94-96
 *  + DIGEST_LANES iff any prep matrix  the preprocessed commit       :97-99
 *  + 4 iff any lookup                  the (alpha, beta) squeeze    :143-144
 *  + DIGEST_LANES + 2*N iff any lookup the perm commit + terminals  :181-192
 *  + 2                                 the batch alpha                 :194
 *  + DIGEST_LANES                      the quotient commit             :276
 *  + DIGEST_LANES iff is_zk            the random commit           :277-279
 *  + 2                                 zeta                            :280
 *  ⚠ The lookup term uses 2*N rather than 2*(instances WITH lookups) because at
 *  this pin the two are equal (every instance has the same `num_lookups`); the
 *  module accessor counts them one by one, and the entry's comparison is what
 *  would catch a pin where they diverge. */
#define DNAC_P2S_TAIR_PRIMING_OPS                                             \
    ((size_t)2 + (size_t)8 * DNAC_P2S_INNER_N +                               \
     (size_t)DNAC_P2M_DIGEST_LANES +                                          \
     DNAC_P2S_INNER_N * DNAC_P2S_INNER_PUBLICS +                              \
     (size_t)2 * DNAC_P2S_INNER_N +                                           \
     (DNAC_P2S_INNER_PREP_WIDTH != 0 ? (size_t)DNAC_P2M_DIGEST_LANES          \
                                     : (size_t)0) +                           \
     (DNAC_P2S_INNER_LOOKUPS != 0                                             \
          ? (size_t)4 + (size_t)DNAC_P2M_DIGEST_LANES +                       \
                (size_t)2 * DNAC_P2S_INNER_N                                  \
          : (size_t)0) +                                                      \
     (size_t)2 + (size_t)DNAC_P2M_DIGEST_LANES +                              \
     (DNAC_P2S_INNER_IS_ZK ? (size_t)DNAC_P2M_DIGEST_LANES : (size_t)0) +     \
     (size_t)2)

/** BLOCK 2 — the PCS claimed-eval LANES (batch_verify.c:432-488, observed at
 *  :637-647). Per instance: the random round iff ZK, the main round's 1 or 2
 *  points, one point per quotient chunk, the preprocessed round's 1 or 2 points
 *  with a ZERO rand tail, and two permutation points iff the AIR has lookups. */
#define DNAC_P2S_TAIR_PCS_LANES                                               \
    (DNAC_P2S_INNER_N *                                                       \
     ((DNAC_P2S_INNER_IS_ZK ? (size_t)2 + DNAC_P2S_INNER_NRC : (size_t)0) +   \
      (DNAC_P2S_INNER_MAIN_NEXT ? (size_t)2 : (size_t)1) *                    \
          (DNAC_P2S_INNER_MAIN_WIDTH + DNAC_P2S_INNER_NRC) +                  \
      DNAC_P2S_INNER_NUM_QC * ((size_t)2 + DNAC_P2S_INNER_NRC) +              \
      (DNAC_P2S_INNER_PREP_WIDTH != 0                                         \
           ? (DNAC_P2S_INNER_PREP_NEXT ? (size_t)2 : (size_t)1) *             \
                 DNAC_P2S_INNER_PREP_WIDTH                                    \
           : (size_t)0) +                                                     \
      (DNAC_P2S_INNER_LOOKUPS != 0                                            \
           ? (size_t)2 * ((DNAC_P2S_INNER_LOOKUPS + (size_t)1) * (size_t)2 +  \
                          DNAC_P2S_INNER_NRC)                                 \
           : (size_t)0)))
/** Each claimed eval is an fp2 = TWO base observes (transcript.c:79-82). */
#define DNAC_P2S_TAIR_PCS_OPS ((size_t)2 * DNAC_P2S_TAIR_PCS_LANES)

/** BLOCK 3 — the FRI tail WITHOUT a DS prefix (fri_verifier.c:693-737; the
 *  prefix belongs to the run, BLOCK 0). */
#define DNAC_P2S_TAIR_TAIL_OPS                                                \
    ((size_t)2 +                                                              \
     DNAC_P2S_FRI_R * ((size_t)DNAC_P2M_DIGEST_LANES +                        \
                       DNAC_P2S_TAIR_POW_OPS(DNAC_P2S_COMMIT_POW_BITS) +      \
                       (size_t)2) +                                           \
     ((size_t)2 << DNAC_P2S_LFPL) + DNAC_P2S_FRI_R +                          \
     DNAC_P2S_TAIR_POW_OPS(DNAC_P2S_QUERY_POW_BITS) + DNAC_P2S_NUM_QUERIES)

/** Op index of the FIRST op of each BLOCK. The entry's structural rails index
 *  into these; they are the builder's own boundaries. */
#define DNAC_P2S_TAIR_OFF_PRIMING ((size_t)DNAC_DUPLEX_RATE)
#define DNAC_P2S_TAIR_OFF_PCS                                                 \
    (DNAC_P2S_TAIR_OFF_PRIMING + DNAC_P2S_TAIR_PRIMING_OPS)
#define DNAC_P2S_TAIR_OFF_TAIL                                                \
    (DNAC_P2S_TAIR_OFF_PCS + DNAC_P2S_TAIR_PCS_OPS)

#define DNAC_P2S_TAIR_NUM_OPS                                                 \
    (DNAC_P2S_TAIR_OFF_TAIL + DNAC_P2S_TAIR_TAIL_OPS)

/** Non-PoW SAMPLE ops that precede the FRI tail — the (alpha, beta) lookup
 *  squeeze iff any instance has lookups (batch_priming.c:143-144), the batch
 *  alpha (:194) and zeta (:280). Every pop ordinal the entry aliases by is
 *  offset by this, because the tail's alpha is no longer pop 0. */
#define DNAC_P2S_TAIR_PRE_POPS                                                \
    ((DNAC_P2S_INNER_LOOKUPS != 0 ? (size_t)4 : (size_t)0) + (size_t)2 +      \
     (size_t)2)

/** OBSERVE ops that precede the FRI tail: the DS prefix, the priming's observes
 *  (its ops minus its pops) and the whole of BLOCK 2, which is pure observe. */
#define DNAC_P2S_TAIR_PRE_OBS                                                 \
    ((size_t)DNAC_DUPLEX_RATE +                                               \
     (DNAC_P2S_TAIR_PRIMING_OPS - DNAC_P2S_TAIR_PRE_POPS) +                   \
     DNAC_P2S_TAIR_PCS_OPS)

/** Exported index bits: one query sample per query, each exporting lgmh lanes
 *  (transcript_air_table.c:607-610). EVERY one of them now has a consumer — query
 *  q's block IS `index_bits[q]` — so the `tair_bits_rest` field and its
 *  DNAC_P2S_TAIR_BITS_REST length that stood for the unconsumed remainder are
 *  GONE (multi-query slice; OBL-P2c-2). */
#define DNAC_P2S_TAIR_TOTAL_BITS (DNAC_P2S_NUM_QUERIES * DNAC_P2S_LGMH)

/** `dnac_tair_num_publics` = payload ‖ exported bits. Compared against the
 *  module accessor by the entry. */
#define DNAC_P2S_TAIR_NUM_PUBLICS                                             \
    (DNAC_P2S_TAIR_NUM_OPS + DNAC_P2S_TAIR_TOTAL_BITS)

/* ── The OBSERVE ordinal map (HONEST LABEL 6's closure) ──────────────────────
 * The pop map above indexes SAMPLE ops by ordinal; the round-digest alias needs
 * the same for OBSERVE ops. From the builder's own order the observes are, in
 * script order:
 *     0 .. PRE_OBS-1                  BLOCK 0 (the DS prefix) + every observe
 *                                     of BLOCK 1 + the whole of BLOCK 2
 *     then per round r:               DIGEST_LANES commit-digest lanes
 *                                     + 1 PoW witness iff grinding is on
 *     then (2 << lfpl)                the final polynomial
 *     then R                          the per-round log_arity
 *     then 1 iff query grinding is on the query PoW witness
 * so round r's digest block starts at PRE_OBS + r*(DIGEST_LANES + pow-observe).
 *
 * ⚠ THE `PRE_OBS` OFFSET IS THE WHOLE CHANGE THIS SLICE MAKES TO THIS MAP. It
 * used to be RATE, because the script started at the DS prefix and went straight
 * into the tail; the priming and PCS blocks now sit between them and every
 * digest ordinal moves by their observe count. The ordinal is still mapped to an
 * OP INDEX by WALKING the script, never by arithmetic on op numbers, and the
 * entry still requires each block to sit BETWEEN the surrounding rounds' beta
 * pops — which is what proves the ordinal really named round r's digest and not
 * some observe of the priming.
 *
 * ⚠ MAIR_DIGEST_LANES *IS* DNAC_P2M_DIGEST_LANES (mmcs_air.h:132 defines the
 * former as the latter), so "lane i of the root public" and "lane i of the
 * observed digest" are the same index by definition, not by coincidence. */
#define DNAC_P2S_TAIR_POW_OBS(bits) ((bits) != 0 ? (size_t)1 : (size_t)0)
#define DNAC_P2S_OBS_DIGEST(r, i)                                             \
    (DNAC_P2S_TAIR_PRE_OBS +                                                  \
     (size_t)(r) * ((size_t)DNAC_P2M_DIGEST_LANES +                           \
                    DNAC_P2S_TAIR_POW_OBS(DNAC_P2S_COMMIT_POW_BITS)) +         \
     (size_t)(i))
/** Total OBSERVE ops of the pinned script — the count the entry compares the
 *  script's own against, so the ordinal map cannot address past the end. */
#define DNAC_P2S_TAIR_NUM_OBS                                                 \
    (DNAC_P2S_TAIR_PRE_OBS +                                                  \
     DNAC_P2S_FRI_R * ((size_t)DNAC_P2M_DIGEST_LANES +                        \
                       DNAC_P2S_TAIR_POW_OBS(DNAC_P2S_COMMIT_POW_BITS)) +      \
     ((size_t)2 << DNAC_P2S_LFPL) + DNAC_P2S_FRI_R +                          \
     DNAC_P2S_TAIR_POW_OBS(DNAC_P2S_QUERY_POW_BITS))

/* ── Public-value counts, DERIVED from each AIR's documented layout ──────────
 * fri  (fri_air.h): bits[lgmh] ‖ beta[2R] ‖ f_init[2] ‖ ro[2*num_rollin] ‖
 *                   final[2]
 * mmcs (mmcs_air.h:181-182 + :227-231): root[4] ‖ dir[depth] ‖ opened[total]
 * mmix (mmcs_mixed_air.h:99-104):        root[4] ‖ dir[depth] ‖ opened[total]
 * oi   (fri_oi_air.h public layout): bits[lgmh] ‖ alpha[2] ‖
 *                            (z,p_z)[4*total_acc] ‖ ro[2*num_heights] ‖
 *                            p_x[total_acc]   (the s2 region, APPENDED LAST)
 * The entry compares each against the module accessor and fails closed on any
 * disagreement, so these cannot drift (the count-KAFADAN discipline). */
#define DNAC_P2S_FRI_NUM_PUBLICS                                              \
    (DNAC_P2S_LGMH + 2 * DNAC_P2S_FRI_R + 2 + 2 * DNAC_P2S_NUM_ROLLIN + 2)
/** PER ROUND: the dir region is that round's depth, so the count descends with
 *  it. `dnac_p2s_num_publics(instance)` is the runtime form. */
#define DNAC_P2S_MMCS_NUM_PUBLICS(r)                                          \
    ((size_t)MAIR_DIGEST_LANES + DNAC_P2S_MMCS_DEPTH(r) +                     \
     DNAC_P2S_MMCS_TOTAL_WIDTH)
/** Σ over r of DNAC_P2S_MMCS_DEPTH(r) — needed as a COMPILE-TIME expression by
 *  the flat publics block below, so it is the closed form of the arithmetic
 *  series R*lgmh - mla*(1 + 2 + ... + R). T-CONST re-derives it by summing the
 *  per-round macro, which is what keeps the closed form honest. */
#define DNAC_P2S_MMCS_SUM_DEPTHS                                              \
    (DNAC_P2S_FRI_R * DNAC_P2S_LGMH -                                         \
     DNAC_P2S_MAX_LOG_ARITY * (DNAC_P2S_FRI_R * (DNAC_P2S_FRI_R + 1) / 2))
/** Σ over r of DNAC_P2S_MMCS_NUM_PUBLICS(r) — one query's whole mmcs share. */
#define DNAC_P2S_MMCS_ALL_PUBLICS                                             \
    (DNAC_P2S_FRI_R *                                                         \
         ((size_t)MAIR_DIGEST_LANES + DNAC_P2S_MMCS_TOTAL_WIDTH) +            \
     DNAC_P2S_MMCS_SUM_DEPTHS)
/** PER BATCH: the opened region is that batch's, so the count moves with the
 *  batch's width. `dnac_p2s_num_publics(instance)` is the runtime form. */
#define DNAC_P2S_MMIX_NUM_PUBLICS(b)                                          \
    ((size_t)MMIX_DIGEST_LANES + DNAC_P2S_MMIX_DEPTH +                        \
     DNAC_P2S_MMIX_TOTAL_OPENED(b))
/** Σ over b of DNAC_P2S_MMIX_NUM_PUBLICS(b) — one query's whole mmix share.
 *  The root+dir part is batch-independent, so only the opened part is summed
 *  (and DNAC_P2S_MMIX_ALL_OPENED is exactly that sum). T-CONST re-derives this
 *  by summing the per-batch macro. */
#define DNAC_P2S_MMIX_ALL_PUBLICS                                             \
    (DNAC_P2S_OI_NUM_BATCHES *                                                \
         ((size_t)MMIX_DIGEST_LANES + DNAC_P2S_MMIX_DEPTH) +                  \
     DNAC_P2S_MMIX_ALL_OPENED)
#define DNAC_P2S_OI_NUM_PUBLICS                                               \
    (DNAC_P2S_LGMH + 2 + 4 * DNAC_P2S_OI_TOTAL_ACC +                          \
     2 * DNAC_P2S_OI_NUM_HEIGHTS + DNAC_P2S_OI_TOTAL_ACC)

/** Widest of the five AIRs, for callers sizing one scratch buffer. */
#define DNAC_P2S_MAX_NUM_PUBLICS DNAC_P2S_OI_NUM_PUBLICS

/* ── The FLAT publics block (multi-query slice) ───────────────────────────────
 * s3b handed `build_instances` five separate `gold_fp_t *`, one per AIR. With
 * 1 + (B+R+2)*Q instances that parameter list is neither writable nor Q-, R- or
 * B-independent, so the instances' publics live CONTIGUOUSLY in ONE
 * caller-owned block, in INSTANCE ORDER: the tair region first, then query 0's
 * B+R+2, then query 1's, and so on. `dnac_p2s_pub_off` is the ONLY thing that
 * knows the layout, so a caller never computes an offset and the entry never
 * hard-codes one. ⚠ The per-query block is NOT SLOTS uniform regions — the R
 * mmcs regions have R different lengths and the B mmix regions have B different
 * lengths — which is exactly why `pub_off` sums `dnac_p2s_num_publics` over the
 * preceding slots instead of multiplying. */
#define DNAC_P2S_QUERY_PUBLICS                                                \
    (DNAC_P2S_MMIX_ALL_PUBLICS + DNAC_P2S_MMCS_ALL_PUBLICS +                  \
     DNAC_P2S_FRI_NUM_PUBLICS + DNAC_P2S_OI_NUM_PUBLICS)

#define DNAC_P2S_TOTAL_PUBLICS                                                \
    (DNAC_P2S_TAIR_NUM_PUBLICS +                                              \
     DNAC_P2S_NUM_QUERIES * DNAC_P2S_QUERY_PUBLICS)

/* ── Max SYMBOLIC constraint degree over the five fold AIRs ─────────────────
 * Not computable at runtime (C has no symbolic builder), so it is a CITED
 * module property, and `log_num_qc` is DERIVED from it by the upstream rule —
 * never written as a number. Each fold header states its own max degree, and
 * each says the same thing: the mandated `is_transition` selector factor
 * (transcription rule §3.2) lifts its degree-3 transition forms to 4.
 *   fri_air_fold.h:39-48   C3b / C3c / C4k / C4l  -> 4
 *   mmcs_air_fold.h:42-49  the two placement forms -> 4
 *   mmcs_mixed_air_fold.h:66-69  likewise          -> 4
 *   fri_oi_air_fold.h:43-48      C1b / C2b-sq      -> 4  (the u64 degree table
 *                                fri_oi_air.c:25-51 tops out at 3 in-AIR)
 *   transcript_air_fold.h:36-45  the transition-anchored forms -> 4 (its own
 *                                note names the same is_transition lift, and
 *                                its INLINE Poseidon2 block folds through the
 *                                shared gadget the two MMCS AIRs already embed
 *                                at this same degree)
 * If any of the five were actually HIGHER, the quotient would be undersized
 * and the honest round-trip would fail — RT-1 in test_fri_statement.c is the
 * evidence, not this comment. */
#define DNAC_P2S_MAX_SYMBOLIC_DEGREE ((size_t)4)

/* ── PIN: the composed preprocessed root ────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA — the
 * prover commits its own tables and exports the lanes (batch_prover.c:818-825)
 * and `dnac_batch_verify` checks only their PRESENCE against the declared
 * matrix count. Nothing else in the tree compares that root to a pinned value,
 * so an all-zero selector table would satisfy every gated constraint of all
 * four AIRs vacuously. Upstream has no such hole: its preprocessed commitment
 * lives verifier-side in `CommonData` (full argument at mmcs_air_table.h:73-100).
 *
 * ⚠ ONE pin, not one per table — a CORRECTED DEVIATION from spec §2/§3.2, which
 * asked for one constant per table. `batch_prover.c:786-822` commits ALL
 * preprocessed matrices in ONE `dnac_p2_mmcs_commit_mixed` call, so a batched
 * proof carries a SINGLE 4-lane preprocessed root
 * (`dnac_batch_vcommits_t::preprocessed_commit`) and no per-table root exists
 * anywhere in it. Per-table constants would have had nothing to compare against.
 * The composed root binds all the tables jointly — tampering ANY cell of ANY
 * of them moves it — which is the property the pin needs; what it cannot do is
 * NAME the guilty table. The per-table discrimination spec §4's N-PIN×N asks
 * for therefore lives in the test, which tampers one table at a time and knows
 * which one it touched.
 *
 * ⚠ RE-PINNED AT THE INPUT-BATCH REPLICATION SLICE. The instance set went from
 * 1 + (R+3)*Q (13) to 1 + (B+R+2)*Q (17) in a NEW ORDER (the B mmix slots now
 * precede the R mmcs ones), so the 13-table value is void the same way the
 * 9-table one was.
 *
 * ⚠ RE-PINNED AGAIN AT THE PRIMING SLICE. The instance SET did not move (still
 * 17, still this order), but the TAIR TABLE did, twice over: the pinned script
 * grew from 31 ops to 93 (its height 64 -> 128) and TAIR_TBL_COLS grew 71 -> 135
 * with TAIR_TBL_MAX_STEPS. One of the 17 matrices therefore has a different
 * width, a different height AND different content, so the composed root is a
 * different value. The 17-table constant is void; the placeholder is back.
 *
 * ⚠ WHAT THE 17 TABLES ARE, honestly. The R mmcs tables are NOT copies of one
 * another — round r's depth is DNAC_P2S_MMCS_DEPTH(r) = 4 / 3 / 2, so the three
 * carry DIFFERENT CONTENT (different leaf/compress/final row types). Their ROW
 * COUNTS nonetheless coincide at this pin: leaf width 4 == the sponge rate, so
 * leaf == 1, `used` = 1 + depth + 1 = 6 / 5 / 4, and with the terminality
 * reserve `pad(used + 1)` = 8 / 8 / 8. Do NOT read the depths off the heights —
 * they are equal here by arithmetic accident, not by construction.
 * The B mmix tables, by contrast, ARE byte-identical to one another: the mixed
 * schedule sees a batch's width only through `leaf_rows = ceil(concat / 4)`
 * (mmcs_mixed_air_table.c:100-104 with :152/:161), and 1 and 2 both give 1. So
 * the batch axis carries NO table content at this pin — it carries a different
 * CFG and a different PUBLIC count, which is why the width must be pinned
 * independently of the root (OBL-4-MMIX) and is.
 * Neither fact weakens N-PIN: the composed root commits the 17 matrices
 * SEPARATELY and IN ORDER, so tampering one cell of any single one of them
 * moves it, which is what the test asserts per instance.
 *
 * The executor ships this constant as the {0,0,0,0} PLACEHOLDER and never fills
 * it; the ORCHESTRATOR re-derives it and fills it. While the placeholder is in
 * place the comparator rejects everything (see DNAC_P2S_PREP_ROOT_UNFILLED) and
 * the pin-dependent checks in tests/test_fri_statement.c assert exactly that;
 * once filled, T-PINKAT recomputes the root through the real pipeline.
 *
 * ⚠ HOW IT WAS RE-DERIVED, AND WHY NOT WITH `--print-roots` ALONE. Pasting the
 * printer's output and watching the KAT go green proves NOTHING: `print_roots`
 * and the KAT call the SAME helper on the SAME generated cells, so they cannot
 * disagree. For the priming slice the ORCHESTRATOR therefore wrote a SECOND
 * driver — its own LDE -> commit transcription, re-reading every shape number
 * from the public accessors instead of the test's constants — and compared it
 * lane for lane against the printer. Both agreed, and the second driver also
 * re-derived n_ops / rows / cols independently. A future re-pin that only runs
 * `--print-roots` should label itself "printer output", not "independently
 * derived". (Caught by an O6 zk-auditor: the previous wording claimed the
 * printer run WAS the independent derivation.)
 *
 * DERIVATION (exactly the pipeline batch_prover.c:786-822 runs, is_zk = 0):
 *   for i in 0 .. DNAC_P2S_NUM_INSTANCES-1:           // prep_map order
 *       table_i = <table module for the slot of i>_generate(PINNED CFG)
 *       lde_i   = dnac_prover_coset_lde_bitrev(table_i, rows_i, COLS_i,
 *                     DNAC_P2S_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *   root = dnac_p2_mmcs_commit_mixed({lde_i}, {COLS_i}, {rows_i << lb},
 *                                    DNAC_P2S_NUM_INSTANCES, ·, NULL)
 * The Q copies of ONE slot's table are byte-identical (and so, at this pin, are
 * the B mmix slots' — see above) while the R mmcs tables are not; the root
 * MOVES when any single cell of any single one is tampered either way, which is
 * what the pin needs and what N-PIN asserts per instance.
 * `dnac_p2_fri_statement_prep_tables` + the test's commit half ARE that
 * pipeline, so the pin is filled and re-checked by running code, never
 * transcribed by hand.
 *
 * The blowup is the OUTER `dnac_p2s_fri_params()->log_blowup`, because that is
 * what the prover commits the preprocessed matrices at. It coincides with the
 * per-module pins' DNAC_P2{B,C}_PREP_LOG_BLOWUP (both 2); the two are
 * independent quantities that happen to agree, so this uses its own constant.
 *
 * salt_elems = 0 is MANDATORY: salted + preprocessed is fail-closed at
 * batch_prover.c:604-612 (the guard inside `if (salt_elems > 0)`; citation
 * corrected — FLEET 028 verifier L3). */
#define DNAC_P2S_PREP_ROOT_LANE0 UINT64_C(0x7bd103f976d60e7a)
#define DNAC_P2S_PREP_ROOT_LANE1 UINT64_C(0x370fd9ef04ca3930)
#define DNAC_P2S_PREP_ROOT_LANE2 UINT64_C(0xdb116b37de732e01)
#define DNAC_P2S_PREP_ROOT_LANE3 UINT64_C(0x75c802c4d448afcc)

#define DNAC_P2S_PREP_ROOT                                                    \
    {                                                                         \
        DNAC_P2S_PREP_ROOT_LANE0, DNAC_P2S_PREP_ROOT_LANE1,                   \
        DNAC_P2S_PREP_ROOT_LANE2, DNAC_P2S_PREP_ROOT_LANE3                    \
    }

/** 1 while the pin above is still the unfilled placeholder. While it is, the
 *  comparator rejects EVERYTHING — a placeholder that accepted an all-zero
 *  root would be strictly worse than no pin, because a zero commitment is
 *  exactly what an adversary supplying an all-zero table would present
 *  (fri_air_table.h:398-401 precedent). Fill it with `--print-roots`. */
#define DNAC_P2S_PREP_ROOT_UNFILLED                                           \
    (DNAC_P2S_PREP_ROOT_LANE0 == 0 && DNAC_P2S_PREP_ROOT_LANE1 == 0 &&        \
     DNAC_P2S_PREP_ROOT_LANE2 == 0 && DNAC_P2S_PREP_ROOT_LANE3 == 0)

/* ── Status ─────────────────────────────────────────────────────────────── */
typedef enum {
    DNAC_P2S_OK = 0,
    DNAC_P2S_ERR_NULL = -1,      /**< required pointer missing               */
    DNAC_P2S_ERR_CANON = -2,     /**< G6: a statement value >= p, or an
                                      index bit outside {0,1}                */
    DNAC_P2S_ERR_PREP_ROOT = -3, /**< the pin comparison failed (incl. the
                                      unfilled-placeholder reject) or the
                                      preprocessed matrix map is not the
                                      identity over DNAC_P2S_NUM_INSTANCES   */
    DNAC_P2S_ERR_CFG = -4,       /**< a fold bind rejected the pinned cfg, a
                                      module accessor disagreed with the
                                      pinned public/geometry constants, or the
                                      STATIC cross-cfg consistency check
                                      (fri roll-in set vs OI.H) failed        */
    DNAC_P2S_ERR_SHAPE = -5,     /**< a pinned table height is not a power of
                                      two / does not fit a degree_bits        */
    DNAC_P2S_ERR_BATCH = -6      /**< dnac_batch_verify rejected; see `out`   */
} dnac_p2s_status_t;

/* ── The statement ──────────────────────────────────────────────────────────
 * Every field is a RAW canonical-candidate lane: step 1 is the ONE place their
 * canonicality is established, which is what lets the fold AIRs take
 * `gold_fp_t` publics (the s1a headers each defer exactly this).
 *
 * Region sizes are the PINNED cfg's, so they are compile-time — there is no
 * caller-supplied length to disagree with, and with it no length-mismatch
 * class. fp2 quantities are TWO consecutive lanes [c0, c1], c0 first, the
 * convention the fold modules use throughout. */
typedef struct {
    /** PER-QUERY. Query q's index, LSB-first: bit l is index_bits[q][l]. Every
     *  instance of query q takes its direction/bit publics as ALIASES of THIS
     *  row (step 6), and the row is ALSO the transcript instance's own q-th
     *  exported bit block — so "the index the transcript produced" and "the
     *  index query q's four AIRs walk" are the same lanes by construction.
     *
     *  ⚠ NEVER aliased ACROSS q. Q consumers reading row 0 is exactly the
     *  soundness collapse OBL-P2c-2 names (fri_air.h): the native samples a
     *  FRESH index per query at fri_verifier.c:737. */
    uint64_t index_bits[DNAC_P2S_NUM_QUERIES][DNAC_P2S_LGMH];

    /** SHARED — the transcript instance's PAYLOAD publics, one lane per script
     *  op in script order: the OBSERVED value on an observe row, the POPPED
     *  challenge on a sampling row (transcript_air_table.h "PUBLIC-VALUE
     *  LAYOUT").
     *
     *  ⚠ THE ROUND-DIGEST LANES OF THIS FIELD ARE DEAD (HONEST LABEL 6). The
     *  observe ops at `DNAC_P2S_OBS_DIGEST(r, i)` are sourced from
     *  `mmcs_root[r]` instead, so whatever a caller puts here at those op
     *  indices is overwritten and read by nothing. They keep their slots
     *  because this array is indexed BY OP INDEX — `pub_tair[k] =
     *  tair_payload[k]` is one loop — and removing R*DIGEST_LANES lanes from
     *  the middle would make every subsequent index conditional. Gate:
     *  N-OBSDEAD asserts the inertness rather than leaving it to this comment.
     *
     *  The rest is the SINGLE SOURCE of every Fiat-Shamir value the other
     *  instances consume, and every consumer of every query reads the SAME
     *  lanes — which is correct, because the native samples them ONCE, outside
     *  the query loop:
     *      fri[q].betas[r] := payload[the (2+2r)-th/(3+2r)-th non-PoW pop] :707
     *      oi[q].alpha     := payload[the first two non-PoW pops]          :694
     *  so the `betas` and `alpha` statement fields of s1b/s1c are GONE, exactly
     *  as `f_init` / `rollins` went at s1c. There is no second field for a
     *  challenge to disagree with — and no per-query copy either, so two
     *  queries cannot be folded with two different betas.
     *
     *  ⚠ The exported index bits of the tair instance are NOT here: they are
     *  `index_bits` above. `tair_bits_rest`, which held the queries no consumer
     *  modelled, is GONE — all Q are consumed now. */
    uint64_t tair_payload[DNAC_P2S_TAIR_NUM_OPS];

    /* fri regions (fri_air.h public layout).
     * ⚠ `f_init`, `rollins` (s1c) and `betas` (s3b) are NOT fields — they are
     * DERIVED from `ro_export[q]` / `tair_payload`. Adding any of them back
     * would re-open the very disagreement those slices removed. */
    /** SHARED — the walk's terminal, fp2. A single fp2 because
     *  log_final_poly_len == 0 is pinned (fri_air.h:105-106), and SHARED across
     *  q because the native observes the final poly once, before the query loop
     *  (fri_verifier.c:710-713). */
    uint64_t final_poly0[2];

    /** SHARED — the CLAIMED EVALUATION p_z of each acc row, in the SAME
     *  SCHEDULE order as `z_pq`: row a is the fp2 at 2*a, 2*a + 1. ONE region,
     *  aliased into every query's oi instance — the `ro_export` / `tair_payload`
     *  pattern, so two queries cannot name two different claimed evaluations
     *  for the same opening.
     *
     *  Native: `p_at_z = pt->claimed_evals[j]` (fri_verifier.c:470) where `pt`
     *  reaches back to `commitments[batch]` (:401 `mo = &cw->matrices[m]`, :437
     *  `pt = &mo->points[point]`, :209 `cw = &commitments[batch]`), and
     *  `commitments` is the SAME pointer on every iteration of the query loop
     *  (:743). Its partner `p_at_x` (:471) comes from `qp->input_proof` and IS
     *  per-query — that one is `mmix_opened[q]`, for EVERY batch since the
     *  input-batch replication slice.
     *
     *  ⚠ THE HONEST WITNESS FOR A SHARED REGION EXISTS ONLY WHILE NO OI HEIGHT
     *  GROUP SITS AT log_blowup. The shipped builder emits
     *  `pz = cur_is_lb ? emb(px) : tfp2(a_global + 3, 19)`
     *  (tests/test_fri_oi_air.c:265-266): the lb branch makes p_z a copy of p_x,
     *  which IS query-dependent, while the pinned cfg's heights {5, 4} against
     *  log_blowup 2 take the other branch on every row — a pure function of the
     *  schedule ordinal. T-CONST already fails closed if any pinned oi group
     *  ever moves to log_blowup (it guards C4b/C5 vacuity); that same check is
     *  now also what protects this region's witness. */
    uint64_t pz_shared[2 * DNAC_P2S_OI_TOTAL_ACC];

    /* oi regions (fri_oi_air.h:64-71 public layout).
     * ⚠ `alpha` is NOT a field either (s3b) — see `tair_payload`. */
    /** PER-QUERY. The OPENING POINT z of each acc row, in SCHEDULE order
     *  (height-descending, then batch-major): row a is the fp2 at 2*a, 2*a + 1.
     *
     *  ⚠ Per-query is WEAKER than the native, which takes z from
     *  `commitments[batch]` — a `fri_open_input` argument that does not move
     *  across the query loop (fri_verifier.c:743 passes the same pointer; :401
     *  and :437 reach z through it). See HONEST LABEL 8: this region stays
     *  per-query because the shipped honest-trace builder derives z as x + zoff
     *  and x IS query-dependent, so a shared region would have no witness. */
    uint64_t z_pq[DNAC_P2S_NUM_QUERIES][2 * DNAC_P2S_OI_TOTAL_ACC];
    /** PER-QUERY. Query q's exported reduced openings, ONE fp2 per height,
     *  DESCENDING — the SINGLE source of that query's fri walk seed and
     *  roll-ins as well as its oi instance's own ro publics
     *  (fri_verifier.c:490-497 writes them in this order; fri_oi_air.h:79-82
     *  exports them in it).
     *  ⚠ NEVER aliased across q: `fri_open_input` runs INSIDE the per-query
     *  loop, against that query's index (fri_verifier.c:742). */
    uint64_t ro_export[DNAC_P2S_NUM_QUERIES][2 * DNAC_P2S_OI_NUM_HEIGHTS];
    /* ⚠ `px_rest` IS NOT A FIELD ANY MORE (input-batch replication; HONEST
     * LABEL 3). It held the p_x of the acc rows the MAIN batch did not cover —
     * the quotient and preprocessed batches' — as a plain statement input bound
     * to no commitment. Every batch has its own mmix instance now, so every acc
     * row's p_x is an ALIAS of `mmix_opened[q]` at that batch's offset and
     * there is nothing left for the field to hold. Adding it back would re-open
     * exactly the seam that closure removed. */

    /** SHARED across q, DISTINCT per INPUT BATCH — batch b's commitment, i.e.
     *  `commitments[b].commitment` as `fri_open_input` reads it
     *  (fri_verifier.c:209 then :383/:392). ONE commitment per batch, opened at
     *  Q different indices, so a per-query root would let two queries open two
     *  trees; three roots because `dnac_batch_verify` gives each round its own
     *  (`main_commit` / `quotient_commit` / `preprocessed_commit`,
     *  batch_verify.c:557-559 / :574-576 / :595-597).
     *  NOT transcript-bound, for ANY b (HONEST LABEL 6a: the input batches are
     *  observed during priming, which the pinned script does not cover). */
    uint64_t mmix_root[DNAC_P2S_OI_NUM_BATCHES][MMIX_DIGEST_LANES];
    /** SHARED across q, DISTINCT per ROUND — `proof->commit_phase_commits[r]`
     *  (fri_verifier.c:585 indexes the array by round). Round r's root is what
     *  query q's round-r opening is checked against, for every q.
     *
     *  ⚠ This field is ALSO the source of the transcript instance's round-r
     *  digest observe lanes (step 6a) — the HONEST LABEL 6 closure. One field,
     *  two consumers: the mmcs[q][r] instances' root publics and the tair
     *  instance's payload at `DNAC_P2S_OBS_DIGEST(r, ·)`. There is no second
     *  place for "the root the challenger absorbed" to disagree with "the root
     *  the Merkle walk verifies against". */
    uint64_t mmcs_root[DNAC_P2S_FRI_R][MAIR_DIGEST_LANES];

    /* PER-QUERY inner opened rows. These ARE the query-dependent half of an
     * MMCS opening: same tree, same root, different leaf.
     *
     * ONE FLAT ROW PER QUERY, holding all B batches back to back in BATCH
     * order; inside batch b's span the matrices are concatenated in MATRIX
     * order using the SEMANTIC widths (mmcs_mixed_air.h "Public values"), which
     * is what the mmix instance's opened-row publics are. Batch b's span starts
     * at `dnac_p2s_mmix_opened_off(b)` and is DNAC_P2S_MMIX_TOTAL_OPENED(b)
     * long — a ragged [B][max] array would leave dead lanes, and dead lanes in
     * a statement are exactly what the honest labels keep having to apologise
     * for, so the spans are exact and the partition is asserted.
     *
     * TWO consumers per lane, by construction: batch b's mmix instance
     * (its opened-row publics) and the oi instance (the p_x of every acc row of
     * batch b at that matrix's height). That is HONEST LABEL 3's closure. */
    uint64_t mmix_opened[DNAC_P2S_NUM_QUERIES][DNAC_P2S_MMIX_ALL_OPENED];
    /** PER-QUERY *and* PER-ROUND. Round r's leaf for query q: the arity fp2
     *  evals BASE-flattened (fri_verifier.c:550-555 assembles the row, :568
     *  flattens it, :585-588 opens it). Per round because the walk shifts the
     *  index once per round (:558) and folds between them (:594), so each round
     *  opens a different tree at a different leaf. */
    uint64_t mmcs_opened[DNAC_P2S_NUM_QUERIES][DNAC_P2S_FRI_R]
                        [DNAC_P2S_MMCS_TOTAL_WIDTH];
} dnac_p2s_statement_t;

/* ── Pinned-cfg accessors (the dnac_p2b_ref_cfg pattern,
 *    mmcs_air_table.h:232 — one definition, no caller re-declaration) ────── */
/** Input batch `batch`'s cfg. NULL when `batch >= DNAC_P2S_OI_NUM_BATCHES`.
 *  Takes a batch because the batches differ in OPENED WIDTH — see the file
 *  header's honest note on which copies are byte-identical and which are not. */
const dnac_p2c_mmix_table_cfg_t *dnac_p2s_mmix_cfg(size_t batch);

/** Start of input batch `batch`'s span inside one query's `mmix_opened` row, in
 *  elements. SIZE_MAX when `batch` is out of range. The spans are contiguous,
 *  in batch order, and together span exactly DNAC_P2S_MMIX_ALL_OPENED. */
size_t dnac_p2s_mmix_opened_off(size_t batch);
/** Commit round `round`'s cfg. NULL when `round >= DNAC_P2S_FRI_R`. Takes a
 *  round because the rounds differ in DEPTH — see the file header's honest
 *  note on which copies are byte-identical and which are not. */
const dnac_p2b_table_cfg_t      *dnac_p2s_mmcs_cfg(size_t round);
const dnac_p2c_table_cfg_t      *dnac_p2s_fri_cfg(void);
const dnac_p2c_oi_table_cfg_t   *dnac_p2s_oi_cfg(void);

/** The transcript AIR's own config (its `pow_bits`). DERIVED from the two
 *  DNAC_P2S_*_POW_BITS widths, and cross-checked against the script by
 *  `dnac_p2s_check_tair_pow_pin`. */
const dnac_tair_config_t *dnac_p2s_tair_cfg(void);

/** The FRI-TAIL half of the cfg the pinned transcript script is expanded from,
 *  filled from the statement constants (R / lfpl / Q / lgmh / the PoW widths). */
const dnac_tair_fri_cfg_t *dnac_p2s_tair_fri_cfg(void);

/** The FULL cfg the pinned transcript script is expanded from — the inner
 *  proof's shape (DNAC_P2S_INNER_*) AND the FRI-tail scalars. Since the priming
 *  slice this, not the FRI half alone, is what the script covers. */
const dnac_tair_full_cfg_t *dnac_p2s_tair_full_cfg(void);

/**
 * @brief The PINNED transcript op script, expanded once from
 *        `dnac_p2s_tair_full_cfg()` by `dnac_tair_full_build_script`.
 *
 * NULL if the shipped builder rejects the derived cfg (fail-close). The script
 * and the arrays it names have static storage duration, so the pointer is
 * valid for the life of the process — which is what lets the fold bind retain
 * it (transcript_air_fold.h:155-166).
 *
 * ⚠ SINGLE-THREADED, like every other binding in this composition: the script
 * is expanded on first use into module-static storage. The expansion is a pure
 * function of compile-time constants — no wire data, no clock, no RNG — so two
 * nodes always obtain the identical script.
 */
const dnac_tair_script_t *dnac_p2s_tair_script(void);

/**
 * @brief The `pow_bits` PIN — OBL-P2a-T1's second half (FLEET 032 #30).
 *
 * The preprocessed root does NOT bind the grinding width: the table's columns
 * are TYPE(6) + IS_POW(1) + POS(64) and the generator branches on zero-vs-
 * non-zero only, so a 1-bit script and a 16-bit script produce a BYTE-IDENTICAL
 * table and the SAME root (transcript_air_table.h:162-173). The width is what
 * the AIR turns into "the low `pow_bits` of the challenge are zero"
 * (transcript_air.c:262-263), so an entry that pins only the root could be
 * handed a 1-bit script where 16 were intended.
 *
 * This compares the width `s` actually carries (`dnac_tair_script_pow_bits`,
 * which itself fails closed when two PoW ops disagree) against the widths of
 * `dnac_p2s_fri_params()`, and rejects on ANY difference — including the case
 * where the params name two DIFFERENT non-zero widths, which one
 * `dnac_tair_config_t::pow_bits` cannot represent at all.
 *
 * Exposed because the pinned constants make both widths 0, so a compile-time
 * mismatch cannot be constructed: N-POWPIN drives this function with a
 * SYNTHETIC non-zero-PoW script instead.
 *
 * @return DNAC_P2S_OK on agreement, DNAC_P2S_ERR_CFG otherwise (or on NULL).
 */
dnac_p2s_status_t dnac_p2s_check_tair_pow_pin(const dnac_tair_script_t *s);

/** The OUTER FRI parameters the composed recursion proof is verified under.
 *  MECHANISM pin (see the header's production caveat): these size the proof,
 *  they do not choose a security level. */
const dnac_fri_params_t *dnac_p2s_fri_params(void);

/** One query's consumer snapshots — one per SLOT, so B for the input batches
 *  and R for the commit rounds. Each round AND each batch binds the SAME AIR at
 *  a DIFFERENT cfg, which is the case FLEET 034's caller-owned states exist
 *  for: with the retired module-static binding, batch 1's bind would have
 *  clobbered batch 0's and both instances would have evaluated the last cfg
 *  bound — at three different opened WIDTHS, which is a live shape mismatch,
 *  not merely a stale pointer. */
typedef struct {
    dnac_mmix_fold_state_t mmix[DNAC_P2S_OI_NUM_BATCHES];
    dnac_mair_fold_state_t mmcs[DNAC_P2S_FRI_R];
    dnac_fair_fold_state_t fri;
    dnac_foi_fold_state_t  oi;
} dnac_p2s_query_fold_states_t;

/**
 * @brief Storage for every instance's fold-state snapshot (FLEET 034, grown to
 *        1 + (B+R+2)*Q by the multi-query, round-replication and input-batch
 *        replication slices).
 *
 * The fold modules keep NO module-static binding: `<module>_fold_bind` fills a
 * CALLER-OWNED state and points the descriptor's `ctx` at it
 * (stark_constraints.h:299-311). That is precisely what makes Q instances of
 * the SAME AIR possible — and, since the round slice, R instances of the mmcs
 * AIR at R DIFFERENT cfgs inside one query, and since this one, B instances of
 * the mmix AIR at B different cfgs: each gets its own snapshot, so batch 1's
 * bind cannot clobber batch 0's any more than round 1's can clobber round 0's.
 * This block is all of them, in instance order, so a caller declares ONE object
 * instead of 1 + (B+R+2)*Q.
 *
 * Contents are this file's business — declare it, pass it, do not read it.
 *
 * ⚠ SIZE, MEASURED at this pin (Q = 2, B = 3, R = 3): 27768 bytes, up from
 * 11768 before input-batch replication. The B-1 extra mmix snapshots cost 4000
 * bytes EACH — `dnac_mmix_fold_state_t` is by far the largest of the five — so
 * this axis is the expensive one: +8000 bytes per query, against +48 per extra
 * commit round. The whole entry frame (this block + the 17 descriptors + the
 * publics) is ~33 KB, MEASURED by the test and printed by it. Still an ordinary
 * automatic on every target here (the default thread stack is 8 MB on glibc and
 * 1 MB on Android's bionic — `dnac_p2_fri_statement_verify` is a leaf-ish call
 * on both), so it stays on the frame; if B or Q grows much further this is the
 * number that decides otherwise, which is why it is measured rather than
 * estimated.
 * `dnac_p2_fri_statement_verify` keeps one on its own FRAME, deliberately: a
 * file-scope object would make the entry non-reentrant and give back exactly
 * the shared-binding hazard FLEET 034 removed, and a heap object would add an
 * allocation-failure path to a function whose whole contract is "construct and
 * reject". A caller that cannot afford the frame should drive
 * `dnac_p2_fri_statement_build_instances` with storage of its own lifetime
 * instead — which is why that entry point is exposed.
 */
typedef struct {
    dnac_tair_fold_state_t       tair;
    dnac_p2s_query_fold_states_t q[DNAC_P2S_NUM_QUERIES];
} dnac_p2s_fold_states_t;

/** Public-value count for instance `i`. 0 if `i` is out of range. */
size_t dnac_p2s_num_publics(uint32_t instance);

/** Start of instance `i`'s region inside the flat publics block, in elements.
 *  SIZE_MAX if `i` is out of range. The regions are contiguous, in instance
 *  order, and together span exactly DNAC_P2S_TOTAL_PUBLICS. */
size_t dnac_p2s_pub_off(uint32_t instance);

/** The per-query SLOT of instance `i`, or DNAC_P2S_SLOTS for the transcript
 *  instance and for an out-of-range index ("no slot"). */
uint32_t dnac_p2s_inst_slot(uint32_t instance);

/** The QUERY instance `i` belongs to. SIZE_MAX for the transcript instance and
 *  for an out-of-range index. */
size_t dnac_p2s_inst_query(uint32_t instance);

/** The COMMIT ROUND instance `i` models, or SIZE_MAX when `i` is not one of the
 *  R mmcs instances (including the transcript instance and out-of-range). The
 *  ONE decoder for the round axis — nothing else subtracts DNAC_P2S_SLOT_MMCS0
 *  from an instance index. */
size_t dnac_p2s_inst_round(uint32_t instance);

/** The INPUT BATCH instance `i` models, or SIZE_MAX when `i` is not one of the
 *  B mmix instances (including the transcript instance and out-of-range). The
 *  ONE decoder for the batch axis — nothing else subtracts DNAC_P2S_SLOT_MMIX0
 *  from an instance index. */
size_t dnac_p2s_inst_batch(uint32_t instance);

/**
 * @brief Build every batch descriptor from the statement — steps 3-6.
 *
 * Exposed because the TEST must prove the SAME instances the entry verifies:
 * were the test to assemble its own publics, a bug in the entry's aliasing
 * would be faithfully mirrored on both sides and RT-1 would pass regardless.
 * With one builder, RT-1 is a statement about the entry's own construction.
 *
 * Fills, per instance: the fold `air` descriptor (via the module's bind,
 * including its `ctx` into `states`), `preprocessed_width`, `prep_next = 1`
 * (PIN-2, hard-coded — see the entry), `degree_bits` from the table's own row
 * count, `log_num_qc` from the upstream symbolic rule, and `public_values` /
 * `num_publics` pointing INTO `pub`, which this function fills.
 *
 * ⚠ On success the descriptors' `ctx` fields point INTO `states` and their
 * `public_values` INTO `pub`, which is why both carry the must-outlive rule.
 *
 * ⚠ On FAILURE — stated exactly, because the useful property is about `insts`,
 * not about `states`. Once `insts` is non-NULL it is ZEROED before anything
 * else, so EVERY failure path below leaves every descriptor with
 * `ctx == NULL` AND `air_eval == NULL`: a caller that ignores the return code
 * cannot evaluate a stale cfg's constraint system, because it cannot evaluate
 * at all. Additionally, each bind that actually RAN disarmed its own state and
 * its own descriptor on entry. States belonging to binds that were never
 * reached (an early step-3a reject, or a later query's binds after an earlier
 * query failed) are left exactly as the caller supplied them — which is why
 * `dnac_p2_fri_statement_verify` zero-initialises the block, and why callers
 * should too.
 *
 * @param stmt      the statement; publics are built from it, nothing is read
 *                  from any proof.
 * @param insts     [DNAC_P2S_NUM_INSTANCES], filled on success.
 * @param states    the fold-state snapshots; must outlive `insts`.
 * @param pub       >= DNAC_P2S_TOTAL_PUBLICS elements; must outlive `insts`.
 *                  Sliced by `dnac_p2s_pub_off` / `dnac_p2s_num_publics`.
 * @return DNAC_P2S_OK, or the first failing step's status.
 */
dnac_p2s_status_t dnac_p2_fri_statement_build_instances(
    const dnac_p2s_statement_t *stmt,
    dnac_batch_vinstance_t     *insts,
    dnac_p2s_fold_states_t     *states,
    gold_fp_t                  *pub);

/**
 * @brief Verify a composed FRI-verify statement.
 *
 * The steps, in this order, every one of them fail-close:
 *   1. G6 canonicality over the WHOLE statement (< p, and the index bits
 *      boolean) — before anything is derived from it.
 *   2. the preprocessed root pin + the preprocessed matrix map.
 *   3a. the STATIC cross-cfg consistency of the five pinned cfgs — no witness,
 *      no proof, pure constants (see `p2s_check_static_consistency` in the .c):
 *        (a) every fri roll-in height is an OI height OTHER than lgmh,
 *        (b) a fri roll-in AT the final height requires an OI group at
 *            log_blowup (fri_oi_air.h:90-99 hands this obligation to the
 *            composition entry explicitly),
 *        (c) OI.H[0] == lgmh == fri.lgmh, and the two cfgs agree on log_blowup,
 *        (d) s3b: the script's op count / public count match the pinned
 *            arithmetic, its non-PoW pop sequence has the alpha + 2R beta + Q
 *            query shape the aliases index into, each query sample exports
 *            exactly lgmh bits, and the `pow_bits` PIN holds
 *            (`dnac_p2s_check_tair_pow_pin`).
 *   3b. every cfg bound; a cfg is never read out of the proof (OBL-P2c-1).
 *   4. each `degree_bits` from `<module>_table_rows(cfg)`.
 *   5. `log_num_qc` from the upstream symbolic rule.
 *   6. every instance's publics assembled from the statement's regions by
 *      ALIASING, not checking:
 *        - SHARED into every query: the ONE `tair_payload` (the s3b source of
 *          every fri instance's betas and every oi instance's alpha), the ONE
 *          `final_poly0`, `mmix_root[b]` into every query's batch-b mmix
 *          instance, and `mmcs_root[r]` into BOTH every query's round-r MMCS
 *          instance AND the transcript instance's round-r digest observe lanes
 *          (HONEST LABEL 6's closure);
 *        - PER QUERY q: `index_bits[q]` into the tair instance's q-th exported
 *          bit block AND into query q's bit/direction regions — round r's dir
 *          region taking the window at `DNAC_P2S_MMCS_BIT_OFF(r)`;
 *          `ro_export[q]` into fri[q]'s f_init + roll-ins and oi[q]'s ro;
 *          `mmix_opened[q]` at batch b's span into mmix[q][b]'s opened row AND
 *          (HONEST LABEL 3's closure) into the p_x publics of every oi[q] acc
 *          row belonging to batch b; `mmcs_opened[q][r]`, `z_pq[q]`,
 *          `pz_shared`.
 *   7. `dnac_batch_verify` with is_zk = 0, num_random_codewords = 0,
 *      salt_elems = 0 and the pinned outer FRI params.
 * Steps 3-6 are `dnac_p2_fri_statement_build_instances`.
 *
 * @param stmt                     the statement.
 * @param opened                   [DNAC_P2S_NUM_INSTANCES] unmerged opened
 *                                 values, in the instance order above.
 * @param commits                  the batch commitments; `preprocessed_commit`
 *                                 is REQUIRED and is what the pin compares.
 * @param prep_matrix_to_instance  MUST be the identity {0, 1, ..., N-1}.
 * @param num_prep_matrices        MUST be DNAC_P2S_NUM_INSTANCES.
 * @param fri_proof                the FRI opening proof.
 * @param out                      optional batch diagnostics (nullable).
 * @return DNAC_P2S_OK on acceptance, else the first failing step's status.
 */
dnac_p2s_status_t dnac_p2_fri_statement_verify(
    const dnac_p2s_statement_t   *stmt,
    const dnac_batch_vopened_t   *opened,
    const dnac_batch_vcommits_t  *commits,
    const uint32_t               *prep_matrix_to_instance,
    uint32_t                      num_prep_matrices,
    const dnac_fri_proof_t       *fri_proof,
    dnac_batch_verify_out_t      *out);

/**
 * @brief Generate the honest preprocessed table of every instance, in the
 *        instance order the pin commits to.
 *
 * Sizes: `out[i]` needs `dnac_p2s_prep_cells(i)` cells. Exposed so the
 * `--print-roots` pin-fill path and the pin negatives can generate, tamper one
 * cell, and re-commit — and so the ORDER lives in one place.
 *
 * ⚠ The LDE + Merkle-commit half of the pin pipeline is deliberately NOT here.
 * `dnac_prover_coset_lde_bitrev` lives in stark_prover.c, so exposing a
 * root-recomputing entry from this module would put the whole PROVER stack on
 * the link line of every consumer of the VERIFY entry — nodus links the verify
 * stack. The verify path compares the proof's root against the CONSTANT and
 * never runs an LDE, so the pipeline belongs to the test, exactly as
 * `mmcs_air_table.c` keeps only the comparator and `test_mmcs_air_table.c:72-95`
 * carries `p2b_commit_table`.
 */
dnac_p2s_status_t dnac_p2_fri_statement_prep_tables(uint64_t *const *out);

/** Preprocessed cell count (rows * cols) for instance `i`. 0 if `i` is out of
 *  range or the pinned cfg is rejected by its table module. */
size_t dnac_p2s_prep_cells(uint32_t instance);

/** Preprocessed width (columns) for instance `i`. 0 if `i` is out of range. */
size_t dnac_p2s_prep_cols(uint32_t instance);

/** Preprocessed row count for instance `i`. 0 if `i` is out of range or the
 *  pinned cfg is rejected. */
size_t dnac_p2s_prep_rows(uint32_t instance);

/**
 * @brief `log_num_qc` for a max symbolic constraint degree, by the upstream
 *        rule — exposed so the test can derive it independently.
 *
 * Plonky3 v0.6.2 `batch-stark/src/symbolic.rs:70-78`
 * (`get_log_num_quotient_chunks`, the function batch_verify.h:126 names as the
 * source of this field):
 *     max_degree        = max(air.max_constraint_degree(), lookup degrees)
 *     constraint_degree = max(max_degree + is_zk, 2)
 *     result            = log2_ceil(constraint_degree - 1)
 * The five fold AIRs declare no lookups, so the lookup term is 0 and drops out
 * (`.unwrap_or(0)` at symbolic.rs:75).
 *
 * @return the chunk-count exponent, or SIZE_MAX on a degenerate input.
 */
size_t dnac_p2s_log_num_qc(size_t max_symbolic_degree, int is_zk);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_STATEMENT_H */
